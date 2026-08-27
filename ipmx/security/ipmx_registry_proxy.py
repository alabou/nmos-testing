# Copyright (C) 2026 Matrox Graphics Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""TR-10-SEC registry-proxy fixture.

The validator uses this proxy to observe a Node's outbound traffic
toward an IS-04 Registry. It sits between the Node and an upstream
registry (real or in-process stub), recording every request's:

  * transport: TLS version, cipher, client-cert presence + identity
  * HTTP: method, path, presence of ``Authorization`` header
  * RAP signal: HTTP vs HTTPS vs HTTPS+mTLS

The recorded log lets the validator's §7.2 / §10.x / §12.2 checks
verify that the Node honours its declared RAP — e.g. RAP=0 means
plain HTTP, RAP=2 means mTLS, and §7.2 forbids any
``Authorization: Bearer`` on registry-side requests regardless of mode.

Two operating modes:

  * **forward**: every request is proxied to ``--upstream`` and the
    upstream's response is returned to the Node verbatim. Use this
    when an existing nmos-cpp registry is available.
  * **stub**: the proxy answers IS-04 registration requests with
    spec-compliant minimal responses (201 / 200 / 204) so the Node
    completes its registration handshake without needing a real
    registry. Useful for CI and fast validator runs.

The proxy is process-isolated from the validator — launched as a
subprocess or run standalone — so a crash here cannot affect the
validator's other work.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import ssl
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import aiohttp
from aiohttp import web


LOG = logging.getLogger("ipmx-registry-proxy")


@dataclass
class RegistryProxyConfig:
    """Configuration for :class:`RegistryProxy`."""
    host: str = "0.0.0.0"
    port: int = 8444
    """Registration port the Node connects to."""
    query_port: int | None = None
    """Query port; defaults to ``port - 1``."""
    mode: str = "stub"
    """Either ``"stub"`` (answer in-process) or ``"forward"``."""
    upstream_base: str | None = None
    """Upstream registry base URL when ``mode == "forward"``."""
    tls: bool = False
    """Serve over HTTPS (TR-10-SEC RAP=1/2). Requires cert+key."""
    cert_chain: Path | None = None
    private_key: Path | None = None
    require_client_cert: bool = False
    """Enforce mTLS — required when probing RAP=2."""
    client_ca: Path | None = None


@dataclass
class ProxyRequestRecord:
    """One entry per HTTP request the proxy observed.

    The validator's §7.2 / §10 / §12.2 checks read this list."""
    method: str
    path: str
    tls_version: str
    cipher: str
    has_authorization: bool
    authorization_scheme: str
    peer_cert_subject: str
    peer_cert_present: bool
    upstream_status: int | None = None


class RegistryProxy:
    """Observer + forwarder for Node→Registry traffic.

    Usage::

        cfg = RegistryProxyConfig(port=8444, mode="stub", tls=True,
                                  cert_chain=..., private_key=...)
        proxy = RegistryProxy(cfg)
        await proxy.start()
        # ... drive tests against the Node ...
        for entry in proxy.request_log:
            assert not entry.has_authorization, "§7.2 violation"
        await proxy.stop()
    """

    def __init__(self, config: RegistryProxyConfig) -> None:
        self._config = config
        self._request_log: list[ProxyRequestRecord] = []
        self._runners: list[web.AppRunner] = []
        self._sites: list[web.TCPSite] = []
        self._upstream_session: aiohttp.ClientSession | None = None
        self._test_uuid_counter = 0
        self._resources: dict[str, list[dict[str, Any]]] = {
            "node": [], "device": [], "source": [],
            "flow": [], "sender": [], "receiver": [],
        }

    @property
    def request_log(self) -> list[ProxyRequestRecord]:
        return list(self._request_log)

    def clear_log(self) -> None:
        self._request_log.clear()

    async def start(self) -> None:
        ssl_ctx: ssl.SSLContext | None = None
        if self._config.tls:
            if self._config.cert_chain is None or self._config.private_key is None:
                raise ValueError("TLS mode requires cert_chain + private_key")
            ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ssl_ctx.load_cert_chain(
                str(self._config.cert_chain), str(self._config.private_key),
            )
            if self._config.require_client_cert:
                if self._config.client_ca is None:
                    raise ValueError(
                        "require_client_cert needs client_ca to verify against",
                    )
                ssl_ctx.verify_mode = ssl.CERT_REQUIRED
                ssl_ctx.load_verify_locations(str(self._config.client_ca))

        if self._config.mode == "forward":
            if self._config.upstream_base is None:
                raise ValueError("forward mode requires upstream_base")
            self._upstream_session = aiohttp.ClientSession()

        for port in self._listen_ports():
            app = web.Application(middlewares=[self._observe_middleware])
            self._wire_routes(app)
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(
                runner, self._config.host, port,
                ssl_context=ssl_ctx,
            )
            await site.start()
            self._runners.append(runner)
            self._sites.append(site)
            scheme = "https" if ssl_ctx else "http"
            LOG.info(
                "RegistryProxy: %s://%s:%d (%s mode%s)",
                scheme, self._config.host, port, self._config.mode,
                ", mTLS" if self._config.require_client_cert else "",
            )

    async def stop(self) -> None:
        for site in self._sites:
            await site.stop()
        for runner in self._runners:
            await runner.cleanup()
        self._sites.clear()
        self._runners.clear()
        if self._upstream_session is not None:
            await self._upstream_session.close()
            self._upstream_session = None

    def _listen_ports(self) -> list[int]:
        ports = [self._config.port]
        qp = self._config.query_port
        if qp is None:
            qp = self._config.port - 1
        if qp and qp != self._config.port:
            ports.append(qp)
        return ports

    @web.middleware
    async def _observe_middleware(
        self,
        request: web.Request,
        handler: Any,
    ) -> web.StreamResponse:
        """Record per-request transport + auth metadata before forwarding."""
        transport = request.transport
        tls_version = "none"
        cipher = "none"
        peer_subject = ""
        peer_present = False
        if transport is not None:
            ssl_obj = transport.get_extra_info("ssl_object")
            if ssl_obj is not None:
                cipher_info = ssl_obj.cipher()
                if cipher_info:
                    cipher = cipher_info[0]
                    tls_version = cipher_info[1]
                peer = ssl_obj.getpeercert()
                if peer:
                    peer_present = True
                    subj = peer.get("subject", ())
                    peer_subject = ", ".join(
                        f"{k}={v}" for rdn in subj for k, v in rdn
                    )
        auth = request.headers.get("Authorization", "")
        scheme = auth.split(" ", 1)[0] if auth else ""
        record = ProxyRequestRecord(
            method=request.method,
            path=request.path,
            tls_version=tls_version,
            cipher=cipher,
            has_authorization=bool(auth),
            authorization_scheme=scheme,
            peer_cert_subject=peer_subject,
            peer_cert_present=peer_present,
        )
        self._request_log.append(record)
        try:
            response: web.StreamResponse = await handler(request)
            if isinstance(response, web.Response):
                record.upstream_status = response.status
            return response
        except Exception:
            record.upstream_status = -1
            raise

    def _wire_routes(self, app: web.Application) -> None:
        if self._config.mode == "forward":
            app.router.add_route("*", "/{tail:.*}", self._forward)
        else:
            app.router.add_get("/x-nmos/registration/{tail:.*}", self._stub_reg_get)
            app.router.add_post("/x-nmos/registration/{tail:.*}", self._stub_reg_post)
            app.router.add_delete("/x-nmos/registration/{tail:.*}", self._stub_reg_delete)
            app.router.add_get("/x-nmos/query/{tail:.*}", self._stub_query_get)
            app.router.add_get("/x-nmos/{tail:.*}", self._stub_root_get)
            app.router.add_get("/", self._stub_root_get)

    async def _forward(self, request: web.Request) -> web.StreamResponse:
        assert self._upstream_session is not None
        base = (self._config.upstream_base or "").rstrip("/")
        url = f"{base}{request.path_qs}"
        body = await request.read()
        # Strip the inbound ``Host`` header; aiohttp recomputes it for
        # the upstream connection.
        headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}
        try:
            async with self._upstream_session.request(
                request.method, url, headers=headers, data=body,
                allow_redirects=False,
            ) as up:
                body_out = await up.read()
                resp_headers = {
                    k: v for k, v in up.headers.items()
                    if k.lower() not in ("transfer-encoding", "content-encoding")
                }
                return web.Response(
                    status=up.status, headers=resp_headers, body=body_out,
                )
        except aiohttp.ClientError as exc:
            return web.Response(
                status=502,
                text=json.dumps({"error": f"upstream unreachable: {exc}"}),
                content_type="application/json",
            )

    # ---- stub-mode handlers -------------------------------------------------

    async def _stub_reg_post(self, request: web.Request) -> web.Response:
        """Minimal IS-04 registration handler: ``POST /resource`` /
        ``POST /health/nodes/<id>`` — return 201/200 and remember the
        registration so subsequent heartbeats and DELETE-by-id work."""
        path = request.path
        if path.endswith("/resource"):
            try:
                payload = await request.json()
            except Exception:
                return web.json_response({"error": "invalid JSON"}, status=400)
            r_type = payload.get("type", "")
            r_data = payload.get("data", {})
            if isinstance(r_data, dict):
                self._resources.setdefault(r_type, []).append(r_data)
            return web.json_response(r_data, status=201)
        if "/health/nodes/" in path:
            return web.json_response({"health": str(self._now())})
        return web.json_response({}, status=204)

    async def _stub_reg_delete(self, request: web.Request) -> web.Response:
        return web.Response(status=204)

    async def _stub_reg_get(self, request: web.Request) -> web.Response:
        return web.json_response({})

    async def _stub_query_get(self, request: web.Request) -> web.Response:
        return web.json_response([])

    async def _stub_root_get(self, request: web.Request) -> web.Response:
        return web.json_response(["x-nmos/"])

    def _now(self) -> int:
        # Spec-shaped pseudo-timestamp; production code would use real
        # time but the unit test runs in deterministic time.
        self._test_uuid_counter += 1
        return self._test_uuid_counter


# ---------------------------------------------------------------------------
# CLI entry — `python3 ipmx_registry_proxy.py --port 8444 --tls ...`
# ---------------------------------------------------------------------------

def _cli() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="IPMX security test-suite registry proxy fixture",
    )
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8444)
    p.add_argument("--query-port", type=int, default=None)
    p.add_argument("--mode", choices=["stub", "forward"], default="stub")
    p.add_argument("--upstream", help="Upstream registry base URL (forward mode)")
    p.add_argument("--tls", action="store_true", help="Serve over HTTPS")
    p.add_argument("--cert", type=Path, help="Server cert (chain PEM)")
    p.add_argument("--key", type=Path, help="Server key (PEM)")
    p.add_argument("--require-client-cert", action="store_true")
    p.add_argument("--client-ca", type=Path, help="CA for client cert verification")
    p.add_argument(
        "--log-out", type=Path, default=None,
        help="On exit, dump request_log to this JSON file",
    )
    return p.parse_args()


async def _amain() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    cli = _cli()
    cfg = RegistryProxyConfig(
        host=cli.host, port=cli.port, query_port=cli.query_port,
        mode=cli.mode, upstream_base=cli.upstream,
        tls=cli.tls, cert_chain=cli.cert, private_key=cli.key,
        require_client_cert=cli.require_client_cert, client_ca=cli.client_ca,
    )
    proxy = RegistryProxy(cfg)
    await proxy.start()
    # Install signal handlers so the matrix runner's SIGTERM (and an
    # operator's Ctrl-C) both cleanly flush the request log to disk
    # via the finally block. Without these, SIGTERM kills the python
    # process before the JSON dump runs.
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    import signal as _sig
    for s in (_sig.SIGTERM, _sig.SIGINT):
        try:
            loop.add_signal_handler(s, stop.set)
        except (NotImplementedError, RuntimeError):
            # add_signal_handler is unavailable on some platforms
            # (Windows) — caller-side SIGINT/KeyboardInterrupt still
            # works via the existing except.
            pass
    try:
        try:
            await stop.wait()
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
    finally:
        if cli.log_out is not None:
            with open(cli.log_out, "w", encoding="utf-8") as f:
                json.dump(
                    [r.__dict__ for r in proxy.request_log], f, indent=2,
                )
            LOG.info("Wrote %d request records to %s",
                     len(proxy.request_log), cli.log_out)
        await proxy.stop()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_amain()))
