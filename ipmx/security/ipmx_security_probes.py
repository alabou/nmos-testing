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

"""Network probes used by the IPMX security check functions.

Each probe is a small async helper that opens a single TLS connection
or HTTP request against the DUT and returns a structured report the
check function can assert on. Keeping these isolated from the
requirement registry makes them reusable and individually testable.

Probe inventory:

* :func:`tls_handshake` — open one TLS handshake with a specific cipher
  suite + optional client cert + optional ALPN, return what was
  negotiated (or the OpenSSL error if the handshake was refused).
* :func:`tls13_suite_handshake` — the same, TLS 1.3 only and offering
  exactly one TLS 1.3 cipher suite.
* :func:`fetch_self` — ``GET /x-nmos/node/v1.3/self`` and parse the
  Node resource; the security-tag verifier consumes this.
* :func:`request_with_token` — issue an HTTPS request carrying a
  Bearer token (or no token, or a malformed Authorization header) and
  return the status + WWW-Authenticate header + body.
* :func:`ws_upgrade` — attempt a WebSocket upgrade with assorted auth
  modes; the §14.3.3.7 check uses this to verify the DUT rejects
  query-param tokens.

All probes route through a single :class:`SecurityHttpClient` that
owns the aiohttp ClientSession and SSL context. The validator creates
one per (DUT, certificate-flavor) pair.
"""

from __future__ import annotations

import asyncio
import json
import os
import ssl
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import aiohttp


# ---------------------------------------------------------------------------
# TLS handshake probe
# ---------------------------------------------------------------------------

@dataclass
class HandshakeReport:
    """What :func:`tls_handshake` observed on the wire."""
    succeeded: bool
    negotiated_cipher: str | None = None
    negotiated_version: str | None = None
    peer_cert_pem: bytes | None = None
    error: str | None = None


async def tls_handshake(
    host: str,
    port: int,
    *,
    ciphers: str | None = None,
    min_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2,
    max_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3,
    server_ca: Path | None = None,
    client_cert: Path | None = None,
    client_key: Path | None = None,
    server_hostname: str | None = None,
    timeout: float = 5.0,
) -> HandshakeReport:
    """Open exactly one TLS handshake to ``host:port`` and report.

    Used for the §3 cipher matrix: pass the IANA name as ``ciphers``
    and assert ``succeeded == expected``. Also for the §11 RAAM mTLS
    checks: pass ``client_cert``/``client_key`` (or omit) to probe
    whether the DUT requires client certs.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = min_version
    ctx.maximum_version = max_version
    if ciphers is not None:
        ctx.set_ciphers(ciphers)
    if server_ca is not None:
        ctx.load_verify_locations(str(server_ca))
    else:
        ctx.load_default_certs()
    # Hostname check is enabled by default; tests can override via the
    # ``server_hostname`` arg to wrap_socket below.
    if client_cert and client_key:
        ctx.load_cert_chain(str(client_cert), str(client_key))

    loop = asyncio.get_running_loop()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host, port, ssl=ctx, server_hostname=server_hostname or host,
            ),
            timeout=timeout,
        )
    except (asyncio.TimeoutError, ssl.SSLError, ConnectionError, OSError) as exc:
        return HandshakeReport(succeeded=False, error=f"{type(exc).__name__}: {exc}")

    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        cipher_info = ssl_obj.cipher() if ssl_obj is not None else None
        peer_der: bytes | None = None
        if ssl_obj is not None:
            peer_der = ssl_obj.getpeercert(binary_form=True)
        return HandshakeReport(
            succeeded=True,
            negotiated_cipher=cipher_info[0] if cipher_info else None,
            negotiated_version=cipher_info[1] if cipher_info else None,
            peer_cert_pem=peer_der,
        )
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ssl.SSLError, ConnectionError):
            pass


# OpenSSL configuration that restricts every SSL_CTX a process creates to
# one TLS 1.3 cipher suite -- the same shape the matrix runner writes to pin
# an ECDH group.
_TLS13_SUITE_CONF = (
    "openssl_conf = ipmx_openssl_init\n"
    "\n"
    "[ipmx_openssl_init]\n"
    "ssl_conf = ipmx_ssl_sect\n"
    "\n"
    "[ipmx_ssl_sect]\n"
    "system_default = ipmx_ssl_default\n"
    "\n"
    "[ipmx_ssl_default]\n"
    "Ciphersuites = {suite}\n"
)


async def tls13_suite_handshake(
    host: str,
    port: int,
    suite: str,
    *,
    server_ca: Path | None = None,
    client_cert: Path | None = None,
    client_key: Path | None = None,
    server_hostname: str | None = None,
    timeout: float = 5.0,
) -> HandshakeReport:
    """Open one TLS 1.3 handshake offering only the cipher suite ``suite``.

    Python's ``ssl`` module cannot restrict TLS 1.3 cipher suites --
    ``set_ciphers`` covers TLS 1.2 and below -- so the handshake runs in a
    child interpreter whose OpenSSL reads a one-line ``Ciphersuites``
    setting through ``OPENSSL_CONF``. The child runs :func:`tls_handshake`
    unchanged, so everything but the offered suite matches the other
    probes. The peer certificate is not carried back.
    """
    request = {
        "host": host,
        "port": port,
        "server_ca": str(server_ca) if server_ca is not None else None,
        "client_cert": str(client_cert) if client_cert else None,
        "client_key": str(client_key) if client_key else None,
        "server_hostname": server_hostname,
        "timeout": timeout,
    }
    with tempfile.TemporaryDirectory(prefix="ipmx-tls13-") as tmp:
        conf = Path(tmp) / "openssl.cnf"
        conf.write_text(_TLS13_SUITE_CONF.format(suite=suite))
        proc = await asyncio.create_subprocess_exec(
            sys.executable, str(Path(__file__).resolve()),
            "tls13-handshake", json.dumps(request),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=dict(os.environ, OPENSSL_CONF=str(conf)),
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(),
                                              timeout=timeout + 15.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return HandshakeReport(succeeded=False,
                                   error="TLS 1.3 suite probe timed out")
    if proc.returncode != 0:
        detail = err.decode(errors="replace").strip()[-300:]
        return HandshakeReport(succeeded=False,
                               error=f"TLS 1.3 suite probe failed: {detail}")
    return HandshakeReport(**json.loads(out))


def _tls13_handshake_child(request_json: str) -> int:
    """Child side of :func:`tls13_suite_handshake`: one handshake under the
    caller's ``OPENSSL_CONF``, reported as JSON on stdout."""
    req = json.loads(request_json)
    report = asyncio.run(tls_handshake(
        req["host"], req["port"],
        min_version=ssl.TLSVersion.TLSv1_3,
        max_version=ssl.TLSVersion.TLSv1_3,
        server_ca=Path(req["server_ca"]) if req["server_ca"] else None,
        client_cert=Path(req["client_cert"]) if req["client_cert"] else None,
        client_key=Path(req["client_key"]) if req["client_key"] else None,
        server_hostname=req["server_hostname"],
        timeout=req["timeout"],
    ))
    print(json.dumps({
        "succeeded": report.succeeded,
        "negotiated_cipher": report.negotiated_cipher,
        "negotiated_version": report.negotiated_version,
        "error": report.error,
    }))
    return 0


# ---------------------------------------------------------------------------
# SecurityHttpClient — shared session + SSL ctx for HTTPS probes
# ---------------------------------------------------------------------------

@dataclass
class HttpResponse:
    """Trimmed response for assertion convenience."""
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> dict[str, Any]:
        return cast(dict[str, Any], json.loads(self.body))


class SecurityHttpClient:
    """Single-DUT aiohttp client with optional client cert + server CA pin.

    Constructed once per validator run; every check function shares it
    to avoid the cost of opening a new ClientSession per probe.
    """

    def __init__(
        self,
        *,
        server_ca: Path | None = None,
        client_cert: Path | None = None,
        client_key: Path | None = None,
        verify_hostname: bool = True,
    ) -> None:
        self._server_ca = server_ca
        self._client_cert = client_cert
        self._client_key = client_key
        self._verify_hostname = verify_hostname
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "SecurityHttpClient":
        ctx = ssl.create_default_context()
        if self._server_ca is not None:
            ctx.load_verify_locations(str(self._server_ca))
        if not self._verify_hostname:
            ctx.check_hostname = False
        if self._client_cert and self._client_key:
            ctx.load_cert_chain(str(self._client_cert), str(self._client_key))
        # ``force_close=True``: each request opens a fresh TCP+TLS
        # connection rather than reusing a keep-alive socket. The
        # validator generates many small, varied requests with
        # different tokens; HTTP/1.1 keep-alive collides with that
        # pattern (servers occasionally close idle connections and
        # the reused socket fails with ServerDisconnectedError).
        # The cost is a few extra handshakes per run — negligible.
        connector = aiohttp.TCPConnector(ssl=ctx, force_close=True)
        self._session = aiohttp.ClientSession(connector=connector)
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    @property
    def session(self) -> aiohttp.ClientSession:
        if self._session is None:
            raise RuntimeError(
                "SecurityHttpClient must be used as an async context manager",
            )
        return self._session

    # ----- Convenience wrappers -----

    async def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        return await self._request("GET", url, headers=headers)

    async def post(
        self, url: str, *,
        data: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        return await self._request(
            "POST", url, headers=headers, data=data, json_body=json_body,
        )

    async def patch(
        self, url: str, *,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        return await self._request("PATCH", url, headers=headers, json_body=json_body)

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> HttpResponse:
        async with self.session.request(
            method, url, headers=headers, data=data, json=json_body,
        ) as resp:
            body = await resp.read()
            return HttpResponse(
                status=resp.status,
                headers={k: v for k, v in resp.headers.items()},
                body=body,
            )


# ---------------------------------------------------------------------------
# DUT resource fetches
# ---------------------------------------------------------------------------

async def fetch_self(
    client: SecurityHttpClient,
    dut_base_url: str,
    *,
    token: str | None = None,
) -> HttpResponse:
    """``GET /x-nmos/node/v1.3/self``. Used by §8 tag + §9 NAP checks."""
    url = f"{dut_base_url.rstrip('/')}/x-nmos/node/v1.3/self"
    headers = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return await client.get(url, headers=headers)


async def request_with_token(
    client: SecurityHttpClient,
    url: str,
    *,
    method: str = "GET",
    token: str | None = None,
    raw_authorization: str | None = None,
    json_body: dict[str, Any] | None = None,
) -> HttpResponse:
    """Issue ``method`` ``url`` carrying a Bearer token in the
    ``Authorization`` header (or a deliberately-malformed header for
    negative tests).

    ``raw_authorization`` takes precedence over ``token``; pass it to
    test things like ``Authorization: Token <jwt>`` (wrong scheme) or
    ``Authorization: Bearer`` (no value).
    """
    headers: dict[str, str] = {}
    if raw_authorization is not None:
        headers["Authorization"] = raw_authorization
    elif token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if method == "GET":
        return await client.get(url, headers=headers)
    if method == "POST":
        return await client.post(url, json_body=json_body, headers=headers)
    if method == "PATCH":
        return await client.patch(url, json_body=json_body, headers=headers)
    return await client._request(method, url, headers=headers, json_body=json_body)  # noqa: SLF001


async def fetch_jwks(client: SecurityHttpClient, jwks_url: str) -> dict[str, Any]:
    """``GET <jwks_url>``. Used by the §14.3.2 metadata + key check."""
    resp = await client.get(jwks_url)
    return resp.json()


# ---------------------------------------------------------------------------
# WebSocket upgrade probe — §14.3.3.7
# ---------------------------------------------------------------------------

@dataclass
class WsUpgradeReport:
    """Outcome of a WebSocket-upgrade attempt."""
    status: int | None
    succeeded: bool
    www_authenticate: str | None = None
    error: str | None = None


async def ws_upgrade(
    client: SecurityHttpClient,
    url: str,
    *,
    token: str | None = None,
    token_in_query: bool = False,
) -> WsUpgradeReport:
    """Attempt a WS upgrade with Bearer-in-header or Bearer-in-query.

    TR-10-SEC §14.3.3.4 mandates header-only (overrides IS-10 /
    RFC 6750), so the validator drives both forms:

      - ``token_in_query=False, token=<valid>`` → 101 expected.
      - ``token_in_query=True,  token=<valid>`` → 401 expected (the
        DUT must reject query-param auth despite the token being
        well-formed).
    """
    target = url
    headers: dict[str, str] = {}
    if token_in_query and token is not None:
        sep = "&" if "?" in target else "?"
        target = f"{target}{sep}access_token={token}"
    elif token is not None:
        headers["Authorization"] = f"Bearer {token}"

    try:
        async with client.session.ws_connect(
            target, headers=headers, timeout=aiohttp.ClientWSTimeout(ws_close=2.0),
        ) as ws:
            # If we got this far the server accepted the upgrade — that's
            # status 101 conceptually.
            await ws.close()
            return WsUpgradeReport(status=101, succeeded=True)
    except aiohttp.WSServerHandshakeError as exc:
        return WsUpgradeReport(
            status=exc.status,
            succeeded=False,
            www_authenticate=exc.headers.get("WWW-Authenticate") if exc.headers else None,
        )
    except (aiohttp.ClientError, OSError, asyncio.TimeoutError) as exc:
        return WsUpgradeReport(
            status=None, succeeded=False,
            error=f"{type(exc).__name__}: {exc}",
        )


if __name__ == "__main__":
    # Internal entry point: tls13_suite_handshake() re-runs this module under
    # a restricted OPENSSL_CONF.
    if len(sys.argv) == 3 and sys.argv[1] == "tls13-handshake":
        sys.exit(_tls13_handshake_child(sys.argv[2]))
    sys.exit(f"usage: {Path(sys.argv[0]).name} tls13-handshake <request-json>")
