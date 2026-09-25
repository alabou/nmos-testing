#!/usr/bin/env python3
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
"""Run the full IPMX TR-10-SEC certification matrix against a DUT.

One script-invocation:

  1. Launches the DUT in each configuration of the matrix (Config A,
     Config B, Config C, with axis variants for NAP/RAP/OAIM/TCT).
  2. Waits for the DUT to come up.
  3. Runs ``ipmx_validate_security.py`` against it with the matching
     ``--expect-*`` flags and the operator-declared optional-feature
     ``--supports`` list.
  4. Captures one ``--json-out`` per run.
  5. Aggregates every run through ``ipmx_aggregate.py`` into a single
     certification report.

Intended usage::

  python3 ipmx_run_matrix.py --out-dir /tmp/ipmx-matrix

The default matrix targets the in-tree ``nmos-reference`` DUT — for
a third-party DUT, the operator either edits ``MATRIX`` below to
point at their own launch script or invokes this script's
``run_one()`` helper from their own automation.
"""

from __future__ import annotations

import argparse
import json
import shlex
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
import urllib.error
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parent
REF_NODE_DIR = WORKSPACE / "nmos-reference"
CERTS = WORKSPACE / "Certificates" / "build.0"
ROOT_CA = CERTS / "ExampleRootCA.pem"

# Validator-side client cert used for Config A / C (mTLS). We use the
# SNX00000 client identity because the grants CSV already provisions
# ``Example.Company.Device.Client.ABC.SNX00000.example.com`` as a
# client_credentials OAuth client in Keycloak — this lets Stage 2
# under Config C succeed the §14.3.3.6 client_id/cert-SAN binding
# (token client_id == cert SAN). Any other cert would require a
# matching OAuth-client provisioning step.
DEFAULT_CLIENT_CERT = CERTS / "pem" / "ExampleDeviceClient.ABC.SNX00000.chain.pem"
DEFAULT_CLIENT_KEY = CERTS / "key" / "ExampleDeviceClient.ABC.SNX00000.key"

# Default fake-AS host/port — the validator brings up its own AS at
# this endpoint in Stage 1 mode, and the DUT trusts it because the
# fake AS's TLS cert is chained to the same Example root.
FAKE_AS_HOST = "XYZ-SNX00000"
FAKE_AS_PORT = 9444

# Untrusted-AS cert: signed by Certificates/build.1/ExampleRootCA.pem
# which has a DIFFERENT sha256 fingerprint than build.0/ExampleRootCA.pem.
# The DUT's CTCA is build.0/, so a fake AS using this cert is NOT
# trusted. Used by the SEC-14.3.2-12 negative probe — the DUT must
# refuse to fetch JWKS from an AS that doesn't chain to its CTCA.
UNTRUSTED_AS_CERT = WORKSPACE / "Certificates" / "build.1" / "pem" / \
    "ExampleDeviceServer.ABC.SNX00000.chain.pem"
UNTRUSTED_AS_KEY = WORKSPACE / "Certificates" / "build.1" / "key" / \
    "ExampleDeviceServer.ABC.SNX00000.key"

# Registry-proxy fixture endpoint. Used to observe every
# Node→Registry request — SEC-7.2-1 / SEC-7.2-2 / SEC-10.1-1 /
# SEC-10.2-1 / etc. The host name (instead of 127.0.0.1) is chosen so
# the proxy can present its TLS server cert ``ExampleDeviceServer.ABC
# .SNX00000.chain.pem`` (which has ``XYZ-SNX00000`` in its SAN) and
# the DUT will validate it when RAP=1/2. Ports avoid collision with
# the nmos-cpp-registry that developers often run on 8443/8444.
PROXY_HOST = "XYZ-SNX00000"
PROXY_REG_PORT = 8454
PROXY_QUERY_PORT = 8453
PROXY_SERVER_CERT = CERTS / "pem" / "ExampleDeviceServer.ABC.SNX00000.chain.pem"
PROXY_SERVER_KEY = CERTS / "key" / "ExampleDeviceServer.ABC.SNX00000.key"

# Default live-AS (Keycloak) endpoint. Operators with a different
# AS override via ``--keycloak-url``.
KEYCLOAK_HOST = "XYZ-SNX00000"
KEYCLOAK_PORT = 9443
KEYCLOAK_REALM = "TR-10-SEC"
KEYCLOAK_ADMIN_USER = "admin"
KEYCLOAK_ADMIN_PASS = "admin"

# DUT endpoint the validator probes. Reference-node binds to this
# hostname:port; third-party DUTs would override.
DUT_HOST = "XYZ-SNX00001"
DUT_PORT = 7051
CONTROL_PORT = 5050

# Optional features the reference node implements. The operator
# overrides this via ``--supports`` for their own DUT.
DEFAULT_SUPPORTS = (
    "tls13,tls12-ciphers-extended,ecdh-secp521r1,ecdh-x448"
)


# Validator client certs rooted under NESTCA / CESTCA — used by
# split-controls matrix entries where the Node listener (NESTCA) and
# control listener (CESTCA) each accept only their own role's
# client-cert root.
NESTCA_CLIENT_CERT = WORKSPACE / "Certificates" / "build.1" / "pem" / \
    "ExampleDeviceClient.ABC.SNX00000.chain.pem"
NESTCA_CLIENT_KEY = WORKSPACE / "Certificates" / "build.1" / "key" / \
    "ExampleDeviceClient.ABC.SNX00000.key"


@dataclass
class MatrixEntry:
    """One configuration to exercise. The label becomes the JSON
    filename and the column header in the aggregator's matrix."""
    label: str
    launch_script: str
    """Filename in ``nmos-reference/`` (no path)."""
    launch_args: list[str] = field(default_factory=list)
    """Positional + named args for the launch script. For
    OAuth-using configs (B/C), the first two are placeholder for
    ``<as-host> <as-port>`` — the orchestrator fills them based on
    ``--as fake/live/both``."""
    expect: dict[str, str] = field(default_factory=dict)
    """Validator ``--expect-*`` flags as {flag-without-prefix: value}."""
    config: str = "A"
    """The ``--config`` selector."""
    uses_oauth: bool = False
    """Whether this configuration's Node uses OAuth 2.0. Config A
    is mTLS-only and never speaks OAuth; Configs B/C do. Drives
    ``--as`` selection: fake-AS / live-AS variants only apply when
    ``uses_oauth=True``."""
    needs_client_cert: bool = True
    """Whether the validator should present a TLS client cert.
    Config A and C require it (mTLS); Config B does not."""
    server_ca: Path | None = None
    """Override of the trusted-root the validator pins for the DUT's
    server cert. ``None`` means use the validator's default
    (ExampleRootCA.pem, RSA). TCT=1 entries set this to
    ExampleRootCA-bundle.pem (RSA + EC roots) so the validator can
    verify an ECDSA server cert."""
    skip_reason: str | None = None
    """When non-None, the entry is logged + skipped (e.g. a known
    semantic mismatch we don't want to fail the matrix on)."""
    skip_live_reason: str | None = None
    """When non-None, the entry's ``stage=live`` variant is skipped
    with this reason (the ``stage=fake`` variant still runs). Used
    to mark known live-AS limitations such as Config C's §14.3.3.6
    client_id/cert-SAN binding requirement."""
    extra_validator_args: list[str] = field(default_factory=list)
    """Extra CLI args to append to the validator invocation for this
    entry. Used for entry-specific scoping such as
    ``--focus-req-ids SEC-12.10-2,SEC-12.12-2`` on the
    split-controls entry whose only purpose is the isolation test."""
    client_cert: Path | None = None
    """Override of the TLS client cert + key the validator presents.
    None means use ``DEFAULT_CLIENT_CERT`` (SNX00000 under build.0/).
    Set this on split-controls entries so the validator's primary
    client cert chains to NESTCA (matching the Node API listener)."""
    client_key: Path | None = None
    untrusted_as: bool = False
    """When True, the matrix runner spawns the fake AS with a server
    cert signed by a CA the DUT does NOT trust (Certificates/build.1).
    The DUT must refuse to fetch JWKS from this AS — proof that
    §14.3.2-12 ("Node shall validate AS cert against a trusted CA")
    is honoured. The validator's SEC-14.3.2-12 check verifies the
    DUT did NOT complete JWKS pickup within the wait window."""
    tls_group_pin: str | None = None
    """OpenSSL group name (e.g. ``X25519``, ``prime256v1``,
    ``secp521r1``, ``X448``) to pin EVERY test-side TLS endpoint to
    via ``OPENSSL_CONF``. The matrix runner writes a tiny per-entry
    config file containing ``Groups = <name>``, then launches the
    registry-proxy AND the fake-AS subprocesses with that
    ``OPENSSL_CONF`` in their env. Each subprocess's libssl reads
    the file at init and restricts every SSL_CTX it creates to that
    one group. The DUT (running with default OpenSSL groups) can
    only complete handshakes against those subprocesses if its
    CLIENT side supports the pinned group — that's the §8-5
    positive proof. When ``None`` the env is not set; the proxy +
    fake AS run with normal defaults."""


# ---------------------------------------------------------------------------
# The matrix
# ---------------------------------------------------------------------------

MATRIX: list[MatrixEntry] = [
    # ----- Config A (mTLS only, RAAM=0) ----------------------------------
    MatrixEntry(
        label="A-baseline",
        launch_script="start-node1-noauth2.sh",
        launch_args=["", ""],            # no AS host/port needed
        expect={"nap": "2", "rap": "0", "tct": "0"},
        config="A",
        uses_oauth=False,
        needs_client_cert=True,
    ),
    MatrixEntry(
        label="A-tct1-ecdsa",
        launch_script="start-node1-noauth2.sh",
        launch_args=["", "", "", "", "--tct=1"],
        expect={"nap": "2", "rap": "0", "tct": "1"},
        config="A",
        uses_oauth=False,
        needs_client_cert=True,
        # Use the bundle so the validator can verify the DUT's
        # ECDSA-flavoured server cert against the EC root while still
        # trusting the RSA root for everything else.
        server_ca=CERTS / "ExampleRootCA-bundle.pem",
    ),
    # Split-controls: NESTCA (build.1) on the Node IS-04 API listener,
    # CESTCA (build.2) on the control listener (:7052). The validator
    # drives the 2x2 cross-presentation TLS handshake matrix; the
    # symmetric refusals are the wire-observable proof that the two
    # trust stores are physically distinct (§12.10 / §12.12).
    MatrixEntry(
        label="A-split-controls",
        launch_script="start-node1-noauth2.sh",
        launch_args=["", "", "", "", "--split-controls"],
        expect={"nap": "2", "rap": "0", "tct": "0"},
        config="A",
        uses_oauth=False,
        needs_client_cert=True,
        # The standard wire tests would fail under split-controls
        # because the validator presents ONE TLS client cert (build.0-
        # rooted by default) to both listeners, but split-controls
        # configures the Node API to trust NESTCA (build.1) and the
        # control listener to trust CESTCA (build.2) — neither honours
        # the build.0-rooted cert. Per-endpoint client cert routing is
        # a larger refactor; for now scope this entry to its only
        # value-add: the isolation cross-presentation test.
        extra_validator_args=[
            "--focus-req-ids", "SEC-12.10-2,SEC-12.12-2",
        ],
        # NESTCA-rooted primary cert so the validator's pre-checks
        # (which hit the Node API for /self) survive. The cross-test
        # uses both NESTCA and CESTCA certs directly via tls_handshake.
        client_cert=NESTCA_CLIENT_CERT,
        client_key=NESTCA_CLIENT_KEY,
    ),

    # Registry-TLS observation: route the DUT through the proxy in
    # HTTPS-server-auth mode (RAP=1). The proxy presents the Example
    # server cert (its SAN includes XYZ-SNX00000) and observes that
    # every Node→Registry request used TLS — converts SEC-7.2-2 /
    # SEC-10.1-1 / SEC-10.1-2 from NOT-APPLICABLE to PASS. The DUT is
    # otherwise the standard Config A device.
    MatrixEntry(
        label="A-rap1-registry-tls",
        launch_script="start-node1-noauth2.sh",
        launch_args=["", "", "", "", "--rap=1"],
        expect={"nap": "2", "rap": "1", "tct": "0"},
        config="A",
        uses_oauth=False,
        needs_client_cert=True,
    ),
    # Registry-mTLS observation: route the DUT through the proxy in
    # HTTPS-mTLS mode (RAP=2). The DUT presents its
    # ExampleDeviceClient cert to the proxy; the proxy verifies it
    # against ExampleRootCA. Observing peer_cert_present=true across
    # the registration handshake converts SEC-10.2-1 to PASS.
    MatrixEntry(
        label="A-rap2-registry-mtls",
        launch_script="start-node1-noauth2.sh",
        launch_args=["", "", "", "", "--rap=2"],
        expect={"nap": "2", "rap": "2", "tct": "0"},
        config="A",
        uses_oauth=False,
        needs_client_cert=True,
    ),
    # ----- §8-5 per-curve positive coverage --------------------------------
    # Each entry pins the registry proxy's TLS group list to ONE
    # OpenSSL curve via OPENSSL_CONF. The DUT (running with default
    # groups) can only complete the registration handshake if its
    # client-side libssl supports that curve. SEC-8-5 PASSes per
    # entry; the aggregator picks PASS across the four entries to
    # demonstrate full positive coverage of the §8 whitelist
    # (X25519, secp256r1 SHALL; secp521r1, X448 SHOULD).
    #
    # We use RAP=1 (HTTPS server-auth) so the proxy actually does a
    # TLS handshake — RAP=0 would make the proxy serve HTTP and the
    # curve pin would not be exercised on the wire.
    MatrixEntry(
        label="A-curve-X25519",
        launch_script="start-node1-noauth2.sh",
        launch_args=["", "", "", "", "--rap=1"],
        expect={"nap": "2", "rap": "1", "tct": "0"},
        config="A",
        uses_oauth=False,
        needs_client_cert=True,
        tls_group_pin="X25519",
        extra_validator_args=["--focus-req-ids", "SEC-8-5"],
    ),
    MatrixEntry(
        label="A-curve-secp256r1",
        launch_script="start-node1-noauth2.sh",
        launch_args=["", "", "", "", "--rap=1"],
        expect={"nap": "2", "rap": "1", "tct": "0"},
        config="A",
        uses_oauth=False,
        needs_client_cert=True,
        tls_group_pin="P-256",
        extra_validator_args=["--focus-req-ids", "SEC-8-5"],
    ),
    MatrixEntry(
        label="A-curve-secp521r1",
        launch_script="start-node1-noauth2.sh",
        launch_args=["", "", "", "", "--rap=1"],
        expect={"nap": "2", "rap": "1", "tct": "0"},
        config="A",
        uses_oauth=False,
        needs_client_cert=True,
        tls_group_pin="P-521",
        extra_validator_args=["--focus-req-ids", "SEC-8-5"],
    ),
    MatrixEntry(
        label="A-curve-X448",
        launch_script="start-node1-noauth2.sh",
        launch_args=["", "", "", "", "--rap=1"],
        expect={"nap": "2", "rap": "1", "tct": "0"},
        config="A",
        uses_oauth=False,
        needs_client_cert=True,
        tls_group_pin="X448",
        extra_validator_args=["--focus-req-ids", "SEC-8-5"],
    ),
    # ----- §12 GCRL coverage ---------------------------------------------
    # The launch script's --gcrl=<path> forwards to nmos_node.py and
    # is loaded by apply_tr10_tls_restrictions into every TLS context.
    # The bundles were produced by Certificates/gen-crl.sh and live
    # alongside the cert hierarchy. Default (every other entry): no
    # --gcrl flag → no CRL checking, no behaviour change.
    MatrixEntry(
        label="A-crl-empty-baseline",
        launch_script="start-node1-noauth2.sh",
        launch_args=["", "", "", "",
                     f"--gcrl={CERTS / 'gcrl-empty.pem'}"],
        expect={"nap": "2", "rap": "0", "tct": "0"},
        config="A",
        uses_oauth=False,
        needs_client_cert=True,
        # Two CRLs in the empty bundle (root + intermediate) — proves
        # §12.14-6 ("as many CRLs as independent resources") + §12.14-7
        # ("all CAs considered during CRL signature validation").
        extra_validator_args=["--focus-req-ids", "SEC-12.14-6,SEC-12.14-7"],
    ),
    MatrixEntry(
        label="A-crl-revoked-cert",
        launch_script="start-node1-noauth2.sh",
        launch_args=["", "", "", "",
                     f"--gcrl={CERTS / 'gcrl-revoke-snx00000.pem'}"],
        expect={"nap": "2", "rap": "0", "tct": "0"},
        config="A",
        uses_oauth=False,
        needs_client_cert=True,
        # SNX00000's serial is in the bundle's intermediate-CA CRL;
        # any mTLS handshake with that client cert must be refused.
        extra_validator_args=["--focus-req-ids",
                              "SEC-12.8-1,SEC-12.11-1,SEC-12.13-1,SEC-14.3.3.5-3"],
    ),

    # ----- §9.2-2 NAP=1 unrestricted-read --------------------------------
    # Launches the DUT with --nap=1 (which maps to
    # --nodeOptionalClientAuth on reference-node — SSL context's
    # verify_mode = CERT_OPTIONAL; middleware permits GET/HEAD/OPTIONS
    # without a peer cert but rejects state-changing methods unless
    # one is presented). The validator does an anonymous GET against
    # /x-nmos/node/v1.3/self and expects 200 — proof of the
    # "unrestricted read access" rule.
    MatrixEntry(
        label="A-nap1-unrestricted-read",
        launch_script="start-node1-noauth2.sh",
        launch_args=["", "", "", "", "--nap=1"],
        expect={"nap": "1", "rap": "0", "tct": "0"},
        config="A",
        uses_oauth=False,
        # No client cert — the whole point is anonymous access works.
        needs_client_cert=False,
        extra_validator_args=["--focus-req-ids", "SEC-9.2-2"],
    ),
    # ----- §14.3.2-12 untrusted-AS negative probe -------------------------
    # The matrix runner spawns the fake AS with a cert from a CA
    # hierarchy NOT in the DUT's CTCA (Certificates/build.1/). The
    # DUT must refuse to fetch JWKS — wire-observable as the DUT
    # remaining in the "no public keys" state (401 on every auth'd
    # request) for the duration of the test.
    MatrixEntry(
        label="B-untrusted-as",
        launch_script="start-node1-nomtls.sh",
        launch_args=["__AS_HOST__", "__AS_PORT__"],
        expect={"rap": "0", "oaim": "0", "tct": "0"},
        config="B",
        uses_oauth=True,
        needs_client_cert=False,
        untrusted_as=True,
        skip_live_reason="untrusted-AS test is Stage 1 only; Keycloak "
                         "is always trusted in our deployment",
        extra_validator_args=["--focus-req-ids", "SEC-14.3.2-12"],
    ),

    # ----- Config B (OAuth2 + server-TLS, RAAM=1) ------------------------
    MatrixEntry(
        label="B-baseline",
        launch_script="start-node1-nomtls.sh",
        launch_args=["__AS_HOST__", "__AS_PORT__"],
        expect={"rap": "0", "oaim": "0", "tct": "0"},
        config="B",
        uses_oauth=True,
        needs_client_cert=False,
    ),
    MatrixEntry(
        label="B-tct1-ecdsa",
        launch_script="start-node1-nomtls.sh",
        launch_args=["__AS_HOST__", "__AS_PORT__", "", "", "--tct=1"],
        expect={"rap": "0", "oaim": "0", "tct": "1"},
        config="B",
        uses_oauth=True,
        needs_client_cert=False,
        # Use the bundle so the validator can verify the DUT's
        # ECDSA-flavoured server cert against the EC root while still
        # trusting the RSA root for everything else.
        server_ca=CERTS / "ExampleRootCA-bundle.pem",
    ),
    MatrixEntry(
        label="B-oaim1-cert",
        launch_script="start-node1-nomtls.sh",
        launch_args=["__AS_HOST__", "__AS_PORT__", "", "", "--oaim=1"],
        expect={"rap": "0", "oaim": "1", "tct": "0"},
        config="B",
        uses_oauth=True,
        needs_client_cert=False,
    ),

    # ----- Config C (mTLS + OAuth2, RAAM=2) ------------------------------
    MatrixEntry(
        label="C-baseline",
        launch_script="start-node1.sh",
        launch_args=["__AS_HOST__", "__AS_PORT__"],
        expect={"rap": "0", "oaim": "0", "tct": "0"},
        config="C",
        uses_oauth=True,
        needs_client_cert=True,
    ),
]


# ---------------------------------------------------------------------------
# DUT lifecycle helpers
# ---------------------------------------------------------------------------

def _wait_for_dut(timeout_s: float = 25.0) -> bool:
    """Poll the DUT's port until a TCP connection is accepted.

    We deliberately avoid the TLS handshake here: under Config A / C
    (mTLS-required), a plain HTTPS probe without a client cert fails
    the handshake even when the DUT is fully up. A plain TCP connect
    is sufficient as a liveness check — the validator runs its own
    full-stack TLS exchange afterwards."""
    import socket
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection(
                (DUT_HOST, DUT_PORT), timeout=2.0,
            ):
                return True
        except (OSError, socket.timeout):
            pass
        time.sleep(0.5)
    return False


def _kill_dut() -> None:
    """SIGTERM any leftover reference-node process for SNX00001 and
    wait a moment for the socket to free up before the next launch."""
    subprocess.run(
        ["pkill", "-f", "nmos_node.py --nodeSerialNumber SNX00001"],
        check=False,
    )
    time.sleep(2.0)


def _write_group_pin_config(out_dir: Path, label: str, group: str) -> Path:
    """Write a per-entry OpenSSL config file restricting Groups to
    ``group``. Returns the path the matrix runner will export as
    ``OPENSSL_CONF`` for both the proxy + fake AS subprocesses."""
    path = out_dir / f"openssl-groups-{label}.cnf"
    path.write_text(
        "openssl_conf = ipmx_openssl_init\n"
        "\n"
        "[ipmx_openssl_init]\n"
        "ssl_conf = ipmx_ssl_sect\n"
        "\n"
        "[ipmx_ssl_sect]\n"
        "system_default = ipmx_ssl_default\n"
        "\n"
        "[ipmx_ssl_default]\n"
        f"Groups = {group}\n",
    )
    return path


def _spawn_registry_proxy(
    out_dir: Path, label_with_stage: str, *, tls: bool,
    require_client_cert: bool,
    upstream: str | None = None,
    openssl_conf: Path | None = None,
) -> tuple[subprocess.Popen[bytes], Path]:
    """Start the registry-proxy fixture as a subprocess so it can
    observe every Node→Registry request the DUT makes during this run.

    Returns ``(process, log_path)``. The proxy listens on
    ``PROXY_HOST:PROXY_REG_PORT`` (registration) and ``PROXY_QUERY_PORT``
    (query). On SIGTERM at the end of the run it dumps its observed
    request log to ``log_path`` as JSON for the validator to consume.

    The DUT-facing side terminates ``tls`` / ``require_client_cert``
    matching the entry's expected RAP mode — RAP=0 → HTTP, RAP=1 →
    HTTPS server-auth, RAP=2 → HTTPS + mTLS. This is INDEPENDENT of
    the upstream side: ``upstream`` may point at a plain-HTTP
    nmos-cpp-registry on ``http://127.0.0.1:8444`` (or any real
    registry that doesn't itself do TLS) and the proxy still presents
    the correct TLS/mTLS configuration to the DUT. When ``upstream``
    is ``None`` the proxy runs in stub mode and answers IS-04
    registration calls in-process.
    """
    import socket
    log_path = out_dir / f"proxy-{label_with_stage}.json"
    stderr_log = out_dir / f"proxy-{label_with_stage}.log"
    cmd = [
        sys.executable,
        str(HERE / "ipmx_registry_proxy.py"),
        "--host", PROXY_HOST,
        "--port", str(PROXY_REG_PORT),
        "--query-port", str(PROXY_QUERY_PORT),
        "--log-out", str(log_path),
    ]
    if upstream:
        cmd += ["--mode", "forward", "--upstream", upstream]
    else:
        cmd += ["--mode", "stub"]
    if tls:
        cmd += [
            "--tls",
            "--cert", str(PROXY_SERVER_CERT),
            "--key", str(PROXY_SERVER_KEY),
        ]
        if require_client_cert:
            cmd += [
                "--require-client-cert",
                "--client-ca", str(ROOT_CA),
            ]
    import os as _os
    proxy_env = _os.environ.copy()
    if openssl_conf is not None:
        proxy_env["OPENSSL_CONF"] = str(openssl_conf)
    with open(stderr_log, "w") as f:
        proc = subprocess.Popen(
            cmd, stdout=f, stderr=subprocess.STDOUT, env=proxy_env,
        )
    deadline = time.time() + 5.0
    while time.time() < deadline:
        try:
            with socket.create_connection(
                (PROXY_HOST, PROXY_REG_PORT), timeout=0.3,
            ):
                return (proc, log_path)
        except OSError:
            time.sleep(0.1)
    proc.terminate()
    raise RuntimeError(
        f"registry proxy did not bind {PROXY_HOST}:{PROXY_REG_PORT} "
        f"within 5s — see {stderr_log}"
    )


def _spawn_fake_as(
    out_dir: Path, label_with_stage: str,
    *, host: str, port: int, cert: Path, key: Path,
    api_selector: str = "TR-10-SEC",
    default_aud: str | None = None,
    openssl_conf: Path | None = None,
) -> subprocess.Popen[bytes]:
    """Spawn the fake AS as a subprocess so per-entry OPENSSL_CONF
    can pin its TLS group. Returns the Popen handle for SIGTERM at
    cleanup time."""
    import os as _os
    import socket
    stderr_log = out_dir / f"fakeas-{label_with_stage}.log"
    cmd = [
        sys.executable,
        str(HERE / "ipmx_fake_as.py"),
        "--host", host,
        "--port", str(port),
        "--cert", str(cert),
        "--key", str(key),
        "--api-selector", api_selector,
    ]
    if default_aud:
        cmd += ["--default-aud", default_aud]
    fa_env = _os.environ.copy()
    if openssl_conf is not None:
        fa_env["OPENSSL_CONF"] = str(openssl_conf)
    with open(stderr_log, "w") as f:
        proc = subprocess.Popen(
            cmd, stdout=f, stderr=subprocess.STDOUT, env=fa_env,
        )
    deadline = time.time() + 5.0
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.3):
                return proc
        except OSError:
            time.sleep(0.1)
    proc.terminate()
    raise RuntimeError(
        f"fake AS did not bind {host}:{port} within 5s — see {stderr_log}"
    )


def _stop_fake_as(proc: subprocess.Popen[bytes]) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=10.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5.0)
    time.sleep(0.5)


def _stop_registry_proxy(
    proc: subprocess.Popen[bytes], log_path: Path,
) -> None:
    """SIGTERM the proxy and wait for it to flush the JSON log file."""
    proc.terminate()
    try:
        proc.wait(timeout=10.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5.0)
    # Give the OS a beat to release the bound ports before the next
    # entry's proxy spawn.
    time.sleep(0.5)


# ---------------------------------------------------------------------------
# Per-run orchestration
# ---------------------------------------------------------------------------

def run_one(
    entry: MatrixEntry, *,
    out_dir: Path,
    supports: str,
    stage: str = "fake",
    verbose: bool = False,
    registry_upstream: str | None = None,
) -> tuple[bool, Path | None, str]:
    """Launch the DUT in ``entry``'s configuration, run the validator,
    capture the JSON dump. Returns ``(success, json_path, summary)``.

    ``stage`` is ``"fake"`` or ``"live"``. For ``uses_oauth=True``
    entries it selects the AS the DUT points at (validator's own
    fake AS vs the live Keycloak) and the validator flags
    (--fake-as vs --no-fake-as + --keycloak-url +
    --provision-keycloak + --scenarios-csv).

    For ``uses_oauth=False`` entries (Config A — mTLS only) the
    stage is irrelevant; the entry runs once and ignores it."""
    if entry.skip_reason is not None:
        return (True, None, f"SKIPPED — {entry.skip_reason}")

    # Each (entry, stage) combination produces a distinct JSON file
    # so the aggregator can show fake-AS and live-AS cells side-by-
    # side without label collisions.
    suffix = f"-{stage}" if entry.uses_oauth else ""
    label_with_stage = f"{entry.label}{suffix}"
    json_path = out_dir / f"run-{label_with_stage}.json"
    dut_log = out_dir / f"dut-{label_with_stage}.log"
    validator_log = out_dir / f"validator-{label_with_stage}.log"

    # 1. Start the registry-proxy fixture BEFORE the DUT so the Node's
    #    very first registration attempt is observed. Proxy mode is
    #    derived from the entry's expected RAP: 0→HTTP, 1→HTTPS,
    #    2→HTTPS+mTLS. The proxy dumps its observed request log to
    #    ``proxy_log`` on SIGTERM at the end of this run.
    _kill_dut()
    rap_mode = entry.expect.get("rap", "0")
    proxy_tls = rap_mode != "0"
    proxy_mtls = rap_mode == "2"
    # Per-curve entries: generate the OpenSSL config that restricts
    # both the proxy and the (Config B/C) fake AS to a single ECDH
    # group via OPENSSL_CONF in their subprocess envs.
    group_pin_cfg: Path | None = None
    if entry.tls_group_pin:
        group_pin_cfg = _write_group_pin_config(
            out_dir, label_with_stage, entry.tls_group_pin,
        )
    spawned_proxy, proxy_log = _spawn_registry_proxy(
        out_dir, label_with_stage,
        tls=proxy_tls, require_client_cert=proxy_mtls,
        upstream=registry_upstream,
        openssl_conf=group_pin_cfg,
    )
    proxy_proc: subprocess.Popen[bytes] | None = spawned_proxy
    fakeas_proc: subprocess.Popen[bytes] | None = None
    # For OAuth-using entries with a curve pin, spawn the fake AS in
    # a separate subprocess so its libssl picks up OPENSSL_CONF too.
    # (In-process fake AS — used by the default Stage 1 path — can't
    # be group-pinned because the validator's libssl is already
    # initialized with system defaults.) The validator gets
    # ``--no-fake-as`` and points the DUT at this subprocess.
    # Pick cert/key for the fake AS subprocess. Default is a server
    # cert chained to ExampleRootCA (DUT trusts it). The untrusted-AS
    # entries use a cert from a DIFFERENT CA hierarchy (build.1) so
    # the DUT refuses to talk to it — the wire test for §14.3.2-12.
    if entry.untrusted_as:
        fake_as_cert = UNTRUSTED_AS_CERT
        fake_as_key = UNTRUSTED_AS_KEY
    else:
        fake_as_cert = CERTS / "pem" / "ExampleDeviceServer.ABC.SNX00000.chain.pem"
        fake_as_key = CERTS / "key" / "ExampleDeviceServer.ABC.SNX00000.key"
    if (entry.tls_group_pin or entry.untrusted_as) and entry.uses_oauth:
        try:
            fakeas_proc = _spawn_fake_as(
                out_dir, label_with_stage,
                host=FAKE_AS_HOST, port=FAKE_AS_PORT,
                cert=fake_as_cert,
                key=fake_as_key,
                default_aud=DUT_HOST,
                openssl_conf=group_pin_cfg,
            )
        except RuntimeError as exc:
            _stop_registry_proxy(spawned_proxy, proxy_log)
            return (False, None, f"fake AS failed to start: {exc}")

    launcher = REF_NODE_DIR / entry.launch_script
    if not launcher.exists():
        if proxy_proc is not None:
            _stop_registry_proxy(proxy_proc, proxy_log)
        return (False, None, f"launcher missing: {launcher}")
    # Substitute the AS-host / AS-port placeholders in launch_args.
    # For uses_oauth=False entries the placeholders don't appear
    # and the loop is a no-op.
    if stage == "live":
        as_host, as_port = KEYCLOAK_HOST, str(KEYCLOAK_PORT)
    else:
        as_host, as_port = FAKE_AS_HOST, str(FAKE_AS_PORT)
    resolved_args = [
        as_host if a == "__AS_HOST__" else
        as_port if a == "__AS_PORT__" else a
        for a in entry.launch_args
    ]
    # Inject the registry-proxy host:port at positions $3 / $4 so the
    # DUT routes its IS-04 registration traffic through the proxy.
    # The launch scripts read $3/$4 as the registry host/port; if the
    # entry already supplied non-empty values there we preserve them.
    while len(resolved_args) < 4:
        resolved_args.append("")
    if not resolved_args[2]:
        resolved_args[2] = PROXY_HOST
    if not resolved_args[3]:
        resolved_args[3] = str(PROXY_REG_PORT)
    cmd = [str(launcher), *resolved_args]
    with open(dut_log, "w") as dut_out:
        proc = subprocess.Popen(
            cmd, cwd=str(REF_NODE_DIR),
            stdout=dut_out, stderr=subprocess.STDOUT,
            preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_IGN),
        )

    try:
        # 2. Wait for the DUT to come up.
        if not _wait_for_dut(timeout_s=25.0):
            return (False, None, "DUT did not respond within 25s — see "
                                 f"{dut_log}")

        # 2b. Give the DUT a moment to push its initial registration
        # to the proxy, then stop the proxy so it flushes its
        # request log to disk. The validator reads the log statically
        # — heartbeats / re-registrations that arrive AFTER this
        # point hit a now-closed port (the proxy is gone) and the
        # DUT's retry loop logs them but otherwise carries on. This
        # keeps the file simple: written once, read once, no races.
        time.sleep(3.0)
        if proxy_proc is not None:
            _stop_registry_proxy(proxy_proc, proxy_log)
            proxy_proc = None

        # 3. Build validator command.
        v_cmd = [
            sys.executable, str(HERE / "ipmx_validate_security.py"),
            "--dut", f"{DUT_HOST}:{DUT_PORT}",
            "--control-port", str(CONTROL_PORT),
            "--config", entry.config,
            "--instance-id", "SNX00001",
            "--supports", supports,
            "--json-out", str(json_path),
        ]
        for axis, value in entry.expect.items():
            v_cmd += [f"--expect-{axis}", value]
        # AS-side validator flags. For Config A (uses_oauth=False)
        # neither stage matters — no fake AS, no Keycloak. For
        # Configs B/C the stage picks which Stage of testing this
        # run is part of: Stage 1 (fake-AS adversarial probes) or
        # Stage 2 (live Keycloak + scenarios CSV + provisioning).
        if entry.uses_oauth and stage == "live":
            v_cmd += [
                "--no-fake-as",
                "--keycloak-url", f"https://{KEYCLOAK_HOST}:{KEYCLOAK_PORT}",
                "--keycloak-realm", KEYCLOAK_REALM,
                "--keycloak-admin-user", KEYCLOAK_ADMIN_USER,
                "--keycloak-admin-pass", KEYCLOAK_ADMIN_PASS,
                "--provision-keycloak",
            ]
        elif entry.uses_oauth and (entry.tls_group_pin or entry.untrusted_as):
            # Per-curve / untrusted-AS entries: matrix runner already
            # spawned the fake AS subprocess with the right cert (or
            # OPENSSL_CONF). Validator must NOT spawn its own in-
            # process AS — would collide on port and would defeat the
            # per-entry fixture purpose.
            v_cmd += ["--no-fake-as"]
        elif entry.uses_oauth:
            v_cmd += [
                "--fake-as",
                "--fake-as-host", FAKE_AS_HOST,
                "--fake-as-port", str(FAKE_AS_PORT),
            ]
        else:
            v_cmd += ["--no-fake-as"]
        if entry.tls_group_pin:
            v_cmd += ["--expect-tls-group", entry.tls_group_pin]
        if entry.needs_client_cert:
            cert = entry.client_cert or DEFAULT_CLIENT_CERT
            key = entry.client_key or DEFAULT_CLIENT_KEY
            v_cmd += [
                "--client-cert", str(cert),
                "--client-key", str(key),
            ]
        if entry.server_ca is not None:
            v_cmd += ["--server-ca", str(entry.server_ca)]
        # Tell the validator where the proxy will write its observed
        # registry-traffic log + which RAP mode was expected, so the
        # §7.2 / §10 checks can grade what the DUT actually did.
        v_cmd += [
            "--registry-proxy-log", str(proxy_log),
            "--registry-proxy-rap", rap_mode,
        ]
        if entry.extra_validator_args:
            v_cmd += list(entry.extra_validator_args)

        if verbose:
            print(f"    $ {shlex.join(v_cmd)}")

        # 4. Run validator with a hard timeout. For live-AS runs we
        # set REQUESTS_CA_BUNDLE so the keycloak/ token-fetch helpers
        # (plain ``requests`` calls under the hood) trust Keycloak's
        # TLS server cert via the Example root.
        import os
        env = os.environ.copy()
        if stage == "live":
            env["REQUESTS_CA_BUNDLE"] = str(ROOT_CA)
        with open(validator_log, "w") as v_out:
            v_proc = subprocess.run(
                v_cmd, stdout=v_out, stderr=subprocess.STDOUT,
                timeout=180, env=env,
            )
        # 5. Extract the summary line.
        summary = _extract_summary(validator_log)
        return (v_proc.returncode == 0, json_path, summary)
    except subprocess.TimeoutExpired:
        return (False, None, "validator timed out after 180s")
    finally:
        _kill_dut()
        # Stop the proxy only if it's still running (it normally
        # gets stopped in step 2b above, but a startup failure may
        # short-circuit past that).
        if proxy_proc is not None:
            _stop_registry_proxy(proxy_proc, proxy_log)
        if fakeas_proc is not None:
            _stop_fake_as(fakeas_proc)


def _extract_summary(log: Path) -> str:
    """Read the validator's stdout log and return the summary line."""
    try:
        for line in log.read_text(errors="replace").splitlines():
            if line.startswith("TR-10-SEC:"):
                return line
    except OSError:
        pass
    return "(no summary line — check log)"


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def aggregate(
    json_paths: list[Path], *,
    out_dir: Path,
) -> tuple[int, str]:
    """Run ``ipmx_aggregate.py`` over ``json_paths`` and return
    ``(exit_code, summary)``."""
    if not json_paths:
        return (0, "(no runs to aggregate)")
    md = out_dir / "aggregate.md"
    aj = out_dir / "aggregate.json"
    cmd = [
        sys.executable, str(HERE / "ipmx_aggregate.py"),
        *[str(p) for p in json_paths],
        "--out", str(md), "--json-out", str(aj),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    # Read the aggregate JSON to build the headline.
    try:
        d = json.loads(aj.read_text())
        counts: dict[tuple[str, str], int] = {}
        for r in d["requirements"]:
            key = (r["level"], r["verdict"])
            counts[key] = counts.get(key, 0) + 1
        lines = [
            f"Aggregate report: {md}",
            f"Aggregate JSON:   {aj}",
            "",
            "Per-level / verdict counts:",
        ]
        for level in ("shall", "should", "info"):
            verdicts = ["PASS", "FAIL", "CANNOT-TEST",
                        "NEEDS-FIXTURE", "NOT-APPLICABLE",
                        "OPTIONAL-ABSENT"]
            row = [f"{counts.get((level, v), 0):>4} {v}" for v in verdicts]
            if any(counts.get((level, v), 0) for v in verdicts):
                lines.append(f"  {level.upper():<6}  " + "  ".join(row))
        return (result.returncode, "\n".join(lines))
    except (OSError, json.JSONDecodeError) as exc:
        return (result.returncode, f"aggregate-parse error: {exc}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _cli() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run the full IPMX TR-10-SEC certification matrix.",
    )
    p.add_argument(
        "--out-dir", type=Path, default=Path("/tmp/ipmx-matrix"),
        help="Where to write per-run JSON + aggregate (default: /tmp/ipmx-matrix).",
    )
    p.add_argument(
        "--supports", default=DEFAULT_SUPPORTS,
        help=(
            "Comma-separated optional-feature tags the device supports "
            f"(default for reference-node: {DEFAULT_SUPPORTS!r})."
        ),
    )
    p.add_argument(
        "--only", default=None,
        help="Comma-separated entry labels to run (default: all).",
    )
    p.add_argument(
        "--verbose", action="store_true",
        help="Print the validator command for each entry.",
    )
    p.add_argument(
        "--keep-going", action="store_true",
        help="Continue after a per-run failure (default: stop).",
    )
    p.add_argument(
        "--as", dest="as_stage",
        choices=["fake", "live", "both"], default="fake",
        help=(
            "AS to drive for OAuth-using configurations (B/C). "
            "'fake' (default) uses the validator's in-process Stage "
            "1 fake AS for adversarial probes. 'live' uses the real "
            "Keycloak at XYZ-SNX00000:9443 and runs the Stage 2 "
            "scenarios CSV (provisioning the realm from "
            "keycloak/TR-10-SEC_grants.csv). 'both' runs each OAuth "
            "configuration TWICE (once each), giving full Stage 1 + "
            "Stage 2 coverage in one invocation."
        ),
    )
    p.add_argument(
        "--registry-upstream", default=None,
        help=(
            "Optional URL of a real upstream IS-04 registry "
            "(e.g. http://127.0.0.1:8444 for a local nmos-cpp-registry). "
            "When set, the proxy runs in forward mode — terminating "
            "TLS/mTLS on the DUT-facing side per the entry's RAP mode "
            "AND forwarding to the real (possibly plain-HTTP) registry "
            "on the upstream side. Without this flag the proxy answers "
            "registration calls itself in stub mode."
        ),
    )
    return p.parse_args()


def main() -> int:
    cli = _cli()
    cli.out_dir.mkdir(parents=True, exist_ok=True)
    # Clear previous JSON dumps so the aggregator only sees this run.
    for stale in cli.out_dir.glob("run-*.json"):
        stale.unlink()

    only = set(cli.only.split(",")) if cli.only else None
    entries = [e for e in MATRIX if only is None or e.label in only]
    if not entries:
        print("error: --only filtered out every matrix entry", file=sys.stderr)
        return 2

    # Expand the matrix per --as. Each OAuth-using entry produces
    # one or two scheduled runs depending on the flag; non-OAuth
    # entries (Config A) always produce exactly one run.
    if cli.as_stage == "fake":
        stages_for_oauth: list[str] = ["fake"]
    elif cli.as_stage == "live":
        stages_for_oauth = ["live"]
    else:  # both
        stages_for_oauth = ["fake", "live"]
    schedule: list[tuple[MatrixEntry, str]] = []
    for entry in entries:
        if entry.uses_oauth:
            for stage in stages_for_oauth:
                if stage == "live" and entry.skip_live_reason:
                    print(f"  ⏭  Skipping {entry.label} [stage=live] — "
                          f"{entry.skip_live_reason}")
                    continue
                schedule.append((entry, stage))
        else:
            schedule.append((entry, "n/a"))

    print(f"IPMX TR-10-SEC matrix — {len(schedule)} run(s) "
          f"(--as {cli.as_stage})")
    print(f"  out-dir   = {cli.out_dir}")
    print(f"  supports  = {cli.supports}")
    print()

    json_paths: list[Path] = []
    failures: list[str] = []
    for i, (entry, stage) in enumerate(schedule, start=1):
        stage_label = f" [stage={stage}]" if entry.uses_oauth else ""
        print(f"─── [{i}/{len(schedule)}] {entry.label}{stage_label} "
              f"(config {entry.config}, expect {entry.expect}) ───")
        t0 = time.time()
        ok, json_path, summary = run_one(
            entry, out_dir=cli.out_dir, supports=cli.supports,
            stage=stage if entry.uses_oauth else "fake",
            verbose=cli.verbose,
            registry_upstream=cli.registry_upstream,
        )
        dt = time.time() - t0
        print(f"  {summary}")
        print(f"  ({dt:.1f}s)")
        if json_path is not None:
            json_paths.append(json_path)
        if not ok:
            failures.append(f"{entry.label}{stage_label}")
            if not cli.keep_going:
                print(f"  ✗ FAIL — stopping (use --keep-going to continue)",
                      flush=True)
                break
        print(flush=True)

    print("─── Aggregation ───")
    code, agg_summary = aggregate(json_paths, out_dir=cli.out_dir)
    print(agg_summary)
    print()

    if failures:
        print(f"Per-run failures: {failures}")
        return 1
    if code != 0:
        print("Aggregate verdict: FAIL — at least one SHALL failed.")
        return 1
    print("Aggregate verdict: PASS — every SHALL is PASS, FAIL, or "
          "covered by another run.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
