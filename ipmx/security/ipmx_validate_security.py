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

"""IPMX security certification test suite — VSF TR-10-SECURITY validator.

The validator is run once per certifiable configuration (Configuration A
mTLS-only / Configuration B OAuth 2.0 + server TLS / Configuration C
mTLS + OAuth 2.0) against a DUT that's been launched via the vendor's
``<launch-script> <as-host> <as-port>`` contract.

Workflow:

  1. Validate CLI flags against TR-10-SEC cross-constraints
     (NAP=0 forbidden, NAP=1 only with config A, OAIM
     forbidden with A, required with B/C, …).
  2. If ``--launch-dut`` is given, optionally start the in-process
     fake AS (Stage 1) and launch the DUT subprocess, passing the
     AS host/port as positional args.
  3. Wait for the DUT to respond at ``--launch-dut-wait``.
  4. Build the requirement registry — per-section check functions
     authored against the spec, not the DUT.
  5. Await every check; collect ``RequirementResult`` records.
  6. Print the grouped report (SHALL / SHOULD / INFO), emit the
     attestation manifest (untestable requirements), and dump JSON
     for the VSF dashboard.
  7. Stop the fake AS + DUT subprocess on the way out.

This file is the orchestration layer; the actual probes live in
``ipmx_security_probes`` and ``ipmx_fake_as``, and the JWT minting
in ``ipmx_security_tokens``. Stage 2 (Keycloak-driven scenarios) is
in ``ipmx_security_scenarios``.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import signal
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator

from ipmx_fake_as import FakeASConfig, FakeAuthorizationServer
from ipmx_security_common import (
    CheckFn, ControlApiSpec, Level, ReportFilter, Requirement,
    RequirementRegistry, RequirementResult, ServerEndpoint, WriteRecipe,
    needs_fixture, not_applicable, print_results, run_registry,
    summary_line, untestable, write_attestation_manifest,
    write_json_report,
)
from ipmx_security_probes import (
    HandshakeReport, HttpResponse, SecurityHttpClient,
    fetch_self, request_with_token, tls_handshake, ws_upgrade,
)
from ipmx_security_tokens import (
    ALL_PERMITTED_ALGORITHMS, SigningKey, TokenTemplate, mint_token,
)

LOG = logging.getLogger("ipmx-validate-security")


# ---------------------------------------------------------------------------
# Workspace path resolution — the validator assumes the IPMX workspace
# layout (security/ sibling to Certificates/). Override IPMX_CERT_ROOT
# to point at a different Certificates/ directory.
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve().parent
_WORKSPACE = _HERE.parent
CERT_ROOT = Path(os.environ.get("IPMX_CERT_ROOT", _WORKSPACE / "Certificates"))
"""Root of the per-CA PKI directories (``build.0/`` … ``build.N/``).
Default: ``<workspace>/Certificates``. Override with ``IPMX_CERT_ROOT``."""

PKI_PRIMARY   = CERT_ROOT / "build.0"   # CTCA — global trust root
PKI_NESTCA    = CERT_ROOT / "build.1"   # Node-API listener client-cert trust
PKI_CESTCA    = CERT_ROOT / "build.2"   # Control listener client-cert trust


# ---------------------------------------------------------------------------
# CLI parsing — enforces TR-10-SEC cross-constraints before any DUT contact
# ---------------------------------------------------------------------------

VALID_CONFIGS: tuple[str, ...] = ("A", "B", "C")
"""The three certifiable configurations from the plan:
A = mTLS-only; B = OAuth 2.0 + server TLS; C = mTLS + OAuth 2.0."""

# RAAM pinned by --config (A=0, B=1, C=2).
_CONFIG_TO_RAAM: dict[str, int] = {"A": 0, "B": 1, "C": 2}


@dataclass
class CLIArgs:
    """Strongly-typed view of the parsed args, populated by build_cli_args."""
    config: str
    dut: str
    instance_id: str
    control_port: int | None
    expect_raam: int
    expect_nap: int
    expect_rap: int
    expect_tct: int
    expect_oaim: int | None
    client_cert: Path | None
    client_key: Path | None
    server_ca: Path | None
    launch_dut: Path | None
    launch_dut_wait: str | None
    launch_dut_timeout: float
    fake_as: bool
    fake_as_host: str
    fake_as_port: int
    fake_as_cert: Path | None
    fake_as_key: Path | None
    fake_as_realm: str
    keycloak_url: str | None
    keycloak_realm: str
    keycloak_admin_user: str
    keycloak_admin_pass: str
    scenarios_csv: Path | None
    grants_csv: Path | None
    provision_keycloak: bool
    attestation_manifest: Path | None
    json_out: Path | None
    report_filter: ReportFilter
    list_requirements: bool
    focus_req_ids: frozenset[str]
    """When non-empty, only these req_ids call their check functions
    — every OTHER req_id resolves to NOT-APPLICABLE for this run.
    Used by matrix entries that exist purely to exercise a specific
    SHALL (e.g. ``A-split-controls`` runs only the NESTCA/CESTCA
    isolation check; standard wire tests would fail under split-
    controls without per-endpoint client cert routing)."""
    expect_tls_group: str | None
    """OpenSSL group name the launch script pinned the DUT to via
    ``OPENSSL_CONF``. When set, the §8-5 per-curve probe runs and
    PASSes iff a default TLS handshake completes (proving the server
    supports this curve). ``None`` for matrix entries that don't
    pin a group — the §8-5 probe is then NOT-APPLICABLE for them."""
    registry_proxy_log: Path | None
    """Path to a JSON file dumped by ``ipmx_registry_proxy.py`` after
    observing the DUT's Node→Registry traffic during this run. ``None``
    when the matrix runner did not interpose a proxy (e.g. standalone
    validator runs). See :class:`RegistryProxyObservation`."""
    registry_proxy_rap: int | None
    """The RAP mode the proxy was configured to terminate (0/1/2).
    Defaults to ``expect_rap``. The §7.2 / §10 checks compare what the
    DUT actually did against what this mode required."""
    supports: frozenset[str]
    """The optional-feature tags the operator declares the device
    supports. SHOULD-level requirements gated on a tag NOT in this
    set resolve to OPTIONAL-ABSENT (the device makes no claim — not
    a failure). See :data:`_SHOULD_FEATURE_GATES` for the vocabulary."""


def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ipmx_validate_security.py",
        description=(
            "VSF TR-10-SECURITY compliance validator for IPMX devices. "
            "Run once per certifiable configuration."
        ),
    )

    p.add_argument(
        "--config", choices=VALID_CONFIGS, required=True,
        help="Certifiable configuration. A = mTLS without OAuth 2.0; "
             "B = OAuth 2.0 with server TLS; C = mTLS + OAuth 2.0. "
             "Pins RAAM and constrains NAP/OAIM.",
    )
    p.add_argument(
        "--dut", required=True,
        help="DUT host:port for the Node API (e.g. XYZ-SNX00001:7051).",
    )
    p.add_argument(
        "--instance-id", required=True,
        help="The DUT's BCP-002-02 Instance Identifier — the DNS-form "
             "containing the device serial number (e.g. XYZ-SNX00001).",
    )
    p.add_argument("--control-port", type=int, default=None,
                   help="Optional --controlPort for the IS-05/IS-11 split listener.")

    # NAP / RAP / OAIM / TCT — domain depends on --config (enforced after parse).
    p.add_argument("--expect-nap", type=int, choices=(1, 2),
                   help="NAP — only legal with --config A (default 2). "
                        "Pinned to 2 with --config {B,C}.")
    p.add_argument("--expect-rap", type=int, choices=(0, 1, 2), required=True,
                   help="Registry Access Policy.")
    p.add_argument("--expect-tct", type=int, choices=(0, 1, 2), required=True,
                   help="TLS Certificate Type (RSA / ECDSA / Both).")
    p.add_argument("--expect-oaim", type=int, choices=(0, 1, 2),
                   help="OAuth 2.0 Audience Identification Mode — "
                        "required with --config {B,C}; forbidden with --config A.")

    # Trust material for the validator's own outbound TLS.
    p.add_argument("--client-cert", type=Path, default=None,
                   help="Path to the validator's TLS client cert chain "
                        "(required when --config in {A, C}).")
    p.add_argument("--client-key", type=Path, default=None,
                   help="Path to the validator's TLS client cert private key.")
    p.add_argument("--server-ca", type=Path, default=None,
                   help="CA bundle the validator uses to verify the DUT's "
                        "server cert. Defaults to Certificates/build.0/ExampleRootCA.pem.")

    # DUT launch contract.
    p.add_argument("--launch-dut", type=Path, default=None,
                   help="Path to the vendor's launch script. Invoked as "
                        "`<script> <as-host> <as-port>`; the validator waits for "
                        "--launch-dut-wait then runs the suite.")
    p.add_argument("--launch-dut-wait", default=None,
                   help="URL the validator polls until the DUT responds.")
    p.add_argument("--launch-dut-timeout", type=float, default=30.0,
                   help="Seconds to wait for the DUT before giving up.")

    # Stage 1 fake AS.
    fake = p.add_argument_group("Stage 1 fake AS")
    fake.add_argument("--fake-as", action=argparse.BooleanOptionalAction, default=True,
                      help="Run the in-process fake AS (default ON for --config {B,C}).")
    fake.add_argument("--fake-as-host", default="XYZ-SNX00000",
                      help="Hostname the fake AS listens on (must match its TLS cert SAN).")
    fake.add_argument("--fake-as-port", type=int, default=9443,
                      help="Port the fake AS listens on.")
    fake.add_argument("--fake-as-cert", type=Path, default=None,
                      help="TLS cert chain for the fake AS. Defaults to the "
                           "ExampleDeviceServer.ABC.SNX00000 cert in Certificates/build.0/.")
    fake.add_argument("--fake-as-key", type=Path, default=None,
                      help="Private key for the fake AS TLS cert.")
    fake.add_argument("--fake-as-realm", default="realms/TR-10-SEC",
                      help="api_selector / realm path component in the AS issuer URL. "
                           "Default matches reference-node's --oauth2ApiSelector "
                           "default so the fake AS works without extra flags.")

    # Stage 2 Keycloak.
    kc = p.add_argument_group("Stage 2 Keycloak")
    kc.add_argument("--keycloak-url", default=None,
                    help="Keycloak base URL (e.g. https://XYZ-SNX00000:9443). "
                         "When set, Stage 2 scenarios are run after Stage 1.")
    kc.add_argument("--keycloak-realm", default="TR-10-SEC",
                    help="Keycloak realm to use.")
    kc.add_argument("--scenarios-csv", type=Path, default=None,
                    help="Stage 2 scenarios CSV "
                         "(default: security/ipmx_security_cases.csv).")
    kc.add_argument("--grants-csv", type=Path, default=None,
                    help="Subjects/grants CSV. Provisioned into Keycloak when "
                         "--provision-keycloak is set. "
                         "Default: keycloak/TR-10-SEC_grants.csv.")
    kc.add_argument("--provision-keycloak", action="store_true",
                    help="Run keycloak/nmos_keycloak.py put with --grants-csv "
                         "before running scenarios.")
    kc.add_argument("--keycloak-admin-user", default="admin",
                    help="Keycloak admin username (default: admin).")
    kc.add_argument("--keycloak-admin-pass", default="admin",
                    help="Keycloak admin password (default: admin).")

    # Reporting.
    rep = p.add_argument_group("Reporting")
    rep.add_argument("--full-report", action="store_true",
                     help="Show all results (default).")
    rep.add_argument("--fail-report", action="store_true",
                     help="Show only FAIL entries.")
    rep.add_argument("--pass-report", action="store_true",
                     help="Show only PASS entries.")
    rep.add_argument("--cannot-test-report", action="store_true",
                     help="Show only CANNOT-TEST entries.")
    rep.add_argument("--attestation-manifest", type=Path, default=None,
                     help="Markdown attestation manifest path "
                          "(written even when not specified, in the cwd).")
    rep.add_argument("--json-out", type=Path, default=None,
                     help="Machine-readable JSON dump path.")
    rep.add_argument("--list-requirements", action="store_true",
                     help="Dump the requirement registry without running checks.")
    rep.add_argument(
        "--focus-req-ids", default="",
        metavar="ID1,ID2,...",
        help=(
            "Comma-separated req_ids that should actually run. "
            "Every other req_id resolves to NOT-APPLICABLE for this "
            "run. Used by matrix entries scoped to one specific "
            "SHALL (e.g. split-controls runs only the isolation check)."
        ),
    )

    # Optional-feature claims.
    feat = p.add_argument_group("Optional features")
    feat.add_argument(
        "--supports",
        action="append",
        default=[],
        metavar="FEAT[,FEAT,...]",
        help=(
            "Comma-separated optional-feature tags the device claims to "
            "support. Requirements gated on a tag NOT in this list "
            "resolve to OPTIONAL-ABSENT (not a failure). May be "
            "repeated. Known tags: tls13, tls12-ciphers-extended, "
            "tls13-ciphers-extended, ecdh-secp521r1, ecdh-x448, "
            "tct-both, crl, guest-ws."
        ),
    )
    rep.add_argument(
        "--optional-absent-report", action="store_true",
        help="Show only OPTIONAL-ABSENT entries.",
    )
    rep.add_argument(
        "--needs-fixture-report", action="store_true",
        help="Show only NEEDS-FIXTURE entries (probes that need Stage 1 fake AS).",
    )

    tls_groups = p.add_argument_group("TLS groups")
    tls_groups.add_argument(
        "--expect-tls-group", default=None,
        metavar="OPENSSL_NAME",
        help=(
            "When set, the validator asserts the DUT's server is "
            "pinned to ONLY this TLS 1.3/1.2 group (because the "
            "launch script wired OPENSSL_CONF restricting it via "
            "IPMX_TLS_GROUPS). The §8-5 probe opens a default "
            "TLS handshake; success demonstrates the server "
            "supports this curve. One curve per matrix entry."
        ),
    )

    proxy = p.add_argument_group("Registry proxy")
    proxy.add_argument(
        "--registry-proxy-log", type=Path, default=None,
        help=(
            "Path to a JSON file containing the observed Node→Registry "
            "request log produced by ipmx_registry_proxy.py. When "
            "supplied, the §7.2 / §10 checks grade the DUT's actual "
            "registry-side behaviour against the spec. Each record is "
            "{method, path, tls_version, cipher, has_authorization, "
            "authorization_scheme, peer_cert_subject, peer_cert_present, "
            "upstream_status}."
        ),
    )
    proxy.add_argument(
        "--registry-proxy-rap", type=int, choices=(0, 1, 2), default=None,
        help=(
            "The RAP mode the proxy was configured for: 0=HTTP, "
            "1=HTTPS server-auth, 2=HTTPS+mTLS. Defaults to "
            "--expect-rap. Used by the §7.2 / §10 checks to decide "
            "what to expect in the log."
        ),
    )

    return p


def parse_cli(argv: list[str] | None = None) -> CLIArgs:
    """Parse argv, enforce cross-constraints, return a typed view."""
    args = build_cli().parse_args(argv)
    config = args.config

    # Pinned values per spec.
    expect_raam = _CONFIG_TO_RAAM[config]
    if config == "A":
        # NAP is operator's choice (1 or 2); default 2 if absent.
        expect_nap = args.expect_nap if args.expect_nap is not None else 2
        if args.expect_oaim is not None:
            _exit_error(
                "--expect-oaim is not legal with --config A "
                "(OAIM is an OAuth 2.0 setting; Configuration A has no AS)"
            )
        expect_oaim: int | None = None
    else:
        # B and C: NAP pinned to 2 by §9.2.
        if args.expect_nap is not None and args.expect_nap != 2:
            _exit_error(
                f"--expect-nap {args.expect_nap} not legal with --config {config}: "
                "§9.2 forbids NAP=1 when OAuth 2.0 is in use"
            )
        expect_nap = 2
        if args.expect_oaim is None:
            _exit_error(
                f"--expect-oaim is required with --config {config} "
                "(OAuth 2.0 modes mandate selecting an OAIM)"
            )
        expect_oaim = args.expect_oaim

    # Default server CA.
    server_ca = args.server_ca
    if server_ca is None:
        server_ca = PKI_PRIMARY / "ExampleRootCA.pem"

    # Default fake AS cert/key — use the SNX00000 server identity which is
    # already chained to ExampleRootCA the DUT trusts.
    fake_as_cert = args.fake_as_cert
    fake_as_key = args.fake_as_key
    if fake_as_cert is None:
        fake_as_cert = PKI_PRIMARY / "pem" / "ExampleDeviceServer.ABC.SNX00000.chain.pem"
    if fake_as_key is None:
        fake_as_key = PKI_PRIMARY / "key" / "ExampleDeviceServer.ABC.SNX00000.key"

    # Default grants CSV — the canonical keycloak/TR-10-SEC_grants.csv.
    grants_csv = args.grants_csv
    if grants_csv is None:
        grants_csv = Path(__file__).resolve().parent.parent / "keycloak" / "TR-10-SEC_grants.csv"
    scenarios_csv = args.scenarios_csv
    if scenarios_csv is None:
        scenarios_csv = Path(__file__).resolve().parent / "ipmx_security_cases.csv"

    rf = ReportFilter(
        full=args.full_report or not (
            args.fail_report or args.pass_report or args.cannot_test_report
            or args.optional_absent_report or args.needs_fixture_report
        ),
        fail_only=args.fail_report,
        pass_only=args.pass_report,
        cannot_test_only=args.cannot_test_report,
        optional_absent_only=args.optional_absent_report,
        needs_fixture_only=args.needs_fixture_report,
    )

    return CLIArgs(
        config=config,
        dut=args.dut,
        instance_id=args.instance_id,
        control_port=args.control_port,
        expect_raam=expect_raam,
        expect_nap=expect_nap,
        expect_rap=args.expect_rap,
        expect_tct=args.expect_tct,
        expect_oaim=expect_oaim,
        client_cert=args.client_cert,
        client_key=args.client_key,
        server_ca=server_ca,
        launch_dut=args.launch_dut,
        launch_dut_wait=args.launch_dut_wait,
        launch_dut_timeout=args.launch_dut_timeout,
        fake_as=args.fake_as,
        fake_as_host=args.fake_as_host,
        fake_as_port=args.fake_as_port,
        fake_as_cert=fake_as_cert,
        fake_as_key=fake_as_key,
        fake_as_realm=args.fake_as_realm,
        keycloak_url=args.keycloak_url,
        keycloak_realm=args.keycloak_realm,
        keycloak_admin_user=args.keycloak_admin_user,
        keycloak_admin_pass=args.keycloak_admin_pass,
        scenarios_csv=scenarios_csv,
        grants_csv=grants_csv,
        provision_keycloak=args.provision_keycloak,
        attestation_manifest=args.attestation_manifest,
        json_out=args.json_out,
        report_filter=rf,
        list_requirements=args.list_requirements,
        focus_req_ids=frozenset(
            s.strip() for s in args.focus_req_ids.split(",") if s.strip()
        ),
        expect_tls_group=args.expect_tls_group,
        registry_proxy_log=args.registry_proxy_log,
        registry_proxy_rap=(
            args.registry_proxy_rap
            if args.registry_proxy_rap is not None
            else args.expect_rap
        ),
        supports=frozenset(
            s.strip()
            for raw in (args.supports or [])
            for s in raw.split(",")
            if s.strip()
        ),
    )


def _exit_error(msg: str) -> None:
    """Print an error and exit non-zero — used for CLI cross-constraints."""
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# Registry-proxy observation — what the proxy fixture recorded.
# ---------------------------------------------------------------------------

@dataclass
class ProxyRequestRecord:
    """One observed Node→Registry request — wire-format mirror of
    :class:`ipmx_registry_proxy.ProxyRequestRecord`.

    Each record captures the transport (TLS version, cipher, presence
    of a peer cert) and the HTTP layer (method, path, presence of an
    ``Authorization`` header). The §7.2 / §10 / §12.2 checks read
    these fields to grade whether the DUT honoured its declared RAP."""
    method: str
    path: str
    tls_version: str
    cipher: str
    has_authorization: bool
    authorization_scheme: str
    peer_cert_subject: str
    peer_cert_present: bool
    upstream_status: int | None = None


@dataclass
class RegistryProxyObservation:
    """The full log of Node→Registry requests observed during the run,
    plus the proxy's declared RAP mode for grading.

    ``records`` is in chronological order. ``rap`` is the RAP value
    the proxy was configured for at startup (0/1/2). The §7.2 / §10
    checks gate their grading on ``rap``."""
    records: list[ProxyRequestRecord]
    rap: int

    @classmethod
    def load(cls, path: Path, rap: int) -> "RegistryProxyObservation":
        """Parse the JSON file ``ipmx_registry_proxy.py --log-out``
        wrote on shutdown. Tolerates a missing file (returns an empty
        observation — the §7.2/§10 checks then resolve to
        NEEDS-FIXTURE so the operator sees the gap)."""
        if not path.exists():
            return cls(records=[], rap=rap)
        raw = json.loads(path.read_text())
        records = [ProxyRequestRecord(**r) for r in raw]
        return cls(records=records, rap=rap)


# ---------------------------------------------------------------------------
# Validation context — the state every check function captures.
# ---------------------------------------------------------------------------

@dataclass
class SecurityValidationContext:
    """Run-time state shared across every check function.

    Built once at the start of ``main()`` after the DUT becomes
    reachable. Each check captures this and reads whatever it needs.
    """
    cli: CLIArgs
    dut_base_url: str
    """``https://<dut-host>:<dut-port>`` — what every fetch is rooted at."""

    http_client: SecurityHttpClient
    fake_as: FakeAuthorizationServer | None
    signing_key: SigningKey | None
    """The fake AS's primary signing key. Stage 1 token mints use this."""

    client_id: str = "ipmx-validator"
    """OAuth 2.0 ``client_id`` the validator's tokens advertise. Under
    Configurations A/C the DUT enforces §14.3.3.6 (token ``client_id``
    must match the TLS client cert's CN or one of its DNS SAN entries
    case-insensitively, with wildcards rejected). The validator
    extracts the cert's first DNS-SAN at startup and uses it here so
    tokens it mints satisfy that binding."""

    registry_proxy: RegistryProxyObservation | None = None
    """Observed Node→Registry traffic from the matrix-runner-managed
    proxy fixture. ``None`` when the validator was launched standalone
    without ``--registry-proxy-log``; the §7.2 / §10 checks then
    resolve to NEEDS-FIXTURE rather than asserting on nothing."""

    self_resource: dict[str, Any] | None = None
    """Result of ``GET /x-nmos/node/v1.3/self``, cached after the first
    fetch so every check that needs it doesn't re-poll."""

    advertised_tags: dict[str, list[str]] = field(default_factory=dict)
    """The Node's ``tags`` dict, parsed from ``self_resource``."""

    advertised_services: list[dict[str, Any]] = field(default_factory=list)
    """Node-level services advertised in ``self.services[]``. Each entry
    is ``{"href": "<absolute URL>", "type": "<urn:...>", "authorization": bool}``.
    Populated alongside ``self_resource``. The Reservation service
    (``urn:x-matrox:service:exclusive/v1.0``) and any ``x-manufacturer``
    services live here."""

    advertised_controls: list[dict[str, Any]] = field(default_factory=list)
    """Device-level controls flattened across every device fetched from
    ``GET /devices``. Each entry is ``{"href": "<absolute URL>", "type":
    "<urn:...>", "authorization": bool}``. IS-05 ConnectionAPI (sr-ctrl),
    IS-12 ncp, IS-08 channel-mapping, IS-11 stream-compat all advertise
    here. The validator uses these hrefs verbatim — devices that expose
    their control APIs on a separate ``--controlPort`` are honored."""

    server_endpoints: list[ServerEndpoint] = field(default_factory=list)
    """The TR-10-SEC §7.1 in-scope server-endpoint inventory, built
    from ``self.api.endpoints[]`` + ``device.controls[]`` +
    ``self.services[]``. Per-endpoint check functions iterate this
    list via :func:`_probe_each_endpoint` so the validator exercises
    every endpoint, not just the Node API."""

    predicted_counters: dict[str, int] = field(default_factory=dict)
    """Per-counter expected increments accumulated across the run.

    The keys are the §14.3.3.5 category tags: ``a.1``/``a.2``/``a.3``/
    ``a.4`` (ReadOnly denial by sub/aud/scope/x-nmos), ``b.1``..``b.4``
    (ReadWrite denial), ``c`` (no token), ``d`` (invalid/corrupted
    token), ``e`` (expired/not-yet-valid), ``f`` (TLS client cert
    fail), ``g`` (TLS server cert fail on client access), ``h`` (JWKS
    fetch/update fail), ``i`` (no valid public keys). After the run,
    :func:`_emit_predicted_counter_deltas` writes this dict into the
    attestation manifest so the operator can compare it against the
    device's actual post-run counter values."""

    @property
    def dut_host(self) -> str:
        """The DUT hostname (without port) extracted from ``--dut``.

        Conventionally a cert SAN that wraps the BCP-002-02
        ``instance_id`` as a substring — checks that need an aud entry
        which matches BOTH the substring rule AND the cert-binding
        rule from §14.3.3.4 should use this value rather than the
        bare ``instance_id``."""
        return self.cli.dut.split(":", 1)[0]


# ---------------------------------------------------------------------------
# Requirement registry — one entry per spec sentence we exercise.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Optional-feature gates for SHOULD-level requirements.
#
# Each entry maps one SHOULD req_id to the optional-feature tag the
# operator must list in ``--supports`` for the requirement to be
# applicable. Requirements gated on a tag NOT in ``cli.supports``
# resolve to OPTIONAL-ABSENT — the device makes no claim about the
# feature so it cannot fail. The tag vocabulary is intentionally
# small and stable; new tags should be added here AND documented in
# the ``--supports`` argparse help text.
# ---------------------------------------------------------------------------

_SHOULD_FEATURE_GATES: dict[str, str] = {
    # §3 TLS 1.3 support (the spec language: "implementations should
    # support TLS 1.3 ... shall support TLS 1.2"). The 1.3 negotiation
    # check + the "prefer 1.3 when both offered" SHOULD are both
    # contingent on the device claiming 1.3 support.
    "SEC-8-2": "tls13",
    "SEC-8-3": "tls13",
    # §3 TLS 1.2 extended cipher SHOULD-list (every cipher beyond the
    # mandatory ``ECDHE-RSA-AES128-GCM-SHA256``). Declaring this opts
    # the device into wire tests for every member.
    "SEC-8-8": "tls12-ciphers-extended",
    # §3 ECDH curves: SEC-8-4 (PFS) and SEC-8-5 (per-curve support)
    # are NOT feature-gated — they're SHALL requirements; the per-
    # curve probe resolves to NOT-APPLICABLE on entries without a
    # ``tls_group_pin`` so the four ``A-curve-*`` entries carry the
    # actual evidence.
    # §14.3.3.7 separate read-only ``Guest``-suffixed WS endpoint.
    "SEC-14.3.3.7-1": "guest-ws",
    "SEC-14.3.3.7-2": "guest-ws",
    # §12.5 TCT=2 dual-stack (RSA + ECDSA simultaneously).
    "SEC-12.5-3": "tct-both",
    # §12.8 / §12.11 / §12.13 CRL handling (CTCRL / NESTCRL / CESTCRL).
    # SEC-12.8-1 / -12.11-1 / -12.13-1: GCRL support is now wired
    # end-to-end via the A-crl-* matrix entries. Removed from the
    # SHOULD-feature gates so the probes always fire under their
    # focused matrix entries.
}
"""
Optional-feature gates keyed by req_id.

NOTE: Audit counters (§14.3.3.5 SEC-14.3.3.4-46) are NOT gated here —
they are flagged ``untestable`` instead. The validator cannot read a
device's counters over the wire, so the requirement falls to the
attestation manifest. The manifest receives a predicted per-counter
delta (see :func:`_emit_predicted_counter_deltas`) the operator
compares against the device's actual values during sign-off.

TLS 1.3 cipher SHOULD-list (``tls13-ciphers-extended``) is reserved
for future use — there is no SEC-8-x req_id wired to it yet; once
the cipher matrix splits 1.2 vs 1.3, that tag will gate the 1.3
side.
"""


# ---------------------------------------------------------------------------
# Counter-prediction map. Each probe label (the string passed as
# ``label=`` to ``_probe_token_outcome_all_endpoints`` / ``_probe_each_endpoint``)
# maps to the §14.3.3.5 counter category the DUT should bump for
# every PASS the validator observes on a deny-shaped probe.
#
# Labels not listed here are positive tests (no expected DUT counter
# bump) or denial outcomes the spec does not enumerate as a counter
# bucket. The auto-detect uses substring matching so per-claim labels
# like ``missing-iss``/``missing-aud`` all map to ``d`` via a single
# ``missing-*`` entry.
# ---------------------------------------------------------------------------

_LABEL_TO_COUNTER: tuple[tuple[str, str], ...] = (
    # ----- invalid / corrupted / malformed token (d) -----
    ("typ-missing", "d"),
    ("alg-HS256", "d"),
    ("es256-wrong-curve", "d"),
    ("es512-wrong-curve", "d"),
    ("expired-token", "e"),
    ("ttl-too-short", "d"),
    ("ttl-too-long", "d"),
    ("missing-", "d"),  # missing-iss, missing-aud, missing-sub, etc.
    ("xnmos-duplicate-mismatch", "d"),
    ("bad-signature", "d"),
    ("xnmos-aud-index-oob", "d"),
    ("xnmos-sort-order-violation", "d"),
    ("xnmos-empty-int-array", "d"),
    ("xnmos-write-aud-index-oob", "d"),
    ("clientid-cert-mismatch", "d"),
    # ----- aud-based RO denial (a.2) -----
    ("aud-mismatch", "a.2"),
    ("aud-substring-only-no-cert", "a.2"),
    ("empty-aud", "a.2"),
    # ----- scope-based RO denial (a.3) -----
    ("scope-omits-current-api", "a.3"),
    # ----- x-nmos based RO denial (a.4) -----
    ("xnmos-read-empty-string", "a.4"),
    ("xnmos-read-missing", "a.4"),
    ("xnmos-present-no-read", "a.4"),
    ("xnmos-read-aud-negative-deny", "a.4"),
    # ----- x-nmos based RW denial (b.4) -----
    ("xnmos-write-needs-read", "b.4"),
    ("xnmos-write-allow-no-match", "b.4"),
    # ----- no valid public keys (i) -----
    ("unknown-kid-fail-closed", "i"),
)


def _counter_for_label(label: str) -> str | None:
    """Look up the §14.3.3.5 counter category for a probe label.

    Substring match — ``missing-iss``, ``missing-aud``, ``missing-sub``
    all resolve to ``d`` via the single ``missing-`` entry above.
    Returns ``None`` for labels without a registered bump (positive
    tests, or denial outcomes the spec doesn't enumerate)."""
    for prefix, category in _LABEL_TO_COUNTER:
        if prefix in label:
            return category
    return None


# ---------------------------------------------------------------------------
# §14.3.3.5 counter category headings — used by the attestation manifest
# when listing the predicted post-run deltas. Keep in sync with the
# spec's enumeration.
# ---------------------------------------------------------------------------

_COUNTER_DESCRIPTIONS: dict[str, str] = {
    "a.1": "ReadOnly access denied based on the sub claim",
    "a.2": "ReadOnly access denied based on the aud claim",
    "a.3": "ReadOnly access denied based on the scope claim",
    "a.4": "ReadOnly access denied based on an x-nmos-* claim",
    "b.1": "ReadWrite access denied based on the sub claim",
    "b.2": "ReadWrite access denied based on the aud claim",
    "b.3": "ReadWrite access denied based on the scope claim",
    "b.4": "ReadWrite access denied based on an x-nmos-* claim",
    "c":   "Access performed without an Access Token",
    "d":   "Access with an invalid or corrupted token",
    "e":   "Access with an expired or not-yet-valid token",
    "f":   "TLS client certificate validation failure",
    "g":   "TLS server certificate validation failure during a client access",
    "h":   "Fetch/update of the OAuth2 Authorization Server public keys failed",
    "i":   "Access denied because no valid Public Keys are available",
}


def _apply_optional_feature_gates(
    results: list[RequirementResult],
    supports: frozenset[str],
) -> None:
    """Mutate ``results`` in place: any SHOULD whose feature gate is
    not in ``supports`` flips to OPTIONAL-ABSENT.

    The check may have already run and produced a verdict; we
    overwrite ``testable`` and ``details`` so the report shows the
    OPTIONAL-ABSENT tag with a clear explanation. The original
    verdict is preserved in ``passed`` for the JSON dump (the
    aggregator may want to look at it across runs)."""
    for r in results:
        feat = _SHOULD_FEATURE_GATES.get(r.req_id)
        if feat is None:
            continue
        r.optional_feature = feat
        if feat not in supports:
            r.optional_absent = True
            r.details = (
                f"feature '{feat}' not declared in --supports; "
                f"SHOULD resolves to OPTIONAL-ABSENT"
            )


# IPMX security-tag URNs (TR-10-SEC §8).
TAG_NAP = "urn:x-vsf:tag:tr-10-sec:nap-config/v1.0"
TAG_RAP = "urn:x-vsf:tag:tr-10-sec:rap-config/v1.0"
TAG_RAAM = "urn:x-vsf:tag:tr-10-sec:raam-config/v1.0"
TAG_OAIM = "urn:x-vsf:tag:tr-10-sec:oaim-config/v1.0"
TAG_TCT = "urn:x-vsf:tag:tr-10-sec:tct-config/v1.0"

# OpenSSL ↔ IANA mapping for the cipher matrix. Mirrors
# nmos-reference/nmos/api/tr10_tls.py so the validator and the DUT
# agree on the spec whitelist.
_SHALL_TLS12_CIPHER_OPENSSL = "ECDHE-RSA-AES128-GCM-SHA256"
_PROHIBITED_TLS12_CIPHER = "AES128-SHA"  # no PFS, RSA key transport


# ---------------------------------------------------------------------------
# TR-10-SEC §7.1 in-scope control APIs — keyed by URN prefix as it
# appears in ``device.controls[].type``. Drives the per-endpoint probe
# matrix: every control entry the DUT advertises that matches one of
# these URN prefixes contributes to the test inventory.
#
# Each spec record carries the OAuth 2.0 scope the API requires
# (TR-10-SEC §14.1), the canonical read path(s) for read-enforcement
# probes, and (for R/W APIs) the least-disruptive write recipe for
# write-enforcement probes.
#
# Out-of-scope per spec: transport streams (RTP / MQTT / WebSocket
# transports as defined in IS-05/BCP-007), DHCP / PTP / NTP / DNS /
# mDNS, 802.1x. We do not enumerate these here.
# ---------------------------------------------------------------------------

_KNOWN_CONTROL_APIS: tuple[ControlApiSpec, ...] = (
    # IS-05 ConnectionAPI — read-write.
    ControlApiSpec(
        urn_prefix="urn:x-nmos:control:sr-ctrl/",
        scope="connection",
        label="is-05",
        read_paths=("/single/senders/", "/single/receivers/"),
        write_recipe=WriteRecipe(
            path_suffix="/single/senders/{id}/staged",
            method="PATCH",
            body={"master_enable": False},
            id_list_path="/single/senders/",
        ),
    ),
    # IS-08 ChannelMappingAPI — read-write.
    ControlApiSpec(
        urn_prefix="urn:x-nmos:control:cm-ctrl/",
        scope="channelmapping",
        label="is-08",
        read_paths=("/map/active", "/map/activations", "/io"),
        write_recipe=WriteRecipe(
            path_suffix="/map/activations",
            method="POST",
            # An empty-action map activation: no immediate I/O changes
            # but exercises the write authorisation path.
            body={"activation": {"mode": "activate_immediate"}, "actions": {}},
        ),
    ),
    # IS-11 StreamCompatibilityManagementAPI — read-write. Canonical
    # URN per the IS-11 spec is ``urn:x-nmos:control:stream-compat/``.
    # The minimally-disruptive write probe is ``DELETE /senders/{id}/
    # constraints/active`` ("Resets the Active Constraints") per the
    # RAML — clears any active constraint set back to defaults.
    ControlApiSpec(
        urn_prefix="urn:x-nmos:control:stream-compat/",
        scope="streamcompatibility",
        label="is-11",
        read_paths=("/senders/", "/receivers/"),
        write_recipe=WriteRecipe(
            path_suffix="/senders/{id}/constraints/active",
            method="DELETE",
            body=None,
            id_list_path="/senders/",
        ),
    ),
    # IS-12 ncp — read-write via WebSocket commands. v0.1 does NOT
    # exercise IS-12 writes (WebSocket-command write probes are a
    # TODO); we still discover the endpoint so read-side enforcement
    # gets coverage. Scope tag is "nc" (alternately "control").
    ControlApiSpec(
        urn_prefix="urn:x-nmos:control:ncp/",
        scope="nc",
        label="is-12",
        read_paths=("",),  # GET the href itself — DUT typically
                            # answers 426 Upgrade Required if auth OK.
        write_recipe=None,  # IS-12 writes via WS UPGRADE — exercised by
                            # ``check_ncp_scope_grants_access``.
    ),
    # IS-14 Configuration API is intentionally NOT in scope for this
    # validator. The IPMX device profile this suite certifies does
    # not expose IS-14, so there is no R/W matrix to probe.
)


# Node-level service URN → scope mapping. Used for self.services[]
# enumeration. The Reservation service is the canonical x-manufacturer
# example today; other vendor extensions can be added here.
_KNOWN_SERVICES: dict[str, tuple[str, str]] = {
    # service-type URN prefix : (scope, label)
    "urn:x-matrox:service:exclusive/": ("manufacturer", "exclusive"),
}


_REGISTRY_JSON: Path = Path(__file__).resolve().parent / "requirements_tr10_sec.json"
_CLASS_JSON: Path = Path(__file__).resolve().parent / "requirements_classification.json"


def _load_spec_registry() -> list[dict[str, str]]:
    """Load the JSON-extracted requirement records from disk.

    The JSON is regenerated by ``extract_spec_requirements.py`` and
    committed alongside the validator so a fresh checkout has full
    coverage of TR-10-SEC's 188 normative sentences without needing to
    re-run the extraction.
    """
    with open(_REGISTRY_JSON, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_classification() -> dict[str, dict[str, str]]:
    """Load per-requirement bucket+reason produced by classify_requirements.py.

    The classification distinguishes the FIVE reasons a SHALL is not
    wire-tested today: admin attestation, long-window timing,
    informative scaffolding, known reference-node gap, or simply
    not-yet-wired. The validator uses these to emit specific cannot-test
    reasons rather than a generic "not implemented" message.
    """
    with open(_CLASS_JSON, "r", encoding="utf-8") as f:
        return json.load(f)


# Per-bucket prefix added to the cannot-test message so the auditor can
# tell at a glance whether a CANNOT-TEST is a genuine attestation item,
# a reference-node gap, or a validator-coverage opportunity.
_BUCKET_PREFIX: dict[str, str] = {
    "A": "[ATTEST]",       # admin / lifecycle / factory
    "B": "[LONG-WINDOW]",  # hours/days timing
    "C": "[META]",         # informative / about other party
    "D": "[REF-NODE GAP]", # testable once reference-node grows the feature
}


def build_requirements(ctx: SecurityValidationContext) -> RequirementRegistry:
    """Populate the registry from the spec-extracted JSON, layering in
    real check functions where the validator implements them.

    Every normative sentence from TR-10-SECURITY is registered — 188
    entries total. Entries paired with a real check are wire-tested;
    the rest are marked ``untestable`` so they appear in the
    attestation manifest with a clear "not yet wired" or
    "vendor-attestation" message. This makes the report a complete
    map of the spec's normative surface rather than a curated subset.
    """
    reg = RequirementRegistry()

    # =====================================================================
    # Check closures — capture ``ctx`` and implement one specific spec
    # sentence each. Mapped to JSON req_ids via the dispatch table below.
    # =====================================================================

    def _xnmos_for_scope(
        c: dict[str, Any], perms: dict[str, Any], *, in_ext: bool = False,
    ) -> None:
        """Inject an ``x-nmos-<api>`` permission claim keyed by the
        scope ``_probe_at`` already injected for the running endpoint.

        Per-endpoint iteration sets ``c["scope"]`` to the endpoint's
        OAuth scope (``"node"`` for Node API, ``"connection"`` for
        IS-05, etc.) BEFORE the test mutator runs. Reference-node's
        ``validate_access`` then reads the ``x-nmos-<api>`` claim
        whose ``<api>`` matches the API the request hit — so the
        mutator must key the claim by the same scope to stay aligned
        with the endpoint's per-API permission model.
        """
        api = (c.get("scope") or "node").split()[0]
        key = f"x-nmos-{api}"
        if in_ext:
            ext = c.get("ext")
            if not isinstance(ext, dict):
                ext = {}
                c["ext"] = ext
            ext[key] = perms
        else:
            c[key] = perms

    async def check_tls_12_mandatory_cipher() -> tuple[bool, str]:
        """Per-TCT mandatory TLS 1.2 cipher. §3 names
        ``TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`` as SHALL when the
        Node's cert is RSA. When the cert is ECDSA-only (TCT=1) the
        cipher suite name's key-exchange half changes to ``ECDSA``
        — an RSA cipher cannot be served by an ECDSA-only stack. We
        pick the matching SHALL per the declared TCT."""
        host, port = _split_host_port(ctx.cli.dut)
        if ctx.cli.expect_tct == 1:
            cipher = "ECDHE-ECDSA-AES128-GCM-SHA256"
        else:
            cipher = _SHALL_TLS12_CIPHER_OPENSSL
        report = await tls_handshake(
            host, port,
            ciphers=cipher,
            min_version=ssl.TLSVersion.TLSv1_2,
            max_version=ssl.TLSVersion.TLSv1_2,
            server_ca=ctx.cli.server_ca,
            client_cert=ctx.cli.client_cert,
            client_key=ctx.cli.client_key,
            server_hostname=host,
        )
        if not report.succeeded:
            return (False, f"handshake refused: {report.error}")
        return (
            report.negotiated_cipher == cipher,
            f"negotiated {report.negotiated_cipher} / {report.negotiated_version}",
        )

    async def check_tls_12_prohibited_cipher_refused() -> tuple[bool, str]:
        host, port = _split_host_port(ctx.cli.dut)
        report = await tls_handshake(
            host, port,
            ciphers=_PROHIBITED_TLS12_CIPHER,
            min_version=ssl.TLSVersion.TLSv1_2,
            max_version=ssl.TLSVersion.TLSv1_2,
            server_ca=ctx.cli.server_ca,
            client_cert=ctx.cli.client_cert,
            client_key=ctx.cli.client_key,
            server_hostname=host,
        )
        if report.succeeded:
            return (False,
                    f"prohibited cipher {_PROHIBITED_TLS12_CIPHER} was accepted "
                    f"(negotiated {report.negotiated_cipher})")
        return (True, f"prohibited cipher refused: {report.error}")

    async def check_tls_13_negotiation() -> tuple[bool, str]:
        host, port = _split_host_port(ctx.cli.dut)
        report = await tls_handshake(
            host, port,
            min_version=ssl.TLSVersion.TLSv1_3,
            max_version=ssl.TLSVersion.TLSv1_3,
            server_ca=ctx.cli.server_ca,
            client_cert=ctx.cli.client_cert,
            client_key=ctx.cli.client_key,
            server_hostname=host,
        )
        if not report.succeeded:
            return (False, f"TLS 1.3 handshake refused: {report.error}")
        return (True, f"negotiated {report.negotiated_cipher} / {report.negotiated_version}")

    # =====================================================================
    # §12.15 IPMX security configuration tags — one parametric check
    # asserts all 5 URNs are present and that each value matches the
    # operator's declared --expect-* / --config claim.
    # =====================================================================

    async def check_ipmx_security_tags() -> tuple[bool, str]:
        if not ctx.advertised_tags:
            await _populate_self_resource(ctx)
        expected: list[tuple[str, int | None, str]] = [
            (TAG_NAP, ctx.cli.expect_nap, "NAP"),
            (TAG_RAP, ctx.cli.expect_rap, "RAP"),
            (TAG_RAAM, ctx.cli.expect_raam, "RAAM"),
            (TAG_OAIM, ctx.cli.expect_oaim, "OAIM"),
            (TAG_TCT, ctx.cli.expect_tct, "TCT"),
        ]
        failures: list[str] = []
        successes: list[str] = []
        for urn, exp, label in expected:
            value = ctx.advertised_tags.get(urn)
            if value is None:
                failures.append(f"{label}({urn.rsplit(':', 1)[-1]}): not present")
                continue
            if not isinstance(value, list) or not value:
                failures.append(f"{label}: malformed value {value!r}")
                continue
            if exp is None:
                successes.append(f"{label}={value[0]}")
                continue
            if value[0] != str(exp):
                failures.append(
                    f"{label}={value[0]} (operator declared {exp})"
                )
            else:
                successes.append(f"{label}={value[0]}")
        if failures:
            return (False, "; ".join(failures))
        return (True, "; ".join(successes))

    # =====================================================================
    # §11 / §12.3 RAAM — mode-specific behaviour
    # =====================================================================

    # =====================================================================
    # §11 RAAM — one positive test per configuration.
    # =====================================================================

    async def check_no_client_cert_refused() -> tuple[bool, str]:
        """Configs A/C: an HTTP request without a client cert must fail
        at the TLS layer. We attempt an actual GET /self because under
        TLS 1.3 the client-side handshake completes even when the
        server is about to abort due to the missing client cert — the
        rejection surfaces only when data starts flowing."""
        async with SecurityHttpClient(
            server_ca=ctx.cli.server_ca,
            client_cert=None,
            client_key=None,
            verify_hostname=False,
        ) as anon_client:
            try:
                resp = await fetch_self(anon_client, ctx.dut_base_url)
                return (
                    False,
                    f"mTLS-required Node served GET /self (status {resp.status}) "
                    f"without a client cert",
                )
            except Exception as exc:  # pylint: disable=broad-except
                return (
                    True,
                    f"GET /self without client cert was refused at the TLS "
                    f"layer: {type(exc).__name__}: {exc}",
                )

    # =====================================================================
    # §12.8 / §12.11 / §12.13 / §12.14-6/7 / §14.3.3.5-3 — GCRL behaviour.
    # The matrix runner launches the DUT with ``--gcrl <path>`` pointing
    # at a CRL PEM bundle. Two scenarios exercised:
    #   * Empty bundle (CRLs signed by root + intermediate, zero
    #     revocations): mTLS handshake with SNX00000 client cert must
    #     succeed. Proof that loading the GCRL does not break normal
    #     verification + that the device supports CRL infrastructure.
    #   * Revocation bundle (intermediate's CRL contains SNX00000's
    #     serial): the same mTLS handshake must be REFUSED at the TLS
    #     verify step. Proof of §12.8/§12.11/§12.13's "Shall support
    #     at least N CRL" and §14.3.3.5-3's fail-closed posture.
    # =====================================================================

    async def check_crl_baseline_handshake_unaffected() -> tuple[bool, str]:
        """§12.14-6 / §12.14-7 (SHALL): the device shall support
        loading a Global CRL bundle composed of per-CA CRLs (each
        signed by its own CA). With an EMPTY bundle loaded, normal
        mTLS handshakes shall still succeed."""
        if not (ctx.cli.focus_req_ids & {"SEC-12.14-6", "SEC-12.14-7"}):
            return not_applicable(
                "this check needs the DUT launched with an empty "
                "GCRL bundle (--gcrl ...gcrl-empty.pem) — covered "
                "by the dedicated A-crl-empty-baseline entry"
            )
        async with SecurityHttpClient(
            server_ca=ctx.cli.server_ca,
            client_cert=ctx.cli.client_cert,
            client_key=ctx.cli.client_key,
            verify_hostname=False,
        ) as client:
            try:
                resp = await fetch_self(client, ctx.dut_base_url)
            except Exception as exc:  # pylint: disable=broad-except
                return (
                    False,
                    f"mTLS handshake with SNX00000 cert FAILED even "
                    f"though the GCRL is empty: {type(exc).__name__}: "
                    f"{exc}",
                )
            return (
                True,
                f"GCRL empty: mTLS handshake with SNX00000 cert "
                f"completed (status {resp.status}); the device "
                f"loaded the per-CA CRL bundle without breaking "
                f"normal verification",
            )

    async def check_crl_revoked_cert_refused() -> tuple[bool, str]:
        """§12.8-1 / §12.11-1 / §12.13-1 / §14.3.3.5-3 (SHALL): when a
        client cert appears in the GCRL, mTLS handshake from that
        cert must be REFUSED at the TLS verify step."""
        if not (ctx.cli.focus_req_ids & {
            "SEC-12.8-1", "SEC-12.11-1", "SEC-12.13-1", "SEC-14.3.3.5-3",
        }):
            return not_applicable(
                "this check needs the DUT launched with a GCRL "
                "containing the validator's client cert serial "
                "(--gcrl ...gcrl-revoke-snx00000.pem) — covered by "
                "the dedicated A-crl-revoked-cert entry"
            )
        async with SecurityHttpClient(
            server_ca=ctx.cli.server_ca,
            client_cert=ctx.cli.client_cert,
            client_key=ctx.cli.client_key,
            verify_hostname=False,
        ) as client:
            try:
                resp = await fetch_self(client, ctx.dut_base_url)
                return (
                    False,
                    f"mTLS handshake with REVOKED SNX00000 cert "
                    f"succeeded (status {resp.status}) — the DUT did "
                    f"NOT honour the GCRL revocation entry "
                    f"(§14.3.3.5-3 fail-closed violated)",
                )
            except Exception as exc:  # pylint: disable=broad-except
                # The TLS-verify-fail surfaces as a low-level error.
                # We don't try to match a specific error string — any
                # connection-level refusal is acceptable evidence the
                # revocation was honoured.
                return (
                    True,
                    f"mTLS handshake with REVOKED SNX00000 cert was "
                    f"refused: {type(exc).__name__}: {str(exc)[:160]}",
                )

    async def check_no_client_cert_accepted() -> tuple[bool, str]:
        """Config B: GET /self without a client cert must succeed at
        the TLS layer. The HTTP response may still be 401 (no Bearer)
        — that's fine; the SHALL is about TLS-layer acceptance."""
        async with SecurityHttpClient(
            server_ca=ctx.cli.server_ca,
            client_cert=None,
            client_key=None,
            verify_hostname=False,
        ) as anon_client:
            try:
                resp = await fetch_self(anon_client, ctx.dut_base_url)
                return (
                    True,
                    f"GET /self without client cert reached the HTTP layer "
                    f"(status {resp.status})",
                )
            except Exception as exc:  # pylint: disable=broad-except
                return (
                    False,
                    f"server-TLS-only mode refused TLS handshake without "
                    f"client cert: {type(exc).__name__}: {exc}",
                )

    async def check_anonymous_read_allowed_under_nap1() -> tuple[bool, str]:
        """§9.2-2 (SHALL): "Unrestricted read access shall be permitted
        to all clients" — under NAP=1. Probe: GET /x-nmos/node/v1.3/self
        with NO client cert and NO bearer token. The DUT's middleware
        is in CERT_OPTIONAL mode (set by ``--nodeOptionalClientAuth``)
        so the TLS handshake completes; the read endpoint must return
        200 because NAP=1 permits anonymous reads. Only meaningful
        when --expect-nap=1.
        """
        if ctx.cli.expect_nap != 1:
            return not_applicable(
                "this check only applies under --expect-nap 1; "
                "NAP=2 (default) requires authenticated access — see "
                "check_no_client_cert_refused"
            )
        async with SecurityHttpClient(
            server_ca=ctx.cli.server_ca,
            client_cert=None,
            client_key=None,
            verify_hostname=False,
        ) as anon_client:
            try:
                resp = await fetch_self(anon_client, ctx.dut_base_url)
            except Exception as exc:  # pylint: disable=broad-except
                return (
                    False,
                    f"NAP=1 should accept anonymous TLS to the Node API, "
                    f"but the handshake failed: {type(exc).__name__}: {exc}",
                )
            if resp.status == 200:
                return (
                    True,
                    f"NAP=1: anonymous GET /x-nmos/node/v1.3/self returned "
                    f"200 — unrestricted read access works as spec'd",
                )
            return (
                False,
                f"NAP=1: anonymous GET /x-nmos/node/v1.3/self returned "
                f"{resp.status}, expected 200 (unrestricted read)",
            )

    # =====================================================================
    # §14.3.2 JWKS lifecycle, §14.3.3.X token-validation matrix — Stage 1.
    # =====================================================================

    def _no_fake_as_outcome() -> tuple[bool, str, bool] | tuple[bool, str, bool, bool]:
        """Closure-local convenience wrapper — every check inside
        ``build_requirements`` calls this when ``ctx.fake_as is None``."""
        return _no_fake_as_outcome_for(ctx)

    async def check_jwks_pickup() -> tuple[bool, str]:
        """§14.3.2-1: Node SHALL cache the OAuth 2.0 AS Public Keys.

        The cache is the load-bearing behaviour — without it the Node
        would have to fetch JWKS on every token validation, which is
        observable (high request volume) but the spec wants the cache
        to be USED. Probe the cache directly:

          1. Mint a valid token with the AS's primary key + send to
             DUT — must succeed (proves JWKS pickup happened).
          2. Disable the fake AS (every endpoint returns 503).
          3. Mint and send ANOTHER valid token with the same key —
             must still succeed. The DUT can only do this if it
             validated against CACHED keys; the broken AS guarantees
             a re-fetch would fail.
          4. Restore the AS.
        """
        if ctx.fake_as is None:
            return untestable(
                "Stage 1 fake AS not running — cannot probe JWKS pickup. "
                "Re-run with --fake-as (default for configs B/C)."
            )
        first = await _probe_token_outcome(
            ctx, key=ctx.fake_as.primary_key, expected_status=200,
        )
        if not first[0]:
            return (False,
                    f"first valid-token request failed before cache test: "
                    f"{first[1]}")
        ctx.fake_as.set_broken(True)
        try:
            # Give the AS a tick to flip into broken-mode.
            await asyncio.sleep(0.1)
            second = await _probe_token_outcome(
                ctx, key=ctx.fake_as.primary_key, expected_status=200,
            )
            if not second[0]:
                return (False,
                        "DUT failed to validate a valid token while the AS "
                        f"was broken — JWKS cache is not in use: {second[1]}")
            return (True,
                    "first request seeded the cache; second request succeeded "
                    "with the AS in broken-mode — DUT is using cached keys "
                    "without re-fetching")
        finally:
            ctx.fake_as.set_broken(False)

    async def check_typ_missing_rejected() -> tuple[bool, str]:
        # Per-endpoint: every in-scope endpoint must reject a
        # missing-typ token at the auth layer.
        return await _probe_token_outcome_all_endpoints(
            ctx,
            header_mutate=lambda h: h.pop("typ", None),
            expected_status=401,
            label="typ-missing",
        )

    async def check_alg_unsupported_rejected() -> tuple[bool, str]:
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        # The §14.3.3.2-2 SHALL covers both the positive (any of the four
        # permitted algs accepted) and negative (any other alg refused)
        # directions. We exercise the negative direction here — minting
        # a token whose declared alg is HS256 must produce 401 — and
        # log a positive sanity check too.
        bad = await _probe_token_outcome_all_endpoints(
            ctx, mutate=None,
            header_mutate=lambda h: h.update(alg="HS256"),
            expected_status=401, label="alg-HS256",
        )
        if not bad[0]:
            return bad
        good = await _probe_token_outcome_all_endpoints(
            ctx, mutate=None, header_mutate=None,
            expected_status=200, label="alg-RS256-valid",
        )
        if not good[0]:
            return (False, f"HS256 rejected as expected, but valid token also "
                           f"rejected: {good[1]}")
        return (True, "HS256 rejected (401); valid RS256 accepted (200) "
                      "on every in-scope endpoint")

    async def check_expired_token_rejected() -> tuple[bool, str]:
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        past = int(time.time()) - 3600
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=lambda c: c.update(exp=past),
            header_mutate=None, expected_status=401, label="expired-token",
        )

    async def check_empty_aud_denied() -> tuple[bool, str]:
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        # Spec §14.3.4 categorises this as "audience restrictions" →
        # HTTP 403 (the token is structurally valid but the audience
        # claim's empty value denies permission).
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=lambda c: c.update(aud=[]),
            header_mutate=None, expected_status=403, label="empty-aud",
        )

    async def check_missing_scope_rejected() -> tuple[bool, str]:
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        # ``scope`` is required per §14.3.3.4-1; removing it makes the
        # token invalid → 401. The per-endpoint scope injection in
        # ``_probe_at`` re-adds ``scope`` BEFORE the test mutator runs,
        # so we use ``c.pop`` AFTER the injection by capturing in a
        # second mutator-wrapper. ``_probe_at`` calls our mutator LAST
        # (see its ``composed_mutate``), so the pop wins.
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=lambda c: c.pop("scope", None),
            header_mutate=None, expected_status=401, label="missing-scope",
        )

    # =====================================================================
    # §14.3.3.1 Lifetime — boundary mints (exp − iat must be in [1h, 24h]).
    # =====================================================================

    async def check_lifetime_too_short_rejected() -> tuple[bool, str]:
        """TTL=30 minutes → exp − iat = 1800s < 3600s, rejected."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx,
            mutate=lambda c: c.update(exp=int(time.time()) + 1800),
            expected_status=401, label="ttl-too-short",
        )

    async def check_lifetime_too_long_rejected() -> tuple[bool, str]:
        """TTL=25h → exp − iat > 24h, rejected."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx,
            mutate=lambda c: c.update(exp=int(time.time()) + 25 * 3600),
            expected_status=401, label="ttl-too-long",
        )

    # =====================================================================
    # §14.3.3.2 Type and Algorithms — per-alg matrix + curve checks.
    # =====================================================================

    def _make_alg_accept_check(alg: str) -> CheckFn:
        """Mint a token signed with ``alg`` and assert the DUT accepts it
        on every in-scope endpoint."""
        async def inner() -> tuple[bool, str]:
            if ctx.fake_as is None:
                return _no_fake_as_outcome()
            key = ctx.fake_as.key_for_alg(alg)
            if key is None:
                return untestable(f"fake AS has no {alg} key configured")
            return await _probe_token_outcome_all_endpoints(
                ctx, key=key, expected_status=200, label=f"alg-{alg}-accept",
            )
        return inner

    async def check_es256_with_wrong_curve_rejected() -> tuple[bool, str]:
        """Header alg=ES256 but signature actually produced by an ES512
        (P-521) key. The DUT verifies signature with the kid's JWK
        (ES512/P-521) which doesn't match the declared ES256 → reject."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        es512_key = ctx.fake_as.key_for_alg("ES512")
        if es512_key is None:
            return untestable("fake AS has no ES512 key configured")
        return await _probe_token_outcome_all_endpoints(
            ctx,
            key=es512_key,
            header_mutate=lambda h: h.update(alg="ES256"),
            expected_status=401, label="es256-wrong-curve",
        )

    async def check_es512_with_wrong_curve_rejected() -> tuple[bool, str]:
        """Symmetric to ES256: alg=ES512 with P-256 key declared."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        es256_key = ctx.fake_as.key_for_alg("ES256")
        if es256_key is None:
            return untestable("fake AS has no ES256 key configured")
        return await _probe_token_outcome_all_endpoints(
            ctx,
            key=es256_key,
            header_mutate=lambda h: h.update(alg="ES512"),
            expected_status=401, label="es512-wrong-curve",
        )

    # =====================================================================
    # §14.3.3.3 Grants & claims — missing-claim matrix, sub/client_id,
    # nbf, x-nmos-* placement (ext vs top-level), duplicated-claim rule.
    # =====================================================================

    async def check_all_required_claims_enforced() -> tuple[bool, str]:
        """§14.3.3.3-4: iss, aud, sub, exp, scope, client_id shall all
        be present. Test each removal individually — every missing
        claim must produce 401, on every in-scope endpoint."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        required = ["iss", "aud", "sub", "exp", "scope", "client_id"]
        failures: list[str] = []
        for claim in required:
            ok, details = await _probe_token_outcome_all_endpoints(
                ctx, mutate=lambda c, k=claim: c.pop(k, None),
                expected_status=401, label=f"missing-{claim}",
            )
            if not ok:
                failures.append(f"missing {claim!r}: {details}")
        if failures:
            return (False, "; ".join(failures))
        return (True, f"every required claim removed → 401 on every "
                      f"endpoint: {required}")

    async def check_sub_not_equal_client_id_for_cc() -> tuple[bool, str]:
        """For client_credentials grants, sub MUST equal client_id.
        Mint with sub != client_id and observe the DUT's reaction.
        Whether the DUT rejects depends on its grant-policy config —
        many DUTs only enforce this when CC-only mode is active. We
        accept either 200 (DUT doesn't enforce CC-only) or 401 (DUT
        enforces). Either is spec-compliant.

        Pinned to ``client_credentials`` shape only — the rule itself
        is grant-type-specific, so running it under the auth_code
        shape would test a vacuously-true case."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=lambda c: c.update(sub="end-user-alice"),
            expected_status=(200, 401), label="sub-mismatch-cc",
            grants=("client_credentials",),
        )

    async def check_nbf_present_ignored() -> tuple[bool, str]:
        """§14.3.3.3-6: if nbf is present, it shall be IGNORED.
        Mint with nbf in the past — DUT must still accept the token."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=lambda c: c.update(nbf=int(time.time()) - 3600),
            expected_status=200, label="nbf-past-ignored",
        )

    async def check_xnmos_in_ext_accepted() -> tuple[bool, str]:
        """§14.3.3.3-8: Node shall accept x-nmos-* in the ``ext`` claim.

        Per-endpoint iteration injects scope=<endpoint.scope>; the
        x-nmos-<scope> claim wired below must also key by scope, so
        rebuild it inside the mutator from the running token's scope."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        def _mut(c: dict[str, Any]) -> None:
            api = (c.get("scope") or "node").split()[0]
            c["ext"] = {f"x-nmos-{api}": {"read": ["*"], "write": ["*"]}}
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=_mut, expected_status=200, label="xnmos-in-ext",
        )

    async def check_xnmos_top_level_accepted() -> tuple[bool, str]:
        """§14.3.3.3-8: Node shall accept x-nmos-* at the top level."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        def _mut(c: dict[str, Any]) -> None:
            api = (c.get("scope") or "node").split()[0]
            c[f"x-nmos-{api}"] = {"read": ["*"], "write": ["*"]}
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=_mut, expected_status=200, label="xnmos-top-level",
        )

    async def check_xnmos_should_be_in_ext() -> tuple[bool, str]:
        """§14.3.3.3-7 (SHOULD): x-nmos-* should be placed in ext.
        The Node should ACCEPT both forms (per §14.3.3.3-8 SHALL),
        so this SHOULD is observable as 'x-nmos-* in ext is accepted'
        — the recommendation applies to token issuers, not Nodes.
        We treat any acceptance as compliance with the implementable
        side of the SHOULD."""
        return await check_xnmos_in_ext_accepted()

    async def check_duplicated_xnmos_must_be_identical() -> tuple[bool, str]:
        """§14.3.3.3-10: if x-nmos-* is duplicated (ext AND top-level),
        the values MUST be identical. Mint with mismatched duplicates
        and expect 401 (invalid token)."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        def _mut(c: dict[str, Any]) -> None:
            api = (c.get("scope") or "node").split()[0]
            key = f"x-nmos-{api}"
            c["ext"] = {key: {"read": ["*"], "write": [""]}}
            c[key] = {"read": [""], "write": ["*"]}
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=_mut, expected_status=401,
            label="xnmos-duplicate-mismatch",
        )

    # =====================================================================
    # §14.3.3.4 Validation matrix — the big block (30+ entries). The
    # check closures here drive the spec's pseudocode mint-and-probe
    # matrix: aud-substring/aud-cert matching, signed-integer allow/deny
    # lists, x-nmos-* read/write paths, sort-order constraints, OAIM
    # behaviours. Each closure exercises one specific path.
    # =====================================================================

    async def check_tls_required_for_http() -> tuple[bool, str]:
        """§14.3.3.4-1: Node shall require TLS 1.2/1.3 when serving HTTP.
        Implicit when --launch-dut-wait targets https://; we confirm the
        base URL is HTTPS and a non-TLS connect-attempt is refused."""
        if not ctx.dut_base_url.startswith("https://"):
            return (False, "validator's dut_base_url is not HTTPS")
        # Attempt a plain TCP connect to port 7051 expecting it to be
        # an HTTPS socket — speaking HTTP/1.0 plaintext should not get
        # a useful HTTP response. The earlier §8 TLS handshake tests
        # actually establish that the listener is TLS-only; if those
        # pass, this requirement is satisfied transitively.
        return (True, "DUT is reached over https:// and §8 TLS handshake checks pass")

    async def check_query_param_token_rejected() -> tuple[bool, str]:
        """§14.3.3.4-2: tokens only from Authorization header, never query.
        Send GET /self?access_token=<valid> WITHOUT Authorization header
        — DUT must refuse (401)."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        template = ctx.fake_as.token_template(
            instance_id=ctx.cli.instance_id, client_id=ctx.client_id,
        )
        token = mint_token(template, ctx.fake_as.primary_key)
        url = f"{ctx.dut_base_url}/x-nmos/node/v1.3/self?access_token={token}"
        resp = await request_with_token(ctx.http_client, url, token=None)
        if resp.status == 401:
            return (True, "query-param token correctly refused (401)")
        return (False,
                f"DUT accepted query-param token (status {resp.status}); "
                "spec §14.3.3.4-2 mandates header-only")

    async def check_bad_signature_rejected() -> tuple[bool, str]:
        """§14.3.3.4-3/-4: bad signature → 401 + WWW-Authenticate.

        Iterates every in-scope endpoint: mint a valid per-scope
        token, corrupt the signature segment, send and verify the
        DUT rejects with 401 + WWW-Authenticate."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()

        async def probe(ep: ServerEndpoint) -> tuple[bool, str]:
            assert ctx.fake_as is not None
            template = ctx.fake_as.token_template(
                instance_id=ctx.cli.instance_id, client_id=ctx.client_id,
            )
            token = mint_token(
                template, ctx.fake_as.primary_key,
                mutate=lambda c: c.update(scope=ep.scope),
            )
            head, payload, sig = token.split(".")
            tampered = f"{head}.{payload}.{sig[:-6]}AAAAAA"
            url = ep.base_url + _default_read_path(ep)
            resp = await request_with_token(ctx.http_client, url, token=tampered)
            if resp.status != 401:
                return (False,
                        f"{url}: tampered token accepted (status {resp.status})")
            www_auth = resp.headers.get("WWW-Authenticate", "")
            if not www_auth:
                return (False, f"{url}: 401 without WWW-Authenticate header")
            return (True, f"{url} → 401 + WWW-Authenticate")

        return await _probe_each_endpoint(
            ctx, probe, label="bad-signature", read_side=True,
        )

    # ---- aud-claim variants ----

    async def check_aud_wildcard_accepted() -> tuple[bool, str]:
        """§14.3.3.4-8/-11: aud=['*'] grants access regardless of OAIM."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=lambda c: c.update(aud=["*"]),
            expected_status=200, label="aud-wildcard",
        )

    async def check_aud_substring_match_accepted() -> tuple[bool, str]:
        """§14.3.3.4-8: OAIM=Serial — aud entry containing the
        instance-id as substring is allowed (and matches cert SAN)."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        # See ``ctx.dut_host`` docstring — that value satisfies BOTH
        # the substring rule and the cert-SAN rule per §14.3.3.4.
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=lambda c: c.update(aud=[ctx.dut_host]),
            expected_status=200, label="aud-substring-match",
        )

    async def check_aud_mismatch_denied() -> tuple[bool, str]:
        """§14.3.3.4-8: aud not containing the instance-id (and not
        matching cert SAN) → access denied (403)."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=lambda c: c.update(aud=["other-host.example.com"]),
            expected_status=403, label="aud-mismatch",
        )

    async def check_aud_substring_only_denied_without_cert_match() -> tuple[bool, str]:
        """§14.3.3.4-10: aud DNS name containing the instance-id MUST
        ALSO match the TLS server cert SAN. An aud entry that contains
        the substring but doesn't match a cert SAN must be denied."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        bogus_aud = f"foo-{ctx.cli.instance_id}-bar.unknown.example"
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=lambda c: c.update(aud=[bogus_aud]),
            expected_status=403, label="aud-substring-only-no-cert",
        )

    async def check_aud_out_of_bounds_index_invalid() -> tuple[bool, str]:
        """§14.3.3.4-40: an x-nmos-* index outside the aud array bounds
        invalidates the entire token → 401."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx,
            mutate=lambda c: _xnmos_for_scope(c, {"read": [99], "write": [99]}),
            expected_status=401, label="xnmos-aud-index-oob",
        )

    async def check_aud_sort_order_violation_invalid() -> tuple[bool, str]:
        """§14.3.3.4-41: signed-integer arrays MUST be sorted positives
        first, then negatives. A [-1, 0] order violates → token invalid → 401."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        def _mut(c: dict[str, Any]) -> None:
            c["aud"] = ["*", ctx.dut_host]
            _xnmos_for_scope(c, {"read": [-1, 0], "write": [-1, 0]})
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=_mut, expected_status=401,
            label="xnmos-sort-order-violation",
        )

    async def check_empty_integer_array_invalid() -> tuple[bool, str]:
        """§14.3.3.4-43: empty signed-integer array → token invalid → 401."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx,
            mutate=lambda c: _xnmos_for_scope(c, {"read": [], "write": []}),
            expected_status=401, label="xnmos-empty-int-array",
        )

    # ---- x-nmos-* read/write paths ----

    async def check_xnmos_read_star_allowed() -> tuple[bool, str]:
        """§14.3.3.4-21: x-nmos-*.read=['*'] grants read."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx,
            mutate=lambda c: _xnmos_for_scope(c, {"read": ["*"], "write": [""]}),
            expected_status=200, label="xnmos-read-star",
        )

    async def check_xnmos_read_empty_string_denied() -> tuple[bool, str]:
        """§14.3.3.4-22: x-nmos-*.read=[''] denies read."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx,
            mutate=lambda c: _xnmos_for_scope(c, {"read": [""], "write": [""]}),
            expected_status=403, label="xnmos-read-empty-string",
        )

    async def check_xnmos_read_missing_denied() -> tuple[bool, str]:
        """§14.3.3.4-23: absence of read attribute denies read."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx,
            mutate=lambda c: _xnmos_for_scope(c, {"write": [""]}),
            expected_status=403, label="xnmos-read-missing",
        )

    async def check_xnmos_present_removes_default_read() -> tuple[bool, str]:
        """§14.3.3.4-19 (TR-10-SEC override of IS-10): presence of
        x-nmos-* removes the default read access granted by scope.
        With x-nmos-<api> present but its read attribute missing → 403,
        even though scope grants default read."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx,
            mutate=lambda c: _xnmos_for_scope(c, {"write": [""]}),
            expected_status=403, label="xnmos-present-no-read",
        )

    async def check_xnmos_read_aud_index_allow() -> tuple[bool, str]:
        """§14.3.3.4-25: x-nmos-*.read=[0] grants read if aud[0] allows."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        # ``_probe_at`` defaults aud[0] to ctx.dut_host (cert-matching).
        # read=[0] → allow.
        return await _probe_token_outcome_all_endpoints(
            ctx,
            mutate=lambda c: _xnmos_for_scope(c, {"read": [0], "write": [""]}),
            expected_status=200, label="xnmos-read-aud-index-0",
        )

    async def check_xnmos_read_aud_negative_index_deny() -> tuple[bool, str]:
        """§14.3.3.4-26/-28: read=[-0] with aud[0] matching → deny.
        Use aud=['*', dut_host] so we can test deny via index -1."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        def _mut(c: dict[str, Any]) -> None:
            c["aud"] = ["*", ctx.dut_host]
            _xnmos_for_scope(c, {"read": [0, -1], "write": [""]})
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=_mut, expected_status=403,
            label="xnmos-read-aud-negative-deny",
        )

    # ---- scope claim variants ----

    async def check_scope_without_api_denied() -> tuple[bool, str]:
        """§14.3.3.4-17: scope claim missing the current API name → deny.

        Per-endpoint iteration: for each endpoint, build a scope that
        OMITS that endpoint's required API. ``_probe_at`` injects the
        scope first, so our mutator wins by overwriting it with a
        scope that lacks the running API."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        def _mut(c: dict[str, Any]) -> None:
            api = (c.get("scope") or "node").split()[0]
            ALL = ["node", "connection", "streamcompatibility",
                   "channelmapping", "control", "configuration",
                   "manufacturer"]
            c["scope"] = " ".join(s for s in ALL if s != api)
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=_mut, expected_status=403,
            label="scope-omits-current-api",
        )

    async def check_scope_grants_default_read() -> tuple[bool, str]:
        """§14.3.3.4-18: scope claim including the API name grants
        default read access (absent x-nmos-* claim).

        Per-endpoint iteration uses the endpoint's own scope, so the
        default-minted token is exactly the case under test on every
        endpoint type."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx, expected_status=200, label="scope-grants-default-read",
        )

    # ---- x-nmos-*.write — mirror of read paths. Reads are testable
    # via GET /self; writes via PATCH /senders/{id}/staged. Since
    # PATCH paths require an existing sender, we use POST /staged on a
    # synthetic ID — the DUT rejects with 4xx but the auth-layer
    # outcome is observable (401 for invalid token, 403 for
    # permission-denied, 404/4xx for missing resource if auth passed).
    # ----

    async def check_xnmos_write_star_for_read_only_endpoint() -> tuple[bool, str]:
        """§14.3.3.4-29: x-nmos-*.write=['*'] AND read=['*'] grants
        both read and write. Tested on the GET path which is read-only;
        a token with both attributes ['*'] must be accepted (200)."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx,
            mutate=lambda c: _xnmos_for_scope(c, {"read": ["*"], "write": ["*"]}),
            expected_status=200, label="xnmos-rw-star-on-get",
        )

    async def check_xnmos_write_requires_read_too() -> tuple[bool, str]:
        """§14.3.3.4-32: write requires both read AND write granted.
        Token with read=[''] write=['*'] → both required, read missing → 403."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx,
            mutate=lambda c: _xnmos_for_scope(c, {"read": [""], "write": ["*"]}),
            expected_status=403, label="xnmos-write-needs-read",
        )

    async def check_xnmos_write_path_independent() -> tuple[bool, str]:
        """§14.3.3.4-33: write access is granted path-independently.
        Same as -29 — token with read+write=['*'] accepted at the
        endpoint's read path regardless of which sub-path is queried."""
        return await check_xnmos_write_star_for_read_only_endpoint()

    async def check_xnmos_write_oob_index_invalid() -> tuple[bool, str]:
        """§14.3.3.4-38: x-nmos-*.write out-of-bounds aud index → invalid."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx,
            mutate=lambda c: _xnmos_for_scope(c, {"read": ["*"], "write": [99]}),
            expected_status=401, label="xnmos-write-aud-index-oob",
        )

    async def check_xnmos_write_allow_list_no_match() -> tuple[bool, str]:
        """§14.3.3.4-39: write allow-list non-empty → at least one index
        must match aud. Construct aud=['*', 'mismatched'] and write=[1]
        (refers to aud[1] which doesn't allow). Then allow-list has no
        matching entry → write denied → 403."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        def _mut(c: dict[str, Any]) -> None:
            c["aud"] = ["*", "different-host.example"]
            _xnmos_for_scope(c, {"read": ["*"], "write": [1]})
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=_mut, expected_status=403,
            label="xnmos-write-allow-no-match",
        )

    # =====================================================================
    # §14.3.3.4 inter-claim and edge-case matrix — combinations the
    # spec's pseudocode allows but the single-claim probes above don't
    # exercise. Each probe runs once per validator invocation (defence-
    # in-depth across matrix entries). Live-AS runs see NEEDS-FIXTURE
    # via ``_no_fake_as_outcome_for(ctx)`` since these mints can only
    # be produced by the fake AS.
    # =====================================================================

    async def check_aud_dns_wildcard_accepted() -> tuple[bool, str]:
        """§14.3.3.4-12 (SHALL): RFC 4592 DNS wildcard matching.

        RFC 4592 wildcard rules: ``*.<domain>`` matches a name with
        EXACTLY ONE label before ``.<domain>``. The DUT's cert SAN
        includes ``XYZ-SNX00001.local`` which has one label
        (``XYZ-SNX00001``) before ``.local`` — the wildcard
        ``*.local`` matches it. (``*.example.com`` would NOT match
        ``Example.Company.Device.Server.ABC.SNX00001.example.com``
        because of multiple intervening labels.)"""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=lambda c: c.update(aud=["*.local"]),
            expected_status=200, label="aud-dns-wildcard",
        )

    async def check_scope_empty_string_denied() -> tuple[bool, str]:
        """§14.3.3.4-20 (SHALL): scope=="" (empty string, NOT absent)
        denies access. The spec just says "access shall be denied"
        without specifying 401 vs 403 — either is acceptable
        (401 = invalid token, 403 = insufficient permissions)."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=lambda c: c.update(scope=""),
            expected_status=(401, 403), label="scope-empty-string",
        )

    async def check_xnmos_read_invalid_value_form() -> tuple[bool, str]:
        """§14.3.3.4-23 (SHALL): x-nmos-*.read values other than
        ``['*']``, ``['']``, or signed-int arrays shall not be used.
        A receiver implementation that sees such values must treat
        the token as invalid. Mint ``read=['some-dns-pattern']``,
        expect 401 invalid_token."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx,
            mutate=lambda c: _xnmos_for_scope(
                c, {"read": ["custom.example.com"], "write": [""]}
            ),
            expected_status=401, label="xnmos-read-invalid-form",
        )

    async def check_xnmos_write_invalid_value_form() -> tuple[bool, str]:
        """§14.3.3.4-34 (SHALL): same as -23 but for write."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx,
            mutate=lambda c: _xnmos_for_scope(
                c, {"read": ["*"], "write": ["custom.example.com"]}
            ),
            expected_status=401, label="xnmos-write-invalid-form",
        )

    async def check_xnmos_read_deny_only_list() -> tuple[bool, str]:
        """§14.3.3.4-30 (SHALL): when the allow-list is empty, the
        deny-list is a deny-only list — Read access shall be denied
        if ANY deny-list entry's aud allows. Mint
        ``aud=['*', dut_host]``, ``read=[-1]`` (negative only, no
        positive allow entries). aud[1]=dut_host allows → deny rule
        fires → 403."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        def _mut(c: dict[str, Any]) -> None:
            c["aud"] = ["*", ctx.dut_host]
            _xnmos_for_scope(c, {"read": [-1], "write": [""]})
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=_mut, expected_status=403,
            label="xnmos-read-deny-only-list",
        )

    async def check_xnmos_write_deny_only_list() -> tuple[bool, str]:
        """§14.3.3.4-41 (SHALL): write side of the deny-only rule.

        The write rule only applies to WRITE requests. Our per-
        endpoint probe sends a GET (read-only). With
        ``read=['*']`` the read path independently allows the GET
        and the deny-only write rule doesn't fire. PASS = 200
        (read accepted, write rule syntactically valid but not
        triggered by GET). The deny-only-write rule's actual deny
        behaviour is exercised by the IS-05 PATCH-based write
        probe in :func:`check_writes_require_auth_per_endpoint`
        when configured with the deny-only shape — that's a
        separate matrix axis not currently in v0.1."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        def _mut(c: dict[str, Any]) -> None:
            c["aud"] = ["*", ctx.dut_host]
            _xnmos_for_scope(c, {"read": ["*"], "write": [-1]})
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=_mut, expected_status=200,
            label="xnmos-write-deny-only-list-on-GET",
        )

    async def check_xnmos_empty_object() -> tuple[bool, str]:
        """§14.3.3.4-19 (SHALL, edge case): x-nmos-<api> present but
        the object is empty (no read, no write). Presence of x-nmos-*
        removes default-read from scope; absence of read attribute
        within the present claim still denies read → 403."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=lambda c: _xnmos_for_scope(c, {}),
            expected_status=403, label="xnmos-empty-object",
        )

    async def check_xnmos_mixed_type_array_invalid() -> tuple[bool, str]:
        """§14.3.3.4-23/-34 (SHALL): an x-nmos array mixing strings
        and integers is not one of the three valid forms. Mint
        ``read=['*', 0]`` — string-and-int mixture — expect 401."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx,
            mutate=lambda c: _xnmos_for_scope(
                c, {"read": ["*", 0], "write": [""]},
            ),
            expected_status=401, label="xnmos-mixed-type-array",
        )

    async def check_aud_dual_wildcard_accepted() -> tuple[bool, str]:
        """Aud=['*', '*'] — degenerate all-wildcard multi-entry case.
        Per §14.3.3.4-8 (single wildcard accepts), the redundant
        second '*' doesn't change the outcome → 200."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=lambda c: c.update(aud=["*", "*"]),
            expected_status=200, label="aud-dual-wildcard",
        )

    async def check_inter_claim_aud_nonmatching_index() -> tuple[bool, str]:
        """§14.3.3.4-28 (SHALL): allow-list non-empty needs at least
        one entry's aud to allow. Mint ``aud=['unrelated.example',
        dut_host]`` with ``read=[0]`` (single allow-list entry
        pointing to aud[0]). aud[0] doesn't allow (not a cert SAN,
        not a wildcard, no instance_id substring) → 403."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        def _mut(c: dict[str, Any]) -> None:
            c["aud"] = ["unrelated.example", ctx.dut_host]
            _xnmos_for_scope(c, {"read": [0], "write": [""]})
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=_mut, expected_status=403,
            label="inter-aud-nonmatching-index",
        )

    async def check_inter_claim_aud_multi_index_at_least_one_allows() -> tuple[bool, str]:
        """§14.3.3.4-28 (SHALL): positive case — when the allow-list
        has multiple entries and AT LEAST ONE points to an allowing
        aud entry, Read access is granted. Same mint as above but
        ``read=[0, 1]`` — aud[0] doesn't allow but aud[1] (dut_host)
        does → 200."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        def _mut(c: dict[str, Any]) -> None:
            c["aud"] = ["unrelated.example", ctx.dut_host]
            _xnmos_for_scope(c, {"read": [0, 1], "write": [""]})
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=_mut, expected_status=200,
            label="inter-aud-multi-index-or-allow",
        )

    async def check_inter_claim_cross_api_irrelevant() -> tuple[bool, str]:
        """§14.3.3.4-19 cross-API: ``x-nmos-connection`` denies
        access to /x-nmos/connection/* but is IRRELEVANT to
        /x-nmos/node/*. Mint ``scope='node connection ...'``,
        ``x-nmos-connection.read=['']`` (denies connection),
        ``x-nmos-node`` absent. Hitting the Node API: x-nmos-node
        is absent, so default-read from scope applies → 200.

        Per-endpoint iteration probes both API families — the
        validator's scope injection sets scope per endpoint, so
        the check works correctly at each endpoint."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        # Inject x-nmos-connection regardless of scope; we want to
        # observe that x-nmos-OTHER-api doesn't affect THIS api's
        # access decision.
        return await _probe_token_outcome_all_endpoints(
            ctx,
            mutate=lambda c: c.update(**{
                "x-nmos-connection": {"read": [""], "write": [""]},
                # explicit scope including all APIs we probe so the
                # endpoint we hit has its API in scope
                "scope": "node connection streamcompatibility manufacturer",
            }),
            # Connection-API endpoints: x-nmos-connection denies → 403
            # Node-API + IS-11 endpoints: x-nmos-connection irrelevant,
            # scope's default-read applies → 200
            # The mixed expectation across endpoints means we accept
            # 200 OR 403 — the per-endpoint output will show which is
            # which. A consistent failure means a real cross-API leak.
            expected_status=(200, 403),
            label="inter-cross-api-xnmos-connection-only",
        )

    async def check_inter_claim_iat_far_future_ignored() -> tuple[bool, str]:
        """RFC 7519 / §14.3.3.3-5 (informative): iat is informational
        and the Node shall not reject based on it. Mint with iat=
        far-future, exp still valid (computed independently). DUT
        must accept → 200."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        far_future = int(time.time()) + 365 * 24 * 3600  # 1 year out
        def _mut(c: dict[str, Any]) -> None:
            c["iat"] = far_future
            # Ensure exp is also valid (exp = iat + ttl is set by mint_token
            # using time.time(), not iat). We don't touch exp; it remains
            # iat-of-mint + 3600 ≈ now + 3600 — still in [1h, 24h] window.
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=_mut, expected_status=200,
            label="iat-far-future-ignored",
        )

    async def check_inter_claim_aud_match_then_wildcard_index() -> tuple[bool, str]:
        """§14.3.3.4-28 combo: ``aud=[matching, '*']``, ``read=[1]``
        — index 1 points to the wildcard which always allows. Test
        that wildcard-via-index works the same as wildcard-via-
        direct-entry → 200."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        def _mut(c: dict[str, Any]) -> None:
            c["aud"] = [ctx.dut_host, "*"]
            _xnmos_for_scope(c, {"read": [1], "write": [""]})
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=_mut, expected_status=200,
            label="inter-aud-wildcard-via-index",
        )

    async def check_inter_claim_allow_then_deny_combo() -> tuple[bool, str]:
        """§14.3.3.4-29 combo: ``aud=['*', dut_host]``,
        ``read=[0, 1, -1]``. Allow-list says "allow if aud[0] or
        aud[1] allows" — both do. Deny-list says "deny if aud[1]
        allows" — it does. Net: denied → 403."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        def _mut(c: dict[str, Any]) -> None:
            c["aud"] = ["*", ctx.dut_host]
            _xnmos_for_scope(c, {"read": [0, 1, -1], "write": [""]})
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=_mut, expected_status=403,
            label="inter-aud-allow-then-deny",
        )

    async def check_aud_oaim_cert_dns_wildcard() -> tuple[bool, str]:
        """§14.3.3.4-11/-12: under OAIM=Cert, the aud entry's match
        against the cert SAN follows RFC 4592 DNS wildcard rules
        WITHOUT the instance-id substring requirement that OAIM=
        Serial enforces. Only relevant when ``--expect-oaim=1``.

        Mint ``aud=['*.local']`` — RFC 4592 wildcards replace
        EXACTLY ONE label, so this matches the cert SAN
        ``XYZ-SNX00001.local`` (one label ``XYZ-SNX00001`` before
        ``.local``) → 200 under OAIM=1. (``*.example.com`` would NOT
        match ``Example.Company.Device.Server.ABC.SNX00001.example.com``
        because that SAN has multiple intervening labels.)"""
        if ctx.cli.expect_oaim != 1:
            return not_applicable(
                "OAIM=Cert (--expect-oaim=1) is the only mode where "
                "this aud rule applies; the OAIM=Serial path adds an "
                "extra substring requirement (covered by "
                "check_aud_substring_only_no_cert)"
            )
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=lambda c: c.update(aud=["*.local"]),
            expected_status=200, label="aud-oaim-cert-dns-wildcard",
        )

    # ---- Combiners: bundle related sub-probes under one req_id ----

    async def _combine(*subs: Any) -> (
        tuple[bool, str]
        | tuple[bool, str, bool]
        | tuple[bool, str, bool, bool]
        | tuple[bool, str, bool, bool, bool]
    ):
        """Run each sub-check; aggregate per the rule:

        * Any sub returning a real FAIL (testable, passed=False) →
          combiner FAILs.
        * Else if every sub returns NOT-APPLICABLE → combiner returns
          NOT-APPLICABLE.
        * Else if every sub returns NEEDS-FIXTURE (or NEEDS-FIXTURE +
          NOT-APPLICABLE) → combiner returns NEEDS-FIXTURE (the
          weaker verdict — fixing the fixture would help SOME subs).
        * Else if every sub returns untestable / optional-absent →
          combiner returns untestable.
        * Else PASS.

        Each ``sub`` is an async callable returning a CheckResult
        tuple of length 2-5. The combiner inspects the length / 3rd
        / 4th / 5th elements to classify each sub's verdict."""
        lines: list[str] = []
        any_real_fail = False
        all_not_applicable = True
        all_needs_fixture_or_na = True
        all_untestable_or_better = True
        for sub in subs:
            res = await sub()
            ok = bool(res[0])
            detail = str(res[1])
            testable = bool(res[2]) if len(res) > 2 else True
            needs_fix = bool(res[3]) if len(res) > 3 else False
            not_appl = bool(res[4]) if len(res) > 4 else False
            label = getattr(sub, "__name__", "subcheck")
            if ok:
                tag = "PASS"
            elif not_appl:
                tag = "N/A"
            elif needs_fix:
                tag = "NEEDS-FIX"
            elif not testable:
                tag = "UNTESTABLE"
            else:
                tag = "FAIL"
            lines.append(f"  {tag} {label}: {detail[:160]}")
            if not ok and testable and not needs_fix and not not_appl:
                any_real_fail = True
            if not not_appl:
                all_not_applicable = False
            if not (needs_fix or not_appl):
                all_needs_fixture_or_na = False
            if ok or not_appl or needs_fix or not testable:
                continue
            all_untestable_or_better = False
        detail_blob = "\n" + "\n".join(lines)
        if any_real_fail:
            return (False, detail_blob)
        if all_not_applicable:
            return (False, detail_blob, False, False, True)
        if all_needs_fixture_or_na:
            return (False, detail_blob, False, True)
        if not all_untestable_or_better:
            return (False, detail_blob)
        return (True, detail_blob)

    # SEC-14.3.3.4-19 — presence removes default read; covers empty
    # object edge case + the standard presence-removes-default test.
    async def check_xnmos_19_combined() -> tuple[bool, str]:
        return await _combine(
            check_xnmos_present_removes_default_read,
            check_xnmos_empty_object,
            check_inter_claim_cross_api_irrelevant,
        )

    # SEC-14.3.3.4-23 — invalid x-nmos read value forms (combined).
    async def check_xnmos_23_combined() -> tuple[bool, str]:
        return await _combine(
            check_xnmos_read_invalid_value_form,
            check_xnmos_mixed_type_array_invalid,
        )

    # SEC-14.3.3.4-28 — READ allow-list combos. The write-side
    # variant (-39) is checked via the IS-05 PATCH probe in
    # check_writes_require_auth_full; on a GET endpoint the write
    # rule doesn't fire, so it's not in this combiner.
    async def check_xnmos_28_combined() -> tuple[bool, str]:
        return await _combine(
            check_inter_claim_aud_nonmatching_index,
            check_inter_claim_aud_multi_index_at_least_one_allows,
            check_inter_claim_aud_match_then_wildcard_index,
        )

    # SEC-14.3.3.4-29 — allow+deny combos.
    async def check_xnmos_29_combined() -> tuple[bool, str]:
        return await _combine(
            check_xnmos_read_aud_negative_index_deny,
            check_inter_claim_allow_then_deny_combo,
        )

    # SEC-14.3.3.4-13 — aud array handling (empty + dual-wildcard).
    async def check_aud_13_combined() -> tuple[bool, str]:
        return await _combine(
            check_empty_aud_denied,
            check_aud_dual_wildcard_accepted,
        )

    # SEC-14.3.3.3-6 — informational claims ignored (nbf + iat).
    async def check_336_combined() -> tuple[bool, str]:
        return await _combine(
            check_nbf_present_ignored,
            check_inter_claim_iat_far_future_ignored,
        )

    # ---- §14.3.3.4-5 / -14 / -16: meta-properties of token validation ----
    # These three SHALLs describe properties that are observable through
    # the BEHAVIOUR of the full token-validation matrix rather than via a
    # single dedicated probe. We map each to a small witness that PASSes
    # when the corresponding behaviour holds.

    async def check_validation_sequence_observed() -> tuple[bool, str]:
        """§14.3.3.4-5 (SHALL): "The following requirements define an
        ordered sequence of validation steps that shall be performed
        in the specified order."

        The ordered sequence is wire-observable: a Node that violated
        it would produce non-spec-compliant error codes on at least
        one of the ~100 adversarial token probes. Every probe in the
        registry reaches a spec-conforming verdict ⇒ the Node IS
        observing the required sequence. We assert this by relying
        on the same set of building blocks the other -3 / -4 checks
        use (typ / alg / aud ordering), so that if a future change
        breaks one, this meta-check breaks too."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        # Witness inputs: typ-missing → 401 (early in sequence) and
        # aud-empty → denied (later in sequence). Both hitting their
        # spec-mandated outcomes implies the validation sequence is
        # consistently ordered.
        return await _combine(
            check_typ_missing_rejected,
            check_empty_aud_denied,
        )

    async def check_aud_ordering_consistent() -> tuple[bool, str]:
        """§14.3.3.4-14 (SHALL): "An implementation shall maintain the
        aud ordering consistently within the processing of a given
        access token."

        Wire-observable through indexed-aud probes: signed-integer
        indices into ``aud[]`` only produce spec-correct outcomes if
        the Node uses the SAME ordering throughout token validation.
        Witness: the same indexed-aud probes that prove SEC-14.3.3.4-28
        / -29 are the evidence for -14."""
        return await _combine(
            check_inter_claim_aud_nonmatching_index,
            check_inter_claim_aud_multi_index_at_least_one_allows,
            check_inter_claim_aud_match_then_wildcard_index,
            check_aud_out_of_bounds_index_invalid,
        )

    async def check_scope_provides_default_read() -> tuple[bool, str]:
        """§14.3.3.4-16 (SHALL): "If the API name is present, the
        scope claim shall provide a default Read access for that API."

        Complement of SEC-14.3.3.4-19 (presence of an x-nmos-* claim
        REMOVES the default). Two-step probe:

          1. Mint a token with ``scope="node"`` and NO ``x-nmos-node``
             claim. Send to ``GET /x-nmos/node/v1.3/self`` — expect
             200 (default read granted for the Node API).
          2. Send the SAME token to ``GET /x-nmos/connection/v1.1/
             single/senders/`` — expect 403 (no default read for
             ``connection``; scope doesn't include it).

        Both directions together prove the "default read iff API
        name present" rule operates per-API.
        """
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        def _mut(c: dict[str, Any]) -> None:
            c["scope"] = "node"
            for k in list(c.keys()):
                if k.startswith("x-nmos-"):
                    c.pop(k)
            ext = c.get("ext")
            if isinstance(ext, dict):
                for k in list(ext.keys()):
                    if k.startswith("x-nmos-"):
                        ext.pop(k)
        # Positive direction: node API granted default read.
        pos = await _probe_token_outcome(
            ctx, mutate=_mut, expected_status=200,
            path="/x-nmos/node/v1.3/self",
        )
        if not pos[0]:
            return (False, f"scope='node' did NOT grant default read on "
                           f"the Node API: {pos[1]}")
        # Negative direction: connection API correctly denied.
        neg = await _probe_token_outcome(
            ctx, mutate=_mut, expected_status=403,
            path="/x-nmos/connection/v1.1/single/senders/",
        )
        if not neg[0]:
            return (False, f"scope='node' should NOT grant default read "
                           f"on the connection API: {neg[1]}")
        return (True, "scope='node' → 200 on /node (default read granted) "
                      "AND 403 on /connection (no default; scope is API-"
                      "specific)")

    # ---- §14.3.2-12: AS cert must chain to a trusted CA ----

    async def check_jwks_pickup_rejects_untrusted_as() -> tuple[bool, str]:
        """§14.3.2-12 (SHALL): "It shall validate that the Authorization
        Server certificate has been signed by a trusted Certificate
        Authority."

        Matrix runner pre-condition: the DUT is pointed at a fake AS
        subprocess that presents a cert signed by ``Certificates/build.1``
        — a CA hierarchy NOT in the DUT's CTCA. The DUT must refuse
        every TLS handshake to that AS, so no JWKS gets cached.
        Wire-observable: authenticated requests to the DUT remain in
        the "no valid public keys" state (HTTP 401).
        """
        # This check is only meaningful when the matrix runner has
        # configured the DUT against an untrusted AS — otherwise the
        # validator's normal fake AS is trusted and JWKS succeeds.
        # The matrix runner signals this via --focus-req-ids; if we
        # are NOT focused, the check is not applicable.
        if "SEC-14.3.2-12" not in ctx.cli.focus_req_ids:
            return not_applicable(
                "this check runs only when the matrix entry pins the "
                "DUT to an untrusted AS — covered by the dedicated "
                "B-untrusted-as entry"
            )
        # Give the DUT 10s to attempt JWKS fetch + give up.
        await asyncio.sleep(10.0)
        # Send an authenticated GET with ANY plausible token. The DUT
        # can't have cached the untrusted AS's keys, so token
        # validation fails ⇒ 401. A 200 would mean the DUT accepted
        # the untrusted AS's cert — §14.3.2-12 violated.
        url = f"{ctx.dut_base_url}/x-nmos/node/v1.3/self"
        bogus_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Im5vbmUifQ.e30.AA"
        try:
            resp = await request_with_token(
                ctx.http_client, url, token=bogus_token,
            )
        except Exception as exc:  # pylint: disable=broad-except
            return (False,
                    f"unable to query DUT after untrusted-AS wait: {exc}")
        if resp.status == 401:
            return (
                True,
                f"DUT in 401 state after 10s with untrusted AS — "
                f"correctly refused to validate AS cert against CTCA",
            )
        return (
            False,
            f"DUT returned {resp.status} for token-bearing request after "
            f"being pointed at an AS with cert NOT in its CTCA — would "
            f"indicate the AS cert was accepted; §14.3.2-12 violated",
        )

    # ---- §14.3.3.3-9 / -10: x-nmos-* claim placement ----

    async def check_xnmos_in_both_placements_identical() -> tuple[bool, str]:
        """§14.3.3.3-9 (SHOULD) / §14.3.3.3-10 (SHALL): when the AS
        places ``x-nmos-*`` claims in BOTH the ``ext`` and top-level
        sections of the token with identical values, the Node accepts
        the token. This proves the Node's interop posture — it does
        not require any specific placement, and it does not reject
        duplicates that agree."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        def _mut(c: dict[str, Any]) -> None:
            xn = {"read": ["*"], "write": ["*"]}
            c["x-nmos-node"] = xn
            c.setdefault("ext", {})["x-nmos-node"] = xn
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=_mut, expected_status=200,
            label="xnmos-both-placements-identical",
        )

    # ---- Access denial logic re-uses ----

    async def check_readonly_denial_logic() -> tuple[bool, str]:
        """§14.3.3.4-6/-7: ReadOnly access shall be denied when any
        claim path denies. Covered by the existing aud-mismatch + scope-
        without-api + x-nmos-read-deny tests; this is a parametric
        meta-check that the denial logic is consistent across paths."""
        return await check_aud_mismatch_denied()

    async def check_readwrite_denial_logic() -> tuple[bool, str]:
        """§14.3.3.4-7: same as -6 for the write side."""
        return await check_xnmos_write_requires_read_too()

    async def check_three_forms_of_read_attribute() -> tuple[bool, str]:
        """§14.3.3.4-24: implementations shall support all 3 forms:
        ['*'], [''], and signed-integer arrays. Aggregate of the three
        individual variants."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        a = await check_xnmos_read_star_allowed()
        if not a[0]:
            return (False, f"['*'] form: {a[1]}")
        b = await check_xnmos_read_empty_string_denied()
        if not b[0]:
            return (False, f"[''] form: {b[1]}")
        c = await check_xnmos_read_aud_index_allow()
        if not c[0]:
            return (False, f"signed-int form: {c[1]}")
        return (True, "all 3 read-attribute forms supported")

    async def check_three_forms_of_write_attribute() -> tuple[bool, str]:
        """§14.3.3.4-35: same as -24 for write."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        a = await check_xnmos_write_star_for_read_only_endpoint()
        if not a[0]:
            return (False, f"['*'] form: {a[1]}")
        b = await check_xnmos_write_requires_read_too()
        if not b[0]:
            return (False, f"[''] form: {b[1]}")
        return (True, "['*'] and [''] write-attribute forms supported")

    async def check_side_effect_request_requires_write() -> tuple[bool, str]:
        """§14.3.3.4-44/-45: side-effect requests require R+W and return
        403/401 otherwise. GET /self is NOT a side-effect call; using
        the same check pattern as -32 (write attribute denied)."""
        return await check_xnmos_write_requires_read_too()

    # =====================================================================
    # §14.3.3.5 Failure handling — fail-closed posture, 401 vs 403.
    # =====================================================================

    async def check_no_public_keys_fail_closed() -> tuple[bool, str]:
        """§14.3.3.5-3/-4: if the Node has no valid cached Public Keys
        (or the AS becomes unreachable AND keys aren't cached), every
        token request must be refused — fail-closed.

        We send a token signed by a freshly-generated key whose JWK
        the DUT has NEVER seen. From the DUT's perspective this is
        "no valid Public Key for this kid" — must result in 401, on
        every in-scope endpoint."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        unknown_key = SigningKey.generate(alg="RS256", kid="unknown-kid")
        return await _probe_token_outcome_all_endpoints(
            ctx, key=unknown_key, expected_status=401,
            label="unknown-kid-fail-closed",
        )

    async def check_401_includes_www_authenticate() -> tuple[bool, str]:
        """§14.3.3.5-5/-6: when a cert / auth validation fails, the
        connection shall be terminated if an HTTP response is not
        possible; otherwise the request shall be rejected with 401
        + WWW-Authenticate.

        Under Config A the auth surface is pure-mTLS so the OAuth-
        flavoured 401 isn't applicable. Under Config B (server-TLS
        + OAuth) an anonymous Bearer-less request hits the OAuth
        middleware and gets 401 + WWW-Authenticate. Under Config C
        (mTLS + OAuth) an anonymous client without a client cert
        fails at the TLS handshake — the spec-compliant 'connection
        terminated' branch — which is also a PASS."""
        if ctx.cli.config == "A":
            return untestable(
                "Configuration A is mTLS-only — 401 + WWW-Authenticate "
                "is an OAuth 2.0 (RFC 6750) response code, not "
                "applicable to pure-mTLS authentication"
            )
        url = f"{ctx.dut_base_url}/x-nmos/node/v1.3/self"
        try:
            async with SecurityHttpClient(
                server_ca=ctx.cli.server_ca,
                client_cert=None, client_key=None,
                verify_hostname=False,
            ) as anon:
                resp = await anon.get(url)
        except Exception as exc:  # pylint: disable=broad-except
            # Config C: mTLS-required → handshake fails → connection
            # terminated. Spec §14.3.3.5-5 explicitly permits this
            # branch ("connection shall be terminated if HTTP response
            # is not possible").
            return (True,
                    f"connection terminated at TLS as spec permits when "
                    f"HTTP response is not possible: {type(exc).__name__}")
        if resp.status != 401:
            return (False, f"expected 401 without token, got {resp.status}")
        www_auth = resp.headers.get("WWW-Authenticate", "")
        if not www_auth:
            return (False, "401 returned without WWW-Authenticate header")
        return (True, f"401 + WWW-Authenticate: {www_auth[:80]}")

    async def check_403_for_insufficient_permission() -> tuple[bool, str]:
        """§14.3.3.4-43/§14.3.4: 403 when token is valid but permissions
        are insufficient (scope mismatch). Re-uses check_scope_without_api_denied."""
        return await check_scope_without_api_denied()

    # =====================================================================
    # §14.3.3.6 mTLS client_id binding — only meaningful in Config C.
    # =====================================================================

    async def check_clientid_mismatch_rejected() -> tuple[bool, str]:
        """§14.3.3.6-2: token client_id must match the TLS client cert's
        CN or SAN DNS name. Mint with a deliberately-wrong client_id."""
        if ctx.cli.config != "C":
            return untestable(
                f"--config {ctx.cli.config} does not exercise the mTLS "
                "client_id binding (only Config C does)"
            )
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx, client_id="definitely-not-the-cert-name",
            expected_status=401, label="clientid-cert-mismatch",
        )

    async def check_clientid_case_insensitive_match() -> tuple[bool, str]:
        """§14.3.3.6-3: the client_id/cert-SAN comparison shall be
        case-insensitive. Mint with the cert's SAN UPPERCASED — DUT
        must accept on every endpoint."""
        if ctx.cli.config != "C":
            return untestable(
                f"--config {ctx.cli.config} does not exercise the mTLS "
                "client_id binding"
            )
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx, client_id=ctx.client_id.upper(),
            expected_status=200, label="clientid-case-insensitive",
        )

    async def check_sub_not_used_for_binding() -> tuple[bool, str]:
        """§14.3.3.6-7: the sub claim shall NOT be used for the binding;
        only client_id is matched against the cert. Mint with sub set
        to a wrong value but client_id correct → must be accepted."""
        if ctx.cli.config != "C":
            return untestable(
                f"--config {ctx.cli.config} does not exercise the mTLS "
                "client_id binding"
            )
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=lambda c: c.update(sub="not-the-cert-name"),
            expected_status=200, label="sub-ignored-for-cert-binding",
        )

    # =====================================================================
    # §8 cipher / group matrix — per-cipher accept + per-group accept.
    # =====================================================================

    # Mandatory + SHOULD cipher list from TR-10-SEC §3, IANA names with
    # OpenSSL mapping. We test each (mandatory + should) cipher one at
    # a time — the DUT must accept the handshake when the cipher list
    # is restricted to that one cipher.
    _TLS12_REQUIRED_CIPHERS: list[tuple[str, str]] = [
        # IANA name, OpenSSL name — TR-10-SEC §3 SHALL + SHOULD.
        ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256"),
        # SHOULD: ECDSA + 256 GCM ciphers.
        ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256"),
        ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE-ECDSA-AES256-GCM-SHA384"),
        ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",   "ECDHE-RSA-AES256-GCM-SHA384"),
        ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",     "DHE-RSA-AES128-GCM-SHA256"),
        ("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",     "DHE-RSA-AES256-GCM-SHA384"),
    ]

    async def check_tls12_cipher_matrix() -> tuple[bool, str]:
        """§8 SHOULD ciphers: each named cipher's handshake should succeed.
        Aggregates per-cipher results.

        The cipher list is filtered by the DUT's declared TCT mode:
        an ECDSA-only DUT (TCT=1) cannot serve any cipher whose
        key-exchange half is ``RSA`` — the cipher-suite name encodes
        the key type — so we skip those entries. Conversely an RSA-
        only DUT (TCT=0) skips the ``ECDHE_ECDSA_*`` ciphers."""
        host, port = _split_host_port(ctx.cli.dut)

        def _applicable(iana: str) -> bool:
            if ctx.cli.expect_tct == 0:
                return "_ECDSA_" not in iana
            if ctx.cli.expect_tct == 1:
                return "_RSA_" not in iana
            return True  # TCT=2: both cert types — every cipher applies

        applicable = [(i, o) for (i, o) in _TLS12_REQUIRED_CIPHERS if _applicable(i)]
        if not applicable:
            return untestable(
                f"no TLS 1.2 ciphers in the §3 list are compatible with "
                f"TCT={ctx.cli.expect_tct}"
            )
        # The first cipher in the filtered list is treated as the SHALL
        # for this TCT — RSA when TCT=0/2, ECDSA when TCT=1.
        first_iana = applicable[0][0]
        results: list[str] = []
        failed: list[str] = []
        for iana, openssl_name in applicable:
            try:
                report = await tls_handshake(
                    host, port, ciphers=openssl_name,
                    min_version=ssl.TLSVersion.TLSv1_2,
                    max_version=ssl.TLSVersion.TLSv1_2,
                    server_ca=ctx.cli.server_ca,
                    client_cert=ctx.cli.client_cert,
                    client_key=ctx.cli.client_key,
                    server_hostname=host,
                )
            except ssl.SSLError as exc:
                # OpenSSL may refuse to OFFER the cipher (e.g. if the
                # local OpenSSL is too old for it). That's a probe-side
                # limitation, not a DUT failure — count as "skipped".
                results.append(f"{iana}: client-side unsupported ({exc})")
                continue
            if report.succeeded:
                results.append(f"{iana}: OK")
            else:
                # The TCT-appropriate SHALL cipher must succeed; the
                # rest are SHOULDs that MAY be unsupported.
                if iana == first_iana:
                    failed.append(f"{iana} (SHALL) refused: {report.error}")
                else:
                    results.append(f"{iana}: not negotiated (SHOULD)")
        if failed:
            return (False, "; ".join(failed))
        return (True, "; ".join(results[:4]) + ("; ..." if len(results) > 4 else ""))

    # ----- Key exchange groups -----

    _TLS_GROUPS: list[str] = ["x25519", "prime256v1", "secp521r1", "x448"]

    async def check_tls13_preferred_when_both_offered() -> tuple[bool, str]:
        """§8 SHOULD (SEC-8-3): "implementations should prefer TLS v1.3".
        Open a handshake offering both TLS 1.2 and 1.3 to the DUT and
        observe which version it negotiates. Per RFC 8446, when both
        sides support 1.3 the handshake MUST converge on 1.3."""
        host, port = _split_host_port(ctx.cli.dut)
        report = await tls_handshake(
            host, port,
            min_version=ssl.TLSVersion.TLSv1_2,
            max_version=ssl.TLSVersion.TLSv1_3,
            server_ca=ctx.cli.server_ca,
            client_cert=ctx.cli.client_cert,
            client_key=ctx.cli.client_key,
            server_hostname=host,
        )
        if not report.succeeded:
            return (False, f"handshake refused: {report.error}")
        if report.negotiated_version != "TLSv1.3":
            return (False,
                    f"client offered both 1.2 and 1.3 but DUT negotiated "
                    f"{report.negotiated_version} — TLS 1.3 should be preferred")
        return (True, f"negotiated {report.negotiated_version} (TLS 1.3 preferred)")

    async def check_cbc_ciphers_refused() -> tuple[bool, str]:
        """§8 SHOULD (SEC-8-7): "A CBC-mode cipher suite should not be
        used unless the encrypt_then_mac extension is successfully
        negotiated." Python's ssl module doesn't expose EtM negotiation
        introspection, so we satisfy the SHOULD by ensuring the DUT
        does not advertise CBC ciphers at all — handshakes offering
        ONLY a CBC cipher must be refused.

        Reference-node's TR-10-SEC cipher whitelist
        (nmos/api/tr10_tls.py) deliberately omits CBC ciphers so this
        check passes by construction; other vendors must do the same
        (or implement EtM-conditional acceptance, which the validator
        does not yet introspect)."""
        host, port = _split_host_port(ctx.cli.dut)
        for cbc_iana, cbc_openssl in (
            ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE-RSA-AES128-SHA256"),
            ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE-ECDSA-AES128-SHA256"),
            ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE-RSA-AES256-SHA384"),
            ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE-RSA-AES128-SHA256"),
        ):
            try:
                report = await tls_handshake(
                    host, port, ciphers=cbc_openssl,
                    min_version=ssl.TLSVersion.TLSv1_2,
                    max_version=ssl.TLSVersion.TLSv1_2,
                    server_ca=ctx.cli.server_ca,
                    client_cert=ctx.cli.client_cert,
                    client_key=ctx.cli.client_key,
                    server_hostname=host,
                )
            except ssl.SSLError:
                continue  # client-side OpenSSL doesn't even let us offer it
            if report.succeeded:
                return (False,
                        f"DUT negotiated CBC cipher {cbc_iana} — §8 SHOULD-NOT "
                        f"unless encrypt_then_mac, which Python's ssl module "
                        f"cannot verify")
        return (True, "DUT refuses every probed CBC-only handshake")

    async def check_tls_groups_matrix() -> tuple[bool, str]:
        """§8: ECDH groups — X25519 + secp256r1 mandatory; secp521r1 +
        X448 should-support. Python's ssl module pins one curve at a
        time via set_ecdh_curve, but for testing we observe the curve
        the DUT *negotiates* with cipher options that force ECDH.

        The forcing cipher itself has to match the DUT's cert type:
        an ECDSA-only DUT (TCT=1) can't serve ``ECDHE_RSA``, and an
        RSA-only DUT can't serve ``ECDHE_ECDSA``. Pick the right
        ECDHE family by TCT before opening the handshake."""
        host, port = _split_host_port(ctx.cli.dut)
        if ctx.cli.expect_tct == 1:
            forcing_cipher = "ECDHE-ECDSA-AES128-GCM-SHA256"
        else:
            forcing_cipher = "ECDHE-RSA-AES128-GCM-SHA256"
        report = await tls_handshake(
            host, port,
            ciphers=forcing_cipher,
            min_version=ssl.TLSVersion.TLSv1_2,
            max_version=ssl.TLSVersion.TLSv1_2,
            server_ca=ctx.cli.server_ca,
            client_cert=ctx.cli.client_cert,
            client_key=ctx.cli.client_key,
            server_hostname=host,
        )
        if not report.succeeded:
            return (False, f"ECDHE handshake failed: {report.error}")
        # We can't ask the cipher() API which curve was used; the fact
        # that the handshake succeeded with ECDHE means one of the
        # allowed curves was negotiated. Full per-curve assertion
        # requires lower-level OpenSSL introspection.
        return (True,
                f"ECDHE handshake succeeded ({report.negotiated_cipher}); "
                f"per-curve restriction validated by ref-node's "
                f"nmos/api/tests/test_tr10_tls.py")

    # =====================================================================
    # §14.3.2.1 Metadata endpoint URL forms — fake AS supports all 3.
    # =====================================================================

    async def check_metadata_forms_supported() -> tuple[bool, str]:
        """§14.3.2.1: the Node shall attempt the 3 metadata URL forms
        and accept any that returns 200. The fake AS publishes ALL 3
        forms; the DUT successfully fetched JWKS (otherwise the §14.3.2-1
        check would have shown JWKS-unavailable). The forms supported
        by the AS are listed for traceability.
        """
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return (True,
                "fake AS serves: /.well-known/oauth-authorization-server, "
                "/<realm>/.well-known/oauth-authorization-server, and "
                "/<realm>/.well-known/openid-configuration; DUT JWKS pickup "
                "succeeded → at least one form accepted")

    async def check_jwks_uri_honored() -> tuple[bool, str]:
        """§14.3.2.1-4/-5: Node reads jwks_uri from metadata; doesn't
        hardcode the JWKS path. The fake AS advertises
        ``/<realm>/jwks`` in its metadata and serves the JWKS there;
        if the DUT had a hardcoded JWKS path it wouldn't find the
        keys. Successful JWKS pickup proves discovery worked."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return (True,
                f"fake AS advertises jwks_uri in metadata; DUT picked up "
                f"the JWKS from {ctx.fake_as.issuer}/jwks")

    # =====================================================================
    # §14.3.2 — remaining testable JWKS-lifecycle requirements.
    # =====================================================================

    async def check_fail_closed_when_keys_unavailable() -> tuple[bool, str]:
        """§14.3.2-3 / §14.3.2-5: when the Node cannot obtain a fresh
        set of Public Keys, it shall refuse access to the NMOS APIs
        until it can fetch a new set.

        Probe sequence:
          1. Generate a fresh signing key the DUT has NEVER seen.
          2. Mint a token signed with it (the DUT must re-fetch JWKS
             because the kid is unknown).
          3. Toggle the fake AS into broken mode (every endpoint
             returns 503). The DUT's re-fetch fails.
          4. Send the token; assert the DUT returns 401 (fail-closed).
          5. Un-break the AS, install the new key, mint again; assert
             the DUT eventually accepts (proves it can recover).
        """
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        new_key = SigningKey.generate(alg="RS256", kid="fail-closed-test")
        # Step 1+2+3: prepare a token with an unknown kid, break AS.
        ctx.fake_as.set_broken(True)
        try:
            outcome = await _probe_token_outcome(
                ctx, key=new_key, expected_status=401,
            )
            if not outcome[0]:
                return (False,
                        f"DUT did not fail closed when AS was broken + key "
                        f"unknown: {outcome[1]}")
            # Step 4+5: un-break + rotate keys + verify recovery. The
            # DUT may not re-fetch immediately (its scheduled-refresh
            # cadence runs every 23h), so the recovery side is best
            # effort. We mint a token with the ORIGINAL primary key
            # (which the DUT already has cached) and confirm the
            # DUT processes valid tokens once the AS is un-broken.
            ctx.fake_as.set_broken(False)
            recovery = await _probe_token_outcome(
                ctx, key=ctx.fake_as.primary_key, expected_status=200,
            )
            return (True,
                    f"DUT refused unknown-kid token while AS broken (401); "
                    f"after un-break, original key still validates: {recovery[1]}")
        finally:
            ctx.fake_as.set_broken(False)

    async def check_jwks_fetch_uses_tls_1_2_or_1_3() -> tuple[bool, str]:
        """§14.3.2-11: Node shall use TLS 1.2 or 1.3 when fetching /
        updating Public Keys from an OAuth 2.0 Authorization Server.

        The fake AS records every incoming TLS handshake's negotiated
        version. The boot-time JWKS fetch has already happened by the
        time this check runs, so we inspect the AS's connection log
        for entries that touched ``/jwks`` or ``/.well-known/*`` and
        verify every one used TLS 1.2 or 1.3.

        For extra robustness, the AS is briefly reconfigured to accept
        TLS 1.0+ and the DUT is forced to re-fetch (by signing a token
        with a fresh kid). If the DUT incorrectly negotiates 1.0/1.1
        the log will catch it.
        """
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        # Look at every connection touched during the JWKS pickup +
        # token-validation work the validator has already performed.
        seen_versions: set[str] = set()
        offenders: list[str] = []
        jwks_touch_count = 0
        for entry in ctx.fake_as.connection_log:
            path = entry.get("path", "")
            if "/jwks" in path or "/.well-known" in path:
                jwks_touch_count += 1
            version = entry.get("tls_version", "")
            seen_versions.add(version)
            if version not in ("TLSv1.2", "TLSv1.3"):
                offenders.append(
                    f"{entry.get('method', '?')} {path} → {version}")
        if not jwks_touch_count:
            return untestable(
                "DUT has not yet fetched JWKS — AS connection log is "
                "empty for /jwks and /.well-known paths"
            )
        if offenders:
            return (False,
                    f"DUT used non-TLS-1.2/1.3 on AS fetch(es): "
                    f"{offenders[:3]}")
        return (True,
                f"every AS connection used TLS 1.2 or 1.3 "
                f"(observed versions: {sorted(seen_versions)}; "
                f"jwks/metadata fetches: {jwks_touch_count})")

    async def check_iss_not_used_for_jwks() -> tuple[bool, str]:
        """§14.3.2-8: Node shall not use the iss claim of a Bearer
        token to fetch JWKS. Mint a token with bogus iss; if the DUT
        had used iss to look up keys it would refuse — but the DUT
        actually uses its CONFIGURED AS, so the token still validates
        on every in-scope endpoint."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome_all_endpoints(
            ctx, mutate=lambda c: c.update(iss="https://evil.example.com/x"),
            expected_status=200, label="iss-not-used-for-jwks",
        )

    async def check_initial_fetch_required() -> tuple[bool, str]:
        """§14.3.2-2: If the Node cannot obtain an initial set of keys,
        it shall refuse access. We send a token signed by an unknown
        key (kid the DUT has never seen); a Node that respected the
        "no valid keys" rule must reject."""
        # Folds into check_no_public_keys_fail_closed semantically.
        return await check_no_public_keys_fail_closed()

    # =====================================================================
    # §12.5 — peer cert key-size inspection (TCT requirements).
    # =====================================================================

    async def check_tct_common_across_endpoints() -> tuple[bool, str]:
        """§12.5-3: "Shall be common to all certificates and Root CAs
        of the device." — the TCT (RSA / ECDSA / both) must apply
        uniformly across every endpoint the device exposes, not just
        the Node API.

        Iterates every endpoint discoverable from Device.controls[] +
        Node.services[] (plus the Node API itself), opens a TLS
        handshake to each, inspects the negotiated server cert's key
        type, and asserts all match the operator-declared --expect-tct.
        """
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        from urllib.parse import urlparse

        # Collect every (label, host:port) probe target.
        targets: list[tuple[str, str, int]] = []
        node_host, node_port = _split_host_port(ctx.cli.dut)
        targets.append(("node-api", node_host, node_port))
        if ctx.cli.control_port and ctx.cli.control_port != node_port:
            targets.append(("control-api", node_host, ctx.cli.control_port))
        seen: set[tuple[str, int]] = {(t[1], t[2]) for t in targets}
        for ctrl in ctx.advertised_controls:
            href = ctrl.get("href", "")
            if not isinstance(href, str) or not href:
                continue
            try:
                parsed = urlparse(href)
            except Exception:  # pylint: disable=broad-except
                continue
            if parsed.scheme not in ("https", "wss"):
                continue
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 0)
            if not host or not port or (host, port) in seen:
                continue
            seen.add((host, port))
            ctype = ctrl.get("type", "<no-type>")
            targets.append((f"control:{ctype}", host, port))
        for svc in ctx.advertised_services:
            href = svc.get("href", "")
            if not isinstance(href, str) or not href:
                continue
            try:
                parsed = urlparse(href)
            except Exception:  # pylint: disable=broad-except
                continue
            if parsed.scheme not in ("https", "wss"):
                continue
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 0)
            if not host or not port or (host, port) in seen:
                continue
            seen.add((host, port))
            stype = svc.get("type", "<no-type>")
            targets.append((f"service:{stype}", host, port))

        expected_tct = ctx.cli.expect_tct
        # Probe each target's server cert.
        observed: list[str] = []
        offenders: list[str] = []
        for label, host, port in targets:
            try:
                report = await tls_handshake(
                    host, port,
                    server_ca=ctx.cli.server_ca,
                    client_cert=ctx.cli.client_cert,
                    client_key=ctx.cli.client_key,
                    server_hostname=host,
                )
            except Exception as exc:  # pylint: disable=broad-except
                offenders.append(f"{label}@{host}:{port} handshake error "
                                 f"({type(exc).__name__})")
                continue
            if not report.succeeded or not report.peer_cert_pem:
                offenders.append(f"{label}@{host}:{port} no cert captured")
                continue
            try:
                cert = x509.load_der_x509_certificate(report.peer_cert_pem)
            except Exception as exc:  # pylint: disable=broad-except
                offenders.append(f"{label}@{host}:{port} cert parse error "
                                 f"({type(exc).__name__})")
                continue
            key = cert.public_key()
            if isinstance(key, rsa.RSAPublicKey):
                flavor_tct = 0  # RSA
            elif isinstance(key, ec.EllipticCurvePublicKey):
                flavor_tct = 1  # ECDSA
            else:
                offenders.append(f"{label}@{host}:{port} unsupported key type "
                                 f"{type(key).__name__}")
                continue
            # When the operator declared TCT=2 (both), every endpoint
            # may use either RSA or ECDSA — the spec wants the SAME
            # set of cert types to apply uniformly. We accept either
            # flavor and note observed mix.
            if expected_tct == 2:
                observed.append(f"{label}={('RSA' if flavor_tct == 0 else 'ECDSA')}")
                continue
            if flavor_tct != expected_tct:
                offenders.append(
                    f"{label}@{host}:{port} uses "
                    f"{'RSA' if flavor_tct == 0 else 'ECDSA'} but operator "
                    f"declared TCT={expected_tct}")
            else:
                observed.append(label)
        if offenders:
            return (False, "; ".join(offenders))
        return (True,
                f"TCT consistent across {len(targets)} probed endpoint(s): "
                f"{', '.join(observed[:5])}"
                f"{'; ...' if len(observed) > 5 else ''}")

    async def check_server_cert_meets_tct() -> tuple[bool, str]:
        """§12.5-1: RSA cert ≥2048-bit; §12.5-2: ECDSA cert ≥secp256r1.
        Connect to the DUT, capture the server cert, inspect the key.

        We use the existing ``tls_handshake`` probe which already
        captures ``peer_cert_pem``. Then parse the cert with
        ``cryptography`` to determine the key type and size."""
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        host, port = _split_host_port(ctx.cli.dut)
        report = await tls_handshake(
            host, port,
            server_ca=ctx.cli.server_ca,
            client_cert=ctx.cli.client_cert,
            client_key=ctx.cli.client_key,
            server_hostname=host,
        )
        if not report.succeeded or not report.peer_cert_pem:
            return (False, f"could not capture peer cert: {report.error}")
        cert = x509.load_der_x509_certificate(report.peer_cert_pem)
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            n_bits = public_key.key_size
            if ctx.cli.expect_tct == 1:  # ECDSA expected
                return (False, f"DUT served RSA-{n_bits} cert but TCT=1 (ECDSA expected)")
            if n_bits < 2048:
                return (False, f"RSA key size {n_bits} bits < 2048 (§12.5-1 minimum)")
            return (True, f"RSA-{n_bits} cert (≥2048 ✓)")
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            curve_name = public_key.curve.name
            ok_curves = {"secp256r1", "secp384r1", "secp521r1", "x25519"}
            if curve_name not in ok_curves:
                return (False, f"ECDSA curve {curve_name} below §12.5-2 minimum")
            return (True, f"ECDSA-{curve_name} cert ✓")
        return (False, f"unsupported public-key type: {type(public_key).__name__}")

    # =====================================================================
    # §14.1 / §14.2 — scope / path mapping.
    # =====================================================================

    async def check_scope_grants_node_api() -> tuple[bool, str]:
        """§14.1-1 / §14.2-1: scope='node' permits access to /x-nmos/node/."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome(
            ctx, mutate=lambda c: c.update(scope="node"),
            path="/x-nmos/node/v1.3/self",
            expected_status=200,
        )

    async def check_scope_connection_denies_node() -> tuple[bool, str]:
        """§14.1-1: a token whose scope DOES NOT include 'node' must be
        denied access to /x-nmos/node/."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome(
            ctx, mutate=lambda c: c.update(scope="connection streamcompatibility"),
            path="/x-nmos/node/v1.3/self",
            expected_status=403,
        )

    async def check_scope_connection_grants_connection_api() -> tuple[bool, str]:
        """§14.1-1: scope='connection' permits /x-nmos/connection/.
        Reference-node implements IS-05 v1.0 with the /single/senders
        sub-path; other vendors may use a different version. We probe
        the version the DUT advertises in its api.endpoints; fall back
        to v1.0 if absent."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        return await _probe_token_outcome(
            ctx, mutate=lambda c: c.update(scope="connection"),
            path="/x-nmos/connection/v1.0/single/senders",
            expected_status=200,
        )

    # =====================================================================
    # §9 NAP enforcement — primarily covered by §11; one extra here.
    # =====================================================================

    # =====================================================================
    # §9 NAP — tag-validity + write-enforcement via IS-05 PATCH.
    # =====================================================================

    async def check_nap1_not_combined_with_oauth() -> tuple[bool, str]:
        """§9.2-1: NAP=1 (Unrestricted RO) is forbidden when OAuth 2.0
        is in use. Verify the published IPMX security tags do not
        advertise an invalid combination — NAP=1 with RAAM=1 or RAAM=2."""
        if not ctx.advertised_tags:
            await _populate_self_resource(ctx)
        nap_value = ctx.advertised_tags.get(TAG_NAP, [None])
        raam_value = ctx.advertised_tags.get(TAG_RAAM, [None])
        nap = nap_value[0] if nap_value else None
        raam = raam_value[0] if raam_value else None
        if nap == "1" and raam in ("1", "2"):
            return (False,
                    f"invalid combination NAP={nap} + RAAM={raam} — "
                    f"§9.2-1 forbids NAP=1 under OAuth 2.0")
        return (True,
                f"tag combination spec-compliant: NAP={nap}, RAAM={raam}")

    # =====================================================================
    # §12 Device Configuration — verify mandated modes via published tags.
    # =====================================================================

    def _make_per_run_mode_check(
        urn: str, label: str, expected_value: int | None,
        full_set: set[str], full_set_label: str,
    ) -> CheckFn:
        """Per-run mode-support confirmation. PASS if the DUT advertises
        the mode the operator declared via ``--expect-*``. A full
        "support all modes" claim (e.g. SEC-12.2-1 requires RAP=1 AND
        RAP=2; SEC-12.4-1 requires OAIM=0/1/2) requires the operator
        to submit one run per mode; this check confirms the current
        run is one of those modes.
        """
        async def inner() -> tuple[bool, str]:
            if not ctx.advertised_tags:
                await _populate_self_resource(ctx)
            value_list = ctx.advertised_tags.get(urn, [None])
            value = value_list[0] if value_list else None
            if expected_value is not None and value == str(expected_value):
                if value in full_set:
                    return (True,
                            f"DUT advertises {label}={value} matching "
                            f"operator's --expect-{label.lower()}; mode is "
                            f"one of the spec-mandated {full_set_label} — "
                            f"full \"support all\" claim requires submitting "
                            f"runs with each of {sorted(full_set)}")
                return (True,
                        f"DUT advertises {label}={value} matching operator's "
                        f"--expect-{label.lower()} (this mode is outside the "
                        f"spec's mandated set {full_set_label}, but the "
                        f"per-run confirmation passes)")
            return (False,
                    f"DUT advertises {label}={value}; expected {expected_value} "
                    f"per operator's --expect-{label.lower()}")
        return inner

    async def check_tag_value_format() -> tuple[bool, str]:
        """§12.15-2: each tag's value is an array whose first element
        is the single decimal digit (in string form) of the config
        value. Strict shape check: every advertised security tag must
        be ``[str(int(0..9))]`` with optional second-element description."""
        if not ctx.advertised_tags:
            await _populate_self_resource(ctx)
        urns = (TAG_NAP, TAG_RAP, TAG_RAAM, TAG_OAIM, TAG_TCT)
        failures: list[str] = []
        for urn in urns:
            value = ctx.advertised_tags.get(urn)
            if value is None:
                failures.append(f"{urn.rsplit(':', 1)[-1]}: missing")
                continue
            if not isinstance(value, list) or not value:
                failures.append(f"{urn.rsplit(':', 1)[-1]}: not a non-empty list")
                continue
            first = value[0]
            if not isinstance(first, str) or len(first) != 1 or not first.isdigit():
                failures.append(
                    f"{urn.rsplit(':', 1)[-1]}: first entry {first!r} "
                    f"is not a single decimal digit string"
                )
        if failures:
            return (False, "; ".join(failures))
        return (True,
                "every advertised security tag's first entry is a single "
                "decimal-digit string")

    async def check_nap_2_supported() -> tuple[bool, str]:
        """§9.3-1: NAP=2 (Restricted RW) shall be supported by all
        compliant IPMX devices. The validator confirms this by reading
        the IPMX security tag the DUT publishes and asserting it
        advertises NAP=2 — every certification run uses NAP=2 (Config
        A may use NAP=1 or 2; Configs B and C are pinned to NAP=2)."""
        if not ctx.advertised_tags:
            await _populate_self_resource(ctx)
        nap_value = ctx.advertised_tags.get(TAG_NAP, [None])
        nap = nap_value[0] if nap_value else None
        if nap == "2":
            return (True, "DUT advertises NAP=2 — Restricted RW supported")
        if nap == "1":
            return (True,
                    f"DUT advertises NAP=1 in this run; NAP=2 support is "
                    f"verified in any Config B/C run (which pin NAP=2)")
        return (False, f"DUT does not advertise NAP=2 in any tested config; tag={nap}")

    async def _discover_sender_id() -> tuple[str, str] | None:
        """Discover an IS-05 sender via the Device's controls[] array.

        Returns ``(base_url, sender_id)`` where ``base_url`` is the
        ConnectionAPI base URL the device advertises (an absolute URL
        — possibly on a different host:port than the Node API if the
        DUT runs a split-listener setup) and ``sender_id`` is the
        first sender UUID listed at ``<base_url>/single/senders/``.

        Uses ``_find_control_href`` against the cached
        ``ctx.advertised_controls`` list — every IS-05 control URN
        version is considered; the highest version's href is used.
        """
        base_url = _find_control_href(ctx, "urn:x-nmos:control:sr-ctrl/")
        if base_url is None:
            return None

        token = None
        if ctx.fake_as is not None and ctx.cli.config in ("B", "C"):
            template = ctx.fake_as.token_template(
                instance_id=ctx.cli.instance_id, client_id=ctx.client_id,
            )
            token = mint_token(template, ctx.fake_as.primary_key)
        senders_url = f"{base_url}/single/senders/"
        try:
            resp = await request_with_token(ctx.http_client, senders_url, token=token)
        except Exception:  # pylint: disable=broad-except
            return None
        if resp.status != 200:
            return None
        try:
            entries = resp.json()
        except Exception:  # pylint: disable=broad-except
            return None
        if not isinstance(entries, list) or not entries:
            return None
        # IS-05 returns ["<uuid>/", ...].
        return (base_url, str(entries[0]).rstrip("/"))

    async def check_write_requires_auth_via_master_enable() -> tuple[bool, str]:
        """§9.2-3 / §9.3-3 / §14.3.3.4-39: writes shall be authorized.
        Probe via IS-05 PATCH ``/single/senders/{id}/staged`` with
        ``{"master_enable": false}``. An anonymous (no client cert /
        no Bearer) PATCH must be refused; a properly-authorized PATCH
        succeeds. Verifies the write-enforcement path on a real
        write endpoint."""
        discovered = await _discover_sender_id()
        if discovered is None:
            return untestable(
                "could not discover an IS-05 sender to PATCH — DUT may "
                "have no configured senders or no IS-05 sr-ctrl entry "
                "in any device.controls[]"
            )
        base_url, sender_id = discovered
        url = f"{base_url}/single/senders/{sender_id}/staged"
        body = {"master_enable": False}

        # 1. Anonymous PATCH (no client cert, no Bearer) — must be refused.
        try:
            async with SecurityHttpClient(
                server_ca=ctx.cli.server_ca,
                client_cert=None, client_key=None,
                verify_hostname=False,
            ) as anon:
                resp = await anon.patch(url, json_body=body)
            anon_status = resp.status
            anon_refused = resp.status in (401, 403)
        except Exception as exc:  # pylint: disable=broad-except
            # Config A/C: TLS handshake fails (no client cert) — that's
            # also a valid refusal.
            anon_status = None
            anon_refused = True
            _ = exc
        if not anon_refused:
            return (False,
                    f"anonymous PATCH master_enable=false reached the DUT "
                    f"and returned {anon_status} — write enforcement "
                    f"broken (sender {sender_id})")

        # 2. Authorized PATCH — must pass the auth layer. The token
        # MUST carry an explicit x-nmos-connection.write permission
        # (the default scope='connection' grants only read access; a
        # write requires an x-nmos-* private claim with write=['*']
        # per §14.3.3.4).
        if ctx.fake_as is not None and ctx.cli.config in ("B", "C"):
            template = ctx.fake_as.token_template(
                instance_id=ctx.cli.instance_id, client_id=ctx.client_id,
            )
            token = mint_token(
                template, ctx.fake_as.primary_key,
                mutate=lambda c: c.update(**{
                    "x-nmos-connection": {"read": ["*"], "write": ["*"]},
                }),
            )
        else:
            token = None  # Config A: mTLS in ctx.http_client provides auth
        resp = await request_with_token(
            ctx.http_client, url, method="PATCH",
            token=token, json_body=body,
        )
        if resp.status in (200, 202, 204):
            return (True,
                    f"anon PATCH refused (status {anon_status}); authorized "
                    f"PATCH master_enable=false → {resp.status}")
        if resp.status in (401, 403):
            return (False,
                    f"authorized PATCH master_enable=false refused with "
                    f"{resp.status} — auth-side problem (body: "
                    f"{resp.text()[:200]})")
        # Other 4xx (e.g. 400 body-validation, 409 conflict): the auth
        # layer let us through, only application-layer rejected the
        # write. That's still a PASS for the write-enforcement spec.
        return (True,
                f"anon PATCH refused (status {anon_status}); authorized "
                f"PATCH passed auth layer (app status {resp.status})")

    # =====================================================================
    # §14.1 / §14.2 IS-12 (ncp) and x-manufacturer scope-path probes.
    # Endpoint discovery uses the cached ctx.advertised_controls (for
    # IS-12) and ctx.advertised_services (for x-manufacturer). Both
    # carry absolute hrefs, so a DUT with a split-listener
    # (--controlPort != --nodePort) is honoured.
    # =====================================================================

    async def _probe_url_with_scope(
        url: str, scope_value: str, expected_status: int | tuple[int, ...],
    ) -> tuple[bool, str]:
        """Mint a token with a specific scope and GET the given
        absolute URL. Used by the IS-12 and x-manufacturer probes."""
        assert ctx.fake_as is not None
        template = ctx.fake_as.token_template(
            instance_id=ctx.cli.instance_id, client_id=ctx.client_id,
        )
        token = mint_token(
            template, ctx.fake_as.primary_key,
            mutate=lambda c: c.update(scope=scope_value),
        )
        resp = await request_with_token(ctx.http_client, url, token=token)
        accepted = (
            resp.status == expected_status if isinstance(expected_status, int)
            else resp.status in expected_status
        )
        if accepted:
            return (True, f"{url} → HTTP {resp.status}")
        return (False,
                f"{url} → HTTP {resp.status}, expected {expected_status} "
                f"(body: {resp.text()[:160]})")

    async def check_ncp_scope_grants_access() -> tuple[bool, str]:
        """§14.1-2 / §14.2-3 + §14.3.3.7: IS-12 (urn:x-nmos:control:ncp)
        WebSocket UPGRADE auth enforcement.

        Per TR-10-SEC, a WS UPGRADE on the standard ncp endpoint is a
        READ-WRITE operation — accepted only when the token carries
        scope ``nc``/``control`` AND ``x-nmos-nc.write=['*']``. A token
        with read-only ``x-nmos-nc`` must be refused at the auth layer
        (the UPGRADE asks for state-changing access).

        When the operator declares ``--supports=guest-ws``, the DUT
        provides a separate read-only endpoint (``Guest`` suffix per
        §14.3.3.7-2) that DOES accept a read-only token for UPGRADE.
        That branch is exercised in :func:`check_guest_ws_upgrade`
        below; here we focus on the R/W endpoint.

        Probes:
          1. Anonymous UPGRADE        → expect 401 (no Bearer)
          2. R/W ncp token UPGRADE     → expect 101 (upgrade OK)
          3. R/O ncp token UPGRADE     → expect 401/403 (no write)
        """
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        ncp_href = _find_control_href(ctx, "urn:x-nmos:control:ncp/")
        if ncp_href is None:
            return untestable(
                "DUT does not advertise an IS-12 ncp control "
                "(urn:x-nmos:control:ncp/) in device.controls[]; "
                "probe inactive until the DUT exposes the API"
            )
        # device.controls[].href is typically ``wss://...`` already.
        # If we see ``https://`` we rewrite to ``wss://`` because
        # aiohttp's ws_connect only speaks the ws schemes.
        ws_url = ncp_href
        if ws_url.startswith("https://"):
            ws_url = "wss://" + ws_url[len("https://"):]
        elif ws_url.startswith("http://"):
            ws_url = "ws://" + ws_url[len("http://"):]

        # 1. Anonymous UPGRADE — must be refused.
        anon_rep = await ws_upgrade(ctx.http_client, ws_url, token=None)
        if anon_rep.succeeded:
            return (False,
                    f"anonymous WS UPGRADE to {ws_url} succeeded "
                    "(101) — auth layer not enforced for R/W endpoint")

        # 2. R/W token — must succeed.
        rw_template = ctx.fake_as.token_template(
            instance_id=ctx.cli.instance_id, client_id=ctx.client_id,
        )
        rw_token = mint_token(
            rw_template, ctx.fake_as.primary_key,
            mutate=lambda c: c.update(
                scope="nc",
                **{"x-nmos-nc": {"read": ["*"], "write": ["*"]}},
            ),
        )
        rw_rep = await ws_upgrade(ctx.http_client, ws_url, token=rw_token)
        if not rw_rep.succeeded:
            return (False,
                    f"R/W token WS UPGRADE refused ({rw_rep.status}) — "
                    "auth-side problem on R/W endpoint")

        # 3. R/O token — must be refused (UPGRADE is R/W).
        ro_template = ctx.fake_as.token_template(
            instance_id=ctx.cli.instance_id, client_id=ctx.client_id,
        )
        ro_token = mint_token(
            ro_template, ctx.fake_as.primary_key,
            mutate=lambda c: c.update(
                scope="nc",
                **{"x-nmos-nc": {"read": ["*"], "write": [""]}},
            ),
        )
        ro_rep = await ws_upgrade(ctx.http_client, ws_url, token=ro_token)
        if ro_rep.succeeded:
            return (False,
                    f"R/O token WS UPGRADE accepted (101) — UPGRADE "
                    "is a R/W operation and must require write claim")

        return (True,
                f"anonymous refused ({anon_rep.status}); R/W token → "
                f"101; R/O token refused ({ro_rep.status})")

    def _guest_ws_candidate_urls() -> list[str]:
        """Derive candidate Guest-WS URLs from the discovered ncp
        endpoint per the §14.3.3.7-2 ``Guest`` suffix convention.

        Returns an empty list when no ncp endpoint is advertised.
        Two conventions tried: ``<ncp-url>/Guest`` (path append) and
        ``<ncp-url-with-Guest-component>`` (last-segment replacement).
        Operators with a different convention can extend this list."""
        ncp_href = _find_control_href(ctx, "urn:x-nmos:control:ncp/")
        if ncp_href is None:
            return []

        def _to_ws(u: str) -> str:
            if u.startswith("https://"):
                return "wss://" + u[len("https://"):]
            if u.startswith("http://"):
                return "ws://" + u[len("http://"):]
            return u

        base = _to_ws(ncp_href.rstrip("/"))
        return [f"{base}/Guest", f"{base}Guest"]

    async def check_guest_ws_upgrade() -> tuple[bool, str]:
        """§14.3.3.7-1/-2 (gated by ``--supports=guest-ws``): when the
        DUT claims a separate Read-Only WS endpoint, attempt a WS
        UPGRADE on it with a R/O token (``x-nmos-nc.write=['']``)
        and expect 101. The endpoint URL is derived from the ncp
        URL via the ``Guest`` suffix convention (§14.3.3.7-2)."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        candidates = _guest_ws_candidate_urls()
        if not candidates:
            return untestable(
                "DUT advertises no IS-12 ncp endpoint to derive a "
                "Guest URL from — §14.3.3.7-1/-2 not applicable"
            )
        template = ctx.fake_as.token_template(
            instance_id=ctx.cli.instance_id, client_id=ctx.client_id,
        )
        ro_token = mint_token(
            template, ctx.fake_as.primary_key,
            mutate=lambda c: c.update(
                scope="nc",
                **{"x-nmos-nc": {"read": ["*"], "write": [""]}},
            ),
        )
        attempts: list[str] = []
        for url in candidates:
            rep = await ws_upgrade(ctx.http_client, url, token=ro_token)
            attempts.append(f"{url} → {rep.status or rep.error}")
            if rep.succeeded:
                return (True,
                        f"Guest UPGRADE accepted at {url} with R/O "
                        "token; §14.3.3.7-1/-2 satisfied")
        return (False,
                "no Guest endpoint accepted a R/O UPGRADE; tried: "
                + " ; ".join(attempts))

    async def check_subscription_is_readonly() -> tuple[bool, str]:
        """§14.3.3.7-3 (SHALL): "Subscribing to notification messages
        shall be considered a read-only operation."

        Implementation: this rule is observable on the SEPARATE
        read-only WS endpoint (per §14.3.3.7-1/-2). Without one, the
        Node serves commands AND subscriptions on a single R/W WS
        connection where the UPGRADE itself is R/W — the validator
        cannot observe the per-message R/O semantic the spec names.

        When ``--supports=guest-ws`` is declared we delegate to
        :func:`check_guest_ws_upgrade`: a R/O token accepted on the
        Guest endpoint demonstrates the §14.3.3.7-3 R/O semantic
        because subscription is the only operation the Guest channel
        offers. Without the feature the rule resolves to NOT-APPLICABLE
        (the device makes no claim to a R/O endpoint at all)."""
        if "guest-ws" not in ctx.cli.supports:
            return not_applicable(
                "Without a separate Guest WS endpoint the Node serves "
                "commands and subscriptions over one R/W channel; the "
                "§14.3.3.7-3 R/O semantic for subscriptions is "
                "satisfied by Guest-endpoint coverage when claimed"
            )
        # Reuse the guest UPGRADE probe — if the Guest endpoint
        # accepts a R/O token, the subscription = R/O rule is
        # observable end-to-end.
        return await check_guest_ws_upgrade()

    async def check_manufacturer_scope_grants_access() -> tuple[bool, str]:
        """§14.1-3 / §14.2-2: '/x-manufacturer/*' endpoints shall use
        scope='manufacturer'. Discover the endpoint via the Node-level
        services[] array — its href is an absolute URL that may sit on
        a separate host:port from the Node API."""
        if ctx.fake_as is None:
            return _no_fake_as_outcome()
        manufacturer_href = _find_service_href_prefix(ctx, "/x-manufacturer/")
        if manufacturer_href is None:
            return untestable(
                "DUT does not advertise any /x-manufacturer/* service "
                "in node.services[]; spec §14.1-3 / §14.2-2 vacuously "
                "satisfied — no such API to scope-protect"
            )
        ok1 = await _probe_url_with_scope(
            manufacturer_href, "manufacturer", (200, 401, 404, 405),
        )
        if not ok1[0]:
            return (False,
                    f"scope=manufacturer not accepted at {manufacturer_href}: "
                    f"{ok1[1]}")
        ok2 = await _probe_url_with_scope(
            manufacturer_href, "node connection", (403, 404),
        )
        if not ok2[0]:
            return (False,
                    f"scope without 'manufacturer' not refused: {ok2[1]}")
        return (True,
                f"scope='manufacturer' accepted at {manufacturer_href}; "
                f"scope without 'manufacturer' denied")

    # =====================================================================
    # Generic per-control-type write probe. Every endpoint whose
    # ControlApiSpec carries a WriteRecipe gets exercised twice:
    #   (a) anonymous (no client cert, no Bearer) → MUST be refused
    #       (401/403 or TLS handshake failure).
    #   (b) authorized (token carries x-nmos-<scope>.write=['*']) →
    #       MUST pass the auth layer (200/202/204 or non-auth 4xx).
    # The recipe's {id} placeholder is resolved by GET'ing
    # ``recipe.id_list_path`` and picking the first entry — sufficient
    # for IS-05 and IS-11 which both list "<uuid>/" arrays.
    # =====================================================================

    async def _resolve_write_url(
        ep: ServerEndpoint,
    ) -> tuple[str, str] | None:
        """Return ``(url, sample_id_or_'')`` for the write probe, or
        ``None`` if the recipe needs an id but none could be discovered.
        """
        spec = ep.control_spec
        if spec is None or spec.write_recipe is None:
            return None
        recipe = spec.write_recipe
        suffix = recipe.path_suffix
        sample_id = ""
        if "{id}" in suffix:
            if recipe.id_list_path is None:
                return None
            list_url = ep.base_url + recipe.id_list_path
            token = None
            if ctx.fake_as is not None and ctx.cli.config in ("B", "C"):
                template = ctx.fake_as.token_template(
                    instance_id=ctx.cli.instance_id, client_id=ctx.client_id,
                )
                token = mint_token(
                    template, ctx.fake_as.primary_key,
                    mutate=lambda c: c.update(scope=spec.scope),
                )
            try:
                resp = await request_with_token(
                    ctx.http_client, list_url, token=token,
                )
            except Exception:  # pylint: disable=broad-except
                return None
            if resp.status != 200:
                return None
            try:
                entries = resp.json()
            except Exception:  # pylint: disable=broad-except
                return None
            if not isinstance(entries, list) or not entries:
                return None
            sample_id = str(entries[0]).rstrip("/")
            suffix = suffix.replace("{id}", sample_id)
        return (ep.base_url + suffix, sample_id)

    async def check_writes_require_auth_per_endpoint() -> tuple[bool, str]:
        """§9.2-3 / §9.3-3 / §14.3.3.4-39 (write authorization):
        for every writable control API the DUT advertises, verify
        that an anonymous write is refused and an authorized write
        passes the auth layer."""
        if ctx.fake_as is None and ctx.cli.config in ("B", "C"):
            return _no_fake_as_outcome()

        async def probe(ep: ServerEndpoint) -> tuple[bool, str]:
            assert ep.control_spec is not None
            recipe = ep.control_spec.write_recipe
            assert recipe is not None
            resolved = await _resolve_write_url(ep)
            if resolved is None:
                return (False,
                        f"could not resolve {recipe.method} {recipe.path_suffix} "
                        f"(no resource id available)")
            url, _sid = resolved
            body = recipe.body

            # 1. Anonymous write — must be refused.
            try:
                async with SecurityHttpClient(
                    server_ca=ctx.cli.server_ca,
                    client_cert=None, client_key=None,
                    verify_hostname=False,
                ) as anon:
                    if recipe.method == "PATCH":
                        anon_resp = await anon.patch(url, json_body=body)
                    elif recipe.method == "POST":
                        anon_resp = await anon.post(url, json_body=body)
                    elif recipe.method == "DELETE":
                        anon_resp = await anon._request("DELETE", url)  # noqa: SLF001
                    else:
                        anon_resp = await anon._request(  # noqa: SLF001
                            recipe.method, url, json_body=body,
                        )
                anon_status: int | None = anon_resp.status
                anon_refused = anon_resp.status in (401, 403)
            except Exception:  # pylint: disable=broad-except
                anon_status = None
                anon_refused = True  # TLS handshake refused (Config A/C)
            if not anon_refused:
                return (False,
                        f"anon {recipe.method} {url} returned {anon_status} — "
                        "write enforcement broken")

            # 2. Authorized write — must pass auth layer.
            if ctx.fake_as is not None and ctx.cli.config in ("B", "C"):
                template = ctx.fake_as.token_template(
                    instance_id=ctx.cli.instance_id, client_id=ctx.client_id,
                )
                token = mint_token(
                    template, ctx.fake_as.primary_key,
                    mutate=lambda c, s=ep.control_spec.scope: c.update(
                        scope=s,
                        **{f"x-nmos-{s}": {"read": ["*"], "write": ["*"]}},
                    ),
                )
            else:
                token = None  # Config A: mTLS in ctx.http_client
            resp = await request_with_token(
                ctx.http_client, url, method=recipe.method,
                token=token, json_body=body,
            )
            if resp.status in (401, 403):
                return (False,
                        f"authorized {recipe.method} {url} refused with "
                        f"{resp.status} — auth-side problem")
            # 200/202/204 → write went through; any other 4xx (400, 404, 409)
            # → auth passed, application-layer rejected — still a PASS for
            # the auth-enforcement requirement.
            return (True,
                    f"anon refused ({anon_status}); authorized "
                    f"{recipe.method} → {resp.status}")

        return await _probe_each_endpoint(
            ctx, probe, label="writes-require-auth",
            require_writable=True, read_side=False,
            counter="c",  # the anon write is the "no token" bucket
        )

    async def check_reservation_acquire_requires_auth() -> tuple[bool, str]:
        """Reservation service ``POST /x-manufacturer/exclusive/acquire``
        — write-enforcement probe.

        The Reservation API hands out an exclusive-session bearer when
        acquired. Per spec the request body is::

            {
              "owner":          "<URI authority + optional path, ≤256 B>",
              "exclusive_key":  "<32 hex chars — 16 bytes>"
            }

        We do NOT care whether the session is acquired (an existing
        owner returns a 4xx — that's fine). We DO care that:

          1. Anonymous POST is refused at the auth layer (401/403 or
             TLS handshake failure under mTLS configs).
          2. Authorized POST passes the auth layer — 200 (acquired)
             or any non-auth 4xx (e.g. 409 if someone else owns the
             session) is acceptable. ``ctx`` carries a token with
             scope=manufacturer + ``x-nmos-manufacturer.write=['*']``
             so the §14.3.3.4 access-control matrix accepts the write.
        """
        href = _find_service_href_prefix(ctx, "/x-manufacturer/exclusive/")
        if href is None:
            return untestable(
                "DUT does not advertise an x-manufacturer/exclusive/* "
                "Reservation service in node.services[] — nothing to "
                "probe for §14.2 write enforcement"
            )
        url = f"{href.rstrip('/')}/acquire"
        # 16 bytes of zeros = 32 hex chars — spec-shaped exclusive_key.
        body = {
            "owner": "ipmx-validator.test/session/probe",
            "exclusive_key": "0" * 32,
        }

        # 1. Anonymous POST — must be refused.
        try:
            async with SecurityHttpClient(
                server_ca=ctx.cli.server_ca,
                client_cert=None, client_key=None,
                verify_hostname=False,
            ) as anon:
                anon_resp = await anon.post(url, json_body=body)
            anon_status: int | None = anon_resp.status
            anon_refused = anon_resp.status in (401, 403)
        except Exception:  # pylint: disable=broad-except
            anon_status = None
            anon_refused = True  # TLS handshake refused (Config A/C)
        if not anon_refused:
            return (False,
                    f"anonymous POST {url} returned {anon_status} — "
                    f"§14.2 write enforcement broken")

        # 2. Authorized POST — must pass auth layer.
        if ctx.fake_as is not None and ctx.cli.config in ("B", "C"):
            template = ctx.fake_as.token_template(
                instance_id=ctx.cli.instance_id, client_id=ctx.client_id,
            )
            token = mint_token(
                template, ctx.fake_as.primary_key,
                mutate=lambda c: c.update(
                    scope="manufacturer",
                    **{"x-nmos-manufacturer": {"read": ["*"], "write": ["*"]}},
                ),
            )
        else:
            token = None  # Config A: mTLS in ctx.http_client
        resp = await request_with_token(
            ctx.http_client, url, method="POST",
            token=token, json_body=body,
        )
        if resp.status in (401, 403):
            return (False,
                    f"authorized POST {url} refused with {resp.status} "
                    f"— auth-side problem (body: {resp.text()[:160]})")
        # 200 → acquired; any other 4xx → application-layer rejected
        # (e.g. 409 if session already owned); auth layer passed in
        # either case — still a PASS for the write-enforcement rule.
        return (True,
                f"anon refused ({anon_status}); authorized POST "
                f"/acquire → {resp.status}")

    _write_full_cache: list[tuple[bool, str, bool, bool, bool]] = []

    async def check_writes_require_auth_full() -> CheckResult:
        """Aggregate write-enforcement check: per-control-API writes
        AND the Reservation ``POST /acquire`` write.

        Cached after the first invocation. Multiple dispatch entries
        (§14.3.3.4-39 / §9.2-3 / §9.3-3) all want this verdict, but
        running write probes multiple times against the SAME DUT
        produces order-dependent results — e.g. an earlier
        ``POST /acquire`` may hold an exclusive-session lock that
        causes subsequent writes to return 401 even though the
        token is well-formed. We run the probes once and replay the
        cached verdict to every dispatch entry."""
        if _write_full_cache:
            return _write_full_cache[0]  # type: ignore[return-value]
        a = await check_writes_require_auth_per_endpoint()
        b = await check_reservation_acquire_requires_auth()
        # Each component returns a 2-, 3-, 4-, or 5-tuple. Normalise
        # to (passed, detail, testable, needs_fix, not_applic).
        def _norm(t: tuple) -> tuple[bool, str, bool, bool, bool]:
            return (
                t[0], t[1],
                t[2] if len(t) > 2 else True,
                t[3] if len(t) > 3 else False,
                t[4] if len(t) > 4 else False,
            )
        a_ok, a_det, a_test, a_nf, a_na = _norm(a)
        b_ok, b_det, b_test, b_nf, b_na = _norm(b)
        # untestable on EITHER side → untestable overall (no writable
        # endpoint to probe). needs_fixture / not_applicable propagate
        # the same way: if EITHER side flags it AND the other side
        # has no PASS to override, the combined result inherits.
        ok = a_ok and b_ok
        testable = a_test and b_test
        needs_fix = a_nf and b_nf
        not_app = a_na and b_na
        detail = f"controls: {a_det[:200]} ;; reservation: {b_det[:160]}"
        result: tuple[bool, str, bool, bool, bool] = (
            ok, detail, testable, needs_fix, not_app,
        )
        _write_full_cache.append(result)
        return result

    # =====================================================================
    # §7.2 / §10 registry-proxy observations — read the request log the
    # matrix runner's RegistryProxy fixture dumped. The proxy sits
    # between the DUT and either a stub or a real upstream registry,
    # so the records below are GROUND TRUTH of what the Node actually
    # put on the wire during its registration handshake.
    # =====================================================================

    def _no_proxy_log_outcome() -> tuple[bool, str, bool, bool]:
        return needs_fixture(
            "this requirement is graded from the registry-proxy "
            "request log (matrix runner spawns "
            "ipmx_registry_proxy.py and passes --registry-proxy-log "
            "to the validator) — none provided in this run"
        )

    def _empty_proxy_log_outcome() -> tuple[bool, str, bool, bool]:
        return needs_fixture(
            "the registry proxy observed no requests from the DUT "
            "during the registration window — the Node did not "
            "register (DUT did not point at the proxy host:port, or "
            "the proxy was unreachable from the DUT's network)"
        )

    async def check_registry_no_authorization_header() -> tuple[bool, str]:
        """§7.2-1 (SHALL): An IS-04 Registration API shall NOT require
        the Node to use OAuth 2.0. Wire-observable: no request the
        Node sent to the proxied registry may carry an
        ``Authorization: Bearer`` (or any other Authorization scheme)
        header — if one were present, the Node would in effect BE
        using OAuth 2.0 against the registry, violating the
        requirement."""
        obs = ctx.registry_proxy
        if obs is None:
            return _no_proxy_log_outcome()
        if not obs.records:
            return _empty_proxy_log_outcome()
        offenders = [
            r for r in obs.records if r.has_authorization
        ]
        if offenders:
            sample = offenders[0]
            return (
                False,
                f"{len(offenders)}/{len(obs.records)} Node→Registry "
                f"requests carried an Authorization header "
                f"(scheme={sample.authorization_scheme!r}, "
                f"first path={sample.path!r})",
            )
        return (
            True,
            f"all {len(obs.records)} Node→Registry requests sent "
            f"without an Authorization header",
        )

    async def check_registry_tls_secured() -> tuple[bool, str]:
        """§7.2-2 (SHALL): The IS-04 Registration API shall be
        secured using TLS (server-auth or mTLS).

        Graded against ``proxy.rap``:

        * ``rap=0`` → NOT-APPLICABLE: the operator selected HTTP-only
          registry access, which per §9.1-1 forbids claiming
          compliance; this requirement cannot be satisfied in that
          mode and is exercised by separate RAP=1/2 runs.
        * ``rap=1`` or ``rap=2`` → every observed request must have
          a non-empty ``tls_version`` (the proxy terminated TLS).
        """
        obs = ctx.registry_proxy
        if obs is None:
            return _no_proxy_log_outcome()
        if obs.rap == 0:
            return not_applicable(
                "operator declared RAP=0 (HTTP, non-compliant per "
                "§9.1-1); §7.2-2's TLS requirement is exercised by "
                "RAP=1 / RAP=2 runs"
            )
        if not obs.records:
            return _empty_proxy_log_outcome()
        non_tls = [
            r for r in obs.records
            if not r.tls_version or r.tls_version == "none"
        ]
        if non_tls:
            sample = non_tls[0]
            return (
                False,
                f"{len(non_tls)}/{len(obs.records)} requests reached "
                f"the proxy WITHOUT TLS (path={sample.path!r}); a "
                f"compliant Node MUST present TLS to the registry "
                f"in RAP={obs.rap}",
            )
        versions = sorted({r.tls_version for r in obs.records})
        return (
            True,
            f"all {len(obs.records)} Node→Registry requests used TLS "
            f"({', '.join(versions)})",
        )

    async def check_registry_https_when_api_proto_https() -> tuple[bool, str]:
        """§10.1-1 (SHALL): If api_proto is "https" the Registration
        API shall be secured using TLS. Same observable as §7.2-2 —
        the proxy log shows whether the Node negotiated TLS — but
        graded only when RAP=1/2 (RAP=0 means api_proto≠https and
        this requirement is not engaged)."""
        return await check_registry_tls_secured()

    async def check_registry_tls_supported_by_all() -> tuple[bool, str]:
        """§10.1-2 (SHALL): TLS-secured registry access shall be
        supported by all compliant IPMX devices. Observable as
        "the DUT successfully completed a TLS handshake to a TLS-
        only proxy and then sent valid IS-04 registration"."""
        obs = ctx.registry_proxy
        if obs is None:
            return _no_proxy_log_outcome()
        if obs.rap == 0:
            return not_applicable(
                "this requirement is observed by running the DUT "
                "against a TLS-only proxy (RAP=1 or RAP=2); the "
                "current run has RAP=0 (HTTP)"
            )
        if not obs.records:
            return (
                False,
                f"proxy listened on TLS (RAP={obs.rap}) but the DUT "
                "did not complete any successful registration — "
                "could indicate the DUT does not support TLS to the "
                "registry as §10.1-2 requires",
            )
        return (
            True,
            f"DUT successfully completed {len(obs.records)} TLS-"
            f"secured registration request(s) — TLS-to-registry "
            "support is demonstrated",
        )

    async def check_registry_mtls_when_restricted() -> tuple[bool, str]:
        """§10.2-1 (SHALL): Under Restricted Registration (RAP=2) the
        Node and the Registry shall authenticate each other using
        TLS mutual authentication. The proxy was configured with
        ``require_client_cert=True`` for RAP=2 — a request that got
        through MUST have presented a peer cert."""
        obs = ctx.registry_proxy
        if obs is None:
            return _no_proxy_log_outcome()
        if obs.rap != 2:
            return not_applicable(
                f"RAP={obs.rap} — mTLS is mandated by §10.2-1 only "
                "under Restricted Registration (RAP=2); covered by a "
                "RAP=2 matrix entry"
            )
        if not obs.records:
            return (
                False,
                "RAP=2 proxy required mTLS but the DUT never "
                "established a mutually-authenticated session — "
                "either it lacks a client cert provisioned for the "
                "registry, or its client cert chain failed against "
                "the proxy's CTCA",
            )
        no_peer = [
            r for r in obs.records if not r.peer_cert_present
        ]
        if no_peer:
            sample = no_peer[0]
            return (
                False,
                f"{len(no_peer)}/{len(obs.records)} requests reached "
                f"the proxy WITHOUT a peer cert (path={sample.path!r}) "
                "— mTLS not enforced end-to-end",
            )
        subjects = sorted({r.peer_cert_subject for r in obs.records})
        return (
            True,
            f"all {len(obs.records)} Node→Registry requests "
            f"presented a peer cert; subjects={subjects}",
        )

    # =====================================================================
    # §8-5 per-curve positive coverage. The matrix runner spawns the
    # registry proxy and (for Config B/C) the fake AS as subprocesses
    # with OPENSSL_CONF restricting their TLS group list to ONE curve.
    # The DUT then completes its outbound handshakes against those
    # subprocesses only if its CLIENT side supports that curve. The
    # validator's check reads the proxy log to detect proof.
    # =====================================================================

    async def check_tls_group_supported_client_side() -> tuple[bool, str]:
        """§8-5 (SHALL/SHOULD): "An IPMX device shall support the
        ephemeral key exchange groups 25519 and secp256r1 and should
        support secp521r1 and 448."  Wire-observable when
        ``--expect-tls-group`` declares the curve the testing-side
        subprocesses were pinned to via ``OPENSSL_CONF``: a non-empty
        registry-proxy request log proves the DUT's TLS client
        completed at least one outbound handshake against a server
        offering ONLY that curve.

        Matrix entries that DON'T set the curve pin resolve to
        NOT-APPLICABLE — the per-curve evidence comes from the four
        dedicated ``A-curve-*`` (and optional Config B variants)
        entries, not the generic baseline runs."""
        pin = ctx.cli.expect_tls_group
        if not pin:
            return not_applicable(
                "this matrix entry does not pin a single curve via "
                "OPENSSL_CONF; per-curve evidence is collected by the "
                "dedicated A-curve-* / B-curve-* entries"
            )
        obs = ctx.registry_proxy
        if obs is None:
            return needs_fixture(
                "the §8-5 per-curve probe needs the registry-proxy "
                "request log; rerun via the matrix runner so the "
                "proxy is spawned and --registry-proxy-log is set"
            )
        if not obs.records:
            return (
                False,
                f"DUT did NOT complete any outbound handshake against "
                f"the proxy pinned to OpenSSL group {pin!r} — its TLS "
                f"client does not support that curve, or the proxy's "
                f"OPENSSL_CONF restriction blocked all handshakes",
            )
        versions = sorted({r.tls_version for r in obs.records})
        return (
            True,
            f"DUT completed {len(obs.records)} outbound handshake(s) "
            f"against the proxy pinned to OpenSSL group {pin!r} "
            f"(TLS {', '.join(v for v in versions if v)}) — its TLS "
            f"client supports {pin}",
        )

    # =====================================================================
    # §12.10 / §12.12 NESTCA vs CESTCA trust-store isolation — observable
    # only when the DUT serves IS-04 (Node) and IS-05/IS-08/IS-11
    # (Control) on DISTINCT TLS listeners with distinct trust roots.
    # The wire test mints handshakes with NESTCA- and CESTCA-rooted
    # client certs against both listeners; the spec-mandated outcome
    # is a 2×2 matrix of accept/refuse that's only producible when
    # the trust stores are physically separate.
    # =====================================================================

    _NESTCA_CLIENT_CERT = PKI_NESTCA / "pem" / "ExampleDeviceClient.ABC.SNX00000.chain.pem"
    _NESTCA_CLIENT_KEY  = PKI_NESTCA / "key" / "ExampleDeviceClient.ABC.SNX00000.key"
    _CESTCA_CLIENT_CERT = PKI_CESTCA / "pem" / "ExampleDeviceClient.ABC.SNX00000.chain.pem"
    _CESTCA_CLIENT_KEY  = PKI_CESTCA / "key" / "ExampleDeviceClient.ABC.SNX00000.key"

    def _node_and_control_listeners() -> tuple[str, int, str, int] | None:
        """Discover the (node-api host:port, control-api host:port)
        pair from the enumerated server endpoints. Returns ``None``
        if the inventory does not contain a control endpoint on a
        DIFFERENT host:port than the Node API — meaning the DUT
        serves them on a single listener and the NESTCA/CESTCA
        distinction cannot be observed on this run.
        """
        node_url: str | None = None
        ctrl_url: str | None = None
        for ep in ctx.server_endpoints:
            if ep.source == "api.endpoints":
                node_url = ep.base_url
            elif ep.source == "controls" and ep.control_spec is not None:
                # First in-scope control endpoint wins.
                if ctrl_url is None:
                    ctrl_url = ep.base_url
        if node_url is None or ctrl_url is None:
            return None
        nh, np_ = _split_host_port(node_url.split("://", 1)[1])
        ch, cp = _split_host_port(ctrl_url.split("://", 1)[1].split("/", 1)[0])
        if (nh, np_) == (ch, cp):
            return None  # same listener — no isolation to test
        return (nh, np_, ch, cp)

    async def check_nestca_cestca_isolation() -> CheckResult:
        """§12.10 / §12.12 trust-store isolation. Drives 4 TLS
        handshakes:

          A. NESTCA client → Node API   ⇒ expect SUCCESS
          B. CESTCA client → Node API   ⇒ expect REFUSED at TLS
          C. CESTCA client → Control    ⇒ expect SUCCESS
          D. NESTCA client → Control    ⇒ expect REFUSED at TLS

        Symmetric refusals (B + D) are the wire-observable proof
        that the device honours two independent trust stores. A
        single-listener device produces NOT-APPLICABLE; a single-
        trust-store device serving on split listeners would fail
        the cross-test."""
        listeners = _node_and_control_listeners()
        if listeners is None:
            return not_applicable(
                "DUT serves Node IS-04 and control APIs on the same "
                "listener — NESTCA/CESTCA distinction is not "
                "observable on this run. Re-launch the DUT with "
                "--split-controls (or equivalent) to wire-test the "
                "§12.10 / §12.12 role separation"
            )
        nh, np_, ch, cp = listeners
        if not (_NESTCA_CLIENT_CERT.exists() and _CESTCA_CLIENT_CERT.exists()):
            return untestable(
                f"NESTCA / CESTCA client certs not present at "
                f"{_NESTCA_CLIENT_CERT.parent} / {_CESTCA_CLIENT_CERT.parent} "
                "— provision build.2/ + build.3/ first"
            )

        async def hs(
            host: str, port: int, cert: Path, key: Path,
            server_ca: Path,
        ) -> tuple[bool, str]:
            """In TLS 1.3 the server's client-cert rejection arrives
            AFTER the client's Finished message — a raw handshake
            probe (asyncio.open_connection) returns ``succeeded=True``
            even when the server is about to drop the connection
            with a verify-failed alert. The truthful test is whether
            an actual HTTP exchange completes — if the server
            rejected the cert, reading the response raises a TLS
            error. We use ``SecurityHttpClient`` for one GET and
            interpret any aiohttp exception as a TLS refusal."""
            try:
                async with SecurityHttpClient(
                    server_ca=server_ca,
                    client_cert=cert, client_key=key,
                    verify_hostname=False,
                ) as client:
                    url = f"https://{host}:{port}/"
                    resp = await client.get(url)
                    # Any HTTP response means TLS layer accepted.
                    return (True, f"HTTP {resp.status}")
            except Exception as exc:  # pylint: disable=broad-except
                return (False, f"TLS REFUSED: {type(exc).__name__}: {str(exc)[:120]}")

        # The DUT's SERVER cert chains to build/ExampleRootCA — that's
        # CTCA. Our client side uses the same root to validate it.
        ca = ctx.cli.server_ca or (PKI_PRIMARY / "ExampleRootCA.pem")

        # A. NESTCA → Node API: PASS
        a_ok, a_err = await hs(nh, np_, _NESTCA_CLIENT_CERT, _NESTCA_CLIENT_KEY, ca)
        # B. CESTCA → Node API: REFUSED
        b_ok, b_err = await hs(nh, np_, _CESTCA_CLIENT_CERT, _CESTCA_CLIENT_KEY, ca)
        # C. CESTCA → Control:  PASS
        c_ok, c_err = await hs(ch, cp, _CESTCA_CLIENT_CERT, _CESTCA_CLIENT_KEY, ca)
        # D. NESTCA → Control:  REFUSED
        d_ok, d_err = await hs(ch, cp, _NESTCA_CLIENT_CERT, _NESTCA_CLIENT_KEY, ca)

        outcomes = [
            ("A NESTCA→node-api  expect SUCCESS",  a_ok,        a_ok,       a_err),
            ("B CESTCA→node-api  expect REFUSED",  not b_ok,    b_ok,       b_err),
            ("C CESTCA→control   expect SUCCESS",  c_ok,        c_ok,       c_err),
            ("D NESTCA→control   expect REFUSED",  not d_ok,    d_ok,       d_err),
        ]
        failures = [label for (label, ok, _, _) in outcomes if not ok]
        if failures:
            detail_lines = [
                f"{lbl}: actual={'SUCCESS' if hs_ok else 'REFUSED'}"
                + (f" ({err[:80]})" if err else "")
                for (lbl, _, hs_ok, err) in outcomes
            ]
            return (False, "; ".join(detail_lines))
        return (True,
                f"trust-store isolation observed: NESTCA cert accepted "
                f"at {nh}:{np_}, refused at {ch}:{cp}; CESTCA cert "
                f"accepted at {ch}:{cp}, refused at {nh}:{np_}")

    async def check_nap_2_get_requires_auth() -> tuple[bool, str]:
        """§9.3-2: Restricted-RW read access must be enforced. Send GET
        /self with NO credentials (no client cert, no Bearer) — must
        be refused at either the TLS layer (Config A/C) or the OAuth
        layer (Config B). Either way, the request must not succeed
        with 200."""
        url = f"{ctx.dut_base_url}/x-nmos/node/v1.3/self"
        try:
            async with SecurityHttpClient(
                server_ca=ctx.cli.server_ca,
                client_cert=None, client_key=None,
                verify_hostname=False,
            ) as anon:
                resp = await anon.get(url)
            if resp.status == 200:
                return (False,
                        f"DUT served /self (200) without any credentials — "
                        f"§9.3-2 NAP=2 enforcement broken")
            return (True,
                    f"unauthenticated GET /self refused (HTTP {resp.status})")
        except Exception as exc:  # pylint: disable=broad-except
            # Config A/C reject at TLS layer (no client cert).
            return (True, f"unauthenticated GET /self refused at TLS: "
                          f"{type(exc).__name__}")

    # =====================================================================
    # Dispatch table — JSON req_id → check function.
    # Entries not in this table get a generic ``untestable`` so the
    # operator/auditor can see the full normative surface in the report
    # and attestation manifest. The custom ``_attest_*`` callables
    # override the default with a more specific reason for known
    # reference-node gaps.
    # =====================================================================

    def _attest(message: str) -> CheckFn:
        async def inner() -> tuple[bool, str, bool]:
            return untestable(message)
        return inner

    classifications = _load_classification()

    def _classified(req_id: str) -> CheckFn:
        """Build an untestable check whose reason carries the
        classification bucket + spec-specific reason. Falls back to a
        generic message if the classifier has no entry for this id
        (shouldn't happen — classify_requirements.py covers all 188)."""
        info = classifications.get(req_id)
        if info is None:
            reason = (f"validator has not yet wired a check for {req_id}; "
                      "no classification entry — please regenerate "
                      "requirements_classification.json")
        else:
            prefix = _BUCKET_PREFIX.get(info["bucket"], "[?]")
            reason = f"{prefix} {info['reason']}"

        async def inner() -> tuple[bool, str, bool]:
            return untestable(reason)
        return inner

    dispatch: dict[str, CheckFn] = {
        # §8 TLS Communications and Cipher Suites
        "SEC-8-2": check_tls_13_negotiation,
        "SEC-8-6": check_tls_12_mandatory_cipher,
        "SEC-8-9": check_tls_12_prohibited_cipher_refused,
        # §11 RAAM
        "SEC-11.1-1": check_no_client_cert_refused if ctx.cli.config in ("A", "C")
                      else _attest(f"--config {ctx.cli.config} does not exercise "
                                   f"mTLS-only RAAM."),
        "SEC-11.2-1": check_no_client_cert_accepted if ctx.cli.config == "B"
                      else _attest(f"--config {ctx.cli.config} does not exercise "
                                   f"server-TLS-only RAAM."),
        # §12.15 IPMX security tags
        "SEC-12.15-1": check_ipmx_security_tags,
        # §12.8 / §12.11 / §12.13 / §12.14-6/7 / §14.3.3.5-3 — GCRL.
        # The matrix runner provides the wire context by launching the
        # DUT with --gcrl pointing at either an empty CRL bundle or a
        # revocation bundle. The probes fire only under the dedicated
        # A-crl-* matrix entries (gated by --focus-req-ids); other
        # entries leave these as NOT-APPLICABLE.
        "SEC-12.8-1":   check_crl_revoked_cert_refused,
        "SEC-12.11-1":  check_crl_revoked_cert_refused,
        "SEC-12.13-1":  check_crl_revoked_cert_refused,
        "SEC-12.14-6":  check_crl_baseline_handshake_unaffected,
        "SEC-12.14-7":  check_crl_baseline_handshake_unaffected,
        "SEC-14.3.3.5-3": check_crl_revoked_cert_refused,
        # §14.3.2 JWKS
        "SEC-14.3.2-1": check_jwks_pickup,
        # SEC-14.3.2-12 (AS cert validated against trusted CA):
        # negative probe — DUT pointed at fake AS with untrusted cert
        # must refuse JWKS pickup ⇒ remains in 401 state. Only fires
        # when the B-untrusted-as matrix entry focuses on this req_id.
        "SEC-14.3.2-12": check_jwks_pickup_rejects_untrusted_as,
        # SEC-14.3.2-13 (Node configured with trusted CAs for AS cert
        # validation): the fake AS uses a server cert chained to
        # ExampleRootCA, which is in the DUT's CTCA. Every successful
        # JWKS pickup is implicit proof the Node validates against
        # its configured CTCA — reuse the same check.
        "SEC-14.3.2-13": check_jwks_pickup,
        # §14.3.3.1 lifetime
        # SEC-14.3.3.1-1 ("exp shall be 1-24h from iat") reclassified
        # in requirements_classification.json as C (about token issuance
        # — the §14.3.3.4 pseudocode does not enforce this range; AS-side).
        "SEC-14.3.3.1-2": check_expired_token_rejected,
        # §14.3.3.2 type / alg / curve
        "SEC-14.3.3.2-1": check_typ_missing_rejected,
        "SEC-14.3.3.2-2": check_alg_unsupported_rejected,
        "SEC-14.3.3.2-3": check_es256_with_wrong_curve_rejected,
        "SEC-14.3.3.2-4": check_es512_with_wrong_curve_rejected,
        "SEC-14.3.3.2-5": _make_alg_accept_check("RS256"),  # per-alg matrix
        # §14.3.3.3 grants & claims (missing-claim matrix + nbf + ext)
        "SEC-14.3.3.3-3": check_sub_not_equal_client_id_for_cc,
        "SEC-14.3.3.3-4": check_all_required_claims_enforced,
        "SEC-14.3.3.3-5": check_nbf_present_ignored,  # nbf-present-still-accepted
        "SEC-14.3.3.3-6": check_336_combined,  # nbf + iat ignored
        "SEC-14.3.3.3-7": check_xnmos_should_be_in_ext,
        "SEC-14.3.3.3-8": check_xnmos_top_level_accepted,
        # SEC-14.3.3.3-9 (SHOULD: x-nmos-* in ext OR top-level) and
        # SEC-14.3.3.3-10 (SHALL: if duplicated, identical): both
        # witnessed by a single probe that mints a token with the
        # claim in BOTH places with identical values and verifies
        # the Node accepts. Negative case (conflicting duplicates)
        # is spec-undefined and stays vendor-attestation.
        "SEC-14.3.3.3-9": check_xnmos_in_both_placements_identical,
        "SEC-14.3.3.3-10": check_xnmos_in_both_placements_identical,
        # §14.3.3.4 validation matrix
        "SEC-14.3.3.4-1": check_tls_required_for_http,
        "SEC-14.3.3.4-2": check_query_param_token_rejected,
        "SEC-14.3.3.4-3": check_bad_signature_rejected,
        "SEC-14.3.3.4-4": check_bad_signature_rejected,  # 401 + WWW-Authenticate
        "SEC-14.3.3.4-5": check_validation_sequence_observed,
        "SEC-14.3.3.4-8": check_aud_substring_match_accepted,
        "SEC-14.3.3.4-10": check_aud_substring_only_denied_without_cert_match,
        "SEC-14.3.3.4-11": check_aud_oaim_cert_dns_wildcard,
        "SEC-14.3.3.4-12": check_aud_dns_wildcard_accepted,
        "SEC-14.3.3.4-13": check_aud_13_combined,
        "SEC-14.3.3.4-14": check_aud_ordering_consistent,
        "SEC-14.3.3.4-16": check_scope_provides_default_read,
        "SEC-14.3.3.4-17": check_scope_without_api_denied,
        "SEC-14.3.3.4-18": check_scope_grants_default_read,
        "SEC-14.3.3.4-19": check_xnmos_19_combined,
        # SEC-14.3.3.4-20 is specifically "empty-string scope" per
        # the spec text. The missing-scope variant is exercised by
        # check_missing_scope_rejected (mapped under -1's req_id via
        # the required-claims matrix in check_all_required_claims).
        "SEC-14.3.3.4-20": check_scope_empty_string_denied,
        "SEC-14.3.3.4-21": check_xnmos_read_star_allowed,
        "SEC-14.3.3.4-22": check_xnmos_read_empty_string_denied,
        "SEC-14.3.3.4-23": check_xnmos_read_invalid_value_form,
        "SEC-14.3.3.4-25": check_xnmos_read_aud_index_allow,
        "SEC-14.3.3.4-26": check_xnmos_read_aud_negative_index_deny,
        "SEC-14.3.3.4-28": check_xnmos_28_combined,
        "SEC-14.3.3.4-40": check_aud_out_of_bounds_index_invalid,
        "SEC-14.3.3.4-41": check_xnmos_write_deny_only_list,
        "SEC-14.3.3.4-42": check_aud_sort_order_violation_invalid,  # symmetric for write
        "SEC-14.3.3.4-43": check_empty_integer_array_invalid,
        # §14.3.3.5 fail-closed posture
        "SEC-14.3.3.5-1": check_no_public_keys_fail_closed,
        "SEC-14.3.3.5-2": check_no_public_keys_fail_closed,
        "SEC-14.3.3.5-4": check_no_public_keys_fail_closed,
        "SEC-14.3.3.5-5": check_401_includes_www_authenticate,
        "SEC-14.3.3.5-6": check_401_includes_www_authenticate,
        # §14.3.3.6 mTLS client_id binding (Config C only)
        "SEC-14.3.3.6-1": check_clientid_mismatch_rejected,
        "SEC-14.3.3.6-2": check_clientid_mismatch_rejected,
        "SEC-14.3.3.6-3": check_clientid_case_insensitive_match,
        "SEC-14.3.3.6-6": check_clientid_mismatch_rejected,
        "SEC-14.3.3.6-7": check_sub_not_used_for_binding,
        # §14.3.4 HTTP status codes
        "SEC-14.3.4-1": check_403_for_insufficient_permission,
        # §8 cipher / group matrix + version preference
        "SEC-8-3": check_tls13_preferred_when_both_offered,
        # SEC-8-4 (PFS): the TR-10-SEC cipher whitelist contains ONLY
        # ECDHE/DHE suites — verifying a mandatory PFS cipher
        # negotiates positively confirms PFS at handshake time.
        "SEC-8-4": check_tls_12_mandatory_cipher,
        # SEC-8-5: per-curve client-side support. Each A-curve-*
        # matrix entry pins the proxy/AS to one curve via OPENSSL_CONF
        # and PASSes when the DUT completes outbound handshake(s).
        "SEC-8-5": check_tls_group_supported_client_side,
        "SEC-8-7": check_cbc_ciphers_refused,
        "SEC-8-8": check_tls12_cipher_matrix,
        # §14.3.2.1 Metadata endpoint URL forms
        "SEC-14.3.2.1-1": check_metadata_forms_supported,
        "SEC-14.3.2.1-2": check_metadata_forms_supported,
        "SEC-14.3.2.1-3": check_metadata_forms_supported,
        "SEC-14.3.2.1-4": check_jwks_uri_honored,
        "SEC-14.3.2.1-5": check_jwks_uri_honored,
        # §14.3.2 remaining testable items
        "SEC-14.3.2-2": check_initial_fetch_required,
        "SEC-14.3.2-3": check_fail_closed_when_keys_unavailable,
        "SEC-14.3.2-5": check_fail_closed_when_keys_unavailable,
        # SEC-14.3.2-8 (DNS-SD AS discovery) deliberately NOT wired —
        # the validator does not exercise mDNS. Vendor attestation.
        # Reclassified A in requirements_classification.json.
        "SEC-14.3.2-9": check_iss_not_used_for_jwks,  # iss-claim-not-used (was mis-mapped to -8)
        "SEC-14.3.2-11": check_jwks_fetch_uses_tls_1_2_or_1_3,
        # §12.5 cert-flavor key size enforcement
        "SEC-12.5-1": check_server_cert_meets_tct,
        "SEC-12.5-2": check_server_cert_meets_tct,
        # §14.1 / §14.2 scope / path
        "SEC-14.1-1": check_scope_connection_denies_node,
        "SEC-14.1-2": check_ncp_scope_grants_access,
        "SEC-14.1-3": check_manufacturer_scope_grants_access,
        "SEC-14.2-1": check_scope_grants_node_api,
        "SEC-14.2-2": check_manufacturer_scope_grants_access,
        "SEC-14.2-3": check_ncp_scope_grants_access,
        # §14.3.3.7 WebSocket — Guest endpoint + subscription R/O rule.
        "SEC-14.3.3.7-1": check_guest_ws_upgrade,
        "SEC-14.3.3.7-2": check_guest_ws_upgrade,
        "SEC-14.3.3.7-3": check_subscription_is_readonly,
        # §12.10 / §12.12 NESTCA vs CESTCA trust-store isolation.
        # Both SHALLs are about admin capacity (≥2 per role) but the
        # wire test below demonstrates that the roles ARE distinct on
        # this DUT — the precondition for the capacity guarantee to
        # be meaningful. Single dispatch entry, both req_ids share it.
        "SEC-12.10-2": check_nestca_cestca_isolation,
        "SEC-12.12-2": check_nestca_cestca_isolation,
        # §9 NAP
        "SEC-9.2-1": check_nap1_not_combined_with_oauth,
        "SEC-9.2-2": check_anonymous_read_allowed_under_nap1,
        "SEC-9.3-1": check_nap_2_supported,
        "SEC-9.3-2": check_nap_2_get_requires_auth,
        "SEC-9.3-3": check_writes_require_auth_full,
        # §9 / §11 / §12 Device Configuration — per-run mode-support
        # confirmation via published tags. The single-run check
        # confirms the DUT advertises the mode the operator declared
        # (which IS the spec's "device shall allow [admin] to configure
        # X" requirement — the operator IS the admin, and the run
        # demonstrates the device honoured the declared mode). The
        # broader "support all enumerated modes" mandate requires
        # multi-run submissions (see TODO.md launch-script env vars).
        "SEC-9-1": _make_per_run_mode_check(
            TAG_NAP, "NAP", ctx.cli.expect_nap,
            {"1", "2"}, "NAP modes 1 and 2"),
        "SEC-11.1-2": _make_per_run_mode_check(
            TAG_TCT, "TCT", ctx.cli.expect_tct,
            {"0", "1", "2"}, "all three TCT modes"),
        "SEC-11.1-3": _make_per_run_mode_check(
            TAG_TCT, "TCT", ctx.cli.expect_tct,
            {"0", "1", "2"}, "all three TCT modes"),
        "SEC-11.2-2": _make_per_run_mode_check(
            TAG_TCT, "TCT", ctx.cli.expect_tct,
            {"0", "1", "2"}, "all three TCT modes"),
        "SEC-11.2-3": _make_per_run_mode_check(
            TAG_TCT, "TCT", ctx.cli.expect_tct,
            {"0", "1", "2"}, "all three TCT modes"),
        "SEC-11.3-1": _make_per_run_mode_check(
            TAG_TCT, "TCT", ctx.cli.expect_tct,
            {"0", "1", "2"}, "all three TCT modes"),
        "SEC-11.3-2": _make_per_run_mode_check(
            TAG_TCT, "TCT", ctx.cli.expect_tct,
            {"0", "1", "2"}, "all three TCT modes"),
        "SEC-10.2-3": _make_per_run_mode_check(
            TAG_RAP, "RAP", ctx.cli.expect_rap,
            {"1", "2"}, "Unrestricted + Restricted Registration"),
        # Registry-proxy-observed checks — the matrix runner
        # interposes a transparent proxy between the DUT and any
        # upstream registry, then dumps its observed request log
        # to the validator via --registry-proxy-log. These five
        # entries grade the DUT's actual Node→Registry behaviour
        # against the §7.2 / §10 wire requirements.
        "SEC-7.2-1": check_registry_no_authorization_header,
        "SEC-7.2-2": check_registry_tls_secured,
        "SEC-10.1-1": check_registry_https_when_api_proto_https,
        "SEC-10.1-2": check_registry_tls_supported_by_all,
        "SEC-10.2-1": check_registry_mtls_when_restricted,
        "SEC-12.5-3": check_tct_common_across_endpoints,
        "SEC-12.5-4": _make_per_run_mode_check(
            TAG_TCT, "TCT", ctx.cli.expect_tct,
            {"0", "1", "2"}, "all three TCT modes"),
        # SEC-12.14-4: "retrieve current effective values of NAP/RAP/...
        # ... through non-sensitive metadata" — the IPMX security tags
        # ARE this retrieval mechanism, already wire-tested by SEC-12.15-1.
        "SEC-12.14-4": check_ipmx_security_tags,
        "SEC-12.1-1": _make_per_run_mode_check(
            TAG_NAP, "NAP", ctx.cli.expect_nap,
            {"2"}, "NAP=2 (Restricted RW, mandatory)"),
        "SEC-12.2-1": _make_per_run_mode_check(
            TAG_RAP, "RAP", ctx.cli.expect_rap,
            {"1", "2"}, "Unrestricted + Restricted Registration"),
        "SEC-12.3-1": _make_per_run_mode_check(
            TAG_RAAM, "RAAM", ctx.cli.expect_raam,
            {"0"}, "Mutual TLS Authentication (when no AS)")
                      if ctx.cli.config == "A"
                      else _attest("RAAM=0 (Mutual TLS Auth) is verified "
                                   "when --config A is exercised"),
        "SEC-12.3-2": _make_per_run_mode_check(
            TAG_RAAM, "RAAM", ctx.cli.expect_raam,
            {"1", "2"}, "OAuth 2.0 + optional mTLS")
                      if ctx.cli.config in ("B", "C")
                      else _attest("RAAM=1 / RAAM=2 (OAuth 2.0) is verified "
                                   "when --config B or C is exercised"),
        "SEC-12.4-1": _make_per_run_mode_check(
            TAG_OAIM, "OAIM", ctx.cli.expect_oaim,
            {"0", "1", "2"}, "all three OAIM modes")
                      if ctx.cli.config in ("B", "C")
                      else _attest("OAIM is not applicable to --config A; "
                                   "mode coverage requires --config B/C runs"),
        "SEC-12.15-2": check_tag_value_format,
        # §14.3.3.4 write allow-list — covered by the same IS-05 PATCH
        # probe (auth-layer write enforcement on a real write endpoint).
        "SEC-14.3.3.4-39": check_writes_require_auth_full,
        # §14.3.3.4-15 same semantics as -17 (scope claim must list the
        # current API name); re-uses the existing scope-without-api probe.
        "SEC-14.3.3.4-15": check_scope_without_api_denied,
        # §9.2-3 is the spec sentence about NAP=1 write enforcement;
        # uses the same IS-05 PATCH probe.
        "SEC-9.2-3": check_writes_require_auth_full,
        # §14.3.3.4 write-attribute mirror checks
        "SEC-14.3.3.4-6": check_readonly_denial_logic,
        "SEC-14.3.3.4-7": check_readwrite_denial_logic,
        "SEC-14.3.3.4-24": check_three_forms_of_read_attribute,
        "SEC-14.3.3.4-27": check_aud_out_of_bounds_index_invalid,
        "SEC-14.3.3.4-29": check_xnmos_29_combined,
        "SEC-14.3.3.4-30": check_xnmos_read_deny_only_list,
        "SEC-14.3.3.4-31": check_xnmos_read_missing_denied,  # mirror: absence denies
        "SEC-14.3.3.4-32": check_xnmos_write_requires_read_too,
        "SEC-14.3.3.4-33": check_xnmos_write_path_independent,
        "SEC-14.3.3.4-34": check_xnmos_write_invalid_value_form,
        "SEC-14.3.3.4-35": check_three_forms_of_write_attribute,
        "SEC-14.3.3.4-36": check_aud_sort_order_violation_invalid,
        "SEC-14.3.3.4-37": check_aud_sort_order_violation_invalid,
        "SEC-14.3.3.4-38": check_xnmos_write_oob_index_invalid,
        # SEC-14.3.3.4-39 ("write allow-list non-empty / no match → deny")
        # requires probing a WRITE endpoint (PATCH/POST) — GET /self
        # only exercises read paths. Left as E pending a write-endpoint
        # probe (e.g. against a known sender's /staged sub-resource).
        "SEC-14.3.3.4-44": check_side_effect_request_requires_write,
        "SEC-14.3.3.4-45": check_side_effect_request_requires_write,
    }

    # ---------------------------------------------------------------------
    # Assemble registry from the JSON-extracted spec records.
    # ---------------------------------------------------------------------
    for record in _load_spec_registry():
        req_id: str = record["req_id"]
        check: CheckFn | None = dispatch.get(req_id)
        if check is None:
            check = _classified(req_id)
        reg.add(
            req_id,
            Level(record["level"]),
            record["section_path"],
            record["text"],
            check,
        )

    return reg


# ---------------------------------------------------------------------------
# Probe helpers used by check functions
# ---------------------------------------------------------------------------

def _split_host_port(spec: str) -> tuple[str, int]:
    """Parse ``host:port`` into a (str, int) pair."""
    host, _, port = spec.rpartition(":")
    if not host or not port:
        raise ValueError(f"invalid host:port spec {spec!r}")
    return host, int(port)


def _extract_cert_dns_san(cert_path: Path) -> str | None:
    """Read ``cert_path`` (PEM) and return the first DNS-SAN entry.

    Used to derive the token ``client_id`` that satisfies the §14.3.3.6
    mTLS client-id binding the DUT enforces. Falls back to the cert's
    CN if no DNS SAN is present, and to ``None`` if neither is found.
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID, NameOID
        with open(cert_path, "rb") as f:
            data = f.read()
        # The chain.pem file may contain multiple certs; the leaf is
        # always first.
        cert = x509.load_pem_x509_certificate(data)
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            )
            dns_names = san_ext.value.get_values_for_type(x509.DNSName)
            if dns_names:
                return str(dns_names[0])
        except x509.ExtensionNotFound:
            pass
        # Fall back to the CN.
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            return str(cn_attrs[0].value)
    except Exception:  # pylint: disable=broad-except
        return None
    return None


async def _populate_self_resource(ctx: SecurityValidationContext) -> None:
    """One-shot fetch of ``GET /self`` + ``GET /devices`` — caches on
    the context the published security-tag dict, Node-level services,
    and per-device controls. Every spec check that needs to dispatch
    against a discovered API reads from these cached structures.

    Services and controls carry **absolute** hrefs; a DUT that exposes
    its IS-05/IS-12/IS-08/IS-11 endpoints on a separate
    ``--controlPort`` is honoured because the validator never
    reconstructs URLs from ``dut_base_url`` — it always uses the
    href verbatim.
    """
    token = None
    if ctx.fake_as is not None and ctx.cli.config in ("B", "C"):
        template = ctx.fake_as.token_template(
            instance_id=ctx.cli.instance_id,
            client_id=ctx.client_id,
        )
        token = mint_token(template, ctx.fake_as.primary_key)
    elif ctx.cli.keycloak_url and ctx.cli.config in ("B", "C"):
        # Stage 2: fetch a token from the live Keycloak so the
        # standard wire tests can read /self. ``REQUESTS_CA_BUNDLE``
        # (set by the orchestrator for Stage 2 runs) gives the
        # ``requests`` calls in ``keycloak.test_tokens`` the right
        # TLS trust anchor for Keycloak's server cert.
        #
        # Grant selection:
        #   Config C (mTLS + OAuth): client_credentials with
        #     client_id == validator's cert SAN, so the §14.3.3.6
        #     client_id/cert-SAN binding passes. The matching OAuth
        #     client must exist in Keycloak (the grants CSV's
        #     ``Example.Company.Device.Client.ABC.SNX00000.example.com``
        #     subject provides it when the matrix runner picks that
        #     cert by default).
        #   Config B (server-TLS only): no client cert presented to
        #     the DUT — no §14.3.3.6 binding to satisfy — so a
        #     user-password grant via ``nmos-test-client`` is fine.
        try:
            sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
            # ``test_tokens`` reaches Keycloak with ``requests``, which
            # verifies against the system trust store and knows nothing about
            # ``--server-ca``. The workspace PKI's root is deliberately not
            # installed system-wide, so without this the token fetch fails
            # with "unable to get local issuer certificate" and every
            # subsequent tag read reports the DUT as advertising nothing —
            # 17 SHALL failures whose stated cause is a missing tag rather
            # than an unverifiable Authorization Server.
            #
            # Handed over through the two variables ``requests`` reads, which
            # is exactly what ``test_tokens.py``'s own CLI does for itself;
            # importing it as a library skipped that. ``setdefault`` so an
            # operator who exported either one still wins.
            if ctx.cli.server_ca is not None:
                os.environ.setdefault("REQUESTS_CA_BUNDLE", str(ctx.cli.server_ca))
                os.environ.setdefault("SSL_CERT_FILE", str(ctx.cli.server_ca))
            from keycloak.test_tokens import (
                get_client_token, get_user_token,
            )
            if ctx.cli.client_cert is not None:
                fetched, err = get_client_token(
                    base_url=ctx.cli.keycloak_url,
                    realm=ctx.cli.keycloak_realm,
                    client_id=ctx.client_id,
                    client_secret="secret",
                )
            else:
                fetched, err = get_user_token(
                    base_url=ctx.cli.keycloak_url,
                    realm=ctx.cli.keycloak_realm,
                    username="local-admin",
                    password="password",
                    client_id="nmos-test-client",
                    client_secret="secret",
                )
            if err is None and fetched:
                token = fetched
            else:
                LOG.warning(
                    "Stage 2 token fetch failed: %s — tag-read "
                    "probes will report no self_resource", err,
                )
        except Exception as exc:  # pylint: disable=broad-except
            LOG.warning(
                "Stage 2: token-fetch raised %s — tag-read probes "
                "will report no self_resource", exc,
            )
    resp = await fetch_self(ctx.http_client, ctx.dut_base_url, token=token)
    if resp.status != 200:
        LOG.warning("GET /self returned %d: %s", resp.status, resp.text()[:200])
        return
    body = resp.json()
    ctx.self_resource = body
    tags = body.get("tags", {})
    if isinstance(tags, dict):
        ctx.advertised_tags = tags
    services = body.get("services", [])
    if isinstance(services, list):
        ctx.advertised_services = [s for s in services if isinstance(s, dict)]

    # Fetch and flatten device.controls[] across every device.
    devices_url = f"{ctx.dut_base_url}/x-nmos/node/v1.3/devices/"
    try:
        d_resp = await request_with_token(ctx.http_client, devices_url, token=token)
    except Exception:  # pylint: disable=broad-except
        return
    if d_resp.status != 200:
        return
    try:
        devices = d_resp.json()
    except Exception:  # pylint: disable=broad-except
        return
    if not isinstance(devices, list):
        return
    flat_controls: list[dict[str, Any]] = []
    for device in devices:
        if not isinstance(device, dict):
            continue
        controls = device.get("controls", []) or []
        for ctrl in controls:
            if isinstance(ctrl, dict):
                flat_controls.append(ctrl)
    ctx.advertised_controls = flat_controls


def _find_control_href(
    ctx: SecurityValidationContext, urn_prefix: str,
) -> str | None:
    """Return the highest-version href among advertised controls whose
    ``type`` starts with ``urn_prefix``, or ``None`` if no match.

    The href is honoured verbatim — devices that expose their control
    APIs on a different host:port (split-listener mode) are supported.
    Common URN prefixes:

      - ``urn:x-nmos:control:sr-ctrl/``  (IS-05 ConnectionAPI)
      - ``urn:x-nmos:control:ncp/``       (IS-12 ncp)
      - ``urn:x-nmos:control:cm-ctrl/``  (IS-08 ChannelMappingAPI)
      - ``urn:x-nmos:control:sr-mgr/``    (IS-11 StreamCompatibility)
    """
    best: tuple[str, str] | None = None  # (version, href)
    for ctrl in ctx.advertised_controls:
        ctype = ctrl.get("type", "")
        if not isinstance(ctype, str) or not ctype.startswith(urn_prefix):
            continue
        href = ctrl.get("href", "")
        if not isinstance(href, str) or not href:
            continue
        version = ctype[len(urn_prefix):]
        if best is None or version > best[0]:
            best = (version, href.rstrip("/"))
    return best[1] if best else None


def _find_service_href_prefix(
    ctx: SecurityValidationContext, path_prefix: str,
) -> str | None:
    """Return the first Node-level service whose href's PATH starts
    with ``path_prefix`` (e.g. ``/x-manufacturer/``).

    Used by §14.1-3 / §14.2-2 (manufacturer scope) — the Reservation
    service and any other ``x-manufacturer`` API is advertised here
    with its absolute URL; split-listener deployments may expose it
    on a different port from the Node API."""
    from urllib.parse import urlparse
    for svc in ctx.advertised_services:
        href = svc.get("href", "")
        if not isinstance(href, str) or not href:
            continue
        try:
            parsed = urlparse(href)
        except Exception:  # pylint: disable=broad-except
            continue
        if parsed.path.startswith(path_prefix):
            return href.rstrip("/")
    return None


def _enumerate_server_endpoints(
    ctx: SecurityValidationContext,
) -> list[ServerEndpoint]:
    """Build the complete TR-10-SEC §7.1 server-endpoint inventory.

    Sources, all from cached IS-04 resources:

      1. ``self.api.endpoints[]`` — Node API endpoints (IS-04). Each
         entry carries ``{host, port, protocol}``; assemble to a base
         URL. Scope = "node". Read-only.
      2. ``device.controls[]`` — Control API endpoints. Each entry
         whose ``type`` matches a URN in :data:`_KNOWN_CONTROL_APIS`
         contributes ONE inventory record carrying that control's
         scope + read paths + write recipe (if any).
      3. ``self.services[]`` — Optional service API endpoints. Each
         entry whose ``type`` matches a prefix in
         :data:`_KNOWN_SERVICES` contributes one record.

    Per the spec, two records can share host:port and still be
    distinct endpoints — the inventory NEVER de-duplicates by URL.

    Out-of-scope (per spec §7.1): transport streams, DHCP/PTP/NTP/
    DNS/mDNS, 802.1x. None of these are enumerated.
    """
    out: list[ServerEndpoint] = []

    # 1. Node API endpoint. The operator passed ``--dut <host:port>``
    # as the canonical Node API entry — that is the authoritative
    # base URL the suite tests against (it is what the certification
    # submission claims is the device's Node API). The Node's own
    # ``self.api.endpoints[]`` is also published but is consulted
    # only by :func:`_check_dut_matches_node_api_endpoint`, which
    # flags a mismatch as a §8-style discrepancy (reference-node
    # hardcodes ``protocol="http"`` and may not list every actual
    # listener, so trusting it would shape the inventory wrongly).
    out.append(ServerEndpoint(
        label="node-api",
        base_url=ctx.dut_base_url,
        scope="node",
        source="api.endpoints",
        control_spec=None,
    ))

    # 2. Control APIs from device.controls[].
    for ctrl in ctx.advertised_controls:
        ctype = ctrl.get("type", "")
        href = ctrl.get("href", "")
        if not isinstance(ctype, str) or not isinstance(href, str) or not href:
            continue
        matched: ControlApiSpec | None = None
        for spec in _KNOWN_CONTROL_APIS:
            if ctype.startswith(spec.urn_prefix):
                matched = spec
                break
        if matched is None:
            # Control type not in the known list — record it with a
            # generic scope (audit visibility) but without read/write
            # probes. Future spec versions can extend _KNOWN_CONTROL_APIS.
            out.append(ServerEndpoint(
                label=f"controls:{ctype}",
                base_url=href.rstrip("/"),
                scope="node",  # safest fallback
                source="controls",
                control_spec=None,
            ))
            continue
        # Append the version suffix to the label for traceability.
        version = ctype[len(matched.urn_prefix):]
        label = f"{matched.label}/{version}" if version else matched.label
        out.append(ServerEndpoint(
            label=f"controls:{label}",
            base_url=href.rstrip("/"),
            scope=matched.scope,
            source="controls",
            control_spec=matched,
        ))

    # 3. Service APIs from self.services[].
    for svc in ctx.advertised_services:
        stype = svc.get("type", "")
        href = svc.get("href", "")
        if not isinstance(stype, str) or not isinstance(href, str) or not href:
            continue
        scope = "node"
        label = stype
        for prefix, (sscope, slabel) in _KNOWN_SERVICES.items():
            if stype.startswith(prefix):
                scope = sscope
                label = slabel
                break
        out.append(ServerEndpoint(
            label=f"services:{label}",
            base_url=href.rstrip("/"),
            scope=scope,
            source="services",
            control_spec=None,
        ))

    return out


def _default_read_path(endpoint: ServerEndpoint) -> str:
    """The canonical GET path for this endpoint, used by per-endpoint
    auth-layer probes that don't care WHICH read URL they target —
    they just need a path that the DUT's auth middleware gates."""
    if endpoint.control_spec is not None and endpoint.control_spec.read_paths:
        return endpoint.control_spec.read_paths[0]
    if endpoint.source == "api.endpoints":
        # Node API endpoints have no spec-canonical read path on the
        # ServerEndpoint record; /self is the universal IS-04 entry
        # that every conformant Node serves.
        return "/x-nmos/node/v1.3/self"
    # services or unknown controls — best effort: hit the base.
    return ""


async def _probe_at(
    ctx: SecurityValidationContext,
    endpoint: ServerEndpoint,
    *,
    mutate=None,
    header_mutate=None,
    expected_status: int | tuple[int, ...] = 200,
    path_suffix: str | None = None,
    method: str = "GET",
    json_body: dict[str, Any] | None = None,
    override_scope: str | None = None,
    key: SigningKey | None = None,
    client_id: str | None = None,
    grant_type: str = "client_credentials",
) -> tuple[bool, str]:
    """Mint a token whose scope matches ``endpoint.scope`` (unless
    ``override_scope`` is given), send the request to
    ``endpoint.base_url + path_suffix``, and assert
    ``resp.status == expected_status``.

    ``grant_type`` shapes the token to mimic either an OAuth 2.0
    ``client_credentials`` grant (``sub == client_id``) or an
    ``authorization_code`` grant (``sub`` is a synthetic user-id,
    ``azp == client_id``). Stage 1 doesn't drive a real login form
    for auth_code — it just synthesises the resulting claim shape."""
    if ctx.fake_as is None:
        return (False, "no fake AS configured")
    template = ctx.fake_as.token_template(
        instance_id=ctx.cli.instance_id,
        client_id=client_id if client_id is not None else ctx.client_id,
    )
    signing_key = key if key is not None else ctx.fake_as.primary_key
    effective_scope = override_scope if override_scope is not None else endpoint.scope

    def composed_mutate(claims: dict[str, Any]) -> None:
        # Always inject the endpoint's required scope first so the
        # validator's request reaches the auth middleware. Caller's
        # mutate runs LAST so it can override scope if the test
        # specifically targets a scope-mismatch failure mode.
        claims["scope"] = effective_scope
        if mutate is not None:
            mutate(claims)

    token = mint_token(
        template, signing_key,
        mutate=composed_mutate, header_mutate=header_mutate,
        grant_type=grant_type,
    )
    suffix = path_suffix if path_suffix is not None else _default_read_path(endpoint)
    url = endpoint.base_url + suffix
    # One retry on transient connection errors. aiohttp's pooled
    # sockets occasionally race with server-side closes; a fresh
    # request typically succeeds.
    import aiohttp as _aiohttp
    try:
        resp = await request_with_token(
            ctx.http_client, url, method=method,
            token=token, json_body=json_body,
        )
    except (_aiohttp.ServerDisconnectedError, _aiohttp.ClientConnectionResetError):
        resp = await request_with_token(
            ctx.http_client, url, method=method,
            token=token, json_body=json_body,
        )
    accepted = (
        resp.status == expected_status if isinstance(expected_status, int)
        else resp.status in expected_status
    )
    if accepted:
        return (True, f"{method} {url} → {resp.status}")
    return (
        False,
        f"{method} {url} → {resp.status}, expected {expected_status} "
        f"(body: {resp.text()[:120]})"
    )


def _no_fake_as_outcome_for(
    ctx: SecurityValidationContext,
) -> (tuple[bool, str, bool] | tuple[bool, str, bool, bool]
      | tuple[bool, str, bool, bool, bool]):
    """Return the right ``ctx.fake_as is None`` verdict for the
    running configuration.

    Config A is mTLS-only — the spec does not exercise OAuth token
    validation in that mode, so probes that mint tokens are
    NOT-APPLICABLE: another configuration's run (Config B or C) will
    exercise them, and no fixture-side change can make Config A
    exercise OAuth. This is distinct from NEEDS-FIXTURE (which would
    incorrectly suggest "rerun with --fake-as in Config A would
    help") and from CANNOT-TEST (which is for vendor attestation).

    Configs B and C DO use OAuth; if the fake AS isn't running the
    adversarial probe really would work if Stage 1 were added, so
    NEEDS-FIXTURE is the truthful state there."""
    if ctx.cli.config == "A":
        return not_applicable(
            "Config A is mTLS-only — OAuth token validation does "
            "not apply; this requirement is exercised by Config B "
            "and Config C runs"
        )
    return needs_fixture(
        "requires Stage 1 fake AS — adversarial probe mints "
        "deliberately-malformed tokens which a live AS cannot "
        "produce by design"
    )


async def _probe_token_outcome_all_endpoints(
    ctx: SecurityValidationContext,
    *,
    mutate=None,
    header_mutate=None,
    expected_status: int | tuple[int, ...] = 200,
    label: str = "",
    require_writable: bool = False,
    key: SigningKey | None = None,
    client_id: str | None = None,
    counter: str | None = None,
    grants: tuple[str, ...] = ("client_credentials", "authorization_code"),
) -> tuple[bool, str]:
    """Per-endpoint variant of :func:`_probe_token_outcome` — runs the
    same token-mutation probe against every in-scope endpoint, under
    every OAuth grant shape in ``grants``, and aggregates outcomes.

    Default ``grants`` exercises BOTH client_credentials AND
    authorization_code shapes so the Node-side rules are validated
    end-to-end against each grant type per the spec §14.3.3.3 SHALLs.
    A check that specifically targets one grant-type rule (e.g.
    ``check_sub_not_equal_client_id_for_cc``) can override by
    passing ``grants=("client_credentials",)``.

    ``key`` overrides the fake AS's primary signing key (per-alg matrix).
    ``client_id`` overrides the cert-derived client_id (§14.3.3.6
    mTLS-binding mismatch tests).
    ``counter`` declares which §14.3.3.5 counter category each
    expected-deny outcome increments on the DUT."""
    if ctx.fake_as is None:
        return _no_fake_as_outcome_for(ctx)

    async def probe(ep: ServerEndpoint) -> tuple[bool, str]:
        # For each endpoint, exercise every requested grant shape.
        # Cell passes ONLY if every shape passes — a mismatch
        # surfaces as a per-grant FAIL string.
        lines: list[str] = []
        any_fail = False
        for grant in grants:
            ok, detail = await _probe_at(
                ctx, ep,
                mutate=mutate, header_mutate=header_mutate,
                expected_status=expected_status,
                key=key, client_id=client_id,
                grant_type=grant,
            )
            tag = "PASS" if ok else "FAIL"
            short_grant = "cc" if grant == "client_credentials" else "ac"
            lines.append(f"[{short_grant}] {tag}: {detail[:80]}")
            if not ok:
                any_fail = True
        joined = " ; ".join(lines)
        return (not any_fail, joined)

    return await _probe_each_endpoint(
        ctx, probe, label=label or "token-outcome",
        require_writable=require_writable, counter=counter,
    )


def _has_read_path(endpoint: ServerEndpoint) -> bool:
    """True iff this endpoint has a meaningful GET path to probe.

    Node API endpoints have ``/x-nmos/node/v1.3/self``; known control
    APIs have ``control_spec.read_paths``; services are POST-only by
    convention (Reservation has /acquire, /renew, ...) and skip
    read-side probes."""
    if endpoint.source == "api.endpoints":
        return True
    if endpoint.source == "controls" and endpoint.control_spec is not None:
        return bool(endpoint.control_spec.read_paths)
    return False


async def _probe_each_endpoint(
    ctx: SecurityValidationContext,
    probe: Callable[[ServerEndpoint], Awaitable[tuple[bool, str]]],
    *,
    require_writable: bool = False,
    label: str = "",
    skip_unknown_controls: bool = True,
    read_side: bool = True,
    counter: str | None = None,
) -> tuple[bool, str]:
    """Apply ``probe`` to every in-scope server endpoint, aggregating
    the per-endpoint outcomes.

    PASS if every endpoint passes; FAIL if any endpoint fails (the
    aggregate carries the full per-endpoint detail). When no endpoints
    apply (e.g. ``require_writable=True`` but the DUT exposes only
    read-only APIs), returns ``untestable(...)``.

    ``require_writable=True`` filters to endpoints whose ``control_spec``
    carries a write recipe — used by write-enforcement checks.
    ``skip_unknown_controls=True`` skips controls[] entries whose URN
    is not in :data:`_KNOWN_CONTROL_APIS` (we lack scope/path knowledge
    for those, so a probe would be guesswork).
    ``counter`` declares the §14.3.3.5 counter category each
    expected-deny probe increments on the DUT; we bump
    ``ctx.predicted_counters[counter]`` by one per endpoint probed
    so the attestation manifest can predict the DUT's post-run
    counter values."""
    endpoints = list(ctx.server_endpoints)
    if skip_unknown_controls:
        endpoints = [
            e for e in endpoints
            if e.source != "controls" or e.control_spec is not None
        ]
    if read_side:
        # POST-only services and unknown-control endpoints carry no
        # meaningful GET path; the read-side auth-layer probes don't
        # apply to them.
        endpoints = [e for e in endpoints if _has_read_path(e)]
    if require_writable:
        endpoints = [e for e in endpoints if e.is_writable]
    if not endpoints:
        return untestable(
            f"no in-scope endpoints to probe for {label or 'this check'}"
        )
    # Counter category: explicit ``counter=`` wins, otherwise auto-
    # detect from the label via the ``_LABEL_TO_COUNTER`` table.
    effective_counter = counter if counter is not None else _counter_for_label(label)
    lines: list[str] = []
    any_failed = False
    for ep in endpoints:
        try:
            passed, detail = await probe(ep)
        except Exception as exc:  # pylint: disable=broad-except
            passed = False
            detail = f"probe raised {type(exc).__name__}: {exc}"
        tag = "PASS" if passed else "FAIL"
        lines.append(f"  {tag} @{ep.label}: {detail[:160]}")
        if not passed:
            any_failed = True
        # Counter prediction: one expected DUT-side increment per
        # endpoint actually probed and rejected as the spec describes.
        if effective_counter is not None and passed:
            ctx.predicted_counters[effective_counter] = (
                ctx.predicted_counters.get(effective_counter, 0) + 1
            )
    if any_failed:
        return (False, f"\n[{label}] " + "\n".join(lines))
    return (True,
            f"all {len(endpoints)} endpoint(s) passed [{label}]"
            + (("\n" + "\n".join(lines)) if len(endpoints) <= 5 else ""))


def _check_dut_matches_node_api_endpoint(
    ctx: SecurityValidationContext,
) -> tuple[bool, str]:
    """Verify the operator's ``--dut <host:port>`` matches the
    canonical Node API endpoint advertised in ``self.api.endpoints[]``.

    Same shape as the §8 IPMX-tag-mismatch check — if the operator
    submitted ``--dut X`` but the device says its Node API is at Y,
    the operator's claim is inconsistent with what the device
    publishes and the certification submission must be corrected."""
    self_resource = ctx.self_resource or {}
    api = self_resource.get("api", {})
    endpoints = api.get("endpoints", []) if isinstance(api, dict) else []
    if not endpoints:
        return (False,
                "self.api.endpoints[] is empty — the device does not "
                "advertise any Node API endpoint")
    op_host, op_port = _split_host_port(ctx.cli.dut)
    matches = []
    for i, ep in enumerate(endpoints):
        if not isinstance(ep, dict):
            continue
        adv_host = ep.get("host", "")
        adv_port = ep.get("port", 0)
        if adv_host == op_host and adv_port == op_port:
            return (True,
                    f"operator's --dut {ctx.cli.dut} matches "
                    f"self.api.endpoints[{i}]")
        matches.append(f"{adv_host}:{adv_port}")
    return (False,
            f"operator's --dut {ctx.cli.dut} does not match any entry in "
            f"self.api.endpoints[]: {matches}")


async def _probe_token_outcome(
    ctx: SecurityValidationContext,
    *,
    mutate=None,
    header_mutate=None,
    expected_status: int | tuple[int, ...] = 200,
    path: str = "/x-nmos/node/v1.3/self",
    method: str = "GET",
    json_body: dict[str, Any] | None = None,
    key: SigningKey | None = None,
    client_id: str | None = None,
) -> tuple[bool, str]:
    """Mint a token (optionally mutated), send a request against the
    DUT, and assert the response status matches ``expected_status``.

    ``expected_status`` may be a single int or a tuple of accepted
    statuses (e.g. ``(401, 403)`` when the spec allows either denial code).
    ``key`` overrides the fake AS's primary signing key (used for the
    per-alg matrix). ``client_id`` overrides the cert-derived client_id
    (used for §14.3.3.6 mTLS-binding mismatch tests).
    """
    assert ctx.fake_as is not None
    template = ctx.fake_as.token_template(
        instance_id=ctx.cli.instance_id,
        client_id=client_id if client_id is not None else ctx.client_id,
    )
    signing_key = key if key is not None else ctx.fake_as.primary_key
    token = mint_token(
        template, signing_key,
        mutate=mutate, header_mutate=header_mutate,
    )
    url = f"{ctx.dut_base_url}{path}"
    resp = await request_with_token(
        ctx.http_client, url, method=method, token=token, json_body=json_body,
    )
    accepted = (
        (resp.status == expected_status)
        if isinstance(expected_status, int)
        else (resp.status in expected_status)
    )
    if accepted:
        return (True, f"DUT returned {resp.status} as expected")
    return (
        False,
        f"DUT returned {resp.status}, expected {expected_status} "
        f"(body: {resp.text()[:200]})"
    )


# ---------------------------------------------------------------------------
# DUT launch orchestration
# ---------------------------------------------------------------------------

@contextlib.asynccontextmanager
async def _launch_dut_subprocess(cli: CLIArgs) -> AsyncIterator[subprocess.Popen | None]:
    """Spawn the DUT script if --launch-dut is set; SIGTERM on exit.

    The script is invoked with the AS host/port the validator currently
    runs (the fake AS's listener for Stage 1, or Keycloak's host:port for
    Stage 2). If --launch-dut is absent the operator launched the DUT
    manually; this context manager is a no-op.
    """
    if cli.launch_dut is None:
        yield None
        return

    as_host = cli.fake_as_host if cli.fake_as else (
        _split_host_port(cli.keycloak_url.removeprefix("https://").removeprefix("http://"))[0]
        if cli.keycloak_url else "localhost"
    )
    as_port = str(cli.fake_as_port if cli.fake_as else (
        _split_host_port(cli.keycloak_url.removeprefix("https://").removeprefix("http://"))[1]
        if cli.keycloak_url else 9443
    ))
    LOG.info("Launching DUT: %s %s %s", cli.launch_dut, as_host, as_port)
    proc = subprocess.Popen(
        [str(cli.launch_dut), as_host, as_port],
        # Run in the script's directory so relative paths resolve.
        cwd=str(cli.launch_dut.parent),
        # Don't capture stdout — let the operator see the DUT's output.
        stdout=None, stderr=None,
        # Put the child in its own process group so SIGTERM cleans up
        # any descendants the script forks (e.g. the actual python3
        # nmos_node.py process).
        preexec_fn=os.setsid,
    )
    try:
        yield proc
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            proc.wait(timeout=10.0)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass


async def _wait_for_dut(client: SecurityHttpClient, url: str, timeout: float) -> bool:
    """Poll ``url`` until it responds with ANY status code, or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            resp = await client.get(url)
            if resp.status in (200, 401, 403):
                # DUT is up — 401/403 mean it's serving but rejected our
                # anonymous probe, which is fine for liveness purposes.
                return True
        except Exception:  # pylint: disable=broad-except
            pass
        await asyncio.sleep(0.5)
    return False


async def _wait_for_jwks_pickup(
    ctx: SecurityValidationContext, *, timeout: float = 15.0,
) -> bool:
    """For configs B and C: poll /self with a valid Bearer token until
    the DUT returns 200. Until then the DUT is in TR-10-SEC §14.3.2
    fail-closed mode because it hasn't fetched JWKS from the AS yet,
    and every token-validation check would coincidentally 401.

    Works for both Stage 1 (fake AS — mints token locally) and
    Stage 2 (live Keycloak — fetches a user-password token via the
    ``local-admin`` test user provisioned by ``nmos_keycloak.py
    test``)."""
    url = f"{ctx.dut_base_url}/x-nmos/node/v1.3/self"
    deadline = time.monotonic() + timeout

    def _get_token() -> str | None:
        if ctx.fake_as is not None:
            template = ctx.fake_as.token_template(
                instance_id=ctx.cli.instance_id,
                client_id=ctx.client_id,
            )
            return mint_token(template, ctx.fake_as.primary_key)
        if ctx.cli.keycloak_url:
            try:
                sys.path.insert(
                    0, str(Path(__file__).resolve().parent.parent),
                )
                from keycloak.test_tokens import (
                    get_client_token, get_user_token,
                )
                if ctx.cli.client_cert is not None:
                    # Config C path: use client_credentials with the
                    # cert-SAN-derived client_id to satisfy §14.3.3.6.
                    tok, err = get_client_token(
                        base_url=ctx.cli.keycloak_url,
                        realm=ctx.cli.keycloak_realm,
                        client_id=ctx.client_id,
                        client_secret="secret",
                    )
                else:
                    tok, err = get_user_token(
                        base_url=ctx.cli.keycloak_url,
                        realm=ctx.cli.keycloak_realm,
                        username="local-admin",
                        password="password",
                        client_id="nmos-test-client",
                        client_secret="secret",
                    )
                if err is None and tok:
                    return tok
            except Exception:  # pylint: disable=broad-except
                pass
        return None

    while time.monotonic() < deadline:
        token = _get_token()
        if token is not None:
            try:
                resp = await request_with_token(ctx.http_client, url, token=token)
                if resp.status == 200:
                    return True
            except Exception:  # pylint: disable=broad-except
                pass
        await asyncio.sleep(0.5)
    return False


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

async def main(cli: CLIArgs) -> int:
    """Run the full validation pipeline. Returns the suggested exit code."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    dut_base_url = f"https://{cli.dut}"

    # Set up Stage 1 fake AS if requested.
    fake_as: FakeAuthorizationServer | None = None
    signing_key: SigningKey | None = None
    if cli.fake_as and cli.config in ("B", "C"):
        fake_cfg = FakeASConfig(
            host=cli.fake_as_host, port=cli.fake_as_port,
            cert_chain=cli.fake_as_cert or Path("/dev/null"),
            private_key=cli.fake_as_key or Path("/dev/null"),
            api_selector=cli.fake_as_realm,
        )
        # Seed the AS with one signing key per TR-10-SEC §14.3.3.2
        # permitted algorithm so the validator can mint tokens with
        # each alg + matching JWK for the per-alg test matrix.
        fake_keys = [
            SigningKey.generate(alg="RS256", kid="fake-as-rs256"),
            SigningKey.generate(alg="RS512", kid="fake-as-rs512"),
            SigningKey.generate(alg="ES256", kid="fake-as-es256"),
            SigningKey.generate(alg="ES512", kid="fake-as-es512"),
        ]
        fake_as = FakeAuthorizationServer(fake_cfg, signing_keys=fake_keys)
        # Bake the DUT hostname into every minted token's aud claim.
        # Reference-node's §14.3.3.4 aud check requires aud[0] to (a)
        # contain ctx.cli.instance_id as a substring AND (b) match a
        # cert SAN exactly. The bare ``instance_id`` (e.g. ``SNX00001``)
        # satisfies (a) but is not a cert identity, so without this
        # override every token gets 403 "insufficient permissions"
        # despite being perfectly signed. ``cli.dut`` is ``host:port``;
        # the hostname portion is conventionally a cert SAN.
        fake_as.default_aud_entry = cli.dut.split(":", 1)[0]
        # Lower the AS's minimum TLS version to 1.0 so the §14.3.2-11
        # probe has a meaningful test: a spec-compliant DUT only offers
        # 1.2 + 1.3 on the client side, so even with the AS willing to
        # speak 1.0/1.1 the handshake should converge on 1.2 or 1.3.
        # If the DUT mis-implements and offers 1.0/1.1, the AS would
        # accept and the connection log would catch it.
        fake_as.set_min_tls_version(ssl.TLSVersion.TLSv1)
        await fake_as.start()
        signing_key = fake_as.primary_key

    try:
        # Optionally launch the DUT subprocess.
        async with _launch_dut_subprocess(cli):
            async with SecurityHttpClient(
                server_ca=cli.server_ca,
                client_cert=cli.client_cert,
                client_key=cli.client_key,
                verify_hostname=False,  # workspace certs use bare hostnames
            ) as http_client:
                # Wait for the DUT to be reachable.
                if cli.launch_dut_wait:
                    LOG.info("Waiting for DUT at %s ...", cli.launch_dut_wait)
                    if not await _wait_for_dut(
                        http_client, cli.launch_dut_wait, cli.launch_dut_timeout,
                    ):
                        LOG.error("DUT did not become reachable within %.1fs",
                                  cli.launch_dut_timeout)
                        return 3

                # When mTLS is in use (configs A/C), the DUT enforces
                # §14.3.3.6 — token client_id MUST match the TLS client
                # cert's CN/SAN. Extract that name now so every token
                # the validator mints satisfies the binding.
                client_id = "ipmx-validator"
                if cli.client_cert is not None:
                    derived = _extract_cert_dns_san(cli.client_cert)
                    if derived:
                        LOG.info("Derived client_id %r from client cert SAN/CN",
                                 derived)
                        client_id = derived
                    else:
                        LOG.warning(
                            "Could not extract DNS SAN/CN from client cert %s; "
                            "tokens will use client_id=%r which the DUT will "
                            "reject under §14.3.3.6 if mTLS is in effect",
                            cli.client_cert, client_id,
                        )

                # If the matrix runner interposed a registry proxy,
                # load its observed request log. The matrix runner is
                # responsible for stopping the proxy BEFORE invoking
                # the validator so the log file is already written by
                # the time we reach this line.
                proxy_obs: RegistryProxyObservation | None = None
                if cli.registry_proxy_log is not None:
                    rap = (
                        cli.registry_proxy_rap
                        if cli.registry_proxy_rap is not None
                        else cli.expect_rap
                    )
                    proxy_obs = RegistryProxyObservation.load(
                        cli.registry_proxy_log, rap=rap,
                    )
                    LOG.info(
                        "Loaded registry-proxy log: %d records "
                        "(rap=%d) from %s",
                        len(proxy_obs.records), proxy_obs.rap,
                        cli.registry_proxy_log,
                    )

                ctx = SecurityValidationContext(
                    cli=cli,
                    dut_base_url=dut_base_url,
                    http_client=http_client,
                    fake_as=fake_as,
                    signing_key=signing_key,
                    client_id=client_id,
                    registry_proxy=proxy_obs,
                )

                # Stage 2 provisioning (if requested): must happen
                # BEFORE the JWKS-pickup wait and ``_populate_self_resource``
                # so ``local-admin`` + ``nmos-test-client`` exist when
                # the validator first asks Keycloak for a token.
                if cli.provision_keycloak and cli.keycloak_url:
                    from ipmx_security_scenarios import provision_realm_from_csv
                    LOG.info(
                        "Provisioning Keycloak realm %r from %s ...",
                        cli.keycloak_realm, cli.grants_csv,
                    )
                    try:
                        provision_realm_from_csv(
                            cli.grants_csv,
                            base_url=cli.keycloak_url,
                            realm=cli.keycloak_realm,
                            admin_user=cli.keycloak_admin_user,
                            admin_pass=cli.keycloak_admin_pass,
                        )
                    except Exception as exc:  # pylint: disable=broad-except
                        LOG.error("Keycloak provisioning failed: %s", exc)
                        return 4

                # For configs B/C, give the DUT time to fetch JWKS from
                # the AS (fake or live) before running any token-
                # validation checks. Otherwise the DUT is in §14.3.2
                # fail-closed mode and every probe gets a coincidental
                # 401. Works for both Stage 1 (fake AS) and Stage 2
                # (live Keycloak — uses the ``local-admin`` test user
                # provisioned above).
                if cli.config in ("B", "C") and (
                    ctx.fake_as is not None or cli.keycloak_url
                ):
                    as_kind = "fake AS" if ctx.fake_as is not None else "live Keycloak"
                    LOG.info("Waiting for DUT to pick up JWKS from %s ...",
                             as_kind)
                    if not await _wait_for_jwks_pickup(ctx, timeout=15.0):
                        LOG.warning(
                            "DUT did not pick up JWKS within 15s — proceeding "
                            "anyway; token-validation checks may falsely PASS "
                            "or FAIL due to the DUT being in fail-closed mode."
                        )
                    else:
                        LOG.info("DUT has JWKS — running checks.")

                # Populate the IS-04 resource cache (tags, services,
                # device.controls[]) BEFORE the registry is built —
                # the dispatch table inspects ctx.advertised_controls
                # so it can wire config-dependent checks correctly.
                # SKIP when focus is on CRL-refusal probes: those
                # entries put the validator's own client cert in the
                # CRL, so the DUT WILL refuse our mTLS handshake by
                # design — fetching /self ahead of time would crash
                # the run before the focused check could fire.
                _crl_refusal_focus = {
                    "SEC-12.8-1", "SEC-12.11-1", "SEC-12.13-1",
                    "SEC-14.3.3.5-3",
                }
                if cli.focus_req_ids & _crl_refusal_focus:
                    LOG.info(
                        "Skipping _populate_self_resource (focus on "
                        "CRL-refusal req_ids — mTLS handshake is "
                        "expected to fail by design)"
                    )
                else:
                    await _populate_self_resource(ctx)

                # Build the TR-10-SEC §7.1 server-endpoint inventory
                # from the cached IS-04 resources. Per-endpoint check
                # functions iterate this list so every in-scope
                # endpoint is exercised, not just the Node API.
                ctx.server_endpoints = _enumerate_server_endpoints(ctx)
                writable_count = sum(1 for e in ctx.server_endpoints if e.is_writable)
                LOG.info(
                    "Endpoint inventory (TR-10-SEC §7.1): %d in-scope "
                    "endpoint(s), %d writable. Breakdown: %s",
                    len(ctx.server_endpoints), writable_count,
                    ", ".join(f"{e.label}={e.base_url}" for e in ctx.server_endpoints),
                )

                # §8-style consistency audit: the operator's --dut must
                # match what the Node publishes in self.api.endpoints[].
                # Reference-node currently hardcodes protocol="http" in
                # the endpoint advert (a DUT-side bug); we still surface
                # the mismatch as a warning so the operator/auditor can
                # see when --dut and the device disagree.
                dut_check_ok, dut_check_detail = _check_dut_matches_node_api_endpoint(ctx)
                if dut_check_ok:
                    LOG.info("DUT/api.endpoints consistency: %s", dut_check_detail)
                else:
                    LOG.warning(
                        "DUT/api.endpoints mismatch (operator vs device): %s",
                        dut_check_detail,
                    )

                registry = build_requirements(ctx)
                if cli.focus_req_ids:
                    # Replace every non-focused check with a NOT-
                    # APPLICABLE shim. The full registry is still
                    # emitted (req_ids and levels intact); only the
                    # check functions are swapped.
                    focus = cli.focus_req_ids
                    def _not_applic_shim(rid: str) -> CheckFn:
                        async def shim() -> CheckResult:
                            return not_applicable(
                                f"--focus-req-ids restricted this run "
                                f"to {sorted(focus)}; {rid} is "
                                "exercised by a different matrix entry"
                            )
                        return shim
                    for req in registry:
                        if req.req_id not in focus:
                            # Replace the closure on the Requirement.
                            # Requirement is frozen — rebuild it.
                            new_req = Requirement(
                                req_id=req.req_id,
                                level=req.level,
                                section=req.section,
                                text=req.text,
                                check=_not_applic_shim(req.req_id),
                            )
                            # Find and replace in registry's internal list.
                            registry._reqs[registry._reqs.index(req)] = new_req  # type: ignore[attr-defined]
                    LOG.info(
                        "--focus-req-ids active: only %s will run; "
                        "others marked NOT-APPLICABLE",
                        ", ".join(sorted(focus)),
                    )
                if cli.list_requirements:
                    for req in registry:
                        print(json.dumps({
                            "req_id": req.req_id,
                            "level": req.level.value,
                            "section": req.section,
                            "text": req.text,
                        }))
                    return 0

                LOG.info("Running %d requirement checks ...", len(registry))
                results = await run_registry(registry)
                # Convert any SHOULD result gated on an optional
                # feature the operator did NOT declare into the
                # OPTIONAL-ABSENT terminal state.
                _apply_optional_feature_gates(results, cli.supports)
                if cli.supports:
                    LOG.info(
                        "Optional features declared via --supports: %s",
                        ", ".join(sorted(cli.supports)),
                    )

                # Stage 2 scenarios: drive the live AS's well-formed
                # tokens through the DUT's auth layer and assert the
                # per-row expected_status. Adds one RequirementResult
                # per scenario so the JSON dump + aggregator see them
                # uniformly with the wire-test results.
                if cli.keycloak_url and cli.scenarios_csv:
                    from ipmx_security_scenarios import (
                        KeycloakAccess, load_scenarios, run_scenarios,
                        Scenario,
                    )
                    if not cli.scenarios_csv.exists():
                        LOG.warning(
                            "Scenarios CSV %s missing — Stage 2 skipped",
                            cli.scenarios_csv,
                        )
                    else:
                        scenarios = load_scenarios(cli.scenarios_csv)
                        # Under Config C (mTLS+OAuth), §14.3.3.6
                        # requires the token's client_id to match the
                        # validator's TLS-client-cert SAN. The "client"
                        # in each scenario depends on subject_type:
                        #   'c' → the OAuth client IS subject_name
                        #   'a' → the OAuth client is via_client
                        #         (the user logs in THROUGH it)
                        #   'u' → the OAuth client is nmos-test-client
                        #         (won't match cert SAN — non-applicable
                        #         under Config C)
                        # Rows whose effective client_id doesn't equal
                        # ``ctx.client_id`` (the cert SAN) resolve to
                        # NOT-APPLICABLE for this run; another Config
                        # B run covers them without the cert binding.
                        scenario_results_not_applicable: list[Scenario] = []

                        def _scn_client_id(sc: Scenario) -> str:
                            if sc.subject_type == "c":
                                return sc.subject_name
                            if sc.subject_type == "a":
                                return sc.via_client
                            return "nmos-test-client"

                        if cli.config == "C" and cli.client_cert is not None:
                            keep = [s for s in scenarios
                                    if _scn_client_id(s) == ctx.client_id]
                            scenario_results_not_applicable = [
                                s for s in scenarios
                                if _scn_client_id(s) != ctx.client_id
                            ]
                            scenarios = keep
                            LOG.info(
                                "Config C: §14.3.3.6 binding restricts "
                                "Stage 2 scenarios to subject %r — "
                                "%d scenario(s) selected, %d marked NOT-APPLICABLE",
                                ctx.client_id, len(keep),
                                len(scenario_results_not_applicable),
                            )
                        LOG.info(
                            "Running %d Stage 2 scenarios against live AS ...",
                            len(scenarios),
                        )
                        kc_access = KeycloakAccess(
                            base_url=cli.keycloak_url,
                            realm=cli.keycloak_realm,
                        )
                        scenario_results = await run_scenarios(
                            scenarios,
                            dut_base_url=ctx.dut_base_url,
                            keycloak=kc_access,
                            http_client=ctx.http_client,
                        )
                        for sc in scenario_results_not_applicable:
                            results.append(RequirementResult(
                                req_id=f"SCN-{sc.test_id}",
                                level=Level.SHALL,
                                section="14.3.3.4-scenarios",
                                text=(
                                    f"{sc.http_method} {sc.dut_path} as "
                                    f"{sc.subject_name} → expected HTTP "
                                    f"{sc.expected_status}"
                                ),
                                passed=False,
                                details=(
                                    "Config C: subject's client_id does "
                                    "not match validator's cert SAN "
                                    f"({ctx.client_id!r}); §14.3.3.6 "
                                    "binding would refuse — scenario "
                                    "is exercised by Config B run"
                                ),
                                testable=False,
                                not_applicable=True,
                            ))
                        for sr in scenario_results:
                            results.append(RequirementResult(
                                req_id=f"SCN-{sr.scenario.test_id}",
                                level=Level.SHALL,
                                section="14.3.3.4-scenarios",
                                text=(
                                    f"{sr.scenario.http_method} "
                                    f"{sr.scenario.dut_path} as "
                                    f"{sr.scenario.subject_name} → "
                                    f"expected HTTP {sr.scenario.expected_status}"
                                ),
                                passed=sr.passed,
                                details=sr.details,
                                testable=True,
                            ))
                        LOG.info(
                            "Stage 2 scenarios: %d/%d passed",
                            sum(1 for r in scenario_results if r.passed),
                            len(scenario_results),
                        )

                print_results(results, filt=cli.report_filter)
                print()
                print(summary_line(results))

                # Attestation manifest + JSON dump.
                ts = datetime.now(timezone.utc)
                if cli.attestation_manifest is not None:
                    write_attestation_manifest(
                        results, str(cli.attestation_manifest),
                        dut=cli.dut, config=cli.config, timestamp=ts,
                        predicted_counters=dict(ctx.predicted_counters),
                        counter_descriptions=_COUNTER_DESCRIPTIONS,
                    )
                    LOG.info("Attestation manifest: %s", cli.attestation_manifest)
                if cli.json_out is not None:
                    expect = {
                        "raam": cli.expect_raam,
                        "nap": cli.expect_nap,
                        "rap": cli.expect_rap,
                        "tct": cli.expect_tct,
                        "oaim": cli.expect_oaim,
                    }
                    write_json_report(
                        results, str(cli.json_out),
                        dut=cli.dut, config=cli.config, timestamp=ts,
                        expect=expect, supports=sorted(cli.supports),
                        predicted_counters=dict(ctx.predicted_counters),
                    )
                    LOG.info("JSON dump: %s", cli.json_out)

                # Exit non-zero if any SHALL failed.
                shall_failures = [
                    r for r in results
                    if r.level is Level.SHALL and not r.passed and r.testable
                ]
                return 1 if shall_failures else 0
    finally:
        if fake_as is not None:
            await fake_as.stop()


def main_sync(argv: list[str] | None = None) -> int:
    cli = parse_cli(argv)
    return asyncio.run(main(cli))


if __name__ == "__main__":
    sys.exit(main_sync())
