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

"""Stage 2 scenario runner — Keycloak-driven access-control tests.

The Stage 1 fake AS exercises the §14.3.3.4 *adversarial* token-
validation matrix: malformed tokens, missing claims, wrong algorithm,
etc. Stage 2 instead drives the DUT with *well-formed* tokens
produced by a real Keycloak deployment, and verifies that the access-
control matrix (aud, scope, x-nmos-* claims, read/write allow/deny
lists) produces exactly the HTTP outcomes the spec mandates.

Each row of ``ipmx_security_cases.csv`` describes one scenario:

  test_id, subject_name, subject_type, dut_path, http_method,
  expected_status, expected_reason, notes

The runner:

  1. Imports ``keycloak.nmos_keycloak`` and ``keycloak.test_tokens``
     from the workspace's ``keycloak/`` subproject. These are the
     canonical Keycloak helpers; security/ does not duplicate them.
  2. (Optionally) provisions the realm + clients from the grants CSV.
  3. For each scenario row, fetches a token for the named subject and
     issues the requested HTTP method against the DUT path. Compares
     the actual status to ``expected_status``.

Subject definitions live in ``keycloak/TR-10-SEC_grants.csv`` (the
canonical grants file) and security-test-specific subjects can be
appended there.
"""

from __future__ import annotations

import csv
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Ensure the workspace root is on sys.path so the ``keycloak`` namespace
# package resolves whether the validator is invoked from security/ or
# from elsewhere. The plan permits this single cross-subproject import
# because keycloak/ is the security-infrastructure home.
_WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
if str(_WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(_WORKSPACE_ROOT))

from keycloak.test_tokens import (  # noqa: E402
    get_authcode_token, get_client_token, get_user_token,
)

from ipmx_security_probes import (
    SecurityHttpClient, auth_challenge_problem, request_with_token,
)


# ---------------------------------------------------------------------------
# Scenario row
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Scenario:
    """One row of ``ipmx_security_cases.csv``."""
    test_id: str
    subject_name: str
    subject_type: str        # 'u' (user), 'c' (client), 'g' (group), 'a' (auth_code)
    dut_path: str            # e.g. ``/x-nmos/node/v1.3/self``
    http_method: str         # GET / POST / PATCH / PUT / DELETE
    expected_status: int     # 200, 401, 403, etc.
    expected_reason: str = ""
    notes: str = ""
    via_client: str = ""
    """For ``subject_type='a'`` rows: the OAuth client_id through
    which the user authenticates via the authorization_code grant.
    The validator drives Keycloak's login form programmatically (no
    browser) and the resulting token carries this client_id while
    ``sub`` identifies the user."""
    via_redirect_uri: str = ""
    """For ``subject_type='a'`` rows: the redirect URI registered
    against ``via_client`` in Keycloak. The Keycloak controller
    client provisioning maps to ``https://xyz-<serial>:<port>/
    controller/oauth2/callback`` — any one of those is acceptable."""


@dataclass
class ScenarioResult:
    """Per-row verdict from :func:`run_scenarios`."""
    scenario: Scenario
    actual_status: int | None
    passed: bool
    details: str


# ---------------------------------------------------------------------------
# CSV loader
# ---------------------------------------------------------------------------

def load_scenarios(csv_path: Path) -> list[Scenario]:
    """Parse a scenarios CSV. Tolerates the ``#apis=...`` header
    directive used by keycloak/TR-10-SEC_grants.csv even though
    scenarios don't consume it (preserving the directive lets the
    same file be used as a grants CSV if needed).
    """
    out: list[Scenario] = []
    with open(csv_path, "r", encoding="utf-8") as f:
        rows = []
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            rows.append(line)
        reader = csv.DictReader(rows)
        for row in reader:
            if not row.get("test_id") or not row.get("subject_name"):
                continue  # blank separator row
            out.append(Scenario(
                test_id=row["test_id"].strip(),
                subject_name=row["subject_name"].strip(),
                subject_type=row["subject_type"].strip(),
                dut_path=row["dut_path"].strip(),
                http_method=row["http_method"].strip().upper(),
                expected_status=int(row["expected_status"]),
                expected_reason=row.get("expected_reason", "").strip(),
                notes=row.get("notes", "").strip(),
                via_client=row.get("via_client", "").strip(),
                via_redirect_uri=row.get("via_redirect_uri", "").strip(),
            ))
    return out


# ---------------------------------------------------------------------------
# Token fetch (delegates to keycloak/)
# ---------------------------------------------------------------------------

@dataclass
class KeycloakAccess:
    """Connection params for the Keycloak instance the validator drives."""
    base_url: str
    realm: str
    # For client_credentials grant subjects.
    default_client_secret: str = "secret"
    # For user-password grant subjects.
    default_user_password: str = "password"
    user_grant_client: str = "nmos-test-client"
    """The OAuth 2.0 client through which user/password grants are
    obtained. Matches keycloak/test_tokens.py DEFAULT_USER_CLIENT."""


def fetch_subject_token(
    subject: Scenario, access: KeycloakAccess,
) -> str | None:
    """Resolve ``subject`` to a Bearer token via keycloak/.

    Returns ``None`` if the keycloak side rejected the credentials
    (subject not provisioned, password mismatch, controller using
    auth_code only, etc.) — the scenario is then recorded as FAIL
    with a diagnostic message. ``keycloak.test_tokens`` functions
    return a ``(token, error)`` tuple; we unpack it and return the
    token string only.
    """
    try:
        if subject.subject_type == "c":
            tok, err = get_client_token(
                base_url=access.base_url, realm=access.realm,
                client_id=subject.subject_name,
                client_secret=access.default_client_secret,
            )
            if err is not None:
                logging.warning("scenario %s: client_credentials fetch "
                                "failed for %s: %s",
                                subject.test_id, subject.subject_name, err)
                return None
            return tok
        if subject.subject_type == "u":
            tok, err = get_user_token(
                base_url=access.base_url, realm=access.realm,
                username=subject.subject_name,
                password=access.default_user_password,
                client_id=access.user_grant_client,
                client_secret=access.default_client_secret,
            )
            if err is not None:
                logging.warning("scenario %s: password-grant fetch "
                                "failed for %s: %s",
                                subject.test_id, subject.subject_name, err)
                return None
            return tok
        if subject.subject_type == "a":
            # authorization_code grant: drive Keycloak's login form
            # programmatically. ``subject_name`` is the user; the
            # ``via_client`` column names the OAuth client through
            # which the user authenticates (typically a
            # ``controller-*`` client provisioned for standardFlow).
            if not subject.via_client or not subject.via_redirect_uri:
                logging.warning(
                    "scenario %s: subject_type='a' requires via_client "
                    "and via_redirect_uri columns",
                    subject.test_id,
                )
                return None
            tok, err = get_authcode_token(
                base_url=access.base_url, realm=access.realm,
                client_id=subject.via_client,
                client_secret=access.default_client_secret,
                username=subject.subject_name,
                password=access.default_user_password,
                redirect_uri=subject.via_redirect_uri,
            )
            if err is not None:
                logging.warning("scenario %s: authorization_code fetch "
                                "failed for user=%s via=%s: %s",
                                subject.test_id, subject.subject_name,
                                subject.via_client, err)
                return None
            return tok
        if subject.subject_type == "g":
            # Group rows aren't directly fetchable; they apply to all
            # subjects that are members. Scenarios should reference
            # individual subjects. We return None so the runner records
            # a clear diagnostic.
            return None
    except Exception as exc:  # pylint: disable=broad-except
        logging.warning("scenario %s: token fetch raised: %s",
                        subject.test_id, exc)
        return None
    return None


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

async def run_scenarios(
    scenarios: list[Scenario],
    *,
    dut_base_url: str,
    keycloak: KeycloakAccess,
    http_client: SecurityHttpClient,
) -> list[ScenarioResult]:
    """Execute every scenario sequentially. Returns per-row verdicts."""
    results: list[ScenarioResult] = []
    for sc in scenarios:
        token = fetch_subject_token(sc, keycloak)
        if token is None:
            results.append(ScenarioResult(
                scenario=sc, actual_status=None, passed=False,
                details=(
                    f"could not obtain a token for subject "
                    f"{sc.subject_name!r} (type {sc.subject_type!r})"
                ),
            ))
            continue

        url = f"{dut_base_url.rstrip('/')}{sc.dut_path}"
        try:
            resp = await request_with_token(
                http_client, url, method=sc.http_method, token=token,
            )
        except Exception as exc:  # pylint: disable=broad-except
            results.append(ScenarioResult(
                scenario=sc, actual_status=None, passed=False,
                details=f"HTTP request raised {type(exc).__name__}: {exc}",
            ))
            continue

        passed = resp.status == sc.expected_status
        details = f"expected HTTP {sc.expected_status}, got {resp.status}"
        if passed:
            # An expected 401/403 still has to carry the Bearer challenge.
            problem = auth_challenge_problem(
                resp.status, resp.header("WWW-Authenticate"),
                bearer_required=True,
            )
            if problem is not None:
                passed = False
                details += f", but {problem}"
        if not passed and resp.text():
            details += f"; body={resp.text()[:200]}"
        results.append(ScenarioResult(
            scenario=sc, actual_status=resp.status,
            passed=passed, details=details,
        ))
    return results


# ---------------------------------------------------------------------------
# Provisioning entry point (delegates to keycloak.nmos_keycloak)
# ---------------------------------------------------------------------------

def provision_realm_from_csv(
    grants_csv: Path,
    *,
    base_url: str,
    realm: str,
    admin_user: str,
    admin_pass: str,
) -> None:
    """Provision Keycloak with the subjects/grants in ``grants_csv``.

    Delegates to ``keycloak.nmos_keycloak`` via subprocess invocation
    rather than direct import — ``nmos_keycloak.py`` is structured as a
    CLI tool whose ``put`` command does the realm bootstrap end-to-end.
    Re-using it as a subprocess preserves the existing tested code path
    and avoids re-implementing realm/user/client setup.
    """
    import subprocess
    # Use ``test`` (not ``put``) so the bootstrap includes
    # ``nmos-test-client`` — the OAuth client our token-fetch helpers
    # (``get_client_token`` / ``get_user_token``) authenticate
    # through. Without it, every Stage 2 token request returns
    # ``invalid_client`` because the client doesn't exist in the realm.
    cmd = [
        sys.executable,
        str(_WORKSPACE_ROOT / "keycloak" / "nmos_keycloak.py"),
        "--url", base_url,
        "--admin-user", admin_user,
        "--admin-pass", admin_pass,
        "--realm", realm,
        "test",
        "--csv", str(grants_csv),
    ]
    logging.info("Provisioning Keycloak: %s", " ".join(cmd))
    subprocess.run(cmd, check=True)
