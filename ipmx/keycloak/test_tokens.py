#!/usr/bin/env python3
"""
NMOS Token Verification Script

Requests OAuth2 tokens from Keycloak for all subjects in a grants CSV,
decodes the JWT claims, and verifies they match the expected access rights.

For clients (subject_type=c): uses client_credentials grant
For users (subject_type=u): uses password grant (direct access)

Usage:
  python test_tokens.py --realm TR-10-SEC --csv TR-10-SEC_grants.csv
  python test_tokens.py --realm TR-10-SEC --csv TR-10-SEC_grants.csv --verbose
  python test_tokens.py --realm TR-10-SEC --csv TR-10-SEC_grants.csv --default-client my-client
"""

import argparse
import base64
import csv
import json
import sys
import time
from dataclasses import dataclass, field

import jwt
import requests
from jwt import PyJWKClient

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_BASE_URL = "https://XYZ-SNX00000:9443"
DEFAULT_TEST_PASSWORD = "password"
DEFAULT_TEST_SECRET = "secret"
# For authorization_code/password grant, users authenticate via a client.
# This is the default client used for user token requests.
DEFAULT_USER_CLIENT = "nmos-test-client"

# CA bundle for verifying Keycloak's TLS cert when talking HTTPS.
# Resolved relative to this script — same convention as nmos_keycloak.py.
# Override via REQUESTS_CA_BUNDLE if a different path is needed.
import os as _os
DEFAULT_CA_BUNDLE = _os.path.normpath(_os.path.join(
    _os.path.dirname(_os.path.abspath(__file__)),
    "..", "Certificates", "build.0", "ExampleRootCA.pem",
))

# Standard NMOS API scope names (must match nmos_keycloak.py)
NMOS_KNOWN_SCOPES = {
    "node", "query", "registration", "connection",
    "channelmapping", "streamcompatibility", "configuration",
    "nc", "control", "manufacturer", "register",
}

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"
WARN = "\033[93mWARN\033[0m"
BOLD = "\033[1m"
RESET = "\033[0m"

# ---------------------------------------------------------------------------
# Data model (mirrors nmos_keycloak.py)
# ---------------------------------------------------------------------------

@dataclass
class CsvRow:
    subject_name: str
    subject_type: str
    application: str
    resource_url: str
    api: str
    read: bool
    write: bool
    enabled: bool
    notes: str = ""


@dataclass
class SubjectGrants:
    subject_name: str
    subject_type: str
    realm: str
    rows: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# CSV parsing
# ---------------------------------------------------------------------------

def _split_csv_list(value):
    return [v.strip() for v in value.split(",") if v.strip()]


def _read_apis_directive(filepath):
    """Read #apis=... directive from the top of a CSV file."""
    with open(filepath, "r") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#apis="):
                return [a for a in stripped[6:].replace(",", " ").split()
                        if a]
            if stripped.startswith("#"):
                continue
            break
    return None


def parse_csv(filepath, api_list=None):
    """Parse grants CSV with support for #apis, api=*, and groups."""
    if api_list is None:
        api_list = _read_apis_directive(filepath)
    if api_list is None:
        api_list = sorted(NMOS_KNOWN_SCOPES)

    with open(filepath, "r", newline="") as f:
        data_lines = [line for line in f
                      if not line.lstrip().startswith("#")]

    raw_entries = []
    reader = csv.DictReader(data_lines)
    for raw in reader:
        name = (raw.get("subject_name") or "").strip()
        if not name:
            continue

        urls = _split_csv_list(raw.get("resource_url") or "*")
        reads = _split_csv_list(raw.get("read") or "false")
        writes = _split_csv_list(raw.get("write") or "false")

        if len(reads) == 1:
            reads = reads * len(urls)
        if len(writes) == 1:
            writes = writes * len(urls)

        if len(reads) != len(urls) or len(writes) != len(urls):
            continue

        raw_entries.append({
            "subject_name": name,
            "subject_type": (raw.get("subject_type") or "c").strip().lower(),
            "application": (raw.get("application") or "").strip(),
            "api": (raw.get("api") or "").strip(),
            "urls": urls,
            "reads": reads,
            "writes": writes,
            "enabled": (raw.get("enabled") or "").strip().lower() == "true",
            "notes": (raw.get("notes") or "").strip(),
        })

    # Separate groups from subjects
    group_entries = [e for e in raw_entries if e["subject_type"] == "g"]
    subject_entries = [e for e in raw_entries if e["subject_type"] != "g"]

    # Expand groups (with api=*)
    groups = {}
    for entry in group_entries:
        gname = entry["subject_name"]
        apis = list(api_list) if entry["api"] == "*" else [entry["api"]]
        for api_name in apis:
            for url, rd, wr in zip(entry["urls"], entry["reads"],
                                   entry["writes"]):
                groups.setdefault(gname, []).append(CsvRow(
                    subject_name=gname, subject_type="g",
                    application=entry["application"],
                    resource_url=url, api=api_name,
                    read=rd.lower() == "true",
                    write=wr.lower() == "true",
                    enabled=entry["enabled"], notes=entry["notes"],
                ))

    # Explicit API override logic (exclude group references)
    explicit_apis = {}
    for entry in subject_entries:
        is_group_ref = (len(entry["urls"]) == 1
                        and entry["urls"][0].startswith("@"))
        if entry["api"] != "*" and not is_group_ref:
            key = (entry["subject_name"], entry["subject_type"],
                   entry["application"])
            explicit_apis.setdefault(key, set()).add(entry["api"])

    # Expand subjects
    rows = []
    for entry in subject_entries:
        urls = entry["urls"]

        # Group reference: read/write gate the group's grants
        if len(urls) == 1 and urls[0].startswith("@"):
            group_name = urls[0][1:]
            if group_name not in groups:
                continue
            ref_read = entry["reads"][0].lower() == "true"
            ref_write = entry["writes"][0].lower() == "true"
            for grow in groups[group_name]:
                rows.append(CsvRow(
                    subject_name=entry["subject_name"],
                    subject_type=entry["subject_type"],
                    application=entry["application"],
                    resource_url=grow.resource_url,
                    api=grow.api,
                    read=grow.read and ref_read,
                    write=grow.write and ref_write,
                    enabled=entry["enabled"] and grow.enabled,
                    notes=entry["notes"] or grow.notes,
                ))
            continue

        # Normal expansion
        if entry["api"] == "*":
            key = (entry["subject_name"], entry["subject_type"],
                   entry["application"])
            overridden = explicit_apis.get(key, set())
            apis = [a for a in api_list if a not in overridden]
        else:
            apis = [entry["api"]]

        for api_name in apis:
            for url, rd, wr in zip(urls, entry["reads"],
                                   entry["writes"]):
                rows.append(CsvRow(
                    subject_name=entry["subject_name"],
                    subject_type=entry["subject_type"],
                    application=entry["application"],
                    resource_url=url, api=api_name,
                    read=rd.lower() == "true",
                    write=wr.lower() == "true",
                    enabled=entry["enabled"], notes=entry["notes"],
                ))

    return rows


def group_by_subject(rows):
    groups = {}
    for r in rows:
        key = (r.subject_name, r.subject_type, r.application)
        if key not in groups:
            groups[key] = SubjectGrants(
                subject_name=r.subject_name,
                subject_type=r.subject_type,
                realm=r.application,
            )
        groups[key].rows.append(r)
    return list(groups.values())


# ---------------------------------------------------------------------------
# Expected claims builder (same logic as nmos_keycloak.py)
# ---------------------------------------------------------------------------

def build_expected_claims(sg):
    """Build expected token claims from enabled CSV rows."""
    enabled = [r for r in sg.rows if r.enabled]

    scopes = sorted({r.api for r in enabled if r.read or r.write})

    resource_urls = {r.resource_url for r in enabled if r.read or r.write}
    specific_urls = sorted(resource_urls - {"*"})
    if "*" in resource_urls:
        aud = ["*"] + specific_urls
    else:
        aud = specific_urls

    apis = {}
    for r in enabled:
        if r.api not in apis:
            apis[r.api] = []
        apis[r.api].append(r)

    ext = {}
    for api_name, api_rows in apis.items():
        claim = {}

        wildcard_read = any(r.read for r in api_rows if r.resource_url == "*")
        wildcard_write = any(r.write for r in api_rows if r.resource_url == "*")

        if wildcard_read:
            claim["read"] = ["*"]
        else:
            read_indices = []
            for r in api_rows:
                if r.read and r.resource_url in aud:
                    read_indices.append(aud.index(r.resource_url))
            if read_indices:
                claim["read"] = sorted(set(read_indices))

        if wildcard_write:
            claim["write"] = ["*"]
        else:
            write_indices = []
            for r in api_rows:
                if r.write and r.resource_url in aud:
                    write_indices.append(aud.index(r.resource_url))
            if write_indices:
                claim["write"] = sorted(set(write_indices))

        if claim:
            ext[f"x-nmos-{api_name}"] = claim

    return {
        "scope": scopes,
        "aud": aud,
        "ext": ext,
    }


# ---------------------------------------------------------------------------
# JWT verification (signature, exp, iss via JWKS)
# ---------------------------------------------------------------------------

def fetch_jwks_client(base_url, realm):
    """Create a PyJWKClient that fetches keys from the realm's JWKS endpoint."""
    jwks_url = f"{base_url}/realms/{realm}/protocol/openid-connect/certs"
    return PyJWKClient(jwks_url)


def decode_jwt_header(token_str):
    """Decode the header of a JWT (unverified, for display/kid lookup)."""
    return jwt.get_unverified_header(token_str)


def verify_and_decode(token_str, jwks_client, expected_issuer,
                      expected_aud=None):
    """
    Verify JWT signature using JWKS and validate exp/iss/aud.

    Returns (header, claims, verification_checks) where verification_checks
    is a list of (name, passed, detail) tuples for the cryptographic checks.
    """
    checks = []
    header = decode_jwt_header(token_str)

    # 1. Match kid from header to a key in the JWKS
    kid = header.get("kid")
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token_str)
        checks.append((
            "kid found in JWKS",
            True,
            f"kid={kid} alg={header.get('alg')}",
        ))
    except jwt.exceptions.PyJWKClientError as e:
        checks.append(("kid found in JWKS", False, f"kid={kid} error={e}"))
        return header, None, checks

    # 2. Verify signature + exp + iss
    #    We disable aud verification here — NMOS aud semantics (resource URLs,
    #    wildcards) don't match PyJWT's built-in aud check. We verify aud
    #    separately in verify_token_claims.
    try:
        claims = jwt.decode(
            token_str,
            signing_key.key,
            algorithms=[header.get("alg", "RS256")],
            issuer=expected_issuer,
            options={
                "verify_aud": False,
                "verify_exp": True,
                "verify_iss": True,
            },
        )
        checks.append((
            f"signature valid ({header.get('alg', 'RS256')})",
            True,
            f"kid={kid}",
        ))
    except jwt.exceptions.InvalidSignatureError:
        checks.append((f"signature valid ({header.get('alg', 'RS256')})", False, "signature mismatch"))
        return header, None, checks
    except jwt.exceptions.ExpiredSignatureError:
        checks.append((f"signature valid ({header.get('alg', 'RS256')})", True, f"kid={kid}"))
        checks.append(("token not expired", False,
                        "exp is in the past"))
        # Still decode for claim inspection
        claims = jwt.decode(
            token_str, signing_key.key,
            algorithms=[header.get("alg", "RS256")],
            options={"verify_exp": False, "verify_iss": False,
                     "verify_aud": False},
        )
        return header, claims, checks
    except jwt.exceptions.InvalidIssuerError:
        checks.append((f"signature valid ({header.get('alg', 'RS256')})", True, f"kid={kid}"))
        claims = jwt.decode(
            token_str, signing_key.key,
            algorithms=[header.get("alg", "RS256")],
            options={"verify_exp": False, "verify_iss": False,
                     "verify_aud": False},
        )
        checks.append(("issuer matches", False,
                        f"expected={expected_issuer} actual={claims.get('iss')}"))
        return header, claims, checks
    except jwt.exceptions.DecodeError as e:
        checks.append((f"signature valid ({header.get('alg', 'RS256')})", False, str(e)))
        return header, None, checks

    # 3. Explicit exp check (passed via jwt.decode, but report it)
    exp = claims.get("exp", 0)
    now = int(time.time())
    checks.append((
        "token not expired",
        exp > now,
        f"exp={exp} now={now} remaining={exp - now}s",
    ))

    # 4. Explicit iss check (passed via jwt.decode, but report it)
    actual_iss = claims.get("iss", "")
    checks.append((
        "issuer matches",
        actual_iss == expected_issuer,
        f"expected={expected_issuer} actual={actual_iss}",
    ))

    return header, claims, checks


# ---------------------------------------------------------------------------
# Token acquisition
# ---------------------------------------------------------------------------

def get_client_token(base_url, realm, client_id, client_secret):
    """Get an access token using client_credentials grant."""
    url = f"{base_url}/realms/{realm}/protocol/openid-connect/token"
    resp = requests.post(url, data={
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    })
    if resp.status_code != 200:
        return None, f"HTTP {resp.status_code}: {resp.text[:200]}"
    return resp.json().get("access_token"), None


def get_user_token(base_url, realm, username, password,
                   client_id, client_secret):
    """Get an access token using password grant (direct access)."""
    url = f"{base_url}/realms/{realm}/protocol/openid-connect/token"
    resp = requests.post(url, data={
        "grant_type": "password",
        "client_id": client_id,
        "client_secret": client_secret,
        "username": username,
        "password": password,
    })
    if resp.status_code != 200:
        return None, f"HTTP {resp.status_code}: {resp.text[:200]}"
    return resp.json().get("access_token"), None


def get_authcode_token(
    base_url, realm, client_id, client_secret,
    username, password, redirect_uri, scope="openid",
):
    """Drive Keycloak's authorization_code grant programmatically.

    Mimics the browser flow without an actual browser:

      1. GET ``/protocol/openid-connect/auth`` with ``response_type=code``
         → Keycloak returns the login-form HTML.
      2. Parse the form's ``action`` URL (carries Keycloak's session_code
         + execution + tab_id) out of the HTML.
      3. POST ``username`` + ``password`` to that action URL — Keycloak
         responds with a 302 redirect to ``redirect_uri?code=...&state=...``.
      4. Extract the ``code`` from the redirect's ``Location`` header.
      5. POST to ``/protocol/openid-connect/token`` with ``grant_type=
         authorization_code`` + ``code`` + ``redirect_uri`` to swap the
         code for an access token.

    The ``redirect_uri`` MUST match (modulo trailing wildcard) one of
    the client's registered ``redirectUris`` in Keycloak. For the
    project's ``controller-*`` clients, valid prefixes are configured
    in ``nmos_keycloak.py::_controller_redirect_uris``.

    Returns ``(access_token, None)`` on success or ``(None, error)``
    on any step's failure. The flow is opaque to callers — every step
    just produces a token string identical to one obtained via a real
    browser login.
    """
    import re
    import html as html_unescape
    from urllib.parse import urlparse, parse_qs

    session = requests.Session()

    # Step 1: GET the login page.
    auth_url = f"{base_url}/realms/{realm}/protocol/openid-connect/auth"
    auth_params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": "validator-state",
    }
    try:
        r1 = session.get(auth_url, params=auth_params,
                         allow_redirects=False, timeout=10)
    except requests.RequestException as exc:
        return None, f"auth GET failed: {exc}"
    if r1.status_code != 200:
        return None, f"auth GET → HTTP {r1.status_code}: {r1.text[:200]}"

    # Step 2: extract the form action URL. Keycloak's standard
    # rendering wraps the URL in <form id="kc-form-login" action="...">.
    m = re.search(r'<form[^>]+id="kc-form-login"[^>]+action="([^"]+)"',
                  r1.text)
    if not m:
        return None, "could not find login-form action in Keycloak response"
    form_action = html_unescape.unescape(m.group(1))

    # Step 3: POST credentials. We use allow_redirects=False so we can
    # observe the 302 + capture the code from the Location header.
    try:
        r2 = session.post(
            form_action,
            data={
                "username": username,
                "password": password,
                "credentialId": "",
            },
            allow_redirects=False, timeout=10,
        )
    except requests.RequestException as exc:
        return None, f"login POST failed: {exc}"
    if r2.status_code not in (302, 303):
        return None, (f"login POST expected 302, got {r2.status_code}: "
                      f"{r2.text[:200]}")
    location = r2.headers.get("Location", "")
    if not location:
        return None, "login POST 302 had no Location header"

    # Step 4: extract the auth code from the redirect URL's query string.
    parsed = urlparse(location)
    qs = parse_qs(parsed.query)
    code = qs.get("code", [None])[0]
    if not code:
        err = qs.get("error", [None])[0]
        desc = qs.get("error_description", [""])[0]
        return None, (f"redirect missing code "
                      f"(error={err!r} desc={desc!r})")

    # Step 5: exchange the code for an access token.
    token_url = f"{base_url}/realms/{realm}/protocol/openid-connect/token"
    try:
        r3 = session.post(
            token_url,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
            },
            timeout=10,
        )
    except requests.RequestException as exc:
        return None, f"token POST failed: {exc}"
    if r3.status_code != 200:
        return None, (f"token POST → HTTP {r3.status_code}: "
                      f"{r3.text[:200]}")
    return r3.json().get("access_token"), None


# ---------------------------------------------------------------------------
# Verification logic
# ---------------------------------------------------------------------------

class VerificationResult:
    def __init__(self, subject_name, subject_type):
        self.subject_name = subject_name
        self.subject_type = subject_type
        self.checks = []  # list of (name, passed, detail)
        self.token_error = None
        self.raw_claims = None

    def add(self, name, passed, detail=""):
        self.checks.append((name, passed, detail))

    @property
    def passed(self):
        return all(p for _, p, _ in self.checks) and not self.token_error

    @property
    def total(self):
        return len(self.checks)

    @property
    def pass_count(self):
        return sum(1 for _, p, _ in self.checks if p)


def verify_token_claims(header, claims, expected, sg):
    """
    Verify actual JWT claims against expected claims from CSV.
    Returns a VerificationResult.
    """
    result = VerificationResult(sg.subject_name, sg.subject_type)
    result.raw_claims = claims

    # 1. Check required standard claims exist
    for req in ["iss", "sub", "exp"]:
        result.add(
            f"claim '{req}' present",
            req in claims,
            f"found={req in claims}",
        )
    # client_id MUST be present per NMOS spec
    result.add(
        "claim 'client_id' present",
        "client_id" in claims,
        f"client_id={claims.get('client_id')}",
    )

    # 2. Check sub vs client_id relationship (NMOS spec requirement)
    #    client_credentials: sub MUST equal client_id
    #    authorization_code/password: sub MUST NOT equal client_id
    if sg.subject_type == "c":
        sub_val = claims.get("sub", "")
        cid_val = claims.get("client_id", "")
        result.add(
            "sub == client_id (client_credentials, per NMOS spec)",
            sub_val == cid_val and cid_val == sg.subject_name,
            f"sub={sub_val} client_id={cid_val} expected={sg.subject_name}",
        )
    else:
        sub_val = claims.get("sub")
        # For user tokens, client_id may be absent (Keycloak uses azp)
        cid_val = claims.get("client_id") or claims.get("azp")
        sub_neq = sub_val != cid_val
        result.add(
            "sub != client_id (user grant, per NMOS spec)",
            sub_neq,
            f"sub={sub_val} client_id/azp={cid_val}",
        )

    # 3. Check scope claim
    actual_scope_str = claims.get("scope", "")
    actual_scopes = set(actual_scope_str.split()) if actual_scope_str else set()
    expected_scopes = set(expected["scope"])

    # Check all expected scopes are present
    missing_scopes = expected_scopes - actual_scopes
    result.add(
        "expected scopes present",
        len(missing_scopes) == 0,
        f"expected={sorted(expected_scopes)} actual={sorted(actual_scopes)}"
        + (f" missing={sorted(missing_scopes)}" if missing_scopes else ""),
    )

    # 4. Check aud claim
    #    Keycloak may add default audiences (e.g. "account"), so we check
    #    that all expected aud values are present (subset check).
    actual_aud = claims.get("aud", [])
    if isinstance(actual_aud, str):
        actual_aud = [actual_aud]
    expected_aud = expected["aud"]

    missing_aud = set(expected_aud) - set(actual_aud)
    extra_aud = set(actual_aud) - set(expected_aud)
    result.add(
        "expected audience entries present",
        len(missing_aud) == 0,
        f"expected={expected_aud} actual={actual_aud}"
        + (f" missing={sorted(missing_aud)}" if missing_aud else "")
        + (f" extra={sorted(extra_aud)}" if extra_aud else ""),
    )

    # 5. Check ext claim and x-nmos-* claims
    actual_ext = claims.get("ext", {})
    expected_ext = expected.get("ext", {})

    for claim_name, expected_val in sorted(expected_ext.items()):
        # Check in ext (private claims SHOULD reside in ext per spec)
        actual_val = actual_ext.get(claim_name, {})
        ext_match = _compare_nmos_claim(expected_val, actual_val)
        result.add(
            f"ext.{claim_name}",
            ext_match,
            f"expected={expected_val} actual={actual_val}",
        )

    # 6. Check no unexpected x-nmos-* claims in ext
    unexpected = set(actual_ext.keys()) - set(expected_ext.keys())
    unexpected_nmos = {k for k in unexpected if k.startswith("x-nmos-")}
    result.add(
        "no unexpected x-nmos-* in ext",
        len(unexpected_nmos) == 0,
        f"unexpected={sorted(unexpected_nmos)}" if unexpected_nmos else "",
    )

    # 7. Check token type (NMOS spec requires typ=JWT per RFC 7515)
    #    typ is a JOSE header parameter, not a payload claim
    result.add(
        "token type is JWT",
        header.get("typ") == "JWT",
        f"typ={header.get('typ')}",
    )

    # 8. Check token is not expired (iat is ignored per spec; use exp only)
    exp = claims.get("exp", 0)
    now = int(time.time())
    if exp:
        remaining = exp - now
        result.add(
            "token not expired (exp check)",
            remaining > 0,
            f"exp={exp} now={now} remaining={remaining}s ({remaining/3600:.1f}h)",
        )

    return result


def _compare_nmos_claim(expected, actual):
    """Compare an x-nmos-* claim (read/write arrays)."""
    if not actual and not expected:
        return True
    if not actual or not expected:
        return False

    for key in ("read", "write"):
        exp_val = expected.get(key)
        act_val = actual.get(key)

        if exp_val is None and act_val is None:
            continue
        if exp_val is None or act_val is None:
            return False

        # Normalize to comparable form
        exp_set = _normalize_rw(exp_val)
        act_set = _normalize_rw(act_val)
        if exp_set != act_set:
            return False

    return True


def _normalize_rw(val):
    """Normalize a read/write array value for comparison."""
    if isinstance(val, list):
        return tuple(sorted(str(v) for v in val))
    return (str(val),)


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def print_token_details(result, verbose=False):
    """Print verification results for one subject."""
    status = PASS if result.passed else FAIL
    stype = "client" if result.subject_type == "c" else "user"
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{status} {BOLD}{result.subject_name}{RESET} ({stype}) "
          f"[{result.pass_count}/{result.total} checks passed]")
    print(f"{'='*60}")

    if result.token_error:
        print(f"  {FAIL} Token request failed: {result.token_error}")
        return

    if verbose and result.raw_claims:
        print(f"\n  {BOLD}Raw JWT Claims:{RESET}")
        for key in sorted(result.raw_claims.keys()):
            val = result.raw_claims[key]
            print(f"    {key}: {json.dumps(val) if isinstance(val, (dict, list)) else val}")

    print(f"\n  {BOLD}Verification Checks:{RESET}")
    for name, passed, detail in result.checks:
        icon = PASS if passed else FAIL
        line = f"  {icon} {name}"
        if detail and (verbose or not passed):
            line += f" — {detail}"
        print(line)


def print_summary(results):
    """Print overall summary."""
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}SUMMARY: {passed}/{total} subjects passed{RESET}")
    if failed:
        print(f"  {FAIL} Failed subjects:")
        for r in results:
            if not r.passed:
                print(f"    - {r.subject_name} ({r.subject_type})")
    print(f"{'='*60}")

    return 0 if failed == 0 else 1


# ---------------------------------------------------------------------------
# Dump mode
# ---------------------------------------------------------------------------

def dump_tokens(args, active_subjects):
    """Request tokens for all subjects and print as formatted JSON."""
    output = []
    for sg in active_subjects:
        entry = {
            "subject": sg.subject_name,
            "type": "client" if sg.subject_type == "c" else "user",
        }

        if sg.subject_type == "c":
            token_str, err = get_client_token(
                args.url, sg.realm,
                sg.subject_name, args.default_secret,
            )
        elif sg.subject_type == "u":
            token_str, err = get_user_token(
                args.url, sg.realm,
                sg.subject_name, args.default_password,
                args.default_client, args.default_client_secret,
            )
        else:
            token_str, err = None, f"Unknown type '{sg.subject_type}'"

        if err:
            entry["error"] = err
        elif not token_str:
            entry["error"] = "No access_token in response"
        else:
            header = decode_jwt_header(token_str)
            claims = jwt.decode(
                token_str, options={"verify_signature": False},
            )
            entry["header"] = header
            entry["claims"] = claims

        output.append(entry)

    print(json.dumps(output, indent=2, default=str))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="NMOS Token Verification — requests tokens and verifies "
                    "claims match CSV grants",
    )
    parser.add_argument(
        "--url", default=DEFAULT_BASE_URL,
        help=f"Keycloak base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--realm", required=True,
        help="Keycloak realm name",
    )
    parser.add_argument(
        "--csv", required=True,
        help="Grants CSV file (same format as nmos_keycloak.py)",
    )
    parser.add_argument(
        "--default-password", default=DEFAULT_TEST_PASSWORD,
        help=f"Password for user token requests (default: {DEFAULT_TEST_PASSWORD})",
    )
    parser.add_argument(
        "--default-secret", default=DEFAULT_TEST_SECRET,
        help=f"Secret for client token requests (default: {DEFAULT_TEST_SECRET})",
    )
    parser.add_argument(
        "--default-client", default=DEFAULT_USER_CLIENT,
        help=f"Client ID used for user (password grant) token requests "
             f"(default: {DEFAULT_USER_CLIENT})",
    )
    parser.add_argument(
        "--default-client-secret", default=DEFAULT_TEST_SECRET,
        help=f"Secret for the user-facing client (default: {DEFAULT_TEST_SECRET})",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show full token claims and all check details",
    )
    parser.add_argument(
        "--dump", action="store_true",
        help="Dump all tokens as formatted JSON (skip verification)",
    )
    parser.add_argument(
        "--apis",
        help="Comma-separated NMOS APIs that api=* expands to "
             "(overrides #apis directive in CSV)",
    )
    args = parser.parse_args()

    # Parse --apis into a list
    args.api_list = None
    if args.apis:
        args.api_list = [a.strip() for a in args.apis.split(",")
                         if a.strip()]

    # When the URL is HTTPS, point both `requests` and `urllib` at the
    # Matrox root CA so the JWKS fetch (PyJWKClient via urllib) and
    # token requests (requests) both verify Keycloak's cert. Avoids
    # adding a new --ca-bundle CLI flag — env-var override still works
    # via the standard REQUESTS_CA_BUNDLE / SSL_CERT_FILE.
    if args.url.startswith("https://") and _os.path.isfile(DEFAULT_CA_BUNDLE):
        _os.environ.setdefault("REQUESTS_CA_BUNDLE", DEFAULT_CA_BUNDLE)
        _os.environ.setdefault("SSL_CERT_FILE", DEFAULT_CA_BUNDLE)

    # Parse CSV
    print(f"Reading {args.csv} ...")
    rows = parse_csv(args.csv, api_list=args.api_list)
    subjects = group_by_subject(rows)

    # Filter to enabled-only subjects (skip subjects with ALL rows disabled)
    active_subjects = [
        sg for sg in subjects
        if any(r.enabled for r in sg.rows)
    ]

    if not active_subjects:
        print("No active subjects found in CSV.")
        sys.exit(0)

    print(f"Found {len(active_subjects)} active subjects "
          f"({len(subjects) - len(active_subjects)} fully disabled, skipped)")

    # Verify connectivity
    print(f"\nConnecting to {args.url} ...")
    try:
        resp = requests.get(
            f"{args.url}/realms/{args.realm}/.well-known/openid-configuration"
        )
        if resp.status_code != 200:
            print(f"ERROR: Realm '{args.realm}' not reachable "
                  f"(HTTP {resp.status_code})")
            sys.exit(1)
        print(f"Realm '{args.realm}' is reachable.")
    except requests.ConnectionError:
        print(f"ERROR: Cannot connect to {args.url}. Is Keycloak running?")
        sys.exit(1)

    # Dump mode: request all tokens and output as JSON, then exit
    if args.dump:
        dump_tokens(args, active_subjects)
        sys.exit(0)

    # Fetch JWKS for signature verification
    expected_issuer = f"{args.url}/realms/{args.realm}"
    print(f"Fetching JWKS from {expected_issuer} ...")
    jwks_client = fetch_jwks_client(args.url, args.realm)

    # Request tokens and verify
    results = []
    for sg in active_subjects:
        expected = build_expected_claims(sg)

        if sg.subject_type == "c":
            # Client credentials grant
            token_str, err = get_client_token(
                args.url, sg.realm,
                sg.subject_name, args.default_secret,
            )
        elif sg.subject_type == "u":
            # Password grant (direct access)
            token_str, err = get_user_token(
                args.url, sg.realm,
                sg.subject_name, args.default_password,
                args.default_client, args.default_client_secret,
            )
        else:
            err = f"Unknown subject_type '{sg.subject_type}'"
            token_str = None

        result = VerificationResult(sg.subject_name, sg.subject_type)

        if err:
            result.token_error = err
            results.append(result)
            print_token_details(result, args.verbose)
            continue

        if not token_str:
            result.token_error = "No access_token in response"
            results.append(result)
            print_token_details(result, args.verbose)
            continue

        # Verify signature, exp, iss via JWKS (as an NMOS device would)
        try:
            header, claims, crypto_checks = verify_and_decode(
                token_str, jwks_client, expected_issuer,
            )
        except Exception as e:
            result.token_error = f"JWT verification error: {e}"
            results.append(result)
            print_token_details(result, args.verbose)
            continue

        if args.verbose:
            print(f"\n  JWT Header: alg={header.get('alg')} "
                  f"typ={header.get('typ')} kid={header.get('kid', 'N/A')}")

        if claims is None:
            # Signature/decode failed — report crypto checks only
            for name, passed, detail in crypto_checks:
                result.add(name, passed, detail)
            results.append(result)
            print_token_details(result, args.verbose)
            continue

        # Verify claims (crypto checks + NMOS claim checks)
        result = verify_token_claims(header, claims, expected, sg)
        # Prepend crypto checks before the claim checks
        result.checks = crypto_checks + result.checks
        result.raw_claims = claims
        results.append(result)
        print_token_details(result, args.verbose)

    # Summary
    exit_code = print_summary(results)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
