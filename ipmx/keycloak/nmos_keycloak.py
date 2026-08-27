#!/usr/bin/env python3
"""
NMOS Keycloak Grant Manager

Manages NMOS OAuth2.0 grants in Keycloak via the Admin REST API.
Grants are defined in a CSV file and mapped to Keycloak client scopes,
audience claims, and x-nmos-* private claims per the NMOS With OAuth2.0 spec.

Commands:
  init   - Bootstrap a fresh realm: create the realm if missing, set
           access-token lifespan + user-profile policy, create the
           four NMOS API client-scopes (channelmapping, connection,
           node, streamcompatibility), optionally configure the
           signing algorithm. NO users, NO clients, NO grants — use
           this when you want to manage subjects by hand and only
           need the realm scaffolding in place. Does not require a
           CSV.
  get    - Export current grants from Keycloak to CSV
  put    - Replace all grants for subjects in CSV (realm must exist)
  update - Merge CSV grants with existing Keycloak config
  test   - Create test users/clients from CSV, then apply grants
           (does the full bootstrap end-to-end)

Usage:
  python nmos_keycloak.py init   --realm TR-10-SEC
  python nmos_keycloak.py get    --realm TR-10-SEC --csv grants_export.csv
  python nmos_keycloak.py put    --realm TR-10-SEC --csv TR-10-SEC_grants.csv
  python nmos_keycloak.py update --realm TR-10-SEC --csv TR-10-SEC_grants.csv
  python nmos_keycloak.py test   --realm TR-10-SEC --csv TR-10-SEC_grants.csv
"""

import argparse
import csv
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Keycloak now runs over HTTPS using the SNX00000 server cert. The SAN
# includes both ``XYZ-SNX00000`` and ``XYZ-SNX00000.local``; we use the
# bare form because /etc/hosts entries are populated for it.
DEFAULT_BASE_URL = "https://XYZ-SNX00000:9443"
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASS = "admin"
DEFAULT_TEST_PASSWORD = "password"
DEFAULT_TEST_SECRET = "secret"
TEST_USER_CLIENT = "nmos-test-client"

# CA bundle for verifying Keycloak's TLS cert. Resolved relative to the
# script location so we don't need a new CLI option (per the
# "ask before adding new CLI flags" feedback). Override via the
# standard ``REQUESTS_CA_BUNDLE`` env var if a different path is needed.
DEFAULT_CA_BUNDLE = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "Certificates", "build.0", "ExampleRootCA.pem",
))

NMOS_CLAIMS_SCOPE = "nmos-claims"

# Default Keycloak scopes that bloat tokens with non-NMOS claims.
# Removing these strips: email, email_verified, given_name, family_name,
# name, preferred_username, realm_access, resource_access, "account" aud,
# allowed-origins, acr.
UNWANTED_DEFAULT_SCOPES = {"email", "profile", "roles", "web-origins", "acr"}

# Standard NMOS API scope names (created as client scopes in Keycloak)
NMOS_KNOWN_SCOPES = {
    "node", "query", "registration", "connection",
    "channelmapping", "streamcompatibility", "configuration",
    "nc", "control", "manufacturer", "register",
}

# NMOS-allowed signing algorithms and their Keycloak key provider config.
# Per spec: RS256, RS512, ES256 (P-256), ES512 (P-521).
NMOS_ALGORITHM_PROVIDERS = {
    "RS256": {
        "providerId": "rsa-generated",
        "config": {
            "priority": ["200"],
            "enabled": ["true"],
            "active": ["true"],
            "keySize": ["2048"],
            "algorithm": ["RS256"],
        },
    },
    "RS512": {
        "providerId": "rsa-generated",
        "config": {
            "priority": ["200"],
            "enabled": ["true"],
            "active": ["true"],
            "keySize": ["4096"],
            "algorithm": ["RS512"],
        },
    },
    "ES256": {
        "providerId": "ecdsa-generated",
        "config": {
            "priority": ["200"],
            "enabled": ["true"],
            "active": ["true"],
            "ecdsaEllipticCurveKey": ["P-256"],
        },
    },
    "ES512": {
        "providerId": "ecdsa-generated",
        "config": {
            "priority": ["200"],
            "enabled": ["true"],
            "active": ["true"],
            "ecdsaEllipticCurveKey": ["P-521"],
        },
    },
}

# ---------------------------------------------------------------------------
# Mapper strategy (Keycloak 26+ removed script-based mappers)
#
# We use oidc-usermodel-attribute-mapper with jsonType.label=JSON to map
# user attributes containing JSON directly into token claims. The x-nmos-*
# private claims reside inside the "ext" claim as per spec (SHOULD).
# Audience is handled via oidc-audience-mapper instances.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class CsvRow:
    subject_name: str
    subject_type: str  # "u" (user) or "c" (client)
    application: str   # realm name
    resource_url: str  # "*" or a URL
    api: str           # e.g. "node", "connection"
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


@dataclass
class GroupDef:
    """A CSV group definition (subject_type=g) for Keycloak group sync."""
    name: str
    device_urls: list       # unique device URLs in this group
    members: set = field(default_factory=set)  # subject names referencing this group


# ---------------------------------------------------------------------------
# CSV parsing
# ---------------------------------------------------------------------------

def _split_csv_list(value):
    """Split a comma-separated CSV field into a list of stripped strings."""
    return [v.strip() for v in value.split(",") if v.strip()]


def _read_apis_directive(filepath):
    """Read #apis=... directive from the top of a CSV file.

    Lines starting with # before the CSV header are treated as directives.
    Returns the list of API names, or None if no directive found.
    """
    with open(filepath, "r") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#apis="):
                # Replace commas with spaces so spreadsheet-added CSV
                # separators (trailing ,,,,) are handled cleanly.
                return [a for a in stripped[6:].replace(",", " ").split()
                        if a]
            if stripped.startswith("#"):
                continue  # other comment lines
            break  # non-comment, non-empty = CSV header
    return None


def parse_csv(filepath, api_list=None):
    """Parse grants CSV into a list of CsvRow objects.

    Supports:
    - #apis=... directive at top of CSV defining what api=* expands to
    - api_list parameter (from --apis CLI) overrides the directive
    - api=* in the api column expands to all APIs in the list
    - Compact multi-valued rows (resource_url, read/write comma-separated)
    - Explicit API rows override wildcard-expanded rows for the same subject
    - Groups (subject_type=g): define reusable grant templates
    - @group-name in resource_url: copies the group's grants to the subject

    Falls back to NMOS_KNOWN_SCOPES if neither directive nor api_list given.
    """
    # Determine the API list for wildcard expansion
    if api_list is None:
        api_list = _read_apis_directive(filepath)
    if api_list is None:
        api_list = sorted(NMOS_KNOWN_SCOPES)

    # Read file, filtering out comment lines
    with open(filepath, "r", newline="") as f:
        data_lines = [line for line in f
                      if not line.lstrip().startswith("#")]

    # First pass: parse raw entries (before api/group expansion)
    raw_entries = []
    reader = csv.DictReader(data_lines)
    for raw in reader:
        name = (raw.get("subject_name") or "").strip()
        if not name:
            continue  # skip blank separator rows

        urls = _split_csv_list(raw.get("resource_url") or "*")
        reads = _split_csv_list(raw.get("read") or "false")
        writes = _split_csv_list(raw.get("write") or "false")

        # Expand single values to match url count
        if len(reads) == 1:
            reads = reads * len(urls)
        if len(writes) == 1:
            writes = writes * len(urls)

        if len(reads) != len(urls) or len(writes) != len(urls):
            api_field = (raw.get("api") or "").strip()
            print(f"  WARNING: read/write count mismatch for "
                  f"'{name}' api='{api_field}' "
                  f"({len(urls)} urls, {len(reads)} reads, "
                  f"{len(writes)} writes) — skipping row")
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

    # Separate group definitions from subject entries
    group_entries = [e for e in raw_entries if e["subject_type"] == "g"]
    subject_entries = [e for e in raw_entries if e["subject_type"] != "g"]

    # Report wildcard expansion
    has_wildcard = any(e["api"] == "*" for e in raw_entries)
    if has_wildcard:
        print(f"  api=* expands to: {', '.join(api_list)}")

    # Expand group entries into CsvRow objects (with api=* expansion)
    groups = {}  # group_name -> [CsvRow, ...]
    for entry in group_entries:
        gname = entry["subject_name"]
        if entry["api"] == "*":
            apis = list(api_list)
        else:
            apis = [entry["api"]]
        for api_name in apis:
            for url, rd, wr in zip(entry["urls"], entry["reads"],
                                   entry["writes"]):
                groups.setdefault(gname, []).append(CsvRow(
                    subject_name=gname,
                    subject_type="g",
                    application=entry["application"],
                    resource_url=url,
                    api=api_name,
                    read=rd.lower() == "true",
                    write=wr.lower() == "true",
                    enabled=entry["enabled"],
                    notes=entry["notes"],
                ))

    # Build GroupDef objects for Keycloak group sync
    group_defs = {}
    for gname, grows in groups.items():
        device_urls = sorted(set(r.resource_url for r in grows))
        group_defs[gname] = GroupDef(name=gname, device_urls=device_urls)

    if groups:
        for gname, grows in sorted(groups.items()):
            apis = sorted(set(r.api for r in grows))
            print(f"  group '{gname}': {len(group_defs[gname].device_urls)}"
                  f" devices, {len(apis)} APIs, {len(grows)} grants")

    # Find which APIs are explicitly specified per subject (override logic)
    # Explicit API rows take precedence over wildcard-expanded rows.
    # Group references (@name) are excluded from this check.
    explicit_apis = {}
    for entry in subject_entries:
        is_group_ref = (len(entry["urls"]) == 1
                        and entry["urls"][0].startswith("@"))
        if entry["api"] != "*" and not is_group_ref:
            key = (entry["subject_name"], entry["subject_type"],
                   entry["application"])
            explicit_apis.setdefault(key, set()).add(entry["api"])

    # Expand subject entries into CsvRow objects
    rows = []
    for entry in subject_entries:
        urls = entry["urls"]

        # Group reference: @group-name copies the group's grants.
        # The reference row's read/write act as gates on the group's
        # grants, and enabled controls whether this reference is active.
        if len(urls) == 1 and urls[0].startswith("@"):
            group_name = urls[0][1:]
            if group_name not in groups:
                print(f"  WARNING: group '{group_name}' not found, "
                      f"referenced by '{entry['subject_name']}' — skipping")
                continue
            # Track membership for Keycloak group sync
            if group_name in group_defs:
                group_defs[group_name].members.add(entry["subject_name"])
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

        # Normal expansion (api=* + multi-valued)
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
                    resource_url=url,
                    api=api_name,
                    read=rd.lower() == "true",
                    write=wr.lower() == "true",
                    enabled=entry["enabled"],
                    notes=entry["notes"],
                ))

    return rows, group_defs


def group_by_subject(rows):
    """Group CsvRow list into SubjectGrants keyed by (name, type, realm)."""
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


def write_csv(filepath, subjects):
    """Write SubjectGrants list to a CSV file."""
    fieldnames = [
        "subject_name", "subject_type", "application",
        "resource_url", "api", "read", "write", "enabled", "notes",
    ]
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        first = True
        for sg in subjects:
            if not first:
                writer.writerow({k: "" for k in fieldnames})  # separator
            first = False
            for r in sg.rows:
                writer.writerow({
                    "subject_name": r.subject_name,
                    "subject_type": r.subject_type,
                    "application": r.realm,
                    "resource_url": r.resource_url,
                    "api": r.api,
                    "read": str(r.read).lower(),
                    "write": str(r.write).lower(),
                    "enabled": str(r.enabled).lower(),
                    "notes": r.notes,
                })


# ---------------------------------------------------------------------------
# Token claim builder
# ---------------------------------------------------------------------------

def build_token_claims(sg):
    """
    Build the nmos-token-claims JSON from a SubjectGrants object.
    Only enabled rows contribute to the token claims.

    Returns dict with keys: scope, aud, ext (containing x-nmos-* claims).
    """
    enabled = [r for r in sg.rows if r.enabled]

    # Step 1: Collect scopes (APIs where at least read or write is granted)
    scopes = sorted({r.api for r in enabled if r.read or r.write})

    # Step 2: Build audience array
    #   Keep all resource_urls (including "*") in a stable order.
    #   "*" comes first, then sorted specific URLs.
    resource_urls = {r.resource_url for r in enabled if r.read or r.write}
    specific_urls = sorted(resource_urls - {"*"})
    if "*" in resource_urls:
        aud = ["*"] + specific_urls
    else:
        aud = specific_urls

    # Step 3: Build x-nmos-{api} claims
    # Group enabled rows by api
    apis = {}
    for r in enabled:
        if r.api not in apis:
            apis[r.api] = []
        apis[r.api].append(r)

    ext = {}
    for api_name, api_rows in apis.items():
        claim = {}

        # Check wildcard row for this API
        wildcard_read = any(r.read for r in api_rows if r.resource_url == "*")
        wildcard_write = any(r.write for r in api_rows if r.resource_url == "*")

        # Build read claim
        if wildcard_read:
            claim["read"] = ["*"]
        else:
            read_indices = []
            for r in api_rows:
                if r.read and r.resource_url in aud:
                    read_indices.append(aud.index(r.resource_url))
            if read_indices:
                claim["read"] = sorted(set(read_indices))

        # Build write claim (independent of read)
        if wildcard_write:
            claim["write"] = ["*"]
        else:
            write_indices = []
            for r in api_rows:
                if r.write and r.resource_url in aud:
                    write_indices.append(aud.index(r.resource_url))
            if write_indices:
                claim["write"] = sorted(set(write_indices))

        if claim:  # only include if there's at least read or write
            ext[f"x-nmos-{api_name}"] = claim

    return {
        "scope": scopes,
        "aud": aud,
        "ext": ext,
    }


def build_raw_grants_json(sg):
    """Build a JSON-serializable list from all rows (including disabled)."""
    return [
        {
            "resource_url": r.resource_url,
            "api": r.api,
            "read": r.read,
            "write": r.write,
            "enabled": r.enabled,
            "notes": r.notes,
        }
        for r in sg.rows
    ]


# ---------------------------------------------------------------------------
# Keycloak Admin REST API wrapper
# ---------------------------------------------------------------------------

class KeycloakError(Exception):
    """Raised on Keycloak API errors."""
    pass


class KeycloakAdmin:
    """Thin wrapper around the Keycloak Admin REST API using raw requests."""

    def __init__(self, base_url, admin_user, admin_password):
        self._base = base_url.rstrip("/")
        self._session = requests.Session()
        # Verify Keycloak's TLS cert against the Matrox root CA when
        # talking HTTPS. ``requests`` honours REQUESTS_CA_BUNDLE
        # automatically, so an env-var override is supported too.
        # If the file is missing we fall back to ``True`` (system CAs)
        # — a self-signed Keycloak cert will fail verification, which
        # is the correct loud failure mode.
        if self._base.startswith("https://") and os.path.isfile(DEFAULT_CA_BUNDLE):
            self._session.verify = DEFAULT_CA_BUNDLE
        self._admin_user = admin_user
        self._admin_pass = admin_password
        self._token = None
        self._token_expiry = 0
        self._authenticate()

    # --- Authentication ---

    def _authenticate(self):
        url = f"{self._base}/realms/master/protocol/openid-connect/token"
        resp = self._session.post(url, data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": self._admin_user,
            "password": self._admin_pass,
        })
        if resp.status_code != 200:
            raise KeycloakError(
                f"Authentication failed ({resp.status_code}): {resp.text}"
            )
        data = resp.json()
        self._token = data["access_token"]
        self._token_expiry = time.time() + data.get("expires_in", 300) - 30

    def _ensure_auth(self):
        if time.time() >= self._token_expiry:
            self._authenticate()

    def _headers(self):
        self._ensure_auth()
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    def _request(self, method, path, **kwargs):
        """Make an authenticated request. Returns response object."""
        url = f"{self._base}{path}"
        resp = self._session.request(method, url, headers=self._headers(), **kwargs)
        return resp

    def _get(self, path, **kwargs):
        resp = self._request("GET", path, **kwargs)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    def _post(self, path, **kwargs):
        resp = self._request("POST", path, **kwargs)
        if resp.status_code == 409:
            return resp  # conflict / already exists
        if resp.status_code not in (200, 201, 204):
            raise KeycloakError(
                f"POST {path} failed ({resp.status_code}): {resp.text}"
            )
        return resp

    def _put(self, path, **kwargs):
        resp = self._request("PUT", path, **kwargs)
        if resp.status_code not in (200, 204):
            raise KeycloakError(
                f"PUT {path} failed ({resp.status_code}): {resp.text}"
            )
        return resp

    def _delete(self, path, **kwargs):
        resp = self._request("DELETE", path, **kwargs)
        if resp.status_code not in (200, 204, 404):
            raise KeycloakError(
                f"DELETE {path} failed ({resp.status_code}): {resp.text}"
            )
        return resp

    # --- Realm ---

    def realm_exists(self, realm):
        return self._get(f"/admin/realms/{realm}") is not None

    def create_realm(self, realm):
        return self._post("/admin/realms", json={
            "realm": realm,
            "enabled": True,
        })

    def update_realm(self, realm, payload):
        self._put(f"/admin/realms/{realm}", json=payload)

    def get_user_profile(self, realm):
        return self._get(f"/admin/realms/{realm}/users/profile")

    def update_user_profile(self, realm, profile):
        self._put(f"/admin/realms/{realm}/users/profile", json=profile)

    def ensure_realm(self, realm):
        if not self.realm_exists(realm):
            print(f"  Creating realm '{realm}' ...")
            self.create_realm(realm)
        # Set access token lifespan to 1 hour (3600s) per NMOS spec
        print(f"  Setting access token lifespan to 3600s ...")
        self.update_realm(realm, {
            "realm": realm,
            "accessTokenLifespan": 3600,
        })
        # Allow admin to set custom user attributes (nmos-*, x-nmos-*)
        # Register nmos-raw-grants and nmos-ext with a 64 KB length limit
        # (Keycloak default is 2048, too small after api=* expansion).
        print(f"  Configuring user profile (ADMIN_EDIT, attribute limits) ...")
        profile = self.get_user_profile(realm)
        profile["unmanagedAttributePolicy"] = "ADMIN_EDIT"
        large_attrs = {"x-nmos-raw-grants", "x-nmos-ext"}
        existing_names = {a["name"] for a in profile.get("attributes", [])}
        for attr_name in sorted(large_attrs):
            attr_def = {
                "name": attr_name,
                "validations": {"length": {"max": "65536"}},
                "permissions": {"edit": ["admin"], "view": ["admin"]},
            }
            if attr_name not in existing_names:
                profile.setdefault("attributes", []).append(attr_def)
            else:
                for a in profile["attributes"]:
                    if a["name"] == attr_name:
                        a.setdefault("validations", {})["length"] = \
                            {"max": "65536"}
        self.update_user_profile(realm, profile)
        # Remove unwanted default scopes to minimize token size
        print(f"  Removing unwanted default scopes ...")
        for s in self.get_realm_default_scopes(realm):
            if s["name"] in UNWANTED_DEFAULT_SCOPES:
                print(f"    -{s['name']}")
                self.remove_realm_default_scope(realm, s["id"])

    # --- Users ---

    def find_user(self, realm, username):
        users = self._get(
            f"/admin/realms/{realm}/users",
            params={"username": username, "exact": "true"},
        )
        if users:
            return users[0]
        return None

    def get_user(self, realm, user_id):
        return self._get(f"/admin/realms/{realm}/users/{user_id}")

    def create_user(self, realm, username, enabled=True):
        resp = self._post(f"/admin/realms/{realm}/users", json={
            "username": username,
            "enabled": enabled,
            "emailVerified": True,
            "email": f"{username}@test.local",
            "firstName": username,
            "lastName": "test",
            "requiredActions": [],
        })
        # Get the created user
        return self.find_user(realm, username)

    def update_user(self, realm, user_id, payload):
        self._put(f"/admin/realms/{realm}/users/{user_id}", json=payload)

    def set_password(self, realm, user_id, password, temporary=False):
        self._put(f"/admin/realms/{realm}/users/{user_id}/reset-password", json={
            "type": "password",
            "value": password,
            "temporary": temporary,
        })

    # --- Clients ---

    def find_client(self, realm, client_id):
        clients = self._get(
            f"/admin/realms/{realm}/clients",
            params={"clientId": client_id},
        )
        if clients:
            for c in clients:
                if c["clientId"] == client_id:
                    return c
        return None

    def create_client(self, realm, client_id, secret=None,
                      service_accounts=True):
        payload = {
            "clientId": client_id,
            "enabled": True,
            "serviceAccountsEnabled": service_accounts,
            "clientAuthenticatorType": "client-secret",
            "directAccessGrantsEnabled": True,
            "publicClient": False,
            "standardFlowEnabled": not service_accounts,
            "protocol": "openid-connect",
            "attributes": {
                "access.token.type": "JWT",
            },
        }
        if secret:
            payload["secret"] = secret
        self._post(f"/admin/realms/{realm}/clients", json=payload)
        return self.find_client(realm, client_id)

    def update_client(self, realm, client_uuid, payload):
        self._put(f"/admin/realms/{realm}/clients/{client_uuid}",
                  json=payload)

    def get_service_account_user(self, realm, client_uuid):
        return self._get(
            f"/admin/realms/{realm}/clients/{client_uuid}/service-account-user"
        )

    # --- Client Scopes ---

    def list_client_scopes(self, realm):
        return self._get(f"/admin/realms/{realm}/client-scopes") or []

    def find_client_scope(self, realm, name):
        for s in self.list_client_scopes(realm):
            if s["name"] == name:
                return s
        return None

    def create_client_scope(self, realm, name, include_in_token_scope=False):
        self._post(f"/admin/realms/{realm}/client-scopes", json={
            "name": name,
            "protocol": "openid-connect",
            "attributes": {
                "include.in.token.scope": str(include_in_token_scope).lower(),
                "display.on.consent.screen": "false",
            },
        })
        return self.find_client_scope(realm, name)

    # --- Protocol Mappers on Client Scopes ---

    def list_scope_mappers(self, realm, scope_id):
        return self._get(
            f"/admin/realms/{realm}/client-scopes/{scope_id}"
            f"/protocol-mappers/models"
        ) or []

    def create_scope_mapper(self, realm, scope_id, mapper):
        self._post(
            f"/admin/realms/{realm}/client-scopes/{scope_id}"
            f"/protocol-mappers/models",
            json=mapper,
        )

    def update_scope_mapper(self, realm, scope_id, mapper_id, mapper):
        self._put(
            f"/admin/realms/{realm}/client-scopes/{scope_id}"
            f"/protocol-mappers/models/{mapper_id}",
            json=mapper,
        )

    def delete_scope_mapper(self, realm, scope_id, mapper_id):
        self._delete(
            f"/admin/realms/{realm}/client-scopes/{scope_id}"
            f"/protocol-mappers/models/{mapper_id}",
        )

    # --- Protocol Mappers on Clients ---

    def list_client_mappers(self, realm, client_uuid):
        return self._get(
            f"/admin/realms/{realm}/clients/{client_uuid}"
            f"/protocol-mappers/models"
        ) or []

    def create_client_mapper(self, realm, client_uuid, mapper):
        self._post(
            f"/admin/realms/{realm}/clients/{client_uuid}"
            f"/protocol-mappers/models",
            json=mapper,
        )

    def update_client_mapper(self, realm, client_uuid, mapper_id, mapper):
        self._put(
            f"/admin/realms/{realm}/clients/{client_uuid}"
            f"/protocol-mappers/models/{mapper_id}",
            json=mapper,
        )

    # --- Client <-> Scope Assignment ---

    def get_client_default_scopes(self, realm, client_uuid):
        return self._get(
            f"/admin/realms/{realm}/clients/{client_uuid}/default-client-scopes"
        ) or []

    def add_client_default_scope(self, realm, client_uuid, scope_id):
        self._put(
            f"/admin/realms/{realm}/clients/{client_uuid}"
            f"/default-client-scopes/{scope_id}"
        )

    def remove_client_default_scope(self, realm, client_uuid, scope_id):
        self._delete(
            f"/admin/realms/{realm}/clients/{client_uuid}"
            f"/default-client-scopes/{scope_id}"
        )

    # --- Realm Default Client Scopes ---

    def get_realm_default_scopes(self, realm):
        return self._get(
            f"/admin/realms/{realm}/default-default-client-scopes"
        ) or []

    def remove_realm_default_scope(self, realm, scope_id):
        self._delete(
            f"/admin/realms/{realm}/default-default-client-scopes/{scope_id}"
        )

    # --- Groups ---

    def list_groups(self, realm):
        return self._get(f"/admin/realms/{realm}/groups") or []

    def find_group(self, realm, name):
        for g in self.list_groups(realm):
            if g["name"] == name:
                return g
        return None

    def create_group(self, realm, name):
        self._post(f"/admin/realms/{realm}/groups",
                   json={"name": name})
        return self.find_group(realm, name)

    def update_group(self, realm, group_id, payload):
        self._put(f"/admin/realms/{realm}/groups/{group_id}",
                  json=payload)

    def get_group_members(self, realm, group_id):
        return self._get(
            f"/admin/realms/{realm}/groups/{group_id}/members"
        ) or []

    def add_user_to_group(self, realm, user_id, group_id):
        self._put(
            f"/admin/realms/{realm}/users/{user_id}/groups/{group_id}"
        )

    def remove_user_from_group(self, realm, user_id, group_id):
        self._delete(
            f"/admin/realms/{realm}/users/{user_id}/groups/{group_id}"
        )

    # --- Key Providers (Components) ---

    def list_key_providers(self, realm):
        """List all key provider components in a realm."""
        return self._get(
            f"/admin/realms/{realm}/components",
            params={"type": "org.keycloak.keys.KeyProvider"},
        ) or []

    def get_realm_id(self, realm):
        """Get the internal UUID of a realm (required for component parentId)."""
        info = self._get(f"/admin/realms/{realm}")
        return info["id"] if info else realm

    def create_key_provider(self, realm, name, provider_id, config):
        """Create a new key provider component."""
        realm_id = self.get_realm_id(realm)
        return self._post(f"/admin/realms/{realm}/components", json={
            "name": name,
            "providerId": provider_id,
            "providerType": "org.keycloak.keys.KeyProvider",
            "parentId": realm_id,
            "config": config,
        })

    def update_key_provider(self, realm, component_id, payload):
        """Update an existing key provider component."""
        self._put(f"/admin/realms/{realm}/components/{component_id}",
                  json=payload)

    def delete_key_provider(self, realm, component_id):
        """Delete a key provider component."""
        self._delete(f"/admin/realms/{realm}/components/{component_id}")

    def get_realm_keys(self, realm):
        """Get active keys and their metadata for a realm."""
        return self._get(f"/admin/realms/{realm}/keys")

    # --- Convenience: list all clients with service accounts ---

    def list_sa_clients(self, realm):
        """List all clients that have service accounts enabled."""
        clients = self._get(f"/admin/realms/{realm}/clients") or []
        return [c for c in clients if c.get("serviceAccountsEnabled")]

    def list_users(self, realm, max_results=1000):
        """List all non-service-account users."""
        users = self._get(
            f"/admin/realms/{realm}/users",
            params={"max": max_results},
        ) or []
        return [u for u in users
                if not u.get("username", "").startswith("service-account-")]


# ---------------------------------------------------------------------------
# Infrastructure setup
# ---------------------------------------------------------------------------

def ensure_nmos_infrastructure(kc, realm):
    """
    Ensure the realm has the nmos-claims client scope with attribute mappers,
    and all known NMOS API scopes.

    Returns a dict mapping scope_name -> scope_id.
    """
    scope_map = {}

    # 1. Ensure nmos-claims scope exists (carrier for script mappers)
    nmos_cs = kc.find_client_scope(realm, NMOS_CLAIMS_SCOPE)
    if nmos_cs:
        print(f"  Client scope '{NMOS_CLAIMS_SCOPE}' ... exists")
    else:
        print(f"  Client scope '{NMOS_CLAIMS_SCOPE}' ... creating")
        nmos_cs = kc.create_client_scope(
            realm, NMOS_CLAIMS_SCOPE, include_in_token_scope=False
        )
    scope_map[NMOS_CLAIMS_SCOPE] = nmos_cs["id"]

    # 2. Ensure the "ext" attribute mapper on nmos-claims scope
    #    Maps user attribute "x-nmos-ext" -> token claim "ext" as JSON
    _ensure_mapper(kc, realm, nmos_cs["id"], {
        "name": "nmos-ext-mapper",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-attribute-mapper",
        "config": {
            "user.attribute": "x-nmos-ext",
            "claim.name": "ext",
            "id.token.claim": "false",
            "access.token.claim": "true",
            "userinfo.token.claim": "false",
            "jsonType.label": "JSON",
        },
    })

    # 2b. client_id claim is handled by a per-client hardcoded mapper
    #     (see ensure_client_id_mapper) because the session-note approach
    #     only works for client_credentials, not password/auth_code grants.

    # 2c. Override "sub" claim using user attribute "x-nmos-sub"
    #     For client_credentials: x-nmos-sub = client_id (spec: sub == client_id)
    #     For users: x-nmos-sub = user UUID (preserves default)
    _ensure_mapper(kc, realm, nmos_cs["id"], {
        "name": "nmos-sub-mapper",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-attribute-mapper",
        "config": {
            "user.attribute": "x-nmos-sub",
            "claim.name": "sub",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
            "jsonType.label": "String",
        },
    })

    # 2d. Ensure the "x-nmos-aud" attribute mapper for audience
    #     Multi-valued String so each entry becomes an array element.
    #     Keycloak collapses single-value aud to a string; we always append
    #     the issuer URL to guarantee 2+ entries (forces array output).
    _ensure_mapper(kc, realm, nmos_cs["id"], {
        "name": "nmos-aud-mapper",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-attribute-mapper",
        "config": {
            "user.attribute": "x-nmos-aud",
            "claim.name": "aud",
            "id.token.claim": "false",
            "access.token.claim": "true",
            "userinfo.token.claim": "false",
            "jsonType.label": "String",
            "multivalued": "true",
        },
    })

    # 3. Ensure NMOS API scopes exist
    for scope_name in sorted(NMOS_KNOWN_SCOPES):
        s = kc.find_client_scope(realm, scope_name)
        if s:
            scope_map[scope_name] = s["id"]
        else:
            print(f"  API scope '{scope_name}' ... creating")
            s = kc.create_client_scope(
                realm, scope_name, include_in_token_scope=True
            )
            scope_map[scope_name] = s["id"]

    # 4. Remove unwanted mappers from the built-in "service_account" scope
    #    (Client Host, Client IP Address bloat client_credentials tokens;
    #     Client ID is redundant — we use a per-client hardcoded mapper)
    sa_scope = kc.find_client_scope(realm, "service_account")
    if sa_scope:
        unwanted_mappers = {"Client Host", "Client IP Address", "Client ID"}
        for m in kc.list_scope_mappers(realm, sa_scope["id"]):
            if m["name"] in unwanted_mappers:
                print(f"  Removing mapper '{m['name']}' from service_account scope")
                kc.delete_scope_mapper(realm, sa_scope["id"], m["id"])

    return scope_map


def _ensure_mapper(kc, realm, scope_id, mapper_def):
    """Create or update a protocol mapper on a client scope."""
    name = mapper_def["name"]
    existing = kc.list_scope_mappers(realm, scope_id)
    for m in existing:
        if m["name"] == name:
            print(f"  Mapper '{name}' ... updating")
            mapper_def["id"] = m["id"]
            kc.update_scope_mapper(realm, scope_id, m["id"], mapper_def)
            return
    print(f"  Mapper '{name}' ... creating")
    kc.create_scope_mapper(realm, scope_id, mapper_def)


def ensure_client_token_type(kc, realm, client_uuid):
    """Set access.token.type=JWT on a client (NMOS spec: typ MUST be JWT)."""
    client = kc._get(f"/admin/realms/{realm}/clients/{client_uuid}")
    attrs = client.get("attributes", {})
    if attrs.get("access.token.type") != "JWT":
        attrs["access.token.type"] = "JWT"
        kc.update_client(realm, client_uuid,
                         {"clientId": client["clientId"],
                          "attributes": attrs})


# ---------------------------------------------------------------------------
# Controller (auth_code) client provisioning
# ---------------------------------------------------------------------------
#
# Per-Node controllers identify themselves to Keycloak with the
# historical client name ``controller-<serial>``. Certificate-style
# client subjects are also treated as controller auth-code clients when
# they contain one of the controller serials parsed from the same CSV.
# These clients differ from the service-account NMOS subjects in two ways:
#
#   * They DON'T have a service account — auth_code requires a real user
#     to log in via Keycloak's form, not a machine identity.
#   * They DO have ``redirectUris`` configured so Keycloak can 302 the
#     code back to the controller's callback handler.
#
# The redirect-URI list below is a small, fixed set of common HTTPS ports
# used by the controller in dev/test. Operators with custom ports edit
# the client in Keycloak's admin UI to add more entries.

_CONTROLLER_CLIENT_PREFIX = "controller-"

# Anchored to ``XYZ-<serial>`` because the cert SAN for each Node uses
# that hostname; the controller embedded in the Node binds to it too.
_CONTROLLER_REDIRECT_PORTS = ("5050", "5060", "8443", "9443")


def _controller_serials_from_subjects(subjects: list[SubjectGrants]) -> set[str]:
    """Return serials declared by explicit ``controller-<serial>`` subjects."""
    serials: set[str] = set()
    for sg in subjects:
        if sg.subject_type != "c":
            continue
        if not sg.subject_name.startswith(_CONTROLLER_CLIENT_PREFIX):
            continue
        serial = sg.subject_name[len(_CONTROLLER_CLIENT_PREFIX):].strip()
        if serial:
            serials.add(serial.upper())
    return serials


def _controller_serial_from_subject(
    name: str,
    known_controller_serials: set[str] | None = None,
) -> str | None:
    """Return the Node serial for a controller auth-code client subject.

    ``controller-<serial>`` keeps the original behaviour. Certificate-style
    client IDs are recognized only when they contain a serial already declared
    by an explicit controller subject in the same CSV. Returned serials are
    normalized to uppercase for redirect URI generation.
    """
    if name.startswith(_CONTROLLER_CLIENT_PREFIX):
        serial = name[len(_CONTROLLER_CLIENT_PREFIX):].strip()
        return serial.upper() if serial else None

    if not known_controller_serials:
        return None
    name_lower = name.lower()
    for serial in sorted(known_controller_serials, key=len, reverse=True):
        if serial.lower() in name_lower:
            return serial
    return None


def _is_controller_client(
    name: str,
    known_controller_serials: set[str] | None = None,
) -> bool:
    return _controller_serial_from_subject(
        name, known_controller_serials,
    ) is not None


def _controller_serial(
    client_name: str,
    known_controller_serials: set[str] | None = None,
) -> str:
    serial = _controller_serial_from_subject(
        client_name, known_controller_serials,
    )
    if serial is None:
        raise ValueError(
            f"client {client_name!r} is not a controller auth_code client"
        )
    return serial


def _controller_redirect_uris(serial: str) -> list:
    """Every redirect URI a controller-<serial> client may come back to.

    Fully-qualified and exact — no trailing ``*``. AMWA IS-10
    ``Behaviour - Clients.md``:

        Redirect URIs MUST be complete (fully-qualified) and not use
        pattern-matching, as this makes them susceptible to Redirect URI
        Validation Attacks, described in Section 4.1. in the OAuth 2.0
        Security Best Current Practice document.

    Earlier revisions appended ``*`` to each entry, which turns Keycloak's
    verbatim comparison into a prefix match: with
    ``https://host:5050/controller/oauth2/callback*`` registered, Keycloak
    also accepts ``.../callback.attacker.example`` and
    ``.../callback/../../somewhere-else``, and an authorization code can be
    delivered to a URL the operator never registered. Nothing needed the
    wildcard — the controller builds its redirect URI as
    ``{scheme}://{host}{OAUTH2_CALLBACK_PATH}`` (``nmos/controller/app.py``)
    and never appends a query string or fragment, so the value sent is
    always exactly one of the strings below.

    Lowercase hostname: aiohttp (and most browsers) normalize the ``Host:``
    header to lowercase before sending it back. Keycloak then compares the
    redirect_uri verbatim against this list, so the registered entries MUST
    match the lowercased form. The cert SAN is uppercase but TLS hostname
    checks ARE case-insensitive per RFC 6125; redirect-URI matching is not.
    """
    node_host = f"xyz-{serial.lower()}"
    uris: list[str] = []
    # Canonical: the serial-bearing hostname matching the cert SAN.
    for port in _CONTROLLER_REDIRECT_PORTS:
        uris.append(f"https://{node_host}:{port}/controller/oauth2/callback")
    # Port-less form, for a controller reached on the default HTTPS port:
    # ``request.host`` omits the port when it is 443, so the URI the
    # controller builds has no port either.
    uris.append(f"https://{node_host}/controller/oauth2/callback")
    # Dev convenience: accept loopback access (e.g. browser on Windows
    # reaching WSL2 via 127.0.0.1) on the same ports.
    for loop_host in ("127.0.0.1", "localhost"):
        for port in _CONTROLLER_REDIRECT_PORTS:
            uris.append(f"https://{loop_host}:{port}/controller/oauth2/callback")
    return uris


def _provision_controller_client_redirects(
    kc, realm, sg, known_controller_serials: set[str] | None = None,
):
    """Set redirectUris + standardFlow flags on a controller client.

    Run after the client has been created (via ``create_client`` with
    ``service_accounts=False``). Idempotent: setting the same payload
    twice is a no-op from Keycloak's side.
    """
    client = kc.find_client(realm, sg.subject_name)
    if not client:
        return
    serial = _controller_serial(sg.subject_name, known_controller_serials)
    redirect_uris = _controller_redirect_uris(serial)
    kc.update_client(realm, client["id"], {
        "clientId": sg.subject_name,
        "enabled": True,
        # auth_code = standard flow ON; no password grant; no SA.
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "publicClient": False,
        "redirectUris": redirect_uris,
        # webOrigins="+" means: same-origin only for CORS; the
        # controller's JS layer talks back to its own host.
        "webOrigins": ["+"],
        "protocol": "openid-connect",
        "attributes": {
            "access.token.type": "JWT",
        },
    })
    print(f"    + auth_code redirect URIs ({len(redirect_uris)})")


def ensure_client_id_mapper(kc, realm, client_uuid, client_id):
    """
    Ensure a hardcoded claim mapper on a client that injects client_id
    into every token. Required by NMOS spec: client_id MUST be present.

    The session-note mapper works for client_credentials but not for
    password/authorization_code grants, so we use a hardcoded claim
    mapper directly on each client.
    """
    mapper_name = "nmos-hardcoded-client-id"
    existing = kc.list_client_mappers(realm, client_uuid)
    mapper_def = {
        "name": mapper_name,
        "protocol": "openid-connect",
        "protocolMapper": "oidc-hardcoded-claim-mapper",
        "config": {
            "claim.name": "client_id",
            "claim.value": client_id,
            "id.token.claim": "false",
            "access.token.claim": "true",
            "userinfo.token.claim": "false",
            "jsonType.label": "String",
        },
    }
    for m in existing:
        if m["name"] == mapper_name:
            print(f"    Mapper '{mapper_name}' ... updating")
            mapper_def["id"] = m["id"]
            kc.update_client_mapper(realm, client_uuid, m["id"], mapper_def)
            return
    print(f"    Mapper '{mapper_name}' ... creating")
    kc.create_client_mapper(realm, client_uuid, mapper_def)


def ensure_signing_algorithm(kc, realm, algorithm):
    """
    Configure the realm's token signing algorithm.

    Creates a new key provider with high priority so it becomes the active
    signing key. Disables any previous NMOS-managed key providers.

    Allowed algorithms per NMOS spec: RS256, RS512, ES256, ES512.
    """
    if algorithm not in NMOS_ALGORITHM_PROVIDERS:
        raise KeycloakError(
            f"Unsupported algorithm '{algorithm}'. "
            f"Allowed: {', '.join(sorted(NMOS_ALGORITHM_PROVIDERS))}"
        )

    provider_def = NMOS_ALGORITHM_PROVIDERS[algorithm]
    nmos_provider_name = f"nmos-{algorithm.lower()}"

    # Check if an NMOS-managed provider for this algorithm already exists
    existing = kc.list_key_providers(realm)
    for comp in existing:
        if comp["name"] == nmos_provider_name:
            print(f"  Key provider '{nmos_provider_name}' already exists, "
                  f"removing to regenerate ...")
            kc.delete_key_provider(realm, comp["id"])

    # Disable any other NMOS-managed key providers (different algorithm)
    for comp in existing:
        name = comp["name"]
        if (name.startswith("nmos-") and name != nmos_provider_name
                and comp.get("config", {}).get("enabled", ["true"])[0]
                == "true"):
            print(f"  Disabling previous key provider '{name}' ...")
            comp["config"]["enabled"] = ["false"]
            comp["config"]["active"] = ["false"]
            kc.update_key_provider(realm, comp["id"], comp)

    # Create the new provider
    print(f"  Creating key provider '{nmos_provider_name}' "
          f"({provider_def['providerId']}) ...")
    kc.create_key_provider(
        realm, nmos_provider_name,
        provider_def["providerId"], provider_def["config"],
    )

    # Set the realm's default signature algorithm
    print(f"  Setting realm defaultSignatureAlgorithm={algorithm} ...")
    kc.update_realm(realm, {
        "realm": realm,
        "defaultSignatureAlgorithm": algorithm,
    })

    # Verify the new key is active
    keys_info = kc.get_realm_keys(realm)
    active = keys_info.get("active", {})
    if algorithm in active:
        print(f"  Active signing key: {algorithm} "
              f"(kid={active[algorithm]})")
    else:
        print(f"  WARNING: {algorithm} not found in active keys")


def ensure_keycloak_groups(kc, realm, group_defs):
    """
    Sync CSV groups to Keycloak groups for admin visibility.

    Creates groups, stores device lists as attributes, and manages
    user membership. Groups are organizational — they don't affect tokens.
    """
    if not group_defs:
        return

    print(f"  Syncing {len(group_defs)} group(s) to Keycloak ...")
    for gname, gdef in sorted(group_defs.items()):
        # Create or find the group
        kc_group = kc.find_group(realm, gname)
        if not kc_group:
            print(f"    Group '{gname}' ... creating")
            kc_group = kc.create_group(realm, gname)
        else:
            print(f"    Group '{gname}' ... exists")

        if not kc_group:
            print(f"    WARNING: Failed to create group '{gname}'")
            continue

        # Store device list as group attribute
        kc.update_group(realm, kc_group["id"], {
            "name": gname,
            "attributes": {
                "x-nmos-devices": gdef.device_urls,
            },
        })

        # Sync membership: add expected members, remove stale ones
        current_members = kc.get_group_members(realm, kc_group["id"])
        current_names = {m["username"] for m in current_members}
        expected_names = gdef.members

        for member_name in sorted(expected_names - current_names):
            user = kc.find_user(realm, member_name)
            if user:
                print(f"      +member {member_name}")
                kc.add_user_to_group(realm, user["id"], kc_group["id"])

        for member_name in sorted(current_names - expected_names):
            user = kc.find_user(realm, member_name)
            if user:
                print(f"      -member {member_name}")
                kc.remove_user_from_group(realm, user["id"], kc_group["id"])


# ---------------------------------------------------------------------------
# Subject configuration helpers
# ---------------------------------------------------------------------------

def _set_nmos_attributes(kc, realm, user_id, token_claims, raw_grants,
                         sub_override=None):
    """
    Set NMOS grant attributes on a user.

    All attributes use the x-nmos- prefix for uniform naming:
    - x-nmos-raw-grants: raw CSV data for roundtripping (GET export)
    - x-nmos-ext: JSON of the ext claim (all x-nmos-* private claims)
    - x-nmos-aud: audience entries (multi-valued)
    - x-nmos-sub: value for the 'sub' claim override
    """
    user = kc.get_user(realm, user_id)
    attrs = user.get("attributes", {})

    # Remove any previous x-nmos-* attributes
    keys_to_remove = [k for k in attrs if k.startswith("x-nmos-")]
    for k in keys_to_remove:
        del attrs[k]

    # Store raw grants for roundtripping
    attrs["x-nmos-raw-grants"] = [json.dumps(raw_grants)]

    # Store the ext claim as a single JSON attribute
    ext = token_claims.get("ext", {})
    if ext:
        attrs["x-nmos-ext"] = [json.dumps(ext)]

    # Store audience as multi-valued attribute. Append the issuer URL so
    # there are always 2+ entries — Keycloak collapses a single aud to a
    # string, but NMOS spec requires an array.
    aud = token_claims.get("aud", [])
    if aud:
        issuer = f"{kc._base}/realms/{realm}"
        attrs["x-nmos-aud"] = aud + [issuer]

    # Store sub override (client_id for clients, user UUID for users)
    if sub_override:
        attrs["x-nmos-sub"] = [sub_override]
    else:
        # Default: preserve Keycloak's UUID-based sub
        attrs["x-nmos-sub"] = [user["id"]]

    # Preserve existing user fields — only update attributes
    update_payload = {
        "email": user.get("email"),
        "firstName": user.get("firstName"),
        "lastName": user.get("lastName"),
        "emailVerified": user.get("emailVerified"),
        "attributes": attrs,
    }
    kc.update_user(realm, user_id, update_payload)


def _clear_nmos_attributes(kc, realm, user_id):
    """Remove all NMOS attributes from a user."""
    user = kc.get_user(realm, user_id)
    attrs = user.get("attributes", {})
    keys_to_remove = [k for k in attrs if k.startswith("x-nmos-")]
    for k in keys_to_remove:
        del attrs[k]
    update_payload = {
        "email": user.get("email"),
        "firstName": user.get("firstName"),
        "lastName": user.get("lastName"),
        "emailVerified": user.get("emailVerified"),
        "attributes": attrs,
    }
    kc.update_user(realm, user_id, update_payload)


def _configure_client_scopes(kc, realm, client_uuid, required_scopes,
                             scope_map, replace=True):
    """
    Manage NMOS default scopes on a client.

    If replace=True (PUT), remove NMOS scopes not in required_scopes.
    If replace=False (UPDATE), only add missing scopes.
    """
    current = kc.get_client_default_scopes(realm, client_uuid)
    current_names = {s["name"] for s in current}
    current_by_name = {s["name"]: s["id"] for s in current}

    # Always ensure nmos-claims scope is assigned
    if NMOS_CLAIMS_SCOPE not in current_names:
        if NMOS_CLAIMS_SCOPE in scope_map:
            print(f"    +scope {NMOS_CLAIMS_SCOPE}")
            kc.add_client_default_scope(
                realm, client_uuid, scope_map[NMOS_CLAIMS_SCOPE]
            )

    # Add required NMOS API scopes
    for scope_name in sorted(required_scopes):
        if scope_name not in current_names and scope_name in scope_map:
            print(f"    +scope {scope_name}")
            kc.add_client_default_scope(
                realm, client_uuid, scope_map[scope_name]
            )

    # Remove NMOS API scopes not in required set (only for PUT / replace)
    if replace:
        for scope_name in sorted(NMOS_KNOWN_SCOPES):
            if (scope_name in current_by_name
                    and scope_name not in required_scopes):
                print(f"    -scope {scope_name}")
                kc.remove_client_default_scope(
                    realm, client_uuid, current_by_name[scope_name]
                )

    # Always strip unwanted default scopes (email, profile, roles, etc.)
    for scope_name in sorted(UNWANTED_DEFAULT_SCOPES):
        if scope_name in current_by_name:
            print(f"    -scope {scope_name}")
            kc.remove_client_default_scope(
                realm, client_uuid, current_by_name[scope_name]
            )


def _get_existing_raw_grants(attrs):
    """Parse existing x-nmos-raw-grants from user attributes."""
    raw_str = (attrs.get("x-nmos-raw-grants") or ["[]"])[0]
    try:
        return json.loads(raw_str)
    except (json.JSONDecodeError, TypeError):
        return []


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------

def cmd_init(kc, args):
    """INIT: Bootstrap a realm end-to-end.

    Without ``--csv``: creates the realm + the NMOS client scopes
    only. Useful when subjects will be created via the Keycloak
    admin UI.

    With ``--csv``: realm + scopes + every user/client in the CSV
    (creating any that don't yet exist) + their grants + the
    shared ``nmos-test-client`` for password / auth_code flows.
    This is the one-shot "make it ready" path most operators want.

    Idempotent in both modes: re-running on an existing realm
    refreshes the scopes, the signing algorithm (if ``--algorithm``
    is given), and any subject attributes / grants that have changed
    in the CSV. Subjects already present are kept; new ones are added.
    """
    realm = args.realm

    if args.csv:
        # Full bootstrap — realm + scopes + users/clients/grants.
        # The shared ``_provision_from_csv`` does the heavy lifting;
        # ``include_test_client=False`` skips the ``nmos-test-client``
        # step, which is the one thing that distinguishes ``init``
        # (production posture) from ``test`` (production + test
        # scaffolding for password-grant token-fetching scripts).
        return _provision_from_csv(kc, args, include_test_client=False)

    # Bare-realm mode — no CSV, no subjects.
    print(f"[1/3] Ensuring realm '{realm}' exists ...")
    kc.ensure_realm(realm)

    print(f"[2/3] Ensuring NMOS infrastructure in '{realm}' ...")
    scope_map = ensure_nmos_infrastructure(kc, realm)
    print(f"  Scopes ready: {', '.join(sorted(scope_map))}")

    print(f"[3/3] Signing algorithm ...")
    if args.algorithm:
        print(f"  Configuring signing algorithm: {args.algorithm} ...")
        ensure_signing_algorithm(kc, realm, args.algorithm)
    else:
        print(f"  (no --algorithm specified — Keycloak default kept)")

    print()
    print(f"Realm '{realm}' is ready. Next steps:")
    print(f"  - Create users / clients via the Keycloak admin UI, OR")
    print(f"  - Re-run with a CSV to populate subjects + grants:")
    print(f"      {sys.argv[0]} init --realm {realm} --csv <file>.csv")


def cmd_get(kc, args):
    """GET: Export current Keycloak NMOS grants to CSV."""
    realm = args.realm
    print(f"[1/3] Verifying realm '{realm}' ...")
    if not kc.realm_exists(realm):
        print(f"  ERROR: Realm '{realm}' does not exist.")
        sys.exit(1)

    subjects = []

    # Export client grants
    print("[2/3] Reading grants ...")
    print("  Scanning clients ...")
    for client in kc.list_sa_clients(realm):
        client_id = client["clientId"]
        try:
            sa_user = kc.get_service_account_user(realm, client["id"])
        except KeycloakError:
            continue

        attrs = sa_user.get("attributes", {})
        raw = _get_existing_raw_grants(attrs)
        if not raw:
            continue

        sg = SubjectGrants(
            subject_name=client_id,
            subject_type="c",
            realm=realm,
        )
        for g in raw:
            sg.rows.append(CsvRow(
                subject_name=client_id,
                subject_type="c",
                application=realm,
                resource_url=g["resource_url"],
                api=g["api"],
                read=g["read"],
                write=g["write"],
                enabled=g["enabled"],
                notes=g.get("notes", ""),
            ))
        subjects.append(sg)
        print(f"    {client_id} (client): {len(sg.rows)} grants")

    # Export user grants
    print("  Scanning users ...")
    for user in kc.list_users(realm):
        username = user.get("username", "")
        attrs = user.get("attributes", {})
        raw = _get_existing_raw_grants(attrs)
        if not raw:
            continue

        sg = SubjectGrants(
            subject_name=username,
            subject_type="u",
            realm=realm,
        )
        for g in raw:
            sg.rows.append(CsvRow(
                subject_name=username,
                subject_type="u",
                application=realm,
                resource_url=g["resource_url"],
                api=g["api"],
                read=g["read"],
                write=g["write"],
                enabled=g["enabled"],
                notes=g.get("notes", ""),
            ))
        subjects.append(sg)
        print(f"    {username} (user): {len(sg.rows)} grants")

    # Write CSV
    print(f"[3/3] Writing {args.csv} ...")
    write_csv(args.csv, subjects)
    total = sum(len(sg.rows) for sg in subjects)
    print(f"  Exported {total} grant rows for {len(subjects)} subjects.")


def cmd_put(kc, args):
    """PUT: Replace all grants for subjects in CSV."""
    realm = args.realm
    rows, group_defs = parse_csv(args.csv, api_list=args.api_list)
    subjects = group_by_subject(rows)

    if not subjects:
        print("No subjects found in CSV.")
        return
    controller_serials = _controller_serials_from_subjects(subjects)

    print(f"[1/4] Verifying realm '{realm}' ...")
    if not kc.realm_exists(realm):
        print(f"  ERROR: Realm '{realm}' does not exist.")
        sys.exit(1)

    print(f"[2/4] Ensuring NMOS infrastructure in '{realm}' ...")
    # Collect all API names from CSV (not just known ones)
    all_apis = {r.api for r in rows if r.api}
    new_apis = all_apis - NMOS_KNOWN_SCOPES
    scope_map = ensure_nmos_infrastructure(kc, realm)

    # Create any non-standard API scopes found in CSV
    for api_name in sorted(new_apis):
        if api_name not in scope_map:
            print(f"  API scope '{api_name}' ... creating (custom)")
            s = kc.create_client_scope(realm, api_name,
                                       include_in_token_scope=True)
            scope_map[api_name] = s["id"]

    # Configure signing algorithm if requested
    if args.algorithm:
        print(f"  Configuring signing algorithm: {args.algorithm} ...")
        ensure_signing_algorithm(kc, realm, args.algorithm)

    print(f"[3/4] Configuring {len(subjects)} subjects ...")
    errors = 0
    for sg in subjects:
        print(f"\n  {sg.subject_name} ({sg.subject_type}) ...")
        token_claims = build_token_claims(sg)
        raw_grants = build_raw_grants_json(sg)
        scopes = set(token_claims["scope"])

        _print_claims_summary(token_claims)

        if sg.subject_type == "c":
            client = kc.find_client(realm, sg.subject_name)
            if not client:
                print(f"    WARNING: Client '{sg.subject_name}' not found, "
                      f"skipping")
                errors += 1
                continue

            if _is_controller_client(sg.subject_name, controller_serials):
                # Auth_code controller client: no service account to
                # stamp grants on (the user logging in supplies the
                # identity + grants via their user attributes). Update
                # scopes + redirect URIs only — same posture as
                # ``cmd_test`` already applies for these clients.
                _configure_client_scopes(kc, realm, client["id"],
                                         scopes, scope_map, replace=True)
                ensure_client_id_mapper(kc, realm, client["id"],
                                        sg.subject_name)
                ensure_client_token_type(kc, realm, client["id"])
                _provision_controller_client_redirects(
                    kc, realm, sg, controller_serials,
                )
                print("    Auth_code client: scopes + redirect URIs updated.")
            else:
                sa_user = kc.get_service_account_user(realm, client["id"])
                _set_nmos_attributes(kc, realm, sa_user["id"],
                                     token_claims, raw_grants,
                                     sub_override=sg.subject_name)
                _configure_client_scopes(kc, realm, client["id"],
                                         scopes, scope_map, replace=True)
                ensure_client_id_mapper(kc, realm, client["id"],
                                        sg.subject_name)
                ensure_client_token_type(kc, realm, client["id"])
                print("    Attributes and scopes updated.")

        elif sg.subject_type == "u":
            user = kc.find_user(realm, sg.subject_name)
            if not user:
                print(f"    WARNING: User '{sg.subject_name}' not found, "
                      f"skipping")
                errors += 1
                continue

            _set_nmos_attributes(kc, realm, user["id"],
                                 token_claims, raw_grants)
            print("    Attributes updated.")

    # Sync groups to Keycloak (for admin visibility)
    if group_defs:
        ensure_keycloak_groups(kc, realm, group_defs)

    print(f"\nDone. {len(subjects)} subjects processed, "
          f"{errors} errors.")


def cmd_update(kc, args):
    """UPDATE: Merge CSV grants with existing Keycloak config."""
    realm = args.realm
    rows, group_defs = parse_csv(args.csv, api_list=args.api_list)
    subjects = group_by_subject(rows)

    if not subjects:
        print("No subjects found in CSV.")
        return
    controller_serials = _controller_serials_from_subjects(subjects)

    print(f"[1/4] Verifying realm '{realm}' ...")
    if not kc.realm_exists(realm):
        print(f"  ERROR: Realm '{realm}' does not exist.")
        sys.exit(1)

    print(f"[2/4] Ensuring NMOS infrastructure in '{realm}' ...")
    all_apis = {r.api for r in rows if r.api}
    new_apis = all_apis - NMOS_KNOWN_SCOPES
    scope_map = ensure_nmos_infrastructure(kc, realm)

    for api_name in sorted(new_apis):
        if api_name not in scope_map:
            print(f"  API scope '{api_name}' ... creating (custom)")
            s = kc.create_client_scope(realm, api_name,
                                       include_in_token_scope=True)
            scope_map[api_name] = s["id"]

    print(f"[3/4] Updating {len(subjects)} subjects ...")
    errors = 0
    for sg in subjects:
        print(f"\n  {sg.subject_name} ({sg.subject_type}) ...")

        # Find the subject and get existing grants
        if sg.subject_type == "c":
            is_controller = _is_controller_client(
                sg.subject_name, controller_serials,
            )
            client = kc.find_client(realm, sg.subject_name)
            if not client:
                print(f"    WARNING: Client '{sg.subject_name}' not found, "
                      f"skipping")
                errors += 1
                continue
            if is_controller:
                existing_raw = []
            else:
                sa_user = kc.get_service_account_user(realm, client["id"])
                existing_raw = _get_existing_raw_grants(
                    sa_user.get("attributes", {})
                )
        elif sg.subject_type == "u":
            user = kc.find_user(realm, sg.subject_name)
            if not user:
                print(f"    WARNING: User '{sg.subject_name}' not found, "
                      f"skipping")
                errors += 1
                continue
            existing_raw = _get_existing_raw_grants(
                user.get("attributes", {})
            )
        else:
            print(f"    WARNING: Unknown type '{sg.subject_type}', skipping")
            errors += 1
            continue

        # Merge: existing grants keyed by (api, resource_url)
        merged = {}
        for g in existing_raw:
            key = (g["api"], g["resource_url"])
            merged[key] = g

        # Overlay new grants from CSV
        for r in sg.rows:
            key = (r.api, r.resource_url)
            merged[key] = {
                "resource_url": r.resource_url,
                "api": r.api,
                "read": r.read,
                "write": r.write,
                "enabled": r.enabled,
                "notes": r.notes,
            }

        # Rebuild SubjectGrants from merged data
        merged_sg = SubjectGrants(
            subject_name=sg.subject_name,
            subject_type=sg.subject_type,
            realm=sg.realm,
        )
        for g in merged.values():
            merged_sg.rows.append(CsvRow(
                subject_name=sg.subject_name,
                subject_type=sg.subject_type,
                application=sg.realm,
                resource_url=g["resource_url"],
                api=g["api"],
                read=g["read"],
                write=g["write"],
                enabled=g["enabled"],
                notes=g.get("notes", ""),
            ))

        token_claims = build_token_claims(merged_sg)
        raw_grants = build_raw_grants_json(merged_sg)
        scopes = set(token_claims["scope"])

        _print_claims_summary(token_claims)

        if sg.subject_type == "c":
            if is_controller:
                _configure_client_scopes(kc, realm, client["id"],
                                         scopes, scope_map, replace=False)
                ensure_client_id_mapper(kc, realm, client["id"],
                                        sg.subject_name)
                ensure_client_token_type(kc, realm, client["id"])
                _provision_controller_client_redirects(
                    kc, realm, sg, controller_serials,
                )
                print("    Auth_code client: scopes + redirect URIs updated.")
            else:
                _set_nmos_attributes(kc, realm, sa_user["id"],
                                     token_claims, raw_grants,
                                     sub_override=sg.subject_name)
                _configure_client_scopes(kc, realm, client["id"],
                                         scopes, scope_map, replace=False)
                ensure_client_id_mapper(kc, realm, client["id"],
                                        sg.subject_name)
                ensure_client_token_type(kc, realm, client["id"])
                print("    Attributes and scopes updated (merged).")

        elif sg.subject_type == "u":
            _set_nmos_attributes(kc, realm, user["id"],
                                 token_claims, raw_grants)
            print("    Attributes updated (merged).")

    # Sync groups to Keycloak (for admin visibility)
    if group_defs:
        ensure_keycloak_groups(kc, realm, group_defs)

    print(f"\nDone. {len(subjects)} subjects processed, "
          f"{errors} errors.")


def cmd_test(kc, args):
    """TEST: ``init --csv`` plus the shared ``nmos-test-client``.

    The test client is a pre-provisioned OAuth2 client with
    ``directAccessGrantsEnabled=True`` so test scripts (e.g.
    ``test_tokens.py``, ``/tmp/authcode_test.py``) can obtain a
    user token via password / auth_code grant without needing a
    per-user calling client. **Production realms shouldn't expose
    this client** — use ``init`` instead.
    """
    return _provision_from_csv(kc, args, include_test_client=True)


def _provision_from_csv(kc, args, *, include_test_client: bool):
    """Shared CSV-driven bootstrap path used by both ``init --csv``
    and ``test``.

    With ``include_test_client=False`` (production / ``init``):
    realm + scopes + every CSV subject + grants. Step labels read
    ``[N/6]`` because the test-client step is skipped.

    With ``include_test_client=True`` (``test``): same as above PLUS
    a step that provisions ``nmos-test-client`` for token-fetching
    scripts. Step labels read ``[N/7]``.
    """
    realm = args.realm
    rows, group_defs = parse_csv(args.csv, api_list=args.api_list)
    subjects = group_by_subject(rows)

    if not subjects:
        print("No subjects found in CSV.")
        return
    controller_serials = _controller_serials_from_subjects(subjects)

    # Step labels track total count so the operator can tell at a
    # glance whether they're on the test-client-included path.
    total = 7 if include_test_client else 6

    print(f"[1/{total}] Ensuring realm '{realm}' exists ...")
    kc.ensure_realm(realm)

    print(f"[2/{total}] Ensuring NMOS infrastructure in '{realm}' ...")
    all_apis = {r.api for r in rows if r.api}
    new_apis = all_apis - NMOS_KNOWN_SCOPES
    scope_map = ensure_nmos_infrastructure(kc, realm)

    for api_name in sorted(new_apis):
        if api_name not in scope_map:
            print(f"  API scope '{api_name}' ... creating (custom)")
            s = kc.create_client_scope(realm, api_name,
                                       include_in_token_scope=True)
            scope_map[api_name] = s["id"]

    # Configure signing algorithm if requested
    if args.algorithm:
        print(f"  Configuring signing algorithm: {args.algorithm} ...")
        ensure_signing_algorithm(kc, realm, args.algorithm)

    # The shared test client is the ONLY thing ``init`` does NOT do.
    # Skipping it in production keeps a real Keycloak realm free of a
    # client whose only purpose is to bypass per-user calling-client
    # provisioning for our test scripts.
    if include_test_client:
        print(f"[3/{total}] Creating test client '{TEST_USER_CLIENT}' for user tokens ...")
        test_client = kc.find_client(realm, TEST_USER_CLIENT)
        if test_client:
            print(f"  Client '{TEST_USER_CLIENT}' ... exists")
        else:
            print(f"  Client '{TEST_USER_CLIENT}' ... creating "
                  f"(secret={args.default_secret})")
            test_client = kc.create_client(realm, TEST_USER_CLIENT,
                                           secret=args.default_secret,
                                           service_accounts=False)
        if test_client:
            kc.update_client(realm, test_client["id"], {
                "clientId": TEST_USER_CLIENT,
                "enabled": True,
                "directAccessGrantsEnabled": True,
                "standardFlowEnabled": True,
                "publicClient": False,
                "serviceAccountsEnabled": False,
                "protocol": "openid-connect",
                "attributes": {
                    "access.token.type": "JWT",
                },
            })
            all_subject_scopes = {r.api for r in rows if r.api and r.enabled}
            _configure_client_scopes(kc, realm, test_client["id"],
                                     all_subject_scopes, scope_map, replace=True)
            ensure_client_id_mapper(kc, realm, test_client["id"],
                                    TEST_USER_CLIENT)
            ensure_client_token_type(kc, realm, test_client["id"])
            print(f"  '{TEST_USER_CLIENT}' configured with all NMOS scopes.")

    step_subjects = 4 if include_test_client else 3
    print(f"[{step_subjects}/{total}] Creating subjects ...")
    for sg in subjects:
        if sg.subject_type == "c":
            is_controller = _is_controller_client(
                sg.subject_name, controller_serials,
            )
            client = kc.find_client(realm, sg.subject_name)
            if client:
                print(f"  Client '{sg.subject_name}' ... exists")
            else:
                kind = "auth_code" if is_controller else "service-account"
                print(f"  Client '{sg.subject_name}' ... creating "
                      f"({kind}, secret={args.default_secret})")
                # Controller clients use auth_code only — no service
                # account, no direct password grant. The user logging
                # in supplies the identity via Keycloak's login form.
                kc.create_client(realm, sg.subject_name,
                                 secret=args.default_secret,
                                 service_accounts=not is_controller)
            if is_controller:
                _provision_controller_client_redirects(
                    kc, realm, sg, controller_serials,
                )

        elif sg.subject_type == "u":
            user = kc.find_user(realm, sg.subject_name)
            if user:
                print(f"  User '{sg.subject_name}' ... exists")
            else:
                print(f"  User '{sg.subject_name}' ... creating "
                      f"(password={args.default_password})")
                user = kc.create_user(realm, sg.subject_name)
                kc.set_password(realm, user["id"], args.default_password)

    step_configure = 5 if include_test_client else 4
    print(f"[{step_configure}/{total}] Configuring {len(subjects)} subjects ...")
    errors = 0
    for sg in subjects:
        print(f"\n  {sg.subject_name} ({sg.subject_type}) ...")
        token_claims = build_token_claims(sg)
        raw_grants = build_raw_grants_json(sg)
        scopes = set(token_claims["scope"])

        _print_claims_summary(token_claims)

        if sg.subject_type == "c":
            client = kc.find_client(realm, sg.subject_name)
            if not client:
                print(f"    ERROR: Client creation failed, skipping")
                errors += 1
                continue

            if _is_controller_client(sg.subject_name, controller_serials):
                # Auth_code controller client: no service account exists
                # to stamp grants on. The user who logs in via this
                # client supplies the identity (and grants via the
                # ``ext`` claim from their own user attributes).
                # Still attach the NMOS scopes + client_id + JWT type
                # so the user's login mints a properly-shaped token.
                _configure_client_scopes(kc, realm, client["id"],
                                         scopes, scope_map, replace=True)
                ensure_client_id_mapper(kc, realm, client["id"],
                                        sg.subject_name)
                ensure_client_token_type(kc, realm, client["id"])
                print("    Auth_code client: scopes + redirect URIs configured.")
            else:
                sa_user = kc.get_service_account_user(realm, client["id"])
                _set_nmos_attributes(kc, realm, sa_user["id"],
                                     token_claims, raw_grants,
                                     sub_override=sg.subject_name)
                _configure_client_scopes(kc, realm, client["id"],
                                         scopes, scope_map, replace=True)
                ensure_client_id_mapper(kc, realm, client["id"],
                                        sg.subject_name)
                ensure_client_token_type(kc, realm, client["id"])
                print("    Attributes and scopes configured.")

        elif sg.subject_type == "u":
            user = kc.find_user(realm, sg.subject_name)
            if not user:
                print(f"    ERROR: User creation failed, skipping")
                errors += 1
                continue

            _set_nmos_attributes(kc, realm, user["id"],
                                 token_claims, raw_grants)
            print("    Attributes configured.")

    step_groups = 6 if include_test_client else 5
    if group_defs:
        print(f"\n[{step_groups}/{total}] Syncing {len(group_defs)} group(s) to Keycloak ...")
        ensure_keycloak_groups(kc, realm, group_defs)
    else:
        print(f"\n[{step_groups}/{total}] No groups to sync.")

    print(f"\n[{total}/{total}] Done. {len(subjects)} subjects processed, "
          f"{errors} errors.")

    # Credentials summary — useful for both modes; the test-client
    # line is suppressed when it wasn't created.
    print("\n--- Credentials ---")
    if include_test_client:
        print(f"  Test client for user tokens: {TEST_USER_CLIENT}  "
              f"secret: {args.default_secret}")
    for sg in subjects:
        if sg.subject_type == "c":
            print(f"  Client: {sg.subject_name}  "
                  f"secret: {args.default_secret}")
        elif sg.subject_type == "u":
            print(f"  User:   {sg.subject_name}  "
                  f"password: {args.default_password}")


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _print_claims_summary(token_claims):
    """Print a compact summary of the computed token claims."""
    scopes = token_claims.get("scope", [])
    aud = token_claims.get("aud", [])
    ext = token_claims.get("ext", {})

    print(f"    Scopes: {' '.join(scopes) if scopes else '(none)'}")
    print(f"    Aud:    {json.dumps(aud)}")
    for claim_name, claim_val in sorted(ext.items()):
        r = claim_val.get("read", "-")
        w = claim_val.get("write", "-")
        print(f"    {claim_name}: read={r} write={w}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        description="NMOS Keycloak Grant Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "command",
        choices=["init", "get", "put", "update", "test"],
        help="Command to execute",
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_BASE_URL,
        help=f"Keycloak base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--admin-user",
        default=DEFAULT_ADMIN_USER,
        help=f"Admin username (default: {DEFAULT_ADMIN_USER})",
    )
    parser.add_argument(
        "--admin-pass",
        default=DEFAULT_ADMIN_PASS,
        help=f"Admin password (default: {DEFAULT_ADMIN_PASS})",
    )
    parser.add_argument(
        "--realm",
        required=True,
        help="Keycloak realm name (maps to 'application' CSV column)",
    )
    parser.add_argument(
        "--csv",
        required=False,
        help="CSV file path (input for put/update/test, output for "
             "get). Not used by ``init``.",
    )
    parser.add_argument(
        "--default-password",
        default=DEFAULT_TEST_PASSWORD,
        help=f"Default password for test-created users "
             f"(default: {DEFAULT_TEST_PASSWORD})",
    )
    parser.add_argument(
        "--default-secret",
        default=DEFAULT_TEST_SECRET,
        help=f"Default secret for test-created clients "
             f"(default: {DEFAULT_TEST_SECRET})",
    )
    parser.add_argument(
        "--apis",
        help="Comma-separated NMOS APIs that api=* expands to "
             "(overrides #apis directive in CSV)",
    )
    parser.add_argument(
        "--algorithm",
        choices=["RS256", "RS512", "ES256", "ES512"],
        help="Token signing algorithm (NMOS spec: RS256, RS512, ES256, ES512). "
             "Applies to 'test' and 'put' commands.",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Parse --apis into a list
    args.api_list = None
    if args.apis:
        args.api_list = [a.strip() for a in args.apis.split(",")
                         if a.strip()]

    # Connect
    print(f"Connecting to {args.url} ...")
    try:
        kc = KeycloakAdmin(args.url, args.admin_user, args.admin_pass)
    except KeycloakError as e:
        print(f"ERROR: {e}")
        sys.exit(1)
    except requests.ConnectionError:
        print(f"ERROR: Cannot connect to {args.url}. "
              f"Is Keycloak running?")
        sys.exit(1)
    print("Authenticated.")

    # ``--csv`` is required for every command that reads or writes
    # grants. ``init`` is the only command that doesn't touch a CSV
    # — it just bootstraps the realm + NMOS scopes.
    if args.command != "init" and not args.csv:
        print(f"ERROR: --csv is required for the '{args.command}' command.")
        sys.exit(1)

    # Dispatch
    try:
        if args.command == "init":
            cmd_init(kc, args)
        elif args.command == "get":
            cmd_get(kc, args)
        elif args.command == "put":
            cmd_put(kc, args)
        elif args.command == "update":
            cmd_update(kc, args)
        elif args.command == "test":
            cmd_test(kc, args)
    except KeycloakError as e:
        print(f"\nERROR: {e}")
        sys.exit(1)
    except requests.ConnectionError:
        print(f"\nERROR: Lost connection to {args.url}.")
        sys.exit(1)


if __name__ == "__main__":
    main()
