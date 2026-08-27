#!/usr/bin/env python3
# Copyright (C) 2025-2026 Alain Bouchard
# SPDX-License-Identifier: Apache-2.0

"""Fetch an OAuth2 access token from Keycloak for the IPMX NMOS test suite.

Prints the raw bearer token to stdout on success; exits non-zero with a
diagnostic on stderr otherwise. Sourced indirectly by
``IPMX-testing/IPMX-GET-OAUTH2-TOKEN.sh`` (and its ``.bat`` sibling), which
captures the stdout into the ``NMOS_TESTING_AUTH_TOKEN`` environment
variable that ``IPMX-testing/nmostesting/UserConfig.py`` reads.

Defaults match ``test_tokens.py`` in this same directory; the client_id
defaults to ``Example.Company.Device.Client.ABC.SNX00000.example.com`` — the full-access ``subject_type=c`` entry added
to ``TR-10-SEC_grants.csv``.

Usage:
    python3 get_test_token.py
    python3 get_test_token.py --client-id Example.Company.Device.Client.ABC.SNX00000.example.com --client-secret secret
    NMOS_TEST_CLIENT_ID=other python3 get_test_token.py
"""

from __future__ import annotations

import argparse
import os
import sys

import requests

# ---------------------------------------------------------------------------
# Defaults (kept aligned with keycloak/test_tokens.py)
# ---------------------------------------------------------------------------

DEFAULT_BASE_URL = "https://XYZ-SNX00000:9443"
DEFAULT_REALM = "TR-10-SEC"
DEFAULT_CLIENT_ID = "Example.Company.Device.Client.ABC.SNX00000.example.com"
DEFAULT_CLIENT_SECRET = "secret"
DEFAULT_CA_BUNDLE = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "Certificates", "build.0", "ExampleRootCA.pem",
))


def fetch_client_credentials_token(
    base_url: str,
    realm: str,
    client_id: str,
    client_secret: str,
    ca_bundle: str,
) -> str:
    """Run the client_credentials grant against Keycloak.

    Returns the access token string. Raises ``RuntimeError`` with a
    descriptive message on any failure (network, non-200, missing
    ``access_token`` field). The caller maps that to stderr + non-zero
    exit; the shell helper then leaves ``NMOS_TESTING_AUTH_TOKEN`` unset.
    """
    url = f"{base_url}/realms/{realm}/protocol/openid-connect/token"
    try:
        resp = requests.post(
            url,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            },
            verify=ca_bundle,
            timeout=10,
        )
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"transport error talking to {url}: {exc}") from exc

    if resp.status_code != 200:
        raise RuntimeError(
            f"token request to {url} returned HTTP {resp.status_code}: "
            f"{resp.text[:300]}"
        )

    try:
        payload = resp.json()
    except ValueError as exc:
        raise RuntimeError(
            f"token endpoint at {url} returned non-JSON body: "
            f"{resp.text[:300]}"
        ) from exc

    token = payload.get("access_token")
    if not token:
        raise RuntimeError(
            f"token endpoint at {url} succeeded but the response carried "
            f"no 'access_token' field: keys={sorted(payload.keys())}"
        )
    return str(token)


def _env_or(name: str, default: str) -> str:
    val = os.environ.get(name)
    return val if val else default


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch an OAuth2 access token from Keycloak via the "
            "client_credentials grant. Defaults target the local Matrox "
            "Keycloak instance with the 'Example.Company.Device.Client.ABC.SNX00000.example.com' service-account client."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--base-url",
        default=_env_or("KEYCLOAK_BASE_URL", DEFAULT_BASE_URL),
        help="Keycloak base URL (env: KEYCLOAK_BASE_URL)",
    )
    parser.add_argument(
        "--realm",
        default=_env_or("KEYCLOAK_REALM", DEFAULT_REALM),
        help="Realm name (env: KEYCLOAK_REALM)",
    )
    parser.add_argument(
        "--client-id",
        default=_env_or("NMOS_TEST_CLIENT_ID", DEFAULT_CLIENT_ID),
        help="OAuth2 client_id (env: NMOS_TEST_CLIENT_ID)",
    )
    parser.add_argument(
        "--client-secret",
        default=_env_or("NMOS_TEST_CLIENT_SECRET", DEFAULT_CLIENT_SECRET),
        help="OAuth2 client_secret (env: NMOS_TEST_CLIENT_SECRET)",
    )
    parser.add_argument(
        "--ca-bundle",
        default=_env_or("REQUESTS_CA_BUNDLE", DEFAULT_CA_BUNDLE),
        help="CA bundle for verifying Keycloak's TLS cert (env: REQUESTS_CA_BUNDLE)",
    )
    args = parser.parse_args(argv)

    try:
        token = fetch_client_credentials_token(
            base_url=args.base_url,
            realm=args.realm,
            client_id=args.client_id,
            client_secret=args.client_secret,
            ca_bundle=args.ca_bundle,
        )
    except RuntimeError as exc:
        print(f"get_test_token: {exc}", file=sys.stderr)
        return 1

    # stdout MUST contain only the bare token; the shell helper does
    # `TOKEN=$(... get_test_token.py)`. Any extra chatter would corrupt
    # the env var. Diagnostics go to stderr.
    print(token)
    return 0


if __name__ == "__main__":
    sys.exit(main())
