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

"""The fake AS's authorization endpoint and user-backed grants.

Covers ``ipmx_fake_as.py``'s ``authorization_code`` flow: the sign-in
form, credential checking, single-use codes, redirect-URI validation,
refresh rotation, and the IS-10 audit trail.

The final section runs the flow end to end against the *real* reference
Controller client from ``nmos-reference``, because that pairing is the
thing that has to work: the Controller discovers this server's endpoints
per RFC 8414 and drives them. Those tests skip cleanly when
``nmos-reference`` is not checked out alongside this directory.

Run with::

    python3 -m pytest test_fake_as_oauth2.py -q
"""

from __future__ import annotations

import ssl
import sys
from dataclasses import replace
import urllib.parse as urlp
from pathlib import Path
from typing import Any, AsyncIterator

import aiohttp
import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestServer

from ipmx_fake_as import (
    AUTHORIZATION_CODE_TTL_SECONDS,
    OperatorAccess,
    FakeASConfig,
    FakeAuthorizationServer,
    GrantType,
    OAuthError,
    RegisteredClient,
    ResponseType,
)

CLIENT_ID = "Example.Company.Device.Client.ABC.SNX00001.example.com"
#: The scope the reference Controller requests (DEFAULT_SCOPES in
#: nmos/controller/oauth2.py). Privilege claims are derived from the
#: granted scope, so a test asserting on x-nmos-streamcompatibility has to
#: ask for streamcompatibility.
CONTROLLER_SCOPE = ("openid node connection streamcompatibility "
                    "channelmapping manufacturer")
CLIENT_SECRET = "secret"
REDIRECT_URI = "https://xyz-snx00001:5050/controller/oauth2/callback"
API_SELECTOR = "realms/TR-10-SEC"
OPERATOR = "tr-10-sec-operator"
PASSWORD = "admin"


# ---------------------------------------------------------------------------
# Plain-HTTP harness
#
# The AS normally terminates TLS itself, which makes it awkward to drive
# from a test. Here the app is mounted on aiohttp's TestServer instead, so
# these cases exercise the handlers without a certificate. The TLS path is
# covered by the end-to-end section at the bottom, which starts the real
# server with the real SNX00000 cert.
# ---------------------------------------------------------------------------

def _config(**overrides: Any) -> FakeASConfig:
    base: dict[str, Any] = dict(
        host="127.0.0.1", port=0,
        cert_chain=Path("/dev/null"), private_key=Path("/dev/null"),
        api_selector=API_SELECTOR,
        clients=(RegisteredClient(
            client_id=CLIENT_ID, client_secret=CLIENT_SECRET,
            redirect_uris=(REDIRECT_URI,),
        ),),
    )
    base.update(overrides)
    return FakeASConfig(**base)


class _Harness:
    """A running fake AS plus a client session pointed at it."""

    def __init__(self, fake: FakeAuthorizationServer, server: TestServer,
                 session: aiohttp.ClientSession) -> None:
        self.fake = fake
        self.server = server
        self.session = session

    def url(self, path: str) -> str:
        return str(self.server.make_url(f"/{API_SELECTOR}{path}"))

    def authorize_params(self, **overrides: str) -> dict[str, str]:
        params = {
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": str(ResponseType.CODE),
            "scope": "openid node connection",
            "state": "state-nonce-abc",
        }
        params.update(overrides)
        return params

    async def sign_in(self, **overrides: str) -> str:
        """Complete a successful authorization and return the code."""
        data = self.authorize_params(**overrides)
        data.update(username=OPERATOR, password=PASSWORD)
        async with self.session.post(
            self.url("/authorize"), data=data, allow_redirects=False,
        ) as resp:
            assert resp.status == 302, await resp.text()
            location = resp.headers["Location"]
        query = dict(urlp.parse_qsl(urlp.urlsplit(location).query))
        return query["code"]


@pytest_asyncio.fixture
async def harness() -> AsyncIterator[_Harness]:
    fake = FakeAuthorizationServer(_config())
    app: web.Application = fake._build_app()  # noqa: SLF001 — test seam
    server = TestServer(app)
    await server.start_server()
    async with aiohttp.ClientSession() as session:
        yield _Harness(fake, server, session)
    await server.close()


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_metadata_advertises_the_authorization_endpoint(
    harness: _Harness,
) -> None:
    """Without this field a conformant client cannot start the flow.

    The client locates the endpoint through metadata only, so an
    unpublished authorization endpoint is an unreachable one.
    """
    async with harness.session.get(
        harness.url("/.well-known/oauth-authorization-server"),
    ) as resp:
        doc = await resp.json()
    assert doc["authorization_endpoint"].endswith(
        f"/{API_SELECTOR}/authorize")


@pytest.mark.asyncio
async def test_metadata_advertises_only_implemented_capabilities(
    harness: _Harness,
) -> None:
    """Advertised grants and response types must all be real.

    ``response_types_supported`` previously claimed ``token`` (the
    implicit grant), which this server has never implemented. A client
    that believed it would have driven a flow that could not complete.
    """
    async with harness.session.get(
        harness.url("/.well-known/oauth-authorization-server"),
    ) as resp:
        doc = await resp.json()
    assert doc["response_types_supported"] == [str(ResponseType.CODE)]
    assert set(doc["grant_types_supported"]) == {
        str(GrantType.CLIENT_CREDENTIALS),
        str(GrantType.AUTHORIZATION_CODE),
        str(GrantType.REFRESH_TOKEN),
    }


# ---------------------------------------------------------------------------
# Authorization endpoint
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_authorize_renders_a_form_carrying_the_request(
    harness: _Harness,
) -> None:
    """The form must round-trip the request parameters.

    The POST that follows has to carry the same ``client_id``,
    ``redirect_uri`` and ``state``; if the form dropped them the code
    would be issued against a different request than the one the user
    approved.
    """
    async with harness.session.get(
        harness.url("/authorize"), params=harness.authorize_params(),
    ) as resp:
        body = await resp.text()
        assert resp.status == 200
    for value in (CLIENT_ID, REDIRECT_URI, "state-nonce-abc"):
        assert value in body


@pytest.mark.asyncio
@pytest.mark.parametrize("username,password", [
    (OPERATOR, "wrong-password"),
    ("wrong-user", PASSWORD),
    ("", ""),
])
async def test_bad_credentials_do_not_issue_a_code(
    harness: _Harness, username: str, password: str,
) -> None:
    """Failed authentication re-renders the form; it never redirects.

    RFC 6749 §4.1.2.1 reserves the error redirect for request-level
    problems. Redirecting on a bad password would also leak, to the
    client, that the endpoint was reached with valid request parameters.
    """
    data = harness.authorize_params()
    data.update(username=username, password=password)
    async with harness.session.post(
        harness.url("/authorize"), data=data, allow_redirects=False,
    ) as resp:
        assert resp.status == 401
        assert "Location" not in resp.headers


@pytest.mark.asyncio
async def test_successful_sign_in_redirects_with_code_and_state(
    harness: _Harness,
) -> None:
    """RFC 6749 §4.1.2: ``state`` is returned unmodified."""
    data = harness.authorize_params()
    data.update(username=OPERATOR, password=PASSWORD)
    async with harness.session.post(
        harness.url("/authorize"), data=data, allow_redirects=False,
    ) as resp:
        assert resp.status == 302
        location = resp.headers["Location"]
    assert location.startswith(REDIRECT_URI)
    query = dict(urlp.parse_qsl(urlp.urlsplit(location).query))
    assert query["state"] == "state-nonce-abc"
    assert query["code"]


@pytest.mark.asyncio
async def test_unregistered_client_gets_an_error_page_not_a_redirect(
    harness: _Harness,
) -> None:
    """IS-10: "MUST NOT grant tokens to unregistered clients".

    And RFC 6749 §4.1.2.1: with an unknown client the server must not
    redirect, because the ``redirect_uri`` has not been validated against
    any registration — bouncing to it would make the AS an open redirector.
    """
    async with harness.session.get(
        harness.url("/authorize"),
        params=harness.authorize_params(client_id="never-registered"),
        allow_redirects=False,
    ) as resp:
        assert resp.status == 400
        assert "Location" not in resp.headers
        assert str(OAuthError.INVALID_CLIENT) in await resp.text()


@pytest.mark.asyncio
@pytest.mark.parametrize("redirect_uri", [
    "https://attacker.example/steal",
    # Prefix of a registered URI — rejected because matching is exact.
    "https://xyz-snx00001:5050/controller/oauth2/callback/../../evil",
    "https://xyz-snx00001:5050/controller/oauth2/callbackX",
    "http://xyz-snx00001:5050/controller/oauth2/callback",
])
async def test_unregistered_redirect_uri_is_refused(
    harness: _Harness, redirect_uri: str,
) -> None:
    """Redirect URIs are matched exactly — no prefixes, no wildcards.

    IS-10 ``Behaviour - Clients.md``: "Redirect URIs MUST be complete
    (fully-qualified) and not use pattern-matching, as this makes them
    susceptible to Redirect URI Validation Attacks".
    """
    async with harness.session.get(
        harness.url("/authorize"),
        params=harness.authorize_params(redirect_uri=redirect_uri),
        allow_redirects=False,
    ) as resp:
        assert resp.status == 400
        assert "Location" not in resp.headers


@pytest.mark.asyncio
async def test_unsupported_response_type_redirects_with_an_error(
    harness: _Harness,
) -> None:
    """Once the redirect URI is trusted, errors go back to the client.

    This is the other half of §4.1.2.1: request problems that arise after
    client and redirect URI check out are reported by redirecting.
    """
    async with harness.session.get(
        harness.url("/authorize"),
        params=harness.authorize_params(response_type="token"),
        allow_redirects=False,
    ) as resp:
        assert resp.status == 302
        location = resp.headers["Location"]
    query = dict(urlp.parse_qsl(urlp.urlsplit(location).query))
    assert query["error"] == str(OAuthError.UNSUPPORTED_RESPONSE_TYPE)
    assert query["state"] == "state-nonce-abc"


# ---------------------------------------------------------------------------
# Token endpoint — authorization_code
# ---------------------------------------------------------------------------

async def _exchange(harness: _Harness, code: str, **overrides: str) -> Any:
    data = {
        "grant_type": str(GrantType.AUTHORIZATION_CODE),
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    data.update(overrides)
    async with harness.session.post(harness.url("/token"), data=data) as resp:
        return resp.status, await resp.json()


@pytest.mark.asyncio
async def test_code_exchange_returns_access_and_refresh_tokens(
    harness: _Harness,
) -> None:
    """The Controller reads ``refresh_token`` unconditionally.

    Returning only an access token would raise a ``KeyError`` inside the
    client rather than a protocol error, so its presence is load-bearing.
    """
    status, payload = await _exchange(harness, await harness.sign_in())
    assert status == 200, payload
    assert payload["access_token"]
    assert payload["refresh_token"]
    assert payload["token_type"] == "Bearer"


@pytest.mark.asyncio
async def test_code_is_single_use(harness: _Harness) -> None:
    """RFC 6749 §4.1.2: an authorization code must not be replayable."""
    code = await harness.sign_in()
    first_status, _ = await _exchange(harness, code)
    assert first_status == 200
    second_status, payload = await _exchange(harness, code)
    assert second_status == 400
    assert payload["error"] == str(OAuthError.INVALID_GRANT)


@pytest.mark.asyncio
async def test_expired_code_is_refused(harness: _Harness) -> None:
    """Codes are short-lived; an aged one is no longer redeemable."""
    code = await harness.sign_in()
    record = harness.fake._codes[code]  # noqa: SLF001 — test seam
    record.expires_at -= AUTHORIZATION_CODE_TTL_SECONDS + 1
    status, payload = await _exchange(harness, code)
    assert status == 400
    assert payload["error"] == str(OAuthError.INVALID_GRANT)


@pytest.mark.asyncio
async def test_redirect_uri_must_match_the_authorization_request(
    harness: _Harness,
) -> None:
    """RFC 6749 §4.1.3 requires the two redirect URIs to be identical."""
    code = await harness.sign_in()
    status, payload = await _exchange(
        harness, code, redirect_uri="https://xyz-snx00001:5050/other")
    assert status == 400
    assert payload["error"] == str(OAuthError.INVALID_GRANT)


@pytest.mark.asyncio
@pytest.mark.parametrize("secret", ["wrong-secret", ""])
async def test_bad_client_secret_is_refused(
    harness: _Harness, secret: str,
) -> None:
    """Client authentication is enforced at the token endpoint."""
    code = await harness.sign_in()
    status, payload = await _exchange(harness, code, client_secret=secret)
    assert status == 401
    assert payload["error"] == str(OAuthError.INVALID_CLIENT)


@pytest.mark.asyncio
async def test_http_basic_client_authentication_is_accepted(
    harness: _Harness,
) -> None:
    """IS-10 requires ``client_secret_basic`` support at the token endpoint."""
    code = await harness.sign_in()
    async with harness.session.post(
        harness.url("/token"),
        data={
            "grant_type": str(GrantType.AUTHORIZATION_CODE),
            "code": code, "redirect_uri": REDIRECT_URI,
        },
        auth=aiohttp.BasicAuth(CLIENT_ID, CLIENT_SECRET),
    ) as resp:
        assert resp.status == 200, await resp.text()
        assert (await resp.json())["access_token"]


@pytest.mark.asyncio
async def test_unsupported_grant_type_is_reported(harness: _Harness) -> None:
    async with harness.session.post(
        harness.url("/token"),
        data={"grant_type": "password", "client_id": CLIENT_ID},
    ) as resp:
        assert resp.status == 400
        assert (await resp.json())["error"] == \
            str(OAuthError.UNSUPPORTED_GRANT_TYPE)


@pytest.mark.asyncio
async def test_client_credentials_grant_still_works(harness: _Harness) -> None:
    """The original fixture behaviour must survive.

    The validator's Stage 1 runs depend on this endpoint's previous
    shape; adding grants must not disturb it.
    """
    async with harness.session.post(
        harness.url("/token"),
        data={"grant_type": str(GrantType.CLIENT_CREDENTIALS),
              "client_id": CLIENT_ID},
    ) as resp:
        assert resp.status == 200
        payload = await resp.json()
    assert payload["access_token"]
    assert payload["token_type"] == "Bearer"


@pytest.mark.asyncio
async def test_client_credentials_defaults_when_grant_type_omitted(
    harness: _Harness,
) -> None:
    """A bare POST behaves as it did before grants were dispatched."""
    async with harness.session.post(
        harness.url("/token"), data={"client_id": CLIENT_ID},
    ) as resp:
        assert resp.status == 200
        assert (await resp.json())["access_token"]


# ---------------------------------------------------------------------------
# Token endpoint — refresh_token
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_refresh_rotates_and_invalidates_the_old_token(
    harness: _Harness,
) -> None:
    """IS-10: clients "MUST discard any old Refresh Tokens once a new
    Refresh Token is issued". Rotation is what makes that enforceable
    rather than advisory."""
    _, first = await _exchange(harness, await harness.sign_in())

    async def refresh(token: str) -> tuple[int, Any]:
        async with harness.session.post(harness.url("/token"), data={
            "grant_type": str(GrantType.REFRESH_TOKEN),
            "refresh_token": token,
            "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
        }) as resp:
            return resp.status, await resp.json()

    status, second = await refresh(first["refresh_token"])
    assert status == 200, second
    assert second["refresh_token"] != first["refresh_token"]
    assert second["access_token"] != first["access_token"]

    replay_status, payload = await refresh(first["refresh_token"])
    assert replay_status == 400
    assert payload["error"] == str(OAuthError.INVALID_GRANT)


# ---------------------------------------------------------------------------
# Audit trail — IS-10 Behaviour - Authorization Servers.md
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_audit_log_records_events_without_secrets(
    harness: _Harness,
) -> None:
    """IS-10 § Audit Requirements.

    "Logs MUST include an accurate timestamp and an identifier for the
    user who authorized the action. Logs MUST NOT contain sensitive
    information such as secrets."
    """
    denied = harness.authorize_params()
    denied.update(username=OPERATOR, password="wrong")
    async with harness.session.post(
        harness.url("/authorize"), data=denied, allow_redirects=False,
    ):
        pass
    code = await harness.sign_in()
    await _exchange(harness, code)

    log = harness.fake.audit_log
    events = [entry["event"] for entry in log]
    assert "authorization_denied" in events
    assert "authorization_granted" in events
    assert "token_issued" in events
    assert all(entry["timestamp"] for entry in log)
    assert any(entry["subject"] == OPERATOR for entry in log)

    blob = str(log)
    assert PASSWORD not in blob
    assert CLIENT_SECRET not in blob
    assert code not in blob


# ---------------------------------------------------------------------------
# End to end against the real reference Controller
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent
_NMOS_REFERENCE = _REPO_ROOT / "nmos-reference"
_CERTS = _NMOS_REFERENCE / "Certificates/build.0"
_CA = _CERTS / "ExampleRootCA.pem"
_AS_CERT = _CERTS / "pem/ExampleDeviceServer.ABC.SNX00000.chain.pem"
_AS_KEY = _CERTS / "key/ExampleDeviceServer.ABC.SNX00000.key"

_HAVE_E2E = all(p.exists() for p in (_NMOS_REFERENCE, _CA, _AS_CERT, _AS_KEY))
_e2e = pytest.mark.skipif(
    not _HAVE_E2E,
    reason="nmos-reference checkout with Certificates/build.0 not available",
)


@pytest_asyncio.fixture
async def live_as() -> AsyncIterator[tuple[FakeAuthorizationServer, str]]:
    """The real AS over TLS with the SNX00000 certificate, as deployed."""
    host, port = "XYZ-SNX00000", 19444
    config = _config(host=host, port=port,
                     cert_chain=_AS_CERT, private_key=_AS_KEY)
    fake = FakeAuthorizationServer(config)
    fake.default_aud_entry = "XYZ-SNX00001"
    await fake.start()
    try:
        yield fake, config.issuer
    finally:
        await fake.stop()


@_e2e
@pytest.mark.asyncio
async def test_reference_controller_completes_the_whole_flow(
    live_as: tuple[FakeAuthorizationServer, str],
) -> None:
    """Discovery, sign-in, code exchange, and refresh, with real code both ends.

    This is the tutorial's critical path. The Controller finds this
    server purely through its metadata document — nothing here imitates
    Keycloak's URL layout — then validates the returned token against the
    discovered JWKS using the Node's own validator.
    """
    if str(_NMOS_REFERENCE) not in sys.path:
        sys.path.insert(0, str(_NMOS_REFERENCE))
    from nmos.controller.oauth2 import OAuth2Client, OAuth2Config

    fake, issuer = live_as
    client = OAuth2Client(OAuth2Config(
        issuer=issuer, client_id=CLIENT_ID, client_secret=CLIENT_SECRET,
        api_selector=API_SELECTOR, ca_bundle=(str(_CA),),
    ))

    # 1. Discovery resolves to this server's own layout.
    auth_endpoint = await client.authorization_endpoint()
    assert auth_endpoint == f"{issuer}/authorize"
    assert "protocol/openid-connect" not in auth_endpoint

    # 2. The browser leg: fetch the form, submit the pre-canned operator.
    state = client.new_state_nonce()
    auth_url = await client.build_auth_url(
        redirect_uri=REDIRECT_URI, state=state)
    assert auth_url.startswith(auth_endpoint)

    ssl_ctx = ssl.create_default_context(cafile=str(_CA))
    connector = aiohttp.TCPConnector(ssl=ssl_ctx)
    async with aiohttp.ClientSession(connector=connector) as session:
        form = dict(urlp.parse_qsl(urlp.urlsplit(auth_url).query))
        form.update(username=OPERATOR, password=PASSWORD)
        async with session.post(
            auth_url.split("?")[0], data=form, allow_redirects=False,
        ) as resp:
            assert resp.status == 302, await resp.text()
            location = resp.headers["Location"]
    query = dict(urlp.parse_qsl(urlp.urlsplit(location).query))
    assert query["state"] == state

    # 3. The Controller exchanges the code and verifies the signature
    #    against the discovered JWKS.
    tokens = await client.exchange_code(
        code=query["code"], redirect_uri=REDIRECT_URI)
    assert tokens.claims["sub"] == OPERATOR, \
        "the token should name the user who signed in, not a synthetic subject"
    assert tokens.claims["azp"] == CLIENT_ID
    assert any("SNX00001" in entry for entry in tokens.claims["aud"]), \
        "aud must cover the node serial or the Controller marks it unreachable"

    # 4. Refresh yields a genuinely different token.
    rolled = await client.refresh(refresh_token=tokens.refresh_token)
    assert rolled.access_token != tokens.access_token
    assert rolled.claims["sub"] == OPERATOR

    assert any(e["event"] == "token_issued" for e in fake.audit_log)


# ---------------------------------------------------------------------------
# Privilege claims — the token must authorise what the operator signed in to do
# ---------------------------------------------------------------------------
#
# These exist because of a real escape. The suite tested the *Node's*
# enforcement of ``x-nmos-*`` privileges thoroughly, but never the AS's ability
# to *issue* a token carrying them: nothing in the validator fetches a token
# from ``/token`` — it mints its own with ``mint_token``. So the token endpoint
# had no test coverage of its claim set, and the ``authorization_code`` grant
# shipped issuing read-only tokens. The Controller displayed every Node
# happily and then failed every configuration call with 403 "insufficient
# permissions".
#
# The assertions below run the AS's real tokens through the reference Node's
# real access check, which is the only thing that settles it.


def _decode(token: str) -> dict[str, Any]:
    """Claims of a JWT, without verifying the signature.

    Safe here: the token was just minted by the fixture under test, and these
    cases are about the claim set rather than the cryptography.
    """
    import base64
    import json
    payload = token.split(".")[1]
    return dict(json.loads(
        base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))))


@pytest.mark.asyncio
async def test_token_carries_write_privileges_by_default(
    harness: _Harness,
) -> None:
    """An operator signing in to operate the system gets write privileges.

    "NMOS With OAuth2.0" § Validation: "The absence of a `write` attribute
    prevents Write access." A scope-only token is therefore read-only, and a
    Controller holding one cannot configure anything.
    """
    _, payload = await _exchange(harness, await harness.sign_in(scope=CONTROLLER_SCOPE))
    ext = _decode(payload["access_token"]).get("ext", {})
    assert ext, "no ext claim: the token would authorise reads only"
    for api in ("node", "connection", "streamcompatibility"):
        grant = ext[f"x-nmos-{api}"]
        assert grant["write"] == ["*"], f"x-nmos-{api} does not grant write"
        # Read must be present too: the same section says the presence of an
        # x-nmos-* claim removes the scope's default read, and that write
        # requires read. Emitting write alone would revoke read.
        assert grant["read"] == ["*"], f"x-nmos-{api} would revoke read access"


@pytest.mark.asyncio
async def test_openid_scope_gets_no_privilege_claim(
    harness: _Harness,
) -> None:
    """``openid`` is an OIDC scope, not an NMOS API."""
    _, payload = await _exchange(harness, await harness.sign_in(scope=CONTROLLER_SCOPE))
    ext = _decode(payload["access_token"]).get("ext", {})
    assert "x-nmos-openid" not in ext


@pytest.mark.asyncio
async def test_read_only_operator_is_denied_write(
    harness: _Harness,
) -> None:
    """``--operator-access read`` issues a genuinely read-only token."""
    harness.fake._config = replace(  # noqa: SLF001 — test seam
        harness.fake._config, operator_access=OperatorAccess.READ)
    _, payload = await _exchange(harness, await harness.sign_in(scope=CONTROLLER_SCOPE))
    ext = _decode(payload["access_token"]).get("ext", {})
    for api in ("node", "connection", "streamcompatibility"):
        grant = ext[f"x-nmos-{api}"]
        assert grant["read"] == ["*"]
        assert "write" not in grant


@_e2e
@pytest.mark.asyncio
@pytest.mark.parametrize("access,expect_write", [
    (OperatorAccess.READ_WRITE, True),
    (OperatorAccess.READ, False),
])
async def test_reference_node_grants_what_the_token_claims(
    harness: _Harness, access: OperatorAccess, expect_write: bool,
) -> None:
    """The decisive check: the reference Node's own access-control function.

    ``validate_access`` is what produced the 403s, so it is what has to agree.
    Read must be allowed in both configurations; write only when the token
    says so.
    """
    if str(_NMOS_REFERENCE) not in sys.path:
        sys.path.insert(0, str(_NMOS_REFERENCE))
    from nmos.oauth2 import validate_access

    harness.fake._config = replace(  # noqa: SLF001 — test seam
        harness.fake._config, operator_access=access)
    harness.fake.default_aud_entry = "XYZ-SNX00001"
    _, payload = await _exchange(harness, await harness.sign_in(scope=CONTROLLER_SCOPE))
    claims = _decode(payload["access_token"])

    for api in ("node", "connection", "streamcompatibility"):
        read_ok, valid = validate_access(
            claims, False, api, "SNX00001", ["XYZ-SNX00001"])
        assert valid and read_ok, f"read denied for {api}"

        write_ok, valid = validate_access(
            claims, True, api, "SNX00001", ["XYZ-SNX00001"])
        assert valid, f"token judged invalid for {api}"
        assert write_ok is expect_write, (
            f"{api}: write allowed={write_ok}, expected {expect_write}")
