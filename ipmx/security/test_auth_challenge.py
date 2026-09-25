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

"""The WWW-Authenticate challenge rule the validator applies to refusals.

Covers ``ipmx_security_probes.parse_www_authenticate`` (RFC 9110 §11
syntax), ``auth_challenge_problem`` (RFC 9110 §15.5.2 for every 401,
RFC 6750 §3 for the Bearer challenge on OAuth 2.0 401/403 refusals), and
the ``HttpResponse`` plumbing that keeps every WWW-Authenticate value.

Run with::

    python3 -m pytest test_auth_challenge.py -q
"""

from __future__ import annotations

from typing import AsyncIterator

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestServer

from ipmx_security_probes import (
    HttpResponse, SecurityHttpClient, auth_challenge_problem,
    parse_www_authenticate,
)


# ---------------------------------------------------------------------------
# parse_www_authenticate — RFC 9110 §11.2 / §11.3 / §11.6.1
# ---------------------------------------------------------------------------

def test_rfc6750_expired_token_example() -> None:
    value = ('Bearer realm="example", error="invalid_token", '
             'error_description="The access token expired"')
    assert parse_www_authenticate(value) == [
        ("bearer", {"realm": "example", "error": "invalid_token",
                    "error_description": "The access token expired"}),
    ]


def test_rfc9110_two_challenge_example() -> None:
    value = 'Basic realm="simple", Newauth realm="apps", type=1, title="Login to \\"apps\\""'
    assert parse_www_authenticate(value) == [
        ("basic", {"realm": "simple"}),
        ("newauth", {"realm": "apps", "type": "1", "title": 'Login to "apps"'}),
    ]


def test_scheme_and_names_are_case_insensitive() -> None:
    assert parse_www_authenticate('bearer Realm="x", ERROR=invalid_token') == [
        ("bearer", {"realm": "x", "error": "invalid_token"}),
    ]


def test_whitespace_empty_elements_and_quoted_commas() -> None:
    value = 'Bearer , realm = "a, b" ,, error = "invalid_token"'
    assert parse_www_authenticate(value) == [
        ("bearer", {"realm": "a, b", "error": "invalid_token"}),
    ]


def test_token68_challenge_has_no_auth_params() -> None:
    assert parse_www_authenticate("Negotiate abc123==") == [("negotiate", {})]


# ---------------------------------------------------------------------------
# auth_challenge_problem — RFC 9110 §15.5.2, RFC 6750 §3
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("status,value", [
    (401, 'Bearer realm="nmos-oauth2"'),
    (401, 'Bearer realm="nmos-oauth2", error="invalid_token"'),
    (403, 'Bearer realm="nmos-oauth2", error="insufficient_scope"'),
    (403, 'Basic realm="x", Bearer error="insufficient_scope"'),
])
def test_bearer_refusal_with_a_bearer_challenge_passes(status: int, value: str) -> None:
    assert auth_challenge_problem(status, value, bearer_required=True) is None


@pytest.mark.parametrize("status,value", [
    (401, None),
    (403, None),
    (403, ""),
    (401, 'Basic realm="x"'),
])
def test_bearer_refusal_without_a_bearer_challenge_fails(
    status: int, value: str | None,
) -> None:
    problem = auth_challenge_problem(status, value, bearer_required=True)
    assert problem is not None
    assert f"HTTP {status}" in problem and "Bearer" in problem and "RFC 6750" in problem


def test_non_bearer_401_needs_some_challenge() -> None:
    assert auth_challenge_problem(401, 'Basic realm="x"', bearer_required=False) is None
    problem = auth_challenge_problem(401, None, bearer_required=False)
    assert problem is not None and "RFC 9110" in problem


def test_non_bearer_403_needs_no_challenge() -> None:
    assert auth_challenge_problem(403, None, bearer_required=False) is None


@pytest.mark.parametrize("status", [200, 101, 404, None])
def test_statuses_other_than_401_403_are_not_refusals(status: int | None) -> None:
    assert auth_challenge_problem(status, None, bearer_required=True) is None


# ---------------------------------------------------------------------------
# HttpResponse — every WWW-Authenticate value reaches the rule
# ---------------------------------------------------------------------------

def test_header_lookup_is_case_insensitive() -> None:
    resp = HttpResponse(status=401, headers={"www-authenticate": 'Bearer realm="x"'})
    assert resp.header("WWW-Authenticate") == 'Bearer realm="x"'
    assert resp.header("Retry-After") is None


async def _two_challenges(_request: web.Request) -> web.Response:
    response = web.Response(status=401)
    response.headers.add("WWW-Authenticate", 'Basic realm="simple"')
    response.headers.add("WWW-Authenticate", 'Bearer realm="api", error="invalid_token"')
    return response


@pytest_asyncio.fixture
async def challenge_server() -> AsyncIterator[TestServer]:
    app = web.Application()
    app.router.add_get("/", _two_challenges)
    server = TestServer(app)
    await server.start_server()
    yield server
    await server.close()


@pytest.mark.asyncio
async def test_repeated_www_authenticate_fields_are_all_kept(
    challenge_server: TestServer,
) -> None:
    async with SecurityHttpClient() as client:
        resp = await client.get(str(challenge_server.make_url("/")))
    assert resp.status == 401
    value = resp.header("WWW-Authenticate")
    assert value is not None
    assert [scheme for scheme, _ in parse_www_authenticate(value)] == ["basic", "bearer"]
    assert auth_challenge_problem(resp.status, value, bearer_required=True) is None
