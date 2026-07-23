#!/bin/bash
#
# Source this script to fetch a fresh Keycloak access token and export it
# as NMOS_TESTING_AUTH_TOKEN. IPMX-testing/nmostesting/UserConfig.py reads
# that env var into CONFIG.AUTH_TOKEN; the 47 *.sh test wrappers inherit
# it transparently.
#
# Atomic semantics: the prior value of NMOS_TESTING_AUTH_TOKEN is
# unset BEFORE the fetch is attempted. If the fetch fails, the env var
# stays unset — no stale token from a previous successful source
# pretends to be current.
#
# Usage:
#   source ./IPMX-GET-OAUTH2-TOKEN.sh
#   source ./IPMX-GET-OAUTH2-TOKEN.sh || echo "auth failed"
#
# Re-sourceable any time to refresh the token (Keycloak access tokens
# default to a 5-minute lifespan).

# Path to this script's directory, resolved via BASH_SOURCE so the
# helper works regardless of the operator's current working directory.
_GET_TOKEN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Step 1 — invalidate any prior token first. If the Python fetch then
# fails, the env var is gone and UserConfig.py's fail-fast guard catches
# the next test run immediately instead of consuming a dead token.
unset NMOS_TESTING_AUTH_TOKEN

# Step 2 — fetch. stdout carries the bare token on success; stderr
# carries diagnostics on failure.
_GET_TOKEN_OUT="$("$_GET_TOKEN_DIR/../keycloak/get_test_token.py")"
_GET_TOKEN_RC=$?

if [ "$_GET_TOKEN_RC" -ne 0 ] || [ -z "$_GET_TOKEN_OUT" ]; then
    echo "IPMX-GET-OAUTH2-TOKEN: failed to acquire OAuth2 token; NMOS_TESTING_AUTH_TOKEN left unset" >&2
    unset _GET_TOKEN_DIR _GET_TOKEN_OUT _GET_TOKEN_RC
    return 1
fi

export NMOS_TESTING_AUTH_TOKEN="$_GET_TOKEN_OUT"
echo "IPMX-GET-OAUTH2-TOKEN: token acquired (NMOS_TESTING_AUTH_TOKEN exported)" >&2

unset _GET_TOKEN_DIR _GET_TOKEN_OUT _GET_TOKEN_RC
return 0
