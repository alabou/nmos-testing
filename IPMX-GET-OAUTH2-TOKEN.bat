@echo off
REM
REM Call this script to fetch a fresh Keycloak access token and set it
REM as NMOS_TESTING_AUTH_TOKEN in the calling environment.
REM IPMX-testing\nmostesting\UserConfig.py reads that env var into
REM CONFIG.AUTH_TOKEN; the *.bat test wrappers inherit it transparently.
REM
REM Atomic semantics: the prior value of NMOS_TESTING_AUTH_TOKEN is
REM cleared BEFORE the fetch is attempted. If the fetch fails, the env
REM var stays unset.
REM
REM Usage:
REM   call IPMX-GET-OAUTH2-TOKEN.bat
REM
REM Re-callable any time to refresh the token (Keycloak access tokens
REM default to a 5-minute lifespan).

REM Step 1 — invalidate any prior token first.
set "NMOS_TESTING_AUTH_TOKEN="

REM Step 2 — fetch. stdout carries the bare token on success; stderr
REM carries diagnostics on failure. We need to capture stdout into the
REM env var while letting stderr surface as usual.
for /f "usebackq tokens=* delims=" %%T in (`python3 "%~dp0..\keycloak\get_test_token.py"`) do (
    set "NMOS_TESTING_AUTH_TOKEN=%%T"
)

if not defined NMOS_TESTING_AUTH_TOKEN (
    echo IPMX-GET-OAUTH2-TOKEN: failed to acquire OAuth2 token; NMOS_TESTING_AUTH_TOKEN left unset 1>&2
    exit /b 1
)

echo IPMX-GET-OAUTH2-TOKEN: token acquired (NMOS_TESTING_AUTH_TOKEN exported) 1>&2
exit /b 0
