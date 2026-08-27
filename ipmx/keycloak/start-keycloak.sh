#!/bin/bash
#
# Start Keycloak in dev mode over HTTPS using the SNX00000 server cert
# bundled at ../Certificates/build.0/. Server-auth-only (no mTLS on the
# OAuth2 endpoint for now). The cert SAN includes XYZ-SNX00000 and
# XYZ-SNX00000.local so resolve at least the bare name in /etc/hosts.
#
# Default flavor: in-container DB, wiped on rm. Volume-mounted variant
# below preserves realm state across rm.

set -e

cd "$(dirname "$0")"

CERT_DIR_HOST="$(cd ../Certificates/build.0 && pwd)"
CERT_DIR_CT="/certs"
CERT_PEM="$CERT_DIR_CT/pem/ExampleDeviceServer.ABC.SNX00000.chain.pem"
CERT_KEY="$CERT_DIR_CT/key/ExampleDeviceServer.ABC.SNX00000.key"

docker rm -f keycloak >/dev/null 2>&1 || true

docker run -d --name keycloak \
  -p 9443:9443 \
  -v "$CERT_DIR_HOST":"$CERT_DIR_CT":ro \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -e KC_FEATURES=scripts \
  -e KC_HTTP_ENABLED=false \
  -e KC_HTTPS_PORT=9443 \
  -e KC_HTTPS_CERTIFICATE_FILE="$CERT_PEM" \
  -e KC_HTTPS_CERTIFICATE_KEY_FILE="$CERT_KEY" \
  -e KC_HOSTNAME=XYZ-SNX00000 \
  -e KC_HOSTNAME_STRICT=false \
  quay.io/keycloak/keycloak:latest \
  start-dev

echo "keycloak starting on https://XYZ-SNX00000:9443/"
echo "  cert: $CERT_PEM"
echo "  key:  $CERT_KEY"
echo "  CA:   $CERT_DIR_HOST/ExampleRootCA.pem (use with curl --cacert)"

# Block until Keycloak's /master/.well-known/openid-configuration
# returns 200. The container starts in the background (``-d`` above)
# but the JVM + Quarkus warm-up takes ~20s on a fresh boot; without
# this gate, the next command in the operator's workflow (typically
# ``nmos_keycloak.py init``) fires before Keycloak is listening and
# fails with "Cannot connect". 90s is long enough for a cold boot
# on a slow box but short enough to flag a real problem.
ROOT_CA="$CERT_DIR_HOST/ExampleRootCA.pem"
URL="https://XYZ-SNX00000:9443/realms/master/.well-known/openid-configuration"
echo -n "  waiting for Keycloak to become ready ..."
for i in $(seq 1 45); do
    if curl -sS --cacert "$ROOT_CA" --max-time 2 -o /dev/null -w '%{http_code}' "$URL" 2>/dev/null | grep -q '^200$'; then
        echo " ready (~$((i*2))s)"
        exit 0
    fi
    sleep 2
    echo -n "."
done
echo
echo "ERROR: Keycloak did not become ready within 90s — check 'docker logs keycloak'." >&2
exit 1

# Persistent-state variant — uncomment to preserve realm/users/clients
# across `docker rm`. Add the same -v $CERT_DIR_HOST:$CERT_DIR_CT:ro
# mount + the same KC_HTTPS_* env vars.
#
# docker run -d --name keycloak \
#   -p 9443:9443 \
#   -v keycloak_data:/opt/keycloak/data \
#   -v "$CERT_DIR_HOST":"$CERT_DIR_CT":ro \
#   -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
#   -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
#   -e KC_FEATURES=scripts \
#   -e KC_HTTP_ENABLED=false \
#   -e KC_HTTPS_PORT=9443 \
#   -e KC_HTTPS_CERTIFICATE_FILE="$CERT_PEM" \
#   -e KC_HTTPS_CERTIFICATE_KEY_FILE="$CERT_KEY" \
#   -e KC_HOSTNAME=XYZ-SNX00000 \
#   -e KC_HOSTNAME_STRICT=false \
#   quay.io/keycloak/keycloak:latest \
#   start-dev
