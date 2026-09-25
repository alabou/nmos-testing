#!/bin/bash
#
# Start Keycloak in dev mode over HTTPS using an SNX00000 server cert
# bundled at ../Certificates/build.0/. Server-auth-only (no mTLS on the
# OAuth2 endpoint for now). The cert SAN includes XYZ-SNX00000 and
# XYZ-SNX00000.local so resolve at least the bare name in /etc/hosts.
#
#   start-keycloak.sh [--tct=T]
#
#   --tct=T   TLS Certificate Type: 0=RSA (default) -- container "keycloak",
#             port 9443; 1=ECDSA -- container "keycloak-ec", port 9445.
#
# A Node trusts only the root of its own TLS Certificate Type (TR-10-SEC
# §12.5: the TCT is common to all certificates and Root CAs of the device),
# so a TCT=1 (ECDSA) Node can only use the ECDSA instance; a TCT=0 Node uses
# the RSA one and a TCT=2 Node accepts either. The two run side by side.
#
# Default flavor: in-container DB, wiped on rm. Volume-mounted variant
# below preserves realm state across rm.

set -e

cd "$(dirname "$0")"

TCT=0
for arg in "$@"; do
  case "$arg" in
    --tct=*) TCT="${arg#*=}" ;;
    *) echo "$(basename "$0"): unknown arg $arg" >&2; exit 64 ;;
  esac
done

# "" for RSA, ".ec" for ECDSA -- the infix this PKI uses for the ECDSA
# generation of an identity.
case "$TCT" in
  0) NAME=keycloak;    PORT=9443; TCT_INFIX="" ;;
  1) NAME=keycloak-ec; PORT=9445; TCT_INFIX=".ec" ;;
  # One instance serves one certificate type; TR-10-SEC's "Both" is a Node
  # posture, and a TCT=2 Node accepts either instance.
  2) echo "$(basename "$0"): --tct=2 (Both) is not available for Keycloak;" \
          "an instance serves one certificate type. Start --tct=0 and/or" \
          "--tct=1 -- a TCT=2 Node accepts either." >&2
     exit 64 ;;
  *) echo "$(basename "$0"): unsupported --tct=$TCT" >&2; exit 64 ;;
esac

CERT_DIR_HOST="$(cd ../Certificates/build.0 && pwd)"
CERT_DIR_CT="/certs"
KEY_DIR_CT="/certs-key"
CERT_PEM="$CERT_DIR_CT/pem/ExampleDeviceServer.ABC.SNX00000.chain${TCT_INFIX}.pem"
KEY_NAME="ExampleDeviceServer.ABC.SNX00000${TCT_INFIX}.key"
CERT_KEY="$KEY_DIR_CT/$KEY_NAME"
ROOT_CA="$CERT_DIR_HOST/ExampleRootCA${TCT_INFIX}.pem"

KEY_DIR_HOST="$CERT_DIR_HOST/key"
LABELS=()
if [ -n "$TCT_INFIX" ]; then
  # The ECDSA key ships in SEC1 form ("BEGIN EC PRIVATE KEY"). Hand Keycloak
  # the PKCS#8 form ("BEGIN PRIVATE KEY") the RSA key already uses, so both
  # instances load their key the same way; the PKI itself is left untouched.
  # The copy lives in a mktemp directory recorded on the container as a label,
  # which stop-keycloak.sh reads to remove it.
  KEY_DIR_HOST="$(mktemp -d -t keycloak-ec-key.XXXXXX)"
  openssl pkcs8 -topk8 -nocrypt \
    -in "$CERT_DIR_HOST/key/$KEY_NAME" -out "$KEY_DIR_HOST/$KEY_NAME"
  # The container runs Keycloak as a non-root user.
  chmod 755 "$KEY_DIR_HOST"
  chmod 644 "$KEY_DIR_HOST/$KEY_NAME"
  LABELS=(--label "ipmx.keycloak.keydir=$KEY_DIR_HOST")
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true

docker run -d --name "$NAME" \
  "${LABELS[@]}" \
  -p "$PORT:$PORT" \
  -v "$CERT_DIR_HOST":"$CERT_DIR_CT":ro \
  -v "$KEY_DIR_HOST":"$KEY_DIR_CT":ro \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -e KC_FEATURES=scripts \
  -e KC_HTTP_ENABLED=false \
  -e KC_HTTPS_PORT="$PORT" \
  -e KC_HTTPS_CERTIFICATE_FILE="$CERT_PEM" \
  -e KC_HTTPS_CERTIFICATE_KEY_FILE="$CERT_KEY" \
  -e KC_HOSTNAME=XYZ-SNX00000 \
  -e KC_HOSTNAME_STRICT=false \
  quay.io/keycloak/keycloak:latest \
  start-dev

echo "$NAME starting on https://XYZ-SNX00000:$PORT/"
echo "  cert: $CERT_PEM"
echo "  key:  $CERT_KEY"
echo "  CA:   $ROOT_CA (use with curl --cacert)"

# Block until Keycloak's /master/.well-known/openid-configuration
# returns 200. The container starts in the background (``-d`` above)
# but the JVM + Quarkus warm-up takes ~20s on a fresh boot; without
# this gate, the next command in the operator's workflow (typically
# ``nmos_keycloak.py init``) fires before Keycloak is listening and
# fails with "Cannot connect". 90s is long enough for a cold boot
# on a slow box but short enough to flag a real problem.
URL="https://XYZ-SNX00000:$PORT/realms/master/.well-known/openid-configuration"
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
echo "ERROR: Keycloak did not become ready within 90s — check 'docker logs $NAME'." >&2
exit 1

# Persistent-state variant — uncomment to preserve realm/users/clients
# across `docker rm`. Add the same -v mounts + the same KC_HTTPS_* env
# vars; one named volume per flavour.
#
# docker run -d --name "$NAME" \
#   "${LABELS[@]}" \
#   -p "$PORT:$PORT" \
#   -v "${NAME}_data":/opt/keycloak/data \
#   -v "$CERT_DIR_HOST":"$CERT_DIR_CT":ro \
#   -v "$KEY_DIR_HOST":"$KEY_DIR_CT":ro \
#   -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
#   -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
#   -e KC_FEATURES=scripts \
#   -e KC_HTTP_ENABLED=false \
#   -e KC_HTTPS_PORT="$PORT" \
#   -e KC_HTTPS_CERTIFICATE_FILE="$CERT_PEM" \
#   -e KC_HTTPS_CERTIFICATE_KEY_FILE="$CERT_KEY" \
#   -e KC_HOSTNAME=XYZ-SNX00000 \
#   -e KC_HOSTNAME_STRICT=false \
#   quay.io/keycloak/keycloak:latest \
#   start-dev
