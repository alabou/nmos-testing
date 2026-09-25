#!/bin/bash
#
# Stop and remove a Keycloak container started by start-keycloak.sh.
#
#   stop-keycloak.sh [--tct=T]
#
#   --tct=T   TLS Certificate Type of the instance: 0=RSA (default) --
#             container "keycloak"; 1=ECDSA -- container "keycloak-ec".
#
# Idempotent: ``docker rm -f`` is a no-op when the container is already
# gone. The container ships its DB inside its writable layer when
# launched via the default form in start-keycloak.sh, so removing it
# wipes the realm/users/clients state too — re-run start-keycloak.sh
# + ./nmos_keycloak.py init to rebuild scaffolding from scratch.
#
# When the persistent-db flavor in start-keycloak.sh is used (the
# commented-out volume-mounted form), the realm survives ``docker rm``;
# the named volume ``<container>_data`` is preserved. To wipe persistent
# state too, run:  docker volume rm keycloak_data   (or keycloak-ec_data)

set -e

TCT=0
for arg in "$@"; do
  case "$arg" in
    --tct=*) TCT="${arg#*=}" ;;
    *) echo "$(basename "$0"): unknown arg $arg" >&2; exit 64 ;;
  esac
done

case "$TCT" in
  0) NAME=keycloak ;;
  1) NAME=keycloak-ec ;;
  2) echo "$(basename "$0"): --tct=2 (Both) is not available for Keycloak;" \
          "an instance serves one certificate type. Stop --tct=0 and/or --tct=1." >&2
     exit 64 ;;
  *) echo "$(basename "$0"): unsupported --tct=$TCT" >&2; exit 64 ;;
esac

if docker ps -a --format '{{.Names}}' | grep -q "^${NAME}\$"; then
    # The ECDSA instance carries the directory holding its PKCS#8 key copy
    # as a label (see start-keycloak.sh); remove it with the container.
    KEY_DIR="$(docker inspect -f '{{index .Config.Labels "ipmx.keycloak.keydir"}}' "$NAME" 2>/dev/null || true)"
    echo "Stopping $NAME container ..."
    docker rm -f "$NAME" >/dev/null
    case "$KEY_DIR" in
      */keycloak-ec-key.*) [ -d "$KEY_DIR" ] && rm -rf "$KEY_DIR" ;;
    esac
    echo "Stopped."
else
    echo "No '$NAME' container — nothing to stop."
fi
