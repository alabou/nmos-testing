#!/bin/bash
#
# Start Keycloak AND provision the TR-10-SEC realm from
# TR-10-SEC_grants.csv in one shot.
#
# Composes the two steps an operator otherwise has to run by hand:
#   1. ./start-keycloak.sh
#        — spins up the container; blocks until the master realm
#          answers /realms/master/.well-known/openid-configuration.
#   2. python3 nmos_keycloak.py --realm <realm> --csv <csv> init
#        — creates the realm + NMOS client scopes + every user /
#          client in the CSV + their grants. Idempotent: re-running
#          on an existing realm refreshes scopes and grants without
#          touching subjects that haven't changed.
#
# Defaults match the rest of the workspace (TR-10-SEC realm,
# TR-10-SEC_grants.csv). Override either by passing positional args:
#
#   ./start-init-keycloak.sh
#   ./start-init-keycloak.sh MY-REALM
#   ./start-init-keycloak.sh MY-REALM my_grants.csv

set -e

cd "$(dirname "$0")"

REALM="${1:-TR-10-SEC}"
CSV="${2:-${REALM}_grants.csv}"

if [ ! -f "$CSV" ]; then
    echo "ERROR: CSV file not found: $CSV" >&2
    exit 1
fi

./start-keycloak.sh

echo
echo "Provisioning realm '$REALM' from '$CSV' ..."
python3 nmos_keycloak.py --realm "$REALM" --csv "$CSV" init

echo
echo "Keycloak ready: https://XYZ-SNX00000:9443/realms/$REALM/.well-known/openid-configuration"
