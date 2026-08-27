#!/bin/bash
#
# Stop and remove the Keycloak container started by start-keycloak.sh.
# Idempotent: ``docker rm -f`` is a no-op when the container is already
# gone. The container ships its DB inside its writable layer when
# launched via the default form in start-keycloak.sh, so removing it
# wipes the realm/users/clients state too — re-run start-keycloak.sh
# + ./nmos_keycloak.py init to rebuild scaffolding from scratch.
#
# When the persistent-db flavor in start-keycloak.sh is used (the
# commented-out volume-mounted form), the realm survives ``docker rm``;
# the named volume ``keycloak_data`` is preserved. To wipe persistent
# state too, run:  docker volume rm keycloak_data

set -e

if docker ps -a --format '{{.Names}}' | grep -q '^keycloak$'; then
    echo "Stopping keycloak container ..."
    docker rm -f keycloak >/dev/null
    echo "Stopped."
else
    echo "No 'keycloak' container — nothing to stop."
fi
