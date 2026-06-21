#!/bin/bash
# If the IP ADDRESS and PORT of the IS-05 and IS-11 interfaces are the same as the
# IS-04 interface, then the IP ADDRESS and PORT of the IS-05 and IS-11 interfaces
# should be left blank.

export IPMX_REGISTRY_ADDRESS=127.0.0.1
export IPMX_REGISTRY_PORT=8443
export IPMX_SENDER_ADDRESS=127.0.0.1
export IPMX_SENDER_IS05_ADDRESS=
export IPMX_SENDER_IS11_ADDRESS=
export IPMX_SENDER_PORT=5050
export IPMX_SENDER_IS05_PORT=
export IPMX_SENDER_IS11_PORT=
export IPMX_RECEIVER_ADDRESS=127.0.0.1
export IPMX_RECEIVER_IS05_ADDRESS=
export IPMX_RECEIVER_IS11_ADDRESS=
export IPMX_RECEIVER_PORT=5050
export IPMX_RECEIVER_IS05_PORT=
export IPMX_RECEIVER_IS11_PORT=
export IPMX_VENDOR=Local
export IPMX_VENDOR_PCAP_CAPTURE=LOCAL

if [ -z "$IPMX_SENDER_IS05_ADDRESS" ]; then
    export IPMX_SENDER_IS05_ADDRESS=$IPMX_SENDER_ADDRESS
fi

if [ -z "$IPMX_SENDER_IS05_PORT" ]; then
    export IPMX_SENDER_IS05_PORT=$IPMX_SENDER_PORT
fi

if [ -z "$IPMX_RECEIVER_IS05_ADDRESS" ]; then
    export IPMX_RECEIVER_IS05_ADDRESS=$IPMX_RECEIVER_ADDRESS
fi

if [ -z "$IPMX_RECEIVER_IS05_PORT" ]; then
    export IPMX_RECEIVER_IS05_PORT=$IPMX_RECEIVER_PORT
fi

if [ -z "$IPMX_SENDER_IS11_ADDRESS" ]; then
    export IPMX_SENDER_IS11_ADDRESS=$IPMX_SENDER_ADDRESS
fi

if [ -z "$IPMX_SENDER_IS11_PORT" ]; then
    export IPMX_SENDER_IS11_PORT=$IPMX_SENDER_PORT
fi

if [ -z "$IPMX_RECEIVER_IS11_ADDRESS" ]; then
    export IPMX_RECEIVER_IS11_ADDRESS=$IPMX_RECEIVER_ADDRESS
fi

if [ -z "$IPMX_RECEIVER_IS11_PORT" ]; then
    export IPMX_RECEIVER_IS11_PORT=$IPMX_RECEIVER_PORT
fi

cd "$(dirname "${BASH_SOURCE[0]}")"

mkdir -p IPMX_VENDOR_$IPMX_VENDOR

[ -f IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-senders.guid ] || cp ipmx-test-senders-NONE.guid IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-senders.guid

[ -f IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-senders-NONE.guid ] || cp ipmx-test-senders-NONE.guid IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-senders-NONE.guid

[ -f IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-receivers.guid ] || cp ipmx-test-receivers-NONE.guid IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-receivers.guid

[ -f IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-receivers-NONE.guid ] || cp ipmx-test-receivers-NONE.guid IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-receivers-NONE.guid
