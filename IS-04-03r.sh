#!/bin/bash
python3 nmos-test.py suite IS-04-03 --tests test_01 --host $IPMX_RECEIVER_ADDRESS --port $IPMX_RECEIVER_PORT --version v1.3 --senders IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-senders-NONE.guid --receivers IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-receivers.guid
