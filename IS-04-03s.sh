#!/bin/bash
python3 nmos-test.py suite IS-04-03 --tests test_01 --host $IPMX_SENDER_ADDRESS --port $IPMX_SENDER_PORT --version v1.3 --senders IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-senders.guid --receivers IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-receivers-NONE.guid
