#!/bin/bash
python3 nmos-test.py suite IS-04-01 --tests auto test_04 test_07 test_11 test_17 test_18 test_19 test_20  test_23 test_25 test_28 --host $IPMX_RECEIVER_ADDRESS --port $IPMX_RECEIVER_PORT --version v1.3 --senders IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-senders-NONE.guid --receivers IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-receivers.guid
