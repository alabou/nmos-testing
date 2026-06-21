#!/bin/bash
python3 nmos-test.py suite IS-04-01 --tests auto test_04 test_07 test_08 test_09 test_10 test_17 test_18 test_19 test_20 test_20_01 test_23 test_24 test_24_01 test_26 test_28 --host $IPMX_SENDER_ADDRESS --port $IPMX_SENDER_PORT --version v1.3 --senders IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-senders.guid --receivers IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-receivers-NONE.guid
