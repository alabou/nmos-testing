#!/bin/bash
python3 nmos-test.py suite BCP-006-03-01 --tests test_01 test_02 test_03 test_04 test_05 --host $IPMX_SENDER_ADDRESS --port $IPMX_SENDER_PORT --version v1.3 --senders IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-senders.guid --receivers IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-receivers-NONE.guid
