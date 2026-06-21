#!/bin/bash
python3 nmos-test.py suite BCP-006-02-01 --tests test_01 test_06 test_07 --host $IPMX_RECEIVER_ADDRESS --port $IPMX_RECEIVER_PORT --version v1.3 --senders IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-senders-NONE.guid --receivers IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-receivers.guid
