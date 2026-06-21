#!/bin/bash
python3 nmos-test.py suite BCP-007-02-01 --tests test_01 test_06 test_07 test_12 test_13 --host $IPMX_RECEIVER_ADDRESS $IPMX_RECEIVER_IS05_ADDRESS --port $IPMX_RECEIVER_PORT $IPMX_RECEIVER_IS05_PORT --version v1.3 v1.1 --senders IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-senders-NONE.guid --receivers IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-receivers.guid
