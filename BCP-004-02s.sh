#!/bin/bash
python3 nmos-test.py suite BCP-004-02-01 --tests test_01 test_02 --host $IPMX_SENDER_ADDRESS $IPMX_SENDER_IS05_ADDRESS --port $IPMX_SENDER_PORT $IPMX_SENDER_IS05_PORT --version v1.3 v1.1 --senders IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-senders.guid --receivers IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-receivers-NONE.guid
