#!/bin/bash
python3 nmos-test.py suite IPMX-Sdp --tests test_04 test_06 test_08 --host $IPMX_REGISTRY_ADDRESS $IPMX_RECEIVER_ADDRESS $IPMX_RECEIVER_IS05_ADDRESS --port $IPMX_REGISTRY_PORT $IPMX_RECEIVER_PORT $IPMX_RECEIVER_IS05_PORT --version v1.3 v1.3 v1.1 --senders IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-senders-NONE.guid --receivers IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-receivers.guid
