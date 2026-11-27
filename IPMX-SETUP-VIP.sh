#!/bin/bash
# If the IP ADDRESS and PORT of the IS-05 and IS-11 interfaces are the same as the
# IS-04 interface, then the IP ADDRESS and PORT of the IS-05 and IS-11 interfaces
# should be left blank.
# ============================================================
# PacketStorm VIP packet capture configuration
# ============================================================
# Requires the VIP capture integration and
# vip_packet_capture_sender_id.py in the main package folder.
#
# BEFORE running IPMX-PCAPs.sh:
# Use an NMOS controller to connect the video and audio Senders
# under test to the VIP Receivers. Verify reception on the VIP.
# The test workflow supplies each selected Sender's GUID.
#
# Select the capture device: LOCAL, VB440, or VIP.
# export IPMX_VENDOR_PCAP_CAPTURE=VIP

# VIP management IP address.
# export VIP_IP="YOUR_VIP_IP_ADDRESS"

# VIP password
# export VIP_PASSWORD="YOUR_VIP_PASSWORD"

# VIP capture port: A or B. This is NOT the RTP UDP port. This is the media port for capturing the packets. 
# export VIP_PORT=A

# For video, count means complete video frames.
# 180 frames is approximately 3 seconds at 60 fps.
# export VIP_VIDEO_COUNT=180

# For audio, count means packets.
# 3500 packets provides approximately 3 seconds for 1 ms audio,
# allowing for included RTCP. Increase for shorter packet times.
# export VIP_AUDIO_COUNT=3500

# Maximum captured bytes per packet.
# Increase if needed to avoid truncating larger packets.
# export VIP_CAPLEN=1500

# RTCP Sender Reports are included in VIP captures.
# Verify that captures exceed 2 seconds for tests requiring
# a 2-second measurement window.
# Finish or stop any existing VIP capture before starting another.

export IPMX_REGISTRY_ADDRESS=10.2.1.170
export IPMX_REGISTRY_PORT=3211
export IPMX_SENDER_ADDRESS=10.2.1.50
export IPMX_SENDER_IS05_ADDRESS=
export IPMX_SENDER_IS11_ADDRESS=
export IPMX_SENDER_PORT=5050
export IPMX_SENDER_IS05_PORT=
export IPMX_SENDER_IS11_PORT=
export IPMX_RECEIVER_ADDRESS=XYZ-SNX00001
export IPMX_RECEIVER_IS05_ADDRESS=
export IPMX_RECEIVER_IS11_ADDRESS=
export IPMX_RECEIVER_PORT=7051
export IPMX_RECEIVER_IS05_PORT=
export IPMX_RECEIVER_IS11_PORT=
export IPMX_VENDOR=VIP
export IPMX_VENDOR_PCAP_CAPTURE=VIP
export VIP_IP="YOUR_VIP_IP_ADDRESS"
export VIP_PORT=A
export VIP_PASSWORD="YOUR_VIP_PASSWORD"

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