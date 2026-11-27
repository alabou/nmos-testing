#!/bin/bash
# VB440 probe address and receiver IDs, set by the IPMX-SETUP script. An undefined or blank
# variable keeps the default below.
if [ -z "$IPMX_VENDOR_PCAP_CAPTURE_VB440_ADDRESS" ]; then
    IPMX_VENDOR_PCAP_CAPTURE_VB440_ADDRESS=25.30.10.112
fi

if [ -z "$IPMX_VENDOR_PCAP_CAPTURE_VB440_VIDEO_RECEIVER_ID" ]; then
    IPMX_VENDOR_PCAP_CAPTURE_VB440_VIDEO_RECEIVER_ID=e64f24f4-e584-5d4a-9d26-0507dde17e65
fi

if [ -z "$IPMX_VENDOR_PCAP_CAPTURE_VB440_AUDIO_RECEIVER_ID" ]; then
    IPMX_VENDOR_PCAP_CAPTURE_VB440_AUDIO_RECEIVER_ID=ea47ad4c-6c49-5b87-a23c-6ab8391f5b87
fi

# for local capture
if [ "$IPMX_VENDOR_PCAP_CAPTURE" == "LOCAL" ]; then
    if [ "$4" == "video" ]; then
        dumpcap -q -i "$5" -B 256 -c 6000 -w "$1" -f "ip and host $2"
    fi
    if [ "$4" == "audio" ]; then
        dumpcap -q -i "$5" -B 256 -c 1000 -w "$1" -f "ip and host $2"
    fi
fi

# for VB440 capture
if [ "$IPMX_VENDOR_PCAP_CAPTURE" == "VB440" ]; then
    if [ "$4" == "video" ]; then
        echo "VB440 capture: probe $IPMX_VENDOR_PCAP_CAPTURE_VB440_ADDRESS, video receiver $IPMX_VENDOR_PCAP_CAPTURE_VB440_VIDEO_RECEIVER_ID"
        curl -k "https://$IPMX_VENDOR_PCAP_CAPTURE_VB440_ADDRESS/probe/api/captures/?responseMode=pcap&deleteOnComplete" -H "Content-Type: application/json" -d "{\"receiverIds\":[\"$IPMX_VENDOR_PCAP_CAPTURE_VB440_VIDEO_RECEIVER_ID\"],\"frameLimit\":30,\"timeLimit\":8000,\"captureRTCP\":true}" -o "$1" 2>&1
        if [ $? -ne 0 ]; then echo "ERROR: curl command failed for video capture"; fi
    fi
    if [ "$4" == "audio" ]; then
        echo "VB440 capture: probe $IPMX_VENDOR_PCAP_CAPTURE_VB440_ADDRESS, audio receiver $IPMX_VENDOR_PCAP_CAPTURE_VB440_AUDIO_RECEIVER_ID"
        curl -k "https://$IPMX_VENDOR_PCAP_CAPTURE_VB440_ADDRESS/probe/api/captures/?responseMode=pcap&deleteOnComplete" -H "Content-Type: application/json" -d "{\"receiverIds\":[\"$IPMX_VENDOR_PCAP_CAPTURE_VB440_AUDIO_RECEIVER_ID\"],\"packetLimit\":1000,\"timeLimit\":8000,\"captureRTCP\":true}" -o "$1" 2>&1
        if [ $? -ne 0 ]; then echo "ERROR: curl command failed for audio capture"; fi
    fi
fi

# ============================================================
# PacketStorm VIP capture using NMOS Sender ID
# ============================================================
# Runs when IPMX_VENDOR_PCAP_CAPTURE is set to VIP.
#
# Prerequisites:
# - Confirm that VIP_IP, VIP_PORT, VIP_PASSWORD env variable
#   are defined (see ./IPMX-SETUP-VIP.sh for ref)
# - Confirm that vip_packet_capture_sender_id.py exists in 
#   the package folder.
# - Connect the Senders under test to VIP Receivers using NMOS
#   before starting the automated capture test.
# - Verify that the VIP is receiving the selected streams.
# - Finish or stop any existing VIP capture before retrying.
#
#
# VIP_PORT selects VIP port A or B
#
# Video:
#   --video true captures complete video frames.
#   VIP_VIDEO_COUNT specifies the frame count.
#
#   --video false captures packets.
#   VIP_VIDEO_COUNT specifies the packet count.
#
# Audio:
#   --video false captures packets.
#   VIP_AUDIO_COUNT specifies the packet count.
#
# RTCP Sender Reports are included in the capture.
# Capture more than 2 seconds when required by the timing tests.
#
# Return a nonzero exit code if capture or download fails.
# Successful VIP capture should exit without an interactive pause.

# for VIP capture
if [ "$IPMX_VENDOR_PCAP_CAPTURE" == "VIP" ]; then
    dest=$(dirname $(realpath "$1"))
    filename="${1##*/}"
    sender_id="${filename%.*}"
    sender_id="${sender_id#*-}"

    if [ "$4" == "video" ]; then
        
        python ./vip_packet_capture_sender_id.py \
            --ip "$VIP_IP" \
            --password "$VIP_PASSWORD" \
            --sender-id "$sender_id" \
            --port "$VIP_PORT" \
            --filename "$filename" \
            --dest "$dest" \
            --count 30 \
            --caplen 1500 \
            --video true
    fi
    if [ "$4" == "audio" ]; then
        python ./vip_packet_capture_sender_id.py \
            --ip "$VIP_IP" \
            --password "$VIP_PASSWORD" \
            --sender-id "$sender_id" \
            --port "$VIP_PORT" \
            --filename "$filename" \
            --dest "$dest" \
            --count 1000 \
            --caplen 1500 \
            --video false
    fi
fi

echo "IPMX_VENDOR_PCAP_CAPTURE is $IPMX_VENDOR_PCAP_CAPTURE"
read -p "Press any key to continue..." -n 1
echo
