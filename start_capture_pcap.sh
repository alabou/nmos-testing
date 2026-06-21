#!/bin/bash
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
        curl -k "https://25.30.10.112/probe/api/captures/?responseMode=pcap&deleteOnComplete" -H "Content-Type: application/json" -d '{"receiverIds":["e64f24f4-e584-5d4a-9d26-0507dde17e65"],"frameLimit":30,"timeLimit":5000,"captureRTCP":true}' -o "$1" 2>&1
        if [ $? -ne 0 ]; then echo "ERROR: curl command failed for video capture"; fi
    fi
    if [ "$4" == "audio" ]; then
        curl -k "https://25.30.10.112/probe/api/captures/?responseMode=pcap&deleteOnComplete" -H "Content-Type: application/json" -d '{"receiverIds":["ea47ad4c-6c49-5b87-a23c-6ab8391f5b87"],"packetLimit":1000,"timeLimit":5000,"captureRTCP":true}' -o "$1" 2>&1
        if [ $? -ne 0 ]; then echo "ERROR: curl command failed for audio capture"; fi
    fi
fi

echo "IPMX_VENDOR_PCAP_CAPTURE is $IPMX_VENDOR_PCAP_CAPTURE"
read -p "Press any key to continue..." -n 1
echo
