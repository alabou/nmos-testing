@echo off
@REM for local capture
if "%IPMX_VENDOR_PCAP_CAPTURE%" == "LOCAL" (
    @REM "C:\Program Files\Wireshark\dumpcap" -q -i %5 -B 256 -c 3000 -w %1 -f "ip and host %2"
    "C:\Program Files\Wireshark\dumpcap" -q -i %5 -B 256 -c 10 -w %1 -f "ip and host %2"
)

@REM for VB440 capture
if "%IPMX_VENDOR_PCAP_CAPTURE%" == "VB440" (
    if "%4" == "video" (
        powershell -Command "curl.exe -k 'https://192.168.112.57/probe/api/captures/?responseMode=pcap&deleteOnComplete' --json '{\"receiverIds\":[\"e64f24f4-e584-5d4a-9d26-0507dde17e65\"],\"packetLimit\":3000,\"timeLimit\":5000,\"captureRTCP\":true}' -o %1"
    )
    if "%4" == "audio" (
        powershell -Command "curl.exe -k 'https://192.168.112.57/probe/api/captures/?responseMode=pcap&deleteOnComplete' --json '{\"receiverIds\":[\"ce278320-000b-102b-aa03-000000000000\"],\"packetLimit\":3000,\"timeLimit\":5000,\"captureRTCP\":true}' -o %1"
    )
)

@echo IPMX_VENDOR_PCAP_CAPTURE is %IPMX_VENDOR_PCAP_CAPTURE%
@echo Press any key to continue...
@pause >nul
@echo.
