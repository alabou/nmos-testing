@echo off
@REM for local capture
if "%IPMX_VENDOR_PCAP_CAPTURE%" == "LOCAL" (
    if "%4" == "video" (
        "C:\Program Files\Wireshark\dumpcap" -q -i %5 -B 256 -c 6000 -w %1 -f "ip and host %2"
    )
    if "%4" == "audio" (
        "C:\Program Files\Wireshark\dumpcap" -q -i %5 -B 256 -c 1000 -w %1 -f "ip and host %2"
    )
)

@REM for VB440 capture
if "%IPMX_VENDOR_PCAP_CAPTURE%" == "VB440" (
    if "%4" == "video" (
	    curl.exe -k "https://25.30.10.112/probe/api/captures/?responseMode=pcap&deleteOnComplete" -H "Content-Type: application/json" -d "{\"receiverIds\":[\"e64f24f4-e584-5d4a-9d26-0507dde17e65\"],\"frameLimit\":30,\"timeLimit\":8000,\"captureRTCP\":true}" -o "%1" 2>&1
	    if errorlevel 1 echo ERROR: curl command failed for video capture
    )
    if "%4" == "audio" (
    	curl.exe -k "https://25.30.10.112/probe/api/captures/?responseMode=pcap&deleteOnComplete" -H "Content-Type: application/json" -d "{\"receiverIds\":[\"ea47ad4c-6c49-5b87-a23c-6ab8391f5b87\"],\"packetLimit\":1000,\"timeLimit\":8000,\"captureRTCP\":true}" -o "%1" 2>&1
    	if errorlevel 1 echo ERROR: curl command failed for audio capture
    )
)

@echo IPMX_VENDOR_PCAP_CAPTURE is %IPMX_VENDOR_PCAP_CAPTURE%
@echo Press any key to continue...
@pause >nul
@echo.
