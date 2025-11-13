@echo off
@REM for local capture
if "%IPMX_VENDOR_PCAP_CAPTURE%" == "LOCAL" (
    @REM "C:\Program Files\Wireshark\dumpcap" -q -i %5 -B 256 -c 3000 -w %1 -f "ip and host %2"
    "C:\Program Files\Wireshark\dumpcap" -q -i %5 -B 256 -c 10 -w %1 -f "ip and host %2"
)

@REM for VB440 capture
if "%IPMX_VENDOR_PCAP_CAPTURE%" == "VB440" (
    for /f "usebackq delims=" %%i in (`ssh capture@10.20.10.194 "capture/capture.mjs %2 %3 %4 | tail -n1"`) do curl -LRs %%i -o %1
)

@echo "IPMX_VENDOR_PCAP_CAPTURE is %IPMX_VENDOR_PCAP_CAPTURE%"
@echo Press any key to continue...
@pause >nul
@echo.
