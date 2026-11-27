@echo off
setlocal

@REM VB440 probe address and receiver IDs, set by the IPMX-SETUP script. An undefined or blank
@REM variable keeps the default below. These lines stay outside the if blocks because cmd expands
@REM %VARIABLE% for a whole block when it reads the block.
if "%IPMX_VENDOR_PCAP_CAPTURE_VB440_ADDRESS%" == "" set IPMX_VENDOR_PCAP_CAPTURE_VB440_ADDRESS=25.30.10.112
if "%IPMX_VENDOR_PCAP_CAPTURE_VB440_VIDEO_RECEIVER_ID%" == "" set IPMX_VENDOR_PCAP_CAPTURE_VB440_VIDEO_RECEIVER_ID=e64f24f4-e584-5d4a-9d26-0507dde17e65
if "%IPMX_VENDOR_PCAP_CAPTURE_VB440_AUDIO_RECEIVER_ID%" == "" set IPMX_VENDOR_PCAP_CAPTURE_VB440_AUDIO_RECEIVER_ID=ea47ad4c-6c49-5b87-a23c-6ab8391f5b87

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
	    echo VB440 capture: probe %IPMX_VENDOR_PCAP_CAPTURE_VB440_ADDRESS%, video receiver %IPMX_VENDOR_PCAP_CAPTURE_VB440_VIDEO_RECEIVER_ID%
	    curl.exe -k "https://%IPMX_VENDOR_PCAP_CAPTURE_VB440_ADDRESS%/probe/api/captures/?responseMode=pcap&deleteOnComplete" -H "Content-Type: application/json" -d "{\"receiverIds\":[\"%IPMX_VENDOR_PCAP_CAPTURE_VB440_VIDEO_RECEIVER_ID%\"],\"frameLimit\":30,\"timeLimit\":8000,\"captureRTCP\":true}" -o "%1" 2>&1
	    if errorlevel 1 echo ERROR: curl command failed for video capture
    )
    if "%4" == "audio" (
    	echo VB440 capture: probe %IPMX_VENDOR_PCAP_CAPTURE_VB440_ADDRESS%, audio receiver %IPMX_VENDOR_PCAP_CAPTURE_VB440_AUDIO_RECEIVER_ID%
    	curl.exe -k "https://%IPMX_VENDOR_PCAP_CAPTURE_VB440_ADDRESS%/probe/api/captures/?responseMode=pcap&deleteOnComplete" -H "Content-Type: application/json" -d "{\"receiverIds\":[\"%IPMX_VENDOR_PCAP_CAPTURE_VB440_AUDIO_RECEIVER_ID%\"],\"packetLimit\":1000,\"timeLimit\":8000,\"captureRTCP\":true}" -o "%1" 2>&1
    	if errorlevel 1 echo ERROR: curl command failed for audio capture
    )
)

@REM ============================================================
@REM PacketStorm VIP capture using NMOS Sender ID
@REM ============================================================
@REM Runs when IPMX_VENDOR_PCAP_CAPTURE is set to VIP.
@REM
@REM Prerequisites:
@REM - Confirm that VIP_IP, VIP_PORT, VIP_PASSWORD env variable
@REM   are defined (see ./IPMX-SETUP-VIP.sh for ref)
@REM - Confirm that vip_packet_capture_sender_id.py exists in 
@REM   the package folder.
@REM - Connect the Senders under test to VIP Receivers using NMOS
@REM   before starting the automated capture test.
@REM - Verify that the VIP is receiving the selected streams.
@REM - Finish or stop any existing VIP capture before retrying.
@REM
@REM
@REM VIP_PORT selects VIP port A or B
@REM
@REM Video:
@REM   --video true captures complete video frames.
@REM   VIP_VIDEO_COUNT specifies the frame count.
@REM
@REM   --video false captures packets.
@REM   VIP_VIDEO_COUNT specifies the packet count.
@REM
@REM Audio:
@REM   --video false captures packets.
@REM   VIP_AUDIO_COUNT specifies the packet count.
@REM
@REM RTCP Sender Reports are included in the capture.
@REM Capture more than 2 seconds when required by the timing tests.
@REM
@REM Return a nonzero exit code if capture or download fails.
@REM Successful VIP capture should exit without an interactive pause.
@REM PacketStorm VIP capture using the selected sender ID

set "dest=%~dp1"
@REM %~dp1 ends with "\", and "\"" escapes the closing quote in the argv of python, which
@REM merges every argument after --dest into dest. Drop the trailing backslash.
if "%dest:~-1%" == "\" set "dest=%dest:~0,-1%"
set "filename=%~nx1"
set "sender_id=%~n1"
set "sender_id=%sender_id:*-=%"
if "%IPMX_VENDOR_PCAP_CAPTURE%" == "VIP" (
    if "%~4" == "video" (
        python "%~dp0vip_packet_capture_sender_id.py" ^
            --ip "%VIP_IP%" ^
            --password "%VIP_PASSWORD%" ^
            --sender-id "%sender_id%" ^
            --port "%VIP_PORT%" ^
            --filename "%filename%" ^
            --dest "%dest%" ^
            --count 30 ^
            --caplen 1500 ^
            --video true

        if errorlevel 1 exit /b 1
    ) else if "%~4" == "audio" (
        python "%~dp0vip_packet_capture_sender_id.py" ^
            --ip "%VIP_IP%" ^
            --password "%VIP_PASSWORD%" ^
            --sender-id "%sender_id%" ^
            --port "%VIP_PORT%" ^
            --filename "%filename%" ^
            --dest "%dest%" ^
            --count 1000 ^
            --caplen 1500 ^
            --video false

        if errorlevel 1 exit /b 1
    ) else (
        echo ERROR: Unsupported capture type "%~4".
        exit /b 1
    )

    exit /b 0
)

@echo IPMX_VENDOR_PCAP_CAPTURE is %IPMX_VENDOR_PCAP_CAPTURE%
@echo Press any key to continue...
@pause >nul
@echo.
