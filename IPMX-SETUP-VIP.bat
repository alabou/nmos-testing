@REM If the IP ADDRESS and PORT of the IS-05 and IS-11 interfaces are the same as the
@REM IS-04 interface, then the IP ADDRESS and PORT of the IS-05 and IS-11 interfaces
@REM should be left blank.

@REM  ============================================================
@REM  PacketStorm VIP packet capture configuration
@REM  ============================================================
@REM  Requires the VIP capture integration and
@REM  vip_packet_capture_sender_id.py in the main package folder.

@REM  BEFORE running IPMX-PCAPs.sh:
@REM  Use an NMOS controller to connect the video and audio Senders
@REM  under test to the VIP Receivers. Verify reception on the VIP.
@REM  The test workflow supplies each selected Sender's GUID.

@REM  Select the capture device: LOCAL, VB440, or VIP.
@REM  export IPMX_VENDOR_PCAP_CAPTURE=VIP
@REM  VIP management IP address.
@REM  export VIP_IP="YOUR_VIP_IP_ADDRESS"
@REM  VIP password
@REM  export VIP_PASSWORD="YOUR_VIP_PASSWORD"
@REM  VIP capture port: A or B. This is NOT the RTP UDP port. This is the media port for capturing the packets. 
@REM  export VIP_PORT=A
@REM  For video, count means complete video frames.
@REM  180 frames is approximately 3 seconds at 60 fps.
@REM  export VIP_VIDEO_COUNT=180
@REM  For audio, count means packets.
@REM  3500 packets provides approximately 3 seconds for 1 ms audio,
@REM  allowing for included RTCP. Increase for shorter packet times.
@REM  export VIP_AUDIO_COUNT=3500
@REM  Maximum captured bytes per packet.
@REM  Increase if needed to avoid truncating larger packets.
@REM  export VIP_CAPLEN=1500
@REM  RTCP Sender Reports are included in VIP captures.
@REM  Verify that captures exceed 2 seconds for tests requiring
@REM  a 2-second measurement window.
@REM  Finish or stop any existing VIP capture before starting another.

set IPMX_REGISTRY_ADDRESS=10.2.1.170
set IPMX_REGISTRY_PORT=3211
set IPMX_SENDER_ADDRESS=10.2.1.50
set IPMX_SENDER_IS05_ADDRESS=
set IPMX_SENDER_IS11_ADDRESS=
set IPMX_SENDER_PORT=5050
set IPMX_SENDER_IS05_PORT=
set IPMX_SENDER_IS11_PORT=
set IPMX_RECEIVER_ADDRESS=XYZ-SNX00001
set IPMX_RECEIVER_IS05_ADDRESS=
set IPMX_RECEIVER_IS11_ADDRESS=
set IPMX_RECEIVER_PORT=7051
set IPMX_RECEIVER_IS05_PORT=
set IPMX_RECEIVER_IS11_PORT=
set IPMX_VENDOR=VIP
set IPMX_VENDOR_PCAP_CAPTURE=VIP
set VIP_IP="YOUR_VIP_IP_ADDRESS"
set VIP_PORT=A
set VIP_PASSWORD="YOUR_VIP_PASSWORD"
@REM set IPMX_VENDOR_PCAP_CAPTURE=LOCAL

@echo off

cd %~dp0

if "%IPMX_SENDER_IS05_ADDRESS%" == "" (
    set IPMX_SENDER_IS05_ADDRESS=%IPMX_SENDER_ADDRESS%
)

if "%IPMX_SENDER_IS05_PORT%" == "" (
    set IPMX_SENDER_IS05_PORT=%IPMX_SENDER_PORT%
)

if "%IPMX_RECEIVER_IS05_ADDRESS%" == "" (
    set IPMX_RECEIVER_IS05_ADDRESS=%IPMX_RECEIVER_ADDRESS%
)

if "%IPMX_RECEIVER_IS05_PORT%" == "" (
    set IPMX_RECEIVER_IS05_PORT=%IPMX_RECEIVER_PORT%
)

if "%IPMX_SENDER_IS11_ADDRESS%" == "" (
    set IPMX_SENDER_IS11_ADDRESS=%IPMX_SENDER_ADDRESS%
)

if "%IPMX_SENDER_IS11_PORT%" == "" (
    set IPMX_SENDER_IS11_PORT=%IPMX_SENDER_PORT%
)

if "%IPMX_RECEIVER_IS11_ADDRESS%" == "" (
    set IPMX_RECEIVER_IS11_ADDRESS=%IPMX_RECEIVER_ADDRESS%
)

if "%IPMX_RECEIVER_IS11_PORT%" == "" (
    set IPMX_RECEIVER_IS11_PORT=%IPMX_RECEIVER_PORT%
)

if not exist IPMX_VENDOR_%IPMX_VENDOR% (
    mkdir IPMX_VENDOR_%IPMX_VENDOR%
)

if not exist IPMX_VENDOR_%IPMX_VENDOR%\ipmx-test-senders.guid (
    copy ipmx-test-senders-NONE.guid IPMX_VENDOR_%IPMX_VENDOR%\ipmx-test-senders.guid >nul
)

if not exist IPMX_VENDOR_%IPMX_VENDOR%\ipmx-test-senders-NONE.guid (
    copy ipmx-test-senders-NONE.guid IPMX_VENDOR_%IPMX_VENDOR%\ipmx-test-senders-NONE.guid >nul
)

if not exist IPMX_VENDOR_%IPMX_VENDOR%\ipmx-test-receivers.guid (
    copy ipmx-test-receivers-NONE.guid IPMX_VENDOR_%IPMX_VENDOR%\ipmx-test-receivers.guid >nul
)

if not exist IPMX_VENDOR_%IPMX_VENDOR%\ipmx-test-receivers-NONE.guid (
    copy ipmx-test-receivers-NONE.guid IPMX_VENDOR_%IPMX_VENDOR%\ipmx-test-receivers-NONE.guid >nul
)

@echo on    