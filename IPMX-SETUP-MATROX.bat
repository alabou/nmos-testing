@REM If the IP ADDRESS and PORT of the IS-05 and IS-11 interfaces are the same as the
@REM IS-04 interface, then the IP ADDRESS and PORT of the IS-05 and IS-11 interfaces
@REM should be left blank.

set IPMX_REGISTRY_ADDRESS=25.30.10.45
set IPMX_REGISTRY_PORT=8870
set IPMX_SENDER_ADDRESS=25.30.10.120
set IPMX_SENDER_IS05_ADDRESS=
set IPMX_SENDER_IS11_ADDRESS=
set IPMX_SENDER_PORT=5050
set IPMX_SENDER_IS05_PORT=
set IPMX_SENDER_IS11_PORT=
set IPMX_RECEIVER_ADDRESS=25.30.10.123
set IPMX_RECEIVER_IS05_ADDRESS=
set IPMX_RECEIVER_IS11_ADDRESS=
set IPMX_RECEIVER_PORT=5050
set IPMX_RECEIVER_IS05_PORT=
set IPMX_RECEIVER_IS11_PORT=
set IPMX_VENDOR=Matrox
set IPMX_VENDOR_PCAP_CAPTURE=VB440
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