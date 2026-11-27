IPMX NMOS Testing Package
=========================

This folder contains the IPMX NMOS Testing package. Follow these instructions to install the required Python environment. These instructions assume a Windows environment but the test suite can also run under Linux if you change the Windows batch file for Linux scripts. For Windows use a regular Command Prompt to run the batch files, do NOT use PowerShell.

- Uncompress the archive into the folder IPMX-Testing-13

- Install the latest Python 3.12 executables on your system (Python 3.12 has been validated)
- Install the GIT executables on your system (Git 2.17.1 has been validated)
- Create a Python virtual environment
    cd IPMX-Testing-18
    python3 -m venv .venv
    .venv\Scripts\activate.bat
- Install the required Python dependencies
    cd IPMX-Testing-18
    python3 -m pip install -r requirements.txt
- OPTIONAL (not used by IPMX tests) install sdpoker. For Windows, install Node.js and then run: npm install -g sdpoker
- OPTIONAL (not used by IPMX tests) install testssl by following the instructions in the testssl\README.md file.

- Set up your VENDOR directory and the IP address and port of your DuT. The testing environment supports per-API IP address and port. Edit the IPMX-SETUP-XYZ.bat to get all the details.

    copy IPMX-SETUP-MATROX.bat IPMX-SETUP-XYZ.bat

    notepad IPMX-SETUP-XYZ.bat
        set IPMX_REGISTRY_ADDRESS=IPv4 address of the registry in your environment
        set IPMX_REGISTRY_PORT=Query port of the registry in your environment
        set IPMX_SENDER_ADDRESS=IPv4 NMOS Control address of the SENDER DuT
        set IPMX_SENDER_PORT=IPv4 NMOS Control port of the SENDER DuT
        set IPMX_RECEIVER_ADDRESS=IPv4 NMOS Control address of the RECEIVER DuT
        set IPMX_RECEIVER_PORT=IPv4 NMOS Control port of the RECEIVER DuT
        set IPMX_VENDOR=XYZ
        set IPMX_VENDOR_PCAP_CAPTURE=LOCAL or VB440 or VIP
        set IPMX_VENDOR_PCAP_CAPTURE_VB440_ADDRESS=IPv4 address, or host:port, of the capture API of the VB440 probe
        set IPMX_VENDOR_PCAP_CAPTURE_VB440_VIDEO_RECEIVER_ID=ID of the VB440 video Receiver to capture from
        set IPMX_VENDOR_PCAP_CAPTURE_VB440_AUDIO_RECEIVER_ID=ID of the VB440 audio Receiver to capture from

    The three IPMX_VENDOR_PCAP_CAPTURE_VB440_* variables are used only when IPMX_VENDOR_PCAP_CAPTURE=VB440. A VB440 has one video, one audio and one ancillary Receiver per Service: set the IDs of the video and audio Receivers of the Service to use, and the address of the probe. To use another Service of the same probe, change the two IDs. To use another VB440, set all three, as the Receiver IDs differ from one probe to another. The probe lists its Receivers, with labels naming their Service (e.g. "Service 01, Video 1"), at http://<VB440 address>/x-nmos/node/v1.3/receivers. A blank or undefined variable keeps the default of start_capture_pcap: address 25.30.10.112, video Receiver e64f24f4-e584-5d4a-9d26-0507dde17e65 and audio Receiver ea47ad4c-6c49-5b87-a23c-6ab8391f5b87.

    IPMX-SETUP-XYZ.bat

    If you have multiple configurations to test and require separate VENDOR directories, create multiple SETUP files as IPMX-SETUP-XYZ-option1.bat

- Note that the captured PCAP and SDP files will be written to the vendor directory

- Set up the GUID of the NMOS audio and video Senders of the DuT.

    notepad IPMX_VENDOR_XYZ\ipmx-test-senders.guid

- To help you get the GUID of your senders, run the following scripts and copy/paste the appropriate GUID, one per line.

    IPMX-GUIDs.bat

- Set up the GUID of the NMOS audio and video Receiver of the DuT

    notepad IPMX_VENDOR_XYZ\ipmx-test-receivers.guid

- To help you get the GUID of your receivers, run the following scripts and copy/paste the appropriate GUID, one per line.

    IPMX-GUIDr.bat

- Set up the local UserConfig.py options

    notepad nmostesting\UserConfig.py

    # Example of setting ENABLE_HTTPS, any value from Config.py can be overridden using the same pattern.
    CONFIG.ENABLE_HTTPS = False

    CONFIG.ENABLE_DNS_SD = False
    CONFIG.DNS_SD_MODE = 'unicast'

    # Read the registry host/port from the environment variables set by the
    # IPMX-SETUP-XYZ scripts, falling back to these defaults if they are not set.
    CONFIG.QUERY_API_HOST = os.environ.get('IPMX_REGISTRY_ADDRESS', '25.30.10.45')
    CONFIG.QUERY_API_PORT = int(os.environ.get('IPMX_REGISTRY_PORT', 8870))

    CONFIG.IS11_REFERENCE_SENDER_CONNECTION_API_URL = "http://25.30.10.163:5050/x-nmos/connection/v1.1/"
    CONFIG.IS11_REFERENCE_SENDER_NODE_API_URL = "http://25.30.10.163:5050/x-nmos/node/v1.3/"

    # The "any" value should work in most cases but in some scenarios the specific interface
    # IP address must be specified in order to join on the proper network interface.
    # CONFIG.MULTICAST_INTERFACE = "any"
    CONFIG.MULTICAST_INTERFACE = "25.30.10.214"

    # A multicast address that is known not to be used by any DuT
    CONFIG.MULTICAST_STREAM_TARGET = '239.1.0.100'

    # Make sure no one fail because accesses are slow
    CONFIG.HTTP_TIMEOUT=30

    # Reference Kramer source taking a long time to respond
    CONFIG.STABLE_STATE_ATTEMPTS=10

    # Manually check that the DuT produces an EDID with expected refresh/sample rate
    CONFIG.IS11_SOURCE_EDID_VERIFICATION=False

    # Geneva testing event required to have this set form 3 to 10
    CONFIG.API_PROCESSING_TIMEOUT=10

- Setup the PCAP capture script start_capture_pcap.bat

    Set the path to the dumpcap program. Ex. C:\Program Files\Wireshark\dumpcap
    The address of the VB440 probe and the IDs of its Receivers are no longer set in this script: set the IPMX_VENDOR_PCAP_CAPTURE_VB440_* variables in IPMX-SETUP-XYZ.bat (see above).

    You may need to adjust the amount captured. By default, LOCAL captures 6000 packets for video and 1000 packets for audio (dumpcap -c), and VB440 captures 30 frames for video (frameLimit) and 1000 packets for audio (packetLimit), with a time limit of 8000 ms for both (timeLimit).

    !!! Note that you need to press a key when the message "Press any key to continue..." appears right after displaying "IPMX_VENDOR_PCAP_CAPTURE is ..."

    !!! Note that the script now gets the LOCAL interface as a parameter.

    !!! Do not forget to have the VB440 Receivers set by IPMX_VENDOR_PCAP_CAPTURE_VB440_VIDEO_RECEIVER_ID and IPMX_VENDOR_PCAP_CAPTURE_VB440_AUDIO_RECEIVER_ID subscribing to the Sender's streams if the VB440 capture mode is used. 

- PacketStorm VIP Capture

    The PacketStorm VIP can capture video and audio streams for analysis by the IPMX Automated Test Package. Captures include RTP media packets and RTCP Sender Reports.

    Prerequisites

    Connect the VIP to the media network.

    Using an NMOS controller, connect the video and audio Senders being tested to the appropriate VIP Receivers BEFORE running the capture test. The streams must be visible on the VIP.

    Confirm that the sender GUIDs configured in the test package identify the Senders connected to the VIP.

    On the VIP, the GUIDs of the connected flows are available on NMOS tab Receive Subsciption: [Active]

    Place vip_packet_capture_sender_id.py in the main test-package folder.

    Install the capture script's dependencies in the Python environment used by the test package:

    python -m pip install requests urllib3

    Configuration

    In the setup file used for your device, select VIP capture and configure the VIP IP address, admin password, and capture port.

    Windows example:

    set "IPMX_VENDOR_PCAP_CAPTURE=VIP"
    set "VIP_IP=YOUR_VIP_IP_ADDRESS"
    set "VIP_PASSWORD=YOUR_ADMIN_PASSWORD"
    set "VIP_PORT=A"
    set "VIP_VIDEO_COUNT=180"
    set "VIP_AUDIO_COUNT=3500"
    set "VIP_CAPLEN=1500"

    Linux/WSL example:

    export IPMX_VENDOR_PCAP_CAPTURE=VIP
    export VIP_IP="YOUR_VIP_IP_ADDRESS"
    export VIP_PASSWORD="YOUR_ADMIN_PASSWORD"
    export VIP_PORT=A
    export VIP_VIDEO_COUNT=180
    export VIP_AUDIO_COUNT=3500
    export VIP_CAPLEN=1500

    Replace the example settings with those for your installation. VIP_PORT selects VIP media capture port A or B; it is not the stream's UDP destination port. Keep the actual admin password out of files committed to the repository.

    Capture Counts

    For video, --video true makes --count specify the number of complete video frames. A count of 180 captures approximately three seconds at 60 fps.

    For video, --video false makes --count specify packets. A count of 235,000 captures approximately three seconds at 60 fps.

    For audio, --video false makes --count specify packets. A count of 3500 provides approximately three seconds for 1 ms audio packet time, allowing for included RTCP packets. Shorter audio packet times require larger counts.

    Verify that the resulting capture spans more than two seconds when performing tests requiring a two-second measurement window.

    Running the Capture

    After loading your setup settings, run:

    Windows:
    IPMX-PCAPs.bat

    Linux/WSL:
    ./IPMX-PCAPs.sh

    The VIP integration passes the selected sender GUID to the capture script and downloads the capture into the output directory selected by the test package, normally IPMX_VENDOR_<vendor>.

    The capture script uses --filename for the remote capture filename and --dest for the local output directory.

    Verification and Troubleshooting

    Confirm that the capture file was downloaded successfully.

    Confirm that it contains both RTP packets and RTCP Sender Reports.

    Use the matching SDP file when running the analysis scripts.

    On the VIP, the SDP for the flow is available on the NMOS tab

    If the VIP reports "Packet capture is currently running," allow the existing capture to finish or stop it before retrying.

    If no packets are captured, check the NMOS connection, sender GUID, VIP port, and network connectivity.

- The following steps, a) un IPMX-SETUP-XYZ.bat, b) Run the IS-04 test suite on your Receiver, c) Run the IS-04 test suite on your Sender, and d) Activate your Sender and capture an SDP transport file and a PCAP, should be performed to make sure your environment is properly setup.

- Run IPMX-SETUP-XYZ.bat

- Run the IS-04 test suite on your Receiver

IS-04-01r.bat

- Run the IS-04 test suite on your Sender

IS-04-01s.bat

- Check for failures

The output of the test suite is sorted to have the FAILED tests printed last. There must be no failures and the test plan will indicate in which cases a status other than PASS is allowed.

- Activate your Sender and capture an SDP transport file and a PCAP for analysis

IPMX-PCAPs.bat

Check IPMX_VENDOR_XYZ for the resulting files.

- In general the DuT must be configured and activated prior to each test. Both Senders and Receivers must be streaming. There are a few exceptions where the test may request the Senders and Receivers to be inactive. In those cases first run with them active and then deactivate them and rerun the test to get all the results.

- Legacy TP-10-1Sec13.*.py PCAP analysis scripts require proper Wireshark configuration as they depend on tshark:

    Active Protocols:
    - RTP: Enable rtp_udp

    Time Display Format:
    - Set to "Time as delta from previous packet"

    Additional Setup:
    - Install Lua dissector for IPMX RTCP Sender Reports

    The new ipmx\streams scripts have no such dependencies.

- IS-11 test results

There are new batch files for the analysis of the IS-11 test results targeting specific environments. The examples provided are IPMX-CHECK-HDMI-IS11s.bat and IPMX-CHECK-HDMI-IS11r.bat. Additional ones can be created for SDI and for scenarios without Input or Outputs.

- This IPMX testing environment is a work-in-progress. Your bug reports and suggestions to make it better are welcome.

- To overlay the GitHub repository on top of the package (Ubuntu commands) firt uncompress the package into the IPMX-testing folder and then execute the following commands:
    cd IPMX-testing
	python3.12 -m venv .venv
	source .venv/bin/activate
	pip install -r requirements.txt
	mkdir temp
	cd temp/
	git clone https://github.com/alabou/nmos-testing .
	mv .git/ ..
	cd ..
	git checkout -f testing-IPMX

- To update the NMOS-Testing cache. Set nmostesting/Config.py CACHE_IS_READ_ONLY = False and on the next run of an NMOS test the cache will be updated. To prevent further updates restore CACHE_IS_READ_ONLY = True.