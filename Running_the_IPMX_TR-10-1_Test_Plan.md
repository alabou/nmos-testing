# Running the IPMX TR-10 TP-1 Test Plan

This document provides step-by-step instructions for running the IPMX TR-10 test plan (VSF TR-10 TP-1). It assumes you have:

1. **Read the TP-1 document (VSF TR-10 TP-1)** that describes the test requirements and specifications
2. **Read the IPMX-README.txt** and completed the IPMX testing environment setup
3. **Configured your vendor-specific setup** using `IPMX-SETUP-XYZ.bat` (where XYZ is your vendor name)
4. **Set up the GUID files** for your Senders and Receivers in `IPMX_VENDOR_XYZ/`

**Note:** This test plan corresponds to VSF TR-10-TP-1, which validates compliance with the IPMX Technical Recommendations (TR-10 suite). The tests are organized according to the TP-1 document structure.

## Prerequisites Checklist

The following steps, as described in IPMX-README.txt, ensure that your environment is properly setup.

Before running tests, ensure:

- ✅ Python virtual environment is activated (`.venv\Scripts\activate.bat`)
- ✅ All dependencies are installed (`pip install -r requirements.txt`)
- ✅ Vendor setup script has been run (`IPMX-SETUP-XYZ.bat`)
- ✅ GUID files are configured:
  - `IPMX_VENDOR_XYZ\ipmx-test-senders.guid` (contains sender GUIDs, one per line)
  - `IPMX_VENDOR_XYZ\ipmx-test-receivers.guid` (contains receiver GUIDs, one per line)
- ✅ `nmostesting\UserConfig.py` is configured with correct IP addresses and ports
If testing a Sender
	- ✅ Wireshark is installed and configured (for PCAP analysis):
	  - RTP protocol enabled (`rtp_udp`)
	  - Time display format set to "Time as delta from previous packet"
	  - Lua dissector for IPMX RTCP Sender Reports installed
	If using the automated script to retreive the SDP and PCAP file
	- ✅ LOCAL capture: `start_capture_pcap.bat` is configured with the dumpcap path
	- ✅ VB440 capture: `IPMX-SETUP-XYZ.bat` sets the VB440 probe address and Receiver IDs (`IPMX_VENDOR_PCAP_CAPTURE_VB440_ADDRESS`, `IPMX_VENDOR_PCAP_CAPTURE_VB440_VIDEO_RECEIVER_ID`, `IPMX_VENDOR_PCAP_CAPTURE_VB440_AUDIO_RECEIVER_ID`)
	- ✅ VIP capture: `IPMX-SETUP-XYZ.bat` sets the VIP IP, PORT, and PASSWORD (`VIP_IP`, `VIP_PORT`, `VIP_PASSWORD`)

## Test Execution Overview

- During the IPMX Certification Test Event, the testing authorities may use dedicated test equipment that they have qualified to perform these measurements.

### GUID Configuration

A DuT may be tested against a video Profile and an audio Profile simultaneously or in sequence. In this document we use as an example the testing of a device against both a video Profile (uncompressed or JPEG XS) and an audio Profile (PCM or AM824). As such the `ipmx-test-senders.guid` file contains the GUID of the video Sender of the DuT and the GUID of the audio Sender of the DuT. The `ipmx-test-receivers.guid` file contains the GUID of the video Receiver of the DuT and the GUID of the audio Receiver of the DuT.

When the DuT supports USB, the USB tests use GUID files that list only the USB Senders and USB Receivers of the DuT, and all the other tests use GUID files that list only its video and audio Senders and Receivers. Use a separate vendor setup for the USB tests: next to `IPMX-SETUP-XYZ.bat`, which sets `IPMX_VENDOR` to `XYZ` and uses the `IPMX_VENDOR_XYZ\` directory, create `IPMX-SETUP-XYZ-usb.bat`, which sets `IPMX_VENDOR` to `XYZ-usb` and uses the `IPMX_VENDOR_XYZ-usb\` directory for the USB GUID files and results. The USB role of a device is usually the reverse of its media role: a device that sends video and audio usually receives USB, and a device that receives video and audio usually sends USB. The Sender and Receiver addresses of the USB vendor setup are then swapped compared to the media vendor setup.

Once selected, the GUIDs of the Senders and Receivers of the DuT cannot be changed as they are required to be persisted during the whole test sequence. When the same DuT is tested both as a Sender and as a Receiver role in sequence (not simultaneously), the GUID of a role can be captured when the testing of such role starts and then cannot be changed.

## Test Execution Workflow

### Phase 0: Verifying the configuration

This phase assumes an environment with a unicast NMOS Registry server and a fully functional network.

- Run IPMX-SETUP-XYZ.bat to setup the environment. Make sure that the `IPMX_VENDOR` variable is set to your company name or a derivative of your company name such that you can easily identify the directory where the resulting SDP, PCAP, JSON and guid files are stored.

    #### If testing a Receiver
	- Run IPMX-GUIDr.bat if you are testing Receivers of the DuT. You should observe among the listed Receiver's GUID those that you selected for testing the DuT and that are stored in the `ipmx-test-receivers.guid` file.

	- Activate the Receivers specified in the `ipmx-test-receivers.guid` file and for each of them have a Sender produce a stream for the Receiver to subscribe. Make sure Senders are streaming and that your personal assessment is that the Receivers operate normally and are ready for testing.

    #### If testing a Sender
	- Run IPMX-GUIDs.bat if you are testing Senders of the DuT. You should observe among the listed Sender's GUID those that you selected for testing the DuT and that are stored in the `ipmx-test-senders.guid` file.

	- Activate the Senders specified in the `ipmx-test-senders.guid` file and for each of them have a Receiver subscribe to the stream. Make sure Receivers are receiving the streams and that your personal assessment is that the Senders operate normally and are ready for testing.

	If you plan on using the automated script for retrieving the SDP and PCAP file used during these tests; verify the proper configuration of the system as follow.

    - If using the VB440 as the capture tool, have the VB440 Receivers set by `IPMX_VENDOR_PCAP_CAPTURE_VB440_VIDEO_RECEIVER_ID` and `IPMX_VENDOR_PCAP_CAPTURE_VB440_AUDIO_RECEIVER_ID` subscribe to the video and/or audio streams of the DuT Sender.

    - If using the VIP as the capture tool, have the VIP subscribe to the one or more senders using NMOS. (see Using the PacketStorm VIP for Packet Capture for details)

	- Run IPMX-PCAPs.bat and verify the information listed as the capture test executes. The following lines describe the most important information displayed during the capture of the SDP and PCAP files. It is expected that a tool like the VB440 or VIP will be used for official IPMX testing but a LOCAL capture is also possible. The test operator must press any key after the capture of each PCAP file: after the video capture and after the audio capture. If using a tools like the VB440 or VIP, the subscribed Receivers are those of the capture tool.

	  ```
	  Joining multicast group for sender ...
	  Successfully joined multicast group ...
	  Windows Interfaces ...
	  Windows NPF is ...
	  Started packet capture: video-*.pcap
	  VB440 capture: probe ..., video receiver ...
	  Capturing on ...
	  File: IPMX_VENDOR_XYZ\video-*.pcap
	  Packets captured ...
	  Packets received/dropped on interface ...
	  IPMX_VENDOR_PCAP_CAPTURE is VB440
	  **Press any key to continue...**
	  Stopped packet capture: video-*.pcap
      IPMX_VENDOR_PCAP_CAPTURE is VIP
	  **Press any key to continue...**
	  Stopped packet capture: video-*.pcap
	  video SDP transport file displayed here ...

	  Left multicast group ...

	  Joining multicast group for sender ...
	  Successfully joined multicast group ...
	  Windows Interfaces ...
	  Windows NPF is ...
	  Started packet capture: audio-*.pcap
	  VB440 capture: probe ..., audio receiver ...
	  Capturing on ...
	  File: IPMX_VENDOR_XYZ\audio-*.pcap
	  Packets captured ...
	  Packets received/dropped on interface ...
	  IPMX_VENDOR_PCAP_CAPTURE is VB440
	  **Press any key to continue...**
      IPMX_VENDOR_PCAP_CAPTURE is VIP
	  **Press any key to continue...**
	  Stopped packet capture: audio-*.pcap

	  audio SDP transport file displayed here ...

	  Left multicast group ...
	  ```

	- Verify that the displayed SDP files match with those stored in the IPMX_VENDOR_XYZ directory and correspond to the actual configuration of the video and audio streams.

	- Use Wireshark to open both the video and audio PCAP files and make sure there are a minimum of 10 RTCP IPMX Sender Reports in each PCAP file. If there are not enough RTCP Sender Reports, edit `start_capture_pcap.bat` to increase the limits in the curl command for VB440 capture mode (default `frameLimit` 30 frames for video, `packetLimit` 1000 packets for audio, `timeLimit` 8000 ms for both) or the `-c` parameter of dumpcap for LOCAL capture mode (default 6000 packets for video and 1000 for audio).

- You are now ready to proceed with the TP-1 Test Plan.

### Phase 1
Executing the Test plan TR-10 TP-1

Make sure you have an environment with a unicast NMOS Registry server and a fully functional network.
Follow the manual tests described in TP-1 sections 11
Follow the manual tests described in TP-1 sections 12.1
For TP-1 sections 12.2 and 12.3 for Sender
    - Configure the multicast address and port of the DuT to the default requirements of IPMX.
    - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory

    - Test the Senders of the DuT:
    ```batch
    IPMX-MCASTs.bat
    ```
    - Results are sorted with FAILED tests printed last
    - Review output for any failures (some may be expected per test plan)
    - The multicast address and port of the DuT must be re-configured after this test.

For TP-1 sections 12.3 for receiver

    - Activate reference or preferred Senders, each one using a configuration from the `cfg` directory and have the Receivers of the DuT subscribe to the streams.

    - Test the Receivers of the DuT:
    ```batch
    IPMX-MCASTr.bat
    ```
    - Results are sorted with FAILED tests printed last
    - Review output for any failures (some may be expected per test plan)

Follow the manual tests described in TP-1 sections 12.4

For TP-1 sections 13

Python scripts are used to verify conformance to TP-1 section 13. For a given format described in a cfg file the SDP file is retrieved from the Sender. A PCAP file of the stream from the Sender is then analyzed and compared to the SDP file and cfg file to test conformance. There is a automated script IPMX-PCAPs.bat or IPMX-PCAPs.sh that retrieves the SDP file and captures a PCAP file automatically. It does this using either the network card of the computer used to run the test script, a VB440 device or a VIP device. The steps are described further down. Alternatively the retrieval of the SDP file and capture of the PCAP file can be done manually.

   #### Manual Capture
   The test scripts for section 13 rely on the PCAP capture corresponding to the moment the stream is first activated. When doing the acquisition of the PCAP file manually the suggested methodology is:
   - Disable the Sender under test.
   - Start the Capture process. 
   - Activate the Sender under test using a configuration from the `cfg` directory
   - Stop the Capture.
   Make sure the captured file contains at least 10 RTCP Sender Reports. IMPORTANT: Seperate PCAP file should be captured for Video and for Audio.
   The name of the SDP file and PCAP file stored do not need to match the name generated by automated test script.
   The instruction contained in this document do assume those names.

   #### Automated Capture
   - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory
   - Capture PCAP and SDP files for the Senders of the DuT:

   ```batch
   IPMX-PCAPs.bat
   ```

   - Check the information displayed during the capture operation to make sure the process completed successfully.

   **Important Notes:**
   - **The DuT must be actively streaming** before running this script
   - This script will:
      - Capture PCAP files for video and audio streams
      - Capture SDP transport files for video and audio streams
      - Save files to `IPMX_VENDOR_XYZ\` directory
      - When using LOCAL capture mode, the script uses the interface IP from `CONFIG.MULTICAST_INTERFACE` in `UserConfig.py`

   **Output Files:**
   - `IPMX_VENDOR_XYZ\video-<guid>.pcap` - Video stream PCAP
   - `IPMX_VENDOR_XYZ\audio-<guid>.pcap` - Audio stream PCAP
   - `IPMX_VENDOR_XYZ\video-<guid>.sdp` - Video SDP file
   - `IPMX_VENDOR_XYZ\audio-<guid>.sdp` - Audio SDP file
   - `IPMX_VENDOR_XYZ\video-<guid>.sender.caps.json` - Video Sender Capabilities file
   - `IPMX_VENDOR_XYZ\audio-<guid>.sender.caps.json` - Audio Sender Capabilities file


#### Running the scripts for each section
   **Section 13.1 Tests**
   **Section 13.2 Tests**
   **Section 13.3a Tests**
   **Section 13.3b Tests**

   #### Verifying the PCAP file

    The measurement of the following parameters from section 13.5 takes precedence over the PCAP analysis:
    - Timing of the RTCP and First packet arrival time of TR-10-9 section 11.2
    - CINST of the network compatibility model of TR-10-1
    - VRX of the virtual receive buffer model of TR-10-1

   Select the script based on the format of the streams: raw, jxsv, h264 or h265 for video, pcm or am824 for audio. The list of requirements verified by a given script can be obtained by running a script ipmx_*_validate_pcap.py with the --list-requirements command line option.

   ```batch
   python ipmx\streams\ipmx-streams-tools\ipmx_raw_validate_pcap.py --cmax --cfg cfg\Test*.cfg --sdp IPMX_VENDOR_XYZ\video-*.sdp IPMX_VENDOR_XYZ\video-*.pcap

   python ipmx\streams\ipmx-streams-tools\ipmx_jxsv_validate_pcap.py --cmax --cfg cfg\Test*.cfg --sdp IPMX_VENDOR_XYZ\video-*.sdp IPMX_VENDOR_XYZ\video-*.pcap

   python ipmx\streams\ipmx-streams-tools\ipmx_jxsv_validate_pcap.py --tdc --cmax --cfg cfg\Test*.cfg --sdp IPMX_VENDOR_XYZ\video-*.sdp IPMX_VENDOR_XYZ\video-*.pcap

   python ipmx\streams\ipmx-streams-tools\ipmx_h264_validate_pcap.py --cmax --hrd --hrd-sim --hrd-timing --cfg cfg\Test*.cfg --sdp IPMX_VENDOR_XYZ\video-*.sdp IPMX_VENDOR_XYZ\video-*.pcap

   python ipmx\streams\ipmx-streams-tools\ipmx_h265_validate_pcap.py --cmax --hrd --hrd-sim --hrd-timing --cfg cfg\Test*.cfg --sdp IPMX_VENDOR_XYZ\video-*.sdp IPMX_VENDOR_XYZ\video-*.pcap

   python ipmx\streams\ipmx-streams-tools\ipmx_h265_validate_pcap.py --444 --cmax --hrd --hrd-sim --hrd-timing --cfg cfg\Test*.cfg --sdp IPMX_VENDOR_XYZ\video-*.sdp IPMX_VENDOR_XYZ\video-*.pcap

   python ipmx\streams\ipmx-streams-tools\ipmx_pcm_validate_pcap.py --cfg cfg\Test*.cfg --sdp IPMX_VENDOR_XYZ\audio-*.sdp IPMX_VENDOR_XYZ\audio-*.pcap

   python ipmx\streams\ipmx-streams-tools\ipmx_am824_validate_pcap.py --cfg cfg\Test*.cfg --sdp IPMX_VENDOR_XYZ\audio-*.sdp IPMX_VENDOR_XYZ\audio-*.pcap
   ```

   For the previous commands if HKEP encryption is used add the --hkep command line parameter, if PEP encryption is used add the --pep command line parameter. It is also useful to add the --cannot-test-report command line option to figure out the requirements that cannot be verified.

   The script must succeed (not FAIL) for all the SHALL and SHOULD requirements being tested.

   #### Verifying the SDP file

   ```batch
   python ipmx\sdp_validation_script.py --cfg cfg\Test*.cfg --sdp IPMX_VENDOR_XYZ\video-*.sdp
   ```

   The script must succeed (not FAIL) for all the requirements being tested.

Follow the manual tests described in TP-1 sections 13.4
Follow the manual tests described in TP-1 sections 13.5

Follow the manual tests described in TP-1 sections 14

For TP-1 Section 15
#### Requirement for this section
For Section 15 tests you will need two NMOS Server and the ability to change the settings in the DNS server entries for the NMOS servers.
The NMOS server must also support mDNS discovery and the ability to turn it on or off.
Follow the manual tests described in TP-1 sections 15.1 , 15.2
Follow the manual tests described in TP-1 sections 15.3 , 15.4
Follow the manual tests described in TP-1 sections 15.5 , 15.6
Follow the manual tests described in TP-1 sections 15.7

For TP-1 sections 15.8
#### Peer-to-Peer Testing
To test the peer-to-peer mode it is required to shutdown all the NMOS Registry servers and to remove the DNS_SD entries of NMOS Registry servers. Then update for this test only the `nmostesting\UserConfig.py` file of the IPMX testing environment to set CONFIG.DNS_SD_MODE = 'multicast' instead of CONFIG.DNS_SD_MODE = 'unicast'.

   - Test the Senders of the DuT:
   ```batch
   IS-04-03s.bat
   ```
   - Results are sorted with FAILED tests printed last
   - Review output for any failures (some may be expected per test plan)

   - Test the Receivers of the DuT:
   ```batch
   IS-04-03r.bat
   ```
   - Results are sorted with FAILED tests printed last
   - Review output for any failures (some may be expected per test plan)

Restore the original `nmostesting\UserConfig.py` file with CONFIG.DNS_SD_MODE = 'unicast' and restore the DNS-SD entries of the NMOS Registry servers then restart them.

### Phase 2: NMOS API Compliance Testing

These tests verify that your Device Under Test (DuT) correctly implements the NMOS APIs. This phase assumes an environment with a unicast NMOS Registry server and a fully functional network.

1. **IS-04 Node API Tests**

    - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory

    - Test the Senders of the DuT:
    ```batch
    IS-04-01s.bat
    ```
    - Results are sorted with FAILED tests printed last
    - Review output for any failures (some may be expected per test plan)
    - Results for auto_node tests indicating the following must be ignored: "This test is only performed when an API supports Authorization and 'ENABLE_AUTH' is True"
    - Results fro auto_node tests indicating the following must be ignored: "No resources found to perform this test: GET /x-nmos/node/v1.3/receivers/{receiverId}", "No resources found to perform this test: OPTIONS /x-nmos/node/v1.3/receivers/{receiverId}/target"

    - Activate reference or preferred Senders, each one using a configuration from the `cfg` directory and have the Receivers of the DuT subscribe to the streams.

    - Test the Receivers of the DuT:
    ```batch
    IS-04-01r.bat
    ```
    - Results are sorted with FAILED tests printed last
    - Review output for any failures (some may be expected per test plan)
    - Results for auto_node tests indicating the following must be ignored: "This test is only performed when an API supports Authorization and 'ENABLE_AUTH' is True"
    - Results for auto_node indicating the following must be ignored: "No resources found to perform this test: GET /x-nmos/node/v1.3/flows/{flowId}", "No resources found to perform this test: GET /x-nmos/node/v1.3/senders/{senderId}", "No resources found to perform this test: GET /x-nmos/node/v1.3/sources/{sourceId}"

2. **IS-05 Connection Management Tests**

    - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory

    - Test the Senders of the DuT:
    ```batch
    IS-05-01s.bat
    ```
    - Results are sorted with FAILED tests printed last
    - Review output for any failures (some may be expected per test plan)
    - Results for auto_connection indicating the following must be ignored: "This test is only performed when an API supports Authorization and 'ENABLE_AUTH' is True"
    - Results for auto_connection indicating the following must be ignored: "No resources found to perform this test: GET /x-nmos/connection/v1.1/single/receivers/{receiverId}", "No resources found to perform this test: GET /x-nmos/connection/v1.1/single/receivers/{receiverId}/active", " No resources found to perform this test: GET /x-nmos/connection/v1.1/single/receivers/{receiverId}/constraints", "No resources found to perform this test: GET /x-nmos/connection/v1.1/single/receivers/{receiverId}/staged", "No resources found to perform this test: OPTIONS /x-nmos/connection/v1.1/single/receivers/{receiverId}/staged", "No resources found to perform this test: GET /x-nmos/connection/v1.1/single/receivers/{receiverId}/transporttype"

    - Activate reference or preferred Senders, each one using a configuration from the `cfg` directory and have the Receivers of the DuT subscribe to the streams.

    - Test the Receivers of the DuT:
    ```batch
    IS-05-01r.bat
    ```
    - Results are sorted with FAILED tests printed last
    - Review output for any failures (some may be expected per test plan)
    - Results for auto_connection indicating the following must be ignored: "This test is only performed when an API supports Authorization and 'ENABLE_AUTH' is True"
    - Results for auto_connection indicating the following must be ignored: "No resources found to perform this test: GET /x-nmos/connection/v1.1/single/senders/{senderId}", "No resources found to perform this test: GET /x-nmos/connection/v1.1/single/senders/{senderId}/active", "No resources found to perform this test: GET /x-nmos/connection/v1.1/single/senders/{senderId}/constraints", "No resources found to perform this test: GET /x-nmos/connection/v1.1/single/senders/{senderId}/staged", "No resources found to perform this test: OPTIONS /x-nmos/connection/v1.1/single/senders/{senderId}/staged", "No resources found to perform this test: GET /x-nmos/connection/v1.1/single/senders/{senderId}/transporttype"

3. **IS-05 Interaction with IS-04**

    - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory

    - Test the Senders of the DuT:
    ```batch
    IS-05-02s.bat
    ```
    - Results are sorted with FAILED tests printed last
    - Review output for any failures (some may be expected per test plan)
    - The multicast address and port of the DuT must be re-configured after this test.

    - Activate reference or preferred Senders, each one using a configuration from the `cfg` directory and have the Receivers of the DuT subscribe to the streams.

    - Test the Receivers of the DuT:
    ```batch
    IS-05-02r.bat
    ```
    - Results are sorted with FAILED tests printed last
    - Review output for any failures (some may be expected per test plan)

4. **IS-11 Stream Compatibility Tests**

    - For HDMI, use a source that follows the EDID’s preferred mode. If such a source is not available, set in UserConfig.py the CONFIG.IS11_SOURCE_EDID_VERIFICATION to False and let the test verify the EDID or set the CONFIG.IS11_SOURCE_EDID_VERIFICATION option to True and verify manually, connecting a source device (e.g., a Kramer) that allows verifying the EDID produced by the DuT. For manual verification, the test suite will pause and indicate the expected refresh/sample rate value to be verified in the EDID’s preferred mode using the tool.
    - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory
    - The source must be directly connected to the Sender.

    - Test the Senders of the DuT:
    ```batch
    IS-11-01s.bat
    ```
    - Results are sorted with FAILED tests printed last
    - Review output for any failures (some may be expected per test plan)
    - The results are saved in `IPMX_VENDOR_XYZ\IS-11-01s.json`
    - According to the testing configuration run an IPMX-CHECK script. The configuration is described as having inputs, outputs or none, supporting EDID or not, etc.
    - The FINAL VERDICT of the IPMX-CHECK script indicates whether the DuT passes or fails the IS-11 tests.
      - *If an IPMX device declares in its conformance IPMX Device Declaration supporting the streaming of only one video refresh rate. It is then allowed to get the result Could Not Test for test_02_03_05_01, otherwise it must PASS.*
     - *If an IPMX device using the UserConfig option IS11_SOURCE_EDID_VERIFICATION=True produces the expected refresh rate in the source EDID preferred mode, it is then allowed to get the result Could Not Test for test_02_03_05_01, otherwise it must PASS.*
     
      - *If an IPMX device declares in its conformance IPMX Device Declaration supporting the streaming of only one audio sample rate. It is then allowed to get the result Could Not Test for test_02_03_05_02, otherwise it must PASS.*
     - *If an IPMX device using the UserConfig option IS11_SOURCE_EDID_VERIFICATION=True produces the expected sample rate in the source EDID preferred mode, it is then allowed to get the result Could Not Test for test_02_03_05_02, otherwise it must PASS.*

    ```batch
    IPMX-CHECK-HDMI-IS11s.bat
    ```
    - Activate reference or preferred Senders, each one using a configuration from the `cfg` directory and have the Receivers of the DuT subscribe to the streams.
    - Make sure the reference or preferred Senders are properly configured in the UserConfig.py file. The reference or preferred Sender must be used by only one Receiver at a time because the test may de-activate and re-activate it.
    - The DuT output must be connected.

    - Test the Receivers of the DuT:
    ```batch
    IS-11-01r.bat
    ```
    - Results are sorted with FAILED tests printed last
    - Review output for any failures (some may be expected per test plan)
    - The results are saved in `IPMX_VENDOR_XYZ\IS-11-01r.json`
    - According to the testing configuration run an IPMX-CHECK script. The configuration is described as having inputs, outputs or none, supporting EDID or not, etc.
    - The FINAL VERDICT of the IPMX-CHECK script indicates whether the DuT passes or fails the IS-11 tests.

    ```batch
    IPMX-CHECK-HDMI-IS11r.bat
    ```

5. **SDP Validation Tests**

    - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory

    - Test the Senders of the DuT:
    ```batch
    IPMX-SDPs.bat
    ```
    - Results are sorted with FAILED tests printed last
    - Review output for any failures (some may be expected per test plan)

    - Activate reference or preferred Senders, each one using a configuration from the `cfg` directory and have the Receivers of the DuT subscribe to the streams.

    - Test the Receivers of the DuT:
    ```batch
    IPMX-SDPr.bat
    ```
    - Results are sorted with FAILED tests printed last
    - Review output for any failures (some may be expected per test plan)

    - Those files are generated:
        - `IPMX_VENDOR_XYZ\video-<guid>.receiver.caps.json` - Video Receiver Capabilities file
        - `IPMX_VENDOR_XYZ\audio-<guid>.receiver.caps.json` - Audio Receiver Capabilities file

6. **Sender and Receiver Capabilities Tests**

    - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory

    - Test the Senders of the DuT:
    ```batch
    BCP-004-02s.bat
    ```
    - Results are sorted with FAILED tests printed last
    - Review output for any failures (some may be expected per test plan)

    - Activate reference or preferred Senders, each one using a configuration from the `cfg` directory and have the Receivers of the DuT subscribe to the streams.

    - Test the Receivers of the DuT:
    ```batch
    BCP-004-01r.bat
    ```
    - Results are sorted with FAILED tests printed last
    - Review output for any failures (some may be expected per test plan)

7. **Compressed Stream Profile Tests**

    - JPEG XS and JPEG XS TDC Profile Mode
        #### BCP-006-01
        - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory for a JPEG XS video stream.

        - Test the Senders of the DuT:
        ```batch
        BCP-006-01s.bat
        ```
        - Results are sorted with FAILED tests printed last
        - Review output for any failures (some may be expected per test plan)

        - Activate reference or preferred Senders, each one using a configuration from the `cfg` directory for a JPEG XS video stream and have the Receivers of the DuT subscribe to the streams.

        - Test the Receivers of the DuT:
        ```batch
        BCP-006-01r.bat
        ```
        - Results are sorted with FAILED tests printed last
        - Review output for any failures (some may be expected per test plan)

        #### SDP Transport File and Capabilities

        - Run the test of section 5 "SDP Validation Tests" with the DuT Sender or a reference Sender configured for the IPMX JPEG XS Profile.
        - Additionally, when testing compliance for the IPMX JPEG XS TDC Profile Mode run the test of section 5 "SDP Validation Tests" with the DuT Sender or a reference Sender configured for the IPMX JPEG XS TDC Profile Mode.

        #### TR-10-15 Part 1

        - Test the Senders of the DuT:

            - Redo Phase one "For TP-1 sections 13" PCAP and SDP files capture with the DuT Sender configured for the IPMX JPEG XS Profile.
                - Rerun the scripts that validate the PCAP and SDP files and verify the script results and the perform visual inspection.
            - Additionally, when testing compliance for the IPMX JPEG XS TDC Profile Mode redo Phase one "For TP-1 sections 13" PCAP and SDP files capture with the DuT Sender configured for the IPMX JPEG XS TDC Profile Mode.
                - Rerun the scripts that validate the PCAP and SDP files using the --tdc command line option, and verify the script results and the perform visual inspection.

        - Test the Receivers of the DuT:

            - Redo Phase one "Follow the manual tests described in TP-1 sections 14", more specifically section 14.3.1, with a reference Sender configured for the IPMX JPEG XS Profile.
            - Additionally, when testing compliance for the IPMX JPEG XS TDC Profile Mode Redo Phase one "Follow the manual tests described in TP-1 sections 14", more specifically section 14.3.1, with a reference Sender configured for the IPMX JPEG XS TDC Profile Mode.

    - H.264
        - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory for an H.264 video stream.

        - Test the Senders of the DuT:
        ```batch
        BCP-006-02s.bat
        ```
        - Results are sorted with FAILED tests printed last
        - Review output for any failures (some may be expected per test plan)

        - Activate reference or preferred Senders, each one using a configuration from the `cfg` directory for an H.264 video stream and have the Receivers of the DuT subscribe to the streams.

        - Test the Receivers of the DuT:
        ```batch
        BCP-006-02r.bat
        ```
        - Results are sorted with FAILED tests printed last
        - Review output for any failures (some may be expected per test plan)

    - H.265 / HEVC
        - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory for an H.265 video stream.

        - Test the Senders of the DuT:
        ```batch
        BCP-006-03s.bat
        ```
        - Results are sorted with FAILED tests printed last
        - Review output for any failures (some may be expected per test plan)

        - Activate reference or preferred Senders, each one using a configuration from the `cfg` directory for an H.265 video stream and have the Receivers of the DuT subscribe to the streams.

        - Test the Receivers of the DuT:
        ```batch
        BCP-006-03r.bat
        ```
        - Results are sorted with FAILED tests printed last
        - Review output for any failures (some may be expected per test plan)


9. **HKEP Capability Tests**

    #### BCP-005-02
    - Disable the PEP feature of the DuT
    - Connect an HDCP compliant source to the inputs of the DuT
    - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory

    - Test the Senders of the DuT:
    ```batch
    BCP-005-02s.bat
    ```
    - Results are sorted with FAILED tests printed last
    - Review output for any failures (some may be expected per test plan)
    - Assess that the Senders are transmitting to reference Receivers without disruptions.

    - Disable the PEP feature of the DuT
    - Connect an HDCP compliant monitor to the outputs of the DuT
    - Activate reference or preferred HKEP Senders, each one using a configuration from the `cfg` directory and have the Receivers of the DuT subscribe to the streams.

    - Test the Receivers of the DuT:
    ```batch
    BCP-005-02r.bat
    ```
    - Results are sorted with FAILED tests printed last
    - Review output for any failures (some may be expected per test plan)
    - Assess that the Receivers are receiving from reference Senders without disruptions.

    #### HKEP as a Profile Capability

    - Test the Senders of the DuT:

        - Redo Phase one "For TP-1 sections 13" PCAP and SDP files capture with the DuT Sender configured for the vendor selected IPMX Profile with HKEP enabled.
            - Rerun the scripts along with the --hkep command line option that validate the PCAP and SDP files and verify the script results and the perform visual inspection.

    - Test the Receivers of the DuT:

        - Redo Phase one "Follow the manual tests described in TP-1 sections 14", more specifically section 14.3.1, with a reference Sender configured for the vendor selected IPMX Profile with HKEP enabled.

    #### HKEP protocol

    - Configure the Sender for the vendor selected IPMX Profile with HKEP enabled, streaming from a reference Sender to a DuT Receiver or streaming from a DuT Sender to a reference Receiver. The media must visually and audibly playback properly on the DuT Receiver or the Reference Receiver without Disruptions. A DuT tested for both audio and video profiles shall support them simultaneously. Once the DuT streaming assessment is completed the following validation shall be performed. 

    - A PCAP of the TCP exchange of the HKEP protocol between a DuT and its Reference peer must be captured, starting the PCAP capture just prior to connecting the Receiver to the Sender and disconnecting the Receiver from the Sender prior to stop the PCAP capture. The media must visually and audibly playback properly on the Receiver for at least 10 seconds prior to disconnecting it from the Sender. After the disconnect the capture must record for at least 10 seconds prior to stopping the PCAP capture.

    - The PCAP shall be analysed with the ipmx/hkep/hkepDissector.py script with the --validate-all command line option, and all the HKEP validations must PASS.

        - It is possible that the disconnect from the Receiver at the end of the above sequence causes an invalid final sequence of messages, as the Sender may not be able to complete the message exchange before the TCP connection is closed. Such an error in the last sequence of the PCAP must be ignored.

10. **PEP Capability Tests**

    #### BCP-005-03

    - If PEP is not supported along with HKEP disable the HKEP feature.
    - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory

    - Test the Senders of the DuT:
    ```batch
    BCP-005-03s.bat
    ```
    - Results are sorted with FAILED tests printed last
    - Review output for any failures (some may be expected per test plan)
    - If test_06 returns "Could Not Test" with the message "testing ECDH private/public keys pair regeneration require inactive senders", deactivate the Senders (master_enable set to false) and run the test suite again, this time only considering the results of test_06.
    - Assess that the Senders are transmitting to reference Receivers without disruptions.

    - If PEP is not supported along with HKEP disable the HKEP feature.
    - Activate reference or preferred PEP Senders, each one using a configuration from the `cfg` directory and have the Receivers of the DuT subscribe to the streams.

    - Test the Receivers of the DuT:
    ```batch
    BCP-005-03r.bat
    ```
    - Results are sorted with FAILED tests printed last
    - Review output for any failures (some may be expected per test plan)
    - If test_07 returns "Could Not Test" with the message "testing ECDH private/public keys pair regeneration require inactive receivers", deactivate the Receivers (master_enable set to false) and run the test suite again, this time only considering the results of test_07.
    - Assess that the Receivers are receiving from reference Senders without disruptions.

    #### PEP as a Profile Capability

    - Test the Senders of the DuT:

        - Redo Phase one "For TP-1 sections 13" PCAP and SDP files capture with the DuT Sender configured for the vendor selected IPMX Profile with PEP enabled.
            - Rerun the scripts along with the --pep command line option that validate the PCAP and SDP files and verify the script results and the perform visual inspection.

    - Test the Receivers of the DuT:

        - Redo Phase one "Follow the manual tests described in TP-1 sections 14", more specifically section 14.3.1, with a reference Sender configured for the vendor selected IPMX Profile with PEP enabled.

    #### PEP privacy requirements

    - An IPMX Reference Sender RS2 shall be configured without PSK and not privacy encrypting its media stream.

    - An IPMX Reference Receiver RR2 shall be configured without PSK and not privacy decrypting its media stream.

    - The DuT Receiver shall not accept to receive the non-encrypted media stream from the RS2 reference Sender.

    - The DuT Receiver shall receive the privacy encrypted media stream from the RS1 reference Sender.

11. **USB Capability Tests**

    These tests follow TP-1 section 21.3. For IPMX certification the USB streams must be privacy encrypted with PEP: the non-encrypted mode described in TR-10-14 is not allowed.

    #### Setup

    - A USB Sender of the DuT has a keyboard and a mouse connected to two of its USB ports. It is connected to a reference USB Receiver, itself connected to a USB port of a host computer.
    - A USB Receiver of the DuT is connected to a USB port of a host computer, to which it provides the keyboard and mouse. It is connected to a reference USB Sender that has a keyboard and a mouse connected to two of its USB ports.
    - The DuT is configured with the 128 bit PSK `000102030405060708090a0b0c0d0e0f` and the key_id `0001020304050607`. A USB Sender of the DuT privacy encrypts its USB streams and a USB Receiver of the DuT privacy decrypts them. The reference USB Sender and Receiver are configured the same way.
    - Run the USB vendor setup (see "GUID Configuration"): its GUID files list only the USB Senders and USB Receivers of the DuT.
    - The DuT remains connected to its reference peer throughout the testing, unless a test calls for a disconnect and reconnect. The Vendor does not disconnect and reconnect the keyboard and mouse of a DuT Sender, or the host computer of a DuT Receiver, during the test.

    #### BCP-007-02

    - Activate the USB Senders of the DuT and connect a reference USB Receiver to them.

    - Test the Senders of the DuT:
    ```batch
    BCP-007-02s.bat
    ```
    - Results are sorted with FAILED tests printed last
        - The Warning on test_04 about “SHOULD declare urn:x-nmos:cap:transport:usb_class capabilities” shall not be considered a failure.
    - Review output for any failures (some may be expected per test plan)
    - Assess that the keyboard and mouse connected to the DuT Sender play back properly, as generated, on the host computer connected to the reference Receiver.

    - Activate a reference USB Sender and connect the USB Receivers of the DuT to it.

    - Test the Receivers of the DuT:
    ```batch
    BCP-007-02r.bat
    ```
    - Results are sorted with FAILED tests printed last
        - The Warning on test_06 about “SHOULD indicate the supported USB class using the ‘urn:x-nmos:cap:transport:usb_class’ parameter constraint” shall not be considered a failure.
        - The Warning on test_07 about “SHOULD declare urn:x-nmos:cap:transport:usb_class capabilities” shall not be considered a failure.
    - Review output for any failures (some may be expected per test plan)
    - Assess that the keyboard and mouse connected to the reference Sender play back properly, as generated, on the host computer connected to the DuT Receiver.

    #### BCP-005-03

    - With the USB Senders of the DuT connected to a reference USB Receiver, test the Senders of the DuT:
    ```batch
    BCP-005-03s.bat
    ```
    - Results are sorted with FAILED tests printed last
    - Review output for any failures (some may be expected per test plan)
    - If test_06 returns "Could Not Test" with the message "testing ECDH private/public keys pair regeneration require inactive senders", deactivate the Senders (master_enable set to false) and run the test suite again, this time only considering the results of test_06.
    - Assess that the keyboard and mouse connected to the DuT Sender play back properly, as generated, on the host computer connected to the reference Receiver. If the test_06 re-run deactivated the Senders, activate them and reconnect the reference Receiver first.

    - With a reference USB Sender connected to the USB Receivers of the DuT, test the Receivers of the DuT:
    ```batch
    BCP-005-03r.bat
    ```
    - Results are sorted with FAILED tests printed last
    - Review output for any failures (some may be expected per test plan)
    - If test_07 returns "Could Not Test" with the message "testing ECDH private/public keys pair regeneration require inactive receivers", deactivate the Receivers (master_enable set to false) and run the test suite again, this time only considering the results of test_07.
    - Assess that the keyboard and mouse connected to the reference Sender play back properly, as generated, on the host computer connected to the DuT Receiver. If the test_07 re-run deactivated the Receivers, connect them to the reference Sender again first.

    - BCP-005-03 only tests the Senders and Receivers that support privacy encryption. A USB Sender of the DuT must have the IS-04 `privacy` attribute set to `true`, and a USB Receiver of the DuT must expose the `ext_privacy_*` transport parameters. For a USB DuT, a "Not Implemented" result with "No BCP-005-03 (IPMX/PEP) Sender found" or "No BCP-005-03 (IPMX/PEP) Receiver found" is a failure.

    #### SDP Transport File and Capabilities

    These tests are those of TP-1 section 18.2.

    - With the USB Senders of the DuT connected to a reference USB Receiver, test the Senders of the DuT:
    ```batch
    IPMX-SDPs-USB.bat
    ```
    - Results are sorted with FAILED tests printed last
    - Review output for any failures (some may be expected per test plan)

    - With a reference USB Sender connected to the USB Receivers of the DuT, test the Receivers of the DuT:
    ```batch
    IPMX-SDPr-USB.bat
    ```
    - Results are sorted with FAILED tests printed last
    - Review output for any failures (some may be expected per test plan)
    - This file is generated:
        - `IPMX_VENDOR_XYZ-usb\data-<guid>.receiver.caps.json` - USB Receiver Capabilities file

    #### USB protocol

    The test is performed with a USB Sender of the DuT and a reference USB Receiver, or with a reference USB Sender and a USB Receiver of the DuT. Both the keyboard and the mouse are used, simultaneously.

    - Connect the Receiver to the Sender and assess that the keyboard and mouse play back properly, as generated, on the host computer connected to the Receiver. Then disconnect the Receiver from the Sender.

    - Capture a PCAP of the TCP exchange between the Sender and the Receiver:
        - Start the capture, then connect the Receiver to the Sender.
        - Use the keyboard and the mouse for at least 10 seconds, making sure they play back properly, as generated, on the host computer connected to the Receiver.
        - Disconnect the Receiver from the Sender, keep capturing for at least 10 more seconds, then stop the capture.
        - The USB exchange is unicast TCP between the Sender and the Receiver, so the capture point must see that traffic, for example a mirrored switch port. `IPMX-PCAPs.bat` captures multicast RTP streams and does not apply here.

    - Save the SDP transport file of the Sender before the Sender is deactivated. A Sender may change the `iv` and `key_version` privacy parameters only across a deactivation and activation (TR-10-13), and the analysis needs the values used during the capture. For a USB Sender of the DuT:
    ```batch
    curl.exe -L -o IPMX_VENDOR_XYZ-usb\usb-<guid>.sdp http://%IPMX_SENDER_IS05_ADDRESS%:%IPMX_SENDER_IS05_PORT%/x-nmos/connection/v1.1/single/senders/<guid>/transportfile
    ```
    - For a reference Sender, use the IS-05 address, port and GUID of the reference Sender.

    - Analyse the PCAP file:
    ```batch
    python ipmx\usb\ipmx-usb-tools\usbDissector.py --psk 000102030405060708090a0b0c0d0e0f --sdp IPMX_VENDOR_XYZ-usb\usb-<guid>.sdp -r IPMX_VENDOR_XYZ-usb\usb-<guid>.pcap
    ```
    - Always pass the `--psk` and `--sdp` options. The error "Error loading PEP parameters: No privacy descriptor found in SDP" means that the Sender does not declare privacy encryption: it is a failure, not a usage error. Do not remove the options to get past it.
    - All the USB validations must PASS: the last line must read `Result: PASS`, and the line before it must report 0 error(s) and 0 warning(s) (`Total: N session(s), 0 error(s), 0 warning(s)`, possibly followed by a count of diag(s)). `Result: PASS` and the exit code 0 do not count warnings, so check both lines. A "Stream is not encrypted" warning is a failure.
    - `Result: NOT TESTED` (exit code 2) means the PCAP file holds no IPMX USB message: the capture missed the exchange between the Sender and the Receiver. Capture again; it is not a pass.
    - DIAG results are for the operator to judge and never count as failures. The `--diagnose` option adds such checks against core USB 2.0 rules that TR-10-14 does not mandate.
    - The `-r` option prints the checklist of the requirements with their result.

    #### Unplug and re-plug USB devices

    The test is performed with a USB Sender of the DuT connected to a reference USB Receiver, or with a reference USB Sender connected to a USB Receiver of the DuT.

    - With the keyboard and mouse connected to the Sender, confirm that the mouse movements and the keystrokes arrive at the host computer connected to the Receiver as generated.
    - The operator unplugs both the keyboard and the mouse and keeps them unplugged for 5 seconds.
    - The operator re-plugs the keyboard and the mouse.
    - Wait until the host computer connected to the Receiver has enumerated the keyboard and the mouse again (it lists them again). Input made before that may never reach it.
    - Confirm again that the mouse movements and the keystrokes arrive at the host computer connected to the Receiver as generated.

## Using the PacketStorm VIP for Packet Capture

    The PacketStorm VIP can capture video and audio streams for the Section 13 tests. Captures include RTP media packets and RTCP Sender Reports.

    Prepare the VIP

    Connect the VIP to the media network and confirm that its management interface is reachable from the computer running the test package.

    Before starting the capture test, use an NMOS controller to connect the video and audio Senders under test to the appropriate VIP Receivers. Verify that the VIP is receiving the streams.

    Confirm that the sender GUIDs in the test package’s ipmx-test-senders.guid file identify the Senders connected to the VIP.

    Confirm that no other VIP packet capture is running.

    Configure the Test Package

    Follow the PacketStorm VIP setup instructions in IPMX-README.txt.

    Select VIP as the capture device and configure:

    VIP management IP address.

    VIP admin password.

    VIP capture port: A or B.

    Video frame count and audio packet count.

    Packet capture length.

    The sender GUID is supplied automatically by the integrated test workflow.

    Select the Capture Length

    Capture enough traffic for the requirements being evaluated. For tests requiring a two-second measurement window, capture approximately three seconds or longer.

    Examples:

    Video Stream
    60 fps video
    Capture setting
    --count 180 --video true
    Approximate duration
    3 seconds

    Video Stream
    50 fps video
    Capture setting
    --count 150 --video true
    Approximate duration
    3 seconds

    Audio Stream with 1 ms packet time
    Capture setting
    --count 3500 --video false
    Approximate duration
    Approximately 3 seconds, including RTCP

    With --video true, the count specifies complete video frames. With --video false, it specifies packets. Shorter audio packet times require larger packet counts.

    Verify the actual duration in the resulting capture.

    Run the Capture

    With the test package’s Python environment activated and the vendor setup settings loaded, run the appropriate command from the main package folder.

    Windows:

    IPMX-PCAPs.bat

    Linux/WSL:

    ./IPMX-PCAPs.sh

    The integrated workflow invokes vip_packet_capture_sender_id.py for each selected Sender and saves the downloaded capture in the output directory selected by the test package, normally IPMX_VENDOR_<vendor>.

    Verify the Captured Files

    Before running the Section 13 analysis:

    Confirm that capture and download completed successfully.

    Confirm that each capture contains the intended media stream and its RTCP Sender Reports.

    Confirm that the capture duration and number of Sender Reports are sufficient for the tests being performed.

    Confirm that the matching SDP describes the stream configuration used during capture.

    Run the appropriate video or audio validator with the capture, matching SDP, and test configuration. Review all individual results, including FAIL and CANNOT_TEST; successful capture does not establish that the stream passes the tests.

    If the VIP reports that a packet capture is already running, allow it to finish or stop it before starting another.

## Important Notes

1. **Device State**: In general, the DuT must be **configured and activated prior to each test**. Both Senders and Receivers must be streaming. There are a few exceptions where tests may request inactive devices - in those cases, first run with them active, then deactivate and rerun the test.

2. **Test Results**: The output of NMOS test suites is sorted to have FAILED tests printed last. Review all failures carefully - the TP-1 document will indicate in which cases a status other than PASS is allowed.

3. **Configuration Files**: The `cfg\` directory contains configuration files for different test scenarios. Select the appropriate `.cfg` file based on:
   - Video format (1080p, UHD)
   - Frame rate (50, 59, 60)
   - Color space (YUV, RGB8)
   - Audio format (L16, L24)
   - Channel count (1, 2, 8)
   - PTP usage (files with "PTP" suffix)

4. **PTP Testing**: Tests should be performed both with and without a PTP Grandmaster present on the network, as specified in TP-1 Section 9.

5. **Command Prompt**: Use a regular Windows Command Prompt to run batch files, **do NOT use PowerShell**.

6. **Debugging**: For example if running IS-04-01s.bat and you get a FAIL for test_08, you should look at the batch file for getting the suite name, here IS-04-01, then get the file name according to the test suite in the `nmostesting\suites` directory, here `nmostesting\suites\IS0401Test.py` and search for a function named `test_08` and look for the error message.

7. **Redundancy**: The IPMX test suite requires that ST 2022-7 redundancy is not active on the DuT during the NMOS tests. It is highly recommended to deactivate redundancy on the Senders and Receivers prior to running this test plan.

---

*This IPMX testing environment is a work-in-progress. Bug reports and suggestions to make it better are welcome.*

