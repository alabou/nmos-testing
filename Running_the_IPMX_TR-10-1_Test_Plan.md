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
	- ✅ `start_capture_pcap.bat` is configured with dumpcap path or VB440 API URL

## Test Execution Overview

### GUID Configuration

A DuT may be tested against a video Profile and an audio Profile simultaneously or in sequence. In this document we use as an example the testing of a device against both a video Profile (uncompressed or JPEG XS) and an audio Profile (PCM or AM824). As such the `ipmx-test-senders.guid` file contains the GUID of the video Sender of the DuT and the GUID of the audio Sender of the DuT. The `ipmx-test-receivers.guid` file contains the GUID of the video Receiver of the DuT and the GUID of the audio Receiver of the DuT.

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

    - If using the VB440 as the capture tool, have the VB440 subscribe to the audio and/or video streams of the DuT Sender.

	- Run IPMX-PCAPs.bat and verify the information listed as the capture test executes. The following lines describe the most important information displayed during the capture of the SDP and PCAP files. It is expected that a tool like the VB440 will be used for official IPMX testing but a LOCAL capture is also possible. The test operator must press any key after the capture of each PCAP file: after the video capture and after the audio capture. If using a tools like the VB440, the subscribed Receivers are those of the capture tool.

	  ```
	  Joining multicast group for sender ...
	  Successfully joined multicast group ...
	  Windows Interfaces ...
	  Windows NPF is ...
	  Started packet capture: video-*.pcap
	  Capturing on ...
	  File: IPMX_VENDOR_XYZ\video-*.pcap
	  Packets captured ...
	  Packets received/dropped on interface ...
	  IPMX_VENDOR_PCAP_CAPTURE is VB440
	  **Press any key to continue...**
	  Stopped packet capture: video-*.pcap

	  video SDP transport file displayed here ...

	  Left multicast group ...

	  Joining multicast group for sender ...
	  Successfully joined multicast group ...
	  Windows Interfaces ...
	  Windows NPF is ...
	  Started packet capture: audio-*.pcap
	  Capturing on ...
	  File: IPMX_VENDOR_XYZ\audio-*.pcap
	  Packets captured ...
	  Packets received/dropped on interface ...
	  IPMX_VENDOR_PCAP_CAPTURE is VB440
	  **Press any key to continue...**

	  Stopped packet capture: audio-*.pcap

	  audio SDP transport file displayed here ...

	  Left multicast group ...
	  ```

	- Verify that the displayed SDP files match with those stored in the IPMX_VENDOR_XYZ directory and correspond to the actual configuration of the video and audio streams.

	- Use Wireshark to open both the video and audio PCAP files and make sure there are a minimum of 10 RTCP IPMX Sender Reports in each PCAP file. If there are not enough RTCP Sender Reports, edit `start_capture_pcap.bat` to increase the `packetLimit` value in the curl command (default is 6000 for video and 1000 for audio) or increase the `-c` parameter for LOCAL capture mode.

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

Python scripts are used to verify conformance to TP-1 section 13. For a given format described in a cfg file the SDP file is retrieved from the Sender. A PCAP file of the stream from the Sender is then analyzed and compared to the SDP file and cfg file to test conformance. There is a automated script IPMX-PCAPs.bat that retrieves the SDP file and captures a PCAP file automatically. It does this using either the network card of the computer used to run the test script or a VB440 device. The steps are described further down. Alternatively the retrieval of the SDP file and capture of the PCAP file can be done manually.

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


#### Running the legacy scripts for each section
   **Section 13.1 Tests**
   ```batch
   python TP-10-1Sec13.1.py cfg\Test*.cfg IPMX_VENDOR_XYZ\video-*.pcap
   python TP-10-1Sec13.1.py cfg\Test*.cfg IPMX_VENDOR_XYZ\audio-*.pcap
   ```

   **Section 13.2 Tests**
   ```batch
   python TP-10-1Sec13.2.py cfg\Test*.cfg IPMX_VENDOR_XYZ\video-*.sdp
   python TP-10-1Sec13.2.py cfg\Test*.cfg IPMX_VENDOR_XYZ\audio-*.sdp
   ```

   **Section 13.3a Tests**
   ```batch
   python TP-10-1Sec13.3a.py IPMX_VENDOR_XYZ\video-*.pcap IPMX_VENDOR_XYZ\video-*.sdp
   python TP-10-1Sec13.3a.py IPMX_VENDOR_XYZ\audio-*.pcap IPMX_VENDOR_XYZ\audio-*.sdp
   ```

   **Section 13.3b Tests**
   ```batch
   python TP-10-1Sec13.3b.py cfg\Test*.cfg IPMX_VENDOR_XYZ\video-*.pcap
   python TP-10-1Sec13.3b.py cfg\Test*.cfg IPMX_VENDOR_XYZ\audio-*.pcap
   ```
#### Running the new scripts for each section
   **Section 13.1 Tests**
   **Section 13.2 Tests**
   **Section 13.3a Tests**
   **Section 13.3b Tests**

   #### Verifying the PCAP file

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
                - Rerun the legacy or new scripts that validate the PCAP and SDP files and verify the script results and the perform visual inspection.
            - Additionally, when testing compliance for the IPMX JPEG XS TDC Profile Mode redo Phase one "For TP-1 sections 13" PCAP and SDP files capture with the DuT Sender configured for the IPMX JPEG XS TDC Profile Mode.
                - Rerun the legacy or new scripts that validate the PCAP and SDP files using the --tdc command line option, and verify the script results and the perform visual inspection.

        - Test the Receivers of the DuT:

            - Redo Phase one "Follow the manual tests described in TP-1 sections 14" with a reference Sender configured for the IPMX JPEG XS Profile.
            - Additionally, when testing compliance for the IPMX JPEG XS TDC Profile Mode Redo Phase one "Follow the manual tests described in TP-1 sections 14" with a reference Sender configured for the IPMX JPEG XS TDC Profile Mode.

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
            - Rerun the legacy or new scripts along with the --hkep command line option that validate the PCAP and SDP files and verify the script results and the perform visual inspection.

    - Test the Receivers of the DuT:

        - Redo Phase one "Follow the manual tests described in TP-1 sections 14" with a reference Sender configured for the vendor selected IPMX Profile with HKEP enabled.

    #### HKEP protocol

    - Configure the Sender for the vendor selected IPMX Profile with HKEP enabled, streaming from a reference Sender to a DuT Receiver or streaming from a DuT Sender to a reference Receiver. The media must visually and audibly playback properly on the DuT Receiver or the Reference Receiver without Disruptions. A DuT tested for both audio and video profiles shall support them simultaneously. Once the DuT streaming assessment is completed the following validation shall be performed. 

    - A PCAP of the TCP exchange of the HKEP protocol between a DuT and its Reference peer must be captured, starting the PCAP capture just prior to connecting the Receiver to the Sender and disconnecting the Receiver from the Sender prior to stop the PCAP capture. The media must visually and audibly playback properly on the Receiver for at least 10 seconds prior to disconnecting it from the Sender. After the disconnect the capture must record for at least 10 seconds prior to stopping the PCAP capture.

    - The PCAP shall be analysed with the ipmx/hkep/hkepDissector.py script with the --validate-all command line option, and all the HKEP validations must PASS.


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
    - Assess that the Senders are transmitting to reference Receivers without disruptions.

    - If PEP is not supported along with HKEP disable the HKEP feature.
    - Activate reference or preferred PEP Senders, each one using a configuration from the `cfg` directory and have the Receivers of the DuT subscribe to the streams.

    - Test the Receivers of the DuT:
    ```batch
    BCP-005-03r.bat
    ```
    - Results are sorted with FAILED tests printed last
    - Review output for any failures (some may be expected per test plan)
    - Assess that the Receivers are receiving from reference Senders without disruptions.

    #### PEP as a Profile Capability

    - Test the Senders of the DuT:

        - Redo Phase one "For TP-1 sections 13" PCAP and SDP files capture with the DuT Sender configured for the vendor selected IPMX Profile with PEP enabled.
            - Rerun the legacy or new scripts along with the --pep command line option that validate the PCAP and SDP files and verify the script results and the perform visual inspection.

    - Test the Receivers of the DuT:

        - Redo Phase one "Follow the manual tests described in TP-1 sections 14" with a reference Sender configured for the vendor selected IPMX Profile with PEP enabled.

    #### PEP privacy requirements

    - An IPMX Reference Sender RS2 shall be configured without PSK and not privacy encrypting its media stream.

    - An IPMX Reference Receiver RR2 shall be configured without PSK and not privacy decrypting its media stream.

    - The DuT Receiver shall not accept to receive the non-encrypted media stream from the RS2 reference Sender.

    - The DuT Receiver shall receive the privacy encrypted media stream from the RS1 reference Sender.

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

