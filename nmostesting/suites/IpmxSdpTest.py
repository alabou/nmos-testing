# Copyright (C) 2025 Matrox Graphics Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# NMOS Testing messages displayed to a user for a test result
#
# PASS => "Pass"
#
# WARNING => "Warning"
#   Not a failure, but the API being tested is responding or configured in a way which is
#
# FAIL => "Fail"
#   Required feature of the specification has been found to be implemented incorrectly
#
# MANUAL => "Manual"
#   Test suite does not currently test this feature, so it must be tested manually
#
# NA => "Not Applicable"
#   Test is not applicable, e.g. due to the version of the specification being tested
#
# OPTIONAL => "Not Implemented"
#   Recommended/optional feature of the specifications has been found to be not implemented. Detail message
#   should explain the effect of this feature being unimplemented
#
# DISABLED => "Test Disabled"
#   Test is disabled due to test suite configuration; change the config or test manually
#
# UNCLEAR => "Could Not Test"
#   Test was not run due to prior responses from the API, which may be OK, or indicate a fault
import time
import json
import subprocess
import os
import platform
from time import sleep

from jsonschema import ValidationError

from ..GenericTest import GenericTest, NMOSTestException
from ..IS04Utils import IS04Utils
from ..IS05Utils import IS05Utils
from ..TestHelper import check_content_type
from ..TestHelper import WebsocketWorker
from ..TestResult import Test
from ..IPMXUtils import filter_resources

from urllib.parse import urlparse

from .. import Config as CONFIG

from ..MatroxSdp import MatroxSdp, MatroxSdpEnums

from ..MatroxSdpCheck import SdpCheckError
from ..MatroxSdpCheck import check_sdp_rfc4175
from ..MatroxSdpCheck import check_sdp_st2110_10
from ..MatroxSdpCheck import check_sdp_st2110_21
from ..MatroxSdpCheck import check_sdp_st2110_20
from ..MatroxSdpCheck import check_sdp_rfc9134
from ..MatroxSdpCheck import check_sdp_st2110_22
from ..MatroxSdpCheck import check_sdp_rfc3551
from ..MatroxSdpCheck import check_sdp_st2110_30
from ..MatroxSdpCheck import check_sdp_st2110_31
from ..MatroxSdpCheck import check_sdp_rfc6184
from ..MatroxSdpCheck import check_sdp_rfc7798

from ..MulticastUtils import MulticastUtils, MulticastJoinError

# Import SDP to CCF capabilities converter
from ..SdpToCapabilities import SdpToCapabilitiesConverter

# Import Flow to CCF capabilities converter
from ..FlowToCapabilities import FlowToCapabilitiesConverter

from ..MatroxCCF import (
    FormatVideo, FormatAudio, FormatData, FormatMux,
    CapFormatMediaType, CapFormatGrainRate, CapFormatFrameWidth, CapFormatFrameHeight,
    CapFormatInterlaceMode, CapFormatColorspace, CapFormatComponentDepth,
    CapFormatChannelCount, CapFormatSampleRate, CapTransportBitRate,
    CapFormatVideoLayers, CapMetaFormat, CapMetaLayer,
    Caps, CapSet, Capability, RangeValue, RangeType, caps_constrict_by_cons, 
    conset_included_in_caps, convert_caps_json_to_caps
)

QUERY_API_KEY = "query"
NODE_API_KEY = "node"
CONNECTION_API_KEY = "connection"

MuxOpaque = "video/MP2T"
MuxFullyDescribedMpeg2TS = "application/MP2T"
MuxFullyDescribedGeneric = "application/mp2t"


def ifelse(c, t, f):
    if c:
        return t
    else:
        return f

class IpmxSdpTest(GenericTest):
    """
    Runs Node Tests covering SDP transport files
    """

    def __init__(self, apis, **kwargs):
        # Don't auto-test /transportfile as it is permitted to generate a 404 when master_enable is false
        omit_paths = [
            "/single/senders/{senderId}/transportfile",
            "/single/senders/{senderId}/staged",
            "/single/senders/{senderId}/active",
            "/single/senders/{senderId}/constraints",
            "/single/senders/{senderId}/transporttype",
            "/single/receivers/{receiverId}/staged",
            "/single/receivers/{receiverId}/active",
            "/single/receivers/{receiverId}/constraints",
            "/single/receivers/{receiverId}/transporttype",
        ]
        GenericTest.__init__(self, apis, omit_paths, **kwargs)
        self.query_url = self.apis[QUERY_API_KEY]["url"]
        self.node_url = self.apis[NODE_API_KEY]["url"]
        self.connection_url = self.apis[CONNECTION_API_KEY]["url"]
        self.is04_resources = {"senders": {}, "receivers": {}, "_requested": [], "sources": {}, "flows": {},
                               "devices": {}, "self": {}}
        self.is05_resources = {"senders": [], "receivers": [], "_requested": [], "transport_types": {},
                               "transport_files": {}}
        self.is04_utils = IS04Utils(self.node_url)
        self.is05_utils = IS05Utils(self.connection_url)
        self.test = Test("default")
        self.is04_query_utils = IS04Utils(self.query_url)

    # Utility function from IS0502Test
    def get_is04_resources(self, resource_type):
        """Retrieve all Senders or Receivers from a Node API, keeping hold of the returned objects"""
        assert resource_type in ["senders", "receivers", "sources", "flows", "devices", "self"]

        # Prevent this being executed twice in one test run
        if resource_type in self.is04_resources["_requested"]:
            return True, ""

        path_url = resource_type
        full_url = self.node_url + path_url
        valid, resources = self.do_request("GET", full_url)
        if not valid:
            return False, "Node API did not respond as expected: {}".format(resources)
        schema = self.get_schema(NODE_API_KEY, "GET", "/" + path_url, resources.status_code)
        valid, message = self.check_response(schema, "GET", resources)
        if not valid:
            raise NMOSTestException(self.test.FAIL(message))

        if resource_type == "self":
            resource = resources.json()
            self.is04_resources[resource_type][resource["id"]] = resource
            self.is04_resources["_requested"].append(resource_type)
        else:
            try:
                for resource in filter_resources(resources.json(), resource_type):
                    self.is04_resources[resource_type][resource["id"]] = resource
                self.is04_resources["_requested"].append(resource_type)
            except json.JSONDecodeError:
                return False, "Non-JSON response returned from Node API"

        return True, ""

    def get_is05_partial_resources(self, resource_type):
        """Retrieve all Senders or Receivers from a Connection API, keeping hold of the returned IDs"""
        assert resource_type in ["senders", "receivers"]

        # Prevent this being executed twice in one test run
        if resource_type in self.is05_resources["_requested"]:
            return True, ""

        path_url = "single/" + resource_type
        full_url = self.connection_url + path_url
        valid, resources = self.do_request("GET", full_url)
        if not valid:
            return False, "Connection API did not respond as expected: {}".format(resources)

        schema = self.get_schema(CONNECTION_API_KEY, "GET", "/" + path_url, resources.status_code)
        valid, message = self.check_response(schema, "GET", resources)
        if not valid:
            raise NMOSTestException(self.test.FAIL(message))

        # The following call to is05_utils.get_transporttype does not validate against the IS-05 schemas,
        # which is good for allowing extended transport. The transporttype-response-schema.json schema is
        # broken as it does not allow additional transport, nor x-nmos ones, nor vendor specific ones.
        try:
            for resource in filter_resources(resources.json(), resource_type):
                resource_id = resource.rstrip("/")
                self.is05_resources[resource_type].append(resource_id)
                if self.is05_utils.compare_api_version(self.apis[CONNECTION_API_KEY]["version"], "v1.1") >= 0:
                    transport_type = self.is05_utils.get_transporttype(resource_id, resource_type.rstrip("s"))
                    self.is05_resources["transport_types"][resource_id] = transport_type
                else:
                    self.is05_resources["transport_types"][resource_id] = "urn:x-nmos:transport:rtp"
                if resource_type == "senders":
                    transport_file = self.is05_utils.get_transportfile(resource_id)
                    self.is05_resources["transport_files"][resource_id] = transport_file
            self.is05_resources["_requested"].append(resource_type)
        except json.JSONDecodeError:
            return False, "Non-JSON response returned from Node API"

        return True, ""

    def check_response_without_transport_params(self, schema, method, response):
        """Confirm that a given Requests response conforms to the expected schema and has any expected headers
        without considering the 'transport_params' attribute"""
        ctype_valid, ctype_message = check_content_type(response.headers)
        if not ctype_valid:
            return False, ctype_message

        cors_valid, cors_message = self.check_CORS(method, response.headers)
        if not cors_valid:
            return False, cors_message

        fields_to_ignore = ["transport_params"]

        data = response.json()

        filtered_data = {k: v for k, v in data.items() if k not in fields_to_ignore}

        filtered_data["transport_params"] = []

        try:
            self.validate_schema(filtered_data, schema)
        except ValidationError as e:
            return False, "Response schema validation error {}".format(e)
        except json.JSONDecodeError:
            return False, "Invalid JSON received"

        return True, ctype_message

    def test_01(self, test):
        """ """

        self.test = test

        valid, result = self.get_is04_resources("senders")
        if not valid:
            return test.FAIL(result)

        valid, result = self.get_is04_resources("flows")
        if not valid:
            return test.FAIL(result)

        # Get wit video sender_id
        sender_id = ""

        for sender in self.is04_resources["senders"].values():
            flow_id = sender['flow_id']
            for flow in self.is04_resources["flows"].values():
                if flow['id'] == flow_id and flow['format'] == FormatVideo:
                    sender_id = sender['id']
                    break

        if sender_id == "":
            return test.FAIL("cannot find a video sender")

        # setup websocket notifications for senders
        try:
            sub_json = self.prepare_subscription("/senders")
            resp_json = self.post_subscription(test, sub_json)
            websocket = WebsocketWorker(resp_json["ws_href"])

            websocket.start()
            sleep(CONFIG.WS_MESSAGE_TIMEOUT)

            found_initial_data_set = False

            while True:
                if websocket.did_error_occur():
                    return test.FAIL("Error opening websocket: {}".format(websocket.get_error_message()))

                received_messages = websocket.get_messages()

                # Verify data inside messages
                grain_data = list()

                for curr_msg in received_messages:
                    json_msg = json.loads(curr_msg)
                    grain_data.extend(json_msg["grain"]["data"])

                found_data_set = False
                for curr_data in grain_data:

                    # case has Pre && has Post:
                    # CREATE / UPDATE
                    #
                    # case has Pre == nil && not has Post:
                    # DELETE
                    #
                    # case not has Pre && has Post:
                    # CREATE
                    #
                    # case not haas Pre != nil && not has Post:
                    # NOP

                    if "pre" not in curr_data or "post" not in curr_data:
                        continue

                    if sender_id == curr_data['path']:
                        found_data_set = True
                        break

                if found_data_set:
                    if found_initial_data_set:
                        break
                    found_initial_data_set = True

            # Now check for the SDP transport file every 500 ms for 10 seconds
            iterations = 10000/100

            while iterations != 0:
                url = "single/senders/{}/transportfile".format(sender_id)
                valid, response = self.is05_utils.checkCleanRequest("GET", url)
                if valid:
                    print(response.content)
                sleep(0.1)
                iterations -= 1
        except Exception as e:
            return test.FAIL("Error during test 01: {}".format(e))

        return test.PASS()

    def test_02(self, test):
        """
        Test that the SDP transport file matches with the video Sender, Flow and Source of the Node
        """

        self.test = test

        for resource_type in ["senders", "flows", "sources", "devices", "self"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"].values()}
        source_map = {source["id"]: source for source in self.is04_resources["sources"].values()}
        device_map = {device["id"]: device for device in self.is04_resources["devices"].values()}
        node_map = {node["id"]: node for node in self.is04_resources["self"].values()}

        try:
            # Testing only uncompressed and JPEG-XS video because other codec like H.26x have have almost no
            # fmtp parameters. When such new formats are added toIPMX a dedicated test could be used to test
            # what remain visible in the SDP.
            raw_video_senders = [sender for sender in self.is04_resources["senders"].values() if sender["flow_id"]
                                 and sender["flow_id"] in flow_map
                                 and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:video"
                                 and flow_map[sender["flow_id"]]["media_type"] == "video/raw"]

            jxsv_video_senders = [sender for sender in self.is04_resources["senders"].values() if sender["flow_id"]
                                  and sender["flow_id"] in flow_map
                                  and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:video"
                                  and flow_map[sender["flow_id"]]["media_type"] == "video/jxsv"]

            h265_video_senders = [sender for sender in self.is04_resources["senders"].values() if sender["flow_id"]
                                  and sender["flow_id"] in flow_map
                                  and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:video"
                                  and flow_map[sender["flow_id"]]["media_type"] == "video/H265"]

            h264_video_senders = [sender for sender in self.is04_resources["senders"].values() if sender["flow_id"]
                                  and sender["flow_id"] in flow_map
                                  and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:video"
                                  and flow_map[sender["flow_id"]]["media_type"] == "video/H264"]

            video_senders = raw_video_senders + jxsv_video_senders + h265_video_senders + h264_video_senders

            sender_tested = list()

            for sender in video_senders:

                flow = flow_map[sender["flow_id"]]
                source = source_map[flow["source_id"]]
                device = device_map[sender["device_id"]]
                node = node_map[device["node_id"]]

                # check the transport => only RTP is currently supported by IPMX
                if not sender["transport"].startswith("urn:x-nmos:transport:rtp"):
                    return test.FAIL("Sender {} transport {} is not RTP"
                                     .format(sender["id"], sender["transport"]))

                url = "single/senders/{}/active".format(sender["id"])
                valid, response = self.is05_utils.checkCleanRequest("GET", url)
                if not valid:
                    return test.FAIL("Sender {} not responding to IS-05 request"
                                     .format(sender["id"]))

                # The IS-05 active transport parameters provide an array of such along with the master_enable.
                active = response.json()

                if not active["master_enable"]:
                    continue

                sender_tested.append(sender["id"])

                # The sender being active it must provide an SDP transport file and be accessible
                if "manifest_href" not in sender:
                    return test.FAIL("Sender {} MUST provide the 'manifest_href' attribute."
                                     .format(sender["id"]))

                href = sender["manifest_href"]
                if not href:
                    return test.FAIL("Sender {} MUST provide a valid 'manifest_href' attribute."
                                     .format(sender["id"]))

                manifest_href_valid, manifest_href_response = self.do_request("GET", href)
                if manifest_href_valid and manifest_href_response.status_code == 200:
                    pass
                elif manifest_href_valid and manifest_href_response.status_code == 404:
                    return test.FAIL("Sender {} cannot GET an SDP transport file {}, got status 404."
                                     .format(sender["id"], href))
                else:
                    return test.FAIL("Sender {} cannot GET an SDP transport file {}, got status {}."
                                     .format(sender["id"], href, manifest_href_response))

                # Create an SDP object and parse the text into it. There must be at least a primary media
                # (no redundancy)
                sdp = MatroxSdp()

                try:
                    decode_error = sdp.decode(manifest_href_response.text)
                    if decode_error:
                        return test.FAIL("Sender {} cannot decode the SDP transport file {}, decode error: {}"
                                         .format(sender["id"], href, decode_error))
                except Exception as e:
                    return test.FAIL("Sender {} cannot decode the SDP transport file {}, raised an exception {}"
                                     .format(sender["id"], href, e))

                # Check IPMX
                if not sdp.primary_media.ipmx:
                    return test.FAIL("Sender {} SDP is not indicating IPMX"
                                     .format(sender["id"]))

                # Check frame width, height
                frame_width = flow["frame_width"]
                frame_height = flow["frame_height"]
                sdp_width = sdp.primary_media.width
                sdp_height = sdp.primary_media.height

                if sdp_width != frame_width or sdp_height != frame_height:
                    return test.FAIL("Sender {} Flow {} frame width {}, height {} mismatch with SDP width {}, height {}"
                                     .format(sender["id"], sender["flow_id"], frame_width, frame_height,
                                             sdp_width, sdp_height))

                # Check frame rate num, den
                rate_num = flow["grain_rate"]["numerator"]
                rate_den = 1

                if "denominator" in flow["grain_rate"]:
                    rate_den = flow["grain_rate"]["denominator"]

                sdp_rate_num = sdp.primary_media.exact_frame_rate_numerator
                sdp_rate_den = sdp.primary_media.exact_frame_rate_denominator

                if sdp_rate_num != rate_num or sdp_rate_den != rate_den:
                    return test.FAIL("Sender {} Flow {} frame rate num {}, den {} mismatch with SDP num {}, den {}"
                                     .format(sender["id"], sender["flow_id"], rate_num, rate_den,
                                             sdp_rate_num, sdp_rate_den))

                # Check component depth. There must be at least 3 planes, all having the same depth
                if len(flow["components"]) < 3:
                    return test.FAIL("Sender {} Flow {} components attribute has less than 3 components"
                                     .format(sender["id"], sender["flow_id"]))

                # Check the color sampling and component depth
                try:
                    sdp_components = GetSdpSamplingAsComponents(sdp)

                    for component in flow["components"]:

                        name = component["name"]

                        if (component["width"] != sdp_components[name]["width"] or
                            component["height"] != sdp_components[name]["height"] or
                                component["bit_depth"] != sdp_components[name]["bit_depth"]):

                            return test.FAIL("Sender {} Flow {} component {} is not matching with SDP color sampling {}"
                                             " and derived components {}"
                                             .format(sender["id"], sender["flow_id"], component,
                                                     sdp.primary_media.sampling, sdp_components[name]))
                except Exception:
                    return test.FAIL("Sender {} SDP color sampling {} is not supported or not matching with the Flow {}"
                                     .format(sender["id"], sdp.primary_media.sampling, sender["flow_id"]))

                # Check that IPMX "measured" parameters are defined
                if (sdp.primary_media.measured_pix_clk == 0 or sdp.primary_media.h_total == 0 or
                        sdp.primary_media.v_total == 0):
                    return test.FAIL("Sender {} SDP measured pixclk {} htotal {} and vtotal {} have invalid values"
                                     .format(sender["id"], sdp.primary_media.measured_pix_clk,
                                             sdp.primary_media.h_total, sdp.primary_media.v_total))

                # Check the mediaclk type
                if (sdp.primary_media.media_clock_type != MatroxSdpEnums.Sender and
                        sdp.primary_media.media_clock_type != MatroxSdpEnums.Direct):
                    return test.FAIL("Sender {} SDP media clock type has an invalid value {}"
                                     .format(sender["id"], sdp.primary_media.media_clock_type))

                # Make sure the clock matches with the Source and Node
                clock_name = source["clock_name"]
                clock_found = False

                for clock in node["clocks"]:
                    if clock["name"] == clock_name:
                        clock_found = True
                        if clock["ref_type"] == "ptp":
                            if (sdp.primary_media.ts_ref_clock_source != "ptp" or sdp.primary_media.ts_delay != 0 or
                                sdp.primary_media.ts_ref_clock_ptp_gmid.capitalize() != clock["gmid"].capitalize() or
                                    sdp.primary_media.ts_ref_clock_ptp_version != clock["version"]):
                                return test.FAIL("Sender {} SDP media clock: source {}, delay {}, gmid {}, version {}"
                                                 " do not match Node clock {}"
                                                 .format(sender["id"], sdp.primary_media.ts_ref_clock_source,
                                                         sdp.primary_media.ts_delay,
                                                         sdp.primary_media.ts_ref_clock_ptp_gmid,
                                                         sdp.primary_media.ts_ref_clock_ptp_version, clock))
                        else:
                            if sdp.primary_media.ts_ref_clock_source != "localmac":
                                return test.FAIL("Sender {} SDP media clock source {} do not match Node clock {}"
                                                 .format(sender["id"],
                                                         sdp.primary_media.sdp.primary_media.ts_ref_clock_source,
                                                         clock))

                if not clock_found:
                    return test.FAIL("Sender {} Source {} clock name {} not found in Node clocks {}"
                                     .format(sender["id"], source["id"], clock_name, node["clocks"]))

                # Check the SDP format, encoding and rate versus the Flow media type
                format, unused, encoding = flow["media_type"].partition("/")

                if (format != sdp.primary_media.type or encoding != sdp.primary_media.encoding_name or
                        sdp.primary_media.clock_rate != 90000):
                    return test.FAIL("Sender {} Flow {} media type {} not matching with sdp type {}, encoding {}"
                                     " and rate {}"
                                     .format(sender["id"], flow["id"], flow["media_type"], sdp.primary_media.type,
                                             sdp.primary_media.encoding_name, sdp.primary_media.clock_rate))

                # Check the multicast address of the transport parameters matches with the SDP
                primary_transport_params = active["transport_params"][0]

                if (primary_transport_params["destination_ip"] != sdp.primary_media.connection_address or
                        primary_transport_params["destination_port"] != sdp.primary_media.port):
                    return test.FAIL("Sender {} destination address {} and port {} not matching with sdp address {}"
                                     " and port {}"
                                     .format(sender["id"], primary_transport_params["destination_ip"],
                                             primary_transport_params["destination_port"],
                                             sdp.primary_media.connection_address, sdp.primary_media.port))

                if (primary_transport_params["source_ip"] != sdp.primary_media.source_filter_src_address or
                        primary_transport_params["destination_ip"] != sdp.primary_media.source_filter_dst_address):
                    return test.FAIL("Sender {} source filter destination address {} and source address {} not"
                                     " matching with sdp destination {} and source {}"
                                     .format(sender["id"], primary_transport_params["destination_ip"],
                                             primary_transport_params["source_ip"],
                                             sdp.primary_media.source_filter_dst_address,
                                             sdp.primary_media.source_filter_src_address))

                # Make sure the number of legs matches with the number of the SDP medias
                if len(active["transport_params"]) != sdp.media_count:
                    return test.FAIL("Sender {} legs in transport parameters {} not matching with SDP media count {}"
                                     .format(sender["id"], len(active["transport_params"]), sdp.media_count))

                # Check the SDP transport file against ST-2110 and RFC requirements
                if flow["media_type"] == "video/raw":
                    try:
                        check_sdp_rfc4175(sdp.primary_media)
                    except SdpCheckError as e:
                        return test.FAIL("Sender {} failed RFC 4175 check: {}".format(sender["id"], e.message))
                    try:
                        check_sdp_st2110_10(sdp.primary_media)
                    except SdpCheckError as e:
                        return test.FAIL("Sender {} failed ST 2110-10 check: {}".format(sender["id"], e.message))
                    try:
                        check_sdp_st2110_21(sdp.primary_media)
                    except SdpCheckError as e:
                        return test.FAIL("Sender {} failed ST 2110-21 check: {}".format(sender["id"], e.message))
                    try:
                        check_sdp_st2110_20(sdp.primary_media)
                    except SdpCheckError as e:
                        return test.FAIL("Sender {} failed ST 2110-20 check: {}".format(sender["id"], e.message))

                elif flow["media_type"] == "video/jxsv":
                    try:
                        check_sdp_rfc9134(sdp.primary_media)
                    except SdpCheckError as e:
                        return test.FAIL("Sender {} failed RFC 9134 check: {}".format(sender["id"], e.message))
                    try:
                        check_sdp_st2110_10(sdp.primary_media)
                    except SdpCheckError as e:
                        return test.FAIL("Sender {} failed ST 2110-10 check: {}".format(sender["id"], e.message))
                    try:
                        check_sdp_st2110_21(sdp.primary_media)
                    except SdpCheckError as e:
                        return test.FAIL("Sender {} failed ST 2110-21 check: {}".format(sender["id"], e.message))
                    try:
                        check_sdp_st2110_22(sdp.primary_media)
                    except SdpCheckError as e:
                        return test.FAIL("Sender {} failed ST 2110-22 check: {}".format(sender["id"], e.message))

                elif flow["media_type"] == "video/H265":
                    try:
                        check_sdp_rfc7798(sdp.primary_media)
                    except SdpCheckError as e:
                        return test.FAIL("Sender {} failed RFC 7798 check: {}".format(sender["id"], e.message))
                elif flow["media_type"] == "video/H264":
                    try:
                        check_sdp_rfc6184(sdp.primary_media)
                    except SdpCheckError as e:
                        return test.FAIL("Sender {} failed RFC 6184 check: {}".format(sender["id"], e.message))

                else:
                    return test.FAIL("Sender {} Flow {} has an unexpected media type {}"
                                     .format(sender["id"], flow["id"], flow["media_type"]))

            if len(sender_tested) == 0:
                return test.UNCLEAR("No ACTIVE Uncompressed, JPEG-XS, HEVC or H.264 video Sender found on the Node => "
                                    "PLEASE ACTIVATE A SENDER to TEST")

            if len(video_senders) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No Uncompressed, JPEG-XS, HEVC or H.264 video Sender resources were found on the Node")

    def test_03(self, test):
        """
        Test that the SDP transport file matches with the audio Sender, Flow and Source of the Node
        """

        self.test = test

        for resource_type in ["senders", "flows", "sources", "devices", "self"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"].values()}
        source_map = {source["id"]: source for source in self.is04_resources["sources"].values()}
        device_map = {device["id"]: device for device in self.is04_resources["devices"].values()}
        node_map = {node["id"]: node for node in self.is04_resources["self"].values()}

        try:
            # Testing only uncompressed and JPEG-XS video because other codec like H.26x have have almost no
            # fmtp parameters. When such new formats are added toIPMX a dedicated test could be used to test
            # what remain visible in the SDP.
            pcm_audio_senders = [sender for sender in self.is04_resources["senders"].values() if sender["flow_id"]
                                 and sender["flow_id"] in flow_map
                                 and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:audio"
                                 and (flow_map[sender["flow_id"]]["media_type"] == "audio/L8" or
                                 flow_map[sender["flow_id"]]["media_type"] == "audio/L16" or
                                 flow_map[sender["flow_id"]]["media_type"] == "audio/L20" or
                                 flow_map[sender["flow_id"]]["media_type"] == "audio/L24")]

            am824_audio_senders = [sender for sender in self.is04_resources["senders"].values() if sender["flow_id"]
                                   and sender["flow_id"] in flow_map
                                   and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:audio"
                                   and flow_map[sender["flow_id"]]["media_type"] == "audio/AM824"]

            audio_senders = pcm_audio_senders + am824_audio_senders

            sender_tested = list()

            for sender in audio_senders:

                flow = flow_map[sender["flow_id"]]
                source = source_map[flow["source_id"]]
                device = device_map[sender["device_id"]]
                node = node_map[device["node_id"]]

                # check the transport => only RTP is currently supported by IPMX
                if not sender["transport"].startswith("urn:x-nmos:transport:rtp"):
                    return test.FAIL("Sender {} transport {} is not RTP"
                                     .format(sender["id"], sender["transport"]))

                url = "single/senders/{}/active".format(sender["id"])
                valid, response = self.is05_utils.checkCleanRequest("GET", url)
                if not valid:
                    return test.FAIL("Sender {} not responding to IS-05 request"
                                     .format(sender["id"]))

                # The IS-05 active transport parameters provide an array of such along with the master_enable.
                active = response.json()

                if not active["master_enable"]:
                    continue

                sender_tested.append(sender["id"])

                # The sender being active it must provide an SDP transport file and be accessible
                if "manifest_href" not in sender:
                    return test.FAIL("Sender {} MUST provide the 'manifest_href' attribute."
                                     .format(sender["id"]))

                href = sender["manifest_href"]
                if not href:
                    return test.FAIL("Sender {} MUST provide a valid 'manifest_href' attribute."
                                     .format(sender["id"]))

                manifest_href_valid, manifest_href_response = self.do_request("GET", href)
                if manifest_href_valid and manifest_href_response.status_code == 200:
                    pass
                elif manifest_href_valid and manifest_href_response.status_code == 404:
                    return test.FAIL("Sender {} cannot GET an SDP transport file {}, got status 404."
                                     .format(sender["id"], href))
                else:
                    return test.FAIL("Sender {} cannot GET an SDP transport file {}, got status {}."
                                     .format(sender["id"], href, manifest_href_response))

                # Create an SDP object and parse the text into it. There must be at least a primary
                # media (no redundancy)
                sdp = MatroxSdp()

                try:
                    decode_error = sdp.decode(manifest_href_response.text)
                    if decode_error:
                        return test.FAIL("Sender {} cannot decode the SDP transport file {}, decode error: {}"
                                         .format(sender["id"], href, decode_error))
                except Exception as e:
                    return test.FAIL("Sender {} cannot decode the SDP transport file {}, raised an exception {}"
                                     .format(sender["id"], href, e))

                # Check IPMX
                if not sdp.primary_media.ipmx:
                    return test.FAIL("Sender {} SDP is not indicating IPMX"
                                     .format(sender["id"]))

                # Check bit depth (PCM from media type, coded from bit_depth attribute), and channel count
                if flow["media_type"] == "audio/L8":
                    bit_depth = 8
                    extra_bit_depth = flow["bit_depth"]
                elif flow["media_type"] == "audio/L16":
                    bit_depth = 16
                    extra_bit_depth = flow["bit_depth"]
                elif flow["media_type"] == "audio/L20":
                    bit_depth = 20
                    extra_bit_depth = flow["bit_depth"]
                elif flow["media_type"] == "audio/L24":
                    bit_depth = 24
                    extra_bit_depth = flow["bit_depth"]
                elif flow["media_type"] == "audio/AM824":
                    bit_depth = None
                    extra_bit_depth = None
                else:
                    return test.FAIL("Sender {} Flow {} has unexpected media_type"
                                     .format(sender["id"], flow["id"]))

                if bit_depth != extra_bit_depth:
                    return test.FAIL("Sender {} Flow {} has invalid bit_depth from media type {} and Flow {}"
                                     .format(sender["id"], flow["id"], bit_depth, extra_bit_depth))

                if sdp.primary_media.encoding_name == "L8":
                    sdp_bit_depth = 8
                elif sdp.primary_media.encoding_name == "L16":
                    sdp_bit_depth = 16
                elif sdp.primary_media.encoding_name == "L20":
                    sdp_bit_depth = 20
                elif sdp.primary_media.encoding_name == "L24":
                    sdp_bit_depth = 24
                elif sdp.primary_media.encoding_name == "AM824":
                    sdp_bit_depth = None
                else:
                    return test.FAIL("Sender {} Flow {} has unexpected media_type"
                                     .format(sender["id"], flow["id"]))

                if bit_depth != sdp_bit_depth:
                    return test.FAIL("Sender {} Flow {} bit_depth {} mismatch with SDP bit_depth {}"
                                     .format(sender["id"], flow["id"], bit_depth, sdp_bit_depth))

                channels_count = len(source["channels"])
                sdp_channels_count = sdp.primary_media.channels

                if channels_count != sdp_channels_count:
                    return test.FAIL("Sender {} Flow {} channels count {} mismatch with SDP channels count {}"
                                     .format(sender["id"], sender["flow_id"], channels_count, sdp_channels_count))

                # Check sample rate num, den
                rate_num = flow["sample_rate"]["numerator"]
                rate_den = 1

                if "denominator" in flow["sample_rate"]:
                    rate_den = flow["sample_rate"]["denominator"]

                sdp_rate_num = sdp.primary_media.sample_rate
                sdp_rate_den = 1

                if sdp_rate_num != rate_num or sdp_rate_den != rate_den:
                    return test.FAIL("Sender {} Flow {} sample rate num {}, den {} mismatch with SDP num {}, den {}"
                                     .format(sender["id"], sender["flow_id"], rate_num, rate_den, sdp_rate_num,
                                             sdp_rate_den))

                # The grain_rate if any must match the required sample rate
                if "grain_rate" in flow:

                    grain_rate_num = flow["grain_rate"]["numerator"]
                    grain_rate_den = 1

                    if "denominator" in flow["grain_rate"]:
                        grain_rate_den = flow["grain_rate"]["denominator"]

                    if (grain_rate_num != rate_num or grain_rate_den != rate_den):
                        return test.FAIL("Sender {} Flow {} sample rate num {}, den {} mismatch with grain_rate"
                                         " num {}, den {}"
                                         .format(sender["id"], sender["flow_id"], rate_num, rate_den, grain_rate_num,
                                                 grain_rate_den))

                # Check that IPMX "measured" parameters are defined
                if sdp.primary_media.measured_sample_rate == 0:
                    return test.FAIL("Sender {} SDP measured sample rate {} has an invalid value"
                                     .format(sender["id"], sdp.primary_media.measured_sample_rate))

                # Check the mediaclk type
                if (sdp.primary_media.media_clock_type != MatroxSdpEnums.Sender and
                        sdp.primary_media.media_clock_type != MatroxSdpEnums.Direct):
                    return test.FAIL("Sender {} SDP media clock type has an invalid value {}"
                                     .format(sender["id"], sdp.primary_media.media_clock_type))

                # Make sure the clock matches with the Source and Node
                clock_name = source["clock_name"]
                clock_found = False

                for clock in node["clocks"]:
                    if clock["name"] == clock_name:
                        clock_found = True
                        if clock["ref_type"] == "ptp":
                            if (sdp.primary_media.ts_ref_clock_source != "ptp" or sdp.primary_media.ts_delay != 0 or
                                sdp.primary_media.ts_ref_clock_ptp_gmid.capitalize() != clock["gmid"].capitalize() or
                                    sdp.primary_media.ts_ref_clock_ptp_version != clock["version"]):
                                return test.FAIL("Sender {} SDP media clock: source {}, delay {}, gmid {}, version {}"
                                                 " do not match Node clock {}"
                                                 .format(sender["id"], sdp.primary_media.ts_ref_clock_source,
                                                         sdp.primary_media.ts_delay,
                                                         sdp.primary_media.ts_ref_clock_ptp_gmid,
                                                         sdp.primary_media.ts_ref_clock_ptp_version, clock))
                        else:
                            if sdp.primary_media.ts_ref_clock_source != "localmac":
                                return test.FAIL("Sender {} SDP media clock source {} do not match Node clock {}"
                                                 .format(sender["id"],
                                                         sdp.primary_media.sdp.primary_media.ts_ref_clock_source,
                                                         clock))

                if not clock_found:
                    return test.FAIL("Sender {} Source {} clock name {} not found in Node clocks {}"
                                     .format(sender["id"], source["id"], clock_name, node["clocks"]))

                # Check the multicast address of the transport parameters matches with the SDP
                primary_transport_params = active["transport_params"][0]

                if (primary_transport_params["destination_ip"] != sdp.primary_media.connection_address or
                        primary_transport_params["destination_port"] != sdp.primary_media.port):
                    return test.FAIL("Sender {} destination address {} and port {} not matching with sdp address {}"
                                     " and port {}"
                                     .format(sender["id"], primary_transport_params["destination_ip"],
                                             primary_transport_params["destination_port"],
                                             sdp.primary_media.connection_address, sdp.primary_media.port))

                if (primary_transport_params["source_ip"] != sdp.primary_media.source_filter_src_address or
                        primary_transport_params["destination_ip"] != sdp.primary_media.source_filter_dst_address):
                    return test.FAIL("Sender {} source filter destination address {} and source address {} not"
                                     " matching with sdp destination {} and source {}"
                                     .format(sender["id"], primary_transport_params["destination_ip"],
                                             primary_transport_params["source_ip"],
                                             sdp.primary_media.source_filter_dst_address,
                                             sdp.primary_media.source_filter_src_address))

                # Make sure the number of legs matches with the number of the SDP medias
                if len(active["transport_params"]) != sdp.media_count:
                    return test.FAIL("Sender {} legs in transport parameters {} not matching with SDP media count {}"
                                     .format(sender["id"], len(active["transport_params"]), sdp.media_count))

                # Check the SDP transport file against ST-2110 and RFC requirements
                if flow["media_type"] in ("audio/L8", "audio/L16", "audio/L20", "audio/L24"):
                    try:
                        check_sdp_rfc3551(sdp.primary_media)
                    except SdpCheckError as e:
                        return test.FAIL("Sender {} failed RFC 3551 check: {}".format(sender["id"], e.message))
                    try:
                        check_sdp_st2110_10(sdp.primary_media)
                    except SdpCheckError as e:
                        return test.FAIL("Sender {} failed ST 2110-10 check: {}".format(sender["id"], e.message))
                    try:
                        check_sdp_st2110_30(sdp.primary_media)
                    except SdpCheckError as e:
                        return test.FAIL("Sender {} failed ST 2110-30 check: {}".format(sender["id"], e.message))

                elif flow["media_type"] == "audio/AM824":
                    try:
                        check_sdp_rfc3551(sdp.primary_media)
                    except SdpCheckError as e:
                        return test.FAIL("Sender {} failed RFC 3551 check: {}".format(sender["id"], e.message))
                    try:
                        check_sdp_st2110_10(sdp.primary_media)
                    except SdpCheckError as e:
                        return test.FAIL("Sender {} failed ST 2110-10 check: {}".format(sender["id"], e.message))
                    try:
                        check_sdp_st2110_31(sdp.primary_media)
                    except SdpCheckError as e:
                        return test.FAIL("Sender {} failed ST 2110-31 check: {}".format(sender["id"], e.message))

                else:
                    return test.FAIL("Sender {} Flow {} has an unexpected media type {}"
                                     .format(sender["id"], flow["id"], flow["media_type"]))

            if len(sender_tested) == 0:
                return test.UNCLEAR("No ACTIVE PCM or ST-2110-31 audio Sender found on the Node => PLEASE ACTIVATE"
                                    " A SENDER to TEST")

            if len(audio_senders) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No PCM or ST-2110-31 audio Sender resources were found on the Node")

    def test_04(self, test):
        """
        Test that the device discovers the registry and register its Node and Device resources in it.
        """

        self.test = test

        REGISTRY_TIMEOUT = 10  # seconds

        valid, result = self.get_is04_resources("self")
        if not valid:
            return test.FAIL(result)

        valid, result = self.get_is04_resources("devices")
        if not valid:
            return test.FAIL(result)

        device_map = {device["id"]: device for device in self.is04_resources["devices"].values()}
        node_map = {node["id"]: node for node in self.is04_resources["self"].values()}

        node = next(iter(node_map.values()))
        node_id = next(iter(node_map.keys()))

        try:

            # Register to get resource updated for devices
            sub_json = self.prepare_subscription("/devices")
            resp_json = self.post_subscription(test, sub_json)
            websocket = WebsocketWorker(resp_json["ws_href"])

            websocket.start()

            sleep(CONFIG.WS_MESSAGE_TIMEOUT)

            found_devices_time_start = time.monotonic()

            while True:

                sleep(0.5)

                if time.monotonic() - found_devices_time_start > REGISTRY_TIMEOUT:
                    return test.FAIL("Node {} Could not find the Node's devices {} in the registry prior to a timeout"
                                     " of {} seconds".format(node_id, list(device_map.keys()), REGISTRY_TIMEOUT))

                if websocket.did_error_occur():
                    return test.FAIL("Node {} Error opening websocket: {}".format(node_id,
                                                                                  websocket.get_error_message()))

                received_messages = websocket.get_messages()

                # Verify data inside messages
                grain_data = list()

                for curr_msg in received_messages:
                    json_msg = json.loads(curr_msg)
                    grain_data.extend(json_msg["grain"]["data"])

                found_devices = list()

                for curr_data in grain_data:

                    # case has Pre && has Post:
                    # => CREATE / UPDATE
                    # case has Pre == nil && not has Post:
                    # => DELETE
                    # case not has Pre && has Post:
                    # => CREATE
                    # case not haas Pre != nil && not has Post:
                    # => NOP
                    if "pre" not in curr_data or "post" not in curr_data:
                        continue

                    if curr_data['path'] in device_map.keys():
                        found_devices.append(curr_data['path'])
                        break

                if all(key in found_devices for key in device_map.keys()):
                    break

            # Now for each device check the NOs API implemented and their version
            found_is04 = False
            found_is05 = False
            found_is11 = False

            if "v1.3" in node["api"]["versions"]:
                found_is04 = True

            for device_id in found_devices:

                device = device_map[device_id]

                found_is05 = False
                found_is11 = False

                for control in device["controls"]:
                    if control["type"] == "urn:x-nmos:control:sr-ctrl/v1.1":
                        found_is05 = True
                    if control["type"] == "urn:x-nmos:control:stream-compat/v1.0":
                        found_is11 = True

                if not found_is05:
                    return test.FAIL("Node {} IS-05 API version v1.1 not found in Device's controls {}"
                                     .format(node_id, device["controls"]))
                if not found_is11:
                    return test.FAIL("Node {} IS-11 API version v1.0 not found in Device's controls {}"
                                     .format(node_id, device["controls"]))

            if not found_is04:
                return test.FAIL("Node {} IS-04 API version v1.3 not found in Node API supported versions {}"
                                 .format(node_id, node["api"]["versions"]))

            return test.PASS()

        except Exception as e:
            return test.FAIL("Unexpected error type '{}' and message '{}'".format(type(e).__name__, str(e)))

    def test_05(self, test):
        """
        Test that SDP transport files can be converted to CCF capabilities and verified against sender capabilities
        """
        self.test = test

        # Initialize the SDP to CCF converter
        converter = SdpToCapabilitiesConverter()

        for resource_type in ["senders", "flows", "devices", "self"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"].values()}

        try:
            # Get all senders - we'll verify capabilities using CCF rather than filtering by format upfront
            all_senders = list(self.is04_resources["senders"].values())
            sender_tested = list()

            for sender in all_senders:

                # Check the transport => only RTP is currently supported by IPMX
                if not sender["transport"].startswith("urn:x-nmos:transport:rtp"):
                    return test.FAIL("Sender {} transport {} is not RTP"
                                     .format(sender["id"], sender["transport"]))

                url = "single/senders/{}/active".format(sender["id"])
                valid, response = self.is05_utils.checkCleanRequest("GET", url)
                if not valid:
                    return test.FAIL("Sender {} not responding to IS-05 request"
                                     .format(sender["id"]))

                # The IS-05 active transport parameters provide an array of such along with the master_enable.
                active = response.json()

                if not active["master_enable"]:
                    continue

                sender_tested.append(sender["id"])

                # The sender being active it must provide an SDP transport file and be accessible
                if "manifest_href" not in sender:
                    return test.FAIL("Sender {} MUST provide the 'manifest_href' attribute."
                                     .format(sender["id"]))

                href = sender["manifest_href"]
                if not href:
                    return test.FAIL("Sender {} MUST provide a valid 'manifest_href' attribute."
                                     .format(sender["id"]))

                manifest_href_valid, manifest_href_response = self.do_request("GET", href)
                if manifest_href_valid and manifest_href_response.status_code == 200:
                    pass
                elif manifest_href_valid and manifest_href_response.status_code == 404:
                    return test.FAIL("Sender {} cannot GET an SDP transport file {}, got status 404."
                                     .format(sender["id"], href))
                else:
                    return test.FAIL("Sender {} cannot GET an SDP transport file {}, got status {}."
                                     .format(sender["id"], href, manifest_href_response))

                # Convert SDP transport file to CCF capabilities
                sdp_content = manifest_href_response.text

                # Get the associated flow
                flow_id = sender.get("flow_id")
                if not flow_id or flow_id not in flow_map:
                    return test.FAIL("Sender {} has invalid or missing flow_id {}"
                                     .format(sender["id"], flow_id))

                flow = flow_map[flow_id]

                mux = True if flow["format"] == FormatMux else False

                try:
                    sdp_caps = converter.convert_string(sdp_content, mux)
                except Exception as e:
                    return test.FAIL("Sender {} SDP transport file conversion to CCF capabilities failed: {}"
                                     .format(sender["id"], e))

                # Verify we have capability sets
                if len(sdp_caps.capsets) == 0:
                    return test.FAIL("Sender {} SDP transport file did not produce any CCF capability sets"
                                     .format(sender["id"]))

                # Verify that SDP capabilities are compatible with sender capabilities using CCF
                compatible, error_msg = self._verify_sender_ccf_capability_compatibility(sender, sdp_caps)
                if not compatible:
                    return test.FAIL(error_msg)

            if len(sender_tested) == 0:
                return test.UNCLEAR("No ACTIVE video, audio, or data Senders found on the Node => "
                                    "PLEASE ACTIVATE A SENDER to TEST")

            return test.PASS()

        except Exception as e:
            return test.FAIL("Error during test 05: {}".format(e))

    def test_06(self, test):
        """
        Test that SDP from receiver active parameters can be converted to CCF capabilities and verified
        against receiver capabilities
        """
        self.test = test

        # Initialize the SDP to CCF converter
        converter = SdpToCapabilitiesConverter()

        for resource_type in ["receivers", "devices", "self"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        # Also get IS-05 receiver resources
        valid, result = self.get_is05_partial_resources("receivers")
        if not valid:
            return test.FAIL(result)

        try:
            # Get all receivers - we'll verify capabilities using CCF rather than filtering by format upfront
            all_receivers = list(self.is04_resources["receivers"].values())
            receiver_tested = list()

            for receiver in all_receivers:

                # Check the transport => only RTP is currently supported by IPMX
                if not receiver["transport"].startswith("urn:x-nmos:transport:rtp"):
                    return test.FAIL("Receiver {} transport {} is not RTP"
                                     .format(receiver["id"], receiver["transport"]))

                url = "single/receivers/{}/active".format(receiver["id"])
                valid, response = self.is05_utils.checkCleanRequest("GET", url)
                if not valid:
                    return test.FAIL("Receiver {} not responding to IS-05 request"
                                     .format(receiver["id"]))

                # The IS-05 active transport parameters provide an array of such along with the master_enable.
                active = response.json()

                if not active["master_enable"]:
                    continue

                receiver_tested.append(receiver["id"])

                # The receiver being active should have SDP in the active parameters
                # For receivers, the SDP is provided via transport_file structure
                sdp_content = None

                # Try to extract SDP from active parameters with proper error handling
                try:
                    transport_file = active["transport_file"]
                    sdp_content = transport_file["data"] if transport_file["type"] == "application/sdp" else None
                except (KeyError, TypeError) as e:
                    return test.FAIL("Receiver {} active parameters have malformed transport_file structure: {}"
                                     .format(receiver["id"], str(e)))

                if not sdp_content:
                    return test.FAIL("Receiver {} active parameters do not contain valid SDP"
                                     .format(receiver["id"]))

                # Ensure SDP is a string
                if not isinstance(sdp_content, str):
                    return test.FAIL("Receiver {} SDP is not a string format"
                                     .format(receiver["id"]))

                # Convert SDP from active parameters to CCF capabilities
                mux = True if receiver["format"] == FormatMux else False

                try:
                    sdp_caps = converter.convert_string(sdp_content, mux)
                except Exception as e:
                    return test.FAIL("Receiver {} SDP active parameters conversion to CCF capabilities failed: {}"
                                     .format(receiver["id"], e))

                # Verify we have capability sets
                if len(sdp_caps.capsets) == 0:
                    return test.FAIL("Receiver {} SDP active parameters did not produce any CCF capability sets"
                                     .format(receiver["id"]))

                # Verify that SDP capabilities are compatible with receiver capabilities using CCF
                compatible, error_msg = self._verify_receiver_ccf_capability_compatibility(receiver, sdp_caps)
                if not compatible:
                    return test.FAIL(error_msg)

            if len(receiver_tested) == 0:
                return test.UNCLEAR("No ACTIVE video, audio, or data Receivers found on the Node => "
                                    "PLEASE ACTIVATE A RECEIVER to TEST")

            return test.PASS()

        except Exception as e:
            return test.FAIL("Error during test 06: {}".format(e))

    def test_07(self, test):
        """
        Test that Flow, Source, and Sender information can be converted to CCF capabilities and
        verified against sender capabilities
        """
        self.test = test

        for resource_type in ["senders", "flows", "sources", "devices", "self"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        device_map = {device["id"]: device for device in self.is04_resources["devices"].values()}
        node_map = {node["id"]: node for node in self.is04_resources["self"].values()}
        flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"].values()}
        source_map = {source["id"]: source for source in self.is04_resources["sources"].values()}

        try:
            # Get all senders - we'll verify capabilities using CCF rather than filtering by format upfront
            all_senders = list(self.is04_resources["senders"].values())
            sender_tested = list()

            for sender in all_senders:
                device = device_map[sender["device_id"]]
                node = node_map[device["node_id"]]

                # Check the transport => only RTP is currently supported by IPMX
                if not sender["transport"].startswith("urn:x-nmos:transport:rtp"):
                    return test.FAIL("Sender {} transport {} is not RTP"
                                     .format(sender["id"], sender["transport"]))

                url = "single/senders/{}/active".format(sender["id"])
                valid, response = self.is05_utils.checkCleanRequest("GET", url)
                if not valid:
                    return test.FAIL("Sender {} not responding to IS-05 request"
                                     .format(sender["id"]))

                # The IS-05 active transport parameters provide an array of such along with the master_enable.
                active = response.json()

                if not active["master_enable"]:
                    continue

                sender_tested.append(sender["id"])

                # Get the associated flow and source
                flow_id = sender.get("flow_id")
                if not flow_id or flow_id not in flow_map:
                    return test.FAIL("Sender {} has invalid or missing flow_id"
                                     .format(sender["id"]))

                flow = flow_map[flow_id]
                source_id = flow.get("source_id")
                if not source_id or source_id not in source_map:
                    return test.FAIL("Flow {} has invalid or missing source_id"
                                     .format(flow_id))

                source = source_map[source_id]

                # Convert Flow, Source, and Sender to CCF capabilities
                converter = FlowToCapabilitiesConverter()
                try:
                    flow_caps = converter.convert(flow, source, sender, node.get("clocks", []))
                except Exception as e:
                    return test.FAIL("Sender {} Flow/Source/Sender conversion to CCF capabilities failed: {}"
                                     .format(sender["id"], e))

                # Verify we have capability sets
                if len(flow_caps.capsets) == 0:
                    return test.FAIL("Sender {} Flow/Source/Sender conversion did not produce any CCF capability sets"
                                     .format(sender["id"]))

                # Verify that Flow capabilities are compatible with sender capabilities using CCF
                compatible, error_msg = self._verify_sender_ccf_capability_compatibility(sender, flow_caps)
                if not compatible:
                    return test.FAIL(error_msg)

            if len(sender_tested) == 0:
                return test.UNCLEAR("No ACTIVE video, audio, or data Senders found on the Node => "
                                    "PLEASE ACTIVATE A SENDER to TEST")

            return test.PASS()

        except Exception as e:
            return test.FAIL("Error during test 07: {}".format(e))

    def test_08(self, test):
        """
        Test that Flow, Source, and Sender capabilities from associated active sender can be converted to CCF
        capabilities and verified against receiver capabilities
        """
        self.test = test

        for resource_type in ["receivers", "devices", "self"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        # Also get IS-05 receiver resources
        valid, result = self.get_is05_partial_resources("receivers")
        if not valid:
            return test.FAIL(result)

        try:
            # Get all receivers - we'll verify capabilities using CCF
            all_receivers = list(self.is04_resources["receivers"].values())
            receiver_tested = list()

            for receiver in all_receivers:

                # Check the transport => only RTP is currently supported by IPMX
                if not receiver["transport"].startswith("urn:x-nmos:transport:rtp"):
                    return test.FAIL("Receiver {} transport {} is not RTP"
                                     .format(receiver["id"], receiver["transport"]))

                url = "single/receivers/{}/active".format(receiver["id"])
                valid, response = self.is05_utils.checkCleanRequest("GET", url)
                if not valid:
                    return test.FAIL("Receiver {} not responding to IS-05 request"
                                     .format(receiver["id"]))

                # The IS-05 active transport parameters provide an array of such along with the master_enable.
                active = response.json()

                if not active["master_enable"]:
                    continue

                receiver_tested.append(receiver["id"])

                # Get the sender information from the receiver's active parameters
                sender_id = None

                # Try to extract sender_id from activation parameters
                if "sender_id" in active:
                    sender_id = active["sender_id"]
                else:
                    return test.FAIL("Receiver {} active parameters do not contain sender_id"
                                     .format(receiver["id"]))
                if not sender_id:
                    return test.FAIL("Receiver {} has no associated sender_id"
                                     .format(receiver["id"]))

                # Get sender information from registry (similar to test_04 approach)
                sender_data = self._get_sender_from_registry(sender_id)
                if not sender_data:
                    return test.FAIL("Receiver {} associated sender {} not found in registry"
                                     .format(receiver["id"], sender_id))

                # Get flow and source information
                flow_id = sender_data.get("flow_id")
                if not flow_id:
                    return test.FAIL("Receiver {} associated sender {} has no flow_id"
                                     .format(receiver["id"], sender_id))

                flow_data = self._get_flow_from_registry(flow_id)
                if not flow_data:
                    return test.FAIL("Receiver {} flow {} not found in registry"
                                     .format(receiver["id"], flow_id))

                source_id = flow_data.get("source_id")
                if not source_id:
                    return test.FAIL("Receiver {} flow {} has no source_id"
                                     .format(receiver["id"], flow_id))

                source_data = self._get_source_from_registry(source_id)
                if not source_data:
                    return test.FAIL("Receiver {} source {} not found in registry"
                                     .format(receiver["id"], source_id))

                # Get the sender's node information for FlowToCapabilities
                sender_node_clocks = None
                if "device_id" in sender_data:
                    # First get the device to find the node_id
                    device_data = self._get_device_from_registry(sender_data["device_id"])
                    if device_data and "node_id" in device_data:
                        # Then get the node information
                        sender_node_data = self._get_node_from_registry(device_data["node_id"])
                        if sender_node_data and "clocks" in sender_node_data:
                            sender_node_clocks = sender_node_data["clocks"]

                # Convert Flow, Source, and Sender to CCF capabilities
                converter = FlowToCapabilitiesConverter()
                try:
                    flow_caps = converter.convert(flow_data, source_data, sender_data, sender_node_clocks or [])
                except Exception as e:
                    return test.FAIL("Receiver {} associated sender {} Flow/Source/Sender conversion to "
                                     "CCF capabilities failed: {}".format(receiver["id"], sender_id, e))

                # Verify we have capability sets
                if len(flow_caps.capsets) == 0:
                    return test.FAIL("Receiver {} associated sender {} Flow/Source/Sender conversion did"
                                     " not produce any CCF capability sets".format(receiver["id"], sender_id))

                # Verify that Flow capabilities are compatible with receiver capabilities using CCF
                compatible, error_msg = self._verify_receiver_ccf_capability_compatibility(receiver, flow_caps)
                if not compatible:
                    return test.FAIL(error_msg)

            if len(receiver_tested) == 0:
                return test.UNCLEAR("No ACTIVE video, audio, or data Receivers found on the Node => "
                                    "PLEASE ACTIVATE A RECEIVER to TEST")

            return test.PASS()

        except Exception as e:
            return test.FAIL("Error during test 08: {}".format(e))

    def test_100(self, test):
        """
        Pre-Test to get a PCAP capture of a video sender along with its SDP transport file. The selection
        between the LOCAL or VB440 mode is based on an IPMX_VENDOR_PCAP_CAPTURE environment variable.
        """
        self.test = test
        
        pcap_capture_vendor = os.environ.get('IPMX_VENDOR_PCAP_CAPTURE')

        if os.environ.get('IPMX_VENDOR_PCAP_CAPTURE') == 'LOCAL':
            return self.test_101(test)
        elif os.environ.get('IPMX_VENDOR_PCAP_CAPTURE') == 'VB440':
            return self.test_102(test)
        else:
            return test.FAIL("Invalid IPMX_VENDOR_PCAP_CAPTURE environment variable: {}".format(pcap_capture_vendor))

    def test_101(self, test):
        """
        Pre-Test to get a << LOCAL >> PCAP capture of a video sender along with its SDP transport file.
        """

        self.test = test

        for resource_type in ["senders", "flows", "sources", "devices", "self"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"].values()}

        video_senders = [sender for sender in self.is04_resources["senders"].values() if sender["flow_id"]
                         and sender["flow_id"] in flow_map
                         and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:video"]

        audio_senders = [sender for sender in self.is04_resources["senders"].values() if sender["flow_id"]
                         and sender["flow_id"] in flow_map
                         and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:audio"]

        senders = video_senders + audio_senders

        for sender in senders:
            # Initialize cleanup variables
            multicast_socket = None
            interface_name = None
            tcpdump_process = None
            multicast_ip = None

            if sender in video_senders:
                format = "video"
            elif sender in audio_senders:
                format = "audio"
            else:
                return test.FAIL("UNEXPECTED sender {}".format(sender["id"]))

            # check the transport => only RTP is currently supported by IPMX
            if not sender["transport"].startswith("urn:x-nmos:transport:rtp"):
                return test.FAIL("Sender {} transport {} is not RTP"
                                 .format(sender["id"], sender["transport"]))

            try:
                url = "single/senders/{}/active".format(sender["id"])
                valid, response = self.is05_utils.checkCleanRequest("GET", url)
                if not valid:
                    return test.FAIL("Sender {} not responding to IS-05 request"
                                     .format(sender["id"]))

                active = response.json()

                # We require an active sender in order to get an SDP transport file
                url = "single/senders/{}/staged".format(sender["id"])
                if not active["master_enable"]:
                    # activate the sender first
                    valid, response = self.is05_utils.checkCleanRequest("PATCH", url, {
                        "master_enable": True,
                        "activation": {"mode": "activate_immediate"}
                    })
                    if not valid:
                        return test.FAIL("Sender {} cannot activate the sender"
                                         .format(sender["id"]))

                    # update the active parameters after activation
                    url = "single/senders/{}/active".format(sender["id"])
                    valid, response = self.is05_utils.checkCleanRequest("GET", url)
                    if not valid:
                        return test.FAIL("Sender {} not responding to IS-05 request"
                                         .format(sender["id"]))

                    active = response.json()

                sdp_retry = 3
                while True:
                    manifest_href = "single/senders/{}/transportfile".format(sender["id"])
                    manifest_href_valid, manifest_href_response = self.is05_utils.checkCleanRequest(
                        "GET", manifest_href)
                    if manifest_href_valid and manifest_href_response.status_code == 200:
                        pass
                    elif manifest_href_valid and manifest_href_response.status_code == 404:
                        return test.FAIL("Sender {} cannot GET an SDP transport file {}, got status 404."
                                         .format(sender["id"], manifest_href))
                    else:
                        return test.FAIL("Sender {} cannot GET an SDP transport file {}, got status {}."
                                         .format(sender["id"], manifest_href, manifest_href_response))

                    if (manifest_href_response.text is None or
                            manifest_href_response.text == "" or
                            manifest_href_response.text.isspace()):
                        sdp_retry -= 1
                        if sdp_retry <= 0:
                            return test.FAIL("Sender {} cannot GET an SDP transport file after 5 retries."
                                             .format(sender["id"]))
                        else:
                            time.sleep(2)
                    else:
                        break

                # Create an SDP object and parse the text into it. There must be at least a primary media
                # (no redundancy)
                sdp = MatroxSdp()

                try:
                    decode_error = sdp.decode(manifest_href_response.text)
                    if decode_error:
                        return test.FAIL("Sender {} cannot decode the SDP transport file {}, decode error: {}"
                                         .format(sender["id"], manifest_href, decode_error))
                except Exception as e:
                    return test.FAIL("Sender {} cannot decode the SDP transport file {}, raised an exception {}"
                                     .format(sender["id"], manifest_href, e))

                # Allow IPMX and ST-2110

                # Check the multicast address of the transport parameters matches with the SDP
                primary_transport_params = active["transport_params"][0]

                if (primary_transport_params["destination_ip"] != sdp.primary_media.connection_address or
                        primary_transport_params["destination_port"] != sdp.primary_media.port):
                    return test.FAIL("Sender {} destination address {} and port {} not matching with sdp address {}"
                                     " and port {}"
                                     .format(sender["id"], primary_transport_params["destination_ip"],
                                             primary_transport_params["destination_port"],
                                             sdp.primary_media.connection_address, sdp.primary_media.port))

                if (primary_transport_params["source_ip"] != sdp.primary_media.source_filter_src_address or
                        primary_transport_params["destination_ip"] != sdp.primary_media.source_filter_dst_address):
                    return test.FAIL("Sender {} source filter destination address {} and source address {} not"
                                     " matching with sdp destination {} and source {}"
                                     .format(sender["id"], primary_transport_params["destination_ip"],
                                             primary_transport_params["source_ip"],
                                             sdp.primary_media.source_filter_dst_address,
                                             sdp.primary_media.source_filter_src_address))

                # deactivate the sender as we want to start streaming only once the PCAP capture is enabled
                url = "single/senders/{}/staged".format(sender["id"])
                valid, response = self.is05_utils.checkCleanRequest("PATCH", url, {
                    "master_enable": False,
                    "activation": {"mode": "activate_immediate"}
                })
                if not valid:
                    return test.FAIL("Sender {} cannot deactivate the sender".format(sender["id"]))

                # Join the multicast stream and keep it joined
                # Extract multicast parameters
                multicast_ip = primary_transport_params["destination_ip"]
                source_ip = primary_transport_params["source_ip"]
                port = primary_transport_params["destination_port"]

                # Validate multicast parameters
                if not MulticastUtils.is_multicast_address(multicast_ip):
                    return test.FAIL("Sender {} destination IP {} is not a valid multicast address"
                                     .format(sender["id"], multicast_ip))

                # Join the multicast group and keep it joined for the duration of the test
                print("Joining multicast group for sender {}: {}:{} from source {}"
                      .format(sender["id"], multicast_ip, port, source_ip))

                try:
                    multicast_socket, interface_name = MulticastUtils.join_multicast_group_simple(
                        multicast_ip, port
                    )
                    print("Successfully joined multicast group {} (ASM mode)"
                            .format(multicast_ip))
                except MulticastJoinError as e:
                    return test.FAIL("Sender {} failed to join multicast stream, error: {}"
                                        .format(sender["id"], e))

                # Start tcpdump to capture the multicast stream for 3 seconds in parallel with this test
                pcap_filename = format + "-{}.pcap".format(sender["id"])
                sdp_filename = format + "-{}.sdp".format(sender["id"])

                # Get the directory of this script for capture scripts, and use vendor-specific directory for output files
                script_dir = os.path.dirname(os.path.abspath(__file__))
                parent_dir = os.path.dirname(os.path.dirname(script_dir))  # parent of parent directory (for scripts)

                # Use IPMX_VENDOR environment variable to determine output directory, fallback to parent_dir if not set
                ipmx_vendor = os.environ.get('IPMX_VENDOR')
                if ipmx_vendor and ipmx_vendor != "":
                    output_dir = f'IPMX_VENDOR_{ipmx_vendor}'
                    # Ensure output directory exists
                    if not os.path.exists(output_dir):
                        os.makedirs(output_dir)
                else:
                    output_dir = parent_dir  # Fallback to original behavior

                # Remove the files from output directory
                try:
                    os.remove(os.path.join(output_dir, pcap_filename))
                    os.remove(os.path.join(output_dir, sdp_filename))
                except Exception:
                    pass  # ignore if file not found

                try:
                    if platform.system() == "Windows":
                        capture_script = os.path.join(parent_dir, "start_capture_pcap.bat")
                        pcap_full_path = os.path.join(output_dir, pcap_filename)
                        print(f"Windows Interfaces {MulticastUtils.get_windows_adapters()}")
                        npf = MulticastUtils.get_windows_interface_NPF(interface_name)
                        print(f"Windows NPF is '{npf}' from {interface_name}")
                        tcpdump_process = subprocess.Popen([capture_script, pcap_full_path, multicast_ip, str(port), format, npf])
                    else:
                        capture_script = os.path.join(parent_dir, "start_capture_pcap.sh")
                        pcap_full_path = os.path.join(output_dir, pcap_filename)
                        # Run through bash explicitly to avoid exec format errors
                        tcpdump_process = subprocess.Popen(["bash", capture_script, pcap_full_path, multicast_ip, str(port), format])

                    print("Started packet capture: {}".format(pcap_filename))

                except (FileNotFoundError, OSError) as e:
                    return test.FAIL("Failed to start packet capture, error: {}".format(e))

                time.sleep(3)

                # Now reactivate the sender for the PCAP capture
                url = "single/senders/{}/staged".format(sender["id"])
                valid, response = self.is05_utils.checkCleanRequest("PATCH", url, {
                    "master_enable": True,
                    "activation": {"mode": "activate_immediate"}
                })
                if not valid:
                    return test.FAIL("Sender {} cannot activate the sender".format(sender["id"]))

                # Wait packet capture if it was started
                try:
                    tcpdump_process.wait(timeout=30)  # wait for the process to terminate with timeout
                    print("Stopped packet capture: {}".format(pcap_filename))
                except subprocess.TimeoutExpired:
                    print("Warning: Packet capture process did not terminate within timeout, terminating...")
                    tcpdump_process.terminate()
                    try:
                        tcpdump_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        print("Warning: Force killing packet capture process...")
                        tcpdump_process.kill()
                        tcpdump_process.wait()
                except Exception as e:
                    print("Warning: Error waiting for packet capture: {}".format(e))
                    # Try to terminate if still running
                    try:
                        if tcpdump_process.poll() is None:
                            tcpdump_process.terminate()
                            tcpdump_process.wait(timeout=5)
                    except Exception:
                        try:
                            tcpdump_process.kill()
                        except Exception:
                            pass

                # We must get the SDP transport file again to get the final PEP parameters that
                # become final on activation with master_enable set to true. We are not expecting
                # any changes in the SDP transport file after activation with master_enable set to true.
                sdp_retry = 2
                while True:
                    manifest_href = "single/senders/{}/transportfile".format(sender["id"])
                    manifest_href_valid, manifest_href_response = self.is05_utils.checkCleanRequest(
                        "GET", manifest_href)
                    if manifest_href_valid and manifest_href_response.status_code == 200:
                        pass
                    elif manifest_href_valid and manifest_href_response.status_code == 404:
                        return test.FAIL("Sender {} cannot GET an SDP transport file {}, got status 404."
                                         .format(sender["id"], manifest_href))
                    else:
                        return test.FAIL("Sender {} cannot GET an SDP transport file {}, got status {}."
                                         .format(sender["id"], manifest_href, manifest_href_response))

                    print(manifest_href_response.text)

                    if (manifest_href_response.text is None or
                            manifest_href_response.text == "" or
                            manifest_href_response.text.isspace()):
                        sdp_retry -= 1
                        if sdp_retry <= 0:
                            return test.FAIL("Sender {} cannot GET an SDP transport file after 5 retries."
                                             .format(sender["id"]))
                        else:
                            time.sleep(2)
                    else:
                        break

                sdp = MatroxSdp()

                try:
                    decode_error = sdp.decode(manifest_href_response.text)
                    if decode_error:
                        return test.FAIL("Sender {} cannot decode the SDP transport file {}, decode error: {}"
                                         .format(sender["id"], manifest_href, decode_error))
                except Exception as e:
                    return test.FAIL("Sender {} cannot decode the SDP transport file {}, raised an exception {}"
                                     .format(sender["id"], manifest_href, e))

                with open(os.path.join(output_dir, sdp_filename), 'wb') as file:
                    file.write(manifest_href_response.content)
                time.sleep(1)

                # Sender kept intentionally active

            except KeyError as e:
                return test.FAIL("Expected attribute not found in IS-04/IS-05 resource: {}".format(e))
            finally:
                # Cleanup: ensure all resources are properly released
                cleanup_errors = []
                
                # 1. Clean up multicast connection
                if multicast_socket is not None and multicast_ip is not None:
                    try:
                        MulticastUtils.leave_multicast_group(multicast_socket, multicast_ip, interface_name)
                        multicast_socket.close()
                        print("Left multicast group {} for sender {}"
                              .format(multicast_ip, sender["id"]))
                    except Exception as e:
                        cleanup_errors.append("Error leaving multicast group: {}".format(str(e)))
                
                # 2. Terminate packet capture process if still running
                if tcpdump_process is not None:
                    try:
                        if tcpdump_process.poll() is None:  # Process still running
                            print("Terminating packet capture process...")
                            tcpdump_process.terminate()
                            try:
                                tcpdump_process.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                print("Force killing packet capture process...")
                                tcpdump_process.kill()
                                tcpdump_process.wait()
                    except Exception as e:
                        cleanup_errors.append("Error terminating packet capture: {}".format(str(e)))
                
                if cleanup_errors:
                    print("Warning: Cleanup errors occurred for sender {}:".format(sender["id"]))
                    for error in cleanup_errors:
                        print("  - {}".format(error))

            time.sleep(3)

        if len(senders) > 0:
            return test.PASS()

        return test.UNCLEAR("No Sender resources were found on the Node")

    def test_102(self, test):
        """
        Pre-Test to get a << VB440 >> PCAP capture of a video sender along with its SDP transport file.
        """
        self.test = test

        for resource_type in ["senders", "flows", "sources", "devices", "self"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"].values()}

        video_senders = [sender for sender in self.is04_resources["senders"].values() if sender["flow_id"]
                            and sender["flow_id"] in flow_map
                            and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:video"]

        audio_senders = [sender for sender in self.is04_resources["senders"].values() if sender["flow_id"]
                            and sender["flow_id"] in flow_map
                            and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:audio"]

        senders = video_senders + audio_senders

        for sender in senders:
            # Initialize cleanup variables
            tcpdump_process = None
            multicast_ip = None

            if sender in video_senders:
                format = "video"
            elif sender in audio_senders:
                format = "audio"
            else:
                return test.FAIL("UNEXPECTED sender {}".format(sender["id"]))

            # check the transport => only RTP is currently supported by IPMX
            if not sender["transport"].startswith("urn:x-nmos:transport:rtp"):
                return test.FAIL("Sender {} transport {} is not RTP"
                                    .format(sender["id"], sender["transport"]))
            try:
                url = "single/senders/{}/active".format(sender["id"])
                valid, response = self.is05_utils.checkCleanRequest("GET", url)
                if not valid:
                    return test.FAIL("Sender {} not responding to IS-05 request"
                                     .format(sender["id"]))

                active = response.json()

                # We require an active sender in order to get an SDP transport file
                url = "single/senders/{}/staged".format(sender["id"])
                if not active["master_enable"]:
                    # activate the sender first
                    valid, response = self.is05_utils.checkCleanRequest("PATCH", url, {
                        "master_enable": True,
                        "activation": {"mode": "activate_immediate"}
                    })
                    if not valid:
                        return test.FAIL("Sender {} cannot activate the sender"
                                         .format(sender["id"]))

                    # update the active parameters after activation
                    url = "single/senders/{}/active".format(sender["id"])
                    valid, response = self.is05_utils.checkCleanRequest("GET", url)
                    if not valid:
                        return test.FAIL("Sender {} not responding to IS-05 request"
                                         .format(sender["id"]))

                    active = response.json()

                sdp_retry = 3
                while True:
                    manifest_href = "single/senders/{}/transportfile".format(sender["id"])
                    manifest_href_valid, manifest_href_response = self.is05_utils.checkCleanRequest(
                        "GET", manifest_href)
                    if manifest_href_valid and manifest_href_response.status_code == 200:
                        pass
                    elif manifest_href_valid and manifest_href_response.status_code == 404:
                        return test.FAIL("Sender {} cannot GET an SDP transport file {}, got status 404."
                                         .format(sender["id"], manifest_href))
                    else:
                        return test.FAIL("Sender {} cannot GET an SDP transport file {}, got status {}."
                                         .format(sender["id"], manifest_href, manifest_href_response))

                    if (manifest_href_response.text is None or
                            manifest_href_response.text == "" or
                            manifest_href_response.text.isspace()):
                        sdp_retry -= 1
                        if sdp_retry <= 0:
                            return test.FAIL("Sender {} cannot GET an SDP transport file after 5 retries."
                                             .format(sender["id"]))
                        else:
                            time.sleep(2)
                    else:
                        break

                # Create an SDP object and parse the text into it. There must be at least a primary media
                # (no redundancy)
                sdp = MatroxSdp()

                try:
                    decode_error = sdp.decode(manifest_href_response.text)
                    if decode_error:
                        return test.FAIL("Sender {} cannot decode the SDP transport file {}, decode error: {}"
                                         .format(sender["id"], manifest_href, decode_error))
                except Exception as e:
                    return test.FAIL("Sender {} cannot decode the SDP transport file {}, raised an exception {}"
                                     .format(sender["id"], manifest_href, e))

                # Allow IPMX and ST-2110

                # Check the multicast address of the transport parameters matches with the SDP
                primary_transport_params = active["transport_params"][0]

                if (primary_transport_params["destination_ip"] != sdp.primary_media.connection_address or
                        primary_transport_params["destination_port"] != sdp.primary_media.port):
                    return test.FAIL("Sender {} destination address {} and port {} not matching with sdp address {}"
                                     " and port {}"
                                     .format(sender["id"], primary_transport_params["destination_ip"],
                                             primary_transport_params["destination_port"],
                                             sdp.primary_media.connection_address, sdp.primary_media.port))

                if (primary_transport_params["source_ip"] != sdp.primary_media.source_filter_src_address or
                        primary_transport_params["destination_ip"] != sdp.primary_media.source_filter_dst_address):
                    return test.FAIL("Sender {} source filter destination address {} and source address {} not"
                                     " matching with sdp destination {} and source {}"
                                     .format(sender["id"], primary_transport_params["destination_ip"],
                                             primary_transport_params["source_ip"],
                                             sdp.primary_media.source_filter_dst_address,
                                             sdp.primary_media.source_filter_src_address))

                # deactivate the sender as we want to start streaming only once the PCAP capture is enabled
                url = "single/senders/{}/staged".format(sender["id"])
                valid, response = self.is05_utils.checkCleanRequest("PATCH", url, {
                    "master_enable": False,
                    "activation": {"mode": "activate_immediate"}
                })
                if not valid:
                    return test.FAIL("Sender {} cannot deactivate the sender".format(sender["id"]))

                # Extract multicast parameters
                multicast_ip = primary_transport_params["destination_ip"]
                source_ip = primary_transport_params["source_ip"]
                port = primary_transport_params["destination_port"]

                # Validate multicast parameters
                if not MulticastUtils.is_multicast_address(multicast_ip):
                    return test.FAIL("Sender {} destination IP {} is not a valid multicast address"
                                        .format(sender["id"], multicast_ip))

                # Start tcpdump to capture the multicast stream for 3 seconds in parallel with this test
                pcap_filename = format + "-{}.pcap".format(sender["id"])
                sdp_filename = format + "-{}.sdp".format(sender["id"])

                # Get the directory of this script for capture scripts, and use vendor-specific directory for output files
                script_dir = os.path.dirname(os.path.abspath(__file__))
                parent_dir = os.path.dirname(os.path.dirname(script_dir))  # parent of parent directory (for scripts)

                # Use IPMX_VENDOR environment variable to determine output directory, fallback to parent_dir if not set
                ipmx_vendor = os.environ.get('IPMX_VENDOR')
                if ipmx_vendor and ipmx_vendor != "":
                    output_dir = f'IPMX_VENDOR_{ipmx_vendor}'
                    # Ensure output directory exists
                    if not os.path.exists(output_dir):
                        os.makedirs(output_dir)
                else:
                    output_dir = parent_dir  # Fallback to original behavior

                # Remove the files from output directory
                try:
                    os.remove(os.path.join(output_dir, pcap_filename))
                    os.remove(os.path.join(output_dir, sdp_filename))
                except Exception:
                    pass  # ignore if file not found

                try:
                    if platform.system() == "Windows":
                        capture_script = os.path.join(parent_dir, "start_capture_pcap.bat")
                        pcap_full_path = os.path.join(output_dir, pcap_filename)
                        tcpdump_process = subprocess.Popen([capture_script, pcap_full_path, multicast_ip, str(port), format])
                    else:
                        capture_script = os.path.join(parent_dir, "start_capture_pcap.sh")
                        pcap_full_path = os.path.join(output_dir, pcap_filename)
                        # Run through bash explicitly to avoid exec format errors
                        tcpdump_process = subprocess.Popen(["bash", capture_script, pcap_full_path, multicast_ip, str(port), format])

                    print("Started packet capture: {}".format(pcap_filename))

                except (FileNotFoundError, OSError) as e:
                    return test.FAIL("Failed to start packet capture, error: {}".format(e))

                time.sleep(3)

                # Now reactivate the sender for the PCAP capture
                url = "single/senders/{}/staged".format(sender["id"])
                valid, response = self.is05_utils.checkCleanRequest("PATCH", url, {
                    "master_enable": True,
                    "activation": {"mode": "activate_immediate"}
                })
                if not valid:
                    return test.FAIL("Sender {} cannot activate the sender".format(sender["id"]))

                # Wait packet capture if it was started
                try:
                    tcpdump_process.wait(timeout=30)  # wait for the process to terminate with timeout
                    print("Stopped packet capture: {}".format(pcap_filename))
                except subprocess.TimeoutExpired:
                    print("Warning: Packet capture process did not terminate within timeout, terminating...")
                    tcpdump_process.terminate()
                    try:
                        tcpdump_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        print("Warning: Force killing packet capture process...")
                        tcpdump_process.kill()
                        tcpdump_process.wait()
                except Exception as e:
                    print("Warning: Error waiting for packet capture: {}".format(e))
                    # Try to terminate if still running
                    try:
                        if tcpdump_process.poll() is None:
                            tcpdump_process.terminate()
                            tcpdump_process.wait(timeout=5)
                    except Exception:
                        try:
                            tcpdump_process.kill()
                        except Exception:
                            pass

                # We must get the SDP transport file again to get the final PEP parameters that
                # become final on activation with master_enable set to true. We are not expecting
                # any changes in the SDP transport file after activation with master_enable set to true.
                sdp_retry = 2
                while True:
                    manifest_href = "single/senders/{}/transportfile".format(sender["id"])
                    manifest_href_valid, manifest_href_response = self.is05_utils.checkCleanRequest(
                        "GET", manifest_href)
                    if manifest_href_valid and manifest_href_response.status_code == 200:
                        pass
                    elif manifest_href_valid and manifest_href_response.status_code == 404:
                        return test.FAIL("Sender {} cannot GET an SDP transport file {}, got status 404."
                                         .format(sender["id"], manifest_href))
                    else:
                        return test.FAIL("Sender {} cannot GET an SDP transport file {}, got status {}."
                                         .format(sender["id"], manifest_href, manifest_href_response))

                    print(manifest_href_response.text)

                    if (manifest_href_response.text is None or
                            manifest_href_response.text == "" or
                            manifest_href_response.text.isspace()):
                        sdp_retry -= 1
                        if sdp_retry <= 0:
                            return test.FAIL("Sender {} cannot GET an SDP transport file after 5 retries."
                                             .format(sender["id"]))
                        else:
                            time.sleep(2)
                    else:
                        break

                sdp = MatroxSdp()

                try:
                    decode_error = sdp.decode(manifest_href_response.text)
                    if decode_error:
                        return test.FAIL("Sender {} cannot decode the SDP transport file {}, decode error: {}"
                                         .format(sender["id"], manifest_href, decode_error))
                except Exception as e:
                    return test.FAIL("Sender {} cannot decode the SDP transport file {}, raised an exception {}"
                                     .format(sender["id"], manifest_href, e))

                with open(os.path.join(output_dir, sdp_filename), 'wb') as file:
                    file.write(manifest_href_response.content)
                time.sleep(1)

                # Sender kept intentionally active

            except KeyError as e:
                return test.FAIL("Expected attribute not found in IS-04/IS-05 resource: {}".format(e))
            finally:
                # Cleanup: ensure all resources are properly released
                cleanup_errors = []
                
                # 1. Terminate packet capture process if still running
                if tcpdump_process is not None:
                    try:
                        if tcpdump_process.poll() is None:  # Process still running
                            print("Terminating packet capture process...")
                            tcpdump_process.terminate()
                            try:
                                tcpdump_process.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                print("Force killing packet capture process...")
                                tcpdump_process.kill()
                                tcpdump_process.wait()
                    except Exception as e:
                        cleanup_errors.append("Error terminating packet capture: {}".format(str(e)))
                
                if cleanup_errors:
                    print("Warning: Cleanup errors occurred for sender {}:".format(sender["id"]))
                    for error in cleanup_errors:
                        print("  - {}".format(error))

            time.sleep(3)

        if len(senders) > 0:
            return test.PASS()

        return test.UNCLEAR("No Sender resources were found on the Node")

    def test_11(self, test):
        """
        IPMX Sender Default Multicast Configuration Test and Multicast Exclusion Range Configurability Test
        """

        self.test = test

        for resource_type in ["senders", "flows", "sources", "devices", "self"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"].values()}

        try:
            video_senders = [sender for sender in self.is04_resources["senders"].values() if sender["flow_id"]
                             and sender["flow_id"] in flow_map
                             and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:video"]

            audio_senders = [sender for sender in self.is04_resources["senders"].values() if sender["flow_id"]
                             and sender["flow_id"] in flow_map
                             and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:audio"]

            senders = video_senders + audio_senders

            for sender in senders:

                # check the transport => only RTP is currently supported by IPMX
                if not sender["transport"].startswith("urn:x-nmos:transport:rtp"):
                    return test.FAIL("Sender {} transport {} is not RTP"
                                     .format(sender["id"], sender["transport"]))

                url = "single/senders/{}/active".format(sender["id"])
                valid, response = self.is05_utils.checkCleanRequest("GET", url)
                if not valid:
                    return test.FAIL("Sender {} not responding to IS-05 request"
                                     .format(sender["id"]))

                active = response.json()

                # We require an active sender in order to get an SDP transport file
                if not active["master_enable"]:
                    return test.FAIL("Sender {} is not active. This test requires an active sender "
                                     "with a default multicast address".format(sender["id"]))

                sdp_retry = 5
                while True:
                    manifest_href = "single/senders/{}/transportfile".format(sender["id"])
                    manifest_href_valid, manifest_href_response = self.is05_utils.checkCleanRequest(
                        "GET", manifest_href)
                    if manifest_href_valid and manifest_href_response.status_code == 200:
                        pass
                    elif manifest_href_valid and manifest_href_response.status_code == 404:
                        return test.FAIL("Sender {} cannot GET an SDP transport file {}, got status 404."
                                         .format(sender["id"], manifest_href))
                    else:
                        return test.FAIL("Sender {} cannot GET an SDP transport file {}, got status {}."
                                         .format(sender["id"], manifest_href, manifest_href_response))

                    if (manifest_href_response.text is None or
                            manifest_href_response.text == "" or
                            manifest_href_response.text.isspace()):
                        sdp_retry -= 1
                        if sdp_retry <= 0:
                            return test.FAIL("Sender {} cannot GET an SDP transport file after 5 retries."
                                             .format(sender["id"]))
                        else:
                            time.sleep(2)
                    else:
                        break

                # Create an SDP object and parse the text into it. There must be at least a primary media
                sdp = MatroxSdp()

                try:
                    decode_error = sdp.decode(manifest_href_response.text)
                    if decode_error:
                        return test.FAIL("Sender {} cannot decode the SDP transport file {}, decode error: {}"
                                         .format(sender["id"], manifest_href, decode_error))
                except Exception as e:
                    return test.FAIL("Sender {} cannot decode the SDP transport file {}, raised an exception {}"
                                     .format(sender["id"], manifest_href, e))

                # Check IPMX
                if not sdp.primary_media.ipmx:
                    return test.FAIL("Sender {} SDP is not indicating IPMX"
                                     .format(sender["id"]))

                # Check that the device is not using redundancy (simplication for this test)
                # if sdp.secondary_media or len(active["transport_params"]) > 1:
                # if len(active["transport_params"]) > 1:
                #     return test.FAIL("Sender {} is using redundancy and multiple transport parameters. Disable redundancy and re-test."
                #                      .format(sender["id"]))

                # Check the multicast address of the transport parameters
                primary_transport_params = active["transport_params"][0]

                if (primary_transport_params["destination_ip"] != sdp.primary_media.connection_address or
                        primary_transport_params["destination_port"] != sdp.primary_media.port):
                    return test.FAIL("Sender {} destination address {} and port {} not matching with sdp address {}"
                                     " and port {}"
                                     .format(sender["id"], primary_transport_params["destination_ip"],
                                             primary_transport_params["destination_port"],
                                             sdp.primary_media.connection_address, sdp.primary_media.port))

                # IPMX Senders shall include source address information in the SDP object.
                if sdp.primary_media.source_filter_src_address == "":
                    return test.FAIL("Sender {} missing source address information in the SDP object"
                                     .format(sender["id"]))

                if (primary_transport_params["source_ip"] != sdp.primary_media.source_filter_src_address or
                        primary_transport_params["destination_ip"] != sdp.primary_media.source_filter_dst_address):
                    return test.FAIL("Sender {} source filter destination address {} and source address {} not"
                                     " matching with sdp destination {} and source {}"
                                     .format(sender["id"], primary_transport_params["destination_ip"],
                                             primary_transport_params["source_ip"],
                                             sdp.primary_media.source_filter_dst_address,
                                             sdp.primary_media.source_filter_src_address))

                # Extract multicast parameters
                multicast_ip = primary_transport_params["destination_ip"]
                source_ip = primary_transport_params["source_ip"]
                port = primary_transport_params["destination_port"]

                # Validate multicast parameters
                if not MulticastUtils.is_multicast_address(multicast_ip):
                    return test.FAIL("Sender {} destination IP {} is not a valid multicast address"
                                     .format(sender["id"], multicast_ip))

                # IPMX Senders shall use a default UDP port value of 5004
                if port != 5004:
                    return test.FAIL("Sender {} destination port {} is not 5004"
                                     .format(sender["id"], port))

                # The default multicast address for a given IPMX media stream shall be
                # 239.S.C.D where S is the stream number larger than 0 and less than 128.
                if not MulticastUtils.is_valid_admin_scope_multicast(multicast_ip):
                    return test.FAIL("Sender {} destination IP {} is not a valid 239.S.C.D multicast address"
                                     .format(sender["id"], multicast_ip))

                # check next byte to be in the range 1 to 127
                if int(multicast_ip.split(".")[1]) < 1 or int(multicast_ip.split(".")[1]) > 127:
                    return test.FAIL("Sender {} destination IP {} is not a valid 239.S.C.D multicast address"
                                     .format(sender["id"], multicast_ip))

                # check the last two bytes to match the source address two equivalent bytes
                if (int(multicast_ip.split(".")[2]) != int(source_ip.split(".")[2]) or
                        int(multicast_ip.split(".")[3]) != int(source_ip.split(".")[3])):
                    return test.FAIL("Sender {} destination IP {} and source IP {} do not match on "
                                     "C and/or D bytes of 239.S.C.D encoding"
                                     .format(sender["id"], multicast_ip, source_ip))

                # deactivate the sender and test multicast ranges, ensuring cleanup in finally block
                url = "single/senders/{}/staged".format(sender["id"])

                try:
                    valid, response = self.is05_utils.checkCleanRequest("PATCH", url, {
                        "master_enable": False,
                        "activation": {"mode": "activate_immediate"}
                    })
                    if not valid:
                        return test.FAIL("Sender {} cannot deactivate the sender".format(sender["id"]))

                    # Now we test the multicast range supported keeping the master_enable to false but setting
                    # various multicast addresses at the base, end and random middle point of the various ranges
                    # to test.
                    ip_to_test_with_success = [
                        "239.1.0.0",
                        "239.127.255.255",
                        MulticastUtils.getRandomIpv4AddressWithinRange("239.1.0.0", "239.127.255.255")]

                    for ip in ip_to_test_with_success:
                        valid, response = self.is05_utils.checkCleanRequest("PATCH", url, {
                            "master_enable": False,
                            "transport_params": [{"destination_ip": ip}],
                            "activation": {"mode": "activate_immediate"}
                        })
                        if not valid:
                            return test.FAIL("Sender {} failed to set a valid multicast address {}"
                                             .format(sender["id"], ip))

                    ip_to_test_with_failure = [
                        "224.0.0.0",
                        "224.0.1.255",
                        MulticastUtils.getRandomIpv4AddressWithinRange("224.0.0.0", "224.0.1.255")]

                    for ip in ip_to_test_with_failure:
                        valid, response = self.is05_utils.checkCleanRequest("PATCH", url, {
                            "master_enable": False,
                            "transport_params": [{"destination_ip": ip}],
                            "activation": {"mode": "activate_immediate"}
                        })
                        if valid:
                            return test.FAIL("Sender {} accepted an invalid multicast address {}".format(sender["id"], ip))
                finally:
                    # Always try to re-activate the sender with its original multicast address (best effort)
                    valid, response = self.is05_utils.checkCleanRequest("PATCH", url, {
                        "master_enable": True,
                        "transport_params": [{"destination_ip": multicast_ip}],
                        "activation": {"mode": "activate_immediate"}
                    })
                    if not valid:
                        print("WARNING: Sender {} could not be re-activated with its original multicast address".format(sender["id"]))

            if len(senders) > 0:
                return test.PASS()

        except KeyError as e:
            return test.FAIL("Expected attribute not found in IS-04/IS-05 resource: {}".format(e))

        return test.UNCLEAR("No Sender resources were found on the Node")

    def test_12(self, test):
        """
        IPMX Receiver multicast Exclusion Range Configurability Test
        """

        self.test = test

        for resource_type in ["receivers", "devices", "self"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        try:
            video_receivers = [receiver for receiver in self.is04_resources["receivers"].values() if receiver["format"]
                               and receiver["format"] == "urn:x-nmos:format:video"]

            audio_receivers = [receiver for receiver in self.is04_resources["receivers"].values() if receiver["format"]
                               and receiver["format"] == "urn:x-nmos:format:audio"]

            receivers = video_receivers + audio_receivers

            for receiver in receivers:

                # check the transport => only RTP is currently supported by IPMX
                if not receiver["transport"].startswith("urn:x-nmos:transport:rtp"):
                    return test.FAIL("Receiver {} transport {} is not RTP"
                                     .format(receiver["id"], receiver["transport"]))

                url = "single/receivers/{}/active".format(receiver["id"])
                valid, response = self.is05_utils.checkCleanRequest("GET", url)
                if not valid:
                    return test.FAIL("Receiver {} not responding to IS-05 request"
                                     .format(receiver["id"]))

                active = response.json()

                # We require an active receiver proving that it can srteazm with the default multicast address
                url = "single/receivers/{}/staged".format(receiver["id"])
                if not active["master_enable"]:
                    return test.FAIL("Receiver {} is not active. This test requires an active receiver with "
                                     "a default multicast address".format(receiver["id"]))

                # Check that the device is not using redundancy (simplication for this test)
                if len(active["transport_params"]) > 1:
                    return test.FAIL("Receiver {} is using redundancy and multiple transport parameters. Disable redundancy and re-test."
                                     .format(receiver["id"]))

                # Check the multicast address of the transport parameters
                primary_transport_params = active["transport_params"][0]

                # Extract multicast parameters
                multicast_ip = primary_transport_params["multicast_ip"]
                source_ip = primary_transport_params["source_ip"]
                port = primary_transport_params["destination_port"]

                # Validate multicast parameters
                if not MulticastUtils.is_multicast_address(multicast_ip):
                    return test.FAIL("Receiver {} destination IP {} is not a valid multicast address"
                                     .format(receiver["id"], multicast_ip))

                # IPMX Receivers shall use a default UDP port value of 5004
                if port != 5004:
                    return test.FAIL("Receiver {} destination port {} is not 5004"
                                     .format(receiver["id"], port))

                # 239.S.C.D where S is the stream number larger than 0 and less than 128.
                if not MulticastUtils.is_valid_admin_scope_multicast(multicast_ip):
                    return test.FAIL("Receiver {} destination IP {} is not a valid 239.S.C.D multicast address"
                                     .format(receiver["id"], multicast_ip))

                # check next byte to be in the range 1 to 127
                if int(multicast_ip.split(".")[1]) < 1 or int(multicast_ip.split(".")[1]) > 127:
                    return test.FAIL("Receiver {} destination IP {} is not a valid 239.S.C.D multicast address"
                                     .format(receiver["id"], multicast_ip))

                # check the last two bytes to match the source address two equivalent bytes
                if (int(multicast_ip.split(".")[2]) != int(source_ip.split(".")[2]) or
                        int(multicast_ip.split(".")[3]) != int(source_ip.split(".")[3])):
                    return test.FAIL("Receiver {} destination IP {} and source IP {} do not match on "
                                     "C and/or D bytes of 239.S.C.D encoding"
                                     .format(receiver["id"], multicast_ip, source_ip))

                # deactivate the receiver
                url = "single/receivers/{}/staged".format(receiver["id"])
                valid, response = self.is05_utils.checkCleanRequest("PATCH", url, {
                    "master_enable": False,
                    "activation": {"mode": "activate_immediate"}
                })
                if not valid:
                    return test.FAIL("Receiver {} cannot deactivate the receiver".format(receiver["id"]))

                # Now we test the multicast range supported keeping the master_enable to false but setting
                # various multicast addresses at the base, end and random middle point of the various ranges
                # to test.
                ip_to_test_with_success = [
                    "239.0.0.0",
                    "239.255.255.255",
                    MulticastUtils.getRandomIpv4AddressWithinRange("239.0.0.0", "239.255.255.255"),
                    "224.0.2.0",
                    "238.255.255.255",
                    MulticastUtils.getRandomIpv4AddressWithinRange("224.0.2.0", "238.255.255.255")]

                for ip in ip_to_test_with_success:
                    valid, response = self.is05_utils.checkCleanRequest("PATCH", url, {
                        "master_enable": False,
                        "transport_params": [{"multicast_ip": ip}],
                        "activation": {"mode": "activate_immediate"}
                    })
                    if not valid:
                        return test.FAIL("Receiver {} failed to set a valid multicast address {}"
                                         .format(receiver["id"], ip))

                ip_to_test_with_failure = [
                    "224.0.0.0",
                    "224.0.1.255",
                    MulticastUtils.getRandomIpv4AddressWithinRange("224.0.0.0", "224.0.1.255")]

                for ip in ip_to_test_with_failure:
                    valid, response = self.is05_utils.checkCleanRequest("PATCH", url, {
                        "master_enable": False,
                        "transport_params": [{"multicast_ip": ip}],
                        "activation": {"mode": "activate_immediate"}
                    })
                    if valid:
                        return test.FAIL("Receiver {} accepted an invalid multicast address {}"
                                         .format(receiver["id"], ip))

            if len(receivers) > 0:
                return test.PASS()

        except KeyError as e:
            return test.FAIL("Expected attribute not found in IS-04/IS-05 resource: {}".format(e))

        return test.UNCLEAR("No Receiver resources were found on the Node")

    def test_13(self, test):
        """
        List all the Senders and Receivers on the Node along with their label, description and transport.
        """
        self.test = test

        for resource_type in ["senders", "receivers"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        # Display Senders in a formatted table
        senders = list(self.is04_resources["senders"].values())
        if senders:
            print("\n" + "=" * 150)
            print("SENDERS")
            print("=" * 150)
            print("{:<38} {:<37} {:<57} {:<18}".format("GUID", "Label", "Description", "Transport"))
            print("-" * 150)
            for sender in senders:
                label = sender.get("label", "")[:36]
                description = sender.get("description", "")[:56]
                transport = sender.get("transport", "").replace("urn:x-nmos:transport:", "")[:17]
                print("{:<38} {:<37} {:<57} {:<18}".format(
                    sender["id"],
                    label,
                    description,
                    transport
                ))
            print("=" * 150)
            print("Total Senders: {}".format(len(senders)))
        else:
            print("\nNo Senders found on the Node")

        # Display Receivers in a formatted table
        receivers = list(self.is04_resources["receivers"].values())
        if receivers:
            print("\n" + "=" * 150)
            print("RECEIVERS")
            print("=" * 150)
            print("{:<38} {:<37} {:<57} {:<18}".format("GUID", "Label", "Description", "Transport"))
            print("-" * 150)
            for receiver in receivers:
                label = receiver.get("label", "")[:36]
                description = receiver.get("description", "")[:56]
                transport = receiver.get("transport", "").replace("urn:x-nmos:transport:", "")[:17]
                print("{:<38} {:<37} {:<57} {:<18}".format(
                    receiver["id"],
                    label,
                    description,
                    transport
                ))
            print("=" * 150)
            print("Total Receivers: {}".format(len(receivers)))
        else:
            print("\nNo Receivers found on the Node")

        print()  # Empty line at the end
        return test.PASS()

    def _get_sender_from_registry(self, sender_id):
        """
        Get sender information from the registry using the query API
        """
        try:
            # Use the query API to get sender information
            query_url = self.query_url
            if not query_url:
                return None

            # Query for the specific sender
            url = "{}senders/{}".format(query_url, sender_id)
            valid, response = self.do_request("GET", url)

            if valid and response.status_code == 200:
                return response.json()
            else:
                return None
        except Exception:
            return None

    def _get_flow_from_registry(self, flow_id):
        """
        Get flow information from the registry using the query API
        """
        try:
            query_url = self.query_url
            if not query_url:
                return None

            # Query for the specific flow
            url = "{}flows/{}".format(query_url, flow_id)
            valid, response = self.do_request("GET", url)

            if valid and response.status_code == 200:
                return response.json()
            else:
                return None
        except Exception:
            return None

    def _get_source_from_registry(self, source_id):
        """
        Get source information from the registry using the query API
        """
        try:
            query_url = self.query_url
            if not query_url:
                return None

            # Query for the specific source
            url = "{}sources/{}".format(query_url, source_id)
            valid, response = self.do_request("GET", url)

            if valid and response.status_code == 200:
                return response.json()
            else:
                return None
        except Exception:
            return None

    def _get_device_from_registry(self, device_id):
        """
        Get device information from the registry using the query API
        """
        try:
            query_url = self.query_url
            if not query_url:
                return None

            # Query for the specific device
            url = "{}devices/{}".format(query_url, device_id)
            valid, response = self.do_request("GET", url)

            if valid and response.status_code == 200:
                return response.json()
            else:
                return None
        except Exception:
            return None

    def _get_node_from_registry(self, node_id):
        """
        Get node information from the registry using the query API
        """
        try:
            query_url = self.query_url
            if not query_url:
                return None

            # Query for the specific node
            url = "{}nodes/{}".format(query_url, node_id)
            valid, response = self.do_request("GET", url)

            if valid and response.status_code == 200:
                return response.json()
            else:
                return None
        except Exception:
            return None

    def _verify_sender_ccf_capability_compatibility(self, sender, sdp_flow_caps):
        """
        Verify that SDP capabilities are compatible with sender CCF capabilities using proper CCF functions

        This method uses CCF convert_caps_json_to_caps and conset_included_in_caps functions
        to properly verify that the SDP capabilities are included in the sender's CCF constraints.

        Args:
            sender: Sender resource from IS-04
            sdp_caps: CCF Caps from SDP conversion

        Returns:
            tuple: (success, error_message) where success is True if compatible,
                   False with error message if not compatible or error occurred
        """
        try:
            # Get sender CCF capabilities from IS-04 and convert to CCF Caps
            sender_ccf_caps = self._get_sender_ccf_capabilities(sender)

            if not sender_ccf_caps:
                # If sender has no capability constraints defined, assume compatibility
                return True, ""

            # Convert sender JSON caps to CCF Caps object
            try:
                sender_caps = convert_caps_json_to_caps(sender_ccf_caps).get() # sort by preference
            except Exception as e:
                return False, "Sender {} caps JSON to CCF conversion failed: {}".format(sender["id"], e)

            print("SENDER CAPS:\n{}\n".format(str(sender_caps)))

            sender_active_constraints = self._get_is11_active_constraints(sender["id"])
            if sender_active_constraints and len(sender_active_constraints.get("constraint_sets", [])):
                try:
                    sender_cons = convert_caps_json_to_caps(sender_active_constraints).to_cons()
                except Exception as e:
                    return False, "Sender {} active constraints JSON to CCF conversion failed: {}".format(
                        sender["id"], e)

                # We want to constrain each capset by the IS-11 constraints and keep the original preference
                # which allow keeing caps that are very similar to the original ones but taking into account
                # the IS-11 constraints. The default algorithms of CCF do not allow this operation so we must
                # implement it manually.
                result_sender_caps = Caps(capsets=[])
                for capset in sender_caps.capsets:
                    try:
                        # Active constraints are already within the caps of the Sender so this operator is ok
                        caps = caps_constrict_by_cons(Caps(capsets=[capset]), sender_cons)
                        for cs in caps.capsets:
                            cs.preference = capset.preference  # keep original preference
                            result_sender_caps.capsets.append(cs)
                    except Exception as e:
                        # It is possible to get empty spaces whch is normal when isolating a single capset
                        pass
                sender_caps = result_sender_caps.get()  # sort by preference

                if len(sender_caps.capsets) == 0:
                    return False, "Sender {} constriction failed, possibly an empty space".format(sender["id"])

                print("SENDER CAPS (constrained by IS-11):\n{}\n".format(str(sender_caps)))

            # Get the primary capability set from SDP
            if len(sdp_flow_caps.capsets) == 0:
                return False, "Sender {} SDP transport file or Flow  produced no capability sets".format(sender["id"])

            primary_capset = sdp_flow_caps.capsets[0]

            print("SDP Transport File or Flow CAPS:\n{}\n".format(str(primary_capset)))

            # Use CCF conset_included_in_caps to verify inclusion
            # This checks if the SDP capset is included in (compatible with) the sender's caps
            try:
                is_included = conset_included_in_caps(primary_capset.to_conset(), sender_caps)
                if is_included:
                    return True, ""
                else:
                    return False, "Sender {} SDP or Flow capabilities are not " \
                        "included in sender CCF constraints".format(sender["id"])
            except Exception as e:
                return False, "Sender {} CCF capability inclusion check failed: {}".format(sender["id"], e)

        except Exception as e:
            return False, "Sender {} CCF capability verification error: {}".format(sender["id"], e)

    def _verify_receiver_ccf_capability_compatibility(self, receiver, sdp_flow_caps):
        """
        Verify that SDP capabilities are compatible with receiver CCF capabilities using proper CCF functions

        This method uses CCF convert_caps_json_to_caps and conset_included_in_caps functions
        to properly verify that the SDP capabilities are included in the receiver's CCF constraints.

        Args:
            receiver: Receiver resource from IS-04
            sdp_caps: CCF Caps from SDP conversion

        Returns:
            tuple: (success, error_message) where success is True if compatible,
                   False with error message if not compatible or error occurred
        """
        try:
            # Get receiver CCF capabilities from IS-04 and convert to CCF Caps
            receiver_ccf_caps = self._get_receiver_ccf_capabilities(receiver)

            if not receiver_ccf_caps:
                # If receiver has no capability constraints defined, assume compatibility
                return True, ""

            # Convert receiver JSON caps to CCF Caps object
            try:
                receiver_caps = convert_caps_json_to_caps(receiver_ccf_caps)
            except Exception as e:
                return False, "Receiver {} caps JSON to CCF conversion failed: {}".format(receiver["id"], e)

            print("RECEIVER CAPS:\n{}\n".format(str(receiver_caps)))

            # Get the primary capability set from SDP
            if len(sdp_flow_caps.capsets) == 0:
                return False, "Receiver {} SDP transport file or Flow produced no capability sets".format(
                    receiver["id"])

            primary_capset = sdp_flow_caps.capsets[0]

            print("SDP Transport File or Flow CAPS:\n{}\n".format(str(primary_capset)))

            # Use CCF conset_included_in_caps to verify inclusion
            # This checks if the SDP capset is included in (compatible with) the receiver's caps
            try:
                is_included = conset_included_in_caps(primary_capset.to_conset(), receiver_caps)
                if is_included:
                    return True, ""
                else:
                    return False, "Receiver {} SDP or Flow capabilities are not included " \
                        "in receiver CCF constraints".format(receiver["id"])
            except Exception as e:
                return False, "Receiver {} CCF capability inclusion check failed: {}".format(receiver["id"], e)

        except Exception as e:
            return False, "Receiver {} CCF capability verification error: {}".format(receiver["id"], e)

    def _get_receiver_ccf_capabilities(self, receiver):
        """
        Get receiver CCF capabilities from IS-04 receiver resource

        Returns:
            Dict of CCF capabilities JSON or None if not available
        """
        try:
            # Check if receiver has CCF capabilities defined
            if "caps" not in receiver or not receiver["caps"]:
                return None

            # Return the receiver's CCF capabilities JSON directly
            # This will be converted to CCF Caps object by convert_caps_json_to_caps
            return receiver["caps"]

        except Exception:
            # Return None on any error - the calling method will handle error reporting
            return None

    def _get_sender_ccf_capabilities(self, sender):
        """
        Get sender CCF capabilities from IS-04 sender resource

        Returns:
            Dict of CCF capabilities JSON or None if not available
        """
        try:
            # Check if sender has CCF capabilities defined
            if "caps" not in sender or not sender["caps"]:
                return None

            # Return the sender's CCF capabilities JSON directly
            # This will be converted to CCF Caps object by convert_caps_json_to_caps
            return sender["caps"]

        except Exception:
            # Return None on any error - the calling method will handle error reporting
            return None

    def prepare_subscription(self, resource_path, params=None, api_ver=None):
        """Prepare an object ready to send as the request body for a Query API subscription"""
        if params is None:
            params = {}
        if api_ver is None:
            api_ver = self.apis[QUERY_API_KEY]["version"]
        sub_json = dict()
        sub_json["params"] = dict()
        sub_json["max_update_rate_ms"] = 100
        sub_json["resource_path"] = resource_path
        sub_json["params"] = params
        sub_json["secure"] = CONFIG.ENABLE_HTTPS
        sub_json["persist"] = True
        if self.is04_query_utils.compare_api_version(api_ver, "v1.3") < 0:
            sub_json = IS04Utils.downgrade_resource("subscription", sub_json, api_ver)
        return sub_json

    def post_subscription(self, test, sub_json, query_url=None):
        """Perform a POST request to a Query API to create a subscription"""
        if query_url is None:
            query_url = self.query_url

        api_ver = query_url.rstrip("/").rsplit("/", 1)[-1]

        valid, r = self.do_request("POST", "{}subscriptions".format(query_url), json=sub_json)

        if not valid:
            raise NMOSTestException(test.FAIL("Query API returned an unexpected response: {}".format(r)))

        if r.status_code in [200, 201]:
            if self.is04_query_utils.compare_api_version(api_ver, "v1.3") >= 0:
                if "Location" not in r.headers:
                    raise NMOSTestException(test.FAIL("Query API failed to return a 'Location' response header"))
                path = "{}subscriptions/".format(urlparse(query_url).path)
                location = r.headers["Location"]
                if path not in location:
                    raise NMOSTestException(test.FAIL("Query API 'Location' response header is incorrect: "
                                                      "Location: {}".format(location)))
                if not location.startswith("/") and not location.startswith(self.protocol + "://"):
                    raise NMOSTestException(test.FAIL("Query API 'Location' response header is invalid for the "
                                                      "current protocol: Location: {}".format(location)))
        elif r.status_code in [400, 501]:
            raise NMOSTestException(test.FAIL("Query API signalled that it does not support the requested "
                                              "subscription parameters: {} {}".format(r.status_code, sub_json)))
        else:
            raise NMOSTestException(test.FAIL("Query API returned an unexpected response: "
                                              "{} {}".format(r.status_code, r.text)))

        # Currently can only validate schema for the API version under test
        if query_url == self.query_url:
            schema = self.get_schema(QUERY_API_KEY, "POST", "/subscriptions", r.status_code)
            valid, message = self.check_response(schema, "POST", r)
            if valid:
                # if message:
                #     return WARNING somehow...
                pass
            else:
                raise NMOSTestException(test.FAIL(message))

        try:
            return r.json()
        except json.JSONDecodeError:
            raise NMOSTestException(test.FAIL("Non-JSON response returned for Query API subscription request"))

    def _get_is11_active_constraints(self, sender_id):
        """
        Get IS-11 active constraints for a specific sender from its device's control endpoints

        Args:
            sender_id: The ID of the sender to get constraints for

        Returns:
            dict or None: Active constraints for the sender, or None if not found/unavailable
        """
        try:
            # Get all devices
            valid, result = self.get_is04_resources("devices")
            if not valid:
                return None

            # Find the device that contains our sender
            sender_device = None
            valid, senders_result = self.get_is04_resources("senders")
            if valid:
                for sender in self.is04_resources["senders"].values():
                    if sender["id"] == sender_id:
                        device_id = sender.get("device_id")
                        if device_id and device_id in self.is04_resources["devices"]:
                            sender_device = self.is04_resources["devices"][device_id]
                        break

            if not sender_device:
                return None

            # Find IS-11 control endpoint in device controls
            is11_endpoint = None
            for control in sender_device.get("controls", []):
                if control.get("type") == "urn:x-nmos:control:stream-compat/v1.0":
                    is11_endpoint = control.get("href")
                    break

            if not is11_endpoint:
                return None

            # Query the IS-11 endpoint for active constraints of this sender
            active_constraints_url = "{}/senders/{}/constraints/active".format(is11_endpoint.rstrip('/'), sender_id)

            # Use the existing HTTP request mechanism
            valid, response = self.do_request("GET", active_constraints_url)

            if valid and response.status_code == 200:
                return response.json()
            else:
                return None

        except Exception:
            # Silently fail for IS-11 constraints - they're optional
            return None


def GetSdpSamplingAsComponents(sdp: MatroxSdp):

    width = sdp.primary_media.width
    height = sdp.primary_media.height
    depth = sdp.primary_media.depth

    # The ordering of the components does not matter ... so using a map
    components = dict()

    # return an dict of components each having a name, with, height and bit_depth
    if sdp.primary_media.sampling == MatroxSdpEnums.SamplingRGB:
        r = dict(name="R", width=width, height=height, bit_depth=depth)
        g = dict(name="G", width=width, height=height, bit_depth=depth)
        b = dict(name="B", width=width, height=height, bit_depth=depth)
        components[r["name"]] = r
        components[g["name"]] = g
        components[b["name"]] = b
    elif sdp.primary_media.sampling == MatroxSdpEnums.SamplingRGBA:
        r = dict(name="R", width=width, height=height, bit_depth=depth)
        g = dict(name="G", width=width, height=height, bit_depth=depth)
        b = dict(name="B", width=width, height=height, bit_depth=depth)
        a = dict(name="A", width=width, height=height, bit_depth=depth)
        components[r["name"]] = r
        components[g["name"]] = g
        components[b["name"]] = b
        components[a["name"]] = a
    elif sdp.primary_media.sampling == MatroxSdpEnums.SamplingBGR:
        r = dict(name="R", width=width, height=height, bit_depth=depth)
        g = dict(name="G", width=width, height=height, bit_depth=depth)
        b = dict(name="B", width=width, height=height, bit_depth=depth)
        components[r["name"]] = r
        components[g["name"]] = g
        components[b["name"]] = b
    elif sdp.primary_media.sampling == MatroxSdpEnums.SamplingBGRA:
        r = dict(name="R", width=width, height=height, bit_depth=depth)
        g = dict(name="G", width=width, height=height, bit_depth=depth)
        b = dict(name="B", width=width, height=height, bit_depth=depth)
        a = dict(name="A", width=width, height=height, bit_depth=depth)
        components[r["name"]] = r
        components[g["name"]] = g
        components[b["name"]] = b
        components[a["name"]] = a
    elif sdp.primary_media.sampling == MatroxSdpEnums.SamplingYCbCr_444:
        y = dict(name="Y", width=width, height=height, bit_depth=depth)
        u = dict(name="Cb", width=width, height=height, bit_depth=depth)
        v = dict(name="Cr", width=width, height=height, bit_depth=depth)
        components[y["name"]] = y
        components[u["name"]] = u
        components[v["name"]] = v
    elif sdp.primary_media.sampling == MatroxSdpEnums.SamplingYCbCr_422:
        y = dict(name="Y", width=width, height=height, bit_depth=depth)
        u = dict(name="Cb", width=width/2, height=height, bit_depth=depth)
        v = dict(name="Cr", width=width/2, height=height, bit_depth=depth)
        components[y["name"]] = y
        components[u["name"]] = u
        components[v["name"]] = v
    elif sdp.primary_media.sampling == MatroxSdpEnums.SamplingYCbCr_420:
        y = dict(name="Y", width=width, height=height, bit_depth=depth)
        u = dict(name="Cb", width=width/2, height=height/2, bit_depth=depth)
        v = dict(name="Cr", width=width/2, height=height/2, bit_depth=depth)
        components[y["name"]] = y
        components[u["name"]] = u
        components[v["name"]] = v
    elif sdp.primary_media.sampling == MatroxSdpEnums.SamplingYCbCr_411:
        y = dict(name="Y", width=width, height=height, bit_depth=depth)
        u = dict(name="Cb", width=width/4, height=height, bit_depth=depth)
        v = dict(name="Cr", width=width/4, height=height, bit_depth=depth)
        components[y["name"]] = y
        components[u["name"]] = u
        components[v["name"]] = v
    # elif sdp.primary_media.sampling == SamplingCLYCbCr_444:
    # elif sdp.primary_media.sampling == SamplingCLYCbCr_422:
    # elif sdp.primary_media.sampling == SamplingCLYCbCr_420:
    elif sdp.primary_media.sampling == MatroxSdpEnums.SamplingICtCp_444:
        i = dict(name="I", width=width, height=height, bit_depth=depth)
        t = dict(name="Ct", width=width, height=height, bit_depth=depth)
        p = dict(name="Cp", width=width, height=height, bit_depth=depth)
        components[i["name"]] = i
        components[t["name"]] = t
        components[p["name"]] = p
    elif sdp.primary_media.sampling == MatroxSdpEnums.SamplingICtCp_422:
        i = dict(name="I", width=width, height=height, bit_depth=depth)
        t = dict(name="Ct", width=width/2, height=height, bit_depth=depth)
        p = dict(name="Cp", width=width/2, height=height, bit_depth=depth)
        components[i["name"]] = i
        components[t["name"]] = t
        components[p["name"]] = p
    elif sdp.primary_media.sampling == MatroxSdpEnums.SamplingICtCp_420:
        i = dict(name="I", width=width, height=height, bit_depth=depth)
        t = dict(name="Ct", width=width/2, height=height/2, bit_depth=depth)
        p = dict(name="Cp", width=width/2, height=height/2, bit_depth=depth)
        components[i["name"]] = i
        components[t["name"]] = t
        components[p["name"]] = p
    # elif sdp.primary_media.sampling == SamplingXYZ:
    # elif sdp.primary_media.sampling == SamplingKey:
    # elif sdp.primary_media.sampling == SamplingUnspecified:
    else:
        raise ValueError(f"unsupported color sampling {sdp.primary_media.sampling}")

    return components
