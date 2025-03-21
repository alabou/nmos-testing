# Copyright (C) 2024 Matrox Graphics Inc.
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

import json
import re
import io

from time import sleep

from jsonschema import ValidationError

from ..GenericTest import GenericTest, NMOSTestException
from ..IS04Utils import IS04Utils
from ..IS05Utils import IS05Utils
from ..TestHelper import load_resolved_schema
from ..TestHelper import check_content_type
from ..TestHelper import WebsocketWorker

from urllib.parse import urlparse

from .. import Config as CONFIG

from .MatroxSdp import MatroxSdp, MatroxSdpEnums

QUERY_API_KEY = "query"
NODE_API_KEY = "node"
CONNECTION_API_KEY = "connection"

FormatVideo     = "urn:x-nmos:format:video"
FormatAudio     = "urn:x-nmos:format:audio"
FormatData      = "urn:x-nmos:format:data"
FormatDataEvent = "urn:x-nmos:format:data.event"
FormatMux       = "urn:x-nmos:format:mux"
FormatUnknown   = "urn:x-nmos:format:UNKNOWN"

MuxOpaque                   = "video/MP2T"
MuxFullyDescribedMpeg2TS    = "application/MP2T"
MuxFullyDescribedGeneric    = "application/mp2t"

class MatroxSdpTest(GenericTest):
    """
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
        self.is04_resources = {"senders": {}, "receivers": {}, "_requested": [], "sources": {}, "flows": {}, "devices": {}, "self": {}}
        self.is05_resources = {"senders": [], "receivers": [], "_requested": [], "transport_types": {}, "transport_files": {}}
        self.is04_utils = IS04Utils(self.node_url)
        self.is05_utils = IS05Utils(self.connection_url)
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
            raise NMOSTestException(message)

        if resource_type == "self":
            resource = resources.json()
            self.is04_resources[resource_type][resource["id"]] = resource
            self.is04_resources["_requested"].append(resource_type)
        else:
            try:
                for resource in resources.json():
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
            raise NMOSTestException(message)

        # The following call to is05_utils.get_transporttype does not validate against the IS-05 schemas,
        # which is good fow allowing extended transport. The transporttype-response-schema.json schema is
        # broken as it does not allow additional transport, nor x-nmos ones, nor vendor spcecific ones.
        try:
            for resource in resources.json():
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
        """Confirm that a given Requests response conforms to the expected schema and has any expected headers without considering the 'transport_params' attribute"""
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
        reg_api = self.apis["schemas"]
        reg_path = reg_api["spec_path"] + "/schemas"

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
                    pre_data = json.dumps(curr_data["pre"], sort_keys=True)
                    post_data = json.dumps(curr_data["post"], sort_keys=True)

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
        except:
            return test.FAIL("Error during test 01")

        return test.PASS()

    def test_02(self, test):
        """ 
        Test thet the SDP transport file matches withthe Sender, Flow and Source
        """
        for resource_type in ["senders", "flows", "sources", "self", "devices"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"].values()}
        source_map = {source["id"]: source for source in self.is04_resources["sources"].values()}
        node_map = {node["id"]: node for node in self.is04_resources["self"].values()}
        device_map = {device["id"]: device for device in self.is04_resources["devices"].values()}

        try:
            raw_video_senders = [sender for sender in self.is04_resources["senders"].values() if sender["flow_id"]
                            and sender["flow_id"] in flow_map
                            and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:video"
                            and flow_map[sender["flow_id"]]["media_type"] == "video/raw"]

            jxsv_video_senders = [sender for sender in self.is04_resources["senders"].values() if sender["flow_id"]
                            and sender["flow_id"] in flow_map
                            and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:video"
                            and flow_map[sender["flow_id"]]["media_type"] == "video/jxsv"]

            # only process raw and jpeg-xs video senders ... H.26x do not have fmtp parameters in the SDP
            video_senders = raw_video_senders + jxsv_video_senders

            access_error = False
            sender_tested = False

            for sender in video_senders:

                flow = flow_map[sender["flow_id"]]
                source = source_map[flow["source_id"]]
                device = device_map[sender["device_id"]]
                node = node_map[device["node_id"]]

                # check transport parameters
                if not sender["transport"].startswith("urn:x-nmos:transport:rtp"):
                    return test.FAIL("Sender {} transport {} is not RTP"
                                    .format(sender["id"], sender["transport"]))

                url = "single/senders/{}/active".format(sender["id"])
                valid, response = self.is05_utils.checkCleanRequest("GET", url)
                if not valid:
                    return test.FAIL("Sender {} not responding to IS-05 request"
                                    .format(sender["id"]))

                active = response.json()

                if not active["master_enable"]:
                    return test.UNCLEAR("Sender {} not active => PLEASE ACTIVATE SENDER to TEST"
                                    .format(sender["id"]))

                # will get back to transport parameters later

                if "manifest_href" not in sender:
                    return test.FAIL("Sender {} MUST indicate the 'manifest_href' attribute."
                                     .format(sender["id"]))

                href = sender["manifest_href"]
                if not href:
                    access_error = True
                    continue

                manifest_href_valid, manifest_href_response = self.do_request("GET", href)
                if manifest_href_valid and manifest_href_response.status_code == 200:
                    pass
                elif manifest_href_valid and manifest_href_response.status_code == 404:
                    access_error = True
                    continue
                else:
                    return test.FAIL("Unexpected response from manifest_href '{}': {}"
                                     .format(href, manifest_href_response))

                sdp_text = manifest_href_response.text

                sdp = MatroxSdp()

                try:
                    sdp.decode(sdp_text)
                except Exception as e:
                    self.fail(f"Decoding {sender['id']} raised an exception: {e}")

                # Check IPMX
                if not sdp.primary_media.ipmx:
                    return test.FAIL("Sender {} SDP is not indicating IPMX"
                                     .format(sender["id"]))

                # Check width, height
                frame_width = flow["frame_width"]
                frame_height = flow["frame_height"]
                sdp_width = sdp.primary_media.width
                sdp_height = sdp.primary_media.height

                if sdp_width != frame_width or sdp_height != frame_height:
                    return test.FAIL("Sender {} Flow {} width {}, height {} mismatch with SDP width {}, height {}"
                                     .format(sender["id"], sender["flow_id"], frame_width, frame_height, sdp_width, sdp_height))

                # Check frame rate num, den
                rate_num = flow["grain_rate"]["numerator"]
                rate_den = flow["grain_rate"]["denominator"]
                sdp_rate_num = sdp.primary_media.exact_frame_rate_numerator
                sdp_rate_den = sdp.primary_media.exact_frame_rate_denominator

                if sdp_rate_num != rate_num or sdp_rate_den != rate_den:
                    return test.FAIL("Sender {} Flow {} frame rate num {}, den {} mismatch with SDP frame rate num {}, den {}"
                                     .format(sender["id"], sender["flow_id"], rate_num, rate_den, sdp_rate_num, sdp_rate_den))

                # Check component depth
                if len(flow["components"]) < 3:
                    return test.FAIL("Sender {} Flow {} components has less than 3 components"
                                     .format(sender["id"], sender["flow_id"]))

                depth0 = flow["components"][0]["bit_depth"]
                depth1 = flow["components"][1]["bit_depth"]
                depth2 = flow["components"][2]["bit_depth"]

                if depth0 != depth1 or depth0 != depth2 or depth1 != depth2:
                    return test.FAIL("Sender {} Flow {} components bit_depth not matching on all components"
                                     .format(sender["id"], sender["flow_id"]))

                if depth0 != sdp.primary_media.depth:
                    return test.FAIL("Sender {} Flow {} components bit_depth {} not matching SDP {}"
                                     .format(sender["id"], sender["flow_id"], depth0, sdp.primary_media.depth))

                try:
                    sdp_components = GetSdpSamplingAsComponents(sdp)

                    for component in flow["components"]:

                        name = component["name"]

                        if (component["width"] != sdp_components[name]["width"] or 
                            component["height"] != sdp_components[name]["height"] or 
                            component["bit_depth"] != sdp_components[name]["bit_depth"]):

                            return test.FAIL("Sender {} Flow {} component {} is not matching with SDP color sampling {}"
                                            .format(sender["id"], sender["flow_id"], component, sdp.primary_media.sampling))
                except:
                    return test.FAIL("Sender {} SDP color sampling {} is not supported or not mathing with the Flow {}"
                                     .format(sender["id"], sdp.primary_media.sampling), sender["flow_id"])

                if sdp.primary_media.measured_pix_clk == 0 or sdp.primary_media.h_total == 0 or sdp.primary_media.v_total == 0:
                    return test.FAIL("Sender {} SDP measured pixclk {} htotal {} and vtotal {} have invalid values"
                                     .format(sender["id"], sdp.primary_media.measured_pix_clk, sdp.primary_media.h_total, sdp.primary_media.v_total))

                if sdp.primary_media.media_clock_type != MatroxSdpEnums.Sender and sdp.primary_media.media_clock_type != MatroxSdpEnums.Direct:
                    return test.FAIL("Sender {} SDP media clock type has an invalid value {}"
                                     .format(sender["id"], sdp.primary_media.media_clock_type))

                # Make sure the clock matches with the Source
                clock_name = source["clock_name"]
                clock_found = False

                for clock in node["clocks"]:
                    if clock["name"] == clock_name:
                        clock_found = True
                        if clock["ref_type"] == "ptp":
                            if sdp.primary_media.ts_ref_clock_source != "ptp" or sdp.primary_media.ts_delay != 0 or sdp.primary_media.ts_ref_clock_ptp_gmid != clock["gmid"] or sdp.primary_media.ts_ref_clock_ptp_version != clock["version"]:
                                return test.FAIL("Sender {} SDP media clock: source {}, delay {}, gmid {}, version {} do not match Node clock {}"
                                                .format(sender["id"], sdp.primary_media.ts_ref_clock_source, sdp.primary_media.ts_delay, sdp.primary_media.ts_ref_clock_ptp_gmid, sdp.primary_media.ts_ref_clock_ptp_version, clock))
                        else:
                            if sdp.primary_media.ts_ref_clock_source != "localmac":
                                return test.FAIL("Sender {} SDP media clock source {} do not match Node clock {}"
                                                .format(sender["id"], sdp.primary_media.sdp.primary_media.ts_ref_clock_source, clock))

                if not clock_found:
                    return test.FAIL("Sender {} Source {} clock name {} not found in Node clocks {}"
                                    .format(sender["id"], source["id"], clock_name, node["clocks"]))

                format, unused, encoding = flow["media_type"].partition("/")

                if format != sdp.primary_media.type or encoding != sdp.primary_media.encoding_name or sdp.primary_media.clock_rate != 90000:
                    return test.FAIL("Sender {} Flow {} media type {} not matching with sdp type {}, encoding {} and rate {}"
                                    .format(sender["id"], flow["id"], flow["media_type"], sdp.primary_media.type, sdp.primary_media.encoding_name, sdp.primary_media.clock_rate))

                if active["transport_params"][0]["destination_ip"] != sdp.primary_media.connection_address or active["transport_params"][0]["destination_port"] != sdp.primary_media.port:
                    return test.FAIL("Sender {} destination address {} and port {} not matching with sdp address {} and port {}"
                                    .format(sender["id"], active["transport_params"][0]["destination_ip"], active["transport_params"][0]["destination_port"], sdp.primary_media.connection_address, sdp.primary_media.port))

                if active["transport_params"][0]["source_ip"] != sdp.primary_media.source_filter_src_address or active["transport_params"][0]["destination_ip"] != sdp.primary_media.source_filter_dst_address:
                    return test.FAIL("Sender {} source filter destination address {} and source address {} not matching with sdp destination {} and source {}"
                                    .format(sender["id"], active["transport_params"][0]["destination_ip"], active["transport_params"][0]["source_ip"], sdp.primary_media.source_filter_dst_address, sdp.primary_media.source_filter_src_address))

                if len(active["transport_params"]) != sdp.media_count:
                    return test.FAIL("Sender {} legs in transport parameters {} not matching with SDP media count {}"
                                    .format(sender["id"], len(active["transport_params"]), sdp.media_count))

            if access_error:
                return test.UNCLEAR("One or more of the tested Senders had null or empty 'manifest_href' or "
                                    "returned a 404 HTTP code. Please ensure all Senders are enabled and re-test.")

            #TODO
            if len(video_senders) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No H.264 Sender resources were found on the Node")

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


def GetSdpSamplingAsComponents(sdp : MatroxSdp):

    width = sdp.primary_media.width
    height = sdp.primary_media.height
    depth = sdp.primary_media.depth

    # The ordering of the components does not matter ... so using a map
    components = dict()

    # return an dict of components each having a name, with, height and bit_depth
    if sdp.primary_media.sampling == MatroxSdpEnums.SamplingRGB:
        r = dict(name= "R", width=width, height=height, bit_depth=depth)
        g = dict(name= "G", width=width, height=height, bit_depth=depth)
        b = dict(name= "B", width=width, height=height, bit_depth=depth)
        components[r["name"]] = r
        components[g["name"]] = g
        components[b["name"]] = b
    elif sdp.primary_media.sampling == MatroxSdpEnums.SamplingRGBA:
        r = dict(name= "R", width=width, height=height, bit_depth=depth)
        g = dict(name= "G", width=width, height=height, bit_depth=depth)
        b = dict(name= "B", width=width, height=height, bit_depth=depth)
        a = dict(name= "A", width=width, height=height, bit_depth=depth)
        components[r["name"]] = r
        components[g["name"]] = g
        components[b["name"]] = b
        components[a["name"]] = a
    elif sdp.primary_media.sampling == MatroxSdpEnums.SamplingBGR:
        r = dict(name= "R", width=width, height=height, bit_depth=depth)
        g = dict(name= "G", width=width, height=height, bit_depth=depth)
        b = dict(name= "B", width=width, height=height, bit_depth=depth)
        components[r["name"]] = r
        components[g["name"]] = g
        components[b["name"]] = b
    elif sdp.primary_media.sampling == MatroxSdpEnums.SamplingBGRA:
        r = dict(name= "R", width=width, height=height, bit_depth=depth)
        g = dict(name= "G", width=width, height=height, bit_depth=depth)
        b = dict(name= "B", width=width, height=height, bit_depth=depth)
        a = dict(name= "A", width=width, height=height, bit_depth=depth)
        components[r["name"]] = r
        components[g["name"]] = g
        components[b["name"]] = b
        components[a["name"]] = a
    elif sdp.primary_media.sampling == MatroxSdpEnums.SamplingYCbCr_444:
        y = dict(name= "Y", width=width, height=height, bit_depth=depth)
        u = dict(name= "Cb", width=width, height=height, bit_depth=depth)
        v = dict(name= "Cr", width=width, height=height, bit_depth=depth)
        components[y["name"]] = y
        components[u["name"]] = u
        components[v["name"]] = v
    elif sdp.primary_media.sampling == MatroxSdpEnums.SamplingYCbCr_422:
        y = dict(name= "Y", width=width, height=height, bit_depth=depth)
        u = dict(name= "Cb", width=width/2, height=height, bit_depth=depth)
        v = dict(name= "Cr", width=width/2, height=height, bit_depth=depth)
        components[y["name"]] = y
        components[u["name"]] = u
        components[v["name"]] = v
    elif sdp.primary_media.sampling == MatroxSdpEnums.SamplingYCbCr_420:
        y = dict(name= "Y", width=width, height=height, bit_depth=depth)
        u = dict(name= "Cb", width=width/2, height=height/2, bit_depth=depth)
        v = dict(name= "Cr", width=width/2, height=height/2, bit_depth=depth)
        components[y["name"]] = y
        components[u["name"]] = u
        components[v["name"]] = v
    elif sdp.primary_media.sampling == MatroxSdpEnums.SamplingYCbCr_411:
        y = dict(name= "Y", width=width, height=height, bit_depth=depth)
        u = dict(name= "Cb", width=width/4, height=height, bit_depth=depth)
        v = dict(name= "Cr", width=width/4, height=height, bit_depth=depth)
        components[y["name"]] = y
        components[u["name"]] = u
        components[v["name"]] = v
    # elif sdp.primary_media.sampling == SamplingCLYCbCr_444:
    # elif sdp.primary_media.sampling == SamplingCLYCbCr_422:
    # elif sdp.primary_media.sampling == SamplingCLYCbCr_420:
    elif sdp.primary_media.sampling == MatroxSdpEnums.SamplingICtCp_444:
        i = dict(name= "I", width=width, height=height, bit_depth=depth)
        t = dict(name= "Ct", width=width, height=height, bit_depth=depth)
        p = dict(name= "Cp", width=width, height=height, bit_depth=depth)
        components[i["name"]] = i
        components[t["name"]] = t
        components[p["name"]] = p
    elif sdp.primary_media.sampling == MatroxSdpEnums.SamplingICtCp_422:
        i = dict(name= "I", width=width, height=height, bit_depth=depth)
        t = dict(name= "Ct", width=width/2, height=height, bit_depth=depth)
        p = dict(name= "Cp", width=width/2, height=height, bit_depth=depth)
        components[i["name"]] = i
        components[t["name"]] = t
        components[p["name"]] = p
    elif sdp.primary_media.sampling == MatroxSdpEnums.SamplingICtCp_420:
        i = dict(name= "I", width=width, height=height, bit_depth=depth)
        t = dict(name= "Ct", width=width/2, height=height/2, bit_depth=depth)
        p = dict(name= "Cp", width=width/2, height=height/2, bit_depth=depth)
        components[i["name"]] = i
        components[t["name"]] = t
        components[p["name"]] = p
    # elif sdp.primary_media.sampling == SamplingXYZ:
    # elif sdp.primary_media.sampling == SamplingKey:
    # elif sdp.primary_media.sampling == SamplingUnspecified:
    else:
        raise ValueError(f"unsupported color sampling {sdp.primary_media.sampling}")
    
    return components