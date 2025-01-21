# Copyright 2024, Matrox Graphics Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import json
import re

from jsonschema import ValidationError

from ..GenericTest import GenericTest, NMOSTestException
from ..IS04Utils import IS04Utils
from ..IS05Utils import IS05Utils
from ..TestHelper import load_resolved_schema
from ..TestHelper import check_content_type

NODE_API_KEY = "node"
CONNECTION_API_KEY = "connection"
FLOW_REGISTER_KEY = "flow-register"
SENDER_REGISTER_KEY = "sender-register"

class MatroxH264Test(GenericTest):
    """
    Runs Node Tests covering BCP-006-02 (H.264)
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
        self.node_url = self.apis[NODE_API_KEY]["url"]
        self.connection_url = self.apis[CONNECTION_API_KEY]["url"]
        self.is04_resources = {"senders": {}, "receivers": {}, "_requested": [], "sources": {}, "flows": {}}
        self.is05_resources = {"senders": [], "receivers": [], "_requested": [], "transport_types": {}, "transport_files": {}}
        self.is04_utils = IS04Utils(self.node_url)
        self.is05_utils = IS05Utils(self.connection_url)

    # Utility function from IS0502Test
    def get_is04_resources(self, resource_type):
        """Retrieve all Senders or Receivers from a Node API, keeping hold of the returned objects"""
        assert resource_type in ["senders", "receivers", "sources", "flows"]

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

    def test_01(self, test):
        """Check that version 1.3 or greater of the Node API is available"""

        api = self.apis[NODE_API_KEY]
        if self.is04_utils.compare_api_version(api["version"], "v1.3") >= 0:
            valid, result = self.do_request("GET", self.node_url)
            if valid:
                return test.PASS()
            else:
                return test.FAIL("Node API did not respond as expected: {}".format(result))
        else:
            return test.FAIL("Node API must be running v1.3 or greater to fully implement this specification")

    def test_02(self, test):
        """H.264 Flows have the required attributes"""

        self.do_test_node_api_v1_3(test)

        reg_api = self.apis[FLOW_REGISTER_KEY]

        valid, result = self.get_is04_resources("flows")
        if not valid:
            return test.FAIL(result)

        reg_path = reg_api["spec_path"] + "/flow-attributes"
        reg_schema = load_resolved_schema(reg_path, "flow_video_register.json", path_prefix=False)

        try:
            flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"].values()}

            h264_flows = [flow for flow in self.is04_resources["flows"].values() if flow["format"] == "urn:x-nmos:format:video"
                                                                        and flow["media_type"] == "video/H264"]
            
            for mux_flow in [flow for flow in self.is04_resources["flows"].values() if flow["format"] == "urn:x-nmos:format:mux"]:
                for parent_flow in mux_flow["parents"]:
                    if flow_map[parent_flow]["format"] == "urn:x-nmos:format:video":
                        if flow_map[parent_flow]["media_type"] == "video/H264":
                            h264_flows.append(flow_map[parent_flow])

            warn_na = False
            warn_message = ""

            for flow in h264_flows:
                # check required attributes are present. constant_bit_rate is not verified because it has a
                # default value of false, making it optional.
                if "components" not in flow:
                    return test.FAIL("Flow {} MUST indicate the color (sub-)sampling using "
                                        "the 'components' attribute.".format(flow["id"]))

                if "profile" not in flow:
                    return test.FAIL("Flow {} MUST indicate the encoding profile using "
                                        "the 'profile' attribute.".format(flow["id"]))

                if "level" not in flow:
                    return test.FAIL("Flow {} MUST indicate the encoding level using "
                                        "the 'level' attribute.".format(flow["id"]))

                if "bit_rate" not in flow:
                    return test.FAIL("Flow {} MUST indicate the target bit rate of the codestream using "
                                        "the 'bit_rate' attribute.".format(flow["id"]))

                # check values of all additional attributes against the schema
                # e.g. 'components', 'profile', 'level', 'bit_rate', 'constant_bit_rate'
                try:
                    self.validate_schema(flow, reg_schema)
                except ValidationError as e:
                    return test.FAIL("Flow {} does not comply with the schema for Video Flow additional and "
                                     "extensible attributes defined in the NMOS Parameter Registers: "
                                     "{}".format(flow["id"], str(e)),
                                     "https://specs.amwa.tv/nmos-parameter-registers/branches/{}"
                                     "/flow-attributes/flow_video_register.html"
                                     .format(reg_api["spec_branch"]))

            if warn_na:
                return test.NA("Additional Flow attributes such as 'components', 'profile', 'level', 'bit_rate' are required "
                               "with 'video/H264' from IS-04 v1.3")

            if len(h264_flows) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No H.264 Flow resources were found on the Node")

    def test_03(self, test):
        """H.264 Sources have the required attributes"""

        self.do_test_node_api_v1_3(test)

        for resource_type in ["flows", "sources"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        source_map = {source["id"]: source for source in self.is04_resources["sources"].values()}
        flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"].values()}

        try:
            h264_flows = [flow for flow in self.is04_resources["flows"].values() if flow["format"] == "urn:x-nmos:format:video"
                                                                        and flow["media_type"] == "video/H264"]
            
            for mux_flow in [flow for flow in self.is04_resources["flows"].values() if flow["format"] == "urn:x-nmos:format:mux"]:
                for parent_flow in mux_flow["parents"]:
                    if flow_map[parent_flow]["format"] == "urn:x-nmos:format:video":
                        if flow_map[parent_flow]["media_type"] == "video/H264":
                            h264_flows.append(flow_map[parent_flow])

            for flow in h264_flows:
                source = source_map[flow["source_id"]]

                if source["format"] != "urn:x-nmos:format:video":
                    return test.FAIL("Source {} MUST indicate format with value 'urn:x-nmos:format:video'"
                                     .format(source["id"]))

            if len(h264_flows) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No H.264 Flow resources were found on the Node")

    def test_04(self, test):
        """H.264 Senders have the required attributes"""

        self.do_test_node_api_v1_3(test)

        reg_api = self.apis[SENDER_REGISTER_KEY]

        for resource_type in ["senders", "flows"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"].values()}

        reg_path = reg_api["spec_path"] + "/sender-attributes"
        reg_schema = load_resolved_schema(reg_path, "sender_register.json", path_prefix=False)

        try:
            # Note: indirect h264 senders do not apply here because, being mux senders they
            #       follow the rules of the mux, not H.264
            h264_senders = [sender for sender in self.is04_resources["senders"].values() if sender["flow_id"]
                            and sender["flow_id"] in flow_map
                            and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:video"
                            and flow_map[sender["flow_id"]]["media_type"] == "video/H264"]

            warn_na = False
            warn_st2110_22 = False
            warn_message = ""

            for sender in h264_senders:
                # check required attributes are present
                if "transport" not in sender:
                    return test.FAIL("Sender {} MUST indicate the 'transport' attribute."
                                     .format(sender["id"]))
                
                # check values of all additional attributes against the schema
                # e.g. 'bit_rate', 'packet_transmission_mode',  'st2110_21_sender_type', 
                # `parameter_sets_flow_mode` and `parameter_sets_transport_mode`
                try:
                    self.validate_schema(sender, reg_schema)
                except ValidationError as e:
                    return test.FAIL("Sender {} does not comply with the schema for Sender additional and "
                                     "extensible attributes defined in the NMOS Parameter Registers: "
                                     "{}".format(sender["id"], str(e)),
                                     "https://specs.amwa.tv/nmos-parameter-registers/branches/{}"
                                     "/sender-attributes/sender_register.html"
                                     .format(reg_api["spec_branch"]))

                other_video, other_mux = self.is_sender_using_other_transports(sender, flow_map)
                rfc6184 = self.is_sender_using_RTP_transport_based_on_RFC6184(sender, flow_map)

                if not (rfc6184 or other_video) or other_mux:
                    return test.FAIL("Sender {} use an invalid transport and format combination" \
                                .format(sender["id"]))
            
                if rfc6184:
                    # check recommended attributes are present
                    if "st2110_21_sender_type" not in sender:
                        if not warn_st2110_22:
                            warn_st2110_22 = True
                            warn_message += "|" + "Sender {} MUST indicate the ST 2110-21 Sender Type using " \
                                        "the 'st2110_21_sender_type' attribute if it is compliant with ST 2110-22." \
                                        .format(sender["id"])

                    # A warning is not given if the bit_rate is not provided even if the specification says "SHOULD" 
                    # because there is not such requirement in RFC6184 and it is not current practice to provide such
                    # information in all the scenarios.
                    if "st2110_21_sender_type" in sender:
                        if "bit_rate" not in sender:
                            return test.FAIL("Sender {} MUST indicate the Sender bit rate using " \
                                        "the 'bit_rate' attribute when conforming to ST 2110-22." \
                                        .format(sender["id"]))
                    if "bit_rate" in sender:
                        if flow_map[sender["flow_id"]]["bit_rate"] >= sender["bit_rate"]:
                            return test.FAIL("Sender {} MUST derive bit rate from Flow bit rate" \
                                        .format(sender["id"]))

            if warn_na:
                return test.NA("Additional Sender attributes such as 'st2110_21_sender_type' are required "
                               "with 'video/H264' from IS-04 v1.3")
            if warn_st2110_22:
                return test.WARNING(warn_message)

            if len(h264_senders) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No H.264 Sender resources were found on the Node")

    def test_05(self, test):
        """H.264 Sender manifests have the required parameters"""

        self.do_test_node_api_v1_3(test)

        for resource_type in ["senders", "flows"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"].values()}
        source_map = {source["id"]: source for source in self.is04_resources["sources"].values()}

        try:
            # Note: indirect h264 senders do not apply here because, being mux senders they
            #       follow the rules of the mux, not H.264
            h264_senders = [sender for sender in self.is04_resources["senders"].values() if sender["flow_id"]
                            and sender["flow_id"] in flow_map
                            and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:video"
                            and flow_map[sender["flow_id"]]["media_type"] == "video/H264"]

            access_error = False
            for sender in h264_senders:
                flow = flow_map[sender["flow_id"]]
                source = source_map[flow["source_id"]]

                other_video, other_mux = self.is_sender_using_other_transports(sender, flow_map)
                rfc6184 = self.is_sender_using_RTP_transport_based_on_RFC6184(sender, flow_map)

                if not (rfc6184 or other_video) or other_mux:
                    return test.FAIL("Sender {} use an invalid transport and format combination" \
                                .format(sender["id"]))

                if not rfc6184:
                    continue

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

                sdp = manifest_href_response.text

                payload_type = self.rtp_ptype(sdp)
                if not payload_type:
                    return test.FAIL("Unable to locate payload type from rtpmap in SDP file for Sender {}"
                                     .format(sender["id"]))

                sdp_lines = [sdp_line.replace("\r", "") for sdp_line in sdp.split("\n")]

                found_fmtp = False
                is_st2110_22 = False
                for sdp_line in sdp_lines:
                    fmtp = re.search(r"^a=fmtp:{} (.+)$".format(payload_type), sdp_line)
                    if not fmtp:
                        continue
                    found_fmtp = True

                    sdp_format_params = {}
                    for param in fmtp.group(1).split(";"):
                        name, _, value = param.strip().partition("=")
                        if name in ["packetization-mode", "sprop-interleaving-depth", "sprop-deint-buf-req", "sprop-init-buf-time", "sprop-max-don-diff"]:
                            try:
                                value = int(value)
                            except ValueError:
                                return test.FAIL("SDP '{}' for Sender {} is not an integer"
                                                 .format(name, sender["id"]))
                        sdp_format_params[name] = value

                    # The `profile-level-id` format-specific parameters MUST be included with the correct value unless it corresponds to the default value. "Baseline" is the default profile value and "1" is the default level value.
                    name = "profile-level-id"
                    if name not in sdp_format_params:
                        profile_level_id = "42000A"
                    else:
                        profile_level_id = sdp_format_params[name]

                    if "profile" in flow and "level" in flow:
                        if not self.check_sdp_profile_level(profile_level_id, flow["profile"], flow["level"]):
                            return test.FAIL("SDP '{}' for Sender {} does not match profile and/or level attributes in its Flow {}"
                                                .format(name, sender["id"], flow["id"]))
                    else:
                        return test.FAIL("SDP '{}' for Sender {} is present but associated profile and/or level attributes are missing in its Flow {}"
                                            .format("profile-level-id", sender["id"], flow["id"]))

                    # The `packetization-mode` format-specific parameters MUST be included with the correct value unless it corresponds to the default value.
                    name, nmos_name = "packetization-mode", "packet_transmission_mode"
                    if name not in sdp_format_params:
                        packetization_mode = 0
                    else:
                        packetization_mode = sdp_format_params[name]

                    if nmos_name not in sender:
                        packet_transmission_mode = "single_nal_unit"
                    else:
                        packet_transmission_mode = sender[nmos_name]

                    if not self.check_sdp_packetization_mode(packetization_mode, packet_transmission_mode):
                        return test.FAIL("SDP '{}' for Sender {} does not match {} in the Sender {} {}"
                                            .format(name, sender["id"], nmos_name, packetization_mode, packet_transmission_mode))

                    # The `sprop-parameter-sets` MUST always be included if the Sender `parameter_sets_transport_mode` attribute is `out_of_band`
                    name, nmos_name = "sprop-parameter-sets", "urn:x-matrox:parameter_sets_transport_mode"

                    if nmos_name in sender and sender[nmos_name] == "out_of_band":
                        if not name in sdp_format_params or sdp_format_params[name] == "":
                            return test.FAIL("SDP '{}' for Sender {} must not be empty when {} in the Sender is 'out_of_band'"
                                                .format(name, sender["id"], nmos_name))
                        if sdp_format_params[name].endswith(","):
                            return test.FAIL("SDP '{}' for Sender {} must not terminate by a comma when {} in the Sender is 'out_of_band'"
                                                .format(name, sender["id"], nmos_name))
                        
                    if nmos_name in sender and sender[nmos_name] == "in_and_out_of_band":
                        if name in sdp_format_params and not sdp_format_params[name].endswith(","):
                            return test.FAIL("SDP '{}' for Sender {} must terminate by a comma when {} in the Sender is 'int_and_out_of_band'"
                                                .format(name, sender["id"], nmos_name))

                    if not nmos_name in sender or sender[nmos_name] == "in_band":
                        if name in sdp_format_params and sdp_format_params[name] != "":
                            return test.FAIL("SDP '{}' for Sender {} must be empty when {} in the Sender is 'in_band'"
                                                .format(name, sender["id"], nmos_name))

                    # this SDP parameter is required if the Sender is compliant with ST 2110-22
                    # and, from v1.3, must correspond to the Sender attribute => alabou: the spec
                    ## dos not say so ... :(
                    name, nmos_name = "TP", "st2110_21_sender_type"
                    if name in sdp_format_params:
                        is_st2110_22 = True
                        if nmos_name in sender:
                            if sdp_format_params[name] != sender[nmos_name]:
                                return test.FAIL("SDP '{}' for Sender {} does not match {} in the Sender"
                                                 .format(name, sender["id"], nmos_name))
                        else:
                            return test.FAIL("SDP '{}' for Sender {} is present but {} is missing in the Sender"
                                             .format(name, sender["id"], nmos_name))
                    elif nmos_name in sender:
                        return test.FAIL("SDP '{}' for Sender {} is missing but must match {} in the Sender"
                                         .format(name, sender["id"], nmos_name))

                if not found_fmtp:
                    return test.FAIL("SDP for Sender {} is missing format-specific parameters".format(sender["id"]))

                # this SDP line is required if the Sender is compliant with ST 2110-22
                # and, from v1.3, must correspond to the Sender attribute
                if is_st2110_22:
                    name, nmos_name = "b=<brtype>:<brvalue>", "bit_rate"
                    found_bandwidth = False
                    for sdp_line in sdp_lines:
                        bandwidth = re.search(r"^b=(.+):(.+)$", sdp_line)
                        if not bandwidth:
                            continue
                        found_bandwidth = True

                        if bandwidth.group(1) != "AS":
                            return test.FAIL("SDP '<brtype>' for Sender {} is not 'AS'"
                                            .format(sender["id"]))

                        value = bandwidth.group(2)
                        try:
                            value = int(value)
                        except ValueError:
                            return test.FAIL("SDP '<brvalue>' for Sender {} is not an integer"
                                            .format(sender["id"]))

                        if nmos_name in sender:
                            if value != sender[nmos_name]:
                                return test.FAIL("SDP '{}' for Sender {} does not match {} in the Sender"
                                                .format(name, sender["id"], nmos_name))
                        else:
                            return test.FAIL("SDP '{}' for Sender {} is present but {} is missing in the Sender"
                                            .format(name, sender["id"], nmos_name))

                    if nmos_name in sender and not found_bandwidth:
                        return test.FAIL("SDP '{}' for Sender {} is missing but must match {} in the Sender"
                                        .format(name, sender["id"], nmos_name))

            if access_error:
                return test.UNCLEAR("One or more of the tested Senders had null or empty 'manifest_href' or "
                                    "returned a 404 HTTP code. Please ensure all Senders are enabled and re-test.")

            if len(h264_senders) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No H.264 Sender resources were found on the Node")

    def test_06(self, test):
        """H.264 Receivers have the required attributes"""

        self.do_test_node_api_v1_3(test)

        valid, result = self.get_is04_resources("receivers")
        if not valid:
            return test.FAIL(result)

        media_type_constraint = "urn:x-nmos:cap:format:media_type"

        # BCP-006-01 recommends indicating "constraints as precisely as possible".
        # BCP-006-01 lists other appropriate parameter constraints as well; all are checked in test_07.
        recommended_constraints = {
            "urn:x-nmos:cap:format:profile": "profile",
            "urn:x-nmos:cap:format:level": "level",
            "urn:x-nmos:cap:format:bit_rate": "bit rate",
            "urn:x-matrox:cap:format:constant_bit_rate": "constant bit rate",
        }

        recommended_rfc6184_constraints = {
            "urn:x-nmos:cap:transport:packet_transmission_mode": "packet transmission mode",
            "urn:x-matrox:cap:transport:parameter_sets_flow_mode": "parameter sets flow mode",
            "urn:x-matrox:cap:transport:parameter_sets_transport_mode": "parameter sets transport mode",
        }

        recommended_rfc2250_constraints = {
        }

        recommended_other_video_constraints = {
            "urn:x-matrox:cap:transport:parameter_sets_flow_mode": "parameter sets flow mode",
            "urn:x-matrox:cap:transport:parameter_sets_transport_mode": "parameter sets transport mode",
        }

        recommended_other_mux_constraints = {
        }

        try:
            h264_receivers = [receiver for receiver in self.is04_resources["receivers"].values()
                              if receiver["format"] == "urn:x-nmos:format:video"
                              and "media_types" in receiver["caps"]
                              and "video/H264" in receiver["caps"]["media_types"]]

            # A mux Receiver not having constraints sets cannot be assumed as supporting H.264
            for receiver in [receiver for receiver in self.is04_resources["receivers"].values()
                              if receiver["format"] == "urn:x-nmos:format:mux"]:
                if "constraint_sets" in receiver["caps"]:
                    for constraint_set in receiver["caps"]["constraint_sets"]:
                        if "urn:x-nmos:cap:format:media_type" in constraint_set:
                            if  "enum" in constraint_set["urn:x-nmos:cap:format:media_type"]:
                                if  "video/H264" in constraint_set["urn:x-nmos:cap:format:media_type"]["enum"]:
                                    h264_receivers.append(receiver)

            warn_message = ""

            for receiver in h264_receivers:

                # check required attributes are present
                if "transport" not in receiver:
                    return test.FAIL("Receiver {} MUST indicate the 'transport' attribute."
                                     .format(receiver["id"]))

                other_video, other_mux = self.is_receiver_using_other_transport(receiver)
                rfc6184 = self.is_receiver_using_RTP_transport_based_on_RFC6184(receiver)
                rfc2250 = self.is_receiver_using_RTP_transport_based_on_RFC2250(receiver)

                if not (rfc6184 or rfc2250 or other_video or other_mux):
                    return test.FAIL("Sender {} use an invalid transport and format combination" \
                                .format(receiver["id"]))

                if "constraint_sets" not in receiver["caps"]:
                    return test.FAIL("Receiver {} MUST indicate constraints in accordance with BCP-004-01 using "
                                     "the 'caps' attribute 'constraint_sets'.".format(receiver["id"]))

                # exclude constraint sets for other media types
                h264_constraint_sets = [constraint_set for constraint_set in receiver["caps"]["constraint_sets"]
                                        if receiver["format"] == "urn:x-nmos:format:video"
                                        and (media_type_constraint not in constraint_set
                                        or ("enum" in constraint_set[media_type_constraint]
                                            and "video/H264" in constraint_set[media_type_constraint]["enum"]))]

                for constraint_set in [constraint_set for constraint_set in receiver["caps"]["constraint_sets"] 
                                       if receiver["format"] == "urn:x-nmos:format:mux"]:
                    if media_type_constraint  in constraint_set:
                        if "enum" in constraint_set[media_type_constraint]:
                            if "video/H264" in constraint_set[media_type_constraint]["enum"]:
                                h264_constraint_sets.append(constraint_set)

                if len(h264_constraint_sets) == 0:
                    return test.FAIL("Receiver {} MUST indicate constraints in accordance with BCP-004-01 using "
                                     "the 'caps' attribute 'constraint_sets'.".format(receiver["id"]))

                # check recommended attributes are present
                for constraint_set in h264_constraint_sets:
                    for constraint, target in recommended_constraints.items():
                        if constraint not in constraint_set:
                            warn_message += "|" + "Receiver {} SHOULD indicate the supported H.264 {} using the " \
                                            "'{}' parameter constraint.".format(receiver["id"], target, constraint)

                    if rfc6184:
                        for constraint, target in recommended_rfc6184_constraints.items():
                            if constraint not in constraint_set:
                                warn_message += "|" + "Receiver {} SHOULD indicate the supported H.264 {} using the " \
                                            "'{}' parameter constraint.".format(receiver["id"], target, constraint)

                    if rfc2250:
                        for constraint, target in recommended_rfc2250_constraints.items():
                            if constraint not in constraint_set:
                                warn_message += "|" + "Receiver {} SHOULD indicate the supported H.264 {} using the " \
                                            "'{}' parameter constraint.".format(receiver["id"], target, constraint)

                    if other_video:
                        for constraint, target in recommended_other_video_constraints.items():
                            if constraint not in constraint_set:
                                warn_message += "|" + "Receiver {} SHOULD indicate the supported H.264 {} using the " \
                                            "'{}' parameter constraint.".format(receiver["id"], target, constraint)

                    if other_mux:
                        for constraint, target in recommended_other_mux_constraints.items():
                            if constraint not in constraint_set:
                                warn_message += "|" + "Receiver {} SHOULD indicate the supported H.264 {} using the " \
                                            "'{}' parameter constraint.".format(receiver["id"], target, constraint)

            if warn_message != "":
                return test.WARNING(warn_message)

            if len(h264_receivers) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No H.264 Receiver resources were found on the Node")

    def test_07(self, test):
        """H.264 Receiver parameter constraints have valid values"""

        self.do_test_node_api_v1_3(test)

        valid, result = self.get_is04_resources("receivers")
        if not valid:
            return test.FAIL(result)

        flow_reg_path = self.apis[FLOW_REGISTER_KEY]["spec_path"] + "/flow-attributes"
        base_properties = load_resolved_schema(flow_reg_path, "flow_video_base_register.json",
                                               path_prefix=False)["properties"]
        h264_properties = load_resolved_schema(flow_reg_path, "flow_video_h264_register.json",
                                               path_prefix=False)["properties"]
        sender_path = self.apis[SENDER_REGISTER_KEY]["spec_path"] + "/sender-attributes"
        sender_properties = load_resolved_schema(sender_path, "sender_register.json",
                                                 path_prefix=False)["properties"]

        media_type_constraint = "urn:x-nmos:cap:format:media_type"

        enum_constraints = {
            "urn:x-nmos:cap:format:profile": h264_properties["profile"]["enum"],
            "urn:x-nmos:cap:format:level": h264_properties["level"]["enum"],
            "urn:x-nmos:cap:format:colorspace": base_properties["colorspace"]["enum"],
            "urn:x-nmos:cap:format:transfer_characteristic": base_properties["transfer_characteristic"]["enum"],
            # sampling corresponds to Flow 'components' so there isn't a Flow schema to use
            "urn:x-nmos:cap:format:color_sampling": [
                # Red-Green-Blue-Alpha
                "RGBA",
                # Red-Green-Blue
                "RGB",
                # Non-constant luminance YCbCr
                "YCbCr-4:4:4",
                "YCbCr-4:2:2",
                "YCbCr-4:2:0",
                "YCbCr-4:1:1",
                # Constant luminance YCbCr
                "CLYCbCr-4:4:4",
                "CLYCbCr-4:2:2",
                "CLYCbCr-4:2:0",
                # Constant intensity ICtCp
                "ICtCp-4:4:4",
                "ICtCp-4:2:2",
                "ICtCp-4:2:0",
                # XYZ
                "XYZ",
                # Key signal represented as a single component
                "KEY",
                # Sampling signaled by the payload
                "UNSPECIFIED"
            ],
            "urn:x-nmos:cap:transport:packet_transmission_mode": sender_properties["packet_transmission_mode"]["anyOf"][1]["enum"], # H.264 second entry
            "urn:x-nmos:cap:transport:st2110_21_sender_type": sender_properties["st2110_21_sender_type"]["enum"],
            "urn:x-matrox:cap:format:constant_bit_rate": h264_properties["urn:x-matrox:constant_bit_rate"]["enum"],
            "urn:x-matrox:cap:transport:parameter_sets_flow_mode": sender_properties["urn:x-matrox:parameter_sets_flow_mode"]["enum"],
            "urn:x-matrox:cap:transport:parameter_sets_transport_mode": sender_properties["urn:x-matrox:parameter_sets_transport_mode"]["enum"],
        }

        try:
            h264_receivers = [receiver for receiver in self.is04_resources["receivers"].values()
                              if receiver["format"] == "urn:x-nmos:format:video"
                              and "media_types" in receiver["caps"]
                              and "video/H264" in receiver["caps"]["media_types"]]

            # A mux Receiver not having constraints sets cannot be assumed as supporting H.264
            for receiver in [receiver for receiver in self.is04_resources["receivers"].values()
                              if receiver["format"] == "urn:x-nmos:format:mux"]:
                if "constraint_sets" in receiver["caps"]:
                    for constraint_set in receiver["caps"]["constraint_sets"]:
                        if "urn:x-nmos:cap:format:media_type" in constraint_set:
                            if  "enum" in constraint_set["urn:x-nmos:cap:format:media_type"]:
                                if  "video/H264" in constraint_set["urn:x-nmos:cap:format:media_type"]["enum"]:
                                    h264_receivers.append(receiver)

            for receiver in h264_receivers:

                other_video, other_mux = self.is_receiver_using_other_transport(receiver)
                rfc6184 = self.is_receiver_using_RTP_transport_based_on_RFC6184(receiver)
                rfc2250 = self.is_receiver_using_RTP_transport_based_on_RFC2250(receiver)

                if not (rfc6184 or rfc2250 or other_video or other_mux):
                    return test.FAIL("Sender {} use an invalid transport and format combination" \
                                .format(receiver["id"]))

                # check required attributes are present
                if "constraint_sets" not in receiver["caps"]:
                    return test.FAIL("Receiver {} MUST indicate constraints in accordance with BCP-004-01 using "
                                     "the 'caps' attribute 'constraint_sets'.".format(receiver["id"]))

                # exclude constraint sets for other media types
                h264_constraint_sets = [constraint_set for constraint_set in receiver["caps"]["constraint_sets"]
                                        if receiver["format"] == "urn:x-nmos:format:video"
                                        and (media_type_constraint not in constraint_set
                                        or ("enum" in constraint_set[media_type_constraint]
                                            and "video/H264" in constraint_set[media_type_constraint]["enum"]))]

                for constraint_set in [constraint_set for constraint_set in receiver["caps"]["constraint_sets"] 
                                       if receiver["format"] == "urn:x-nmos:format:mux"]:
                    if media_type_constraint  in constraint_set:
                        if "enum" in constraint_set[media_type_constraint]:
                            if "video/H264" in constraint_set[media_type_constraint]["enum"]:
                                h264_constraint_sets.append(constraint_set)

                if len(h264_constraint_sets) == 0:
                    return test.FAIL("Receiver {} MUST indicate constraints in accordance with BCP-004-01 using "
                                     "the 'caps' attribute 'constraint_sets'.".format(receiver["id"]))

                # check recommended attributes are present
                for constraint_set in h264_constraint_sets:
                    for constraint, enum_values in enum_constraints.items():
                        if constraint in constraint_set and "enum" in constraint_set[constraint]:
                            for enum_value in constraint_set[constraint]["enum"]:
                                if enum_value not in enum_values:
                                    return test.FAIL("Receiver {} uses an invalid value for '{}': {}"
                                                     .format(receiver["id"], constraint, enum_value))
                                
                            if (rfc2250 or other_mux) and constraint == "urn:x-matrox:cap:transport:parameter_sets_flow_mode":
                                if not "dynamic" in constraint_set[constraint]["enum"]:
                                    return test.FAIL("Receiver {} must support 'dynamic' or be unconstrained '{}': {}"
                                                     .format(receiver["id"], constraint, constraint_set[constraint]["enum"]))
            
                            if (rfc2250 or other_mux) and constraint == "urn:x-matrox:cap:transport:parameter_sets_transport_mode":
                                if not "in_band" in constraint_set[constraint]["enum"]:
                                    return test.FAIL("Receiver {} must support 'in_band' or be unconstrained '{}': {}"
                                                     .format(receiver["id"], constraint, constraint_set[constraint]["enum"]))

            if len(h264_receivers) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No H.264 Receiver resources were found on the Node")

    # Utility function from IS0502Test
    def exactframerate(self, grain_rate):
        """Format an NMOS grain rate like the SDP video format-specific parameter 'exactframerate'"""
        d = grain_rate.get("denominator", 1)
        if d == 1:
            return "{}".format(grain_rate.get("numerator"))
        else:
            return "{}/{}".format(grain_rate.get("numerator"), d)

    # Utility function from IS0502Test
    def rtp_ptype(self, sdp_file):
        """Extract the payload type from an SDP file string"""
        payload_type = None
        for sdp_line in sdp_file.split("\n"):
            sdp_line = sdp_line.replace("\r", "")
            try:
                payload_type = int(re.search(r"^a=rtpmap:(\d+) ", sdp_line).group(1))
            except Exception:
                pass
        return payload_type

    # Utility function from IS0502Test
    def check_sampling(self, flow_components, flow_width, flow_height, sampling):
        """Check SDP video format-specific parameter 'sampling' matches Flow 'components'"""
        # SDP sampling should be like:
        # "RGBA", "RGB", "YCbCr-J:a:b", "CLYCbCr-J:a:b", "ICtCp-J:a:b", "XYZ", "KEY"
        components, _, sampling = sampling.partition("-")

        # Flow component names should be like:
        # "R", "G", "B", "A", "Y", "Cb", "Cr", "Yc", "Cbc", "Crc", "I", "Ct", "Cp", "X", "Z", "Key"
        if components == "CLYCbCr":
            components = "YcCbcCrc"
        if components == "KEY":
            components = "Key"

        sampler = None
        if not sampling or sampling == "4:4:4":
            sampler = (1, 1)
        elif sampling == "4:2:2":
            sampler = (2, 1)
        elif sampling == "4:2:0":
            sampler = (2, 2)
        elif sampling == "4:1:1":
            sampler = (4, 1)

        for component in flow_components:
            if component["name"] not in components:
                return False
            components = components.replace(component["name"], "")
            # subsampled components are "Cb", "Cr", "Cbc", "Crc", "Ct", "Cp"
            c = component["name"].startswith("C")
            if component["width"] != flow_width / (sampler[0] if c else 1) or \
                    component["height"] != flow_height / (sampler[1] if c else 1):
                return False

        return components == ""

    def do_test_node_api_v1_3(self, test):
        """
        Precondition check of the API version.
        Raises an NMOSTestException when the Node API version is less than v1.3
        """
        api = self.apis[NODE_API_KEY]
        if self.is04_utils.compare_api_version(api["version"], "v1.3") < 0:
            raise NMOSTestException(test.NA("This test cannot be run against Node API below version v1.3."))

    def is_sender_using_other_transports(self, sender, flow_map):
        if not sender["transport"] in {"urn:x-nmos:transport:rtp",
                                    "urn:x-nmos:transport:rtp.ucast",
                                    "urn:x-nmos:transport:rtp.mcast"}:
            if flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:video":
                return True, False
            if flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:mux":
                return False,  True
        return False, False

    def is_sender_using_RTP_transport_based_on_RFC6184(self, sender, flow_map):
        if sender["transport"] in {"urn:x-nmos:transport:rtp",
                                    "urn:x-nmos:transport:rtp.ucast",
                                    "urn:x-nmos:transport:rtp.mcast"}:
            if flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:video":
                return True
        return False

    def is_sender_using_RTP_transport_based_on_RFC2250(self, sender, flow_map):
        if sender["transport"] in {"urn:x-nmos:transport:rtp",
                                         "urn:x-nmos:transport:rtp.ucast",
                                        "urn:x-nmos:transport:rtp.mcast"}:
            if flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:mux":
                return True
        return False

    def is_receiver_using_other_transport(self, receiver):
        if not receiver["transport"] in {"urn:x-nmos:transport:rtp",
                                    "urn:x-nmos:transport:rtp.ucast",
                                    "urn:x-nmos:transport:rtp.mcast"}:
            if receiver["format"] == "urn:x-nmos:format:video":
                return True, False
            if receiver["format"] == "urn:x-nmos:format:mux":
                return False, True
        return False, False

    def is_receiver_using_RTP_transport_based_on_RFC6184(self, receiver):
        if receiver["transport"] in {"urn:x-nmos:transport:rtp",
                                    "urn:x-nmos:transport:rtp.ucast",
                                    "urn:x-nmos:transport:rtp.mcast"}:
            if receiver["format"] == "urn:x-nmos:format:video":
                return True
        return False
    
    def is_receiver_using_RTP_transport_based_on_RFC2250(self, receiver):
        if receiver["transport"] in {"urn:x-nmos:transport:rtp",
                                         "urn:x-nmos:transport:rtp.ucast",
                                        "urn:x-nmos:transport:rtp.mcast"}:
            if receiver["format"] == "urn:x-nmos:format:mux":
                return True
        return False

    def check_sdp_profile_level(self, profile_level_id, profile, level):
        sdp_profile, sdp_level = getH264ProfileLevelFromSdp(profile_level_id)
        if sdp_profile != profile or sdp_level != level:
            return False
        return True
    
    def check_sdp_packetization_mode(self, packetization_mode, packet_transmission_mode):
        if packet_transmission_mode == "single_nal_unit" and packetization_mode == 0:
            return True
        if packet_transmission_mode == "non_interleaved_nal_units" and packetization_mode == 1:
            return True
        if packet_transmission_mode == "interleaved_nal_units" and packetization_mode == 2:
            return True
        
        return False

# (profile, level)
def getH264ProfileLevelFromSdp(profile_level_id):

    value = int(profile_level_id, 16)

    profile_idc = ((value >> 16) & 255)
    profile_iop = ((value >> 8) & 255) # 0x80(set0), 0x40(set1), 0x2(set2)0, 0x10(set3), 0x08(set4), 0x04(set5)
    level_idc = (value & 255)

    if level_idc == 9:
        level = "1b"
    elif level_idc ==  10:
        level = "1"
    elif level_idc ==  11:
        if profile_idc == 0x42 or profile_idc == 0x4d or profile_idc == 0x58:
            level = "1b"
        else:
            level = "1.1"
    elif level_idc ==  12:
        level = "1.2"
    elif level_idc ==  13:
        level = "1.3"
    elif level_idc ==  20:
        level = "2"
    elif level_idc ==  21:
        level = "2.1"
    elif level_idc ==  22:
        level = "2.2"
    elif level_idc ==  30:
        level = "3"
    elif level_idc ==  31:
        level = "3.1"
    elif level_idc ==  32:
        level = "3.2"
    elif level_idc ==  40:
        level = "4"
    elif level_idc ==  41:
        level = "4.1"
    elif level_idc ==  42:
        level = "4.2"
    elif level_idc ==  50:
        level = "5"
    elif level_idc ==  51:
        level = "5.1"
    elif level_idc ==  52:
        level = "5.2"
    elif level_idc ==  60:
        level = "6"
    elif level_idc ==  61:
        level = "6.1"
    elif level_idc ==  62:
        level = "6.2"
    else:
        level = ""

    if profile_idc == 0x42:
        if profile_iop == 0x40:
            profile = "BaselineConstrained"
        else:
            profile = "Baseline"
    elif profile_idc ==  0x4d:
        profile = "Main"
    elif profile_idc ==  0x58:
        profile = "Extended"
    elif profile_idc ==  0x64:
        if profile_iop == 0:
            profile = "High"
        elif profile_iop == 0x08:
            profile = "HighProgressive"
        elif profile_iop == (0x08 | 0x04):
            profile = "HighConstrained"
        else:
            return "", ""
    elif profile_idc ==  0x6e:
        if profile_iop == 0:
            profile = "High10"
        elif profile_iop == 0x08:
            profile = "High10Progressive"
        elif profile_iop == 0x10:
            profile = "High10Intra"
        else:
            return "", ""
    elif profile_idc ==  0x7a:
        if profile_iop == 0:
            profile = "High-422"
        elif profile_iop == 0x10:
            profile = "HighIntra-422"
        else:
            return "", ""
    elif profile_idc ==  0xf4:
        if profile_iop == 0:
            profile = "HighPredictive-444"
        elif profile_iop == 0x10:
            profile = "HighIntra-444"
        else:
            return "", ""
    elif profile_idc ==  0x2c:
        profile = "CAVLCIntra-444"
    else:
        return "", ""

    return profile, level

# Copyright (C) 2023 Advanced Media Workflow Association
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

