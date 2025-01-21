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

AacProfileMain                      = "Main"
AacProfileSpeech                    = "Speech"
AacProfileSynthetic                 = "Synthetic"
AacProfileScalable                  = "Scalable"
AacProfileProfileMain               = "Main"
AacProfileHighQuality               = "HighQuality"
AacProfileLowDelay                  = "LowDelay"
AacProfileNatural                   = "Natural"
AacProfileMobile                    = "Mobile"
AacProfileAAC                       = "AAC"
AacProfileHighEfficiencyAAC         = "HighEfficiencyAAC"
AacProfileHighEfficiencyAACv2       = "HighEfficiencyAACv2"
AacProfileLowDelayAAC               = "LowDelayAAC"
AacProfileLowDelayAACv2             = "LowDelayAACv2"
AacProfileExtendedHighEfficiencyAAC = "ExtendedHighEfficiencyAAC"

AacCodecLevel1   = "1"
AacCodecLevel2   = "2"
AacCodecLevel3   = "3"
AacCodecLevel4   = "4"
AacCodecLevel5   = "5"
AacCodecLevel6   = "6"
AacCodecLevel7   = "7"
AacCodecLevel8   = "8"

class MatroxAacTest(GenericTest):
    """
    Runs Node Tests covering (AAC)
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
        """AAC Flows have the required attributes"""

        self.do_test_node_api_v1_3(test)

        reg_api = self.apis[FLOW_REGISTER_KEY]

        valid, result = self.get_is04_resources("flows")
        if not valid:
            return test.FAIL(result)

        reg_path = reg_api["spec_path"] + "/flow-attributes"
        reg_schema = load_resolved_schema(reg_path, "flow_audio_register.json", path_prefix=False)

        try:
            flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"].values()}

            aac_flows = [flow for flow in self.is04_resources["flows"].values() if flow["format"] == "urn:x-nmos:format:audio"
                    and (flow["media_type"] == "audio/mpeg4-generic" or flow["media_type"] == "audio/MP4A-LATM" or flow["media_type"] == "audio/MP4A-ADTS")]
            
            for mux_flow in [flow for flow in self.is04_resources["flows"].values() if flow["format"] == "urn:x-nmos:format:mux"]:
                for parent_flow in mux_flow["parents"]:
                    if flow_map[parent_flow]["format"] == "urn:x-nmos:format:audio":
                        if flow_map[parent_flow]["media_type"] == "audio/mpeg4-generic" or flow_map[parent_flow]["media_type"] == "audio/MP4A-LATM" or flow_map[parent_flow]["media_type"] == "audio/MP4A-ADTS":
                            aac_flows.append(flow_map[parent_flow])

            warn_na = False
            warn_message = ""

            for flow in aac_flows:
                # check required attributes are present. constant_bit_rate is not verified because it has a
                # default value of false, making it optional.
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
                # e.g. 'profile', 'level', 'bit_rate', 'constant_bit_rate'
                try:
                    self.validate_schema(flow, reg_schema)
                except ValidationError as e:
                    return test.FAIL("Flow {} does not comply with the schema for Audio Flow additional and "
                                     "extensible attributes defined in the NMOS Parameter Registers: "
                                     "{}".format(flow["id"], str(e)),
                                     "https://specs.amwa.tv/nmos-parameter-registers/branches/{}"
                                     "/flow-attributes/flow_audio_register.html"
                                     .format(reg_api["spec_branch"]))

            if warn_na:
                return test.NA("Additional Flow attributes such as 'profile', 'level', 'bit_rate' are required "
                               "with AAC audio from IS-04 v1.3")

            if len(aac_flows) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No AAC Flow resources were found on the Node")

    def test_03(self, test):
        """AAC Sources have the required attributes"""

        self.do_test_node_api_v1_3(test)

        for resource_type in ["flows", "sources"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        source_map = {source["id"]: source for source in self.is04_resources["sources"].values()}
        flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"].values()}

        try:
            aac_flows = [flow for flow in self.is04_resources["flows"].values() if flow["format"] == "urn:x-nmos:format:Audio"
                            and (flow["media_type"] == "audio/mpeg4-generic" or flow["media_type"] == "audio/MP4A-LATM" or flow["media_type"] == "audio/MP4A-ADTS")]
            
            for mux_flow in [flow for flow in self.is04_resources["flows"].values() if flow["format"] == "urn:x-nmos:format:mux"]:
                for parent_flow in mux_flow["parents"]:
                    if flow_map[parent_flow]["format"] == "urn:x-nmos:format:audio":
                        if flow_map[parent_flow]["media_type"] == "audio/mpeg4-generic" or flow_map[parent_flow]["media_type"] == "audio/MP4A-LATM" or flow_map[parent_flow]["media_type"] == "audio/MP4A-ADTS":
                            aac_flows.append(flow_map[parent_flow])

            for flow in aac_flows:
                source = source_map[flow["source_id"]]

                if source["format"] != "urn:x-nmos:format:audio":
                    return test.FAIL("Source {} MUST indicate format with value 'urn:x-nmos:format:audio'"
                                     .format(source["id"]))

            if len(aac_flows) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No AAC Flow resources were found on the Node")

    def test_04(self, test):
        """AAC Senders have the required attributes"""

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
            # Note: indirect aac senders do not apply here because, being mux senders they
            #       follow the rules of the mux, not AAC
            aac_senders = [sender for sender in self.is04_resources["senders"].values() if sender["flow_id"]
                            and sender["flow_id"] in flow_map
                            and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:audio"
                            and (flow_map[sender["flow_id"]]["media_type"] == "audio/mpeg4-generic" or flow_map[sender["flow_id"]]["media_type"] == "audio/MP4A-LATM" or flow_map[sender["flow_id"]]["media_type"] == "audio/MP4A-ADTS")]

            warn_message = ""

            for sender in aac_senders:
                # check required attributes are present
                if "transport" not in sender:
                    return test.FAIL("Sender {} MUST indicate the 'transport' attribute."
                                     .format(sender["id"]))
                
                # check values of all additional attributes against the schema
                # e.g. 'bit_rate', 'packet_transmission_mode',   
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

                other_audio, other_mux = self.is_sender_using_other_transports(sender, flow_map)
                rfc6416 = self.is_sender_using_RTP_transport_based_on_RFC6416(sender, flow_map)
                rfc3640 = self.is_sender_using_RTP_transport_based_on_RFC3640(sender, flow_map)

                if not (rfc6416 or rfc3640 or other_audio) or other_mux:
                    return test.FAIL("Sender {} use an invalid transport and format combination" \
                                .format(sender["id"]))
            
                if rfc6416 or rfc3640:
                    # check recommended attributes are present

                    # A warning is not given if the bit_rate is not provided even if the specification says "SHOULD" 
                    # because there is not such requirement in RFC6184 and it is not current practice to provide such
                    # information in all the scenarios.
                    if "bit_rate" in sender:
                        if flow_map[sender["flow_id"]]["bit_rate"] >= sender["bit_rate"]:
                            return test.FAIL("Sender {} MUST derive bit rate from Flow bit rate" \
                                        .format(sender["id"]))

            if len(aac_senders) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No AAC Sender resources were found on the Node")

    def test_05(self, test):
        """AAC Sender manifests have the required parameters"""

        self.do_test_node_api_v1_3(test)

        for resource_type in ["senders", "flows", "sources"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"].values()}
        source_map = {source["id"]: source for source in self.is04_resources["sources"].values()}

        try:
            # Note: indirect aac senders do not apply here because, being mux senders they
            #       follow the rules of the mux, not AAC
            aac_senders = [sender for sender in self.is04_resources["senders"].values() if sender["flow_id"]
                            and sender["flow_id"] in flow_map
                            and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:audio"
                            and (flow_map[sender["flow_id"]]["media_type"] == "audio/mpeg4-generic" or flow_map[sender["flow_id"]]["media_type"] == "audio/MP4A-LATM" or flow_map[sender["flow_id"]]["media_type"] == "audio/MP4A-ADTS")]

            access_error = False
            for sender in aac_senders:
                flow = flow_map[sender["flow_id"]]
                source = source_map[flow["source_id"]]

                other_audio, other_mux = self.is_sender_using_other_transports(sender, flow_map)
                rfc6416 = self.is_sender_using_RTP_transport_based_on_RFC6416(sender, flow_map)
                rfc3640 = self.is_sender_using_RTP_transport_based_on_RFC3640(sender, flow_map)

                if not (rfc6416 or rfc3640 or other_audio) or other_mux:
                    return test.FAIL("Sender {} use an invalid transport and format combination" \
                                .format(sender["id"]))

                if not rfc6416 and not rfc3640:
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
                for sdp_line in sdp_lines:
                    fmtp = re.search(r"^a=fmtp:{} (.+)$".format(payload_type), sdp_line)
                    if not fmtp:
                        continue
                    found_fmtp = True

                    sdp_format_params = {}
                    for param in fmtp.group(1).split(";"):
                        name, _, value = param.strip().partition("=")
                        if name in ["profile-level-id", "streamType", "maxDisplacement", "constantDuration", "de-interleaveBufferSize", "constantDuration", "ptime", "sizeLength", "indexLength", "indexDeltaLength"]:
                            try:
                                value = int(value)
                            except ValueError:
                                return test.FAIL("SDP '{}' for Sender {} is not an integer"
                                                 .format(name, sender["id"]))
                        sdp_format_params[name] = value

                    # The `profile-level-id` format-specific parameters MUST be included with the correct value.
                    name = "profile-level-id"
                    if name not in sdp_format_params:
                        return test.FAIL("SDP 'profile-level-id' for Sender {} is not present".format(sender["id"]))
                    else:
                        profile_level_id = sdp_format_params[name]

                    if "profile" in flow and "level" in flow:
                        if not self.check_sdp_profile_level(profile_level_id, flow["profile"], flow["level"]):
                            return test.FAIL("SDP '{}' for Sender {} does not match profile and/or level attributes in its Flow {}"
                                                .format(name, sender["id"], flow["id"]))
                    else:
                        return test.FAIL("SDP '{}' for Sender {} is present but associated profile and/or level attributes are missing in its Flow {}"
                                            .format("profile-level-id", sender["id"], flow["id"]))

                    # The `config` format-specific parameter MUST always be included if the Sender `parameter_sets_transport_mode` property is `out_of_band`. The hexadecimal value of the "config" parameter is the AudioSpecificConfig(), as defined in ISO/IEC 14496-3. Ex config=AB8902. To explicitly indicate that `parameter_sets_transport_mode` property is `in_band` the value "" MUST be used with RFC 3640. Ex config=""
                    name, nmos_name = "config", "urn:x-matrox:parameter_sets_transport_mode"

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
                        if rfc3640 and (not name in sdp_format_params or sdp_format_params[name] != ""):
                            return test.FAIL("SDP '{}' for Sender {} must be present and empty when {} in the Sender is 'in_band'"
                                                .format(name, sender["id"], nmos_name))

                    name = "mode"
                    if rfc3640 and (not name in sdp_format_params or sdp_format_params[name] != "AAC-hbr"):
                        return test.FAIL("SDP '{}' for Sender {} must be 'AAC-hbr' with RFC3640"
                                            .format(name, sender["id"]))

                    name = "streamType"
                    if rfc3640 and (not name in sdp_format_params or sdp_format_params[name] != 5): # 5: "audio"
                        return test.FAIL("SDP '{}' for Sender {} must be 'audio' with RFC3640"
                                            .format(name, sender["id"]))

                    name = "constantDuration"
                    if rfc3640 and (not name in sdp_format_params):
                        return test.FAIL("SDP '{}' for Sender {} must be present with RFC3640"
                                            .format(name, sender["id"]))

                    name = "sizeLength"
                    if rfc3640 and (not name in sdp_format_params or sdp_format_params[name] != 13):
                        return test.FAIL("SDP '{}' for Sender {} must be '13' with RFC3640"
                                            .format(name, sender["id"]))

                    name = "indexLength"
                    if rfc3640 and (not name in sdp_format_params or sdp_format_params[name] != 3):
                        return test.FAIL("SDP '{}' for Sender {} must be '13' with RFC3640"
                                            .format(name, sender["id"]))
                    
                    name = "indexDeltaLength"
                    if rfc3640 and (not name in sdp_format_params or sdp_format_params[name] != 3):
                        return test.FAIL("SDP '{}' for Sender {} must be '13' with RFC3640"
                                            .format(name, sender["id"]))                    
                    name = "ptime"
                    if rfc6416 and (not name in sdp_format_params):
                        return test.FAIL("SDP '{}' for Sender {} must be present with RFC6416"
                                            .format(name, sender["id"]))

                if not found_fmtp:
                    return test.FAIL("SDP for Sender {} is missing format-specific parameters".format(sender["id"]))

            if access_error:
                return test.UNCLEAR("One or more of the tested Senders had null or empty 'manifest_href' or "
                                    "returned a 404 HTTP code. Please ensure all Senders are enabled and re-test.")

            if len(aac_senders) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No AAC Sender resources were found on the Node")

    def test_06(self, test):
        """AAC Receivers have the required attributes"""

        self.do_test_node_api_v1_3(test)

        valid, result = self.get_is04_resources("receivers")
        if not valid:
            return test.FAIL(result)

        media_type_constraint = "urn:x-nmos:cap:format:media_type"

        # BCP-006-?? recommends indicating "constraints as precisely as possible".
        # BCP-006-?? lists other appropriate parameter constraints as well; all are checked in test_07.
        recommended_constraints = {
            "urn:x-nmos:cap:format:profile": "profile",
            "urn:x-nmos:cap:format:level": "level",
            "urn:x-nmos:cap:format:bit_rate": "bit rate",
            "urn:x-matrox:cap:format:constant_bit_rate": "constant bit rate",
        }

        recommended_rfc6416_constraints = {
            "urn:x-nmos:cap:transport:packet_transmission_mode": "packet transmission mode",
            "urn:x-matrox:cap:transport:parameter_sets_flow_mode": "parameter sets flow mode",
            "urn:x-matrox:cap:transport:parameter_sets_transport_mode": "parameter sets transport mode",
        }

        recommended_rfc3640_constraints = {
            "urn:x-nmos:cap:transport:packet_transmission_mode": "packet transmission mode",
            "urn:x-matrox:cap:transport:parameter_sets_flow_mode": "parameter sets flow mode",
            "urn:x-matrox:cap:transport:parameter_sets_transport_mode": "parameter sets transport mode",
        }

        recommended_rfc2250_constraints = {
        }

        recommended_other_audioconstraints = {
            "urn:x-matrox:cap:transport:parameter_sets_flow_mode": "parameter sets flow mode",
            "urn:x-matrox:cap:transport:parameter_sets_transport_mode": "parameter sets transport mode",
        }

        recommended_other_mux_constraints = {
        }

        try:
            aac_receivers = [receiver for receiver in self.is04_resources["receivers"].values()
                              if receiver["format"] == "urn:x-nmos:format:audio"
                              and "media_types" in receiver["caps"]
                              and("audio/mpeg4-generic" in receiver["caps"]["media_types"] or "audio/MP4A-LATM" in receiver["caps"]["media_types"] or "audio/MP4A-ADTS" in receiver["caps"]["media_types"])]

            # A mux Receiver not having constraints sets cannot be assumed as supporting AAC
            for receiver in [receiver for receiver in self.is04_resources["receivers"].values()
                              if receiver["format"] == "urn:x-nmos:format:mux"]:
                if "constraint_sets" in receiver["caps"]:
                    for constraint_set in receiver["caps"]["constraint_sets"]:
                        if "urn:x-nmos:cap:format:media_type" in constraint_set:
                            if  "enum" in constraint_set["urn:x-nmos:cap:format:media_type"]:
                                if  "audio/mpeg4-generic" in constraint_set["urn:x-nmos:cap:format:media_type"]["enum"] or "audio/MP4A-LATM" in constraint_set["urn:x-nmos:cap:format:media_type"]["enum"] or "audio/MP4A-ADTS" in constraint_set["urn:x-nmos:cap:format:media_type"]["enum"]:
                                    aac_receivers.append(receiver)

            warn_message = ""

            for receiver in aac_receivers:

                # check required attributes are present
                if "transport" not in receiver:
                    return test.FAIL("Receiver {} MUST indicate the 'transport' attribute."
                                     .format(receiver["id"]))

                other_audio, other_mux = self.is_receiver_using_other_transport(receiver)
                rfc6416 = self.is_receiver_using_RTP_transport_based_on_RFC6416(receiver)
                rfc3640 = self.is_receiver_using_RTP_transport_based_on_RFC3640(receiver)
                rfc2250 = self.is_receiver_using_RTP_transport_based_on_RFC2250(receiver)

                if not (rfc6416 or rfc3640 or rfc2250 or other_audio or other_mux):
                    return test.FAIL("Sender {} use an invalid transport and format combination" \
                                .format(receiver["id"]))

                if "constraint_sets" not in receiver["caps"]:
                    return test.FAIL("Receiver {} MUST indicate constraints in accordance with BCP-004-?? using "
                                     "the 'caps' attribute 'constraint_sets'.".format(receiver["id"]))

                # exclude constraint sets for other media types
                aac_constraint_sets = [constraint_set for constraint_set in receiver["caps"]["constraint_sets"]
                                        if receiver["format"] == "urn:x-nmos:format:audio"
                                        and (media_type_constraint not in constraint_set
                                        or ("enum" in constraint_set[media_type_constraint]
                                            and ("audio/mpeg4-generic" in constraint_set[media_type_constraint]["enum"] or "audio/MP4A-LATM" in constraint_set[media_type_constraint]["enum"] or "audio/MP4A-ADTS" in constraint_set[media_type_constraint]["enum"])))]

                for constraint_set in [constraint_set for constraint_set in receiver["caps"]["constraint_sets"] 
                                       if receiver["format"] == "urn:x-nmos:format:mux"]:
                    if media_type_constraint  in constraint_set:
                        if "enum" in constraint_set[media_type_constraint]:
                            if ("audio/mpeg4-generic" in constraint_set[media_type_constraint]["enum"] or "audio/MP4A-LATM" in constraint_set[media_type_constraint]["enum"] or "audio/MP4A-ADTS" in constraint_set[media_type_constraint]["enum"]):
                                aac_constraint_sets.append(constraint_set)

                if len(aac_constraint_sets) == 0:
                    return test.FAIL("Receiver {} MUST indicate constraints in accordance with BCP-004-?? using "
                                     "the 'caps' attribute 'constraint_sets'.".format(receiver["id"]))

                # check recommended attributes are present
                for constraint_set in aac_constraint_sets:
                    for constraint, target in recommended_constraints.items():
                        if constraint not in constraint_set:
                            warn_message += "|" + "Receiver {} SHOULD indicate the supported AAC {} using the " \
                                            "'{}' parameter constraint.".format(receiver["id"], target, constraint)

                    if rfc6416:
                        for constraint, target in recommended_rfc6416_constraints.items():
                            if constraint not in constraint_set:
                                warn_message += "|" + "Receiver {} SHOULD indicate the supported AAC {} using the " \
                                            "'{}' parameter constraint.".format(receiver["id"], target, constraint)

                    if rfc3640:
                        for constraint, target in recommended_rfc3640_constraints.items():
                            if constraint not in constraint_set:
                                warn_message += "|" + "Receiver {} SHOULD indicate the supported AAC {} using the " \
                                            "'{}' parameter constraint.".format(receiver["id"], target, constraint)

                    if rfc2250:
                        for constraint, target in recommended_rfc2250_constraints.items():
                            if constraint not in constraint_set:
                                warn_message += "|" + "Receiver {} SHOULD indicate the supported AAC {} using the " \
                                            "'{}' parameter constraint.".format(receiver["id"], target, constraint)

                    if other_audio:
                        for constraint, target in recommended_other_audio_constraints.items():
                            if constraint not in constraint_set:
                                warn_message += "|" + "Receiver {} SHOULD indicate the supported AAC {} using the " \
                                            "'{}' parameter constraint.".format(receiver["id"], target, constraint)

                    if other_mux:
                        for constraint, target in recommended_other_mux_constraints.items():
                            if constraint not in constraint_set:
                                warn_message += "|" + "Receiver {} SHOULD indicate the supported AAC {} using the " \
                                            "'{}' parameter constraint.".format(receiver["id"], target, constraint)

            if warn_message != "":
                return test.WARNING(warn_message)

            if len(aac_receivers) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No AAC Receiver resources were found on the Node")

    def test_07(self, test):
        """AAC Receiver parameter constraints have valid values"""

        self.do_test_node_api_v1_3(test)

        valid, result = self.get_is04_resources("receivers")
        if not valid:
            return test.FAIL(result)

        flow_reg_path = self.apis[FLOW_REGISTER_KEY]["spec_path"] + "/flow-attributes"
        base_properties = load_resolved_schema(flow_reg_path, "flow_audio_base_register.json",
                                               path_prefix=False)["properties"]
        aac_properties = load_resolved_schema(flow_reg_path, "flow_audio_aac_register.json",
                                               path_prefix=False)["properties"]
        sender_path = self.apis[SENDER_REGISTER_KEY]["spec_path"] + "/sender-attributes"
        sender_properties = load_resolved_schema(sender_path, "sender_register.json",
                                                 path_prefix=False)["properties"]

        media_type_constraint = "urn:x-nmos:cap:format:media_type"

        enum_constraints = {
            "urn:x-nmos:cap:format:profile": aac_properties["profile"]["enum"],
            "urn:x-nmos:cap:format:level": aac_properties["level"]["enum"],
            "urn:x-nmos:cap:transport:packet_transmission_mode": sender_properties["packet_transmission_mode"]["anyOf"][3]["enum"], # AAC entry
            "urn:x-matrox:cap:format:constant_bit_rate": aac_properties["urn:x-matrox:constant_bit_rate"]["enum"],
            "urn:x-matrox:cap:transport:parameter_sets_flow_mode": sender_properties["urn:x-matrox:parameter_sets_flow_mode"]["enum"],
            "urn:x-matrox:cap:transport:parameter_sets_transport_mode": sender_properties["urn:x-matrox:parameter_sets_transport_mode"]["enum"],
        }

        try:
            aac_receivers = [receiver for receiver in self.is04_resources["receivers"].values()
                              if receiver["format"] == "urn:x-nmos:format:audio"
                              and "media_types" in receiver["caps"]
                              and ("audio/mpeg4-generic" in receiver["caps"]["media_types"] or "audio/MP4A-LATM" in receiver["caps"]["media_types"] or "audio/MP4A-ADTS" in receiver["caps"]["media_types"])]

            # A mux Receiver not having constraints sets cannot be assumed as supporting AAC
            for receiver in [receiver for receiver in self.is04_resources["receivers"].values()
                              if receiver["format"] == "urn:x-nmos:format:mux"]:
                if "constraint_sets" in receiver["caps"]:
                    for constraint_set in receiver["caps"]["constraint_sets"]:
                        if "urn:x-nmos:cap:format:media_type" in constraint_set:
                            if  "enum" in constraint_set["urn:x-nmos:cap:format:media_type"]:
                                if  ("audio/mpeg4-generic" in constraint_set["urn:x-nmos:cap:format:media_type"]["enum"] or "audio/MP4A-LATM" in constraint_set["urn:x-nmos:cap:format:media_type"]["enum"] or "audio/MP4A-ADTS" in constraint_set["urn:x-nmos:cap:format:media_type"]["enum"]):
                                    aac_receivers.append(receiver)

            for receiver in aac_receivers:

                other_audio, other_mux = self.is_receiver_using_other_transport(receiver)
                rfc6416 = self.is_receiver_using_RTP_transport_based_on_RFC6416(receiver)
                rfc3640 = self.is_receiver_using_RTP_transport_based_on_RFC3640(receiver)
                rfc2250 = self.is_receiver_using_RTP_transport_based_on_RFC2250(receiver)

                if not (rfc6416 or rfc3640 or rfc2250 or other_audio or other_mux):
                    return test.FAIL("Sender {} use an invalid transport and format combination" \
                                .format(receiver["id"]))

                # check required attributes are present
                if "constraint_sets" not in receiver["caps"]:
                    return test.FAIL("Receiver {} MUST indicate constraints in accordance with BCP-004-01 using "
                                     "the 'caps' attribute 'constraint_sets'.".format(receiver["id"]))

                # exclude constraint sets for other media types
                aac_constraint_sets = [constraint_set for constraint_set in receiver["caps"]["constraint_sets"]
                                        if receiver["format"] == "urn:x-nmos:format:audio"
                                        and (media_type_constraint not in constraint_set
                                        or ("enum" in constraint_set[media_type_constraint]
                                            and ("audio/mpeg4-generic" in constraint_set[media_type_constraint]["enum"] or "audio/MP4A-LATM" in constraint_set[media_type_constraint]["enum"] or "audio/MP4A-ADTS" in constraint_set[media_type_constraint]["enum"])))]

                for constraint_set in [constraint_set for constraint_set in receiver["caps"]["constraint_sets"] 
                                       if receiver["format"] == "urn:x-nmos:format:mux"]:
                    if media_type_constraint  in constraint_set:
                        if "enum" in constraint_set[media_type_constraint]:
                            if ("audio/mpeg4-generic" in constraint_set[media_type_constraint]["enum"] or "audio/MP4A-LATM" in constraint_set[media_type_constraint]["enum"] or "audio/MP4A-ADTS" in constraint_set[media_type_constraint]["enum"]):
                                aac_constraint_sets.append(constraint_set)

                if len(aac_constraint_sets) == 0:
                    return test.FAIL("Receiver {} MUST indicate constraints in accordance with BCP-004-01 using "
                                     "the 'caps' attribute 'constraint_sets'.".format(receiver["id"]))

                # check recommended attributes are present
                for constraint_set in aac_constraint_sets:
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

            if len(aac_receivers) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No AAC Receiver resources were found on the Node")

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
            if flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:audio":
                return True, False
            if flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:mux":
                return False,  True
        return False, False

    def is_sender_using_RTP_transport_based_on_RFC6416(self, sender, flow_map):
        if sender["transport"] in {"urn:x-nmos:transport:rtp",
                                    "urn:x-nmos:transport:rtp.ucast",
                                    "urn:x-nmos:transport:rtp.mcast"}:
            if flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:audio" and flow_map[sender["flow_id"]]["media_type"] == "audio/MP4A-LATM":
                return True
        return False

    def is_sender_using_RTP_transport_based_on_RFC3640(self, sender, flow_map):
        if sender["transport"] in {"urn:x-nmos:transport:rtp",
                                    "urn:x-nmos:transport:rtp.ucast",
                                    "urn:x-nmos:transport:rtp.mcast"}:
            if flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:audio" and flow_map[sender["flow_id"]]["media_type"] == "audio/mpeg4-generic":
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
            if receiver["format"] == "urn:x-nmos:format:audio":
                return True, False
            if receiver["format"] == "urn:x-nmos:format:mux":
                return False, True
        return False, False

    def is_receiver_using_RTP_transport_based_on_RFC6416(self, receiver):
        if receiver["transport"] in {"urn:x-nmos:transport:rtp",
                                    "urn:x-nmos:transport:rtp.ucast",
                                    "urn:x-nmos:transport:rtp.mcast"}:
            if receiver["format"] == "urn:x-nmos:format:audio" and "audio/MP4A-LATM" in receiver["caps"]["media_types"]:
                return True
        return False

    def is_receiver_using_RTP_transport_based_on_RFC3640(self, receiver):
        if receiver["transport"] in {"urn:x-nmos:transport:rtp",
                                    "urn:x-nmos:transport:rtp.ucast",
                                    "urn:x-nmos:transport:rtp.mcast"}:
            if receiver["format"] == "urn:x-nmos:format:audio" and "audio/mpeg4-generic" in receiver["caps"]["media_types"]:
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
        sdp_profile, sdp_level = self.getAacProfileLevelFromSdp(profile_level_id)
        if sdp_profile != profile or sdp_level != level:
            return False
        return True
    
        return False

    # (profile, level)
    def getAacProfileLevelFromSdp(self, profile_level_id):

        value = profile_level_id

        if value ==  1:
            profile = AacProfileMain
            level = AacCodecLevel1
        elif value ==  2:
            profile = AacProfileMain
            level = AacCodecLevel2
        elif value ==  3:
            profile = AacProfileMain
            level = AacCodecLevel3
        elif value ==  4:
            profile = AacProfileMain
            level = AacCodecLevel4
        elif value ==  5:
            profile = AacProfileScalable
            level = AacCodecLevel1
        elif value ==  6:
            profile = AacProfileScalable
            level = AacCodecLevel2
        elif value ==  7:
            profile = AacProfileScalable
            level = AacCodecLevel3
        elif value ==  8:
            profile = AacProfileScalable
            level = AacCodecLevel4
        elif value ==  9:
            profile = AacProfileSpeech
            level = AacCodecLevel1
        elif value ==  10:
            profile = AacProfileSpeech
            level = AacCodecLevel2
        elif value ==  11:
            profile = AacProfileSynthetic
            level = AacCodecLevel1
        elif value ==  12:
            profile = AacProfileSynthetic
            level = AacCodecLevel2
        elif value ==  13:
            profile = AacProfileSynthetic
            level = AacCodecLevel3
        elif value ==  14:
            profile = AacProfileHighQuality
            level = AacCodecLevel1
        elif value ==  15:
            profile = AacProfileHighQuality
            level = AacCodecLevel2
        elif value ==  16:
            profile = AacProfileHighQuality
            level = AacCodecLevel3
        elif value ==  17:
            profile = AacProfileHighQuality
            level = AacCodecLevel4
        elif value ==  18:
            profile = AacProfileHighQuality
            level = AacCodecLevel5
        elif value ==  19:
            profile = AacProfileHighQuality
            level = AacCodecLevel6
        elif value ==  20:
            profile = AacProfileHighQuality
            level = AacCodecLevel7
        elif value ==  21:
            profile = AacProfileHighQuality
            level = AacCodecLevel8
        elif value ==  22:
            profile = AacProfileLowDelay
            level = AacCodecLevel1
        elif value ==  23:
            profile = AacProfileLowDelay
            level = AacCodecLevel2
        elif value ==  24:
            profile = AacProfileLowDelay
            level = AacCodecLevel3
        elif value ==  25:
            profile = AacProfileLowDelay
            level = AacCodecLevel4
        elif value ==  26:
            profile = AacProfileLowDelay
            level = AacCodecLevel5
        elif value ==  27:
            profile = AacProfileLowDelay
            level = AacCodecLevel6
        elif value ==  28:
            profile = AacProfileLowDelay
            level = AacCodecLevel7
        elif value ==  29:
            profile = AacProfileLowDelay
            level = AacCodecLevel8
        elif value ==  30:
            profile = AacProfileNatural
            level = AacCodecLevel1
        elif value ==  31:
            profile = AacProfileNatural
            level = AacCodecLevel2
        elif value ==  32:
            profile = AacProfileNatural
            level = AacCodecLevel3
        elif value ==  33:
            profile = AacProfileNatural
            level = AacCodecLevel4
        elif value ==  34:
            profile = AacProfileMobile
            level = AacCodecLevel1
        elif value ==  35:
            profile = AacProfileMobile
            level = AacCodecLevel2
        elif value ==  36:
            profile = AacProfileMobile
            level = AacCodecLevel3
        elif value ==  37:
            profile = AacProfileMobile
            level = AacCodecLevel4
        elif value ==  38:
            profile = AacProfileMobile
            level = AacCodecLevel5
        elif value ==  39:
            profile = AacProfileMobile
            level = AacCodecLevel6
        elif value ==  40:
            profile = AacProfileAAC
            level = AacCodecLevel1
        elif value ==  41:
            profile = AacProfileAAC
            level = AacCodecLevel2
        elif value ==  42:
            profile = AacProfileAAC
            level = AacCodecLevel4
        elif value ==  43:
            profile = AacProfileAAC
            level = AacCodecLevel5
        elif value ==  44:
            profile = AacProfileHighEfficiencyAAC
            level = AacCodecLevel2
        elif value ==  45:
            profile = AacProfileHighEfficiencyAAC
            level = AacCodecLevel3
        elif value ==  46:
            profile = AacProfileHighEfficiencyAAC
            level = AacCodecLevel4
        elif value ==  47:
            profile = AacProfileHighEfficiencyAAC
            level = AacCodecLevel5
        elif value ==  48:
            profile = AacProfileHighEfficiencyAAC
            level = AacCodecLevel2
        elif value ==  49:
            profile = AacProfileHighEfficiencyAAC
            level = AacCodecLevel3
        elif value ==  50:
            profile = AacProfileHighEfficiencyAAC
            level = AacCodecLevel4
        elif value ==  51:
            profile = AacProfileHighEfficiencyAAC
            level = AacCodecLevel5
        elif value ==  52:
            profile = AacProfileLowDelay
            level = AacCodecLevel1
            
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

