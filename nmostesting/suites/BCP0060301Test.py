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

import json
import re

from jsonschema import ValidationError

from ..GenericTest import GenericTest, NMOSTestException
from ..IS04Utils import IS04Utils
from ..TestHelper import load_resolved_schema

NODE_API_KEY = "node"
FLOW_REGISTER_KEY = "flow-register"
SENDER_REGISTER_KEY = "sender-register"


class BCP0060301Test(GenericTest):
    """
    Runs Node Tests covering BCP-006-03
    """
    def __init__(self, apis, **kwargs):
        # Don't auto-test /transportfile as it is permitted to generate a 404 when master_enable is false
        omit_paths = [
            "/single/senders/{senderId}/transportfile"
        ]
        GenericTest.__init__(self, apis, omit_paths, **kwargs)
        self.node_url = self.apis[NODE_API_KEY]["url"]
        self.is04_resources = {"senders": [], "receivers": [], "_requested": [], "sources": [], "flows": []}
        self.is04_utils = IS04Utils(self.node_url)

    # Utility function from IS0502Test
    def get_is04_resources(self, resource_type):
        """Retrieve all Senders or Receivers from a Node API, keeping hold of the returned objects"""
        assert resource_type in ["senders", "receivers", "sources", "flows"]

        # Prevent this being executed twice in one test run
        if resource_type in self.is04_resources["_requested"]:
            return True, ""

        valid, resources = self.do_request("GET", self.node_url + resource_type)
        if not valid:
            return False, "Node API did not respond as expected: {}".format(resources)

        try:
            for resource in resources.json():
                self.is04_resources[resource_type].append(resource)
            self.is04_resources["_requested"].append(resource_type)
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
            return test.FAIL("Node API must be running v1.3 or greater to fully implement BCP-006-01")

    def test_02(self, test):
        """H.265 Flows have the required attributes"""

        self.do_test_node_api_v1_1(test)

        v1_3 = self.is04_utils.compare_api_version(self.apis[NODE_API_KEY]["version"], "v1.3") >= 0

        reg_api = self.apis[FLOW_REGISTER_KEY]

        valid, result = self.get_is04_resources("flows")
        if not valid:
            return test.FAIL(result)

        reg_path = reg_api["spec_path"] + "/flow-attributes"
        reg_schema = load_resolved_schema(reg_path, "flow_video_register.json", path_prefix=False)

        try:
            flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"]}

            h265_flows = [flow for flow in self.is04_resources["flows"] if flow["format"] == "urn:x-nmos:format:video"
                                                                        and flow["media_type"] == "video/H265"]
            
            for mux_flow in [flow for flow in self.is04_resources["flows"] if flow["format"] == "urn:x-nmos:format:mux"]:
                for parent_flow in mux_flow["parents"]:
                    if flow_map[parent_flow]["format"] == "urn:x-nmos:format:video":
                        if flow_map[parent_flow]["media_type"] == "video/H265":
                            h265_flows.append(parent_flow)

            warn_na = False
            warn_message = ""

            for flow in h265_flows:
                # check required attributes are present. constant_bit_rate is not verified because it has a
                # default value of false, making it optional.
                if "components" not in flow:
                    if v1_3:
                        return test.FAIL("Flow {} MUST indicate the color (sub-)sampling using "
                                         "the 'components' attribute.".format(flow["id"]))
                    else:
                        warn_na = True

                if "profile" not in flow:
                    if v1_3:
                        return test.FAIL("Flow {} MUST indicate the encoding profile using "
                                         "the 'profile' attribute.".format(flow["id"]))
                    else:
                        warn_na = True

                if "level" not in flow:
                    if v1_3:
                        return test.FAIL("Flow {} MUST indicate the encoding level using "
                                         "the 'level' attribute.".format(flow["id"]))
                    else:
                        warn_na = True

                if "bit_rate" not in flow:
                    if v1_3:
                        return test.FAIL("Flow {} MUST indicate the target bit rate of the codestream using "
                                         "the 'bit_rate' attribute.".format(flow["id"]))
                    else:
                        warn_na = True

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
                               "with 'video/H265' from IS-04 v1.3")

            if len(h265_flows) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No H.265 Flow resources were found on the Node")

    def test_03(self, test):
        """H.265 Sources have the required attributes"""

        self.do_test_node_api_v1_1(test)

        for resource_type in ["flows", "sources"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        source_map = {source["id"]: source for source in self.is04_resources["sources"]}
        flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"]}

        try:
            h265_flows = [flow for flow in self.is04_resources["flows"] if flow["format"] == "urn:x-nmos:format:video"
                                                                        and flow["media_type"] == "video/H265"]
            
            for mux_flow in [flow for flow in self.is04_resources["flows"] if flow["format"] == "urn:x-nmos:format:mux"]:
                for parent_flow in mux_flow["parents"]:
                    if flow_map[parent_flow]["format"] == "urn:x-nmos:format:video":
                        if flow_map[parent_flow]["media_type"] == "video/H265":
                            h265_flows.append(parent_flow)

            for flow in h265_flows:
                source = source_map[flow["source_id"]]

                if source["format"] != "urn:x-nmos:format:video":
                    return test.FAIL("Source {} MUST indicate format with value 'urn:x-nmos:format:video'"
                                     .format(source["id"]))

            if len(h265_flows) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No H.265 Flow resources were found on the Node")

    def test_04(self, test):
        """H.265 Senders have the required attributes"""

        self.do_test_node_api_v1_1(test)

        v1_3 = self.is04_utils.compare_api_version(self.apis[NODE_API_KEY]["version"], "v1.3") >= 0

        reg_api = self.apis[SENDER_REGISTER_KEY]

        for resource_type in ["senders", "flows"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"]}

        reg_path = reg_api["spec_path"] + "/sender-attributes"
        reg_schema = load_resolved_schema(reg_path, "sender_h26x_register.json", path_prefix=False)

        try:
            # Note: indirect h265 senders do not apply here because, being mux senders they
            #       follow the rules of the mux, not H.265
            h265_senders = [sender for sender in self.is04_resources["senders"] if sender["flow_id"]
                            and sender["flow_id"] in flow_map
                            and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:video"
                            and flow_map[sender["flow_id"]]["media_type"] == "video/H265"]

            warn_na = False
            warn_st2110_22 = False
            warn_message = ""

            for sender in h265_senders:
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
                                     "/sender-attributes/sender_h26x_register.html"
                                     .format(reg_api["spec_branch"]))

                other_video, other_mux = self.is_sender_using_other_transports(sender, flow_map)
                rfc7798 = self.is_sender_using_RTP_transport_based_on_RFC7798(sender, flow_map)

                if not (rfc7798 or other_video) or other_mux:
                    return test.FAIL("Sender {} use an invalid transport and format combination" \
                                .format(sender["id"]))
            
                if rfc7798:
                    # check recommended attributes are present
                    if "st2110_21_sender_type" not in sender:
                        if v1_3 and not warn_st2110_22:
                            warn_st2110_22 = True
                            warn_message = "Sender {} MUST indicate the ST 2110-21 Sender Type using " \
                                        "the 'st2110_21_sender_type' attribute if it is compliant with ST 2110-22." \
                                        .format(sender["id"])

                    # A warning is not given if the bit_rate is not provided even if the spaeicication says "SHOULD" 
                    # because there is not such requirement in RFC7798 and it is not current practice to provide such
                    # information in all the scenarios.
                    if "st2110_21_sender_type" in sender:
                        if "bit_rate" not in sender:
                            if v1_3:
                                return test.FAIL("Sender {} MUST indicate the Sender bit rate using " \
                                            "the 'bit_rate' attribute when conforming to ST 2110-22." \
                                            .format(sender["id"]))
                    if "bit_rate" in sender:
                        if v1_3:
                            if flow_map[sender["flow_id"]]["bit_rate"] >= sender["bit_rate"]:
                                return test.FAIL("Sender {} MUST derive bit rate from Flow bit rate" \
                                            .format(sender["id"]))

            if warn_na:
                return test.NA("Additional Sender attributes such as 'st2110_21_sender_type' are required "
                               "with 'video/H265' from IS-04 v1.3")
            if warn_st2110_22:
                return test.WARNING(warn_message)

            if len(h265_senders) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No H.265 Sender resources were found on the Node")

    def test_05(self, test):
        """H.265 Sender manifests have the required parameters"""

        self.do_test_node_api_v1_1(test)

        v1_3 = self.is04_utils.compare_api_version(self.apis[NODE_API_KEY]["version"], "v1.3") >= 0

        for resource_type in ["senders", "flows"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"]}
        source_map = {source["id"]: source for source in self.is04_resources["sources"]}

        try:
            # Note: indirect h265 senders do not apply here because, being mux senders they
            #       follow the rules of the mux, not H.265
            h265_senders = [sender for sender in self.is04_resources["senders"] if sender["flow_id"]
                            and sender["flow_id"] in flow_map
                            and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:video"
                            and flow_map[sender["flow_id"]]["media_type"] == "video/H265"]

            access_error = False
            for sender in h265_senders:
                flow = flow_map[sender["flow_id"]]
                source = source_map[flow["source_id"]]

                other_video, other_mux = self.is_sender_using_other_transports(sender, flow_map)
                rfc7798 = self.is_sender_using_RTP_transport_based_on_RFC7798(sender, flow_map)

                if not (rfc7798 or other_video) or other_mux:
                    return test.FAIL("Sender {} use an invalid transport and format combination" \
                                .format(sender["id"]))

                if not rfc7798:
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
                        if name in ["packetization-mode", "profile-space", "profile-id", "level-id", "tier-flag", "sprop-max-don-diff", "sprop-depack-buf-nalus", "sprop-depack-buf-bytes"]:
                            try:
                                value = int(value)
                            except ValueError:
                                return test.FAIL("SDP '{}' for Sender {} is not an integer"
                                                 .format(name, sender["id"]))
                        sdp_format_params[name] = value

                    # The `profile-space`, `profile-id`, `profile-compatibility-indicator`, `interop-constraints`, `level-id` and `tier-flag` format-specific parameters MUST be included with the correct value unless it corresponds to the default value. "Main" is the default profile value and "Main-3.1" is the default level value (tier-flag 0, level-id 3.1).
                    name = "profile-id"
                    if name not in sdp_format_params:
                        profile_id = 1
                    else:
                        profile_id = sdp_format_params[name]

                    if "profile-space" not in sdp_format_params:
                        profile_space = 0
                    else:
                        profile_space = sdp_format_params["profile-space"]

                    if "profile-compatibility-indicator" not in sdp_format_params:
                        profile_compatibility_indicator = ""
                    else:
                        profile_compatibility_indicator = sdp_format_params["profile-compatibility-indicator"]

                    if "interop-constraints" not in sdp_format_params:
                        interop_constraints = ""
                    else:
                        interop_constraints = sdp_format_params["interop-constraints"]

                    name = "level-id"
                    if name not in sdp_format_params:
                        leve_id = "3.1"
                    else:
                        level_id = sdp_format_params[name]

                    if "tier-flag" not in sdp_format_params:
                        tier_flag = "0"
                    else:
                        tier_flag = sdp_format_params["tier-flag"]

                    if "profile" in flow and "level" in flow:
                        if not self.check_sdp_profile_level(profile_id, profile_space, profile_compatibility_indicator, interop_constraints, level_id, tier_flag, flow["profile"], flow["level"]):
                            return test.FAIL("SDP '{}' for Sender {} does not match profile, level attributes in its Flow {}"
                                                .format("profile-id, level-id, tier-flag", sender["id"], flow["id"]))
                    elif v1_3:
                        return test.FAIL("SDP '{}' for Sender {} is present but associated profile, level attributes are missing in its Flow {}"
                                            .format("profile-id", sender["id"], flow["id"]))

                    # The `packetization-mode` format-specific parameters MUST be included with the correct value unless it corresponds to the default value.
                    name, nmos_name = "sprop-max-don-diff", "packet_transmission_mode"
                    if name not in sdp_format_params:
                        sprop_max_don_diff = 0
                    else:
                        sprop_max_don_diff = sdp_format_params[name]

                    if nmos_name not in sender:
                        packet_transmission_mode = "non_interleaved_nal_units"
                    else:
                        packet_transmission_mode = sender[nmos_name]

                    if not self.check_sdp_packetization_mode(sprop_max_don_diff, packet_transmission_mode):
                        return test.FAIL("SDP '{}' for Sender {} does not match {} in the Sender {} {}"
                                            .format(name, sender["id"], nmos_name, sprop_max_don_diff, packet_transmission_mode))

                    # The `sprop-parameter-sets` MUST always be included if the Sender `parameter_sets_transport_mode` attribute is `out_of_band`
                    name, nmos_name = "sprop-parameter-sets", "parameter_sets_transport_mode"

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
                        elif v1_3:
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
                        elif v1_3:
                            return test.FAIL("SDP '{}' for Sender {} is present but {} is missing in the Sender"
                                            .format(name, sender["id"], nmos_name))

                    if nmos_name in sender and not found_bandwidth:
                        return test.FAIL("SDP '{}' for Sender {} is missing but must match {} in the Sender"
                                        .format(name, sender["id"], nmos_name))

            if access_error:
                return test.UNCLEAR("One or more of the tested Senders had null or empty 'manifest_href' or "
                                    "returned a 404 HTTP code. Please ensure all Senders are enabled and re-test.")

            if len(h265_senders) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No H.265 Sender resources were found on the Node")

    def test_06(self, test):
        """H.265 Receivers have the required attributes"""

        self.do_test_node_api_v1_1(test)

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
            "urn:x-nmos:cap:format:constant_bit_rate": "constant bit rate",
        }

        recommended_rfc7798_constraints = {
            "urn:x-nmos:cap:transport:packet_transmission_mode": "packet transmission mode",
            "urn:x-nmos:cap:transport:parameter_sets_flow_mode": "parameter sets flow mode",
            "urn:x-nmos:cap:transport:parameter_sets_transport_mode": "parameter sets transport mode",
        }

        recommended_rfc2250_constraints = {
        }

        recommended_other_video_constraints = {
            "urn:x-nmos:cap:transport:parameter_sets_flow_mode": "parameter sets flow mode",
            "urn:x-nmos:cap:transport:parameter_sets_transport_mode": "parameter sets transport mode",
        }

        recommended_other_mux_constraints = {
        }

        try:
            h265_receivers = [receiver for receiver in self.is04_resources["receivers"]
                              if receiver["format"] == "urn:x-nmos:format:video"
                              and "media_types" in receiver["caps"]
                              and "video/H265" in receiver["caps"]["media_types"]]

            # A mux Receiver not having constraints sets cannot be assumed as supporting H.265
            for receiver in [receiver for receiver in self.is04_resources["receivers"]
                              if receiver["format"] == "urn:x-nmos:format:mux"]:
                if "constraint_sets" in receiver["caps"]:
                    for constraint_set in receiver["caps"]["constraint_sets"]:
                        if "urn:x-nmos:cap:format:media_type" in constraint_set:
                            if  "enum" in constraint_set["urn:x-nmos:cap:format:media_type"]:
                                if  "video/H265" in constraint_set["urn:x-nmos:cap:format:media_type"]["enum"]:
                                    h265_receivers.append(receiver)

            warn_unrestricted = False
            warn_message = ""

            for receiver in h265_receivers:

                # check required attributes are present
                if "transport" not in receiver:
                    return test.FAIL("Receiver {} MUST indicate the 'transport' attribute."
                                     .format(receiver["id"]))

                other_video, other_mux = self.is_receiver_using_other_transport(receiver)
                rfc7798 = self.is_receiver_using_RTP_transport_based_on_RFC7798(receiver)
                rfc2250 = self.is_receiver_using_RTP_transport_based_on_RFC2250(receiver)

                if not (rfc7798 or rfc2250 or other_video or other_mux):
                    return test.FAIL("Sender {} use an invalid transport and format combination" \
                                .format(receiver["id"]))

                if "constraint_sets" not in receiver["caps"]:
                    return test.FAIL("Receiver {} MUST indicate constraints in accordance with BCP-004-01 using "
                                     "the 'caps' attribute 'constraint_sets'.".format(receiver["id"]))

                # exclude constraint sets for other media types
                h265_constraint_sets = [constraint_set for constraint_set in receiver["caps"]["constraint_sets"]
                                        if receiver["format"] == "urn:x-nmos:format:video"
                                        and (media_type_constraint not in constraint_set
                                        or ("enum" in constraint_set[media_type_constraint]
                                            and "video/H265" in constraint_set[media_type_constraint]["enum"]))]

                for constraint_set in [constraint_set for constraint_set in receiver["caps"]["constraint_sets"] 
                                       if receiver["format"] == "urn:x-nmos:format:mux"]:
                    if media_type_constraint  in constraint_set:
                        if "enum" in constraint_set[media_type_constraint]:
                            if "video/H265" in constraint_set[media_type_constraint]["enum"]:
                                h265_constraint_sets.append(constraint_set)

                if len(h265_constraint_sets) == 0:
                    return test.FAIL("Receiver {} MUST indicate constraints in accordance with BCP-004-01 using "
                                     "the 'caps' attribute 'constraint_sets'.".format(receiver["id"]))

                # check recommended attributes are present
                for constraint_set in h265_constraint_sets:
                    for constraint, target in recommended_constraints.items():
                        if constraint not in constraint_set:
                            if not warn_unrestricted:
                                warn_unrestricted = True
                                warn_message = "Receiver {} SHOULD indicate the supported H.265 {} using the " \
                                               "'{}' parameter constraint.".format(receiver["id"], target, constraint)

                    if rfc7798:
                        for constraint, target in recommended_rfc7798_constraints.items():
                            if constraint not in constraint_set:
                                if not warn_unrestricted:
                                    warn_unrestricted = True
                                    warn_message = "Receiver {} SHOULD indicate the supported H.265 {} using the " \
                                                "'{}' parameter constraint.".format(receiver["id"], target, constraint)

                    if rfc2250:
                        for constraint, target in recommended_rfc2250_constraints.items():
                            if constraint not in constraint_set:
                                if not warn_unrestricted:
                                    warn_unrestricted = True
                                    warn_message = "Receiver {} SHOULD indicate the supported H.265 {} using the " \
                                                "'{}' parameter constraint.".format(receiver["id"], target, constraint)

                    if other_video:
                        for constraint, target in recommended_other_video_constraints.items():
                            if constraint not in constraint_set:
                                if not warn_unrestricted:
                                    warn_unrestricted = True
                                    warn_message = "Receiver {} SHOULD indicate the supported H.265 {} using the " \
                                                "'{}' parameter constraint.".format(receiver["id"], target, constraint)

                    if other_mux:
                        for constraint, target in recommended_other_mux_constraints.items():
                            if constraint not in constraint_set:
                                if not warn_unrestricted:
                                    warn_unrestricted = True
                                    warn_message = "Receiver {} SHOULD indicate the supported H.265 {} using the " \
                                                "'{}' parameter constraint.".format(receiver["id"], target, constraint)

            if warn_unrestricted:
                return test.WARNING(warn_message)

            if len(h265_receivers) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No H.265 Receiver resources were found on the Node")

    def test_07(self, test):
        """H.265 Receiver parameter constraints have valid values"""

        self.do_test_node_api_v1_1(test)

        valid, result = self.get_is04_resources("receivers")
        if not valid:
            return test.FAIL(result)

        flow_reg_path = self.apis[FLOW_REGISTER_KEY]["spec_path"] + "/flow-attributes"
        base_properties = load_resolved_schema(flow_reg_path, "flow_video_base_register.json",
                                               path_prefix=False)["properties"]
        h265_properties = load_resolved_schema(flow_reg_path, "flow_video_h265_register.json",
                                               path_prefix=False)["properties"]
        sender_path = self.apis[SENDER_REGISTER_KEY]["spec_path"] + "/sender-attributes"
        sender_properties = load_resolved_schema(sender_path, "sender_h26x_register.json",
                                                 path_prefix=False)["properties"]

        media_type_constraint = "urn:x-nmos:cap:format:media_type"

        enum_constraints = {
            "urn:x-nmos:cap:format:profile": h265_properties["profile"]["enum"],
            "urn:x-nmos:cap:format:level": h265_properties["level"]["enum"],
            "urn:x-nmos:cap:format:constant_bit_rate": h265_properties["constant_bit_rate"]["enum"],
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
            "urn:x-nmos:cap:transport:packet_transmission_mode": sender_properties["packet_transmission_mode"]["enum"],
            "urn:x-nmos:cap:transport:st2110_21_sender_type": sender_properties["st2110_21_sender_type"]["enum"],
            "urn:x-nmos:cap:transport:parameter_sets_flow_mode": sender_properties["parameter_sets_flow_mode"]["enum"],
            "urn:x-nmos:cap:transport:parameter_sets_transport_mode": sender_properties["parameter_sets_transport_mode"]["enum"],
        }

        try:
            h265_receivers = [receiver for receiver in self.is04_resources["receivers"]
                              if receiver["format"] == "urn:x-nmos:format:video"
                              and "media_types" in receiver["caps"]
                              and "video/H265" in receiver["caps"]["media_types"]]

            # A mux Receiver not having constraints sets cannot be assumed as supporting H.265
            for receiver in [receiver for receiver in self.is04_resources["receivers"]
                              if receiver["format"] == "urn:x-nmos:format:mux"]:
                if "constraint_sets" in receiver["caps"]:
                    for constraint_set in receiver["caps"]["constraint_sets"]:
                        if "urn:x-nmos:cap:format:media_type" in constraint_set:
                            if  "enum" in constraint_set["urn:x-nmos:cap:format:media_type"]:
                                if  "video/H265" in constraint_set["urn:x-nmos:cap:format:media_type"]["enum"]:
                                    h265_receivers.append(receiver)

            for receiver in h265_receivers:

                other_video, other_mux = self.is_receiver_using_other_transport(receiver)
                rfc7798 = self.is_receiver_using_RTP_transport_based_on_RFC7798(receiver)
                rfc2250 = self.is_receiver_using_RTP_transport_based_on_RFC2250(receiver)

                if not (rfc7798 or rfc2250 or other_video or other_mux):
                    return test.FAIL("Sender {} use an invalid transport and format combination" \
                                .format(receiver["id"]))

                # check required attributes are present
                if "constraint_sets" not in receiver["caps"]:
                    # FAIL reported by test_05
                    continue

                # exclude constraint sets for other media types
                h265_constraint_sets = [constraint_set for constraint_set in receiver["caps"]["constraint_sets"]
                                        if receiver["format"] == "urn:x-nmos:format:video"
                                        and (media_type_constraint not in constraint_set
                                        or ("enum" in constraint_set[media_type_constraint]
                                            and "video/H265" in constraint_set[media_type_constraint]["enum"]))]

                for constraint_set in [constraint_set for constraint_set in receiver["caps"]["constraint_sets"] 
                                       if receiver["format"] == "urn:x-nmos:format:mux"]:
                    if media_type_constraint  in constraint_set:
                        if "enum" in constraint_set[media_type_constraint]:
                            if "video/H265" in constraint_set[media_type_constraint]["enum"]:
                                h265_constraint_sets.append(constraint_set)

                if len(h265_constraint_sets) == 0:
                    # FAIL reported by test_05
                    continue

                # check recommended attributes are present
                for constraint_set in h265_constraint_sets:
                    for constraint, enum_values in enum_constraints.items():
                        if constraint in constraint_set and "enum" in constraint_set[constraint]:
                            for enum_value in constraint_set[constraint]["enum"]:
                                if enum_value not in enum_values:
                                    return test.FAIL("Receiver {} uses an invalid value for '{}': {}"
                                                     .format(receiver["id"], constraint, enum_value))
                                
                            if (rfc2250 or other_mux) and constraint == "parameter_sets_flow_mode":
                                if not "dynamic" in constraint_set[constraint]["enum"]:
                                    return test.FAIL("Receiver {} must support 'dynamic' or be unconstrained '{}': {}"
                                                     .format(receiver["id"], constraint, constraint_set[constraint]["enum"]))
            
                            if (rfc2250 or other_mux) and constraint == "parameter_sets_transport_mode":
                                if not "in_band" in constraint_set[constraint]["enum"]:
                                    return test.FAIL("Receiver {} must support 'in_band' or be unconstrained '{}': {}"
                                                     .format(receiver["id"], constraint, constraint_set[constraint]["enum"]))

            if len(h265_receivers) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No H.265 Receiver resources were found on the Node")

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

    def do_test_node_api_v1_1(self, test):
        """
        Precondition check of the API version.
        Raises an NMOSTestException when the Node API version is less than v1.1
        """
        api = self.apis[NODE_API_KEY]
        if self.is04_utils.compare_api_version(api["version"], "v1.1") < 0:
            raise NMOSTestException(test.NA("This test cannot be run against Node API below version v1.1."))

    def is_sender_using_other_transports(self, sender, flow_map):
        if not sender["transport"] in {"urn:x-nmos:transport:rtp",
                                    "urn:x-nmos:transport:rtp.ucast",
                                    "urn:x-nmos:transport:rtp.mcast"}:
            if flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:video":
                return True, False
            if flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:mux":
                return False,  True
        return False, False

    def is_sender_using_RTP_transport_based_on_RFC7798(self, sender, flow_map):
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

    def is_receiver_using_RTP_transport_based_on_RFC7798(self, receiver):
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

    def check_sdp_profile_level(self, profile_id, profile_space, profile_compatibility_indicator, interop_constraints, level_id, tier_flag, profile, level):

        if profile_space != 0:
            return False

        sdp_profile, sdp_level = getH265ProfileLevelFromSdp(profile_space, profile_id, tier_flag, level_id, profile_compatibility_indicator, interop_constraints)

        if sdp_profile != profile or sdp_level != level:
            return False

        return True

    def check_sdp_packetization_mode(self, sprop_max_don_diff, packet_transmission_mode):
        if packet_transmission_mode == "non_interleaved_nal_units" and sprop_max_don_diff == 0:
            return True
        if packet_transmission_mode == "interleaved_nal_units" and sprop_max_don_diff > 11:
            return True
        
        return False
    
general_progressive_source_flag = 1 << 47    # used to express interlaced versus progressive
general_interlaced_source_flag = 1 << 46     # used to express interlaced versus progressive
general_non_packed_constraint_flag = 1 << 45 # set to 1 by default
general_frame_only_constraint_flag = 1 << 44 # set to 1 if progressive_source_flag is 1, 0 otherwise
general_max_12bit_constraint_flag = 1 << 43
general_max_10bit_constraint_flag = 1 << 42
general_max_8bit_constraint_flag = 1 << 41
general_max_422chroma_constraint_flag = 1 << 40
general_max_420chroma_constraint_flag = 1 << 39
general_max_monochrome_constraint_flag = 1 << 38
general_intra_constraint_flag = 1 << 37
general_one_picture_only_constraint_flag = 1 << 36
general_lower_bit_rate_constraint_flag = 1 << 35
general_max_14bit_constraint_flag = 1 << 34
general_inbld_flag = 1 << 0

profile_constraints_mask = (general_max_14bit_constraint_flag |
    general_max_12bit_constraint_flag |
    general_max_10bit_constraint_flag |
    general_max_8bit_constraint_flag |
    general_max_422chroma_constraint_flag |
    general_max_420chroma_constraint_flag |
    general_max_monochrome_constraint_flag |
    general_intra_constraint_flag |
    general_one_picture_only_constraint_flag |
    general_lower_bit_rate_constraint_flag)

profile_constraints_intra_mask = (general_max_14bit_constraint_flag |
    general_max_12bit_constraint_flag |
    general_max_10bit_constraint_flag |
    general_max_8bit_constraint_flag |
    general_max_422chroma_constraint_flag |
    general_max_420chroma_constraint_flag |
    general_max_monochrome_constraint_flag |
    general_intra_constraint_flag |
    general_one_picture_only_constraint_flag)
    # general_lower_bit_rate_constraint_flag

profile_constraints_still_mask = (general_max_14bit_constraint_flag |
    general_max_12bit_constraint_flag |
    general_max_10bit_constraint_flag |
    general_max_8bit_constraint_flag |
    general_max_422chroma_constraint_flag |
    general_max_420chroma_constraint_flag |
    general_max_monochrome_constraint_flag |
    general_intra_constraint_flag |
    general_one_picture_only_constraint_flag)
    # general_lower_bit_rate_constraint_flag

# (profile, level)
def getH265ProfileLevelFromSdp(profile_space, profile_id, tier_flag, level_id, profile_compatibility, interop_constraints):

    if profile_space != 0:
        return "", ""

    if interop_constraints == "":
        interop_constraints = (general_progressive_source_flag|general_non_packed_constraint_flag|general_frame_only_constraint_flag)
    else:
        constraints = int(interop_constraints, 16)

    if profile_compatibility == "":
        compatibility = 1 << profile_id
    else:
        compatibility = int(profile_compatibility, 16)

    if profile_id == 1:
        profile = "Main" # do not check compatibility flags

    elif profile_id ==  2:
        if (constraints & general_one_picture_only_constraint_flag) != 0:
            profile = "Main10StillPicture"
        else:
            profile = "Main10"
        
    elif profile_id ==  3:
        profile = "MainStillPicture"

    elif profile_id ==  4:

        if (constraints & profile_constraints_mask) == (
            0|
                general_max_12bit_constraint_flag|
                general_max_10bit_constraint_flag|
                general_max_8bit_constraint_flag|
                general_max_422chroma_constraint_flag|
                general_max_420chroma_constraint_flag|
                general_max_monochrome_constraint_flag|
                # general_intra_constraint_flag |
                # general_one_picture_only_constraint_flag |
                general_lower_bit_rate_constraint_flag|
                0):
            profile = "Monochrome"
        elif (constraints & profile_constraints_mask) == (
            0|
                general_max_12bit_constraint_flag|
                general_max_10bit_constraint_flag|
                # general_max_8bit_constraint_flag |
                general_max_422chroma_constraint_flag|
                general_max_420chroma_constraint_flag|
                general_max_monochrome_constraint_flag|
                # general_intra_constraint_flag |
                # general_one_picture_only_constraint_flag |
                general_lower_bit_rate_constraint_flag|
                0):
            profile = "Monochrome10"
        elif (constraints & profile_constraints_mask) == (
            0|
                general_max_12bit_constraint_flag|
                # general_max_10bit_constraint_flag|
                # general_max_8bit_constraint_flag|
                general_max_422chroma_constraint_flag|
                general_max_420chroma_constraint_flag|
                general_max_monochrome_constraint_flag|
                # general_intra_constraint_flag|
                # general_one_picture_only_constraint_flag|
                general_lower_bit_rate_constraint_flag|
                0) :
            profile = "Monochrome12"
        elif (constraints & profile_constraints_mask) == (
            0|
                # general_max_12bit_constraint_flag |
                # general_max_10bit_constraint_flag |
                # general_max_8bit_constraint_flag |
                general_max_422chroma_constraint_flag|
                general_max_420chroma_constraint_flag|
                general_max_monochrome_constraint_flag|
                # general_intra_constraint_flag |
                # general_one_picture_only_constraint_flag |
                general_lower_bit_rate_constraint_flag|
                0) :
            profile = "Monochrome16"
        elif (constraints & profile_constraints_mask) == (
            0|
                general_max_12bit_constraint_flag|
                # general_max_10bit_constraint_flag |
                # general_max_8bit_constraint_flag |
                general_max_422chroma_constraint_flag|
                general_max_420chroma_constraint_flag|
                # general_max_monochrome_constraint_flag |
                # general_intra_constraint_flag |
                # general_one_picture_only_constraint_flag |
                general_lower_bit_rate_constraint_flag|
                0) :
            profile = "Main12"
        elif (constraints & profile_constraints_mask) == (
            0|
                general_max_12bit_constraint_flag|
                general_max_10bit_constraint_flag|
                # general_max_8bit_constraint_flag|
                general_max_422chroma_constraint_flag|
                # general_max_420chroma_constraint_flag|
                # general_max_monochrome_constraint_flag|
                # general_intra_constraint_flag|
                # general_one_picture_only_constraint_flag|
                general_lower_bit_rate_constraint_flag|
                0) :
            profile = "Main10-422"
        elif (constraints & profile_constraints_mask) == (
            0|
                general_max_12bit_constraint_flag|
                # general_max_10bit_constraint_flag |
                # general_max_8bit_constraint_flag |
                general_max_422chroma_constraint_flag|
                # general_max_420chroma_constraint_flag |
                # general_max_monochrome_constraint_flag |
                # general_intra_constraint_flag |
                # general_one_picture_only_constraint_flag |
                general_lower_bit_rate_constraint_flag|
                0) :
            profile = "Main12-422"
        elif (constraints & profile_constraints_mask) == (
            0|
                general_max_12bit_constraint_flag|
                general_max_10bit_constraint_flag|
                general_max_8bit_constraint_flag|
                # general_max_422chroma_constraint_flag |
                # general_max_420chroma_constraint_flag |
                # general_max_monochrome_constraint_flag |
                # general_intra_constraint_flag |
                # general_one_picture_only_constraint_flag |
                general_lower_bit_rate_constraint_flag|
                0) :
            profile = "Main-444"
        elif (constraints & profile_constraints_mask) == (
            0|
                general_max_12bit_constraint_flag|
                general_max_10bit_constraint_flag|
                # general_max_8bit_constraint_flag |
                # general_max_422chroma_constraint_flag |
                # general_max_420chroma_constraint_flag |
                # general_max_monochrome_constraint_flag |
                # general_intra_constraint_flag |
                # general_one_picture_only_constraint_flag |
                general_lower_bit_rate_constraint_flag|
                0) :
            profile = "Main10-444"
        elif (constraints & profile_constraints_mask) == (
            0|
                general_max_12bit_constraint_flag|
                # general_max_10bit_constraint_flag |
                # general_max_8bit_constraint_flag |
                # general_max_422chroma_constraint_flag |
                # general_max_420chroma_constraint_flag |
                # general_max_monochrome_constraint_flag |
                # general_intra_constraint_flag |
                # general_one_picture_only_constraint_flag |
                general_lower_bit_rate_constraint_flag|
                0) :
            profile = "Main12-444"
        elif (constraints & profile_constraints_intra_mask) == (
            0|
                general_max_12bit_constraint_flag|
                general_max_10bit_constraint_flag|
                general_max_8bit_constraint_flag|
                general_max_422chroma_constraint_flag|
                general_max_420chroma_constraint_flag|
                # general_max_monochrome_constraint_flag |
                general_intra_constraint_flag|
                # general_one_picture_only_constraint_flag |
                # general_lower_bit_rate_constraint_flag |
                0) :
            profile = "MainIntra"
        elif (constraints & profile_constraints_intra_mask) == (
            0|
                general_max_12bit_constraint_flag|
                general_max_10bit_constraint_flag|
                # general_max_8bit_constraint_flag |
                general_max_422chroma_constraint_flag|
                general_max_420chroma_constraint_flag|
                # general_max_monochrome_constraint_flag |
                general_intra_constraint_flag|
                # general_one_picture_only_constraint_flag |
                # general_lower_bit_rate_constraint_flag |
                0) :
            profile = "Main10Intra"
        elif (constraints & profile_constraints_intra_mask) == (
            0|
                general_max_12bit_constraint_flag|
                # general_max_10bit_constraint_flag |
                # general_max_8bit_constraint_flag |
                general_max_422chroma_constraint_flag|
                general_max_420chroma_constraint_flag|
                # general_max_monochrome_constraint_flag |
                general_intra_constraint_flag|
                # general_one_picture_only_constraint_flag |
                # general_lower_bit_rate_constraint_flag |
                0) :
            profile = "Main12Intra"
        elif (constraints & profile_constraints_intra_mask) == (
            0|
                general_max_12bit_constraint_flag|
                general_max_10bit_constraint_flag|
                # general_max_8bit_constraint_flag |
                general_max_422chroma_constraint_flag|
                # general_max_420chroma_constraint_flag |
                # general_max_monochrome_constraint_flag |
                general_intra_constraint_flag|
                # general_one_picture_only_constraint_flag |
                # general_lower_bit_rate_constraint_flag |
                0) :
            profile = "Main10Intra-422"
        elif (constraints & profile_constraints_intra_mask) == (
            0|
                general_max_12bit_constraint_flag|
                # general_max_10bit_constraint_flag |
                # general_max_8bit_constraint_flag |
                general_max_422chroma_constraint_flag|
                # general_max_420chroma_constraint_flag |
                # general_max_monochrome_constraint_flag |
                general_intra_constraint_flag|
                # general_one_picture_only_constraint_flag |
                # general_lower_bit_rate_constraint_flag |
                0) :
            profile = "Main12Intra-422"
        elif (constraints & profile_constraints_intra_mask) == (
            0|
                general_max_12bit_constraint_flag|
                general_max_10bit_constraint_flag|
                general_max_8bit_constraint_flag|
                # general_max_422chroma_constraint_flag |
                # general_max_420chroma_constraint_flag |
                # general_max_monochrome_constraint_flag |
                general_intra_constraint_flag|
                # general_one_picture_only_constraint_flag |
                # general_lower_bit_rate_constraint_flag |
                0) :
            profile = "MainIntra-444"
        elif (constraints & profile_constraints_intra_mask) == (
            0|
                general_max_12bit_constraint_flag|
                general_max_10bit_constraint_flag|
                # general_max_8bit_constraint_flag |
                # general_max_422chroma_constraint_flag |
                # general_max_420chroma_constraint_flag |
                # general_max_monochrome_constraint_flag |
                general_intra_constraint_flag|
                # general_one_picture_only_constraint_flag |
                # general_lower_bit_rate_constraint_flag |
                0) :
            profile = "Main10Intra-444"
        elif (constraints & profile_constraints_intra_mask) == (
            0|
                general_max_12bit_constraint_flag|
                # general_max_10bit_constraint_flag |
                # general_max_8bit_constraint_flag |
                # general_max_422chroma_constraint_flag |
                # general_max_420chroma_constraint_flag |
                # general_max_monochrome_constraint_flag |
                general_intra_constraint_flag|
                # general_one_picture_only_constraint_flag |
                # general_lower_bit_rate_constraint_flag |
                0) :
            profile = "Main12Intra-444"
        elif (constraints & profile_constraints_intra_mask) == (
            0|
                # general_max_12bit_constraint_flag |
                # general_max_10bit_constraint_flag |
                # general_max_8bit_constraint_flag |
                # general_max_422chroma_constraint_flag |
                # general_max_420chroma_constraint_flag |
                # general_max_monochrome_constraint_flag |
                general_intra_constraint_flag|
                # general_one_picture_only_constraint_flag |
                # general_lower_bit_rate_constraint_flag |
                0) :
            profile = "Main16Intra-444"
        elif (constraints & profile_constraints_still_mask) == (
            0|
                general_max_12bit_constraint_flag|
                general_max_10bit_constraint_flag|
                general_max_8bit_constraint_flag|
                # general_max_422chroma_constraint_flag |
                # general_max_420chroma_constraint_flag |
                # general_max_monochrome_constraint_flag |
                general_intra_constraint_flag|
                general_one_picture_only_constraint_flag|
                # general_lower_bit_rate_constraint_flag |
                0) :
            profile = "MainStillPicture-444"
        elif (constraints & profile_constraints_still_mask) == (
            0|
                # general_max_12bit_constraint_flag |
                # general_max_10bit_constraint_flag |
                # general_max_8bit_constraint_flag |
                # general_max_422chroma_constraint_flag |
                # general_max_420chroma_constraint_flag |
                # general_max_monochrome_constraint_flag |
                general_intra_constraint_flag|
                general_one_picture_only_constraint_flag|
                # general_lower_bit_rate_constraint_flag |
                0) :
            profile = "Main16StillPicture-444"
        else :
            return "", ""
        
    elif profile_id ==  5:
        if (constraints & profile_constraints_mask) == (
            0|
                general_max_14bit_constraint_flag|
                general_max_12bit_constraint_flag|
                general_max_10bit_constraint_flag|
                general_max_8bit_constraint_flag|
                # general_max_422chroma_constraint_flag |
                # general_max_420chroma_constraint_flag |
                # general_max_monochrome_constraint_flag |
                # general_intra_constraint_flag |
                # general_one_picture_only_constraint_flag |
                general_lower_bit_rate_constraint_flag|
                0) :
            profile = "HighThroughput-444"
        elif (constraints & profile_constraints_mask) == (
            0|
                general_max_14bit_constraint_flag|
                general_max_12bit_constraint_flag|
                general_max_10bit_constraint_flag|
                # general_max_8bit_constraint_flag |
                # general_max_422chroma_constraint_flag |
                # general_max_420chroma_constraint_flag |
                # general_max_monochrome_constraint_flag |
                # general_intra_constraint_flag |
                # general_one_picture_only_constraint_flag |
                general_lower_bit_rate_constraint_flag|
                0) :
            profile = "HighThroughput10-444"
        elif (constraints & profile_constraints_mask) == (
            0|
                general_max_14bit_constraint_flag|
                # general_max_12bit_constraint_flag |
                # general_max_10bit_constraint_flag |
                # general_max_8bit_constraint_flag |
                # general_max_422chroma_constraint_flag |
                # general_max_420chroma_constraint_flag |
                # general_max_monochrome_constraint_flag |
                # general_intra_constraint_flag |
                # general_one_picture_only_constraint_flag |
                general_lower_bit_rate_constraint_flag|
                0) :
            profile = "HighThroughput14-444"
        elif (constraints & profile_constraints_intra_mask) == (
            0|
                # general_max_14bit_constraint_flag |
                # general_max_12bit_constraint_flag |
                # general_max_10bit_constraint_flag |
                # general_max_8bit_constraint_flag |
                # general_max_422chroma_constraint_flag |
                # general_max_420chroma_constraint_flag |
                # general_max_monochrome_constraint_flag |
                general_intra_constraint_flag|
                # general_one_picture_only_constraint_flag |
                # general_lower_bit_rate_constraint_flag |
                0) :
            profile = "HighThroughput16Intra-444"
        else :
            return "", ""
        
    elif profile_id ==  9:
        if (constraints & profile_constraints_mask) == (
            0|
                general_max_14bit_constraint_flag|
                general_max_12bit_constraint_flag|
                general_max_10bit_constraint_flag|
                general_max_8bit_constraint_flag|
                general_max_422chroma_constraint_flag|
                general_max_420chroma_constraint_flag|
                # general_max_monochrome_constraint_flag |
                # general_intra_constraint_flag |
                # general_one_picture_only_constraint_flag |
                general_lower_bit_rate_constraint_flag|
                0) :
            profile = "ScreenExtendedMain"
        elif (constraints & profile_constraints_mask) == (
            0|
                general_max_14bit_constraint_flag|
                general_max_12bit_constraint_flag|
                general_max_10bit_constraint_flag|
                #  general_max_8bit_constraint_flag |
                general_max_422chroma_constraint_flag|
                general_max_420chroma_constraint_flag|
                # general_max_monochrome_constraint_flag |
                # general_intra_constraint_flag |
                # general_one_picture_only_constraint_flag |
                general_lower_bit_rate_constraint_flag|
                0) :
            profile = "ScreenExtendedMain10"
        elif (constraints & profile_constraints_mask) == (
            0|
                general_max_14bit_constraint_flag|
                general_max_12bit_constraint_flag|
                general_max_10bit_constraint_flag|
                general_max_8bit_constraint_flag|
                # general_max_422chroma_constraint_flag |
                # general_max_420chroma_constraint_flag |
                # general_max_monochrome_constraint_flag |
                # general_intra_constraint_flag |
                # general_one_picture_only_constraint_flag |
                general_lower_bit_rate_constraint_flag|
                0) :
            profile = "ScreenExtendedMain-444"
        elif (constraints & profile_constraints_mask) == (
            0|
                general_max_14bit_constraint_flag|
                general_max_12bit_constraint_flag|
                general_max_10bit_constraint_flag|
                # general_max_8bit_constraint_flag |
                # general_max_422chroma_constraint_flag |
                # general_max_420chroma_constraint_flag |
                # general_max_monochrome_constraint_flag |
                # general_intra_constraint_flag |
                # general_one_picture_only_constraint_flag |
                general_lower_bit_rate_constraint_flag|
                0) :
            profile = "ScreenExtendedMain10-444"
        else :
            return "", ""
        
    elif profile_id ==  11:
        if (constraints & profile_constraints_mask) == (
            0|
                general_max_14bit_constraint_flag|
                general_max_12bit_constraint_flag|
                general_max_10bit_constraint_flag|
                general_max_8bit_constraint_flag|
                # general_max_422chroma_constraint_flag |
                # general_max_420chroma_constraint_flag |
                # general_max_monochrome_constraint_flag |
                # general_intra_constraint_flag |
                # general_one_picture_only_constraint_flag |
                general_lower_bit_rate_constraint_flag|
                0) :
            profile = "ScreenExtendedHighThroughput-444"
        elif (constraints & profile_constraints_mask) == (
            0|
                general_max_14bit_constraint_flag|
                general_max_12bit_constraint_flag|
                general_max_10bit_constraint_flag|
                # general_max_8bit_constraint_flag |
                # general_max_422chroma_constraint_flag |
                # general_max_420chroma_constraint_flag |
                # general_max_monochrome_constraint_flag |
                # general_intra_constraint_flag |
                # general_one_picture_only_constraint_flag |
                general_lower_bit_rate_constraint_flag|
                0) :
            profile = "ScreenExtendedHighThroughput10-444"
        elif (constraints & profile_constraints_mask) == (
            0|
                general_max_14bit_constraint_flag|
                # general_max_12bit_constraint_flag |
                # general_max_10bit_constraint_flag |
                # general_max_8bit_constraint_flag |
                # general_max_422chroma_constraint_flag |
                # general_max_420chroma_constraint_flag |
                # general_max_monochrome_constraint_flag |
                # general_intra_constraint_flag |
                # general_one_picture_only_constraint_flag |
                general_lower_bit_rate_constraint_flag|
                0) :
            profile = "ScreenExtendedHighThroughput14-444"
        else :
            return "", ""
    else:
        return "", ""
    
    if tier_flag == 0:
        if level_id == 30:
            level = "Main-1"
        elif level_id == 60:
            level = "Main-2"
        elif level_id == 63:
            level = "Main-2.1"
        elif level_id == 90:
            level = "Main-3"
        elif level_id == 93:
            level = "Main-3.1"
        elif level_id == 120:
            level = "Main-4"
        elif level_id == 123:
            level = "Main-4.1"
        elif level_id == 150:
            level = "Main-5"
        elif level_id == 153:
            level = "Main-5.1"
        elif level_id == 156:
            level = "Main-5.2"
        elif level_id == 180:
            level = "Main-6"
        elif level_id == 183:
            level = "Main-6.1"
        elif level_id == 186:
            level = "Main-6.2"
        else:
            return "", ""
    else:
        if level_id == 30:
            level = "High-1"
        elif level_id == 60:
            level = "High-2"
        elif level_id == 63:
            level = "High-2.1"
        elif level_id == 90:
            level = "High-3"
        elif level_id == 93:
            level = "High-3.1"
        elif level_id == 120:
            level = "High-4"
        elif level_id == 123:
            level = "High-4.1"
        elif level_id == 150:
            level = "High-5"
        elif level_id == 153:
            level = "High-5.1"
        elif level_id == 156:
            level = "High-5.2"
        elif level_id == 180:
            level = "High-6"
        elif level_id == 183:
            level = "High-6.1"
        elif level_id == 186:
            level = "High-6.2"
        elif level_id == 255:
            level = "High-8.5"
        else:
            return "", ""

    return profile, level
    