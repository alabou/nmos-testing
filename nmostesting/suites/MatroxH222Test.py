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

from .MatroxCapabilitiesTest import AttributeLayer
from .MatroxCapabilitiesTest import AttributeLayerCompatibilityGroups
from .MatroxCapabilitiesTest import AttributeReceiverId
from .MatroxCapabilitiesTest import AttributeSynchronousMedia
from .MatroxCapabilitiesTest import AttributeParameterSetsTransportMode
from .MatroxCapabilitiesTest import AttributeParameterSetsFlowMode
from .MatroxCapabilitiesTest import AttributeAudioLayers
from .MatroxCapabilitiesTest import AttributeVideoLayers
from .MatroxCapabilitiesTest import AttributeDataLayers
from .MatroxCapabilitiesTest import AttributeConstantBitRate

from .MatroxCapabilitiesTest import CapFormatVideoLayers
from .MatroxCapabilitiesTest import CapFormatAudioLayers
from .MatroxCapabilitiesTest import CapFormatDataLayers
from .MatroxCapabilitiesTest import CapMetaFormat
from .MatroxCapabilitiesTest import CapMetaLayer
from .MatroxCapabilitiesTest import CapMetaLayerCompatibilityGroups

NODE_API_KEY = "node"
CONNECTION_API_KEY = "connection"
FLOW_REGISTER_KEY = "flow-register"
SENDER_REGISTER_KEY = "sender-register"

AttributeReceiverId = "urn:x-matrox:receiver_id"
AttributeLayer = "urn:x-matrox:layer"
AttributeLayerCompatibilityGroups = "urn:x-matrox:layer_compatibility_groups"
AttributeAudioLayers = "urn:x-matrox:audio_layers"
AttributeVideoLayers = "urn:x-matrox:video_layers"
AttributeDataLayers = "urn:x-matrox:data_layers"

media_type_constraint = "urn:x-nmos:cap:format:media_type"

class MatroxH222Test(GenericTest):
    """
    Runs Node Tests covering 'Matrox With H222.0'
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
        """MPEG2-TS Flows have the required attributes"""

        self.do_test_node_api_v1_3(test)

        reg_api = self.apis[FLOW_REGISTER_KEY]

        valid, result = self.get_is04_resources("flows")
        if not valid:
            return test.FAIL(result)

        valid, result = self.get_is04_resources("sources")
        if not valid:
            return test.FAIL(result)

        reg_path = reg_api["spec_path"] + "/flow-attributes"
        reg_schema = load_resolved_schema(reg_path, "flow_data_register.json", path_prefix=False)

        flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"].values()}
        source_map = {source["id"]: source for source in self.is04_resources["sources"].values()}

        try:
            mp2t_flows = [flow for flow in self.is04_resources["flows"].values() if flow["format"] == "urn:x-nmos:format:mux"
                                                                 and flow["media_type"] in ("application/MP2T", "application/mp2t")]
            for flow in mp2t_flows:

                # Make sure flow matches the requirements of the JSON schemas from the Flow Parameter Register
                try:
                    self.validate_schema(flow, reg_schema)
                except ValidationError as e:
                    return test.FAIL("flow {} does not comply with the schema for Data Flow additional and "
                                     "extensible attributes defined in the NMOS Parameter Registers: "
                                     "{}".format(flow["id"], str(e)),
                                     "https://specs.amwa.tv/nmos-parameter-registers/branches/{}"
                                     "/flow-attributes/flow_data_register.html"
                                     .format(reg_api["spec_branch"]))

                # MUST have a source of same type
                parent_flow_source_id = flow["source_id"]
                if parent_flow_source_id not in source_map:
                    return test.FAIL("flow {}: has invalid associated source {}".format(flow["id"], parent_flow_source_id))
                parent_flow_source = source_map[parent_flow_source_id]

                if parent_flow_source["format"] != flow["format"]:
                    return test.FAIL("flow {}: MUST have an associated source {} of the same 'format'".format(flow["id"], parent_flow_source["id"]))

                if AttributeLayer in flow:
                    return test.FAIL("flow {}: MUST NOT have a 'layer' attribute.".format(flow["id"]))

                # Check for other required attributes. The value of those attributes is tested in Matrox-Capabilities test suite
                if AttributeAudioLayers not in flow:
                    return test.FAIL("flow {}: MUST have the 'audio_layers' attribute.".format(flow["id"]))
                if AttributeVideoLayers not in flow:
                    return test.FAIL("flow {}: MUST have the 'video_layers' attribute.".format(flow["id"]))
                if AttributeDataLayers not in flow:
                    return test.FAIL("flow {}: MUST have the 'data_layers' attribute.".format(flow["id"]))

                for parent_flow_id in flow["parents"]:
                    if parent_flow_id not in flow_map:
                        return test.FAIL("flow {}: has an invalid parent flow {}".format(flow["id"], parent_flow_id))
                    parent_flow = flow_map[parent_flow_id]

                    parent_source_id = parent_flow["source_id"]
                    if parent_source_id not in parent_flow_source["parents"]:
                        return test.FAIL("source {}: has invalid parent source {}".format(parent_flow_source["id"], parent_source_id))
                    parent_source = source_map[parent_source_id]

                    # parent flow cannot be of format mux
                    if parent_flow["format"] not in ("urn:x-nmos:format:audio", "urn:x-nmos:format:video", "urn:x-nmos:format:data"):
                        return test.FAIL("parent flow {}: MUST have a 'format' of 'urn:x-nmos:format:audio', 'urn:x-nmos:format:video' or 'urn:x-nmos:format:data'".format(parent_flow["id"]))
                    if parent_flow["format"] != parent_source["format"]:
                        return test.FAIL("parent source {} and parent flow {}: MUST have the same 'format'".format(parent_source["id"], parent_flow["id"]))
                    if parent_source_id not in parent_flow_source["parents"]:
                        return test.FAIL("source {}: MUST have a parent for each sub-flow".format(parent_flow_source["id"]))

                    # The full testing of the values of the layer attribute is done in Matrox-Capabilities test suite
                    if AttributeLayer not in parent_flow:
                        return test.FAIL("parent flow {}: MUST have a 'layer' attribute.".format(parent_flow["id"]))

                    if AttributeAudioLayers in parent_flow:
                        return test.FAIL("parent flow {}: MUST NOT have the 'audio_layers' attribute.".format(parent_flow["id"]))
                    if AttributeVideoLayers in parent_flow:
                        return test.FAIL("parent flow {}: MUST NOT have the 'video_layers' attribute.".format(parent_flow["id"]))
                    if AttributeDataLayers in parent_flow:
                        return test.FAIL("parent flow {}: MUST NOT have the 'data_layers' attribute.".format(parent_flow["id"]))

                    # special cases for audio sub-flows
                    if parent_flow["format"] == "urn:x-nmos:format:audio":
                        if parent_flow["media_type"] in ("audio/L16", "audio/L20", "audio/L24", "audio/AM824"):
                            parent_flow_source_id = parent_flow["source_id"]
                            if parent_flow_source_id not in source_map:
                                return test.FAIL("parent flow {}: source id {} not found".format(parent_flow["id"]), parent_flow_source_id)
                            parent_flow_source = source_map[parent_flow_source_id]
                            if "channels" not in parent_flow_source:
                                return test.FAIL("source {}: MUST indicate the 'channels' attribute.".format(parent_flow_source["id"]))
                            if parent_flow_source["channels"] & 1 != 0:
                                return test.FAIL("source {}: 'channels' attribute MUST be an even number.".format(parent_flow_source["id"]))

            if len(mp2t_flows) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No MPEG2-TS Flow resources were found on the Node")

    def test_03(self, test):
        """MPEG2-TS Sources have the required attributes"""

        self.do_test_node_api_v1_3(test)

        for resource_type in ["flows", "sources", "receivers"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        source_map = {source["id"]: source for source in self.is04_resources["sources"].values()}
        flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"].values()}
        receiver_map = {receiver["id"]: receiver for receiver in self.is04_resources["receivers"].values()}

        try:
            # get mp2t sources from mp2t flows
            mp2t_flows = [flow for flow in self.is04_resources["flows"].values() if flow["format"] == "urn:x-nmos:format:mux"
                                               and flow["media_type"] in ("application/MP2T", "application/mp2t")]
            for flow in mp2t_flows:

                source_id = flow["source_id"]

                if not source_id in source_map:
                    return test.FAIL("flow {}: associated source {} is invalid".format(flow["id"], source_id))
                
                source = source_map[source_id]

                if source["format"] != "urn:x-nmos:format:mux":
                    return test.FAIL("source {}: MUST indicate 'format' with value 'urn:x-nmos:format:mux'"
                                     .format(source["id"]))

                # source and flow must have same number of parents .. if mux not fully described len is 0
                if len(source["parents"]) != len(flow["parents"]):
                    return test.FAIL("source {}: MUST have the same number of parents as its associated Flow"
                                     .format(source["id"]))

                # sub-Flow source must be in this source's parents
                for parent_flow_id in flow["parents"]:
                    if parent_flow_id not in flow_map:
                        return test.FAIL("flow {}: has an invalid parent flow {}".format(flow["id"], parent_flow_id))
                    parent_flow = flow_map[parent_flow_id]

                    parent_source_id = parent_flow["source_id"]
                    if parent_source_id not in source["parents"]:
                        return test.FAIL("source {}: has invalid parent source {}".format(source["id"], parent_source_id))
                    parent_source = source_map[parent_source_id]

                    # parent flow cannot be of format mux
                    if parent_flow["format"] not in ("urn:x-nmos:format:audio", "urn:x-nmos:format:video", "urn:x-nmos:format:data"):
                        return test.FAIL("parent flow {}: MUST have a 'format' of 'urn:x-nmos:format:audio', 'urn:x-nmos:format:video' or 'urn:x-nmos:format:data'".format(parent_flow["id"]))
                    if parent_flow["format"] != parent_source["format"]:
                        return test.FAIL("parent source {} and parent flow {}: MUST have the same 'format'".format(parent_source["id"], parent_flow["id"]))
                    if parent_source_id not in source["parents"]:
                        return test.FAIL("source {}: MUST have a parent for each sub-flow".format(source["id"]))
                    
            # get sources that are not mux
            non_mux_sources = [source for source in self.is04_resources["sources"].values() if source["format"] in ("urn:x-nmos:format:audio", "urn:x-nmos:format:video", "urn:x-nmos:format:data")]
            for source in non_mux_sources:
                # receiver_id is optional, it can be unspecified or null
                if AttributeReceiverId in source and source[AttributeReceiverId]:
                    receiver_id = source[AttributeReceiverId]
                    if receiver_id not in receiver_map:
                        return test.FAIL("source {}: receiver_id {} does not correspond to a valid Receiver".format(source["id"], receiver_id))
                    receiver = receiver_map[receiver_id]
                    if receiver["format"] == "urn:x-nmos:format:mux":
                        # must have a layer attribute
                        if AttributeLayer not in source or source[AtributeLayer] < 0:
                            return test.FAIL("source {}: MUST indicate the 'layer' attribute.".format(source["id"]))

            # no mux Flows also means no mux Sources
            if len(mp2t_flows) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No MPGE2-TS Flow/Source resources were found on the Node")

    def test_04(self, test):
        """MPEG2-TS Senders have the required attributes"""

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
            # opaque MPEG2-TS senders are not covered by this specification and ignored.
            mp2t_senders = [sender for sender in self.is04_resources["senders"].values() if sender["flow_id"]
                            and sender["flow_id"] in flow_map
                            and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:mux"
                            and flow_map[sender["flow_id"]]["media_type"] in ("application/MP2T", "application/mp2t")]

            warn_message = ""

            for sender in mp2t_senders:

                # check values of all additional attributes against the JSON schemas of the Sender Parameter Register
                try:
                    self.validate_schema(sender, reg_schema)
                except ValidationError as e:
                    return test.FAIL("sender {}: does not comply with the schema for Sender additional and "
                                     "extensible attributes defined in the NMOS Parameter Registers: "
                                     "{}".format(sender["id"], str(e)),
                                     "https://specs.amwa.tv/nmos-parameter-registers/branches/{}"
                                     "/sender-attributes/sender_register.html"
                                     .format(reg_api["spec_branch"]))

                # check the associated flow media_type based on the sender transport (from Flow requirement)
                if "transport" in sender:
                    flow_id = sender["flow_id"]
                    if flow_id not in flow_map:
                        return test.FAIL("sender {}: has an invalid associated flow {}".format(sender["id"], flow_id))
                    flow = flow_map[flow_id]
                    if sender["transport"].startswith("urn:x-nmos:transport:rtp") or sender["transport"] == "urn:x-nmos:transport:srt.rtp":
                        if flow["media_type"] != "application/MP2T":
                            return test.FAIL("flow {}: MUST indicate media_type 'application/MP2T' for RTP based transport.".format(flow["id"]))
                    else:
                        if flow["media_type"] != "application/mp2t":
                            return test.FAIL("flow {}: MUST indicate media_type 'application/mp2t' for non-RTP based transport.".format(flow["id"]))

                # MUST to expose capabilities for the mux
                if "constraint_sets" in sender["caps"]:

                    # make sure sender capabilities are not confused with receivers ones
                    if "media_types" in sender["caps"] or "event_types" in sender["caps"]:
                        return test.FAIL("sender {}: capabilities MUST NOT have 'media_types' or 'event_types' attributes that are specific to receivers".format(sender["id"]))

                    # discard constraints sets that are known to not be MPEG2-TS from the media_type
                    mp2t_constraint_sets = []
                    
                    for constraint_set in sender["caps"]["constraint_sets"]:
                        # reject based on media_type
                        if (media_type_constraint in constraint_set and "enum" in constraint_set[media_type_constraint] 
                                and not "application/MP2T" in constraint_set[media_type_constraint]["enum"]
                                and not "application/mp2t" in constraint_set[media_type_constraint]["enum"]):
                            continue

                        # reject based on sub-Flow rules
                        if CapMetaFormat in constraint_set or CapMetaLayer in constraint_set:
                            continue

                        mp2t_constraint_sets.append(constraint_set)

                    # the Matrox-Capabilities test suite will perform thorough testing of the values of the constraints
                    if not mp2t_constraint_sets:
                        return test.FAIL("sender {}: MUST declare its capabilities for the mux".format(sender["id"]))
                else:
                    warn_message += "|" + "sender {}: SHOULD declare its capabilities".format(sender["id"])

                # mux sender must not expose the parameter_sets_flow_mode and parameter_sets_transport_mode  attributes
                if AttributeParameterSetsFlowMode in sender or AttributeParameterSetsTransportMode in sender:
                    return test.FAIL("sender {}: MUST NOT expose the 'parameter_sets_flow_mode' or 'parameter_sets_transport_mode' attributes".format(sender["id"]))

            if len(mp2t_senders) > 0:
                if warn_message != "":
                    return test.WARNING(warn_message)
                else:
                    return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No MPEG2-TS Sender resources were found on the Node")

    def test_05(self, test):
        """MPEG2-TS Sender manifests have the required parameters"""

        self.do_test_node_api_v1_3(test)

        for resource_type in ["senders", "flows"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"].values()}

        try:
            mp2t_senders = [sender for sender in self.is04_resources["senders"].values() if sender["flow_id"]
                            and sender["flow_id"] in flow_map
                            and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:mux"
                            and flow_map[sender["flow_id"]]["media_type"] in("application/MP2T","application/mp2t")]

            access_error = False

            for sender in mp2t_senders:

                if "transport" not in sender:
                    return test.FAIL("sender {}: MUST indicate the 'transport' attribute."
                                     .format(sender["id"]))

                rtp_based_transport = False

                if sender["transport"].startswith("urn:x-nmos:transport:rtp") or sender["transport"] == "urn:x-nmos:transport:srt.rtp":
                    rtp_based_transport = True
                else:
                    rtp_based_transport = False

                if "manifest_href" not in sender:
                    return test.FAIL("sender {}: MUST indicate the 'manifest_href' attribute."
                                    .format(sender["id"]))

                # For RTP based transport the manifest is required ... but it could be available 
                # only once the sender is activated such that the same rules apply for non-RTP 
                # based transport that may or not use a manifest. Actually there is nothing special 
                # in the manifest for MPEG2-TS senders.
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
                sdp_lines = [sdp_line.replace("\r", "") for sdp_line in sdp.split("\n")]

                found_media = 0
                for sdp_line in sdp_lines:
                    media = re.search(r"^m=(.+) (.+) (.+) (.+)$", sdp_line)
                    if not media:
                        continue
                    found_media += 1

                    if rtp_based_transport and media.group(1) != "video":
                        return test.FAIL("sender {}: SDP transport file <media> MUST be 'video'".format(sender["id"]))
                    
                    if not rtp_based_transport and media.group(1) != "application":
                        return test.FAIL("sender {}: SDP transport file <media> MUST be 'application'".format(sender["id"]))

                if found_media == 0:
                    return test.FAIL("SDP for sender {}: is missing a media description line".format(sender["id"]))

                if found_media > 2:
                    return test.FAIL("SDP for sender {}: at most two media description lines MUST be used with redundancy".format(sender["id"]))

            if access_error:
                return test.UNCLEAR("One or more of the tested Senders had null or empty 'manifest_href' or "
                                    "returned a 404 HTTP code. Please ensure all Senders are enabled and re-test.")

            if len(mp2t_senders) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No MPEG2-TS Sender resources were found on the Node")

    def test_06(self, test):
        """MPEG2-TS Receivers have the required attributes"""

        self.do_test_node_api_v1_3(test)

        valid, result = self.get_is04_resources("receivers")
        if not valid:
            return test.FAIL(result)

        recommended_constraints = {
        }

        try:
            mp2t_receivers = [receiver for receiver in self.is04_resources["receivers"].values()
                              if receiver["format"] == "urn:x-nmos:format:mux"
                              and "media_types" in receiver["caps"]
                              and ("application/mp2t" in receiver["caps"]["media_types"] or "application/MP2T" in receiver["caps"]["media_types"])]

            mp2t_receivers_ids = [receiver["id"] for receiver in mp2t_receivers]

            # mux receivers identified by transport
            for receiver in [receiver for receiver in self.is04_resources["receivers"].values() if receiver["format"] == "urn:x-nmos:format:mux"]:
                if receiver["transport"] in ("urn:x-matrox:transport:srt", "urn:x-matrox:transport:srt.mp2t") or receiver["transport"].startswith("urn:x-matrox:transport:udp"):
                    if receiver["id"] not in mp2t_receivers_ids:
                        return test.FAIL("receiver {}: of `mux` format MUST have 'media_types' set to 'application/MP2T' or 'application/mp2t'.".format(receiver["id"]))
                        
            # non-mux receivers
            for receiver in [receiver for receiver in self.is04_resources["receivers"].values() if receiver["format"] != "urn:x-nmos:format:mux"]:
                if "constraint_sets" in receiver["caps"]:
                    for constraint_set in receiver["caps"]["constraint_sets"]:
                        if media_type_constraint in constraint_set:
                            if  "enum" in constraint_set[media_type_constraint]:
                                if  "application/MP2T" in constraint_set[media_type_constraint]["enum"] or "application/mp2t" in constraint_set[media_type_constraint]["enum"]:
                                    return test.FAIL("receiver {}: of `audio`, 'video' or `data` format MUST NOT have constraint sets having 'media_type' set to 'application/MP2T' or 'application/mp2t'.".format(receiver["id"]))

            warn_message = ""

            for receiver in mp2t_receivers:

                # check required attributes are present
                if "transport" not in receiver:
                    return test.FAIL("receiver {}: MUST indicate the 'transport' attribute."
                                     .format(receiver["id"]))

                if "constraint_sets" not in receiver["caps"]:
                    return test.FAIL("receiver {}: MUST indicate constraints in accordance with BCP-004-01 using "
                                     "the 'caps' attribute 'constraint_sets'.".format(receiver["id"]))

                # discard constraints sets that are known to not be MPEG2-TS from the media_type
                mp2t_constraint_sets = []
                
                for constraint_set in receiver["caps"]["constraint_sets"]:
                    # reject based on media_type
                    if (media_type_constraint in constraint_set and "enum" in constraint_set[media_type_constraint] 
                            and not "application/MP2T" in constraint_set[media_type_constraint]["enum"]
                            and not "application/mp2t" in constraint_set[media_type_constraint]["enum"]):
                        continue

                    # reject based on sub-Flow rules
                    if CapMetaFormat in constraint_set or CapMetaLayer in constraint_set:
                        continue

                    mp2t_constraint_sets.append(constraint_set)

                if len(mp2t_constraint_sets) == 0:
                    return test.FAIL("receiver {}: MUST indicate constraints in accordance with BCP-004-01 using "
                                     "the 'caps' attribute 'constraint_sets'.".format(receiver["id"]))

                # check recommended attributes are present
                for constraint_set in mp2t_constraint_sets:
                    for constraint, target in recommended_constraints.items():
                        if constraint not in constraint_set:
                                warn_message += "|" + "receiver {}: SHOULD indicate the supported {} using the " \
                                               "'{}' parameter constraint.".format(receiver["id"], target, constraint)
            if warn_message != "":
                return test.WARNING(warn_message)

            if len(mp2t_receivers) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No MPEG2-TS Receiver resources were found on the Node")

    def test_07(self, test):
        """MPEG2-TS Receiver parameter constraints have valid values"""

        self.do_test_node_api_v1_3(test)

        valid, result = self.get_is04_resources("receivers")
        if not valid:
            return test.FAIL(result)

        flow_reg_path = self.apis[FLOW_REGISTER_KEY]["spec_path"] + "/flow-attributes"
        mp2t_properties = load_resolved_schema(flow_reg_path, "flow_data_register.json",
                                               path_prefix=False)["properties"]
        sender_path = self.apis[SENDER_REGISTER_KEY]["spec_path"] + "/sender-attributes"
        sender_properties = load_resolved_schema(sender_path, "sender_register.json",
                                                 path_prefix=False)["properties"]

        try:
            mp2t_receivers = [receiver for receiver in self.is04_resources["receivers"].values()
                              if receiver["format"] == "urn:x-nmos:format:mux"
                              and "media_types" in receiver["caps"]
                              and ("application/mp2t" in receiver["caps"]["media_types"] or "application/MP2T" in receiver["caps"]["media_types"])]

            warn_message = ""

            for receiver in mp2t_receivers:

                # check required attributes are present
                if "constraint_sets" not in receiver["caps"]:
                    return test.FAIL("Receiver {} MUST indicate constraints in accordance with BCP-004-01 using "
                                     "the 'caps' attribute 'constraint_sets'.".format(receiver["id"]))

                # discard constraints sets that are known to not be MPEG2-TS from the media_type
                mp2t_constraint_sets = []
                
                for constraint_set in receiver["caps"]["constraint_sets"]:
                    # reject based on media_type
                    if (media_type_constraint in constraint_set and "enum" in constraint_set[media_type_constraint] 
                            and not "application/MP2T" in constraint_set[media_type_constraint]["enum"]
                            and not "application/mp2t" in constraint_set[media_type_constraint]["enum"]):
                        continue

                    # reject based on sub-Flow rules
                    if CapMetaFormat in constraint_set or CapMetaLayer in constraint_set:
                        continue

                    mp2t_constraint_sets.append(constraint_set)

                if len(mp2t_constraint_sets) == 0:
                    return test.FAIL("receiver {}: MUST indicate constraints in accordance with BCP-004-01 using "
                                     "the 'caps' attribute 'constraint_sets'.".format(receiver["id"]))


                # check recommended attributes are present
                for constraint_set in mp2t_constraint_sets:
                    pass # TODO

            if len(mp2t_receivers) > 0:
                if warn_message != "":
                    return test.WARNING(warn_message)
                else:
                    return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No MPEG2-TS Receiver resources were found on the Node")

    def do_test_node_api_v1_3(self, test):
        """
        Precondition check of the API version.
        Raises an NMOSTestException when the Node API version is less than v1.3
        """
        api = self.apis[NODE_API_KEY]
        if self.is04_utils.compare_api_version(api["version"], "v1.3") < 0:
            raise NMOSTestException(test.NA("This test cannot be run against Node API below version v1.3."))

