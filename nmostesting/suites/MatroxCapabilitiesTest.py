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
import os

from jsonschema import ValidationError

from ..GenericTest import GenericTest, NMOSTestException
from ..IS04Utils import IS04Utils
from ..IS05Utils import IS05Utils
from ..TestHelper import load_resolved_schema
from ..TestHelper import check_content_type

from .MatroxTransportsTest import getFormatFromTransport

from urllib.parse import urlparse
from pathlib import Path

NODE_API_KEY = "node"
CONNECTION_API_KEY = "connection"
RECEIVER_CAPS_KEY = "receiver-caps"

FormatVideo                             = "urn:x-nmos:format:video"
FormatAudio                             = "urn:x-nmos:format:audio"
FormatData                              = "urn:x-nmos:format:data"
FormatDataEvent                         = "urn:x-nmos:format:data.event"
FormatMux                               = "urn:x-nmos:format:mux"
FormatUnknown                           = "urn:x-nmos:format:UNKNOWN"

CapFormatMediaType                      = "urn:x-nmos:cap:format:media_type"
CapFormatEventType                      = "urn:x-nmos:cap:format:event_type"
CapFormatGrainRate                      = "urn:x-nmos:cap:format:grain_rate"
CapFormatFrameWidth                     = "urn:x-nmos:cap:format:frame_width"
CapFormatFrameHeight                    = "urn:x-nmos:cap:format:frame_height"
CapFormatInterlaceMode                  = "urn:x-nmos:cap:format:interlace_mode"
CapFormatColorspace                     = "urn:x-nmos:cap:format:colorspace"
CapFormatTransferCharacteristic         = "urn:x-nmos:cap:format:transfer_characteristic"
CapFormatColorSampling                  = "urn:x-nmos:cap:format:color_sampling"
CapFormatComponentDepth                 = "urn:x-nmos:cap:format:component_depth"
CapFormatChannelCount                   = "urn:x-nmos:cap:format:channel_count"
CapFormatSampleRate                     = "urn:x-nmos:cap:format:sample_rate"
CapFormatSampleDepth                    = "urn:x-nmos:cap:format:sample_depth"
CapFormatBitRate                        = "urn:x-nmos:cap:format:bit_rate"
CapFormatProfile                        = "urn:x-nmos:cap:format:profile"
CapFormatLevel                          = "urn:x-nmos:cap:format:level"
CapFormatSublevel                       = "urn:x-nmos:cap:format:sublevel"
CapFormatConstantBitRate                = "urn:x-matrox:cap:format:constant_bit_rate"
CapFormatVideoLayers                    = "urn:x-matrox:cap:format:video_layers"
CapFormatAudioLayers                    = "urn:x-matrox:cap:format:audio_layers"
CapFormatDataLayers                     = "urn:x-matrox:cap:format:data_layers"
CapTransportBitRate                     = "urn:x-nmos:cap:transport:bit_rate"
CapTransportPacketTime                  = "urn:x-nmos:cap:transport:packet_time"
CapTransportMaxPacketTtime              = "urn:x-nmos:cap:transport:max_packet_time"
CapTransportSenderType                  = "urn:x-nmos:cap:transport:st2110_21_sender_type"
CapTransportPacketTransmissionMode      = "urn:x-nmos:cap:transport:packet_transmission_mode"
CapTransportParameterSetsFlowMode       = "urn:x-matrox:cap:transport:parameter_sets_flow_mode"
CapTransportParameterSetsTransportMode  = "urn:x-matrox:cap:transport:parameter_sets_transport_mode"
CapTransportChannelOrder                = "urn:x-matrox:cap:transport:channel_order"
CapTransportHKEP                        = "urn:x-matrox:cap:transport:hkep"
CapTransportPrivacy                     = "urn:x-matrox:cap:transport:privacy"
CapTransportClockRefType                = "urn:x-matrox:cap:transport:clock_ref_type"
CapTransportInfoBlock                   = "urn:x-matrox:cap:transport:info_block"
CapTransportSynchronousMedia            = "urn:x-matrox:cap:transport:synchronous_media"

CapMetaLabel                            = "urn:x-nmos:cap:meta:label"
CapMetaFormat                           = "urn:x-matrox:cap:meta:format"
CapMetaLayer                            = "urn:x-matrox:cap:meta:layer"
CapMetaLayerCompatibilityGroups         = "urn:x-matrox:cap:meta:layer_compatibility_groups"
CapMetaEnabled                          = "urn:x-nmos:cap:meta:enabled"
CapMetaPreference                       = "urn:x-nmos:cap:meta:preference"

AttributeLayer                          = "urn:x-matrox:layer"
AttributeLayerCompatibilityGroups       = "urn:x-matrox:layer_compatibility_groups"
AttributeReceiverId                     = "urn:x-matrox:receiver_id"
AttributeSynchronousMedia               = "urn:x-matrox:synchronous_media"
AttributeParameterSetsTransportMode     = "urn:x-matrox:parameter_sets_transport_mode"
AttributeParameterSetsFlowMode          = "urn:x-matrox:parameter_sets_flow_mode"

AttributeAudioLayers                    = "urn:x-matrox:audio_layers"
AttributeVideoLayers                    = "urn:x-matrox:video_layers"
AttributeDataLayers                     = "urn:x-matrox:data_layers"
AttributeConstantBitRate                = "urn:x-matrox:constant_bit_rate"

def is_consecutive_from_zero(a):
    # Check if the length of arr matches the max element + 1 and that all elements from 0 to max are present
    return sorted(a) == list(range(len(a)))

def append_if_not_exists(a, value):
    if value not in a:
        a.append(value)

class MatroxCapabilitiesTest(GenericTest):
    """
    Runs Node Tests covering Matrox capabilities
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

        """Check Receiver Capabilities"""

        api = self.apis[RECEIVER_CAPS_KEY]

        reg_api = self.apis["schemas"]
        reg_path = reg_api["spec_path"] + "/schemas"

        valid, result = self.get_is04_resources("receivers")
        if not valid:
            return test.FAIL(result)

        schema = load_resolved_schema(api["spec_path"], "receiver_constraint_sets.json")

        # workaround to load the Capabilities register schema as if with load_resolved_schema directly
        # but with the base_uri of the Receiver Capabilities schemas
        reg_schema_file = str(Path(os.path.abspath(reg_path)) / "is-04-constraint-set-schema.json")
        with open(reg_schema_file, "r") as f:
            reg_schema_obj = json.load(f)
        reg_schema = load_resolved_schema(api["spec_path"], schema_obj=reg_schema_obj)

        warning = None

        for receiver in self.is04_resources["receivers"].values():
            if "constraint_sets" in receiver["caps"]:
                try:
                    self.validate_schema(receiver, schema)
                except ValidationError as e:
                    return test.FAIL("Receiver {} does not comply with chema".format(receiver["id"]))

                layers = []

                for constraint_set in receiver["caps"]["constraint_sets"]:
                    try:
                        self.validate_schema(constraint_set, reg_schema)
                    except ValidationError as e:
                        return test.FAIL("Receiver {} constraint_sets do not comply with schema".format(receiver["id"]))

                    # unless the receiver is of format mux, sub-flow capabilities should not be used
                    if receiver["format"] != FormatMux:
                        if (CapMetaFormat in constraint_set) or (CapMetaLayer in constraint_set):
                            return test.FAIL("Receiver {} sub-Flow/sub-Stream are illegal for a Receiver of format {}".format(receiver["id"], receiver["format"]))
                    else:
                        if (CapMetaFormat in constraint_set) or (CapMetaLayer in constraint_set):
                            if (CapMetaFormat not in constraint_set) or (CapMetaLayer not in constraint_set):
                                return test.FAIL("Receiver {} sub-Flow/sub-Stream require both {} and {}".format(receiver["id"], CapMetaFormat, CapMetaLayer))
                            if CapFormatMediaType not in constraint_set or constraint_set[CapFormatMediaType] in receiver["caps"]["media_types"]:
                                warning = "Receiver {} sub-Flow/sub-Stream constraint_sets should have a media_type capability which is not part of the media_types array {}.".format(receiver["id"], receiver["caps"]["media_types"])
                            if constraint_set[CapMetaFormat] not in (FormatAudio, FormatVideo, FormatData):
                                warning = "Receiver {} sub-Flow/sub-Stream constraint_sets should have an audio, video or data format.".format(receiver["id"])
                            for param_constraint in constraint_set:
                                if param_constraint.startswith("urn:x-matrox:cap:transport:") or param_constraint.startswith("urn:x-nmos:cap:transport:"):
                                    return test.FAIL("Receiver {} sub-Flow/sub-Stream cannot have transport capabilities".format(receiver["id"]))
                                
                            append_if_not_exists(layers, constraint_set[CapMetaLayer]) # because of preferences alternatives
            else:
                warning = "Receiver {} not having constraint_sets".format(receiver["id"])

        if warning is not None:
            return test.WARNING(warning)
        else:
            return test.PASS()

    def getLayers(self, format, sender):

        flow_id = sender["flow_id"]

        if flow_id not in self.is04_resources["flows"]:
            return None
        
        flow = self.is04_resources["flows"][flow_id]

        if flow["format"] != FormatMux:
            return None

        layers = []

        for parent_id in flow["parents"]:

            if parent_id not in self.is04_resources["flows"]:
                raise NMOSTestException("parent flow not found")
            
            parent_flow = self.is04_resources["flows"][parent_id]

            if parent_flow["format"] != format:
                continue

            if AttributeLayer not in parent_flow:
                raise NMOSTestException("parent layer not found")

            layers.append(parent_flow[AttributeLayer])

        return layers            

    def getLayerCompatibilityGroups(self, format, layer, sender):

        flow_id = sender["flow_id"]

        if flow_id not in self.is04_resources["flows"]:
            return None
        
        flow = self.is04_resources["flows"][flow_id]

        if flow["format"] != FormatMux:
            return None

        layer_compatibility_groups = []
        intersection = 0xffffffffffffffff

        for parent_id in flow["parents"]:

            if parent_id not in self.is04_resources["flows"]:
                raise NMOSTestException("parent flow not found")
            
            parent_flow = self.is04_resources["flows"][parent_id]

            if parent_flow["format"] != format:
                continue

            if AttributeLayer not in parent_flow:
                raise NMOSTestException("parent layer not found")

            # for all layers
            if AttributeLayerCompatibilityGroups not in parent_flow:
                raise NMOSTestException("parent layer compatibility groups not found")

            groups = parent_flow[AttributeLayerCompatibilityGroups]
            mask = 0
            for v in groups:
                mask |= 1 << v
            mask = 0xffffffffffffffff ^ mask

            if intersection == 0xffffffffffffffff:
                intersection = mask
            else:
                intersection &= mask

            if (parent_flow[AttributeLayer] == layer):
                layer_compatibility_groups = parent_flow[AttributeLayerCompatibilityGroups]

        return layer_compatibility_groups, intersection

    def test_03(self, test):

        """Check Sender Capabilities"""

        api = self.apis[RECEIVER_CAPS_KEY] # same base schemas for both senders and receivers

        reg_api = self.apis["schemas"]
        reg_path = reg_api["spec_path"] + "/schemas"

        valid, result = self.get_is04_resources("senders")
        if not valid:
            return test.FAIL(result)

        valid, result = self.get_is04_resources("flows")
        if not valid:
            return test.FAIL(result)

        schema = load_resolved_schema(api["spec_path"], "receiver_constraint_sets.json") # same base schemas for both senders and receivers

        # workaround to load the Capabilities register schema as if with load_resolved_schema directly
        # but with the base_uri of the Receiver Capabilities schemas
        reg_schema_file = str(Path(os.path.abspath(reg_path)) / "is-04-constraint-set-schema.json")
        with open(reg_schema_file, "r") as f:
            reg_schema_obj = json.load(f)
        reg_schema = load_resolved_schema(api["spec_path"], schema_obj=reg_schema_obj)

        warning = None

        for sender in self.is04_resources["senders"].values():

            # Make sure Senders do not use the Receiver's specific "media_types" attribute in their caps
            if "media_types" in sender["caps"]:
                return test.FAIL("Sender {} has an illegal 'media_types' attribute in its caps".format(sender["id"]))

            if "constraint_sets" in sender["caps"]:
                try:
                    self.validate_schema(sender, schema)
                except ValidationError as e:
                    return test.FAIL("Sender {} does not comply with chema".format(sender["id"]))

                for constraint_set in sender["caps"]["constraint_sets"]:
                    try:
                        self.validate_schema(constraint_set, reg_schema)
                    except ValidationError as e:
                        return test.FAIL("Sender {} constraint_sets do not comply with schema".format(sender["id"]))

                    format = getFormatFromTransport(sender["transport"])

                    if format == FormatUnknown:
                        if sender["flow_id"] in self.is04_resources["flows"]:
                            format = self.is04_resources["flows"][sender["flow_id"]]["format"]
                        else:
                            warning = "Sender {} Flow {} not found in Flows".format(sender["id"], sender["flow_id"])
                            continue # continue ITERATION
                            
                    if format != FormatMux:
                        if (CapMetaFormat in constraint_set) or (CapMetaLayer in constraint_set):
                            return test.FAIL("Sender {} sub-Flow/sub-Stream are illegal for a Sender of format {}".format(sender["id"], format))
                    else:
                        if (CapMetaFormat in constraint_set) or (CapMetaLayer in constraint_set):
                            if (CapMetaFormat not in constraint_set) or (CapMetaLayer not in constraint_set):
                                return test.FAIL("Sender {} sub-Flow/sub-Stream require both {} and {}".format(sender["id"], CapMetaFormat, CapMetaLayer))
                            if CapFormatMediaType not in constraint_set:
                                warning = "Sender {} sub-Flow/sub-Stream constraint_sets should have a media_type capability which is not part of the media_types array {}.".format(sender["id"], sender["caps"]["media_types"])
                            if constraint_set[CapMetaFormat] not in (FormatAudio, FormatVideo, FormatData):
                                warning = "Sender {} sub-Flow/sub-Stream constraint_sets should have an audio, video or data format.".format(sender["id"])
                            for param_constraint in constraint_set:
                                if param_constraint.startswith("urn:x-matrox:cap:transport:") or param_constraint.startswith("urn:x-nmos:cap:transport:"):
                                    return test.FAIL("Sender {} sub-Flow/sub-Stream cannot have transport capabilities".format(sender["id"]))
                                
                            layer = constraint_set[CapMetaLayer]
                            layers = self.getLayers(constraint_set[CapMetaFormat], sender)

                            if layer not in layers:
                                return test.FAIL("Sender {} sub-Flow/sub-Stream constraint_set of format {} missing a parent Flow matching layer {}".format(sender["id"], constraint_set[CapMetaFormat], constraint_set[CapMetaLayer]))

                            if not is_consecutive_from_zero(layers):
                                return test.FAIL("Sender {} sub-Flow of format {} have an invalid layers {} sequence".format(sender["id"], constraint_set[CapMetaFormat], layers))

                            layer_compatibility_groups, intersection = self.getLayerCompatibilityGroups(constraint_set[CapMetaFormat], layer, sender)

                            if intersection == 0:
                                return test.FAIL("Sender {} sub-Flows of format {} have an invalid layer_compatibility_group null intersection".format(sender["id"], constraint_set[CapMetaFormat]))
                            
            else:
                warning = "Sender {} not having constraint_sets".format(sender["id"])

        if warning is not None:
            return test.WARNING(warning)
        else:
            return test.PASS()
        
    def test_04(self, test):

        """Check Sender Flows and sub-Flows"""

        valid, result = self.get_is04_resources("senders")
        if not valid:
            return test.FAIL(result)

        valid, result = self.get_is04_resources("flows")
        if not valid:
            return test.FAIL(result)

        warning = None

        for sender in self.is04_resources["senders"].values():

            format = getFormatFromTransport(sender["transport"])

            if format == FormatUnknown:
                if sender["flow_id"] in self.is04_resources["flows"]:
                    format = self.is04_resources["flows"][sender["flow_id"]]["format"]
                else:
                    warning = "Sender {} Flow {} not found in Flows".format(sender["id"], sender["flow_id"])
                    continue # continue ITERATION

            flow_id = sender["flow_id"]

            if flow_id not in self.is04_resources["flows"]:
                warning = "Sender {} Flow {} not found in Flows".format(sender["id"], flow_id)
                continue
            
            flow = self.is04_resources["flows"][flow_id]

            if flow["format"] != format:
                return test.FAIL("Sender {} Flow has an invalid format {}. Expecting {}".format(sender["id"], flow["format"], format))

            # Make sure there is no sub-Flow specific attributes
            if (AttributeLayer in sender) or (AttributeLayerCompatibilityGroups in flow):
                return test.FAIL("Sender {} has invalid sub-Flow attributes".format(sender["id"]))
            
            if format != FormatMux:

                # Make sure there is no mux Flow specific attributes
                if (AttributeAudioLayers in flow) or (AttributeVideoLayers in flow) or (AttributeDataLayers in flow):
                    return test.FAIL("Sender {} has invalid mux Flow attributes".format(sender["id"]))

            else:

                audio_intersection = 0xffffffffffffffff
                video_intersection = 0xffffffffffffffff
                data_intersection = 0xffffffffffffffff

                audio_layers = []
                video_layers = []
                data_layers = []

                for parent_id in flow["parents"]:

                    if parent_id not in self.is04_resources["flows"]:
                        warning = "Sender {} parent flow not found".format(sender["id"])
                        continue
                    
                    parent_flow = self.is04_resources["flows"][parent_id]

                    if AttributeLayer not in parent_flow:
                        return test.FAIL("Sender {} parent layer not found".format(sender["id"]))

                    if parent_flow["format"] == FormatAudio:
                        audio_layers.append(parent_flow[AttributeLayer])
                    elif parent_flow["format"] == FormatVideo:
                        video_layers.append(parent_flow[AttributeLayer])
                    elif parent_flow["format"] == FormatData:
                        data_layers.append(parent_flow[AttributeLayer])
                    else:
                        return test.FAIL("Sender {} parent flow format is invalid".format(sender["id"]))

                    if AttributeLayerCompatibilityGroups not in parent_flow:
                        return test.FAIL("Sender {} parent layer compatibility groups not found".format(sender["id"]))

                    groups = parent_flow[AttributeLayerCompatibilityGroups]

                    mask = 0
                    for v in groups:
                        mask |= 1 << v
                    mask = 0xffffffffffffffff ^ mask

                    if parent_flow["format"] == FormatAudio:
                        if audio_intersection == 0xffffffffffffffff:
                            audio_intersection = mask
                        else:
                            audio_intersection &= mask
                    elif parent_flow["format"] == FormatVideo:
                        if video_intersection == 0xffffffffffffffff:
                            video_intersection = mask
                        else:
                            video_intersection &= mask
                    elif parent_flow["format"] == FormatData:
                        if data_intersection == 0xffffffffffffffff:
                            data_intersection = mask
                        else:
                            data_intersection &= mask
                    else:
                        return test.FAIL("Sender {} parent flow format is invalid".format(sender["id"]))

                if not is_consecutive_from_zero(audio_layers):
                    return test.FAIL("Sender {} parent flows have invalid layers sequence {}".format(sender["id"], audio_layers))
                if not is_consecutive_from_zero(video_layers):
                    return test.FAIL("Sender {} parent flows have invalid layers sequence {}".format(sender["id"], video_layers))
                if not is_consecutive_from_zero(data_layers):
                    return test.FAIL("Sender {} parent flows have invalid layers sequence {}".format(sender["id"], data_layers))

                if audio_intersection == 0:
                    return test.FAIL("Sender {} audio parent flows have invalid null layer_compatibility_groups intersection".format(sender["id"]))
                if video_intersection == 0:
                    return test.FAIL("Sender {} video parent flows have invalid null layer_compatibility_groups intersection".format(sender["id"]))
                if data_intersection == 0:
                    return test.FAIL("Sender {} data parent flows have invalid null layer_compatibility_groups intersection".format(sender["id"]))

                if len(audio_layers) != 0 and AttributeAudioLayers not in flow:
                    return test.FAIL("Sender {} mux Flow is missing the audio_layers attribute".format(sender["id"]))
                if len(video_layers) != 0 and AttributeVideoLayers not in flow:
                    return test.FAIL("Sender {} mux Flow is missing the video_layers attribute".format(sender["id"]))
                if len(data_layers) != 0 and AttributeDataLayers not in flow:
                    return test.FAIL("Sender {} mux Flow is missing the data_layers attribute".format(sender["id"]))

                if len(audio_layers) != flow[AttributeAudioLayers]:
                    return test.FAIL("Sender {} mux Flow audio_layers attribute not matching sub-Flows".format(sender["id"]))
                if len(video_layers) != flow[AttributeVideoLayers]:
                    return test.FAIL("Sender {} mux Flow video_layers attribute not matching sub-Flows".format(sender["id"]))
                if len(data_layers) != flow[AttributeDataLayers]:
                    return test.FAIL("Sender {} mux Flow data_layers attribute not matching sub-Flows".format(sender["id"]))

        if warning is not None:
            return test.WARNING(warning)
        else:
            return test.PASS()        