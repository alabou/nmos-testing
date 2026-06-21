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
from ..TestResult import Test
from ..IPMXUtils import filter_resources

from pathlib import Path

NODE_API_KEY = "node"
CONNECTION_API_KEY = "connection"
RECEIVER_CAPS_KEY = "receiver-caps"
SENDER_CAPS_KEY = "sender-caps"

from ..MatroxCCF import (
    FormatVideo,
    FormatAudio,
    FormatData,
    FormatMux,
    FormatUnknown,
    CapFormatMediaType,
    CapFormatEventType,
    CapFormatGrainRate,
    CapFormatFrameWidth,
    CapFormatFrameHeight,
    CapFormatInterlaceMode,
    CapFormatColorspace,
    CapFormatTransferCharacteristic,
    CapFormatColorSampling,
    CapFormatComponentDepth,
    CapFormatChannelCount,
    CapFormatSampleRate,
    CapFormatSampleDepth,
    CapFormatBitRate,
    CapFormatProfile,
    CapFormatLevel,
    CapFormatSublevel,
    CapFormatConstantBitRate,
    CapFormatVideoLayers,
    CapFormatAudioLayers,
    CapFormatDataLayers,
    CapTransportBitRate,
    CapTransportPacketTime,
    CapTransportMaxPacketTime,
    CapTransport_ST2110_21_SenderType,
    CapTransportPacketTransmissionMode,
    CapTransportParameterSetsFlowMode,
    CapTransportParameterSetsTransportMode,
    CapTransportChannelOrder,
    CapTransportHkep,
    CapTransportPrivacy,
    CapTransportClockRefType,
    CapTransportInfoBlock,
    CapTransportSynchronousMedia,
    CapMetaLabel,
    CapMetaFormat,
    CapMetaLayerEnabled,
    CapMetaLayer,
    CapMetaLayerCompatibilityGroups,
    CapMetaEnabled,
    CapMetaPreference,
)

AttributeLayer                          = "urn:x-matrox:layer"
AttributeLayerCompatibilityGroups       = "urn:x-matrox:layer_compatibility_groups"
AttributeAudioLayers                    = "urn:x-matrox:audio_layers"
AttributeVideoLayers                    = "urn:x-matrox:video_layers"
AttributeDataLayers                     = "urn:x-matrox:data_layers"

# Generic capabilities from any namespace
def urn_without_namespace(s):
    match = re.search(r'^urn:[a-z0-9][a-z0-9-]+:(.*)', s)
    return match.group(1) if match else None


def get_key_value(obj, name):
    # Accept either a bare suffix ("cap:meta:format") or a fully namespaced
    # constant ("urn:x-matrox:cap:meta:format"); matching ignores the namespace
    suffix = urn_without_namespace(name)
    if suffix is not None:
        name = suffix
    regex = re.compile(r'^urn:[a-z0-9][a-z0-9-]+:' + name + r'$')
    for key, value in obj.items():
        if regex.fullmatch(key):
            return value
    return obj[name]  # final try without a namespace


def has_key(obj, name):
    # Accept either a bare suffix ("cap:meta:format") or a fully namespaced
    # constant ("urn:x-matrox:cap:meta:format"); matching ignores the namespace
    suffix = urn_without_namespace(name)
    if suffix is not None:
        name = suffix
    regex = re.compile(r'^urn:[a-z0-9][a-z0-9-]+:' + name + r'$')
    for key in obj.keys():
        if regex.fullmatch(key):
            return True
    return name in obj  # final try without a namespace

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
        self.is04_resources = {"senders": {}, "receivers": {}, "_requested": [], "sources": {}, "flows": {},
                               "devices": {}, "self": {}}
        self.is05_resources = {"senders": [], "receivers": [], "_requested": [], "transport_types": {},
                               "transport_files": {}}
        self.is04_utils = IS04Utils(self.node_url)
        self.is05_utils = IS05Utils(self.connection_url)
        self.test = Test("default")

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
        """Check that version 1.3 or greater of the Node API is available"""

        self.test = test

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

        """Check Receiver Capabilities"""

        self.test = test

        api = self.apis[RECEIVER_CAPS_KEY]

        reg_api = self.apis["caps-register"]
        reg_path = reg_api["spec_path"] + "/capabilities"

        valid, result = self.get_is04_resources("receivers")
        if not valid:
            return test.FAIL(result)

        schema = load_resolved_schema(api["spec_path"], "receiver_constraint_sets.json")

        # workaround to load the Capabilities register schema as if with load_resolved_schema directly
        # but with the base_uri of the Receiver Capabilities schemas
        reg_schema_file = str(Path(os.path.abspath(reg_path)) / "constraint_set.json")
        with open(reg_schema_file, "r") as f:
            reg_schema_obj = json.load(f)
        reg_schema = load_resolved_schema(api["spec_path"], schema_obj=reg_schema_obj)

        warning = ""

        for receiver in self.is04_resources["receivers"].values():
            if "constraint_sets" in receiver["caps"]:
                try:
                    self.validate_schema(receiver, schema)
                except ValidationError as e:
                    return test.FAIL("Receiver {} does not comply with schema: {}".format(receiver["id"], e))

                audio_layers = []
                video_layers = []
                data_layers = []

                try:
                    caps_version = receiver["caps"]["version"]
                    core_version = receiver["version"]
                    
                    if self.is04_utils.compare_resource_version(caps_version, core_version) > 0:
                        return test.FAIL("Receiver {} caps version is later than resource version".format(receiver["id"]))

                except (KeyError, IndexError, ValueError, AttributeError) as e:
                    return test.FAIL("Receiver {} has an invalid or missing caps/resource version: {}".format(receiver["id"], e))

                has_label = None
                warn_label = False

                for constraint_set in receiver["caps"]["constraint_sets"]:
                    try:
                        self.validate_schema(constraint_set, reg_schema)
                    except ValidationError as e:
                        return test.FAIL("Receiver {} constraint_sets do not comply with schema: {}".format(receiver["id"], e))

                    has_current_label = has_key(constraint_set, CapMetaLabel)

                    # Ensure consistent labeling across all constraint_sets
                    if has_label is None:
                        has_label = has_current_label
                    elif has_label != has_current_label:
                        warn_label = True

                    has_pattern_attribute = False
                    for param_constraint in constraint_set:
                        # enumeration do not allow empty arrays by schema, disallow empty range by test
                        if not urn_without_namespace(param_constraint).startswith("cap:meta:"):
                            has_pattern_attribute = True
                            if "minimum" in param_constraint and "maximum" in param_constraint:
                                if compare_min_larger_than_max(param_constraint):
                                    warning += "|" + "Receiver {} parameter constraint {} has an invalid empty range".format(receiver["id"], param_constraint)

                        if param_constraint.startswith("urn:x-nmos:") and param_constraint not in reg_schema_obj["properties"]:
                            warning += "|" + "Receiver {} parameter constraint {} is not registered ".format(receiver["id"], param_constraint)

                    if not has_pattern_attribute:
                        return test.FAIL("Receiver {} has an illegal constraint set without any parameter attribute".format(receiver["id"]))

                    # When present on any Constraint Set (mux Flow/Stream or sub-Flow/sub-Stream), the
                    # layer_compatibility_groups meta attribute must be an array of unsigned integers 0..63
                    if has_key(constraint_set, CapMetaLayerCompatibilityGroups):
                        lcg = get_key_value(constraint_set, CapMetaLayerCompatibilityGroups)
                        if not check_layer_compatibility_groups(lcg):
                            return test.FAIL("Receiver {} constraint_set has an invalid {} meta attribute {}".format(receiver["id"], CapMetaLayerCompatibilityGroups, lcg))

                    # unless the receiver is of format mux, sub-flow capabilities should not be used
                    has_meta_format = has_key(constraint_set, CapMetaFormat)
                    has_meta_layer = has_key(constraint_set, CapMetaLayer)
                    if receiver["format"] != FormatMux:
                        if has_meta_format or has_meta_layer:
                            return test.FAIL("Receiver {} sub-Flow/sub-Stream are illegal for a Receiver of format {}".format(receiver["id"], receiver["format"]))
                    else:
                        if has_meta_format or has_meta_layer:
                            if not has_meta_format or not has_meta_layer:
                                return test.FAIL("Receiver {} sub-Flow/sub-Stream require both {} and {}".format(receiver["id"], CapMetaFormat, CapMetaLayer))
                            # A sub-Flow/sub-Stream Constraint Set must be explicitly layer-enabled and must be
                            # disabled (enabled=false) so non-compatible Controllers/Users ignore it
                            if not has_key(constraint_set, CapMetaLayerEnabled):
                                return test.FAIL("Receiver {} sub-Flow/sub-Stream constraint_set is missing the {} meta attribute".format(receiver["id"], CapMetaLayerEnabled))
                            if not has_key(constraint_set, CapMetaEnabled) or get_key_value(constraint_set, CapMetaEnabled) is not False:
                                return test.FAIL("Receiver {} sub-Flow/sub-Stream constraint_set must have {} set to false".format(receiver["id"], CapMetaEnabled))
                            cs_format = get_key_value(constraint_set, CapMetaFormat)
                            cs_layer = get_key_value(constraint_set, CapMetaLayer)
                            if not has_key(constraint_set, CapFormatMediaType) or get_key_value(constraint_set, CapFormatMediaType) in receiver["caps"]["media_types"]:
                                warning += "|" + "Receiver {} sub-Flow/sub-Stream constraint_sets should have a media_type capability which is not part of the media_types array {}.".format(receiver["id"], receiver["caps"]["media_types"])
                            if cs_format not in (FormatAudio, FormatVideo, FormatData):
                                warning += "|" + "Receiver {} sub-Flow/sub-Stream constraint_sets should have an audio, video or data format.".format(receiver["id"])
                            for param_constraint in constraint_set:
                                if urn_without_namespace(param_constraint).startswith("cap:transport:"):
                                    return test.FAIL("Receiver {} sub-Flow/sub-Stream cannot have transport capabilities".format(receiver["id"]))

                            if cs_format == FormatAudio:
                                append_if_not_exists(audio_layers, cs_layer)
                            elif cs_format == FormatVideo:
                                append_if_not_exists(video_layers, cs_layer)
                            elif cs_format == FormatData:
                                append_if_not_exists(data_layers, cs_layer)
                            else:
                                return test.FAIL("Receiver {} constraint set format is invalid".format(receiver["id"]))

                # Note: the Node caps cannot have non-contiguous layers but once processed by a controller in accordance
                #       with layer mapping, the receiver caps can have non-contiguous layers. Here we enforece the Receiver's
                #       declaration.
                if not is_consecutive_from_zero(audio_layers):
                    return test.FAIL("Receiver {} audio sub-srteams have invalid layers sequence {}".format(receiver["id"], audio_layers))
                if not is_consecutive_from_zero(video_layers):
                    return test.FAIL("Receiver {} video sub-streams have invalid layers sequence {}".format(receiver["id"], video_layers))
                if not is_consecutive_from_zero(data_layers):
                    return test.FAIL("Receiver {} data sub-streams have invalid layers sequence {}".format(receiver["id"], data_layers))
                
                if warn_label:
                    warning += "|" + "Receiver {} constraint_sets should either 'urn:x-nmos:cap:meta:label' for all constraint sets or none".format(receiver["id"])

            else:
                warning += "|" + "Receiver {} not having constraint_sets".format(receiver["id"])

        if warning != "":
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

            if not has_key(parent_flow, AttributeLayer):
                raise NMOSTestException("parent layer not found")

            layer = get_key_value(parent_flow, AttributeLayer)

            if not check_layer(layer):
                raise NMOSTestException("parent layer is invalid")

            if layer in layers:
                raise NMOSTestException("parent layer already exists")

            layers.append(layer)

        return layers            

    def getLayerCompatibilityGroups(self, format, layer, sender):

        flow_id = sender["flow_id"]

        if flow_id not in self.is04_resources["flows"]:
            return None
        
        flow = self.is04_resources["flows"][flow_id]

        if flow["format"] != FormatMux:
            return None

        layer_compatibility_groups = []

        # init with MUX
        if not has_key(flow, AttributeLayerCompatibilityGroups):
            groups = list(range(64))
        else:
            groups = get_key_value(flow, AttributeLayerCompatibilityGroups)
            if not check_layer_compatibility_groups(groups):
                raise NMOSTestException("mux layer_compatibility_groups is invalid")

        mask = 0
        for v in groups:
            mask |= 1 << v
        mask = 0xffffffffffffffff ^ mask

        intersection = mask

        for parent_id in flow["parents"]:

            if parent_id not in self.is04_resources["flows"]:
                raise NMOSTestException("parent flow not found")
            
            parent_flow = self.is04_resources["flows"][parent_id]

            if parent_flow["format"] != format:
                continue

            if not has_key(parent_flow, AttributeLayer):
                raise NMOSTestException("parent layer not found")

            # for all layers
            if not has_key(parent_flow, AttributeLayerCompatibilityGroups):
                groups = list(range(64))
            else:
                groups = get_key_value(parent_flow, AttributeLayerCompatibilityGroups)
                if not check_layer_compatibility_groups(groups):
                    raise NMOSTestException("parent layer_compatibility_groups is invalid")

            mask = 0
            for v in groups:
                mask |= 1 << v
            mask = 0xffffffffffffffff ^ mask

            if intersection == 0xffffffffffffffff:
                intersection = mask
            else:
                intersection &= mask

            if (get_key_value(parent_flow, AttributeLayer) == layer):
                layer_compatibility_groups = groups

        return layer_compatibility_groups, intersection

    def test_03(self, test):
        """Check Sender Capabilities"""

        self.test = test

        api = self.apis[SENDER_CAPS_KEY]

        reg_api = self.apis["caps-register"]
        reg_path = reg_api["spec_path"] + "/capabilities"

        valid, result = self.get_is04_resources("senders")
        if not valid:
            return test.FAIL(result)

        valid, result = self.get_is04_resources("flows")
        if not valid:
            return test.FAIL(result)

        schema = load_resolved_schema(api["spec_path"], "sender_constraint_sets.json")

        # workaround to load the Capabilities register schema as if with load_resolved_schema directly
        # but with the base_uri of the Sender Capabilities schemas
        reg_schema_file = str(Path(os.path.abspath(reg_path)) / "constraint_set.json")
        with open(reg_schema_file, "r") as f:
            reg_schema_obj = json.load(f)
        reg_schema = load_resolved_schema(api["spec_path"], schema_obj=reg_schema_obj)

        warning = ""

        for sender in self.is04_resources["senders"].values():

            # Make sure Senders do not use the Receiver's specific "media_types" attribute in their caps
            if "media_types" in sender["caps"]:
                return test.FAIL("Sender {} has an illegal 'media_types' attribute in its caps".format(sender["id"]))

            # Make sure Senders do not use the Receiver's specific "event_types" attribute in their caps
            if "event_types" in sender["caps"]:
                return test.FAIL("Sender {} has an illegal 'event_types' attribute in its caps".format(sender["id"]))

            if "constraint_sets" in sender["caps"]:
                try:
                    self.validate_schema(sender, schema)
                except ValidationError as e:
                    return test.FAIL("Sender {} does not comply with schema: {}".format(sender["id"], e))
                try:
                    caps_version = sender["caps"]["version"]
                    core_version = sender["version"]
                    
                    if self.is04_utils.compare_resource_version(caps_version, core_version) > 0:
                        return test.FAIL("Sender {} caps version is later than resource version".format(sender["id"]))

                except (KeyError, IndexError, ValueError, AttributeError) as e:
                    return test.FAIL("Sender {} has an invalid or missing caps/resource version: {}".format(sender["id"], e))

                has_label = None
                warn_label = False
                
                for constraint_set in sender["caps"]["constraint_sets"]:
                    try:
                        self.validate_schema(constraint_set, reg_schema)
                    except ValidationError as e:
                        return test.FAIL("Sender {} constraint_sets do not comply with schema: {}".format(sender["id"], e))

                    has_current_label = has_key(constraint_set, CapMetaLabel)

                    # Ensure consistent labeling across all constraint_sets
                    if has_label is None:
                        has_label = has_current_label
                    elif has_label != has_current_label:
                        warn_label = True

                    has_pattern_attribute = False
                    for param_constraint in constraint_set:
                        # enumeration do not allow empty arrays by schema, disallow empty range by test
                        if not urn_without_namespace(param_constraint).startswith("cap:meta:"):
                            has_pattern_attribute = True
                            if "minimum" in param_constraint and "maximum" in param_constraint:
                                if compare_min_larger_than_max(param_constraint):
                                    warning += "|" + "Sender {} parameter constraint {} has an invalid empty range".format(sender["id"], param_constraint)

                        if param_constraint.startswith("urn:x-nmos:") and param_constraint not in reg_schema_obj["properties"]:
                            warning += "|" + "Sender {} parameter constraint {} is not registered ".format(sender["id"], param_constraint)

                    if not has_pattern_attribute:
                        return test.FAIL("Sender {} has an illegal constraint set without any parameter attribute".format(sender["id"]))

                    # When present on any Constraint Set (mux Flow/Stream or sub-Flow/sub-Stream), the
                    # layer_compatibility_groups meta attribute must be an array of unsigned integers 0..63
                    if has_key(constraint_set, CapMetaLayerCompatibilityGroups):
                        lcg = get_key_value(constraint_set, CapMetaLayerCompatibilityGroups)
                        if not check_layer_compatibility_groups(lcg):
                            return test.FAIL("Sender {} constraint_set has an invalid {} meta attribute {}".format(sender["id"], CapMetaLayerCompatibilityGroups, lcg))

                    format = getFormatFromTransport(sender["transport"])

                    if format == FormatUnknown:
                        if sender["flow_id"] in self.is04_resources["flows"]:
                            format = self.is04_resources["flows"][sender["flow_id"]]["format"]
                        else:
                            warning += "|" + "Sender {} Flow {} not found in Flows".format(sender["id"], sender["flow_id"])
                            continue # continue ITERATION

                    has_meta_format = has_key(constraint_set, CapMetaFormat)
                    has_meta_layer = has_key(constraint_set, CapMetaLayer)
                    if format != FormatMux:
                        if has_meta_format or has_meta_layer:
                            return test.FAIL("Sender {} sub-Flow/sub-Stream are illegal for a Sender of format {}".format(sender["id"], format))
                    else:
                        if has_meta_format or has_meta_layer:
                            if not has_meta_format or not has_meta_layer:
                                return test.FAIL("Sender {} sub-Flow/sub-Stream require both {} and {}".format(sender["id"], CapMetaFormat, CapMetaLayer))
                            # A sub-Flow/sub-Stream Constraint Set must be explicitly layer-enabled and must be
                            # disabled (enabled=false) so non-compatible Controllers/Users ignore it
                            if not has_key(constraint_set, CapMetaLayerEnabled):
                                return test.FAIL("Sender {} sub-Flow/sub-Stream constraint_set is missing the {} meta attribute".format(sender["id"], CapMetaLayerEnabled))
                            if not has_key(constraint_set, CapMetaEnabled) or get_key_value(constraint_set, CapMetaEnabled) is not False:
                                return test.FAIL("Sender {} sub-Flow/sub-Stream constraint_set must have {} set to false".format(sender["id"], CapMetaEnabled))
                            cs_format = get_key_value(constraint_set, CapMetaFormat)
                            cs_layer = get_key_value(constraint_set, CapMetaLayer)
                            if not has_key(constraint_set, CapFormatMediaType):
                                warning += "|" + "Sender {} sub-Flow/sub-Stream constraint_sets should have a media_type capability which is not part of the media_types array {}.".format(sender["id"], sender["caps"]["media_types"])
                            if cs_format not in (FormatAudio, FormatVideo, FormatData):
                                warning += "|" + "Sender {} sub-Flow/sub-Stream constraint_sets should have an audio, video or data format.".format(sender["id"])
                            for param_constraint in constraint_set:
                                if urn_without_namespace(param_constraint).startswith("cap:transport:"):
                                    return test.FAIL("Sender {} sub-Flow/sub-Stream cannot have transport capabilities".format(sender["id"]))

                            layer = cs_layer
                            layers = self.getLayers(cs_format, sender)

                            if layer not in layers:
                                return test.FAIL("Sender {} sub-Flow/sub-Stream constraint_set of format {} missing a parent Flow matching layer {}".format(sender["id"], cs_format, cs_layer))

                            if not is_consecutive_from_zero(layers):
                                return test.FAIL("Sender {} sub-Flow of format {} have an invalid layers {} sequence".format(sender["id"], cs_format, layers))

                            layer_compatibility_groups, intersection = self.getLayerCompatibilityGroups(cs_format, layer, sender)

                            if intersection == 0:
                                return test.FAIL("Sender {} sub-Flows of format {} have an invalid layer_compatibility_group null intersection".format(sender["id"], cs_format))
                            
                if warn_label:
                    warning += "|" + "Sender {} constraint_sets should either 'urn:x-nmos:cap:meta:label' for all constraint sets or none".format(sender["id"])

            else:
                warning += "|" + "Sender {} not having constraint_sets".format(sender["id"])

        if warning != "":
            return test.WARNING(warning)
        else:
            return test.PASS()
        
    def test_04(self, test):
        """Check Sender Flows and sub-Flows"""

        self.test = test

        valid, result = self.get_is04_resources("senders")
        if not valid:
            return test.FAIL(result)

        valid, result = self.get_is04_resources("flows")
        if not valid:
            return test.FAIL(result)

        warning = ""

        for sender in self.is04_resources["senders"].values():

            format = getFormatFromTransport(sender["transport"])

            if format == FormatUnknown:
                if sender["flow_id"] in self.is04_resources["flows"]:
                    format = self.is04_resources["flows"][sender["flow_id"]]["format"]
                else:
                    warning += "|" + "Sender {} Flow {} not found in Flows".format(sender["id"], sender["flow_id"])
                    continue # continue ITERATION

            flow_id = sender["flow_id"]

            if flow_id not in self.is04_resources["flows"]:
                warning += "|" + "Sender {} Flow {} not found in Flows".format(sender["id"], flow_id)
                continue
            
            flow = self.is04_resources["flows"][flow_id]

            if flow["format"] != format:
                return test.FAIL("Sender {} Flow has an invalid format {}. Expecting {}".format(sender["id"], flow["format"], format))

            # Make sure there is no sub-Flow specific attributes
            if has_key(flow, AttributeLayer):
                return test.FAIL("Sender {} has invalid sub-Flow attributes".format(sender["id"]))

            if format != FormatMux:

                # Make sure there is no mux Flow specific attributes
                if has_key(flow, AttributeAudioLayers) or has_key(flow, AttributeVideoLayers) or has_key(flow, AttributeDataLayers):
                    return test.FAIL("Sender {} has invalid mux Flow attributes".format(sender["id"]))

                if has_key(flow, AttributeLayerCompatibilityGroups):
                   return test.FAIL("Sender {} has invalid sub-Flow attributes".format(sender["id"]))
            else:

                if not has_key(flow, AttributeLayerCompatibilityGroups):
                    groups = list(range(64))
                else:
                    groups = get_key_value(flow, AttributeLayerCompatibilityGroups)
                    if not check_layer_compatibility_groups(groups):
                        raise NMOSTestException("layer_compatibility_groups is invalid")

                mask = 0
                for v in groups:
                    mask |= 1 << v
                mask = 0xffffffffffffffff ^ mask

                # Init with mux compatibility_groups
                audio_intersection = mask
                video_intersection = mask
                data_intersection = mask

                audio_layers = []
                video_layers = []
                data_layers = []

                for parent_id in flow["parents"]:

                    if parent_id not in self.is04_resources["flows"]:
                        warning += "|" + "Sender {} parent flow not found".format(sender["id"])
                        continue
                    
                    parent_flow = self.is04_resources["flows"][parent_id]

                    if not has_key(parent_flow, AttributeLayer):
                        return test.FAIL("Sender {} parent layer not found".format(sender["id"]))

                    if parent_flow["format"] == FormatAudio:
                        audio_layers.append(get_key_value(parent_flow, AttributeLayer))
                    elif parent_flow["format"] == FormatVideo:
                        video_layers.append(get_key_value(parent_flow, AttributeLayer))
                    elif parent_flow["format"] == FormatData:
                        data_layers.append(get_key_value(parent_flow, AttributeLayer))
                    else:
                        return test.FAIL("Sender {} parent flow format is invalid".format(sender["id"]))

                    if not has_key(parent_flow, AttributeLayerCompatibilityGroups):
                        groups = list(range(64))
                    else:
                        groups = get_key_value(parent_flow, AttributeLayerCompatibilityGroups)
                        if not check_layer_compatibility_groups(groups):
                            raise NMOSTestException("parent layer_compatibility_groups is invalid")

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

                if len(audio_layers) != 0 and not has_key(flow, AttributeAudioLayers):
                    return test.FAIL("Sender {} mux Flow is missing the audio_layers attribute".format(sender["id"]))
                if len(video_layers) != 0 and not has_key(flow, AttributeVideoLayers):
                    return test.FAIL("Sender {} mux Flow is missing the video_layers attribute".format(sender["id"]))
                if len(data_layers) != 0 and not has_key(flow, AttributeDataLayers):
                    return test.FAIL("Sender {} mux Flow is missing the data_layers attribute".format(sender["id"]))

                if len(audio_layers) != get_key_value(flow, AttributeAudioLayers):
                    return test.FAIL("Sender {} mux Flow audio_layers attribute not matching sub-Flows".format(sender["id"]))
                if len(video_layers) != get_key_value(flow, AttributeVideoLayers):
                    return test.FAIL("Sender {} mux Flow video_layers attribute not matching sub-Flows".format(sender["id"]))
                if len(data_layers) != get_key_value(flow, AttributeDataLayers):
                    return test.FAIL("Sender {} mux Flow data_layers attribute not matching sub-Flows".format(sender["id"]))

        if warning != "":
            return test.WARNING(warning)
        else:
            return test.PASS()
        
def check_layer_compatibility_groups(lcg):
    if not isinstance(lcg, list):
        return False
    if len(lcg) == 0:
        return False
    for i in lcg:
        if not isinstance(i, int):
            return False
        if i < 0 or i > 63:
            return False
    return True

def check_layer(l):
    if not isinstance(l, int):
        return False
    if l < 0:
        return False

    return True

def compare_min_larger_than_max(param_constraint):
    
    min_val = param_constraint["minimum"]
    max_val = param_constraint["maximum"]

    if isinstance(min_val, int) and isinstance(max_val, int):
        return min_val > max_val
    elif isinstance(min_val, float) and isinstance(max_val, float):
        return min_val > max_val
    elif isinstance(min_val, (int, float)) and isinstance(max_val, (int, float)):
        return float(min_val) > float(max_val)
    elif isinstance(min_val, dict) and isinstance(max_val, dict):
        min_num = min_val["numerator"]
        max_num = max_val["numerator"]
        min_den = min_val.get("denominator", 1)
        max_den = max_val.get("denominator", 1)
        return (min_num*max_den) > (max_num*min_den)
        
    return False


def getFormatFromTransport(transport) :
    format = None
    # for RTP based transport the format is not imposed by the transport
    if transport in ('urn:x-matrox:transport:srt.rtp'):
        format = FormatUnknown
    elif transport in ('urn:x-matrox:transport:srt.mp2t', 'urn:x-matrox:transport:srt'):
        format = FormatMux
    elif transport in ('urn:x-matrox:transport:ndi', 'urn:x-nmos:transport:ndi'):
        format = FormatMux
    elif transport in ('urn:x-matrox:transport:usb', 'urn:x-nmos:transport:usb'):
        format = FormatData
    elif transport in ('urn:x-matrox:transport:udp', 'urn:x-matrox:transport:udp.mcast', 'urn:x-matrox:transport:udp.ucast', 'urn:x-matrox:transport:udp.mp2t', 'urn:x-matrox:transport:udp.mp2t.mcast', 'urn:x-matrox:transport:udp.mp2t.ucast'):
        format = FormatMux
    elif transport in ('urn:x-matrox:transport:rtp.tcp', 'urn:x-nmos:transport:rtp', 'urn:x-nmos:transport:rtp.mcast', 'urn:x-nmos:transport:rtp.ucast'):
        format = FormatUnknown
    elif transport in ('urn:x-matrox:transport:rtsp', 'urn:x-matrox:transport:rtsp.tcp'):
        format = FormatUnknown
    return format