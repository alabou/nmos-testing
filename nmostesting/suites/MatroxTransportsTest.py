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

from jsonschema import ValidationError

from ..GenericTest import GenericTest, NMOSTestException
from ..IS04Utils import IS04Utils
from ..IS05Utils import IS05Utils
from ..TestHelper import load_resolved_schema
from ..TestHelper import check_content_type

from urllib.parse import urlparse

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
MuxFullyDescribedRtsp       = "application/rtsp"

def getSchemaFromTransport(reg_path, target, transport) :

    if target != "sender" and target != "receiver":
        raise NMOSTestException("target of getSchemaFromTransport must be 'sender'' or 'receiver'")

    # todo: missing a pure TCP schema

    reg_schema = None
    if transport in ('urn:x-matrox:transport:srt.rtp', 'urn:x-matrox:transport:srt.mp2t', 'urn:x-matrox:transport:srt'):
        reg_schema = load_resolved_schema(reg_path, "{}_transport_params_srt.json".format(target), path_prefix=False)
    elif transport in ('urn:x-matrox:transport:ndi', 'urn:x-nmos:transport:ndi'):
        reg_schema = load_resolved_schema(reg_path, "{}_transport_params_ndi.json".format(target), path_prefix=False)
    elif transport in ('urn:x-matrox:transport:usb'):
        reg_schema = load_resolved_schema(reg_path, "{}_transport_params_usb.json".format(target), path_prefix=False)
    elif transport in ('urn:x-matrox:transport:udp', 'urn:x-matrox:transport:udp.mcast', 'urn:x-matrox:transport:udp.ucast', 'urn:x-matrox:transport:udp.mp2t', 'urn:x-matrox:transport:udp.mp2t.mcast', 'urn:x-matrox:transport:udp.mp2t.ucast'):
        reg_schema = load_resolved_schema(reg_path, "{}_transport_params_udp.json".format(target), path_prefix=False)
    elif transport in ('urn:x-matrox:transport:rtp.tcp'):
        reg_schema = load_resolved_schema(reg_path, "{}_transport_params_rtp_tcp.json".format(target), path_prefix=False)
    elif transport in ('urn:x-nmos:transport:rtp', 'urn:x-nmos:transport:rtp.mcast', 'urn:x-nmos:transport:rtp.ucast'):
        reg_schema = load_resolved_schema(reg_path, "{}_transport_params_rtp.json".format(target), path_prefix=False)
    elif transport in ('urn:x-matrox:transport:rtsp', 'urn:x-matrox:transport:rtsp.tcp'):
        reg_schema = load_resolved_schema(reg_path, "{}_transport_params_tcp.json".format(target), path_prefix=False)
    return reg_schema

def getPrivacyProtocolFromTransport(transport) :

    # todo: missing a pure TCP schema

    if transport in ('urn:x-matrox:transport:srt.rtp'):
        return ("NULL", "SRT", "RTP", "RTP_KV")
    elif transport in ('urn:x-matrox:transport:srt.mp2t', 'urn:x-matrox:transport:srt'):
        return ("NULL", "SRT", "UDP", "UDP_KV")
    elif transport in ('urn:x-matrox:transport:ndi', 'urn:x-nmos:transport:ndi'):
        return ("NULL")
    elif transport in ('urn:x-matrox:transport:usb'):
        return ("NULL", "USB", "USB_KV")
    elif transport in ('urn:x-matrox:transport:udp', 'urn:x-matrox:transport:udp.mcast', 'urn:x-matrox:transport:udp.ucast', 'urn:x-matrox:transport:udp.mp2t', 'urn:x-matrox:transport:udp.mp2t.mcast', 'urn:x-matrox:transport:udp.mp2t.ucast'):
        return ("NULL", "UDP", "UDP_KV")
    elif transport in ('urn:x-matrox:transport:rtp.tcp', 'urn:x-nmos:transport:rtp', 'urn:x-nmos:transport:rtp.mcast', 'urn:x-nmos:transport:rtp.ucast'):
        return ("NULL", "RTP", "RTP_KV")
    elif transport in ('urn:x-matrox:transport:rtsp', 'urn:x-matrox:transport:rtsp.tcp'):
        return ("NULL", "RTSP", "RTSP_KV")

    return None

def getGroupNameFromTransport(transport) :
    if transport in ('urn:x-nmos:transport:rtp', 'urn:x-nmos:transport:rtp.mcast', 'urn:x-nmos:transport:rtp.ucast', 'urn:x-nmos:transport:rtp.tcp'):
        return "RTP"
    elif transport == 'urn:x-nmos:transport:mqtt':
        return "MQTT"
    elif transport == 'urn:x-nmos:transport:websocket':
        return "WS"
    elif transport in ('urn:x-matrox:transport:ndi', 'urn:x-nmos:transport:ndi'):
        return "NDI"
    elif transport in ('urn:x-matrox:transport:srt', 'urn:x-matrox:transport:srt.mp2t', 'urn:x-matrox:transport:srt.rtp'):
        return "SRT"
    elif transport == 'urn:x-matrox:transport:usb':
        return "USB"
    elif transport in ('urn:x-matrox:transport:udp', 'urn:x-matrox:transport:udp.mcast', 'urn:x-matrox:transport:udp.ucast', 'urn:x-matrox:transport:udp.mp2t', 'urn:x-matrox:transport:udp.mp2t.mcast', 'urn:x-matrox:transport:udp.mp2t.ucast'):
        return "UDP"
    elif transport == 'urn:x-matrox:transport:tcp':
        return "TCP"
    elif transport in ('urn:x-matrox:transport:rtsp', 'urn:x-matrox:transport:rtsp.tcp'):
        return "RTSP"

def getGroupNameFromTags(tags):
    if "urn:x-nmos:tag:grouphint/v1.0" not in tags:
        return None

    tag = tags["urn:x-nmos:tag:grouphint/v1.0"]

    if len(tag) == 0:
        return None

    pattern = r"(?P<group_name>[a-zA-Z]+)\s(?P<group_index>[1-9]\d*|0):(?P<role_in_group>[a-zA-Z]+)\s(?P<role_index>[1-9]\d*|0)"

    match = re.match(pattern, tag[0])
    if match:
        group_name = match.group("group_name")
        group_index = match.group("group_index")
        role_in_group = match.group("role_in_group")
        role_index = match.group("role_index")
    else:
        return None
            
    return group_name

def getGroupIndexFromTags(tags):
    if "urn:x-nmos:tag:grouphint/v1.0" not in tags:
        return None

    tag = tags["urn:x-nmos:tag:grouphint/v1.0"]

    if len(tag) == 0:
        return None

    pattern = r"(?P<group_name>[a-zA-Z]+)\s(?P<group_index>[1-9]\d*|0):(?P<role_in_group>[a-zA-Z]+)\s(?P<role_index>[1-9]\d*|0)"

    match = re.match(pattern, tag[0])
    if match:
        group_name = match.group("group_name")
        group_index = match.group("group_index")
        role_in_group = match.group("role_in_group")
        role_index = match.group("role_index")
    else:
        return None
            
    return group_index

def getRoleNameFromTags(tags):
    if "urn:x-nmos:tag:grouphint/v1.0" not in tags:
        return None

    tag = tags["urn:x-nmos:tag:grouphint/v1.0"]

    if len(tag) == 0:
        return None

    pattern = r"(?P<group_name>[a-zA-Z]+)\s(?P<group_index>[1-9]\d*|0):(?P<role_in_group>[a-zA-Z]+)\s(?P<role_index>[1-9]\d*|0)"

    match = re.match(pattern, tag[0])
    if match:
        group_name = match.group("group_name")
        group_index = match.group("group_index")
        role_in_group = match.group("role_in_group")
        role_index = match.group("role_index")
    else:
        return None
            
    return role_in_group


def getRoleIndexFromTags(tags):
    if "urn:x-nmos:tag:grouphint/v1.0" not in tags:
        return None

    tag = tags["urn:x-nmos:tag:grouphint/v1.0"]

    if len(tag) == 0:
        return None

    pattern = r"(?P<group_name>[a-zA-Z]+)\s(?P<group_index>[1-9]\d*|0):(?P<role_in_group>[a-zA-Z]+)\s(?P<role_index>[1-9]\d*|0)"

    match = re.match(pattern, tag[0])
    if match:
        group_name = match.group("group_name")
        group_index = match.group("group_index")
        role_in_group = match.group("role_in_group")
        role_index = match.group("role_index")
    else:
        return None
            
    return role_index

def getGroupHintFromTags(tags):
    if "urn:x-nmos:tag:grouphint/v1.0" not in tags:
        return None

    tag = tags["urn:x-nmos:tag:grouphint/v1.0"]

    if len(tag) == 0:
        return None

    pattern = r"(?P<group_name>[a-zA-Z]+)\s(?P<group_index>[1-9]\d*|0):(?P<role_in_group>[a-zA-Z]+)\s(?P<role_index>[1-9]\d*|0)"

    match = re.match(pattern, tag[0])
    if match:
        group_name = match.group("group_name")
        group_index = match.group("group_index")
        role_in_group = match.group("role_in_group")
        role_index = match.group("role_index")
    else:
        return None
            
    return group_name + " " + group_index + ":" + role_in_group + " " + role_index

def getFormatFromTransport(transport) :
    format = None
    # for RTP based transport the format is not imposed by the transport
    if transport in ('urn:x-matrox:transport:srt.rtp'):
        format = FormatUnknown
    elif transport in ('urn:x-matrox:transport:srt.mp2t', 'urn:x-matrox:transport:srt'):
        format = FormatMux
    elif transport in ('urn:x-matrox:transport:ndi', 'urn:x-nmos:transport:ndi'):
        format = FormatMux
    elif transport in ('urn:x-matrox:transport:usb'):
        format = FormatData
    elif transport in ('urn:x-matrox:transport:udp', 'urn:x-matrox:transport:udp.mcast', 'urn:x-matrox:transport:udp.ucast', 'urn:x-matrox:transport:udp.mp2t', 'urn:x-matrox:transport:udp.mp2t.mcast', 'urn:x-matrox:transport:udp.mp2t.ucast'):
        format = FormatMux
    elif transport in ('urn:x-matrox:transport:rtp.tcp', 'urn:x-nmos:transport:rtp', 'urn:x-nmos:transport:rtp.mcast', 'urn:x-nmos:transport:rtp.ucast'):
        format = FormatUnknown
    elif transport in ('urn:x-matrox:transport:rtsp', 'urn:x-matrox:transport:rtsp.tcp'):
        format = FormatUnknown
    return format

def hasLayersMappingAttribute(params):
    if ("ext_audio_layers_mapping" in params) or ("ext_video_layers_mapping" in params) or ("ext_data_layers_mapping" in params):
        return True
    else:
        return False

class MatroxTransportsTest(GenericTest):
    """
    Runs Node Tests covering Matrox transports
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
            return test.FAIL("Node API must be running v1.3 or greater to fully implement this specification")

    def test_02(self, test):

        """ Check that senders staged and active transport parameters are valid"""

        reg_api = self.apis["schemas"]
        reg_path = reg_api["spec_path"] + "/schemas"

        valid, result = self.get_is04_resources("senders")
        if not valid:
            return test.FAIL(result)

        valid, result = self.get_is05_partial_resources("senders")
        if not valid:
            return test.FAIL(result)

        warning = ""

        for sender in self.is04_resources["senders"].values():

            reg_schema = getSchemaFromTransport(reg_path, "sender", sender["transport"])

            if reg_schema is not None:
                url = "single/senders/{}/staged".format(sender["id"])
                valid, response = self.is05_utils.checkCleanRequest("GET", url)
                if valid:

                    schema = self.get_schema(CONNECTION_API_KEY, "GET", "/single/senders/{senderId}/staged", response.status_code)
                    valid, msg = self.check_response_without_transport_params(schema, "GET", response)
                    if not valid:
                        return test.FAIL("sender request to staged transport parameters is not valid against schemas, error {}".format(msg))

                    staged = response.json()

                    try:
                        for params in staged["transport_params"]:
                            self.validate_schema(params, reg_schema)

                    except ValidationError as e:
                        return test.FAIL("sender staged transport parameters do not match schema")
                else:
                    return test.FAIL("sender request to staged transport parameters is not valid")

                url = "single/senders/{}/active".format(sender["id"])
                valid, response = self.is05_utils.checkCleanRequest("GET", url)
                if valid:

                    schema = self.get_schema(CONNECTION_API_KEY, "GET", "/single/senders/{senderId}/active", response.status_code)
                    valid, msg = self.check_response_without_transport_params(schema, "GET", response)
                    if not valid:
                        return test.FAIL("sender request to active transport parameters is not valid against schemas, error {}".format(msg))

                    active = response.json()

                    try:
                        for params in active["transport_params"]:
                            self.validate_schema(params, reg_schema)

                    except ValidationError as e:
                        return test.FAIL("sender active transport parameters do not match schema")
                else:
                    return test.FAIL("sender request to active transport parameters is not valid")
            else:
                warning += "|" + "unknown transport {}".format(sender["transport"])

        if warning != "":
            return test.WARNING(warning)
        else:
            return test.PASS()

    def test_03(self, test):

        """ Check that receivers staged and active transport parameters are valid"""

        reg_api = self.apis["schemas"]
        reg_path = reg_api["spec_path"] + "/schemas"

        valid, result = self.get_is04_resources("receivers")
        if not valid:
            return test.FAIL(result)

        warning = ""

        for receiver in self.is04_resources["receivers"].values():

            reg_schema = getSchemaFromTransport(reg_path, "receiver", receiver["transport"])

            if reg_schema is not None:
                url = "single/receivers/{}/staged".format(receiver["id"])
                valid, response = self.is05_utils.checkCleanRequest("GET", url)
                if valid:

                    schema = self.get_schema(CONNECTION_API_KEY, "GET", "/single/receivers/{receiverId}/staged", response.status_code)
                    valid, msg = self.check_response_without_transport_params(schema, "GET", response)
                    if not valid:
                        return test.FAIL("receiver request to staged transport parameters is not valid against schemas, error {}".format(msg))

                    staged = response.json()

                    try:
                        for params in staged["transport_params"]:
                            self.validate_schema(params, reg_schema)
                    except ValidationError as e:
                        return test.FAIL("receiver staged transport parameters do not match schema")
                else:
                    return test.FAIL("receiver request to staged transport parameters is not valid")

                url = "single/receivers/{}/active".format(receiver["id"])
                valid, response = self.is05_utils.checkCleanRequest("GET", url)
                if valid:

                    schema = self.get_schema(CONNECTION_API_KEY, "GET", "/single/receivers/{receiverId}/active", response.status_code)
                    valid, msg = self.check_response_without_transport_params(schema, "GET", response)
                    if not valid:
                        return test.FAIL("receiver request to active transport parameters is not valid against schemas, error {}".format(msg))

                    active = response.json()

                    try:
                        for params in active["transport_params"]:
                            self.validate_schema(params, reg_schema)
                    except ValidationError as e:
                        return test.FAIL("receiver active transport parameters do not match schema")
                else:
                    return test.FAIL("receiver request to active transport parameters is not valid")
            else:
                warning += "|" + "unknown transport {}".format(receiver["transport"])

        if warning != "":
            return test.WARNING(warning)
        else:
            return test.PASS()

    def test_04(self, test):

        """ Check that receivers format matches with the requirements of the transport """

        reg_api = self.apis["schemas"]

        valid, result = self.get_is04_resources("receivers")
        if not valid:
            return test.FAIL(result)

        valid, result = self.get_is05_partial_resources("receivers")
        if not valid:
            return test.FAIL(result)

        warning = ""

        for receiver in self.is04_resources["receivers"].values():

            format = getFormatFromTransport(receiver["transport"])

            if format is None:
                warning += "|" + "unknown transport {}".format(receiver["transport"])
            elif format != FormatUnknown and receiver["format"] != format:
                test.FAIL("receiver {} does have the proper format {} for the transport {}".format(receiver["id"], format, receiver["transport"]))

        if warning != "":
            return test.WARNING(warning)
        else:
            return test.PASS()

    def test_05(self, test):

        """ Check that senders that have an associated Flow have a format that matches with the requirements of the transport """

        reg_api = self.apis["schemas"]

        valid, result = self.get_is04_resources("senders")
        if not valid:
            return test.FAIL(result)

        valid, result = self.get_is04_resources("flows")
        if not valid:
            return test.FAIL(result)

        valid, result = self.get_is05_partial_resources("senders")
        if not valid:
            return test.FAIL(result)

        warning = ""

        for sender in self.is04_resources["senders"].values():

            format = getFormatFromTransport(sender["transport"])

            if format is None:
                warning += "|" + "unknown transport {}".format(sender["transport"])
            else:
                flow_id = sender["flow_id"]
                if flow_id is None:
                    warning += "|" + "sender {} is not having a current flow".format(sender["id"])
                else:
                    if flow_id not in self.is04_resources["flows"]:
                        warning += "|" + "flow {} not found in IS-04 resources".format(flow_id)
                    else:
                        flow = self.is04_resources["flows"][flow_id]
                        if format == FormatUnknown:
                            if len(flow["parents"]) == 0:
                                # only opaque mux is allowed to have no parents
                                if flow["format"] == FormatMux and flow["media_type"] != MuxOpaque:
                                    test.FAIL("sender {} flow {} does not have the proper format {} for not having parent flows for the transport {}".format(sender["id"], flow_id, FormatMux, sender["transport"]))
                            else:
                                if flow["format"] != FormatMux or flow["media_type"] == MuxOpaque:
                                    test.FAIL("sender {} flow {} does not have the proper format {} for having parent flows for the transport {}".format(sender["id"], flow_id, FormatMux, sender["transport"]))
                        else: 
                            if flow["format"] != format:
                                test.FAIL("sender {} flow {} does not have the proper format {} for the transport {}".format(sender["id"], flow_id, format, sender["transport"]))

        if warning != "":
            return test.WARNING(warning)
        else:
            return test.PASS()

    def test_06(self, test):

        """ Check that only receivers of mux type implement the *_layers_mapping attributes """

        reg_api = self.apis["schemas"]
        reg_path = reg_api["spec_path"] + "/schemas"

        valid, result = self.get_is04_resources("receivers")
        if not valid:
            return test.FAIL(result)

        valid, result = self.get_is05_partial_resources("receivers")
        if not valid:
            return test.FAIL(result)

        warning = ""

        for receiver in self.is04_resources["receivers"].values():

            reg_schema = getSchemaFromTransport(reg_path, "receiver", receiver["transport"])

            if reg_schema is not None:
                url = "single/receivers/{}/active".format(receiver["id"])
                valid, response = self.is05_utils.checkCleanRequest("GET", url)
                if valid:

                    schema = self.get_schema(CONNECTION_API_KEY, "GET", "/single/receivers/{receiverId}/active", response.status_code)
                    valid, msg = self.check_response_without_transport_params(schema, "GET", response)
                    if not valid:
                        return test.FAIL("receiver request to active transport parameters is not valid against schemas, error {}".format(msg))

                    active = response.json()

                    try:
                        for params in active["transport_params"]:
                            self.validate_schema(params, reg_schema)
                            if hasLayersMappingAttribute(params) and receiver["format"] != FormatMux:
                                return test.FAIL("receiver {} does have the proper format {} for using ext_*_layers_mapping attributes".format(receiver["id"], FormatMux))
                    except ValidationError as e:
                        return test.FAIL("receiver active transport parameters do not match schema")
                else:
                    return test.FAIL("receiver request to active transport parameters is not valid")
            else:
                warning += "|" + "unknown transport {}".format(receiver["transport"])

        if warning != "":
            return test.WARNING(warning)
        else:
            return test.PASS()

    def test_07(self, test):

        """ Check that senders transport parameters constraints are valid"""

        reg_api = self.apis["schemas"]
        reg_path = reg_api["spec_path"] + "/schemas"

        valid, result = self.get_is04_resources("senders")
        if not valid:
            return test.FAIL(result)

        valid, result = self.get_is05_partial_resources("senders")
        if not valid:
            return test.FAIL(result)

        warning = ""

        for sender in self.is04_resources["senders"].values():

            reg_schema = load_resolved_schema(reg_path, "is-05-constraints-schema.json", path_prefix=False)

            if reg_schema is not None:
                url = "single/senders/{}/constraints".format(sender["id"])
                valid, response = self.is05_utils.checkCleanRequest("GET", url)
                if valid:

                    # There is nothing to validate in the response as there are only constraints
                    constraints = response.json()

                    try:
                        for params in constraints:
                            self.validate_schema(params, reg_schema)
                    except ValidationError as e:
                        return test.FAIL("sender transport parameters constraints do not match schema")
                else:
                    return test.FAIL("sender request to transport parameters constraints is not valid")
            else:
                warning += "|" + "unknown transport {}".format(sender["transport"])

            # Now check that the elements of the constraints, stages and active all match
            url = "single/senders/{}/staged".format(sender["id"])
            valid, response = self.is05_utils.checkCleanRequest("GET", url)
            if not valid:
                return test.FAIL("cannot get sender staged parameters")
            staged = response.json()

            url = "single/senders/{}/active".format(sender["id"])
            valid, response = self.is05_utils.checkCleanRequest("GET", url)
            if not valid:
                return test.FAIL("cannot get sender active parameters")
            active = response.json()

            if len(constraints) != len(staged["transport_params"]) or len(constraints) != len(active["transport_params"]):
                return test.FAIL("sender staged, active and constraints arrays are inconsistent")
            
            # across staged, active and constraints
            i = 0
            for c_params in constraints:
                s_params = staged["transport_params"][i]
                a_params = active["transport_params"][i]

                for c in c_params.keys():
                    if (c not in s_params.keys()) or (c not in a_params.keys()):
                        return test.FAIL("sender staged, active and constraints parameters are inconsistent")

                i = i + 1

            # across legs
            for c_params in constraints:
                for c in c_params.keys():
                    if (c not in constraints[0].keys()):
                        return test.FAIL("sender constraints parameters are inconsistent")

            for s_params in staged["transport_params"]:
                for c in s_params.keys():
                    if (c not in staged["transport_params"][0].keys()):
                        return test.FAIL("sender staged parameters are inconsistent")

            for a_params in active["transport_params"]:
                for c in a_params.keys():
                    if (c not in active["transport_params"][0].keys()):
                        return test.FAIL("sender active parameters are inconsistent")

            # now check transport minimum requirements
            i = 0
            for c_params in constraints:

                valid, msg = checkSenderTransportParameters(sender["transport"], c_params, staged["transport_params"][i], active["transport_params"][i])
                if not valid:
                    return test.FAIL("sender active transport parameters is not valid against minimum requirements, error {}".format(msg))
                
                i = i + 1

        if warning != "":
            return test.WARNING(warning)
        else:
            return test.PASS()

    def test_08(self, test):

        """ Check that receivers transport parameters constraints are valid and that per transport minimum requirement are met """

        reg_api = self.apis["schemas"]
        reg_path = reg_api["spec_path"] + "/schemas"

        valid, result = self.get_is04_resources("receivers")
        if not valid:
            return test.FAIL(result)

        valid, result = self.get_is05_partial_resources("receivers")
        if not valid:
            return test.FAIL(result)

        warning = ""

        for receiver in self.is04_resources["receivers"].values():

            reg_schema = load_resolved_schema(reg_path, "is-05-constraints-schema.json", path_prefix=False)

            if reg_schema is not None:
                url = "single/receivers/{}/constraints".format(receiver["id"])
                valid, response = self.is05_utils.checkCleanRequest("GET", url)
                if valid:

                    # There is nothing to validate in the response as there are only constraints
                    constraints = response.json()

                    try:
                        for params in constraints:
                            self.validate_schema(params, reg_schema)
                    except ValidationError as e:
                        return test.FAIL("receiver transport parameters constraints do not match schema")
                else:
                    return test.FAIL("receiver request to transport parameters constraints is not valid")
            else:
                warning += "|" + "unknown transport {}".format(receiver["transport"])

            # Now check that the elements of the constraints, stages and active all match
            url = "single/receivers/{}/staged".format(receiver["id"])
            valid, response = self.is05_utils.checkCleanRequest("GET", url)
            if not valid:
                return test.FAIL("cannot get receiver staged parameters")
            staged = response.json()

            url = "single/receivers/{}/active".format(receiver["id"])
            valid, response = self.is05_utils.checkCleanRequest("GET", url)
            if not valid:
                return test.FAIL("cannot get receiver active parameters")
            active = response.json()

            if len(constraints) != len(staged["transport_params"]) or len(constraints) != len(active["transport_params"]):
                return test.FAIL("receiver staged, active and constraints arrays are inconsistent")
            
            # across staged, active and constraints
            i = 0
            for c_params in constraints:
                s_params = staged["transport_params"][i]
                a_params = active["transport_params"][i]

                # Use active as a reference
                for c in a_params.keys():
                    if (c not in c_params.keys()) or (c not in s_params.keys()):
                        return test.FAIL("receiver staged, active and constraints parameters are inconsistent")

                i = i + 1

            # across legs
            for c_params in constraints:
                for c in c_params.keys():
                    if (c not in constraints[0].keys()):
                        return test.FAIL("receiver constraints parameters are inconsistent")

            for s_params in staged["transport_params"]:
                for c in s_params.keys():
                    if (c not in staged["transport_params"][0].keys()):
                        return test.FAIL("receiver staged parameters are inconsistent")

            for a_params in active["transport_params"]:
                for c in a_params.keys():
                    if (c not in active["transport_params"][0].keys()):
                        return test.FAIL("receiver active parameters are inconsistent")

            # now check transport minimum requirements
            i = 0
            for c_params in constraints:

                valid, msg = checkReceiverTransportParameters(receiver["transport"], c_params, staged["transport_params"][i], active["transport_params"][i])
                if not valid:
                    return test.FAIL("receiver active transport parameters is not valid against minimum requirements, error {}".format(msg))
                
                i = i + 1

        if warning != "":
            return test.WARNING(warning)
        else:
            return test.PASS()

    def test_09(self, test):

        """ Check that senders grouphint group name matches the transport"""

        reg_api = self.apis["schemas"]
        reg_path = reg_api["spec_path"] + "/schemas"

        valid, result = self.get_is04_resources("senders")
        if not valid:
            return test.FAIL(result)

        valid, result = self.get_is05_partial_resources("senders")
        if not valid:
            return test.FAIL(result)

        warning = ""

        found_in_devices = {} # check uniqueness of group names

        for sender in self.is04_resources["senders"].values():
            required_group_name = getGroupNameFromTransport(sender["transport"])
            actual_group_name = getGroupNameFromTags(sender["tags"])

            if required_group_name != actual_group_name:
                return test.FAIL("sender {} group name {} does not match with required transport group name {}".format(sender["id"], actual_group_name, required_group_name))

            # We also perform a sanity check of the unicity of the grouphint. the complete testing of the grouping is not performed here.
            group_hint = getGroupHintFromTags(sender["tags"])

            device_id = sender["device_id"]

            if device_id not in found_in_devices:
                found_in_devices[device_id] = {group_hint: True}
            else:
                if group_hint not in found_in_devices[device_id]:
                    found_in_devices[device_id][group_hint] = True
                else:
                    return test.FAIL("sender {} group hint {} of device {} is not unique among the senders of the device".format(sender["id"], group_hint, device_id))

        if warning != "":
            return test.WARNING(warning)
        else:
            return test.PASS()

    
    def test_10(self, test):

        """ Check that receivers grouphint group name matches the transport"""

        reg_api = self.apis["schemas"]
        reg_path = reg_api["spec_path"] + "/schemas"

        valid, result = self.get_is04_resources("receivers")
        if not valid:
            return test.FAIL(result)

        valid, result = self.get_is05_partial_resources("receivers")
        if not valid:
            return test.FAIL(result)

        warning = ""

        found_in_devices = {} # check uniqueness of group names

        for receiver in self.is04_resources["receivers"].values():
            required_group_name = getGroupNameFromTransport(receiver["transport"])
            actual_group_name = getGroupNameFromTags(receiver["tags"])

            if required_group_name != actual_group_name:
                return test.FAIL("receiver {} group name {} does not match with required transport group name {}".format(receiver["id"], actual_group_name, required_group_name))

            # We also perform a sanity check of the unicity of the grouphint. the complete testing of the grouping is not performed here.
            group_hint = getGroupHintFromTags(receiver["tags"])

            device_id = receiver["device_id"]

            if device_id not in found_in_devices:
                found_in_devices[device_id] = {group_hint: True}
            else:
                if group_hint not in found_in_devices[device_id]:
                    found_in_devices[device_id][group_hint] = True
                else:
                    return test.FAIL("receiver {} group hint {} of device {} is not unique among the receivers of the device".format(receiver["id"], group_hint, device_id))

        if warning != "":
            return test.WARNING(warning)
        else:
            return test.PASS()

def checkSenderTransportParameters(transport, constraints, staged, active):

    if transport in ('urn:x-matrox:transport:srt.rtp', 'urn:x-matrox:transport:srt.mp2t', 'urn:x-matrox:transport:srt'):
        return checkSenderTransportParametersSrt(transport, constraints, staged, active)
    elif transport in ('urn:x-matrox:transport:ndi', 'urn:x-nmos:transport:ndi'):
        return checkSenderTransportParametersNdi(transport, constraints, staged, active)
    elif transport in ('urn:x-matrox:transport:usb'):
        return checkSenderTransportParametersUsb(transport, constraints, staged, active)
    elif transport in ('urn:x-matrox:transport:udp', 'urn:x-matrox:transport:udp.mcast', 'urn:x-matrox:transport:udp.ucast', 'urn:x-matrox:transport:udp.mp2t', 'urn:x-matrox:transport:udp.mp2t.mcast', 'urn:x-matrox:transport:udp.mp2t.ucast'):
        return checkSenderTransportParametersUdp(transport, constraints, staged, active)
    elif transport in ('urn:x-matrox:transport:rtp.tcp'):
        return checkSenderTransportParametersRtp(transport, constraints, staged, active)
    elif transport in ('urn:x-nmos:transport:rtp', 'urn:x-nmos:transport:rtp.mcast', 'urn:x-nmos:transport:rtp.ucast'):
        return checkSenderTransportParametersRtp(transport, constraints, staged, active)
    elif transport in ('urn:x-matrox:transport:rtsp', 'urn:x-matrox:transport:rtsp.tcp'):
        return checkSenderTransportParametersRtsp(transport, constraints, staged, active)

    return False, "unknown transport"

def checkReceiverTransportParameters(transport, constraints, staged, active):

    if transport in ('urn:x-matrox:transport:srt.rtp', 'urn:x-matrox:transport:srt.mp2t', 'urn:x-matrox:transport:srt'):
        return checkReceiverTransportParametersSrt(transport, constraints, staged, active)
    elif transport in ('urn:x-matrox:transport:ndi', 'urn:x-nmos:transport:ndi'):
        return checkReceiverTransportParametersNdi(transport, constraints, staged, active)
    elif transport in ('urn:x-matrox:transport:usb'):
        return checkReceiverTransportParametersUsb(transport, constraints, staged, active)
    elif transport in ('urn:x-matrox:transport:udp', 'urn:x-matrox:transport:udp.mcast', 'urn:x-matrox:transport:udp.ucast', 'urn:x-matrox:transport:udp.mp2t', 'urn:x-matrox:transport:udp.mp2t.mcast', 'urn:x-matrox:transport:udp.mp2t.ucast'):
        return checkReceiverTransportParametersUdp(transport, constraints, staged, active)
    elif transport in ('urn:x-matrox:transport:rtp.tcp'):
        return checkReceiverTransportParametersRtp(transport, constraints, staged, active)
    elif transport in ('urn:x-nmos:transport:rtp', 'urn:x-nmos:transport:rtp.mcast', 'urn:x-nmos:transport:rtp.ucast'):
        return checkReceiverTransportParametersRtp(transport, constraints, staged, active)
    elif transport in ('urn:x-matrox:transport:rtsp', 'urn:x-matrox:transport:rtsp.tcp'):
        return checkReceiverTransportParametersRtsp(transport, constraints, staged, active)

    return False, "unknown transport"

# cannot check the default configuration because there is no way for the test suite to force that state
def checkSenderTransportParametersSrt(transport, constraints, staged, active):

    required = ('source_ip', 'source_port', 'destination_ip', 'destination_port', 'protocol', 'latency')
    optional = ('stream_id')

    for p in required:
        if p not in constraints.keys():
            return False, "required transport parameter {} not found in constraints".format(p)
        if p not in staged.keys():
            return False, "required transport parameter {} not found in staged".format(p)
        if p not in active.keys():
            return False, "required transport parameter {} not found in active".format(p)

    for p in constraints.keys():
        if not p.startswith("ext_") and p not in required and p not in optional:
            return False, "unknown transport parameter {} in constraints".format(p)
    for p in staged.keys():
        if not p.startswith("ext_") and p not in required and p not in optional:
            return False, "unknown transport parameter {} in staged".format(p)
    for p in active.keys():
        if not p.startswith("ext_") and p not in required and p not in optional:
            return False, "unknown transport parameter {} in active".format(p)

    # check only on active as staged parameters are transient and can as a whole be invalid prior to activation
    if active["protocol"] == "rendezvous" and active["source_port"] != active["destination_port"]:
            return False, "in 'rendezvous' mode the 'source_port' and 'destination_port' must be equal"

    return checkSenderTransportParametersPEP(transport, constraints, staged, active)

# cannot check the default configuration because there is no way for the test suite to force that state
def checkReceiverTransportParametersSrt(transport, constraints, staged, active):

    required = ('source_ip', 'source_port', 'destination_ip', 'destination_port', 'protocol', 'latency')
    optional = ('stream_id')

    for p in required:
        if p not in constraints.keys():
            return False, "required transport parameter {} not found in constraints".format(p)
        if p not in staged.keys():
            return False, "required transport parameter {} not found in staged".format(p)
        if p not in active.keys():
            return False, "required transport parameter {} not found in active".format(p)

    for p in constraints.keys():
        if not p.startswith("ext_") and p not in required and p not in optional:
            return False, "unknown transport parameter {} in constraints".format(p)
    for p in staged.keys():
        if not p.startswith("ext_") and p not in required and p not in optional:
            return False, "unknown transport parameter {} in staged".format(p)
    for p in active.keys():
        if not p.startswith("ext_") and p not in required and p not in optional:
            return False, "unknown transport parameter {} in active".format(p)

    # check only on active as staged parameters are transient and can as a whole be invalid prior to activation
    if active["protocol"] == "rendezvous" and active["source_port"] != active["destination_port"]:
            return False, "in 'rendezvous' mode the 'source_port' and 'destination_port' must be equal"

    return checkReceiverTransportParametersPEP(transport, constraints, staged, active)

def checkSenderTransportParametersUsb(transport, constraints, staged, active):
        
    required = ('source_ip', 'source_port')

    for p in required:
        if p not in constraints.keys():
            return False, "required transport parameter {} not found in constraints".format(p)
        if p not in staged.keys():
            return False, "required transport parameter {} not found in staged".format(p)
        if p not in active.keys():
            return False, "required transport parameter {} not found in active".format(p)

    for p in constraints.keys():
        if not p.startswith("ext_") and p not in required:
            return False, "unknown transport parameter {} in constraints".format(p)
    for p in staged.keys():
        if not p.startswith("ext_") and p not in required:
            return False, "unknown transport parameter {} in staged".format(p)
    for p in active.keys():
        if not p.startswith("ext_") and p not in required:
            return False, "unknown transport parameter {} in active".format(p)

    return checkSenderTransportParametersPEP(transport, constraints, staged, active)

def checkReceiverTransportParametersUsb(transport, constraints, staged, active):

    required = ('source_ip', 'source_port', 'interface_ip')

    for p in required:
        if p not in constraints.keys():
            return False, "required transport parameter {} not found in constraints".format(p)
        if p not in staged.keys():
            return False, "required transport parameter {} not found in staged".format(p)
        if p not in active.keys():
            return False, "required transport parameter {} not found in active".format(p)

    for p in constraints.keys():
        if not p.startswith("ext_") and p not in required:
            return False, "unknown transport parameter {} in constraints".format(p)
    for p in staged.keys():
        if not p.startswith("ext_") and p not in required:
            return False, "unknown transport parameter {} in staged".format(p)
    for p in active.keys():
        if not p.startswith("ext_") and p not in required:
            return False, "unknown transport parameter {} in active".format(p)

    return checkReceiverTransportParametersPEP(transport, constraints, staged, active)

def checkSenderTransportParametersNdi(transport, constraints, staged, active):

    # NMOS not worried about cross domain issues
    if transport == 'urn:x-nmos:transport:ndi':
        required = ('source_name', 'machine_name')
    else:
        required = ('source_ip', 'source_port', 'source_name', 'machine_name')

    optional = ('source_url')

    for p in required:
        if p not in constraints.keys():
            return False, "required transport parameter {} not found in constraints".format(p)
        if p not in staged.keys():
            return False, "required transport parameter {} not found in staged".format(p)
        if p not in active.keys():
            return False, "required transport parameter {} not found in active".format(p)

    for p in constraints.keys():
        if not p.startswith("ext_") and p not in required and p not in optional:
            return False, "unknown transport parameter {} in constraints".format(p)
    for p in staged.keys():
        if not p.startswith("ext_") and p not in required and p not in optional:
            return False, "unknown transport parameter {} in staged".format(p)
    for p in active.keys():
        if not p.startswith("ext_") and p not in required and p not in optional:
            return False, "unknown transport parameter {} in active".format(p)

    if not re.match(r'^[a-zA-Z0-9_]+$', staged['source_name']):
        return False, "source anme {} is invalid".format(staged['source_name'])
    if not re.match(r'^[a-zA-Z0-9_]+$', active['source_name']):
        return False, "source anme {} is invalid".format(staged['source_name'])

    return checkSenderTransportParametersPEP(transport, constraints, staged, active)

def checkReceiverTransportParametersNdi(transport, constraints, staged, active):

    # NMOS not worried about cross domain issues
    if transport == 'urn:x-nmos:transport:ndi':
        required = ('source_name', 'machine_name')
    else:
        required = ('source_ip', 'source_port', 'source_name', 'machine_name', 'interface_ip')

    optional = ('source_url')

    for p in required:
        if p not in constraints.keys():
            return False, "required transport parameter {} not found in constraints".format(p)
        if p not in staged.keys():
            return False, "required transport parameter {} not found in staged".format(p)
        if p not in active.keys():
            return False, "required transport parameter {} not found in active".format(p)

    for p in constraints.keys():
        if not p.startswith("ext_") and p not in required and p not in optional:
            return False, "unknown transport parameter {} in constraints".format(p)
    for p in staged.keys():
        if not p.startswith("ext_") and p not in required and p not in optional:
            return False, "unknown transport parameter {} in staged".format(p)
    for p in active.keys():
        if not p.startswith("ext_") and p not in required and p not in optional:
            return False, "unknown transport parameter {} in active".format(p)

    if staged['source_name'] is not None:
        if not re.match(r'^[a-zA-Z0-9_]+$', staged['source_name']):
            return False, "source anme {} is invalid".format(staged['source_name'])
    if active['source_name'] is not None:
        if not re.match(r'^[a-zA-Z0-9_]+$', active['source_name']):
            return False, "source anme {} is invalid".format(staged['source_name'])

    return checkReceiverTransportParametersPEP(transport, constraints, staged, active)

# We do not enforce the all or nothing rule for FEC
def checkSenderTransportParametersRtp(transport, constraints, staged, active):

    required = ('source_ip', 'destination_ip', 'source_port', 'destination_port', 'rtp_enabled')
    rtcp_required = ('rtcp_enabled', 'rtcp_destination_ip', 'rtcp_destination_port', 'rtcp_source_port')
    optional = ('fec_enabled', 'fec_destination_ip', 'fec_type', 'fec_mode', 'fec_block_width', 'fec_block_height', 'fec1D_destination_port', 'fec2D_destination_port', 'fec1D_source_port', 'fec2D_source_port' )

    for p in required:
        if p not in constraints.keys():
            return False, "required transport parameter {} not found in constraints".format(p)
        if p not in staged.keys():
            return False, "required transport parameter {} not found in staged".format(p)
        if p not in active.keys():
            return False, "required transport parameter {} not found in active".format(p)

    for k in constraints.keys():
        if k.startswith("rtcp_"):
            for p in rtcp_required:
                if p not in constraints.keys():
                    return False, "required transport parameter {} not found in constraints".format(p)
                if p not in staged.keys():
                    return False, "required transport parameter {} not found in staged".format(p)
                if p not in active.keys():
                    return False, "required transport parameter {} not found in active".format(p)
            break # check once

    for p in constraints.keys():
        if not p.startswith("ext_") and p not in required and p not in rtcp_required and p not in optional:
            return False, "unknown transport parameter {} in constraints".format(p)
    for p in staged.keys():
        if not p.startswith("ext_") and p not in required and p not in rtcp_required and p not in optional:
            return False, "unknown transport parameter {} in staged".format(p)
    for p in active.keys():
        if not p.startswith("ext_") and p not in required and p not in rtcp_required and p not in optional:
            return False, "unknown transport parameter {} in active".format(p)
        
    return checkSenderTransportParametersPEP(transport, constraints, staged, active)

# We do not enforce the all or nothing rule for FEC
def checkReceiverTransportParametersRtp(transport, constraints, staged, active):

    required = ('source_ip', 'interface_ip', 'destination_port', 'rtp_enabled')
    rtcp_required = ('rtcp_destination_ip', 'rtcp_enabled', 'rtcp_destination_port')
    optional = ('multicast_ip', 'fec_enabled', 'fec_destination_ip', 'fec_mode', 'fec1D_destination_port', 'fec2D_destination_port')

    for p in required:
        if p not in constraints.keys():
            return False, "required transport parameter {} not found in constraints".format(p)
        if p not in staged.keys():
            return False, "required transport parameter {} not found in staged".format(p)
        if p not in active.keys():
            return False, "required transport parameter {} not found in active".format(p)

    for k in constraints.keys():
        if k.startswith("rtcp_"):
            for p in rtcp_required:
                if p not in constraints.keys():
                    return False, "required transport parameter {} not found in constraints".format(p)
                if p not in staged.keys():
                    return False, "required transport parameter {} not found in staged".format(p)
                if p not in active.keys():
                    return False, "required transport parameter {} not found in active".format(p)
            break # check once

    for p in constraints.keys():
        if not p.startswith("ext_") and p not in required and p not in rtcp_required and p not in optional:
            return False, "unknown transport parameter {} in constraints".format(p)
    for p in staged.keys():
        if not p.startswith("ext_") and p not in required and p not in rtcp_required and p not in optional:
            return False, "unknown transport parameter {} in staged".format(p)
    for p in active.keys():
        if not p.startswith("ext_") and p not in required and p not in rtcp_required and p not in optional:
            return False, "unknown transport parameter {} in active".format(p)
        
    return checkReceiverTransportParametersPEP(transport, constraints, staged, active)

# We do not enforce the all or nothing rule for FEC
def checkSenderTransportParametersUdp(transport, constraints, staged, active):

    required = ('source_ip', 'destination_ip', 'source_port', 'destination_port', 'enabled')
    optional = ('fec_enabled', 'fec_destination_ip', 'fec_type', 'fec_mode', 'fec_block_width', 'fec_block_height', 'fec1D_destination_port', 'fec2D_destination_port', 'fec1D_source_port', 'fec2D_source_port' )

    for p in required:
        if p not in constraints.keys():
            return False, "required transport parameter {} not found in constraints".format(p)
        if p not in staged.keys():
            return False, "required transport parameter {} not found in staged".format(p)
        if p not in active.keys():
            return False, "required transport parameter {} not found in active".format(p)

    for p in constraints.keys():
        if not p.startswith("ext_") and p not in required and p not in optional:
            return False, "unknown transport parameter {} in constraints".format(p)
    for p in staged.keys():
        if not p.startswith("ext_") and p not in required and p not in optional:
            return False, "unknown transport parameter {} in staged".format(p)
    for p in active.keys():
        if not p.startswith("ext_") and p not in required and p not in optional:
            return False, "unknown transport parameter {} in active".format(p)

    return checkSenderTransportParametersPEP(transport, constraints, staged, active)

# We do not enforce the all or nothing rule for FEC
def checkReceiverTransportParametersUdp(transport, constraints, staged, active):

    required = ('source_ip', 'interface_ip', 'destination_port', 'enabled')
    optional = ('multicast_ip', 'fec_enabled', 'fec_destination_ip', 'fec_mode', 'fec1D_destination_port', 'fec2D_destination_port')

    for p in required:
        if p not in constraints.keys():
            return False, "required transport parameter {} not found in constraints".format(p)
        if p not in staged.keys():
            return False, "required transport parameter {} not found in staged".format(p)
        if p not in active.keys():
            return False, "required transport parameter {} not found in active".format(p)

    for p in constraints.keys():
        if not p.startswith("ext_") and p not in required and p not in optional:
            return False, "unknown transport parameter {} in constraints".format(p)
    for p in staged.keys():
        if not p.startswith("ext_") and p not in required and p not in optional:
            return False, "unknown transport parameter {} in staged".format(p)
    for p in active.keys():
        if not p.startswith("ext_") and p not in required and p not in optional:
            return False, "unknown transport parameter {} in active".format(p)

    return checkReceiverTransportParametersPEP(transport, constraints, staged, active)

def checkSenderTransportParametersRtsp(transport, constraints, staged, active):

    required = ('source_ip', 'source_port')

    for p in required:
        if p not in constraints.keys():
            return False, "required transport parameter {} not found in constraints".format(p)
        if p not in staged.keys():
            return False, "required transport parameter {} not found in staged".format(p)
        if p not in active.keys():
            return False, "required transport parameter {} not found in active".format(p)

    for p in constraints.keys():
        if not p.startswith("ext_") and p not in required:
            return False, "unknown transport parameter {} in constraints".format(p)
    for p in staged.keys():
        if not p.startswith("ext_") and p not in required:
            return False, "unknown transport parameter {} in staged".format(p)
    for p in active.keys():
        if not p.startswith("ext_") and p not in required:
            return False, "unknown transport parameter {} in active".format(p)

    return checkSenderTransportParametersPEP(transport, constraints, staged, active)

def checkReceiverTransportParametersRtsp(transport, constraints, staged, active):

    required = ('source_ip', 'interface_ip', 'source_port')

    for p in required:
        if p not in constraints.keys():
            return False, "required transport parameter {} not found in constraints".format(p)
        if p not in staged.keys():
            return False, "required transport parameter {} not found in staged".format(p)
        if p not in active.keys():
            return False, "required transport parameter {} not found in active".format(p)

    for p in constraints.keys():
        if not p.startswith("ext_") and p not in required:
            return False, "unknown transport parameter {} in constraints".format(p)
    for p in staged.keys():
        if not p.startswith("ext_") and p not in required:
            return False, "unknown transport parameter {} in staged".format(p)
    for p in active.keys():
        if not p.startswith("ext_") and p not in required:
            return False, "unknown transport parameter {} in active".format(p)

    return checkReceiverTransportParametersPEP(transport, constraints, staged, active)

def checkSenderTransportParametersPEP(transport, constraints, staged, active):

    pep_required = ('ext_privacy_protocol', 'ext_privacy_mode', 'ext_privacy_iv', 'ext_privacy_key_generator', 'ext_privacy_key_version', 'ext_privacy_key_id' )
    ecdh_required = ('ext_privacy_ecdh_sender_public_key', 'ext_privacy_ecdh_receiver_public_key', 'ext_privacy_ecdh_curve' )

    for k in constraints.keys():
        if k.startswith("ext_privacy_"):
            for p in pep_required:
                if p not in constraints.keys():
                    return False, "required transport parameter {} not found in constraints".format(p)
                if p not in staged.keys():
                    return False, "required transport parameter {} not found in staged".format(p)
                if p not in active.keys():
                    return False, "required transport parameter {} not found in active".format(p)
                
            protocols = getPrivacyProtocolFromTransport(transport)

            if staged["ext_privacy_protocol"] not in protocols:
                return False, "invalid PEP protocol {}, expecting one of {} ".format(staged["ext_privacy_protocol"], protocols)
            if active["ext_privacy_protocol"] not in protocols:
                return False, "invalid PEP protocol {}, expecting one of {} ".format(active["ext_privacy_protocol"], protocols)

            break # check once

    for k in constraints.keys():
        if k.startswith("ext_privacy_ecdh_"):
            for p in ecdh_required:
                if p not in constraints.keys():
                    return False, "required transport parameter {} not found in constraints".format(p)
                if p not in staged.keys():
                    return False, "required transport parameter {} not found in staged".format(p)
                if p not in active.keys():
                    return False, "required transport parameter {} not found in active".format(p)
            break # check once

    return True, None

def checkReceiverTransportParametersPEP(transport, constraints, staged, active):

    pep_required = ('ext_privacy_protocol', 'ext_privacy_mode', 'ext_privacy_iv', 'ext_privacy_key_generator', 'ext_privacy_key_version', 'ext_privacy_key_id' )
    ecdh_required = ('ext_privacy_ecdh_sender_public_key', 'ext_privacy_ecdh_receiver_public_key', 'ext_privacy_ecdh_curve' )

    for k in constraints.keys():
        if k.startswith("ext_privacy_"):
            for p in pep_required:
                if p not in constraints.keys():
                    return False, "required transport parameter {} not found in constraints".format(p)
                if p not in staged.keys():
                    return False, "required transport parameter {} not found in staged".format(p)
                if p not in active.keys():
                    return False, "required transport parameter {} not found in active".format(p)

            protocols = getPrivacyProtocolFromTransport(transport)

            if staged["ext_privacy_protocol"] not in protocols:
                return False, "invalid PEP protocol {}, expecting one of {} ".format(staged["ext_privacy_protocol"], protocols)
            if active["ext_privacy_protocol"] not in protocols:
                return False, "invalid PEP protocol {}, expecting one of {} ".format(active["ext_privacy_protocol"], protocols)

            break # check once

    for k in constraints.keys():
        if k.startswith("ext_privacy_ecdh_"):
            for p in ecdh_required:
                if p not in constraints.keys():
                    return False, "required transport parameter {} not found in constraints".format(p)
                if p not in staged.keys():
                    return False, "required transport parameter {} not found in staged".format(p)
                if p not in active.keys():
                    return False, "required transport parameter {} not found in active".format(p)
            break # check once

    return True, None
