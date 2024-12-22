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
from .MatroxTransportsTest import checkSenderTransportParametersPEP
from .MatroxTransportsTest import checkReceiverTransportParametersPEP
from .MatroxTransportsTest import getSchemaFromTransport
from .MatroxTransportsTest import getPrivacyProtocolFromTransport
from .MatroxTransportsTest import getGroupNameFromTransport
from .MatroxTransportsTest import getFormatFromTransport
from .MatroxTransportsTest import checkSenderTransportParameters
from .MatroxTransportsTest import checkReceiverTransportParameters

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

privacy_protocol = 'ext_privacy_protocol'
privacy_mode = 'ext_privacy_mode'
privacy_iv = 'ext_privacy_iv'
privacy_key_generator = 'ext_privacy_key_generator'
privacy_key_version = 'ext_privacy_key_version'
privacy_key_id = 'ext_privacy_key_id'
privacy_ecdh_sender_public_key = 'ext_privacy_ecdh_sender_public_key'
privacy_ecdh_receiver_public_key = 'ext_privacy_ecdh_receiver_public_key'
privacy_ecdh_curve = 'ext_privacy_ecdh_curve'

sdp_privacy_protocol = 'protocol'
sdp_privacy_mode = 'mode'
sdp_privacy_iv = 'iv'
sdp_privacy_key_generator = 'key_generator'
sdp_privacy_key_version = 'key_version'
sdp_privacy_key_id = 'key_id'

privacy_capability = "urn:x-matrox:cap:transport:privacy"

class MatroxPrivacyTest(GenericTest):
    """
    Runs Node Tests covering Privacy Encryption Protocol (PEP)
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

        """ Check that senders transport parameters having 'ext_privacy' parameters are valid """

        reg_api = self.apis["schemas"]
        reg_path = reg_api["spec_path"] + "/schemas"

        valid, result = self.get_is04_resources("senders")
        if not valid:
            return test.FAIL(result)

        valid, result = self.get_is05_partial_resources("senders")
        if not valid:
            return test.FAIL(result)

        warning = None
        all_active = True # proven otherwise

        iv = dict()

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
                        return test.FAIL("sender {} : transport parameters constraints do not match schema".format(sender["id"]))
                else:
                    return test.FAIL("sender {} : request to transport parameters constraints is not valid".format(sender["id"]))
            else:
                warning = (warning or "") + " " + "sender {} : unknown transport {}".format(sender["id"], sender["transport"])

            # Now check that the elements of the constraints, stages and active all match
            url = "single/senders/{}/staged".format(sender["id"])
            valid, response = self.is05_utils.checkCleanRequest("GET", url)
            if not valid:
                return test.FAIL("sender {} : cannot get sender staged parameters".format(sender["id"]))
            staged = response.json()

            url = "single/senders/{}/active".format(sender["id"])
            valid, response = self.is05_utils.checkCleanRequest("GET", url)
            if not valid:
                return test.FAIL("sender {} : cannot get sender active parameters".format(sender["id"]))
            active = response.json()

            if len(constraints) != len(staged["transport_params"]) or len(constraints) != len(active["transport_params"]):
                return test.FAIL("sender {} : staged, active and constraints arrays are inconsistent".format(sender["id"]))
            
            # across staged, active and constraints
            i = 0
            for c_params in constraints:
                s_params = staged["transport_params"][i]
                a_params = active["transport_params"][i]

                for c in c_params.keys():
                    if (c not in s_params.keys()) or (c not in a_params.keys()):
                        return test.FAIL("sender {} : staged, active and constraints parameters are inconsistent".format(sender["id"]))

                i = i + 1

            # across legs
            for c_params in constraints:
                for c in c_params.keys():
                    if (c not in constraints[0].keys()):
                        return test.FAIL("sender {} : constraints parameters are inconsistent".format(sender["id"]))

            for s_params in staged["transport_params"]:
                for c in s_params.keys():
                    if (c not in staged["transport_params"][0].keys()):
                        return test.FAIL("sender {} : staged parameters are inconsistent".format(sender["id"]))

            for a_params in active["transport_params"]:
                for c in a_params.keys():
                    if (c not in active["transport_params"][0].keys()):
                        return test.FAIL("sender {} : active parameters are inconsistent".format(sender["id"]))

            # now check transport minimum requirements
            i = 0
            for c_params in constraints:

                valid, msg = checkSenderTransportParameters(sender["transport"], c_params, staged["transport_params"][i], active["transport_params"][i])
                if not valid:
                    return test.FAIL("sender {} : active transport parameters is not valid against minimum requirements, error {}".format(sender["id"], msg))
                valid, generic, elliptic, msg = self.hasSenderTransportParametersPEP(sender["transport"], c_params, staged["transport_params"][i], active["transport_params"][i])
                if not valid:
                    return test.FAIL("sender {} : active transport parameters is not valid against minimum requirements, error {}".format(sender["id"], msg))

                if generic:

                    ok, msg = self.check_generic_attribute_values(True, sender, c_params, staged["transport_params"][i], active["transport_params"][i], elliptic)
                    if not ok:
                        return test.FAIL("sender {} : invalid privacy encryption attribute value, error {}".format(sender["id"], msg))
                    if msg is not None:
                        warning = (warning or "") + " " + msg

                    null_mode  = "NULL" in constraints[i][privacy_mode]["enum"]
                    null_curve = "NULL" in constraints[i][privacy_ecdh_curve]["enum"]

                    # check sender capability if present
                    if "constraint_sets" in sender["caps"]:
                        for constraint_set in sender["caps"]["constraint_sets"]:
                            if privacy_capability in constraint_set:
                                capability = constraint_set[privacy_capability]
                                if "enum" in capability:
                                    enums = capability["enum"]
                                    if len(enums) != 1:
                                        return test.FAIL("sender {} : invalid privacy capabilities {}".format(sender["id"], capability))
                                    for value in enums:
                                        if not isinstance(value, bool):
                                            return test.FAIL("sender {} : privacy capability must be of type bool".format(sender["id"]))
                                        if value and null_mode is True:
                                            return test.FAIL("sender {} : privacy capability must match privacy transport parameters".format(sender["id"]))
                                        if not value and null_mode is False:
                                            return test.FAIL("sender {} : privacy capability must match privacy transport parameters".format(sender["id"]))

                    # check uniqueness of iv among all the senders (not matter what PSK is used)
                    params = active["transport_params"][i]

                    if params[privacy_iv] in iv:
                        warning = (warning or "") + " " + "sender {} : invalid duplicated iv attribute {}".format(sender["id"], params[privacy_iv])
                    else:
                        iv[params[privacy_iv]] = None # must be unique among all senders

                i = i + 1

            # attributes must match across legs
            ok, msg = self.check_across_legs(True, sender, constraints, staged["transport_params"], active["transport_params"], elliptic)
            if not ok:
                return test.FAIL("sender {} : invalid privacy capability, error {}".format(sender["id"], msg))
            if msg is not None:
                warning = (warning or "") + " " + msg

            # We do require an active sender to get final parameters and to know if there is really no SDP transport file
            if active["master_enable"]:

                # in an NMOS environment the SDP privacy attribute is required if an SDP transport file is used
                # check SDP transport file matching transport parameters, check RTP Extension header declaration
                if "manifest_href" in sender and sender["manifest_href"] is not None:

                    href = sender["manifest_href"]

                    manifest_href_valid, manifest_href_response = self.do_request("GET", href)
                    if not manifest_href_valid or (manifest_href_response.status_code != 200 and manifest_href_response.status_code != 404):
                        return test.FAIL("sender {} : unexpected response from manifest_href '{}': {}".format(sender["id"], href, manifest_href_response))
                    elif manifest_href_valid and manifest_href_response.status_code == 404:
                        return test.UNCLEAR("sender {} : one or more of the tested Senders had returned a 404 HTTP code. Please ensure all Senders are enabled and re-test.".format(sender["id"]))
                    else:
                        sdp_lines = [sdp_line.replace("\r", "") for sdp_line in manifest_href_response.text.split("\n")]

                        ok, msg = self.check_privacy_attribute(True, sender, len(constraints), constraints[0], active["transport_params"][0], sdp_lines)
                        if not ok:
                            return test.FAIL("sender {} : invalid privacy capability, error {}".format(sender["id"], msg))
                        if msg is not None:
                            warning = (warning or "") + " " + msg
            else:
                all_active = False

        if not all_active:
            return test.UNCLEAR("sender {} : one or more of the tested Senders has master_enable set to false. Please ensure all Senders are enabled and re-test.".format(sender["id"]))

        if warning is not None:
            return test.WARNING(warning)
        else:
            return test.PASS()

    def test_03(self, test):

        """ Check that senders transport parameters having 'ext_privacy' parameters are properly validated on activation against constraints """

        reg_api = self.apis["schemas"]
        reg_path = reg_api["spec_path"] + "/schemas"

        valid, result = self.get_is04_resources("senders")
        if not valid:
            return test.FAIL(result)

        valid, result = self.get_is05_partial_resources("senders")
        if not valid:
            return test.FAIL(result)

        warning = None
        all_active = True # proven otherwise

        iv = dict()

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
                        return test.FAIL("sender {} : transport parameters constraints do not match schema".format(sender["id"]))
                else:
                    return test.FAIL("sender {} : request to transport parameters constraints is not valid".format(sender["id"]))
            else:
                warning = (warning or "") + " " + "sender {} : unknown transport {}".format(sender["id"], sender["transport"])

            # Now check that the elements of the constraints, stages and active all match
            url = "single/senders/{}/staged".format(sender["id"])
            valid, response = self.is05_utils.checkCleanRequest("GET", url)
            if not valid:
                return test.FAIL("sender {} : cannot get sender staged parameters".format(sender["id"]))
            staged = response.json()

            url = "single/senders/{}/active".format(sender["id"])
            valid, response = self.is05_utils.checkCleanRequest("GET", url)
            if not valid:
                return test.FAIL("sender {} : cannot get sender active parameters".format(sender["id"]))
            active = response.json()

            if len(constraints) != len(staged["transport_params"]) or len(constraints) != len(active["transport_params"]):
                return test.FAIL("sender {} : staged, active and constraints arrays are inconsistent".format(sender["id"]))
            
            # now check transport minimum requirements
            i = 0
            for c_params in constraints:

                valid, msg = checkSenderTransportParameters(sender["transport"], c_params, staged["transport_params"][i], active["transport_params"][i])
                if not valid:
                    return test.FAIL("sender {} : active transport parameters is not valid against minimum requirements, error {}".format(sender["id"], msg))
                valid, generic, elliptic, msg = self.hasSenderTransportParametersPEP(sender["transport"], c_params, staged["transport_params"][i], active["transport_params"][i])
                if not valid:
                    return test.FAIL("sender {} : active transport parameters is not valid against minimum requirements, error {}".format(sender["id"], msg))

                null_mode  = "NULL" in constraints[i][privacy_mode]["enum"]
                null_curve = "NULL" in constraints[i][privacy_ecdh_curve]["enum"]

                if generic:

                    if active["master_enable"]:

                        # It must be possible to change any privacy attribute if active to its current value as re-activation
                        for name in c_params.keys():
                            if name.startswith("ext_privacy_"):
                                valid, response = self.updateSenderParameter(sender, True, name, active["transport_params"][i][name], staged["transport_params"])
                                if not valid:
                                    return test.FAIL("sender {} : fail re-activation, response {}".format(sender["id"], response))
                                else:
                                    pass
                    else:

                        # It must be possible to change any privacy attribute if inactive to its current value
                        for name in c_params.keys():
                            if name.startswith("ext_privacy_"):
                                valid, response = self.updateSenderParameter(sender, False, name, active["transport_params"][i][name], staged["transport_params"])
                                if not valid:
                                    return test.FAIL("sender {} : failed activation, response {}".format(sender["id"], response))
                                else:
                                    pass

                        # It must not be possible to change any privacy attribute if inactive to an invalid value if a constraint is declared
                        for name in c_params.keys():
                            if name.startswith("ext_privacy_"):
                                if "enum" in c_params[name]: 
                                    valid, response = self.updateSenderParameter(sender, False, name, "this-is-an-invalid-value", staged["transport_params"])
                                    if valid:
                                        return test.FAIL("sender {} : dit not fail activation as expected, response {}".format(sender["id"], response))
                                    else:
                                        pass

                        # It must be possible to change any privacy attribute if inactive to any value of the associated constraints
                        for name in c_params.keys():
                            if name.startswith("ext_privacy_"):
                                if "enum" in c_params[name]: 
                                    for value in c_params[name]["enum"]:
                                        valid, response = self.updateSenderParameter(sender, False, name, value, staged["transport_params"])
                                        if not valid:
                                            return test.FAIL("sender {} : failed activation, response {}".format(sender["id"], response))
                                        else:
                                            pass

                        # It must not be possible to disable privacy encryption unless already disabled
                        if not null_mode:

                            valid, response = self.updateSenderParameter(sender, False, privacy_protocol, "NULL", staged["transport_params"])
                            if valid:
                                return test.FAIL("sender {} : did not fail activation as expected, response {}".format(sender["id"], response))
                            else:
                                pass

                            valid, response = self.updateSenderParameter(sender, False, privacy_mode, "NULL", staged["transport_params"])
                            if valid:
                                return test.FAIL("sender {} : did not fail activation as expected, response {}".format(sender["id"], response))
                            else:
                                pass

                i = i + 1


        if warning is not None:
            return test.WARNING(warning)
        else:
            return test.PASS()

    def test_04(self, test):

        """ Check that receivers transport parameters having 'ext_privacy' parameters are valid """

        reg_api = self.apis["schemas"]
        reg_path = reg_api["spec_path"] + "/schemas"

        valid, result = self.get_is04_resources("receivers")
        if not valid:
            return test.FAIL(result)

        valid, result = self.get_is05_partial_resources("receivers")
        if not valid:
            return test.FAIL(result)

        warning = None
        all_active = True # proven otherwise

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
                        return test.FAIL("receiver {} : transport parameters constraints do not match schema".format(receiver["id"]))
                else:
                    return test.FAIL("receiver {} : request to transport parameters constraints is not valid".format(receiver["id"]))
            else:
                warning = (warning or "") + " " + "receiver {} : unknown transport {}".format(receiver["id"], receiver["transport"])

            # Now check that the elements of the constraints, stages and active all match
            url = "single/receivers/{}/staged".format(receiver["id"])
            valid, response = self.is05_utils.checkCleanRequest("GET", url)
            if not valid:
                return test.FAIL("receiver {} : cannot get receiver staged parameters".format(receiver["id"]))
            staged = response.json()

            url = "single/receivers/{}/active".format(receiver["id"])
            valid, response = self.is05_utils.checkCleanRequest("GET", url)
            if not valid:
                return test.FAIL("receiver {} : cannot get receiver active parameters".format(receiver["id"]))
            active = response.json()

            if len(constraints) != len(staged["transport_params"]) or len(constraints) != len(active["transport_params"]):
                return test.FAIL("receiver {} : staged, active and constraints arrays are inconsistent".format(receiver["id"]))
            
            # across staged, active and constraints
            i = 0
            for c_params in constraints:
                s_params = staged["transport_params"][i]
                a_params = active["transport_params"][i]

                for c in c_params.keys():
                    if (c not in s_params.keys()) or (c not in a_params.keys()):
                        return test.FAIL("receiver {} : staged, active and constraints parameters are inconsistent".format(receiver["id"]))

                i = i + 1

            # across legs
            for c_params in constraints:
                for c in c_params.keys():
                    if (c not in constraints[0].keys()):
                        return test.FAIL("receiver {} : constraints parameters are inconsistent".format(receiver["id"]))

            for s_params in staged["transport_params"]:
                for c in s_params.keys():
                    if (c not in staged["transport_params"][0].keys()):
                        return test.FAIL("receiver {} : staged parameters are inconsistent".format(receiver["id"]))

            for a_params in active["transport_params"]:
                for c in a_params.keys():
                    if (c not in active["transport_params"][0].keys()):
                        return test.FAIL("receiver {} : active parameters are inconsistent".format(receiver["id"]))

            # now check transport minimum requirements
            i = 0
            for c_params in constraints:

                valid, msg = checkReceiverTransportParameters(receiver["transport"], c_params, staged["transport_params"][i], active["transport_params"][i])
                if not valid:
                    return test.FAIL("receiver {} : active transport parameters is not valid against minimum requirements, error {}".format(receiver["id"], msg))
                valid, generic, elliptic, msg = self.hasReceiverTransportParametersPEP(receiver["transport"], c_params, staged["transport_params"][i], active["transport_params"][i])
                if not valid:
                    return test.FAIL("receiver {} : active transport parameters is not valid against minimum requirements, error {}".format(receiver["id"], msg))

                if generic:

                    ok, msg = self.check_generic_attribute_values(False, receiver, c_params, staged["transport_params"][i], active["transport_params"][i], elliptic)
                    if not ok:
                        return test.FAIL("receiver {} : invalid privacy encryption attribute value, error {}".format(receiver["id"], msg))
                    if msg is not None:
                        warning = (warning or "") + " " + msg

                    null_mode  = "NULL" in constraints[i][privacy_mode]["enum"]
                    null_curve = "NULL" in constraints[i][privacy_ecdh_curve]["enum"]

                    # check receiver capability if present
                    if "constraint_sets" in receiver["caps"]:
                        for constraint_set in receiver["caps"]["constraint_sets"]:
                            if privacy_capability in constraint_set:
                                capability = constraint_set[privacy_capability]
                                if "enum" in capability:
                                    enums = capability["enum"]
                                    if len(enums) != 1:
                                        return test.FAIL("receiver {} : invalid privacy capabilities {}".format(receiver["id"], capability))
                                    for value in enums:
                                        if not isinstance(value, bool):
                                            return test.FAIL("receiver {} : privacy capability must be of type bool".format(receiver["id"]))
                                        if value and null_mode is True:
                                            return test.FAIL("receiver {} : privacy capability must match privacy transport parameters".format(receiver["id"]))
                                        if not value and null_mode is False:
                                            return test.FAIL("receiver {} : privacy capability must match privacy transport parameters".format(receiver["id"]))

                i = i + 1

            # attributes must match across legs
            ok, msg = self.check_across_legs(True, receiver, constraints, staged["transport_params"], active["transport_params"], elliptic)
            if not ok:
                return test.FAIL("receiver {} : invalid privacy capability, error {}".format(receiver["id"], msg))
            if msg is not None:
                warning = (warning or "") + " " + msg

            # We do require an active receiver to get final parameters and to know if there is really no SDP transport file
            if active["master_enable"]:

                # in an NMOS environment the SDP privacy attribute is required if an SDP transport file is used
                # check SDP transport file matching transport parameters, check RTP Extension header declaration
                if active["transport_file"]["data"] is not None:

                    sdp_lines = [sdp_line.replace("\r", "") for sdp_line in active["transport_file"]["data"].split("\n")]

                    ok, msg = self.check_privacy_attribute(False, receiver, len(constraints), constraints[0], active["transport_params"][0], sdp_lines)
                    if not ok:
                        return test.FAIL("receiver {} : invalid privacy capability, error {}".format(receiver["id"], msg))
                    if msg is not None:
                        warning = (warning or "") + " " + msg
            else:
                all_active = False

        if not all_active:
            return test.UNCLEAR("receiver {} : one or more of the tested Receivers has master_enable set to false. Please ensure all Receivers are enabled and re-test.".format(receiver["id"]))

        if warning is not None:
            return test.WARNING(warning)
        else:
            return test.PASS()

    def test_05(self, test):

        """ Check that receiver transport parameters having 'ext_privacy' parameters are properly validated on activation against constraints """

        reg_api = self.apis["schemas"]
        reg_path = reg_api["spec_path"] + "/schemas"

        valid, result = self.get_is04_resources("receivers")
        if not valid:
            return test.FAIL(result)

        valid, result = self.get_is05_partial_resources("receivers")
        if not valid:
            return test.FAIL(result)

        warning = None
        all_active = True # proven otherwise

        iv = dict()

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
                        return test.FAIL("receiver {} : transport parameters constraints do not match schema".format(receiver["id"]))
                else:
                    return test.FAIL("receiver {} : request to transport parameters constraints is not valid".format(receiver["id"]))
            else:
                warning = (warning or "") + " " + "receiver {} : unknown transport {}".format(receiver["id"], receiver["transport"])

            # Now check that the elements of the constraints, stages and active all match
            url = "single/receivers/{}/staged".format(receiver["id"])
            valid, response = self.is05_utils.checkCleanRequest("GET", url)
            if not valid:
                return test.FAIL("receiver {} : cannot get receiver staged parameters".format(receiver["id"]))
            staged = response.json()

            url = "single/receivers/{}/active".format(receiver["id"])
            valid, response = self.is05_utils.checkCleanRequest("GET", url)
            if not valid:
                return test.FAIL("receiver {} : cannot get receiver active parameters".format(receiver["id"]))
            active = response.json()

            if len(constraints) != len(staged["transport_params"]) or len(constraints) != len(active["transport_params"]):
                return test.FAIL("receiver {} : staged, active and constraints arrays are inconsistent".format(receiver["id"]))
            
            # now check transport minimum requirements
            i = 0
            for c_params in constraints:

                valid, msg = checkReceiverTransportParameters(receiver["transport"], c_params, staged["transport_params"][i], active["transport_params"][i])
                if not valid:
                    return test.FAIL("receiver {} : active transport parameters is not valid against minimum requirements, error {}".format(receiver["id"], msg))
                valid, generic, elliptic, msg = self.hasReceiverTransportParametersPEP(receiver["transport"], c_params, staged["transport_params"][i], active["transport_params"][i])
                if not valid:
                    return test.FAIL("receiver {} : active transport parameters is not valid against minimum requirements, error {}".format(receiver["id"], msg))

                null_mode  = "NULL" in constraints[i][privacy_mode]["enum"]
                null_curve = "NULL" in constraints[i][privacy_ecdh_curve]["enum"]

                if generic:

                    if active["master_enable"]:

                        # It must be possible to change any privacy attribute if active to its current value as re-activation
                        for name in c_params.keys():
                            if name.startswith("ext_privacy_"):
                                valid, response = self.updateReceiverParameter(receiver, True, name, active["transport_params"][i][name], staged["transport_params"])
                                if not valid:
                                    return test.FAIL("receiver {} : fail re-activation, response {}".format(receiver["id"], response))
                                else:
                                    pass
                    else:

                        # It must be possible to change any privacy attribute if inactive to its current value
                        for name in c_params.keys():
                            if name.startswith("ext_privacy_"):
                                valid, response = self.updateReceiverParameter(receiver, False, name, active["transport_params"][i][name], staged["transport_params"])
                                if not valid:
                                    return test.FAIL("receiver {} : failed activation, response {}".format(receiver["id"], response))
                                else:
                                    pass

                        # It must not be possible to change any privacy attribute if inactive to an invalid value if a constraint is declared
                        for name in c_params.keys():
                            if name.startswith("ext_privacy_"):
                                if "enum" in c_params[name]: 
                                    valid, response = self.updateReceiverParameter(receiver, False, name, "this-is-an-invalid-value", staged["transport_params"])
                                    if valid:
                                        return test.FAIL("receiver {} : dit not fail activation as expected, response {}".format(receiver["id"], response))
                                    else:
                                        pass

                        # It must be possible to change any privacy attribute if inactive to any value of the associated constraints
                        for name in c_params.keys():
                            if name.startswith("ext_privacy_"):
                                if "enum" in c_params[name]: 
                                    for value in c_params[name]["enum"]:
                                        valid, response = self.updateReceiverParameter(receiver, False, name, value, staged["transport_params"])
                                        if not valid:
                                            return test.FAIL("receiver {} : failed activation, response {}".format(receiver["id"], response))
                                        else:
                                            pass

                        # It must not be possible to disable privacy encryption unless already disabled
                        if not null_mode:

                            valid, response = self.updateReceiverParameter(receiver, False, privacy_protocol, "NULL", staged["transport_params"])
                            if valid:
                                return test.FAIL("receiver {} : did not fail activation as expected, response {}".format(receiver["id"], response))
                            else:
                                pass

                            valid, response = self.updateReceiverParameter(receiver, False, privacy_mode, "NULL", staged["transport_params"])
                            if valid:
                                return test.FAIL("receiver {} : did not fail activation as expected, response {}".format(receiver["id"], response))
                            else:
                                pass

                i = i + 1


        if warning is not None:
            return test.WARNING(warning)
        else:
            return test.PASS()

    def test_06(self, test):

        """ Check that senders ECDH private/public key is regenerated on an activation with master_enable set to false """

        reg_api = self.apis["schemas"]
        reg_path = reg_api["spec_path"] + "/schemas"

        valid, result = self.get_is04_resources("senders")
        if not valid:
            return test.FAIL(result)

        valid, result = self.get_is05_partial_resources("senders")
        if not valid:
            return test.FAIL(result)

        warning = None
        all_active = True # proven otherwise

        iv = dict()

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
                        return test.FAIL("sender {} : transport parameters constraints do not match schema".format(sender["id"]))
                else:
                    return test.FAIL("sender {} : request to transport parameters constraints is not valid".format(sender["id"]))
            else:
                warning = (warning or "") + " " + "sender {} : unknown transport {}".format(sender["id"], sender["transport"])

            # Now check that the elements of the constraints, stages and active all match
            url = "single/senders/{}/staged".format(sender["id"])
            valid, response = self.is05_utils.checkCleanRequest("GET", url)
            if not valid:
                return test.FAIL("sender {} : cannot get sender staged parameters".format(sender["id"]))
            staged = response.json()

            url = "single/senders/{}/active".format(sender["id"])
            valid, response = self.is05_utils.checkCleanRequest("GET", url)
            if not valid:
                return test.FAIL("sender {} : cannot get sender active parameters".format(sender["id"]))
            active = response.json()

            if len(constraints) != len(staged["transport_params"]) or len(constraints) != len(active["transport_params"]):
                return test.FAIL("sender {} : staged, active and constraints arrays are inconsistent".format(sender["id"]))
            
            # now check transport minimum requirements
            i = 0
            for c_params in constraints:

                valid, msg = checkSenderTransportParameters(sender["transport"], c_params, staged["transport_params"][i], active["transport_params"][i])
                if not valid:
                    return test.FAIL("sender {} : active transport parameters is not valid against minimum requirements, error {}".format(sender["id"], msg))
                valid, generic, elliptic, msg = self.hasSenderTransportParametersPEP(sender["transport"], c_params, staged["transport_params"][i], active["transport_params"][i])
                if not valid:
                    return test.FAIL("sender {} : active transport parameters is not valid against minimum requirements, error {}".format(sender["id"], msg))

                null_mode  = "NULL" in constraints[i][privacy_mode]["enum"]
                null_curve = "NULL" in constraints[i][privacy_ecdh_curve]["enum"]

                if generic and elliptic:

                    if null_curve:
                        return test.DISABLED("sender {} : ECDH mode not supported".format(sender["id"]))

                    if active["master_enable"]:
                        return test.DISABLED("sender {} : testing ECDH private/public keys pair regeneration require inactive senders".format(sender["id"]))

                    previous_key = active["transport_params"][i][privacy_ecdh_sender_public_key]

                    valid, response = self.updateSenderParameter(sender, False, privacy_ecdh_sender_public_key, previous_key, staged["transport_params"])
                    if not valid:
                        return test.FAIL("sender {} : fail activation, response {}".format(sender["id"], response))

                    if reg_schema is not None:
                        url = "single/senders/{}/constraints".format(sender["id"])
                        valid, response = self.is05_utils.checkCleanRequest("GET", url)
                        if valid:

                            # There is nothing to validate in the response as there are only constraints
                            new_constraints = response.json()

                            try:
                                for params in new_constraints:
                                    self.validate_schema(params, reg_schema)
                            except ValidationError as e:
                                return test.FAIL("sender {} : transport parameters constraints do not match schema".format(sender["id"]))
                        else:
                            return test.FAIL("sender {} : request to transport parameters constraints is not valid".format(sender["id"]))
                    else:
                        warning = (warning or "") + " " + "sender {} : unknown transport {}".format(sender["id"], sender["transport"])

                    # Now check that the elements of the constraints, stages and active all match
                    url = "single/senders/{}/staged".format(sender["id"])
                    valid, response = self.is05_utils.checkCleanRequest("GET", url)
                    if not valid:
                        return test.FAIL("sender {} : cannot get sender staged parameters".format(sender["id"]))
                    new_staged = response.json()

                    url = "single/senders/{}/active".format(sender["id"])
                    valid, response = self.is05_utils.checkCleanRequest("GET", url)
                    if not valid:
                        return test.FAIL("sender {} : cannot get sender active parameters".format(sender["id"]))
                    new_active = response.json()

                    if len(new_constraints) != len(new_staged["transport_params"]) or len(new_constraints) != len(new_active["transport_params"]):
                        return test.FAIL("sender {} : staged, active and constraints arrays are inconsistent".format(sender["id"]))

                    if previous_key == new_staged["transport_params"][i][privacy_ecdh_sender_public_key]:
                        return test.FAIL("sender {} : ECDH private/public key {} not regenerated on staged endpoint at de-activation".format(sender["id"], previous_key))

                    if previous_key == new_active["transport_params"][i][privacy_ecdh_sender_public_key]:
                        return test.FAIL("sender {} : ECDH private/public key {} not regenerated on active endpoint at de-activation".format(sender["id"], previous_key))

                i = i + 1

        if warning is not None:
            return test.WARNING(warning)
        else:
            return test.PASS()

    def test_07(self, test):

        """ Check that receivers ECDH private/public key is regenerated on an activation with master_enable set to false """

        reg_api = self.apis["schemas"]
        reg_path = reg_api["spec_path"] + "/schemas"

        valid, result = self.get_is04_resources("receivers")
        if not valid:
            return test.FAIL(result)

        valid, result = self.get_is05_partial_resources("receivers")
        if not valid:
            return test.FAIL(result)

        warning = None
        all_active = True # proven otherwise

        iv = dict()

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
                        return test.FAIL("receiver {} : transport parameters constraints do not match schema".format(receiver["id"]))
                else:
                    return test.FAIL("receiver {} : request to transport parameters constraints is not valid".format(receiver["id"]))
            else:
                warning = (warning or "") + " " + "receiver {} : unknown transport {}".format(receiver["id"], receiver["transport"])

            # Now check that the elements of the constraints, stages and active all match
            url = "single/receivers/{}/staged".format(receiver["id"])
            valid, response = self.is05_utils.checkCleanRequest("GET", url)
            if not valid:
                return test.FAIL("receiver {} : cannot get receiver staged parameters".format(receiver["id"]))
            staged = response.json()

            url = "single/receivers/{}/active".format(receiver["id"])
            valid, response = self.is05_utils.checkCleanRequest("GET", url)
            if not valid:
                return test.FAIL("receiver {} : cannot get receiver active parameters".format(receiver["id"]))
            active = response.json()

            if len(constraints) != len(staged["transport_params"]) or len(constraints) != len(active["transport_params"]):
                return test.FAIL("receiver {} : staged, active and constraints arrays are inconsistent".format(receiver["id"]))
            
            # now check transport minimum requirements
            i = 0
            for c_params in constraints:

                valid, msg = checkReceiverTransportParameters(receiver["transport"], c_params, staged["transport_params"][i], active["transport_params"][i])
                if not valid:
                    return test.FAIL("receiver {} : active transport parameters is not valid against minimum requirements, error {}".format(receiver["id"], msg))
                valid, generic, elliptic, msg = self.hasReceiverTransportParametersPEP(receiver["transport"], c_params, staged["transport_params"][i], active["transport_params"][i])
                if not valid:
                    return test.FAIL("receiver {} : active transport parameters is not valid against minimum requirements, error {}".format(receiver["id"], msg))

                null_mode  = "NULL" in constraints[i][privacy_mode]["enum"]
                null_curve = "NULL" in constraints[i][privacy_ecdh_curve]["enum"]

                if generic and elliptic:

                    if null_curve:
                        return test.DISABLED("receiver {} : ECDH mode not supported".format(receiver["id"]))

                    if active["master_enable"]:
                        return test.DISABLED("receiver {} : testing ECDH private/public keys pair regeneration require inactive receivers".format(receiver["id"]))

                    previous_key = active["transport_params"][i][privacy_ecdh_receiver_public_key]

                    valid, response = self.updateReceiverParameter(receiver, False, privacy_ecdh_receiver_public_key, previous_key, staged["transport_params"])
                    if not valid:
                        return test.FAIL("receiver {} : fail activation, response {}".format(receiver["id"], response))

                    if reg_schema is not None:
                        url = "single/receivers/{}/constraints".format(receiver["id"])
                        valid, response = self.is05_utils.checkCleanRequest("GET", url)
                        if valid:

                            # There is nothing to validate in the response as there are only constraints
                            new_constraints = response.json()

                            try:
                                for params in new_constraints:
                                    self.validate_schema(params, reg_schema)
                            except ValidationError as e:
                                return test.FAIL("receiver {} : transport parameters constraints do not match schema".format(receiver["id"]))
                        else:
                            return test.FAIL("receiver {} : request to transport parameters constraints is not valid".format(receiver["id"]))
                    else:
                        warning = (warning or "") + " " + "receiver {} : unknown transport {}".format(receiver["id"], receiver["transport"])

                    # Now check that the elements of the constraints, stages and active all match
                    url = "single/receivers/{}/staged".format(receiver["id"])
                    valid, response = self.is05_utils.checkCleanRequest("GET", url)
                    if not valid:
                        return test.FAIL("receiver {} : cannot get receiver staged parameters".format(receiver["id"]))
                    new_staged = response.json()

                    url = "single/receivers/{}/active".format(receiver["id"])
                    valid, response = self.is05_utils.checkCleanRequest("GET", url)
                    if not valid:
                        return test.FAIL("receiver {} : cannot get receiver active parameters".format(receiver["id"]))
                    new_active = response.json()

                    if len(new_constraints) != len(new_staged["transport_params"]) or len(new_constraints) != len(new_active["transport_params"]):
                        return test.FAIL("receiver {} : staged, active and constraints arrays are inconsistent".format(receiver["id"]))

                    if previous_key == new_staged["transport_params"][i][privacy_ecdh_receiver_public_key]:
                        return test.FAIL("receiver {} : ECDH private/public key {} not regenerated on staged endpoint at de-activation".format(receiver["id"], previous_key))

                    if previous_key == new_active["transport_params"][i][privacy_ecdh_receiver_public_key]:
                        return test.FAIL("receiver {} : ECDH private/public key {} not regenerated on active endpoint at de-activation".format(receiver["id"], previous_key))

                i = i + 1

        if warning is not None:
            return test.WARNING(warning)
        else:
            return test.PASS()

    def updateSenderParameter(self, sender, master_enable, name, value, staged):

        if len(staged) == 1:

            data = {
                "master_enable": master_enable,
                "activation": {
                    "mode": "activate_immediate"
                },
                "transport_params": [
                    {name: value}
                ]
            }

        else:

            data = {
                "master_enable": master_enable,
                "activation": {
                    "mode": "activate_immediate"
                },
                "transport_params": [
                    {name: value},
                    {name: value}
                ]
            }

        url = "single/senders/{}/staged".format(sender["id"])
        valid, response = self.is05_utils.checkCleanRequest("PATCH", url, data=data)

        return valid, response

    def updateReceiverParameter(self, receiver, master_enable, name, value, staged):

        if len(staged) == 1:

            data = {
                "master_enable": master_enable,
                "activation": {
                    "mode": "activate_immediate"
                },
                "transport_params": [
                    {name: value}
                ]
            }

        else:

            data = {
                "master_enable": master_enable,
                "activation": {
                    "mode": "activate_immediate"
                },
                "transport_params": [
                    {name: value},
                    {name: value}
                ]
            }

        url = "single/receivers/{}/staged".format(receiver["id"])
        valid, response = self.is05_utils.checkCleanRequest("PATCH", url, data=data)

        return valid, response

    def hasSenderTransportParametersPEP(self, transport, constraints, staged, active):

        pep_required = ( privacy_protocol, privacy_mode, privacy_iv, privacy_key_generator, privacy_key_version, privacy_key_id )
        ecdh_required = ( privacy_ecdh_sender_public_key, privacy_ecdh_receiver_public_key, privacy_ecdh_curve )

        has_generic  = False
        has_elliptic = False

        for k in constraints.keys():
            if k.startswith("ext_privacy_"):
                for p in pep_required:
                    if p not in constraints.keys():
                        return False, False, False, "required transport parameter {} not found in constraints".format(p)
                    if p not in staged.keys():
                        return False, False, False, "required transport parameter {} not found in staged".format(p)
                    if p not in active.keys():
                        return False, False, False, "required transport parameter {} not found in active".format(p)
                    
                protocols = getPrivacyProtocolFromTransport(transport)

                if staged["ext_privacy_protocol"] not in protocols:
                    return False, False, False, "invalid PEP protocol {}, expecting one of {} ".format(staged["ext_privacy_protocol"], protocols)
                if active["ext_privacy_protocol"] not in protocols:
                    return False, False, False, "invalid PEP protocol {}, expecting one of {} ".format(active["ext_privacy_protocol"], protocols)

                has_generic = True

                break # check once

        for k in constraints.keys():
            if k.startswith("ext_privacy_ecdh_"):
                for p in ecdh_required:
                    if p not in constraints.keys():
                        return False, False, False, "required transport parameter {} not found in constraints".format(p)
                    if p not in staged.keys():
                        return False, False, False, "required transport parameter {} not found in staged".format(p)
                    if p not in active.keys():
                        return False, False, False, "required transport parameter {} not found in active".format(p)

                has_elliptic = True

                break # check once

        return True, has_generic, has_elliptic, None
    
    def hasReceiverTransportParametersPEP(self, transport, constraints, staged, active):

        pep_required = (privacy_protocol, privacy_mode, privacy_iv, privacy_key_generator, privacy_key_version, privacy_key_id )
        ecdh_required = (privacy_ecdh_sender_public_key, privacy_ecdh_receiver_public_key, privacy_ecdh_curve )

        has_generic  = False
        has_elliptic = False

        for k in constraints.keys():
            if k.startswith("ext_privacy_"):
                for p in pep_required:
                    if p not in constraints.keys():
                        return False, False, False, "required transport parameter {} not found in constraints".format(p)
                    if p not in staged.keys():
                        return False, False, False, "required transport parameter {} not found in staged".format(p)
                    if p not in active.keys():
                        return False, False, False, "required transport parameter {} not found in active".format(p)

                protocols = getPrivacyProtocolFromTransport(transport)

                if staged["ext_privacy_protocol"] not in protocols:
                    return False, False, False, "invalid PEP protocol {}, expecting one of {} ".format(staged["ext_privacy_protocol"], protocols)
                if active["ext_privacy_protocol"] not in protocols:
                    return False, False, False, "invalid PEP protocol {}, expecting one of {} ".format(active["ext_privacy_protocol"], protocols)

                has_generic = True

                break # check once

        for k in constraints.keys():
            if k.startswith("ext_privacy_ecdh_"):
                for p in ecdh_required:
                    if p not in constraints.keys():
                        return False, False, False, "required transport parameter {} not found in constraints".format(p)
                    if p not in staged.keys():
                        return False, False, False, "required transport parameter {} not found in staged".format(p)
                    if p not in active.keys():
                        return False, False, False, "required transport parameter {} not found in active".format(p)
                    
                has_elliptic = True

                break # check once

        return True, has_generic, has_elliptic, None

    def check_generic_attribute_values(self, is_sender, sender_receiver, constraints, staged, active, elliptic):

        warning = None

        if is_sender:
            identity = "sender"
        else:
            identity = "receiver"

        null_protocol = False

        # check 'protocol' constraints
        allowed_protocols = ("RTP", "RTP_KV", "UDP", "UDP_KV", "USB", "USB_KV", "SRT", "RTSP", "RTSP_KV", "NULL")

        # protocol parameter must have a constraint the describe the protocols supported or NULL
        if "enum" not in constraints[privacy_protocol]:
            return False, "{} {} : {} constraint must list all the supported protocols or NULL".format(identity, sender_receiver["id"], privacy_protocol)

        enums = constraints[privacy_protocol]["enum"]

        # At least one protocol must be allowed
        if len(enums) == 0:
            return False, "{} {} : {} constraint must allow at least one value".format(identity, sender_receiver["id"], privacy_protocol)

        # Each allowed protocol must be a string and one of the allowed protocols of the specification.
        for c in enums:
            if not isinstance(c, str):
                return False, "{} {} : {} constraint value must be string".format(identity, sender_receiver["id"], privacy_protocol)
            if c not in allowed_protocols:
                return False, "{} {} : {} constraint value must be one of {}".format(identity, sender_receiver["id"], privacy_protocol, allowed_protocols)

        # If NULL is allowed, it must be the only one allowed            
        if "NULL" in enums:
            null_protocol = True
            if  len(enums) != 1:
                return False, "{} {} : {} constraint cannot allow other values if 'NULL' is allowed".format(identity, sender_receiver["id"], privacy_protocol)
        # if not NULL then verify against the transport being used
        else:
            if sender_receiver["transport"] in ("urn:x-nmos:transport:rtp", "urn:x-nmos:transport:rtp.mcast" and "urn:x-nmos:transport:rtp.ucast"):
                # for RTP based transport, the RTP protocol adaptation MUST be supported
                if "RTP" not in enums:
                    return False, "{} {} : {} constraint value must allow 'RTP' for transport {}".format(identity, sender_receiver["id"], privacy_protocol, sender_receiver["transport"])
                # for an RTP based transport only the RTP and RTP_KV adaptations are allowed
                for c in enums:
                    if c not in ("RTP", "RTP_KV"):
                        return False, "{} {} : {} constraint value must be one of 'RTP', 'RTP_KV' for transport {}".format(identity, sender_receiver["id"], privacy_protocol, sender_receiver["transport"])
            
            if sender_receiver["transport"] in ("urn:x-matrox:transport:udp", "urn:x-matrox:transport:udp.mcast" and "urn:x-matrox:transport:udp.ucast"):
                # for UDP based transport, the UDP protocol adaptation MUST be supported
                if "UDP" not in enums:
                    return False, "{} {} : {} constraint value must allow 'UDP' for transport {}".format(identity, sender_receiver["id"], privacy_protocol, sender_receiver["transport"])
                # for a UDP based transport only the UDP and UDP_KV adaptations are allowed
                for c in enums:
                    if c not in ("UDP", "UDP_KV"):
                        return False, "{} {} : {} constraint value must be one of 'UDP', 'UDP_KV' for transport {}".format(identity, sender_receiver["id"], privacy_protocol, sender_receiver["transport"])

            if sender_receiver["transport"] in ("urn:x-matrox:transport:usb"):
                # for USB based transport, the USB_KV protocol adaptation MUST be supported
                if "USB_KV" not in enums:
                    return False, "{} {} : {} constraint value must allow 'USB_KV' for transport {}".format(identity, sender_receiver["id"], privacy_protocol, sender_receiver["transport"])
                # for a USB based transport only the USB and USB_KV adaptations are allowed
                for c in enums:
                    if c not in ("USB", "USB_KV"):
                        return False, "{} {} : {} constraint value must be one of 'USB', 'USB_KV' for transport {}".format(identity, sender_receiver["id"], privacy_protocol, sender_receiver["transport"])

            if sender_receiver["transport"] in ("urn:x-matrox:transport:srt", "urn:x-matrox:transport:srt.mp2t"):
                # for SRT based transport (MPEG2-TS flavor), the SRT protocol adaptation MUST be supported
                if "SRT" not in enums:
                    return False, "{} {} : {} constraint value must allow 'SRT' for transport {}".format(identity, sender_receiver["id"], privacy_protocol, sender_receiver["transport"])
                # for an SRT based transport (MPEG2-TS flavor) only the SRT and UDP adaptations are allowed
                for c in enums:
                    if c not in ("SRT", "UDP"):
                        return False, "{} {} : {} constraint value must be one of 'SRT', 'UDP' for transport {}".format(identity, sender_receiver["id"], privacy_protocol, sender_receiver["transport"])
            if sender_receiver["transport"] in ("urn:x-matrox:transport:srt.rtp"):
                # for SRT based transport (RTP flavor), the SRT protocol adaptation MUST be supported
                if "SRT" not in enums:
                    return False, "{} {} : {} constraint value must allow 'SRT' for transport {}".format(identity, sender_receiver["id"], privacy_protocol, sender_receiver["transport"])
                # for an SRT based transport (RTP flavor) only the SRT and RTP adaptations are allowed
                for c in enums:
                    if c not in ("SRT", "RTP"):
                        return False, "{} {} : {} constraint value must be one of 'SRT', 'RTP' for transport {}".format(identity, sender_receiver["id"], privacy_protocol, sender_receiver["transport"])
            if sender_receiver["transport"] in ("urn:x-matrox:transport:rtsp", "urn:x-matrox:transport:rtsp.tcp"):
                # for RTSP based transport, the RTSP protocol adaptation MUST be supported
                if "RTSP" not in enums:
                    return False, "{} {} : {} constraint value must allow 'RTSP' for transport {}".format(identity, sender_receiver["id"], privacy_protocol, sender_receiver["transport"])
                # for a RTSP based transport only the RTSP and RTSP_KV adaptations are allowed
                for c in enums:
                    if c not in ("RTSP", "RTSP_KV"):
                        return False, "{} {} : {} constraint value must be one of 'RTSP', 'RTSP_KV' for transport {}".format(identity, sender_receiver["id"], privacy_protocol, sender_receiver["transport"])
                
        # check that 'protocol' staged and active values are within constraints
        if staged[privacy_protocol] not in enums:
            return False, "{} {} : {} staged value {} is not within constraints {}".format(identity, sender_receiver["id"], privacy_protocol, staged[privacy_protocol], enums)
        if active[privacy_protocol] not in enums:
            return False, "{} {} : {} active value {} is not within constraints {}".format(identity, sender_receiver["id"], privacy_protocol, staged[privacy_protocol], enums)

        ecdh = False

        if elliptic:
            # if ECDH privacy parameters are present
            allowed_curves = ("secp256r1", "secp521r1", "25519", "448", "NULL")

            # ecdh_curve parameter must have a constraint the describe the protocols supported or NULL
            if "enum" not in constraints[privacy_ecdh_curve]:
                return False, "{} {} : {} constraint must list all the supported curves".format(identity, sender_receiver["id"], privacy_ecdh_curve)
            
            # Note: the enum is allowed to have no value for the ECDH curve
            enums = constraints[privacy_ecdh_curve]["enum"]

            # Each allowed curve must be a string and one of the allowed curves of the specification.
            for c in enums:
                if not isinstance(c, str):
                    return False, "{} {} : {} constraint value must be string".format(identity, sender_receiver["id"], privacy_ecdh_curve)
                if c not in allowed_curves:
                    return False, "{} {} : {} constraint value must be one of {}".format(identity, sender_receiver["id"], privacy_ecdh_curve, allowed_modes)

            # If NULL is allowed, it must be the only one allowed            
            if "NULL" in enums:
                if len(enums) != 1:
                    return False, "{} {} : {} constraint cannot have other values if 'NULL' is allowed".format(identity, sender_receiver["id"], privacy_ecdh_curve)
            else:
                if "secp256r1" not in enums:
                    return False, "{} {} : {} constraint value must allow 'secp256r1'".format(identity, sender_receiver["id"], privacy_ecdh_curve)

                ecdh = True

            # check that 'ecdh_curve' staged and active values are within constraints
            if staged[privacy_ecdh_curve] not in enums:
                return False, "{} {} : {} staged value {} is not within constraints {}".format(identity, sender_receiver["id"], privacy_ecdh_curve, staged[privacy_ecdh_curve], enums)
            if active[privacy_ecdh_curve] not in enums:
                return False, "{} {} : {} active value {} is not within constraints {}".format(identity, sender_receiver["id"], privacy_ecdh_curve, staged[privacy_ecdh_curve], enums)

        # check 'mode' constraints. 
        if ecdh:
            allowed_rtp_modes = ("AES-128-CTR", "AES-256-CTR", "AES-128-CTR_CMAC-64", "AES-256-CTR_CMAC-64", "AES-128-CTR_CMAC-64-AAD", "AES-256-CTR_CMAC-64-AAD", "ECDH_AES-128-CTR", "ECDH_AES-256-CTR", "ECDH_AES-128-CTR_CMAC-64", "ECDH_AES-256-CTR_CMAC-64", "ECDH_AES-128-CTR_CMAC-64-AAD", "ECDH_AES-256-CTR_CMAC-64-AAD")
            allowed_udp_modes = ("AES-128-CTR", "AES-256-CTR", "ECDH_AES-128-CTR", "ECDH_AES-256-CTR")
            allowed_srt_modes = ("AES-128-CTR", "AES-256-CTR", "ECDH_AES-128-CTR", "ECDH_AES-256-CTR", "AES-128-GMAC-128", "AES-256-GMAC-128", "ECDH_AES-128-GMAC-128", "ECDH_AES-256-GMAC-128")
            allowed_usb_modes = ("AES-128-CTR_CMAC-64-AAD", "AES-256-CTR_CMAC-64-AAD", "ECDH_AES-128-CTR_CMAC-64-AAD", "ECDH_AES-256-CTR_CMAC-64-AAD")
        else:
            # ECDH modes must not be allowed if an ECDH curve is not supported
            allowed_rtp_modes = ("AES-128-CTR", "AES-256-CTR", "AES-128-CTR_CMAC-64", "AES-256-CTR_CMAC-64", "AES-128-CTR_CMAC-64-AAD", "AES-256-CTR_CMAC-64-AAD")
            allowed_udp_modes = ("AES-128-CTR", "AES-256-CTR")
            allowed_srt_modes = ("AES-128-CTR", "AES-256-CTR", "AES-128-GMAC-128", "AES-256-GMAC-128")
            allowed_usb_modes = ("AES-128-CTR_CMAC-64-AAD", "AES-256-CTR_CMAC-64-AAD")

        allowed_rtsp_modes = tuple(set(allowed_rtp_modes + allowed_udp_modes)) # remove duplicates

        allowed_modes = tuple(set(allowed_rtp_modes + allowed_udp_modes + allowed_srt_modes + allowed_usb_modes)) # remove duplicates

        # mode parameter must have a constraint the describe the modes supported or NULL
        if "enum" not in constraints[privacy_mode]:
            return False, "{} {} : {} constraint must list all the supported modes or NULL".format(identity, sender_receiver["id"], privacy_mode)
        
        enums = constraints[privacy_mode]["enum"]

        # At least one mode must be allowed
        if len(enums) == 0:
            return False, "{} {} : {} constraint must allow at least one value".format(identity, sender_receiver["id"], privacy_mode)

        # Each allowed mode must be a string and one of the allowed modes of the specification.
        for c in enums:
            if not isinstance(c, str):
                return False, "{} {} : {} constraint value must be string".format(identity, sender_receiver["id"], privacy_mode)
            if c not in allowed_modes:
                return False, "{} {} : {} constraint value must be one of {}".format(identity, sender_receiver["id"], privacy_mode, allowed_modes)

        # If NULL is allowed, it must be the only one allowed and must match with protocol
        if "NULL" in enums:
            if not null_protocol:
                return False, "{} {} : {} constraint must match protocol if 'NULL' is allowed".format(identity, sender_receiver["id"], privacy_mode)
            if  len(enums) != 1:
                return False, "{} {} : {} constraint cannot have other values if 'NULL' is allowed".format(identity, sender_receiver["id"], privacy_mode)
        # if not NULL then verify against the protocol adaptation being used
        else:            
            if all(item in ("RTP", "RTP_KV") for item in constraints[privacy_protocol]["enum"]):
                # for RTP, RTP_KV adaptations the AES-128-CTR mode MUST be supported
                if "AES-128-CTR" not in enums:
                    return False, "{} {} : {} constraint value must allow 'AES-128-CTR' for protocol {}".format(identity, sender_receiver["id"], privacy_mode, constraints[privacy_protocol]["enum"])
                # for RTP, RTP_KV adaptations the mode MUST be on of the RTP modes
                for c in enums:
                    if c not in allowed_rtp_modes:
                        return False, "{} {} : {} constraint value must be one of {} for protocol {}".format(identity, sender_receiver["id"], privacy_mode, allowed_modes, constraints[privacy_protocol]["enum"])
            if all(item in ("UDP", "UDP_KV") for item in constraints[privacy_protocol]["enum"]):
                # for UDP, UDP_KV adaptations the AES-128-CTR mode MUST be supported
                if "AES-128-CTR" not in enums:
                    return False, "{} {} : {} constraint value must allow 'AES-128-CTR' for protocol {}".format(identity, sender_receiver["id"], privacy_mode, constraints[privacy_protocol]["enum"])
                # for UDP, UDP_KV adaptations the mode MUST be on of the UDP modes
                for c in enums:
                    if c not in allowed_udp_modes:
                        return False, "{} {} : {} constraint value must be one of {} for protocol {}".format(identity, sender_receiver["id"], privacy_mode, allowed_udp_modes, constraints[privacy_protocol]["enum"])
            if all(item in ("USB", "USB_KV") for item in constraints[privacy_protocol]["enum"]):
                # for USB, USB_KV adaptations the AES-128-CTR_CMAC-64-AAD mode MUST be supported
                if "AES-128-CTR_CMAC-64-AAD" not in enums:
                    return False, "{} {} : {} constraint value must allow 'AES-128-CTR_CMAC-64-AAD' for protocol {}".format(identity, sender_receiver["id"], privacy_mode, constraints[privacy_protocol]["enum"])
                # for USB, USB_KV adaptations the mode MUST be on of the USB modes
                for c in enums:
                    if c not in allowed_usb_modes:
                        return False, "{} {} : {} constraint value must be one of {} for protocol {}".format(identity, sender_receiver["id"], privacy_mode, allowed_usb_modes, constraints[privacy_protocol]["enum"])
            if all(item in ("SRT") for item in constraints[privacy_protocol]["enum"]):
                # for SRT adaptations the AES-128-CTR mode MUST be supported
                if "AES-128-CTR" not in enums:
                    return False, "{} {} : {} constraint value must allow 'AES-128-CTR' for protocol {}".format(identity, sender_receiver["id"], privacy_mode, constraints[privacy_protocol]["enum"])
                # for SRT adaptations the mode MUST be on of the SRT modes
                for c in enums:
                    if c not in allowed_srt_modes:
                        return False, "{} {} : {} constraint value must be one of {} for protocol {}".format(identity, sender_receiver["id"], privacy_mode, allowed_srt_modes, constraints[privacy_protocol]["enum"])
            if all(item in ("RTSP", "RTSP_KV") for item in constraints[privacy_protocol]["enum"]):
                # for RTSP adaptations the AES-128-CTR mode MUST be supported
                if "AES-128-CTR" not in enums:
                    return False, "{} {} : {} constraint value must allow 'AES-128-CTR' for protocol {}".format(identity, sender_receiver["id"], privacy_mode, constraints[privacy_protocol]["enum"])
                # for RTSP, RTSP_KV adaptations the mode MUST be on of the union of RTP and UDP modes
                for c in enums:
                    if c not in allowed_rtsp_modes:
                        return False, "{} {} : {} constraint value must be one of {} for protocol {}".format(identity, sender_receiver["id"], privacy_mode, allowed_srt_modes, constraints[privacy_protocol]["enum"])

        # check that 'mode' staged and active values are within constraints
        if staged[privacy_mode] not in enums:
            return False, "{} {} : {} staged value {} is not within constraints {}".format(identity, sender_receiver["id"], privacy_mode, staged[privacy_mode], enums)
        if active[privacy_mode] not in enums:
            return False, "{} {} : {} active value {} is not within constraints {}".format(identity, sender_receiver["id"], privacy_mode, staged[privacy_mode], enums)

        if is_sender:
            # The iv parameter constraints MUST allow only one value an be properly formatted
            if "enum" not in constraints[privacy_iv]:
                return False, "{} {} : {} constraint must allow exactly one value for read-only parameters".format(identity, sender_receiver["id"], privacy_iv)
            enums = constraints[privacy_iv]["enum"]
            if len(enums) != 1:
                return False, "{} {} : {} constraint must allow exactly one value for read-only parameters".format(identity, sender_receiver["id"], privacy_iv)
            if not isinstance(enums[0], str):
                return False, "{} {} : {} constraint value must be string".format(identity, sender_receiver["id"], privacy_iv)
            if len(enums[0]) != 16 or not all(char in "0123456789abcdefABCDEF" for char in enums[0]):
                return False, "{} {} : {} constraint must be a 64 bit hexadecimal value".format(identity, sender_receiver["id"], privacy_iv)
            # check that staged and active values are within constraints
            if staged[privacy_iv] not in enums:
                return False, "{} {} : {} staged value {} is not within constraints {}".format(identity, sender_receiver["id"], privacy_iv, staged[privacy_iv], enums)
            if active[privacy_iv] not in enums:
                return False, "{} {} : {} active value {} is not within constraints {}".format(identity, sender_receiver["id"], privacy_iv, staged[privacy_iv], enums)
        else:
            # for the Receiver the iv parameter constraints SHOULD allow any value and internally verify for proper size and hexadecimal
            if "enum" in constraints[privacy_iv]:
                warning = (warning or "") + " " + "{} {} : {} constraint should allow any value".format(identity, sender_receiver["id"], privacy_iv)
            if "pattern" in constraints[privacy_iv] and constraints[privacy_iv]["pattern"] != "^[0-9a-fA-F]{16}$":
                warning = (warning or "") + " " + "{} {} : {} constraint pattern should be '^[0-9a-fA-F]{16}$'".format(identity, sender_receiver["id"], privacy_iv)
            if len(staged[privacy_iv]) < 2 or not all(char in "0123456789abcdefABCDEF" for char in staged[privacy_iv]):
                return False, "{} {} : {} staged value {} is not within constraints {}".format(identity, sender_receiver["id"], privacy_iv, staged[privacy_iv], enums)
            if len(active[privacy_iv]) < 2 or not all(char in "0123456789abcdefABCDEF" for char in active[privacy_iv]):
                return False, "{} {} : {} active value {} is not within constraints {}".format(identity, sender_receiver["id"], privacy_iv, staged[privacy_iv], enums)

        if is_sender:
            # The key_generator parameter constraints MUST allow only one value an be properly formatted
            if "enum" not in constraints[privacy_key_generator]:
                return False, "{} {} : {} constraint must allow exactly one value for read-only parameters".format(identity, sender_receiver["id"], privacy_key_generator)
            enums = constraints[privacy_key_generator]["enum"]
            if len(enums) != 1:
                return False, "{} {} : {} constraint must allow exactly one value for read-only parameters".format(identity, sender_receiver["id"], privacy_key_generator)
            if not isinstance(enums[0], str):
                return False, "{} {} : {} constraint value must be string".format(identity, sender_receiver["id"], privacy_key_generator)
            if len(enums[0]) != 32 or not all(char in "0123456789abcdefABCDEF" for char in enums[0]):
                return False, "{} {} : {} constraint must be a 128 bit hexadecimal value".format(identity, sender_receiver["id"], privacy_key_generator)
        else:
            # for the Receiver the key_generator parameter constraints SHOULD allow any value and internally verify for proper size and hexadecimal
            if "enum" in constraints[privacy_key_generator]:
                warning = (warning or "") + " " + "{} {} : {} constraint should allow any value".format(identity, sender_receiver["id"], privacy_key_generator)
            if "pattern" in constraints[privacy_key_generator] and constraints[privacy_key_generator]["pattern"] != "^[0-9a-fA-F]{32}$":
                warning = (warning or "") + " " + "{} {} : {} constraint pattern should be '^[0-9a-fA-F]{32}$'".format(identity, sender_receiver["id"], privacy_key_generator)
            if len(staged[privacy_key_generator]) < 2 or not all(char in "0123456789abcdefABCDEF" for char in staged[privacy_key_generator]):
                return False, "{} {} : {} staged value {} is not within constraints {}".format(identity, sender_receiver["id"], privacy_key_generator, staged[privacy_key_generator], enums)
            if len(active[privacy_key_generator]) < 2 or not all(char in "0123456789abcdefABCDEF" for char in active[privacy_key_generator]):
                return False, "{} {} : {} active value {} is not within constraints {}".format(identity, sender_receiver["id"], privacy_key_generator, staged[privacy_key_generator], enums)

        if is_sender:
            # The key_version parameter constraints MUST allow only one value an be properly formatted
            if "enum" not in constraints[privacy_key_version]:
                return False, "{} {} : {} constraint must allow exactly one value for read-only parameters".format(identity, sender_receiver["id"], privacy_key_version)
            enums = constraints[privacy_key_version]["enum"]
            if len(enums) != 1:
                return False, "{} {} : {} constraint must allow exactly one value for read-only parameters".format(identity, sender_receiver["id"], privacy_key_version)
            if not isinstance(enums[0], str):
                return False, "{} {} : {} constraint value must be string".format(identity, sender_receiver["id"], privacy_key_version)
            if len(enums[0]) != 8 or not all(char in "0123456789abcdefABCDEF" for char in enums[0]):
                return False, "{} {} : {} constraint must be a 32 bit hexadecimal value".format(identity, sender_receiver["id"], privacy_key_version)
        else:
            # for the Receiver the key_version parameter constraints SHOULD allow any value and internally verify for proper size and hexadecimal
            if "enum" in constraints[privacy_key_version]:
                warning = (warning or "") + " " + "{} {} : {} constraint should allow any value".format(identity, sender_receiver["id"], privacy_key_version)
            if "pattern" in constraints[privacy_key_version] and constraints[privacy_key_version]["pattern"] != "^[0-9a-fA-F]{8}$":
                warning = (warning or "") + " " + "{} {} : {} constraint pattern should be '^[0-9a-fA-F]{8}$'".format(identity, sender_receiver["id"], privacy_key_version)
            if len(staged[privacy_key_version]) < 2 or not all(char in "0123456789abcdefABCDEF" for char in staged[privacy_key_version]):
                return False, "{} {} : {} staged value {} is not within constraints {}".format(identity, sender_receiver["id"], privacy_key_version, staged[privacy_key_version], enums)
            if len(active[privacy_key_version]) < 2 or not all(char in "0123456789abcdefABCDEF" for char in active[privacy_key_version]):
                return False, "{} {} : {} active value {} is not within constraints {}".format(identity, sender_receiver["id"], privacy_key_version, staged[privacy_key_version], enums)

        if is_sender:
            # The key_id parameter constraints MUST allow only one value an be properly formatted
            if "enum" not in constraints[privacy_key_id]:
                return False, "{} {} : {} constraint must allow exactly one value for read-only parameters".format(identity, sender_receiver["id"], privacy_key_id)
            enums = constraints[privacy_key_id]["enum"]
            if len(enums) != 1:
                return False, "{} {} : {} constraint must allow exactly one value for read-only parameters".format(identity, sender_receiver["id"], privacy_key_id)
            if not isinstance(enums[0], str):
                return False, "{} {} : {} constraint value must be string".format(identity, sender_receiver["id"], privacy_key_id)
            if len(enums[0]) != 16 or not all(char in "0123456789abcdefABCDEF" for char in enums[0]):
                return False, "{} {} : {} constraint must be a 64 bit hexadecimal value".format(identity, sender_receiver["id"], privacy_key_id)
        else:
            # for a Receiver all knowned key_id MUST be listed
            if "enum" not in constraints[privacy_key_id]:
                return False, "{} {} : {} constraint must allow at least one value".format(identity, sender_receiver["id"], privacy_key_id)
            enums = constraints[privacy_key_id]["enum"]
            if len(enums) == 0:
                return False, "{} {} : {} constraint must allow at least one value".format(identity, sender_receiver["id"], privacy_key_id)
            #            
            for c in enums:
                if not isinstance(c, str):
                    return False, "{} {} : {} constraint value must be string".format(identity, sender_receiver["id"], privacy_key_id)
                if len(c) != 16 or not all(char in "0123456789abcdefABCDEF" for char in c):
                    return False, "{} {} : {} constraint must be a 64 bit hexadecimal value".format(identity, sender_receiver["id"], privacy_key_id)

        if elliptic:
            if ecdh:
                if is_sender:
                    if "enum" not in constraints[privacy_ecdh_sender_public_key]:
                        return False, "{} {} : {} constraint must allow exactly one value for read-only parameters".format(identity, sender_receiver["id"], privacy_ecdh_sender_public_key)
                    enums = constraints[privacy_ecdh_sender_public_key]["enum"]
                    if len(enums) != 1:
                        return False, "{} {} : {} constraint must allow exactly one value for read-only parameters".format(identity, sender_receiver["id"], privacy_ecdh_sender_public_key)
                    if not isinstance(enums[0], str):
                        return False, "{} {} : {} constraint value must be string".format(identity, sender_receiver["id"], privacy_ecdh_sender_public_key)
                    # check for minimum length of 2 for "00" but left the upper bound open as it depends on many factors
                    if len(enums[0]) < 2 or not all(char in "0123456789abcdefABCDEF" for char in enums[0]):
                        return False, "{} {} : {} constraint must be an hexadecimal value".format(identity, sender_receiver["id"], privacy_ecdh_sender_public_key)
                else:
                    if "enum" in constraints[privacy_ecdh_sender_public_key]:
                        warning = (warning or "") + " " + "{} {} : {} constraint should allow any value".format(identity, sender_receiver["id"], privacy_ecdh_sender_public_key)
                    if "pattern" in constraints[privacy_ecdh_sender_public_key] and constraints[privacy_ecdh_sender_public_key]["pattern"] != "^[0-9a-fA-F]{2,}$":
                        warning = (warning or "") + " " + "{} {} : {} constraint pattern should be '^[0-9a-fA-F]{2,}$'".format(identity, sender_receiver["id"], privacy_ecdh_sender_public_key)
                    if len(staged[privacy_ecdh_sender_public_key]) < 2 or not all(char in "0123456789abcdefABCDEF" for char in staged[privacy_ecdh_sender_public_key]):
                        return False, "{} {} : {} staged value {} is not within constraints {}".format(identity, sender_receiver["id"], privacy_ecdh_sender_public_key, staged[privacy_ecdh_sender_public_key], enums)
                    if len(active[privacy_ecdh_sender_public_key]) < 2 or not all(char in "0123456789abcdefABCDEF" for char in active[privacy_ecdh_sender_public_key]):
                        return False, "{} {} : {} active value {} is not within constraints {}".format(identity, sender_receiver["id"], privacy_ecdh_sender_public_key, staged[privacy_ecdh_sender_public_key], enums)

                if not is_sender:
                    if "enum" not in constraints[privacy_ecdh_receiver_public_key]:
                        return False, "{} {} : {} constraint must allow exactly one value for read-only parameters".format(identity, sender_receiver["id"], privacy_ecdh_receiver_public_key)
                    enums = constraints[privacy_ecdh_receiver_public_key]["enum"]
                    if len(enums) != 1:
                        return False, "{} {} : {} constraint must allow exactly one value for read-only parameters".format(identity, sender_receiver["id"], privacy_ecdh_receiver_public_key)
                    if not isinstance(enums[0], str):
                        return False, "{} {} : {} constraint value must be string".format(identity, sender_receiver["id"], privacy_ecdh_receiver_public_key)
                    # check for minimum length of 2 for "00" but left the upper bound open as it depends on many factors
                    if len(enums[0]) < 2 or not all(char in "0123456789abcdefABCDEF" for char in enums[0]):
                        return False, "{} {} : {} constraint must be an hexadecimal value".format(identity, sender_receiver["id"], privacy_ecdh_receiver_public_key)
                else:
                    if "enum" in constraints[privacy_ecdh_receiver_public_key]:
                        warning = (warning or "") + " " + "{} {} : {} constraint should allow any value".format(identity, sender_receiver["id"], privacy_ecdh_receiver_public_key)
                    if "pattern" in constraints[privacy_ecdh_receiver_public_key] and constraints[privacy_ecdh_receiver_public_key]["pattern"] != "^[0-9a-fA-F]{2,}$":
                        warning = (warning or "") + " " + "{} {} : {} constraint pattern should be '^[0-9a-fA-F]{2,}$'".format(identity, sender_receiver["id"], privacy_ecdh_receiver_public_key)
                    if len(staged[privacy_ecdh_receiver_public_key]) < 2 or not all(char in "0123456789abcdefABCDEF" for char in staged[privacy_ecdh_receiver_public_key]):
                        return False, "{} {} : {} staged value {} is not within constraints {}".format(identity, sender_receiver["id"], privacy_ecdh_receiver_public_key, staged[privacy_ecdh_receiver_public_key], enums)
                    if len(active[privacy_ecdh_receiver_public_key]) < 2 or not all(char in "0123456789abcdefABCDEF" for char in active[privacy_ecdh_receiver_public_key]):
                        return False, "{} {} : {} active value {} is not within constraints {}".format(identity, sender_receiver["id"], privacy_ecdh_receiver_public_key, staged[privacy_ecdh_receiver_public_key], enums)
            else:
                # if the parameter is present but ECDH is not supported, then if a constraint is provided is MUST be "00" or empty
                if "enum" in constraints[privacy_ecdh_sender_public_key]:
                    enums = constraints[privacy_ecdh_sender_public_key]["enum"]
                    if len(enums) > 1:
                        return False, "{} {} : {} constraint must not allow more than the 00 value for unsupported ECDH mode".format(identity, sender_receiver["id"], privacy_ecdh_sender_public_key)
                    if len(enums) != 0:                    
                        if not isinstance(enums[0], str):
                            return False, "{} {} : {} constraint value must be string".format(identity, sender_receiver["id"], privacy_ecdh_sender_public_key)
                        if len(enums[0]) != 2 or not all(char in "0123456789abcdefABCDEF" for char in enums[0]):
                            return False, "{} {} : {} constraint must be an 8 bit hexadecimal null value".format(identity, sender_receiver["id"], privacy_ecdh_sender_public_key)
                # if the parameter is present but ECDH is not supported, then if a constraint is provided is MUST be "00" or empty
                if "enum" in constraints[privacy_ecdh_receiver_public_key]:
                    enums = constraints[privacy_ecdh_receiver_public_key]["enum"]
                    if len(enums) > 1:
                        return False, "{} {} : {} constraint must not allow more than the 00 value for unsupported ECDH mode".format(identity, sender_receiver["id"], privacy_ecdh_receiver_public_key)
                    if len(enums) != 0:                    
                        if not isinstance(enums[0], str):
                            return False, "{} {} : {} constraint value must be string".format(identity, sender_receiver["id"], privacy_ecdh_receiver_public_key)
                        if len(enums[0]) != 2 or not all(char in "0123456789abcdefABCDEF" for char in enums[0]):
                            return False, "{} {} : {} constraint must be an 8 bit hexadecimal null value".format(identity, sender_receiver["id"], privacy_ecdh_receiver_public_key)

        # a warning is a success with a message
        return True, warning

    def check_across_legs(self, is_sender, sender_receiver, constraints, staged, active, elliptic):

        warning = None

        if is_sender:
            identity = "sender"
        else:
            identity = "receiver"

        null_protocol = False

        if not isinstance(constraints, list) or not isinstance(staged, list) or not isinstance(active, list):
            raise Exception("expecting arrays")

        i = 0
        for leg in constraints:
            for k in leg.keys():
                if constraints[i][k] != constraints[0][k]:
                    return False, "{} {} : {} parameter constraints value of leg {} not matching leg 0".format(identity, sender_receiver["id"], k, i)
                if staged[i][k] != staged[0][k]:
                    return False, "{} {} : {} staged parameter value of leg {} not matching leg 0".format(identity, sender_receiver["id"], k, i)
                if active[i][k] != active[0][k]:
                    return False, "{} {} : {} staged parameter value of leg {} not matching leg 0".format(identity, sender_receiver["id"], k, i)

            i += 1

        if not warning:
            return True, None
        else:
            return False, warning
        
    def check_privacy_attribute(self, is_sender, sender_receiver, legs, constraints, active, sdp_lines):

        if is_sender:
            identity = "sender"
        else:
            identity = "receiver"

        found_session = 0
        found_media = 0
        session_level = True

        for sdp_line in sdp_lines:

            media = re.search(r"^m=(.+)$", sdp_line)
            if media:
                session_level = False
                continue

            privacy = re.search(r"^a=privacy:(.+)$", sdp_line)
            if privacy:

                if session_level:
                    found_session +=1
                else:
                    found_media +=1

                sdp_privacy_params = {}
                for param in privacy.group(1).split(";"):
                    name, _, value = param.strip().partition("=")
                    if name not in [sdp_privacy_protocol, sdp_privacy_mode, sdp_privacy_iv, sdp_privacy_key_generator, sdp_privacy_key_version, sdp_privacy_key_id ]:
                        return False, "{} {} : privacy attribute parameter {} is invalid".format(identity, sender_receiver["id"], name)
                    sdp_privacy_params[name] = value

                # check against constraints
                if sdp_privacy_params[sdp_privacy_protocol] not in constraints[privacy_protocol]["enum"]:
                    return False, "{} {} : privacy attribute parameter {} value {} is not within constraints {}".format(identity, sender_receiver["id"], name, sdp_privacy_params[sdp_privacy_protocol], constraints[privacy_protocol]["enum"])
                if sdp_privacy_params[sdp_privacy_mode] not in constraints[privacy_mode]["enum"]:
                    return False, "{} {} : privacy attribute parameter {} value {} is not within constraints {}".format(identity, sender_receiver["id"], name, sdp_privacy_params[sdp_privacy_mode], constraints[privacy_mode]["enum"])
                if sdp_privacy_params[sdp_privacy_key_id] not in constraints[privacy_key_id]["enum"]:
                    return False, "{} {} : privacy attribute parameter {} value {} is not within constraints {}".format(identity, sender_receiver["id"], name, sdp_privacy_params[sdp_privacy_key_id], constraints[privacy_key_id]["enum"])

                if is_sender:
                    if sdp_privacy_params[sdp_privacy_iv] not in constraints[privacy_iv]["enum"]:
                        return False, "{} {} : privacy attribute parameter {} value {} is not within constraints {}".format(identity, sender_receiver["id"], name, sdp_privacy_params[sdp_privacy_iv], constraints[privacy_iv]["enum"])
                    if sdp_privacy_params[sdp_privacy_key_generator] not in constraints[privacy_key_generator]["enum"]:
                        return False, "{} {} : privacy attribute parameter {} value {} is not within constraints {}".format(identity, sender_receiver["id"], name, sdp_privacy_params[sdp_privacy_key_generator], constraints[privacy_key_generator]["enum"])
                    if sdp_privacy_params[sdp_privacy_key_version] not in constraints[privacy_key_version]["enum"]:
                        return False, "{} {} : privacy attribute parameter {} value {} is not within constraints {}".format(identity, sender_receiver["id"], name, sdp_privacy_params[sdp_privacy_key_version], constraints[privacy_key_version]["enum"])
                else:
                    if len(sdp_privacy_params[sdp_privacy_iv]) != 16 or not all(char in "0123456789abcdefABCDEF" for char in sdp_privacy_params[sdp_privacy_iv]):
                        return False, "{} {} : privacy attribute parameter {} value {} is not valid".format(identity, sender_receiver["id"], name, sdp_privacy_params[sdp_privacy_iv])
                    if len(sdp_privacy_params[sdp_privacy_key_generator]) != 32 or not all(char in "0123456789abcdefABCDEF" for char in sdp_privacy_params[sdp_privacy_key_generator]):
                        return False, "{} {} : privacy attribute parameter {} value {} is not valid".format(identity, sender_receiver["id"], name, sdp_privacy_params[sdp_privacy_key_generator])
                    if len(sdp_privacy_params[sdp_privacy_key_version]) != 8 or not all(char in "0123456789abcdefABCDEF" for char in sdp_privacy_params[sdp_privacy_key_version]):
                        return False, "{} {} : privacy attribute parameter {} value {} is not valid".format(identity, sender_receiver["id"], name, sdp_privacy_params[sdp_privacy_key_version])

                # check against active values
                if sdp_privacy_params[sdp_privacy_protocol] != active[privacy_protocol]:
                    return False, "{} {} : privacy attribute parameter {} value {} is not matching active value {}".format(identity, sender_receiver["id"], name, sdp_privacy_params[sdp_privacy_protocol], active[privacy_protocol])
                if sdp_privacy_params[sdp_privacy_mode] != active[privacy_mode]:
                    return False, "{} {} : privacy attribute parameter {} value {} is not matching active value {}".format(identity, sender_receiver["id"], name, sdp_privacy_params[sdp_privacy_mode], active[privacy_mode])
                if sdp_privacy_params[sdp_privacy_key_id] != active[privacy_key_id]:
                    return False, "{} {} : privacy attribute parameter {} value {} is not matching active value {}".format(identity, sender_receiver["id"], name, sdp_privacy_params[sdp_privacy_key_id], active[privacy_key_id])
                if sdp_privacy_params[sdp_privacy_iv] != active[privacy_iv]:
                    return False, "{} {} : privacy attribute parameter {} value {} is not matching active value {}".format(identity, sender_receiver["id"], name, sdp_privacy_params[sdp_privacy_iv], active[privacy_iv])
                if sdp_privacy_params[sdp_privacy_key_generator] != active[privacy_key_generator]:
                    return False, "{} {} : privacy attribute parameter {} value {} is not matching active value {}".format(identity, sender_receiver["id"], name, sdp_privacy_params[sdp_privacy_key_generator], active[privacy_key_generator])
                if sdp_privacy_params[sdp_privacy_key_version] != active[privacy_key_version]:
                    return False, "{} {} : privacy attribute parameter {} value {} is not matching active value {}".format(identity, sender_receiver["id"], name, sdp_privacy_params[sdp_privacy_key_version], active[privacy_key_version])

        if (found_session > 1) or (found_media != 0 and found_media != legs) or (found_session == 0 and found_media == 0):
            return False, "{} {} : missing privacy session/media attribute(s) in SDP transport file, found {} session level, {} media level, has {} legs".format(identity, sender_receiver["id"], found_session, found_media, legs)

        # check RTP extension headers for RTP protocol adaptation
        if active[privacy_protocol] in ("RTP", "RTP_KV"):

            found_short = False
            found_full = False

            for sdp_line in sdp_lines:
                extmap = re.search(r"^a=extmap:[0-9]+/([a-z]+) (.+)$", sdp_line)
                if extmap:
                    if extmap.group(1) != "sendonly" and (extmap.group(2) == "urn:ietf:params:rtp-hdrext:PEP-Full-IV-Counter" or extmap.group(2) != "urn:ietf:params:rtphdrext:PEP-Short-IV-Counter"):
                        return False, "{} {} : extmap attribute is invalid, direction is {} and mus tbe sendonly.".format(identity, sender_receiver["id"], extmap.group(1))
                    if extmap.group(2) == "urn:ietf:params:rtp-hdrext:PEP-Full-IV-Counter":
                        found_full = True
                    if extmap.group(2) == "urn:ietf:params:rtp-hdrext:PEP-Short-IV-Counter":
                        found_short = True

            # This is a SHOULD for VSF/PEP specification made MUST by the NMOS specification to enhance interoperability.
            if not found_short or not found_full:
                return False, "{} {} : extmap attributes for PEP extension headers are missing".format(identity, sender_receiver["id"])

        return True, None
