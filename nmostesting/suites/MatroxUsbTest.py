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

media_type_constraint = "urn:x-nmos:cap:format:media_type"

def urn_without_namespace(s):
    match = re.search(r'^urn:[a-z0-9][a-z0-9-]+:(.*)', s)
    return match.group(1) if match else None

def get_key_value(obj, name):
    regex = re.compile(r'^urn:[a-z0-9][a-z0-9-]+:' + name + r'$')
    for key, value in obj.items():
        if regex.fullmatch(key):
            return value
    return obj[name]  # final try without a namespace


def has_key(obj, name):
    regex = re.compile(r'^urn:[a-z0-9][a-z0-9-]+:' + name + r'$')
    for key in obj.keys():
        if regex.fullmatch(key):
            return True
    return name in obj  # final try without a namespace


class MatroxUsbTest(GenericTest):
    """
    Runs Node Tests covering 'Matrox With USB'
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
        """USB Flows have the required attributes"""

        self.do_test_node_api_v1_3(test)

        reg_api = self.apis[FLOW_REGISTER_KEY]

        valid, result = self.get_is04_resources("flows")
        if not valid:
            return test.FAIL(result)

        reg_path = reg_api["spec_path"] + "/flow-attributes"
        reg_schema = load_resolved_schema(reg_path, "flow_data_register.json", path_prefix=False)

        try:
            flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"].values()}

            usb_flows = [flow for flow in self.is04_resources["flows"].values() if flow["format"] == "urn:x-nmos:format:data"
                                                                        and flow["media_type"] == "application/usb"]
            
            for mux_flow in [flow for flow in self.is04_resources["flows"].values() if flow["format"] == "urn:x-nmos:format:mux"]:
                for parent_flow in mux_flow["parents"]:
                    if flow_map[parent_flow]["format"] == "urn:x-nmos:format:data":
                        if flow_map[parent_flow]["media_type"] == "application/usb":
                            return test.FAIL("flow {}: USB data flow cannot be parebt of a mux Flow".format(parent_flow["id"]))

            for flow in usb_flows:
                # There are no required attributes
                # Check values against the schema
                try:
                    self.validate_schema(flow, reg_schema)
                except ValidationError as e:
                    return test.FAIL("flow {} does not comply with the schema for Data Flow additional and "
                                     "extensible attributes defined in the NMOS Parameter Registers: "
                                     "{}".format(flow["id"], str(e)),
                                     "https://specs.amwa.tv/nmos-parameter-registers/branches/{}"
                                     "/flow-attributes/flow_data_register.html"
                                     .format(reg_api["spec_branch"]))

            if len(usb_flows) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No USB Flow resources were found on the Node")

    def test_03(self, test):
        """USB Sources have the required attributes"""

        self.do_test_node_api_v1_3(test)

        for resource_type in ["flows", "sources"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        source_map = {source["id"]: source for source in self.is04_resources["sources"].values()}
        flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"].values()}

        try:
            usb_flows = [flow for flow in self.is04_resources["flows"].values() if flow["format"] == "urn:x-nmos:format:data"
                                                                        and flow["media_type"] == "application/usb"]
            
            for mux_flow in [flow for flow in self.is04_resources["flows"].values() if flow["format"] == "urn:x-nmos:format:mux"]:
                for parent_flow in mux_flow["parents"]:
                    if flow_map[parent_flow]["format"] == "urn:x-nmos:format:data":
                        if flow_map[parent_flow]["media_type"] == "application/usb":
                            return test.FAIL("flow {}: USB data flow cannot be parent of a mux Flow".format(parent_flow["id"]))

            for flow in usb_flows:
                source = source_map[flow["source_id"]]

                if source["format"] != "urn:x-nmos:format:data":
                    return test.FAIL("source {}: MUST indicate format with value 'urn:x-nmos:format:data'"
                                     .format(source["id"]))

                # Check that the optional 'usb_devices' attribute has proper structure
                if has_key(source, "usb_devices"):
                    ok, msg = check_usb_devices_attribute(get_key_value(source, "usb_devices"))
                    if not ok:
                        return test.FAIL("source {}: invalid 'usb_devices' attribute, error {}".format(source["id"]), msg)

            if len(usb_flows) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No USB Flow resources were found on the Node")

    def test_04(self, test):
        """USB Senders have the required attributes"""

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
            usb_senders = [sender for sender in self.is04_resources["senders"].values() if sender["flow_id"]
                            and sender["flow_id"] in flow_map
                            and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:data"
                            and flow_map[sender["flow_id"]]["media_type"] == "application/usb"]

            warn_message = ""

            for sender in usb_senders:
                # check required attributes are present
                if "transport" not in sender:
                    return test.FAIL("sender {}: MUST indicate the 'transport' attribute."
                                     .format(sender["id"]))

                if urn_without_namespace(sender["transport"]) != "transport:usb":
                    return test.FAIL("sender {}: 'transport' attribute MUST indicate 'urn:*:transport:usb'"
                                     .format(sender["id"]))

                # check values of all additional attributes against the schema
                try:
                    self.validate_schema(sender, reg_schema)
                except ValidationError as e:
                    return test.FAIL("sender {}: does not comply with the schema for Sender additional and "
                                     "extensible attributes defined in the NMOS Parameter Registers: "
                                     "{}".format(sender["id"], str(e)),
                                     "https://specs.amwa.tv/nmos-parameter-registers/branches/{}"
                                     "/sender-attributes/sender_register.html"
                                     .format(reg_api["spec_branch"]))

                # Recommended to expose capabilities
                if "constraint_sets" in sender["caps"]:

                    # make sure sender capabilities are not confused with receivers ones
                    if "media_types" in sender["caps"] or "event_types" in sender["caps"]:
                        return test.FAIL("sender {}: capabilities MUST NOT have 'media_types' or 'event_types' attributes that are specific to receivers".format(sender["id"]))

                    # discard constraints sets that are known to not be USB
                    usb_constraint_sets = []
                    
                    for constraint_set in sender["caps"]["constraint_sets"]:
                        if media_type_constraint in constraint_set and "enum" in constraint_set[media_type_constraint] and not "application/usb" in constraint_set[media_type_constraint]["enum"]:
                            continue

                        usb_constraint_sets.append(constraint_set)

                    for constraint_set in usb_constraint_sets:
                        constraint = "urn:x-nmos:cap:transport:usb_class"
                        if has_key(constraint_set, constraint):
                            ok, msg = check_usb_class_capability(get_key_value(constraint_set, constraint))
                            if not ok:
                                return test.FAIL("sender {}: invalid {} capabilities, error {}".format(sender["id"], constraint, msg))
                        else:
                            warn_message += "|" + "sender {}: SHOULD declare {} capabilities".format(sender["id"], constraint)
                else:
                    warn_message += "|" + "sender {}: SHOULD declare its capabilities".format(sender["id"])

            if len(usb_senders) > 0:
                if warn_message != "":
                    return test.WARNING(warn_message)
                else:
                    return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No USB Sender resources were found on the Node")

    def test_05(self, test):
        """USB Sender manifests have the required parameters"""

        self.do_test_node_api_v1_3(test)

        for resource_type in ["senders", "flows"]:
            valid, result = self.get_is04_resources(resource_type)
            if not valid:
                return test.FAIL(result)

        flow_map = {flow["id"]: flow for flow in self.is04_resources["flows"].values()}

        try:
            usb_senders = [sender for sender in self.is04_resources["senders"].values() if sender["flow_id"]
                            and sender["flow_id"] in flow_map
                            and flow_map[sender["flow_id"]]["format"] == "urn:x-nmos:format:data"
                            and flow_map[sender["flow_id"]]["media_type"] == "application/usb"]

            access_error = False
            for sender in usb_senders:

                if "transport" not in sender:
                    return test.FAIL("sender {}: MUST indicate the 'transport' attribute."
                                     .format(sender["id"]))

                if urn_without_namespace(sender["transport"]) != "transport:usb":
                    return test.FAIL("sender {}: transport attribute MUST indicate the 'urn:*:transport:usb'"
                                     .format(sender["id"]))

                if "manifest_href" not in sender:
                    return test.FAIL("sender {}: MUST indicate the 'manifest_href' attribute."
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
                sdp_lines = [sdp_line.replace("\r", "") for sdp_line in sdp.split("\n")]

                found_media = 0
                found_setup = 0
                for sdp_line in sdp_lines:
                    media = re.search(r"^m=(.+) (.+) (.+) (.+)$", sdp_line)
                    if not media:
                        setup = re.search(r"^a=setup:passive$", sdp_line)
                        if setup:
                            found_setup += 1
                        continue
                    found_media += 1

                    if media.group(1) != "application":
                        return test.FAIL("sender {}: SDP transport file <media> MUST be 'application'".format(sender["id"]))

                    try:
                        port = int(media.group(2))
                    except ValueError:
                        return test.FAIL("sender {}: SDP transport file <port> MUST be an integer".format(sender["id"]))

                    if media.group(3) != "TCP":
                        return test.FAIL("sender {}: SDP transport file <proto> MUST be 'TCP'".format(sender["id"]))

                    if media.group(4) != "usb":
                        return test.FAIL("sender {}: SDP transport file <fmt> MUST be 'usb'".format(sender["id"]))

                if found_media == 0:
                    return test.FAIL("SDP for sender {}: is missing a media description line".format(sender["id"]))

                if found_media > 2:
                    return test.FAIL("SDP for sender {}: at most two media description lines MUST be used with redundancy".format(sender["id"]))

                if found_setup != found_media:
                    return test.FAIL("SDP for sender {}: there MUST be as many 'a=setup:passive' lines as there are media description lines".format(sender["id"]))

            if access_error:
                return test.UNCLEAR("One or more of the tested Senders had null or empty 'manifest_href' or "
                                    "returned a 404 HTTP code. Please ensure all Senders are enabled and re-test.")

            if len(usb_senders) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No USB Sender resources were found on the Node")

    def test_06(self, test):
        """USB Receivers have the required attributes"""

        self.do_test_node_api_v1_3(test)

        valid, result = self.get_is04_resources("receivers")
        if not valid:
            return test.FAIL(result)

        media_type_constraint = "urn:x-nmos:cap:format:media_type"

        recommended_constraints = {
            "urn:x-nmos:cap:transport:usb_class": "USB class",
        }

        try:
            usb_receivers = [receiver for receiver in self.is04_resources["receivers"].values()
                              if receiver["format"] == "urn:x-nmos:format:data"
                              and "media_types" in receiver["caps"]
                              and "application/usb" in receiver["caps"]["media_types"]]

            # a mux receiver cannot have a constraint set with media_type set to application/usb
            for receiver in [receiver for receiver in self.is04_resources["receivers"].values()
                              if receiver["format"] == "urn:x-nmos:format:mux"]:
                if "constraint_sets" in receiver["caps"]:
                    for constraint_set in receiver["caps"]["constraint_sets"]:
                        if "urn:x-nmos:cap:format:media_type" in constraint_set:
                            if  "enum" in constraint_set["urn:x-nmos:cap:format:media_type"]:
                                if  "application/usb" in constraint_set["urn:x-nmos:cap:format:media_type"]["enum"]:
                                    return test.FAIL("receiver {}: of 'mux' format MUST NOT have constraint sets having 'media_type' set to 'application/usb'.".format(receiver["id"]))

            warn_message = ""

            for receiver in usb_receivers:

                # check required attributes are present
                if "transport" not in receiver:
                    return test.FAIL("receiver {}: MUST indicate the 'transport' attribute."
                                     .format(receiver["id"]))

                if urn_without_namespace(receiver["transport"]) != "transport:usb":
                    return test.FAIL("receiver {}: 'transport' attribute MUST indicate 'urn:*:transport:usb'.".format(receiver["id"]))

                if "urn:x-nmos:tag:grouphint/v1.0" in receiver["tags"]:
                    grouphint = receiver["tags"]["urn:x-nmos:tag:grouphint/v1.0"]
                    if len(grouphint) != 1:
                        return test.FAIL("receiver {}: 'urn:x-nmos:tag:grouphint/v1.0' tag array MUST contain a single value.".format(receiver["id"]))
                    if not check_grouphint(grouphint[0]):
                        return test.FAIL("receiver {}: 'urn:x-nmos:tag:grouphint/v1.0' tag array MUST use a 'DATA' role.".format(receiver["id"]))

                if "constraint_sets" not in receiver["caps"]:
                    return test.FAIL("receiver {}: MUST indicate constraints in accordance with BCP-004-01 using "
                                     "the 'caps' attribute 'constraint_sets'.".format(receiver["id"]))

                # exclude constraint sets for other media types
                usb_constraint_sets = [constraint_set for constraint_set in receiver["caps"]["constraint_sets"]
                                        if receiver["format"] == "urn:x-nmos:format:data"
                                        and (media_type_constraint not in constraint_set
                                        or ("enum" in constraint_set[media_type_constraint]
                                            and "application/usb" in constraint_set[media_type_constraint]["enum"]))]

                if len(usb_constraint_sets) == 0:
                    return test.FAIL("receiver {}: MUST indicate constraints in accordance with BCP-004-01 using "
                                     "the 'caps' attribute 'constraint_sets'.".format(receiver["id"]))

                # check recommended attributes are present
                for constraint_set in usb_constraint_sets:
                    for constraint, target in recommended_constraints.items():
                        if not has_key(constraint_set, constraint):
                                warn_message += "|" + "receiver {}: SHOULD indicate the supported {} using the " \
                                               "'{}' parameter constraint.".format(receiver["id"], target, constraint)
            if warn_message != "":
                return test.WARNING(warn_message)

            if len(usb_receivers) > 0:
                return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No USB Receiver resources were found on the Node")

    def test_07(self, test):
        """USB Receiver parameter constraints have valid values"""

        self.do_test_node_api_v1_3(test)

        valid, result = self.get_is04_resources("receivers")
        if not valid:
            return test.FAIL(result)

        flow_reg_path = self.apis[FLOW_REGISTER_KEY]["spec_path"] + "/flow-attributes"
        usb_properties = load_resolved_schema(flow_reg_path, "flow_data_register.json",
                                               path_prefix=False)["properties"]
        sender_path = self.apis[SENDER_REGISTER_KEY]["spec_path"] + "/sender-attributes"
        sender_properties = load_resolved_schema(sender_path, "sender_register.json",
                                                 path_prefix=False)["properties"]

        media_type_constraint = "urn:x-nmos:cap:format:media_type"

        try:
            usb_receivers = [receiver for receiver in self.is04_resources["receivers"].values()
                              if receiver["format"] == "urn:x-nmos:format:data"
                              and "media_types" in receiver["caps"]
                              and "application/usb" in receiver["caps"]["media_types"]]

            warn_message = ""

            for receiver in usb_receivers:

                # check required attributes are present
                if "constraint_sets" not in receiver["caps"]:
                    return test.FAIL("Receiver {} MUST indicate constraints in accordance with BCP-004-01 using "
                                     "the 'caps' attribute 'constraint_sets'.".format(receiver["id"]))

                # exclude constraint sets for other media types
                usb_constraint_sets = [constraint_set for constraint_set in receiver["caps"]["constraint_sets"]
                                        if receiver["format"] == "urn:x-nmos:format:data"
                                        and (media_type_constraint not in constraint_set
                                        or ("enum" in constraint_set[media_type_constraint]
                                            and "application/usb" in constraint_set[media_type_constraint]["enum"]))]

                if len(usb_constraint_sets) == 0:
                    return test.FAIL("Receiver {} MUST indicate constraints in accordance with BCP-004-01 using "
                                     "the 'caps' attribute 'constraint_sets'.".format(receiver["id"]))

                # check recommended attributes are present
                for constraint_set in usb_constraint_sets:
                    constraint = "urn:x-nmos:cap:transport:usb_class"
                    if has_key(constraint_set, constraint):
                        ok, msg = check_usb_class_capability(get_key_value(constraint_set, constraint))
                        if not ok:
                            return test.FAIL("receiver {}: invalid {} capabilities, error {}.".format(receiver["id"], constraint, msg))
                    else:
                        warn_message += "|" + "receiver {}: SHOULD declare {} capabilities.".format(receiver["id"], constraint)
                        continue

            if len(usb_receivers) > 0:
                if warn_message != "":
                    return test.WARNING(warn_message)
                else:
                    return test.PASS()

        except KeyError as ex:
            return test.FAIL("Expected attribute not found in IS-04 resource: {}".format(ex))

        return test.UNCLEAR("No USB Receiver resources were found on the Node")

    def do_test_node_api_v1_3(self, test):
        """
        Precondition check of the API version.
        Raises an NMOSTestException when the Node API version is less than v1.3
        """
        api = self.apis[NODE_API_KEY]
        if self.is04_utils.compare_api_version(api["version"], "v1.3") < 0:
            raise NMOSTestException(test.NA("This test cannot be run against Node API below version v1.3."))

def check_grouphint(gh):

    halves = gh.split(":")

    if len(halves) != 2:
        return False
    if not halves[1].startswith("DATA"):
        return False

    return True

def check_usb_devices_attribute(usb_devices):

    if usb_devices is None:
        # Optional attribute
        return True, None

    if not isinstance(usb_devices, list):
        return False, "usb_devices must be an array."

    for idx, device in enumerate(usb_devices):
        if not isinstance(device, dict):
            return False, f"USB device at index {idx} must be a dictionary."

        # Validate ipmx_bus_id
        ipmx_bus_id = device.get("ipmx_bus_id")
        if not (isinstance(ipmx_bus_id, list) and len(ipmx_bus_id) == 64 and
                all(isinstance(i, int) and 0 <= i <= 255 for i in ipmx_bus_id)):
            return False, f"Invalid ipmx_bus_id at index {idx}: {ipmx_bus_id}"

        # Validate device_class
        device_class = device.get("class")
        if not (isinstance(device_class, list) and
                all(isinstance(c, int) and 0 <= c <= 255 for c in device_class)):
            return False, f"Invalid class at index {idx}: {device_class}"
        
        # Validate vendor
        vendor = device.get("vendor")
        if not (isinstance(vendor, int) and 0 <= vendor <= 0xFFFF):
            return False, f"Invalid vendor ID at index {idx}: {vendor}"

        # Validate product
        product = device.get("product")
        if not (isinstance(product, int) and 0 <= product <= 0xFFFF):
            return False, f"Invalid product ID at index {idx}: {product}"

        # Validate serial
        serial = device.get("serial")
        if not isinstance(serial, str):
            return False, f"Invalid serial at index {idx}: {serial}"

    return True, None


def check_usb_class_capability(usb_class_capability):

    if "enum" in usb_class_capability and not all(isinstance(c, int) and 0 <= c <= 255 for c in usb_class_capability["enum"]):
        return False, "MUST be integers in the range 0 to 255"
    if "minimum" in usb_class_capability and (not isinstance(usb_class_capability["minimum"], int) or usb_class_capability["minimum"] < 0 or usb_class_capability["minimum"] > 255):
        return False, "MUST be integers in the range 0 to 255"
    if "maximum" in usb_class_capability and (not isinstance(usb_class_capability["maximum"], int) or usb_class_capability["maximum"] < 0 or usb_class_capability["minimum"] > 255):
        return False, "MUST be integers in the range 0 to 255"
    if "minimum" in usb_class_capability and not "maximum" in usb_class_capability:
        return False, "MUST be integers in the range 0 to 255"
    if "maximum" in usb_class_capability and not "minimum" in usb_class_capability:
        return False, "MUST be integers in the range 0 to 255"

    return True, ""