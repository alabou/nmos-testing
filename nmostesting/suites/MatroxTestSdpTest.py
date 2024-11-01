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

class MatroxTestSdpTest(GenericTest):
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
        self.is04_resources = {"senders": {}, "receivers": {}, "_requested": [], "sources": {}, "flows": {}}
        self.is05_resources = {"senders": [], "receivers": [], "_requested": [], "transport_types": {}, "transport_files": {}}
        self.is04_utils = IS04Utils(self.node_url)
        self.is05_utils = IS05Utils(self.connection_url)
        self.is04_query_utils = IS04Utils(self.query_url)

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

