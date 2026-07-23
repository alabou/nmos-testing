# Copyright (C) 2020 Advanced Media Workflow Association
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

from . import Config as CONFIG

# Copy this file to "UserConfig.py" to change configuration values.

# Test using HTTPS rather than HTTP as per AMWA BCP-003-01
CONFIG.ENABLE_HTTPS = True

# Which certificate authority to trust when performing requests in HTTPS mode.
# Defaults to the CA contained within this testing tool
CONFIG.CERT_TRUST_ROOT_CA = "test_data/IPMX-Certificates/MatroxRootCA.pem"
CONFIG.CERT_CLIENT = "test_data/IPMX-Certificates/MatroxDeviceClient.MTX.MTX00000.chain.pem"
CONFIG.KEY_CLIENT = "test_data/IPMX-Certificates/MatroxDeviceClient.MTX.MTX00000.key"

# Test using authorization as per AMWA IS-10 and BCP-003-02
CONFIG.ENABLE_AUTH = True

# When True, the test runner uses the external token in CONFIG.AUTH_TOKEN
# (populated from the NMOS_TESTING_AUTH_TOKEN env var below) and bypasses
# AMWA's embedded mock authorization server. When False (the AMWA default),
# the test runner generates its own mock token on every run via
# self.primary_auth.generate_token() in GenericTest.run_tests — that mock
# token is signed by the test-runner's CA and the DUT must trust it.
#
# IPMX runs use True: real Keycloak tokens (TR-10-SEC realm, 'Matrox.Graphics.Device.Client.MTX.MTX00000.matrox.com'
# client) against an OAuth2-enabled IPMX Node.
CONFIG.USE_EXTERNAL_AUTH = True

# Picked up from the environment. The IPMX-GET-OAUTH2-TOKEN.sh / .bat
# helper in this directory fetches a fresh Keycloak access token and
# exports NMOS_TESTING_AUTH_TOKEN; sourcing the helper (or re-sourcing
# it after the Keycloak default access-token TTL has elapsed) is what
# populates this field.
#
# Fail-fast guard: when ENABLE_AUTH and USE_EXTERNAL_AUTH are both True
# but the env var is missing / empty, we raise here so the test runner
# bails immediately with an actionable message — rather than silently
# proceeding with AUTH_TOKEN=None and producing opaque 401s deep inside
# the suite. (When USE_EXTERNAL_AUTH=False the test runner generates a
# mock token regardless, so no guard is needed there.)
import os
CONFIG.AUTH_TOKEN = os.environ.get("NMOS_TESTING_AUTH_TOKEN") or None
if CONFIG.ENABLE_AUTH and CONFIG.USE_EXTERNAL_AUTH and not CONFIG.AUTH_TOKEN:
    raise RuntimeError(
        "CONFIG.ENABLE_AUTH and CONFIG.USE_EXTERNAL_AUTH are both True "
        "but NMOS_TESTING_AUTH_TOKEN is missing or empty. Source "
        "IPMX-GET-OAUTH2-TOKEN.sh first, set CONFIG.USE_EXTERNAL_AUTH = "
        "False to use AMWA's mock auth server instead, or set "
        "CONFIG.ENABLE_AUTH = False to run without auth."
    )

CONFIG.ENABLE_DNS_SD = False
# CONFIG.ENABLE_DNS_SD = True
CONFIG.DNS_SD_MODE = 'unicast'
#CONFIG.DNS_SD_MODE = 'multicast'
CONFIG.QUERY_API_HOST = '127.0.0.1'
CONFIG.QUERY_API_PORT = 8443

CONFIG.IS11_REFERENCE_SENDER_CONNECTION_API_URL = "http://10.20.10.160:5050/x-nmos/connection/v1.1/"
CONFIG.IS11_REFERENCE_SENDER_NODE_API_URL = "http://10.20.10.160:5050/x-nmos/node/v1.3/"

# The "any" value should work in most cases but in some scenarios the specific interface
# IP address must be specified in order to join on the proper network interface.
# CONFIG.MULTICAST_INTERFACE = "any"
CONFIG.MULTICAST_INTERFACE = "10.20.10.214"

# A multicast address that is known not to be used by any DuT
CONFIG.MULTICAST_STREAM_TARGET = '239.1.0.100'

# Make sure no one fail because accesses are slow
CONFIG.HTTP_TIMEOUT=30

# Reference Kramer source taking a long time to respond
CONFIG.STABLE_STATE_ATTEMPTS=10

# Check that the DuT produces an EDID with expected refresh/sample rate
# CONFIG.IS11_SOURCE_EDID_VERIFICATION=True