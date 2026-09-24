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

import os

from . import Config as CONFIG

# Copy this file to "UserConfig.py" to change configuration values.

# --- bench proxy: reach the bench over the SOCKS5 relay, not the HTTP proxy ---
#
# This sandbox has NO direct route to the bench (a direct connect returns
# [Errno 101] Network is unreachable); everything goes through a local proxy. Two are
# offered, and they are not equivalent. Measured 2026-08-20 against ConvertIP
# CD33533, 30 rapid GETs each:
#
#                              /receivers      /senders (~1.9 s response)
#     HTTP proxy  :3128        7-14 / 30 fail  13-15 / 30 fail   (all HTTP 502)
#     SOCKS5 relay :1080        0 / 30          0 / 30
#
# The 502s are produced by the HTTP proxy, not the device: the error response carries
# none of the device's own headers (no CORS set, no cache-control, no chunked
# encoding — just text/plain, Content-Length: 11, "Bad Gateway"), and the same suite
# run directly from a human's shell is 41/41 clean. Left on the HTTP proxy, runs
# report phantom failures — "Unexpected response from the Node API: <Response [502]>"
# and, where a caller parses the body without checking status, the much more
# misleading "Non-JSON response returned from Node API".
#
# `requests` needs PySocks to honour socks5h:// (see requirements.txt). Without it
# this block would raise InvalidSchema on every request, so it is applied only when
# the import is available — a missing PySocks degrades to the old behaviour rather
# than breaking the run.
_socks_relay = os.environ.get('ftp_proxy') or os.environ.get('all_proxy') or ''
if _socks_relay.startswith('socks'):
    try:
        import socks  # noqa: F401  — PySocks; presence is what matters
    except ImportError:
        pass
    else:
        for _var in ('http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY'):
            os.environ[_var] = _socks_relay

# Safety net only. With the SOCKS relay above the measured failure rate is 0/30, so
# this should never fire; it exists so a transient gateway error cannot turn into a
# phantom conformance failure. Retries SAFE methods only (GET/HEAD/OPTIONS) on
# 502/503/504 and prints every attempt — see nmostesting/TestHelper.py.
CONFIG.PROXY_RETRY_ATTEMPTS = 2
CONFIG.PROXY_RETRY_BACKOFF_S = 1.0

# Example of setting ENABLE_HTTPS, any value from Config.py can be overridden using the same pattern.
CONFIG.ENABLE_HTTPS = False

CONFIG.ENABLE_DNS_SD = False
# CONFIG.ENABLE_DNS_SD = True
CONFIG.DNS_SD_MODE = 'unicast'
#CONFIG.DNS_SD_MODE = 'multicast'

# Read the registry host/port from the environment variables set by the
# IPMX-SETUP-XYZ scripts, falling back to these defaults if they are not set.
CONFIG.QUERY_API_HOST = os.environ.get('IPMX_REGISTRY_ADDRESS', '25.30.10.45')
CONFIG.QUERY_API_PORT = int(os.environ.get('IPMX_REGISTRY_PORT', 8870))

# CONFIG.IS11_REFERENCE_SENDER_CONNECTION_API_URL = "http://127.0.0.1:7051/x-nmos/connection/v1.1/"
# CONFIG.IS11_REFERENCE_SENDER_NODE_API_URL = "http://127.0.0.1:7051/x-nmos/node/v1.3/"
CONFIG.IS11_REFERENCE_SENDER_CONNECTION_API_URL = "http://25.30.10.120:5050/x-nmos/connection/v1.1/"
CONFIG.IS11_REFERENCE_SENDER_NODE_API_URL = "http://25.30.10.120:5050/x-nmos/node/v1.3/"

# The "any" value should work in most cases but in some scenarios the specific interface
# IP address must be specified in order to join on the proper network interface.
# CONFIG.MULTICAST_INTERFACE = "any"
CONFIG.MULTICAST_INTERFACE = "25.30.10.214"

# A multicast address that is known not to be used by any DuT
CONFIG.MULTICAST_STREAM_TARGET = '239.1.0.100'

# Make sure no one fail because accesses are slow
CONFIG.HTTP_TIMEOUT=30

# Reference Kramer source taking a long time to respond
CONFIG.STABLE_STATE_ATTEMPTS=10

# Manually check that the DuT produces an EDID with expected refresh/sample rate
# CONFIG.IS11_SOURCE_EDID_VERIFICATION=True
CONFIG.IS11_SOURCE_EDID_VERIFICATION=False

# Geneva testing event required to have this set form 3 to 10
CONFIG.API_PROCESSING_TIMEOUT=10
