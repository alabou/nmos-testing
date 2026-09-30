#!/usr/bin/env python3
# Copyright (C) 2026 Matrox Graphics Inc.
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

"""QoS marking helpers for IPMX test-stream generation.

Two producer-side concerns live here so the generators mark RTP (and, by
mirroring, RTCP) consistently:

* RFC 1112 §6.4 IPv4-multicast → Ethernet destination MAC mapping.
* TR-10-9 §16 default DiffServ code points per media class.

These are the marking rules the ``streams/`` validators enforce
(``RFC1112-MCAST-MAC`` / ``RFC1112-SR-MAC`` and ``TR-10-9-16a`` / ``-16b``).
"""

from __future__ import annotations

from enum import IntEnum

# IPv4 multicast range is 224.0.0.0/4 (224.0.0.0 – 239.255.255.255).
_MULTICAST_FIRST_OCTET_MIN = 224
_MULTICAST_FIRST_OCTET_MAX = 239


def ipv4_multicast_to_mac(addr: str) -> str | None:
    """Map an IPv4 multicast dotted-quad to its Ethernet MAC (RFC 1112 §6.4).

    The MAC is ``01:00:5e`` followed by the low 23 bits of the group address
    (lowercase colon-hex).  Returns ``None`` when *addr* is not a well-formed
    IPv4 multicast literal (unicast/invalid → caller keeps its own default).
    """
    parts = addr.split(".") if addr else []
    if len(parts) != 4:
        return None
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return None
    if any(o < 0 or o > 255 for o in octets):
        return None
    if not (_MULTICAST_FIRST_OCTET_MIN <= octets[0] <= _MULTICAST_FIRST_OCTET_MAX):
        return None
    ipint = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    low23 = ipint & 0x7FFFFF
    return f"01:00:5e:{(low23 >> 16) & 0x7F:02x}:{(low23 >> 8) & 0xFF:02x}:{low23 & 0xFF:02x}"


def dst_mac_for(dst_ip: str, fallback: str) -> str:
    """Ethernet destination MAC for *dst_ip*: RFC 1112 mapping if multicast,
    otherwise *fallback* (unicast has no standard L2 mapping)."""
    return ipv4_multicast_to_mac(dst_ip) or fallback


class MediaDscp(IntEnum):
    """TR-10-9 §16 default DiffServ code points by media class."""

    VIDEO_AF42 = 36   # TR-10-2/4/7/11 — raw, JPEG XS, compressed video
    AUDIO_AF41 = 34   # TR-10-3/12 — PCM and AM824 audio

    @property
    def tos(self) -> int:
        """IPv4 DS-field (ToS) byte: DSCP in the high 6 bits, ECN = 0."""
        return int(self) << 2
