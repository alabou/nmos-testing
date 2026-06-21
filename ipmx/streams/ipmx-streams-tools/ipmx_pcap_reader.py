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

"""Low-level PCAP file reading and UDP packet iteration.

This module is the single source of truth for extracting raw UDP payloads from
libpcap-format capture files.  Two back-ends are provided:

* **Scapy** — used automatically when the ``scapy`` package is importable.
* **Manual** — pure-Python fallback that parses global/packet headers,
  Ethernet, IPv4/IPv6, and UDP directly from the binary file.

Higher-level modules (``ipmx_parse_rtp_pcap``, ``ipmx_validate_common``, etc.) build
on top of the iterators exposed here.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence

try:
    from scapy.all import PcapReader
    from scapy.layers.inet import IP, UDP
    from scapy.layers.inet6 import IPv6
    SCAPY_AVAILABLE = True
except Exception:
    PcapReader = None  # type: ignore[assignment]
    IP = UDP = IPv6 = None  # type: ignore[assignment]
    SCAPY_AVAILABLE = False


PCAP_GLOBAL_HEADER_SIZE = 24
PCAP_PACKET_HEADER_SIZE = 16
ETHERNET_HEADER_SIZE = 14


@dataclass
class UdpPacket:
    """A single UDP datagram extracted from a PCAP file."""
    payload: bytes
    capture_time: float
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None


# ---------------------------------------------------------------------------
# UDP packet iteration (Scapy back-end)
# ---------------------------------------------------------------------------

def iter_udp_packets_scapy(
    pcap_path: Path, port: int | None
) -> Iterator[UdpPacket]:
    """Yield :class:`UdpPacket` instances using Scapy's PCAP reader."""
    if not SCAPY_AVAILABLE or PcapReader is None or UDP is None:
        raise RuntimeError("Scapy is not available")
    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            if not pkt.haslayer(UDP):
                continue
            udp = pkt[UDP]
            if port is not None and udp.dport != port and udp.sport != port:
                continue
            payload = bytes(udp.payload)
            if not payload:
                continue
            capture_time = float(pkt.time)
            src_ip: str | None = None
            dst_ip: str | None = None
            if pkt.haslayer(IP):
                ip_layer = pkt[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
            elif pkt.haslayer(IPv6):
                ip6_layer = pkt[IPv6]
                src_ip = ip6_layer.src
                dst_ip = ip6_layer.dst
            yield UdpPacket(
                payload=payload,
                capture_time=capture_time,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=int(udp.sport),
                dst_port=int(udp.dport),
            )


# ---------------------------------------------------------------------------
# UDP packet iteration (manual / pure-Python back-end)
# ---------------------------------------------------------------------------

def _parse_pcap_magic(magic: bytes) -> tuple[str, bool]:
    """Return ``(endian, is_nanosecond)`` for the given 4-byte PCAP magic.

    Raises :class:`SystemExit` for unrecognised magic numbers.
    """
    if magic == b"\xd4\xc3\xb2\xa1":
        return "<", False
    if magic == b"\xa1\xb2\xc3\xd4":
        return ">", False
    if magic == b"\x4d\x3c\xb2\xa1":
        return "<", True
    if magic == b"\xa1\xb2\x3c\x4d":
        return ">", True
    raise SystemExit("Unsupported PCAP magic number")


def iter_udp_packets_manual(
    pcap_path: Path, port: int | None
) -> Iterator[UdpPacket]:
    """Yield :class:`UdpPacket` instances by parsing the PCAP binary directly."""
    with open(pcap_path, "rb") as fh:
        global_header = fh.read(PCAP_GLOBAL_HEADER_SIZE)
        if len(global_header) < PCAP_GLOBAL_HEADER_SIZE:
            return
        endian, is_nsec = _parse_pcap_magic(global_header[:4])
        frac_divisor = 1_000_000_000 if is_nsec else 1_000_000
        _, _, _, _, _, network = struct.unpack(
            endian + "HHIIII", global_header[4:]
        )
        if network != 1:
            raise SystemExit("Only Ethernet PCAPs are supported")

        while True:
            packet_header = fh.read(PCAP_PACKET_HEADER_SIZE)
            if len(packet_header) < PCAP_PACKET_HEADER_SIZE:
                break
            sec, usec, incl_len, _ = struct.unpack(
                endian + "IIII", packet_header
            )
            packet_data = fh.read(incl_len)
            if len(packet_data) < incl_len:
                break
            if len(packet_data) < ETHERNET_HEADER_SIZE:
                continue

            eth_type = int.from_bytes(packet_data[12:14], "big")
            ip_payload = packet_data[ETHERNET_HEADER_SIZE:]
            src_ip: str | None = None
            dst_ip: str | None = None
            udp_src_port: int | None = None
            udp_dst_port: int | None = None
            udp_payload = b""

            if eth_type == 0x0800 and len(packet_data) >= 34:
                ihl = (ip_payload[0] & 0x0F) * 4
                if ihl < 20 or len(ip_payload) < ihl + 8:
                    continue
                if ip_payload[9] != 17:
                    continue
                src_ip = socket.inet_ntoa(ip_payload[12:16])
                dst_ip = socket.inet_ntoa(ip_payload[16:20])
                udp_offset = ihl
                if len(ip_payload) < udp_offset + 8:
                    continue
                udp_src_port = int.from_bytes(
                    ip_payload[udp_offset : udp_offset + 2], "big"
                )
                udp_dst_port = int.from_bytes(
                    ip_payload[udp_offset + 2 : udp_offset + 4], "big"
                )
                udp_len = int.from_bytes(
                    ip_payload[udp_offset + 4 : udp_offset + 6], "big"
                )
                udp_payload = ip_payload[udp_offset + 8 : udp_offset + udp_len]
            elif eth_type == 0x86DD and len(packet_data) >= 54:
                src_ip = socket.inet_ntop(
                    socket.AF_INET6, packet_data[22:38]
                )
                dst_ip = socket.inet_ntop(
                    socket.AF_INET6, packet_data[38:54]
                )
                if ip_payload[6] != 17:
                    continue
                udp_offset = 40
                udp_src_port = int.from_bytes(
                    ip_payload[udp_offset : udp_offset + 2], "big"
                )
                udp_dst_port = int.from_bytes(
                    ip_payload[udp_offset + 2 : udp_offset + 4], "big"
                )
                udp_len = int.from_bytes(
                    ip_payload[udp_offset + 4 : udp_offset + 6], "big"
                )
                udp_payload = ip_payload[
                    udp_offset + 8 : udp_offset + 8 + (udp_len - 8)
                ]
            else:
                continue

            if port is not None and udp_dst_port != port and udp_src_port != port:
                continue
            if not udp_payload:
                continue

            yield UdpPacket(
                payload=udp_payload,
                capture_time=sec + (usec / frac_divisor),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=udp_src_port,
                dst_port=udp_dst_port,
            )


# ---------------------------------------------------------------------------
# Public dispatcher — Scapy with manual fallback
# ---------------------------------------------------------------------------

def iter_udp_packets(
    pcap_path: Path, port: int | None
) -> Iterator[UdpPacket]:
    """Iterate UDP packets from *pcap_path*, optionally filtered by *port*.

    Uses Scapy when available, otherwise falls back to the built-in parser.
    """
    if SCAPY_AVAILABLE:
        try:
            yield from iter_udp_packets_scapy(pcap_path, port)
            return
        except Exception:
            pass
    yield from iter_udp_packets_manual(pcap_path, port)


# ---------------------------------------------------------------------------
# Raw PCAP read / write (for tools that manipulate capture files)
# ---------------------------------------------------------------------------

def read_pcap(
    path: Path,
) -> tuple[bytes, str, int, list[dict[str, object]]]:
    """Read an entire PCAP file and return its components.

    Returns ``(global_header, endian, network_type, packets)`` where each
    element of *packets* is a dict with keys ``time``, ``sec``, ``usec``,
    ``incl_len``, ``orig_len``, and ``data``.
    """
    packets: list[dict[str, object]] = []
    with open(path, "rb") as fh:
        global_header = fh.read(PCAP_GLOBAL_HEADER_SIZE)
        if len(global_header) != PCAP_GLOBAL_HEADER_SIZE:
            raise SystemExit("PCAP too short to contain global header")
        endian, is_nsec = _parse_pcap_magic(global_header[:4])
        frac_divisor = 1_000_000_000 if is_nsec else 1_000_000
        header_fields = struct.unpack(endian + "HHIIII", global_header[4:])
        network = header_fields[-1]
        if network != 1:
            raise SystemExit("Only Ethernet PCAPs are supported")
        while True:
            header = fh.read(PCAP_PACKET_HEADER_SIZE)
            if len(header) < PCAP_PACKET_HEADER_SIZE:
                break
            sec, usec, incl_len, orig_len = struct.unpack(
                endian + "IIII", header
            )
            payload = fh.read(incl_len)
            if len(payload) < incl_len:
                break
            packets.append(
                {
                    "time": sec + usec / frac_divisor,
                    "sec": sec,
                    "usec": usec,
                    "incl_len": incl_len,
                    "orig_len": orig_len,
                    "data": payload,
                }
            )
    return global_header, endian, network, packets


def write_pcap(
    path: Path,
    global_header: bytes,
    endian: str,
    packets: Sequence[dict[str, object]],
) -> None:
    """Write *packets* back into a PCAP file at *path*."""
    with open(path, "wb") as fh:
        fh.write(global_header)
        for packet in packets:
            sec = packet["sec"]
            usec = packet["usec"]
            data = packet["data"]
            incl_len = len(data)  # type: ignore[arg-type]
            orig_len = packet["orig_len"]
            header = struct.pack(endian + "IIII", sec, usec, incl_len, orig_len)
            fh.write(header)
            fh.write(data)  # type: ignore[arg-type]
