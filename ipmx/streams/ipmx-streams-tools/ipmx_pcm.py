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
"""Helpers for building and parsing clear RTP/PCM (ST 2110-30) test streams.

PCM audio uses raw big-endian samples in the RTP payload with no AES3 subframe
wrapping.  The encoding name is L16, L20, or L24 depending on bit depth.
"""

from __future__ import annotations

import hashlib
import math
import struct
import time as time_mod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, cast

import ipmx_parse_rtp_pcap
from ipmx_am824 import (
    SUPPORTED_PACKET_TIME_PROFILES,
    ChannelOrderConfig,
    ChannelOrderGroup,
    PtimePreset,
    compute_audio_sender_report_interval_packets,
    deterministic_ssrc,
    legal_ptimes_us,
    resolve_nominal_packet_time_us,
    resolve_packet_samples_per_packet,
)

DEFAULT_CAPTURE_START = 1_700_000_000.0
DEFAULT_CAPTURE_INTERVAL = 0.001
DEFAULT_SRC_IP = "127.0.0.1"
DEFAULT_DST_IP = "239.0.0.1"
DEFAULT_ORIGIN_IP = "127.0.0.1"
DEFAULT_ETH_SRC = "02:00:00:00:00:01"
DEFAULT_ETH_DST = "02:00:00:00:00:02"


class PcmBitDepth(Enum):
    L16 = 16
    L20 = 20
    L24 = 24


_ENCODING_NAMES: dict[int, str] = {16: "L16", 20: "L20", 24: "L24"}
_ENCODING_DEPTHS: dict[str, int] = {v: k for k, v in _ENCODING_NAMES.items()}
_BYTES_PER_SAMPLE: dict[int, int] = {16: 2, 20: 3, 24: 3}


def encoding_name_for_depth(depth: int) -> str:
    """Return the SDP encoding name for a PCM bit depth."""
    name = _ENCODING_NAMES.get(depth)
    if name is None:
        raise ValueError(f"Unsupported PCM bit depth: {depth}")
    return name


def bit_depth_from_encoding(enc: str) -> int:
    """Return the PCM bit depth for an SDP encoding name."""
    depth = _ENCODING_DEPTHS.get(enc.upper())
    if depth is None:
        raise ValueError(f"Unsupported PCM encoding: {enc}")
    return depth


def bytes_per_sample(depth: int) -> int:
    """Return the number of bytes per PCM sample on the wire.

    L16 uses 2 bytes, L20 and L24 both use 3 bytes (L20 is packed into
    the most-significant 20 bits of a 24-bit container per ST 2110-30).
    """
    bps = _BYTES_PER_SAMPLE.get(depth)
    if bps is None:
        raise ValueError(f"Unsupported PCM bit depth: {depth}")
    return bps


@dataclass(frozen=True)
class PcmStreamConfig:
    name: str
    description: str
    bit_depth: int
    nchan: int
    channel_order_groups: tuple[ChannelOrderGroup, ...]
    sample_rate: int = 48_000
    ptime: PtimePreset = PtimePreset.PTIME_1MS
    payload_type: int = 96
    duration_seconds: float = 6

    @property
    def periods_per_packet(self) -> int:
        return self.sample_rate * self.ptime.value // 1_000_000

    @property
    def packet_count(self) -> int:
        return round(self.duration_seconds * 1_000_000 / self.ptime.value)

    @property
    def period_count(self) -> int:
        return self.packet_count * self.periods_per_packet

    @property
    def payload_bytes_per_packet(self) -> int:
        return self.periods_per_packet * self.nchan * bytes_per_sample(self.bit_depth)

    @property
    def encoding_name(self) -> str:
        return encoding_name_for_depth(self.bit_depth)


@dataclass
class PcmPacketReport:
    seq: int
    timestamp: int
    ssrc: int
    payload_type: int
    marker: bool
    payload_bytes: int
    sample_count: int
    issues: list[str] = field(default_factory=list)


@dataclass
class PcmStreamReport:
    packets: list[PcmPacketReport]
    packet_count: int
    sequence_analysis: ipmx_parse_rtp_pcap.RtpSequenceAnalysis
    payload_type_set: set[int]
    ssrc_set: set[int]
    payload_size_set: set[int]
    marker_set: set[bool]
    issues: list[str] = field(default_factory=list)


def build_channel_order(config: PcmStreamConfig) -> str:
    groups = ",".join(group.value for group in config.channel_order_groups)
    return f"SMPTE2110.({groups})"


def build_channel_order_config(config: PcmStreamConfig) -> ChannelOrderConfig:
    return ChannelOrderConfig(
        groups=config.channel_order_groups,
        value=build_channel_order(config),
        sequence_count=config.nchan,
    )


def _generate_sine_sample(
    sample_index: int,
    frequency_hz: float,
    sample_rate: int,
    amplitude: float,
    bit_depth: int,
) -> int:
    """Generate a single signed PCM sample from a sine wave."""
    max_val = (1 << (bit_depth - 1)) - 1
    value = amplitude * math.sin(2.0 * math.pi * frequency_hz * sample_index / sample_rate)
    return int(round(value * max_val))


def build_pcm_payload(
    samples: list[list[int]],
    bit_depth: int,
) -> bytes:
    """Build a raw PCM RTP payload from per-channel sample lists.

    *samples* is indexed as ``samples[period][channel]``.  Each sample is
    written in big-endian network byte order using the appropriate container
    size for the bit depth.
    """
    bps = bytes_per_sample(bit_depth)
    payload = bytearray()
    for period_samples in samples:
        for sample in period_samples:
            if bps == 2:
                payload.extend(struct.pack("!H", sample & 0xFFFF))
            else:
                raw = sample & 0xFFFFFF
                payload.extend(raw.to_bytes(3, "big"))
    return bytes(payload)


def build_rtp_packet(
    payload: bytes,
    *,
    payload_type: int,
    sequence_number: int,
    timestamp: int,
    ssrc: int,
) -> bytes:
    header = struct.pack(
        "!BBHII",
        0x80,
        payload_type & 0x7F,
        sequence_number & 0xFFFF,
        timestamp & 0xFFFFFFFF,
        ssrc & 0xFFFFFFFF,
    )
    return header + payload


def build_pcm_packets(
    config: PcmStreamConfig,
    *,
    frequencies: tuple[float, ...] | None = None,
    amplitude: float = 0.35,
) -> list[bytes]:
    """Generate synthetic PCM RTP packets with sine-wave content.

    *frequencies* provides one frequency per channel; defaults to 330 Hz
    increments starting at 330 Hz.
    """
    if frequencies is None:
        frequencies = tuple(330.0 + i * 220.0 for i in range(config.nchan))
    if len(frequencies) < config.nchan:
        frequencies = frequencies + (440.0,) * (config.nchan - len(frequencies))

    ssrc = deterministic_ssrc(config.name)
    packets: list[bytes] = []
    for pkt_idx in range(config.packet_count):
        start_sample = pkt_idx * config.periods_per_packet
        period_data: list[list[int]] = []
        for s in range(config.periods_per_packet):
            sample_idx = start_sample + s
            period_data.append([
                _generate_sine_sample(
                    sample_idx, frequencies[ch], config.sample_rate,
                    amplitude, config.bit_depth,
                )
                for ch in range(config.nchan)
            ])
        payload = build_pcm_payload(period_data, config.bit_depth)
        packets.append(
            build_rtp_packet(
                payload,
                payload_type=config.payload_type,
                sequence_number=pkt_idx,
                timestamp=pkt_idx * config.periods_per_packet,
                ssrc=ssrc,
            )
        )
    return packets


def write_pcm_pcap(
    pcap_path: Path,
    rtp_packets: list[bytes],
    *,
    dst_port: int,
    src_port: int,
    capture_start: float = DEFAULT_CAPTURE_START,
    capture_interval: float = DEFAULT_CAPTURE_INTERVAL,
    src_ip: str = DEFAULT_SRC_IP,
    dst_ip: str = DEFAULT_DST_IP,
    eth_src: str = DEFAULT_ETH_SRC,
    eth_dst: str = DEFAULT_ETH_DST,
) -> None:
    from scapy.all import Ether, IP, UDP, Raw  # type: ignore[import-untyped]
    from scapy.utils import PcapWriter  # type: ignore[import-untyped]

    writer = PcapWriter(str(pcap_path), sync=True)
    try:
        for index, rtp_packet in enumerate(rtp_packets):
            pkt = (
                Ether(src=eth_src, dst=eth_dst)
                / IP(src=src_ip, dst=dst_ip)
                / UDP(sport=src_port, dport=dst_port)
                / Raw(load=rtp_packet)
            )
            pkt.time = capture_start + (index * capture_interval)
            writer.write(pkt)
    finally:
        writer.close()


def generate_pcm_sdp(
    config: PcmStreamConfig,
    *,
    port: int,
    channel_order: str,
    hkep: bool = False,
    pep: bool = False,
) -> str:
    from MatroxSdp import (
        MatroxSdp,
        MatroxSdpEnums,
        ExtmapDescriptor,
        HkepDescriptor,
        PrivacyDescriptor,
        auto_lookup_enum,
    )
    from MatroxSdpWrite import encode as sdp_encode

    E = MatroxSdpEnums
    sdp = MatroxSdp()
    sdp.username = "-"
    ntp_epoch_offset = 2_208_988_800
    ntp_timestamp = int(time_mod.time()) + ntp_epoch_offset
    sdp.session_id = ntp_timestamp
    sdp.session_version = ntp_timestamp
    sdp.origin_address = DEFAULT_ORIGIN_IP
    sdp.session_name = "PCM Test Stream"
    sdp.session_information = config.description
    sdp.connection_address = DEFAULT_DST_IP
    sdp.connection_ttl = 32
    sdp.ts_ref_clock_source = E.LocalMac.value
    sdp.ts_ref_clock_local_mac_address = "00-20-FC-32-2F-40"
    sdp.media_clock_type = E.Sender.value

    encoding_enum = {
        16: E.EncodingL16,
        20: E.EncodingL20,
        24: E.EncodingL24,
    }[config.bit_depth]

    media = sdp.medias[0]
    media.type = E.Audio.value
    media.port = port
    media.protocol = E.ProtocolRTP_AVP.value
    media.format_code = config.payload_type
    media.payload_type = config.payload_type
    media.encoding_name = encoding_enum.value
    media.sample_rate = config.sample_rate
    media.channels = config.nchan
    media.media_name = "primary"
    media.channel_order = channel_order
    media.p_time_us = config.ptime.value
    media.measured_sample_rate = config.sample_rate
    media.ipmx = True
    media.sender_type = E.SenderType2110TPN.value
    media.max_udp = config.payload_bytes_per_packet

    media.source_filter_dst_address = DEFAULT_DST_IP
    media.source_filter_src_address = DEFAULT_SRC_IP

    if hkep:
        hd = HkepDescriptor()
        hd.address = "127.0.0.1"
        hd.port = 3497
        hd.node_id = "a0b1c2d3-e4f5-6789-abcd-ef0123456789"
        hd.port_id = "00-00-00-00-01"
        media.hkep_desc[0] = hd
        media.hkep = True

    if pep:
        pd = PrivacyDescriptor()
        pd.protocol = auto_lookup_enum("RTP")
        pd.mode = auto_lookup_enum("AES-128-CTR")
        pd.iv = "0000000000000000"
        pd.key_generator = "00000000000000000000000000000000"
        pd.key_version = "00000001"
        pd.key_id = "0000000000000001"
        media.privacy_desc = pd
        media.privacy = True

    ext_idx = 0
    if hkep:
        full = ExtmapDescriptor()
        full.id = 1
        full.direction = "sendonly"
        full.uri = "urn:ietf:params:rtp-hdrext:HDCP-Full-IV-Counter-metadata"
        media.ext_map[ext_idx] = full
        ext_idx += 1
        short = ExtmapDescriptor()
        short.id = 2
        short.direction = "sendonly"
        short.uri = "urn:ietf:params:rtp-hdrext:HDCP-Short-IV-Counter-metadata"
        media.ext_map[ext_idx] = short
        ext_idx += 1
    elif pep:
        full = ExtmapDescriptor()
        full.id = 1
        full.direction = "sendonly"
        full.uri = "urn:ietf:params:rtp-hdrext:PEP-Full-IV-Counter"
        media.ext_map[ext_idx] = full
        ext_idx += 1
        short = ExtmapDescriptor()
        short.id = 2
        short.direction = "sendonly"
        short.uri = "urn:ietf:params:rtp-hdrext:PEP-Short-IV-Counter"
        media.ext_map[ext_idx] = short
        ext_idx += 1

    sdp.primary_media_name = "primary"
    sdp.primary_media = media
    return sdp_encode(sdp)


def parse_rtp_header(packet: bytes) -> dict[str, int]:
    if len(packet) < 12:
        raise ValueError("RTP packet shorter than 12 bytes")
    b0, b1, sequence_number, timestamp, ssrc = struct.unpack("!BBHII", packet[:12])
    return {
        "version": b0 >> 6,
        "payload_type": b1 & 0x7F,
        "marker": (b1 >> 7) & 0x1,
        "sequence_number": sequence_number,
        "timestamp": timestamp,
        "ssrc": ssrc,
    }


def parse_pcm_payload(
    payload: bytes,
    nchan: int,
    bit_depth: int,
) -> list[list[int]]:
    """Parse raw PCM payload into ``samples[period][channel]``."""
    bps = bytes_per_sample(bit_depth)
    sample_frame_bytes = nchan * bps
    if len(payload) % sample_frame_bytes != 0:
        return []
    periods = len(payload) // sample_frame_bytes
    result: list[list[int]] = []
    offset = 0
    for _ in range(periods):
        frame: list[int] = []
        for _ in range(nchan):
            if bps == 2:
                (val,) = struct.unpack_from("!h", payload, offset)
            else:
                raw = int.from_bytes(payload[offset : offset + 3], "big")
                if raw >= 0x800000:
                    raw -= 0x1000000
                val = raw
            frame.append(val)
            offset += bps
        result.append(frame)
    return result


def build_pcm_packet_report(
    packet: ipmx_parse_rtp_pcap.RTPPacket,
    nchan: int,
    bit_depth: int,
) -> PcmPacketReport:
    issues: list[str] = []
    bps = bytes_per_sample(bit_depth)
    sample_frame_bytes = nchan * bps
    payload_len = len(packet.payload)
    if sample_frame_bytes > 0 and payload_len % sample_frame_bytes != 0:
        issues.append(
            f"payload length {payload_len} is not a multiple of "
            f"sample frame size {sample_frame_bytes}"
        )
    sample_count = payload_len // sample_frame_bytes if sample_frame_bytes > 0 else 0
    return PcmPacketReport(
        seq=packet.seq,
        timestamp=packet.timestamp,
        ssrc=packet.ssrc,
        payload_type=packet.payload_type,
        marker=packet.marker,
        payload_bytes=payload_len,
        sample_count=sample_count,
        issues=issues,
    )


def analyze_pcm_packets(
    packets: list[ipmx_parse_rtp_pcap.RTPPacket],
    nchan: int,
    bit_depth: int,
) -> PcmStreamReport:
    tracker = ipmx_parse_rtp_pcap.RtpSequenceTracker()
    packet_reports: list[PcmPacketReport] = []
    payload_types: set[int] = set()
    ssrcs: set[int] = set()
    payload_sizes: set[int] = set()
    markers: set[bool] = set()
    issues: list[str] = []

    for packet in packets:
        tracker.feed(packet.seq, packet.capture_time)
        report = build_pcm_packet_report(packet, nchan, bit_depth)
        packet_reports.append(report)
        payload_types.add(packet.payload_type)
        ssrcs.add(packet.ssrc)
        payload_sizes.add(len(packet.payload))
        markers.add(packet.marker)
        issues.extend(report.issues)

    if len(payload_types) > 1:
        issues.append(f"multiple RTP payload types observed: {sorted(payload_types)}")
    if len(ssrcs) > 1:
        issues.append(
            f"multiple SSRC values observed: "
            f"{[f'0x{v:08X}' for v in sorted(ssrcs)]}"
        )

    return PcmStreamReport(
        packets=packet_reports,
        packet_count=len(packet_reports),
        sequence_analysis=tracker.analysis,
        payload_type_set=payload_types,
        ssrc_set=ssrcs,
        payload_size_set=payload_sizes,
        marker_set=markers,
        issues=issues,
    )


def iter_selected_rtp_packets(
    pcap_path: Path,
    *,
    stream_info: ipmx_parse_rtp_pcap.RtpStreamInfo | None = None,
) -> list[ipmx_parse_rtp_pcap.RTPPacket]:
    return list(
        ipmx_parse_rtp_pcap.iter_rtp_packets_stream(
            pcap_path, None, stream_info=stream_info,
        )
    )


def smoke_parse_pcm_outputs(
    *,
    config: PcmStreamConfig,
    sdp_text: str,
    pcap_path: Path,
    dst_port: int,
) -> dict[str, Any]:
    """Quick sanity check of generated PCM PCAP + SDP."""
    from scapy.layers.inet import UDP  # type: ignore[import-untyped]
    from scapy.utils import PcapReader  # type: ignore[import-untyped]

    from MatroxSdp import MatroxSdp

    sdp = MatroxSdp()
    err = sdp.decode(sdp_text)
    if err:
        raise ValueError(f"SDP decode failed: {err}")

    media = sdp.primary_media or sdp.medias[0]
    if media.type is None or media.type.s != "audio":
        raise ValueError("Unexpected SDP media type")
    expected_enc = encoding_name_for_depth(config.bit_depth)
    if media.encoding_name is None or media.encoding_name.s != expected_enc:
        raise ValueError(f"Unexpected SDP encoding: {media.encoding_name}")
    if media.sample_rate != config.sample_rate:
        raise ValueError(f"Unexpected SDP sample rate: {media.sample_rate}")
    if media.channels != config.nchan:
        raise ValueError(f"Unexpected SDP channel count: {media.channels}")
    if media.p_time_us != config.ptime.value:
        raise ValueError(f"Unexpected SDP ptime: {media.p_time_us}")
    if media.payload_type != config.payload_type:
        raise ValueError(f"Unexpected SDP payload type: {media.payload_type}")
    if media.channel_order != build_channel_order(config):
        raise ValueError(f"Unexpected channel-order: {media.channel_order}")

    packet_count = 0
    payload_bytes = config.payload_bytes_per_packet
    expected_ssrc = deterministic_ssrc(config.name)
    previous_time: float | None = None
    reader = cast(Any, PcapReader(str(pcap_path)))
    try:
        for packet in reader:
            if UDP not in packet:
                raise ValueError("PCAP packet missing UDP layer")
            udp = packet[UDP]
            if int(udp.dport) != dst_port:
                raise ValueError(f"Unexpected destination port: {udp.dport}")
            rtp_packet = bytes(udp.payload)
            header = parse_rtp_header(rtp_packet)
            if header["version"] != 2:
                raise ValueError("Unexpected RTP version")
            if header["marker"] != 0:
                raise ValueError("Unexpected RTP marker bit")
            if header["payload_type"] != config.payload_type:
                raise ValueError(f"Unexpected RTP payload type: {header['payload_type']}")
            if header["ssrc"] != expected_ssrc:
                raise ValueError("Unexpected RTP SSRC")
            if header["sequence_number"] != packet_count:
                raise ValueError("Unexpected RTP sequence number")
            if header["timestamp"] != packet_count * config.periods_per_packet:
                raise ValueError("Unexpected RTP timestamp")
            if len(rtp_packet) - 12 != payload_bytes:
                raise ValueError("Unexpected RTP payload size")

            capture_time = float(packet.time)
            if previous_time is not None:
                delta = capture_time - previous_time
                expected_interval = config.ptime.value / 1_000_000.0
                if abs(delta - expected_interval) > 1e-6:
                    raise ValueError(f"Unexpected capture interval: {delta}")
            previous_time = capture_time
            packet_count += 1
    finally:
        reader.close()

    if packet_count != config.packet_count:
        raise ValueError(f"Unexpected packet count: {packet_count}")

    return {
        "status": "ok",
        "packet_count": packet_count,
        "payload_bytes_per_packet": payload_bytes,
        "ssrc": expected_ssrc,
        "channel_order": media.channel_order,
    }
