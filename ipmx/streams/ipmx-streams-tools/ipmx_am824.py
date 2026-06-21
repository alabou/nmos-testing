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
"""Helpers for building clear RTP/AM824 test streams."""

from __future__ import annotations

import hashlib
import struct
import time as time_mod
import wave
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Protocol, cast

import ipmx_parse_rtp_pcap


DEFAULT_CAPTURE_START = 1_700_000_000.0
DEFAULT_CAPTURE_INTERVAL = 0.001
DEFAULT_SRC_IP = "127.0.0.1"
DEFAULT_DST_IP = "239.0.0.1"
DEFAULT_ORIGIN_IP = "127.0.0.1"
DEFAULT_ETH_SRC = "02:00:00:00:00:01"
DEFAULT_ETH_DST = "02:00:00:00:00:02"
AES3_BLOCK_PERIOD = 192
AES3_CHANNEL_STATUS_BYTES = 24

# ST 2110-31:2022 Table 1 — the only nine permitted packet-time / clock-rate
# combinations.  Two keys can map to the same entry to tolerate the rounding
# that ST 2110-31 section 7 note mandates ("rounded to 2 decimal places, with
# midway values such as 0.125 rounded down"):
#
#   key = accepted ptime in µs  →  (nominal_ptime_us, periods_per_packet)
#
# "Signaled" key  — value of a=ptime × 1000 as written by a spec-compliant
#                   sender (e.g. 120 for 0.12 ms).
# "Exact" key     — physical period rounded to the nearest integer µs
#                   (e.g. 125 for 6 × 1/48000 s = 125.000 µs exactly).
#
# NOTE: stream *generation* currently only supports 125 µs (6 periods) and
# 1000 µs (48 periods) because PtimePreset only defines those two values.
# The 4-period entries (80/83 µs for 48/96 kHz, 90/91 µs for 44.1 kHz) are
# present so that the validator and SR-injector can handle all spec-legal
# captures, but build_dynamic_audio_stream_config will raise ValueError for
# those ptimes until PtimePreset is extended.
SUPPORTED_PACKET_TIME_PROFILES: dict[int, dict[int, tuple[int, int]]] = {
    # 44.1 kHz — three permitted ptimes (Table 1)
    44_100: {
        # 4 periods: 4/44100 s = 90.703 µs  →  SDP 0.09 ms = 90 µs
        91:   (91, 4),    # exact (rounded)
        90:   (91, 4),    # SDP signaled
        # 6 periods: 6/44100 s = 136.054 µs  →  SDP 0.14 ms = 140 µs
        136:  (136, 6),   # exact (rounded)
        140:  (136, 6),   # SDP signaled
        # 48 periods: 48/44100 s = 1088.435 µs  →  SDP 1.09 ms = 1090 µs
        1088: (1088, 48), # exact (rounded)
        1090: (1088, 48), # SDP signaled
    },
    # 48 kHz — three permitted ptimes (Table 1)
    48_000: {
        # 4 periods: 4/48000 s = 83.333 µs  →  SDP 0.08 ms = 80 µs
        83:   (83, 4),    # exact (rounded)
        80:   (83, 4),    # SDP signaled
        # 6 periods: 6/48000 s = 125.000 µs  →  SDP 0.12 ms = 120 µs
        # (0.125 ms rounds down to 0.12 ms per the spec note)
        125:  (125, 6),   # exact
        120:  (125, 6),   # SDP signaled
        # 48 periods: 48/48000 s = 1000.000 µs  →  SDP 1 ms = 1000 µs
        1000: (1000, 48), # exact and SDP signaled
    },
    # 96 kHz — three permitted ptimes (Table 1)
    96_000: {
        # 8 periods: 8/96000 s = 83.333 µs  →  SDP 0.08 ms = 80 µs
        83:   (83, 8),    # exact (rounded)
        80:   (83, 8),    # SDP signaled
        # 12 periods: 12/96000 s = 125.000 µs  →  SDP 0.12 ms = 120 µs
        125:  (125, 12),  # exact
        120:  (125, 12),  # SDP signaled
        # 96 periods: 96/96000 s = 1000.000 µs  →  SDP 1 ms = 1000 µs
        1000: (1000, 96), # exact and SDP signaled
    },
}


class AudioSourceKind(Enum):
    PCM = "pcm"
    SPDIF = "spdif"


class PtimePreset(Enum):
    PTIME_125US = 125
    PTIME_1MS = 1000


class ChannelOrderGroup(Enum):
    ST = "ST"
    GROUP_51 = "51"
    GROUP_71 = "71"
    AES3 = "AES3"


class Aes3ChannelMode(Enum):
    UNSPECIFIED = 0x0
    TWO_CHANNEL = 0x1
    STEREOPHONIC = 0x4


@dataclass(frozen=True)
class Aes3Subframe:
    block_start: int
    frame_start: int
    pcuv: int
    data24: int

    def to_word(self) -> int:
        """Return the AM824 32-bit word for this subframe."""
        return (
            ((self.block_start & 0x1) << 29)
            | ((self.frame_start & 0x1) << 28)
            | ((self.pcuv & 0xF) << 24)
            | (self.data24 & 0xFFFFFF)
        )

    @property
    def parity_bit(self) -> int:
        return (self.pcuv >> 3) & 0x1

    @property
    def channel_status_bit(self) -> int:
        return (self.pcuv >> 2) & 0x1

    @property
    def user_data_bit(self) -> int:
        return (self.pcuv >> 1) & 0x1

    @property
    def validity_bit(self) -> int:
        return self.pcuv & 0x1

    @classmethod
    def from_aes3_fields(
        cls,
        *,
        block_start: int,
        frame_start: int,
        channel_status_bit: int,
        user_data_bit: int,
        validity_bit: int,
        data24: int,
    ) -> "Aes3Subframe":
        lower_bits = (
            ((channel_status_bit & 0x1) << 2)
            | ((user_data_bit & 0x1) << 1)
            | (validity_bit & 0x1)
        )
        parity_bit = (_count_ones24(data24) + _count_ones4(lower_bits)) & 0x1
        pcuv = ((parity_bit & 0x1) << 3) | lower_bits
        return cls(
            block_start=block_start,
            frame_start=frame_start,
            pcuv=pcuv,
            data24=data24 & 0xFFFFFF,
        )


@dataclass(frozen=True)
class AudioElementConfig:
    name: str
    source_kind: AudioSourceKind
    description: str
    channels: int
    frequencies_hz: tuple[int, ...] = ()
    codec: str = ""
    aes3_channel_mode: Aes3ChannelMode = Aes3ChannelMode.UNSPECIFIED


@dataclass(frozen=True)
class AudioStreamConfig:
    name: str
    description: str
    elements: tuple[AudioElementConfig, ...]
    channel_order_groups: tuple[ChannelOrderGroup, ...]
    payload_type: int = 96
    sample_rate: int = 48_000
    ptime: PtimePreset = PtimePreset.PTIME_1MS
    # float so that AES3-block-aligned durations (e.g. 192/44100 s) can be
    # expressed exactly without truncation to an integer second boundary.
    duration_seconds: float = 6

    @property
    def periods_per_packet(self) -> int:
        return self.sample_rate * self.ptime.value // 1_000_000

    @property
    def packet_count(self) -> int:
        # Use round() to absorb the tiny floating-point error that can arise
        # when duration_seconds is derived from an integer sample count.
        return round(self.duration_seconds * 1_000_000 / self.ptime.value)

    @property
    def period_count(self) -> int:
        return self.packet_count * self.periods_per_packet

    @property
    def nchan(self) -> int:
        total = 0
        for element in self.elements:
            if element.source_kind == AudioSourceKind.PCM:
                total += element.channels
            else:
                total += 2
        return total

    @property
    def aes3_signal_count(self) -> int:
        return self.nchan // 2

    @property
    def payload_bytes_per_packet(self) -> int:
        return self.periods_per_packet * self.nchan * 4


@dataclass(frozen=True)
class ChannelOrderConfig:
    groups: tuple[ChannelOrderGroup, ...]
    value: str
    sequence_count: int


@dataclass(frozen=True)
class ParsedAm824Subframe:
    block_start: int
    frame_start: int
    pcuv: int
    data24: int
    reserved_bits: int

    @property
    def parity_bit(self) -> int:
        return (self.pcuv >> 3) & 0x1

    @property
    def channel_status_bit(self) -> int:
        return (self.pcuv >> 2) & 0x1

    @property
    def user_data_bit(self) -> int:
        return (self.pcuv >> 1) & 0x1

    @property
    def validity_bit(self) -> int:
        return self.pcuv & 0x1


@dataclass
class Am824PacketReport:
    seq: int
    timestamp: int
    ssrc: int
    payload_type: int
    marker: bool
    payload_bytes: int
    subframe_count: int
    subframes: list[ParsedAm824Subframe]
    issues: list[str] = field(default_factory=list)


@dataclass
class Am824StreamReport:
    packets: list[Am824PacketReport]
    packet_count: int
    sequence_analysis: ipmx_parse_rtp_pcap.RtpSequenceAnalysis
    payload_type_set: set[int]
    ssrc_set: set[int]
    payload_size_set: set[int]
    marker_set: set[bool]
    issues: list[str] = field(default_factory=list)


class Aes3SignalSource(Protocol):
    def sequence_count(self) -> int:
        ...

    def period_count(self) -> int:
        ...

    def subframes_for_period(self, period_index: int) -> tuple[Aes3Subframe, Aes3Subframe]:
        ...


def _count_ones24(value: int) -> int:
    return bin(value & 0xFFFFFF).count("1")


def _count_ones4(value: int) -> int:
    return bin(value & 0x0F).count("1")


def aes3_sample_rate_byte0_bits(sample_rate: int) -> int:
    """Return AES3 channel-status byte 0 bits 6-7 encoding for a given sample rate (frame frequency).

    Returns 0 (not indicated) for sample rates not listed in AES3 § 6.
    """
    if sample_rate == 48_000:
        return 0b01 << 6
    if sample_rate == 44_100:
        return 0b10 << 6
    if sample_rate == 32_000:
        return 0b11 << 6
    return 0


def aes3_word_length_byte2(sample_size: int) -> int:
    """Return AES3 channel-status byte 2 encoding for a given PCM sample word length.

    Bits 0-2 encode auxiliary-sample-bit usage; bits 3-5 encode word length.
    Returns 0 (not indicated) for sizes not listed in AES3 § 6.
    """
    if sample_size == 24:
        return 0b001 | (0b101 << 3)
    if sample_size == 20:
        return 0
    if sample_size == 16:
        return 0b100 << 3
    return 0


def compute_aes3_channel_status_crc(channel_status_without_crc: bytes) -> int:
    if len(channel_status_without_crc) != AES3_CHANNEL_STATUS_BYTES - 1:
        raise ValueError("AES3 channel status CRC expects bytes 0..22")
    crc = 0xFF
    for byte in channel_status_without_crc:
        for bit_index in range(8):
            bit = (byte >> bit_index) & 0x1
            feedback = (crc & 0x1) ^ bit
            crc >>= 1
            if feedback:
                crc ^= 0xB8
    return crc


def build_aes3_channel_status_bytes(
    *,
    sample_rate: int,
    linear_pcm: bool,
    channel_mode: Aes3ChannelMode,
    sample_size: int,
) -> bytes:
    data = bytearray(AES3_CHANNEL_STATUS_BYTES)
    data[0] = 0x01 | aes3_sample_rate_byte0_bits(sample_rate)
    if not linear_pcm:
        data[0] |= 1 << 1
    data[1] = channel_mode.value & 0x0F
    # Byte 2 word-length field (AES3 §6.2): set from `sample_size` for both
    # PCM and non-PCM. For non-PCM S337M streams the word length must
    # reflect the burst data_mode (16 → 0x20, 20 → 0x00, 24 → 0x2C) so a
    # receiver can size the unpacking correctly (TR-10-12 §10).
    data[2] = aes3_word_length_byte2(sample_size)
    data[23] = compute_aes3_channel_status_crc(data[:23])
    return bytes(data)


def extract_channel_status_bit(channel_status_bytes: bytes, period_index: int) -> int:
    bit_index = period_index % AES3_BLOCK_PERIOD
    byte_index = bit_index // 8
    bit_offset = bit_index % 8
    return (channel_status_bytes[byte_index] >> bit_offset) & 0x1


class PcmAes3SignalSource:
    """PCM channel pair converted into one AES3 signal."""

    def __init__(
        self,
        samples: tuple[list[int], list[int]],
        *,
        period_total: int,
        channel_status_bytes: bytes,
    ) -> None:
        self._left, self._right = samples
        self._period_total = period_total
        self._channel_status_bytes = channel_status_bytes

    def sequence_count(self) -> int:
        return 2

    def period_count(self) -> int:
        return self._period_total

    def subframes_for_period(self, period_index: int) -> tuple[Aes3Subframe, Aes3Subframe]:
        left = self._left[period_index]
        right = self._right[period_index]
        block_start = 1 if (period_index % AES3_BLOCK_PERIOD) == 0 else 0
        channel_status_bit = extract_channel_status_bit(self._channel_status_bytes, period_index)
        return (
            Aes3Subframe.from_aes3_fields(
                block_start=block_start,
                frame_start=1,
                channel_status_bit=channel_status_bit,
                user_data_bit=0,
                validity_bit=0,
                data24=left & 0xFFFFFF,
            ),
            Aes3Subframe.from_aes3_fields(
                block_start=0,
                frame_start=0,
                channel_status_bit=channel_status_bit,
                user_data_bit=0,
                validity_bit=0,
                data24=right & 0xFFFFFF,
            ),
        )


class SpdifAes3SignalSource:
    """IEC 61937 / S/PDIF words transported opaquely as an AES3 signal."""

    def __init__(self, data: bytes, *, period_total: int, channel_status_bytes: bytes) -> None:
        required = period_total * 4
        if len(data) < required:
            data = data + (b"\x00" * (required - len(data)))
        self._data = memoryview(data[:required])
        self._period_total = period_total
        self._channel_status_bytes = channel_status_bytes

    def sequence_count(self) -> int:
        return 2

    def period_count(self) -> int:
        return self._period_total

    def subframes_for_period(self, period_index: int) -> tuple[Aes3Subframe, Aes3Subframe]:
        base = period_index * 4
        left = int.from_bytes(self._data[base : base + 2], "big") << 8
        right = int.from_bytes(self._data[base + 2 : base + 4], "big") << 8
        block_start = 1 if (period_index % AES3_BLOCK_PERIOD) == 0 else 0
        channel_status_bit = extract_channel_status_bit(self._channel_status_bytes, period_index)
        return (
            Aes3Subframe.from_aes3_fields(
                block_start=block_start,
                frame_start=1,
                channel_status_bit=channel_status_bit,
                user_data_bit=0,
                validity_bit=1,
                data24=left & 0xFFFFFF,
            ),
            Aes3Subframe.from_aes3_fields(
                block_start=0,
                frame_start=0,
                channel_status_bit=channel_status_bit,
                user_data_bit=0,
                validity_bit=1,
                data24=right & 0xFFFFFF,
            ),
        )


def build_channel_order(config: AudioStreamConfig) -> str:
    groups = ",".join(group.value for group in config.channel_order_groups)
    return f"SMPTE2110.({groups})"


def build_channel_order_config(config: AudioStreamConfig) -> ChannelOrderConfig:
    return ChannelOrderConfig(
        groups=config.channel_order_groups,
        value=build_channel_order(config),
        sequence_count=config.nchan,
    )


def deterministic_ssrc(name: str) -> int:
    digest = hashlib.sha1(name.encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big")


def legal_ptimes_us(sample_rate: int) -> set[int] | None:
    profiles = SUPPORTED_PACKET_TIME_PROFILES.get(sample_rate)
    if profiles is None:
        return None
    return set(profiles)


def resolve_nominal_packet_time_us(
    sample_rate: int,
    signaled_ptime_us: int,
) -> int | None:
    profiles = SUPPORTED_PACKET_TIME_PROFILES.get(sample_rate)
    if profiles is None:
        return None
    entry = profiles.get(signaled_ptime_us)
    return None if entry is None else entry[0]


def resolve_packet_samples_per_packet(
    sample_rate: int,
    signaled_ptime_us: int,
) -> int | None:
    profiles = SUPPORTED_PACKET_TIME_PROFILES.get(sample_rate)
    if profiles is None:
        return None
    entry = profiles.get(signaled_ptime_us)
    return None if entry is None else entry[1]


def compute_audio_sender_report_interval_packets(
    sample_rate: int,
    signaled_ptime_us: int,
) -> int | None:
    samples_per_packet = resolve_packet_samples_per_packet(sample_rate, signaled_ptime_us)
    if samples_per_packet is None or samples_per_packet <= 0:
        return None
    return sample_rate // (100 * samples_per_packet)


def build_am824_payload(
    signal_sources: list[Aes3SignalSource],
    start_period: int,
    periods_per_packet: int,
) -> bytes:
    payload = bytearray()
    for period_index in range(start_period, start_period + periods_per_packet):
        for signal_source in signal_sources:
            left, right = signal_source.subframes_for_period(period_index)
            payload.extend(struct.pack("!I", left.to_word()))
            payload.extend(struct.pack("!I", right.to_word()))
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


def build_am824_packets(config: AudioStreamConfig, signal_sources: list[Aes3SignalSource]) -> list[bytes]:
    packets: list[bytes] = []
    ssrc = deterministic_ssrc(config.name)
    for signal_source in signal_sources:
        if signal_source.period_count() < config.period_count:
            raise ValueError("Signal source shorter than requested AM824 stream duration")
    for packet_index in range(config.packet_count):
        start_period = packet_index * config.periods_per_packet
        payload = build_am824_payload(signal_sources, start_period, config.periods_per_packet)
        packets.append(
            build_rtp_packet(
                payload,
                payload_type=config.payload_type,
                sequence_number=packet_index,
                timestamp=packet_index * config.periods_per_packet,
                ssrc=ssrc,
            )
        )
    return packets


def write_am824_pcap(
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


def generate_am824_sdp(
    config: AudioStreamConfig,
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
    sdp.session_name = "AM824 Test Stream"
    sdp.session_information = config.description
    sdp.connection_address = DEFAULT_DST_IP
    sdp.connection_ttl = 32
    sdp.ts_ref_clock_source = E.LocalMac.value
    sdp.ts_ref_clock_local_mac_address = "00-20-FC-32-2F-40"
    sdp.media_clock_type = E.Sender.value

    media = sdp.medias[0]
    media.type = E.Audio.value
    media.port = port
    media.protocol = E.ProtocolRTP_AVP.value
    media.format_code = config.payload_type
    media.payload_type = config.payload_type
    media.encoding_name = E.EncodingAM824.value
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

    # --- HKEP ---
    if hkep:
        hd = HkepDescriptor()
        hd.address = "127.0.0.1"
        hd.port = 3497
        hd.node_id = "a0b1c2d3-e4f5-6789-abcd-ef0123456789"
        hd.port_id = "00-00-00-00-01"
        media.hkep_desc[0] = hd
        media.hkep = True

    # --- Privacy ---
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

    # --- Encryption extmap (RFC 8285 one-byte header) ---
    # When both HKEP and PEP are active, only HDCP extmap entries are declared.
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


def load_pcm_signal_sources(
    path: Path,
    *,
    config: AudioStreamConfig,
    element: AudioElementConfig,
) -> list[PcmAes3SignalSource]:
    with wave.open(str(path), "rb") as wav_file:
        if wav_file.getframerate() != config.sample_rate:
            raise ValueError(f"Unexpected PCM sample rate in {path}: {wav_file.getframerate()}")
        if wav_file.getsampwidth() != 3:
            raise ValueError(f"Unexpected PCM sample width in {path}: {wav_file.getsampwidth()}")
        channels = wav_file.getnchannels()
        frames = wav_file.readframes(wav_file.getnframes())

    expected_periods = config.period_count
    frame_size = channels * 3
    sample_total = len(frames) // frame_size
    usable_samples = min(sample_total, expected_periods)
    channel_samples = [[0] * expected_periods for _ in range(channels)]

    for period_index in range(usable_samples):
        base = period_index * frame_size
        for channel_index in range(channels):
            start = base + (channel_index * 3)
            sample = int.from_bytes(frames[start : start + 3], "little", signed=True)
            channel_samples[channel_index][period_index] = sample

    sources: list[PcmAes3SignalSource] = []
    pair_count = element.channels // 2
    for pair_index in range(pair_count):
        channel_index = pair_index * 2
        channel_status = build_aes3_channel_status_bytes(
            sample_rate=config.sample_rate,
            linear_pcm=True,
            channel_mode=element.aes3_channel_mode,
            sample_size=24,
        )
        sources.append(
            PcmAes3SignalSource(
                (channel_samples[channel_index], channel_samples[channel_index + 1]),
                period_total=expected_periods,
                channel_status_bytes=channel_status,
            )
        )
    return sources


def detect_spdif_data_mode(data: bytes) -> int:
    """Return the S337M data_mode used by the first burst found in
    `data` (an SPDIF byte stream packed as AES3 left/right 16-bit BE
    pairs, the format ffmpeg's SPDIF wrapper produces).

    Falls back to 0 (16-bit packed) when no burst preamble is detected
    (e.g. all-silence input). Used as the source-of-truth for both the
    AES3 channel-status word length and the AES3 audio MIB sample_size
    so the metadata stays in lockstep with whatever the encoder emits.
    """
    from ipmx_s337m import scan_s337m_signal

    n_periods = len(data) // 4
    data24_words: list[int] = []
    validity_bits: list[int] = []
    for i in range(n_periods):
        base = i * 4
        left = int.from_bytes(data[base : base + 2], "big") << 8
        right = int.from_bytes(data[base + 2 : base + 4], "big") << 8
        data24_words.append(left)
        data24_words.append(right)
        validity_bits.append(1)
        validity_bits.append(1)
    result = scan_s337m_signal(data24_words, validity_bits, 0)
    if result.bursts:
        return result.bursts[0].data_mode
    return 0


def load_spdif_signal_source(
    path: Path,
    *,
    config: AudioStreamConfig,
    element: AudioElementConfig,
) -> SpdifAes3SignalSource:
    from ipmx_s337m import S337M_DATA_MODE_TO_SAMPLE_SIZE

    data = path.read_bytes()
    data_mode = detect_spdif_data_mode(data)
    sample_size = S337M_DATA_MODE_TO_SAMPLE_SIZE[data_mode]
    channel_status = build_aes3_channel_status_bytes(
        sample_rate=config.sample_rate,
        linear_pcm=False,
        channel_mode=element.aes3_channel_mode,
        sample_size=sample_size,
    )
    return SpdifAes3SignalSource(
        data,
        period_total=config.period_count,
        channel_status_bytes=channel_status,
    )


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


def parse_am824_word(word: int) -> ParsedAm824Subframe:
    return ParsedAm824Subframe(
        reserved_bits=(word >> 30) & 0x03,
        block_start=(word >> 29) & 0x01,
        frame_start=(word >> 28) & 0x01,
        pcuv=(word >> 24) & 0x0F,
        data24=word & 0xFFFFFF,
    )


def parse_am824_payload(payload: bytes) -> tuple[list[ParsedAm824Subframe], list[str]]:
    issues: list[str] = []
    if len(payload) % 4 != 0:
        issues.append(f"payload length {len(payload)} is not a multiple of 4 bytes")
    subframes: list[ParsedAm824Subframe] = []
    usable = len(payload) - (len(payload) % 4)
    for offset in range(0, usable, 4):
        word = int.from_bytes(payload[offset : offset + 4], "big")
        subframes.append(parse_am824_word(word))
    return subframes, issues


def build_am824_packet_report(packet: ipmx_parse_rtp_pcap.RTPPacket) -> Am824PacketReport:
    subframes, issues = parse_am824_payload(packet.payload)
    return Am824PacketReport(
        seq=packet.seq,
        timestamp=packet.timestamp,
        ssrc=packet.ssrc,
        payload_type=packet.payload_type,
        marker=packet.marker,
        payload_bytes=len(packet.payload),
        subframe_count=len(subframes),
        subframes=subframes,
        issues=issues,
    )


def analyze_am824_packets(
    packets: list[ipmx_parse_rtp_pcap.RTPPacket],
) -> Am824StreamReport:
    tracker = ipmx_parse_rtp_pcap.RtpSequenceTracker()
    packet_reports: list[Am824PacketReport] = []
    payload_types: set[int] = set()
    ssrcs: set[int] = set()
    payload_sizes: set[int] = set()
    markers: set[bool] = set()
    issues: list[str] = []

    for packet in packets:
        tracker.feed(packet.seq, packet.capture_time)
        report = build_am824_packet_report(packet)
        packet_reports.append(report)
        payload_types.add(packet.payload_type)
        ssrcs.add(packet.ssrc)
        payload_sizes.add(len(packet.payload))
        markers.add(packet.marker)
        issues.extend(report.issues)

    if len(payload_types) > 1:
        issues.append(f"multiple RTP payload types observed: {sorted(payload_types)}")
    if len(ssrcs) > 1:
        issues.append(f"multiple SSRC values observed: {[f'0x{value:08X}' for value in sorted(ssrcs)]}")

    return Am824StreamReport(
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
    return list(ipmx_parse_rtp_pcap.iter_rtp_packets_stream(pcap_path, None, stream_info=stream_info))


def smoke_parse_am824_outputs(
    *,
    config: AudioStreamConfig,
    sdp_text: str,
    pcap_path: Path,
    dst_port: int,
) -> dict[str, Any]:
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
    if media.encoding_name is None or media.encoding_name.s != "AM824":
        raise ValueError("Unexpected SDP encoding")
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
