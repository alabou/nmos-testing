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

"""Parse RTP video streams (H.264, H.265, JPEG XS) from PCAP captures.

For H.264/H.265 the script reconstructs NAL-unit elementary streams, reassembles
FU-A/FU fragments, appends start codes, and emits a JSON report correlating RTP
timing with codec metadata (VPS/SPS/PPS/SEI).

For JPEG XS (jxsv) the script validates the RTP transport layer per RFC 9134
without requiring access to the (potentially encrypted) codestream payload.  It
parses the 4-byte JXSV RTP payload header, tracks frame/field boundaries, and
validates counter progression, packetization mode consistency, and interlace
signalling.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import subprocess
import sys
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Iterator
import ipmx_pcap_reader

START_CODE = b"\x00\x00\x00\x01"
H264_SPECIAL = {6: "SEI", 7: "SPS", 8: "PPS"}
H265_SPECIAL = {32: "VPS", 33: "SPS", 34: "PPS", 39: "SEI", 40: "SEI", 20: "SEI"}

RTP_SEQ_MOD = 1 << 16


# ---------------------------------------------------------------------------
# RTP sequence-number gap tracker
# ---------------------------------------------------------------------------

@dataclass
class RtpSeqGap:
    """A contiguous gap in the RTP sequence-number space."""
    after_seq: int
    expected_seq: int
    received_seq: int
    missing_count: int
    capture_time: float | None


@dataclass
class RtpSequenceAnalysis:
    """Summary of sequence-number continuity for an RTP stream."""
    total_received: int = 0
    total_missing: int = 0
    total_duplicates: int = 0
    gaps: list[RtpSeqGap] = field(default_factory=list)
    first_seq: int | None = None
    last_seq: int | None = None

    @property
    def complete(self) -> bool:
        return self.total_missing == 0

    def summary(self) -> str:
        if self.complete:
            return (
                f"{self.total_received} packets, no gaps, "
                f"seq {self.first_seq}..{self.last_seq}"
            )
        return (
            f"{self.total_received} received, {self.total_missing} missing "
            f"({len(self.gaps)} gap(s)), {self.total_duplicates} duplicate(s), "
            f"seq {self.first_seq}..{self.last_seq}"
        )


class RtpSequenceTracker:
    """Track RTP sequence numbers and detect gaps / duplicates."""

    def __init__(self) -> None:
        self._prev_seq: int | None = None
        self._seen: set[int] = set()
        self._analysis = RtpSequenceAnalysis()

    def feed(self, seq: int, capture_time: float | None = None) -> None:
        self._analysis.total_received += 1
        if self._analysis.first_seq is None:
            self._analysis.first_seq = seq
        self._analysis.last_seq = seq

        if seq in self._seen:
            self._analysis.total_duplicates += 1
        self._seen.add(seq)

        if self._prev_seq is not None:
            expected = (self._prev_seq + 1) % RTP_SEQ_MOD
            if seq != expected:
                missing = (seq - expected) % RTP_SEQ_MOD
                if missing > 0 and missing < RTP_SEQ_MOD // 2:
                    self._analysis.total_missing += missing
                    self._analysis.gaps.append(RtpSeqGap(
                        after_seq=self._prev_seq,
                        expected_seq=expected,
                        received_seq=seq,
                        missing_count=missing,
                        capture_time=capture_time,
                    ))
        self._prev_seq = seq

    @property
    def analysis(self) -> RtpSequenceAnalysis:
        return self._analysis


# ---------------------------------------------------------------------------
# JXSV (JPEG XS over RTP, RFC 9134) payload header definitions
# ---------------------------------------------------------------------------

class JXSVPacketizationMode(IntEnum):
    """RFC 9134 section 4.3 — pacKetization mode (K bit)."""
    CODESTREAM = 0
    SLICE = 1


class JXSVInterlaceInfo(IntEnum):
    """RFC 9134 section 4.3 — Interlaced information (I bits)."""
    PROGRESSIVE = 0b00
    RESERVED = 0b01
    INTERLACED_FIRST = 0b10
    INTERLACED_SECOND = 0b11


JXSV_PAYLOAD_HEADER_SIZE = 4
JXSV_F_COUNTER_MOD = 32
JXSV_SEP_COUNTER_MOD = 2048
JXSV_P_COUNTER_MOD = 2048
JXSV_SEP_HEADER_SEGMENT = 0x07FF


@dataclass
class JXSVPayloadHeader:
    """Decoded 4-byte JXSV RTP payload header per RFC 9134 section 4.3."""
    transmission_mode: int  # T  (1 bit): 1=sequential, 0=may be out-of-order
    packetization_mode: int  # K  (1 bit): 0=codestream, 1=slice
    last: int                # L  (1 bit): last packet of packetization unit
    interlace_info: int      # I  (2 bits)
    f_counter: int           # F  (5 bits): frame counter mod 32
    sep_counter: int         # SEP (11 bits)
    p_counter: int           # P  (11 bits): packet counter within PU

    @staticmethod
    def parse(data: bytes) -> JXSVPayloadHeader | None:
        if len(data) < JXSV_PAYLOAD_HEADER_SIZE:
            return None
        word = int.from_bytes(data[:JXSV_PAYLOAD_HEADER_SIZE], "big")
        return JXSVPayloadHeader(
            transmission_mode=(word >> 31) & 1,
            packetization_mode=(word >> 30) & 1,
            last=(word >> 29) & 1,
            interlace_info=(word >> 27) & 0x03,
            f_counter=(word >> 22) & 0x1F,
            sep_counter=(word >> 11) & 0x7FF,
            p_counter=word & 0x7FF,
        )

    def absolute_packet_index(self) -> int:
        """Compute the linear packet index within the packetization unit.

        In codestream mode the SEP counter extends the P counter beyond 2047.
        In slice mode the SEP counter identifies the slice, so the linear
        index is just P.
        """
        if self.packetization_mode == JXSVPacketizationMode.CODESTREAM:
            return self.sep_counter * JXSV_P_COUNTER_MOD + self.p_counter
        return self.p_counter

    def describe_interlace(self) -> str:
        try:
            return JXSVInterlaceInfo(self.interlace_info).name.lower()
        except ValueError:
            return f"unknown({self.interlace_info})"

    def describe_packetization(self) -> str:
        try:
            return JXSVPacketizationMode(self.packetization_mode).name.lower()
        except ValueError:
            return f"unknown({self.packetization_mode})"


@dataclass
class JXSVFrameState:
    """Tracks the assembly state of one JXSV video frame (one RTP timestamp)."""
    timestamp: int
    f_counter: int
    interlace_info: int
    first_seq: int
    last_seq: int
    first_capture_time: float | None
    last_capture_time: float | None
    packet_count: int = 0
    total_payload_bytes: int = 0
    marker_seen: bool = False
    first_absolute_index: int = -1
    last_p_counter: int = -1
    last_sep_counter: int = 0
    last_absolute_index: int = -1
    issues: list[str] = field(default_factory=list)


@dataclass
class JXSVStreamState:
    """Accumulated validation state across the entire JXSV RTP stream."""
    first_t: int | None = None
    first_k: int | None = None
    frame_count: int = 0
    field_count: int = 0
    packet_count: int = 0
    total_payload_bytes: int = 0
    last_f_counter: int | None = None
    last_timestamp: int | None = None
    seq_analysis: RtpSequenceAnalysis = field(default_factory=RtpSequenceAnalysis)
    issues: list[str] = field(default_factory=list)


def validate_jxsv_packet(
    jxsv: JXSVPayloadHeader,
    rtp: RTPPacket,
    frame: JXSVFrameState,
    stream: JXSVStreamState,
) -> list[str]:
    """Return a list of RFC 9134 conformance issues for one packet."""
    issues: list[str] = []

    if stream.first_t is None:
        stream.first_t = jxsv.transmission_mode
    elif jxsv.transmission_mode != stream.first_t:
        issues.append(
            f"T bit changed from {stream.first_t} to {jxsv.transmission_mode} "
            f"(SHALL be identical for all packets, RFC 9134 §4.3)"
        )

    if stream.first_k is None:
        stream.first_k = jxsv.packetization_mode
    elif jxsv.packetization_mode != stream.first_k:
        issues.append(
            f"K bit changed from {stream.first_k} to {jxsv.packetization_mode} "
            f"(SHALL be identical for all packets, RFC 9134 §4.3)"
        )

    if jxsv.transmission_mode == 0 and jxsv.packetization_mode != JXSVPacketizationMode.SLICE:
        issues.append(
            "T=0 (out-of-order) requires K=1 (slice packetization mode), "
            f"but K={jxsv.packetization_mode} (RFC 9134 §4.3)"
        )

    if jxsv.interlace_info == JXSVInterlaceInfo.RESERVED:
        issues.append("I=01 is reserved for future use (RFC 9134 §4.3)")

    if rtp.marker and not jxsv.last:
        issues.append(
            "M=1 (RTP marker) but L=0; L SHALL be set when M is set (RFC 9134 §4.3)"
        )

    if jxsv.packetization_mode == JXSVPacketizationMode.CODESTREAM:
        if jxsv.last != rtp.marker:
            issues.append(
                f"In codestream mode L ({jxsv.last}) and M ({int(rtp.marker)}) "
                f"SHALL have identical values (RFC 9134 §4.3)"
            )

    abs_idx = jxsv.absolute_packet_index()
    if frame.last_absolute_index >= 0:
        expected = frame.last_absolute_index + 1
        if abs_idx != expected:
            issues.append(
                f"Packet index gap: expected {expected}, got {abs_idx} "
                f"(SEP={jxsv.sep_counter}, P={jxsv.p_counter})"
            )

    return issues


def process_jxsv_stream(
    pcap_path: Path,
    port: int | None,
    payload_type_filter: int | None,
    max_frames: int | None,
    wallclock_backstep_threshold: float | None,
    *,
    stream_info: RtpStreamInfo | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], JXSVStreamState, dict[str, Any] | None]:
    """Process a JXSV RTP stream and return per-packet report, per-frame summary,
    accumulated stream state, and optional wallclock disruption info."""

    stream = JXSVStreamState()
    seq_tracker = RtpSequenceTracker()
    packets_report: list[dict[str, Any]] = []
    frames_report: list[dict[str, Any]] = []
    wallclock_disruption: dict[str, Any] | None = None

    current_frame: JXSVFrameState | None = None
    frame_order: list[int] = []
    frame_timestamps: set[int] = set()
    last_frame_timestamp: int | None = None
    last_frame_capture_time: float | None = None
    observed_rtp_deltas: list[float] = []

    def _finalize_frame(frm: JXSVFrameState) -> dict[str, Any]:
        if not frm.marker_seen:
            frm.issues.append("Frame ended without RTP marker bit (M=1)")
        summary: dict[str, Any] = {
            "frame_index": stream.frame_count,
            "timestamp": frm.timestamp,
            "f_counter": frm.f_counter,
            "interlace": JXSVInterlaceInfo(frm.interlace_info).name.lower()
            if frm.interlace_info != JXSVInterlaceInfo.RESERVED
            else f"reserved({frm.interlace_info})",
            "seq_range": [frm.first_seq, frm.last_seq],
            "packet_count": frm.packet_count,
            "total_payload_bytes": frm.total_payload_bytes,
            "first_capture_time": frm.first_capture_time,
            "last_capture_time": frm.last_capture_time,
            "marker_seen": frm.marker_seen,
            "first_absolute_index": frm.first_absolute_index,
            "issues": frm.issues,
        }
        stream.frame_count += 1
        if frm.interlace_info in (
            JXSVInterlaceInfo.INTERLACED_FIRST,
            JXSVInterlaceInfo.INTERLACED_SECOND,
        ):
            stream.field_count += 1
        return summary

    for pkt in iter_rtp_packets_stream(pcap_path, port, stream_info=stream_info):
        if not pkt.payload or len(pkt.payload) < JXSV_PAYLOAD_HEADER_SIZE:
            continue
        if payload_type_filter is not None and pkt.payload_type != payload_type_filter:
            continue

        jxsv = JXSVPayloadHeader.parse(pkt.payload)
        if jxsv is None:
            continue

        is_new_frame = current_frame is None or pkt.timestamp != current_frame.timestamp

        if is_new_frame and current_frame is not None:
            frames_report.append(_finalize_frame(current_frame))

        if is_new_frame and pkt.capture_time is not None:
            if last_frame_timestamp is not None and last_frame_capture_time is not None:
                rtp_delta = ((pkt.timestamp - last_frame_timestamp) & 0xFFFFFFFF) / 90000.0
                if rtp_delta > 0:
                    observed_rtp_deltas.append(rtp_delta)
                if observed_rtp_deltas:
                    sorted_d = sorted(observed_rtp_deltas)
                    mid = len(sorted_d) // 2
                    nominal_period = (
                        sorted_d[mid]
                        if len(sorted_d) % 2
                        else (sorted_d[mid - 1] + sorted_d[mid]) / 2.0
                    )
                else:
                    nominal_period = 1.0 / 60.0
                threshold = (
                    wallclock_backstep_threshold
                    if wallclock_backstep_threshold is not None
                    else max(0.050, 3.0 * nominal_period)
                )
                capture_delta = pkt.capture_time - last_frame_capture_time
                if capture_delta < -threshold:
                    wallclock_disruption = {
                        "at_frame_index": stream.frame_count,
                        "previous_timestamp": last_frame_timestamp,
                        "current_timestamp": pkt.timestamp,
                        "previous_capture_time": last_frame_capture_time,
                        "current_capture_time": pkt.capture_time,
                        "capture_delta": capture_delta,
                        "rtp_delta": rtp_delta,
                        "threshold": threshold,
                    }
                    break
            last_frame_timestamp = pkt.timestamp
            last_frame_capture_time = pkt.capture_time

        if (
            max_frames is not None
            and is_new_frame
            and pkt.timestamp not in frame_timestamps
            and len(frame_order) >= max_frames
        ):
            break

        if is_new_frame:
            if pkt.timestamp not in frame_timestamps:
                frame_timestamps.add(pkt.timestamp)
                frame_order.append(pkt.timestamp)

                if stream.last_f_counter is not None:
                    expected_f = (stream.last_f_counter + 1) % JXSV_F_COUNTER_MOD
                    if jxsv.f_counter != expected_f:
                        ts_delta = (pkt.timestamp - (stream.last_timestamp or 0)) & 0xFFFFFFFF
                        skip_count = (jxsv.f_counter - stream.last_f_counter) % JXSV_F_COUNTER_MOD
                        if skip_count > 1:
                            stream.issues.append(
                                f"F counter jumped from {stream.last_f_counter} to {jxsv.f_counter} "
                                f"(skipped {skip_count - 1} frame(s), "
                                f"RTP timestamp delta={ts_delta})"
                            )
                stream.last_f_counter = jxsv.f_counter
                stream.last_timestamp = pkt.timestamp

            current_frame = JXSVFrameState(
                timestamp=pkt.timestamp,
                f_counter=jxsv.f_counter,
                interlace_info=jxsv.interlace_info,
                first_seq=pkt.seq,
                last_seq=pkt.seq,
                first_capture_time=pkt.capture_time,
                last_capture_time=pkt.capture_time,
                first_absolute_index=jxsv.absolute_packet_index(),
            )

        assert current_frame is not None

        pkt_issues = validate_jxsv_packet(jxsv, pkt, current_frame, stream)
        current_frame.issues.extend(pkt_issues)
        current_frame.packet_count += 1
        payload_data_size = len(pkt.payload) - JXSV_PAYLOAD_HEADER_SIZE
        current_frame.total_payload_bytes += payload_data_size
        current_frame.last_seq = pkt.seq
        current_frame.last_capture_time = pkt.capture_time
        current_frame.last_absolute_index = jxsv.absolute_packet_index()
        if pkt.marker:
            current_frame.marker_seen = True

        stream.packet_count += 1
        stream.total_payload_bytes += payload_data_size
        seq_tracker.feed(pkt.seq, pkt.capture_time)

        packet_record: dict[str, Any] = {
            "seq": pkt.seq,
            "timestamp": pkt.timestamp,
            "ssrc": pkt.ssrc,
            "marker": pkt.marker,
            "payload_type": pkt.payload_type,
            "src_ip": pkt.src_ip,
            "dst_ip": pkt.dst_ip,
            "src_port": pkt.src_port,
            "dst_port": pkt.dst_port,
            "capture_time": pkt.capture_time,
            "payload_size": len(pkt.payload),
            "ext_elements": pkt.ext_elements,
            "jxsv": {
                "T": jxsv.transmission_mode,
                "K": jxsv.packetization_mode,
                "L": jxsv.last,
                "I": jxsv.interlace_info,
                "F": jxsv.f_counter,
                "SEP": jxsv.sep_counter,
                "P": jxsv.p_counter,
                "abs_index": jxsv.absolute_packet_index(),
                "interlace_desc": jxsv.describe_interlace(),
                "packetization_desc": jxsv.describe_packetization(),
            },
            "issues": pkt_issues,
        }
        if is_new_frame and jxsv.p_counter == 0:
            packet_record["codestream_header"] = bytes(
                pkt.payload[JXSV_PAYLOAD_HEADER_SIZE : JXSV_PAYLOAD_HEADER_SIZE + 256]
            )
        packets_report.append(packet_record)

    if current_frame is not None:
        frames_report.append(_finalize_frame(current_frame))

    stream.seq_analysis = seq_tracker.analysis
    return packets_report, frames_report, stream, wallclock_disruption


def write_jxsv_csv(
    csv_path: Path,
    packets_report: list[dict[str, Any]],
) -> None:
    """Write a CSV with one row per RTP packet carrying JXSV payload."""
    fieldnames = [
        "capture_time", "ssrc", "rtp_timestamp",
        "seq", "marker", "payload_type", "payload_size",
        "T", "K", "L", "I", "F", "SEP", "P", "abs_index",
        "interlace_desc", "packetization_desc",
        "src_ip", "dst_ip", "src_port", "dst_port",
        "issues",
    ]
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for rec in packets_report:
            jxsv_fields = rec.get("jxsv", {})
            row = {
                "capture_time": rec.get("capture_time"),
                "ssrc": rec["ssrc"],
                "rtp_timestamp": rec["timestamp"],
                "seq": rec["seq"],
                "marker": int(rec["marker"]),
                "payload_type": rec["payload_type"],
                "payload_size": rec.get("payload_size"),
                "T": jxsv_fields.get("T"),
                "K": jxsv_fields.get("K"),
                "L": jxsv_fields.get("L"),
                "I": jxsv_fields.get("I"),
                "F": jxsv_fields.get("F"),
                "SEP": jxsv_fields.get("SEP"),
                "P": jxsv_fields.get("P"),
                "abs_index": jxsv_fields.get("abs_index"),
                "interlace_desc": jxsv_fields.get("interlace_desc"),
                "packetization_desc": jxsv_fields.get("packetization_desc"),
                "src_ip": rec.get("src_ip"),
                "dst_ip": rec.get("dst_ip"),
                "src_port": rec.get("src_port"),
                "dst_port": rec.get("dst_port"),
                "issues": "; ".join(rec.get("issues", [])),
            }
            writer.writerow(row)


# ---------------------------------------------------------------------------
# RFC 4175 / ST 2110-20 uncompressed video payload header definitions
# ---------------------------------------------------------------------------

SRD_HEADER_SIZE = 6   # 6 bytes per Sample Row Data Header
RAW_EXT_SEQ_SIZE = 2  # 2 bytes for extended sequence number
RAW_MIN_PAYLOAD = RAW_EXT_SEQ_SIZE + SRD_HEADER_SIZE  # 8 bytes minimum
RAW_MAX_SRD_HEADERS = 3  # ST 2110-20 §6.2.1


@dataclass
class SRDHeader:
    """Decoded Sample Row Data Header per ST 2110-20 §6.1.4.

    Wire layout (6 bytes):
      [0:2]  SRD Length   (16 bits) — octets of data for this sample row
      [2:4]  F (1 bit) | SRD Row Number (15 bits)
      [4:6]  C (1 bit) | SRD Offset (15 bits)
    """
    length: int       # SRD Length: octets of sample row data
    field_id: int     # F: 0=first field (or progressive), 1=second field
    row_number: int   # SRD Row Number (0-based from top)
    continuation: int # C: 1=another SRD header follows, 0=last header
    offset: int       # SRD Offset: pixel offset within sample row

    @staticmethod
    def parse(data: bytes, pos: int) -> SRDHeader | None:
        """Parse one SRD header starting at *pos* in *data*."""
        if pos + SRD_HEADER_SIZE > len(data):
            return None
        length = int.from_bytes(data[pos:pos + 2], "big")
        fn = int.from_bytes(data[pos + 2:pos + 4], "big")
        co = int.from_bytes(data[pos + 4:pos + 6], "big")
        return SRDHeader(
            length=length,
            field_id=(fn >> 15) & 1,
            row_number=fn & 0x7FFF,
            continuation=(co >> 15) & 1,
            offset=co & 0x7FFF,
        )


def parse_raw_payload_header(
    payload: bytes,
) -> tuple[int, list[SRDHeader], int] | None:
    """Parse the RFC 4175 / ST 2110-20 RTP payload header.

    Returns ``(extended_seq_num, srd_headers, data_offset)`` or ``None``
    if the payload is too short.  *data_offset* is the byte position
    where the first Sample Row Data Segment begins.
    """
    if len(payload) < RAW_MIN_PAYLOAD:
        return None
    ext_seq = int.from_bytes(payload[0:2], "big")
    headers: list[SRDHeader] = []
    pos = RAW_EXT_SEQ_SIZE
    for _ in range(RAW_MAX_SRD_HEADERS):
        hdr = SRDHeader.parse(payload, pos)
        if hdr is None:
            break
        headers.append(hdr)
        pos += SRD_HEADER_SIZE
        if hdr.continuation == 0:
            break
    if not headers:
        return None
    return ext_seq, headers, pos


@dataclass
class RawFrameState:
    """Tracks the assembly state of one uncompressed video frame."""
    timestamp: int
    first_seq: int
    last_seq: int
    first_capture_time: float | None
    last_capture_time: float | None
    packet_count: int = 0
    total_data_bytes: int = 0
    marker_seen: bool = False
    head_seen: bool = False
    observed_field_ids: set[int] = field(default_factory=set)
    max_row_number: int = -1
    min_row_number: int = 0x7FFF
    last_row_number: int = -1
    last_offset: int = -1
    issues: list[str] = field(default_factory=list)


@dataclass
class RawStreamState:
    """Accumulated validation state across an entire RFC 4175 RTP stream."""
    frame_count: int = 0
    packet_count: int = 0
    total_payload_bytes: int = 0
    last_timestamp: int | None = None
    last_ext_seq32: int | None = None
    seq_analysis: RtpSequenceAnalysis = field(default_factory=RtpSequenceAnalysis)
    issues: list[str] = field(default_factory=list)


def _validate_raw_srd_headers(
    headers: list[SRDHeader],
    frame: RawFrameState,
) -> list[str]:
    """Return per-packet conformance issues for SRD headers."""
    issues: list[str] = []

    if len(headers) > RAW_MAX_SRD_HEADERS:
        issues.append(
            f"Packet contains {len(headers)} SRD headers; "
            f"max {RAW_MAX_SRD_HEADERS} allowed (ST 2110-20 §6.2.1)"
        )

    if headers[-1].continuation != 0:
        issues.append("Last SRD header has C=1; shall be 0 (ST 2110-20 §6.1.4)")

    for i, hdr in enumerate(headers):
        # SRD Row Number must only increase within the frame
        if hdr.row_number < frame.last_row_number:
            issues.append(
                f"SRD Row Number decreased from {frame.last_row_number} to "
                f"{hdr.row_number} (ST 2110-20 §6.1.4)"
            )
        # SRD Offset must only increase within same row
        if (hdr.row_number == frame.last_row_number
                and hdr.offset <= frame.last_offset
                and frame.last_offset >= 0):
            issues.append(
                f"SRD Offset did not increase within row {hdr.row_number}: "
                f"prev={frame.last_offset}, cur={hdr.offset} (ST 2110-20 §6.1.5)"
            )
        # Update tracking
        frame.last_row_number = hdr.row_number
        frame.last_offset = hdr.offset

        if hdr.row_number > frame.max_row_number:
            frame.max_row_number = hdr.row_number
        if hdr.row_number < frame.min_row_number:
            frame.min_row_number = hdr.row_number
        # The frame's head is captured only if its very first sample
        # (row 0, offset 0 of the field) is present. A capture that starts
        # mid-frame misses it (ST 2110-20 §6.1.4-6.1.5 row/offset ordering).
        if hdr.row_number == 0 and hdr.offset == 0:
            frame.head_seen = True

        frame.observed_field_ids.add(hdr.field_id)

    return issues


def process_raw_stream(
    pcap_path: Path,
    port: int | None,
    payload_type_filter: int | None,
    max_frames: int | None,
    wallclock_backstep_threshold: float | None,
    *,
    stream_info: RtpStreamInfo | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], RawStreamState, dict[str, Any] | None]:
    """Process an RFC 4175 / ST 2110-20 uncompressed video RTP stream.

    Returns ``(packets_report, frames_report, stream_state, wallclock_disruption)``.
    """

    stream = RawStreamState()
    seq_tracker = RtpSequenceTracker()
    packets_report: list[dict[str, Any]] = []
    frames_report: list[dict[str, Any]] = []
    wallclock_disruption: dict[str, Any] | None = None

    current_frame: RawFrameState | None = None
    frame_order: list[int] = []
    frame_timestamps: set[int] = set()
    last_frame_timestamp: int | None = None
    last_frame_capture_time: float | None = None
    observed_rtp_deltas: list[float] = []

    def _finalize_frame(frm: RawFrameState) -> dict[str, Any]:
        if not frm.marker_seen:
            frm.issues.append("Frame ended without RTP marker bit (M=1)")
        field_ids = sorted(frm.observed_field_ids)
        if len(field_ids) == 1 and field_ids[0] == 0:
            interlace = "progressive"
        elif len(field_ids) == 1 and field_ids[0] == 1:
            interlace = "field_1"
        else:
            interlace = "progressive" if field_ids == [0] else f"fields={field_ids}"
        summary: dict[str, Any] = {
            "frame_index": stream.frame_count,
            "timestamp": frm.timestamp,
            "interlace": interlace,
            "field_ids": field_ids,
            "seq_range": [frm.first_seq, frm.last_seq],
            "packet_count": frm.packet_count,
            "total_data_bytes": frm.total_data_bytes,
            "first_capture_time": frm.first_capture_time,
            "last_capture_time": frm.last_capture_time,
            "marker_seen": frm.marker_seen,
            "head_seen": frm.head_seen,
            "min_row_number": frm.min_row_number if frm.min_row_number != 0x7FFF else 0,
            "max_row_number": frm.max_row_number if frm.max_row_number >= 0 else 0,
            "issues": frm.issues,
        }
        stream.frame_count += 1
        return summary

    for pkt in iter_rtp_packets_stream(pcap_path, port, stream_info=stream_info):
        if not pkt.payload or len(pkt.payload) < RAW_MIN_PAYLOAD:
            continue
        if payload_type_filter is not None and pkt.payload_type != payload_type_filter:
            continue

        parsed = parse_raw_payload_header(pkt.payload)
        if parsed is None:
            continue
        ext_seq, srd_headers, data_offset = parsed

        # Compute total data bytes from SRD Lengths (always in the clear)
        data_bytes = sum(h.length for h in srd_headers)

        is_new_frame = current_frame is None or pkt.timestamp != current_frame.timestamp

        if is_new_frame and current_frame is not None:
            frames_report.append(_finalize_frame(current_frame))

        # Wallclock backstep detection (same pattern as JXSV)
        if is_new_frame and pkt.capture_time is not None:
            if last_frame_timestamp is not None and last_frame_capture_time is not None:
                rtp_delta = ((pkt.timestamp - last_frame_timestamp) & 0xFFFFFFFF) / 90000.0
                if rtp_delta > 0:
                    observed_rtp_deltas.append(rtp_delta)
                if observed_rtp_deltas:
                    sorted_d = sorted(observed_rtp_deltas)
                    mid = len(sorted_d) // 2
                    nominal_period = (
                        sorted_d[mid]
                        if len(sorted_d) % 2
                        else (sorted_d[mid - 1] + sorted_d[mid]) / 2.0
                    )
                else:
                    nominal_period = 1.0 / 60.0
                threshold = (
                    wallclock_backstep_threshold
                    if wallclock_backstep_threshold is not None
                    else max(0.050, 3.0 * nominal_period)
                )
                capture_delta = pkt.capture_time - last_frame_capture_time
                if capture_delta < -threshold:
                    wallclock_disruption = {
                        "at_frame_index": stream.frame_count,
                        "previous_timestamp": last_frame_timestamp,
                        "current_timestamp": pkt.timestamp,
                        "previous_capture_time": last_frame_capture_time,
                        "current_capture_time": pkt.capture_time,
                        "capture_delta": capture_delta,
                        "rtp_delta": rtp_delta,
                        "threshold": threshold,
                    }
                    break
            last_frame_timestamp = pkt.timestamp
            last_frame_capture_time = pkt.capture_time

        if (
            max_frames is not None
            and is_new_frame
            and pkt.timestamp not in frame_timestamps
            and len(frame_order) >= max_frames
        ):
            break

        if is_new_frame:
            if pkt.timestamp not in frame_timestamps:
                frame_timestamps.add(pkt.timestamp)
                frame_order.append(pkt.timestamp)
                stream.last_timestamp = pkt.timestamp

            current_frame = RawFrameState(
                timestamp=pkt.timestamp,
                first_seq=pkt.seq,
                last_seq=pkt.seq,
                first_capture_time=pkt.capture_time,
                last_capture_time=pkt.capture_time,
            )

        assert current_frame is not None

        # Validate SRD headers
        pkt_issues = _validate_raw_srd_headers(srd_headers, current_frame)

        # Track extended 32-bit sequence
        ext_seq32 = (ext_seq << 16) | pkt.seq
        if stream.last_ext_seq32 is not None:
            expected = (stream.last_ext_seq32 + 1) & 0xFFFFFFFF
            if ext_seq32 != expected:
                gap = (ext_seq32 - stream.last_ext_seq32) & 0xFFFFFFFF
                if gap > 1:
                    stream.issues.append(
                        f"Extended seq gap: expected 0x{expected:08X}, got 0x{ext_seq32:08X} "
                        f"(gap={gap - 1})"
                    )
        stream.last_ext_seq32 = ext_seq32

        current_frame.issues.extend(pkt_issues)
        current_frame.packet_count += 1
        current_frame.total_data_bytes += data_bytes
        current_frame.last_seq = pkt.seq
        current_frame.last_capture_time = pkt.capture_time
        if pkt.marker:
            current_frame.marker_seen = True

        stream.packet_count += 1
        stream.total_payload_bytes += data_bytes
        seq_tracker.feed(pkt.seq, pkt.capture_time)

        packet_record: dict[str, Any] = {
            "seq": pkt.seq,
            "timestamp": pkt.timestamp,
            "ssrc": pkt.ssrc,
            "marker": pkt.marker,
            "payload_type": pkt.payload_type,
            "src_ip": pkt.src_ip,
            "dst_ip": pkt.dst_ip,
            "src_port": pkt.src_port,
            "dst_port": pkt.dst_port,
            "capture_time": pkt.capture_time,
            "payload_size": len(pkt.payload),
            "ext_elements": pkt.ext_elements,
            "ext_seq_num": ext_seq,
            "ext_seq32": ext_seq32,
            "srd_headers": [
                {
                    "length": h.length,
                    "field_id": h.field_id,
                    "row_number": h.row_number,
                    "continuation": h.continuation,
                    "offset": h.offset,
                }
                for h in srd_headers
            ],
            "srd_count": len(srd_headers),
            "data_bytes": data_bytes,
            "issues": pkt_issues,
        }
        packets_report.append(packet_record)

    if current_frame is not None:
        frames_report.append(_finalize_frame(current_frame))

    stream.seq_analysis = seq_tracker.analysis
    return packets_report, frames_report, stream, wallclock_disruption


def write_h26x_csv(
    csv_path: Path,
    codec: str,
    packets_report: list[dict[str, Any]],
) -> None:
    """Write a CSV with one row per RTP packet carrying H.264/H.265 payload."""
    fieldnames = [
        "capture_time", "ssrc", "rtp_timestamp",
        "seq", "marker", "payload_type",
        "nal_types", "summary",
        "src_ip", "dst_ip", "src_port", "dst_port",
    ]
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for rec in packets_report:
            nal_types_raw: list[int] = rec.get("nal_types", [])
            nal_labels = sorted({describe_nal(codec, nt) for nt in nal_types_raw})
            row = {
                "capture_time": rec.get("capture_time"),
                "ssrc": rec["ssrc"],
                "rtp_timestamp": rec["timestamp"],
                "seq": rec["seq"],
                "marker": int(rec["marker"]),
                "payload_type": rec["payload_type"],
                "nal_types": " ".join(str(t) for t in nal_types_raw),
                "summary": rec.get("summary", ", ".join(nal_labels)),
                "src_ip": rec.get("src_ip"),
                "dst_ip": rec.get("dst_ip"),
                "src_port": rec.get("src_port"),
                "dst_port": rec.get("dst_port"),
            }
            writer.writerow(row)


@dataclass
class ParseContext:
    byte_offset: int = 0
    nalu_counter: int = 0


@dataclass
class FragmentState:
    buffer: bytearray
    start_offset: int
    header_bytes: bytes


@dataclass
class RtpExtensionElement:
    """A single RFC 8285 one-byte header extension element."""
    ext_id: int   # 4-bit ID (1-14)
    length: int   # data length in bytes (L field value + 1)
    data: bytes


_RFC8285_ONE_BYTE_PROFILE = 0xBEDE


def _parse_rfc8285_one_byte(ext_data: bytes) -> list[RtpExtensionElement]:
    """Parse RFC 8285 one-byte header extension elements from raw extension data."""
    elements: list[RtpExtensionElement] = []
    offset = 0
    while offset < len(ext_data):
        byte = ext_data[offset]
        if byte == 0:
            offset += 1
            continue
        ext_id = (byte >> 4) & 0xF
        if ext_id == 0xF:
            break
        l_field = byte & 0xF
        data_len = l_field + 1
        offset += 1
        if offset + data_len > len(ext_data):
            break
        elements.append(RtpExtensionElement(
            ext_id=ext_id,
            length=data_len,
            data=ext_data[offset : offset + data_len],
        ))
        offset += data_len
    return elements


@dataclass
class RTPPacket:
    seq: int
    timestamp: int
    ssrc: int
    version: int
    padding: bool
    extension: bool
    csrc_count: int
    header_len: int
    marker: bool
    payload_type: int
    payload: bytes
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    capture_time: float | None
    ext_elements: list[RtpExtensionElement] | None = None


def parse_rtp_header(data: bytes) -> tuple[RTPPacket, int] | None:
    if len(data) < 12:
        return None
    version = data[0] >> 6
    if version != 2:
        return None
    padding = bool((data[0] >> 5) & 0x01)
    extension = bool((data[0] >> 4) & 0x01)
    csrc_count = data[0] & 0x0F
    header_len = 12 + (csrc_count * 4)
    if len(data) < header_len:
        return None
    ext_elements: list[RtpExtensionElement] | None = None
    if extension:
        if len(data) < header_len + 4:
            return None
        ext_profile = int.from_bytes(data[header_len : header_len + 2], "big")
        ext_len = int.from_bytes(data[header_len + 2 : header_len + 4], "big")
        ext_data_start = header_len + 4
        ext_data_end = ext_data_start + ext_len * 4
        if ext_profile == _RFC8285_ONE_BYTE_PROFILE and ext_data_end <= len(data):
            ext_elements = _parse_rfc8285_one_byte(
                data[ext_data_start:ext_data_end])
        header_len = ext_data_start + ext_len * 4
    if len(data) < header_len:
        return None
    if padding:
        pad_amount = data[-1]
        if pad_amount == 0 or pad_amount > len(data) - header_len:
            return None
        payload_end = len(data) - pad_amount
    else:
        payload_end = len(data)
    marker = bool((data[1] >> 7) & 0x01)
    payload_type = data[1] & 0x7F
    seq = int.from_bytes(data[2:4], "big")
    timestamp = int.from_bytes(data[4:8], "big")
    ssrc = int.from_bytes(data[8:12], "big")
    payload = data[header_len:payload_end]
    return (
        RTPPacket(
            seq=seq,
            timestamp=timestamp,
            ssrc=ssrc,
            version=version,
            padding=padding,
            extension=extension,
            csrc_count=csrc_count,
            header_len=header_len,
            marker=marker,
            payload_type=payload_type,
            payload=payload,
            src_ip=None,
            dst_ip=None,
            src_port=None,
            dst_port=None,
            capture_time=None,
            ext_elements=ext_elements,
        ),
        header_len,
    )


def run_ffmpeg_trace(stream: Path, frames: int) -> str:
    from ffmpeg_location import find_ffmpeg
    _ffmpeg, _ffmpeg_env = find_ffmpeg()
    cmd = [
        _ffmpeg,
        "-hide_banner",
        "-loglevel",
        "verbose",
        "-i",
        str(stream),
        "-frames:v",
        str(frames),
        "-c:v",
        "copy",
        "-bsf:v",
        "trace_headers",
        "-f",
        "null",
        "-",
    ]
    proc = subprocess.run(cmd, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, text=True, check=False, env=_ffmpeg_env)
    if proc.returncode != 0:
        raise SystemExit(f"ffmpeg trace_headers failed ({proc.returncode}); see stderr")
    return proc.stderr


def parse_trace_headers(stderr: str) -> tuple[list[dict[str, Any]], list[int]]:
    entries: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    type_keywords = [
        ("Video Parameter Set", "VPS", "Video Parameter Set"),
        ("Sequence Parameter Set", "SPS", "Sequence Parameter Set"),
        ("Picture Parameter Set", "PPS", "Picture Parameter Set"),
        ("Supplemental", "SEI", "Supplemental Enhancement Information"),
    ]
    field_re = re.compile(r"\]\s*\d+\s+(.*?)\s+=\s+(.*)")
    packet_re = re.compile(r"Packet:\s*([0-9]+)\s+bytes")
    bsf_prefix_re = re.compile(r"\[(trace_headers|AVBSFContext)\s")
    packet_sizes: list[int] = []
    packet_seen = False
    for line in stderr.splitlines():
        if not bsf_prefix_re.search(line):
            continue
        if "Slice Header" in line:
            current = None
            continue
        packet_match = packet_re.search(line)
        if packet_match:
            packet_seen = True
            packet_sizes.append(int(packet_match.group(1)))
            continue
        for match, tag, label in type_keywords:
            if match in line:
                if packet_seen:
                    current = {"type": tag, "label": label, "fields": {}}
                    entries.append(current)
                else:
                    current = None
                break
        else:
            if current is None:
                continue
            match = field_re.search(line)
            if not match:
                continue
            raw_name = match.group(1).strip()
            parts = re.split(r"\s{2,}", raw_name)
            name_part = parts[0].strip()
            sanitized = name_part.lower().replace(" ", "_")
            array_match = re.match(r"(user_data_payload_byte)(?:\[\d+\])?", sanitized)
            value_raw = match.group(2).strip()
            try:
                numeric_value = int(value_raw, 0)
                value: int | str = numeric_value
            except ValueError:
                numeric_value = None
                value = value_raw
            field_value: dict[str, str | int] = {"value": value}
            if len(parts) > 1:
                field_value["bits"] = parts[1].strip()
            if array_match:
                array_key = f"{array_match.group(1)}s"
                array = current["fields"].setdefault(array_key, [])
                array.append(numeric_value if isinstance(value, int) else value)
            else:
                current["fields"][sanitized] = field_value
    return entries, packet_sizes


def expected_header_bytes(codec: str, fields: dict[str, Any]) -> bytes | None:
    try:
        forbidden = int(fields["forbidden_zero_bit"]["value"])
        nal_unit_type = int(fields["nal_unit_type"]["value"])
    except (KeyError, TypeError, ValueError):
        return None
    if codec == "h264":
        try:
            nal_ref_idc = int(fields["nal_ref_idc"]["value"])
        except (KeyError, TypeError, ValueError):
            return None
        byte = (forbidden << 7) | ((nal_ref_idc & 0x03) << 5) | (nal_unit_type & 0x1F)
        return bytes([byte])
    else:
        try:
            nuh_layer_id = int(fields["nuh_layer_id"]["value"])
            nuh_temporal = int(fields["nuh_temporal_id_plus1"]["value"])
        except (KeyError, TypeError, ValueError):
            return None
        first = (forbidden << 7) | ((nal_unit_type & 0x3F) << 1) | ((nuh_layer_id >> 5) & 0x01)
        second = ((nuh_layer_id & 0x1F) << 3) | (nuh_temporal & 0x07)
        return bytes([first, second])


def correlate_headers(report: dict[str, Any], headers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    header_labels = set(H264_SPECIAL.values()) | set(H265_SPECIAL.values())
    meta_by_type: dict[str, list[dict[str, Any]]] = {}
    for meta in report.get("nalus", []):
        label = meta["type_label"]
        if label not in header_labels:
            continue
        meta_by_type.setdefault(label, []).append(dict(meta))

    combined: list[dict[str, Any]] = []
    for header_index, header in enumerate(headers, start=1):
        typ = header["type"]
        candidates = meta_by_type.get(typ)
        if not candidates:
            raise SystemExit(
                f"FFmpeg trace_headers produced a '{typ}' header but no matching RTP NALU exists in the capture."
            )
        expected = expected_header_bytes(report["codec"], header["fields"])
        match = None
        match_idx = None
        for idx, candidate in enumerate(candidates):
            stored = bytes(candidate.get("header_bytes", []))
            if expected is None or not stored or stored == expected:
                match = candidate
                match_idx = idx
                if expected is None or stored == expected:
                    break
        if match is None or match_idx is None:
            raise SystemExit(
                f"No matching RTP NALU found for FFmpeg header type '{typ}' with expected "
                f"first bytes {expected.hex() if expected else 'unknown'}"
            )
        candidates.pop(match_idx)
        combined.append(
            {
                "nal_index": match["index"],
                "type_label": typ,
                "timestamp": match["timestamp"],
                "seq": match["seq"],
                "ssrc": match["ssrc"],
                "payload_type": match["payload_type"],
                "capture_time": match.get("capture_time"),
                "fields": header["fields"],
                "label": header["label"],
                "nalu_size": match["nalu_size"],
                "stream_offset": match["stream_offset"],
                "header_order": header_index,
            }
        )
    leftovers = {typ: len(entries) for typ, entries in meta_by_type.items() if entries}
    if leftovers:
        entries = ", ".join(f"{count}x {typ}" for typ, count in leftovers.items())
        raise SystemExit(
            f"FFmpeg trace_headers missed {entries}; cannot safely pair the remaining parameter sets with RTP."
        )
    return combined


def validate_packet_sizes(packet_sizes: list[int], total_bytes: int) -> None:
    if not packet_sizes:
        return
    total = sum(packet_sizes)
    if total != total_bytes:
        raise SystemExit(
            f"FFmpeg trace_headers reported {total} bytes across {len(packet_sizes)} packets "
            f"but the reconstructed stream is {total_bytes} bytes; cannot trust the timeline."
        )


@dataclass
class RtpStreamInfo:
    """Identifies a unique RTP stream discovered in a PCAP capture.

    Per RFC 3550 an RTP stream uses an even destination port and the
    companion RTCP stream uses the next odd port.  A stream is uniquely
    identified by the tuple ``(dst_ip, dst_port, ssrc)``.
    """
    dst_ip: str
    dst_port: int
    ssrc: int

    @property
    def rtcp_port(self) -> int:
        return self.dst_port + 1


def detect_rtp_stream(
    pcap_path: Path,
    *,
    port: int | None = None,
    ssrc: int | None = None,
    dst_ip: str | None = None,
) -> RtpStreamInfo | None:
    """Auto-detect or validate the RTP stream parameters from a PCAP.

    Scans all UDP packets, parses RTP headers, and groups traffic by
    ``(dst_ip, even dst_port, ssrc)``.

    **Auto-detect mode** (no CLI parameters given):
    Returns the stream carrying the most packets.

    **Validation mode** (one or more of *port*, *ssrc*, *dst_ip* given):
    Verifies that packets matching the provided criteria actually exist
    in the PCAP.  Raises ``SystemExit`` if the supplied parameters do not
    match any traffic — this prevents silent misconfiguration.  When only
    some parameters are specified, the remainder is inferred from the
    dominant match.
    """
    counts: dict[tuple, int] = {}  # key: (dst_ip, dst_port, ssrc)
    has_cli_params = port is not None or ssrc is not None or dst_ip is not None
    for udp in ipmx_pcap_reader.iter_udp_packets(pcap_path, port=None):
        dp = udp.dst_port
        if dp is None or dp % 2 != 0:
            continue
        if port is not None and dp != port:
            continue
        if dst_ip is not None and udp.dst_ip != dst_ip:
            continue
        result = parse_rtp_header(udp.payload)
        if result is None:
            continue
        rtp_pkt, _ = result
        if ssrc is not None and rtp_pkt.ssrc != ssrc:
            continue
        d_ip = udp.dst_ip or ""
        key: Key = (d_ip, dp, rtp_pkt.ssrc)
        counts[key] = counts.get(key, 0) + 1
    if not counts:
        if has_cli_params:
            parts = []
            if port is not None:
                parts.append(f"port={port}")
            if ssrc is not None:
                parts.append(f"ssrc=0x{ssrc:08X}")
            if dst_ip is not None:
                parts.append(f"dst_ip={dst_ip}")
            raise SystemExit(
                f"No RTP packets matching {', '.join(parts)} found in {pcap_path}"
            )
        return None
    best = max(counts, key=counts.get)  # type: ignore[arg-type]
    return RtpStreamInfo(dst_ip=best[0], dst_port=best[1], ssrc=best[2])


def iter_rtp_packets(pcap_path: Path, port: int | None) -> list[RTPPacket]:
    return list(iter_rtp_packets_stream(pcap_path, port))


def iter_rtp_packets_stream(
    pcap_path: Path,
    port: int | None,
    *,
    stream_info: RtpStreamInfo | None = None,
) -> Iterator[RTPPacket]:
    """Iterate RTP packets from a PCAP, using :mod:`ipmx_pcap_reader` for UDP extraction.

    When neither *port* nor *stream_info* is supplied the stream is
    auto-detected via :func:`detect_rtp_stream`.  If *stream_info* is
    given, packets are filtered by ``(dst_ip, dst_port, ssrc)`` so that
    only the intended stream is returned.
    """
    if stream_info is None and port is None:
        stream_info = detect_rtp_stream(pcap_path)
    effective_port = stream_info.dst_port if stream_info is not None else port
    for udp in ipmx_pcap_reader.iter_udp_packets(pcap_path, effective_port):
        if stream_info is not None and udp.dst_ip != stream_info.dst_ip:
            continue
        result = parse_rtp_header(udp.payload)
        if result is None:
            continue
        rtp_pkt, _ = result
        if stream_info is not None and rtp_pkt.ssrc != stream_info.ssrc:
            continue
        rtp_pkt.capture_time = udp.capture_time
        rtp_pkt.src_ip = udp.src_ip
        rtp_pkt.dst_ip = udp.dst_ip
        rtp_pkt.src_port = udp.src_port
        rtp_pkt.dst_port = udp.dst_port
        yield rtp_pkt


def describe_nal(codec: str, nal_type: int | None) -> str:
    table = H265_SPECIAL if codec == "h265" else H264_SPECIAL
    if nal_type is None:
        return "unknown"
    return table.get(nal_type, f"type {nal_type}")


def is_vcl_nal(codec: str, nal_type: int) -> bool:
    if codec == "h264":
        return 1 <= nal_type <= 5
    return 0 <= nal_type <= 31


def is_recovery_point_nal(codec: str, nal_type: int) -> bool:
    """True if the NAL type is a clean random-access / recovery point.

    These mark an access unit at which a decoder can begin cleanly, so they
    are the deterministic anchor for the start of a mid-stream capture:
      - H.264: IDR (NAL unit type 5) — ITU-T H.264 Table 7-1.
      - H.265: IRAP pictures (NAL unit types 16-21: BLA_W_LP..CRA_NUT) —
        ITU-T H.265 Table 7-1.
    Note: this covers closed-GOP random access. Open-GOP gradual decoding
    refresh signalled only via a recovery_point SEI is not detected here.
    """
    if codec == "h264":
        return nal_type == 5
    return 16 <= nal_type <= 21


def _extract_size_prefixed_nal_types(codec: str, payload: bytes, offset: int) -> list[int]:
    types: list[int] = []
    while offset + 2 <= len(payload):
        nal_size = int.from_bytes(payload[offset : offset + 2], "big")
        offset += 2
        if nal_size == 0 or offset + nal_size > len(payload):
            break
        chunk = payload[offset : offset + nal_size]
        if not chunk:
            break
        if codec == "h264":
            types.append(chunk[0] & 0x1F)
        else:
            types.append((chunk[0] & 0x7E) >> 1)
        offset += nal_size
    return types


def extract_packet_nal_types(
    codec: str, payload: bytes, *, encrypted: bool = False,
) -> list[int]:
    if not payload:
        return []
    if codec == "h264":
        nal_type = payload[0] & 0x1F
        if encrypted:
            return [nal_type]
        if nal_type == 24:
            return _extract_size_prefixed_nal_types(codec, payload, 1)
        if nal_type in {25, 26, 27, 29}:
            # H.264 interleaved-mode packetization (RFC 6184 §5.7). Not used
            # by IPMX (TR-10-15c §15 mandates non-interleaved). Returning []
            # rather than raising lets non-H.264 RTP streams (e.g. audio
            # payloads passed via an unfiltered report builder) flow through
            # harmlessly — they contribute nothing to the H.264 NAL stream.
            return []
        if nal_type == 28 and len(payload) >= 2:
            return [payload[1] & 0x1F]
        return [nal_type]

    if len(payload) < 2:
        return []
    nal_type = (payload[0] & 0x7E) >> 1
    if encrypted:
        return [nal_type]
    if nal_type == 48:
        return _extract_size_prefixed_nal_types(codec, payload, 2)
    if nal_type == 49 and len(payload) >= 3:
        return [payload[2] & 0x3F]
    if nal_type == 50:
        if len(payload) < 4:
            return []
        layer_id = ((payload[0] & 0x01) << 5) | (payload[1] >> 3)
        temporal_id = payload[1] & 0x07
        byte2 = payload[2]
        byte3 = payload[3]
        a_bit = (byte2 >> 7) & 0x01
        contained_type = (byte2 >> 1) & 0x3F
        phs_size = ((byte2 & 0x01) << 4) | ((byte3 >> 4) & 0x0F)
        start = 4 + phs_size
        if start > len(payload):
            return [contained_type]
        nested_payload = payload[start:]
        if not nested_payload:
            return [contained_type]
        header_first = (a_bit << 7) | ((contained_type & 0x3F) << 1) | ((layer_id >> 5) & 0x01)
        header_second = ((layer_id & 0x1F) << 3) | (temporal_id & 0x07)
        nested_data = bytes([header_first, header_second]) + nested_payload
        return extract_packet_nal_types(codec, nested_data)
    return [nal_type]


def record_nalu_metadata(
    nalus_meta: list[dict[str, Any]],
    codec: str,
    nal_type: int,
    packet: RTPPacket,
    size: int,
    offset: int,
    context: ParseContext,
    header_bytes: bytes,
) -> None:
    context.nalu_counter += 1
    nalus_meta.append(
        {
            "index": context.nalu_counter,
            "nal_type": nal_type,
            "type_label": describe_nal(codec, nal_type),
            "timestamp": packet.timestamp,
            "seq": packet.seq,
            "ssrc": packet.ssrc,
            "payload_type": packet.payload_type,
            "capture_time": packet.capture_time,
            "nalu_size": size,
            "stream_offset": offset,
            "header_bytes": [b for b in header_bytes],
        }
    )

def _consume_size_prefixed_nalus(
    payload: bytes,
    offset: int,
    codec: str,
    packet_meta: dict[str, Any],
    nalus: list[bytes],
    nalus_meta: list[dict[str, Any]],
    packet: RTPPacket,
    context: ParseContext,
) -> None:
    while offset + 2 <= len(payload):
        nal_size = int.from_bytes(payload[offset : offset + 2], "big")
        offset += 2
        if nal_size == 0 or offset + nal_size > len(payload):
            break
        chunk = payload[offset : offset + nal_size]
        add_single_nalu(nalus, chunk, codec, packet_meta, nalus_meta, packet, context)
        offset += nal_size


def _handle_hevc_paci(
    payload: bytes,
    codec: str,
    fragments: dict[tuple[int, int, int], list[FragmentState]],
    nalus: list[bytes],
    nalus_meta: list[dict[str, Any]],
    packet_meta: dict[str, Any],
    packet: RTPPacket,
    context: ParseContext,
) -> None:
    if len(payload) < 4:
        return
    layer_id = ((payload[0] & 0x01) << 5) | (payload[1] >> 3)
    temporal_id = payload[1] & 0x07
    byte2 = payload[2]
    byte3 = payload[3]
    a_bit = (byte2 >> 7) & 0x01
    contained_type = (byte2 >> 1) & 0x3F
    phs_size = ((byte2 & 0x01) << 4) | ((byte3 >> 4) & 0x0F)
    start = 4 + phs_size
    if start > len(payload):
        return
    nested_payload = payload[start:]
    if not nested_payload:
        return
    header_first = (a_bit << 7) | ((contained_type & 0x3F) << 1) | ((layer_id >> 5) & 0x01)
    header_second = ((layer_id & 0x1F) << 3) | (temporal_id & 0x07)
    nested_data = bytes([header_first, header_second]) + nested_payload
    _process_payload_data(
        codec,
        nested_data,
        fragments,
        nalus,
        nalus_meta,
        packet_meta,
        packet,
        context,
    )


def _process_payload_data(
    codec: str,
    payload: bytes,
    fragments: dict[tuple[int, int, int], list[FragmentState]],
    nalus: list[bytes],
    nalus_meta: list[dict[str, Any]],
    packet_meta: dict[str, Any],
    packet: RTPPacket,
    context: ParseContext,
) -> None:
    if not payload:
        return
    if codec == "h264":
        nal_type = payload[0] & 0x1F
        if nal_type == 24:
            _consume_size_prefixed_nalus(
                payload, 1, codec, packet_meta, nalus, nalus_meta, packet, context
            )
            return
        if nal_type in {25, 26, 27, 29}:
            # H.264 interleaved-mode packetization (RFC 6184 §5.7). Not used
            # by IPMX; return without producing NALs so non-H.264 RTP
            # payloads (audio, etc.) that happen to have low-5-bits == one
            # of these values don't crash the parser.
            return
        if nal_type == 28 and len(payload) >= 2:
            fu_header = payload[1]
            start = bool(fu_header & 0x80)
            end = bool(fu_header & 0x40)
            orig_type = fu_header & 0x1F
            packet_meta["nal_types"].append(orig_type)
            key = (packet.ssrc, packet.timestamp, orig_type)
            if start:
                header = bytes([(payload[0] & 0xE0) | orig_type])
                start_fragment(fragments, key, header, payload[2:], context)
            else:
                append_fragment(fragments, key, payload[2:])
            if end:
                finish_fragment(fragments, key, nalus, packet, codec, nalus_meta, context)
            return
        add_single_nalu(nalus, payload, codec, packet_meta, nalus_meta, packet, context)
    else:
        if len(payload) < 2:
            return
        nal_type = (payload[0] & 0x7E) >> 1
        if nal_type == 48:
            _consume_size_prefixed_nalus(
                payload, 2, codec, packet_meta, nalus, nalus_meta, packet, context
            )
            return
        if nal_type == 49 and len(payload) >= 3:
            nuh_layer_id = ((payload[0] & 0x01) << 5) | (payload[1] >> 3)
            nuh_temporal_id_plus1 = payload[1] & 0x07
            fu_header = payload[2]
            start = bool(fu_header & 0x80)
            end = bool(fu_header & 0x40)
            orig_type = fu_header & 0x3F
            packet_meta["nal_types"].append(orig_type)
            key = (packet.ssrc, packet.timestamp, orig_type)
            if start:
                f_bit = payload[0] & 0x80
                first = (f_bit) | ((orig_type << 1) & 0x7E) | ((nuh_layer_id >> 5) & 0x01)
                second = ((nuh_layer_id & 0x1F) << 3) | (nuh_temporal_id_plus1 & 0x07)
                header = bytes([first, second])
                start_fragment(fragments, key, header, payload[3:], context)
            else:
                append_fragment(fragments, key, payload[3:])
            if end:
                finish_fragment(fragments, key, nalus, packet, codec, nalus_meta, context)
            return
        if nal_type == 50:
            _handle_hevc_paci(
                payload, codec, fragments, nalus, nalus_meta, packet_meta, packet, context
            )
            return
        add_single_nalu(nalus, payload, codec, packet_meta, nalus_meta, packet, context)

def add_single_nalu(
    nalus: list[bytes],
    payload: bytes,
    codec: str,
    packet_meta: dict[str, Any],
    nalus_meta: list[dict[str, Any]],
    packet: RTPPacket,
    context: ParseContext,
) -> None:
    if codec == "h264":
        nal_type = payload[0] & 0x1F
    else:
        nal_type = (payload[0] & 0x7E) >> 1
    packet_meta["nal_types"].append(nal_type)
    if codec == "h264":
        header_bytes = payload[:1]
    else:
        header_bytes = payload[:2]
    nalu_bytes = START_CODE + payload
    nalu_size = len(nalu_bytes)
    record_nalu_metadata(
        nalus_meta,
        codec,
        nal_type,
        packet,
        nalu_size,
        context.byte_offset,
        context,
        header_bytes,
    )
    nalus.append(nalu_bytes)
    context.byte_offset += nalu_size


def start_fragment(
    fragments: dict[tuple[int, int, int], list[FragmentState]],
    key: tuple[int, int, int],
    header: bytes,
    payload_tail: bytes,
    context: ParseContext,
) -> None:
    if key not in fragments:
        fragments[key] = []
    buf = bytearray(START_CODE)
    buf.extend(header)
    buf.extend(payload_tail)
    fragments[key].append(FragmentState(buffer=buf, start_offset=context.byte_offset, header_bytes=bytes(header)))


def append_fragment(
    fragments: dict[tuple[int, int, int], list[FragmentState]],
    key: tuple[int, int, int],
    payload_tail: bytes,
) -> None:
    if key not in fragments or not fragments[key]:
        return
    fragments[key][-1].buffer.extend(payload_tail)


def finish_fragment(
    fragments: dict[tuple[int, int, int], list[FragmentState]],
    key: tuple[int, int, int],
    nalus: list[bytes],
    packet: RTPPacket,
    codec: str,
    nalus_meta: list[dict[str, Any]],
    context: ParseContext,
) -> None:
    if key not in fragments or not fragments[key]:
        return
    fragment = fragments[key].pop()
    if not fragments[key]:
        del fragments[key]
    nalu_bytes = bytes(fragment.buffer)
    nalu_size = len(nalu_bytes)
    header_bytes = fragment.header_bytes
    record_nalu_metadata(nalus_meta, codec, key[2], packet, nalu_size, fragment.start_offset, context, header_bytes)
    nalus.append(nalu_bytes)
    context.byte_offset += nalu_size


def process_payload(
    codec: str,
    packet: RTPPacket,
    fragments: dict[tuple[int, int, int], list[FragmentState]],
    nalus: list[bytes],
    nalus_meta: list[dict[str, Any]],
    packet_meta: dict[str, Any],
    context: ParseContext,
) -> None:
    _process_payload_data(
        codec,
        packet.payload,
        fragments,
        nalus,
        nalus_meta,
        packet_meta,
        packet,
        context,
    )


def _main_h26x(args: argparse.Namespace) -> None:
    """H.264 / H.265 processing path (NAL-unit reconstruction)."""
    context = ParseContext()
    fragments: dict[tuple[int, int, int], list[FragmentState]] = {}
    nalus: list[bytes] = []
    report: list[dict[str, Any]] = []
    nalus_meta: list[dict[str, Any]] = []
    au_timestamps: set[int] = set()
    au_order: list[int] = []
    stopped_on_limit = False
    stopped_on_disruption = False
    wallclock_disruption: dict[str, Any] | None = None
    last_au_timestamp: int | None = None
    last_au_capture_time: float | None = None
    observed_au_rtp_deltas: list[float] = []

    for pkt in iter_rtp_packets_stream(args.pcap, args.port):
        if not pkt.payload:
            continue
        packet_nal_types = extract_packet_nal_types(args.codec, pkt.payload)
        packet_has_vcl = any(is_vcl_nal(args.codec, nal_type) for nal_type in packet_nal_types)
        is_new_vcl_au = packet_has_vcl and pkt.timestamp not in au_timestamps

        if is_new_vcl_au and pkt.capture_time is not None:
            if last_au_timestamp is not None and last_au_capture_time is not None:
                rtp_delta = ((pkt.timestamp - last_au_timestamp) & 0xFFFFFFFF) / 90000.0
                if rtp_delta > 0:
                    observed_au_rtp_deltas.append(rtp_delta)
                if observed_au_rtp_deltas:
                    sorted_deltas = sorted(observed_au_rtp_deltas)
                    mid = len(sorted_deltas) // 2
                    nominal_period = (
                        sorted_deltas[mid]
                        if len(sorted_deltas) % 2
                        else (sorted_deltas[mid - 1] + sorted_deltas[mid]) / 2.0
                    )
                else:
                    nominal_period = 1.0 / 60.0
                threshold = (
                    args.wallclock_backstep_threshold
                    if args.wallclock_backstep_threshold is not None
                    else max(0.050, 3.0 * nominal_period)
                )
                capture_delta = pkt.capture_time - last_au_capture_time
                if capture_delta < -threshold:
                    wallclock_disruption = {
                        "at_access_unit_index": len(au_order),
                        "previous_timestamp": last_au_timestamp,
                        "current_timestamp": pkt.timestamp,
                        "previous_capture_time": last_au_capture_time,
                        "current_capture_time": pkt.capture_time,
                        "capture_delta": capture_delta,
                        "rtp_delta": rtp_delta,
                        "threshold": threshold,
                    }
                    stopped_on_disruption = True
                    break
            last_au_timestamp = pkt.timestamp
            last_au_capture_time = pkt.capture_time

        if (
            args.max_access_units is not None
            and is_new_vcl_au
            and len(au_order) >= args.max_access_units
        ):
            stopped_on_limit = True
            break

        meta: dict[str, Any] = {
            "seq": pkt.seq,
            "timestamp": pkt.timestamp,
            "ssrc": pkt.ssrc,
            "marker": pkt.marker,
            "payload_type": pkt.payload_type,
            "src_ip": pkt.src_ip,
            "dst_ip": pkt.dst_ip,
            "src_port": pkt.src_port,
            "dst_port": pkt.dst_port,
            "capture_time": pkt.capture_time,
            "nal_types": [],
        }
        process_payload(args.codec, pkt, fragments, nalus, nalus_meta, meta, context)
        if is_new_vcl_au:
            au_timestamps.add(pkt.timestamp)
            au_order.append(pkt.timestamp)
        meta["summary"] = ", ".join(
            sorted({describe_nal(args.codec, nal) for nal in meta["nal_types"]})
        )
        report.append(meta)

    if fragments:
        print("Warning: unfinished fragments dropped", file=sys.stderr)
    if stopped_on_disruption and wallclock_disruption is not None:
        print(
            "Wallclock disruption detected in capture timeline: "
            f"AU {wallclock_disruption['at_access_unit_index'] - 1} -> "
            f"AU {wallclock_disruption['at_access_unit_index']}, "
            f"capture delta {wallclock_disruption['capture_delta']:.6f}s while RTP advanced "
            f"{wallclock_disruption['rtp_delta']:.6f}s. "
            "Parsing stopped before disruption; recapture is recommended.",
            file=sys.stderr,
        )
    if stopped_on_limit and args.max_access_units is not None:
        print(
            f"Stopped after {args.max_access_units} access units (--max-access-units).",
            file=sys.stderr,
        )

    output_path = args.output or Path("tmp") / f"recovered.{args.codec[1:]}"
    report_path = args.report or Path("tmp") / f"rtp_report_{args.codec}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as fh:
        for nalu in nalus:
            fh.write(nalu)
    print(f"Wrote {len(nalus)} NAL units to {output_path}")

    report_payload: dict[str, Any] = {
        "pcap": str(args.pcap),
        "codec": args.codec,
        "output": str(output_path),
        "packets": report,
        "nalus": nalus_meta,
        "processed_access_units": len(au_order),
    }
    if wallclock_disruption is not None:
        report_payload["wallclock_disruption"] = wallclock_disruption
    timeline_data: list[dict[str, Any]] | None = None
    if args.timeline or args.ffmpeg_log:
        trace_log = run_ffmpeg_trace(output_path, args.frames)
        if args.ffmpeg_log:
            args.ffmpeg_log.parent.mkdir(parents=True, exist_ok=True)
            args.ffmpeg_log.write_text(trace_log, encoding="utf-8")
        headers, packet_sizes = parse_trace_headers(trace_log)
        validate_packet_sizes(packet_sizes, context.byte_offset)
        timeline_data = correlate_headers(report_payload, headers)
        report_payload["timeline"] = timeline_data
        if args.timeline:
            timeline_content = {
                "pcap": str(args.pcap),
                "codec": args.codec,
                "frames_sampled": args.frames,
                "timeline": timeline_data,
            }
            args.timeline.parent.mkdir(parents=True, exist_ok=True)
            args.timeline.write_text(json.dumps(timeline_content, indent=2), encoding="utf-8")
            print(f"Wrote header timeline to {args.timeline}")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report_payload, fh, indent=2)
    print(f"Wrote RTP/NALU report to {report_path}")

    if args.csv is not None:
        write_h26x_csv(args.csv, args.codec, report)
        print(f"Wrote {args.codec} CSV to {args.csv}")


def _main_jxsv(args: argparse.Namespace) -> None:
    """JPEG XS (jxsv) processing path — RFC 9134 transport-layer validation."""
    packets_report, frames_report, stream, wallclock_disruption = process_jxsv_stream(
        pcap_path=args.pcap,
        port=args.port,
        payload_type_filter=getattr(args, "payload_type", None),
        max_frames=args.max_access_units,
        wallclock_backstep_threshold=args.wallclock_backstep_threshold,
    )

    if wallclock_disruption is not None:
        print(
            "Wallclock disruption detected in capture timeline: "
            f"frame {wallclock_disruption['at_frame_index'] - 1} -> "
            f"frame {wallclock_disruption['at_frame_index']}, "
            f"capture delta {wallclock_disruption['capture_delta']:.6f}s while RTP advanced "
            f"{wallclock_disruption['rtp_delta']:.6f}s. "
            "Parsing stopped before disruption; recapture is recommended.",
            file=sys.stderr,
        )

    all_issues = list(stream.issues)
    for frm in frames_report:
        all_issues.extend(frm.get("issues", []))

    print(f"JXSV stream: {stream.packet_count} packets, "
          f"{stream.frame_count} frames, "
          f"{stream.total_payload_bytes} payload bytes")
    if stream.first_t is not None:
        mode_t = "sequential" if stream.first_t == 1 else "out-of-order-allowed"
        print(f"  Transmission mode (T): {stream.first_t} ({mode_t})")
    if stream.first_k is not None:
        mode_k = JXSVPacketizationMode(stream.first_k).name.lower()
        print(f"  Packetization mode (K): {stream.first_k} ({mode_k})")
    if stream.field_count > 0:
        print(f"  Interlaced fields: {stream.field_count}")

    if frames_report:
        pkts_per_frame = [f["packet_count"] for f in frames_report]
        bytes_per_frame = [f["total_payload_bytes"] for f in frames_report]
        complete_frames = [f for f in frames_report if f["marker_seen"]]
        print(f"  Packets/frame: min={min(pkts_per_frame)} max={max(pkts_per_frame)} "
              f"(across {len(complete_frames)} complete frames)")
        if bytes_per_frame:
            print(f"  Payload bytes/frame: min={min(bytes_per_frame)} max={max(bytes_per_frame)}")

    if all_issues:
        print(f"\n  RFC 9134 issues found: {len(all_issues)}", file=sys.stderr)
        for issue in all_issues[:20]:
            print(f"    - {issue}", file=sys.stderr)
        if len(all_issues) > 20:
            print(f"    ... and {len(all_issues) - 20} more", file=sys.stderr)
    else:
        print("  No RFC 9134 conformance issues detected.")

    report_path = args.report or Path("tmp") / "rtp_report_jxsv.json"
    report_payload: dict[str, Any] = {
        "pcap": str(args.pcap),
        "codec": "jxsv",
        "stream": {
            "transmission_mode": stream.first_t,
            "packetization_mode": stream.first_k,
            "frame_count": stream.frame_count,
            "field_count": stream.field_count,
            "packet_count": stream.packet_count,
            "total_payload_bytes": stream.total_payload_bytes,
            "stream_issues": stream.issues,
        },
        "frames": frames_report,
        "packets": packets_report,
    }
    if wallclock_disruption is not None:
        report_payload["wallclock_disruption"] = wallclock_disruption
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report_payload, fh, indent=2)
    print(f"Wrote JXSV RTP report to {report_path}")

    csv_path = args.csv
    if csv_path is not None:
        write_jxsv_csv(csv_path, packets_report)
        print(f"Wrote JXSV CSV to {csv_path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Parse RTP video streams (H.264, H.265, JPEG XS) from PCAP captures."
    )
    parser.add_argument("pcap", type=Path, help="PCAP file containing RTP video")
    parser.add_argument(
        "--codec", required=True, choices=["h264", "h265", "jxsv"],
        help="Codec carried in RTP (jxsv = JPEG XS per RFC 9134)",
    )
    parser.add_argument("--port", type=int, help="Filter RTP packets by UDP port (default: any)")
    parser.add_argument("--output", type=Path, help="Output raw stream (.264/.265); ignored for jxsv")
    parser.add_argument("--report", type=Path, help="JSON report path")
    parser.add_argument(
        "--max-access-units",
        type=int,
        help="Stop after this many access units / frames",
    )
    parser.add_argument(
        "--wallclock-backstep-threshold",
        type=float,
        help=(
            "Backward capture-time jump (seconds) considered a wallclock disruption; "
            "default is max(0.050, 3 * nominal frame RTP period)"
        ),
    )
    parser.add_argument(
        "--frames",
        type=int,
        default=5,
        help="Number of frames ffmpeg should sample when `--timeline` is requested (h264/h265 only)",
    )
    parser.add_argument(
        "--timeline",
        type=Path,
        help="Optional JSON timeline merging FFmpeg trace_headers with RTP metadata (h264/h265 only)",
    )
    parser.add_argument(
        "--ffmpeg-log",
        type=Path,
        help="Optional path to write the ffmpeg stderr output (h264/h265 only)",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        help="Write per-packet CSV with codec-specific fields",
    )
    parser.add_argument(
        "--payload-type",
        type=int,
        dest="payload_type",
        help="Filter by RTP payload type number (useful for jxsv when the PCAP contains mixed traffic)",
    )
    args = parser.parse_args()

    if not args.pcap.exists():
        raise SystemExit(f"{args.pcap} does not exist")
    if args.max_access_units is not None and args.max_access_units <= 0:
        raise SystemExit("--max-access-units must be a positive integer")
    if (
        args.wallclock_backstep_threshold is not None
        and args.wallclock_backstep_threshold <= 0
    ):
        raise SystemExit("--wallclock-backstep-threshold must be a positive value")

    if args.codec == "jxsv":
        _main_jxsv(args)
    else:
        _main_h26x(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
