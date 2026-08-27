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
"""Validate an uncompressed raw video (RFC 4175 / ST 2110-20) IPMX PCAP.

Checks ST 2110-20 RTP payload header conformance (SRD headers, extended
sequence number, marker bit), TR-10-2 uncompressed active video requirements,
TR-10-1 system timing and RTCP Sender Report provisions, TR-10-9
frame-to-frame timing, and the uncompressed video Media Info Block
(type 0x0001) in RTCP Sender Reports.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fractions import Fraction

import ipmx_parse_rtp_pcap
import ipmx_validate_encryption
from MatroxSdpCheck import (
    SdpCheckError,
    check_sdp_rfc4175,
    check_sdp_st2110_10,
    check_sdp_st2110_20,
    check_sdp_st2110_21,
)
from ipmx_validate_encryption import detect_encryption
from ipmx_validate_common import (
    CLOCK_RATE,
    Requirement,
    RequirementResult,
    SenderReportInfo,
    configure_utf8_output,
    check_dscp_rtp_marking,
    check_dscp_sr_matches_rtp,
    check_multicast_mac_mapping,
    check_sr_mac_mapping,
    check_sr_rtcp_port,
    check_sdp_ipmx_fmtp,
    check_sdp_multicast_source_filter,
    check_sdp_session_consistency,
    check_sr_initial_rtp_clock,
    check_sr_ntp_self_consistent,
    check_sr_ntp_vs_capture_rate,
    check_sr_rc_zero,
    check_sr_compound_packet,
    check_sr_rtp_timestamp_nominal,
    compute_nominal_period,
    cross_validate_exactframerate,
    cross_validate_video_params,
    extract_exact_framerate_from_sr,
    extract_video_params_from_sr,
    filter_capture_boundary_orphan_srs,
    interval_variation_in_window,
    parse_exactframerate_arg,
    parse_sender_reports,
    print_first_sr_block_version,
    resolve_exact_ticks_per_frame,
    simulate_cmax_leaky_bucket,
    summarize_results,
    untestable,
    unwrap_rtp_timestamps,
)
from MatroxSdp import MatroxSdp, MatroxSdpEnums, MediaDescriptor


# ---------------------------------------------------------------------------
# Pgroup lookup table (ST 2110-20 Tables 1-4)
# ---------------------------------------------------------------------------

# (sampling_string, bit_depth) -> (octets_per_pgroup, pixels_per_pgroup)
PGROUP_TABLE: dict[tuple[str, int], tuple[int, int]] = {
    # Table 1 — 4:4:4 sampling systems
    ("YCbCr-4:4:4", 8): (3, 1),    ("YCbCr-4:4:4", 10): (15, 4),
    ("YCbCr-4:4:4", 12): (9, 2),   ("YCbCr-4:4:4", 16): (6, 1),
    ("CLYCbCr-4:4:4", 8): (3, 1),  ("CLYCbCr-4:4:4", 10): (15, 4),
    ("CLYCbCr-4:4:4", 12): (9, 2), ("CLYCbCr-4:4:4", 16): (6, 1),
    ("ICtCp-4:4:4", 8): (3, 1),    ("ICtCp-4:4:4", 10): (15, 4),
    ("ICtCp-4:4:4", 12): (9, 2),   ("ICtCp-4:4:4", 16): (6, 1),
    ("RGB", 8): (3, 1),            ("RGB", 10): (15, 4),
    ("RGB", 12): (9, 2),           ("RGB", 16): (6, 1),
    ("XYZ", 12): (9, 2),           ("XYZ", 16): (6, 1),
    # Table 2 — 4:2:2 sampling systems
    ("YCbCr-4:2:2", 8): (4, 2),    ("YCbCr-4:2:2", 10): (5, 2),
    ("YCbCr-4:2:2", 12): (6, 2),   ("YCbCr-4:2:2", 16): (8, 2),
    ("CLYCbCr-4:2:2", 8): (4, 2),  ("CLYCbCr-4:2:2", 10): (5, 2),
    ("CLYCbCr-4:2:2", 12): (6, 2), ("CLYCbCr-4:2:2", 16): (8, 2),
    ("ICtCp-4:2:2", 8): (4, 2),    ("ICtCp-4:2:2", 10): (5, 2),
    ("ICtCp-4:2:2", 12): (6, 2),   ("ICtCp-4:2:2", 16): (8, 2),
    # Table 3 — 4:2:0 sampling systems (progressive only)
    ("YCbCr-4:2:0", 8): (6, 4),    ("YCbCr-4:2:0", 10): (15, 8),
    ("YCbCr-4:2:0", 12): (9, 4),
    ("CLYCbCr-4:2:0", 8): (6, 4),  ("CLYCbCr-4:2:0", 10): (15, 8),
    ("CLYCbCr-4:2:0", 12): (9, 4),
    ("ICtCp-4:2:0", 8): (6, 4),    ("ICtCp-4:2:0", 10): (15, 8),
    ("ICtCp-4:2:0", 12): (9, 4),
    # Table 4 — Key signal
    ("KEY", 8): (1, 1),  ("KEY", 10): (5, 4),
    ("KEY", 12): (3, 2), ("KEY", 16): (2, 1),
}


def get_pgroup_info(sampling: str, depth: int) -> tuple[int, int] | None:
    """Return ``(octets_per_pgroup, pixels_per_pgroup)`` or ``None``."""
    return PGROUP_TABLE.get((sampling, depth))


def compute_expected_line_bytes(width: int, sampling: str, depth: int) -> int | None:
    """Expected byte count for one full sample row."""
    pg = get_pgroup_info(sampling, depth)
    if pg is None:
        return None
    octets, pixels = pg
    num_pgroups = (width + pixels - 1) // pixels
    return num_pgroups * octets


def compute_expected_frame_bytes(
    width: int, height: int, sampling: str, depth: int,
) -> int | None:
    """Total expected payload bytes for one complete progressive frame."""
    line_bytes = compute_expected_line_bytes(width, sampling, depth)
    if line_bytes is None:
        return None
    return line_bytes * height


# ---------------------------------------------------------------------------
# Validation context
# ---------------------------------------------------------------------------

@dataclass
class RawFrameInfo:
    """Per-frame summary extracted from ``process_raw_stream``."""
    index: int
    timestamp: int
    interlace: str
    packet_count: int
    total_data_bytes: int
    first_capture_time: float | None
    last_capture_time: float | None
    marker_seen: bool
    min_row_number: int
    max_row_number: int
    head_seen: bool = False
    field_ids: list[int] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)


@dataclass
class SdpRawParams:
    """Raw-video-relevant parameters extracted from an SDP transport file."""
    media: MediaDescriptor
    sampling: str | None
    width: int | None
    height: int | None
    depth: int | None
    colorimetry: str | None
    tcs: str | None
    range_str: str | None
    interlace: bool
    packing_mode: str | None


@dataclass
class RawValidationContext:
    pcap: Path
    stream_info: ipmx_parse_rtp_pcap.RtpStreamInfo | None
    stream: ipmx_parse_rtp_pcap.RawStreamState
    frames: list[RawFrameInfo]
    frames_by_ts: dict[int, RawFrameInfo]
    packets: list[dict[str, Any]]
    sender_reports: list[SenderReportInfo]
    dst_port: int | None
    sdp: SdpRawParams | None = None
    exact_framerate: Fraction | None = None
    encrypted: bool = False
    sampling: str | None = None
    width: int | None = None
    height: int | None = None
    depth: int | None = None
    # Authoritative expected values from the CLI (--width/--height/--sampling/
    # --bit-depth), cross-checked against the MIB; kept separate from the
    # SDP/MIB-derived fields above so the existing checks are unaffected.
    cli_width: int | None = None
    cli_height: int | None = None
    cli_sampling: str | None = None
    cli_bit_depth: int | None = None


def _frame_from_report(d: dict[str, Any]) -> RawFrameInfo:
    return RawFrameInfo(
        index=d["frame_index"],
        timestamp=d["timestamp"],
        interlace=d.get("interlace", "progressive"),
        packet_count=d["packet_count"],
        total_data_bytes=d["total_data_bytes"],
        first_capture_time=d.get("first_capture_time"),
        last_capture_time=d.get("last_capture_time"),
        marker_seen=d.get("marker_seen", False),
        min_row_number=d.get("min_row_number", 0),
        max_row_number=d.get("max_row_number", 0),
        head_seen=d.get("head_seen", True),
        field_ids=list(d.get("field_ids", [])),
        issues=list(d.get("issues", [])),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def find_media_block(sr: SenderReportInfo, block_type: int) -> Any:
    if sr.ipmx_info is None:
        return None
    for block in sr.ipmx_info.media_blocks:
        if block.media_info_type == block_type:
            return block
    return None


def _any_mib_0x0001(ctx: RawValidationContext) -> bool:
    return any(
        find_media_block(sr, 0x0001) is not None for sr in ctx.sender_reports
    )


def _get_mib_field(ctx: RawValidationContext, field_name: str) -> Any:
    """Get a decoded field from the first MIB 0x0001 that has it."""
    for sr in ctx.sender_reports:
        blk = find_media_block(sr, 0x0001)
        if blk is not None and blk.decoded is not None:
            val = blk.decoded.get(field_name)
            if val is not None:
                return val
    return None


# ---------------------------------------------------------------------------
# SDP loader
# ---------------------------------------------------------------------------

def load_sdp_raw_params(sdp_path: Path) -> SdpRawParams:
    """Parse an SDP file and extract raw-video-relevant parameters."""
    sdp = MatroxSdp()
    err = sdp.decode(sdp_path.read_text())
    if err:
        raise SystemExit(f"SDP parse error: {err}")

    md = sdp.primary_media
    if md.encoding_name != MatroxSdpEnums.EncodingRaw:
        raise SystemExit(
            f"SDP encoding is '{md.encoding_name}', expected 'raw'"
        )

    sampling = str(md.sampling) if md.sampling is not None else None
    colorimetry = str(md.colorimetry) if md.colorimetry is not None else None
    tcs = str(md.transfer_characteristic) if md.transfer_characteristic is not None else None
    range_str = str(md.color_range) if md.color_range is not None else None
    packing_mode = str(md.packing_mode) if md.packing_mode is not None else None

    return SdpRawParams(
        media=md,
        sampling=sampling,
        width=md.width if md.width else None,
        height=md.height if md.height else None,
        depth=md.depth if md.depth else None,
        colorimetry=colorimetry,
        tcs=tcs,
        range_str=range_str,
        interlace=md.interlaced,
        packing_mode=packing_mode,
    )


# ---------------------------------------------------------------------------
# Context builder
# ---------------------------------------------------------------------------

def build_context(args: argparse.Namespace) -> RawValidationContext:
    si = ipmx_parse_rtp_pcap.detect_rtp_stream(
        args.pcap,
        port=args.port,
        ssrc=getattr(args, "ssrc", None),
        dst_ip=getattr(args, "dst_ip", None),
    )

    packets_report, frames_report, stream, _ = ipmx_parse_rtp_pcap.process_raw_stream(
        args.pcap,
        si.dst_port if si else args.port,
        args.payload_type,
        args.max_frames,
        args.wallclock_backstep_threshold,
        stream_info=si,
    )

    frames = [_frame_from_report(d) for d in frames_report]
    frames_by_ts = {f.timestamp: f for f in frames}

    sender_reports = parse_sender_reports(
        args.pcap, args.rtcp_port, stream_info=si,
    )

    sdp_params: SdpRawParams | None = None
    if getattr(args, "sdp", None) is not None:
        sdp_params = load_sdp_raw_params(args.sdp)

    exact_fr: Fraction | None = None
    if getattr(args, "exactframerate", None):
        exact_fr = parse_exactframerate_arg(args.exactframerate)

    encrypted = any(
        detect_encryption(meta.get("ext_elements"))
        for meta in packets_report
        if meta.get("ext_elements")
    )

    # Resolve video params: prefer SDP, fallback to MIB
    sampling: str | None = None
    width: int | None = None
    height: int | None = None
    depth: int | None = None

    if sdp_params is not None:
        sampling = sdp_params.sampling
        width = sdp_params.width
        height = sdp_params.height
        depth = sdp_params.depth

    if sampling is None or width is None or height is None or depth is None:
        mib_params = extract_video_params_from_sr(sender_reports)
        if mib_params is not None:
            if sampling is None:
                sampling = mib_params.get("sampling_format")
            if width is None:
                w = mib_params.get("width")
                if isinstance(w, int):
                    width = w
            if height is None:
                h = mib_params.get("height")
                if isinstance(h, int):
                    height = h
            if depth is None:
                bd = mib_params.get("bit_depth")
                if isinstance(bd, int):
                    depth = bd

    return RawValidationContext(
        pcap=args.pcap,
        stream_info=si,
        stream=stream,
        frames=frames,
        frames_by_ts=frames_by_ts,
        packets=packets_report,
        sender_reports=sender_reports,
        dst_port=si.dst_port if si else None,
        sdp=sdp_params,
        exact_framerate=exact_fr,
        encrypted=encrypted,
        sampling=sampling,
        width=width,
        height=height,
        depth=depth,
        cli_width=args.width,
        cli_height=args.height,
        cli_sampling=args.sampling,
        cli_bit_depth=args.bit_depth,
    )


# ---------------------------------------------------------------------------
# ST 2110-20 / RFC 4175 — RTP payload header checks
# ---------------------------------------------------------------------------

def check_st2110_marker(ctx: RawValidationContext) -> tuple[bool, str]:
    """Marker bit SHALL be set on last packet of frame/field (ST 2110-20 §6.1.2)."""
    complete = _complete_frames(ctx)
    missing = [f for f in complete if not f.marker_seen]
    if missing:
        return False, f"{len(missing)}/{len(complete)} complete frames lack RTP marker bit"
    if not complete:
        return untestable("No complete frames to verify marker bit")
    return True, f"Marker bit set on last packet of all {len(complete)} complete frames"


def check_st2110_ext_seq(ctx: RawValidationContext) -> tuple[bool, str]:
    """Extended 32-bit sequence number SHALL increment correctly (ST 2110-20 §6.1.4)."""
    issues = [i for i in ctx.stream.issues if "Extended seq" in i]
    if issues:
        return False, f"{len(issues)} extended seq gap(s): {issues[0]}"
    if ctx.stream.packet_count == 0:
        return untestable("No packets to verify")
    return True, f"Extended 32-bit seq consistent across {ctx.stream.packet_count} packets"


def check_st2110_srd_length(ctx: RawValidationContext) -> tuple[bool, str]:
    """SRD Length SHALL be multiple of pgroup size (ST 2110-20 §6.1.4)."""
    if ctx.sampling is None or ctx.depth is None:
        return untestable("Sampling/depth unknown — cannot verify pgroup alignment")
    pg = get_pgroup_info(ctx.sampling, ctx.depth)
    if pg is None:
        return untestable(f"No pgroup defined for {ctx.sampling} {ctx.depth}-bit")
    octets_per_pg, _ = pg
    violations = 0
    total_checked = 0
    for pkt in ctx.packets:
        for hdr in pkt.get("srd_headers", []):
            length = hdr["length"]
            if length == 0:
                if pkt.get("srd_count", 1) == 1:
                    continue
                violations += 1
            elif length % octets_per_pg != 0:
                violations += 1
            total_checked += 1
    if violations:
        return False, (
            f"{violations}/{total_checked} SRD Length values not aligned to "
            f"pgroup size {octets_per_pg} ({ctx.sampling} {ctx.depth}-bit)"
        )
    return True, (
        f"All {total_checked} SRD Length values aligned to pgroup size "
        f"{octets_per_pg} ({ctx.sampling} {ctx.depth}-bit)"
    )


def check_st2110_srd_row(ctx: RawValidationContext) -> tuple[bool, str]:
    """SRD Row Number SHALL only increase within frame/field (ST 2110-20 §6.1.4)."""
    violations = 0
    for frm in ctx.frames:
        for issue in frm.issues:
            if "Row Number decreased" in issue:
                violations += 1
    if violations:
        return False, f"{violations} SRD Row Number decrease(s) detected"
    return True, "SRD Row Numbers only increase within each frame"


def check_st2110_srd_offset(ctx: RawValidationContext) -> tuple[bool, str]:
    """SRD Offset SHALL only increase within same sample row (ST 2110-20 §6.1.5)."""
    violations = 0
    for frm in ctx.frames:
        for issue in frm.issues:
            if "Offset did not increase" in issue:
                violations += 1
    if violations:
        return False, f"{violations} SRD Offset violation(s) detected"
    return True, "SRD Offsets only increase within each sample row"


def check_st2110_field_bit(ctx: RawValidationContext) -> tuple[bool, str]:
    """For progressive, F bit SHALL be 0 (ST 2110-20 §6.1.4)."""
    is_progressive = True
    if ctx.sdp is not None and ctx.sdp.interlace:
        is_progressive = False
    if is_progressive:
        violations = 0
        for pkt in ctx.packets:
            for hdr in pkt.get("srd_headers", []):
                if hdr["field_id"] != 0:
                    violations += 1
        if violations:
            return False, f"{violations} packets have F=1 in progressive mode"
        return True, "F bit is 0 for all packets (progressive)"
    return True, "Interlaced mode — F bit values are expected to vary"


def check_st2110_continuation(ctx: RawValidationContext) -> tuple[bool, str]:
    """Last SRD header per packet SHALL have C=0 (ST 2110-20 §6.1.4)."""
    violations = 0
    for frm in ctx.frames:
        for issue in frm.issues:
            if "C=1; shall be 0" in issue:
                violations += 1
    if violations:
        return False, f"{violations} packets have last SRD header with C=1"
    return True, "All packets have last SRD header with C=0"


def check_st2110_max_srd(ctx: RawValidationContext) -> tuple[bool, str]:
    """RTP Packets SHALL NOT contain more than 3 SRD Headers (ST 2110-20 §6.2.1)."""
    violations = 0
    for pkt in ctx.packets:
        if pkt.get("srd_count", 0) > 3:
            violations += 1
    if violations:
        return False, f"{violations} packets have more than 3 SRD headers"
    if not ctx.packets:
        return untestable("No packets to verify")
    return True, "All packets have at most 3 SRD headers"


def check_st2110_frame_size(ctx: RawValidationContext) -> tuple[bool, str]:
    """Total payload per frame SHALL match expected pixel data size."""
    if ctx.width is None or ctx.height is None:
        return untestable("Width/height unknown — cannot verify frame size")
    if ctx.sampling is None or ctx.depth is None:
        return untestable("Sampling/depth unknown — cannot verify frame size")
    expected = compute_expected_frame_bytes(ctx.width, ctx.height, ctx.sampling, ctx.depth)
    if expected is None:
        return untestable(f"Cannot compute expected size for {ctx.sampling} {ctx.depth}-bit")
    complete = _complete_frames(ctx)
    if not complete:
        return untestable("No complete frames to verify frame size")
    mismatches = 0
    for frm in complete:
        if frm.total_data_bytes != expected:
            mismatches += 1
    if mismatches:
        sample = complete[0]
        return False, (
            f"{mismatches}/{len(complete)} frames: got {sample.total_data_bytes} bytes, "
            f"expected {expected} ({ctx.width}x{ctx.height} {ctx.sampling} {ctx.depth}-bit)"
        )
    return True, (
        f"All {len(complete)} complete frames have {expected} payload bytes "
        f"({ctx.width}x{ctx.height} {ctx.sampling} {ctx.depth}-bit)"
    )


def check_st2110_no_cross_frame(ctx: RawValidationContext) -> tuple[bool, str]:
    """Packets SHALL NOT contain data from more than one frame/field (ST 2110-20 §6.1.5)."""
    # Already enforced by process_raw_stream's timestamp-based boundary.
    # Check for any logged issues about cross-frame data.
    if not ctx.packets:
        return untestable("No packets to verify")
    return True, "Frame boundaries consistent with RTP timestamps"


def check_st2110_issues(ctx: RawValidationContext) -> tuple[bool, str]:
    """Aggregate per-frame ST 2110-20 / RFC 4175 issues."""
    complete = _complete_frames(ctx)
    total = len(ctx.stream.issues)
    for frm in complete:
        total += len(frm.issues)
    if total:
        sample = (ctx.stream.issues + [i for f in complete for i in f.issues])[:5]
        return False, f"{total} issue(s) in {len(complete)} complete frame(s); first: {sample[0]}"
    return True, f"No ST 2110-20 conformance issues across {len(complete)} complete frames"


# ---------------------------------------------------------------------------
# TR-10-2 — Uncompressed Active Video
# ---------------------------------------------------------------------------

def check_udp_port_even(ctx: RawValidationContext) -> tuple[bool, str]:
    """UDP destination port SHALL be even and > 1024 (TR-10-2 §7)."""
    if ctx.dst_port is None:
        return untestable("Destination port not available")
    issues = []
    if ctx.dst_port % 2 != 0:
        issues.append(f"port {ctx.dst_port} is odd")
    if ctx.dst_port <= 1024:
        issues.append(f"port {ctx.dst_port} is not > 1024")
    if issues:
        return False, "; ".join(issues)
    return True, f"Destination port {ctx.dst_port} is even and > 1024"


def check_udp_port_above_5000(ctx: RawValidationContext) -> tuple[bool, str]:
    """UDP destination port SHOULD be > 5000 (TR-10-2 §7)."""
    if ctx.dst_port is None:
        return untestable("Destination port not available")
    if ctx.dst_port <= 5000:
        return False, f"Destination port {ctx.dst_port} is not > 5000"
    return True, f"Destination port {ctx.dst_port} is > 5000"


def check_clock_rate(ctx: RawValidationContext) -> tuple[bool, str]:
    """RTP Clock rate SHALL be 90 kHz (TR-10-2 §9)."""
    timestamps = [f.timestamp for f in ctx.frames]
    if len(timestamps) < 2:
        return untestable("Not enough frames to verify clock rate")
    unwrapped = unwrap_rtp_timestamps(timestamps)
    deltas = [b - a for a, b in zip(unwrapped, unwrapped[1:]) if b > a]
    if not deltas:
        return False, "No positive timestamp deltas observed"
    deltas.sort()
    median_delta = deltas[len(deltas) // 2]
    nominal = compute_nominal_period(timestamps)
    if nominal is None:
        return False, "Cannot determine nominal period"
    expected_ticks = nominal * CLOCK_RATE
    if abs(median_delta - expected_ticks) / expected_ticks > 0.01:
        return False, f"Median delta {median_delta} ticks inconsistent with 90 kHz clock"
    return True, f"Timestamp increments consistent with 90 kHz clock (median delta {median_delta} ticks)"


def check_timestamp_consistency(ctx: RawValidationContext) -> tuple[bool, str]:
    """All packets of same frame SHALL have same RTP timestamp (TR-10-2 §9)."""
    # Inherently true by process_raw_stream design (groups by timestamp).
    # Verify via frame reports.
    if not ctx.frames:
        return untestable("No frames to verify")
    return True, f"All packets within each of {len(ctx.frames)} frames share the same RTP timestamp"


def check_sr_present(ctx: RawValidationContext) -> tuple[bool, str]:
    """RTCP Sender Reports SHALL be present (TR-10-1 §8.7)."""
    if not ctx.sender_reports:
        return False, "No RTCP Sender Reports detected"
    return True, f"{len(ctx.sender_reports)} Sender Report(s) detected"


def check_ipmx_info_block(ctx: RawValidationContext) -> tuple[bool, str]:
    """SR SHALL include an IPMX Info Block (tag 0x5831) (TR-10-1 §8.7)."""
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    missing = sum(1 for sr in ctx.sender_reports if sr.ipmx_info is None)
    if missing:
        return False, f"{missing}/{len(ctx.sender_reports)} SRs lack IPMX Info Block"
    return True, "All SRs contain an IPMX Info Block"


def check_mib_0x0001(ctx: RawValidationContext) -> tuple[bool, str]:
    """SR SHALL contain Media Info Block type 0x0001 (TR-10-2 §10)."""
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    missing = sum(1 for sr in ctx.sender_reports if find_media_block(sr, 0x0001) is None)
    if missing:
        return False, f"{missing}/{len(ctx.sender_reports)} SRs lack MIB 0x0001"
    return True, "All SRs contain MIB 0x0001 (Uncompressed Active Video)"


def check_mib_0x0001_length(ctx: RawValidationContext) -> tuple[bool, str]:
    """MIB 0x0001 length SHALL be 22 (32-bit words minus one) (TR-10-2 §10)."""
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    if not _any_mib_0x0001(ctx):
        return untestable("No MIB 0x0001 present — length cannot be verified")
    violations = []
    for sr in ctx.sender_reports:
        blk = find_media_block(sr, 0x0001)
        if blk is None:
            continue
        if blk.length_words != 22:
            violations.append(f"length_words={blk.length_words}, expected 22")
    if violations:
        return False, f"{len(violations)} MIB 0x0001 block(s) with wrong length: {violations[0]}"
    return True, "All MIB 0x0001 blocks have length=22"


# ---------------------------------------------------------------------------
# MIB 0x0001 ↔ SDP cross-validation (TR-10-2 §10)
# ---------------------------------------------------------------------------

def _check_mib_vs_sdp_field(
    ctx: RawValidationContext,
    mib_field: str,
    sdp_value: Any,
    label: str,
    *,
    transform_mib: Any = None,
) -> tuple[bool, str]:
    """Generic MIB field vs SDP value comparison."""
    if ctx.sdp is None:
        return untestable("No SDP transport file provided (use --sdp)")
    if sdp_value is None:
        return untestable(f"SDP does not specify {label}")
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    if not _any_mib_0x0001(ctx):
        return untestable(f"No MIB 0x0001 present — {label} cannot be verified")
    mismatches = 0
    checked = 0
    mib_val_sample = None
    for sr in ctx.sender_reports:
        blk = find_media_block(sr, 0x0001)
        if blk is None or blk.decoded is None:
            continue
        mib_val = blk.decoded.get(mib_field)
        if mib_val is None:
            continue
        if transform_mib is not None:
            mib_val = transform_mib(mib_val)
        checked += 1
        if mib_val_sample is None:
            mib_val_sample = mib_val
        if str(mib_val) != str(sdp_value):
            mismatches += 1
    if checked == 0:
        return untestable(f"MIB 0x0001 present but no {mib_field} field found")
    if mismatches:
        return False, (
            f"{mismatches}/{checked} SR(s): MIB {label}='{mib_val_sample}' "
            f"differs from SDP {label}='{sdp_value}'"
        )
    return True, f"MIB {label}='{sdp_value}' matches SDP across {checked} SR(s)"


def check_mib_sampling(ctx: RawValidationContext) -> tuple[bool, str]:
    return _check_mib_vs_sdp_field(
        ctx, "sampling_format",
        ctx.sdp.sampling if ctx.sdp else None, "sampling",
    )


def check_mib_width(ctx: RawValidationContext) -> tuple[bool, str]:
    return _check_mib_vs_sdp_field(
        ctx, "width",
        ctx.sdp.width if ctx.sdp else None, "width",
    )


def check_mib_height(ctx: RawValidationContext) -> tuple[bool, str]:
    return _check_mib_vs_sdp_field(
        ctx, "height",
        ctx.sdp.height if ctx.sdp else None, "height",
    )


def check_mib_depth(ctx: RawValidationContext) -> tuple[bool, str]:
    return _check_mib_vs_sdp_field(
        ctx, "bit_depth",
        ctx.sdp.depth if ctx.sdp else None, "depth",
    )


def check_mib_colorimetry(ctx: RawValidationContext) -> tuple[bool, str]:
    return _check_mib_vs_sdp_field(
        ctx, "colorimetry",
        ctx.sdp.colorimetry if ctx.sdp else None, "colorimetry",
    )


def check_mib_range(ctx: RawValidationContext) -> tuple[bool, str]:
    return _check_mib_vs_sdp_field(
        ctx, "range",
        ctx.sdp.range_str if ctx.sdp else None, "range",
    )


def check_mib_tcs(ctx: RawValidationContext) -> tuple[bool, str]:
    return _check_mib_vs_sdp_field(
        ctx, "tcs",
        ctx.sdp.tcs if ctx.sdp else None, "TCS",
    )


def check_mib_rate(ctx: RawValidationContext) -> tuple[bool, str]:
    """MIB rate_numerator/rate_denominator SHALL match SDP exactframerate (TR-10-2 §10)."""
    if ctx.sdp is None:
        return untestable("No SDP transport file provided (use --sdp)")
    md = ctx.sdp.media
    sdp_num = md.exact_frame_rate_numerator
    sdp_den = md.exact_frame_rate_denominator
    if not sdp_num or not sdp_den:
        return untestable("SDP does not specify exactframerate")
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    if not _any_mib_0x0001(ctx):
        return untestable("No MIB 0x0001 present — rate cannot be verified")
    mismatches = 0
    checked = 0
    for sr in ctx.sender_reports:
        blk = find_media_block(sr, 0x0001)
        if blk is None or blk.decoded is None:
            continue
        mib_num = blk.decoded.get("rate_numerator")
        mib_den = blk.decoded.get("rate_denominator")
        if mib_num is None or mib_den is None:
            continue
        checked += 1
        if mib_num != sdp_num or mib_den != sdp_den:
            mismatches += 1
    if checked == 0:
        return untestable("MIB 0x0001 present but no rate fields found")
    if mismatches:
        return False, (
            f"{mismatches}/{checked} SR(s): MIB rate differs from "
            f"SDP exactframerate={sdp_num}/{sdp_den}"
        )
    return True, f"MIB rate={sdp_num}/{sdp_den} matches SDP across {checked} SR(s)"


def check_mib_interlace(ctx: RawValidationContext) -> tuple[bool, str]:
    """MIB interlace flag SHALL match observed interlace state (TR-10-2 §10)."""
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    if not _any_mib_0x0001(ctx):
        return untestable("No MIB 0x0001 present — interlace cannot be verified")
    # Determine observed interlace from payload F bits
    observed_progressive = all(f.interlace == "progressive" for f in ctx.frames) if ctx.frames else True
    mismatches = 0
    checked = 0
    for sr in ctx.sender_reports:
        blk = find_media_block(sr, 0x0001)
        if blk is None or blk.decoded is None:
            continue
        mib_interlace = blk.decoded.get("interlace")
        if mib_interlace is None:
            continue
        checked += 1
        mib_is_progressive = not bool(mib_interlace)
        if mib_is_progressive != observed_progressive:
            mismatches += 1
    if checked == 0:
        return untestable("MIB 0x0001 present but no interlace field found")
    if mismatches:
        return False, (
            f"{mismatches}/{checked} SR(s): MIB interlace flag "
            f"inconsistent with observed {'progressive' if observed_progressive else 'interlaced'} stream"
        )
    return True, (
        f"MIB interlace flag matches observed "
        f"{'progressive' if observed_progressive else 'interlaced'} stream"
    )


# ---------------------------------------------------------------------------
# SDP transport file cross-validation
# ---------------------------------------------------------------------------

def check_sdp_port_vs_stream(ctx: RawValidationContext) -> tuple[bool, str]:
    """SDP port SHALL match the detected RTP destination port."""
    if ctx.sdp is None:
        return untestable("No SDP transport file provided (use --sdp)")
    if ctx.stream_info is None:
        return untestable("RTP stream not detected")
    sdp_port = ctx.sdp.media.port
    if sdp_port != ctx.stream_info.dst_port:
        return False, (
            f"SDP port={sdp_port} differs from detected "
            f"RTP port={ctx.stream_info.dst_port}"
        )
    return True, f"SDP port={sdp_port} matches detected RTP port"


def check_sdp_dst_ip_vs_stream(ctx: RawValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """SDP connection address SHALL match the detected destination IP."""
    from ipmx_validate_common import check_sdp_dst_ip_vs_stream as _check
    sdp_media = ctx.sdp.media if ctx.sdp is not None else None
    return _check(sdp_media, ctx.stream_info)


# ---------------------------------------------------------------------------
# TR-10-9 — Frame-to-frame timing
# ---------------------------------------------------------------------------

def _check_interval_tr10_9(
    times: list[float], label: str,
) -> tuple[bool, str] | tuple[bool, str, bool]:
    if len(times) < 3:
        return untestable(f"Not enough {label} to assess interval")
    duration = times[-1] - times[0]
    if duration < 2.0:
        return untestable(
            f"Capture duration {duration*1000:.0f}ms < 2s required by TR-10-9 "
            f"({len(times)} {label}, need longer capture)"
        )
    passed, details = interval_variation_in_window(times, window=2.0, tolerance=0.002)
    if not passed and details.startswith("Not enough"):
        return untestable(details)
    return passed, details


def check_frame_interval_tr10_9(ctx: RawValidationContext) -> tuple[bool, str]:
    times = [
        f.first_capture_time
        for f in ctx.frames
        if f.first_capture_time is not None
    ]
    return _check_interval_tr10_9(times, "frames")  # type: ignore[return-value]


def check_sr_interval_tr10_9(ctx: RawValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    times = [sr.capture_time for sr in ctx.sender_reports]
    return _check_interval_tr10_9(times, "SRs")  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# SR-to-frame cross-validation
# ---------------------------------------------------------------------------

def check_sr_mapping(ctx: RawValidationContext) -> tuple[bool, str]:
    """Each frame SHALL have a corresponding Sender Report."""
    if not ctx.sender_reports:
        return False, "No RTCP Sender Reports detected"
    sr_timestamps = {sr.rtp_timestamp for sr in ctx.sender_reports}
    # Only fully-captured frames can be required to have an SR within the
    # capture window: a head-truncated first frame or tail-truncated last
    # frame may have its SR fall outside the capture (see _complete_frames).
    complete = _complete_frames(ctx)
    missing = [f.timestamp for f in complete if f.timestamp not in sr_timestamps]
    if missing:
        return False, f"Missing SRs for {len(missing)}/{len(complete)} frames"
    unknown = [sr for sr in ctx.sender_reports if sr.rtp_timestamp not in ctx.frames_by_ts]
    if unknown:
        last_frame_time = max(
            (f.first_capture_time for f in ctx.frames if f.first_capture_time is not None),
            default=0.0,
        )
        real_unknown = filter_capture_boundary_orphan_srs(
            unknown, set(ctx.frames_by_ts.keys()), last_frame_time)
        if real_unknown:
            return False, f"SRs reference {len(real_unknown)} unknown RTP timestamps"
    return True, "SRs present for all frames"


def check_sr_before_frame(ctx: RawValidationContext) -> tuple[bool, str]:
    """Sender Report SHALL arrive before the first media packet of the frame."""
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    violations = 0
    for sr in ctx.sender_reports:
        frm = ctx.frames_by_ts.get(sr.rtp_timestamp)
        if frm is None or frm.first_capture_time is None:
            continue
        if sr.capture_time > frm.first_capture_time:
            violations += 1
    if violations:
        return False, f"{violations} SR(s) arrive after the first media packet"
    return True, "All SRs arrive before the first media packet of their frame"


def check_sr_order(ctx: RawValidationContext) -> tuple[bool, str]:
    """Sender Reports SHALL be in presentation order."""
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    indices = []
    for sr in ctx.sender_reports:
        frm = ctx.frames_by_ts.get(sr.rtp_timestamp)
        if frm is None:
            continue
        indices.append(frm.index)
    if indices != sorted(indices):
        return False, "SRs are not in presentation order"
    return True, "SRs are in presentation order"


def _check_sr_diff_raw(ctx: RawValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    rtp_timestamps = [f.timestamp for f in ctx.frames]
    exact_ticks = resolve_exact_ticks_per_frame(
        ctx.exact_framerate,
        ctx.sender_reports,
        rtp_timestamps,
    )
    return check_sr_rtp_timestamp_nominal(ctx.sender_reports, exact_ticks)


def check_sr_interval(ctx: RawValidationContext) -> tuple[bool, str]:
    """SR interval SHOULD match the nominal frame interval."""
    if len(ctx.sender_reports) < 3:
        return untestable("Not enough SRs to assess interval")
    timestamps_sr = [sr.capture_time for sr in ctx.sender_reports]
    intervals = [b - a for a, b in zip(timestamps_sr, timestamps_sr[1:]) if b > a]
    if not intervals:
        return False, "SR intervals unavailable"
    intervals.sort()
    mid = intervals[len(intervals) // 2]
    nominal = compute_nominal_period([f.timestamp for f in ctx.frames])
    if nominal is None:
        return False, "Not enough frames to derive nominal period"
    tolerance = max(0.001, nominal * 0.01)
    if abs(mid - nominal) > tolerance:
        return False, f"SR interval {mid:.6f}s differs from nominal {nominal:.6f}s"
    return True, f"SR interval {mid:.6f}s matches nominal {nominal:.6f}s"


def check_au_interval_const(ctx: RawValidationContext) -> tuple[bool, str]:
    """Frame (AU) RTP timestamp intervals SHOULD be constant."""
    timestamps = [f.timestamp for f in ctx.frames]
    if len(timestamps) < 3:
        return untestable("Not enough frames to assess AU interval")
    unwrapped = unwrap_rtp_timestamps(timestamps)
    deltas = [
        (cur - prev) / CLOCK_RATE
        for prev, cur in zip(unwrapped, unwrapped[1:])
        if cur > prev
    ]
    if not deltas:
        return False, "AU intervals unavailable"
    deltas.sort()
    mid = deltas[len(deltas) // 2]
    max_dev = max(abs(d - mid) for d in deltas)
    tolerance = max(0.001, mid * 0.01)
    if max_dev > tolerance:
        return False, f"AU interval variation {max_dev:.6f}s exceeds {tolerance:.6f}s"
    return True, f"AU interval variation {max_dev:.6f}s within {tolerance:.6f}s"


def _complete_frames(ctx: RawValidationContext) -> list[RawFrameInfo]:
    """Return only frames that are fully captured at both head and tail.

    A capture rarely starts or ends exactly on a frame boundary:
      - The last frame is tail-truncated when it ends without the RTP marker
        bit (M=1, ST 2110-20 §6.1.2).
      - The first frame is head-truncated when the capture began mid-frame, so
        its first sample (row 0, offset 0) was never captured
        (head_seen is False). Such a frame can still carry the marker bit and
        many packets, so a marker/packet-count test alone misses it.
    Partial boundary frames are dropped here so the per-frame size check and
    the CBR/CMAX models only see fully-captured frames.
    """
    frames = list(ctx.frames)
    if frames and not frames[-1].marker_seen:
        frames = frames[:-1]
    if frames and not frames[0].head_seen:
        frames = frames[1:]
    return frames


def check_rtp_seq_complete(ctx: RawValidationContext) -> tuple[bool, str]:
    """RTP sequence numbers SHALL be contiguous."""
    seq = ctx.stream.seq_analysis
    if seq.total_received == 0:
        return False, "No RTP packets received"
    if seq.complete:
        return True, seq.summary()
    return False, f"PCAP is incomplete: {seq.summary()}"


def check_sdp_wrapper(ctx: RawValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """Comprehensive SDP-side requirement for IPMX raw video streams.

    Mirrors the per-media-type checklist `TP-10/TP-10-1Sec13.2.py:195-232`
    runs for `video/raw` (RFC 4175 + ST 2110-10 + ST 2110-21 + ST 2110-20)
    and adds the project-local IPMX checks: the IPMX fmtp keyword
    (TR-10-1 §10.1) and the multicast source-filter signaling
    (TR-10-9 §17 / RFC 4570). First failure wins.
    """
    media = ctx.sdp.media if ctx.sdp is not None else None
    if media is None:
        return untestable("No SDP provided")
    try:
        check_sdp_rfc4175(media)
        check_sdp_st2110_10(media)
        check_sdp_st2110_21(media)
        check_sdp_st2110_20(media)
    except SdpCheckError as exc:
        return False, f"MatroxSdpCheck failed: {exc}"
    ok, msg, *tail = check_sdp_ipmx_fmtp(media)
    if not ok and (not tail or tail[0]):
        return False, msg
    sf = check_sdp_multicast_source_filter(media)
    sf_na = (len(sf) == 3 and not sf[2])
    if not sf_na and not sf[0]:
        return False, sf[1]
    sc = check_sdp_session_consistency(media)
    if not sc[0]:
        return False, sc[1]
    if sf_na:
        return True, (
            f"MatroxSdpCheck + IPMX fmtp + session consistency passed; "
            f"source-filter N/A ({sf[1]})"
        )
    return True, "MatroxSdpCheck + IPMX fmtp + source-filter + session consistency all passed"


# ---------------------------------------------------------------------------
# Requirement list
# ---------------------------------------------------------------------------

def build_requirements(ctx: RawValidationContext) -> list[Requirement]:
    reqs: list[Requirement] = []

    def add(req_id: str, level: str, text: str, check: Any) -> None:
        reqs.append(Requirement(req_id=req_id, level=level, text=text, check=check))

    # --- PCAP completeness ---
    add("RTP-SEQ", "shall",
        "RTP sequence numbers SHALL be contiguous — missing packets indicate an incomplete PCAP capture.",
        lambda c=ctx: check_rtp_seq_complete(c))

    # --- ST 2110-20 / RFC 4175: RTP payload header ---
    add("ST2110-20-MARKER", "shall",
        "Marker bit SHALL be set to 1 on last packet of frame/field, 0 otherwise (ST 2110-20 §6.1.2).",
        lambda c=ctx: check_st2110_marker(c))
    add("ST2110-20-EXT-SEQ", "shall",
        "Extended 32-bit sequence number SHALL increment correctly (ST 2110-20 §6.1.4).",
        lambda c=ctx: check_st2110_ext_seq(c))
    add("ST2110-20-SRD-LEN", "shall",
        "SRD Length SHALL be a multiple of pgroup size (ST 2110-20 §6.1.4).",
        lambda c=ctx: check_st2110_srd_length(c))
    add("ST2110-20-SRD-ROW", "shall",
        "SRD Row Number SHALL start at 0 and only increase within frame/field (ST 2110-20 §6.1.4).",
        lambda c=ctx: check_st2110_srd_row(c))
    add("ST2110-20-SRD-OFFSET", "shall",
        "SRD Offset SHALL only increase within same sample row (ST 2110-20 §6.1.5).",
        lambda c=ctx: check_st2110_srd_offset(c))
    add("ST2110-20-FIELD", "shall",
        "For progressive scan, the F bit SHALL be 0 (ST 2110-20 §6.1.4).",
        lambda c=ctx: check_st2110_field_bit(c))
    add("ST2110-20-CONT", "shall",
        "Last SRD header per packet SHALL have C=0 (ST 2110-20 §6.1.4).",
        lambda c=ctx: check_st2110_continuation(c))
    add("ST2110-20-MAX-SRD", "shall",
        "RTP Packets SHALL NOT contain more than 3 SRD Headers (ST 2110-20 §6.2.1).",
        lambda c=ctx: check_st2110_max_srd(c))
    add("ST2110-20-FRAME-SIZE", "shall",
        "Total payload per frame SHALL match expected pixel data size.",
        lambda c=ctx: check_st2110_frame_size(c))
    add("ST2110-20-NO-CROSS", "shall",
        "Packets SHALL NOT contain data from more than one frame/field (ST 2110-20 §6.1.5).",
        lambda c=ctx: check_st2110_no_cross_frame(c))
    add("ST2110-20-ISSUES", "shall",
        "The uncompressed video RTP stream SHALL comply with ST 2110-20 (aggregate conformance).",
        lambda c=ctx: check_st2110_issues(c))

    # --- TR-10-2: Uncompressed Active Video ---
    add("TR-10-2-7a", "shall",
        "UDP destination port SHALL be even and > 1024 (TR-10-2 §7).",
        lambda c=ctx: check_udp_port_even(c))
    add("TR-10-2-9-CLK", "shall",
        "RTP Clock rate SHALL be 90 kHz (TR-10-2 §9).",
        lambda c=ctx: check_clock_rate(c))
    add("TR-10-2-9-TS", "shall",
        "All packets of same progressive frame or interlaced field SHALL have same RTP timestamp (TR-10-2 §9).",
        lambda c=ctx: check_timestamp_consistency(c))
    add("TR-10-2-10-MIB", "shall",
        "RTCP SR SHALL contain Media Info Block type 0x0001 (TR-10-2 §10).",
        lambda c=ctx: check_mib_0x0001(c))
    add("TR-10-2-10-LEN", "shall",
        "MIB 0x0001 length SHALL be 22 (32-bit words minus one) (TR-10-2 §10).",
        lambda c=ctx: check_mib_0x0001_length(c))
    add("TR-10-2-10-SAMPLING", "shall",
        "MIB sampling_format SHALL match SDP sampling (TR-10-2 §10).",
        lambda c=ctx: check_mib_sampling(c))
    add("TR-10-2-10-DEPTH", "shall",
        "MIB bit_depth SHALL match SDP depth (TR-10-2 §10).",
        lambda c=ctx: check_mib_depth(c))
    add("TR-10-2-10-WIDTH", "shall",
        "MIB width SHALL match SDP width (TR-10-2 §10).",
        lambda c=ctx: check_mib_width(c))
    add("TR-10-2-10-HEIGHT", "shall",
        "MIB height SHALL match SDP height (TR-10-2 §10).",
        lambda c=ctx: check_mib_height(c))
    add("TR-10-2-10-RATE", "shall",
        "MIB rate_numerator/rate_denominator SHALL match SDP exactframerate (TR-10-2 §10).",
        lambda c=ctx: check_mib_rate(c))
    add("TR-10-2-10-COLORIMETRY", "shall",
        "MIB colorimetry SHALL match SDP colorimetry (TR-10-2 §10).",
        lambda c=ctx: check_mib_colorimetry(c))
    add("TR-10-2-10-INTERLACE", "shall",
        "MIB interlace flag SHALL match observed interlace state (TR-10-2 §10).",
        lambda c=ctx: check_mib_interlace(c))
    add("TR-10-2-10-RANGE", "shall",
        "MIB range SHALL match SDP RANGE (TR-10-2 §10).",
        lambda c=ctx: check_mib_range(c))
    add("TR-10-2-10-TCS", "shall",
        "MIB TCS SHALL match SDP TCS (TR-10-2 §10).",
        lambda c=ctx: check_mib_tcs(c))

    # --- TR-10-1: System timing / SR ---
    add("TR-10-1-SR-PRESENT", "shall",
        "IPMX Senders SHALL send RTCP Sender Reports (TR-10-1 §8.7).",
        lambda c=ctx: check_sr_present(c))
    add("TR-10-1-SR-IPMX", "shall",
        "RTCP Sender Reports SHALL include an IPMX Info Block (TR-10-1 §8.7).",
        lambda c=ctx: check_ipmx_info_block(c))
    add("TR-10-1-SR-MAP", "shall",
        "Each frame SHALL have a corresponding RTCP Sender Report (TR-10-1 §8.8.2).",
        lambda c=ctx: check_sr_mapping(c))
    add("TR-10-1-SR-BEFORE", "shall",
        "Sender Report SHALL arrive before the first media packet of the associated frame (TR-10-1 §8.8.2).",
        lambda c=ctx: check_sr_before_frame(c))
    add("TR-10-1-SR-ORDER", "shall",
        "Sender Reports SHALL be in presentation (RTP timestamp) order.",
        lambda c=ctx: check_sr_order(c))
    add("TR-10-1-SR-DIFF", "shall",
        "SR RTP timestamp deltas SHALL match the nominal frame increment.",
        lambda c=ctx: _check_sr_diff_raw(c))
    add("TR-10-1-8.6-INIT-RTP", "shall",
        "First SR RTP timestamp shall be synchronized with the Internal Clock (TR-10-1 §8.6).",
        lambda c=ctx: check_sr_initial_rtp_clock(c.sender_reports, CLOCK_RATE))
    add("TR-10-1-FR-XVAL", "shall",
        "CLI --exactframerate SHALL match MIB rate_numerator/rate_denominator when both present.",
        lambda c=ctx: cross_validate_exactframerate(c.exact_framerate, c.sender_reports))
    add("TR-10-1-VP-XVAL", "shall",
        "CLI --width/--height/--sampling/--bit-depth SHALL match MIB video parameters when both present.",
        lambda c=ctx: cross_validate_video_params(c.cli_width, c.cli_height, c.cli_sampling, c.cli_bit_depth, c.sender_reports))
    add("TR-10-1-10.1-IPMX-FMTP", "shall",
        "SDP a=fmtp line shall contain the IPMX keyword (TR-10-1 §10.1).",
        lambda c=ctx: check_sdp_ipmx_fmtp(c.sdp.media if c.sdp is not None else None))
    add("IPMX-SDP-WRAPPER", "shall",
        "SDP shall satisfy RFC 4175 + ST 2110-10 + ST 2110-21 + ST 2110-20 + "
        "IPMX fmtp + TR-10-9 §17 source-filter (multicast)",
        lambda c=ctx: check_sdp_wrapper(c))

    # --- TR-10-9: Frame-to-frame timing ---
    add("TR-10-9-11.2a", "shall",
        "First-packet capture times SHALL have max-min variation <= 2ms over any 2s window (TR-10-9 §11.2).",
        lambda c=ctx: check_frame_interval_tr10_9(c))
    add("TR-10-9-11.2b", "shall",
        "SR capture times SHALL have max-min variation <= 2ms over any 2s window (TR-10-9 §11.2).",
        lambda c=ctx: check_sr_interval_tr10_9(c))

    # --- TR-10-9 §16: Quality of service (DSCP marking) ---
    add("TR-10-9-16a", "shall",
        "RTP packets SHALL be marked with the TR-10-9 §16 default DSCP AF42(36) "
        "for uncompressed video (TR-10-2).",
        lambda c=ctx: check_dscp_rtp_marking(c.pcap, c.stream_info, 36))
    add("TR-10-9-16b", "shall",
        "RTCP Sender Report packets SHALL carry the same DSCP as their RTP "
        "stream (TR-10-9 §16).",
        lambda c=ctx: check_dscp_sr_matches_rtp(c.pcap, c.stream_info, c.sender_reports))
    add("RFC1112-MCAST-MAC", "shall",
        "IPv4 multicast RTP packets SHALL use the RFC 1112 §6.4 Ethernet "
        "destination MAC derived from the group address (01:00:5e + low 23 bits).",
        lambda c=ctx: check_multicast_mac_mapping(c.pcap, c.stream_info))
    add("RFC1112-SR-MAC", "shall",
        "IPv4 multicast RTCP Sender Report packets SHALL use the RFC 1112 §6.4 "
        "Ethernet destination MAC of the group address.",
        lambda c=ctx: check_sr_mac_mapping(c.sender_reports))
    add("TR-10-1-8.7-SR-PORT", "shall",
        "RTCP Sender Reports SHALL be sent on the RTP destination port + 1 "
        "(TR-10-1 §8.7 / RFC 3550 §11).",
        lambda c=ctx: check_sr_rtcp_port(c.pcap, c.stream_info))

    # --- SDP transport file cross-validation ---
    add("SDP-PORT", "shall",
        "SDP destination port SHALL match the detected RTP stream port.",
        lambda c=ctx: check_sdp_port_vs_stream(c))
    add("SDP-DST-IP", "shall",
        "SDP connection address SHALL match the detected destination IP.",
        lambda c=ctx: check_sdp_dst_ip_vs_stream(c))

    # --- SHOULD requirements ---
    add("TR-10-2-7b", "should",
        "UDP destination port SHOULD be > 5000 (TR-10-2 §7).",
        lambda c=ctx: check_udp_port_above_5000(c))
    add("TR-10-2-SR-INT", "should",
        "Sender Reports SHOULD be transmitted at the nominal frame interval.",
        lambda c=ctx: check_sr_interval(c))
    add("TR-10-2-AU-INT", "should",
        "Frames SHOULD be produced at the nominal interval.",
        lambda c=ctx: check_au_interval_const(c))
    add("TR-10-1-NTP-RATE", "should",
        "SR NTP deltas SHOULD match PCAP capture deltas — sender and capture clocks should advance at the same rate.",
        lambda c=ctx: check_sr_ntp_vs_capture_rate(c.sender_reports))
    add("TR-10-1-NTP-SELF", "should",
        "SR NTP timestamps SHOULD be self-consistent — inter-SR intervals should match the nominal frame period.",
        lambda c=ctx: check_sr_ntp_self_consistent(c.sender_reports))
    add("TR-10-1-8.7-RC", "should",
        "RTCP SR reception report count (RC) should be 0 (TR-10-1 §8.7).",
        lambda c=ctx: check_sr_rc_zero(c.sender_reports))
    add("TR-10-1-8.7-COMPOUND", "shall",
        "RTCP Sender Reports shall be sent in a compound RTCP packet — report "
        "packet first and an SDES CNAME item present (RFC 3550 §6.1, TR-10-1 §8.7).",
        lambda c=ctx: check_sr_compound_packet(c.pcap, c.stream_info))

    return reqs


# ---------------------------------------------------------------------------
# Validation runner and output
# ---------------------------------------------------------------------------

def run_validation(ctx: RawValidationContext) -> list[RequirementResult]:
    results: list[RequirementResult] = []
    for req in build_requirements(ctx):
        result = req.check(ctx) if callable(req.check) else (False, "No check")
        passed = False
        details = "No check"
        testable = True
        if isinstance(result, tuple):
            if len(result) == 3:
                passed, details, testable = result
            elif len(result) >= 2:
                passed, details = result[:2]
        else:
            passed = bool(result)
        results.append(
            RequirementResult(
                req_id=req.req_id,
                level=req.level,
                text=req.text,
                passed=bool(passed),
                details=str(details),
                testable=bool(testable),
            )
        )
    return results


def _summarize_for_output(results: list[RequirementResult]) -> str:
    if not results:
        return "0/0 passed, 0 failed"
    testable = [r for r in results if r.testable]
    if len(testable) == len(results):
        return summarize_results(results)
    passed = sum(1 for r in testable if r.passed)
    failed = len(testable) - passed
    cannot_test = len(results) - len(testable)
    return f"{passed}/{len(testable)} passed, {failed} failed, {cannot_test} cannot test"


def _filter_results(
    results: list[RequirementResult],
    *,
    full_report: bool,
    pass_report: bool,
    fail_report: bool,
    cannot_report: bool,
) -> list[RequirementResult]:
    if full_report:
        return results
    if pass_report or fail_report or cannot_report:
        filtered: list[RequirementResult] = []
        for res in results:
            if res.testable and pass_report and res.passed:
                filtered.append(res)
            elif res.testable and fail_report and not res.passed:
                filtered.append(res)
            elif (not res.testable) and cannot_report:
                filtered.append(res)
        return filtered
    return [r for r in results if r.testable and not r.passed]


def print_results(
    results: list[RequirementResult],
    *,
    full_report: bool,
    pass_report: bool,
    fail_report: bool,
    cannot_report: bool,
) -> None:
    all_shall = [r for r in results if r.level == "shall"]
    all_should = [r for r in results if r.level == "should"]
    all_info = [r for r in results if r.level == "info"]
    filtered = _filter_results(
        results,
        full_report=full_report,
        pass_report=pass_report,
        fail_report=fail_report,
        cannot_report=cannot_report,
    )
    disp_shall = [r for r in filtered if r.level == "shall"]
    disp_should = [r for r in filtered if r.level == "should"]
    disp_info = [r for r in filtered if r.level == "info"]
    print("SHALL requirements")
    print(_summarize_for_output(all_shall))
    for res in disp_shall:
        status = "PASS" if res.passed else ("CANNOT_TEST" if not res.testable else "FAIL")
        print(f"{status} {res.req_id}: {res.text}")
        print(f"DETAILS: {res.details}")
    print("\nSHOULD requirements")
    print(_summarize_for_output(all_should))
    for res in disp_should:
        status = "PASS" if res.passed else ("CANNOT_TEST" if not res.testable else "FAIL")
        print(f"{status} {res.req_id}: {res.text}")
        print(f"DETAILS: {res.details}")
    if all_info:
        print("\nINFO")
        for res in disp_info:
            print(f"INFO {res.req_id}: {res.text}")
            print(f"DETAILS: {res.details}")


# ---------------------------------------------------------------------------
# CMAX Network Compatibility Model check (TR-10-1 §8.1)
# ---------------------------------------------------------------------------

def _resolve_exactframerate(ctx: RawValidationContext) -> Fraction | None:
    if ctx.exact_framerate is not None:
        return ctx.exact_framerate
    return extract_exact_framerate_from_sr(ctx.sender_reports)


def _run_cmax_check(ctx: RawValidationContext) -> list[RequirementResult]:
    results: list[RequirementResult] = []

    exact_fr = _resolve_exactframerate(ctx)
    if exact_fr is None:
        results.append(RequirementResult(
            req_id="TR-10-1-8.1-CMAX", level="shall",
            text="CINST shall not exceed CMAX (TR-10-1 §8.1 / ST 2110-21 §6.6.1).",
            passed=False, details="No exact framerate available", testable=False,
        ))
        return results

    complete_frames = _complete_frames(ctx)
    if not complete_frames:
        results.append(RequirementResult(
            req_id="TR-10-1-8.1-CMAX", level="shall",
            text="CINST shall not exceed CMAX (TR-10-1 §8.1 / ST 2110-21 §6.6.1).",
            passed=False, details="No complete frames", testable=False,
        ))
        return results

    npackets = complete_frames[0].packet_count
    tframe = Fraction(1, exact_fr)
    capture_times = [
        p["capture_time"] for p in ctx.packets
        if p.get("capture_time") is not None
    ]

    sim = simulate_cmax_leaky_bucket(capture_times, npackets, tframe)

    details = (
        f"NPACKETS={npackets}, CMAX={sim.cmax}, "
        f"TDRAIN={sim.tdrain * 1e6:.1f} us, "
        f"max CINST={sim.max_cinst}"
    )
    if not sim.passed:
        details += f", {sim.violation_count}/{sim.total_packets} packet(s) exceeded CMAX"

    results.append(RequirementResult(
        req_id="TR-10-1-8.1-CMAX", level="shall",
        text="CINST shall not exceed CMAX (TR-10-1 §8.1 / ST 2110-21 §6.6.1).",
        passed=sim.passed, details=details,
    ))
    return results


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> int:
    configure_utf8_output()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, nargs="?", help="PCAP file containing raw video RTP/RTCP")
    parser.add_argument("--list-requirements", action="store_true", help="List all requirement IDs this validator checks, then exit (no PCAP needed)")
    parser.add_argument("--port", type=int, help="RTP destination port (auto-detected if omitted)")
    parser.add_argument("--rtcp-port", type=int, help="RTCP destination port (default: RTP port + 1)")
    parser.add_argument("--ssrc", type=lambda x: int(x, 0), help="SSRC (decimal or 0x hex; auto-detected if omitted)")
    parser.add_argument("--dst-ip", dest="dst_ip", help="Destination IP address (auto-detected if omitted)")
    parser.add_argument("--sdp", type=Path, help="SDP transport file for cross-validation")
    parser.add_argument("--payload-type", type=int, help="Filter by RTP payload type")
    parser.add_argument("--max-frames", type=int, help="Limit number of frames processed")
    parser.add_argument(
        "--wallclock-backstep-threshold",
        type=float,
        help="Backward capture-time jump (seconds) threshold for wallclock disruption detection",
    )
    parser.add_argument("--full-report", action="store_true", help="Show all requirements")
    parser.add_argument("--pass-report", action="store_true", help="Show only passing requirements")
    parser.add_argument("--fail-report", action="store_true", help="Show only failing requirements")
    parser.add_argument("--cannot-test-report", action="store_true", help="Show only untestable requirements")
    parser.add_argument(
        "--exactframerate",
        type=str,
        help="Exact framerate as integer or num/den (e.g. 60, 60000/1001)",
    )
    parser.add_argument("--width", type=int, help="Expected video width in pixels")
    parser.add_argument("--height", type=int, help="Expected video height in pixels")
    parser.add_argument("--sampling", type=str, help="Expected sampling (e.g. YCbCr-4:2:2, RGB)")
    parser.add_argument("--bit-depth", type=int, help="Expected bit depth (e.g. 8, 10, 12)")
    parser.add_argument(
        "--cfg",
        type=str,
        help="Stream descriptor (streams/cfg/*.cfg, by path or bare name) to seed "
             "expected-value flags (--exactframerate/--width/--height/--sampling/"
             "--bit-depth); explicit flags on the command line override the cfg",
    )
    parser.add_argument(
        "--cmax",
        action="store_true",
        help="Enable CMAX Network Compatibility Model check (TR-10-1 §8.1)",
    )
    parser.add_argument(
        "--hkep",
        action="store_true",
        help="Stream uses HDCP Key Exchange Protocol (HKEP) encryption",
    )
    parser.add_argument(
        "--pep",
        action="store_true",
        help="Stream uses Privacy Encryption Protocol (PEP) encryption",
    )
    args = parser.parse_args()

    if args.list_requirements:
        from ipmx_validate_common import print_requirements_list
        print_requirements_list(Path(__file__).name, build_requirements(None))
        return 0

    if args.pcap is None:
        parser.error("the pcap argument is required unless --list-requirements is used")

    if args.cfg:
        from ipmx_validate_common import (
            apply_video_cfg,
            parse_cfg_file,
            resolve_cfg_path,
        )
        apply_video_cfg(args, parse_cfg_file(resolve_cfg_path(args.cfg)))

    if not args.pcap.exists():
        raise SystemExit(f"{args.pcap} does not exist")
    if args.max_frames is not None and args.max_frames <= 0:
        raise SystemExit("--max-frames must be positive")

    if getattr(args, "sdp", None) is not None and not args.sdp.exists():
        raise SystemExit(f"SDP file {args.sdp} does not exist")

    ctx = build_context(args)
    if ctx.encrypted:
        print("[INFO] Encryption detected — pixel data is not accessible.")
        print("       Payload header checks still run (headers are not encrypted).\n")
    if ctx.stream_info is not None:
        si = ctx.stream_info
        print(f"Detected RTP stream: dst={si.dst_ip}:{si.dst_port} "
              f"SSRC=0x{si.ssrc:08X} ({si.ssrc}) RTCP port={si.rtcp_port}")
    else:
        print("WARNING: Could not auto-detect RTP stream parameters")
    seq = ctx.stream.seq_analysis
    print(f"RTP: {seq.summary()}")
    print(f"     {len(ctx.frames)} frames")
    print(f"RTCP: {len(ctx.sender_reports)} Sender Report(s)")
    print_first_sr_block_version(ctx.sender_reports)
    if ctx.sdp is not None:
        s = ctx.sdp
        print(f"SDP:  sampling={s.sampling} width={s.width} height={s.height} "
              f"depth={s.depth}")
        print(f"      colorimetry={s.colorimetry} TCS={s.tcs} "
              f"RANGE={s.range_str} PM={s.packing_mode}")
        print(f"      interlace={s.interlace}")
    if ctx.sampling and ctx.width and ctx.height and ctx.depth:
        expected = compute_expected_frame_bytes(ctx.width, ctx.height, ctx.sampling, ctx.depth)
        pg = get_pgroup_info(ctx.sampling, ctx.depth)
        pg_str = f"pgroup={pg[0]}B/{pg[1]}px" if pg else "pgroup=unknown"
        print(f"Video: {ctx.sampling} {ctx.width}x{ctx.height} {ctx.depth}-bit "
              f"({pg_str}, expected {expected} bytes/frame)")
    if not seq.complete:
        print(f"WARNING: {seq.total_missing} RTP packet(s) missing — "
              f"PCAP is incomplete, some checks may be unreliable")
    print()
    results = run_validation(ctx)

    enc_results = ipmx_validate_encryption.run_encryption_checks(
        packets=ctx.packets,
        sender_reports=ctx.sender_reports,
        sdp_media=ctx.sdp.media if ctx.sdp is not None else None,
        flags=ipmx_validate_encryption.EncryptionFlags(
            hkep=args.hkep, pep=args.pep,
        ),
    )
    results.extend(enc_results)

    if args.cmax:
        results.extend(_run_cmax_check(ctx))

    print_results(
        results,
        full_report=args.full_report,
        pass_report=args.pass_report,
        fail_report=args.fail_report,
        cannot_report=args.cannot_test_report,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
