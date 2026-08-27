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
"""Validate an ST 2110-30 PCM RTP PCAP."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from MatroxSdp import MatroxSdp, MatroxSdpEnums, MediaDescriptor
from MatroxSdpCheck import (
    SdpCheckError,
    check_sdp_rfc3551,
    check_sdp_st2110_10,
    check_sdp_st2110_30,
)
from ipmx_pcm import (
    PcmStreamReport,
    analyze_pcm_packets,
    bit_depth_from_encoding,
    bytes_per_sample,
    encoding_name_for_depth,
    iter_selected_rtp_packets,
)
from ipmx_am824 import (
    compute_audio_sender_report_interval_packets,
    legal_ptimes_us,
    resolve_nominal_packet_time_us,
    resolve_packet_samples_per_packet,
)
from ipmx_validate_common import (
    Requirement,
    RequirementResult,
    SenderReportInfo,
    configure_utf8_output,
    check_dscp_rtp_marking,
    check_dscp_sr_matches_rtp,
    check_multicast_mac_mapping,
    check_sr_mac_mapping,
    check_sdp_ipmx_fmtp,
    check_sdp_multicast_source_filter,
    check_sdp_session_consistency,
    check_sr_initial_rtp_clock,
    check_sr_rc_zero,
    check_sr_compound_packet,
    parse_sender_reports,
    print_first_sr_block_version,
    summarize_results,
    untestable,
)
import ipmx_parse_rtp_pcap
import ipmx_validate_encryption

PCM_MIB_TYPE = 0x0002

_PCM_ENCODING_ENUMS = {
    MatroxSdpEnums.EncodingL16,
    MatroxSdpEnums.EncodingL20,
    MatroxSdpEnums.EncodingL24,
}


@dataclass
class PcmValidationContext:
    pcap: Path
    stream_info: ipmx_parse_rtp_pcap.RtpStreamInfo
    rtp_packets: list[ipmx_parse_rtp_pcap.RTPPacket]
    pcm_report: PcmStreamReport
    sdp_media: MediaDescriptor | None
    sender_reports: list[SenderReportInfo]
    cli_payload_type: int | None
    cli_sample_rate: int | None
    cli_nchan: int | None
    cli_ptime_us: int | None
    cli_channel_order: str | None
    cli_ssrc: int | None
    cli_port: int | None
    cli_dst_ip: str | None
    cli_rtcp_port: int | None
    cli_sample_size: int | None
    cli_measured_sample_rate: int | None
    cli_bit_depth: int | None
    expect_stream_start: bool
    resolved_payload_type: int | None
    resolved_sample_rate: int | None
    resolved_sample_size: int | None
    resolved_nchan: int | None
    resolved_ptime_us: int | None
    resolved_channel_order: str | None
    resolved_rtcp_port: int | None
    resolved_bit_depth: int | None
    encrypted: bool
    enc_flags: ipmx_validate_encryption.EncryptionFlags


def _enum_string(value: Any) -> str:
    return getattr(value, "s", str(value))


def _sdp_ts_refclk_string(media: MediaDescriptor) -> str:
    if media.ts_ref_clock_source is None:
        return ""
    source = _enum_string(media.ts_ref_clock_source)
    if not source:
        return ""
    if source == "localmac":
        return f"localmac={media.ts_ref_clock_local_mac_address}"
    if source == "ntp":
        return f"ntp={media.ts_ref_clock_ntp_address}"
    if source == "ptp":
        parts = [media.ts_ref_clock_ptp_version]
        if media.ts_ref_clock_ptp_traceable:
            parts.append("traceable")
        if media.ts_ref_clock_ptp_gmid:
            parts.append(media.ts_ref_clock_ptp_gmid)
        if media.ts_ref_clock_ptp_domain:
            parts.append(media.ts_ref_clock_ptp_domain)
        return "ptp=" + ":".join(part for part in parts if part)
    if source == "local":
        return "local"
    return source


def _sdp_mediaclk_string(media: MediaDescriptor) -> str:
    if media.media_clock_type is None:
        return ""
    clock_type = _enum_string(media.media_clock_type)
    if not clock_type:
        return ""
    if clock_type == "sender":
        return "sender"
    if clock_type == "direct":
        value = f"direct={media.media_clock_offset}"
        if media.media_clock_rate_numerator:
            value += f" rate={media.media_clock_rate_numerator}"
            if media.media_clock_rate_denominator not in (0, 1):
                value += f"/{media.media_clock_rate_denominator}"
        return value
    return clock_type


def parse_ptime_arg(value: str) -> int:
    try:
        milliseconds = Decimal(value)
    except InvalidOperation as exc:
        raise argparse.ArgumentTypeError(f"Invalid ptime '{value}'") from exc
    if milliseconds <= 0:
        raise argparse.ArgumentTypeError("ptime must be > 0 ms")
    microseconds = milliseconds * Decimal(1000)
    if microseconds != microseconds.to_integral_value():
        raise argparse.ArgumentTypeError("ptime must resolve to an integer number of microseconds")
    return int(microseconds)


def format_ptime_us(value: int | None) -> str:
    if value is None:
        return "unknown"
    milliseconds = Decimal(value) / Decimal(1000)
    return f"{milliseconds.normalize()} ms"


def load_sdp_media(path: Path) -> MediaDescriptor:
    sdp = MatroxSdp()
    err = sdp.decode(path.read_text(encoding="utf-8"))
    if err:
        raise SystemExit(f"SDP parse error: {err}")
    media = sdp.primary_media or (sdp.medias[0] if sdp.medias else None)
    if media is None:
        raise SystemExit("SDP contains no media descriptor")
    return media


def resolve_payload_type(
    cli_value: int | None,
    sdp_media: MediaDescriptor | None,
    report: PcmStreamReport,
) -> int | None:
    if cli_value is not None:
        return cli_value
    if sdp_media is not None and sdp_media.payload_type != 0:
        return sdp_media.payload_type
    if len(report.payload_type_set) == 1:
        return next(iter(report.payload_type_set))
    return None


def _resolve_bit_depth(
    cli_value: int | None,
    sdp_media: MediaDescriptor | None,
) -> int | None:
    if cli_value is not None:
        return cli_value
    if sdp_media is not None and sdp_media.encoding_name is not None:
        enc_str = _enum_string(sdp_media.encoding_name)
        try:
            return bit_depth_from_encoding(enc_str)
        except ValueError:
            pass
    return None


def build_context(args: argparse.Namespace) -> PcmValidationContext:
    stream_info = ipmx_parse_rtp_pcap.detect_rtp_stream(
        args.pcap,
        port=args.port,
        ssrc=args.ssrc,
        dst_ip=args.dst_ip,
    )
    packets = iter_selected_rtp_packets(args.pcap, stream_info=stream_info)
    if not packets:
        raise SystemExit("No RTP packets found for the selected stream")

    sdp_media = load_sdp_media(args.sdp) if args.sdp else None

    resolved_bit_depth = _resolve_bit_depth(args.bit_depth, sdp_media)
    resolved_nchan = args.nchan
    if resolved_nchan is None and sdp_media is not None:
        resolved_nchan = sdp_media.channels or None

    nchan_for_analysis = resolved_nchan or 2
    depth_for_analysis = resolved_bit_depth or 24

    report = analyze_pcm_packets(packets, nchan_for_analysis, depth_for_analysis)

    sender_reports = parse_sender_reports(
        args.pcap,
        args.rtcp_port,
        stream_info=stream_info,
        ssrc=args.ssrc,
    )

    resolved_payload_type = resolve_payload_type(args.payload_type, sdp_media, report)
    resolved_sample_rate = args.sample_rate
    if resolved_sample_rate is None and sdp_media is not None:
        resolved_sample_rate = sdp_media.sample_rate or None
    resolved_sample_size = args.sample_size
    if resolved_sample_size is None:
        mib_sizes: set[int] = set()
        for sr in sender_reports:
            for block in sr.raw_blocks:
                if block.media_info_type == PCM_MIB_TYPE and block.decoded is not None:
                    sz = block.decoded.get("sample_size")
                    if sz is not None:
                        mib_sizes.add(int(sz))
        if len(mib_sizes) == 1:
            resolved_sample_size = next(iter(mib_sizes))
    resolved_ptime_us = args.ptime
    if resolved_ptime_us is None and sdp_media is not None:
        resolved_ptime_us = sdp_media.p_time_us or None
    resolved_channel_order = args.channel_order
    if resolved_channel_order is None and sdp_media is not None and sdp_media.channel_order:
        resolved_channel_order = sdp_media.channel_order
    resolved_rtcp_port = args.rtcp_port
    if resolved_rtcp_port is None:
        resolved_rtcp_port = stream_info.rtcp_port

    enc_flags = ipmx_validate_encryption.EncryptionFlags(
        hkep=getattr(args, "hkep", False),
        pep=getattr(args, "pep", False),
    )
    first_ext = packets[0].ext_elements if packets else None
    encrypted = enc_flags.any_encryption or ipmx_validate_encryption.detect_encryption(first_ext)

    return PcmValidationContext(
        pcap=args.pcap,
        stream_info=stream_info,
        rtp_packets=packets,
        pcm_report=report,
        sdp_media=sdp_media,
        sender_reports=sender_reports,
        cli_payload_type=args.payload_type,
        cli_sample_rate=args.sample_rate,
        cli_nchan=args.nchan,
        cli_ptime_us=args.ptime,
        cli_channel_order=args.channel_order,
        cli_ssrc=args.ssrc,
        cli_port=args.port,
        cli_dst_ip=args.dst_ip,
        cli_rtcp_port=args.rtcp_port,
        cli_sample_size=args.sample_size,
        cli_measured_sample_rate=args.measured_sample_rate,
        cli_bit_depth=args.bit_depth,
        expect_stream_start=bool(args.expect_stream_start),
        resolved_payload_type=resolved_payload_type,
        resolved_sample_rate=resolved_sample_rate,
        resolved_sample_size=resolved_sample_size,
        resolved_nchan=resolved_nchan,
        resolved_ptime_us=resolved_ptime_us,
        resolved_channel_order=resolved_channel_order,
        resolved_rtcp_port=resolved_rtcp_port,
        resolved_bit_depth=resolved_bit_depth,
        encrypted=encrypted,
        enc_flags=enc_flags,
    )


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _timestamp_deltas(ctx: PcmValidationContext) -> list[int]:
    if len(ctx.rtp_packets) < 2:
        return []
    timestamps = [p.timestamp for p in ctx.rtp_packets]
    unwrapped: list[int] = []
    wraps = 0
    previous = timestamps[0]
    for value in timestamps:
        if value < previous and (previous - value) > 0x80000000:
            wraps += 1
        unwrapped.append(value + wraps * (1 << 32))
        previous = value
    return [cur - prev for prev, cur in zip(unwrapped, unwrapped[1:])]


def _resolved_packet_samples(ctx: PcmValidationContext) -> int | None:
    if ctx.resolved_sample_rate is None or ctx.resolved_ptime_us is None:
        return None
    return resolve_packet_samples_per_packet(
        ctx.resolved_sample_rate,
        ctx.resolved_ptime_us,
    )


def _audio_mib_blocks(ctx: PcmValidationContext) -> list[dict[str, object]]:
    blocks: list[dict[str, object]] = []
    for report in ctx.sender_reports:
        for block in report.raw_blocks:
            if block.media_info_type == PCM_MIB_TYPE and block.decoded is not None:
                blocks.append(block.decoded)
    return blocks


def _associate_sender_reports(
    ctx: PcmValidationContext,
) -> list[tuple[SenderReportInfo, int]]:
    timestamp_to_index: dict[int, int] = {}
    for index, packet in enumerate(ctx.rtp_packets):
        timestamp_to_index.setdefault(packet.timestamp, index)
    associations: list[tuple[SenderReportInfo, int]] = []
    for report in ctx.sender_reports:
        packet_index = timestamp_to_index.get(report.rtp_timestamp)
        if packet_index is not None:
            associations.append((report, packet_index))
    return associations


# ---------------------------------------------------------------------------
# RTP header checks
# ---------------------------------------------------------------------------

def check_encapsulation(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if not ctx.rtp_packets:
        return False, "No RTP packets selected"
    invalid = sum(1 for p in ctx.rtp_packets if p.version != 2)
    if invalid:
        return False, f"{invalid} packet(s) are not RTP version 2"
    if ctx.encrypted:
        return untestable(
            f"{len(ctx.rtp_packets)} RTP packets selected — "
            "PCM payload content cannot be validated on encrypted payloads"
        )
    return True, f"{len(ctx.rtp_packets)} RTP packets selected with valid PCM payloads"


def check_payload_type_constant(ctx: PcmValidationContext) -> tuple[bool, str]:
    if len(ctx.pcm_report.payload_type_set) != 1:
        return False, f"Multiple payload types observed: {sorted(ctx.pcm_report.payload_type_set)}"
    value = next(iter(ctx.pcm_report.payload_type_set))
    return True, f"RTP payload type is constant at {value}"


def check_ssrc_constant(ctx: PcmValidationContext) -> tuple[bool, str]:
    if len(ctx.pcm_report.ssrc_set) != 1:
        return False, f"Multiple SSRC values observed: {[f'0x{v:08X}' for v in sorted(ctx.pcm_report.ssrc_set)]}"
    value = next(iter(ctx.pcm_report.ssrc_set))
    return True, f"RTP SSRC is constant at 0x{value:08X}"


def check_csrc_zero(ctx: PcmValidationContext) -> tuple[bool, str]:
    offenders = [p.seq for p in ctx.rtp_packets if p.csrc_count != 0]
    if offenders:
        return False, f"{len(offenders)} packet(s) have non-zero CSRC count; first seq={offenders[0]}"
    return True, "CSRC count is 0 on all packets"


def check_marker_zero(ctx: PcmValidationContext) -> tuple[bool, str]:
    offenders = [p.seq for p in ctx.rtp_packets if p.marker]
    if offenders:
        return False, f"{len(offenders)} packet(s) set the marker bit; first seq={offenders[0]}"
    return True, "Marker bit is 0 on all packets"


def check_timestamp_step(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    deltas = _timestamp_deltas(ctx)
    if not deltas:
        return untestable("Not enough RTP packets to verify timestamp step")
    unique = sorted(set(deltas))
    if len(unique) != 1:
        return False, f"Observed multiple RTP timestamp deltas: {unique}"
    return True, f"All RTP timestamp deltas equal {unique[0]} sample periods"


def check_extension_state(ctx: PcmValidationContext) -> tuple[bool, str]:
    inconsistent = 0
    with_extension = 0
    for packet in ctx.rtp_packets:
        if packet.extension:
            with_extension += 1
        if not packet.extension and packet.ext_elements:
            inconsistent += 1
    if inconsistent:
        return False, f"{inconsistent} packet(s) expose extension elements without RTP extension bit"
    return True, f"RTP extension state is structurally consistent ({with_extension} packet(s) with X=1)"


# ---------------------------------------------------------------------------
# Payload checks
# ---------------------------------------------------------------------------

def check_payload_size(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.encrypted:
        return untestable("Payload encrypted — PCM payload size cannot be validated")
    if ctx.resolved_nchan is None or ctx.resolved_bit_depth is None:
        return untestable("nchan or bit depth unresolved — cannot verify payload size")
    expected_samples = _resolved_packet_samples(ctx)
    if expected_samples is None:
        return untestable("Cannot resolve samples per packet from sample rate and ptime")
    bps = bytes_per_sample(ctx.resolved_bit_depth)
    expected_bytes = expected_samples * ctx.resolved_nchan * bps
    sizes = ctx.pcm_report.payload_size_set
    if sizes != {expected_bytes}:
        return False, (
            f"Observed payload sizes {sorted(sizes)} do not match expected "
            f"{expected_bytes} bytes ({expected_samples} samples x {ctx.resolved_nchan} ch x {bps} B)"
        )
    return True, (
        f"All payloads are {expected_bytes} bytes "
        f"({expected_samples} samples x {ctx.resolved_nchan} ch x {bps} B)"
    )


def check_payload_alignment(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.encrypted:
        return untestable("Payload encrypted — PCM payload alignment cannot be validated")
    if ctx.resolved_nchan is None or ctx.resolved_bit_depth is None:
        return untestable("nchan or bit depth unresolved — cannot verify payload alignment")
    bps = bytes_per_sample(ctx.resolved_bit_depth)
    frame_bytes = ctx.resolved_nchan * bps
    bad: list[int] = []
    for report in ctx.pcm_report.packets:
        if frame_bytes > 0 and report.payload_bytes % frame_bytes != 0:
            bad.append(report.seq)
    if bad:
        return False, (
            f"{len(bad)} packet(s) have payloads not aligned to sample frame size "
            f"{frame_bytes}; first seq={bad[0]}"
        )
    return True, f"All payloads are aligned to {frame_bytes}-byte sample frames"


def check_payload_constant(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.encrypted:
        return untestable("Payload encrypted — PCM payload size constancy cannot be validated")
    sizes = ctx.pcm_report.payload_size_set
    if len(sizes) != 1:
        return False, f"Multiple payload sizes observed: {sorted(sizes)}"
    return True, f"Payload size is constant at {next(iter(sizes))} bytes"


# ---------------------------------------------------------------------------
# Timing checks
# ---------------------------------------------------------------------------

def check_sample_rate_legal(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.resolved_sample_rate is None:
        return untestable("Sample rate unresolved")
    if legal_ptimes_us(ctx.resolved_sample_rate) is None:
        return False, f"Resolved sample rate {ctx.resolved_sample_rate} is not one of 44100, 48000, 96000"
    return True, f"Resolved sample rate {ctx.resolved_sample_rate} Hz is legal for ST 2110-30"


def check_rtp_clock(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.resolved_sample_rate is None or ctx.resolved_ptime_us is None:
        return untestable("Sample rate or ptime unresolved")
    deltas = _timestamp_deltas(ctx)
    if not deltas:
        return untestable("Not enough RTP packets to verify RTP clock")
    expected = _resolved_packet_samples(ctx)
    if expected is None:
        return False, (
            f"ptime={format_ptime_us(ctx.resolved_ptime_us)} is not a supported signaling value "
            f"for sample_rate={ctx.resolved_sample_rate}"
        )
    bad = [d for d in deltas if d != expected]
    if bad:
        return False, f"Observed RTP timestamp deltas {sorted(set(bad))} do not match {expected}"
    return True, (
        f"RTP timestamp deltas match sample_rate={ctx.resolved_sample_rate} Hz and "
        f"ptime={format_ptime_us(ctx.resolved_ptime_us)} ({expected} samples/packet)"
    )


# ---------------------------------------------------------------------------
# SDP checks
# ---------------------------------------------------------------------------

def check_sdp_media(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.sdp_media is None:
        return untestable("No SDP provided")
    if ctx.sdp_media.type != MatroxSdpEnums.Audio:
        return False, f"SDP media type is {_enum_string(ctx.sdp_media.type)}, expected audio"
    return True, "SDP media type is audio"


def check_sdp_rtpmap(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.sdp_media is None:
        return untestable("No SDP provided")
    if ctx.sdp_media.encoding_name not in _PCM_ENCODING_ENUMS:
        return False, f"SDP encoding is {_enum_string(ctx.sdp_media.encoding_name)}, expected L16/L20/L24"
    if not ctx.sdp_media.sample_rate or not ctx.sdp_media.channels:
        return False, "SDP rtpmap is missing sample rate or channel count"
    enc = _enum_string(ctx.sdp_media.encoding_name)
    return True, f"SDP rtpmap declares {enc}/{ctx.sdp_media.sample_rate}/{ctx.sdp_media.channels}"


def check_sdp_nchan(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.sdp_media is None:
        return untestable("No SDP provided")
    if not ctx.sdp_media.channels or ctx.sdp_media.channels <= 0:
        return False, "SDP channels is missing or invalid"
    return True, f"SDP channels={ctx.sdp_media.channels}"


def check_sdp_ptime(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.sdp_media is None:
        return untestable("No SDP provided")
    if not ctx.sdp_media.p_time_us:
        return False, "SDP ptime is missing"
    return True, f"SDP ptime={format_ptime_us(ctx.sdp_media.p_time_us)}"


def check_sdp_ptime_legal(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.sdp_media is None:
        return untestable("No SDP provided")
    valid = legal_ptimes_us(ctx.sdp_media.sample_rate) if ctx.sdp_media.sample_rate else None
    if valid is None:
        return False, f"SDP sample rate {ctx.sdp_media.sample_rate} is invalid"
    if ctx.sdp_media.p_time_us not in valid:
        return False, (
            f"SDP ptime={format_ptime_us(ctx.sdp_media.p_time_us)} is not legal for "
            f"{ctx.sdp_media.sample_rate} Hz"
        )
    return True, f"SDP ptime={format_ptime_us(ctx.sdp_media.p_time_us)} is legal for {ctx.sdp_media.sample_rate} Hz"


def check_sdp_payload_match(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.sdp_media is None:
        return untestable("No SDP provided")
    if len(ctx.pcm_report.payload_type_set) != 1:
        return untestable("Observed RTP payload type is not constant")
    observed = next(iter(ctx.pcm_report.payload_type_set))
    if ctx.sdp_media.payload_type != observed:
        return False, f"SDP payload type {ctx.sdp_media.payload_type} != RTP payload type {observed}"
    return True, f"SDP payload type {ctx.sdp_media.payload_type} matches RTP"


def check_sdp_channel_order(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.sdp_media is None:
        return untestable("No SDP provided")
    if not ctx.sdp_media.channel_order:
        return untestable("SDP channel-order not present")
    if not ctx.sdp_media.channel_order.startswith("SMPTE2110."):
        return False, f"SDP channel-order '{ctx.sdp_media.channel_order}' does not use SMPTE2110. convention"
    return True, f"SDP channel-order '{ctx.sdp_media.channel_order}' uses SMPTE2110. convention"


def check_sdp_wrapper(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """Comprehensive SDP-side requirement for IPMX PCM streams.

    Mirrors the per-media-type checklist `TP-10/TP-10-1Sec13.2.py:195-232`
    runs for `audio/L*` (RFC 3551 + ST 2110-10 + ST 2110-30) and adds the
    project-local IPMX checks: the IPMX fmtp keyword (TR-10-1 §10.1) and
    the multicast source-filter signaling (TR-10-9 §17 / RFC 4570).
    First failure wins; on success the message is a one-line summary.
    """
    if ctx.sdp_media is None:
        return untestable("No SDP provided")
    try:
        check_sdp_rfc3551(ctx.sdp_media)
        check_sdp_st2110_10(ctx.sdp_media)
        check_sdp_st2110_30(ctx.sdp_media)
    except SdpCheckError as exc:
        return False, f"MatroxSdpCheck failed: {exc}"
    ok, msg, *tail = check_sdp_ipmx_fmtp(ctx.sdp_media)
    if not ok and (not tail or tail[0]):
        return False, msg
    sf = check_sdp_multicast_source_filter(ctx.sdp_media)
    sf_na = (len(sf) == 3 and not sf[2])
    if not sf_na and not sf[0]:
        return False, sf[1]
    sc = check_sdp_session_consistency(ctx.sdp_media)
    if not sc[0]:
        return False, sc[1]
    if sf_na:
        return True, (
            f"MatroxSdpCheck + IPMX fmtp + session consistency passed; "
            f"source-filter N/A ({sf[1]})"
        )
    return True, "MatroxSdpCheck + IPMX fmtp + source-filter + session consistency all passed"


# ---------------------------------------------------------------------------
# Sender Report checks
# ---------------------------------------------------------------------------

def check_sr_present(ctx: PcmValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No RTCP Sender Reports found for the selected stream"
    return True, f"Found {len(ctx.sender_reports)} RTCP Sender Report(s)"


def check_sr_port(ctx: PcmValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No RTCP Sender Reports found"
    expected = ctx.resolved_rtcp_port or ctx.stream_info.rtcp_port
    bad = [r.dst_port for r in ctx.sender_reports if r.dst_port != expected]
    if bad:
        return False, f"Observed RTCP destination ports {sorted(set(bad))} do not match expected {expected}"
    return True, f"All RTCP sender reports use destination port {expected}"


def check_sr_ip(ctx: PcmValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No RTCP Sender Reports found"
    expected = ctx.stream_info.dst_ip
    bad = [r.dst_ip for r in ctx.sender_reports if r.dst_ip != expected]
    if bad:
        return False, f"Observed RTCP destination IPs {sorted(set(bad))} do not match RTP dst_ip {expected}"
    return True, f"All RTCP sender reports use destination IP {expected}"


def check_sr_ssrc(ctx: PcmValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No RTCP Sender Reports found"
    expected_ssrc = ctx.stream_info.ssrc
    bad = [r for r in ctx.sender_reports if r.ssrc != expected_ssrc]
    if bad:
        return False, f"{len(bad)} RTCP SR(s) use SSRC values different from RTP SSRC 0x{expected_ssrc:08X}"
    return True, f"All RTCP SRs use RTP SSRC 0x{expected_ssrc:08X}"


def check_sr_ipmx_info(ctx: PcmValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No RTCP Sender Reports found"
    missing = [i for i, r in enumerate(ctx.sender_reports) if r.ipmx_info is None]
    if missing:
        return False, f"{len(missing)} RTCP SR(s) do not contain an IPMX Info Block"
    return True, "All RTCP SRs contain an IPMX Info Block"


def check_sr_ipmx_tag(ctx: PcmValidationContext) -> tuple[bool, str]:
    for index, report in enumerate(ctx.sender_reports):
        if report.ipmx_info is None:
            return False, f"RTCP SR #{index} is missing an IPMX Info Block"
        if report.ipmx_info.tag != 0x5831:
            return False, f"RTCP SR #{index} IPMX tag is 0x{report.ipmx_info.tag:04X}, expected 0x5831"
    return True, "All RTCP SR IPMX tags are 0x5831"


def check_sr_block_version(ctx: PcmValidationContext) -> tuple[bool, str]:
    versions = {r.ipmx_info.version for r in ctx.sender_reports if r.ipmx_info is not None}
    if not versions:
        return False, "No RTCP SR IPMX Info Blocks found"
    if len(versions) != 1:
        return False, f"Observed multiple IPMX Info Block versions: {sorted(versions)}"
    return True, f"Observed stable IPMX Info Block version {next(iter(versions))}"


def check_sr_reserved(ctx: PcmValidationContext) -> tuple[bool, str]:
    for index, report in enumerate(ctx.sender_reports):
        if report.ipmx_info is None:
            return False, f"RTCP SR #{index} is missing an IPMX Info Block"
        if report.ipmx_info.reserved != 0:
            return False, f"RTCP SR #{index} IPMX reserved field is 0x{report.ipmx_info.reserved:06X}"
    return True, "All RTCP SR IPMX reserved fields are zero"


def check_sr_first(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if not ctx.expect_stream_start:
        return untestable("--expect-stream-start not set")
    associations = _associate_sender_reports(ctx)
    if not associations:
        return False, "No SR/RTP associations found"
    if associations[0][1] != 0:
        return False, f"First associated SR maps to RTP packet index {associations[0][1]}, expected 0"
    return True, "First RTP packet has an associated RTCP Sender Report"


def check_sr_every_n(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.resolved_sample_rate is None or ctx.resolved_ptime_us is None:
        return untestable("Sample rate or ptime unresolved")
    interval_packets = compute_audio_sender_report_interval_packets(
        ctx.resolved_sample_rate,
        ctx.resolved_ptime_us,
    )
    if interval_packets is None:
        return untestable("Resolved sample rate / ptime do not map to a supported audio SR interval")
    associations = _associate_sender_reports(ctx)
    if not associations:
        return False, "No SR/RTP associations found"
    observed = [pkt_idx for _, pkt_idx in associations]
    if ctx.expect_stream_start:
        expected = list(range(0, len(ctx.rtp_packets), interval_packets))[:len(observed)]
        if observed != expected:
            return False, f"Observed SR packet indexes {observed[:10]} do not match expected {expected[:10]}"
        return True, f"SRs occur at packet indexes 0, {interval_packets}, 2*{interval_packets}, ..."
    deltas = [cur - prev for prev, cur in zip(observed, observed[1:])]
    if any(d != interval_packets for d in deltas):
        return False, f"Observed SR packet-index deltas {sorted(set(deltas))} != expected {interval_packets}"
    return True, f"Successive SR associations are spaced by {interval_packets} RTP packets"


def check_sr_rtp_timestamp_map(ctx: PcmValidationContext) -> tuple[bool, str]:
    associations = _associate_sender_reports(ctx)
    if not associations:
        return False, "No SR/RTP associations found"
    for report, pkt_idx in associations:
        if report.rtp_timestamp != ctx.rtp_packets[pkt_idx].timestamp:
            return False, (
                f"SR rtp_timestamp={report.rtp_timestamp} does not match associated RTP packet timestamp "
                f"{ctx.rtp_packets[pkt_idx].timestamp}"
            )
    return True, "Each SR RTP timestamp matches its associated RTP packet"


def check_sr_before(ctx: PcmValidationContext) -> tuple[bool, str]:
    associations = _associate_sender_reports(ctx)
    if not associations:
        return False, "No SR/RTP associations found"
    for report, pkt_idx in associations:
        packet = ctx.rtp_packets[pkt_idx]
        if packet.capture_time is None or report.capture_time > packet.capture_time:
            return False, f"SR for RTP packet index {pkt_idx} does not arrive before the packet"
    return True, "Each SR arrives before its associated RTP packet"


def check_sr_after_previous(ctx: PcmValidationContext) -> tuple[bool, str]:
    associations = _associate_sender_reports(ctx)
    if len(associations) < 2:
        return True, "Fewer than two SRs present"
    prev_report, prev_pkt_idx = associations[0]
    prev_packet = ctx.rtp_packets[prev_pkt_idx]
    for report, pkt_idx in associations[1:]:
        packet = ctx.rtp_packets[pkt_idx]
        if report.capture_time <= prev_report.capture_time:
            return False, "An SR does not arrive after the previous SR"
        if prev_packet.capture_time is None or report.capture_time <= prev_packet.capture_time:
            return False, "An SR does not arrive after the previous associated RTP packet"
        prev_report = report
        prev_packet = packet
    return True, "Each SR arrives after the previous SR and previous associated RTP packet"


def check_sr_order(ctx: PcmValidationContext) -> tuple[bool, str]:
    associations = _associate_sender_reports(ctx)
    observed = [pkt_idx for _, pkt_idx in associations]
    if observed != sorted(observed):
        return False, f"SR associations are out of order: {observed}"
    return True, "SR associations follow RTP packet order"


def check_sr_counts(ctx: PcmValidationContext) -> tuple[bool, str]:
    associations = _associate_sender_reports(ctx)
    if not associations:
        return False, "No SR/RTP associations found"
    cumulative_octets = 0
    octets_by_packet: list[int] = []
    for packet in ctx.rtp_packets:
        cumulative_octets += len(packet.payload)
        octets_by_packet.append(cumulative_octets)

    # The SR packet/octet counters are cumulative from the start of the RTP
    # stream (RFC 3550 §6.4.1: "total number ... since starting transmission"),
    # which may precede the start of the capture when the PCAP begins
    # mid-stream. Anchor the counter offset on the first captured SR rather
    # than assuming the capture begins at stream packet 1, then require every
    # subsequent SR to be consistent with that same offset. This keeps the
    # cross-SR increment invariant verifiable on partial captures (analogous to
    # trimming boundary frames in the video validators) while still absorbing
    # the 0-based-vs-1-based counter convention. The octet expectation stays
    # tied to pkt_offset * payload_size, so packet/octet mutual consistency is
    # still enforced (this identity holds for both counter conventions and for
    # mid-stream offsets, given the constant PCM payload size).
    first_report, first_idx = associations[0]
    pkt_offset = first_report.packet_count - (first_idx + 1)

    payload_size = len(ctx.rtp_packets[0].payload) if ctx.rtp_packets else 0

    for report, pkt_idx in associations:
        expected_pkt_count = pkt_idx + 1 + pkt_offset
        expected_octet_count = octets_by_packet[pkt_idx] + pkt_offset * payload_size
        if report.packet_count != expected_pkt_count:
            return False, (
                f"SR for packet index {pkt_idx} reports packet_count={report.packet_count}, "
                f"expected {expected_pkt_count}"
            )
        if report.octet_count != expected_octet_count:
            return False, (
                f"SR for packet index {pkt_idx} reports octet_count={report.octet_count}, "
                f"expected {expected_octet_count}"
            )
    if pkt_offset == 0:
        basis = "1-based, capture from stream start"
    elif pkt_offset == -1:
        basis = "0-based, capture from stream start"
    else:
        basis = f"consistent counter offset {pkt_offset:+d} (capture started mid-stream)"
    return True, f"SR packet_count and octet_count match cumulative RTP payload counters ({basis})"


# ---------------------------------------------------------------------------
# MIB checks
# ---------------------------------------------------------------------------

def check_mib_type(ctx: PcmValidationContext) -> tuple[bool, str]:
    blocks = _audio_mib_blocks(ctx)
    if not blocks:
        return False, f"No PCM audio MIB type 0x{PCM_MIB_TYPE:04X} present in RTCP sender reports"
    return True, f"Found {len(blocks)} PCM audio MIB block(s) of type 0x{PCM_MIB_TYPE:04X}"


def check_mib_count(ctx: PcmValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No RTCP Sender Reports found"
    for index, report in enumerate(ctx.sender_reports):
        audio_blocks = [b for b in report.raw_blocks if b.media_info_type in {0x0002, 0x0004}]
        if not audio_blocks:
            return False, f"RTCP SR #{index} does not contain any audio MIB"
        if any(b.media_info_type != PCM_MIB_TYPE for b in audio_blocks):
            return False, f"RTCP SR #{index} contains a non-PCM audio MIB type"
    return True, f"All RTCP SR audio MIBs are PCM type 0x{PCM_MIB_TYPE:04X}"


def check_mib_format(ctx: PcmValidationContext) -> tuple[bool, str]:
    blocks = _audio_mib_blocks(ctx)
    if not blocks:
        return False, "No PCM audio MIB present"
    required = {"sampling_rate", "sample_size", "channel_count", "packet_time", "measured_sample_rate", "channel_order"}
    for block in blocks:
        if required - set(block):
            return False, f"PCM audio MIB is missing fields: {sorted(required - set(block))}"
    return True, "PCM audio MIBs decode using the PCM-audio layout"


def check_mib_sampling_rate(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.resolved_sample_rate is None:
        return untestable("Sample rate unresolved")
    blocks = _audio_mib_blocks(ctx)
    if not blocks:
        return False, "No PCM audio MIB present"
    values = {int(b["sampling_rate"]) for b in blocks}
    if values != {ctx.resolved_sample_rate}:
        return False, f"MIB sampling_rate values {sorted(values)} do not match expected {ctx.resolved_sample_rate}"
    return True, f"All MIB sampling_rate values match {ctx.resolved_sample_rate}"


def check_mib_sample_size(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.cli_sample_size is None:
        return untestable("No --sample-size provided")
    blocks = _audio_mib_blocks(ctx)
    if not blocks:
        return False, "No PCM audio MIB present"
    values = {int(b["sample_size"]) for b in blocks}
    if values != {ctx.cli_sample_size}:
        return False, f"MIB sample_size values {sorted(values)} do not match CLI {ctx.cli_sample_size}"
    return True, f"All MIB sample_size values match CLI {ctx.cli_sample_size}"


def check_mib_channels(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.resolved_nchan is None:
        return untestable("nchan unresolved")
    blocks = _audio_mib_blocks(ctx)
    if not blocks:
        return False, "No PCM audio MIB present"
    values = {int(b["channel_count"]) for b in blocks}
    if values != {ctx.resolved_nchan}:
        return False, f"MIB channel_count values {sorted(values)} do not match expected {ctx.resolved_nchan}"
    return True, f"All MIB channel_count values match {ctx.resolved_nchan}"


def check_mib_packet_time(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.resolved_sample_rate is None or ctx.resolved_ptime_us is None:
        return untestable("Sample rate or ptime unresolved")
    expected = resolve_nominal_packet_time_us(ctx.resolved_sample_rate, ctx.resolved_ptime_us)
    if expected is None:
        return untestable("Resolved ptime does not map to a nominal packet-time bucket")
    blocks = _audio_mib_blocks(ctx)
    if not blocks:
        return False, "No PCM audio MIB present"
    values = {int(b["packet_time"]) for b in blocks}
    if values != {expected}:
        return False, f"MIB packet_time values {sorted(values)} do not match expected {expected}"
    return True, f"All MIB packet_time values match nominal {expected} us"


def check_mib_measured_sample_rate(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    expected = ctx.cli_measured_sample_rate
    if expected is None and ctx.sdp_media is not None and ctx.sdp_media.measured_sample_rate:
        expected = int(ctx.sdp_media.measured_sample_rate)
    if expected is None:
        return untestable("Measured sample rate unresolved")
    blocks = _audio_mib_blocks(ctx)
    if not blocks:
        return False, "No PCM audio MIB present"
    values = {int(b["measured_sample_rate"]) for b in blocks}
    if values != {expected}:
        return False, f"MIB measured_sample_rate values {sorted(values)} do not match expected {expected}"
    return True, f"All MIB measured_sample_rate values match {expected}"


def check_mib_channel_order(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    expected = ctx.resolved_channel_order
    if expected is None:
        return untestable("Channel-order unresolved")
    blocks = _audio_mib_blocks(ctx)
    if not blocks:
        return False, "No PCM audio MIB present"
    values = {str(b["channel_order"]) for b in blocks}
    if values != {expected}:
        return False, f"MIB channel_order values {sorted(values)} do not match expected '{expected}'"
    return True, f"All MIB channel_order values match '{expected}'"


# ---------------------------------------------------------------------------
# SDP / SR cross-validation
# ---------------------------------------------------------------------------

def check_sdp_ts_refclk(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.sdp_media is None:
        return untestable("No SDP provided")
    if not ctx.sender_reports or ctx.sender_reports[0].ipmx_info is None:
        return untestable("No SR IPMX Info Block available")
    expected = _sdp_ts_refclk_string(ctx.sdp_media)
    observed = ctx.sender_reports[0].ipmx_info.ts_refclk
    if expected != observed:
        return False, f"SR ts_refclk='{observed}' != SDP ts-refclk='{expected}'"
    return True, "SR ts_refclk matches SDP"


def check_sdp_mediaclk(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.sdp_media is None:
        return untestable("No SDP provided")
    if not ctx.sender_reports or ctx.sender_reports[0].ipmx_info is None:
        return untestable("No SR IPMX Info Block available")
    expected = _sdp_mediaclk_string(ctx.sdp_media)
    observed = ctx.sender_reports[0].ipmx_info.mediaclk
    if expected != observed:
        return False, f"SR mediaclk='{observed}' != SDP mediaclk='{expected}'"
    return True, "SR mediaclk matches SDP"


def check_sdp_measured_sample_rate(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.sdp_media is None:
        return untestable("No SDP provided")
    if not ctx.sdp_media.measured_sample_rate:
        return untestable("SDP measuredsamplerate not present")
    blocks = _audio_mib_blocks(ctx)
    if not blocks:
        return False, "No PCM audio MIB present"
    values = {int(b["measured_sample_rate"]) for b in blocks}
    expected = int(ctx.sdp_media.measured_sample_rate)
    if values != {expected}:
        return False, f"MIB measured_sample_rate values {sorted(values)} do not match SDP {expected}"
    return True, f"MIB measured_sample_rate matches SDP {expected}"


# ---------------------------------------------------------------------------
# CLI cross-validation
# ---------------------------------------------------------------------------

def check_cli_payload_type(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.cli_payload_type is None:
        return untestable("No --payload-type provided")
    if len(ctx.pcm_report.payload_type_set) != 1:
        return False, f"Observed RTP payload types are not constant: {sorted(ctx.pcm_report.payload_type_set)}"
    observed = next(iter(ctx.pcm_report.payload_type_set))
    if observed != ctx.cli_payload_type:
        return False, f"CLI payload_type={ctx.cli_payload_type} != RTP payload type {observed}"
    return True, f"CLI payload_type={ctx.cli_payload_type} matches RTP"


def check_cli_ssrc(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.cli_ssrc is None:
        return untestable("No --ssrc provided")
    if len(ctx.pcm_report.ssrc_set) != 1:
        return False, f"Observed SSRCs are not constant: {[f'0x{v:08X}' for v in sorted(ctx.pcm_report.ssrc_set)]}"
    observed = next(iter(ctx.pcm_report.ssrc_set))
    if observed != ctx.cli_ssrc:
        return False, f"CLI ssrc=0x{ctx.cli_ssrc:08X} != RTP SSRC 0x{observed:08X}"
    return True, f"CLI ssrc=0x{ctx.cli_ssrc:08X} matches RTP"


def check_cli_sample_rate(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.cli_sample_rate is None:
        return untestable("No --sample-rate provided")
    details = [f"CLI sample_rate={ctx.cli_sample_rate}"]
    validated = False
    if ctx.sdp_media is not None:
        if ctx.sdp_media.sample_rate != ctx.cli_sample_rate:
            return False, f"CLI sample_rate={ctx.cli_sample_rate} != SDP sample_rate={ctx.sdp_media.sample_rate}"
        details.append("matches SDP")
        validated = True
    blocks = _audio_mib_blocks(ctx)
    if blocks:
        mib_values = {int(b["sampling_rate"]) for b in blocks}
        if mib_values != {ctx.cli_sample_rate}:
            return False, f"CLI sample_rate={ctx.cli_sample_rate} != MIB sampling_rate values {sorted(mib_values)}"
        details.append("matches MIB")
        validated = True
    if not validated:
        return untestable("No SDP or MIB context available to cross-validate --sample-rate")
    return True, ", ".join(details)


def check_cli_nchan(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.cli_nchan is None:
        return untestable("No --nchan provided")
    if ctx.cli_nchan <= 0:
        return False, f"CLI nchan={ctx.cli_nchan} is invalid"
    if ctx.sdp_media is not None and ctx.sdp_media.channels != ctx.cli_nchan:
        return False, f"CLI nchan={ctx.cli_nchan} != SDP channels={ctx.sdp_media.channels}"
    blocks = _audio_mib_blocks(ctx)
    if blocks:
        mib_values = {int(b["channel_count"]) for b in blocks}
        if mib_values != {ctx.cli_nchan}:
            return False, f"CLI nchan={ctx.cli_nchan} != MIB channel_count values {sorted(mib_values)}"
    detail = f"CLI nchan={ctx.cli_nchan} matches payload geometry"
    if ctx.sdp_media is not None:
        detail += " and SDP"
    return True, detail


def check_cli_ptime(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.cli_ptime_us is None:
        return untestable("No --ptime provided")
    validated = False
    if ctx.sdp_media is not None and ctx.sdp_media.p_time_us != ctx.cli_ptime_us:
        return False, f"CLI ptime={format_ptime_us(ctx.cli_ptime_us)} != SDP ptime={format_ptime_us(ctx.sdp_media.p_time_us)}"
    if ctx.sdp_media is not None:
        validated = True
    if ctx.resolved_sample_rate is not None:
        expected_nominal = resolve_nominal_packet_time_us(ctx.resolved_sample_rate, ctx.cli_ptime_us)
        blocks = _audio_mib_blocks(ctx)
        if expected_nominal is not None and blocks:
            mib_values = {int(b["packet_time"]) for b in blocks}
            if mib_values != {expected_nominal}:
                return False, (
                    f"CLI ptime={format_ptime_us(ctx.cli_ptime_us)} maps to nominal {expected_nominal} us, "
                    f"but MIB packet_time values are {sorted(mib_values)}"
                )
            validated = True
    if ctx.resolved_sample_rate is None:
        if validated:
            return True, f"CLI ptime={format_ptime_us(ctx.cli_ptime_us)} matches SDP"
        return untestable("Sample rate unresolved — cannot verify RTP timing from --ptime")
    expected = resolve_packet_samples_per_packet(ctx.resolved_sample_rate, ctx.cli_ptime_us)
    if expected is None:
        return False, (
            f"CLI ptime={format_ptime_us(ctx.cli_ptime_us)} is not supported for "
            f"sample_rate={ctx.resolved_sample_rate}"
        )
    deltas = _timestamp_deltas(ctx)
    if deltas and any(d != expected for d in deltas):
        return False, (
            f"CLI ptime={format_ptime_us(ctx.cli_ptime_us)} with sample_rate={ctx.resolved_sample_rate} "
            f"implies {expected} samples/packet, observed deltas={sorted(set(deltas))}"
        )
    if deltas:
        validated = True
    detail = f"CLI ptime={format_ptime_us(ctx.cli_ptime_us)}"
    if ctx.sdp_media is not None:
        detail += " matches SDP"
    if deltas:
        detail += f" and RTP timing ({expected} samples/packet)"
    if not validated:
        return untestable("No SDP or RTP timing context available to cross-validate --ptime")
    return True, detail


def check_cli_channel_order(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.cli_channel_order is None:
        return untestable("No --channel-order provided")
    validated = False
    if ctx.sdp_media is not None:
        if ctx.sdp_media.channel_order != ctx.cli_channel_order:
            return False, f"CLI channel-order='{ctx.cli_channel_order}' != SDP channel-order='{ctx.sdp_media.channel_order}'"
        validated = True
    blocks = _audio_mib_blocks(ctx)
    if blocks:
        mib_values = {str(b["channel_order"]) for b in blocks}
        if mib_values != {ctx.cli_channel_order}:
            return False, f"CLI channel-order='{ctx.cli_channel_order}' != MIB channel_order values {sorted(mib_values)}"
        validated = True
    if not validated:
        return untestable("No SDP or MIB available — cannot cross-validate --channel-order")
    return True, f"CLI channel-order='{ctx.cli_channel_order}' matches expected metadata"


def check_cli_port(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.cli_port is None:
        return untestable("No --port provided")
    if ctx.stream_info.dst_port != ctx.cli_port:
        return False, f"CLI port={ctx.cli_port} != selected RTP dst_port={ctx.stream_info.dst_port}"
    return True, f"CLI port={ctx.cli_port} matches selected RTP stream"


def check_cli_dst_ip(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.cli_dst_ip is None:
        return untestable("No --dst-ip provided")
    if ctx.stream_info.dst_ip != ctx.cli_dst_ip:
        return False, f"CLI dst-ip={ctx.cli_dst_ip} != selected RTP dst_ip={ctx.stream_info.dst_ip}"
    return True, f"CLI dst-ip={ctx.cli_dst_ip} matches selected RTP stream"


def check_cli_rtcp_port(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.cli_rtcp_port is None:
        return untestable("No --rtcp-port provided")
    if ctx.resolved_rtcp_port != ctx.cli_rtcp_port:
        return False, f"CLI rtcp-port={ctx.cli_rtcp_port} != selected RTCP port {ctx.resolved_rtcp_port}"
    return True, f"CLI rtcp-port={ctx.cli_rtcp_port} matches selected RTCP stream"


def check_cli_sample_size(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    return check_mib_sample_size(ctx)


def check_cli_measured_sample_rate(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.cli_measured_sample_rate is None:
        return untestable("No --measured-sample-rate provided")
    blocks = _audio_mib_blocks(ctx)
    if not blocks:
        return False, "No PCM audio MIB present"
    values = {int(b["measured_sample_rate"]) for b in blocks}
    if values != {ctx.cli_measured_sample_rate}:
        return False, f"MIB measured_sample_rate values {sorted(values)} do not match CLI {ctx.cli_measured_sample_rate}"
    if ctx.sdp_media is not None and ctx.sdp_media.measured_sample_rate:
        if int(ctx.sdp_media.measured_sample_rate) != ctx.cli_measured_sample_rate:
            return False, (
                f"CLI measured-sample-rate={ctx.cli_measured_sample_rate} != "
                f"SDP measuredsamplerate={ctx.sdp_media.measured_sample_rate}"
            )
    return True, f"CLI measured-sample-rate={ctx.cli_measured_sample_rate} matches MIB"


def check_cli_bit_depth(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.cli_bit_depth is None:
        return untestable("No --bit-depth provided")
    if ctx.sdp_media is not None and ctx.sdp_media.encoding_name is not None:
        enc_str = _enum_string(ctx.sdp_media.encoding_name)
        try:
            sdp_depth = bit_depth_from_encoding(enc_str)
            if sdp_depth != ctx.cli_bit_depth:
                return False, f"CLI bit-depth={ctx.cli_bit_depth} != SDP encoding {enc_str} ({sdp_depth}-bit)"
        except ValueError:
            pass
    return True, f"CLI bit-depth={ctx.cli_bit_depth} matches SDP encoding"


# ---------------------------------------------------------------------------
# SHOULD-level checks
# ---------------------------------------------------------------------------

def check_sequence_continuity(ctx: PcmValidationContext) -> tuple[bool, str]:
    analysis = ctx.pcm_report.sequence_analysis
    if analysis.total_missing or analysis.total_duplicates:
        return False, analysis.summary()
    return True, analysis.summary()


def check_capture_interval_stability(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    # AES67 §7.5 SHOULD: variation from nominal transmission time ≤ 1 packet time
    if len(ctx.rtp_packets) < 3:
        return untestable("Not enough packets to assess capture interval stability")
    if ctx.resolved_ptime_us is None:
        return untestable("ptime unresolved — cannot assess capture interval stability")
    times = [p.capture_time for p in ctx.rtp_packets if p.capture_time is not None]
    if len(times) < 3:
        return untestable("Capture timestamps unavailable")
    expected = ctx.resolved_ptime_us / 1_000_000.0
    deltas = [cur - prev for prev, cur in zip(times, times[1:])]
    max_error = max(abs(d - expected) for d in deltas)
    if max_error > expected:
        return False, f"Capture interval variation {max_error*1000:.3f} ms exceeds AES67 §7.5 SHOULD ≤ 1·ptime ({expected*1000:.3f} ms)"
    return True, f"Capture intervals stable within AES67 §7.5 SHOULD ≤ 1·ptime ({expected*1000:.3f} ms)"


def check_capture_interval_aes67_shall(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    # AES67 §7.5 SHALL: variation from nominal transmission time ≤ min(17·ptime, 17 ms)
    if len(ctx.rtp_packets) < 3:
        return untestable("Not enough packets to assess capture interval stability")
    if ctx.resolved_ptime_us is None:
        return untestable("ptime unresolved — cannot assess capture interval stability")
    times = [p.capture_time for p in ctx.rtp_packets if p.capture_time is not None]
    if len(times) < 3:
        return untestable("Capture timestamps unavailable")
    expected = ctx.resolved_ptime_us / 1_000_000.0
    shall = min(17 * expected, 0.017)
    deltas = [cur - prev for prev, cur in zip(times, times[1:])]
    max_error = max(abs(d - expected) for d in deltas)
    if max_error > shall:
        return False, f"Capture interval variation {max_error*1000:.3f} ms exceeds AES67 §7.5 SHALL ≤ min(17·ptime, 17 ms) ({shall*1000:.3f} ms)"
    return True, f"Capture intervals within AES67 §7.5 SHALL ≤ min(17·ptime, 17 ms) ({shall*1000:.3f} ms)"


# ---------------------------------------------------------------------------
# Requirement list
# ---------------------------------------------------------------------------

def check_sdp_dst_ip_vs_stream_pcm(ctx: PcmValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    from ipmx_validate_common import check_sdp_dst_ip_vs_stream as _check
    return _check(ctx.sdp_media, ctx.stream_info)


def build_requirements() -> list[Requirement]:
    reqs: list[Requirement] = []

    def add(req_id: str, level: str, text: str, fn: Any) -> None:
        reqs.append(Requirement(req_id=req_id, level=level, text=text, check=fn))

    add("ST2110-30-5.1-ENCAP", "shall", "Selected packets shall be RTP packets carrying valid PCM payloads", check_encapsulation)
    add("ST2110-30-5.1-PT", "shall", "RTP payload type shall be constant within the stream", check_payload_type_constant)
    add("ST2110-30-5.1-SSRC", "shall", "RTP SSRC shall be constant within the stream", check_ssrc_constant)
    add("ST2110-30-5.1-CC", "shall", "RTP CSRC count shall be 0", check_csrc_zero)
    add("ST2110-30-5.1-M", "shall", "RTP marker bit shall be 0", check_marker_zero)
    add("ST2110-30-5.1-TS", "shall", "RTP timestamp step shall match the packet sample-period count", check_timestamp_step)
    add("ST2110-30-5.1-X", "shall", "RTP extension/header state shall be structurally consistent", check_extension_state)
    add("ST2110-30-PAYLOAD-SIZE", "shall", "PCM payload size shall equal nchan x bytes_per_sample x samples_per_packet", check_payload_size)
    add("ST2110-30-PAYLOAD-ALIGN", "shall", "PCM payload shall be aligned to sample frame boundaries", check_payload_alignment)
    add("ST2110-30-PAYLOAD-CONST", "shall", "PCM payload size shall be constant across all packets", check_payload_constant)
    add("ST2110-30-5.1-RATE", "shall", "Resolved sample rate shall be legal for ST 2110-30", check_sample_rate_legal)
    add("ST2110-30-5.1-RTPCLOCK", "shall", "RTP clock shall match sample-rate and ptime relationship", check_rtp_clock)
    add("ST2110-30-6.1-MEDIA", "shall", "SDP media type shall be audio", check_sdp_media)
    add("ST2110-30-6.1-RTPMAP", "shall", "SDP rtpmap shall declare L16/L20/L24 with rate and nchan", check_sdp_rtpmap)
    add("ST2110-30-6.1-NCHAN", "shall", "SDP nchan shall be present and valid", check_sdp_nchan)
    add("ST2110-30-6.1-PTIME", "shall", "SDP ptime shall be present", check_sdp_ptime)
    add("ST2110-30-6.1-PTIME-LEGAL", "shall", "SDP ptime shall be legal for the SDP sample rate", check_sdp_ptime_legal)
    add("ST2110-30-6.1-PT-MATCH", "shall", "SDP payload type shall match the RTP stream", check_sdp_payload_match)
    add("ST2110-30-6.2-CHORDER", "shall", "SDP channel-order shall follow the ST 2110 convention when present", check_sdp_channel_order)
    add("IPMX-SDP-WRAPPER", "shall",
        "SDP shall satisfy RFC 3551 + ST 2110-10 + ST 2110-30 + IPMX fmtp + "
        "TR-10-9 §17 source-filter (multicast)",
        check_sdp_wrapper)
    add("SDP-DST-IP", "shall",
        "SDP connection address SHALL match the detected destination IP.",
        check_sdp_dst_ip_vs_stream_pcm)
    add("TR-10-9-16a", "shall",
        "IPMX Senders conforming to TR-10-3 (PCM audio) shall mark RTP packets "
        "with the TR-10-9 §16 default DSCP AF41(34).",
        lambda c: check_dscp_rtp_marking(c.pcap, c.stream_info, 34))
    add("TR-10-9-16b", "shall",
        "IPMX Senders shall mark outgoing RTCP Sender Report packets with the "
        "same DSCP value as the respective RTP stream packets (TR-10-9 §16).",
        lambda c: check_dscp_sr_matches_rtp(c.pcap, c.stream_info, c.sender_reports))
    add("RFC1112-MCAST-MAC", "shall",
        "IPv4 multicast RTP packets SHALL use the RFC 1112 §6.4 Ethernet "
        "destination MAC derived from the group address (01:00:5e + low 23 bits).",
        lambda c: check_multicast_mac_mapping(c.pcap, c.stream_info))
    add("RFC1112-SR-MAC", "shall",
        "IPv4 multicast RTCP Sender Report packets SHALL use the RFC 1112 §6.4 "
        "Ethernet destination MAC of the group address.",
        lambda c: check_sr_mac_mapping(c.sender_reports))
    add("TR-10-1-8.7-SR-PRESENT", "shall", "RTCP Sender Reports shall be present", check_sr_present)
    add("TR-10-1-8.7-SR-IP", "shall", "RTCP Sender Reports shall use the same destination IP as RTP", check_sr_ip)
    add("TR-10-1-8.7-SR-PORT", "shall", "RTCP Sender Reports shall use the expected RTCP destination port", check_sr_port)
    add("TR-10-1-8.7-SSRC", "shall", "RTCP Sender Report SSRC shall match RTP SSRC", check_sr_ssrc)
    add("TR-10-1-8.7-IPMXINFO", "shall", "RTCP Sender Reports shall include the IPMX Info Block", check_sr_ipmx_info)
    add("TR-10-1-8.7-IPMXTAG", "shall", "RTCP Sender Report IPMX tag shall be 0x5831", check_sr_ipmx_tag)
    add("TR-10-1-8.7-BLOCKVER", "shall", "RTCP Sender Report IPMX block version shall be stable", check_sr_block_version)
    add("TR-10-1-8.7-RESERVED", "shall", "RTCP Sender Report IPMX reserved bits shall be zero", check_sr_reserved)
    add("TR-10-1-8.10.1-FIRST", "shall", "The first RTP packet shall have an associated SR when stream start is expected", check_sr_first)
    add("TR-10-1-8.10.1-EVERY-N", "shall", "Audio SRs shall occur on the required packet interval", check_sr_every_n)
    add("TR-10-1-8.10.1-RTPMAP", "shall", "Each audio SR shall map to the associated RTP timestamp", check_sr_rtp_timestamp_map)
    add("TR-10-1-8.10.1-BEFORE", "shall", "Each audio SR shall arrive before its associated RTP packet", check_sr_before)
    add("TR-10-1-8.10.1-AFTER-PREV", "shall", "Each audio SR shall arrive after the previous SR and associated RTP packet", check_sr_after_previous)
    add("TR-10-1-8.10.1-ORDER", "shall", "Audio SRs shall follow RTP packet order", check_sr_order)
    add("TR-10-1-8.10.1-COUNTS", "shall", "Audio SR packet/octet counters shall match cumulative RTP counts", check_sr_counts)
    add("TR-10-3-MIB-TYPE", "shall", "PCM audio transport shall use MIB type 0x0002", check_mib_type)
    add("TR-10-3-MIB-COUNT", "shall", "Generated audio sender reports shall carry PCM audio MIBs", check_mib_count)
    add("TR-10-3-MIB-FMT", "shall", "PCM audio MIBs shall decode using the PCM-audio layout", check_mib_format)
    add("TR-10-3-MIB-SAMPLERATE", "shall", "PCM audio MIB sampling rate shall match the expected sample rate", check_mib_sampling_rate)
    add("TR-10-3-MIB-SAMPLESIZE", "shall", "PCM audio MIB sample size shall match the expected sample size", check_mib_sample_size)
    add("TR-10-3-MIB-CHANNELS", "shall", "PCM audio MIB channel count shall match nchan", check_mib_channels)
    add("TR-10-3-MIB-PACKETTIME", "shall", "PCM audio MIB packet_time shall match the nominal packet time", check_mib_packet_time)
    add("TR-10-3-MIB-MEASURED", "shall", "PCM audio MIB measured sample rate shall match the expected value", check_mib_measured_sample_rate)
    add("TR-10-3-MIB-CHORDER", "shall", "PCM audio MIB channel_order shall match the expected value", check_mib_channel_order)
    add("TR-10-1-8.7-TSREFCLK", "shall", "SR ts-refclk shall match SDP", check_sdp_ts_refclk)
    add("TR-10-1-8.7-MEDIACLK", "shall", "SR mediaclk shall match SDP", check_sdp_mediaclk)
    add("TR-10-1-8.6-INIT-RTP", "shall",
        "First SR RTP timestamp shall be synchronized with the Internal Clock (TR-10-1 §8.6).",
        lambda c: check_sr_initial_rtp_clock(c.sender_reports, c.resolved_sample_rate or 48000))
    add("TR-10-1-8.7-RC", "should",
        "RTCP SR reception report count (RC) should be 0 (TR-10-1 §8.7).",
        lambda c: check_sr_rc_zero(c.sender_reports))
    add("TR-10-1-8.7-COMPOUND", "shall",
        "RTCP Sender Reports shall be sent in a compound RTCP packet — report "
        "packet first and an SDES CNAME item present (RFC 3550 §6.1, TR-10-1 §8.7).",
        lambda c: check_sr_compound_packet(c.pcap, c.stream_info))
    add("TR-10-1-10.1-IPMX-FMTP", "shall",
        "SDP a=fmtp line shall contain the IPMX keyword (TR-10-1 §10.1).",
        lambda c: check_sdp_ipmx_fmtp(c.sdp_media))
    add("TR-10-1-10.3-MEASUREDSAMPLERATE", "shall", "MIB measured sample rate shall match SDP measuredsamplerate", check_sdp_measured_sample_rate)
    add("PCM-CLI-PT", "shall", "CLI --payload-type shall match the RTP stream when provided", check_cli_payload_type)
    add("PCM-CLI-SSRC", "shall", "CLI --ssrc shall match the RTP stream when provided", check_cli_ssrc)
    add("PCM-CLI-SAMPLE-RATE", "shall", "CLI --sample-rate shall match SDP and RTP timing when provided", check_cli_sample_rate)
    add("PCM-CLI-NCHAN", "shall", "CLI --nchan shall match SDP and payload geometry when provided", check_cli_nchan)
    add("PCM-CLI-PTIME", "shall", "CLI --ptime shall match SDP and RTP timing when provided", check_cli_ptime)
    add("PCM-CLI-CHORDER", "shall", "CLI --channel-order shall match SDP when provided", check_cli_channel_order)
    add("PCM-CLI-PORT", "shall", "CLI --port shall match the selected RTP stream when provided", check_cli_port)
    add("PCM-CLI-RTCP-PORT", "shall", "CLI --rtcp-port shall match the selected RTCP stream when provided", check_cli_rtcp_port)
    add("PCM-CLI-DST-IP", "shall", "CLI --dst-ip shall match the selected RTP stream when provided", check_cli_dst_ip)
    add("PCM-CLI-SAMPLESIZE", "shall", "CLI --sample-size shall match the SR audio MIB when provided", check_cli_sample_size)
    add("PCM-CLI-MEASURED-SR", "shall", "CLI --measured-sample-rate shall match the SR audio MIB when provided", check_cli_measured_sample_rate)
    add("PCM-CLI-BITDEPTH", "shall", "CLI --bit-depth shall match the SDP encoding name when provided", check_cli_bit_depth)
    add("RTP-SEQ", "should", "RTP sequence numbers should be contiguous", check_sequence_continuity)
    add("RTP-CAPTURE-PTIME", "should",
        "AES67 §7.5 SHOULD: sender variation from nominal transmission time should be ≤ 1 packet time",
        check_capture_interval_stability)
    add("AES67-7.5-PTIME-SHALL", "shall",
        "AES67 §7.5: sender variation from nominal transmission time shall be ≤ min(17·ptime, 17 ms)",
        check_capture_interval_aes67_shall)
    return reqs


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def run_requirements(ctx: PcmValidationContext, requirements: list[Requirement]) -> list[RequirementResult]:
    results: list[RequirementResult] = []
    for requirement in requirements:
        outcome = requirement.check(ctx)
        if len(outcome) == 2:
            passed, details = outcome
            testable = True
        else:
            passed, details, testable = outcome
        results.append(
            RequirementResult(
                req_id=requirement.req_id,
                level=requirement.level,
                text=requirement.text,
                passed=passed,
                details=details,
                testable=testable,
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
        for r in results:
            if r.testable and pass_report and r.passed:
                filtered.append(r)
            elif r.testable and fail_report and not r.passed:
                filtered.append(r)
            elif (not r.testable) and cannot_report:
                filtered.append(r)
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
    filtered = _filter_results(
        results,
        full_report=full_report,
        pass_report=pass_report,
        fail_report=fail_report,
        cannot_report=cannot_report,
    )
    display_shall = [r for r in filtered if r.level == "shall"]
    display_should = [r for r in filtered if r.level == "should"]

    print("SHALL requirements")
    print(_summarize_for_output(all_shall))
    for r in display_shall:
        status = "PASS" if r.passed else ("CANNOT_TEST" if not r.testable else "FAIL")
        print(f"{status} {r.req_id}: {r.text}")
        print(f"DETAILS: {r.details}")

    print("\nSHOULD requirements")
    print(_summarize_for_output(all_should))
    for r in display_should:
        status = "PASS" if r.passed else ("CANNOT_TEST" if not r.testable else "FAIL")
        print(f"{status} {r.req_id}: {r.text}")
        print(f"DETAILS: {r.details}")


def main() -> int:
    configure_utf8_output()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, nargs="?", help="PCAP file containing PCM RTP")
    parser.add_argument("--list-requirements", action="store_true", help="List all requirement IDs this validator checks, then exit (no PCAP needed)")
    parser.add_argument("--port", type=int, help="RTP destination port (auto-detected if omitted)")
    parser.add_argument("--ssrc", type=lambda v: int(v, 0), help="Expected SSRC (decimal or 0x hex)")
    parser.add_argument("--dst-ip", dest="dst_ip", help="Expected destination IP address")
    parser.add_argument("--payload-type", type=int, help="Expected RTP payload type")
    parser.add_argument("--sdp", type=Path, help="SDP transport file for cross-validation")
    parser.add_argument("--sample-rate", type=int, help="Expected PCM sample rate in Hz")
    parser.add_argument("--nchan", type=int, help="Expected channel count")
    parser.add_argument("--ptime", type=parse_ptime_arg, help="Expected packet time in milliseconds (e.g. 1, 0.33, 0.12)")
    parser.add_argument("--channel-order", type=str, help="Expected SDP channel-order value")
    parser.add_argument("--rtcp-port", type=int, help="Expected RTCP destination port")
    parser.add_argument("--sample-size", type=int, help="Expected SR audio MIB sample size")
    parser.add_argument("--measured-sample-rate", type=int, help="Expected SR audio MIB measured sample rate")
    parser.add_argument("--bit-depth", type=int, choices=[16, 20, 24], help="PCM bit depth (16, 20, or 24)")
    parser.add_argument(
        "--expect-stream-start",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Require the first RTP packet to have an associated SR (on by default; "
             "use --no-expect-stream-start for captures that begin mid-stream)",
    )
    parser.add_argument("--hkep", action="store_true", help="Assert that HDCP encryption (HKEP) is active")
    parser.add_argument("--pep", action="store_true", help="Assert that Privacy Encryption Protocol (PEP) is active")
    parser.add_argument("--full-report", action="store_true", help="Include all requirements (pass, fail, cannot test)")
    parser.add_argument("--pass-report", action="store_true", help="Show only passing requirements")
    parser.add_argument("--fail-report", action="store_true", help="Show only failing requirements")
    parser.add_argument("--cannot-test-report", action="store_true", help="Show only requirements that cannot be tested")
    parser.add_argument(
        "--cfg",
        type=str,
        help="Stream descriptor (streams/cfg/*.cfg, by path or bare name) to seed "
             "expected-value flags (--sample-rate/--nchan/--ptime/--bit-depth/"
             "--sample-size); explicit flags on the command line override the cfg",
    )
    args = parser.parse_args()

    if args.list_requirements:
        from ipmx_validate_common import print_requirements_list
        print_requirements_list(Path(__file__).name, build_requirements())
        return 0

    if args.pcap is None:
        parser.error("the pcap argument is required unless --list-requirements is used")

    if args.cfg:
        from ipmx_validate_common import (
            apply_audio_cfg,
            parse_cfg_file,
            resolve_cfg_path,
        )
        apply_audio_cfg(args, parse_cfg_file(resolve_cfg_path(args.cfg)), parse_ptime_arg)

    ctx = build_context(args)

    if ctx.encrypted:
        print("[INFO] Encryption detected — PCM payload content is not accessible.")
        print("       Payload-level checks will be marked as untestable.\n")

    print_first_sr_block_version(ctx.sender_reports)

    results = run_requirements(ctx, build_requirements())

    packets_as_dicts = [{"ext_elements": pkt.ext_elements} for pkt in ctx.rtp_packets]
    enc_results = ipmx_validate_encryption.run_encryption_checks(
        packets=packets_as_dicts,
        sender_reports=ctx.sender_reports,
        sdp_media=ctx.sdp_media,
        flags=ctx.enc_flags,
    )
    results.extend(enc_results)

    print_results(
        results,
        full_report=args.full_report,
        pass_report=args.pass_report,
        fail_report=args.fail_report,
        cannot_report=args.cannot_test_report,
    )

    shall_failures = [r for r in results if r.level == "shall" and r.testable and not r.passed]
    return 1 if shall_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
