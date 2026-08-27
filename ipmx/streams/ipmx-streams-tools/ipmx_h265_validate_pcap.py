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
"""Validate an H.265 IPMX PCAP against VSF TR-10-15b requirements."""

from __future__ import annotations

import argparse
import base64
import sys
from pathlib import Path
from typing import Any

from fractions import Fraction

import ipmx_parse_rtp_pcap
import ipmx_validate_encryption
import ipmx_validate_hrd
import ipmx_validate_hrd_subpic
from MatroxSdp import MatroxSdp, MatroxSdpEnums, MediaDescriptor
from MatroxSdpCheck import (
    SdpCheckError,
    check_sdp_rfc7798,
    check_sdp_st2110_10,
    check_sdp_st2110_22,
)
from ipmx_validate_common import (
    AccessUnit,
    RtpReport,
    CLOCK_RATE,
    Requirement,
    RequirementResult,
    ValidationContext,
    configure_utf8_output,
    build_rtp_report,
    build_timeline,
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
    cross_validate_interlace,
    cross_validate_video_params,
    extract_interlace_from_sr,
    extract_video_params_from_sr,
    filter_capture_boundary_orphan_srs,
    apply_recovery_point_window,
    print_recovery_window_note,
    get_int_field,
    compute_sr_prefix_length,
    infer_rtp_port,
    interval_variation_in_window,
    nominal_ticks_per_period_from_seconds,
    parse_exactframerate_arg,
    parse_sender_reports,
    print_first_sr_block_version,
    rate_matches,
    resolve_exact_ticks_per_frame,
    run_cmax_hrd_check,
    summarize_results,
    untestable,
    unwrap_rtp_timestamps,
    walk_trace_pairs,
)

H265_INFO_FIELD_BITS = {
    "profile_space": 0,
    "profile_id": 1,
    "level_id": 2,
    "tier_flag": 3,
    "profile_compatibility_indicator": 4,
    "interop_constraints": 5,
    "sprop_max_don_diff": 6,
    "tx_mode": 7,
    "sprop_depack_buf_bytes": 8,
    "sprop_depack_buf_nalus": 9,
    "sprop_spatial_segmentation_idc": 10,
    "sprop_sub_layer_id": 11,
    "sprop_segmentation_id": 12,
    "sprop_vps": 13,
    "sprop_sps": 14,
    "sprop_pps": 15,
    "extra_bytes": 16,
}

H265_RA_TYPES = {16, 17, 18, 19, 20, 21}
BUFFERING_PERIOD_FIELDS = {"bp_seq_parameter_set_id", "irap_cpb_params_present_flag"}
PIC_TIMING_FIELDS = {"au_cpb_removal_delay_minus1", "pic_dpb_output_delay"}
RECOVERY_POINT_FIELDS = {"recovery_poc_cnt"}
DECODING_UNIT_INFO_FIELDS = {"decoding_unit_idx", "du_spt_cpb_removal_delay_increment"}

TRACE_NAL_TYPES = {32, 33, 34, 39, 40}

NAL_TO_HDR_H265 = {
    32: "VPS",
    33: "SPS",
    34: "PPS",
    39: "SEI",  # SEI_PREFIX
    40: "SEI",  # SEI_SUFFIX
}
PIXCLK_TOLERANCE_PPM = 100


def _detect_sei_types_from_fields(fields: dict[str, Any]) -> set[str]:
    """Detect which SEI message types are present from parsed ffmpeg trace fields.

    A single SEI NAL may carry multiple messages; last_payload_type_byte only
    reflects the last one.  We identify types by their characteristic fields.
    """
    found: set[str] = set()
    keys = set(fields.keys())
    if keys & BUFFERING_PERIOD_FIELDS:
        found.add("buffering_period")
    if keys & PIC_TIMING_FIELDS:
        found.add("pic_timing")
    if keys & RECOVERY_POINT_FIELDS:
        found.add("recovery_point")
    if keys & DECODING_UNIT_INFO_FIELDS:
        found.add("decoding_unit_info")
    return found


def _build_au_sei_map(
    report: RtpReport,
    raw_headers: list[dict[str, Any]],
    lossy_timestamps: set[int] | None = None,
) -> tuple[dict[int, set[str]], set[int]]:
    """Map each AU RTP timestamp to the set of SEI types found by the ffmpeg trace.

    The trace emits headers only for VPS/SPS/PPS/SEI NALs, in the same order
    they appear in the elementary stream written from nalus_bytes.  We walk
    nalus_meta in parallel with raw_headers to correlate each trace entry back
    to its AU timestamp.

    Returns ``(sei_map, traced_timestamps)`` where *traced_timestamps* is the
    set of AU RTP timestamps that were covered by the trace (regardless of
    whether they contained SEIs).
    """
    sei_map: dict[int, set[str]] = {}
    traced_ts: set[int] = set()
    for meta, header in walk_trace_pairs(
        report, raw_headers, NAL_TO_HDR_H265, skip_timestamps=lossy_timestamps
    ):
        ts = int(meta["timestamp"])
        traced_ts.add(ts)
        if header.get("type") != "SEI":
            continue
        sei_types = _detect_sei_types_from_fields(header.get("fields", {}))
        sei_map.setdefault(ts, set()).update(sei_types)
    return sei_map, traced_ts


def parse_h265_media_info(payload: bytes) -> dict[str, Any]:
    if len(payload) < 40:
        return {"error": "payload too short"}
    data: dict[str, Any] = {}
    data["mask"] = int.from_bytes(payload[0:4], "big")
    data["profile_space"] = payload[4]
    data["profile_id"] = payload[5]
    data["level_id"] = payload[6]
    data["tier_flag"] = payload[7]
    data["profile_compatibility_indicator"] = int.from_bytes(payload[8:12], "big")
    data["interop_constraints"] = payload[12:18]
    data["sprop_max_don_diff"] = int.from_bytes(payload[18:20], "big")
    data["tx_mode"] = payload[20:24]
    data["sprop_depack_buf_bytes"] = int.from_bytes(payload[24:28], "big")
    data["sprop_depack_buf_nalus"] = int.from_bytes(payload[28:30], "big")
    data["sprop_spatial_segmentation_idc"] = int.from_bytes(payload[30:32], "big")
    data["sprop_sub_layer_id"] = payload[32]
    data["sprop_segmentation_id"] = payload[33]
    data["reserved"] = payload[34:36]
    data["sprop_vps_len"] = payload[36]
    data["sprop_sps_len"] = payload[37]
    data["sprop_pps_len"] = payload[38]
    data["extra_len"] = payload[39]
    cursor = 40
    vps_len = data["sprop_vps_len"]
    sps_len = data["sprop_sps_len"]
    pps_len = data["sprop_pps_len"]
    extra_len = data["extra_len"]
    data["sprop_vps"] = payload[cursor : cursor + vps_len]
    cursor += vps_len
    data["sprop_sps"] = payload[cursor : cursor + sps_len]
    cursor += sps_len
    data["sprop_pps"] = payload[cursor : cursor + pps_len]
    cursor += pps_len
    data["extra_bytes"] = payload[cursor : cursor + extra_len]
    cursor += extra_len
    data["padding"] = payload[cursor:]
    return data


def _is_interlaced(ctx: ValidationContext) -> bool | None:
    """Determine interlace status: CLI > MIB > None (unknown)."""
    if ctx.interlace is not None:
        return ctx.interlace
    return extract_interlace_from_sr(ctx.sender_reports)


def load_sdp_hevc_params(sdp_path: Path) -> MediaDescriptor:
    """Parse an SDP file and return the media descriptor for H.265."""
    sdp = MatroxSdp()
    err = sdp.decode(sdp_path.read_text())
    if err:
        raise SystemExit(f"SDP parse error: {err}")
    md = sdp.primary_media
    if md is None:
        raise SystemExit("SDP contains no media descriptor")
    if md.encoding_name != MatroxSdpEnums.EncodingH265:
        raise SystemExit(
            f"SDP encoding is '{md.encoding_name}', expected 'H265'"
        )
    return md


def build_context(args: argparse.Namespace) -> ValidationContext:
    si = ipmx_parse_rtp_pcap.detect_rtp_stream(
        args.pcap,
        port=args.port,
        ssrc=getattr(args, "ssrc", None),
        dst_ip=getattr(args, "dst_ip", None),
    )
    rtp_port = si.dst_port if si else args.port
    if rtp_port is None:
        rtp_port = infer_rtp_port(args.pcap, "h265")
    rtp_report = build_rtp_report(
        args.pcap,
        "h265",
        rtp_port,
        args.max_access_units,
        args.wallclock_backstep_threshold,
        stream_info=si,
    )
    sender_reports = parse_sender_reports(args.pcap, args.rtcp_port, stream_info=si)
    sr_prefix = compute_sr_prefix_length(rtp_report, sender_reports)
    if sr_prefix is not None:
        rtp_report = build_rtp_report(
            args.pcap,
            "h265",
            rtp_port,
            sr_prefix,
            args.wallclock_backstep_threshold,
            stream_info=si,
        )
        au_ts = {au.timestamp for au in rtp_report.access_units}
        sender_reports = [sr for sr in sender_reports if sr.rtp_timestamp in au_ts]
    timeline = build_timeline(rtp_report, "h265", args.frames)
    # Restrict AU-based checks to the cleanly-validatable window (first
    # recovery point .. last marker-complete AU). Done AFTER build_timeline so
    # HRD trace correlation still sees the full AU/NAL stream.
    apply_recovery_point_window(rtp_report)

    exact_fr: Fraction | None = None
    if getattr(args, "exactframerate", None):
        exact_fr = parse_exactframerate_arg(args.exactframerate)

    interlace_flag: bool | None = None
    if getattr(args, "interlace", None) is not None:
        interlace_flag = args.interlace

    sdp_media: MediaDescriptor | None = None
    if getattr(args, "sdp", None) is not None:
        sdp_media = load_sdp_hevc_params(args.sdp)

    return ValidationContext(
        pcap=args.pcap,
        codec="h265",
        rtp_report=rtp_report,
        sender_reports=sender_reports,
        timeline=timeline,
        exact_framerate=exact_fr,
        interlace=interlace_flag,
        width=getattr(args, "width", None),
        height=getattr(args, "height", None),
        sampling=getattr(args, "sampling", None),
        bit_depth=getattr(args, "bit_depth", None),
        sdp_media=sdp_media,
        stream_info=si,
        encrypted=rtp_report.encrypted,
        allow_superset_profile=getattr(args, "allow_superset_profile", False),
        is_444=getattr(args, "is_444", False),
    )


def find_media_block(sr_info, block_type: int) -> Any:
    if sr_info.ipmx_info is None:
        return None
    for block in sr_info.ipmx_info.media_blocks:
        if block.media_info_type == block_type:
            return block
    return None


def collect_param_sets(report: ValidationContext) -> dict[str, list[bytes]]:
    vps = []
    sps = []
    pps = []
    for nalu in report.rtp_report.nalus_bytes:
        if nalu.startswith(b"\x00\x00\x00\x01"):
            payload = nalu[4:]
        else:
            payload = nalu
        if len(payload) < 2:
            continue
        nal_type = (payload[0] & 0x7E) >> 1
        if nal_type == 32:
            vps.append(payload)
        elif nal_type == 33:
            sps.append(payload)
        elif nal_type == 34:
            pps.append(payload)
    return {"vps": vps, "sps": sps, "pps": pps}


def decode_base64_sets(value: bytes) -> list[bytes]:
    if not value:
        return []
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError:
        return [value]
    parts = [part.strip() for part in text.split(",") if part.strip()]
    if not parts:
        return []
    decoded: list[bytes] = []
    for part in parts:
        try:
            decoded.append(base64.b64decode(part, validate=True))
        except Exception:
            return [value]
    return decoded


def _remove_emulation_prevention_bytes(data: bytes) -> bytes:
    """Strip emulation prevention bytes (0x00 0x00 0x03 → 0x00 0x00) from RBSP."""
    out = bytearray()
    i = 0
    while i < len(data):
        if (
            i + 2 < len(data)
            and data[i] == 0
            and data[i + 1] == 0
            and data[i + 2] == 3
        ):
            out.append(0)
            out.append(0)
            i += 3
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


def _reverse_bits_32(n: int) -> int:
    """Reverse the 32 bits of an integer.

    The SPS bitstream stores general_profile_compatibility_flag[j] at bit (31-j)
    when read as a big-endian 32-bit value (flag[0] is MSB).  The MIB stores it
    as a big-endian integer with flag[j] at bit j (standard integer convention).
    This function converts between the two representations.
    """
    result = 0
    for i in range(32):
        result = (result << 1) | ((n >> i) & 1)
    return result


def parse_h265_sps_profile_tier_level(sps_nalu: bytes) -> dict[str, Any] | None:
    """Extract profile_tier_level fields from a raw H.265 SPS NAL unit.

    EPBs are stripped first, then the RBSP is parsed:
      byte 0:  vps_id(4) | max_sub_layers_minus1(3) | temporal_nesting(1)
      byte 1:  general_profile_space(2) | general_tier_flag(1) | general_profile_idc(5)
      bytes 2–5:  general_profile_compatibility_flag[32]
      bytes 6–11: general constraint indicator flags (48 bits)
      byte 12: general_level_idc

    The profile_compatibility_indicator is returned in the MIB convention
    (flag[j] at bit j, big-endian integer), not the raw SPS bitstream layout.
    """
    MIN_SPS_BYTES = 2 + 13
    if len(sps_nalu) < MIN_SPS_BYTES:
        return None
    rbsp = _remove_emulation_prevention_bytes(sps_nalu[2:])
    if len(rbsp) < 13:
        return None
    ptl_byte = rbsp[1]
    bitstream_compat = int.from_bytes(rbsp[2:6], "big")
    return {
        "profile_space": (ptl_byte >> 6) & 0x03,
        "tier_flag": (ptl_byte >> 5) & 0x01,
        "profile_id": ptl_byte & 0x1F,
        "profile_compatibility_indicator": _reverse_bits_32(bitstream_compat),
        "interop_constraints": bytes(rbsp[6:12]),
        "level_id": rbsp[12],
    }


def nal_layer_ids(report: ValidationContext) -> list[int]:
    layer_ids: list[int] = []
    for meta in report.rtp_report.nalus_meta:
        header = meta.get("header_bytes")
        if not header or len(header) < 2:
            continue
        b0, b1 = header[0], header[1]
        layer_id = ((b0 & 0x01) << 5) | ((b1 >> 3) & 0x1F)
        layer_ids.append(layer_id)
    return layer_ids


def check_sr_mapping(ctx: ValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No RTCP Sender Reports detected"
    rep = ctx.rtp_report
    au_by_ts = rep.access_units_by_ts
    sr_timestamps = {sr.rtp_timestamp for sr in ctx.sender_reports}
    aus = rep.access_units
    # AUs are restricted to the recovery-point window. The window's first AU is
    # a recovery point with captured pre-roll before it, so its SR is in-window
    # — UNLESS no pre-roll was dropped, i.e. it is the capture's very first AU,
    # whose SR (sent just before it) may predate the capture. Exempt only that
    # one boundary AU; every other windowed AU must carry its SR.
    checked = aus[1:] if (aus and rep.dropped_pre_recovery == 0) else aus
    missing = [au.timestamp for au in checked if au.timestamp not in sr_timestamps]
    if missing:
        return False, f"Missing SRs for {len(missing)} access units"
    unknown = [sr for sr in ctx.sender_reports if sr.rtp_timestamp not in au_by_ts]
    if unknown:
        last_au_time = max(
            (au.first_packet_time for au in ctx.rtp_report.access_units if au.first_packet_time is not None),
            default=0.0,
        )
        real_unknown = filter_capture_boundary_orphan_srs(
            unknown, set(au_by_ts.keys()), last_au_time)
        if real_unknown:
            return False, f"SRs reference {len(real_unknown)} unknown RTP timestamps"
    return True, "SRs present for all access units"


def check_sr_before_au(ctx: ValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No sender reports"
    violations = []
    for sr in ctx.sender_reports:
        au = ctx.rtp_report.access_units_by_ts.get(sr.rtp_timestamp)
        if au is None or au.first_packet_time is None:
            continue
        if sr.capture_time > au.first_packet_time:
            violations.append((sr.rtp_timestamp, sr.capture_time, au.first_packet_time))
    if violations:
        return False, f"{len(violations)} SRs occur after first media packet"
    return True, "All SRs occur before first media packet"


def check_sr_order(ctx: ValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No sender reports"
    order = []
    for sr in ctx.sender_reports:
        au = ctx.rtp_report.access_units_by_ts.get(sr.rtp_timestamp)
        if au is None:
            continue
        order.append(au.index)
    if order != sorted(order):
        return False, "SRs are not in presentation order"
    return True, "SRs are in presentation order"


def _check_sr_diff_h26x(ctx: ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """SR RTP timestamp deltas SHALL match nominal frame increment (TR-10-1 §13.3b)."""
    rtp_timestamps = [au.timestamp for au in ctx.rtp_report.access_units]
    exact_ticks = resolve_exact_ticks_per_frame(
        ctx.exact_framerate,
        ctx.sender_reports,
        rtp_timestamps,
    )
    return check_sr_rtp_timestamp_nominal(ctx.sender_reports, exact_ticks)


def check_sr_interval(ctx: ValidationContext) -> tuple[bool, str]:
    if len(ctx.sender_reports) < 3:
        return untestable("Not enough SRs to assess interval")
    timestamps = [sr.capture_time for sr in ctx.sender_reports]
    intervals = [b - a for a, b in zip(timestamps, timestamps[1:]) if b > a]
    if not intervals:
        return False, "SR intervals unavailable"
    intervals.sort()
    mid = intervals[len(intervals) // 2]
    nominal = compute_nominal_period([au.timestamp for au in ctx.rtp_report.access_units])
    if nominal is None:
        return False, "Not enough AUs to derive nominal period"
    if not rate_matches(nominal, mid, tolerance=0.01):
        return False, f"SR interval {mid:.6f}s differs from nominal {nominal:.6f}s"
    return True, f"SR interval {mid:.6f}s matches nominal {nominal:.6f}s"


def check_frame_interval_tr10_9(ctx: ValidationContext) -> tuple[bool, str]:
    return untestable(
        "Not applicable for compressed video — TR-10-9 §11.2a applies to "
        "uncompressed streams; compressed H.265 follows HRD schedule"
    )


def check_sr_interval_tr10_9(ctx: ValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No sender reports"
    times = [sr.capture_time for sr in ctx.sender_reports]
    passed, details = interval_variation_in_window(times, window=2.0, tolerance=0.002)
    if not passed and details.startswith("Not enough"):
        return untestable(details)
    return passed, details


def check_au_interval_const(ctx: ValidationContext) -> tuple[bool, str]:
    timestamps = [au.timestamp for au in ctx.rtp_report.access_units]
    if len(timestamps) < 3:
        return untestable("Not enough access units to assess AU interval")
    unwrapped = unwrap_rtp_timestamps(timestamps)
    ordered = sorted(unwrapped)
    deltas = [
        (cur - prev) / CLOCK_RATE for prev, cur in zip(ordered, ordered[1:]) if cur > prev
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


def check_packet_vcl_limit(ctx: ValidationContext) -> tuple[bool, str]:
    if ctx.encrypted:
        return untestable("Payload encrypted — NAL content not accessible")
    violations = 0
    for pkt in ctx.rtp_report.packets:
        vcl = [
            nal for nal in pkt.get("packet_nal_types", [])
            if ipmx_parse_rtp_pcap.is_vcl_nal("h265", nal)
        ]
        if len(vcl) > 1:
            violations += 1
    if violations:
        return False, f"{violations} packets contain multiple VCL NAL units"
    return True, "No packets contain multiple VCL NAL units"


def check_paci(ctx: ValidationContext) -> tuple[bool, str]:
    if ctx.encrypted:
        return untestable("Payload encrypted — NAL content not accessible")
    paci = 0
    for pkt in ctx.rtp_report.packets:
        payload = pkt.get("payload")
        if payload is None:
            continue
        if isinstance(payload, bytes) and len(payload) >= 2:
            nal_type = (payload[0] & 0x7E) >> 1
            if nal_type == 50:
                paci += 1
    if paci:
        return False, f"{paci} PACI packets detected"
    return True, "No PACI packets detected"


def check_mib_signal_sanity(ctx: ValidationContext) -> tuple[bool, str]:
    """Verify MIB baseband signal parameters are internally consistent.

    htotal/vtotal describe the source baseband signal (active + blanking) so
    htotal >= width and vtotal >= height must always hold.  The measured pixel
    clock must equal htotal * vtotal * exactframerate.
    """
    mib = extract_video_params_from_sr(ctx.sender_reports)
    if mib is None:
        return untestable("No video MIB available")

    width = mib.get("width")
    height = mib.get("height")
    htotal = mib.get("htotal")
    vtotal = mib.get("vtotal")
    measured_pixclk = mib.get("measured_pixel_clock")

    if any(v is None for v in (width, height, htotal, vtotal)):
        return untestable("MIB missing width/height/htotal/vtotal fields")

    errors: list[str] = []
    if htotal < width:  # type: ignore[operator]
        errors.append(f"htotal={htotal} < width={width}")
    if vtotal < height:  # type: ignore[operator]
        errors.append(f"vtotal={vtotal} < height={height}")

    if errors:
        return False, "MIB signal inconsistency: " + "; ".join(errors)

    if measured_pixclk is None:
        return True, (
            f"htotal={htotal} >= width={width}, vtotal={vtotal} >= height={height} "
            f"(measured_pixel_clock not present — cannot verify)"
        )

    exact_fr = _resolve_exactframerate(ctx)
    if exact_fr is None:
        return True, (
            f"htotal={htotal} >= width={width}, vtotal={vtotal} >= height={height} "
            f"(exactframerate unknown — cannot verify measured_pixel_clock)"
        )

    expected_pixclk = Fraction(htotal) * Fraction(vtotal) * exact_fr  # type: ignore[arg-type]
    if expected_pixclk:
        ppm_error = abs(Fraction(measured_pixclk) - expected_pixclk) / expected_pixclk * 1_000_000
    else:
        ppm_error = Fraction(0)
    if ppm_error > PIXCLK_TOLERANCE_PPM:
        return False, (
            f"measured_pixel_clock={measured_pixclk} vs "
            f"htotal({htotal}) * vtotal({vtotal}) * exactframerate({exact_fr}) = "
            f"{float(expected_pixclk):.0f} "
            f"(error {float(ppm_error):.1f} ppm, tolerance {PIXCLK_TOLERANCE_PPM} ppm)"
        )

    return True, (
        f"MIB signal consistent: htotal={htotal} >= width={width}, "
        f"vtotal={vtotal} >= height={height}, "
        f"measured_pixel_clock={measured_pixclk} ~ {htotal}*{vtotal}*{exact_fr} "
        f"({float(ppm_error):.1f} ppm)"
    )


def _resolve_exactframerate(ctx: ValidationContext) -> Fraction | None:
    """Resolve exact framerate from CLI > MIB."""
    if ctx.exact_framerate is not None:
        return ctx.exact_framerate
    from ipmx_validate_common import extract_exact_framerate_from_sr
    return extract_exact_framerate_from_sr(ctx.sender_reports)


def _first_packet_times(ctx: ValidationContext) -> list[float]:
    """Collect the PCAP capture time of the first packet of each AU."""
    times: list[float] = []
    for au in ctx.rtp_report.access_units:
        if au.first_packet_time is not None:
            times.append(au.first_packet_time)
    return times


def check_random_access(ctx: ValidationContext) -> tuple[bool, str]:
    if ctx.encrypted:
        return untestable("Payload encrypted — NAL content not accessible")
    aus = ctx.rtp_report.access_units
    if not aus:
        return False, "No access units detected"
    timestamps = [au.timestamp for au in aus]
    unwrapped = unwrap_rtp_timestamps(timestamps)
    base = unwrapped[0]
    total = (unwrapped[-1] - base) / CLOCK_RATE
    ra_times = []
    for au, ts in zip(aus, unwrapped):
        if any(nal in H265_RA_TYPES for nal in au.nal_types):
            ra_times.append((ts - base) / CLOCK_RATE)
    if not ra_times:
        return False, "No random access points (IDR/CRA/BLA) detected in capture"
    ra_times.sort()
    gaps = [b - a for a, b in zip(ra_times, ra_times[1:])]
    max_gap = max(gaps) if gaps else 0.0
    if total > 5.0 and max_gap > 5.0:
        return False, f"Random access gap {max_gap:.3f}s exceeds 5s"
    return True, "Random access points occur at least every 5s"


def check_random_access_content(ctx: ValidationContext) -> tuple[bool, str]:
    if ctx.encrypted:
        return untestable("Payload encrypted — NAL content not accessible")
    has_ra = False
    failures = 0
    for au in ctx.rtp_report.access_units:
        if not any(nal in H265_RA_TYPES for nal in au.nal_types):
            continue
        has_ra = True
        has_vps = 32 in au.nal_types
        has_sps = 33 in au.nal_types
        has_pps = 34 in au.nal_types
        has_sei = 39 in au.nal_types or 40 in au.nal_types
        if not ((has_vps and has_sps and has_pps) or has_sei):
            failures += 1
    if not has_ra:
        return untestable("No random access points detected to validate content")
    if failures:
        return False, f"{failures} random access points missing VPS/SPS/PPS or SEI"
    return True, "Random access points include required NAL units"


def check_buffering_period_sei(ctx: ValidationContext) -> tuple[bool, str]:
    """Buffering Period SEI shall be present at each recovery point (IDR/CRA/BLA)."""
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    au_sei, traced_ts = _build_au_sei_map(ctx.rtp_report, ctx.timeline.raw_headers, lossy_timestamps=ctx.timeline.lossy_timestamps)
    ra_aus = [
        au for au in ctx.rtp_report.access_units
        if any(nal in H265_RA_TYPES for nal in au.nal_types)
        and au.timestamp in traced_ts
    ]
    if not ra_aus:
        return untestable("No traced recovery points (IDR/CRA/BLA) detected")
    missing: list[int] = []
    for au in ra_aus:
        sei_types = au_sei.get(au.timestamp, set())
        if "buffering_period" not in sei_types:
            missing.append(au.timestamp)
    total_ra = sum(
        1 for au in ctx.rtp_report.access_units
        if any(nal in H265_RA_TYPES for nal in au.nal_types)
    )
    if missing:
        return False, (
            f"{len(missing)}/{len(ra_aus)} traced recovery point AUs missing "
            f"Buffering Period SEI (first missing ts={missing[0]})"
        )
    return True, (
        f"Buffering Period SEI present at all {len(ra_aus)} traced recovery points"
        + (f" ({total_ra} total in stream)" if total_ra != len(ra_aus) else "")
    )


def check_pic_timing_sei(ctx: ValidationContext) -> tuple[bool, str]:
    """Picture Timing SEI shall be present for each access unit."""
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    au_sei, traced_ts = _build_au_sei_map(ctx.rtp_report, ctx.timeline.raw_headers, lossy_timestamps=ctx.timeline.lossy_timestamps)
    traced_aus = [au for au in ctx.rtp_report.access_units if au.timestamp in traced_ts]
    if not traced_aus:
        return untestable("No access units covered by trace")
    missing: list[int] = []
    for au in traced_aus:
        sei_types = au_sei.get(au.timestamp, set())
        if "pic_timing" not in sei_types:
            missing.append(au.timestamp)
    total_aus = len(ctx.rtp_report.access_units)
    if missing:
        return False, (
            f"{len(missing)}/{len(traced_aus)} traced access units missing "
            f"Picture Timing SEI (first missing ts={missing[0]})"
        )
    return True, (
        f"Picture Timing SEI present in all {len(traced_aus)} traced access units"
        + (f" ({total_aus} total in stream)" if total_aus != len(traced_aus) else "")
    )


def check_sub_pic_hrd(ctx: ValidationContext) -> tuple[bool, str]:
    """Validate sub-picture HRD constraints when sub_pic_hrd_params_present_flag is set.

    Requirements:
    - tick_divisor_minus2 shall be 0..254
    - sub_pic_cpb_params_in_pic_timing_sei_flag shall be 0
    - decoding_unit_info SEI shall be provided for each slice
    """
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        return untestable("No SPS fields parsed")

    sub_pic_flag = get_int_field(sps, "sub_pic_hrd_params_present_flag")
    if sub_pic_flag is None:
        return untestable("sub_pic_hrd_params_present_flag not found in SPS")
    if sub_pic_flag != 1:
        return True, "sub_pic_hrd_params_present_flag is 0 — sub-picture HRD not used"

    issues: list[str] = []

    tick_div = get_int_field(sps, "tick_divisor_minus2")
    if tick_div is None:
        issues.append("tick_divisor_minus2 not present in SPS")
    elif tick_div < 0 or tick_div > 254:
        issues.append(f"tick_divisor_minus2={tick_div} outside valid range 0..254")

    cpb_in_pt = get_int_field(sps, "sub_pic_cpb_params_in_pic_timing_sei_flag")
    if cpb_in_pt is None:
        issues.append("sub_pic_cpb_params_in_pic_timing_sei_flag not present in SPS")
    elif cpb_in_pt != 0:
        issues.append(f"sub_pic_cpb_params_in_pic_timing_sei_flag={cpb_in_pt}, expected 0")

    au_sei, traced_ts = _build_au_sei_map(ctx.rtp_report, ctx.timeline.raw_headers, lossy_timestamps=ctx.timeline.lossy_timestamps)
    traced_aus = [au for au in ctx.rtp_report.access_units if au.timestamp in traced_ts]
    missing_du: list[int] = []
    for au in traced_aus:
        sei_types = au_sei.get(au.timestamp, set())
        if "decoding_unit_info" not in sei_types:
            missing_du.append(au.timestamp)
    if missing_du:
        issues.append(
            f"{len(missing_du)}/{len(traced_aus)} traced AUs missing "
            f"decoding_unit_info SEI (first ts={missing_du[0]})"
        )

    if issues:
        return False, "; ".join(issues)
    return True, (
        f"Sub-picture HRD valid: tick_divisor_minus2={tick_div}, "
        f"sub_pic_cpb_params_in_pic_timing_sei_flag=0, "
        f"decoding_unit_info present in {len(traced_aus)} traced AUs"
    )


def check_vui_flags(ctx: ValidationContext) -> tuple[bool, str]:
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        return untestable("No SPS fields parsed")
    required = {
        "video_signal_type_present_flag": 1,
        "colour_description_present_flag": 1,
        "vui_timing_info_present_flag": 1,
    }
    missing = []
    for key, expected in required.items():
        value = get_int_field(sps, key)
        if value != expected:
            missing.append(f"{key}={value}")
    vui_hrd, nal_hrd = _hrd_flags(sps)
    if vui_hrd != 1:
        missing.append(f"vui_hrd_parameters_present_flag={vui_hrd}")
    if nal_hrd != 1:
        missing.append(f"nal_hrd_parameters_present_flag={nal_hrd}")
    is_interlaced = _is_interlaced(ctx)
    if is_interlaced is True:
        ffip = get_int_field(sps, "frame_field_info_present_flag")
        if ffip != 1:
            missing.append(f"frame_field_info_present_flag={ffip} (SHALL be 1 for interlaced)")
    if missing:
        return False, "Missing/incorrect VUI flags: " + ", ".join(missing)
    return True, "Required VUI flags are set"


CHROMA_FORMAT_TO_SAMPLING: dict[int, str] = {
    0: "YCbCr-4:0:0",
    1: "YCbCr-4:2:0",
    2: "YCbCr-4:2:2",
    3: "YCbCr-4:4:4",
}

CHROMA_IDC_EQUIVALENT_SAMPLINGS: dict[int, set[str]] = {
    0: {"YCbCr-4:0:0", "KEY"},
}

HEVC_SUB_WIDTH_C: dict[int, int] = {0: 1, 1: 2, 2: 2, 3: 1}
HEVC_SUB_HEIGHT_C: dict[int, int] = {0: 1, 1: 2, 2: 1, 3: 1}


def _hevc_sps_display_resolution(
    sps: dict[str, Any],
) -> tuple[int | None, int | None]:
    """Compute display width/height from H.265 SPS, applying conformance window."""
    coded_w = get_int_field(sps, "pic_width_in_luma_samples")
    coded_h = get_int_field(sps, "pic_height_in_luma_samples")
    if coded_w is None or coded_h is None:
        return None, None

    conf_flag = get_int_field(sps, "conformance_window_flag")
    if conf_flag != 1:
        return coded_w, coded_h

    chroma_idc = get_int_field(sps, "chroma_format_idc")
    if chroma_idc is None:
        chroma_idc = 1
    sub_w = HEVC_SUB_WIDTH_C.get(chroma_idc, 1)
    sub_h = HEVC_SUB_HEIGHT_C.get(chroma_idc, 1)

    cl = get_int_field(sps, "conf_win_left_offset") or 0
    cr = get_int_field(sps, "conf_win_right_offset") or 0
    ct = get_int_field(sps, "conf_win_top_offset") or 0
    cb = get_int_field(sps, "conf_win_bottom_offset") or 0

    display_w = coded_w - sub_w * (cl + cr)
    display_h = coded_h - sub_h * (ct + cb)
    return display_w, display_h


def check_vui_present(ctx: ValidationContext) -> tuple[bool, str]:
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        return untestable("No SPS fields parsed")
    value = get_int_field(sps, "vui_parameters_present_flag")
    if value != 1:
        return False, f"vui_parameters_present_flag={value}"
    return True, "VUI parameters present"


def check_sps_vs_signal_params(ctx: ValidationContext) -> tuple[bool, str]:
    """Cross-validate SPS signal description against resolved video parameters.

    Resolution priority for each parameter: CLI > MIB.
    """
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        return untestable("No SPS fields parsed")
    mib = extract_video_params_from_sr(ctx.sender_reports)

    ref_width = ctx.width or (mib.get("width") if mib else None)
    ref_height = ctx.height or (mib.get("height") if mib else None)
    ref_sampling = ctx.sampling or (mib.get("sampling_format") if mib else None)
    ref_bit_depth = ctx.bit_depth or (mib.get("bit_depth") if mib else None)

    if all(v is None for v in (ref_width, ref_height, ref_sampling, ref_bit_depth)):
        return untestable("No reference video parameters (CLI or MIB) to cross-validate")

    mismatches: list[str] = []

    sps_width, sps_height = _hevc_sps_display_resolution(sps)
    if sps_width is not None and ref_width is not None and sps_width != ref_width:
        src = "CLI" if ctx.width is not None else "MIB"
        mismatches.append(f"width SPS={sps_width} {src}={ref_width}")
    if sps_height is not None and ref_height is not None and sps_height != ref_height:
        src = "CLI" if ctx.height is not None else "MIB"
        mismatches.append(f"height SPS={sps_height} {src}={ref_height}")

    chroma_idc = get_int_field(sps, "chroma_format_idc")
    if chroma_idc is not None and ref_sampling is not None:
        sps_sampling = CHROMA_FORMAT_TO_SAMPLING.get(chroma_idc)
        equivalents = CHROMA_IDC_EQUIVALENT_SAMPLINGS.get(chroma_idc, set())
        if sps_sampling is not None and sps_sampling != ref_sampling and ref_sampling not in equivalents:
            src = "CLI" if ctx.sampling is not None else "MIB"
            mismatches.append(
                f"sampling SPS chroma_format_idc={chroma_idc} ({sps_sampling}) "
                f"{src}={ref_sampling}"
            )

    sps_bd = get_int_field(sps, "bit_depth_luma_minus8")
    if sps_bd is not None and ref_bit_depth is not None:
        sps_bit_depth = sps_bd + 8
        if sps_bit_depth != ref_bit_depth:
            src = "CLI" if ctx.bit_depth is not None else "MIB"
            mismatches.append(f"bit_depth SPS={sps_bit_depth} {src}={ref_bit_depth}")

    if mismatches:
        return False, "SPS vs signal params mismatch: " + "; ".join(mismatches)
    return True, "SPS signal description matches reference parameters"


def check_alpha_channel(ctx: ValidationContext) -> tuple[bool, str]:
    """Validate alpha channel constraints when stream is monochrome (4:0:0).

    In IPMX, chroma_format_idc==0 always indicates alpha.  When detected:
    - MIB sampling_format shall be "KEY"
    - MIB colorimetry shall be "ALPHA"
    - SPS transfer_characteristics shall be 2 (UNSPECIFIED)
    """
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        return untestable("No SPS fields parsed")

    chroma_idc = get_int_field(sps, "chroma_format_idc")
    if chroma_idc is None:
        return untestable("chroma_format_idc not found in SPS")
    if chroma_idc != 0:
        return True, "Not an alpha stream (chroma_format_idc != 0)"

    issues: list[str] = []

    tcs = get_int_field(sps, "transfer_characteristics")
    if tcs is None:
        issues.append("transfer_characteristics not present in SPS")
    elif tcs != 2:
        issues.append(f"transfer_characteristics={tcs}, expected 2 (UNSPECIFIED)")

    mib = extract_video_params_from_sr(ctx.sender_reports)
    if mib is not None:
        mib_sampling = mib.get("sampling_format")
        if mib_sampling is not None and mib_sampling != "KEY":
            issues.append(f"MIB sampling_format='{mib_sampling}', expected 'KEY'")
        mib_color = mib.get("colorimetry")
        if mib_color is not None and mib_color != "ALPHA":
            issues.append(f"MIB colorimetry='{mib_color}', expected 'ALPHA'")
    else:
        issues.append("No MIB available to cross-validate KEY sampling and ALPHA colorimetry")

    if issues:
        return False, "Alpha stream (chroma_format_idc=0): " + "; ".join(issues)
    return True, (
        "Alpha stream confirmed: chroma_format_idc=0, "
        "transfer_characteristics=UNSPECIFIED, MIB=KEY/ALPHA"
    )


def check_monochrome_profile(ctx: ValidationContext) -> tuple[bool, str]:
    """Validate monochrome (alpha) streams use Main-444/Main10-444 profile."""
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    sps = ctx.timeline.header_fields.get("SPS")
    vps = ctx.timeline.header_fields.get("VPS")
    if sps is None or vps is None:
        return untestable("Missing VPS/SPS fields")

    chroma_idc = get_int_field(sps, "chroma_format_idc")
    if chroma_idc is None:
        return untestable("chroma_format_idc not found in SPS")
    if chroma_idc != 0:
        return True, "Not a monochrome stream (chroma_format_idc != 0)"

    profile_idc = get_int_field(vps, "general_profile_idc")
    if profile_idc == 4:
        bit_depth = get_int_field(sps, "bit_depth_luma_minus8")
        if bit_depth == 0:
            return True, "Monochrome profile: Main-444 (Rext, profile_idc=4, 8-bit)"
        elif bit_depth == 2:
            return True, "Monochrome profile: Main10-444 (Rext, profile_idc=4, 10-bit)"
        else:
            return True, f"Monochrome profile: Rext (profile_idc=4, bit_depth={8 + (bit_depth or 0)})"
    return False, (
        f"Monochrome stream requires Main-444/Main10-444 (Rext profile_idc=4), "
        f"found profile_idc={profile_idc}"
    )


def check_444_profile(ctx: ValidationContext) -> tuple[bool, str]:
    """Validate 4:4:4 streams use Main-444/Main10-444 profile (Rext profile_idc=4)."""
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    sps = ctx.timeline.header_fields.get("SPS")
    vps = ctx.timeline.header_fields.get("VPS")
    if sps is None or vps is None:
        return untestable("Missing VPS/SPS fields")

    chroma_idc = get_int_field(sps, "chroma_format_idc")
    if chroma_idc is None:
        return untestable("chroma_format_idc not found in SPS")
    if chroma_idc != 3:
        return True, "Not a 4:4:4 stream (chroma_format_idc != 3)"

    profile_idc = get_int_field(vps, "general_profile_idc")
    if profile_idc == 4:
        bit_depth = get_int_field(sps, "bit_depth_luma_minus8")
        if bit_depth == 0:
            return True, "4:4:4 profile: Main-444 (Rext, profile_idc=4, 8-bit)"
        elif bit_depth == 2:
            return True, "4:4:4 profile: Main10-444 (Rext, profile_idc=4, 10-bit)"
        else:
            return True, f"4:4:4 profile: Rext (profile_idc=4, bit_depth={8 + (bit_depth or 0)})"
    return False, (
        f"4:4:4 stream requires Main-444/Main10-444 (Rext profile_idc=4), "
        f"found profile_idc={profile_idc}"
    )


def check_timing_info(ctx: ValidationContext) -> tuple[bool, str]:
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        return untestable("No SPS fields parsed")
    flag = get_int_field(sps, "vui_timing_info_present_flag")
    num_units = get_int_field(sps, "vui_num_units_in_tick")
    time_scale = get_int_field(sps, "vui_time_scale")
    if flag != 1 or num_units is None or time_scale is None:
        return False, "VUI timing info missing"
    nominal = compute_nominal_period([au.timestamp for au in ctx.rtp_report.access_units])
    if nominal is None:
        return untestable("Cannot derive nominal period")
    observed_rate = 1.0 / nominal
    expected_rate = time_scale / num_units
    if not rate_matches(expected_rate, observed_rate):
        return False, f"VUI rate {expected_rate:.3f} vs observed {observed_rate:.3f}"
    return True, "VUI timing matches observed frame rate"


def check_vps_timing(ctx: ValidationContext) -> tuple[bool, str]:
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    vps = ctx.timeline.header_fields.get("VPS")
    if vps is None:
        return untestable("No VPS fields parsed")
    flag = get_int_field(vps, "vps_timing_info_present_flag")
    num_units = get_int_field(vps, "vps_num_units_in_tick")
    time_scale = get_int_field(vps, "vps_time_scale")
    if flag != 1 or num_units is None or time_scale is None:
        return False, "VPS timing info missing"
    nominal = compute_nominal_period([au.timestamp for au in ctx.rtp_report.access_units])
    if nominal is None:
        return untestable("Cannot derive nominal period")
    observed_rate = 1.0 / nominal
    expected_rate = time_scale / num_units
    if not rate_matches(expected_rate, observed_rate):
        return False, f"VPS rate {expected_rate:.3f} vs observed {observed_rate:.3f}"
    return True, "VPS timing matches observed frame rate"


def check_reorder_flags(ctx: ValidationContext) -> tuple[bool, str]:
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    vps = ctx.timeline.header_fields.get("VPS")
    sps = ctx.timeline.header_fields.get("SPS")
    if vps is None or sps is None:
        return untestable("Missing VPS/SPS fields")
    vps_reorder = get_int_field(vps, "vps_max_num_reorder_pics")
    sps_reorder = get_int_field(sps, "sps_max_num_reorder_pics")
    if vps_reorder != 0 or sps_reorder != 0:
        return False, f"reorder_pics vps={vps_reorder} sps={sps_reorder}"
    return True, "Reorder pics set to 0"


def check_nuh_layer_id(ctx: ValidationContext) -> tuple[bool, str]:
    layers = nal_layer_ids(ctx)
    if not layers:
        return untestable("No NAL units parsed")
    if any(layer_id != 0 for layer_id in layers):
        return False, "Non-zero nuh_layer_id detected"
    return True, "All nuh_layer_id values are 0"


_H265_PROFILE_SUPERSET: dict[int, set[int]] = {
    1: set(),
    2: {1},
    4: {1, 2},
}
"""H.265 profile superset hierarchy (ITU-T H.265 Annex A).

Key = profile_idc, value = set of profile_idc values it is a superset of.
- Main 10 (2) is a superset of Main (1).
- Rext (4) is a superset of Main (1) and Main 10 (2).
"""


def check_profile_levels(ctx: ValidationContext) -> tuple[bool, str]:
    """TR-10-15b-123: Main/Main10 YCbCr-4:2:0 profile check.

    Monochrome (alpha) and 4:4:4 streams have their own profile requirements
    validated by TR-10-15b-124 and TR-10-15b-132 respectively.
    """
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    vps = ctx.timeline.header_fields.get("VPS")
    sps = ctx.timeline.header_fields.get("SPS")
    if vps is None or sps is None:
        return untestable("Missing VPS/SPS fields")
    chroma = get_int_field(sps, "chroma_format_idc")
    if chroma == 0:
        return True, "Monochrome/alpha stream — profile validated by TR-10-15b-124"
    if chroma == 3:
        return True, "4:4:4 stream — profile validated by TR-10-15b-132"
    profile_idc = get_int_field(vps, "general_profile_idc")
    bit_depth = get_int_field(sps, "bit_depth_luma_minus8")
    if bit_depth is None:
        bit_depth = get_int_field(sps, "bit_depth_chroma_minus8")
    required = {1, 2}
    if profile_idc not in required:
        if ctx.allow_superset_profile and any(
            profile_idc in _H265_PROFILE_SUPERSET
            and req in _H265_PROFILE_SUPERSET[profile_idc]
            for req in required
        ):
            return True, (
                f"Profile {profile_idc} is a superset of Main/Main10 "
                f"(--allow-superset-profile)"
            )
        return False, f"Profile {profile_idc} is not Main/Main10"
    if chroma != 1:
        return False, f"chroma_format_idc={chroma} is not 4:2:0"
    if bit_depth not in (0, 2):
        return False, f"bit_depth_luma_minus8={bit_depth} not 8/10-bit"
    return True, "Profile and chroma/bit depth match IPMX HEVC profile (Main/Main10 4:2:0)"


def check_no_annexes_fghi(ctx: ValidationContext) -> tuple[bool, str]:
    """Annexes F, G, H, I of H.265 shall not be used.

    Annex F (multilayer framework) also covers Annex G (multiview) and
    Annex H (scalable).  Detected via VPS and SPS/PPS extension flags
    per ITU-T H.265 sections 7.3.2.1, 7.3.2.2.1, 7.3.2.3.1.
    """
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    vps = ctx.timeline.header_fields.get("VPS")
    sps = ctx.timeline.header_fields.get("SPS")
    pps = ctx.timeline.header_fields.get("PPS")
    if vps is None or sps is None:
        return untestable("Missing VPS/SPS fields")

    violations: list[str] = []

    max_layers = get_int_field(vps, "vps_max_layers_minus1")
    if max_layers is not None and max_layers > 0:
        violations.append(f"vps_max_layers_minus1={max_layers} (multi-layer, Annex F)")

    vps_ext = get_int_field(vps, "vps_extension_flag")
    if vps_ext == 1:
        violations.append("vps_extension_flag=1 (Annex F VPS extension)")

    sps_ml = get_int_field(sps, "sps_multilayer_extension_flag")
    if sps_ml == 1:
        violations.append("sps_multilayer_extension_flag=1 (Annex F)")

    sps_3d = get_int_field(sps, "sps_3d_extension_flag")
    if sps_3d == 1:
        violations.append("sps_3d_extension_flag=1 (Annex I)")

    if pps is not None:
        pps_ml = get_int_field(pps, "pps_multilayer_extension_flag")
        if pps_ml == 1:
            violations.append("pps_multilayer_extension_flag=1 (Annex F)")

        pps_3d = get_int_field(pps, "pps_3d_extension_flag")
        if pps_3d == 1:
            violations.append("pps_3d_extension_flag=1 (Annex I)")

    if violations:
        return False, "Forbidden annex extensions detected: " + "; ".join(violations)
    return True, "No Annex F/G/H/I extensions present"


def check_media_info_block(ctx: ValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No sender reports"
    sr = ctx.sender_reports[0]
    if sr.ipmx_info is None:
        return False, "No IPMX Info Block in SR"
    types = [block.media_info_type for block in sr.ipmx_info.media_blocks]
    if 0x0005 not in types or 0x0009 not in types:
        return False, "Missing 0x0005 or 0x0009 media info blocks"
    idx_0005 = types.index(0x0005)
    idx_0009 = types.index(0x0009)
    if idx_0009 != idx_0005 + 1:
        return False, f"0x0009 does not immediately follow 0x0005 (positions {idx_0005}, {idx_0009})"
    return True, "Required media info blocks present and immediately ordered"


def check_media_info_lengths(ctx: ValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No sender reports"
    sr = ctx.sender_reports[0]
    block = find_media_block(sr, 0x0009)
    if block is None:
        return False, "Missing 0x0009 media info block"
    total = (block.length_words + 1) * 4
    if len(block.payload) + 4 != total:
        return False, "Media info block length field does not match payload size"
    if total % 4 != 0:
        return False, "Media info block is not 32-bit aligned"
    return True, "Media info block length is aligned"


def check_h265_info_mask(ctx: ValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No sender reports"
    sr = ctx.sender_reports[0]
    block = find_media_block(sr, 0x0009)
    if block is None:
        return False, "Missing 0x0009 media info block"
    data = parse_h265_media_info(block.payload)
    if "error" in data:
        return False, data["error"]
    mask = data["mask"]
    failures = []
    fixed_fields = [
        "profile_space",
        "profile_id",
        "level_id",
        "tier_flag",
        "profile_compatibility_indicator",
        "interop_constraints",
        "sprop_max_don_diff",
        "tx_mode",
        "sprop_depack_buf_bytes",
        "sprop_depack_buf_nalus",
        "sprop_spatial_segmentation_idc",
        "sprop_sub_layer_id",
        "sprop_segmentation_id",
    ]
    for field in fixed_fields:
        bit = H265_INFO_FIELD_BITS[field]
        if not (mask & (1 << bit)):
            value = data[field]
            if isinstance(value, bytes):
                if any(b != 0 for b in value):
                    failures.append(field)
            else:
                if value != 0:
                    failures.append(field)
    for field in ("sprop_vps", "sprop_sps", "sprop_pps", "extra_bytes"):
        bit = H265_INFO_FIELD_BITS[field]
        length_key = field + "_len" if field != "extra_bytes" else "extra_len"
        length = data[length_key]
        if not (mask & (1 << bit)):
            if length != 0 or data[field]:
                failures.append(field)
    if failures:
        return False, "Fields present without mask bit: " + ", ".join(failures)
    return True, "FIELD-PRESENT-MASK matches payload content"


def check_h265_info_variable_len(ctx: ValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No sender reports"
    sr = ctx.sender_reports[0]
    block = find_media_block(sr, 0x0009)
    if block is None:
        return False, "Missing 0x0009 media info block"
    data = parse_h265_media_info(block.payload)
    if "error" in data:
        return False, data["error"]
    variable_len = (
        data["sprop_vps_len"]
        + data["sprop_sps_len"]
        + data["sprop_pps_len"]
        + data["extra_len"]
    )
    fixed_len = 40
    total = fixed_len + variable_len
    padded = total if total % 4 == 0 else total + (4 - (total % 4))
    if len(block.payload) != padded:
        return False, f"Variable section length {variable_len} does not align to 4 bytes"
    return True, "Variable section length matches padding requirement"


def check_h265_info_matches_stream(ctx: ValidationContext) -> tuple[bool, str]:
    """Verify MIB 0x0009 against the coded stream.

    1. Extract profile/tier/level from the stream's first SPS and compare
       against the MIB fixed fields (for every field whose mask bit is set).
    2. If the MIB also carries raw VPS/SPS/PPS, the first occurrence of each
       in the stream must be byte-identical to the MIB copy.
    """
    if ctx.encrypted:
        return untestable("Payload encrypted — NAL content not accessible")
    if not ctx.sender_reports:
        return False, "No sender reports"
    sr = ctx.sender_reports[0]
    block = find_media_block(sr, 0x0009)
    if block is None:
        return False, "Missing 0x0009 media info block"
    data = parse_h265_media_info(block.payload)
    if "error" in data:
        return False, data["error"]

    param_sets = collect_param_sets(ctx)
    mask = data["mask"]
    mismatches: list[str] = []

    # --- Part 1: compare MIB fixed PTL fields against stream SPS ---
    stream_sps_list = param_sets.get("sps", [])
    if not stream_sps_list:
        return untestable("No SPS NAL units found in stream — cannot verify MIB fields")

    ptl = parse_h265_sps_profile_tier_level(stream_sps_list[0])
    if ptl is None:
        return untestable("First SPS too short to extract profile_tier_level")

    PTL_FIELDS = (
        "profile_space",
        "profile_id",
        "level_id",
        "tier_flag",
        "profile_compatibility_indicator",
        "interop_constraints",
    )
    for field in PTL_FIELDS:
        bit = H265_INFO_FIELD_BITS[field]
        if not (mask & (1 << bit)):
            continue
        mib_val = data[field]
        stream_val = ptl[field]
        if isinstance(mib_val, bytes):
            if mib_val != stream_val:
                mismatches.append(
                    f"{field} MIB={mib_val.hex()} stream={stream_val.hex()}"  # type: ignore[union-attr]
                )
        else:
            if mib_val != stream_val:
                mismatches.append(f"{field} MIB={mib_val} stream={stream_val}")

    # --- Part 2: if MIB carries raw VPS/SPS/PPS, first from stream must be identical ---
    for kind, mib_key in (("vps", "sprop_vps"), ("sps", "sprop_sps"), ("pps", "sprop_pps")):
        bit = H265_INFO_FIELD_BITS[mib_key]
        if not (mask & (1 << bit)):
            continue
        mib_raw = data[mib_key]
        if not mib_raw:
            continue
        decoded_list = decode_base64_sets(mib_raw)
        stream_list = param_sets.get(kind, [])
        if not stream_list:
            mismatches.append(f"{kind}: MIB carries data but stream has none")
            continue
        for decoded in decoded_list:
            if decoded and decoded != stream_list[0]:
                mismatches.append(
                    f"{kind}: first from stream differs from MIB"
                )
                break

    if mismatches:
        return False, "MIB 0x0009 vs stream mismatch: " + "; ".join(mismatches)
    return True, "MIB 0x0009 fixed fields and param sets match stream"


def _hrd_flags(sps: dict[str, Any]) -> tuple[int | None, int | None]:
    """Return (vui_hrd_present, nal_hrd_present) from SPS trace fields."""
    vui_hrd = get_int_field(sps, "vui_hrd_parameters_present_flag")
    nal_hrd = get_int_field(sps, "nal_hrd_parameters_present_flag")
    return vui_hrd, nal_hrd


def check_hrd_present(ctx: ValidationContext) -> tuple[bool, str]:
    """TR-10-15b-114: HRD shall be in VUI with nal_hrd_parameters_present_flag=1."""
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        return untestable("No SPS fields parsed")
    vui_hrd, nal_hrd = _hrd_flags(sps)
    issues: list[str] = []
    if vui_hrd != 1:
        issues.append(f"vui_hrd_parameters_present_flag={vui_hrd}")
    if nal_hrd != 1:
        vcl_hrd = get_int_field(sps, "vcl_hrd_parameters_present_flag")
        if vcl_hrd == 1:
            issues.append(
                f"nal_hrd_parameters_present_flag={nal_hrd} — "
                f"vcl_hrd is set instead (TR-10-15b requires NAL HRD)"
            )
        else:
            issues.append(f"nal_hrd_parameters_present_flag={nal_hrd}")
    if issues:
        return False, "; ".join(issues)
    return True, "HRD parameters present in VUI with NAL HRD enabled"


def _parse_per_layer_hrd(
    sps: dict[str, Any], num_layers: int,
) -> tuple[list[int], list[int], int | None, int | None]:
    """Extract per-temporal-layer HRD bit_rate and cpb_size values.

    Returns (bitrates, cpb_sizes, bit_rate_scale, cpb_size_scale).
    Each list has *num_layers* entries (one per temporal sub-layer).
    An entry is -1 when the field is missing from the trace.
    """
    bit_rate_scale = get_int_field(sps, "bit_rate_scale")
    cpb_size_scale = get_int_field(sps, "cpb_size_scale")
    bitrates: list[int] = []
    cpb_sizes: list[int] = []
    for i in range(num_layers):
        br_val = get_int_field(sps, f"bit_rate_value_minus1[{i}]")
        cs_val = get_int_field(sps, f"cpb_size_value_minus1[{i}]")
        if br_val is not None and bit_rate_scale is not None:
            bitrates.append((br_val + 1) * (2 ** (6 + bit_rate_scale)))
        else:
            bitrates.append(-1)
        if cs_val is not None and cpb_size_scale is not None:
            cpb_sizes.append((cs_val + 1) * (2 ** (4 + cpb_size_scale)))
        else:
            cpb_sizes.append(-1)
    return bitrates, cpb_sizes, bit_rate_scale, cpb_size_scale


def check_hrd_parameters(ctx: ValidationContext) -> tuple[bool, str]:
    """Validate HRD parameters for each temporal sub-layer per TR-10-15b.

    When sps_max_sub_layers_minus1 > 0, HRD parameters shall be specified
    for each temporal sub-layer.  BitRate and CpbSize must be positive at
    every layer, and the highest layer's declared BitRate is compared
    against the measured stream average (with 5 % margin).
    """
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        return untestable("No SPS fields parsed")
    vui_hrd, nal_hrd = _hrd_flags(sps)
    if vui_hrd != 1 or nal_hrd != 1:
        return untestable("NAL HRD parameters not present in VUI")

    max_sub_layers = (get_int_field(sps, "sps_max_sub_layers_minus1") or 0) + 1
    bitrates, cpb_sizes, br_scale, cs_scale = _parse_per_layer_hrd(sps, max_sub_layers)

    if br_scale is None or cs_scale is None:
        return untestable("HRD bit_rate_scale/cpb_size_scale not found in trace")

    issues: list[str] = []

    for i in range(max_sub_layers):
        if bitrates[i] < 0:
            issues.append(f"layer {i}: bit_rate_value_minus1[{i}] missing")
        elif bitrates[i] == 0:
            issues.append(f"layer {i}: declared BitRate is 0")
        if cpb_sizes[i] < 0:
            issues.append(f"layer {i}: cpb_size_value_minus1[{i}] missing")
        elif cpb_sizes[i] == 0:
            issues.append(f"layer {i}: declared CpbSize is 0")

    valid_bitrates = [b for b in bitrates if b > 0]
    if len(valid_bitrates) >= 2:
        for i in range(1, len(valid_bitrates)):
            if valid_bitrates[i] < valid_bitrates[i - 1]:
                issues.append(
                    f"BitRate not monotonically non-decreasing: "
                    f"layer {i - 1}={valid_bitrates[i - 1]}, layer {i}={valid_bitrates[i]}"
                )
                break

    top_bitrate = bitrates[-1] if bitrates[-1] > 0 else (bitrates[0] if bitrates[0] > 0 else 0)
    top_cpb_size = cpb_sizes[-1] if cpb_sizes[-1] > 0 else (cpb_sizes[0] if cpb_sizes[0] > 0 else 0)

    HRD_BITRATE_MARGIN = 0.05
    aus = ctx.rtp_report.access_units
    if top_bitrate > 0 and len(aus) >= 2:
        total_bits = sum(len(n) for n in ctx.rtp_report.nalus_bytes) * 8
        duration_s = (aus[-1].timestamp - aus[0].timestamp) / CLOCK_RATE
        if duration_s > 0:
            actual_avg_bps = total_bits / duration_s
            if top_bitrate * (1 + HRD_BITRATE_MARGIN) < actual_avg_bps:
                issues.append(
                    f"top-layer declared BitRate {top_bitrate / 1e6:.2f} Mbps "
                    f"< actual average {actual_avg_bps / 1e6:.2f} Mbps "
                    f"(>{HRD_BITRATE_MARGIN:.0%} margin exceeded)"
                )

    init_delay_len = get_int_field(sps, "initial_cpb_removal_delay_length_minus1")
    au_delay_len = get_int_field(sps, "au_cpb_removal_delay_length_minus1")
    dpb_delay_len = get_int_field(sps, "dpb_output_delay_length_minus1")
    for name, val in [
        ("initial_cpb_removal_delay_length_minus1", init_delay_len),
        ("au_cpb_removal_delay_length_minus1", au_delay_len),
        ("dpb_output_delay_length_minus1", dpb_delay_len),
    ]:
        if val is not None and (val < 0 or val > 31):
            issues.append(f"{name}={val} out of range [0..31]")

    if issues:
        return False, "; ".join(issues)

    if max_sub_layers == 1:
        detail = (
            f"BitRate={top_bitrate / 1e6:.2f} Mbps, "
            f"CpbSize={top_cpb_size / 1e6:.2f} Mbit"
        )
    else:
        layer_parts = [
            f"layer {i}: BitRate={bitrates[i] / 1e6:.2f} Mbps, CpbSize={cpb_sizes[i] / 1e6:.2f} Mbit"
            for i in range(max_sub_layers)
            if bitrates[i] > 0 and cpb_sizes[i] > 0
        ]
        detail = f"{max_sub_layers} temporal sub-layers; " + "; ".join(layer_parts)
    if top_bitrate > 0 and len(aus) >= 2:
        total_bits = sum(len(n) for n in ctx.rtp_report.nalus_bytes) * 8
        duration_s = (aus[-1].timestamp - aus[0].timestamp) / CLOCK_RATE
        if duration_s > 0:
            detail += f", actual avg={total_bits / duration_s / 1e6:.2f} Mbps"
    return True, detail


def check_cpb_cnt(ctx: ValidationContext) -> tuple[bool, str]:
    """Verify cpb_cnt_minus1 == 0 for every temporal sub-layer."""
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        return untestable("No SPS fields parsed")

    max_sub_layers = (get_int_field(sps, "sps_max_sub_layers_minus1") or 0) + 1
    issues: list[str] = []
    found_any = False

    for i in range(max_sub_layers):
        cpb = get_int_field(sps, f"cpb_cnt_minus1[{i}]")
        if cpb is None:
            cpb = get_int_field(sps, "cpb_cnt_minus1") if i == 0 else None
        if cpb is not None:
            found_any = True
            if cpb != 0:
                issues.append(f"cpb_cnt_minus1[{i}]={cpb}")

    if not found_any:
        return False, "cpb_cnt_minus1 not present"
    if issues:
        return False, "; ".join(issues)
    if max_sub_layers == 1:
        return True, "cpb_cnt_minus1 is 0"
    return True, f"cpb_cnt_minus1 is 0 for all {max_sub_layers} temporal sub-layers"


def check_nal_hrd_flag(ctx: ValidationContext) -> tuple[bool, str]:
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        return untestable("No SPS fields parsed")
    flag = get_int_field(sps, "nal_hrd_parameters_present_flag")
    if flag != 1:
        return False, f"nal_hrd_parameters_present_flag={flag}"
    return True, "NAL HRD parameters present"


def check_no_backward_pred(ctx: ValidationContext) -> tuple[bool, str]:
    return untestable("NoBackwardPredFlag not observable in this capture")


# ---------------------------------------------------------------------------
# SDP cross-validation helpers (H.265)
# ---------------------------------------------------------------------------

_H265_SDP_FIELD_MAP: list[tuple[str, str, type]] = [
    ("profile_space", "h265_profile_space", int),
    ("profile_id", "h265_profile_id", int),
    ("level_id", "h265_level_id", int),
    ("tier_flag", "h265_tier_flag", bool),
    ("sprop_max_don_diff", "h26x_max_don_diff", int),
    ("sprop_depack_buf_bytes", "h265_depack_buf_bytes", int),
    ("sprop_depack_buf_nalus", "h265_depack_buf_nalus", int),
]

_H265_SDP_HEX_FIELDS: list[tuple[str, str, int]] = [
    ("profile_compatibility_indicator", "h265_profile_compatibility_indicator", 4),
    ("interop_constraints", "h265_interop_constraints", 6),
]

_H265_SDP_SPROP_FIELDS: list[tuple[str, str]] = [
    ("sprop_vps", "h265_vps"),
    ("sprop_sps", "h265_sps"),
    ("sprop_pps", "h265_pps"),
]

_H265_SDP_STRING_FIELDS: list[tuple[str, str]] = [
    ("sprop_spatial_segmentation_idc", "h265_spatial_segmentation_idc"),
]


def _sdp_hex_to_int(hex_str: str) -> int | None:
    """Convert a hex string (e.g. '60000000') to an integer, or None if empty."""
    if not hex_str:
        return None
    return int(hex_str, 16)


def _sdp_hex_to_bytes(hex_str: str, length: int) -> bytes | None:
    """Convert a hex string to bytes of *length*, or None if empty."""
    if not hex_str:
        return None
    raw = bytes.fromhex(hex_str)
    if len(raw) < length:
        raw = raw + b"\x00" * (length - len(raw))
    return raw[:length]


def _sdp_field_is_set(md: MediaDescriptor, attr: str, typ: type) -> bool:
    """Return True if the SDP media descriptor attribute has a non-default value."""
    val = getattr(md, attr, None)
    if val is None:
        return False
    if typ is bool:
        return True  # bool is always explicitly set in SDP fmtp
    if typ is int:
        return val != 0
    if typ is str:
        return val != ""
    return False


def check_sdp_tp_mode(ctx: ValidationContext) -> tuple[bool, str]:
    """TR-10-15b-105: TP shall be 2110TPW in SDP fmtp."""
    if ctx.sdp_media is None:
        return untestable("No SDP transport file provided (use --sdp)")
    tp = ctx.sdp_media.sender_type
    if tp is None:
        return untestable("SDP does not specify TP attribute")
    if tp != MatroxSdpEnums.SenderType2110TPW:
        return False, f"SDP TP='{tp}', expected '2110TPW'"
    return True, "SDP TP=2110TPW"


def check_mib_vs_sdp_fmtp_h265(ctx: ValidationContext) -> tuple[bool, str]:
    """TR-10-15b-150: MIB 0x0009 fields shall match SDP fmtp syntax."""
    if ctx.sdp_media is None:
        return untestable("No SDP transport file provided (use --sdp)")
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    sr = ctx.sender_reports[0]
    block = find_media_block(sr, 0x0009)
    if block is None:
        return untestable("No MIB 0x0009 present")
    data = parse_h265_media_info(block.payload)
    if "error" in data:
        return False, data["error"]

    md = ctx.sdp_media
    mask = data["mask"]
    mismatches: list[str] = []

    for mib_field, sdp_attr, typ in _H265_SDP_FIELD_MAP:
        bit = H265_INFO_FIELD_BITS[mib_field]
        if not (mask & (1 << bit)):
            continue
        if not _sdp_field_is_set(md, sdp_attr, typ):
            continue
        mib_val = data[mib_field]
        sdp_val = getattr(md, sdp_attr)
        if typ is bool:
            sdp_val = int(sdp_val)
        if mib_val != sdp_val:
            mismatches.append(f"{mib_field}: MIB={mib_val} SDP={sdp_val}")

    for mib_field, sdp_attr, nbytes in _H265_SDP_HEX_FIELDS:
        bit = H265_INFO_FIELD_BITS[mib_field]
        if not (mask & (1 << bit)):
            continue
        sdp_hex: str = getattr(md, sdp_attr, "")
        if not sdp_hex:
            continue
        mib_val = data[mib_field]
        if nbytes == 4:
            sdp_int = _sdp_hex_to_int(sdp_hex)
            if sdp_int is not None and mib_val != sdp_int:
                mismatches.append(f"{mib_field}: MIB={mib_val:#x} SDP={sdp_int:#x}")
        else:
            sdp_bytes = _sdp_hex_to_bytes(sdp_hex, nbytes)
            if sdp_bytes is not None and mib_val != sdp_bytes:
                mismatches.append(
                    f"{mib_field}: MIB={mib_val.hex() if isinstance(mib_val, bytes) else mib_val} "
                    f"SDP={sdp_bytes.hex()}"
                )

    for mib_field, sdp_attr in _H265_SDP_SPROP_FIELDS:
        bit = H265_INFO_FIELD_BITS[mib_field]
        if not (mask & (1 << bit)):
            continue
        sdp_b64: str = getattr(md, sdp_attr, "")
        if not sdp_b64:
            continue
        mib_raw: bytes = data[mib_field]
        if not mib_raw:
            mismatches.append(f"{mib_field}: MIB empty but SDP has data")
            continue
        try:
            sdp_raw = base64.b64decode(sdp_b64)
        except Exception:
            mismatches.append(f"{mib_field}: SDP base64 decode failed")
            continue
        if mib_raw != sdp_raw:
            mismatches.append(f"{mib_field}: MIB and SDP differ")

    for mib_field, sdp_attr in _H265_SDP_STRING_FIELDS:
        bit = H265_INFO_FIELD_BITS[mib_field]
        if not (mask & (1 << bit)):
            continue
        sdp_str: str = getattr(md, sdp_attr, "")
        if not sdp_str:
            continue
        mib_int_val = data[mib_field]
        try:
            sdp_int_val = int(sdp_str)
        except ValueError:
            mismatches.append(f"{mib_field}: SDP value '{sdp_str}' is not an integer")
            continue
        if mib_int_val != sdp_int_val:
            mismatches.append(f"{mib_field}: MIB={mib_int_val} SDP={sdp_int_val}")

    if mismatches:
        return False, "MIB vs SDP mismatch: " + "; ".join(mismatches)
    return True, "MIB 0x0009 fields match SDP fmtp"


def check_sdp_fmtp_in_mib_h265(ctx: ValidationContext) -> tuple[bool, str]:
    """TR-10-15b-240: SDP fmtp fields shall be present in MIB."""
    if ctx.sdp_media is None:
        return untestable("No SDP transport file provided (use --sdp)")
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    sr = ctx.sender_reports[0]
    block = find_media_block(sr, 0x0009)
    if block is None:
        return untestable("No MIB 0x0009 present")
    data = parse_h265_media_info(block.payload)
    if "error" in data:
        return False, data["error"]

    md = ctx.sdp_media
    mask = data["mask"]
    missing: list[str] = []

    for mib_field, sdp_attr, typ in _H265_SDP_FIELD_MAP:
        if not _sdp_field_is_set(md, sdp_attr, typ):
            continue
        bit = H265_INFO_FIELD_BITS[mib_field]
        if not (mask & (1 << bit)):
            missing.append(mib_field)

    for mib_field, sdp_attr, _nbytes in _H265_SDP_HEX_FIELDS:
        sdp_hex = getattr(md, sdp_attr, "")
        if not sdp_hex:
            continue
        bit = H265_INFO_FIELD_BITS[mib_field]
        if not (mask & (1 << bit)):
            missing.append(mib_field)

    for mib_field, sdp_attr in _H265_SDP_SPROP_FIELDS:
        sdp_b64 = getattr(md, sdp_attr, "")
        if not sdp_b64:
            continue
        bit = H265_INFO_FIELD_BITS[mib_field]
        if not (mask & (1 << bit)):
            missing.append(mib_field)

    for mib_field, sdp_attr in _H265_SDP_STRING_FIELDS:
        sdp_str = getattr(md, sdp_attr, "")
        if not sdp_str:
            continue
        bit = H265_INFO_FIELD_BITS[mib_field]
        if not (mask & (1 << bit)):
            missing.append(mib_field)

    if missing:
        return False, "SDP fmtp fields missing from MIB mask: " + ", ".join(missing)
    return True, "All SDP fmtp fields present in MIB"


def check_sdp_wrapper(ctx: ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """Comprehensive SDP-side requirement for IPMX H.265 streams.

    Mirrors the per-media-type checklist `TP-10/TP-10-1Sec13.2.py:195-232`
    runs for `video/H265` (RFC 7798 + ST 2110-10 + ST 2110-22) and adds
    the project-local IPMX checks: the IPMX fmtp keyword (TR-10-1 §10.1)
    and the multicast source-filter signaling (TR-10-9 §17 / RFC 4570).
    """
    media = ctx.sdp_media
    if media is None:
        from ipmx_validate_common import untestable as _ut
        return _ut("No SDP provided")
    try:
        check_sdp_rfc7798(media)
        check_sdp_st2110_10(media)
        check_sdp_st2110_22(media)
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


def build_requirements(ctx: ValidationContext) -> list[Requirement]:
    reqs: list[Requirement] = []
    def add(req_id: str, level: str, text: str, fn):
        reqs.append(Requirement(req_id=req_id, level=level, text=text, check=fn))

    add("TR-10-15b-87", "shall", "An IPMX Sender producing an H.265 coded stream shall comply with the VSF TR-10-7 Technical Recommendation.", lambda _: untestable("Not observable in PCAP"))
    add("TR-10-15b-88", "shall", "An IPMX Sender producing an H.265 coded stream shall comply with the BCP-006-03 specification.", lambda _: untestable("Not observable in PCAP"))
    add("TR-10-15b-89", "shall", "The H.265 coded bitstream produced by an IPMX Sender shall conform to the H.265 specification, as well as the requirements defined in BCP-006-03 and this Technical Recommendation.", lambda _: untestable("Full bitstream compliance not verifiable here"))
    add("TR-10-15b-90", "shall", "An IPMX Receiver shall communicate its capabilities for the \"video/H265\" media type through BCP-004-01, Receiver Capabilities.", lambda _: untestable("Not observable in PCAP"))
    add("TR-10-15b-91", "shall", "An IPMX Sender shall communicate its capabilities for the \"video/H265\" media type through BCP-004-02, Sender Capabilities.", lambda _: untestable("Not observable in PCAP"))
    add("TR-10-15b-94", "shall", "The vui_parameters() shall be present in SPS and shall describe the uncompressed YCbCr video signal.", lambda c=ctx: check_vui_present(c))
    add("TR-10-15b-94-XVAL", "shall", "SPS signal description (width, height, sampling, bit_depth) shall match CLI/MIB video parameters.", lambda c=ctx: check_sps_vs_signal_params(c))
    add("TR-10-15b-95", "shall", "VUI flags video_signal_type_present_flag, colour_description_present_flag, vui_timing_info_present_flag, vui_hrd_parameters_present_flag, and nal_hrd_parameters_present_flag shall be 1; frame_field_info_present_flag shall be 1 for interlaced video.", lambda c=ctx: check_vui_flags(c))
    add("TR-10-15b-96", "shall", "If supported, the alpha channel shall be transported as an independent monochrome bitstream using KEY 4:0:0 sampling, ALPHA colorimetry and UNSPECIFIED transfer characteristics.", lambda c=ctx: check_alpha_channel(c))
    add("TR-10-15b-99", "shall", "UDP/IP packets shall comply with RFC 7798 and NMOS BCP-006-03 restrictions.", lambda _: untestable("RFC/BCP compliance not fully validated"))
    add("TR-10-9-11.2a", "shall", "IPMX Senders shall send the first packet of each frame at regular intervals that correspond to the Frame-to-Frame Interval. The difference between maximum and minimum of this interval measured over a 2 second period shall not exceed 2 mSec.", lambda c=ctx: check_frame_interval_tr10_9(c))
    add("TR-10-9-11.2b", "shall", "IPMX Senders shall send IPMX Sender Reports for each frame at regular intervals that correspond to the Frame-to-Frame Interval. The difference between maximum and minimum of this interval measured over a 2 second period shall not exceed 2 mSec.", lambda c=ctx: check_sr_interval_tr10_9(c))
    add("TR-10-9-11.2c", "shall", "For a Baseband IPMX Sender the Frame-to-Frame Interval shall correspond to the timing of their baseband input signal.", lambda _: untestable("Baseband input not observable"))
    add("TR-10-9-11.2d", "shall", "For IPMX Senders not based on the conversion of a baseband signal, the Frame-to-Frame interval shall correspond to the nominal frame rate of the media signal.", lambda _: untestable("Sender type not observable"))
    add("TR-10-9-16a", "shall", "IPMX Senders conforming to TR-10-7 (compressed video) shall mark RTP packets with the TR-10-9 §16 default DSCP AF42(36).", lambda c=ctx: check_dscp_rtp_marking(c.pcap, c.stream_info, 36))
    add("TR-10-9-16b", "shall", "IPMX Senders shall mark outgoing RTCP Sender Report packets with the same DSCP value as the respective RTP stream packets (TR-10-9 §16).", lambda c=ctx: check_dscp_sr_matches_rtp(c.pcap, c.stream_info, c.sender_reports))
    add("RFC1112-MCAST-MAC", "shall", "IPv4 multicast RTP packets SHALL use the RFC 1112 §6.4 Ethernet destination MAC derived from the group address (01:00:5e + low 23 bits).", lambda c=ctx: check_multicast_mac_mapping(c.pcap, c.stream_info))
    add("RFC1112-SR-MAC", "shall", "IPv4 multicast RTCP Sender Report packets SHALL use the RFC 1112 §6.4 Ethernet destination MAC of the group address.", lambda c=ctx: check_sr_mac_mapping(c.sender_reports))
    add("TR-10-1-8.7-SR-PORT", "shall", "RTCP Sender Reports SHALL be sent on the RTP destination port + 1 (TR-10-1 §8.7 / RFC 3550 §11).", lambda c=ctx: check_sr_rtcp_port(c.pcap, c.stream_info))
    add("TR-10-15b-100", "shall", "PACI packets defined in RFC 7798 shall not be produced by an IPMX Sender.", lambda c=ctx: check_paci(c))
    add("TR-10-15b-101", "shall", "A UDP/IP packet shall not contain more than one VCL NAL Unit.", lambda c=ctx: check_packet_vcl_limit(c))
    add("TR-10-15b-103", "shall", "H.265 coded video shall be transmitted and decoded using the HRD transmitter and decoder schedules.", lambda _: untestable("HRD presence verified by TR-10-15b-114; schedule conformance not testable from PCAP"))
    add("TR-10-1-MIB-SIG", "shall", "MIB baseband signal parameters shall be internally consistent (htotal >= width, vtotal >= height, pixclk = htotal*vtotal*fps).", lambda c=ctx: check_mib_signal_sanity(c))
    add("TR-10-15b-105", "shall", "Traffic shaping mode shall be set to TP=2110TPW and explicitly declared in the SDP fmtp attribute.", lambda c=ctx: check_sdp_tp_mode(c))
    add("TR-10-15b-107", "shall", "Buffering Period SEI messages shall be provided at each recovery point.", lambda c=ctx: check_buffering_period_sei(c))
    add("TR-10-15b-108", "shall", "Picture Timing SEI messages shall be provided for each access unit; pic_struct shall be provided for interlaced video.", lambda c=ctx: check_pic_timing_sei(c))
    add("TR-10-15b-109", "shall", "vps_timing_info_present_flag shall equal 1 and vps_num_units_in_tick/vps_time_scale shall match the frame rate.", lambda c=ctx: check_vps_timing(c))
    add("TR-10-15b-110", "shall", "vui_timing_info_present_flag shall equal 1 and vui_num_units_in_tick/vui_time_scale shall match the frame rate.", lambda c=ctx: check_timing_info(c))
    add("TR-10-15b-111d", "shall", "Decode order shall equal output order.", lambda c=ctx: check_reorder_flags(c))
    add("TR-10-15b-112a", "shall", "When using temporal layers, HRD parameters shall be specified for each temporal layer; otherwise for the base layer.", lambda c=ctx: check_hrd_parameters(c))
    add("TR-10-15b-112b", "shall", "The cpb_cnt_minus1 value of hrd_parameters() shall be 0 (for each temporal sub-layer when applicable).", lambda c=ctx: check_cpb_cnt(c))
    add("TR-10-15b-113a", "shall", "A coded bitstream shall conform to Type II HRD.", lambda _: untestable("Type II HRD not verifiable here"))
    add("TR-10-15b-113b", "shall", "nal_hrd_parameters_present_flag shall equal 1.", lambda c=ctx: check_nal_hrd_flag(c))
    add("TR-10-15b-114", "shall", "HRD parameters shall be specified in the VUI parameters of the SPS.", lambda c=ctx: check_hrd_present(c))
    add("TR-10-15b-116", "shall", "If sub-picture HRD mode is used, tick_divisor_minus2 shall be 0..254, sub_pic_hrd_params_present_flag shall be 1, sub_pic_cpb_params_in_pic_timing_sei_flag shall be 0, and decoding_unit_info SEI shall be provided.", lambda c=ctx: check_sub_pic_hrd(c))
    add("TR-10-15b-119", "shall", "A coded stream shall include a random access point at least once every 5 seconds.", lambda c=ctx: check_random_access(c))
    add("TR-10-15b-120", "shall", "Each random access point shall provide IDR/CRA/BLA and VPS/SPS/PPS, or SEI recovery_point.", lambda c=ctx: check_random_access_content(c))
    add("TR-10-15b-121", "shall", "The use of GDR shall be signaled through the recovery point SEI recovery_poc_cnt attribute.", lambda _: untestable("GDR signaling not parsed"))
    add("TR-10-15b-124", "shall", "An HEVC encoder supporting a monochrome bitstream shall support producing Main-444/Main10-444 4:0:0.", lambda c=ctx: check_monochrome_profile(c))
    add("TR-10-15b-127", "shall", "An HEVC decoder supporting a monochrome bitstream shall support consuming Main-444/Main10-444 4:0:0.", lambda _: untestable("Decoder capability not observable"))
    add("TR-10-15b-128", "shall", "An HEVC Receiver compliant with the IPMX HEVC Profile shall be capable of consuming Level 5.1 main tier.", lambda _: untestable("Receiver level capability not observable"))
    # The base IPMX HEVC Profile (4:2:0) and the 4:4:4 Profile Mode are validated
    # from separate captures, selected by --444 — mirroring the jxsv --tdc gating.
    # A single capture exhibits one profile; the other mode's "shall also be
    # compliant with the base Profile" leg (131/133) is untestable here and is
    # validated from a separate run without --444 (cf. TR-10-15a-TDC-BASE).
    if ctx.is_444:
        add("TR-10-15b-131", "shall", "An HEVC Sender compliant with the IPMX HEVC 4:4:4 Profile Mode shall be compliant with the IPMX HEVC Profile.", lambda _: untestable("Base IPMX HEVC Profile (4:2:0) leg not observable in a 4:4:4 capture — validate it from a separate capture without --444"))
        add("TR-10-15b-132", "shall", "An HEVC Sender compliant with the IPMX HEVC 4:4:4 Profile Mode shall support producing Main-444/Main10-444 YCbCr-444.", lambda c=ctx: check_444_profile(c))
        add("TR-10-15b-133", "shall", "An HEVC Receiver compliant with the IPMX HEVC 4:4:4 Profile Mode shall be compliant with the IPMX HEVC Profile.", lambda _: untestable("Base IPMX HEVC Profile (4:2:0) leg not observable in a 4:4:4 capture — validate it from a separate capture without --444"))
        add("TR-10-15b-134", "shall", "An HEVC Receiver compliant with the IPMX HEVC 4:4:4 Profile Mode shall be capable of consuming Main-444/Main10-444 YCbCr-444.", lambda _: untestable("Receiver profile mode capability not observable"))
    else:
        add("TR-10-15b-123", "shall", "An HEVC Sender compliant with the IPMX HEVC Profile shall support producing a bitstream compliant with Main/Main10 YCbCr-420.", lambda c=ctx: check_profile_levels(c))
        add("TR-10-15b-126", "shall", "An HEVC Receiver compliant with the IPMX HEVC Profile shall be capable of consuming Main/Main10 YCbCr-420.", lambda _: untestable("Receiver capability not observable"))
    add("TR-10-15b-137", "shall", "A decoder shall support consuming both H.265 CBR and VBR bitstreams.", lambda _: untestable("Decoder capability not observable"))
    add("TR-10-15b-139a", "shall", "Annexes F, G, H, and I of H.265 shall not be used.", lambda c=ctx: check_no_annexes_fghi(c))
    add("TR-10-15b-139b", "shall", "Multi-layer video coding shall be disabled, and nuh_layer_id shall be set to 0.", lambda c=ctx: check_nuh_layer_id(c))
    add("TR-10-15b-141", "shall", "Media Info Block shall provide stream parameters compliant with active VPS/SPS/PPS.", lambda c=ctx: check_h265_info_matches_stream(c))
    add("TR-10-15b-142", "shall", "RTCP Sender Report shall be sent before the first video media packet of the associated frame/field, if any.", lambda c=ctx: check_sr_before_au(c))
    add("TR-10-15b-144d", "shall", "Encoder shall start placing access units into the CPB after a constant encoder_delay from capture.", lambda _: untestable("encoder_delay not observable"))
    add("TR-10-15b-145a", "shall", "Encoder shall transmit the sender report before transmitting the coded access unit.", lambda c=ctx: check_sr_before_au(c))
    add("TR-10-15b-145b", "shall", "Encoder shall transmit the sender report no more than encoder_delay seconds after capture.", lambda _: untestable("encoder_delay not observable"))
    add("TR-10-15b-146a", "shall", "Sender reports shall be transmitted in presentation order.", lambda c=ctx: check_sr_order(c))
    add("TR-10-15b-146b", "shall", "If a frame/field is skipped, it shall not skip the associated sender report.", lambda c=ctx: check_sr_mapping(c))
    add("TR-10-1-SR-DIFF", "shall",
        "SR RTP timestamp deltas SHALL match the nominal frame increment (TR-10-1 §13.3b).",
        lambda c=ctx: _check_sr_diff_h26x(c))
    add("TR-10-1-FR-XVAL", "shall",
        "CLI --exactframerate SHALL match MIB rate_numerator/rate_denominator when both present.",
        lambda c=ctx: cross_validate_exactframerate(c.exact_framerate, c.sender_reports))
    add("TR-10-1-INTL-XVAL", "shall",
        "CLI --interlace SHALL match MIB interlace field when both present.",
        lambda c=ctx: cross_validate_interlace(c.interlace, c.sender_reports))
    add("TR-10-1-VP-XVAL", "shall",
        "CLI --width/--height/--sampling/--bit-depth SHALL match MIB video parameters when both present.",
        lambda c=ctx: cross_validate_video_params(c.width, c.height, c.sampling, c.bit_depth, c.sender_reports))
    add("TR-10-15b-149", "shall", "An H.265 coded stream shall carry an additional Media Info Block type 0x0009 immediately following type 0x0005.", lambda c=ctx: check_media_info_block(c))
    add("TR-10-15b-150", "shall", "Media Info Block parameters shall use the same syntax as the SDP fmtp line.", lambda c=ctx: check_mib_vs_sdp_fmtp_h265(c))
    add("TR-10-15b-151", "shall", "When a value is not provided, associated bytes shall be 0x00 and length shall be 0.", lambda c=ctx: check_h265_info_mask(c))
    add("TR-10-15b-237", "shall", "Variable-length section size shall be rounded to a multiple of 4 bytes following the 44th byte.", lambda c=ctx: check_h265_info_variable_len(c))
    add("TR-10-15b-239", "shall", "Media Info Block shall be 32-bit aligned and length shall equal (words - 1).", lambda c=ctx: check_media_info_lengths(c))
    add("TR-10-15b-240", "shall", "If parameters are present in SDP fmtp, they shall also be present in the media info block.", lambda c=ctx: check_sdp_fmtp_in_mib_h265(c))

    # SHOULD requirements
    add("TR-10-15b-111a", "should", "max_vps_num_reorder_pics should be 0.", lambda c=ctx: check_reorder_flags(c))
    add("TR-10-15b-111b", "should", "sps_max_num_reorder_pics should be 0.", lambda c=ctx: check_reorder_flags(c))
    add("TR-10-15b-111c", "should", "NoBackwardPredFlag should equal 1.", lambda c=ctx: check_no_backward_pred(c))
    add("TR-10-15b-144a", "should", "Encoder should transmit sender reports at the nominal frame interval.", lambda c=ctx: check_sr_interval(c))
    add("TR-10-15b-144b", "should", "Coded access units should be put into the CPB at the nominal interval.", lambda c=ctx: check_au_interval_const(c))
    add("TR-10-1-NTP-RATE", "should",
        "SR NTP deltas SHOULD match PCAP capture deltas — sender and capture clocks should advance at the same rate.",
        lambda c=ctx: check_sr_ntp_vs_capture_rate(c.sender_reports))
    add("TR-10-1-NTP-SELF", "should",
        "SR NTP timestamps SHOULD be self-consistent — inter-SR intervals should match the nominal frame period.",
        lambda c=ctx: check_sr_ntp_self_consistent(c.sender_reports))
    add("TR-10-1-8.6-INIT-RTP", "shall",
        "First SR RTP timestamp shall be synchronized with the Internal Clock (TR-10-1 §8.6).",
        lambda c=ctx: check_sr_initial_rtp_clock(c.sender_reports, CLOCK_RATE))
    add("TR-10-1-8.7-RC", "should",
        "RTCP SR reception report count (RC) should be 0 (TR-10-1 §8.7).",
        lambda c=ctx: check_sr_rc_zero(c.sender_reports))
    add("TR-10-1-8.7-COMPOUND", "shall",
        "RTCP Sender Reports shall be sent in a compound RTCP packet — report "
        "packet first and an SDES CNAME item present (RFC 3550 §6.1, TR-10-1 §8.7).",
        lambda c=ctx: check_sr_compound_packet(c.pcap, c.stream_info))
    add("TR-10-1-10.1-IPMX-FMTP", "shall",
        "SDP a=fmtp line shall contain the IPMX keyword (TR-10-1 §10.1).",
        lambda c=ctx: check_sdp_ipmx_fmtp(c.sdp_media))
    add("IPMX-SDP-WRAPPER", "shall",
        "SDP shall satisfy RFC 7798 + ST 2110-10 + ST 2110-22 + IPMX fmtp + "
        "TR-10-9 §17 source-filter (multicast)",
        lambda c=ctx: check_sdp_wrapper(c))
    add("SDP-DST-IP", "shall",
        "SDP connection address SHALL match the detected destination IP.",
        lambda c=ctx: _check_sdp_dst_ip(c))

    return reqs


def _check_sdp_dst_ip(ctx: ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    from ipmx_validate_common import check_sdp_dst_ip_vs_stream
    return check_sdp_dst_ip_vs_stream(ctx.sdp_media, ctx.stream_info)


def run_validation(ctx: ValidationContext) -> list[RequirementResult]:
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
            elif len(result) == 1:
                passed = bool(result[0])
                details = "No details"
        else:
            passed = bool(result)
            details = "No details"
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
    testable = [res for res in results if res.testable]
    if len(testable) == len(results):
        return summarize_results(results)
    passed = sum(1 for res in testable if res.passed)
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


def _run_cmax_check(ctx: ValidationContext) -> list[RequirementResult]:
    """Simulate ST 2110-21 CMAX using HRD bitrate-derived equivalent packets/frame."""
    sps = ctx.timeline.header_fields.get("SPS") if ctx.timeline else None
    hrd = ipmx_validate_hrd.extract_hrd_parameters(sps) if sps else None
    return run_cmax_hrd_check(
        packets=ctx.rtp_report.packets,
        hrd_bit_rate=hrd.bit_rate if hrd else None,
        exact_framerate=_resolve_exactframerate(ctx),
    )


def main() -> int:
    configure_utf8_output()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, nargs="?", help="PCAP file containing RTP/RTCP")
    parser.add_argument("--list-requirements", action="store_true", help="List all requirement IDs this validator checks, then exit (no PCAP needed)")
    parser.add_argument("--port", type=int, help="Filter RTP packets by UDP port")
    parser.add_argument("--rtcp-port", type=int, help="Filter RTCP packets by UDP port")
    parser.add_argument("--frames", type=int, default=5, help="Frames to sample with ffmpeg")
    parser.add_argument("--max-access-units", type=int, help="Limit access units processed")
    parser.add_argument(
        "--wallclock-backstep-threshold",
        type=float,
        help=(
            "Backward capture-time jump (seconds) considered a wallclock disruption; "
            "default is max(0.050, 3 * nominal period)"
        ),
    )
    parser.add_argument(
        "--full-report",
        action="store_true",
        help="Include all requirements (pass, fail, cannot test)",
    )
    parser.add_argument(
        "--pass-report",
        action="store_true",
        help="Show only passing requirements",
    )
    parser.add_argument(
        "--fail-report",
        action="store_true",
        help="Show only failing requirements",
    )
    parser.add_argument(
        "--cannot-test-report",
        action="store_true",
        help="Show only requirements that cannot be tested",
    )
    parser.add_argument(
        "--exactframerate",
        type=str,
        help="Exact framerate as integer or num/den (e.g. 60, 60000/1001)",
    )
    parser.add_argument(
        "--interlace",
        action="store_true",
        default=None,
        help="Stream is interlaced (enables frame_field_info_present_flag check)",
    )
    parser.add_argument("--width", type=int, help="Expected video width in pixels")
    parser.add_argument("--height", type=int, help="Expected video height in pixels")
    parser.add_argument(
        "--sampling",
        type=str,
        help="Expected chroma sampling (e.g. YCbCr-4:2:0, YCbCr-4:2:2, YCbCr-4:4:4)",
    )
    parser.add_argument("--bit-depth", type=int, dest="bit_depth", help="Expected bit depth (e.g. 8, 10)")
    parser.add_argument("--sdp", type=Path, help="SDP transport file for cross-validation")
    parser.add_argument(
        "--hrd",
        action="store_true",
        help="Enable HRD self-consistency checks (Tier 1)",
    )
    parser.add_argument(
        "--hrd-sim",
        action="store_true",
        help="Enable CPB leaky-bucket simulation (Tier 2, implies --hrd)",
    )
    parser.add_argument(
        "--hrd-timing",
        action="store_true",
        help="Enable PCAP timing cross-validation against HRD model (Tier 3, implies --hrd)",
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
    parser.add_argument(
        "--allow-superset-profile",
        action="store_true",
        help="Accept superset profiles (e.g. Rext 4:2:2 includes Main 10 4:2:0 capability)",
    )
    parser.add_argument(
        "--444",
        dest="is_444",
        action="store_true",
        help="Test conformance to the IPMX HEVC 4:4:4 Profile Mode; enables the "
             "TR-10-15b-131..134 4:4:4 Profile Mode requirements (authoritative, "
             "analogous to --tdc for JPEG XS)",
    )
    parser.add_argument(
        "--cfg",
        type=str,
        help="Stream descriptor (streams/cfg/*.cfg, by path or bare name) to seed "
             "expected-value flags (--exactframerate/--width/--height/--sampling/"
             "--bit-depth); explicit flags on the command line override the cfg",
    )
    args = parser.parse_args()

    if args.list_requirements:
        from types import SimpleNamespace
        from ipmx_validate_common import print_requirements_list
        print_requirements_list(Path(__file__).name, build_requirements(SimpleNamespace(is_444=bool(args.is_444))))
        return 0

    if args.pcap is None:
        parser.error("the pcap argument is required unless --list-requirements is used")

    if args.cfg:
        from ipmx_validate_common import (
            apply_video_cfg,
            parse_cfg_file,
            resolve_cfg_path,
        )
        apply_video_cfg(args, parse_cfg_file(resolve_cfg_path(args.cfg)), ycbcr_only=True)

    if not args.pcap.exists():
        raise SystemExit(f"{args.pcap} does not exist")
    if args.max_access_units is not None and args.max_access_units <= 0:
        raise SystemExit("--max-access-units must be positive")

    ctx = build_context(args)
    print_recovery_window_note(ctx.rtp_report)
    if ctx.timeline is not None and ctx.timeline.trace_warning:
        print(ctx.timeline.trace_warning, file=sys.stderr)
    if ctx.encrypted:
        print("[INFO] Encryption detected — payload content is not accessible.")
        print("       NAL content checks will be marked as untestable.\n")
    print_first_sr_block_version(ctx.sender_reports)
    results = run_validation(ctx)

    hrd_results = ipmx_validate_hrd.run_hrd_checks(
        ctx,
        enable_hrd=args.hrd,
        enable_hrd_sim=args.hrd_sim,
        enable_hrd_timing=args.hrd_timing,
    )
    results.extend(hrd_results)

    subpic_results = ipmx_validate_hrd_subpic.run_subpic_hrd_checks(
        ctx,
        enable_hrd=args.hrd,
        enable_hrd_sim=args.hrd_sim,
        enable_hrd_timing=args.hrd_timing,
    )
    results.extend(subpic_results)

    enc_results = ipmx_validate_encryption.run_encryption_checks(
        packets=ctx.rtp_report.packets,
        sender_reports=ctx.sender_reports,
        sdp_media=ctx.sdp_media,
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
