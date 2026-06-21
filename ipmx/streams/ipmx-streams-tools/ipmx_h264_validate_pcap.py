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
"""Validate an H.264 IPMX PCAP against VSF TR-10-15c requirements."""

from __future__ import annotations

import argparse
import base64
import sys
from pathlib import Path
from typing import Any

from fractions import Fraction

import ipmx_parse_rtp_pcap
import ipmx_validate_encryption
import ipmx_validate_hrd_h264
from MatroxSdp import MatroxSdp, MatroxSdpEnums, MediaDescriptor
from MatroxSdpCheck import (
    SdpCheckError,
    check_sdp_rfc6184,
    check_sdp_st2110_10,
    check_sdp_st2110_22,
)
from ipmx_validate_common import (
    CLOCK_RATE,
    Requirement,
    RequirementResult,
    ValidationContext,
    build_rtp_report,
    build_timeline,
    check_sdp_ipmx_fmtp,
    check_sdp_multicast_source_filter,
    check_sdp_session_consistency,
    check_sr_initial_rtp_clock,
    check_sr_ntp_self_consistent,
    check_sr_ntp_vs_capture_rate,
    check_sr_rc_zero,
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
    rate_matches,
    resolve_exact_ticks_per_frame,
    run_cmax_hrd_check,
    summarize_results,
    untestable,
    unwrap_rtp_timestamps,
)

PIXCLK_TOLERANCE_PPM = 100

H264_EXTENSION_NAL_TYPES = {14, 15, 20, 21}

H264_SVC_PROFILES = {83, 86}
H264_MVC_PROFILES = {118, 128, 134}
H264_MVCD_PROFILES = {138, 135}
H264_3DAVC_PROFILES = {139}
H264_FORBIDDEN_ANNEX_PROFILES = (
    H264_SVC_PROFILES | H264_MVC_PROFILES | H264_MVCD_PROFILES | H264_3DAVC_PROFILES
)

H264_INFO_FIELD_BITS = {
    "profile_level_id": 0,
    "packetization_mode": 1,
    "sprop_max_don_diff": 2,
    "sprop_interleaving_depth": 3,
    "sprop_deint_buf_req": 4,
    "sprop_init_buf_time": 5,
    "sprop_parameter_sets": 6,
    "sprop_level_parameter_sets": 7,
    "extra_bytes": 8,
}


def parse_h264_media_info(payload: bytes) -> dict[str, Any]:
    if len(payload) < 24:
        return {"error": "payload too short"}
    data: dict[str, Any] = {}
    data["mask"] = int.from_bytes(payload[0:4], "big")
    data["profile_level_id"] = payload[4:7]
    data["packetization_mode"] = payload[7]
    data["sprop_max_don_diff"] = int.from_bytes(payload[8:10], "big")
    data["sprop_interleaving_depth"] = int.from_bytes(payload[10:12], "big")
    data["sprop_deint_buf_req"] = int.from_bytes(payload[12:16], "big")
    data["sprop_init_buf_time"] = int.from_bytes(payload[16:20], "big")
    data["sprop_parameter_sets_len"] = payload[20]
    data["sprop_level_parameter_sets_len"] = payload[21]
    data["extra_len"] = payload[22]
    data["reserved"] = payload[23]
    cursor = 24
    ps_len = data["sprop_parameter_sets_len"]
    lps_len = data["sprop_level_parameter_sets_len"]
    extra_len = data["extra_len"]
    data["sprop_parameter_sets"] = payload[cursor : cursor + ps_len]
    cursor += ps_len
    data["sprop_level_parameter_sets"] = payload[cursor : cursor + lps_len]
    cursor += lps_len
    data["extra_bytes"] = payload[cursor : cursor + extra_len]
    cursor += extra_len
    data["padding"] = payload[cursor:]
    return data


def _is_interlaced(ctx: ValidationContext) -> bool | None:
    """Determine interlace status: CLI > MIB > None (unknown)."""
    if ctx.interlace is not None:
        return ctx.interlace
    return extract_interlace_from_sr(ctx.sender_reports)


def load_sdp_h264_params(sdp_path: Path) -> MediaDescriptor:
    """Parse an SDP file and return the media descriptor for H.264."""
    sdp = MatroxSdp()
    err = sdp.decode(sdp_path.read_text())
    if err:
        raise SystemExit(f"SDP parse error: {err}")
    md = sdp.primary_media
    if md is None:
        raise SystemExit("SDP contains no media descriptor")
    if md.encoding_name != MatroxSdpEnums.EncodingH264:
        raise SystemExit(
            f"SDP encoding is '{md.encoding_name}', expected 'H264'"
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
        rtp_port = infer_rtp_port(args.pcap, "h264")
    rtp_report = build_rtp_report(
        args.pcap,
        "h264",
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
            "h264",
            rtp_port,
            sr_prefix,
            args.wallclock_backstep_threshold,
            stream_info=si,
        )
        au_ts = {au.timestamp for au in rtp_report.access_units}
        sender_reports = [sr for sr in sender_reports if sr.rtp_timestamp in au_ts]
    timeline = build_timeline(rtp_report, "h264", args.frames)
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
        sdp_media = load_sdp_h264_params(args.sdp)

    return ValidationContext(
        pcap=args.pcap,
        codec="h264",
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
    )


def find_media_block(sr_info, block_type: int) -> Any:
    if sr_info.ipmx_info is None:
        return None
    for block in sr_info.ipmx_info.media_blocks:
        if block.media_info_type == block_type:
            return block
    return None


def collect_param_sets(ctx: ValidationContext) -> dict[str, list[bytes]]:
    sps = []
    pps = []
    for nalu in ctx.rtp_report.nalus_bytes:
        payload = nalu[4:] if nalu.startswith(b"\x00\x00\x00\x01") else nalu
        if not payload:
            continue
        nal_type = payload[0] & 0x1F
        if nal_type == 7:
            sps.append(payload)
        elif nal_type == 8:
            pps.append(payload)
    return {"sps": sps, "pps": pps}


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


def parse_h264_sps_profile_level_id(sps_nalu: bytes) -> bytes | None:
    """Extract the 3-byte profile_level_id from a raw H.264 SPS NAL unit.

    Layout after the 1-byte NAL header:
      byte 0: profile_idc
      byte 1: constraint_set flags
      byte 2: level_idc
    """
    if len(sps_nalu) < 4:  # 1 NAL header + 3 bytes
        return None
    return bytes(sps_nalu[1:4])


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
        "uncompressed streams; compressed H.264 follows HRD schedule"
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
            if ipmx_parse_rtp_pcap.is_vcl_nal("h264", nal)
        ]
        if len(vcl) > 1:
            violations += 1
    if violations:
        return False, f"{violations} packets contain multiple VCL NAL units"
    return True, "No packets contain multiple VCL NAL units"


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
        if 5 in au.nal_types:
            ra_times.append((ts - base) / CLOCK_RATE)
    if not ra_times:
        return False, "No IDR access units detected in capture"
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
        if 5 not in au.nal_types:
            continue
        has_ra = True
        has_sps = 7 in au.nal_types
        has_pps = 8 in au.nal_types
        has_sei = 6 in au.nal_types
        if not ((has_sps and has_pps) or has_sei):
            failures += 1
    if not has_ra:
        return untestable("No IDR access units detected to validate content")
    if failures:
        return False, f"{failures} IDR access units missing SPS/PPS or SEI"
    return True, "IDR access units include required NAL units"


def check_no_annexes_fghij(ctx: ValidationContext) -> tuple[bool, str]:
    """Annexes F, G, H, I and J of H.264 shall not be used.

    Detected via:
    - NAL unit types 14 (prefix), 15 (subset SPS), 20 (SVC/MVC coded slice),
      21 (3D-AVC coded slice) per ITU-T H.264 section 7.3.1.
    - SPS profile_idc values associated with SVC (83, 86), MVC (118, 128, 134),
      MVCD (138, 135), and 3D-AVC (139) per section 7.3.2.1.3.
    """
    if ctx.encrypted:
        return untestable("Payload encrypted — NAL content not accessible")
    violations: list[str] = []

    forbidden_nals: set[int] = set()
    for au in ctx.rtp_report.access_units:
        forbidden_nals.update(au.nal_types & H264_EXTENSION_NAL_TYPES)
    if forbidden_nals:
        type_names = {14: "prefix (SVC/MVC)", 15: "subset SPS", 20: "coded slice ext (SVC/MVC)", 21: "coded slice 3D-AVC"}
        desc = ", ".join(f"{t} ({type_names.get(t, '?')})" for t in sorted(forbidden_nals))
        violations.append(f"Extension NAL types present: {desc}")

    if ctx.timeline is not None:
        sps = ctx.timeline.header_fields.get("SPS")
        if sps is not None:
            profile_idc = get_int_field(sps, "profile_idc")
            if profile_idc is not None and profile_idc in H264_FORBIDDEN_ANNEX_PROFILES:
                annex = "G (SVC)" if profile_idc in H264_SVC_PROFILES else \
                        "H (MVC)" if profile_idc in H264_MVC_PROFILES else \
                        "I (MVCD)" if profile_idc in H264_MVCD_PROFILES else \
                        "I+J (3D-AVC)" if profile_idc in H264_3DAVC_PROFILES else "?"
                violations.append(f"profile_idc={profile_idc} indicates Annex {annex}")

    if violations:
        return False, "Forbidden annex extensions detected: " + "; ".join(violations)
    return True, "No Annex F/G/H/I/J extensions present"


CHROMA_FORMAT_TO_SAMPLING: dict[int, str] = {
    0: "YCbCr-4:0:0",
    1: "YCbCr-4:2:0",
    2: "YCbCr-4:2:2",
    3: "YCbCr-4:4:4",
}


def _h264_sps_resolution(sps: dict[str, Any]) -> tuple[int | None, int | None]:
    """Compute pixel width/height from H.264 SPS macroblock fields."""
    mbs_w = get_int_field(sps, "pic_width_in_mbs_minus1")
    mbs_h = get_int_field(sps, "pic_height_in_map_units_minus1")
    frame_mbs_only = get_int_field(sps, "frame_mbs_only_flag")
    if mbs_w is None or mbs_h is None:
        return None, None
    width = (mbs_w + 1) * 16
    height = (mbs_h + 1) * 16 * (2 - (frame_mbs_only if frame_mbs_only is not None else 1))

    crop_flag = get_int_field(sps, "frame_cropping_flag")
    if crop_flag == 1:
        chroma_idc = get_int_field(sps, "chroma_format_idc")
        if chroma_idc is None:
            chroma_idc = 1
        sub_w = 2 if chroma_idc in (1, 2) else 1
        sub_h = 2 if chroma_idc == 1 else 1
        if frame_mbs_only is not None and frame_mbs_only == 0:
            sub_h *= 2
        cl = get_int_field(sps, "frame_crop_left_offset") or 0
        cr = get_int_field(sps, "frame_crop_right_offset") or 0
        ct = get_int_field(sps, "frame_crop_top_offset") or 0
        cb = get_int_field(sps, "frame_crop_bottom_offset") or 0
        width -= sub_w * (cl + cr)
        height -= sub_h * (ct + cb)

    return width, height


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

    sps_width, sps_height = _h264_sps_resolution(sps)
    if sps_width is not None and ref_width is not None and sps_width != ref_width:
        src = "CLI" if ctx.width is not None else "MIB"
        mismatches.append(f"width SPS={sps_width} {src}={ref_width}")
    if sps_height is not None and ref_height is not None and sps_height != ref_height:
        src = "CLI" if ctx.height is not None else "MIB"
        mismatches.append(f"height SPS={sps_height} {src}={ref_height}")

    chroma_idc = get_int_field(sps, "chroma_format_idc")
    if chroma_idc is None:
        chroma_idc = 1
    if ref_sampling is not None:
        sps_sampling = CHROMA_FORMAT_TO_SAMPLING.get(chroma_idc)
        if sps_sampling is not None and sps_sampling != ref_sampling:
            src = "CLI" if ctx.sampling is not None else "MIB"
            mismatches.append(
                f"sampling SPS chroma_format_idc={chroma_idc} ({sps_sampling}) "
                f"{src}={ref_sampling}"
            )

    sps_bd = get_int_field(sps, "bit_depth_luma_minus8")
    if sps_bd is None:
        sps_bd = 0
    if ref_bit_depth is not None:
        sps_bit_depth = sps_bd + 8
        if sps_bit_depth != ref_bit_depth:
            src = "CLI" if ctx.bit_depth is not None else "MIB"
            mismatches.append(f"bit_depth SPS={sps_bit_depth} {src}={ref_bit_depth}")

    if mismatches:
        return False, "SPS vs signal params mismatch: " + "; ".join(mismatches)
    return True, "SPS signal description matches reference parameters"


def check_vui_flags(ctx: ValidationContext) -> tuple[bool, str]:
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        return untestable("No SPS fields parsed")
    required = {
        "video_signal_type_present_flag": 1,
        "colour_description_present_flag": 1,
        "timing_info_present_flag": 1,
        "nal_hrd_parameters_present_flag": 1,
    }
    missing = []
    for key, expected in required.items():
        value = get_int_field(sps, key)
        if value != expected:
            missing.append(f"{key}={value}")
    is_interlaced = _is_interlaced(ctx)
    if is_interlaced is True:
        pic_struct = get_int_field(sps, "pic_struct_present_flag")
        if pic_struct != 1:
            missing.append(f"pic_struct_present_flag={pic_struct} (SHALL be 1 for interlaced)")
    if missing:
        return False, "Missing/incorrect VUI flags: " + ", ".join(missing)
    return True, "Required VUI flags are set"


def check_timing_info(ctx: ValidationContext) -> tuple[bool, str]:
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        return untestable("No SPS fields parsed")
    flag = get_int_field(sps, "timing_info_present_flag")
    num_units = get_int_field(sps, "num_units_in_tick")
    time_scale = get_int_field(sps, "time_scale")
    if flag != 1 or num_units is None or time_scale is None:
        return False, "Timing info missing"
    nominal = compute_nominal_period([au.timestamp for au in ctx.rtp_report.access_units])
    if nominal is None:
        return untestable("Cannot derive nominal period")
    observed_rate = 1.0 / nominal
    expected_rate = time_scale / (2 * num_units)
    if not rate_matches(expected_rate, observed_rate):
        return False, f"Timing rate {expected_rate:.3f} vs observed {observed_rate:.3f}"
    return True, "Timing info matches observed frame rate"


_H264_PROFILE_SUPERSET: dict[int, set[int]] = {
    77: set(),
    100: {77},
    110: {77, 100},
    122: {77, 100, 110},
    244: {77, 100, 110, 122},
}
"""H.264 profile superset hierarchy (ITU-T H.264 Annex A).

Key = profile_idc, value = set of profile_idc values it is a superset of.
- High (100) is a superset of Main (77).
- High 10 (110) is a superset of High and Main.
- High 4:2:2 (122) is a superset of High 10, High, and Main.
- High 4:4:4 Predictive (244) is a superset of all above.
"""


def check_profile_levels(ctx: ValidationContext) -> tuple[bool, str]:
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        return untestable("No SPS fields parsed")
    profile_idc = get_int_field(sps, "profile_idc")
    chroma = get_int_field(sps, "chroma_format_idc")
    bit_depth = get_int_field(sps, "bit_depth_luma_minus8")
    if bit_depth is None:
        bit_depth = get_int_field(sps, "bit_depth_chroma_minus8")
    if chroma is None:
        chroma = 1
    if bit_depth is None:
        bit_depth = 0
    required = {77, 100}
    if profile_idc not in required:
        if ctx.allow_superset_profile and any(
            profile_idc in _H264_PROFILE_SUPERSET
            and req in _H264_PROFILE_SUPERSET[profile_idc]
            for req in required
        ):
            return True, (
                f"Profile {profile_idc} is a superset of Main/High "
                f"(--allow-superset-profile)"
            )
        return False, f"Profile {profile_idc} is not Main/High"
    if chroma != 1:
        return False, f"chroma_format_idc={chroma} is not 4:2:0"
    if bit_depth != 0:
        return False, f"bit_depth_luma_minus8={bit_depth} not 8-bit"
    return True, "Profile/chroma/bit depth match IPMX H.264 profile"


def check_paff_not_used(ctx: ValidationContext) -> tuple[bool, str]:
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        return untestable("No SPS fields parsed")
    frame_mbs_only = get_int_field(sps, "frame_mbs_only_flag")
    if frame_mbs_only == 1:
        return True, "Progressive stream; PAFF not used"
    mbaff = get_int_field(sps, "mb_adaptive_frame_field_flag")
    if mbaff == 1:
        return True, "MBAFF interlace; PAFF not used"
    return False, "Cannot confirm PAFF is disabled"


def check_max_reorder(ctx: ValidationContext) -> tuple[bool, str]:
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        return untestable("No SPS fields parsed")
    value = get_int_field(sps, "max_num_reorder_frames")
    if value != 0:
        return False, f"max_num_reorder_frames={value}"
    return True, "max_num_reorder_frames is 0"


def check_decode_order(ctx: ValidationContext) -> tuple[bool, str]:
    return check_max_reorder(ctx)


def check_cpb_cnt(ctx: ValidationContext) -> tuple[bool, str]:
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        return untestable("No SPS fields parsed")
    cpb = get_int_field(sps, "cpb_cnt_minus1")
    if cpb is None:
        return False, "cpb_cnt_minus1 not present"
    if cpb != 0:
        return False, f"cpb_cnt_minus1={cpb}"
    return True, "cpb_cnt_minus1 is 0"


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


def check_hrd_present(ctx: ValidationContext) -> tuple[bool, str]:
    """HRD parameters shall be specified in the VUI of the SPS with NAL HRD enabled."""
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        return untestable("No SPS fields parsed")
    nal_hrd = get_int_field(sps, "nal_hrd_parameters_present_flag")
    if nal_hrd != 1:
        return False, f"nal_hrd_parameters_present_flag={nal_hrd}"
    return True, "HRD parameters present in VUI with NAL HRD enabled"


def check_cpb_cnt(ctx: ValidationContext) -> tuple[bool, str]:
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        return untestable("No SPS fields parsed")
    cpb = get_int_field(sps, "cpb_cnt_minus1")
    if cpb is None:
        return False, "cpb_cnt_minus1 not present"
    if cpb != 0:
        return False, f"cpb_cnt_minus1={cpb}"
    return True, "cpb_cnt_minus1 is 0"


def check_hrd_parameters(ctx: ValidationContext) -> tuple[bool, str]:
    """Validate HRD parameter values: BitRate >= actual, CpbSize > 0, delay lengths sane."""
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        return untestable("No SPS fields parsed")
    if get_int_field(sps, "nal_hrd_parameters_present_flag") != 1:
        return untestable("NAL HRD parameters not present")

    bit_rate_scale = get_int_field(sps, "bit_rate_scale")
    bit_rate_val = get_int_field(sps, "bit_rate_value_minus1[0]")
    cpb_size_scale = get_int_field(sps, "cpb_size_scale")
    cpb_size_val = get_int_field(sps, "cpb_size_value_minus1[0]")
    if any(v is None for v in (bit_rate_scale, bit_rate_val, cpb_size_scale, cpb_size_val)):
        return untestable("HRD bit_rate/cpb_size fields not found in trace")

    declared_bitrate = (bit_rate_val + 1) * (2 ** (6 + bit_rate_scale))
    declared_cpb_size = (cpb_size_val + 1) * (2 ** (4 + cpb_size_scale))

    issues: list[str] = []

    if declared_bitrate <= 0:
        issues.append("declared BitRate is 0")
    if declared_cpb_size <= 0:
        issues.append("declared CpbSize is 0")

    HRD_BITRATE_MARGIN = 0.05
    aus = ctx.rtp_report.access_units
    if len(aus) >= 2:
        total_bits = sum(len(n) for n in ctx.rtp_report.nalus_bytes) * 8
        duration_s = (aus[-1].timestamp - aus[0].timestamp) / CLOCK_RATE
        if duration_s > 0:
            actual_avg_bps = total_bits / duration_s
            if declared_bitrate * (1 + HRD_BITRATE_MARGIN) < actual_avg_bps:
                issues.append(
                    f"declared BitRate {declared_bitrate / 1e6:.2f} Mbps "
                    f"< actual average {actual_avg_bps / 1e6:.2f} Mbps "
                    f"(>{HRD_BITRATE_MARGIN:.0%} margin exceeded)"
                )

    init_delay_len = get_int_field(sps, "initial_cpb_removal_delay_length_minus1")
    au_delay_len = get_int_field(sps, "cpb_removal_delay_length_minus1")
    dpb_delay_len = get_int_field(sps, "dpb_output_delay_length_minus1")
    for name, val in [
        ("initial_cpb_removal_delay_length_minus1", init_delay_len),
        ("cpb_removal_delay_length_minus1", au_delay_len),
        ("dpb_output_delay_length_minus1", dpb_delay_len),
    ]:
        if val is not None and (val < 0 or val > 31):
            issues.append(f"{name}={val} out of range [0..31]")

    if issues:
        return False, "; ".join(issues)

    detail = (
        f"BitRate={declared_bitrate / 1e6:.2f} Mbps, "
        f"CpbSize={declared_cpb_size / 1e6:.2f} Mbit"
    )
    if len(aus) >= 2:
        total_bits = sum(len(n) for n in ctx.rtp_report.nalus_bytes) * 8
        duration_s = (aus[-1].timestamp - aus[0].timestamp) / CLOCK_RATE
        if duration_s > 0:
            detail += f", actual avg={total_bits / duration_s / 1e6:.2f} Mbps"
    return True, detail


def check_media_info_block(ctx: ValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No sender reports"
    sr = ctx.sender_reports[0]
    if sr.ipmx_info is None:
        return False, "No IPMX Info Block in SR"
    types = [block.media_info_type for block in sr.ipmx_info.media_blocks]
    if 0x0005 not in types or 0x000A not in types:
        return False, "Missing 0x0005 or 0x000A media info blocks"
    idx_0005 = types.index(0x0005)
    idx_000a = types.index(0x000A)
    if idx_000a != idx_0005 + 1:
        return False, f"0x000A does not immediately follow 0x0005 (positions {idx_0005}, {idx_000a})"
    return True, "Required media info blocks present and immediately ordered"


def check_media_info_lengths(ctx: ValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No sender reports"
    sr = ctx.sender_reports[0]
    block = find_media_block(sr, 0x000A)
    if block is None:
        return False, "Missing 0x000A media info block"
    total = (block.length_words + 1) * 4
    if len(block.payload) + 4 != total:
        return False, "Media info block length field does not match payload size"
    if total % 4 != 0:
        return False, "Media info block is not 32-bit aligned"
    return True, "Media info block length is aligned"


def check_h264_info_mask(ctx: ValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No sender reports"
    sr = ctx.sender_reports[0]
    block = find_media_block(sr, 0x000A)
    if block is None:
        return False, "Missing 0x000A media info block"
    data = parse_h264_media_info(block.payload)
    if "error" in data:
        return False, data["error"]
    mask = data["mask"]
    failures = []
    fixed_fields = [
        "profile_level_id",
        "packetization_mode",
        "sprop_max_don_diff",
        "sprop_interleaving_depth",
        "sprop_deint_buf_req",
        "sprop_init_buf_time",
    ]
    for field in fixed_fields:
        bit = H264_INFO_FIELD_BITS[field]
        if not (mask & (1 << bit)):
            value = data[field]
            if isinstance(value, bytes):
                if any(b != 0 for b in value):
                    failures.append(field)
            else:
                if value != 0:
                    failures.append(field)
    for field in ("sprop_parameter_sets", "sprop_level_parameter_sets", "extra_bytes"):
        bit = H264_INFO_FIELD_BITS[field]
        length_key = field + "_len"
        if field == "extra_bytes":
            length_key = "extra_len"
        length = data[length_key]
        if not (mask & (1 << bit)):
            if length != 0 or data[field]:
                failures.append(field)
    if failures:
        return False, "Fields present without mask bit: " + ", ".join(failures)
    return True, "FIELD-PRESENT-MASK matches payload content"


def check_h264_info_variable_len(ctx: ValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No sender reports"
    sr = ctx.sender_reports[0]
    block = find_media_block(sr, 0x000A)
    if block is None:
        return False, "Missing 0x000A media info block"
    data = parse_h264_media_info(block.payload)
    if "error" in data:
        return False, data["error"]
    variable_len = (
        data["sprop_parameter_sets_len"]
        + data["sprop_level_parameter_sets_len"]
        + data["extra_len"]
    )
    fixed_len = 24
    total = fixed_len + variable_len
    padded = total if total % 4 == 0 else total + (4 - (total % 4))
    if len(block.payload) != padded:
        return False, f"Variable section length {variable_len} does not align to 4 bytes"
    return True, "Variable section length matches padding requirement"


def check_h264_info_matches_stream(ctx: ValidationContext) -> tuple[bool, str]:
    """Verify MIB 0x000A against the coded stream.

    1. Extract profile_level_id from the stream's first SPS and compare
       against the MIB fixed field (when the mask bit is set).
    2. If the MIB also carries raw sprop_parameter_sets, the first SPS and
       PPS from the stream must be byte-identical to the MIB copies.
    """
    if ctx.encrypted:
        return untestable("Payload encrypted — NAL content not accessible")
    if not ctx.sender_reports:
        return False, "No sender reports"
    sr = ctx.sender_reports[0]
    block = find_media_block(sr, 0x000A)
    if block is None:
        return False, "Missing 0x000A media info block"
    data = parse_h264_media_info(block.payload)
    if "error" in data:
        return False, data["error"]

    param_sets = collect_param_sets(ctx)
    mask = data["mask"]
    mismatches: list[str] = []

    # --- Part 1: compare MIB profile_level_id against stream SPS ---
    stream_sps_list = param_sets.get("sps", [])
    if not stream_sps_list:
        return untestable("No SPS NAL units found in stream — cannot verify MIB fields")

    pli_bit = H264_INFO_FIELD_BITS["profile_level_id"]
    if mask & (1 << pli_bit):
        stream_pli = parse_h264_sps_profile_level_id(stream_sps_list[0])
        if stream_pli is None:
            return untestable("First SPS too short to extract profile_level_id")
        mib_pli = bytes(data["profile_level_id"])
        if mib_pli != stream_pli:
            mismatches.append(
                f"profile_level_id MIB={mib_pli.hex()} stream={stream_pli.hex()}"
            )

    # --- Part 2: if MIB carries raw param sets, first from stream must be identical ---
    ps_bit = H264_INFO_FIELD_BITS["sprop_parameter_sets"]
    if (mask & (1 << ps_bit)) and data["sprop_parameter_sets"]:
        decoded_sets = decode_base64_sets(data["sprop_parameter_sets"])
        for decoded in decoded_sets:
            if not decoded:
                continue
            nal_type = decoded[0] & 0x1F
            if nal_type == 7:
                if stream_sps_list and decoded != stream_sps_list[0]:
                    mismatches.append("SPS: first from stream differs from MIB")
            elif nal_type == 8:
                stream_pps = param_sets.get("pps", [])
                if stream_pps and decoded != stream_pps[0]:
                    mismatches.append("PPS: first from stream differs from MIB")

    if mismatches:
        return False, "MIB 0x000A vs stream mismatch: " + "; ".join(mismatches)
    return True, "MIB 0x000A fixed fields and param sets match stream"


def check_extended_profile(ctx: ValidationContext) -> tuple[bool, str]:
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        return untestable("No SPS fields parsed")
    profile_idc = get_int_field(sps, "profile_idc")
    if profile_idc == 88:
        return False, "Extended profile in use"
    return True, "Extended profile not used"


def check_fmo(ctx: ValidationContext) -> tuple[bool, str]:
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    pps = ctx.timeline.header_fields.get("PPS")
    if pps is None:
        return untestable("No PPS fields parsed")
    value = get_int_field(pps, "num_slice_groups_minus1")
    if value is None:
        return False, "num_slice_groups_minus1 not present"
    if value != 0:
        return False, f"FMO enabled (num_slice_groups_minus1={value})"
    return True, "FMO not used"


def check_redundant_slices(ctx: ValidationContext) -> tuple[bool, str]:
    if ctx.timeline is None:
        return untestable("FFmpeg trace unavailable")
    pps = ctx.timeline.header_fields.get("PPS")
    if pps is None:
        return untestable("No PPS fields parsed")
    value = get_int_field(pps, "redundant_pic_cnt_present_flag")
    if value is None:
        return False, "redundant_pic_cnt_present_flag not present"
    if value != 0:
        return False, "Redundant slices enabled"
    return True, "Redundant slices not used"


# ---------------------------------------------------------------------------
# SDP cross-validation helpers (H.264)
# ---------------------------------------------------------------------------

_H264_SDP_FIELD_MAP: list[tuple[str, str, type]] = [
    ("packetization_mode", "h264_packetization_mode", int),
    ("sprop_max_don_diff", "h26x_max_don_diff", int),
    ("sprop_interleaving_depth", "h264_interleaving_depth", int),
    ("sprop_deint_buf_req", "h264_deint_buf_req", int),
    ("sprop_init_buf_time", "h264_init_buf_time", int),
]


def _sdp_field_is_set_h264(md: MediaDescriptor, attr: str, typ: type) -> bool:
    """Return True if the SDP media descriptor attribute has a non-default value."""
    val = getattr(md, attr, None)
    if val is None:
        return False
    if typ is int:
        return val != 0
    if typ is str:
        return val != ""
    return False


def check_sdp_tp_mode_h264(ctx: ValidationContext) -> tuple[bool, str]:
    """TR-10-15c-101: TP shall be 2110TPW in SDP fmtp."""
    if ctx.sdp_media is None:
        return untestable("No SDP transport file provided (use --sdp)")
    tp = ctx.sdp_media.sender_type
    if tp is None:
        return untestable("SDP does not specify TP attribute")
    if tp != MatroxSdpEnums.SenderType2110TPW:
        return False, f"SDP TP='{tp}', expected '2110TPW'"
    return True, "SDP TP=2110TPW"


def check_mib_vs_sdp_fmtp_h264(ctx: ValidationContext) -> tuple[bool, str]:
    """TR-10-15c-139: MIB 0x000A fields shall match SDP fmtp syntax."""
    if ctx.sdp_media is None:
        return untestable("No SDP transport file provided (use --sdp)")
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    sr = ctx.sender_reports[0]
    block = find_media_block(sr, 0x000A)
    if block is None:
        return untestable("No MIB 0x000A present")
    data = parse_h264_media_info(block.payload)
    if "error" in data:
        return False, data["error"]

    md = ctx.sdp_media
    mask = data["mask"]
    mismatches: list[str] = []

    pli_bit = H264_INFO_FIELD_BITS["profile_level_id"]
    if (mask & (1 << pli_bit)) and md.codec_profile_level_id:
        mib_pli: bytes = data["profile_level_id"]
        try:
            sdp_pli = bytes.fromhex(md.codec_profile_level_id)
        except ValueError:
            mismatches.append(f"profile_level_id: SDP value '{md.codec_profile_level_id}' is not valid hex")
            sdp_pli = None
        if sdp_pli is not None and mib_pli != sdp_pli:
            mismatches.append(
                f"profile_level_id: MIB={mib_pli.hex()} SDP={sdp_pli.hex()}"
            )

    for mib_field, sdp_attr, typ in _H264_SDP_FIELD_MAP:
        bit = H264_INFO_FIELD_BITS[mib_field]
        if not (mask & (1 << bit)):
            continue
        if not _sdp_field_is_set_h264(md, sdp_attr, typ):
            continue
        mib_val = data[mib_field]
        sdp_val = getattr(md, sdp_attr)
        if mib_val != sdp_val:
            mismatches.append(f"{mib_field}: MIB={mib_val} SDP={sdp_val}")

    ps_bit = H264_INFO_FIELD_BITS["sprop_parameter_sets"]
    if (mask & (1 << ps_bit)) and md.h264_parameter_sets:
        # TR-10-15c §16: the MIB stores the same base64 ASCII characters
        # (with optional ',' list separators) as the SDP a=fmtp value, so
        # the comparison is a byte-for-byte ASCII match.
        mib_raw: bytes = data["sprop_parameter_sets"]
        sdp_raw = md.h264_parameter_sets.encode("ascii")
        if mib_raw != sdp_raw:
            mismatches.append(
                f"sprop_parameter_sets: MIB={mib_raw!r} SDP={sdp_raw!r}"
            )

    if mismatches:
        return False, "MIB vs SDP mismatch: " + "; ".join(mismatches)
    return True, "MIB 0x000A fields match SDP fmtp"


def check_sdp_fmtp_in_mib_h264(ctx: ValidationContext) -> tuple[bool, str]:
    """TR-10-15c-196: SDP fmtp fields shall be present in MIB."""
    if ctx.sdp_media is None:
        return untestable("No SDP transport file provided (use --sdp)")
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    sr = ctx.sender_reports[0]
    block = find_media_block(sr, 0x000A)
    if block is None:
        return untestable("No MIB 0x000A present")
    data = parse_h264_media_info(block.payload)
    if "error" in data:
        return False, data["error"]

    md = ctx.sdp_media
    mask = data["mask"]
    missing: list[str] = []

    if md.codec_profile_level_id:
        bit = H264_INFO_FIELD_BITS["profile_level_id"]
        if not (mask & (1 << bit)):
            missing.append("profile_level_id")

    for mib_field, sdp_attr, typ in _H264_SDP_FIELD_MAP:
        if not _sdp_field_is_set_h264(md, sdp_attr, typ):
            continue
        bit = H264_INFO_FIELD_BITS[mib_field]
        if not (mask & (1 << bit)):
            missing.append(mib_field)

    if md.h264_parameter_sets:
        bit = H264_INFO_FIELD_BITS["sprop_parameter_sets"]
        if not (mask & (1 << bit)):
            missing.append("sprop_parameter_sets")

    if missing:
        return False, "SDP fmtp fields missing from MIB mask: " + ", ".join(missing)
    return True, "All SDP fmtp fields present in MIB"


def check_sdp_wrapper(ctx: ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """Comprehensive SDP-side requirement for IPMX H.264 streams.

    Mirrors the per-media-type checklist `TP-10/TP-10-1Sec13.2.py:195-232`
    runs for `video/H264` (RFC 6184 + ST 2110-10 + ST 2110-22) and adds
    the project-local IPMX checks: the IPMX fmtp keyword (TR-10-1 §10.1)
    and the multicast source-filter signaling (TR-10-9 §17 / RFC 4570).
    """
    media = ctx.sdp_media
    if media is None:
        from ipmx_validate_common import untestable as _ut
        return _ut("No SDP provided")
    try:
        check_sdp_rfc6184(media)
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

    add("TR-10-15c-84", "shall", "An IPMX Sender producing an H.264 coded stream shall comply with the VSF TR-10-7 Technical Recommendation.", lambda _: untestable("Not observable in PCAP"))
    add("TR-10-15c-85", "shall", "An IPMX Sender producing an H.264 coded stream shall comply with the BCP-006-02 specification.", lambda _: untestable("Not observable in PCAP"))
    add("TR-10-15c-86", "shall", "The H.264 coded bitstream produced by an IPMX Sender shall conform to the H.264 specification, as well as the requirements defined in BCP-006-02 and this Technical Recommendation.", lambda _: untestable("Full bitstream compliance not verifiable here"))
    add("TR-10-15c-87", "shall", "An IPMX Receiver shall communicate its capabilities for the \"video/H264\" media type through BCP-004-01.", lambda _: untestable("Not observable in PCAP"))
    add("TR-10-15c-88", "shall", "An IPMX Sender shall communicate its capabilities for the \"video/H264\" media type through BCP-004-02.", lambda _: untestable("Not observable in PCAP"))
    add("TR-10-15c-91", "shall", "The vui_parameters() shall be present in SPS and shall describe the uncompressed YCbCr video signal.", lambda c=ctx: check_vui_present(c))
    add("TR-10-15c-91-XVAL", "shall", "SPS signal description (width, height, sampling, bit_depth) shall match CLI/MIB video parameters.", lambda c=ctx: check_sps_vs_signal_params(c))
    add("TR-10-15c-92", "shall", "VUI flags video_signal_type_present_flag, colour_description_present_flag, timing_info_present_flag, and nal_hrd_parameters_present_flag shall be 1; pic_struct_present_flag shall be 1 for interlaced video and pic_timing SEI shall include valid pic_struct.", lambda c=ctx: check_vui_flags(c))
    add("TR-10-15c-93", "shall", "If supported, the alpha channel shall be transported as an independent monochrome bitstream using KEY 4:0:0 sampling, ALPHA colorimetry and UNSPECIFIED transfer characteristics.", lambda _: untestable("Alpha support not detectable"))
    add("TR-10-15c-94", "shall", "The PAFF (PicAFF) feature shall not be used by encoders.", lambda c=ctx: check_paff_not_used(c))
    add("TR-10-15c-96", "shall", "UDP/IP packets shall comply with RFC 6184 and NMOS BCP-006-02 restrictions.", lambda _: untestable("RFC/BCP compliance not fully validated"))
    add("TR-10-9-11.2a", "shall", "IPMX Senders shall send the first packet of each frame at regular intervals that correspond to the Frame-to-Frame Interval. The difference between maximum and minimum of this interval measured over a 2 second period shall not exceed 2 mSec.", lambda c=ctx: check_frame_interval_tr10_9(c))
    add("TR-10-9-11.2b", "shall", "IPMX Senders shall send IPMX Sender Reports for each frame at regular intervals that correspond to the Frame-to-Frame Interval. The difference between maximum and minimum of this interval measured over a 2 second period shall not exceed 2 mSec.", lambda c=ctx: check_sr_interval_tr10_9(c))
    add("TR-10-9-11.2c", "shall", "For a Baseband IPMX Sender the Frame-to-Frame Interval shall correspond to the timing of their baseband input signal.", lambda _: untestable("Baseband input not observable"))
    add("TR-10-9-11.2d", "shall", "For IPMX Senders not based on the conversion of a baseband signal, the Frame-to-Frame interval shall correspond to the nominal frame rate of the media signal.", lambda _: untestable("Sender type not observable"))
    add("TR-10-15c-97", "shall", "A UDP/IP packet shall not contain more than one VCL NAL Unit.", lambda c=ctx: check_packet_vcl_limit(c))
    add("TR-10-15c-99", "shall", "H.264 coded video shall be transmitted and decoded using the HRD transmitter and decoder schedules.", lambda c=ctx: untestable("HRD presence verified by TR-10-15c-110; schedule conformance not testable from PCAP"))
    add("TR-10-1-MIB-SIG", "shall", "MIB baseband signal parameters shall be internally consistent (htotal >= width, vtotal >= height, pixclk = htotal*vtotal*fps).", lambda c=ctx: check_mib_signal_sanity(c))
    add("TR-10-15c-101", "shall", "Traffic shaping mode shall be set to TP=2110TPW and explicitly declared in the SDP fmtp attribute.", lambda c=ctx: check_sdp_tp_mode_h264(c))
    add("TR-10-15c-103", "shall", "Buffering Period SEI messages shall be provided at each recovery point.", lambda _: untestable("SEI recovery point details not parsed"))
    add("TR-10-15c-104", "shall", "Picture Timing SEI messages shall be provided for each access unit; pic_struct shall be provided for interlaced video.", lambda _: untestable("SEI picture timing not parsed"))
    add("TR-10-15c-105", "shall", "timing_info_present_flag shall equal 1 and num_units_in_tick/time_scale shall match frame rate (time_scale = 2*frame_rate numerator).", lambda c=ctx: check_timing_info(c))
    add("TR-10-15c-106", "shall", "The nominal removal time tr,n(n) shall be an even number for a progressive byte stream.", lambda _: untestable("Nominal removal time not parsed"))
    add("TR-10-15c-107b", "shall", "Decode order shall equal output order.", lambda c=ctx: check_decode_order(c))
    add("TR-10-15c-108a", "shall", "HRD parameters shall be specified for the bitrate of the base layer.", lambda c=ctx: check_hrd_parameters(c))
    add("TR-10-15c-108b", "shall", "The cpb_cnt_minus1 value of hrd_parameters() shall be 0.", lambda c=ctx: check_cpb_cnt(c))
    add("TR-10-15c-109a", "shall", "Bitstream shall conform to Type II HRD.", lambda _: untestable("Type II HRD not verifiable here"))
    add("TR-10-15c-109b", "shall", "nal_hrd_parameters_present_flag shall equal 1.", lambda c=ctx: check_nal_hrd_flag(c))
    add("TR-10-15c-110", "shall", "HRD parameters shall be specified in the VUI parameters of the SPS.", lambda c=ctx: check_hrd_present(c))
    add("TR-10-15c-113", "shall", "A coded stream shall include a random access point at least once every 5 seconds.", lambda c=ctx: check_random_access(c))
    add("TR-10-15c-114", "shall", "Each random access point shall provide IDR and SPS/PPS, or SEI recovery_point.", lambda c=ctx: check_random_access_content(c))
    add("TR-10-15c-116", "shall", "An H.264 Sender compliant with IPMX H.264 Profile shall support producing High/Main profile 4:2:0 8-bit.", lambda c=ctx: check_profile_levels(c))
    add("TR-10-15c-117", "shall", "An H.264 encoder supporting a monochrome bitstream shall support producing HighPredictive-444 4:0:0 8-bit.", lambda _: untestable("Monochrome encoder support not observable"))
    add("TR-10-15c-120", "shall", "An H.264 Receiver compliant with IPMX H.264 Profile shall be capable of consuming High/Main profile 4:2:0 8-bit.", lambda _: untestable("Receiver capability not observable"))
    add("TR-10-15c-121", "shall", "An H.264 decoder supporting a monochrome bitstream shall support consuming HighPredictive-444 4:0:0 8-bit.", lambda _: untestable("Decoder capability not observable"))
    add("TR-10-15c-122", "shall", "An H.264 Receiver compliant with IPMX H.264 Profile shall be capable of consuming Level 4.2.", lambda _: untestable("Receiver capability not observable"))
    add("TR-10-15c-126", "shall", "A decoder shall support consuming both H.264 CBR and VBR bitstreams.", lambda _: untestable("Decoder capability not observable"))
    add("TR-10-15c-128", "shall", "Annexes F,G,H,I and J of H.264 shall not be used.", lambda c=ctx: check_no_annexes_fghij(c))
    add("TR-10-15c-130", "shall", "Media Info Block shall provide stream parameters compliant with active SPS/PPS.", lambda c=ctx: check_h264_info_matches_stream(c))
    add("TR-10-15c-131", "shall", "RTCP Sender Report shall be sent before the first video media packet of the associated frame/field, if any.", lambda c=ctx: check_sr_before_au(c))
    add("TR-10-15c-133d", "shall", "Encoder shall start placing access units into the CPB after a constant encoder_delay from capture.", lambda _: untestable("encoder_delay not observable"))
    add("TR-10-15c-134a", "shall", "Encoder shall transmit the sender report before transmitting the coded access unit.", lambda c=ctx: check_sr_before_au(c))
    add("TR-10-15c-134b", "shall", "Encoder shall transmit the sender report no more than encoder_delay seconds after capture.", lambda _: untestable("encoder_delay not observable"))
    add("TR-10-15c-135a", "shall", "Sender reports shall be transmitted in presentation order.", lambda c=ctx: check_sr_order(c))
    add("TR-10-15c-135b", "shall", "If a frame/field is skipped, it shall not skip the associated sender report.", lambda c=ctx: check_sr_mapping(c))
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
    add("TR-10-15c-138", "shall", "An H.264 coded stream shall carry an additional Media Info Block type 0x000A immediately following type 0x0005.", lambda c=ctx: check_media_info_block(c))
    add("TR-10-15c-139", "shall", "Media Info Block parameters shall use the same syntax as the SDP fmtp line.", lambda c=ctx: check_mib_vs_sdp_fmtp_h264(c))
    add("TR-10-15c-140", "shall", "When a value is not provided, associated bytes shall be 0x00 and length shall be 0.", lambda c=ctx: check_h264_info_mask(c))
    add("TR-10-15c-193", "shall", "Variable-length section size shall be rounded to a multiple of 4 bytes following the 28th byte.", lambda c=ctx: check_h264_info_variable_len(c))
    add("TR-10-15c-195", "shall", "Media Info Block shall be 32-bit aligned and length shall equal (words - 1).", lambda c=ctx: check_media_info_lengths(c))
    add("TR-10-15c-196", "shall", "If parameters are present in SDP fmtp, they shall also be present in the media info block.", lambda c=ctx: check_sdp_fmtp_in_mib_h264(c))

    # SHOULD requirements
    add("TR-10-15c-107a", "should", "max_num_reorder_frames should be 0.", lambda c=ctx: check_max_reorder(c))
    add("TR-10-15c-119a", "should", "The Extended profile should not be used by an encoder.", lambda c=ctx: check_extended_profile(c))
    add("TR-10-15c-119b", "should", "FMO should not be used by an encoder.", lambda c=ctx: check_fmo(c))
    add("TR-10-15c-119c", "should", "RS (redundant slices) should not be used by an encoder.", lambda c=ctx: check_redundant_slices(c))
    add("TR-10-15c-119d", "should", "ASO, DP, SI, and SP features should not be used by an encoder.", lambda _: untestable("Feature usage not observable"))
    add("TR-10-15c-133a", "should", "Encoder should transmit sender reports at the nominal frame interval.", lambda c=ctx: check_sr_interval(c))
    add("TR-10-15c-133b", "should", "Coded access units should be put into the CPB at the nominal interval.", lambda c=ctx: check_au_interval_const(c))
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
    add("TR-10-1-10.1-IPMX-FMTP", "shall",
        "SDP a=fmtp line shall contain the IPMX keyword (TR-10-1 §10.1).",
        lambda c=ctx: check_sdp_ipmx_fmtp(c.sdp_media))
    add("IPMX-SDP-WRAPPER", "shall",
        "SDP shall satisfy RFC 6184 + ST 2110-10 + ST 2110-22 + IPMX fmtp + "
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
    hrd = ipmx_validate_hrd_h264.extract_hrd_parameters_h264(sps) if sps else None
    return run_cmax_hrd_check(
        packets=ctx.rtp_report.packets,
        hrd_bit_rate=hrd.bit_rate if hrd else None,
        exact_framerate=_resolve_exactframerate(ctx),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, help="PCAP file containing RTP/RTCP")
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
        help="Stream is interlaced (enables pic_struct_present_flag check)",
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
        help="Accept superset profiles (e.g. High 4:2:2 includes High 4:2:0 capability)",
    )
    args = parser.parse_args()

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
    results = run_validation(ctx)

    hrd_results = ipmx_validate_hrd_h264.run_hrd_checks(
        ctx,
        enable_hrd=args.hrd,
        enable_hrd_sim=args.hrd_sim,
        enable_hrd_timing=args.hrd_timing,
    )
    results.extend(hrd_results)

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
