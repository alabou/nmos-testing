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
"""HRD (Hypothetical Reference Decoder) validation for H.265/HEVC streams.

Implements three tiers of validation controlled by CLI flags:

  --hrd          Tier 1: Self-consistency checks on HRD/SEI parameters.
  --hrd-sim      Tier 2: CPB leaky-bucket simulation (implies --hrd).
  --hrd-timing   Tier 3: PCAP timing cross-validation (implies --hrd).

The CPB simulation follows ITU-T H.265 Annex C using exact Fraction
arithmetic so that no rounding errors accumulate.  All inputs are
integers extracted from the bitstream (SPS hrd_parameters, buffering
period SEI, picture timing SEI, NAL unit sizes).

PCAP capture times are used only in Tier 3 and are treated as
informational — they are sniffer wall-clock times with jitter, not
the HSS delivery schedule.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from fractions import Fraction
from typing import Any

from ipmx_validate_common import (
    AccessUnit,
    RequirementResult,
    RtpReport,
    ValidationContext,
    get_int_field,
    untestable,
    walk_trace_pairs,
)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class HrdMode(Enum):
    """Which HRD parameter set is being tested."""
    NAL = auto()
    VCL = auto()


class Severity(Enum):
    ERROR = auto()
    WARNING = auto()
    INFO = auto()


# ---------------------------------------------------------------------------
# Data structures extracted from the bitstream
# ---------------------------------------------------------------------------

@dataclass
class HrdParameters:
    """Extracted from SPS hrd_parameters() + sub_layer_hrd_parameters()."""
    nal_hrd_present: bool
    vcl_hrd_present: bool
    bit_rate: Fraction
    cpb_size: Fraction
    cbr_flag: bool
    low_delay_hrd_flag: bool
    initial_cpb_removal_delay_length: int
    au_cpb_removal_delay_length: int
    dpb_output_delay_length: int
    sub_pic_hrd_params_present: bool
    clock_tick: Fraction
    clock_sub_tick: Fraction | None


@dataclass
class BufferingPeriodInfo:
    """Extracted from a buffering period SEI message."""
    au_index: int
    rtp_timestamp: int
    init_cpb_removal_delay: int
    init_cpb_removal_delay_offset: int
    concatenation_flag: bool
    cpb_delay_offset: int
    dpb_delay_offset: int
    is_irap_alt: bool


@dataclass
class PictureTimingInfo:
    """Extracted from a picture timing SEI message."""
    au_index: int
    rtp_timestamp: int
    au_cpb_removal_delay_minus1: int
    pic_dpb_output_delay: int


@dataclass
class AccessUnitSize:
    """Bit-size of each access unit for CPB occupancy tracking."""
    au_index: int
    rtp_timestamp: int
    size_in_bits_vcl: int
    size_in_bits_all: int


# ---------------------------------------------------------------------------
# CPB simulation results
# ---------------------------------------------------------------------------

@dataclass
class CpbAuResult:
    """Per-AU result of the CPB simulation."""
    au_index: int
    rtp_timestamp: int
    size_in_bits: int
    init_arrival_time: Fraction
    final_arrival_time: Fraction
    nominal_removal_time: Fraction
    cpb_removal_time: Fraction
    cpb_occupancy_at_removal: Fraction
    cpb_occupancy_after_removal: Fraction
    overflow: bool
    underflow: bool
    near_overflow: bool
    near_underflow: bool


@dataclass
class CpbSimulationSummary:
    """Aggregate results of the CPB simulation."""
    au_results: list[CpbAuResult]
    overflow_count: int
    underflow_count: int
    near_overflow_count: int
    near_underflow_count: int
    max_occupancy_fraction: Fraction
    min_margin_before_underflow: Fraction | None
    valid: bool
    detail: str


# ---------------------------------------------------------------------------
# Extraction: SPS → HrdParameters
# ---------------------------------------------------------------------------

def extract_hrd_parameters(sps: dict[str, Any]) -> HrdParameters | None:
    """Extract HRD parameters from SPS trace fields.

    Returns None if the required fields are not present.
    """
    vui_hrd = get_int_field(sps, "vui_hrd_parameters_present_flag")
    if vui_hrd != 1:
        return None

    nal_hrd = get_int_field(sps, "nal_hrd_parameters_present_flag")
    vcl_hrd = get_int_field(sps, "vcl_hrd_parameters_present_flag")
    if nal_hrd != 1 and vcl_hrd != 1:
        return None

    num_units = get_int_field(sps, "vui_num_units_in_tick")
    time_scale = get_int_field(sps, "vui_time_scale")
    if not num_units or not time_scale or num_units <= 0 or time_scale <= 0:
        return None

    clock_tick = Fraction(num_units, time_scale)

    bit_rate_scale = get_int_field(sps, "bit_rate_scale")
    cpb_size_scale = get_int_field(sps, "cpb_size_scale")
    br_val = get_int_field(sps, "bit_rate_value_minus1[0]")
    if br_val is None:
        br_val = get_int_field(sps, "bit_rate_value_minus1")
    cs_val = get_int_field(sps, "cpb_size_value_minus1[0]")
    if cs_val is None:
        cs_val = get_int_field(sps, "cpb_size_value_minus1")

    if bit_rate_scale is None or cpb_size_scale is None:
        return None
    if br_val is None or cs_val is None:
        return None

    bit_rate = Fraction((br_val + 1) * (2 ** (6 + bit_rate_scale)))
    cpb_size = Fraction((cs_val + 1) * (2 ** (4 + cpb_size_scale)))

    cbr_val = get_int_field(sps, "cbr_flag[0]")
    if cbr_val is None:
        cbr_val = get_int_field(sps, "cbr_flag")
    cbr_flag = cbr_val == 1

    low_delay_val = get_int_field(sps, "low_delay_hrd_flag[0]")
    if low_delay_val is None:
        low_delay_val = get_int_field(sps, "low_delay_hrd_flag")
    low_delay_hrd_flag = low_delay_val == 1

    init_delay_len = get_int_field(sps, "initial_cpb_removal_delay_length_minus1")
    au_delay_len = get_int_field(sps, "au_cpb_removal_delay_length_minus1")
    dpb_delay_len = get_int_field(sps, "dpb_output_delay_length_minus1")
    if init_delay_len is None or au_delay_len is None or dpb_delay_len is None:
        return None

    sub_pic = get_int_field(sps, "sub_pic_hrd_params_present_flag")
    sub_pic_present = sub_pic == 1

    clock_sub_tick: Fraction | None = None
    if sub_pic_present:
        tick_div = get_int_field(sps, "tick_divisor_minus2")
        if tick_div is not None:
            clock_sub_tick = clock_tick / (tick_div + 2)

    return HrdParameters(
        nal_hrd_present=nal_hrd == 1,
        vcl_hrd_present=vcl_hrd == 1,
        bit_rate=bit_rate,
        cpb_size=cpb_size,
        cbr_flag=cbr_flag,
        low_delay_hrd_flag=low_delay_hrd_flag,
        initial_cpb_removal_delay_length=init_delay_len + 1,
        au_cpb_removal_delay_length=au_delay_len + 1,
        dpb_output_delay_length=dpb_delay_len + 1,
        sub_pic_hrd_params_present=sub_pic_present,
        clock_tick=clock_tick,
        clock_sub_tick=clock_sub_tick,
    )


# ---------------------------------------------------------------------------
# Extraction: SEI fields from FFmpeg trace headers
# ---------------------------------------------------------------------------

_BUFFERING_PERIOD_FIELDS = {"bp_seq_parameter_set_id", "irap_cpb_params_present_flag"}
_PIC_TIMING_FIELDS = {"au_cpb_removal_delay_minus1", "pic_dpb_output_delay"}

_TRACE_NAL_TYPES = {32, 33, 34, 39, 40}

_NAL_TO_HDR_H265 = {
    32: "VPS",
    33: "SPS",
    34: "PPS",
    39: "SEI",  # SEI_PREFIX
    40: "SEI",  # SEI_SUFFIX
}


def _get_sei_int(fields: dict[str, Any], name: str) -> int | None:
    """Get an integer value from FFmpeg trace SEI fields.

    Fields are stored as ``{"value": <int|str>, "bits": ...}`` dicts.
    """
    entry = fields.get(name)
    if entry is None:
        return None
    val = entry.get("value") if isinstance(entry, dict) else entry
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        try:
            return int(val, 0)
        except ValueError:
            return None
    return None


def extract_sei_per_au(
    report: RtpReport,
    raw_headers: list[dict[str, Any]],
    lossy_timestamps: set[int] | None = None,
) -> tuple[
    dict[int, BufferingPeriodInfo],
    dict[int, PictureTimingInfo],
    set[int],
]:
    """Walk ``raw_headers`` in parallel with ``nalus_meta`` to extract SEI values.

    *raw_headers* is ``TimelineInfo.raw_headers`` — the uncorrelated list
    produced by ``parse_trace_headers``.  Each entry has ``"type"`` and
    ``"fields"`` keys.  We walk ``nalus_meta`` to correlate each header
    back to its AU RTP timestamp (same approach as ``_build_au_sei_map``).

    Returns (buffering_periods_by_ts, picture_timings_by_ts, traced_timestamps).
    """
    bp_map: dict[int, BufferingPeriodInfo] = {}
    pt_map: dict[int, PictureTimingInfo] = {}
    traced_ts: set[int] = set()

    au_index_by_ts: dict[int, int] = {}
    for au in report.access_units:
        au_index_by_ts[au.timestamp] = au.index

    for meta, header in walk_trace_pairs(
        report, raw_headers, _NAL_TO_HDR_H265, skip_timestamps=lossy_timestamps
    ):
        ts = int(meta["timestamp"])
        traced_ts.add(ts)

        if header.get("type") != "SEI":
            continue

        fields: dict[str, Any] = header.get("fields", {})
        keys = set(fields.keys())
        au_idx = au_index_by_ts.get(ts, -1)

        if keys & _BUFFERING_PERIOD_FIELDS and ts not in bp_map:
            init_delay = _get_sei_int(fields, "nal_initial_cpb_removal_delay[0]")
            if init_delay is None:
                init_delay = _get_sei_int(fields, "nal_initial_cpb_removal_delay")
            if init_delay is None:
                init_delay = _get_sei_int(fields, "vcl_initial_cpb_removal_delay[0]")
            if init_delay is None:
                init_delay = _get_sei_int(fields, "vcl_initial_cpb_removal_delay")

            init_offset = _get_sei_int(fields, "nal_initial_cpb_removal_offset[0]")
            if init_offset is None:
                init_offset = _get_sei_int(fields, "nal_initial_cpb_removal_offset")
            if init_offset is None:
                init_offset = _get_sei_int(fields, "vcl_initial_cpb_removal_offset[0]")
            if init_offset is None:
                init_offset = _get_sei_int(fields, "vcl_initial_cpb_removal_offset")

            concat = _get_sei_int(fields, "concatenation_flag")
            cpb_off = _get_sei_int(fields, "cpb_delay_offset")
            dpb_off = _get_sei_int(fields, "dpb_delay_offset")

            is_alt = False
            alt_delay = _get_sei_int(fields, "nal_initial_alt_cpb_removal_delay[0]")
            if alt_delay is None:
                alt_delay = _get_sei_int(fields, "vcl_initial_alt_cpb_removal_delay[0]")
            if alt_delay is not None:
                is_alt = True

            if init_delay is not None:
                bp_map[ts] = BufferingPeriodInfo(
                    au_index=au_idx,
                    rtp_timestamp=ts,
                    init_cpb_removal_delay=init_delay,
                    init_cpb_removal_delay_offset=init_offset or 0,
                    concatenation_flag=concat == 1,
                    cpb_delay_offset=cpb_off or 0,
                    dpb_delay_offset=dpb_off or 0,
                    is_irap_alt=is_alt,
                )

        if keys & _PIC_TIMING_FIELDS and ts not in pt_map:
            removal_delay = _get_sei_int(fields, "au_cpb_removal_delay_minus1")
            dpb_output = _get_sei_int(fields, "pic_dpb_output_delay")
            if removal_delay is not None:
                pt_map[ts] = PictureTimingInfo(
                    au_index=au_idx,
                    rtp_timestamp=ts,
                    au_cpb_removal_delay_minus1=removal_delay,
                    pic_dpb_output_delay=dpb_output or 0,
                )

    return bp_map, pt_map, traced_ts


# ---------------------------------------------------------------------------
# Extraction: AU sizes from RTP report
# ---------------------------------------------------------------------------

_H265_VCL_RANGE = range(0, 32)


def compute_au_sizes(report: RtpReport) -> list[AccessUnitSize]:
    """Compute bit-sizes of each access unit from reconstructed NAL units."""
    vcl_bits_by_ts: dict[int, int] = {}
    all_bits_by_ts: dict[int, int] = {}

    for meta in report.nalus_meta:
        ts = int(meta["timestamp"])
        nalu_size = int(meta.get("nalu_size", 0))
        bits = nalu_size * 8
        all_bits_by_ts[ts] = all_bits_by_ts.get(ts, 0) + bits
        nal_type = int(meta.get("nal_type", -1))
        if nal_type in _H265_VCL_RANGE:
            vcl_bits_by_ts[ts] = vcl_bits_by_ts.get(ts, 0) + bits

    result: list[AccessUnitSize] = []
    for au in report.access_units:
        ts = au.timestamp
        result.append(AccessUnitSize(
            au_index=au.index,
            rtp_timestamp=ts,
            size_in_bits_vcl=vcl_bits_by_ts.get(ts, 0),
            size_in_bits_all=all_bits_by_ts.get(ts, 0),
        ))
    return result


# ---------------------------------------------------------------------------
# Tier 1: HRD Self-Consistency Checks (--hrd)
# ---------------------------------------------------------------------------

def check_hrd_self_consistency(ctx: ValidationContext) -> list[RequirementResult]:
    """Run all Tier 1 HRD self-consistency checks.

    These verify that the stream's own signalled HRD values are internally
    consistent.  No floating-point or timing imprecision is involved.
    """
    results: list[RequirementResult] = []

    def _add(req_id: str, passed: bool, details: str, testable: bool = True) -> None:
        results.append(RequirementResult(
            req_id=req_id,
            level="shall",
            text=_HRD_CHECK_DESCRIPTIONS.get(req_id, req_id),
            passed=passed,
            details=details,
            testable=testable,
        ))

    if ctx.timeline is None:
        _add("HRD-01", False, "FFmpeg trace unavailable", testable=False)
        return results

    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        _add("HRD-01", False, "No SPS fields parsed", testable=False)
        return results

    # HRD-01: vui_hrd_parameters_present_flag
    vui_hrd = get_int_field(sps, "vui_hrd_parameters_present_flag")
    if vui_hrd != 1:
        _add("HRD-01", False, f"vui_hrd_parameters_present_flag={vui_hrd}")
    else:
        _add("HRD-01", True, "vui_hrd_parameters_present_flag=1")

    # HRD-02: nal_hrd or vcl_hrd present
    nal_hrd = get_int_field(sps, "nal_hrd_parameters_present_flag")
    vcl_hrd = get_int_field(sps, "vcl_hrd_parameters_present_flag")
    if nal_hrd != 1 and vcl_hrd != 1:
        _add("HRD-02", False,
             f"nal_hrd_parameters_present_flag={nal_hrd}, "
             f"vcl_hrd_parameters_present_flag={vcl_hrd}")
    else:
        mode = "NAL" if nal_hrd == 1 else "VCL"
        _add("HRD-02", True, f"{mode} HRD parameters present")

    # HRD-03: ClockTick derivable
    num_units = get_int_field(sps, "vui_num_units_in_tick")
    time_scale = get_int_field(sps, "vui_time_scale")
    if not num_units or not time_scale or num_units <= 0 or time_scale <= 0:
        _add("HRD-03", False,
             f"vui_num_units_in_tick={num_units}, vui_time_scale={time_scale}")
    else:
        ct = Fraction(num_units, time_scale)
        _add("HRD-03", True,
             f"ClockTick={float(ct)*1000:.6f}ms "
             f"(num_units={num_units}, time_scale={time_scale})")

    # HRD-04: BitRate derivable
    bit_rate_scale = get_int_field(sps, "bit_rate_scale")
    br_val = get_int_field(sps, "bit_rate_value_minus1[0]")
    if br_val is None:
        br_val = get_int_field(sps, "bit_rate_value_minus1")
    if bit_rate_scale is None or br_val is None:
        _add("HRD-04", False,
             f"bit_rate_scale={bit_rate_scale}, bit_rate_value_minus1={br_val}")
    else:
        br = (br_val + 1) * (2 ** (6 + bit_rate_scale))
        _add("HRD-04", True, f"BitRate[0]={br/1e6:.2f} Mbps")

    # HRD-05: CpbSize derivable
    cpb_size_scale = get_int_field(sps, "cpb_size_scale")
    cs_val = get_int_field(sps, "cpb_size_value_minus1[0]")
    if cs_val is None:
        cs_val = get_int_field(sps, "cpb_size_value_minus1")
    if cpb_size_scale is None or cs_val is None:
        _add("HRD-05", False,
             f"cpb_size_scale={cpb_size_scale}, cpb_size_value_minus1={cs_val}")
    else:
        cs = (cs_val + 1) * (2 ** (4 + cpb_size_scale))
        _add("HRD-05", True, f"CpbSize[0]={cs/1e6:.2f} Mbit")

    # HRD-06: cpb_cnt_minus1 == 0
    cpb_cnt = get_int_field(sps, "cpb_cnt_minus1[0]")
    if cpb_cnt is None:
        cpb_cnt = get_int_field(sps, "cpb_cnt_minus1")
    if cpb_cnt is None:
        _add("HRD-06", False, "cpb_cnt_minus1 not present")
    elif cpb_cnt != 0:
        _add("HRD-06", False, f"cpb_cnt_minus1={cpb_cnt}, expected 0")
    else:
        _add("HRD-06", True, "cpb_cnt_minus1=0")

    # HRD-07..09: delay length fields present and in range
    for req_id, field_name in [
        ("HRD-07", "initial_cpb_removal_delay_length_minus1"),
        ("HRD-08", "au_cpb_removal_delay_length_minus1"),
        ("HRD-09", "dpb_output_delay_length_minus1"),
    ]:
        val = get_int_field(sps, field_name)
        if val is None:
            _add(req_id, False, f"{field_name} not present")
        elif val < 0 or val > 31:
            _add(req_id, False, f"{field_name}={val} out of range [0..31]")
        else:
            _add(req_id, True, f"{field_name}={val} (length={val + 1} bits)")

    # HRD-10: Buffering period SEI at every IRAP
    bp_result = _check_bp_presence(ctx)
    _add("HRD-10", *bp_result)

    # HRD-11: Picture timing SEI at every AU
    pt_result = _check_pt_presence(ctx)
    _add("HRD-11", *pt_result)

    # HRD-12: low_delay_hrd_flag
    ld = get_int_field(sps, "low_delay_hrd_flag[0]")
    if ld is None:
        ld = get_int_field(sps, "low_delay_hrd_flag")
    if ld is None:
        _add("HRD-12", True, "low_delay_hrd_flag not present (inferred 0)", testable=True)
    else:
        _add("HRD-12", True, f"low_delay_hrd_flag={ld}")

    # HRD-13: cbr_flag
    cb = get_int_field(sps, "cbr_flag[0]")
    if cb is None:
        cb = get_int_field(sps, "cbr_flag")
    if cb is None:
        _add("HRD-13", True, "cbr_flag not present (inferred 0 = VBR)", testable=True)
    else:
        mode_str = "CBR" if cb == 1 else "VBR"
        _add("HRD-13", True, f"cbr_flag={cb} ({mode_str})")

    return results


_HRD_CHECK_DESCRIPTIONS: dict[str, str] = {
    "HRD-01": "vui_hrd_parameters_present_flag shall be 1.",
    "HRD-02": "nal_hrd_parameters_present_flag or vcl_hrd_parameters_present_flag shall be 1.",
    "HRD-03": "ClockTick shall be derivable (vui_num_units_in_tick > 0 and vui_time_scale > 0).",
    "HRD-04": "BitRate[0] shall be derivable from bit_rate_value_minus1 and bit_rate_scale.",
    "HRD-05": "CpbSize[0] shall be derivable from cpb_size_value_minus1 and cpb_size_scale.",
    "HRD-06": "cpb_cnt_minus1 shall be 0 (single delivery schedule).",
    "HRD-07": "initial_cpb_removal_delay_length_minus1 shall be present and in [0..31].",
    "HRD-08": "au_cpb_removal_delay_length_minus1 shall be present and in [0..31].",
    "HRD-09": "dpb_output_delay_length_minus1 shall be present and in [0..31].",
    "HRD-10": "Buffering Period SEI shall be present at each IRAP access unit.",
    "HRD-11": "Picture Timing SEI shall be present for each access unit.",
    "HRD-12": "low_delay_hrd_flag value noted.",
    "HRD-13": "cbr_flag value noted (CBR vs VBR).",
}


def _compute_traced_timestamps(
    report: RtpReport,
    raw_headers: list[dict[str, Any]],
    lossy_timestamps: set[int] | None = None,
) -> tuple[set[int], dict[int, set[str]]]:
    """Compute the set of AU timestamps covered by the FFmpeg trace (H.265).

    Pairs each filtered nalus_meta entry with the next raw_headers entry of
    the matching FFmpeg trace type (VPS=32, SPS=33, PPS=34,
    SEI_PREFIX=39, SEI_SUFFIX=40). Robust to trace_headers dropping
    individual blocks for malformed NALs.

    AUs in ``lossy_timestamps`` (slice-only packets where FFmpeg emitted
    no PPS/SEI/SPS) are skipped from coverage so that subsequent AUs stay
    aligned with raw_headers.

    Returns ``(traced_timestamps, sei_type_map)`` where *sei_type_map*
    maps each AU timestamp to the set of SEI field-name keys found.
    """
    traced_ts: set[int] = set()
    sei_map: dict[int, set[str]] = {}
    for meta, header in walk_trace_pairs(
        report, raw_headers, _NAL_TO_HDR_H265, skip_timestamps=lossy_timestamps
    ):
        ts = int(meta["timestamp"])
        traced_ts.add(ts)
        if header.get("type") == "SEI":
            fields = header.get("fields", {})
            sei_map.setdefault(ts, set()).update(fields.keys())
    return traced_ts, sei_map


def _check_bp_presence(ctx: ValidationContext) -> tuple[bool, str]:
    """Check buffering period SEI at every IRAP."""
    if ctx.timeline is None:
        return False, "FFmpeg trace unavailable"
    traced_ts, sei_map = _compute_traced_timestamps(
        ctx.rtp_report, ctx.timeline.raw_headers,
        lossy_timestamps=ctx.timeline.lossy_timestamps)
    h265_ra_types = {16, 17, 18, 19, 20, 21}
    ra_aus = [
        au for au in ctx.rtp_report.access_units
        if any(nal in h265_ra_types for nal in au.nal_types)
        and au.timestamp in traced_ts
    ]
    if not ra_aus:
        return (False, "No traced IRAP access units detected")
    missing = [
        au.timestamp for au in ra_aus
        if not (sei_map.get(au.timestamp, set()) & _BUFFERING_PERIOD_FIELDS)
    ]
    if missing:
        return (False,
                f"{len(missing)}/{len(ra_aus)} IRAP AUs missing Buffering Period SEI "
                f"(first missing ts={missing[0]})")
    return (True,
            f"Buffering Period SEI present at all {len(ra_aus)} traced IRAP AUs")


def _check_pt_presence(ctx: ValidationContext) -> tuple[bool, str]:
    """Check picture timing SEI at every traced AU from the first IRAP onward.

    AUs before the first random access point are not part of the HRD model
    and are excluded from this check.
    """
    if ctx.timeline is None:
        return False, "FFmpeg trace unavailable"
    traced_ts, sei_map = _compute_traced_timestamps(
        ctx.rtp_report, ctx.timeline.raw_headers,
        lossy_timestamps=ctx.timeline.lossy_timestamps)

    h265_ra_types = {16, 17, 18, 19, 20, 21}
    first_irap_idx: int | None = None
    for au in ctx.rtp_report.access_units:
        if any(nal in h265_ra_types for nal in au.nal_types):
            first_irap_idx = au.index
            break

    traced_aus = [
        au for au in ctx.rtp_report.access_units
        if au.timestamp in traced_ts
        and (first_irap_idx is not None and au.index >= first_irap_idx)
    ]
    if not traced_aus:
        return (False, "No access units covered by trace from first IRAP onward")
    missing = [
        au.timestamp for au in traced_aus
        if not (sei_map.get(au.timestamp, set()) & _PIC_TIMING_FIELDS)
    ]
    if missing:
        return (False,
                f"{len(missing)}/{len(traced_aus)} traced AUs missing "
                f"Picture Timing SEI (first missing ts={missing[0]})")
    return (True,
            f"Picture Timing SEI present in all {len(traced_aus)} traced AUs "
            f"(from first IRAP onward)")


def hrd_self_consistency_passed(results: list[RequirementResult]) -> bool:
    """Return True if all critical HRD self-consistency checks passed.

    Checks HRD-01 through HRD-11 must pass for the simulation to be meaningful.
    HRD-12 and HRD-13 are informational.
    """
    critical_ids = {f"HRD-{i:02d}" for i in range(1, 12)}
    for r in results:
        if r.req_id in critical_ids and not r.passed and r.testable:
            return False
    return True


# ---------------------------------------------------------------------------
# Tier 2: CPB Simulation (--hrd-sim)
# ---------------------------------------------------------------------------

_NEAR_OVERFLOW_THRESHOLD = Fraction(99, 100)
_NEAR_UNDERFLOW_TICKS = 1


def simulate_cpb(
    hrd: HrdParameters,
    buffering_periods: dict[int, BufferingPeriodInfo],
    picture_timings: dict[int, PictureTimingInfo],
    au_sizes: list[AccessUnitSize],
    *,
    use_nal_type: bool = True,
) -> CpbSimulationSummary:
    """Simulate the CPB leaky bucket per H.265 Annex C.

    All arithmetic uses Fraction for exact results.
    """
    if not au_sizes:
        return CpbSimulationSummary(
            au_results=[], overflow_count=0, underflow_count=0,
            near_overflow_count=0, near_underflow_count=0,
            max_occupancy_fraction=Fraction(0),
            min_margin_before_underflow=None,
            valid=True, detail="No access units to simulate",
        )

    bit_rate = hrd.bit_rate
    cpb_size = hrd.cpb_size
    clock_tick = hrd.clock_tick
    cbr = hrd.cbr_flag
    low_delay = hrd.low_delay_hrd_flag

    au_results: list[CpbAuResult] = []
    overflow_count = 0
    underflow_count = 0
    near_overflow_count = 0
    near_underflow_count = 0
    max_occ_frac = Fraction(0)
    min_underflow_margin: Fraction | None = None

    prev_final_arrival = Fraction(0)
    current_bp: BufferingPeriodInfo | None = None
    first_pic_in_curr_bp_removal: Fraction | None = None
    first_pic_in_prev_bp_removal: Fraction | None = None
    sim_started = False

    near_overflow_bits = cpb_size * _NEAR_OVERFLOW_THRESHOLD

    for n, au_size in enumerate(au_sizes):
        ts = au_size.rtp_timestamp
        size_bits = Fraction(
            au_size.size_in_bits_all if use_nal_type else au_size.size_in_bits_vcl
        )

        pt = picture_timings.get(ts)
        bp = buffering_periods.get(ts)

        if bp is not None:
            first_pic_in_prev_bp_removal = first_pic_in_curr_bp_removal
            current_bp = bp

        if current_bp is None:
            # Skip AUs before the first Buffering Period (first random
            # access point).  The HRD model is undefined until the first
            # BP SEI initialises the CPB.
            continue

        init_delay = Fraction(current_bp.init_cpb_removal_delay)
        init_offset = Fraction(current_bp.init_cpb_removal_delay_offset)

        # --- Nominal removal time (C.2.3) ---
        if not sim_started:
            sim_started = True
            nominal_removal = init_delay / 90000
            first_pic_in_curr_bp_removal = nominal_removal
        elif bp is not None and bp.rtp_timestamp == ts:
            # First AU of a new buffering period
            if not bp.concatenation_flag:
                if first_pic_in_prev_bp_removal is not None and pt is not None:
                    au_cpb_delay = Fraction(pt.au_cpb_removal_delay_minus1 + 1)
                    cpb_delay_off = Fraction(bp.cpb_delay_offset)
                    nominal_removal = (
                        first_pic_in_prev_bp_removal
                        + clock_tick * (au_cpb_delay - cpb_delay_off)
                    )
                else:
                    nominal_removal = init_delay / 90000
            else:
                nominal_removal = init_delay / 90000
            first_pic_in_curr_bp_removal = nominal_removal
        else:
            # Non-first AU within a buffering period (C-11)
            if pt is not None and first_pic_in_curr_bp_removal is not None:
                au_cpb_delay = Fraction(pt.au_cpb_removal_delay_minus1 + 1)
                cpb_delay_off = Fraction(current_bp.cpb_delay_offset)
                nominal_removal = (
                    first_pic_in_curr_bp_removal
                    + clock_tick * (au_cpb_delay - cpb_delay_off)
                )
            else:
                # Fallback: advance by one clock tick from previous
                if au_results:
                    nominal_removal = au_results[-1].nominal_removal_time + clock_tick
                else:
                    nominal_removal = init_delay / 90000

        # --- Initial arrival time (C.2.2) ---
        if not au_results:
            init_arrival = Fraction(0)
        elif cbr:
            init_arrival = prev_final_arrival
        else:
            earliest = nominal_removal - (init_delay + init_offset) / 90000
            init_arrival = max(prev_final_arrival, earliest)

        # --- Final arrival time (C-8) ---
        final_arrival = init_arrival + size_bits / bit_rate

        # --- Actual removal time (C-13) ---
        if not low_delay or nominal_removal >= final_arrival:
            cpb_removal = nominal_removal
        else:
            overshoot = final_arrival - nominal_removal
            ticks_needed = _ceil_fraction(overshoot / clock_tick)
            cpb_removal = nominal_removal + clock_tick * ticks_needed

        # --- CPB occupancy (H.265 Annex C) ---
        # Bits arrive at BitRate during [init_arrival, final_arrival] for
        # each AU.  Between AUs no bits arrive (VBR) or bits arrive
        # continuously (CBR).  We compute the total bits in the CPB just
        # before removal by summing bits that arrived minus bits removed.
        #
        # For AU n, bits_arrived_n = min(cpb_removal - init_arrival_n, final_arrival_n - init_arrival_n) * BitRate
        # i.e. all bits of AU n have arrived by final_arrival_n; if removal
        # is after that, all size_bits are in the buffer.
        if cpb_removal >= final_arrival:
            bits_of_this_au_in_cpb = size_bits
        else:
            bits_of_this_au_in_cpb = bit_rate * (cpb_removal - init_arrival)

        if au_results:
            prev = au_results[-1]
            # Bits remaining from previous AUs (after previous removal)
            # plus any bits that arrived between prev removal and this removal.
            # In VBR, bits only arrive during scheduled arrival windows.
            # Since all previous AUs' bits arrived before prev removal
            # (otherwise prev would have underflowed), the leftover is just
            # prev.occ_after_removal.  No new bits from old AUs arrive after
            # their final_arrival.
            occ_at_removal = prev.cpb_occupancy_after_removal + bits_of_this_au_in_cpb
        else:
            occ_at_removal = bits_of_this_au_in_cpb

        occ_after_removal = occ_at_removal - size_bits

        # --- Overflow / underflow checks ---
        overflow = occ_at_removal > cpb_size
        underflow = False
        if not low_delay and nominal_removal < final_arrival:
            underflow = True

        near_of = occ_at_removal > near_overflow_bits and not overflow
        margin = nominal_removal - final_arrival
        near_uf = (
            not underflow
            and not low_delay
            and Fraction(0) <= margin < clock_tick * _NEAR_UNDERFLOW_TICKS
        )

        if overflow:
            overflow_count += 1
        if underflow:
            underflow_count += 1
        if near_of:
            near_overflow_count += 1
        if near_uf:
            near_underflow_count += 1

        occ_frac = occ_at_removal / cpb_size if cpb_size > 0 else Fraction(0)
        if occ_frac > max_occ_frac:
            max_occ_frac = occ_frac

        if not underflow:
            if min_underflow_margin is None or margin < min_underflow_margin:
                min_underflow_margin = margin

        au_results.append(CpbAuResult(
            au_index=n,
            rtp_timestamp=ts,
            size_in_bits=int(size_bits),
            init_arrival_time=init_arrival,
            final_arrival_time=final_arrival,
            nominal_removal_time=nominal_removal,
            cpb_removal_time=cpb_removal,
            cpb_occupancy_at_removal=occ_at_removal,
            cpb_occupancy_after_removal=occ_after_removal,
            overflow=overflow,
            underflow=underflow,
            near_overflow=near_of,
            near_underflow=near_uf,
        ))

        prev_final_arrival = final_arrival

    skipped = len(au_sizes) - len(au_results)
    valid = overflow_count == 0 and underflow_count == 0
    parts: list[str] = []
    parts.append(f"{len(au_results)} AUs simulated")
    if skipped > 0:
        parts.append(f"{skipped} skipped before first random access point")
    if overflow_count:
        parts.append(f"{overflow_count} overflow(s)")
    if underflow_count:
        parts.append(f"{underflow_count} underflow(s)")
    if near_overflow_count:
        parts.append(f"{near_overflow_count} near-overflow(s)")
    if near_underflow_count:
        parts.append(f"{near_underflow_count} near-underflow(s)")
    parts.append(f"max occupancy {float(max_occ_frac)*100:.1f}%")
    if min_underflow_margin is not None:
        parts.append(f"min underflow margin {float(min_underflow_margin)*1000:.3f}ms")

    return CpbSimulationSummary(
        au_results=au_results,
        overflow_count=overflow_count,
        underflow_count=underflow_count,
        near_overflow_count=near_overflow_count,
        near_underflow_count=near_underflow_count,
        max_occupancy_fraction=max_occ_frac,
        min_margin_before_underflow=min_underflow_margin,
        valid=valid,
        detail="; ".join(parts),
    )


def _ceil_fraction(x: Fraction) -> int:
    """Ceiling of a Fraction as an integer."""
    if x.denominator == 1:
        return x.numerator
    return x.numerator // x.denominator + 1


def check_cpb_simulation(ctx: ValidationContext) -> list[RequirementResult]:
    """Run Tier 2 CPB simulation checks."""
    results: list[RequirementResult] = []

    def _add(req_id: str, level: str, passed: bool, details: str,
             testable: bool = True) -> None:
        results.append(RequirementResult(
            req_id=req_id, level=level,
            text=_SIM_CHECK_DESCRIPTIONS.get(req_id, req_id),
            passed=passed, details=details, testable=testable,
        ))

    if ctx.timeline is None:
        _add("HRD-SIM-01", "shall", False, "FFmpeg trace unavailable", testable=False)
        return results

    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        _add("HRD-SIM-01", "shall", False, "No SPS fields parsed", testable=False)
        return results

    hrd = extract_hrd_parameters(sps)
    if hrd is None:
        _add("HRD-SIM-01", "shall", False,
             "Cannot extract HRD parameters — run --hrd first", testable=False)
        return results

    bp_map, pt_map, traced_ts = extract_sei_per_au(
        ctx.rtp_report, ctx.timeline.raw_headers,
        lossy_timestamps=ctx.timeline.lossy_timestamps)
    au_sizes = compute_au_sizes(ctx.rtp_report)

    # Only simulate AUs that have picture timing info
    simulated_sizes = [s for s in au_sizes if s.rtp_timestamp in pt_map]
    if not simulated_sizes:
        _add("HRD-SIM-01", "shall", False,
             "No AUs with Picture Timing SEI values — cannot simulate",
             testable=False)
        return results

    sim = simulate_cpb(hrd, bp_map, pt_map, simulated_sizes, use_nal_type=hrd.nal_hrd_present)

    # HRD-SIM-01: No overflow
    if sim.overflow_count > 0:
        first_of = next(r for r in sim.au_results if r.overflow)
        _add("HRD-SIM-01", "shall", False,
             f"CPB overflow at AU {first_of.au_index} "
             f"(ts={first_of.rtp_timestamp}, "
             f"occupancy={float(first_of.cpb_occupancy_at_removal)/1e6:.2f} Mbit, "
             f"CpbSize={float(hrd.cpb_size)/1e6:.2f} Mbit)")
    else:
        _add("HRD-SIM-01", "shall", True,
             f"No CPB overflow ({len(sim.au_results)} AUs, "
             f"max occupancy {float(sim.max_occupancy_fraction)*100:.1f}%)")

    # HRD-SIM-02: No underflow
    if sim.underflow_count > 0:
        first_uf = next(r for r in sim.au_results if r.underflow)
        _add("HRD-SIM-02", "shall", False,
             f"CPB underflow at AU {first_uf.au_index} "
             f"(ts={first_uf.rtp_timestamp}, "
             f"nominal_removal={float(first_uf.nominal_removal_time)*1000:.3f}ms, "
             f"final_arrival={float(first_uf.final_arrival_time)*1000:.3f}ms)")
    else:
        margin_str = ""
        if sim.min_margin_before_underflow is not None:
            margin_str = (f", min margin "
                          f"{float(sim.min_margin_before_underflow)*1000:.3f}ms")
        _add("HRD-SIM-02", "shall", True,
             f"No CPB underflow ({len(sim.au_results)} AUs{margin_str})")

    # HRD-SIM-03: au_cpb_removal_delay increasing within buffering period
    delay_issue = _check_removal_delay_monotonic(pt_map, bp_map, ctx.rtp_report.access_units)
    if delay_issue:
        _add("HRD-SIM-03", "shall", False, delay_issue)
    else:
        _add("HRD-SIM-03", "shall", True,
             "au_cpb_removal_delay strictly increasing within each buffering period")

    # HRD-SIM-04: Near-overflow warning
    if sim.near_overflow_count > 0:
        _add("HRD-SIM-04", "should", False,
             f"{sim.near_overflow_count} AUs with CPB occupancy > 99% of CpbSize")
    else:
        _add("HRD-SIM-04", "should", True,
             f"No near-overflow conditions (max {float(sim.max_occupancy_fraction)*100:.1f}%)")

    # HRD-SIM-05: Near-underflow warning
    if sim.near_underflow_count > 0:
        _add("HRD-SIM-05", "should", False,
             f"{sim.near_underflow_count} AUs within 1 ClockTick of underflow")
    else:
        _add("HRD-SIM-05", "should", True, "No near-underflow conditions")

    return results


def _check_removal_delay_monotonic(
    pt_map: dict[int, PictureTimingInfo],
    bp_map: dict[int, BufferingPeriodInfo],
    access_units: list[AccessUnit],
) -> str | None:
    """Verify au_cpb_removal_delay_minus1 is strictly increasing within each BP.

    Per H.265 Annex C, the removal time of the first AU in a buffering
    period is derived from InitCpbRemovalDelay, not from
    au_cpb_removal_delay_minus1.  The monotonicity check therefore starts
    from the *second* AU of each buffering period — the first AU that
    actually uses au_cpb_removal_delay for its removal time.
    """
    current_bp_ts: int | None = None
    prev_delay: int | None = None
    is_first_in_bp = False

    for au in access_units:
        ts = au.timestamp
        if ts in bp_map:
            current_bp_ts = ts
            prev_delay = None
            is_first_in_bp = True

        pt = pt_map.get(ts)
        if pt is None:
            continue

        if is_first_in_bp:
            is_first_in_bp = False
            continue

        delay = pt.au_cpb_removal_delay_minus1

        if prev_delay is not None and delay <= prev_delay:
            return (
                f"au_cpb_removal_delay_minus1 not strictly increasing: "
                f"AU ts={ts} has delay={delay}, previous={prev_delay} "
                f"(within BP starting at ts={current_bp_ts})"
            )
        prev_delay = delay

    return None


_SIM_CHECK_DESCRIPTIONS: dict[str, str] = {
    "HRD-SIM-01": "CPB shall never overflow (occupancy <= CpbSize).",
    "HRD-SIM-02": "CPB shall never underflow (nominal removal >= final arrival, unless low_delay_hrd_flag).",
    "HRD-SIM-03": "au_cpb_removal_delay shall be strictly increasing within each buffering period.",
    "HRD-SIM-04": "CPB occupancy should not exceed 99% of CpbSize (near-overflow warning).",
    "HRD-SIM-05": "Nominal removal should not be within 1 ClockTick of final arrival (near-underflow warning).",
}


# ---------------------------------------------------------------------------
# Tier 3: PCAP Timing Cross-Validation (--hrd-timing)
# ---------------------------------------------------------------------------

def check_pcap_timing(ctx: ValidationContext) -> list[RequirementResult]:
    """Run Tier 3 PCAP timing cross-validation checks."""
    results: list[RequirementResult] = []

    def _add(req_id: str, level: str, passed: bool, details: str,
             testable: bool = True) -> None:
        results.append(RequirementResult(
            req_id=req_id, level=level,
            text=_TIMING_CHECK_DESCRIPTIONS.get(req_id, req_id),
            passed=passed, details=details, testable=testable,
        ))

    if ctx.timeline is None:
        _add("HRD-TIME-01", "should", False, "FFmpeg trace unavailable", testable=False)
        return results

    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        _add("HRD-TIME-01", "should", False, "No SPS fields parsed", testable=False)
        return results

    hrd = extract_hrd_parameters(sps)
    if hrd is None:
        _add("HRD-TIME-01", "should", False,
             "Cannot extract HRD parameters", testable=False)
        return results

    bp_map, pt_map, traced_ts = extract_sei_per_au(
        ctx.rtp_report, ctx.timeline.raw_headers,
        lossy_timestamps=ctx.timeline.lossy_timestamps)
    au_sizes = compute_au_sizes(ctx.rtp_report)
    simulated_sizes = [s for s in au_sizes if s.rtp_timestamp in pt_map]

    if not simulated_sizes:
        _add("HRD-TIME-01", "should", False,
             "No AUs with Picture Timing SEI — cannot cross-validate", testable=False)
        return results

    sim = simulate_cpb(hrd, bp_map, pt_map, simulated_sizes, use_nal_type=hrd.nal_hrd_present)

    aus = ctx.rtp_report.access_units
    aus_by_ts = ctx.rtp_report.access_units_by_ts

    # HRD-TIME-01: AU last-packet arrival vs nominal removal ordering
    late_arrivals = 0
    first_late_ts: int | None = None
    for r in sim.au_results:
        au = aus_by_ts.get(r.rtp_timestamp)
        if au is None or au.last_packet_time is None:
            continue
        if len(sim.au_results) < 2:
            continue
        # Compare relative PCAP times to relative HRD removal times
        au0 = aus_by_ts.get(sim.au_results[0].rtp_timestamp)
        if au0 is None or au0.last_packet_time is None:
            continue
        pcap_relative = au.last_packet_time - au0.last_packet_time
        hrd_removal_relative = float(r.cpb_removal_time - sim.au_results[0].cpb_removal_time)
        if pcap_relative > hrd_removal_relative + 0.010:
            late_arrivals += 1
            if first_late_ts is None:
                first_late_ts = r.rtp_timestamp

    if late_arrivals > 0:
        _add("HRD-TIME-01", "should", False,
             f"{late_arrivals} AUs where PCAP last-packet time exceeds "
             f"HRD removal time by >10ms (first ts={first_late_ts})")
    else:
        _add("HRD-TIME-01", "should", True,
             f"PCAP arrival times consistent with HRD removal schedule "
             f"({len(sim.au_results)} AUs)")

    # HRD-TIME-02: Actual bit delivery rate vs signalled BitRate
    timed_aus = [au for au in aus if au.first_packet_time is not None]
    if len(timed_aus) >= 2:
        total_bits = sum(s.size_in_bits_all for s in au_sizes)
        duration = timed_aus[-1].first_packet_time - timed_aus[0].first_packet_time
        if duration and duration > 0:
            actual_rate = total_bits / duration
            declared_rate = float(hrd.bit_rate)
            ratio = actual_rate / declared_rate if declared_rate > 0 else 0
            if ratio > 1.5:
                _add("HRD-TIME-02", "should", False,
                     f"Actual avg rate {actual_rate/1e6:.2f} Mbps is "
                     f"{ratio:.1f}x declared BitRate {declared_rate/1e6:.2f} Mbps")
            elif ratio > 1.2:
                _add("HRD-TIME-02", "should", False,
                     f"Actual avg rate {actual_rate/1e6:.2f} Mbps exceeds "
                     f"declared BitRate {declared_rate/1e6:.2f} Mbps by "
                     f"{(ratio-1)*100:.0f}%")
            else:
                _add("HRD-TIME-02", "should", True,
                     f"Actual avg rate {actual_rate/1e6:.2f} Mbps within "
                     f"declared BitRate {declared_rate/1e6:.2f} Mbps "
                     f"(ratio {ratio:.2f})")
        else:
            _add("HRD-TIME-02", "should", False,
                 "Cannot compute rate — zero duration", testable=False)
    else:
        _add("HRD-TIME-02", "should", False,
             "Not enough timed AUs for rate comparison", testable=False)

    # HRD-TIME-03: Initial buffering delay
    if sim.au_results and bp_map:
        first_bp = next(iter(bp_map.values()))
        declared_delay_s = float(Fraction(first_bp.init_cpb_removal_delay) / 90000)
        au0 = aus_by_ts.get(sim.au_results[0].rtp_timestamp)
        if au0 is not None and au0.first_packet_time is not None and au0.last_packet_time is not None:
            pcap_fill_time = au0.last_packet_time - au0.first_packet_time
            _add("HRD-TIME-03", "should", True,
                 f"InitCpbRemovalDelay={declared_delay_s*1000:.3f}ms, "
                 f"first AU PCAP spread={pcap_fill_time*1000:.3f}ms")
        else:
            _add("HRD-TIME-03", "should", True,
                 f"InitCpbRemovalDelay={declared_delay_s*1000:.3f}ms "
                 f"(no PCAP timing for first AU)", testable=False)
    else:
        _add("HRD-TIME-03", "should", False,
             "No buffering period data for initial delay check", testable=False)

    # HRD-TIME-EQC3: eq (C-3) lower-bound check on wire schedule.
    # Per TR-10-15c §15, the AU offset between encoder CPB insertion and
    # transmission ranges over [0, cpb_size/max_bitrate]. The sender is
    # therefore free to delay AU j's first byte beyond eq (C-3)'s lower
    # bound t_ai(j) = max(t_af(j-1), tai_earliest(j)); doing so is required
    # to honour the encoder pour timeline T_pour(j) (TR-10-9 §11.2b SR
    # cadence + TR-10-15c §15 SR-before-AU). What is NOT permitted is for
    # wire(j) to fire BEFORE eq (C-3)'s lower bound — that would underrun
    # the decoder's CPB. The upper bound (t_af(j) ≤ t_r,n(j)) is enforced
    # separately by HRD-TIME-01. Tolerance is 1 ms (kernel jitter band).
    EQC3_TOLERANCE_S = 0.002  # 2 ms — aligned with IPMX TR-10-9 §11.2b SR-cadence jitter cap
    if len(sim.au_results) >= 2:
        au0_first = None
        for r0 in sim.au_results:
            a0 = aus_by_ts.get(r0.rtp_timestamp)
            if a0 is not None and a0.first_packet_time is not None:
                au0_first = a0.first_packet_time
                au0_hrd_arr = float(r0.init_arrival_time)
                break
        if au0_first is not None:
            max_lateness_s = 0.0
            min_earliness_s = 0.0
            worst_au_ts: int | None = None
            early_count = 0
            for r in sim.au_results:
                au = aus_by_ts.get(r.rtp_timestamp)
                if au is None or au.first_packet_time is None:
                    continue
                pcap_relative = au.first_packet_time - au0_first
                hrd_relative = float(r.init_arrival_time) - au0_hrd_arr
                delta = pcap_relative - hrd_relative
                if delta < -EQC3_TOLERANCE_S:
                    early_count += 1
                    if delta < min_earliness_s:
                        min_earliness_s = delta
                        worst_au_ts = r.rtp_timestamp
                if delta > max_lateness_s:
                    max_lateness_s = delta
            if early_count > 0:
                _add("HRD-TIME-EQC3", "shall", False,
                     f"{early_count} AUs fired BEFORE eq C-3 lower bound by >"
                     f"{EQC3_TOLERANCE_S*1000:.1f}ms; min earliness "
                     f"{min_earliness_s*1000:.3f}ms (at ts={worst_au_ts})")
            else:
                _add("HRD-TIME-EQC3", "shall", True,
                     f"PCAP first-packet times ≥ eq C-3 lower bound within "
                     f"{EQC3_TOLERANCE_S*1000:.1f}ms; max lateness "
                     f"{max_lateness_s*1000:.3f}ms (TR-10-15c §15 permissive "
                     f"AU_offset window, {len(sim.au_results)} AUs)")
        else:
            _add("HRD-TIME-EQC3", "shall", False,
                 "No AU with PCAP first_packet_time — cannot evaluate eq C-3",
                 testable=False)
    else:
        _add("HRD-TIME-EQC3", "shall", False,
             "Need ≥2 AUs in HRD trace for eq C-3 schedule comparison",
             testable=False)

    # HRD-EDELAY-BP0: BP 0's symmetric-CPB E_delay reconstructed from
    # the HRD parameters (CpbSize / BitRate − init_cpb_removal_delay)
    # should equal init_cpb_removal_delay_offset. Equivalently, BP 0's
    # `delay + offset` should equal the canonical CPB transit time
    # CpbSize / BitRate. Cross-validates the SPS VUI HRD parameters
    # against the BP 0 buffering-period SEI; if they disagree, one of
    # the two declarations is internally inconsistent. 1-tick tolerance
    # for integer-rounding noise.
    #
    # Gated on low_delay_hrd_flag == 0: under low_delay_hrd_flag = 1,
    # H.265 §E.3.2 NOTE 3 permits "big pictures" that exceed nominal
    # CPB removal times, and encoders typically oversize the declared
    # CpbSize to absorb them while computing delay/offset against a
    # smaller working envelope. In that regime `delay + offset` is
    # expected to be strictly less than CpbSize/BitRate, so the
    # identity is not a meaningful invariant.
    if bp_map and hrd.bit_rate > 0 and not hrd.low_delay_hrd_flag:
        bp_first = bp_map[next(iter(bp_map))]
        delay_ticks = bp_first.init_cpb_removal_delay
        offset_ticks = bp_first.init_cpb_removal_delay_offset
        # CpbSize/BitRate expressed in 90 kHz ticks (rounded to nearest int).
        cpb_transit_ticks = int(round(float(hrd.cpb_size) * 90000 / float(hrd.bit_rate)))
        our_edelay_ticks = cpb_transit_ticks - delay_ticks
        diff_ticks = our_edelay_ticks - offset_ticks
        if abs(diff_ticks) <= 1:
            _add("HRD-EDELAY-BP0", "should", True,
                 f"BP 0 init_cpb_removal_delay_offset={offset_ticks} ticks "
                 f"({offset_ticks/90000*1000:.3f}ms) matches "
                 f"CpbSize/BitRate − init_cpb_removal_delay "
                 f"= {cpb_transit_ticks} − {delay_ticks} = "
                 f"{our_edelay_ticks} ticks within 1-tick tolerance")
        else:
            _add("HRD-EDELAY-BP0", "should", False,
                 f"BP 0 init_cpb_removal_delay_offset={offset_ticks} ticks "
                 f"differs from CpbSize/BitRate − init_cpb_removal_delay "
                 f"= {cpb_transit_ticks} − {delay_ticks} = "
                 f"{our_edelay_ticks} ticks by {diff_ticks:+d} ticks "
                 f"(> 1-tick tolerance)")
    elif hrd.low_delay_hrd_flag:
        _add("HRD-EDELAY-BP0", "should", True,
             "low_delay_hrd_flag=1 — CpbSize may be oversized for big "
             "pictures; symmetric-CPB identity does not apply",
             testable=False)
    else:
        _add("HRD-EDELAY-BP0", "should", True,
             "No BP SEI or no HRD BitRate — cannot reconstruct E_delay",
             testable=False)

    return results


_TIMING_CHECK_DESCRIPTIONS: dict[str, str] = {
    "HRD-TIME-01": "PCAP last-packet arrival should not exceed HRD nominal removal time.",
    "HRD-TIME-02": "Actual average bit rate should be consistent with declared BitRate.",
    "HRD-TIME-03": "InitCpbRemovalDelay should be consistent with observed initial buffering.",
    "HRD-TIME-EQC3": "PCAP first-packet times shall be ≥ H.265 §C.2.1.1 eq (C-3) lower bound "
                     "max(t_af(j-1), tai_earliest(j)); lateness is permitted by TR-10-15b §15 "
                     "AU_offset window. Underrun (early firing) is the only violation.",
}


# ---------------------------------------------------------------------------
# Top-level entry point for the validator
# ---------------------------------------------------------------------------

def run_hrd_checks(
    ctx: ValidationContext,
    *,
    enable_hrd: bool = False,
    enable_hrd_sim: bool = False,
    enable_hrd_timing: bool = False,
) -> list[RequirementResult]:
    """Run the requested HRD validation tiers and return results.

    --hrd-sim and --hrd-timing imply --hrd.  If Tier 1 fails on critical
    checks, Tier 2 is skipped with a clear message.
    """
    if not enable_hrd and not enable_hrd_sim and not enable_hrd_timing:
        return []

    effective_hrd = enable_hrd or enable_hrd_sim or enable_hrd_timing
    results: list[RequirementResult] = []

    if effective_hrd:
        tier1 = check_hrd_self_consistency(ctx)
        results.extend(tier1)

    if enable_hrd_sim:
        if hrd_self_consistency_passed(results):
            tier2 = check_cpb_simulation(ctx)
            results.extend(tier2)
        else:
            results.append(RequirementResult(
                req_id="HRD-SIM-00",
                level="shall",
                text="CPB simulation requires passing HRD self-consistency checks.",
                passed=False,
                details="Skipped: one or more HRD self-consistency checks (HRD-01..HRD-11) failed.",
                testable=False,
            ))

    if enable_hrd_timing:
        if hrd_self_consistency_passed(results):
            tier3 = check_pcap_timing(ctx)
            results.extend(tier3)
        else:
            results.append(RequirementResult(
                req_id="HRD-TIME-00",
                level="should",
                text="PCAP timing cross-validation requires passing HRD self-consistency checks.",
                passed=False,
                details="Skipped: one or more HRD self-consistency checks (HRD-01..HRD-11) failed.",
                testable=False,
            ))

    return results
