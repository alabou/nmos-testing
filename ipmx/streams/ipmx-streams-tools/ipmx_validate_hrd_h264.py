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
"""HRD (Hypothetical Reference Decoder) validation for H.264/AVC streams.

Implements three tiers of validation controlled by CLI flags:

  --hrd          Tier 1: Self-consistency checks on HRD/SEI parameters.
  --hrd-sim      Tier 2: CPB leaky-bucket simulation (implies --hrd).
  --hrd-timing   Tier 3: PCAP timing cross-validation (implies --hrd).

The CPB simulation follows ITU-T H.264 Annex C using exact Fraction
arithmetic so that no rounding errors accumulate.  The leaky-bucket
model is structurally identical to H.265 and is reused from
``ipmx_validate_hrd.simulate_cpb``.

Key differences from H.265:
  - No VPS; timing info is in SPS VUI only.
  - Field naming: ``cpb_removal_delay`` (direct tick count) vs
    H.265's ``au_cpb_removal_delay_minus1`` (tick count minus 1).
  - NAL types: VCL = 1-5, IDR = 5, SPS = 7, PPS = 8, SEI = 6.
  - No sub-picture HRD.
"""

from __future__ import annotations

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
from ipmx_validate_hrd import (
    AccessUnitSize,
    BufferingPeriodInfo,
    CpbSimulationSummary,
    HrdParameters,
    PictureTimingInfo,
    simulate_cpb,
    _get_sei_int,
)


# ---------------------------------------------------------------------------
# H.264 NAL type constants
# ---------------------------------------------------------------------------

_H264_VCL_RANGE = range(1, 6)       # NAL types 1-5 are VCL
_H264_IDR_NAL_TYPE = 5
_H264_SEI_NAL_TYPE = 6
_H264_SPS_NAL_TYPE = 7
_H264_PPS_NAL_TYPE = 8

_TRACE_NAL_TYPES_H264 = {
    _H264_SEI_NAL_TYPE,
    _H264_SPS_NAL_TYPE,
    _H264_PPS_NAL_TYPE,
}

_NAL_TO_HDR_H264 = {
    _H264_SEI_NAL_TYPE: "SEI",
    _H264_SPS_NAL_TYPE: "SPS",
    _H264_PPS_NAL_TYPE: "PPS",
}


# ---------------------------------------------------------------------------
# Extraction: SPS → HrdParameters (H.264-specific)
# ---------------------------------------------------------------------------

def extract_hrd_parameters_h264(sps: dict[str, Any]) -> HrdParameters | None:
    """Extract HRD parameters from H.264 SPS trace fields.

    H.264 uses ``timing_info_present_flag`` / ``num_units_in_tick`` /
    ``time_scale`` (no ``vui_`` prefix) and has no VPS or sub-picture HRD.
    """
    nal_hrd = get_int_field(sps, "nal_hrd_parameters_present_flag")
    if nal_hrd != 1:
        return None

    timing_present = get_int_field(sps, "timing_info_present_flag")
    if timing_present is None:
        timing_present = get_int_field(sps, "vui_timing_info_present_flag")

    num_units = get_int_field(sps, "num_units_in_tick")
    if num_units is None:
        num_units = get_int_field(sps, "vui_num_units_in_tick")

    time_scale = get_int_field(sps, "time_scale")
    if time_scale is None:
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

    low_delay_val = get_int_field(sps, "low_delay_hrd_flag")
    low_delay_hrd_flag = low_delay_val == 1

    init_delay_len = get_int_field(sps, "initial_cpb_removal_delay_length_minus1")
    cpb_delay_len = get_int_field(sps, "cpb_removal_delay_length_minus1")
    dpb_delay_len = get_int_field(sps, "dpb_output_delay_length_minus1")
    if init_delay_len is None or cpb_delay_len is None or dpb_delay_len is None:
        return None

    return HrdParameters(
        nal_hrd_present=True,
        vcl_hrd_present=False,
        bit_rate=bit_rate,
        cpb_size=cpb_size,
        cbr_flag=cbr_flag,
        low_delay_hrd_flag=low_delay_hrd_flag,
        initial_cpb_removal_delay_length=init_delay_len + 1,
        au_cpb_removal_delay_length=cpb_delay_len + 1,
        dpb_output_delay_length=dpb_delay_len + 1,
        sub_pic_hrd_params_present=False,
        clock_tick=clock_tick,
        clock_sub_tick=None,
    )


# ---------------------------------------------------------------------------
# Extraction: SEI fields from FFmpeg trace headers (H.264-specific)
# ---------------------------------------------------------------------------

_BP_FIELDS_H264 = {"initial_cpb_removal_delay", "initial_cpb_removal_delay[0]"}
_PT_FIELDS_H264 = {"cpb_removal_delay", "dpb_output_delay"}


def extract_sei_per_au_h264(
    report: RtpReport,
    raw_headers: list[dict[str, Any]],
    lossy_timestamps: set[int] | None = None,
) -> tuple[
    dict[int, BufferingPeriodInfo],
    dict[int, PictureTimingInfo],
    set[int],
]:
    """Walk ``raw_headers`` in parallel with ``nalus_meta`` to extract H.264 SEI values.

    H.264 Buffering Period SEI carries ``initial_cpb_removal_delay`` and
    ``initial_cpb_removal_delay_offset``.  Picture Timing SEI carries
    ``cpb_removal_delay`` (direct tick count, not minus-1) and
    ``dpb_output_delay``.

    To reuse ``simulate_cpb`` which expects ``au_cpb_removal_delay_minus1``,
    we store ``cpb_removal_delay - 1`` in the ``PictureTimingInfo`` field.
    """
    bp_map: dict[int, BufferingPeriodInfo] = {}
    pt_map: dict[int, PictureTimingInfo] = {}
    traced_ts: set[int] = set()

    au_index_by_ts: dict[int, int] = {}
    for au in report.access_units:
        au_index_by_ts[au.timestamp] = au.index

    for meta, header in walk_trace_pairs(
        report, raw_headers, _NAL_TO_HDR_H264, skip_timestamps=lossy_timestamps
    ):
        ts = int(meta["timestamp"])
        traced_ts.add(ts)

        if header.get("type") != "SEI":
            continue

        fields: dict[str, Any] = header.get("fields", {})
        keys = set(fields.keys())
        au_idx = au_index_by_ts.get(ts, -1)

        if keys & _BP_FIELDS_H264 and ts not in bp_map:
            init_delay = _get_sei_int(fields, "initial_cpb_removal_delay[0]")
            if init_delay is None:
                init_delay = _get_sei_int(fields, "initial_cpb_removal_delay")

            init_offset = _get_sei_int(fields, "initial_cpb_removal_delay_offset[0]")
            if init_offset is None:
                init_offset = _get_sei_int(fields, "initial_cpb_removal_delay_offset")

            if init_delay is not None:
                bp_map[ts] = BufferingPeriodInfo(
                    au_index=au_idx,
                    rtp_timestamp=ts,
                    init_cpb_removal_delay=init_delay,
                    init_cpb_removal_delay_offset=init_offset or 0,
                    concatenation_flag=False,
                    cpb_delay_offset=0,
                    dpb_delay_offset=0,
                    is_irap_alt=False,
                )

        if keys & _PT_FIELDS_H264 and ts not in pt_map:
            removal_delay = _get_sei_int(fields, "cpb_removal_delay")
            dpb_output = _get_sei_int(fields, "dpb_output_delay")
            if removal_delay is not None:
                pt_map[ts] = PictureTimingInfo(
                    au_index=au_idx,
                    rtp_timestamp=ts,
                    au_cpb_removal_delay_minus1=removal_delay - 1,
                    pic_dpb_output_delay=dpb_output or 0,
                )

    return bp_map, pt_map, traced_ts


# ---------------------------------------------------------------------------
# Extraction: AU sizes from RTP report (H.264 VCL range)
# ---------------------------------------------------------------------------

def compute_au_sizes_h264(report: RtpReport) -> list[AccessUnitSize]:
    """Compute bit-sizes of each access unit using H.264 VCL NAL types (1-5)."""
    vcl_bits_by_ts: dict[int, int] = {}
    all_bits_by_ts: dict[int, int] = {}

    for meta in report.nalus_meta:
        ts = int(meta["timestamp"])
        nalu_size = int(meta.get("nalu_size", 0))
        bits = nalu_size * 8
        all_bits_by_ts[ts] = all_bits_by_ts.get(ts, 0) + bits
        nal_type = int(meta.get("nal_type", -1))
        if nal_type in _H264_VCL_RANGE:
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

_H264_HRD_CHECK_DESCRIPTIONS: dict[str, str] = {
    "H264-HRD-01": "nal_hrd_parameters_present_flag shall be 1.",
    "H264-HRD-02": "ClockTick shall be derivable (timing_info_present_flag, num_units_in_tick > 0, time_scale > 0).",
    "H264-HRD-03": "BitRate[0] shall be derivable from bit_rate_value_minus1 and bit_rate_scale.",
    "H264-HRD-04": "CpbSize[0] shall be derivable from cpb_size_value_minus1 and cpb_size_scale.",
    "H264-HRD-05": "cpb_cnt_minus1 shall be 0 (single delivery schedule).",
    "H264-HRD-06": "initial_cpb_removal_delay_length_minus1 shall be present and in [0..31].",
    "H264-HRD-07": "cpb_removal_delay_length_minus1 shall be present and in [0..31].",
    "H264-HRD-08": "dpb_output_delay_length_minus1 shall be present and in [0..31].",
    "H264-HRD-09": "Buffering Period SEI shall be present at each IDR access unit.",
    "H264-HRD-10": "Picture Timing SEI shall be present for each access unit (from first IDR onward).",
    "H264-HRD-11": "cbr_flag / low_delay_hrd_flag values noted.",
}


def check_hrd_self_consistency(ctx: ValidationContext) -> list[RequirementResult]:
    """Run all Tier 1 H.264 HRD self-consistency checks."""
    results: list[RequirementResult] = []

    def _add(req_id: str, passed: bool, details: str, testable: bool = True) -> None:
        results.append(RequirementResult(
            req_id=req_id,
            level="shall",
            text=_H264_HRD_CHECK_DESCRIPTIONS.get(req_id, req_id),
            passed=passed,
            details=details,
            testable=testable,
        ))

    if ctx.timeline is None:
        _add("H264-HRD-01", False, "FFmpeg trace unavailable", testable=False)
        return results

    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        _add("H264-HRD-01", False, "No SPS fields parsed", testable=False)
        return results

    # H264-HRD-01: nal_hrd_parameters_present_flag
    nal_hrd = get_int_field(sps, "nal_hrd_parameters_present_flag")
    if nal_hrd != 1:
        _add("H264-HRD-01", False, f"nal_hrd_parameters_present_flag={nal_hrd}")
    else:
        _add("H264-HRD-01", True, "nal_hrd_parameters_present_flag=1")

    # H264-HRD-02: ClockTick derivable
    num_units = get_int_field(sps, "num_units_in_tick")
    if num_units is None:
        num_units = get_int_field(sps, "vui_num_units_in_tick")
    time_scale = get_int_field(sps, "time_scale")
    if time_scale is None:
        time_scale = get_int_field(sps, "vui_time_scale")

    if not num_units or not time_scale or num_units <= 0 or time_scale <= 0:
        _add("H264-HRD-02", False,
             f"num_units_in_tick={num_units}, time_scale={time_scale}")
    else:
        ct = Fraction(num_units, time_scale)
        _add("H264-HRD-02", True,
             f"ClockTick={float(ct)*1000:.6f}ms "
             f"(num_units_in_tick={num_units}, time_scale={time_scale})")

    # H264-HRD-03: BitRate derivable
    bit_rate_scale = get_int_field(sps, "bit_rate_scale")
    br_val = get_int_field(sps, "bit_rate_value_minus1[0]")
    if br_val is None:
        br_val = get_int_field(sps, "bit_rate_value_minus1")
    if bit_rate_scale is None or br_val is None:
        _add("H264-HRD-03", False,
             f"bit_rate_scale={bit_rate_scale}, bit_rate_value_minus1={br_val}")
    else:
        br = (br_val + 1) * (2 ** (6 + bit_rate_scale))
        _add("H264-HRD-03", True, f"BitRate[0]={br/1e6:.2f} Mbps")

    # H264-HRD-04: CpbSize derivable
    cpb_size_scale = get_int_field(sps, "cpb_size_scale")
    cs_val = get_int_field(sps, "cpb_size_value_minus1[0]")
    if cs_val is None:
        cs_val = get_int_field(sps, "cpb_size_value_minus1")
    if cpb_size_scale is None or cs_val is None:
        _add("H264-HRD-04", False,
             f"cpb_size_scale={cpb_size_scale}, cpb_size_value_minus1={cs_val}")
    else:
        cs = (cs_val + 1) * (2 ** (4 + cpb_size_scale))
        _add("H264-HRD-04", True, f"CpbSize[0]={cs/1e6:.2f} Mbit")

    # H264-HRD-05: cpb_cnt_minus1 == 0
    cpb_cnt = get_int_field(sps, "cpb_cnt_minus1")
    if cpb_cnt is None:
        _add("H264-HRD-05", False, "cpb_cnt_minus1 not present")
    elif cpb_cnt != 0:
        _add("H264-HRD-05", False, f"cpb_cnt_minus1={cpb_cnt}, expected 0")
    else:
        _add("H264-HRD-05", True, "cpb_cnt_minus1=0")

    # H264-HRD-06..08: delay length fields
    for req_id, field_name in [
        ("H264-HRD-06", "initial_cpb_removal_delay_length_minus1"),
        ("H264-HRD-07", "cpb_removal_delay_length_minus1"),
        ("H264-HRD-08", "dpb_output_delay_length_minus1"),
    ]:
        val = get_int_field(sps, field_name)
        if val is None:
            _add(req_id, False, f"{field_name} not present")
        elif val < 0 or val > 31:
            _add(req_id, False, f"{field_name}={val} out of range [0..31]")
        else:
            _add(req_id, True, f"{field_name}={val} (length={val + 1} bits)")

    # H264-HRD-09: Buffering Period SEI at every IDR
    bp_result = _check_bp_presence_h264(ctx)
    _add("H264-HRD-09", *bp_result)

    # H264-HRD-10: Picture Timing SEI at every AU (from first IDR onward)
    pt_result = _check_pt_presence_h264(ctx)
    _add("H264-HRD-10", *pt_result)

    # H264-HRD-11: cbr_flag / low_delay_hrd_flag
    cb = get_int_field(sps, "cbr_flag[0]")
    if cb is None:
        cb = get_int_field(sps, "cbr_flag")
    ld = get_int_field(sps, "low_delay_hrd_flag")
    mode_str = "CBR" if cb == 1 else "VBR"
    ld_str = f"low_delay_hrd_flag={ld}" if ld is not None else "low_delay_hrd_flag not present (inferred 0)"
    _add("H264-HRD-11", True, f"cbr_flag={cb} ({mode_str}), {ld_str}")

    return results


def _compute_traced_timestamps_h264(
    report: RtpReport,
    raw_headers: list[dict[str, Any]],
    lossy_timestamps: set[int] | None = None,
) -> tuple[set[int], dict[int, set[str]]]:
    """Compute the set of AU timestamps covered by the FFmpeg trace (H.264).

    Pairs each filtered nalus_meta entry with the next raw_headers entry of
    the matching FFmpeg trace type (SEI=6, SPS=7, PPS=8). Robust to
    trace_headers dropping individual blocks for malformed NALs.

    AUs in ``lossy_timestamps`` (slice-only packets where FFmpeg emitted
    no PPS/SEI/SPS) are skipped from coverage so that subsequent AUs stay
    aligned with raw_headers and HRD checks don't judge them.
    """
    traced_ts: set[int] = set()
    sei_map: dict[int, set[str]] = {}
    for meta, header in walk_trace_pairs(
        report, raw_headers, _NAL_TO_HDR_H264, skip_timestamps=lossy_timestamps
    ):
        ts = int(meta["timestamp"])
        traced_ts.add(ts)
        if header.get("type") == "SEI":
            fields = header.get("fields", {})
            sei_map.setdefault(ts, set()).update(fields.keys())
    return traced_ts, sei_map


def _check_bp_presence_h264(ctx: ValidationContext) -> tuple[bool, str]:
    """Check buffering period SEI at every IDR (H.264 NAL type 5)."""
    if ctx.timeline is None:
        return False, "FFmpeg trace unavailable"
    traced_ts, sei_map = _compute_traced_timestamps_h264(
        ctx.rtp_report,
        ctx.timeline.raw_headers,
        lossy_timestamps=ctx.timeline.lossy_timestamps,
    )

    idr_aus = [
        au for au in ctx.rtp_report.access_units
        if _H264_IDR_NAL_TYPE in au.nal_types
        and au.timestamp in traced_ts
    ]
    if not idr_aus:
        return (False, "No traced IDR access units detected")
    missing = [
        au.timestamp for au in idr_aus
        if not (sei_map.get(au.timestamp, set()) & _BP_FIELDS_H264)
    ]
    if missing:
        return (False,
                f"{len(missing)}/{len(idr_aus)} IDR AUs missing Buffering Period SEI "
                f"(first missing ts={missing[0]})")
    return (True,
            f"Buffering Period SEI present at all {len(idr_aus)} traced IDR AUs")


def _check_pt_presence_h264(ctx: ValidationContext) -> tuple[bool, str]:
    """Check picture timing SEI at every traced AU from the first IDR onward.

    AUs before the first IDR are not part of the HRD model and are excluded.
    """
    if ctx.timeline is None:
        return False, "FFmpeg trace unavailable"
    traced_ts, sei_map = _compute_traced_timestamps_h264(
        ctx.rtp_report,
        ctx.timeline.raw_headers,
        lossy_timestamps=ctx.timeline.lossy_timestamps,
    )

    first_idr_idx: int | None = None
    for au in ctx.rtp_report.access_units:
        if _H264_IDR_NAL_TYPE in au.nal_types:
            first_idr_idx = au.index
            break

    traced_aus = [
        au for au in ctx.rtp_report.access_units
        if au.timestamp in traced_ts
        and (first_idr_idx is not None and au.index >= first_idr_idx)
    ]
    if not traced_aus:
        return (False, "No access units covered by trace from first IDR onward")
    missing = [
        au.timestamp for au in traced_aus
        if not (sei_map.get(au.timestamp, set()) & _PT_FIELDS_H264)
    ]
    if missing:
        return (False,
                f"{len(missing)}/{len(traced_aus)} traced AUs missing "
                f"Picture Timing SEI (first missing ts={missing[0]})")
    return (True,
            f"Picture Timing SEI present in all {len(traced_aus)} traced AUs "
            f"(from first IDR onward)")


def hrd_self_consistency_passed(results: list[RequirementResult]) -> bool:
    """Return True if all critical H.264 HRD self-consistency checks passed.

    Checks H264-HRD-01 through H264-HRD-10 must pass for simulation to be meaningful.
    H264-HRD-11 is informational.
    """
    critical_ids = {f"H264-HRD-{i:02d}" for i in range(1, 11)}
    for r in results:
        if r.req_id in critical_ids and not r.passed and r.testable:
            return False
    return True


# ---------------------------------------------------------------------------
# Tier 2: CPB Simulation (--hrd-sim)
# ---------------------------------------------------------------------------

_H264_SIM_CHECK_DESCRIPTIONS: dict[str, str] = {
    "H264-HRD-SIM-01": "CPB shall never overflow (occupancy <= CpbSize).",
    "H264-HRD-SIM-02": "CPB shall never underflow (nominal removal >= final arrival, unless low_delay_hrd_flag).",
    "H264-HRD-SIM-03": "cpb_removal_delay shall be strictly increasing within each buffering period.",
    "H264-HRD-SIM-04": "CPB occupancy should not exceed 99% of CpbSize (near-overflow warning).",
    "H264-HRD-SIM-05": "Nominal removal should not be within 1 ClockTick of final arrival (near-underflow warning).",
}


def check_cpb_simulation(ctx: ValidationContext) -> list[RequirementResult]:
    """Run Tier 2 CPB simulation checks for H.264."""
    results: list[RequirementResult] = []

    def _add(req_id: str, level: str, passed: bool, details: str,
             testable: bool = True) -> None:
        results.append(RequirementResult(
            req_id=req_id, level=level,
            text=_H264_SIM_CHECK_DESCRIPTIONS.get(req_id, req_id),
            passed=passed, details=details, testable=testable,
        ))

    if ctx.timeline is None:
        _add("H264-HRD-SIM-01", "shall", False, "FFmpeg trace unavailable", testable=False)
        return results

    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        _add("H264-HRD-SIM-01", "shall", False, "No SPS fields parsed", testable=False)
        return results

    hrd = extract_hrd_parameters_h264(sps)
    if hrd is None:
        _add("H264-HRD-SIM-01", "shall", False,
             "Cannot extract HRD parameters — run --hrd first", testable=False)
        return results

    bp_map, pt_map, traced_ts = extract_sei_per_au_h264(
        ctx.rtp_report,
        ctx.timeline.raw_headers,
        lossy_timestamps=ctx.timeline.lossy_timestamps,
    )
    au_sizes = compute_au_sizes_h264(ctx.rtp_report)

    simulated_sizes = [s for s in au_sizes if s.rtp_timestamp in pt_map]
    if not simulated_sizes:
        _add("H264-HRD-SIM-01", "shall", False,
             "No AUs with Picture Timing SEI values — cannot simulate",
             testable=False)
        return results

    sim = simulate_cpb(hrd, bp_map, pt_map, simulated_sizes, use_nal_type=True)

    # H264-HRD-SIM-01: No overflow
    if sim.overflow_count > 0:
        first_of = next(r for r in sim.au_results if r.overflow)
        _add("H264-HRD-SIM-01", "shall", False,
             f"CPB overflow at AU {first_of.au_index} "
             f"(ts={first_of.rtp_timestamp}, "
             f"occupancy={float(first_of.cpb_occupancy_at_removal)/1e6:.2f} Mbit, "
             f"CpbSize={float(hrd.cpb_size)/1e6:.2f} Mbit)")
    else:
        _add("H264-HRD-SIM-01", "shall", True,
             f"No CPB overflow ({len(sim.au_results)} AUs, "
             f"max occupancy {float(sim.max_occupancy_fraction)*100:.1f}%)")

    # H264-HRD-SIM-02: No underflow
    if sim.underflow_count > 0:
        first_uf = next(r for r in sim.au_results if r.underflow)
        _add("H264-HRD-SIM-02", "shall", False,
             f"CPB underflow at AU {first_uf.au_index} "
             f"(ts={first_uf.rtp_timestamp}, "
             f"nominal_removal={float(first_uf.nominal_removal_time)*1000:.3f}ms, "
             f"final_arrival={float(first_uf.final_arrival_time)*1000:.3f}ms)")
    else:
        margin_str = ""
        if sim.min_margin_before_underflow is not None:
            margin_str = (f", min margin "
                          f"{float(sim.min_margin_before_underflow)*1000:.3f}ms")
        _add("H264-HRD-SIM-02", "shall", True,
             f"No CPB underflow ({len(sim.au_results)} AUs{margin_str})")

    # H264-HRD-SIM-03: cpb_removal_delay increasing within buffering period
    delay_issue = _check_removal_delay_monotonic_h264(
        pt_map, bp_map, ctx.rtp_report.access_units)
    if delay_issue:
        _add("H264-HRD-SIM-03", "shall", False, delay_issue)
    else:
        _add("H264-HRD-SIM-03", "shall", True,
             "cpb_removal_delay strictly increasing within each buffering period")

    # H264-HRD-SIM-04: Near-overflow warning
    if sim.near_overflow_count > 0:
        _add("H264-HRD-SIM-04", "should", False,
             f"{sim.near_overflow_count} AUs with CPB occupancy > 99% of CpbSize")
    else:
        _add("H264-HRD-SIM-04", "should", True,
             f"No near-overflow conditions (max {float(sim.max_occupancy_fraction)*100:.1f}%)")

    # H264-HRD-SIM-05: Near-underflow warning
    if sim.near_underflow_count > 0:
        _add("H264-HRD-SIM-05", "should", False,
             f"{sim.near_underflow_count} AUs within 1 ClockTick of underflow")
    else:
        _add("H264-HRD-SIM-05", "should", True, "No near-underflow conditions")

    return results


def _check_removal_delay_monotonic_h264(
    pt_map: dict[int, PictureTimingInfo],
    bp_map: dict[int, BufferingPeriodInfo],
    access_units: list[AccessUnit],
) -> str | None:
    """Verify cpb_removal_delay is strictly increasing within each BP (H.264).

    The first AU of each buffering period uses InitCpbRemovalDelay for its
    removal time, so monotonicity starts from the second AU of each BP.

    Note: ``PictureTimingInfo.au_cpb_removal_delay_minus1`` stores
    ``cpb_removal_delay - 1`` for H.264, so we compare the stored values
    directly (monotonicity is preserved by the subtraction).
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
                f"cpb_removal_delay not strictly increasing: "
                f"AU ts={ts} has delay={delay + 1}, previous={prev_delay + 1} "
                f"(within BP starting at ts={current_bp_ts})"
            )
        prev_delay = delay

    return None


# ---------------------------------------------------------------------------
# Tier 3: PCAP Timing Cross-Validation (--hrd-timing)
# ---------------------------------------------------------------------------

_H264_TIMING_CHECK_DESCRIPTIONS: dict[str, str] = {
    "H264-HRD-TIME-01": "PCAP last-packet arrival should not exceed HRD nominal removal time.",
    "H264-HRD-TIME-02": "Actual average bit rate should be consistent with declared BitRate.",
    "H264-HRD-TIME-03": "InitCpbRemovalDelay should be consistent with observed initial buffering.",
    "H264-HRD-TIME-EQC3": "PCAP first-packet times shall be ≥ H.264 §C.1.1 eq (C-3) lower bound "
                          "max(t_af(j-1), tai_earliest(j)); lateness is permitted by TR-10-15c §15 "
                          "AU_offset window. Underrun (early firing) is the only violation.",
}


def check_pcap_timing(ctx: ValidationContext) -> list[RequirementResult]:
    """Run Tier 3 PCAP timing cross-validation checks for H.264."""
    results: list[RequirementResult] = []

    def _add(req_id: str, level: str, passed: bool, details: str,
             testable: bool = True) -> None:
        results.append(RequirementResult(
            req_id=req_id, level=level,
            text=_H264_TIMING_CHECK_DESCRIPTIONS.get(req_id, req_id),
            passed=passed, details=details, testable=testable,
        ))

    if ctx.timeline is None:
        _add("H264-HRD-TIME-01", "should", False, "FFmpeg trace unavailable", testable=False)
        return results

    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        _add("H264-HRD-TIME-01", "should", False, "No SPS fields parsed", testable=False)
        return results

    hrd = extract_hrd_parameters_h264(sps)
    if hrd is None:
        _add("H264-HRD-TIME-01", "should", False,
             "Cannot extract HRD parameters", testable=False)
        return results

    bp_map, pt_map, traced_ts = extract_sei_per_au_h264(
        ctx.rtp_report,
        ctx.timeline.raw_headers,
        lossy_timestamps=ctx.timeline.lossy_timestamps,
    )
    au_sizes = compute_au_sizes_h264(ctx.rtp_report)
    simulated_sizes = [s for s in au_sizes if s.rtp_timestamp in pt_map]

    if not simulated_sizes:
        _add("H264-HRD-TIME-01", "should", False,
             "No AUs with Picture Timing SEI — cannot cross-validate", testable=False)
        return results

    sim = simulate_cpb(hrd, bp_map, pt_map, simulated_sizes, use_nal_type=True)

    aus = ctx.rtp_report.access_units
    aus_by_ts = ctx.rtp_report.access_units_by_ts

    # H264-HRD-TIME-01: AU last-packet arrival vs nominal removal ordering
    late_arrivals = 0
    first_late_ts: int | None = None
    for r in sim.au_results:
        au = aus_by_ts.get(r.rtp_timestamp)
        if au is None or au.last_packet_time is None:
            continue
        if len(sim.au_results) < 2:
            continue
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
        _add("H264-HRD-TIME-01", "should", False,
             f"{late_arrivals} AUs where PCAP last-packet time exceeds "
             f"HRD removal time by >10ms (first ts={first_late_ts})")
    else:
        _add("H264-HRD-TIME-01", "should", True,
             f"PCAP arrival times consistent with HRD removal schedule "
             f"({len(sim.au_results)} AUs)")

    # H264-HRD-TIME-02: Actual bit delivery rate vs signalled BitRate
    timed_aus = [au for au in aus if au.first_packet_time is not None]
    if len(timed_aus) >= 2:
        total_bits = sum(s.size_in_bits_all for s in au_sizes)
        duration = timed_aus[-1].first_packet_time - timed_aus[0].first_packet_time
        if duration and duration > 0:
            actual_rate = total_bits / duration
            declared_rate = float(hrd.bit_rate)
            ratio = actual_rate / declared_rate if declared_rate > 0 else 0
            if ratio > 1.5:
                _add("H264-HRD-TIME-02", "should", False,
                     f"Actual avg rate {actual_rate/1e6:.2f} Mbps is "
                     f"{ratio:.1f}x declared BitRate {declared_rate/1e6:.2f} Mbps")
            elif ratio > 1.2:
                _add("H264-HRD-TIME-02", "should", False,
                     f"Actual avg rate {actual_rate/1e6:.2f} Mbps exceeds "
                     f"declared BitRate {declared_rate/1e6:.2f} Mbps by "
                     f"{(ratio-1)*100:.0f}%")
            else:
                _add("H264-HRD-TIME-02", "should", True,
                     f"Actual avg rate {actual_rate/1e6:.2f} Mbps within "
                     f"declared BitRate {declared_rate/1e6:.2f} Mbps "
                     f"(ratio {ratio:.2f})")
        else:
            _add("H264-HRD-TIME-02", "should", False,
                 "Cannot compute rate — zero duration", testable=False)
    else:
        _add("H264-HRD-TIME-02", "should", False,
             "Not enough timed AUs for rate comparison", testable=False)

    # H264-HRD-TIME-03: Initial buffering delay
    if sim.au_results and bp_map:
        first_bp = next(iter(bp_map.values()))
        declared_delay_s = float(Fraction(first_bp.init_cpb_removal_delay) / 90000)
        au0 = aus_by_ts.get(sim.au_results[0].rtp_timestamp)
        if au0 is not None and au0.first_packet_time is not None and au0.last_packet_time is not None:
            pcap_fill_time = au0.last_packet_time - au0.first_packet_time
            _add("H264-HRD-TIME-03", "should", True,
                 f"InitCpbRemovalDelay={declared_delay_s*1000:.3f}ms, "
                 f"first AU PCAP spread={pcap_fill_time*1000:.3f}ms")
        else:
            _add("H264-HRD-TIME-03", "should", True,
                 f"InitCpbRemovalDelay={declared_delay_s*1000:.3f}ms "
                 f"(no PCAP timing for first AU)", testable=False)
    else:
        _add("H264-HRD-TIME-03", "should", False,
             "No buffering period data for initial delay check", testable=False)

    # H264-HRD-TIME-EQC3: eq (C-3) lower-bound check on wire schedule.
    # Per TR-10-15c §15, the AU offset between encoder CPB insertion and
    # transmission ranges over [0, cpb_size/max_bitrate]. The sender is
    # therefore free to delay AU j's first byte beyond eq (C-3)'s lower
    # bound t_ai(j) = max(t_af(j-1), tai_earliest(j)); doing so is required
    # to honour the encoder pour timeline T_pour(j) (TR-10-9 §11.2b SR
    # cadence + TR-10-15c §15 SR-before-AU). What is NOT permitted is for
    # wire(j) to fire BEFORE eq (C-3)'s lower bound — that would underrun
    # the decoder's CPB. The upper bound (t_af(j) ≤ t_r,n(j)) is enforced
    # separately by H264-HRD-TIME-01. Tolerance is 1 ms (kernel jitter band).
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
                _add("H264-HRD-TIME-EQC3", "shall", False,
                     f"{early_count} AUs fired BEFORE eq C-3 lower bound by >"
                     f"{EQC3_TOLERANCE_S*1000:.1f}ms; min earliness "
                     f"{min_earliness_s*1000:.3f}ms (at ts={worst_au_ts})")
            else:
                _add("H264-HRD-TIME-EQC3", "shall", True,
                     f"PCAP first-packet times ≥ eq C-3 lower bound within "
                     f"{EQC3_TOLERANCE_S*1000:.1f}ms; max lateness "
                     f"{max_lateness_s*1000:.3f}ms (TR-10-15c §15 permissive "
                     f"AU_offset window, {len(sim.au_results)} AUs)")
        else:
            _add("H264-HRD-TIME-EQC3", "shall", False,
                 "No AU with PCAP first_packet_time — cannot evaluate eq C-3",
                 testable=False)
    else:
        _add("H264-HRD-TIME-EQC3", "shall", False,
             "Need ≥2 AUs in HRD trace for eq C-3 schedule comparison",
             testable=False)

    # H264-HRD-EDELAY-BP0: BP 0's symmetric-CPB E_delay reconstructed
    # from the HRD parameters (CpbSize / BitRate − init_cpb_removal_delay)
    # should equal init_cpb_removal_delay_offset. Equivalently, BP 0's
    # `delay + offset` should equal the canonical CPB transit time
    # CpbSize / BitRate. Cross-validates the SPS VUI HRD parameters
    # against the BP 0 buffering-period SEI; if they disagree, one of
    # the two declarations is internally inconsistent. 1-tick tolerance
    # for integer-rounding noise.
    #
    # Gated on low_delay_hrd_flag == 0: under low_delay_hrd_flag = 1,
    # H.264 Annex E.2.2 permits "big pictures" that exceed nominal CPB
    # removal times, and encoders typically oversize the declared
    # CpbSize to absorb them while computing delay/offset against a
    # smaller working envelope. In that regime `delay + offset` is
    # expected to be strictly less than CpbSize/BitRate, so the
    # identity is not a meaningful invariant.
    if bp_map and hrd.bit_rate > 0 and not hrd.low_delay_hrd_flag:
        bp_first = bp_map[next(iter(bp_map))]
        delay_ticks = bp_first.init_cpb_removal_delay
        offset_ticks = bp_first.init_cpb_removal_delay_offset
        cpb_transit_ticks = int(round(float(hrd.cpb_size) * 90000 / float(hrd.bit_rate)))
        our_edelay_ticks = cpb_transit_ticks - delay_ticks
        diff_ticks = our_edelay_ticks - offset_ticks
        if abs(diff_ticks) <= 1:
            _add("H264-HRD-EDELAY-BP0", "should", True,
                 f"BP 0 init_cpb_removal_delay_offset={offset_ticks} ticks "
                 f"({offset_ticks/90000*1000:.3f}ms) matches "
                 f"CpbSize/BitRate − init_cpb_removal_delay "
                 f"= {cpb_transit_ticks} − {delay_ticks} = "
                 f"{our_edelay_ticks} ticks within 1-tick tolerance")
        else:
            _add("H264-HRD-EDELAY-BP0", "should", False,
                 f"BP 0 init_cpb_removal_delay_offset={offset_ticks} ticks "
                 f"differs from CpbSize/BitRate − init_cpb_removal_delay "
                 f"= {cpb_transit_ticks} − {delay_ticks} = "
                 f"{our_edelay_ticks} ticks by {diff_ticks:+d} ticks "
                 f"(> 1-tick tolerance)")
    elif hrd.low_delay_hrd_flag:
        _add("H264-HRD-EDELAY-BP0", "should", True,
             "low_delay_hrd_flag=1 — CpbSize may be oversized for big "
             "pictures; symmetric-CPB identity does not apply",
             testable=False)
    else:
        _add("H264-HRD-EDELAY-BP0", "should", True,
             "No BP SEI or no HRD BitRate — cannot reconstruct E_delay",
             testable=False)

    return results


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------

def run_hrd_checks(
    ctx: ValidationContext,
    *,
    enable_hrd: bool = False,
    enable_hrd_sim: bool = False,
    enable_hrd_timing: bool = False,
) -> list[RequirementResult]:
    """Run the requested H.264 HRD validation tiers and return results.

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
                req_id="H264-HRD-SIM-00",
                level="shall",
                text="CPB simulation requires passing HRD self-consistency checks.",
                passed=False,
                details="Skipped: one or more H264-HRD self-consistency checks failed.",
                testable=False,
            ))

    if enable_hrd_timing:
        if hrd_self_consistency_passed(results):
            tier3 = check_pcap_timing(ctx)
            results.extend(tier3)
        else:
            results.append(RequirementResult(
                req_id="H264-HRD-TIME-00",
                level="should",
                text="PCAP timing cross-validation requires passing HRD self-consistency checks.",
                passed=False,
                details="Skipped: one or more H264-HRD self-consistency checks failed.",
                testable=False,
            ))

    return results
