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
"""Sub-picture HRD validation for H.265/HEVC streams.

When ``sub_pic_hrd_params_present_flag`` is 1 in the SPS, the HRD
operates at **decoding-unit** (DU) granularity rather than access-unit
granularity.  Each DU is a subset of an access unit (typically one
slice) and has its own arrival/removal schedule.

This module is additive — it imports from ``ipmx_validate_hrd`` but
does **not modify** any existing AU-based code.  The sub-picture checks
auto-activate when the SPS signals sub-picture HRD and the user
enables ``--hrd`` / ``--hrd-sim`` / ``--hrd-timing``.

Per TR-10-15b-116, IPMX constrains sub-picture HRD to:
  - ``sub_pic_cpb_params_in_pic_timing_sei_flag = 0``
    (delays come from decoding_unit_info SEI, not pic_timing)
  - ``tick_divisor_minus2`` in range 0..254
  - A ``decoding_unit_info`` SEI per slice with valid
    ``du_spt_cpb_removal_delay_increment``

Key equations from H.265 Annex C:
  ClockSubTick = ClockTick / (tick_divisor_minus2 + 2)           (C-2)
  DuNominalRemovalTime[last DU in AU n] = AuNominalRemovalTime[n]
  DuNominalRemovalTime[m] = AuNominalRemovalTime[n]
      - ClockSubTick * du_spt_cpb_removal_delay_increment        (C-12)
  Arrival/removal equations (C-3..C-8, C-14) are structurally
  identical to AU-level but use DU-level variables.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Any

from ipmx_validate_common import (
    RequirementResult,
    RtpReport,
    ValidationContext,
    get_int_field,
)
from ipmx_validate_hrd import (
    BufferingPeriodInfo,
    CpbAuResult,
    HrdParameters,
    PictureTimingInfo,
    _get_sei_int,
    extract_hrd_parameters,
    extract_sei_per_au,
    compute_au_sizes,
    simulate_cpb,
)


# ---------------------------------------------------------------------------
# H.265 NAL types emitted by FFmpeg trace_headers
# ---------------------------------------------------------------------------

_TRACE_NAL_TYPES = {32, 33, 34, 39, 40}
_H265_RA_TYPES = {16, 17, 18, 19, 20, 21}

_DECODING_UNIT_INFO_FIELDS = {"decoding_unit_idx", "du_spt_cpb_removal_delay_increment"}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DecodingUnitInfo:
    """Extracted from a decoding_unit_info SEI message."""
    au_index: int
    du_index_in_au: int
    rtp_timestamp: int
    du_spt_cpb_removal_delay_increment: int
    size_in_bits: int
    is_last_in_au: bool


@dataclass
class DuCpbResult:
    """Per-DU result of the sub-picture CPB simulation."""
    au_index: int
    du_index_in_au: int
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
class SubPicCpbSimulationSummary:
    """Aggregate results of the sub-picture CPB simulation."""
    du_results: list[DuCpbResult]
    overflow_count: int
    underflow_count: int
    near_overflow_count: int
    near_underflow_count: int
    max_occupancy_fraction: Fraction
    min_margin_before_underflow: Fraction | None
    valid: bool
    detail: str


# ---------------------------------------------------------------------------
# Extraction: decoding_unit_info SEI from FFmpeg trace headers
# ---------------------------------------------------------------------------

def extract_du_info(
    report: RtpReport,
    raw_headers: list[dict[str, Any]],
) -> dict[int, list[DecodingUnitInfo]]:
    """Extract decoding_unit_info SEI values grouped by AU timestamp.

    Walks ``nalus_meta`` in parallel with ``raw_headers`` to correlate
    each trace entry back to its AU.  For each ``decoding_unit_info``
    SEI, extracts ``decoding_unit_idx`` and
    ``du_spt_cpb_removal_delay_increment``.

    Returns a dict mapping AU RTP timestamp to a list of
    ``DecodingUnitInfo`` sorted by ``du_index_in_au``.
    """
    au_index_by_ts: dict[int, int] = {}
    for au in report.access_units:
        au_index_by_ts[au.timestamp] = au.index

    du_map: dict[int, list[DecodingUnitInfo]] = {}

    header_idx = 0
    n_headers = len(raw_headers)
    for meta in report.nalus_meta:
        nal_type = int(meta.get("nal_type", -1))
        if nal_type not in _TRACE_NAL_TYPES:
            continue
        if header_idx >= n_headers:
            break
        header = raw_headers[header_idx]
        header_idx += 1
        ts = int(meta["timestamp"])

        if header.get("type") != "SEI":
            continue

        fields: dict[str, Any] = header.get("fields", {})
        keys = set(fields.keys())

        if not (keys & _DECODING_UNIT_INFO_FIELDS):
            continue

        du_idx = _get_sei_int(fields, "decoding_unit_idx")
        du_delay = _get_sei_int(fields, "du_spt_cpb_removal_delay_increment")
        if du_idx is None or du_delay is None:
            continue

        nalu_size = int(meta.get("nalu_size", 0))
        au_idx = au_index_by_ts.get(ts, -1)

        du = DecodingUnitInfo(
            au_index=au_idx,
            du_index_in_au=du_idx,
            rtp_timestamp=ts,
            du_spt_cpb_removal_delay_increment=du_delay,
            size_in_bits=nalu_size * 8,
            is_last_in_au=False,
        )
        du_map.setdefault(ts, []).append(du)

    for ts, dus in du_map.items():
        dus.sort(key=lambda d: d.du_index_in_au)
        if dus:
            dus[-1] = DecodingUnitInfo(
                au_index=dus[-1].au_index,
                du_index_in_au=dus[-1].du_index_in_au,
                rtp_timestamp=dus[-1].rtp_timestamp,
                du_spt_cpb_removal_delay_increment=dus[-1].du_spt_cpb_removal_delay_increment,
                size_in_bits=dus[-1].size_in_bits,
                is_last_in_au=True,
            )

    return du_map


def _compute_du_sizes(
    report: RtpReport,
    du_map: dict[int, list[DecodingUnitInfo]],
) -> dict[int, list[DecodingUnitInfo]]:
    """Assign bit sizes to DUs from VCL NAL units.

    Each VCL NAL in an AU is assigned to the DU whose
    ``decoding_unit_idx`` range covers it.  For simplicity (and because
    FFmpeg trace_headers only emits non-VCL NALs), we distribute the
    total AU VCL bits evenly across DUs when we cannot correlate
    individual slices.
    """
    vcl_bits_by_ts: dict[int, int] = {}
    all_bits_by_ts: dict[int, int] = {}
    for meta in report.nalus_meta:
        ts = int(meta["timestamp"])
        nalu_size = int(meta.get("nalu_size", 0))
        bits = nalu_size * 8
        all_bits_by_ts[ts] = all_bits_by_ts.get(ts, 0) + bits
        nal_type = int(meta.get("nal_type", -1))
        if nal_type in range(0, 32):
            vcl_bits_by_ts[ts] = vcl_bits_by_ts.get(ts, 0) + bits

    result: dict[int, list[DecodingUnitInfo]] = {}
    for ts, dus in du_map.items():
        total_bits = all_bits_by_ts.get(ts, 0)
        n_dus = len(dus)
        if n_dus == 0:
            continue

        if n_dus == 1:
            updated = [DecodingUnitInfo(
                au_index=dus[0].au_index,
                du_index_in_au=dus[0].du_index_in_au,
                rtp_timestamp=ts,
                du_spt_cpb_removal_delay_increment=dus[0].du_spt_cpb_removal_delay_increment,
                size_in_bits=total_bits,
                is_last_in_au=dus[0].is_last_in_au,
            )]
        else:
            base_bits = total_bits // n_dus
            remainder = total_bits - base_bits * n_dus
            updated = []
            for i, du in enumerate(dus):
                du_bits = base_bits + (1 if i < remainder else 0)
                updated.append(DecodingUnitInfo(
                    au_index=du.au_index,
                    du_index_in_au=du.du_index_in_au,
                    rtp_timestamp=ts,
                    du_spt_cpb_removal_delay_increment=du.du_spt_cpb_removal_delay_increment,
                    size_in_bits=du_bits,
                    is_last_in_au=du.is_last_in_au,
                ))
        result[ts] = updated
    return result


# ---------------------------------------------------------------------------
# Sub-picture CPB simulation (H.265 Annex C with SubPicHrdFlag=1)
# ---------------------------------------------------------------------------

_NEAR_OVERFLOW_THRESHOLD = Fraction(99, 100)
_NEAR_UNDERFLOW_SUBTICKS = 1


def simulate_cpb_subpic(
    hrd: HrdParameters,
    au_sim: list[CpbAuResult],
    du_map: dict[int, list[DecodingUnitInfo]],
) -> SubPicCpbSimulationSummary:
    """Simulate the CPB at decoding-unit granularity per H.265 Annex C.

    *au_sim* provides the AU-level nominal removal times (from the
    existing ``simulate_cpb``).  For each AU that has DU info, this
    function derives per-DU nominal removal times using ClockSubTick
    and ``du_spt_cpb_removal_delay_increment``, then runs the
    arrival/removal/overflow/underflow checks at DU level.
    """
    if hrd.clock_sub_tick is None:
        return SubPicCpbSimulationSummary(
            du_results=[], overflow_count=0, underflow_count=0,
            near_overflow_count=0, near_underflow_count=0,
            max_occupancy_fraction=Fraction(0),
            min_margin_before_underflow=None,
            valid=True, detail="ClockSubTick not available",
        )

    clock_sub_tick = hrd.clock_sub_tick
    bit_rate = hrd.bit_rate
    cpb_size = hrd.cpb_size
    cbr = hrd.cbr_flag
    low_delay = hrd.low_delay_hrd_flag

    near_overflow_bits = cpb_size * _NEAR_OVERFLOW_THRESHOLD

    au_removal_by_ts: dict[int, CpbAuResult] = {
        r.rtp_timestamp: r for r in au_sim
    }

    du_results: list[DuCpbResult] = []
    overflow_count = 0
    underflow_count = 0
    near_overflow_count = 0
    near_underflow_count = 0
    max_occ_frac = Fraction(0)
    min_underflow_margin: Fraction | None = None

    prev_du_final_arrival = Fraction(0)

    init_delay = Fraction(0)
    init_offset = Fraction(0)
    if au_sim:
        init_delay = au_sim[0].nominal_removal_time * 90000
        init_offset = Fraction(0)

    for au_result in au_sim:
        ts = au_result.rtp_timestamp
        dus = du_map.get(ts)
        if not dus:
            continue

        au_nominal_removal = au_result.nominal_removal_time

        for du in dus:
            size_bits = Fraction(du.size_in_bits)

            # --- DU nominal removal time (C-12) ---
            if du.is_last_in_au:
                du_nominal_removal = au_nominal_removal
            else:
                du_delay_inc = Fraction(du.du_spt_cpb_removal_delay_increment)
                du_nominal_removal = au_nominal_removal - clock_sub_tick * du_delay_inc

            # --- DU initial arrival time (C-3/C-4 with subPicParamsFlag=1) ---
            if not du_results:
                du_init_arrival = Fraction(0)
            elif cbr:
                du_init_arrival = prev_du_final_arrival
            else:
                earliest = du_nominal_removal - au_result.init_arrival_time
                if earliest < Fraction(0):
                    earliest = Fraction(0)
                du_init_arrival = max(prev_du_final_arrival, du_nominal_removal - init_delay / 90000)

            # --- DU final arrival time (C-8 with subPicParamsFlag=1) ---
            du_final_arrival = du_init_arrival + size_bits / bit_rate

            # --- DU actual removal time (C-14) ---
            if not low_delay or du_nominal_removal >= du_final_arrival:
                du_cpb_removal = du_nominal_removal
            else:
                du_cpb_removal = du_final_arrival

            # --- CPB occupancy ---
            if du_cpb_removal >= du_final_arrival:
                bits_in_cpb = size_bits
            else:
                bits_in_cpb = bit_rate * (du_cpb_removal - du_init_arrival)

            if du_results:
                prev = du_results[-1]
                occ_at_removal = prev.cpb_occupancy_after_removal + bits_in_cpb
            else:
                occ_at_removal = bits_in_cpb

            occ_after_removal = occ_at_removal - size_bits

            # --- Overflow / underflow ---
            overflow = occ_at_removal > cpb_size
            underflow = False
            if not low_delay and du_nominal_removal < du_final_arrival:
                underflow = True

            near_of = occ_at_removal > near_overflow_bits and not overflow
            margin = du_nominal_removal - du_final_arrival
            near_uf = (
                not underflow
                and not low_delay
                and Fraction(0) <= margin < clock_sub_tick * _NEAR_UNDERFLOW_SUBTICKS
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

            du_results.append(DuCpbResult(
                au_index=du.au_index,
                du_index_in_au=du.du_index_in_au,
                rtp_timestamp=ts,
                size_in_bits=du.size_in_bits,
                init_arrival_time=du_init_arrival,
                final_arrival_time=du_final_arrival,
                nominal_removal_time=du_nominal_removal,
                cpb_removal_time=du_cpb_removal,
                cpb_occupancy_at_removal=occ_at_removal,
                cpb_occupancy_after_removal=occ_after_removal,
                overflow=overflow,
                underflow=underflow,
                near_overflow=near_of,
                near_underflow=near_uf,
            ))

            prev_du_final_arrival = du_final_arrival

    valid = overflow_count == 0 and underflow_count == 0
    parts: list[str] = []
    parts.append(f"{len(du_results)} DUs simulated")
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
        parts.append(f"min underflow margin {float(min_underflow_margin)*1e6:.1f}us")

    return SubPicCpbSimulationSummary(
        du_results=du_results,
        overflow_count=overflow_count,
        underflow_count=underflow_count,
        near_overflow_count=near_overflow_count,
        near_underflow_count=near_underflow_count,
        max_occupancy_fraction=max_occ_frac,
        min_margin_before_underflow=min_underflow_margin,
        valid=valid,
        detail="; ".join(parts),
    )


# ---------------------------------------------------------------------------
# Tier 1: Sub-picture HRD Self-Consistency Checks
# ---------------------------------------------------------------------------

_SUBPIC_CHECK_DESCRIPTIONS: dict[str, str] = {
    "SUBPIC-HRD-01": "sub_pic_hrd_params_present_flag shall be 1.",
    "SUBPIC-HRD-02": "ClockSubTick shall be derivable (tick_divisor_minus2 in 0..254).",
    "SUBPIC-HRD-03": "sub_pic_cpb_params_in_pic_timing_sei_flag shall be 0.",
    "SUBPIC-HRD-04": "decoding_unit_info SEI shall be present for each DU from first IRAP onward.",
    "SUBPIC-HRD-05": "Last DU in each AU shall have du_spt_cpb_removal_delay_increment=0.",
}


def check_subpic_hrd_self_consistency(ctx: ValidationContext) -> list[RequirementResult]:
    """Run Tier 1 sub-picture HRD self-consistency checks."""
    results: list[RequirementResult] = []

    def _add(req_id: str, passed: bool, details: str, testable: bool = True) -> None:
        results.append(RequirementResult(
            req_id=req_id,
            level="shall",
            text=_SUBPIC_CHECK_DESCRIPTIONS.get(req_id, req_id),
            passed=passed,
            details=details,
            testable=testable,
        ))

    if ctx.timeline is None:
        _add("SUBPIC-HRD-01", False, "FFmpeg trace unavailable", testable=False)
        return results

    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        _add("SUBPIC-HRD-01", False, "No SPS fields parsed", testable=False)
        return results

    # SUBPIC-HRD-01: sub_pic_hrd_params_present_flag
    sub_pic = get_int_field(sps, "sub_pic_hrd_params_present_flag")
    if sub_pic != 1:
        _add("SUBPIC-HRD-01", False,
             f"sub_pic_hrd_params_present_flag={sub_pic}")
        return results
    _add("SUBPIC-HRD-01", True, "sub_pic_hrd_params_present_flag=1")

    # SUBPIC-HRD-02: ClockSubTick derivable
    tick_div = get_int_field(sps, "tick_divisor_minus2")
    if tick_div is None:
        _add("SUBPIC-HRD-02", False, "tick_divisor_minus2 not present")
    elif tick_div < 0 or tick_div > 254:
        _add("SUBPIC-HRD-02", False,
             f"tick_divisor_minus2={tick_div} outside range 0..254")
    else:
        hrd = extract_hrd_parameters(sps)
        cst_str = ""
        if hrd and hrd.clock_sub_tick is not None:
            cst_str = f", ClockSubTick={float(hrd.clock_sub_tick)*1e6:.3f}us"
        _add("SUBPIC-HRD-02", True,
             f"tick_divisor_minus2={tick_div} (divisor={tick_div + 2}){cst_str}")

    # SUBPIC-HRD-03: sub_pic_cpb_params_in_pic_timing_sei_flag == 0
    cpb_in_pt = get_int_field(sps, "sub_pic_cpb_params_in_pic_timing_sei_flag")
    if cpb_in_pt is None:
        _add("SUBPIC-HRD-03", False,
             "sub_pic_cpb_params_in_pic_timing_sei_flag not present")
    elif cpb_in_pt != 0:
        _add("SUBPIC-HRD-03", False,
             f"sub_pic_cpb_params_in_pic_timing_sei_flag={cpb_in_pt}, expected 0")
    else:
        _add("SUBPIC-HRD-03", True,
             "sub_pic_cpb_params_in_pic_timing_sei_flag=0")

    # SUBPIC-HRD-04: decoding_unit_info SEI presence from first IRAP onward
    du_map = extract_du_info(ctx.rtp_report, ctx.timeline.raw_headers)

    first_irap_idx: int | None = None
    for au in ctx.rtp_report.access_units:
        if any(nal in _H265_RA_TYPES for nal in au.nal_types):
            first_irap_idx = au.index
            break

    if first_irap_idx is None:
        _add("SUBPIC-HRD-04", False,
             "No IRAP detected — cannot verify DU info presence", testable=False)
    else:
        relevant_aus = [
            au for au in ctx.rtp_report.access_units
            if au.index >= first_irap_idx
        ]
        missing_du = [
            au.timestamp for au in relevant_aus
            if au.timestamp not in du_map
        ]
        if missing_du:
            _add("SUBPIC-HRD-04", False,
                 f"{len(missing_du)}/{len(relevant_aus)} AUs missing "
                 f"decoding_unit_info SEI (first ts={missing_du[0]})")
        else:
            _add("SUBPIC-HRD-04", True,
                 f"decoding_unit_info SEI present in all "
                 f"{len(relevant_aus)} AUs from first IRAP onward")

    # SUBPIC-HRD-05: last DU in each AU has du_spt_cpb_removal_delay_increment=0
    bad_last_du: list[int] = []
    for ts, dus in du_map.items():
        if dus and dus[-1].du_spt_cpb_removal_delay_increment != 0:
            bad_last_du.append(ts)
    if bad_last_du:
        _add("SUBPIC-HRD-05", False,
             f"{len(bad_last_du)} AUs where last DU has "
             f"du_spt_cpb_removal_delay_increment != 0 "
             f"(first ts={bad_last_du[0]})")
    elif du_map:
        _add("SUBPIC-HRD-05", True,
             f"Last DU in all {len(du_map)} AUs has "
             f"du_spt_cpb_removal_delay_increment=0")
    else:
        _add("SUBPIC-HRD-05", True,
             "No DU info available to check", testable=False)

    return results


def subpic_self_consistency_passed(results: list[RequirementResult]) -> bool:
    """Return True if all critical sub-picture HRD checks passed."""
    critical_ids = {f"SUBPIC-HRD-{i:02d}" for i in range(1, 6)}
    for r in results:
        if r.req_id in critical_ids and not r.passed and r.testable:
            return False
    return True


# ---------------------------------------------------------------------------
# Tier 2: Sub-picture CPB Simulation
# ---------------------------------------------------------------------------

_SIM_CHECK_DESCRIPTIONS: dict[str, str] = {
    "SUBPIC-HRD-SIM-01": "CPB shall never overflow at DU level (occupancy <= CpbSize).",
    "SUBPIC-HRD-SIM-02": "CPB shall never underflow at DU level (nominal removal >= final arrival, unless low_delay_hrd_flag).",
    "SUBPIC-HRD-SIM-03": "CPB occupancy should not exceed 99% of CpbSize at DU level (near-overflow warning).",
    "SUBPIC-HRD-SIM-04": "Nominal DU removal should not be within 1 ClockSubTick of final arrival (near-underflow warning).",
}


def check_subpic_cpb_simulation(ctx: ValidationContext) -> list[RequirementResult]:
    """Run Tier 2 sub-picture CPB simulation checks."""
    results: list[RequirementResult] = []

    def _add(req_id: str, level: str, passed: bool, details: str,
             testable: bool = True) -> None:
        results.append(RequirementResult(
            req_id=req_id, level=level,
            text=_SIM_CHECK_DESCRIPTIONS.get(req_id, req_id),
            passed=passed, details=details, testable=testable,
        ))

    if ctx.timeline is None:
        _add("SUBPIC-HRD-SIM-01", "shall", False,
             "FFmpeg trace unavailable", testable=False)
        return results

    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        _add("SUBPIC-HRD-SIM-01", "shall", False,
             "No SPS fields parsed", testable=False)
        return results

    hrd = extract_hrd_parameters(sps)
    if hrd is None or not hrd.sub_pic_hrd_params_present:
        _add("SUBPIC-HRD-SIM-01", "shall", False,
             "Sub-picture HRD parameters not available", testable=False)
        return results

    if hrd.clock_sub_tick is None:
        _add("SUBPIC-HRD-SIM-01", "shall", False,
             "ClockSubTick not derivable", testable=False)
        return results

    bp_map, pt_map, _ = extract_sei_per_au(
        ctx.rtp_report,
        ctx.timeline.raw_headers,
        lossy_timestamps=ctx.timeline.lossy_timestamps,
    )
    au_sizes = compute_au_sizes(ctx.rtp_report)
    simulated_sizes = [s for s in au_sizes if s.rtp_timestamp in pt_map]

    if not simulated_sizes:
        _add("SUBPIC-HRD-SIM-01", "shall", False,
             "No AUs with Picture Timing SEI — cannot simulate", testable=False)
        return results

    au_sim_result = simulate_cpb(
        hrd, bp_map, pt_map, simulated_sizes,
        use_nal_type=hrd.nal_hrd_present)

    du_map_raw = extract_du_info(ctx.rtp_report, ctx.timeline.raw_headers)
    du_map = _compute_du_sizes(ctx.rtp_report, du_map_raw)

    if not du_map:
        _add("SUBPIC-HRD-SIM-01", "shall", False,
             "No decoding_unit_info SEI data — cannot simulate at DU level",
             testable=False)
        return results

    sim = simulate_cpb_subpic(hrd, au_sim_result.au_results, du_map)

    # SUBPIC-HRD-SIM-01: No overflow
    if sim.overflow_count > 0:
        first_of = next(r for r in sim.du_results if r.overflow)
        _add("SUBPIC-HRD-SIM-01", "shall", False,
             f"CPB overflow at DU {first_of.du_index_in_au} of AU {first_of.au_index} "
             f"(ts={first_of.rtp_timestamp}, "
             f"occupancy={float(first_of.cpb_occupancy_at_removal)/1e6:.2f} Mbit, "
             f"CpbSize={float(hrd.cpb_size)/1e6:.2f} Mbit)")
    else:
        _add("SUBPIC-HRD-SIM-01", "shall", True,
             f"No CPB overflow ({len(sim.du_results)} DUs, "
             f"max occupancy {float(sim.max_occupancy_fraction)*100:.1f}%)")

    # SUBPIC-HRD-SIM-02: No underflow
    if sim.underflow_count > 0:
        first_uf = next(r for r in sim.du_results if r.underflow)
        _add("SUBPIC-HRD-SIM-02", "shall", False,
             f"CPB underflow at DU {first_uf.du_index_in_au} of AU {first_uf.au_index} "
             f"(ts={first_uf.rtp_timestamp})")
    else:
        margin_str = ""
        if sim.min_margin_before_underflow is not None:
            margin_str = (f", min margin "
                          f"{float(sim.min_margin_before_underflow)*1e6:.1f}us")
        _add("SUBPIC-HRD-SIM-02", "shall", True,
             f"No CPB underflow ({len(sim.du_results)} DUs{margin_str})")

    # SUBPIC-HRD-SIM-03: Near-overflow warning
    if sim.near_overflow_count > 0:
        _add("SUBPIC-HRD-SIM-03", "should", False,
             f"{sim.near_overflow_count} DUs with CPB occupancy > 99% of CpbSize")
    else:
        _add("SUBPIC-HRD-SIM-03", "should", True,
             f"No near-overflow conditions "
             f"(max {float(sim.max_occupancy_fraction)*100:.1f}%)")

    # SUBPIC-HRD-SIM-04: Near-underflow warning
    if sim.near_underflow_count > 0:
        _add("SUBPIC-HRD-SIM-04", "should", False,
             f"{sim.near_underflow_count} DUs within 1 ClockSubTick of underflow")
    else:
        _add("SUBPIC-HRD-SIM-04", "should", True, "No near-underflow conditions")

    return results


# ---------------------------------------------------------------------------
# Tier 3: PCAP Timing Cross-Validation
# ---------------------------------------------------------------------------

_TIMING_CHECK_DESCRIPTIONS: dict[str, str] = {
    "SUBPIC-HRD-TIME-01": "Sub-picture HRD timing is informational (PCAP has no per-slice timestamps).",
}


def check_subpic_pcap_timing(ctx: ValidationContext) -> list[RequirementResult]:
    """Run Tier 3 sub-picture PCAP timing checks (informational only).

    PCAP capture times are per-packet, not per-slice, so DU-level
    timing cross-validation is inherently limited.  We report the
    number of DUs and the ClockSubTick granularity for reference.
    """
    results: list[RequirementResult] = []

    if ctx.timeline is None:
        results.append(RequirementResult(
            req_id="SUBPIC-HRD-TIME-01", level="should",
            text=_TIMING_CHECK_DESCRIPTIONS["SUBPIC-HRD-TIME-01"],
            passed=True,
            details="FFmpeg trace unavailable — skipped",
            testable=False,
        ))
        return results

    sps = ctx.timeline.header_fields.get("SPS")
    hrd = extract_hrd_parameters(sps) if sps else None

    du_map = extract_du_info(ctx.rtp_report, ctx.timeline.raw_headers)
    total_dus = sum(len(dus) for dus in du_map.values())

    cst_str = ""
    if hrd and hrd.clock_sub_tick is not None:
        cst_str = f", ClockSubTick={float(hrd.clock_sub_tick)*1e6:.3f}us"

    results.append(RequirementResult(
        req_id="SUBPIC-HRD-TIME-01", level="should",
        text=_TIMING_CHECK_DESCRIPTIONS["SUBPIC-HRD-TIME-01"],
        passed=True,
        details=(f"{total_dus} DUs across {len(du_map)} AUs{cst_str}; "
                 f"per-slice PCAP timing not available"),
    ))
    return results


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------

_PREVIEW_TAG = "[PREVIEW] "


def _tag_results(results: list[RequirementResult]) -> list[RequirementResult]:
    """Prepend the preview tag to every result's details and text fields.

    Sub-picture HRD validation has not been verified against real
    encoder output (no encoder currently emits decoding_unit_info SEI
    in a testable configuration).  The tag makes this explicit in the
    output so users know these checks are preliminary.
    """
    tagged: list[RequirementResult] = []
    for r in results:
        tagged.append(RequirementResult(
            req_id=r.req_id,
            level=r.level,
            text=_PREVIEW_TAG + r.text,
            passed=r.passed,
            details=_PREVIEW_TAG + r.details,
            testable=r.testable,
        ))
    return tagged


def run_subpic_hrd_checks(
    ctx: ValidationContext,
    *,
    enable_hrd: bool = False,
    enable_hrd_sim: bool = False,
    enable_hrd_timing: bool = False,
) -> list[RequirementResult]:
    """Run sub-picture HRD validation tiers if sub_pic_hrd_params_present_flag=1.

    Returns an empty list if sub-picture HRD is not signalled or if
    no ``--hrd*`` flags are enabled.  This function is safe to call
    unconditionally — it auto-detects whether sub-picture HRD applies.

    All results are tagged ``[PREVIEW]`` because this validation path
    has only been tested with synthetic data — no real encoder stream
    with ``decoding_unit_info`` SEI has been available for verification.
    """
    if not enable_hrd and not enable_hrd_sim and not enable_hrd_timing:
        return []

    if ctx.timeline is None:
        return []
    sps = ctx.timeline.header_fields.get("SPS")
    if sps is None:
        return []
    sub_pic = get_int_field(sps, "sub_pic_hrd_params_present_flag")
    if sub_pic != 1:
        return []

    effective_hrd = enable_hrd or enable_hrd_sim or enable_hrd_timing
    results: list[RequirementResult] = []

    if effective_hrd:
        tier1 = check_subpic_hrd_self_consistency(ctx)
        results.extend(tier1)

    if enable_hrd_sim:
        if subpic_self_consistency_passed(results):
            tier2 = check_subpic_cpb_simulation(ctx)
            results.extend(tier2)
        else:
            results.append(RequirementResult(
                req_id="SUBPIC-HRD-SIM-00",
                level="shall",
                text="Sub-picture CPB simulation requires passing self-consistency checks.",
                passed=False,
                details="Skipped: one or more SUBPIC-HRD checks failed.",
                testable=False,
            ))

    if enable_hrd_timing:
        if subpic_self_consistency_passed(results):
            tier3 = check_subpic_pcap_timing(ctx)
            results.extend(tier3)
        else:
            results.append(RequirementResult(
                req_id="SUBPIC-HRD-TIME-00",
                level="should",
                text="Sub-picture PCAP timing requires passing self-consistency checks.",
                passed=False,
                details="Skipped: one or more SUBPIC-HRD checks failed.",
                testable=False,
            ))

    return _tag_results(results)
