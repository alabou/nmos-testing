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
"""Shared helpers for IPMX H.264/H.265 PCAP validation."""

from __future__ import annotations

import math
import re
import shutil
import tempfile
import subprocess
from dataclasses import dataclass, field
from collections import deque
from collections import Counter
from fractions import Fraction
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Iterator

if TYPE_CHECKING:
    from MatroxSdp import MediaDescriptor

import ipmx_pcap_reader
import ipmx_parse_rtp_pcap
import ipmx_sender_report
from ipmx_pcap_reader import UdpPacket, iter_udp_packets  # re-exported

NTP_UNIX_OFFSET = 2_208_988_800
CLOCK_RATE = 90_000
NANOSECONDS_PER_SECOND = 1_000_000_000


# ---------------------------------------------------------------------------
# NTP / PTP timestamp conversions (TR-10-1 §8.7)
#
# Read direction  : ntp_unix property on SenderReportInfo (below)
# Write direction : the two helpers below, one per format.
# ---------------------------------------------------------------------------

def unix_to_ipmx_ptp(unix_time: float) -> tuple[int, int]:
    """Unix seconds → IPMX PTP truncated format (MSW = seconds, LSW = nanoseconds)."""
    seconds = int(math.floor(unix_time))
    nanoseconds = int((unix_time - seconds) * NANOSECONDS_PER_SECOND)
    return seconds, nanoseconds


def unix_to_rfc3550_ntp(unix_time: float) -> tuple[int, int]:
    """Unix seconds → RFC 3550 NTP format (MSW = seconds since 1900, LSW = fraction/2^32)."""
    seconds = int(math.floor(unix_time))
    fraction = int((unix_time - seconds) * (1 << 32))
    return seconds + NTP_UNIX_OFFSET, fraction


def rtp_timestamp_to_ipmx_ptp(
    rtp_timestamp: int,
    capture_time: float,
    clock_rate: int = CLOCK_RATE,
) -> tuple[int, int]:
    """Derive IPMX PTP NTP fields from an RTP timestamp (TR-10-1 §8.6).

    Per section 8.6, the RTP clock is initialized from the Internal Clock,
    so ``rtp_timestamp == int(ptp_seconds * clock_rate + ptp_nanoseconds *
    clock_rate / 1e9) mod 2^32``.  We cannot recover the full PTP time from
    the 32-bit RTP timestamp alone, so we use *capture_time* (Unix seconds)
    to anchor the high-order bits and then solve for the exact PTP nanoseconds
    that reproduce the given *rtp_timestamp*.

    The nanosecond value is chosen so that the forward computation
    ``int(sec * rate + ns * rate / 1e9) mod 2^32`` reproduces *rtp_timestamp*
    exactly.  Uses ``Fraction`` arithmetic to stay exact.
    """
    base_sec = int(math.floor(capture_time))
    base_rtp = int(Fraction(base_sec) * clock_rate) % (1 << 32)
    tick_offset = (rtp_timestamp - base_rtp) % (1 << 32)
    if tick_offset >= (1 << 31):
        tick_offset -= (1 << 32)
    total_ticks = Fraction(base_sec) * clock_rate + tick_offset
    ptp_seconds = int(total_ticks // clock_rate)
    remainder_ticks = total_ticks - Fraction(ptp_seconds) * clock_rate

    # Solve for nanoseconds: we need int(remainder_ticks * 1e9 / rate) such
    # that the forward path reproduces the same tick.  The exact fractional
    # nanosecond is remainder_ticks * 1e9 / rate; we take the floor, then
    # verify the forward path.  If it undershoots by 1 tick, bump ns by 1.
    ns_exact = remainder_ticks * NANOSECONDS_PER_SECOND / clock_rate
    ptp_nanoseconds = int(ns_exact)
    ptp_nanoseconds = max(0, min(ptp_nanoseconds, NANOSECONDS_PER_SECOND - 1))

    # Forward-verify and adjust if needed
    check_rtp = int(
        Fraction(ptp_seconds) * clock_rate
        + Fraction(ptp_nanoseconds) * clock_rate / NANOSECONDS_PER_SECOND
    ) % (1 << 32)
    if check_rtp != rtp_timestamp and ptp_nanoseconds < NANOSECONDS_PER_SECOND - 1:
        ptp_nanoseconds += 1
    return ptp_seconds, ptp_nanoseconds


@dataclass
class AccessUnit:
    index: int
    timestamp: int
    first_packet_time: float | None
    last_packet_time: float | None
    nal_types: set[int]
    packet_count: int
    marker_seen: bool = False
    recovery_point: bool = False


@dataclass
class SenderReportInfo:
    capture_time: float
    src_port: int
    dst_port: int
    dst_ip: str
    ssrc: int
    ntp_seconds: int
    ntp_fraction: int
    rtp_timestamp: int
    packet_count: int
    octet_count: int
    ipmx_info: ipmx_sender_report.ParsedIPMXInfoBlock | None
    raw_blocks: list[ipmx_sender_report.ParsedMediaInfoBlock]
    reception_report_count: int = 0

    @property
    def ntp_unix(self) -> float:
        """Convert the SR timestamp to Unix seconds.

        IPMX (TR-10-1 §8.7) repurposes the RFC 3550 "NTP timestamp" field
        with the PTP truncated format: MSW = PTP seconds (Unix epoch),
        LSW = nanoseconds.  Standard RFC 3550 uses MSW = seconds since
        NTP epoch (1900) and LSW = fraction of second (full-scale 2^32).

        We auto-detect via the IPMX Info Block: if present the SR is IPMX
        and uses PTP format; otherwise we fall back to RFC 3550 NTP format.
        """
        if self.ipmx_info is not None:
            return self.ntp_seconds + (self.ntp_fraction / NANOSECONDS_PER_SECOND)
        return (self.ntp_seconds - NTP_UNIX_OFFSET) + (self.ntp_fraction / 2**32)


@dataclass
class RtpReport:
    packets: list[dict[str, Any]]
    nalus_meta: list[dict[str, Any]]
    nalus_bytes: list[bytes]
    access_units: list[AccessUnit]
    access_units_by_ts: dict[int, AccessUnit]
    seq_analysis: ipmx_parse_rtp_pcap.RtpSequenceAnalysis = field(
        default_factory=ipmx_parse_rtp_pcap.RtpSequenceAnalysis
    )
    has_rtp_extensions: bool = False
    ext_ids: set[int] = field(default_factory=set)
    encrypted: bool = False
    # Recovery-point capture window (populated by apply_recovery_point_window):
    # how many boundary AUs were excluded so that all AU-based checks see only
    # the cleanly-decodable, fully-captured AUs of a mid-stream PCAP.
    dropped_pre_recovery: int = 0      # AUs before the first IRAP/IDR
    dropped_tail_truncated: int = 0    # trailing AUs ending without an RTP marker
    recovery_point_found: bool = True  # False => no IRAP/IDR in capture (head not trimmed)


@dataclass
class TimelineInfo:
    timeline: list[dict[str, Any]]
    header_fields: dict[str, dict[str, Any]]
    raw_headers: list[dict[str, Any]] = field(default_factory=list)
    sampled_frames: int = 0
    trace_warning: str | None = None
    lossy_timestamps: set[int] = field(default_factory=set)


@dataclass
class ValidationContext:
    pcap: Path
    codec: str
    rtp_report: RtpReport
    sender_reports: list[SenderReportInfo]
    timeline: TimelineInfo | None
    exact_framerate: Fraction | None = None
    interlace: bool | None = None
    width: int | None = None
    height: int | None = None
    sampling: str | None = None
    bit_depth: int | None = None
    sdp_media: MediaDescriptor | None = None
    stream_info: "ipmx_parse_rtp_pcap.RtpStreamInfo | None" = None
    encrypted: bool = False
    allow_superset_profile: bool = False


@dataclass
class RequirementResult:
    req_id: str
    level: str
    text: str
    passed: bool
    details: str
    testable: bool = True


@dataclass
class Requirement:
    req_id: str
    level: str
    text: str
    check: Any


def unwrap_rtp_timestamps(timestamps: list[int]) -> list[int]:
    if not timestamps:
        return []
    result: list[int] = []
    wraps = 0
    prev = timestamps[0]
    for ts in timestamps:
        if ts < prev and (prev - ts) > 0x80000000:
            wraps += 1
        result.append(ts + wraps * (1 << 32))
        prev = ts
    return result


def compute_nominal_period(timestamps: list[int], clock_rate: int = CLOCK_RATE) -> float | None:
    if len(timestamps) < 2:
        return None
    unwrapped = unwrap_rtp_timestamps(timestamps)
    deltas = [
        (cur - prev) / clock_rate
        for prev, cur in zip(unwrapped, unwrapped[1:])
        if (cur - prev) > 0
    ]
    if not deltas:
        return None
    deltas.sort()
    mid = len(deltas) // 2
    if len(deltas) % 2:
        return deltas[mid]
    return (deltas[mid - 1] + deltas[mid]) / 2.0


def parse_sender_reports(
    pcap_path: Path,
    port: int | None,
    *,
    stream_info: ipmx_parse_rtp_pcap.RtpStreamInfo | None = None,
    ssrc: int | None = None,
) -> list[SenderReportInfo]:
    """Parse RTCP Sender Reports from *pcap_path*.

    Filtering is applied in order of specificity:

    * **stream_info** — when provided, the RTCP port is derived as
      ``stream_info.rtcp_port``, the destination IP must match
      ``stream_info.dst_ip``, and only SRs whose SSRC equals
      ``stream_info.ssrc`` are returned.  This is the recommended way
      to call this function after auto-detecting the RTP stream.
    * **port** / **ssrc** — manual overrides; they take precedence over
      *stream_info* when specified.
    """
    effective_port: int | None = port
    effective_ssrc: int | None = ssrc
    effective_dst_ip: str | None = None
    if stream_info is not None:
        if effective_port is None:
            effective_port = stream_info.rtcp_port
        if effective_ssrc is None:
            effective_ssrc = stream_info.ssrc
        effective_dst_ip = stream_info.dst_ip

    reports: list[SenderReportInfo] = []
    for udp in iter_udp_packets(pcap_path, effective_port):
        if effective_dst_ip is not None and udp.dst_ip != effective_dst_ip:
            continue
        for packet in ipmx_sender_report.iter_rtcp_packets(udp.payload):
            parsed = ipmx_sender_report.parse_rtcp_sender_report(packet)
            if parsed is None:
                continue
            if effective_ssrc is not None and parsed.ssrc != effective_ssrc:
                continue
            reports.append(
                SenderReportInfo(
                    capture_time=udp.capture_time,
                    src_port=udp.src_port,
                    dst_port=udp.dst_port,
                    dst_ip=udp.dst_ip,
                    ssrc=parsed.ssrc,
                    ntp_seconds=parsed.ntp_seconds,
                    ntp_fraction=parsed.ntp_fraction,
                    rtp_timestamp=parsed.rtp_timestamp,
                    packet_count=parsed.packet_count,
                    octet_count=parsed.octet_count,
                    ipmx_info=parsed.info_block,
                    raw_blocks=parsed.raw_blocks,
                    reception_report_count=parsed.reception_report_count,
                )
            )
    reports.sort(key=lambda sr: sr.capture_time)
    return reports


def filter_capture_boundary_orphan_srs(
    unknown_srs: list,
    au_timestamps: set[int],
    last_au_first_packet_time: float,
) -> list:
    """Filter SRs whose ``rtp_timestamp`` doesn't match any AU on the wire.

    Two end-of-capture failure modes are *not* real conformance failures —
    they are artifacts of where the packet capture happened to start and
    stop:

    1. **Trailing-tail orphans** — kernel-level captures (e.g. tcpdump on
       loopback) sometimes lose the last few media packets at SIGINT
       because the BPF buffer hasn't yet drained.  The SR for those
       missing AUs is captured (SRs fire ~50 µs before their AU's first
       packet, so they get into the BPF queue earlier) while the AU
       packets themselves don't.  These show up as SRs whose
       ``rtp_timestamp`` is *past* the last captured AU's
       ``rtp_timestamp`` (signed 32-bit delta > 0).

    2. **Leading-head orphans** — symmetric case at capture start: the
       very first media packets of a stream might land before tcpdump
       attaches, while an SR fires earlier and lands inside the capture
       window. These have ``rtp_timestamp`` *before* the earliest
       captured AU's ``rtp_timestamp``.

    A real conformance failure is an SR whose ``rtp_timestamp`` falls
    *within* the captured AU range yet doesn't match — e.g. a skipped
    frame in the middle of the stream — which is what TR-10-15c-135b /
    TR-10-15b-146b actually try to detect. This helper preserves that
    distinction.

    Compares using signed 32-bit deltas to handle RTP-timestamp
    wraparound correctly (RFC 3550 random base + 32-bit counter).
    """
    if not unknown_srs or not au_timestamps:
        return unknown_srs
    sorted_aus = sorted(au_timestamps)
    first_au_ts = sorted_aus[0]
    last_au_ts  = sorted_aus[-1]

    def signed32(a: int, b: int) -> int:
        d = (a - b) & 0xFFFFFFFF
        return d - 0x1_0000_0000 if d & 0x8000_0000 else d

    real = []
    for sr in unknown_srs:
        # Past the captured range (trailing tail) — capture lost the AU.
        if signed32(sr.rtp_timestamp, last_au_ts) > 0:
            continue
        # Before the captured range (leading head) — capture started late.
        if signed32(sr.rtp_timestamp, first_au_ts) < 0:
            continue
        # Inside the captured range. Apply the existing capture-time guard
        # so post-stream SRs (e.g. a final SR fired after the last AU's
        # first packet wallclock) are still excluded.
        if sr.capture_time > last_au_first_packet_time:
            continue
        real.append(sr)
    return real


def apply_recovery_point_window(report: RtpReport) -> RtpReport:
    """Restrict ``report.access_units`` to the cleanly-validatable capture window.

    A mid-stream PCAP rarely starts or stops on a clean boundary, so its
    leading and trailing access units are not meaningfully validatable:
      - **Head** — AUs before the first recovery point (IRAP/IDR) reference
        frames that were never captured and carry no parameter sets, so a
        decoder could not start there. We anchor the window at the first AU
        flagged ``recovery_point`` (deterministic NAL-type test, ITU-T H.264 /
        H.265 Table 7-1). If the capture contains no recovery point the head is
        left intact (``recovery_point_found = False``) so we never silently
        validate nothing.
      - **Tail** — a capture cut mid-AU leaves the final AU without its RTP
        marker (M=1 marks an AU's last packet, RFC 6184 §5.1 / RFC 7798 §4.4).
        Trailing AUs lacking the marker are dropped. Interior markerless AUs
        are NOT dropped — those indicate real loss, surfaced elsewhere.

    Mutates and returns ``report``: ``access_units`` is trimmed and re-indexed,
    ``access_units_by_ts`` is rebuilt, and the drop counts are recorded on the
    report. Per-packet/NAL lists are left untouched so HRD timeline correlation
    (which is 1:1 with the full ``nalus_bytes``) stays intact — callers must
    apply this only AFTER building the timeline.
    """
    aus = report.access_units
    if not aus:
        return report

    # --- Head: first recovery point ---
    head = next((i for i, au in enumerate(aus) if au.recovery_point), None)
    if head is None:
        report.recovery_point_found = False
        head = 0
    else:
        report.recovery_point_found = True
    report.dropped_pre_recovery = head

    windowed = aus[head:]

    # --- Tail: drop trailing AUs that end without an RTP marker ---
    # Only when markers are in use at all (else this would drop everything).
    dropped_tail = 0
    if any(au.marker_seen for au in windowed):
        while windowed and not windowed[-1].marker_seen:
            windowed.pop()
            dropped_tail += 1
    report.dropped_tail_truncated = dropped_tail

    for idx, au in enumerate(windowed):
        au.index = idx
    report.access_units = windowed
    report.access_units_by_ts = {au.timestamp: au for au in windowed}
    return report


def print_recovery_window_note(report: RtpReport) -> None:
    """Surface what the recovery-point window excluded (never silently)."""
    if not report.recovery_point_found:
        print(
            f"[INFO] No recovery point (IRAP/IDR) in capture; validating all "
            f"{len(report.access_units)} access unit(s) without head trim "
            f"(mid-GOP start cannot be cleanly anchored)."
        )
        return
    if report.dropped_pre_recovery or report.dropped_tail_truncated:
        print(
            f"[INFO] Recovery-point window: skipped "
            f"{report.dropped_pre_recovery} pre-IRAP and "
            f"{report.dropped_tail_truncated} tail-truncated access unit(s); "
            f"validating {len(report.access_units)} access unit(s)."
        )


def infer_rtp_port(pcap_path: Path, codec: str) -> int | None:
    counts: Counter[int] = Counter()
    vcl_counts: Counter[int] = Counter()
    for pkt in ipmx_parse_rtp_pcap.iter_rtp_packets_stream(pcap_path, None):
        if not pkt.payload:
            continue
        try:
            nal_types = ipmx_parse_rtp_pcap.extract_packet_nal_types(codec, pkt.payload)
        except SystemExit:
            continue
        if not nal_types:
            continue
        port = pkt.dst_port or pkt.src_port
        if port is None:
            continue
        counts[port] += 1
        if any(ipmx_parse_rtp_pcap.is_vcl_nal(codec, nal) for nal in nal_types):
            vcl_counts[port] += 1
    if not counts:
        return None
    if vcl_counts:
        return max(vcl_counts.items(), key=lambda item: (item[1], counts[item[0]]))[0]
    return counts.most_common(1)[0][0]


def compute_sr_prefix_length(
    report: RtpReport, sender_reports: list[SenderReportInfo]
) -> int | None:
    if not sender_reports:
        return None
    au_timestamps = [au.timestamp for au in report.access_units]
    if not au_timestamps:
        return None
    sr_timestamps = {sr.rtp_timestamp for sr in sender_reports}
    missing_index = None
    for idx, ts in enumerate(au_timestamps):
        if ts not in sr_timestamps:
            missing_index = idx
            break
    if missing_index is None:
        return None
    if any(ts in sr_timestamps for ts in au_timestamps[missing_index + 1 :]):
        return None
    if missing_index <= 0:
        return None
    return missing_index


def _detect_encryption_from_ext(
    ext_elements: list[ipmx_parse_rtp_pcap.RtpExtensionElement] | None,
) -> bool:
    """Return True if any extension element has L matching HKEP/PEP sizes."""
    if not ext_elements:
        return False
    _ENC_L_FULL = 0x0E
    _ENC_L_SHORT = 0x02
    for elem in ext_elements:
        l_field = elem.length - 1
        if l_field == _ENC_L_FULL or l_field == _ENC_L_SHORT:
            return True
    return False


def build_rtp_report(
    pcap_path: Path,
    codec: str,
    port: int | None,
    max_access_units: int | None,
    wallclock_backstep_threshold: float | None = None,
    *,
    stream_info: ipmx_parse_rtp_pcap.RtpStreamInfo | None = None,
) -> RtpReport:
    context = ipmx_parse_rtp_pcap.ParseContext()
    seq_tracker = ipmx_parse_rtp_pcap.RtpSequenceTracker()
    fragments: dict[tuple[int, int, int], list[ipmx_parse_rtp_pcap.FragmentState]] = {}
    nalus: list[bytes] = []
    nalus_meta: list[dict[str, Any]] = []
    packets: list[dict[str, Any]] = []
    au_timestamps: set[int] = set()
    au_order: list[int] = []
    last_au_timestamp: int | None = None
    last_au_capture_time: float | None = None
    observed_au_rtp_deltas: list[float] = []
    encrypted = False
    encryption_checked = False

    for pkt in ipmx_parse_rtp_pcap.iter_rtp_packets_stream(
        pcap_path, port, stream_info=stream_info,
    ):
        if not pkt.payload:
            continue
        if not encryption_checked and pkt.ext_elements:
            encrypted = _detect_encryption_from_ext(pkt.ext_elements)
            encryption_checked = True
        seq_tracker.feed(pkt.seq, pkt.capture_time)
        packet_nal_types = ipmx_parse_rtp_pcap.extract_packet_nal_types(
            codec, pkt.payload, encrypted=encrypted)
        packet_has_vcl = any(
            ipmx_parse_rtp_pcap.is_vcl_nal(codec, nal_type)
            for nal_type in packet_nal_types
        )
        is_new_vcl_au = packet_has_vcl and pkt.timestamp not in au_timestamps
        if is_new_vcl_au and pkt.capture_time is not None:
            if last_au_timestamp is not None and last_au_capture_time is not None:
                # Truncate on non-wrap RTP timestamp backstep (stream restart/discontinuity).
                if pkt.timestamp < last_au_timestamp and (last_au_timestamp - pkt.timestamp) < 0x80000000:
                    break
                rtp_delta = ((pkt.timestamp - last_au_timestamp) & 0xFFFFFFFF) / CLOCK_RATE
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
                    wallclock_backstep_threshold
                    if wallclock_backstep_threshold is not None
                    else max(0.050, 3.0 * nominal_period)
                )
                capture_delta = pkt.capture_time - last_au_capture_time
                if capture_delta < -threshold:
                    break
            last_au_timestamp = pkt.timestamp
            last_au_capture_time = pkt.capture_time
        if max_access_units is not None and is_new_vcl_au and len(au_order) >= max_access_units:
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
            "packet_nal_types": packet_nal_types,
            "payload": pkt.payload,
            "ext_elements": pkt.ext_elements,
        }
        if not encrypted:
            ipmx_parse_rtp_pcap.process_payload(codec, pkt, fragments, nalus, nalus_meta, meta, context)
        if is_new_vcl_au:
            au_timestamps.add(pkt.timestamp)
            au_order.append(pkt.timestamp)
        meta["summary"] = ", ".join(
            sorted({ipmx_parse_rtp_pcap.describe_nal(codec, nal) for nal in meta["nal_types"]})
        )
        packets.append(meta)

    access_units_by_ts: dict[int, AccessUnit] = {}
    for meta in packets:
        ts = int(meta["timestamp"])
        au = access_units_by_ts.get(ts)
        cap_time = meta.get("capture_time")
        if au is None:
            au = AccessUnit(
                index=len(access_units_by_ts),
                timestamp=ts,
                first_packet_time=cap_time,
                last_packet_time=cap_time,
                nal_types=set(),
                packet_count=0,
            )
            access_units_by_ts[ts] = au
        au.packet_count += 1
        if cap_time is not None:
            if au.first_packet_time is None or cap_time < au.first_packet_time:
                au.first_packet_time = cap_time
            if au.last_packet_time is None or cap_time > au.last_packet_time:
                au.last_packet_time = cap_time
        if meta.get("marker"):
            # RFC 6184 §5.1 / RFC 7798 §4.4: M=1 marks an AU's last packet.
            au.marker_seen = True
        au.nal_types.update(int(nal) for nal in meta.get("nal_types", []))

    # Order access units by first_packet_time if available, otherwise by RTP timestamp order.
    access_units = list(access_units_by_ts.values())
    access_units.sort(
        key=lambda au: (
            au.first_packet_time if au.first_packet_time is not None else float("inf"),
            au.timestamp,
        )
    )
    for idx, au in enumerate(access_units):
        au.index = idx
        au.recovery_point = any(
            ipmx_parse_rtp_pcap.is_recovery_point_nal(codec, nal)
            for nal in au.nal_types
        )

    has_rtp_extensions = False
    all_ext_ids: set[int] = set()
    for meta in packets:
        ext_elems = meta.get("ext_elements")
        if ext_elems:
            has_rtp_extensions = True
            for elem in ext_elems:
                all_ext_ids.add(elem.ext_id)

    return RtpReport(
        packets=packets,
        nalus_meta=nalus_meta,
        nalus_bytes=nalus,
        access_units=access_units,
        access_units_by_ts=access_units_by_ts,
        seq_analysis=seq_tracker.analysis,
        has_rtp_extensions=has_rtp_extensions,
        ext_ids=all_ext_ids,
        encrypted=encrypted,
    )


def write_elementary_stream(nalus: list[bytes], suffix: str) -> Path:
    tmp_root = Path(__file__).resolve().parent / "tmp"
    tmp_root.mkdir(parents=True, exist_ok=True)
    tmp_dir = Path(tempfile.mkdtemp(prefix="ipmx_validate_", dir=tmp_root))
    stream_path = tmp_dir / f"stream{suffix}"
    with open(stream_path, "wb") as fh:
        for nalu in nalus:
            fh.write(nalu)
    return stream_path


def walk_trace_pairs(
    report: "RtpReport",
    raw_headers: list[dict[str, Any]],
    nal_type_to_header_type: dict[int, str],
    skip_timestamps: set[int] | None = None,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Pair each filtered nalus_meta entry with the next raw_headers entry of
    the matching FFmpeg trace type.

    Robust to ``trace_headers`` dropping or inserting individual trace blocks
    (e.g. when an SEI is malformed and the BSF aborts that packet). Same-type
    entries in ``raw_headers`` are consumed in bitstream order; NALUs whose
    type bucket is exhausted are skipped silently.

    ``skip_timestamps`` lists AU RTP timestamps known to be "lossy" — i.e.
    AUs whose PPS/SEI/SPS were not emitted by the trace at all (slice-only
    packets). Their nalus_meta entries are skipped without consuming bucket
    cursors, so subsequent AUs stay aligned with raw_headers.

    Mirrors the type-bucket strategy of ``correlate_headers()`` in
    ``ipmx_parse_rtp_pcap.py``, simplified for the partial-trace case (where
    ``correlate_headers`` raises).
    """
    headers_by_type: dict[str, list[dict[str, Any]]] = {}
    for h in raw_headers:
        headers_by_type.setdefault(h.get("type"), []).append(h)
    cursors: dict[str, int] = {t: 0 for t in headers_by_type}
    skip = skip_timestamps or set()

    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []

    for meta in report.nalus_meta:
        nal_type = int(meta.get("nal_type", -1))
        hdr_type = nal_type_to_header_type.get(nal_type)
        if hdr_type is None:
            continue
        ts = int(meta.get("timestamp", -1))
        if ts in skip:
            continue
        bucket = headers_by_type.get(hdr_type, [])
        cursor = cursors.get(hdr_type, 0)
        if cursor >= len(bucket):
            continue
        pairs.append((meta, bucket[cursor]))
        cursors[hdr_type] = cursor + 1

    return pairs


def find_slice_only_packets(trace_log: str) -> list[int]:
    """Return 0-indexed positions of packets that emitted only a Slice
    Header (no SPS/PPS/SEI/VPS trace block).

    These are packets where FFmpeg's ``trace_headers`` BSF lost state
    after a previous failure and skipped emitting trace for the
    parameter-set / SEI NALs of THIS packet. Their elementary-stream
    position 1:1 corresponds to a bitstream AU, so we use the index to
    derive the lossy AU's RTP timestamp and exclude it from coverage.
    """
    bsf_prefix_re = re.compile(r"\[(trace_headers|AVBSFContext)\s")
    packet_re = re.compile(r"Packet:\s*([0-9]+)\s+bytes")
    slice_only: list[int] = []
    pkt_idx = -1
    has_block = False
    for line in trace_log.splitlines():
        if not bsf_prefix_re.search(line):
            continue
        if packet_re.search(line):
            pkt_idx += 1
            has_block = False
            continue
        if pkt_idx < 0:
            continue
        if (
            "Sequence Parameter Set" in line
            or "Picture Parameter Set" in line
            or "Video Parameter Set" in line
            or "Supplemental" in line
        ):
            has_block = True
            continue
        if "Slice Header" in line and not has_block:
            slice_only.append(pkt_idx)
    return slice_only


def build_timeline(report: RtpReport, codec: str, frames: int) -> TimelineInfo | None:
    if report.encrypted:
        return None
    from ffmpeg_location import find_ffmpeg
    try:
        find_ffmpeg()
    except SystemExit:
        return None
    stream_path = write_elementary_stream(report.nalus_bytes, f".{codec[1:]}")
    try:
        trace_log = ipmx_parse_rtp_pcap.run_ffmpeg_trace(stream_path, frames)
    except SystemExit:
        trace_log = run_ffmpeg_trace_lenient(stream_path, frames)
    headers, packet_sizes = ipmx_parse_rtp_pcap.parse_trace_headers(trace_log)
    if not headers:
        return None
    report_payload = {
        "codec": codec,
        "nalus": report.nalus_meta,
    }
    timeline: list[dict[str, Any]] = []
    try:
        ipmx_parse_rtp_pcap.validate_packet_sizes(
            packet_sizes, sum(len(n) for n in report.nalus_bytes)
        )
        timeline = ipmx_parse_rtp_pcap.correlate_headers(report_payload, headers)
        header_fields: dict[str, dict[str, Any]] = {}
        for entry in timeline:
            header_fields.setdefault(entry["type_label"], entry["fields"])
    except SystemExit:
        header_fields = {}
        for header in headers:
            header_fields.setdefault(header["type"], header["fields"])
    trace_warning = _summarise_trace_errors(trace_log)
    slice_only_packets = find_slice_only_packets(trace_log)
    lossy_timestamps: set[int] = set()
    if slice_only_packets:
        # The elementary stream we feed FFmpeg has 1:1 packet↔AU
        # ordering matching report.access_units.
        au_list = report.access_units
        for pkt_idx in slice_only_packets:
            if 0 <= pkt_idx < len(au_list):
                lossy_timestamps.add(au_list[pkt_idx].timestamp)
    return TimelineInfo(
        timeline=timeline,
        header_fields=header_fields,
        raw_headers=headers,
        sampled_frames=frames,
        trace_warning=trace_warning,
        lossy_timestamps=lossy_timestamps,
    )


def _summarise_trace_errors(trace_log: str) -> str | None:
    """One-line warning when FFmpeg's trace_headers BSF reported parse
    failures. Returns ``None`` when the trace is clean.

    These markers (``Failed to read unit``, ``Invalid SEI message``,
    ``Error applying bitstream filters``) appear once per packet that
    the BSF couldn't fully parse — typically a malformed SEI in the
    user's stream. Surfacing the count lets the user know that HRD
    correlation had to recover around an FFmpeg parsing issue rather
    than silently ignoring it.
    """
    failed_units = 0
    invalid_sei = 0
    bsf_errors = 0
    for line in trace_log.splitlines():
        if "Failed to read unit" in line:
            failed_units += 1
        elif "Invalid SEI message" in line:
            invalid_sei += 1
        elif "Error applying bitstream filters" in line:
            bsf_errors += 1
    if not (failed_units or invalid_sei or bsf_errors):
        return None
    parts: list[str] = []
    if failed_units:
        parts.append(f"{failed_units} 'Failed to read unit'")
    if invalid_sei:
        parts.append(f"{invalid_sei} 'Invalid SEI message'")
    if bsf_errors:
        parts.append(f"{bsf_errors} 'Error applying bitstream filters'")
    return (
        "Warning: ffmpeg trace_headers reported parse issues ("
        + ", ".join(parts)
        + "). HRD correlation recovered using type-partitioned matching; "
        "field values for affected AUs may come from a neighbouring AU's SEI."
    )


def run_ffmpeg_trace_lenient(stream: Path, frames: int) -> str:
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
    return proc.stderr


def get_field(fields: dict[str, Any] | None, name: str) -> int | str | None:
    if not fields:
        return None
    if name in fields:
        return fields[name].get("value")
    for key, value in fields.items():
        if key.startswith(name + "["):
            return value.get("value")
    return None


def get_int_field(fields: dict[str, Any] | None, name: str) -> int | None:
    value = get_field(fields, name)
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except ValueError:
        return None


def rate_matches(expected: float, observed: float, tolerance: float = 0.005) -> bool:
    if expected <= 0 or observed <= 0:
        return False
    return abs(expected - observed) <= max(tolerance, expected * 0.005)


def interval_variation_in_window(
    times: list[float],
    window: float = 2.0,
    tolerance: float = 0.002,
) -> tuple[bool, str]:
    if len(times) < 3:
        return False, "Not enough samples to evaluate 2s window"
    intervals: list[tuple[float, float]] = []
    for i in range(1, len(times)):
        dt = times[i] - times[i - 1]
        if dt <= 0:
            return False, "Non-positive interval detected"
        intervals.append((times[i], dt))
    if len(intervals) < 2:
        return False, "Not enough intervals to evaluate 2s window"

    max_deque: deque[tuple[int, float]] = deque()
    min_deque: deque[tuple[int, float]] = deque()
    start = 0
    max_variation = 0.0
    worst_end = None
    for end, (t, dt) in enumerate(intervals):
        while max_deque and max_deque[-1][1] < dt:
            max_deque.pop()
        max_deque.append((end, dt))
        while min_deque and min_deque[-1][1] > dt:
            min_deque.pop()
        min_deque.append((end, dt))

        while t - intervals[start][0] > window:
            if max_deque and max_deque[0][0] == start:
                max_deque.popleft()
            if min_deque and min_deque[0][0] == start:
                min_deque.popleft()
            start += 1

        count = end - start + 1
        if count < 2 or not max_deque or not min_deque:
            continue
        variation = max_deque[0][1] - min_deque[0][1]
        if variation > max_variation:
            max_variation = variation
            worst_end = t

    if worst_end is None:
        return False, "Not enough intervals within any 2s window"
    if max_variation > tolerance:
        return (
            False,
            f"Max-min interval variation {max_variation*1000:.3f}ms exceeds {tolerance*1000:.3f}ms",
        )
    return (
        True,
        f"Max-min interval variation {max_variation*1000:.3f}ms within {tolerance*1000:.3f}ms",
    )


def untestable(message: str) -> tuple[bool, str, bool]:
    """Return a standardized 'cannot test' result triple."""
    return False, message, False


def check_sr_ntp_vs_capture_rate(
    sender_reports: list[SenderReportInfo],
) -> tuple[bool, str]:
    """SR NTP deltas SHOULD match PCAP capture deltas (both are real clocks).

    The sender's reference clock and the capture machine's clock are
    independent but should advance at the same rate.  The absolute offset
    between them may be arbitrary; only the delta consistency matters.
    """
    if len(sender_reports) < 3:
        return untestable("Not enough SRs to assess clock rate consistency")
    offsets = [sr.ntp_unix - sr.capture_time for sr in sender_reports]
    min_o, max_o = min(offsets), max(offsets)
    drift = max_o - min_o
    mean_offset = sum(offsets) / len(offsets)
    if drift > 0.010:
        return False, (
            f"Sender-to-capture clock offset varies by {drift*1000:.3f}ms "
            f"(mean offset {mean_offset:.3f}s) — clocks are drifting"
        )
    return True, (
        f"Clock offset stable: variation {drift*1000:.3f}ms "
        f"(mean offset {mean_offset:.3f}s, {len(offsets)} SRs)"
    )


def check_sr_ntp_self_consistent(
    sender_reports: list[SenderReportInfo],
) -> tuple[bool, str]:
    """SR NTP timestamps SHOULD be self-consistent (constant frame interval).

    The sender's reference clock should advance by approximately the
    nominal frame period between consecutive Sender Reports.
    """
    if len(sender_reports) < 3:
        return untestable("Not enough SRs to assess NTP self-consistency")
    ntp_deltas = [
        sender_reports[i].ntp_unix - sender_reports[i - 1].ntp_unix
        for i in range(1, len(sender_reports))
    ]
    if not ntp_deltas:
        return untestable("No NTP deltas available")
    ntp_deltas.sort()
    median = ntp_deltas[len(ntp_deltas) // 2]
    max_dev = max(abs(d - median) for d in ntp_deltas)
    if max_dev > 0.002:
        return False, (
            f"NTP inter-SR variation {max_dev*1000:.3f}ms exceeds 2ms "
            f"(median interval {median*1000:.3f}ms)"
        )
    return True, (
        f"NTP inter-SR variation {max_dev*1000:.3f}ms "
        f"(median interval {median*1000:.3f}ms, {len(ntp_deltas)} intervals)"
    )


def nominal_ticks_per_period_from_seconds(
    period_seconds: float,
    clock_rate: int = CLOCK_RATE,
) -> float:
    """Expected RTP timestamp increment per frame (one period) in ticks.

    period_seconds is the nominal frame period in seconds (e.g. 1/60 or 1001/60000).
    """
    return clock_rate * period_seconds


# ---------------------------------------------------------------------------
# Exact framerate helpers for SR-DIFF check
# ---------------------------------------------------------------------------


def extract_video_params_from_sr(
    sender_reports: list[SenderReportInfo],
) -> dict[str, Any] | None:
    """Extract video signal description from MIB 0x0005, 0x0003, or 0x0001.

    Returns a dict with keys: sampling_format, width, height, bit_depth,
    interlace, or None if no video MIB is present.
    """
    for sr in sender_reports:
        if sr.ipmx_info is None:
            continue
        for block in sr.ipmx_info.media_blocks:
            if block.media_info_type in (0x0001, 0x0003, 0x0005) and block.decoded:
                return dict(block.decoded)
    return None


def extract_interlace_from_sr(
    sender_reports: list[SenderReportInfo],
) -> bool | None:
    """Extract the interlace flag from MIB 0x0005, 0x0003, or 0x0001."""
    for sr in sender_reports:
        if sr.ipmx_info is None:
            continue
        for block in sr.ipmx_info.media_blocks:
            if block.media_info_type in (0x0001, 0x0003, 0x0005) and block.decoded:
                val = block.decoded.get("interlace")
                if val is not None:
                    return bool(val)
    return None


def extract_exact_framerate_from_sr(
    sender_reports: list[SenderReportInfo],
) -> Fraction | None:
    """Extract the exact framerate as num/den from MIB 0x0005 or 0x0003."""
    for sr in sender_reports:
        if sr.ipmx_info is None:
            continue
        for block in sr.ipmx_info.media_blocks:
            if block.media_info_type in (0x0001, 0x0003, 0x0005) and block.decoded:
                num = block.decoded.get("rate_numerator")
                den = block.decoded.get("rate_denominator")
                if isinstance(num, int) and isinstance(den, int) and num > 0 and den > 0:
                    return Fraction(num, den)
    return None


def parse_exactframerate_arg(value: str) -> Fraction:
    """Parse a CLI --exactframerate value like '60', '60/1', or '60000/1001'."""
    if "/" in value:
        num_s, den_s = value.split("/", 1)
        num, den = int(num_s.strip()), int(den_s.strip())
        if num <= 0 or den <= 0:
            raise ValueError(f"exactframerate num/den must be positive: {value}")
        return Fraction(num, den)
    val = int(value.strip())
    if val <= 0:
        raise ValueError(f"exactframerate must be positive: {value}")
    return Fraction(val)


def infer_ticks_per_frame_from_rtp(
    rtp_timestamps: list[int],
) -> Fraction | None:
    """Infer exact ticks-per-frame from RTP media stream nominal timestamps.

    Builds a histogram of inter-frame deltas and accepts only two shapes:

    1. **One bucket** — all deltas identical → integer ticks per frame.
    2. **Two buckets** differing by 1 with equal count (±1 for odd total) →
       half-integer ticks (e.g. 1501 and 1502 in equal proportion → 1501½).

    Any other histogram shape (3+ buckets, or 2 buckets with unequal counts)
    means the stream is noisy or non-conformant and we cannot infer.
    """
    if len(rtp_timestamps) < 3:
        return None
    unwrapped = unwrap_rtp_timestamps(rtp_timestamps)
    deltas = [
        unwrapped[i + 1] - unwrapped[i]
        for i in range(len(unwrapped) - 1)
        if (unwrapped[i + 1] - unwrapped[i]) > 0
    ]
    if not deltas:
        return None

    histogram = Counter(deltas)
    buckets = sorted(histogram.keys())

    if len(buckets) == 1:
        return Fraction(buckets[0])

    if len(buckets) == 2 and buckets[1] - buckets[0] == 1:
        lo_count = histogram[buckets[0]]
        hi_count = histogram[buckets[1]]
        if abs(lo_count - hi_count) <= 1:
            return Fraction(2 * buckets[0] + 1, 2)

    return None


def resolve_exact_ticks_per_frame(
    exact_framerate: Fraction | None,
    sender_reports: list[SenderReportInfo] | None,
    rtp_timestamps: list[int] | None,
    clock_rate: int = CLOCK_RATE,
) -> Fraction | None:
    """Resolve the exact ticks-per-frame from the best available source.

    Priority: explicit exact_framerate > MIB > RTP inference.
    """
    if exact_framerate is not None:
        return Fraction(clock_rate) / exact_framerate
    if sender_reports:
        mib_rate = extract_exact_framerate_from_sr(sender_reports)
        if mib_rate is not None:
            return Fraction(clock_rate) / mib_rate
    if rtp_timestamps:
        return infer_ticks_per_frame_from_rtp(rtp_timestamps)
    return None


def cross_validate_interlace(
    cli_interlace: bool | None,
    sender_reports: list[SenderReportInfo],
) -> tuple[bool, str] | tuple[bool, str, bool]:
    """Cross-validate CLI --interlace against MIB interlace field."""
    if cli_interlace is None:
        return untestable("No --interlace provided — nothing to cross-validate")
    mib_interlace = extract_interlace_from_sr(sender_reports)
    if mib_interlace is None:
        return untestable("No MIB interlace field available for cross-validation")
    if cli_interlace != mib_interlace:
        return (
            False,
            f"CLI interlace={cli_interlace} != MIB interlace={mib_interlace}",
        )
    return True, f"CLI interlace={cli_interlace} matches MIB"


def cross_validate_video_params(
    ctx_width: int | None,
    ctx_height: int | None,
    ctx_sampling: str | None,
    ctx_bit_depth: int | None,
    sender_reports: list[SenderReportInfo],
) -> tuple[bool, str] | tuple[bool, str, bool]:
    """Cross-validate CLI --width/--height/--sampling/--bit-depth against MIB."""
    has_cli = any(v is not None for v in (ctx_width, ctx_height, ctx_sampling, ctx_bit_depth))
    if not has_cli:
        return untestable("No video signal CLI parameters provided — nothing to cross-validate")
    mib = extract_video_params_from_sr(sender_reports)
    if mib is None:
        return untestable("No video MIB available for cross-validation")

    mismatches: list[str] = []
    if ctx_width is not None:
        mib_w = mib.get("width")
        if mib_w is not None and ctx_width != mib_w:
            mismatches.append(f"width CLI={ctx_width} MIB={mib_w}")
    if ctx_height is not None:
        mib_h = mib.get("height")
        if mib_h is not None and ctx_height != mib_h:
            mismatches.append(f"height CLI={ctx_height} MIB={mib_h}")
    if ctx_sampling is not None:
        mib_s = mib.get("sampling_format")
        if mib_s is not None and ctx_sampling != mib_s:
            mismatches.append(f"sampling CLI={ctx_sampling} MIB={mib_s}")
    if ctx_bit_depth is not None:
        mib_bd = mib.get("bit_depth")
        if mib_bd is not None and ctx_bit_depth != mib_bd:
            mismatches.append(f"bit_depth CLI={ctx_bit_depth} MIB={mib_bd}")

    if mismatches:
        return False, "CLI vs MIB mismatch: " + "; ".join(mismatches)
    return True, "CLI video signal parameters match MIB"


def cross_validate_exactframerate(
    cli_rate: Fraction | None,
    sender_reports: list[SenderReportInfo],
) -> tuple[bool, str] | tuple[bool, str, bool]:
    """Cross-validate CLI --exactframerate against MIB rate_numerator/rate_denominator."""
    if cli_rate is None:
        return untestable("No --exactframerate provided — nothing to cross-validate")
    mib_rate = extract_exact_framerate_from_sr(sender_reports)
    if mib_rate is None:
        return untestable("No MIB rate_numerator/rate_denominator available for cross-validation")
    if cli_rate != mib_rate:
        return (
            False,
            f"CLI exactframerate {cli_rate} != MIB rate {mib_rate} "
            f"({mib_rate.numerator}/{mib_rate.denominator})",
        )
    return True, f"CLI exactframerate {cli_rate} matches MIB rate"


def check_sr_rtp_timestamp_nominal(
    sender_reports: list[SenderReportInfo],
    exact_ticks_per_frame: Fraction | None,
    clock_rate: int = CLOCK_RATE,
) -> tuple[bool, str] | tuple[bool, str, bool]:
    """SR RTP timestamp deltas SHALL match the nominal frame increment (TR-10-1 §13.3b).

    exact_ticks_per_frame is a Fraction giving the exact ticks per frame
    (e.g. Fraction(1500) for 60 Hz, Fraction(3003, 2) for 59.94 Hz).

    Integer case: every single delta must be exactly the integer value.
    Fractional case: only floor(ticks) and ceil(ticks) are allowed, and
    every k consecutive deltas (k = denominator) must sum to the exact
    integer numerator.
    """
    if len(sender_reports) < 2:
        return untestable("Not enough SRs to verify nominal RTP timestamp increment")

    ts_list = [sr.rtp_timestamp for sr in sender_reports]
    unwrapped = unwrap_rtp_timestamps(ts_list)
    deltas = [unwrapped[i + 1] - unwrapped[i] for i in range(len(unwrapped) - 1)]

    if not deltas:
        return untestable("No SR deltas to verify")

    if exact_ticks_per_frame is None:
        return untestable("Exact framerate unknown — cannot verify SR RTP timestamp increments")

    ticks = exact_ticks_per_frame
    ticks_float = float(ticks)

    # Skipped-frame detection
    for i, d in enumerate(deltas):
        if d > 1.5 * ticks_float:
            return (
                False,
                f"SR RTP delta {d} at interval {i + 1} suggests skipped frame "
                f"(expected ~{ticks_float:.2f} ticks/frame)",
            )

    if ticks.denominator == 1:
        # Integer case: every delta must be exactly this value
        exact_int = int(ticks)
        for i, d in enumerate(deltas):
            if d != exact_int:
                return (
                    False,
                    f"SR RTP delta {d} at interval {i + 1} != expected {exact_int} "
                    f"(integer ticks/frame for this framerate)",
                )
        return (
            True,
            f"SR RTP timestamp deltas all exactly {exact_int} ticks/frame "
            f"({len(deltas)} intervals)",
        )

    # Fractional case
    lo = int(ticks)       # floor
    hi = lo + 1           # ceil
    k = ticks.denominator  # repeat period: k deltas must sum to ticks.numerator
    exact_k_sum = ticks.numerator

    # Every individual delta must be either lo or hi
    for i, d in enumerate(deltas):
        if d != lo and d != hi:
            return (
                False,
                f"SR RTP delta {d} at interval {i + 1} is not {lo} or {hi} "
                f"(allowed values for {ticks_float:.4f} ticks/frame)",
            )

    # Every k consecutive deltas must sum to exact_k_sum
    for i in range(len(deltas) - k + 1):
        window_sum = sum(deltas[i : i + k])
        if window_sum != exact_k_sum:
            return (
                False,
                f"SR RTP {k}-period sum {window_sum} at intervals {i + 1}..{i + k} "
                f"!= expected {exact_k_sum} "
                f"({ticks_float:.4f} ticks/frame, repeat period {k})",
            )

    return (
        True,
        f"SR RTP timestamp deltas follow exact {lo}/{hi} pattern "
        f"({ticks_float:.4f} ticks/frame, {k}-period sum {exact_k_sum}, "
        f"{len(deltas)} intervals)",
    )


def check_sr_initial_rtp_clock(
    sender_reports: list[SenderReportInfo],
    clock_rate: int = CLOCK_RATE,
) -> tuple[bool, str] | tuple[bool, str, bool]:
    """First SR RTP timestamp SHALL be synchronized with the Internal Clock (TR-10-1 §8.6).

    The spec requires that when the first RTP timestamp is sampled, the RTP
    clock is synchronized with the Internal Clock.  We verify this by computing
    the expected RTP timestamp from the SR NTP field (which represents the
    Internal Clock) and comparing it to the actual SR RTP timestamp.

    Only the first SR in the PCAP is checked — subsequent SRs may drift for
    async media (``mediaclk:sender``).

    Uses exact ``Fraction`` arithmetic to avoid floating-point precision loss
    when multiplying large PTP seconds by the clock rate.
    """
    if not sender_reports:
        return untestable("No Sender Reports available")

    sr = sender_reports[0]
    if sr.ipmx_info is None:
        return untestable("First SR has no IPMX Info Block — cannot confirm PTP timestamp format")

    expected_rtp = int(
        Fraction(sr.ntp_seconds) * clock_rate
        + Fraction(sr.ntp_fraction) * clock_rate / NANOSECONDS_PER_SECOND
    ) % (1 << 32)

    raw_offset = (sr.rtp_timestamp - expected_rtp) % (1 << 32)
    signed_offset = raw_offset if raw_offset < (1 << 31) else raw_offset - (1 << 32)

    if abs(signed_offset) <= 1:
        return (
            True,
            f"First SR RTP clock offset from Internal Clock: {signed_offset} tick(s) "
            f"(ntp={sr.ntp_seconds}.{sr.ntp_fraction:09d}, "
            f"expected_rtp={expected_rtp}, actual_rtp={sr.rtp_timestamp})",
        )
    return (
        False,
        f"First SR RTP clock offset {signed_offset} ticks from Internal Clock "
        f"(ntp={sr.ntp_seconds}.{sr.ntp_fraction:09d}, "
        f"expected_rtp={expected_rtp}, actual_rtp={sr.rtp_timestamp}) — "
        f"expected ±1 tick per TR-10-1 §8.6",
    )


def check_sr_rc_zero(
    sender_reports: list[SenderReportInfo],
) -> tuple[bool, str] | tuple[bool, str, bool]:
    """RTCP SR reception report count (RC) SHOULD be 0 (TR-10-1 §8.7).

    Per the TR-10-1 note on the RTCP SR header, the RC field should be 0
    for IPMX senders since IPMX does not require reception reports.
    """
    if not sender_reports:
        return untestable("No Sender Reports available")
    non_zero = [
        (i, sr.reception_report_count)
        for i, sr in enumerate(sender_reports)
        if sr.reception_report_count != 0
    ]
    if non_zero:
        examples = ", ".join(f"SR[{i}]={rc}" for i, rc in non_zero[:5])
        return (
            False,
            f"{len(non_zero)}/{len(sender_reports)} SR(s) have non-zero RC field: {examples}",
        )
    return True, f"All {len(sender_reports)} SR(s) have RC=0"


def compute_cmax_type_w(npackets: int | float | Fraction, tframe: Fraction) -> int:
    """Compute CMAX for a Type W sender per TR-10-1 §8.1 / ST 2110-21 §7.1.4.

    ``CMAX = MAX(16, INT(NPACKETS / (21600 × TFRAME)))``
    """
    return max(16, int(npackets / (21600 * float(tframe))))


@dataclass
class CmaxSimulationResult:
    """Result of the CMAX Network Compatibility Model leaky-bucket simulation."""
    passed: bool
    max_cinst: int
    cmax: int
    npackets: int | float | Fraction
    tframe: Fraction
    tdrain: float
    total_packets: int
    violation_count: int
    cinst_trace: list[int] | None = None


@dataclass
class HrdBurstGuardResult:
    """Result of a token-bucket burst guard anchored on HRD bitrate."""

    passed: bool
    max_debt_bits: int
    allowance_bits: int
    reference_bitrate_bits_per_s: float
    tframe: Fraction
    total_packets: int
    violation_count: int


def simulate_cmax_leaky_bucket(
    packet_capture_times: list[float],
    npackets: int | float | Fraction,
    tframe: Fraction,
    beta: Fraction = Fraction(11, 10),
    *,
    trace: bool = False,
) -> CmaxSimulationResult:
    """Run the ST 2110-21 Network Compatibility Model leaky-bucket simulation.

    Packets enter the bucket at their PCAP capture time.  The bucket drains
    one packet every *TDRAIN* seconds where
    ``TDRAIN = TFRAME / (NPACKETS × beta)``.  The instantaneous fullness
    *CINST* must never exceed *CMAX*.

    *beta* defaults to 1.10 per ST 2110-21 §7.1.

    When *trace* is True, ``cinst_trace`` in the result contains the CINST
    value recorded after each packet arrival (one entry per packet).
    """
    cmax = compute_cmax_type_w(npackets, tframe)
    tdrain = float(Fraction(tframe, Fraction(npackets) * beta))

    if not packet_capture_times:
        return CmaxSimulationResult(
            passed=True, max_cinst=0, cmax=cmax, npackets=npackets,
            tframe=tframe, tdrain=tdrain, total_packets=0, violation_count=0,
            cinst_trace=[] if trace else None,
        )

    t0 = packet_capture_times[0]
    cinst = 0
    max_cinst = 0
    violations = 0
    last_drain_count = 0
    cinst_values: list[int] | None = [] if trace else None

    for t in packet_capture_times:
        elapsed = t - t0
        drain_count = int(elapsed / tdrain) if tdrain > 0 else 0
        drained = drain_count - last_drain_count
        cinst = max(0, cinst - drained)
        last_drain_count = drain_count
        cinst += 1
        if cinst > max_cinst:
            max_cinst = cinst
        if cinst > cmax:
            violations += 1
        if cinst_values is not None:
            cinst_values.append(cinst)

    return CmaxSimulationResult(
        passed=max_cinst <= cmax,
        max_cinst=max_cinst,
        cmax=cmax,
        npackets=npackets,
        tframe=tframe,
        tdrain=tdrain,
        total_packets=len(packet_capture_times),
        violation_count=violations,
        cinst_trace=cinst_values,
    )


def simulate_hrd_burst_guard(
    packet_capture_times: list[float],
    packet_payload_sizes_bytes: list[int],
    reference_bitrate_bits_per_s: Fraction | int | float,
    cpb_size_bits: Fraction | int | float,
    tframe: Fraction,
    burst_frames: Fraction = Fraction(1, 1),
) -> HrdBurstGuardResult:
    """Run a token-bucket burst guard using HRD bitrate as the refill rate.

    This is intentionally a first-trial metric for compressed H.26x streams:
    - refill rate = HRD BitRate (bits/s)
    - burst allowance = min(CPB size, BitRate * TFRAME * burst_frames)
    """
    if len(packet_capture_times) != len(packet_payload_sizes_bytes):
        raise ValueError("capture-time and packet-size lists must have the same length")

    reference_rate = float(reference_bitrate_bits_per_s)
    if reference_rate <= 0:
        raise ValueError("reference bitrate must be positive")
    if not packet_capture_times:
        allowance_bits = int(min(float(cpb_size_bits), float(reference_bitrate_bits_per_s * tframe * burst_frames)))
        return HrdBurstGuardResult(
            passed=True,
            max_debt_bits=0,
            allowance_bits=max(0, allowance_bits),
            reference_bitrate_bits_per_s=reference_rate,
            tframe=tframe,
            total_packets=0,
            violation_count=0,
        )

    allowance_bits = int(
        min(
            float(cpb_size_bits),
            float(reference_bitrate_bits_per_s * tframe * burst_frames),
        )
    )
    allowance_bits = max(0, allowance_bits)
    tokens = float(allowance_bits)
    max_debt_bits = 0
    violations = 0
    prev_time = packet_capture_times[0]

    for capture_time, payload_size_bytes in zip(packet_capture_times, packet_payload_sizes_bytes):
        dt = max(0.0, capture_time - prev_time)
        prev_time = capture_time
        tokens = min(float(allowance_bits), tokens + (reference_rate * dt))
        tokens -= float(payload_size_bytes * 8)
        if tokens < 0.0:
            debt_bits = int(math.ceil(-tokens))
            if debt_bits > max_debt_bits:
                max_debt_bits = debt_bits
            violations += 1

    return HrdBurstGuardResult(
        passed=max_debt_bits == 0,
        max_debt_bits=max_debt_bits,
        allowance_bits=allowance_bits,
        reference_bitrate_bits_per_s=reference_rate,
        tframe=tframe,
        total_packets=len(packet_capture_times),
        violation_count=violations,
    )


def run_cmax_hrd_check(
    packets: list[dict[str, Any]],
    hrd_bit_rate: Fraction | None,
    exact_framerate: Fraction | None,
) -> list[RequirementResult]:
    """Simulate ST 2110-21 CMAX using HRD bitrate-derived equivalent packets/frame.

    Shared logic for H.264 and H.265 validators.  The caller extracts
    ``hrd_bit_rate`` using the codec-specific HRD parser.
    """
    req_id = "TR-10-1-8.1-CMAX"
    req_text = "CINST shall not exceed CMAX (TR-10-1 §8.1 / ST 2110-21 §6.6.1)."

    def _untestable(detail: str) -> list[RequirementResult]:
        return [RequirementResult(
            req_id=req_id, level="shall", text=req_text,
            passed=False, details=detail, testable=False,
        )]

    if exact_framerate is None:
        return _untestable("No exact framerate available")
    if hrd_bit_rate is None:
        return _untestable("Cannot extract HRD parameters for NPACKETS derivation")

    tframe = Fraction(1, exact_framerate)
    capture_times: list[float] = []
    payload_bits: list[int] = []
    for pkt in packets:
        capture_time = pkt.get("capture_time")
        payload = pkt.get("payload")
        if capture_time is None or payload is None:
            continue
        capture_times.append(float(capture_time))
        payload_bits.append(len(payload) * 8)

    if not capture_times:
        return _untestable("No RTP packet timing/payload data available")

    bits_per_frame = hrd_bit_rate * tframe
    avg_payload_bits = Fraction(sum(payload_bits), len(payload_bits))
    npackets_eq = bits_per_frame / avg_payload_bits

    sim = simulate_cmax_leaky_bucket(
        packet_capture_times=capture_times,
        npackets=npackets_eq,
        tframe=tframe,
    )

    window_seconds = float(tframe)
    samples = sorted(zip(capture_times, payload_bits), key=lambda x: x[0])
    left = 0
    running_bits = 0
    max_window_bits = 0
    for right, (t_right, bits_right) in enumerate(samples):
        running_bits += bits_right
        while t_right - samples[left][0] > window_seconds:
            running_bits -= samples[left][1]
            left += 1
        if running_bits > max_window_bits:
            max_window_bits = running_bits
    period_budget_bits = float(hrd_bit_rate * tframe)
    peak_ratio = (max_window_bits / period_budget_bits) if period_budget_bits > 0 else 0.0
    peak_bitrate_mbps = (max_window_bits / float(tframe)) / 1e6

    details = (
        f"HRD BitRate={float(hrd_bit_rate)/1e6:.2f} Mbps, "
        f"NPACKETS_eq={float(npackets_eq):.3f} "
        f"(BitRate*TFRAME / avg_payload={float(avg_payload_bits):.1f} bits), "
        f"CMAX={sim.cmax}, TDRAIN={sim.tdrain * 1e6:.1f} us, "
        f"max CINST={sim.max_cinst}, "
        f"peak_1T={max_window_bits/1e6:.3f} Mbit vs "
        f"budget_1T={period_budget_bits/1e6:.3f} Mbit "
        f"(peak {peak_bitrate_mbps:.2f} Mbps = {peak_ratio:.2f}x HRD BitRate)"
    )
    if not sim.passed:
        details += f", {sim.violation_count}/{sim.total_packets} packet(s) exceeded CMAX"

    return [RequirementResult(
        req_id=req_id, level="shall", text=req_text,
        passed=sim.passed, details=details,
    )]


def check_sdp_ipmx_fmtp(
    sdp_media: MediaDescriptor | None,
) -> tuple[bool, str] | tuple[bool, str, bool]:
    """SDP a=fmtp SHALL contain the IPMX keyword (TR-10-1 §10.1)."""
    if sdp_media is None:
        return untestable("No SDP provided")
    if not sdp_media.ipmx:
        return False, "SDP a=fmtp line does not contain the IPMX keyword"
    return True, "SDP a=fmtp contains the IPMX keyword"


def _is_ipv4_multicast(addr: str) -> bool:
    """Return True if `addr` is a dotted-quad in 224.0.0.0/4 (RFC 5771)."""
    if not addr:
        return False
    try:
        first = int(addr.split(".", 1)[0])
    except (ValueError, IndexError):
        return False
    return 224 <= first <= 239


def _is_ipv6_multicast(addr: str) -> bool:
    """Return True if `addr` is in ff::/8 (RFC 4291 §2.7)."""
    if not addr:
        return False
    return addr.lower().startswith("ff")


def _is_wildcard(addr: str, ipv6: bool) -> bool:
    """Wildcard ("any") source addresses on a multicast m= block — never
    routable under IGMPv3 (S,G) since the network can't compute RPF for
    them. Loopback (127.x / ::1) is permitted: it is the conventional
    sender address for single-host loopback test fixtures, and the only
    way the (S,G) state diverges from production is at the routing layer,
    which receivers parsing PCAPs don't exercise."""
    if not addr:
        return True
    if ipv6:
        return addr in ("::", "0:0:0:0:0:0:0:0")
    return addr == "0.0.0.0"


def check_sdp_multicast_source_filter(
    sdp_media: MediaDescriptor | None,
) -> tuple[bool, str] | tuple[bool, str, bool]:
    """SDP `a=source-filter:` SHALL be present on multicast streams
    (TR-10-9 §17 / RFC 4570). Skipped on unicast.

    The filter's *destination* SHALL match the m= block's `c=` connection
    address. The filter's *source* SHALL NOT be the wildcard ("any")
    address (0.0.0.0 / ::) — IGMPv3 (S,G) joins can never route from
    a wildcard source. Loopback (127.x / ::1) is permitted: single-host
    loopback test fixtures legitimately advertise a loopback sender, and
    receivers parsing PCAPs don't exercise the routing layer where the
    SSM RPF check would otherwise reject loopback.

    ST 2110-10 §8.4 expresses the broader real-outgoing-interface intent
    at SHOULD severity; TR-10-9 hardens to SHALL for the wildcard case,
    which is what this check enforces.
    """
    if sdp_media is None:
        return untestable("No SDP provided")

    dst = sdp_media.connection_address
    is_v6 = bool(getattr(sdp_media, "is_connection_ipv6", False))
    if not dst:
        return untestable("No connection address in SDP m= block")

    is_mc = _is_ipv6_multicast(dst) if is_v6 else _is_ipv4_multicast(dst)
    if not is_mc:
        return untestable(
            f"unicast destination {dst} — RFC 4570 source-filter N/A"
        )

    sf_dst = getattr(sdp_media, "source_filter_dst_address", "") or ""
    sf_src = getattr(sdp_media, "source_filter_src_address", "") or ""
    if not sf_src:
        return False, (
            f"SDP a=source-filter missing on multicast destination {dst} "
            f"(TR-10-9 §17 / RFC 4570 SHALL)"
        )
    if sf_dst and sf_dst != dst:
        return False, (
            f"SDP a=source-filter destination {sf_dst} does not match "
            f"m=c= connection address {dst}"
        )
    if _is_wildcard(sf_src, is_v6):
        return False, (
            f"SDP a=source-filter source {sf_src} is the wildcard address "
            f"on multicast destination {dst} — IGMPv3 (S,G) joins won't route"
        )
    return True, (
        f"SDP a=source-filter present: dst={dst} src={sf_src}"
    )


def check_sdp_dst_ip_vs_stream(
    sdp_media: "MediaDescriptor | None",
    stream_info: "Any | None",
) -> tuple[bool, str] | tuple[bool, str, bool]:
    """SDP `c=` connection address SHALL match the destination IP observed
    on the wire (TR-10-1 §10 transport consistency).

    Codec-independent: the rule is about whether receivers can route to the
    advertised group/address, not about media semantics. Per-codec validators
    should register this as a SHALL requirement and pass their context's
    media descriptor and stream_info directly.
    """
    if sdp_media is None:
        return untestable("No SDP transport file provided (use --sdp)")
    if stream_info is None:
        return untestable("RTP stream not detected")
    sdp_ip = sdp_media.connection_address
    if not sdp_ip:
        return untestable("SDP does not specify a connection address")
    if sdp_ip != stream_info.dst_ip:
        return False, (
            f"SDP connection address={sdp_ip} differs from detected "
            f"dst_ip={stream_info.dst_ip}"
        )
    return True, f"SDP connection address={sdp_ip} matches detected dst_ip"


def check_sdp_session_consistency(
    sdp_media: MediaDescriptor | None,
) -> tuple[bool, str] | tuple[bool, str, bool]:
    """SDP self-consistency rules per TR-10-1 §10.4 / §10.5 + IPMX video MIB.

    Asserts the same constraints `TP-10/TP-10-1Sec13.2.py:validate_config_vs_sdp`
    enforces independent of any user config:

      * `ts_ref_clock_source` ∈ {ptp, localmac}    (TR-10-1 §10.4)
      * When source == localmac, the MAC string SHALL be UPPERCASE
                                                  (TR-10-1 §10.4 formatting)
      * `media_clock_type`     ∈ {direct, sender}  (TR-10-1 §10.5)
      * When IPMX is set on a video stream, `h_total > 0`, `v_total > 0`,
        `measured_pix_clk > 0` SHALL all hold on the SDP itself
        (TR-10-1 §10.2 + §13 IPMX info-block consistency).

    First failure wins; on success returns a one-line summary.
    """
    if sdp_media is None:
        return untestable("No SDP provided")

    # ts_ref_clock_source ∈ {ptp, localmac}
    src = str(sdp_media.ts_ref_clock_source) if sdp_media.ts_ref_clock_source is not None else ""
    if src not in ("ptp", "localmac"):
        return False, (
            f"SDP a=ts-refclk source must be 'ptp' or 'localmac' "
            f"(TR-10-1 §10.4); got '{src or '<missing>'}'"
        )

    # localmac MAC SHALL be uppercase when present
    if src == "localmac":
        mac = sdp_media.ts_ref_clock_local_mac_address or ""
        if mac and mac != mac.upper():
            return False, (
                f"SDP a=ts-refclk localmac MAC SHALL be UPPERCASE "
                f"(TR-10-1 §10.4); got '{mac}'"
            )

    # media_clock_type ∈ {direct, sender}
    mct = str(sdp_media.media_clock_type) if sdp_media.media_clock_type is not None else ""
    if mct not in ("direct", "sender"):
        return False, (
            f"SDP a=mediaclk type must be 'direct' or 'sender' "
            f"(TR-10-1 §10.5); got '{mct or '<missing>'}'"
        )

    # IPMX-on-video → h_total / v_total / measured_pix_clk SHALL all be > 0
    is_ipmx = bool(getattr(sdp_media, "ipmx", False))
    type_str = str(sdp_media.type).lower() if sdp_media.type is not None else ""
    if is_ipmx and type_str == "video":
        h_total = getattr(sdp_media, "h_total", 0) or 0
        v_total = getattr(sdp_media, "v_total", 0) or 0
        meas_px = getattr(sdp_media, "measured_pix_clk", 0) or 0
        if h_total == 0 or v_total == 0 or meas_px == 0:
            return False, (
                f"IPMX video stream missing required fmtp fields "
                f"(TR-10-1 §10.2): h_total={h_total}, v_total={v_total}, "
                f"measured_pix_clk={meas_px}"
            )

    return True, (
        f"SDP self-consistency OK: ts-refclk={src}, mediaclk={mct}"
    )


def summarize_results(results: list[RequirementResult]) -> str:
    total = len(results)
    passed = sum(1 for res in results if res.passed)
    failed = total - passed
    return f"{passed}/{total} passed, {failed} failed"
