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
"""Validate AU-offset calculations against known HRD/VBV settings.

Workflow:
1) Re-encode the source stream with explicit x26x HRD/VBV parameters.
2) Packetize the encoded stream over RTP and capture packets into a PCAP without root.
3) Run ipmx_parse_rtp_pcap.py to recover RTP/NALU metadata.
4) Derive the minimum constant encoder delay compatible with captured timing and
   compare it to the theoretical HRD delay (vbv_bufsize * vbv_init / vbv_maxrate).

Use --ipmx-profile to enable VUI/HRD/profile settings intended to satisfy
TR-10-15b H.265 requirements (VUI flags, timing info, HRD presence, and
repeated VPS/SPS/PPS at random access points) or TR-10-15c H.264 requirements
(VUI flags, HRD presence, and timing info).
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import socket
import statistics
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any

from scapy.all import Ether, IP, UDP, Raw, PcapWriter

import ipmx_parse_rtp_pcap
import ipmx_validate_common
import ipmx_validate_hrd
import ipmx_validate_hrd_h264
from ffmpeg_location import find_ffmpeg

_FFMPEG, _FFMPEG_ENV = find_ffmpeg()


def ensure_tool(name: str) -> None:
    if name == "ffmpeg":
        return  # already resolved by find_ffmpeg() above
    if shutil.which(name) is None:
        raise SystemExit(f"{name} was not found in PATH")


def build_x265_params(args: argparse.Namespace) -> str:
    params = [
        f"vbv-maxrate={args.vbv_maxrate}",
        f"vbv-bufsize={args.vbv_bufsize}",
        f"vbv-init={args.vbv_init}",
        f"keyint={args.keyint}",
        f"min-keyint={args.keyint}",
        "scenecut=0",
    ]
    if args.ipmx_profile:
        params.extend(
            [
                "hrd=1",
                "nal-hrd=vbr",
                "vui-hrd-info=1",
                "vui-timing-info=1",
                "repeat-headers=1",
                "aud=1",
                "open-gop=0",
            ]
        )
    if not args.allow_bframes:
        params.append("bframes=0")
    if args.extra_x265_params:
        params.extend([p for p in args.extra_x265_params.split(":") if p])
    return ":".join(params)


def build_x264_params(args: argparse.Namespace) -> str:
    params = [
        f"vbv-maxrate={args.vbv_maxrate}",
        f"vbv-bufsize={args.vbv_bufsize}",
        f"keyint={args.keyint}",
        f"min-keyint={args.keyint}",
        "scenecut=0",
    ]
    if args.ipmx_profile:
        params.extend(
            [
                "nal-hrd=cbr",
                "aud=1",
                "repeat-headers=1",
                "open-gop=0",
                "force-cfr=1",
                "cabac=1",
                "8x8dct=0",
            ]
        )
    if not args.allow_bframes:
        params.append("bframes=0")
    if args.extra_x264_params:
        params.extend([p for p in args.extra_x264_params.split(":") if p])
    return ":".join(params)


def run_checked(cmd: list[str], env: dict | None = None) -> None:
    proc = subprocess.run(cmd, check=False, env=env)
    if proc.returncode != 0:
        raise SystemExit(f"Command failed ({proc.returncode}): {' '.join(cmd)}")


def encode_with_hrd(args: argparse.Namespace, encoded_mp4: Path) -> str:
    if args.codec == "h265":
        encoder_params = build_x265_params(args)
        encoder = "libx265"
        param_flag = "-x265-params"
    else:
        encoder_params = build_x264_params(args)
        encoder = "libx264"
        param_flag = "-x264-params"
    cmd = [
        _FFMPEG,
        "-hide_banner",
        "-loglevel",
        "error",
        "-y",
        "-r",
        str(args.fps),
        "-i",
        str(args.input),
        "-frames:v",
        str(args.encode_frames),
        "-c:v",
        encoder,
        "-preset",
        args.preset,
        param_flag,
        encoder_params,
    ]
    if args.ipmx_profile:
        cmd.extend(
            [
                "-pix_fmt",
                "yuv420p",
                "-color_range",
                "tv",
                "-colorspace",
                "bt709",
                "-color_primaries",
                "bt709",
                "-color_trc",
                "bt709",
                "-chroma_sample_location",
                "left",
            ]
        )
        if args.codec == "h265":
            cmd.extend(
                [
                    "-bsf:v",
                    f"hevc_metadata=tick_rate={args.fps}",
                ]
            )
        else:
            cmd.extend(
                [
                    "-b:v",
                    f"{args.vbv_maxrate}k",
                    "-maxrate",
                    f"{args.vbv_maxrate}k",
                    "-bufsize",
                    f"{args.vbv_bufsize}k",
                    "-profile:v",
                    "main",
                    "-level",
                    "5.1",
                ]
            )
    cmd.extend(
        [
        "-video_track_timescale", "90000",
        "-an",
        str(encoded_mp4),
        ]
    )
    run_checked(cmd, env=_FFMPEG_ENV)
    return encoder_params


def capture_rtp_to_pcap(input_mp4: Path, pcap_path: Path, port: int, payload_type: int) -> int:
    packets: list[tuple[float, bytes, int]] = []
    stop_event = threading.Event()

    def recv_loop() -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", port))
        sock.settimeout(0.2)
        while not stop_event.is_set():
            try:
                payload, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            packets.append((time.time(), payload, addr[1]))
        sock.close()

    receiver = threading.Thread(target=recv_loop, daemon=True)
    receiver.start()

    cmd = [
        _FFMPEG,
        "-hide_banner",
        "-loglevel",
        "error",
        "-re",
        "-i",
        str(input_mp4),
        "-c:v",
        "copy",
        "-payload_type",
        str(payload_type),
        "-an",
        "-f",
        "rtp",
        f"rtp://127.0.0.1:{port}",
    ]
    proc = subprocess.run(cmd, check=False, env=_FFMPEG_ENV)
    time.sleep(0.5)
    stop_event.set()
    receiver.join(timeout=2.0)

    if proc.returncode != 0:
        raise SystemExit(f"RTP packetization failed ({proc.returncode})")
    if not packets:
        raise SystemExit("No RTP packets were captured")

    writer = PcapWriter(str(pcap_path), sync=True)
    for capture_time, payload, src_port in packets:
        packet = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="127.0.0.1", dst="127.0.0.1")
            / UDP(sport=src_port, dport=port)
            / Raw(load=payload)
        )
        packet.time = capture_time
        writer.write(packet)
    writer.close()
    return len(packets)


def run_parser(codec: str, pcap: Path, report: Path, recovered: Path) -> None:
    cmd = [
        sys.executable,
        "ipmx_parse_rtp_pcap.py",
        str(pcap),
        "--codec",
        codec,
        "--report",
        str(report),
        "--output",
        str(recovered),
    ]
    run_checked(cmd)


def is_vcl(codec: str, nal_type: int) -> bool:
    if codec == "h264":
        return 1 <= nal_type <= 5
    return 0 <= nal_type <= 31


def unwrap_timestamps(timestamps: list[int]) -> list[int]:
    if not timestamps:
        return []
    unwrapped: list[int] = []
    wraps = 0
    prev = timestamps[0]
    for ts in timestamps:
        if ts < prev and (prev - ts) > 0x80000000:
            wraps += 1
        unwrapped.append(ts + wraps * (1 << 32))
        prev = ts
    return unwrapped


def derive_delay_metrics(report_json: dict[str, object], codec: str, clock_rate: int, theoretical_delay: float) -> dict[str, object]:
    first_capture_by_ts: dict[int, float] = {}
    au_order: list[int] = []
    for nalu in report_json.get("nalus", []):
        nal_type = int(nalu["nal_type"])
        capture_time = nalu.get("capture_time")
        if capture_time is None or not is_vcl(codec, nal_type):
            continue
        ts = int(nalu["timestamp"])
        existing = first_capture_by_ts.get(ts)
        if existing is None:
            first_capture_by_ts[ts] = float(capture_time)
            au_order.append(ts)
        elif float(capture_time) < existing:
            first_capture_by_ts[ts] = float(capture_time)

    if len(au_order) < 2:
        raise SystemExit("Not enough access units were reconstructed to derive timing metrics")

    unwrapped = unwrap_timestamps(au_order)
    base_ts = unwrapped[0]
    base_capture = first_capture_by_ts[au_order[0]]

    rel_rtp = [(ts - base_ts) / clock_rate for ts in unwrapped]
    rel_capture = [first_capture_by_ts[ts] - base_capture for ts in au_order]
    required_delay = [rel_rtp_i - rel_cap_i for rel_rtp_i, rel_cap_i in zip(rel_rtp, rel_capture)]
    d_min = max(required_delay)
    limiting_index = max(range(len(required_delay)), key=lambda i: required_delay[i])

    offsets_dmin = [d_min + rel_capture[i] - rel_rtp[i] for i in range(len(rel_rtp))]
    offsets_theory = [
        theoretical_delay + rel_capture[i] - rel_rtp[i] for i in range(len(rel_rtp))
    ]

    return {
        "access_units": len(au_order),
        "first_rtp_timestamp": au_order[0],
        "d_min_seconds": d_min,
        "limiting_au_index": limiting_index,
        "offsets_with_d_min": {
            "first": offsets_dmin[0],
            "min": min(offsets_dmin),
            "median": statistics.median(offsets_dmin),
            "max": max(offsets_dmin),
        },
        "offsets_with_theoretical_delay": {
            "first": offsets_theory[0],
            "min": min(offsets_theory),
            "median": statistics.median(offsets_theory),
            "max": max(offsets_theory),
            "negative_count": sum(1 for value in offsets_theory if value < 0.0),
        },
        "samples": [
            {
                "au_index": i,
                "rtp_timestamp": au_order[i],
                "rtp_elapsed": rel_rtp[i],
                "capture_elapsed": rel_capture[i],
                "offset_d_min": offsets_dmin[i],
                "offset_theory": offsets_theory[i],
            }
            for i in range(min(20, len(au_order)))
        ],
    }


_ETHER_HEADER = 14
_IP_HEADER = 20
_UDP_HEADER = 8


def _classify_frame(codec: str, nal_types: set[int]) -> str:
    """Derive a human-readable frame type from the NAL types in an AU."""
    if codec == "h265":
        if nal_types & {19, 20}:
            return "IDR"
        if nal_types & {21}:
            return "CRA"
        if nal_types & {0, 1}:
            return "P/B"
        return "other"
    # H.264
    if 5 in nal_types:
        return "IDR"
    if nal_types & {1, 2, 3, 4}:
        return "P/B"
    return "other"


@dataclass
class _AuAggregate:
    """Pre-computed per-AU totals, denormalized onto every packet row."""
    au_index: int
    frame_type: str
    packet_count: int
    nalu_total_bytes: int
    wire_total_bytes: int
    first_capture_time: float
    last_capture_time: float


@dataclass
class _CpbInfo:
    """CPB simulation values for a single AU."""
    init_arrival_time: float
    final_arrival_time: float
    cpb_removal_time: float
    cpb_occupancy_at_removal: float
    cpb_occupancy_after_removal: float
    overflow: bool
    underflow: bool


def write_analysis_csv(
    csv_path: Path,
    pcap_path: Path,
    codec: str,
    exact_framerate: Fraction,
    ffmpeg_frames: int,
    port: int | None = None,
) -> None:
    """Build a per-RTP-packet CSV with CMAX, HRD, wire, and AU columns.

    Every row is self-contained so that Excel formulas can reference any
    column on the same row without cross-lookups. ``port`` filters to a
    single UDP destination port so audio streams on adjacent ports don't
    feed the H.264/H.265 NAL parser with non-codec payloads.
    """
    # ---- 1. Parse the PCAP with the full validation pipeline ----
    report = ipmx_validate_common.build_rtp_report(pcap_path, codec, port, None)
    timeline = ipmx_validate_common.build_timeline(report, codec, ffmpeg_frames)

    # ---- 2. Extract HRD parameters from SPS ----
    hrd: ipmx_validate_hrd.HrdParameters | None = None
    if timeline is not None:
        sps = timeline.header_fields.get("SPS")
        if sps is not None:
            if codec == "h265":
                hrd = ipmx_validate_hrd.extract_hrd_parameters(sps)
            else:
                hrd = ipmx_validate_hrd_h264.extract_hrd_parameters_h264(sps)

    hrd_bit_rate = float(hrd.bit_rate) if hrd else 0.0
    hrd_cpb_size = float(hrd.cpb_size) if hrd else 0.0
    tframe = Fraction(1, exact_framerate)
    fps = float(exact_framerate)

    # ---- 3. Collect per-packet RTP header sizes from the PCAP ----
    rtp_header_by_seq: dict[int, int] = {}
    for rtp_pkt in ipmx_parse_rtp_pcap.iter_rtp_packets_stream(pcap_path, None):
        rtp_header_by_seq[rtp_pkt.seq] = rtp_pkt.header_len

    # ---- 4. Build AU index map and AU aggregate data ----
    au_index_by_ts: dict[int, int] = {}
    for au in report.access_units:
        au_index_by_ts[au.timestamp] = au.index

    # NALU bits per AU (from nalus_meta)
    nalu_bytes_by_ts: dict[int, int] = {}
    for meta in report.nalus_meta:
        ts = int(meta["timestamp"])
        nalu_bytes_by_ts[ts] = nalu_bytes_by_ts.get(ts, 0) + int(meta.get("nalu_size", 0))

    # First pass: compute per-AU wire totals and timing
    au_wire_bytes: dict[int, int] = {}
    au_first_capture: dict[int, float] = {}
    au_last_capture: dict[int, float] = {}
    au_packet_counts: dict[int, int] = {}
    au_nal_type_sets: dict[int, set[int]] = {}

    for pkt_meta in report.packets:
        ts = int(pkt_meta["timestamp"])
        payload_bytes = len(pkt_meta.get("payload", b""))
        rtp_hdr = rtp_header_by_seq.get(int(pkt_meta["seq"]), 12)
        wire = _ETHER_HEADER + _IP_HEADER + _UDP_HEADER + rtp_hdr + payload_bytes
        au_wire_bytes[ts] = au_wire_bytes.get(ts, 0) + wire
        au_packet_counts[ts] = au_packet_counts.get(ts, 0) + 1
        cap = pkt_meta.get("capture_time")
        if cap is not None:
            cap_f = float(cap)
            if ts not in au_first_capture or cap_f < au_first_capture[ts]:
                au_first_capture[ts] = cap_f
            if ts not in au_last_capture or cap_f > au_last_capture[ts]:
                au_last_capture[ts] = cap_f
        for nt in pkt_meta.get("nal_types", []):
            au_nal_type_sets.setdefault(ts, set()).add(int(nt))

    au_agg: dict[int, _AuAggregate] = {}
    for au in report.access_units:
        ts = au.timestamp
        au_agg[ts] = _AuAggregate(
            au_index=au.index,
            frame_type=_classify_frame(codec, au_nal_type_sets.get(ts, set())),
            packet_count=au_packet_counts.get(ts, 0),
            nalu_total_bytes=nalu_bytes_by_ts.get(ts, 0),
            wire_total_bytes=au_wire_bytes.get(ts, 0),
            first_capture_time=au_first_capture.get(ts, 0.0),
            last_capture_time=au_last_capture.get(ts, 0.0),
        )

    # ---- 5. CMAX leaky-bucket simulation with per-packet trace ----
    capture_times: list[float] = []
    payload_bits_list: list[int] = []
    for pkt_meta in report.packets:
        cap = pkt_meta.get("capture_time")
        payload = pkt_meta.get("payload")
        if cap is None or payload is None:
            continue
        capture_times.append(float(cap))
        payload_bits_list.append(len(payload) * 8)

    npackets_eq = Fraction(0)
    if hrd and capture_times:
        bits_per_frame = hrd.bit_rate * tframe
        avg_payload_bits = Fraction(sum(payload_bits_list), len(payload_bits_list))
        npackets_eq = bits_per_frame / avg_payload_bits

    cmax_sim = ipmx_validate_common.simulate_cmax_leaky_bucket(
        capture_times, npackets_eq if npackets_eq > 0 else 1, tframe, trace=True,
    )
    cinst_trace = cmax_sim.cinst_trace or []

    # ---- 6. CPB simulation (HRD timing) ----
    # Dispatch SEI extraction by codec: H.265's extract_sei_per_au reads
    # PREFIX_SEI_NUT (nal_type 39), while H.264 SEIs live in NAL type 6 —
    # different field layouts in both BP and pic_timing SEIs. Using the
    # H.265 extractor for an H.264 stream returns empty maps and the CPB
    # simulation gets skipped → CSV HRD columns stay blank. Fixed here so
    # ipmx_validate_hrd_h264.extract_sei_per_au_h264 is used for codec=h264.
    cpb_by_ts: dict[int, _CpbInfo] = {}
    bp_map: dict[int, Any] = {}
    if hrd and timeline and timeline.raw_headers:
        if codec == "h264":
            bp_map, pt_map, _ = ipmx_validate_hrd_h264.extract_sei_per_au_h264(
                report, timeline.raw_headers)
        else:
            bp_map, pt_map, _ = ipmx_validate_hrd.extract_sei_per_au(
                report, timeline.raw_headers)
        au_sizes = ipmx_validate_hrd.compute_au_sizes(report)
        simulated_sizes = [s for s in au_sizes if s.rtp_timestamp in pt_map]
        if simulated_sizes:
            cpb_sim = ipmx_validate_hrd.simulate_cpb(
                hrd, bp_map, pt_map, simulated_sizes,
                use_nal_type=hrd.nal_hrd_present,
            )
            for ar in cpb_sim.au_results:
                cpb_by_ts[ar.rtp_timestamp] = _CpbInfo(
                    init_arrival_time=float(ar.init_arrival_time),
                    final_arrival_time=float(ar.final_arrival_time),
                    cpb_removal_time=float(ar.cpb_removal_time),
                    cpb_occupancy_at_removal=float(ar.cpb_occupancy_at_removal),
                    cpb_occupancy_after_removal=float(ar.cpb_occupancy_after_removal),
                    overflow=ar.overflow,
                    underflow=ar.underflow,
                )

    # ---- 6b. Per-AU initial_cpb_removal_delay_offset (H.264 §C.1.2 / H.265 §C.2.4.1) ----
    # The buffering-period SEI is only attached to RAP AUs. Per the CVS-wide
    # constraint (sum of delay + offset is constant), the offset declared at
    # any BP applies to subsequent AUs until the next BP. Carry it forward
    # so every AU row shows the active offset value. Raw units are 90 kHz
    # ticks; the CSV exports nanoseconds to match the other timing columns.
    removal_delay_offset_ticks_by_ts: dict[int, int] = {}
    current_offset_ticks: int | None = None
    for au in report.access_units:
        bp = bp_map.get(au.timestamp)
        if bp is not None:
            current_offset_ticks = int(bp.init_cpb_removal_delay_offset)
        if current_offset_ticks is not None:
            removal_delay_offset_ticks_by_ts[au.timestamp] = current_offset_ticks

    # ---- 7. Write the CSV ----
    fieldnames = [
        # Packet
        "pkt",
        "cap ns",
        "cap rel ns",
        "rtp ts",
        "seq",
        "marker",
        "NAL types",
        # Wire (per packet)
        "payload B",
        "rtp hdr B",
        "udp B",
        "ether B",
        # CMAX (per packet)
        "cinst",
        "cmax",
        "tdrain ns",
        "npackets eq",
        # AU (denormalized)
        "AU",
        "frame",
        "AU pkts",
        "AU NALU B",
        "AU NALU bits",
        "AU wire B",
        "AU first ns",
        "AU last ns",
        "AU dur ns",
        # HRD CPB (per AU, denormalized)
        "HRD arr ns",
        "HRD fin ns",
        "HRD rem ns",
        "rem delay offset ns",
        "CPB at rem bits",
        "CPB after bits",
        "overflow",
        "underflow",
        # Constants
        "bitrate bps",
        "CPB size bits",
        "tframe ns",
        "fps",
    ]

    first_capture = capture_times[0] if capture_times else 0.0

    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()

        pkt_index = 0
        for pkt_meta in report.packets:
            ts = int(pkt_meta["timestamp"])
            cap = pkt_meta.get("capture_time")
            payload = pkt_meta.get("payload", b"")
            seq = int(pkt_meta["seq"])

            payload_bytes = len(payload)
            rtp_hdr = rtp_header_by_seq.get(seq, 12)
            udp_total = _UDP_HEADER + rtp_hdr + payload_bytes
            ether_total = _ETHER_HEADER + _IP_HEADER + udp_total

            agg = au_agg.get(ts)
            cpb = cpb_by_ts.get(ts)
            cinst_val = cinst_trace[pkt_index] if pkt_index < len(cinst_trace) else ""

            nal_types_raw: list[int] = pkt_meta.get("nal_types", [])
            nal_labels = sorted(
                {ipmx_parse_rtp_pcap.describe_nal(codec, nt) for nt in nal_types_raw}
            )

            row: dict[str, Any] = {
                "pkt": pkt_index,
                "cap ns": (
                    int(float(cap) * 1_000_000_000) if cap is not None else ""
                ),
                "cap rel ns": (
                    int((float(cap) - first_capture) * 1_000_000_000)
                    if cap is not None else ""
                ),
                "rtp ts": pkt_meta["timestamp"],
                "seq": seq,
                "marker": int(pkt_meta.get("marker", False)),
                "NAL types": " ".join(nal_labels) if nal_labels else "",
                "payload B": payload_bytes,
                "rtp hdr B": rtp_hdr,
                "udp B": udp_total,
                "ether B": ether_total,
                "cinst": cinst_val,
                "cmax": cmax_sim.cmax,
                "tdrain ns": int(cmax_sim.tdrain * 1_000_000_000),
                "npackets eq": f"{float(npackets_eq):.3f}",
                "AU": agg.au_index if agg else "",
                "frame": agg.frame_type if agg else "",
                "AU pkts": agg.packet_count if agg else "",
                "AU NALU B": agg.nalu_total_bytes if agg else "",
                "AU NALU bits": agg.nalu_total_bytes * 8 if agg else "",
                "AU wire B": agg.wire_total_bytes if agg else "",
                "AU first ns": (
                    int((agg.first_capture_time - first_capture) * 1_000_000_000)
                    if agg else ""
                ),
                "AU last ns": (
                    int((agg.last_capture_time - first_capture) * 1_000_000_000)
                    if agg else ""
                ),
                "AU dur ns": (
                    int((agg.last_capture_time - agg.first_capture_time) * 1_000_000_000)
                    if agg else ""
                ),
                "HRD arr ns": (
                    int(cpb.init_arrival_time * 1_000_000_000) if cpb else ""
                ),
                "HRD fin ns": (
                    int(cpb.final_arrival_time * 1_000_000_000) if cpb else ""
                ),
                "HRD rem ns": (
                    int(cpb.cpb_removal_time * 1_000_000_000) if cpb else ""
                ),
                "rem delay offset ns": (
                    int(removal_delay_offset_ticks_by_ts[ts] * 1_000_000_000 / 90000)
                    if ts in removal_delay_offset_ticks_by_ts else ""
                ),
                "CPB at rem bits": (
                    f"{cpb.cpb_occupancy_at_removal:.0f}" if cpb else ""
                ),
                "CPB after bits": (
                    f"{cpb.cpb_occupancy_after_removal:.0f}" if cpb else ""
                ),
                "overflow": int(cpb.overflow) if cpb else "",
                "underflow": int(cpb.underflow) if cpb else "",
                "bitrate bps": f"{hrd_bit_rate:.0f}",
                "CPB size bits": f"{hrd_cpb_size:.0f}",
                "tframe ns": int(float(tframe) * 1_000_000_000),
                "fps": f"{fps:.4f}",
            }
            writer.writerow(row)
            pkt_index += 1

    print(f"Wrote analysis CSV       : {csv_path} ({pkt_index} rows)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="PCAP to analyse, or source video when --re-encode is used")
    parser.add_argument("--codec", choices=["h265", "h264"], default="h265")
    parser.add_argument(
        "--port",
        type=int,
        default=5004,
        help="UDP port of the video RTP stream (default 5004); audio streams on other ports are ignored",
    )
    parser.add_argument("--fps", type=float, default=60.0, help="Frame rate (used for TFRAME derivation)")
    parser.add_argument("--frames", type=int, default=0, help="Frames to trace with ffmpeg for SPS/SEI extraction (0 = all)")
    parser.add_argument(
        "--csv",
        type=Path,
        help="Write per-packet analysis CSV (CINST, HRD, wire breakdown, AU totals)",
    )

    # ---- Re-encode pipeline options ----
    re_group = parser.add_argument_group(
        "re-encode pipeline (requires --re-encode)",
        "Encode a source video with explicit HRD settings, packetize over RTP, "
        "capture into a PCAP, then analyse.",
    )
    re_group.add_argument(
        "--re-encode",
        action="store_true",
        help="Enable the encode → RTP capture → analyse pipeline",
    )
    re_group.add_argument("--encode-frames", type=int, default=240, help="Number of frames to encode")
    re_group.add_argument("--preset", default="ultrafast", help="x26x preset")
    re_group.add_argument("--keyint", type=int, default=60, help="keyint/min-keyint")
    re_group.add_argument(
        "--ipmx-profile",
        action="store_true",
        help="Enable IPMX-oriented encoder + VUI settings (HRD, timing info, repeat headers, BT.709 metadata)",
    )
    re_group.add_argument(
        "--allow-bframes",
        action="store_true",
        help="Allow encoder B-frames (default keeps bframes=0 for simpler timing validation)",
    )
    re_group.add_argument(
        "--vbv-maxrate",
        type=float,
        default=20000.0,
        help="Encoder vbv-maxrate in kbit/s",
    )
    re_group.add_argument(
        "--vbv-bufsize",
        type=float,
        default=20000.0,
        help="Encoder vbv-bufsize in kbit",
    )
    re_group.add_argument(
        "--vbv-init",
        type=float,
        default=1.0,
        help="x265 vbv-init ratio [0..1]",
    )
    re_group.add_argument(
        "--extra-x265-params",
        default="",
        help="Extra x265 params appended as colon-separated key=value entries",
    )
    re_group.add_argument(
        "--extra-x264-params",
        default="",
        help="Extra x264 params appended as colon-separated key=value entries",
    )
    re_group.add_argument("--rtp-port", type=int, default=5020)
    re_group.add_argument("--payload-type", type=int)
    re_group.add_argument("--clock-rate", type=int, default=90000)
    re_group.add_argument(
        "--prefix",
        default="hrd_validation",
        help="Prefix for generated artifact files",
    )
    re_group.add_argument(
        "--summary-json",
        type=Path,
        help="Optional output path for summary JSON (default: <prefix>_summary.json)",
    )
    args = parser.parse_args()

    if not args.input.exists():
        raise SystemExit(f"{args.input} does not exist")

    if not args.re_encode:
        # ---- Direct PCAP analysis mode (default) ----
        if args.csv is None:
            raise SystemExit("--csv <path> is required for PCAP analysis mode")
        exact_fr = Fraction(args.fps).limit_denominator(100000)
        ffmpeg_frames = args.frames if args.frames > 0 else 999_999
        write_analysis_csv(args.csv, args.input, args.codec, exact_fr, ffmpeg_frames, port=args.port)
        return 0

    # ---- Re-encode → capture → analyse pipeline ----
    if args.vbv_maxrate <= 0 or args.vbv_bufsize <= 0:
        raise SystemExit("vbv-maxrate and vbv-bufsize must be > 0")
    if not (0.0 <= args.vbv_init <= 1.0):
        raise SystemExit("vbv-init must be between 0 and 1")
    if args.payload_type is None:
        args.payload_type = 98 if args.codec == "h265" else 96

    ensure_tool("ffmpeg")
    if shutil.which("python3") is None and not Path(sys.executable).exists():
        raise SystemExit("Python interpreter not found")

    prefix = Path(args.prefix)
    encoded_mp4 = Path(f"{prefix}_encoded.mp4")
    pcap_path = Path(f"{prefix}_rtp.pcap")
    recovered_path = Path(f"{prefix}_recovered.{'265' if args.codec == 'h265' else '264'}")
    report_path = Path(f"{prefix}_rtp_report.json")
    summary_path = args.summary_json or Path(f"{prefix}_summary.json")

    encoder_params = encode_with_hrd(args, encoded_mp4)
    packet_count = capture_rtp_to_pcap(encoded_mp4, pcap_path, args.rtp_port, args.payload_type)
    run_parser(args.codec, pcap_path, report_path, recovered_path)

    with open(report_path, "r", encoding="utf-8") as fh:
        report_json = json.load(fh)
    parser_disruption = report_json.get("wallclock_disruption")

    theoretical_delay = (args.vbv_bufsize * args.vbv_init) / args.vbv_maxrate
    metrics = derive_delay_metrics(report_json, args.codec, args.clock_rate, theoretical_delay)

    summary = {
        "input": str(args.input),
        "codec": args.codec,
        "frames_encoded": args.encode_frames,
        "fps": args.fps,
        "encoder_params": encoder_params,
        "theoretical_initial_cpb_delay_seconds": theoretical_delay,
        "artifacts": {
            "encoded_mp4": str(encoded_mp4),
            "rtp_pcap": str(pcap_path),
            "recovered_stream": str(recovered_path),
            "rtp_report": str(report_path),
        },
        "rtp_packet_count": packet_count,
        "analysis": metrics,
    }
    if parser_disruption is not None:
        summary["wallclock_disruption"] = parser_disruption
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    theory_stats = metrics["offsets_with_theoretical_delay"]
    dmin_stats = metrics["offsets_with_d_min"]
    print(f"Encoded MP4              : {encoded_mp4}")
    print(f"Captured PCAP            : {pcap_path} ({packet_count} RTP packets)")
    print(f"Parsed report            : {report_path}")
    print(f"Theoretical CPB delay    : {theoretical_delay:.6f}s")
    print(f"Derived minimum delay    : {metrics['d_min_seconds']:.6f}s")
    print(
        "Offset@theory min/max    : "
        f"{theory_stats['min']:.6f}s / {theory_stats['max']:.6f}s"
    )
    print(
        "Offset@D_min min/max     : "
        f"{dmin_stats['min']:.6f}s / {dmin_stats['max']:.6f}s"
    )
    print(f"Offset@theory negatives  : {theory_stats['negative_count']}")
    if parser_disruption is not None:
        print(
            "Wallclock disruption     : "
            f"AU {parser_disruption['at_access_unit_index'] - 1} -> "
            f"AU {parser_disruption['at_access_unit_index']} "
            f"(capture delta {parser_disruption['capture_delta']:.6f}s)"
        )
    print(f"Summary JSON             : {summary_path}")

    if args.csv is not None:
        exact_fr = Fraction(args.fps).limit_denominator(100000)
        write_analysis_csv(args.csv, pcap_path, args.codec, exact_fr, args.encode_frames, port=args.port)

    return 0


if __name__ == "__main__":
    sys.exit(main())
