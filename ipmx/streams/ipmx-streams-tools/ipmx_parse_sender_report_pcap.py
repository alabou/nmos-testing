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

"""Parse RTCP Sender Reports from a PCAP capture.

Extracts RTCP Sender Reports (RFC 3550 PT=200) from UDP packets, decodes the
IPMX Info Block (tag 0x5831) and its Media Info Blocks (including the JPEG XS
type 0x0008 per VSF TR-10-15a), and produces a JSON report and optional CSV.

The parser works for any media type (video, audio, jxsv, h264, h265) — the
Media Info Block type is auto-detected from the binary payload.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

import ipmx_validate_common as common
import ipmx_sender_report


NTP_UNIX_OFFSET = 2_208_988_800


def _media_info_type_name(code: int) -> str:
    entry = ipmx_sender_report.MEDIA_INFO_TYPES.get(code)
    if entry is not None:
        return entry[0]
    return f"unknown (0x{code:04x})"


def sr_to_dict(csr: common.SenderReportInfo) -> dict[str, Any]:
    """Convert a SenderReportInfo to a JSON-serializable dict."""
    blocks: list[dict[str, Any]] = []
    for blk in csr.raw_blocks:
        block_dict: dict[str, Any] = {
            "type": blk.media_info_type,
            "type_hex": f"0x{blk.media_info_type:04x}",
            "type_name": _media_info_type_name(blk.media_info_type),
            "length_words": blk.length_words,
            "payload_hex": blk.payload.hex(),
        }
        if blk.decoded is not None:
            block_dict["decoded"] = blk.decoded
        blocks.append(block_dict)

    info_dict: dict[str, Any] | None = None
    if csr.ipmx_info is not None:
        info_dict = {
            "version": csr.ipmx_info.version,
            "ts_refclk": csr.ipmx_info.ts_refclk,
            "mediaclk": csr.ipmx_info.mediaclk,
            "media_info_blocks": blocks,
        }

    return {
        "capture_time": csr.capture_time,
        "ssrc": csr.ssrc,
        "ntp_seconds": csr.ntp_seconds,
        "ntp_fraction": csr.ntp_fraction,
        "ntp_unix": csr.ntp_unix,
        "rtp_timestamp": csr.rtp_timestamp,
        "packet_count": csr.packet_count,
        "octet_count": csr.octet_count,
        "ipmx_info_block": info_dict,
    }


def write_csv(
    csv_path: Path,
    reports: list[common.SenderReportInfo],
) -> None:
    """Write a CSV with one row per sender report, flattening media info blocks."""
    fieldnames = [
        "capture_time",
        "ssrc",
        "rtp_timestamp",
        "ntp_seconds",
        "ntp_fraction",
        "ntp_unix",
        "packet_count",
        "octet_count",
        "ipmx_version",
        "ts_refclk",
        "mediaclk",
        "media_block_types",
        "video_width",
        "video_height",
        "video_rate_num",
        "video_rate_den",
        "video_sampling",
        "video_bit_depth",
        "video_colorimetry",
        "video_tcs",
        "video_range",
        "video_interlace",
        "jxsv_transmode",
        "jxsv_packetmode",
        "jxsv_ppih",
        "jxsv_ppih_hex",
        "jxsv_plev",
        "jxsv_plev_hex",
        "audio_sampling_rate",
        "audio_sample_size",
        "audio_channel_count",
        "audio_packet_time",
        "audio_channel_order",
    ]
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for csr in reports:
            video_fields: dict[str, Any] = {}
            jxsv_fields: dict[str, Any] = {}
            audio_fields: dict[str, Any] = {}
            block_type_strs: list[str] = []

            for blk in csr.raw_blocks:
                block_type_strs.append(f"0x{blk.media_info_type:04x}")
                if blk.decoded is None:
                    continue
                if blk.media_info_type in (0x0001, 0x0003, 0x0005):
                    video_fields = dict(blk.decoded)
                elif blk.media_info_type == 0x0008:
                    jxsv_fields = dict(blk.decoded)
                elif blk.media_info_type == 0x0002:
                    audio_fields = dict(blk.decoded)

            row: dict[str, Any] = {
                "capture_time": csr.capture_time,
                "ssrc": csr.ssrc,
                "ntp_seconds": csr.ntp_seconds,
                "ntp_fraction": csr.ntp_fraction,
                "ntp_unix": csr.ntp_unix,
                "rtp_timestamp": csr.rtp_timestamp,
                "packet_count": csr.packet_count,
                "octet_count": csr.octet_count,
                "ipmx_version": csr.ipmx_info.version if csr.ipmx_info else "",
                "ts_refclk": csr.ipmx_info.ts_refclk if csr.ipmx_info else "",
                "mediaclk": csr.ipmx_info.mediaclk if csr.ipmx_info else "",
                "media_block_types": " ".join(block_type_strs),
                "video_width": video_fields.get("width", ""),
                "video_height": video_fields.get("height", ""),
                "video_rate_num": video_fields.get("rate_numerator", ""),
                "video_rate_den": video_fields.get("rate_denominator", ""),
                "video_sampling": video_fields.get("sampling_format", ""),
                "video_bit_depth": video_fields.get("bit_depth", ""),
                "video_colorimetry": video_fields.get("colorimetry", ""),
                "video_tcs": video_fields.get("tcs", ""),
                "video_range": video_fields.get("range", ""),
                "video_interlace": video_fields.get("interlace", ""),
                "jxsv_transmode": jxsv_fields.get("transmode", ""),
                "jxsv_packetmode": jxsv_fields.get("packetmode", ""),
                "jxsv_ppih": jxsv_fields.get("ppih", ""),
                "jxsv_ppih_hex": jxsv_fields.get("ppih_hex", ""),
                "jxsv_plev": jxsv_fields.get("plev", ""),
                "jxsv_plev_hex": jxsv_fields.get("plev_hex", ""),
                "audio_sampling_rate": audio_fields.get("sampling_rate", ""),
                "audio_sample_size": audio_fields.get("sample_size", ""),
                "audio_channel_count": audio_fields.get("channel_count", ""),
                "audio_packet_time": audio_fields.get("packet_time", ""),
                "audio_channel_order": audio_fields.get("channel_order", ""),
            }
            writer.writerow(row)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Parse RTCP Sender Reports from a PCAP capture."
    )
    parser.add_argument("pcap", type=Path, help="PCAP file containing RTCP traffic")
    parser.add_argument(
        "--port", type=int,
        help="Filter by UDP port (default: any)",
    )
    parser.add_argument(
        "--report", type=Path,
        help="JSON report path (default: rtcp_sender_reports.json)",
    )
    parser.add_argument(
        "--csv", type=Path,
        help="Per-sender-report CSV output path",
    )
    parser.add_argument(
        "--ssrc", type=lambda x: int(x, 0),
        help="Filter by SSRC (decimal or 0x hex)",
    )
    args = parser.parse_args()

    if not args.pcap.exists():
        raise SystemExit(f"{args.pcap} does not exist")

    all_reports = common.parse_sender_reports(args.pcap, args.port)

    if args.ssrc is not None:
        all_reports = [r for r in all_reports if r.ssrc == args.ssrc]

    print(f"Found {len(all_reports)} sender report(s)")

    if all_reports:
        ssrcs = {r.ssrc for r in all_reports}
        for ssrc in sorted(ssrcs):
            subset = [r for r in all_reports if r.ssrc == ssrc]
            sr0 = subset[0]
            print(f"  SSRC 0x{ssrc:08x}: {len(subset)} report(s)")
            if sr0.ipmx_info:
                print(f"    IPMX Info Block v{sr0.ipmx_info.version}")
                print(f"    ts-refclk: {sr0.ipmx_info.ts_refclk}")
                print(f"    mediaclk:  {sr0.ipmx_info.mediaclk}")
                for blk in sr0.raw_blocks:
                    name = _media_info_type_name(blk.media_info_type)
                    print(f"    Media Info Block 0x{blk.media_info_type:04x}: {name}")
                    if blk.decoded:
                        for k, v in blk.decoded.items():
                            print(f"      {k}: {v}")

    report_path = args.report or Path("tmp") / "rtcp_sender_reports.json"
    report_payload: dict[str, Any] = {
        "pcap": str(args.pcap),
        "sender_report_count": len(all_reports),
        "sender_reports": [sr_to_dict(r) for r in all_reports],
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report_payload, fh, indent=2)
    print(f"Wrote JSON report to {report_path}")

    if args.csv is not None:
        write_csv(args.csv, all_reports)
        print(f"Wrote CSV to {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
