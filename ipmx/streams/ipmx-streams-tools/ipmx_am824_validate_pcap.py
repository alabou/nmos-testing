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
"""Validate an ST 2110-31 AM824 RTP PCAP."""

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
    check_sdp_st2110_31,
)
from ipmx_am824 import (
    Am824StreamReport,
    analyze_am824_packets,
    AES3_BLOCK_PERIOD,
    aes3_sample_rate_byte0_bits,
    aes3_word_length_byte2,
    compute_audio_sender_report_interval_packets,
    compute_aes3_channel_status_crc,
    iter_selected_rtp_packets,
    legal_ptimes_us,
    resolve_nominal_packet_time_us,
    resolve_packet_samples_per_packet,
)
from ipmx_s337m import (
    S337mScanResult,
    S337M_MAX_BURST_GAP_FRAMES,
    S337M_DATA_MODE_TO_SAMPLE_SIZE,
    S337M_SAMPLE_SIZE_TO_DATA_MODE,
    scan_s337m_signal,
)
from ipmx_validate_common import (
    Requirement,
    RequirementResult,
    SenderReportInfo,
    check_sdp_ipmx_fmtp,
    check_sdp_multicast_source_filter,
    check_sdp_session_consistency,
    check_sr_initial_rtp_clock,
    check_sr_rc_zero,
    parse_sender_reports,
    summarize_results,
    untestable,
)
import ipmx_parse_rtp_pcap
import ipmx_validate_encryption


@dataclass
class Am824ValidationContext:
    pcap: Path
    stream_info: ipmx_parse_rtp_pcap.RtpStreamInfo
    rtp_packets: list[ipmx_parse_rtp_pcap.RTPPacket]
    am824_report: Am824StreamReport
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
    expect_stream_start: bool
    resolved_payload_type: int | None
    resolved_sample_rate: int | None
    resolved_sample_size: int | None
    resolved_nchan: int | None
    resolved_ptime_us: int | None
    resolved_channel_order: str | None
    resolved_rtcp_port: int | None
    # S337M non-PCM burst scan — None for PCM streams or when nchan is unresolved.
    s337m_scan_results: list[S337mScanResult] | None
    cli_s337m_data_type: int | None
    # Encryption state — derived from RTP extension headers and CLI flags.
    encrypted: bool
    enc_flags: ipmx_validate_encryption.EncryptionFlags


AES3_ALLOWED_CHANNEL_MODES = {0x0, 0x1, 0x4}


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
    report: Am824StreamReport,
) -> int | None:
    if cli_value is not None:
        return cli_value
    if sdp_media is not None and sdp_media.payload_type != 0:
        return sdp_media.payload_type
    if len(report.payload_type_set) == 1:
        return next(iter(report.payload_type_set))
    return None


def _build_s337m_scan_results(ctx: Am824ValidationContext) -> list[S337mScanResult] | None:
    """Scan all AES3 signals for S337M bursts if the stream is non-PCM.

    Returns a list with one S337mScanResult per AES3 stereo pair, or None when
    the stream is PCM, the channel mode is inconsistent, or nchan is unresolved.
    This is analogous to how video validators build their NAL-unit or box
    analysis in build_context so that every check function shares one parse pass.
    """
    blocks = _collect_channel_status_blocks(ctx)
    if blocks is None:
        return None
    if _stream_is_pcm(blocks) is not False:
        return None  # PCM or inconsistent — S337M scanning does not apply
    nchan = ctx.resolved_nchan
    if nchan is None or nchan < 2 or nchan % 2 != 0:
        return None
    sequences = _extract_sequence_subframes(ctx, nchan)
    if sequences is None:
        return None
    results: list[S337mScanResult] = []
    for signal_idx in range(nchan // 2):
        ch1 = sequences[signal_idx * 2]
        ch2 = sequences[signal_idx * 2 + 1]
        data24_words: list[int] = []
        validity_bits: list[int] = []
        for sf1, sf2 in zip(ch1, ch2):
            data24_words.extend([sf1.data24, sf2.data24])
            validity_bits.extend([sf1.validity_bit, sf2.validity_bit])
        results.append(scan_s337m_signal(data24_words, validity_bits, signal_idx))
    return results


def build_context(args: argparse.Namespace) -> Am824ValidationContext:
    stream_info = ipmx_parse_rtp_pcap.detect_rtp_stream(
        args.pcap,
        port=args.port,
        ssrc=args.ssrc,
        dst_ip=args.dst_ip,
    )
    packets = iter_selected_rtp_packets(args.pcap, stream_info=stream_info)
    if not packets:
        raise SystemExit("No RTP packets found for the selected stream")
    report = analyze_am824_packets(packets)
    sdp_media = load_sdp_media(args.sdp) if args.sdp else None
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
                if block.media_info_type == 0x0004 and block.decoded is not None:
                    sz = block.decoded.get("sample_size")
                    if sz is not None:
                        mib_sizes.add(int(sz))
        if len(mib_sizes) == 1:
            resolved_sample_size = next(iter(mib_sizes))
    resolved_nchan = args.nchan
    if resolved_nchan is None and sdp_media is not None:
        resolved_nchan = sdp_media.channels or None
    resolved_ptime_us = args.ptime
    if resolved_ptime_us is None and sdp_media is not None:
        resolved_ptime_us = sdp_media.p_time_us or None
    resolved_channel_order = args.channel_order
    if resolved_channel_order is None and sdp_media is not None and sdp_media.channel_order:
        resolved_channel_order = sdp_media.channel_order
    resolved_rtcp_port = args.rtcp_port
    if resolved_rtcp_port is None:
        resolved_rtcp_port = stream_info.rtcp_port

    # Detect encryption from the first packet's RTP extension elements
    enc_flags = ipmx_validate_encryption.EncryptionFlags(
        hkep=getattr(args, "hkep", False),
        pep=getattr(args, "pep", False),
    )
    first_ext = packets[0].ext_elements if packets else None
    encrypted = enc_flags.any_encryption or ipmx_validate_encryption.detect_encryption(first_ext)

    ctx = Am824ValidationContext(
        pcap=args.pcap,
        stream_info=stream_info,
        rtp_packets=packets,
        am824_report=report,
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
        expect_stream_start=bool(args.expect_stream_start),
        resolved_payload_type=resolved_payload_type,
        resolved_sample_rate=resolved_sample_rate,
        resolved_sample_size=resolved_sample_size,
        resolved_nchan=resolved_nchan,
        resolved_ptime_us=resolved_ptime_us,
        resolved_channel_order=resolved_channel_order,
        resolved_rtcp_port=resolved_rtcp_port,
        s337m_scan_results=None,
        cli_s337m_data_type=getattr(args, "s337m_data_type", None),
        encrypted=encrypted,
        enc_flags=enc_flags,
    )
    # Populate S337M scan results when the stream is confirmed non-PCM.
    # This mirrors how video validators build their bitstream analysis objects
    # in build_context so that all check functions share one scan pass.
    ctx.s337m_scan_results = _build_s337m_scan_results(ctx)
    return ctx


def _packet_periods(packet, nchan: int | None) -> int | None:
    if nchan is None or nchan <= 0:
        return None
    if packet.subframe_count % nchan != 0:
        return None
    return packet.subframe_count // nchan


def _stream_periods(ctx: Am824ValidationContext) -> list[int] | None:
    if ctx.resolved_nchan is None:
        return None
    return _stream_periods_for_nchan(ctx.am824_report, ctx.resolved_nchan)


def _stream_periods_for_nchan(report: Am824StreamReport, nchan: int) -> list[int] | None:
    periods: list[int] = []
    for packet in report.packets:
        value = _packet_periods(packet, nchan)
        if value is None:
            return None
        periods.append(value)
    return periods


def _timestamp_deltas(ctx: Am824ValidationContext) -> list[int]:
    if len(ctx.rtp_packets) < 2:
        return []
    timestamps = [packet.timestamp for packet in ctx.rtp_packets]
    unwrapped = []
    wraps = 0
    previous = timestamps[0]
    for value in timestamps:
        if value < previous and (previous - value) > 0x80000000:
            wraps += 1
        unwrapped.append(value + wraps * (1 << 32))
        previous = value
    return [cur - prev for prev, cur in zip(unwrapped, unwrapped[1:])]


def _resolved_packet_samples(ctx: Am824ValidationContext) -> int | None:
    if ctx.resolved_sample_rate is None or ctx.resolved_ptime_us is None:
        return None
    return resolve_packet_samples_per_packet(
        ctx.resolved_sample_rate,
        ctx.resolved_ptime_us,
    )


def _audio_mib_blocks(ctx: Am824ValidationContext) -> list[dict[str, object]]:
    blocks: list[dict[str, object]] = []
    for report in ctx.sender_reports:
        for block in report.raw_blocks:
            if block.media_info_type == 0x0004 and block.decoded is not None:
                blocks.append(block.decoded)
    return blocks


def _associate_sender_reports(
    ctx: Am824ValidationContext,
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


def _extract_sequence_subframes(
    ctx: Am824ValidationContext,
    nchan: int,
) -> list[list[Any]] | None:
    if ctx.encrypted:
        return None  # AM824 subframe bit-fields are not accessible on encrypted payloads
    if nchan <= 0:
        return None
    sequences: list[list[Any]] = [[] for _ in range(nchan)]
    for packet in ctx.am824_report.packets:
        if packet.subframe_count % nchan != 0:
            return None
        for offset in range(0, packet.subframe_count, nchan):
            period = packet.subframes[offset : offset + nchan]
            for index, subframe in enumerate(period):
                sequences[index].append(subframe)
    return sequences


def _find_channel_status_start_index(sequence: list[Any]) -> int | None:
    for index, subframe in enumerate(sequence):
        if subframe.block_start and subframe.frame_start:
            return index
    return None


def _extract_channel_status_bytes_from_sequence(
    sequences: list[list[Any]],
    sequence_index: int,
) -> bytes | None:
    sequence = sequences[sequence_index]
    if len(sequence) < AES3_BLOCK_PERIOD:
        return None
    if sequence_index % 2 == 0:
        start_index = _find_channel_status_start_index(sequence)
    else:
        start_index = _find_channel_status_start_index(sequences[sequence_index - 1])
    if start_index is None or len(sequence) < start_index + AES3_BLOCK_PERIOD:
        return None
    block = sequence[start_index : start_index + AES3_BLOCK_PERIOD]
    data = bytearray(24)
    for bit_index, subframe in enumerate(block):
        if subframe.channel_status_bit:
            data[bit_index // 8] |= 1 << (bit_index % 8)
    return bytes(data)


def _effective_ptime_set(sample_rate: int | None) -> set[int] | None:
    if sample_rate is None:
        return None
    return legal_ptimes_us(sample_rate)


def check_encapsulation(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if not ctx.rtp_packets:
        return False, "No RTP packets selected"
    invalid = sum(1 for packet in ctx.rtp_packets if packet.version != 2)
    if invalid:
        return False, f"{invalid} packet(s) are not RTP version 2"
    if ctx.encrypted:
        return untestable(
            f"{len(ctx.rtp_packets)} RTP packets selected — "
            "AM824 subframe structure cannot be validated on encrypted payloads"
        )
    malformed = sum(1 for packet in ctx.am824_report.packets if packet.issues)
    if malformed:
        return False, f"{malformed} packet(s) have malformed AM824 payload structure"
    return True, f"{len(ctx.rtp_packets)} RTP packets selected and AM824 payloads parsed"


def check_payload_type_constant(ctx: Am824ValidationContext) -> tuple[bool, str]:
    if len(ctx.am824_report.payload_type_set) != 1:
        return False, f"Multiple payload types observed: {sorted(ctx.am824_report.payload_type_set)}"
    value = next(iter(ctx.am824_report.payload_type_set))
    return True, f"RTP payload type is constant at {value}"


def check_ssrc_constant(ctx: Am824ValidationContext) -> tuple[bool, str]:
    if len(ctx.am824_report.ssrc_set) != 1:
        return False, f"Multiple SSRC values observed: {[f'0x{value:08X}' for value in sorted(ctx.am824_report.ssrc_set)]}"
    value = next(iter(ctx.am824_report.ssrc_set))
    return True, f"RTP SSRC is constant at 0x{value:08X}"


def check_csrc_zero(ctx: Am824ValidationContext) -> tuple[bool, str]:
    offenders = [packet.seq for packet in ctx.rtp_packets if packet.csrc_count != 0]
    if offenders:
        return False, f"{len(offenders)} packet(s) have non-zero CSRC count; first seq={offenders[0]}"
    return True, "CSRC count is 0 on all packets"


def check_marker_zero(ctx: Am824ValidationContext) -> tuple[bool, str]:
    offenders = [packet.seq for packet in ctx.rtp_packets if packet.marker]
    if offenders:
        return False, f"{len(offenders)} packet(s) set the marker bit; first seq={offenders[0]}"
    return True, "Marker bit is 0 on all packets"


def check_timestamp_step(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    deltas = _timestamp_deltas(ctx)
    if not deltas:
        return untestable("Not enough RTP packets to verify timestamp step")
    periods = _stream_periods(ctx)
    if not periods:
        return untestable("nchan unresolved or payload geometry invalid — cannot derive periods per packet")
    expected = periods[0]
    if any(period != expected for period in periods[1:]):
        return False, f"Packet payload periods are not constant: {sorted(set(periods))}"
    bad = [delta for delta in deltas if delta != expected]
    if bad:
        return False, f"Observed RTP timestamp deltas {sorted(set(bad))} do not match expected {expected}"
    return True, f"All RTP timestamp deltas equal {expected} sample periods"


def check_extension_state(ctx: Am824ValidationContext) -> tuple[bool, str]:
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


def check_word_alignment(ctx: Am824ValidationContext) -> tuple[bool, str]:
    bad = [packet.seq for packet in ctx.am824_report.packets if packet.payload_bytes == 0 or packet.payload_bytes % 4 != 0]
    if bad:
        return False, f"{len(bad)} packet(s) have empty or non-32-bit-aligned payloads; first seq={bad[0]}"
    return True, "All AM824 payloads are non-empty multiples of 4 bytes"


def check_reserved_bits(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.encrypted:
        return untestable("Payload encrypted — AM824 reserved bits are not accessible")
    for packet in ctx.am824_report.packets:
        for index, subframe in enumerate(packet.subframes):
            if subframe.reserved_bits != 0:
                return False, (
                    f"Packet seq={packet.seq} subframe #{index} has reserved_bits={subframe.reserved_bits}"
                )
    return True, "Reserved bits are 0 in all AM824 words"


def check_bf_legality(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.encrypted:
        return untestable("Payload encrypted — AM824 B/F bits are not accessible")
    for packet in ctx.am824_report.packets:
        for index, subframe in enumerate(packet.subframes):
            if subframe.block_start and not subframe.frame_start:
                return False, f"Packet seq={packet.seq} subframe #{index} has B=1 and F=0"
    return True, "All AM824 subframes satisfy B=1 => F=1"


def check_parity_bit(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.encrypted:
        return untestable("Payload encrypted — AES3 parity bits are not accessible")
    for packet in ctx.am824_report.packets:
        for index, subframe in enumerate(packet.subframes):
            expected = (
                bin(subframe.data24).count("1")
                + subframe.channel_status_bit
                + subframe.user_data_bit
                + subframe.validity_bit
            ) & 0x1
            if subframe.parity_bit != expected:
                return False, (
                    f"Packet seq={packet.seq} subframe #{index} has parity bit {subframe.parity_bit}, "
                    f"expected {expected}"
                )
    return True, "All AES3 parity bits satisfy even parity over DATA24+C+U+V+P"


def check_channel_status_standard_impl(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.encrypted:
        return untestable("Payload is encrypted — AES3 channel-status cannot be reconstructed")
    nchan = ctx.resolved_nchan
    if nchan is None:
        return untestable("nchan unresolved — cannot reconstruct AES3 channel status")
    sequences = _extract_sequence_subframes(ctx, nchan)
    if sequences is None:
        return False, "Packet payload geometry is incompatible with nchan"
    for index, _sequence in enumerate(sequences):
        channel_status = _extract_channel_status_bytes_from_sequence(sequences, index)
        if channel_status is None:
            return untestable("Fewer than 192 AES3 frames available for channel-status reconstruction")
        non_zero = [byte_index for byte_index, value in enumerate(channel_status) if value != 0]
        if any(byte_index not in {0, 1, 2, 23} for byte_index in non_zero):
            return False, (
                f"Sequence {index} channel-status bytes {non_zero} violate the restricted standard implementation"
            )
        if (channel_status[0] & 0x1) != 0x1:
            return False, f"Sequence {index} channel-status byte 0 bit 0 is not set for professional use"
    return True, "Reconstructed channel status uses only bytes 0, 1, 2, and 23"


def check_channel_status_modes(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.encrypted:
        return untestable("Payload is encrypted — AES3 channel-status cannot be reconstructed")
    nchan = ctx.resolved_nchan
    if nchan is None:
        return untestable("nchan unresolved — cannot reconstruct AES3 channel status")
    sequences = _extract_sequence_subframes(ctx, nchan)
    if sequences is None:
        return False, "Packet payload geometry is incompatible with nchan"
    for index, _sequence in enumerate(sequences):
        channel_status = _extract_channel_status_bytes_from_sequence(sequences, index)
        if channel_status is None:
            return untestable("Fewer than 192 AES3 frames available for channel-status reconstruction")
        mode = channel_status[1] & 0x0F
        if mode not in AES3_ALLOWED_CHANNEL_MODES:
            return False, (
                f"Sequence {index} channel mode 0x{mode:X} is not one of "
                "unspecified, two-channel, or stereophonic"
            )
    return True, "All reconstructed AES3 channel modes are restricted to unspecified/two-channel/stereophonic"


def check_channel_status_crc(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.encrypted:
        return untestable("Payload is encrypted — AES3 channel-status cannot be reconstructed")
    nchan = ctx.resolved_nchan
    if nchan is None:
        return untestable("nchan unresolved — cannot reconstruct AES3 channel status")
    sequences = _extract_sequence_subframes(ctx, nchan)
    if sequences is None:
        return False, "Packet payload geometry is incompatible with nchan"
    for index, _sequence in enumerate(sequences):
        channel_status = _extract_channel_status_bytes_from_sequence(sequences, index)
        if channel_status is None:
            return untestable("Fewer than 192 AES3 frames available for channel-status reconstruction")
        expected_crc = compute_aes3_channel_status_crc(channel_status[:23])
        if channel_status[23] != expected_crc:
            return False, (
                f"Sequence {index} channel-status byte 23 is 0x{channel_status[23]:02X}, "
                f"expected 0x{expected_crc:02X}"
            )
    return True, "All reconstructed AES3 channel-status CRCC values are valid"


def _collect_channel_status_blocks(
    ctx: Am824ValidationContext,
) -> list[tuple[int, bytes]] | None:
    """Return [(sequence_index, channel_status_bytes), ...] for all sequences, or None if geometry fails."""
    nchan = ctx.resolved_nchan
    if nchan is None:
        return None
    sequences = _extract_sequence_subframes(ctx, nchan)
    if sequences is None:
        return None
    result: list[tuple[int, bytes]] = []
    for index in range(nchan):
        cs = _extract_channel_status_bytes_from_sequence(sequences, index)
        if cs is not None:
            result.append((index, cs))
    return result if result else None


def _stream_is_pcm(blocks: list[tuple[int, bytes]]) -> bool | None:
    """Infer PCM vs non-PCM from byte 0 bit 1 across all channel-status blocks.

    Returns True (all PCM), False (all non-PCM), or None (inconsistent / unknown).
    AES3 byte 0 bit 1 = 0 means audio (PCM); = 1 means non-audio (non-PCM, per S337M § 6.2).
    """
    modes = {(cs[0] & 0x02) == 0x00 for _, cs in blocks}
    if len(modes) == 1:
        return next(iter(modes))
    return None


def check_channel_status_pcm_flag(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """Within each AES3 stereo pair, byte 0 bit 1 shall be consistent (both PCM or both non-PCM).

    Different pairs in a mixed PCM/non-PCM stream are allowed to carry different
    signal types; only the two channels that share a stereo pair (channels 2k and
    2k+1) must agree on the audio/non-audio flag.
    """
    blocks = _collect_channel_status_blocks(ctx)
    if blocks is None:
        return untestable("nchan unresolved or fewer than 192 AES3 frames available")
    pair_mismatches: list[str] = []
    pair_descriptions: list[str] = []
    pairs: dict[int, list[tuple[int, bytes]]] = {}
    for idx, cs in blocks:
        pairs.setdefault(idx // 2, []).append((idx, cs))
    for pair_idx, channels in sorted(pairs.items()):
        pair_modes = {(cs[0] & 0x02) == 0x00 for _, cs in channels}
        if len(pair_modes) > 1:
            ch_str = ", ".join(
                f"ch{i}: byte0=0x{cs[0]:02X} ({'PCM' if (cs[0] & 0x02) == 0 else 'non-PCM'})"
                for i, cs in channels
            )
            pair_mismatches.append(f"pair {pair_idx}: {ch_str}")
        else:
            mode_name = "PCM" if next(iter(pair_modes)) else "non-PCM"
            pair_descriptions.append(f"pair {pair_idx}: {mode_name}")
    if pair_mismatches:
        return False, "AES3 byte 0 bit 1 inconsistent within stereo pair(s): " + "; ".join(pair_mismatches)
    return True, "All AES3 stereo pairs consistently signal PCM/non-PCM: " + ", ".join(pair_descriptions)


def check_channel_status_sample_rate(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """AES3 byte 0 bits 6-7 (frame frequency) must match resolved_sample_rate (applies to both PCM and non-PCM)."""
    if ctx.resolved_sample_rate is None:
        return untestable("sample rate unresolved — cannot cross-check channel-status byte 0 frame-frequency bits")
    blocks = _collect_channel_status_blocks(ctx)
    if blocks is None:
        return untestable("nchan unresolved or fewer than 192 AES3 frames available")
    expected_bits = aes3_sample_rate_byte0_bits(ctx.resolved_sample_rate)
    for index, cs in blocks:
        actual_bits = cs[0] & 0xC0
        if actual_bits != expected_bits:
            return False, (
                f"Sequence {index} channel-status byte 0 bits 6-7 = 0x{actual_bits >> 6:01X} "
                f"(0x{actual_bits:02X}), expected 0x{expected_bits >> 6:01X} "
                f"(0x{expected_bits:02X}) for {ctx.resolved_sample_rate} Hz"
            )
    return True, (
        f"All channel-status byte 0 frame-frequency bits match {ctx.resolved_sample_rate} Hz "
        f"(0x{expected_bits:02X})"
    )


def check_channel_status_pcm_word_length(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """PCM only — AES3 byte 2 bits 3-5 (word length) must match resolved_sample_size."""
    blocks = _collect_channel_status_blocks(ctx)
    if blocks is None:
        return untestable("nchan unresolved or fewer than 192 AES3 frames available")
    is_pcm = _stream_is_pcm(blocks)
    if is_pcm is False:
        return untestable("Stream is non-PCM — word-length byte 2 encoding is not defined for PCM")
    if is_pcm is None:
        return untestable("PCM mode inconsistent across channels")
    if ctx.resolved_sample_size is None:
        return untestable("sample size unresolved — provide --sample-size or ensure SR MIBs are present")
    expected = aes3_word_length_byte2(ctx.resolved_sample_size)
    for index, cs in blocks:
        actual = cs[2] & 0x3F
        if actual != expected:
            return False, (
                f"Sequence {index} channel-status byte 2 = 0x{cs[2]:02X} "
                f"(bits 3-5 word-length field = 0x{(actual >> 3) & 0x7:01X}), "
                f"expected 0x{expected:02X} for {ctx.resolved_sample_size}-bit PCM"
            )
    return True, (
        f"All channel-status byte 2 word-length fields match {ctx.resolved_sample_size}-bit PCM "
        f"(0x{expected:02X})"
    )


def check_channel_status_nonpcm_emphasis(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """Non-PCM (S337M) only — AES3 byte 0 bits 2-4 shall be 000 (emphasis not indicated, per S337M Table 2)."""
    blocks = _collect_channel_status_blocks(ctx)
    if blocks is None:
        return untestable("nchan unresolved or fewer than 192 AES3 frames available")
    is_pcm = _stream_is_pcm(blocks)
    if is_pcm is True:
        return untestable("Stream is PCM — S337M emphasis bits do not apply")
    if is_pcm is None:
        return untestable("PCM mode inconsistent across channels")
    for index, cs in blocks:
        emphasis_bits = (cs[0] >> 2) & 0x07
        if emphasis_bits != 0x00:
            return False, (
                f"Sequence {index} channel-status byte 0 bits 2-4 = 0b{emphasis_bits:03b}, "
                "expected 000 (emphasis not indicated) for non-PCM per S337M Table 2"
            )
    return True, "All non-PCM channel-status byte 0 bits 2-4 = 000 (emphasis not indicated)"


def check_channel_status_nonpcm_channel_mode(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """Non-PCM (S337M) only — AES3 byte 1 bits 0-3 shall be 0000 (channel mode not indicated, per S337M Table 3)."""
    blocks = _collect_channel_status_blocks(ctx)
    if blocks is None:
        return untestable("nchan unresolved or fewer than 192 AES3 frames available")
    is_pcm = _stream_is_pcm(blocks)
    if is_pcm is True:
        return untestable("Stream is PCM — S337M channel-mode restriction does not apply")
    if is_pcm is None:
        return untestable("PCM mode inconsistent across channels")
    for index, cs in blocks:
        mode = cs[1] & 0x0F
        if mode != 0x00:
            return False, (
                f"Sequence {index} channel-status byte 1 bits 0-3 = 0x{mode:X}, "
                "expected 0x0 (not indicated) for non-PCM per S337M Table 3"
            )
    return True, "All non-PCM channel-status byte 1 channel-mode fields = 0x0 (not indicated)"


def check_channel_status_nonpcm_byte2_reserved(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """Non-PCM (S337M) only — AES3 byte 2 bits 6-7 shall be 00 (reserved, per S337M Table 4)."""
    blocks = _collect_channel_status_blocks(ctx)
    if blocks is None:
        return untestable("nchan unresolved or fewer than 192 AES3 frames available")
    is_pcm = _stream_is_pcm(blocks)
    if is_pcm is True:
        return untestable("Stream is PCM — S337M byte 2 reserved bits do not apply")
    if is_pcm is None:
        return untestable("PCM mode inconsistent across channels")
    for index, cs in blocks:
        reserved = (cs[2] >> 6) & 0x03
        if reserved != 0x00:
            return False, (
                f"Sequence {index} channel-status byte 2 bits 6-7 = 0b{reserved:02b}, "
                "expected 00 (reserved) for non-PCM per S337M Table 4"
            )
    return True, "All non-PCM channel-status byte 2 bits 6-7 = 00 (reserved, as required)"


def check_pair_interleave(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.encrypted:
        return untestable("Payload encrypted — AES3 F-bit interleave cannot be verified")
    nchan = ctx.resolved_nchan
    if nchan is None:
        return untestable("nchan unresolved — cannot verify AES3 pair cadence")
    if nchan % 2 != 0:
        return False, f"nchan={nchan} is odd"
    for packet in ctx.am824_report.packets:
        if packet.subframe_count % nchan != 0:
            return False, f"Packet seq={packet.seq} subframe_count={packet.subframe_count} is not divisible by nchan={nchan}"
        for offset in range(0, packet.subframe_count, nchan):
            period = packet.subframes[offset : offset + nchan]
            for pair_index in range(0, len(period), 2):
                left = period[pair_index]
                right = period[pair_index + 1]
                if left.frame_start != 1 or right.frame_start != 0:
                    return False, (
                        f"Packet seq={packet.seq} period offset={offset} pair={pair_index // 2} "
                        f"has F bits {left.frame_start}/{right.frame_start}, expected 1/0"
                    )
    return True, f"AES3 subframes are sequentially interleaved in ordered pairs for nchan={nchan}"


def check_multi_interleave(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    nchan = ctx.resolved_nchan
    if nchan is None:
        return untestable("nchan unresolved — cannot verify multi-signal interleave")
    if nchan % 2 != 0:
        return False, f"nchan={nchan} is odd"
    if nchan == 2:
        return True, "Single AES3 signal stream (nchan=2)"
    periods = _stream_periods(ctx)
    if not periods:
        return False, f"At least one packet payload is incompatible with nchan={nchan}"
    if len(set(periods)) != 1:
        return False, f"Multiple periods-per-packet values observed: {sorted(set(periods))}"
    return True, f"Multiple AES3 signals are carried as ordered 2-subframe groups with {periods[0]} period(s)/packet"


def check_packet_periods(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    periods = _stream_periods(ctx)
    if not periods:
        return untestable("nchan unresolved or payload geometry invalid — cannot verify sample periods per packet")
    unique = sorted(set(periods))
    if len(unique) != 1:
        return False, f"Observed multiple periods-per-packet values: {unique}"
    return True, f"Every packet carries {unique[0]} sample period(s)"


def check_sample_rate_legal(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.resolved_sample_rate is None:
        return untestable("Sample rate unresolved")
    if legal_ptimes_us(ctx.resolved_sample_rate) is None:
        return False, f"Resolved sample rate {ctx.resolved_sample_rate} is not one of 44100, 48000, 96000"
    return True, f"Resolved sample rate {ctx.resolved_sample_rate} Hz is legal for ST 2110-31"


def check_rtp_clock(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
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
    bad = [delta for delta in deltas if delta != expected]
    if bad:
        return False, f"Observed RTP timestamp deltas {sorted(set(bad))} do not match {expected}"
    return True, (
        f"RTP timestamp deltas match sample_rate={ctx.resolved_sample_rate} Hz and "
        f"ptime={format_ptime_us(ctx.resolved_ptime_us)} ({expected} samples/packet)"
    )


def check_sdp_media(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.sdp_media is None:
        return untestable("No SDP provided")
    if ctx.sdp_media.type != MatroxSdpEnums.Audio:
        return False, f"SDP media type is {_enum_string(ctx.sdp_media.type)}, expected audio"
    return True, "SDP media type is audio"


def check_sdp_rtpmap(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.sdp_media is None:
        return untestable("No SDP provided")
    if ctx.sdp_media.encoding_name != MatroxSdpEnums.EncodingAM824:
        return False, f"SDP encoding is {_enum_string(ctx.sdp_media.encoding_name)}, expected AM824"
    if not ctx.sdp_media.sample_rate or not ctx.sdp_media.channels:
        return False, "SDP AM824 rtpmap is missing sample rate or channel count"
    return True, (
        f"SDP rtpmap declares AM824/{ctx.sdp_media.sample_rate}/{ctx.sdp_media.channels}"
    )


def check_sdp_nchan(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.sdp_media is None:
        return untestable("No SDP provided")
    if ctx.sdp_media.channels % 2 != 0:
        return False, f"SDP channels={ctx.sdp_media.channels} is not even"
    return True, f"SDP channels={ctx.sdp_media.channels} is even"


def check_sdp_ptime(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.sdp_media is None:
        return untestable("No SDP provided")
    if not ctx.sdp_media.p_time_us:
        return False, "SDP ptime is missing"
    return True, f"SDP ptime={format_ptime_us(ctx.sdp_media.p_time_us)}"


def check_sdp_ptime_legal(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.sdp_media is None:
        return untestable("No SDP provided")
    valid = _effective_ptime_set(ctx.sdp_media.sample_rate)
    if valid is None:
        return False, f"SDP sample rate {ctx.sdp_media.sample_rate} is invalid"
    if ctx.sdp_media.p_time_us not in valid:
        return False, (
            f"SDP ptime={format_ptime_us(ctx.sdp_media.p_time_us)} is not legal for "
            f"{ctx.sdp_media.sample_rate} Hz"
        )
    return True, f"SDP ptime={format_ptime_us(ctx.sdp_media.p_time_us)} is legal for {ctx.sdp_media.sample_rate} Hz"


def check_sdp_payload_match(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.sdp_media is None:
        return untestable("No SDP provided")
    if len(ctx.am824_report.payload_type_set) != 1:
        return untestable("Observed RTP payload type is not constant")
    observed = next(iter(ctx.am824_report.payload_type_set))
    if ctx.sdp_media.payload_type != observed:
        return False, f"SDP payload type {ctx.sdp_media.payload_type} != RTP payload type {observed}"
    return True, f"SDP payload type {ctx.sdp_media.payload_type} matches RTP"


def check_sdp_channel_order(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.sdp_media is None:
        return untestable("No SDP provided")
    if not ctx.sdp_media.channel_order:
        return untestable("SDP channel-order not present")
    if not ctx.sdp_media.channel_order.startswith("SMPTE2110."):
        return False, f"SDP channel-order '{ctx.sdp_media.channel_order}' does not use SMPTE2110. convention"
    return True, f"SDP channel-order '{ctx.sdp_media.channel_order}' uses SMPTE2110. convention"


def check_sdp_wrapper(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """Comprehensive SDP-side requirement for IPMX AM824 streams.

    Mirrors the per-media-type checklist `TP-10/TP-10-1Sec13.2.py:195-232`
    runs for `audio/am824` (RFC 3551 + ST 2110-10 + ST 2110-31) and adds
    the project-local IPMX checks: the IPMX fmtp keyword (TR-10-1 §10.1)
    and the multicast source-filter signaling (TR-10-9 §17 / RFC 4570).
    First failure wins; on success the message is a one-line summary.
    """
    if ctx.sdp_media is None:
        return untestable("No SDP provided")
    try:
        check_sdp_rfc3551(ctx.sdp_media)
        check_sdp_st2110_10(ctx.sdp_media)
        check_sdp_st2110_31(ctx.sdp_media)
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


def check_cli_payload_type(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.cli_payload_type is None:
        return untestable("No --payload-type provided")
    if len(ctx.am824_report.payload_type_set) != 1:
        return False, f"Observed RTP payload types are not constant: {sorted(ctx.am824_report.payload_type_set)}"
    observed = next(iter(ctx.am824_report.payload_type_set))
    if observed != ctx.cli_payload_type:
        return False, f"CLI payload_type={ctx.cli_payload_type} != RTP payload type {observed}"
    return True, f"CLI payload_type={ctx.cli_payload_type} matches RTP"


def check_cli_ssrc(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.cli_ssrc is None:
        return untestable("No --ssrc provided")
    if len(ctx.am824_report.ssrc_set) != 1:
        return False, f"Observed SSRCs are not constant: {[f'0x{value:08X}' for value in sorted(ctx.am824_report.ssrc_set)]}"
    observed = next(iter(ctx.am824_report.ssrc_set))
    if observed != ctx.cli_ssrc:
        return False, f"CLI ssrc=0x{ctx.cli_ssrc:08X} != RTP SSRC 0x{observed:08X}"
    return True, f"CLI ssrc=0x{ctx.cli_ssrc:08X} matches RTP"


def check_cli_sample_rate(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
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
        mib_values = {int(block["sampling_rate"]) for block in blocks}
        if mib_values != {ctx.cli_sample_rate}:
            return False, f"CLI sample_rate={ctx.cli_sample_rate} != MIB sampling_rate values {sorted(mib_values)}"
        details.append("matches MIB")
        validated = True
    if ctx.resolved_ptime_us is not None:
        expected = resolve_packet_samples_per_packet(
            ctx.cli_sample_rate,
            ctx.resolved_ptime_us,
        )
        if expected is not None:
            deltas = _timestamp_deltas(ctx)
            if deltas and any(delta != expected for delta in deltas):
                return False, (
                    f"CLI sample_rate={ctx.cli_sample_rate} with ptime={format_ptime_us(ctx.resolved_ptime_us)} "
                    f"implies {expected} samples/packet, observed deltas={sorted(set(deltas))}"
                )
            if deltas:
                details.append("matches RTP timing")
                validated = True
    if not validated:
        return untestable("No SDP or RTP timing context available to cross-validate --sample-rate")
    return True, ", ".join(details)


def check_cli_nchan(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.cli_nchan is None:
        return untestable("No --nchan provided")
    if ctx.cli_nchan <= 0 or ctx.cli_nchan % 2 != 0:
        return False, f"CLI nchan={ctx.cli_nchan} is invalid"
    if ctx.sdp_media is not None and ctx.sdp_media.channels != ctx.cli_nchan:
        return False, f"CLI nchan={ctx.cli_nchan} != SDP channels={ctx.sdp_media.channels}"
    blocks = _audio_mib_blocks(ctx)
    if blocks:
        mib_values = {int(block["channel_count"]) for block in blocks}
        if mib_values != {ctx.cli_nchan}:
            return False, f"CLI nchan={ctx.cli_nchan} != MIB channel_count values {sorted(mib_values)}"
    for packet in ctx.am824_report.packets:
        if packet.subframe_count % ctx.cli_nchan != 0:
            return False, f"Packet seq={packet.seq} subframe_count={packet.subframe_count} is not divisible by CLI nchan={ctx.cli_nchan}"
    periods = _stream_periods_for_nchan(ctx.am824_report, ctx.cli_nchan)
    if periods and len(set(periods)) != 1:
        return False, f"CLI nchan={ctx.cli_nchan} yields multiple periods-per-packet values: {sorted(set(periods))}"
    detail = f"CLI nchan={ctx.cli_nchan} matches payload geometry"
    if ctx.sdp_media is not None:
        detail += " and SDP"
    return True, detail


def check_cli_ptime(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.cli_ptime_us is None:
        return untestable("No --ptime provided")
    validated = False
    if ctx.sdp_media is not None and ctx.sdp_media.p_time_us != ctx.cli_ptime_us:
        return False, f"CLI ptime={format_ptime_us(ctx.cli_ptime_us)} != SDP ptime={format_ptime_us(ctx.sdp_media.p_time_us)}"
    if ctx.sdp_media is not None:
        validated = True
    if ctx.resolved_sample_rate is not None:
        expected_nominal = resolve_nominal_packet_time_us(
            ctx.resolved_sample_rate,
            ctx.cli_ptime_us,
        )
        blocks = _audio_mib_blocks(ctx)
        if expected_nominal is not None and blocks:
            mib_values = {int(block["packet_time"]) for block in blocks}
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
    expected = resolve_packet_samples_per_packet(
        ctx.resolved_sample_rate,
        ctx.cli_ptime_us,
    )
    if expected is None:
        return False, (
            f"CLI ptime={format_ptime_us(ctx.cli_ptime_us)} is not supported for "
            f"sample_rate={ctx.resolved_sample_rate}"
        )
    deltas = _timestamp_deltas(ctx)
    if deltas and any(delta != expected for delta in deltas):
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


def check_cli_channel_order(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.cli_channel_order is None:
        return untestable("No --channel-order provided")
    validated = False
    if ctx.sdp_media is not None:
        if ctx.sdp_media.channel_order != ctx.cli_channel_order:
            return False, f"CLI channel-order='{ctx.cli_channel_order}' != SDP channel-order='{ctx.sdp_media.channel_order}'"
        validated = True
    blocks = _audio_mib_blocks(ctx)
    if blocks:
        mib_values = {str(block["channel_order"]) for block in blocks}
        if mib_values != {ctx.cli_channel_order}:
            return False, (
                f"CLI channel-order='{ctx.cli_channel_order}' != MIB channel_order values {sorted(mib_values)}"
            )
        validated = True
    if not validated:
        return untestable("No SDP or MIB available — cannot cross-validate --channel-order")
    return True, f"CLI channel-order='{ctx.cli_channel_order}' matches expected metadata"


def check_cli_port(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.cli_port is None:
        return untestable("No --port provided")
    if ctx.stream_info.dst_port != ctx.cli_port:
        return False, f"CLI port={ctx.cli_port} != selected RTP dst_port={ctx.stream_info.dst_port}"
    return True, f"CLI port={ctx.cli_port} matches selected RTP stream"


def check_cli_dst_ip(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.cli_dst_ip is None:
        return untestable("No --dst-ip provided")
    if ctx.stream_info.dst_ip != ctx.cli_dst_ip:
        return False, f"CLI dst-ip={ctx.cli_dst_ip} != selected RTP dst_ip={ctx.stream_info.dst_ip}"
    return True, f"CLI dst-ip={ctx.cli_dst_ip} matches selected RTP stream"


def check_sr_present(ctx: Am824ValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No RTCP Sender Reports found for the selected stream"
    return True, f"Found {len(ctx.sender_reports)} RTCP Sender Report(s)"


def check_sr_port(ctx: Am824ValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No RTCP Sender Reports found"
    expected = ctx.resolved_rtcp_port or ctx.stream_info.rtcp_port
    bad = [report.dst_port for report in ctx.sender_reports if report.dst_port != expected]
    if bad:
        return False, f"Observed RTCP destination ports {sorted(set(bad))} do not match expected {expected}"
    return True, f"All RTCP sender reports use destination port {expected}"


def check_sr_ip(ctx: Am824ValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No RTCP Sender Reports found"
    expected = ctx.stream_info.dst_ip
    bad = [report.dst_ip for report in ctx.sender_reports if report.dst_ip != expected]
    if bad:
        return False, f"Observed RTCP destination IPs {sorted(set(bad))} do not match RTP dst_ip {expected}"
    return True, f"All RTCP sender reports use destination IP {expected}"


def check_sr_ssrc(ctx: Am824ValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No RTCP Sender Reports found"
    expected_ssrc = ctx.stream_info.ssrc
    bad = [report for report in ctx.sender_reports if report.ssrc != expected_ssrc]
    if bad:
        return False, (
            f"{len(bad)} RTCP SR(s) use SSRC values different from RTP SSRC 0x{expected_ssrc:08X}"
        )
    return True, f"All RTCP SRs use RTP SSRC 0x{expected_ssrc:08X}"


def check_sr_ipmx_info(ctx: Am824ValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No RTCP Sender Reports found"
    missing = [index for index, report in enumerate(ctx.sender_reports) if report.ipmx_info is None]
    if missing:
        return False, f"{len(missing)} RTCP SR(s) do not contain an IPMX Info Block"
    return True, "All RTCP SRs contain an IPMX Info Block"


def check_sr_ipmx_tag(ctx: Am824ValidationContext) -> tuple[bool, str]:
    for index, report in enumerate(ctx.sender_reports):
        if report.ipmx_info is None:
            return False, f"RTCP SR #{index} is missing an IPMX Info Block"
        if report.ipmx_info.tag != 0x5831:
            return False, f"RTCP SR #{index} IPMX tag is 0x{report.ipmx_info.tag:04X}, expected 0x5831"
    return True, "All RTCP SR IPMX tags are 0x5831"


def check_sr_block_version(ctx: Am824ValidationContext) -> tuple[bool, str]:
    versions = {
        report.ipmx_info.version
        for report in ctx.sender_reports
        if report.ipmx_info is not None
    }
    if not versions:
        return False, "No RTCP SR IPMX Info Blocks found"
    if len(versions) != 1:
        return False, f"Observed multiple IPMX Info Block versions: {sorted(versions)}"
    return True, f"Observed stable IPMX Info Block version {next(iter(versions))}"


def check_sr_reserved(ctx: Am824ValidationContext) -> tuple[bool, str]:
    for index, report in enumerate(ctx.sender_reports):
        if report.ipmx_info is None:
            return False, f"RTCP SR #{index} is missing an IPMX Info Block"
        if report.ipmx_info.reserved != 0:
            return False, f"RTCP SR #{index} IPMX reserved field is 0x{report.ipmx_info.reserved:06X}"
    return True, "All RTCP SR IPMX reserved fields are zero"


def check_sr_first(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if not ctx.expect_stream_start:
        return untestable("--expect-stream-start not set")
    associations = _associate_sender_reports(ctx)
    if not associations:
        return False, "No SR/RTP associations found"
    if associations[0][1] != 0:
        return False, f"First associated SR maps to RTP packet index {associations[0][1]}, expected 0"
    return True, "First RTP packet has an associated RTCP Sender Report"


def check_sr_every_n(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
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
    observed = [packet_index for _, packet_index in associations]
    if ctx.expect_stream_start:
        expected = list(range(0, len(ctx.rtp_packets), interval_packets))[: len(observed)]
        if observed != expected:
            return False, f"Observed SR packet indexes {observed[:10]} do not match expected {expected[:10]}"
        return True, f"SRs occur at packet indexes 0, {interval_packets}, 2*{interval_packets}, ..."
    deltas = [cur - prev for prev, cur in zip(observed, observed[1:])]
    if any(delta != interval_packets for delta in deltas):
        return False, f"Observed SR packet-index deltas {sorted(set(deltas))} != expected {interval_packets}"
    return True, f"Successive SR associations are spaced by {interval_packets} RTP packets"


def check_sr_rtp_timestamp_map(ctx: Am824ValidationContext) -> tuple[bool, str]:
    associations = _associate_sender_reports(ctx)
    if not associations:
        return False, "No SR/RTP associations found"
    for report, packet_index in associations:
        if report.rtp_timestamp != ctx.rtp_packets[packet_index].timestamp:
            return False, (
                f"SR rtp_timestamp={report.rtp_timestamp} does not match associated RTP packet timestamp "
                f"{ctx.rtp_packets[packet_index].timestamp}"
            )
    return True, "Each SR RTP timestamp matches its associated RTP packet"


def check_sr_before(ctx: Am824ValidationContext) -> tuple[bool, str]:
    associations = _associate_sender_reports(ctx)
    if not associations:
        return False, "No SR/RTP associations found"
    for report, packet_index in associations:
        packet = ctx.rtp_packets[packet_index]
        if packet.capture_time is None or report.capture_time >= packet.capture_time:
            return False, f"SR for RTP packet index {packet_index} does not arrive before the packet"
    return True, "Each SR arrives before its associated RTP packet"


def check_sr_after_previous(ctx: Am824ValidationContext) -> tuple[bool, str]:
    associations = _associate_sender_reports(ctx)
    if len(associations) < 2:
        return True, "Fewer than two SRs present"
    previous_report, previous_packet_index = associations[0]
    previous_packet = ctx.rtp_packets[previous_packet_index]
    for report, packet_index in associations[1:]:
        packet = ctx.rtp_packets[packet_index]
        if report.capture_time <= previous_report.capture_time:
            return False, "An SR does not arrive after the previous SR"
        if previous_packet.capture_time is None or report.capture_time <= previous_packet.capture_time:
            return False, "An SR does not arrive after the previous associated RTP packet"
        previous_report = report
        previous_packet = packet
    return True, "Each SR arrives after the previous SR and previous associated RTP packet"


def check_sr_order(ctx: Am824ValidationContext) -> tuple[bool, str]:
    associations = _associate_sender_reports(ctx)
    observed = [packet_index for _, packet_index in associations]
    if observed != sorted(observed):
        return False, f"SR associations are out of order: {observed}"
    return True, "SR associations follow RTP packet order"


def check_sr_counts(ctx: Am824ValidationContext) -> tuple[bool, str]:
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
    # mid-stream offsets, given the constant AM824 payload size).
    first_report, first_idx = associations[0]
    pkt_offset = first_report.packet_count - (first_idx + 1)

    payload_size = len(ctx.rtp_packets[0].payload) if ctx.rtp_packets else 0

    for report, packet_index in associations:
        expected_packet_count = packet_index + 1 + pkt_offset
        expected_octet_count = octets_by_packet[packet_index] + pkt_offset * payload_size
        if report.packet_count != expected_packet_count:
            return False, (
                f"SR for packet index {packet_index} reports packet_count={report.packet_count}, "
                f"expected {expected_packet_count}"
            )
        if report.octet_count != expected_octet_count:
            return False, (
                f"SR for packet index {packet_index} reports octet_count={report.octet_count}, "
                f"expected {expected_octet_count}"
            )
    if pkt_offset == 0:
        basis = "1-based, capture from stream start"
    elif pkt_offset == -1:
        basis = "0-based, capture from stream start"
    else:
        basis = f"consistent counter offset {pkt_offset:+d} (capture started mid-stream)"
    return True, f"SR packet_count and octet_count match cumulative RTP payload counters ({basis})"


def check_mib_type(ctx: Am824ValidationContext) -> tuple[bool, str]:
    blocks = _audio_mib_blocks(ctx)
    if not blocks:
        return False, "No AES3 audio MIB type 0x0004 present in RTCP sender reports"
    return True, f"Found {len(blocks)} AES3 audio MIB block(s) of type 0x0004"


def check_mib_count(ctx: Am824ValidationContext) -> tuple[bool, str]:
    if not ctx.sender_reports:
        return False, "No RTCP Sender Reports found"
    for index, report in enumerate(ctx.sender_reports):
        audio_blocks = [block for block in report.raw_blocks if block.media_info_type in {0x0002, 0x0004}]
        if not audio_blocks:
            return False, f"RTCP SR #{index} does not contain any audio MIB"
        if any(block.media_info_type != 0x0004 for block in audio_blocks):
            return False, f"RTCP SR #{index} contains a non-AES3 audio MIB type"
    return True, "All RTCP SR audio MIBs are AES3 type 0x0004"


def check_mib_format(ctx: Am824ValidationContext) -> tuple[bool, str]:
    blocks = _audio_mib_blocks(ctx)
    if not blocks:
        return False, "No AES3 audio MIB present"
    required = {"sampling_rate", "sample_size", "channel_count", "packet_time", "measured_sample_rate", "channel_order"}
    for block in blocks:
        if required - set(block):
            return False, f"AES3 audio MIB is missing fields: {sorted(required - set(block))}"
    return True, "AES3 audio MIBs decode using the PCM-audio layout"


def check_mib_sampling_rate(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.resolved_sample_rate is None:
        return untestable("Sample rate unresolved")
    blocks = _audio_mib_blocks(ctx)
    if not blocks:
        return False, "No AES3 audio MIB present"
    values = {int(block["sampling_rate"]) for block in blocks}
    if values != {ctx.resolved_sample_rate}:
        return False, f"MIB sampling_rate values {sorted(values)} do not match expected {ctx.resolved_sample_rate}"
    return True, f"All MIB sampling_rate values match {ctx.resolved_sample_rate}"


def check_mib_sample_size(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.cli_sample_size is None:
        return untestable("No --sample-size provided")
    blocks = _audio_mib_blocks(ctx)
    if not blocks:
        return False, "No AES3 audio MIB present"
    values = {int(block["sample_size"]) for block in blocks}
    if values != {ctx.cli_sample_size}:
        return False, f"MIB sample_size values {sorted(values)} do not match CLI {ctx.cli_sample_size}"
    return True, f"All MIB sample_size values match CLI {ctx.cli_sample_size}"


def check_mib_channels(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.resolved_nchan is None:
        return untestable("nchan unresolved")
    blocks = _audio_mib_blocks(ctx)
    if not blocks:
        return False, "No AES3 audio MIB present"
    values = {int(block["channel_count"]) for block in blocks}
    if values != {ctx.resolved_nchan}:
        return False, f"MIB channel_count values {sorted(values)} do not match expected {ctx.resolved_nchan}"
    return True, f"All MIB channel_count values match {ctx.resolved_nchan}"


def check_mib_packet_time(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.resolved_sample_rate is None or ctx.resolved_ptime_us is None:
        return untestable("Sample rate or ptime unresolved")
    expected = resolve_nominal_packet_time_us(
        ctx.resolved_sample_rate,
        ctx.resolved_ptime_us,
    )
    if expected is None:
        return untestable("Resolved ptime does not map to a nominal packet-time bucket")
    blocks = _audio_mib_blocks(ctx)
    if not blocks:
        return False, "No AES3 audio MIB present"
    values = {int(block["packet_time"]) for block in blocks}
    if values != {expected}:
        return False, f"MIB packet_time values {sorted(values)} do not match expected {expected}"
    return True, f"All MIB packet_time values match nominal {expected} us"


def check_mib_measured_sample_rate(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    expected = ctx.cli_measured_sample_rate
    if expected is None and ctx.sdp_media is not None and ctx.sdp_media.measured_sample_rate:
        expected = int(ctx.sdp_media.measured_sample_rate)
    if expected is None:
        return untestable("Measured sample rate unresolved")
    blocks = _audio_mib_blocks(ctx)
    if not blocks:
        return False, "No AES3 audio MIB present"
    values = {int(block["measured_sample_rate"]) for block in blocks}
    if values != {expected}:
        return False, f"MIB measured_sample_rate values {sorted(values)} do not match expected {expected}"
    return True, f"All MIB measured_sample_rate values match {expected}"


def check_mib_channel_order(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    expected = ctx.resolved_channel_order
    if expected is None:
        return untestable("Channel-order unresolved")
    blocks = _audio_mib_blocks(ctx)
    if not blocks:
        return False, "No AES3 audio MIB present"
    values = {str(block["channel_order"]) for block in blocks}
    if values != {expected}:
        return False, f"MIB channel_order values {sorted(values)} do not match expected '{expected}'"
    return True, f"All MIB channel_order values match '{expected}'"


def check_sdp_ts_refclk(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.sdp_media is None:
        return untestable("No SDP provided")
    if not ctx.sender_reports or ctx.sender_reports[0].ipmx_info is None:
        return untestable("No SR IPMX Info Block available")
    expected = _sdp_ts_refclk_string(ctx.sdp_media)
    observed = ctx.sender_reports[0].ipmx_info.ts_refclk
    if expected != observed:
        return False, f"SR ts_refclk='{observed}' != SDP ts-refclk='{expected}'"
    return True, "SR ts_refclk matches SDP"


def check_sdp_mediaclk(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.sdp_media is None:
        return untestable("No SDP provided")
    if not ctx.sender_reports or ctx.sender_reports[0].ipmx_info is None:
        return untestable("No SR IPMX Info Block available")
    expected = _sdp_mediaclk_string(ctx.sdp_media)
    observed = ctx.sender_reports[0].ipmx_info.mediaclk
    if expected != observed:
        return False, f"SR mediaclk='{observed}' != SDP mediaclk='{expected}'"
    return True, "SR mediaclk matches SDP"


def check_sdp_measured_sample_rate(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.sdp_media is None:
        return untestable("No SDP provided")
    if not ctx.sdp_media.measured_sample_rate:
        return untestable("SDP measuredsamplerate not present")
    blocks = _audio_mib_blocks(ctx)
    if not blocks:
        return False, "No AES3 audio MIB present"
    values = {int(block["measured_sample_rate"]) for block in blocks}
    expected = int(ctx.sdp_media.measured_sample_rate)
    if values != {expected}:
        return False, f"MIB measured_sample_rate values {sorted(values)} do not match SDP {expected}"
    return True, f"MIB measured_sample_rate matches SDP {expected}"


def check_cli_rtcp_port(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.cli_rtcp_port is None:
        return untestable("No --rtcp-port provided")
    if ctx.resolved_rtcp_port != ctx.cli_rtcp_port:
        return False, f"CLI rtcp-port={ctx.cli_rtcp_port} != selected RTCP port {ctx.resolved_rtcp_port}"
    return True, f"CLI rtcp-port={ctx.cli_rtcp_port} matches selected RTCP stream"


def check_cli_sample_size(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    return check_mib_sample_size(ctx)


def check_cli_measured_sample_rate(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    if ctx.cli_measured_sample_rate is None:
        return untestable("No --measured-sample-rate provided")
    blocks = _audio_mib_blocks(ctx)
    if not blocks:
        return False, "No AES3 audio MIB present"
    values = {int(block["measured_sample_rate"]) for block in blocks}
    if values != {ctx.cli_measured_sample_rate}:
        return False, (
            f"MIB measured_sample_rate values {sorted(values)} do not match CLI {ctx.cli_measured_sample_rate}"
        )
    if ctx.sdp_media is not None and ctx.sdp_media.measured_sample_rate:
        if int(ctx.sdp_media.measured_sample_rate) != ctx.cli_measured_sample_rate:
            return False, (
                f"CLI measured-sample-rate={ctx.cli_measured_sample_rate} != "
                f"SDP measuredsamplerate={ctx.sdp_media.measured_sample_rate}"
            )
    return True, f"CLI measured-sample-rate={ctx.cli_measured_sample_rate} matches MIB"


def check_sequence_continuity(ctx: Am824ValidationContext) -> tuple[bool, str]:
    analysis = ctx.am824_report.sequence_analysis
    if analysis.total_missing or analysis.total_duplicates:
        return False, analysis.summary()
    return True, analysis.summary()


def check_capture_interval_stability(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    # AES67 §7.5 SHOULD: variation from nominal transmission time ≤ 1 packet time
    if len(ctx.rtp_packets) < 3:
        return untestable("Not enough packets to assess capture interval stability")
    if ctx.resolved_ptime_us is None:
        return untestable("ptime unresolved — cannot assess capture interval stability")
    times = [packet.capture_time for packet in ctx.rtp_packets if packet.capture_time is not None]
    if len(times) < 3:
        return untestable("Capture timestamps unavailable")
    expected = ctx.resolved_ptime_us / 1_000_000.0
    deltas = [cur - prev for prev, cur in zip(times, times[1:])]
    max_error = max(abs(delta - expected) for delta in deltas)
    if max_error > expected:
        return False, f"Capture interval variation {max_error*1000:.3f} ms exceeds AES67 §7.5 SHOULD ≤ 1·ptime ({expected*1000:.3f} ms)"
    return True, f"Capture intervals stable within AES67 §7.5 SHOULD ≤ 1·ptime ({expected*1000:.3f} ms)"


def check_capture_interval_aes67_shall(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    # AES67 §7.5 SHALL: variation from nominal transmission time ≤ min(17·ptime, 17 ms)
    if len(ctx.rtp_packets) < 3:
        return untestable("Not enough packets to assess capture interval stability")
    if ctx.resolved_ptime_us is None:
        return untestable("ptime unresolved — cannot assess capture interval stability")
    times = [packet.capture_time for packet in ctx.rtp_packets if packet.capture_time is not None]
    if len(times) < 3:
        return untestable("Capture timestamps unavailable")
    expected = ctx.resolved_ptime_us / 1_000_000.0
    shall = min(17 * expected, 0.017)
    deltas = [cur - prev for prev, cur in zip(times, times[1:])]
    max_error = max(abs(delta - expected) for delta in deltas)
    if max_error > shall:
        return False, f"Capture interval variation {max_error*1000:.3f} ms exceeds AES67 §7.5 SHALL ≤ min(17·ptime, 17 ms) ({shall*1000:.3f} ms)"
    return True, f"Capture intervals within AES67 §7.5 SHALL ≤ min(17·ptime, 17 ms) ({shall*1000:.3f} ms)"


# ---------------------------------------------------------------------------
# S337M (non-PCM) content checks — Level 1 structural + Level 2 consistency
# ---------------------------------------------------------------------------

def _require_s337m(ctx: Am824ValidationContext) -> list[S337mScanResult] | tuple[bool, str, bool]:
    """Return the S337M scan results or an untestable 3-tuple."""
    if ctx.s337m_scan_results is None:
        return untestable("Stream is PCM, nchan is unresolved, or S337M scan was not performed")
    return ctx.s337m_scan_results


def check_s337m_sync_words(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """S337M §7.1 — Pa/Pb sync words shall be found in all non-PCM AES3 signals."""
    r = _require_s337m(ctx)
    if not isinstance(r, list):
        return r
    issues: list[str] = []
    found_counts: list[str] = []
    for result in r:
        if result.all_validity_zero:
            issues.append(f"Signal {result.signal_index}: all validity bits = 0 (no non-PCM subframes)")
            continue
        if not result.bursts and not result.parse_errors:
            issues.append(f"Signal {result.signal_index}: no S337M Pa/Pb sync words found")
        elif result.parse_errors:
            issues.append(
                f"Signal {result.signal_index}: {len(result.parse_errors)} parse error(s): "
                + result.parse_errors[0]
            )
        else:
            found_counts.append(f"signal {result.signal_index}: {len(result.bursts)} burst(s)")
    if issues:
        return False, "; ".join(issues)
    return True, "S337M Pa/Pb sync words found — " + ", ".join(found_counts)


def check_s337m_data_mode(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """S337M §7.1.3.2 — data_mode shall be 0, 1, or 2 (value 3 is reserved);
    Pc data_mode field shall match the mode detected from Pa/Pb."""
    r = _require_s337m(ctx)
    if not isinstance(r, list):
        return r
    issues: list[str] = []
    for result in r:
        for burst in result.bursts:
            if burst.data_mode not in (0, 1, 2):
                issues.append(
                    f"Signal {result.signal_index} frame {burst.frame_offset}: "
                    f"data_mode={burst.data_mode} (reserved)"
                )
            if burst.pc_data_mode_field != burst.data_mode:
                issues.append(
                    f"Signal {result.signal_index} frame {burst.frame_offset}: "
                    f"Pc data_mode_field={burst.pc_data_mode_field} "
                    f"does not match Pa/Pb detected mode {burst.data_mode}"
                )
    if issues:
        return False, "; ".join(issues)
    modes = {burst.data_mode for result in r for burst in result.bursts}
    if not modes:
        return untestable("No S337M bursts parsed — cannot verify data_mode")
    names = {0: "16-bit", 1: "20-bit", 2: "24-bit"}
    return True, "All burst data_mode values are valid: " + ", ".join(
        f"mode {m} ({names[m]})" for m in sorted(modes)
    )


def check_s337m_error_flag(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """S337M §7.1.3.3 — error_flag shall be 0 (payload not known to contain errors)."""
    r = _require_s337m(ctx)
    if not isinstance(r, list):
        return r
    flagged: list[str] = []
    for result in r:
        for burst in result.bursts:
            if burst.error_flag:
                flagged.append(
                    f"signal {result.signal_index} frame {burst.frame_offset} "
                    f"data_type=0x{burst.data_type:02X}"
                )
    if flagged:
        return False, f"error_flag set in {len(flagged)} burst(s): " + "; ".join(flagged[:5])
    total = sum(len(result.bursts) for result in r)
    if total == 0:
        return untestable("No S337M bursts parsed — cannot verify error_flag")
    return True, f"error_flag = 0 in all {total} burst(s)"


def check_s337m_length_code(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """S337M §7.1.4 — Pd length_code shall be consistent with the actual burst_payload length."""
    r = _require_s337m(ctx)
    if not isinstance(r, list):
        return r
    inconsistent: list[str] = []
    for result in r:
        for burst in result.bursts:
            if not burst.length_code_consistent:
                inconsistent.append(
                    f"signal {result.signal_index} frame {burst.frame_offset}: "
                    f"length_code={burst.length_code} bits declares "
                    f"{burst.payload_frames_declared} frame(s) but "
                    f"{burst.payload_frames_actual} frame(s) follow"
                )
    if inconsistent:
        return False, "; ".join(inconsistent)
    total = sum(len(result.bursts) for result in r)
    if total == 0:
        return untestable("No S337M bursts parsed — cannot verify length_code")
    return True, f"All {total} burst(s) have consistent length_code values"


def check_s337m_burst_spacing(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """S337M §7.3 — There shall not be a gap of 4096 or more AES3 frames between burst starts."""
    r = _require_s337m(ctx)
    if not isinstance(r, list):
        return r
    violations: list[str] = []
    for result in r:
        if result.max_inter_burst_gap_frames >= S337M_MAX_BURST_GAP_FRAMES:
            violations.append(
                f"signal {result.signal_index}: "
                f"max gap = {result.max_inter_burst_gap_frames} frames "
                f"(limit {S337M_MAX_BURST_GAP_FRAMES})"
            )
    if violations:
        return False, "S337M burst spacing limit exceeded: " + "; ".join(violations)
    gaps = [r.max_inter_burst_gap_frames for r in r if r.bursts]
    if not gaps:
        return untestable("No S337M bursts parsed — cannot verify burst spacing")
    return True, (
        f"All burst gaps within limit — max = {max(gaps)} frames "
        f"(limit {S337M_MAX_BURST_GAP_FRAMES})"
    )


def check_s337m_data_type_stable(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """S337M §7.1.3.1 — data_type shall be consistent across all bursts in the stream.

    A changing data_type mid-stream would indicate an unexpected codec switch.
    This is the S337M equivalent of checking that the video codec does not
    change between parameter sets.
    """
    r = _require_s337m(ctx)
    if not isinstance(r, list):
        return r
    all_types = {burst.data_type for result in r for burst in result.bursts}
    if not all_types:
        return untestable("No S337M bursts parsed — cannot verify data_type stability")
    if len(all_types) > 1:
        return False, (
            f"data_type is not stable — {len(all_types)} different values found: "
            + ", ".join(f"0x{t:02X}" for t in sorted(all_types))
        )
    data_type = next(iter(all_types))
    total = sum(len(result.bursts) for result in r)
    return True, f"data_type = 0x{data_type:02X} consistently across all {total} burst(s)"


def check_s337m_stream_zero(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """S337M §8.2 — At least one data stream with data_stream_number = 0 shall be present.

    Consumer devices may not receive streams with data_stream_number > 0.
    """
    r = _require_s337m(ctx)
    if not isinstance(r, list):
        return r
    all_bursts = [burst for result in r for burst in result.bursts]
    if not all_bursts:
        return untestable("No S337M bursts parsed — cannot verify data_stream_number")
    has_zero = any(burst.data_stream_number == 0 for burst in all_bursts)
    if not has_zero:
        stream_numbers = sorted({burst.data_stream_number for burst in all_bursts})
        return False, (
            "No burst with data_stream_number = 0 found "
            f"(values present: {stream_numbers})"
        )
    return True, "At least one burst carries data_stream_number = 0"


def check_s337m_datamode_vs_chstatus(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """S337M §6.2 — AES3 channel-status byte 2 word-length field shall reflect
    the highest data_mode in use across all bursts.

    Cross-validates the S337M burst Pc data_mode against the AES3 channel-status
    word (which was already verified to be present and CRC-valid). This is the
    S337M equivalent of checking that SPS profile/level matches SDP fmtp.
    """
    r = _require_s337m(ctx)
    if not isinstance(r, list):
        return r
    all_bursts = [burst for result in r for burst in result.bursts]
    if not all_bursts:
        return untestable("No S337M bursts parsed — cannot cross-check channel-status byte 2")
    max_data_mode = max(burst.data_mode for burst in all_bursts)
    sample_size = S337M_DATA_MODE_TO_SAMPLE_SIZE[max_data_mode]
    expected_byte2 = aes3_word_length_byte2(sample_size)

    blocks = _collect_channel_status_blocks(ctx)
    if blocks is None:
        return untestable("Channel-status blocks not available for cross-check")
    for seq_idx, cs in blocks:
        actual_byte2 = cs[2] & 0x3F
        if actual_byte2 != expected_byte2:
            return False, (
                f"Sequence {seq_idx} channel-status byte 2 = 0x{cs[2]:02X} "
                f"(word-length field = 0x{(actual_byte2 >> 3) & 0x7:01X}), "
                f"expected 0x{expected_byte2:02X} for highest S337M data_mode={max_data_mode} "
                f"({sample_size}-bit per S337M §6.2)"
            )
    return True, (
        f"Channel-status byte 2 = 0x{expected_byte2:02X} matches "
        f"highest S337M data_mode={max_data_mode} ({sample_size}-bit)"
    )


def check_s337m_datamode_vs_mib(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """TR-10-12 §10 — MIB sample_size shall match the highest S337M data_mode in use.

    The AES3 audio MIB (type 0x0004) encodes sample_size as 16, 20, or 24 to
    reflect the S337M data word length (data_mode 0, 1, 2). This cross-validates
    the MIB-reported value against the actual data_mode found in the burst stream,
    mirroring how video MIB fields are checked against bitstream parameters.
    """
    r = _require_s337m(ctx)
    if not isinstance(r, list):
        return r
    all_bursts = [burst for result in r for burst in result.bursts]
    if not all_bursts:
        return untestable("No S337M bursts parsed — cannot cross-check MIB sample_size")
    if ctx.resolved_sample_size is None:
        return untestable(
            "MIB sample_size not available — provide --sample-size or ensure SR MIBs are present"
        )
    max_data_mode = max(burst.data_mode for burst in all_bursts)
    expected_sample_size = S337M_DATA_MODE_TO_SAMPLE_SIZE[max_data_mode]
    if ctx.resolved_sample_size != expected_sample_size:
        return False, (
            f"MIB sample_size={ctx.resolved_sample_size} does not match "
            f"highest S337M data_mode={max_data_mode} "
            f"(expected sample_size={expected_sample_size})"
        )
    return True, (
        f"MIB sample_size={ctx.resolved_sample_size} matches "
        f"S337M data_mode={max_data_mode}"
    )


def check_cli_s337m_data_type(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """CLI --s337m-data-type shall match the data_type detected in S337M bursts when provided.

    Allows the operator to assert the expected SMPTE 338 data_type (e.g. 0x01
    for AC-3, 0x15 for E-AC-3, 0x07 for AAC). Analogous to how video validators
    accept --codec or codec-specific CLI parameters for cross-validation.
    """
    if ctx.cli_s337m_data_type is None:
        return untestable("No --s337m-data-type provided")
    r = _require_s337m(ctx)
    if not isinstance(r, list):
        return r
    all_bursts = [burst for result in r for burst in result.bursts]
    if not all_bursts:
        return untestable("No S337M bursts parsed — cannot verify --s337m-data-type")
    detected = {burst.data_type for burst in all_bursts}
    if detected != {ctx.cli_s337m_data_type}:
        return False, (
            f"CLI --s337m-data-type=0x{ctx.cli_s337m_data_type:02X} "
            f"does not match detected data_type(s): "
            + ", ".join(f"0x{t:02X}" for t in sorted(detected))
        )
    return True, f"S337M data_type = 0x{ctx.cli_s337m_data_type:02X} matches --s337m-data-type"


def check_sdp_dst_ip_vs_stream_am824(ctx: Am824ValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    from ipmx_validate_common import check_sdp_dst_ip_vs_stream as _check
    return _check(ctx.sdp_media, ctx.stream_info)


def build_requirements() -> list[Requirement]:
    reqs: list[Requirement] = []

    def add(req_id: str, level: str, text: str, fn: Any) -> None:
        reqs.append(Requirement(req_id=req_id, level=level, text=text, check=fn))

    add("ST2110-31-5.2-ENCAP", "shall", "Selected packets shall be RTP packets carrying parseable AM824 payloads", check_encapsulation)
    add("ST2110-31-5.3-PT", "shall", "RTP payload type shall be constant within the stream", check_payload_type_constant)
    add("ST2110-31-5.3-SSRC", "shall", "RTP SSRC shall be constant within the stream", check_ssrc_constant)
    add("ST2110-31-5.3-CC", "shall", "RTP CSRC count shall be 0", check_csrc_zero)
    add("ST2110-31-5.3-M", "shall", "RTP marker bit shall be 0", check_marker_zero)
    add("ST2110-31-5.3-TS", "shall", "RTP timestamp step shall match the packet sample-period count", check_timestamp_step)
    add("ST2110-31-5.3-X", "shall", "RTP extension/header state shall be structurally consistent", check_extension_state)
    add("ST2110-31-5.4-AM824-WORD", "shall", "RTP payload shall be composed of 32-bit AM824 subframes", check_word_alignment)
    add("ST2110-31-5.4-RESERVED", "shall", "Reserved bits in AM824 words shall be zero", check_reserved_bits)
    add("ST2110-31-5.4-BF", "shall", "AM824 B/F indicators shall be structurally legal", check_bf_legality)
    add("AES3-4.1.1-P", "shall", "AES3 parity bits shall satisfy even parity", check_parity_bit)
    add("AES3-7.2.2-CHSTATUS", "shall", "AES3 standard implementation over IP shall only use channel-status bytes 0, 1, 2, and 23", check_channel_status_standard_impl)
    add("AES3-7.2.2-CRCC", "shall", "AES3 standard implementation over IP shall carry a valid channel-status CRCC in byte 23", check_channel_status_crc)
    add("AES3-RESTRICT-MODE", "shall", "AES3 channel mode shall be unspecified, two-channel, or stereophonic", check_channel_status_modes)
    add("AES3-S337-PCMFLAG", "shall", "AES3 channel-status byte 0 bit 1 (non-audio flag) shall be consistent across all channels", check_channel_status_pcm_flag)
    add("AES3-7.2.2-CHSTATUS-SR", "shall", "AES3 channel-status byte 0 bits 6-7 (frame frequency) shall match the resolved sample rate", check_channel_status_sample_rate)
    add("AES3-7.2.2-WORDLEN", "shall", "PCM: AES3 channel-status byte 2 word-length field shall match the resolved sample size", check_channel_status_pcm_word_length)
    add("S337-6.2-EMPHASIS", "shall", "Non-PCM: AES3 channel-status byte 0 bits 2-4 shall be 000 (emphasis not indicated)", check_channel_status_nonpcm_emphasis)
    add("S337-6.2-CHMODE", "shall", "Non-PCM: AES3 channel-status byte 1 bits 0-3 shall be 0000 (channel mode not indicated)", check_channel_status_nonpcm_channel_mode)
    add("S337-6.2-BYTE2-RESERVED", "shall", "Non-PCM: AES3 channel-status byte 2 bits 6-7 shall be 00 (reserved)", check_channel_status_nonpcm_byte2_reserved)
    # S337M data burst structural integrity (Level 1)
    add("S337-7.1-SYNC", "shall", "Non-PCM: S337M Pa/Pb sync words shall be found in all AES3 signals", check_s337m_sync_words)
    add("S337-7.1-DATAMODE", "shall", "Non-PCM: S337M data_mode shall be 0, 1, or 2 and Pc data_mode field shall match Pa/Pb", check_s337m_data_mode)
    add("S337-7.1-ERRFLAG", "shall", "Non-PCM: S337M error_flag shall be 0 in all bursts", check_s337m_error_flag)
    add("S337-7.1-LENCODE", "shall", "Non-PCM: S337M Pd length_code shall be consistent with the actual burst_payload length", check_s337m_length_code)
    add("S337-7.3-SPACING", "shall", "Non-PCM: S337M burst gap shall not reach 4096 AES3 frames", check_s337m_burst_spacing)
    # S337M codec-agnostic consistency and cross-validation (Level 2)
    add("S337-7.1-DTYPE-STABLE", "shall", "Non-PCM: S337M data_type shall be stable across all bursts", check_s337m_data_type_stable)
    add("S337-8.2-STREAM0", "shall", "Non-PCM: At least one S337M burst shall carry data_stream_number = 0", check_s337m_stream_zero)
    add("S337-6.2-DATAMODE-CS", "should", "Non-PCM: AES3 channel-status byte 2 word-length should reflect the highest S337M data_mode", check_s337m_datamode_vs_chstatus)
    add("S337-6.2-DATAMODE-MIB", "should", "Non-PCM: MIB sample_size should match the highest S337M data_mode in the burst stream", check_s337m_datamode_vs_mib)
    add("AM824-CLI-S337M-DTYPE", "shall", "CLI --s337m-data-type shall match the S337M data_type detected in the burst stream when provided", check_cli_s337m_data_type)
    add("ST2110-31-5.4-INTERLEAVE", "shall", "AES3 subframes 1 and 2 shall be sequentially interleaved", check_pair_interleave)
    add("ST2110-31-5.4-MULTI", "shall", "Multiple AES3 signals shall be sequentially interleaved", check_multi_interleave)
    add("ST2110-31-5.4-PERIODS", "shall", "Each packet shall carry a whole and constant number of sample periods", check_packet_periods)
    add("ST2110-31-5.5-RATE", "shall", "Resolved sample rate shall be legal for ST 2110-31", check_sample_rate_legal)
    add("ST2110-31-5.5-RTPCLOCK", "shall", "RTP clock shall match sample-rate and ptime relationship", check_rtp_clock)
    add("ST2110-31-6.1-MEDIA", "shall", "SDP media type shall be audio", check_sdp_media)
    add("ST2110-31-6.1-RTPMAP", "shall", "SDP rtpmap shall declare AM824/<rate>/<nchan>", check_sdp_rtpmap)
    add("ST2110-31-6.1-NCHAN", "shall", "SDP nchan shall be even", check_sdp_nchan)
    add("ST2110-31-6.1-PTIME", "shall", "SDP ptime shall be present", check_sdp_ptime)
    add("ST2110-31-6.1-PTIME-LEGAL", "shall", "SDP ptime shall be legal for the SDP sample rate", check_sdp_ptime_legal)
    add("ST2110-31-6.1-PT-MATCH", "shall", "SDP payload type shall match the RTP stream", check_sdp_payload_match)
    add("ST2110-31-6.2-CHORDER", "shall", "SDP channel-order shall follow the ST 2110 convention when present", check_sdp_channel_order)
    add("IPMX-SDP-WRAPPER", "shall",
        "SDP shall satisfy RFC 3551 + ST 2110-10 + ST 2110-31 + IPMX fmtp + "
        "TR-10-9 §17 source-filter (multicast)",
        check_sdp_wrapper)
    add("SDP-DST-IP", "shall",
        "SDP connection address SHALL match the detected destination IP.",
        check_sdp_dst_ip_vs_stream_am824)
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
    add("TR-10-12-10-MIBTYPE", "shall", "AES3 transparent transport shall use MIB type 0x0004", check_mib_type)
    add("TR-10-12-10-MIBCOUNT", "shall", "Generated audio sender reports shall carry AES3 audio MIBs", check_mib_count)
    add("TR-10-12-10-MIBFMT", "shall", "AES3 audio MIBs shall decode using the PCM-audio layout", check_mib_format)
    add("TR-10-12-10-SAMPLERATE", "shall", "AES3 audio MIB sampling rate shall match the expected sample rate", check_mib_sampling_rate)
    add("TR-10-12-10-SAMPLESIZE", "shall", "AES3 audio MIB sample size shall match the expected sample size", check_mib_sample_size)
    add("TR-10-12-10-CHANNELS", "shall", "AES3 audio MIB channel count shall match nchan", check_mib_channels)
    add("TR-10-12-10-PACKETTIME", "shall", "AES3 audio MIB packet_time shall match the nominal packet time", check_mib_packet_time)
    add("TR-10-12-10-MEASURED", "shall", "AES3 audio MIB measured sample rate shall match the expected value", check_mib_measured_sample_rate)
    add("TR-10-12-10-CHORDER", "shall", "AES3 audio MIB channel_order shall match the expected value", check_mib_channel_order)
    add("TR-10-1-8.7-TSREFCLK", "shall", "SR ts-refclk shall match SDP", check_sdp_ts_refclk)
    add("TR-10-1-8.7-MEDIACLK", "shall", "SR mediaclk shall match SDP", check_sdp_mediaclk)
    add("TR-10-1-8.6-INIT-RTP", "shall",
        "First SR RTP timestamp shall be synchronized with the Internal Clock (TR-10-1 §8.6).",
        lambda c: check_sr_initial_rtp_clock(c.sender_reports, c.resolved_sample_rate or 48000))
    add("TR-10-1-8.7-RC", "should",
        "RTCP SR reception report count (RC) should be 0 (TR-10-1 §8.7).",
        lambda c: check_sr_rc_zero(c.sender_reports))
    add("TR-10-1-10.1-IPMX-FMTP", "shall",
        "SDP a=fmtp line shall contain the IPMX keyword (TR-10-1 §10.1).",
        lambda c: check_sdp_ipmx_fmtp(c.sdp_media))
    add("TR-10-1-10.3-MEASUREDSAMPLERATE", "shall", "MIB measured sample rate shall match SDP measuredsamplerate", check_sdp_measured_sample_rate)
    add("AM824-CLI-PT", "shall", "CLI --payload-type shall match the RTP stream when provided", check_cli_payload_type)
    add("AM824-CLI-SSRC", "shall", "CLI --ssrc shall match the RTP stream when provided", check_cli_ssrc)
    add("AM824-CLI-SAMPLE-RATE", "shall", "CLI --sample-rate shall match SDP and RTP timing when provided", check_cli_sample_rate)
    add("AM824-CLI-NCHAN", "shall", "CLI --nchan shall match SDP and payload geometry when provided", check_cli_nchan)
    add("AM824-CLI-PTIME", "shall", "CLI --ptime shall match SDP and RTP timing when provided", check_cli_ptime)
    add("AM824-CLI-CHORDER", "shall", "CLI --channel-order shall match SDP when provided", check_cli_channel_order)
    add("AM824-CLI-PORT", "shall", "CLI --port shall match the selected RTP stream when provided", check_cli_port)
    add("AM824-CLI-RTCP-PORT", "shall", "CLI --rtcp-port shall match the selected RTCP stream when provided", check_cli_rtcp_port)
    add("AM824-CLI-DST-IP", "shall", "CLI --dst-ip shall match the selected RTP stream when provided", check_cli_dst_ip)
    add("AM824-CLI-SAMPLESIZE", "shall", "CLI --sample-size shall match the SR audio MIB when provided", check_cli_sample_size)
    add("AM824-CLI-MEASURED-SR", "shall", "CLI --measured-sample-rate shall match the SR audio MIB when provided", check_cli_measured_sample_rate)
    add("RTP-SEQ", "should", "RTP sequence numbers should be contiguous", check_sequence_continuity)
    add("RTP-CAPTURE-PTIME", "should",
        "AES67 §7.5 SHOULD: sender variation from nominal transmission time should be ≤ 1 packet time",
        check_capture_interval_stability)
    add("AES67-7.5-PTIME-SHALL", "shall",
        "AES67 §7.5: sender variation from nominal transmission time shall be ≤ min(17·ptime, 17 ms)",
        check_capture_interval_aes67_shall)
    return reqs


def run_requirements(ctx: Am824ValidationContext, requirements: list[Requirement]) -> list[RequirementResult]:
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
    testable = [result for result in results if result.testable]
    if len(testable) == len(results):
        return summarize_results(results)
    passed = sum(1 for result in testable if result.passed)
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
        for result in results:
            if result.testable and pass_report and result.passed:
                filtered.append(result)
            elif result.testable and fail_report and not result.passed:
                filtered.append(result)
            elif (not result.testable) and cannot_report:
                filtered.append(result)
        return filtered
    return [result for result in results if result.testable and not result.passed]


def print_results(
    results: list[RequirementResult],
    *,
    full_report: bool,
    pass_report: bool,
    fail_report: bool,
    cannot_report: bool,
) -> None:
    all_shall = [result for result in results if result.level == "shall"]
    all_should = [result for result in results if result.level == "should"]
    filtered = _filter_results(
        results,
        full_report=full_report,
        pass_report=pass_report,
        fail_report=fail_report,
        cannot_report=cannot_report,
    )
    display_shall = [result for result in filtered if result.level == "shall"]
    display_should = [result for result in filtered if result.level == "should"]

    print("SHALL requirements")
    print(_summarize_for_output(all_shall))
    for result in display_shall:
        status = "PASS" if result.passed else ("CANNOT_TEST" if not result.testable else "FAIL")
        print(f"{status} {result.req_id}: {result.text}")
        print(f"DETAILS: {result.details}")

    print("\nSHOULD requirements")
    print(_summarize_for_output(all_should))
    for result in display_should:
        status = "PASS" if result.passed else ("CANNOT_TEST" if not result.testable else "FAIL")
        print(f"{status} {result.req_id}: {result.text}")
        print(f"DETAILS: {result.details}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, help="PCAP file containing AM824 RTP")
    parser.add_argument("--port", type=int, help="RTP destination port (auto-detected if omitted)")
    parser.add_argument("--ssrc", type=lambda value: int(value, 0), help="Expected SSRC (decimal or 0x hex)")
    parser.add_argument("--dst-ip", dest="dst_ip", help="Expected destination IP address")
    parser.add_argument("--payload-type", type=int, help="Expected RTP payload type")
    parser.add_argument("--sdp", type=Path, help="SDP transport file for cross-validation")
    parser.add_argument("--sample-rate", type=int, help="Expected AM824 sample rate in Hz")
    parser.add_argument("--nchan", type=int, help="Expected AM824 nchan value")
    parser.add_argument("--ptime", type=parse_ptime_arg, help="Expected packet time in milliseconds (e.g. 1, 0.33, 0.12)")
    parser.add_argument("--channel-order", type=str, help="Expected SDP channel-order value")
    parser.add_argument("--rtcp-port", type=int, help="Expected RTCP destination port")
    parser.add_argument("--sample-size", type=int, help="Expected SR audio MIB sample size")
    parser.add_argument("--measured-sample-rate", type=int, help="Expected SR audio MIB measured sample rate")
    parser.add_argument(
        "--s337m-data-type",
        type=lambda v: int(v, 0),
        dest="s337m_data_type",
        metavar="TYPE",
        help="Expected S337M data_type value (SMPTE 338 codec ID, e.g. 0x01=AC-3, 0x15=E-AC-3, 0x07=AAC)",
    )
    parser.add_argument("--expect-stream-start", action="store_true", help="Require the first RTP packet in the selected capture to have an associated SR")
    parser.add_argument("--hkep", action="store_true", help="Assert that HDCP encryption (HKEP) is active")
    parser.add_argument("--pep",  action="store_true", help="Assert that Privacy Encryption Protocol (PEP) is active")
    parser.add_argument("--full-report", action="store_true", help="Include all requirements (pass, fail, cannot test)")
    parser.add_argument("--pass-report", action="store_true", help="Show only passing requirements")
    parser.add_argument("--fail-report", action="store_true", help="Show only failing requirements")
    parser.add_argument("--cannot-test-report", action="store_true", help="Show only requirements that cannot be tested")
    args = parser.parse_args()

    ctx = build_context(args)

    if ctx.encrypted:
        print("[INFO] Encryption detected — AM824 payload content is not accessible.")
        print("       Subframe bit-field, channel-status, and S337M checks will be marked as untestable.\n")

    results = run_requirements(ctx, build_requirements())

    # Encryption cross-validation (RTP extensions, RTCP MIBs, SDP)
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

    shall_failures = [result for result in results if result.level == "shall" and result.testable and not result.passed]
    return 1 if shall_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
