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

"""
IPMX USB (TR-10-14) Dissector / Validator for PCAP files.

Parses TCP streams containing IPMX USB messages, identifies control and
data channels, and validates all normative SHALL / SHOULD requirements from
VSF TR-10-14 (2024-09-24).

Usage:
    python3 usbDissector.py <pcap_file> [options]

See --help for all options.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

# Decoded payloads can carry non-ASCII bytes (e.g. a vendor busid string that
# isn't cleanly null-padded). Make stdout/stderr tolerant so such content never
# raises UnicodeEncodeError on a legacy Windows code page. This must run before
# scapy is imported, since scapy pulls in colorama which wraps stdout with the
# strict console encoding.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(errors="backslashreplace")

try:
    from scapy.all import rdpcap, TCP, IP, Raw
    from scapy.utils import PcapReader
except ImportError:
    print("Error: scapy is required.  Install with: pip install scapy")
    sys.exit(1)

import ipmx_pep as pepmod
import ipmx_usb_message as usb
import usb_decode
from ipmx_usb_message import IpmxUsbMessage, MsgType, StatusCode, _VALID_STATUS_CODES
from tcp_reassembler import TcpConnection, make_stream_key, find_contiguous_blocks


# ---------------------------------------------------------------------------
# Validation result helpers
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    ERROR   = "ERROR"    # SHALL violation
    WARNING = "WARNING"  # SHOULD violation
    INFO    = "INFO"


@dataclass
class Finding:
    severity: Severity
    section: str          # e.g. "8.3.1.1"
    description: str
    packet_number: Optional[int] = None
    detail: Optional[str] = None

    def __str__(self) -> str:
        pkt = f" [pkt #{self.packet_number}]" if self.packet_number else ""
        detail = f"\n    Detail: {self.detail}" if self.detail else ""
        return f"  [{self.severity.value}] §{self.section}{pkt}: {self.description}{detail}"


# ---------------------------------------------------------------------------
# Per-channel message record
# ---------------------------------------------------------------------------

@dataclass
class ChannelMessage:
    """One parsed IPMX USB message with its capture context."""
    packet_number: int
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    msg: IpmxUsbMessage
    mac_ok: Optional[bool] = None  # None = not checked, True/False = CMAC result


# ---------------------------------------------------------------------------
# Session and channel models
# ---------------------------------------------------------------------------

@dataclass
class DataChannel:
    """Tracks state for one data channel (one USB device)."""
    substreamid: int
    busid: str
    usbspeed: int
    stream_info_pkt: Optional[int] = None     # packet where USBStreamInfo was seen
    stream_status_pkt: Optional[int] = None   # packet where USBStreamStatus was seen
    stream_status_ok: bool = False
    messages: list[ChannelMessage] = field(default_factory=list)
    # per-direction SEQNUM trackers: {seqnum: packet_number}
    submit_seqnums: dict[int, dict] = field(default_factory=dict)  # seqnum → submit info


@dataclass
class ControlChannel:
    """Tracks state for the control channel."""
    messages: list[ChannelMessage] = field(default_factory=list)
    sender_info: Optional[dict] = None        # payload of SenderConnectionInfo
    receiver_status: Optional[dict] = None    # payload of SenderConnectionStatus
    heartbeat_times: list[float] = field(default_factory=list)
    connection_info_pkt: Optional[int] = None
    connection_status_pkt: Optional[int] = None
    # Vendor query tracking: vqtype → list of (pkt_num, answered)
    pending_vendor_queries: dict[int, list[int]] = field(default_factory=dict)


@dataclass
class Session:
    """One complete Sender ↔ Receiver session (may span a reconnect)."""
    sender_ip: str
    sender_port: int
    receiver_ip: str
    receiver_data_port: int = 0
    control: ControlChannel = field(default_factory=ControlChannel)
    data_channels: dict[int, DataChannel] = field(default_factory=dict)  # substreamid → channel
    findings: list[Finding] = field(default_factory=list)

    def add(self, severity: Severity, section: str, description: str,
            packet_number: int = None, detail: str = None) -> None:
        self.findings.append(Finding(severity, section, description, packet_number, detail))


# ---------------------------------------------------------------------------
# PCAP loader and stream collector
# ---------------------------------------------------------------------------

def _load_packets(pcap_file: str) -> list:
    """Load all packets from a PCAP file."""
    try:
        return list(PcapReader(pcap_file))
    except Exception as exc:
        print(f"Error reading {pcap_file}: {exc}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Framing diagnostics
#
# Stream bytes that cannot be framed used to be dropped without a word, which let
# a partially-parsed capture look complete and turned missing messages into bogus
# "never sent" conclusions. Channel identification re-parses the same blocks
# several times, so entries are keyed by block content and overwritten rather
# than accumulated.
# ---------------------------------------------------------------------------

_UNFRAMED: dict[tuple, dict] = {}
_FRAMED_PORTS: set[int] = set()


def _reset_framing_stats() -> None:
    _UNFRAMED.clear()
    _FRAMED_PORTS.clear()


def _block_ports(block) -> tuple[int, int]:
    """TCP ports of the connection a block belongs to, or (0, 0) if unknown."""
    if not block.packets:
        return (0, 0)
    meta = block.packets[0]
    try:
        return (int(meta[3]), int(meta[5]))
    except (TypeError, ValueError, IndexError):
        return (0, 0)


def _note_framed(block) -> None:
    """Remember that this connection really does carry IPMX USB messages."""
    _FRAMED_PORTS.update(p for p in _block_ports(block) if p)


def _record_unframed(block, nbytes: int, kind: str) -> None:
    """Record *nbytes* of stream data that could not be framed as USB messages."""
    if nbytes <= 0:
        return
    key = (hash(block.data), len(block.data), kind)
    _UNFRAMED[key] = {'bytes': nbytes, 'kind': kind, 'ports': _block_ports(block)}


def _framing_report() -> Optional[str]:
    """
    Summarise stream data that could not be framed, or None when there is none.

    Only connections demonstrably carrying IPMX USB are reported — ones that
    yielded messages elsewhere, plus any block that needed resynchronising. This
    dissector walks every TCP stream in the capture, so counting unrelated HTTP,
    TLS or HKEP traffic as "unframed USB" would bury the real signal in noise.
    The Session sender port is deliberately not used to widen this: it is
    auto-detected and can land on a busy non-USB port such as HKEP's 5051.
    """
    relevant = [v for v in _UNFRAMED.values()
                if v['kind'] == 'resync' or any(p in _FRAMED_PORTS for p in v['ports'])]
    if not relevant:
        return None

    total   = sum(v['bytes'] for v in relevant)
    resyncs = sum(1 for v in relevant if v['kind'] == 'resync')
    tails   = sum(1 for v in relevant if v['kind'] == 'tail')
    lost    = sum(1 for v in relevant if v['kind'] == 'unframed')

    lines = [f"[!] WARNING: this capture was not fully parsed - {total} byte(s) of IPMX USB "
             f"stream data could not be framed as messages"]
    if resyncs:
        lines.append(f"  {resyncs} block(s) did not start on a message boundary, so framing was "
                     f"resynchronised (capture likely started mid-stream)")
        lines.append(f"    Resynchronised framing is best-effort: it locates a boundary that is "
                     f"consistent with the rest of the stream, which is strong evidence but not "
                     f"proof. Treat messages from those blocks with corresponding caution.")
    if tails:
        lines.append(f"  {tails} block(s) ended in a message truncated by the end of the capture")
    if lost:
        lines.append(f"  {lost} block(s) could not be framed at all")
    lines.append("  Messages contained in those bytes are absent from the analysis below, so "
                 "'not sent' conclusions may reflect the gap rather than the device.")
    return "\n".join(lines)


def _collect_streams(packets: list) -> dict[str, TcpConnection]:
    """
    First pass: collect all TCP payload packets into per-connection buffers.
    Returns dict of stream_key → TcpConnection.

    All TCP streams with payload data are collected; channel-type
    classification is done later by message content inspection.
    """
    connections: dict[str, TcpConnection] = {}

    for pkt_num, pkt in enumerate(packets, 1):
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            continue
        tcp = pkt[TCP]
        ip = pkt[IP]

        # Real TCP payload length from the IP total-length field. Short frames
        # (e.g. bare ACK/SYN, 54 bytes) are zero-padded to Ethernet's 60-byte
        # minimum, and scapy surfaces that padding as trailing TCP-payload
        # bytes. Using bytes(tcp.payload) directly would inject phantom bytes
        # into the reassembled stream — corrupting sequence tracking and
        # dropping legitimate messages (e.g. a Receiver's SenderConnectionStatus
        # whose header lands right after a padded ACK). Bound by ip.len, which
        # accounts for IP/TCP options. When ip.len is 0 (e.g. TCP segmentation
        # offload), fall back to the raw payload bytes.
        raw = bytes(tcp.payload)
        if ip.len:
            seg_len = ip.len - (ip.ihl * 4) - (tcp.dataofs * 4)
            if seg_len >= 0:
                raw = raw[:seg_len]
        if not raw:
            continue
        payload = raw

        src_ip   = ip.src
        dst_ip   = ip.dst
        src_port = tcp.sport
        dst_port = tcp.dport

        key = make_stream_key(src_ip, src_port, dst_ip, dst_port)
        if key not in connections:
            connections[key] = TcpConnection()

        conn = connections[key]
        ts = float(pkt.time) if hasattr(pkt, 'time') else 0.0
        meta = (pkt_num, ts, src_ip, src_port, dst_ip, dst_port)

        # TcpConnection.forward = lower(ip,port) → higher(ip,port)
        if (src_ip, src_port) < (dst_ip, dst_port):
            conn.feed_forward(tcp.seq, payload, meta)
        else:
            conn.feed_reverse(tcp.seq, payload, meta)

    return connections


def _parse_messages_from_connection(
    conn: TcpConnection,
    verbose: bool,
    pep_key_fwd: Optional[bytes] = None,
    pep_key_rev: Optional[bytes] = None,
    pep_params: Optional[pepmod.PepParams] = None,
    iv_forward: Optional[int] = None,
    iv_reverse: Optional[int] = None,
    iv_mode_fwd: pepmod.IvMode = pepmod.IvMode.SPEC,
    iv_mode_rev: pepmod.IvMode = pepmod.IvMode.SPEC,
    handshake_iv_fwd: Optional[int] = None,
    handshake_iv_rev: Optional[int] = None,
    force_plaintext: bool = False,
) -> tuple[list[ChannelMessage], list[ChannelMessage]]:
    """
    Reassemble and parse IPMX USB messages from both directions of a connection.
    Returns (forward_messages, reverse_messages).

    Each TCP direction may have its own privacy key (per TR-10-13 dynamic
    key versioning: Sender and Receiver each have their own KEYVERSION).
    *pep_key_fwd* / *pep_key_rev* are used for the TCP forward/reverse
    directions respectively.
    """

    mac_fail_logged = False

    def _try_decrypt(raw_bytes: bytes, key: bytes, iv_prime: int,
                     parsed_enc: IpmxUsbMessage,
                     iv_mode: pepmod.IvMode = pepmod.IvMode.SPEC,
                     ) -> tuple[IpmxUsbMessage, Optional[bool]]:
        """Decrypt *raw_bytes* and return (msg, mac_ok).

        When MAC verification fails the original *parsed_enc* message
        is returned untouched (payload stays encrypted) so downstream
        validation never sees garbled data.
        """
        nonlocal mac_fail_logged
        dec_bytes, mac_ok = pepmod.decrypt_usb_message(
            raw_bytes, key, iv_prime, pep_params.mode,  # type: ignore[arg-type]
            iv_mode=iv_mode)
        if not mac_ok:
            if verbose and not mac_fail_logged:
                print("    ⚠ CMAC verification FAILED — cannot decrypt "
                      "(wrong PSK or key derivation mismatch)")
                mac_fail_logged = True
            return parsed_enc, False
        plain_raw = b"\x00" * 12 + dec_bytes[12:]
        parsed = usb.parse_one(plain_raw, 0)
        parsed.ctr = int.from_bytes(raw_bytes[:8], "big")
        parsed.key_version = int.from_bytes(raw_bytes[8:12], "big")
        return parsed, mac_ok

    def _parse_direction(blocks_fn, direction_label,
                         dir_key: Optional[bytes], iv_prime: Optional[int],
                         dir_iv_mode: pepmod.IvMode = pepmod.IvMode.SPEC,
                         handshake_iv: Optional[int] = None):
        msgs: list[ChannelMessage] = []
        first_encrypted_seen = False
        for block in blocks_fn():
            offset = 0

            # Establish a trustworthy starting point before framing anything. A
            # block that does not begin on a message boundary (capture started
            # mid-stream) used to be abandoned silently at the first bad header,
            # discarding every message in it.
            if not usb.block_starts_on_boundary(block.data):
                start = usb.next_sync_offset(block.data, 1)
                if start is None:
                    # No trustworthy boundary anywhere. Recorded rather than
                    # discarded outright, but only reported if the connection
                    # turns out to be IPMX USB — this dissector walks every TCP
                    # stream in the capture, so most such blocks are simply other
                    # traffic and warning about them would be noise.
                    _record_unframed(block, len(block.data), 'unframed')
                    continue
                _record_unframed(block, start, 'resync')
                offset = start

            while True:
                length = usb.peek_length(block.data, offset)
                if length is None or offset + length > len(block.data):
                    # Trailing message cut short by the end of the capture.
                    if offset < len(block.data):
                        _record_unframed(block, len(block.data) - offset, 'tail')
                    break
                try:
                    parsed = usb.parse_one(block.data, offset,
                                           force_plaintext=force_plaintext)
                except ValueError as exc:
                    if verbose:
                        print(f"    Parse error at offset {offset}: {exc}")
                    # The boundary is trusted because the chain validated, so skip
                    # this message rather than sliding a byte and losing framing.
                    offset += length
                    continue

                mac_ok: Optional[bool] = None

                if parsed.is_encrypted and dir_key and pep_params and iv_prime is not None:
                    raw_msg = block.data[offset:offset + length]
                    effective_iv = iv_prime
                    if not first_encrypted_seen and handshake_iv is not None:
                        effective_iv = handshake_iv
                    try:
                        parsed, mac_ok = _try_decrypt(
                            raw_msg, dir_key, effective_iv, parsed,
                            iv_mode=dir_iv_mode)
                        if mac_ok is not False:
                            first_encrypted_seen = True
                    except Exception as exc:
                        if verbose:
                            print(f"    Decrypt error at offset {offset}: {exc}")

                # This connection demonstrably carries IPMX USB, so unframed
                # bytes found on it are a real gap rather than unrelated traffic.
                _note_framed(block)

                meta = block.meta_at(offset)
                if meta is not None:
                    pkt_num, ts, src_ip, src_port, dst_ip, dst_port = meta
                else:
                    pkt_num, ts, src_ip, src_port, dst_ip, dst_port = 0, 0.0, '', 0, '', 0

                msgs.append(ChannelMessage(
                    packet_number=pkt_num,
                    timestamp=ts,
                    src_ip=src_ip, src_port=src_port,
                    dst_ip=dst_ip, dst_port=dst_port,
                    msg=parsed,
                    mac_ok=mac_ok,
                ))
                offset += length
        return msgs

    forward = _parse_direction(conn.forward_blocks, 'forward',
                               pep_key_fwd, iv_forward, iv_mode_fwd,
                               handshake_iv=handshake_iv_fwd)
    reverse = _parse_direction(conn.reverse_blocks, 'reverse',
                               pep_key_rev, iv_reverse, iv_mode_rev,
                               handshake_iv=handshake_iv_rev)
    return forward, reverse


# ---------------------------------------------------------------------------
# Channel identification
# ---------------------------------------------------------------------------

def _identify_channels(
    connections: dict[str, TcpConnection],
    verbose: bool,
    pep_key: Optional[bytes] = None,
    pep_params: Optional[pepmod.PepParams] = None,
    iv_mode_s2r: pepmod.IvMode = pepmod.IvMode.SPEC,
    iv_mode_r2s: pepmod.IvMode = pepmod.IvMode.SPEC,
    force_plaintext: bool = False,
) -> tuple[dict[str, tuple[str, list[ChannelMessage], list[ChannelMessage]]],
           dict[str, tuple[int, int, bool]]]:
    """
    For each connection parse messages and label it as 'control' or 'data'.

    Control channel: Receiver connects TO Sender (Sender is server on sender_port).
    Data channel:    Sender connects TO Receiver (Sender is client, connects to
                     PORT from SenderConnectionStatus).

    When *pep_key* / *pep_params* are provided, a two-pass approach is used:
    first classify channels (MSGTYPE is always in the clear), then re-parse
    with decryption using the correct substreamid for iv' computation.

    Per TR-10-13 dynamic key versioning, the Sender and Receiver may each
    have their own KEYVERSION (and thus different derived privacy keys).
    The dissector derives per-direction keys from the KEYVERSION found in
    each direction's encrypted messages.

    Returns dict: stream_key → (channel_type, sender_to_receiver_msgs, receiver_to_sender_msgs)

    channel_type is 'control', 'data', or 'unknown'.
    """
    # Pass 1: classify channels, determine TCP direction mapping.
    # MSGTYPE is always in the clear, so we can identify channel type and
    # which TCP direction corresponds to Sender-to-Receiver (S2R).
    classified: dict[str, tuple[str, TcpConnection, bool]] = {}
    for key, conn in connections.items():
        fwd_msgs, rev_msgs = _parse_messages_from_connection(
            conn, verbose, force_plaintext=force_plaintext)
        all_msgs = sorted(fwd_msgs + rev_msgs, key=lambda m: m.packet_number)
        if not all_msgs:
            continue

        first_mt = all_msgs[0].msg.msg_type_enum
        # SenderConnectionInfo and USBStreamInfo come from the Sender (S2R).
        # Determine if the S2R direction is "forward" or "reverse" in TCP.
        first_is_fwd = bool(fwd_msgs and fwd_msgs[0].packet_number == all_msgs[0].packet_number)
        if first_mt == MsgType.SENDER_CONNECTION_INFO:
            classified[key] = ('control', conn, first_is_fwd)
        elif first_mt == MsgType.USB_STREAM_INFO:
            classified[key] = ('data', conn, first_is_fwd)
        else:
            classified[key] = ('unknown', conn, first_is_fwd)

    def _extract_kv_from_direction(blocks_fn) -> int:
        """Return the first non-zero KEYVERSION found in the given TCP direction."""
        for block in blocks_fn():
            offset = 0
            while True:
                length = usb.peek_length(block.data, offset)
                if length is None or offset + length > len(block.data):
                    break
                kv = int.from_bytes(block.data[offset + 8: offset + 12], "big")
                if kv != 0:
                    return kv
                offset += length
        return 0

    def _derive_direction_keys(
        conn: TcpConnection, s2r_is_forward: bool,
    ) -> tuple[Optional[bytes], Optional[bytes]]:
        """Derive per-direction privacy keys for a connection.

        For non-KV protocols both directions share *pep_key*.
        For _KV protocols, each direction's key is derived from
        that direction's in-message KEYVERSION.

        Returns (key_s2r, key_r2s).
        """
        if not pep_key or not pep_params:
            return None, None

        if not pep_params.is_kv:
            return pep_key, pep_key

        s2r_blocks = conn.forward_blocks if s2r_is_forward else conn.reverse_blocks
        r2s_blocks = conn.reverse_blocks if s2r_is_forward else conn.forward_blocks

        kv_s2r = _extract_kv_from_direction(s2r_blocks)
        kv_r2s = _extract_kv_from_direction(r2s_blocks)

        key_s2r = pep_params.derive_key_for_version(kv_s2r) if kv_s2r else pep_key
        key_r2s = pep_params.derive_key_for_version(kv_r2s) if kv_r2s else pep_key

        if verbose:
            sdp_kv = int.from_bytes(pep_params.key_version, 'big')
            if kv_s2r and kv_s2r != sdp_kv:
                print(f"  S2R KEYVERSION=0x{kv_s2r:08X} (SDP had 0x{sdp_kv:08X}), "
                      "re-derived S2R key")
            if kv_r2s and kv_r2s != sdp_kv:
                print(f"  R2S KEYVERSION=0x{kv_r2s:08X} (SDP had 0x{sdp_kv:08X}), "
                      "re-derived R2S key")

        return key_s2r, key_r2s

    def _find_substreamid_and_direction(
        conn: TcpConnection, s2r_is_forward: bool,
        key_s2r: Optional[bytes],
    ) -> tuple[int, int, bool]:
        """Determine the handshake and payload substreamids for a data channel.

        Returns ``(handshake_ssid, payload_ssid, spec_compliant)`` where:
        - *handshake_ssid* is the SSID used to encrypt the first USB_STREAM_INFO
        - *payload_ssid* is the SUBSTREAMID from inside the USB_STREAM_INFO payload
        - *spec_compliant* is True when the handshake used the spec SSID (2)

        Tries SSID 2 first (spec-required handshake SSID).  Falls back to
        brute-force 0-254 if CMAC fails with SSID 2.
        """
        fwd, rev = _parse_messages_from_connection(
            conn, verbose=False, force_plaintext=force_plaintext)
        for m in sorted(fwd + rev, key=lambda x: x.packet_number):
            if m.msg.msg_type_enum == MsgType.USB_STREAM_INFO:
                if not m.msg.is_encrypted:
                    ssid = m.msg.payload.get('substreamid', 0)
                    return (ssid, ssid, True)
                break

        if not key_s2r or not pep_params:
            return (0, 0, True)

        s2r_blocks = conn.forward_blocks if s2r_is_forward else conn.reverse_blocks
        first_raw: Optional[bytes] = None
        for block in s2r_blocks():
            length = usb.peek_length(block.data, 0)
            if length and length <= len(block.data):
                raw = block.data[:length]
                kv = int.from_bytes(raw[8:12], "big")
                if kv != 0 and raw[12] == MsgType.USB_STREAM_INFO.value:
                    first_raw = raw
                    break

        if first_raw is None:
            return (0, 0, True)

        def _try_ssid(candidate: int) -> Optional[int]:
            """Try to decrypt with *candidate* SSID; return payload_ssid or None."""
            iv_prime = pepmod.compute_iv_prime(pep_params.iv, candidate, iv_mode_s2r)
            try:
                dec, mac_ok = pepmod.decrypt_usb_message(
                    first_raw, key_s2r, iv_prime, pep_params.mode,
                    iv_mode=iv_mode_s2r)
                if mac_ok:
                    plain = b"\x00" * 12 + dec[12:]
                    parsed = usb.parse_one(plain, 0)
                    return parsed.payload.get('substreamid', candidate)
            except Exception:
                pass
            return None

        # Try spec-required handshake SSID first
        payload = _try_ssid(2)
        if payload is not None:
            return (2, payload, True)

        # Fallback: brute-force
        for candidate in range(0, 256, 2):
            payload = _try_ssid(candidate)
            if payload is not None:
                return (candidate, payload, False)

        return (0, 0, True)

    # Pass 2: re-parse with decryption using per-direction keys and iv'.
    # Track handshake-SSID compliance findings for data channels.
    ssid_findings: dict[str, tuple[int, int, bool]] = {}
    result: dict[str, tuple[str, list, list]] = {}
    for key, (ctype, conn, s2r_is_fwd) in classified.items():
        iv_fwd: Optional[int] = None
        iv_rev: Optional[int] = None
        key_fwd: Optional[bytes] = None
        key_rev: Optional[bytes] = None
        ivm_fwd: pepmod.IvMode = iv_mode_s2r
        ivm_rev: pepmod.IvMode = iv_mode_r2s
        hs_iv_fwd: Optional[int] = None
        hs_iv_rev: Optional[int] = None

        if pep_key and pep_params:
            key_s2r, key_r2s = _derive_direction_keys(conn, s2r_is_fwd)

            handshake_ssid = 0
            payload_ssid = 0
            ssid_compliant = True
            if ctype == 'data':
                handshake_ssid, payload_ssid, ssid_compliant = \
                    _find_substreamid_and_direction(conn, s2r_is_fwd, key_s2r)
                ssid_findings[key] = (handshake_ssid, payload_ssid, ssid_compliant)

            substreamid = payload_ssid if ctype == 'data' else 0
            iv_s2r = pepmod.compute_iv_prime(pep_params.iv, substreamid, iv_mode_s2r)
            iv_r2s = pepmod.compute_iv_prime(pep_params.iv, substreamid | 1, iv_mode_r2s)

            # Handshake IVs when handshake SSID differs from payload SSID
            if ctype == 'data' and handshake_ssid != payload_ssid:
                hs_iv_s2r = pepmod.compute_iv_prime(
                    pep_params.iv, handshake_ssid, iv_mode_s2r)
                hs_iv_r2s = pepmod.compute_iv_prime(
                    pep_params.iv, handshake_ssid | 1, iv_mode_r2s)
                hs_iv_fwd = hs_iv_s2r if s2r_is_fwd else hs_iv_r2s
                hs_iv_rev = hs_iv_r2s if s2r_is_fwd else hs_iv_s2r

            iv_fwd = iv_s2r if s2r_is_fwd else iv_r2s
            iv_rev = iv_r2s if s2r_is_fwd else iv_s2r
            key_fwd = key_s2r if s2r_is_fwd else key_r2s
            key_rev = key_r2s if s2r_is_fwd else key_s2r
            ivm_fwd = iv_mode_s2r if s2r_is_fwd else iv_mode_r2s
            ivm_rev = iv_mode_r2s if s2r_is_fwd else iv_mode_s2r

        fwd_msgs, rev_msgs = _parse_messages_from_connection(
            conn, verbose,
            pep_key_fwd=key_fwd, pep_key_rev=key_rev,
            pep_params=pep_params,
            iv_forward=iv_fwd, iv_reverse=iv_rev,
            iv_mode_fwd=ivm_fwd, iv_mode_rev=ivm_rev,
            handshake_iv_fwd=hs_iv_fwd, handshake_iv_rev=hs_iv_rev,
            force_plaintext=force_plaintext)

        all_msgs = sorted(fwd_msgs + rev_msgs, key=lambda m: m.packet_number)
        if not all_msgs:
            continue

        if ctype in ('control', 'data'):
            sender_msgs = fwd_msgs if s2r_is_fwd else rev_msgs
            receiver_msgs = rev_msgs if s2r_is_fwd else fwd_msgs
        else:
            sender_msgs = fwd_msgs
            receiver_msgs = rev_msgs

        result[key] = (ctype, sender_msgs, receiver_msgs)

    return result, ssid_findings


# ---------------------------------------------------------------------------
# Heartbeat period calculator
# ---------------------------------------------------------------------------

def _heartbeat_period(hbeat: int) -> float:
    """Section 11: Heartbeat_Period = 5 × 1.25^HBEAT seconds."""
    return 5.0 * (1.25 ** hbeat)


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def _check_reserved_header_bits(
    session: Session, cm: ChannelMessage
) -> None:
    """§9 Table 1: Reserved 7 bits in header SHALL be 0 before transmission."""
    raw = cm.msg.raw
    if not raw or len(raw) < 14:
        return
    b13 = raw[13]
    # Bytes 13-15 encode Reserved(7 bits) || LENGTH(17 bits).
    # Reserved occupies bits 23:17 of the 24-bit word, i.e. bits 7:1 of byte 13.
    reserved_bits = (b13 >> 1) & 0x7F
    if reserved_bits != 0:
        session.add(Severity.ERROR, "9",
                    f"{cm.msg.msg_type_name}: Reserved header bits are 0x{reserved_bits:02X}; "
                    "SHALL be 0",
                    packet_number=cm.packet_number)


def _check_endpoint_rsvd_bits(
    session: Session, cm: ChannelMessage, role: str
) -> None:
    """§9.14/9.18 Table 10-14: Rsvd 3 bits in endpoint byte SHALL be 0."""
    p = cm.msg.payload
    if not p:
        return
    raw = cm.msg.raw
    if not raw or len(raw) < 17 + 4:
        return
    # Endpoint byte is at DATA offset 3 (absolute offset 16+3=19).
    ep_byte = raw[16 + 3]
    rsvd = (ep_byte >> 1) & 0x07   # bits 3:1
    if rsvd != 0:
        section = "9.14" if role == "submit" else "9.18"
        session.add(Severity.ERROR, section,
                    f"{cm.msg.msg_type_name}: Reserved bits in endpoint byte are 0x{rsvd:X}; "
                    "SHALL be 0",
                    packet_number=cm.packet_number)


def _validate_control_channel(
    session: Session,
    sender_msgs: list[ChannelMessage],
    receiver_msgs: list[ChannelMessage],
    expected_cid: Optional[bytes],
    expected_sn: Optional[str],
    encrypted: bool,
    decrypted: bool = False,
) -> None:
    s = session
    ctrl = session.control

    all_msgs = sorted(sender_msgs + receiver_msgs, key=lambda m: (m.packet_number, m.timestamp))
    ctrl.messages = all_msgs

    # ------------------------------------------------------------------ §9
    # Header Reserved bits — check every message
    for cm in all_msgs:
        _check_reserved_header_bits(s, cm)

    # ------------------------------------------------------------------ §9 SHOULD
    # Messages SHOULD be encrypted and authenticated (TR-10-13).
    # Issue a WARNING if the stream appears unencrypted and --encrypted was not set.
    if not encrypted:
        s.add(Severity.WARNING, "9",
              "Stream is not encrypted; messages SHOULD be encrypted and authenticated (TR-10-13)")

    # ------------------------------------------------------------------ §12 MAC verification
    if decrypted:
        for cm in all_msgs:
            if cm.mac_ok is False:
                s.add(Severity.ERROR, "12",
                      f"{cm.msg.msg_type_name}: CMAC-64 verification failed",
                      packet_number=cm.packet_number)

    # ------------------------------------------------------------------ 8.3.1.1
    # SHALL: first message on control channel from Sender is SenderConnectionInfo.
    if not sender_msgs:
        s.add(Severity.ERROR, "8.3.1.1",
              "No messages from Sender on control channel")
        return

    first_sender = sender_msgs[0]
    if first_sender.msg.msg_type_enum != MsgType.SENDER_CONNECTION_INFO:
        s.add(Severity.ERROR, "8.3.1.1",
              f"First Sender message is {first_sender.msg.msg_type_name}; "
              "expected SenderConnectionInfo",
              packet_number=first_sender.packet_number)

    # Store SenderConnectionInfo payload for later checks
    sci = next((m for m in sender_msgs
                if m.msg.msg_type_enum == MsgType.SENDER_CONNECTION_INFO), None)
    if sci:
        ctrl.sender_info = sci.msg.payload
        ctrl.connection_info_pkt = sci.packet_number

    # ------------------------------------------------------------------ §9.1 Table 2
    # Skip field-level checks when encrypted (DATA is ciphertext).
    if sci and ctrl.sender_info and (not encrypted or decrypted) and not ctrl.sender_info.get('_encrypted'):
        info = ctrl.sender_info
        # SHALL: MAVER = 0 for this version
        if info.get('maver', -1) != 0:
            s.add(Severity.ERROR, "9.1",
                  f"SenderConnectionInfo MAVER={info['maver']}; SHALL be 0",
                  packet_number=sci.packet_number)
        # SHALL: MIVER = 0 for this version
        if info.get('miver', -1) != 0:
            s.add(Severity.ERROR, "9.1",
                  f"SenderConnectionInfo MIVER={info['miver']}; SHALL be 0",
                  packet_number=sci.packet_number)
        # SHALL: Reserved byte (byte 1 of DATA) SHALL be 0
        raw_data = sci.msg.data
        if len(raw_data) >= 2 and raw_data[1] != 0:
            s.add(Severity.ERROR, "9.1",
                  f"SenderConnectionInfo Reserved byte=0x{raw_data[1]:02X}; SHALL be 0",
                  packet_number=sci.packet_number)
        # CID match
        if expected_cid is not None:
            actual_cid = bytes.fromhex(info.get('cid', ''))
            if actual_cid != expected_cid:
                s.add(Severity.ERROR, "9.1",
                      f"SenderConnectionInfo CID={info.get('cid')} does not match "
                      f"expected {expected_cid.hex().upper()}",
                      packet_number=sci.packet_number)
        # SN match
        if expected_sn is not None:
            actual_sn = info.get('sn', '')
            if actual_sn != expected_sn:
                s.add(Severity.ERROR, "9.1",
                      f"SenderConnectionInfo SN='{actual_sn}' does not match "
                      f"expected '{expected_sn}'",
                      packet_number=sci.packet_number)

    # ------------------------------------------------------------------ 8.3.1.1
    # SHALL: on reception of SenderConnectionInfo Receiver SHALL send SenderConnectionStatus
    scs = next((m for m in receiver_msgs
                if m.msg.msg_type_enum == MsgType.SENDER_CONNECTION_STATUS), None)
    if sci and not scs:
        s.add(Severity.ERROR, "8.3.1.1",
              "Receiver did not send SenderConnectionStatus after SenderConnectionInfo",
              packet_number=sci.packet_number)

    if scs:
        ctrl.receiver_status = scs.msg.payload
        ctrl.connection_status_pkt = scs.packet_number

    # ------------------------------------------------------------------ §9.2 Table 3
    # Skip field-level checks when encrypted.
    if scs and ctrl.receiver_status and ctrl.sender_info and (not encrypted or decrypted) and not ctrl.receiver_status.get('_encrypted'):
        sts = ctrl.receiver_status
        sender_ver = (ctrl.sender_info.get('maver', 0) << 4) | ctrl.sender_info.get('miver', 0)
        receiver_ver = (sts.get('maver', 0) << 4) | sts.get('miver', 0)
        # SHALL: Receiver version ≤ Sender version
        if receiver_ver > sender_ver:
            s.add(Severity.ERROR, "9.2",
                  f"SenderConnectionStatus version ({sts.get('maver')}.{sts.get('miver')}) "
                  f"exceeds Sender version ({ctrl.sender_info.get('maver')}.{ctrl.sender_info.get('miver')})",
                  packet_number=scs.packet_number)
        # SHALL: HBEAT in [5, 30]
        hbeat = sts.get('hbeat', -1)
        if not (5 <= hbeat <= 30):
            s.add(Severity.ERROR, "9.2",
                  f"HBEAT={hbeat} out of valid range [5, 30]",
                  packet_number=scs.packet_number)
        # SHALL: Rsvd 3 bits in byte 1 of SenderConnectionStatus DATA SHALL be 0
        raw_scs_data = scs.msg.data
        if len(raw_scs_data) >= 2:
            rsvd3 = (raw_scs_data[1] >> 5) & 0x07   # bits 7:5 of byte 1
            if rsvd3 != 0:
                s.add(Severity.ERROR, "9.2",
                      f"SenderConnectionStatus Rsvd bits=0x{rsvd3:X}; SHALL be 0",
                      packet_number=scs.packet_number)
        # Record receiver data port
        session.receiver_data_port = sts.get('port', 0)

    # ------------------------------------------------------------------ §9.4 — VendorSpecificInfo
    # Skip payload field checks when encrypted (DATA is ciphertext).
    vsinfo_msgs = [m for m in sender_msgs
                   if m.msg.msg_type_enum == MsgType.VENDOR_SPECIFIC_INFO
                   and not m.msg.payload.get('_encrypted')]
    for cm in vsinfo_msgs:
        p = cm.msg.payload
        vmtype = p.get('vmtype', -1)
        # SHALL: VMTYPE 1-15 are reserved
        if 1 <= vmtype <= 15:
            s.add(Severity.ERROR, "9.4",
                  f"VendorSpecificInfo VMTYPE={vmtype} is reserved (1-15); SHALL NOT be used",
                  packet_number=cm.packet_number)
        # SHALL: VMTYPE=0 VMDATA SHALL be ≤ 256 bytes
        if vmtype == 0:
            vmdata = p.get('vmdata_str', '') or p.get('vmdata', '')
            vmdata_len = len(vmdata.encode('utf-8')) if isinstance(vmdata, str) else len(vmdata)
            if vmdata_len > 256:
                s.add(Severity.ERROR, "9.4",
                      f"VendorSpecificInfo VMTYPE=0 VMDATA={vmdata_len} bytes; SHALL be ≤ 256",
                      packet_number=cm.packet_number)

    # ------------------------------------------------------------------ §9.6 — VendorSpecificQuery/Return
    # Skip payload checks for encrypted messages.
    queries = [m for m in sender_msgs
               if m.msg.msg_type_enum == MsgType.VENDOR_SPECIFIC_QUERY
               and not m.msg.payload.get('_encrypted')]
    returns = [m for m in receiver_msgs
               if m.msg.msg_type_enum == MsgType.VENDOR_SPECIFIC_QUERY_RETURN
               and not m.msg.payload.get('_encrypted')]
    if len(returns) < len(queries):
        s.add(Severity.ERROR, "9.6",
              f"Receiver sent {len(returns)} VendorSpecificQueryReturn(s) "
              f"for {len(queries)} VendorSpecificQuery message(s)")

    for idx, q in enumerate(queries):
        vqtype = q.msg.payload.get('vqtype', -1)
        q_cid = q.msg.payload.get('cid', '')
        ret = returns[idx] if idx < len(returns) else None
        if ret:
            vqsts = ret.msg.payload.get('vqsts', -1)
            # SHALL: VQSTS=255 for reserved VQTYPE (1–15)
            if 1 <= vqtype <= 15:
                if vqsts != 255:
                    s.add(Severity.ERROR, "9.6",
                          f"VendorSpecificQueryReturn for reserved VQTYPE={vqtype}: "
                          f"VQSTS={vqsts}; SHALL be 255",
                          packet_number=ret.packet_number)
            # SHALL: VQTYPE=0 VQDATA SHALL be ≤ 256 bytes
            if vqtype == 0 and vqsts == 0:
                vqdata = ret.msg.payload.get('vqdata_str', '')
                vqdata_len = len(vqdata.encode('utf-8')) if isinstance(vqdata, str) else 0
                if vqdata_len > 256:
                    s.add(Severity.ERROR, "9.6",
                          f"VendorSpecificQueryReturn VQTYPE=0 VQDATA={vqdata_len} bytes; "
                          "SHALL be ≤ 256",
                          packet_number=ret.packet_number)
            # SHALL: CID in QueryReturn SHALL match Query CID for VQTYPE 16-255
            if vqtype >= 16:
                ret_cid = ret.msg.payload.get('cid', '')
                if ret_cid != q_cid:
                    s.add(Severity.ERROR, "9.6",
                          f"VendorSpecificQueryReturn CID={ret_cid} does not match "
                          f"Query CID={q_cid} for VQTYPE={vqtype}",
                          packet_number=ret.packet_number)

    # ------------------------------------------------------------------ §9.12 — USB Enter Sleep / WoL
    # Skip payload-dependent checks when encrypted.
    enter_sleep_msgs = [m for m in sender_msgs
                        if m.msg.msg_type_enum == MsgType.USB_ENTER_SLEEP]
    wol_ctrl_msgs = [m for m in receiver_msgs
                     if m.msg.msg_type_enum == MsgType.USB_WAKEUP_CONTROL
                     and not m.msg.payload.get('_encrypted')]
    wol_enabled = False
    for cm in wol_ctrl_msgs:
        wakectrl = cm.msg.payload.get('wakectrl', 0)
        wol_enabled = (wakectrl == 1)

    if enter_sleep_msgs and wol_enabled:
        # §9.12 SHALL: Sender SHALL close all connections after Enter Sleep + WoL enabled.
        # We detect this by checking that no further messages appear from the Sender after
        # the Enter Sleep on this channel (i.e. the stream ends).
        enter_pkt = enter_sleep_msgs[-1].packet_number
        after_sleep = [m for m in sender_msgs
                       if m.packet_number > enter_pkt
                       and m.msg.msg_type_enum not in (MsgType.USB_ENTER_SLEEP,)]
        if after_sleep:
            s.add(Severity.ERROR, "9.12",
                  "Sender sent messages after USB Enter Sleep with WoL enabled; "
                  "SHALL close all connections",
                  packet_number=after_sleep[0].packet_number)

    # ------------------------------------------------------------------ §9.3 — Heartbeat DATA
    hbeat_msgs = [m for m in sender_msgs if m.msg.msg_type_enum == MsgType.HEARTBEAT]
    for cm in hbeat_msgs:
        if len(cm.msg.data) != 0:
            s.add(Severity.ERROR, "9.3",
                  f"Heartbeat DATA is {len(cm.msg.data)} bytes; SHALL be empty (0 bytes)",
                  packet_number=cm.packet_number)

    # ------------------------------------------------------------------ §9.11 — USBWakeupControl
    for cm in wol_ctrl_msgs:
        wakectrl = cm.msg.payload.get('wakectrl', -1)
        if wakectrl not in (0, 1):
            s.add(Severity.ERROR, "9.11",
                  f"USBWakeupControl WAKECTRL={wakectrl}; SHALL be 0 or 1",
                  packet_number=cm.packet_number)

    # ------------------------------------------------------------------ §11 — Heartbeat timing
    ctrl.heartbeat_times = [m.timestamp for m in hbeat_msgs]

    if ctrl.receiver_status:
        hbeat_idx = ctrl.receiver_status.get('hbeat', 10)
        if 5 <= hbeat_idx <= 30:
            period = _heartbeat_period(hbeat_idx)
            deadline = period * 2.0
            if hbeat_msgs:
                for i in range(1, len(hbeat_msgs)):
                    gap = hbeat_msgs[i].timestamp - hbeat_msgs[i - 1].timestamp
                    if gap > deadline:
                        s.add(Severity.ERROR, "11",
                              f"Heartbeat gap {gap:.2f}s exceeds 2× period "
                              f"({deadline:.2f}s); Sender is considered unresponsive",
                              packet_number=hbeat_msgs[i].packet_number)
                    elif gap > period * 1.1:
                        s.add(Severity.WARNING, "11",
                              f"Heartbeat gap {gap:.2f}s > 1.1 × period ({period:.2f}s)",
                              packet_number=hbeat_msgs[i].packet_number)

    # ------------------------------------------------------------------ §12 — Encryption
    if not encrypted:
        for cm in all_msgs:
            m = cm.msg
            if m.ctr != 0:
                s.add(Severity.ERROR, "12",
                      f"{m.msg_type_name}: CTR=0x{m.ctr:016X} SHALL be 0 when encryption disabled",
                      packet_number=cm.packet_number)
            if m.key_version != 0:
                s.add(Severity.ERROR, "12",
                      f"{m.msg_type_name}: KEYVERSION=0x{m.key_version:08X} SHALL be 0 when encryption disabled",
                      packet_number=cm.packet_number)
            if m.mac != b'\x00' * 8:
                s.add(Severity.ERROR, "12",
                      f"{m.msg_type_name}: MAC SHALL be 0 when encryption disabled",
                      packet_number=cm.packet_number)
    else:
        # ---------------------------------------------------------------- §12 — CTR monotonicity
        _check_ctr_monotonic(s, sender_msgs, "Sender->Receiver (control)")
        _check_ctr_monotonic(s, receiver_msgs, "Receiver->Sender (control)")
        # ---------------------------------------------------------------- §12 — KEYVERSION consistency
        _check_keyversion_consistency(s, sender_msgs, receiver_msgs, "control")


def _check_keyversion_consistency(
    session: Session,
    sender_msgs: list[ChannelMessage],
    receiver_msgs: list[ChannelMessage],
    channel_label: str,
) -> None:
    """§12: KEYVERSION SHALL be consistent and non-zero within each direction.

    Per TR-10-13 §19.2, Sender and Receiver each independently manage
    their own key_version.  Consistency is checked per-direction: all
    S2R messages must share one KEYVERSION and all R2S messages must
    share one (possibly different) KEYVERSION.
    """
    s = session
    for direction_label, msgs in (("Sender->Receiver", sender_msgs),
                                  ("Receiver->Sender", receiver_msgs)):
        kv_set: set[int] = set()
        for cm in msgs:
            kv = cm.msg.key_version
            if kv == 0:
                s.add(Severity.ERROR, "12",
                      f"{channel_label} {direction_label} {cm.msg.msg_type_name}: "
                      "KEYVERSION=0x00000000 SHALL be non-zero when encryption is used",
                      packet_number=cm.packet_number)
            kv_set.add(kv)
        kv_nonzero = {v for v in kv_set if v != 0}
        if len(kv_nonzero) > 1:
            sorted_kvs = sorted(kv_nonzero)
            _MAX_KV_SHOWN = 6
            if len(sorted_kvs) <= _MAX_KV_SHOWN:
                vals = ", ".join(f"0x{v:08X}" for v in sorted_kvs)
            else:
                head = ", ".join(f"0x{v:08X}" for v in sorted_kvs[:3])
                tail = ", ".join(f"0x{v:08X}" for v in sorted_kvs[-2:])
                vals = f"{head}, ... ({len(sorted_kvs) - 5} more) ..., {tail}"
            s.add(Severity.ERROR, "12",
                  f"{channel_label} {direction_label}: Multiple KEYVERSION values "
                  f"({vals}) in a single TCP session; SHALL be consistent")


def _check_ctr_monotonic(
    session: Session,
    msgs: list[ChannelMessage],
    direction_label: str,
) -> None:
    """Verify that CTR values are strictly increasing in *msgs* (per §12)."""
    prev_ctr: Optional[int] = None
    for cm in msgs:
        ctr = cm.msg.ctr
        if ctr == 0:
            continue           # unencrypted message mixed in — checked elsewhere
        if prev_ctr is not None and ctr <= prev_ctr:
            session.add(
                Severity.ERROR, "12",
                f"{direction_label}: {cm.msg.msg_type_name} CTR=0x{ctr:016X} "
                f"is not greater than previous CTR=0x{prev_ctr:016X}; "
                "SHALL be strictly increasing",
                packet_number=cm.packet_number,
            )
        prev_ctr = ctr


def _validate_data_channel(
    session: Session,
    channel: DataChannel,
    sender_msgs: list[ChannelMessage],
    receiver_msgs: list[ChannelMessage],
    encrypted: bool,
    decrypted: bool = False,
) -> None:
    s = session
    all_msgs = sorted(sender_msgs + receiver_msgs, key=lambda m: (m.packet_number, m.timestamp))
    channel.messages = all_msgs

    # ------------------------------------------------------------------ §9 — Reserved header bits
    for cm in all_msgs:
        _check_reserved_header_bits(s, cm)

    # ------------------------------------------------------------------ §9 SHOULD — Encryption
    if not encrypted:
        s.add(Severity.WARNING, "9",
              f"Data channel (substreamid={channel.substreamid}): stream is not encrypted; "
              "messages SHOULD be encrypted and authenticated (TR-10-13)")

    # ------------------------------------------------------------------ §12 MAC verification
    if decrypted:
        for cm in all_msgs:
            if cm.mac_ok is False:
                s.add(Severity.ERROR, "12",
                      f"Data channel {cm.msg.msg_type_name}: CMAC-64 verification failed",
                      packet_number=cm.packet_number)

    # ------------------------------------------------------------------ §8.3.1.2
    # SHALL: Sender sends USBStreamInformation as first message
    if not sender_msgs:
        s.add(Severity.ERROR, "8.3.1.2",
              f"Data channel (substreamid={channel.substreamid}): no messages from Sender")
        return

    first_sender = sender_msgs[0]
    if first_sender.msg.msg_type_enum != MsgType.USB_STREAM_INFO:
        s.add(Severity.ERROR, "8.3.1.2",
              f"Data channel first Sender message is {first_sender.msg.msg_type_name}; "
              "expected USBStreamInformation",
              packet_number=first_sender.packet_number)

    channel.stream_info_pkt = first_sender.packet_number

    # ------------------------------------------------------------------ §9.7 — USBStreamInfo field checks
    # Skip payload checks when encrypted (DATA is ciphertext).
    si = next((m for m in sender_msgs if m.msg.msg_type_enum == MsgType.USB_STREAM_INFO), None)
    if si and si.msg.payload and (not encrypted or decrypted) and not si.msg.is_encrypted:
        substreamid = si.msg.payload.get('substreamid', 0)
        # SHALL: bit 0 of SUBSTREAMID SHALL be 0 (Sender-to-Receiver direction indicator)
        if substreamid & 0x01 != 0:
            s.add(Severity.ERROR, "9.7",
                  f"USBStreamInfo SUBSTREAMID=0x{substreamid:02X}: bit 0 SHALL be 0 "
                  "(Sender-to-Receiver direction)",
                  packet_number=si.packet_number)
        # SHALL: bits 7:1 SHALL be in [1, 127] for data channels
        channel_id = (substreamid >> 1) & 0x7F
        if channel_id == 0:
            s.add(Severity.ERROR, "9.7",
                  f"USBStreamInfo SUBSTREAMID=0x{substreamid:02X}: channel bits 7:1 = 0 "
                  "is reserved for the Control channel; SHALL be 1-127 on data channels",
                  packet_number=si.packet_number)

    # ------------------------------------------------------------------ §8.3.1.2
    # SHALL: Receiver sends USBStreamStatus on reception of USBStreamInformation
    uss = next((m for m in receiver_msgs
                if m.msg.msg_type_enum == MsgType.USB_STREAM_STATUS), None)
    if not uss:
        s.add(Severity.ERROR, "8.3.1.2",
              f"Data channel (substreamid={channel.substreamid}): "
              "Receiver did not send USBStreamStatus after USBStreamInformation",
              packet_number=first_sender.packet_number)
    else:
        channel.stream_status_pkt = uss.packet_number
        if (not encrypted or decrypted) and not uss.msg.is_encrypted:
            channel.stream_status_ok = uss.msg.payload.get('cstatus', 255) == 0
        else:
            channel.stream_status_ok = True   # cannot decode ciphertext; assume OK

    # ------------------------------------------------------------------ §9.8 — USBStreamStatus CSTATUS
    # Skip when encrypted.
    if uss and uss.msg.payload and (not encrypted or decrypted) and not uss.msg.is_encrypted:
        cstatus = uss.msg.payload.get('cstatus', -1)
        if cstatus not in (0, 255):
            s.add(Severity.ERROR, "9.8",
                  f"USBStreamStatus CSTATUS={cstatus} is reserved; SHALL be 0 (OK) or 255 (error)",
                  packet_number=uss.packet_number)

    # ------------------------------------------------------------------ §8.3.1.2
    # SHALL: Receiver SHALL NOT send USB Submit messages before USBStreamStatus
    submit_types = {
        MsgType.USB_CONTROL_SUBMIT, MsgType.USB_BULK_SUBMIT,
        MsgType.USB_INTERRUPT_SUBMIT, MsgType.USB_ISOCHRONOUS_SUBMIT,
        MsgType.USB_CANCEL_SUBMIT,
    }
    if uss:
        early_submits = [
            m for m in receiver_msgs
            if m.msg.msg_type_enum in submit_types
            and m.packet_number < uss.packet_number
        ]
        for em in early_submits:
            s.add(Severity.ERROR, "8.3.1.2",
                  f"Data channel: Receiver sent {em.msg.msg_type_name} before USBStreamStatus",
                  packet_number=em.packet_number)

    if not encrypted or decrypted:
        # -------------------------------------------------------------- 9.14–9.16
        # SEQNUM tracking: two-pass approach.
        # Pass 1: collect all Submits from receiver_msgs (in order).
        # Pass 2: for each Submit Return from sender_msgs, validate against its Submit.
        # This avoids ordering ambiguity when messages share the same packet_number
        # (i.e. all came from a single reassembled block).
        # Skipped entirely when encrypted (payload is opaque ciphertext).

        submit_return_map = {
            MsgType.USB_CONTROL_SUBMIT:            MsgType.USB_CONTROL_SUBMIT_RETURN,
            MsgType.USB_BULK_SUBMIT:               MsgType.USB_BULK_SUBMIT_RETURN,
            MsgType.USB_INTERRUPT_SUBMIT:          MsgType.USB_INTERRUPT_SUBMIT_RETURN,
            MsgType.USB_ISOCHRONOUS_SUBMIT:        MsgType.USB_ISOCHRONOUS_SUBMIT_RETURN,
            MsgType.USB_CANCEL_SUBMIT:             MsgType.USB_CANCEL_SUBMIT_RETURN,
        }

        # Pass 1: index all Submits by SEQNUM
        # Cancel Submit is excluded from SEQNUM sequence checking because its
        # SEQNUM references an already-issued transfer (not a new one).
        pending_submits: dict[int, dict] = {}
        expected_seqnum = 0
        seqnum_error_reported = False
        for cm in receiver_msgs:
            mt = cm.msg.msg_type_enum
            p = cm.msg.payload
            if not p or mt not in submit_return_map:
                continue
            seqnum = p.get('seqnum', -1)
            if mt != MsgType.USB_CANCEL_SUBMIT:
                if not seqnum_error_reported:
                    if seqnum != expected_seqnum:
                        s.add(Severity.ERROR, "9.14",
                              f"Data channel (substreamid={channel.substreamid}): "
                              f"{mt.name} SEQNUM={seqnum}; expected {expected_seqnum}",
                              packet_number=cm.packet_number)
                        seqnum_error_reported = True
                expected_seqnum = seqnum + 1
            # §9.14 / §9.22: Rsvd 3 bits in endpoint byte SHALL be 0
            _check_endpoint_rsvd_bits(s, cm, "submit")
            pending_submits[seqnum] = {
                'msg_type': mt,
                'endpoint': p.get('endpoint'),
                'direction': p.get('direction'),
                'transferlength': p.get('transferlength') or 0,
                'packet_number': cm.packet_number,
                'timestamp': cm.timestamp,
            }

        # Pass 2: validate Submit Returns from sender_msgs
        return_types = set(submit_return_map.values())
        for cm in sender_msgs:
            mt = cm.msg.msg_type_enum
            p = cm.msg.payload
            if not p or mt not in return_types:
                continue
            # §9.18/§9.23: Rsvd 3 bits in endpoint byte SHALL be 0
            _check_endpoint_rsvd_bits(s, cm, "return")
            seqnum = p.get('seqnum', -1)
            if seqnum not in pending_submits:
                if mt != MsgType.USB_CANCEL_SUBMIT_RETURN:
                    s.add(Severity.ERROR, "9.18",
                          f"Data channel: {mt.name} SEQNUM={seqnum} has no matching Submit",
                          packet_number=cm.packet_number)
                continue

            sub = pending_submits.pop(seqnum)

            # SHALL: Return ENDPOINT matches Submit ENDPOINT
            if p.get('endpoint') != sub.get('endpoint'):
                s.add(Severity.ERROR, "9.18",
                      f"Data channel: {mt.name} SEQNUM={seqnum} ENDPOINT={p.get('endpoint')} "
                      f"does not match Submit ENDPOINT={sub.get('endpoint')}",
                      packet_number=cm.packet_number)

            # SHALL: Return D matches Submit D
            if p.get('direction') != sub.get('direction'):
                s.add(Severity.ERROR, "9.18",
                      f"Data channel: {mt.name} SEQNUM={seqnum} D={p.get('direction')} "
                      f"does not match Submit D={sub.get('direction')}",
                      packet_number=cm.packet_number)

            # ACTUALLENGTH / DIRECTION checks don't apply to ISO returns
            # (ISO uses per-packet descriptors instead).
            if mt != MsgType.USB_ISOCHRONOUS_SUBMIT_RETURN:
                # SHALL: ACTUALLENGTH = 0 when D = 0 (OUT transfer)
                actual = p.get('actuallength', -1)
                direction = p.get('direction', -1)
                if direction == 0 and actual != 0:
                    s.add(Severity.ERROR, "9.18",
                          f"Data channel: {mt.name} SEQNUM={seqnum} "
                          f"ACTUALLENGTH={actual} "
                          "SHALL be 0 for OUT (D=0) transfers",
                          packet_number=cm.packet_number)

                # SHALL: ACTUALLENGTH ≤ TRANSFERLENGTH when D = 1 (IN)
                if direction == 1 and actual > sub.get('transferlength', 0):
                    s.add(Severity.ERROR, "9.18",
                          f"Data channel: {mt.name} SEQNUM={seqnum} "
                          f"ACTUALLENGTH={actual} exceeds "
                          f"TRANSFERLENGTH={sub.get('transferlength')}",
                          packet_number=cm.packet_number)

            # SHALL: RSTATUS / ISOSTATUS is a known status code
            if mt == MsgType.USB_ISOCHRONOUS_SUBMIT_RETURN:
                for idx, iso_desc in enumerate(
                        p.get('iso_packets', [])):
                    iso_st = iso_desc.get('isostatus', -1)
                    if iso_st not in _VALID_STATUS_CODES:
                        s.add(Severity.ERROR, "A.1",
                              f"Data channel: {mt.name} SEQNUM={seqnum} "
                              f"ISOSTATUS[{idx}]=0x{iso_st:08X} "
                              "is not a defined status code",
                              packet_number=cm.packet_number)
            else:
                rstatus = p.get('rstatus', -1)
                if rstatus not in _VALID_STATUS_CODES:
                    s.add(Severity.ERROR, "A.1",
                          f"Data channel: {mt.name} SEQNUM={seqnum} "
                          f"RSTATUS=0x{rstatus:08X} "
                          "is not a defined status code; SHALL use UNKNOWN_ERROR",
                          packet_number=cm.packet_number)

        # -------------------------------------------------------------- 9.17
        # ISO_SUBMIT: when A=1 (ASAP), STARTFRAME SHALL be 0
        for cm in receiver_msgs:
            if cm.msg.msg_type_enum != MsgType.USB_ISOCHRONOUS_SUBMIT:
                continue
            p = cm.msg.payload
            if p.get('asap', 0) == 1 and p.get('startframe', 0) != 0:
                s.add(Severity.ERROR, "9.17",
                      f"Data channel: ISO_SUBMIT ASAP=1 but "
                      f"STARTFRAME={p['startframe']} "
                      "(SHALL be 0 when A=1)",
                      packet_number=cm.packet_number)

        # -------------------------------------------------------------- 9.17/9.21
        # STARTFRAME monotonicity: ISO_SUBMIT_RETURN STARTFRAME should be
        # monotonically non-decreasing per endpoint (USB frame number
        # advances with time).  Tracked per-endpoint because video and
        # audio may interleave on the same data channel at different rates.
        last_iso_startframe_by_ep: dict[int, int] = {}
        for cm in sender_msgs:
            if cm.msg.msg_type_enum != MsgType.USB_ISOCHRONOUS_SUBMIT_RETURN:
                continue
            sf = cm.msg.payload.get('startframe', 0)
            ep = cm.msg.payload.get('endpoint', 0)
            if sf == 0:
                continue
            prev = last_iso_startframe_by_ep.get(ep)
            if prev is not None and sf < prev:
                s.add(Severity.WARNING, "9.21",
                      f"Data channel: ISO_SUBMIT_RETURN EP={ep:#04x} "
                      f"STARTFRAME={sf} decreased from previous {prev} "
                      "(expected monotonic USB frame number)",
                      packet_number=cm.packet_number)
            last_iso_startframe_by_ep[ep] = sf

        # -------------------------------------------------------------- 9.9
        # USB Stream Reset: after sending Reset, Receiver SHALL wait for Reset Return
        resets = [m for m in receiver_msgs if m.msg.msg_type_enum == MsgType.USB_STREAM_RESET]
        reset_returns = [m for m in sender_msgs if m.msg.msg_type_enum == MsgType.USB_STREAM_RESET_RETURN]
        for reset in resets:
            # Check that no Submit is sent by Receiver between this Reset and its Return
            next_return = next(
                (r for r in reset_returns if r.packet_number > reset.packet_number), None
            )
            if next_return is None:
                s.add(Severity.ERROR, "9.9",
                      f"Data channel (substreamid={channel.substreamid}): "
                      "USBStreamReset sent but no USBStreamResetReturn received",
                      packet_number=reset.packet_number)
            else:
                # Any Submit between reset and reset_return?
                early = [
                    m for m in receiver_msgs
                    if m.msg.msg_type_enum in {
                        MsgType.USB_CONTROL_SUBMIT, MsgType.USB_BULK_SUBMIT,
                        MsgType.USB_INTERRUPT_SUBMIT, MsgType.USB_ISOCHRONOUS_SUBMIT,
                    }
                    and reset.packet_number < m.packet_number < next_return.packet_number
                ]
                for em in early:
                    s.add(Severity.ERROR, "9.9",
                          f"Data channel: Receiver sent {em.msg.msg_type_name} "
                          "after USBStreamReset and before USBStreamResetReturn",
                          packet_number=em.packet_number)

        # -------------------------------------------------------------- §9.10
        for cm in reset_returns:
            if len(cm.msg.data) != 0:
                s.add(Severity.ERROR, "9.10",
                      f"USBStreamResetReturn DATA is {len(cm.msg.data)} bytes; "
                      "SHALL be empty (0 bytes)",
                      packet_number=cm.packet_number)

        # -------------------------------------------------------------- §9.15
        ctrl_submits = [m for m in receiver_msgs
                        if m.msg.msg_type_enum == MsgType.USB_CONTROL_SUBMIT
                        and not m.msg.payload.get('_encrypted')]
        for cm in ctrl_submits:
            usbdevreq = cm.msg.payload.get('usbdevreq', '')
            req_bytes = bytes.fromhex(usbdevreq) if isinstance(usbdevreq, str) else usbdevreq
            if len(req_bytes) != 8:
                s.add(Severity.ERROR, "9.15",
                      f"USB Control Submit USBDEVREQ is {len(req_bytes)} bytes; SHALL be 8",
                      packet_number=cm.packet_number)

        # -------------------------------------------------------------- §10
        for cm in sender_msgs:
            ssid = cm.msg.payload.get('substreamid')
            if ssid is not None and ssid & 1 != 0:
                s.add(Severity.ERROR, "10",
                      f"S2R message {cm.msg.msg_type_name} substreamid=0x{ssid:02X} "
                      "is odd; SHALL be even for Sender-to-Receiver",
                      packet_number=cm.packet_number)
        for cm in receiver_msgs:
            ssid = cm.msg.payload.get('substreamid')
            if ssid is not None and ssid & 1 == 0:
                s.add(Severity.ERROR, "10",
                      f"R2S message {cm.msg.msg_type_name} substreamid=0x{ssid:02X} "
                      "is even; SHALL be odd for Receiver-to-Sender",
                      packet_number=cm.packet_number)

    # ------------------------------------------------------------------ §12
    if not encrypted:
        for cm in all_msgs:
            m = cm.msg
            if m.ctr != 0:
                s.add(Severity.ERROR, "12",
                      f"Data channel {m.msg_type_name}: CTR=0x{m.ctr:016X} SHALL be 0 when encryption disabled",
                      packet_number=cm.packet_number)
            if m.key_version != 0:
                s.add(Severity.ERROR, "12",
                      f"Data channel {m.msg_type_name}: KEYVERSION=0x{m.key_version:08X} SHALL be 0 when encryption disabled",
                      packet_number=cm.packet_number)
            if m.mac != b'\x00' * 8:
                s.add(Severity.ERROR, "12",
                      f"Data channel {m.msg_type_name}: MAC SHALL be 0x0000000000000000 when encryption disabled",
                      packet_number=cm.packet_number)
    else:
        # ---------------------------------------------------------------- §12 — CTR monotonicity
        _check_ctr_monotonic(s, sender_msgs,
                             f"Sender->Receiver (data substreamid=0x{channel.substreamid:02X})")
        _check_ctr_monotonic(s, receiver_msgs,
                             f"Receiver->Sender (data substreamid=0x{channel.substreamid:02X})")
        # ---------------------------------------------------------------- §12 — KEYVERSION consistency
        _check_keyversion_consistency(
            s, sender_msgs, receiver_msgs,
            f"Data (substreamid=0x{channel.substreamid:02X})")


# ---------------------------------------------------------------------------
# Main analysis entry point
# ---------------------------------------------------------------------------

def analyze_pcap(
    pcap_file: str,
    *,
    sender_port: Optional[int] = None,
    sender_cid: Optional[bytes] = None,
    sender_sn: Optional[str] = None,
    encrypted: Optional[bool] = None,
    verbose: bool = False,
    show_tcp_issues: bool = False,
    pep_params: Optional[pepmod.PepParams] = None,
    iv_mode_s2r: pepmod.IvMode = pepmod.IvMode.SPEC,
    iv_mode_r2s: pepmod.IvMode = pepmod.IvMode.SPEC,
) -> list[Session]:
    """
    Analyze a PCAP file and return a list of :class:`Session` objects,
    each carrying the parsed messages and validation findings.

    When *pep_params* is provided with a PSK, encrypted messages are
    decrypted transparently and field-level validation is applied to
    the decrypted content.
    """
    _reset_framing_stats()

    # §12: Valid modes for TR-10-14 USB privacy
    _VALID_USB_MODES = {
        "AES-128-CTR_CMAC-64-AAD",
        "AES-256-CTR_CMAC-64-AAD",
        "ECDH_AES-128-CTR_CMAC-64-AAD",
        "ECDH_AES-256-CTR_CMAC-64-AAD",
    }

    pep_key: Optional[bytes] = None
    decrypted = False
    mode_warning: Optional[str] = None
    if pep_params is not None and pep_params.psk:
        # Initial key from SDP — will be re-derived in _identify_channels
        # if the protocol is _KV and the in-message KEYVERSION differs.
        pep_key = pep_params.derive_key()
        decrypted = True
        if verbose:
            print(f"  PEP decryption enabled: mode={pep_params.mode.value}")
        if pep_params.mode.value not in _VALID_USB_MODES:
            mode_warning = (
                f"PEP mode '{pep_params.mode.value}' is not one of the modes "
                "defined in §12: " + ", ".join(sorted(_VALID_USB_MODES))
            )

    packets = _load_packets(pcap_file)

    if verbose:
        print(f"\nLoaded {len(packets)} packets from {pcap_file}")

    # If no port specified try auto-detect (use the port with most SYN packets)
    if sender_port is None:
        port_counts: dict[int, int] = {}
        for pkt in packets:
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                if tcp.flags.S and not tcp.flags.A:
                    port_counts[tcp.dport] = port_counts.get(tcp.dport, 0) + 1
        if port_counts:
            sender_port = max(port_counts, key=port_counts.__getitem__)
            if verbose:
                print(f"  Auto-detected Sender port: {sender_port}")

    connections = _collect_streams(packets)

    if verbose:
        print(f"  Found {len(connections)} TCP stream(s)")

    # --no-encrypted (encrypted is False) forces plaintext decoding even when a
    # message header carries a non-zero CTR/KEYVERSION. --encrypted / auto leave
    # the parser's own is_encrypted heuristic in charge.
    force_plaintext = encrypted is False

    channel_map, ssid_findings = _identify_channels(
        connections, verbose,
        pep_key=pep_key, pep_params=pep_params,
        iv_mode_s2r=iv_mode_s2r,
        iv_mode_r2s=iv_mode_r2s,
        force_plaintext=force_plaintext)

    # Auto-detect encryption from messages: if any message on any channel has
    # non-zero CTR or KEYVERSION, treat the stream as encrypted. Only runs when
    # the caller left it unspecified (None); --encrypted / --no-encrypted force
    # the value and skip detection.
    mac_failures = 0
    if encrypted is None:
        encrypted = False
        for _ctype, _smsgs, _rmsgs in channel_map.values():
            for cm in _smsgs + _rmsgs:
                if cm.msg.is_encrypted:
                    encrypted = True
                    if verbose:
                        print("  Auto-detected encrypted stream")
                    break
            if encrypted:
                break

    # Count MAC failures — tells the user decryption is not working.
    if decrypted:
        for _ctype, _smsgs, _rmsgs in channel_map.values():
            for cm in _smsgs + _rmsgs:
                if cm.mac_ok is False:
                    mac_failures += 1
        if mac_failures and verbose:
            print(f"  ⚠ {mac_failures} message(s) with CMAC verification failure "
                  "— decryption key is wrong (check PSK)")

    # Group channels into sessions.
    # A session = one (Sender IP, Sender port) pair.
    # Multiple reconnects of the same Sender produce separate sessions.
    sessions: list[Session] = []
    session_by_ctrl_key: dict[str, Session] = {}

    # Process control channels first to build sessions.
    for key, (ctype, sender_msgs, receiver_msgs) in channel_map.items():
        if ctype != 'control':
            continue
        src_ip, src_port = key.split('-')[0].rsplit(':', 1)
        sender_ip = sender_msgs[0].src_ip if sender_msgs else src_ip

        sess = Session(
            sender_ip=sender_ip,
            sender_port=sender_port or 0,
            receiver_ip='',
        )
        if mode_warning:
            sess.add(Severity.ERROR, "12", mode_warning)
        sessions.append(sess)
        session_by_ctrl_key[key] = sess

        if verbose:
            print(f"\n  Control channel: {key}")

        _validate_control_channel(
            sess, sender_msgs, receiver_msgs,
            sender_cid, sender_sn, encrypted, decrypted,
        )

    # If no control channel found, create a default session.
    if not sessions:
        sessions.append(Session(sender_ip='', sender_port=0, receiver_ip=''))

    default_session = sessions[0]

    # Process data channels.
    for key, (ctype, sender_msgs, receiver_msgs) in channel_map.items():
        if ctype != 'data':
            continue

        if verbose:
            print(f"\n  Data channel: {key}")

        # Determine substreamid from the first USBStreamInfo message.
        first_info = next(
            (m for m in sender_msgs if m.msg.msg_type_enum == MsgType.USB_STREAM_INFO), None
        )
        substreamid = first_info.msg.payload.get('substreamid', 0) if first_info else 0
        busid = first_info.msg.payload.get('busid', '') if first_info else ''
        usbspeed = first_info.msg.payload.get('usbspeed', 0) if first_info else 0

        channel = DataChannel(substreamid=substreamid, busid=busid, usbspeed=usbspeed)

        # Associate with the session whose Sender IP matches this data channel's sender.
        # If there are multiple sessions (reconnect), pick the one with no existing
        # data channel for this substreamid yet (FIFO assignment).
        sender_ip_from_channel = sender_msgs[0].src_ip if sender_msgs else ''
        sess = default_session
        for candidate in sessions:
            if candidate.sender_ip == sender_ip_from_channel and substreamid not in candidate.data_channels:
                sess = candidate
                break
        sess.data_channels[substreamid] = channel

        if key in ssid_findings:
            hs_ssid, _pl_ssid, compliant = ssid_findings[key]
            if not compliant:
                sess.add(Severity.WARNING, "9.7",
                         f"Data channel: handshake USB_STREAM_INFO encrypted "
                         f"with SSID=0x{hs_ssid:02X}, expected SSID=0x02 "
                         "(data channels SHOULD use SSID 2/3 for handshake phase)")

        _validate_data_channel(sess, channel, sender_msgs, receiver_msgs,
                               encrypted, decrypted)

    if mac_failures:
        for sess in sessions:
            sess.add(Severity.ERROR, "12",
                     f"{mac_failures} encrypted message(s) failed CMAC verification "
                     "— cannot decrypt (wrong PSK or key derivation mismatch)")

    return sessions


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Complete normative requirements table — sourced from VSF TR-10-14 (2024-09-24).
# Each entry: (section, "SHALL"|"SHOULD", short description)
# Sections follow the document numbering exactly.
# ---------------------------------------------------------------------------
_ALL_REQUIREMENTS: list[tuple[str, str, str]] = [
    # §8 — Communication channels
    ("8.3.1.1",  "SHALL",  "Control channel: first Sender message is SenderConnectionInfo"),
    ("8.3.1.1",  "SHALL",  "Control channel: Receiver sends SenderConnectionStatus in response"),
    ("8.3.1.2",  "SHALL",  "Data channel: first Sender message is USBStreamInformation"),
    ("8.3.1.2",  "SHALL",  "Data channel: Receiver sends USBStreamStatus in response"),
    ("8.3.1.2",  "SHALL",  "Data channel: Receiver does not send USB Submit before USBStreamStatus"),
    # §9 — Message framing
    ("9",        "SHALL",  "Header Reserved 7 bits SHALL be 0 before transmission"),
    ("9",        "SHOULD", "Messages SHOULD be encrypted and authenticated (TR-10-13)"),
    # §9.1 — SenderConnectionInfo
    ("9.1",      "SHALL",  "SenderConnectionInfo: MAVER=0 for this version"),
    ("9.1",      "SHALL",  "SenderConnectionInfo: MIVER=0 for this version"),
    ("9.1",      "SHALL",  "SenderConnectionInfo: Reserved byte SHALL be 0"),
    ("9.1",      "SHALL",  "SenderConnectionInfo: CID matches expected value (if supplied)"),
    ("9.1",      "SHALL",  "SenderConnectionInfo: SN matches expected value (if supplied)"),
    # §9.2 — SenderConnectionStatus
    ("9.2",      "SHALL",  "SenderConnectionStatus: Receiver version ≤ Sender version"),
    ("9.2",      "SHALL",  "SenderConnectionStatus: HBEAT in [5, 30]"),
    ("9.2",      "SHALL",  "SenderConnectionStatus: Rsvd 3 bits SHALL be 0"),
    # §9.4 — VendorSpecificInfo
    ("9.4",      "SHALL",  "VendorSpecificInfo VMTYPE 1-15 are reserved — SHALL NOT be used"),
    ("9.4",      "SHALL",  "VendorSpecificInfo VMTYPE=0 VMDATA SHALL be ≤ 256 bytes"),
    # §9.5/9.6 — VendorSpecificQuery/Return
    ("9.6",      "SHALL",  "VendorSpecificQuery: Receiver SHALL answer every query"),
    ("9.6",      "SHALL",  "VendorSpecificQuery: VQSTS=255 for unknown/reserved VQTYPE"),
    ("9.6",      "SHALL",  "VendorSpecificQueryReturn VQDATA (VQTYPE=0) SHALL be ≤ 256 bytes"),
    ("9.6",      "SHALL",  "VendorSpecificQueryReturn CID SHALL match Query CID for VQTYPE 16-255"),
    # §9.3 — Heartbeat
    ("9.3",      "SHALL",  "Heartbeat DATA SHALL be empty (0 bytes)"),
    # §9.7 — USBStreamInfo
    ("9.7",      "SHALL",  "USBStreamInfo SUBSTREAMID bit 0 SHALL be 0 (Sender-to-Receiver direction)"),
    ("9.7",      "SHALL",  "USBStreamInfo SUBSTREAMID bits 7:1 SHALL be in [1, 127] for data channels"),
    ("9.7",      "SHOULD", "Data-channel handshake (USB_STREAM_INFO/USB_STREAM_STATUS) "
                            "SHOULD be encrypted with SSID 2 (S2R) / 3 (R2S)"),
    # §9.8 — USBStreamStatus
    ("9.8",      "SHALL",  "USBStreamStatus CSTATUS SHALL be 0 (OK) or 255 (error); others are reserved"),
    # §9.9 — USBStreamReset
    ("9.9",      "SHALL",  "USBStreamReset: Receiver SHALL wait for ResetReturn before further Submits"),
    # §9.10 — USBStreamResetReturn
    ("9.10",     "SHALL",  "USBStreamResetReturn DATA SHALL be empty (0 bytes)"),
    # §9.11 — USBWakeupControl
    ("9.11",     "SHALL",  "USBWakeupControl WAKECTRL SHALL be 0 or 1"),
    # §9.12 — USB Enter Sleep
    ("9.12",     "SHALL",  "USB Enter Sleep + WoL enabled: Sender SHALL close all connections"),
    ("9.12",     "SHOULD", "USB Enter Sleep received: Receiver SHOULD NOT reconnect until WoL"),
    # §9.15 — USB Control Submit
    ("9.15",     "SHALL",  "USB Control Submit USBDEVREQ SHALL be 8 bytes"),
    # §10 — Sub-stream multiplexing
    ("10",       "SHALL",  "S2R substreamid SHALL be even; R2S substreamid SHALL be odd"),
    # §9.14 — SEQNUM
    ("9.14",     "SHALL",  "Submit SEQNUM starts at 0 and increments by 1 per Submit"),
    ("9.14",     "SHALL",  "Submit Reserved bits (Rsvd 3 in endpoint byte) SHALL be 0"),
    # §9.18 — Submit Return
    ("9.18",     "SHALL",  "Submit Return SEQNUM SHALL match an outstanding Submit"),
    ("9.18",     "SHALL",  "Submit Return ENDPOINT SHALL match Submit ENDPOINT"),
    ("9.18",     "SHALL",  "Submit Return D SHALL match Submit D"),
    ("9.18",     "SHALL",  "OUT (D=0) Submit Return: ACTUALLENGTH SHALL be 0"),
    ("9.18",     "SHALL",  "IN (D=1) Submit Return: ACTUALLENGTH SHALL be ≤ TRANSFERLENGTH"),
    ("9.18",     "SHALL",  "Submit Return Reserved bits (Rsvd 3 in endpoint byte) SHALL be 0"),
    # §11 — Heartbeat
    ("11",       "SHALL",  "Heartbeat gap SHALL be ≤ 2 × Heartbeat_Period (unresponsive threshold)"),
    ("11",       "SHOULD", "Heartbeat gap SHOULD be ≤ 1.1 × Heartbeat_Period (jitter budget)"),
    # §12 — Encryption
    ("12",       "SHALL",  "Unencrypted mode: CTR SHALL be 0 on every message"),
    ("12",       "SHALL",  "Unencrypted mode: KEYVERSION SHALL be 0 on every message"),
    ("12",       "SHALL",  "Unencrypted mode: MAC SHALL be 0x0000000000000000 on every message"),
    ("12",       "SHALL",  "Encrypted mode: CTR SHALL increase monotonically per direction"),
    ("12",       "SHALL",  "Encrypted mode: KEYVERSION SHALL be non-zero and consistent within a TCP session"),
    ("12",       "SHALL",  "Encrypted mode: CMAC-64 authentication SHALL verify correctly"),
    ("12",       "SHALL",  "Mode SHALL be one of the allowed values (AES-128/256-CTR_CMAC-64-AAD, ECDH variants)"),
    ("12",       "SHALL",  "Senders and Receivers SHALL support AES-128-CTR_CMAC-64-AAD mode"),
    # §A.1 — Status codes
    ("A.1",      "SHALL",  "RSTATUS / ISOSTATUS SHALL be a defined status code"),
]


def _print_requirements(sess: Session) -> None:
    """Print a per-requirement pass/fail checklist for *sess*."""
    failed_sections: set[str] = {f.section for f in sess.findings}

    print("\n  Requirements checklist:")
    print(f"  {'§Section':<10} {'Level':<8} {'Status':<6}  Description")
    print(f"  {'-'*9:<10} {'-'*7:<8} {'-'*5:<6}  {'-'*50}")

    for section, level, desc in _ALL_REQUIREMENTS:
        matching = [f for f in sess.findings if f.section == section]
        if matching:
            status = "FAIL"
            marker = "[FAIL]"
        else:
            status = "PASS"
            marker = "[PASS]"
        print(f"  §{section:<9} {level:<8} {marker:<8} {desc}")
        for f in matching:
            pkt = f"pkt #{f.packet_number}" if f.packet_number else ""
            print(f"    {'':22}↳ {f.severity.value}: {f.description}"
                  + (f"  [{pkt}]" if pkt else ""))


def _format_payload(payload: dict) -> str:
    """Return a compact one-line rendering of a message payload dict."""
    if not payload:
        return ""
    # Encrypted message: DATA is ciphertext — show opaque indicator
    if payload.get('_encrypted'):
        n = payload.get('_data_len', '?')
        return f"  [encrypted, {n} bytes]"
    parts = []
    for k, v in payload.items():
        if k.endswith('_name'):
            continue                           # skip redundant *_name companions
        name_key = k + '_name'
        if name_key in payload:
            parts.append(f"{k}={payload[name_key]}(0x{v:X})" if isinstance(v, int) else f"{k}={v!r}")
        elif isinstance(v, int):
            parts.append(f"{k}=0x{v:X}" if v > 9 else f"{k}={v}")
        elif isinstance(v, str) and v:
            parts.append(f"{k}='{v}'")
        elif v is not None and v != b'' and v != '':
            parts.append(f"{k}={v!r}")
    return "  " + "  ".join(parts) if parts else ""


def _hid_kind_by_shape(data: bytes) -> usb_decode.HidBootProtocol:
    """Fallback HID classification when no Configuration descriptor was captured.

    A boot keyboard report is 8 bytes with a zero reserved byte (index 1); a
    boot mouse report is 3-4 bytes.  Ambiguous shapes return NONE so nothing is
    mis-decoded.
    """
    n = len(data)
    if n >= 8 and data[1] == 0:
        return usb_decode.HidBootProtocol.KEYBOARD
    if 3 <= n <= 4:
        return usb_decode.HidBootProtocol.MOUSE
    return usb_decode.HidBootProtocol.NONE


def _hid_report_lines(data: bytes, ep: Optional[usb_decode.EndpointInfo]) -> list[str]:
    """ASCII-only annotation for a tunneled HID boot keyboard/mouse report.

    Classification prefers the endpoint's boot-interface protocol (from a
    Configuration descriptor captured earlier on the same channel) and falls
    back to the report shape otherwise.  Idle reports (nothing pressed or moved)
    and non-HID endpoints produce no line.
    """
    kind = usb_decode.classify_hid(ep) if ep is not None else _hid_kind_by_shape(data)
    if kind == usb_decode.HidBootProtocol.KEYBOARD:
        r = usb_decode.decode_keyboard_report(data)
        if r is None or (not r.text and not r.modifiers):
            return []
        keys = f" keys={ascii(r.text)}" if r.text else ""
        mods = f" mods=[{', '.join(r.modifiers)}]" if r.modifiers else ""
        return [f"-> Keyboard{keys}{mods}"]
    if kind == usb_decode.HidBootProtocol.MOUSE:
        r = usb_decode.decode_mouse_report(data)
        if r is None or (not r.buttons and r.dx == 0 and r.dy == 0 and r.wheel == 0):
            return []
        btns = f" buttons=[{', '.join(r.buttons)}]" if r.buttons else ""
        return [f"-> Mouse{btns} dx={r.dx:+d} dy={r.dy:+d} wheel={r.wheel:+d}"]
    return []


def _print_messages(sess: Session, decode_usb: bool = False) -> None:
    """Print every message on the control channel and each data channel.

    When ``decode_usb`` is set, each row that carries a tunneled USB SETUP
    packet (USBDEVREQ) or descriptor payload (TRANSFERDATA) is followed by
    indented, ASCII-only annotation lines decoding the USB standard layer.
    Returned descriptors are decoded in the context of the SETUP request that
    produced them, correlated per-channel by SEQNUM.
    """

    def _usb_annotations(m: IpmxUsbMessage,
                         setup_by_seqnum: dict[int, dict],
                         hid_endpoints: dict[int, usb_decode.EndpointInfo]) -> list[str]:
        """Return decoded USB lines for one message, updating the correlation maps.

        ``setup_by_seqnum`` correlates a SETUP request to its returned data;
        ``hid_endpoints`` maps endpoint number -> EndpointInfo, learned from a
        Configuration descriptor seen earlier on the channel, so a boot HID
        interrupt report can be classified as keyboard vs mouse.
        """
        p = m.payload
        if not p or p.get('_encrypted'):
            return []
        lines: list[str] = []
        seqnum = p.get('seqnum')

        # SUBMIT direction: decode the 8-byte SETUP and remember it by SEQNUM so
        # the matching RETURN's descriptor can be decoded in context.
        req_hex = p.get('usbdevreq')
        if req_hex:
            setup = usb_decode.decode_setup(bytes.fromhex(req_hex))
            if setup:
                if seqnum is not None:
                    setup_by_seqnum[seqnum] = setup
                lines.append(setup['summary'])

        # Any direction may carry returned/outgoing descriptor bytes.
        data_hex = p.get('transferdata')
        if data_hex:
            data = bytes.fromhex(data_hex)
            setup = setup_by_seqnum.get(seqnum) if seqnum is not None else None
            hint_type = setup.get('descriptor_type') if setup else None
            hint_index = setup.get('descriptor_index') if setup else None
            lines.extend(usb_decode.describe_descriptor(data, hint_type, hint_index))
            # Learn endpoint->interface mapping from a Configuration descriptor so
            # later interrupt reports on this channel can be classified.
            if hint_type == usb_decode.DescriptorType.CONFIGURATION:
                for ep in usb_decode.parse_config_descriptor(data):
                    hid_endpoints[ep.endpoint_num] = ep
            # Tunneled HID boot keyboard/mouse reports ride in interrupt returns.
            if (m.msg_type_enum == MsgType.USB_INTERRUPT_SUBMIT_RETURN
                    and p.get('direction') == 1):
                lines.extend(_hid_report_lines(data, hid_endpoints.get(p.get('endpoint'))))
        return lines

    # Reference time (t0): earliest message timestamp across the whole session,
    # so the Time(ms) column is comparable across the control and data channels.
    all_ts = [cm.timestamp
              for msgs in ([sess.control.messages]
                           + [ch.messages for ch in sess.data_channels.values()])
              for cm in msgs]
    t0 = min(all_ts) if all_ts else 0.0

    def _dump(label: str, messages: list[ChannelMessage]) -> None:
        if not messages:
            print(f"\n  {label}: (no messages)")
            return
        print(f"\n  {label}  ({len(messages)} messages)")
        print(f"  {'#Pkt':<6} {'Time(ms)':>11} {'Dir':<30} {'Type':<38} {'Len':>6}  Payload")
        print(f"  {'-'*5:<6} {'-'*11:>11} {'-'*30:<30} {'-'*37:<38} {'-'*6}  {'-'*50}")
        setup_by_seqnum: dict[int, dict] = {}
        hid_endpoints: dict[int, usb_decode.EndpointInfo] = {}
        for cm in messages:
            m = cm.msg
            src_short = f"{cm.src_ip.split('.')[-1]}:{cm.src_port}"
            dst_short = f"{cm.dst_ip.split('.')[-1]}:{cm.dst_port}"
            direction = f"{src_short}->{dst_short}"
            t_ms = (cm.timestamp - t0) * 1000.0
            payload_str = _format_payload(m.payload)
            print(f"  {cm.packet_number:<6} {t_ms:>11.3f} {direction:<30} {m.msg_type_name:<38} {m.length:>6}{payload_str}")
            if decode_usb:
                for line in _usb_annotations(m, setup_by_seqnum, hid_endpoints):
                    print(f"  {'':6} {'':11} {'':30} {line}")

    _dump("Control channel", sess.control.messages)
    for substreamid, ch in sess.data_channels.items():
        speed = (usb.UsbSpeed(ch.usbspeed).name
                 if ch.usbspeed in usb.UsbSpeed._value2member_map_ else str(ch.usbspeed))
        _dump(
            f"Data channel  SubstreamID=0x{substreamid:02X}  BusID='{ch.busid}'  Speed={speed}",
            ch.messages,
        )


def _print_session(sess: Session, verbose: bool, show_messages: bool = False,
                   show_requirements: bool = False, decode_usb: bool = False) -> None:
    print(f"\n{'='*72}")
    print(f"Session: Sender={sess.sender_ip}:{sess.sender_port}")
    if sess.control.sender_info:
        info = sess.control.sender_info
        print(f"  Sender  CID={info.get('cid','?')}  SN='{info.get('sn','?')}'")
    if sess.control.receiver_status:
        sts = sess.control.receiver_status
        print(f"  Receiver CID={sts.get('cid','?')}  SN='{sts.get('sn','?')}'  "
              f"HBEAT={sts.get('hbeat','?')}  Port={sts.get('port','?')}")
    print(f"  Data channels: {len(sess.data_channels)}")
    for substreamid, ch in sess.data_channels.items():
        print(f"    SubstreamID=0x{substreamid:02X}  BusID='{ch.busid}'  "
              f"Speed={usb.UsbSpeed(ch.usbspeed).name if ch.usbspeed in usb.UsbSpeed._value2member_map_ else ch.usbspeed}  "
              f"Messages={len(ch.messages)}")

    ctrl_msgs = len(sess.control.messages)
    data_msgs = sum(len(ch.messages) for ch in sess.data_channels.values())
    print(f"  Control messages: {ctrl_msgs}  Data messages (total): {data_msgs}")

    errors   = [f for f in sess.findings if f.severity == Severity.ERROR]
    warnings = [f for f in sess.findings if f.severity == Severity.WARNING]
    infos    = [f for f in sess.findings if f.severity == Severity.INFO]

    print(f"\n  Findings: {len(errors)} error(s), {len(warnings)} warning(s), {len(infos)} info(s)")
    for finding in sess.findings:
        print(str(finding))

    if not sess.findings:
        print("  [OK] No violations found")

    if show_messages:
        _print_messages(sess, decode_usb=decode_usb)

    if show_requirements:
        _print_requirements(sess)


def _sessions_to_json(sessions: list[Session]) -> dict:
    out = []
    for sess in sessions:
        errors   = [f for f in sess.findings if f.severity == Severity.ERROR]
        warnings = [f for f in sess.findings if f.severity == Severity.WARNING]

        out.append({
            'sender_ip': sess.sender_ip,
            'sender_port': sess.sender_port,
            'sender_info': sess.control.sender_info,
            'receiver_status': sess.control.receiver_status,
            'data_channels': [
                {
                    'substreamid': ch.substreamid,
                    'busid': ch.busid,
                    'usbspeed': ch.usbspeed,
                    'message_count': len(ch.messages),
                    'stream_status_ok': ch.stream_status_ok,
                }
                for ch in sess.data_channels.values()
            ],
            'control_message_count': len(sess.control.messages),
            'findings': [
                {
                    'severity': f.severity.value,
                    'section': f.section,
                    'description': f.description,
                    'packet_number': f.packet_number,
                    'detail': f.detail,
                }
                for f in sess.findings
            ],
            'error_count': len(errors),
            'warning_count': len(warnings),
        })
    return {'sessions': out}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="IPMX USB (TR-10-14) Protocol Dissector and Validator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('pcap_file', help="PCAP file to analyze")
    parser.add_argument('--sender-port', type=int, default=None,
                        help="Sender TCP port (default: auto-detect)")
    parser.add_argument('--sender-cid', default=None,
                        help="Expected Sender CID as hex string, e.g. 0050C2")
    parser.add_argument('--sender-sn', default=None,
                        help="Expected Sender serial number string")
    parser.add_argument('--encrypted', action=argparse.BooleanOptionalAction, default=None,
                        help="Force encryption handling. --encrypted: treat the stream as "
                             "encrypted (only validate non-encrypted fields). --no-encrypted: "
                             "force plaintext validation, skipping auto-detection. "
                             "Default: auto-detect from non-zero CTR/KEYVERSION/MAC.")
    parser.add_argument('--verbose', '-v', action='store_true',
                        help="Show stream classification details")
    parser.add_argument('--messages', '-m', action='store_true',
                        help="Print every parsed message with decoded fields")
    parser.add_argument('--decode-usb', action='store_true',
                        help="With -m, also decode the tunneled USB standard "
                             "layer (SETUP packets and returned descriptors)")
    parser.add_argument('--requirements', '-r', action='store_true',
                        help="Print a per-requirement pass/fail checklist")
    parser.add_argument('--show-tcp-issues', action='store_true',
                        help="Show TCP reassembly debug information")
    parser.add_argument('--output', '-o', default=None,
                        help="Write results to JSON file")
    parser.add_argument('--quiet', '-q', action='store_true',
                        help="Suppress console output")

    pepmod.add_pep_args(parser)

    args = parser.parse_args()

    if not Path(args.pcap_file).exists():
        print(f"Error: file not found: {args.pcap_file}", file=sys.stderr)
        return 1

    if args.sender_cid:
        cid_hex = args.sender_cid.replace('0x', '').replace('0X', '').zfill(6)
        sender_cid = bytes.fromhex(cid_hex)
    else:
        sender_cid = None

    pep_params: Optional[pepmod.PepParams] = None
    if (args.psk or args.psk_file) and (args.sdp or args.pep_protocol):
        try:
            pep_params = pepmod.PepParams.from_cli(args)
        except Exception as exc:
            print(f"Error loading PEP parameters: {exc}", file=sys.stderr)
            return 1
    elif args.sdp:
        psk = b""
        if args.psk:
            psk = bytes.fromhex(args.psk)
        elif args.psk_file:
            psk = open(args.psk_file, "rb").read()
        try:
            pep_params = pepmod.PepParams.from_sdp(args.sdp, psk)
        except Exception as exc:
            print(f"Error loading SDP: {exc}", file=sys.stderr)
            return 1

    iv_s2r_mode = pepmod.IvMode.SWAP if args.iv_s2r_swap0 else pepmod.IvMode.SPEC
    if args.iv_r2s_swap0 or args.iv_r2s_swap1:
        iv_r2s_mode = pepmod.IvMode.SWAP
    else:
        iv_r2s_mode = pepmod.IvMode.SPEC

    sessions = analyze_pcap(
        args.pcap_file,
        sender_port=args.sender_port,
        sender_cid=sender_cid,
        sender_sn=args.sender_sn,
        encrypted=args.encrypted,
        verbose=args.verbose and not args.quiet,
        show_tcp_issues=args.show_tcp_issues,
        pep_params=pep_params,
        iv_mode_s2r=iv_s2r_mode,
        iv_mode_r2s=iv_r2s_mode,
    )

    if not args.quiet:
        framing_warning = _framing_report()
        if framing_warning:
            print(f"\n{framing_warning}")

        for sess in sessions:
            _print_session(sess, verbose=args.verbose,
                           show_messages=args.messages,
                           show_requirements=args.requirements,
                           decode_usb=args.decode_usb)

        total_errors   = sum(len([f for f in s.findings if f.severity == Severity.ERROR]) for s in sessions)
        total_warnings = sum(len([f for f in s.findings if f.severity == Severity.WARNING]) for s in sessions)
        print(f"\n{'='*72}")
        print(f"Total: {len(sessions)} session(s), {total_errors} error(s), {total_warnings} warning(s)")

    if args.output:
        result = _sessions_to_json(sessions)
        with open(args.output, 'w') as fh:
            json.dump(result, fh, indent=2)
        if not args.quiet:
            print(f"Results written to {args.output}")

    total_errors = sum(len([f for f in s.findings if f.severity == Severity.ERROR]) for s in sessions)
    return 0 if total_errors == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
