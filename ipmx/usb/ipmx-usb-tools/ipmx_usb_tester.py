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
IPMX USB (TR-10-14) Live Receiver Test Harness.

Connects to a real IPMX Sender device (or another TR-10-14 implementation),
runs the full Receiver-side protocol for the duration of a test, validates
conformance in real-time, and optionally writes a PCAP for post-analysis with
usbDissector.py.

Architecture
------------
  Receiver (this tool, WSL2 / Linux) connects to Sender on control port 27502.
  After exchanging SenderConnectionInfo / SenderConnectionStatus the Sender
  connects back to our data port (advertised in SenderConnectionStatus.PORT).

  Threads:
    main          – startup, shutdown, final report
    ctrl-thread   – ControlChannelClient: drive the control channel
    data-srv      – DataChannelServer: listen for Sender data connections
    data-N        – DataChannelHandler: enumerate + poll one USB device

Usage
-----
    python3 ipmx_usb_tester.py <sender_ip> [options]
    python3 ipmx_usb_tester.py --help
"""

from __future__ import annotations

import argparse
import logging
import os
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from scapy.all import Ether, IP, TCP, PcapWriter
except ImportError:
    print("Error: scapy is required.  pip install scapy", file=sys.stderr)
    sys.exit(1)

import ipmx_usb_message as usb
from ipmx_usb_message import IpmxUsbMessage, MsgType
import ipmx_pep as pepmod

# Import validation infrastructure from the dissector
from usbDissector import (
    Severity, Finding, ChannelMessage, DataChannel, ControlChannel, Session,
    _validate_control_channel, _validate_data_channel, _heartbeat_period,
)


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# HID Usage Table (Keyboard/Keypad Page 0x07) — USB HID 1.11, Section 10
# Maps HID usage ID → (unshifted char, shifted char)
# ---------------------------------------------------------------------------
_HID_KEY_MAP: dict[int, tuple[str, str]] = {
    0x04: ('a', 'A'),   0x05: ('b', 'B'),   0x06: ('c', 'C'),   0x07: ('d', 'D'),
    0x08: ('e', 'E'),   0x09: ('f', 'F'),   0x0A: ('g', 'G'),   0x0B: ('h', 'H'),
    0x0C: ('i', 'I'),   0x0D: ('j', 'J'),   0x0E: ('k', 'K'),   0x0F: ('l', 'L'),
    0x10: ('m', 'M'),   0x11: ('n', 'N'),   0x12: ('o', 'O'),   0x13: ('p', 'P'),
    0x14: ('q', 'Q'),   0x15: ('r', 'R'),   0x16: ('s', 'S'),   0x17: ('t', 'T'),
    0x18: ('u', 'U'),   0x19: ('v', 'V'),   0x1A: ('w', 'W'),   0x1B: ('x', 'X'),
    0x1C: ('y', 'Y'),   0x1D: ('z', 'Z'),
    0x1E: ('1', '!'),   0x1F: ('2', '@'),   0x20: ('3', '#'),   0x21: ('4', '$'),
    0x22: ('5', '%'),   0x23: ('6', '^'),   0x24: ('7', '&'),   0x25: ('8', '*'),
    0x26: ('9', '('),   0x27: ('0', ')'),
    0x28: ('\n', '\n'),   # Return
    0x29: ('\x1b', '\x1b'),  # Escape
    0x2A: ('\x7f', '\x7f'),  # Backspace / Delete
    0x2B: ('\t', '\t'),      # Tab
    0x2C: (' ', ' '),        # Space
    0x2D: ('-', '_'),   0x2E: ('=', '+'),
    0x2F: ('[', '{'),   0x30: (']', '}'),   0x31: ('\\', '|'),
    0x33: (';', ':'),   0x34: ("'", '"'),   0x35: ('`', '~'),
    0x36: (',', '<'),   0x37: ('.', '>'),   0x38: ('/', '?'),
    # Function keys — display as label
    0x3A: ('<F1>', '<F1>'),  0x3B: ('<F2>', '<F2>'),   0x3C: ('<F3>', '<F3>'),
    0x3D: ('<F4>', '<F4>'),  0x3E: ('<F5>', '<F5>'),   0x3F: ('<F6>', '<F6>'),
    0x40: ('<F7>', '<F7>'),  0x41: ('<F8>', '<F8>'),   0x42: ('<F9>', '<F9>'),
    0x43: ('<F10>', '<F10>'),0x44: ('<F11>', '<F11>'), 0x45: ('<F12>', '<F12>'),
    # Navigation
    0x4F: ('<Right>', '<Right>'), 0x50: ('<Left>', '<Left>'),
    0x51: ('<Down>', '<Down>'),   0x52: ('<Up>', '<Up>'),
    0x49: ('<Ins>', '<Ins>'),     0x4A: ('<Home>', '<Home>'),
    0x4B: ('<PgUp>', '<PgUp>'),   0x4C: ('<Del>', '<Del>'),
    0x4D: ('<End>', '<End>'),     0x4E: ('<PgDn>', '<PgDn>'),
    # Numpad
    0x59: ('1', 'End'),    0x5A: ('2', '↓'),    0x5B: ('3', 'PgDn'),
    0x5C: ('4', '←'),     0x5D: ('5', '5'),    0x5E: ('6', '→'),
    0x5F: ('7', 'Home'),   0x60: ('8', '↑'),    0x61: ('9', 'PgUp'),
    0x62: ('0', 'Ins'),    0x63: ('.', 'Del'),  0x58: ('\n', '\n'),
    0x54: ('/', '/'),      0x55: ('*', '*'),    0x56: ('-', '-'),
    0x57: ('+', '+'),
}

_SHIFT_MODS = 0x02 | 0x20  # L-Shift | R-Shift


def _hid_key_to_char(keycode: int, mods: int) -> str:
    """Return a printable representation for a HID keycode + modifier byte."""
    shifted = bool(mods & _SHIFT_MODS)
    pair = _HID_KEY_MAP.get(keycode)
    if pair is None:
        return f'<0x{keycode:02X}>'
    ch = pair[1] if shifted else pair[0]
    # Replace control chars with readable labels
    if ch == '\n':
        return '<Enter>'
    if ch == '\t':
        return '<Tab>'
    if ch == '\x1b':
        return '<Esc>'
    if ch == '\x7f':
        return '<Backspace>'
    return ch


DEFAULT_SENDER_CTRL_PORT = 27502
DEFAULT_RECEIVER_DATA_PORT = 40000
DEFAULT_HBEAT_INDEX = 10          # period ≈ 47 s
DEFAULT_OUR_CID = bytes.fromhex("0050C2")
DEFAULT_OUR_SN = "IPMX-USB-Tester-v1"
DEFAULT_POLL_INTERVAL_MS = 8      # 1 ms USB frame = 8 polls/frame for HID


# ---------------------------------------------------------------------------
# USB standard request builders (USB 2.0 §9.4, HID 1.11 §7.2)
# ---------------------------------------------------------------------------

USB_REQ_GET_DESCRIPTOR   = 0x06
USB_REQ_SET_ADDRESS      = 0x05
USB_REQ_SET_CONFIGURATION = 0x09
USB_REQ_SET_IDLE         = 0x0A
USB_REQ_SET_PROTOCOL     = 0x0B

USB_DT_DEVICE  = 0x01
USB_DT_CONFIG  = 0x02
USB_DT_STRING  = 0x03
USB_DT_HID     = 0x21
USB_DT_REPORT  = 0x22

USB_CLASS_HID  = 0x03


def _get_descriptor_req(dtype: int, index: int, length: int,
                         lang_id: int = 0) -> bytes:
    bmt = 0x81 if dtype in (USB_DT_HID, USB_DT_REPORT) else 0x80
    wValue = (dtype << 8) | index
    return struct.pack('<BBHHH', bmt, USB_REQ_GET_DESCRIPTOR, wValue, lang_id, length)


def _set_address_req(addr: int) -> bytes:
    return struct.pack('<BBHHH', 0x00, USB_REQ_SET_ADDRESS, addr, 0, 0)


def _set_configuration_req(cfg: int) -> bytes:
    return struct.pack('<BBHHH', 0x00, USB_REQ_SET_CONFIGURATION, cfg, 0, 0)


def _set_idle_req() -> bytes:
    return struct.pack('<BBHHH', 0x21, USB_REQ_SET_IDLE, 0x0000, 0, 0)


def _set_protocol_req(protocol: int) -> bytes:
    return struct.pack('<BBHHH', 0x21, USB_REQ_SET_PROTOCOL, protocol, 0, 0)


# ---------------------------------------------------------------------------
# USB configuration descriptor parser
# ---------------------------------------------------------------------------

@dataclass
class EndpointInfo:
    address: int       # full bEndpointAddress byte
    endpoint_num: int  # bits 3:0
    direction: int     # 1 = IN (device→host), 0 = OUT
    transfer_type: int # 0=ctrl 1=iso 2=bulk 3=interrupt
    interval: int      # bInterval (ms for FS, 125 µs units for HS)
    max_packet: int


def _parse_config_descriptor(data: bytes) -> list[EndpointInfo]:
    """Walk a full configuration descriptor blob and return all endpoint descriptors."""
    endpoints: list[EndpointInfo] = []
    i = 0
    while i + 2 <= len(data):
        bLength = data[i]
        bType   = data[i + 1]
        if bLength < 2:
            break
        if bType == 0x05 and bLength >= 7:  # Endpoint descriptor
            addr     = data[i + 2]
            attrs    = data[i + 3]
            maxpkt   = struct.unpack_from('<H', data, i + 4)[0] & 0x07FF
            interval = data[i + 6]
            endpoints.append(EndpointInfo(
                address      = addr,
                endpoint_num = addr & 0x0F,
                direction    = (addr >> 7) & 0x01,
                transfer_type= attrs & 0x03,
                interval     = interval,
                max_packet   = maxpkt,
            ))
        i += bLength
    return endpoints


def _hid_interrupt_in(endpoints: list[EndpointInfo]) -> Optional[EndpointInfo]:
    """Return the first interrupt IN endpoint, or None."""
    for ep in endpoints:
        if ep.transfer_type == 3 and ep.direction == 1:
            return ep
    return None


# ---------------------------------------------------------------------------
# PcapCapture — write live traffic as a PCAP readable by usbDissector.py
# ---------------------------------------------------------------------------

_FAKE_SRC_MAC = "02:00:00:00:00:01"
_FAKE_DST_MAC = "02:00:00:00:00:02"


class PcapCapture:
    """
    Wraps Scapy PcapWriter to record every send/recv as fake Ether/IP/TCP
    frames.  The resulting PCAP can be fed directly into usbDissector.py.

    Synthetic TCP sequence numbers are tracked per-direction.
    """

    def __init__(self, path: str):
        self._writer = PcapWriter(path, append=False, sync=True)
        self._lock   = threading.Lock()
        self._seq: dict[tuple, int] = {}   # (src_ip, src_port) → next_seq
        self._pkt_num = 0

    def _next_seq(self, src_ip: str, src_port: int, n: int) -> int:
        key = (src_ip, src_port)
        seq = self._seq.get(key, 1000)
        self._seq[key] = seq + n
        return seq

    def record(self, data: bytes,
               src_ip: str, src_port: int,
               dst_ip: str, dst_port: int) -> int:
        """Write one TCP segment; returns the assigned packet number."""
        with self._lock:
            self._pkt_num += 1
            seq = self._next_seq(src_ip, src_port, len(data))
            pkt = (
                Ether(src=_FAKE_SRC_MAC, dst=_FAKE_DST_MAC) /
                IP(src=src_ip, dst=dst_ip) /
                TCP(sport=src_port, dport=dst_port,
                    seq=seq, flags='PA') /
                data
            )
            pkt.time = time.time()
            self._writer.write(pkt)
            return self._pkt_num

    def close(self) -> None:
        try:
            self._writer.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# IpmxChannel — socket wrapper with buffered message receive
# ---------------------------------------------------------------------------

class IpmxChannel:
    """
    Wraps a connected TCP socket for IPMX USB message exchange.

    Provides:
      send_msg(raw_bytes)  — sendall + optional PCAP recording
      recv_msg(timeout)    — block until one complete IPMX message arrives
      configure_pep(...)   — enable transparent AES-CTR encrypt/decrypt
      close()
    """

    def __init__(self,
                 sock: socket.socket,
                 local_ip: str,  local_port: int,
                 remote_ip: str, remote_port: int,
                 capture: Optional[PcapCapture] = None):
        self._sock        = sock
        self._buf         = bytearray()
        self.local_ip     = local_ip
        self.local_port   = local_port
        self.remote_ip    = remote_ip
        self.remote_port  = remote_port
        self._capture     = capture

        # PEP encryption/decryption state (set via configure_pep)
        self._pep_key_send: Optional[bytes] = None
        self._pep_key_recv: Optional[bytes] = None
        self._pep_mode: Optional[pepmod.PepMode] = None
        self._iv_send: Optional[int] = None
        self._iv_recv: Optional[int] = None
        self._iv_mode_s2r: pepmod.IvMode = pepmod.IvMode.SPEC
        self._iv_mode_r2s: pepmod.IvMode = pepmod.IvMode.SPEC
        self._initial_ctr: int = 0
        self._ctr_send: int = 0
        self._kv_send: int = 0
        self.last_mac_ok: Optional[bool] = None
        self.last_recv_raw: Optional[bytes] = None
        self._mac_fail_count: int = 0
        self.closed: bool = False

    def configure_pep(self, mode: pepmod.PepMode,
                      key_send: bytes, iv_send: int, kv_send: int,
                      key_recv: bytes, iv_recv: int,
                      iv_mode_s2r: pepmod.IvMode = pepmod.IvMode.SPEC,
                      iv_mode_r2s: pepmod.IvMode = pepmod.IvMode.SPEC,
                      pep_params: Optional[pepmod.PepParams] = None) -> None:
        """Enable PEP encrypt/decrypt on this channel.

        Each direction has its own privacy key derived from that
        direction's KEYVERSION (TR-10-13 dynamic key versioning).

        *key_send* / *iv_send* / *kv_send*: our outgoing (R2S) direction.
        *key_recv* / *iv_recv*: incoming (S2R) direction.
        *iv_mode_s2r* / *iv_mode_r2s*: byte-order modes for the iv'_ctr block.
        *pep_params*: retained for dynamic key re-derivation on KV changes.
        """
        self._pep_key_send = key_send
        self._pep_key_recv = key_recv
        self._pep_mode = mode
        self._iv_send = iv_send
        self._iv_recv = iv_recv
        self._kv_send = kv_send
        self._kv_recv: int = 0
        self._iv_mode_s2r = iv_mode_s2r
        self._iv_mode_r2s = iv_mode_r2s
        self._pep_params = pep_params
        self._ctr_send = self._initial_ctr

    @property
    def pep_active(self) -> bool:
        return self._pep_key_recv is not None

    # ------------------------------------------------------------------

    def send_msg(self, raw: bytes) -> tuple[int, IpmxUsbMessage]:
        """Send a pre-built IPMX message, encrypting if PEP is active.

        Returns ``(pcap_pkt_number, parsed_msg)`` where *parsed_msg*
        has decoded payload fields and the actual CTR/KEYVERSION that
        were sent on the wire.
        """
        # Parse plaintext for payload decode before any encryption
        parsed = usb.parse_one(raw)

        sent_ctr = 0
        sent_kv  = 0
        if self._pep_key_send is not None and self._iv_send is not None:
            sent_ctr = self._ctr_send
            sent_kv  = self._kv_send
            out = bytearray(raw)
            struct.pack_into('>Q', out, 0, sent_ctr)
            struct.pack_into('>I', out, 8, sent_kv)
            plaintext_for_verify = bytes(out)
            raw = pepmod.encrypt_usb_message(
                plaintext_for_verify, self._pep_key_send, self._iv_send,
                self._pep_mode, self._iv_mode_r2s)
            rt, rt_mac_ok = pepmod.decrypt_usb_message(
                raw, self._pep_key_send, self._iv_send,
                self._pep_mode, self._iv_mode_r2s)
            if not rt_mac_ok:
                logging.warning("SELF-TEST: our own encrypted message fails MAC!")
            self._ctr_send += pepmod.usb_ctr_advance(len(raw))
            parsed.ctr = sent_ctr
            parsed.key_version = sent_kv

        self.last_sent_raw = raw
        self._sock.sendall(raw)
        pkt_num = 0
        if self._capture:
            pkt_num = self._capture.record(
                raw, self.local_ip, self.local_port,
                self.remote_ip, self.remote_port,
            )
        return pkt_num, parsed

    def _decrypt_and_parse(self, raw: bytes) -> IpmxUsbMessage:
        """Decrypt *raw* with PEP, re-parse with zeroed header for payload decode.

        When MAC verification fails the decryption is untrustworthy: the
        message is returned as-is (encrypted, payload not decoded) so
        callers never see garbled field values.

        If the incoming KEYVERSION differs from the last one used, the
        decryption key is re-derived automatically (USB_KV protocol).
        """
        ctr = struct.unpack_from('>Q', raw, 0)[0]
        kv = struct.unpack_from('>I', raw, 8)[0]

        if kv != 0 and kv != self._kv_recv and self._pep_params is not None:
            self._pep_key_recv = self._pep_params.derive_key_for_version(kv)
            self._kv_recv = kv

        plaintext, mac_ok = pepmod.decrypt_usb_message(
            raw, self._pep_key_recv, self._iv_recv, self._pep_mode,
            self._iv_mode_s2r)
        self.last_mac_ok = mac_ok
        if not mac_ok:
            self._mac_fail_count += 1
            return usb.parse_one(raw)
        plain_for_parse = b'\x00' * 12 + plaintext[12:]
        msg = usb.parse_one(plain_for_parse)
        msg.ctr = ctr
        msg.key_version = kv
        return msg

    def recv_msg(self, timeout: float = 30.0) -> Optional[IpmxUsbMessage]:
        """
        Block until one complete IPMX USB message is available and return it.
        If PEP is active and the message is encrypted, it is decrypted
        transparently.  Returns None on timeout or connection close.
        """
        self.last_mac_ok = None
        deadline = time.monotonic() + timeout
        while True:
            if len(self._buf) >= usb.HEADER_SIZE:
                length = usb.peek_length(bytes(self._buf))
                if length is not None and len(self._buf) >= length:
                    raw = bytes(self._buf[:length])
                    del self._buf[:length]

                    ctr = struct.unpack_from('>Q', raw, 0)[0]
                    kv = struct.unpack_from('>I', raw, 8)[0]
                    is_enc = (ctr != 0 or kv != 0)

                    self.last_recv_raw = raw
                    if is_enc and self._pep_key_recv is not None and self._iv_recv is not None:
                        return self._decrypt_and_parse(raw)
                    return usb.parse_one(raw)

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None

            try:
                self._sock.settimeout(min(1.0, remaining))
                chunk = self._sock.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                self.closed = True
                return None

            if not chunk:
                self.closed = True
                return None

            if self._capture:
                self._capture.record(
                    chunk, self.remote_ip, self.remote_port,
                    self.local_ip, self.local_port,
                )
            self._buf.extend(chunk)

    def recv_raw(self, timeout: float = 30.0) -> Optional[bytes]:
        """Block until one complete raw IPMX message is available (no parsing/decryption)."""
        deadline = time.monotonic() + timeout
        while True:
            if len(self._buf) >= usb.HEADER_SIZE:
                length = usb.peek_length(bytes(self._buf))
                if length is not None and len(self._buf) >= length:
                    raw = bytes(self._buf[:length])
                    del self._buf[:length]
                    if self._capture:
                        self._capture.record(
                            raw, self.remote_ip, self.remote_port,
                            self.local_ip, self.local_port,
                        )
                    return raw

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                self._sock.settimeout(min(1.0, remaining))
                chunk = self._sock.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                self.closed = True
                return None
            if not chunk:
                self.closed = True
                return None
            self._buf.extend(chunk)

    def close(self) -> None:
        try:
            self._sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# IpmxReceiverSession — shared state and live validation
# ---------------------------------------------------------------------------

class IpmxReceiverSession:
    """
    Accumulates ChannelMessage objects from all threads and provides:
      - record_ctrl_msg() / record_data_msg()  — thread-safe message recording
      - run_validation()                        — re-run full validators, report new findings
      - log() / warn()                          — timestamped console output
    """

    def __init__(self, sender_ip: str, sender_ctrl_port: int,
                 our_ip: str, our_data_port: int,
                 our_cid: bytes, our_sn: str,
                 live_validate: bool = True,
                 encrypted: bool = False,
                 verbose: bool = False,
                 hid_only: bool = False,
                 pep_params: Optional[pepmod.PepParams] = None,
                 pep_key: Optional[bytes] = None,
                 kv_mode: pepmod.KvMode = pepmod.KvMode.RANDOM,
                 iv_mode_s2r: pepmod.IvMode = pepmod.IvMode.SPEC,
                 iv_mode_r2s: pepmod.IvMode = pepmod.IvMode.SPEC,
                 r2s_substreamid: int = 1,
                 initial_ctr: int = 0,
                 echo_version: bool = False,
                 iv_swapn: bool = False):
        self.sender_ip       = sender_ip
        self.sender_ctrl_port= sender_ctrl_port
        self.our_ip          = our_ip
        self.our_data_port   = our_data_port
        self.our_cid         = our_cid
        self.our_sn          = our_sn
        self.live_validate   = live_validate
        self.encrypted       = encrypted or (pep_params is not None)
        self.verbose         = verbose
        self.hid_only        = hid_only
        self.pep_params      = pep_params
        self.pep_key         = pep_key
        self.kv_mode         = kv_mode
        self.random_kv       = int.from_bytes(os.urandom(4), 'big') or 1
        self.iv_mode_s2r     = iv_mode_s2r
        self.iv_mode_r2s     = iv_mode_r2s
        self.r2s_substreamid = r2s_substreamid
        self.matrox_queries  = False
        self.initial_ctr     = initial_ctr
        self.echo_version    = echo_version
        self.iv_swapn        = iv_swapn

        # Session object used by validators (mirrored from usbDissector)
        self.session = Session(
            sender_ip   = sender_ip,
            sender_port = sender_ctrl_port,
            receiver_ip = our_ip,
        )

        # Per-direction message lists for the validators
        self.ctrl_sender_msgs:   list[ChannelMessage] = []
        self.ctrl_receiver_msgs: list[ChannelMessage] = []
        # substreamid → lists
        self.data_sender_msgs:   dict[int, list[ChannelMessage]] = {}
        self.data_receiver_msgs: dict[int, list[ChannelMessage]] = {}

        # Track findings already reported (avoid duplicates during incremental re-runs)
        self._reported_findings: set[tuple] = set()

        self._lock      = threading.Lock()
        self._pkt_counter = 0
        self.suppress_vq_log = False

    def resolve_r2s_kv(self, sender_kv: int, sdp_kv: int) -> int:
        """Determine the key_version to use for R2S messages."""
        if self.kv_mode == pepmod.KvMode.S2R:
            return sender_kv if sender_kv != 0 else (sdp_kv if sdp_kv != 0 else 1)
        if self.kv_mode == pepmod.KvMode.SDP:
            return sdp_kv if sdp_kv != 0 else 1
        return self.random_kv

    # ------------------------------------------------------------------
    # Reconnect: reset per-TCP-session state

    def reset_ctrl_for_reconnect(self) -> None:
        """Clear control-channel message lists and stale findings on reconnect.

        Each TCP connection is a separate session for validation purposes
        (e.g. KEYVERSION consistency is per-TCP-session).
        """
        with self._lock:
            self.ctrl_sender_msgs.clear()
            self.ctrl_receiver_msgs.clear()
            self._reported_findings.clear()

    def reset_data_for_reconnect(self, substreamid: int) -> None:
        """Clear data-channel message lists for *substreamid* on reconnect.

        Called when the Sender opens a new TCP connection for the same
        substreamid; ensures KEYVERSION consistency is checked per TCP session.
        """
        with self._lock:
            if substreamid in self.data_sender_msgs:
                self.data_sender_msgs[substreamid].clear()
            if substreamid in self.data_receiver_msgs:
                self.data_receiver_msgs[substreamid].clear()
            self._reported_findings.clear()

    # ------------------------------------------------------------------
    # Packet number allocation (shared across all channels)

    def next_pkt_num(self) -> int:
        with self._lock:
            self._pkt_counter += 1
            return self._pkt_counter

    # ------------------------------------------------------------------
    # Message recording

    def _make_cm(self, msg: IpmxUsbMessage,
                 src_ip: str, src_port: int,
                 dst_ip: str, dst_port: int,
                 pkt_num: int = 0) -> ChannelMessage:
        return ChannelMessage(
            packet_number = pkt_num or self.next_pkt_num(),
            timestamp     = time.time(),
            src_ip        = src_ip,
            src_port      = src_port,
            dst_ip        = dst_ip,
            dst_port      = dst_port,
            msg           = msg,
        )

    def record_ctrl_msg(self, msg: IpmxUsbMessage,
                        role: str,      # 'sender' or 'receiver'
                        src_ip: str, src_port: int,
                        dst_ip: str, dst_port: int,
                        pkt_num: int = 0) -> None:
        cm = self._make_cm(msg, src_ip, src_port, dst_ip, dst_port, pkt_num)
        with self._lock:
            if role == 'sender':
                self.ctrl_sender_msgs.append(cm)
            else:
                self.ctrl_receiver_msgs.append(cm)
        if self.verbose and not self.suppress_vq_log:
            arrow = "←" if role == 'sender' else "→"
            self.log(f"  CTRL {arrow} {msg.msg_type_name}  len={msg.length}")
        if self.live_validate and role == 'receiver':
            self._validate_and_report()

    def record_data_msg(self, msg: IpmxUsbMessage,
                        substreamid: int,
                        role: str,
                        src_ip: str, src_port: int,
                        dst_ip: str, dst_port: int,
                        pkt_num: int = 0) -> None:
        cm = self._make_cm(msg, src_ip, src_port, dst_ip, dst_port, pkt_num)
        with self._lock:
            if substreamid not in self.data_sender_msgs:
                self.data_sender_msgs[substreamid]   = []
                self.data_receiver_msgs[substreamid] = []
            if role == 'sender':
                self.data_sender_msgs[substreamid].append(cm)
            else:
                self.data_receiver_msgs[substreamid].append(cm)
        if self.verbose:
            arrow = "←" if role == 'sender' else "→"
            self.log(f"  DATA[{substreamid:#04x}] {arrow} {msg.msg_type_name}  len={msg.length}")
        if self.live_validate and role == 'receiver':
            self._validate_and_report()

    # ------------------------------------------------------------------
    # Live validation

    def _validate_and_report(self) -> None:
        with self._lock:
            ctrl_s = list(self.ctrl_sender_msgs)
            ctrl_r = list(self.ctrl_receiver_msgs)
            data_s = {k: list(v) for k, v in self.data_sender_msgs.items()}
            data_r = {k: list(v) for k, v in self.data_receiver_msgs.items()}
            sess   = self.session

        # Clear findings and re-run all validators
        sess.findings.clear()
        # Reset mutable channel states (validators repopulate them)
        sess.control = ControlChannel()
        sess.data_channels = {}

        # Only validate the control channel once both sides have spoken
        # (avoids transient false positives when SCI arrives before SCS is sent).
        if ctrl_s and ctrl_r:
            _validate_control_channel(
                sess, ctrl_s, ctrl_r,
                expected_cid=None, expected_sn=None,
                encrypted=self.encrypted,
            )

        for substreamid in set(data_s) | set(data_r):
            s_msgs = data_s.get(substreamid, [])
            r_msgs = data_r.get(substreamid, [])
            # Only validate once both sides have sent at least one message
            # to avoid transient false positives during stream setup.
            if not (s_msgs and r_msgs):
                continue
            channel = DataChannel(substreamid=substreamid, busid='', usbspeed=0)
            sess.data_channels[substreamid] = channel
            _validate_data_channel(
                sess, channel,
                s_msgs, r_msgs,
                encrypted=self.encrypted,
            )

        # Report only new findings
        current_keys = {
            (f.severity, f.section, f.description)
            for f in sess.findings
        }
        new_keys = current_keys - self._reported_findings
        self._reported_findings = current_keys

        if self.hid_only:
            return   # suppress all validation noise in --hid mode

        for f in sess.findings:
            key = (f.severity, f.section, f.description)
            if key in new_keys:
                color = "\033[91m" if f.severity == Severity.ERROR else "\033[93m"
                reset = "\033[0m"
                print(f"{color}  [LIVE {f.severity.value}] §{f.section}: {f.description}{reset}",
                      flush=True)

    def final_report(self) -> None:
        """Run a final validation pass and print the findings summary."""
        if self.hid_only:
            return   # --hid mode: skip report entirely, keep output clean
        self._validate_and_report()
        sess = self.session
        errors   = sum(1 for f in sess.findings if f.severity == Severity.ERROR)
        warnings = sum(1 for f in sess.findings if f.severity == Severity.WARNING)
        print("\n" + "=" * 68)
        print("Final Validation Report")
        print("=" * 68)
        for f in sess.findings:
            print(str(f))
        if not sess.findings:
            print("  [OK] No violations found")
        print(f"\nTotal: {errors} error(s), {warnings} warning(s)")

    # ------------------------------------------------------------------
    # Console output

    def log(self, msg: str) -> None:
        """Protocol/status log — suppressed by --hid (hid_only mode)."""
        if self.hid_only:
            return
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}] {msg}", flush=True)

    def hid(self, msg: str) -> None:
        """HID event output — shown with --verbose or --hid, suppressed otherwise."""
        if not (self.verbose or self.hid_only):
            return
        if self.hid_only:
            # Clean output: just the event, no timestamp
            print(msg, flush=True)
        else:
            ts = time.strftime("%H:%M:%S")
            print(f"[{ts}] {msg}", flush=True)

    def warn(self, msg: str) -> None:
        if self.hid_only:
            return
        self.log(f"\033[93mWARN: {msg}\033[0m")

    def error(self, msg: str) -> None:
        if self.hid_only:
            return
        self.log(f"\033[91mERR:  {msg}\033[0m")


# ---------------------------------------------------------------------------
# ControlChannelClient
# ---------------------------------------------------------------------------

class ControlChannelClient:
    """
    Connects to the Sender's control port, exchanges SenderConnectionInfo /
    SenderConnectionStatus, then maintains the heartbeat loop for the
    lifetime of the test.
    """

    def __init__(self, session: IpmxReceiverSession,
                 sender_ip: str, sender_ctrl_port: int,
                 our_cid: bytes, our_sn: str,
                 hbeat_index: int, data_port: int,
                 capture: Optional[PcapCapture] = None,
                 stop_event: Optional[threading.Event] = None,
                 data_server: Optional['DataChannelServer'] = None):
        self._session  = session
        self._addr     = (sender_ip, sender_ctrl_port)
        self._our_cid  = our_cid
        self._our_sn   = our_sn
        self._hbeat    = hbeat_index
        self._data_port= data_port
        self._capture  = capture
        self._stop     = stop_event or threading.Event()
        self._channel: Optional[IpmxChannel] = None
        self._data_server = data_server

        # Matrox hub-state simulation: real Receivers start with hub OFF,
        # then transition to ON after USB host initializes.  The Sender
        # opens data channels only when it receives a 0x81 (hub-change)
        # reply signalling the OFF→ON transition.
        self._hub_on = False
        self._hub_change_pending: Optional[bytes] = None  # queued 0x81 CID

        # VendorSpecificQuery log suppression: accumulate per-VQTYPE counts
        self._vq_counts: dict[int, int] = {}
        self._vq_first_time: float = 0.0
        self._vq_logged_first: set[int] = set()

    def _flush_vq_repeat(self, sess: IpmxReceiverSession) -> None:
        """Print a summary line for suppressed VendorSpecificQuery bursts."""
        total = sum(self._vq_counts.values())
        if total > 0:
            elapsed = time.monotonic() - self._vq_first_time
            rate = total / elapsed if elapsed > 0 else 0
            parts = ", ".join(f"0x{vq:02X}×{n}" for vq, n in sorted(self._vq_counts.items()))
            sess.log(f"  ... VQ burst: {total} queries in {elapsed:.1f}s "
                     f"({rate:.1f}/s) [{parts}]")
        self._vq_counts.clear()
        self._vq_first_time = 0.0
        self._vq_logged_first.clear()

    def shutdown(self) -> None:
        """Close the control socket immediately, unblocking any recv in progress."""
        if self._channel is not None:
            self._channel.close()

    def run(self) -> None:
        """Blocking; call from a dedicated thread.

        Wraps :meth:`_run_once` in a retry loop so the tester survives
        Sender-initiated disconnects and automatically reconnects.
        """
        sess = self._session
        attempt = 0
        while not self._stop.is_set():
            attempt += 1
            try:
                self._run_once(attempt)
            except (ConnectionError, OSError, BrokenPipeError) as exc:
                if self._stop.is_set():
                    break
                sess.warn(f"Control channel lost: {exc}")

            if self._stop.is_set():
                break

            if self._data_server is not None:
                self._data_server.shutdown_all()

            self._vq_counts.clear()
            self._vq_first_time = 0.0
            self._vq_logged_first.clear()
            self._channel = None

            if getattr(self, '_cmac_failed_on_sci', False):
                delay = 5.0
                sess.log("Reconnect delayed 5 s (CMAC mismatch — "
                         "check PSK / SDP key derivation parameters)")
            else:
                delay = 3.0
            self._stop.wait(timeout=delay)

    def _run_once(self, attempt: int = 1) -> None:
        """Single control-channel connection cycle."""
        sess = self._session
        self._cmac_failed_on_sci = False
        self._hub_on = False
        self._hub_change_pending = None

        if attempt > 1:
            sess.reset_ctrl_for_reconnect()
            sess.log(f"Reconnecting to Sender control channel "
                     f"{self._addr[0]}:{self._addr[1]} (attempt {attempt}) …")
        else:
            sess.log(f"Connecting to Sender control channel "
                     f"{self._addr[0]}:{self._addr[1]} …")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(self._addr)

        local_ip, local_port = sock.getsockname()
        sess.log(f"Control TCP local endpoint: {local_ip}:{local_port} "
                 f"(Sender will connect data channel to {local_ip}:{self._data_port})")
        ch = IpmxChannel(sock, local_ip, local_port,
                         self._addr[0], self._addr[1],
                         capture=self._capture)
        ch._initial_ctr = sess.initial_ctr
        self._channel = ch

        # Step 1 — receive SenderConnectionInfo (raw, before PEP is
        #   configured, so we can read the actual KEYVERSION and derive
        #   the correct key for _KV protocols).
        sess.log("Waiting for SenderConnectionInfo …")
        raw = ch.recv_raw(timeout=30.0)
        if raw is None:
            sess.error("Timeout waiting for SenderConnectionInfo")
            self._stop.set()
            return

        # Configure PEP on control channel (substreamid=0).
        # Each direction has its own KEYVERSION and derived key.
        # The Sender's KEYVERSION is read from its first message;
        # the Receiver (us) selects its own initial KEYVERSION.
        if sess.pep_params and sess.pep_key:
            pp = sess.pep_params
            sender_kv = struct.unpack_from('>I', raw, 8)[0]
            sdp_kv = int.from_bytes(pp.key_version, 'big')

            # Derive key for decrypting incoming (S2R) — use Sender's KEYVERSION
            if pp.is_kv and sender_kv != 0:
                key_recv = pp.derive_key_for_version(sender_kv)
                if sender_kv != sdp_kv:
                    sess.log(f"  Sender KEYVERSION=0x{sender_kv:08X} "
                             f"(SDP had 0x{sdp_kv:08X}), re-derived recv key")
            else:
                key_recv = sess.pep_key

            our_kv = sess.resolve_r2s_kv(sender_kv, sdp_kv)
            if pp.is_kv:
                key_send = pp.derive_key_for_version(our_kv)
            else:
                key_send = sess.pep_key

            iv_s2r = pepmod.compute_iv_prime(pp.iv, 0, sess.iv_mode_s2r)
            iv_r2s = pepmod.compute_iv_prime(pp.iv, sess.r2s_substreamid,
                                             sess.iv_mode_r2s)
            ch.configure_pep(pp.mode,
                             key_send=key_send, iv_send=iv_r2s, kv_send=our_kv,
                             key_recv=key_recv, iv_recv=iv_s2r,
                             iv_mode_s2r=sess.iv_mode_s2r,
                             iv_mode_r2s=sess.iv_mode_r2s,
                             pep_params=pp)

        # Now parse the SCI (channel decrypts if PEP is active)
        ctr = struct.unpack_from('>Q', raw, 0)[0]
        kv = struct.unpack_from('>I', raw, 8)[0]
        is_enc = (ctr != 0 or kv != 0)
        if is_enc and ch.pep_active:
            msg = ch._decrypt_and_parse(raw)
            if ch.last_mac_ok is False:
                self._cmac_failed_on_sci = True
                sess.warn("CMAC verification FAILED on SenderConnectionInfo "
                          "— decryption key is wrong (check PSK / key derivation)")
        else:
            msg = usb.parse_one(raw)

        if msg is None:
            sess.error("Failed to parse SenderConnectionInfo")
            self._stop.set()
            return
        if msg.msg_type_enum != MsgType.SENDER_CONNECTION_INFO:
            sess.error(f"Expected SenderConnectionInfo, got {msg.msg_type_name}")
            self._stop.set()
            return

        sess.record_ctrl_msg(msg, 'sender',
                             self._addr[0], self._addr[1],
                             local_ip, local_port)
        sender_maver = 0
        sender_miver = 0
        if not msg.payload.get('_encrypted'):
            info = msg.payload
            sender_maver = info.get('maver', 0)
            sender_miver = info.get('miver', 0)
            sess.log(f"  Sender CID={info.get('cid','?')}  "
                     f"SN='{info.get('sn','?')}'  "
                     f"v{sender_maver}.{sender_miver}")
            # §9.1: MAVER and MIVER SHALL be 0 for this version
            if sender_maver != 0:
                sess.error(f"§9.1: SenderConnectionInfo MAVER={sender_maver}; SHALL be 0")
            if sender_miver != 0:
                sess.error(f"§9.1: SenderConnectionInfo MIVER={sender_miver}; SHALL be 0")
            # §9.1: Reserved byte (byte 1 of DATA) SHALL be 0
            if len(msg.data) >= 2 and msg.data[1] != 0:
                sess.error(f"§9.1: SenderConnectionInfo Reserved byte=0x{msg.data[1]:02X}; SHALL be 0")
            # §9.1: DATA SHALL be 66 bytes
            if len(msg.data) != 66:
                sess.error(f"§9.1: SenderConnectionInfo DATA={len(msg.data)}B; SHALL be 66B")
        elif is_enc:
            sess.log("  (encrypted — cannot decrypt, payload not shown)")

        # §9.2: SCS version SHALL be ≤ Sender's, and SHALL be 0.0 for this spec.
        # Default: spec-compliant 0.0.  We still log the Sender's value above.
        scs_raw = usb.build_sender_connection_status(
            self._our_cid, self._our_sn, self._hbeat, self._data_port,
            maver=sender_maver if sess.echo_version else 0,
            miver=sender_miver if sess.echo_version else 0,
        )
        if sess.verbose:
            # Dump the cleartext DATA portion of SenderConnectionStatus
            # Header: CTR(8)+KV(4)+MSGTYPE(1)+RsvLen(3) = 16 bytes
            # DATA starts at offset 16, MAC is last 8 bytes
            scs_data = scs_raw[16:-8] if len(scs_raw) > 24 else scs_raw[16:]
            sess.log(f"  SCS cleartext DATA ({len(scs_data)}B): {scs_data.hex()}")
            # Parse the DATA: ver(1) hbeat(1) port(2) cid(3) sn(61)
            if len(scs_data) >= 4:
                ver_byte = scs_data[0]
                hb = scs_data[1] & 0x1F
                port_val = int.from_bytes(scs_data[2:4], 'big')
                cid_hex = scs_data[4:7].hex().upper()
                sn_str = scs_data[7:68].rstrip(b'\x00').decode('utf-8', errors='replace')
                sess.log(f"  SCS fields: MAVER={ver_byte>>4} MIVER={ver_byte&0xF} "
                         f"HBEAT={hb} PORT={port_val} CID={cid_hex} SN='{sn_str}'")
        pkt_num, scs_msg = ch.send_msg(scs_raw)
        sess.record_ctrl_msg(scs_msg, 'receiver',
                             local_ip, local_port,
                             self._addr[0], self._addr[1],
                             pkt_num=pkt_num)
        if sess.verbose and ch.pep_active:
            sess.log(f"  S2R decrypt: key={key_recv.hex()} iv'=0x{iv_s2r:016X} "
                     f"KV=0x{sender_kv:08X} CTR={struct.unpack_from('>Q', raw, 0)[0]} "
                     f"iv_mode={sess.iv_mode_s2r.value} ssid=0")
            sess.log(f"  R2S encrypt: key={key_send.hex()} iv'=0x{iv_r2s:016X} "
                     f"KV=0x{our_kv:08X} CTR={scs_msg.ctr} "
                     f"iv_mode={sess.iv_mode_r2s.value} ssid={sess.r2s_substreamid} "
                     f"kv_mode={sess.kv_mode.value}")
        sess.log(f"  Sent SenderConnectionStatus (data_port={self._data_port}, hbeat={self._hbeat})")

        # Step 3 — heartbeat + message loop
        hbeat_period = _heartbeat_period(self._hbeat)
        last_hbeat   = time.monotonic()
        sess.log(f"Control channel active (heartbeat period ≈ {hbeat_period:.0f} s)")

        while not self._stop.is_set():
            msg = ch.recv_msg(timeout=1.0)

            if msg is None:
                if ch.closed:
                    sess.warn("Sender closed the TCP connection")
                    break
                # Section 11 SHALL: disconnect non-responsive Sender
                elapsed = time.monotonic() - last_hbeat
                limit = hbeat_period * 2.0
                if elapsed > limit:
                    sess.warn(
                        f"Heartbeat timeout — Sender non-responsive for "
                        f"{elapsed:.1f}s (limit {limit:.1f}s). "
                        f"Disconnecting per Section 11.")
                    sess.session.findings.append(Finding(
                        severity=Severity.ERROR,
                        section="11",
                        message=(
                            f"Sender failed to send Heartbeat within "
                            f"2x period ({limit:.1f}s); "
                            f"elapsed {elapsed:.1f}s — SHALL violation"),
                        packet_number=0,
                    ))
                    if self._data_server is not None:
                        self._data_server.shutdown_all()
                    ch.close()
                    break
                continue

            if ch.last_mac_ok is False and ch._mac_fail_count == 1:
                sess.warn("CMAC verification FAILED — cannot decrypt "
                          "(wrong PSK or key derivation mismatch)")

            mt = msg.msg_type_enum

            if mt != MsgType.VENDOR_SPECIFIC_QUERY and self._vq_counts:
                self._flush_vq_repeat(sess)

            # Suppress CTRL ←/→ logging for repeated VQ bursts
            if mt == MsgType.VENDOR_SPECIFIC_QUERY:
                encrypted_pl = msg.payload.get('_encrypted', False)
                vqt = msg.payload.get('vqtype', 255) if not encrypted_pl else 255
                sess.suppress_vq_log = (vqt in self._vq_logged_first)
            else:
                sess.suppress_vq_log = False

            sess.record_ctrl_msg(msg, 'sender',
                                 self._addr[0], self._addr[1],
                                 local_ip, local_port)

            if mt == MsgType.HEARTBEAT:
                last_hbeat = time.monotonic()
                if sess.verbose:
                    sess.log(f"  HEARTBEAT received")

            elif mt == MsgType.VENDOR_SPECIFIC_QUERY:
                encrypted_payload = msg.payload.get('_encrypted', False)
                vqtype = msg.payload.get('vqtype', 255) if not encrypted_payload else 255
                query_cid = bytes.fromhex(msg.payload.get('cid', '000000')) if not encrypted_payload else self._our_cid

                reply: Optional[bytes] = None
                status_label = ""

                if vqtype == 0:
                    # §9.6: All Receivers SHALL respond with no error to VQTYPE=0.
                    info_str = f"{self._our_sn}".encode('utf-8')[:256]
                    reply = usb.build_vendor_specific_query_return(
                        query_cid, vqtype, vqsts=0, vqdata=info_str)
                    status_label = f"OK ({info_str.decode()})"
                elif 1 <= vqtype <= 15:
                    # §9.6: Reserved VQTYPEs — respond unsupported.
                    reply = usb.build_vendor_specific_query_return(
                        query_cid, vqtype, vqsts=255)
                    status_label = "UNKNOWN (reserved)"
                elif sess.matrox_queries and vqtype == 0x80:
                    hub_val = b'\x01' if self._hub_on else b'\x00'
                    reply = usb.build_vendor_specific_query_return(
                        query_cid, vqtype, vqsts=0, vqdata=hub_val)
                    if self._hub_on:
                        status_label = "OK hub=ON (Matrox 0x80)"
                    else:
                        status_label = "OK hub=OFF (Matrox 0x80, will turn ON via 0x81)"
                elif sess.matrox_queries and vqtype == 0x81:
                    if not self._hub_on:
                        self._hub_change_pending = query_cid
                        status_label = "queued hub-change (Matrox 0x81, hub OFF→ON pending)"
                    else:
                        status_label = "queued hub-change (Matrox 0x81, hub already ON)"
                elif sess.matrox_queries and vqtype == 0x90:
                    reply = usb.build_vendor_specific_query_return(
                        query_cid, vqtype, vqsts=0, vqdata=b'\x00')
                    status_label = "OK leds=0x00 (Matrox 0x90)"
                elif sess.matrox_queries and vqtype == 0x91:
                    status_label = "queued led-change (Matrox 0x91, no reply)"
                else:
                    # §9.6: Unknown vendor VQTYPE — respond unsupported.
                    reply = usb.build_vendor_specific_query_return(
                        query_cid, vqtype, vqsts=255)
                    status_label = f"UNSUPPORTED (0x{vqtype:02X})"

                if reply is not None:
                    pkt_num, reply_msg = ch.send_msg(reply)
                    sess.record_ctrl_msg(reply_msg, 'receiver',
                                         local_ip, local_port,
                                         self._addr[0], self._addr[1],
                                         pkt_num=pkt_num)

                log_line = f"VendorSpecificQuery CID={query_cid.hex().upper()} VQTYPE={vqtype} (0x{vqtype:02X}) → {status_label}"
                if vqtype not in self._vq_logged_first:
                    self._vq_logged_first.add(vqtype)
                    sess.log(f"  {log_line}")
                if not self._vq_counts:
                    self._vq_first_time = time.monotonic()
                self._vq_counts[vqtype] = self._vq_counts.get(vqtype, 0) + 1
                sess.suppress_vq_log = False

                # Deferred hub ON: once the 0x81 subscription arrives and
                # the hub hasn't turned ON yet, simulate the USB host
                # coming up by sending a 0x81 reply with hub=1.
                if self._hub_change_pending is not None and not self._hub_on:
                    self._hub_on = True
                    hub_cid = self._hub_change_pending
                    self._hub_change_pending = None
                    hub_reply = usb.build_vendor_specific_query_return(
                        hub_cid, 0x81, vqsts=0, vqdata=b'\x01')
                    pkt_num, hub_msg = ch.send_msg(hub_reply)
                    sess.record_ctrl_msg(hub_msg, 'receiver',
                                         local_ip, local_port,
                                         self._addr[0], self._addr[1],
                                         pkt_num=pkt_num)
                    sess.log("  Hub turned ON → sent 0x81 hub-change reply (hub=1)")

            elif mt == MsgType.USB_ENTER_SLEEP:
                sess.log("  USB Enter Sleep received — test will stop")
                self._stop.set()

            elif mt == MsgType.VENDOR_SPECIFIC_INFO:
                vi_cid = msg.payload.get('cid', '?')
                vi_vmtype = msg.payload.get('vmtype', -1)
                if vi_vmtype == 0:
                    vi_detail = msg.payload.get('vmdata_str', '')
                    sess.log(f"  VendorSpecificInfo CID={vi_cid} VMTYPE=0 str='{vi_detail}'")
                else:
                    vi_hex = msg.payload.get('vmdata', '')
                    sess.log(f"  VendorSpecificInfo CID={vi_cid} VMTYPE={vi_vmtype} data={vi_hex}")

        self._flush_vq_repeat(sess)
        ch.close()
        sess.log("Control channel closed")


# ---------------------------------------------------------------------------
# DataChannelHandler — USB enumeration + interrupt polling
# ---------------------------------------------------------------------------

class DataChannelHandler:
    """
    Handles one accepted data channel connection from the Sender:
      1. Receive USBStreamInfo, send USBStreamStatus
      2. Run USB enumeration (as USB host)
      3. Poll interrupt IN endpoint for HID events
    """

    def __init__(self, session: IpmxReceiverSession,
                 sock: socket.socket,
                 local_ip: str, local_port: int,
                 remote_ip: str, remote_port: int,
                 poll_interval_ms: float,
                 capture: Optional[PcapCapture] = None,
                 stop_event: Optional[threading.Event] = None):
        self._session   = session
        self._ch        = IpmxChannel(sock, local_ip, local_port,
                                      remote_ip, remote_port,
                                      capture=capture)
        self._ch._initial_ctr = session.initial_ctr
        self._poll_ms   = poll_interval_ms
        self._stop      = stop_event or threading.Event()
        self._seqnum    = 0
        self._substreamid: Optional[int] = None
        self._prev_hid: bytes = b''   # last HID report; used to suppress repeated reports

    def shutdown(self) -> None:
        """Close the data socket immediately, unblocking any recv in progress."""
        self._ch.close()

    # ------------------------------------------------------------------

    def _send(self, raw: bytes, role: str = 'receiver') -> None:
        """Send a message and record it in the session."""
        ch = self._ch
        pkt_num, msg = ch.send_msg(raw)
        if self._session.verbose:
            wire_hex = ch.last_sent_raw.hex() if ch.last_sent_raw else "?"
            self._session.log(
                f"    send raw ({len(ch.last_sent_raw) if ch.last_sent_raw else 0}B): "
                f"{wire_hex}")
            self._session.log(
                f"    send KV=0x{msg.key_version:08X} CTR={msg.ctr} "
                f"type=0x{msg.msg_type:02X} ({msg.msg_type_name})")
        if self._substreamid is not None:
            self._session.record_data_msg(
                msg, self._substreamid, role,
                ch.local_ip, ch.local_port,
                ch.remote_ip, ch.remote_port,
                pkt_num=pkt_num,
            )

    def _recv(self, timeout: float = 10.0) -> Optional[IpmxUsbMessage]:
        """Receive and record one message from the Sender."""
        ch = self._ch
        msg = ch.recv_msg(timeout=timeout)
        if msg is not None:
            mac_ok = ch.last_mac_ok
            if mac_ok is False and ch._mac_fail_count == 1:
                self._session.warn(
                    f"Data channel (substreamid=0x{self._substreamid or 0:02X}): "
                    "CMAC verification FAILED — cannot decrypt")
            if self._session.verbose:
                raw_hex = ch.last_recv_raw.hex() if ch.last_recv_raw else "?"
                self._session.log(
                    f"    recv raw ({len(ch.last_recv_raw) if ch.last_recv_raw else 0}B): "
                    f"{raw_hex}")
                self._session.log(
                    f"    recv KV=0x{msg.key_version:08X} CTR={msg.ctr} "
                    f"mac_ok={mac_ok} type=0x{msg.msg_type:02X} "
                    f"({msg.msg_type_name})")
                if mac_ok is not False and msg.payload:
                    pl = {k: v for k, v in msg.payload.items()
                          if k != '_encrypted'}
                    if pl:
                        self._session.log(f"    payload: {pl}")
            if self._substreamid is not None:
                self._session.record_data_msg(
                    msg, self._substreamid, 'sender',
                    ch.remote_ip, ch.remote_port,
                    ch.local_ip, ch.local_port,
                )
        return msg

    # ------------------------------------------------------------------

    def _ctrl_transfer(self, req: bytes, transferlength: int,
                       binterval: int = 0,
                       retries: int = 0) -> Optional[IpmxUsbMessage]:
        """
        Issue one USB control transfer (submit + wait for return).
        Returns the SUBMIT_RETURN message, or None on failure.
        *retries* — number of additional attempts on STALL before giving up.
        """
        _STALL_PID = 0xC0000004
        endpoint  = 0     # default control endpoint
        direction = 1 if (req[0] & 0x80) else 0   # bmRequestType bit 7

        for attempt in range(1 + retries):
            self._send(usb.build_usb_control_submit(
                self._seqnum, endpoint, direction, binterval,
                transferlength, req,
            ))
            ret = self._recv(timeout=10.0)
            if ret is None:
                if self._ch.closed:
                    self._session.warn(
                        f"Sender closed data channel before replying to "
                        f"CONTROL_SUBMIT seq={self._seqnum}")
                else:
                    self._session.warn(
                        f"Timeout (10 s) on CONTROL_SUBMIT_RETURN "
                        f"seq={self._seqnum}")
                return None

            is_submit_return = (ret.msg_type_name
                                and 'SUBMIT_RETURN' in ret.msg_type_name)
            if ret.msg_type_enum != MsgType.USB_CONTROL_SUBMIT_RETURN:
                if is_submit_return:
                    self._session.log(
                        f"    Note: Sender replied with {ret.msg_type_name} "
                        f"instead of CONTROL_SUBMIT_RETURN")
                else:
                    self._session.warn(
                        f"Expected CONTROL_SUBMIT_RETURN, got "
                        f"{ret.msg_type_name}")
                    return None

            rstatus = ret.payload.get('rstatus', 0) if ret.payload else 0
            if rstatus == _STALL_PID and attempt < retries:
                self._session.log(
                    f"    STALL on attempt {attempt + 1}/{1 + retries}, "
                    f"retrying in 0.5 s …")
                self._seqnum += 1
                time.sleep(0.5)
                continue

            self._seqnum += 1
            return ret

        return None

    # ------------------------------------------------------------------

    def _discover_substreamid(self, raw: bytes) -> tuple[int, int]:
        """Brute-force even substreamid values on an encrypted USBStreamInfo.

        The Matrox Sender encrypts the first data-channel message
        (USBStreamInfo) with a *handshake* substreamid
        (RECEIVER_SERVER_STREAMID = 2), not with the per-device
        substreamid carried inside the payload.  After USBStreamStatus
        is exchanged both sides switch to the payload substreamid.

        Returns ``(handshake_ssid, payload_ssid)`` where:

        * *handshake_ssid* – encryption substreamid for the first
          message exchange (USBStreamInfo + USBStreamStatus).
        * *payload_ssid* – substreamid from the USBStreamInfo payload,
          used for all subsequent data messages.

        PEP is configured for the handshake phase on return; the caller
        must call :meth:`_switch_pep_to_data` after sending
        USBStreamStatus to switch to the payload substreamid.
        """
        sess = self._session
        ch   = self._ch
        pp   = sess.pep_params
        assert pp is not None and sess.pep_key is not None

        sender_kv = struct.unpack_from('>I', raw, 8)[0]
        sdp_kv = int.from_bytes(pp.key_version, 'big')

        # Derive recv key (Sender's direction)
        if pp.is_kv and sender_kv != 0:
            key_recv = pp.derive_key_for_version(sender_kv)
        else:
            key_recv = sess.pep_key

        our_kv = sess.resolve_r2s_kv(sender_kv, sdp_kv)
        if pp.is_kv:
            key_send = pp.derive_key_for_version(our_kv)
        else:
            key_send = sess.pep_key

        # IV mode for data channel substreamid addition:
        # --iv-swapn → SWAP (same trick as --iv-s2r-swap0 / --iv-r2s-swap1)
        dc_iv_mode = pepmod.IvMode.SWAP if sess.iv_swapn else pepmod.IvMode.SPEC

        # Store PEP parameters for _switch_pep_to_data()
        self._dc_key_recv = key_recv
        self._dc_key_send = key_send
        self._dc_our_kv   = our_kv
        self._dc_iv_mode  = dc_iv_mode

        for candidate in range(0, 256, 2):
            iv_s2r = pepmod.compute_iv_prime(pp.iv, candidate, dc_iv_mode)
            try:
                rebuilt, mac_ok = pepmod.decrypt_usb_message(
                    raw, key_recv, iv_s2r, pp.mode, sess.iv_mode_s2r)
            except Exception:
                continue
            if mac_ok:
                plain_data = rebuilt[16:-8]
                payload_ssid = plain_data[0] if len(plain_data) >= 1 else candidate

                if payload_ssid != candidate:
                    sess.log(f"  Handshake substreamid=0x{candidate:02X}, "
                             f"payload substreamid=0x{payload_ssid:02X} "
                             f"(will switch after USBStreamStatus)")

                ctr_val = struct.unpack_from('>Q', raw, 0)[0]
                r2s_ssid = candidate | 1
                iv_r2s = pepmod.compute_iv_prime(pp.iv, r2s_ssid, dc_iv_mode)

                sess.log(f"  S2R decrypt: key={key_recv.hex()} "
                         f"iv'=0x{iv_s2r:016X} "
                         f"KV=0x{sender_kv:08X} CTR={ctr_val} "
                         f"iv_mode={dc_iv_mode.value} "
                         f"ssid={candidate}")
                sess.log(f"  R2S encrypt: key={key_send.hex()} "
                         f"iv'=0x{iv_r2s:016X} "
                         f"KV=0x{our_kv:08X} CTR={sess.initial_ctr} "
                         f"iv_mode={dc_iv_mode.value} "
                         f"ssid={r2s_ssid} "
                         f"kv_mode={sess.kv_mode.value}")
                ch.configure_pep(pp.mode,
                                 key_send=key_send, iv_send=iv_r2s,
                                 kv_send=our_kv,
                                 key_recv=key_recv, iv_recv=iv_s2r,
                                 iv_mode_s2r=dc_iv_mode,
                                 iv_mode_r2s=dc_iv_mode,
                                 pep_params=pp)
                return (candidate, payload_ssid)

        sess.warn("Could not determine substreamid — CMAC failed for all candidates")
        return (0, 0)

    def _switch_pep_to_data(self, payload_ssid: int) -> None:
        """Reconfigure PEP for the per-device data substreamid.

        Called after USBStreamStatus has been sent with the handshake
        PEP.  Computes new iv' values for the payload substreamid pair
        (even = S2R, odd = R2S) and reconfigures the channel.
        """
        sess = self._session
        ch   = self._ch
        pp   = sess.pep_params
        assert pp is not None

        # CTR resets to 0 (spec) at every ACCEPT (new TCP connection),
        # which configure_pep already handles.  Within the same
        # connection, SetSubStreamID does NOT reset CTR — it continues
        # from the handshake phase (USBStreamStatus encrypted with
        # substreamid 2/3).  We must preserve _ctr_send here because
        # configure_pep would otherwise reset it.
        prev_ctr_send = ch._ctr_send

        iv_s2r = pepmod.compute_iv_prime(pp.iv, payload_ssid, self._dc_iv_mode)
        iv_r2s = pepmod.compute_iv_prime(pp.iv, payload_ssid | 1, self._dc_iv_mode)
        ch.configure_pep(pp.mode,
                         key_send=self._dc_key_send, iv_send=iv_r2s,
                         kv_send=self._dc_our_kv,
                         key_recv=self._dc_key_recv, iv_recv=iv_s2r,
                         iv_mode_s2r=self._dc_iv_mode,
                         iv_mode_r2s=self._dc_iv_mode,
                         pep_params=pp)
        ch._ctr_send = prev_ctr_send

        sess.log(f"  PEP switched: "
                 f"S2R iv'=0x{iv_s2r:016X} ssid={payload_ssid}  "
                 f"R2S iv'=0x{iv_r2s:016X} ssid={payload_ssid | 1}  "
                 f"KV=0x{self._dc_our_kv:08X} next_CTR={prev_ctr_send}")

    def run(self) -> None:
        """Blocking; call from a dedicated thread."""
        sess  = self._session
        ch    = self._ch
        rip   = ch.remote_ip
        rport = ch.remote_port

        # Step 1 — receive USBStreamInfo
        # Read raw first so we can brute-force substreamid before configuring PEP.
        raw = ch.recv_raw(timeout=15.0)
        if raw is None:
            sess.error("Timeout waiting for USBStreamInfo")
            ch.close()
            return

        ctr = struct.unpack_from('>Q', raw, 0)[0]
        kv = struct.unpack_from('>I', raw, 8)[0]
        is_enc = (ctr != 0 or kv != 0)

        handshake_ssid = 0
        payload_ssid = 0
        if is_enc and sess.pep_key and sess.pep_params:
            handshake_ssid, payload_ssid = self._discover_substreamid(raw)

        # Parse USBStreamInfo (PEP is configured for handshake substreamid)
        if ch.pep_active and is_enc:
            msg = ch._decrypt_and_parse(raw)
        else:
            msg = usb.parse_one(raw)

        if msg.msg_type_enum != MsgType.USB_STREAM_INFO:
            sess.error(f"Expected USBStreamInfo, got {msg.msg_type_name}")
            ch.close()
            return

        # The USBStreamInfo payload carries the substreamid that uniquely
        # identifies this data channel.  Use it as the channel key for
        # message grouping (validation tracks SEQNUMs per channel).
        # In encrypted mode _discover_substreamid() already extracted it;
        # for unencrypted we read it from the parsed payload.
        if not msg.payload.get('_encrypted'):
            substreamid = msg.payload.get('substreamid', 0)
        else:
            substreamid = payload_ssid if payload_ssid else handshake_ssid
        self._substreamid = substreamid

        if not msg.payload.get('_encrypted'):
            sess.log(f"Data channel connected: substreamid=0x{substreamid:02X}  "
                     f"busid='{msg.payload.get('busid','?')}'  "
                     f"speed={msg.payload.get('usbspeed_name','?')}")
        else:
            sess.log(f"Data channel connected (encrypted, substreamid=0x{substreamid:02X})")

        sess.reset_data_for_reconnect(substreamid)

        # Record USBStreamInfo (Sender-originated)
        sess.record_data_msg(
            msg, substreamid, 'sender',
            rip, rport, ch.local_ip, ch.local_port,
        )

        # Step 2 — send USBStreamStatus with the handshake PEP (base=2,
        # R2S=3) matching SecureReceiver.cpp: "Send status before update
        # SubStreamID".  Then switch to the payload substreamid.
        self._send(usb.build_usb_stream_status(0))
        sess.log("  Sent USBStreamStatus(0) → stream accepted")

        if is_enc and payload_ssid != 0 and payload_ssid != handshake_ssid:
            self._switch_pep_to_data(payload_ssid)

        # Wait for the Sender's stub driver to bind the physical device.
        # The Sender calls BindDevice + StartStubChannel + OpenUSBStream
        # sequentially; 1 s gives the USB stack time to be ready.
        time.sleep(1.0)

        # Step 3 — USB enumeration
        interrupt_ep = self._enumerate()

        if interrupt_ep is None:
            sess.warn("No HID interrupt IN endpoint found — skipping polling")
            self._idle_loop()
            return

        # Step 4 — HID interrupt polling loop (re-enters after USB_STREAM_RESET)
        while interrupt_ep is not None and not self._stop.is_set():
            sess.log(f"  Polling interrupt endpoint 0x{interrupt_ep.address:02X}  "
                     f"interval={interrupt_ep.interval} ms  "
                     f"maxpkt={interrupt_ep.max_packet} B")
            interrupt_ep = self._poll_loop(interrupt_ep)

        ch.close()
        sess.log(f"Data channel 0x{substreamid:02X} closed")

    # ------------------------------------------------------------------

    def _enumerate(self) -> Optional[EndpointInfo]:
        """
        Drive the USB host enumeration sequence against the real device.

        Returns the interrupt IN endpoint if found, None otherwise.
        """
        sess = self._session
        sess.log("  Starting USB enumeration …")

        def _xfr(ret) -> bytes:
            """Extract USB transfer data bytes from a SUBMIT_RETURN payload.

            The payload stores transferdata as a hex string (see decoder);
            convert back to bytes for USB descriptor parsing.
            """
            if ret is None or ret.payload.get('_encrypted'):
                return b''
            td = ret.payload.get('transferdata') or ''
            if isinstance(td, str):
                return bytes.fromhex(td) if td else b''
            return bytes(td)

        def _ok(ret: Optional[IpmxUsbMessage]) -> bool:
            if ret is None:
                return False
            return ret.payload.get('rstatus', -1) == 0

        def _status(ret: Optional[IpmxUsbMessage]) -> str:
            if ret is None:
                return "timeout/closed"
            rs = ret.payload.get('rstatus', -1)
            rn = ret.payload.get('rstatus_name', '?')
            return f"0x{rs:08X} ({rn})"

        max_pkt0     = 8
        device_class = 0
        num_strings  = 0
        int_ep: Optional[EndpointInfo] = None
        fatal = False   # only set when Sender closes the connection

        # 1. GET_DESCRIPTOR(Device, 8) — learn bMaxPacketSize0
        #    Retry up to 5 times on STALL: the Sender's stub driver may still
        #    be binding the physical device.
        ret = self._ctrl_transfer(
            _get_descriptor_req(USB_DT_DEVICE, 0, 8), 8, retries=5)
        if ret is None and self._ch.closed:
            fatal = True
        if _ok(ret):
            dev8 = _xfr(ret)
            max_pkt0 = dev8[7] if len(dev8) >= 8 else 8
            sess.log(f"    GET_DESCRIPTOR(Device,8): OK  "
                     f"max_pkt0={max_pkt0}  data={dev8.hex() or '(empty)'}")
        elif not fatal:
            sess.warn(f"GET_DESCRIPTOR(Device,8): {_status(ret)}")

        # 2. SET_ADDRESS(3)
        if not fatal:
            ret = self._ctrl_transfer(_set_address_req(3), 0)
            if ret is None and self._ch.closed:
                fatal = True
            elif not _ok(ret):
                sess.warn(f"SET_ADDRESS(3): {_status(ret)}")

        # 3. GET_DESCRIPTOR(Device, 18) — full device descriptor
        if not fatal:
            ret = self._ctrl_transfer(
                _get_descriptor_req(USB_DT_DEVICE, 0, 18), 18)
            if ret is None and self._ch.closed:
                fatal = True
            if _ok(ret):
                raw_dev = _xfr(ret)
                device_class = raw_dev[4]  if len(raw_dev) >= 5  else 0
                num_strings  = raw_dev[14] if len(raw_dev) >= 15 else 0
                sess.log(f"    Device class=0x{device_class:02X}  "
                         f"data={raw_dev.hex() or '(empty)'}")
            elif not fatal:
                sess.warn(f"GET_DESCRIPTOR(Device,18): {_status(ret)}")

        # 4. GET_DESCRIPTOR(Config, 9) — learn wTotalLength
        total_len = 34
        if not fatal:
            ret = self._ctrl_transfer(
                _get_descriptor_req(USB_DT_CONFIG, 0, 9), 9)
            if ret is None and self._ch.closed:
                fatal = True
            if _ok(ret):
                raw_cfg9 = _xfr(ret)
                if len(raw_cfg9) >= 4:
                    total_len = max(
                        struct.unpack_from('<H', raw_cfg9, 2)[0], 9)
                sess.log(f"    Config wTotalLength={total_len}  "
                         f"data={raw_cfg9.hex() or '(empty)'}")
            elif not fatal:
                sess.warn(f"GET_DESCRIPTOR(Config,9): {_status(ret)}")

        # 5. GET_DESCRIPTOR(Config, wTotalLength) — full configuration
        if not fatal:
            ret = self._ctrl_transfer(
                _get_descriptor_req(USB_DT_CONFIG, 0, total_len), total_len)
            if ret is None and self._ch.closed:
                fatal = True
            if _ok(ret):
                raw_cfg = _xfr(ret)
                endpoints = _parse_config_descriptor(raw_cfg)
                int_ep = _hid_interrupt_in(endpoints)
                sess.log(f"    Config descriptor: {len(endpoints)} endpoint(s)  "
                         f"interrupt_in={'yes' if int_ep else 'no'}  "
                         f"data={raw_cfg.hex() or '(empty)'}")
            elif not fatal:
                sess.warn(f"GET_DESCRIPTOR(Config,{total_len}): {_status(ret)}")

        # 6–8. String descriptors (best-effort)
        if not fatal:
            for idx in range(1, min(num_strings + 1, 4)):
                self._ctrl_transfer(
                    _get_descriptor_req(USB_DT_STRING, idx, 255, 0x0409), 255)

        # 9. SET_CONFIGURATION(1) — always attempt, even if descriptors failed
        if not fatal:
            ret = self._ctrl_transfer(_set_configuration_req(1), 0)
            if ret is None and self._ch.closed:
                fatal = True
            elif _ok(ret):
                sess.log("    SET_CONFIGURATION(1): OK")
            elif ret is not None:
                sess.warn(f"SET_CONFIGURATION(1): {_status(ret)}")

        # 10–11. HID-specific: SET_IDLE + SET_PROTOCOL (boot protocol)
        if not fatal and (device_class == USB_CLASS_HID or int_ep is not None):
            self._ctrl_transfer(_set_idle_req(), 0)
            self._ctrl_transfer(_set_protocol_req(0), 0)  # 0 = boot protocol

        if fatal:
            sess.warn("Enumeration aborted — Sender closed data channel")
            return None

        sess.log(f"  USB enumeration complete (seqnum now={self._seqnum})")
        return int_ep

    # ------------------------------------------------------------------

    def _poll_loop(self, ep: EndpointInfo) -> Optional[EndpointInfo]:
        """Periodically poll the interrupt IN endpoint for HID events.

        Returns an :class:`EndpointInfo` if a USB_STREAM_RESET was received
        and re-enumeration discovered a new interrupt endpoint (caller should
        re-enter the poll loop).  Returns ``None`` on normal exit or error.
        """
        sess      = self._session
        interval  = self._poll_ms / 1000.0   # seconds
        max_pkt   = ep.max_packet or 8

        while not self._stop.is_set():
            # Send INTERRUPT_SUBMIT
            self._send(usb.build_usb_interrupt_submit(
                self._seqnum, ep.endpoint_num, ep.direction,
                ep.interval, max_pkt,
            ))

            # Wait for INTERRUPT_SUBMIT_RETURN
            ret = self._ch.recv_msg(timeout=interval * 20 + 2.0)
            if ret is None:
                sess.warn("Timeout on INTERRUPT_SUBMIT_RETURN")
                break

            self._record_sender_msg(ret)
            mt = ret.msg_type_enum

            if mt == MsgType.USB_STREAM_RESET:
                return self._handle_stream_reset(ret)
            if mt == MsgType.USB_CANCEL_SUBMIT_RETURN:
                sess.log(f"  USB_CANCEL_SUBMIT_RETURN (seqnum={ret.payload.get('seqnum','?')})")
                continue
            if mt == MsgType.USB_ENTER_SLEEP:
                sess.log("  USB Enter Sleep on data channel — stopping")
                self._stop.set()
                break
            if mt != MsgType.USB_INTERRUPT_SUBMIT_RETURN:
                sess.warn(f"Expected INTERRUPT_SUBMIT_RETURN, got {ret.msg_type_name}")
                break

            self._seqnum += 1

            if (sess.verbose or sess.hid_only) and not ret.payload.get('_encrypted'):
                td_raw = ret.payload.get('transferdata') or ''
                td = bytes.fromhex(td_raw) if isinstance(td_raw, str) else bytes(td_raw)
                if td != self._prev_hid:
                    self._prev_hid = td
                    if any(td):
                        self._decode_hid(td, ep.max_packet)

            # Pace polling
            time.sleep(interval)
        return None

    def _record_sender_msg(self, msg: 'IpmxUsbMessage') -> None:
        """Record a Sender-originated data-channel message."""
        if self._substreamid is not None:
            self._session.record_data_msg(
                msg, self._substreamid, 'sender',
                self._ch.remote_ip, self._ch.remote_port,
                self._ch.local_ip, self._ch.local_port,
            )

    def _handle_stream_reset(self, msg: 'IpmxUsbMessage') -> Optional[EndpointInfo]:
        """Respond to USB_STREAM_RESET, re-enumerate, return new endpoint."""
        sess = self._session
        sess.log("  USB_STREAM_RESET received — sending return and re-enumerating")
        self._send(usb.build_usb_stream_reset_return())
        self._seqnum = 0
        self._prev_hid = b''
        return self._enumerate()

    # ------------------------------------------------------------------

    def _decode_hid(self, data: bytes, max_pkt: int) -> None:
        """Decode a HID boot-protocol report and print human-readable output.

        Keyboard: shows the actual character(s) typed (using the standard HID
        usage table) plus any active modifier keys.
        Mouse: shows button presses and movement direction as an ASCII arrow.
        """
        sess = self._session

        if max_pkt == 8 and len(data) >= 3:
            # ---- Keyboard boot protocol: [mods, reserved, key0..key5] ----
            mods = data[0]
            keys = [k for k in data[2:min(8, len(data))] if k != 0]

            # Decode each pressed key to its character
            chars = [_hid_key_to_char(k, mods) for k in keys]
            char_str = ''.join(chars) if chars else ''

            # Build modifier label (only non-shift mods — shift is folded into char)
            mod_parts = []
            if mods & 0x01: mod_parts.append('Ctrl')
            if mods & 0x04: mod_parts.append('Alt')
            if mods & 0x08: mod_parts.append('Win')
            if mods & 0x10: mod_parts.append('R-Ctrl')
            if mods & 0x40: mod_parts.append('AltGr')
            if mods & 0x80: mod_parts.append('R-Win')
            if mods & 0x02: mod_parts.append('Shift')   # show if no printable char
            if mods & 0x20: mod_parts.append('R-Shift')

            if char_str and mod_parts:
                non_shift_mods = [m for m in mod_parts if 'Shift' not in m]
                prefix = '+'.join(non_shift_mods) + '+' if non_shift_mods else ''
                sess.hid(f"  ⌨  {prefix}{char_str!r}")
            elif char_str:
                sess.hid(f"  ⌨  {char_str!r}")
            elif mods:
                sess.hid(f"  ⌨  <{'+'.join(mod_parts)}>")
            # all-zero report = key release, skip

        elif max_pkt <= 4 and len(data) >= 3:
            # ---- Mouse boot protocol: [buttons, dx, dy, wheel?] ----
            btns  = data[0]
            dx    = struct.unpack_from('b', data, 1)[0]
            dy    = struct.unpack_from('b', data, 2)[0]
            wheel = struct.unpack_from('b', data, 3)[0] if len(data) >= 4 else 0

            parts = []

            # Movement arrow
            if dx != 0 or dy != 0:
                horiz = ('→' * min(abs(dx), 5) if dx > 0 else '←' * min(abs(dx), 5)) if dx else ''
                vert  = ('↓' * min(abs(dy), 5) if dy > 0 else '↑' * min(abs(dy), 5)) if dy else ''
                parts.append(f"{horiz}{vert} ({dx:+d},{dy:+d})")

            # Wheel
            if wheel > 0:
                parts.append(f"scroll↑{wheel}")
            elif wheel < 0:
                parts.append(f"scroll↓{abs(wheel)}")

            # Buttons
            btn_names = {0: 'Left', 1: 'Right', 2: 'Middle'}
            pressed = [btn_names.get(i, f'B{i+1}') for i in range(8) if btns & (1 << i)]
            if pressed:
                parts.append(f"[{' '.join(pressed)}]")

            if parts:
                sess.hid(f"  🖱  {' '.join(parts)}")

        else:
            sess.hid(f"  HID raw ({max_pkt}B): {data.hex()}")

    # ------------------------------------------------------------------

    def _idle_loop(self) -> None:
        """Stay alive handling any messages when no interrupt endpoint exists."""
        sess = self._session
        ssid = self._substreamid or 0
        msg_count = 0
        sess.log(f"  Idle loop on data channel 0x{ssid:02X} — monitoring …")
        while not self._stop.is_set():
            msg = self._recv(timeout=5.0)
            if msg is None:
                if self._ch.closed:
                    sess.log(f"  Data channel 0x{ssid:02X} closed by Sender")
                    break
                continue

            msg_count += 1
            mt = msg.msg_type_enum

            if mt == MsgType.USB_STREAM_RESET:
                new_ep = self._handle_stream_reset(msg)
                if new_ep is not None:
                    while new_ep is not None and not self._stop.is_set():
                        sess.log(f"  Polling interrupt endpoint 0x{new_ep.address:02X}  "
                                 f"interval={new_ep.interval} ms  "
                                 f"maxpkt={new_ep.max_packet} B")
                        new_ep = self._poll_loop(new_ep)
                    return
            elif mt == MsgType.USB_CANCEL_SUBMIT_RETURN:
                sess.log(f"  USB_CANCEL_SUBMIT_RETURN (seqnum={msg.payload.get('seqnum','?')})")
            elif mt == MsgType.USB_ENTER_SLEEP:
                sess.log("  USB Enter Sleep on data channel — stopping")
                self._stop.set()
                break
            else:
                sess.log(f"  Idle recv: {msg.msg_type_name}  "
                         f"payload={msg.payload}")

        sess.log(f"  Idle loop ended — {msg_count} message(s) received")


# ---------------------------------------------------------------------------
# DataChannelServer — listens for Sender data connections
# ---------------------------------------------------------------------------

class DataChannelServer:
    """
    Listens on the Receiver's data port and spawns a DataChannelHandler
    thread for each connection accepted from the Sender.
    """

    def __init__(self, session: IpmxReceiverSession,
                 listen_ip: str, listen_port: int,
                 poll_interval_ms: float,
                 capture: Optional[PcapCapture] = None,
                 stop_event: Optional[threading.Event] = None):
        self._session  = session
        self._ip       = listen_ip
        self._port     = listen_port
        self._poll_ms  = poll_interval_ms
        self._capture  = capture
        self._stop     = stop_event or threading.Event()
        self._threads:  list[threading.Thread] = []
        self._handlers: list[DataChannelHandler] = []

    def shutdown_all(self) -> None:
        """Close all active data channel sockets, unblocking any recv in progress."""
        for h in self._handlers:
            h.shutdown()

    def run(self) -> None:
        """Blocking; call from a dedicated thread."""
        sess = self._session
        srv  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self._ip, self._port))
        srv.listen(8)
        srv.settimeout(1.0)
        sess.log(f"Data channel server listening on {self._ip}:{self._port}")

        while not self._stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            remote_ip, remote_port = addr
            local_ip, local_port   = conn.getsockname()
            sess.log(f"Sender data connection from {remote_ip}:{remote_port}")

            handler = DataChannelHandler(
                session         = sess,
                sock            = conn,
                local_ip        = local_ip,
                local_port      = local_port,
                remote_ip       = remote_ip,
                remote_port     = remote_port,
                poll_interval_ms= self._poll_ms,
                capture         = self._capture,
                stop_event      = self._stop,
            )
            t = threading.Thread(
                target=handler.run,
                name=f"data-{remote_ip}:{remote_port}",
                daemon=True,
            )
            t.start()
            self._threads.append(t)
            self._handlers.append(handler)

        srv.close()
        for t in self._threads:
            t.join(timeout=3.0)
        sess.log("Data channel server stopped")


# ---------------------------------------------------------------------------
# Main test runner
# ---------------------------------------------------------------------------

def _get_local_ip(remote_ip: str) -> str:
    """Determine the local IP that would be used to reach *remote_ip*."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((remote_ip, 80))
        return s.getsockname()[0]
    except Exception:
        return "0.0.0.0"
    finally:
        try:
            s.close()
        except Exception:
            pass


def run_test(
    sender_ip: str,
    sender_ctrl_port: int = DEFAULT_SENDER_CTRL_PORT,
    data_port: int        = DEFAULT_RECEIVER_DATA_PORT,
    duration: Optional[float] = None,
    capture_file: Optional[str] = None,
    live_validate: bool   = True,
    encrypted: bool       = False,
    verbose: bool         = False,
    hid_only: bool        = False,
    our_cid: bytes        = DEFAULT_OUR_CID,
    our_sn: str           = DEFAULT_OUR_SN,
    hbeat_index: int      = DEFAULT_HBEAT_INDEX,
    poll_interval_ms: float = DEFAULT_POLL_INTERVAL_MS,
    pep_params: Optional[pepmod.PepParams] = None,
    pep_key: Optional[bytes] = None,
    kv_mode: pepmod.KvMode = pepmod.KvMode.RANDOM,
    iv_mode_s2r: pepmod.IvMode = pepmod.IvMode.SPEC,
    iv_mode_r2s: pepmod.IvMode = pepmod.IvMode.SPEC,
    r2s_substreamid: int = 1,
    initial_ctr: int = 0,
    matrox_queries: bool = False,
    echo_version: bool = False,
    iv_swapn: bool = False,
) -> int:
    """
    Run the live Receiver test.  Blocks until duration expires or Ctrl-C.
    Returns exit code (0 = OK, 1 = errors found).
    """
    our_ip = _get_local_ip(sender_ip)

    capture: Optional[PcapCapture] = None
    if capture_file:
        capture = PcapCapture(capture_file)
        print(f"Capturing traffic to {capture_file}")

    session = IpmxReceiverSession(
        sender_ip        = sender_ip,
        sender_ctrl_port = sender_ctrl_port,
        our_ip           = our_ip,
        our_data_port    = data_port,
        our_cid          = our_cid,
        our_sn           = our_sn,
        live_validate    = live_validate,
        encrypted        = encrypted,
        verbose          = verbose,
        hid_only         = hid_only,
        pep_params       = pep_params,
        pep_key          = pep_key,
        kv_mode          = kv_mode,
        iv_mode_s2r      = iv_mode_s2r,
        iv_mode_r2s      = iv_mode_r2s,
        r2s_substreamid  = r2s_substreamid,
        initial_ctr      = initial_ctr,
        echo_version     = echo_version,
        iv_swapn         = iv_swapn,
    )
    session.matrox_queries = matrox_queries

    stop_event = threading.Event()

    ctrl_client = ControlChannelClient(
        session          = session,
        sender_ip        = sender_ip,
        sender_ctrl_port = sender_ctrl_port,
        our_cid          = our_cid,
        our_sn           = our_sn,
        hbeat_index      = hbeat_index,
        data_port        = data_port,
        capture          = capture,
        stop_event       = stop_event,
    )

    data_server = DataChannelServer(
        session          = session,
        listen_ip        = "0.0.0.0",
        listen_port      = data_port,
        poll_interval_ms = poll_interval_ms,
        capture          = capture,
        stop_event       = stop_event,
    )

    ctrl_client._data_server = data_server

    ctrl_thread = threading.Thread(target=ctrl_client.run, name="ctrl", daemon=True)
    data_thread = threading.Thread(target=data_server.run, name="data-srv", daemon=True)

    ctrl_thread.start()
    data_thread.start()

    session.log(f"Test running (Ctrl-C to stop{f', duration={duration:.0f}s' if duration else ''})")

    try:
        if duration:
            stop_event.wait(timeout=duration)
            if not stop_event.is_set():
                session.log("Duration elapsed — stopping")
                stop_event.set()
        else:
            while not stop_event.is_set():
                stop_event.wait(timeout=1.0)
    except KeyboardInterrupt:
        session.log("\nCtrl-C — stopping")
        stop_event.set()

    # Close sockets immediately so any blocked recv() unblocks right away.
    ctrl_client.shutdown()
    data_server.shutdown_all()

    # Join threads in parallel — wait at most 3 s total.
    ctrl_thread.join(timeout=3.0)
    data_thread.join(timeout=3.0)

    if capture:
        capture.close()
        session.log(f"PCAP written to {capture_file}")
        session.log(f"  → Analyse with: python3 usbDissector.py {capture_file} --messages")

    session.final_report()

    errors = sum(1 for f in session.session.findings if f.severity == Severity.ERROR)
    return 1 if errors else 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="IPMX USB (TR-10-14) Live Receiver Test Harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Connect using SDP (provides IP, port, and privacy params):
  python3 ipmx_usb_tester.py --sdp sender.sdp --psk 000102...0f

  # Connect without SDP:
  python3 ipmx_usb_tester.py 192.168.1.10

  # Same but also capture to a PCAP for post-analysis:
  python3 ipmx_usb_tester.py 192.168.1.10 --capture session.pcap

  # Run for 60 seconds then stop:
  python3 ipmx_usb_tester.py 192.168.1.10 --duration 60

  # Verbose — print every message as it flows:
  python3 ipmx_usb_tester.py 192.168.1.10 --verbose

  # Analyse the captured PCAP afterward:
  python3 usbDissector.py session.pcap --messages --requirements
""",
    )

    parser.add_argument(
        'sender_ip', nargs='?', default=None,
        help="IP address of the IPMX Sender device (optional if --sdp provides it)",
    )
    parser.add_argument(
        '--sender-port', type=int, default=None,
        metavar='PORT',
        help=f"Sender control port (default: from SDP or {DEFAULT_SENDER_CTRL_PORT})",
    )
    parser.add_argument(
        '--data-port', type=int, default=DEFAULT_RECEIVER_DATA_PORT,
        metavar='PORT',
        help=f"Our data listen port (default: {DEFAULT_RECEIVER_DATA_PORT})",
    )
    parser.add_argument(
        '--duration', type=float, default=None,
        metavar='SECS',
        help="Stop after N seconds (default: run until Ctrl-C)",
    )
    parser.add_argument(
        '--capture', metavar='FILE.pcap',
        help="Write live traffic to PCAP for usbDissector.py analysis",
    )
    parser.add_argument(
        '--no-live-validate', action='store_true',
        help="Suppress real-time finding output (print only at the end)",
    )
    parser.add_argument(
        '--encrypted', action='store_true',
        help="Treat stream as encrypted (auto-detected when --psk is given)",
    )
    parser.add_argument(
        '--cid', default=DEFAULT_OUR_CID.hex(),
        metavar='HEX',
        help=f"Our 3-byte CID in hex (default: {DEFAULT_OUR_CID.hex()})",
    )
    parser.add_argument(
        '--sn', default=DEFAULT_OUR_SN,
        metavar='STRING',
        help=f"Our serial number (default: {DEFAULT_OUR_SN!r})",
    )
    parser.add_argument(
        '--hbeat', type=int, default=DEFAULT_HBEAT_INDEX,
        metavar='IDX',
        help=f"Heartbeat index 5-30 (default: {DEFAULT_HBEAT_INDEX})",
    )
    parser.add_argument(
        '--poll-interval', type=float, default=DEFAULT_POLL_INTERVAL_MS,
        metavar='MS',
        help=f"HID interrupt poll interval in ms (default: {DEFAULT_POLL_INTERVAL_MS})",
    )
    parser.add_argument(
        '--verbose', action='store_true',
        help="Print every message and HID events as they flow",
    )
    parser.add_argument(
        '--hid', action='store_true',
        help="Show only keyboard characters and mouse movements (no protocol noise)",
    )
    parser.add_argument(
        '--matrox-queries', action='store_true', default=False,
        help="Handle Matrox-specific VendorSpecificQuery types (0x80 hub-state, "
             "0x81 hub-change, 0x90 led-state, 0x91 led-change). Default is "
             "spec-compliant: unknown VQTYPE >= 16 gets VQSTS=255.",
    )
    parser.add_argument(
        '--echo-version', action='store_true', default=False,
        help="Echo the Sender's MAVER/MIVER in our SenderConnectionStatus "
             "instead of the spec-compliant 0.0 (workaround for devices that "
             "reject version 0.0 responses).",
    )

    pepmod.add_pep_args(parser)

    args = parser.parse_args()

    try:
        our_cid = bytes.fromhex(args.cid)
        if len(our_cid) != 3:
            raise ValueError("CID must be exactly 3 bytes")
    except ValueError as exc:
        parser.error(f"--cid: {exc}")

    if not (5 <= args.hbeat <= 30):
        parser.error("--hbeat must be in [5, 30]")

    # ---- Resolve Sender IP and port from SDP and/or CLI ----
    sender_ip: Optional[str] = args.sender_ip
    sender_port: Optional[int] = args.sender_port

    sdp_ip: Optional[str] = None
    sdp_port: Optional[int] = None
    if args.sdp:
        sdp_ip, sdp_port = pepmod.PepParams.sdp_connection_info(args.sdp)

    if sender_ip is None:
        sender_ip = sdp_ip
    if sender_ip is None:
        parser.error("sender_ip is required (provide it as a positional arg or via --sdp)")
    if sender_port is None:
        sender_port = sdp_port if sdp_port else DEFAULT_SENDER_CTRL_PORT

    # ---- Load PEP params ----
    pep_params: Optional[pepmod.PepParams] = None
    pep_key: Optional[bytes] = None
    psk = b""
    if args.psk:
        psk = bytes.fromhex(args.psk)
    elif args.psk_file:
        with open(args.psk_file, "rb") as f:
            psk = f.read()

    if args.sdp and psk:
        pep_params = pepmod.PepParams.from_sdp(args.sdp, psk)
        pep_key = pep_params.derive_key()
        print(f"PEP decryption enabled: mode={pep_params.mode.value}  "
              f"key={pep_key.hex()}")
    elif psk and args.pep_mode:
        pep_params = pepmod.PepParams.from_cli(args)
        pep_key = pep_params.derive_key()
        print(f"PEP decryption enabled: mode={pep_params.mode.value}  "
              f"key={pep_key.hex()}")
    elif psk:
        print("Warning: --psk given without --sdp or --pep-mode; "
              "encryption will be detected but decryption skipped")

    # ---- Resolve IV byte-order modes ----
    iv_s2r_mode = pepmod.IvMode.SWAP if args.iv_s2r_swap0 else pepmod.IvMode.SPEC
    if args.iv_r2s_swap0 or args.iv_r2s_swap1:
        iv_r2s_mode = pepmod.IvMode.SWAP
    else:
        iv_r2s_mode = pepmod.IvMode.SPEC

    # Substreamid for R2S control channel: normally 1 (odd, first R2S),
    # but --iv-r2s-spec0 forces substreamid=0 and --iv-r2s-swap0 also
    # uses substreamid=0 (in SWAP mode).
    if args.iv_r2s_spec0 or args.iv_r2s_swap0:
        r2s_ssid = 0
    else:
        r2s_ssid = 1

    initial_ctr = 1 if args.ctr_1 else 0

    if args.kv_s2r and args.kv_sdp:
        parser.error("--kv-s2r and --kv-sdp are mutually exclusive")
    if args.kv_s2r:
        kv_mode = pepmod.KvMode.S2R
    elif args.kv_sdp:
        kv_mode = pepmod.KvMode.SDP
    else:
        kv_mode = pepmod.KvMode.RANDOM

    iv_swapn = args.iv_swapn

    has_overrides = (iv_s2r_mode != pepmod.IvMode.SPEC
                     or iv_r2s_mode != pepmod.IvMode.SPEC
                     or r2s_ssid != 1
                     or initial_ctr != 0
                     or kv_mode != pepmod.KvMode.RANDOM
                     or args.echo_version
                     or iv_swapn)
    if has_overrides:
        labels = []
        labels.append(f"S2R iv_mode={iv_s2r_mode.value} ssid=0")
        labels.append(f"R2S iv_mode={iv_r2s_mode.value} ssid={r2s_ssid}")
        if iv_swapn:
            labels.append("iv_swapn=SWAP")
        if initial_ctr != 0:
            labels.append(f"initial_ctr={initial_ctr}")
        if kv_mode != pepmod.KvMode.RANDOM:
            labels.append(f"kv_mode={kv_mode.value}")
        if args.echo_version:
            labels.append("echo_version")
        print(f"Debug overrides: {', '.join(labels)}")

    sys.exit(run_test(
        sender_ip        = sender_ip,
        sender_ctrl_port = sender_port,
        data_port        = args.data_port,
        duration         = args.duration,
        capture_file     = args.capture,
        live_validate    = not args.no_live_validate,
        encrypted        = args.encrypted,
        verbose          = args.verbose,
        hid_only         = args.hid,
        our_cid          = our_cid,
        our_sn           = args.sn,
        hbeat_index      = args.hbeat,
        poll_interval_ms = args.poll_interval,
        pep_params       = pep_params,
        pep_key          = pep_key,
        kv_mode          = kv_mode,
        iv_mode_s2r      = iv_s2r_mode,
        iv_mode_r2s      = iv_r2s_mode,
        r2s_substreamid  = r2s_ssid,
        initial_ctr      = initial_ctr,
        matrox_queries   = args.matrox_queries,
        echo_version     = args.echo_version,
        iv_swapn         = iv_swapn,
    ))


if __name__ == '__main__':
    main()
