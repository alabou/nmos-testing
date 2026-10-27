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
import collections
import enum
import logging
import os
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Collection, Optional

try:
    from scapy.all import Ether, IP, TCP, PcapWriter
except ImportError:
    print("Error: scapy is required.  pip install scapy", file=sys.stderr)
    sys.exit(1)

import ipmx_usb_message as usb
from ipmx_usb_message import IpmxUsbMessage, MsgType
import ipmx_pep as pepmod

# Shared USB standard-layer decoders (SETUP, descriptors, HID boot keyboard/mouse).
# The byte-level parsing lives here so usbDissector.py decodes captured reports
# the same way this live harness decodes them; this tool only formats the result.
from usb_decode import (
    HidBootProtocol, EndpointInfo, TransferType, parse_config_descriptor, classify_hid,
    decode_keyboard_report, decode_mouse_report,
)

# Import validation infrastructure from the dissector
from usbDissector import (
    Severity, Finding, ChannelMessage, DataChannel, ControlChannel, Session, ChannelRole,
    sent_by_other_side,
    _validate_control_channel, _validate_data_channel, _diagnose_data_channel, _heartbeat_period,
)


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

# The HID keyboard usage table and keycode->character mapping now live in
# usb_decode.py (see hid_key_to_char / decode_keyboard_report) so this harness
# and usbDissector.py decode reports identically.


DEFAULT_SENDER_CTRL_PORT = 27502
DEFAULT_RECEIVER_DATA_PORT = 40000
DEFAULT_HBEAT_INDEX = 10          # period ≈ 47 s
DEFAULT_OUR_CID = bytes.fromhex("0050C2")
DEFAULT_OUR_SN = "IPMX-USB-Tester-v1"
DEFAULT_POLL_INTERVAL_MS = 8      # 1 ms USB frame = 8 polls/frame for HID

#: The messages that answer one Submit each, identified by its SEQNUM (Table 14).
_SUBMIT_RETURNS = {MsgType.USB_CONTROL_SUBMIT_RETURN, MsgType.USB_BULK_SUBMIT_RETURN,
                   MsgType.USB_INTERRUPT_SUBMIT_RETURN, MsgType.USB_ISOCHRONOUS_SUBMIT_RETURN}


# ---------------------------------------------------------------------------
# USB standard request builders (USB 2.0 §9.4, HID 1.11 §7.2)
# ---------------------------------------------------------------------------

USB_REQ_GET_DESCRIPTOR   = 0x06
USB_REQ_SET_ADDRESS      = 0x05
USB_REQ_SET_CONFIGURATION = 0x09
USB_REQ_SET_IDLE         = 0x0A
USB_REQ_SET_PROTOCOL     = 0x0B

USB_DT_DEVICE    = 0x01
USB_DT_CONFIG    = 0x02
USB_DT_STRING    = 0x03
USB_DT_DEVICE_QUALIFIER = 0x06
USB_DT_INTERFACE = 0x04
USB_DT_ENDPOINT  = 0x05
USB_DT_HID       = 0x21
USB_DT_REPORT    = 0x22

USB_CLASS_HID  = 0x03
USB_HID_SUBCLASS_BOOT = 0x01   # bInterfaceSubClass: Boot Interface Subclass (HID 1.11 §4.2)


class Verdict(enum.IntEnum):
    """The run's result; its value is the process exit code."""
    PASS       = 0
    FAIL       = 1   # an ERROR: a requirement failed
    NOT_TESTED = 2   # no session with the Sender (no SenderConnectionInfo), so nothing was tested


class HidProtocol(enum.IntEnum):
    """SET_PROTOCOL wValue (HID 1.11 §7.2.6)."""
    BOOT   = 0
    REPORT = 1


# HidBootProtocol is imported from usb_decode (shared with usbDissector.py).


def _get_descriptor_req(dtype: int, index: int, length: int,
                         lang_id: int = 0) -> bytes:
    bmt = 0x81 if dtype in (USB_DT_HID, USB_DT_REPORT) else 0x80
    wValue = (dtype << 8) | index
    return struct.pack('<BBHHH', bmt, USB_REQ_GET_DESCRIPTOR, wValue, lang_id, length)


def _set_address_req(addr: int) -> bytes:
    return struct.pack('<BBHHH', 0x00, USB_REQ_SET_ADDRESS, addr, 0, 0)


def _set_configuration_req(cfg: int) -> bytes:
    return struct.pack('<BBHHH', 0x00, USB_REQ_SET_CONFIGURATION, cfg, 0, 0)


def _set_idle_req(interface: int) -> bytes:
    """SET_IDLE(indefinite, all reports) to a HID interface (HID 1.11 §7.2.4: wIndex Interface)."""
    return struct.pack('<BBHHH', 0x21, USB_REQ_SET_IDLE, 0x0000, interface, 0)


def _set_protocol_req(protocol: HidProtocol, interface: int) -> bytes:
    """SET_PROTOCOL to a HID interface (HID 1.11 §7.2.6: wIndex Interface)."""
    return struct.pack('<BBHHH', 0x21, USB_REQ_SET_PROTOCOL, protocol, interface, 0)


def _ignore_receiver_message(sess: 'IpmxReceiverSession', msg: IpmxUsbMessage, where: str,
                             warned: set[MsgType]) -> bool:
    """True for a message the Sender sent although TR-10-14 assigns its type to the Receiver (a
    USB Stream Reset, a Submit, ...): the tester takes no action on it and goes on. It is
    recorded like every message, so the validators report it (MESSAGE_DIRECTION) and the run
    FAILS. The first one of each type in *where* is printed; *warned* holds the types printed."""
    other = sent_by_other_side(msg.msg_type_enum, ChannelRole.SENDER)
    if other is None:
        return False
    if msg.msg_type_enum not in warned:
        warned.add(msg.msg_type_enum)
        sess.error(f"{where}: the Sender sent {msg.msg_type_name}, which §{other[1]} assigns to "
                   f"the Receiver: ignored. A violation the validators report; further "
                   f"{msg.msg_type_name} from the Sender are not printed")
    return True


def _langids(string0: bytes) -> list[int]:
    """The LANGIDs string descriptor 0 lists, in order (USB 2.0 §9.6.7, Table 9-15)."""
    if len(string0) < 4 or string0[1] != USB_DT_STRING:
        return []
    end = min(len(string0), string0[0])
    return [int.from_bytes(string0[i:i + 2], 'little') for i in range(2, end - 1, 2)]


# ---------------------------------------------------------------------------
# USB configuration descriptor parser
# ---------------------------------------------------------------------------

# EndpointInfo and parse_config_descriptor are imported from usb_decode
# (shared with usbDissector.py).


def _interrupt_in_endpoints(endpoints: list[EndpointInfo]) -> list[EndpointInfo]:
    """The interrupt IN endpoints to poll: every HID interface's when there is one (a
    composite device, such as a keyboard and a mouse in one device, has one per HID
    interface), else the first one, or none. Only alternate setting 0 counts: the tester sends
    no SET_INTERFACE, and setting 0 is the one a device is in once configured (USB 2.0 §9.2.3)."""
    candidates = [ep for ep in endpoints
                  if ep.transfer_type == TransferType.INTERRUPT and ep.direction == 1
                  and ep.iface_alt == 0]
    hid = [ep for ep in candidates if ep.iface_class == USB_CLASS_HID]
    return hid or candidates[:1]


def _hid_interfaces(endpoints: list[EndpointInfo]) -> list[EndpointInfo]:
    """One endpoint per HID interface of alternate setting 0, carrying that interface's
    number, subclass and protocol (a HID interface always has an interrupt IN, HID 1.11 §4.4)."""
    seen: set[int] = set()
    interfaces: list[EndpointInfo] = []
    for ep in endpoints:
        if ep.iface_class == USB_CLASS_HID and ep.iface_alt == 0 and ep.iface_number not in seen:
            seen.add(ep.iface_number)
            interfaces.append(ep)
    return interfaces


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
        # [byte count, PCAP packet number] of each received chunk still in _buf (0: not in
        # the capture), so a message is numbered by the packet that carried its first byte,
        # as usbDissector.py numbers it when it reads the capture.
        self._buf_pkts: collections.deque = collections.deque()
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
        self.last_recv_pkt_num: int = 0     # PCAP packet number of the last message received
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

    def _take(self, length: int) -> tuple[bytes, int]:
        """Remove the first *length* bytes of the buffer; return them and the PCAP packet
        number of the chunk that carried the first of them."""
        raw = bytes(self._buf[:length])
        del self._buf[:length]
        pkt_num = self._buf_pkts[0][1] if self._buf_pkts else 0
        while length and self._buf_pkts:
            n = min(length, self._buf_pkts[0][0])
            self._buf_pkts[0][0] -= n
            length -= n
            if not self._buf_pkts[0][0]:
                self._buf_pkts.popleft()
        return raw, pkt_num

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
                    raw, self.last_recv_pkt_num = self._take(length)

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

            pkt_num = 0
            if self._capture:
                pkt_num = self._capture.record(
                    chunk, self.remote_ip, self.remote_port,
                    self.local_ip, self.local_port,
                )
            self._buf.extend(chunk)
            self._buf_pkts.append([len(chunk), pkt_num])

    def recv_raw(self, timeout: float = 30.0) -> Optional[bytes]:
        """Block until one complete raw IPMX message is available (no parsing/decryption)."""
        deadline = time.monotonic() + timeout
        while True:
            if len(self._buf) >= usb.HEADER_SIZE:
                length = usb.peek_length(bytes(self._buf))
                if length is not None and len(self._buf) >= length:
                    raw, _ = self._take(length)
                    self.last_recv_pkt_num = 0
                    if self._capture:
                        self.last_recv_pkt_num = self._capture.record(
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
            self._buf_pkts.append([len(chunk), 0])      # recorded message by message, above

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
        # Test options set by run_test() (see --strict-actuallength,
        # --enumerate-in-sequence, --device-qualifier, --diagnose).
        self.strict_actuallength   = False
        self.enumerate_in_sequence = False
        self.device_qualifier      = False
        self.diagnose              = False
        self.set_address           = SetAddressMode.UNIQUE
        self._next_address         = 1      # USB addresses 1..127, allocated per device
        self.enum_lock = threading.Lock()   # one channel enumerates at a time when in sequence
        # Findings the tester makes itself (the validators rebuild theirs on every pass).
        self.tester_findings: list[Finding] = []

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

        # The recorded messages are already decrypted whenever a PEP key was derived. Without
        # `decrypted`, an encrypted session skips every payload check of the validators
        # (SEQNUM, Submit/Return matching, ACTUALLENGTH, RSTATUS, DATA sizes).
        decrypted = self.pep_key is not None

        # Only validate the control channel once both sides have spoken
        # (avoids transient false positives when SCI arrives before SCS is sent).
        if ctrl_s and ctrl_r:
            _validate_control_channel(
                sess, ctrl_s, ctrl_r,
                expected_cid=None, expected_sn=None,
                encrypted=self.encrypted,
                decrypted=decrypted,
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
                decrypted=decrypted,
            )
            if self.diagnose:
                _diagnose_data_channel(sess, channel, s_msgs, r_msgs)
        sess.diagnosed = self.diagnose
        with self._lock:
            sess.findings.extend(self.tester_findings)

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

    def allocate_address(self) -> int:
        """The next free USB device address, 1..127, as a host allocates them."""
        with self._lock:
            addr = self._next_address
            self._next_address = addr % 127 + 1
            return addr

    def add_tester_finding(self, severity: Severity, section: str, description: str,
                           packet_number: Optional[int] = None) -> None:
        """Record a finding the tester itself observed (not derived by the validators)."""
        with self._lock:
            self.tester_findings.append(Finding(severity, section, description, packet_number))
        if self.live_validate:
            self._validate_and_report()

    def final_report(self) -> Verdict:
        """Run a final validation pass, print the findings summary and return the verdict."""
        with self._lock:
            no_session = not self.ctrl_sender_msgs
        # The test has ended: messages still outstanding are reported against this time.
        self.session.capture_end = time.time()
        self._validate_and_report()
        sess = self.session
        errors   = sum(1 for f in sess.findings if f.severity == Severity.ERROR)
        warnings = sum(1 for f in sess.findings if f.severity == Severity.WARNING)
        diags    = sum(1 for f in sess.findings if f.severity == Severity.DIAG)
        # Any ERROR is a failed requirement; continuing past a non-fatal one never changes that.
        # Without a session with the Sender nothing was tested, which is no PASS either.
        verdict = (Verdict.FAIL if errors else Verdict.NOT_TESTED if no_session else Verdict.PASS)
        if self.hid_only:
            return verdict   # --hid mode: skip report entirely, keep output clean
        print("\n" + "=" * 68)
        print("Final Validation Report")
        print("=" * 68)
        for f in sess.findings:
            print(str(f))
        if not sess.findings:
            print("  [OK] No violations found")
        print(f"\nTotal: {errors} error(s), {warnings} warning(s)"
              + (f", {diags} diag(s)" if self.diagnose or diags else ""))
        if verdict is Verdict.NOT_TESTED:
            print(f"Result: NOT TESTED: no session with the Sender at "
                  f"{self.sender_ip}:{self.sender_ctrl_port} (no SenderConnectionInfo received)")
        else:
            print(f"Result: {verdict.name}")
        return verdict

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

        self._warned_wrong_side: set[MsgType] = set()   # Receiver message types the Sender sent

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
        # §8.3.1.1 sets no time for it: wait as long as the test runs.
        connected_at = time.monotonic()
        raw = None
        while raw is None and not self._stop.is_set() and not ch.closed:
            raw = ch.recv_raw(timeout=1.0)
        if raw is None:
            ended = "the test ended" if self._stop.is_set() else "the Sender closed the connection"
            sess.add_tester_finding(
                Severity.DIAG, "8.3.1.1",
                f"Control channel: no SenderConnectionInfo in the "
                f"{time.monotonic() - connected_at:.1f} s until {ended}. TR-10-14 sets no time "
                f"for it")
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
                             local_ip, local_port,
                             pkt_num=ch.last_recv_pkt_num)
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
                                 local_ip, local_port,
                                 pkt_num=ch.last_recv_pkt_num)

            if _ignore_receiver_message(sess, msg, "Control channel", self._warned_wrong_side):
                continue

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

class SetAddressMode(enum.Enum):
    """What the tester sends as SET_ADDRESS during enumeration (--set-address)."""
    # What a USB host does (USB 2.0 §9.1.2, step 5: "The host assigns a unique address to the
    # USB device"): each device its own address, allocated 1, 2, 3, ... across the session.
    UNIQUE = "unique"
    # No SET_ADDRESS at all, like a Receiver that keeps the bus address local (Avio 2).
    NONE = "none"


class ReturnDataUnusable(Exception):
    """A Submit Return the tester cannot continue with on its data channel (see
    DataChannelHandler._return_data). The channel stops; the run has already failed."""


class DataChannelHandler:
    """
    Handles one accepted data channel connection from the Sender:
      1. Receive USBStreamInfo, send USBStreamStatus
      2. Run USB enumeration (as USB host)
      3. Poll its interrupt IN endpoints for HID events
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
        self._usbspeed: Optional[int] = None   # USBSPEED of the channel's USB Stream Information
        # last HID report of each endpoint (by bEndpointAddress); used to suppress repeated reports
        self._prev_hid: dict[int, bytes] = {}
        self._warned_excess = False   # bytes past ACTUALLENGTH already reported on this channel
        self._warned_stray = False    # a Return of no outstanding Submit already reported
        self._warned_wrong_side: set[MsgType] = set()   # Receiver message types the Sender sent
        self._address: Optional[int] = None   # USB address given by SET_ADDRESS (unique mode)

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
                    pkt_num=ch.last_recv_pkt_num,
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
            seq = self._seqnum
            self._send(usb.build_usb_control_submit(
                seq, endpoint, direction, binterval,
                transferlength, req,
            ))
            # Table 10: every Submit sent takes the next SEQNUM, whether or not it is
            # answered - a timed-out Submit must not lend its number to the next one.
            self._seqnum += 1
            # The Return of this Submit, within 10 s; a Return of another SEQNUM is not it.
            ret = None
            deadline = time.monotonic() + 10.0
            while ret is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                msg = self._recv(timeout=remaining)
                if msg is None:
                    break
                if not (self._from_wrong_side(msg) or self._answers_other_submit(msg, (seq,))):
                    ret = msg
            if ret is None:
                if self._ch.closed:
                    self._session.warn(
                        f"Sender closed data channel before replying to "
                        f"CONTROL_SUBMIT seq={seq}")
                else:
                    self._session.warn(
                        f"No CONTROL_SUBMIT_RETURN seq={seq} in 10 s: the tester stops "
                        f"waiting for it, as a host does (its own limit; TR-10-14 sets none)")
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
                time.sleep(0.5)
                continue

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
        # §8.3.1.2 sets no time for it: wait as long as the test runs.
        accepted_at = time.monotonic()
        raw = None
        while raw is None and not self._stop.is_set() and not ch.closed:
            raw = ch.recv_raw(timeout=1.0)
        if raw is None:
            ended = "the test ended" if self._stop.is_set() else "the Sender closed the connection"
            sess.add_tester_finding(
                Severity.DIAG, "8.3.1.2",
                f"Data channel from {rip}:{rport}: no USBStreamInfo in the "
                f"{time.monotonic() - accepted_at:.1f} s until {ended}. TR-10-14 sets no time "
                f"for it")
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
            self._usbspeed = msg.payload.get('usbspeed')
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
            pkt_num=ch.last_recv_pkt_num,
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
        interrupt_eps = self._run_enumeration()

        if not interrupt_eps:
            sess.warn("No HID interrupt IN endpoint found — skipping polling")
            self._idle_loop()
            return

        # Step 4 — HID interrupt polling loop
        self._poll_loop(interrupt_eps)

        ch.close()
        sess.log(f"Data channel 0x{substreamid:02X} closed")

    # ------------------------------------------------------------------

    def _run_enumeration(self) -> list[EndpointInfo]:
        """Enumerate this channel's device; with --enumerate-in-sequence, one channel at a
        time across the session. TR-10-14 requires neither order: once a Sender has the USB
        Stream Status it "shall be ready to receive USB Submit messages" on that channel."""
        try:
            if not self._session.enumerate_in_sequence:
                return self._enumerate()
            with self._session.enum_lock:
                return self._enumerate()
        except ReturnDataUnusable as e:
            self._session.error(f"Data channel {self._sid()}: cannot continue: {e}. "
                                f"Enumeration of this channel stops; the run FAILS")
            return []

    def _sid(self) -> str:
        return f"0x{self._substreamid:02X}" if self._substreamid is not None else "?"

    def _answers_other_submit(self, msg: IpmxUsbMessage, awaited: Collection[int]) -> bool:
        """True for a Submit Return whose SEQNUM is none of *awaited*, the Submits this channel
        waits on. A Submit Return answers the Submit whose SEQNUM it carries (§9.18), so such a
        Return answers none of this channel's: it is not taken as an awaited one, and the
        wait goes on. It is recorded like every message, so the validators report it."""
        if msg.msg_type_enum not in _SUBMIT_RETURNS or msg.payload.get('_encrypted'):
            return False
        got = msg.payload.get('seqnum')
        if got is None or got in awaited:
            return False
        if not self._warned_stray:
            self._warned_stray = True
            waiting = ', '.join(str(s) for s in sorted(awaited)) or 'none'
            self._session.warn(
                f"Data channel {self._sid()}: {msg.msg_type_name} SEQNUM={got} answers no "
                f"Submit outstanding on this channel (waiting on SEQNUM {waiting}): ignored. A "
                f"§9.18 violation the validators report; further ones are not printed")
        return True

    def _return_data(self, ret: Optional[IpmxUsbMessage]) -> bytes:
        """The data a Submit Return carries: per Table 14, the ACTUALLENGTH bytes of
        TRANFERDATA. Any ACTUALLENGTH other than the number of bytes the message carries after
        RSTATUS (its DATA is LENGTH - 24 bytes, Table 1) is a §9.18-20 SHALL violation, which
        the validators report as an ERROR: the run FAILS. Whether the tester can continue on
        the channel depends on the case:

        * ACTUALLENGTH 0 with bytes present (a Sender that leaves the field unset): continues
          with the bytes present.
        * 0 < ACTUALLENGTH < bytes present: continues with the ACTUALLENGTH bytes; the bytes
          past them belong to no field and are not used.
        * ACTUALLENGTH larger than the bytes present: the message lacks its own data - cannot
          continue (ReturnDataUnusable).
        * With --strict-actuallength, ACTUALLENGTH 0 with bytes present cannot continue either.

        The first continued violation on a channel is printed as an error."""
        if ret is None or ret.payload.get('_encrypted'):
            return b''

        def _b(v) -> bytes:
            return bytes.fromhex(v) if isinstance(v, str) else bytes(v or b'')

        td = _b(ret.payload.get('transferdata') or '')
        actual = ret.payload.get('actuallength', 0)
        present = max(len(ret.data) - 12, 0)   # bytes after SEQNUM..RSTATUS (Figure 23)
        if actual == present:
            return td
        where = f"{ret.msg_type_name} SEQNUM={ret.payload.get('seqnum')}"
        if actual > present:
            raise ReturnDataUnusable(f"{where}: ACTUALLENGTH={actual} exceeds the {present} "
                                     f"byte(s) the message carries (§9.18-20)")
        if actual == 0 and self._session.strict_actuallength:
            raise ReturnDataUnusable(f"{where}: ACTUALLENGTH=0 with {present} byte(s) after "
                                     f"RSTATUS, not accepted with --strict-actuallength "
                                     f"(§9.18-20)")
        if actual == 0:
            use = _b(ret.payload.get('excess_data') or '')
            note = (f"ACTUALLENGTH=0 but {present} byte(s) follow RSTATUS; continuing with "
                    f"those bytes")
        else:
            use = td
            note = (f"{present - actual} byte(s) follow the ACTUALLENGTH={actual} bytes of "
                    f"data; continuing with the ACTUALLENGTH bytes")
        if not self._warned_excess:
            self._warned_excess = True
            self._session.error(f"Data channel {self._sid()}: {where}: {note}. A §9.18-20 "
                                f"SHALL violation: the run FAILS (non-fatal, the test continues)")
        return use

    def _check_device_qualifier(self, bcd_usb: Optional[int]) -> bool:
        """GET_DESCRIPTOR(Device_Qualifier, 10), sent with --device-qualifier.

        Optional for a host (USB 2.0 §9.2.6.6: "These descriptors are not retrieved unless
        the host explicitly issues the corresponding GetDescriptor requests"), and not sent to
        a device below bcdUSB 0x0200 ("A USB 1.x device ... should not be issued the
        other_speed requests"). A device with version 0200H that answers neither a
        device_qualifier descriptor nor a request error is reported against §9.6.2: "If a
        full-speed only device (with a device descriptor version number equal to 0200H)
        receives a GetDescriptor() request for a device_qualifier, it must respond with a
        request error." Returns True when the Sender closed the channel (fatal)."""
        sess = self._session
        if bcd_usb is None:
            sess.warn("GET_DESCRIPTOR(Device_Qualifier): skipped, bcdUSB unknown "
                      "(no device descriptor)")
            return False
        if bcd_usb < 0x0200:
            sess.log(f"    GET_DESCRIPTOR(Device_Qualifier): skipped, bcdUSB=0x{bcd_usb:04X} "
                     f"< 0x0200 (USB 2.0 §9.2.6.6)")
            return False
        ret = self._ctrl_transfer(
            _get_descriptor_req(USB_DT_DEVICE_QUALIFIER, 0, 10), 10)
        if ret is None:
            if self._ch.closed:
                return True
            sess.warn("GET_DESCRIPTOR(Device_Qualifier): timeout")
            return False
        rstatus = ret.payload.get('rstatus', -1)
        rname = ret.payload.get('rstatus_name', '?')
        data = self._return_data(ret)
        speed = (usb.UsbSpeed(self._usbspeed).name
                 if self._usbspeed in usb.UsbSpeed._value2member_map_ else "unknown speed")
        if rstatus != 0:
            sess.log(f"    GET_DESCRIPTOR(Device_Qualifier): request error {rname} "
                     f"(what USB 2.0 §9.6.2 requires of a full-speed only device)")
        elif len(data) >= 10 and data[1] == USB_DT_DEVICE_QUALIFIER:
            sess.log(f"    GET_DESCRIPTOR(Device_Qualifier): OK, the device declares "
                     f"high-speed capability  data={data.hex()}")
        else:
            sid = f"0x{self._substreamid:02X}" if self._substreamid is not None else "?"
            desc = (f"Data channel (substreamid={sid}): GET_DESCRIPTOR(Device_Qualifier) answered "
                    f"{rname} with {len(data)} byte(s) and no device_qualifier descriptor, by a "
                    f"device with bcdUSB=0x{bcd_usb:04X} operating at {speed}; a full-speed only "
                    f"device with version 0200H must respond with a request error "
                    f"(USB 2.0 §9.6.2)")
            sess.error(desc)
            sess.add_tester_finding(Severity.ERROR, "USB2-9.6.2", desc)
        return False

    def _enumerate(self) -> list[EndpointInfo]:
        """
        Drive the USB host enumeration sequence against the real device.

        Returns the interrupt IN endpoints to poll (see _interrupt_in_endpoints), [] if none.
        """
        sess = self._session
        sess.log("  Starting USB enumeration …")

        def _xfr(ret) -> bytes:
            """USB transfer data bytes of a SUBMIT_RETURN (see _return_data)."""
            return self._return_data(ret)

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
        str_indexes: list[int] = []        # iManufacturer, iProduct, iSerialNumber that are set
        bcd_usb: Optional[int] = None
        cfg_value: Optional[int] = None    # bConfigurationValue of the configuration descriptor
        int_eps: list[EndpointInfo] = []
        hid_ifaces: list[EndpointInfo] = []
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

        # 2. SET_ADDRESS — --set-address: "unique" (default) gives each device its own
        #    address, as a USB host does; "none" sends none. TR-10-14 says nothing of
        #    SET_ADDRESS.
        if not fatal and sess.set_address == SetAddressMode.UNIQUE:
            if self._address is None:
                self._address = sess.allocate_address()
            addr = self._address
            ret = self._ctrl_transfer(_set_address_req(addr), 0)
            if ret is None and self._ch.closed:
                fatal = True
            elif not _ok(ret):
                sess.warn(f"SET_ADDRESS({addr}): {_status(ret)}")

        # 3. GET_DESCRIPTOR(Device, 18) — full device descriptor
        if not fatal:
            ret = self._ctrl_transfer(
                _get_descriptor_req(USB_DT_DEVICE, 0, 18), 18)
            if ret is None and self._ch.closed:
                fatal = True
            if _ok(ret):
                raw_dev = _xfr(ret)
                device_class = raw_dev[4]  if len(raw_dev) >= 5  else 0
                # Table 9-8 offsets 14-16 are string indexes, 0 when the string is absent.
                str_indexes  = list(dict.fromkeys(i for i in raw_dev[14:17] if i))
                bcd_usb = struct.unpack_from('<H', raw_dev, 2)[0] if len(raw_dev) >= 4 else None
                sess.log(f"    Device class=0x{device_class:02X}  "
                         f"data={raw_dev.hex() or '(empty)'}")
            elif not fatal:
                sess.warn(f"GET_DESCRIPTOR(Device,18): {_status(ret)}")

        # 3b. GET_DESCRIPTOR(Device_Qualifier, 10) — with --device-qualifier only
        if not fatal and sess.device_qualifier:
            fatal = self._check_device_qualifier(bcd_usb)

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
                if len(raw_cfg9) >= 6 and raw_cfg9[1] == USB_DT_CONFIG:
                    cfg_value = raw_cfg9[5]
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
                endpoints = parse_config_descriptor(raw_cfg)
                int_eps = _interrupt_in_endpoints(endpoints)
                hid_ifaces = _hid_interfaces(endpoints)
                if len(raw_cfg) >= 6 and raw_cfg[1] == USB_DT_CONFIG:
                    cfg_value = raw_cfg[5]
                polled = ' '.join(f"0x{ep.address:02X}" for ep in int_eps) or 'none'
                sess.log(f"    Config descriptor: {len(endpoints)} endpoint(s)  "
                         f"interrupt_in={polled}  "
                         f"data={raw_cfg.hex() or '(empty)'}")
            elif not fatal:
                sess.warn(f"GET_DESCRIPTOR(Config,{total_len}): {_status(ret)}")

        # 6–8. String descriptors (best-effort): string 0 lists the LANGIDs the device supports
        #      (USB 2.0 §9.6.7); its iManufacturer, iProduct and iSerialNumber are read in one of
        #      them, 0x0409 when listed. A device without strings has no index set and no list.
        if not fatal and str_indexes:
            ret = self._ctrl_transfer(_get_descriptor_req(USB_DT_STRING, 0, 255, 0), 255)
            if ret is None and self._ch.closed:
                fatal = True
            langids = _langids(_xfr(ret)) if _ok(ret) else []
            langid = 0x0409 if 0x0409 in langids else (langids[0] if langids else None)
            if not fatal and langid is None:
                sess.warn(f"String descriptor 0: {_status(ret) if not _ok(ret) else 'no LANGID'} "
                          f"— strings {str_indexes} not read")
            for idx in str_indexes if langid is not None else []:
                if fatal:
                    break
                ret = self._ctrl_transfer(
                    _get_descriptor_req(USB_DT_STRING, idx, 255, langid), 255)
                if ret is None and self._ch.closed:
                    fatal = True

        # 9. SET_CONFIGURATION — with the configuration descriptor's bConfigurationValue
        #    (USB 2.0 §9.4.7). Always attempted, even if descriptors failed: then with 1.
        configured = False
        if not fatal:
            value = cfg_value if cfg_value else 1
            if not cfg_value:
                sess.warn("SET_CONFIGURATION: no bConfigurationValue known — trying 1")
            ret = self._ctrl_transfer(_set_configuration_req(value), 0)
            if ret is None and self._ch.closed:
                fatal = True
            elif _ok(ret):
                configured = True
                sess.log(f"    SET_CONFIGURATION({value}): OK")
            elif ret is not None:
                sess.warn(f"SET_CONFIGURATION({value}): {_status(ret)}")
            if not fatal and not configured and int_eps:
                # Testing continues: USB 2.0 is not a TR-10-14 requirement (--diagnose: DIAG).
                sess.warn("SET_CONFIGURATION did not succeed: the device is polled although "
                          "it may not be configured (USB 2.0 §9.2.3)")

        # 10–11. HID class requests, to each HID interface by its number (HID 1.11 §7.2):
        #        SET_IDLE to all of them; SET_PROTOCOL(boot) only to the boot subclass, where
        #        it is supported (§7.2.6) and where the poll decodes boot reports.
        for iface in hid_ifaces:
            if fatal:
                break
            ret = self._ctrl_transfer(_set_idle_req(iface.iface_number), 0)
            if ret is None and self._ch.closed:
                fatal = True
                break
            if iface.iface_subclass == USB_HID_SUBCLASS_BOOT:
                ret = self._ctrl_transfer(
                    _set_protocol_req(HidProtocol.BOOT, iface.iface_number), 0)
                if ret is None and self._ch.closed:
                    fatal = True

        if fatal:
            sess.warn("Enumeration aborted — Sender closed data channel")
            return []

        sess.log(f"  USB enumeration complete (seqnum now={self._seqnum})")
        return int_eps

    # ------------------------------------------------------------------

    def _poll_loop(self, eps: list[EndpointInfo]) -> None:
        """Periodically poll the interrupt IN endpoints for HID events, until the test stops,
        the Sender closes the channel, or the channel cannot go on.

        Each endpoint has one INTERRUPT_SUBMIT outstanding at a time, and the endpoints are
        polled together: an interrupt IN transfer completes only when the device has data, so
        a quiet endpoint (a keyboard nobody types on, an absolute mouse that does not move) is
        normal and must not hold back another (the mouse of a composite keyboard+mouse). A
        Return answers the Submit whose SEQNUM it carries (§9.18); its endpoint is submitted
        again one poll interval after it.
        """
        sess      = self._session
        interval  = self._poll_ms / 1000.0   # seconds
        for ep in eps:
            sess.log(f"  Polling interrupt endpoint 0x{ep.address:02X}  "
                     f"interval={ep.interval} ms  "
                     f"maxpkt={ep.max_packet} B")

        outstanding: dict[int, EndpointInfo] = {}           # SEQNUM -> endpoint, not yet returned
        due: dict[int, float] = {ep.address: 0.0 for ep in eps}   # endpoint -> next Submit time

        while not self._stop.is_set() and not self._ch.closed:
            # Send the INTERRUPT_SUBMIT of each endpoint that is due
            for ep in eps:
                if due.get(ep.address, float('inf')) <= time.monotonic():
                    del due[ep.address]
                    seq = self._seqnum
                    self._send(usb.build_usb_interrupt_submit(
                        seq, ep.endpoint_num, ep.direction,
                        ep.interval, ep.max_packet or 8,
                    ))
                    # Table 11: the next Submit takes the next SEQNUM whatever this one gets back.
                    self._seqnum += 1
                    outstanding[seq] = ep

            # Wait for a Return until the next endpoint is due, at most 1 s. A message the
            # Sender may not send (a USB Stream Reset, …), a Return of no outstanding Submit,
            # or a Cancel Submit Return (this tester sends no Cancel Submit) answers nothing
            # outstanding here: the wait goes on.
            wait = min([1.0] + [t - time.monotonic() for t in due.values()])
            msg = self._ch.recv_msg(timeout=max(wait, 0.0))
            if msg is None:
                continue
            self._record_sender_msg(msg)
            if self._from_wrong_side(msg) or self._answers_other_submit(msg, outstanding):
                continue
            mt = msg.msg_type_enum
            if mt == MsgType.USB_CANCEL_SUBMIT_RETURN:
                sess.log(f"  USB_CANCEL_SUBMIT_RETURN (seqnum="
                         f"{msg.payload.get('seqnum', '?')}) for no Cancel Submit: ignored")
                continue

            if mt == MsgType.USB_ENTER_SLEEP:
                sess.log("  USB Enter Sleep on data channel — stopping")
                self._stop.set()
                break
            if mt != MsgType.USB_INTERRUPT_SUBMIT_RETURN:
                sess.warn(f"Expected INTERRUPT_SUBMIT_RETURN, got {msg.msg_type_name}")
                break

            # A Return that could not be decrypted has no readable SEQNUM: it is taken as the
            # answer of the oldest Submit outstanding, so that polling goes on.
            seq = msg.payload.get('seqnum')
            if seq not in outstanding:
                if not outstanding:
                    continue
                seq = min(outstanding)
            ep = outstanding.pop(seq)
            due[ep.address] = time.monotonic() + interval

            try:
                td = self._return_data(msg)
            except ReturnDataUnusable as e:
                sess.error(f"Data channel {self._sid()}: cannot continue: {e}. Polling of "
                           f"this channel stops; the run FAILS")
                break
            if (sess.verbose or sess.hid_only) and not msg.payload.get('_encrypted'):
                if td != self._prev_hid.get(ep.address, b''):
                    self._prev_hid[ep.address] = td
                    if any(td):
                        self._decode_hid(td, ep)

        if self._ch.closed and outstanding:
            sess.warn("Sender closed the data channel with an INTERRUPT_SUBMIT pending")

    def _record_sender_msg(self, msg: 'IpmxUsbMessage') -> None:
        """Record a Sender-originated data-channel message."""
        if self._substreamid is not None:
            self._session.record_data_msg(
                msg, self._substreamid, 'sender',
                self._ch.remote_ip, self._ch.remote_port,
                self._ch.local_ip, self._ch.local_port,
                pkt_num=self._ch.last_recv_pkt_num,
            )

    def _from_wrong_side(self, msg: IpmxUsbMessage) -> bool:
        """True for a message type TR-10-14 assigns to the Receiver, sent by the Sender: flagged
        and ignored (see _ignore_receiver_message)."""
        return _ignore_receiver_message(self._session, msg, f"Data channel {self._sid()}",
                                        self._warned_wrong_side)

    # ------------------------------------------------------------------

    def _decode_hid(self, data: bytes, ep: EndpointInfo) -> None:
        """Decode a HID boot-protocol report and print human-readable output.

        Keyboard: shows the actual character(s) typed (using the standard HID
        usage table) plus any active modifier keys.
        Mouse: shows button presses and movement direction as an arrow.

        Classification and byte-level parsing live in :mod:`usb_decode`, shared
        with usbDissector.py; this method only renders the structured result as
        an emoji event line.
        """
        sess = self._session
        kind = classify_hid(ep)

        if kind == HidBootProtocol.KEYBOARD and len(data) >= 3:
            self._decode_keyboard_report(data)
        elif kind == HidBootProtocol.MOUSE and len(data) >= 3:
            self._decode_mouse_report(data)
        else:
            sess.hid(f"  HID raw ({ep.max_packet}B): {data.hex()}")

    def _decode_keyboard_report(self, data: bytes) -> None:
        """Render a keyboard boot report: [mods, reserved, key0..key5]."""
        sess = self._session
        report = decode_keyboard_report(data)
        if report is None:
            return
        char_str = report.text
        mod_parts = report.modifiers

        if char_str and mod_parts:
            non_shift_mods = [m for m in mod_parts if 'Shift' not in m]
            prefix = '+'.join(non_shift_mods) + '+' if non_shift_mods else ''
            sess.hid(f"  ⌨  {prefix}{char_str!r}")
        elif char_str:
            sess.hid(f"  ⌨  {char_str!r}")
        elif report.mods:
            sess.hid(f"  ⌨  <{'+'.join(mod_parts)}>")
        # all-zero report = key release, skip

    def _decode_mouse_report(self, data: bytes) -> None:
        """Render a mouse boot report: [buttons, dx, dy, wheel?]."""
        sess = self._session
        report = decode_mouse_report(data)
        if report is None:
            return
        dx, dy, wheel = report.dx, report.dy, report.wheel

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
        if report.buttons:
            parts.append(f"[{' '.join(report.buttons)}]")

        if parts:
            sess.hid(f"  🖱  {' '.join(parts)}")

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

            if self._from_wrong_side(msg):
                continue
            if mt == MsgType.USB_CANCEL_SUBMIT_RETURN:
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
    strict_actuallength: bool = False,
    enumerate_in_sequence: bool = False,
    device_qualifier: bool = False,
    set_address: SetAddressMode = SetAddressMode.UNIQUE,
    first_address: int = 1,
    diagnose: bool = False,
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
    session.strict_actuallength = strict_actuallength
    session.enumerate_in_sequence = enumerate_in_sequence
    session.device_qualifier = device_qualifier
    session.set_address = set_address
    session._next_address = first_address
    session.diagnose = diagnose

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

    return session.final_report().value


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
        help=f"HID interrupt poll interval in ms, per endpoint (default: {DEFAULT_POLL_INTERVAL_MS})",
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

    parser.add_argument(
        '--strict-actuallength', action='store_true', default=False,
        help="Do not continue past a Submit Return with ACTUALLENGTH 0 and bytes after "
             "RSTATUS: that channel stops. Default: such a Return is a §9.18-20 error "
             "(the run fails) but the test continues with those bytes. Either way a "
             "Return shorter than its ACTUALLENGTH stops the channel, and one with "
             "bytes past a non-zero ACTUALLENGTH continues with ACTUALLENGTH bytes.",
    )
    parser.add_argument(
        '--diagnose', action='store_true', default=False,
        help="Also check each data channel against core USB 2.0 Chapter 9 rules, as "
             "usbDissector.py --diagnose does. Breaches are DIAG findings: TR-10-14 does not "
             "mandate them, so they never fail the run or stop it.",
    )
    parser.add_argument(
        '--enumerate-in-sequence', action='store_true', default=False,
        help="Enumerate the data channels one at a time instead of all at once. "
             "TR-10-14 requires neither; use it to test further a Sender that fails "
             "under concurrent enumeration.",
    )
    parser.add_argument(
        '--device-qualifier', action='store_true', default=False,
        help="Request the device_qualifier descriptor during enumeration (optional "
             "for a host, USB 2.0 §9.2.6.6) and report a device with bcdUSB 0x0200 "
             "that answers neither a qualifier nor a request error (§9.6.2).",
    )
    parser.add_argument(
        '--set-address', type=SetAddressMode, default=SetAddressMode.UNIQUE,
        choices=list(SetAddressMode), metavar='{unique,none}',
        help="SET_ADDRESS during enumeration: 'unique' (default) gives each device its "
             "own address, 1, 2, 3, ..., as a USB host does (USB 2.0 §9.1.2); 'none' "
             "sends no SET_ADDRESS, like a Receiver that keeps the bus address local. "
             "TR-10-14 says nothing of SET_ADDRESS.",
    )
    parser.add_argument(
        '--first-address', type=int, default=1, metavar='N',
        help="First address 'unique' gives (1-127, default 1); the next devices get N+1, "
             "N+2, ... A host gives the next free addresses on its bus, so behind a "
             "Receiver whose host has other USB devices they rarely start at 1.",
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
    if not (1 <= args.first_address <= 127):
        parser.error("--first-address must be in [1, 127]")

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
        strict_actuallength   = args.strict_actuallength,
        enumerate_in_sequence = args.enumerate_in_sequence,
        device_qualifier      = args.device_qualifier,
        set_address           = args.set_address,
        first_address         = args.first_address,
        diagnose              = args.diagnose,
        iv_swapn         = iv_swapn,
    ))


if __name__ == '__main__':
    main()
