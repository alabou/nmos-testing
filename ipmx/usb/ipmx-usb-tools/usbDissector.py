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
import collections
import json
import math
import statistics
import struct
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
    DIAG    = "DIAG"     # for the operator to judge; never an error, a warning or a reason to stop:
                         # a core USB 2.0 rule not met (--diagnose), which TR-10-14 does not mandate,
                         # or a message TR-10-14 requires but sets no time for, not sent by the time
                         # the observation of it ended (always reported)


class Requirement(Enum):
    """
    The requirements checklist (-r): one member per normative statement a check
    enforces, in checklist order. Each finding names the member its check enforces,
    so a row fails only on its own findings, never on another row's in the same section.
    """
    # §8 — Communication channels
    CTRL_FIRST_IS_SENDER_INFO   = ("8.3.1.1",  "SHALL",  "Control channel: first Sender message is SenderConnectionInfo")
    CTRL_STATUS_RESPONSE        = ("8.3.1.1",  "SHALL",  "Control channel: Receiver sends SenderConnectionStatus in response")
    DATA_FIRST_IS_STREAM_INFO   = ("8.3.1.2",  "SHALL",  "Data channel: first Sender message is USBStreamInformation")
    DATA_STATUS_RESPONSE        = ("8.3.1.2",  "SHALL",  "Data channel: Receiver sends USBStreamStatus in response")
    DATA_NO_SUBMIT_BEFORE_STATUS = ("8.3.1.2", "SHALL",  "Data channel: Receiver does not send USB Submit before USBStreamStatus")
    # §9 — Message framing
    HEADER_RESERVED_ZERO        = ("9",        "SHALL",  "Header Reserved 7 bits SHALL be 0 before transmission")
    MESSAGE_DIRECTION           = ("9.1-23",   "SHALL",  "Each message is sent only by the side its section assigns it (MSGTYPE bit 0: 0 Sender, 1 Receiver)")
    ENCRYPTED                   = ("9",        "SHOULD", "Messages SHOULD be encrypted and authenticated (TR-10-13)")
    # §9.1 — SenderConnectionInfo
    SCI_MAVER                   = ("9.1",      "SHALL",  "SenderConnectionInfo: MAVER=0 for this version")
    SCI_MIVER                   = ("9.1",      "SHALL",  "SenderConnectionInfo: MIVER=0 for this version")
    SCI_RESERVED                = ("9.1",      "SHALL",  "SenderConnectionInfo: Reserved byte SHALL be 0")
    SCI_CID                     = ("9.1",      "SHALL",  "SenderConnectionInfo: CID matches expected value (if supplied)")
    SCI_SN                      = ("9.1",      "SHALL",  "SenderConnectionInfo: SN matches expected value (if supplied)")
    # §9.2 — SenderConnectionStatus
    SCS_VERSION                 = ("9.2",      "SHALL",  "SenderConnectionStatus: Receiver version ≤ Sender version")
    SCS_HBEAT_RANGE             = ("9.2",      "SHALL",  "SenderConnectionStatus: HBEAT in [5, 30]")
    SCS_RSVD                    = ("9.2",      "SHALL",  "SenderConnectionStatus: Rsvd 3 bits SHALL be 0")
    # §9.4 — VendorSpecificInfo
    VSI_VMTYPE_RESERVED         = ("9.4",      "SHALL",  "VendorSpecificInfo VMTYPE 1-15 are reserved — SHALL NOT be used")
    VSI_VMDATA_LENGTH           = ("9.4",      "SHALL",  "VendorSpecificInfo VMTYPE=0 VMDATA SHALL be ≤ 256 bytes")
    # §9.5/9.6 — VendorSpecificQuery/Return
    VSQ_ANSWERED                = ("9.6",      "SHALL",  "VendorSpecificQuery: Receiver SHALL answer every query")
    VSQ_VQSTS_RESERVED          = ("9.6",      "SHALL",  "VendorSpecificQuery: VQSTS=255 for unknown/reserved VQTYPE")
    VSQR_VQDATA_LENGTH          = ("9.6",      "SHALL",  "VendorSpecificQueryReturn VQDATA (VQTYPE=0) SHALL be ≤ 256 bytes")
    VSQR_CID                    = ("9.6",      "SHALL",  "VendorSpecificQueryReturn CID SHALL match Query CID for VQTYPE 16-255")
    # §9.3 — Heartbeat
    HEARTBEAT_EMPTY             = ("9.3",      "SHALL",  "Heartbeat DATA SHALL be empty (0 bytes)")
    # §9.7 — USBStreamInfo
    SSI_SUBSTREAMID_BIT0        = ("9.7",      "SHALL",  "USBStreamInfo SUBSTREAMID bit 0 SHALL be 0 (Sender-to-Receiver direction)")
    SSI_SUBSTREAMID_CHANNEL     = ("9.7",      "SHALL",  "USBStreamInfo SUBSTREAMID bits 7:1 SHALL be in [1, 127] for data channels")
    HANDSHAKE_SSID              = ("9.7",      "SHOULD", "Data-channel handshake (USB_STREAM_INFO/USB_STREAM_STATUS) "
                                                         "SHOULD be encrypted with SSID 2 (S2R) / 3 (R2S)")
    # §9.8 — USBStreamStatus
    USS_CSTATUS                 = ("9.8",      "SHALL",  "USBStreamStatus CSTATUS SHALL be 0 (OK) or 255 (error); others are reserved")
    # §9.9 — USBStreamReset
    RESET_WAIT                  = ("9.9",      "SHALL",  "USBStreamReset: Receiver SHALL wait for ResetReturn before further Submits")
    # §9.10 — USBStreamResetReturn
    RESET_RETURN_SENT           = ("9.10",     "SHALL",  "USBStreamResetReturn SHALL be sent by the Sender for every USBStreamReset")
    RESET_RETURN_EMPTY          = ("9.10",     "SHALL",  "USBStreamResetReturn DATA SHALL be empty (0 bytes)")
    # §9.11 — USBWakeupControl
    WAKECTRL_VALUE              = ("9.11",     "SHALL",  "USBWakeupControl WAKECTRL SHALL be 0 or 1")
    # §9.12 — USB Enter Sleep
    SLEEP_CLOSE                 = ("9.12",     "SHALL",  "USB Enter Sleep + WoL enabled: Sender SHALL close all connections")
    SLEEP_NO_RECONNECT          = ("9.12",     "SHOULD", "USB Enter Sleep received: Receiver SHOULD NOT reconnect until WoL")
    # §9.15 — USB Control Submit
    CONTROL_USBDEVREQ_LENGTH    = ("9.15",     "SHALL",  "USB Control Submit USBDEVREQ SHALL be 8 bytes")
    # §9.17 — USB Isochronous Submit
    ISO_ASAP_STARTFRAME         = ("9.17",     "SHALL",  "USB Isochronous Submit: STARTFRAME SHALL be 0 when A (ASAP) is 1")
    # §10 — Sub-stream multiplexing
    SUBSTREAM_PARITY            = ("10",       "SHALL",  "S2R substreamid SHALL be even; R2S substreamid SHALL be odd")
    # §9.14 — SEQNUM
    SUBMIT_SEQNUM               = ("9.14",     "SHALL",  "Submit SEQNUM starts at 0 and increments by 1 per Submit")
    SUBMIT_RSVD                 = ("9.14",     "SHALL",  "Submit Reserved bits (Rsvd 3 in endpoint byte) SHALL be 0")
    SUBMIT_DATA_FIELDS          = ("9.14-16",  "SHALL",  "Control/Bulk/Interrupt Submit DATA SHALL be exactly its Table 10/11 fields (TRANFERDATA = TRANSFERLENGTH bytes on OUT, none on IN)")
    # §9.18 — Submit Return
    RETURN_SEQNUM               = ("9.18",     "SHALL",  "Submit Return SEQNUM SHALL match an outstanding Submit")
    RETURN_ENDPOINT             = ("9.18",     "SHALL",  "Submit Return ENDPOINT SHALL match Submit ENDPOINT")
    RETURN_DIRECTION            = ("9.18",     "SHALL",  "Submit Return D SHALL match Submit D")
    RETURN_OUT_LENGTH           = ("9.18",     "SHALL",  "OUT (D=0) Submit Return: ACTUALLENGTH SHALL be 0")
    RETURN_IN_LENGTH            = ("9.18",     "SHALL",  "IN (D=1) Submit Return: ACTUALLENGTH SHALL be ≤ TRANSFERLENGTH")
    RETURN_RSVD                 = ("9.18",     "SHALL",  "Submit Return Reserved bits (Rsvd 3 in endpoint byte) SHALL be 0")
    RETURN_DATA_FIELDS          = ("9.18-20",  "SHALL",  "Control/Bulk/Interrupt Submit Return DATA SHALL be exactly its Table 14 fields (TRANFERDATA = ACTUALLENGTH bytes)")
    RETURN_SENT                 = ("9.18/19/23", "SHALL", "Every Control, Bulk and Cancel Submit SHALL get its Submit Return")
    # §11 — Heartbeat
    HEARTBEAT_GAP_MAX           = ("11",       "SHALL",  "Heartbeat gap SHALL be ≤ 2 × Heartbeat_Period (unresponsive threshold)")
    # §12 — Encryption
    CLEAR_CTR_ZERO              = ("12",       "SHALL",  "Unencrypted mode: CTR SHALL be 0 on every message")
    CLEAR_KEYVERSION_ZERO       = ("12",       "SHALL",  "Unencrypted mode: KEYVERSION SHALL be 0 on every message")
    CLEAR_MAC_ZERO              = ("12",       "SHALL",  "Unencrypted mode: MAC SHALL be 0x0000000000000000 on every message")
    CTR_MONOTONIC               = ("12",       "SHALL",  "Encrypted mode: CTR SHALL increase monotonically per direction")
    KEYVERSION_NONZERO_CONSISTENT = ("12",     "SHALL",  "Encrypted mode: KEYVERSION SHALL be non-zero and consistent within a TCP session")
    CMAC_VERIFIES               = ("12",       "SHALL",  "Encrypted mode: CMAC-64 authentication SHALL verify correctly")
    MODE_ALLOWED                = ("12",       "SHALL",  "Mode SHALL be one of the allowed values (AES-128/256-CTR_CMAC-64-AAD, ECDH variants)")
    MODE_AES128_SUPPORTED       = ("12",       "SHALL",  "Senders and Receivers SHALL support AES-128-CTR_CMAC-64-AAD mode")
    # §A.1 — Status codes
    STATUS_DEFINED              = ("A.1",      "SHALL",  "RSTATUS / ISOSTATUS SHALL be a defined status code")

    def __init__(self, section: str, level: str, text: str) -> None:
        self.section = section
        self.level = level
        self.text = text


class Diagnostic(Enum):
    """
    The USB 2.0 diagnostics (--diagnose): core Chapter 9 rules a data channel's
    traffic can be checked against. TR-10-14 is based on USB 2.0 (§1) but does not
    say which of these a Receiver or Sender must honour across IPMX, so a breach
    is reported as DIAG and never fails a capture.

    Each rule is judged per data-channel connection from what that connection
    itself shows: a rule that depends on the device's state applies only once the
    stream has established that state (a USB Stream Reset, a SET_CONFIGURATION),
    never from what the device behind the Sender might be. Levels follow the USB
    2.0 wording: SHALL for "must"/"shall", SHOULD for "should", UNSPEC for
    "behavior … is not specified", IMPLIED where the rule follows from a
    definition without a keyword.
    """
    CONFIGURE_BEFORE_USE  = ("USB2 9.2.3",   "SHALL",   "Interrupt, bulk and isochronous transfers only after a successful "
                                                        "SET_CONFIGURATION on the connection")
    CONFIGURATION_VALUE   = ("USB2 9.4.7",   "SHALL",   "SET_CONFIGURATION value is 0 or the bConfigurationValue of a "
                                                        "configuration descriptor returned on the connection")
    CONFIGURATION_FIELDS  = ("USB2 9.4.7",   "UNSPEC",  "SET_CONFIGURATION wIndex, wLength and wValue high byte are zero")
    ADDRESS_WHEN_CONFIGURED = ("USB2 9.4.6", "UNSPEC",  "No SET_ADDRESS once the connection has configured the device")
    CONFIGURED_ONLY       = ("USB2 9.4",     "SHALL",   "Requests valid only in the Configured state are not sent while "
                                                        "the connection has left the device unconfigured")
    OTHER_SPEED_ORDER     = ("USB2 9.6.2",   "SHALL",   "other_speed_configuration requested only after a successful "
                                                        "device_qualifier")
    OTHER_SPEED_USB1      = ("USB2 9.2.6.6", "SHOULD",  "No other_speed request to a device whose bcdUSB is below 0x0200")
    STRING_LANGID         = ("USB2 9.6.7",   "IMPLIED", "String descriptors requested with a LANGID listed by string "
                                                        "descriptor 0 of the connection")
    DESCRIPTOR_INDEX      = ("USB2 9.4.3",   "SHALL",   "Descriptor index 0 for standard descriptors other than "
                                                        "configuration and string; configuration index below "
                                                        "bNumConfigurations")
    DESCRIPTOR_WINDEX     = ("USB2 9.4.3",   "SHALL",   "wIndex 0 on standard descriptor requests other than string")

    def __init__(self, section: str, level: str, text: str) -> None:
        self.section = section
        self.level = level
        self.text = text


@dataclass
class Finding:
    severity: Severity
    section: str          # e.g. "8.3.1.1"
    description: str
    packet_number: Optional[int] = None
    detail: Optional[str] = None
    connection: Optional[str] = None   # label of the TCP connection it was found on, if any
    requirement: Optional[Enum] = None   # the Requirement or Diagnostic row its check enforces

    def __str__(self) -> str:
        pkt = f" [pkt #{self.packet_number}]" if self.packet_number else ""
        conn = f" [{self.connection}]" if self.connection else ""
        detail = f"\n    Detail: {_printable(self.detail)}" if self.detail else ""
        return (f"  [{self.severity.value}] §{self.section}{pkt}{conn}: "
                f"{_printable(self.description)}{detail}")


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
# TCP connection lifecycle
#
# Communication channels are TCP connections (§8). SYN, FIN and RST segments
# carry no payload, so they never reach the stream reassembler; they are
# collected separately so the report can say when each channel opened, when it
# ended and which side ended it. A Sender closing a data channel means the USB
# device was disconnected (§8.3.1.2), so a channel closed while its device is
# still attached shows up on the wire only here.
# ---------------------------------------------------------------------------

class TcpEventKind(str, Enum):
    SYN = "SYN"    # connection request from the TCP client
    FIN = "FIN"    # orderly close by the side that sent it
    RST = "RST"    # abort by the side that sent it


class ChannelRole(str, Enum):
    SENDER   = "Sender"
    RECEIVER = "Receiver"


#: The side that sends each message type, and the TR-10-14 section that assigns it (§9.1-§9.23;
#: §11 also gives the Heartbeat to the Sender). MSGTYPE says the same in its bit 0 ("Bit 0 the
#: direction", §9): 0 on every message a Sender sends, 1 on every message a Receiver sends.
MESSAGE_SENDER: dict[MsgType, tuple[ChannelRole, str]] = {
    MsgType.SENDER_CONNECTION_INFO:        (ChannelRole.SENDER,   "9.1"),
    MsgType.SENDER_CONNECTION_STATUS:      (ChannelRole.RECEIVER, "9.2"),
    MsgType.HEARTBEAT:                     (ChannelRole.SENDER,   "9.3"),
    MsgType.VENDOR_SPECIFIC_INFO:          (ChannelRole.SENDER,   "9.4"),
    MsgType.VENDOR_SPECIFIC_QUERY:         (ChannelRole.SENDER,   "9.5"),
    MsgType.VENDOR_SPECIFIC_QUERY_RETURN:  (ChannelRole.RECEIVER, "9.6"),
    MsgType.USB_STREAM_INFO:               (ChannelRole.SENDER,   "9.7"),
    MsgType.USB_STREAM_STATUS:             (ChannelRole.RECEIVER, "9.8"),
    MsgType.USB_STREAM_RESET:              (ChannelRole.RECEIVER, "9.9"),
    MsgType.USB_STREAM_RESET_RETURN:       (ChannelRole.SENDER,   "9.10"),
    MsgType.USB_WAKEUP_CONTROL:            (ChannelRole.RECEIVER, "9.11"),
    MsgType.USB_ENTER_SLEEP:               (ChannelRole.SENDER,   "9.12"),
    MsgType.USB_RESUME_OPERATION:          (ChannelRole.SENDER,   "9.13"),
    MsgType.USB_CONTROL_SUBMIT:            (ChannelRole.RECEIVER, "9.14"),
    MsgType.USB_BULK_SUBMIT:               (ChannelRole.RECEIVER, "9.15"),
    MsgType.USB_INTERRUPT_SUBMIT:          (ChannelRole.RECEIVER, "9.16"),
    MsgType.USB_ISOCHRONOUS_SUBMIT:        (ChannelRole.RECEIVER, "9.17"),
    MsgType.USB_CONTROL_SUBMIT_RETURN:     (ChannelRole.SENDER,   "9.18"),
    MsgType.USB_BULK_SUBMIT_RETURN:        (ChannelRole.SENDER,   "9.19"),
    MsgType.USB_INTERRUPT_SUBMIT_RETURN:   (ChannelRole.SENDER,   "9.20"),
    MsgType.USB_ISOCHRONOUS_SUBMIT_RETURN: (ChannelRole.SENDER,   "9.21"),
    MsgType.USB_CANCEL_SUBMIT:             (ChannelRole.RECEIVER, "9.22"),
    MsgType.USB_CANCEL_SUBMIT_RETURN:      (ChannelRole.SENDER,   "9.23"),
}


def sent_by_other_side(mt: Optional[MsgType], sent_by: ChannelRole) -> Optional[tuple[ChannelRole, str]]:
    """The side and section TR-10-14 assigns message type *mt* to, when *sent_by* is not that
    side; None when *sent_by* is that side or the type is unknown."""
    assigned = MESSAGE_SENDER.get(mt)
    return assigned if assigned and assigned[0] != sent_by else None


@dataclass
class TcpEvent:
    """One connection-level TCP segment."""
    kind: TcpEventKind
    packet_number: int
    timestamp: float
    endpoint: str          # "ip:port" of the side that sent it


@dataclass
class TcpLifecycle:
    """How one TCP connection opened and ended within the capture.

    Only the client's first SYN, the first FIN from each side and the first RST
    are kept; later ones are retransmissions or the rest of the teardown.
    """
    syn: Optional[TcpEvent] = None          # None: the connection opened before the capture
    fins: list[TcpEvent] = field(default_factory=list)
    rst: Optional[TcpEvent] = None
    first_timestamp: Optional[float] = None
    last_timestamp: Optional[float] = None

    @property
    def opened_at(self) -> Optional[float]:
        return self.syn.timestamp if self.syn else self.first_timestamp

    @property
    def close(self) -> Optional[TcpEvent]:
        """The segment that ended the connection (its first FIN or RST), or None if still open."""
        events = self.fins[:1] + ([self.rst] if self.rst else [])
        return min(events, key=lambda e: e.packet_number) if events else None


# ---------------------------------------------------------------------------
# Session and channel models
# ---------------------------------------------------------------------------

@dataclass
class DataChannel:
    """Tracks state for one data channel (one USB device) over one TCP connection."""
    substreamid: int
    busid: str
    usbspeed: int
    stream_info_pkt: Optional[int] = None     # packet where USBStreamInfo was seen
    stream_status_pkt: Optional[int] = None   # packet where USBStreamStatus was seen
    stream_status_ok: bool = False
    messages: list[ChannelMessage] = field(default_factory=list)
    # per-direction SEQNUM trackers: {seqnum: packet_number}
    submit_seqnums: dict[int, dict] = field(default_factory=dict)  # seqnum → submit info
    # TCP connection carrying the channel (left empty by callers that validate live traffic)
    index: int = 0                            # 1-based, in the order the connections opened
    key: str = ''                             # canonical stream key
    sender_endpoint: str = ''                 # "ip:port" of the Sender side
    connection: Optional[TcpLifecycle] = None

    @property
    def receiver_endpoint(self) -> str:
        return next((e for e in self.key.split('-') if e != self.sender_endpoint), '')

    @property
    def label(self) -> str:
        return f"data #{self.index} {self.sender_endpoint}->{self.receiver_endpoint}"


@dataclass
class ControlChannel:
    """Tracks state for the control channel."""
    messages: list[ChannelMessage] = field(default_factory=list)
    sender_info: Optional[dict] = None        # payload of SenderConnectionInfo
    receiver_status: Optional[dict] = None    # payload of SenderConnectionStatus
    heartbeat_times: list[float] = field(default_factory=list)
    heartbeat_period: Optional[float] = None  # §11, from the SenderConnectionStatus HBEAT
    sleep_with_wol_at: Optional[float] = None # USB Enter Sleep with WoL enabled: all connections close (§9.12)
    connection_info_pkt: Optional[int] = None
    connection_status_pkt: Optional[int] = None
    # Vendor query tracking: vqtype → list of (pkt_num, answered)
    pending_vendor_queries: dict[int, list[int]] = field(default_factory=dict)
    # TCP connection carrying the channel (left empty by callers that validate live traffic)
    key: str = ''                             # canonical stream key
    sender_endpoint: str = ''                 # "ip:port" of the Sender side
    connection: Optional[TcpLifecycle] = None

    @property
    def receiver_endpoint(self) -> str:
        return next((e for e in self.key.split('-') if e != self.sender_endpoint), '')

    @property
    def label(self) -> str:
        return f"control {self.receiver_endpoint}->{self.sender_endpoint}"


@dataclass
class Session:
    """One complete Sender ↔ Receiver session (may span a reconnect)."""
    sender_ip: str
    sender_port: int
    receiver_ip: str
    receiver_data_port: int = 0
    control: ControlChannel = field(default_factory=ControlChannel)
    # The latest data-channel connection per SUBSTREAMID. A Sender that closes and
    # reopens a channel leaves several connections per SUBSTREAMID: every one of them
    # is in data_connections.
    data_channels: dict[int, DataChannel] = field(default_factory=dict)  # substreamid → channel
    data_connections: list[DataChannel] = field(default_factory=list)    # in the order they opened
    findings: list[Finding] = field(default_factory=list)
    # The end of the observation: the capture's last packet, or the end of a live test (None
    # while it runs). Messages still outstanding are reported against it (_report_outstanding).
    capture_end: Optional[float] = None
    diagnosed: bool = False                   # the USB 2.0 diagnostics ran (--diagnose)

    def add(self, severity: Severity, section: str, description: str,
            packet_number: int = None, detail: str = None,
            requirement: Optional[Enum] = None) -> None:
        self.findings.append(Finding(severity, section, description, packet_number, detail,
                                     requirement=requirement))


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


def _collect_lifecycles(packets: list) -> dict[str, TcpLifecycle]:
    """
    Record how each TCP connection opened and ended: its SYN, FINs and RST.
    Returns dict of stream_key → TcpLifecycle, keyed and numbered as _collect_streams.
    """
    lifecycles: dict[str, TcpLifecycle] = {}

    for pkt_num, pkt in enumerate(packets, 1):
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            continue
        tcp = pkt[TCP]
        ip = pkt[IP]

        key = make_stream_key(ip.src, tcp.sport, ip.dst, tcp.dport)
        lc = lifecycles.setdefault(key, TcpLifecycle())
        ts = float(pkt.time) if hasattr(pkt, 'time') else 0.0
        if lc.first_timestamp is None:
            lc.first_timestamp = ts
        lc.last_timestamp = ts

        endpoint = f"{ip.src}:{tcp.sport}"
        if tcp.flags.S and not tcp.flags.A and lc.syn is None:
            lc.syn = TcpEvent(TcpEventKind.SYN, pkt_num, ts, endpoint)
        if tcp.flags.F and all(f.endpoint != endpoint for f in lc.fins):
            lc.fins.append(TcpEvent(TcpEventKind.FIN, pkt_num, ts, endpoint))
        if tcp.flags.R and lc.rst is None:
            lc.rst = TcpEvent(TcpEventKind.RST, pkt_num, ts, endpoint)

    return lifecycles


def _close_role(event: TcpEvent, sender_endpoint: str) -> ChannelRole:
    return ChannelRole.SENDER if event.endpoint == sender_endpoint else ChannelRole.RECEIVER


def _endpoint_ip(endpoint: str) -> str:
    return endpoint.rpartition(':')[0]


def _session_for_data_channel(sessions: list[Session], channel: DataChannel,
                              opened_at: float) -> Optional[Session]:
    """
    The session a data channel belongs to: its Sender and Receiver, and the control
    connection that was up when the data channel opened.

    A Sender opens data channels for a Receiver that holds its control channel
    (§8.3.1.2), so after a control-channel reconnect each data channel belongs to
    the control connection open at the time. Falls back to the latest control
    connection opened before it; None when no session has this Sender.
    """
    sender_ip = _endpoint_ip(channel.sender_endpoint)
    receiver_ip = _endpoint_ip(channel.receiver_endpoint)
    same_sender = [s for s in sessions if s.sender_ip == sender_ip]
    candidates = ([s for s in same_sender
                   if _endpoint_ip(s.control.receiver_endpoint) == receiver_ip] or same_sender)

    spans = []
    for s in candidates:
        lc = s.control.connection
        start = (lc.opened_at if lc is not None
                 else min((m.timestamp for m in s.control.messages), default=None))
        end = lc.close.timestamp if lc is not None and lc.close is not None else None
        spans.append((s, start, end))

    for s, start, end in spans:
        if start is not None and start <= opened_at and (end is None or opened_at <= end):
            return s
    earlier = [(start, s) for s, start, _end in spans if start is not None and start <= opened_at]
    if earlier:
        return max(earlier, key=lambda e: e[0])[1]
    return candidates[0] if candidates else None


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
                    packet_number=cm.packet_number,
                    requirement=Requirement.HEADER_RESERVED_ZERO)


def _check_message_direction(
    session: Session,
    sender_msgs: list[ChannelMessage],
    receiver_msgs: list[ChannelMessage],
    where: str,
) -> None:
    """Each message type is sent by one side only (MESSAGE_SENDER): a message from the other
    side is an ERROR, reported once per message. MSGTYPE is in the clear, so this holds for
    messages that could not be decrypted too."""
    for msgs, role in ((sender_msgs, ChannelRole.SENDER), (receiver_msgs, ChannelRole.RECEIVER)):
        for cm in msgs:
            mt = cm.msg.msg_type_enum
            other = sent_by_other_side(mt, role)
            if other is None:
                continue
            assigned, section = other
            session.add(Severity.ERROR, section,
                        f"{where}: the {role.value} sent {mt.name} (MSGTYPE 0x{int(mt):02X}); "
                        f"§{section} assigns it to the {assigned.value}, and MSGTYPE bit 0 = "
                        f"{int(mt) & 1} identifies the {assigned.value}-to-{role.value} direction",
                        packet_number=cm.packet_number,
                        requirement=Requirement.MESSAGE_DIRECTION)


def _mandated_close(session: Session, close: TcpEvent, closer: ChannelRole,
                    data_channel: bool) -> str:
    """The TR-10-14 clause that has *closer* end the connection at *close*, if one applies."""
    ctrl = session.control
    if data_channel and closer is ChannelRole.SENDER:
        return "; §8.3.1.2: a Sender closes a data channel when its USB device is disconnected"
    if ctrl.sleep_with_wol_at is not None and close.timestamp >= ctrl.sleep_with_wol_at:
        return "; §9.12: USB Enter Sleep with WoL enabled, after which both sides close all connections"
    if closer is ChannelRole.RECEIVER and ctrl.heartbeat_period:
        last = max((t for t in ctrl.heartbeat_times if t <= close.timestamp), default=None)
        if last is not None and close.timestamp - last > 2.0 * ctrl.heartbeat_period:
            return (f"; §11: no Heartbeat in the {close.timestamp - last:.1f} s before it, more than "
                    f"2 × Heartbeat_Period, and a Receiver disconnects a non-responsive Sender")
    return ""


def _report_outstanding(
    session: Session,
    connection: Optional[TcpLifecycle],
    sender_endpoint: str,
    data_channel: bool,
    since: float,
    what: str,
    requirement: Requirement,
    packet_number: Optional[int],
) -> None:
    """Report a message TR-10-14 requires but sets no time for (a response, or a channel's first
    Sender message) that was not sent: *what* names it. A capture or a test can show only how long
    it was outstanding, never that it would not come, so this is a DIAG for the operator to judge,
    with that time and how the observation ended: the connection closed (by which side, and the
    clause that had it close, if any), or the capture or test ended with it open.

    Nothing is reported while a live test still runs (no capture_end and no closed connection)."""
    close = connection.close if connection is not None else None
    if close is not None:
        closer = _close_role(close, sender_endpoint)
        end = close.timestamp
        how = (f"when the {closer.value} closed the connection ({close.kind.value}, "
               f"pkt #{close.packet_number}){_mandated_close(session, close, closer, data_channel)}")
    elif session.capture_end is not None:
        end = session.capture_end
        how = ("when the capture ended, the connection still open" if connection is not None
               else "at the end of the test")
    else:
        return
    session.add(Severity.DIAG, requirement.section,
                f"{what}: outstanding {max(end - since, 0.0):.3f} s {how}. TR-10-14 sets no time "
                f"for it",
                packet_number=packet_number, requirement=requirement)


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
                    packet_number=cm.packet_number,
                    requirement=Requirement.SUBMIT_RSVD if role == "submit" else Requirement.RETURN_RSVD)


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

    # ------------------------------------------------------------------ §9.1-9.23
    # Each message from the side TR-10-14 assigns it to
    _check_message_direction(s, sender_msgs, receiver_msgs, "Control channel")

    # ------------------------------------------------------------------ §9 SHOULD
    # Messages SHOULD be encrypted and authenticated (TR-10-13).
    # Issue a WARNING if the stream appears unencrypted and --encrypted was not set.
    if not encrypted:
        s.add(Severity.WARNING, "9",
              "Stream is not encrypted; messages SHOULD be encrypted and authenticated (TR-10-13)",
              requirement=Requirement.ENCRYPTED)

    # ------------------------------------------------------------------ §12 MAC verification
    if decrypted:
        for cm in all_msgs:
            if cm.mac_ok is False:
                s.add(Severity.ERROR, "12",
                      f"{cm.msg.msg_type_name}: CMAC-64 verification failed",
                      packet_number=cm.packet_number,
                      requirement=Requirement.CMAC_VERIFIES)

    # ------------------------------------------------------------------ 8.3.1.1
    # SHALL: first message on control channel from Sender is SenderConnectionInfo.
    if not sender_msgs:
        lc = ctrl.connection
        since = lc.opened_at if lc is not None else None
        if since is None:
            since = min((m.timestamp for m in receiver_msgs), default=None)
        if since is not None:
            _report_outstanding(s, lc, ctrl.sender_endpoint, False, since,
                                "Control channel: the Sender sent no message (its first SHALL be "
                                "SenderConnectionInfo)",
                                Requirement.CTRL_FIRST_IS_SENDER_INFO,
                                lc.syn.packet_number if lc is not None and lc.syn else None)
        return

    first_sender = sender_msgs[0]
    if first_sender.msg.msg_type_enum != MsgType.SENDER_CONNECTION_INFO:
        s.add(Severity.ERROR, "8.3.1.1",
              f"First Sender message is {first_sender.msg.msg_type_name}; "
              "expected SenderConnectionInfo",
              packet_number=first_sender.packet_number,
              requirement=Requirement.CTRL_FIRST_IS_SENDER_INFO)

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
                  packet_number=sci.packet_number,
                  requirement=Requirement.SCI_MAVER)
        # SHALL: MIVER = 0 for this version
        if info.get('miver', -1) != 0:
            s.add(Severity.ERROR, "9.1",
                  f"SenderConnectionInfo MIVER={info['miver']}; SHALL be 0",
                  packet_number=sci.packet_number,
                  requirement=Requirement.SCI_MIVER)
        # SHALL: Reserved byte (byte 1 of DATA) SHALL be 0
        raw_data = sci.msg.data
        if len(raw_data) >= 2 and raw_data[1] != 0:
            s.add(Severity.ERROR, "9.1",
                  f"SenderConnectionInfo Reserved byte=0x{raw_data[1]:02X}; SHALL be 0",
                  packet_number=sci.packet_number,
                  requirement=Requirement.SCI_RESERVED)
        # CID match
        if expected_cid is not None:
            actual_cid = bytes.fromhex(info.get('cid', ''))
            if actual_cid != expected_cid:
                s.add(Severity.ERROR, "9.1",
                      f"SenderConnectionInfo CID={info.get('cid')} does not match "
                      f"expected {expected_cid.hex().upper()}",
                      packet_number=sci.packet_number,
                      requirement=Requirement.SCI_CID)
        # SN match
        if expected_sn is not None:
            actual_sn = info.get('sn', '')
            if actual_sn != expected_sn:
                s.add(Severity.ERROR, "9.1",
                      f"SenderConnectionInfo SN='{actual_sn}' does not match "
                      f"expected '{expected_sn}'",
                      packet_number=sci.packet_number,
                      requirement=Requirement.SCI_SN)

    # Messages TR-10-14 requires but sets no time for, still not sent: reported at the end, once
    # the clauses that end a connection (§9.12, §11) are known.
    outstanding: list[tuple[float, str, Requirement, int]] = []

    # ------------------------------------------------------------------ 8.3.1.1
    # SHALL: on reception of SenderConnectionInfo Receiver SHALL send SenderConnectionStatus
    scs = next((m for m in receiver_msgs
                if m.msg.msg_type_enum == MsgType.SENDER_CONNECTION_STATUS), None)
    if sci and not scs:
        outstanding.append((sci.timestamp,
                            "Control channel: SenderConnectionInfo has no SenderConnectionStatus "
                            "from the Receiver",
                            Requirement.CTRL_STATUS_RESPONSE, sci.packet_number))

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
                  packet_number=scs.packet_number,
                  requirement=Requirement.SCS_VERSION)
        # SHALL: HBEAT in [5, 30]
        hbeat = sts.get('hbeat', -1)
        if not (5 <= hbeat <= 30):
            s.add(Severity.ERROR, "9.2",
                  f"HBEAT={hbeat} out of valid range [5, 30]",
                  packet_number=scs.packet_number,
                  requirement=Requirement.SCS_HBEAT_RANGE)
        # SHALL: Rsvd 3 bits in byte 1 of SenderConnectionStatus DATA SHALL be 0
        raw_scs_data = scs.msg.data
        if len(raw_scs_data) >= 2:
            rsvd3 = (raw_scs_data[1] >> 5) & 0x07   # bits 7:5 of byte 1
            if rsvd3 != 0:
                s.add(Severity.ERROR, "9.2",
                      f"SenderConnectionStatus Rsvd bits=0x{rsvd3:X}; SHALL be 0",
                      packet_number=scs.packet_number,
                      requirement=Requirement.SCS_RSVD)
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
                  packet_number=cm.packet_number,
                  requirement=Requirement.VSI_VMTYPE_RESERVED)
        # SHALL: VMTYPE=0 VMDATA SHALL be ≤ 256 bytes
        if vmtype == 0:
            vmdata = p.get('vmdata_str', '') or p.get('vmdata', '')
            vmdata_len = len(vmdata.encode('utf-8')) if isinstance(vmdata, str) else len(vmdata)
            if vmdata_len > 256:
                s.add(Severity.ERROR, "9.4",
                      f"VendorSpecificInfo VMTYPE=0 VMDATA={vmdata_len} bytes; SHALL be ≤ 256",
                      packet_number=cm.packet_number,
                      requirement=Requirement.VSI_VMDATA_LENGTH)

    # ------------------------------------------------------------------ §9.6 — VendorSpecificQuery/Return
    # A Return answers the oldest unanswered Query of its VQTYPE (Table 6 carries the Query's
    # VQTYPE) and is checked against that Query. A Return with no Query of its VQTYPE outstanding
    # answers none; no requirement is found against it. Skip payload checks for encrypted messages.
    queries = [m for m in sender_msgs
               if m.msg.msg_type_enum == MsgType.VENDOR_SPECIFIC_QUERY
               and not m.msg.payload.get('_encrypted')]
    returns = [m for m in receiver_msgs
               if m.msg.msg_type_enum == MsgType.VENDOR_SPECIFIC_QUERY_RETURN
               and not m.msg.payload.get('_encrypted')]
    unanswered_queries: dict[int, list[ChannelMessage]] = {}   # VQTYPE -> Queries, oldest first
    answered_queries: list[tuple[ChannelMessage, ChannelMessage]] = []
    for cm in sorted(queries + returns, key=lambda m: (m.packet_number, m.timestamp)):
        vqtype = cm.msg.payload.get('vqtype', -1)
        if cm.msg.msg_type_enum == MsgType.VENDOR_SPECIFIC_QUERY:
            unanswered_queries.setdefault(vqtype, []).append(cm)
        elif unanswered_queries.get(vqtype):
            answered_queries.append((unanswered_queries[vqtype].pop(0), cm))
    for q in sorted((q for qs in unanswered_queries.values() for q in qs),
                    key=lambda m: m.packet_number):
        outstanding.append((q.timestamp,
                            f"VendorSpecificQuery VQTYPE=0x{q.msg.payload.get('vqtype', -1):02X} "
                            f"(CID {q.msg.payload.get('cid', '')}) has no "
                            f"VendorSpecificQueryReturn from the Receiver",
                            Requirement.VSQ_ANSWERED, q.packet_number))

    for q, ret in answered_queries:
        vqtype = q.msg.payload.get('vqtype', -1)
        q_cid = q.msg.payload.get('cid', '')
        vqsts = ret.msg.payload.get('vqsts', -1)
        # SHALL: VQSTS=255 for reserved VQTYPE (1–15)
        if 1 <= vqtype <= 15:
            if vqsts != 255:
                s.add(Severity.ERROR, "9.6",
                      f"VendorSpecificQueryReturn for reserved VQTYPE={vqtype}: "
                      f"VQSTS={vqsts}; SHALL be 255",
                      packet_number=ret.packet_number,
                      requirement=Requirement.VSQ_VQSTS_RESERVED)
        # SHALL: VQTYPE=0 VQDATA SHALL be ≤ 256 bytes
        if vqtype == 0 and vqsts == 0:
            vqdata = ret.msg.payload.get('vqdata_str', '')
            vqdata_len = len(vqdata.encode('utf-8')) if isinstance(vqdata, str) else 0
            if vqdata_len > 256:
                s.add(Severity.ERROR, "9.6",
                      f"VendorSpecificQueryReturn VQTYPE=0 VQDATA={vqdata_len} bytes; "
                      "SHALL be ≤ 256",
                      packet_number=ret.packet_number,
                      requirement=Requirement.VSQR_VQDATA_LENGTH)
        # SHALL: CID in QueryReturn SHALL match Query CID for VQTYPE 16-255
        if vqtype >= 16:
            ret_cid = ret.msg.payload.get('cid', '')
            if ret_cid != q_cid:
                s.add(Severity.ERROR, "9.6",
                      f"VendorSpecificQueryReturn CID={ret_cid} does not match "
                      f"Query CID={q_cid} for VQTYPE={vqtype}",
                      packet_number=ret.packet_number,
                      requirement=Requirement.VSQR_CID)

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
        ctrl.sleep_with_wol_at = enter_sleep_msgs[-1].timestamp
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
                  packet_number=after_sleep[0].packet_number,
                  requirement=Requirement.SLEEP_CLOSE)

    # ------------------------------------------------------------------ §9.3 — Heartbeat DATA
    hbeat_msgs = [m for m in sender_msgs if m.msg.msg_type_enum == MsgType.HEARTBEAT]
    for cm in hbeat_msgs:
        if len(cm.msg.data) != 0:
            s.add(Severity.ERROR, "9.3",
                  f"Heartbeat DATA is {len(cm.msg.data)} bytes; SHALL be empty (0 bytes)",
                  packet_number=cm.packet_number,
                  requirement=Requirement.HEARTBEAT_EMPTY)

    # ------------------------------------------------------------------ §9.11 — USBWakeupControl
    for cm in wol_ctrl_msgs:
        wakectrl = cm.msg.payload.get('wakectrl', -1)
        if wakectrl not in (0, 1):
            s.add(Severity.ERROR, "9.11",
                  f"USBWakeupControl WAKECTRL={wakectrl}; SHALL be 0 or 1",
                  packet_number=cm.packet_number,
                  requirement=Requirement.WAKECTRL_VALUE)

    # ------------------------------------------------------------------ §11 — Heartbeat timing
    ctrl.heartbeat_times = [m.timestamp for m in hbeat_msgs]

    if ctrl.receiver_status:
        hbeat_idx = ctrl.receiver_status.get('hbeat', 10)
        if 5 <= hbeat_idx <= 30:
            period = _heartbeat_period(hbeat_idx)
            ctrl.heartbeat_period = period
            deadline = period * 2.0
            if hbeat_msgs:
                for i in range(1, len(hbeat_msgs)):
                    gap = hbeat_msgs[i].timestamp - hbeat_msgs[i - 1].timestamp
                    if gap > deadline:
                        s.add(Severity.ERROR, "11",
                              f"Heartbeat gap {gap:.2f}s exceeds 2× period "
                              f"({deadline:.2f}s); Sender is considered unresponsive",
                              packet_number=hbeat_msgs[i].packet_number,
                              requirement=Requirement.HEARTBEAT_GAP_MAX)

    # ------------------------------------------------------------------ §12 — Encryption
    if not encrypted:
        for cm in all_msgs:
            m = cm.msg
            if m.ctr != 0:
                s.add(Severity.ERROR, "12",
                      f"{m.msg_type_name}: CTR=0x{m.ctr:016X} SHALL be 0 when encryption disabled",
                      packet_number=cm.packet_number,
                      requirement=Requirement.CLEAR_CTR_ZERO)
            if m.key_version != 0:
                s.add(Severity.ERROR, "12",
                      f"{m.msg_type_name}: KEYVERSION=0x{m.key_version:08X} SHALL be 0 when encryption disabled",
                      packet_number=cm.packet_number,
                      requirement=Requirement.CLEAR_KEYVERSION_ZERO)
            if m.mac != b'\x00' * 8:
                s.add(Severity.ERROR, "12",
                      f"{m.msg_type_name}: MAC SHALL be 0 when encryption disabled",
                      packet_number=cm.packet_number,
                      requirement=Requirement.CLEAR_MAC_ZERO)
    else:
        # ---------------------------------------------------------------- §12 — CTR monotonicity
        _check_ctr_monotonic(s, sender_msgs, "Sender->Receiver (control)")
        _check_ctr_monotonic(s, receiver_msgs, "Receiver->Sender (control)")
        # ---------------------------------------------------------------- §12 — KEYVERSION consistency
        _check_keyversion_consistency(s, sender_msgs, receiver_msgs, "control")

    # ------------------------------------------------------------------ §8.3.1.1, §9.6
    for since, what, requirement, packet_number in outstanding:
        _report_outstanding(s, ctrl.connection, ctrl.sender_endpoint, False, since, what,
                            requirement, packet_number)


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
                      packet_number=cm.packet_number,
                      requirement=Requirement.KEYVERSION_NONZERO_CONSISTENT)
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
                  f"({vals}) in a single TCP session; SHALL be consistent",
                  requirement=Requirement.KEYVERSION_NONZERO_CONSISTENT)


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
                requirement=Requirement.CTR_MONOTONIC,
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

    # ------------------------------------------------------------------ §9.1-9.23 — Sending side
    _check_message_direction(s, sender_msgs, receiver_msgs,
                             f"Data channel (substreamid={channel.substreamid})")

    # ------------------------------------------------------------------ §9 SHOULD — Encryption
    if not encrypted:
        s.add(Severity.WARNING, "9",
              f"Data channel (substreamid={channel.substreamid}): stream is not encrypted; "
              "messages SHOULD be encrypted and authenticated (TR-10-13)",
              requirement=Requirement.ENCRYPTED)

    # ------------------------------------------------------------------ §12 MAC verification
    if decrypted:
        for cm in all_msgs:
            if cm.mac_ok is False:
                s.add(Severity.ERROR, "12",
                      f"Data channel {cm.msg.msg_type_name}: CMAC-64 verification failed",
                      packet_number=cm.packet_number,
                      requirement=Requirement.CMAC_VERIFIES)

    # ------------------------------------------------------------------ §8.3.1.2
    # SHALL: Sender sends USBStreamInformation as first message
    if not sender_msgs:
        lc = channel.connection
        since = lc.opened_at if lc is not None else None
        if since is None:
            since = min((m.timestamp for m in receiver_msgs), default=None)
        if since is not None:
            _report_outstanding(s, lc, channel.sender_endpoint, True, since,
                                f"Data channel (substreamid={channel.substreamid}): the Sender "
                                f"sent no message (its first SHALL be USBStreamInformation)",
                                Requirement.DATA_FIRST_IS_STREAM_INFO,
                                lc.syn.packet_number if lc is not None and lc.syn else None)
        return

    first_sender = sender_msgs[0]
    if first_sender.msg.msg_type_enum != MsgType.USB_STREAM_INFO:
        s.add(Severity.ERROR, "8.3.1.2",
              f"Data channel first Sender message is {first_sender.msg.msg_type_name}; "
              "expected USBStreamInformation",
              packet_number=first_sender.packet_number,
              requirement=Requirement.DATA_FIRST_IS_STREAM_INFO)

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
                  packet_number=si.packet_number,
                  requirement=Requirement.SSI_SUBSTREAMID_BIT0)
        # SHALL: bits 7:1 SHALL be in [1, 127] for data channels
        channel_id = (substreamid >> 1) & 0x7F
        if channel_id == 0:
            s.add(Severity.ERROR, "9.7",
                  f"USBStreamInfo SUBSTREAMID=0x{substreamid:02X}: channel bits 7:1 = 0 "
                  "is reserved for the Control channel; SHALL be 1-127 on data channels",
                  packet_number=si.packet_number,
                  requirement=Requirement.SSI_SUBSTREAMID_CHANNEL)

    # ------------------------------------------------------------------ §8.3.1.2
    # SHALL: Receiver sends USBStreamStatus on reception of USBStreamInformation
    uss = next((m for m in receiver_msgs
                if m.msg.msg_type_enum == MsgType.USB_STREAM_STATUS), None)
    if not uss:
        _report_outstanding(s, channel.connection, channel.sender_endpoint, True,
                            first_sender.timestamp,
                            f"Data channel (substreamid={channel.substreamid}): "
                            f"USBStreamInformation has no USBStreamStatus from the Receiver",
                            Requirement.DATA_STATUS_RESPONSE, first_sender.packet_number)
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
                  packet_number=uss.packet_number,
                  requirement=Requirement.USS_CSTATUS)

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
                  packet_number=em.packet_number,
                  requirement=Requirement.DATA_NO_SUBMIT_BEFORE_STATUS)

    if not encrypted or decrypted:
        # -------------------------------------------------------------- 9.14–9.16
        # SEQNUM tracking: two passes.
        # Pass 1: the Submits' SEQNUM sequence, in the order the Receiver sent them.
        # Pass 2: each Submit Return against the Submit it answers, in capture order.
        # Skipped entirely when encrypted (payload is opaque ciphertext).

        submit_return_map = {
            MsgType.USB_CONTROL_SUBMIT:            MsgType.USB_CONTROL_SUBMIT_RETURN,
            MsgType.USB_BULK_SUBMIT:               MsgType.USB_BULK_SUBMIT_RETURN,
            MsgType.USB_INTERRUPT_SUBMIT:          MsgType.USB_INTERRUPT_SUBMIT_RETURN,
            MsgType.USB_ISOCHRONOUS_SUBMIT:        MsgType.USB_ISOCHRONOUS_SUBMIT_RETURN,
            MsgType.USB_CANCEL_SUBMIT:             MsgType.USB_CANCEL_SUBMIT_RETURN,
        }

        # Pass 1: the SEQNUM sequence of the Submits.
        # Cancel Submit is excluded from SEQNUM sequence checking because its
        # SEQNUM references an already-issued transfer (not a new one).
        # Tables 10-12: the first Submit on a data channel is 0, then each one is "incremented by
        # one from the SEQNUM value of the previous Submit message sent on this data channel". A USB
        # Stream Reset (§9.9) resets the USB port and opens no data channel, so the sequence goes on.
        stream_resets = [m for m in all_msgs
                         if m.msg.msg_type_enum in (MsgType.USB_STREAM_RESET,
                                                    MsgType.USB_STREAM_RESET_RETURN)]
        expected_seqnum = 0
        seqnum_error_reported = False
        previous_submit_pkt = -1
        for cm in receiver_msgs:
            mt = cm.msg.msg_type_enum
            p = cm.msg.payload
            if not p or mt not in submit_return_map:
                continue
            seqnum = p.get('seqnum', -1)
            if mt != MsgType.USB_CANCEL_SUBMIT:
                if not seqnum_error_reported:
                    if seqnum != expected_seqnum:
                        reset = next((m for m in stream_resets
                                      if previous_submit_pkt < m.packet_number < cm.packet_number),
                                     None)
                        after_reset = (
                            f", after the {reset.msg.msg_type_name} of packet "
                            f"#{reset.packet_number}. A USB Stream Reset opens no new data channel: "
                            f"SEQNUM goes on from the previous Submit sent on this data channel "
                            f"(Tables 10-12)") if reset else ""
                        s.add(Severity.ERROR, "9.14",
                              f"Data channel (substreamid={channel.substreamid}): "
                              f"{mt.name} SEQNUM={seqnum}; expected {expected_seqnum}{after_reset}",
                              packet_number=cm.packet_number,
                              requirement=Requirement.SUBMIT_SEQNUM)
                        seqnum_error_reported = True
                expected_seqnum = seqnum + 1
                previous_submit_pkt = cm.packet_number
            # §9.14 / §9.22: Rsvd 3 bits in endpoint byte SHALL be 0
            _check_endpoint_rsvd_bits(s, cm, "submit")

        # Pass 2: each Submit Return, in capture order, answers the earliest still-unanswered
        # Submit of its own type (§9.19-9.20: a Return is sent "in response to" a Submit of that
        # type; §9.23 for Cancel) and SEQNUM (Table 14) sent before it on this channel - once.
        # A Return of a Submit made on another connection, or one arriving before its Submit,
        # answers none. Where capture order cannot tell (same packet and timestamp), a Submit is
        # taken as sent first, so an unknown order never makes a Return unmatched.
        return_types = set(submit_return_map.values())
        receiver_ids = {id(cm) for cm in receiver_msgs}
        outstanding: dict[tuple, list[dict]] = {}    # (Return type, SEQNUM) -> Submits, oldest first
        for cm in sorted(all_msgs, key=lambda m: (m.packet_number, m.timestamp,
                                                   0 if id(m) in receiver_ids else 1)):
            mt = cm.msg.msg_type_enum
            p = cm.msg.payload
            if not p:
                continue
            seqnum = p.get('seqnum', -1)
            if id(cm) in receiver_ids:
                if mt in submit_return_map:
                    outstanding.setdefault((submit_return_map[mt], seqnum), []).append({
                        'msg_type': mt,
                        'endpoint': p.get('endpoint'),
                        'direction': p.get('direction'),
                        'transferlength': p.get('transferlength') or 0,
                        'packet_number': cm.packet_number,
                        'timestamp': cm.timestamp,
                    })
                continue
            if mt not in return_types:
                continue
            # §9.18/§9.23: Rsvd 3 bits in endpoint byte SHALL be 0
            _check_endpoint_rsvd_bits(s, cm, "return")
            waiting = outstanding.get((mt, seqnum))
            if not waiting:
                if mt != MsgType.USB_CANCEL_SUBMIT_RETURN:
                    s.add(Severity.ERROR, "9.18",
                          f"Data channel: {mt.name} SEQNUM={seqnum} has no matching Submit",
                          packet_number=cm.packet_number,
                          requirement=Requirement.RETURN_SEQNUM)
                continue

            sub = waiting.pop(0)

            # SHALL: Return ENDPOINT matches Submit ENDPOINT
            if p.get('endpoint') != sub.get('endpoint'):
                s.add(Severity.ERROR, "9.18",
                      f"Data channel: {mt.name} SEQNUM={seqnum} ENDPOINT={p.get('endpoint')} "
                      f"does not match Submit ENDPOINT={sub.get('endpoint')}",
                      packet_number=cm.packet_number,
                      requirement=Requirement.RETURN_ENDPOINT)

            # SHALL: Return D matches Submit D
            if p.get('direction') != sub.get('direction'):
                s.add(Severity.ERROR, "9.18",
                      f"Data channel: {mt.name} SEQNUM={seqnum} D={p.get('direction')} "
                      f"does not match Submit D={sub.get('direction')}",
                      packet_number=cm.packet_number,
                      requirement=Requirement.RETURN_DIRECTION)

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
                          packet_number=cm.packet_number,
                          requirement=Requirement.RETURN_OUT_LENGTH)

                # SHALL: ACTUALLENGTH ≤ TRANSFERLENGTH when D = 1 (IN)
                if direction == 1 and actual > sub.get('transferlength', 0):
                    s.add(Severity.ERROR, "9.18",
                          f"Data channel: {mt.name} SEQNUM={seqnum} "
                          f"ACTUALLENGTH={actual} exceeds "
                          f"TRANSFERLENGTH={sub.get('transferlength')}",
                          packet_number=cm.packet_number,
                          requirement=Requirement.RETURN_IN_LENGTH)

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
                              packet_number=cm.packet_number,
                              requirement=Requirement.STATUS_DEFINED)
            else:
                rstatus = p.get('rstatus', -1)
                if rstatus not in _VALID_STATUS_CODES:
                    s.add(Severity.ERROR, "A.1",
                          f"Data channel: {mt.name} SEQNUM={seqnum} "
                          f"RSTATUS=0x{rstatus:08X} "
                          "is not a defined status code; SHALL use UNKNOWN_ERROR",
                          packet_number=cm.packet_number,
                          requirement=Requirement.STATUS_DEFINED)

        # -------------------------------------------------------------- §9.18, §9.19, §9.23
        # SHALL: "USB Control Submit Return message shall be sent by a Sender in response to
        # a USB Control Submit message" (§9.19 the same for Bulk, §9.23 for Cancel), at no set
        # time: a Submit still unanswered is reported with how long it waited (_report_outstanding).
        # Interrupt and Isochronous Submits are not: an interrupt IN Submit legitimately stays
        # pending until the device has data, so every capture ends with some.
        cancels = [m for m in receiver_msgs if m.msg.msg_type_enum == MsgType.USB_CANCEL_SUBMIT]
        unanswered = sorted(((seq, sub) for (_rt, seq), subs in outstanding.items() for sub in subs),
                            key=lambda e: e[1]['packet_number'])
        for seqnum, sub in unanswered:
            if sub['msg_type'] not in (MsgType.USB_CONTROL_SUBMIT, MsgType.USB_BULK_SUBMIT,
                                       MsgType.USB_CANCEL_SUBMIT):
                continue
            cancel = (next((m for m in cancels if m.msg.payload.get('seqnum') == seqnum
                            and m.packet_number > sub['packet_number']), None)
                      if sub['msg_type'] != MsgType.USB_CANCEL_SUBMIT else None)
            cancelled = (f" (cancelled by the USB_CANCEL_SUBMIT of pkt #{cancel.packet_number}; "
                         f"TR-10-14 does not say whether a cancelled Submit gets its own Return)"
                         if cancel else "")
            _report_outstanding(s, channel.connection, channel.sender_endpoint, True,
                                sub['timestamp'],
                                f"Data channel (substreamid=0x{channel.substreamid:02X}): "
                                f"{sub['msg_type'].name} SEQNUM={seqnum} has no Return from the "
                                f"Sender{cancelled}",
                                Requirement.RETURN_SENT, sub['packet_number'])

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
                      packet_number=cm.packet_number,
                      requirement=Requirement.ISO_ASAP_STARTFRAME)

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
                # §9.10: "USB Stream Reset Return message shall be sent by the Sender", at no
                # set time
                _report_outstanding(s, channel.connection, channel.sender_endpoint, True,
                                    reset.timestamp,
                                    f"Data channel (substreamid={channel.substreamid}): "
                                    f"USBStreamReset has no USBStreamResetReturn from the Sender",
                                    Requirement.RESET_RETURN_SENT, reset.packet_number)
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
                          packet_number=em.packet_number,
                          requirement=Requirement.RESET_WAIT)

        # -------------------------------------------------------------- §9.10
        for cm in reset_returns:
            if len(cm.msg.data) != 0:
                s.add(Severity.ERROR, "9.10",
                      f"USBStreamResetReturn DATA is {len(cm.msg.data)} bytes; "
                      "SHALL be empty (0 bytes)",
                      packet_number=cm.packet_number,
                      requirement=Requirement.RESET_RETURN_EMPTY)

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
                      packet_number=cm.packet_number,
                      requirement=Requirement.CONTROL_USBDEVREQ_LENGTH)

        # -------------------------------------------------------------- §9.14-9.16, §9.18-9.20
        # SHALL: "Fields of the DATA field shall be as described in Table 10 / 11 / 14".
        # DATA is LENGTH - 24 bytes (Table 1) and those tables account for every byte of it:
        # the fixed fields plus TRANFERDATA of M bytes, M = TRANSFERLENGTH (OUT Submit), 0 (IN
        # Submit) or ACTUALLENGTH (Submit Return). Bytes past that, or missing, are a violation;
        # the decoder keeps the spec reading of TRANFERDATA and shows the rest as excess_data.
        # One finding per message type, with the count: a sender that gets this wrong usually
        # does so in every message.
        size_mismatches: dict[MsgType, list[tuple[ChannelMessage, int]]] = {}
        size_checked: dict[MsgType, int] = {}
        for cm in all_msgs:
            mt = cm.msg.msg_type_enum
            if mt is None or cm.msg.payload.get('_encrypted'):
                continue
            expected = usb.defined_data_length(mt, cm.msg.data)
            if expected is None:
                continue
            size_checked[mt] = size_checked.get(mt, 0) + 1
            if len(cm.msg.data) != expected:
                size_mismatches.setdefault(mt, []).append((cm, expected))
        for mt, bad in size_mismatches.items():
            first, expected = bad[0]
            p = first.msg.payload
            is_return = not (mt & 0x01)
            m_field = (f"ACTUALLENGTH={p.get('actuallength')}" if is_return
                       else f"TRANSFERLENGTH={p.get('transferlength')}, D={p.get('direction')}")
            table = "14" if is_return else ("10" if mt == MsgType.USB_CONTROL_SUBMIT else "11")
            s.add(Severity.ERROR, "9.18-20" if is_return else "9.14-16",
                  f"Data channel (substreamid=0x{channel.substreamid:02X}): {mt.name} DATA is "
                  f"{len(first.msg.data)} bytes but its Table {table} fields total {expected} "
                  f"({m_field}), in {len(bad)} of {size_checked[mt]} messages "
                  f"(first SEQNUM={p.get('seqnum')}); fields of the DATA field SHALL be as "
                  f"described in Table {table}",
                  packet_number=first.packet_number,
                  requirement=Requirement.RETURN_DATA_FIELDS if is_return else Requirement.SUBMIT_DATA_FIELDS)

        # -------------------------------------------------------------- §10
        for cm in sender_msgs:
            ssid = cm.msg.payload.get('substreamid')
            if ssid is not None and ssid & 1 != 0:
                s.add(Severity.ERROR, "10",
                      f"S2R message {cm.msg.msg_type_name} substreamid=0x{ssid:02X} "
                      "is odd; SHALL be even for Sender-to-Receiver",
                      packet_number=cm.packet_number,
                      requirement=Requirement.SUBSTREAM_PARITY)
        for cm in receiver_msgs:
            ssid = cm.msg.payload.get('substreamid')
            if ssid is not None and ssid & 1 == 0:
                s.add(Severity.ERROR, "10",
                      f"R2S message {cm.msg.msg_type_name} substreamid=0x{ssid:02X} "
                      "is even; SHALL be odd for Receiver-to-Sender",
                      packet_number=cm.packet_number,
                      requirement=Requirement.SUBSTREAM_PARITY)

    # ------------------------------------------------------------------ §12
    if not encrypted:
        for cm in all_msgs:
            m = cm.msg
            if m.ctr != 0:
                s.add(Severity.ERROR, "12",
                      f"Data channel {m.msg_type_name}: CTR=0x{m.ctr:016X} SHALL be 0 when encryption disabled",
                      packet_number=cm.packet_number,
                      requirement=Requirement.CLEAR_CTR_ZERO)
            if m.key_version != 0:
                s.add(Severity.ERROR, "12",
                      f"Data channel {m.msg_type_name}: KEYVERSION=0x{m.key_version:08X} SHALL be 0 when encryption disabled",
                      packet_number=cm.packet_number,
                      requirement=Requirement.CLEAR_KEYVERSION_ZERO)
            if m.mac != b'\x00' * 8:
                s.add(Severity.ERROR, "12",
                      f"Data channel {m.msg_type_name}: MAC SHALL be 0x0000000000000000 when encryption disabled",
                      packet_number=cm.packet_number,
                      requirement=Requirement.CLEAR_MAC_ZERO)
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
# USB 2.0 diagnostics (--diagnose)
# ---------------------------------------------------------------------------

class DeviceState(str, Enum):
    """A data channel's device state as the connection's own traffic establishes it (USB 2.0 §9.1.1)."""
    UNKNOWN    = "unknown"      # nothing on the connection has set it: the device behind the
                                # Sender may already be addressed and configured by its own host
    DEFAULT    = "default"      # after a USB Stream Reset and its Return (TR-10-14 §9.9 → USB 2.0 reset)
    ADDRESS    = "address"
    CONFIGURED = "configured"


#: Data transfers that use a device's function rather than its default control pipe.
_FUNCTION_SUBMITS = {MsgType.USB_INTERRUPT_SUBMIT, MsgType.USB_BULK_SUBMIT,
                     MsgType.USB_ISOCHRONOUS_SUBMIT}


def _diagnose_data_channel(
    session: Session,
    channel: DataChannel,
    sender_msgs: list[ChannelMessage],
    receiver_msgs: list[ChannelMessage],
) -> None:
    """
    Check one data-channel connection against the core USB 2.0 rules of Diagnostic and
    add a DIAG finding per rule breached, with its occurrences and first packet.

    The Receiver side plays the USB host and the Sender side the device. Requests are
    judged in packet order against the device state the connection has established so
    far; a Submit Return applies its request's effect (SET_CONFIGURATION, SET_ADDRESS,
    the descriptors learnt) where it arrives. A connection whose payloads cannot be
    read (encrypted without a key) is not diagnosed.
    """
    # A message from the side TR-10-14 does not assign it to is reported by the validators
    # (MESSAGE_DIRECTION) and has no effect on the device state here.
    rows = sorted([(cm.packet_number, 0, cm) for cm in receiver_msgs
                   if not sent_by_other_side(cm.msg.msg_type_enum, ChannelRole.RECEIVER)]
                  + [(cm.packet_number, 1, cm) for cm in sender_msgs
                     if not sent_by_other_side(cm.msg.msg_type_enum, ChannelRole.SENDER)],
                  key=lambda r: (r[0], r[1]))
    if any(cm.msg.payload.get('_encrypted') for _p, _o, cm in rows):
        return
    # The rules weigh a request against what came before it on the connection, so a
    # connection is judged only when the capture holds its start (USB Stream Information).
    first = min(sender_msgs, key=lambda cm: cm.packet_number, default=None)
    if first is None or first.msg.msg_type_enum != MsgType.USB_STREAM_INFO:
        return

    state = DeviceState.UNKNOWN
    configured = False                 # a SET_CONFIGURATION(non-zero) succeeded on the connection
    config_values: set[int] = set()    # bConfigurationValue of each configuration descriptor returned
    num_configurations: Optional[int] = None
    bcd_usb: Optional[int] = None
    langids: Optional[set[int]] = None  # None until string descriptor 0 was answered
    qualifier_ok = False
    pending: dict[int, tuple] = {}     # SEQNUM -> (bmRequestType, bRequest, wValue, wIndex, wLength)
    breaches: dict[Diagnostic, list] = {}

    def breach(rule: Diagnostic, cm: ChannelMessage, what: str) -> None:
        breaches.setdefault(rule, []).append((cm.packet_number, what))

    def returned_bytes(cm: ChannelMessage) -> bytes:
        # The bytes the Sender returned. ACTUALLENGTH is checked by the validators; using
        # what is present keeps a wrong ACTUALLENGTH from hiding the descriptor here.
        p = cm.msg.payload
        if p.get('transferdata'):
            return bytes.fromhex(p['transferdata'])
        return bytes(cm.msg.data[12:])

    for _pkt, _order, cm in rows:
        mt = cm.msg.msg_type_enum
        p = cm.msg.payload

        if mt == MsgType.USB_STREAM_RESET_RETURN:
            state, configured = DeviceState.DEFAULT, False
            continue
        if mt in _FUNCTION_SUBMITS:
            if not configured:
                breach(Diagnostic.CONFIGURE_BEFORE_USE, cm,
                       f"{mt.name} on endpoint {p.get('endpoint')} with no successful "
                       "SET_CONFIGURATION before it on this connection")
            continue

        if mt == MsgType.USB_CONTROL_SUBMIT and p.get('usbdevreq'):
            req = bytes.fromhex(p['usbdevreq'])
            if len(req) < 8:
                continue
            bm, breq = req[0], req[1]
            wvalue, windex, wlength = struct.unpack_from('<HHH', req, 2)
            pending[p.get('seqnum')] = (bm, breq, wvalue, windex, wlength)
            if (bm >> 5) & 0x03 != usb_decode.RequestType.STANDARD:
                continue
            recipient = bm & 0x1F
            std = usb_decode.UsbStandardRequest

            if breq == std.SET_CONFIGURATION and bm == 0x00:
                value = wvalue & 0xFF
                if wvalue >> 8 or windex or wlength:
                    breach(Diagnostic.CONFIGURATION_FIELDS, cm,
                           f"wValue=0x{wvalue:04X} wIndex=0x{windex:04X} wLength={wlength}")
                if value and value not in config_values:
                    known = (f"descriptors returned value(s) {sorted(config_values)}" if config_values
                             else "no configuration descriptor was returned on this connection")
                    breach(Diagnostic.CONFIGURATION_VALUE, cm, f"value {value}; {known}")
            elif breq == std.SET_ADDRESS and bm == 0x00:
                if state == DeviceState.CONFIGURED:
                    breach(Diagnostic.ADDRESS_WHEN_CONFIGURED, cm,
                           f"SET_ADDRESS({wvalue & 0x7F}) after SET_CONFIGURATION")

            if state in (DeviceState.DEFAULT, DeviceState.ADDRESS):
                configured_only = (
                    (breq == std.GET_INTERFACE and bm == 0x81)
                    or (breq == std.SET_INTERFACE and bm == 0x01)
                    or (breq == std.SYNCH_FRAME and bm == 0x82)
                    or (breq in (std.CLEAR_FEATURE, std.SET_FEATURE, std.GET_STATUS)
                        and (recipient == usb_decode.Recipient.INTERFACE
                             or (recipient == usb_decode.Recipient.ENDPOINT and windex & 0x0F))))
                if configured_only:
                    name = std(breq).name if breq in std._value2member_map_ else f"bRequest 0x{breq:02X}"
                    breach(Diagnostic.CONFIGURED_ONLY, cm,
                           f"{name} (bmRequestType 0x{bm:02X}) in the {state.value} state")

            if breq == std.GET_DESCRIPTOR and bm == 0x80:
                dtype, index = wvalue >> 8, wvalue & 0xFF
                dt = usb_decode.DescriptorType
                if dtype == dt.OTHER_SPEED_CONFIG and not qualifier_ok:
                    breach(Diagnostic.OTHER_SPEED_ORDER, cm,
                           "other_speed_configuration with no successful device_qualifier before it")
                if dtype in (dt.DEVICE_QUALIFIER, dt.OTHER_SPEED_CONFIG) and bcd_usb is not None \
                        and bcd_usb < 0x0200:
                    breach(Diagnostic.OTHER_SPEED_USB1, cm,
                           f"descriptor type 0x{dtype:02X} to a device with bcdUSB 0x{bcd_usb:04X}")
                if dtype == dt.STRING:
                    if index and langids is None:
                        breach(Diagnostic.STRING_LANGID, cm,
                               f"string {index} with LANGID 0x{windex:04X}; string descriptor 0 "
                               "was not read before it on this connection")
                    elif index and windex not in langids:
                        listed = (", ".join(f"0x{l:04X}" for l in sorted(langids)) if langids
                                  else "none (the device returned no LANGID array)")
                        breach(Diagnostic.STRING_LANGID, cm,
                               f"string {index} with LANGID 0x{windex:04X}; listed: {listed}")
                else:
                    if windex:
                        breach(Diagnostic.DESCRIPTOR_WINDEX, cm,
                               f"descriptor type 0x{dtype:02X} with wIndex 0x{windex:04X}")
                    if dtype == dt.CONFIGURATION:
                        if num_configurations is not None and index >= num_configurations:
                            breach(Diagnostic.DESCRIPTOR_INDEX, cm,
                                   f"configuration index {index} with bNumConfigurations "
                                   f"{num_configurations}")
                    elif index:
                        breach(Diagnostic.DESCRIPTOR_INDEX, cm,
                               f"descriptor type 0x{dtype:02X} with index {index}")
            continue

        if mt == MsgType.USB_CONTROL_SUBMIT_RETURN:
            req = pending.pop(p.get('seqnum'), None)
            if req is None:
                continue
            bm, breq, wvalue, windex, wlength = req
            ok = p.get('rstatus') == StatusCode.SUCCESS
            std = usb_decode.UsbStandardRequest
            if bm == 0x80 and breq == std.GET_DESCRIPTOR:
                dtype, index = wvalue >> 8, wvalue & 0xFF
                dt = usb_decode.DescriptorType
                data = returned_bytes(cm) if ok else b''
                if dtype == dt.DEVICE and len(data) >= 4:
                    bcd_usb = struct.unpack_from('<H', data, 2)[0]
                    if len(data) >= 18:
                        num_configurations = data[17]
                elif dtype == dt.CONFIGURATION and len(data) >= 6 and data[1] == dt.CONFIGURATION:
                    config_values.add(data[5])
                elif dtype == dt.STRING and index == 0:
                    # A device without strings must not return a LANGID array (§9.6.7).
                    langids = ({int.from_bytes(data[i:i + 2], 'little')
                                for i in range(2, min(len(data), data[0]) - 1, 2)}
                               if len(data) >= 4 and data[1] == dt.STRING else set())
                elif dtype == dt.DEVICE_QUALIFIER and ok:
                    qualifier_ok = True
            elif ok and bm == 0x00 and breq == std.SET_CONFIGURATION:
                if wvalue & 0xFF:
                    state, configured = DeviceState.CONFIGURED, True
                elif state != DeviceState.UNKNOWN:
                    state, configured = DeviceState.ADDRESS, False
            elif ok and bm == 0x00 and breq == std.SET_ADDRESS:
                if state == DeviceState.DEFAULT and wvalue & 0x7F:
                    state = DeviceState.ADDRESS
                elif state == DeviceState.ADDRESS and not wvalue & 0x7F:
                    state = DeviceState.DEFAULT

    for rule, hits in breaches.items():
        first_pkt, first_what = hits[0]
        session.add(Severity.DIAG, rule.section, rule.text, packet_number=first_pkt,
                    detail=f"{len(hits)} occurrence(s) on this connection; first: {first_what}",
                    requirement=rule)


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
    diagnose: bool = False,
) -> list[Session]:
    """
    Analyze a PCAP file and return a list of :class:`Session` objects,
    each carrying the parsed messages and validation findings.

    When *pep_params* is provided with a PSK, encrypted messages are
    decrypted transparently and field-level validation is applied to
    the decrypted content.

    With *diagnose*, each data channel is also checked against the core USB 2.0
    rules of :class:`Diagnostic`; breaches are DIAG findings, never errors.
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
    lifecycles = _collect_lifecycles(packets)
    capture_end = max((float(p.time) for p in packets if hasattr(p, 'time')), default=None)

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
    # Channels are taken in the order their connections opened, so a SUBSTREAMID's
    # latest connection is the one left in Session.data_channels.
    def _opened_at(key: str, msgs: list[ChannelMessage]) -> float:
        lc = lifecycles.get(key)
        if lc is not None and lc.opened_at is not None:
            return lc.opened_at
        return min((m.timestamp for m in msgs), default=0.0)

    def _in_open_order(ctype_wanted: str) -> list[tuple[str, tuple]]:
        return sorted(((k, v) for k, v in channel_map.items() if v[0] == ctype_wanted),
                      key=lambda kv: _opened_at(kv[0], kv[1][1] + kv[1][2]))

    sessions: list[Session] = []
    session_by_ctrl_key: dict[str, Session] = {}

    # Process control channels first to build sessions.
    for key, (ctype, sender_msgs, receiver_msgs) in _in_open_order('control'):
        src_ip, src_port = key.split('-')[0].rsplit(':', 1)
        sender_ip = sender_msgs[0].src_ip if sender_msgs else src_ip

        sess = Session(
            sender_ip=sender_ip,
            sender_port=sender_port or 0,
            receiver_ip='',
            capture_end=capture_end,
        )
        sess.control.key = key
        sess.control.sender_endpoint = (f"{sender_msgs[0].src_ip}:{sender_msgs[0].src_port}"
                                        if sender_msgs else '')
        sess.control.connection = lifecycles.get(key)
        if mode_warning:
            sess.add(Severity.ERROR, "12", mode_warning,
                     requirement=Requirement.MODE_ALLOWED)
        sessions.append(sess)
        session_by_ctrl_key[key] = sess

        if verbose:
            print(f"\n  Control channel: {key}")

        first_finding = len(sess.findings)
        _validate_control_channel(
            sess, sender_msgs, receiver_msgs,
            sender_cid, sender_sn, encrypted, decrypted,
        )
        for f in sess.findings[first_finding:]:
            f.connection = f.connection or sess.control.label

    # If no control channel found, create a default session.
    if not sessions:
        sessions.append(Session(sender_ip='', sender_port=0, receiver_ip='',
                                capture_end=capture_end))

    default_session = sessions[0]

    # Process data channels.
    for key, (ctype, sender_msgs, receiver_msgs) in _in_open_order('data'):
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
        channel.key = key
        channel.sender_endpoint = (f"{sender_msgs[0].src_ip}:{sender_msgs[0].src_port}"
                                   if sender_msgs else '')
        channel.connection = lifecycles.get(key)

        sess = (_session_for_data_channel(sessions, channel,
                                          _opened_at(key, sender_msgs + receiver_msgs))
                or default_session)
        channel.index = len(sess.data_connections) + 1
        sess.data_connections.append(channel)
        sess.data_channels[substreamid] = channel

        first_finding = len(sess.findings)
        if key in ssid_findings:
            hs_ssid, _pl_ssid, compliant = ssid_findings[key]
            if not compliant:
                sess.add(Severity.WARNING, "9.7",
                         f"Data channel: handshake USB_STREAM_INFO encrypted "
                         f"with SSID=0x{hs_ssid:02X}, expected SSID=0x02 "
                         "(data channels SHOULD use SSID 2/3 for handshake phase)",
                         requirement=Requirement.HANDSHAKE_SSID)

        _validate_data_channel(sess, channel, sender_msgs, receiver_msgs,
                               encrypted, decrypted)
        if diagnose:
            _diagnose_data_channel(sess, channel, sender_msgs, receiver_msgs)
        for f in sess.findings[first_finding:]:
            f.connection = f.connection or channel.label

    if mac_failures:
        for sess in sessions:
            sess.add(Severity.ERROR, "12",
                     f"{mac_failures} encrypted message(s) failed CMAC verification "
                     "— cannot decrypt (wrong PSK or key derivation mismatch)",
                     requirement=Requirement.CMAC_VERIFIES)

    for sess in sessions:
        sess.diagnosed = diagnose

    return sessions


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

#: A checklist row's status by the most severe finding naming it, most severe first.
_ROW_STATUS = ((Severity.ERROR, "[FAIL]"), (Severity.WARNING, "[WARN]"),
               (Severity.DIAG, "[DIAG]"), (Severity.INFO, "[INFO]"))


def _print_requirements(sess: Session) -> None:
    """
    Print a per-requirement pass/fail checklist for *sess*.

    A row's status is the most severe of the findings that name it (Finding.requirement):
    FAIL for an ERROR, WARN for a WARNING, DIAG for a DIAG, INFO for an INFO. A row no
    finding names passes, which only means nothing in the capture contradicted it.
    Findings that name no row are listed after the checklist.
    """
    def _finding_line(f: Finding, lead: str = f"    {'':22}") -> str:
        pkt = f"pkt #{f.packet_number}" if f.packet_number else ""
        return (f"{lead}↳ {f.severity.value}: {_printable(f.description)}"
                + (f"  [{pkt}]" if pkt else ""))

    print("\n  Requirements checklist:")
    print(f"  {'§Section':<10} {'Level':<8} {'Status':<6}  Description")
    print(f"  {'-'*9:<10} {'-'*7:<8} {'-'*5:<6}  {'-'*50}")

    for req in Requirement:
        matching = [f for f in sess.findings if f.requirement is req]
        marker = next((m for sev, m in _ROW_STATUS if any(f.severity is sev for f in matching)),
                      "[PASS]")
        print(f"  §{req.section:<9} {req.level:<8} {marker:<8} {req.text}")
        for f in matching:
            print(_finding_line(f))

    unlisted = [f for f in sess.findings if f.requirement is None]
    if unlisted:
        print("\n  Findings not on the checklist:")
        for f in unlisted:
            print(_finding_line(f, lead=f"  §{f.section:<9} {'':17}"))

    if sess.diagnosed:
        print("\n  USB 2.0 diagnostics (--diagnose; DIAG is never a failure):")
        print(f"  {'§Section':<14} {'Level':<8} {'Status':<6}  Description")
        print(f"  {'-'*13:<14} {'-'*7:<8} {'-'*5:<6}  {'-'*50}")
        for rule in Diagnostic:
            matching = [f for f in sess.findings if f.requirement is rule]
            marker = "[DIAG]" if matching else "[ ok ]"
            print(f"  §{rule.section:<13} {rule.level:<8} {marker:<8} {rule.text}")
            for f in matching:
                print(_finding_line(f, lead=f"    {'':26}") + (f"  [{f.connection}]" if f.connection else ""))


def _printable(text: str) -> str:
    """*text* with non-printable characters escaped (\\x00, \\x1b, ...).

    Strings decoded from the wire (vendor strings, SN, BUSID) may carry NUL padding
    or other control bytes; printed raw they corrupt the console output and make
    tools such as grep treat the whole report as binary.
    """
    return "".join(c if c.isprintable()
                   else f"\\x{ord(c):02x}" if ord(c) < 0x100 else f"\\u{ord(c):04x}"
                   for c in text)


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
            parts.append(f"{k}='{_printable(v)}'")
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


def _short_endpoint(endpoint: str) -> str:
    """'25.30.10.166:5802' -> '166:5802', the form the message listing uses."""
    ip, _, port = endpoint.rpartition(':')
    return f"{ip.split('.')[-1]}:{port}"


def _session_data_connections(sess: Session) -> list[DataChannel]:
    """Every data-channel connection of *sess*; data_channels for a Session built elsewhere."""
    return sess.data_connections or list(sess.data_channels.values())


def _session_t0(sess: Session) -> float:
    """Time zero of a session's listings: its earliest message or SYN."""
    data = _session_data_connections(sess)
    stamps = [cm.timestamp for cm in sess.control.messages]
    stamps += [cm.timestamp for ch in data for cm in ch.messages]
    stamps += [lc.opened_at for lc in [sess.control.connection] + [ch.connection for ch in data]
               if lc is not None and lc.opened_at is not None]
    return min(stamps) if stamps else 0.0


def _lifecycle_text(lc: Optional[TcpLifecycle], sender_endpoint: str, t0: float) -> str:
    """One connection's opening and end, times in seconds from *t0*."""
    if lc is None:
        return "connection not seen"
    opened = (f"opened {lc.opened_at - t0:.3f} s" if lc.syn
              else f"open before the capture started (first segment {lc.first_timestamp - t0:.3f} s)")
    close = lc.close
    if close is None:
        return f"{opened}, still open at end of capture (last segment {lc.last_timestamp - t0:.3f} s)"
    return (f"{opened}, closed {close.timestamp - t0:.3f} s by the "
            f"{_close_role(close, sender_endpoint).value} ({close.kind.value}, pkt #{close.packet_number}), "
            f"lifetime {close.timestamp - lc.opened_at:.3f} s")


def _print_reconnects(data: list[DataChannel]) -> None:
    """One line per USB device whose data channel was opened more than once.

    A device is known by the BUSID of its USBStreamInformation; channels whose
    USBStreamInformation could not be read (encrypted, no key) are not grouped.
    """
    groups: dict[str, list[DataChannel]] = {}
    for ch in data:
        if ch.busid:
            groups.setdefault(f"BusID '{_printable(ch.busid)}'", []).append(ch)

    for name, chs in groups.items():
        if len(chs) < 2:
            continue
        closed = [ch for ch in chs if ch.connection is not None and ch.connection.close is not None]
        closers = collections.Counter(
            f"{_close_role(ch.connection.close, ch.sender_endpoint).value} "
            f"({ch.connection.close.kind.value})" for ch in closed)
        parts = [f"{len(chs)} connections",
                 "closed by " + ", ".join(f"{who} x{n}" for who, n in closers.most_common())
                 if closers else "none closed"]
        still_open = sum(1 for ch in chs if ch.connection is not None and ch.connection.close is None)
        if still_open:
            parts.append(f"{still_open} open at end of capture")
        lifetimes = [ch.connection.close.timestamp - ch.connection.opened_at for ch in closed
                     if ch.connection.opened_at is not None]
        if lifetimes:
            parts.append(f"lifetimes {min(lifetimes):.3f}-{max(lifetimes):.3f} s "
                         f"(median {statistics.median(lifetimes):.3f} s)")
        gaps = [nxt.connection.opened_at - prev.connection.close.timestamp
                for prev, nxt in zip(chs, chs[1:])
                if prev.connection is not None and prev.connection.close is not None
                and nxt.connection is not None and nxt.connection.opened_at is not None]
        reopened = [g for g in gaps if g >= 0]
        if reopened:
            parts.append(f"reopened {min(reopened):.3f}-{max(reopened):.3f} s after the previous close")
        if len(reopened) < len(gaps):
            parts.append(f"{len(gaps) - len(reopened)} opened before the previous one closed")
        print(f"    {name}: " + "; ".join(parts))


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

    # Reference time (t0): earliest message or SYN across the whole session,
    # so the Time(ms) column is comparable across the control and data channels.
    t0 = _session_t0(sess)

    def _dump(label: str, messages: list[ChannelMessage],
              lc: Optional[TcpLifecycle] = None, key: str = '', sender_endpoint: str = '') -> None:
        if not messages:
            print(f"\n  {label}: (no messages)")
            return
        # The connection's SYN, FIN and RST are listed among the messages, in packet order.
        events = ([lc.syn] if lc and lc.syn else []) + (lc.fins if lc else []) + ([lc.rst] if lc and lc.rst else [])
        rows: list[tuple[int, int, float, object]] = [
            (cm.packet_number, 0, cm.timestamp, cm) for cm in messages]
        rows += [(ev.packet_number, -1 if ev.kind == TcpEventKind.SYN else 1, ev.timestamp, ev)
                 for ev in events]
        rows.sort(key=lambda r: (r[0], r[1]))
        print(f"\n  {label}  ({len(messages)} messages)")
        print(f"  {'#Pkt':<6} {'Time(ms)':>11} {'Dir':<30} {'Type':<38} {'Len':>6}  Payload")
        print(f"  {'-'*5:<6} {'-'*11:>11} {'-'*30:<30} {'-'*37:<38} {'-'*6}  {'-'*50}")
        setup_by_seqnum: dict[int, dict] = {}
        hid_endpoints: dict[int, usb_decode.EndpointInfo] = {}
        for pkt, _order, ts, item in rows:
            t_ms = (ts - t0) * 1000.0
            if isinstance(item, TcpEvent):
                peer = next((e for e in key.split('-') if e != item.endpoint), '')
                direction = f"{_short_endpoint(item.endpoint)}->{_short_endpoint(peer)}"
                kind = f"TCP {item.kind.value}"
                if item.kind != TcpEventKind.SYN:
                    kind += f" ({_close_role(item, sender_endpoint).value})"
                print(f"  {pkt:<6} {t_ms:>11.3f} {direction:<30} {kind:<38} {'':>6}")
                continue
            cm = item
            m = cm.msg
            src_short = f"{cm.src_ip.split('.')[-1]}:{cm.src_port}"
            dst_short = f"{cm.dst_ip.split('.')[-1]}:{cm.dst_port}"
            direction = f"{src_short}->{dst_short}"
            payload_str = _format_payload(m.payload)
            print(f"  {cm.packet_number:<6} {t_ms:>11.3f} {direction:<30} {m.msg_type_name:<38} {m.length:>6}{payload_str}")
            if decode_usb:
                for line in _usb_annotations(m, setup_by_seqnum, hid_endpoints):
                    print(f"  {'':6} {'':11} {'':30} {line}")

    ctrl = sess.control
    _dump("Control channel", ctrl.messages, ctrl.connection, ctrl.key, ctrl.sender_endpoint)
    for ch in _session_data_connections(sess):
        speed = (usb.UsbSpeed(ch.usbspeed).name
                 if ch.usbspeed in usb.UsbSpeed._value2member_map_ else str(ch.usbspeed))
        number = f" #{ch.index}" if ch.index else ""
        _dump(
            f"Data channel{number}  SubstreamID=0x{ch.substreamid:02X}  "
            f"BusID='{_printable(ch.busid)}'  Speed={speed}",
            ch.messages, ch.connection, ch.key, ch.sender_endpoint,
        )


def _print_session(sess: Session, verbose: bool, show_messages: bool = False,
                   show_requirements: bool = False, decode_usb: bool = False) -> None:
    print(f"\n{'='*72}")
    print(f"Session: Sender={sess.sender_ip}:{sess.sender_port}")
    if sess.control.sender_info:
        info = sess.control.sender_info
        print(f"  Sender  CID={info.get('cid','?')}  SN='{_printable(str(info.get('sn','?')))}'")
    if sess.control.receiver_status:
        sts = sess.control.receiver_status
        print(f"  Receiver CID={sts.get('cid','?')}  SN='{_printable(str(sts.get('sn','?')))}'  "
              f"HBEAT={sts.get('hbeat','?')}  Port={sts.get('port','?')}")
    data = _session_data_connections(sess)
    t0 = _session_t0(sess)
    ctrl = sess.control
    if ctrl.key:
        print(f"  Control channel: {ctrl.receiver_endpoint} -> {ctrl.sender_endpoint}  "
              f"{_lifecycle_text(ctrl.connection, ctrl.sender_endpoint, t0)}")
    identified = [ch for ch in data if ch.busid]
    unidentified = len(data) - len(identified)
    print(f"  Data channels: {len(data)} connection(s), "
          f"{len({ch.substreamid for ch in identified})} SubstreamID(s)"
          + (f", {unidentified} not identified (USBStreamInformation not readable)"
             if unidentified else "")
          + ("  (times in s from the session's first segment)" if data else ""))
    if data:
        print(f"    {'#':>3} {'Opened':>9} {'Closed':>9} {'Lifetime':>9}  {'Closed by':<15} "
              f"{'Status':<6} {'SSID':<5} {'BusID':<12} {'Speed':<11} {'Msgs':>6}  Sender -> Receiver")
        for ch in data:
            lc = ch.connection
            opened = (lc.opened_at if lc is not None
                      else (ch.messages[0].timestamp if ch.messages else None))
            close = lc.close if lc is not None else None
            # '<': the connection opened before the capture started; the time is its first segment.
            before = '<' if lc is not None and lc.syn is None else ''
            opened_s = f"{before}{opened - t0:.3f}".rjust(9) if opened is not None else f"{'?':>9}"
            closed_s = f"{close.timestamp - t0:9.3f}" if close else f"{'-':>9}"
            life_s = (f"{close.timestamp - opened:9.3f}" if close and opened is not None
                      else f"{'-':>9}")
            if close is not None:
                closed_by = f"{_close_role(close, ch.sender_endpoint).value} ({close.kind.value})"
            else:
                closed_by = "open at end" if lc is not None else "not seen"
            status = ("none" if ch.stream_status_pkt is None
                      else "OK" if ch.stream_status_ok else "error")
            speed = (usb.UsbSpeed(ch.usbspeed).name
                     if ch.usbspeed in usb.UsbSpeed._value2member_map_ else str(ch.usbspeed))
            busid = f"'{_printable(ch.busid)}'"
            print(f"    {ch.index:>3} {opened_s} {closed_s} {life_s}  {closed_by:<15} {status:<6} "
                  f"0x{ch.substreamid:02X}  {busid:<12} {speed:<11} {len(ch.messages):>6}  "
                  f"{ch.sender_endpoint} -> {ch.receiver_endpoint}")
        if any(ch.connection is not None and ch.connection.syn is None for ch in data):
            print("    < opened before the capture started (time of its first segment)")
        _print_reconnects(data)

    ctrl_msgs = len(sess.control.messages)
    data_msgs = sum(len(ch.messages) for ch in data)
    print(f"  Control messages: {ctrl_msgs}  Data messages (total): {data_msgs}")

    errors   = [f for f in sess.findings if f.severity == Severity.ERROR]
    warnings = [f for f in sess.findings if f.severity == Severity.WARNING]
    infos    = [f for f in sess.findings if f.severity == Severity.INFO]
    diags    = [f for f in sess.findings if f.severity == Severity.DIAG]

    print(f"\n  Findings: {len(errors)} error(s), {len(warnings)} warning(s), {len(infos)} info(s)"
          + (f", {len(diags)} diag(s)" if sess.diagnosed or diags else ""))
    for finding in sess.findings:
        print(str(finding))

    if not sess.findings:
        print("  [OK] No violations found")

    if show_messages:
        _print_messages(sess, decode_usb=decode_usb)

    if show_requirements:
        _print_requirements(sess)


def _lifecycle_json(lc: Optional[TcpLifecycle], sender_endpoint: str) -> Optional[dict]:
    """A connection's opening and end; timestamps are the capture's own clock."""
    if lc is None:
        return None
    close = lc.close
    return {
        'opened_at': lc.opened_at,
        'syn_packet': lc.syn.packet_number if lc.syn else None,
        'closed_at': close.timestamp if close else None,
        'close_packet': close.packet_number if close else None,
        'close_kind': close.kind.value if close else None,
        'closed_by': _close_role(close, sender_endpoint).value if close else None,
        'lifetime_s': (close.timestamp - lc.opened_at
                       if close and lc.opened_at is not None else None),
        'last_segment_at': lc.last_timestamp,
    }


def _sessions_to_json(sessions: list[Session]) -> dict:
    out = []
    for sess in sessions:
        errors   = [f for f in sess.findings if f.severity == Severity.ERROR]
        warnings = [f for f in sess.findings if f.severity == Severity.WARNING]
        ctrl = sess.control

        out.append({
            'sender_ip': sess.sender_ip,
            'sender_port': sess.sender_port,
            'sender_info': sess.control.sender_info,
            'receiver_status': sess.control.receiver_status,
            'capture_end': sess.capture_end,
            'control_connection': ({
                'receiver': ctrl.receiver_endpoint,
                'sender': ctrl.sender_endpoint,
                'lifecycle': _lifecycle_json(ctrl.connection, ctrl.sender_endpoint),
            } if ctrl.key else None),
            # Every data-channel TCP connection, in the order they opened.
            'data_connections': [
                {
                    'index': ch.index,
                    'sender': ch.sender_endpoint,
                    'receiver': ch.receiver_endpoint,
                    'substreamid': ch.substreamid,
                    'busid': ch.busid,
                    'usbspeed': ch.usbspeed,
                    'message_count': len(ch.messages),
                    'stream_status_seen': ch.stream_status_pkt is not None,
                    'stream_status_ok': ch.stream_status_ok,
                    'lifecycle': _lifecycle_json(ch.connection, ch.sender_endpoint),
                }
                for ch in sess.data_connections
            ],
            # The latest data-channel connection per SUBSTREAMID (see data_connections).
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
                    'connection': f.connection,
                    'requirement': f.requirement.name if f.requirement else None,
                }
                for f in sess.findings
            ],
            'error_count': len(errors),
            'warning_count': len(warnings),
            'diagnosed': sess.diagnosed,
            'diag_count': sum(1 for f in sess.findings if f.severity == Severity.DIAG),
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
    parser.add_argument('--diagnose', action='store_true',
                        help="Also check each data channel against core USB 2.0 Chapter 9 rules "
                             "(configure before use, SET_CONFIGURATION/SET_ADDRESS, descriptor "
                             "and LANGID requests). Breaches are reported as DIAG: TR-10-14 does "
                             "not mandate them, so they never count as errors or change the exit code")

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
        diagnose=args.diagnose,
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
        total_diags    = sum(len([f for f in s.findings if f.severity == Severity.DIAG]) for s in sessions)
        print(f"\n{'='*72}")
        print(f"Total: {len(sessions)} session(s), {total_errors} error(s), {total_warnings} warning(s)"
              + (f", {total_diags} diag(s)" if args.diagnose or total_diags else ""))

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
