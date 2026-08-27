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
TR-10-14 IPMX USB TCP message definitions and parser.

All field sizes and byte offsets are taken verbatim from VSF TR-10-14 (2024-09-24).
Big-endian byte order throughout.

Message framing (Table 1):
  Bytes  0– 7  CTR         64-bit AES-CTR counter (0 when unencrypted)
  Bytes  8–11  KEYVERSION  32-bit key version     (0 when unencrypted)
  Byte  12     MSGTYPE     8-bit message type
  Bytes 13–15  Reserved(7 bits) || LENGTH(17 bits) — big-endian packed 3-byte word
  Bytes 16 … LENGTH–9  DATA  (LENGTH – 24) bytes
  Bytes LENGTH–8 … LENGTH–1  MAC  64-bit CMAC (0 when unencrypted)

  Minimum LENGTH = 24 (no data, no MAC padding).
  Maximum LENGTH = 131047 (17-bit max = 131071, but spec says ≤131047).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Iterator, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class MsgType(IntEnum):
    """IPMX USB TCP message types (Table 1, Section 9)."""
    SENDER_CONNECTION_INFO        = 0x00
    SENDER_CONNECTION_STATUS      = 0x01
    HEARTBEAT                     = 0x02
    VENDOR_SPECIFIC_INFO          = 0x04
    VENDOR_SPECIFIC_QUERY         = 0x06
    VENDOR_SPECIFIC_QUERY_RETURN  = 0x07
    USB_WAKEUP_CONTROL            = 0x11
    USB_ENTER_SLEEP               = 0x12
    USB_RESUME_OPERATION          = 0x14
    USB_STREAM_INFO               = 0x80
    USB_STREAM_STATUS             = 0x81
    USB_STREAM_RESET_RETURN       = 0x82
    USB_STREAM_RESET              = 0x83
    USB_CONTROL_SUBMIT_RETURN     = 0x90
    USB_CONTROL_SUBMIT            = 0x91
    USB_BULK_SUBMIT_RETURN        = 0x92
    USB_BULK_SUBMIT               = 0x93
    USB_INTERRUPT_SUBMIT_RETURN   = 0x94
    USB_INTERRUPT_SUBMIT          = 0x95
    USB_ISOCHRONOUS_SUBMIT_RETURN = 0x96
    USB_ISOCHRONOUS_SUBMIT        = 0x97
    USB_CANCEL_SUBMIT_RETURN      = 0x98
    USB_CANCEL_SUBMIT             = 0x99


_MSG_TYPE_NAMES: dict[int, str] = {v: v.name for v in MsgType}


class UsbSpeed(IntEnum):
    """USBSPEED values (Section 9.7, Table 7)."""
    UNKNOWN    = 0
    LOW_SPEED  = 1
    FULL_SPEED = 2
    HIGH_SPEED = 3


class StreamStatus(IntEnum):
    """CSTATUS values for USB Stream Status (Section 9.8, Table 8)."""
    OK    = 0
    ERROR = 255


class WakeCtrl(IntEnum):
    """WAKECTRL values (Section 9.11, Table 9)."""
    DISABLE = 0
    ENABLE  = 1


class VendorQueryStatus(IntEnum):
    """VQSTS values (Section 9.6, Table 6)."""
    OK            = 0
    UNKNOWN_QUERY = 255


class StatusCode(IntEnum):
    """RSTATUS / ISOSTATUS values (Appendix A.1, Table 19)."""
    SUCCESS                        = 0x00000000
    CRC                            = 0xC0000001
    BTSTUFF                        = 0xC0000002
    DATA_TOGGLE_MISMATCH           = 0xC0000003
    STALL_PID                      = 0xC0000004
    DEV_NOT_RESPONDING             = 0xC0000005
    PID_CHECK_FAILURE              = 0xC0000006
    UNEXPECTED_PID                 = 0xC0000007
    DATA_OVERRUN                   = 0xC0000008
    DATA_UNDERRUN                  = 0xC0000009
    BUFFER_OVERRUN                 = 0xC000000C
    BUFFER_UNDERRUN                = 0xC000000D
    NOT_ACCESSED                   = 0xC000000F
    FIFO                           = 0xC0000010
    XACT_ERROR                     = 0xC0000011
    BABBLE_DETECTED                = 0xC0000012
    DATA_BUFFER_ERROR              = 0xC0000013
    NO_PING_RESPONSE               = 0xC0000014
    INVALID_STREAM_TYPE            = 0xC0000015
    INVALID_STREAM_ID              = 0xC0000016
    ENDPOINT_HALTED                = 0xC0000030
    INVALID_URB_FUNCTION           = 0x80000200
    INVALID_PARAMETER              = 0x80000300
    ERROR_BUSY                     = 0x80000400
    REQUEST_FAILED                 = 0x80000500
    INVALID_PIPE_HANDLE            = 0x80000600
    NO_BANDWIDTH                   = 0x80000700
    INTERNAL_HC_ERROR              = 0x80000800
    ERROR_SHORT_TRANSFER           = 0x80000900
    BAD_START_FRAME                = 0xC0000A00
    ISOCH_REQUEST_FAILED           = 0xC0000B00
    FRAME_CONTROL_OWNED            = 0xC0000C00
    FRAME_CONTROL_NOT_OWNED        = 0xC0000D00
    NOT_SUPPORTED                  = 0xC0000E00
    INVALID_CONFIGURATION_DESC     = 0xC0000F00
    INSUFFICIENT_RESOURCES         = 0xC0001000
    SET_CONFIG_FAILED              = 0xC0002000
    BUFFER_TOO_SMALL               = 0xC0003000
    INTERFACE_NOT_FOUND            = 0xC0004000
    INVALID_PIPE_FLAGS             = 0xC0005000
    TIMEOUT                        = 0xC0006000
    DEVICE_GONE                    = 0xC0007000
    STATUS_NOT_MAPPED              = 0xC0008000
    HUB_INTERNAL_ERROR             = 0xC0009000
    CANCELED                       = 0xC0010000
    ISO_NOT_ACCESSED_BY_HW         = 0xC0020000
    ISO_TD_ERROR                   = 0xC0030000
    ISO_NA_LATE_USBPORT            = 0xC0040000
    ISO_NOT_ACCESSED_LATE          = 0xC0050000
    BAD_DESCRIPTOR                 = 0xC0100000
    BAD_DESCRIPTOR_BLEN            = 0xC0100001
    BAD_DESCRIPTOR_TYPE            = 0xC0100002
    BAD_INTERFACE_DESCRIPTOR       = 0xC0100003
    BAD_ENDPOINT_DESCRIPTOR        = 0xC0100004
    BAD_INTERFACE_ASSOC_DESCRIPTOR = 0xC0100005
    BAD_CONFIG_DESC_LENGTH         = 0xC0100006
    BAD_NUMBER_OF_INTERFACES       = 0xC0100007
    BAD_NUMBER_OF_ENDPOINTS        = 0xC0100008
    BAD_ENDPOINT_ADDRESS           = 0xC0100009
    UNKNOWN_ERROR                  = 0xFFFFFFFF


_VALID_STATUS_CODES: frozenset[int] = frozenset(v.value for v in StatusCode)


# ---------------------------------------------------------------------------
# Header constants
# ---------------------------------------------------------------------------

HEADER_SIZE = 16       # bytes before DATA: CTR(8) + KEYVERSION(4) + MSGTYPE(1) + Rsvd+LENGTH(3)
MAC_SIZE = 8           # bytes after DATA
MIN_LENGTH = HEADER_SIZE + MAC_SIZE  # 24
MAX_LENGTH = 131047    # spec upper bound


# ---------------------------------------------------------------------------
# Parsed message
# ---------------------------------------------------------------------------

@dataclass
class IpmxUsbMessage:
    """One parsed IPMX USB TCP message."""

    # --- outer framing ---
    ctr: int          # 64-bit AES-CTR counter
    key_version: int  # 32-bit key version
    msg_type: int     # 8-bit raw MSGTYPE byte
    length: int       # 17-bit LENGTH field (= total message bytes)
    data: bytes       # raw DATA bytes (length - 24 bytes)
    mac: bytes        # 8-byte MAC (all-zero when unencrypted)

    # --- parsing context ---
    raw: bytes = field(repr=False)   # full original bytes
    offset: int = 0                  # byte offset within stream where this message started

    # --- decoded payload (filled by parse_data()) ---
    payload: dict = field(default_factory=dict)

    # When set, the message is treated as plaintext even if CTR/KEYVERSION are
    # non-zero — used by the dissector's --no-encrypted override so a stream a
    # vendor mislabels as encrypted (non-zero KEYVERSION but plaintext DATA)
    # can still be decoded. Does not suppress §12 CTR/KEYVERSION checks, which
    # read the raw fields directly.
    force_plaintext: bool = False

    @property
    def msg_type_enum(self) -> Optional[MsgType]:
        try:
            return MsgType(self.msg_type)
        except ValueError:
            return None

    @property
    def msg_type_name(self) -> str:
        mt = self.msg_type_enum
        return mt.name if mt is not None else f"UNKNOWN(0x{self.msg_type:02X})"

    @property
    def is_encrypted(self) -> bool:
        if self.force_plaintext:
            return False
        return self.ctr != 0 or self.key_version != 0

    @property
    def is_control_channel(self) -> bool:
        """Bit 7 of MSGTYPE = 0 → control channel."""
        return (self.msg_type & 0x80) == 0

    @property
    def is_data_channel(self) -> bool:
        """Bit 7 of MSGTYPE = 1 → data channel."""
        return (self.msg_type & 0x80) != 0

    def __str__(self) -> str:
        return (
            f"IpmxUsbMessage({self.msg_type_name}, length={self.length}, "
            f"data={len(self.data)}B, encrypted={self.is_encrypted})"
        )


# ---------------------------------------------------------------------------
# Low-level framing parser
# ---------------------------------------------------------------------------

def _parse_header(raw: bytes, offset: int) -> tuple[int, int, int, int]:
    """
    Parse the 16-byte IPMX USB message header starting at *offset*.

    Returns (ctr, key_version, msg_type, length).
    Raises :exc:`ValueError` for invalid fields.
    """
    if offset + HEADER_SIZE > len(raw):
        raise ValueError("Insufficient bytes for header")

    ctr = struct.unpack_from('>Q', raw, offset)[0]
    key_version = struct.unpack_from('>I', raw, offset + 8)[0]
    msg_type = raw[offset + 12]

    # Bytes 13–15: Reserved[6:0] || LENGTH[16:0] packed big-endian in 3 bytes.
    b13, b14, b15 = raw[offset + 13], raw[offset + 14], raw[offset + 15]
    word24 = (b13 << 16) | (b14 << 8) | b15
    length = word24 & 0x1FFFF  # lower 17 bits

    if length < MIN_LENGTH:
        raise ValueError(f"LENGTH {length} below minimum {MIN_LENGTH}")
    if length > MAX_LENGTH:
        raise ValueError(f"LENGTH {length} exceeds maximum {MAX_LENGTH}")

    return ctr, key_version, msg_type, length


def parse_one(raw: bytes, offset: int = 0, *,
              force_plaintext: bool = False) -> IpmxUsbMessage:
    """
    Parse one complete IPMX USB TCP message from *raw* starting at *offset*.

    The caller must ensure ``len(raw) - offset >= length`` before calling.

    When *force_plaintext* is True the DATA is decoded as plaintext even if
    CTR/KEYVERSION are non-zero (see :attr:`IpmxUsbMessage.force_plaintext`).
    """
    ctr, key_version, msg_type, length = _parse_header(raw, offset)

    end = offset + length
    if end > len(raw):
        raise ValueError(f"Message claims {length} bytes but only {len(raw) - offset} available")

    data_start = offset + HEADER_SIZE
    data_end = end - MAC_SIZE
    data = raw[data_start:data_end]
    mac = raw[data_end:end]

    msg = IpmxUsbMessage(
        ctr=ctr,
        key_version=key_version,
        msg_type=msg_type,
        length=length,
        data=data,
        mac=mac,
        raw=raw[offset:end],
        offset=offset,
        force_plaintext=force_plaintext,
    )
    if msg.is_encrypted:
        # DATA is ciphertext — cannot decode field values.
        # Store a sentinel so callers know the message is present but opaque.
        msg.payload = {'_encrypted': True, '_data_len': len(data)}
    else:
        msg.payload = _decode_payload(msg)
    return msg


def parse_stream(stream_bytes: bytes, *,
                 force_plaintext: bool = False) -> Iterator[IpmxUsbMessage]:
    """
    Yield all complete :class:`IpmxUsbMessage` objects from a reassembled
    byte stream.  Stops when insufficient bytes remain for the next message.
    Raises :exc:`ValueError` if a malformed header is encountered.
    """
    offset = 0
    total = len(stream_bytes)
    while offset + HEADER_SIZE <= total:
        _, _, _, length = _parse_header(stream_bytes, offset)
        if offset + length > total:
            break  # incomplete trailing message — wait for more data
        yield parse_one(stream_bytes, offset, force_plaintext=force_plaintext)
        offset += length


def peek_length(data: bytes, offset: int = 0) -> Optional[int]:
    """
    Return the LENGTH field of the message at *offset* without full parsing,
    or None if there are not enough bytes to read the header.
    """
    if offset + HEADER_SIZE > len(data):
        return None
    try:
        _, _, _, length = _parse_header(data, offset)
        return length
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Frame synchronisation
#
# The only field a header check can really lean on is LENGTH, and it is accepted
# over [24, 131047] out of a 17-bit range — about 99.96% of possible values. So a
# single readable header is almost no evidence that an offset is a real message
# boundary: measured on a real capture, 83% of *misaligned* offsets pass it, and
# 100% do on high-entropy (encrypted) payload. Framing therefore has to be
# justified by a run of messages whose lengths tile the stream, not by one header.
# ---------------------------------------------------------------------------

RESYNC_MIN_MESSAGES = 3


def chain_frames_cleanly(data: bytes, start: int = 0, min_messages: int = 1,
                         allow_truncated_tail: bool = True) -> bool:
    """
    Return True if framing forward from *start* accounts for the rest of *data*.

    Every message from *start* onwards must have a readable header, the chain must
    contain at least *min_messages* complete messages, and it must consume the
    buffer — landing exactly on the final byte, or, when *allow_truncated_tail* is
    set, on a trailing message cut short by the end of the capture.

    Note that msg_type is deliberately *not* validated here. Unknown message types
    are tolerated elsewhere in this module (``msg_type_enum`` returns None and the
    payload decodes to an empty dict), so rejecting them during framing would make
    a vendor-specific or future message type break the whole stream.
    """
    offset = start
    framed = 0

    while offset < len(data):
        if offset + HEADER_SIZE > len(data):
            # Trailing bytes too short to hold a header: a message truncated by
            # the end of the capture.
            return allow_truncated_tail and framed >= min_messages

        length = peek_length(data, offset)
        if length is None:
            return False

        if offset + length > len(data):
            # Trailing message truncated by the end of the capture.
            return allow_truncated_tail and framed >= min_messages

        offset += length
        framed += 1

    return framed >= min_messages


def block_starts_on_boundary(data: bytes) -> bool:
    """
    Return True if *data* can be trusted to begin on a message boundary.

    A buffer whose messages tile it exactly is self-evidently well framed. One
    that ends in a truncated message needs corroboration first, because "a single
    readable header followed by a length that overruns the buffer" is a pattern
    unrelated traffic satisfies easily — it is how an HTTP stream ends up being
    parsed as one enormous USB message. Requiring RESYNC_MIN_MESSAGES complete
    messages before trusting a truncated tail costs nothing on real USB streams,
    which carry far more than that before a capture cuts off.
    """
    if chain_frames_cleanly(data, 0, 1, allow_truncated_tail=False):
        return True
    return chain_frames_cleanly(data, 0, RESYNC_MIN_MESSAGES, allow_truncated_tail=True)


def next_sync_offset(data: bytes, start: int = 0) -> Optional[int]:
    """
    Find the first offset at or after *start* that can be trusted as a message
    boundary, or None when there is no such offset.

    The test here is deliberately far stricter than the one used to validate the
    start of a block. usbDissector inspects *every* TCP stream in a capture, not
    just USB ones, so a permissive rule does not merely mis-frame USB data — it
    manufactures USB messages out of TLS, HKEP and any other traffic that happens
    to be present. Requiring a chain of RESYNC_MIN_MESSAGES that tiles the buffer
    to its exact end (no truncated tail) is what keeps unrelated streams from
    producing a sync point at all.
    """
    limit = len(data) - HEADER_SIZE
    if limit < start:
        return None
    for candidate in range(start, limit + 1):
        if chain_frames_cleanly(data, candidate, RESYNC_MIN_MESSAGES,
                                allow_truncated_tail=False):
            return candidate
    return None


# ---------------------------------------------------------------------------
# Payload decoders — one per message type
# ---------------------------------------------------------------------------

def _decode_payload(msg: IpmxUsbMessage) -> dict:
    """Dispatch to the appropriate per-type decoder.  Returns empty dict on error."""
    mt = msg.msg_type_enum
    if mt is None:
        return {}
    decoder = _DECODERS.get(mt)
    if decoder is None:
        return {}
    try:
        return decoder(msg.data)
    except Exception:
        return {}


def _decode_sender_connection_info(data: bytes) -> dict:
    """Section 9.1, Table 2.  DATA is 66 bytes."""
    if len(data) < 66:
        return {}
    maver = (data[0] >> 4) & 0x0F
    miver = data[0] & 0x0F
    cid = data[2:5]   # byte 1 is Reserved; CID starts at byte 2 per figure 10
    sn = data[5:66].rstrip(b'\x00').decode('utf-8', errors='replace')
    return {
        'maver': maver,
        'miver': miver,
        'cid': cid.hex().upper(),
        'sn': sn,
    }


def _decode_sender_connection_status(data: bytes) -> dict:
    """Section 9.2, Table 3.  DATA is 68 bytes."""
    if len(data) < 68:
        return {}
    maver = (data[0] >> 4) & 0x0F
    miver = data[0] & 0x0F
    # byte 1: Rsvd(3 bits) || HBEAT(5 bits)
    hbeat = data[1] & 0x1F
    port = struct.unpack_from('>H', data, 2)[0]
    cid = data[4:7]
    sn = data[7:68].rstrip(b'\x00').decode('utf-8', errors='replace')
    return {
        'maver': maver,
        'miver': miver,
        'hbeat': hbeat,
        'port': port,
        'cid': cid.hex().upper(),
        'sn': sn,
    }


def _decode_heartbeat(_data: bytes) -> dict:
    """Section 9.3.  No DATA."""
    return {}


def _decode_vendor_specific_info(data: bytes) -> dict:
    """Section 9.4, Table 4."""
    if len(data) < 4:
        return {}
    cid = data[0:3]
    vmtype = data[3]
    vmdata = data[4:]
    result: dict = {'cid': cid.hex().upper(), 'vmtype': vmtype}
    if vmtype == 0:
        result['vmdata_str'] = vmdata.decode('utf-8', errors='replace')
    else:
        result['vmdata'] = vmdata.hex()
    return result


def _decode_vendor_specific_query(data: bytes) -> dict:
    """Section 9.5, Table 5.  DATA is 4 bytes."""
    if len(data) < 4:
        return {}
    cid = data[0:3]
    vqtype = data[3]
    return {'cid': cid.hex().upper(), 'vqtype': vqtype}


def _decode_vendor_specific_query_return(data: bytes) -> dict:
    """Section 9.6, Table 6."""
    if len(data) < 5:
        return {}
    cid = data[0:3]
    vqtype = data[3]
    vqsts = data[4]
    vqdata = data[5:]
    result: dict = {
        'cid': cid.hex().upper(),
        'vqtype': vqtype,
        'vqsts': vqsts,
    }
    if vqtype == 0 and vqsts == 0:
        result['vqdata_str'] = vqdata.decode('utf-8', errors='replace')
    else:
        result['vqdata'] = vqdata.hex()
    return result


def _decode_usb_wakeup_control(data: bytes) -> dict:
    """Section 9.11, Table 9.  DATA 1–7 bytes."""
    if len(data) < 1:
        return {}
    wakectrl = data[0]
    passwd = data[1:]
    return {
        'wakectrl': wakectrl,
        'passwd': passwd.hex(),
        'passwd_len': len(passwd),
    }


def _decode_usb_enter_sleep(_data: bytes) -> dict:
    """Section 9.12.  No DATA."""
    return {}


def _decode_usb_resume_operation(_data: bytes) -> dict:
    """Section 9.13.  No DATA."""
    return {}


def _decode_usb_stream_info(data: bytes) -> dict:
    """Section 9.7, Table 7.  DATA is 66 bytes."""
    if len(data) < 66:
        return {}
    substreamid = data[0]
    usbspeed = data[1]
    busid = data[2:66].rstrip(b'\x00').decode('utf-8', errors='replace')
    return {
        'substreamid': substreamid,
        'usbspeed': usbspeed,
        'usbspeed_name': UsbSpeed(usbspeed).name if usbspeed in UsbSpeed._value2member_map_ else f'UNKNOWN({usbspeed})',
        'busid': busid,
    }


def _decode_usb_stream_status(data: bytes) -> dict:
    """Section 9.8, Table 8.  DATA is 1 byte."""
    if len(data) < 1:
        return {}
    cstatus = data[0]
    return {'cstatus': cstatus}


def _decode_usb_stream_reset(_data: bytes) -> dict:
    """Section 9.9.  No DATA."""
    return {}


def _decode_usb_stream_reset_return(_data: bytes) -> dict:
    """Section 9.10.  No DATA."""
    return {}


def _decode_submit_common(data: bytes) -> dict:
    """Shared fields for Control/Bulk/Interrupt Submit (Tables 10, 11)."""
    if len(data) < 12:
        return {}
    seqnum = struct.unpack_from('>I', b'\x00' + data[0:3])[0]
    endpoint_byte = data[3]
    endpoint = (endpoint_byte >> 4) & 0x0F
    direction = (endpoint_byte >> 0) & 0x01   # D bit
    binterval = struct.unpack_from('>I', data, 4)[0]
    transferlength = struct.unpack_from('>I', data, 8)[0]
    transferdata = data[12:] if direction == 0 else b''
    return {
        'seqnum': seqnum,
        'endpoint': endpoint,
        'direction': direction,
        'binterval': binterval,
        'transferlength': transferlength,
        'transferdata': transferdata.hex() if transferdata else None,
    }


def _decode_usb_control_submit(data: bytes) -> dict:
    """Section 9.14, Table 10.  Extra USBDEVREQ field (8 bytes at offset 12)."""
    if len(data) < 20:
        return {}
    base = _decode_submit_common(data)
    if not base:
        return {}
    usbdevreq = data[12:20]
    transferdata = data[20:] if base['direction'] == 0 else b''
    base['usbdevreq'] = usbdevreq.hex()
    base['transferdata'] = transferdata.hex() if transferdata else None
    return base


def _decode_usb_bulk_submit(data: bytes) -> dict:
    """Section 9.15, Table 11."""
    return _decode_submit_common(data)


def _decode_usb_interrupt_submit(data: bytes) -> dict:
    """Section 9.16.  Same layout as Bulk Submit."""
    return _decode_submit_common(data)


def _decode_usb_isochronous_submit(data: bytes) -> dict:
    """Section 9.17, Table 12."""
    if len(data) < 16:
        return {}
    seqnum = struct.unpack_from('>I', b'\x00' + data[0:3])[0]
    endpoint_byte = data[3]
    endpoint = (endpoint_byte >> 4) & 0x0F
    direction = endpoint_byte & 0x01
    binterval = struct.unpack_from('>I', data, 4)[0]
    # byte 8: A(1 bit) || STARTFRAME(31 bits)
    word32 = struct.unpack_from('>I', data, 8)[0]
    asap = (word32 >> 31) & 0x01
    startframe = word32 & 0x7FFFFFFF
    num_packets = struct.unpack_from('>I', data, 12)[0]
    iso_desc_end = 16 + num_packets * 2
    iso_descs = [
        struct.unpack_from('>H', data, 16 + i * 2)[0]
        for i in range(num_packets)
    ] if len(data) >= iso_desc_end else []
    return {
        'seqnum': seqnum,
        'endpoint': endpoint,
        'direction': direction,
        'binterval': binterval,
        'asap': asap,
        'startframe': startframe,
        'num_packets': num_packets,
        'isolengths': iso_descs,
    }


def _decode_submit_return_common(data: bytes) -> dict:
    """Shared fields for Control/Bulk/Interrupt Submit Return (Table 14)."""
    if len(data) < 12:
        return {}
    seqnum = struct.unpack_from('>I', b'\x00' + data[0:3])[0]
    endpoint_byte = data[3]
    endpoint = (endpoint_byte >> 4) & 0x0F
    direction = endpoint_byte & 0x01
    actuallength = struct.unpack_from('>I', data, 4)[0]
    rstatus = struct.unpack_from('>I', data, 8)[0]
    transferdata = data[12:12 + actuallength] if direction == 1 and actuallength > 0 else b''
    return {
        'seqnum': seqnum,
        'endpoint': endpoint,
        'direction': direction,
        'actuallength': actuallength,
        'rstatus': rstatus,
        'rstatus_name': StatusCode(rstatus).name if rstatus in _VALID_STATUS_CODES else f'UNKNOWN(0x{rstatus:08X})',
        'transferdata': transferdata.hex() if transferdata else None,
    }


def _decode_usb_control_submit_return(data: bytes) -> dict:
    """Section 9.18, Table 14."""
    return _decode_submit_return_common(data)


def _decode_usb_bulk_submit_return(data: bytes) -> dict:
    """Section 9.19, Table 14."""
    return _decode_submit_return_common(data)


def _decode_usb_interrupt_submit_return(data: bytes) -> dict:
    """Section 9.20, Table 14."""
    return _decode_submit_return_common(data)


def _decode_usb_isochronous_submit_return(data: bytes) -> dict:
    """Section 9.21, Table 15."""
    if len(data) < 16:
        return {}
    seqnum = struct.unpack_from('>I', b'\x00' + data[0:3])[0]
    endpoint_byte = data[3]
    endpoint = (endpoint_byte >> 4) & 0x0F
    direction = endpoint_byte & 0x01
    startframe = struct.unpack_from('>I', data, 4)[0]
    errorcount = struct.unpack_from('>I', data, 8)[0]
    num_packets = struct.unpack_from('>I', data, 12)[0]
    desc_end = 16 + num_packets * 6
    iso_ret = []
    if len(data) >= desc_end:
        for i in range(num_packets):
            off = 16 + i * 6
            actual_len = struct.unpack_from('>H', data, off)[0]
            iso_status = struct.unpack_from('>I', data, off + 2)[0]
            iso_ret.append({'actuallength': actual_len, 'isostatus': iso_status})
    return {
        'seqnum': seqnum,
        'endpoint': endpoint,
        'direction': direction,
        'startframe': startframe,
        'errorcount': errorcount,
        'num_packets': num_packets,
        'iso_packets': iso_ret,
    }


def _decode_usb_cancel_submit(data: bytes) -> dict:
    """Section 9.22, Table 17.  DATA is 4 bytes."""
    if len(data) < 4:
        return {}
    seqnum = struct.unpack_from('>I', b'\x00' + data[0:3])[0]
    endpoint_byte = data[3]
    endpoint = (endpoint_byte >> 4) & 0x0F
    direction = endpoint_byte & 0x01
    return {'seqnum': seqnum, 'endpoint': endpoint, 'direction': direction}


def _decode_usb_cancel_submit_return(data: bytes) -> dict:
    """Section 9.23, Table 18.  DATA is 8 bytes: SEQNUM(3) + EP+D(1) + RSTATUS(4)."""
    if len(data) < 8:
        return {}
    seqnum = struct.unpack_from('>I', b'\x00' + data[0:3])[0]
    endpoint_byte = data[3]
    endpoint = (endpoint_byte >> 4) & 0x0F
    direction = endpoint_byte & 0x01
    rstatus = struct.unpack_from('>I', data, 4)[0]  # offset 4, not 3
    return {
        'seqnum': seqnum,
        'endpoint': endpoint,
        'direction': direction,
        'rstatus': rstatus,
        'rstatus_name': StatusCode(rstatus).name if rstatus in _VALID_STATUS_CODES else f'UNKNOWN(0x{rstatus:08X})',
    }


# Dispatcher table — maps MsgType → decoder function
_DECODERS = {
    MsgType.SENDER_CONNECTION_INFO:        _decode_sender_connection_info,
    MsgType.SENDER_CONNECTION_STATUS:      _decode_sender_connection_status,
    MsgType.HEARTBEAT:                     _decode_heartbeat,
    MsgType.VENDOR_SPECIFIC_INFO:          _decode_vendor_specific_info,
    MsgType.VENDOR_SPECIFIC_QUERY:         _decode_vendor_specific_query,
    MsgType.VENDOR_SPECIFIC_QUERY_RETURN:  _decode_vendor_specific_query_return,
    MsgType.USB_WAKEUP_CONTROL:            _decode_usb_wakeup_control,
    MsgType.USB_ENTER_SLEEP:               _decode_usb_enter_sleep,
    MsgType.USB_RESUME_OPERATION:          _decode_usb_resume_operation,
    MsgType.USB_STREAM_INFO:               _decode_usb_stream_info,
    MsgType.USB_STREAM_STATUS:             _decode_usb_stream_status,
    MsgType.USB_STREAM_RESET:              _decode_usb_stream_reset,
    MsgType.USB_STREAM_RESET_RETURN:       _decode_usb_stream_reset_return,
    MsgType.USB_CONTROL_SUBMIT:            _decode_usb_control_submit,
    MsgType.USB_CONTROL_SUBMIT_RETURN:     _decode_usb_control_submit_return,
    MsgType.USB_BULK_SUBMIT:               _decode_usb_bulk_submit,
    MsgType.USB_BULK_SUBMIT_RETURN:        _decode_usb_bulk_submit_return,
    MsgType.USB_INTERRUPT_SUBMIT:          _decode_usb_interrupt_submit,
    MsgType.USB_INTERRUPT_SUBMIT_RETURN:   _decode_usb_interrupt_submit_return,
    MsgType.USB_ISOCHRONOUS_SUBMIT:        _decode_usb_isochronous_submit,
    MsgType.USB_ISOCHRONOUS_SUBMIT_RETURN: _decode_usb_isochronous_submit_return,
    MsgType.USB_CANCEL_SUBMIT:             _decode_usb_cancel_submit,
    MsgType.USB_CANCEL_SUBMIT_RETURN:      _decode_usb_cancel_submit_return,
}


# ---------------------------------------------------------------------------
# Message builder (for test PCAP generation)
# ---------------------------------------------------------------------------

def build_message(
    msg_type: MsgType,
    data: bytes,
    *,
    ctr: int = 0,
    key_version: int = 0,
    mac: bytes = b'\x00' * 8,
) -> bytes:
    """
    Construct the raw bytes of one IPMX USB TCP message.

    Args:
        msg_type:    Message type enum value.
        data:        DATA payload bytes (may be empty).
        ctr:         64-bit AES-CTR counter (0 = unencrypted).
        key_version: 32-bit key version    (0 = unencrypted).
        mac:         8-byte MAC            (all zeros = unencrypted).

    Returns:
        Raw message bytes ready to be written into a TCP stream.
    """
    length = HEADER_SIZE + len(data) + MAC_SIZE
    if length < MIN_LENGTH or length > MAX_LENGTH:
        raise ValueError(f"Message length {length} out of range [{MIN_LENGTH}, {MAX_LENGTH}]")

    # Bytes 13–15: Reserved(7 bits) = 0, LENGTH(17 bits)
    rsvd_length = length & 0x1FFFF
    b13 = (rsvd_length >> 16) & 0xFF
    b14 = (rsvd_length >> 8) & 0xFF
    b15 = rsvd_length & 0xFF

    header = struct.pack('>Q', ctr)           # 8 bytes CTR
    header += struct.pack('>I', key_version)  # 4 bytes KEYVERSION
    header += bytes([msg_type & 0xFF])        # 1 byte MSGTYPE
    header += bytes([b13, b14, b15])          # 3 bytes Rsvd+LENGTH

    return header + data + mac


# ---------------------------------------------------------------------------
# Convenience builders for each message type
# ---------------------------------------------------------------------------

def build_sender_connection_info(
    cid: bytes,
    sn: str,
    maver: int = 0,
    miver: int = 0,
) -> bytes:
    """Build a SenderConnectionInfo DATA block (66 bytes) and return full message."""
    ver_byte = ((maver & 0x0F) << 4) | (miver & 0x0F)
    cid3 = (cid + b'\x00' * 3)[:3]
    sn_bytes = sn.encode('utf-8')[:61].ljust(61, b'\x00')
    data = bytes([ver_byte, 0x00]) + cid3 + sn_bytes
    return build_message(MsgType.SENDER_CONNECTION_INFO, data)


def build_sender_connection_status(
    cid: bytes,
    sn: str,
    hbeat: int,
    port: int,
    maver: int = 0,
    miver: int = 0,
) -> bytes:
    """Build a SenderConnectionStatus DATA block (68 bytes) and return full message."""
    ver_byte = ((maver & 0x0F) << 4) | (miver & 0x0F)
    hbeat_byte = hbeat & 0x1F
    cid3 = (cid + b'\x00' * 3)[:3]
    sn_bytes = sn.encode('utf-8')[:61].ljust(61, b'\x00')
    data = bytes([ver_byte, hbeat_byte]) + struct.pack('>H', port) + cid3 + sn_bytes
    return build_message(MsgType.SENDER_CONNECTION_STATUS, data)


def build_heartbeat() -> bytes:
    """Build a Heartbeat message (no DATA)."""
    return build_message(MsgType.HEARTBEAT, b'')


def build_vendor_specific_info(cid: bytes, vmtype: int, vmdata: bytes) -> bytes:
    cid3 = (cid + b'\x00' * 3)[:3]
    data = cid3 + bytes([vmtype]) + vmdata
    return build_message(MsgType.VENDOR_SPECIFIC_INFO, data)


def build_vendor_specific_query(cid: bytes, vqtype: int) -> bytes:
    cid3 = (cid + b'\x00' * 3)[:3]
    data = cid3 + bytes([vqtype])
    return build_message(MsgType.VENDOR_SPECIFIC_QUERY, data)


def build_vendor_specific_query_return(
    cid: bytes, vqtype: int, vqsts: int, vqdata: bytes = b''
) -> bytes:
    cid3 = (cid + b'\x00' * 3)[:3]
    data = cid3 + bytes([vqtype, vqsts]) + vqdata
    return build_message(MsgType.VENDOR_SPECIFIC_QUERY_RETURN, data)


def build_usb_stream_info(substreamid: int, usbspeed: int, busid: str) -> bytes:
    busid_bytes = busid.encode('utf-8')[:64].ljust(64, b'\x00')
    data = bytes([substreamid, usbspeed]) + busid_bytes
    return build_message(MsgType.USB_STREAM_INFO, data)


def build_usb_stream_status(cstatus: int = 0) -> bytes:
    return build_message(MsgType.USB_STREAM_STATUS, bytes([cstatus]))


def build_usb_stream_reset() -> bytes:
    return build_message(MsgType.USB_STREAM_RESET, b'')


def build_usb_stream_reset_return() -> bytes:
    return build_message(MsgType.USB_STREAM_RESET_RETURN, b'')


def build_usb_wakeup_control(wakectrl: int, passwd: bytes = b'') -> bytes:
    data = bytes([wakectrl]) + passwd[:6]
    return build_message(MsgType.USB_WAKEUP_CONTROL, data)


def build_usb_enter_sleep() -> bytes:
    return build_message(MsgType.USB_ENTER_SLEEP, b'')


def _build_submit_data(
    seqnum: int, endpoint: int, direction: int,
    binterval: int, transferlength: int, transferdata: bytes
) -> bytes:
    seq3 = struct.pack('>I', seqnum)[1:]   # 3 bytes
    ep_d = ((endpoint & 0x0F) << 4) | (direction & 0x01)
    return (seq3 + bytes([ep_d])
            + struct.pack('>I', binterval)
            + struct.pack('>I', transferlength)
            + transferdata)


def build_usb_control_submit(
    seqnum: int, endpoint: int, direction: int,
    binterval: int, transferlength: int,
    usbdevreq: bytes, transferdata: bytes = b'',
) -> bytes:
    seq3 = struct.pack('>I', seqnum)[1:]
    ep_d = ((endpoint & 0x0F) << 4) | (direction & 0x01)
    data = (seq3 + bytes([ep_d])
            + struct.pack('>I', binterval)
            + struct.pack('>I', transferlength)
            + (usbdevreq + b'\x00' * 8)[:8]
            + transferdata)
    return build_message(MsgType.USB_CONTROL_SUBMIT, data)


def _build_submit_return_data(
    seqnum: int, endpoint: int, direction: int,
    actuallength: int, rstatus: int, transferdata: bytes
) -> bytes:
    seq3 = struct.pack('>I', seqnum)[1:]
    ep_d = ((endpoint & 0x0F) << 4) | (direction & 0x01)
    return (seq3 + bytes([ep_d])
            + struct.pack('>I', actuallength)
            + struct.pack('>I', rstatus)
            + transferdata)


def build_usb_control_submit_return(
    seqnum: int, endpoint: int, direction: int,
    actuallength: int, rstatus: int, transferdata: bytes = b'',
) -> bytes:
    data = _build_submit_return_data(seqnum, endpoint, direction, actuallength, rstatus, transferdata)
    return build_message(MsgType.USB_CONTROL_SUBMIT_RETURN, data)


def build_usb_bulk_submit(
    seqnum: int, endpoint: int, direction: int,
    binterval: int, transferlength: int, transferdata: bytes = b'',
) -> bytes:
    data = _build_submit_data(seqnum, endpoint, direction, binterval, transferlength, transferdata)
    return build_message(MsgType.USB_BULK_SUBMIT, data)


def build_usb_bulk_submit_return(
    seqnum: int, endpoint: int, direction: int,
    actuallength: int, rstatus: int, transferdata: bytes = b'',
) -> bytes:
    data = _build_submit_return_data(seqnum, endpoint, direction, actuallength, rstatus, transferdata)
    return build_message(MsgType.USB_BULK_SUBMIT_RETURN, data)


def build_usb_interrupt_submit(
    seqnum: int, endpoint: int, direction: int,
    binterval: int, transferlength: int, transferdata: bytes = b'',
) -> bytes:
    data = _build_submit_data(seqnum, endpoint, direction, binterval, transferlength, transferdata)
    return build_message(MsgType.USB_INTERRUPT_SUBMIT, data)


def build_usb_interrupt_submit_return(
    seqnum: int, endpoint: int, direction: int,
    actuallength: int, rstatus: int, transferdata: bytes = b'',
) -> bytes:
    data = _build_submit_return_data(seqnum, endpoint, direction, actuallength, rstatus, transferdata)
    return build_message(MsgType.USB_INTERRUPT_SUBMIT_RETURN, data)


def build_usb_isochronous_submit(
    seqnum: int, endpoint: int, direction: int,
    binterval: int, asap: int, startframe: int,
    num_packets: int, isolengths: list[int],
) -> bytes:
    """Build USB_ISOCHRONOUS_SUBMIT (Section 9.17, Table 12)."""
    seq3 = struct.pack('>I', seqnum)[1:]
    ep_d = ((endpoint & 0x0F) << 4) | (direction & 0x01)
    a_sf = ((asap & 0x01) << 31) | (startframe & 0x7FFFFFFF)
    data = (seq3 + bytes([ep_d])
            + struct.pack('>I', binterval)
            + struct.pack('>I', a_sf)
            + struct.pack('>I', num_packets)
            + b''.join(struct.pack('>H', l) for l in isolengths))
    return build_message(MsgType.USB_ISOCHRONOUS_SUBMIT, data)


def build_usb_isochronous_submit_return(
    seqnum: int, endpoint: int, direction: int,
    startframe: int, errorcount: int,
    num_packets: int, iso_packets: list[tuple[int, int]],
    transferdata: bytes = b'',
) -> bytes:
    """Build USB_ISOCHRONOUS_SUBMIT_RETURN (Section 9.21, Table 15).

    *iso_packets* is a list of ``(actuallength, isostatus)`` tuples, one per
    isochronous packet descriptor.
    """
    seq3 = struct.pack('>I', seqnum)[1:]
    ep_d = ((endpoint & 0x0F) << 4) | (direction & 0x01)
    descs = b''.join(
        struct.pack('>H', al) + struct.pack('>I', st)
        for al, st in iso_packets
    )
    data = (seq3 + bytes([ep_d])
            + struct.pack('>I', startframe)
            + struct.pack('>I', errorcount)
            + struct.pack('>I', num_packets)
            + descs
            + transferdata)
    return build_message(MsgType.USB_ISOCHRONOUS_SUBMIT_RETURN, data)


def build_usb_cancel_submit(seqnum: int, endpoint: int, direction: int) -> bytes:
    seq3 = struct.pack('>I', seqnum)[1:]
    ep_d = ((endpoint & 0x0F) << 4) | (direction & 0x01)
    return build_message(MsgType.USB_CANCEL_SUBMIT, seq3 + bytes([ep_d]))


def build_usb_cancel_submit_return(
    seqnum: int, endpoint: int, direction: int, rstatus: int
) -> bytes:
    seq3 = struct.pack('>I', seqnum)[1:]
    ep_d = ((endpoint & 0x0F) << 4) | (direction & 0x01)
    data = seq3 + bytes([ep_d]) + struct.pack('>I', rstatus)
    return build_message(MsgType.USB_CANCEL_SUBMIT_RETURN, data)
