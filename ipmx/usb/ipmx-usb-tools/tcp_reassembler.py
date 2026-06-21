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
TCP stream reassembly for IPMX USB dissector.

Handles retransmissions, partial overlaps, out-of-order (OOO) segments,
and 32-bit sequence number wraparound.  Protocol-agnostic — the caller
supplies raw (seq, payload) pairs and gets back a contiguous bytearray.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seq_lt(a: int, b: int) -> bool:
    """Return True if TCP sequence number *a* is strictly before *b* (mod 2^32)."""
    return ((b - a) & 0xFFFF_FFFF) < 0x8000_0000


def _seq_le(a: int, b: int) -> bool:
    return a == b or _seq_lt(a, b)


def _seq_add(seq: int, n: int) -> int:
    return (seq + n) & 0xFFFF_FFFF


def _seq_diff(later: int, earlier: int) -> int:
    """Signed distance from *earlier* to *later* (positive means later > earlier)."""
    d = (later - earlier) & 0xFFFF_FFFF
    if d >= 0x8000_0000:
        return d - 0x1_0000_0000
    return d


# ---------------------------------------------------------------------------
# Core reassembly state machine
# ---------------------------------------------------------------------------

@dataclass
class TcpStream:
    """
    Per-direction TCP stream reassembler.

    Usage::

        stream = TcpStream()
        # Feed packets in arrival order (not sorted).
        for seq, payload in packets:
            stream.feed(seq, payload)
        data = stream.read_all()
    """

    _expected: int | None = field(default=None, init=False, repr=False)
    _buf: bytearray = field(default_factory=bytearray, init=False, repr=False)
    # OOO buffer: seq → payload (32-bit key, gaps held for later)
    _ooo: dict[int, bytes] = field(default_factory=dict, init=False, repr=False)

    def feed(self, seq: int, payload: bytes) -> None:
        """Accept one TCP segment.  Silently handles retransmissions and OOO."""
        if not payload:
            return

        if self._expected is None:
            # First data byte seen — anchor the stream.
            self._expected = seq
            self._accept(seq, payload)
            return

        exp = self._expected

        if seq == exp:
            self._accept(seq, payload)
        elif _seq_lt(seq, exp):
            # Retransmission or partial overlap.
            overlap = _seq_diff(exp, seq)  # bytes already consumed
            if overlap < len(payload):
                # Partial overlap: only the new suffix is interesting.
                self._accept(exp, payload[overlap:])
            # else: full retransmission — nothing new.
        else:
            # Future segment — buffer it.
            self._ooo[seq] = payload

    def _accept(self, seq: int, payload: bytes) -> None:
        """Append *payload* (guaranteed to start at expected seq) and drain OOO."""
        self._buf.extend(payload)
        self._expected = _seq_add(seq, len(payload))

        # Drain any buffered OOO segments that are now contiguous.
        while True:
            nxt = self._ooo.pop(self._expected, None)
            if nxt is None:
                break
            self._buf.extend(nxt)
            self._expected = _seq_add(self._expected, len(nxt))

    # ------------------------------------------------------------------
    # Read interface
    # ------------------------------------------------------------------

    def available(self) -> int:
        """Number of reassembled bytes ready to consume."""
        return len(self._buf)

    def read(self, n: int) -> bytes:
        """Consume and return the next *n* bytes (raises if not enough data)."""
        if n > len(self._buf):
            raise ValueError(f"Only {len(self._buf)} bytes available, requested {n}")
        data = bytes(self._buf[:n])
        del self._buf[:n]
        return data

    def peek(self, n: int) -> bytes:
        """Return the next *n* bytes without consuming them."""
        return bytes(self._buf[:n])

    def read_all(self) -> bytes:
        """Consume and return all reassembled bytes."""
        data = bytes(self._buf)
        self._buf.clear()
        return data

    @property
    def ooo_segments(self) -> int:
        """Number of out-of-order segments still waiting."""
        return len(self._ooo)


# ---------------------------------------------------------------------------
# Contiguous-block finder (for two-pass PCAP analysis)
# ---------------------------------------------------------------------------

@dataclass
class Block:
    """A contiguous slice of reassembled TCP stream data."""
    data: bytes
    packets: list  # all packet metas contributing to this block (for backward compat)
    # Byte-range map: list of (block_start, block_end, meta) sorted by block_start.
    # Allows mapping any byte offset within data[] back to the originating TCP packet.
    packet_ranges: list = field(default_factory=list)

    def meta_at(self, offset: int) -> object:
        """Return the meta of the TCP packet that carries byte *offset* of this block."""
        for start, end, meta in self.packet_ranges:
            if start <= offset < end:
                return meta
        # Fallback: first packet (should not happen for well-formed data)
        return self.packets[0] if self.packets else None


def find_contiguous_blocks(
    packets: list[tuple[int, int, bytes, object]],
) -> list[Block]:
    """
    Group a list of ``(seq, length, payload, packet_meta)`` tuples into
    contiguous blocks with no gaps.

    Retransmissions and partial overlaps are absorbed into the current block
    rather than starting a new one (fixing the hkepDissector Bug 1 pattern).
    Gaps (true lost-packet discontinuities) end the current block and start
    a fresh one.

    Args:
        packets: list of ``(seq, length, payload, packet_meta)`` tuples,
                 in any order.

    Returns:
        List of :class:`Block` objects ordered by starting sequence number.
    """
    if not packets:
        return []

    # Sort by sequence number (32-bit aware: treat as unsigned and sort by
    # distance from the minimum observed seq so wraparound sorts correctly).
    min_seq = min(s for s, _, _, _ in packets)
    sorted_pkts = sorted(packets, key=lambda t: _seq_diff(t[0], min_seq))

    blocks: list[Block] = []
    cur_data = bytearray()
    cur_pkts: list = []
    cur_ranges: list[tuple[int, int, object]] = []   # (start, end, meta) within cur_data
    expected: int | None = None

    def _append(payload: bytes, meta: object) -> None:
        start = len(cur_data)
        cur_data.extend(payload)
        cur_ranges.append((start, len(cur_data), meta))
        cur_pkts.append(meta)

    def _flush() -> None:
        if cur_data:
            blocks.append(Block(
                data=bytes(cur_data),
                packets=list(cur_pkts),
                packet_ranges=list(cur_ranges),
            ))

    for seq, length, payload, meta in sorted_pkts:
        if not payload:
            continue

        if expected is None:
            _append(payload, meta)
            expected = _seq_add(seq, len(payload))

        elif seq == expected:
            _append(payload, meta)
            expected = _seq_add(seq, len(payload))

        elif _seq_lt(seq, expected):
            # Retransmission or partial overlap — absorb into current block.
            overlap = _seq_diff(expected, seq)
            if overlap < len(payload):
                new_suffix = payload[overlap:]
                _append(new_suffix, meta)
                expected = _seq_add(seq, len(payload))
            # else: full retransmission — skip.

        else:
            # True gap: save current block and start a new one.
            _flush()
            cur_data.clear()
            cur_pkts.clear()
            cur_ranges.clear()
            _append(payload, meta)
            expected = _seq_add(seq, len(payload))

    _flush()
    return blocks


# ---------------------------------------------------------------------------
# Bidirectional stream pair
# ---------------------------------------------------------------------------

@dataclass
class TcpConnection:
    """
    A pair of :class:`TcpStream` objects representing both directions of a
    single TCP connection.

    *forward*: from the TCP client to the TCP server (SYN originator).
    *reverse*: from the TCP server to the TCP client.
    """
    forward: TcpStream = field(default_factory=TcpStream)
    reverse: TcpStream = field(default_factory=TcpStream)

    # Raw packet lists for two-pass block analysis
    forward_packets: list = field(default_factory=list, repr=False)
    reverse_packets: list = field(default_factory=list, repr=False)

    def feed_forward(self, seq: int, payload: bytes, meta: object = None) -> None:
        self.forward.feed(seq, payload)
        if meta is not None and payload:
            self.forward_packets.append((seq, len(payload), payload, meta))

    def feed_reverse(self, seq: int, payload: bytes, meta: object = None) -> None:
        self.reverse.feed(seq, payload)
        if meta is not None and payload:
            self.reverse_packets.append((seq, len(payload), payload, meta))

    def forward_blocks(self) -> list[Block]:
        return find_contiguous_blocks(self.forward_packets)

    def reverse_blocks(self) -> list[Block]:
        return find_contiguous_blocks(self.reverse_packets)


# ---------------------------------------------------------------------------
# Stream key helpers (matching hkepDissector conventions)
# ---------------------------------------------------------------------------

def make_stream_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
    """
    Return a canonical bidirectional stream key for a TCP connection.
    The lower (ip, port) tuple always appears first so both directions
    of a connection map to the same key.
    """
    if (src_ip, src_port) < (dst_ip, dst_port):
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
    return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"


def is_forward_direction(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int
) -> bool:
    """
    Return True if this packet travels in the *forward* direction for the
    stream key produced by :func:`make_stream_key`.
    """
    return (src_ip, src_port) < (dst_ip, dst_port)
