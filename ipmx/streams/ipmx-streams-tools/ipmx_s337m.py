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
"""SMPTE 337M (S337M) data burst parsing for AES3 transparent transport.

SMPTE 337-2008 defines the framing for non-PCM audio and data in AES3 subframes.
Each data burst consists of four preamble words (Pa, Pb, Pc, Pd) followed by
a burst_payload:

  Pa  — sync word 1 (value depends on data_mode)
  Pb  — sync word 2 (value depends on data_mode)
  Pc  — burst_info: data_type (5-bit), data_mode (2-bit), error_flag (1-bit),
         data_type_dependent (5-bit), data_stream_number (3-bit)
  Pd  — length_code: number of data bits in the burst_payload

The three data modes place data words in different AES3 time slot ranges:

  Mode 0 (16-bit)  time slots 27-12  → DATA24 bits 23-8  (lower 8 bits = 0)
  Mode 1 (20-bit)  time slots 27-8   → DATA24 bits 23-4  (lower 4 bits = 0)
  Mode 2 (24-bit)  time slots 27-4   → DATA24 bits 23-0  (all 24 bits used)

In frame mode (used by ST 2110-31 AM824), both AES3 channels carry a combined
data stream. Pa is placed in channel 1 of frame N, Pb in channel 2 of frame N,
Pc in channel 1 of frame N+1, Pd in channel 2 of frame N+1. The scan therefore
operates on the interleaved DATA24 word stream
  [ch1[0].data24, ch2[0].data24, ch1[1].data24, ch2[1].data24, ...]
where each (ch1[k], ch2[k]) pair forms one AES3 frame.

Reference: SMPTE 337-2008 §7.1 (burst_preamble), §7.2 (burst_payload),
           §7.3 (burst spacing), §8.2 (consumer compatibility).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Pa / Pb sync word constants as they appear in the 24-bit DATA24 field
# ---------------------------------------------------------------------------

#: Pa and Pb sync words keyed by data_mode (0=16-bit, 1=20-bit, 2=24-bit).
S337M_PA: dict[int, int] = {0: 0xF87200, 1: 0x6F8720, 2: 0x96F872}
S337M_PB: dict[int, int] = {0: 0x4E1F00, 1: 0x54E1F0, 2: 0xA54E1F}

# Reverse lookup: DATA24 value → (Pa|Pb, data_mode)
_PA_LOOKUP: dict[int, int] = {v: k for k, v in S337M_PA.items()}
_PB_LOOKUP: dict[int, int] = {v: k for k, v in S337M_PB.items()}

#: Number of data bits per AES3 frame (2 subframes) per data_mode in frame mode.
S337M_BITS_PER_FRAME: dict[int, int] = {0: 32, 1: 40, 2: 48}

#: Maximum number of AES3 frames between consecutive burst starts (S337M §7.3).
S337M_MAX_BURST_GAP_FRAMES: int = 4096

#: data_mode value → PCM equivalent sample size (used for MIB cross-validation).
S337M_DATA_MODE_TO_SAMPLE_SIZE: dict[int, int] = {0: 16, 1: 20, 2: 24}

#: PCM equivalent sample size → data_mode (reverse mapping).
S337M_SAMPLE_SIZE_TO_DATA_MODE: dict[int, int] = {16: 0, 20: 1, 24: 2}


# ---------------------------------------------------------------------------
# Burst_info (Pc) field extraction
# ---------------------------------------------------------------------------

def _extract_pc_fields(data24: int, data_mode: int) -> dict[str, int]:
    """Extract burst_info fields from the Pc DATA24 value.

    Field layout per S337M Table 7, adapted for each data_mode:

      16-bit Pc word (bits 15-0 of the 16-bit word at DATA24 bits 23-8):
        bits  0-4   data_type (5-bit)
        bits  5-6   data_mode (2-bit; shall equal detected Pa/Pb data_mode)
        bit   7     error_flag
        bits  8-12  data_type_dependent (5-bit)
        bits 13-15  data_stream_number (3-bit)

      20-bit Pc word (bits 19-0 of the 20-bit word at DATA24 bits 23-4):
        bits  0-3   reserved
        bits  4-8   data_type
        bits  9-10  data_mode
        bit  11     error_flag
        bits 12-16  data_type_dependent
        bits 17-19  data_stream_number

      24-bit Pc word (DATA24 bits 23-0):
        bits  0-7   reserved
        bits  8-12  data_type
        bits 13-14  data_mode
        bit  15     error_flag
        bits 16-20  data_type_dependent
        bits 21-23  data_stream_number
    """
    if data_mode == 0:
        pc = (data24 >> 8) & 0xFFFF
        return {
            "data_type":            pc & 0x1F,
            "data_mode_field":      (pc >> 5) & 0x03,
            "error_flag":           (pc >> 7) & 0x01,
            "data_type_dependent":  (pc >> 8) & 0x1F,
            "data_stream_number":   (pc >> 13) & 0x07,
        }
    if data_mode == 1:
        pc = (data24 >> 4) & 0xFFFFF
        return {
            "data_type":            (pc >> 4) & 0x1F,
            "data_mode_field":      (pc >> 9) & 0x03,
            "error_flag":           (pc >> 11) & 0x01,
            "data_type_dependent":  (pc >> 12) & 0x1F,
            "data_stream_number":   (pc >> 17) & 0x07,
        }
    # data_mode == 2
    pc = data24 & 0xFFFFFF
    return {
        "data_type":            (pc >> 8) & 0x1F,
        "data_mode_field":      (pc >> 13) & 0x03,
        "error_flag":           (pc >> 15) & 0x01,
        "data_type_dependent":  (pc >> 16) & 0x1F,
        "data_stream_number":   (pc >> 21) & 0x07,
    }


def _extract_pd_value(data24: int, data_mode: int) -> int:
    """Extract the length_code from the Pd DATA24 value."""
    if data_mode == 0:
        return (data24 >> 8) & 0xFFFF
    if data_mode == 1:
        return (data24 >> 4) & 0xFFFFF
    return data24 & 0xFFFFFF


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class S337mBurst:
    """One parsed S337M data burst."""

    #: AES3 frame index (word_index // 2) where Pa was found.
    frame_offset: int

    #: Data mode detected from the Pa sync word (0=16-bit, 1=20-bit, 2=24-bit).
    data_mode: int

    #: 5-bit data_type from Pc (SMPTE 338 codec identifier).
    data_type: int

    #: True if Pc error_flag bit is set (sender signals payload may contain errors).
    error_flag: bool

    #: 5-bit data_type_dependent field from Pc (codec-specific).
    data_type_dependent: int

    #: 3-bit data_stream_number from Pc (0-6 for regular streams, 7 reserved for timestamps).
    data_stream_number: int

    #: data_mode field inside Pc (must equal data_mode from Pa/Pb detection).
    pc_data_mode_field: int

    #: length_code from Pd: number of payload bits declared by the sender.
    length_code: int

    #: Number of DATA24 word-pairs (frames) the declared length_code requires.
    payload_frames_declared: int

    #: Number of DATA24 word-pairs (frames) between end of preamble and next Pa.
    payload_frames_actual: int

    #: True when payload_frames_actual is consistent with payload_frames_declared.
    length_code_consistent: bool


@dataclass
class S337mScanResult:
    """Results of scanning one AES3 signal (stereo pair) for S337M bursts."""

    #: Index of the AES3 signal (0 = first stereo pair, 1 = second, etc.).
    signal_index: int

    #: Parsed bursts in stream order.
    bursts: list[S337mBurst] = field(default_factory=list)

    #: True when every subframe in the signal has validity_bit=0 (PCM / silence).
    all_validity_zero: bool = False

    #: Maximum AES3 frame gap between consecutive Pa sync words (for spacing check).
    max_inter_burst_gap_frames: int = 0

    #: Structural parse errors (e.g. Pb mismatch, stream truncated after Pa).
    parse_errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def scan_s337m_signal(
    data24_words: list[int],
    validity_bits: list[int],
    signal_index: int,
) -> S337mScanResult:
    """Scan the interleaved DATA24 word stream of one AES3 signal for S337M bursts.

    Args:
        data24_words: Interleaved DATA24 values in frame order:
            [ch1[0].data24, ch2[0].data24, ch1[1].data24, ch2[1].data24, ...]
        validity_bits: Corresponding AES3 validity bits (1 = non-PCM / data).
        signal_index: Which AES3 stereo pair this is (for reporting).

    Returns:
        S337mScanResult with all detected bursts and diagnostic information.
    """
    result = S337mScanResult(signal_index=signal_index)

    if not any(v == 1 for v in validity_bits):
        result.all_validity_zero = True
        return result

    n = len(data24_words)

    # ------------------------------------------------------------------
    # Pass 1 — locate Pa+Pb sync sequences. The S337M sync is the *pair*
    # Pa(0xF87200…) followed by Pb(0x4E1F00…) in the next DATA24 slot.
    # Compressed payload bytes (e.g. inside an AAC burst) can randomly
    # match the Pa pattern alone — but the chance of also matching the
    # next slot as Pb is vanishingly small (~1/16M). Requiring both here
    # filters out content-dependent false positives without losing real
    # bursts. (Catching real bursts with corrupt Pb is already covered
    # by AES3-4.1.1-P parity and ENC-* integrity checks.)
    # ------------------------------------------------------------------
    pa_positions: list[tuple[int, int]] = []  # (word_index, data_mode)
    for i in range(n - 1):
        word = data24_words[i]
        mode = _PA_LOOKUP.get(word)
        if mode is None:
            continue
        if data24_words[i + 1] != S337M_PB[mode]:
            continue  # false-positive Pa pattern in payload bytes
        pa_positions.append((i, mode))

    if not pa_positions:
        # No Pa+Pb sync sequence found — check_s337m_sync_words will fail.
        return result

    # ------------------------------------------------------------------
    # Pass 2 — for each confirmed Pa+Pb, parse Pc/Pd and build S337mBurst
    # ------------------------------------------------------------------
    for burst_idx, (pa_idx, data_mode) in enumerate(pa_positions):
        if pa_idx + 3 >= n:
            result.parse_errors.append(
                f"Signal {signal_index}: Pa+Pb at word {pa_idx} (frame {pa_idx // 2}) "
                "— stream ends before Pc/Pd can be read"
            )
            continue

        # Pc and Pd occupy the next frame
        pc_fields = _extract_pc_fields(data24_words[pa_idx + 2], data_mode)
        length_code = _extract_pd_value(data24_words[pa_idx + 3], data_mode)

        # Declared payload size in AES3 frames (each frame = 2 DATA24 words)
        bits_per_frame = S337M_BITS_PER_FRAME[data_mode]
        declared_frames = math.ceil(length_code / bits_per_frame) if length_code > 0 else 0

        # Actual payload extent: from pa_idx+4 to next Pa (or end of stream).
        # This distance includes both the declared burst_payload AND any trailing
        # null (silence) AES3 frames that pad to the next burst start.  We do NOT
        # constrain the upper end because S337M allows any number of null frames
        # between bursts.  The consistency check only ensures that the declared
        # payload length does not exceed the available space (i.e., the burst
        # does not overflow into the next burst or beyond end-of-stream).
        if burst_idx + 1 < len(pa_positions):
            next_pa_idx = pa_positions[burst_idx + 1][0]
        else:
            next_pa_idx = n
        actual_words = next_pa_idx - (pa_idx + 4)
        actual_frames = actual_words // 2

        length_consistent = declared_frames <= actual_frames

        result.bursts.append(S337mBurst(
            frame_offset=pa_idx // 2,
            data_mode=data_mode,
            data_type=pc_fields["data_type"],
            error_flag=bool(pc_fields["error_flag"]),
            data_type_dependent=pc_fields["data_type_dependent"],
            data_stream_number=pc_fields["data_stream_number"],
            pc_data_mode_field=pc_fields["data_mode_field"],
            length_code=length_code,
            payload_frames_declared=declared_frames,
            payload_frames_actual=actual_frames,
            length_code_consistent=length_consistent,
        ))

    # ------------------------------------------------------------------
    # Compute maximum inter-burst gap (Pa-to-Pa distance in AES3 frames)
    # ------------------------------------------------------------------
    if len(pa_positions) >= 2:
        for (a, _), (b, _) in zip(pa_positions, pa_positions[1:]):
            gap = (b - a) // 2
            if gap > result.max_inter_burst_gap_frames:
                result.max_inter_burst_gap_frames = gap
    elif pa_positions:
        # Single burst — use total stream length as the effective gap
        result.max_inter_burst_gap_frames = n // 2

    return result
