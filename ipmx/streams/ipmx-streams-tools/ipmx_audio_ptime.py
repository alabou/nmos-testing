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
"""Packet-time / RTP-clock-rate profiles for the two audio transports.

AM824 (ST 2110-31) and PCM (ST 2110-30 / AES67) are governed by *different*
normative texts, so each transport gets its own profile map here.  They are
deliberately not merged, and the difference is not cosmetic:

* ST 2110-31:2022 section 7 Table 1 is a **closed** list -- nine permitted
  <packet-time> / <clock-rate> combinations, and its wording is "shall take one
  of the values from the Table 1".  The AM824 map is kept exactly that, so a
  sender violating it still fails.
* ST 2110-30:2017 carries no packet-time table at all and defers the signaling
  to AES67-2018, which enumerates a different set (250 us, 333 us and 4 ms
  packet times that ST 2110-31 lacks; no 4-period entries, which it has),
  describes one shared packet time differently (0,13 vs 0.14 ms at 44,1 kHz),
  and adds an integer-millisecond interoperability allowance ST 2110-31 has no
  equivalent of.

The consequence is worth stating plainly: **the same SDP can be conformant on
the PCM path and non-conformant on the AM824 path.**  That is a fact about the
two standards, not a bug here.  The three places where AES67 and ST 2110-31
conflict -- including one where AES67 contradicts itself -- are written up in
the trunk repo at
``knowledge/deviations/2026-08-21-aes67-st2110-31-packet-time-signaling-conflicts.md``.

Use the transport-bound wrappers exported by ``ipmx_am824`` and ``ipmx_pcm``
rather than calling into this module with an explicit ``path``; that keeps each
validator wired to exactly one table.
"""

from __future__ import annotations

from enum import Enum


class AudioPath(Enum):
    """Which normative packet-time table governs a stream."""

    AM824 = "am824"  # ST 2110-31:2022 section 7 Table 1
    PCM = "pcm"      # ST 2110-30:2017 section 6, signaling per AES67-2018 section 8.1


# ST 2110-31:2022 Table 1 — the only nine permitted packet-time / clock-rate
# combinations.  Two keys can map to the same entry to tolerate the rounding
# that ST 2110-31 section 7 note mandates ("rounded to 2 decimal places, with
# midway values such as 0.125 rounded down"):
#
#   key = accepted ptime in µs  →  (nominal_ptime_us, periods_per_packet)
#
# "Signaled" key  — value of a=ptime × 1000 as written by a spec-compliant
#                   sender (e.g. 120 for 0.12 ms).
# "Exact" key     — physical period rounded to the nearest integer µs
#                   (e.g. 125 for 6 × 1/48000 s = 125.000 µs exactly).
#
# This table is kept PURE: every key is a representation of a value Table 1
# actually permits.  Interoperability tolerances belong in the alias map below,
# never here — see AES67_INTEGER_MS_PTIME_ALIASES for why.
ST2110_31_PACKET_TIME_PROFILES: dict[int, dict[int, tuple[int, int]]] = {
    # 44.1 kHz — three permitted ptimes (Table 1)
    44_100: {
        # 4 periods: 4/44100 s = 90.703 µs  →  SDP 0.09 ms = 90 µs
        91:   (91, 4),    # exact (rounded)
        90:   (91, 4),    # SDP signaled
        # 6 periods: 6/44100 s = 136.054 µs  →  SDP 0.14 ms = 140 µs
        136:  (136, 6),   # exact (rounded)
        140:  (136, 6),   # SDP signaled
        # 48 periods: 48/44100 s = 1088.435 µs  →  SDP 1.09 ms = 1090 µs
        1088: (1088, 48), # exact (rounded)
        1090: (1088, 48), # SDP signaled
    },
    # 48 kHz — three permitted ptimes (Table 1)
    48_000: {
        # 4 periods: 4/48000 s = 83.333 µs  →  SDP 0.08 ms = 80 µs
        83:   (83, 4),    # exact (rounded)
        80:   (83, 4),    # SDP signaled
        # 6 periods: 6/48000 s = 125.000 µs  →  SDP 0.12 ms = 120 µs
        # (0.125 ms rounds down to 0.12 ms per the spec note)
        125:  (125, 6),   # exact
        120:  (125, 6),   # SDP signaled
        # 48 periods: 48/48000 s = 1000.000 µs  →  SDP 1 ms = 1000 µs
        1000: (1000, 48), # exact and SDP signaled
    },
    # 96 kHz — three permitted ptimes (Table 1)
    96_000: {
        # 8 periods: 8/96000 s = 83.333 µs  →  SDP 0.08 ms = 80 µs
        83:   (83, 8),    # exact (rounded)
        80:   (83, 8),    # SDP signaled
        # 12 periods: 12/96000 s = 125.000 µs  →  SDP 0.12 ms = 120 µs
        125:  (125, 12),  # exact
        120:  (125, 12),  # SDP signaled
        # 96 periods: 96/96000 s = 1000.000 µs  →  SDP 1 ms = 1000 µs
        1000: (1000, 96), # exact and SDP signaled
    },
}

# AES67-2018 Table 2 (required and recommended packet times) keyed by the
# descriptions AES67 Table 4 gives for them.  Same key convention as the
# ST 2110-31 table above:
#
#   key = accepted ptime in µs  →  (nominal_ptime_us, periods_per_packet)
#
# Every value here is derived from the sample counts in Table 2 — the nominal is
# n/rate rounded to the nearest µs, and each Table 4 description was checked
# against the AES67 section 8.1 rule that a description carry "error less than
# half a sample period"; all of them pass.
#
# Two AES67 quirks are handled explicitly rather than smoothed over:
#
#  * 4 ms at 96 kHz is ABSENT.  Table 2 marks that combination "n.a." while
#    Table 4 still prints a description ("4") for it.  Table 2 is the clause
#    that says which packet times exist, so it wins; AES67 disagrees with itself
#    here.
#  * At 44,1 kHz the 6-period packet gets TWO signaled forms.  Table 4 describes
#    it as 0,13 (a truncation of 0.136054 ms) while ST 2110-31 section 7 mandates
#    2-decimal *rounding*, giving 0.14.  Both satisfy the AES67 half-sample-period
#    rule (6.05 µs and 3.95 µs error against an 11.34 µs allowance) and both
#    round back to 6 periods, so both are legitimate.  0,13 is listed here; 140
#    arrives via the union with the ST 2110-31 table below.
AES67_PACKET_TIME_PROFILES: dict[int, dict[int, tuple[int, int]]] = {
    # 44.1 kHz
    44_100: {
        # "125 microseconds" — 6 periods: 6/44100 s = 136.054 µs → T4 0,13
        136:  (136, 6),     # exact (rounded)
        130:  (136, 6),     # AES67 Table 4 signaled
        # "250 microseconds" — 12 periods: 12/44100 s = 272.109 µs → T4 0,27
        272:  (272, 12),    # exact (rounded)
        270:  (272, 12),    # SDP signaled
        # "333 microseconds" — 16 periods: 16/44100 s = 362.812 µs → T4 0,36
        363:  (363, 16),    # exact (rounded)
        360:  (363, 16),    # SDP signaled
        # "1 millisecond" — 48 periods: 48/44100 s = 1088.435 µs → T4 1,09
        1088: (1088, 48),   # exact (rounded)
        1090: (1088, 48),   # SDP signaled
        # "4 milliseconds" — 192 periods: 192/44100 s = 4353.741 µs → T4 4,35
        4354: (4354, 192),  # exact (rounded)
        4350: (4354, 192),  # SDP signaled
    },
    # 48 kHz
    48_000: {
        # "125 microseconds" — 6 periods: 125.000 µs exactly → T4 0,12
        125:  (125, 6),     # exact
        120:  (125, 6),     # SDP signaled
        # "250 microseconds" — 12 periods: 250.000 µs exactly → T4 0,25
        250:  (250, 12),    # exact and SDP signaled
        # "333 microseconds" — 16 periods: 333.333 µs → T4 0,33
        333:  (333, 16),    # exact (rounded)
        330:  (333, 16),    # SDP signaled
        # "1 millisecond" — 48 periods: 1000.000 µs exactly → T4 1
        1000: (1000, 48),   # exact and SDP signaled
        # "4 milliseconds" — 192 periods: 4000.000 µs exactly → T4 4
        4000: (4000, 192),  # exact and SDP signaled
    },
    # 96 kHz  (no 4 ms entry — Table 2 marks it n.a.)
    96_000: {
        # "125 microseconds" — 12 periods: 125.000 µs exactly → T4 0,12
        125:  (125, 12),    # exact
        120:  (125, 12),    # SDP signaled
        # "250 microseconds" — 24 periods: 250.000 µs exactly → T4 0,25
        250:  (250, 24),    # exact and SDP signaled
        # "333 microseconds" — 32 periods: 333.333 µs → T4 0,33
        333:  (333, 32),    # exact (rounded)
        330:  (333, 32),    # SDP signaled
        # "1 millisecond" — 96 periods: 1000.000 µs exactly → T4 1
        1000: (1000, 96),   # exact and SDP signaled
    },
}

# AES67-2018 section 8.1 integer-millisecond interoperability allowance:
#
#   "NOTE  The non-integral-millisecond descriptions may not be correctly
#    understood by connection management partners not in compliance with this
#    standard. The description may need to be confined to integer <millisecond>
#    values when attempting connection to such partners."
#       — AES67-2018 section 8.1, final NOTE ("this standard" = AES67-2018)
#
# AES67 Table 2 names the 44,1 kHz / 48-period packet time "1 millisecond", and
# Table 4 gives its conforming description as 1,09 ms.  A sender talking to a
# non-compliant partner may therefore signal a=ptime:1 for that very same
# 48-period packet.  This map records which permitted value such an alias
# stands in for, so the PCM path resolves a=ptime:1 at 44,1 kHz to 48 periods
# and a 1088 µs nominal packet time.
#
# Two caveats, both deliberate:
#
#  * The alias contradicts AES67-2018 section 8.1 paragraph 2, which says the
#    sample count is the signaled ptime × sampling frequency rounded to nearest
#    -- 1.000 ms × 44100 = 44.1 → 44 periods, not 48 -- and requires the
#    description be given "with error less than half a sample period" (here the
#    error is 88.4 µs against an 11.3 µs allowance, ~7.8× over).  The normative
#    paragraph and the NOTE disagree; this alias follows the NOTE, because the
#    NOTE is the clause that describes real interoperability behaviour.  The
#    conflict is in AES67 itself, not in this table.
#  * It applies to the PCM path ONLY.  ST 2110-31:2022 section 7 admits no such
#    tolerance -- for 44100 its Table 1 permits 1.09, 0.14 and 0.09 and nothing
#    else -- so honouring a=ptime:1 on the AM824 path would mask a genuine
#    ST 2110-31 violation.
#
# Only 44,1 kHz needs aliases, and only for the two descriptions that are >= 1 ms:
# confining 0,13 / 0,27 / 0,36 to a whole number of milliseconds would give 0,
# so the allowance cannot apply to them.  The 4 ms alias breaches the
# half-sample-period rule far harder than the 1 ms one (353.7 µs error = 31.2x
# the allowance, and section 8.1 paragraph 2 arithmetic yields 176 periods rather
# than 192), but it is the same allowance and excluding it would be arbitrary.
#
#   key = alias ptime in µs  →  the permitted signaled ptime it stands in for
AES67_INTEGER_MS_PTIME_ALIASES: dict[int, dict[int, int]] = {
    44_100: {
        1000: 1090,  # "1 millisecond",  described 1,09 → confined to 1
        4000: 4350,  # "4 milliseconds", described 4,35 → confined to 4
    },
}


def _apply_ptime_aliases(
    base: dict[int, dict[int, tuple[int, int]]],
    aliases: dict[int, dict[int, int]],
) -> dict[int, dict[int, tuple[int, int]]]:
    """Return a copy of `base` with each alias bound to the entry it stands in for.

    Derived rather than restated so an alias cannot drift away from the
    permitted value it aliases.
    """
    merged = {rate: dict(profiles) for rate, profiles in base.items()}
    for sample_rate, alias_map in aliases.items():
        for alias_ptime_us, permitted_ptime_us in alias_map.items():
            merged[sample_rate][alias_ptime_us] = base[sample_rate][permitted_ptime_us]
    return merged


def _merge_profiles(
    *tables: dict[int, dict[int, tuple[int, int]]],
) -> dict[int, dict[int, tuple[int, int]]]:
    """Union several profile tables, refusing to merge contradictory entries.

    Two standards describing the same packet must agree on its geometry.  If
    they ever disagree on a shared key that is a fact about the specs worth
    stopping for, not something to resolve by declaring a winner silently.
    """
    merged: dict[int, dict[int, tuple[int, int]]] = {}
    for table in tables:
        for sample_rate, profiles in table.items():
            target = merged.setdefault(sample_rate, {})
            for ptime_us, entry in profiles.items():
                existing = target.get(ptime_us)
                if existing is not None and existing != entry:
                    raise ValueError(
                        f"conflicting packet-time profiles for {sample_rate} Hz "
                        f"ptime={ptime_us} us: {existing} vs {entry}"
                    )
                target[ptime_us] = entry
    return merged


# ST 2110-30:2017 section 6 requires AES67 conformance and states no packet-time
# table of its own, so the PCM path is built from AES67 rather than from
# ST 2110-31.  It is the *union* of the two tables because both are legitimate
# here: AES67 section 7.2.2 says senders and receivers "may support additional
# packet times", and section 8.1 requires that "Values outside those enumerated
# in table 4 shall be correctly interpreted".  The union adds, in each direction:
#
#   from AES67       — 250 µs and 333 µs at every rate, 4 ms at 48 and 44,1 kHz,
#                      and the 0,13 ms (130 µs) description at 44,1 kHz
#   from ST 2110-31  — the 4-period entries AES67 does not enumerate (80/83 µs at
#                      48 and 96 kHz, 90/91 µs at 44,1 kHz) and the 0.14 ms
#                      (140 µs) description of the 44,1 kHz 6-period packet
#
# Then the integer-millisecond allowance is applied on top.
ST2110_30_PACKET_TIME_PROFILES: dict[int, dict[int, tuple[int, int]]] = _apply_ptime_aliases(
    _merge_profiles(AES67_PACKET_TIME_PROFILES, ST2110_31_PACKET_TIME_PROFILES),
    AES67_INTEGER_MS_PTIME_ALIASES,
)

_PROFILES_BY_PATH: dict[AudioPath, dict[int, dict[int, tuple[int, int]]]] = {
    AudioPath.AM824: ST2110_31_PACKET_TIME_PROFILES,
    AudioPath.PCM: ST2110_30_PACKET_TIME_PROFILES,
}


def packet_time_profiles(path: AudioPath) -> dict[int, dict[int, tuple[int, int]]]:
    """Return the packet-time profile map governing `path`."""
    return _PROFILES_BY_PATH[path]


def legal_ptimes_us(sample_rate: int, *, path: AudioPath) -> set[int] | None:
    """Return every ptime `path` accepts at `sample_rate`, or None if the rate is illegal."""
    profiles = packet_time_profiles(path).get(sample_rate)
    if profiles is None:
        return None
    return set(profiles)


def resolve_nominal_packet_time_us(
    sample_rate: int,
    signaled_ptime_us: int,
    *,
    path: AudioPath,
) -> int | None:
    """Return the nominal (physical) packet time a signaled ptime denotes."""
    profiles = packet_time_profiles(path).get(sample_rate)
    if profiles is None:
        return None
    entry = profiles.get(signaled_ptime_us)
    return None if entry is None else entry[0]


def resolve_packet_samples_per_packet(
    sample_rate: int,
    signaled_ptime_us: int,
    *,
    path: AudioPath,
) -> int | None:
    """Return the number of RTP-clock periods per packet a signaled ptime denotes."""
    profiles = packet_time_profiles(path).get(sample_rate)
    if profiles is None:
        return None
    entry = profiles.get(signaled_ptime_us)
    return None if entry is None else entry[1]


def compute_audio_sender_report_interval_packets(
    sample_rate: int,
    signaled_ptime_us: int,
    *,
    path: AudioPath,
) -> int | None:
    """Return the RTCP Sender Report interval, in packets, for a signaled ptime."""
    samples_per_packet = resolve_packet_samples_per_packet(
        sample_rate, signaled_ptime_us, path=path
    )
    if samples_per_packet is None or samples_per_packet <= 0:
        return None
    return sample_rate // (100 * samples_per_packet)


def aes67_integer_ms_alias_target_us(sample_rate: int, signaled_ptime_us: int) -> int | None:
    """Return the permitted ptime `signaled_ptime_us` aliases, or None if it is not an alias.

    Lets a validator report "accepted as the AES67 integer-millisecond form of
    1.09 ms" instead of an unqualified pass, so a reader of the results can see
    that an interoperability allowance was applied.
    """
    return AES67_INTEGER_MS_PTIME_ALIASES.get(sample_rate, {}).get(signaled_ptime_us)


def acceptable_nominal_packet_times_us(
    sample_rate: int,
    signaled_ptime_us: int,
    *,
    path: AudioPath,
) -> set[int] | None:
    """Return the nominal packet-time values a device may report for a signaled ptime.

    Normally the single nominal value.  When `signaled_ptime_us` is an AES67
    section 8.1 integer-millisecond alias, the signaled value itself is also
    accepted: a sender that confines its SDP description to whole milliseconds
    may carry the same rounding into the packet time it reports elsewhere (its
    audio MIB, for instance), and that must not be scored as a failure.
    """
    nominal = resolve_nominal_packet_time_us(sample_rate, signaled_ptime_us, path=path)
    if nominal is None:
        return None
    accepted = {nominal}
    if aes67_integer_ms_alias_target_us(sample_rate, signaled_ptime_us) is not None:
        accepted.add(signaled_ptime_us)
    return accepted
