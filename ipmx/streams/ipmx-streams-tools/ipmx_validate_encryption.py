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
"""HKEP / PEP encryption validation for IPMX streams.

Cross-validates encryption state across four sources:
  1. CLI flags (--hkep / --pep)
  2. RTP extension headers (RFC 8285 one-byte, 0xBEDE)
  3. RTCP Media Info Blocks (0x0010 HKEP, 0x0011 PEP)
  4. SDP attributes (a=hkep, a=privacy, a=extmap URNs)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from MatroxSdp import MediaDescriptor

from ipmx_parse_rtp_pcap import RtpExtensionElement
from ipmx_validate_common import (
    RequirementResult,
    SenderReportInfo,
    untestable,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class EncExtLValue(IntEnum):
    """RFC 8285 one-byte extension L-field values for HKEP/PEP headers."""
    FULL = 0x0E   # 15 data bytes (L+1), 4 extension words
    SHORT = 0x02  # 3 data bytes (L+1), 1 extension word


def detect_encryption(ext_elements: list[RtpExtensionElement] | None) -> bool:
    """Return True if any extension element has an L value matching HKEP/PEP sizes."""
    if not ext_elements:
        return False
    for elem in ext_elements:
        l_field = elem.length - 1
        if l_field == EncExtLValue.FULL or l_field == EncExtLValue.SHORT:
            return True
    return False


class MibType(IntEnum):
    HKEP = 0x0010
    PEP = 0x0011


FULL_DATA_LEN = EncExtLValue.FULL + 1   # 15 bytes
SHORT_DATA_LEN = EncExtLValue.SHORT + 1  # 3 bytes

HKEP_SDP_URNS = frozenset({
    "urn:ietf:params:rtp-hdrext:HDCP-Full-IV-Counter-metadata",
    "urn:ietf:params:rtp-hdrext:HDCP-Short-IV-Counter-metadata",
})
PEP_SDP_URNS = frozenset({
    "urn:ietf:params:rtp-hdrext:PEP-Full-IV-Counter",
    "urn:ietf:params:rtp-hdrext:PEP-Short-IV-Counter",
})
ALL_ENCRYPTION_URNS = HKEP_SDP_URNS | PEP_SDP_URNS

FULL_URNS = frozenset({
    "urn:ietf:params:rtp-hdrext:HDCP-Full-IV-Counter-metadata",
    "urn:ietf:params:rtp-hdrext:PEP-Full-IV-Counter",
})
SHORT_URNS = frozenset({
    "urn:ietf:params:rtp-hdrext:HDCP-Short-IV-Counter-metadata",
    "urn:ietf:params:rtp-hdrext:PEP-Short-IV-Counter",
})


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class EncryptionFlags:
    """CLI-provided encryption flags."""
    hkep: bool = False
    pep: bool = False

    @property
    def any_encryption(self) -> bool:
        return self.hkep or self.pep


@dataclass
class _MibEncInfo:
    """Encryption info extracted from RTCP MIBs."""
    hkep_present: bool = False
    pep_present: bool = False
    hkep_f_id: int | None = None
    hkep_s_id: int | None = None
    pep_f_id: int | None = None
    pep_s_id: int | None = None


@dataclass
class _RtpExtSummary:
    """Summary of encryption-candidate RTP extension elements."""
    full_ids: set[int]
    short_ids: set[int]
    total_packets: int
    packets_with_full: int
    packets_with_short: int
    reserved_violations: int


# ---------------------------------------------------------------------------
# MIB extraction
# ---------------------------------------------------------------------------

def _extract_mib_enc_info(sender_reports: list[SenderReportInfo]) -> _MibEncInfo:
    info = _MibEncInfo()
    for sr in sender_reports:
        if sr.ipmx_info is None:
            continue
        for block in sr.ipmx_info.media_blocks:
            if block.media_info_type == MibType.HKEP and block.decoded:
                info.hkep_present = True
                info.hkep_f_id = int(block.decoded.get("f_id", 0))
                info.hkep_s_id = int(block.decoded.get("s_id", 0))
            elif block.media_info_type == MibType.PEP and block.decoded:
                info.pep_present = True
                info.pep_f_id = int(block.decoded.get("f_id", 0))
                info.pep_s_id = int(block.decoded.get("s_id", 0))
    return info


# ---------------------------------------------------------------------------
# RTP extension analysis
# ---------------------------------------------------------------------------

def _analyze_rtp_extensions(packets: list[dict[str, Any]]) -> _RtpExtSummary:
    full_ids: set[int] = set()
    short_ids: set[int] = set()
    total = 0
    with_full = 0
    with_short = 0
    reserved_violations = 0

    for meta in packets:
        total += 1
        ext_elements: list[RtpExtensionElement] | None = meta.get("ext_elements")
        if not ext_elements:
            continue
        pkt_has_full = False
        pkt_has_short = False
        for elem in ext_elements:
            l_field = elem.length - 1
            if l_field == EncExtLValue.FULL:
                full_ids.add(elem.ext_id)
                pkt_has_full = True
                if len(elem.data) >= 3 and (elem.data[0] & 0x7F) != 0:
                    reserved_violations += 1
            elif l_field == EncExtLValue.SHORT:
                short_ids.add(elem.ext_id)
                pkt_has_short = True
        if pkt_has_full:
            with_full += 1
        if pkt_has_short:
            with_short += 1

    return _RtpExtSummary(
        full_ids=full_ids,
        short_ids=short_ids,
        total_packets=total,
        packets_with_full=with_full,
        packets_with_short=with_short,
        reserved_violations=reserved_violations,
    )


# ---------------------------------------------------------------------------
# SDP helpers
# ---------------------------------------------------------------------------

def _sdp_has_hkep(sdp_media: MediaDescriptor) -> bool:
    if getattr(sdp_media, "hkep", False):
        return True
    hkep_desc = getattr(sdp_media, "hkep_desc", [])
    return any(getattr(hd, "address", "") for hd in hkep_desc)


def _sdp_has_privacy(sdp_media: MediaDescriptor) -> bool:
    if getattr(sdp_media, "privacy", False):
        return True
    privacy_desc = getattr(sdp_media, "privacy_desc", None)
    return privacy_desc is not None and bool(getattr(privacy_desc, "protocol", None))


def _sdp_extmap_entries(sdp_media: MediaDescriptor) -> list[tuple[int, str]]:
    """Return (id, uri) pairs from the SDP extmap."""
    entries: list[tuple[int, str]] = []
    ext_map = getattr(sdp_media, "ext_map", [])
    for em in ext_map:
        uri = getattr(em, "uri", "")
        ext_id = getattr(em, "id", 0)
        if uri:
            entries.append((ext_id, uri))
    return entries


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_enc_01_rtp_ext_present(
    flags: EncryptionFlags,
    ext_summary: _RtpExtSummary,
) -> RequirementResult:
    """ENC-01: RTP extension elements with matching L values present when encryption specified."""
    if not flags.any_encryption:
        return RequirementResult(
            req_id="ENC-01", level="shall", passed=True,
            text="RTP encryption extension headers present when --hkep/--pep specified",
            details="No encryption flags specified — check not applicable",
            testable=False,
        )
    has_candidates = ext_summary.packets_with_full > 0 or ext_summary.packets_with_short > 0
    if has_candidates:
        return RequirementResult(
            req_id="ENC-01", level="shall", passed=True,
            text="RTP encryption extension headers present when --hkep/--pep specified",
            details=(
                f"Full headers on {ext_summary.packets_with_full}/{ext_summary.total_packets} packets "
                f"(IDs: {sorted(ext_summary.full_ids)}), "
                f"short headers on {ext_summary.packets_with_short}/{ext_summary.total_packets} packets "
                f"(IDs: {sorted(ext_summary.short_ids)})"
            ),
        )
    return RequirementResult(
        req_id="ENC-01", level="shall", passed=False,
        text="RTP encryption extension headers present when --hkep/--pep specified",
        details=(
            f"Encryption specified via CLI but no RTP extension elements with "
            f"L={EncExtLValue.FULL} (full) or L={EncExtLValue.SHORT} (short) found "
            f"in {ext_summary.total_packets} packets"
        ),
    )


def _check_enc_02_l_value(
    flags: EncryptionFlags,
    ext_summary: _RtpExtSummary,
) -> RequirementResult:
    """ENC-02: Extension header L value correct (0xE for full, 0x2 for short)."""
    if not flags.any_encryption:
        return RequirementResult(
            req_id="ENC-02", level="shall", passed=True,
            text="Encryption extension L values correct",
            details="No encryption flags — not applicable",
            testable=False,
        )
    has_full = ext_summary.packets_with_full > 0
    has_short = ext_summary.packets_with_short > 0
    if not has_full and not has_short:
        return RequirementResult(
            req_id="ENC-02", level="shall", passed=True,
            text="Encryption extension L values correct",
            details="No encryption extension elements found to validate",
            testable=False,
        )
    return RequirementResult(
        req_id="ENC-02", level="shall", passed=True,
        text="Encryption extension L values correct",
        details=(
            f"Full (L=0x{EncExtLValue.FULL:X}): {ext_summary.packets_with_full} packets, "
            f"Short (L=0x{EncExtLValue.SHORT:X}): {ext_summary.packets_with_short} packets"
        ),
    )


def _check_enc_03_reserved_bits(
    flags: EncryptionFlags,
    ext_summary: _RtpExtSummary,
) -> RequirementResult:
    """ENC-03: Reserved bits in full extension header are 0."""
    if not flags.any_encryption or ext_summary.packets_with_full == 0:
        return RequirementResult(
            req_id="ENC-03", level="shall", passed=True,
            text="Reserved bits in full encryption extension header are 0",
            details="No full encryption extensions to validate",
            testable=False,
        )
    if ext_summary.reserved_violations > 0:
        return RequirementResult(
            req_id="ENC-03", level="shall", passed=False,
            text="Reserved bits in full encryption extension header are 0",
            details=(
                f"{ext_summary.reserved_violations} packet(s) have non-zero reserved bits "
                f"in the full encryption extension header"
            ),
        )
    return RequirementResult(
        req_id="ENC-03", level="shall", passed=True,
        text="Reserved bits in full encryption extension header are 0",
        details=f"All {ext_summary.packets_with_full} full extension headers have reserved bits = 0",
    )


def _check_enc_04_ext_id_vs_mib(
    flags: EncryptionFlags,
    ext_summary: _RtpExtSummary,
    mib: _MibEncInfo,
) -> RequirementResult:
    """ENC-04: Extension ID matches MIB f_id (full) or s_id (short)."""
    if not flags.any_encryption:
        return RequirementResult(
            req_id="ENC-04", level="shall", passed=True,
            text="RTP extension IDs match MIB f_id/s_id",
            details="No encryption flags — not applicable",
            testable=False,
        )
    if not mib.hkep_present and not mib.pep_present:
        return RequirementResult(
            req_id="ENC-04", level="shall", passed=True,
            text="RTP extension IDs match MIB f_id/s_id",
            details="No HKEP/PEP MIBs present — cannot cross-validate extension IDs",
            testable=False,
        )

    mismatches: list[str] = []

    expected_f_ids: set[int] = set()
    expected_s_ids: set[int] = set()
    if mib.hkep_present and mib.hkep_f_id is not None:
        expected_f_ids.add(mib.hkep_f_id)
    if mib.hkep_present and mib.hkep_s_id is not None:
        expected_s_ids.add(mib.hkep_s_id)
    if mib.pep_present and mib.pep_f_id is not None:
        expected_f_ids.add(mib.pep_f_id)
    if mib.pep_present and mib.pep_s_id is not None:
        expected_s_ids.add(mib.pep_s_id)

    if ext_summary.full_ids and expected_f_ids:
        unexpected_full = ext_summary.full_ids - expected_f_ids
        if unexpected_full:
            mismatches.append(
                f"Full extension IDs {sorted(unexpected_full)} not in MIB f_id set {sorted(expected_f_ids)}"
            )

    if ext_summary.short_ids and expected_s_ids:
        unexpected_short = ext_summary.short_ids - expected_s_ids
        if unexpected_short:
            mismatches.append(
                f"Short extension IDs {sorted(unexpected_short)} not in MIB s_id set {sorted(expected_s_ids)}"
            )

    if mismatches:
        return RequirementResult(
            req_id="ENC-04", level="shall", passed=False,
            text="RTP extension IDs match MIB f_id/s_id",
            details="; ".join(mismatches),
        )
    return RequirementResult(
        req_id="ENC-04", level="shall", passed=True,
        text="RTP extension IDs match MIB f_id/s_id",
        details=(
            f"Full IDs {sorted(ext_summary.full_ids)} match MIB f_id {sorted(expected_f_ids)}, "
            f"Short IDs {sorted(ext_summary.short_ids)} match MIB s_id {sorted(expected_s_ids)}"
        ),
    )


def _check_enc_14_fid_sid_distinct(
    flags: EncryptionFlags,
    mib: _MibEncInfo,
    sdp_media: MediaDescriptor | None,
) -> RequirementResult:
    """ENC-14: Full and short extension IDs must be distinct within each protocol."""
    if not flags.any_encryption:
        return RequirementResult(
            req_id="ENC-14", level="shall", passed=True,
            text="Full and short extension IDs are distinct per protocol",
            details="No encryption flags — not applicable",
            testable=False,
        )

    collisions: list[str] = []

    if mib.hkep_present and mib.hkep_f_id is not None and mib.hkep_s_id is not None:
        if mib.hkep_f_id == mib.hkep_s_id:
            collisions.append(
                f"MIB HKEP f_id={mib.hkep_f_id} == s_id={mib.hkep_s_id}"
            )
    if mib.pep_present and mib.pep_f_id is not None and mib.pep_s_id is not None:
        if mib.pep_f_id == mib.pep_s_id:
            collisions.append(
                f"MIB PEP f_id={mib.pep_f_id} == s_id={mib.pep_s_id}"
            )

    if sdp_media is not None:
        extmap_entries = _sdp_extmap_entries(sdp_media)
        hkep_full_id: int | None = None
        hkep_short_id: int | None = None
        pep_full_id: int | None = None
        pep_short_id: int | None = None
        for ext_id, uri in extmap_entries:
            if uri in HKEP_SDP_URNS:
                if uri in FULL_URNS:
                    hkep_full_id = ext_id
                elif uri in SHORT_URNS:
                    hkep_short_id = ext_id
            elif uri in PEP_SDP_URNS:
                if uri in FULL_URNS:
                    pep_full_id = ext_id
                elif uri in SHORT_URNS:
                    pep_short_id = ext_id
        if hkep_full_id is not None and hkep_short_id is not None and hkep_full_id == hkep_short_id:
            collisions.append(
                f"SDP HKEP full extmap ID={hkep_full_id} == short extmap ID={hkep_short_id}"
            )
        if pep_full_id is not None and pep_short_id is not None and pep_full_id == pep_short_id:
            collisions.append(
                f"SDP PEP full extmap ID={pep_full_id} == short extmap ID={pep_short_id}"
            )

    if not mib.hkep_present and not mib.pep_present and sdp_media is None:
        return RequirementResult(
            req_id="ENC-14", level="shall", passed=True,
            text="Full and short extension IDs are distinct per protocol",
            details="No MIBs or SDP available — cannot validate",
            testable=False,
        )

    if collisions:
        return RequirementResult(
            req_id="ENC-14", level="shall", passed=False,
            text="Full and short extension IDs are distinct per protocol",
            details="; ".join(collisions),
        )
    return RequirementResult(
        req_id="ENC-14", level="shall", passed=True,
        text="Full and short extension IDs are distinct per protocol",
        details="All f_id/s_id pairs are distinct within each encryption protocol",
    )


def _check_enc_05_hkep_mib_present(
    flags: EncryptionFlags,
    mib: _MibEncInfo,
) -> RequirementResult:
    """ENC-05: HKEP MIB (0x0010) present in RTCP when --hkep specified."""
    if not flags.hkep:
        return RequirementResult(
            req_id="ENC-05", level="shall", passed=True,
            text="HKEP MIB (0x0010) present when --hkep specified",
            details="--hkep not specified — not applicable",
            testable=False,
        )
    if mib.hkep_present:
        return RequirementResult(
            req_id="ENC-05", level="shall", passed=True,
            text="HKEP MIB (0x0010) present when --hkep specified",
            details=f"HKEP MIB found (f_id={mib.hkep_f_id}, s_id={mib.hkep_s_id})",
        )
    return RequirementResult(
        req_id="ENC-05", level="shall", passed=False,
        text="HKEP MIB (0x0010) present when --hkep specified",
        details="--hkep specified but no HKEP MIB (type 0x0010) found in any Sender Report",
    )


def _check_enc_06_pep_mib_present(
    flags: EncryptionFlags,
    mib: _MibEncInfo,
) -> RequirementResult:
    """ENC-06: PEP MIB (0x0011) present in RTCP when --pep specified."""
    if not flags.pep:
        return RequirementResult(
            req_id="ENC-06", level="shall", passed=True,
            text="PEP MIB (0x0011) present when --pep specified",
            details="--pep not specified — not applicable",
            testable=False,
        )
    if mib.pep_present:
        return RequirementResult(
            req_id="ENC-06", level="shall", passed=True,
            text="PEP MIB (0x0011) present when --pep specified",
            details=f"PEP MIB found (f_id={mib.pep_f_id}, s_id={mib.pep_s_id})",
        )
    return RequirementResult(
        req_id="ENC-06", level="shall", passed=False,
        text="PEP MIB (0x0011) present when --pep specified",
        details="--pep specified but no PEP MIB (type 0x0011) found in any Sender Report",
    )


def _check_enc_07_hkep_mib_absent(
    flags: EncryptionFlags,
    mib: _MibEncInfo,
    sdp_media: MediaDescriptor | None,
) -> RequirementResult:
    """ENC-07: HKEP MIB absent when --hkep not specified (and no SDP a=hkep)."""
    if flags.hkep:
        return RequirementResult(
            req_id="ENC-07", level="shall", passed=True,
            text="HKEP MIB absent when HKEP not expected",
            details="--hkep specified — check not applicable",
            testable=False,
        )
    sdp_hkep = sdp_media is not None and _sdp_has_hkep(sdp_media)
    if sdp_hkep:
        return RequirementResult(
            req_id="ENC-07", level="shall", passed=True,
            text="HKEP MIB absent when HKEP not expected",
            details="SDP has a=hkep — HKEP MIB is expected",
            testable=False,
        )
    if mib.hkep_present:
        return RequirementResult(
            req_id="ENC-07", level="shall", passed=False,
            text="HKEP MIB absent when HKEP not expected",
            details="HKEP MIB (0x0010) found but neither --hkep nor SDP a=hkep is set",
        )
    return RequirementResult(
        req_id="ENC-07", level="shall", passed=True,
        text="HKEP MIB absent when HKEP not expected",
        details="No HKEP MIB present, consistent with no HKEP indication",
    )


def _check_enc_08_pep_mib_absent(
    flags: EncryptionFlags,
    mib: _MibEncInfo,
    sdp_media: MediaDescriptor | None,
) -> RequirementResult:
    """ENC-08: PEP MIB absent when --pep not specified (and no SDP a=privacy)."""
    if flags.pep:
        return RequirementResult(
            req_id="ENC-08", level="shall", passed=True,
            text="PEP MIB absent when PEP not expected",
            details="--pep specified — check not applicable",
            testable=False,
        )
    sdp_privacy = sdp_media is not None and _sdp_has_privacy(sdp_media)
    if sdp_privacy:
        return RequirementResult(
            req_id="ENC-08", level="shall", passed=True,
            text="PEP MIB absent when PEP not expected",
            details="SDP has a=privacy — PEP MIB is expected",
            testable=False,
        )
    if mib.pep_present:
        return RequirementResult(
            req_id="ENC-08", level="shall", passed=False,
            text="PEP MIB absent when PEP not expected",
            details="PEP MIB (0x0011) found but neither --pep nor SDP a=privacy is set",
        )
    return RequirementResult(
        req_id="ENC-08", level="shall", passed=True,
        text="PEP MIB absent when PEP not expected",
        details="No PEP MIB present, consistent with no PEP indication",
    )


def _check_enc_09_sdp_hkep(
    flags: EncryptionFlags,
    sdp_media: MediaDescriptor | None,
) -> RequirementResult:
    """ENC-09: SDP a=hkep present when --hkep specified."""
    if sdp_media is None:
        return RequirementResult(
            req_id="ENC-09", level="shall", passed=True,
            text="SDP a=hkep present when --hkep specified",
            details="No SDP provided — cannot validate",
            testable=False,
        )
    if not flags.hkep:
        return RequirementResult(
            req_id="ENC-09", level="shall", passed=True,
            text="SDP a=hkep present when --hkep specified",
            details="--hkep not specified — not applicable",
            testable=False,
        )
    if _sdp_has_hkep(sdp_media):
        return RequirementResult(
            req_id="ENC-09", level="shall", passed=True,
            text="SDP a=hkep present when --hkep specified",
            details="SDP contains a=hkep attribute",
        )
    return RequirementResult(
        req_id="ENC-09", level="shall", passed=False,
        text="SDP a=hkep present when --hkep specified",
        details="--hkep specified but SDP does not contain a=hkep attribute",
    )


def _check_enc_10_sdp_privacy(
    flags: EncryptionFlags,
    sdp_media: MediaDescriptor | None,
) -> RequirementResult:
    """ENC-10: SDP a=privacy present when --pep specified."""
    if sdp_media is None:
        return RequirementResult(
            req_id="ENC-10", level="shall", passed=True,
            text="SDP a=privacy present when --pep specified",
            details="No SDP provided — cannot validate",
            testable=False,
        )
    if not flags.pep:
        return RequirementResult(
            req_id="ENC-10", level="shall", passed=True,
            text="SDP a=privacy present when --pep specified",
            details="--pep not specified — not applicable",
            testable=False,
        )
    if _sdp_has_privacy(sdp_media):
        return RequirementResult(
            req_id="ENC-10", level="shall", passed=True,
            text="SDP a=privacy present when --pep specified",
            details="SDP contains a=privacy attribute",
        )
    return RequirementResult(
        req_id="ENC-10", level="shall", passed=False,
        text="SDP a=privacy present when --pep specified",
        details="--pep specified but SDP does not contain a=privacy attribute",
    )


def _check_enc_11_sdp_extmap_urns(
    flags: EncryptionFlags,
    sdp_media: MediaDescriptor | None,
) -> RequirementResult:
    """ENC-11: SDP a=extmap URNs match the protocol."""
    if sdp_media is None:
        return RequirementResult(
            req_id="ENC-11", level="shall", passed=True,
            text="SDP extmap URNs match encryption protocol",
            details="No SDP provided — cannot validate",
            testable=False,
        )
    if not flags.any_encryption:
        return RequirementResult(
            req_id="ENC-11", level="shall", passed=True,
            text="SDP extmap URNs match encryption protocol",
            details="No encryption flags — not applicable",
            testable=False,
        )

    extmap_entries = _sdp_extmap_entries(sdp_media)
    sdp_urns = {uri for _, uri in extmap_entries}
    enc_urns = sdp_urns & ALL_ENCRYPTION_URNS

    # TR-10-13 §20.4: PEP may encrypt an HDCP-encrypted stream in-place
    # using the same HDCP CTR Full/Short RTP Extension Headers; in that
    # combined case only the HDCP extmap URNs appear in the SDP and PEP
    # reuses them. So a PEP URN is only required when PEP is active and
    # HKEP is not.
    mismatches: list[str] = []
    if flags.hkep:
        hkep_urns = enc_urns & HKEP_SDP_URNS
        if not hkep_urns:
            mismatches.append("No HKEP extmap URNs found in SDP")
    if flags.pep and not flags.hkep:
        pep_urns = enc_urns & PEP_SDP_URNS
        if not pep_urns:
            mismatches.append("No PEP extmap URNs found in SDP")

    if mismatches:
        return RequirementResult(
            req_id="ENC-11", level="shall", passed=False,
            text="SDP extmap URNs match encryption protocol",
            details="; ".join(mismatches),
        )
    return RequirementResult(
        req_id="ENC-11", level="shall", passed=True,
        text="SDP extmap URNs match encryption protocol",
        details=f"Encryption extmap URNs present: {sorted(enc_urns)}",
    )


def _check_enc_12_sdp_extmap_ids(
    flags: EncryptionFlags,
    sdp_media: MediaDescriptor | None,
    mib: _MibEncInfo,
) -> RequirementResult:
    """ENC-12: SDP extmap IDs consistent with MIB f_id/s_id."""
    if sdp_media is None:
        return RequirementResult(
            req_id="ENC-12", level="shall", passed=True,
            text="SDP extmap IDs consistent with MIB f_id/s_id",
            details="No SDP provided — cannot validate",
            testable=False,
        )
    if not flags.any_encryption:
        return RequirementResult(
            req_id="ENC-12", level="shall", passed=True,
            text="SDP extmap IDs consistent with MIB f_id/s_id",
            details="No encryption flags — not applicable",
            testable=False,
        )
    if not mib.hkep_present and not mib.pep_present:
        return RequirementResult(
            req_id="ENC-12", level="shall", passed=True,
            text="SDP extmap IDs consistent with MIB f_id/s_id",
            details="No HKEP/PEP MIBs — cannot cross-validate extmap IDs",
            testable=False,
        )

    extmap_entries = _sdp_extmap_entries(sdp_media)
    mismatches: list[str] = []

    for ext_id, uri in extmap_entries:
        if uri in FULL_URNS:
            if uri in HKEP_SDP_URNS and mib.hkep_present and mib.hkep_f_id is not None:
                if ext_id != mib.hkep_f_id:
                    mismatches.append(
                        f"SDP HKEP full extmap ID={ext_id} != MIB HKEP f_id={mib.hkep_f_id}"
                    )
            if uri in PEP_SDP_URNS and mib.pep_present and mib.pep_f_id is not None:
                if ext_id != mib.pep_f_id:
                    mismatches.append(
                        f"SDP PEP full extmap ID={ext_id} != MIB PEP f_id={mib.pep_f_id}"
                    )
        elif uri in SHORT_URNS:
            if uri in HKEP_SDP_URNS and mib.hkep_present and mib.hkep_s_id is not None:
                if ext_id != mib.hkep_s_id:
                    mismatches.append(
                        f"SDP HKEP short extmap ID={ext_id} != MIB HKEP s_id={mib.hkep_s_id}"
                    )
            if uri in PEP_SDP_URNS and mib.pep_present and mib.pep_s_id is not None:
                if ext_id != mib.pep_s_id:
                    mismatches.append(
                        f"SDP PEP short extmap ID={ext_id} != MIB PEP s_id={mib.pep_s_id}"
                    )

    if mismatches:
        return RequirementResult(
            req_id="ENC-12", level="shall", passed=False,
            text="SDP extmap IDs consistent with MIB f_id/s_id",
            details="; ".join(mismatches),
        )
    return RequirementResult(
        req_id="ENC-12", level="shall", passed=True,
        text="SDP extmap IDs consistent with MIB f_id/s_id",
        details="SDP extmap IDs are consistent with MIB f_id/s_id values",
    )


def _check_enc_13_informational(
    flags: EncryptionFlags,
    mib: _MibEncInfo,
    ext_summary: _RtpExtSummary,
) -> RequirementResult:
    """ENC-13: Informational — encrypted stream detected."""
    sources: list[str] = []
    if flags.hkep:
        sources.append("CLI --hkep")
    if flags.pep:
        sources.append("CLI --pep")
    if mib.hkep_present:
        sources.append("HKEP MIB (0x0010)")
    if mib.pep_present:
        sources.append("PEP MIB (0x0011)")
    if ext_summary.packets_with_full > 0 or ext_summary.packets_with_short > 0:
        sources.append(
            f"RTP extensions (full on {ext_summary.packets_with_full} pkts, "
            f"short on {ext_summary.packets_with_short} pkts)"
        )

    if not sources:
        return RequirementResult(
            req_id="ENC-13", level="info", passed=True,
            text="Encryption status",
            details="No encryption detected from CLI, MIB, or RTP extensions",
        )
    return RequirementResult(
        req_id="ENC-13", level="info", passed=True,
        text="Encryption status",
        details=(
            f"Encrypted stream detected via: {', '.join(sources)}. "
            f"Payload headers (VPS/SPS/PPS/SEI or codec boxes) may not be in the clear — "
            f"some validation checks may be limited."
        ),
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_encryption_checks(
    packets: list[dict[str, Any]],
    sender_reports: list[SenderReportInfo],
    sdp_media: MediaDescriptor | None,
    flags: EncryptionFlags,
) -> list[RequirementResult]:
    """Run all encryption validation checks.

    Returns an empty list when no encryption flags are set and no encryption
    indicators are found (to avoid noise in non-encrypted streams).
    """
    mib = _extract_mib_enc_info(sender_reports)
    ext_summary = _analyze_rtp_extensions(packets)

    has_any_indicator = (
        flags.any_encryption
        or mib.hkep_present
        or mib.pep_present
        or ext_summary.packets_with_full > 0
        or ext_summary.packets_with_short > 0
    )
    if sdp_media is not None:
        has_any_indicator = (
            has_any_indicator
            or _sdp_has_hkep(sdp_media)
            or _sdp_has_privacy(sdp_media)
            or bool({uri for _, uri in _sdp_extmap_entries(sdp_media)} & ALL_ENCRYPTION_URNS)
        )

    if not has_any_indicator:
        return []

    results: list[RequirementResult] = []

    results.append(_check_enc_01_rtp_ext_present(flags, ext_summary))
    results.append(_check_enc_02_l_value(flags, ext_summary))
    results.append(_check_enc_03_reserved_bits(flags, ext_summary))
    results.append(_check_enc_04_ext_id_vs_mib(flags, ext_summary, mib))
    results.append(_check_enc_14_fid_sid_distinct(flags, mib, sdp_media))

    results.append(_check_enc_05_hkep_mib_present(flags, mib))
    results.append(_check_enc_06_pep_mib_present(flags, mib))
    results.append(_check_enc_07_hkep_mib_absent(flags, mib, sdp_media))
    results.append(_check_enc_08_pep_mib_absent(flags, mib, sdp_media))

    results.append(_check_enc_09_sdp_hkep(flags, sdp_media))
    results.append(_check_enc_10_sdp_privacy(flags, sdp_media))
    results.append(_check_enc_11_sdp_extmap_urns(flags, sdp_media))
    results.append(_check_enc_12_sdp_extmap_ids(flags, sdp_media, mib))

    results.append(_check_enc_13_informational(flags, mib, ext_summary))

    return results
