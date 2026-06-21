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

"""Build IPMX TR-10-7 sender reports with IPMX Info Block payloads."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, fields as dc_fields
from pathlib import Path
from collections.abc import Sequence
from typing import BinaryIO, Iterator


def pad_string(value: str, length: int) -> bytes:
    encoded = value.encode("ascii", "ignore")
    if len(encoded) > length:
        raise ValueError(f"{value!r} is longer than {length} bytes")
    return encoded.ljust(length, b"\x00")


def word_boundary_pad(data: bytearray) -> None:
    if len(data) % 4:
        data.extend(b"\x00" * (4 - (len(data) % 4)))


def _int_or_none(value: object | None) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    if text.startswith(("0x", "0X")):
        return int(text, 16)
    if text.startswith(("0b", "0B")):
        return int(text, 2)
    return int(text)


def _fixed_length_bytes(
    value: object | None, length: int, *, allow_empty: bool = False
) -> bytes | None:
    if value in (None, ""):
        return None if not allow_empty else b""
    if isinstance(value, (bytes, bytearray)):
        data = bytes(value)
    elif isinstance(value, int):
        data = value.to_bytes(length, "big")
    else:
        text = str(value).strip()
        if text.startswith(("0x", "0X")):
            text = text[2:]
        text = "".join(text.split()).replace(":", "")
        if len(text) % 2:
            text = "0" + text
        data = bytes.fromhex(text)
    if len(data) != length:
        raise ValueError(f"{value!r} is not {length} bytes long")
    return data


def _ascii_bytes(value: object | None, length: int) -> bytes | None:
    if value in (None, ""):
        return None
    if isinstance(value, (bytes, bytearray)):
        data = bytes(value)
    else:
        text = str(value)
        try:
            candidate = bytes.fromhex(text)
            if len(candidate) <= length:
                return candidate.ljust(length, b"\x00")
        except ValueError:
            pass
        data = text.encode("ascii")
    if len(data) > length:
        raise ValueError(f"{value!r} is longer than {length} bytes")
    return data.ljust(length, b"\x00")


def _variable_bytes(value: object | None) -> bytes:
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return bytes(value)
    text = str(value)
    if not text:
        return b""
    try:
        return bytes.fromhex(text)
    except ValueError:
        return text.encode("ascii")


def _h264_param_set_bytes(value: object | None) -> bytes:
    """Decode an sprop-parameter-sets / sprop-level-parameter-sets value.

    Per TR-10-15c §16, these MIB byte arrays carry the same base64 ASCII
    characters that appear in the SDP a=fmtp line (with optional ',' list
    separators). The JSON config holds that ASCII string verbatim.
    """
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    text = str(value)
    return text.encode("ascii") if text else b""


MEDIA_INFO_TYPES: dict[int, tuple[str, type["IPMXMediaInfoBlock"]]] = {}


def register_media_info_type(
    code: int, name: str, cls: type["IPMXMediaInfoBlock"]
) -> None:
    MEDIA_INFO_TYPES[code] = (name, cls)


class IPMXMediaInfoBlock:
    def to_bytes(self) -> bytes:
        raise NotImplementedError

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {}
        for f in dc_fields(self):  # type: ignore[arg-type]
            val = getattr(self, f.name)
            if isinstance(val, (bytes, bytearray)):
                result[f.name] = val.hex() if val else ""
            else:
                result[f.name] = val
        return result


@dataclass
class VideoMediaInfoBlock(IPMXMediaInfoBlock):
    """Represents a TR-10-2/TR-10-7 Media Info Block.

    The bit-packed layout follows TR-10-2 section 10 (Figure 1) so the parser
    and writer produce the same sequence of bytes.
    """

    sampling_format: str
    width: int
    height: int
    rate_numerator: int
    rate_denominator: int
    measured_pixel_clock: int
    htotal: int
    vtotal: int
    bit_depth: int
    floating_point: bool = False
    packing_mode: bool = False
    interlace: bool = False
    segmented: bool = False
    par_width: int = 1
    par_height: int = 1
    range_string: str = "NARROW"
    colorimetry: str = "BT709"
    tcs_string: str = "SDR"
    media_info_type: int = 0x0005

    def to_bytes(self) -> bytes:
        payload = bytearray()
        payload.extend(pad_string(self.sampling_format, 16))

        field_value = (
            (int(self.floating_point) & 0x1) << 31
            | (self.bit_depth & 0x7F) << 24
            | (int(self.packing_mode) & 0x1) << 23
            | (int(self.interlace) & 0x1) << 22
            | (int(self.segmented) & 0x1) << 21
            | (0 & 0x1F) << 16
            | (self.par_width & 0xFF) << 8
            | (self.par_height & 0xFF)
        )
        payload.extend(field_value.to_bytes(4, "big"))

        payload.extend(pad_string(self.range_string, 12))
        payload.extend(pad_string(self.colorimetry, 20))
        payload.extend(pad_string(self.tcs_string, 16))
        payload.extend(self.width.to_bytes(2, "big"))
        payload.extend(self.height.to_bytes(2, "big"))

        rate_field = (
            (self.rate_numerator & 0x3FFFFF) << 10
            | (self.rate_denominator & 0x3FF)
        )
        payload.extend(rate_field.to_bytes(4, "big"))
        payload.extend(self.measured_pixel_clock.to_bytes(8, "big"))
        payload.extend(self.htotal.to_bytes(2, "big"))
        payload.extend(self.vtotal.to_bytes(2, "big"))

        word_boundary_pad(payload)

        total_words = (4 + len(payload)) // 4
        header = bytearray()
        header.extend(self.media_info_type.to_bytes(2, "big"))
        header.extend((total_words - 1).to_bytes(2, "big"))
        return bytes(header + payload)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "VideoMediaInfoBlock":
        return cls(
            sampling_format=data["sampling_format"],  # type: ignore[arg-type]
            width=int(data["width"]),
            height=int(data["height"]),
            rate_numerator=int(data["rate_numerator"]),
            rate_denominator=int(data["rate_denominator"]),
            measured_pixel_clock=int(data["measured_pixel_clock"]),
            htotal=int(data["htotal"]),
            vtotal=int(data["vtotal"]),
            bit_depth=int(data["bit_depth"]),
            floating_point=bool(data.get("floating_point", False)),
            packing_mode=bool(data.get("packing_mode", False)),
            interlace=bool(data.get("interlace", False)),
            segmented=bool(data.get("segmented", False)),
            par_width=int(data.get("par_width", 1)),
            par_height=int(data.get("par_height", 1)),
            range_string=str(data.get("range_string", "NARROW")),
            colorimetry=str(data.get("colorimetry", "BT709")),
            tcs_string=str(data.get("tcs_string", "SDR")),
            media_info_type=int(data.get("media_info_type", 0x0005)),
        )


@dataclass
class H265MediaInfoBlock(IPMXMediaInfoBlock):
    """Media Info Block type 0x0009 (VSF TR-10-15b) with H.265-specific fields."""

    profile_space: int | None = None
    profile_id: int | None = None
    level_id: int | None = None
    tier_flag: int | None = None
    profile_compatibility_indicator: int | None = None
    interop_constraints: bytes | None = None
    sprop_max_don_diff: int | None = None
    tx_mode: bytes | None = None
    sprop_depack_buf_bytes: int | None = None
    sprop_depack_buf_nalus: int | None = None
    sprop_spatial_segmentation_idc: int | None = None
    sprop_sub_layer_id: int | None = None
    sprop_segmentation_id: int | None = None
    sprop_vps: bytes = b""
    sprop_sps: bytes = b""
    sprop_pps: bytes = b""
    extra_bytes: bytes = b""
    media_info_type: int = 0x0009

    FIELD_BITS = {
        "profile_space": 0,
        "profile_id": 1,
        "level_id": 2,
        "tier_flag": 3,
        "profile_compatibility_indicator": 4,
        "interop_constraints": 5,
        "sprop_max_don_diff": 6,
        "tx_mode": 7,
        "sprop_depack_buf_bytes": 8,
        "sprop_depack_buf_nalus": 9,
        "sprop_spatial_segmentation_idc": 10,
        "sprop_sub_layer_id": 11,
        "sprop_segmentation_id": 12,
        "sprop_vps": 13,
        "sprop_sps": 14,
        "sprop_pps": 15,
        "extra_bytes": 16,
    }

    def to_bytes(self) -> bytes:
        mask = 0
        if self.profile_space is not None:
            mask |= 1 << self.FIELD_BITS["profile_space"]
        if self.profile_id is not None:
            mask |= 1 << self.FIELD_BITS["profile_id"]
        if self.level_id is not None:
            mask |= 1 << self.FIELD_BITS["level_id"]
        if self.tier_flag is not None:
            mask |= 1 << self.FIELD_BITS["tier_flag"]
        if self.profile_compatibility_indicator is not None:
            mask |= 1 << self.FIELD_BITS["profile_compatibility_indicator"]
        if self.interop_constraints is not None:
            mask |= 1 << self.FIELD_BITS["interop_constraints"]
        if self.sprop_max_don_diff is not None:
            mask |= 1 << self.FIELD_BITS["sprop_max_don_diff"]
        if self.tx_mode is not None:
            mask |= 1 << self.FIELD_BITS["tx_mode"]
        if self.sprop_depack_buf_bytes is not None:
            mask |= 1 << self.FIELD_BITS["sprop_depack_buf_bytes"]
        if self.sprop_depack_buf_nalus is not None:
            mask |= 1 << self.FIELD_BITS["sprop_depack_buf_nalus"]
        if self.sprop_spatial_segmentation_idc is not None:
            mask |= 1 << self.FIELD_BITS["sprop_spatial_segmentation_idc"]
        if self.sprop_sub_layer_id is not None:
            mask |= 1 << self.FIELD_BITS["sprop_sub_layer_id"]
        if self.sprop_segmentation_id is not None:
            mask |= 1 << self.FIELD_BITS["sprop_segmentation_id"]
        if self.sprop_vps:
            mask |= 1 << self.FIELD_BITS["sprop_vps"]
        if self.sprop_sps:
            mask |= 1 << self.FIELD_BITS["sprop_sps"]
        if self.sprop_pps:
            mask |= 1 << self.FIELD_BITS["sprop_pps"]
        if self.extra_bytes:
            mask |= 1 << self.FIELD_BITS["extra_bytes"]

        payload = bytearray()
        payload.extend(mask.to_bytes(4, "big"))
        payload.extend((self.profile_space or 0).to_bytes(1, "big"))
        payload.extend((self.profile_id or 0).to_bytes(1, "big"))
        payload.extend((self.level_id or 0).to_bytes(1, "big"))
        payload.extend((self.tier_flag or 0).to_bytes(1, "big"))
        payload.extend(
            (self.profile_compatibility_indicator or 0).to_bytes(4, "big")
        )
        payload.extend(self.interop_constraints or b"\x00" * 6)
        payload.extend((self.sprop_max_don_diff or 0).to_bytes(2, "big"))
        tx_mode = self.tx_mode or b""
        payload.extend(tx_mode.ljust(4, b"\x00"))
        payload.extend((self.sprop_depack_buf_bytes or 0).to_bytes(4, "big"))
        payload.extend((self.sprop_depack_buf_nalus or 0).to_bytes(2, "big"))
        payload.extend((self.sprop_spatial_segmentation_idc or 0).to_bytes(2, "big"))
        payload.extend((self.sprop_sub_layer_id or 0).to_bytes(1, "big"))
        payload.extend((self.sprop_segmentation_id or 0).to_bytes(1, "big"))
        payload.extend(b"\x00\x00")

        sprop_vps_len = len(self.sprop_vps)
        sprop_sps_len = len(self.sprop_sps)
        sprop_pps_len = len(self.sprop_pps)
        extra_len = len(self.extra_bytes)
        for length in (sprop_vps_len, sprop_sps_len, sprop_pps_len, extra_len):
            if length > 0xFF:
                raise ValueError("sprop lengths must fit in one byte")
        payload.extend(sprop_vps_len.to_bytes(1, "big"))
        payload.extend(sprop_sps_len.to_bytes(1, "big"))
        payload.extend(sprop_pps_len.to_bytes(1, "big"))
        payload.extend(extra_len.to_bytes(1, "big"))
        payload.extend(self.sprop_vps)
        payload.extend(self.sprop_sps)
        payload.extend(self.sprop_pps)
        payload.extend(self.extra_bytes)

        word_boundary_pad(payload)

        total_words = (4 + len(payload)) // 4
        header = bytearray()
        header.extend(self.media_info_type.to_bytes(2, "big"))
        header.extend((total_words - 1).to_bytes(2, "big"))
        return bytes(header + payload)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "H265MediaInfoBlock":
        return cls(
            profile_space=_int_or_none(data.get("profile_space")),
            profile_id=_int_or_none(data.get("profile_id")),
            level_id=_int_or_none(data.get("level_id")),
            tier_flag=_int_or_none(data.get("tier_flag")),
            profile_compatibility_indicator=_int_or_none(
                data.get("profile_compatibility_indicator")
            ),
            interop_constraints=_fixed_length_bytes(
                data.get("interop_constraints"), 6
            ),
            sprop_max_don_diff=_int_or_none(data.get("sprop_max_don_diff")),
            tx_mode=_ascii_bytes(data.get("tx_mode"), 4),
            sprop_depack_buf_bytes=_int_or_none(
                data.get("sprop_depack_buf_bytes")
            ),
            sprop_depack_buf_nalus=_int_or_none(
                data.get("sprop_depack_buf_nalus")
            ),
            sprop_spatial_segmentation_idc=_int_or_none(
                data.get("sprop_spatial_segmentation_idc")
            ),
            sprop_sub_layer_id=_int_or_none(data.get("sprop_sub_layer_id")),
            sprop_segmentation_id=_int_or_none(
                data.get("sprop_segmentation_id")
            ),
            sprop_vps=_variable_bytes(data.get("sprop_vps")),
            sprop_sps=_variable_bytes(data.get("sprop_sps")),
            sprop_pps=_variable_bytes(data.get("sprop_pps")),
            extra_bytes=_variable_bytes(data.get("extra_bytes")),
            media_info_type=int(data.get("media_info_type", 0x0009)),
        )


@dataclass
class H264MediaInfoBlock(IPMXMediaInfoBlock):
    """Media Info Block type 0x000A (VSF TR-10-15c) with H.264-specific fields."""

    profile_level_id: bytes | None = None
    packetization_mode: int | None = None
    sprop_max_don_diff: int | None = None
    sprop_interleaving_depth: int | None = None
    sprop_deint_buf_req: int | None = None
    sprop_init_buf_time: int | None = None
    sprop_parameter_sets: bytes = b""
    sprop_level_parameter_sets: bytes = b""
    extra_bytes: bytes = b""
    media_info_type: int = 0x000A

    FIELD_BITS = {
        "profile_level_id": 0,
        "packetization_mode": 1,
        "sprop_max_don_diff": 2,
        "sprop_interleaving_depth": 3,
        "sprop_deint_buf_req": 4,
        "sprop_init_buf_time": 5,
        "sprop_parameter_sets": 6,
        "sprop_level_parameter_sets": 7,
        "extra_bytes": 8,
    }

    def to_bytes(self) -> bytes:
        mask = 0
        if self.profile_level_id:
            mask |= 1 << self.FIELD_BITS["profile_level_id"]
        if self.packetization_mode is not None:
            mask |= 1 << self.FIELD_BITS["packetization_mode"]
        if self.sprop_max_don_diff is not None:
            mask |= 1 << self.FIELD_BITS["sprop_max_don_diff"]
        if self.sprop_interleaving_depth is not None:
            mask |= 1 << self.FIELD_BITS["sprop_interleaving_depth"]
        if self.sprop_deint_buf_req is not None:
            mask |= 1 << self.FIELD_BITS["sprop_deint_buf_req"]
        if self.sprop_init_buf_time is not None:
            mask |= 1 << self.FIELD_BITS["sprop_init_buf_time"]
        if self.sprop_parameter_sets:
            mask |= 1 << self.FIELD_BITS["sprop_parameter_sets"]
        if self.sprop_level_parameter_sets:
            mask |= 1 << self.FIELD_BITS["sprop_level_parameter_sets"]
        if self.extra_bytes:
            mask |= 1 << self.FIELD_BITS["extra_bytes"]

        payload = bytearray()
        payload.extend(mask.to_bytes(4, "big"))
        profile_level_id = self.profile_level_id or b"\x00" * 3
        payload.extend(profile_level_id.ljust(3, b"\x00"))
        payload.extend((self.packetization_mode or 0).to_bytes(1, "big"))
        payload.extend((self.sprop_max_don_diff or 0).to_bytes(2, "big"))
        payload.extend((self.sprop_interleaving_depth or 0).to_bytes(2, "big"))
        payload.extend((self.sprop_deint_buf_req or 0).to_bytes(4, "big"))
        payload.extend((self.sprop_init_buf_time or 0).to_bytes(4, "big"))

        param_sets_len = len(self.sprop_parameter_sets)
        level_sets_len = len(self.sprop_level_parameter_sets)
        extra_len = len(self.extra_bytes)
        for length in (param_sets_len, level_sets_len, extra_len):
            if length > 0xFF:
                raise ValueError("sprop lengths must fit in one byte")
        payload.extend(param_sets_len.to_bytes(1, "big"))
        payload.extend(level_sets_len.to_bytes(1, "big"))
        payload.extend(extra_len.to_bytes(1, "big"))
        payload.extend(b"\x00")
        payload.extend(self.sprop_parameter_sets)
        payload.extend(self.sprop_level_parameter_sets)
        payload.extend(self.extra_bytes)

        word_boundary_pad(payload)

        total_words = (4 + len(payload)) // 4
        header = bytearray()
        header.extend(self.media_info_type.to_bytes(2, "big"))
        header.extend((total_words - 1).to_bytes(2, "big"))
        return bytes(header + payload)

    def to_dict(self) -> dict[str, object]:
        # TR-10-15c §16: sprop_parameter_sets and sprop_level_parameter_sets
        # are base64 ASCII characters as represented in the SDP transport file
        # (with optional ',' list separators). Keep them human-readable on
        # export rather than hex-encoding the ASCII bytes.
        result = super().to_dict()
        for key in ("sprop_parameter_sets", "sprop_level_parameter_sets"):
            val = getattr(self, key)
            result[key] = val.decode("ascii") if val else ""
        return result

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "H264MediaInfoBlock":
        return cls(
            profile_level_id=_fixed_length_bytes(
                data.get("profile_level_id"), 3
            ),
            packetization_mode=_int_or_none(data.get("packetization_mode")),
            sprop_max_don_diff=_int_or_none(data.get("sprop_max_don_diff")),
            sprop_interleaving_depth=_int_or_none(
                data.get("sprop_interleaving_depth")
            ),
            sprop_deint_buf_req=_int_or_none(data.get("sprop_deint_buf_req")),
            sprop_init_buf_time=_int_or_none(data.get("sprop_init_buf_time")),
            sprop_parameter_sets=_h264_param_set_bytes(
                data.get("sprop_parameter_sets")
            ),
            sprop_level_parameter_sets=_h264_param_set_bytes(
                data.get("sprop_level_parameter_sets")
            ),
            extra_bytes=_variable_bytes(data.get("extra_bytes")),
            media_info_type=int(data.get("media_info_type", 0x000A)),
        )

register_media_info_type(
    0x0001, "Uncompressed video (TR-10-2)", VideoMediaInfoBlock
)
register_media_info_type(
    0x0005, "Compressed Video (TR-10-7)", VideoMediaInfoBlock
)
register_media_info_type(
    0x0009, "H.265 compressed video (TR-10-15b)", H265MediaInfoBlock
)
register_media_info_type(
    0x000A, "H.264 compressed video (TR-10-15c)", H264MediaInfoBlock
)
register_media_info_type(
    0x0003, "ConstantSize Compressed Video (TR-10-11)", VideoMediaInfoBlock
)

@dataclass
class AudioMediaInfoBlock(IPMXMediaInfoBlock):
    """Shared audio MIB payload layout for PCM and AES3 transparent transport.

    TR-10-12 section 10 states that AES3 transparent transport uses media info
    type 0x0004 with the same payload structure as the PCM audio MIB.
    """

    sampling_rate: int
    sample_size: int
    channel_count: int
    packet_time: int
    measured_sample_rate: int
    channel_order: str
    media_info_type: int = 0x0002

    def to_bytes(self) -> bytes:
        channel_bytes = self.channel_order.encode("ascii")
        padding = (-len(channel_bytes)) % 4
        channel_bytes_padded = channel_bytes + (b"\x00" * padding)
        channel_words = len(channel_bytes_padded) // 4

        payload = bytearray()
        payload.extend(self.sampling_rate.to_bytes(4, "big"))
        payload.append(self.sample_size & 0xFF)
        payload.append(self.channel_count & 0xFF)
        payload.extend(self.packet_time.to_bytes(2, "big"))
        payload.extend(self.measured_sample_rate.to_bytes(4, "big"))
        payload.extend(channel_words.to_bytes(4, "big"))
        payload.extend(channel_bytes_padded)

        word_boundary_pad(payload)

        total_words = (4 + len(payload)) // 4
        header = bytearray()
        header.extend(self.media_info_type.to_bytes(2, "big"))
        header.extend((total_words - 1).to_bytes(2, "big"))
        return bytes(header + payload)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "AudioMediaInfoBlock":
        return cls(
            sampling_rate=int(data["sampling_rate"]),
            sample_size=int(data["sample_size"]),
            channel_count=int(data["channel_count"]),
            packet_time=int(data["packet_time"]),
            measured_sample_rate=int(data["measured_sample_rate"]),
            channel_order=str(data["channel_order"]),
            media_info_type=int(data.get("media_info_type", 0x0002)),
        )


register_media_info_type(
    0x0002, "PCM audio (TR-10-3)", AudioMediaInfoBlock
)
register_media_info_type(
    0x0004, "AES3 transparent audio (TR-10-12)", AudioMediaInfoBlock
)


@dataclass
class JXSVMediaInfoBlock(IPMXMediaInfoBlock):
    """Media Info Block type 0x0008 (VSF TR-10-15 Part 1 §9) for JPEG XS streams."""

    transmode: int = 1
    packetmode: int = 0
    ppih: int = 0
    plev: int = 0
    media_info_type: int = 0x0008

    def to_bytes(self) -> bytes:
        payload = bytearray()
        dw1 = (
            ((self.transmode & 0x1) << 31)
            | ((self.packetmode & 0x1) << 30)
            | (self.ppih & 0xFFFF)
        )
        dw2 = (self.plev & 0xFFFF) << 16
        payload.extend(dw1.to_bytes(4, "big"))
        payload.extend(dw2.to_bytes(4, "big"))
        word_boundary_pad(payload)
        total_words = (4 + len(payload)) // 4
        header = bytearray()
        header.extend(self.media_info_type.to_bytes(2, "big"))
        header.extend((total_words - 1).to_bytes(2, "big"))
        return bytes(header + payload)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "JXSVMediaInfoBlock":
        return cls(
            transmode=int(data.get("transmode", 1)),
            packetmode=int(data.get("packetmode", 0)),
            ppih=int(data.get("ppih", 0)),
            plev=int(data.get("plev", 0)),
            media_info_type=int(data.get("media_info_type", 0x0008)),
        )


register_media_info_type(
    0x0008, "JPEG XS (TR-10-15a)", JXSVMediaInfoBlock
)


@dataclass
class HKEPMediaInfoBlock(IPMXMediaInfoBlock):
    """Media Info Block type 0x0010 for HDCP Key Exchange Protocol (HKEP).

    Layout (1 dw payload):
      hkep_version (8b) | rsvd1 (4b) | f_id (4b) | rsvd2 (4b) | s_id (4b) | rsvd3 (8b)
    """

    hkep_version: int = 0
    f_id: int = 0
    s_id: int = 0
    media_info_type: int = 0x0010

    def to_bytes(self) -> bytes:
        payload = bytearray()
        field = (
            ((self.hkep_version & 0xFF) << 24)
            | ((self.f_id & 0xF) << 16)
            | ((self.s_id & 0xF) << 8)
        )
        payload.extend(field.to_bytes(4, "big"))

        total_words = (4 + len(payload)) // 4
        header = bytearray()
        header.extend(self.media_info_type.to_bytes(2, "big"))
        header.extend((total_words - 1).to_bytes(2, "big"))
        return bytes(header + payload)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "HKEPMediaInfoBlock":
        return cls(
            hkep_version=int(data.get("hkep_version", 0)),
            f_id=int(data.get("f_id", 0)),
            s_id=int(data.get("s_id", 0)),
            media_info_type=int(data.get("media_info_type", 0x0010)),
        )


register_media_info_type(
    0x0010, "HKEP (HDCP Key Exchange Protocol)", HKEPMediaInfoBlock
)


@dataclass
class PEPMediaInfoBlock(IPMXMediaInfoBlock):
    """Media Info Block type 0x0011 for Privacy Encryption Protocol (PEP).

    Layout (1 dw payload):
      privacy_version (8b) | rsvd1 (4b) | f_id (4b) | rsvd2 (4b) | s_id (4b) | rsvd3 (8b)
    """

    privacy_version: int = 0
    f_id: int = 0
    s_id: int = 0
    media_info_type: int = 0x0011

    def to_bytes(self) -> bytes:
        payload = bytearray()
        field = (
            ((self.privacy_version & 0xFF) << 24)
            | ((self.f_id & 0xF) << 16)
            | ((self.s_id & 0xF) << 8)
        )
        payload.extend(field.to_bytes(4, "big"))

        total_words = (4 + len(payload)) // 4
        header = bytearray()
        header.extend(self.media_info_type.to_bytes(2, "big"))
        header.extend((total_words - 1).to_bytes(2, "big"))
        return bytes(header + payload)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "PEPMediaInfoBlock":
        return cls(
            privacy_version=int(data.get("privacy_version", 0)),
            f_id=int(data.get("f_id", 0)),
            s_id=int(data.get("s_id", 0)),
            media_info_type=int(data.get("media_info_type", 0x0011)),
        )


register_media_info_type(
    0x0011, "PEP (Privacy Encryption Protocol)", PEPMediaInfoBlock
)


def build_media_info_block(data: dict[str, object]) -> IPMXMediaInfoBlock:
    media_info_type = int(data.get("media_info_type", 0x0005))
    entry = MEDIA_INFO_TYPES.get(media_info_type)
    if entry is None:
        raise ValueError(
            f"unsupported media info type 0x{media_info_type:04x}; "
            f"available types: {', '.join(f'0x{code:04x}' for code in MEDIA_INFO_TYPES)}"
        )
    _, cls = entry
    return cls.from_dict(data)  # type: ignore[arg-type]


def _default_video_media_info() -> dict[str, object]:
    return {
        "media_info_type": 0x0005,
        "sampling_format": "YCbCr-4:2:2",
        "width": 1920,
        "height": 1080,
        "rate_numerator": 60000,
        "rate_denominator": 1001,
        "measured_pixel_clock": 148_550_104,
        "htotal": 2200,
        "vtotal": 1125,
        "bit_depth": 10,
        "floating_point": False,
        "packing_mode": True,
        "interlace": False,
        "segmented": False,
        "par_width": 1,
        "par_height": 1,
    }


@dataclass
class IPMXInfoBlock:
    """Encapsulates the IPMX Info Block extension (tag = 0x5831)."""

    version: int
    ts_refclk: str
    mediaclk: str
    media_info_blocks: Sequence[IPMXMediaInfoBlock]

    def to_bytes(self) -> bytes:
        body = bytearray()
        body.extend(self.version.to_bytes(1, "big"))
        body.extend(b"\x00" * 3)  # reserved
        body.extend(pad_string(self.ts_refclk, 64))
        body.extend(pad_string(self.mediaclk, 12))
        for block in self.media_info_blocks:
            body.extend(block.to_bytes())

        word_boundary_pad(body)
        total_words = (4 + len(body)) // 4
        header = bytearray()
        header.extend((0x5831).to_bytes(2, "big"))
        header.extend((total_words - 1).to_bytes(2, "big"))
        return bytes(header + body)

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "ts_refclk": self.ts_refclk,
            "mediaclk": self.mediaclk,
            "media_info_blocks": [b.to_dict() for b in self.media_info_blocks],
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "IPMXInfoBlock":
        blocks_data = data.get("media_info_blocks", [])
        return cls(
            version=int(data.get("version", 1)),
            ts_refclk=str(data.get("ts_refclk", "")),
            mediaclk=str(data.get("mediaclk", "")),
            media_info_blocks=[
                build_media_info_block(block) for block in blocks_data  # type: ignore[arg-type]
            ],
        )


@dataclass
class ParsedMediaInfoBlock:
    media_info_type: int
    length_words: int
    payload: bytes
    decoded: dict[str, object] | None = None


@dataclass
class ParsedIPMXInfoBlock:
    tag: int
    length_words: int
    version: int
    reserved: int
    ts_refclk: str
    mediaclk: str
    media_blocks: list[ParsedMediaInfoBlock]
    raw_bytes: bytes = b""


@dataclass
class ParsedSenderReport:
    ssrc: int
    ntp_seconds: int
    ntp_fraction: int
    rtp_timestamp: int
    packet_count: int
    octet_count: int
    info_block: ParsedIPMXInfoBlock | None
    raw_blocks: list[ParsedMediaInfoBlock]
    reception_report_count: int = 0


@dataclass
class SenderReport:
    """Represents the RTCP Sender Report as described in TR-10-7 / RFC 3550."""

    ssrc: int
    ntp_seconds: int
    ntp_fraction: int
    rtp_timestamp: int
    packet_count: int
    octet_count: int
    info_block: IPMXInfoBlock
    version: int = 2
    padding: int = 0
    reception_count: int = 0
    packet_type: int = 200

    def to_bytes(self) -> bytes:
        header = bytearray(4)
        header[0] = (self.version << 6) | (self.padding << 5) | (
            self.reception_count & 0x1F
        )
        header[1] = self.packet_type
        header[2:4] = b"\x00\x00"

        payload = bytearray()
        payload.extend(self.ssrc.to_bytes(4, "big"))
        payload.extend(self.ntp_seconds.to_bytes(4, "big"))
        payload.extend(self.ntp_fraction.to_bytes(4, "big"))
        payload.extend(self.rtp_timestamp.to_bytes(4, "big"))
        payload.extend(self.packet_count.to_bytes(4, "big"))
        payload.extend(self.octet_count.to_bytes(4, "big"))
        payload.extend(self.info_block.to_bytes())

        total_words = (len(header) + len(payload)) // 4
        header[2:4] = (total_words - 1).to_bytes(2, "big")
        return bytes(header + payload)

    def write(self, fh: BinaryIO) -> None:
        fh.write(self.to_bytes())

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "SenderReport":
        info_block = IPMXInfoBlock.from_dict(  # type: ignore[arg-type]
            data["info_block"]  # type: ignore[index]
        )
        return cls(
            ssrc=int(data["ssrc"]),
            ntp_seconds=int(data["ntp_seconds"]),
            ntp_fraction=int(data["ntp_fraction"]),
            rtp_timestamp=int(data["rtp_timestamp"]),
            packet_count=int(data["packet_count"]),
            octet_count=int(data["octet_count"]),
            info_block=info_block,
        )


def iter_rtcp_packets(payload: bytes) -> Iterator[bytes]:
    offset = 0
    while offset + 4 <= len(payload):
        v_p_count = payload[offset]
        version = v_p_count >> 6
        if version != 2:
            break
        length_words = int.from_bytes(payload[offset + 2 : offset + 4], "big")
        packet_len = (length_words + 1) * 4
        if packet_len <= 0 or offset + packet_len > len(payload):
            break
        yield payload[offset : offset + packet_len]
        offset += packet_len


# ---------------------------------------------------------------------------
# Media Info Block decoders — convert raw payload bytes to a dict of fields
# ---------------------------------------------------------------------------

def _decode_video_media_info(payload: bytes) -> dict[str, object] | None:
    """Decode types 0x0001, 0x0003, 0x0005 (VideoMediaInfoBlock layout)."""
    if len(payload) < 76:
        return None
    sampling_format = payload[0:16].split(b"\x00", 1)[0].decode("ascii", "ignore")
    field_value = int.from_bytes(payload[16:20], "big")
    floating_point = bool((field_value >> 31) & 0x1)
    bit_depth = (field_value >> 24) & 0x7F
    packing_mode = bool((field_value >> 23) & 0x1)
    interlace = bool((field_value >> 22) & 0x1)
    segmented = bool((field_value >> 21) & 0x1)
    par_width = (field_value >> 8) & 0xFF
    par_height = field_value & 0xFF
    range_str = payload[20:32].split(b"\x00", 1)[0].decode("ascii", "ignore")
    colorimetry = payload[32:52].split(b"\x00", 1)[0].decode("ascii", "ignore")
    tcs = payload[52:68].split(b"\x00", 1)[0].decode("ascii", "ignore")
    width = int.from_bytes(payload[68:70], "big")
    height = int.from_bytes(payload[70:72], "big")
    rate_field = int.from_bytes(payload[72:76], "big")
    rate_numerator = (rate_field >> 10) & 0x3FFFFF
    rate_denominator = rate_field & 0x3FF

    result: dict[str, object] = {
        "sampling_format": sampling_format,
        "width": width,
        "height": height,
        "rate_numerator": rate_numerator,
        "rate_denominator": rate_denominator,
        "bit_depth": bit_depth,
        "floating_point": floating_point,
        "packing_mode": packing_mode,
        "interlace": interlace,
        "segmented": segmented,
        "par_width": par_width,
        "par_height": par_height,
        "range": range_str,
        "colorimetry": colorimetry,
        "tcs": tcs,
    }

    if len(payload) >= 88:
        measured_pixel_clock = int.from_bytes(payload[76:84], "big")
        htotal = int.from_bytes(payload[84:86], "big")
        vtotal = int.from_bytes(payload[86:88], "big")
        result["measured_pixel_clock"] = measured_pixel_clock
        result["htotal"] = htotal
        result["vtotal"] = vtotal

    return result


def _decode_audio_media_info(payload: bytes) -> dict[str, object] | None:
    """Decode types 0x0002 and 0x0004 (AudioMediaInfoBlock layout)."""
    if len(payload) < 16:
        return None
    sampling_rate = int.from_bytes(payload[0:4], "big")
    sample_size = payload[4]
    channel_count = payload[5]
    packet_time = int.from_bytes(payload[6:8], "big")
    measured_sample_rate = int.from_bytes(payload[8:12], "big")
    channel_words = int.from_bytes(payload[12:16], "big")
    channel_bytes = payload[16 : 16 + channel_words * 4]
    channel_order = channel_bytes.split(b"\x00", 1)[0].decode("ascii", "ignore")
    return {
        "sampling_rate": sampling_rate,
        "sample_size": sample_size,
        "channel_count": channel_count,
        "packet_time": packet_time,
        "measured_sample_rate": measured_sample_rate,
        "channel_order": channel_order,
    }


def _decode_jxsv_media_info(payload: bytes) -> dict[str, object] | None:
    """Decode type 0x0008 (JPEG XS Media Info Block per VSF TR-10-15 Part 1 §9)."""
    if len(payload) < 8:
        return None
    dw1 = int.from_bytes(payload[0:4], "big")
    dw2 = int.from_bytes(payload[4:8], "big")
    transmode = (dw1 >> 31) & 0x1
    packetmode = (dw1 >> 30) & 0x1
    ppih = dw1 & 0xFFFF
    plev = (dw2 >> 16) & 0xFFFF
    return {
        "transmode": transmode,
        "packetmode": packetmode,
        "ppih": ppih,
        "ppih_hex": f"0x{ppih:04x}",
        "plev": plev,
        "plev_hex": f"0x{plev:04x}",
    }


def _decode_hkep_media_info(payload: bytes) -> dict[str, object] | None:
    """Decode type 0x0010 (HKEP Media Info Block)."""
    if len(payload) < 4:
        return None
    field = int.from_bytes(payload[0:4], "big")
    return {
        "hkep_version": (field >> 24) & 0xFF,
        "f_id": (field >> 16) & 0xF,
        "s_id": (field >> 8) & 0xF,
    }


def _decode_pep_media_info(payload: bytes) -> dict[str, object] | None:
    """Decode type 0x0011 (PEP Media Info Block)."""
    if len(payload) < 4:
        return None
    field = int.from_bytes(payload[0:4], "big")
    return {
        "privacy_version": (field >> 24) & 0xFF,
        "f_id": (field >> 16) & 0xF,
        "s_id": (field >> 8) & 0xF,
    }


MEDIA_INFO_DECODERS: dict[int, object] = {
    0x0001: _decode_video_media_info,
    0x0003: _decode_video_media_info,
    0x0005: _decode_video_media_info,
    0x0002: _decode_audio_media_info,
    0x0004: _decode_audio_media_info,
    0x0008: _decode_jxsv_media_info,
    0x0010: _decode_hkep_media_info,
    0x0011: _decode_pep_media_info,
}


def decode_media_info_block(
    media_info_type: int, payload: bytes
) -> dict[str, object] | None:
    """Return decoded fields for a Media Info Block, or *None* if unknown."""
    decoder = MEDIA_INFO_DECODERS.get(media_info_type)
    if decoder is None:
        return None
    return decoder(payload)  # type: ignore[operator]


def parse_ipmx_info_block(data: bytes) -> ParsedIPMXInfoBlock | None:
    if len(data) < 4:
        return None
    tag = int.from_bytes(data[0:2], "big")
    if tag != 0x5831:
        return None
    length_words = int.from_bytes(data[2:4], "big")
    total_bytes = (length_words + 1) * 4
    if total_bytes > len(data):
        return None
    body = data[4:total_bytes]
    if len(body) < 80:
        return None
    version = body[0]
    reserved = int.from_bytes(body[1:4], "big")
    ts_refclk = body[4:68].split(b"\x00", 1)[0].decode("ascii", "ignore")
    mediaclk = body[68:80].split(b"\x00", 1)[0].decode("ascii", "ignore")
    offset = 80
    blocks: list[ParsedMediaInfoBlock] = []
    while offset + 4 <= len(body):
        block_type = int.from_bytes(body[offset : offset + 2], "big")
        block_len_words = int.from_bytes(body[offset + 2 : offset + 4], "big")
        block_total = (block_len_words + 1) * 4
        if block_total <= 0 or offset + block_total > len(body):
            break
        payload = body[offset + 4 : offset + block_total]
        decoded = decode_media_info_block(block_type, payload)
        blocks.append(
            ParsedMediaInfoBlock(
                media_info_type=block_type,
                length_words=block_len_words,
                payload=payload,
                decoded=decoded,
            )
        )
        offset += block_total
    return ParsedIPMXInfoBlock(
        tag=tag,
        length_words=length_words,
        version=version,
        reserved=reserved,
        ts_refclk=ts_refclk,
        mediaclk=mediaclk,
        media_blocks=blocks,
        raw_bytes=data[:total_bytes],
    )


def parse_rtcp_sender_report(packet: bytes) -> ParsedSenderReport | None:
    if len(packet) < 28:
        return None
    v_p_count = packet[0]
    packet_type = packet[1]
    if packet_type != 200:
        return None
    rc = v_p_count & 0x1F
    offset = 4
    if len(packet) < offset + 20:
        return None
    ssrc = int.from_bytes(packet[offset : offset + 4], "big")
    ntp_sec = int.from_bytes(packet[offset + 4 : offset + 8], "big")
    ntp_frac = int.from_bytes(packet[offset + 8 : offset + 12], "big")
    rtp_ts = int.from_bytes(packet[offset + 12 : offset + 16], "big")
    packet_count = int.from_bytes(packet[offset + 16 : offset + 20], "big")
    octet_count = int.from_bytes(packet[offset + 20 : offset + 24], "big")
    offset = 4 + 24 + (rc * 24)
    ipmx_info = None
    raw_blocks: list[ParsedMediaInfoBlock] = []
    if offset + 4 <= len(packet):
        ipmx_info = parse_ipmx_info_block(packet[offset:])
        if ipmx_info:
            raw_blocks = ipmx_info.media_blocks
    return ParsedSenderReport(
        ssrc=ssrc,
        ntp_seconds=ntp_sec,
        ntp_fraction=ntp_frac,
        rtp_timestamp=rtp_ts,
        packet_count=packet_count,
        octet_count=octet_count,
        info_block=ipmx_info,
        raw_blocks=raw_blocks,
        reception_report_count=rc,
    )


def load_config(path: Path | None, media: str) -> dict[str, object]:
    if path is None:
        if media in {"pcm", "aes3"}:
            return {
                "ssrc": 2345,
                "ntp_seconds": 1666377592,
                "ntp_fraction": 777737730,
                "rtp_timestamp": 4070650991,
                "packet_count": 9000560,
                "octet_count": 432026880,
                "info_block": {
                    "version": 3,
                    "ts_refclk": "localmac=00-20-FC-32-2F-40",
                    "mediaclk": "sender",
                    "media_info_blocks": [
                        {
                            "media_info_type": 0x0004 if media == "aes3" else 0x0002,
                            "sampling_rate": 48000,
                            "sample_size": 24,
                            "channel_count": 8,
                            "packet_time": 125,
                            "measured_sample_rate": 47952,
                            "channel_order": "SMPTE2110.(U08)",
                        }
                    ],
                },
            }

        media_blocks = [_default_video_media_info()]
        if media == "h265":
            media_blocks.append(
                {
                    "media_info_type": 0x0009,
                    "profile_space": 0,
                    "profile_id": 4,
                    "level_id": 90,
                    "tier_flag": 0,
                    "profile_compatibility_indicator": "00000010",
                    "interop_constraints": "BD0800000000",
                    "sprop_max_don_diff": 0,
                    "tx_mode": "SRST",
                    "sprop_depack_buf_bytes": 0,
                    "sprop_depack_buf_nalus": 0,
                    "sprop_spatial_segmentation_idc": 0,
                    "sprop_sub_layer_id": 0,
                    "sprop_segmentation_id": 0,
                }
            )
        elif media == "h264":
            media_blocks.append(
                {
                    "media_info_type": 0x000A,
                    "profile_level_id": "7A0028",
                    "packetization_mode": 1,
                    "sprop_max_don_diff": 0,
                    "sprop_interleaving_depth": 0,
                    "sprop_deint_buf_req": 0,
                    "sprop_init_buf_time": 0,
                }
            )
        elif media == "jxsv":
            media_blocks.append(
                {
                    "media_info_type": 0x0008,
                    "transmode": 1,
                    "packetmode": 0,
                    "ppih": 0x1500,
                    "plev": 0x2040,
                }
            )

        return {
            "ssrc": 3254,
            "ntp_seconds": 1665165600,
            "ntp_fraction": 262167158,
            "rtp_timestamp": 610164507,
            "packet_count": 0,
            "octet_count": 0,
            "info_block": {
                "version": 1,
                "ts_refclk": "localmac=00-20-FC-32-2F-40",
                "mediaclk": "sender",
                "media_info_blocks": media_blocks,
            },
        }
    with path.open() as fh:
        return json.load(fh)


def print_media_info_types() -> None:
    """Print the supported media info block types and their base structures."""
    for code, (description, cls) in sorted(MEDIA_INFO_TYPES.items()):
        print(f"0x{code:04x}: {description} (structure: {cls.__name__})")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build an IPMX TR-10-7 RTCP Sender Report and emit it as binary."
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="JSON file describing report fields (defaults to TR-10-2 example).",
    )
    parser.add_argument(
        "--media",
        choices=["video", "pcm", "aes3", "h265", "h264", "jxsv"],
        default="video",
        help="Built-in example to emit when no config is provided (h264/h265 append codec-specific IPMX blocks).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("tmp") / "sender_report.bin",
        help="Path to the binary RTCP packet that will be written.",
    )
    parser.add_argument(
        "--show-hex",
        action="store_true",
        help="Print the serialized packet as hex after writing.",
    )
    parser.add_argument(
        "--list-types",
        action="store_true",
        help="List the supported media info block types and exit.",
    )
    args = parser.parse_args()

    if args.list_types:
        print_media_info_types()
        return 0

    config = load_config(args.config, args.media)
    report = SenderReport.from_dict(config)
    data = report.to_bytes()
    args.output.write_bytes(data)
    print(f"Saved {len(data)} bytes to {args.output}")
    if args.show_hex:
        print(data.hex())
    return 0


if __name__ == "__main__":
    sys.exit(main())
