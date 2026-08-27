#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2025, Matrox Graphics Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions, and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions, and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""SDP to CCF Capabilities Converter

This module provides functionality to convert SDP (Session Description Protocol)
files into CCF (Constraint-Capability Framework) capabilities using the MatroxSdp
parser and MatroxCCF framework.
"""

from typing import Optional, List, Dict
from fractions import Fraction
from .MatroxSdp import (
    MatroxSdp, MediaDescriptor, MatroxSdpEnums, get_aac_profile_level_from_sdp,
    get_h264_profile_level_from_sdp, get_h265_profile_level_from_sdp
)
from .MatroxCCF import (
    Caps, CapSet, Capability, RangeValue, RangeType,
    FormatVideo, FormatAudio, FormatData, FormatMux,
    CapFormatMediaType, CapFormatGrainRate, CapFormatFrameWidth, CapFormatFrameHeight,
    CapFormatInterlaceMode, CapFormatColorspace, CapFormatTransferCharacteristic,
    CapFormatColorSampling, CapFormatComponentDepth, CapFormatChannelCount,
    CapFormatSampleRate, CapFormatSampleDepth, CapFormatBitRate, CapFormatProfile,
    CapFormatLevel, CapFormatSublevel, CapTransportBitRate,
    CapTransportPacketTime, CapTransportMaxPacketTime, CapTransport_ST2110_21_SenderType,
    CapTransportPacketTransmissionMode, CapTransportParameterSetsFlowMode,
    CapTransportParameterSetsTransportMode, CapTransportChannelOrder,
    CapTransportHkep, CapTransportPrivacy, CapTransportClockRefType,
    CapTransportInfoBlock, CapTransportSynchronousMedia
)


class SdpToCapabilitiesConverter:
    """Converts SDP files to CCF Capabilities"""

    def __init__(self):
        self.sdp = MatroxSdp()

    def convert_file(self, sdp_file_path: str, mux: bool = False) -> Caps:
        """
        Convert an SDP file to CCF Capabilities

        Args:
            sdp_file_path: Path to the SDP file

        Returns:
            Caps: CCF Capabilities structure
        """
        with open(sdp_file_path, 'r') as f:
            sdp_content = f.read()

        return self.convert_string(sdp_content, mux)

    def convert_string(self, sdp_content: str, mux: bool = False) -> Caps:
        """
        Convert SDP content string to CCF Capabilities

        Args:
            sdp_content: SDP content as string

        Returns:
            Caps: CCF Capabilities structure
        """
        # Parse SDP
        error = self.sdp.decode(sdp_content)
        if error:
            raise ValueError(f"SDP parsing error: {error}")

        # Convert to capabilities
        return self._convert_sdp_to_caps(mux)

    def _convert_sdp_to_caps(self, mux: bool = False) -> Caps:
        """
        Convert parsed SDP to CCF Capabilities

        Returns:
            Caps: CCF Capabilities structure
        """
        capsets: List[CapSet] = []

        # Handle primary media
        if self.sdp.primary_media:
            primary_capset = self._convert_media_to_capset(
                self.sdp.primary_media,
                "SDP",
                preference=100
            )

            # Handle secondary media (redundancy) - verify it's identical to primary
            if (self.sdp.secondary_media and
                self.sdp.has_group_attribute and
                    self.sdp.secondary_media != self.sdp.primary_media):

                secondary_capset = self._convert_media_to_capset(
                    self.sdp.secondary_media,
                    "SDP_Verification",
                    preference=100
                )

                # Verify capabilities are identical
                if not self._verify_capabilities_identical(primary_capset, secondary_capset):
                    raise ValueError(
                        "Secondary media capabilities must be identical to primary media for redundancy. "
                        "Found differences between primary and secondary streams."
                    )

                # Add redundancy metadata to primary capset
                primary_capset.label = "Primary (with redundancy)"

            capsets.append(primary_capset)

        return Caps(capsets=capsets)

    def _verify_capabilities_identical(self, primary_capset: CapSet, secondary_capset: CapSet) -> bool:
        """
        Verify that two CapSets have identical capabilities (for redundancy verification)

        Args:
            primary_capset: Primary media CapSet
            secondary_capset: Secondary media CapSet

        Returns:
            bool: True if capabilities are identical, False otherwise
        """
        # Check if they have the same capability parameter names
        primary_params = set(primary_capset.caps.keys())
        secondary_params = set(secondary_capset.caps.keys())

        if primary_params != secondary_params:
            return False

        # Check if each capability has the same value
        for param_name in primary_params:
            primary_cap = primary_capset.caps[param_name]
            secondary_cap = secondary_capset.caps[param_name]

            # Compare capability values
            if (primary_cap.value.infinite != secondary_cap.value.infinite or
                primary_cap.value.empty != secondary_cap.value.empty or
                primary_cap.value.type != secondary_cap.value.type or
                primary_cap.value.min != secondary_cap.value.min or
                primary_cap.value.max != secondary_cap.value.max or
                    primary_cap.value.enumerated != secondary_cap.value.enumerated):
                return False

        return True

    def _convert_media_to_capset(self, media: MediaDescriptor, label: str, preference: int = 100,
                                 mux: bool = False) -> CapSet:
        """
        Convert a MediaDescriptor to a CapSet

        Args:
            media: MediaDescriptor from SDP
            label: Label for the CapSet
            preference: Preference value for the CapSet

        Returns:
            CapSet: Converted capability set
        """
        capabilities: Dict[str, Capability] = {}
        format_type = self._determine_format_type(media)

        # Media type capability
        media_type = self._get_media_type_from_format(format_type, media, mux)

        capabilities[CapFormatMediaType] = Capability(
            CapFormatMediaType,
            RangeValue(values=(media_type,), type=RangeType.STRING)
        )

        # Format-specific capabilities
        if format_type == FormatVideo:
            self._add_video_capabilities(media, capabilities)
        elif format_type == FormatAudio:
            self._add_audio_capabilities(media, capabilities)
        elif format_type == FormatData:
            self._add_data_capabilities(media, capabilities)
        elif format_type == FormatMux:
            self._add_mux_capabilities(media, capabilities)
        else:
            raise ValueError("Unsupported format type: {}".format(format_type.s))

        # Transport capabilities
        self._add_transport_capabilities(media, capabilities)

        return CapSet(
            caps=capabilities,
            label=label,
            preference=preference)

    def _determine_format_type(self, media: MediaDescriptor, mux: bool = False) -> Optional[str]:
        """Determine the NMOS format type from media descriptor"""
        if media.type is None:
            raise ValueError("Media descriptor missing type")

        if media.type == MatroxSdpEnums.Video:
            assert media.format_code != 0 and media.format_string is None
            # Check if this is actually data (ST 2110-40)
            if media.encoding_name == MatroxSdpEnums.EncodingSmpte291:
                return FormatData
            elif media.encoding_name == MatroxSdpEnums.EncodingMP2T:
                return FormatMux
            else:
                return FormatVideo
        elif media.type == MatroxSdpEnums.Audio:
            assert media.format_code != 0 and media.format_string is None
            if media.encoding_name == MatroxSdpEnums.EncodingAM824 and mux:
                return FormatMux
            else:
                return FormatAudio
        elif media.type == MatroxSdpEnums.Application:
            assert media.format_code == 0 and media.encoding_name is None
            if media.format_string == MatroxSdpEnums.FormatUsb:
                return FormatData
            else:
                return FormatMux
        else:
            raise ValueError("Unsupported media type: {}".format(media.type.s))

    def _get_media_type_from_format(self, format_type: str, media: MediaDescriptor, mux: bool = False) -> Optional[str]:
        """Get the media type string for capabilities"""
        # If the Receiver is of format mux then always application/
        if mux:
            type = "application/"
        # Otherwise, use the media type
        else:
            type = media.type.s + "/"

        # RTP media (format_code != 0) carry the subtype in the rtpmap encoding
        # name; non-RTP media such as application/usb (format_code == 0) carry it
        # in the media-line format string and have no encoding name.
        if media.format_code != 0:
            if not media.encoding_name:
                raise ValueError("Media descriptor missing encoding name")
            return type + media.encoding_name.s
        else:
            if media.format_string is None:
                raise ValueError("Media descriptor missing format string")
            return type + media.format_string.s

    def _add_video_capabilities(self, media: MediaDescriptor, capabilities: Dict[str, Capability]):
        """Add video-specific capabilities"""
        # Frame rate
        if media.exact_frame_rate_numerator > 0:
            denominator = media.exact_frame_rate_denominator if media.exact_frame_rate_denominator > 0 else 1
            frame_rate = Fraction(media.exact_frame_rate_numerator, denominator)
            capabilities[CapFormatGrainRate] = Capability(
                CapFormatGrainRate,
                RangeValue(values=(frame_rate,), type=RangeType.RATIONAL)
            )

        # Frame dimensions
        if media.width > 0:
            capabilities[CapFormatFrameWidth] = Capability(
                CapFormatFrameWidth,
                RangeValue(values=(media.width,), type=RangeType.INT)
            )

        if media.height > 0:
            capabilities[CapFormatFrameHeight] = Capability(
                CapFormatFrameHeight,
                RangeValue(values=(media.height,), type=RangeType.INT)
            )

        # Interlace mode
        interlace_mode = "progressive"
        if media.interlaced:
            interlace_mode = "interlaced_tff" if media.top_field_first else "interlaced_bff"
        elif media.segmented:
            interlace_mode = "interlaced_psf"

        capabilities[CapFormatInterlaceMode] = Capability(
            CapFormatInterlaceMode,
            RangeValue(values=(interlace_mode,), type=RangeType.STRING)
        )

        # Colorimetry
        if media.colorimetry:
            colorspace = str(media.colorimetry)
            capabilities[CapFormatColorspace] = Capability(
                CapFormatColorspace,
                RangeValue(values=(colorspace,), type=RangeType.STRING)
            )

        # Transfer characteristic
        if media.transfer_characteristic:
            transfer_characteristic = str(media.transfer_characteristic)
            capabilities[CapFormatTransferCharacteristic] = Capability(
                CapFormatTransferCharacteristic,
                RangeValue(values=(transfer_characteristic,), type=RangeType.STRING)
            )

        # Color sampling
        if media.sampling:
            sampling = str(media.sampling)
            capabilities[CapFormatColorSampling] = Capability(
                CapFormatColorSampling,
                RangeValue(values=(sampling,), type=RangeType.STRING)
            )

        # Component depth
        if media.depth > 0:
            capabilities[CapFormatComponentDepth] = Capability(
                CapFormatComponentDepth,
                RangeValue(values=(media.depth,), type=RangeType.INT)
            )

        if media.encoding_name == MatroxSdpEnums.EncodingJxsv:
            # Profile/Level for coded formats
            if media.profile:
                profile = str(media.profile)
                capabilities[CapFormatProfile] = Capability(
                    CapFormatProfile,
                    RangeValue(values=(profile,), type=RangeType.STRING)
                )

            if media.level:
                level = str(media.level)
                capabilities[CapFormatLevel] = Capability(
                    CapFormatLevel,
                    RangeValue(values=(level,), type=RangeType.STRING)
                )

            if media.sub_level:
                sublevel = str(media.sub_level)
                capabilities[CapFormatSublevel] = Capability(
                    CapFormatSublevel,
                    RangeValue(values=(sublevel,), type=RangeType.STRING)
                )

            if media.jxsv_packet_mode == MatroxSdpEnums.CodeStream:
                capabilities[CapTransportPacketTransmissionMode] = Capability(
                    CapTransportPacketTransmissionMode,
                    RangeValue(values=("codestream",), type=RangeType.STRING)
                )
            elif media.jxsv_trans_mode == MatroxSdpEnums.SequentialOnly:
                capabilities[CapTransportPacketTransmissionMode] = Capability(
                    CapTransportPacketTransmissionMode,
                    RangeValue(values=("slice_sequential",), type=RangeType.STRING)
                )
            else:
                capabilities[CapTransportPacketTransmissionMode] = Capability(
                    CapTransportPacketTransmissionMode,
                    RangeValue(values=("slice_out_of_order",), type=RangeType.STRING)
                )

            if media.bitrate_kbits > 0:
                capabilities[CapTransportBitRate] = Capability(
                    CapTransportBitRate,
                    RangeValue(values=(media.bitrate_kbits,), type=RangeType.INT)
                )

        elif media.encoding_name == MatroxSdpEnums.EncodingH264:

            profile, level = get_h264_profile_level_from_sdp(media.codec_profile_level_id)

            if profile:
                capabilities[CapFormatProfile] = Capability(
                    CapFormatProfile,
                    RangeValue(values=(profile,), type=RangeType.STRING)
                )

            if level:
                capabilities[CapFormatLevel] = Capability(
                    CapFormatLevel,
                    RangeValue(values=(level,), type=RangeType.STRING)
                )

            if media.h264_packetization_mode == 0:
                capabilities[CapTransportPacketTransmissionMode] = Capability(
                    CapTransportPacketTransmissionMode,
                    RangeValue(values=("single_nal_unit",), type=RangeType.STRING)
                )
            elif media.h264_packetization_mode == 1:
                capabilities[CapTransportPacketTransmissionMode] = Capability(
                    CapTransportPacketTransmissionMode,
                    RangeValue(values=("non_interleaved_nal_units",), type=RangeType.STRING)
                )
            else:
                capabilities[CapTransportPacketTransmissionMode] = Capability(
                    CapTransportPacketTransmissionMode,
                    RangeValue(values=("interleaved_nal_units",), type=RangeType.STRING)
                )

            if media.h264_parameter_sets == "":
                capabilities[CapTransportParameterSetsTransportMode] = Capability(
                    CapTransportParameterSetsTransportMode,
                    RangeValue(values=("in_band",), type=RangeType.STRING)
                )
            elif media.h264_parameter_sets.endswith(","):
                capabilities[CapTransportParameterSetsTransportMode] = Capability(
                    CapTransportParameterSetsTransportMode,
                    RangeValue(values=("in_and_out_of_band",), type=RangeType.STRING)
                )
            else:
                capabilities[CapTransportParameterSetsTransportMode] = Capability(
                    CapTransportParameterSetsTransportMode,
                    RangeValue(values=("out_of_band",), type=RangeType.STRING)
                )

            if media.bitrate_kbits > 0:
                capabilities[CapTransportBitRate] = Capability(
                    CapTransportBitRate,
                    RangeValue(values=(media.bitrate_kbits,), type=RangeType.INT)
                )

        elif media.encoding_name == MatroxSdpEnums.EncodingH265:

            tier_flag = 0
            if media.h265_tier_flag:
                tier_flag = 1

            profile, level, progressive = get_h265_profile_level_from_sdp(media.h265_profile_space,
                                                                          media.h265_profile_id, tier_flag,
                                                                          media.h265_level_id,
                                                                          media.h265_profile_compatibility_indicator,
                                                                          media.h265_interop_constraints)

            if profile:
                capabilities[CapFormatProfile] = Capability(
                    CapFormatProfile,
                    RangeValue(values=(profile,), type=RangeType.STRING)
                )

            if level:
                capabilities[CapFormatLevel] = Capability(
                    CapFormatLevel,
                    RangeValue(values=(level,), type=RangeType.STRING)
                )

            if progressive:
                capabilities[CapFormatInterlaceMode] = Capability(
                    CapFormatInterlaceMode,
                    RangeValue(values=("progressive",), type=RangeType.STRING)
                )

            if media.h26x_max_don_diff > 0:
                capabilities[CapTransportPacketTransmissionMode] = Capability(
                    CapTransportPacketTransmissionMode,
                    RangeValue(values=("interleaved_nal_units",), type=RangeType.STRING)
                )
            else:
                capabilities[CapTransportPacketTransmissionMode] = Capability(
                    CapTransportPacketTransmissionMode,
                    RangeValue(values=("non_interleaved_nal_units",), type=RangeType.STRING)
                )

            if media.h265_vps == "" and media.h265_sps == "" and media.h265_pps == "":
                capabilities[CapTransportParameterSetsTransportMode] = Capability(
                    CapTransportParameterSetsTransportMode,
                    RangeValue(values=("in_band",), type=RangeType.STRING)
                )
            elif media.h265_vps.endswith(",") or media.h265_sps.endswith(",") or media.h265_pps.endswith(","):

                capabilities[CapTransportParameterSetsTransportMode] = Capability(
                    CapTransportParameterSetsTransportMode,
                    RangeValue(values=("in_and_out_of_band",), type=RangeType.STRING)
                )
            else:
                capabilities[CapTransportParameterSetsTransportMode] = Capability(
                    CapTransportParameterSetsTransportMode,
                    RangeValue(values=("out_of_band",), type=RangeType.STRING)
                )

            if media.bitrate_kbits > 0:
                capabilities[CapTransportBitRate] = Capability(
                    CapTransportBitRate,
                    RangeValue(values=(media.bitrate_kbits,), type=RangeType.INT)
                )

    def _add_audio_capabilities(self, media: MediaDescriptor, capabilities: Dict[str, Capability]):
        """Add audio-specific capabilities"""
        
        # Channel count
        if media.channels > 0:
            capabilities[CapFormatChannelCount] = Capability(
                CapFormatChannelCount,
                RangeValue(values=(media.channels,), type=RangeType.INT)
            )

        # Sample rate
        if media.sample_rate > 0:
            # Convert to rational for precise representation
            sample_rate = Fraction(media.sample_rate, 1)
            capabilities[CapFormatSampleRate] = Capability(
                CapFormatSampleRate,
                RangeValue(values=(sample_rate,), type=RangeType.RATIONAL)
            )

        if media.bitrate_kbits > 0:
            capabilities[CapTransportBitRate] = Capability(
                CapTransportBitRate,
                RangeValue(values=(media.bitrate_kbits,), type=RangeType.INT)
            )

        if (media.encoding_name == MatroxSdpEnums.EncodingL8 or media.encoding_name == MatroxSdpEnums.EncodingL16 or
                media.encoding_name == MatroxSdpEnums.EncodingL20 or media.encoding_name == MatroxSdpEnums.EncodingL24):
            try:
                # Extract bit depth from encoding name like "L24", "L16"
                depth = int(str(media.encoding_name)[1:])
                capabilities[CapFormatSampleDepth] = Capability(
                    CapFormatSampleDepth,
                    RangeValue(values=(depth,), type=RangeType.INT)
                )
            except ValueError:
                pass

            # Packet time
            if media.p_time_us > 0:
                capabilities[CapTransportPacketTime] = Capability(
                    CapTransportPacketTime,
                    RangeValue(values=(float(media.p_time_us)/1000.0,), type=RangeType.FLOAT)
                )

            if media.max_p_time_us > 0:
                capabilities[CapTransportMaxPacketTime] = Capability(
                    CapTransportMaxPacketTime,
                    RangeValue(values=(float(media.max_p_time_us)/1000.0,), type=RangeType.FLOAT)
                )

        elif media.encoding_name == MatroxSdpEnums.EncodingAM824:

            # Packet time
            if media.p_time_us > 0:
                capabilities[CapTransportPacketTime] = Capability(
                    CapTransportPacketTime,
                    RangeValue(values=(float(media.p_time_us)/1000.0,), type=RangeType.FLOAT)
                )

            if media.max_p_time_us > 0:
                capabilities[CapTransportMaxPacketTime] = Capability(
                    CapTransportMaxPacketTime,
                    RangeValue(values=(float(media.max_p_time_us)/1000.0,), type=RangeType.FLOAT)
                )

            if media.channel_order:
                capabilities[CapTransportChannelOrder] = Capability(
                    CapTransportChannelOrder,
                    RangeValue(values=(media.channel_order,), type=RangeType.STRING)
                )

        elif media.encoding_name == MatroxSdpEnums.EncodingAAC:

            profile, level = get_aac_profile_level_from_sdp(media.codec_profile_level_id)

            if profile:
                capabilities[CapFormatProfile] = Capability(
                    CapFormatProfile,
                    RangeValue(values=(profile,), type=RangeType.STRING)
                )

            if level:
                capabilities[CapFormatLevel] = Capability(
                    CapFormatLevel,
                    RangeValue(values=(level,), type=RangeType.STRING)
                )

            if media.aac_bitrate != 0:
                capabilities[CapFormatBitRate] = Capability(
                    CapFormatBitRate,
                    RangeValue(values=(media.aac_bitrate / 1000,), type=RangeType.INT)  # in Kbps
                )

            if media.aac_max_displacement > 0:
                capabilities[CapTransportPacketTransmissionMode] = Capability(
                    CapTransportPacketTransmissionMode,
                    RangeValue(values=("interleaved_access_units",), type=RangeType.STRING)
                )
            else:
                capabilities[CapTransportPacketTransmissionMode] = Capability(
                    CapTransportPacketTransmissionMode,
                    RangeValue(values=("non_interleaved_access_units",), type=RangeType.STRING)
                )

            if media.aac_config == "":
                capabilities[CapTransportParameterSetsTransportMode] = Capability(
                    CapTransportParameterSetsTransportMode,
                    RangeValue(values=("in_band",), type=RangeType.STRING)
                )
            else:
                capabilities[CapTransportParameterSetsTransportMode] = Capability(
                    CapTransportParameterSetsTransportMode,
                    RangeValue(values=("out_of_band",), type=RangeType.STRING)
                )

            # RFC 6416 Packet time
            if media.p_time_us > 0:
                capabilities[CapTransportPacketTime] = Capability(
                    CapTransportPacketTime,
                    RangeValue(values=(float(media.p_time_us)/1000.0,), type=RangeType.FLOAT)
                )

            if media.max_p_time_us > 0:
                capabilities[CapTransportMaxPacketTime] = Capability(
                    CapTransportMaxPacketTime,
                    RangeValue(values=(float(media.max_p_time_us)/1000.0,), type=RangeType.FLOAT)
                )

            # RFC 3640 Packet time
            if media.aac_constant_duration > 0:
                capabilities[CapTransportPacketTime] = Capability(
                    CapTransportPacketTime,
                    RangeValue(values=(media.aac_constant_duration,), type=RangeType.FLOAT)
                )
                capabilities[CapTransportMaxPacketTime] = Capability(
                    CapTransportMaxPacketTime,
                    RangeValue(values=(media.aac_constant_duration,), type=RangeType.FLOAT)
                )

        elif (media.encoding_name == MatroxSdpEnums.EncodingAAC_LATM or
              media.encoding_name == MatroxSdpEnums.EncodingAAC_ADTS):

            profile, level = get_aac_profile_level_from_sdp(media.codec_profile_level_id)

            if profile:
                capabilities[CapFormatProfile] = Capability(
                    CapFormatProfile,
                    RangeValue(values=(profile,), type=RangeType.STRING)
                )

            if level:
                capabilities[CapFormatLevel] = Capability(
                    CapFormatLevel,
                    RangeValue(values=(level,), type=RangeType.STRING)
                )

            if media.aac_bitrate != 0:
                capabilities[CapFormatBitRate] = Capability(
                    CapFormatBitRate,
                    RangeValue(values=(media.aac_bitrate / 1000,), type=RangeType.INT)  # in Kbps
                    )

            if media.aac_max_displacement > 0:
                capabilities[CapTransportPacketTransmissionMode] = Capability(
                    CapTransportPacketTransmissionMode,
                    RangeValue(values=("interleaved_access_units",), type=RangeType.STRING)
                )
            else:
                capabilities[CapTransportPacketTransmissionMode] = Capability(
                    CapTransportPacketTransmissionMode,
                    RangeValue(values=("non_interleaved_access_units",), type=RangeType.STRING)
                )

            if media.aac_config_present is False:
                if media.aac_config == "":
                    capabilities[CapTransportParameterSetsTransportMode] = Capability(
                        CapTransportParameterSetsTransportMode,
                        RangeValue(values=("in_band",), type=RangeType.STRING)
                    )
                else:
                    capabilities[CapTransportParameterSetsTransportMode] = Capability(
                        CapTransportParameterSetsTransportMode,
                        RangeValue(values=("in_and_out_of_band",), type=RangeType.STRING)
                    )
            else:
                capabilities[CapTransportParameterSetsTransportMode] = Capability(
                    CapTransportParameterSetsTransportMode,
                    RangeValue(values=("out_of_band",), type=RangeType.STRING)
                )

            # RFC 6416 Packet time
            if media.p_time_us > 0:
                capabilities[CapTransportPacketTime] = Capability(
                    CapTransportPacketTime,
                    RangeValue(values=(float(media.p_time_us)/1000.0,), type=RangeType.FLOAT)
                )

            if media.max_p_time_us > 0:
                capabilities[CapTransportMaxPacketTime] = Capability(
                    CapTransportMaxPacketTime,
                    RangeValue(values=(float(media.max_p_time_us)/1000.0,), type=RangeType.FLOAT)
                )

            # RFC 3640 Packet time
            if media.aac_constant_duration > 0:
                capabilities[CapTransportPacketTime] = Capability(
                    CapTransportPacketTime,
                    RangeValue(values=(media.aac_constant_duration,), type=RangeType.FLOAT)
                )
                capabilities[CapTransportMaxPacketTime] = Capability(
                    CapTransportMaxPacketTime,
                    RangeValue(values=(media.aac_constant_duration,), type=RangeType.FLOAT)
                )

    def _add_data_capabilities(self, media: MediaDescriptor, capabilities: Dict[str, Capability]):
        """Add data-specific capabilities"""
        pass

    def _add_mux_capabilities(self, media: MediaDescriptor, capabilities: Dict[str, Capability]):
        """Add mux-specific capabilities"""
        pass

    def _add_transport_capabilities(self, media: MediaDescriptor, capabilities: Dict[str, Capability]):
        """Add some basic transport-specific capabilities"""

        # ST 2110-21 sender type
        if media.sender_type:
            sender_type = str(media.sender_type)
            capabilities[CapTransport_ST2110_21_SenderType] = Capability(
                CapTransport_ST2110_21_SenderType,
                RangeValue(values=(sender_type,), type=RangeType.STRING)
            )

        # HKEP
        if media.hkep:
            capabilities[CapTransportHkep] = Capability(
                CapTransportHkep,
                RangeValue(values=(True,), type=RangeType.BOOL)
            )

        # Privacy
        if media.privacy:
            capabilities[CapTransportPrivacy] = Capability(
                CapTransportPrivacy,
                RangeValue(values=(True,), type=RangeType.BOOL)
            )

        # Get clock, HDCP and Privacy information
        if media.media_clock_type == MatroxSdpEnums.Sender:
            capabilities[CapTransportSynchronousMedia] = Capability(
                CapTransportSynchronousMedia,
                RangeValue(values=(False,), type=RangeType.BOOL)
            )
        else:
            capabilities[CapTransportSynchronousMedia] = Capability(
                CapTransportSynchronousMedia,
                RangeValue(values=(True,), type=RangeType.BOOL)
            )

        if media.ts_ref_clock_source == MatroxSdpEnums.PTP:
            capabilities[CapTransportClockRefType] = Capability(
                CapTransportClockRefType,
                RangeValue(values=("ptp",), type=RangeType.STRING)
            )
        else:
            capabilities[CapTransportClockRefType] = Capability(
                CapTransportClockRefType,
                RangeValue(values=("internal",), type=RangeType.STRING)
            )


def convert_sdp_file_to_capabilities(sdp_file_path: str) -> Caps:
    """
    Convenience function to convert an SDP file to CCF Capabilities

    Args:
        sdp_file_path: Path to the SDP file

    Returns:
        Caps: CCF Capabilities structure
    """
    converter = SdpToCapabilitiesConverter()
    return converter.convert_file(sdp_file_path)


def convert_sdp_string_to_capabilities(sdp_content: str) -> Caps:
    """
    Convenience function to convert SDP content to CCF Capabilities

    Args:
        sdp_content: SDP content as string

    Returns:
        Caps: CCF Capabilities structure
    """
    converter = SdpToCapabilitiesConverter()
    return converter.convert_string(sdp_content)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python SdpToCapabilities.py <sdp_file_path>")
        sys.exit(1)

    sdp_file = sys.argv[1]

    try:
        caps = convert_sdp_file_to_capabilities(sdp_file)
        print("Converted SDP to CCF Capabilities:")
        print(caps)

        # Example of using the capabilities
        print("\nTrunk capabilities:")
        trunk_caps = caps.get(format=FormatMux)
        print(trunk_caps)

        print("\nVideo layer capabilities:")
        video_caps = caps.get(format=FormatVideo)
        print(video_caps)

        print("\nAudio layer capabilities:")
        audio_caps = caps.get(format=FormatAudio)
        print(audio_caps)

    except Exception as e:
        print(f"Error converting SDP: {e}")
        sys.exit(1)
