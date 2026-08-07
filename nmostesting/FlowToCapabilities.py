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

"""
Flow to CCF Capabilities Converter

Note: some transport capabilities can only be obtained from the SDP transport file.

hkep and privacy are reported only when true, matching SdpToCapabilities. This is a
deliberate divergence from nmos-reference and the Go node, which always report both
the true and the false value. Keep the two converters in this file and
SdpToCapabilities.py in step with each other.

TODO: add urn:x-nmos:cap:transport:usb_class

"""

from typing import Optional, Dict, Any, Tuple, List, Union
from fractions import Fraction

from .MatroxCCF import (
    Caps, CapSet, Capability, RangeValue, RangeType,
    FormatVideo, FormatAudio, FormatData, FormatMux,
    CapFormatMediaType, CapFormatGrainRate, CapFormatFrameWidth, CapFormatFrameHeight,
    CapFormatInterlaceMode, CapFormatColorspace, CapFormatTransferCharacteristic,
    CapFormatColorSampling, CapFormatComponentDepth, CapFormatChannelCount,
    CapFormatSampleRate, CapFormatSampleDepth, CapFormatBitRate, CapFormatProfile,
    CapFormatLevel, CapFormatSublevel, CapFormatFbblevel, CapFormatConstantBitRate, CapFormatVideoLayers,
    CapFormatAudioLayers, CapFormatDataLayers, CapTransportClockRefType,
    CapTransportSynchronousMedia, CapTransportHkep, CapTransportPrivacy,
    CapTransport_ST2110_21_SenderType, CapTransportPacketTransmissionMode,
    CapTransportParameterSetsFlowMode, CapTransportParameterSetsTransportMode,
    CapTransportChannelOrder, CapTransportInfoBlock, CapTransportBitRate
)


def ifelse(t, a, b):
    if t:
        return a
    else:
        return b


class FlowToCapabilitiesConverter:
    """Converts a Flow, Source and Sender) description to CCF Capabilities"""

    def convert(self, flow: Dict[str, Any], source: Dict[str, Any], sender: Dict[str, Any],
                node_clocks: Optional[list] = None) -> Caps:
        """Convert a Flow dict (NMOS) and Source dict (NMOS) to Caps.
        """
        if not isinstance(flow, dict) or not isinstance(source, dict) or not isinstance(sender, dict):
            return Caps(capsets=[])

        if flow.get("format") is None or source.get("format") is None or flow.get("format") != source.get("format"):
            return Caps(capsets=[])

        flow_format, coded_flow = self._determine_flow_type(flow)

        if flow_format == FormatVideo:
            if coded_flow:
                capset = self._convert_coded_video_flow_to_capset(flow, source, sender, node_clocks)
            else:
                capset = self._convert_raw_video_flow_to_capset(flow, source, sender, node_clocks)

        elif flow_format == FormatAudio:
            if coded_flow:
                capset = self._convert_coded_audio_flow_to_capset(flow, source, sender, node_clocks)
            else:
                capset = self._convert_raw_audio_flow_to_capset(flow, source, sender, node_clocks)

        elif flow_format == FormatData:
            capset = self._convert_data_flow_to_capset(flow, source, sender, node_clocks)

        elif flow_format == FormatMux:
            capset = self._convert_mux_flow_to_capset(flow, source, sender, node_clocks)

        else:
            return Caps(capsets=[])

        return Caps(capsets=[capset])

    # ----------------------- Helpers -----------------------

    def _determine_flow_type(self, flow: Dict[str, Any]) -> Tuple[str, bool]:

        fmt = flow.get("format")

        if fmt == "urn:x-nmos:format:video":
            return FormatVideo, self._is_coded_video(flow)
        if fmt == "urn:x-nmos:format:audio":
            return FormatAudio, self._is_coded_audio(flow)
        if fmt == "urn:x-nmos:format:data":
            return FormatData, False
        if fmt == "urn:x-nmos:format:mux":
            return FormatMux, False

        raise ValueError("FlowToCapabilities: unsupported NMOS flow format: %s" % fmt)

    # ----------------------- Explicit converters (public-style) -----------------------
    def _convert_raw_video_flow_to_capset(self, flow: Dict[str, Any], source: Dict[str, Any],
                                          sender: Dict[str, Any], node_clocks: Optional[list]) -> CapSet:

        caps: Dict[str, Capability] = {}

        # media_type
        media_type = flow.get("media_type")
        if not isinstance(media_type, str):
            raise ValueError("FlowToCapabilities: missing media_type in raw video flow")
        caps[CapFormatMediaType] = Capability(CapFormatMediaType, RangeValue(values=(media_type,),
                                                                             type=RangeType.STRING))

        synchronous_media, clock_name = self._require_video_source(source)

        # grain rate (optional)
        grain = self._get_rational(flow, "grain_rate")
        caps[CapFormatGrainRate] = Capability(
            CapFormatGrainRate, RangeValue(values=(grain,) if grain is not None else None, type=RangeType.RATIONAL)
        )

        # frame dimensions
        fw = self._get_int(flow, ["frame_width"])
        fh = self._get_int(flow, ["frame_height"])
        caps[CapFormatFrameWidth] = Capability(CapFormatFrameWidth,
                                               RangeValue(values=(fw,) if fw is not None else None,
                                                          type=RangeType.INT))
        caps[CapFormatFrameHeight] = Capability(CapFormatFrameHeight,
                                                RangeValue(values=(fh,) if fh is not None else None,
                                                           type=RangeType.INT))

        # interlace, colorspace, transfer
        im = flow.get("interlace_mode")
        caps[CapFormatInterlaceMode] = Capability(CapFormatInterlaceMode,
                                                  RangeValue(values=(im,) if im is not None else None,
                                                             type=RangeType.STRING))
        cs = flow.get("colorspace")
        caps[CapFormatColorspace] = Capability(CapFormatColorspace,
                                               RangeValue(values=(cs,) if cs is not None else None,
                                                          type=RangeType.STRING))
        tc = flow.get("transfer_characteristic")
        caps[CapFormatTransferCharacteristic] = Capability(CapFormatTransferCharacteristic,
                                                           RangeValue(values=(tc,) if tc is not None else None,
                                                                      type=RangeType.STRING))

        components = flow.get("components")
        if not isinstance(components, list):
            raise ValueError("FlowToCapabilities: raw video flow missing components array")
        if isinstance(fw, int) and isinstance(fh, int):
            sampling = self._infer_sampling_from_components(components, fw, fh)
            caps[CapFormatColorSampling] = Capability(CapFormatColorSampling,
                                                      RangeValue(values=(sampling,) if sampling is not None
                                                                 else None, type=RangeType.STRING))
        comp_depth = self._get_component_depth(components)
        caps[CapFormatComponentDepth] = Capability(CapFormatComponentDepth,
                                                   RangeValue(values=(comp_depth,) if comp_depth is not None
                                                              else None, type=RangeType.INT))

        layer = flow.get("urn:x-matrox:layer", None)
        format = FormatVideo

        if layer is None:
            format = None
            caps[CapTransportSynchronousMedia] = Capability(CapTransportSynchronousMedia,
                                                            RangeValue(values=(synchronous_media,)
                                                                       if synchronous_media is not None
                                                                       else None, type=RangeType.BOOL))

            sender_type = sender.get("sender_type", None)
            if sender_type:
                caps[CapTransport_ST2110_21_SenderType] = Capability(CapTransport_ST2110_21_SenderType,
                                                                     RangeValue(values=(sender_type,)
                                                                                if sender_type is not None
                                                                                else None, type=RangeType.STRING))

            clk_ref = self._clock_ref_type_from_node_clocks(clock_name, node_clocks)
            caps[CapTransportClockRefType] = Capability(CapTransportClockRefType,
                                                        RangeValue(values=(clk_ref,)
                                                                   if clk_ref is not None
                                                                   else None, type=RangeType.STRING))

            hkep = sender.get("hkep", None)
            if hkep:
                caps[CapTransportHkep] = Capability(CapTransportHkep,
                                                    RangeValue(values=(hkep,)
                                                               if hkep is not None else None, type=RangeType.BOOL))

            privacy = sender.get("privacy", None)
            if privacy:
                caps[CapTransportPrivacy] = Capability(CapTransportPrivacy,
                                                       RangeValue(values=(privacy,)
                                                                  if privacy is not None
                                                                  else None, type=RangeType.BOOL))

        return CapSet(caps=caps, label="Flow", preference=100, format=format, layer=layer)

    def _convert_coded_video_flow_to_capset(self, flow: Dict[str, Any], source: Dict[str, Any],
                                            sender: Dict[str, Any], node_clocks: Optional[list]) -> CapSet:
        """Build CapSet for coded video flows (mirrors Go getFlowProperties coded video branch)."""

        caps: Dict[str, Capability] = {}

        # media_type
        media_type = flow.get("media_type")
        if not isinstance(media_type, str):
            raise ValueError("FlowToCapabilities: missing media_type in raw video flow")
        caps[CapFormatMediaType] = Capability(CapFormatMediaType,
                                              RangeValue(values=(media_type,), type=RangeType.STRING))

        synchronous_media, clock_name = self._require_video_source(source)

        # grain rate (optional)
        grain = self._get_rational(flow, "grain_rate")
        caps[CapFormatGrainRate] = Capability(CapFormatGrainRate,
                                              RangeValue(values=(grain,) if grain is not None
                                                         else None, type=RangeType.RATIONAL))

        # frame dimensions
        fw = self._get_int(flow, ["frame_width"])
        fh = self._get_int(flow, ["frame_height"])
        caps[CapFormatFrameWidth] = Capability(CapFormatFrameWidth,
                                               RangeValue(values=(fw,) if fw is not None
                                                          else None, type=RangeType.INT))
        caps[CapFormatFrameHeight] = Capability(CapFormatFrameHeight,
                                                RangeValue(values=(fh,) if fh is not None
                                                           else None, type=RangeType.INT))

        # interlace, colorspace, transfer
        im = flow.get("interlace_mode")
        caps[CapFormatInterlaceMode] = Capability(CapFormatInterlaceMode,
                                                  RangeValue(values=(im,) if im is not None
                                                             else None, type=RangeType.STRING))
        cs = flow.get("colorspace")
        caps[CapFormatColorspace] = Capability(CapFormatColorspace,
                                               RangeValue(values=(cs,) if cs is not None
                                                          else None, type=RangeType.STRING))
        tc = flow.get("transfer_characteristic")
        caps[CapFormatTransferCharacteristic] = Capability(CapFormatTransferCharacteristic,
                                                           RangeValue(values=(tc,) if tc is not None
                                                                      else None, type=RangeType.STRING))

        components = flow.get("components")
        if not isinstance(components, list):
            raise ValueError("FlowToCapabilities: raw video flow missing components array")
        if isinstance(fw, int) and isinstance(fh, int):
            sampling = self._infer_sampling_from_components(components, fw, fh)
            caps[CapFormatColorSampling] = Capability(CapFormatColorSampling,
                                                      RangeValue(values=(sampling,) if sampling is not None
                                                                 else None, type=RangeType.STRING))
        comp_depth = self._get_component_depth(components)
        caps[CapFormatComponentDepth] = Capability(CapFormatComponentDepth,
                                                   RangeValue(values=(comp_depth,) if comp_depth is not None
                                                              else None, type=RangeType.INT))

        # coded video extras
        bitrate = self._get_int(flow, ["bit_rate"])  # Kbps
        if bitrate:
            caps[CapFormatBitRate] = Capability(CapFormatBitRate,
                                                RangeValue(values=(bitrate,) if bitrate is not None
                                                           else None, type=RangeType.INT))
        cbr = flow.get("constant_bit_rate", None)
        if cbr is not None:
            caps[CapFormatConstantBitRate] = Capability(CapFormatConstantBitRate,
                                                        RangeValue(values=(cbr,) if cbr is not None
                                                                   else None, type=RangeType.BOOL))
        profile = flow.get("profile", None)
        if profile:
            caps[CapFormatProfile] = Capability(CapFormatProfile,
                                                RangeValue(values=(profile,) if profile is not None
                                                           else None, type=RangeType.STRING))
        level = flow.get("level", None)
        if level:
            caps[CapFormatLevel] = Capability(CapFormatLevel,
                                              RangeValue(values=(level,) if level is not None
                                                         else None, type=RangeType.STRING))

        sublevel = flow.get("sublevel", None)
        if sublevel:
            caps[CapFormatSublevel] = Capability(CapFormatSublevel,
                                                 RangeValue(values=(sublevel,) if sublevel is not None
                                                            else None, type=RangeType.STRING))

        fbblevel = flow.get("fbblevel", None)
        if sublevel:
            caps[CapFormatFbblevel] = Capability(CapFormatFbblevel,
                                                 RangeValue(values=(fbblevel,) if fbblevel is not None
                                                            else None, type=RangeType.STRING))

        layer = flow.get("urn:x-matrox:layer", None)
        format = FormatVideo

        if layer is None:
            format = None
            caps[CapTransportSynchronousMedia] = Capability(CapTransportSynchronousMedia,
                                                            RangeValue(values=(synchronous_media,),
                                                                       type=RangeType.BOOL))

            sender_type = sender.get("sender_type", None)
            if sender_type:
                caps[CapTransport_ST2110_21_SenderType] = Capability(CapTransport_ST2110_21_SenderType,
                                                                     RangeValue(values=(sender_type,)
                                                                                if sender_type is not None
                                                                                else None, type=RangeType.STRING))

            packet_transmission_mode = sender.get("packet_transmission_mode", None)
            if packet_transmission_mode:
                caps[CapTransportPacketTransmissionMode] = Capability(CapTransportPacketTransmissionMode,
                                                                      RangeValue(values=(packet_transmission_mode,)
                                                                                 if packet_transmission_mode is not None
                                                                                 else None, type=RangeType.STRING))

            paramerer_sets_flow_mode = sender.get("parameter_sets_flow_mode", None)
            if paramerer_sets_flow_mode:
                caps[CapTransportParameterSetsFlowMode] = Capability(CapTransportParameterSetsFlowMode,
                                                                     RangeValue(values=(paramerer_sets_flow_mode,)
                                                                                if paramerer_sets_flow_mode is not None
                                                                                else None, type=RangeType.STRING))

            parameter_sets_transport_mode = sender.get("parameter_sets_transport_mode", None)
            if parameter_sets_transport_mode:
                caps[CapTransportParameterSetsTransportMode] = Capability(
                    CapTransportParameterSetsTransportMode,
                    RangeValue(values=(parameter_sets_transport_mode,)
                               if parameter_sets_transport_mode is not None
                               else None, type=RangeType.STRING))

            transport_bitrate = sender.get("transport_bitrate", None)
            if transport_bitrate:
                caps[CapTransportBitRate] = Capability(CapTransportBitRate,
                                                       RangeValue(values=(transport_bitrate,)
                                                                  if transport_bitrate is not None
                                                                  else None, type=RangeType.INT))

            clk_ref = self._clock_ref_type_from_node_clocks(clock_name, node_clocks)
            caps[CapTransportClockRefType] = Capability(CapTransportClockRefType,
                                                        RangeValue(values=(clk_ref,)
                                                                   if clk_ref is not None
                                                                   else None, type=RangeType.STRING))

            hkep = sender.get("hkep", None)
            if hkep:
                caps[CapTransportHkep] = Capability(CapTransportHkep,
                                                    RangeValue(values=(hkep,) if hkep is not None
                                                               else None, type=RangeType.BOOL))

            privacy = sender.get("privacy", None)
            if privacy:
                caps[CapTransportPrivacy] = Capability(CapTransportPrivacy,
                                                       RangeValue(values=(privacy,) if privacy is not None
                                                                  else None, type=RangeType.BOOL))

        return CapSet(caps=caps, label="Flow", preference=100, format=format, layer=layer)

    def _convert_coded_audio_flow_to_capset(self, flow: Dict[str, Any], source: Dict[str, Any],
                                            sender: Dict[str, Any], node_clocks: Optional[list]) -> CapSet:

        caps: Dict[str, Capability] = {}

        media_type = flow.get("media_type")
        if not isinstance(media_type, str):
            raise ValueError("FlowToCapabilities: missing media_type in coded audio flow")
        caps[CapFormatMediaType] = Capability(CapFormatMediaType,
                                              RangeValue(values=(media_type,), type=RangeType.STRING))

        channels, synchronous_media, clock_name = self._require_audio_source(source)
        caps[CapFormatChannelCount] = Capability(CapFormatChannelCount,
                                                 RangeValue(values=(len(channels),), type=RangeType.INT))

        # sample_rate
        sample_rate = self._get_sample_rate(flow)
        caps[CapFormatSampleRate] = Capability(CapFormatSampleRate,
                                               RangeValue(values=(sample_rate,) if sample_rate is not None
                                                          else None, type=RangeType.RATIONAL))

        # coded audio extras
        bitrate = self._get_int(flow, ["bit_rate"])  # Kbps
        if bitrate:
            caps[CapFormatBitRate] = Capability(CapFormatBitRate,
                                                RangeValue(values=(bitrate,) if bitrate is not None
                                                           else None, type=RangeType.INT))
        cbr = flow.get("constant_bit_rate", None)
        if cbr is not None:
            caps[CapFormatConstantBitRate] = Capability(CapFormatConstantBitRate,
                                                        RangeValue(values=(cbr,) if cbr is not None
                                                                   else None, type=RangeType.BOOL))
        profile = flow.get("profile", None)
        if profile:
            caps[CapFormatProfile] = Capability(CapFormatProfile,
                                                RangeValue(values=(profile,) if profile is not None
                                                           else None, type=RangeType.STRING))
        level = flow.get("level", None)
        if level:
            caps[CapFormatLevel] = Capability(CapFormatLevel,
                                              RangeValue(values=(level,) if level is not None
                                                         else None, type=RangeType.STRING))

        layer = flow.get("urn:x-matrox:layer", None)
        format = FormatAudio

        if layer is None:
            format = None
            caps[CapTransportSynchronousMedia] = Capability(CapTransportSynchronousMedia,
                                                            RangeValue(values=(synchronous_media,),
                                                                       type=RangeType.BOOL))

            sender_type = sender.get("sender_type", None)
            if sender_type:
                caps[CapTransport_ST2110_21_SenderType] = Capability(CapTransport_ST2110_21_SenderType,
                                                                     RangeValue(values=(sender_type,)
                                                                                if sender_type is not None
                                                                                else None, type=RangeType.STRING))

            packet_transmission_mode = sender.get("packet_transmission_mode", None)
            if packet_transmission_mode:
                caps[CapTransportPacketTransmissionMode] = Capability(CapTransportPacketTransmissionMode,
                                                                      RangeValue(values=(packet_transmission_mode,)
                                                                                 if packet_transmission_mode is not None
                                                                                 else None, type=RangeType.STRING))

            parameter_sets_flow_mode = sender.get("parameter_sets_flow_mode", None)
            if parameter_sets_flow_mode:
                caps[CapTransportParameterSetsFlowMode] = Capability(CapTransportParameterSetsFlowMode,
                                                                     RangeValue(values=(parameter_sets_flow_mode,)
                                                                                if parameter_sets_flow_mode is not None
                                                                                else None, type=RangeType.STRING))

            parameter_sets_transport_mode = sender.get("parameter_sets_transport_mode", None)
            if parameter_sets_transport_mode:
                caps[CapTransportParameterSetsTransportMode] = Capability(
                    CapTransportParameterSetsTransportMode,
                    RangeValue(values=(parameter_sets_transport_mode,)
                               if parameter_sets_transport_mode is not None
                               else None, type=RangeType.STRING))

            channel_order = sender.get("channel_order", None)
            if channel_order:
                caps[CapTransportChannelOrder] = Capability(CapTransportChannelOrder,
                                                            RangeValue(values=(channel_order,)
                                                                       if channel_order is not None
                                                                       else None, type=RangeType.STRING))

            transport_bitrate = sender.get("transport_bitrate", None)
            if transport_bitrate:
                caps[CapTransportBitRate] = Capability(CapTransportBitRate,
                                                       RangeValue(values=(transport_bitrate,)
                                                                  if transport_bitrate is not None
                                                                  else None, type=RangeType.INT))

            clk_ref = self._clock_ref_type_from_node_clocks(clock_name, node_clocks)
            caps[CapTransportClockRefType] = Capability(CapTransportClockRefType,
                                                        RangeValue(values=(clk_ref,)
                                                                   if clk_ref is not None
                                                                   else None, type=RangeType.STRING))

            hkep = sender.get("hkep", None)
            if hkep:
                caps[CapTransportHkep] = Capability(CapTransportHkep,
                                                    RangeValue(values=(hkep,) if hkep is not None
                                                               else None, type=RangeType.BOOL))

            privacy = sender.get("privacy", None)
            if privacy:
                caps[CapTransportPrivacy] = Capability(CapTransportPrivacy,
                                                       RangeValue(values=(privacy,) if privacy is not None
                                                                  else None, type=RangeType.BOOL))

        return CapSet(caps=caps, label="Flow", preference=100, format=format, layer=layer)

    def _convert_raw_audio_flow_to_capset(self, flow: Dict[str, Any], source: Dict[str, Any],
                                          sender: Dict[str, Any], node_clocks: Optional[list]) -> CapSet:

        caps: Dict[str, Capability] = {}

        media_type = flow.get("media_type")
        if not isinstance(media_type, str):
            raise ValueError("FlowToCapabilities: missing media_type in coded audio flow")
        caps[CapFormatMediaType] = Capability(CapFormatMediaType,
                                              RangeValue(values=(media_type,), type=RangeType.STRING))

        channels, synchronous_media, clock_name = self._require_audio_source(source)
        caps[CapFormatChannelCount] = Capability(CapFormatChannelCount,
                                                 RangeValue(values=(len(channels),), type=RangeType.INT))

        # sample_rate
        sample_rate = self._get_sample_rate(flow)
        caps[CapFormatSampleRate] = Capability(CapFormatSampleRate,
                                               RangeValue(values=(sample_rate,) if sample_rate is not None
                                                          else None, type=RangeType.RATIONAL))

        # sample_depth
        bit_depth = self._get_int(flow, ["bit_depth"])
        caps[CapFormatSampleDepth] = Capability(CapFormatSampleDepth,
                                                RangeValue(values=(bit_depth,) if bit_depth is not None
                                                           else None, type=RangeType.INT))

        layer = flow.get("urn:x-matrox:layer", None)
        format = FormatAudio

        if layer is None:
            format = None
            caps[CapTransportSynchronousMedia] = Capability(CapTransportSynchronousMedia,
                                                            RangeValue(values=(synchronous_media,),
                                                                       type=RangeType.BOOL))

            sender_type = sender.get("sender_type", None)
            if sender_type:
                caps[CapTransport_ST2110_21_SenderType] = Capability(CapTransport_ST2110_21_SenderType,
                                                                     RangeValue(values=(sender_type,)
                                                                                if sender_type is not None
                                                                                else None, type=RangeType.STRING))

            channel_order = sender.get("channel_order", None)
            if channel_order:
                caps[CapTransportChannelOrder] = Capability(CapTransportChannelOrder,
                                                            RangeValue(values=(channel_order,)
                                                                       if channel_order is not None
                                                                       else None, type=RangeType.STRING))

            clk_ref = self._clock_ref_type_from_node_clocks(clock_name, node_clocks)
            caps[CapTransportClockRefType] = Capability(CapTransportClockRefType,
                                                        RangeValue(values=(clk_ref,) if clk_ref is not None
                                                                   else None, type=RangeType.STRING))

            hkep = sender.get("hkep", None)
            if hkep:
                caps[CapTransportHkep] = Capability(CapTransportHkep,
                                                    RangeValue(values=(hkep,) if hkep is not None
                                                               else None, type=RangeType.BOOL))

            privacy = sender.get("privacy", None)
            if privacy:
                caps[CapTransportPrivacy] = Capability(CapTransportPrivacy,
                                                       RangeValue(values=(privacy,) if privacy is not None
                                                                  else None, type=RangeType.BOOL))

        return CapSet(caps=caps, label="Flow", preference=100, format=format, layer=layer)

    def _convert_data_flow_to_capset(self, flow: Dict[str, Any], source: Dict[str, Any],
                                     sender: Dict[str, Any], node_clocks: Optional[list]) -> CapSet:

        caps: Dict[str, Capability] = {}

        media_type = flow.get("media_type")
        if not isinstance(media_type, str):
            raise ValueError("FlowToCapabilities: missing media_type in data flow")
        caps[CapFormatMediaType] = Capability(CapFormatMediaType,
                                              RangeValue(values=(media_type,), type=RangeType.STRING))

        synchronous_media, clock_name = self._require_data_source(source)

        layer = flow.get("urn:x-matrox:layer", None)
        format = FormatData

        if layer is None:
            format = None
            caps[CapTransportSynchronousMedia] = Capability(CapTransportSynchronousMedia,
                                                            RangeValue(values=(synchronous_media,),
                                                                       type=RangeType.BOOL))

            sender_type = sender.get("sender_type", None)
            if sender_type:
                caps[CapTransport_ST2110_21_SenderType] = Capability(CapTransport_ST2110_21_SenderType,
                                                                     RangeValue(values=(sender_type,)
                                                                                if sender_type is not None
                                                                                else None, type=RangeType.STRING))

            clk_ref = self._clock_ref_type_from_node_clocks(clock_name, node_clocks)
            caps[CapTransportClockRefType] = Capability(CapTransportClockRefType,
                                                        RangeValue(values=(clk_ref,) if clk_ref is not None
                                                                   else None, type=RangeType.STRING))

            hkep = sender.get("hkep", None)
            if hkep:
                caps[CapTransportHkep] = Capability(CapTransportHkep,
                                                    RangeValue(values=(hkep,) if hkep is not None
                                                               else None, type=RangeType.BOOL))

            privacy = sender.get("privacy", None)
            if privacy:
                caps[CapTransportPrivacy] = Capability(CapTransportPrivacy,
                                                       RangeValue(values=(privacy,) if privacy is not None
                                                                  else None, type=RangeType.BOOL))

        return CapSet(caps=caps, label="Flow", preference=100, format=format, layer=layer)

    def _convert_mux_flow_to_capset(self, flow: Dict[str, Any], source: Dict[str, Any],
                                    sender: Dict[str, Any], node_clocks: Optional[list]) -> CapSet:

        caps: Dict[str, Capability] = {}

        media_type = flow.get("media_type")
        if not isinstance(media_type, str):
            raise ValueError("FlowToCapabilities: missing media_type in mux flow")
        caps[CapFormatMediaType] = Capability(CapFormatMediaType,
                                              RangeValue(values=(media_type,), type=RangeType.STRING))

        # mux: layers
        v = self._get_int(flow, ["video_layers"])
        a = self._get_int(flow, ["audio_layers"])
        d = self._get_int(flow, ["data_layers"])
        if v is not None:
            caps[CapFormatVideoLayers] = Capability(CapFormatVideoLayers,
                                                    RangeValue(values=(v,) if v is not None
                                                               else None, type=RangeType.INT))
        if a is not None:
            caps[CapFormatAudioLayers] = Capability(CapFormatAudioLayers,
                                                    RangeValue(values=(a,) if a is not None
                                                               else None, type=RangeType.INT))
        if d is not None:
            caps[CapFormatDataLayers] = Capability(CapFormatDataLayers,
                                                   RangeValue(values=(d,) if d is not None
                                                              else None, type=RangeType.INT))

        synchronous_media, clock_name = self._require_mux_source(source)

        layer = flow.get("urn:x-matrox:layer", None)
        format = FormatMux

        if layer is None:
            format = None
            caps[CapTransportSynchronousMedia] = Capability(CapTransportSynchronousMedia,
                                                            RangeValue(values=(synchronous_media,),
                                                                       type=RangeType.BOOL))

            clk_ref = self._clock_ref_type_from_node_clocks(clock_name, node_clocks)
            caps[CapTransportClockRefType] = Capability(CapTransportClockRefType,
                                                        RangeValue(values=(clk_ref,) if clk_ref is not None
                                                                   else None, type=RangeType.STRING))

            hkep = sender.get("hkep", None)
            if hkep:
                caps[CapTransportHkep] = Capability(CapTransportHkep,
                                                    RangeValue(values=(hkep,) if hkep is not None
                                                               else None, type=RangeType.BOOL))

            privacy = sender.get("privacy", None)
            if privacy:
                caps[CapTransportPrivacy] = Capability(CapTransportPrivacy,
                                                       RangeValue(values=(privacy,) if privacy is not None
                                                                  else None, type=RangeType.BOOL))

        return CapSet(caps=caps, label="Flow", preference=100, format=format, layer=layer)

    def _is_raw_audio(self, flow: Dict[str, Any]) -> bool:
        mt = flow.get("media_type")
        if isinstance(mt, str) and mt.lower().startswith("audio/l"):
            return True
        return False

    def _is_coded_audio(self, flow: Dict[str, Any]) -> bool:
        mt = flow.get("media_type")
        if isinstance(mt, str):
            mtl = mt.lower()
            if mtl in ("audio/mpeg4-generic", "audio/mp4a-latm", "audio/mp4a-adts", "audio/am824"):
                return True
            if mtl.startswith("audio/l"):
                return False
        return False

    def _is_coded_video(self, flow: Dict[str, Any]) -> bool:
        mt = flow.get("media_type")
        if isinstance(mt, str):
            mtl = mt.lower()
            if mtl in ("video/jxsv", "video/h264", "video/h265"):
                return True
            if mtl == "video/raw":
                return False
        return False

    def _get_sample_rate(self, flow: Dict[str, Any]) -> Optional[Fraction]:
        # favor sample_rate over grain_rate
        sr = flow.get("sample_rate")
        if isinstance(sr, dict):
            num = sr.get("numerator")
            den = sr.get("denominator", 1)
            if isinstance(num, int) and isinstance(den, int) and den != 0:
                return Fraction(num, den)
        if isinstance(sr, int):
            return Fraction(sr, 1)

        # fallback to grain_rate when present (rational)
        return self._get_rational(flow, "grain_rate")

    def _get_rational(self, obj: Dict[str, Any], key: str) -> Optional[Fraction]:
        r = obj.get(key)
        if isinstance(r, dict):
            num = r.get("numerator")
            den = r.get("denominator", 1)
            if isinstance(num, int) and isinstance(den, int) and den != 0:
                return Fraction(num, den)
        return None

    def _get_int(self, obj: Dict[str, Any], keys: Union[Tuple[str, ...], List[str]]) -> Optional[int]:
        for k in keys:
            v = obj.get(k)
            if isinstance(v, int):
                return v
        return None

    def _require_audio_source(self, source: Dict[str, Any]) -> Tuple[list, bool, str]:

        channels = []
        synchronous_media = False
        clock_name = ""

        if not isinstance(source, dict):
            raise ValueError("FlowToCapabilities: missing source for audio flow")

        channels = source.get("channels")
        if not isinstance(channels, list):
            raise ValueError("FlowToCapabilities: source missing channels for audio flow")

        synchronous_media = source.get("synchronous_media", False)
        if not isinstance(synchronous_media, bool):
            raise ValueError("FlowToCapabilities: source missing synchronous_media for audio flow")

        clock_name = source.get("clock_name")
        if not isinstance(clock_name, str):
            raise ValueError("FlowToCapabilities: source missing clock_name")

        return channels, synchronous_media, clock_name

    def _clock_ref_type_from_node_clocks(self, clock_name: Optional[str], node_clocks: Optional[list]) -> Optional[str]:
        """
        Map a Source/Flow clock_name to a transport clock ref type using Node.clocks from IS-04 v1.3.
        We return:
          - "Ptp" if the referenced clock ref_type indicates PTP (e.g., "ptp", "smpte_2110_10", "smpte-2059-2").
          - "Internal" if ref_type indicates internal or unknown.
          - None if clock_name is None or not found.
        """
        if not clock_name or not isinstance(clock_name, str):
            return None
        if not node_clocks or not isinstance(node_clocks, list):
            return None

        # Normalize helpers
        def _to_str(v: Any) -> Optional[str]:
            return v if isinstance(v, str) else None

        name_lower = clock_name.lower()
        for clk in node_clocks:
            if not isinstance(clk, dict):
                raise ValueError("FlowToCapabilities: node_clocks entry "
                                 "is not a dict (invalid according to IS-04 schema)")
            if not isinstance(clk.get("name"), str):
                raise ValueError("FlowToCapabilities: node_clocks entry "
                                 "is missing name (invalid according to IS-04 schema)")
            if not isinstance(clk.get("ref_type"), str):
                raise ValueError("FlowToCapabilities: node_clocks entry "
                                 "is missing ref_type (invalid according to IS-04 schema)")

            if clk.get("name").lower() != name_lower:
                continue

            ref_type = clk.get("ref_type")
            if ref_type not in ("ptp", "internal"):
                raise ValueError("FlowToCapabilities: node_clocks entry "
                                 "has invalid ref_type (invalid according to IS-04 schema)")

            return ref_type

        # Not found
        return None

    def _require_video_source(self, source: Dict[str, Any]) -> Tuple[bool, str]:

        synchronous_media = False
        clock_name = ""

        if not isinstance(source, dict):
            raise ValueError("FlowToCapabilities: missing source for video flow")

        synchronous_media = source.get("synchronous_media", False)
        if not isinstance(synchronous_media, bool):
            raise ValueError("FlowToCapabilities: source missing synchronous_media for video flow")

        clock_name = source.get("clock_name")
        if not isinstance(clock_name, str):
            raise ValueError("FlowToCapabilities: source missing clock_name")

        return synchronous_media, clock_name

    def _require_data_source(self, source: Dict[str, Any]) -> Tuple[bool, str]:

        synchronous_media = False
        clock_name = ""

        if not isinstance(source, dict):
            raise ValueError("FlowToCapabilities: missing source for data flow")

        synchronous_media = source.get("synchronous_media", False)
        if not isinstance(synchronous_media, bool):
            raise ValueError("FlowToCapabilities: source missing synchronous_media for data flow")

        clock_name = source.get("clock_name")
        if not isinstance(clock_name, str):
            raise ValueError("FlowToCapabilities: source missing clock_name")

        return synchronous_media, clock_name

    def _require_mux_source(self, source: Dict[str, Any]) -> Tuple[bool, str]:

        synchronous_media = False
        clock_name = ""

        if not isinstance(source, dict):
            raise ValueError("FlowToCapabilities: missing source for mux flow")

        synchronous_media = source.get("synchronous_media", False)
        if not isinstance(synchronous_media, bool):
            raise ValueError("FlowToCapabilities: source missing synchronous_media for mux flow")

        clock_name = source.get("clock_name")
        if not isinstance(clock_name, str):
            raise ValueError("FlowToCapabilities: source missing clock_name")

        return synchronous_media, clock_name

    def _get_component_depth(self, components: list) -> Optional[int]:
        # Use luma (Y) if present, otherwise first component bit_depth
        if not components:
            return None
        y = next((c for c in components if isinstance(c, dict) and c.get("name") in ("Y", "R")), None)
        c0 = y if y is not None else components[0]
        bd = c0.get("bit_depth") if isinstance(c0, dict) else None
        return bd if isinstance(bd, int) else None

    def _infer_sampling_from_components(self, components: list, fw: int, fh: int) -> Optional[str]:
        # Infer sampling for common YCbCr layouts; handle RGB as well
        names = [c.get("name") for c in components if isinstance(c, dict)]
        if set(names) >= {"R", "G", "B"}:
            return "RGB"
        if not (set(names) >= {"Y", "Cb", "Cr"}):
            return None
        y = next((c for c in components if c.get("name") == "Y"), None)
        cb = next((c for c in components if c.get("name") == "Cb"), None)
        cr = next((c for c in components if c.get("name") == "Cr"), None)

        if not y or not cb or not cr:
            return None
        yw, yh = y.get("width"), y.get("height")
        cbw, cbh = cb.get("width"), cb.get("height")
        crw, crh = cr.get("width"), cr.get("height")
        if yw == fw and yh == fh:
            if cbw == fw and cbh == fh and crw == fw and crh == fh:
                return "YCbCr-4:4:4"
            if cbw == fw // 2 and cbh == fh and crw == fw // 2 and crh == fh:
                return "YCbCr-4:2:2"
            if cbw == fw // 2 and cbh == fh // 2 and crw == fw // 2 and crh == fh // 2:
                return "YCbCr-4:2:0"
        return None


def convert_flow_to_capabilities(flow: Dict[str, Any], source: Dict[str, Any],
                                 sender: Dict[str, Any],
                                 node_clocks: Optional[list] = None) -> Caps:
    return FlowToCapabilitiesConverter().convert(flow, source, sender, node_clocks)
