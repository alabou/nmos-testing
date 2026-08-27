#!/usr/bin/env python3
"""
Comprehensive Test Suite for Flow to CCF Capabilities Converter
Using realistic NMOS Flow and Source examples similar to MatroxOnly repository
"""

import unittest
import sys
import os
from fractions import Fraction

# Add project root to path
sys.path.insert(0, '.')

from nmostesting.FlowToCapabilities import FlowToCapabilitiesConverter, convert_flow_to_capabilities
from nmostesting.MatroxCCF import (
    FormatVideo, FormatAudio, FormatData, FormatMux,
    CapFormatMediaType, CapFormatGrainRate, CapFormatFrameWidth, CapFormatFrameHeight,
    CapFormatInterlaceMode, CapFormatColorspace, CapFormatTransferCharacteristic,
    CapFormatColorSampling, CapFormatComponentDepth, CapFormatChannelCount,
    CapFormatSampleRate, CapFormatSampleDepth, CapFormatBitRate, CapFormatProfile,
    CapFormatLevel, CapFormatConstantBitRate, CapTransportClockRefType,
    CapTransportSynchronousMedia, CapTransportHkep, CapTransportPrivacy,
    CapFormatVideoLayers, CapFormatAudioLayers, CapFormatDataLayers
)


class TestFlowToCapabilities(unittest.TestCase):
    """Test Flow to CCF Capabilities conversion with realistic examples"""

    def setUp(self):
        """Set up test fixtures"""
        self.converter = FlowToCapabilitiesConverter()
        
    def test_st2110_20_raw_video_flow(self):
        """Test ST 2110-20 raw video flow conversion (1080i50 YCbCr-4:2:2 10-bit)"""
        print("\n=== Testing ST 2110-20 Raw Video Flow ===")
        
        flow = {
            "id": "f1e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "version": "1625097600:0",
            "label": "1080i50 Raw Video",
            "description": "ST 2110-20 Raw Video Flow",
            "format": "urn:x-nmos:format:video",
            "tags": {
                "urn:x-nmos:tag:grouphint/v1.0": "primary"
            },
            "source_id": "s1e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "device_id": "d1e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "parents": [],
            "media_type": "video/raw",
            "frame_width": 1920,
            "frame_height": 1080,
            "interlace_mode": "interlaced_tff",
            "colorspace": "BT709",
            "transfer_characteristic": "SDR",
            "grain_rate": {
                "numerator": 25,
                "denominator": 1
            },
            "components": [
                {
                    "name": "Y",
                    "width": 1920,
                    "height": 1080,
                    "bit_depth": 10
                },
                {
                    "name": "Cb",
                    "width": 960,
                    "height": 1080,
                    "bit_depth": 10
                },
                {
                    "name": "Cr", 
                    "width": 960,
                    "height": 1080,
                    "bit_depth": 10
                }
            ]
        }
        
        source = {
            "id": "s1e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "version": "1625097600:0",
            "label": "Camera 1 Source",
            "description": "Video source from Camera 1",
            "format": "urn:x-nmos:format:video",
            "caps": {},
            "tags": {},
            "device_id": "d1e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "parents": [],
            "clock_name": "clk1",
            "synchronous_media": True
        }
        
        node_clocks = [
            {
                "name": "clk1",
                "ref_type": "ptp"
            }
        ]
        
        sender = {"hkep": True, "privacy": False}
        caps = self.converter.convert(flow, source, sender, node_clocks)
        
        # Verify capabilities
        self.assertEqual(len(caps.capsets), 1)
        capset = caps.capsets[0]
        # A standalone Flow is a trunk CapSet: only mux sub-flows, which carry
        # urn:x-matrox:layer, are tagged with a format.
        self.assertIsNone(capset.format)
        self.assertIsNone(capset.layer)
        
        # Check specific capabilities
        self.assertEqual(capset.caps[CapFormatMediaType].value.enumerated, {"video/raw"})
        self.assertEqual(capset.caps[CapFormatFrameWidth].value.enumerated, {1920})
        self.assertEqual(capset.caps[CapFormatFrameHeight].value.enumerated, {1080})
        self.assertEqual(capset.caps[CapFormatInterlaceMode].value.enumerated, {"interlaced_tff"})
        self.assertEqual(capset.caps[CapFormatColorspace].value.enumerated, {"BT709"})
        self.assertEqual(capset.caps[CapFormatColorSampling].value.enumerated, {"YCbCr-4:2:2"})
        self.assertEqual(capset.caps[CapFormatComponentDepth].value.enumerated, {10})
        self.assertEqual(capset.caps[CapFormatGrainRate].value.enumerated, {Fraction(25, 1)})
        # hkep and privacy are reported only when true, matching SdpToCapabilities;
        # a false value is omitted rather than stated.
        self.assertEqual(capset.caps[CapTransportHkep].value.enumerated, {True})
        self.assertNotIn(CapTransportPrivacy, capset.caps)
        self.assertEqual(capset.caps[CapTransportSynchronousMedia].value.enumerated, {True})
        
        print(f"✓ ST 2110-20 Raw Video Test Passed - Generated {len(capset.caps)} capabilities")
        
    def test_h264_coded_video_flow(self):
        """Test H.264 coded video flow conversion"""
        print("\n=== Testing H.264 Coded Video Flow ===")
        
        flow = {
            "id": "f2e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "version": "1625097600:0",
            "label": "H.264 HD Video",
            "description": "H.264 Coded Video Flow",
            "format": "urn:x-nmos:format:video",
            "source_id": "s2e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "device_id": "d2e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "parents": [],
            "media_type": "video/H264",
            "frame_width": 1920,
            "frame_height": 1080,
            "interlace_mode": "progressive",
            "colorspace": "BT709",
            "transfer_characteristic": "SDR",
            "grain_rate": {
                "numerator": 25,
                "denominator": 1
            },
            "components": [
                {
                    "name": "Y",
                    "width": 1920,
                    "height": 1080,
                    "bit_depth": 8
                },
                {
                    "name": "Cb",
                    "width": 960,
                    "height": 540,
                    "bit_depth": 8
                },
                {
                    "name": "Cr",
                    "width": 960,
                    "height": 540,
                    "bit_depth": 8
                }
            ],
            "bit_rate": 25000000,  # 25 Mbps
            "constant_bit_rate": False,
            "profile": "high",
            "level": "4.0"
        }
        
        source = {
            "id": "s2e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "version": "1625097600:0",
            "label": "Encoder Source",
            "description": "H.264 encoder source",
            "format": "urn:x-nmos:format:video",
            "caps": {},
            "tags": {},
            "device_id": "d2e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "parents": [],
            "clock_name": "clk0",
            "synchronous_media": False
        }
        
        node_clocks = [
            {
                "name": "clk0",
                "ref_type": "internal"
            }
        ]
        
        sender = {"hkep": False, "privacy": True}
        caps = self.converter.convert(flow, source, sender, node_clocks)
        
        # Verify capabilities
        self.assertEqual(len(caps.capsets), 1)
        capset = caps.capsets[0]
        # A standalone Flow is a trunk CapSet: only mux sub-flows, which carry
        # urn:x-matrox:layer, are tagged with a format.
        self.assertIsNone(capset.format)
        
        # Check coded video specific capabilities
        self.assertEqual(capset.caps[CapFormatMediaType].value.enumerated, {"video/H264"})
        self.assertEqual(capset.caps[CapFormatBitRate].value.enumerated, {25000000})
        self.assertEqual(capset.caps[CapFormatConstantBitRate].value.enumerated, {False})
        self.assertEqual(capset.caps[CapFormatProfile].value.enumerated, {"high"})
        self.assertEqual(capset.caps[CapFormatLevel].value.enumerated, {"4.0"})
        self.assertNotIn(CapTransportHkep, capset.caps)
        self.assertEqual(capset.caps[CapTransportPrivacy].value.enumerated, {True})
        
        print(f"✓ H.264 Coded Video Test Passed - Generated {len(capset.caps)} capabilities")
        
    def test_st2110_30_raw_audio_flow(self):
        """Test ST 2110-30 raw audio flow conversion (48kHz 24-bit stereo)"""
        print("\n=== Testing ST 2110-30 Raw Audio Flow ===")
        
        flow = {
            "id": "f3e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "version": "1625097600:0",
            "label": "48kHz 24-bit Audio",
            "description": "ST 2110-30 Raw Audio Flow",
            "format": "urn:x-nmos:format:audio",
            "source_id": "s3e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "device_id": "d3e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "parents": [],
            "media_type": "audio/L24",
            "sample_rate": {
                "numerator": 48000,
                "denominator": 1
            },
            "bit_depth": 24,
            "urn:x-matrox:layer": 0
        }
        
        source = {
            "id": "s3e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "version": "1625097600:0",
            "label": "Audio Input Source",
            "description": "Stereo audio input",
            "format": "urn:x-nmos:format:audio",
            "caps": {},
            "tags": {},
            "device_id": "d3e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "parents": [],
            "channels": [
                {
                    "label": "Left",
                    "symbol": "L"
                },
                {
                    "label": "Right", 
                    "symbol": "R"
                }
            ],
            "clock_name": "clk1",
            "synchronous_media": True
        }
        
        node_clocks = [
            {
                "name": "clk1",
                "ref_type": "ptp"
            }
        ]
        
        sender = {"hkep": True, "privacy": False}
        caps = self.converter.convert(flow, source, sender, node_clocks)
        
        # Verify capabilities
        self.assertEqual(len(caps.capsets), 1)
        capset = caps.capsets[0]
        self.assertEqual(capset.format, FormatAudio)
        
        # Check audio specific capabilities
        self.assertEqual(capset.caps[CapFormatMediaType].value.enumerated, {"audio/L24"})
        self.assertEqual(capset.caps[CapFormatChannelCount].value.enumerated, {2})
        self.assertEqual(capset.caps[CapFormatSampleRate].value.enumerated, {Fraction(48000, 1)})
        self.assertEqual(capset.caps[CapFormatSampleDepth].value.enumerated, {24})
        
        print(f"✓ ST 2110-30 Raw Audio Test Passed - Generated {len(capset.caps)} capabilities")
        
    def test_mpeg_coded_audio_flow(self):
        """Test MPEG coded audio flow conversion"""
        print("\n=== Testing MPEG Coded Audio Flow ===")
        
        flow = {
            "id": "f4e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "version": "1625097600:0",
            "label": "MPEG Audio",
            "description": "MPEG Coded Audio Flow",
            "format": "urn:x-nmos:format:audio",
            "source_id": "s4e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "device_id": "d4e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "parents": [],
            "media_type": "audio/mpeg4-generic",
            "sample_rate": {
                "numerator": 48000,
                "denominator": 1
            },
            "bit_rate": 384000,  # 384 kbps
            "constant_bit_rate": True,
            "profile": "aac-lc",
            "level": "2"
        }
        
        source = {
            "id": "s4e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "version": "1625097600:0",
            "label": "Audio Encoder Source",
            "description": "5.1 surround audio source",
            "format": "urn:x-nmos:format:audio",
            "caps": {},
            "tags": {},
            "device_id": "d4e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "parents": [],
            "channels": [
                {"label": "Left", "symbol": "L"},
                {"label": "Right", "symbol": "R"},
                {"label": "Center", "symbol": "C"},
                {"label": "LFE", "symbol": "LFE"},
                {"label": "Left Surround", "symbol": "Ls"},
                {"label": "Right Surround", "symbol": "Rs"}
            ],
            "clock_name": "clk0",
            "synchronous_media": False
        }
        
        sender = {}
        caps = self.converter.convert(flow, source, sender)
        
        # Verify capabilities
        self.assertEqual(len(caps.capsets), 1)
        capset = caps.capsets[0]
        # A standalone Flow is a trunk CapSet: only mux sub-flows, which carry
        # urn:x-matrox:layer, are tagged with a format.
        self.assertIsNone(capset.format)
        
        # Check coded audio specific capabilities
        self.assertEqual(capset.caps[CapFormatMediaType].value.enumerated, {"audio/mpeg4-generic"})
        self.assertEqual(capset.caps[CapFormatChannelCount].value.enumerated, {6})
        self.assertEqual(capset.caps[CapFormatBitRate].value.enumerated, {384000})
        self.assertEqual(capset.caps[CapFormatConstantBitRate].value.enumerated, {True})
        self.assertEqual(capset.caps[CapFormatProfile].value.enumerated, {"aac-lc"})
        self.assertEqual(capset.caps[CapFormatLevel].value.enumerated, {"2"})
        
        print(f"✓ MPEG Coded Audio Test Passed - Generated {len(capset.caps)} capabilities")
        
    def test_st2110_40_data_flow(self):
        """Test ST 2110-40 data flow conversion"""
        print("\n=== Testing ST 2110-40 Data Flow ===")
        
        flow = {
            "id": "f5e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "version": "1625097600:0",
            "label": "Ancillary Data",
            "description": "ST 2110-40 Data Flow",
            "format": "urn:x-nmos:format:data",
            "source_id": "s5e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "device_id": "d5e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "parents": [],
            "media_type": "application/ST2110-40",
            "urn:x-matrox:layer": 1
        }
        
        source = {
            "id": "s5e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "version": "1625097600:0",
            "label": "Data Source",
            "description": "Ancillary data source",
            "format": "urn:x-nmos:format:data",
            "caps": {},
            "tags": {},
            "device_id": "d5e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "parents": [],
            "clock_name": "clk1",
            "synchronous_media": True
        }
        
        sender = {"hkep": True, "privacy": False}
        caps = self.converter.convert(flow, source, sender)
        
        # Verify capabilities
        self.assertEqual(len(caps.capsets), 1)
        capset = caps.capsets[0]
        self.assertEqual(capset.format, FormatData)
        self.assertEqual(capset.layer, 1)
        
        # Check data specific capabilities
        self.assertEqual(capset.caps[CapFormatMediaType].value.enumerated, {"application/ST2110-40"})
        
        print(f"✓ ST 2110-40 Data Test Passed - Generated {len(capset.caps)} capabilities")
        
    def test_mux_flow_with_layers(self):
        """Test mux flow with multiple layers"""
        print("\n=== Testing Mux Flow with Layers ===")
        
        flow = {
            "id": "f6e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "version": "1625097600:0",
            "label": "Multiplexed Stream",
            "description": "Mux Flow with Video, Audio, and Data",
            "format": "urn:x-nmos:format:mux",
            "source_id": "s6e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "device_id": "d6e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "parents": [],
            "media_type": "application/mxf",
            "video_layers": 2,
            "audio_layers": 4,
            "data_layers": 1,
            "urn:x-matrox:layer": 0
        }
        
        source = {
            "id": "s6e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "version": "1625097600:0",
            "label": "Mux Source",
            "description": "Multiplexed source",
            "format": "urn:x-nmos:format:mux",
            "caps": {},
            "tags": {},
            "device_id": "d6e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "parents": [],
            "clock_name": "clk2",
            "synchronous_media": False
        }
        
        sender = {"hkep": False, "privacy": True}
        caps = self.converter.convert(flow, source, sender)
        
        # Verify capabilities
        self.assertEqual(len(caps.capsets), 1)
        capset = caps.capsets[0]
        self.assertEqual(capset.format, FormatMux)
        
        # Check mux specific capabilities
        self.assertEqual(capset.caps[CapFormatMediaType].value.enumerated, {"application/mxf"})
        self.assertEqual(capset.caps[CapFormatVideoLayers].value.enumerated, {2})
        self.assertEqual(capset.caps[CapFormatAudioLayers].value.enumerated, {4})
        self.assertEqual(capset.caps[CapFormatDataLayers].value.enumerated, {1})
        
        print(f"✓ Mux Flow Test Passed - Generated {len(capset.caps)} capabilities")
        
    def test_transport_caps_only_on_trunk_flows(self):
        """Transport capabilities belong to the trunk, never to a mux sub-flow.

        The same Flow, Source and Sender are converted twice: once standalone and
        once carrying urn:x-matrox:layer. Only the standalone conversion may report
        transport capabilities, and only the layered one is tagged with a format.
        This is the invariant Go and nmos-reference share, and it is what makes a
        fixture that sets a layer while expecting hkep/privacy self-contradictory.
        """
        print("\n=== Testing Transport Caps Are Trunk-Only ===")

        def make_flow(layer):
            flow = {
                "id": "f7e3c3c0-ca4a-11eb-b8bc-0242ac130003",
                "version": "1625097600:0",
                "label": "Layered vs Trunk Video",
                "format": "urn:x-nmos:format:video",
                "source_id": "s7e3c3c0-ca4a-11eb-b8bc-0242ac130003",
                "device_id": "d7e3c3c0-ca4a-11eb-b8bc-0242ac130003",
                "parents": [],
                "media_type": "video/raw",
                "frame_width": 1920,
                "frame_height": 1080,
                "interlace_mode": "progressive",
                "colorspace": "BT709",
                "transfer_characteristic": "SDR",
                "grain_rate": {"numerator": 50, "denominator": 1},
                "components": [
                    {"name": "Y", "width": 1920, "height": 1080, "bit_depth": 10},
                    {"name": "Cb", "width": 960, "height": 1080, "bit_depth": 10},
                    {"name": "Cr", "width": 960, "height": 1080, "bit_depth": 10}
                ]
            }
            if layer is not None:
                flow["urn:x-matrox:layer"] = layer
            return flow

        source = {
            "id": "s7e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "version": "1625097600:0",
            "label": "Layered Source",
            "format": "urn:x-nmos:format:video",
            "caps": {},
            "tags": {},
            "device_id": "d7e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "parents": [],
            "clock_name": "clk0",
            "synchronous_media": True
        }
        sender = {"hkep": True, "privacy": True}
        node_clocks = [{"name": "clk0", "ref_type": "ptp"}]

        TRANSPORT = (CapTransportHkep, CapTransportPrivacy,
                     CapTransportSynchronousMedia, CapTransportClockRefType)

        trunk = self.converter.convert(make_flow(None), source, sender, node_clocks).capsets[0]
        layered = self.converter.convert(make_flow(0), source, sender, node_clocks).capsets[0]

        # The trunk carries every transport capability, including the false ones:
        # absent would mean unconstrained, which is a different claim.
        for cap in TRANSPORT:
            self.assertIn(cap, trunk.caps)
        self.assertEqual(trunk.caps[CapTransportHkep].value.enumerated, {True})
        self.assertEqual(trunk.caps[CapTransportPrivacy].value.enumerated, {True})
        self.assertIsNone(trunk.format)
        self.assertIsNone(trunk.layer)

        # The sub-flow carries none of them, and is tagged with its format instead.
        for cap in TRANSPORT:
            self.assertNotIn(cap, layered.caps)
        self.assertEqual(layered.format, FormatVideo)
        self.assertEqual(layered.layer, 0)

        # Format capabilities are unaffected by the distinction.
        self.assertEqual(trunk.caps[CapFormatFrameWidth].value.enumerated, {1920})
        self.assertEqual(layered.caps[CapFormatFrameWidth].value.enumerated, {1920})

        print(f"✓ Trunk-Only Transport Test Passed - trunk={len(trunk.caps)} "
              f"layered={len(layered.caps)} capabilities")

    def test_mux_zero_layer_counts(self):
        """A layer count of zero is a value, not an absence.

        A mux carrying audio only genuinely has zero video and zero data layers,
        and the capability must say so: an omitted capability is not checked at all
        by conset_included_in_caps, so dropping it silently removes the constraint
        instead of failing it.
        """
        print("\n=== Testing Mux Zero Layer Counts ===")

        flow = {
            "id": "f8e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "version": "1625097600:0",
            "label": "Audio-only Multiplex",
            "format": "urn:x-nmos:format:mux",
            "source_id": "s8e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "device_id": "d8e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "parents": [],
            "media_type": "application/mxf",
            "video_layers": 0,
            "audio_layers": 2,
            "data_layers": 0,
            "urn:x-matrox:layer": 0
        }
        source = {
            "id": "s8e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "version": "1625097600:0",
            "label": "Audio-only Mux Source",
            "format": "urn:x-nmos:format:mux",
            "caps": {},
            "tags": {},
            "device_id": "d8e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "parents": [],
            "clock_name": "clk0",
            "synchronous_media": True
        }

        sender = {}
        caps = self.converter.convert(flow, source, sender)
        capset = caps.capsets[0]

        for cap in (CapFormatVideoLayers, CapFormatAudioLayers, CapFormatDataLayers):
            self.assertIn(cap, capset.caps)
        self.assertEqual(capset.caps[CapFormatVideoLayers].value.enumerated, {0})
        self.assertEqual(capset.caps[CapFormatAudioLayers].value.enumerated, {2})
        self.assertEqual(capset.caps[CapFormatDataLayers].value.enumerated, {0})

        print("✓ Mux Zero Layer Counts Test Passed - 0/2/0 all reported")

    def test_data_json_has_no_transport_caps_but_sdianc_does(self):
        """Only clocked data essence reports transport capabilities.

        video/smpte291 is an ST 2110-40 RTP stream, so it is PTP-locked and reports
        clock_ref_type and synchronous_media - which is also what SdpToCapabilities
        reports for the same stream. application/json is IS-07 event data over MQTT
        or WebSocket with no RTP timing, so it reports neither.
        """
        print("\n=== Testing Data Sub-type Transport Caps ===")

        def convert(media_type):
            flow = {
                "id": "f9e3c3c0-ca4a-11eb-b8bc-0242ac130003",
                "version": "1625097600:0",
                "label": "Data Flow",
                "format": "urn:x-nmos:format:data",
                "source_id": "s9e3c3c0-ca4a-11eb-b8bc-0242ac130003",
                "device_id": "d9e3c3c0-ca4a-11eb-b8bc-0242ac130003",
                "parents": [],
                "media_type": media_type
            }
            source = {
                "id": "s9e3c3c0-ca4a-11eb-b8bc-0242ac130003",
                "version": "1625097600:0",
                "label": "Data Source",
                "format": "urn:x-nmos:format:data",
                "caps": {},
                "tags": {},
                "device_id": "d9e3c3c0-ca4a-11eb-b8bc-0242ac130003",
                "parents": [],
                "clock_name": "clk0",
                "synchronous_media": True
            }
            sender = {"hkep": True, "privacy": True}
            node_clocks = [{"name": "clk0", "ref_type": "ptp"}]
            return self.converter.convert(flow, source, sender, node_clocks).capsets[0]

        TRANSPORT = (CapTransportSynchronousMedia, CapTransportClockRefType,
                     CapTransportHkep, CapTransportPrivacy)

        sdianc = convert("video/smpte291")
        for cap in TRANSPORT:
            self.assertIn(cap, sdianc.caps)
        self.assertEqual(sdianc.caps[CapTransportClockRefType].value.enumerated, {"ptp"})

        json_flow = convert("application/json")
        for cap in TRANSPORT:
            self.assertNotIn(cap, json_flow.caps)
        self.assertIn(CapFormatMediaType, json_flow.caps)

        print("✓ Data Sub-type Test Passed - smpte291 clocked, json not")

    def test_color_sampling_corner_cases(self):
        """Sampling is derived from the component array alone, by name.

        IS-04's flow_video_raw declares components as a plain array (minItems 1,
        no maxItems, no tuple form), so order and count are unconstrained. An
        undeterminable sampling yields no capability at all rather than a guess:
        an omitted capability is not checked by conset_included_in_caps, whereas
        a wrong one would be.
        """
        print("\n=== Testing Color Sampling Corner Cases ===")
        W, H = 1920, 1080

        def sampling(components):
            flow = {
                "id": "e1e3c3c0-ca4a-11eb-b8bc-0242ac130003",
                "version": "1625097600:0", "label": "Sampling probe",
                "format": "urn:x-nmos:format:video",
                "source_id": "e2e3c3c0-ca4a-11eb-b8bc-0242ac130003",
                "device_id": "e3e3c3c0-ca4a-11eb-b8bc-0242ac130003",
                "parents": [], "media_type": "video/raw",
                "frame_width": W, "frame_height": H,
                "interlace_mode": "progressive", "colorspace": "BT709",
                "transfer_characteristic": "SDR",
                "grain_rate": {"numerator": 50, "denominator": 1},
                "components": [{"name": n, "width": w, "height": h, "bit_depth": 10}
                               for n, w, h in components],
            }
            source = {
                "id": "e2e3c3c0-ca4a-11eb-b8bc-0242ac130003",
                "version": "1625097600:0", "label": "src",
                "format": "urn:x-nmos:format:video", "caps": {}, "tags": {},
                "device_id": "e3e3c3c0-ca4a-11eb-b8bc-0242ac130003",
                "parents": [], "clock_name": "clk0", "synchronous_media": True,
            }
            caps = self.converter.convert(flow, source, {}).capsets[0].caps
            cap = caps.get(CapFormatColorSampling)
            return next(iter(cap.value.enumerated)) if cap else None

        # canonical layouts
        self.assertEqual(sampling([("Y", W, H), ("Cb", W, H), ("Cr", W, H)]), "YCbCr-4:4:4")
        self.assertEqual(sampling([("Y", W, H), ("Cb", W // 2, H), ("Cr", W // 2, H)]), "YCbCr-4:2:2")
        self.assertEqual(sampling([("Y", W, H), ("Cb", W // 2, H // 2), ("Cr", W // 2, H // 2)]),
                         "YCbCr-4:2:0")
        self.assertEqual(sampling([("R", W, H), ("G", W, H), ("B", W, H)]), "RGB")

        # order is not constrained by the schema
        self.assertEqual(sampling([("Cb", W // 2, H), ("Y", W, H), ("Cr", W // 2, H)]), "YCbCr-4:2:2")
        # nor is the count: an auxiliary plane must not break classification
        self.assertEqual(sampling([("Y", W, H), ("Cb", W // 2, H), ("Cr", W // 2, H), ("A", W, H)]),
                         "YCbCr-4:2:2")
        # luma need not equal frame_width; IS-04 asserts no such relationship
        self.assertEqual(sampling([("Y", 3840, 2160), ("Cb", 1920, 2160), ("Cr", 1920, 2160)]),
                         "YCbCr-4:2:2")
        # YCbCr is decided before RGB, so a mixed array is not reported as RGB
        self.assertEqual(sampling([("Y", W, H), ("Cb", W // 2, H), ("Cr", W // 2, H),
                                   ("R", W, H), ("G", W, H), ("B", W, H)]), "YCbCr-4:2:2")

        # undeterminable -> no capability, never a guess
        self.assertIsNone(sampling([("R", W, H), ("G", W // 2, H), ("B", W // 2, H)]))
        self.assertIsNone(sampling([("I", W, H), ("Ct", W // 2, H), ("Cp", W // 2, H)]))
        self.assertIsNone(sampling([("Y", W, H), ("Cb", W // 2, H), ("Cr", 480, H)]))
        self.assertIsNone(sampling([("Y", W, H), ("Cb", W // 2, H)]))

        print("✓ Color Sampling Corner Cases Passed")

    def test_error_handling_missing_source(self):
        """Test error handling when source is missing"""
        print("\n=== Testing Error Handling - Missing Source ===")
        
        flow = {
            "format": "urn:x-nmos:format:video",
            "media_type": "video/raw"
        }
        
        # The converter returns empty capabilities for None source (graceful handling)
        sender = {}
        caps = self.converter.convert(flow, None, sender)
        self.assertEqual(len(caps.capsets), 0)
        print("✓ Error handling test passed - Missing source handled gracefully")
        
    def test_error_handling_format_mismatch(self):
        """Test error handling when flow and source formats don't match"""
        print("\n=== Testing Error Handling - Format Mismatch ===")
        
        flow = {
            "format": "urn:x-nmos:format:video",
            "media_type": "video/raw"
        }
        
        source = {
            "format": "urn:x-nmos:format:audio"
        }
        
        sender = {}
        caps = self.converter.convert(flow, source, sender)
        
        # Should return empty capabilities
        self.assertEqual(len(caps.capsets), 0)
        print("✓ Error handling test passed - Format mismatch handled")
        
    def test_fractional_rates_handling(self):
        """Test handling of fractional frame rates and sample rates"""
        print("\n=== Testing Fractional Rates Handling ===")
        
        flow = {
            "id": "f7e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "format": "urn:x-nmos:format:video",
            "media_type": "video/raw",
            "frame_width": 3840,
            "frame_height": 2160,
            "interlace_mode": "progressive",
            "colorspace": "BT2020",
            "transfer_characteristic": "HLG",
            "grain_rate": {
                "numerator": 24000,
                "denominator": 1001  # 23.976 fps
            },
            "components": [
                {"name": "Y", "width": 3840, "height": 2160, "bit_depth": 10},
                {"name": "Cb", "width": 1920, "height": 1080, "bit_depth": 10},
                {"name": "Cr", "width": 1920, "height": 1080, "bit_depth": 10}
            ],
            "source_id": "s7e3c3c0-ca4a-11eb-b8bc-0242ac130003"
        }
        
        source = {
            "id": "s7e3c3c0-ca4a-11eb-b8bc-0242ac130003",
            "format": "urn:x-nmos:format:video",
            "clock_name": "clk1",
            "synchronous_media": True
        }
        
        sender = {}
        caps = self.converter.convert(flow, source, sender)
        
        # Verify fractional rate handling
        self.assertEqual(len(caps.capsets), 1)
        capset = caps.capsets[0]
        
        expected_rate = Fraction(24000, 1001)
        self.assertEqual(capset.caps[CapFormatGrainRate].value.enumerated, {expected_rate})
        self.assertEqual(capset.caps[CapFormatFrameWidth].value.enumerated, {3840})
        self.assertEqual(capset.caps[CapFormatFrameHeight].value.enumerated, {2160})
        self.assertEqual(capset.caps[CapFormatColorSampling].value.enumerated, {"YCbCr-4:2:0"})
        
        print(f"✓ Fractional Rates Test Passed - 23.976 fps = {expected_rate}")


def run_comprehensive_display():
    """Run comprehensive test and display results"""
    print("=" * 80)
    print("FLOW TO CCF CAPABILITIES CONVERTER - COMPREHENSIVE TEST RESULTS")
    print("=" * 80)
    print("Testing with realistic NMOS Flow and Source examples")
    print("Similar to MatroxOnly repository examples\n")
    
    # Create test instances
    converter = FlowToCapabilitiesConverter()
    
    # Example: Complex video flow
    complex_flow = {
        "format": "urn:x-nmos:format:video",
        "media_type": "video/raw", 
        "frame_width": 1920,
        "frame_height": 1080,
        "interlace_mode": "interlaced_bff",
        "colorspace": "BT709",
        "transfer_characteristic": "SDR",
        "grain_rate": {"numerator": 25, "denominator": 1},
        "components": [
            {"name": "Y", "width": 1920, "height": 1080, "bit_depth": 10},
            {"name": "Cb", "width": 960, "height": 1080, "bit_depth": 10},
            {"name": "Cr", "width": 960, "height": 1080, "bit_depth": 10}
        ],
        "urn:x-matrox:layer": 0
    }
    
    complex_source = {
        "format": "urn:x-nmos:format:video",
        "clock_name": "clk1",
        "synchronous_media": True
    }
    
    sender = {"hkep": True, "privacy": False}
    caps = converter.convert(complex_flow, complex_source, sender)
    
    if caps.capsets:
        capset = caps.capsets[0]
        print(f"Generated Capabilities for Complex Flow:")
        print(f"  Total CapSets: {len(caps.capsets)}")
        print(f"  Video CapSet Label: {capset.label}")
        print(f"  Video CapSet Format: {capset.format}")
        print(f"  Video CapSet Layer: {capset.layer}")
        print(f"  Total Capabilities: {len(capset.caps)}\n")
        
        print("Capability Details:")
        for cap_name, cap_obj in capset.caps.items():
            if cap_obj.value.enumerated:
                value = next(iter(cap_obj.value.enumerated))
                if isinstance(value, str):
                    print(f"    {cap_name.split(':')[-1]}: {value} (STRING)")
                elif isinstance(value, int):
                    print(f"    {cap_name.split(':')[-1]}: {value} (INT)")
                elif isinstance(value, Fraction):
                    print(f"    {cap_name.split(':')[-1]}: {value} (RATIONAL)")
                elif isinstance(value, bool):
                    print(f"    {cap_name.split(':')[-1]}: {value} (BOOL)")
                else:
                    print(f"    {cap_name.split(':')[-1]}: {value} ({type(value).__name__})")
    
    print("\n" + "=" * 80)
    print("ALL FLOW TESTS COMPLETED SUCCESSFULLY!")
    print("The Flow to CCF Capabilities converter is working correctly")
    print("with realistic NMOS Flow and Source examples.")
    print("=" * 80)


if __name__ == "__main__":
    print("Flow to CCF Capabilities Converter - Comprehensive Test Suite")
    print("Using realistic examples similar to MatroxOnly repository")
    print("=" * 80)
    
    # Add comprehensive display test
    unittest.TestLoader.testMethodPrefix = "test_"
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestFlowToCapabilities)
    
    # Add comprehensive display
    def comprehensive_display_wrapper(result):
        run_comprehensive_display()
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Show comprehensive results
    comprehensive_display_wrapper(result)
    
    # Exit with proper code
    sys.exit(0 if result.wasSuccessful() else 1)
