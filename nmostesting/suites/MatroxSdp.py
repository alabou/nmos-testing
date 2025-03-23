# Copyright (C) 2025 Matrox Graphics Inc.
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

import re
from io import StringIO
from typing import List, Dict, Optional, Tuple
import math
from enum import Enum

# Constants
MAX_MEDIAS = 2
MAX_HKEPS = 2
MAX_EXTMAPS = 8

# Simulate Go's uint types with Python integers (no strict bit width in Python)
uint8 = int
uint16 = int
uint = int
uint64 = int
float64 = float

# TargetSpecification Enum (simulating Go's iota-based enum)
class TargetSpecification(Enum):
    NONE = 0
    RFC4175 = 1      # video/raw
    RFC9134 = 2      # video/jxsv
    RFC3551 = 3      # audio/L*
    RFC8331 = 4      # ST-291-1
    RFC6184 = 5      # video/H264
    RFC7798 = 6      # video/H265
    RFC3640 = 7      # audio/mpeg4-generic
    RFC6416 = 8      # audio/MP4A-LATM, audio/MP4A-ADTS
    RFC2250 = 9      # video/MP2T
    ST2110_10 = 10
    ST2110_20 = 11
    ST2110_21 = 12
    ST2110_22 = 13
    ST2110_30 = 14
    ST2110_31 = 15
    ST2110_40 = 16
    IPMX = 17
    NMOS = 18

# AAC Object Types
AAC_OBJECT_TYPES = {
    "Main": 1,
    "LC": 2,
    "SSR": 3,
    "LTP": 4,
    "SBR": 5,
    "ER_LC": 17,
    "ER_LTP": 18,
    "ER_LD": 23,
    "PS": 29,
    "ER_ESCAPE": 31,
    "ER_ELD": 39,
}

# Enum simulation using a dictionary
ALL_ENUMS: Dict[str, str] = {}
PANIC_ON_DUPLICATE_ENUM = False

class EnumId:
    def __init__(self, s: str):
        self.s = s

    def __str__(self) -> str:
        return self.s

    def __hash__(self):
        return hash(self.s)

    def __eq__(self, other) -> bool:

        if isinstance(other, EnumId):
            return self.s == other.s
        if isinstance(other, str):
            return self.s == other
        if isinstance(other, Enum):
            return self.s == other.value
        
        return False


class MatroxSdpEnums(Enum):

    def __hash__(self):
        return hash(self.value.s)

    Audio                                = EnumId("audio")                # media type
    Video                                = EnumId("video")                # media type
    Text                                 = EnumId("text")                 # media type
    Application                          = EnumId("application")          # media type
    Message                              = EnumId("message")              # media type
    Local                                = EnumId("local")                # clock source
    LocalMac                             = EnumId("localmac")             # clock source
    NTP                                  = EnumId("ntp")                  # clock source
    PTP                                  = EnumId("ptp")                  # clock source
    Sender                               = EnumId("sender")               # mediaclk type
    Direct                               = EnumId("direct")               # mediaclk type
    OutOfOrderAllowed                    = EnumId("out-of-order-allowed") # jxsv transmode
    SequentialOnly                       = EnumId("sequential-only")      # jxsv transmode
    CodeStream                           = EnumId("codestream")           # jxsv packetmode
    Slice                                = EnumId("slice")                # jxsv packetmode
    EncodingRaw                          = EnumId("raw")
    EncodingJxsv                         = EnumId("jxsv")
    EncodingSmpte291                     = EnumId("smpte291")
    EncodingL8                           = EnumId("L8")
    EncodingL16                          = EnumId("L16")
    EncodingL20                          = EnumId("L20")
    EncodingL24                          = EnumId("L24")
    EncodingAM824                        = EnumId("AM824")
    EncodingH264                         = EnumId("H264")
    EncodingH265                         = EnumId("H265")
    EncodingAAC                          = EnumId("mpeg4-generic")
    EncodingAAC_LATM                     = EnumId("MP4A-LATM")
    EncodingAAC_ADTS                     = EnumId("MP4A-ADTS")
    EncodingMP2T                         = EnumId("MP2T")
    SamplingRGB                          = EnumId("RGB")
    SamplingRGBA                         = EnumId("RGBA")
    SamplingBGR                          = EnumId("BGR")
    SamplingBGRA                         = EnumId("BGRA")
    SamplingYCbCr_444                    = EnumId("YCbCr-4:4:4")
    SamplingYCbCr_422                    = EnumId("YCbCr-4:2:2")
    SamplingYCbCr_420                    = EnumId("YCbCr-4:2:0")
    SamplingYCbCr_411                    = EnumId("YCbCr-4:1:1")
    SamplingCLYCbCr_444                  = EnumId("CLYCbCr-4:4:4")
    SamplingCLYCbCr_422                  = EnumId("CLYCbCr-4:2:2")
    SamplingCLYCbCr_420                  = EnumId("CLYCbCr-4:2:0")
    SamplingICtCp_444                    = EnumId("ICtCp-4:4:4")
    SamplingICtCp_422                    = EnumId("ICtCp-4:2:2")
    SamplingICtCp_420                    = EnumId("ICtCp-4:2:0")
    SamplingXYZ                          = EnumId("XYZ")
    SamplingKey                          = EnumId("KEY")
    SamplingUnspecified                  = EnumId("UNSPECIFIED")
    ColorimetryBT601_5                   = EnumId("BT601-5")
    ColorimetryBT709_2                   = EnumId("BT709-2")
    ColorimetrySmpte240M                 = EnumId("SMPTE240M")
    ColorimetryBT601                     = EnumId("BT601")
    ColorimetryBT709                     = EnumId("BT709")
    ColorimetryBT2020                    = EnumId("BT2020")
    ColorimetryBT2100                    = EnumId("BT2100")
    ColorimetryST2065_1                  = EnumId("ST2065-1")
    ColorimetryST2065_3                  = EnumId("ST2065-3")
    ColorimetryXYZ                       = EnumId("XYZ")
    ColorimetryALPHA                     = EnumId("ALPHA")
    ColorimetryUnspecified               = EnumId("UNSPECIFIED")
    TransferSDR                          = EnumId("SDR")
    TransferPQ                           = EnumId("PQ")
    TransferHLG                          = EnumId("HLG")
    TransferUnspecified                  = EnumId("UNSPECIFIED")
    TransferLinear                       = EnumId("LINEAR")
    TransferBT2100LINPQ                  = EnumId("BT2100LINPQ")
    TransferBT2100LINHLG                 = EnumId("BT2100LINHLG")
    TransferST2065_1                     = EnumId("ST2065-1")
    TransferST248_1                      = EnumId("ST248-1")
    TransferDensity                      = EnumId("DENSITY")
    TransferST2115LOGS3                  = EnumId("ST2115LOGS3")
    RangeNarrow                          = EnumId("NARROW")
    RangeFull                            = EnumId("FULL")
    RangeFullProtect                     = EnumId("FULLPROTECT")
    RangeUnspecified                     = EnumId("UNSPECIFIED")
    PackingMode2110GPM                   = EnumId("2110GPM")
    PackingMode2110BPM                   = EnumId("2110BPM")
    SenderType2110TPN                    = EnumId("2110TPN")
    SenderType2110TPNL                   = EnumId("2110TPNL")
    SenderType2110TPW                    = EnumId("2110TPW")
    ProtocolTCP                          = EnumId("TCP")
    ProtocolUDP                          = EnumId("UDP")
    ProtocolTCP_RTP_AVP                  = EnumId("TCP/RTP/AVP")
    ProtocolRTP_AVP                      = EnumId("RTP/AVP")
    FormatJson                           = EnumId("json")
    FormatUsb                            = EnumId("usb")
    FormatMpeg2TS                        = EnumId("mp2t") # special lowercase one for using as application/mp2t
    FormatRtsp                           = EnumId("rtsp")
    PrivacyProtocolRTP                   = EnumId("RTP")
    PrivacyProtocolRTP_KV                = EnumId("RTP_KV")
    PrivacyProtocolSRT                   = EnumId("SRT")
    PrivacyProtocolSRTP                  = EnumId("SRTP")
    PrivacyProtocolRTSP                  = EnumId("RTSP")
    PrivacyProtocolRTSP_KV               = EnumId("RTSP_KV")
    PrivacyProtocolUDP                   = EnumId("UDP")
    PrivacyProtocolUDP_KV                = EnumId("UDP_KV")
    PrivacyProtocolUSB                   = EnumId("USB")
    PrivacyProtocolUSB_KV                = EnumId("USB_KV")
    PrivacyProtocolNULL                  = EnumId("NULL")
    PrivacyModeAES128CTR                 = EnumId("AES-128-CTR")
    PrivacyModeAES256CTR                 = EnumId("AES-256-CTR")
    PrivacyModeAES128CTR_CMAC64          = EnumId("AES-128-CTR_CMAC-64")
    PrivacyModeAES256CTR_CMAC64          = EnumId("AES-256-CTR_CMAC-64")
    PrivacyModeAES128CTR_CMAC64_AAD      = EnumId("AES-128-CTR_CMAC-64-AAD")
    PrivacyModeAES256CTR_CMAC64_AAD      = EnumId("AES-256-CTR_CMAC-64-AAD")
    PrivacyModeAES128_GCM128             = EnumId("AES-128-GMAC-128")
    PrivacyModeAES256_GCM128             = EnumId("AES-256-GMAC-128")
    PrivacyModeECDH_AES128CTR            = EnumId("ECDH_AES-128-CTR")
    PrivacyModeECDH_AES256CTR            = EnumId("ECDH_AES-256-CTR")
    PrivacyModeECDH_AES128CTR_CMAC64     = EnumId("ECDH_AES-128-CTR_CMAC-64")
    PrivacyModeECDH_AES256CTR_CMAC64     = EnumId("ECDH_AES-256-CTR_CMAC-64")
    PrivacyModeECDH_AES128CTR_CMAC64_AAD = EnumId("ECDH_AES-128-CTR_CMAC-64-AAD")
    PrivacyModeECDH_AES256CTR_CMAC64_AAD = EnumId("ECDH_AES-256-CTR_CMAC-64-AAD")
    PrivacyModeECDH_AES128_GCM128        = EnumId("ECDH_AES-128-GMAC-128")
    PrivacyModeECDH_AES256_GCM128        = EnumId("ECDH_AES-256-GMAC-128")
    TsModeSample    = EnumId("SAMP")
    TsModeNew       = EnumId("NEW")
    TsModePreserved = EnumId("PRES")
    JxsvProfileMain420_12  = EnumId("Main420.12")
    JxsvProfileHigh420_12  = EnumId("High420.12")
    JxsvProfileMain444_12  = EnumId("Main444.12")
    JxsvProfileMain4444_12 = EnumId("Main4444.12")
    JxsvProfileHigh444_12  = EnumId("High444.12")
    JxsvProfileHigh4444_12 = EnumId("High4444.12")
    JxsvLevel1k1           = EnumId("1k-1")
    JxsvLevel2k1           = EnumId("2k-1")
    JxsvLevel4k1           = EnumId("4k-1")
    JxsvLevel4k2           = EnumId("4k-2")
    JxsvLevel4k3           = EnumId("4k-3")
    JxsvLevel8k1           = EnumId("8k-1")
    JxsvLevel8k2           = EnumId("8k-2")
    JxsvLevel8k3           = EnumId("8k-3")
    JxsvSublevel2bpp       = EnumId("Sublev2bpp")
    JxsvSublevel3bpp       = EnumId("Sublev3bpp")
    JxsvSublevel4bpp       = EnumId("Sublev4bpp")
    JxsvSublevel6bpp       = EnumId("Sublev6bpp")
    JxsvSublevel9bpp       = EnumId("Sublev9bpp")
    JxsvSublevel12bpp      = EnumId("Sublev12bpp")
    H265TxModeSRST = EnumId("SRST")
    H265TxModeMRST = EnumId("MRST")
    H265TxModeMRMT = EnumId("MRMT")

def init_enums():
    global ALL_ENUMS
    for e in MatroxSdpEnums:
        if e.value.s in ALL_ENUMS and PANIC_ON_DUPLICATE_ENUM and e.value.s != "":
            raise ValueError(f"duplicate enum {e.value}")
        ALL_ENUMS[e.value.s] = e.value

init_enums()

def lookup_enum(s: str, auto_enum: bool) -> Tuple[Optional[EnumId], Optional[str]]:
    if s in ALL_ENUMS:
        return ALL_ENUMS[s], None
    if auto_enum:
        enum_id = EnumId(s)
        ALL_ENUMS[s] = enum_id
        return enum_id, None
    return None, f"enum string not found: {s}"

def auto_lookup_enum(s: str) -> EnumId:
    if s in ALL_ENUMS:
        return ALL_ENUMS[s]
    enum_id = EnumId(s)
    ALL_ENUMS[s] = enum_id
    return enum_id

# Helper class for error simulation
class SdpError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)

class HkepDescriptor:
    def __init__(self):
        self.is_ipv6: bool = False
        self.address: str = ""
        self.port: uint16 = 0
        self.node_id: str = ""
        self.port_id: str = ""

class PrivacyDescriptor:
    def __init__(self):
        self.protocol: Optional[EnumId] = None
        self.mode: Optional[EnumId] = None
        self.iv: str = ""
        self.key_generator: str = ""
        self.key_id: str = ""
        self.key_version: str = ""

class ExtmapDescriptor:
    def __init__(self):
        self.id: uint = 0
        self.uri: str = ""
        self.direction: str = ""  # "sendonly", "recvonly", "sendrecv", "inactive"

class MediaDescriptor:
    def __init__(self):
        # Grouping
        self.media_name: str = ""
        # Information
        self.media_information: str = ""
        # Base
        self.port: uint16 = 0
        self.port_count: uint = 0
        self.rtcp_port: uint16 = 0
        self.rtcp_connection_address: str = ""
        self.rtcp_is_connection_ipv6: bool = False
        self.rtcp_connection_ttl: uint8 = 0
        self.rtcp_connection_count: uint8 = 0
        # Type and Protocol
        self.type: Optional[EnumId] = None
        self.protocol: Optional[EnumId] = None
        self.format_code: uint8 = 0
        self.format_string: Optional[EnumId] = None
        # Connection
        self.connection_address: str = ""
        self.is_connection_ipv6: bool = False
        self.connection_ttl: uint8 = 0
        self.connection_count: uint8 = 0
        self.bitrate_kbits: uint = 0
        # Source Filter
        self.source_filter_dst_address: str = ""
        self.source_filter_src_address: str = ""
        self.is_source_filter_ipv6: bool = False
        # RTP Map / FMTP
        self.payload_type: uint8 = 0
        self.encoding_name: Optional[EnumId] = None
        self.clock_rate: uint64 = 0
        self.sample_rate: uint64 = 0
        self.channels: uint = 0
        # FMTP Generic
        self.ipmx: bool = False
        self.hkep: bool = False
        self.privacy: bool = False
        # FMTP Video
        self.sampling: Optional[EnumId] = None
        self.depth: uint = 0
        self.width: uint = 0
        self.height: uint = 0
        self.exact_frame_rate_numerator: uint64 = 0
        self.exact_frame_rate_denominator: uint64 = 0
        self.colorimetry: Optional[EnumId] = None
        self.color_range: Optional[EnumId] = None
        self.transfer_characteristic: Optional[EnumId] = None
        self.chroma_position_cb: uint = 0
        self.chroma_position_cr: uint = 0
        self.gamma: float64 = 0.0
        self.interlaced: bool = False
        self.segmented: bool = False
        self.top_field_first: bool = False
        self.picture_aspect_ratio_width: uint = 0
        self.picture_aspect_ratio_height: uint = 0
        self.h_total: uint = 0
        self.v_total: uint = 0
        self.measured_pix_clk: uint64 = 0
        self.measured_sample_rate: uint64 = 0
        self.smpte_standard_number: str = ""
        self.sender_type: Optional[EnumId] = None
        self.packing_mode: Optional[EnumId] = None
        self.max_udp: uint = 0
        self.troff: uint = 0
        self.cmax: uint = 0
        # JXSV Specific
        self.profile: Optional[EnumId] = None
        self.level: Optional[EnumId] = None
        self.sub_level: Optional[EnumId] = None
        self.jxsv_trans_mode: Optional[EnumId] = None
        self.jxsv_packet_mode: Optional[EnumId] = None
        # H264/H265 Shared
        self.codec_profile_level_id: str = ""
        # H264 Specific
        self.h264_parameter_sets: str = ""
        self.h264_packetization_mode: uint8 = 0
        self.h264_interleaving_depth: uint = 0
        self.h264_deint_buf_req: uint = 0
        self.h264_init_buf_time: uint = 0
        self.h26x_max_don_diff: uint = 0
        # H265 Specific
        self.h265_profile_space: uint8 = 0
        self.h265_profile_id: uint8 = 0
        self.h265_level_id: uint8 = 0
        self.h265_interop_constraints: str = ""
        self.h265_profile_compatibility_indicator: str = ""
        self.h265_tier_flag: bool = False
        self.h265_tx_mode: Optional[EnumId] = None
        self.h265_vps: str = ""
        self.h265_sps: str = ""
        self.h265_pps: str = ""
        self.h265_depack_buf_nalus: uint = 0
        self.h265_depack_buf_bytes: uint = 0
        self.h265_segmentation_id: uint8 = 0
        self.h265_spatial_segmentation_idc: str = ""
        # ST-2110-40
        self.did_sdid: str = ""
        self.vpid_code: uint = 0
        # FMTP Audio
        self.channel_order: str = ""
        self.p_time_us: uint64 = 0
        self.max_p_time_us: uint64 = 0
        self.frame_count: uint = 0
        self.emphasis: str = ""
        # AAC Specific
        self.aac_stream_type: uint8 = 0
        self.aac_mode: str = ""
        self.aac_config: str = ""
        self.aac_config_present: bool = False
        self.aac_object_type: uint8 = 0
        self.aac_constant_duration: uint = 0
        self.aac_max_displacement: uint = 0
        self.aac_de_interleave_buffer_size: uint = 0
        self.aac_size_length: uint8 = 0
        self.aac_index_length: uint8 = 0
        self.aac_index_delta_length: uint8 = 0
        self.aac_cts_delta_length: uint8 = 0
        self.aac_dts_delta_length: uint8 = 0
        self.aac_random_access_indication: bool = False
        self.aac_bitrate: uint64 = 0
        # HKEP
        self.hkep: List[HkepDescriptor] = [HkepDescriptor() for _ in range(MAX_HKEPS)]
        # Privacy
        self.privacy_desc: PrivacyDescriptor = PrivacyDescriptor()
        # Media Clock
        self.media_clock_type: Optional[EnumId] = None
        self.media_clock_offset: uint64 = 0
        self.media_clock_rate_numerator: uint64 = 0
        self.media_clock_rate_denominator: uint64 = 0
        # TS Reference Clock
        self.ts_ref_clock_source: Optional[EnumId] = None
        self.ts_ref_clock_ptp_version: str = ""
        self.ts_ref_clock_ptp_gmid: str = ""
        self.ts_ref_clock_ptp_domain: str = ""
        self.ts_ref_clock_ntp_address: str = ""
        self.ts_ref_clock_local_mac_address: str = ""
        # TS Mode
        self.ts_mode: Optional[EnumId] = None
        self.ts_delay: uint64 = 0
        # Extmap
        self.ext_map: List[ExtmapDescriptor] = [ExtmapDescriptor() for _ in range(MAX_EXTMAPS)]
        # Framerate
        self.frame_rate_numerator: uint64 = 0
        self.frame_rate_denominator: uint64 = 0
        # RTSP Sub-stream Control
        self.sub_stream_control: str = ""

class MatroxSdp:
    def __init__(self):
        # Version
        self.version: uint8 = 0
        # Originator
        self.username: str = ""
        self.session_id: uint64 = 0
        self.session_version: uint64 = 0
        self.is_origin_ipv6: bool = False
        self.origin_address: str = ""
        # Session Name
        self.session_name: str = ""
        # Session Information
        self.session_information: str = ""
        # Timing
        self.start: uint64 = 0
        self.stop: uint64 = 0
        # Connection (session level)
        self.connection_address: str = ""
        self.is_connection_ipv6: bool = False
        self.connection_ttl: uint8 = 0
        self.connection_count: uint8 = 0
        # Bandwidth (session level)
        self.bitrate_kbits: uint = 0
        # HKEP (session level)
        self.hkep: List[HkepDescriptor] = [HkepDescriptor() for _ in range(MAX_HKEPS)]
        # Privacy
        self.privacy: PrivacyDescriptor = PrivacyDescriptor()
        # Media Clock
        self.media_clock_type: Optional[EnumId] = None
        self.media_clock_offset: uint64 = 0
        self.media_clock_rate_numerator: uint64 = 0
        self.media_clock_rate_denominator: uint64 = 0
        # TS Reference Clock
        self.ts_ref_clock_source: Optional[EnumId] = None
        self.ts_ref_clock_ptp_version: str = ""
        self.ts_ref_clock_ptp_gmid: str = ""
        self.ts_ref_clock_ptp_domain: str = ""
        self.ts_ref_clock_ntp_address: str = ""
        self.ts_ref_clock_local_mac_address: str = ""
        # Extmap (session level)
        self.ext_map: List[ExtmapDescriptor] = [ExtmapDescriptor() for _ in range(MAX_EXTMAPS)]
        # Group Attribute
        self.has_group_attribute: bool = False
        self.primary_media_name: str = ""
        self.primary_media: Optional[MediaDescriptor] = None
        self.secondary_media_name: str = ""
        self.secondary_media: Optional[MediaDescriptor] = None
        # RTSP Session Control
        self.session_control: str = ""
        # Internal Members
        self.current_input: Optional[List[str]] = None
        self.current_output: Optional[StringIO] = None
        self.current_media: Optional[MediaDescriptor] = None
        self.in_media_section: bool = False
        self.media_count: uint = 0
        self.medias: List[MediaDescriptor] = [MediaDescriptor() for _ in range(MAX_MEDIAS)]

    def reset(self):
        # Reset all fields to their zero values
        self.__init__()
        self.primary_media = self.medias[0]
        self.secondary_media = self.medias[1]

    def decode(self, reader: str) -> Optional[str]:
        self.reset()
        self.current_input = reader.splitlines()
        err = self.process_lines()
        if err:
            return err

        # Setup primary and secondary media pointers
        if self.has_group_attribute:
            if self.media_count != 2:
                return f"invalid media count: {self.media_count}"
            if self.medias[0].media_name == self.primary_media_name:
                self.primary_media = self.medias[0]
            elif self.medias[1].media_name == self.primary_media_name:
                self.primary_media = self.medias[1]
            else:
                return "invalid primary group name"
            if self.medias[0].media_name == self.secondary_media_name:
                self.secondary_media = self.medias[0]
            elif self.medias[1].media_name == self.secondary_media_name:
                self.secondary_media = self.medias[1]
            else:
                return "invalid secondary group name"
            if self.primary_media == self.secondary_media:
                return "invalid group"
        else:
            if self.media_count != 1:
                return f"invalid media count: {self.media_count}"
            self.primary_media = self.medias[0]
            self.primary_media_name = self.medias[0].media_name
            self.secondary_media = self.medias[0]
            self.secondary_media_name = self.medias[0].media_name

        err = self.check_sdp_base_requirements()
        if err:
            return err
        return None

    def process_lines(self) -> Optional[str]:
        if not self.current_input:
            return None
        for line in self.current_input:
            line = line.strip()
            if len(line) < 2:
                continue
            if line[1] != '=':
                return "missing = character after line type"
            line_type = line[0]
            line_content = line[2:].encode('utf-8')
            if line_type == 'v':
                err = self.process_version(line_content)
            elif line_type == 'o':
                err = self.process_origin(line_content)
            elif line_type == 's':
                err = self.process_session_name(line_content)
            elif line_type == 'i':
                err = self.process_information(line_content)
            elif line_type == 'c':
                err = self.process_connection(line_content)
            elif line_type == 'b':
                err = self.process_bitrate(line_content)
            elif line_type == 't':
                err = self.process_timing(line_content)
            elif line_type == 'a':
                err = self.process_attribute(line_content)
            elif line_type == 'm':
                err = self.process_media(line_content)
            elif line_type in ('k', 'z', 'u', 'e', 'p', 'r'):
                print(f"Warning: line type '{line_type}' not supported and ignored")
                err = None
            else:
                print(f"Warning: line type '{line_type}' unknown and ignored")
                err = None
            if err:
                return err
        return None

    def process_version(self, line: bytes) -> Optional[str]:
        if line.decode('utf-8')[0] != '0':
            return "invalid protocol version"
        return None

    def process_origin(self, line: bytes) -> Optional[str]:
        split = line.split(b' ')
        if len(split) != 6:
            return "invalid origin line"
        self.username = split[0].decode('utf-8')
        try:
            self.session_id = int(split[1])
            self.session_version = int(split[2])
        except ValueError:
            return "invalid origin session-id or session-version"
        if split[3] != b"IN":
            return "invalid origin nettype"
        if split[4] not in (b"IP4", b"IP6"):
            return "invalid origin addrtype"
        self.is_origin_ipv6 = split[4] == b"IP6"
        self.origin_address = split[5].decode('utf-8')
        return None

    def process_session_name(self, line: bytes) -> Optional[str]:
        self.session_name = line.decode('utf-8')
        return None

    def process_information(self, line: bytes) -> Optional[str]:
        info = line.decode('utf-8')
        if self.in_media_section:
            self.current_media.media_information = info
        else:
            self.session_information = info
        return None

    def process_connection(self, line: bytes) -> Optional[str]:
        split = line.split(b' ')
        if len(split) != 3:
            return "invalid connection line"
        if split[0] != b"IN":
            return "invalid connection nettype"
        if split[1] not in (b"IP4", b"IP6"):
            return "invalid connection addrtype"
        is_ipv6 = split[1] == b"IP6"
        split_address = split[2].split(b'/')
        if not split_address:
            return "invalid connection-address"
        address = split_address[0].decode('utf-8')
        count = 1
        ttl = 0
        if is_ipv6:
            if len(split_address) > 1:
                try:
                    count = int(split_address[1])
                except ValueError:
                    return "invalid connection-address number of addresses"
        else:
            if len(split_address) > 2:
                try:
                    ttl = int(split_address[1])
                    count = int(split_address[2])
                except ValueError:
                    return "invalid connection-address TTL or number of addresses"
            elif len(split_address) > 1:
                try:
                    ttl = int(split_address[1])
                    count = 1
                except ValueError:
                    return "invalid connection-address TTL"
            else:
                count = 1
        if self.in_media_section:
            self.current_media.connection_address = address
            self.current_media.is_connection_ipv6 = is_ipv6
            self.current_media.connection_ttl = ttl
            self.current_media.connection_count = count
        else:
            self.connection_address = address
            self.is_connection_ipv6 = is_ipv6
            self.connection_ttl = ttl
            self.connection_count = count
        return None

    def process_bitrate(self, line: bytes) -> Optional[str]:
        split = line.split(b':')
        if len(split) != 2:
            return "invalid bandwidth line"
        if split[0] != b"AS":
            return "invalid bandwidth type"
        try:
            value = int(split[1])
        except ValueError:
            return "invalid bandwidth"
        if self.in_media_section:
            self.current_media.bitrate_kbits = value
        else:
            self.bitrate_kbits = value
        return None

    def process_timing(self, line: bytes) -> Optional[str]:
        split = line.split(b' ')
        if len(split) != 2:
            return "invalid timing line"
        try:
            self.start = int(split[0])
            self.stop = int(split[1])
        except ValueError:
            return "invalid start-time or stop-time"
        return None

    def process_attribute(self, line: bytes) -> Optional[str]:
        if self.in_media_section:
            return self.process_media_attribute(line)
        return self.process_session_attribute(line)

    def process_session_attribute(self, line: bytes) -> Optional[str]:
        attr, value = line.split(b':', 1) if b':' in line else (line, None)
        attr_str = attr.decode('utf-8')
        if attr_str == "group":
            if value is None:
                return "invalid session attribute line"
            split = value.split(b' ')
            if len(split) != 3 or split[0] != b"DUP":
                return "invalid group attribute"
            self.primary_media_name = split[1].decode('utf-8')
            self.secondary_media_name = split[2].decode('utf-8')
            self.has_group_attribute = True
        elif attr_str == "ts-refclk":
            return self.process_ts_ref_clk(value)
        elif attr_str == "mediaclk":
            return self.process_media_clk(value)
        elif attr_str == "hkep":
            return self.process_hkep(value)
        elif attr_str == "privacy":
            return self.process_privacy(value)
        elif attr_str == "control":
            return self.process_session_control(value)
        elif attr_str == "extmap":
            return self.process_extmap(value)
        elif attr_str == "charset":
            return "invalid charset attribute"
        else:
            print(f"Warning: attribute '{attr_str}' unknown and ignored")
        return None

    def process_media_attribute(self, line: bytes) -> Optional[str]:
        attr, value = line.split(b':', 1) if b':' in line else (line, None)
        attr_str = attr.decode('utf-8')
        if attr_str == "source-filter":
            return self.process_source_filter(value)
        elif attr_str == "rtcp":
            return self.process_rtcp(value)
        elif attr_str == "rtpmap":
            return self.process_rtp_map(value)
        elif attr_str == "fmtp":
            return self.process_fmtp(value)
        elif attr_str == "ts-refclk":
            return self.process_ts_ref_clk(value)
        elif attr_str == "mediaclk":
            return self.process_media_clk(value)
        elif attr_str == "hkep":
            return self.process_hkep(value)
        elif attr_str == "privacy":
            return self.process_privacy(value)
        elif attr_str == "control":
            return self.process_session_control(value)
        elif attr_str == "mid":
            return self.process_mid(value)
        elif attr_str == "ptime":
            return self.process_p_time(value)
        elif attr_str == "maxptime":
            return self.process_max_p_time(value)
        elif attr_str == "framecount":
            return self.process_frame_count(value)
        elif attr_str == "framerate":
            return self.process_frame_rate(value)
        elif attr_str == "extmap":
            return self.process_extmap(value)
        else:
            print(f"Warning: attribute '{attr_str}' unknown and ignored")
        return None

    def process_media(self, line: bytes) -> Optional[str]:
        if self.media_count >= MAX_MEDIAS:
            return "too many medias"
        self.medias[self.media_count] = MediaDescriptor()
        self.current_media = self.medias[self.media_count]
        self.media_count += 1
        self.in_media_section = True
        self.copy_session_level_to_media_level()
        split = line.split(b' ')
        if len(split) != 4:
            return "invalid media line"
        enum, err = lookup_enum(split[0].decode('utf-8'), True)
        if err:
            return err
        self.current_media.type = enum
        if self.current_media.type.s not in ("audio", "video", "text", "application", "message"):
            return "invalid media type"
        split_port = split[1].split(b'/')
        if len(split_port) == 2:
            try:
                self.current_media.port = int(split_port[0])
                self.current_media.port_count = int(split_port[1])
            except ValueError:
                return "invalid transport port or port count"
        else:
            try:
                self.current_media.port = int(split[1])
                self.current_media.port_count = 1
            except ValueError:
                return "invalid transport port"
        enum, err = lookup_enum(split[2].decode('utf-8'), True)
        if err:
            return err
        self.current_media.protocol = enum
        enum, err = lookup_enum(split[3].decode('utf-8'), True)
        if err:
            return err
        self.current_media.format_string = enum
        self.current_media.format_code = 0
        try:
            code = int(self.current_media.format_string.s)
            self.current_media.format_code = code
            self.current_media.format_string = None
        except ValueError:
            pass
        return None

    def copy_session_level_to_media_level(self):
        self.current_media.media_information = self.session_information
        if self.connection_address:
            self.current_media.connection_address = self.connection_address
            self.current_media.connection_ttl = self.connection_ttl
            self.current_media.connection_count = self.connection_count
            self.current_media.is_connection_ipv6 = self.is_connection_ipv6
        if self.bitrate_kbits:
            self.current_media.bitrate_kbits = self.bitrate_kbits
        for i in range(MAX_HKEPS):
            if self.hkep[i].address:
                self.current_media.hkep[i].address = self.hkep[i].address
                self.current_media.hkep[i].is_ipv6 = self.hkep[i].is_ipv6
                self.current_media.hkep[i].port = self.hkep[i].port
                self.current_media.hkep[i].node_id = self.hkep[i].node_id
                self.current_media.hkep[i].port_id = self.hkep[i].port_id
        if self.privacy.protocol:
            self.current_media.privacy_desc = self.privacy
        if self.session_control:
            self.current_media.sub_stream_control = self.session_control
        for i in range(MAX_EXTMAPS):
            if self.ext_map[i].uri:
                self.current_media.ext_map[i].uri = self.ext_map[i].uri
                self.current_media.ext_map[i].direction = self.ext_map[i].direction
                self.current_media.ext_map[i].id = self.ext_map[i].id
        if self.media_clock_type:
            self.current_media.media_clock_type = self.media_clock_type
            self.current_media.media_clock_offset = self.media_clock_offset
            self.current_media.media_clock_rate_numerator = self.media_clock_rate_numerator
            self.current_media.media_clock_rate_denominator = self.media_clock_rate_denominator
        if self.ts_ref_clock_source:
            self.current_media.ts_ref_clock_source = self.ts_ref_clock_source
            self.current_media.ts_ref_clock_local_mac_address = self.ts_ref_clock_local_mac_address
            self.current_media.ts_ref_clock_ntp_address = self.ts_ref_clock_ntp_address
            self.current_media.ts_ref_clock_ptp_version = self.ts_ref_clock_ptp_version
            self.current_media.ts_ref_clock_ptp_gmid = self.ts_ref_clock_ptp_gmid
            self.current_media.ts_ref_clock_ptp_domain = self.ts_ref_clock_ptp_domain

    def process_source_filter(self, value: bytes) -> Optional[str]:
        if not self.in_media_section:
            return "unexpected source-filter attribute"
        value = value.strip()
        if value.startswith(b' '):
            value = value[1:]
        split = value.split(b' ')
        if len(split) < 5:
            return "invalid source-filter attribute"
        if len(split) > 5:
            print("Warning: using only the first src-address")
        if split[0] != b"incl":
            return "invalid source-filter mode"
        if split[1] != b"IN":
            return "invalid source-filter nettype"
        if split[2] not in (b"IP4", b"IP6"):
            return "invalid source-filter addrtype"
        self.current_media.is_source_filter_ipv6 = split[2] == b"IP6"
        self.current_media.source_filter_dst_address = split[3].decode('utf-8')
        self.current_media.source_filter_src_address = split[4].decode('utf-8')
        return None

    def process_rtcp(self, value: bytes) -> Optional[str]:
        if not self.in_media_section:
            return "unexpected rtcp attribute"
        split = value.split(b' ')
        if len(split) not in (1, 4):
            return "rtcp attribute must contain either only a port or a port, nettype, addrtype and connection-address"
        try:
            self.current_media.rtcp_port = int(split[0])
        except ValueError:
            return "invalid rtcp port"
        if len(split) == 4:
            if split[1] != b"IN":
                return "invalid connection nettype"
            if split[2] not in (b"IP4", b"IP6"):
                return "invalid connection addrtype"
            is_ipv6 = split[2] == b"IP6"
            split_address = split[3].split(b'/')
            if not split_address:
                return "invalid connection-address"
            address = split_address[0].decode('utf-8')
            count = 1
            ttl = 0
            if is_ipv6:
                if len(split_address) > 1:
                    try:
                        count = int(split_address[1])
                    except ValueError:
                        return "invalid connection-address number of addresses"
            else:
                if len(split_address) > 2:
                    try:
                        ttl = int(split_address[1])
                        count = int(split_address[2])
                    except ValueError:
                        return "invalid connection-address TTL or number of addresses"
                elif len(split_address) > 1:
                    try:
                        ttl = int(split_address[1])
                    except ValueError:
                        return "invalid connection-address TTL"
            self.current_media.rtcp_connection_address = address
            self.current_media.rtcp_is_connection_ipv6 = is_ipv6
            self.current_media.rtcp_connection_ttl = ttl
            self.current_media.rtcp_connection_count = count
        return None

    def process_rtp_map(self, value: bytes) -> Optional[str]:
        if not self.in_media_section:
            return "unexpected rtpmap attribute"
        if self.current_media.format_string:
            return "invalid rtpmap attribute"
        split = value.split(b' ')
        if len(split) != 2:
            return "invalid rtpmap attribute"
        try:
            code = int(split[0])
            if code > 127:
                raise ValueError
        except ValueError:
            return "invalid rtpmap payload-type"
        self.current_media.payload_type = code
        if self.current_media.payload_type != self.current_media.format_code:
            return "invalid rtpmap payload-type"
        split_encoding = split[1].split(b'/')
        if len(split_encoding) < 2:
            return "invalid rtpmap encoding/rate/params"
        enum, err = lookup_enum(split_encoding[0].decode('utf-8'), True)
        if err:
            return err
        self.current_media.encoding_name = enum
        if self.current_media.type.s == "audio":
            try:
                self.current_media.sample_rate = int(split_encoding[1])
            except ValueError:
                return "invalid rtpmap clock-rate"
            if len(split_encoding) > 2:
                try:
                    self.current_media.channels = int(split_encoding[2])
                except ValueError:
                    return "invalid rtpmap encoding-params"
                if len(split_encoding) > 3:
                    print("Warning: ignoring extra encoding-params")
            else:
                self.current_media.channels = 1
        else:
            try:
                self.current_media.clock_rate = int(split_encoding[1])
            except ValueError:
                return "invalid rtpmap clock-rate"
            if len(split_encoding) > 2:
                print("Warning: ignoring extra encoding-params")
        return None

    def process_fmtp(self, value: bytes) -> Optional[str]:
        if not self.in_media_section:
            return "unexpected fmtp attribute"
        split = value.split(b' ', 1)
        if len(split) < 2:
            return None
        if self.current_media.format_string is None:
            try:
                code = int(split[0])
                if code > 127:
                    raise ValueError
            except ValueError:
                return "invalid fmtp payload-type"
            if self.current_media.payload_type == 0:
                self.current_media.payload_type = code
            if self.current_media.payload_type != self.current_media.format_code:
                return "invalid fmtp payload-type"
        else:
            enum, err = lookup_enum(split[0].decode('utf-8'), True)
            if err:
                return err
            if self.current_media.format_string != enum:
                return "invalid fmtp format"
        split_params = split[1].split(b';')
        for pair in split_params:
            param, val = pair.split(b'=', 1) if b'=' in pair else (pair, None)
            param = param.strip().decode('utf-8')
            val = val.strip().decode('utf-8') if val else None
            method_name = f"process_parameter_{param.replace('-', '_').lower()}"
            if hasattr(self, method_name):
                err = getattr(self, method_name)(val.encode('utf-8') if val else None)
                if err:
                    return err
            else:
                print(f"Warning: ignoring unknown parameter '{param}'")
        return None

    def process_ts_ref_clk(self, value: bytes) -> Optional[str]:
        src, val = value.split(b'=', 1) if b'=' in value else (value, None)
        src = src.strip().decode('utf-8')
        val = val.strip().decode('utf-8') if val else ""
        enum, err = lookup_enum(src, True)
        if err:
            return err
        ts_ref_clock_source = enum
        ts_ref_clock_local_mac_address = ""
        ts_ref_clock_ntp_address = ""
        ts_ref_clock_ptp_version = ""
        ts_ref_clock_ptp_gmid = ""
        ts_ref_clock_ptp_domain = ""
        if ts_ref_clock_source.s == "local":
            pass
        elif ts_ref_clock_source.s == "localmac":
            ts_ref_clock_local_mac_address = val
        elif ts_ref_clock_source.s == "ntp":
            ts_ref_clock_ntp_address = val
        elif ts_ref_clock_source.s == "ptp":
            split_ptp = val.split(':')
            if len(split_ptp) < 2:
                return "invalid ts-refclk ptp clock value"
            ts_ref_clock_ptp_version = split_ptp[0]
            ts_ref_clock_ptp_gmid = split_ptp[1]
            if len(split_ptp) > 2:
                ts_ref_clock_ptp_domain = split_ptp[2]
        else:
            print(f"Warning: unknown ts-refclk source '{ts_ref_clock_source.s}' ignored")
        if self.in_media_section:
            self.current_media.ts_ref_clock_source = ts_ref_clock_source
            self.current_media.ts_ref_clock_local_mac_address = ts_ref_clock_local_mac_address
            self.current_media.ts_ref_clock_ntp_address = ts_ref_clock_ntp_address
            self.current_media.ts_ref_clock_ptp_version = ts_ref_clock_ptp_version
            self.current_media.ts_ref_clock_ptp_gmid = ts_ref_clock_ptp_gmid
            self.current_media.ts_ref_clock_ptp_domain = ts_ref_clock_ptp_domain
        else:
            self.ts_ref_clock_source = ts_ref_clock_source
            self.ts_ref_clock_local_mac_address = ts_ref_clock_local_mac_address
            self.ts_ref_clock_ntp_address = ts_ref_clock_ntp_address
            self.ts_ref_clock_ptp_version = ts_ref_clock_ptp_version
            self.ts_ref_clock_ptp_gmid = ts_ref_clock_ptp_gmid
            self.ts_ref_clock_ptp_domain = ts_ref_clock_ptp_domain
        return None

    def process_media_clk(self, value: bytes) -> Optional[str]:
        kind, val = value.split(b'=', 1) if b'=' in value else (value, None)
        kind = kind.strip().decode('utf-8')
        val = val.strip().decode('utf-8') if val else ""
        enum, err = lookup_enum(kind, True)
        if err:
            return err
        media_clock_type = enum
        media_clock_offset = 0
        media_clock_rate_numerator = 0
        media_clock_rate_denominator = 0
        if media_clock_type.s == "sender":
            pass
        elif media_clock_type.s == "direct":
            split_value = val.split()
            if not split_value:
                return "invalid mediaclk direct attribute"
            try:
                media_clock_offset = int(split_value[0])
            except ValueError:
                return "invalid mediaclk direct offset"
            if len(split_value) > 1:
                split_rate = split_value[1].split('=')
                if len(split_rate) != 2 or split_rate[0] != "rate":
                    return "invalid mediaclk direct attribute"
                split_ratio = split_rate[1].split('/')
                if not split_ratio:
                    return "invalid mediaclk direct rate"
                try:
                    media_clock_rate_numerator = int(split_ratio[0])
                    media_clock_rate_denominator = int(split_ratio[1]) if len(split_ratio) > 1 else 1
                except ValueError:
                    return "invalid mediaclk direct rate numerator or denominator"
        else:
            print(f"Warning: unknown mediaclk type '{media_clock_type.s}' ignored")
        if self.in_media_section:
            self.current_media.media_clock_type = media_clock_type
            self.current_media.media_clock_offset = media_clock_offset
            self.current_media.media_clock_rate_numerator = media_clock_rate_numerator
            self.current_media.media_clock_rate_denominator = media_clock_rate_denominator
        else:
            self.media_clock_type = media_clock_type
            self.media_clock_offset = media_clock_offset
            self.media_clock_rate_numerator = media_clock_rate_numerator
            self.media_clock_rate_denominator = media_clock_rate_denominator
        return None

    def process_hkep(self, value: bytes) -> Optional[str]:
        split = value.split(b' ')
        if len(split) != 6:
            return "invalid hkep attribute line"
        try:
            port = int(split[0])
        except ValueError:
            return "invalid hkep port"
        if split[1] != b"IN":
            return "invalid hkep nettype"
        if split[2] not in (b"IP4", b"IP6"):
            return "invalid hkep addrtype"
        is_ipv6 = split[2] == b"IP6"
        address = split[3].decode('utf-8')
        node_id = split[4].decode('utf-8')
        port_id = split[5].decode('utf-8')
        hkep_desc = HkepDescriptor()
        hkep_desc.is_ipv6 = is_ipv6
        hkep_desc.address = address
        hkep_desc.port = port
        hkep_desc.node_id = node_id
        hkep_desc.port_id = port_id
        target = self.current_media.hkep if self.in_media_section else self.hkep
        for i in range(MAX_HKEPS):
            if not target[i].address:
                target[i] = hkep_desc
                break
        else:
            print("Warning: too many hkep entries")
        if self.in_media_section:
            self.current_media.hkep = True
        return None

    def process_privacy(self, value: bytes) -> Optional[str]:
        if not self.in_media_section:
            return "invalid privacy attribute line"
        split = value.split(b';')
        if len(split) != 6:
            return "invalid privacy attribute line"
        privacy = PrivacyDescriptor()
        for pair in split:
            key, val = pair.split(b'=')
            key = key.strip().decode('utf-8')
            val = val.strip().decode('utf-8')
            if key == "protocol":
                enum, err = lookup_enum(val, False)
                if err or enum.s not in (
                    "RTP", "RTP_KV", "UDP", "UDP_KV", "RTSP", "RTSP_KV",
                    "SRT", "SRTP", "USB", "USB_KV"
                ):
                    return "invalid privacy attribute line"
                privacy.protocol = enum
            elif key == "mode":
                enum, err = lookup_enum(val, False)
                if err or enum.s not in (
                    "AES-128-CTR", "AES-128-CTR_CMAC-64", "AES-128-CTR_CMAC-64-AAD",
                    "ECDH_AES-128-CTR", "ECDH_AES-128-CTR_CMAC-64", "ECDH_AES-128-CTR_CMAC-64-AAD",
                    "AES-256-CTR", "AES-256-CTR_CMAC-64", "AES-256-CTR_CMAC-64-AAD",
                    "ECDH_AES-256-CTR", "ECDH_AES-256-CTR_CMAC-64", "ECDH_AES-256-CTR_CMAC-64-AAD",
                    "AES-128-GMAC-128", "AES-256-GMAC-128",
                    "ECDH_AES-128-GMAC-128", "ECDH_AES-256-GMAC-128"
                ):
                    return "invalid privacy attribute line"
                privacy.mode = enum
            elif key == "iv":
                if len(val) != 16 or not re.match(r'^[0-9A-Fa-f]+$', val):
                    return "invalid privacy attribute line"
                privacy.iv = val
            elif key == "key_generator":
                if len(val) != 32 or not re.match(r'^[0-9A-Fa-f]+$', val):
                    return "invalid privacy attribute line"
                privacy.key_generator = val
            elif key == "key_version":
                if len(val) != 8 or not re.match(r'^[0-9A-Fa-f]+$', val):
                    return "invalid privacy attribute line"
                privacy.key_version = val
            elif key == "key_id":
                if len(val) != 16 or not re.match(r'^[0-9A-Fa-f]+$', val):
                    return "invalid privacy attribute line"
                privacy.key_id = val
            else:
                return "invalid privacy attribute line"
        self.current_media.privacy_desc = privacy
        self.current_media.privacy = True
        return None

    def process_session_control(self, value: bytes) -> Optional[str]:
        val = value.decode('utf-8')
        if self.in_media_section:
            self.current_media.sub_stream_control = val
        else:
            self.session_control = val
        return None

    def process_extmap(self, value: bytes) -> Optional[str]:
        split = value.split(b' ')
        if len(split) < 2:
            return "invalid extmap line"
        split_id = split[0].split(b'/')
        if not split_id:
            return "invalid extmap id"
        if len(split_id) > 1:
            try:
                id_val = int(split_id[0])
                if id_val > 256:
                    raise ValueError
                direction = split_id[1].decode('utf-8')
            except ValueError:
                return "invalid extmap id"
            uri = split[1].decode('utf-8')
        else:
            try:
                id_val = int(split_id[0])
                if id_val > 256:
                    raise ValueError
            except ValueError:
                return "invalid extmap id"
            direction = "sendonly"
            uri = split[1].decode('utf-8')
        if direction != "sendonly":
            return "invalid extmap direction"
        extmap = ExtmapDescriptor()
        extmap.id = id_val
        extmap.direction = direction
        extmap.uri = uri
        target = self.ext_map if not self.in_media_section else self.current_media.ext_map
        for i in range(MAX_EXTMAPS):
            if not target[i].uri:
                target[i] = extmap
                break
        else:
            return "too many extmap entries"
        return None

    def process_mid(self, value: bytes) -> Optional[str]:
        if not self.in_media_section:
            return "unexpected mid attribute"
        self.current_media.media_name = value.decode('utf-8')
        return None

    def process_p_time(self, value: bytes) -> Optional[str]:
        if not self.in_media_section:
            return "unexpected ptime attribute"
        try:
            f = float(value)
            if f == 0.0:
                raise ValueError
        except ValueError:
            return "invalid ptime value"
        self.current_media.p_time_us = int(f * 1000)
        return None

    def process_max_p_time(self, value: bytes) -> Optional[str]:
        if not self.in_media_section:
            return "unexpected maxptime attribute"
        try:
            f = float(value)
            if f == 0.0:
                raise ValueError
        except ValueError:
            return "invalid maxptime value"
        self.current_media.max_p_time_us = int(f * 1000)
        return None

    def process_frame_count(self, value: bytes) -> Optional[str]:
        if not self.in_media_section:
            return "unexpected framecount attribute"
        try:
            count = int(value)
            if count == 0:
                raise ValueError
        except ValueError:
            return "invalid framecount value"
        self.current_media.frame_count = count
        return None

    def process_frame_rate(self, value: bytes) -> Optional[str]:
        if not self.in_media_section:
            return "unexpected framerate attribute"
        try:
            f = float(value)
        except ValueError:
            return "invalid framerate value"
        if b'.' in value:
            self.current_media.frame_rate_numerator = int(math.trunc(f * 1001.0 + 0.5))
            self.current_media.frame_rate_denominator = 1001
        else:
            self.current_media.frame_rate_numerator = int(f)
            self.current_media.frame_rate_denominator = 1
        return None

    # Parameter Processing Methods
    def process_parameter_sampling(self, value: bytes) -> Optional[str]:
        enum, err = lookup_enum(value.decode('utf-8'), True)
        if err:
            return err
        self.current_media.sampling = enum
        return None

    def process_parameter_width(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.width = int(value)
        except ValueError:
            return "invalid width value"
        return None

    def process_parameter_height(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.height = int(value)
        except ValueError:
            return "invalid height value"
        return None

    def process_parameter_depth(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.depth = int(value)
        except ValueError:
            return "invalid depth value"
        return None

    def process_parameter_colorimetry(self, value: bytes) -> Optional[str]:
        enum, err = lookup_enum(value.decode('utf-8'), True)
        if err:
            return err
        self.current_media.colorimetry = enum
        return None

    def process_parameter_range(self, value: bytes) -> Optional[str]:
        enum, err = lookup_enum(value.decode('utf-8'), True)
        if err:
            return err
        self.current_media.color_range = enum
        return None

    def process_parameter_exactframerate(self, value: bytes) -> Optional[str]:
        split = value.split(b'/')
        if len(split) > 2:
            return "invalid exactframerate value"
        try:
            n = int(split[0])
            d = int(split[1]) if len(split) == 2 else 1
        except ValueError:
            return "invalid numerator or denominator value"
        self.current_media.exact_frame_rate_numerator = n
        self.current_media.exact_frame_rate_denominator = d
        return None

    def process_parameter_pm(self, value: bytes) -> Optional[str]:
        enum, err = lookup_enum(value.decode('utf-8'), True)
        if err:
            return err
        self.current_media.packing_mode = enum
        return None

    def process_parameter_ssn(self, value: bytes) -> Optional[str]:
        self.current_media.smpte_standard_number = value.decode('utf-8')
        return None

    def process_parameter_ipmx(self, value: bytes) -> Optional[str]:
        if value is not None:
            return "invalid IPMX value"
        self.current_media.ipmx = True
        return None

    def process_parameter_tp(self, value: bytes) -> Optional[str]:
        enum, err = lookup_enum(value.decode('utf-8'), True)
        if err:
            return err
        self.current_media.sender_type = enum
        return None

    def process_parameter_chroma_position(self, value: bytes) -> Optional[str]:
        split = value.split(b',')
        if len(split) > 2:
            return "invalid chroma position value"
        try:
            cb = int(split[0])
            cr = int(split[1]) if len(split) == 2 else cb
        except ValueError:
            return "invalid chroma position Cb or Cr value"
        self.current_media.chroma_position_cb = cb
        self.current_media.chroma_position_cr = cr
        return None

    def process_parameter_top_field_first(self, value: bytes) -> Optional[str]:
        if value is not None:
            return "invalid top-field-first value"
        self.current_media.top_field_first = True
        return None

    def process_parameter_interlace(self, value: bytes) -> Optional[str]:
        if value is not None:
            return "invalid interlace value"
        self.current_media.interlaced = True
        return None

    def process_parameter_gamma(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.gamma = float(value)
        except ValueError:
            return "invalid gamma value"
        return None

    def process_parameter_htotal(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.h_total = int(value)
        except ValueError:
            return "invalid HTotal value"
        return None

    def process_parameter_vtotal(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.v_total = int(value)
        except ValueError:
            return "invalid VTotal value"
        return None

    def process_parameter_measuredpixclk(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.measured_pix_clk = int(value)
        except ValueError:
            return "invalid measuredpixclk value"
        return None

    def process_parameter_measuredsamplerate(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.measured_sample_rate = int(value)
        except ValueError:
            return "invalid measuredsamplerate value"
        return None

    def process_parameter_segmented(self, value: bytes) -> Optional[str]:
        if value is not None:
            return "invalid segmented value"
        self.current_media.segmented = True
        return None

    def process_parameter_maxudp(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.max_udp = int(value)
        except ValueError:
            return "invalid MAXUDP value"
        return None

    def process_parameter_par(self, value: bytes) -> Optional[str]:
        value = value.strip(b'"')
        split = value.split(b':')
        if len(split) > 2:
            return "invalid PAR value"
        try:
            w = int(split[0])
            h = int(split[1]) if len(split) == 2 else 1
        except ValueError:
            return "invalid PAR width or height value"
        self.current_media.picture_aspect_ratio_width = w
        self.current_media.picture_aspect_ratio_height = h
        return None

    def process_parameter_tcs(self, value: bytes) -> Optional[str]:
        enum, err = lookup_enum(value.decode('utf-8'), True)
        if err:
            return err
        self.current_media.transfer_characteristic = enum
        return None

    def process_parameter_troff(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.troff = int(value)
        except ValueError:
            return "invalid TROFF value"
        return None

    def process_parameter_cmax(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.cmax = int(value)
        except ValueError:
            return "invalid CMAX value"
        return None

    def process_parameter_transmode(self, value: bytes) -> Optional[str]:
        try:
            v = int(value)
            self.current_media.jxsv_trans_mode = EnumId("out-of-order-allowed" if v == 0 else "sequential-only")
        except ValueError:
            return "invalid transmode value"
        return None

    def process_parameter_packetmode(self, value: bytes) -> Optional[str]:
        try:
            v = int(value)
            self.current_media.jxsv_packet_mode = EnumId("codestream" if v == 0 else "slice")
        except ValueError:
            return "invalid packetmode value"
        return None

    def process_parameter_profile(self, value: bytes) -> Optional[str]:
        enum, err = lookup_enum(value.decode('utf-8'), True)
        if err:
            return err
        self.current_media.profile = enum
        return None

    def process_parameter_level(self, value: bytes) -> Optional[str]:
        enum, err = lookup_enum(value.decode('utf-8'), True)
        if err:
            return err
        self.current_media.level = enum
        return None

    def process_parameter_sublevel(self, value: bytes) -> Optional[str]:
        enum, err = lookup_enum(value.decode('utf-8'), True)
        if err:
            return err
        self.current_media.sub_level = enum
        return None

    def process_parameter_did_sdid(self, value: bytes) -> Optional[str]:
        self.current_media.did_sdid = value.decode('utf-8')
        return None

    def process_parameter_vpid_code(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.vpid_code = int(value)
        except ValueError:
            return "invalid VPID_Code value"
        return None

    def process_parameter_channel_order(self, value: bytes) -> Optional[str]:
        self.current_media.channel_order = value.decode('utf-8')
        return None

    def process_parameter_emphasis(self, value: bytes) -> Optional[str]:
        self.current_media.emphasis = value.decode('utf-8')
        return None

    def process_parameter_streamtype(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.aac_stream_type = int(value)
        except ValueError:
            return "invalid streamType value"
        return None

    def process_parameter_mode(self, value: bytes) -> Optional[str]:
        self.current_media.aac_mode = value.decode('utf-8')
        return None

    def process_parameter_config(self, value: bytes) -> Optional[str]:
        self.current_media.aac_config = value.decode('utf-8')
        return None

    def process_parameter_cpresent(self, value: bytes) -> Optional[str]:
        try:
            v = int(value)
            self.current_media.aac_config_present = v != 0
        except ValueError:
            return "invalid cpresent value"
        return None

    def process_parameter_objecttype(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.aac_object_type = int(value)
        except ValueError:
            return "invalid objectType/object value"
        return None

    def process_parameter_object(self, value: bytes) -> Optional[str]:
        return self.process_parameter_objecttype(value)

    def process_parameter_constantduration(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.aac_constant_duration = int(value)
        except ValueError:
            return "invalid constantDuration value"
        return None

    def process_parameter_maxdisplacement(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.aac_max_displacement = int(value)
        except ValueError:
            return "invalid maxDisplacement value"
        return None

    def process_parameter_de_interleavebuffersize(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.aac_de_interleave_buffer_size = int(value)
        except ValueError:
            return "invalid de-interleaveBufferSize value"
        return None

    def process_parameter_sizelength(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.aac_size_length = int(value)
        except ValueError:
            return "invalid sizeLength value"
        return None

    def process_parameter_indexlength(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.aac_index_length = int(value)
        except ValueError:
            return "invalid indexLength value"
        return None

    def process_parameter_indexdeltalength(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.aac_index_delta_length = int(value)
        except ValueError:
            return "invalid indexDeltaLength value"
        return None

    def process_parameter_ctsdeltalength(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.aac_cts_delta_length = int(value)
        except ValueError:
            return "invalid CTSDeltaLength value"
        return None

    def process_parameter_dtsdeltalength(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.aac_dts_delta_length = int(value)
        except ValueError:
            return "invalid DTSDeltaLength value"
        return None

    def process_parameter_randomaccessindication(self, value: bytes) -> Optional[str]:
        try:
            v = int(value)
            self.current_media.aac_random_access_indication = v != 0
        except ValueError:
            return "invalid randomAccessIndication value"
        return None

    def process_parameter_bitrate(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.aac_bitrate = int(value)
        except ValueError:
            return "invalid bitrate value"
        return None

    def process_parameter_tsmode(self, value: bytes) -> Optional[str]:
        enum, err = lookup_enum(value.decode('utf-8'), True)
        if err:
            return err
        self.current_media.ts_mode = enum
        return None

    def process_parameter_tsdelay(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.ts_delay = int(value)
        except ValueError:
            return "invalid TSDELAY value"
        return None

    def process_parameter_profile_level_id(self, value: bytes) -> Optional[str]:
        self.current_media.codec_profile_level_id = value.decode('utf-8')
        return None

    def process_parameter_sprop_parameter_sets(self, value: bytes) -> Optional[str]:
        self.current_media.h264_parameter_sets = value.decode('utf-8')
        return None

    def process_parameter_packetization_mode(self, value: bytes) -> Optional[str]:
        try:
            v = int(value)
            if v not in (0, 1, 2):
                raise ValueError
            self.current_media.h264_packetization_mode = v
        except ValueError:
            return "invalid packetization-mode value"
        return None

    def process_parameter_sprop_interleaving_depth(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.h264_interleaving_depth = int(value)
        except ValueError:
            return "invalid sprop-interleaving-depth value"
        return None

    def process_parameter_sprop_deint_buf_req(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.h264_deint_buf_req = int(value)
        except ValueError:
            return "invalid sprop-deint-buf-req value"
        return None

    def process_parameter_sprop_init_buf_time(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.h264_init_buf_time = int(value)
        except ValueError:
            return "invalid sprop-init-buf-time value"
        return None

    def process_parameter_sprop_max_don_diff(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.h26x_max_don_diff = int(value)
        except ValueError:
            return "invalid sprop-max-don-diff value"
        return None

    def process_parameter_profile_space(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.h265_profile_space = int(value)
        except ValueError:
            return "invalid profile-space value"
        return None

    def process_parameter_profile_id(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.h265_profile_id = int(value)
        except ValueError:
            return "invalid profile-id value"
        return None

    def process_parameter_tier_flag(self, value: bytes) -> Optional[str]:
        try:
            v = int(value)
            self.current_media.h265_tier_flag = v == 1
        except ValueError:
            return "invalid tier-flag value"
        return None

    def process_parameter_level_id(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.h265_level_id = int(value)
        except ValueError:
            return "invalid level-id value"
        return None

    def process_parameter_interop_constraints(self, value: bytes) -> Optional[str]:
        self.current_media.h265_interop_constraints = value.decode('utf-8')
        return None

    def process_parameter_profile_compatibility_indicator(self, value: bytes) -> Optional[str]:
        self.current_media.h265_profile_compatibility_indicator = value.decode('utf-8')
        return None

    def process_parameter_tx_mode(self, value: bytes) -> Optional[str]:
        enum, err = lookup_enum(value.decode('utf-8'), False)
        if err:
            return "invalid tx-mode value"
        self.current_media.h265_tx_mode = enum
        return None

    def process_parameter_sprop_vps(self, value: bytes) -> Optional[str]:
        self.current_media.h265_vps = value.decode('utf-8')
        return None

    def process_parameter_sprop_sps(self, value: bytes) -> Optional[str]:
        self.current_media.h265_sps = value.decode('utf-8')
        return None

    def process_parameter_sprop_pps(self, value: bytes) -> Optional[str]:
        self.current_media.h265_pps = value.decode('utf-8')
        return None

    def process_parameter_sprop_depack_buf_nalus(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.h265_depack_buf_nalus = int(value)
        except ValueError:
            return "invalid sprop-depack-buf-nalus value"
        return None

    def process_parameter_sprop_depack_buf_bytes(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.h265_depack_buf_bytes = int(value)
        except ValueError:
            return "invalid sprop-depack-buf-bytes value"
        return None

    def process_parameter_sprop_segmentation_id(self, value: bytes) -> Optional[str]:
        try:
            self.current_media.h265_segmentation_id = int(value)
        except ValueError:
            return "invalid sprop-segmentation-id value"
        return None

    def process_parameter_sprop_spatial_segmentation_idc(self, value: bytes) -> Optional[str]:
        self.current_media.h265_spatial_segmentation_idc = value.decode('utf-8')
        return None

    def check_sdp_base_requirements(self) -> Optional[str]:
        if not self.username or not self.session_id or not self.session_version or not self.origin_address:
            return "missing o= line"
        if not self.session_name:
            return "missing s= line"
        if self.primary_media.protocol and self.primary_media.protocol.s in ("RTP/AVP", "TCP/RTP/AVP"):
            if (self.primary_media.port % 2) != 0 and not self.primary_media.rtcp_port:
                return "missing a=rtcp: line with odd RTP port"
            if (self.secondary_media.port % 2) != 0 and not self.secondary_media.rtcp_port:
                return "missing a=rtcp: line with odd RTP port"
            if self.primary_media.port_count != 1 and self.primary_media.rtcp_port:
                return "invalid a=rtcp: line with multiple ports"
            if self.secondary_media.port_count != 1 and self.secondary_media.rtcp_port:
                return "invalid a=rtcp: line with multiple ports"
            if not self.primary_media.rtcp_port and self.primary_media.port:
                self.primary_media.rtcp_port = self.primary_media.port + 1
            if not self.secondary_media.rtcp_port and self.secondary_media.port:
                self.secondary_media.rtcp_port = self.secondary_media.port + 1
        return None

