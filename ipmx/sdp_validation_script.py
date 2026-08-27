#!/usr/bin/env python3
"""
SDP Validation Script

This script loads MatroxSDP and MatroxSDPCheck modules, parses an SDP file,
loads configuration parameters from a config file, and sets up validation
between the two sets of information.

Usage: python sdp_validation_script.py --cfg <config_file> --sdp <sdp_file>
"""

import sys
import os
import argparse
from typing import Dict, Any, Optional

# Use the MatroxSdp / MatroxSdpCheck modules shipped alongside the stream
# validation tools, so this script stays in sync with the ipmx_*_validate_pcap.py
# scripts. These use flat (non-package) imports, so add that directory to the
# Python path regardless of the current working directory.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                'streams', 'ipmx-streams-tools'))

try:
    from MatroxSdp import MatroxSdp, MatroxSdpEnums, MediaDescriptor
    from MatroxSdpCheck import SdpCheckError
    from MatroxSdpCheck import (
        check_sdp_rfc4175, check_sdp_rfc9134, check_sdp_rfc3551,
        check_sdp_rfc3640, check_sdp_rfc6416, check_sdp_rfc8331,
        check_sdp_rfc6184, check_sdp_rfc7798, check_sdp_rfc2250,
        check_sdp_st2110_10, check_sdp_st2110_20, check_sdp_st2110_21,
        check_sdp_st2110_22, check_sdp_st2110_30, check_sdp_st2110_31,
        check_sdp_st2110_40, check_sdp_ipmx, check_sdp_nmos
    )
except ImportError as e:
    print(f"Error importing required modules: {e}")
    print("Expected MatroxSdp.py / MatroxSdpCheck.py in ipmx/streams/ipmx-streams-tools/.")
    sys.exit(1)


class SDPValidationScript:
    """Main class for SDP validation script functionality."""

    def __init__(self, config_file: str, sdp_file: str):
        """
        Initialize the validation script.

        Args:
            config_file: Path to the configuration file containing parameter=value pairs
            sdp_file: Path to the SDP file to be parsed
        """
        self.config_file = config_file
        self.sdp_file = sdp_file
        self.sdp: Optional[MatroxSdp] = None
        self.config_data: Dict[str, str] = {}

    def load_config_file(self) -> bool:
        """
        Load and parse the configuration file.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not os.path.exists(self.config_file):
                print(f"Error: Configuration file '{self.config_file}' does not exist.")
                return False

            print(f"Loading configuration from: {self.config_file}")

            with open(self.config_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()

                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue

                    # Parse parameter=value format
                    if '=' in line:
                        param, value = line.split('=', 1)
                        param = param.strip()
                        value = value.strip()
                        self.config_data[param] = value
                        print(f"  {param} = {value}")
                    else:
                        print(f"Warning: Skipping invalid line {line_num}: {line}")

            print(f"Loaded {len(self.config_data)} configuration parameters.")
            return True

        except Exception as e:
            print(f"Error loading configuration file: {e}")
            return False

    def load_and_parse_sdp_file(self) -> bool:
        """
        Load and parse the SDP file using MatroxSDP.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not os.path.exists(self.sdp_file):
                print(f"Error: SDP file '{self.sdp_file}' does not exist.")
                return False

            print(f"Loading SDP file: {self.sdp_file}")

            # Read SDP file content
            with open(self.sdp_file, 'r', encoding='utf-8') as f:
                sdp_content = f.read()

            print(f"SDP file size: {len(sdp_content)} characters")

            # Create MatroxSdp instance and parse
            self.sdp = MatroxSdp()

            print("Parsing SDP content...")
            error = self.sdp.decode(sdp_content)

            if error:
                print(f"Error parsing SDP: {error}")
                return False

            print("SDP parsing successful!")
            self.display_sdp_info()
            return True

        except Exception as e:
            print(f"Error loading/parsing SDP file: {e}")
            return False

    def display_sdp_info(self):
        """Display basic information about the parsed SDP."""
        if not self.sdp:
            return

        print("\n--- SDP Information ---")
        print(f"Version: {self.sdp.version}")
        print(f"Session Name: {self.sdp.session_name}")
        print(f"Originator: {self.sdp.username}@{self.sdp.origin_address}")
        print(f"Session ID: {self.sdp.session_id}, Version: {self.sdp.session_version}")

        if self.sdp.primary_media:
            media = self.sdp.primary_media
            print("\n--- Primary Media Information ---")
            print(f"Media Name: {media.media_name}")
            print(f"Type: {media.type}")
            print(f"Encoding: {media.encoding_name}")
            print(f"Clock Rate: {media.clock_rate}")
            print(f"Sample Rate: {media.sample_rate}")
            print(f"Multicast Addess: {media.connection_address}")
            print(f"Multicast Filter Source Addess: {media.source_filter_src_address}")
            print(f"Multicast Filter Destination Addess: {media.source_filter_dst_address}")
            print(f"MediaClock Type: {media.media_clock_type}")
            print(f"MediaClock Offset: {media.media_clock_offset}")
            print(f"TS Reference Clock Source: {media.ts_ref_clock_source}")
            print(f"TS Reference Clock Local MAC Address: {media.ts_ref_clock_local_mac_address}")
            print(f"TS Reference Clock PTP Version: {media.ts_ref_clock_ptp_version}")
            print(f"TS Reference Clock PTP GMID: {media.ts_ref_clock_ptp_gmid}")
            print(f"TS Reference Clock PTP Domain: {media.ts_ref_clock_ptp_domain}")
            print(f"HTOTAL, VTOTAL, Measured PixClk: {media.h_total}, {media.v_total}, {media.measured_pix_clk}")
            print(f"Measured Sample Rate: {media.measured_sample_rate}")
            print(f"PTime: {round(media.p_time_us / 1000.0, 2)}")

            if hasattr(media, 'width') and media.width:
                print(f"Resolution: {media.width}x{media.height}")
            if hasattr(media, 'sampling') and media.sampling:
                print(f"Sampling: {media.sampling}")
            if hasattr(media, 'depth') and media.depth:
                print(f"Depth: {media.depth} bits")

            print(f"IPMX: {media.ipmx}")

    def get_media_type(self, media):
        """Determine the media type from the SDP media descriptor."""
        if not media or not hasattr(media, 'type') or not hasattr(media, 'encoding_name'):
            return None

        media_type = str(media.type).lower() if media.type else ""
        encoding_name = str(media.encoding_name).lower() if media.encoding_name else ""

        return f"{media_type}/{encoding_name}"

    def validate_sdp_standards(self):
        """Run standard SDP validation checks based on media type."""
        if not self.sdp or not self.sdp.primary_media:
            print("No SDP data available for validation.")
            return

        media = self.sdp.primary_media
        media_type = self.get_media_type(media)

        print(f"\n--- SDP Standard Validation (Media Type: {media_type}) ---")

        # Select validation checks based on media type (similar to IpmxSdpTest.py)
        validations = []

        if media_type == "video/raw":
            validations.extend([
                ('RFC 4175 (video/raw)', check_sdp_rfc4175),
                ('ST 2110-10', check_sdp_st2110_10),
                ('ST 2110-21', check_sdp_st2110_21),
                ('ST 2110-20', check_sdp_st2110_20),
            ])
        elif media_type == "video/jxsv":
            validations.extend([
                ('RFC 9134 (video/jxsv)', check_sdp_rfc9134),
                ('ST 2110-10', check_sdp_st2110_10),
                ('ST 2110-21', check_sdp_st2110_21),
                ('ST 2110-22', check_sdp_st2110_22),
            ])
        elif media_type == "video/h265":
            validations.extend([
                ('RFC 7798 (video/H265)', check_sdp_rfc7798),
                ('ST 2110-10', check_sdp_st2110_10),
                ('ST 2110-22', check_sdp_st2110_22),
            ])
        elif media_type == "video/h264":
            validations.extend([
                ('RFC 6184 (video/H264)', check_sdp_rfc6184),
                ('ST 2110-10', check_sdp_st2110_10),
                ('ST 2110-22', check_sdp_st2110_22),
            ])
        elif media_type in ("audio/l8", "audio/l16", "audio/l20", "audio/l24"):
            validations.extend([
                ('RFC 3551 (audio/L*)', check_sdp_rfc3551),
                ('ST 2110-10', check_sdp_st2110_10),
                ('ST 2110-30', check_sdp_st2110_30),
            ])
        elif media_type == "audio/am824":
            validations.extend([
                ('RFC 3551 (audio/L*)', check_sdp_rfc3551),
                ('ST 2110-10', check_sdp_st2110_10),
                ('ST 2110-31', check_sdp_st2110_31),
            ])
        else:
            # Fallback: run all validations if media type is unknown
            print(f"Warning: Unknown media type '{media_type}', running all validations")
            validations.extend([
                ('RFC 4175 (video/raw)', check_sdp_rfc4175),
                ('RFC 9134 (video/jxsv)', check_sdp_rfc9134),
                ('RFC 3551 (audio/L*)', check_sdp_rfc3551),
                ('RFC 3640 (audio/mpeg4-generic)', check_sdp_rfc3640),
                ('RFC 6416 (audio/MP4A-LATM, audio/MP4A-ADTS)', check_sdp_rfc6416),
                ('RFC 6184 (video/H264)', check_sdp_rfc6184),
                ('RFC 7798 (video/H265)', check_sdp_rfc7798),
                ('RFC 2250 (video/MP2T)', check_sdp_rfc2250),
                ('ST 2110-10', check_sdp_st2110_10),
                ('ST 2110-20', check_sdp_st2110_20),
                ('ST 2110-21', check_sdp_st2110_21),
                ('ST 2110-22', check_sdp_st2110_22),
                ('ST 2110-30', check_sdp_st2110_30),
                ('ST 2110-31', check_sdp_st2110_31),
                ('IPMX', check_sdp_ipmx),
            ])

        # Run selected validations
        if not validations:
            print("No specific validations configured for this media type.")
            return

        for standard_name, validation_func in validations:
            try:
                validation_func(media)
                print(f"[PASS] {standard_name}: OK")
            except SdpCheckError as e:
                print(f"[FAIL] {standard_name}: FAIL - {e.message}")
            except Exception as e:
                print(f"? {standard_name}: ERROR - {e}")

    def validate_config_vs_sdp(self):
        """Validate configuration parameters against SDP data."""
        if not self.sdp or not self.sdp.primary_media or not self.config_data:
            print("Missing SDP data or configuration for validation.")
            return

        print("\n--- Configuration vs SDP Validation ---")

        media = self.sdp.primary_media
        issues = []

        # Configuration parameter mappings - support both legacy and new formats
        config_checks = {
            # Direct parameter mappings (for backward compatibility)
            'width': ('width', int),
            'height': ('height', int),
            'sampling': ('sampling', str),
            'depth': ('depth', int),
            'rtpclock': (None, int),  # Special handling: clock_rate for video, sample_rate for audio
            'exactframerate': ('exact_frame_rate_numerator', str),  # Special handling needed
            'type': ('type', str),
            'samplefmt': ('encoding_name', str),
            'samplesize': ('channels', int),  # Note: samplesize might represent channels
        }

        for config_key, (sdp_attr, type_converter) in config_checks.items():
            if config_key in self.config_data:
                expected_value = self.config_data[config_key]

                # Special handling for rtpclock: use different SDP attributes based on media type
                if config_key == 'rtpclock':
                    media_type = self.get_media_type(media)
                    if media_type.startswith('audio/'):
                        sdp_attr = 'sample_rate'
                    else:
                        sdp_attr = 'clock_rate'

                actual_value = getattr(media, sdp_attr, None) if sdp_attr else None

                try:
                    if type_converter == int:
                        expected_value = int(expected_value)
                        actual_value = int(actual_value) if actual_value else 0
                    elif type_converter == str:
                        expected_value = str(expected_value)
                        actual_value = str(actual_value) if actual_value else ""

                    # Special handling for exactframerate
                    if config_key == 'exactframerate':
                        # Handle both fractional format (e.g., "60000/1001") and decimal format (e.g., "59.94")
                        if media.exact_frame_rate_denominator and media.exact_frame_rate_denominator != 0:
                            actual_framerate = media.exact_frame_rate_numerator / media.exact_frame_rate_denominator

                            # Try to parse expected_value - it could be fractional or decimal
                            try:
                                if '/' in expected_value:
                                    # Fractional format like "60000/1001"
                                    num_str, den_str = expected_value.split('/', 1)
                                    expected_framerate = float(num_str) / float(den_str)
                                else:
                                    # Decimal format like "59.94"
                                    expected_framerate = float(expected_value)

                                if abs(actual_framerate - expected_framerate) > 0.01:  # Allow small floating point differences
                                    issues.append(f"{config_key}: expected {expected_value}, got {actual_framerate:.2f}")
                                else:
                                    print(f"[OK] {config_key}: {expected_value} matches ({actual_framerate:.2f})")
                            except (ValueError, ZeroDivisionError):
                                issues.append(f"{config_key}: invalid expected framerate format '{expected_value}'")
                        else:
                            issues.append(f"{config_key}: cannot determine actual framerate from SDP")
                        continue

                    # Special handling for type checking
                    if config_key == 'type':
                        expected_type = expected_value.lower()
                        actual_type = str(media.type).lower() if media.type else ""
                        if expected_type not in actual_type:
                            issues.append(f"{config_key}: expected {expected_value}, got {actual_type}")
                        else:
                            print(f"[OK] {config_key}: {expected_value} matches")
                        continue

                    if expected_value != actual_value:
                        issues.append(f"{config_key}: expected {expected_value}, got {actual_value}")
                    else:
                        print(f"[OK] {config_key}: {expected_value} matches")
                except (ValueError, TypeError) as e:
                    issues.append(f"{config_key}: conversion error - {e}")

        # PTP Configuration Validation
        if 'PTP' in self.config_data:
            ptp = self.config_data['PTP'].lower() == 'true'
        else:
            ptp = False

        print(f"\n--- PTP Configuration Validation (PTP Enabled: {ptp}) ---")
        
        if ptp:
            # PTP enabled: ts_ref_clock_source must be "ptp" and media_clock_type must be "direct"
            if media.ts_ref_clock_source != "ptp":
                issues.append(f"PTP enabled but ts_ref_clock_source is '{media.ts_ref_clock_source}', expected 'ptp'")
            else:
                print(f"[OK] ts_ref_clock_source: 'ptp' (correct for PTP enabled)")
            
            if media.media_clock_type != "direct" and media.media_clock_type != "sender":
                issues.append(f"PTP enabled but media_clock_type is '{media.media_clock_type}', expected 'direct' or 'sender'")
            else:
                print(f"[OK] media_clock_type: 'direct' or 'sender' (correct for PTP enabled)")
        else:
            # PTP disabled: ts_ref_clock_source must be "localmac" and media_clock_type must be "sender"
            if media.ts_ref_clock_source != "localmac":
                issues.append(f"PTP disabled but ts_ref_clock_source is '{media.ts_ref_clock_source}', expected 'localmac'")
            else:
                print(f"[OK] ts_ref_clock_source: 'localmac' (correct for PTP disabled)")
            
            if media.media_clock_type != "direct" and media.media_clock_type != "sender":
                issues.append(f"PTP disabled but media_clock_type is '{media.media_clock_type}', expected 'direct' or 'sender'")
            else:
                print(f"[OK] media_clock_type: 'sender' (correct for PTP disabled)")

            if media.ts_ref_clock_local_mac_address.upper() != media.ts_ref_clock_local_mac_address:
                issues.append(f"PTP disabled and localmac {media.ts_ref_clock_local_mac_address} is not in upper cases")
            else:
                print(f"[OK] localmac {media.ts_ref_clock_local_mac_address} is in upper cases (correct for PTP disabled)")

        # IPMX Validation
        print(f"\n--- IPMX Validation ---")
        if hasattr(media, 'ipmx') and media.ipmx:
            if media.type == MatroxSdpEnums.Video: 
                if not hasattr(media, 'h_total') or not hasattr(media, 'v_total') or not hasattr(media, 'measured_pix_clk') or \
                   media.h_total == 0 or media.v_total == 0 or media.measured_pix_clk == 0:
                    issues.append(f"IPMX enabled but h_total, v_total, or measured_pix_clk is 0 or missing")
                else:
                    print(f"[OK] h_total={media.h_total}, v_total={media.v_total}, measured_pix_clk={media.measured_pix_clk}")
            elif media.type == MatroxSdpEnums.Audio:
                if not hasattr(media, 'sample_rate') or media.sample_rate == 0:
                    issues.append(f"IPMX enabled but sample_rate is 0 or missing")
                else:
                    print(f"[OK] sample_rate={media.sample_rate}")
            else:
                issues.append(f"IPMX enabled but type is not video or audio (type: {media.type})")
        else:
            issues.append("IPMX must be declared in the SDP")

        if media.type == MatroxSdpEnums.Audio and 'ptime' in self.config_data: 
            print(f"\n--- ptime Validation ---")
            actual_ptime = round(media.p_time_us / 1000.0, 2)
            expected_ptime = float(self.config_data['ptime'])
            if expected_ptime != actual_ptime:
                issues.append(f"ptime is {actual_ptime} but expected {expected_ptime}")
            else:
                print(f"[OK] ptime is {actual_ptime}")

        if issues:
            print("Validation issues found:")
            for issue in issues:
                print(f"  [FAIL] {issue}")
        else:
            print("All configuration validations passed!")

    def run_validation(self):
        """Run all validation checks."""
        self.validate_sdp_standards()
        self.validate_config_vs_sdp()


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cfg", required=True, dest="config_file",
                        help="Path to configuration file with parameter=value pairs")
    parser.add_argument("--sdp", required=True, dest="sdp_file",
                        help="Path to SDP file to be parsed and validated")
    args = parser.parse_args()

    config_file = args.config_file
    sdp_file = args.sdp_file

    print("SDP Validation Script")
    print("=" * 50)

    # Create validation script instance
    validator = SDPValidationScript(config_file, sdp_file)

    # Load configuration
    if not validator.load_config_file():
        sys.exit(1)

    # Load and parse SDP
    if not validator.load_and_parse_sdp_file():
        sys.exit(1)

    # Run validations
    validator.run_validation()

    print("\n" + "=" * 50)
    print("Validation complete!")


if __name__ == "__main__":
    main()
