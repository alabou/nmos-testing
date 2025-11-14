#!/usr/bin/env python3
"""
IS-11 Stream Compatibility Management Test Results Analyzer

This script analyzes JSON test results from IS-11 Stream Compatibility Management tests
and determines pass/fail status based on the IS-11 specification and IPMX requirements

Note:
    - IPMX require support for Base EDID for inputs supporting an EDID.
    - Inputs and outputs must be connected
    - Test senders that are all of the same type:
        - all having inputs with or without EDID support
        - all not having inputs
    - Test receivers that are all of the same type:
        - all having outputs with or without EDID support
        - all not having outputs
    - When senders and receivers are tested simultaneously, their inputs/outputs, if any,
      must all be with or without EDID support

Usage:
    python is11_test_analyzer.py [environment flags] <path_to_results.json>
"""

import json
import sys
import argparse
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class TestState(Enum):
    PASS = "Pass"
    FAIL = "Fail"
    COULD_NOT_TEST = "Could Not Test"
    TEST_DISABLED = "Test Disabled"
    NOT_APPLICABLE = "Not Applicable"


@dataclass
class TestResult:
    name: str
    state: TestState
    detail: str
    duration: float


@dataclass
class EnvironmentSpec:
    with_inputs: Optional[bool]
    without_inputs: Optional[bool]
    with_outputs: Optional[bool]
    without_outputs: Optional[bool]
    edid_supported: Optional[bool]
    edid_not_supported: Optional[bool]
    with_senders: Optional[bool]
    without_senders: Optional[bool]
    with_receivers: Optional[bool]
    without_receivers: Optional[bool]


class IS11TestAnalyzer:
    """Analyzer for IS-11 Stream Compatibility Management test results"""

    def __init__(self, json_file_path: str, environment_spec: Optional[EnvironmentSpec] = None):
        self.json_file_path = json_file_path
        self.test_results: Dict[str, TestResult] = {}
        self.provided_environment_spec = environment_spec
        self.environment_spec = None
        self.final_verdict = None
        self.failure_reasons = []

    def load_results(self) -> bool:
        """Load and parse the JSON test results file"""
        try:
            with open(self.json_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if 'results' not in data:
                print(f"ERROR: No 'results' array found in {self.json_file_path}")
                return False

            for test_data in data['results']:
                if 'name' not in test_data or 'state' not in test_data:
                    continue

                test_result = TestResult(
                    name=test_data['name'],
                    state=TestState(test_data.get('state', 'Unknown')),
                    detail=test_data.get('detail', ''),
                    duration=test_data.get('duration', 0.0)
                )
                self.test_results[test_result.name] = test_result

            return True

        except FileNotFoundError:
            print(f"ERROR: File {self.json_file_path} not found")
            return False
        except json.JSONDecodeError as e:
            print(f"ERROR: Invalid JSON in {self.json_file_path}: {e}")
            return False
        except Exception as e:
            print(f"ERROR: Failed to load {self.json_file_path}: {e}")
            return False

    def get_test_result(self, test_name: str) -> Optional[TestResult]:
        """Get a test result by name"""
        return self.test_results.get(test_name)

    def analyze_environment(self) -> EnvironmentSpec:
        """Analyze the test environment based on provided specification or test results"""
        if self.provided_environment_spec:
            # Use provided environment specification, but auto-detect IS-11 capabilities
            spec = self.provided_environment_spec

            # Determine final with_/without_ flags (explicit or auto-detected with validation)
            self.environment_spec = self._finalize_environment_flags(spec)
        else:
            # Auto-detect everything from test results
            # Create a spec with all None values (no explicit settings)
            auto_detect_spec = EnvironmentSpec(
                with_inputs=None,
                without_inputs=None,
                with_outputs=None,
                without_outputs=None,
                edid_supported=None,
                edid_not_supported=None,
                with_senders=None,
                without_senders=None,
                with_receivers=None,
                without_receivers=None
            )

            # Finalize flags using auto-detection
            self.environment_spec = self._finalize_environment_flags(auto_detect_spec)

        return self.environment_spec

    def _finalize_environment_flags(self, spec: EnvironmentSpec) -> EnvironmentSpec:
        """Finalize all with_/without_ flags based on explicit settings or auto-detection with validation"""

        # Helper function to determine final flag value with validation
        # Ensures explicit command-line arguments don't contradict test results
        def finalize_flag(explicit_with, explicit_without, auto_detect_with, auto_detect_without, flag_name):
            if explicit_with is not None:
                # User explicitly specified --with-{flag_name}
                # Must validate that test results agree (capability exists)
                if not auto_detect_with:
                    raise ValueError(f"Command-line specifies --with-{flag_name}, "
                                     "but test results indicate no {flag_name} capability")
                return explicit_with, None
            elif explicit_without is not None:
                # User explicitly specified --without-{flag_name}
                # Must validate that test results agree (capability doesn't exist)
                if not auto_detect_without:
                    raise ValueError(f"Command-line specifies --without-{flag_name}, "
                                     "but test results indicate {flag_name} capability exists")
                return None, explicit_without
            else:
                # No explicit specification - use auto-detected values
                return auto_detect_with, auto_detect_without

        # Get auto-detection results
        test_01_01 = self.get_test_result('test_01_01')
        test_01_04 = self.get_test_result('test_01_04')
        test_03_00 = self.get_test_result('test_03_00')
        test_03_01 = self.get_test_result('test_03_01')
        test_02_01 = self.get_test_result('test_02_01')
        test_04_01 = self.get_test_result('test_04_01')

        # Auto-detect device capabilities from test results
        has_inputs = not (test_01_01 and test_01_01.state == TestState.COULD_NOT_TEST and
                          test_01_04 and test_01_04.state == TestState.COULD_NOT_TEST)
        has_outputs = not (test_03_00 and test_03_00.state == TestState.COULD_NOT_TEST and
                           test_03_01 and test_03_01.state == TestState.COULD_NOT_TEST)

        # EDID detection
        has_edid_inputs = test_01_01 and test_01_01.state != TestState.COULD_NOT_TEST
        has_edid_outputs = test_03_00 and test_03_00.state != TestState.COULD_NOT_TEST

        if (has_inputs and has_outputs and (has_edid_inputs != has_edid_outputs)):
            raise ValueError("Inputs and outputs must have the same EDID support")

        has_edid = (has_inputs and has_edid_inputs) or (has_outputs and has_edid_outputs)

        # IS-11 sender/receiver detection based on test capability
        # If test_02_01 is "Could Not Test", device has no IS-11 senders
        has_senders = not (test_02_01 and test_02_01.state == TestState.COULD_NOT_TEST)
        has_receivers = not (test_04_01 and test_04_01.state == TestState.COULD_NOT_TEST)

        try:
            # Finalize all flags with validation
            final_with_inputs, final_without_inputs = finalize_flag(
                spec.with_inputs, spec.without_inputs, has_inputs, not has_inputs, "inputs")

            final_with_outputs, final_without_outputs = finalize_flag(
                spec.with_outputs, spec.without_outputs, has_outputs, not has_outputs, "outputs")

            final_edid_supported, final_edid_not_supported = finalize_flag(
                spec.edid_supported, spec.edid_not_supported, has_edid, not has_edid, "edid")

            final_with_senders, final_without_senders = finalize_flag(
                spec.with_senders, spec.without_senders, has_senders, not has_senders, "senders")

            final_with_receivers, final_without_receivers = finalize_flag(
                spec.with_receivers, spec.without_receivers, has_receivers, not has_receivers, "receivers")

            return EnvironmentSpec(
                with_inputs=final_with_inputs,
                without_inputs=final_without_inputs,
                with_outputs=final_with_outputs,
                without_outputs=final_without_outputs,
                edid_supported=final_edid_supported,
                edid_not_supported=final_edid_not_supported,
                with_senders=final_with_senders,
                without_senders=final_without_senders,
                with_receivers=final_with_receivers,
                without_receivers=final_without_receivers
            )
        except ValueError as e:
            print("ERROR: Environment specification contradicts test results:")
            print(f"  - {e}")
            print("\nPlease adjust your command-line arguments to match the device's actual capabilities,")
            print("or run without environment arguments to auto-detect from test results.")
            sys.exit(1)

    def check_device_requirements(self) -> bool:
        """
        Check if the device meets basic IS-11 requirements for sender/receiver support.

        IS-11 specification requires devices to expose at least one IS-11 sender OR receiver.
        Devices may expose both senders and receivers, or only one type.
        """
        if not self.environment_spec:
            return False

        spec = self.environment_spec

        # Determine IS-11 capability based on final environment flags
        has_senders = spec.with_senders is True
        has_receivers = spec.with_receivers is True

        # IS-11 compliance requirements:
        # - Device MUST expose at least one IS-11 sender OR receiver
        # - Device MAY expose both senders and receivers
        # - Device MAY expose only senders OR only receivers
        if has_senders and has_receivers:
            # Device exposes both IS-11 senders and receivers - fully compliant
            pass
        elif has_senders and not has_receivers:
            # Device exposes only IS-11 senders - compliant (allowed by spec)
            pass
        elif not has_senders and has_receivers:
            # Device exposes only IS-11 receivers - compliant (allowed by spec)
            pass
        else:
            # Device exposes neither IS-11 senders nor receivers - NOT compliant
            # This violates the basic requirement that devices must expose IS-11 functionality
            self.failure_reasons.append("Device exposes neither IS-11 senders nor receivers")
            return False

        return True

    def validate_test_results(self) -> Tuple[bool, List[str]]:
        """Validate all test results against IS-11 specification"""
        if not self.environment_spec:
            return False, ["Environment specification not determined"]

        spec = self.environment_spec
        failures = []

        # Check auto_streamcompatibility tests
        # The DuT is considered to have FAIL if the result of an
        # auto_streamcompatibility_* test case is any value other
        # than PASS, Could Not Test or Test Disabled.
        for test_name, test_result in self.test_results.items():
            if test_name.startswith('auto_streamcompatibility_'):
                if test_result.state not in [TestState.PASS, TestState.COULD_NOT_TEST, TestState.TEST_DISABLED]:
                    failures.append(f"Auto stream compatibility test {test_name} failed: {test_result.state}")

        # Check streamcompatibility tests
        # The DuT is considered to have FAIL if the result of a test
        # case is any value other than PASS or Could Not Test.
        for test_name, test_result in self.test_results.items():
            if test_name.startswith('test_'):
                if test_result.state not in [TestState.PASS, TestState.COULD_NOT_TEST]:
                    failures.append(f"Stream compatibility test {test_name} failed: {test_result.state}")

        # Validate basic requirements
        test_00_00 = self.get_test_result('test_00_00')
        if not test_00_00 or test_00_00.state != TestState.PASS:
            failures.append("test_00_00 (IS-11 API advertisement) must PASS")

        # Validate based on input capabilities
        if spec.with_inputs:
            self._validate_input_tests(failures)

        # Validate based on output capabilities
        if spec.with_outputs:
            self._validate_output_tests(failures)

        # Validate IS-11 functionality based on detected capabilities
        # Environment flags are already guaranteed to match test results (from _finalize_environment_flags)
        if spec.with_senders:
            self._validate_sender_tests(failures)

        if spec.with_receivers:
            self._validate_receiver_tests(failures)

        self.failure_reasons = failures
        self.final_verdict = len(failures) == 0

        return self.final_verdict, failures

    def _validate_input_tests(self, failures: List[str]):
        """Validate input-related tests"""
        spec = self.environment_spec

        # Only validate if we have inputs
        has_inputs = spec.with_inputs

        if has_inputs:
            # test_01_00 should pass if there are inputs
            test_01_00 = self.get_test_result('test_01_00')
            if test_01_00 and test_01_00.state != TestState.PASS:
                failures.append("test_01_00 (input signal verification) must PASS when inputs are available")

            # Validate EDID tests based on finalized EDID support flags
            if spec.edid_supported:
                # Device supports EDID - expect HDMI/DisplayPort behavior
                self._validate_edid_input_tests(failures)
            else:
                # Device does not support EDID - expect non-HDMI/DisplayPort behavior
                self._validate_non_edid_input_tests(failures)

    def _validate_edid_input_tests(self, failures: List[str]):
        """Validate input tests for HDMI/DisplayPort inputs"""
        # test_01_01 should PASS (EDID support expected)
        test_01_01 = self.get_test_result('test_01_01')
        if test_01_01 and test_01_01.state != TestState.PASS:
            failures.append("test_01_01 must PASS for inputs with EDID support")

        # Base EDID tests are optional but should be PASS or Could Not Test
        base_edid_tests = ['test_01_02', 'test_01_03', 'test_01_05', 'test_01_06']
        for test_name in base_edid_tests:
            test_result = self.get_test_result(test_name)
            if test_result and test_result.state not in [TestState.PASS]:
                failures.append(f"{test_name} must be PASS for inputs with EDID support "
                                "(Base EDID support is required)")

        # test_01_04 should be Could Not Test (no inputs without EDID support)
        test_01_04 = self.get_test_result('test_01_04')
        if test_01_04 and test_01_04.state != TestState.COULD_NOT_TEST:
            failures.append("test_01_04 should be Could Not Test when all inputs support EDID")

    def _validate_non_edid_input_tests(self, failures: List[str]):
        """Validate input tests for non-HDMI/DisplayPort inputs"""
        # EDID tests should be Could Not Test
        edid_tests = ['test_01_01', 'test_01_02', 'test_01_03', 'test_01_05', 'test_01_06']
        for test_name in edid_tests:
            test_result = self.get_test_result(test_name)
            if test_result and test_result.state != TestState.COULD_NOT_TEST:
                failures.append(f"{test_name} should be Could Not Test for inputs without EDID support")

        # test_01_04 should PASS (no EDID support expected)
        test_01_04 = self.get_test_result('test_01_04')
        if test_01_04 and test_01_04.state != TestState.PASS:
            failures.append("test_01_04 must PASS for inputs without EDID support")

    def _validate_output_tests(self, failures: List[str]):
        """Validate output-related tests"""
        spec = self.environment_spec

        # Only validate if we have outputs
        has_outputs = spec.with_outputs

        if has_outputs:
            # Validate EDID tests based on finalized EDID support flags
            # Environment finalization guarantees EDID flags are set appropriately
            if spec.edid_supported:
                # Device supports EDID - expect HDMI/DisplayPort behavior
                test_03_00 = self.get_test_result('test_03_00')
                if test_03_00 and test_03_00.state != TestState.PASS:
                    failures.append("test_03_00 must PASS for outputs with EDID support")

                test_03_01 = self.get_test_result('test_03_01')
                if test_03_01 and test_03_01.state != TestState.COULD_NOT_TEST:
                    failures.append("test_03_01 must be Could Not Test for connected outputs")
            else:
                # Device does not support EDID - expect non-HDMI/DisplayPort behavior
                test_03_00 = self.get_test_result('test_03_00')
                if test_03_00 and test_03_00.state != TestState.COULD_NOT_TEST:
                    failures.append("test_03_00 must be Could Not Test for outputs without EDID support")

                test_03_01 = self.get_test_result('test_03_01')
                if test_03_01 and test_03_01.state != TestState.COULD_NOT_TEST:
                    failures.append("test_03_01 must be Could Not Test for connected outputs")

    def _validate_sender_tests(self, failures: List[str]):
        """Validate IS-11 sender tests"""
        # Required sender tests
        required_sender_tests = [
            'test_02_00', 'test_02_01', 'test_02_01_01', 'test_02_02',
            'test_02_02_01', 'test_02_02_03', 'test_02_02_03_01',
            'test_02_02_03_02', 'test_06_01', 'test_06_02', 'test_06_03'
        ]

        for test_name in required_sender_tests:
            test_result = self.get_test_result(test_name)
            if test_result and test_result.state not in [TestState.PASS]:
                failures.append(f"{test_name} must be PASS")

        # Validate sender constraint tests
        constraint_tests = [
            'test_02_02_04_01', 'test_02_02_04_02', 'test_02_02_05_01',
            'test_02_02_05_02', 'test_02_02_06_01', 'test_02_02_06_02',
            'test_02_02_07_01', 'test_02_02_07_02'
        ]

        for test_name in constraint_tests:
            test_result = self.get_test_result(test_name)
            if test_result and test_result.state not in [TestState.PASS]:
                failures.append(f"{test_name} must PASS")

        # Validate sender input support consistency
        self._validate_sender_input_consistency(failures)

    def _validate_sender_input_consistency(self, failures: List[str]):
        """Validate sender input support consistency based on environment specification"""

        # Base tests that apply to all senders with inputs
        with_input_tests = [
            'test_02_03_00', 'test_02_03_01', 'test_02_03_02', 'test_02_03_03'
        ]

        without_input_tests = [
            'test_02_04', 'test_02_04_01'
        ]

        # EDID-related tests that depend on EDID support
        edid_input_tests = [
            'test_02_03_04', 'test_02_03_05_01', 'test_02_03_05_02'
        ]

        if self.environment_spec.with_inputs:
            # Device has inputs - these tests should PASS
            for test_name in with_input_tests:
                test_result = self.get_test_result(test_name)
                if test_result and test_result.state != TestState.PASS:
                    failures.append(f"{test_name} must PASS for sender with inputs")

            for test_name in without_input_tests:
                test_result = self.get_test_result(test_name)
                if test_result and test_result.state != TestState.COULD_NOT_TEST:
                    failures.append(f"{test_name} must be Could Not Test for sender without inputs")

            if self.environment_spec.edid_supported:
                # Device supports EDID - EDID tests should PASS
                for test_name in edid_input_tests:
                    test_result = self.get_test_result(test_name)
                    if test_result and test_result.state != TestState.PASS:
                        failures.append(f"{test_name} must PASS for sender with inputs and EDID support")
            else:
                # Device does not support EDID - EDID tests should be Could Not Test
                for test_name in edid_input_tests:
                    test_result = self.get_test_result(test_name)
                    if test_result and test_result.state != TestState.COULD_NOT_TEST:
                        failures.append(f"{test_name} must be Could Not Test for sender with "
                                        "inputs and no EDID support")
        else:
            # Device has no inputs - all input support tests should be Could Not Test
            all_input_tests = with_input_tests + edid_input_tests
            for test_name in all_input_tests:
                test_result = self.get_test_result(test_name)
                if test_result and test_result.state != TestState.COULD_NOT_TEST:
                    failures.append(f"{test_name} must be Could Not Test for sender without inputs")

            for test_name in without_input_tests:
                test_result = self.get_test_result(test_name)
                if test_result and test_result.state != TestState.PASS:
                    failures.append(f"{test_name} must PASS for sender without inputs")

    def _validate_receiver_tests(self, failures: List[str]):
        """Validate IS-11 receiver tests"""
        # Required receiver tests
        required_receiver_tests = [
            'test_04_01', 'test_04_01_01', 'test_04_02', 'test_04_02_01', 'test_04_02_02'
        ]

        for test_name in required_receiver_tests:
            test_result = self.get_test_result(test_name)
            if test_result and test_result.state not in [TestState.PASS, TestState.COULD_NOT_TEST]:
                failures.append(f"{test_name} must be PASS or Could Not Test")

        # Validate receiver output support consistency
        self._validate_receiver_output_consistency(failures)

    def _validate_receiver_output_consistency(self, failures: List[str]):
        """Validate receiver output support consistency based on environment specification"""
        spec = self.environment_spec
        with_output_tests = [
            'test_04_03', 'test_04_03_01', 'test_04_03_01_01', 'test_04_03_02', 'test_04_03_02_01'
        ]
        without_output_tests = [
            'test_04_04', 'test_04_04_01', 'test_04_04_02',
        ]

        if spec.with_outputs:
            for test_name in with_output_tests:
                test_result = self.get_test_result(test_name)
                if test_result and test_result.state != TestState.PASS:
                    failures.append(f"{test_name} must PASS for receiver with outputs")

            for test_name in without_output_tests:
                test_result = self.get_test_result(test_name)
                if test_result and test_result.state != TestState.COULD_NOT_TEST:
                    failures.append(f"{test_name} must be Could Not Test for receiver without outputs")
        else:
            for test_name in with_output_tests:
                test_result = self.get_test_result(test_name)
                if test_result and test_result.state != TestState.COULD_NOT_TEST:
                    failures.append(f"{test_name} must be Could Not Test for receiver with outputs")

            for test_name in without_output_tests:
                test_result = self.get_test_result(test_name)
                if test_result and test_result.state != TestState.PASS:
                    failures.append(f"{test_name} must PASS for receiver without outputs")

    def print_environment_spec(self):
        """Print the determined environment specification"""
        if not self.environment_spec:
            print("Environment specification not determined")
            return

        spec = self.environment_spec
        print("\n=== ENVIRONMENT SPECIFICATION ===")

        # Show device capabilities based on final with_/without_ flags
        if spec.with_inputs:
            print("Inputs: Yes")
        elif spec.without_inputs:
            print("Inputs: No")

        if spec.with_outputs:
            print("Outputs: Yes")
        elif spec.without_outputs:
            print("Outputs: No")

        if spec.edid_supported:
            print("EDID: Yes")
        elif spec.edid_not_supported:
            print("EDID: No")

        if spec.with_senders:
            print("IS-11 Senders: Yes")
        elif spec.without_senders:
            print("IS-11 Senders: No")

        if spec.with_receivers:
            print("IS-11 Receivers: Yes")
        elif spec.without_receivers:
            print("IS-11 Receivers: No")

    def print_test_results_summary(self):
        """Print a summary of test results"""
        print("\n=== TEST RESULTS SUMMARY ===")

        states = {}
        for test_result in self.test_results.values():
            state_str = test_result.state.value
            if (not test_result.name.startswith('test_') and
                    not test_result.name.startswith('auto_streamcompatibility_')):
                continue
            states[state_str] = states.get(state_str, 0) + 1

        for state, count in sorted(states.items()):
            print(f"{state}: {count} tests")

        print(f"\nTotal tests: {len(self.test_results)}")

    def print_verdict(self):
        """Print the final pass/fail verdict"""
        print("\n=== FINAL VERDICT ===")
        if self.final_verdict:
            print("PASS - Device meets IS-11 Stream Compatibility Management requirements")
        else:
            print("FAIL - Device does not meet IS-11 Stream Compatibility Management requirements")
            print("\nFailure reasons:")
            for i, reason in enumerate(self.failure_reasons, 1):
                print(f"{i}. {reason}")

    def run_analysis(self):
        """Run the complete analysis"""
        print(f"Analyzing IS-11 test results from: {self.json_file_path}")

        if not self.load_results():
            return False

        self.analyze_environment()
        self.check_device_requirements()
        self.validate_test_results()

        self.print_environment_spec()
        self.print_test_results_summary()
        self.print_verdict()

        return self.final_verdict


def main():
    parser = argparse.ArgumentParser(description='IS-11 Stream Compatibility Management Test Results Analyzer')
    parser.add_argument('json_file', help='Path to the JSON test results file')

    # Environment specification arguments
    env_group = parser.add_argument_group('Environment Specification')
    env_group.add_argument('--with-inputs', action='store_true',
                           help='Device has inputs (default: auto-detect)')
    env_group.add_argument('--without-inputs', action='store_true',
                           help='Device has no inputs (default: auto-detect)')
    env_group.add_argument('--with-outputs', action='store_true',
                           help='Device has outputs (default: auto-detect)')
    env_group.add_argument('--without-outputs', action='store_true',
                           help='Device has no outputs (default: auto-detect)')
    env_group.add_argument('--edid-supported', action='store_true',
                           help='Device supports EDID (default: auto-detect)')
    env_group.add_argument('--edid-not-supported', action='store_true',
                           help='Device does not support EDID (default: auto-detect)')
    env_group.add_argument('--with-senders', action='store_true',
                           help='Device has IS-11 senders (default: auto-detect)')
    env_group.add_argument('--without-senders', action='store_true',
                           help='Device has no IS-11 senders (default: auto-detect)')
    env_group.add_argument('--with-receivers', action='store_true',
                           help='Device has IS-11 receivers (default: auto-detect)')
    env_group.add_argument('--without-receivers', action='store_true',
                           help='Device has no IS-11 receivers (default: auto-detect)')

    args = parser.parse_args()

    # Validate mutually exclusive arguments
    if args.with_inputs and args.without_inputs:
        parser.error("--with-inputs and --without-inputs are mutually exclusive")
    if args.with_outputs and args.without_outputs:
        parser.error("--with-outputs and --without-outputs are mutually exclusive")
    if args.edid_supported and args.edid_not_supported:
        parser.error("--edid-supported and --edid-not-supported are mutually exclusive")
    if args.with_senders and args.without_senders:
        parser.error("--with-senders and --without-senders are mutually exclusive")
    if args.with_receivers and args.without_receivers:
        parser.error("--with-receivers and --without-receivers are mutually exclusive")

    # Create environment specification from arguments
    # Convert False to None for flags that weren't specified (since argparse defaults to False)
    import sys
    with_senders = args.with_senders if '--with-senders' in sys.argv else None
    without_senders = args.without_senders if '--without-senders' in sys.argv else None
    with_receivers = args.with_receivers if '--with-receivers' in sys.argv else None
    without_receivers = args.without_receivers if '--without-receivers' in sys.argv else None
    with_inputs = args.with_inputs if '--with-inputs' in sys.argv else None
    without_inputs = args.without_inputs if '--without-inputs' in sys.argv else None
    with_outputs = args.with_outputs if '--with-outputs' in sys.argv else None
    without_outputs = args.without_outputs if '--without-outputs' in sys.argv else None
    edid_supported = args.edid_supported if '--edid-supported' in sys.argv else None
    edid_not_supported = args.edid_not_supported if '--edid-not-supported' in sys.argv else None

    env_spec = None
    if any([with_inputs, without_inputs, with_outputs, without_outputs,
            edid_supported, edid_not_supported, with_senders, without_senders,
            with_receivers, without_receivers]):
        env_spec = EnvironmentSpec(
            with_inputs=with_inputs,
            without_inputs=without_inputs,
            with_outputs=with_outputs,
            without_outputs=without_outputs,
            edid_supported=edid_supported,
            edid_not_supported=edid_not_supported,
            with_senders=with_senders,
            without_senders=without_senders,
            with_receivers=with_receivers,
            without_receivers=without_receivers
        )

    try:
        analyzer = IS11TestAnalyzer(args.json_file, env_spec)
        success = analyzer.run_analysis()
    except Exception as e:
        print(f"ERROR: {e}")

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
