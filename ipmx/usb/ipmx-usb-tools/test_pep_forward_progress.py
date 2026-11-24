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

"""
Tests of the TR-10-13 §18 forward-progress checks of the in-band KEYVERSION and CTR
(usbDissector, also run live by ipmx_usb_tester) and of the tester's Receiver-to-Sender
KEYVERSION, one per TCP connection.

    python3 -m unittest test_pep_forward_progress -v
"""

import threading
import unittest

import ipmx_pep as pepmod
import ipmx_usb_message as usb
from ipmx_usb_message import MsgType
from ipmx_usb_tester import IpmxReceiverSession
from usbDissector import (
    ChannelMessage, DataChannel, Requirement, Session, Severity,
    _check_keyversion_nonzero, _check_pep_forward_progress,
    _validate_control_channel, _validate_data_channel,
)

KV = 0x2D9BC4E0      # the key_version of TR-10-14's SDP example (§14.1)
_MAC = b'\x5a' * 8   # any non-zero MAC: the checks read only the clear header

# DATA sizes, and the 16-byte slices each message then encrypts (DATA + MAC)
_STREAM_INFO_DATA = 66     # 90-byte message: 5 slices
_SUBMIT_RETURN_DATA = 20   # 44-byte message: 2 slices
_HEARTBEAT_DATA = 0        # 24-byte message: 1 slice
_SCI_DATA = 66             # 90-byte message: 5 slices


def _captured(msg_type: MsgType, data_len: int, ctr: int, key_version: int,
              packet_number: int) -> ChannelMessage:
    """One message as a capture holds it, with *ctr* and *key_version* in its clear header."""
    raw = usb.build_message(msg_type, b'\x00' * data_len,
                            ctr=ctr, key_version=key_version, mac=_MAC)
    return ChannelMessage(packet_number=packet_number, timestamp=float(packet_number),
                          src_ip='192.0.2.1', src_port=27502, dst_ip='192.0.2.2', dst_port=40000,
                          msg=usb.parse_one(raw))


def _session() -> Session:
    return Session(sender_ip='192.0.2.1', sender_port=27502, receiver_ip='192.0.2.2')


def _findings(session: Session, requirement: Requirement) -> list:
    return [f for f in session.findings if f.requirement is requirement]


class SliceArithmetic(unittest.TestCase):

    def test_slices_per_message(self):
        self.assertEqual(pepmod.usb_ctr_advance(16 + _STREAM_INFO_DATA + 8), 5)
        self.assertEqual(pepmod.usb_ctr_advance(16 + _SUBMIT_RETURN_DATA + 8), 2)
        self.assertEqual(pepmod.usb_ctr_advance(16 + _HEARTBEAT_DATA + 8), 1)


class ForwardProgress(unittest.TestCase):
    """_check_pep_forward_progress() on the messages one side sends on one TCP connection."""

    def _check(self, msgs: list) -> Session:
        s = _session()
        _check_pep_forward_progress(s, msgs, "Sender->Receiver (data)")
        return s

    def test_counter_stepping_by_slice_passes(self):
        s = self._check([
            _captured(MsgType.USB_STREAM_INFO, _STREAM_INFO_DATA, 0, KV, 1),             # 0..4
            _captured(MsgType.USB_CONTROL_SUBMIT_RETURN, _SUBMIT_RETURN_DATA, 5, KV, 2),  # 5..6
            _captured(MsgType.USB_CONTROL_SUBMIT_RETURN, _SUBMIT_RETURN_DATA, 7, KV, 3),
            _captured(MsgType.USB_CONTROL_SUBMIT_RETURN, _SUBMIT_RETURN_DATA, 9, KV, 4),
        ])
        self.assertEqual(s.findings, [])

    def test_skipping_values_ahead_passes(self):
        s = self._check([
            _captured(MsgType.USB_STREAM_INFO, _STREAM_INFO_DATA, 0, KV, 1),
            _captured(MsgType.USB_CONTROL_SUBMIT_RETURN, _SUBMIT_RETURN_DATA, 100, KV, 2),
            _captured(MsgType.USB_CONTROL_SUBMIT_RETURN, _SUBMIT_RETURN_DATA, 102, KV, 3),
        ])
        self.assertEqual(s.findings, [])

    def test_first_message_is_the_baseline(self):
        s = self._check([_captured(MsgType.USB_STREAM_INFO, _STREAM_INFO_DATA, 12345, KV, 1)])
        self.assertEqual(s.findings, [])

    def test_restart_at_zero_under_the_same_keyversion_is_diag(self):
        # The counter goes back to 0 after the sub-stream switch, under the same key.
        s = self._check([
            _captured(MsgType.USB_STREAM_INFO, _STREAM_INFO_DATA, 0, KV, 1),
            _captured(MsgType.USB_CONTROL_SUBMIT_RETURN, _SUBMIT_RETURN_DATA, 0, KV, 2),
        ])
        found = _findings(s, Requirement.PEP_CTR_FORWARD)
        self.assertEqual([f.packet_number for f in found], [2])
        self.assertTrue(all(f.severity is Severity.DIAG for f in s.findings))
        self.assertEqual(found[0].section, "TR-10-13 18")
        self.assertIn("forward progress needs CTR 5 or more", found[0].description)

    def test_counter_stepping_by_message_is_diag_on_every_reused_slice(self):
        # Sender Connection Information uses CTR 0..4; heartbeats then step by one message.
        s = _session()
        _check_pep_forward_progress(s, [
            _captured(MsgType.SENDER_CONNECTION_INFO, _SCI_DATA, 0, KV, 1),
            *[_captured(MsgType.HEARTBEAT, _HEARTBEAT_DATA, ctr, KV, 1 + ctr)
              for ctr in range(1, 8)],
        ], "Sender->Receiver (control)")
        found = _findings(s, Requirement.PEP_CTR_FORWARD)
        # CTR 1..4 re-use the slices of the Sender Connection Information; 5, 6, 7 do not.
        self.assertEqual([f.packet_number for f in found], [2, 3, 4, 5])

    def test_multi_slice_messages_stepping_by_one_are_diag(self):
        s = self._check([
            _captured(MsgType.USB_CONTROL_SUBMIT_RETURN, _SUBMIT_RETURN_DATA, ctr, KV, 1 + ctr)
            for ctr in range(4)
        ])
        self.assertEqual([f.packet_number for f in _findings(s, Requirement.PEP_CTR_FORWARD)],
                         [2, 3, 4])

    def test_new_keyversion_starts_a_counter_space_of_its_own(self):
        s = self._check([
            _captured(MsgType.USB_STREAM_INFO, _STREAM_INFO_DATA, 0, KV, 1),
            _captured(MsgType.USB_CONTROL_SUBMIT_RETURN, _SUBMIT_RETURN_DATA, 0, KV + 1, 2),
            _captured(MsgType.USB_CONTROL_SUBMIT_RETURN, _SUBMIT_RETURN_DATA, 2, KV + 1, 3),
        ])
        self.assertEqual(s.findings, [])

    def test_keyversion_going_back_is_diag_and_its_counter_space_is_kept(self):
        s = self._check([
            _captured(MsgType.USB_STREAM_INFO, _STREAM_INFO_DATA, 0, KV, 1),
            _captured(MsgType.USB_CONTROL_SUBMIT_RETURN, _SUBMIT_RETURN_DATA, 0, KV + 1, 2),
            _captured(MsgType.USB_CONTROL_SUBMIT_RETURN, _SUBMIT_RETURN_DATA, 0, KV, 3),
        ])
        self.assertEqual([f.packet_number for f in _findings(s, Requirement.PEP_KEYVERSION_FORWARD)],
                         [3])
        # Back under KV, CTR 0 re-uses that key's slices 0..4.
        self.assertEqual([f.packet_number for f in _findings(s, Requirement.PEP_CTR_FORWARD)], [3])

    def test_keyversion_wrapping_around_moves_forward(self):
        s = self._check([
            _captured(MsgType.USB_STREAM_INFO, _STREAM_INFO_DATA, 0, 0xFFFFFFFF, 1),
            _captured(MsgType.USB_CONTROL_SUBMIT_RETURN, _SUBMIT_RETURN_DATA, 0, 0x00000001, 2),
        ])
        self.assertEqual(s.findings, [])

    def test_keyversion_half_the_range_ahead_is_diag(self):
        s = self._check([
            _captured(MsgType.USB_STREAM_INFO, _STREAM_INFO_DATA, 0, KV, 1),
            _captured(MsgType.USB_CONTROL_SUBMIT_RETURN, _SUBMIT_RETURN_DATA, 0,
                      (KV + (1 << 31)) % (1 << 32), 2),
        ])
        self.assertEqual([f.packet_number for f in _findings(s, Requirement.PEP_KEYVERSION_FORWARD)],
                         [2])

    def test_counter_wrapping_around_moves_forward(self):
        s = self._check([
            _captured(MsgType.USB_CONTROL_SUBMIT_RETURN, _SUBMIT_RETURN_DATA, (1 << 64) - 1, KV, 1),
            _captured(MsgType.USB_CONTROL_SUBMIT_RETURN, _SUBMIT_RETURN_DATA, 1, KV, 2),
        ])
        self.assertEqual(s.findings, [])


class KeyVersionNonZero(unittest.TestCase):

    def test_zero_keyversion_on_an_encrypted_message_is_an_error(self):
        s = _session()
        _check_keyversion_nonzero(
            s, [_captured(MsgType.USB_STREAM_INFO, _STREAM_INFO_DATA, 7, 0, 1)], [], "Data")
        found = _findings(s, Requirement.KEYVERSION_NONZERO)
        self.assertEqual([(f.severity, f.packet_number) for f in found], [(Severity.ERROR, 1)])

    def test_replaced_rows_are_gone(self):
        # The forward-progress rows replace "CTR SHALL increase monotonically" and "KEYVERSION
        # SHALL be consistent within a TCP session", which TR-10-14 §12 does not state.
        self.assertNotIn('CTR_MONOTONIC', Requirement.__members__)
        self.assertNotIn('KEYVERSION_NONZERO_CONSISTENT', Requirement.__members__)


class ValidatorsRunTheChecks(unittest.TestCase):
    """Both directions of each channel go through the checks, in the dissector and the tester."""

    def test_control_channel(self):
        s = _session()
        sender = [_captured(MsgType.SENDER_CONNECTION_INFO, _SCI_DATA, 0, KV, 1),
                  _captured(MsgType.HEARTBEAT, _HEARTBEAT_DATA, 1, KV, 3)]
        receiver = [_captured(MsgType.SENDER_CONNECTION_STATUS, 68, 0, KV ^ 0xFFFF, 2),
                    _captured(MsgType.VENDOR_SPECIFIC_QUERY_RETURN, 5, 0, KV ^ 0xFFFF, 4)]
        _validate_control_channel(s, sender, receiver, None, None, True, False)
        self.assertEqual(sorted(f.packet_number for f in _findings(s, Requirement.PEP_CTR_FORWARD)),
                         [3, 4])

    def test_data_channel(self):
        s = _session()
        sender = [_captured(MsgType.USB_STREAM_INFO, _STREAM_INFO_DATA, 0, KV, 1),
                  _captured(MsgType.USB_CONTROL_SUBMIT_RETURN, _SUBMIT_RETURN_DATA, 0, KV, 4)]
        receiver = [_captured(MsgType.USB_STREAM_STATUS, 1, 0, KV + 7, 2),
                    _captured(MsgType.USB_CONTROL_SUBMIT, 20, 1, KV + 7, 3)]
        _validate_data_channel(s, DataChannel(substreamid=4, busid='', usbspeed=0),
                               sender, receiver, encrypted=True)
        self.assertEqual([f.packet_number for f in _findings(s, Requirement.PEP_CTR_FORWARD)], [4])


class ReceiverKeyVersion(unittest.TestCase):
    """The tester's KEYVERSION on its Receiver-to-Sender messages, per TCP connection."""

    def _session(self, kv_mode: pepmod.KvMode = pepmod.KvMode.RANDOM) -> IpmxReceiverSession:
        return IpmxReceiverSession('192.0.2.1', 27502, '192.0.2.2', 40000,
                                   bytes.fromhex('0050C2'), 'unit-test', live_validate=False,
                                   kv_mode=kv_mode)

    def test_one_more_for_each_connection(self):
        sess = self._session()
        first = sess.resolve_r2s_kv(KV, 0x11111111)
        self.assertNotEqual(first, 0)
        self.assertEqual([sess.resolve_r2s_kv(KV, 0x11111111) for _ in range(3)],
                         [(first + n) % (1 << 32) or 1 for n in (1, 2, 3)])

    def test_wrap_around_skips_zero(self):
        sess = self._session()
        sess._next_r2s_kv = 0xFFFFFFFF
        self.assertEqual([sess.resolve_r2s_kv(KV, 0), sess.resolve_r2s_kv(KV, 0)],
                         [0xFFFFFFFF, 0x00000001])

    def test_unique_across_connection_threads(self):
        sess = self._session()
        values: list[int] = []
        lock = threading.Lock()

        def connections() -> None:
            got = [sess.resolve_r2s_kv(KV, 0) for _ in range(200)]
            with lock:
                values.extend(got)

        threads = [threading.Thread(target=connections) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(values), 1600)
        self.assertEqual(len(set(values)), 1600)

    def test_debugging_modes(self):
        self.assertEqual(self._session(pepmod.KvMode.S2R).resolve_r2s_kv(KV, 0x11111111), KV)
        self.assertEqual(self._session(pepmod.KvMode.SDP).resolve_r2s_kv(KV, 0x11111111),
                         0x11111111)
        self.assertIsNone(pepmod.KvMode.RANDOM.debug_risk)
        self.assertIn("re-use", pepmod.KvMode.S2R.debug_risk)
        self.assertIn("re-use", pepmod.KvMode.SDP.debug_risk)


if __name__ == '__main__':
    unittest.main()
