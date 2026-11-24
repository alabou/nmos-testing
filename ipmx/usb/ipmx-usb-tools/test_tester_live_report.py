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
Tests of ipmx_usb_tester's live output: each finding is printed once, a reconnect does not
print the earlier findings again, and a closed connection is attributed to the side that
closed it.

    python3 -m unittest test_tester_live_report -v
"""

import contextlib
import io
import socket
import unittest

import ipmx_usb_message as usb
from ipmx_usb_message import MsgType
from ipmx_usb_tester import IpmxChannel, IpmxReceiverSession
from usbDissector import ChannelRole, Severity

SENDER, RECEIVER = '192.0.2.1', '192.0.2.2'
SENDER_KV, RECEIVER_KV = 0x2D9BC4E0, 0x11111111
_MAC = b'\x5a' * 8   # any non-zero MAC: an encrypted message as far as the checks go


def _msg(msg_type: MsgType, data_len: int, ctr: int, key_version: int) -> usb.IpmxUsbMessage:
    return usb.parse_one(usb.build_message(msg_type, b'\x00' * data_len,
                                           ctr=ctr, key_version=key_version, mac=_MAC))


def _session() -> IpmxReceiverSession:
    return IpmxReceiverSession(SENDER, 27502, RECEIVER, 40000, bytes.fromhex('0050C2'), 'unit-test',
                               live_validate=True, encrypted=True)


def _live_lines(text: str, needle: str) -> list:
    return [ln for ln in text.splitlines() if '[LIVE' in ln and needle in ln]


class LiveReport(unittest.TestCase):

    def test_a_reconnect_does_not_print_earlier_findings_again(self):
        sess, out = _session(), io.StringIO()
        with contextlib.redirect_stdout(out):
            # Control channel: the Sender Connection Information uses CTR 0..4, so a heartbeat at
            # CTR 1 re-uses its counter values: one DIAG, found when the Receiver next speaks.
            sess.record_ctrl_msg(_msg(MsgType.SENDER_CONNECTION_INFO, 66, 0, SENDER_KV),
                                 'sender', SENDER, 27502, RECEIVER, 50000)
            sess.record_ctrl_msg(_msg(MsgType.SENDER_CONNECTION_STATUS, 68, 0, RECEIVER_KV),
                                 'receiver', RECEIVER, 50000, SENDER, 27502)
            sess.record_ctrl_msg(_msg(MsgType.HEARTBEAT, 0, 1, SENDER_KV),
                                 'sender', SENDER, 27502, RECEIVER, 50000)
            sess.record_ctrl_msg(_msg(MsgType.VENDOR_SPECIFIC_QUERY_RETURN, 5, 5, RECEIVER_KV),
                                 'receiver', RECEIVER, 50000, SENDER, 27502)
            # Then a data channel opens, closes and reopens on the same SUBSTREAMID.
            for n, port in enumerate((50001, 50002), 1):
                sess.reset_data_for_reconnect(4)
                sess.record_data_msg(_msg(MsgType.USB_STREAM_INFO, 66, 0, SENDER_KV + n),
                                     4, 'sender', SENDER, port, RECEIVER, 40000)
                sess.record_data_msg(_msg(MsgType.USB_STREAM_STATUS, 1, 0, RECEIVER_KV + n),
                                     4, 'receiver', RECEIVER, 40000, SENDER, port)
        self.assertEqual(len(_live_lines(out.getvalue(), 'HEARTBEAT CTR=1')), 1, out.getvalue())

    def test_each_tester_finding_is_printed_once(self):
        # As a Sender that closes the control channel before its first message, three times.
        sess, out = _session(), io.StringIO()
        with contextlib.redirect_stdout(out):
            for _ in range(3):
                sess.reset_ctrl_for_reconnect()
                sess.add_tester_finding(Severity.DIAG, "8.3.1.1",
                                        "Control channel: no SenderConnectionInfo")
        self.assertEqual(len(_live_lines(out.getvalue(), 'no SenderConnectionInfo')), 3,
                         out.getvalue())

    def test_the_same_text_on_another_connection_is_printed_again(self):
        # The same DIAG text on two control connections is two occurrences.
        sess, out = _session(), io.StringIO()
        with contextlib.redirect_stdout(out):
            for port in (50000, 50010):
                sess.reset_ctrl_for_reconnect()
                for msg, role in ((_msg(MsgType.SENDER_CONNECTION_INFO, 66, 0, SENDER_KV), 'sender'),
                                  (_msg(MsgType.SENDER_CONNECTION_STATUS, 68, 0, RECEIVER_KV), 'receiver'),
                                  (_msg(MsgType.HEARTBEAT, 0, 1, SENDER_KV), 'sender'),
                                  (_msg(MsgType.VENDOR_SPECIFIC_QUERY_RETURN, 5, 5, RECEIVER_KV), 'receiver')):
                    ends = ((SENDER, 27502, RECEIVER, port) if role == 'sender'
                            else (RECEIVER, port, SENDER, 27502))
                    sess.record_ctrl_msg(msg, role, *ends)
        self.assertEqual(len(_live_lines(out.getvalue(), 'HEARTBEAT CTR=1')), 2, out.getvalue())


class CloseAttribution(unittest.TestCase):
    """IpmxChannel.closed_by: which side ended the TCP connection."""

    def _channel(self):
        ours, peer = socket.socketpair()
        self.addCleanup(peer.close)
        return IpmxChannel(ours, RECEIVER, 40000, SENDER, 50001), peer

    def test_the_sender_closing(self):
        ch, peer = self._channel()
        peer.close()
        self.assertIsNone(ch.recv_msg(timeout=2.0))
        self.assertTrue(ch.closed)
        self.assertIs(ch.closed_by, ChannelRole.SENDER)

    def test_the_tester_closing(self):
        ch, _peer = self._channel()
        ch.close()
        self.assertIsNone(ch.recv_msg(timeout=2.0))
        self.assertTrue(ch.closed)
        self.assertIs(ch.closed_by, ChannelRole.RECEIVER)

    def test_the_tester_closing_after_the_sender_keeps_the_sender(self):
        ch, peer = self._channel()
        peer.close()
        ch.recv_raw(timeout=2.0)
        ch.close()
        self.assertIs(ch.closed_by, ChannelRole.SENDER)


if __name__ == '__main__':
    unittest.main()
