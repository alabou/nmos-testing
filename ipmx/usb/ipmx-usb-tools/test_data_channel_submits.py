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
Tests of the dissector's checks of the USB Submits a Receiver sends on a data channel:

- the USB Cancel Submit against TR-10-14 §9.22, Table 17: its SEQNUM, ENDPOINT and D match the
  USB Submit it cancels, and its DATA is the table's fields, 4 bytes;
- the SEQNUM of each Submit, cited to the section of its type and the table holding the rule
  (§9.14 Table 10, §9.15 and §9.16 Table 11, §9.17 Table 12).

    python3 -m unittest test_data_channel_submits -v
"""

import unittest

import ipmx_usb_message as usb
from ipmx_usb_message import MsgType, StatusCode
from usbDissector import (
    ChannelMessage, DataChannel, Requirement, Session, Severity, _validate_data_channel,
)

_SENDER = ('192.0.2.1', 27502)
_RECEIVER = ('192.0.2.2', 40000)
_GET_DEVICE_DESCRIPTOR = bytes.fromhex('8006000100004000')    # SETUP: GET_DESCRIPTOR(Device), 64 bytes


def _control_in(seqnum: int) -> bytes:
    return usb.build_usb_control_submit(seqnum, 0, 1, 0, 64, _GET_DEVICE_DESCRIPTOR)


def _control_in_return(seqnum: int) -> bytes:
    return usb.build_usb_control_submit_return(seqnum, 0, 1, 18, StatusCode.SUCCESS, b'\x12' + b'\x00' * 17)


def _interrupt_in(seqnum: int, endpoint: int) -> bytes:
    return usb.build_usb_interrupt_submit(seqnum, endpoint, 1, 8, 8)


def _interrupt_in_return(seqnum: int, endpoint: int) -> bytes:
    return usb.build_usb_interrupt_submit_return(seqnum, endpoint, 1, 3, StatusCode.SUCCESS, b'\x00' * 3)


def _cancel(seqnum: int, endpoint: int, direction: int, past_table_17: bytes = b'') -> bytes:
    """A USB Cancel Submit: Table 17's SEQNUM, ENDPOINT and D, then *past_table_17*, which no field
    of the table accounts for."""
    data = seqnum.to_bytes(3, 'big') + bytes([(endpoint << 4) | direction]) + past_table_17
    return usb.build_message(MsgType.USB_CANCEL_SUBMIT, data)


def _cancel_return(seqnum: int, endpoint: int, direction: int) -> bytes:
    return usb.build_usb_cancel_submit_return(seqnum, endpoint, direction, StatusCode.CANCELED)


class _Channel:
    """One unencrypted data channel as a capture holds it, one message per packet in the order they
    were sent: from the USB Stream Information and USB Stream Status on, or, *from_its_start*
    False, from a later message on, as a capture started on an open connection holds it."""

    def __init__(self, from_its_start: bool = True):
        self.sender_msgs: list[ChannelMessage] = []
        self.receiver_msgs: list[ChannelMessage] = []
        self._pkt = 0
        if from_its_start:
            self.from_sender(usb.build_usb_stream_info(4, 2, '1-1.2'))
            self.from_receiver(usb.build_usb_stream_status(0))

    def _captured(self, raw: bytes, src: tuple, dst: tuple) -> ChannelMessage:
        self._pkt += 1
        return ChannelMessage(packet_number=self._pkt, timestamp=float(self._pkt),
                              src_ip=src[0], src_port=src[1], dst_ip=dst[0], dst_port=dst[1],
                              msg=usb.parse_one(raw))

    def from_sender(self, raw: bytes) -> int:
        self.sender_msgs.append(self._captured(raw, _SENDER, _RECEIVER))
        return self._pkt

    def from_receiver(self, raw: bytes) -> int:
        self.receiver_msgs.append(self._captured(raw, _RECEIVER, _SENDER))
        return self._pkt

    def validate(self) -> Session:
        s = Session(sender_ip=_SENDER[0], sender_port=_SENDER[1], receiver_ip=_RECEIVER[0])
        _validate_data_channel(s, DataChannel(substreamid=4, busid='1-1.2', usbspeed=2),
                               self.sender_msgs, self.receiver_msgs, encrypted=False)
        return s


def _findings(session: Session, *requirements: Requirement) -> list:
    return [f for f in session.findings if f.requirement in requirements]


class CancelSubmit(unittest.TestCase):
    """§9.22, Table 17: the Cancel Submit names, by its SEQNUM, the Submit it cancels."""

    def setUp(self):
        # Control Submit 0, answered; then Interrupt IN Submits 1 (ENDPOINT 2) and 2 (ENDPOINT 1),
        # both waiting for the device.
        self.ch = _Channel()
        self.ch.from_receiver(_control_in(0))
        self.ch.from_sender(_control_in_return(0))
        self.ch.from_receiver(_interrupt_in(1, 2))
        self.ch.from_receiver(_interrupt_in(2, 1))

    def _cancel_findings(self, session: Session) -> list:
        return _findings(session, Requirement.CANCEL_SEQNUM, Requirement.CANCEL_ENDPOINT,
                         Requirement.CANCEL_DIRECTION, Requirement.CANCEL_DATA_FIELDS)

    def test_a_cancel_naming_a_waiting_submit_passes(self):
        self.ch.from_receiver(_cancel(2, 1, 1))
        self.ch.from_sender(_cancel_return(2, 1, 1))
        self.assertEqual(self._cancel_findings(self.ch.validate()), [])

    def test_a_cancel_of_a_submit_already_answered_passes(self):
        # Its Submit Return can cross the Cancel Submit on the wire.
        self.ch.from_sender(_interrupt_in_return(1, 2))
        self.ch.from_receiver(_cancel(1, 2, 1))
        self.assertEqual(self._cancel_findings(self.ch.validate()), [])

    def test_a_seqnum_no_submit_carries_fails(self):
        pkt = self.ch.from_receiver(_cancel(3, 2, 1))
        s = self.ch.validate()
        [f] = _findings(s, Requirement.CANCEL_SEQNUM)
        self.assertEqual((f.severity, f.section, f.packet_number), (Severity.ERROR, '9.22', pkt))
        self.assertIn('SEQNUM=3', f.description)
        # The Submits then waiting for their Return, which it may have meant; not the one answered.
        self.assertIn('SEQNUM 1 (USB_INTERRUPT_SUBMIT, ENDPOINT=2, D=1', f.description)
        self.assertIn('SEQNUM 2 (USB_INTERRUPT_SUBMIT, ENDPOINT=1, D=1', f.description)
        self.assertNotIn('SEQNUM 0 ', f.description)
        # No Submit identified: ENDPOINT and D have nothing to match.
        self.assertEqual(_findings(s, Requirement.CANCEL_ENDPOINT, Requirement.CANCEL_DIRECTION), [])

    def test_a_seqnum_only_a_later_submit_carries_fails(self):
        pkt = self.ch.from_receiver(_cancel(3, 0, 1))
        self.ch.from_receiver(_control_in(3))
        s = self.ch.validate()
        self.assertEqual([f.packet_number for f in _findings(s, Requirement.CANCEL_SEQNUM)], [pkt])

    def test_a_capture_started_after_the_submits_judges_no_seqnum(self):
        # The Submit it cancels may have been sent before the capture began.
        ch = _Channel(from_its_start=False)
        ch.from_sender(_control_in_return(7))
        ch.from_receiver(_cancel(8, 1, 1))
        self.assertEqual(_findings(ch.validate(), Requirement.CANCEL_SEQNUM), [])

    def test_a_cancel_on_a_channel_with_no_submit_fails(self):
        # Every message the Receiver sent on the channel is in the capture, and none is a Submit.
        ch = _Channel()
        pkt = ch.from_receiver(_cancel(0, 0, 0))
        [f] = _findings(ch.validate(), Requirement.CANCEL_SEQNUM)
        self.assertEqual(f.packet_number, pkt)
        self.assertIn('no Submit was waiting for its Return', f.description)

    def test_no_submit_waiting_is_said(self):
        self.ch.from_sender(_interrupt_in_return(1, 2))
        self.ch.from_sender(_interrupt_in_return(2, 1))
        self.ch.from_receiver(_cancel(3, 1, 1))
        [f] = _findings(self.ch.validate(), Requirement.CANCEL_SEQNUM)
        self.assertIn('no Submit was waiting for its Return', f.description)

    def test_an_endpoint_other_than_the_submits_fails(self):
        pkt = self.ch.from_receiver(_cancel(2, 2, 1))
        s = self.ch.validate()
        [f] = _findings(s, Requirement.CANCEL_ENDPOINT)
        self.assertEqual((f.severity, f.section, f.packet_number), (Severity.ERROR, '9.22', pkt))
        self.assertIn('ENDPOINT=2', f.description)
        self.assertIn('ENDPOINT=1', f.description)
        self.assertEqual(_findings(s, Requirement.CANCEL_SEQNUM, Requirement.CANCEL_DIRECTION), [])

    def test_a_direction_other_than_the_submits_fails(self):
        pkt = self.ch.from_receiver(_cancel(2, 1, 0))
        s = self.ch.validate()
        [f] = _findings(s, Requirement.CANCEL_DIRECTION)
        self.assertEqual((f.severity, f.section, f.packet_number), (Severity.ERROR, '9.22', pkt))
        self.assertIn('D=0', f.description)
        self.assertIn('D=1', f.description)
        self.assertEqual(_findings(s, Requirement.CANCEL_SEQNUM, Requirement.CANCEL_ENDPOINT), [])

    def test_data_past_table_17_fails_once_for_the_channel(self):
        first = self.ch.from_receiver(_cancel(2, 1, 1, past_table_17=b'\x02\x00\x00\x00'))
        self.ch.from_receiver(_cancel(1, 2, 1, past_table_17=b'\x01\x00\x00\x00'))
        s = self.ch.validate()
        [f] = _findings(s, Requirement.CANCEL_DATA_FIELDS)
        self.assertEqual((f.severity, f.section, f.packet_number), (Severity.ERROR, '9.22', first))
        self.assertIn('DATA is 8 bytes', f.description)
        self.assertIn('in 2 of 2', f.description)
        self.assertIn('02 00 00 00', f.description)
        # The fields Table 17 defines are still read and checked.
        self.assertEqual(_findings(s, Requirement.CANCEL_SEQNUM, Requirement.CANCEL_ENDPOINT,
                                   Requirement.CANCEL_DIRECTION), [])

    def test_data_short_of_table_17_fails(self):
        pkt = self.ch.from_receiver(usb.build_message(MsgType.USB_CANCEL_SUBMIT, b'\x00\x00\x02'))
        s = self.ch.validate()
        [f] = _findings(s, Requirement.CANCEL_DATA_FIELDS)
        self.assertEqual(f.packet_number, pkt)
        self.assertIn('DATA is 3 bytes', f.description)
        self.assertEqual(_findings(s, Requirement.CANCEL_SEQNUM), [])

    def test_a_cancel_takes_no_seqnum_from_the_submits(self):
        self.ch.from_receiver(_cancel(2, 1, 1))
        self.ch.from_receiver(_interrupt_in(3, 1))
        self.assertEqual(_findings(self.ch.validate(), Requirement.SUBMIT_SEQNUM), [])

    def test_cancels_numbered_as_new_submits(self):
        """A Receiver that numbers each Cancel Submit as a new Submit, with ENDPOINT 0 and D 0, and
        names the Submit to cancel in 4 bytes past Table 17: no Cancel identifies a Submit, their
        DATA is 8 bytes, and the next Submit skips the numbers the Cancels took."""
        c1 = self.ch.from_receiver(_cancel(3, 0, 0, past_table_17=(2).to_bytes(4, 'little')))
        self.ch.from_sender(_cancel_return(3, 0, 0))
        c2 = self.ch.from_receiver(_cancel(4, 0, 0, past_table_17=(1).to_bytes(4, 'little')))
        self.ch.from_sender(_cancel_return(4, 0, 0))
        nxt = self.ch.from_receiver(_interrupt_in(5, 2))
        s = self.ch.validate()
        self.assertEqual([f.packet_number for f in _findings(s, Requirement.CANCEL_SEQNUM)], [c1, c2])
        self.assertEqual([f.packet_number for f in _findings(s, Requirement.CANCEL_DATA_FIELDS)], [c1])
        [seq] = _findings(s, Requirement.SUBMIT_SEQNUM)
        self.assertEqual((seq.section, seq.packet_number), ('9.16', nxt))
        self.assertIn('expected 3', seq.description)


class CancelSubmitReturn(unittest.TestCase):
    """§9.23, Table 18: a Cancel Submit Return has no ACTUALLENGTH, so the ACTUALLENGTH rules of
    Table 14 have nothing to check in it."""

    _BULK_OUT = staticmethod(lambda seqnum: usb.build_usb_bulk_submit(seqnum, 2, 0, 0, 4, b'\x01\x02\x03\x04'))

    def test_an_out_cancel_return_gets_no_actuallength_finding(self):
        ch = _Channel()
        ch.from_receiver(self._BULK_OUT(0))
        ch.from_receiver(_cancel(0, 2, 0))
        ch.from_sender(_cancel_return(0, 2, 0))
        self.assertEqual(_findings(ch.validate(), Requirement.RETURN_OUT_LENGTH,
                                   Requirement.RETURN_IN_LENGTH), [])

    def test_an_in_cancel_return_gets_no_actuallength_finding(self):
        ch = _Channel()
        ch.from_receiver(_interrupt_in(0, 1))
        ch.from_receiver(_cancel(0, 1, 1))
        ch.from_sender(_cancel_return(0, 1, 1))
        self.assertEqual(_findings(ch.validate(), Requirement.RETURN_OUT_LENGTH,
                                   Requirement.RETURN_IN_LENGTH), [])

    def test_an_out_submit_return_still_needs_actuallength_0(self):
        ch = _Channel()
        ch.from_receiver(self._BULK_OUT(0))
        pkt = ch.from_sender(usb.build_usb_bulk_submit_return(0, 2, 0, 4, StatusCode.SUCCESS))
        [f] = _findings(ch.validate(), Requirement.RETURN_OUT_LENGTH)
        self.assertEqual((f.severity, f.packet_number), (Severity.ERROR, pkt))


def _with_rsvd(raw: bytes, rsvd: int = 0b101) -> bytes:
    """*raw*, unencrypted, with the 3 Rsvd bits of its endpoint byte (DATA offset 3) set to *rsvd*."""
    msg = bytearray(raw)
    msg[usb.HEADER_SIZE + 3] |= (rsvd & 0x07) << 1
    return bytes(msg)


class FieldCitations(unittest.TestCase):
    """A finding on the fields of a Submit or a Return cites the message's own section and the
    table of DATA fields that section refers to (§9.14-9.23)."""

    SUBMITS = (
        ('9.14', 'Table 10', _control_in(0)),
        ('9.15', 'Table 11', usb.build_usb_bulk_submit(0, 2, 1, 0, 64)),
        ('9.16', 'Table 11', _interrupt_in(0, 1)),
        ('9.17', 'Table 12', usb.build_usb_isochronous_submit(0, 3, 1, 1, 1, 0, 1, [192])),
        ('9.22', 'Table 17', _cancel(0, 1, 1)),
    )
    RETURNS = (
        ('9.18', 'Table 14', _control_in_return(0)),
        ('9.19', 'Table 14', usb.build_usb_bulk_submit_return(0, 2, 1, 0, StatusCode.SUCCESS)),
        ('9.20', 'Table 14', usb.build_usb_interrupt_submit_return(0, 1, 1, 0, StatusCode.SUCCESS)),
        ('9.21', 'Table 15', usb.build_usb_isochronous_submit_return(0, 3, 1, 0, 0, 1, [(0, 0)])),
        ('9.23', 'Table 18', _cancel_return(0, 1, 1)),
    )

    def _assert_cites(self, finding, section: str, table: str, pkt: int) -> None:
        self.assertEqual((finding.severity, finding.section, finding.packet_number),
                         (Severity.ERROR, section, pkt))
        self.assertIn(table, finding.description)

    def test_reserved_bits_of_a_submit(self):
        for section, table, raw in self.SUBMITS:
            with self.subTest(section=section):
                ch = _Channel()
                pkt = ch.from_receiver(_with_rsvd(raw))
                [f] = _findings(ch.validate(), Requirement.SUBMIT_RSVD)
                self._assert_cites(f, section, table, pkt)

    def test_reserved_bits_of_a_return(self):
        for section, table, raw in self.RETURNS:
            with self.subTest(section=section):
                ch = _Channel()
                pkt = ch.from_sender(_with_rsvd(raw))
                [f] = _findings(ch.validate(), Requirement.RETURN_RSVD)
                self._assert_cites(f, section, table, pkt)

    def test_a_return_answering_no_submit(self):
        for section, table, raw in self.RETURNS[:4]:     # not checked on a Cancel Submit Return
            with self.subTest(section=section):
                ch = _Channel()
                pkt = ch.from_sender(raw)
                [f] = _findings(ch.validate(), Requirement.RETURN_SEQNUM)
                self._assert_cites(f, section, table, pkt)

    def test_endpoint_and_direction_of_a_return(self):
        # Each Return answers a Submit to ENDPOINT 1 with D 1, and carries ENDPOINT 2 and D 0.
        cases = (
            ('9.19', 'Table 14', [usb.build_usb_bulk_submit(0, 1, 1, 0, 64)],
             usb.build_usb_bulk_submit_return(0, 2, 0, 0, StatusCode.SUCCESS)),
            ('9.21', 'Table 15', [usb.build_usb_isochronous_submit(0, 1, 1, 1, 1, 0, 1, [192])],
             usb.build_usb_isochronous_submit_return(0, 2, 0, 0, 0, 1, [(0, 0)])),
            ('9.23', 'Table 18', [_interrupt_in(0, 1), _cancel(0, 1, 1)], _cancel_return(0, 2, 0)),
        )
        for section, table, submits, answer in cases:
            with self.subTest(section=section):
                ch = _Channel()
                for submit in submits:
                    ch.from_receiver(submit)
                pkt = ch.from_sender(answer)
                s = ch.validate()
                for requirement in (Requirement.RETURN_ENDPOINT, Requirement.RETURN_DIRECTION):
                    [f] = _findings(s, requirement)
                    self._assert_cites(f, section, table, pkt)

    def test_actuallength_of_a_return(self):
        out = _Channel()
        out.from_receiver(usb.build_usb_interrupt_submit(0, 2, 0, 8, 4, b'\x01\x02\x03\x04'))
        pkt = out.from_sender(usb.build_usb_interrupt_submit_return(0, 2, 0, 4, StatusCode.SUCCESS))
        [f] = _findings(out.validate(), Requirement.RETURN_OUT_LENGTH)
        self._assert_cites(f, '9.20', 'Table 14', pkt)

        into = _Channel()
        into.from_receiver(usb.build_usb_bulk_submit(0, 1, 1, 0, 8))
        pkt = into.from_sender(usb.build_usb_bulk_submit_return(0, 1, 1, 16, StatusCode.SUCCESS, b'\x00' * 16))
        [f] = _findings(into.validate(), Requirement.RETURN_IN_LENGTH)
        self._assert_cites(f, '9.19', 'Table 14', pkt)

    def test_usbdevreq_of_a_control_submit(self):
        data = usb.parse_one(_control_in(0)).data[:17]      # USBDEVREQ cut to 5 bytes
        ch = _Channel()
        pkt = ch.from_receiver(usb.build_message(MsgType.USB_CONTROL_SUBMIT, data))
        [f] = _findings(ch.validate(), Requirement.CONTROL_USBDEVREQ_LENGTH)
        self._assert_cites(f, '9.14', 'Table 10', pkt)

    def test_the_checklist_rows(self):
        rows = (Requirement.CONTROL_USBDEVREQ_LENGTH, Requirement.SUBMIT_RSVD,
                Requirement.RETURN_SEQNUM, Requirement.RETURN_ENDPOINT, Requirement.RETURN_DIRECTION,
                Requirement.RETURN_OUT_LENGTH, Requirement.RETURN_IN_LENGTH, Requirement.RETURN_RSVD)
        self.assertEqual({r.name: r.section for r in rows},
                         {'CONTROL_USBDEVREQ_LENGTH': '9.14', 'SUBMIT_RSVD': '9.14-17/22',
                          'RETURN_SEQNUM': '9.18-21', 'RETURN_ENDPOINT': '9.18-21/23',
                          'RETURN_DIRECTION': '9.18-21/23', 'RETURN_OUT_LENGTH': '9.18-20',
                          'RETURN_IN_LENGTH': '9.18-20', 'RETURN_RSVD': '9.18-21/23'})


class SubmitSeqnumCitation(unittest.TestCase):
    """A SEQNUM finding cites the section of its Submit's type and the table holding the rule."""

    CASES = (
        ('9.14', 'Table 10', _control_in),
        ('9.15', 'Table 11', lambda seqnum: usb.build_usb_bulk_submit(seqnum, 2, 1, 0, 64)),
        ('9.16', 'Table 11', lambda seqnum: _interrupt_in(seqnum, 1)),
        ('9.17', 'Table 12', lambda seqnum: usb.build_usb_isochronous_submit(seqnum, 3, 1, 1, 1, 0, 1, [192])),
    )

    def test_a_submit_skipping_a_seqnum(self):
        for section, table, submit in self.CASES:
            with self.subTest(section=section):
                ch = _Channel()
                ch.from_receiver(submit(0))
                pkt = ch.from_receiver(submit(2))
                [f] = _findings(ch.validate(), Requirement.SUBMIT_SEQNUM)
                self.assertEqual((f.severity, f.section, f.packet_number), (Severity.ERROR, section, pkt))
                self.assertIn(table, f.description)
                self.assertIn('expected 1', f.description)

    def test_a_first_submit_other_than_0(self):
        for section, table, submit in self.CASES:
            with self.subTest(section=section):
                ch = _Channel()
                pkt = ch.from_receiver(submit(5))
                [f] = _findings(ch.validate(), Requirement.SUBMIT_SEQNUM)
                self.assertEqual((f.section, f.packet_number), (section, pkt))
                self.assertIn(table, f.description)

    def test_the_checklist_row_spans_the_four_submit_sections(self):
        self.assertEqual(Requirement.SUBMIT_SEQNUM.section, '9.14-17')


if __name__ == '__main__':
    unittest.main()
