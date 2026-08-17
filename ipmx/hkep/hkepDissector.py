#!/usr/bin/env python3
"""
HKEP (HDCP Key Exchange Protocol) Dissector/Analyzer for PCAP files

Copyright (c) 2024, Matrox Graphics Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Credits: Parsing of HDCP messages has initially been derived from the HKEP
         Wireshark Lua dissector written by Ryosuke Yamamoto.
"""

import struct
import sys
from typing import Dict, List, Tuple, Optional

try:
    from scapy.all import rdpcap, TCP, IP, Raw
    from scapy.packet import Packet
    from scapy.utils import PcapReader
except ImportError:
    print("Error: scapy is required. Install with: pip install scapy")
    sys.exit(1)


# ---------------------------------------------------------------------------
# TCP sequence number arithmetic (RFC 1982 serial-number comparison)
#
# TCP sequence numbers are 32-bit and wrap around to 0 after 2^32-1. Comparing
# them with plain < / > breaks across that boundary: a segment at seq 20 that
# follows one at seq 0xFFFFFFF0 looks like it comes *before* it, so the
# reassembler either mistakes fresh data for an old retransmission or declares
# a bogus gap. These helpers mirror ipmx/usb/ipmx-usb-tools/tcp_reassembler.py
# so both dissectors reassemble streams identically.
# ---------------------------------------------------------------------------

def _seq_lt(a: int, b: int) -> bool:
    """Return True if TCP sequence number *a* is strictly before *b* (mod 2^32)."""
    return ((b - a) & 0xFFFFFFFF) < 0x80000000


def _seq_add(seq: int, n: int) -> int:
    """Advance *seq* by *n* bytes, wrapping at 2^32."""
    return (seq + n) & 0xFFFFFFFF


def _seq_diff(later: int, earlier: int) -> int:
    """Signed distance from *earlier* to *later* (positive means later > earlier)."""
    d = (later - earlier) & 0xFFFFFFFF
    if d >= 0x80000000:
        return d - 0x100000000
    return d


class HKEPExchange:
    """Represents a single HKEP protocol exchange (HKEP session identified by receiverId, nodeId, portId)"""

    def __init__(self, session_key: str, receiver_id: str, node_id: str, port_id: str):
        """
        Initialize HKEP exchange with session tuple
        
        Args:
            session_key: Unique key for this session: "(receiverId, nodeId, portId)"
            receiver_id: Receiver ID from AKE_PreInit
            node_id: Node ID from AKE_PreInit
            port_id: Port ID from AKE_PreInit
        """
        self.session_key = session_key
        self.receiver_id = receiver_id
        self.node_id = node_id
        self.port_id = port_id
        self.tcp_connections = []  # List of (stream_key, src_ip, src_port, dst_ip, dst_port) tuples
        self.messages = []
        self.start_time = None
        self.end_time = None
        self.connection_state = 'unknown'
        self.disconnection_reason = None
        self.is_complete = None  # True if exchange is complete enough to validate, False if incomplete/invalid
        self.incomplete_reason = None  # Why exchange is incomplete
    
    def add_tcp_connection(self, stream_key: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int):
        """Add a TCP connection to this HKEP session"""
        conn_info = (stream_key, src_ip, src_port, dst_ip, dst_port)
        if conn_info not in self.tcp_connections:
            self.tcp_connections.append(conn_info)
    
    @property
    def stream_key(self):
        """Backward compatibility: return first TCP connection's stream_key"""
        if self.tcp_connections:
            return self.tcp_connections[0][0]
        return self.session_key

    def add_message(self, message: Dict):
        """Add a message to this exchange"""
        self.messages.append(message)

        # Update timing
        msg_time = message.get('timestamp', 0)
        if self.start_time is None or msg_time < self.start_time:
            self.start_time = msg_time
        if self.end_time is None or msg_time > self.end_time:
            self.end_time = msg_time

    def get_messages(self) -> List[Dict]:
        """Get all messages in chronological order"""
        return sorted(self.messages, key=lambda x: x.get('timestamp', 0))

    def get_messages_by_type(self, msg_type: str) -> List[Dict]:
        """Get all messages of a specific type"""
        return [msg for msg in self.messages if msg.get('hkep', {}).get('message_type') == msg_type]

    def get_message_count(self) -> int:
        """Get total number of messages"""
        return len(self.messages)

    def get_duration(self) -> float:
        """Get duration of the exchange in seconds"""
        if self.start_time is None or self.end_time is None:
            return 0.0
        return self.end_time - self.start_time

    def get_encoder_messages(self) -> List[Dict]:
        """Get messages sent from encoder to decoder"""
        return [msg for msg in self.messages if msg.get('hkep', {}).get('direction') == 'Encoder->Decoder']

    def get_decoder_messages(self) -> List[Dict]:
        """Get messages sent from decoder to encoder"""
        return [msg for msg in self.messages if msg.get('hkep', {}).get('direction') == 'Decoder->Encoder']

    def is_successful(self) -> bool:
        """Check if the exchange completed successfully"""
        return self.disconnection_reason is None or self.disconnection_reason == 'FIN'
    
    def validate_completeness(self) -> tuple[bool, str]:
        """
        Check if exchange has the proper initial sequence to be considered valid.
        Returns: (is_complete, reason_if_incomplete)
        
        A valid HKEP exchange MUST start with:
        1. TCP connection established (implicit - we have messages)
        2. Client (Decoder) sends AKE_PreInit → Server (Encoder)
        3. Server (Encoder) responds AKE_PreInitStatus → Client (Decoder)
        
        Without this initial handshake sequence, the exchange is incomplete/invalid.
        """
        if not self.messages:
            return False, "No messages in exchange"
        
        # Sort messages by timestamp to check sequence
        sorted_messages = sorted(self.messages, key=lambda x: x.get('timestamp', 0))
        
        # Find AKE_PreInit (must be from Decoder->Encoder, i.e., client to server)
        preinit_msg = None
        preinit_index = None
        for idx, msg in enumerate(sorted_messages):
            if msg.get('hkep', {}).get('message_type') == 'AKE_PreInit':
                preinit_msg = msg
                preinit_index = idx
                break
        
        if not preinit_msg:
            return False, "Missing AKE_PreInit message (initial client request not captured)"
        
        # Verify AKE_PreInit direction is correct (Decoder->Encoder = client->server)
        preinit_direction = preinit_msg.get('hkep', {}).get('direction', '')
        if preinit_direction != 'Decoder->Encoder':
            return False, f"AKE_PreInit has wrong direction '{preinit_direction}' (should be Decoder->Encoder)"
        
        # Find AKE_PreInitStatus (must be from Encoder->Decoder, i.e., server to client)
        # It should come AFTER AKE_PreInit
        preinitstatus_msg = None
        for idx, msg in enumerate(sorted_messages[preinit_index + 1:], start=preinit_index + 1):
            if msg.get('hkep', {}).get('message_type') == 'AKE_PreInitStatus':
                preinitstatus_msg = msg
                break
        
        if not preinitstatus_msg:
            return False, "Missing AKE_PreInitStatus response (server response not captured)"
        
        # Verify AKE_PreInitStatus direction is correct (Encoder->Decoder = server->client)
        preinitstatus_direction = preinitstatus_msg.get('hkep', {}).get('direction', '')
        if preinitstatus_direction != 'Encoder->Decoder':
            return False, f"AKE_PreInitStatus has wrong direction '{preinitstatus_direction}' (should be Encoder->Decoder)"
        
        # Verify the sequence: PreInit must come before PreInitStatus
        preinit_time = preinit_msg.get('timestamp', 0)
        preinitstatus_time = preinitstatus_msg.get('timestamp', 0)
        if preinitstatus_time <= preinit_time:
            return False, "AKE_PreInitStatus appears before AKE_PreInit (incorrect sequence)"
        
        # Initial handshake sequence is present and correct
        return True, ""

    def __str__(self):
        tcp_info = f", {len(self.tcp_connections)} TCP connection(s)" if len(self.tcp_connections) > 1 else ""
        return f"HKEPExchange(session={self.session_key}{tcp_info}, {self.get_message_count()} messages, {self.get_duration():.3f}s)"


class HKEPAnalysisResult:
    """Container for HKEP analysis results"""

    def __init__(self):
        self.exchanges = []
        self.total_packets = 0
        self.total_messages = 0

    def add_exchange(self, exchange: HKEPExchange):
        """Add an exchange to the results"""
        self.exchanges.append(exchange)
        self.total_messages += exchange.get_message_count()

    def get_all_exchanges(self) -> List[HKEPExchange]:
        """Get all exchanges"""
        return self.exchanges

    def get_successful_exchanges(self) -> List[HKEPExchange]:
        """Get exchanges that completed successfully"""
        return [ex for ex in self.exchanges if ex.is_successful()]

    def get_failed_exchanges(self) -> List[HKEPExchange]:
        """Get exchanges that failed or were aborted"""
        return [ex for ex in self.exchanges if not ex.is_successful()]

    def get_exchange_by_stream_key(self, stream_key: str) -> Optional[HKEPExchange]:
        """Get exchange by stream key (searches all TCP connections)"""
        for ex in self.exchanges:
            for conn_stream_key, _, _, _, _ in ex.tcp_connections:
                if conn_stream_key == stream_key:
                    return ex
        return None
    
    def get_exchange_by_session_key(self, session_key: str) -> Optional[HKEPExchange]:
        """Get exchange by session key (receiverId, nodeId, portId)"""
        for ex in self.exchanges:
            if ex.session_key == session_key:
                return ex
        return None

    def get_exchange_count(self) -> int:
        """Get total number of exchanges"""
        return len(self.exchanges)

    def __str__(self):
        return f"HKEPAnalysisResult({self.get_exchange_count()} exchanges, {self.total_messages} messages)"


class HKEPDissector:
    """HKEP Protocol Dissector"""
    
    # HKEP Message Types
    MSG_TYPES = {
        1: "Null message",
        2: "AKE_Init",
        3: "AKE_Send_Cert",
        4: "AKE_No_Stored_km",
        5: "AKE_Stored_km",
        6: "AKE_Send_rrx",
        7: "AKE_Send_H_prime",
        8: "AKE_Send_Pairing_Info",
        9: "LC_Init",
        10: "LC_Send_L_prime",
        11: "SKE_Send_Eks",
        12: "RepeaterAuth_Send_ReceiverID_List",
        13: "RTT_Ready",
        14: "RTT_Challenge",
        15: "RepeaterAuth_Send_Ack",
        16: "RepeaterAuth_Stream_Manage",
        17: "RepeaterAuth_Stream_Ready",
        18: "Receiver_AuthStatus",
        19: "AKE_Transmitter_Info",
        20: "AKE_Receiver_Info",
        32: "AKE_PreInit",
        33: "AKE_PreInitStatus"
    }
    
    def __init__(self, target_port: Optional[int] = None):
        """
        Initialize the HKEP dissector
        
        Args:
            target_port: TCP port to filter for HKEP traffic (None = auto-detect)
        """
        self.target_port = target_port
        self.tcp_streams = {}  # Track TCP streams for reassembly
        self.seen_packets = set()  # Track packet hashes to detect retransmissions
        # Framing diagnostics: bytes the framer could not attribute to a message,
        # and how many times it had to resynchronise. Reported instead of being
        # dropped silently, so a partially-framed capture is visible.
        self._framing_skipped_bytes = 0
        self._framing_resyncs = 0
        
    def bytes_to_hex(self, data: bytes) -> str:
        """Convert bytes to hex string representation"""
        return data.hex()
    
    def dissect_null_message(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 1: Null message"""
        return {
            "message_type": "Null message",
            "msg_size": msg_size,
            "msg_id": 1
        }
    
    def dissect_ake_init(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 2: AKE_Init (Encoder->Decoder)"""
        r_tx = data[3:11]
        return {
            "message_type": "AKE_Init",
            "direction": "Encoder->Decoder",
            "msg_size": msg_size,
            "msg_id": 2,
            "r_tx[63:0]": self.bytes_to_hex(r_tx)
        }
    
    def dissect_ake_send_cert(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 3: AKE_Send_Cert (Decoder->Encoder)"""
        # AKE_Send_Cert should be 526 bytes total (2 header + 524 data)
        # But msg_size includes msg_id, so msg_size should be 524
        # Total = 2 + 524 = 526
        
        if len(data) < 4:
            raise ValueError(f"AKE_Send_Cert requires at least 4 bytes, got {len(data)}")
        
        repeater = data[3] == 1 if len(data) > 3 else False
        
        # Extract fields with bounds checking
        cert_rx = data[4:min(526, len(data))] if len(data) > 4 else b''
        receiver_id = data[4:9] if len(data) >= 9 else data[4:] if len(data) > 4 else b''
        receiver_pubkey = data[9:140] if len(data) >= 140 else data[9:] if len(data) > 9 else b''
        
        # Parse protocol descriptor
        if len(data) >= 142:
            protocol_descriptor_bytes = data[140:142]
            protocol_descriptor = struct.unpack('>H', protocol_descriptor_bytes)[0]
            sertrx_reserved = protocol_descriptor % 4096
            protocol_descriptor = (protocol_descriptor - sertrx_reserved) // 4096
        else:
            protocol_descriptor = 0
            sertrx_reserved = 0
        
        dcp_signature = data[142:526] if len(data) >= 526 else data[142:] if len(data) > 142 else b''
        
        return {
            "message_type": "AKE_Send_Cert",
            "direction": "Decoder->Encoder",
            "msg_size": msg_size,
            "msg_id": 3,
            "REPEATER": repeater,
            "cert_rx[4175:0]": self.bytes_to_hex(cert_rx),
            "Receiver_ID": self.bytes_to_hex(receiver_id),
            "Receiver_Public_Key": self.bytes_to_hex(receiver_pubkey),
            "Protocol_Descriptor": protocol_descriptor,
            "Reserved": sertrx_reserved,
            "DCP_LLC_Signature": self.bytes_to_hex(dcp_signature)
        }
    
    def dissect_ake_no_stored_km(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 4: AKE_No_Stored_km (Encoder->Decoder)"""
        ekpub_km = data[3:131]
        return {
            "message_type": "AKE_No_Stored_km",
            "direction": "Encoder->Decoder",
            "msg_size": msg_size,
            "msg_id": 4,
            "Ekpub_km[1023:0]": self.bytes_to_hex(ekpub_km)
        }
    
    def dissect_ake_stored_km(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 5: AKE_Stored_km (Encoder->Decoder)"""
        ekh_km = data[3:19]
        m = data[19:35]
        return {
            "message_type": "AKE_Stored_km",
            "direction": "Encoder->Decoder",
            "msg_size": msg_size,
            "msg_id": 5,
            "Ekh_km[127:0]": self.bytes_to_hex(ekh_km),
            "m[127:0]": self.bytes_to_hex(m)
        }
    
    def dissect_ake_send_rrx(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 6: AKE_Send_rrx (Decoder->Encoder)"""
        r_rx = data[3:11]
        return {
            "message_type": "AKE_Send_rrx",
            "direction": "Decoder->Encoder",
            "msg_size": msg_size,
            "msg_id": 6,
            "r_rx[63:0]": self.bytes_to_hex(r_rx)
        }
    
    def dissect_ake_send_h_prime(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 7: AKE_Send_H_prime (Decoder->Encoder)"""
        h_prime = data[3:35]
        return {
            "message_type": "AKE_Send_H_prime",
            "direction": "Decoder->Encoder",
            "msg_size": msg_size,
            "msg_id": 7,
            "H'[255:0]": self.bytes_to_hex(h_prime)
        }
    
    def dissect_ake_send_pairing_info(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 8: AKE_Send_Pairing_Info (Decoder->Encoder)"""
        ekh_km = data[3:19]
        return {
            "message_type": "AKE_Send_Pairing_Info",
            "direction": "Decoder->Encoder",
            "msg_size": msg_size,
            "msg_id": 8,
            "Ekh_km[127:0]": self.bytes_to_hex(ekh_km)
        }
    
    def dissect_lc_init(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 9: LC_Init (Encoder->Decoder)"""
        r_n = data[3:11]
        return {
            "message_type": "LC_Init",
            "direction": "Encoder->Decoder",
            "msg_size": msg_size,
            "msg_id": 9,
            "r_n[63:0]": self.bytes_to_hex(r_n)
        }
    
    def dissect_lc_send_l_prime(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 10: LC_Send_L_prime (Decoder->Encoder)"""
        result = {
            "message_type": "LC_Send_L_prime",
            "direction": "Decoder->Encoder",
            "msg_size": msg_size,
            "msg_id": 10
        }
        
        if msg_size == 35:
            result["L'[255:0]"] = self.bytes_to_hex(data[3:35])
        else:
            result["L'[255:128]"] = self.bytes_to_hex(data[3:19])
            
        return result
    
    def dissect_ske_send_eks(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 11: SKE_Send_Eks (Encoder->Decoder)"""
        edkey_ks = data[3:19]
        r_iv = data[19:27]
        
        result = {
            "message_type": "SKE_Send_Eks",
            "direction": "Encoder->Decoder",
            "msg_size": msg_size,
            "msg_id": 11,
            "Edkey_Ks[127:0]": self.bytes_to_hex(edkey_ks),
            "r_iv[63:0]": self.bytes_to_hex(r_iv)
        }
        
        if msg_size == 59:
            result["HMAC(r_iv)[255:0]"] = self.bytes_to_hex(data[27:59])
            result["note"] = "The receiver complies with HDCP2.3 or higher."
        else:
            result["note"] = "The receiver is not compliant with HDCP2.3 or above."
            
        return result
    
    def dissect_repeaterauth_send_receiverid_list(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 12: RepeaterAuth_Send_ReceiverID_List (Decoder->Encoder)"""
        max_devs_exceeded = data[3] == 1
        max_cascade_exceeded = data[4] == 1
        repeaterauth_type = (msg_size - 39) % 5
        
        result = {
            "message_type": "RepeaterAuth_Send_ReceiverID_List",
            "direction": "Decoder->Encoder",
            "msg_size": msg_size,
            "msg_id": 12,
            "HDCP_2.0_compliant": repeaterauth_type == 0,
            "MAX_DEVS_EXCEEDED": max_devs_exceeded,
            "MAX_CASCADE_EXCEEDED": max_cascade_exceeded
        }
        
        if not max_devs_exceeded and not max_cascade_exceeded:
            device_count = data[5]
            depth = data[6]
            result["DEVICE_COUNT"] = device_count
            result["DEPTH"] = depth
            
            if repeaterauth_type == 0:
                result["V'[255:0]"] = self.bytes_to_hex(data[7:39])
                j_max = (msg_size - 39) // 5
                receiver_ids = []
                for j in range(j_max):
                    offset = 39 + (j * 5)
                    receiver_ids.append(self.bytes_to_hex(data[offset:offset+5]))
                result["Receiver_IDs"] = receiver_ids
            else:
                result["HDCP2_LEGACY_DEVICE_DOWNSTREAM"] = data[7] == 1
                result["HDCP1_DEVICE_DOWNSTREAM"] = data[8] == 1
                result["seq_num_V"] = struct.unpack('>I', b'\x00' + data[9:12])[0]
                result["V'[255:128]"] = self.bytes_to_hex(data[12:28])
                j_max = (msg_size - 28) // 5
                receiver_ids = []
                for j in range(j_max):
                    offset = 28 + (j * 5)
                    receiver_ids.append(self.bytes_to_hex(data[offset:offset+5]))
                result["Receiver_IDs"] = receiver_ids
                
        return result
    
    def dissect_rtt_ready(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 13: RTT_Ready (Decoder->Encoder)"""
        return {
            "message_type": "RTT_Ready",
            "direction": "Decoder->Encoder",
            "msg_size": msg_size,
            "msg_id": 13
        }
    
    def dissect_rtt_challenge(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 14: RTT_Challenge (Encoder->Decoder)"""
        l_value = data[3:19]
        return {
            "message_type": "RTT_Challenge",
            "direction": "Encoder->Decoder",
            "msg_size": msg_size,
            "msg_id": 14,
            "L[127:0]": self.bytes_to_hex(l_value)
        }
    
    def dissect_repeaterauth_send_ack(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 15: RepeaterAuth_Send_Ack (Encoder->Decoder)"""
        v_value = data[3:19]
        return {
            "message_type": "RepeaterAuth_Send_Ack",
            "direction": "Encoder->Decoder",
            "msg_size": msg_size,
            "msg_id": 15,
            "V[127:0]": self.bytes_to_hex(v_value)
        }
    
    def dissect_repeaterauth_stream_manage(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 16: RepeaterAuth_Stream_Manage (Encoder->Decoder)"""
        seq_num_m = struct.unpack('>I', b'\x00' + data[3:6])[0]
        k_value = struct.unpack('>H', data[6:8])[0]
        
        result = {
            "message_type": "RepeaterAuth_Stream_Manage",
            "direction": "Encoder->Decoder",
            "msg_size": msg_size,
            "msg_id": 16,
            "seq_num_M": seq_num_m,
            "k": k_value,
            "streams": []
        }
        
        for j in range(k_value):
            offset = 8 + (j * 12)
            stream_ctr = self.bytes_to_hex(data[offset:offset+4])
            content_stream_id = data[offset+4:offset+11]
            
            # Parse IP address (can be IPv4 or IPv6)
            ip_bytes = data[offset+4:offset+8]
            ipv4 = f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"
            ipv6 = f"::{self.bytes_to_hex(data[offset+4:offset+6])}:{self.bytes_to_hex(data[offset+6:offset+8])}"
            
            udp_port = struct.unpack('>H', data[offset+8:offset+10])[0]
            payload_type = data[offset+10]
            stream_type = data[offset+11]
            
            stream_info = {
                "stream_number": j + 1,
                "streamCtr": stream_ctr,
                "ContentStreamID": self.bytes_to_hex(content_stream_id),
                "Destination_IPv4": ipv4,
                "Destination_IPv6": ipv6,
                "Destination_UDP_Port": udp_port,
                "Payload_Type": payload_type,
                "Type": stream_type
            }
            result["streams"].append(stream_info)
            
        return result
    
    def dissect_repeaterauth_stream_ready(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 17: RepeaterAuth_Stream_Ready (Decoder->Encoder)"""
        m_prime = data[3:35]
        return {
            "message_type": "RepeaterAuth_Stream_Ready",
            "direction": "Decoder->Encoder",
            "msg_size": msg_size,
            "msg_id": 17,
            "M'[255:0]": self.bytes_to_hex(m_prime)
        }
    
    def dissect_receiver_authstatus(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 18: Receiver_AuthStatus (Decoder->Encoder)"""
        length = struct.unpack('>H', data[3:5])[0]
        reauth_req = data[5] == 1
        return {
            "message_type": "Receiver_AuthStatus",
            "direction": "Decoder->Encoder",
            "msg_size": msg_size,
            "msg_id": 18,
            "LENGTH": length,
            "REAUTH_REQ": reauth_req
        }
    
    def dissect_ake_transmitter_info(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 19: AKE_Transmitter_Info (Encoder->Decoder)"""
        length = struct.unpack('>H', data[3:5])[0]
        version = data[5]
        transinfo_tmp = struct.unpack('>H', data[6:8])[0]
        
        transinfo_cap_msk = transinfo_tmp % 4
        transinfo_reserved = (transinfo_tmp - transinfo_cap_msk) // 4
        transinfo_locality_precompute = transinfo_cap_msk % 2
        transinfo_ccont_category = (transinfo_cap_msk - transinfo_locality_precompute) // 2
        
        return {
            "message_type": "AKE_Transmitter_Info",
            "direction": "Encoder->Decoder",
            "msg_size": msg_size,
            "msg_id": 19,
            "LENGTH": length,
            "VERSION": version,
            "TRANSMITTER_CAPABILITY_MASK": hex(transinfo_tmp),
            "Reserved": hex(transinfo_reserved),
            "TRANSMITTER_CONTENT_CATEGORY_SUPPORT": transinfo_ccont_category == 1,
            "TRANSMITTER_LOCALITY_PRECOMPUTE_SUPPORT": transinfo_locality_precompute == 1
        }
    
    def dissect_ake_receiver_info(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 20: AKE_Receiver_Info (Decoder->Encoder)"""
        length = struct.unpack('>H', data[3:5])[0]
        version = data[5]
        receiverinfo_tmp = struct.unpack('>H', data[6:8])[0]
        
        receiverinfo_cap_msk = receiverinfo_tmp % 2
        receiverinfo_reserved = (receiverinfo_tmp - receiverinfo_cap_msk) // 2
        receiverinfo_locality_precompute = receiverinfo_cap_msk
        
        return {
            "message_type": "AKE_Receiver_Info",
            "direction": "Decoder->Encoder",
            "msg_size": msg_size,
            "msg_id": 20,
            "LENGTH": length,
            "VERSION": version,
            "RECEIVER_CAPABILITY_MASK": hex(receiverinfo_tmp),
            "Reserved": hex(receiverinfo_reserved),
            "RECEIVER_LOCALITY_PRECOMPUTE_SUPPORT": receiverinfo_locality_precompute == 1
        }
    
    def dissect_ake_preinit(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 32: AKE_PreInit (Decoder->Encoder)"""
        version_byte = data[3]
        minor_ver = version_byte % 16
        major_ver = (version_byte - minor_ver) // 16
        
        pairing = data[4] == 1
        restart_reauth = data[5] == 1
        receiver = data[6] == 1
        
        return {
            "message_type": "AKE_PreInit",
            "direction": "Decoder->Encoder",
            "msg_size": msg_size,
            "msg_id": 32,
            "Version": hex(version_byte),
            "MajorVersion": major_ver,
            "MinorVersion": minor_ver,
            "pairing": pairing,
            "restart/REAUTH_REQ": restart_reauth,
            "receiver": receiver,
            "receiverId": self.bytes_to_hex(data[7:12]),
            "portId": self.bytes_to_hex(data[12:17]),
            "nodeId": self.bytes_to_hex(data[17:33]),
            "vendorExtension": self.bytes_to_hex(data[33:49])
        }
    
    def dissect_ake_preinitstatus(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 33: AKE_PreInitStatus (Encoder->Decoder)"""
        version_byte = data[3]
        minor_ver = version_byte % 16
        major_ver = (version_byte - minor_ver) // 16
        
        preinit_status = data[4]
        status_map = {
            0: "Ok",
            1: "statusInvalidParameters",
            2: "statusPairingExpired",
            3: "statusSessionExpired"
        }
        status_text = status_map.get(preinit_status, "Reserved")
        
        pairing_slots = struct.unpack('>H', data[5:7])[0]
        session_slots = struct.unpack('>H', data[7:9])[0]
        
        return {
            "message_type": "AKE_PreInitStatus",
            "direction": "Encoder->Decoder",
            "msg_size": msg_size,
            "msg_id": 33,
            "Version": hex(version_byte),
            "MajorVersion": major_ver,
            "MinorVersion": minor_ver,
            "status": preinit_status,
            "status_text": status_text,
            "pairingSlots": pairing_slots,
            "sessionSlots": session_slots,
            "vendorExtension": self.bytes_to_hex(data[9:25])
        }
    
    def dissect_hkep_message(self, data: bytes) -> Optional[Dict]:
        """
        Dissect a single HKEP message
        
        Args:
            data: Raw bytes containing HKEP message
            
        Returns:
            Dictionary with parsed message data or None if invalid
        """
        if len(data) < 3:
            return None
            
        msg_size = struct.unpack('>H', data[0:2])[0]
        msg_id = data[2]
        
        if msg_id not in self.MSG_TYPES:
            return {
                "message_type": f"Unknown (ID: {msg_id})",
                "msg_size": msg_size,
                "msg_id": msg_id,
                "raw_data": self.bytes_to_hex(data[:min(len(data), msg_size + 2)])
            }
        
        # Dispatch to appropriate dissector based on msg_id
        dissectors = {
            1: self.dissect_null_message,
            2: self.dissect_ake_init,
            3: self.dissect_ake_send_cert,
            4: self.dissect_ake_no_stored_km,
            5: self.dissect_ake_stored_km,
            6: self.dissect_ake_send_rrx,
            7: self.dissect_ake_send_h_prime,
            8: self.dissect_ake_send_pairing_info,
            9: self.dissect_lc_init,
            10: self.dissect_lc_send_l_prime,
            11: self.dissect_ske_send_eks,
            12: self.dissect_repeaterauth_send_receiverid_list,
            13: self.dissect_rtt_ready,
            14: self.dissect_rtt_challenge,
            15: self.dissect_repeaterauth_send_ack,
            16: self.dissect_repeaterauth_stream_manage,
            17: self.dissect_repeaterauth_stream_ready,
            18: self.dissect_receiver_authstatus,
            19: self.dissect_ake_transmitter_info,
            20: self.dissect_ake_receiver_info,
            32: self.dissect_ake_preinit,
            33: self.dissect_ake_preinitstatus
        }
        
        dissector_func = dissectors.get(msg_id)
        if dissector_func:
            try:
                return dissector_func(data, msg_size)
            except Exception as e:
                return {
                    "message_type": f"Parse Error ({self.MSG_TYPES[msg_id]})",
                    "msg_size": msg_size,
                    "msg_id": msg_id,
                    "error": str(e),
                    "raw_data": self.bytes_to_hex(data[:min(len(data), 50)])
                }
        
        return None
    
    def get_stream_key(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
        """Generate a unique key for TCP stream identification"""
        # Normalize the stream key (bidirectional)
        if (src_ip, src_port) < (dst_ip, dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
    
    def get_packet_hash(self, packet: Packet) -> str:
        """Generate hash of packet to detect retransmissions"""
        if not packet.haslayer(TCP):
            return ""
        tcp_layer = packet[TCP]
        # Use SEQ number, payload, and IPs to identify unique packets
        src_ip = packet[IP].src if packet.haslayer(IP) else "0"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "0"
        payload = bytes(tcp_layer.payload) if tcp_layer.payload else b""
        return f"{src_ip}:{dst_ip}:{tcp_layer.seq}:{len(payload)}:{payload[:20].hex()}"

    def get_tcp_payload(self, packet: Packet) -> bytes:
        """
        Return a packet's TCP payload with any Ethernet padding removed.

        Real TCP payload length comes from the IP total-length field. Short frames
        (e.g. bare ACK/SYN, 54 bytes) are zero-padded to Ethernet's 60-byte
        minimum, and scapy surfaces that padding as trailing TCP-payload bytes.
        Using bytes(tcp.payload) directly would inject phantom bytes into the
        reassembled stream — corrupting sequence tracking and manufacturing
        messages that were never sent (e.g. a Receiver_AuthStatus whose header
        lands right after a padded ACK). Bound by ip.len, which accounts for
        IP/TCP options. When ip.len is 0 (e.g. TCP segmentation offload), fall
        back to the raw payload bytes.
        """
        if not packet.haslayer(TCP):
            return b""
        tcp_layer = packet[TCP]
        raw = bytes(tcp_layer.payload) if tcp_layer.payload else b""
        if raw and packet.haslayer(IP):
            ip_layer = packet[IP]
            if ip_layer.len:
                seg_len = ip_layer.len - (ip_layer.ihl * 4) - (tcp_layer.dataofs * 4)
                if seg_len >= 0:
                    raw = raw[:seg_len]
        return raw

    def is_complete_hkep_message(self, data: bytes) -> Tuple[bool, int]:
        """
        Check if data contains a complete HKEP message

        Returns:
            (is_complete, expected_length)

        HKEP message format: [2 bytes msg_size] [1 byte msg_id] [msg_size-1 bytes data]
        The msg_size includes the msg_id byte.
        """
        if len(data) < 3:  # Need at least msg_size (2) + msg_id (1)
            return False, 3

        msg_size = struct.unpack('>H', data[0:2])[0]
        msg_id = data[2]

        # msg_size includes the msg_id byte, so payload should be exactly msg_size bytes
        expected_length = msg_size

        if len(data) >= expected_length:
            # Additional validation: check that msg_id is valid
            if msg_id in self.MSG_TYPES:
                return True, expected_length
            else:
                return False, expected_length
        else:
            return False, expected_length
    
    def detect_hkep_ports(self, pcap_file: str) -> Dict[int, int]:
        """
        Scan all TCP ports to detect which ones contain HKEP traffic
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            Dictionary mapping port numbers to count of HKEP messages
        """
        try:
            packets = rdpcap(pcap_file)
        except Exception as e:
            print(f"Error reading PCAP file: {e}")
            return {}
        
        port_hkep_counts = {}
        
        for packet in packets:
            if not packet.haslayer(TCP):
                continue
                
            tcp_layer = packet[TCP]
            
            if not tcp_layer.payload:
                continue
                
            payload = self.get_tcp_payload(packet)
            if len(payload) < 3:
                continue

            # Try to parse as HKEP
            try:
                msg_size = struct.unpack('>H', payload[0:2])[0]
                msg_id = payload[2]
                
                # Check if msg_id is a valid HKEP message type
                if msg_id in self.MSG_TYPES:
                    # Check if message size is reasonable (HKEP messages are typically < 1000 bytes)
                    if 1 <= msg_size <= 1000:
                        # Valid HKEP message detected
                        sport = tcp_layer.sport
                        dport = tcp_layer.dport
                        
                        port_hkep_counts[sport] = port_hkep_counts.get(sport, 0) + 1
                        port_hkep_counts[dport] = port_hkep_counts.get(dport, 0) + 1
            except:
                continue
        
        return port_hkep_counts
    
    def _fix_missing_timestamps(self, packets: List) -> int:
        """
        Fix packets with 0.0 timestamps by interpolating from surrounding packets.
        
        Strategy:
        1. For packets between two valid timestamps: linear interpolation
        2. For packets at the start (before first valid): use first valid timestamp - small offset
        3. For packets at the end (after last valid): use last valid timestamp + small offset
        
        Args:
            packets: List of Scapy packets (modified in-place)
            
        Returns:
            Number of timestamps fixed
        """
        fixed_count = 0
        
        # Find all valid timestamps and their positions
        valid_timestamps = []  # List of (index, timestamp)
        for idx, pkt in enumerate(packets):
            if hasattr(pkt, 'time'):
                ts = float(pkt.time)
                if ts > 0.0:  # Valid timestamp
                    valid_timestamps.append((idx, ts))
        
        if len(valid_timestamps) < 2:
            # Not enough valid timestamps to interpolate
            return 0
        
        # Estimate average time between packets from valid samples
        time_diffs = []
        for i in range(1, min(len(valid_timestamps), 100)):  # Sample first 100 valid timestamps
            idx_diff = valid_timestamps[i][0] - valid_timestamps[i-1][0]
            time_diff = valid_timestamps[i][1] - valid_timestamps[i-1][1]
            if idx_diff > 0:
                time_diffs.append(time_diff / idx_diff)
        
        avg_packet_interval = sum(time_diffs) / len(time_diffs) if time_diffs else 0.0001  # Default 0.1ms
        
        # Fix each packet with 0.0 timestamp
        for idx, pkt in enumerate(packets):
            if not hasattr(pkt, 'time') or float(pkt.time) != 0.0:
                continue
            
            # Find surrounding valid timestamps
            prev_valid = None
            next_valid = None
            
            # Find previous valid timestamp
            for valid_idx, valid_ts in reversed(valid_timestamps):
                if valid_idx < idx:
                    prev_valid = (valid_idx, valid_ts)
                    break
            
            # Find next valid timestamp
            for valid_idx, valid_ts in valid_timestamps:
                if valid_idx > idx:
                    next_valid = (valid_idx, valid_ts)
                    break
            
            # Interpolate timestamp
            if prev_valid and next_valid:
                # Between two valid timestamps: linear interpolation
                prev_idx, prev_ts = prev_valid
                next_idx, next_ts = next_valid
                
                # Linear interpolation
                ratio = (idx - prev_idx) / (next_idx - prev_idx)
                interpolated_ts = prev_ts + ratio * (next_ts - prev_ts)
                pkt.time = interpolated_ts
                fixed_count += 1
                
            elif prev_valid:
                # After last valid timestamp: extrapolate forward
                prev_idx, prev_ts = prev_valid
                packets_after = idx - prev_idx
                pkt.time = prev_ts + (packets_after * avg_packet_interval)
                fixed_count += 1
                
            elif next_valid:
                # Before first valid timestamp: extrapolate backward
                next_idx, next_ts = next_valid
                packets_before = next_idx - idx
                pkt.time = max(0.0, next_ts - (packets_before * avg_packet_interval))
                fixed_count += 1
        
        return fixed_count
    
    def _find_contiguous_blocks(self, packets: List[Tuple[int, int, bytes, int, Packet]]) -> List[Tuple[bytes, List[Tuple[int, int, bytes, int, Packet]]]]:
        """
        Find contiguous blocks of packets (no gaps in sequence numbers)

        Out-of-order segments are handled by the sequence-number sort below, so
        capture order does not matter. All sequence comparisons are 32-bit
        wraparound-safe (see _seq_lt / _seq_add / _seq_diff).

        Returns list of (block_data, block_packets) tuples
        """
        if not packets:
            return []

        # Sort by sequence number. Sorting on the raw value would split a stream
        # that wraps past 2^32 into two blocks in the wrong order, so order by
        # signed distance from the lowest observed sequence number instead.
        base_seq = packets[0][0]
        for pkt in packets:
            if _seq_lt(pkt[0], base_seq):
                base_seq = pkt[0]
        packets.sort(key=lambda x: _seq_diff(x[0], base_seq))

        blocks = []
        current_block = []
        current_data = bytearray()
        expected_seq = None

        for seq, length, payload, pkt_num, packet in packets:
            if len(payload) == 0:
                continue

            if expected_seq is None:
                # Start new block
                current_block = [(seq, length, payload, pkt_num, packet)]
                current_data = bytearray(payload)
                expected_seq = _seq_add(seq, len(payload))
            elif seq == expected_seq:
                # Continuation of current block
                current_block.append((seq, length, payload, pkt_num, packet))
                current_data.extend(payload)
                expected_seq = _seq_add(seq, len(payload))
            elif _seq_lt(seq, expected_seq):
                # Retransmission or partial overlap — do not start a new block.
                overlap = _seq_diff(expected_seq, seq)
                if overlap < len(payload):
                    # Partial overlap: only the new suffix carries unseen bytes.
                    new_payload = payload[overlap:]
                    current_block.append((_seq_add(seq, overlap), len(new_payload), new_payload, pkt_num, packet))
                    current_data.extend(new_payload)
                    expected_seq = _seq_add(seq, len(payload))
                # else: full retransmission — already have all these bytes; skip.
            else:
                # True gap (seq after expected_seq) — save current block and start a new one.
                if current_block:
                    blocks.append((bytes(current_data), current_block))

                # Start new block
                current_block = [(seq, length, payload, pkt_num, packet)]
                current_data = bytearray(payload)
                expected_seq = _seq_add(seq, len(payload))

        # Add final block
        if current_block:
            blocks.append((bytes(current_data), current_block))

        return blocks

    # A resynchronisation point has to be justified by more than one message.
    # Header density in HDCP key material is roughly one plausible 3-byte header
    # per 270 bytes, so a single message — or even a pair — can line up by
    # chance; a run of three whose lengths tile the block does not.
    RESYNC_MIN_MESSAGES = 3

    def _chain_frames_cleanly(self, block_data: bytes, start: int, min_messages: int = 1) -> bool:
        """
        Return True if framing forward from *start* accounts for the rest of the block.

        Every message from *start* onwards must carry a valid header, the chain
        must consume the block exactly — ending either on its final byte or on a
        trailing message cut short by the end of the capture — and it must contain
        at least *min_messages* complete messages.

        Requiring the whole chain to close is what separates a genuine message
        boundary from a byte pattern inside a certificate or a hash that happens
        to look like a header. A lone plausible header is weak evidence; a run of
        headers whose lengths tile the block is strong evidence.
        """
        offset = start
        framed = 0

        while offset < len(block_data):
            if offset + 3 > len(block_data):
                # Trailing bytes too short to hold a header: a message truncated
                # by the end of the capture.
                return framed >= min_messages

            msg_size = struct.unpack('>H', block_data[offset:offset+2])[0]
            if msg_size < 3 or msg_size > 1000:
                return False
            if block_data[offset+2] not in self.MSG_TYPES:
                return False

            if offset + msg_size > len(block_data):
                # Trailing message truncated by the end of the capture.
                return framed >= min_messages

            offset += msg_size
            framed += 1

        return framed >= min_messages

    def _next_sync_offset(self, block_data: bytes, start: int) -> Optional[int]:
        """
        Find the first offset at or after *start* whose message chain closes cleanly.

        Prefers the strongest available evidence: a chain of RESYNC_MIN_MESSAGES
        or more is tried first, and shorter chains are only considered when no
        such point exists anywhere in the block. That keeps the strict rule for
        the common case while still recovering the last message or two of a
        block, where a long chain is impossible by definition.

        Returns None when no remaining offset can frame the rest of the block, in
        which case the caller should account for the skipped bytes rather than
        guessing at a boundary.
        """
        for min_messages in range(self.RESYNC_MIN_MESSAGES, 0, -1):
            for candidate in range(start, len(block_data) - 2):
                if self._chain_frames_cleanly(block_data, candidate, min_messages):
                    return candidate
        return None

    def _extract_messages_from_block(self, block_data: bytes, block_packets: List, stream_key: str, direction_name: str, hkep_message_count: int) -> List[Dict]:
        """
        Extract HKEP messages from a contiguous block of data

        A block is only framed from an offset whose whole message chain tiles the
        rest of the block (see _chain_frames_cleanly). Resynchronising on the
        first 3-byte pattern that merely looks like a header is not safe here:
        an HKEP header is only a 2-byte length plus a 1-byte msg_id, and that
        pattern occurs roughly once every 270 bytes of HDCP key material, so
        scanning forward through a certificate or a hash will eventually
        manufacture a message that was never sent.

        Returns list of message results
        """
        messages = []
        offset = 0

        # Establish a trustworthy starting point before framing anything.
        if not self._chain_frames_cleanly(block_data, 0):
            start = self._next_sync_offset(block_data, 1)
            if start is None:
                self._framing_skipped_bytes += len(block_data)
                return messages
            self._framing_skipped_bytes += start
            self._framing_resyncs += 1
            offset = start

        while offset + 3 <= len(block_data):
            # msg_size is the total on-wire length, i.e. it already covers its own
            # two bytes and the msg_id (same convention as is_complete_hkep_message).
            msg_size = struct.unpack('>H', block_data[offset:offset+2])[0]
            if msg_size < 3 or msg_size > 1000 or offset + msg_size > len(block_data):
                # Trailing message cut short by the end of the capture.
                self._framing_skipped_bytes += len(block_data) - offset
                break

            msg_data = block_data[offset:offset+msg_size]
            msg_id = msg_data[2]
            if msg_id not in self.MSG_TYPES:
                # Unreachable once the chain has been validated; kept as a guard.
                self._framing_skipped_bytes += len(block_data) - offset
                break

            try:
                hkep_data = self.dissect_hkep_message(msg_data)
            except (ValueError, IndexError, struct.error):
                hkep_data = None

            if hkep_data and hkep_data.get('msg_id') in self.MSG_TYPES:
                # Set direction for Null messages based on TCP stream direction
                # forward = server->client (Encoder->Decoder), reverse = client->server (Decoder->Encoder)
                if hkep_data.get('message_type') == 'Null message' and 'direction' not in hkep_data:
                    hkep_data['direction'] = 'Encoder->Decoder' if direction_name == 'forward' else 'Decoder->Encoder'

                # Find which packet contains this message
                actual_pkt_num = block_packets[0][3]  # Default to first packet
                actual_timestamp = float(block_packets[0][4].time) if hasattr(block_packets[0][4], 'time') else 0.0

                # Track offset to find the right packet
                current_offset = 0
                for seq, length, payload, pkt_num, pkt in block_packets:
                    if current_offset <= offset < current_offset + len(payload):
                        actual_pkt_num = pkt_num
                        actual_timestamp = float(pkt.time) if hasattr(pkt, 'time') else 0.0
                        break
                    current_offset += len(payload)

                messages.append({
                    "packet_number": actual_pkt_num,
                    "timestamp": actual_timestamp,
                    "hkep": hkep_data
                })

            # The message boundary is trusted even when the body failed to
            # dissect, so a single bad message does not cost us the rest.
            offset += msg_size

        return messages

    def analyze_pcap(self, pcap_file: str, verbose: bool = True, handle_reassembly: bool = True, show_tcp_issues: bool = False, validate_12_6: bool = False, validate_12_7: bool = False, validate_13_1: bool = False, validate_13_2: bool = False, validate_13_3: bool = False, validate_session_caching: bool = False, ignore_slot_limits: bool = False) -> HKEPAnalysisResult:
        """
        Analyze PCAP file for HKEP messages

        Args:
            pcap_file: Path to PCAP file
            verbose: Print results to console
            handle_reassembly: Enable TCP stream reassembly (recommended)
            show_tcp_issues: Show warnings for TCP reassembly issues (default: False)
            validate_12_6: Enable validation for section 12.6
            validate_12_7: Enable validation for section 12.7
            validate_13_1: Enable validation for section 13.1
            validate_13_2: Enable validation for section 13.2
            validate_13_3: Enable validation for section 13.3
            validate_session_caching: Enable session caching validation
            ignore_slot_limits: If True, ignore pairingSlots and sessionSlots values and assume infinite slots (default: False)

        Returns:
            HKEPAnalysisResult containing grouped HKEP exchanges and messages
        """
        # Auto-detect HKEP ports if target_port not specified
        if self.target_port is None:
            if verbose:
                print("No port specified. Scanning for HKEP traffic...")
            port_counts = self.detect_hkep_ports(pcap_file)
            
            if not port_counts:
                if verbose:
                    print("No HKEP traffic detected on any port.")
                return HKEPAnalysisResult()
            
            # Find the port(s) with HKEP traffic
            # Use the port with most HKEP messages
            detected_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)
            
            if verbose:
                print(f"\nDetected HKEP traffic on the following ports:")
                for port, count in detected_ports:
                    print(f"  Port {port}: {count} potential HKEP messages")
                print()
            
            # Use the port with most traffic
            self.target_port = detected_ports[0][0]
            
            if verbose:
                print(f"Using port {self.target_port} for analysis (highest HKEP message count)")
                print()
        
        try:
            packets = rdpcap(pcap_file)
            
            # Check for packets with 0.0 timestamps (PCAP file quality issue)
            zero_timestamp_packets = []
            for idx, pkt in enumerate(packets, 1):
                if hasattr(pkt, 'time') and float(pkt.time) == 0.0:
                    zero_timestamp_packets.append(idx)
            
            if zero_timestamp_packets:
                print(f"\n[!] WARNING: PCAP file quality issue detected!")
                print(f"  {len(zero_timestamp_packets)} out of {len(packets)} packets have missing timestamps (0.0)")
                print(f"  First affected packets: {zero_timestamp_packets[:20]}")
                if len(zero_timestamp_packets) > 20:
                    print(f"  ... and {len(zero_timestamp_packets) - 20} more")
                print(f"\n  Attempting to fix timestamps using interpolation...")
                
                # Fix timestamps by interpolating based on packet ordering
                fixed_count = self._fix_missing_timestamps(packets)
                
                print(f"  [OK] Fixed {fixed_count} timestamps using interpolation from surrounding packets")
                print(f"  Continuing with analysis...\n")
        except Exception as e:
            print(f"Error reading PCAP file: {e}")
            return HKEPAnalysisResult()
        
        # Store validation flags for use in analysis
        self._validate_12_6 = validate_12_6
        self._validate_12_7 = validate_12_7
        self._validate_13_1 = validate_13_1
        self._validate_13_2 = validate_13_2
        self._validate_13_3 = validate_13_3
        self._validate_session_caching = validate_session_caching
        self._ignore_slot_limits = ignore_slot_limits
        
        # Use proper TCP stream reassembly
        if handle_reassembly:
            return self._analyze_with_proper_reassembly(packets, verbose, show_tcp_issues)
        
        # Fallback to packet-by-packet (original method)
        results = []
        hkep_packet_count = 0
        retransmission_count = 0
        incomplete_count = 0
        tcp_issue_count = 0
        tcp_connections = {}  # Track connection states
        
        for pkt_num, packet in enumerate(packets, 1):
            if not packet.haslayer(TCP):
                continue
                
            tcp_layer = packet[TCP]
            
            # Filter for target port
            if tcp_layer.dport != self.target_port and tcp_layer.sport != self.target_port:
                continue
            
            # Extract packet metadata
            src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
            dst_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            
            # Track TCP connection state changes
            conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            conn_key_rev = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
            
            # Detect TCP connection events (SYN, FIN, RST)
            if tcp_layer.flags.S and not tcp_layer.flags.A:
                # SYN - new connection
                tcp_connections[conn_key] = 'SYN'
                if verbose:
                    print(f"\n{'='*80}")
                    print(f"[TCP CONNECTION START] Packet #{pkt_num}")
                    print(f"  {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    print(f"  SYN: SEQ={tcp_layer.seq}")
                    print(f"{'='*80}")
            elif tcp_layer.flags.S and tcp_layer.flags.A:
                # SYN-ACK - connection acknowledgment
                tcp_connections[conn_key_rev] = 'ESTABLISHED'
                if verbose:
                    print(f"\n{'='*80}")
                    print(f"[TCP CONNECTION ESTABLISHED] Packet #{pkt_num}")
                    print(f"  {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    print(f"  SYN-ACK: SEQ={tcp_layer.seq}, ACK={tcp_layer.ack}")
                    print(f"{'='*80}")
            elif tcp_layer.flags.F:
                # FIN - graceful disconnect
                if verbose:
                    print(f"\n{'='*80}")
                    print(f"[TCP DISCONNECT - FIN] Packet #{pkt_num}")
                    print(f"  {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    print(f"  FIN: SEQ={tcp_layer.seq}, ACK={tcp_layer.ack if tcp_layer.flags.A else 'N/A'}")
                    print(f"{'='*80}")
                    print(f"\n{'#'*80} << END OF HKEP EXCHANGE\n")
                # Mark connection as closing
                if conn_key in tcp_connections:
                    tcp_connections[conn_key] = 'CLOSING'
                if conn_key_rev in tcp_connections:
                    tcp_connections[conn_key_rev] = 'CLOSING'
            elif tcp_layer.flags.R:
                # RST - abrupt disconnect
                if verbose:
                    print(f"\n{'='*80}")
                    print(f"[TCP DISCONNECT - RST] Packet #{pkt_num}")
                    print(f"  {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    print(f"  RST: SEQ={tcp_layer.seq}")
                    print(f"{'='*80}")
                    print(f"\n{'#'*80} << END OF HKEP EXCHANGE (ABORTED)\n")
                # Remove connection from tracking
                tcp_connections.pop(conn_key, None)
                tcp_connections.pop(conn_key_rev, None)
            
            # Get TCP payload - use TCP payload directly (Raw layer may be incomplete)
            if not tcp_layer.payload:
                continue
            
            payload = self.get_tcp_payload(packet)
            if len(payload) < 3:
                continue

            # Track seen packets for retransmission detection (but don't skip yet - might be needed for reassembly)
            pkt_hash = self.get_packet_hash(packet)
            is_retransmission = pkt_hash in self.seen_packets
            if is_retransmission:
                retransmission_count += 1
                if show_tcp_issues and verbose:
                    print(f"\n[WARNING] Packet #{pkt_num}: TCP Retransmission detected")
                    print(f"  {src_ip}:{src_port} -> {dst_ip}:{dst_port}, SEQ={tcp_layer.seq}")
                # Don't skip retransmissions - they might be needed for reassembly
                # We'll skip them later if they're truly duplicates
            if not is_retransmission:
                self.seen_packets.add(pkt_hash)
            
            # Check for complete HKEP message
            is_complete, expected_length = self.is_complete_hkep_message(payload)
            
            tcp_flags = []
            if tcp_layer.flags.P:
                tcp_flags.append("PSH")
            if tcp_layer.flags.A:
                tcp_flags.append("ACK")
            if tcp_layer.flags.S:
                tcp_flags.append("SYN")
            if tcp_layer.flags.F:
                tcp_flags.append("FIN")
            if tcp_layer.flags.R:
                tcp_flags.append("RST")
            
            if not is_complete:
                incomplete_count += 1
                tcp_issue_count += 1
                if show_tcp_issues and verbose:
                    print(f"\n[WARNING] Packet #{pkt_num}: Incomplete HKEP message")
                    print(f"  {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    print(f"  TCP Flags: {','.join(tcp_flags) if tcp_flags else 'None'}")
                    print(f"  Payload length: {len(payload)} bytes, Expected: {expected_length} bytes")
                    print(f"  SEQ: {tcp_layer.seq}, ACK: {tcp_layer.ack if tcp_layer.flags.A else 'N/A'}")
                
                if handle_reassembly:
                    # Store for potential reassembly
                    # Use directional stream key (src->dst)
                    stream_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                    
                    if stream_key not in self.tcp_streams:
                        self.tcp_streams[stream_key] = {
                            'buffer': b'',
                            'expected_seq': None,  # Will be set from first packet
                            'packets': []
                        }
                    
                    stream = self.tcp_streams[stream_key]
                    
                    # Initialize expected_seq from first packet with data
                    if stream['expected_seq'] is None:
                        stream['expected_seq'] = tcp_layer.seq
                    
                    # Check if this is the expected sequence number
                    if tcp_layer.seq == stream['expected_seq']:
                        # In-order packet - add to buffer
                        stream['buffer'] += payload
                        stream['expected_seq'] = _seq_add(tcp_layer.seq, len(payload))
                        stream['packets'].append(pkt_num)
                    elif _seq_lt(tcp_layer.seq, stream['expected_seq']):
                        # Old/duplicate packet - skip
                        if show_tcp_issues and verbose:
                            print(f"  [INFO] Skipping old/duplicate packet with SEQ={tcp_layer.seq}")
                        continue
                    else:
                        # Out-of-order packet - this shouldn't happen often
                        if show_tcp_issues and verbose:
                            print(f"  [WARNING] Out-of-order packet detected!")
                        continue
                    
                    # Extract all complete messages from buffer
                    messages_extracted = False
                    while len(stream['buffer']) >= 2:
                        is_complete_now, expected_length_now = self.is_complete_hkep_message(stream['buffer'])
                        if is_complete_now:
                            if show_tcp_issues and verbose and len(stream['packets']) > 1:
                                print(f"  [INFO] Reassembled complete message from packets: {stream['packets']}")
                            payload = stream['buffer'][:expected_length_now]
                            # Remove processed message from buffer
                            stream['buffer'] = stream['buffer'][expected_length_now:]
                            stream['packets'] = [pkt_num]  # Reset for next message
                            messages_extracted = True
                            break  # Process this message, then come back for more
                        else:
                            # Not enough data for a complete message yet
                            break
                    
                    if not messages_extracted:
                        # No complete message yet - wait for more packets
                        continue
                else:
                    continue  # Skip incomplete messages if reassembly disabled
            
            # Check for spurious data (payload longer than expected)
            # This might actually be multiple messages in one packet!
            if len(payload) > expected_length:
                tcp_issue_count += 1
                if show_tcp_issues and verbose:
                    print(f"\n[WARNING] Packet #{pkt_num}: Payload longer than expected message")
                    print(f"  {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    print(f"  Payload length: {len(payload)} bytes, Expected: {expected_length} bytes")
                    print(f"  This might contain multiple messages - processing first message")
                # Process first message, then check if there's more
                first_message = payload[:expected_length]
                remaining_data = payload[expected_length:]
                
                # Process first message
                payload = first_message
                
                # If there's remaining data, try to process it as additional messages
                # But for now, just process the first one to avoid complexity
            
            hkep_packet_count += 1
            
            # Dissect HKEP message
            hkep_data = self.dissect_hkep_message(payload)
            
            if hkep_data:
                result = {
                    "packet_number": pkt_num,
                    "hkep_packet_number": hkep_packet_count,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "timestamp": float(packet.time) if hasattr(packet, 'time') else 0,
                    "tcp_seq": tcp_layer.seq,
                    "tcp_ack": tcp_layer.ack if tcp_layer.flags.A else None,
                    "tcp_flags": ','.join(tcp_flags) if tcp_flags else None,
                    "hkep": hkep_data
                }
                results.append(result)
                
                if verbose:
                    self.print_hkep_message(result)
        
        if verbose:
            # Count TCP connection events
            active_connections = sum(1 for state in tcp_connections.values() if state == 'ESTABLISHED')
            closing_connections = sum(1 for state in tcp_connections.values() if state == 'CLOSING')
            
            print(f"\n{'='*80}")
            print(f"Summary:")
            print(f"  Total packets: {len(packets)}")
            print(f"  Valid HKEP messages: {hkep_packet_count}")
            print(f"  Active TCP connections: {active_connections}")
            print(f"  Closing TCP connections: {closing_connections}")
            if show_tcp_issues:
                print(f"  TCP retransmissions detected: {retransmission_count}")
                print(f"  Incomplete/fragmented messages: {incomplete_count}")
                print(f"  Total TCP issues: {tcp_issue_count}")
            print(f"{'='*80}")
        
        return results
    
    def _get_or_create_exchange(self, exchanges: Dict, stream_to_session: Dict, stream_key: str, 
                                src_ip: str, src_port: int, dst_ip: str, dst_port: int,
                                receiver_id: str = None, node_id: str = None, port_id: str = None,
                                is_new_preinit: bool = False) -> tuple:
        """
        Get or create an HKEP exchange based on session tuple or stream_key
        
        Args:
            is_new_preinit: If True, indicates this is a new AKE_PreInit message, 
                           potentially starting a new exchange (reconnection attempt)
        
        Returns:
            (exchange, session_key) tuple
        """
        # If we have session tuple (from AKE_PreInit), use it
        if receiver_id is not None and node_id is not None and port_id is not None:
            base_session_key = f"({receiver_id}, {node_id}, {port_id})"
            
            # Check if we need to create a new exchange for a reconnection attempt
            # If is_new_preinit is True and an exchange already exists for this session,
            # this is a reconnection - create a new exchange with a unique suffix
            if is_new_preinit and base_session_key in exchanges:
                # This is a reconnection - create a new exchange with a unique suffix
                # Find the next available suffix
                suffix = 1
                while f"{base_session_key}_{suffix}" in exchanges:
                    suffix += 1
                session_key = f"{base_session_key}_{suffix}"
                exchanges[session_key] = HKEPExchange(session_key, receiver_id, node_id, port_id)
            else:
                # First time seeing this session, or not a new PreInit
                session_key = base_session_key
                if session_key not in exchanges:
                    exchanges[session_key] = HKEPExchange(session_key, receiver_id, node_id, port_id)
            
            exchange = exchanges[session_key]
            exchange.add_tcp_connection(stream_key, src_ip, src_port, dst_ip, dst_port)
            stream_to_session[stream_key] = session_key
            return exchange, session_key
        
        # Otherwise, check if we've seen this stream before (from a previous AKE_PreInit)
        if stream_key in stream_to_session:
            session_key = stream_to_session[stream_key]
            exchange = exchanges[session_key]
            exchange.add_tcp_connection(stream_key, src_ip, src_port, dst_ip, dst_port)
            return exchange, session_key
        
        # No session tuple yet and haven't seen this stream - return None
        # Messages before AKE_PreInit are not part of an HKEP exchange and are ignored
        return None, None

    def _analyze_with_proper_reassembly(self, packets: List, verbose: bool, show_tcp_issues: bool) -> HKEPAnalysisResult:
        """Analyze using proper TCP stream reassembly - gets ALL messages"""
        analysis_result = HKEPAnalysisResult()
        analysis_result.total_packets = len(packets)

        exchanges = {}  # session_key -> HKEPExchange (keyed by "(receiverId, nodeId, portId)")
        stream_to_session = {}  # stream_key -> session_key (maps TCP connection to HKEP session)
        tcp_connections = {}
        stream_data = {}  # stream_key -> {'forward': [(seq, len, payload, pkt_num, packet)], 'reverse': [...]}
        timeline_events = []  # List of events in chronological order: (pkt_num, timestamp, event_type, event_data)
        
        # First pass: collect all packets, track connections, and record TCP events
        for pkt_num, packet in enumerate(packets, 1):
            if not packet.haslayer(TCP):
                continue
            
            tcp_layer = packet[TCP]
            if tcp_layer.dport != self.target_port and tcp_layer.sport != self.target_port:
                continue
            
            src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
            dst_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            timestamp = float(packet.time) if hasattr(packet, 'time') else 0.0
            
            # Track TCP connection events and add to timeline
            conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            conn_key_rev = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
            
            if tcp_layer.flags.S and not tcp_layer.flags.A:
                tcp_connections[conn_key] = 'SYN'
                timeline_events.append({
                    'pkt_num': pkt_num,
                    'timestamp': timestamp,
                    'type': 'tcp_syn',
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'seq': tcp_layer.seq
                })
            elif tcp_layer.flags.S and tcp_layer.flags.A:
                tcp_connections[conn_key_rev] = 'ESTABLISHED'
                timeline_events.append({
                    'pkt_num': pkt_num,
                    'timestamp': timestamp,
                    'type': 'tcp_syn_ack',
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'seq': tcp_layer.seq,
                    'ack': tcp_layer.ack
                })
            elif tcp_layer.flags.F:
                timeline_events.append({
                    'pkt_num': pkt_num,
                    'timestamp': timestamp,
                    'type': 'tcp_fin',
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'seq': tcp_layer.seq,
                    'ack': tcp_layer.ack if tcp_layer.flags.A else None
                })
            elif tcp_layer.flags.R:
                timeline_events.append({
                    'pkt_num': pkt_num,
                    'timestamp': timestamp,
                    'type': 'tcp_rst',
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'seq': tcp_layer.seq
                })
            
            # Collect payload for reassembly
            if tcp_layer.payload:
                payload = self.get_tcp_payload(packet)
                if len(payload) > 0:
                    # Create bidirectional stream key
                    if (src_ip, src_port) < (dst_ip, dst_port):
                        stream_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                    else:
                        stream_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
                    
                    # Determine direction
                    if src_port == self.target_port:
                        direction = 'forward'
                    else:
                        direction = 'reverse'
                    
                    if stream_key not in stream_data:
                        stream_data[stream_key] = {'forward': [], 'reverse': []}
                    
                    seq = tcp_layer.seq
                    stream_data[stream_key][direction].append((seq, len(payload), payload, pkt_num, packet))
        
        # Second pass: reassemble streams and extract HKEP messages
        hkep_message_count = 0
        
        if verbose:
            print(f"\nReassembling {len(stream_data)} TCP streams...")
        
        # Collect HKEP messages with their packet info for timeline
        hkep_messages = []  # List of (pkt_num, timestamp, hkep_data, stream_info)
        
        # Track AKE_PreInit packets to properly handle reconnections
        # Each AKE_PreInit starts a new exchange, even with same session identifiers
        preinit_packets = {}  # pkt_num -> (stream_key, receiver_id, node_id, port_id, timestamp)
        stream_preinits = {}  # stream_key -> [(pkt_num, session_key)]  sorted by pkt_num
        
        # Helper function to find which exchange a packet belongs to
        def find_exchange_for_packet(stream_key, pkt_num):
            """Find the correct exchange for a packet based on AKE_PreInit boundaries"""
            if stream_key not in stream_preinits:
                return stream_to_session.get(stream_key), None
            
            # Find the most recent AKE_PreInit before this packet
            preinits_for_stream = stream_preinits[stream_key]
            session_key = None
            for preinit_pkt, preinit_session in preinits_for_stream:
                if preinit_pkt <= pkt_num:
                    session_key = preinit_session
                else:
                    break
            return session_key, exchanges.get(session_key) if session_key else None
        
        # First pass: Find all AKE_PreInit messages to establish session mappings
        # This ensures we can associate all messages with the correct exchange
        for stream_key, directions in stream_data.items():
            # Get metadata from first packet in either direction
            first_direction = 'forward' if directions['forward'] else 'reverse'
            first_packet = directions[first_direction][0][4] if directions[first_direction] else None
            if not first_packet:
                continue
            tcp_layer = first_packet[TCP]
            src_ip = first_packet[IP].src if first_packet.haslayer(IP) else "unknown"
            dst_ip = first_packet[IP].dst if first_packet.haslayer(IP) else "unknown"
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            
            # Look for AKE_PreInit in all directions to establish session
            for direction_name in ['forward', 'reverse']:
                direction_packets = directions[direction_name]
                if not direction_packets:
                    continue
                
                # Check individual packets for AKE_PreInit
                for seq, length, payload, pkt_num, packet in direction_packets:
                    if len(payload) < 3:
                        continue
                    is_complete, expected_length = self.is_complete_hkep_message(payload)
                    if is_complete and len(payload) >= expected_length:
                        hkep_data = self.dissect_hkep_message(payload[:expected_length])
                        if hkep_data and hkep_data.get('message_type') == 'AKE_PreInit':
                            receiver_id = hkep_data.get('receiverId')
                            node_id = hkep_data.get('nodeId')
                            port_id = hkep_data.get('portId')
                            if receiver_id and node_id and port_id:
                                timestamp = float(packet.time) if hasattr(packet, 'time') else 0.0
                                preinit_packets[pkt_num] = (stream_key, receiver_id, node_id, port_id, timestamp)
                                # Create exchange and map stream to session
                                exchange, session_key = self._get_or_create_exchange(
                                    exchanges, stream_to_session, stream_key, src_ip, src_port, dst_ip, dst_port,
                                    receiver_id, node_id, port_id, is_new_preinit=True
                                )
                                # Track this PreInit for packet-to-exchange mapping
                                if stream_key not in stream_preinits:
                                    stream_preinits[stream_key] = []
                                stream_preinits[stream_key].append((pkt_num, session_key))
                                break
                
                # Also check reassembled blocks for AKE_PreInit.
                # This handles the case where AKE_PreInit is fragmented across multiple TCP segments
                # and therefore not visible in the individual-packet scan above.
                contiguous_blocks = self._find_contiguous_blocks(direction_packets)
                for block_data, block_packets in contiguous_blocks:
                    if len(block_data) < 3:
                        continue
                    messages_from_block = self._extract_messages_from_block(
                        block_data, block_packets, stream_key, direction_name, 0
                    )
                    for msg_result in messages_from_block:
                        hkep_data = msg_result.get("hkep", {})
                        if hkep_data.get('message_type') == 'AKE_PreInit':
                            receiver_id = hkep_data.get('receiverId')
                            node_id = hkep_data.get('nodeId')
                            port_id = hkep_data.get('portId')
                            if receiver_id and node_id and port_id:
                                pkt_num = msg_result.get('packet_number')
                                # Skip if the individual-packet scan already registered this
                                # exact AKE_PreInit, which would otherwise create a spurious
                                # duplicate exchange with a "_N" suffix.
                                if pkt_num in preinit_packets:
                                    break
                                timestamp = msg_result.get('timestamp', 0)
                                preinit_packets[pkt_num] = (stream_key, receiver_id, node_id, port_id, timestamp)
                                # Create exchange and map stream to session
                                exchange, session_key = self._get_or_create_exchange(
                                    exchanges, stream_to_session, stream_key, src_ip, src_port, dst_ip, dst_port,
                                    receiver_id, node_id, port_id, is_new_preinit=True
                                )
                                # Track this PreInit for packet-to-exchange mapping
                                if stream_key not in stream_preinits:
                                    stream_preinits[stream_key] = []
                                stream_preinits[stream_key].append((pkt_num, session_key))
                                break
        
        # Sort stream_preinits by packet number to ensure proper ordering
        for stream_key in stream_preinits:
            stream_preinits[stream_key].sort(key=lambda x: x[0])
        
        # Second pass: Process all messages and associate with exchanges.
        # Reset the framing diagnostics so they describe this pass only (the
        # AKE_PreInit discovery pass above walks the same blocks).
        self._framing_skipped_bytes = 0
        self._framing_resyncs = 0

        for stream_key, directions in stream_data.items():
            # Get metadata from first packet in either direction
            first_direction = 'forward' if directions['forward'] else 'reverse'
            first_packet = directions[first_direction][0][4] if directions[first_direction] else None
            if not first_packet:
                continue
            tcp_layer = first_packet[TCP]
            src_ip = first_packet[IP].src if first_packet.haslayer(IP) else "unknown"
            dst_ip = first_packet[IP].dst if first_packet.haslayer(IP) else "unknown"
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport

            # Process each direction - collect ALL packets and try multiple approaches
            for direction_name in ['forward', 'reverse']:
                direction_packets = directions[direction_name]

                if not direction_packets:
                    continue

                # Get metadata from first packet
                first_pkt_num, first_packet = direction_packets[0][3], direction_packets[0][4]
                tcp_layer = first_packet[TCP]
                src_ip = first_packet[IP].src if first_packet.haslayer(IP) else "unknown"
                dst_ip = first_packet[IP].dst if first_packet.haslayer(IP) else "unknown"

                if verbose:
                    print(f"  Stream {stream_key} {direction_name}: {len(direction_packets)} packets")

                # Approach 1: Process each packet individually (like Wireshark does)
                # This catches all packets that contain complete HKEP messages
                for seq, length, payload, pkt_num, packet in direction_packets:
                    if len(payload) < 3:
                        continue

                    # Check if this packet contains a complete HKEP message
                    is_complete, expected_length = self.is_complete_hkep_message(payload)
                    if is_complete and len(payload) >= expected_length:
                        # Try to parse this individual packet
                        hkep_data = self.dissect_hkep_message(payload[:expected_length])
                        if hkep_data and hkep_data.get('msg_id') in self.MSG_TYPES:
                            # Set direction for Null messages based on TCP stream direction
                            # forward = server->client (Encoder->Decoder), reverse = client->server (Decoder->Encoder)
                            if hkep_data.get('message_type') == 'Null message' and 'direction' not in hkep_data:
                                hkep_data['direction'] = 'Encoder->Decoder' if direction_name == 'forward' else 'Decoder->Encoder'
                            
                            # Get exchange for this packet based on AKE_PreInit boundaries
                            session_key, exchange = find_exchange_for_packet(stream_key, pkt_num)
                            if not session_key or not exchange:
                                # No AKE_PreInit found before this message - skip
                                # Messages without AKE_PreInit are not part of an HKEP exchange
                                if verbose:
                                    print(f"    Packet #{pkt_num}: HKEP message without AKE_PreInit in stream, ignoring (not part of HKEP exchange)")
                                continue
                            
                            # If this is AKE_PreInit, ensure exchange is set up (should already be done)
                            if hkep_data.get('message_type') == 'AKE_PreInit':
                                receiver_id = hkep_data.get('receiverId')
                                node_id = hkep_data.get('nodeId')
                                port_id = hkep_data.get('portId')
                                if receiver_id and node_id and port_id:
                                    # Ensure TCP connection is registered
                                    exchange.add_tcp_connection(stream_key, src_ip, src_port, dst_ip, dst_port)
                            
                            # Check if we already processed this message from a block.
                            # A single TCP segment can carry several back-to-back HKEP
                            # messages (e.g. AKE_Init followed by AKE_Transmitter_Info),
                            # so the message type has to be part of the identity here —
                            # keying on the packet number alone silently drops all but
                            # the first message of such a segment.
                            already_processed = any(
                                msg['packet_number'] == pkt_num
                                and msg['hkep'].get('msg_id') == hkep_data.get('msg_id')
                                for msg in exchange.messages
                            )

                            if not already_processed:
                                hkep_message_count += 1
                                timestamp = float(packet.time) if hasattr(packet, 'time') else 0.0

                                message = {
                                    "packet_number": pkt_num,
                                    "hkep_packet_number": hkep_message_count,
                                    "src_ip": src_ip,
                                    "src_port": tcp_layer.sport,
                                    "dst_ip": dst_ip,
                                    "dst_port": tcp_layer.dport,
                                    "timestamp": timestamp,
                                    "stream": stream_key,
                                    "session": session_key,
                                    "direction": direction_name,
                                    "hkep": hkep_data
                                }
                                exchange.add_message(message)

                                # Add to timeline
                                timeline_events.append({
                                    'pkt_num': pkt_num,
                                    'timestamp': timestamp,
                                    'type': 'hkep_message',
                                    'result': message
                                })

                                if verbose:
                                    print(f"    Packet #{pkt_num}: extracted HKEP message")

                # Approach 2: Try to reassemble contiguous blocks for messages that span packets
                contiguous_blocks = self._find_contiguous_blocks(direction_packets)

                for block_idx, (block_data, block_packets) in enumerate(contiguous_blocks):
                    if len(block_data) < 3:
                        continue

                    if verbose and len(contiguous_blocks) > 1:
                        print(f"    Block {block_idx + 1}: {len(block_data)} bytes from {len(block_packets)} packets")

                    # Try to extract messages from this contiguous block
                    messages_from_block = self._extract_messages_from_block(
                        block_data, block_packets, stream_key, direction_name, hkep_message_count
                    )

                    for msg_result in messages_from_block:
                        # Get exchange for this packet based on AKE_PreInit boundaries
                        pkt_num = msg_result['packet_number']
                        session_key, exchange = find_exchange_for_packet(stream_key, pkt_num)
                        if not session_key or not exchange:
                            # No AKE_PreInit found before this message - skip
                            # Messages without AKE_PreInit are not part of an HKEP exchange
                            if verbose:
                                print(f"    Packet #{pkt_num}: HKEP message without AKE_PreInit in stream, ignoring (not part of HKEP exchange)")
                            continue
                        
                        hkep_data = msg_result.get("hkep", {})
                        
                        # If this is AKE_PreInit, ensure exchange is set up (should already be done)
                        if hkep_data.get('message_type') == 'AKE_PreInit':
                            receiver_id = hkep_data.get('receiverId')
                            node_id = hkep_data.get('nodeId')
                            port_id = hkep_data.get('portId')
                            if receiver_id and node_id and port_id:
                                # Ensure TCP connection is registered
                                exchange.add_tcp_connection(stream_key, src_ip, src_port, dst_ip, dst_port)
                        
                        # Check if we already processed this message from individual packet
                        # processing. Keyed on message type as well as packet number, since a
                        # single TCP segment can carry several back-to-back HKEP messages.
                        already_processed = any(
                            msg['packet_number'] == msg_result["packet_number"]
                            and msg['hkep'].get('msg_id') == hkep_data.get('msg_id')
                            for msg in exchange.messages
                        )

                        if not already_processed:
                            hkep_message_count += 1
                            message = {
                                "packet_number": msg_result["packet_number"],
                                "hkep_packet_number": hkep_message_count,
                                "src_ip": src_ip,
                                "src_port": tcp_layer.sport,
                                "dst_ip": dst_ip,
                                "dst_port": tcp_layer.dport,
                                "timestamp": msg_result["timestamp"],
                                "stream": stream_key,
                                "session": session_key,
                                "direction": direction_name,
                                "hkep": msg_result["hkep"]
                            }
                            exchange.add_message(message)

                            # Add to timeline
                            timeline_events.append({
                                'pkt_num': msg_result["packet_number"],
                                'timestamp': msg_result["timestamp"],
                                'type': 'hkep_message',
                                'result': message
                            })

        
        # Surface any stream bytes the framer could not attribute to a message.
        # Staying quiet here would let a partially-framed capture look complete
        # and turn missing messages into bogus "never sent" conclusions.
        if verbose and self._framing_skipped_bytes:
            print(f"\n[!] WARNING: this capture was not fully parsed - {self._framing_skipped_bytes} "
                  f"stream byte(s) could not be framed as HKEP messages")
            if self._framing_resyncs:
                print(f"  {self._framing_resyncs} block(s) did not start on a message boundary, so "
                      f"framing was resynchronised (capture likely started mid-stream)")
                print(f"    Resynchronised framing is best-effort: it locates a boundary that is "
                      f"consistent with the rest of the stream, which is strong evidence but not "
                      f"proof. Treat messages from those blocks with corresponding caution.")
            print(f"  Messages contained in those bytes are absent from the analysis below, so "
                  f"'not sent' conclusions may reflect the gap rather than the device.")

        # Add all exchanges to the analysis result
        for exchange in exchanges.values():
            analysis_result.add_exchange(exchange)
        
        # Check completeness of all exchanges first
        incomplete_packet_set = set()  # Track packets from incomplete exchanges
        for exchange in exchanges.values():
            is_complete, incomplete_reason = exchange.validate_completeness()
            exchange.is_complete = is_complete
            exchange.incomplete_reason = incomplete_reason
            
            # If exchange is incomplete, track all its packet numbers
            if not is_complete:
                for msg in exchange.messages:
                    pkt_num = msg.get('packet_number')
                    if pkt_num:
                        incomplete_packet_set.add(pkt_num)
        
        # Build violation map: packet_number -> list of violations
        # Process in numerical section order: 12.6, 12.7, 13.1, 13.2, 13.3
        # ONLY validate complete exchanges - incomplete exchanges are excluded
        violation_map = {}  # packet_number -> [violations]
        if hasattr(self, '_validate_12_6') and self._validate_12_6:
            for exchange in exchanges.values():
                if not exchange.is_complete:
                    continue  # Skip incomplete exchanges
                errors = self.validate_section_12_6(exchange)
                for error in errors:
                    pkt_num = error.get('packet_number')
                    if pkt_num:
                        if pkt_num not in violation_map:
                            violation_map[pkt_num] = []
                        violation_map[pkt_num].append(error)
        
        if hasattr(self, '_validate_12_7') and self._validate_12_7:
            for exchange in exchanges.values():
                if not exchange.is_complete:
                    continue  # Skip incomplete exchanges
                errors = self.validate_section_12_7(exchange)
                for error in errors:
                    pkt_num = error.get('packet_number')
                    if pkt_num:
                        if pkt_num not in violation_map:
                            violation_map[pkt_num] = []
                        violation_map[pkt_num].append(error)
        
        if hasattr(self, '_validate_13_1') and self._validate_13_1:
            for exchange in exchanges.values():
                if not exchange.is_complete:
                    continue  # Skip incomplete exchanges
                errors = self.validate_section_13_1(exchange)
                for error in errors:
                    pkt_num = error.get('packet_number')
                    if pkt_num:
                        if pkt_num not in violation_map:
                            violation_map[pkt_num] = []
                        violation_map[pkt_num].append(error)
        
        if hasattr(self, '_validate_13_2') and self._validate_13_2:
            for exchange in exchanges.values():
                if not exchange.is_complete:
                    continue  # Skip incomplete exchanges
                errors = self.validate_section_13_2(exchange)
                for error in errors:
                    pkt_num = error.get('packet_number')
                    if pkt_num:
                        if pkt_num not in violation_map:
                            violation_map[pkt_num] = []
                        violation_map[pkt_num].append(error)
        
        if hasattr(self, '_validate_13_3') and self._validate_13_3:
            for exchange in exchanges.values():
                if not exchange.is_complete:
                    continue  # Skip incomplete exchanges
                errors = self.validate_section_13_3(exchange)
                for error in errors:
                    pkt_num = error.get('packet_number')
                    if pkt_num:
                        if pkt_num not in violation_map:
                            violation_map[pkt_num] = []
                        violation_map[pkt_num].append(error)
        
        if hasattr(self, '_validate_session_caching') and self._validate_session_caching:
            # Session caching validation works across all exchanges
            errors = self.validate_session_caching(analysis_result)
            for error in errors:
                pkt_num = error.get('packet_number')
                if pkt_num:
                    if pkt_num not in violation_map:
                        violation_map[pkt_num] = []
                    violation_map[pkt_num].append(error)
        
        # Sort timeline events by packet number (chronological order)
        timeline_events.sort(key=lambda x: (x['pkt_num'], x.get('timestamp', 0)))
        
        # Print events in chronological order
        if verbose:
            for event in timeline_events:
                if event['type'] == 'tcp_syn':
                    print(f"\n{'='*80}")
                    print(f"[TCP CONNECTION START] Packet #{event['pkt_num']}")
                    print(f"  {event['src_ip']}:{event['src_port']} -> {event['dst_ip']}:{event['dst_port']}")
                    print(f"  SYN: SEQ={event['seq']}")
                    print(f"{'='*80}")
                elif event['type'] == 'tcp_syn_ack':
                    print(f"\n{'='*80}")
                    print(f"[TCP CONNECTION ESTABLISHED] Packet #{event['pkt_num']}")
                    print(f"  {event['src_ip']}:{event['src_port']} -> {event['dst_ip']}:{event['dst_port']}")
                    print(f"  SYN-ACK: SEQ={event['seq']}, ACK={event['ack']}")
                    print(f"{'='*80}")
                elif event['type'] == 'tcp_fin':
                    print(f"\n{'='*80}")
                    print(f"[TCP DISCONNECT - FIN] Packet #{event['pkt_num']}")
                    print(f"  {event['src_ip']}:{event['src_port']} -> {event['dst_ip']}:{event['dst_port']}")
                    print(f"  FIN: SEQ={event['seq']}, ACK={event.get('ack', 'N/A')}")
                    print(f"{'='*80}")
                    print(f"\n{'#'*80} << END OF HKEP EXCHANGE\n")
                elif event['type'] == 'tcp_rst':
                    print(f"\n{'='*80}")
                    print(f"[TCP DISCONNECT - RST] Packet #{event['pkt_num']}")
                    print(f"  {event['src_ip']}:{event['src_port']} -> {event['dst_ip']}:{event['dst_port']}")
                    print(f"  RST: SEQ={event['seq']}")
                    print(f"{'='*80}")
                    print(f"\n{'#'*80} << END OF HKEP EXCHANGE (ABORTED)\n")
                elif event['type'] == 'hkep_message':
                    # Skip packets from incomplete exchanges
                    pkt_num = event['result'].get('packet_number')
                    if pkt_num in incomplete_packet_set:
                        continue  # Don't show packets from incomplete exchanges
                    
                    # Get violations for this packet if any
                    violations = violation_map.get(pkt_num, [])
                    self.print_hkep_message(event['result'], violations)

        if verbose:
            print(f"\n{'='*80}")
            print(f"Summary:")
            print(f"  Total packets: {analysis_result.total_packets}")
            print(f"  Valid HKEP messages: {analysis_result.total_messages}")
            print(f"  HKEP exchanges: {analysis_result.get_exchange_count()}")
            print(f"{'='*80}")

        return analysis_result
    
    # Per-section reason string shown when a section is NOT VALIDATED because no
    # complete exchange actually exercised it (positive-evidence absent).
    SECTION_NO_EVIDENCE_REASON = {
        "12.6": "no receiver-protocol AKE_PreInit/AKE_PreInitStatus handshake observed",
        "12.7": "no non-receiver-protocol exchange (receiver=false, pairing=true) observed",
        "13.1": "no locality-check activity (AKE_*_Info / LC_Init) observed",
        "13.2": "RepeaterAuth phase not observed",
        "13.3": "no RepeaterAuth_Stream_Manage observed (Sender may have used Null)",
        "session_caching": "no RepeaterAuth_Send_Ack observed (no first-successful exchange to cache)",
    }

    @staticmethod
    def _validation_status(applicable_count: int, all_errors: List[Dict]) -> str:
        """
        Map a section's outcome to a status string for JSON/reporting:
          - 'NO_DATA' : no complete exchange exercised the section (nothing validated)
          - 'FAILED'  : at least one error-severity violation
          - 'ISSUES'  : warning-severity issues but no errors
          - 'PASSED'  : exercised with no errors/warnings (info-severity notes don't count)

        Info-severity items are informational annotations and never affect status.
        """
        if applicable_count == 0:
            return 'NO_DATA'
        if any(e.get('severity') == 'error' for e in all_errors):
            return 'FAILED'
        if any(e.get('severity') == 'warning' for e in all_errors):
            return 'ISSUES'
        return 'PASSED'

    def _exchange_message_types(self, exchange: HKEPExchange) -> set:
        """Return the set of HKEP message_type strings present in an exchange."""
        return {m.get('hkep', {}).get('message_type') for m in exchange.messages}

    def _exchange_exercises_section(self, section: str, exchange: HKEPExchange) -> bool:
        """
        Return True if this exchange actually contains the protocol activity that
        section `section` is meant to validate (its "positive evidence").

        A section may only report PASSED when at least one complete exchange exercises
        it; otherwise it reports NOT VALIDATED (NO DATA) rather than a vacuous PASS.
        Verified against VSF TR-10-5:2026. Receiver_AuthStatus (msg 18) is intentionally
        never used here (§13.2.1: the Sender shall ignore it).
        """
        msgs = exchange.messages
        types = self._exchange_message_types(exchange)

        if section == "12.6":
            # Receiver protocol: an AKE_PreInit with receiver=true plus its PreInitStatus response.
            has_receiver_preinit = any(
                m.get('hkep', {}).get('message_type') == 'AKE_PreInit'
                and m.get('hkep', {}).get('receiver') is True
                for m in msgs
            )
            return has_receiver_preinit and 'AKE_PreInitStatus' in types

        if section == "12.7":
            # Non-receiver protocol: AKE_PreInit with receiver=false and pairing=true (§12.7).
            return any(
                m.get('hkep', {}).get('message_type') == 'AKE_PreInit'
                and m.get('hkep', {}).get('receiver') is False
                and m.get('hkep', {}).get('pairing') is True
                for m in msgs
            )

        if section == "13.1":
            # Locality check (§13.1) was exercised if locality activity is present: the precompute
            # Info messages (which carry *_LOCALITY_PRECOMPUTE_SUPPORT) and/or the LC exchange.
            # Either Info message alone qualifies (a capture may not include both), as does LC_Init/
            # LC_Send_L_prime/RTT_Challenge -- locality was actually performed.
            return bool(types & {
                'AKE_Transmitter_Info', 'AKE_Receiver_Info',
                'LC_Init', 'LC_Send_L_prime', 'RTT_Challenge',
            })

        if section == "13.2":
            # Authentication with repeaters: the RepeaterAuth phase was entered.
            return bool(types & {
                'RepeaterAuth_Send_ReceiverID_List',
                'RepeaterAuth_Send_Ack',
                'RepeaterAuth_Stream_Manage',
                'RepeaterAuth_Stream_Ready',
            })

        if section == "13.3":
            return 'RepeaterAuth_Stream_Manage' in types

        # Unknown section: be conservative and treat as exercised so behavior is unchanged.
        return True

    def validate_all_exchanges(self, analysis_result: HKEPAnalysisResult, verbose: bool = True, section: str = "13.2") -> Dict:
        """
        Validate HKEP section requirements for all exchanges
        
        Args:
            analysis_result: Analysis result containing exchanges
            verbose: Print validation results
            section: Section to validate ("12.6", "12.7", "13.1", "13.2", "13.3", or "session_caching")
        
        Returns:
            Dictionary with validation results
        """
        all_errors = []
        exchange_errors = {}  # stream_key -> list of errors
        
        # First pass: check completeness of all exchanges (done ONCE for all validations)
        incomplete_exchanges = []
        for exchange in analysis_result.get_all_exchanges():
            if not hasattr(exchange, 'is_complete') or exchange.is_complete is None:
                # Completeness not yet checked - do it now
                is_complete, incomplete_reason = exchange.validate_completeness()
                exchange.is_complete = is_complete
                exchange.incomplete_reason = incomplete_reason
            
            if not exchange.is_complete:
                incomplete_exchanges.append((exchange, exchange.incomplete_reason))
        
        # Show incomplete exchanges warning (once, regardless of section)
        if verbose and incomplete_exchanges and not hasattr(self, '_incomplete_warning_shown'):
            print(f"\n{'='*80}")
            print(f"[!] INCOMPLETE EXCHANGES DETECTED")
            print(f"{'='*80}")
            print(f"\nThe following {len(incomplete_exchanges)} exchange(s) are INCOMPLETE and excluded from validation:")
            print(f"(Likely due to missing packets or incomplete capture)\n")
            for exchange, reason in incomplete_exchanges:
                print(f"  - Exchange: {exchange.session_key}")
                print(f"    Messages captured: {exchange.get_message_count()}")
                print(f"    Reason: {reason}")
                if exchange.messages:
                    first_packet = min(m.get('packet_number', 0) for m in exchange.messages)
                    last_packet = max(m.get('packet_number', 0) for m in exchange.messages)
                    print(f"    Packet range: #{first_packet} - #{last_packet}")
                print()
            self._incomplete_warning_shown = True

        # Number of complete exchanges available to validate. Used to distinguish a genuine
        # PASS (a section was actually exercised) from a vacuous one (nothing to validate).
        complete_count = sum(1 for ex in analysis_result.get_all_exchanges() if ex.is_complete)
        no_evidence_reason = self.SECTION_NO_EVIDENCE_REASON.get(section, "section not exercised")

        validate_func = None
        section_name = ""
        if section == "12.6":
            validate_func = self.validate_section_12_6
            section_name = "12.6"
        elif section == "12.7":
            validate_func = self.validate_section_12_7
            section_name = "12.7"
        elif section == "13.1":
            validate_func = self.validate_section_13_1
            section_name = "13.1"
        elif section == "13.2":
            validate_func = self.validate_section_13_2
            section_name = "13.2"
        elif section == "13.3":
            validate_func = self.validate_section_13_3
            section_name = "13.3"
        elif section == "session_caching":
            # Session caching validation works on all exchanges, not per exchange
            # Handle it separately
            all_errors = self.validate_session_caching(analysis_result)
            exchange_errors = {}
            # Group errors by session (since session_caching validates across exchanges)
            for error in all_errors:
                # For session_caching, we'll use a special key or group by packet
                session_key = f"session_caching_{error.get('packet_number', 'unknown')}"
                if session_key not in exchange_errors:
                    exchange_errors[session_key] = []
                exchange_errors[session_key].append(error)

            # Positive evidence for session caching: a session became valid, i.e. a Sender sent
            # RepeaterAuth_Send_Ack in a complete exchange (§13.2.2). Without it there is nothing
            # to validate the caching behavior against -> NOT VALIDATED rather than a vacuous PASS.
            cache_applicable = sum(
                1 for ex in analysis_result.get_all_exchanges()
                if ex.is_complete and 'RepeaterAuth_Send_Ack' in self._exchange_message_types(ex)
            )

            # Info-severity items are informational and must not affect status (see _validation_status).
            sc_blocking = [e for e in all_errors if e.get('severity') in ('error', 'warning')]

            if verbose and sc_blocking:
                print(f"\n{'='*80}")
                print(f"HKEP Session Caching Validation Results")
                print(f"{'='*80}")
                
                error_count = sum(1 for e in all_errors if e['severity'] == 'error')
                warning_count = sum(1 for e in all_errors if e['severity'] == 'warning')
                info_count = sum(1 for e in all_errors if e['severity'] == 'info')
                
                print(f"\nTotal validation issues: {len(all_errors)} ({error_count} errors, {warning_count} warnings, {info_count} info)")
                
                for session_key, errors in exchange_errors.items():
                    print(f"\n  Session: {session_key}")
                    for error in errors:
                        if error['severity'] == 'error':
                            severity_marker = "[ERROR]"
                        elif error['severity'] == 'warning':
                            severity_marker = "[WARNING]"
                        else:  # info
                            severity_marker = "[INFO]"
                        print(f"    {severity_marker} {error['description']}")
                        print(f"      Packet: #{error['packet_number']}, Timestamp: {error['timestamp']:.6f}")
                        print(f"      Expected: {error['expected']}")
                        print(f"      HKEP Section: {error['hkep_section']}")
                        if error.get('note'):
                            print(f"      Note: {error['note']}")
                
                print(f"\n{'='*80}")
            elif verbose and cache_applicable == 0:
                reason = ("No complete HKEP exchanges were available to validate."
                          if complete_count == 0
                          else f"No HKEP exchange exercised session caching "
                               f"({self.SECTION_NO_EVIDENCE_REASON['session_caching']}).")
                print(f"\n{'='*80}")
                print(f"HKEP Session Caching Validation: NOT VALIDATED (NO DATA)")
                print(f"  {reason}")
                print(f"{'='*80}")
            elif verbose:
                print(f"\n{'='*80}")
                print(f"HKEP Session Caching Validation: PASSED")
                print(f"  All session caching requirements are satisfied:")
                print(f"    - Sender session caching consistency met")
                print(f"    - Receiver session reuse patterns met")
                info_notes = [e for e in all_errors if e.get('severity') == 'info']
                if info_notes:
                    print(f"  ({len(info_notes)} informational note(s), not violations):")
                    for e in info_notes:
                        print(f"    [INFO] {e['description']}")
                print(f"{'='*80}")

            return {
                'total_errors': sum(1 for e in all_errors if e['severity'] == 'error'),
                'total_warnings': sum(1 for e in all_errors if e['severity'] == 'warning'),
                'total_issues': len(all_errors),
                'exchange_errors': exchange_errors,
                'all_errors': all_errors,
                'status': self._validation_status(cache_applicable, all_errors),
                'applicable_exchanges': cache_applicable,
                'complete_exchanges': complete_count
            }
        else:
            return {
                'total_errors': 0,
                'total_warnings': 0,
                'total_issues': 0,
                'exchange_errors': {},
                'all_errors': [],
                'status': 'NO_DATA',
                'applicable_exchanges': 0,
                'complete_exchanges': complete_count
            }

        # Validate only complete exchanges that actually exercise this section.
        # An exchange that never reaches the section's protocol activity carries no positive
        # evidence for it, so it is skipped here and the section reports NOT VALIDATED below
        # rather than a vacuous PASS. (Real violations on exercised exchanges are still raised.)
        applicable_count = 0
        for exchange in analysis_result.get_all_exchanges():
            # Skip incomplete exchanges
            if not exchange.is_complete:
                continue

            if not self._exchange_exercises_section(section, exchange):
                continue

            applicable_count += 1
            errors = validate_func(exchange)
            if errors:
                exchange_errors[exchange.session_key] = errors
                all_errors.extend(errors)

        # Only error/warning severities affect a section's status. Info-severity items are
        # informational annotations (e.g. "session becomes valid", "Null Topology") and must
        # not flip a section away from PASSED; they are still displayed below for visibility.
        blocking_errors = [e for e in all_errors if e.get('severity') in ('error', 'warning')]

        if verbose and blocking_errors:
            print(f"\n{'='*80}")
            print(f"HKEP Section {section_name} Validation Results")
            print(f"{'='*80}")
            
            error_count = sum(1 for e in all_errors if e['severity'] == 'error')
            warning_count = sum(1 for e in all_errors if e['severity'] == 'warning')
            info_count = sum(1 for e in all_errors if e['severity'] == 'info')
            
            print(f"\nTotal validation issues: {len(all_errors)} ({error_count} errors, {warning_count} warnings, {info_count} info)")
            
            for session_key, errors in exchange_errors.items():
                exchange = analysis_result.get_exchange_by_session_key(session_key)
                
                # Skip incomplete exchanges - they're already reported separately
                if exchange and not exchange.is_complete:
                    continue
                
                is_reconnect = exchange and self._is_reconnect_exchange(exchange) if exchange else False
                reconnect_note = " (RECONNECT)" if is_reconnect else ""
                tcp_info = f" [{len(exchange.tcp_connections)} TCP connection(s)]" if exchange and len(exchange.tcp_connections) > 1 else ""
                
                print(f"\n  Exchange: {session_key}{tcp_info}{reconnect_note}")
                for error in errors:
                    if error['severity'] == 'error':
                        severity_marker = "[ERROR]"
                    elif error['severity'] == 'warning':
                        severity_marker = "[WARNING]"
                    else:  # info
                        severity_marker = "[INFO]"

                    ts = error.get("timestamp")
                    ts_str = f"{ts:.6f}" if ts is not None else "N/A"

                    print(f"    {severity_marker} {error['description']}")
                    print(f"      Packet: #{error.get('packet_number','?')}, Timestamp: {ts_str}")
                    print(f"      Expected: {error['expected']}")
                    print(f"      HKEP Section: {error['hkep_section']}")
                    if error.get('note'):
                        print(f"      Note: {error['note']}")
            
            print(f"\n{'='*80}")
        elif verbose and applicable_count == 0:
            reason = ("No complete HKEP exchanges were available to validate."
                      if complete_count == 0
                      else f"No HKEP exchange exercised section {section_name} ({no_evidence_reason}).")
            print(f"\n{'='*80}")
            print(f"HKEP Section {section_name} Validation: NOT VALIDATED (NO DATA)")
            print(f"  {reason}")
            print(f"{'='*80}")
        elif verbose:
            print(f"\n{'='*80}")
            print(f"HKEP Section {section_name} Validation: PASSED")
            if section == "12.6":
                print(f"  All section 12.6 requirements are satisfied:")
                print(f"    - AKE_PreInit requirements met")
                print(f"    - AKE_PreInitStatus requirements met")
                print(f"    - Reconnect requirements met")
            elif section == "12.7":
                print(f"  All section 12.7 requirements are satisfied:")
                print(f"    - AKE_PreInit requirements met (receiver=false, pairing=true)")
                print(f"    - AKE_PreInitStatus requirements met")
                print(f"    - Only AKE_PreInit/AKE_PreInitStatus messages exchanged")
            elif section == "13.1":
                print(f"  All section 13.1 requirements are satisfied:")
                print(f"    - Locality precompute support flags met")
                print(f"    - LC_Init retry count within limits")
            elif section == "13.2":
                print(f"  All section 13.2 requirements are satisfied:")
                print(f"    - Initial message exchange requirements met")
                print(f"    - Message sequence requirements met")
            elif section == "13.3":
                print(f"  All section 13.3 requirements are satisfied:")
                print(f"    - streamCtr immutability requirements met")
                print(f"    - k attribute bounds met")
                print(f"    - Unique streamCtr count within limits")
            # Informational notes do not affect PASS status, but keep them visible.
            info_notes = sum(1 for e in all_errors if e.get('severity') == 'info')
            if info_notes:
                print(f"  ({info_notes} informational note(s), not violations):")
                for session_key, errors in exchange_errors.items():
                    sess_info = [e for e in errors if e.get('severity') == 'info']
                    if not sess_info:
                        continue
                    print(f"    Exchange: {session_key}")
                    for e in sess_info:
                        print(f"      [INFO] {e['description']}")
            print(f"{'='*80}")

        return {
            'total_errors': sum(1 for e in all_errors if e['severity'] == 'error'),
            'total_warnings': sum(1 for e in all_errors if e['severity'] == 'warning'),
            'total_issues': len(all_errors),
            'exchange_errors': exchange_errors,
            'all_errors': all_errors,
            'status': self._validation_status(applicable_count, all_errors),
            'applicable_exchanges': applicable_count,
            'complete_exchanges': complete_count
        }

    def _is_reconnect_exchange(self, exchange: HKEPExchange) -> bool:
        """
        Determine if this exchange is a reconnect scenario
        
        A reconnect is indicated by:
        - Presence of AKE_PreInit or AKE_PreInitStatus messages with restart/REAUTH_REQ=false
        - Or absence of AKE_Init at the start but presence of Stream_Ready/Send_Ack
        
        Note: If AKE_Init is present, this is NOT a reconnect - it's a full authentication.
        """
        messages = exchange.get_messages()
        if not messages:
            return False
        
        # Check for AKE_Init - if present, this is NOT a reconnect
        has_ake_init = False
        has_preinit_with_restart_false = False
        first_message_type = None
        
        for msg in messages:
            hkep_data = msg.get('hkep', {})
            msg_type = hkep_data.get('message_type')
            
            if first_message_type is None:
                first_message_type = msg_type
            
            if msg_type == "AKE_Init":
                has_ake_init = True
                # If AKE_Init is present, this is a full auth, not a reconnect
                return False
            
            if msg_type == "AKE_PreInit":
                restart_reauth = hkep_data.get('restart/REAUTH_REQ', False)
                # If restart/REAUTH_REQ is false, it's a reconnect
                if not restart_reauth:
                    has_preinit_with_restart_false = True
        
        # If PreInit with restart=false is present, it's a reconnect
        if has_preinit_with_restart_false:
            return True
        
        # If exchange doesn't start with AKE_Init but has Stream_Ready/Send_Ack, likely a reconnect
        if first_message_type not in [None, "AKE_Init"]:
            stream_ready_count = len(exchange.get_messages_by_type("RepeaterAuth_Stream_Ready"))
            send_ack_count = len(exchange.get_messages_by_type("RepeaterAuth_Send_Ack"))
            if (stream_ready_count > 0 or send_ack_count > 0) and not has_ake_init:
                return True
        
        return False
    
    def validate_section_13_2(self, exchange: HKEPExchange) -> List[Dict]:
        """
        Validate all requirements of HKEP section 13.2 (Exchange sequence - section 13.2.1)
        
        Per VSF TR-10-5:2024 section 13.2.1:
        1. Initial Message Exchange (in RepeaterAuth phase):
           - Receiver shall initially send RepeaterAuth_Send_ReceiverID_List or Null
           - Sender shall initially send RepeaterAuth_Stream_Manage or Null
        
        2. Message Sequence Requirements:
           - If Receiver receives RepeaterAuth_Stream_Manage, it shall send RepeaterAuth_Stream_Ready
           - If Receiver sends RepeaterAuth_Send_ReceiverID_List, it shall receive RepeaterAuth_Send_Ack
           - If Sender sends RepeaterAuth_Stream_Manage, it shall receive RepeaterAuth_Stream_Ready
           - If Sender receives RepeaterAuth_Send_ReceiverID_List, it shall send RepeaterAuth_Send_Ack
           - RepeaterAuth_Stream_Ready must be sent before RepeaterAuth_Send_Ack
              (per note: "When receiving the RepeaterAuth_Send_Ack message a Receiver knows
              for sure that the HKEP session on the Sender became valid because the Sender
              does not return this message before it successfully receives a
              RepeaterAuth_Stream_Ready message from the Receiver.")
        
        Note: This validation only applies to the RepeaterAuth phase messages.
        AKE/LC/SKE/RTT phase messages are not validated here.
        
        Returns:
            List of validation errors (empty if sequence is valid)
        """
        errors = []
        messages = exchange.get_messages()
        
        if not messages:
            return errors
        
        # Check if this is a reconnect exchange
        is_reconnect = self._is_reconnect_exchange(exchange)
        
        # Get first messages from each direction to check initial message requirements
        decoder_messages = exchange.get_decoder_messages()  # Decoder->Encoder (Receiver)
        encoder_messages = exchange.get_encoder_messages()  # Encoder->Decoder (Sender)
        
        # 1. Validate Initial Message Exchange
        # Section 13.2 is specifically about the RepeaterAuth phase, which comes AFTER:
        # - AKE phase (AKE_PreInit, AKE_PreInitStatus, AKE_Init, AKE_Send_Cert, etc.)
        # - LC phase (LC_Init, LC_Send_L_prime)
        # - SKE phase (SKE_Send_Eks)
        # - RTT phase (RTT_Ready, RTT_Challenge)
        # We must only validate the first RepeaterAuth message, not any AKE/LC/SKE/RTT messages
        
        # RepeaterAuth message types (section 13.2 scope)
        # Note: Null message is also a valid RepeaterAuth phase message
        repeaterauth_messages = [
            "RepeaterAuth_Send_ReceiverID_List",
            "RepeaterAuth_Send_Ack",
            "RepeaterAuth_Stream_Manage",
            "RepeaterAuth_Stream_Ready",
            "Null message"
        ]

        # Substantive RepeaterAuth messages always belong to the RepeaterAuth phase.
        substantive_repeaterauth_messages = {
            "RepeaterAuth_Send_ReceiverID_List",
            "RepeaterAuth_Send_Ack",
            "RepeaterAuth_Stream_Manage",
            "RepeaterAuth_Stream_Ready",
        }

        # Pre-RepeaterAuth handshake message types (AKE/LC/SKE/RTT phases). These always
        # precede the RepeaterAuth phase within an exchange. Note: Receiver_AuthStatus and
        # Null are intentionally excluded here - Receiver_AuthStatus is a post-auth status
        # message (it can appear after the RepeaterAuth exchange) and Null is phase-agnostic,
        # so neither marks the pre-RepeaterAuth boundary.
        pre_repeaterauth_handshake_messages = {
            "AKE_PreInit", "AKE_PreInitStatus",
            "AKE_Init", "AKE_Send_Cert", "AKE_No_Stored_km", "AKE_Stored_km",
            "AKE_Send_rrx", "AKE_Send_H_prime", "AKE_Send_Pairing_Info",
            "AKE_Transmitter_Info", "AKE_Receiver_Info",
            "LC_Init", "LC_Send_L_prime",
            "SKE_Send_Eks",
            "RTT_Ready", "RTT_Challenge",
        }

        # A "Null message" is a phase-agnostic keep-alive: it can legitimately appear in
        # any phase (AKE/LC/SKE/RTT) as well as being a valid RepeaterAuth-phase opener
        # (e.g. a reconnect may start with Null). Therefore a Null only counts as a
        # RepeaterAuth message when it occurs AFTER the last pre-RepeaterAuth handshake
        # message. This prevents a keep-alive Null interleaved in the AKE phase from being
        # mistaken for the sender/receiver's initial RepeaterAuth message.
        pre_ra_timestamps = [
            m.get('timestamp', 0) for m in messages
            if m.get('hkep', {}).get('message_type') in pre_repeaterauth_handshake_messages
        ]
        last_pre_ra_timestamp = max(pre_ra_timestamps) if pre_ra_timestamps else None

        def is_repeaterauth_phase_msg(msg):
            msg_type = msg.get('hkep', {}).get('message_type')
            if msg_type in substantive_repeaterauth_messages:
                return True
            if msg_type == "Null message":
                return (last_pre_ra_timestamp is None
                        or msg.get('timestamp', 0) > last_pre_ra_timestamp)
            return False

        if decoder_messages:
            sorted_decoder_msgs = sorted(decoder_messages, key=lambda x: x.get('timestamp', 0))
            
            # Find first RepeaterAuth message (skip all AKE/LC/SKE/RTT messages)
            first_repeaterauth_decoder_msg = None
            for msg in sorted_decoder_msgs:
                if is_repeaterauth_phase_msg(msg):
                    first_repeaterauth_decoder_msg = msg
                    break
            
            # Only validate if there's a RepeaterAuth message
            if first_repeaterauth_decoder_msg:
                first_decoder_type = first_repeaterauth_decoder_msg.get('hkep', {}).get('message_type')
                
                # Receiver's initial RepeaterAuth message should be RepeaterAuth_Send_ReceiverID_List or Null
                if first_decoder_type not in ["RepeaterAuth_Send_ReceiverID_List", "Null message"]:
                    # Allow other messages if this is a reconnect
                    if not is_reconnect:
                        errors.append({
                            'type': 'invalid_initial_receiver_message',
                            'severity': 'error',
                            'description': f"Receiver's initial RepeaterAuth message is '{first_decoder_type}' (packet #{first_repeaterauth_decoder_msg.get('packet_number')}), expected RepeaterAuth_Send_ReceiverID_List or Null",
                            'packet_number': first_repeaterauth_decoder_msg.get('packet_number'),
                            'timestamp': first_repeaterauth_decoder_msg.get('timestamp', 0),
                            'expected': 'Receiver must send RepeaterAuth_Send_ReceiverID_List or Null message first in RepeaterAuth phase',
                            'hkep_section': '13.2'
                        })
        
        if encoder_messages:
            sorted_encoder_msgs = sorted(encoder_messages, key=lambda x: x.get('timestamp', 0))
            
            # Find first RepeaterAuth message (skip all AKE/LC/SKE/RTT messages)
            first_repeaterauth_encoder_msg = None
            for msg in sorted_encoder_msgs:
                if is_repeaterauth_phase_msg(msg):
                    first_repeaterauth_encoder_msg = msg
                    break
            
            # Only validate if there's a RepeaterAuth message
            if first_repeaterauth_encoder_msg:
                first_encoder_type = first_repeaterauth_encoder_msg.get('hkep', {}).get('message_type')
                
                # Sender's initial RepeaterAuth message should be RepeaterAuth_Stream_Manage or Null
                if first_encoder_type not in ["RepeaterAuth_Stream_Manage", "Null message"]:
                    # Allow other messages if this is a reconnect
                    if not is_reconnect:
                        errors.append({
                            'type': 'invalid_initial_sender_message',
                            'severity': 'error',
                            'description': f"Sender's initial RepeaterAuth message is '{first_encoder_type}' (packet #{first_repeaterauth_encoder_msg.get('packet_number')}), expected RepeaterAuth_Stream_Manage or Null",
                            'packet_number': first_repeaterauth_encoder_msg.get('packet_number'),
                            'timestamp': first_repeaterauth_encoder_msg.get('timestamp', 0),
                            'expected': 'Sender must send RepeaterAuth_Stream_Manage or Null message first in RepeaterAuth phase',
                            'hkep_section': '13.2'
                        })
        
        # 2. Validate Message Sequence Requirements per section 13.2.1
        # Per spec:
        # - Receiver shall send RepeaterAuth_Stream_Ready if it initially received RepeaterAuth_Stream_Manage
        # - Receiver shall attempt to receive RepeaterAuth_Send_Ack if it initially sent RepeaterAuth_Send_ReceiverID_List
        # - Sender shall attempt to receive RepeaterAuth_Stream_Ready if it sent initial RepeaterAuth_Stream_Manage
        # - Sender shall send RepeaterAuth_Send_Ack if it initially received RepeaterAuth_Send_ReceiverID_List
        # - RepeaterAuth_Stream_Ready must be sent before RepeaterAuth_Send_Ack
        #   (Sender does not return Send_Ack before it successfully receives Stream_Ready)
        
        # Track initial messages sent/received
        receiver_initial_sent = None  # What Receiver initially sent
        sender_initial_sent = None   # What Sender initially sent
        receiver_initial_received = None  # What Receiver initially received
        sender_initial_received = None    # What Sender initially received
        sender_ack_sent = None
        receiver_ready_sent = None
        receiver_status_sent = None
        
        # Find initial RepeaterAuth messages
        for msg in sorted(messages, key=lambda x: x.get('timestamp', 0)):
            hkep_data = msg.get('hkep', {})
            msg_type = hkep_data.get('message_type')
            direction = hkep_data.get('direction', '')

            if not is_repeaterauth_phase_msg(msg):
                continue
            
            if direction == "Decoder->Encoder":  # Receiver
                if receiver_initial_sent is None:
                    receiver_initial_sent = msg
                if receiver_ready_sent is None and msg_type == "RepeaterAuth_Stream_Ready":
                    receiver_ready_sent = msg
                if receiver_status_sent is None and msg_type == "Receiver_AuthStatus":
                    receiver_status_sent = msg

            elif direction == "Encoder->Decoder":  # Sender
                if sender_initial_sent is None:
                    sender_initial_sent = msg
                if sender_ack_sent is None and msg_type == "RepeaterAuth_Send_Ack":
                    sender_ack_sent = msg

        # Find what each party initially received (first message from peer)
        receiver_initial_received = sender_initial_sent
        sender_initial_received = receiver_initial_sent

        if receiver_initial_sent is None  or sender_initial_sent is None or receiver_initial_received is None or sender_initial_received is None:
            errors.append({
                'type': 'invalid_sequence',
                'severity': 'error',
                'description': 'Initial RepeaterAuth messages not found',
                'packet_number': None,
                'timestamp': None,
                'expected': 'Initial RepeaterAuth messages must be found',
                'hkep_section': '13.2.1'
            })
            return errors

        # Track sequence state from the Sender point of view
        if sender_initial_sent.get('hkep', {}).get('message_type') == "Null message":
            if sender_initial_received.get('hkep', {}).get('message_type') == "Null message":
                if sender_ack_sent is not None:

                    errors.append({
                        'type': 'invalid_sequence',
                        'severity': 'error',
                        'description': f"RepeaterAuth_Send_Ack (packet #{sender_ack_sent.get('packet_number')}) sent without receiving RepeaterAuth_Send_ReceiverID_List.",
                        'packet_number': sender_ack_sent.get('packet_number'),
                        'timestamp':  sender_ack_sent.get('timestamp', 0),
                        'expected': 'RepeaterAuth_Send_Ack must be sent only for a RepeaterAuth_Send_ReceiverID_List (per section 13.2.1 note)',
                        'hkep_section': '13.2.1'
                    })
                else:
                    pass  # ok
            else:

                if sender_ack_sent is None:

                    errors.append({
                        'type': 'invalid_sequence',
                        'severity': 'error',
                        'description': f"RepeaterAuth_Send_ReceiverID_List (packet #{sender_initial_received.get('packet_number')}) received without sending RepeaterAuth_Send_Ack.",
                        'packet_number': sender_initial_received.get('packet_number'),
                        'timestamp': sender_initial_received.get('timestamp', 0),
                        'expected': 'RepeaterAuth_Send_Ack must be sent for a RepeaterAuth_Send_ReceiverID_List (per section 13.2.1 note)',
                        'hkep_section': '13.2.1'
                    })

                else:

                    if sender_ack_sent.get('timestamp', 0) < sender_initial_received.get('timestamp', 0):
                        errors.append({
                            'type': 'invalid_sequence',
                            'severity': 'error',
                            'description': f"RepeaterAuth_Send_Ack (packet #{sender_ack_sent.get('packet_number')}) sent before receiving RepeaterAuth_Send_ReceiverID_List (packet #{sender_initial_received.get('packet_number')}).",
                            'packet_number': sender_ack_sent.get('packet_number'),
                            'timestamp': sender_ack_sent.get('timestamp'),
                            'expected': 'RepeaterAuth_Send_Ack must be sent after receiving RepeaterAuth_Send_ReceiverID_List (per section 13.2.1 note)',
                            'hkep_section': '13.2.1'
                        })

        else:
            if sender_initial_received.get('hkep', {}).get('message_type') == "Null message":
                if sender_ack_sent is not None:

                    errors.append({
                        'type': 'invalid_sequence',
                        'severity': 'error',
                        'description': f"RepeaterAuth_Send_Ack (packet #{sender_ack_sent.get('packet_number')}) sent without receiving RepeaterAuth_Send_ReceiverID_List.",
                        'packet_number': sender_ack_sent.get('packet_number'),
                        'timestamp':  sender_ack_sent.get('timestamp', 0),
                        'expected': 'RepeaterAuth_Send_Ack must be sent only for a RepeaterAuth_Send_ReceiverID_List (per section 13.2.1 note)',
                        'hkep_section': '13.2.1'
                    })
                else:
                    pass  # ok
            else:

                if sender_ack_sent is None:

                    errors.append({
                        'type': 'invalid_sequence',
                        'severity': 'error',
                        'description': f"RepeaterAuth_Send_ReceiverID_List (packet #{sender_initial_received.get('packet_number')}) received without sending RepeaterAuth_Send_Ack.",
                        'packet_number': sender_initial_received.get('packet_number'),
                        'timestamp': sender_initial_received.get('timestamp', 0),
                        'expected': 'RepeaterAuth_Send_Ack must be sent for a RepeaterAuth_Send_ReceiverID_List (per section 13.2.1 note)',
                        'hkep_section': '13.2.1'
                    })

                else:

                    if receiver_ready_sent is not None and sender_ack_sent.get('timestamp', 0) < receiver_ready_sent.get('timestamp', 0):

                        errors.append({
                            'type': 'invalid_sequence',
                            'severity': 'error',
                            'description': f"RepeaterAuth_Send_Ack (packet #{sender_ack_sent.get('packet_number')}) sent before receiving RepeaterAuth_Stream_Ready (packet #{receiver_ready_sent.get('packet_number')}).",
                            'packet_number': sender_ack_sent.get('packet_number'),
                            'timestamp': sender_ack_sent.get('timestamp'),
                            'expected': 'RepeaterAuth_Send_Ack must be sent after receiving RepeaterAuth_Stream_Ready (per section 13.2.1 note)',
                            'hkep_section': '13.2.1'
                        })

        # Track sequence state from the Receiver point of view
        if receiver_initial_sent.get('hkep', {}).get('message_type') == "Null message":
            if receiver_initial_received.get('hkep', {}).get('message_type') == "Null message":
                if receiver_ready_sent is not None:

                    errors.append({
                        'type': 'invalid_sequence',
                        'severity': 'error',
                        'description': f"RepeaterAuth_Stream_Ready (packet #{receiver_ready_sent.get('packet_number')}) sent without receiving RepeaterAuth_Stream_Manage.",
                        'packet_number': receiver_ready_sent.get('packet_number'),
                        'timestamp':  receiver_ready_sent.get('timestamp', 0),
                        'expected': 'RepeaterAuth_Stream_Ready must be sent only for a RepeaterAuth_Stream_Manage (per section 13.2.1 note)',
                        'hkep_section': '13.2.1'
                    })
                else:
                    pass  # ok
            else:

                if receiver_ready_sent is None:

                    errors.append({
                        'type': 'invalid_sequence',
                        'severity': 'error',
                        'description': f"RepeaterAuth_Stream_Manage (packet #{receiver_initial_received.get('packet_number')}) received without sending RepeaterAuth_Stream_Ready.",
                        'packet_number': receiver_initial_received.get('packet_number'),
                        'timestamp': receiver_initial_received.get('timestamp', 0),
                        'expected': 'RepeaterAuth_Stream_Ready must be sent in response to RepeaterAuth_Stream_Manage (per section 13.2.1 note)',
                        'hkep_section': '13.2.1'
                    })

                else:

                    if receiver_ready_sent.get('timestamp', 0) < receiver_initial_received.get('timestamp', 0):
                        errors.append({
                            'type': 'invalid_sequence',
                            'severity': 'error',
                            'description': f"RepeaterAuth_Stream_Ready (packet #{receiver_ready_sent.get('packet_number')}) sent before receiving RepeaterAuth_Stream_Manage (packet #{receiver_initial_received.get('packet_number')}).",
                            'packet_number': receiver_ready_sent.get('packet_number'),
                            'timestamp': receiver_ready_sent.get('timestamp'),
                            'expected': 'RepeaterAuth_Stream_Ready must be sent after receiving RepeaterAuth_Stream_Manage (per section 13.2.1 note)',
                            'hkep_section': '13.2.1'
                        })

        else:
            if receiver_initial_received.get('hkep', {}).get('message_type') == "Null message":
                if receiver_ready_sent is not None:

                    errors.append({
                        'type': 'invalid_sequence',
                        'severity': 'error',
                        'description': f"RepeaterAuth_Stream_Ready (packet #{receiver_ready_sent.get('packet_number')}) sent without receiving RepeaterAuth_Stream_Manage.",
                        'packet_number': receiver_ready_sent.get('packet_number'),
                        'timestamp':  receiver_ready_sent.get('timestamp', 0),
                        'expected': 'RepeaterAuth_Stream_Ready must be sent only for a RepeaterAuth_Stream_Manage (per section 13.2.1 note)',
                        'hkep_section': '13.2.1'
                    })
                else:
                    pass  # ok
            else:

                if receiver_ready_sent is None:

                    errors.append({
                        'type': 'invalid_sequence',
                        'severity': 'error',
                        'description': f"RepeaterAuth_Stream_Manage (packet #{receiver_initial_received.get('packet_number')}) received without sending RepeaterAuth_Stream_Ready.",
                        'packet_number': receiver_initial_received.get('packet_number'),
                        'timestamp': receiver_initial_received.get('timestamp', 0),
                        'expected': 'RepeaterAuth_Stream_Ready must be sent in response to RepeaterAuth_Stream_Manage (per section 13.2.1 note)',
                        'hkep_section': '13.2.1'
                    })

        # 13.2.1: Receiver_AuthStatus Message Restrictions
        # Per spec: "A Receiver should send a Receiver_AuthStatus message as required by the HDCP RTP v2.3 
        # specification but a Sender shall not use it to establish the validity of an HKEP or HDCP RTP v2.3 session. 
        # A Sender shall ignore the message if it receives it, as allowed by the HDCP RTP v2.3 specification...
        # A Receiver shall not send a Receiver_AuthStatus message with REAUTH_REQ set false."
        receiver_authstatus_messages = [msg for msg in sorted(messages, key=lambda x: x.get('timestamp', 0))
                                        if msg.get('hkep', {}).get('message_type') == 'Receiver_AuthStatus']
        
        for authstatus_msg in receiver_authstatus_messages:
            hkep_data = authstatus_msg.get('hkep', {})
            reauth_req = hkep_data.get('REAUTH_REQ')
            
            # Validate: Receiver shall not send Receiver_AuthStatus with REAUTH_REQ=false
            if reauth_req is False:
                errors.append({
                    'type': 'invalid_receiver_authstatus_reauth_req',
                    'severity': 'error',
                    'description': f"Receiver_AuthStatus (packet #{authstatus_msg.get('packet_number')}) has REAUTH_REQ set to false. Receiver shall not send Receiver_AuthStatus with REAUTH_REQ=false.",
                    'packet_number': authstatus_msg.get('packet_number'),
                    'timestamp': authstatus_msg.get('timestamp', 0),
                    'expected': 'Receiver shall not send Receiver_AuthStatus message with REAUTH_REQ set false (per section 13.2.1)',
                    'hkep_section': '13.2.1',
                    'note': 'Receiver communicates REAUTH_REQ state to Sender through AKE_PreInit message using restart/REAUTH_REQ flag, not through Receiver_AuthStatus'
                })
            
            # Note: We could also check if connection closes after Receiver_AuthStatus with REAUTH_REQ=true
            # Per spec: "A Receiver shall close the TCP/IP connection either instead of, or after sending 
            # a Receiver_AuthStatus message with REAUTH_REQ set to true"
            # But this is difficult to validate reliably from PCAP without TCP state tracking
        
        # 13.2.4: Null Topology Detection
        # Per spec: "A Receiver unsubscribing from the HDCP Content of a Sender may choose to make its HKEP 
        # session inactive at the Sender by sending an RepeaterAuth_Send_ReceiverID_List message with the 
        # DEVICE_COUNT and DEPTH attributes set to 0 (Null Topology)"
        receiverid_list_messages = [msg for msg in sorted(messages, key=lambda x: x.get('timestamp', 0))
                                    if msg.get('hkep', {}).get('message_type') == 'RepeaterAuth_Send_ReceiverID_List']
        
        null_topology_detected = False
        null_topology_packet = None
        
        for receiverid_msg in receiverid_list_messages:
            hkep_data = receiverid_msg.get('hkep', {})
            device_count = hkep_data.get('DEVICE_COUNT', -1)
            depth = hkep_data.get('DEPTH', -1)
            
            # Detect Null Topology: DEVICE_COUNT=0 and DEPTH=0
            if device_count == 0 and depth == 0:
                null_topology_detected = True
                null_topology_packet = receiverid_msg.get('packet_number')
                
                # Informational: Log that Null Topology was sent (session becoming inactive)
                # This is not an error, but important for session lifecycle tracking
                errors.append({
                    'type': 'null_topology_detected',
                    'severity': 'info',
                    'description': f"RepeaterAuth_Send_ReceiverID_List (packet #{receiverid_msg.get('packet_number')}) contains Null Topology (DEVICE_COUNT=0, DEPTH=0). Receiver is requesting to make its HKEP session inactive (unsubscribing); inactivation is confirmed when the Receiver receives the RepeaterAuth_Send_Ack.",
                    'packet_number': receiverid_msg.get('packet_number'),
                    'timestamp': receiverid_msg.get('timestamp', 0),
                    'expected': 'Null Topology indicates Receiver is unsubscribing from HDCP Content; the Receiver must receive the RepeaterAuth_Send_Ack before treating its session inactive (per sections 13.2.1 and 13.2.4)',
                    'hkep_section': '13.2.4',
                    'note': 'Informational - inactivation is requested here and becomes effective once the Sender acknowledges it with RepeaterAuth_Send_Ack. Receiver will no longer be part of the topology tree.'
                })
                
                # Check if Sender acknowledges the Null Topology with Send_Ack (session becomes INACTIVE)
                null_topology_timestamp = receiverid_msg.get('timestamp', 0)
                send_ack_after_null = next((m for m in sorted(messages, key=lambda x: x.get('timestamp', 0))
                                           if m.get('hkep', {}).get('message_type') == 'RepeaterAuth_Send_Ack' and
                                              m.get('hkep', {}).get('direction') == 'Encoder->Decoder' and
                                              m.get('timestamp', 0) > null_topology_timestamp), None)
                
                if send_ack_after_null:
                    errors.append({
                        'type': 'session_becomes_inactive',
                        'severity': 'info',
                        'description': f"HKEP session becomes INACTIVE at packet #{send_ack_after_null.get('packet_number')} (timestamp {send_ack_after_null.get('timestamp', 0):.6f}). Sender acknowledges Null Topology with RepeaterAuth_Send_Ack. Receiver is no longer in topology tree.",
                        'packet_number': send_ack_after_null.get('packet_number'),
                        'timestamp': send_ack_after_null.get('timestamp', 0),
                        'expected': 'When Sender sends RepeaterAuth_Send_Ack after receiving Null Topology, it acknowledges that HKEP session is becoming inactive (per section 13.2.4)',
                        'hkep_section': '13.2.4',
                        'note': 'This Send_Ack acknowledges Null Topology - session is now INACTIVE, not valid'
                    })
        
        # If Null Topology was detected, check if subsequent messages inappropriately send non-zero topology
        # without full re-authentication (new AKE_PreInit with restart/REAUTH_REQ=true)
        if null_topology_detected:
            # Find messages after Null Topology
            null_topology_msg_time = next((m.get('timestamp', 0) for m in receiverid_list_messages 
                                          if m.get('packet_number') == null_topology_packet), 0)
            
            messages_after_null = [m for m in sorted(messages, key=lambda x: x.get('timestamp', 0))
                                   if m.get('timestamp', 0) > null_topology_msg_time]
            
            # Check if there's a non-null topology sent without proper re-authentication
            for msg in messages_after_null:
                hkep_data = msg.get('hkep', {})
                msg_type = hkep_data.get('message_type')
                
                # Check for non-Null topology after Null Topology
                if msg_type == 'RepeaterAuth_Send_ReceiverID_List':
                    device_count = hkep_data.get('DEVICE_COUNT', -1)
                    depth = hkep_data.get('DEPTH', -1)
                    
                    # Non-zero topology after Null Topology
                    if device_count > 0 or depth > 0:
                        # Check if there was an AKE_PreInit with restart=true between null and this message
                        ake_preinit_between = any(
                            m.get('hkep', {}).get('message_type') == 'AKE_PreInit' and
                            m.get('hkep', {}).get('restart/REAUTH_REQ') is True and
                            null_topology_msg_time < m.get('timestamp', 0) < msg.get('timestamp', 0)
                            for m in messages
                        )
                        
                        if not ake_preinit_between:
                            errors.append({
                                'type': 'topology_after_null_without_reauth',
                                'severity': 'warning',
                                'description': f"RepeaterAuth_Send_ReceiverID_List (packet #{msg.get('packet_number')}) contains non-zero topology (DEVICE_COUNT={device_count}, DEPTH={depth}) after Null Topology (packet #{null_topology_packet}) without full re-authentication. Session was marked inactive.",
                                'packet_number': msg.get('packet_number'),
                                'timestamp': msg.get('timestamp', 0),
                                'expected': 'After sending Null Topology (session inactive), Receiver should perform full re-authentication with AKE_PreInit restart/REAUTH_REQ=true before sending non-zero topology (per section 13.2.4)',
                                'hkep_section': '13.2.4',
                                'note': 'Receiver may be attempting to reactivate session after making it inactive'
                            })
        
        # 13.2.2: Session Validity Timing
        # Per VSF TR-10-5:2026 section 13.2.2, an HKEP session becomes valid only after a FIRST
        # successful exchange, marked by the RepeaterAuth_Send_Ack message -- when the Sender sends
        # it and when the Receiver receives it. A subsequent (reconnect) exchange presupposes an
        # already-valid session (section 13.2.3), so it does not (re)establish validity.

        # Find when session becomes valid
        session_valid_timestamp = None
        session_valid_packet = None
        session_valid_reason = None

        # Track Send_Ack packets that respond to Null Topology (these make session INACTIVE, not valid)
        null_topology_ack_packets = set()

        sorted_msgs = sorted(messages, key=lambda x: x.get('timestamp', 0))

        # Check for RepeaterAuth_Send_Ack (session becomes valid for both)
        # IMPORTANT: Send_Ack after Null Topology does NOT make session valid - it acknowledges session becoming INACTIVE
        # STEP 1: First pass - identify ALL null topology acks before setting session validity
        send_ack_messages = [m for m in sorted_msgs 
                             if m.get('hkep', {}).get('message_type') == 'RepeaterAuth_Send_Ack' and
                                m.get('hkep', {}).get('direction') == 'Encoder->Decoder']
        
        # First pass: Identify all null topology acknowledgments
        for send_ack_msg in send_ack_messages:
            send_ack_timestamp = send_ack_msg.get('timestamp', 0)
            send_ack_packet = send_ack_msg.get('packet_number')
            
            # Look for the ReceiverID_List that this Send_Ack is responding to
            # Send_Ack responds to ReceiverID_List, not to other RepeaterAuth messages
            receiverid_list_before_ack = [m for m in sorted_msgs 
                                          if m.get('hkep', {}).get('message_type') == 'RepeaterAuth_Send_ReceiverID_List' and
                                             m.get('timestamp', 0) < send_ack_timestamp]
            
            if receiverid_list_before_ack:
                # Get the most recent ReceiverID_List before this Send_Ack
                last_receiverid_list = max(receiverid_list_before_ack, key=lambda x: x.get('timestamp', 0))
                last_msg_packet = last_receiverid_list.get('packet_number')
                device_count = last_receiverid_list.get('hkep', {}).get('DEVICE_COUNT', -1)
                depth = last_receiverid_list.get('hkep', {}).get('DEPTH', -1)
                
                # Check if it's Null Topology
                if device_count == 0 and depth == 0:
                    # This is a null topology ack - track it so we don't report it as "session becomes valid"
                    null_topology_ack_packets.add(send_ack_packet)
                    # Note: The "session becomes INACTIVE" message is already generated earlier in the function
                    # (around line 2520) so we don't duplicate it here
        
        # Second pass: Find the most recent non-null-topology Send_Ack for session validity
        for send_ack_msg in send_ack_messages:
            send_ack_timestamp = send_ack_msg.get('timestamp', 0)
            send_ack_packet = send_ack_msg.get('packet_number')
            
            # Skip if this is a null topology ack
            if send_ack_packet in null_topology_ack_packets:
                continue
            
            # Skip if we already have a more recent session validity timestamp
            if session_valid_timestamp and send_ack_timestamp <= session_valid_timestamp:
                continue
            
            # A session becomes valid only at the Send_Ack of a FIRST (non-subsequent) exchange,
            # when the Sender sends it and the Receiver receives it (section 13.2.2). Subsequent
            # (reconnect) exchanges presuppose an already-valid session, so they do not re-establish it.
            if not is_reconnect and send_ack_packet not in null_topology_ack_packets:
                session_valid_timestamp = send_ack_timestamp
                session_valid_packet = send_ack_packet
                session_valid_reason = "RepeaterAuth_Send_Ack (sent by Sender / received by Receiver) - first successful exchange (per section 13.2.2)"

        # Log session validity information
        # BUT: Skip if:
        # 1. session_valid_packet is actually a Null Topology ack (session becoming INACTIVE, not valid)
        # 2. There are any null topology acks at or after the session valid timestamp (those would make session inactive instead)
        skip_session_valid_message = False
        
        if session_valid_timestamp and session_valid_packet:
            # Check if the specific packet is a null topology ack
            if session_valid_packet in null_topology_ack_packets:
                skip_session_valid_message = True
            
            # Check if there are any null topology acks at or after this timestamp that would override it
            for msg in sorted_msgs:
                if (msg.get('packet_number') in null_topology_ack_packets and
                    msg.get('timestamp', 0) >= session_valid_timestamp):
                    skip_session_valid_message = True
                    break
        else:
            skip_session_valid_message = True
        
        # FINAL CHECK: Absolutely do NOT output "session becomes valid" if this packet is a null topology ack
        # Make absolutely sure session_valid_packet is set and is NOT a null topology ack
        if (not skip_session_valid_message and 
            session_valid_packet is not None and 
            session_valid_packet not in null_topology_ack_packets):
            
            errors.append({
                'type': 'session_validity_established',
                'severity': 'info',
                'description': f"HKEP session becomes valid at packet #{session_valid_packet} (timestamp {session_valid_timestamp:.6f}). Reason: {session_valid_reason}",
                'packet_number': session_valid_packet,
                'timestamp': session_valid_timestamp,
                'expected': 'HKEP session becomes valid at the instant the HDCP RTP v2.3 session becomes valid (per section 13.2.2)',
                'hkep_section': '13.2.2',
                'note': session_valid_reason
            })
            
            # Validate: Messages sent before session is valid should not include encrypted content
            # This is implicit - we're just logging when session becomes valid for reference
            # Future enhancement could check if any RTP packets are sent before this point
        
        # 13.2.3: Subsequent Exchange Sequence Validation
        # Per TR-10-5 section 13.2.3, a subsequent exchange consists of one or more of these sequences:
        # 1. Receiver sends ReceiverID_List → Sender responds with Send_Ack
        # 2. Receiver sends Null → Sender responds with Null
        # 3. Sender sends Stream_Manage → Receiver responds with Stream_Ready
        # 4. Sender sends Null → Receiver responds with Null
        #
        # Multiple sequences can occur concurrently in the same exchange
        # Each request MUST have its corresponding response
        
        # Only validate if this is a reconnect (subsequent exchange after initial authentication)
        if is_reconnect:
            # Collect all RepeaterAuth messages in chronological order
            repeaterauth_msgs_ordered = sorted(
                [m for m in messages if m.get('hkep', {}).get('message_type') in repeaterauth_messages],
                key=lambda x: x.get('timestamp', 0)
            )
            
            # Track pending requests that need responses
            # Format: {message_type: (packet_number, timestamp)}
            pending_sender_stream_manage = None
            pending_receiver_receiverid_list = None
            pending_sender_null = None
            pending_receiver_null = None
            
            for msg in repeaterauth_msgs_ordered:
                msg_type = msg.get('hkep', {}).get('message_type')
                msg_dir = msg.get('hkep', {}).get('direction', '')
                msg_pkt = msg.get('packet_number')
                msg_ts = msg.get('timestamp', 0)
                
                # Sender messages (Encoder->Decoder)
                if msg_dir == 'Encoder->Decoder':
                    if msg_type == 'RepeaterAuth_Stream_Manage':
                        # Sender sends Stream_Manage - expects Stream_Ready from Receiver
                        if pending_sender_stream_manage:
                            errors.append({
                                'type': 'stream_manage_without_response',
                                'severity': 'error',
                                'description': f"Sender sent Stream_Manage (packet #{pending_sender_stream_manage[0]}) but sent another Stream_Manage (packet #{msg_pkt}) before receiving Stream_Ready response.",
                                'packet_number': msg_pkt,
                                'timestamp': msg_ts,
                                'expected': 'Sender shall wait for Stream_Ready response before sending another Stream_Manage (per section 13.2.3)',
                                'hkep_section': '13.2.3',
                                'note': f'Previous Stream_Manage at packet #{pending_sender_stream_manage[0]} not yet responded'
                            })
                        pending_sender_stream_manage = (msg_pkt, msg_ts)
                    
                    elif msg_type == 'RepeaterAuth_Send_Ack':
                        # Sender sends Send_Ack - this is response to Receiver's ReceiverID_List
                        if not pending_receiver_receiverid_list:
                            errors.append({
                                'type': 'send_ack_without_receiverid_list',
                                'severity': 'error',
                                'description': f"Sender sent Send_Ack (packet #{msg_pkt}) without prior ReceiverID_List from Receiver.",
                                'packet_number': msg_pkt,
                                'timestamp': msg_ts,
                                'expected': 'Send_Ack shall be sent in response to ReceiverID_List (per section 13.2.3)',
                                'hkep_section': '13.2.3',
                                'note': 'No pending ReceiverID_List found'
                            })
                        else:
                            # Valid response - clear pending request
                            pending_receiver_receiverid_list = None
                    
                    elif msg_type == 'Null message':
                        # Sender sends Null - may be independent or response to Receiver Null
                        if pending_receiver_null:
                            # This is response to Receiver's Null
                            pending_receiver_null = None
                        else:
                            # This is independent Sender Null - expects Receiver Null response
                            pending_sender_null = (msg_pkt, msg_ts)
                    
                    else:
                        # Invalid message type in subsequent exchange
                        errors.append({
                            'type': 'invalid_sender_message_subsequent_exchange',
                            'severity': 'error',
                            'description': f"Sender sent invalid message '{msg_type}' (packet #{msg_pkt}) in subsequent exchange. Valid: Null, Stream_Manage, Send_Ack.",
                            'packet_number': msg_pkt,
                            'timestamp': msg_ts,
                            'expected': 'In subsequent exchange, Sender may send: Null, Stream_Manage, or Send_Ack (per section 13.2.3)',
                            'hkep_section': '13.2.3',
                            'note': f'Invalid message type: {msg_type}'
                        })
                
                # Receiver messages (Decoder->Encoder)
                elif msg_dir == 'Decoder->Encoder':
                    if msg_type == 'RepeaterAuth_Send_ReceiverID_List':
                        # Receiver sends ReceiverID_List - expects Send_Ack from Sender
                        if pending_receiver_receiverid_list:
                            errors.append({
                                'type': 'receiverid_list_without_response',
                                'severity': 'error',
                                'description': f"Receiver sent ReceiverID_List (packet #{pending_receiver_receiverid_list[0]}) but sent another ReceiverID_List (packet #{msg_pkt}) before receiving Send_Ack response.",
                                'packet_number': msg_pkt,
                                'timestamp': msg_ts,
                                'expected': 'Receiver shall wait for Send_Ack response before sending another ReceiverID_List (per section 13.2.3)',
                                'hkep_section': '13.2.3',
                                'note': f'Previous ReceiverID_List at packet #{pending_receiver_receiverid_list[0]} not yet responded'
                            })
                        pending_receiver_receiverid_list = (msg_pkt, msg_ts)
                    
                    elif msg_type == 'RepeaterAuth_Stream_Ready':
                        # Receiver sends Stream_Ready - this is response to Sender's Stream_Manage
                        if not pending_sender_stream_manage:
                            errors.append({
                                'type': 'stream_ready_without_stream_manage',
                                'severity': 'error',
                                'description': f"Receiver sent Stream_Ready (packet #{msg_pkt}) without prior Stream_Manage from Sender.",
                                'packet_number': msg_pkt,
                                'timestamp': msg_ts,
                                'expected': 'Stream_Ready shall be sent in response to Stream_Manage (per section 13.2.3)',
                                'hkep_section': '13.2.3',
                                'note': 'No pending Stream_Manage found'
                            })
                        else:
                            # Valid response - clear pending request
                            pending_sender_stream_manage = None
                    
                    elif msg_type == 'Null message':
                        # Receiver sends Null - may be independent or response to Sender Null
                        if pending_sender_null:
                            # This is response to Sender's Null
                            pending_sender_null = None
                        else:
                            # This is independent Receiver Null - expects Sender Null response
                            pending_receiver_null = (msg_pkt, msg_ts)
                    
                    else:
                        # Invalid message type in subsequent exchange
                        errors.append({
                            'type': 'invalid_receiver_message_subsequent_exchange',
                            'severity': 'error',
                            'description': f"Receiver sent invalid message '{msg_type}' (packet #{msg_pkt}) in subsequent exchange. Valid: Null, ReceiverID_List, Stream_Ready.",
                            'packet_number': msg_pkt,
                            'timestamp': msg_ts,
                            'expected': 'In subsequent exchange, Receiver may send: Null, ReceiverID_List, or Stream_Ready (per section 13.2.3)',
                            'hkep_section': '13.2.3',
                            'note': f'Invalid message type: {msg_type}'
                        })
            
            # Check for pending requests without responses at end of exchange
            if pending_sender_stream_manage:
                errors.append({
                    'type': 'missing_stream_ready_response',
                    'severity': 'warning',
                    'description': f"Sender sent Stream_Manage (packet #{pending_sender_stream_manage[0]}) but did not receive Stream_Ready response.",
                    'packet_number': pending_sender_stream_manage[0],
                    'timestamp': pending_sender_stream_manage[1],
                    'expected': 'Receiver shall respond to Stream_Manage with Stream_Ready (per section 13.2.3)',
                    'hkep_section': '13.2.3',
                    'note': 'Stream_Ready response missing or not captured'
                })
            
            if pending_receiver_receiverid_list:
                errors.append({
                    'type': 'missing_send_ack_response',
                    'severity': 'warning',
                    'description': f"Receiver sent ReceiverID_List (packet #{pending_receiver_receiverid_list[0]}) but did not receive Send_Ack response.",
                    'packet_number': pending_receiver_receiverid_list[0],
                    'timestamp': pending_receiver_receiverid_list[1],
                    'expected': 'Sender shall respond to ReceiverID_List with Send_Ack (per section 13.2.3)',
                    'hkep_section': '13.2.3',
                    'note': 'Send_Ack response missing or not captured'
                })
        
        return errors
    
    def validate_section_12_6(self, exchange: HKEPExchange) -> List[Dict]:
        """
        Validate all requirements of HKEP section 12.6 (The receiver protocol)

        Per VSF TR-10-5:2024 section 12.6:
        12.6 Main requirements:
        - AKE_PreInit shall always be the first message exchanged after TCP/IP connection
        - AKE_PreInit.receiver attribute shall be true

        12.6.1 With explicit pairing (pairing=true):
        - Sender shall respond with AKE_PreInitStatus
        - If statusInvalidParameters, connection shall be closed
        - Otherwise statusPairingExpired, start HDCP protocol with AKE_Init
        - Receiver waits for AKE_PreInitStatus, then receives AKE_Init

        12.6.2 With implicit pairing (pairing=false):
        - Sender shall respond with AKE_PreInitStatus with appropriate status
        - Receiver behavior based on status value

        12.6.3 With reconnect:
        - restart/REAUTH_REQ should be false when reconnecting after session is valid
        - When restart/REAUTH_REQ is false, Receiver sends RepeaterAuth_Send_ReceiverID_List or Null
        - Sender sends RepeaterAuth_Stream_Manage or Null

        Additional HKEP requirements:
        - HDCP Protocol Descriptor must be 0x01 (HDCP v2.2+ compliance) (section 9.3.2)
        - Receivers must be HDCP Repeaters (REPEATER flag must be true) (sections 7.1, 9.3.1)

        Returns:
            List of validation errors (empty if sequence is valid)
        """
        errors = []
        messages = exchange.get_messages()
        
        if not messages:
            return errors
        
        sorted_messages = sorted(messages, key=lambda x: x.get('timestamp', 0))
        
        # 12.6: AKE_PreInit shall always be the first message exchanged after TCP/IP connection
        first_message = sorted_messages[0] if sorted_messages else None
        if first_message:
            first_msg_type = first_message.get('hkep', {}).get('message_type')
            if first_msg_type != "AKE_PreInit":
                errors.append({
                    'type': 'invalid_first_message',
                    'severity': 'error',
                    'description': f"First message after TCP/IP connection is '{first_msg_type}' (packet #{first_message.get('packet_number')}), expected AKE_PreInit",
                    'packet_number': first_message.get('packet_number'),
                    'timestamp': first_message.get('timestamp', 0),
                    'expected': 'AKE_PreInit shall always be the first message exchanged after TCP/IP connection (per section 12.6)',
                    'hkep_section': '12.6'
                })
        
        # Find AKE_PreInit message
        preinit_msg = None
        preinitstatus_msg = None
        pairing_flag = None
        restart_reauth_flag = None
        receiver_flag = None
        
        for msg in sorted_messages:
            hkep_data = msg.get('hkep', {})
            msg_type = hkep_data.get('message_type')
            
            if msg_type == "AKE_PreInit":
                preinit_msg = msg
                pairing_flag = hkep_data.get('pairing', False)
                restart_reauth_flag = hkep_data.get('restart/REAUTH_REQ', False)
                receiver_flag = hkep_data.get('receiver', False)
                
                # 12.6: AKE_PreInit.receiver attribute shall be true
                if not receiver_flag:
                    errors.append({
                        'type': 'invalid_preinit_receiver_flag',
                        'severity': 'error',
                        'description': f"AKE_PreInit (packet #{msg.get('packet_number')}) has receiver attribute set to false, expected true",
                        'packet_number': msg.get('packet_number'),
                        'timestamp': msg.get('timestamp', 0),
                        'expected': 'AKE_PreInit.receiver attribute shall be true (per section 12.6)',
                        'hkep_section': '12.6'
                    })
            
            elif msg_type == "AKE_PreInitStatus":
                preinitstatus_msg = msg
        
        # Validate AKE_PreInitStatus response
        if preinit_msg and not preinitstatus_msg:
            errors.append({
                'type': 'missing_preinitstatus',
                'severity': 'error',
                'description': f"AKE_PreInit (packet #{preinit_msg.get('packet_number')}) was sent but AKE_PreInitStatus response was not received",
                'packet_number': preinit_msg.get('packet_number'),
                'timestamp': preinit_msg.get('timestamp', 0),
                'expected': 'Sender shall respond with AKE_PreInitStatus after receiving AKE_PreInit (per section 12.6)',
                'hkep_section': '12.6'
            })
        
        # 12.4.1: Protocol Version Matching
        # Per spec: "Both the client and server sides of a TCP/IP connection shall use the same HKEP protocol version"
        if preinit_msg and preinitstatus_msg:
            preinit_version = preinit_msg.get('hkep', {}).get('Version', 0)
            preinitstatus_version = preinitstatus_msg.get('hkep', {}).get('Version', 0)
            status = preinitstatus_msg.get('hkep', {}).get('status')
            
            # If status is NOT statusInvalidParameters, versions MUST match
            if status != 1:  # Not statusInvalidParameters
                if preinit_version != preinitstatus_version:
                    errors.append({
                        'type': 'version_mismatch',
                        'severity': 'error',
                        'description': f"AKE_PreInit (packet #{preinit_msg.get('packet_number')}) has version {preinit_version}, but AKE_PreInitStatus (packet #{preinitstatus_msg.get('packet_number')}) has version {preinitstatus_version}. Both sides shall use the same protocol version.",
                        'packet_number': preinitstatus_msg.get('packet_number'),
                        'timestamp': preinitstatus_msg.get('timestamp', 0),
                        'expected': 'Both client and server sides of TCP/IP connection shall use the same HKEP protocol version. Server shall match client version in AKE_PreInitStatus response (per section 12.4.1)',
                        'hkep_section': '12.4.1'
                    })
            # If status IS statusInvalidParameters, PreInitStatus version indicates server's highest supported version
            # This is informational, not an error
        
        # 12.5: Vendor Extension Echo Behavior
        # Per spec: "A Sender should copy the value of the vendorExtension attribute from an AKE_PreInit message 
        # into the vendorExtension attribute of the AKE_PreInitStatus message response"
        if preinit_msg and preinitstatus_msg:
            preinit_vendor_ext = preinit_msg.get('hkep', {}).get('vendorExtension', '')
            preinitstatus_vendor_ext = preinitstatus_msg.get('hkep', {}).get('vendorExtension', '')
            
            # Only check if vendorExtension is non-zero in PreInit
            if preinit_vendor_ext and preinit_vendor_ext != '00000000000000000000000000000000':
                if preinit_vendor_ext != preinitstatus_vendor_ext:
                    errors.append({
                        'type': 'vendor_extension_not_echoed',
                        'severity': 'warning',
                        'description': f"AKE_PreInit (packet #{preinit_msg.get('packet_number')}) has vendorExtension={preinit_vendor_ext[:16]}..., but AKE_PreInitStatus (packet #{preinitstatus_msg.get('packet_number')}) has different vendorExtension={preinitstatus_vendor_ext[:16]}... Sender should copy vendorExtension from PreInit to PreInitStatus for cross-vendor interoperability.",
                        'packet_number': preinitstatus_msg.get('packet_number'),
                        'timestamp': preinitstatus_msg.get('timestamp', 0),
                        'expected': 'Sender should copy vendorExtension from AKE_PreInit to AKE_PreInitStatus response (per section 12.5 - recommended cross-vendor behavior)',
                        'hkep_section': '12.5',
                        'note': 'Same-vendor implementations may intentionally use different vendorExtension values'
                    })
        
        if preinitstatus_msg:
            status = preinitstatus_msg.get('hkep', {}).get('status')
            status_text = preinitstatus_msg.get('hkep', {}).get('status_text', 'Unknown')
            
            # 12.6.1 and 12.6.2: TCP Connection Closure After statusInvalidParameters
            # Per spec: "If the attributes of an AKE_PreInit message are invalid, the Sender shall respond 
            # with an AKE_PreInitStatus message with status set to statusInvalidParameters and the connection 
            # shall be closed"
            if status == 1:  # statusInvalidParameters
                # Connection SHALL be closed - check if there are HKEP messages after PreInitStatus
                messages_after = [m for m in sorted_messages 
                                 if m.get('timestamp', 0) > preinitstatus_msg.get('timestamp', 0) and
                                    m.get('hkep', {}).get('message_type') not in [None, '']]
                
                if messages_after:
                    # There are HKEP messages after statusInvalidParameters - this violates the spec
                    first_msg_after = messages_after[0]
                    errors.append({
                        'type': 'messages_after_invalid_parameters',
                        'severity': 'error',
                        'description': f"AKE_PreInitStatus (packet #{preinitstatus_msg.get('packet_number')}) has status statusInvalidParameters, but HKEP message '{first_msg_after.get('hkep', {}).get('message_type')}' (packet #{first_msg_after.get('packet_number')}) was sent after. Connection shall be closed after statusInvalidParameters.",
                        'packet_number': first_msg_after.get('packet_number'),
                        'timestamp': first_msg_after.get('timestamp', 0),
                        'expected': 'When AKE_PreInitStatus.status is statusInvalidParameters, connection shall be closed immediately. No further HKEP messages shall be sent (per sections 12.6.1 and 12.6.2)',
                        'hkep_section': '12.6.1, 12.6.2',
                        'note': f'Connection should close after packet #{preinitstatus_msg.get("packet_number")}, but packet #{first_msg_after.get("packet_number")} was sent'
                    })
            
            # 12.6.1: With explicit pairing (pairing=true)
            if pairing_flag is True:
                # Should be statusPairingExpired (unless invalid parameters)
                if status not in [1, 2]:  # statusInvalidParameters or statusPairingExpired
                    errors.append({
                        'type': 'invalid_preinitstatus_for_explicit_pairing',
                        'severity': 'error',
                        'description': f"AKE_PreInitStatus (packet #{preinitstatus_msg.get('packet_number')}) has status '{status_text}' (status={status}), expected statusPairingExpired when pairing=true",
                        'packet_number': preinitstatus_msg.get('packet_number'),
                        'timestamp': preinitstatus_msg.get('timestamp', 0),
                        'expected': 'When AKE_PreInit.pairing is true, AKE_PreInitStatus.status should be statusPairingExpired (unless statusInvalidParameters) (per section 12.6.1)',
                        'hkep_section': '12.6.1'
                    })
                # 12.6.1: "Otherwise, the Sender shall respond with an AKE_PreInitStatus message with 
                # the status attribute set to statusPairingExpired, and it shall start the HDCP RTP v2.3 
                # protocol by sending the AKE_Init message to the Receiver."
                elif status == 2:  # statusPairingExpired
                    # Check if AKE_Init follows after AKE_PreInitStatus
                    messages_after = [m for m in sorted_messages if m.get('timestamp', 0) > preinitstatus_msg.get('timestamp', 0)]
                    has_ake_init = any(m.get('hkep', {}).get('message_type') == 'AKE_Init' for m in messages_after)
                    if not has_ake_init:
                        errors.append({
                            'type': 'missing_ake_init_after_pairing_expired',
                            'severity': 'error',
                            'description': f"AKE_PreInitStatus with statusPairingExpired (packet #{preinitstatus_msg.get('packet_number')}) was sent but AKE_Init message did not follow",
                            'packet_number': preinitstatus_msg.get('packet_number'),
                            'timestamp': preinitstatus_msg.get('timestamp', 0),
                            'expected': 'When AKE_PreInit.pairing is true and status is statusPairingExpired, Sender shall start HDCP protocol by sending AKE_Init (per section 12.6.1)',
                            'hkep_section': '12.6.1'
                        })
            
            # 12.6.2: With implicit pairing (pairing=false)
            elif pairing_flag is False:
                # Status should be one of: statusInvalidParameters, statusPairingExpired, statusSessionExpired, statusOk
                if status not in [0, 1, 2, 3]:  # statusOk, statusInvalidParameters, statusPairingExpired, statusSessionExpired
                    errors.append({
                        'type': 'invalid_preinitstatus_for_implicit_pairing',
                        'severity': 'error',
                        'description': f"AKE_PreInitStatus (packet #{preinitstatus_msg.get('packet_number')}) has invalid status '{status_text}' (status={status}) when pairing=false",
                        'packet_number': preinitstatus_msg.get('packet_number'),
                        'timestamp': preinitstatus_msg.get('timestamp', 0),
                        'expected': 'When AKE_PreInit.pairing is false, AKE_PreInitStatus.status should be statusOk, statusInvalidParameters, statusPairingExpired, or statusSessionExpired (per section 12.6.2)',
                        'hkep_section': '12.6.2'
                    })
            
            # Check if we should ignore slot limits (assume infinite slots)
            ignore_slot_limits = hasattr(self, '_ignore_slot_limits') and self._ignore_slot_limits
            
            # 12.6: Validate sessionSlots - must be present and at least 1
            # Per spec: "Senders and Receivers may support a limited number of session slots. 
            # The attribute sessionSlots of the AKE_PreInitStatus message shall indicate the 
            # maximum number of slots available on the Sender."
            # If sessionSlots is 0, no HKEP session can be established, which defeats the purpose
            session_slots = preinitstatus_msg.get('hkep', {}).get('sessionSlots')
            if session_slots is None:
                errors.append({
                    'type': 'missing_session_slots',
                    'severity': 'error',
                    'description': f"AKE_PreInitStatus (packet #{preinitstatus_msg.get('packet_number')}) missing sessionSlots attribute",
                    'packet_number': preinitstatus_msg.get('packet_number'),
                    'timestamp': preinitstatus_msg.get('timestamp', 0),
                    'expected': 'AKE_PreInitStatus shall include sessionSlots attribute indicating maximum number of session slots available (per section 12.6)',
                    'hkep_section': '12.6'
                })
            elif session_slots == 0 and not ignore_slot_limits:
                errors.append({
                    'type': 'invalid_session_slots_zero',
                    'severity': 'error',
                    'description': f"AKE_PreInitStatus (packet #{preinitstatus_msg.get('packet_number')}) has sessionSlots=0, which prevents any HKEP session from being established",
                    'packet_number': preinitstatus_msg.get('packet_number'),
                    'timestamp': preinitstatus_msg.get('timestamp', 0),
                    'expected': 'sessionSlots must be at least 1 to allow HKEP sessions to be established (per section 12.6)',
                    'hkep_section': '12.6',
                    'note': 'If sessionSlots is 0, no HKEP session can be established, which defeats the purpose of the protocol'
                })
            
            # 12.6.1: Validate pairingSlots when pairing=true
            pairing_slots = preinitstatus_msg.get('hkep', {}).get('pairingSlots')
            
            if pairing_flag is True:
                if pairing_slots is None:
                    errors.append({
                        'type': 'missing_pairing_slots',
                        'severity': 'warning',
                        'description': f"AKE_PreInitStatus (packet #{preinitstatus_msg.get('packet_number')}) missing pairingSlots attribute when pairing=true",
                        'packet_number': preinitstatus_msg.get('packet_number'),
                        'timestamp': preinitstatus_msg.get('timestamp', 0),
                        'expected': 'AKE_PreInitStatus shall include pairingSlots attribute indicating maximum number of pairing slots available (per section 12.6.1)',
                        'hkep_section': '12.6.1'
                    })
            
            # 12.6: pairingSlots cannot be 0 as it prevents session caching
            if pairing_slots is not None and pairing_slots == 0 and not ignore_slot_limits:
                errors.append({
                    'type': 'invalid_pairing_slots_zero',
                    'severity': 'error',
                    'description': f"AKE_PreInitStatus (packet #{preinitstatus_msg.get('packet_number')}) has pairingSlots=0, which prevents any HKEP session from being cached",
                    'packet_number': preinitstatus_msg.get('packet_number'),
                    'timestamp': preinitstatus_msg.get('timestamp', 0),
                    'expected': 'pairingSlots must be at least 1 to allow HKEP sessions to be cached (per section 12.6)',
                    'hkep_section': '12.6',
                    'note': 'If pairingSlots is 0, no HKEP session can be cached, which goes against the requirement to cache an HKEP session'
                })
            
            # 12.6: If pairingSlots is 0, Sender must not send AKE_Stored_km messages
            # AKE_Stored_km messages come from using pairing information, which requires pairing slots
            if pairing_slots is not None and pairing_slots == 0 and not ignore_slot_limits:
                # Check if any AKE_Stored_km messages were sent
                stored_km_messages = [msg for msg in sorted_messages 
                                     if msg.get('hkep', {}).get('message_type') == 'AKE_Stored_km']
                if stored_km_messages:
                    for stored_km_msg in stored_km_messages:
                        errors.append({
                            'type': 'invalid_stored_km_with_zero_pairing_slots',
                            'severity': 'error',
                            'description': f"AKE_Stored_km message (packet #{stored_km_msg.get('packet_number')}) was sent but pairingSlots=0, which means no pairing information can be stored",
                            'packet_number': stored_km_msg.get('packet_number'),
                            'timestamp': stored_km_msg.get('timestamp', 0),
                            'expected': 'If pairingSlots=0, Sender must not send AKE_Stored_km messages as there are no pairing slots to store pairing information (per section 12.6)',
                            'hkep_section': '12.6',
                            'note': 'AKE_Stored_km messages indicate stored pairing information, which requires pairing slots to be available'
                        })
        
        # 12.6.2: A statusOk reconnect must NOT re-authenticate.
        # When the Receiver reconnects with restart/REAUTH_REQ=false and the Sender answers statusOk
        # ("the HKEP session is valid and has not expired"), the Sender "shall restart an existing
        # HDCPRTP v2.3 session at the Authentication with Repeaters stage" -- i.e. proceed to the
        # subsequent RepeaterAuth exchange, NOT send AKE_Init. AKE_Init is reserved for the
        # statusPairingExpired / statusSessionExpired branches. Deliberately NOT gated on the
        # is_reconnect heuristic: that helper treats the presence of AKE_Init as "not a reconnect",
        # which is exactly the violation this rule must catch.
        if preinit_msg and preinitstatus_msg and restart_reauth_flag is False:
            if preinitstatus_msg.get('hkep', {}).get('status') == 0:  # statusOk
                preinitstatus_time = preinitstatus_msg.get('timestamp', 0)
                ake_init_after = next(
                    (m for m in sorted_messages
                     if m.get('hkep', {}).get('message_type') == 'AKE_Init'
                     and m.get('timestamp', 0) > preinitstatus_time),
                    None
                )
                if ake_init_after:
                    errors.append({
                        'type': 'unexpected_ake_init_after_statusok_reconnect',
                        'severity': 'error',
                        'description': f"AKE_Init (packet #{ake_init_after.get('packet_number')}) was sent after AKE_PreInitStatus statusOk (packet #{preinitstatus_msg.get('packet_number')}) on a reconnect (restart/REAUTH_REQ=false). A valid, non-expired session shall be restarted at the Authentication with Repeaters stage, not re-authenticated.",
                        'packet_number': ake_init_after.get('packet_number'),
                        'timestamp': ake_init_after.get('timestamp', 0),
                        'expected': 'When restart/REAUTH_REQ=false and AKE_PreInitStatus.status is statusOk, the Sender shall restart the existing session at the Authentication with Repeaters stage and shall not send AKE_Init (per section 12.6.2)',
                        'hkep_section': '12.6.2'
                    })

        # 12.6.3: With reconnect - restart/REAUTH_REQ should be false when reconnecting after session is valid
        # Per spec: "A Receiver should reconnect to a Sender with the restart/REAUTH_REQ attribute
        # of the AKE_PreInit message set to false after an HKEP session has become valid"
        # So reconnect per 12.6.3 specifically requires restart/REAUTH_REQ=false
        is_reconnect = self._is_reconnect_exchange(exchange)
        
        # 12.6.3: When restart/REAUTH_REQ is false and this is a reconnect, validate initial RepeaterAuth messages
        # Note: If restart/REAUTH_REQ=true, it's not a reconnect per 12.6.3 (it's a full restart)
        if is_reconnect and preinit_msg and restart_reauth_flag is False:
            # Find first RepeaterAuth messages
            repeaterauth_messages = [
                "RepeaterAuth_Send_ReceiverID_List",
                "RepeaterAuth_Send_Ack",
                "RepeaterAuth_Stream_Manage",
                "RepeaterAuth_Stream_Ready"
            ]
            
            decoder_messages = exchange.get_decoder_messages()  # Receiver
            encoder_messages = exchange.get_encoder_messages()  # Sender
            
            # Find first RepeaterAuth message from Receiver
            first_repeaterauth_receiver = None
            for msg in sorted(decoder_messages, key=lambda x: x.get('timestamp', 0)):
                msg_type = msg.get('hkep', {}).get('message_type')
                if msg_type in repeaterauth_messages + ["Null message"]:
                    first_repeaterauth_receiver = msg_type
                    break
            
            # Find first RepeaterAuth message from Sender
            first_repeaterauth_sender = None
            for msg in sorted(encoder_messages, key=lambda x: x.get('timestamp', 0)):
                msg_type = msg.get('hkep', {}).get('message_type')
                if msg_type in repeaterauth_messages + ["Null message"]:
                    first_repeaterauth_sender = msg_type
                    break
            
            # 12.6.3: Receiver shall send RepeaterAuth_Send_ReceiverID_List or Null
            if first_repeaterauth_receiver and first_repeaterauth_receiver not in ["RepeaterAuth_Send_ReceiverID_List", "Null message"]:
                receiver_msg = next((m for m in sorted(decoder_messages, key=lambda x: x.get('timestamp', 0)) 
                                   if m.get('hkep', {}).get('message_type') in repeaterauth_messages + ["Null message"]), None)
                if receiver_msg:
                    errors.append({
                        'type': 'invalid_reconnect_receiver_message',
                        'severity': 'error',
                        'description': f"Receiver's initial RepeaterAuth message during reconnect is '{first_repeaterauth_receiver}' (packet #{receiver_msg.get('packet_number')}), expected RepeaterAuth_Send_ReceiverID_List or Null",
                        'packet_number': receiver_msg.get('packet_number'),
                        'timestamp': receiver_msg.get('timestamp', 0),
                        'expected': 'When reconnecting with restart/REAUTH_REQ=false, Receiver shall send RepeaterAuth_Send_ReceiverID_List or Null (per section 12.6.3)',
                        'hkep_section': '12.6.3'
                    })
            
            # 12.6.3: Sender shall send RepeaterAuth_Stream_Manage or Null
            if first_repeaterauth_sender and first_repeaterauth_sender not in ["RepeaterAuth_Stream_Manage", "Null message"]:
                sender_msg = next((m for m in sorted(encoder_messages, key=lambda x: x.get('timestamp', 0)) 
                                 if m.get('hkep', {}).get('message_type') in repeaterauth_messages + ["Null message"]), None)
                if sender_msg:
                    errors.append({
                        'type': 'invalid_reconnect_sender_message',
                        'severity': 'error',
                        'description': f"Sender's initial RepeaterAuth message during reconnect is '{first_repeaterauth_sender}' (packet #{sender_msg.get('packet_number')}), expected RepeaterAuth_Stream_Manage or Null",
                        'packet_number': sender_msg.get('packet_number'),
                        'timestamp': sender_msg.get('timestamp', 0),
                        'expected': 'When reconnecting with restart/REAUTH_REQ=false, Sender shall send RepeaterAuth_Stream_Manage or Null (per section 12.6.3)',
                        'hkep_section': '12.6.3'
                    })

        # HKEP Section 9.3.2: HDCP Protocol Descriptor Validation
        # "HDCP Device Key Set associated with an RXip Port shall have an HDCP Protocol Descriptor value equal to 0x01 to indicate an HDCP v2.2+ compliant device"
        for msg in sorted_messages:
            hkep_data = msg.get('hkep', {})
            msg_type = hkep_data.get('message_type')

            if msg_type == "AKE_Send_Cert":
                protocol_descriptor = hkep_data.get('Protocol_Descriptor', 0)
                if protocol_descriptor != 1:  # 0x01 = 1 in decimal
                    errors.append({
                        'type': 'invalid_hdcp_protocol_descriptor',
                        'severity': 'error',
                        'description': f"HDCP Protocol Descriptor must be 0x01 (HDCP v2.2+ compliant), got {protocol_descriptor:#04x} (packet #{msg.get('packet_number')})",
                        'packet_number': msg.get('packet_number'),
                        'timestamp': msg.get('timestamp', 0),
                        'expected': 'HDCP Device Key Set must have Protocol Descriptor = 0x01 for HDCP v2.2+ compliance (per section 9.3.2)',
                        'hkep_section': '9.3.2'
                    })

                # HKEP Sections 7.1, 9.3.1: Receiver Must Be HDCP Repeater
                # "A Receiver in an IP-based HDCP System is an HDCP Repeater"
                # "A Receiver subscribing to a Sender's HDCP Content shall behave as a Self-Subscribing HDCP Repeater"
                repeater_flag = hkep_data.get('REPEATER', False)
                if not repeater_flag:
                    errors.append({
                        'type': 'receiver_must_be_hdcp_repeater',
                        'severity': 'error',
                        'description': f"HKEP receivers must behave as HDCP Repeaters (REPEATER flag is false in packet #{msg.get('packet_number')})",
                        'packet_number': msg.get('packet_number'),
                        'timestamp': msg.get('timestamp', 0),
                        'expected': 'Receivers in HKEP systems must be HDCP Repeaters (REPEATER flag must be true) (per sections 7.1, 9.3.1)',
                        'hkep_section': '7.1, 9.3.1'
                    })

        return errors
    
    def validate_section_12_7(self, exchange: HKEPExchange) -> List[Dict]:
        """
        Validate all requirements of HKEP section 12.7 (The non-receiver protocol)
        
        Per VSF TR-10-5:2024 section 12.7:
        - AKE_PreInit.receiver attribute shall be false
        - AKE_PreInit.pairing attribute shall be true
        - AKE_PreInit shall be the first message exchanged after TCP/IP connection
        - Only AKE_PreInit and AKE_PreInitStatus messages shall be exchanged
        - Only msg_id, version_*, pairing, receiver, vendorExtension attributes are valid
        - If invalid attributes: statusInvalidParameters, connection closed
        - If valid attributes: statusOk, pairingSlots/sessionSlots indicate capabilities
        
        Returns:
            List of validation errors (empty if sequence is valid)
        """
        errors = []
        messages = exchange.get_messages()
        
        if not messages:
            return errors
        
        sorted_messages = sorted(messages, key=lambda x: x.get('timestamp', 0))
        
        # Find AKE_PreInit message first to determine if this is a non-receiver protocol exchange
        preinit_msg = None
        pairing_flag = None
        receiver_flag = None
        
        for msg in sorted_messages:
            hkep_data = msg.get('hkep', {})
            msg_type = hkep_data.get('message_type')
            
            if msg_type == "AKE_PreInit":
                preinit_msg = msg
                pairing_flag = hkep_data.get('pairing', False)
                receiver_flag = hkep_data.get('receiver', True)  # Default to True if not present
                break
        
        # Section 12.7 only applies to non-receiver protocol exchanges
        # If there's no AKE_PreInit, or if receiver=true or pairing=false, this is NOT a section 12.7 exchange
        # Skip validation for this exchange
        if not preinit_msg or receiver_flag or not pairing_flag:
            return errors
        
        # Now we know this is a non-receiver protocol exchange (receiver=false, pairing=true)
        # Continue with section 12.7 validation
        
        # 12.7: AKE_PreInit shall be the first message exchanged after TCP/IP connection
        first_message = sorted_messages[0] if sorted_messages else None
        if first_message:
            first_msg_type = first_message.get('hkep', {}).get('message_type')
            if first_msg_type != "AKE_PreInit":
                errors.append({
                    'type': 'invalid_first_message',
                    'severity': 'error',
                    'description': f"First message after TCP/IP connection is '{first_msg_type}' (packet #{first_message.get('packet_number')}), expected AKE_PreInit",
                    'packet_number': first_message.get('packet_number'),
                    'timestamp': first_message.get('timestamp', 0),
                    'expected': 'AKE_PreInit shall always be the first message exchanged after TCP/IP connection (per section 12.7)',
                    'hkep_section': '12.7'
                })
        
        # Find AKE_PreInitStatus message
        preinitstatus_msg = None
        
        for msg in sorted_messages:
            hkep_data = msg.get('hkep', {})
            msg_type = hkep_data.get('message_type')
            
            if msg_type == "AKE_PreInitStatus":
                preinitstatus_msg = msg
            
            # 12.7: Only AKE_PreInit and AKE_PreInitStatus messages shall be exchanged
            elif msg_type not in ["AKE_PreInit", "AKE_PreInitStatus"]:
                errors.append({
                    'type': 'invalid_message_for_non_receiver',
                    'severity': 'error',
                    'description': f"Unexpected message '{msg_type}' (packet #{msg.get('packet_number')}) in non-receiver protocol exchange",
                    'packet_number': msg.get('packet_number'),
                    'timestamp': msg.get('timestamp', 0),
                    'expected': 'Only AKE_PreInit and AKE_PreInitStatus messages shall be exchanged in non-receiver protocol (per section 12.7)',
                    'hkep_section': '12.7'
                })
        
        # Validate AKE_PreInitStatus response
        if preinit_msg and not preinitstatus_msg:
            errors.append({
                'type': 'missing_preinitstatus',
                'severity': 'error',
                'description': f"AKE_PreInit (packet #{preinit_msg.get('packet_number')}) was sent but AKE_PreInitStatus response was not received",
                'packet_number': preinit_msg.get('packet_number'),
                'timestamp': preinit_msg.get('timestamp', 0),
                'expected': 'Sender shall respond with AKE_PreInitStatus after receiving AKE_PreInit (per section 12.7)',
                'hkep_section': '12.7'
            })
        
        if preinitstatus_msg:
            status = preinitstatus_msg.get('hkep', {}).get('status')
            status_text = preinitstatus_msg.get('hkep', {}).get('status_text', 'Unknown')
            
            # 12.7: Status should be statusOk (if valid) or statusInvalidParameters (if invalid)
            if status not in [0, 1]:  # statusOk or statusInvalidParameters
                errors.append({
                    'type': 'invalid_preinitstatus_status',
                    'severity': 'error',
                    'description': f"AKE_PreInitStatus (packet #{preinitstatus_msg.get('packet_number')}) has invalid status '{status_text}' (status={status}), expected statusOk or statusInvalidParameters",
                    'packet_number': preinitstatus_msg.get('packet_number'),
                    'timestamp': preinitstatus_msg.get('timestamp', 0),
                    'expected': 'AKE_PreInitStatus.status shall be statusOk (if valid) or statusInvalidParameters (if invalid) (per section 12.7)',
                    'hkep_section': '12.7'
                })
            
            # 12.7: If status is statusOk, pairingSlots and sessionSlots should be present
            if status == 0:  # statusOk
                pairing_slots = preinitstatus_msg.get('hkep', {}).get('pairingSlots')
                session_slots = preinitstatus_msg.get('hkep', {}).get('sessionSlots')
                
                # Check if we should ignore slot limits (assume infinite slots)
                ignore_slot_limits = hasattr(self, '_ignore_slot_limits') and self._ignore_slot_limits
                
                if pairing_slots is None:
                    errors.append({
                        'type': 'missing_pairing_slots',
                        'severity': 'warning',
                        'description': f"AKE_PreInitStatus (packet #{preinitstatus_msg.get('packet_number')}) with statusOk missing pairingSlots attribute",
                        'packet_number': preinitstatus_msg.get('packet_number'),
                        'timestamp': preinitstatus_msg.get('timestamp', 0),
                        'expected': 'AKE_PreInitStatus with statusOk shall include pairingSlots attribute indicating maximum device capabilities (per section 12.7)',
                        'hkep_section': '12.7'
                    })
                elif pairing_slots == 0 and not ignore_slot_limits:
                    errors.append({
                        'type': 'invalid_pairing_slots_zero',
                        'severity': 'error',
                        'description': f"AKE_PreInitStatus (packet #{preinitstatus_msg.get('packet_number')}) with statusOk has pairingSlots=0, which prevents any HKEP session from being cached",
                        'packet_number': preinitstatus_msg.get('packet_number'),
                        'timestamp': preinitstatus_msg.get('timestamp', 0),
                        'expected': 'pairingSlots must be at least 1 to allow HKEP sessions to be cached (per section 12.7)',
                        'hkep_section': '12.7',
                        'note': 'If pairingSlots is 0, no HKEP session can be cached, which goes against the requirement to cache an HKEP session'
                    })
                
                if session_slots is None:
                    errors.append({
                        'type': 'missing_session_slots',
                        'severity': 'error',
                        'description': f"AKE_PreInitStatus (packet #{preinitstatus_msg.get('packet_number')}) with statusOk missing sessionSlots attribute",
                        'packet_number': preinitstatus_msg.get('packet_number'),
                        'timestamp': preinitstatus_msg.get('timestamp', 0),
                        'expected': 'AKE_PreInitStatus with statusOk shall include sessionSlots attribute indicating maximum device capabilities (per section 12.7)',
                        'hkep_section': '12.7'
                    })
                elif session_slots == 0 and not ignore_slot_limits:
                    errors.append({
                        'type': 'invalid_session_slots_zero',
                        'severity': 'error',
                        'description': f"AKE_PreInitStatus (packet #{preinitstatus_msg.get('packet_number')}) with statusOk has sessionSlots=0, which prevents any HKEP session from being established",
                        'packet_number': preinitstatus_msg.get('packet_number'),
                        'timestamp': preinitstatus_msg.get('timestamp', 0),
                        'expected': 'sessionSlots must be at least 1 to allow HKEP sessions to be established (per section 12.7)',
                        'hkep_section': '12.7',
                        'note': 'If sessionSlots is 0, no HKEP session can be established, which defeats the purpose of the protocol'
                    })
        
        # 12.7: AKE_Send_Pairing_Info Sequence and Connection Closure
        # Per spec: "After the HDCP protocol pairing, the Sender shall send an AKE_Send_Pairing_Info 
        # message to the Receiver and close the TCP/IP connection. The Receiver waits for the 
        # AKE_Send_Pairing_Info message and closes the TCP/IP connection after receiving it."
        
        # Look for HDCP pairing completion indicators (this happens in non-receiver protocol with pairing=true)
        # The pairing sequence is: AKE_Init → ... → AKE_Send_Pairing_Info → connection closes
        ake_send_pairing_info_msg = next((m for m in sorted_messages 
                                          if m.get('hkep', {}).get('message_type') == 'AKE_Send_Pairing_Info'), None)
        
        if ake_send_pairing_info_msg:
            # AKE_Send_Pairing_Info was sent - connection SHALL be closed after this
            messages_after_pairing = [m for m in sorted_messages 
                                     if m.get('timestamp', 0) > ake_send_pairing_info_msg.get('timestamp', 0) and
                                        m.get('hkep', {}).get('message_type') not in [None, '']]
            
            if messages_after_pairing:
                first_msg_after = messages_after_pairing[0]
                errors.append({
                    'type': 'messages_after_pairing_info',
                    'severity': 'error',
                    'description': f"AKE_Send_Pairing_Info (packet #{ake_send_pairing_info_msg.get('packet_number')}) was sent, but HKEP message '{first_msg_after.get('hkep', {}).get('message_type')}' (packet #{first_msg_after.get('packet_number')}) was sent after. Connection shall be closed after AKE_Send_Pairing_Info.",
                    'packet_number': first_msg_after.get('packet_number'),
                    'timestamp': first_msg_after.get('timestamp', 0),
                    'expected': 'After AKE_Send_Pairing_Info message, Sender shall close TCP/IP connection. No further HKEP messages shall be sent (per section 12.7)',
                    'hkep_section': '12.7',
                    'note': f'Connection should close after packet #{ake_send_pairing_info_msg.get("packet_number")}, but packet #{first_msg_after.get("packet_number")} was sent'
                })
        
        # Check if pairing was initiated but AKE_Send_Pairing_Info is missing
        # This would be detected if we see AKE_Init (start of HDCP pairing) but no AKE_Send_Pairing_Info
        if preinit_msg and preinitstatus_msg:
            status = preinitstatus_msg.get('hkep', {}).get('status')
            pairing_flag = preinit_msg.get('hkep', {}).get('pairing')
            
            # If status is statusOk and pairing was true, we expect to see HDCP pairing
            if status == 0 and pairing_flag:  # statusOk
                # Look for AKE_Init (start of HDCP pairing)
                ake_init_msg = next((m for m in sorted_messages 
                                    if m.get('hkep', {}).get('message_type') == 'AKE_Init'), None)
                
                if ake_init_msg and not ake_send_pairing_info_msg:
                    # HDCP pairing started but didn't complete with AKE_Send_Pairing_Info
                    errors.append({
                        'type': 'missing_pairing_info',
                        'severity': 'warning',
                        'description': f"HDCP pairing started with AKE_Init (packet #{ake_init_msg.get('packet_number')}) but AKE_Send_Pairing_Info message is missing. After pairing, Sender shall send AKE_Send_Pairing_Info.",
                        'packet_number': ake_init_msg.get('packet_number'),
                        'timestamp': ake_init_msg.get('timestamp', 0),
                        'expected': 'After HDCP protocol pairing completes, Sender shall send AKE_Send_Pairing_Info message (per section 12.7)',
                        'hkep_section': '12.7',
                        'note': 'Pairing may have failed, or capture may be incomplete'
                    })
        
        return errors
    
    def validate_section_13_1(self, exchange: HKEPExchange) -> List[Dict]:
        """
        Validate all requirements of HKEP section 13.1 (Locality check)
        
        Per VSF TR-10-5:2024 section 13.1:
        - Senders and Receivers shall set TRANSMITTER_LOCALITY_PRECOMPUTE_SUPPORT 
          and RECEIVER_LOCALITY_PRECOMPUTE_SUPPORT to true in AKE_Transmitter_Info 
          and AKE_Receiver_Info messages
        - In case of locality check failure, locality check shall be reattempted 
          for a maximum of 1023 additional attempts (1024 total trials) with LC_Init
        - Sender shall send new LC_Init as soon as it observes mismatch of L and L'
        - If Sender does not receive LC_Send_L_prime within ProtocolTimeout after 
          RTT_Challenge, it shall abort and close TCP/IP connection
        
        Returns:
            List of validation errors (empty if sequence is valid)
        """
        errors = []
        messages = exchange.get_messages()
        
        if not messages:
            return errors
        
        sorted_messages = sorted(messages, key=lambda x: x.get('timestamp', 0))
        
        # Find AKE_Transmitter_Info and AKE_Receiver_Info messages
        transmitter_info_msg = None
        receiver_info_msg = None
        
        for msg in sorted_messages:
            hkep_data = msg.get('hkep', {})
            msg_type = hkep_data.get('message_type')
            
            if msg_type == "AKE_Transmitter_Info":
                transmitter_info_msg = msg
            elif msg_type == "AKE_Receiver_Info":
                receiver_info_msg = msg
        
        # 13.1: TRANSMITTER_LOCALITY_PRECOMPUTE_SUPPORT shall be true
        if transmitter_info_msg:
            locality_precompute = transmitter_info_msg.get('hkep', {}).get('TRANSMITTER_LOCALITY_PRECOMPUTE_SUPPORT', False)
            if not locality_precompute:
                errors.append({
                    'type': 'invalid_transmitter_locality_precompute',
                    'severity': 'error',
                    'description': f"AKE_Transmitter_Info (packet #{transmitter_info_msg.get('packet_number')}) has TRANSMITTER_LOCALITY_PRECOMPUTE_SUPPORT set to false, expected true",
                    'packet_number': transmitter_info_msg.get('packet_number'),
                    'timestamp': transmitter_info_msg.get('timestamp', 0),
                    'expected': 'Senders shall set TRANSMITTER_LOCALITY_PRECOMPUTE_SUPPORT to true in AKE_Transmitter_Info (per section 13.1)',
                    'hkep_section': '13.1'
                })
        
        # 13.1: RECEIVER_LOCALITY_PRECOMPUTE_SUPPORT shall be true
        if receiver_info_msg:
            locality_precompute = receiver_info_msg.get('hkep', {}).get('RECEIVER_LOCALITY_PRECOMPUTE_SUPPORT', False)
            if not locality_precompute:
                errors.append({
                    'type': 'invalid_receiver_locality_precompute',
                    'severity': 'error',
                    'description': f"AKE_Receiver_Info (packet #{receiver_info_msg.get('packet_number')}) has RECEIVER_LOCALITY_PRECOMPUTE_SUPPORT set to false, expected true",
                    'packet_number': receiver_info_msg.get('packet_number'),
                    'timestamp': receiver_info_msg.get('timestamp', 0),
                    'expected': 'Receivers shall set RECEIVER_LOCALITY_PRECOMPUTE_SUPPORT to true in AKE_Receiver_Info (per section 13.1)',
                    'hkep_section': '13.1'
                })
        
        # 13.1: Validate LC_Init retry count (maximum 1024 total trials)
        # Count LC_Init messages - if more than 1024, it's a violation
        lc_init_messages = [msg for msg in sorted_messages 
                           if msg.get('hkep', {}).get('message_type') == 'LC_Init']
        if len(lc_init_messages) > 1024:
            errors.append({
                'type': 'excessive_lc_init_retries',
                'severity': 'error',
                'description': f"Found {len(lc_init_messages)} LC_Init messages, exceeding maximum allowed 1024 total trials",
                'packet_number': lc_init_messages[1024].get('packet_number') if len(lc_init_messages) > 1024 else None,
                'timestamp': lc_init_messages[1024].get('timestamp', 0) if len(lc_init_messages) > 1024 else 0,
                'expected': 'Locality check shall be reattempted for a maximum of 1023 additional attempts (1024 total trials) (per section 13.1)',
                'hkep_section': '13.1'
            })
        
        # 13.1: Track RTT_Challenge and LC_Send_L_prime to detect timeout violations
        # Note: We can't directly detect L/L' mismatch from PCAP, but we can track the sequence
        rtt_challenge_messages = []
        lc_send_l_prime_messages = []
        
        for msg in sorted_messages:
            hkep_data = msg.get('hkep', {})
            msg_type = hkep_data.get('message_type')
            
            if msg_type == "RTT_Challenge":
                rtt_challenge_messages.append(msg)
            elif msg_type == "LC_Send_L_prime":
                lc_send_l_prime_messages.append(msg)
        
        # 13.1: If Sender does not receive LC_Send_L_prime within ProtocolTimeout after RTT_Challenge, it shall abort
        # Note: We can't know the exact ProtocolTimeout value from PCAP, but we can check if
        # RTT_Challenge is followed by LC_Send_L_prime. If connection closes after RTT_Challenge
        # without LC_Send_L_prime, it might indicate a timeout (but this is hard to validate precisely)
        # We'll check if there are RTT_Challenge messages without corresponding LC_Send_L_prime
        # This is a best-effort check since we don't have ProtocolTimeout value
        
        # Track LC_Init messages after RTT_Challenge to detect retry patterns
        # Multiple LC_Init messages after RTT_Challenge suggest locality check failures/retries
        if len(lc_init_messages) > 1 and len(rtt_challenge_messages) > 0:
            # Check if LC_Init messages appear after RTT_Challenge (indicating retries)
            first_rtt_challenge = rtt_challenge_messages[0]
            lc_init_after_rtt = [msg for msg in lc_init_messages 
                                if msg.get('timestamp', 0) > first_rtt_challenge.get('timestamp', 0)]
            if len(lc_init_after_rtt) > 1023:
                errors.append({
                    'type': 'excessive_lc_init_retries_after_rtt',
                    'severity': 'error',
                    'description': f"Found {len(lc_init_after_rtt)} LC_Init messages after RTT_Challenge, exceeding maximum allowed 1023 retries",
                    'packet_number': lc_init_after_rtt[1023].get('packet_number') if len(lc_init_after_rtt) > 1023 else None,
                    'timestamp': lc_init_after_rtt[1023].get('timestamp', 0) if len(lc_init_after_rtt) > 1023 else 0,
                    'expected': 'Locality check shall be reattempted for a maximum of 1023 additional attempts after initial attempt (per section 13.1)',
                    'hkep_section': '13.1'
                })
        
        return errors
    
    def validate_section_13_3(self, exchange: HKEPExchange) -> List[Dict]:
        """
        Validate all requirements of HKEP section 13.3 (RepeaterAuth_Stream_Manage)
        
        Per VSF TR-10-5:2024 section 13.3:
        - For each content stream, associate unique streamCtr to Type and ContentStreamID
        - Type and ContentStreamID associated with streamCtr shall be immutable for session duration
        - A given streamCtr shall be associated with given Type and ContentStreamID once for 
          the lifetime of the Sender session key
        - Attribute k shall be bounded to maximum value of (2 * ProtocolMaxContentStreams)
        - There shall not be more than ProtocolMaxContentStreams different values of streamCtr 
          in a given RepeaterAuth_Stream_Manage message
        
        Note: ProtocolMaxContentStreams is typically 32 per HDCP RTP v2.3 specification
        
        Returns:
            List of validation errors (empty if sequence is valid)
        """
        errors = []
        messages = exchange.get_messages()
        
        if not messages:
            return errors
        
        sorted_messages = sorted(messages, key=lambda x: x.get('timestamp', 0))
        
        # ProtocolMaxContentStreams - per HDCP RTP v2.3, typically 32
        # This can be overridden if needed, but 32 is the standard value
        PROTOCOL_MAX_CONTENT_STREAMS = 32
        
        # Track streamCtr -> (Type, ContentStreamID) mappings across all RepeaterAuth_Stream_Manage messages
        # Key: streamCtr (as hex string), Value: set of (Type, ContentStreamID) tuples
        stream_ctr_mappings = {}  # streamCtr -> set((Type, ContentStreamID))
        
        # Process all RepeaterAuth_Stream_Manage messages in the exchange
        stream_manage_messages = [msg for msg in sorted_messages 
                                 if msg.get('hkep', {}).get('message_type') == 'RepeaterAuth_Stream_Manage']
        
        for stream_manage_msg in stream_manage_messages:
            hkep_data = stream_manage_msg.get('hkep', {})
            k_value = hkep_data.get('k')
            streams = hkep_data.get('streams', [])
            packet_num = stream_manage_msg.get('packet_number')
            
            # 13.3: Validate k is bounded to maximum (2 * ProtocolMaxContentStreams)
            if k_value is not None:
                max_k = 2 * PROTOCOL_MAX_CONTENT_STREAMS
                if k_value > max_k:
                    errors.append({
                        'type': 'excessive_k_value',
                        'severity': 'error',
                        'description': f"RepeaterAuth_Stream_Manage (packet #{packet_num}) has k={k_value}, exceeding maximum allowed {max_k} (2 * ProtocolMaxContentStreams)",
                        'packet_number': packet_num,
                        'timestamp': stream_manage_msg.get('timestamp', 0),
                        'expected': f'Attribute k of RepeaterAuth_Stream_Manage shall be bounded to maximum value of {max_k} (2 * ProtocolMaxContentStreams) (per section 13.3)',
                        'hkep_section': '13.3'
                    })
            
            # 13.3: Validate number of unique streamCtr values <= ProtocolMaxContentStreams
            unique_stream_ctrs = set()
            for stream in streams:
                stream_ctr = stream.get('streamCtr')
                if stream_ctr:
                    unique_stream_ctrs.add(stream_ctr)
            
            if len(unique_stream_ctrs) > PROTOCOL_MAX_CONTENT_STREAMS:
                errors.append({
                    'type': 'excessive_unique_stream_ctrs',
                    'severity': 'error',
                    'description': f"RepeaterAuth_Stream_Manage (packet #{packet_num}) has {len(unique_stream_ctrs)} unique streamCtr values, exceeding maximum allowed {PROTOCOL_MAX_CONTENT_STREAMS}",
                    'packet_number': packet_num,
                    'timestamp': stream_manage_msg.get('timestamp', 0),
                    'expected': f'There shall not be more than {PROTOCOL_MAX_CONTENT_STREAMS} different values of streamCtr in a given RepeaterAuth_Stream_Manage message (per section 13.3)',
                    'hkep_section': '13.3'
                })
            
            # 13.3: Track streamCtr -> (Type, ContentStreamID) associations
            # Validate immutability: same streamCtr must have same Type and ContentStreamID
            for stream in streams:
                stream_ctr = stream.get('streamCtr')
                stream_type = stream.get('Type')
                content_stream_id = stream.get('ContentStreamID')
                
                if stream_ctr is None or stream_type is None or content_stream_id is None:
                    continue
                
                # Create association tuple
                association = (stream_type, content_stream_id)
                
                # Check if this streamCtr was seen before
                if stream_ctr in stream_ctr_mappings:
                    # Check if the association matches previous ones
                    existing_associations = stream_ctr_mappings[stream_ctr]
                    
                    # 13.3: Type and ContentStreamID shall be immutable for session duration
                    # Note: The spec allows a streamCtr to be associated with multiple ContentStreamID values
                    # (when content stream is transmitted over multiple transport channels)
                    # So we check if this is a NEW association that differs from existing ones
                    if association not in existing_associations:
                        # Check if this violates immutability: if streamCtr was previously associated with
                        # a different Type, that's a violation (Type must be immutable)
                        # If it's the same Type but different ContentStreamID, that's allowed (multiple transport channels)
                        existing_types = {assoc[0] for assoc in existing_associations}
                        if stream_type not in existing_types:
                            # This is a violation: streamCtr is being reused with different Type
                            errors.append({
                                'type': 'immutable_stream_ctr_violation',
                                'severity': 'error',
                                'description': f"RepeaterAuth_Stream_Manage (packet #{packet_num}) has streamCtr={stream_ctr} with Type={stream_type}, ContentStreamID={content_stream_id}, but this streamCtr was previously associated with different Type values",
                                'packet_number': packet_num,
                                'timestamp': stream_manage_msg.get('timestamp', 0),
                                'expected': 'Type and ContentStreamID values associated with a streamCtr value shall be immutable for the duration of a session. A given streamCtr value shall be associated with given Type and ContentStreamID values once for the lifetime of the Sender session key (per section 13.3)',
                                'hkep_section': '13.3',
                                'note': f'streamCtr {stream_ctr} was previously associated with Type values: {existing_types}'
                            })
                        else:
                            # Same Type, different ContentStreamID - this is allowed (multiple transport channels)
                            # Add this association to the set
                            stream_ctr_mappings[stream_ctr].add(association)
                    # If association already exists, it's valid (same streamCtr can appear multiple times with same Type/ContentStreamID)
                else:
                    # First time seeing this streamCtr, record the association
                    stream_ctr_mappings[stream_ctr] = {association}
        
        return errors
    
    def validate_session_caching(self, analysis_result: HKEPAnalysisResult) -> List[Dict]:
        """
        Validate session caching consistency across all exchanges
        
        Per HKEP requirements:
        - Sender: Session becomes active after sending RepeaterAuth_Send_Ack
        - If sender sends RepeaterAuth_Send_Ack, it must cache the session
        - If receiver connects with REAUTH_REQ=false, sender should reuse cached session
        - Receiver: Session becomes active after sending Receiver_AuthStatus or closing connection
        - Receiver with REAUTH_REQ=false should be reusing a valid cached session
        
        Returns:
            List of validation errors/warnings
        """
        errors = []
        
        # Group exchanges by session tuple to analyze session lifecycle
        # Note: session_key might have suffixes like "_1", "_2" due to reconnection attempts
        # We need to normalize by removing the suffix to group all attempts together
        sessions = {}  # base_session_key -> list of exchanges (in chronological order)
        
        for exchange in analysis_result.get_all_exchanges():
            # Skip incomplete exchanges - can't validate session caching without proper initial sequence
            if hasattr(exchange, 'is_complete') and not exchange.is_complete:
                continue
            
            session_key = exchange.session_key
            # Remove suffix if present (format: "..._<number>")
            base_session_key = session_key
            if '_' in session_key:
                parts = session_key.rsplit('_', 1)
                if len(parts) == 2 and parts[1].isdigit():
                    base_session_key = parts[0]
            
            if base_session_key not in sessions:
                sessions[base_session_key] = []
            sessions[base_session_key].append(exchange)
        
        # Sort exchanges within each session by start time
        for session_key in sessions:
            sessions[session_key].sort(key=lambda x: x.start_time if x.start_time else 0)
        
        # Analyze each session
        for session_key, exchanges in sessions.items():
            if len(exchanges) == 0:
                continue
            
            # Track session state across exchanges
            sender_session_active = False
            receiver_session_active = False
            sender_send_ack_packet = None
            receiver_authstatus_packet = None
            
            # For each exchange, if it has multiple TCP connections, we need to split it into logical connection cycles
            # A new AKE_PreInit after a previous connection ended indicates a new logical exchange (reconnect)
            logical_exchanges = []
            for exchange in exchanges:
                if len(exchange.tcp_connections) > 1:
                    # Multiple TCP connections - split by AKE_PreInit messages
                    # Each AKE_PreInit starts a new logical exchange
                    all_messages = exchange.get_messages()
                    sorted_messages = sorted(all_messages, key=lambda x: x.get('timestamp', 0))
                    
                    # Find all AKE_PreInit messages
                    preinit_indices = []
                    for idx, msg in enumerate(sorted_messages):
                        hkep_data = msg.get('hkep', {})
                        if hkep_data.get('message_type') == 'AKE_PreInit':
                            preinit_indices.append(idx)
                    
                    if len(preinit_indices) > 1:
                        # Multiple AKE_PreInit messages - split into logical exchanges
                        for i, preinit_idx in enumerate(preinit_indices):
                            start_idx = preinit_idx
                            end_idx = preinit_indices[i + 1] if i + 1 < len(preinit_indices) else len(sorted_messages)
                            
                            logical_messages = sorted_messages[start_idx:end_idx]
                            
                            # Create a temporary exchange-like object for this connection cycle
                            # Use a class to properly capture the messages
                            class LogicalExchange:
                                def __init__(self, session_key, messages, tcp_connections, start_time, end_time):
                                    self.session_key = session_key
                                    self._messages = messages
                                    self.tcp_connections = tcp_connections
                                    self.start_time = start_time
                                    self.end_time = end_time
                                
                                def get_messages(self):
                                    return self._messages
                            
                            logical_exchange = LogicalExchange(
                                exchange.session_key,
                                logical_messages,
                                exchange.tcp_connections,
                                min((m.get('timestamp', 0) for m in logical_messages), default=0),
                                max((m.get('timestamp', 0) for m in logical_messages), default=0)
                            )
                            logical_exchanges.append(logical_exchange)
                    else:
                        # Only one AKE_PreInit - use as is
                        logical_exchanges.append(exchange)
                else:
                    # Single TCP connection - use as is
                    logical_exchanges.append(exchange)
            
            # Sort logical exchanges by start time
            logical_exchanges.sort(key=lambda x: x.start_time if hasattr(x, 'start_time') and x.start_time else 0)
            
            # Analyze logical exchanges in chronological order
            for exchange_idx, exchange in enumerate(logical_exchanges):
                messages = exchange.get_messages()
                sorted_messages = sorted(messages, key=lambda x: x.get('timestamp', 0))
                
                # Check for AKE_PreInit with REAUTH_REQ flag
                # Note: sender_session_active reflects the state from the PREVIOUS exchange
                ake_preinit_msg = None
                reauth_req = None
                for msg in sorted_messages:
                    hkep_data = msg.get('hkep', {})
                    if hkep_data.get('message_type') == 'AKE_PreInit':
                        ake_preinit_msg = msg
                        reauth_req = hkep_data.get('restart/REAUTH_REQ', True)
                        break
                
                # If this is a reconnect (REAUTH_REQ=false) and not the first exchange
                # Use BOTH approaches:
                # 1. If we saw RepeaterAuth_Send_Ack in previous exchange, we KNOW session was cached
                # 2. If we didn't see it, check AKE_PreInitStatus response to determine if sender had cached session
                if ake_preinit_msg and reauth_req is False and exchange_idx > 0:
                    # This is a reconnect attempt
                    # Find sender's AKE_PreInitStatus response
                    preinitstatus_msg = None
                    for msg in sorted_messages:
                        hkep_data = msg.get('hkep', {})
                        if hkep_data.get('message_type') == 'AKE_PreInitStatus':
                            preinitstatus_msg = msg
                            break
                    
                    if sender_session_active:
                        # We KNOW session was cached (saw Send_Ack in previous exchange)
                        # Validate that sender responds with statusOk to indicate valid cached session
                        if preinitstatus_msg:
                            status = preinitstatus_msg.get('hkep', {}).get('status')
                            # Only statusOk (0) indicates sender has a valid cached session
                            if status != 0:  # Not statusOk
                                status_text = preinitstatus_msg.get('hkep', {}).get('status_text', 'Unknown')
                                errors.append({
                                    'type': 'reconnect_invalid_preinitstatus',
                                    'severity': 'error',
                                    'description': f"Receiver attempting reconnect (REAUTH_REQ=false) in exchange {exchange_idx + 1} (packet #{ake_preinit_msg.get('packet_number')}). Sender had cached session (Send_Ack seen in previous exchange at packet #{sender_send_ack_packet}), but AKE_PreInitStatus has status '{status_text}' (status={status}) instead of statusOk",
                                    'packet_number': preinitstatus_msg.get('packet_number'),
                                    'timestamp': preinitstatus_msg.get('timestamp', 0),
                                    'expected': 'When reconnecting with REAUTH_REQ=false, sender with cached session should respond with AKE_PreInitStatus statusOk (per section 12.6.3)',
                                    'hkep_section': 'session_caching',
                                    'note': 'Only statusOk indicates the sender has a valid cached HKEP session. Other statuses (statusSessionExpired, statusPairingExpired, etc.) indicate the session is not valid or was not cached.'
                                })
                        else:
                            # Missing PreInitStatus response when we know session was cached
                            errors.append({
                                'type': 'reconnect_missing_preinitstatus_with_cached_session',
                                'severity': 'error',
                                'description': f"Receiver attempting reconnect (REAUTH_REQ=false) in exchange {exchange_idx + 1} (packet #{ake_preinit_msg.get('packet_number')}). Sender had cached session (Send_Ack seen in previous exchange at packet #{sender_send_ack_packet}), but did not respond with AKE_PreInitStatus",
                                'packet_number': ake_preinit_msg.get('packet_number'),
                                'timestamp': ake_preinit_msg.get('timestamp', 0),
                                'expected': 'Sender must respond with AKE_PreInitStatus after receiving AKE_PreInit (per section 12.6)',
                                'hkep_section': 'session_caching'
                            })
                    else:
                        # We DIDN'T see Send_Ack in previous exchange - check PreInitStatus to infer if sender had cached session
                        if preinitstatus_msg:
                            status = preinitstatus_msg.get('hkep', {}).get('status')
                            status_text = preinitstatus_msg.get('hkep', {}).get('status_text', 'Unknown')
                            
                            # Only statusOk (0) indicates sender has a valid cached session
                            # statusSessionExpired (3) could mean session expired OR never existed - cannot infer
                            # statusPairingExpired (2) also does not indicate cached session
                            if status == 0:  # statusOk
                                # Sender has valid cached session - update state
                                sender_session_active = True
                            else:
                                # statusInvalidParameters (1), statusPairingExpired (2), statusSessionExpired (3), or other
                                # Cannot confirm sender had a cached session
                                errors.append({
                                    'type': 'reconnect_without_cached_session',
                                    'severity': 'error',
                                    'description': f"Receiver attempting reconnect (REAUTH_REQ=false) in exchange {exchange_idx + 1} (packet #{ake_preinit_msg.get('packet_number')}), but AKE_PreInitStatus has status '{status_text}' (status={status}), indicating sender does not have a valid cached session",
                                    'packet_number': preinitstatus_msg.get('packet_number'),
                                    'timestamp': preinitstatus_msg.get('timestamp', 0),
                                    'expected': 'If receiver uses REAUTH_REQ=false, sender must have a valid cached session and should respond with AKE_PreInitStatus statusOk (per section 12.6.3)',
                                    'hkep_section': 'session_caching',
                                    'note': 'No Send_Ack seen in previous exchange, and AKE_PreInitStatus status is not statusOk. Only statusOk indicates a valid cached HKEP session.'
                                })
                        else:
                            # No PreInitStatus response - cannot determine if session was cached
                            errors.append({
                                'type': 'reconnect_missing_preinitstatus',
                                'severity': 'error',
                                'description': f"Receiver attempting reconnect (REAUTH_REQ=false) in exchange {exchange_idx + 1} (packet #{ake_preinit_msg.get('packet_number')}), but sender did not respond with AKE_PreInitStatus",
                                'packet_number': ake_preinit_msg.get('packet_number'),
                                'timestamp': ake_preinit_msg.get('timestamp', 0),
                                'expected': 'Sender must respond with AKE_PreInitStatus after receiving AKE_PreInit (per section 12.6)',
                                'hkep_section': 'session_caching'
                            })
                
                # If this is a full restart (REAUTH_REQ=true) but sender had active session
                if ake_preinit_msg and reauth_req is True and sender_session_active and exchange_idx > 0:
                    # Sender had active session but receiver is doing full restart
                    # This might be intentional (session expired, etc.) but worth noting
                    errors.append({
                        'type': 'full_restart_with_active_session',
                        'severity': 'warning',
                        'description': f"Full restart (REAUTH_REQ=true) in exchange {exchange_idx + 1} (packet #{ake_preinit_msg.get('packet_number')}), but sender had active session from previous exchange",
                        'packet_number': ake_preinit_msg.get('packet_number'),
                        'timestamp': ake_preinit_msg.get('timestamp', 0),
                        'expected': 'If sender has active cached session, receiver should use REAUTH_REQ=false to reconnect (per section 12.6.3)',
                        'hkep_section': 'session_caching',
                        'note': 'This may be intentional if session expired or was invalidated'
                    })
                
                # Check for RepeaterAuth_Send_Ack in this exchange (sender caches session after sending this)
                # This sets the state for the NEXT exchange
                for msg in sorted_messages:
                    hkep_data = msg.get('hkep', {})
                    if hkep_data.get('message_type') == 'RepeaterAuth_Send_Ack':
                        # Sender sent Send_Ack, so session should be cached for next exchange
                        sender_session_active = True
                        sender_send_ack_packet = msg.get('packet_number')
                        break
            
            # Final validation: If sender sent RepeaterAuth_Send_Ack, it should cache the session
            # This is validated by checking if subsequent reconnects work correctly
            if sender_send_ack_packet and len(exchanges) == 1:
                # Only one exchange, so we can't verify caching behavior
                # But we can note that sender should cache this session
                pass  # No error - single exchange is valid
        
        return errors
    
    def print_hkep_message(self, result: Dict, violations: List[Dict] = None):
        """
        Pretty print a single HKEP message
        
        Args:
            result: Message data dictionary
            violations: List of validation violations for this packet (optional)
        """
        packet_num = result['packet_number']
        
        # Check if there are violations for this packet
        has_violations = violations and len(violations) > 0
        
        # Print header with violation indicator
        print(f"\n{'='*80}")
        timestamp = result['timestamp']
        if has_violations:
            error_count = sum(1 for v in violations if v.get('severity') == 'error')
            warning_count = sum(1 for v in violations if v.get('severity') == 'warning')
            info_count = sum(1 for v in violations if v.get('severity') == 'info')
            violation_marker = f" [VIOLATION: {error_count} error(s), {warning_count} warning(s), {info_count} info]"
            print(f"Packet #{packet_num} {timestamp} (HKEP #{result['hkep_packet_number']}){violation_marker}")
        else:
            print(f"Packet #{packet_num} {timestamp} (HKEP #{result['hkep_packet_number']})")
        
        print(f"{result['src_ip']}:{result['src_port']} -> {result['dst_ip']}:{result['dst_port']}")
        if result.get('tcp_flags'):
            print(f"TCP: SEQ={result['tcp_seq']}, ACK={result.get('tcp_ack', 'N/A')}, Flags=[{result['tcp_flags']}]")
        print(f"{'='*80}")
        
        hkep = result['hkep']
        print(f"HKEP Protocol: {hkep.get('message_type', 'Unknown')}")
        
        # Print violations inline if present
        if has_violations:
            print(f"\n  *** SECTION 13.2 VALIDATION VIOLATIONS ***")
            for violation in violations:
                if violation.get('severity') == 'error':
                    severity_marker = "[ERROR]"
                elif violation.get('severity') == 'warning':
                    severity_marker = "[WARNING]"
                else:  # info
                    severity_marker = "[INFO]"
                print(f"    {severity_marker} {violation.get('description', 'Unknown violation')}")
                print(f"      Expected: {violation.get('expected', 'N/A')}")
                if violation.get('note'):
                    print(f"      Note: {violation.get('note')}")
            print(f"  {'-'*76}")
        
        for key, value in hkep.items():
            if key in ['message_type']:
                continue
            elif key == 'streams':
                print(f"  Streams ({len(value)}):")
                for stream in value:
                    print(f"    Stream {stream['stream_number']}:")
                    for sk, sv in stream.items():
                        if sk != 'stream_number':
                            print(f"      {sk}: {sv}")
            elif key == 'Receiver_IDs':
                print(f"  Receiver ID List ({len(value)} devices):")
                for i, rid in enumerate(value):
                    print(f"    Receiver_ID{i}[39:0]: {rid}")
            elif isinstance(value, bool):
                print(f"  {key}: {'true' if value else 'false'}")
            else:
                print(f"  {key}: {value}")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='HKEP Protocol Dissector for PCAP files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s capture.pcap
  %(prog)s capture.pcap --port 48879
  %(prog)s capture.pcap --quiet
  %(prog)s capture.pcap --output results.txt
  %(prog)s capture.pcap --validate-13-2
  %(prog)s capture.pcap --validate-13-2 --output results.json
  %(prog)s capture.pcap --validate-all
  %(prog)s capture.pcap --validate-all --output results.json
  
The --validate-13-2 option validates all HKEP section 13.2 requirements:
  - Initial message exchange (Receiver/Sender first messages)
  - Message sequences (Stream_Manage->Stream_Ready, Send_ReceiverID_List->Send_Ack)
  - Stream_Ready/Send_Ack ordering

The --validate-12-6 option validates all HKEP section 12.6 requirements:
  - AKE_PreInit must be first message
  - AKE_PreInit.receiver attribute must be true
  - AKE_PreInitStatus response requirements
  - Reconnect message requirements
  - HDCP Protocol Descriptor must be 0x01 (v2.2+ compliance)
  - Receivers must be HDCP Repeaters (REPEATER flag must be true)

The --validate-12-7 option validates all HKEP section 12.7 requirements:
  - AKE_PreInit must be first message
  - AKE_PreInit.receiver attribute must be false
  - AKE_PreInit.pairing attribute must be true
  - Only AKE_PreInit and AKE_PreInitStatus messages exchanged
  - AKE_PreInitStatus status and capabilities requirements

The --validate-13-1 option validates all HKEP section 13.1 requirements:
  - TRANSMITTER_LOCALITY_PRECOMPUTE_SUPPORT must be true
  - RECEIVER_LOCALITY_PRECOMPUTE_SUPPORT must be true
  - LC_Init retry count within limits (max 1024 total trials)

The --validate-13-3 option validates all HKEP section 13.3 requirements:
  - streamCtr immutability (Type and ContentStreamID must remain constant for session)
  - k attribute bounded to maximum (2 * ProtocolMaxContentStreams)
  - Number of unique streamCtr values <= ProtocolMaxContentStreams

The --validate-session-caching option validates session caching consistency:
  - Sender must cache session after sending RepeaterAuth_Send_Ack
  - If receiver uses REAUTH_REQ=false, sender should have cached session from previous exchange
  - Receiver reconnect patterns (warnings when receiver doesn't appear to reuse valid session)
        """
    )
    
    parser.add_argument('pcap_file', help='PCAP file to analyze')
    parser.add_argument('--port', type=int, default=None, 
                        help='TCP port to filter for HKEP traffic (default: auto-detect)')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Suppress console output')
    parser.add_argument('--output', '-o', help='Write results to JSON file')
    parser.add_argument('--no-reassembly', action='store_true',
                        help='Disable TCP stream reassembly (not recommended)')
    parser.add_argument('--show-tcp-issues', action='store_true',
                        help='Show warnings for TCP retransmissions, fragmentation, etc.')
    parser.add_argument('--validate-12-6', action='store_true',
                        help='Validate all HKEP section 12.6 requirements (AKE_PreInit, AKE_PreInitStatus, reconnect)')
    parser.add_argument('--validate-12-7', action='store_true',
                        help='Validate all HKEP section 12.7 requirements (non-receiver protocol: AKE_PreInit with receiver=false, pairing=true)')
    parser.add_argument('--validate-13-1', action='store_true',
                        help='Validate all HKEP section 13.1 requirements (locality check: precompute support flags, LC_Init retry limits)')
    parser.add_argument('--validate-13-2', action='store_true',
                        help='Validate all HKEP section 13.2 requirements (initial messages, message sequences)')
    parser.add_argument('--validate-13-3', action='store_true',
                        help='Validate all HKEP section 13.3 requirements (RepeaterAuth_Stream_Manage: streamCtr immutability, k bounds)')
    parser.add_argument('--validate-session-caching', action='store_true',
                        help='Validate session caching consistency (sender must cache after RepeaterAuth_Send_Ack, receiver reconnect patterns)')
    parser.add_argument('--validate-all', action=argparse.BooleanOptionalAction, default=True,
                        help='Validate all HKEP sections (12.6, 12.7, 13.1, 13.2, 13.3, and session caching). Enabled by default; use --no-validate-all to disable.')
    parser.add_argument('--ignore-slot-limits', action='store_true',
                        help='Ignore pairingSlots and sessionSlots values from PreInitStatus and assume they are infinite (useful for initial testing when values may be missing or zero)')
    
    args = parser.parse_args()
    
    # Collect validation sections
    # If --validate-all is set, enable all validations
    validate_12_6 = args.validate_12_6 or args.validate_all
    validate_12_7 = args.validate_12_7 or args.validate_all
    validate_13_1 = args.validate_13_1 or args.validate_all
    validate_13_2 = args.validate_13_2 or args.validate_all
    validate_13_3 = args.validate_13_3 or args.validate_all
    validate_session_caching = args.validate_session_caching or args.validate_all
    
    # Create dissector
    dissector = HKEPDissector(target_port=args.port)
    
    # Analyze PCAP
    results = dissector.analyze_pcap(
        args.pcap_file, 
        verbose=not args.quiet,
        handle_reassembly=not args.no_reassembly,
        show_tcp_issues=args.show_tcp_issues,
        validate_12_6=validate_12_6,
        validate_12_7=validate_12_7,
        validate_13_1=validate_13_1,
        validate_13_2=validate_13_2,
        validate_13_3=validate_13_3,
        validate_session_caching=validate_session_caching,
        ignore_slot_limits=args.ignore_slot_limits
    )
    
    # Validate sections if requested (in numerical order: 12.6, 12.7, 13.1, 13.2, 13.3, then session_caching)
    if validate_12_6:
        validation_results_12_6 = dissector.validate_all_exchanges(results, verbose=not args.quiet, section="12.6")
    if validate_12_7:
        validation_results_12_7 = dissector.validate_all_exchanges(results, verbose=not args.quiet, section="12.7")
    if validate_13_1:
        validation_results_13_1 = dissector.validate_all_exchanges(results, verbose=not args.quiet, section="13.1")
    if validate_13_2:
        validation_results_13_2 = dissector.validate_all_exchanges(results, verbose=not args.quiet, section="13.2")
    if validate_13_3:
        validation_results_13_3 = dissector.validate_all_exchanges(results, verbose=not args.quiet, section="13.3")
    if validate_session_caching:
        validation_results_session_caching = dissector.validate_all_exchanges(results, verbose=not args.quiet, section="session_caching")
    
    # Write to JSON if requested
    if args.output:
        import json
        try:
            # Convert analysis result to serializable format
            output_data = {
                'total_packets': results.total_packets,
                'total_messages': results.total_messages,
                'exchange_count': results.get_exchange_count(),
                'exchanges': []
            }

            for exchange in results.get_all_exchanges():
                is_reconnect = dissector._is_reconnect_exchange(exchange)
                exchange_data = {
                    'session_key': exchange.session_key,
                    'receiver_id': exchange.receiver_id,
                    'node_id': exchange.node_id,
                    'port_id': exchange.port_id,
                    'tcp_connections': [
                        {
                            'stream_key': conn[0],
                            'src_ip': conn[1],
                            'src_port': conn[2],
                            'dst_ip': conn[3],
                            'dst_port': conn[4]
                        }
                        for conn in exchange.tcp_connections
                    ],
                    # Backward compatibility: use first TCP connection's endpoints
                    'src_ip': exchange.tcp_connections[0][1] if exchange.tcp_connections else None,
                    'src_port': exchange.tcp_connections[0][2] if exchange.tcp_connections else None,
                    'dst_ip': exchange.tcp_connections[0][3] if exchange.tcp_connections else None,
                    'dst_port': exchange.tcp_connections[0][4] if exchange.tcp_connections else None,
                    'message_count': exchange.get_message_count(),
                    'duration': exchange.get_duration(),
                    'start_time': exchange.start_time,
                    'end_time': exchange.end_time,
                    'successful': exchange.is_successful(),
                    'disconnection_reason': exchange.disconnection_reason,
                    'is_reconnect': is_reconnect,
                    'is_complete': exchange.is_complete if exchange.is_complete is not None else True,
                    'incomplete_reason': exchange.incomplete_reason,
                    'messages': exchange.get_messages()
                }
                output_data['exchanges'].append(exchange_data)

            # Add validation results if available (in numerical section order: 12.6, 12.7, 13.1, 13.2, 13.3, then session_caching)
            if validate_12_6 and 'validation_results_12_6' in locals():
                output_data['section_12_6_validation'] = {
                    'total_errors': validation_results_12_6['total_errors'],
                    'total_warnings': validation_results_12_6['total_warnings'],
                    'total_issues': validation_results_12_6['total_issues'],
                    'status': validation_results_12_6.get('status'),
                    'applicable_exchanges': validation_results_12_6.get('applicable_exchanges'),
                    'complete_exchanges': validation_results_12_6.get('complete_exchanges'),
                    'exchanges_with_errors': len(validation_results_12_6['exchange_errors']),
                    'errors_by_exchange': {
                        session_key: [
                            {
                                'type': e['type'],
                                'severity': e['severity'],
                                'description': e['description'],
                                'packet_number': e['packet_number'],
                                'timestamp': e['timestamp'],
                                'expected': e['expected'],
                                'hkep_section': e['hkep_section'],
                                'note': e.get('note')  # Include note if present
                            }
                            for e in errors
                        ]
                        for session_key, errors in validation_results_12_6['exchange_errors'].items()
                    }
                }
            
            if validate_12_7 and 'validation_results_12_7' in locals():
                output_data['section_12_7_validation'] = {
                    'total_errors': validation_results_12_7['total_errors'],
                    'total_warnings': validation_results_12_7['total_warnings'],
                    'total_issues': validation_results_12_7['total_issues'],
                    'status': validation_results_12_7.get('status'),
                    'applicable_exchanges': validation_results_12_7.get('applicable_exchanges'),
                    'complete_exchanges': validation_results_12_7.get('complete_exchanges'),
                    'exchanges_with_errors': len(validation_results_12_7['exchange_errors']),
                    'errors_by_exchange': {
                        session_key: [
                            {
                                'type': e['type'],
                                'severity': e['severity'],
                                'description': e['description'],
                                'packet_number': e['packet_number'],
                                'timestamp': e['timestamp'],
                                'expected': e['expected'],
                                'hkep_section': e['hkep_section'],
                                'note': e.get('note')  # Include note if present
                            }
                            for e in errors
                        ]
                        for session_key, errors in validation_results_12_7['exchange_errors'].items()
                    }
                }
            
            if validate_13_1 and 'validation_results_13_1' in locals():
                output_data['section_13_1_validation'] = {
                    'total_errors': validation_results_13_1['total_errors'],
                    'total_warnings': validation_results_13_1['total_warnings'],
                    'total_issues': validation_results_13_1['total_issues'],
                    'status': validation_results_13_1.get('status'),
                    'applicable_exchanges': validation_results_13_1.get('applicable_exchanges'),
                    'complete_exchanges': validation_results_13_1.get('complete_exchanges'),
                    'exchanges_with_errors': len(validation_results_13_1['exchange_errors']),
                    'errors_by_exchange': {
                        session_key: [
                            {
                                'type': e['type'],
                                'severity': e['severity'],
                                'description': e['description'],
                                'packet_number': e['packet_number'],
                                'timestamp': e['timestamp'],
                                'expected': e['expected'],
                                'hkep_section': e['hkep_section'],
                                'note': e.get('note')  # Include note if present
                            }
                            for e in errors
                        ]
                        for session_key, errors in validation_results_13_1['exchange_errors'].items()
                    }
                }
            
            if validate_13_2 and 'validation_results_13_2' in locals():
                output_data['section_13_2_validation'] = {
                    'total_errors': validation_results_13_2['total_errors'],
                    'total_warnings': validation_results_13_2['total_warnings'],
                    'total_issues': validation_results_13_2['total_issues'],
                    'status': validation_results_13_2.get('status'),
                    'applicable_exchanges': validation_results_13_2.get('applicable_exchanges'),
                    'complete_exchanges': validation_results_13_2.get('complete_exchanges'),
                    'exchanges_with_errors': len(validation_results_13_2['exchange_errors']),
                    'errors_by_exchange': {
                        session_key: [
                            {
                                'type': e['type'],
                                'severity': e['severity'],
                                'description': e['description'],
                                'packet_number': e['packet_number'],
                                'timestamp': e['timestamp'],
                                'expected': e['expected'],
                                'hkep_section': e['hkep_section'],
                                'note': e.get('note')  # Include note if present
                            }
                            for e in errors
                        ]
                        for session_key, errors in validation_results_13_2['exchange_errors'].items()
                    }
                }
            
            if validate_13_3 and 'validation_results_13_3' in locals():
                output_data['section_13_3_validation'] = {
                    'total_errors': validation_results_13_3['total_errors'],
                    'total_warnings': validation_results_13_3['total_warnings'],
                    'total_issues': validation_results_13_3['total_issues'],
                    'status': validation_results_13_3.get('status'),
                    'applicable_exchanges': validation_results_13_3.get('applicable_exchanges'),
                    'complete_exchanges': validation_results_13_3.get('complete_exchanges'),
                    'exchanges_with_errors': len(validation_results_13_3['exchange_errors']),
                    'errors_by_exchange': {
                        session_key: [
                            {
                                'type': e['type'],
                                'severity': e['severity'],
                                'description': e['description'],
                                'packet_number': e['packet_number'],
                                'timestamp': e['timestamp'],
                                'expected': e['expected'],
                                'hkep_section': e['hkep_section'],
                                'note': e.get('note')  # Include note if present
                            }
                            for e in errors
                        ]
                        for session_key, errors in validation_results_13_3['exchange_errors'].items()
                    }
                }
            
            if validate_session_caching and 'validation_results_session_caching' in locals():
                output_data['session_caching_validation'] = {
                    'total_errors': validation_results_session_caching['total_errors'],
                    'total_warnings': validation_results_session_caching['total_warnings'],
                    'total_issues': validation_results_session_caching['total_issues'],
                    'status': validation_results_session_caching.get('status'),
                    'applicable_exchanges': validation_results_session_caching.get('applicable_exchanges'),
                    'complete_exchanges': validation_results_session_caching.get('complete_exchanges'),
                    'exchanges_with_errors': len(validation_results_session_caching['exchange_errors']),
                    'errors_by_exchange': {
                        session_key: [
                            {
                                'type': e['type'],
                                'severity': e['severity'],
                                'description': e['description'],
                                'packet_number': e['packet_number'],
                                'timestamp': e['timestamp'],
                                'expected': e['expected'],
                                'hkep_section': e['hkep_section'],
                                'note': e.get('note')  # Include note if present
                            }
                            for e in errors
                        ]
                        for session_key, errors in validation_results_session_caching['exchange_errors'].items()
                    }
                }

            with open(args.output, 'w') as f:
                json.dump(output_data, f, indent=2)
            print(f"\nResults written to {args.output}")
        except Exception as e:
            print(f"Error writing output file: {e}")


def example_programmatic_usage():
    """
    Example of how to programmatically analyze HKEP exchanges. An external program may use this API to analyze HKEP exchanges
    without the need to use the command line interface. It may be used to analyze protocol issues or search for specific 
    exchanges or message sequences.
    """
    dissector = HKEPDissector()

    # Analyze a PCAP file
    results = dissector.analyze_pcap("example.pcap", verbose=False)

    print(f"Found {results.get_exchange_count()} HKEP exchanges")
    print(f"Total messages: {results.total_messages}")

    # Analyze each exchange
    for exchange in results.get_all_exchanges():
        print(f"\nExchange: {exchange.session_key}")
        if len(exchange.tcp_connections) > 1:
            print(f"  TCP Connections: {len(exchange.tcp_connections)}")
            for i, (conn_stream_key, conn_src_ip, conn_src_port, conn_dst_ip, conn_dst_port) in enumerate(exchange.tcp_connections, 1):
                print(f"    {i}. {conn_stream_key} ({conn_src_ip}:{conn_src_port} <-> {conn_dst_ip}:{conn_dst_port})")
        print(f"  Duration: {exchange.get_duration():.3f} seconds")
        print(f"  Messages: {exchange.get_message_count()}")
        print(f"  Successful: {exchange.is_successful()}")

        # Get messages by type
        ake_init_messages = exchange.get_messages_by_type("AKE_Init")
        print(f"  AKE_Init messages: {len(ake_init_messages)}")

        # Get messages by direction
        encoder_messages = exchange.get_encoder_messages()
        decoder_messages = exchange.get_decoder_messages()
        print(f"  Encoder->Decoder: {len(encoder_messages)}")
        print(f"  Decoder->Encoder: {len(decoder_messages)}")

        # Access individual messages
        for msg in exchange.get_messages():
            hkep_data = msg['hkep']
            print(f"    Packet {msg['packet_number']}: {hkep_data['message_type']}")

    # Get only successful exchanges
    successful = results.get_successful_exchanges()
    print(f"\nSuccessful exchanges: {len(successful)}")

    # Get specific exchange by stream key
    specific_exchange = results.get_exchange_by_stream_key("10.20.10.168:49160-10.20.10.189:2000")
    if specific_exchange:
        print(f"Specific exchange has {specific_exchange.get_message_count()} messages")


if __name__ == "__main__":
    main()

