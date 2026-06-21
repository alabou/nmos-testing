# IPMX USB Tools Package

Self-contained Python test/validation suite for VSF TR-10-14 (IPMX USB)
with TR-10-13 privacy encryption support.

## Prerequisites

- Python 3.10+
- pycryptodome (`pip install pycryptodome`)
- scapy (`pip install scapy`)

## Tools

### Dissector (offline PCAP validation)

    python3 usbDissector.py capture.pcap [--psk KEY] [--sdp FILE]

### Live Receiver Tester

    python3 ipmx_usb_tester.py --host SENDER_IP [--port 5004] [--psk KEY] [--sdp FILE]

### Sender Simulator (PCAP-driven)

    python3 pcap_sender_sim.py capture.pcap [--port 5004] [--psk KEY] [--sdp FILE]

### PEP Unit Tests

    python3 -m pytest test_ipmx_pep.py -v

## Debug/Interop Flags (common to dissector and tester)

    --iv-s2r-swap0       IV endianness: S2R swap mode 0
    --iv-r2s-swap0       IV endianness: R2S swap mode 0
    --iv-r2s-swap1       IV endianness: R2S swap mode 1
    --iv-r2s-spec0       IV endianness: R2S spec mode 0
    --ctr-1              Start CTR at 1 (some devices reject CTR=0)
    --kv-s2r             R2S key_version from S2R direction
    --kv-sdp             R2S key_version from SDP
    --strict-pep         Strict PEP enforcement
