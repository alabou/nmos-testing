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
    --kv-s2r             Tester, debugging only: R2S key_version echoes the Sender's (see below)
    --kv-sdp             Tester, debugging only: R2S key_version from SDP on every connection
    --strict-pep         Strict PEP enforcement

## Tester key_version (Receiver-to-Sender)

By default the tester gives each TCP connection, the control channel and every data channel, a
key of its own: a random KEYVERSION for the first connection of the run, then one more for each
next connection (modulo 2^32, skipping 0). Each data channel sends its USB Stream Status on
sub-stream 3 (TR-10-14 Table 19), so this is what keeps the quartet (iv', key_generator,
key_version, key_id) unique (TR-10-13 §14) and lets every connection start at CTR 0 without
re-using keystream (TR-10-13 §15).

`--kv-s2r` and `--kv-sdp` are for debugging, and the tester warns when one is given: `--kv-sdp`
re-uses keystream on every connection, and `--kv-s2r` does whenever the Sender keeps its
KEYVERSION from one TCP connection to the next. The tester also warns when the SDP's PEP protocol
is not `USB_KV` (TR-10-14 §14): without an in-band key_version its key cannot change per
connection.

## PEP forward-progress checks (DIAG)

The dissector, and the tester as it runs, check TR-10-13 §18 on each direction of each TCP
connection. The connection is the subscription, so the first message each side sends on it is
the baseline.

- KEYVERSION: each one is larger than or equal to the one before it (modulo 2^32, at most 2^31
  ahead). A new KEYVERSION is a new key, whose CTR may start again.
- CTR: under one KEYVERSION, each CTR is at or past every counter value already used on the
  connection in that direction. A message uses its CTR and one value more for each 16-byte slice
  it encrypts. Skipping values ahead is forward progress; a CTR below that point re-uses iv'_ctr
  values (TR-10-13 §15), whether the counter restarts at 0 within the connection or steps by
  message instead of by slice.

A breach is a DIAG finding, on the `TR-10-13 18` rows of the `-r` checklist: it never fails a
capture. The checks read the clear message header, so they need no PSK.
