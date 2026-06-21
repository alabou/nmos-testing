# IPMX Stream Validation Toolkit

Per-PCAP validators for IPMX (VSF TR-10) media streams. Each tool reads a
single PCAP capture (and optionally an SDP transport file) and reports
SHALL/SHOULD pass/fail against the relevant IPMX, ST 2110, NMOS BCP, and
codec specifications.

This package is **validation-only** — it does not generate test streams.
A capture taken from a real IPMX sender is the expected input.

## Supported Streams

| Codec | Validator | Specifications |
|-------|-----------|----------------|
| H.265 / HEVC | `ipmx_h265_validate_pcap.py` | VSF TR-10-15b, NMOS BCP-006-03, RFC 7798, ITU-T H.265 |
| H.264 / AVC | `ipmx_h264_validate_pcap.py` | VSF TR-10-15c, NMOS BCP-006-02, RFC 6184, ITU-T H.264 |
| JPEG XS | `ipmx_jxsv_validate_pcap.py` | VSF TR-10-15a, NMOS BCP-006-04, RFC 9134, ISO/IEC 21122 |
| Uncompressed Video | `ipmx_raw_validate_pcap.py` | VSF TR-10-2, ST 2110-20, RFC 4175 |
| AM824 (AES3 over IP) | `ipmx_am824_validate_pcap.py` | VSF TR-10-12, ST 2110-31, AES3, SMPTE 337M |
| PCM | `ipmx_pcm_validate_pcap.py` | VSF TR-10-12, ST 2110-30, RFC 3551 |

## Prerequisites

- Python 3.10+ (Python 3.12 recommended)
- `scapy ≥ 2.5` (`pip install scapy`)
- `ffmpeg` with `libx265` / `libx264` only when running HRD tier-3 checks
  (`--hrd-timing`) on compressed video — the validator invokes
  `ffmpeg trace_headers` to parse SPS / PPS / VPS / SEI structures.

Plain `--hrd` / `--cmax` / `--sdp` checks have no ffmpeg dependency.

## Usage

Every validator follows the same shape: positional PCAP, optional SDP,
optional codec / encryption / profile flags. Examples:

### H.265

```bash
python3 ipmx_h265_validate_pcap.py capture.pcap \
    --exactframerate 60 \
    --sdp transport.sdp \
    --cmax --hrd-timing
```

### H.264 with encryption

```bash
python3 ipmx_h264_validate_pcap.py capture.pcap \
    --exactframerate 60000/1001 \
    --sdp transport.sdp \
    --cmax --hrd-timing \
    --hkep --pep
```

### JPEG XS

```bash
python3 ipmx_jxsv_validate_pcap.py capture.pcap \
    --exactframerate 60 --sdp transport.sdp
```

### Uncompressed video (ST 2110-20)

```bash
python3 ipmx_raw_validate_pcap.py capture.pcap --sdp transport.sdp
```

### ST 2110-31 / AM824

```bash
python3 ipmx_am824_validate_pcap.py capture.pcap \
    --sdp transport.sdp \
    --sample-rate 48000 --nchan 2 --ptime 1 \
    --sample-size 24 --measured-sample-rate 48000 \
    --rtcp-port 15001
```

### ST 2110-30 / PCM

```bash
python3 ipmx_pcm_validate_pcap.py capture.pcap \
    --sdp transport.sdp \
    --sample-rate 48000 --nchan 2 --ptime 1 \
    --sample-size 24 --measured-sample-rate 48000 \
    --rtcp-port 15001
```

### RTCP Sender Report inspection

```bash
python3 ipmx_parse_sender_report_pcap.py capture.pcap
```

Each tool prints a per-requirement PASS / FAIL / CANNOT_TEST table and
exits non-zero if any SHALL fails. Use `--full-report` for verbose output
and `--help` for the full flag set.

## Recommended Flag Combinations

For thorough compressed-video validation, always pair `--cmax` with
`--hrd-timing`. Both are opt-in: without them the wire-timing SHALLs
(HRD-TIME-01..03, HRD-TIME-EQC3, TR-10-1 §8.1 CMAX / CINST) report
PASS only because the underlying check never executed.

```bash
python3 ipmx_h265_validate_pcap.py capture.pcap \
    --sdp transport.sdp --cmax --hrd-timing
```

For encrypted captures, add `--hkep` and/or `--pep` to enable the
encryption-validation requirement family (`ENC-01`..`ENC-14`).

## Validation Surface

Every check is tagged with the normative requirement ID. The major
families are:

- `TR-10-15a-*` / `-15b-*` / `-15c-*` — IPMX codec profiles (JXSV / H.265 / H.264)
- `TR-10-9-*` — IPMX compressed-video RTP transport
- `TR-10-12-*` — IPMX audio transport
- `TR-10-1-*` — IPMX system timing, RTCP Sender Reports, IPMX fmtp keyword
- `ST2110-30-*` / `ST2110-31-*` — ST 2110 audio encapsulation
- `HRD-*` / `HRD-TIME-*` — HRD self-consistency and PCAP timing
  cross-validation (compressed video only)
- `ENC-01`..`ENC-14` — HKEP and PEP encryption checks
- `SDP-*` — SDP transport-file cross-validation

### HRD tiers (compressed video)

| Tier | Flag | What it checks |
|------|------|----------------|
| 1 | `--hrd` | HRD parameter self-consistency (VUI timing, CPB params) |
| 2 | `--hrd-sim` | CPB leaky-bucket simulation |
| 3 | `--hrd-timing` | PCAP capture timing cross-validated against the HRD model |

`--hrd-timing` implies `--hrd-sim`, which implies `--hrd`.

### CMAX (ST 2110-21 traffic shape)

`--cmax` on video validators runs the TR-10-1 §8.1 Network Compatibility
Model check (Type W). Computes `CMAX = MAX(16, INT(NPACKETS / (21600 × TFRAME)))`,
simulates the CINST leaky-bucket against captured packet timestamps, and
reports the peak burst observed. Audio validators do not need this — TR-10-1
§8.2 routes audio to AES67 §7.5 which has no CMAX semantics.

### Encryption (HKEP / PEP)

`--hkep` and `--pep` cross-validate four sources:

1. CLI flags
2. RTP extension headers (RFC 8285)
3. RTCP Media Info Blocks (0x0010 HKEP, 0x0011 PEP)
4. SDP attributes (`a=hkep`, `a=privacy`, `a=extmap` URNs)

Per TR-10-13 §20.4, when both HKEP and PEP are active in-place, PEP
reuses the HDCP CTR Full/Short RTP extension headers and only the HDCP
URNs appear in the SDP; the validator's ENC-11 check accounts for this.

### Profile superset acceptance

`--allow-superset-profile` accepts higher codec profiles that are
backward-compatible supersets of the IPMX-mandated baseline:

- H.265: Rext (4) ⊃ Main 10 (2) ⊃ Main (1)
- H.264: High 4:4:4 Predictive (244) ⊃ High 4:2:2 (122) ⊃ High 10 (110) ⊃ High (100) ⊃ Main (77)

### SDP cross-validation

`--sdp transport.sdp` adds the SDP-side rules: RFC 6184 / 7798 / 9134
shape, ST 2110-10 / -22 / -30 / -31, IPMX fmtp keyword (TR-10-1 §10.1),
multicast source-filter (TR-10-9 §17 / RFC 4570), session consistency,
and `c=` destination cross-checked against the wire.

## Time Domains

The toolkit distinguishes three independent time bases:

1. **RTP timestamps** — constant per-frame increments in the 90 kHz video
   clock (or sample-rate audio clock). Not wall-clock.
2. **Sender Reference Clock (SR NTP)** — PTP truncated timestamp
   (seconds + nanoseconds) per VSF TR-10-1 §8.7.
3. **PCAP capture time** — the capturing machine's wall clock,
   independent of the sender's clock.

Many validation rules cross-correlate these. The HRD-TIME-EQC3 check, for
instance, requires PCAP first-packet times to be no earlier than the
HRD eq (C-3) lower bound expressed in capture-time units relative to AU 0.

## Reference Documents

- VSF TR-10-1 (IPMX System Timing and Definitions)
- VSF TR-10-5 (IPMX HDCP Key Exchange Protocol)
- VSF TR-10-7 (IPMX Sender Reports)
- VSF TR-10-9 (IPMX Compressed Video RTP Transport)
- VSF TR-10-11 / TR-10-12 (IPMX Audio)
- VSF TR-10-13 (IPMX Privacy Encryption Protocol)
- VSF TR-10-15a / -15b / -15c (IPMX JPEG XS / HEVC / H.264 Profiles)
- SMPTE ST 2110-10 / -20 / -21 / -22 / -30 / -31
- ITU-T H.265, ITU-T H.264, ISO/IEC 21122 (JPEG XS)
- RFC 4175, 6184, 7798, 8285, 9134
- NMOS BCP-006

## License

Apache License 2.0 — Copyright © 2026 Matrox Graphics Inc.
