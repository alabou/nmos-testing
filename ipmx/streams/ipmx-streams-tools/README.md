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

## Stream descriptor presets (`--cfg`)

Every validator accepts `--cfg <file>` to seed the per-stream
expected-value flags from a descriptor in [`cfg/`](cfg/) instead of typing
them one by one. The argument takes a path or a bare name resolved against
`cfg/` (e.g. `--cfg Test1080p59YUVPTP`). A cfg value only fills a flag that is
still unset — an explicit flag on the command line always wins. `--cfg` never
sets policy flags (`--cmax`, `--hrd-timing`, `--hkep`, `--pep`) or `--sdp`;
keep passing those explicitly.

The cfg files are INI-style `key=value`. Fields map to flags as follows:

| cfg field | flag(s) set | validators |
|-----------|-------------|------------|
| `exactframerate` | `--exactframerate` | jxsv, raw, h264, h265 |
| `width` / `height` | `--width` / `--height` | jxsv, raw, h264, h265 |
| `sampling` | `--sampling` | jxsv, raw, h264, h265 |
| `depth` | `--bit-depth` | jxsv, raw, h264, h265 |
| `rtpclock` | `--sample-rate` | pcm, am824 |
| `samplesize` (channel count) | `--nchan` | pcm, am824 |
| `samplefmt` (L16/L20/L24) | `--bit-depth` + `--sample-size` | pcm (both), am824 (`--sample-size`) |
| `ptime` | `--ptime` | pcm, am824 |

`type`/`PTP` are not flags (`type` is a media sanity-check). For H.264/H.265 a
non-YCbCr `sampling` (e.g. `RGB`) is skipped with a warning, since those codecs
carry YCbCr only. `--measured-sample-rate` is a measured value and is not set
from a cfg.

```bash
# H.265, parameters from a descriptor; SDP and policy flags still explicit
python3 ipmx_h265_validate_pcap.py capture.pcap \
    --cfg Test1080p59YUVPTP --sdp transport.sdp --cmax --hrd-timing

# PCM audio
python3 ipmx_pcm_validate_pcap.py capture.pcap --cfg TestL24-2 --sdp transport.sdp
```

For `jxsv` and `raw`, `--width/--height/--sampling/--bit-depth` are
authoritative expected values cross-checked against the RTCP Sender-Report MIB
(`TR-10-1-VP-XVAL`), behaving exactly like `--exactframerate` — untestable when
omitted, exact-match-or-fail when supplied.

## Profile-mode switches

Some requirement families apply only when a specific profile mode is under test.
These are opt-in, authoritative switches — the mode's requirements are only
checked (and only listed by `--list-requirements`) when the switch is given:

| Validator | Switch | Enables (in place of the base-profile requirements) |
|-----------|--------|---------|
| `jxsv` | `--tdc` | IPMX-JPEG-XS-TDC profile-mode requirements (`TR-10-15a` TDC), instead of the base High444.12 profile requirements |
| `h265` | `--444` | IPMX HEVC 4:4:4 Profile Mode requirements (`TR-10-15b-131..134`), instead of the base `TR-10-15b-123`/`126` Main/Main10 4:2:0 requirements |

A single capture exhibits one profile, so the base profile and the profile mode
are validated from **separate captures**: run **without** the switch to validate
the base profile, and **with** it to validate the mode. Each mode's "shall also
be compliant with the base profile" requirement is untestable from one capture
and is reported as such (validate the base leg from the without-switch run).

## Listing requirements (`--list-requirements`)

Every validator accepts `--list-requirements` to print its full requirement
catalogue (ID, level, text, grouped by SHALL/SHOULD/INFO) and exit, without
needing a PCAP. The list reflects the profile-mode switches above — e.g.
`ipmx_h265_validate_pcap.py --444 --list-requirements` includes the 4:4:4
Profile Mode requirements, and `--list-requirements` alone omits them.

Rows that can never be tested from a PCAP (receiver / NMOS / decoder
capabilities, and similar sender declarations) are marked **`NA`**, and the
header reports the split, e.g. `70 requirements (53 testable, 17 NA)`. An
unmarked row has a real check that yields PASS / FAIL / CANNOT_TEST at run time
depending on the capture. (`NA` is the `lambda _: untestable(...)` sentinel in
the requirement tables.)

```bash
python3 ipmx_h265_validate_pcap.py --list-requirements
python3 ipmx_jxsv_validate_pcap.py --tdc --list-requirements
```

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
