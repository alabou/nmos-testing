#!/usr/bin/env python3
import sys
from collections import defaultdict, deque
from typing import Dict, Deque, Tuple, Optional, List

# Packet iterator; we only use it to access UDP payload bytes.
#   pip install pyshark
import pyshark

import asyncio
loop = asyncio.ProactorEventLoop()
asyncio.set_event_loop(loop)

from datetime import datetime  # Add this import at the top of your file
from typing import Optional

USAGE = "Usage: python TP-10-1Sec13.3b.py <config.cfg> <file.pcap>"

def load_config(path: str):
    cfg = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if not raw or raw.startswith(("#", ";", "//")):
                continue
            if "=" in raw:
                k, v = raw.split("=", 1)
                cfg[k.strip().lower()] = v.strip()
    return cfg

def parse_fraction_or_float(s: str) -> Optional[float]:
    """
    Parse a string as either a float/integer or a 'numerator/denominator' fraction.
    Examples: '60' -> 60.0, '60000/1001' -> ~59.94
    """
    if s is None:
        return None
    s = s.strip()
    if not s:
        return None
    if "/" in s:
        parts = s.split("/", 1)
        try:
            num = float(parts[0].strip())
            den = float(parts[1].strip())
            if den == 0:
                return None
            return num / den
        except Exception:
            return None
    else:
        try:
            return float(s)
        except Exception:
            return None

# -------- expected tick/time helpers --------
def compute_expected_ticks(cfg: Dict[str, str]) -> Optional[float]:
    """
    Expected SR_DIFF in RTP ticks:
      - video: rtpclock / exactframerate
      - audio: rtpclock * 0.01
    """
    t = cfg.get("type", "").lower()
    try:
        rtpclock = float(cfg.get("rtpclock", "0"))
    except Exception:
        return None

    if t == "video":
        fr = parse_fraction_or_float(cfg.get("exactframerate", ""))
        if fr and rtpclock > 0:
            return rtpclock / fr
        return None
    elif t == "audio":
        return rtpclock * 0.01 if rtpclock > 0 else None
    return None

def compute_expected_time_interval(cfg: Dict[str, str]) -> Optional[float]:
    """
    Expected SR time spacing in seconds:
      - video: 1 / exactframerate
      - audio: 0.01
    """
    t = cfg.get("type", "").lower()
    if t == "video":
        fr = parse_fraction_or_float(cfg.get("exactframerate", ""))
        if fr and fr > 0:
            return 1.0 / fr
        return None
    elif t == "audio":
        return 0.01
    return None

# -------- UDP payload helpers --------
def udp_payload_bytes(pkt) -> Optional[bytes]:
    if 'udp' not in pkt:
        return None
    hex_str = None
    for name in ('payload', 'udp_payload'):
        if hasattr(pkt.udp, name):
            hex_str = str(getattr(pkt.udp, name))
            break
    if not hex_str:
        return None
    try:
        hex_str = hex_str.replace(":", "").replace(" ", "")
        if len(hex_str) % 2 != 0:
            return None
        return bytes.fromhex(hex_str)
    except Exception:
        return None

def pkt_time_seconds(pkt) -> Optional[float]:
    """Get packet capture time in seconds (float) from the pcap."""
    def parse_time_str(ts_str: str) -> Optional[float]:
        """Helper to parse ISO string or float."""
        if ts_str is None:
            return None
        try:
            return float(ts_str)  # If already numeric string/float
        except (ValueError, TypeError):
            pass
        
        # Handle ISO format: replace 'Z' with '+00:00' for UTC
        if isinstance(ts_str, str) and ts_str.endswith('Z'):
            ts_str = ts_str[:-1] + '+00:00'
        
        try:
            dt = datetime.fromisoformat(ts_str)
            return dt.timestamp()  # Returns float Unix time
        except ValueError:
            return None

    # Try sniff_timestamp first
    if hasattr(pkt, "sniff_timestamp") and pkt.sniff_timestamp is not None:
        result = parse_time_str(pkt.sniff_timestamp)
        if result is not None:
            #print("Using sniff_timestamp")
            return result

    # Fallback to frame_info.time_epoch
    if hasattr(pkt, "frame_info") and pkt.frame_info and hasattr(pkt.frame_info, "time_epoch"):
        result = parse_time_str(pkt.frame_info.time_epoch)
        if result is not None:
            #print("Using frame_info.time_epoch")
            return result

    print("Failed to parse any timestamp")
    return None

# -------- RTCP parsing (RFC 3550) --------
def parse_rtcp_compound_for_srs(b: bytes) -> List[Tuple[int, int]]:
    """Return list of (ssrc, sr_rtp_ts) for every RTCP SR in this UDP payload."""
    out: List[Tuple[int, int]] = []
    i, n = 0, len(b)
    while i + 4 <= n:
        v_p_rc = b[i]
        pt = b[i+1]
        length_words_minus1 = int.from_bytes(b[i+2:i+4], 'big')
        block_len = (length_words_minus1 + 1) * 4
        if block_len <= 0 or i + block_len > n:
            break
        version = (v_p_rc >> 6) & 0x03
        if version == 2 and 192 <= pt <= 223:
            if pt == 200 and block_len >= 24:
                ssrc = int.from_bytes(b[i+4:i+8], 'big')
                rtp_ts = int.from_bytes(b[i+16:i+20], 'big')
                out.append((ssrc, rtp_ts))
        i += block_len
    return out

# -------- RTP parsing (RFC 3550) --------
def try_parse_rtp(b: bytes) -> Optional[Tuple[int, int]]:
    """Parse RTP header. Returns (timestamp, ssrc) if it looks like RTP v2 (and PT < 192)."""
    if not b or len(b) < 12:
        return None
    vpxcc = b[0]
    m_pt = b[1] & 0x7F
    version = (vpxcc >> 6) & 0x03
    if version != 2:
        return None
    if m_pt >= 192:  # RTCP PT range
        return None
    csrc_count = vpxcc & 0x0F
    header_len = 12 + 4 * csrc_count
    if len(b) < header_len:
        return None
    ts = int.from_bytes(b[4:8], 'big')
    ssrc = int.from_bytes(b[8:12], 'big')
    return (ts, ssrc)

def main():
    if len(sys.argv) != 3:
        print(USAGE, file=sys.stderr)
        sys.exit(1)

    cfg_path = sys.argv[1]
    pcap_path = sys.argv[2]

    try:
        cfg = load_config(cfg_path)
    except Exception as e:
        print(f"Error reading config: {e}", file=sys.stderr)
        sys.exit(2)

    expected_ticks = compute_expected_ticks(cfg)
    expected_time = compute_expected_time_interval(cfg)

    try:
        cap = pyshark.FileCapture(
            pcap_path,
            keep_packets=False,   # stream
            use_json=True,
            include_raw=True,
            display_filter="udp && ip",
        )
    except Exception as e:
        print(f"Error opening pcap: {e}", file=sys.stderr)
        sys.exit(3)

    # State for streaming logic
    last_rtp_ts_by_ssrc: Dict[int, int] = {}
    last_sr_ts_by_ssrc: Dict[int, int] = {}
    last_sr_time_by_ssrc: Dict[int, float] = {}  # capture time of previous SR per SSRC

    # each pending item: (sr_ts, sr_diff_desc, prev_desc|prev_match, sr_time_delta_desc)
    pending_srs_by_ssrc: Dict[int, Deque[Tuple[int, str, str, str]]] = defaultdict(deque)

    # Accumulators
    sr_diff_values: List[int] = []          # numeric SR_DIFFs (ticks)
    sr_time_delta_values: List[float] = []  # numeric SR_TIME_DELTA_SEC (seconds)

    # Overall PASS/FAIL trackers
    prev_ok_all = True
    next_ok_all = True

    def print_sr_line(sr_ts: int, sr_diff_desc: str, sr_time_delta_desc: str,
                      prev_desc: str, prev_match: str, next_desc: str, next_match: str):
        print(
            f"(TP10-1, sec 13.3b) "
            f"SR_RTP={sr_ts} SR_DIFF={sr_diff_desc} SR_TIME_DELTA_SEC={sr_time_delta_desc} | "
            f"prev_rtp_ts={prev_desc} -> {prev_match} | "
            f"next_rtp_ts={next_desc} -> {next_match}"
        )

    # Streaming pass
    for pkt in cap:
        b = udp_payload_bytes(pkt)
        if not b:
            continue

        pt = b[1] if len(b) >= 2 else 0
        version = (b[0] >> 6) & 0x03 if len(b) >= 1 else 0

        if version == 2 and 192 <= pt <= 223:
            # RTCP compound; handle all SRs immediately
            sr_wall_time = pkt_time_seconds(pkt)  # capture time of this UDP frame
            for (ssrc, sr_ts) in parse_rtcp_compound_for_srs(b):
                # prev RTP (before SR) from this SSRC
                if ssrc in last_rtp_ts_by_ssrc:
                    prev_ts = last_rtp_ts_by_ssrc[ssrc]
                    prev_desc = str(prev_ts)
                    prev_match = "MATCH" if prev_ts == sr_ts else "DIFF"
                    if ssrc in last_sr_ts_by_ssrc and prev_match != "DIFF":
                        prev_ok_all = False
                else:
                    prev_desc = "N/A"
                    prev_match = "N/A"
                    if ssrc in last_sr_ts_by_ssrc:
                        prev_ok_all = False

                # SR_DIFF vs previous SR (per SSRC)
                if ssrc in last_sr_ts_by_ssrc:
                    sr_diff_val = sr_ts - last_sr_ts_by_ssrc[ssrc]
                    sr_diff_desc = str(sr_diff_val)
                    sr_diff_values.append(sr_diff_val)
                else:
                    sr_diff_desc = "N/A"

                # SR time delta vs previous SR (per SSRC)
                if sr_wall_time is not None and ssrc in last_sr_time_by_ssrc:
                    dt = sr_wall_time - last_sr_time_by_ssrc[ssrc]
                    if dt >= 0:
                        sr_time_delta_values.append(dt)
                    sr_time_delta_desc = f"{dt:.6f}"
                else:
                    sr_time_delta_desc = "N/A"

                # update last SR seen for this SSRC
                last_sr_ts_by_ssrc[ssrc] = sr_ts
                if sr_wall_time is not None:
                    last_sr_time_by_ssrc[ssrc] = sr_wall_time

                # queue this SR awaiting the next RTP for this SSRC
                pending_srs_by_ssrc[ssrc].append((sr_ts, sr_diff_desc, f"{prev_desc}|{prev_match}", sr_time_delta_desc))
            continue

        # RTP packet (by bytes)
        r = try_parse_rtp(b)
        if r:
            rtp_ts, ssrc = r
            last_rtp_ts_by_ssrc[ssrc] = rtp_ts
            if pending_srs_by_ssrc[ssrc]:
                while pending_srs_by_ssrc[ssrc]:
                    sr_ts, sr_diff_desc, prev_bundle, sr_time_delta_desc = pending_srs_by_ssrc[ssrc].popleft()
                    prev_desc, prev_match = prev_bundle.split("|", 1)
                    next_desc = str(rtp_ts)
                    next_match = "MATCH" if rtp_ts == sr_ts else "DIFF"
                    if next_match != "MATCH":
                        next_ok_all = False
                    print_sr_line(sr_ts, sr_diff_desc, sr_time_delta_desc, prev_desc, prev_match, next_desc, next_match)

    # Flush any SRs that never saw a subsequent RTP (these fail next-match condition)
    for ssrc, dq in pending_srs_by_ssrc.items():
        while dq:
            sr_ts, sr_diff_desc, prev_bundle, sr_time_delta_desc = dq.popleft()
            prev_desc, prev_match = prev_bundle.split("|", 1)
            next_ok_all = False
            print_sr_line(sr_ts, sr_diff_desc, sr_time_delta_desc, prev_desc, prev_match, "N/A", "N/A")

    try:
        cap.close()
    except Exception:
        pass

    # ---- Final averages ----
    # 1) SR_DIFF (ticks) — use only an even number of samples; if odd, drop the last one
    if sr_diff_values:
        usable_n = len(sr_diff_values)
        if usable_n % 2 == 1:
            usable_n -= 1
        if usable_n >= 2:
            subset = sr_diff_values[:usable_n]
            avg_ticks = sum(subset) / float(usable_n)
            result = "N/A"
            if expected_ticks is not None and avg_ticks == expected_ticks:
                result = "PASS"
            elif expected_ticks is not None:
                result = "FAIL"
            print(f"(TP10-1, sec 13.3b) AVG_SR_DIFF={avg_ticks} SAMPLES_USED={usable_n} EXPECTED={expected_ticks if expected_ticks is not None else 'N/A'} RESULT={result}")
        else:
            print(f"(TP10-1, sec 13.3b) AVG_SR_DIFF=N/A SAMPLES_USED={usable_n} EXPECTED={expected_ticks if expected_ticks is not None else 'N/A'} RESULT=N/A")
    else:
        print(f"(TP10-1, sec 13.3b) AVG_SR_DIFF=N/A SAMPLES_USED=0 EXPECTED={expected_ticks if expected_ticks is not None else 'N/A'} RESULT=N/A")

    # 2) SR_TIME_DELTA_SEC (seconds) — separate line
    if sr_time_delta_values:
        avg_time = sum(sr_time_delta_values) / float(len(sr_time_delta_values))
        if expected_time is not None:
            diff = avg_time - expected_time
            print(f"(TP10-1, sec 13.3b) AVG_SR_TIME_DELTA_SEC={avg_time:.6f} EXPECTED={expected_time:.6f} DIFF={diff:.6f}")
        else:
            print(f"(TP10-1, sec 13.3b) AVG_SR_TIME_DELTA_SEC={avg_time:.6f} EXPECTED=N/A DIFF=N/A")
    else:
        if expected_time is not None:
            print(f"(TP10-1, sec 13.3b) AVG_SR_TIME_DELTA_SEC=N/A EXPECTED={expected_time:.6f} DIFF=N/A")
        else:
            print(f"(TP10-1, sec 13.3b) AVG_SR_TIME_DELTA_SEC=N/A EXPECTED=N/A DIFF=N/A")

    # 3) Overall SR_RTP_TS PASS/FAIL line
    overall_result = "PASS" if (prev_ok_all and next_ok_all) else "FAIL"
    print(f"(TP10-1, sec 13.3b) SR_RTP_TS RESULT={overall_result}")

if __name__ == "__main__":
    main()
