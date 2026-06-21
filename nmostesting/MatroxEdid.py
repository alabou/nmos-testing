# Minimal EDID parser for video preferred timing and audio sample rates.
#
# References:
#   VESA E-EDID Release A, Revision 2 (base 128-byte block, DTD at 0x36)
#   CTA-861-G (Extension block tag 0x02, Short Audio Descriptors)


# Sample-rate bitfield in byte 2 of a Short Audio Descriptor (CTA-861).
_SAD_SAMPLE_RATES_KHZ = [
    (0x01, 32000),
    (0x02, 44100),
    (0x04, 48000),
    (0x08, 88200),
    (0x10, 96000),
    (0x20, 176400),
    (0x40, 192000),
]

# LPCM bit-depth bitfield in byte 3 of an LPCM Short Audio Descriptor.
_SAD_LPCM_BIT_DEPTHS = [
    (0x01, 16),
    (0x02, 20),
    (0x04, 24),
]


class MatroxEdid:
    """Parsed view of a raw EDID blob.

    Use parse_edid(raw) to construct. Query with:
        obj.preferred_resolution()  -> (width, height, fps) or None
        obj.audio_sample_rates()    -> sorted list of ints (Hz)
    """

    def __init__(self, raw):
        self.raw = bytes(raw)
        self.base = self.raw[:128]
        self.extensions = []
        # EDID 1.3+: byte 126 holds the number of 128-byte extension blocks.
        ext_count = self.base[126] if len(self.base) == 128 else 0
        for i in range(ext_count):
            start = 128 * (i + 1)
            end = start + 128
            if end <= len(self.raw):
                self.extensions.append(self.raw[start:end])

    # -- validation ----------------------------------------------------------

    def is_valid_header(self):
        return self.base[:8] == b"\x00\xff\xff\xff\xff\xff\xff\x00"

    def _checksum_ok(self, block):
        return len(block) == 128 and (sum(block) & 0xFF) == 0

    def checksums_ok(self):
        if not self._checksum_ok(self.base):
            return False
        return all(self._checksum_ok(ext) for ext in self.extensions)

    # -- video: preferred timing --------------------------------------------

    def preferred_timing_fields(self):
        """Return a dict of the raw parsed fields from the first DTD at
        base offset 0x36, or None if the descriptor is not a DTD.
        Useful for debugging.
        """
        dtd = self.base[0x36:0x36 + 18]
        if len(dtd) != 18:
            return None
        pclk_10khz = dtd[0] | (dtd[1] << 8)
        if pclk_10khz == 0:
            return None
        h_active = dtd[2] | ((dtd[4] >> 4) << 8)
        h_blank = dtd[3] | ((dtd[4] & 0x0F) << 8)
        v_active = dtd[5] | ((dtd[7] >> 4) << 8)
        v_blank = dtd[6] | ((dtd[7] & 0x0F) << 8)
        h_total = h_active + h_blank
        v_total = v_active + v_blank
        interlaced = bool(dtd[17] & 0x80)
        return {
            "pixel_clock_hz": pclk_10khz * 10_000,
            "pixel_clock_10khz": pclk_10khz,
            "h_active": h_active,
            "h_blank": h_blank,
            "h_total": h_total,
            "v_active": v_active,
            "v_blank": v_blank,
            "v_total": v_total,
            "interlaced": interlaced,
            "dtd_bytes_hex": dtd.hex(),
        }

    def preferred_resolution(self):
        """Return (width, height, fps) from the first Detailed Timing
        Descriptor at base offset 0x36, or None if absent/invalid.

        fps is a float derived from pixel clock and total (active+blank)
        pixel/line counts. Interlaced timings report field rate (i.e.
        pixel_clock / (H_total * V_total_field)).
        """
        dtd = self.base[0x36:0x36 + 18]
        if len(dtd) != 18:
            return None

        pixel_clock_10khz = dtd[0] | (dtd[1] << 8)
        if pixel_clock_10khz == 0:
            # Not a DTD (could be a monitor descriptor starting with 00 00).
            return None
        pixel_clock_hz = pixel_clock_10khz * 10_000

        h_active = dtd[2] | ((dtd[4] >> 4) << 8)
        h_blank = dtd[3] | ((dtd[4] & 0x0F) << 8)
        v_active = dtd[5] | ((dtd[7] >> 4) << 8)
        v_blank = dtd[6] | ((dtd[7] & 0x0F) << 8)

        h_total = h_active + h_blank
        v_total = v_active + v_blank
        if h_total == 0 or v_total == 0:
            return None

        interlaced = bool(dtd[17] & 0x80)
        fps = pixel_clock_hz / (h_total * v_total)
        # For interlaced, pixel_clock/(H*V) already yields field rate; report
        # the frame rate as half so the caller sees e.g. 30 rather than 60 for
        # 1080i. Adjust to taste.
        if interlaced:
            fps = fps / 2.0
            reported_v = v_active * 2
        else:
            reported_v = v_active

        return (h_active, reported_v, fps)

    def matches_preferred_grain_rate(self, numerator, denominator):
        """Return True iff the preferred DTD's pixel clock matches the
        rational rate numerator/denominator at the DTD's H_total x V_total.

        Exact match (no float tolerance): the EDID stores pixel clock at
        10 kHz granularity, so the comparison is
            |pclk_10khz * 10_000 * den - H_total * V_total * num| <= 10_000 * den
        which allows only the unavoidable +/-1 unit of 10 kHz quantization.
        With this rule, 60/1 (clk 148500) and 60000/1001 (clk 148350) for
        1920x1080 @ 2200x1125 are correctly distinguished.
        """
        dtd = self.base[0x36:0x36 + 18]
        if len(dtd) != 18 or denominator == 0:
            return False
        pclk_10khz = dtd[0] | (dtd[1] << 8)
        if pclk_10khz == 0:
            return False
        h_active = dtd[2] | ((dtd[4] >> 4) << 8)
        h_blank = dtd[3] | ((dtd[4] & 0x0F) << 8)
        v_active = dtd[5] | ((dtd[7] >> 4) << 8)
        v_blank = dtd[6] | ((dtd[7] & 0x0F) << 8)
        h_total = h_active + h_blank
        v_total = v_active + v_blank
        if h_total == 0 or v_total == 0:
            return False
        encoded = pclk_10khz * 10_000 * denominator
        ideal = h_total * v_total * numerator
        return abs(encoded - ideal) <= 10_000 * denominator

    # -- audio: CTA-861 Short Audio Descriptors -----------------------------

    def _iter_cta_data_blocks(self):
        """Yield (block_type, payload_bytes) for each Data Block in every
        CTA-861 extension block present.
        """
        for ext in self.extensions:
            if len(ext) != 128 or ext[0] != 0x02:
                continue
            # ext[1] = revision, ext[2] = DTD offset (end of Data Block
            # Collection), ext[3] low 4 bits = DTD count, high 4 bits = flags.
            dtd_offset = ext[2]
            if dtd_offset == 0 or dtd_offset > 127:
                continue
            i = 4
            while i < dtd_offset:
                tag = ext[i]
                block_type = (tag >> 5) & 0x07
                block_len = tag & 0x1F
                payload = ext[i + 1:i + 1 + block_len]
                if len(payload) != block_len:
                    break
                yield block_type, payload
                i += 1 + block_len

    def short_audio_descriptors(self):
        """Return a list of dicts describing each SAD.

        Each dict: {'format': int, 'channels': int, 'sample_rates': [Hz...],
        and for LPCM (format=1) also 'bit_depths': [int...]}.
        """
        sads = []
        for block_type, payload in self._iter_cta_data_blocks():
            if block_type != 1:  # 1 = Audio Data Block
                continue
            # SADs are 3 bytes each.
            for j in range(0, len(payload) - 2, 3):
                b1, b2, b3 = payload[j], payload[j + 1], payload[j + 2]
                fmt = (b1 >> 3) & 0x0F
                channels = (b1 & 0x07) + 1
                rates = [hz for mask, hz in _SAD_SAMPLE_RATES_KHZ if b2 & mask]
                sad = {
                    "format": fmt,
                    "channels": channels,
                    "sample_rates": rates,
                }
                if fmt == 1:  # LPCM
                    sad["bit_depths"] = [
                        bd for mask, bd in _SAD_LPCM_BIT_DEPTHS if b3 & mask
                    ]
                sads.append(sad)
        return sads

    def audio_sample_rates(self):
        """Union of sample rates (Hz) declared across all Short Audio
        Descriptors in all CTA-861 extension blocks. Sorted ascending.
        Empty list if no CTA Audio Data Block is present.
        """
        rates = set()
        for sad in self.short_audio_descriptors():
            rates.update(sad["sample_rates"])
        return sorted(rates)


def _coerce_to_bytes(raw):
    """Accept bytes, bytearray, iterable of ints, or a hex string (with or
    without whitespace / 0x prefixes).
    """
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    if isinstance(raw, str):
        s = raw.strip().replace("0x", "").replace(",", " ")
        s = "".join(s.split())
        return bytes.fromhex(s)
    return bytes(raw)


def parse_edid(raw):
    """Create a MatroxEdid from a raw EDID.

    `raw` may be bytes/bytearray, a hex string, or an iterable of ints.
    """
    return MatroxEdid(_coerce_to_bytes(raw))
