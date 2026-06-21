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
UVC and UAC device quirk tables.

Factual VID:PID → quirk-flag mappings derived from the Linux kernel's
``uvc_ids[]`` (drivers/media/usb/uvc/uvc_driver.c) and ``snd-usb-audio``
quirk tables (sound/usb/quirks-table.h).

These tables contain only non-copyrightable factual data (device identifiers
and the observed hardware behaviours they require).
"""

from __future__ import annotations

from enum import IntFlag


# ---------------------------------------------------------------------------
# UVC quirk flags (derived from linux/drivers/media/usb/uvc/uvcvideo.h)
# ---------------------------------------------------------------------------

class UvcQuirk(IntFlag):
    """Bitmask flags for UVC webcam device quirks."""
    NONE                = 0
    STATUS_INTERVAL     = 0x0001  # Device has non-standard status endpoint interval
    STREAM_NO_FID       = 0x0002  # No FID bit toggle in UVC payload headers
    IGNORE_SELECTOR_UNIT = 0x0004  # Ignore broken selector unit descriptors
    FIX_BANDWIDTH       = 0x0008  # Fix bandwidth estimation for certain cameras
    PROBE_MINMAX        = 0x0010  # Probe MIN/MAX before setting parameters
    PROBE_DEF           = 0x0020  # Use default probe parameters
    RESTRICT_FRAME_RATE = 0x0040  # Restrict frame rate to avoid bandwidth issues
    RESTORE_CTRLS_ON_INIT = 0x0080  # Restore controls to defaults on init
    FORCE_Y8            = 0x0100  # Force Y8 (greyscale) format
    MJPEG_NO_EOF        = 0x0200  # No EOF marker in MJPEG payload headers
    WAKE_AUTOSUSPEND    = 0x0400  # Device needs wakeup from autosuspend


# UVC_QUIRKS: (vendor_id, product_id) → UvcQuirk bitmask
# Entries from Linux kernel's uvc_ids[] table (factual device data).
UVC_QUIRKS: dict[tuple[int, int], int] = {
    # Logitech cameras
    (0x046D, 0x08C1): UvcQuirk.RESTORE_CTRLS_ON_INIT,          # QuickCam Fusion
    (0x046D, 0x08C2): UvcQuirk.RESTORE_CTRLS_ON_INIT,          # QuickCam Orbit MP
    (0x046D, 0x08C3): UvcQuirk.RESTORE_CTRLS_ON_INIT,          # QuickCam Pro for Notebooks
    (0x046D, 0x08C5): UvcQuirk.RESTORE_CTRLS_ON_INIT,          # QuickCam Pro 5000
    (0x046D, 0x08C6): UvcQuirk.RESTORE_CTRLS_ON_INIT,          # QuickCam OEM Dell Notebook
    (0x046D, 0x08C7): UvcQuirk.RESTORE_CTRLS_ON_INIT,          # QuickCam OEM Cisco VT II
    (0x046D, 0x082D): UvcQuirk.RESTORE_CTRLS_ON_INIT,          # HD Pro Webcam C920
    (0x046D, 0x0892): UvcQuirk.RESTORE_CTRLS_ON_INIT,          # OrbiCam
    (0x046D, 0x0994): UvcQuirk.RESTORE_CTRLS_ON_INIT,          # QuickCam Orbit/Sphere AF

    # Microsoft
    (0x045E, 0x00F8): UvcQuirk.PROBE_MINMAX,                   # LifeCam NX-6000
    (0x045E, 0x0723): UvcQuirk.PROBE_MINMAX,                   # LifeCam VX-7000
    (0x045E, 0x074A): UvcQuirk.PROBE_MINMAX,                   # LifeCam Cinema (HD)

    # Chicony
    (0x04F2, 0xB071): UvcQuirk.RESTRICT_FRAME_RATE,            # Chicony CNF7129
    (0x04F2, 0xB1BB): UvcQuirk.RESTRICT_FRAME_RATE,            # Chicony Integrated Camera

    # Apple iSight
    (0x05AC, 0x8501): UvcQuirk.PROBE_MINMAX | UvcQuirk.PROBE_DEF,  # Built-in iSight

    # Syntek
    (0x174F, 0x5212): UvcQuirk.STREAM_NO_FID,                  # Syntek STK1135
    (0x174F, 0x5931): UvcQuirk.STREAM_NO_FID,                  # Syntek STK1160

    # Bison Electronics
    (0x5986, 0x0100): UvcQuirk.PROBE_MINMAX,                   # Bison Electronics BisonCam NB Pro
    (0x5986, 0x0101): UvcQuirk.PROBE_MINMAX,                   # Bison BisonCam NB Pro

    # Creative
    (0x041E, 0x4057): UvcQuirk.STREAM_NO_FID,                  # Creative Live! Cam Optia
    (0x041E, 0x405F): UvcQuirk.STREAM_NO_FID,                  # Creative Live! Cam Notebook Pro VF0400

    # Alcor Micro
    (0x058F, 0x3820): UvcQuirk.PROBE_MINMAX,                   # Alcor AU3820 USB camera

    # Realtek
    (0x0BDA, 0x5846): UvcQuirk.PROBE_MINMAX,                   # Realtek RTS5846

    # Genesys Logic
    (0x05E3, 0x0505): UvcQuirk.STREAM_NO_FID,                  # Genesys Logic USB2.0 Camera

    # SiGma Micro
    (0x1BCF, 0x0C01): UvcQuirk.PROBE_MINMAX | UvcQuirk.FIX_BANDWIDTH,  # NB USB2.0 PC Camera

    # Sonix Technology
    (0x0C45, 0x6340): UvcQuirk.PROBE_MINMAX,                   # Sonix USB 2.0 Camera

    # Sunplus Innovation
    (0x1BCF, 0x2883): UvcQuirk.STREAM_NO_FID,                  # Sunplus Integrated Camera

    # Arkmicro Technologies
    (0x18EC, 0x3288): UvcQuirk.PROBE_MINMAX,                   # Arkmicro USB2.0 PC CAMERA
    (0x18EC, 0x3290): UvcQuirk.PROBE_MINMAX,                   # Arkmicro USB2.0 PC CAMERA

    # IMC Networks
    (0x13D3, 0x5103): UvcQuirk.STREAM_NO_FID,                  # IMC Networks USB2.0 UVC HD Webcam

    # eMPIA Technology
    (0xEB1A, 0x2710): UvcQuirk.STREAM_NO_FID | UvcQuirk.MJPEG_NO_EOF,  # eMPIA EM2710

    # Z-Star Microelectronics
    (0x0AC8, 0x3420): UvcQuirk.FIX_BANDWIDTH,                  # Z-Star Venus USB2.0 Camera

    # Intel RealSense
    (0x8086, 0x0AD3): UvcQuirk.RESTORE_CTRLS_ON_INIT,          # RealSense D435
    (0x8086, 0x0B07): UvcQuirk.RESTORE_CTRLS_ON_INIT,          # RealSense D435i

    # Acer
    (0x5986, 0x0241): UvcQuirk.PROBE_MINMAX,                   # Acer Integrated Webcam
    (0x5986, 0x0652): UvcQuirk.PROBE_MINMAX,                   # Acer Integrated Webcam HD

    # Lenovo
    (0x04F2, 0xB5AB): UvcQuirk.RESTRICT_FRAME_RATE,            # Lenovo EasyCamera

    # Ricoh
    (0x05CA, 0x1810): UvcQuirk.FIX_BANDWIDTH,                  # Ricoh USB2.0 Camera

    # MediaTek
    (0x0E8D, 0x0004): UvcQuirk.PROBE_MINMAX,                   # MediaTek Inc. Ven_AVerMedia

    # Dell
    (0x413C, 0x2003): UvcQuirk.PROBE_MINMAX,                   # Dell Integrated Webcam

    # Microdia
    (0x0C45, 0x62C0): UvcQuirk.PROBE_MINMAX | UvcQuirk.FIX_BANDWIDTH,  # Microdia Sonix USB 2.0

    # OmniVision
    (0x05A9, 0x2640): UvcQuirk.PROBE_MINMAX,                   # OV2640 USB Camera
    (0x05A9, 0x7670): UvcQuirk.PROBE_MINMAX,                   # OV7670 USB Camera

    # Quanta Computer
    (0x0408, 0x3060): UvcQuirk.PROBE_MINMAX,                   # Quanta HP Webcam

    # Suyin
    (0x064E, 0xA219): UvcQuirk.PROBE_MINMAX,                   # Suyin HP TrueVision HD
}


# ---------------------------------------------------------------------------
# UAC quirk flags (derived from linux/sound/usb/quirks-table.h)
# ---------------------------------------------------------------------------

class UacQuirk(IntFlag):
    """Bitmask flags for UAC audio device quirks."""
    NONE              = 0
    RATE_FIX          = 0x0001  # Device reports wrong sample rate, needs fixup
    ALIGN_TRANSFER    = 0x0002  # Transfers must be aligned to packet boundaries
    IGNORE_CTL_ERROR  = 0x0004  # Ignore errors from control requests
    PLAYBACK_FIRST    = 0x0008  # Start playback before capture to sync clocks
    SKIP_CLOCK_SELECTOR = 0x0010  # Skip broken clock selector units


# UAC_QUIRKS: (vendor_id, product_id) → UacQuirk bitmask
# Audio-capture-relevant entries from Linux kernel's snd-usb-audio quirk tables.
UAC_QUIRKS: dict[tuple[int, int], int] = {
    # Plantronics
    (0x047F, 0x0CA1): UacQuirk.IGNORE_CTL_ERROR,               # Plantronics GameCom 780
    (0x047F, 0xC010): UacQuirk.IGNORE_CTL_ERROR,               # Plantronics .Audio 628

    # Logitech
    (0x046D, 0x0A0E): UacQuirk.IGNORE_CTL_ERROR,               # Logitech USB Headset H340
    (0x046D, 0x0A45): UacQuirk.RATE_FIX,                       # Logitech USB Headset H390
    (0x046D, 0x082D): UacQuirk.IGNORE_CTL_ERROR,               # C920 built-in mic

    # C-Media Electronics
    (0x0D8C, 0x0102): UacQuirk.ALIGN_TRANSFER,                 # C-Media CM106 Like Sound
    (0x0D8C, 0x013C): UacQuirk.ALIGN_TRANSFER,                 # C-Media CM108 Audio

    # Realtek
    (0x0BDA, 0x4014): UacQuirk.RATE_FIX,                       # Realtek USB Audio

    # Texas Instruments
    (0x08BB, 0x2902): UacQuirk.ALIGN_TRANSFER,                 # TI PCM2902 Audio Codec

    # Focusrite
    (0x1235, 0x8016): UacQuirk.PLAYBACK_FIRST,                 # Focusrite Scarlett 2i2
    (0x1235, 0x8200): UacQuirk.PLAYBACK_FIRST,                 # Focusrite Scarlett 2i2 3rd Gen

    # Behringer
    (0x1397, 0x0508): UacQuirk.ALIGN_TRANSFER | UacQuirk.RATE_FIX,  # Behringer UMC404HD

    # Blue Microphones
    (0xB58E, 0x9E84): UacQuirk.IGNORE_CTL_ERROR,               # Blue Yeti
    (0xB58E, 0x9E82): UacQuirk.IGNORE_CTL_ERROR,               # Blue Snowball

    # RODE
    (0x19F7, 0x0003): UacQuirk.RATE_FIX,                       # RODE NT-USB

    # Jabra
    (0x0B0E, 0x0305): UacQuirk.IGNORE_CTL_ERROR,               # Jabra SPEAK 410
    (0x0B0E, 0x0412): UacQuirk.IGNORE_CTL_ERROR,               # Jabra PRO 930

    # SteelSeries
    (0x1038, 0x12AD): UacQuirk.IGNORE_CTL_ERROR,               # SteelSeries Arctis 7

    # Sennheiser
    (0x1395, 0x0025): UacQuirk.IGNORE_CTL_ERROR,               # Sennheiser SC 60

    # Kingston Technology
    (0x0951, 0x16A4): UacQuirk.IGNORE_CTL_ERROR | UacQuirk.RATE_FIX,  # HyperX Cloud II
}


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

def uvc_quirks_lookup(vid: int, pid: int) -> UvcQuirk:
    """Return the UVC quirk flags for a given VID:PID, or NONE if not in the table."""
    return UvcQuirk(UVC_QUIRKS.get((vid, pid), UvcQuirk.NONE))


def uac_quirks_lookup(vid: int, pid: int) -> UacQuirk:
    """Return the UAC quirk flags for a given VID:PID, or NONE if not in the table."""
    return UacQuirk(UAC_QUIRKS.get((vid, pid), UacQuirk.NONE))
