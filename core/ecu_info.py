"""
ecu_info.py - ECU identification: auto-detect family, extract VIN, SW, HW.

Entry point
-----------
>>> extractor = ECUInfoExtractor()
>>> report    = extractor.detect(rom_bytes)
>>> print(report)
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from formats.ecu_profiles import ECUProfile, ECUFamily, get_profile, ALL_PROFILES


# ---------------------------------------------------------------------------
# ISO 3779 VIN validator
# ---------------------------------------------------------------------------

_VIN_RE = re.compile(
    rb"(?<![A-HJ-NPR-Z0-9])"   # no preceding alphanumeric (word boundary)
    rb"[A-HJ-NPR-Z]{1}"        # WMI first char (letter, no I/O/Q)
    rb"[A-HJ-NPR-Z0-9]{2}"     # WMI remaining 2 chars
    rb"[A-HJ-NPR-Z0-9]{5}"     # VDS (vehicle descriptor section)
    rb"[0-9X]{1}"               # check digit
    rb"[A-HJ-NPR-Z0-9]{2}"     # MY + plant code
    rb"[A-HJ-NPR-Z0-9]{6}"     # sequential number
    rb"(?![A-HJ-NPR-Z0-9])"    # no following alphanumeric
)

# Bosch software / hardware part number patterns
# Examples: "0 261 207 694"  "0 281 015 xxx"
_BOSCH_SW_RE = re.compile(rb"0 2[0-9]{2} [0-9]{3} [0-9]{3}")
_BOSCH_HW_RE = re.compile(rb"0 2[0-9]{2} 1[0-9]{2} [0-9]{3}")

# Generic software version patterns (e.g. "SW:1.23.456" or "SW 5678")
_SW_GENERIC_RE = re.compile(rb"SW[: ]?([0-9][0-9A-Z._\-]{2,19})", re.IGNORECASE)
_HW_GENERIC_RE = re.compile(rb"HW[: ]?([0-9][0-9A-Z._\-]{2,19})", re.IGNORECASE)

# Calibration / ROM ID (often 20-char ASCII near end of ROM)
_CAL_ID_RE = re.compile(rb"[A-Z0-9]{4}[A-Z0-9_\-]{4,16}")


# ---------------------------------------------------------------------------
# ECU Report
# ---------------------------------------------------------------------------

@dataclass
class ECUReport:
    """Full identification report for an ECU binary.

    Attributes
    ----------
    profile : ECUProfile | None
        Matched profile, or None if ECU is unrecognised.
    family : ECUFamily
    file_size : int
        ROM size in bytes.
    vin : str | None
        Decoded VIN (17 chars) or None.
    sw_version : str | None
        Software part number / version string.
    hw_version : str | None
        Hardware part number / version string.
    cal_id : str | None
        Calibration / software ID.
    vin_offset : int
        Byte offset where VIN was found (-1 if not found).
    sw_offset : int
        Byte offset of SW number (-1 if not found).
    hw_offset : int
        Byte offset of HW number (-1 if not found).
    confidence : float
        Match confidence 0.0–1.0.
    notes : list[str]
        Human-readable diagnostic notes.
    """
    profile:     Optional[ECUProfile]
    family:      ECUFamily
    file_size:   int
    vin:         Optional[str]       = None
    sw_version:  Optional[str]       = None
    hw_version:  Optional[str]       = None
    cal_id:      Optional[str]       = None
    vin_offset:  int                 = -1
    sw_offset:   int                 = -1
    hw_offset:   int                 = -1
    confidence:  float               = 0.0
    notes:       List[str]           = field(default_factory=list)

    # -----------------------------------------------------------------------

    def __str__(self) -> str:
        lines = [
            "╔══════════════════════════════════════════╗",
            "║          ECU Identification Report        ║",
            "╚══════════════════════════════════════════╝",
            f"  ECU Profile : {self.profile.name if self.profile else 'Unknown'}",
            f"  Family      : {self.family.name}",
            f"  File Size   : {self.file_size:,} bytes  ({self.file_size / 1024:.0f} KB)",
            f"  Confidence  : {self.confidence:.0%}",
            "  ─────────────────────────────────────────",
            f"  VIN         : {self.vin or '(not found)'}",
            f"  SW Version  : {self.sw_version or '(not found)'}",
            f"  HW Version  : {self.hw_version or '(not found)'}",
            f"  Cal ID      : {self.cal_id or '(not found)'}",
        ]
        if self.vin_offset >= 0:
            lines.append(f"  VIN offset  : 0x{self.vin_offset:08X}")
        if self.sw_offset >= 0:
            lines.append(f"  SW offset   : 0x{self.sw_offset:08X}")
        if self.hw_offset >= 0:
            lines.append(f"  HW offset   : 0x{self.hw_offset:08X}")
        if self.notes:
            lines.append("  ─────────────────────────────────────────")
            for n in self.notes:
                lines.append(f"  ⚠  {n}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "profile":    self.profile.name if self.profile else None,
            "family":     self.family.name,
            "file_size":  self.file_size,
            "vin":        self.vin,
            "sw_version": self.sw_version,
            "hw_version": self.hw_version,
            "cal_id":     self.cal_id,
            "vin_offset": self.vin_offset,
            "sw_offset":  self.sw_offset,
            "hw_offset":  self.hw_offset,
            "confidence": self.confidence,
            "notes":      self.notes,
        }


# ---------------------------------------------------------------------------
# ECUInfoExtractor
# ---------------------------------------------------------------------------

class ECUInfoExtractor:
    """Detect ECU family and extract identification strings from a binary.

    Usage
    -----
    >>> ext    = ECUInfoExtractor()
    >>> report = ext.detect(data)
    >>> print(report.vin)
    'WVWZZZ1JZ3W386752'
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, data: bytes) -> ECUReport:
        """Run full identification on *data* and return an :class:`ECUReport`.

        Parameters
        ----------
        data : bytes
            Raw ECU ROM bytes.
        """
        data   = bytes(data)
        notes  = []
        conf   = 0.0

        # 1. Profile match
        profile = get_profile(data)
        family  = profile.family if profile else ECUFamily.UNKNOWN

        if profile:
            conf += 0.4
            # Verify identification string presence
            probe = data[:65536]
            hits  = sum(1 for s in profile.identification_strings if s in probe)
            conf += min(hits * 0.15, 0.45)
        else:
            notes.append("ECU not recognised by profile database – using heuristics only.")

        # 2. Extract identifiers
        vin, vin_off = self._find_vin(data)
        sw,  sw_off  = self._find_sw(data, profile)
        hw,  hw_off  = self._find_hw(data, profile)
        cal, _       = self._find_cal_id(data, profile)

        if vin:
            conf = min(conf + 0.15, 1.0)
        if sw:
            conf = min(conf + 0.05, 1.0)

        # 3. Validate VIN check digit
        if vin and not _vin_checksum_ok(vin):
            notes.append(f"VIN '{vin}' has invalid check digit (may be a test VIN or ECU prototype).")

        return ECUReport(
            profile    = profile,
            family     = family,
            file_size  = len(data),
            vin        = vin,
            sw_version = sw,
            hw_version = hw,
            cal_id     = cal,
            vin_offset = vin_off,
            sw_offset  = sw_off,
            hw_offset  = hw_off,
            confidence = round(conf, 2),
            notes      = notes,
        )

    def detect_file(self, path: "str | Path") -> ECUReport:
        """Load *path* from disk and run :meth:`detect`."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"'{p}' not found")
        return self.detect(p.read_bytes())

    # ------------------------------------------------------------------
    # VIN extraction
    # ------------------------------------------------------------------

    def _find_vin(self, data: bytes) -> Tuple[Optional[str], int]:
        """Scan *data* for a plausible ISO 3779 VIN.

        Returns
        -------
        (vin_string, byte_offset) or (None, -1)
        """
        # Search the whole ROM (VIN can be in various locations)
        for m in _VIN_RE.finditer(data):
            candidate = m.group().decode("ascii", errors="replace")
            # Skip obvious test/placeholder VINs
            if candidate in ("00000000000000000", "11111111111111111",
                             "AAAAAAAAAAAAAAAAA"):
                continue
            return candidate, m.start()
        return None, -1

    # ------------------------------------------------------------------
    # SW / HW extraction
    # ------------------------------------------------------------------

    def _find_sw(
        self, data: bytes, profile: Optional[ECUProfile]
    ) -> Tuple[Optional[str], int]:
        """Extract the software part number / version string."""
        # 1. Profile-specific offset
        if profile and profile.sw_offset > 0:
            s = _read_ascii_field(data, profile.sw_offset, 20)
            if s:
                return s, profile.sw_offset

        # 2. Bosch format "0 2XX XXX XXX"
        for m in _BOSCH_SW_RE.finditer(data):
            # Heuristic: SW numbers have part 2 ≥ 200 (not HW)
            txt = m.group().decode("ascii")
            parts = txt.split()
            if len(parts) == 4 and int(parts[1]) >= 200:
                return txt, m.start()

        # 3. Generic SW: tag
        for m in _SW_GENERIC_RE.finditer(data):
            txt = m.group(1).decode("ascii", errors="replace").strip()
            if txt:
                return txt, m.start()

        return None, -1

    def _find_hw(
        self, data: bytes, profile: Optional[ECUProfile]
    ) -> Tuple[Optional[str], int]:
        """Extract the hardware part number / version string."""
        if profile and profile.hw_offset > 0:
            s = _read_ascii_field(data, profile.hw_offset, 20)
            if s:
                return s, profile.hw_offset

        for m in _BOSCH_HW_RE.finditer(data):
            return m.group().decode("ascii"), m.start()

        for m in _HW_GENERIC_RE.finditer(data):
            txt = m.group(1).decode("ascii", errors="replace").strip()
            if txt:
                return txt, m.start()

        return None, -1

    # ------------------------------------------------------------------
    # Calibration ID
    # ------------------------------------------------------------------

    def _find_cal_id(
        self, data: bytes, profile: Optional[ECUProfile]
    ) -> Tuple[Optional[str], int]:
        """Extract calibration / ROM software ID."""
        if profile and profile.cal_id_offset > 0:
            s = _read_ascii_field(data, profile.cal_id_offset, 20)
            if s:
                return s, profile.cal_id_offset

        # Look for 8-20 char uppercase alphanumeric string near the end of ROM
        tail = data[max(0, len(data) - 0x1000):]
        for m in _CAL_ID_RE.finditer(tail):
            txt = m.group().decode("ascii", errors="replace")
            if len(txt) >= 8 and txt.isupper():
                return txt, max(0, len(data) - 0x1000) + m.start()

        return None, -1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_ascii_field(data: bytes, offset: int, max_len: int = 32) -> Optional[str]:
    """Read a null-terminated or space-padded ASCII field at *offset*."""
    if offset + max_len > len(data):
        return None
    chunk = data[offset : offset + max_len]
    # Strip null bytes and trailing spaces
    txt = chunk.split(b"\x00")[0].decode("ascii", errors="replace").strip()
    return txt if txt else None


def _vin_checksum_ok(vin: str) -> bool:
    """Validate the ISO 3779 VIN check digit (position 9)."""
    _TRANSLITERATION = {
        "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7, "H": 8,
        "J": 1, "K": 2, "L": 3, "M": 4, "N": 5,         "P": 7, "R": 9,
        "S": 2, "T": 3, "U": 4, "V": 5, "W": 6, "X": 7, "Y": 8, "Z": 9,
    }
    _WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]

    if len(vin) != 17:
        return False
    total = 0
    for i, ch in enumerate(vin):
        val = int(ch) if ch.isdigit() else _TRANSLITERATION.get(ch, 0)
        total += val * _WEIGHTS[i]
    remainder = total % 11
    check = str(remainder) if remainder < 10 else "X"
    return vin[8] == check
