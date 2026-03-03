"""
ecu_bin.py - ECU binary format parser for automotive control unit ROM images.

Supports common ECU formats:
  - Bosch ME7.x (petrol engines)
  - Bosch EDC15 (diesel, common rail / pump-injector)
  - Bosch EDC16/EDC17 (modern diesel)
  - Delphi DCM3.x
  - Magneti Marelli MJD/IAW

Each format has a distinct header signature, checksum algorithm, and map
table layout.  This module parses those structures and provides checksum
repair utilities.
"""

from __future__ import annotations

import struct
import zlib
import math
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from formats.base_format import (
    BinaryFormat,
    ChecksumMixin,
    ParseError,
    StructReaderMixin,
    ValidationError,
)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ECUFamily(Enum):
    UNKNOWN    = auto()
    BOSCH_ME7  = auto()
    BOSCH_EDC15= auto()
    BOSCH_EDC16= auto()
    BOSCH_EDC17= auto()
    DELPHI_DCM = auto()
    MARELLI    = auto()


class AxisType(Enum):
    LINEAR    = auto()   # evenly spaced
    NONLINEAR = auto()   # explicit axis array
    NONE      = auto()   # scalar or 1-D without axis


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ECUHeader:
    """Parsed ECU ROM header fields."""
    magic:           bytes
    family:          ECUFamily
    version_string:  str
    checksum_offset: int
    checksum_type:   str      # "sum32", "crc32", "xor8", "custom"
    data_offset:     int
    data_size:       int
    map_count:       int
    map_table_offset:int
    raw_header:      bytes = field(default=b"", repr=False)


@dataclass
class MapDescriptor:
    """Describes a calibration map found in the ROM.

    Attributes
    ----------
    name : str
        Auto-generated or ROM-embedded name.
    offset : int
        Byte offset of the map data in the ROM.
    size : int
        Total byte size of the map data (not including axes).
    rows : int
        Number of rows (Y dimension).
    cols : int
        Number of columns (X dimension).
    element_size : int
        Size in bytes of each element (1, 2, or 4).
    signed : bool
        Whether elements are signed integers.
    factor : float
        Scaling factor (physical = raw * factor + offset_val).
    offset_val : float
        Scaling offset.
    x_axis_offset : int
        ROM offset of the X-axis data (0 = none).
    y_axis_offset : int
        ROM offset of the Y-axis data (0 = none).
    axis_type : AxisType
    units : str
    description : str
    """
    name:           str
    offset:         int
    size:           int
    rows:           int
    cols:           int
    element_size:   int   = 2
    signed:         bool  = False
    factor:         float = 1.0
    offset_val:     float = 0.0
    x_axis_offset:  int   = 0
    y_axis_offset:  int   = 0
    axis_type:      AxisType = AxisType.NONE
    units:          str   = ""
    description:    str   = ""

    def total_bytes(self) -> int:
        return self.rows * self.cols * self.element_size

    def read_values(self, data: bytes) -> List[List[float]]:
        """Read map elements from *data* and return scaled 2-D list."""
        result = []
        fmt    = (">" if False else "<") + ("h" if self.signed else "H") * self.cols
        if self.element_size == 1:
            fmt = "<" + ("b" if self.signed else "B") * self.cols
        elif self.element_size == 4:
            fmt = "<" + ("i" if self.signed else "I") * self.cols

        row_size = struct.calcsize(fmt)
        for r in range(self.rows):
            off  = self.offset + r * row_size
            if off + row_size > len(data):
                break
            raw_row = struct.unpack_from(fmt, data, off)
            result.append([v * self.factor + self.offset_val for v in raw_row])
        return result

    def write_values(
        self, data: bytearray, values: List[List[float]]
    ) -> bytearray:
        """Write scaled values back into *data*."""
        fmt = "<" + ("h" if self.signed else "H") * self.cols
        if self.element_size == 1:
            fmt = "<" + ("b" if self.signed else "B") * self.cols
        elif self.element_size == 4:
            fmt = "<" + ("i" if self.signed else "I") * self.cols

        row_size = struct.calcsize(fmt)
        for r, row in enumerate(values):
            off = self.offset + r * row_size
            raw = [int((v - self.offset_val) / self.factor) for v in row]
            struct.pack_into(fmt, data, off, *raw)
        return data


# ---------------------------------------------------------------------------
# ECU format signatures
# ---------------------------------------------------------------------------

# (family, magic, magic_offset, typical_sizes_kb, description)
_ECU_SIGNATURES: List[dict] = [
    {
        "family": ECUFamily.BOSCH_ME7,
        "magic":  b"\x3d\x00\x00\x00",
        "offset": 0x0000,
        "sizes":  [512, 256],
        "desc":   "Bosch ME7.x — petrol injection ECU",
        "checksum_offset": 0x7FF0,
        "checksum_type":   "sum32",
        "map_table_offset":0x1000,
    },
    {
        "family": ECUFamily.BOSCH_ME7,
        "magic":  b"\x5a\xa5",
        "offset": 0x0000,
        "sizes":  [512, 256],
        "desc":   "Bosch ME7.x variant B",
        "checksum_offset": 0x7FFE,
        "checksum_type":   "xor16",
        "map_table_offset":0x0800,
    },
    {
        "family": ECUFamily.BOSCH_EDC15,
        "magic":  b"EDC15",
        "offset": 0x0000,
        "sizes":  [512],
        "desc":   "Bosch EDC15 — diesel common rail",
        "checksum_offset": 0x7FFC,
        "checksum_type":   "crc32",
        "map_table_offset":0x2000,
    },
    {
        "family": ECUFamily.BOSCH_EDC15,
        "magic":  b"\x04\x00\x00\x00EDC15",
        "offset": 0x0000,
        "sizes":  [512],
        "desc":   "Bosch EDC15 extended header",
        "checksum_offset": 0xFFFC,
        "checksum_type":   "crc32",
        "map_table_offset":0x4000,
    },
    {
        "family": ECUFamily.BOSCH_EDC16,
        "magic":  b"EDC16",
        "offset": 0x0000,
        "sizes":  [1024, 2048],
        "desc":   "Bosch EDC16 — modern diesel",
        "checksum_offset": 0xFFFC,
        "checksum_type":   "crc32",
        "map_table_offset":0x8000,
    },
    {
        "family": ECUFamily.BOSCH_EDC17,
        "magic":  b"EDC17",
        "offset": 0x0000,
        "sizes":  [2048, 4096],
        "desc":   "Bosch EDC17 — next-gen diesel",
        "checksum_offset": 0x1FFFC,
        "checksum_type":   "crc32",
        "map_table_offset":0x10000,
    },
    {
        "family": ECUFamily.DELPHI_DCM,
        "magic":  b"DCM3",
        "offset": 0x0000,
        "sizes":  [512, 1024],
        "desc":   "Delphi DCM3.x ECU",
        "checksum_offset": 0xFFF8,
        "checksum_type":   "sum32",
        "map_table_offset":0x3000,
    },
    {
        "family": ECUFamily.MARELLI,
        "magic":  b"IAW",
        "offset": 0x0000,
        "sizes":  [512],
        "desc":   "Magneti Marelli IAW ECU",
        "checksum_offset": 0x7FF8,
        "checksum_type":   "xor8",
        "map_table_offset":0x1800,
    },
    {
        "family": ECUFamily.MARELLI,
        "magic":  b"MJD",
        "offset": 0x0000,
        "sizes":  [512, 1024],
        "desc":   "Magneti Marelli MJD ECU",
        "checksum_offset": 0xFFF4,
        "checksum_type":   "sum32",
        "map_table_offset":0x2000,
    },
]


# ---------------------------------------------------------------------------
# ECUBinFormat
# ---------------------------------------------------------------------------

class ECUBinFormat(BinaryFormat, ChecksumMixin, StructReaderMixin):
    """Parser for automotive ECU ROM binary images.

    Supports Bosch ME7, EDC15, EDC16, EDC17, Delphi DCM3, and
    Magneti Marelli IAW/MJD families.

    Usage
    -----
    >>> fmt = ECUBinFormat.from_file("me7_rom.bin")
    >>> header = fmt.parse_header(fmt.read_bytes())
    >>> maps    = fmt.find_maps(fmt.read_bytes(), header)
    >>> ok, err = fmt.validate_checksum(fmt.read_bytes(), header)
    """

    MAGIC         = b""           # detection uses _ECU_SIGNATURES
    FORMAT_NAME   = "ECU Binary"
    FORMAT_VERSION= "1.0"
    EXTENSIONS    = [".bin", ".rom", ".ori", ".mod"]

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    @classmethod
    def detect(cls, data: bytes) -> bool:
        """Return True if *data* matches any known ECU signature."""
        return cls._find_signature(data) is not None

    @classmethod
    def _find_signature(cls, data: bytes) -> Optional[dict]:
        for sig in _ECU_SIGNATURES:
            magic  = sig["magic"]
            offset = sig["offset"]
            if len(data) >= offset + len(magic) and \
               data[offset:offset + len(magic)] == magic:
                return sig
        return None

    # ------------------------------------------------------------------
    # BinaryFormat.parse implementation
    # ------------------------------------------------------------------

    def parse(self, data: bytes) -> dict:
        """Parse *data* as an ECU ROM image.

        Returns a dict with keys: header, maps, checksum_valid.
        """
        data   = bytes(data)
        header = self.parse_header(data)
        maps   = self.find_maps(data, header)
        ok, _  = self.validate_checksum(data, header)
        return {
            "header":          _header_to_dict(header),
            "maps":            [_map_to_dict(m) for m in maps],
            "checksum_valid":  ok,
            "size":            len(data),
        }

    # ------------------------------------------------------------------
    # Header parsing
    # ------------------------------------------------------------------

    def parse_header(self, data: bytes) -> ECUHeader:
        """Detect and parse the ECU ROM header.

        Parameters
        ----------
        data : bytes
            Raw ROM data.

        Returns
        -------
        ECUHeader

        Raises
        ------
        ParseError
            If no known ECU signature is found.
        """
        data = bytes(data)
        sig  = self._find_signature(data)
        if sig is None:
            raise ParseError("No known ECU signature found in data")

        family   = sig["family"]
        cs_off   = sig.get("checksum_offset", len(data) - 4)
        cs_type  = sig.get("checksum_type", "sum32")
        mt_off   = sig.get("map_table_offset", 0)
        magic    = sig["magic"]
        desc     = sig.get("desc", "")

        # Try to extract a version string near the start of the ROM
        version_str = self._read_version_string(data)

        # Map count: heuristic — scan for valid map table entries
        map_count = self._estimate_map_count(data, mt_off)

        return ECUHeader(
            magic            = magic,
            family           = family,
            version_string   = version_str,
            checksum_offset  = min(cs_off, len(data) - 4),
            checksum_type    = cs_type,
            data_offset      = 0,
            data_size        = len(data),
            map_count        = map_count,
            map_table_offset = mt_off,
            raw_header       = data[:min(64, len(data))],
        )

    def _read_version_string(self, data: bytes) -> str:
        """Scan for a printable version string near the start of the ROM."""
        import re
        m = re.search(rb"[A-Z0-9][A-Z0-9._\-]{3,31}", data[:512])
        if m:
            return m.group().decode("ascii", errors="replace")
        return ""

    def _estimate_map_count(self, data: bytes, map_table_offset: int) -> int:
        """Heuristically count valid map entries at *map_table_offset*."""
        count = 0
        pos   = map_table_offset
        while pos + 8 <= len(data):
            # A "map pointer" must be inside file bounds and 4-byte aligned
            ptr = struct.unpack_from("<I", data, pos)[0]
            if ptr == 0xFFFFFFFF or ptr == 0:
                break
            if ptr < len(data) and ptr % 4 == 0:
                count += 1
                pos   += 8
            else:
                break
            if count > 512:
                break
        return count

    # ------------------------------------------------------------------
    # Map discovery
    # ------------------------------------------------------------------

    def find_maps(
        self,
        data: bytes,
        header: Optional[ECUHeader] = None,
        max_maps: int = 256,
    ) -> List[MapDescriptor]:
        """Locate calibration maps in the ROM.

        The search uses a combination of:
        1. Reading the map table at ``header.map_table_offset``
        2. Heuristic scan for aligned 2-D arrays

        Parameters
        ----------
        data : bytes
            ROM data.
        header : ECUHeader, optional
            If None, parse_header is called first.
        max_maps : int
            Maximum number of maps to return.

        Returns
        -------
        list of MapDescriptor
        """
        data   = bytes(data)
        if header is None:
            try:
                header = self.parse_header(data)
            except ParseError:
                header = ECUHeader(
                    magic=b"", family=ECUFamily.UNKNOWN,
                    version_string="", checksum_offset=0,
                    checksum_type="sum32", data_offset=0,
                    data_size=len(data), map_count=0,
                    map_table_offset=0,
                )

        maps: List[MapDescriptor] = []

        # 1. Read from map table
        mt_off = header.map_table_offset
        for i in range(header.map_count):
            pos = mt_off + i * 8
            if pos + 8 > len(data):
                break
            map_ptr  = struct.unpack_from("<I", data, pos)[0]
            map_meta = struct.unpack_from("<I", data, pos + 4)[0]
            if map_ptr == 0 or map_ptr >= len(data):
                continue
            rows = (map_meta >> 8) & 0xFF
            cols = map_meta & 0xFF
            if rows == 0 or cols == 0:
                rows, cols = 1, 1
            md = MapDescriptor(
                name         = f"Map_{i:03d}",
                offset       = map_ptr,
                size         = rows * cols * 2,
                rows         = rows,
                cols         = cols,
                element_size = 2,
                axis_type    = AxisType.NONLINEAR if rows > 1 else AxisType.NONE,
            )
            maps.append(md)

        # 2. Heuristic scan for 2-D map structures
        if len(maps) == 0:
            maps.extend(self._heuristic_map_scan(data, max_maps))

        return maps[:max_maps]

    def _heuristic_map_scan(
        self, data: bytes, max_maps: int = 64
    ) -> List[MapDescriptor]:
        """Scan for candidate 2-D map structures using entropy / pattern analysis."""
        maps: List[MapDescriptor] = []
        size = len(data)
        # Look for regions with entropy in a typical data range (1.5–6.5)
        step = 256
        for off in range(0, min(size, 0x20000), step):
            chunk = data[off:off + step]
            if len(chunk) < 16:
                break
            ent = _entropy(chunk)
            if 1.5 <= ent <= 6.5:
                # Try to interpret as a 16x16 map of uint16
                if off + 512 <= size:
                    md = MapDescriptor(
                        name         = f"HeuristicMap_0x{off:06X}",
                        offset       = off,
                        size         = 512,
                        rows         = 16,
                        cols         = 16,
                        element_size = 2,
                        axis_type    = AxisType.NONLINEAR,
                    )
                    maps.append(md)
            if len(maps) >= max_maps:
                break
        return maps

    # ------------------------------------------------------------------
    # Checksum validation / repair
    # ------------------------------------------------------------------

    def validate_checksum(
        self, data: bytes, header: Optional[ECUHeader] = None
    ) -> Tuple[bool, str]:
        """Validate the checksum embedded in the ROM.

        Parameters
        ----------
        data : bytes
            ROM data.
        header : ECUHeader, optional
            If None, parse_header is called.

        Returns
        -------
        (valid, message)
        """
        data = bytes(data)
        if header is None:
            try:
                header = self.parse_header(data)
            except ParseError as e:
                return False, str(e)

        cs_off  = header.checksum_offset
        cs_type = header.checksum_type

        if cs_off + 4 > len(data):
            return False, "Checksum offset out of bounds"

        body = data[:cs_off]

        if cs_type == "crc32":
            stored  = struct.unpack_from("<I", data, cs_off)[0]
            calc    = zlib.crc32(body) & 0xFFFFFFFF
            ok      = stored == calc
            return ok, f"CRC32: stored=0x{stored:08X} calc=0x{calc:08X}"

        elif cs_type == "sum32":
            stored  = struct.unpack_from("<I", data, cs_off)[0]
            calc    = 0
            for i in range(0, len(body) - 3, 4):
                calc = (calc + struct.unpack_from("<I", body, i)[0]) & 0xFFFFFFFF
            ok   = stored == calc
            return ok, f"SUM32: stored=0x{stored:08X} calc=0x{calc:08X}"

        elif cs_type == "xor8":
            stored = data[cs_off]
            calc   = 0
            for b in body:
                calc ^= b
            ok = stored == calc
            return ok, f"XOR8: stored=0x{stored:02X} calc=0x{calc:02X}"

        elif cs_type == "xor16":
            stored = struct.unpack_from("<H", data, cs_off)[0]
            calc   = 0
            for i in range(0, len(body) - 1, 2):
                calc = (calc ^ struct.unpack_from("<H", body, i)[0]) & 0xFFFF
            ok = stored == calc
            return ok, f"XOR16: stored=0x{stored:04X} calc=0x{calc:04X}"

        else:
            return False, f"Unknown checksum type: {cs_type!r}"

    def repair_checksum(
        self, data: bytes, header: Optional[ECUHeader] = None
    ) -> bytes:
        """Recalculate and write the correct checksum into the ROM.

        Parameters
        ----------
        data : bytes
            Original ROM data.
        header : ECUHeader, optional
            If None, parse_header is called.

        Returns
        -------
        bytes
            New ROM data with repaired checksum.
        """
        data = bytearray(data)
        if header is None:
            header = self.parse_header(bytes(data))

        cs_off  = header.checksum_offset
        cs_type = header.checksum_type
        body    = bytes(data[:cs_off])

        if cs_type == "crc32":
            calc = zlib.crc32(body) & 0xFFFFFFFF
            struct.pack_into("<I", data, cs_off, calc)

        elif cs_type == "sum32":
            calc = 0
            for i in range(0, len(body) - 3, 4):
                calc = (calc + struct.unpack_from("<I", body, i)[0]) & 0xFFFFFFFF
            struct.pack_into("<I", data, cs_off, calc)

        elif cs_type == "xor8":
            calc = 0
            for b in body:
                calc ^= b
            data[cs_off] = calc & 0xFF

        elif cs_type == "xor16":
            calc = 0
            for i in range(0, len(body) - 1, 2):
                calc = (calc ^ struct.unpack_from("<H", body, i)[0]) & 0xFFFF
            struct.pack_into("<H", data, cs_off, calc)

        return bytes(data)

    # ------------------------------------------------------------------
    # Validation (override)
    # ------------------------------------------------------------------

    def validate(self, data: bytes):
        """Validate ECU ROM: check signature and checksum."""
        errors = []
        if not self.detect(data):
            errors.append("No ECU signature found")
        else:
            try:
                header = self.parse_header(data)
                ok, msg = self.validate_checksum(data, header)
                if not ok:
                    errors.append(f"Checksum invalid: {msg}")
            except Exception as e:
                errors.append(str(e))
        return (len(errors) == 0, errors)

    # ------------------------------------------------------------------
    # Summary (override)
    # ------------------------------------------------------------------

    def summary(self, data: bytes) -> str:
        try:
            header = self.parse_header(data)
            ok, cs_msg = self.validate_checksum(data, header)
            return (
                f"ECU ROM: {header.family.name}  "
                f"version={header.version_string!r}  "
                f"size={len(data):,}B  "
                f"maps={header.map_count}  "
                f"checksum={'OK' if ok else 'FAIL'}  ({cs_msg})"
            )
        except ParseError as e:
            return f"ECU ROM: parse error — {e}"

    # ------------------------------------------------------------------
    # Map modification helpers
    # ------------------------------------------------------------------

    def read_map(self, data: bytes, md: MapDescriptor) -> List[List[float]]:
        """Read and scale values from a map descriptor."""
        return md.read_values(data)

    def write_map(
        self, data: bytes, md: MapDescriptor, values: List[List[float]]
    ) -> bytes:
        """Write scaled values into a copy of *data*."""
        buf = bytearray(data)
        md.write_values(buf, values)
        return bytes(buf)

    def patch_map_value(
        self,
        data: bytes,
        md: MapDescriptor,
        row: int,
        col: int,
        new_value: float,
    ) -> bytes:
        """Patch a single cell in a map.

        Parameters
        ----------
        data : bytes
            ROM data.
        md : MapDescriptor
            Target map.
        row, col : int
            Cell coordinates (0-indexed).
        new_value : float
            Physical (scaled) value to write.

        Returns
        -------
        bytes
            Modified ROM data.
        """
        buf     = bytearray(data)
        raw_val = int((new_value - md.offset_val) / md.factor)
        off     = md.offset + (row * md.cols + col) * md.element_size
        if md.element_size == 1:
            fmt = "<b" if md.signed else "<B"
        elif md.element_size == 2:
            fmt = "<h" if md.signed else "<H"
        else:
            fmt = "<i" if md.signed else "<I"
        struct.pack_into(fmt, buf, off, raw_val)
        return bytes(buf)

    # ------------------------------------------------------------------
    # Batch operations
    # ------------------------------------------------------------------

    def find_tables_by_size(
        self,
        data: bytes,
        rows: int,
        cols: int,
        element_size: int = 2,
    ) -> List[int]:
        """Find all candidate offsets for a table of given dimensions.

        A candidate must have low byte-variance (monotone or patterned data).
        """
        data    = bytes(data)
        stride  = rows * cols * element_size
        offsets = []
        for off in range(0, len(data) - stride, element_size):
            chunk = data[off:off + stride]
            # Compute variance of 16-bit words
            words = struct.unpack_from(f"<{rows * cols}H", chunk)
            mean  = sum(words) / len(words)
            var   = sum((w - mean) ** 2 for w in words) / len(words)
            if 10 < var < 1e7:  # not all-same, not all-random
                offsets.append(off)
        return offsets[:64]

    def dump_map(self, data: bytes, md: MapDescriptor) -> str:
        """Format a map as a readable ASCII table."""
        values = self.read_map(data, md)
        lines  = [f"Map: {md.name}  ({md.rows}x{md.cols})  [{md.units}]"]
        for row in values:
            lines.append("  " + "  ".join(f"{v:8.3f}" for v in row))
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Identifier / metadata extraction
    # ------------------------------------------------------------------

    def extract_calibration_id(self, data: bytes) -> str:
        """Try to extract a calibration/part-number string from the ROM."""
        import re
        # Common patterns: e.g. "0261209001", "1037373519", "EDC15_0.0.1"
        m = re.search(rb"\b(\d{10}|\d{7}[A-Z]{2}|[A-Z]{3}\d{2}_\d+\.\d+\.\d+)\b", data)
        if m:
            return m.group().decode("ascii", errors="replace")
        return ""

    def find_string_table(self, data: bytes) -> List[Tuple[int, str]]:
        """Locate a contiguous block of null-terminated ASCII strings."""
        import re
        results: List[Tuple[int, str]] = []
        for m in re.finditer(rb"([ -~]{4,64})\x00", data):
            results.append((m.start(), m.group(1).decode("ascii", errors="replace")))
        return results[:100]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    from collections import Counter
    freq = Counter(data)
    n    = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _header_to_dict(h: ECUHeader) -> dict:
    return {
        "family":           h.family.name,
        "version":          h.version_string,
        "checksum_offset":  f"0x{h.checksum_offset:08X}",
        "checksum_type":    h.checksum_type,
        "data_offset":      f"0x{h.data_offset:08X}",
        "data_size":        h.data_size,
        "map_count":        h.map_count,
        "map_table_offset": f"0x{h.map_table_offset:08X}",
    }


def _map_to_dict(m: MapDescriptor) -> dict:
    return {
        "name":          m.name,
        "offset":        f"0x{m.offset:08X}",
        "size":          m.size,
        "rows":          m.rows,
        "cols":          m.cols,
        "element_size":  m.element_size,
        "signed":        m.signed,
        "factor":        m.factor,
        "offset_val":    m.offset_val,
        "units":         m.units,
        "axis_type":     m.axis_type.name,
    }


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------

def detect_ecu_family(data: bytes) -> ECUFamily:
    """Return the ECUFamily enum value for *data*, or UNKNOWN."""
    sig = ECUBinFormat._find_signature(data)
    return sig["family"] if sig else ECUFamily.UNKNOWN


def quick_validate(path: str) -> Tuple[bool, str]:
    """Load *path* and validate its checksum.  Returns (valid, message)."""
    data = Path(path).read_bytes()
    fmt  = ECUBinFormat()
    try:
        header = fmt.parse_header(data)
        return fmt.validate_checksum(data, header)
    except ParseError as e:
        return False, str(e)


def repair_file(src: str, dst: str) -> bool:
    """Repair the checksum of *src* and write result to *dst*.

    Returns True on success.
    """
    data = Path(src).read_bytes()
    fmt  = ECUBinFormat()
    try:
        header  = fmt.parse_header(data)
        repaired = fmt.repair_checksum(data, header)
        Path(dst).write_bytes(repaired)
        return True
    except (ParseError, Exception):
        return False


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import os

    print("ECUBinFormat self-test")
    print("=" * 40)

    # Build a minimal fake EDC15 ROM
    rom_size = 0x10000  # 64 KB
    rom      = bytearray(b"\xFF" * rom_size)

    # Write EDC15 magic
    rom[:5] = b"EDC15"

    # Write a dummy map table entry at 0x2000
    map_off = 0x4000  # map data lives at 0x4000
    rom[0x2000:0x2008] = struct.pack("<II", map_off, (8 << 8) | 8)  # 8x8 map

    # Fill map with 0x0100 = 1.0 (factor=1/256)
    for i in range(64):
        struct.pack_into("<H", rom, map_off + i * 2, 0x0100)

    # Compute CRC32 and store at 0x7FFC
    body = bytes(rom[:0x7FFC])
    crc  = zlib.crc32(body) & 0xFFFFFFFF
    struct.pack_into("<I", rom, 0x7FFC, crc)

    rom_bytes = bytes(rom)
    fmt       = ECUBinFormat()
    assert fmt.detect(rom_bytes), "Detection failed"
    print("PASS: detect")

    header = fmt.parse_header(rom_bytes)
    assert header.family == ECUFamily.BOSCH_EDC15
    print(f"PASS: parse_header → {header.family.name}")

    ok, msg = fmt.validate_checksum(rom_bytes, header)
    assert ok, f"Checksum validation failed: {msg}"
    print(f"PASS: validate_checksum → {msg}")

    maps = fmt.find_maps(rom_bytes, header)
    print(f"PASS: find_maps → {len(maps)} map(s) found")

    # Corrupt and repair
    bad = bytearray(rom_bytes)
    bad[0x7FFC] ^= 0xFF
    ok2, _ = fmt.validate_checksum(bytes(bad), header)
    assert not ok2
    repaired = fmt.repair_checksum(bytes(bad), header)
    ok3, msg3 = fmt.validate_checksum(repaired, header)
    assert ok3, f"Repair failed: {msg3}"
    print("PASS: repair_checksum")

    parsed = fmt.parse(rom_bytes)
    assert "header" in parsed and "maps" in parsed
    print("PASS: parse() returns dict")

    print("\nAll ECUBinFormat self-tests passed.")
