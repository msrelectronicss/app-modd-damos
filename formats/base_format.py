"""
base_format.py - Abstract base class and registry for binary file formats.

All concrete format parsers (ELF, ECU, Firmware …) extend BinaryFormat and
register themselves with FormatRegistry for auto-detection.
"""

from __future__ import annotations

import hashlib
import struct
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple, Type


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class FormatError(Exception):
    """Base exception for all format-related errors."""


class ParseError(FormatError):
    """Raised when a file cannot be parsed."""


class ValidationError(FormatError):
    """Raised when format validation fails."""


# ---------------------------------------------------------------------------
# Abstract base class
# ---------------------------------------------------------------------------

class BinaryFormat(ABC):
    """Abstract base for all binary file format parsers.

    Subclass and implement :meth:`parse`.  Override :meth:`detect`,
    :meth:`validate`, and :meth:`summary` as needed.

    Class attributes
    ----------------
    MAGIC : bytes
        Magic bytes that identify this format (used by the default
        :meth:`detect` implementation).  May be ``b""`` if detection
        requires a more complex check.
    MAGIC_OFFSET : int
        Byte offset at which MAGIC is expected (default 0).
    EXTENSIONS : list[str]
        Common file extensions for this format (e.g. ``[".elf", ".so"]``).
    FORMAT_NAME : str
        Human-readable format name.
    FORMAT_VERSION : str
        Version of this format parser.
    """

    MAGIC:          bytes     = b""
    MAGIC_OFFSET:   int       = 0
    EXTENSIONS:     List[str] = []
    FORMAT_NAME:    str       = "Generic Binary"
    FORMAT_VERSION: str       = "1.0"

    def __init__(self) -> None:
        self._data:     Optional[bytes] = None
        self._path:     Optional[Path]  = None
        self._parsed:   Optional[dict]  = None

    # ------------------------------------------------------------------
    # Class methods
    # ------------------------------------------------------------------

    @classmethod
    def detect(cls, data: bytes) -> bool:
        """Return True if *data* appears to be in this format.

        The default implementation checks for MAGIC at MAGIC_OFFSET.
        Override for formats requiring more complex detection.

        Parameters
        ----------
        data : bytes
            Raw file contents.
        """
        if not cls.MAGIC:
            return False
        off = cls.MAGIC_OFFSET
        return len(data) >= off + len(cls.MAGIC) and \
               data[off:off + len(cls.MAGIC)] == cls.MAGIC

    @classmethod
    def from_file(cls, path: str) -> "BinaryFormat":
        """Create an instance and load *path*.

        Parameters
        ----------
        path : str or Path
            Path to the file to load.
        """
        inst = cls.__new__(cls)
        BinaryFormat.__init__(inst)
        inst._path = Path(path)
        inst._data = inst._path.read_bytes()
        return inst

    @classmethod
    def from_bytes(cls, data: bytes) -> "BinaryFormat":
        """Create an instance from raw *data*."""
        inst = cls.__new__(cls)
        BinaryFormat.__init__(inst)
        inst._data = bytes(data)
        return inst

    # ------------------------------------------------------------------
    # Abstract methods
    # ------------------------------------------------------------------

    @abstractmethod
    def parse(self, data: bytes) -> dict:
        """Parse *data* and return a structured dictionary.

        Subclasses must implement this method.

        Parameters
        ----------
        data : bytes
            Raw file contents.

        Returns
        -------
        dict
            Structured representation of the file contents.

        Raises
        ------
        ParseError
            If the data cannot be parsed.
        """

    # ------------------------------------------------------------------
    # Concrete methods with sensible defaults
    # ------------------------------------------------------------------

    def validate(self, data: bytes) -> Tuple[bool, List[str]]:
        """Validate *data* for format correctness.

        Returns
        -------
        (valid, errors)
            *valid* is True if no errors were found.
            *errors* is a list of human-readable error strings.
        """
        errors: List[str] = []
        if not self.detect(data):
            errors.append(f"Magic bytes not found for {self.FORMAT_NAME}")
        return (len(errors) == 0, errors)

    def summary(self, data: bytes) -> str:
        """Return a short human-readable summary of *data*.

        Override for format-specific summaries.
        """
        valid, errors = self.validate(data)
        status = "valid" if valid else "INVALID"
        error_str = "; ".join(errors) if errors else "none"
        return (
            f"{self.FORMAT_NAME} ({self.FORMAT_VERSION}) — "
            f"size={len(data)} bytes, status={status}, errors: {error_str}"
        )

    def get_parsed(self) -> Optional[dict]:
        """Return cached parse result, or None if not yet parsed."""
        return self._parsed

    def ensure_parsed(self) -> dict:
        """Return parse result, parsing now if needed."""
        if self._parsed is None:
            if self._data is None:
                raise ParseError("No data loaded — call from_file() or from_bytes() first")
            self._parsed = self.parse(self._data)
        return self._parsed

    def read_bytes(self) -> bytes:
        """Return the raw bytes this instance was loaded with."""
        if self._data is None:
            raise ParseError("No data loaded")
        return self._data

    # ------------------------------------------------------------------
    # Utility helpers available to all subclasses
    # ------------------------------------------------------------------

    @staticmethod
    def _read_u8(data: bytes, off: int) -> int:
        return data[off]

    @staticmethod
    def _read_u16(data: bytes, off: int, big_endian: bool = False) -> int:
        fmt = ">H" if big_endian else "<H"
        return struct.unpack_from(fmt, data, off)[0]

    @staticmethod
    def _read_u32(data: bytes, off: int, big_endian: bool = False) -> int:
        fmt = ">I" if big_endian else "<I"
        return struct.unpack_from(fmt, data, off)[0]

    @staticmethod
    def _read_u64(data: bytes, off: int, big_endian: bool = False) -> int:
        fmt = ">Q" if big_endian else "<Q"
        return struct.unpack_from(fmt, data, off)[0]

    @staticmethod
    def _read_cstring(data: bytes, off: int, max_len: int = 256) -> str:
        end = data.find(b"\x00", off, off + max_len)
        if end == -1:
            end = min(off + max_len, len(data))
        return data[off:end].decode("ascii", errors="replace")

    @staticmethod
    def _crc32(data: bytes) -> int:
        """Compute CRC-32 of *data*."""
        import zlib
        return zlib.crc32(data) & 0xFFFFFFFF

    @staticmethod
    def _checksum_sum32(data: bytes) -> int:
        """Simple 32-bit summation checksum."""
        total = 0
        for i in range(0, len(data) - 3, 4):
            total = (total + struct.unpack_from("<I", data, i)[0]) & 0xFFFFFFFF
        return total

    @staticmethod
    def _sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _is_printable(data: bytes, threshold: float = 0.85) -> bool:
        """Return True if most bytes are printable ASCII."""
        printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
        return printable / len(data) >= threshold if data else True

    @staticmethod
    def _hexdump(data: bytes, offset: int = 0, width: int = 16) -> str:
        """Format data as hex dump string."""
        lines: List[str] = []
        for i in range(0, len(data), width):
            chunk = data[i:i + width]
            hex_p = " ".join(f"{b:02x}" for b in chunk)
            asc_p = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{offset + i:08X}  {hex_p:<{width * 3 - 1}}  |{asc_p}|")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Iteration helpers
    # ------------------------------------------------------------------

    def iter_chunks(
        self, data: bytes, chunk_size: int
    ) -> Iterator[Tuple[int, bytes]]:
        """Yield (offset, chunk) pairs of *chunk_size* bytes from *data*."""
        for off in range(0, len(data), chunk_size):
            yield off, data[off:off + chunk_size]

    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        size = len(self._data) if self._data else 0
        path = str(self._path) if self._path else "<bytes>"
        return f"{self.__class__.__name__}({path!r}, {size} bytes)"

    def __str__(self) -> str:
        if self._data:
            return self.summary(self._data)
        return repr(self)


# ---------------------------------------------------------------------------
# Format Registry
# ---------------------------------------------------------------------------

class FormatRegistry:
    """Central registry mapping format classes to their metadata.

    Usage
    -----
    >>> reg = FormatRegistry()
    >>> reg.register(ELFFormat)
    >>> fmt_cls = reg.auto_detect(data)
    >>> if fmt_cls:
    ...     parsed = fmt_cls().parse(data)
    """

    def __init__(self) -> None:
        self._formats: Dict[str, Type[BinaryFormat]] = {}

    # ------------------------------------------------------------------

    def register(self, fmt_class: Type[BinaryFormat]) -> None:
        """Register a format class.

        Parameters
        ----------
        fmt_class : Type[BinaryFormat]
            A concrete subclass of BinaryFormat.
        """
        name = fmt_class.FORMAT_NAME
        if name in self._formats:
            raise FormatError(f"Format {name!r} is already registered")
        self._formats[name] = fmt_class

    def unregister(self, name: str) -> None:
        """Remove a registered format by name."""
        self._formats.pop(name, None)

    def get(self, name: str) -> Optional[Type[BinaryFormat]]:
        """Return the format class registered under *name*, or None."""
        return self._formats.get(name)

    def all_formats(self) -> List[Type[BinaryFormat]]:
        """Return a list of all registered format classes."""
        return list(self._formats.values())

    def format_names(self) -> List[str]:
        """Return sorted list of registered format names."""
        return sorted(self._formats.keys())

    def detect(self, data: bytes) -> Optional[BinaryFormat]:
        """Auto-detect the format of *data* and return an instance.

        Tries every registered format's :meth:`detect` classmethod and
        returns an instance of the first match, or None.

        Parameters
        ----------
        data : bytes
            Raw file contents.

        Returns
        -------
        BinaryFormat instance or None
        """
        data = bytes(data)
        for fmt_cls in self._formats.values():
            try:
                if fmt_cls.detect(data):
                    return fmt_cls.from_bytes(data)
            except Exception:
                continue
        return None

    def detect_all(self, data: bytes) -> List[BinaryFormat]:
        """Return instances for every matching format class."""
        data   = bytes(data)
        result = []
        for fmt_cls in self._formats.values():
            try:
                if fmt_cls.detect(data):
                    result.append(fmt_cls.from_bytes(data))
            except Exception:
                continue
        return result

    def parse_file(self, path: str) -> Optional[dict]:
        """Auto-detect and parse *path*, returning the parsed dict or None."""
        data = Path(path).read_bytes()
        inst = self.detect(data)
        if inst is None:
            return None
        return inst.parse(data)

    def __len__(self) -> int:
        return len(self._formats)

    def __repr__(self) -> str:
        return f"FormatRegistry({len(self._formats)} formats: {self.format_names()})"

    # ------------------------------------------------------------------
    # Plugin-style decorator
    # ------------------------------------------------------------------

    def format(self, cls: Type[BinaryFormat]) -> Type[BinaryFormat]:
        """Class decorator that registers *cls* with this registry."""
        self.register(cls)
        return cls


# ---------------------------------------------------------------------------
# Mixin for formats with checksums
# ---------------------------------------------------------------------------

class ChecksumMixin:
    """Provides common checksum validation helpers as a mixin."""

    def check_crc32(
        self, data: bytes, crc_offset: int, crc_start: int, crc_end: int
    ) -> bool:
        """Validate a stored CRC-32 value.

        Parameters
        ----------
        data : bytes
            Full file data.
        crc_offset : int
            Offset of the stored CRC-32 (4 bytes, LE).
        crc_start, crc_end : int
            Range of bytes to include in the CRC calculation.
        """
        import zlib
        stored = struct.unpack_from("<I", data, crc_offset)[0]
        calc   = zlib.crc32(data[crc_start:crc_end]) & 0xFFFFFFFF
        return stored == calc

    def check_sum32(
        self, data: bytes, sum_offset: int, sum_start: int, sum_end: int
    ) -> bool:
        """Validate a 32-bit summation checksum."""
        stored = struct.unpack_from("<I", data, sum_offset)[0]
        total  = 0
        for i in range(sum_start, sum_end - 3, 4):
            total = (total + struct.unpack_from("<I", data, i)[0]) & 0xFFFFFFFF
        return stored == total

    def compute_checksum_xor(self, data: bytes) -> int:
        """XOR all bytes together."""
        result = 0
        for b in data:
            result ^= b
        return result

    def repair_crc32(
        self,
        data: bytearray,
        crc_offset: int,
        crc_start: int,
        crc_end: int,
    ) -> bytearray:
        """Recalculate CRC-32 and write it to *data* at *crc_offset*."""
        import zlib
        crc = zlib.crc32(data[crc_start:crc_end]) & 0xFFFFFFFF
        struct.pack_into("<I", data, crc_offset, crc)
        return data


# ---------------------------------------------------------------------------
# Mixin for structured field reading
# ---------------------------------------------------------------------------

class StructReaderMixin:
    """Provides structured field reading helpers."""

    def read_struct(
        self,
        data: bytes,
        offset: int,
        fmt: str,
    ) -> tuple:
        """Read a ``struct.unpack``-style format from *data* at *offset*."""
        size = struct.calcsize(fmt)
        if offset + size > len(data):
            raise ParseError(
                f"Not enough data at 0x{offset:X}: need {size}B, "
                f"have {len(data) - offset}B"
            )
        return struct.unpack_from(fmt, data, offset)

    def read_bytes_at(self, data: bytes, offset: int, size: int) -> bytes:
        """Return *size* bytes from *data* starting at *offset*."""
        if offset + size > len(data):
            raise ParseError(
                f"Not enough data at 0x{offset:X}: need {size}B, "
                f"have {len(data) - offset}B"
            )
        return data[offset:offset + size]

    def assert_magic(self, data: bytes, offset: int, expected: bytes) -> None:
        """Raise ParseError if *data[offset:]* does not start with *expected*."""
        actual = data[offset:offset + len(expected)]
        if actual != expected:
            raise ParseError(
                f"Magic mismatch at 0x{offset:X}: "
                f"expected {expected!r}, got {actual!r}"
            )


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    class _TestFmt(BinaryFormat):
        MAGIC       = b"TEST"
        FORMAT_NAME = "Test Format"

        def parse(self, data: bytes) -> dict:
            self.assert_magic(data, 0, self.MAGIC)
            return {"size": len(data), "content": data[4:].decode("ascii", errors="replace")}

    _TestFmt.__bases__ = (_TestFmt.__bases__[0], StructReaderMixin)

    reg = FormatRegistry()
    reg.register(_TestFmt)
    assert "Test Format" in reg.format_names()

    data = b"TESTHello"
    fmt  = reg.detect(data)
    assert fmt is not None
    parsed = fmt.parse(data)
    assert parsed["content"] == "Hello"

    valid, errs = fmt.validate(data)
    assert valid
    print("PASS: base_format self-test")
