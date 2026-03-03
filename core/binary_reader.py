# =============================================================================
# BinModder - Binary Reader Module
# =============================================================================
# Provides comprehensive binary file reading capabilities with full endianness
# support, type-safe reading operations, streaming support, and context manager
# integration. Supports Little Endian, Big Endian, PDP Endian, and Honeywell
# Middle Endian byte orders.
#
# Author: MSR Electronics
# Version: 1.0.0
# =============================================================================

import os
import io
import struct
import mmap
from enum import Enum, auto
from typing import (
    Optional, Union, List, Tuple, Iterator, Generator,
    Any, BinaryIO, Callable
)
from pathlib import Path


# =============================================================================
# Enumerations
# =============================================================================

class Endianness(Enum):
    """Byte order enumeration for multi-byte value reading."""
    LITTLE    = "little"   # x86, ARM (default mode)
    BIG       = "big"      # Network, PowerPC, MIPS (BE)
    PDP       = "pdp"      # PDP-11 middle endian (word-swapped LE)
    HONEYWELL = "honey"    # Honeywell middle endian (word-swapped BE)
    NATIVE    = "native"   # Platform native byte order

    def struct_prefix(self) -> str:
        """Return struct format prefix for this endianness."""
        mapping = {
            Endianness.LITTLE:    "<",
            Endianness.BIG:       ">",
            Endianness.NATIVE:    "=",
            Endianness.PDP:       "<",   # handled specially
            Endianness.HONEYWELL: ">",   # handled specially
        }
        return mapping[self]


class SeekMode(Enum):
    """File seek mode enumeration."""
    BEGIN   = 0   # Seek from beginning of file
    CURRENT = 1   # Seek from current position
    END     = 2   # Seek from end of file


class ReadMode(Enum):
    """File open mode enumeration."""
    READ_ONLY   = "rb"   # Open for reading only
    READ_WRITE  = "r+b"  # Open for reading and writing (file must exist)


# =============================================================================
# Exceptions
# =============================================================================

class BinaryReaderError(Exception):
    """Base exception for binary reader errors."""
    pass


class EndOfFileError(BinaryReaderError):
    """Raised when attempting to read past the end of file."""
    def __init__(self, offset: int, requested: int, available: int):
        self.offset    = offset
        self.requested = requested
        self.available = available
        super().__init__(
            f"End of file at offset 0x{offset:08X}: "
            f"requested {requested} bytes, only {available} available"
        )


class InvalidOffsetError(BinaryReaderError):
    """Raised when seeking to an invalid offset."""
    def __init__(self, offset: int, file_size: int):
        self.offset    = offset
        self.file_size = file_size
        super().__init__(
            f"Invalid offset 0x{offset:08X}: file size is 0x{file_size:08X}"
        )


class StructUnpackError(BinaryReaderError):
    """Raised when struct unpacking fails."""
    def __init__(self, fmt: str, data: bytes, error: Exception):
        self.fmt   = fmt
        self.data  = data
        self.cause = error
        super().__init__(
            f"Failed to unpack format '{fmt}' from {len(data)} bytes: {error}"
        )


# =============================================================================
# Data Types
# =============================================================================

class DataType:
    """Constants for common data types with their sizes and struct formats."""
    # Unsigned integers
    UINT8   = ("B", 1)
    UINT16  = ("H", 2)
    UINT32  = ("I", 4)
    UINT64  = ("Q", 8)
    # Signed integers
    INT8    = ("b", 1)
    INT16   = ("h", 2)
    INT32   = ("i", 4)
    INT64   = ("q", 8)
    # Floating point
    FLOAT32 = ("f", 4)
    FLOAT64 = ("d", 8)
    # Boolean
    BOOL8   = ("?", 1)
    # Char
    CHAR    = ("c", 1)


# =============================================================================
# Bookmark System
# =============================================================================

class Bookmark:
    """Represents a named position bookmark in a binary file."""

    def __init__(self, name: str, offset: int, description: str = ""):
        self.name        = name
        self.offset      = offset
        self.description = description

    def __repr__(self) -> str:
        return f"Bookmark(name={self.name!r}, offset=0x{self.offset:08X})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Bookmark):
            return NotImplemented
        return self.name == other.name and self.offset == other.offset

    def __hash__(self) -> int:
        return hash((self.name, self.offset))

    def to_dict(self) -> dict:
        """Serialize bookmark to dictionary."""
        return {
            "name":        self.name,
            "offset":      self.offset,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Bookmark":
        """Deserialize bookmark from dictionary."""
        return cls(
            name=data["name"],
            offset=data["offset"],
            description=data.get("description", ""),
        )


class BookmarkManager:
    """Manages a collection of named bookmarks for a binary file."""

    def __init__(self):
        self._bookmarks: dict[str, Bookmark] = {}

    def add(self, name: str, offset: int, description: str = "") -> Bookmark:
        """Add or update a bookmark."""
        bm = Bookmark(name, offset, description)
        self._bookmarks[name] = bm
        return bm

    def remove(self, name: str) -> bool:
        """Remove a bookmark by name. Returns True if removed."""
        if name in self._bookmarks:
            del self._bookmarks[name]
            return True
        return False

    def get(self, name: str) -> Optional[Bookmark]:
        """Get a bookmark by name."""
        return self._bookmarks.get(name)

    def list_all(self) -> List[Bookmark]:
        """Return all bookmarks sorted by offset."""
        return sorted(self._bookmarks.values(), key=lambda b: b.offset)

    def clear(self) -> None:
        """Clear all bookmarks."""
        self._bookmarks.clear()

    def __len__(self) -> int:
        return len(self._bookmarks)

    def __iter__(self) -> Iterator[Bookmark]:
        return iter(self.list_all())

    def __contains__(self, name: str) -> bool:
        return name in self._bookmarks


# =============================================================================
# Read History
# =============================================================================

class ReadHistoryEntry:
    """Records a single read operation for undo/replay support."""

    def __init__(self, offset: int, size: int, data: bytes, type_name: str):
        self.offset    = offset
        self.size      = size
        self.data      = data
        self.type_name = type_name

    def __repr__(self) -> str:
        return (
            f"ReadHistoryEntry(offset=0x{self.offset:08X}, "
            f"size={self.size}, type={self.type_name})"
        )


class ReadHistory:
    """Maintains a history of read operations."""

    def __init__(self, max_entries: int = 1000):
        self._entries:     List[ReadHistoryEntry] = []
        self._max_entries = max_entries

    def record(self, offset: int, size: int, data: bytes, type_name: str) -> None:
        """Record a read operation."""
        entry = ReadHistoryEntry(offset, size, data, type_name)
        self._entries.append(entry)
        if len(self._entries) > self._max_entries:
            self._entries.pop(0)

    def get_all(self) -> List[ReadHistoryEntry]:
        """Return all history entries."""
        return list(self._entries)

    def get_last(self, n: int = 1) -> List[ReadHistoryEntry]:
        """Return the last n entries."""
        return self._entries[-n:]

    def clear(self) -> None:
        """Clear history."""
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)


# =============================================================================
# Binary Reader - Main Class
# =============================================================================

class BinaryReader:
    """
    Advanced binary file reader with full endianness support.

    Features:
    - Read all primitive types (uint8/16/32/64, int8/16/32/64, float32/64)
    - Little Endian, Big Endian, PDP, and Honeywell byte orders
    - String reading (null-terminated, fixed-length, Pascal-style)
    - Bit-level reading operations
    - Memory-mapped file support for large files
    - Bookmark system for named positions
    - Read history tracking
    - Context manager support
    - Streaming/chunked reading
    - Structured data reading

    Usage:
        with BinaryReader("myfile.bin") as r:
            r.seek(0x1000)
            value = r.read_uint32_le()
            data = r.read_bytes(64)
            text = r.read_cstring()
    """

    def __init__(
        self,
        source: Union[str, Path, bytes, bytearray, BinaryIO],
        endianness:    Endianness = Endianness.LITTLE,
        use_mmap:      bool       = False,
        track_history: bool       = False,
    ):
        """
        Initialize BinaryReader.

        Args:
            source:        File path, bytes, bytearray, or file object
            endianness:    Default byte order for multi-byte reads
            use_mmap:      Use memory mapping for large files (file path only)
            track_history: Enable read history tracking
        """
        self._endianness    = endianness
        self._use_mmap      = use_mmap
        self._track_history = track_history
        self._bookmarks     = BookmarkManager()
        self._history       = ReadHistory() if track_history else None
        self._mmap_obj      = None
        self._file_obj      = None
        self._owned_file    = False
        self._source_name   = "<unknown>"

        self._stream = self._open_source(source)
        self._size   = self._get_size()

    # -------------------------------------------------------------------------
    # Initialization Helpers
    # -------------------------------------------------------------------------

    def _open_source(
        self,
        source: Union[str, Path, bytes, bytearray, BinaryIO]
    ) -> io.IOBase:
        """Open the binary source and return a stream."""
        if isinstance(source, (str, Path)):
            path = Path(source)
            if not path.exists():
                raise FileNotFoundError(f"Binary file not found: {path}")
            if not path.is_file():
                raise ValueError(f"Not a file: {path}")

            self._source_name = str(path)
            self._file_obj    = open(path, "rb")
            self._owned_file  = True

            if self._use_mmap:
                self._mmap_obj = mmap.mmap(
                    self._file_obj.fileno(), 0, access=mmap.ACCESS_READ
                )
                return io.BytesIO(self._mmap_obj)
            return self._file_obj

        elif isinstance(source, (bytes, bytearray)):
            self._source_name = f"<bytes:{len(source)}>"
            return io.BytesIO(bytes(source))

        elif hasattr(source, "read"):
            self._source_name = getattr(source, "name", "<stream>")
            return source

        else:
            raise TypeError(
                f"Unsupported source type: {type(source).__name__}. "
                "Expected str, Path, bytes, bytearray, or file-like object."
            )

    def _get_size(self) -> int:
        """Determine the total size of the binary data."""
        pos = self._stream.tell()
        self._stream.seek(0, 2)  # Seek to end
        size = self._stream.tell()
        self._stream.seek(pos)   # Restore position
        return size

    # -------------------------------------------------------------------------
    # Context Manager
    # -------------------------------------------------------------------------

    def __enter__(self) -> "BinaryReader":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def close(self) -> None:
        """Close the binary reader and release resources."""
        if self._mmap_obj is not None:
            try:
                self._mmap_obj.close()
            except Exception:
                pass
            self._mmap_obj = None

        if self._owned_file and self._file_obj is not None:
            try:
                self._file_obj.close()
            except Exception:
                pass
            self._file_obj = None

    # -------------------------------------------------------------------------
    # Properties
    # -------------------------------------------------------------------------

    @property
    def endianness(self) -> Endianness:
        """Current default endianness."""
        return self._endianness

    @endianness.setter
    def endianness(self, value: Endianness) -> None:
        """Set default endianness."""
        if not isinstance(value, Endianness):
            raise TypeError(f"Expected Endianness enum, got {type(value).__name__}")
        self._endianness = value

    @property
    def position(self) -> int:
        """Current read position (offset)."""
        return self._stream.tell()

    @property
    def size(self) -> int:
        """Total size of the binary data in bytes."""
        return self._size

    @property
    def remaining(self) -> int:
        """Number of bytes remaining from current position."""
        return max(0, self._size - self.position)

    @property
    def at_end(self) -> bool:
        """True if at or past end of file."""
        return self.position >= self._size

    @property
    def source_name(self) -> str:
        """Name/path of the source."""
        return self._source_name

    @property
    def bookmarks(self) -> BookmarkManager:
        """Access the bookmark manager."""
        return self._bookmarks

    @property
    def history(self) -> Optional[ReadHistory]:
        """Access read history (None if not tracking)."""
        return self._history

    # -------------------------------------------------------------------------
    # Position Control
    # -------------------------------------------------------------------------

    def seek(self, offset: int, mode: SeekMode = SeekMode.BEGIN) -> int:
        """
        Seek to a position in the file.

        Args:
            offset: Byte offset to seek to
            mode:   Seek mode (BEGIN, CURRENT, END)

        Returns:
            New position after seek

        Raises:
            InvalidOffsetError: If resulting position is out of bounds
        """
        self._stream.seek(offset, mode.value)
        pos = self._stream.tell()
        if pos > self._size:
            raise InvalidOffsetError(pos, self._size)
        return pos

    def seek_begin(self) -> int:
        """Seek to beginning of file."""
        return self.seek(0)

    def seek_end(self) -> int:
        """Seek to end of file."""
        return self.seek(0, SeekMode.END)

    def skip(self, n: int) -> int:
        """Skip n bytes forward from current position."""
        return self.seek(n, SeekMode.CURRENT)

    def back(self, n: int) -> int:
        """Move n bytes backward from current position."""
        return self.seek(-n, SeekMode.CURRENT)

    def tell(self) -> int:
        """Return current position (alias for .position)."""
        return self._stream.tell()

    def save_position(self) -> int:
        """Save current position and return it."""
        return self.position

    def restore_position(self, saved: int) -> None:
        """Restore a previously saved position."""
        self.seek(saved)

    # -------------------------------------------------------------------------
    # Core Read Operations
    # -------------------------------------------------------------------------

    def read_bytes(self, size: int) -> bytes:
        """
        Read exactly `size` bytes from current position.

        Args:
            size: Number of bytes to read

        Returns:
            Bytes read

        Raises:
            EndOfFileError: If not enough bytes available
        """
        if size < 0:
            raise ValueError(f"Cannot read negative bytes: {size}")
        if size == 0:
            return b""

        available = self.remaining
        if available < size:
            raise EndOfFileError(self.position, size, available)

        offset = self.position
        data   = self._stream.read(size)

        if len(data) < size:
            raise EndOfFileError(offset, size, len(data))

        if self._track_history and self._history is not None:
            self._history.record(offset, size, data, "bytes")

        return data

    def read_bytes_at(self, offset: int, size: int) -> bytes:
        """Read `size` bytes at specific `offset` without changing position."""
        saved = self.save_position()
        try:
            self.seek(offset)
            return self.read_bytes(size)
        finally:
            self.restore_position(saved)

    def peek_bytes(self, size: int) -> bytes:
        """Read bytes without advancing position."""
        saved = self.save_position()
        try:
            return self.read_bytes(size)
        finally:
            self.restore_position(saved)

    def read_all(self) -> bytes:
        """Read all remaining bytes from current position."""
        return self.read_bytes(self.remaining)

    def read_all_from_start(self) -> bytes:
        """Read entire file content from beginning."""
        self.seek_begin()
        return self.read_all()

    # -------------------------------------------------------------------------
    # Struct-Based Read Operations
    # -------------------------------------------------------------------------

    def _read_struct(
        self,
        fmt_char: str,
        size: int,
        endianness: Optional[Endianness] = None
    ) -> Any:
        """Internal: read a struct-formatted value."""
        endi  = endianness or self._endianness
        prefix = endi.struct_prefix()
        fmt   = f"{prefix}{fmt_char}"

        try:
            data = self.read_bytes(size)
        except EndOfFileError:
            raise

        try:
            value = struct.unpack(fmt, data)[0]
        except struct.error as e:
            raise StructUnpackError(fmt, data, e)

        return value

    def _read_pdp_uint32(self) -> int:
        """Read PDP-endian 32-bit value (word-swapped little endian)."""
        data = self.read_bytes(4)
        # PDP: bytes are B1 B0 B3 B2 (swap 16-bit words)
        swapped = bytes([data[2], data[3], data[0], data[1]])
        return struct.unpack("<I", swapped)[0]

    def _read_honey_uint32(self) -> int:
        """Read Honeywell middle endian 32-bit value (word-swapped big endian)."""
        data = self.read_bytes(4)
        # Honeywell: bytes are B3 B2 B1 B0 (word swapped big endian)
        swapped = bytes([data[2], data[3], data[0], data[1]])
        return struct.unpack(">I", swapped)[0]

    # -------------------------------------------------------------------------
    # Unsigned Integer Reads
    # -------------------------------------------------------------------------

    def read_uint8(self) -> int:
        """Read an unsigned 8-bit integer (1 byte)."""
        return self._read_struct("B", 1)

    def read_uint16(self, endianness: Optional[Endianness] = None) -> int:
        """Read an unsigned 16-bit integer."""
        return self._read_struct("H", 2, endianness)

    def read_uint32(self, endianness: Optional[Endianness] = None) -> int:
        """Read an unsigned 32-bit integer."""
        endi = endianness or self._endianness
        if endi == Endianness.PDP:
            return self._read_pdp_uint32()
        if endi == Endianness.HONEYWELL:
            return self._read_honey_uint32()
        return self._read_struct("I", 4, endi)

    def read_uint64(self, endianness: Optional[Endianness] = None) -> int:
        """Read an unsigned 64-bit integer."""
        return self._read_struct("Q", 8, endianness)

    # Explicit LE/BE convenience methods
    def read_uint16_le(self) -> int:
        """Read unsigned 16-bit little endian integer."""
        return self.read_uint16(Endianness.LITTLE)

    def read_uint16_be(self) -> int:
        """Read unsigned 16-bit big endian integer."""
        return self.read_uint16(Endianness.BIG)

    def read_uint32_le(self) -> int:
        """Read unsigned 32-bit little endian integer."""
        return self.read_uint32(Endianness.LITTLE)

    def read_uint32_be(self) -> int:
        """Read unsigned 32-bit big endian integer."""
        return self.read_uint32(Endianness.BIG)

    def read_uint64_le(self) -> int:
        """Read unsigned 64-bit little endian integer."""
        return self.read_uint64(Endianness.LITTLE)

    def read_uint64_be(self) -> int:
        """Read unsigned 64-bit big endian integer."""
        return self.read_uint64(Endianness.BIG)

    def read_u8(self)  -> int: return self.read_uint8()
    def read_u16(self) -> int: return self.read_uint16()
    def read_u32(self) -> int: return self.read_uint32()
    def read_u64(self) -> int: return self.read_uint64()
    def read_u16_le(self) -> int: return self.read_uint16_le()
    def read_u16_be(self) -> int: return self.read_uint16_be()
    def read_u32_le(self) -> int: return self.read_uint32_le()
    def read_u32_be(self) -> int: return self.read_uint32_be()
    def read_u64_le(self) -> int: return self.read_uint64_le()
    def read_u64_be(self) -> int: return self.read_uint64_be()

    # -------------------------------------------------------------------------
    # Signed Integer Reads
    # -------------------------------------------------------------------------

    def read_int8(self) -> int:
        """Read a signed 8-bit integer."""
        return self._read_struct("b", 1)

    def read_int16(self, endianness: Optional[Endianness] = None) -> int:
        """Read a signed 16-bit integer."""
        return self._read_struct("h", 2, endianness)

    def read_int32(self, endianness: Optional[Endianness] = None) -> int:
        """Read a signed 32-bit integer."""
        return self._read_struct("i", 4, endianness)

    def read_int64(self, endianness: Optional[Endianness] = None) -> int:
        """Read a signed 64-bit integer."""
        return self._read_struct("q", 8, endianness)

    def read_int16_le(self) -> int: return self.read_int16(Endianness.LITTLE)
    def read_int16_be(self) -> int: return self.read_int16(Endianness.BIG)
    def read_int32_le(self) -> int: return self.read_int32(Endianness.LITTLE)
    def read_int32_be(self) -> int: return self.read_int32(Endianness.BIG)
    def read_int64_le(self) -> int: return self.read_int64(Endianness.LITTLE)
    def read_int64_be(self) -> int: return self.read_int64(Endianness.BIG)

    def read_i8(self)     -> int: return self.read_int8()
    def read_i16(self)    -> int: return self.read_int16()
    def read_i32(self)    -> int: return self.read_int32()
    def read_i64(self)    -> int: return self.read_int64()
    def read_i16_le(self) -> int: return self.read_int16_le()
    def read_i16_be(self) -> int: return self.read_int16_be()
    def read_i32_le(self) -> int: return self.read_int32_le()
    def read_i32_be(self) -> int: return self.read_int32_be()
    def read_i64_le(self) -> int: return self.read_int64_le()
    def read_i64_be(self) -> int: return self.read_int64_be()

    # -------------------------------------------------------------------------
    # Floating Point Reads
    # -------------------------------------------------------------------------

    def read_float32(self, endianness: Optional[Endianness] = None) -> float:
        """Read a 32-bit (single precision) float."""
        return self._read_struct("f", 4, endianness)

    def read_float64(self, endianness: Optional[Endianness] = None) -> float:
        """Read a 64-bit (double precision) float."""
        return self._read_struct("d", 8, endianness)

    def read_float32_le(self) -> float: return self.read_float32(Endianness.LITTLE)
    def read_float32_be(self) -> float: return self.read_float32(Endianness.BIG)
    def read_float64_le(self) -> float: return self.read_float64(Endianness.LITTLE)
    def read_float64_be(self) -> float: return self.read_float64(Endianness.BIG)

    def read_f32(self)    -> float: return self.read_float32()
    def read_f64(self)    -> float: return self.read_float64()
    def read_f32_le(self) -> float: return self.read_float32_le()
    def read_f32_be(self) -> float: return self.read_float32_be()
    def read_f64_le(self) -> float: return self.read_float64_le()
    def read_f64_be(self) -> float: return self.read_float64_be()

    # -------------------------------------------------------------------------
    # Boolean and Char Reads
    # -------------------------------------------------------------------------

    def read_bool(self) -> bool:
        """Read a 1-byte boolean."""
        return bool(self.read_uint8())

    def read_char(self) -> str:
        """Read a single ASCII character."""
        return chr(self.read_uint8())

    def read_char_bytes(self) -> bytes:
        """Read a single character as bytes."""
        return self.read_bytes(1)

    # -------------------------------------------------------------------------
    # Variable-Length Integer Reads
    # -------------------------------------------------------------------------

    def read_uint24_le(self) -> int:
        """Read unsigned 24-bit little endian integer."""
        data = self.read_bytes(3)
        return data[0] | (data[1] << 8) | (data[2] << 16)

    def read_uint24_be(self) -> int:
        """Read unsigned 24-bit big endian integer."""
        data = self.read_bytes(3)
        return (data[0] << 16) | (data[1] << 8) | data[2]

    def read_uint48_le(self) -> int:
        """Read unsigned 48-bit little endian integer."""
        lo = self.read_uint32_le()
        hi = self.read_uint16_le()
        return lo | (hi << 32)

    def read_uint48_be(self) -> int:
        """Read unsigned 48-bit big endian integer."""
        hi = self.read_uint16_be()
        lo = self.read_uint32_be()
        return (hi << 32) | lo

    def read_varint(self) -> int:
        """Read a variable-length integer (LEB128 unsigned)."""
        result = 0
        shift  = 0
        while True:
            b = self.read_uint8()
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
            if shift >= 64:
                raise BinaryReaderError("LEB128 varint too large")
        return result

    def read_varint_signed(self) -> int:
        """Read a variable-length signed integer (SLEB128)."""
        result = 0
        shift  = 0
        while True:
            b = self.read_uint8()
            result |= (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                if shift < 64 and (b & 0x40):
                    result |= -(1 << shift)
                break
            if shift >= 64:
                raise BinaryReaderError("SLEB128 varint too large")
        return result

    # -------------------------------------------------------------------------
    # String Reads
    # -------------------------------------------------------------------------

    def read_cstring(self, max_length: int = 4096, encoding: str = "utf-8") -> str:
        """
        Read a null-terminated C string.

        Args:
            max_length: Maximum number of bytes to read before giving up
            encoding:   Character encoding (default: utf-8)

        Returns:
            Decoded string (without null terminator)
        """
        raw = bytearray()
        for _ in range(max_length):
            b = self.read_uint8()
            if b == 0:
                break
            raw.append(b)
        else:
            raise BinaryReaderError(
                f"Null terminator not found within {max_length} bytes"
            )
        return raw.decode(encoding, errors="replace")

    def read_cstring_at(
        self,
        offset: int,
        max_length: int = 4096,
        encoding: str = "utf-8"
    ) -> str:
        """Read a null-terminated C string at specific offset."""
        saved = self.save_position()
        try:
            self.seek(offset)
            return self.read_cstring(max_length, encoding)
        finally:
            self.restore_position(saved)

    def read_fixed_string(
        self,
        size: int,
        encoding: str = "utf-8",
        strip_null: bool = True
    ) -> str:
        """
        Read a fixed-length string.

        Args:
            size:       Number of bytes to read
            encoding:   Character encoding
            strip_null: Strip trailing null bytes

        Returns:
            Decoded string
        """
        data = self.read_bytes(size)
        if strip_null:
            data = data.rstrip(b"\x00")
        return data.decode(encoding, errors="replace")

    def read_pascal_string(self, length_size: int = 1, encoding: str = "utf-8") -> str:
        """
        Read a Pascal-style string with a length prefix.

        Args:
            length_size: Size of length prefix in bytes (1 or 2 or 4)
            encoding:    Character encoding

        Returns:
            Decoded string
        """
        if length_size == 1:
            length = self.read_uint8()
        elif length_size == 2:
            length = self.read_uint16()
        elif length_size == 4:
            length = self.read_uint32()
        else:
            raise ValueError(f"Invalid length_size: {length_size}. Must be 1, 2, or 4.")

        data = self.read_bytes(length)
        return data.decode(encoding, errors="replace")

    def read_utf16_string(
        self,
        max_chars: int = 2048,
        endianness: Optional[Endianness] = None
    ) -> str:
        """Read a null-terminated UTF-16 string."""
        endi = endianness or self._endianness
        chars = []
        for _ in range(max_chars):
            if endi == Endianness.LITTLE:
                code = self.read_uint16_le()
            else:
                code = self.read_uint16_be()
            if code == 0:
                break
            chars.append(chr(code))
        else:
            raise BinaryReaderError(
                f"UTF-16 null terminator not found within {max_chars} chars"
            )
        return "".join(chars)

    def read_string_until(
        self,
        delimiter: bytes,
        max_length: int = 4096,
        include_delimiter: bool = False,
        encoding: str = "utf-8"
    ) -> str:
        """Read a string until a specific delimiter byte sequence."""
        raw      = bytearray()
        dlen     = len(delimiter)
        delbytes = bytearray()

        for _ in range(max_length + dlen):
            try:
                b = self.read_uint8()
            except EndOfFileError:
                break
            delbytes.append(b)
            if len(delbytes) > dlen:
                raw.append(delbytes.pop(0))
            if bytes(delbytes) == delimiter:
                if include_delimiter:
                    raw.extend(delbytes)
                break
        else:
            raise BinaryReaderError(
                f"Delimiter {delimiter.hex()} not found within {max_length} bytes"
            )

        return raw.decode(encoding, errors="replace")

    # -------------------------------------------------------------------------
    # Array / Batch Reads
    # -------------------------------------------------------------------------

    def read_uint8_array(self, count: int) -> List[int]:
        """Read an array of unsigned 8-bit integers."""
        data = self.read_bytes(count)
        return list(data)

    def read_uint16_array(
        self, count: int, endianness: Optional[Endianness] = None
    ) -> List[int]:
        """Read an array of unsigned 16-bit integers."""
        return [self.read_uint16(endianness) for _ in range(count)]

    def read_uint32_array(
        self, count: int, endianness: Optional[Endianness] = None
    ) -> List[int]:
        """Read an array of unsigned 32-bit integers."""
        return [self.read_uint32(endianness) for _ in range(count)]

    def read_uint64_array(
        self, count: int, endianness: Optional[Endianness] = None
    ) -> List[int]:
        """Read an array of unsigned 64-bit integers."""
        return [self.read_uint64(endianness) for _ in range(count)]

    def read_float32_array(
        self, count: int, endianness: Optional[Endianness] = None
    ) -> List[float]:
        """Read an array of 32-bit floats."""
        return [self.read_float32(endianness) for _ in range(count)]

    def read_float64_array(
        self, count: int, endianness: Optional[Endianness] = None
    ) -> List[float]:
        """Read an array of 64-bit doubles."""
        return [self.read_float64(endianness) for _ in range(count)]

    def read_struct_array(
        self,
        fmt_char: str,
        item_size: int,
        count: int,
        endianness: Optional[Endianness] = None
    ) -> List[Any]:
        """Read an array of struct values."""
        return [self._read_struct(fmt_char, item_size, endianness) for _ in range(count)]

    # -------------------------------------------------------------------------
    # Structured Read Operations
    # -------------------------------------------------------------------------

    def read_struct_format(
        self,
        format_string: str,
        endianness: Optional[Endianness] = None
    ) -> tuple:
        """
        Read multiple values using a struct format string.

        Args:
            format_string: Struct format string (without endian prefix)
            endianness:    Byte order to use

        Returns:
            Tuple of parsed values

        Example:
            values = reader.read_struct_format("HHI")  # 2x uint16, 1x uint32
        """
        endi   = endianness or self._endianness
        prefix = endi.struct_prefix()
        fmt    = f"{prefix}{format_string}"
        size   = struct.calcsize(fmt)

        data = self.read_bytes(size)
        try:
            return struct.unpack(fmt, data)
        except struct.error as e:
            raise StructUnpackError(fmt, data, e)

    def read_dict(self, schema: dict, endianness: Optional[Endianness] = None) -> dict:
        """
        Read multiple named fields from a schema dictionary.

        Schema format:
            {
                "field_name": ("read_method_name", optional_args...),
                ...
            }

        Args:
            schema:     Dictionary mapping field names to read methods
            endianness: Byte order for numeric fields

        Returns:
            Dictionary of field names to parsed values

        Example:
            data = reader.read_dict({
                "magic":    "read_uint32_be",
                "version":  "read_uint16_le",
                "name":     ("read_fixed_string", 16),
                "checksum": "read_uint32_le",
            })
        """
        result = {}
        for field_name, spec in schema.items():
            if isinstance(spec, str):
                method = getattr(self, spec)
                result[field_name] = method()
            elif isinstance(spec, (list, tuple)):
                method_name = spec[0]
                args        = spec[1:]
                method      = getattr(self, method_name)
                result[field_name] = method(*args)
            else:
                raise ValueError(f"Invalid schema spec for field '{field_name}': {spec!r}")
        return result

    # -------------------------------------------------------------------------
    # Bit-Level Operations
    # -------------------------------------------------------------------------

    class BitReader:
        """Helper class for reading individual bits from a byte."""

        def __init__(self, byte_val: int):
            self._val      = byte_val
            self._bit_pos  = 7  # Start from MSB

        def read_bit(self) -> int:
            """Read the next bit (1 or 0)."""
            if self._bit_pos < 0:
                raise BinaryReaderError("No more bits in current byte")
            bit = (self._val >> self._bit_pos) & 1
            self._bit_pos -= 1
            return bit

        def read_bits(self, n: int) -> int:
            """Read n bits and return as integer."""
            result = 0
            for _ in range(n):
                result = (result << 1) | self.read_bit()
            return result

        def bits_remaining(self) -> int:
            """Number of bits remaining in current byte."""
            return self._bit_pos + 1

    def get_bit_reader(self, byte_val: int) -> "BinaryReader.BitReader":
        """Create a bit reader for a given byte value."""
        return self.BitReader(byte_val)

    def read_bits_from_byte(self, byte_val: int, start_bit: int, count: int) -> int:
        """Extract `count` bits starting at `start_bit` from a byte value."""
        mask = (1 << count) - 1
        return (byte_val >> start_bit) & mask

    def read_bits_from_bytes(
        self,
        data: bytes,
        bit_offset: int,
        bit_count: int
    ) -> int:
        """
        Extract bits from a bytes object at a given bit offset.

        Args:
            data:       Source bytes
            bit_offset: Starting bit position (0 = MSB of first byte)
            bit_count:  Number of bits to extract

        Returns:
            Integer value of the extracted bits
        """
        result    = 0
        byte_pos  = bit_offset // 8
        bit_pos   = 7 - (bit_offset % 8)  # MSB first

        for _ in range(bit_count):
            if byte_pos >= len(data):
                raise BinaryReaderError("Bit read out of bounds")
            bit = (data[byte_pos] >> bit_pos) & 1
            result = (result << 1) | bit
            bit_pos -= 1
            if bit_pos < 0:
                bit_pos = 7
                byte_pos += 1

        return result

    # -------------------------------------------------------------------------
    # Chunk / Streaming Operations
    # -------------------------------------------------------------------------

    def iter_chunks(
        self,
        chunk_size: int = 4096,
        start: Optional[int] = None,
        end: Optional[int] = None
    ) -> Generator[Tuple[int, bytes], None, None]:
        """
        Iterate over the file in chunks.

        Args:
            chunk_size: Size of each chunk in bytes
            start:      Start offset (default: current position)
            end:        End offset (default: end of file)

        Yields:
            (offset, chunk_bytes) tuples
        """
        if start is not None:
            self.seek(start)
        if end is None:
            end = self._size

        while self.position < end:
            offset    = self.position
            remaining = end - self.position
            size      = min(chunk_size, remaining)
            chunk     = self.read_bytes(size)
            yield offset, chunk

    def iter_rows(
        self,
        row_size: int = 16,
        start: Optional[int] = None,
        end: Optional[int] = None
    ) -> Generator[Tuple[int, bytes], None, None]:
        """
        Iterate over the file in fixed-size rows (for hex display).

        Args:
            row_size: Bytes per row (default: 16)
            start:    Start offset
            end:      End offset

        Yields:
            (offset, row_bytes) tuples
        """
        yield from self.iter_chunks(row_size, start, end)

    def iter_records(
        self,
        record_size: int,
        count: Optional[int] = None,
        start: Optional[int] = None
    ) -> Generator[Tuple[int, int, bytes], None, None]:
        """
        Iterate over fixed-size records.

        Args:
            record_size: Size of each record
            count:       Number of records (default: until EOF)
            start:       Start offset

        Yields:
            (index, offset, record_bytes) tuples
        """
        if start is not None:
            self.seek(start)

        index = 0
        while not self.at_end:
            if count is not None and index >= count:
                break
            if self.remaining < record_size:
                break
            offset = self.position
            data   = self.read_bytes(record_size)
            yield index, offset, data
            index += 1

    # -------------------------------------------------------------------------
    # Pattern / Magic Reads
    # -------------------------------------------------------------------------

    def expect_bytes(self, expected: bytes) -> bool:
        """
        Read bytes and verify they match expected value.

        Returns:
            True if bytes match

        Raises:
            BinaryReaderError if bytes don't match
        """
        actual = self.read_bytes(len(expected))
        if actual != expected:
            raise BinaryReaderError(
                f"Expected {expected.hex()}, got {actual.hex()} "
                f"at offset 0x{self.position - len(expected):08X}"
            )
        return True

    def check_bytes(self, expected: bytes) -> bool:
        """
        Peek and check if next bytes match expected (no position change).

        Returns:
            True if bytes match, False otherwise
        """
        try:
            actual = self.peek_bytes(len(expected))
            return actual == expected
        except EndOfFileError:
            return False

    def find_magic(
        self,
        magic: bytes,
        search_range: Optional[Tuple[int, int]] = None
    ) -> Optional[int]:
        """
        Find a magic byte sequence in the file.

        Args:
            magic:        Byte sequence to find
            search_range: (start, end) tuple, or None for whole file

        Returns:
            Offset of first occurrence, or None if not found
        """
        if search_range:
            start, end = search_range
        else:
            start, end = 0, self._size

        saved = self.save_position()
        try:
            self.seek(start)
            chunk_size = max(4096, len(magic) * 2)

            buffer = bytearray()
            pos    = start

            while pos < end:
                to_read = min(chunk_size, end - pos)
                data    = self.read_bytes(to_read)
                buffer.extend(data)

                idx = buffer.find(magic)
                if idx != -1:
                    return start + idx

                # Keep overlap to handle magic spanning chunks
                overlap = len(magic) - 1
                if len(buffer) > overlap:
                    buffer = buffer[-overlap:]
                    start  = pos + to_read - overlap
                pos += to_read

            return None
        finally:
            self.restore_position(saved)

    # -------------------------------------------------------------------------
    # Statistical Operations
    # -------------------------------------------------------------------------

    def byte_frequency(
        self,
        start: Optional[int] = None,
        end: Optional[int] = None
    ) -> dict:
        """
        Calculate byte frequency distribution.

        Returns:
            Dictionary mapping byte values (0-255) to their counts
        """
        saved = self.save_position()
        try:
            freq = {i: 0 for i in range(256)}
            for _, chunk in self.iter_chunks(4096, start, end):
                for b in chunk:
                    freq[b] += 1
            return freq
        finally:
            self.restore_position(saved)

    def entropy(
        self,
        start: Optional[int] = None,
        end: Optional[int] = None
    ) -> float:
        """
        Calculate Shannon entropy of file region.

        Returns:
            Entropy value (0.0 = uniform, 8.0 = maximum randomness)
        """
        import math
        freq  = self.byte_frequency(start, end)
        total = sum(freq.values())
        if total == 0:
            return 0.0

        entropy = 0.0
        for count in freq.values():
            if count > 0:
                prob = count / total
                entropy -= prob * math.log2(prob)

        return entropy

    def null_ratio(
        self,
        start: Optional[int] = None,
        end: Optional[int] = None
    ) -> float:
        """Calculate ratio of null (0x00) bytes in a region."""
        freq  = self.byte_frequency(start, end)
        total = sum(freq.values())
        if total == 0:
            return 0.0
        return freq[0] / total

    # -------------------------------------------------------------------------
    # Representation
    # -------------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"BinaryReader("
            f"source={self._source_name!r}, "
            f"size=0x{self._size:08X}, "
            f"pos=0x{self.position:08X}, "
            f"endianness={self._endianness.name}"
            f")"
        )

    def __str__(self) -> str:
        return (
            f"BinaryReader [{self._source_name}] "
            f"pos=0x{self.position:08X}/{self._size:08X}"
        )

    def info(self) -> dict:
        """Return a dictionary of reader information."""
        return {
            "source":     self._source_name,
            "size":       self._size,
            "position":   self.position,
            "remaining":  self.remaining,
            "endianness": self._endianness.name,
            "at_end":     self.at_end,
            "bookmarks":  len(self._bookmarks),
            "mmap":       self._mmap_obj is not None,
        }


# =============================================================================
# Factory Functions
# =============================================================================

def from_file(
    path: Union[str, Path],
    endianness: Endianness = Endianness.LITTLE,
    use_mmap: bool = False
) -> BinaryReader:
    """Create a BinaryReader from a file path."""
    return BinaryReader(path, endianness=endianness, use_mmap=use_mmap)


def from_bytes(
    data: Union[bytes, bytearray],
    endianness: Endianness = Endianness.LITTLE
) -> BinaryReader:
    """Create a BinaryReader from bytes or bytearray."""
    return BinaryReader(data, endianness=endianness)


def from_hex_string(
    hex_str: str,
    endianness: Endianness = Endianness.LITTLE
) -> BinaryReader:
    """Create a BinaryReader from a hex string (spaces ignored)."""
    cleaned = hex_str.replace(" ", "").replace("\n", "").replace("\t", "")
    data    = bytes.fromhex(cleaned)
    return from_bytes(data, endianness)


# =============================================================================
# Utility: Multi-File Reader
# =============================================================================

class MultiFileReader:
    """
    Read from multiple files as if they were concatenated into one stream.
    Useful for split ROMs and multi-part firmware images.
    """

    def __init__(
        self,
        files:      List[Union[str, Path]],
        endianness: Endianness = Endianness.LITTLE
    ):
        self._files      = [Path(f) for f in files]
        self._endianness = endianness
        self._readers:   List[BinaryReader] = []
        self._sizes:     List[int]           = []
        self._total_size = 0

        for path in self._files:
            reader = BinaryReader(path, endianness=endianness)
            self._readers.append(reader)
            self._sizes.append(reader.size)
            self._total_size += reader.size

        self._global_pos = 0

    def _resolve_position(self, global_pos: int) -> Tuple[int, int]:
        """Resolve global position to (reader_index, local_offset)."""
        acc = 0
        for i, size in enumerate(self._sizes):
            if global_pos < acc + size:
                return i, global_pos - acc
            acc += size
        raise InvalidOffsetError(global_pos, self._total_size)

    def seek(self, offset: int) -> None:
        """Seek to global offset."""
        if offset < 0 or offset > self._total_size:
            raise InvalidOffsetError(offset, self._total_size)
        self._global_pos = offset

    def read_bytes(self, size: int) -> bytes:
        """Read bytes across file boundaries."""
        result = bytearray()
        remaining = size

        while remaining > 0:
            idx, local_offset = self._resolve_position(self._global_pos)
            reader = self._readers[idx]
            reader.seek(local_offset)
            available = reader.remaining
            to_read = min(remaining, available)
            chunk = reader.read_bytes(to_read)
            result.extend(chunk)
            self._global_pos += to_read
            remaining -= to_read

            if to_read == 0:
                raise EndOfFileError(self._global_pos, size, len(result))

        return bytes(result)

    @property
    def total_size(self) -> int:
        """Total size across all files."""
        return self._total_size

    @property
    def position(self) -> int:
        """Current global position."""
        return self._global_pos

    def close(self) -> None:
        """Close all readers."""
        for reader in self._readers:
            reader.close()

    def __enter__(self) -> "MultiFileReader":
        return self

    def __exit__(self, *args) -> None:
        self.close()
