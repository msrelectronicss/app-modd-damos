# =============================================================================
# BinModder - Binary Writer Module
# =============================================================================
# Provides comprehensive binary file writing capabilities with transaction
# support, undo/redo history, endianness-aware writing, and atomic operations.
# Supports creating new binary files or modifying existing ones with safety.
#
# Author: MSR Electronics
# Version: 1.0.0
# =============================================================================

import os
import io
import struct
import shutil
import tempfile
from enum import Enum
from typing import Optional, Union, List, Tuple, Any, BinaryIO
from pathlib import Path
from copy import deepcopy

from .binary_reader import Endianness, BinaryReaderError


# =============================================================================
# Exceptions
# =============================================================================

class BinaryWriterError(Exception):
    """Base exception for binary writer errors."""
    pass


class WriteOutOfBoundsError(BinaryWriterError):
    """Raised when writing beyond the allowed bounds."""
    def __init__(self, offset: int, write_size: int, file_size: int):
        self.offset     = offset
        self.write_size = write_size
        self.file_size  = file_size
        super().__init__(
            f"Write at 0x{offset:08X} ({write_size} bytes) exceeds file size 0x{file_size:08X}"
        )


class TransactionError(BinaryWriterError):
    """Raised when a transaction operation fails."""
    pass


class WriteAlignmentError(BinaryWriterError):
    """Raised when a write violates alignment requirements."""
    def __init__(self, offset: int, alignment: int):
        super().__init__(
            f"Offset 0x{offset:08X} is not aligned to {alignment} bytes"
        )


# =============================================================================
# Write Operation (Undo/Redo support)
# =============================================================================

class WriteOperation:
    """Records a single write operation for undo/redo support."""

    def __init__(self, offset: int, old_data: bytes, new_data: bytes, description: str = ""):
        self.offset      = offset
        self.old_data    = old_data
        self.new_data    = new_data
        self.description = description

    def __repr__(self) -> str:
        return (
            f"WriteOperation("
            f"offset=0x{self.offset:08X}, "
            f"size={len(self.new_data)}, "
            f"desc={self.description!r})"
        )

    def reverse(self) -> "WriteOperation":
        """Create the reverse (undo) operation."""
        return WriteOperation(
            offset=self.offset,
            old_data=self.new_data,
            new_data=self.old_data,
            description=f"Undo: {self.description}",
        )


# =============================================================================
# Write History (Undo/Redo stack)
# =============================================================================

class WriteHistory:
    """Manages undo/redo history for write operations."""

    def __init__(self, max_history: int = 500):
        self._undo_stack: List[WriteOperation] = []
        self._redo_stack: List[WriteOperation] = []
        self._max_history = max_history

    def push(self, op: WriteOperation) -> None:
        """Push a new operation onto the undo stack."""
        self._undo_stack.append(op)
        self._redo_stack.clear()  # Clear redo stack on new operation
        if len(self._undo_stack) > self._max_history:
            self._undo_stack.pop(0)

    def pop_undo(self) -> Optional[WriteOperation]:
        """Pop the last operation for undoing."""
        if not self._undo_stack:
            return None
        op = self._undo_stack.pop()
        self._redo_stack.append(op)
        return op

    def pop_redo(self) -> Optional[WriteOperation]:
        """Pop the last undone operation for redoing."""
        if not self._redo_stack:
            return None
        op = self._redo_stack.pop()
        self._undo_stack.append(op)
        return op

    @property
    def can_undo(self) -> bool:
        return len(self._undo_stack) > 0

    @property
    def can_redo(self) -> bool:
        return len(self._redo_stack) > 0

    def clear(self) -> None:
        """Clear all history."""
        self._undo_stack.clear()
        self._redo_stack.clear()

    def undo_count(self) -> int:
        return len(self._undo_stack)

    def redo_count(self) -> int:
        return len(self._redo_stack)


# =============================================================================
# Write Transaction
# =============================================================================

class WriteTransaction:
    """
    Context manager for atomic write transactions.

    All writes within a transaction are applied atomically.
    If any write fails, all changes are rolled back.

    Usage:
        with writer.begin_transaction("My Changes") as tx:
            tx.write_uint32_le(0x1000, 0xDEADBEEF)
            tx.write_bytes(0x2000, b"HELLO")
            # Committed automatically on success
            # Rolled back automatically on exception
    """

    def __init__(self, writer: "BinaryWriter", description: str = ""):
        self._writer       = writer
        self._description  = description
        self._operations:  List[WriteOperation] = []
        self._committed    = False
        self._rolled_back  = False

    def _record_write(
        self, offset: int, new_data: bytes, description: str = ""
    ) -> None:
        """Record a write operation within this transaction."""
        # Read current data for undo
        saved_pos = self._writer.position
        self._writer._stream.seek(offset)
        old_data = self._writer._stream.read(len(new_data))
        self._writer._stream.seek(saved_pos)

        # Apply the write
        self._writer._stream.seek(offset)
        self._writer._stream.write(new_data)
        self._writer._stream.seek(saved_pos)

        op = WriteOperation(offset, old_data, new_data, description or self._description)
        self._operations.append(op)

    def write_bytes(
        self, offset: int, data: bytes, description: str = ""
    ) -> None:
        """Write bytes within this transaction."""
        self._writer._check_bounds(offset, len(data))
        self._record_write(offset, data, description)

    def write_uint8(self, offset: int, value: int) -> None:
        self.write_bytes(offset, struct.pack("B", value & 0xFF))

    def write_uint16_le(self, offset: int, value: int) -> None:
        self.write_bytes(offset, struct.pack("<H", value & 0xFFFF))

    def write_uint16_be(self, offset: int, value: int) -> None:
        self.write_bytes(offset, struct.pack(">H", value & 0xFFFF))

    def write_uint32_le(self, offset: int, value: int) -> None:
        self.write_bytes(offset, struct.pack("<I", value & 0xFFFFFFFF))

    def write_uint32_be(self, offset: int, value: int) -> None:
        self.write_bytes(offset, struct.pack(">I", value & 0xFFFFFFFF))

    def write_uint64_le(self, offset: int, value: int) -> None:
        self.write_bytes(offset, struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))

    def write_uint64_be(self, offset: int, value: int) -> None:
        self.write_bytes(offset, struct.pack(">Q", value & 0xFFFFFFFFFFFFFFFF))

    def commit(self) -> None:
        """Commit the transaction."""
        if self._committed or self._rolled_back:
            return
        # Combine all operations into one history entry
        if self._operations:
            combined_op = WriteOperation(
                offset=self._operations[0].offset,
                old_data=b"".join(op.old_data for op in self._operations),
                new_data=b"".join(op.new_data for op in self._operations),
                description=self._description,
            )
            self._writer._history.push(combined_op)
        self._committed = True

    def rollback(self) -> None:
        """Roll back all writes in this transaction."""
        if self._committed or self._rolled_back:
            return
        # Reverse all operations in reverse order
        for op in reversed(self._operations):
            self._writer._stream.seek(op.offset)
            self._writer._stream.write(op.old_data)
        self._rolled_back = True

    def __enter__(self) -> "WriteTransaction":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if exc_type is not None:
            self.rollback()
        else:
            self.commit()


# =============================================================================
# Binary Writer - Main Class
# =============================================================================

class BinaryWriter:
    """
    Advanced binary file writer with transaction support and undo/redo.

    Features:
    - Write all primitive types with endianness control
    - Transaction-based atomic writes with rollback
    - Undo/redo history
    - Insert, overwrite, and append modes
    - Alignment padding
    - Fill/pattern operations
    - Backup before modifying
    - Context manager support

    Usage:
        # Modify existing file
        with BinaryWriter("myfile.bin") as w:
            w.seek(0x1000)
            w.write_uint32_le(0xDEADBEEF)

        # Create new file
        writer = BinaryWriter.create("newfile.bin", size=0x10000)
        writer.fill(0xFF)
        writer.write_bytes_at(0x0, b"MAGIC")
        writer.save()
    """

    def __init__(
        self,
        source:      Union[str, Path, bytes, bytearray, BinaryIO],
        endianness:  Endianness = Endianness.LITTLE,
        allow_grow:  bool       = False,
        max_history: int        = 500,
        auto_backup: bool       = False,
    ):
        """
        Initialize BinaryWriter.

        Args:
            source:      File path, bytes, bytearray, or file object
            endianness:  Default byte order
            allow_grow:  Allow the file to grow beyond its original size
            max_history: Maximum undo history entries
            auto_backup: Create a backup before any modifications
        """
        self._endianness  = endianness
        self._allow_grow  = allow_grow
        self._history     = WriteHistory(max_history)
        self._modified    = False
        self._source_path: Optional[Path] = None
        self._backup_path: Optional[Path] = None
        self._owned_file  = False

        self._stream = self._open_source(source)
        self._size   = self._get_size()

        if auto_backup and self._source_path:
            self._create_backup()

    # -------------------------------------------------------------------------
    # Initialization
    # -------------------------------------------------------------------------

    def _open_source(
        self, source: Union[str, Path, bytes, bytearray, BinaryIO]
    ) -> io.RawIOBase:
        """Open source for read-write access."""
        if isinstance(source, (str, Path)):
            path = Path(source)
            if not path.exists():
                raise FileNotFoundError(f"File not found: {path}")
            self._source_path = path
            self._owned_file  = True
            return open(path, "r+b")

        elif isinstance(source, bytes):
            return io.BytesIO(bytearray(source))

        elif isinstance(source, bytearray):
            return io.BytesIO(source)

        elif hasattr(source, "write"):
            return source

        else:
            raise TypeError(f"Unsupported source type: {type(source).__name__}")

    def _get_size(self) -> int:
        """Get current stream size."""
        pos = self._stream.tell()
        self._stream.seek(0, 2)
        size = self._stream.tell()
        self._stream.seek(pos)
        return size

    def _create_backup(self) -> None:
        """Create a .bak backup of the source file."""
        if self._source_path:
            backup = self._source_path.with_suffix(
                self._source_path.suffix + ".bak"
            )
            shutil.copy2(self._source_path, backup)
            self._backup_path = backup

    # -------------------------------------------------------------------------
    # Context Manager
    # -------------------------------------------------------------------------

    def __enter__(self) -> "BinaryWriter":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def close(self) -> None:
        """Close the writer."""
        if self._owned_file and self._stream:
            try:
                self._stream.close()
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # Factory Methods
    # -------------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        path: Union[str, Path],
        size: int = 0,
        fill_byte: int = 0x00,
        endianness: Endianness = Endianness.LITTLE
    ) -> "BinaryWriter":
        """
        Create a new binary file.

        Args:
            path:       Destination file path
            size:       Initial file size in bytes
            fill_byte:  Byte to fill with (default: 0x00)
            endianness: Default byte order

        Returns:
            BinaryWriter instance for the new file
        """
        path = Path(path)
        with open(path, "wb") as f:
            if size > 0:
                f.write(bytes([fill_byte & 0xFF]) * size)
        return cls(path, endianness=endianness, allow_grow=True)

    @classmethod
    def from_bytes(
        cls,
        data: Union[bytes, bytearray],
        endianness: Endianness = Endianness.LITTLE
    ) -> "BinaryWriter":
        """Create a BinaryWriter from bytes/bytearray."""
        return cls(bytearray(data), endianness=endianness)

    @classmethod
    def empty(
        cls,
        endianness: Endianness = Endianness.LITTLE
    ) -> "BinaryWriter":
        """Create an empty BinaryWriter (in-memory)."""
        buf = io.BytesIO()
        instance = cls.__new__(cls)
        instance._endianness  = endianness
        instance._allow_grow  = True
        instance._history     = WriteHistory()
        instance._modified    = False
        instance._source_path = None
        instance._backup_path = None
        instance._owned_file  = False
        instance._stream      = buf
        instance._size        = 0
        return instance

    # -------------------------------------------------------------------------
    # Properties
    # -------------------------------------------------------------------------

    @property
    def endianness(self) -> Endianness:
        return self._endianness

    @endianness.setter
    def endianness(self, value: Endianness) -> None:
        self._endianness = value

    @property
    def position(self) -> int:
        return self._stream.tell()

    @property
    def size(self) -> int:
        return self._size

    @property
    def modified(self) -> bool:
        return self._modified

    @property
    def can_undo(self) -> bool:
        return self._history.can_undo

    @property
    def can_redo(self) -> bool:
        return self._history.can_redo

    @property
    def backup_path(self) -> Optional[Path]:
        return self._backup_path

    # -------------------------------------------------------------------------
    # Position Control
    # -------------------------------------------------------------------------

    def seek(self, offset: int, mode: int = 0) -> int:
        """Seek to position. mode: 0=begin, 1=current, 2=end."""
        self._stream.seek(offset, mode)
        return self._stream.tell()

    def seek_begin(self) -> int:
        return self.seek(0)

    def seek_end(self) -> int:
        return self.seek(0, 2)

    def tell(self) -> int:
        return self._stream.tell()

    def skip(self, n: int) -> int:
        return self.seek(n, 1)

    # -------------------------------------------------------------------------
    # Bounds Checking
    # -------------------------------------------------------------------------

    def _check_bounds(self, offset: int, size: int) -> None:
        """Verify write is within bounds."""
        end = offset + size
        if end > self._size:
            if self._allow_grow:
                self._size = end
            else:
                raise WriteOutOfBoundsError(offset, size, self._size)

    def _check_alignment(self, offset: int, alignment: int) -> None:
        """Verify offset alignment."""
        if alignment > 1 and (offset % alignment) != 0:
            raise WriteAlignmentError(offset, alignment)

    # -------------------------------------------------------------------------
    # Core Write Operations
    # -------------------------------------------------------------------------

    def write_bytes(self, data: bytes) -> None:
        """
        Write bytes at current position and advance position.

        Args:
            data: Bytes to write
        """
        offset = self.position
        self._check_bounds(offset, len(data))

        # Record old data for undo
        self._stream.seek(offset)
        old_data = self._stream.read(len(data))
        self._stream.seek(offset)
        self._stream.write(data)

        op = WriteOperation(offset, old_data, data, "write_bytes")
        self._history.push(op)
        self._modified = True

    def write_bytes_at(self, offset: int, data: bytes, description: str = "") -> None:
        """Write bytes at a specific offset without moving current position."""
        saved = self.position
        try:
            self.seek(offset)
            self._check_bounds(offset, len(data))
            self._stream.seek(offset)
            old_data = self._stream.read(len(data))
            self._stream.seek(offset)
            self._stream.write(data)

            op = WriteOperation(offset, old_data, data, description or "write_bytes_at")
            self._history.push(op)
            self._modified = True
        finally:
            self.seek(saved)

    def write_byte(self, value: int) -> None:
        """Write a single byte at current position."""
        self.write_bytes(bytes([value & 0xFF]))

    def write_byte_at(self, offset: int, value: int) -> None:
        """Write a single byte at specific offset."""
        self.write_bytes_at(offset, bytes([value & 0xFF]))

    def write_byte_repeated(self, value: int, count: int) -> None:
        """Write a byte repeated `count` times."""
        self.write_bytes(bytes([value & 0xFF]) * count)

    # -------------------------------------------------------------------------
    # Struct-Based Write Operations
    # -------------------------------------------------------------------------

    def _pack_and_write(
        self,
        fmt_char:   str,
        value:      Any,
        endianness: Optional[Endianness] = None
    ) -> None:
        """Pack a value and write at current position."""
        endi   = endianness or self._endianness
        prefix = endi.struct_prefix()
        fmt    = f"{prefix}{fmt_char}"
        data   = struct.pack(fmt, value)
        self.write_bytes(data)

    def _pack_and_write_at(
        self,
        offset:     int,
        fmt_char:   str,
        value:      Any,
        endianness: Optional[Endianness] = None,
        description: str = ""
    ) -> None:
        """Pack a value and write at specific offset."""
        endi   = endianness or self._endianness
        prefix = endi.struct_prefix()
        fmt    = f"{prefix}{fmt_char}"
        data   = struct.pack(fmt, value)
        self.write_bytes_at(offset, data, description)

    # -------------------------------------------------------------------------
    # Unsigned Integer Writes (at current position)
    # -------------------------------------------------------------------------

    def write_uint8(self, value: int) -> None:
        """Write unsigned 8-bit integer."""
        self._pack_and_write("B", value & 0xFF)

    def write_uint16(self, value: int, endianness: Optional[Endianness] = None) -> None:
        """Write unsigned 16-bit integer."""
        self._pack_and_write("H", value & 0xFFFF, endianness)

    def write_uint32(self, value: int, endianness: Optional[Endianness] = None) -> None:
        """Write unsigned 32-bit integer."""
        self._pack_and_write("I", value & 0xFFFFFFFF, endianness)

    def write_uint64(self, value: int, endianness: Optional[Endianness] = None) -> None:
        """Write unsigned 64-bit integer."""
        self._pack_and_write("Q", value & 0xFFFFFFFFFFFFFFFF, endianness)

    def write_uint16_le(self, value: int) -> None:
        self.write_uint16(value, Endianness.LITTLE)

    def write_uint16_be(self, value: int) -> None:
        self.write_uint16(value, Endianness.BIG)

    def write_uint32_le(self, value: int) -> None:
        self.write_uint32(value, Endianness.LITTLE)

    def write_uint32_be(self, value: int) -> None:
        self.write_uint32(value, Endianness.BIG)

    def write_uint64_le(self, value: int) -> None:
        self.write_uint64(value, Endianness.LITTLE)

    def write_uint64_be(self, value: int) -> None:
        self.write_uint64(value, Endianness.BIG)

    # Short aliases
    def write_u8(self, v: int) -> None:  self.write_uint8(v)
    def write_u16(self, v: int) -> None: self.write_uint16(v)
    def write_u32(self, v: int) -> None: self.write_uint32(v)
    def write_u64(self, v: int) -> None: self.write_uint64(v)
    def write_u16_le(self, v: int) -> None: self.write_uint16_le(v)
    def write_u16_be(self, v: int) -> None: self.write_uint16_be(v)
    def write_u32_le(self, v: int) -> None: self.write_uint32_le(v)
    def write_u32_be(self, v: int) -> None: self.write_uint32_be(v)
    def write_u64_le(self, v: int) -> None: self.write_uint64_le(v)
    def write_u64_be(self, v: int) -> None: self.write_uint64_be(v)

    # -------------------------------------------------------------------------
    # Unsigned Integer Writes (at specific offset)
    # -------------------------------------------------------------------------

    def write_uint8_at(self, offset: int, value: int, desc: str = "") -> None:
        self._pack_and_write_at(offset, "B", value & 0xFF, description=desc)

    def write_uint16_at(
        self, offset: int, value: int,
        endianness: Optional[Endianness] = None, desc: str = ""
    ) -> None:
        self._pack_and_write_at(offset, "H", value & 0xFFFF, endianness, desc)

    def write_uint32_at(
        self, offset: int, value: int,
        endianness: Optional[Endianness] = None, desc: str = ""
    ) -> None:
        self._pack_and_write_at(offset, "I", value & 0xFFFFFFFF, endianness, desc)

    def write_uint64_at(
        self, offset: int, value: int,
        endianness: Optional[Endianness] = None, desc: str = ""
    ) -> None:
        self._pack_and_write_at(offset, "Q", value & 0xFFFFFFFFFFFFFFFF, endianness, desc)

    def write_u16_le_at(self, offset: int, v: int) -> None:
        self.write_uint16_at(offset, v, Endianness.LITTLE)

    def write_u16_be_at(self, offset: int, v: int) -> None:
        self.write_uint16_at(offset, v, Endianness.BIG)

    def write_u32_le_at(self, offset: int, v: int) -> None:
        self.write_uint32_at(offset, v, Endianness.LITTLE)

    def write_u32_be_at(self, offset: int, v: int) -> None:
        self.write_uint32_at(offset, v, Endianness.BIG)

    def write_u64_le_at(self, offset: int, v: int) -> None:
        self.write_uint64_at(offset, v, Endianness.LITTLE)

    def write_u64_be_at(self, offset: int, v: int) -> None:
        self.write_uint64_at(offset, v, Endianness.BIG)

    # -------------------------------------------------------------------------
    # Signed Integer Writes
    # -------------------------------------------------------------------------

    def write_int8(self, value: int) -> None:
        self._pack_and_write("b", value)

    def write_int16(self, value: int, endianness: Optional[Endianness] = None) -> None:
        self._pack_and_write("h", value, endianness)

    def write_int32(self, value: int, endianness: Optional[Endianness] = None) -> None:
        self._pack_and_write("i", value, endianness)

    def write_int64(self, value: int, endianness: Optional[Endianness] = None) -> None:
        self._pack_and_write("q", value, endianness)

    def write_int16_le(self, v: int) -> None: self.write_int16(v, Endianness.LITTLE)
    def write_int16_be(self, v: int) -> None: self.write_int16(v, Endianness.BIG)
    def write_int32_le(self, v: int) -> None: self.write_int32(v, Endianness.LITTLE)
    def write_int32_be(self, v: int) -> None: self.write_int32(v, Endianness.BIG)
    def write_int64_le(self, v: int) -> None: self.write_int64(v, Endianness.LITTLE)
    def write_int64_be(self, v: int) -> None: self.write_int64(v, Endianness.BIG)

    def write_i8(self, v: int) -> None:  self.write_int8(v)
    def write_i16(self, v: int) -> None: self.write_int16(v)
    def write_i32(self, v: int) -> None: self.write_int32(v)
    def write_i64(self, v: int) -> None: self.write_int64(v)

    # -------------------------------------------------------------------------
    # Float Writes
    # -------------------------------------------------------------------------

    def write_float32(self, value: float, endianness: Optional[Endianness] = None) -> None:
        """Write 32-bit float."""
        self._pack_and_write("f", value, endianness)

    def write_float64(self, value: float, endianness: Optional[Endianness] = None) -> None:
        """Write 64-bit double."""
        self._pack_and_write("d", value, endianness)

    def write_f32_le(self, v: float) -> None: self.write_float32(v, Endianness.LITTLE)
    def write_f32_be(self, v: float) -> None: self.write_float32(v, Endianness.BIG)
    def write_f64_le(self, v: float) -> None: self.write_float64(v, Endianness.LITTLE)
    def write_f64_be(self, v: float) -> None: self.write_float64(v, Endianness.BIG)

    # -------------------------------------------------------------------------
    # String Writes
    # -------------------------------------------------------------------------

    def write_cstring(self, text: str, encoding: str = "utf-8") -> None:
        """Write a null-terminated C string."""
        data = text.encode(encoding) + b"\x00"
        self.write_bytes(data)

    def write_fixed_string(
        self, text: str, size: int,
        encoding: str = "utf-8",
        pad_byte: int = 0x00
    ) -> None:
        """Write a fixed-length string, padded or truncated to `size` bytes."""
        encoded = text.encode(encoding)
        if len(encoded) > size:
            encoded = encoded[:size]
        elif len(encoded) < size:
            encoded = encoded + bytes([pad_byte]) * (size - len(encoded))
        self.write_bytes(encoded)

    def write_pascal_string(
        self, text: str,
        length_size: int = 1,
        encoding: str = "utf-8"
    ) -> None:
        """Write a Pascal-style string with length prefix."""
        encoded = text.encode(encoding)
        length  = len(encoded)
        if length_size == 1:
            self.write_uint8(length)
        elif length_size == 2:
            self.write_uint16(length)
        elif length_size == 4:
            self.write_uint32(length)
        else:
            raise ValueError(f"Invalid length_size: {length_size}")
        self.write_bytes(encoded)

    def write_utf16_string(
        self, text: str,
        endianness: Optional[Endianness] = None
    ) -> None:
        """Write a null-terminated UTF-16 string."""
        endi = endianness or self._endianness
        for ch in text:
            code = ord(ch)
            if endi == Endianness.LITTLE:
                self.write_uint16_le(code)
            else:
                self.write_uint16_be(code)
        # Null terminator
        if endi == Endianness.LITTLE:
            self.write_uint16_le(0)
        else:
            self.write_uint16_be(0)

    def write_hex_string(self, hex_str: str) -> None:
        """Write bytes from a hex string (spaces ignored)."""
        cleaned = hex_str.replace(" ", "").replace("\n", "").replace("\t", "")
        data    = bytes.fromhex(cleaned)
        self.write_bytes(data)

    # -------------------------------------------------------------------------
    # Fill Operations
    # -------------------------------------------------------------------------

    def fill(
        self,
        byte_value: int = 0x00,
        start: Optional[int] = None,
        end: Optional[int] = None
    ) -> None:
        """
        Fill a region with a constant byte value.

        Args:
            byte_value: Byte to fill (0-255)
            start:      Start offset (default: 0)
            end:        End offset (default: end of file)
        """
        if start is None:
            start = 0
        if end is None:
            end = self._size

        size = end - start
        if size <= 0:
            return

        data = bytes([byte_value & 0xFF]) * size
        self.write_bytes_at(start, data, f"fill 0x{byte_value:02X}")

    def fill_pattern(
        self,
        pattern:    bytes,
        start:      Optional[int] = None,
        end:        Optional[int] = None
    ) -> None:
        """Fill a region with a repeating byte pattern."""
        if start is None:
            start = 0
        if end is None:
            end = self._size

        size = end - start
        if size <= 0 or not pattern:
            return

        # Tile the pattern to fill the region
        repeat = (size + len(pattern) - 1) // len(pattern)
        data   = (pattern * repeat)[:size]
        self.write_bytes_at(start, data, "fill_pattern")

    def zero_fill(
        self,
        start: Optional[int] = None,
        end:   Optional[int] = None
    ) -> None:
        """Fill a region with zero bytes."""
        self.fill(0x00, start, end)

    def ff_fill(
        self,
        start: Optional[int] = None,
        end:   Optional[int] = None
    ) -> None:
        """Fill a region with 0xFF bytes."""
        self.fill(0xFF, start, end)

    # -------------------------------------------------------------------------
    # Pad / Align
    # -------------------------------------------------------------------------

    def pad_to_alignment(
        self,
        alignment:  int,
        pad_byte:   int = 0x00
    ) -> int:
        """
        Pad current position to the next alignment boundary.

        Args:
            alignment: Alignment value (must be power of 2)
            pad_byte:  Byte to pad with

        Returns:
            Number of padding bytes written
        """
        pos     = self.position
        aligned = (pos + alignment - 1) & ~(alignment - 1)
        padding = aligned - pos
        if padding > 0:
            self.write_bytes(bytes([pad_byte & 0xFF]) * padding)
        return padding

    def align_to(self, alignment: int, pad_byte: int = 0x00) -> int:
        """Alias for pad_to_alignment."""
        return self.pad_to_alignment(alignment, pad_byte)

    def pad_to_size(self, target_size: int, pad_byte: int = 0x00) -> int:
        """Pad file to a specific size."""
        current = self._size
        if target_size <= current:
            return 0
        padding = target_size - current
        self.seek_end()
        self.write_bytes(bytes([pad_byte & 0xFF]) * padding)
        return padding

    # -------------------------------------------------------------------------
    # Array / Batch Writes
    # -------------------------------------------------------------------------

    def write_uint8_array(self, values: List[int]) -> None:
        """Write an array of uint8 values."""
        self.write_bytes(bytes(v & 0xFF for v in values))

    def write_uint16_array(
        self, values: List[int],
        endianness: Optional[Endianness] = None
    ) -> None:
        """Write an array of uint16 values."""
        for v in values:
            self.write_uint16(v, endianness)

    def write_uint32_array(
        self, values: List[int],
        endianness: Optional[Endianness] = None
    ) -> None:
        """Write an array of uint32 values."""
        for v in values:
            self.write_uint32(v, endianness)

    def write_uint64_array(
        self, values: List[int],
        endianness: Optional[Endianness] = None
    ) -> None:
        """Write an array of uint64 values."""
        for v in values:
            self.write_uint64(v, endianness)

    def write_float32_array(
        self, values: List[float],
        endianness: Optional[Endianness] = None
    ) -> None:
        """Write an array of float32 values."""
        for v in values:
            self.write_float32(v, endianness)

    # -------------------------------------------------------------------------
    # Struct Format Write
    # -------------------------------------------------------------------------

    def write_struct_format(
        self,
        format_string: str,
        *values,
        endianness: Optional[Endianness] = None
    ) -> None:
        """
        Write multiple values using a struct format string.

        Args:
            format_string: Struct format (without endian prefix)
            *values:       Values to write
            endianness:    Byte order

        Example:
            writer.write_struct_format("HHI", 1, 2, 3)  # 2x uint16, 1x uint32
        """
        endi   = endianness or self._endianness
        prefix = endi.struct_prefix()
        fmt    = f"{prefix}{format_string}"
        data   = struct.pack(fmt, *values)
        self.write_bytes(data)

    # -------------------------------------------------------------------------
    # Insert / Delete Operations
    # -------------------------------------------------------------------------

    def insert_bytes(self, offset: int, data: bytes) -> None:
        """
        Insert bytes at offset, shifting existing data to the right.

        This requires allow_grow=True.

        Args:
            offset: Position to insert at
            data:   Bytes to insert
        """
        if not self._allow_grow:
            raise BinaryWriterError(
                "Cannot insert bytes: allow_grow is False"
            )

        # Read all data after insertion point
        self._stream.seek(offset)
        tail = self._stream.read()

        # Write inserted data then tail
        self._stream.seek(offset)
        self._stream.write(data)
        self._stream.write(tail)
        self._size += len(data)
        self._modified = True

    def delete_bytes(self, offset: int, size: int) -> bytes:
        """
        Delete bytes at offset, shifting remaining data left.

        Args:
            offset: Position to delete from
            size:   Number of bytes to delete

        Returns:
            The deleted bytes
        """
        self._stream.seek(offset)
        deleted = self._stream.read(size)

        tail = self._stream.read()

        self._stream.seek(offset)
        self._stream.write(tail)
        self._stream.truncate()
        self._size -= len(deleted)
        self._modified = True

        return deleted

    # -------------------------------------------------------------------------
    # Append Operations
    # -------------------------------------------------------------------------

    def append_bytes(self, data: bytes) -> int:
        """
        Append bytes to end of file.

        Returns:
            Offset where data was written
        """
        offset = self._size
        self._stream.seek(0, 2)
        self._stream.write(data)
        self._size += len(data)
        self._modified = True
        return offset

    def append_uint8(self, value: int) -> int:
        return self.append_bytes(struct.pack("B", value & 0xFF))

    def append_uint16_le(self, value: int) -> int:
        return self.append_bytes(struct.pack("<H", value & 0xFFFF))

    def append_uint32_le(self, value: int) -> int:
        return self.append_bytes(struct.pack("<I", value & 0xFFFFFFFF))

    def append_uint64_le(self, value: int) -> int:
        return self.append_bytes(struct.pack("<Q", value))

    def append_uint16_be(self, value: int) -> int:
        return self.append_bytes(struct.pack(">H", value & 0xFFFF))

    def append_uint32_be(self, value: int) -> int:
        return self.append_bytes(struct.pack(">I", value & 0xFFFFFFFF))

    def append_uint64_be(self, value: int) -> int:
        return self.append_bytes(struct.pack(">Q", value))

    def append_cstring(self, text: str, encoding: str = "utf-8") -> int:
        return self.append_bytes(text.encode(encoding) + b"\x00")

    # -------------------------------------------------------------------------
    # Undo / Redo
    # -------------------------------------------------------------------------

    def undo(self) -> Optional[WriteOperation]:
        """Undo the last write operation."""
        op = self._history.pop_undo()
        if op is None:
            return None
        # Apply the reverse
        self._stream.seek(op.offset)
        self._stream.write(op.old_data)
        return op

    def redo(self) -> Optional[WriteOperation]:
        """Redo the last undone write operation."""
        op = self._history.pop_redo()
        if op is None:
            return None
        self._stream.seek(op.offset)
        self._stream.write(op.new_data)
        return op

    def undo_all(self) -> int:
        """Undo all operations. Returns count of operations undone."""
        count = 0
        while self._history.can_undo:
            self.undo()
            count += 1
        return count

    # -------------------------------------------------------------------------
    # Transactions
    # -------------------------------------------------------------------------

    def begin_transaction(self, description: str = "") -> WriteTransaction:
        """
        Begin a write transaction.

        Usage:
            with writer.begin_transaction("Apply Header Patch") as tx:
                tx.write_uint32_le(0x0, 0xDEADBEEF)
                tx.write_bytes(0x10, b"PATCHED")
        """
        return WriteTransaction(self, description)

    # -------------------------------------------------------------------------
    # Save / Export
    # -------------------------------------------------------------------------

    def save(self, path: Optional[Union[str, Path]] = None) -> Path:
        """
        Save to file.

        Args:
            path: Destination path (default: original source path)

        Returns:
            Path where file was saved
        """
        if path is None:
            if self._source_path is None:
                raise BinaryWriterError(
                    "No source path: specify a path to save to"
                )
            path = self._source_path
        else:
            path = Path(path)

        self._stream.seek(0)
        data = self._stream.read()

        with open(path, "wb") as f:
            f.write(data)

        self._modified = False
        return path

    def save_as(self, path: Union[str, Path]) -> Path:
        """Save to a new path."""
        return self.save(path)

    def to_bytes(self) -> bytes:
        """Return entire content as bytes."""
        self._stream.seek(0)
        return self._stream.read()

    def to_bytearray(self) -> bytearray:
        """Return entire content as bytearray."""
        return bytearray(self.to_bytes())

    def export_region(
        self,
        start: int,
        end:   int,
        path:  Union[str, Path]
    ) -> Path:
        """Export a region of the file to a new file."""
        self._stream.seek(start)
        data = self._stream.read(end - start)
        path = Path(path)
        with open(path, "wb") as f:
            f.write(data)
        return path

    # -------------------------------------------------------------------------
    # Restore Backup
    # -------------------------------------------------------------------------

    def restore_backup(self) -> bool:
        """Restore from backup file if it exists."""
        if self._backup_path and self._backup_path.exists() and self._source_path:
            shutil.copy2(self._backup_path, self._source_path)
            # Re-open
            self._stream.close()
            self._stream = open(self._source_path, "r+b")
            self._size   = self._get_size()
            self._modified = False
            self._history.clear()
            return True
        return False

    # -------------------------------------------------------------------------
    # Representation
    # -------------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"BinaryWriter("
            f"size=0x{self._size:08X}, "
            f"pos=0x{self.position:08X}, "
            f"modified={self._modified}, "
            f"endianness={self._endianness.name}"
            f")"
        )

    def info(self) -> dict:
        return {
            "size":       self._size,
            "position":   self.position,
            "modified":   self._modified,
            "endianness": self._endianness.name,
            "allow_grow": self._allow_grow,
            "can_undo":   self.can_undo,
            "can_redo":   self.can_redo,
            "undo_count": self._history.undo_count(),
            "redo_count": self._history.redo_count(),
            "source":     str(self._source_path) if self._source_path else None,
            "backup":     str(self._backup_path) if self._backup_path else None,
        }


# =============================================================================
# Builder Pattern for creating new binary files
# =============================================================================

class BinaryBuilder:
    """
    Fluent API for building binary data from scratch.

    Usage:
        data = (BinaryBuilder()
            .append_bytes(b"MAGIC")
            .append_uint32_le(0x100)
            .append_fixed_string("Hello", 16)
            .pad_to(0x20)
            .build())
    """

    def __init__(self, endianness: Endianness = Endianness.LITTLE):
        self._endianness = endianness
        self._buffer     = bytearray()

    def append_bytes(self, data: bytes) -> "BinaryBuilder":
        self._buffer.extend(data)
        return self

    def append_uint8(self, value: int) -> "BinaryBuilder":
        self._buffer.append(value & 0xFF)
        return self

    def append_uint16_le(self, value: int) -> "BinaryBuilder":
        self._buffer.extend(struct.pack("<H", value & 0xFFFF))
        return self

    def append_uint16_be(self, value: int) -> "BinaryBuilder":
        self._buffer.extend(struct.pack(">H", value & 0xFFFF))
        return self

    def append_uint32_le(self, value: int) -> "BinaryBuilder":
        self._buffer.extend(struct.pack("<I", value & 0xFFFFFFFF))
        return self

    def append_uint32_be(self, value: int) -> "BinaryBuilder":
        self._buffer.extend(struct.pack(">I", value & 0xFFFFFFFF))
        return self

    def append_uint64_le(self, value: int) -> "BinaryBuilder":
        self._buffer.extend(struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))
        return self

    def append_uint64_be(self, value: int) -> "BinaryBuilder":
        self._buffer.extend(struct.pack(">Q", value & 0xFFFFFFFFFFFFFFFF))
        return self

    def append_int32_le(self, value: int) -> "BinaryBuilder":
        self._buffer.extend(struct.pack("<i", value))
        return self

    def append_int32_be(self, value: int) -> "BinaryBuilder":
        self._buffer.extend(struct.pack(">i", value))
        return self

    def append_float32_le(self, value: float) -> "BinaryBuilder":
        self._buffer.extend(struct.pack("<f", value))
        return self

    def append_float64_le(self, value: float) -> "BinaryBuilder":
        self._buffer.extend(struct.pack("<d", value))
        return self

    def append_cstring(self, text: str, encoding: str = "utf-8") -> "BinaryBuilder":
        self._buffer.extend(text.encode(encoding) + b"\x00")
        return self

    def append_fixed_string(
        self, text: str, size: int,
        encoding: str = "utf-8",
        pad_byte: int = 0x00
    ) -> "BinaryBuilder":
        encoded = text.encode(encoding)
        if len(encoded) > size:
            encoded = encoded[:size]
        else:
            encoded = encoded + bytes([pad_byte]) * (size - len(encoded))
        self._buffer.extend(encoded)
        return self

    def append_hex(self, hex_str: str) -> "BinaryBuilder":
        cleaned = hex_str.replace(" ", "").replace("\n", "")
        self._buffer.extend(bytes.fromhex(cleaned))
        return self

    def fill(self, byte_val: int, size: int) -> "BinaryBuilder":
        self._buffer.extend(bytes([byte_val & 0xFF]) * size)
        return self

    def pad_to(self, alignment: int, pad_byte: int = 0x00) -> "BinaryBuilder":
        pos     = len(self._buffer)
        aligned = (pos + alignment - 1) & ~(alignment - 1)
        padding = aligned - pos
        if padding > 0:
            self._buffer.extend(bytes([pad_byte & 0xFF]) * padding)
        return self

    def pad_to_size(self, size: int, pad_byte: int = 0x00) -> "BinaryBuilder":
        current = len(self._buffer)
        if size > current:
            self._buffer.extend(bytes([pad_byte & 0xFF]) * (size - current))
        return self

    @property
    def position(self) -> int:
        return len(self._buffer)

    @property
    def size(self) -> int:
        return len(self._buffer)

    def build(self) -> bytes:
        """Build and return the binary data as bytes."""
        return bytes(self._buffer)

    def build_bytearray(self) -> bytearray:
        """Build and return the binary data as bytearray."""
        return bytearray(self._buffer)

    def save(self, path: Union[str, Path]) -> Path:
        """Save the built data to a file."""
        path = Path(path)
        with open(path, "wb") as f:
            f.write(self._buffer)
        return path

    def reset(self) -> "BinaryBuilder":
        """Reset the builder buffer."""
        self._buffer = bytearray()
        return self

    def __len__(self) -> int:
        return len(self._buffer)

    def __repr__(self) -> str:
        return f"BinaryBuilder(size={len(self._buffer)} bytes)"
