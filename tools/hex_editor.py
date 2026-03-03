# =============================================================================
# BinModder - Hex Editor Tool
# =============================================================================
# High-level hex editing interface that composes BinaryReader, BinaryWriter,
# and SearchEngine into a single stateful editor object. Tracks a cursor
# position, selection range, modification marks, and undo/redo history.
#
# Author: MSR Electronics
# Version: 1.0.0
# =============================================================================

import sys
from pathlib import Path
from typing import List, Optional, Tuple

from core.binary_reader import BinaryReader, Endianness
from core.binary_writer import BinaryWriter
from core.search_engine import SearchEngine, Pattern, SearchResult
from core.hex_engine    import HexEngine, HexConfig, DisplayMode
from utils.file_utils   import backup_file, safe_write
from utils.log_utils    import BinModderLogger

log = BinModderLogger.get("tools.hex_editor")


# =============================================================================
# HexEditor
# =============================================================================

class HexEditor:
    """Stateful hex editor session for a single binary file.

    Attributes
    ----------
    path : Path | None
        Currently open file, or ``None`` if working with in-memory data.
    data : bytearray
        Live buffer of the file contents.  All edits are performed here
        and are only flushed to disk via :meth:`save`.
    cursor : int
        Current byte offset of the editing cursor.
    selection : tuple[int, int] | None
        ``(start, end)`` byte range (inclusive) of the active selection,
        or ``None`` when nothing is selected.
    modified : bool
        True if the buffer differs from the on-disk content.
    """

    def __init__(
        self,
        path: Optional["str | Path"] = None,
        *,
        endianness: Endianness = Endianness.LITTLE,
    ) -> None:
        self.path:      Optional[Path]              = None
        self.data:      bytearray                   = bytearray()
        self.cursor:    int                         = 0
        self.selection: Optional[Tuple[int, int]]   = None
        self.modified:  bool                        = False
        self._undo:     List[bytearray]             = []
        self._redo:     List[bytearray]             = []
        self._endian    = endianness
        self._hex       = HexEngine(HexConfig(bytes_per_row=16))
        self._search    = SearchEngine()

        if path is not None:
            self.open(path)

    # ------------------------------------------------------------------
    # File I/O
    # ------------------------------------------------------------------

    def open(self, path: "str | Path") -> None:
        """Load a file into the editor buffer.

        Parameters
        ----------
        path : str | Path
            Path to the binary file to open.

        Raises
        ------
        FileNotFoundError
            If the file does not exist.
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"'{p}' not found")
        self.data     = bytearray(p.read_bytes())
        self.path     = p
        self.cursor   = 0
        self.selection = None
        self.modified  = False
        self._undo.clear()
        self._redo.clear()
        log.info("Opened '%s' (%d bytes)", p.name, len(self.data))

    def save(self, path: Optional["str | Path"] = None, backup: bool = False) -> Path:
        """Write the current buffer to disk.

        Parameters
        ----------
        path : str | Path | None
            Destination path.  Defaults to the currently open file.
        backup : bool
            Create a timestamped ``.bak`` copy before overwriting.

        Returns
        -------
        Path
            The path that was written.

        Raises
        ------
        ValueError
            If no path has been set.
        """
        dst = Path(path) if path else self.path
        if dst is None:
            raise ValueError("No file path specified")
        safe_write(dst, bytes(self.data), backup=backup)
        self.path     = dst
        self.modified  = False
        log.info("Saved '%s' (%d bytes)", dst.name, len(self.data))
        return dst

    # ------------------------------------------------------------------
    # Editing operations
    # ------------------------------------------------------------------

    def _snapshot(self) -> None:
        """Push the current buffer onto the undo stack."""
        self._undo.append(bytearray(self.data))
        self._redo.clear()
        if len(self._undo) > 64:
            self._undo.pop(0)

    def write_byte(self, offset: int, value: int) -> None:
        """Overwrite the byte at *offset* with *value* (0–255)."""
        if not 0 <= offset < len(self.data):
            raise IndexError(f"Offset 0x{offset:X} out of range")
        if not 0 <= value <= 0xFF:
            raise ValueError(f"Byte value {value} out of range 0–255")
        self._snapshot()
        self.data[offset] = value
        self.modified = True

    def write_bytes(self, offset: int, patch: bytes) -> None:
        """Overwrite *len(patch)* bytes starting at *offset*.

        Raises
        ------
        IndexError
            If the patch extends beyond the buffer.
        """
        end = offset + len(patch)
        if offset < 0 or end > len(self.data):
            raise IndexError(
                f"Write [{offset:#x}:{end:#x}] exceeds buffer size {len(self.data):#x}"
            )
        self._snapshot()
        self.data[offset:end] = patch
        self.modified = True

    def fill(self, offset: int, size: int, byte: int = 0x00) -> None:
        """Fill *size* bytes starting at *offset* with *byte*."""
        self.write_bytes(offset, bytes([byte]) * size)

    def insert(self, offset: int, data: bytes) -> None:
        """Insert *data* at *offset*, growing the buffer."""
        if not 0 <= offset <= len(self.data):
            raise IndexError(f"Offset 0x{offset:X} out of range")
        self._snapshot()
        self.data[offset:offset] = data
        self.modified = True

    def delete(self, offset: int, size: int) -> bytes:
        """Remove *size* bytes at *offset* and return them."""
        end = offset + size
        if offset < 0 or end > len(self.data):
            raise IndexError(f"Delete [{offset:#x}:{end:#x}] out of range")
        self._snapshot()
        removed = bytes(self.data[offset:end])
        del self.data[offset:end]
        self.modified = True
        return removed

    # ------------------------------------------------------------------
    # Undo / Redo
    # ------------------------------------------------------------------

    def undo(self) -> bool:
        """Restore the previous state. Returns True on success."""
        if not self._undo:
            return False
        self._redo.append(bytearray(self.data))
        self.data = self._undo.pop()
        self.modified = True
        return True

    def redo(self) -> bool:
        """Re-apply a previously undone change. Returns True on success."""
        if not self._redo:
            return False
        self._undo.append(bytearray(self.data))
        self.data = self._redo.pop()
        self.modified = True
        return True

    # ------------------------------------------------------------------
    # Cursor & selection
    # ------------------------------------------------------------------

    def goto(self, offset: int) -> None:
        """Move the cursor to *offset*, clamped to valid range."""
        self.cursor = max(0, min(offset, len(self.data) - 1))

    def select(self, start: int, end: int) -> None:
        """Set the active selection to the byte range [start, end]."""
        lo = max(0, min(start, end))
        hi = min(len(self.data) - 1, max(start, end))
        self.selection = (lo, hi)

    def clear_selection(self) -> None:
        self.selection = None

    def selected_bytes(self) -> Optional[bytes]:
        """Return the currently selected bytes, or None."""
        if self.selection is None:
            return None
        s, e = self.selection
        return bytes(self.data[s : e + 1])

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def find(
        self,
        pattern: "str | bytes",
        start: int = 0,
        *,
        hex_string: bool = False,
    ) -> List[SearchResult]:
        """Search for *pattern* in the buffer.

        Parameters
        ----------
        pattern : str | bytes
            Byte sequence to find.  If *hex_string* is True, a string like
            ``"DE AD BE EF"`` is accepted.
        start : int
            Search start offset.
        hex_string : bool
            Parse *pattern* as a space-separated hex string.

        Returns
        -------
        list[SearchResult]
            All matches found.
        """
        if hex_string and isinstance(pattern, str):
            raw = bytes.fromhex(pattern.replace(" ", ""))
        elif isinstance(pattern, str):
            raw = pattern.encode()
        else:
            raw = pattern

        pat = Pattern(raw)
        return self._search.find_all(bytes(self.data), pat, start=start)

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    def hex_view(
        self,
        offset: int = 0,
        size: Optional[int] = None,
        *,
        colour: bool = True,
    ) -> str:
        """Return a formatted hex+ASCII view of *size* bytes from *offset*.

        Parameters
        ----------
        offset : int
            Start offset.
        size : int | None
            Number of bytes to display. Defaults to the whole file.
        colour : bool
            Whether to include ANSI colour codes.
        """
        chunk = bytes(self.data[offset : offset + size]) if size else bytes(self.data[offset:])
        cfg = HexConfig(bytes_per_row=16, use_color=colour, base_offset=offset)
        return HexEngine(cfg).render(chunk)

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self.data)

    def __repr__(self) -> str:
        name = self.path.name if self.path else "<memory>"
        return (
            f"HexEditor('{name}', size={len(self.data)}, "
            f"cursor=0x{self.cursor:X}, modified={self.modified})"
        )
