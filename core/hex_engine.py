# =============================================================================
# BinModder - Hex Engine Module
# =============================================================================
# Provides hex display formatting with colored output, ASCII panel,
# offset display, and various display modes for binary data visualization.
#
# Author: MSR Electronics
# Version: 1.0.0
# =============================================================================

import os
import sys
import struct
from enum import Enum
from typing import Optional, Union, List, Tuple, Dict, Any
from pathlib import Path


# =============================================================================
# Color Definitions
# =============================================================================

class AnsiColor:
    """ANSI terminal color codes."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    # Foreground
    BLACK   = "\033[30m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"
    # Bright foreground
    BRIGHT_RED     = "\033[91m"
    BRIGHT_GREEN   = "\033[92m"
    BRIGHT_YELLOW  = "\033[93m"
    BRIGHT_BLUE    = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN    = "\033[96m"
    BRIGHT_WHITE   = "\033[97m"
    # Background
    BG_BLACK   = "\033[40m"
    BG_RED     = "\033[41m"
    BG_GREEN   = "\033[42m"
    BG_YELLOW  = "\033[43m"
    BG_BLUE    = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN    = "\033[46m"
    BG_WHITE   = "\033[47m"

    @staticmethod
    def colorize(text: str, color: str, reset: bool = True) -> str:
        """Apply ANSI color to text."""
        if reset:
            return f"{color}{text}{AnsiColor.RESET}"
        return f"{color}{text}"


class HexColor:
    """Color scheme for hex display."""

    def __init__(
        self,
        null_color:      str = AnsiColor.DIM,
        printable_color: str = AnsiColor.BRIGHT_GREEN,
        control_color:   str = AnsiColor.BRIGHT_RED,
        high_color:      str = AnsiColor.BRIGHT_BLUE,
        ff_color:        str = AnsiColor.BRIGHT_YELLOW,
        offset_color:    str = AnsiColor.CYAN,
        ascii_color:     str = AnsiColor.GREEN,
        highlight_color: str = AnsiColor.BG_YELLOW + AnsiColor.BLACK,
        separator_color: str = AnsiColor.DIM,
    ):
        self.null_color      = null_color       # 0x00
        self.printable_color = printable_color  # 0x20-0x7E
        self.control_color   = control_color    # 0x01-0x1F, 0x7F
        self.high_color      = high_color       # 0x80-0xFE
        self.ff_color        = ff_color         # 0xFF
        self.offset_color    = offset_color     # Offset column
        self.ascii_color     = ascii_color      # ASCII panel
        self.highlight_color = highlight_color  # Highlighted bytes
        self.separator_color = separator_color  # Separators

    def colorize_byte(self, byte_val: int) -> str:
        """Return the ANSI color for a given byte value."""
        if byte_val == 0x00:
            return self.null_color
        elif byte_val == 0xFF:
            return self.ff_color
        elif 0x20 <= byte_val <= 0x7E:
            return self.printable_color
        elif byte_val < 0x20 or byte_val == 0x7F:
            return self.control_color
        else:
            return self.high_color

    @classmethod
    def default(cls) -> "HexColor":
        """Return default color scheme."""
        return cls()

    @classmethod
    def no_color(cls) -> "HexColor":
        """Return empty color scheme (no colors)."""
        return cls(
            null_color="", printable_color="", control_color="",
            high_color="", ff_color="", offset_color="",
            ascii_color="", highlight_color="", separator_color="",
        )

    @classmethod
    def dark_theme(cls) -> "HexColor":
        """Dark terminal theme."""
        return cls(
            null_color=AnsiColor.DIM + AnsiColor.WHITE,
            printable_color=AnsiColor.BRIGHT_GREEN,
            control_color=AnsiColor.RED,
            high_color=AnsiColor.BRIGHT_BLUE,
            ff_color=AnsiColor.YELLOW,
            offset_color=AnsiColor.BRIGHT_CYAN,
            ascii_color=AnsiColor.GREEN,
        )

    @classmethod
    def monochrome(cls) -> "HexColor":
        """Monochrome scheme (bold only)."""
        return cls(
            null_color=AnsiColor.DIM,
            printable_color=AnsiColor.BOLD,
            control_color=AnsiColor.DIM,
            high_color="",
            ff_color=AnsiColor.BOLD,
            offset_color=AnsiColor.BOLD,
            ascii_color="",
        )


# =============================================================================
# Display Configuration
# =============================================================================

class HexDisplayMode(Enum):
    """Hex display modes."""
    HEX_ASCII   = "hex_ascii"   # Standard hex + ASCII view
    HEX_ONLY    = "hex_only"    # Hex without ASCII
    ASCII_ONLY  = "ascii_only"  # ASCII only
    WIDE        = "wide"        # 32 bytes per row
    NARROW      = "narrow"      # 8 bytes per row
    WORDS       = "words"       # Display as 16-bit words
    DWORDS      = "dwords"      # Display as 32-bit DWORDs
    QWORDS      = "qwords"      # Display as 64-bit QWORDs


class HexConfig:
    """Configuration for hex display."""

    def __init__(
        self,
        bytes_per_row:   int            = 16,
        group_size:      int            = 1,   # 1=bytes, 2=words, 4=dwords
        show_offset:     bool           = True,
        show_ascii:      bool           = True,
        show_header:     bool           = True,
        show_separator:  bool           = True,
        use_colors:      bool           = True,
        uppercase:       bool           = True,
        offset_width:    int            = 8,   # Width of offset column
        offset_base:     int            = 16,  # 16=hex, 10=decimal
        display_mode:    HexDisplayMode = HexDisplayMode.HEX_ASCII,
        color_scheme:    Optional[HexColor] = None,
        highlights:      Optional[Dict[int, str]] = None,  # offset->color
    ):
        self.bytes_per_row  = bytes_per_row
        self.group_size     = group_size
        self.show_offset    = show_offset
        self.show_ascii     = show_ascii
        self.show_header    = show_header
        self.show_separator = show_separator
        self.use_colors     = use_colors
        self.uppercase      = uppercase
        self.offset_width   = offset_width
        self.offset_base    = offset_base
        self.display_mode   = display_mode
        self.color_scheme   = color_scheme or HexColor.default()
        self.highlights     = highlights or {}

    @classmethod
    def default(cls) -> "HexConfig":
        return cls()

    @classmethod
    def compact(cls) -> "HexConfig":
        return cls(
            bytes_per_row=32,
            show_header=False,
            use_colors=True,
        )

    @classmethod
    def wide(cls) -> "HexConfig":
        return cls(bytes_per_row=32)

    @classmethod
    def narrow(cls) -> "HexConfig":
        return cls(bytes_per_row=8)

    @classmethod
    def no_color(cls) -> "HexConfig":
        return cls(use_colors=False, color_scheme=HexColor.no_color())

    @classmethod
    def plain(cls) -> "HexConfig":
        return cls(
            use_colors=False,
            show_header=False,
            show_separator=False,
            color_scheme=HexColor.no_color(),
        )


# =============================================================================
# Hex Engine - Main Class
# =============================================================================

class HexEngine:
    """
    Advanced hex display engine for binary data visualization.

    Features:
    - Configurable columns, grouping, and display mode
    - ANSI color support with multiple themes
    - Byte highlighting by offset
    - ASCII panel with printable character display
    - Multiple offset display formats (hex/decimal)
    - Header row generation
    - Diff highlighting between two buffers

    Usage:
        engine = HexEngine()
        print(engine.display(data))
        print(engine.display(data, start=0x100, end=0x200))
        print(engine.display_diff(data1, data2))
    """

    ASCII_PRINTABLE = set(range(0x20, 0x7F))
    ASCII_UNPRINTABLE_CHAR = "."

    def __init__(self, config: Optional[HexConfig] = None):
        self.config = config or HexConfig.default()

    # -------------------------------------------------------------------------
    # Internal Helpers
    # -------------------------------------------------------------------------

    def _supports_color(self) -> bool:
        """Check if terminal supports ANSI colors."""
        if not self.config.use_colors:
            return False
        if os.name == "nt":
            return os.environ.get("TERM_PROGRAM") == "vscode" or \
                   "ANSICON" in os.environ
        return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

    def _fmt_byte(self, byte_val: int, offset: int, highlighted: bool = False) -> str:
        """Format a single byte for display."""
        fmt_str = f"{byte_val:02X}" if self.config.uppercase else f"{byte_val:02x}"

        if not self.config.use_colors:
            return fmt_str

        if highlighted or offset in self.config.highlights:
            color = self.config.highlights.get(offset, self.config.color_scheme.highlight_color)
        else:
            color = self.config.color_scheme.colorize_byte(byte_val)

        if color:
            return f"{color}{fmt_str}{AnsiColor.RESET}"
        return fmt_str

    def _fmt_ascii_char(self, byte_val: int, offset: int) -> str:
        """Format a byte as ASCII character."""
        if byte_val in self.ASCII_PRINTABLE:
            ch = chr(byte_val)
        else:
            ch = self.ASCII_UNPRINTABLE_CHAR

        if not self.config.use_colors:
            return ch

        if offset in self.config.highlights:
            color = self.config.highlights[offset]
        elif byte_val in self.ASCII_PRINTABLE:
            color = self.config.color_scheme.ascii_color
        else:
            color = self.config.color_scheme.null_color

        if color:
            return f"{color}{ch}{AnsiColor.RESET}"
        return ch

    def _fmt_offset(self, offset: int) -> str:
        """Format an offset value."""
        width = self.config.offset_width
        if self.config.offset_base == 16:
            fmt = f"{offset:0{width}X}" if self.config.uppercase else f"{offset:0{width}x}"
        else:
            fmt = f"{offset:{width}d}"

        if self.config.use_colors and self.config.color_scheme.offset_color:
            return f"{self.config.color_scheme.offset_color}{fmt}{AnsiColor.RESET}"
        return fmt

    def _fmt_separator(self, sep: str) -> str:
        """Format a separator character."""
        if self.config.use_colors and self.config.color_scheme.separator_color:
            return f"{self.config.color_scheme.separator_color}{sep}{AnsiColor.RESET}"
        return sep

    def _build_header(self) -> str:
        """Build the column header row."""
        bpr    = self.config.bytes_per_row
        width  = self.config.offset_width

        # Offset label
        header = " " * (width + 2)  # Space for "  "

        # Byte columns
        for i in range(bpr):
            if i > 0 and i % 8 == 0 and self.config.show_separator:
                header += " "
            header += f" {i:02X}" if self.config.uppercase else f" {i:02x}"

        # ASCII header
        if self.config.show_ascii:
            sep = "  |"
            header += sep
            header += "".join(
                f"{i:X}" if self.config.uppercase else f"{i:x}"
                for i in range(min(bpr, 16))
            )
            header += "|"

        return header

    # -------------------------------------------------------------------------
    # Row Formatting
    # -------------------------------------------------------------------------

    def _format_row(
        self,
        offset:    int,
        row_data:  bytes,
        pad_to:    int = 0,
        highlights: Optional[Dict[int, str]] = None
    ) -> str:
        """
        Format a single row of hex display.

        Args:
            offset:     Starting offset for this row
            row_data:   Bytes for this row
            pad_to:     Pad row to this many bytes (for last row)
            highlights: Per-offset highlight colors

        Returns:
            Formatted row string
        """
        cfg = self.config
        bpr = cfg.bytes_per_row

        # Offset column
        parts = []
        if cfg.show_offset:
            parts.append(self._fmt_offset(offset))
            parts.append("  ")

        # Hex columns
        hex_parts = []
        for i in range(bpr):
            if i > 0 and i % 8 == 0 and cfg.show_separator:
                hex_parts.append(" ")

            if i < len(row_data):
                byte_val    = row_data[i]
                byte_offset = offset + i
                highlighted = (highlights or {}).get(byte_offset) is not None
                hex_parts.append(" " + self._fmt_byte(byte_val, byte_offset, highlighted))
            else:
                # Padding for last row
                hex_parts.append("   ")

        parts.append("".join(hex_parts))

        # ASCII column
        if cfg.show_ascii:
            parts.append("  |")
            for i in range(bpr):
                if i < len(row_data):
                    byte_val    = row_data[i]
                    byte_offset = offset + i
                    parts.append(self._fmt_ascii_char(byte_val, byte_offset))
                else:
                    parts.append(" ")
            parts.append("|")

        return "".join(parts)

    def _format_row_words(self, offset: int, row_data: bytes) -> str:
        """Format row as 16-bit words."""
        cfg   = self.config
        parts = []

        if cfg.show_offset:
            parts.append(self._fmt_offset(offset))
            parts.append("  ")

        i = 0
        while i < len(row_data):
            if i + 1 < len(row_data):
                word = struct.unpack_from("<H", row_data, i)[0]
                parts.append(f" {word:04X}" if cfg.uppercase else f" {word:04x}")
                i += 2
            else:
                parts.append(f" {row_data[i]:02X}  ")
                i += 1

        return "".join(parts)

    def _format_row_dwords(self, offset: int, row_data: bytes) -> str:
        """Format row as 32-bit DWORDs."""
        cfg   = self.config
        parts = []

        if cfg.show_offset:
            parts.append(self._fmt_offset(offset))
            parts.append("  ")

        i = 0
        while i < len(row_data):
            remaining = len(row_data) - i
            if remaining >= 4:
                dword = struct.unpack_from("<I", row_data, i)[0]
                parts.append(f" {dword:08X}" if cfg.uppercase else f" {dword:08x}")
                i += 4
            elif remaining >= 2:
                word = struct.unpack_from("<H", row_data, i)[0]
                parts.append(f" {word:04X}    " if cfg.uppercase else f" {word:04x}    ")
                i += 2
            else:
                parts.append(f" {row_data[i]:02X}      ")
                i += 1

        return "".join(parts)

    def _format_row_qwords(self, offset: int, row_data: bytes) -> str:
        """Format row as 64-bit QWORDs."""
        cfg   = self.config
        parts = []

        if cfg.show_offset:
            parts.append(self._fmt_offset(offset))
            parts.append("  ")

        i = 0
        while i < len(row_data):
            remaining = len(row_data) - i
            if remaining >= 8:
                qword = struct.unpack_from("<Q", row_data, i)[0]
                parts.append(f" {qword:016X}" if cfg.uppercase else f" {qword:016x}")
                i += 8
            else:
                # Format remaining as hex bytes
                for j in range(remaining):
                    parts.append(f" {row_data[i + j]:02X}")
                break

        return "".join(parts)

    # -------------------------------------------------------------------------
    # Main Display Method
    # -------------------------------------------------------------------------

    def display(
        self,
        data:       Union[bytes, bytearray],
        start:      int = 0,
        end:        Optional[int] = None,
        highlights: Optional[Dict[int, str]] = None,
    ) -> str:
        """
        Generate a hex display string for binary data.

        Args:
            data:       Binary data to display
            start:      Start offset
            end:        End offset (default: end of data)
            highlights: Dict of {offset: ansi_color} for highlighting

        Returns:
            Formatted hex display string
        """
        if end is None:
            end = len(data)

        cfg    = self.config
        bpr    = cfg.bytes_per_row
        lines  = []

        # Header
        if cfg.show_header:
            lines.append(self._build_header())
            lines.append("-" * (cfg.offset_width + 2 + bpr * 3 + 5))

        # Data rows
        row_start = start
        while row_start < end:
            row_end  = min(row_start + bpr, end)
            row_data = data[row_start:row_end]

            mode = cfg.display_mode
            if mode in (HexDisplayMode.HEX_ASCII, HexDisplayMode.HEX_ONLY):
                line = self._format_row(row_start, row_data, bpr, highlights)
            elif mode == HexDisplayMode.WORDS:
                line = self._format_row_words(row_start, row_data)
            elif mode == HexDisplayMode.DWORDS:
                line = self._format_row_dwords(row_start, row_data)
            elif mode == HexDisplayMode.QWORDS:
                line = self._format_row_qwords(row_start, row_data)
            elif mode == HexDisplayMode.ASCII_ONLY:
                if cfg.show_offset:
                    line = self._fmt_offset(row_start) + "  "
                else:
                    line = ""
                line += "".join(
                    chr(b) if b in self.ASCII_PRINTABLE else "."
                    for b in row_data
                )
            else:
                line = self._format_row(row_start, row_data, bpr, highlights)

            lines.append(line)
            row_start = row_end

        return "\n".join(lines)

    def display_file(
        self,
        path:   Union[str, Path],
        start:  int = 0,
        end:    Optional[int] = None,
        max_bytes: Optional[int] = None,
    ) -> str:
        """Generate hex display from a file."""
        path = Path(path)
        with open(path, "rb") as f:
            if start:
                f.seek(start)
            if max_bytes is not None:
                data = f.read(max_bytes)
            elif end is not None:
                data = f.read(end - start)
            else:
                data = f.read()

        return self.display(data, 0, len(data) if end is None else min(end - start, len(data)))

    # -------------------------------------------------------------------------
    # Diff Display
    # -------------------------------------------------------------------------

    def display_diff(
        self,
        data1: bytes,
        data2: bytes,
        start: int = 0,
        end:   Optional[int] = None,
        label1: str = "File 1",
        label2: str = "File 2",
    ) -> str:
        """
        Display two binary buffers side-by-side with differences highlighted.

        Args:
            data1:  First binary buffer
            data2:  Second binary buffer
            start:  Start offset
            end:    End offset
            label1: Label for first buffer
            label2: Label for second buffer

        Returns:
            Formatted diff display
        """
        if end is None:
            end = max(len(data1), len(data2))

        cfg = self.config
        bpr = cfg.bytes_per_row

        lines = [
            f"=== BINARY DIFF: {label1} vs {label2} ===",
            f"    Size: {len(data1)} vs {len(data2)} bytes",
        ]

        diff_count = 0
        row_start  = start

        while row_start < end:
            row_end   = min(row_start + bpr, end)
            row1      = data1[row_start:row_end] if row_start < len(data1) else b""
            row2      = data2[row_start:row_end] if row_start < len(data2) else b""

            # Check if rows differ
            max_len   = max(len(row1), len(row2))
            has_diff  = False
            diff_pos  = []

            for i in range(max_len):
                b1 = row1[i] if i < len(row1) else -1
                b2 = row2[i] if i < len(row2) else -1
                if b1 != b2:
                    has_diff = True
                    diff_pos.append(row_start + i)
                    diff_count += 1

            if has_diff:
                # Show both rows with differences
                off_str = self._fmt_offset(row_start)
                # Row 1 with diffs highlighted
                hl1 = {o: AnsiColor.BG_RED for o in diff_pos}
                line1 = self._format_row(row_start, row1, bpr, hl1)
                hl2   = {o: AnsiColor.BG_GREEN for o in diff_pos}
                line2 = self._format_row(row_start, row2, bpr, hl2)
                lines.append(f"< {line1}")
                lines.append(f"> {line2}")
                lines.append("")

            row_start = row_end

        if diff_count == 0:
            lines.append("Files are IDENTICAL")
        else:
            lines.append(f"Total differences: {diff_count} bytes")

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Export Formats
    # -------------------------------------------------------------------------

    def to_c_array(
        self,
        data:     bytes,
        var_name: str = "bin_data",
        type_str: str = "uint8_t",
        cols:     int = 16,
    ) -> str:
        """
        Export binary data as a C array.

        Args:
            data:     Binary data
            var_name: Variable name
            type_str: C type string
            cols:     Values per row

        Returns:
            C array string
        """
        lines = [
            f"/* Generated by BinModder - {len(data)} bytes */",
            f"static const {type_str} {var_name}[] = {{",
        ]

        for i in range(0, len(data), cols):
            row   = data[i:i + cols]
            hex_vals = ", ".join(f"0x{b:02X}" for b in row)
            comment  = f" /* 0x{i:08X} */"
            if i + cols < len(data):
                lines.append(f"    {hex_vals},{comment}")
            else:
                lines.append(f"    {hex_vals}{comment}")

        lines.append("};")
        lines.append(f"static const size_t {var_name}_size = {len(data)};")
        return "\n".join(lines)

    def to_python_bytes(
        self,
        data:     bytes,
        var_name: str = "bin_data",
        cols:     int = 16,
    ) -> str:
        """Export binary data as Python bytes literal."""
        lines = [
            f"# Generated by BinModder - {len(data)} bytes",
            f"{var_name} = (",
        ]
        for i in range(0, len(data), cols):
            row     = data[i:i + cols]
            hex_str = "".join(f"\\x{b:02x}" for b in row)
            comment = f"  # 0x{i:08X}"
            lines.append(f'    b"{hex_str}"{comment}')
        lines.append(")")
        return "\n".join(lines)

    def to_hex_string(
        self,
        data:   bytes,
        sep:    str = " ",
        upper:  bool = True,
    ) -> str:
        """Convert binary data to a hex string."""
        if upper:
            return sep.join(f"{b:02X}" for b in data)
        return sep.join(f"{b:02x}" for b in data)

    def to_srec(
        self,
        data:      bytes,
        base_addr: int = 0x0000,
        record_type: str = "S1",  # S1=16bit, S2=24bit, S3=32bit addr
    ) -> str:
        """Export binary data in Motorola S-Record format."""
        lines = []
        # S0 header record
        hdr_data = b"HDR\x00"
        hdr_len  = len(hdr_data) + 3  # addr(2) + data + checksum
        hdr_sum  = (hdr_len + 0x00 + 0x00 + sum(hdr_data)) & 0xFF
        hdr_chk  = (~hdr_sum) & 0xFF
        lines.append(f"S0{hdr_len:02X}0000{hdr_data.hex().upper()}{hdr_chk:02X}")

        # Data records
        rec_size = 32
        for i in range(0, len(data), rec_size):
            chunk   = data[i:i + rec_size]
            addr    = base_addr + i

            if record_type == "S1":
                addr_bytes = addr.to_bytes(2, "big")
                rec_type   = "S1"
            elif record_type == "S2":
                addr_bytes = (addr & 0xFFFFFF).to_bytes(3, "big")
                rec_type   = "S2"
            else:
                addr_bytes = addr.to_bytes(4, "big")
                rec_type   = "S3"

            byte_count = len(addr_bytes) + len(chunk) + 1  # addr + data + checksum
            checksum   = (byte_count + sum(addr_bytes) + sum(chunk)) & 0xFF
            checksum   = (~checksum) & 0xFF

            rec = (
                rec_type
                + f"{byte_count:02X}"
                + addr_bytes.hex().upper()
                + chunk.hex().upper()
                + f"{checksum:02X}"
            )
            lines.append(rec)

        # End record
        record_count = len([l for l in lines if l.startswith("S1")])
        end_sum      = (~(0x03 + (record_count >> 8) + (record_count & 0xFF))) & 0xFF
        lines.append(f"S5{0x03:02X}{record_count:04X}{end_sum:02X}")
        lines.append(f"S9030000FC")

        return "\n".join(lines)

    def to_intel_hex(
        self,
        data:      bytes,
        base_addr: int = 0x0000,
    ) -> str:
        """Export binary data in Intel HEX format."""
        lines     = []
        rec_size  = 16
        curr_addr = base_addr

        # Extended linear address record for addresses > 64KB
        if base_addr > 0xFFFF:
            ula = base_addr >> 16
            rec_data = struct.pack(">H", ula)
            checksum = (~(0x02 + 0x00 + 0x00 + 0x04 + sum(rec_data)) + 1) & 0xFF
            lines.append(
                f":02000004{ula:04X}{checksum:02X}"
            )

        for i in range(0, len(data), rec_size):
            chunk   = data[i:i + rec_size]
            addr    = (curr_addr + i) & 0xFFFF
            bcount  = len(chunk)
            chksum  = bcount + (addr >> 8) + (addr & 0xFF) + sum(chunk)
            chksum  = (~chksum + 1) & 0xFF
            lines.append(
                f":{bcount:02X}{addr:04X}00{chunk.hex().upper()}{chksum:02X}"
            )

        # End of file record
        lines.append(":00000001FF")
        return "\n".join(lines)

    def from_intel_hex(self, intel_hex: str) -> Tuple[bytes, int]:
        """
        Parse Intel HEX format.

        Returns:
            (data_bytes, base_address) tuple
        """
        buffer    = bytearray()
        base_addr = 0
        upper_ext = 0

        for line in intel_hex.strip().splitlines():
            line = line.strip()
            if not line.startswith(":"):
                continue

            byte_count  = int(line[1:3],   16)
            address     = int(line[3:7],   16)
            record_type = int(line[7:9],   16)
            data_hex    = line[9:9 + byte_count * 2]

            if record_type == 0x00:
                # Data record
                abs_addr = (upper_ext << 16) | address
                chunk    = bytes.fromhex(data_hex)
                # Extend buffer if needed
                end_pos  = abs_addr + len(chunk) - base_addr
                while len(buffer) < end_pos:
                    buffer.extend(b"\xFF")
                start = abs_addr - base_addr
                buffer[start:start + len(chunk)] = chunk

            elif record_type == 0x01:
                # End of file
                break

            elif record_type == 0x04:
                # Extended linear address
                upper_ext = int(data_hex, 16)
                if not buffer:
                    base_addr = upper_ext << 16

            elif record_type == 0x02:
                # Extended segment address
                upper_ext = int(data_hex, 16) << 4

        return bytes(buffer), base_addr

    def from_srec(self, srec: str) -> Tuple[bytes, int]:
        """
        Parse Motorola S-Record format.

        Returns:
            (data_bytes, base_address) tuple
        """
        buffer    = bytearray()
        base_addr = None

        for line in srec.strip().splitlines():
            line = line.strip()
            if not line.startswith("S"):
                continue

            rec_type   = line[0:2]
            byte_count = int(line[2:4], 16)
            data_field = line[4:-2]  # Exclude checksum

            if rec_type == "S1":
                addr  = int(data_field[:4], 16)
                chunk = bytes.fromhex(data_field[4:])
                if base_addr is None:
                    base_addr = addr
                end_pos = addr + len(chunk) - base_addr
                while len(buffer) < end_pos:
                    buffer.extend(b"\xFF")
                start = addr - base_addr
                buffer[start:start + len(chunk)] = chunk

            elif rec_type == "S2":
                addr  = int(data_field[:6], 16)
                chunk = bytes.fromhex(data_field[6:])
                if base_addr is None:
                    base_addr = addr
                end_pos = addr + len(chunk) - base_addr
                while len(buffer) < end_pos:
                    buffer.extend(b"\xFF")
                start = addr - base_addr
                buffer[start:start + len(chunk)] = chunk

            elif rec_type == "S3":
                addr  = int(data_field[:8], 16)
                chunk = bytes.fromhex(data_field[8:])
                if base_addr is None:
                    base_addr = addr
                end_pos = addr + len(chunk) - base_addr
                while len(buffer) < end_pos:
                    buffer.extend(b"\xFF")
                start = addr - base_addr
                buffer[start:start + len(chunk)] = chunk

        return bytes(buffer), base_addr or 0

    # -------------------------------------------------------------------------
    # Utility Methods
    # -------------------------------------------------------------------------

    def bytes_to_grid(
        self,
        data: bytes,
        cols: int = 16
    ) -> List[List[int]]:
        """Convert bytes to a 2D grid."""
        grid = []
        for i in range(0, len(data), cols):
            grid.append(list(data[i:i + cols]))
        return grid

    def parse_hex_string(self, hex_str: str) -> bytes:
        """
        Parse a hex string to bytes.
        Accepts: "DE AD BE EF", "DEADBEEF", "0xDE 0xAD 0xBE 0xEF"
        """
        cleaned = hex_str.replace("0x", "").replace("0X", "")
        cleaned = cleaned.replace(" ", "").replace("\t", "").replace("\n", "")
        return bytes.fromhex(cleaned)

    def byte_stats(self, data: bytes) -> Dict[str, Any]:
        """
        Compute statistics about a binary buffer.

        Returns:
            Dictionary with frequency, entropy, null count, etc.
        """
        freq  = [0] * 256
        for b in data:
            freq[b] += 1

        total       = len(data)
        null_count  = freq[0]
        ff_count    = freq[255]
        printable   = sum(freq[i] for i in range(0x20, 0x7F))

        # Shannon entropy
        import math
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)

        return {
            "size":          total,
            "null_count":    null_count,
            "ff_count":      ff_count,
            "printable":     printable,
            "entropy":       round(entropy, 4),
            "most_common":   sorted(range(256), key=lambda i: freq[i], reverse=True)[:10],
            "least_common":  sorted(range(256), key=lambda i: freq[i])[:10],
        }

    def __repr__(self) -> str:
        return (
            f"HexEngine("
            f"bpr={self.config.bytes_per_row}, "
            f"mode={self.config.display_mode.name}, "
            f"colors={self.config.use_colors}"
            f")"
        )


# =============================================================================
# Quick Display Functions
# =============================================================================

def hexdump(
    data:    Union[bytes, bytearray],
    start:   int = 0,
    end:     Optional[int] = None,
    width:   int = 16,
    colors:  bool = True,
) -> str:
    """Quick hex dump of binary data."""
    cfg    = HexConfig(bytes_per_row=width, use_colors=colors)
    engine = HexEngine(cfg)
    return engine.display(data, start, end)


def hexdump_print(
    data:   Union[bytes, bytearray],
    start:  int = 0,
    end:    Optional[int] = None,
    width:  int = 16,
    colors: bool = True,
) -> None:
    """Print hex dump to stdout."""
    print(hexdump(data, start, end, width, colors))


def to_hex(data: bytes, sep: str = " ") -> str:
    """Convert bytes to uppercase hex string."""
    return sep.join(f"{b:02X}" for b in data)


def from_hex(hex_str: str) -> bytes:
    """Convert hex string to bytes (spaces ignored)."""
    cleaned = hex_str.replace(" ", "").replace("0x", "")
    return bytes.fromhex(cleaned)
