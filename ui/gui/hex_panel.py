# =============================================================================
# BinModder - Hex Panel Widget
# =============================================================================
# Advanced hex editor panel with synchronized hex and ASCII views,
# cursor navigation, selection, byte editing, and colored display.
#
# Author: MSR Electronics
# Version: 1.0.0
# =============================================================================

import tkinter as tk
from tkinter import ttk
import struct
from typing import Optional, List, Tuple, Callable, Dict, Any
from pathlib import Path


# =============================================================================
# Color Configuration
# =============================================================================

HEX_COLORS = {
    "bg":            "#11111B",
    "fg":            "#CDD6F4",
    "offset_fg":     "#89DCEB",
    "null_fg":       "#45475A",
    "ff_fg":         "#F9E2AF",
    "printable_fg":  "#A6E3A1",
    "control_fg":    "#F38BA8",
    "high_fg":       "#89B4FA",
    "ascii_fg":      "#A6E3A1",
    "selection_bg":  "#313244",
    "cursor_bg":     "#CBA6F7",
    "cursor_fg":     "#1E1E2E",
    "highlight_bg":  "#F9E2AF",
    "highlight_fg":  "#1E1E2E",
    "modified_bg":   "#F38BA8",
    "modified_fg":   "#1E1E2E",
    "separator_fg":  "#45475A",
    "header_bg":     "#181825",
    "header_fg":     "#89DCEB",
}

HEX_FONT = ("Courier New", 11)
HEX_FONT_BOLD = ("Courier New", 11, "bold")


# =============================================================================
# Hex Panel
# =============================================================================

class HexPanel(tk.Frame):
    """
    Interactive hex editor panel with:
    - Offset column | Hex columns (16 per row) | ASCII column
    - Cursor navigation with arrow keys
    - Byte selection with shift+arrows or mouse drag
    - In-place byte editing (type hex digits)
    - Colored byte categories
    - Bookmarks and highlights
    - Copy/paste support
    - Find result highlighting

    Usage:
        panel = HexPanel(parent)
        panel.load_data(bytearray(open("file.bin", "rb").read()))
        panel.pack(fill="both", expand=True)
    """

    BYTES_PER_ROW = 16
    ROWS_VISIBLE  = 40

    def __init__(
        self,
        parent: tk.Widget,
        on_change: Optional[Callable] = None,
        on_cursor_move: Optional[Callable] = None,
        **kwargs
    ):
        super().__init__(parent, bg=HEX_COLORS["bg"], **kwargs)

        self._data:           bytearray            = bytearray()
        self._cursor:         int                  = 0
        self._selection:      Optional[Tuple[int, int]] = None
        self._scroll_row:     int                  = 0
        self._bytes_per_row:  int                  = self.BYTES_PER_ROW
        self._edit_nibble:    Optional[int]        = None  # 0=high, 1=low
        self._highlights:     Dict[int, str]       = {}    # offset -> color
        self._bookmarks:      Dict[int, str]       = {}    # offset -> name
        self._modified_bytes: Dict[int, int]       = {}    # offset -> original
        self._on_change       = on_change
        self._on_cursor_move  = on_cursor_move
        self._read_only       = False

        self._setup_widgets()
        self._bind_events()
        self._render()

    # -------------------------------------------------------------------------
    # Widget Setup
    # -------------------------------------------------------------------------

    def _setup_widgets(self) -> None:
        """Create inner widgets."""
        # Header row
        self._header = tk.Canvas(
            self, bg=HEX_COLORS["header_bg"], height=22, relief="flat"
        )
        self._header.pack(fill="x", side="top")

        # Main editing area
        edit_frame = tk.Frame(self, bg=HEX_COLORS["bg"])
        edit_frame.pack(fill="both", expand=True)

        # Canvas for hex display
        self._canvas = tk.Canvas(
            edit_frame,
            bg=HEX_COLORS["bg"],
            relief="flat",
            bd=0,
            highlightthickness=0,
            cursor="ibeam",
        )
        self._canvas.pack(side="left", fill="both", expand=True)

        # Vertical scrollbar
        self._vscroll = tk.Scrollbar(
            edit_frame, orient="vertical",
            command=self._on_vscroll
        )
        self._vscroll.pack(side="right", fill="y")

        # Horizontal scrollbar
        self._hscroll = tk.Scrollbar(
            self, orient="horizontal",
            command=self._canvas.xview
        )
        self._hscroll.pack(side="bottom", fill="x")

        self._canvas.configure(
            yscrollcommand=self._vscroll.set,
            xscrollcommand=self._hscroll.set
        )

        # Calculate dimensions
        self._update_dimensions()
        self._draw_header()

    def _update_dimensions(self) -> None:
        """Recalculate pixel dimensions based on font."""
        import tkinter.font as tkfont
        f = tkfont.Font(family="Courier New", size=11)
        self._char_w  = f.measure("0")
        self._char_h  = f.metrics("linespace")
        self._off_w   = self._char_w * 10    # "XXXXXXXX  "
        self._hex_w   = self._char_w * 3     # "XX " per byte
        self._gap_w   = self._char_w         # Gap between groups of 8
        self._ascii_w = self._char_w         # 1 char per byte
        self._sep_w   = self._char_w * 3     # " | "

        bpr           = self._bytes_per_row
        self._row_w   = (
            self._off_w +
            bpr * self._hex_w +
            (bpr // 8 - 1) * self._gap_w +
            self._sep_w +
            bpr * self._ascii_w +
            20  # padding
        )

    def _draw_header(self) -> None:
        """Draw the column header row."""
        self._header.delete("all")
        x = 10

        # Offset header
        self._header.create_text(
            x, 11, text="Offset    ",
            anchor="w", font=HEX_FONT_BOLD,
            fill=HEX_COLORS["header_fg"]
        )
        x += self._off_w

        # Byte column headers
        for i in range(self._bytes_per_row):
            if i > 0 and i % 8 == 0:
                x += self._gap_w

            self._header.create_text(
                x, 11,
                text=f"{i:02X} ",
                anchor="w",
                font=HEX_FONT_BOLD,
                fill=HEX_COLORS["header_fg"]
            )
            x += self._hex_w

        # ASCII header separator
        x += self._char_w
        self._header.create_text(
            x, 11, text="ASCII",
            anchor="w", font=HEX_FONT_BOLD,
            fill=HEX_COLORS["header_fg"]
        )

    # -------------------------------------------------------------------------
    # Data Management
    # -------------------------------------------------------------------------

    def load_data(self, data: bytearray, reset_view: bool = True) -> None:
        """Load binary data into the panel."""
        self._data = bytearray(data)
        self._modified_bytes.clear()
        if reset_view:
            self._cursor     = 0
            self._scroll_row = 0
            self._selection  = None
        self._render()
        self._update_scrollbar()

    def get_data(self) -> bytes:
        """Return current data as bytes."""
        return bytes(self._data)

    def get_data_mutable(self) -> bytearray:
        """Return current data as bytearray."""
        return bytearray(self._data)

    def set_byte(self, offset: int, value: int) -> None:
        """Set a single byte value."""
        if 0 <= offset < len(self._data):
            if offset not in self._modified_bytes:
                self._modified_bytes[offset] = self._data[offset]
            self._data[offset] = value & 0xFF
            if self._on_change:
                self._on_change(offset, value)
            self._render_row(offset // self._bytes_per_row)

    def get_byte(self, offset: int) -> int:
        """Get a single byte value."""
        if 0 <= offset < len(self._data):
            return self._data[offset]
        return 0

    def write_bytes(self, offset: int, data: bytes) -> None:
        """Write multiple bytes starting at offset."""
        for i, b in enumerate(data):
            self.set_byte(offset + i, b)

    @property
    def cursor(self) -> int:
        return self._cursor

    @property
    def data_size(self) -> int:
        return len(self._data)

    @property
    def modified_count(self) -> int:
        return len(self._modified_bytes)

    @property
    def selection(self) -> Optional[Tuple[int, int]]:
        return self._selection

    # -------------------------------------------------------------------------
    # Rendering
    # -------------------------------------------------------------------------

    def _render(self) -> None:
        """Full re-render of the hex panel."""
        self._canvas.delete("all")
        if not self._data:
            self._canvas.create_text(
                10, 20, text="No data loaded",
                anchor="w", fill=HEX_COLORS["null_fg"], font=HEX_FONT
            )
            return

        bpr     = self._bytes_per_row
        n_rows  = (len(self._data) + bpr - 1) // bpr
        visible = min(self.ROWS_VISIBLE, n_rows - self._scroll_row)

        for row in range(visible):
            self._render_row(self._scroll_row + row, row)

        # Update scroll region
        total_h = n_rows * self._char_h + 10
        self._canvas.configure(scrollregion=(0, 0, self._row_w, total_h))

    def _render_row(self, abs_row: int, vis_row: Optional[int] = None) -> None:
        """Render a single row."""
        if vis_row is None:
            vis_row = abs_row - self._scroll_row
            if vis_row < 0 or vis_row >= self.ROWS_VISIBLE:
                return

        bpr    = self._bytes_per_row
        offset = abs_row * bpr
        y      = vis_row * self._char_h + 4
        x      = 10

        # Clear row area
        self._canvas.delete(f"row_{abs_row}")

        if offset >= len(self._data):
            return

        row_data = self._data[offset:offset + bpr]
        tag      = f"row_{abs_row}"

        # Offset
        self._canvas.create_text(
            x, y, text=f"{offset:08X}  ",
            anchor="w", font=HEX_FONT,
            fill=HEX_COLORS["offset_fg"], tags=tag
        )
        x += self._off_w

        # Hex bytes
        for i, b in enumerate(row_data):
            if i > 0 and i % 8 == 0:
                self._canvas.create_text(
                    x, y, text=" ",
                    anchor="w", font=HEX_FONT,
                    fill=HEX_COLORS["separator_fg"], tags=tag
                )
                x += self._gap_w

            byte_offset = offset + i
            color       = self._get_byte_color(b, byte_offset)
            text        = f"{b:02X}"

            # Background for cursor/selection/modified
            bg_color = None
            if byte_offset == self._cursor:
                bg_color = HEX_COLORS["cursor_bg"]
                color    = HEX_COLORS["cursor_fg"]
            elif self._selection and min(*self._selection) <= byte_offset <= max(*self._selection):
                bg_color = HEX_COLORS["selection_bg"]
            elif byte_offset in self._modified_bytes:
                bg_color = HEX_COLORS["modified_bg"]
                color    = HEX_COLORS["modified_fg"]
            elif byte_offset in self._highlights:
                bg_color = self._highlights[byte_offset]
                color    = HEX_COLORS["cursor_fg"]

            if bg_color:
                self._canvas.create_rectangle(
                    x - 1, y - 1,
                    x + self._char_w * 2 + 1, y + self._char_h - 2,
                    fill=bg_color, outline="", tags=tag
                )

            self._canvas.create_text(
                x, y, text=text, anchor="w",
                font=HEX_FONT, fill=color, tags=tag
            )
            x += self._char_w * 2

            self._canvas.create_text(
                x, y, text=" ", anchor="w",
                font=HEX_FONT, fill=HEX_COLORS["separator_fg"], tags=tag
            )
            x += self._char_w

        # Pad for short last row
        if len(row_data) < bpr:
            pad = bpr - len(row_data)
            x  += pad * self._hex_w

        # ASCII separator
        self._canvas.create_text(
            x, y, text=" |",
            anchor="w", font=HEX_FONT,
            fill=HEX_COLORS["separator_fg"], tags=tag
        )
        x += self._sep_w - self._char_w

        # ASCII bytes
        for i, b in enumerate(row_data):
            byte_offset = offset + i
            ch          = chr(b) if 0x20 <= b <= 0x7E else "."
            color       = HEX_COLORS["ascii_fg"] if 0x20 <= b <= 0x7E else HEX_COLORS["null_fg"]

            if byte_offset == self._cursor:
                self._canvas.create_rectangle(
                    x - 1, y - 1,
                    x + self._char_w + 1, y + self._char_h - 2,
                    fill=HEX_COLORS["cursor_bg"], outline="", tags=tag
                )
                color = HEX_COLORS["cursor_fg"]

            self._canvas.create_text(
                x, y, text=ch, anchor="w",
                font=HEX_FONT, fill=color, tags=tag
            )
            x += self._ascii_w

        self._canvas.create_text(
            x, y, text="|",
            anchor="w", font=HEX_FONT,
            fill=HEX_COLORS["separator_fg"], tags=tag
        )

    def _get_byte_color(self, b: int, offset: int) -> str:
        """Get display color for a byte."""
        if offset in self._highlights:
            return HEX_COLORS["cursor_fg"]
        if b == 0x00:
            return HEX_COLORS["null_fg"]
        if b == 0xFF:
            return HEX_COLORS["ff_fg"]
        if 0x20 <= b <= 0x7E:
            return HEX_COLORS["printable_fg"]
        if b < 0x20 or b == 0x7F:
            return HEX_COLORS["control_fg"]
        return HEX_COLORS["high_fg"]

    # -------------------------------------------------------------------------
    # Scrolling
    # -------------------------------------------------------------------------

    def _update_scrollbar(self) -> None:
        """Update the vertical scrollbar."""
        if not self._data:
            self._vscroll.set(0, 1)
            return

        bpr    = self._bytes_per_row
        n_rows = (len(self._data) + bpr - 1) // bpr
        vis    = self.ROWS_VISIBLE

        if n_rows <= vis:
            self._vscroll.set(0, 1)
        else:
            top = self._scroll_row / n_rows
            bot = min(1.0, (self._scroll_row + vis) / n_rows)
            self._vscroll.set(top, bot)

    def _on_vscroll(self, action: str, *args) -> None:
        """Handle vertical scroll events."""
        bpr    = self._bytes_per_row
        n_rows = (len(self._data) + bpr - 1) // bpr

        if action == "moveto":
            frac            = float(args[0])
            self._scroll_row = max(0, min(int(frac * n_rows), n_rows - self.ROWS_VISIBLE))
        elif action == "scroll":
            amount           = int(args[0])
            units            = args[1]
            if units == "units":
                self._scroll_row = max(0, min(self._scroll_row + amount, n_rows - self.ROWS_VISIBLE))
            elif units == "pages":
                self._scroll_row = max(0, min(self._scroll_row + amount * self.ROWS_VISIBLE, n_rows - self.ROWS_VISIBLE))

        self._render()
        self._update_scrollbar()

    def _scroll_to_cursor(self) -> None:
        """Ensure cursor is visible by scrolling if needed."""
        bpr      = self._bytes_per_row
        cur_row  = self._cursor // bpr

        if cur_row < self._scroll_row:
            self._scroll_row = cur_row
            self._render()
        elif cur_row >= self._scroll_row + self.ROWS_VISIBLE:
            self._scroll_row = cur_row - self.ROWS_VISIBLE + 1
            self._render()

        self._update_scrollbar()

    # -------------------------------------------------------------------------
    # Cursor Movement
    # -------------------------------------------------------------------------

    def move_cursor(self, delta: int, extend_selection: bool = False) -> None:
        """Move cursor by delta bytes."""
        new_pos = max(0, min(self._cursor + delta, len(self._data) - 1))

        if extend_selection:
            if self._selection is None:
                self._selection = (self._cursor, self._cursor)
            self._selection = (self._selection[0], new_pos)
        else:
            self._selection = None

        self._cursor = new_pos
        self._scroll_to_cursor()
        self._render()

        if self._on_cursor_move:
            self._on_cursor_move(self._cursor)

    def set_cursor(self, offset: int, extend_selection: bool = False) -> None:
        """Set cursor to specific offset."""
        if 0 <= offset < len(self._data):
            self.move_cursor(offset - self._cursor, extend_selection)

    def cursor_left(self, extend=False):  self.move_cursor(-1, extend)
    def cursor_right(self, extend=False): self.move_cursor(1, extend)
    def cursor_up(self, extend=False):    self.move_cursor(-self._bytes_per_row, extend)
    def cursor_down(self, extend=False):  self.move_cursor(self._bytes_per_row, extend)
    def cursor_home(self, extend=False):  self.set_cursor(0, extend)
    def cursor_end(self, extend=False):   self.set_cursor(len(self._data) - 1, extend)
    def page_up(self, extend=False):      self.move_cursor(-self._bytes_per_row * self.ROWS_VISIBLE, extend)
    def page_down(self, extend=False):    self.move_cursor(self._bytes_per_row * self.ROWS_VISIBLE, extend)

    # -------------------------------------------------------------------------
    # Event Bindings
    # -------------------------------------------------------------------------

    def _bind_events(self) -> None:
        """Bind keyboard and mouse events."""
        self._canvas.bind("<Button-1>",      self._on_mouse_click)
        self._canvas.bind("<B1-Motion>",     self._on_mouse_drag)
        self._canvas.bind("<MouseWheel>",    self._on_mousewheel)
        self._canvas.bind("<Button-4>",      lambda e: self._on_vscroll("scroll", -3, "units"))
        self._canvas.bind("<Button-5>",      lambda e: self._on_vscroll("scroll", 3, "units"))
        self._canvas.bind("<Key>",           self._on_key)
        self._canvas.bind("<FocusIn>",       lambda e: self._render())
        self._canvas.bind("<FocusOut>",      lambda e: self._render())
        self._canvas.focus_set()

    def _pixel_to_offset(self, x: int, y: int) -> Optional[int]:
        """Convert canvas pixel coordinates to byte offset."""
        vis_row = (y - 4) // self._char_h
        abs_row = vis_row + self._scroll_row
        bpr     = self._bytes_per_row

        # Determine if click is in hex area or ASCII area
        hex_start = 10 + self._off_w
        hex_end   = hex_start + bpr * self._hex_w + (bpr // 8 - 1) * self._gap_w
        ascii_start = hex_end + self._sep_w

        if hex_start <= x < hex_end:
            # Hex area
            rel_x  = x - hex_start
            col    = rel_x // (self._hex_w + (1 if rel_x > 8 * self._hex_w else 0))
            col    = min(col, bpr - 1)
        elif x >= ascii_start:
            # ASCII area
            col = min((x - ascii_start) // self._ascii_w, bpr - 1)
        else:
            return None

        offset = abs_row * bpr + col
        if 0 <= offset < len(self._data):
            return offset
        return None

    def _on_mouse_click(self, event) -> None:
        """Handle mouse click."""
        self._canvas.focus_set()
        offset = self._pixel_to_offset(event.x, event.y)
        if offset is not None:
            self._cursor    = offset
            self._selection = None
            self._edit_nibble = None
            self._render()
            if self._on_cursor_move:
                self._on_cursor_move(self._cursor)

    def _on_mouse_drag(self, event) -> None:
        """Handle mouse drag for selection."""
        offset = self._pixel_to_offset(event.x, event.y)
        if offset is not None:
            if self._selection is None:
                self._selection = (self._cursor, offset)
            else:
                self._selection = (self._selection[0], offset)
            self._render()

    def _on_mousewheel(self, event) -> None:
        """Handle mouse wheel scrolling."""
        if event.delta > 0:
            self._on_vscroll("scroll", -3, "units")
        else:
            self._on_vscroll("scroll", 3, "units")

    def _on_key(self, event) -> None:
        """Handle keyboard input."""
        key     = event.keysym
        shift   = bool(event.state & 1)
        ctrl    = bool(event.state & 4)

        # Navigation
        if key == "Left":
            self.cursor_left(shift)
        elif key == "Right":
            self.cursor_right(shift)
        elif key == "Up":
            self.cursor_up(shift)
        elif key == "Down":
            self.cursor_down(shift)
        elif key == "Home":
            if ctrl:
                self.cursor_home(shift)
            else:
                self.set_cursor((self._cursor // self._bytes_per_row) * self._bytes_per_row, shift)
        elif key == "End":
            if ctrl:
                self.cursor_end(shift)
            else:
                end = min((self._cursor // self._bytes_per_row + 1) * self._bytes_per_row - 1,
                          len(self._data) - 1)
                self.set_cursor(end, shift)
        elif key == "Prior":
            self.page_up(shift)
        elif key == "Next":
            self.page_down(shift)

        # Copy/paste
        elif ctrl and key == "c":
            self._copy_selection()
        elif ctrl and key == "v":
            self._paste_clipboard()
        elif ctrl and key == "a":
            self._selection = (0, len(self._data) - 1)
            self._render()

        # Hex editing
        elif not self._read_only and len(key) == 1 and key in "0123456789ABCDEFabcdef":
            self._handle_hex_input(key.upper())

        # Escape clears selection
        elif key == "Escape":
            self._selection  = None
            self._edit_nibble = None
            self._render()

    def _handle_hex_input(self, hex_char: str) -> None:
        """Handle hex character input for byte editing."""
        if self._edit_nibble is None:
            self._edit_nibble = 0
            self._current_edit_byte = 0

        nibble = int(hex_char, 16)

        if self._edit_nibble == 0:
            # High nibble
            self._current_edit_byte = nibble << 4
            self._edit_nibble       = 1
        else:
            # Low nibble
            self._current_edit_byte |= nibble
            self.set_byte(self._cursor, self._current_edit_byte)
            self._edit_nibble = None
            self.cursor_right()

        self._render()

    # -------------------------------------------------------------------------
    # Copy / Paste
    # -------------------------------------------------------------------------

    def _copy_selection(self) -> None:
        """Copy selected bytes to clipboard as hex."""
        if self._selection is None:
            return
        start = min(*self._selection)
        end   = max(*self._selection) + 1
        data  = bytes(self._data[start:end])
        hex_str = " ".join(f"{b:02X}" for b in data)
        self.clipboard_clear()
        self.clipboard_append(hex_str)

    def _paste_clipboard(self) -> None:
        """Paste hex string from clipboard."""
        if self._read_only:
            return
        try:
            text = self.clipboard_get().strip()
            data = bytes.fromhex(text.replace(" ", ""))
            self.write_bytes(self._cursor, data)
            self._render()
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Highlights / Bookmarks
    # -------------------------------------------------------------------------

    def highlight(self, offset: int, color: str = HEX_COLORS["highlight_bg"]) -> None:
        """Highlight a byte at offset."""
        self._highlights[offset] = color
        self._render_row(offset // self._bytes_per_row)

    def highlight_range(self, start: int, end: int, color: str = HEX_COLORS["highlight_bg"]) -> None:
        """Highlight a range of bytes."""
        for offset in range(start, end):
            self._highlights[offset] = color
        self._render()

    def clear_highlights(self) -> None:
        """Clear all highlights."""
        self._highlights.clear()
        self._render()

    def add_bookmark(self, offset: int, name: str = "") -> None:
        """Add a bookmark at offset."""
        self._bookmarks[offset] = name or f"BM_{offset:08X}"

    def goto_offset(self, offset: int) -> None:
        """Move cursor to offset and scroll into view."""
        self.set_cursor(offset)

    # -------------------------------------------------------------------------
    # Configuration
    # -------------------------------------------------------------------------

    def set_bytes_per_row(self, bpr: int) -> None:
        """Set the number of bytes per row."""
        if bpr in (8, 16, 32, 64):
            self._bytes_per_row = bpr
            self._update_dimensions()
            self._draw_header()
            self._render()

    def set_read_only(self, read_only: bool) -> None:
        """Enable or disable read-only mode."""
        self._read_only = read_only

    def set_font(self, family: str, size: int) -> None:
        """Change the hex display font."""
        global HEX_FONT, HEX_FONT_BOLD
        HEX_FONT      = (family, size)
        HEX_FONT_BOLD = (family, size, "bold")
        self._update_dimensions()
        self._draw_header()
        self._render()

    # -------------------------------------------------------------------------
    # Representation
    # -------------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"HexPanel("
            f"size={len(self._data)}, "
            f"cursor=0x{self._cursor:08X}, "
            f"bpr={self._bytes_per_row})"
        )
