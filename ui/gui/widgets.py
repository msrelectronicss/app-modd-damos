# =============================================================================
# BinModder - Custom Widgets
# =============================================================================
# Reusable custom tkinter widgets for BinModder GUI.
#
# Author: MSR Electronics
# Version: 1.0.0
# =============================================================================

import tkinter as tk
from tkinter import ttk
from typing import Optional, Callable, List, Dict, Tuple
import struct

COLORS = {
    "bg":          "#1E1E2E",
    "panel_bg":    "#181825",
    "hex_bg":      "#11111B",
    "hex_fg":      "#CDD6F4",
    "offset_fg":   "#89DCEB",
    "ascii_fg":    "#A6E3A1",
    "null_fg":     "#45475A",
    "ff_fg":       "#F9E2AF",
    "ctrl_fg":     "#F38BA8",
    "high_fg":     "#89B4FA",
    "accent":      "#CBA6F7",
    "success":     "#A6E3A1",
    "warning":     "#F9E2AF",
    "error":       "#F38BA8",
    "separator":   "#45475A",
    "selection_bg":"#313244",
    "modified_bg": "#F38BA8",
}

FONTS = {
    "mono":    ("Courier New", 10),
    "ui":      ("Segoe UI", 10),
    "small":   ("Segoe UI", 9),
    "bold":    ("Segoe UI", 10, "bold"),
    "large":   ("Segoe UI", 12, "bold"),
}


class HexByte(tk.Label):
    """A single byte display widget showing value as hex with color coding."""

    def __init__(self, parent: tk.Widget, value: int = 0, **kwargs):
        self._value = value
        super().__init__(
            parent,
            text=f"{value:02X}",
            font=FONTS["mono"],
            bg=COLORS["hex_bg"],
            fg=self._get_color(value),
            width=2,
            anchor="center",
            relief="flat",
            cursor="hand2",
            **kwargs
        )
        self.bind("<Button-1>", self._on_click)
        self._on_click_cb: Optional[Callable] = None

    def _get_color(self, val: int) -> str:
        if val == 0x00: return COLORS["null_fg"]
        if val == 0xFF: return COLORS["ff_fg"]
        if 0x20 <= val <= 0x7E: return COLORS["ascii_fg"]
        if val < 0x20 or val == 0x7F: return COLORS["ctrl_fg"]
        return COLORS["high_fg"]

    def set_value(self, value: int) -> None:
        self._value = value & 0xFF
        self.configure(text=f"{self._value:02X}", fg=self._get_color(self._value))

    def get_value(self) -> int:
        return self._value

    def highlight(self, color: str = COLORS["accent"]) -> None:
        self.configure(bg=color)

    def reset_highlight(self) -> None:
        self.configure(bg=COLORS["hex_bg"])

    def _on_click(self, event) -> None:
        if self._on_click_cb:
            self._on_click_cb(self._value)

    def set_click_callback(self, cb: Callable) -> None:
        self._on_click_cb = cb


class OffsetLabel(tk.Label):
    """Label showing a file offset in hex format."""

    def __init__(self, parent: tk.Widget, offset: int = 0, width: int = 8, **kwargs):
        self._offset = offset
        self._width  = width
        super().__init__(
            parent,
            text=self._fmt(offset),
            font=FONTS["mono"],
            bg=COLORS["hex_bg"],
            fg=COLORS["offset_fg"],
            anchor="w",
            **kwargs
        )

    def _fmt(self, offset: int) -> str:
        return f"0x{offset:0{self._width}X}"

    def set_offset(self, offset: int) -> None:
        self._offset = offset
        self.configure(text=self._fmt(offset))

    def get_offset(self) -> int:
        return self._offset


class ByteInfoPanel(tk.LabelFrame):
    """
    Panel showing detailed information about a byte value:
    - Hex, decimal, binary, octal representations
    - Signed/unsigned interpretations
    - Multi-byte value interpretations (u16, u32, float)
    """

    def __init__(self, parent: tk.Widget, **kwargs):
        super().__init__(
            parent,
            text=" Byte Info ",
            bg=COLORS["panel_bg"],
            fg=COLORS["accent"],
            font=FONTS["bold"],
            relief="flat",
            bd=1,
            **kwargs
        )
        self._data:   bytes  = b""
        self._offset: int    = 0
        self._build()

    def _build(self) -> None:
        self._vars: Dict[str, tk.StringVar] = {}

        rows = [
            ("Offset (hex)",  "off_hex"),
            ("Offset (dec)",  "off_dec"),
            ("Value (hex)",   "val_hex"),
            ("Value (dec)",   "val_dec"),
            ("Value (bin)",   "val_bin"),
            ("Value (oct)",   "val_oct"),
            ("uint8",         "u8"),
            ("int8",          "i8"),
            ("uint16 LE",     "u16_le"),
            ("uint16 BE",     "u16_be"),
            ("uint32 LE",     "u32_le"),
            ("uint32 BE",     "u32_be"),
            ("int32 LE",      "i32_le"),
            ("float32 LE",    "f32_le"),
            ("float64 LE",    "f64_le"),
            ("uint64 LE",     "u64_le"),
            ("ASCII char",    "ascii"),
        ]

        for label, key in rows:
            frame = tk.Frame(self, bg=COLORS["panel_bg"])
            frame.pack(fill="x", padx=4, pady=1)

            tk.Label(
                frame, text=f"{label}:",
                width=14, anchor="w",
                font=FONTS["small"],
                bg=COLORS["panel_bg"],
                fg=COLORS["hex_fg"]
            ).pack(side="left")

            var = tk.StringVar(value="--")
            self._vars[key] = var

            tk.Label(
                frame, textvariable=var,
                anchor="e",
                font=FONTS["mono"],
                bg=COLORS["panel_bg"],
                fg=COLORS["ascii_fg"]
            ).pack(side="right", fill="x", expand=True)

    def update(self, data: bytes, offset: int) -> None:
        """Update the panel with new data and offset."""
        self._data   = data
        self._offset = offset

        if offset >= len(data):
            for var in self._vars.values():
                var.set("--")
            return

        b = data[offset]

        self._vars["off_hex"].set(f"0x{offset:08X}")
        self._vars["off_dec"].set(str(offset))
        self._vars["val_hex"].set(f"0x{b:02X}")
        self._vars["val_dec"].set(str(b))
        self._vars["val_bin"].set(f"{b:08b}")
        self._vars["val_oct"].set(f"0o{b:03o}")
        self._vars["u8"].set(str(b))
        self._vars["i8"].set(str(b if b < 128 else b - 256))
        self._vars["ascii"].set(chr(b) if 0x20 <= b <= 0x7E else f"<{b:02X}>")

        # Multi-byte reads
        if offset + 2 <= len(data):
            chunk = data[offset:offset + 2]
            self._vars["u16_le"].set(str(struct.unpack_from("<H", chunk)[0]))
            self._vars["u16_be"].set(str(struct.unpack_from(">H", chunk)[0]))

        if offset + 4 <= len(data):
            chunk = data[offset:offset + 4]
            self._vars["u32_le"].set(f"0x{struct.unpack_from('<I', chunk)[0]:08X}")
            self._vars["u32_be"].set(f"0x{struct.unpack_from('>I', chunk)[0]:08X}")
            self._vars["i32_le"].set(str(struct.unpack_from("<i", chunk)[0]))
            try:
                self._vars["f32_le"].set(f"{struct.unpack_from('<f', chunk)[0]:.6g}")
            except Exception:
                self._vars["f32_le"].set("N/A")

        if offset + 8 <= len(data):
            chunk = data[offset:offset + 8]
            self._vars["u64_le"].set(f"0x{struct.unpack_from('<Q', chunk)[0]:016X}")
            try:
                self._vars["f64_le"].set(f"{struct.unpack_from('<d', chunk)[0]:.10g}")
            except Exception:
                self._vars["f64_le"].set("N/A")


class BookmarkPanel(tk.LabelFrame):
    """Panel for managing file bookmarks."""

    def __init__(
        self,
        parent:     tk.Widget,
        on_goto:    Optional[Callable] = None,
        on_add:     Optional[Callable] = None,
        on_remove:  Optional[Callable] = None,
        **kwargs
    ):
        super().__init__(
            parent,
            text=" Bookmarks ",
            bg=COLORS["panel_bg"],
            fg=COLORS["accent"],
            font=FONTS["bold"],
            relief="flat",
            bd=1,
            **kwargs
        )
        self._on_goto   = on_goto
        self._on_add    = on_add
        self._on_remove = on_remove
        self._bookmarks: List[Tuple[str, int]] = []
        self._build()

    def _build(self) -> None:
        # Controls
        ctrl = tk.Frame(self, bg=COLORS["panel_bg"])
        ctrl.pack(fill="x", padx=4, pady=4)

        tk.Button(
            ctrl, text="Add",
            command=self._do_add,
            bg=COLORS["accent"], fg=COLORS["hex_bg"],
            relief="flat", padx=6, pady=2,
            font=FONTS["small"], cursor="hand2"
        ).pack(side="left", padx=2)

        tk.Button(
            ctrl, text="Remove",
            command=self._do_remove,
            bg=COLORS["error"], fg=COLORS["hex_bg"],
            relief="flat", padx=6, pady=2,
            font=FONTS["small"], cursor="hand2"
        ).pack(side="left", padx=2)

        tk.Button(
            ctrl, text="Go",
            command=self._do_goto,
            bg=COLORS["panel_bg"], fg=COLORS["hex_fg"],
            relief="flat", padx=6, pady=2,
            font=FONTS["small"], cursor="hand2"
        ).pack(side="right", padx=2)

        # List
        list_frame = tk.Frame(self, bg=COLORS["panel_bg"])
        list_frame.pack(fill="both", expand=True, padx=4, pady=4)

        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")

        self._listbox = tk.Listbox(
            list_frame,
            bg=COLORS["hex_bg"], fg=COLORS["hex_fg"],
            font=FONTS["mono"], relief="flat", bd=0,
            selectbackground=COLORS["selection_bg"],
            yscrollcommand=scrollbar.set,
            activestyle="none",
        )
        self._listbox.pack(fill="both", expand=True)
        scrollbar.configure(command=self._listbox.yview)
        self._listbox.bind("<Double-Button-1>", lambda e: self._do_goto())

    def add_bookmark(self, name: str, offset: int) -> None:
        """Add a bookmark."""
        self._bookmarks.append((name, offset))
        self._listbox.insert("end", f"{name:<20} 0x{offset:08X}")

    def remove_bookmark(self, index: int) -> None:
        """Remove bookmark by index."""
        if 0 <= index < len(self._bookmarks):
            self._bookmarks.pop(index)
            self._listbox.delete(index)

    def clear(self) -> None:
        """Clear all bookmarks."""
        self._bookmarks.clear()
        self._listbox.delete(0, "end")

    def _do_add(self) -> None:
        if self._on_add:
            self._on_add()

    def _do_remove(self) -> None:
        sel = self._listbox.curselection()
        if sel:
            idx = sel[0]
            self.remove_bookmark(idx)
            if self._on_remove:
                self._on_remove(idx)

    def _do_goto(self) -> None:
        sel = self._listbox.curselection()
        if sel and self._on_goto:
            idx = sel[0]
            if idx < len(self._bookmarks):
                self._on_goto(self._bookmarks[idx][1])

    def get_bookmarks(self) -> List[Tuple[str, int]]:
        return list(self._bookmarks)


class HexEntryWidget(tk.Frame):
    """An entry widget that only accepts valid hex input."""

    def __init__(
        self,
        parent:    tk.Widget,
        width:     int = 10,
        on_change: Optional[Callable] = None,
        **kwargs
    ):
        super().__init__(parent, bg=COLORS["panel_bg"], **kwargs)
        self._on_change = on_change
        self._var = tk.StringVar()
        self._var.trace_add("write", self._validate)

        self._entry = tk.Entry(
            self,
            textvariable=self._var,
            width=width,
            font=FONTS["mono"],
            bg=COLORS["hex_bg"],
            fg=COLORS["hex_fg"],
            insertbackground=COLORS["accent"],
            relief="flat", bd=3,
            validate="key",
            validatecommand=(self.register(self._is_valid_hex), "%P"),
        )
        self._entry.pack()

    def _is_valid_hex(self, text: str) -> bool:
        if not text:
            return True
        return all(c in "0123456789ABCDEFabcdef " for c in text)

    def _validate(self, *args) -> None:
        if self._on_change:
            self._on_change(self._var.get())

    def get(self) -> str:
        return self._var.get().strip()

    def get_bytes(self) -> Optional[bytes]:
        try:
            return bytes.fromhex(self.get().replace(" ", ""))
        except ValueError:
            return None

    def set(self, value: str) -> None:
        self._var.set(value)

    def set_bytes(self, data: bytes) -> None:
        self._var.set(" ".join(f"{b:02X}" for b in data))


class EntropyBar(tk.Canvas):
    """Visual entropy display bar."""

    def __init__(self, parent: tk.Widget, width: int = 300, height: int = 20, **kwargs):
        super().__init__(
            parent,
            width=width, height=height,
            bg=COLORS["hex_bg"],
            relief="flat", bd=0, highlightthickness=0,
            **kwargs
        )
        self._width  = width
        self._height = height
        self._blocks: List[float] = []

    def set_entropy(self, entropy_values: List[float]) -> None:
        """
        Set entropy values (0.0 to 8.0) for display.

        Args:
            entropy_values: List of per-block entropy values
        """
        self._blocks = entropy_values
        self._draw()

    def _draw(self) -> None:
        self.delete("all")
        if not self._blocks:
            return

        block_w = self._width / len(self._blocks)
        for i, entropy in enumerate(self._blocks):
            # Color gradient: low entropy = blue, high = red
            ratio = min(1.0, entropy / 8.0)
            r     = int(255 * ratio)
            g     = int(100 * (1 - abs(ratio - 0.5) * 2))
            b     = int(255 * (1 - ratio))
            color = f"#{r:02X}{g:02X}{b:02X}"

            x0 = int(i * block_w)
            x1 = int((i + 1) * block_w)
            self.create_rectangle(x0, 0, x1, self._height, fill=color, outline="")

    def clear(self) -> None:
        self._blocks = []
        self.delete("all")


class ScrolledText(tk.Frame):
    """Text widget with scrollbars."""

    def __init__(
        self,
        parent:   tk.Widget,
        height:   int = 10,
        readonly: bool = False,
        **kwargs
    ):
        super().__init__(parent, bg=COLORS["panel_bg"], **kwargs)

        v_scroll = tk.Scrollbar(self, orient="vertical")
        h_scroll = tk.Scrollbar(self, orient="horizontal")

        self._text = tk.Text(
            self,
            bg=COLORS["hex_bg"], fg=COLORS["hex_fg"],
            font=FONTS["mono"],
            relief="flat", bd=4,
            insertbackground=COLORS["accent"],
            yscrollcommand=v_scroll.set,
            xscrollcommand=h_scroll.set,
            wrap="none",
            height=height,
            state="disabled" if readonly else "normal",
        )

        v_scroll.configure(command=self._text.yview)
        h_scroll.configure(command=self._text.xview)

        h_scroll.pack(side="bottom", fill="x")
        v_scroll.pack(side="right",  fill="y")
        self._text.pack(fill="both", expand=True)

    def insert(self, text: str, tags: Optional[str] = None) -> None:
        self._text.configure(state="normal")
        if tags:
            self._text.insert("end", text, tags)
        else:
            self._text.insert("end", text)
        self._text.configure(state="disabled")

    def clear(self) -> None:
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.configure(state="disabled")

    def get_all(self) -> str:
        return self._text.get("1.0", "end")

    def set_text(self, text: str) -> None:
        self.clear()
        self.insert(text)

    @property
    def text_widget(self) -> tk.Text:
        return self._text


class StatusBar(tk.Frame):
    """Multi-section status bar."""

    def __init__(self, parent: tk.Widget, **kwargs):
        super().__init__(
            parent,
            bg=COLORS["selection_bg"],
            height=22,
            relief="flat",
            **kwargs
        )
        self.pack_propagate(False)
        self._vars: Dict[str, tk.StringVar] = {}
        self._default_status = "Ready"
        self._build()

    def _build(self) -> None:
        sections = [
            ("main",      40),
            ("offset",    20),
            ("size",      14),
            ("selection", 20),
            ("mode",      10),
            ("modified",   6),
        ]

        for key, width in sections:
            var = tk.StringVar()
            self._vars[key] = var

            lbl = tk.Label(
                self, textvariable=var,
                width=width, anchor="w",
                font=("Segoe UI", 9),
                bg=COLORS["selection_bg"],
                fg=COLORS["hex_fg"],
                padx=6
            )
            lbl.pack(side="left")

            tk.Frame(self, bg=COLORS["separator"], width=1).pack(
                side="left", fill="y", pady=2
            )

        self.set("main", self._default_status)

    def set(self, key: str, value: str) -> None:
        if key in self._vars:
            self._vars[key].set(value)

    def set_status(self, msg: str) -> None:
        self.set("main", msg)

    def set_offset(self, offset: int) -> None:
        self.set("offset", f"0x{offset:08X}")

    def set_size(self, size: int) -> None:
        self.set("size", f"{size:,} bytes")

    def set_modified(self, mod: bool) -> None:
        self.set("modified", "MOD" if mod else "")

    def set_mode(self, mode: str) -> None:
        self.set("mode", mode)

    def clear(self) -> None:
        for key in self._vars:
            self._vars[key].set("")
        self.set("main", self._default_status)
