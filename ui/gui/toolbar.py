# =============================================================================
# BinModder - Toolbar and Menu Components
# =============================================================================
# Provides the main application toolbar with buttons, dropdowns,
# search bar, and quick-action icons.
#
# Author: MSR Electronics
# Version: 1.0.0
# =============================================================================

import tkinter as tk
from tkinter import ttk
from typing import Optional, Callable, Dict, List, Any
from pathlib import Path

COLORS = {
    "bg":          "#1E1E2E",
    "toolbar_bg":  "#181825",
    "btn_bg":      "#181825",
    "btn_fg":      "#CDD6F4",
    "btn_hover":   "#313244",
    "accent":      "#CBA6F7",
    "separator":   "#45475A",
    "hex_bg":      "#11111B",
    "hex_fg":      "#CDD6F4",
    "success":     "#A6E3A1",
    "warning":     "#F9E2AF",
    "error":       "#F38BA8",
}

FONTS = {
    "icon":  ("Segoe UI Emoji", 13),
    "label": ("Segoe UI", 9),
    "entry": ("Courier New", 10),
}


class ToolbarButton(tk.Button):
    """Custom styled toolbar button with hover effects."""

    def __init__(
        self,
        parent:   tk.Widget,
        text:     str,
        command:  Optional[Callable] = None,
        icon:     str = "",
        tooltip:  str = "",
        **kwargs
    ):
        display = f"{icon} {text}".strip() if icon else text
        super().__init__(
            parent,
            text=display,
            command=command,
            bg=COLORS["btn_bg"],
            fg=COLORS["btn_fg"],
            activebackground=COLORS["btn_hover"],
            activeforeground=COLORS["accent"],
            relief="flat",
            bd=0,
            padx=8,
            pady=5,
            cursor="hand2",
            font=FONTS["label"],
            **kwargs
        )
        self._tooltip_text = tooltip
        self._tooltip_win  = None

        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)

    def _on_enter(self, event) -> None:
        self.configure(bg=COLORS["btn_hover"], fg=COLORS["accent"])
        if self._tooltip_text:
            self._show_tooltip()

    def _on_leave(self, event) -> None:
        self.configure(bg=COLORS["btn_bg"], fg=COLORS["btn_fg"])
        self._hide_tooltip()

    def _show_tooltip(self) -> None:
        x = self.winfo_rootx() + 20
        y = self.winfo_rooty() + self.winfo_height() + 4
        self._tooltip_win = tk.Toplevel(self)
        self._tooltip_win.wm_overrideredirect(True)
        self._tooltip_win.geometry(f"+{x}+{y}")
        tk.Label(
            self._tooltip_win,
            text=self._tooltip_text,
            bg="#F9E2AF", fg="#1E1E2E",
            font=FONTS["label"], relief="solid", bd=1, padx=4
        ).pack()

    def _hide_tooltip(self) -> None:
        if self._tooltip_win:
            self._tooltip_win.destroy()
            self._tooltip_win = None


class ToolbarSeparator(tk.Frame):
    """Vertical separator for toolbar."""

    def __init__(self, parent: tk.Widget):
        super().__init__(
            parent,
            bg=COLORS["separator"],
            width=1
        )
        self.pack(side="left", fill="y", padx=6, pady=4)


class ToolbarDropdown(tk.Frame):
    """Dropdown selector for toolbar."""

    def __init__(
        self,
        parent:  tk.Widget,
        label:   str,
        options: List[str],
        on_select: Optional[Callable] = None,
        **kwargs
    ):
        super().__init__(parent, bg=COLORS["toolbar_bg"], **kwargs)
        self._on_select = on_select

        tk.Label(
            self, text=label,
            bg=COLORS["toolbar_bg"], fg=COLORS["btn_fg"],
            font=FONTS["label"]
        ).pack(side="left", padx=(4, 2))

        self._var = tk.StringVar(value=options[0] if options else "")
        combo = ttk.Combobox(
            self,
            textvariable=self._var,
            values=options,
            width=10,
            state="readonly",
            font=FONTS["label"],
        )
        combo.pack(side="left", padx=2)
        combo.bind("<<ComboboxSelected>>", self._on_change)

    def _on_change(self, event) -> None:
        if self._on_select:
            self._on_select(self._var.get())

    @property
    def value(self) -> str:
        return self._var.get()

    def set_value(self, val: str) -> None:
        self._var.set(val)


class SearchBar(tk.Frame):
    """Inline search bar for the toolbar."""

    def __init__(
        self,
        parent:    tk.Widget,
        on_search: Optional[Callable] = None,
        **kwargs
    ):
        super().__init__(parent, bg=COLORS["toolbar_bg"], **kwargs)
        self._on_search = on_search

        # Entry
        self._var = tk.StringVar()
        self._entry = tk.Entry(
            self,
            textvariable=self._var,
            width=24,
            font=FONTS["entry"],
            bg=COLORS["hex_bg"],
            fg=COLORS["hex_fg"],
            insertbackground=COLORS["accent"],
            relief="flat", bd=3
        )
        self._entry.pack(side="left", padx=(4, 2))
        self._entry.bind("<Return>", lambda e: self._do_search())

        # Placeholder
        self._entry.insert(0, "Search hex pattern...")
        self._entry.configure(fg=COLORS["separator"])
        self._entry.bind("<FocusIn>",  self._on_focus_in)
        self._entry.bind("<FocusOut>", self._on_focus_out)
        self._has_placeholder = True

        # Search button
        ToolbarButton(
            self, text="Search",
            command=self._do_search,
            icon=""
        ).pack(side="left")

        # Result indicator
        self._result_var = tk.StringVar()
        tk.Label(
            self,
            textvariable=self._result_var,
            bg=COLORS["toolbar_bg"],
            fg=COLORS["accent"],
            font=FONTS["label"],
            width=16, anchor="w"
        ).pack(side="left", padx=4)

    def _on_focus_in(self, event) -> None:
        if self._has_placeholder:
            self._entry.delete(0, "end")
            self._entry.configure(fg=COLORS["hex_fg"])
            self._has_placeholder = False

    def _on_focus_out(self, event) -> None:
        if not self._entry.get():
            self._entry.insert(0, "Search hex pattern...")
            self._entry.configure(fg=COLORS["separator"])
            self._has_placeholder = True

    def _do_search(self) -> None:
        pattern = self._var.get().strip()
        if not pattern or self._has_placeholder:
            return
        if self._on_search:
            result = self._on_search(pattern)
            if result is not None:
                self._result_var.set(f"{result} match(es)")
            else:
                self._result_var.set("Not found")

    @property
    def pattern(self) -> str:
        return "" if self._has_placeholder else self._var.get()

    def set_result(self, text: str) -> None:
        self._result_var.set(text)

    def clear(self) -> None:
        self._var.set("")
        self._result_var.set("")


class BinModderToolbar(tk.Frame):
    """
    Main application toolbar for BinModder.

    Contains:
    - File operations (New, Open, Save)
    - Edit operations (Undo, Redo)
    - Navigation (Go to offset)
    - Search bar
    - View controls (bytes per row, display mode)
    - Tools (Checksums, Patch, Analyze)
    """

    def __init__(
        self,
        parent: tk.Widget,
        callbacks: Dict[str, Callable],
        **kwargs
    ):
        super().__init__(
            parent,
            bg=COLORS["toolbar_bg"],
            height=42,
            relief="flat",
            **kwargs
        )
        self.pack_propagate(False)
        self._callbacks = callbacks
        self._build()

    def _build(self) -> None:
        """Build the toolbar content."""
        cb = self._callbacks

        # File group
        self._add_group([
            ("📂", "Open",   cb.get("open"),    "Open file (Ctrl+O)"),
            ("💾", "Save",   cb.get("save"),    "Save file (Ctrl+S)"),
            ("📄", "New",    cb.get("new"),     "New file (Ctrl+N)"),
        ])

        ToolbarSeparator(self)

        # Edit group
        self._add_group([
            ("↩", "Undo", cb.get("undo"), "Undo (Ctrl+Z)"),
            ("↪", "Redo", cb.get("redo"), "Redo (Ctrl+Y)"),
        ])

        ToolbarSeparator(self)

        # Navigation
        self._add_group([
            ("⇒", "Goto", cb.get("goto"), "Go to offset (Ctrl+G)"),
        ])

        ToolbarSeparator(self)

        # Bytes per row selector
        bpr_dropdown = ToolbarDropdown(
            self, "BPR:",
            ["8", "16", "32", "64"],
            on_select=cb.get("set_bpr")
        )
        bpr_dropdown.pack(side="left", padx=2)
        bpr_dropdown.set_value("16")
        self._bpr_dropdown = bpr_dropdown

        ToolbarSeparator(self)

        # View mode selector
        mode_dropdown = ToolbarDropdown(
            self, "Mode:",
            ["Hex+ASCII", "Hex Only", "ASCII Only", "DWORDs", "QWORDs"],
            on_select=cb.get("set_mode")
        )
        mode_dropdown.pack(side="left", padx=2)
        self._mode_dropdown = mode_dropdown

        ToolbarSeparator(self)

        # Tools group
        self._add_group([
            ("✓", "Checksum", cb.get("checksum"), "Calculate checksums"),
            ("🔧", "Patch",   cb.get("patch"),    "Apply/create patch"),
            ("🔍", "Analyze", cb.get("analyze"),  "Analyze file"),
            ("▶",  "Script",  cb.get("script"),   "Run BSL script"),
        ])

        ToolbarSeparator(self)

        # Search bar (right side)
        self._search_bar = SearchBar(
            self,
            on_search=cb.get("search")
        )
        self._search_bar.pack(side="right", padx=8)

    def _add_group(self, buttons: list) -> None:
        """Add a group of toolbar buttons."""
        for icon, label, cmd, tooltip in buttons:
            btn = ToolbarButton(
                self,
                text=label,
                command=cmd,
                icon=icon,
                tooltip=tooltip,
            )
            btn.pack(side="left", padx=1, pady=3)

    def set_bpr(self, bpr: int) -> None:
        self._bpr_dropdown.set_value(str(bpr))

    def search_result(self, text: str) -> None:
        self._search_bar.set_result(text)

    @property
    def search_pattern(self) -> str:
        return self._search_bar.pattern


class StatusBar(tk.Frame):
    """Application status bar with multiple sections."""

    SECTIONS = [
        ("status",    40, "w"),   # Main status message
        ("offset",    18, "w"),   # Cursor offset
        ("size",      14, "w"),   # File size
        ("selection", 18, "w"),   # Selection info
        ("encoding",  12, "center"), # Encoding
        ("modified",   5, "center"), # Modified indicator
    ]

    def __init__(self, parent: tk.Widget, **kwargs):
        super().__init__(
            parent,
            bg=COLORS["btn_hover"],
            height=22,
            relief="flat",
            **kwargs
        )
        self.pack_propagate(False)
        self._vars: Dict[str, tk.StringVar] = {}
        self._build()

    def _build(self) -> None:
        for key, width, anchor in self.SECTIONS:
            var = tk.StringVar()
            self._vars[key] = var

            label = tk.Label(
                self,
                textvariable=var,
                anchor=anchor,
                width=width,
                font=FONTS["label"],
                bg=COLORS["btn_hover"],
                fg=COLORS["btn_fg"],
                padx=6
            )
            label.pack(side="left")

            # Separator after each section
            tk.Frame(
                self, bg=COLORS["separator"], width=1
            ).pack(side="left", fill="y", pady=2)

    def set(self, key: str, value: str) -> None:
        """Set a status bar section value."""
        if key in self._vars:
            self._vars[key].set(value)

    def set_status(self, message: str) -> None:
        self.set("status", message)

    def set_offset(self, offset: int) -> None:
        self.set("offset", f"Offset: 0x{offset:08X}")

    def set_size(self, size: int) -> None:
        self.set("size", f"Size: {size:,}")

    def set_selection(self, start: int, end: int) -> None:
        size = abs(end - start)
        self.set("selection", f"Sel: {size:,} bytes")

    def clear_selection(self) -> None:
        self.set("selection", "")

    def set_modified(self, modified: bool) -> None:
        self.set("modified", "MOD" if modified else "")

    def set_encoding(self, encoding: str) -> None:
        self.set("encoding", encoding)

    def clear(self) -> None:
        for var in self._vars.values():
            var.set("")
