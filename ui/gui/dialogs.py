# =============================================================================
# BinModder - Dialog Windows
# =============================================================================
# All dialog windows for BinModder GUI: Goto, Find, Replace, Checksum,
# Patch, Script, and About dialogs.
#
# Author: MSR Electronics
# Version: 1.0.0
# =============================================================================

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Optional, Callable, List, Any
from pathlib import Path


# Shared colors matching main window
COLORS = {
    "bg":          "#1E1E2E",
    "panel_bg":    "#181825",
    "hex_bg":      "#11111B",
    "hex_fg":      "#CDD6F4",
    "offset_fg":   "#89DCEB",
    "ascii_fg":    "#A6E3A1",
    "accent":      "#CBA6F7",
    "error":       "#F38BA8",
    "warning":     "#F9E2AF",
    "separator":   "#45475A",
}
FONTS = {
    "mono":    ("Courier New", 10),
    "ui":      ("Segoe UI", 10),
    "ui_bold": ("Segoe UI", 10, "bold"),
    "small":   ("Segoe UI", 9),
    "title":   ("Segoe UI", 14, "bold"),
}


def _btn(parent, text, cmd, color=None, **kwargs):
    """Helper: create a styled button."""
    bg = color or COLORS["accent"]
    return tk.Button(
        parent, text=text, command=cmd,
        bg=bg, fg=COLORS["hex_bg"] if bg != COLORS["panel_bg"] else COLORS["hex_fg"],
        relief="flat", padx=12, pady=5, font=FONTS["ui"], cursor="hand2",
        **kwargs
    )


def _label(parent, text, bold=False, color=None, **kwargs):
    return tk.Label(
        parent, text=text,
        bg=COLORS["panel_bg"],
        fg=color or COLORS["hex_fg"],
        font=FONTS["ui_bold"] if bold else FONTS["ui"],
        **kwargs
    )


def _entry(parent, var, width=30, **kwargs):
    return tk.Entry(
        parent, textvariable=var, width=width,
        bg=COLORS["hex_bg"], fg=COLORS["hex_fg"],
        insertbackground=COLORS["accent"],
        relief="flat", bd=4, font=FONTS["mono"],
        **kwargs
    )


class BaseDialog(tk.Toplevel):
    """Base class for all BinModder dialogs."""

    def __init__(
        self,
        parent: tk.Widget,
        title:  str,
        width:  int = 400,
        height: int = 250
    ):
        super().__init__(parent)
        self.title(title)
        self.geometry(f"{width}x{height}")
        self.configure(bg=COLORS["panel_bg"])
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        # Center on parent
        self.update_idletasks()
        px = parent.winfo_rootx() + (parent.winfo_width() - width) // 2
        py = parent.winfo_rooty() + (parent.winfo_height() - height) // 2
        self.geometry(f"{width}x{height}+{px}+{py}")

        self._build_ui()
        self.focus_set()

    def _build_ui(self) -> None:
        """Override in subclasses."""
        pass


# =============================================================================
# Goto Dialog
# =============================================================================

class GotoDialog(BaseDialog):
    """Go to offset dialog."""

    def __init__(self, parent, on_goto: Callable[[int], None]):
        self._on_goto = on_goto
        self._result  = None
        super().__init__(parent, "Go to Offset", 320, 140)

    def _build_ui(self) -> None:
        _label(self, "Enter offset (hex 0x... or decimal):").pack(pady=(12, 4), padx=10, anchor="w")

        self._var = tk.StringVar()
        entry = _entry(self, self._var, width=30)
        entry.pack(padx=10)
        entry.focus_set()
        entry.bind("<Return>", lambda e: self._go())

        self._error_var = tk.StringVar()
        tk.Label(
            self, textvariable=self._error_var,
            bg=COLORS["panel_bg"], fg=COLORS["error"], font=FONTS["small"]
        ).pack(pady=2)

        btn_frame = tk.Frame(self, bg=COLORS["panel_bg"])
        btn_frame.pack(pady=8)
        _btn(btn_frame, "Go",     self._go).pack(side="left", padx=4)
        _btn(btn_frame, "Cancel", self.destroy, color=COLORS["panel_bg"]).pack(side="left", padx=4)

    def _go(self) -> None:
        text = self._var.get().strip()
        try:
            offset = int(text, 0)
            if offset < 0:
                raise ValueError("Negative offset")
            self._on_goto(offset)
            self.destroy()
        except ValueError:
            self._error_var.set(f"Invalid offset: {text!r}")


# =============================================================================
# Find Dialog
# =============================================================================

class FindDialog(BaseDialog):
    """Binary pattern find dialog."""

    def __init__(
        self,
        parent,
        on_find: Callable[[str, bool, bool], None],
        on_find_next: Callable[[], None],
        on_find_prev: Callable[[], None],
    ):
        self._on_find      = on_find
        self._on_find_next = on_find_next
        self._on_find_prev = on_find_prev
        self._results_var  = tk.StringVar()
        super().__init__(parent, "Find Pattern", 480, 260)

    def _build_ui(self) -> None:
        # Pattern type
        type_frame = tk.Frame(self, bg=COLORS["panel_bg"])
        type_frame.pack(fill="x", padx=12, pady=(10, 0))

        _label(type_frame, "Search type:").pack(side="left")
        self._search_type = tk.StringVar(value="hex")
        for val, label in [("hex", "Hex Pattern"), ("text", "Text String"), ("regex", "Regex")]:
            tk.Radiobutton(
                type_frame, text=label, variable=self._search_type, value=val,
                bg=COLORS["panel_bg"], fg=COLORS["hex_fg"],
                selectcolor=COLORS["hex_bg"], activebackground=COLORS["panel_bg"],
                font=FONTS["small"]
            ).pack(side="left", padx=4)

        # Pattern entry
        _label(self, "Pattern:").pack(padx=12, anchor="w", pady=(8, 0))
        self._pattern_var = tk.StringVar()
        _entry(self, self._pattern_var, width=55).pack(padx=12)

        # Options
        opt_frame = tk.Frame(self, bg=COLORS["panel_bg"])
        opt_frame.pack(fill="x", padx=12, pady=4)

        self._case_sensitive = tk.BooleanVar(value=True)
        tk.Checkbutton(
            opt_frame, text="Case sensitive",
            variable=self._case_sensitive,
            bg=COLORS["panel_bg"], fg=COLORS["hex_fg"],
            selectcolor=COLORS["hex_bg"], font=FONTS["small"]
        ).pack(side="left")

        self._search_from_cursor = tk.BooleanVar(value=False)
        tk.Checkbutton(
            opt_frame, text="From cursor",
            variable=self._search_from_cursor,
            bg=COLORS["panel_bg"], fg=COLORS["hex_fg"],
            selectcolor=COLORS["hex_bg"], font=FONTS["small"]
        ).pack(side="left", padx=8)

        # Result
        tk.Label(
            self, textvariable=self._results_var,
            bg=COLORS["panel_bg"], fg=COLORS["accent"], font=FONTS["small"]
        ).pack(pady=2)

        # Buttons
        btn_frame = tk.Frame(self, bg=COLORS["panel_bg"])
        btn_frame.pack(pady=8)

        _btn(btn_frame, "Find All",      self._do_find_all).pack(side="left", padx=3)
        _btn(btn_frame, "Find Next",     self._on_find_next).pack(side="left", padx=3)
        _btn(btn_frame, "Find Previous", self._on_find_prev).pack(side="left", padx=3)
        _btn(btn_frame, "Close",         self.destroy, color=COLORS["panel_bg"]).pack(side="left", padx=3)

    def _do_find_all(self) -> None:
        pattern = self._pattern_var.get().strip()
        if not pattern:
            return
        self._on_find(
            pattern,
            self._case_sensitive.get(),
            self._search_from_cursor.get()
        )


# =============================================================================
# Replace Dialog
# =============================================================================

class ReplaceDialog(BaseDialog):
    """Find and replace dialog."""

    def __init__(
        self,
        parent,
        on_replace: Callable[[str, str, bool], int],
    ):
        self._on_replace = on_replace
        super().__init__(parent, "Find & Replace", 480, 280)

    def _build_ui(self) -> None:
        _label(self, "Find pattern (hex):").pack(padx=12, anchor="w", pady=(10, 0))
        self._find_var = tk.StringVar()
        _entry(self, self._find_var, width=55).pack(padx=12)

        _label(self, "Replace with (hex):").pack(padx=12, anchor="w", pady=(8, 0))
        self._replace_var = tk.StringVar()
        _entry(self, self._replace_var, width=55).pack(padx=12)

        opt_frame = tk.Frame(self, bg=COLORS["panel_bg"])
        opt_frame.pack(fill="x", padx=12, pady=4)

        self._verify_before = tk.BooleanVar(value=True)
        tk.Checkbutton(
            opt_frame, text="Verify before replacing",
            variable=self._verify_before,
            bg=COLORS["panel_bg"], fg=COLORS["hex_fg"],
            selectcolor=COLORS["hex_bg"], font=FONTS["small"]
        ).pack(side="left")

        self._result_var = tk.StringVar()
        tk.Label(
            self, textvariable=self._result_var,
            bg=COLORS["panel_bg"], fg=COLORS["accent"], font=FONTS["small"]
        ).pack(pady=2)

        btn_frame = tk.Frame(self, bg=COLORS["panel_bg"])
        btn_frame.pack(pady=8)

        _btn(btn_frame, "Replace All", self._do_replace_all).pack(side="left", padx=3)
        _btn(btn_frame, "Replace Once", self._do_replace_once).pack(side="left", padx=3)
        _btn(btn_frame, "Cancel", self.destroy, color=COLORS["panel_bg"]).pack(side="left", padx=3)

    def _do_replace_all(self) -> None:
        find    = self._find_var.get().strip()
        replace = self._replace_var.get().strip()
        if not find:
            return
        count = self._on_replace(find, replace, False)
        self._result_var.set(f"Replaced {count} occurrence(s)")

    def _do_replace_once(self) -> None:
        find    = self._find_var.get().strip()
        replace = self._replace_var.get().strip()
        if not find:
            return
        count = self._on_replace(find, replace, True)
        if count:
            self._result_var.set(f"Replaced {count} occurrence")
        else:
            self._result_var.set("Pattern not found")


# =============================================================================
# Checksum Dialog
# =============================================================================

class ChecksumDialog(BaseDialog):
    """Comprehensive checksum calculator dialog."""

    def __init__(self, parent, data: bytes):
        self._data = data
        super().__init__(parent, "Checksum Calculator", 520, 560)

    def _build_ui(self) -> None:
        tk.Label(
            self, text="Checksum Calculator",
            font=FONTS["title"], bg=COLORS["panel_bg"], fg=COLORS["accent"]
        ).pack(pady=(10, 4))

        # Range selection
        range_frame = tk.Frame(self, bg=COLORS["panel_bg"])
        range_frame.pack(fill="x", padx=12, pady=4)

        _label(range_frame, "Start:").pack(side="left")
        self._start_var = tk.StringVar(value="0x00000000")
        _entry(range_frame, self._start_var, width=14).pack(side="left", padx=4)

        _label(range_frame, "End:").pack(side="left", padx=(8, 0))
        self._end_var = tk.StringVar(value=f"0x{len(self._data):08X}")
        _entry(range_frame, self._end_var, width=14).pack(side="left", padx=4)

        _btn(range_frame, "Compute", self._compute).pack(side="left", padx=8)

        # Results listbox
        list_frame = tk.Frame(self, bg=COLORS["panel_bg"])
        list_frame.pack(fill="both", expand=True, padx=12, pady=4)

        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")

        self._listbox = tk.Listbox(
            list_frame,
            bg=COLORS["hex_bg"], fg=COLORS["hex_fg"],
            font=FONTS["mono"], relief="flat", bd=0,
            selectbackground=COLORS["accent"],
            yscrollcommand=scrollbar.set,
            width=60
        )
        self._listbox.pack(fill="both", expand=True)
        scrollbar.configure(command=self._listbox.yview)

        btn_frame = tk.Frame(self, bg=COLORS["panel_bg"])
        btn_frame.pack(pady=8)

        _btn(btn_frame, "Copy Selected", self._copy_selected).pack(side="left", padx=4)
        _btn(btn_frame, "Copy All",      self._copy_all).pack(side="left", padx=4)
        _btn(btn_frame, "Close",         self.destroy, color=COLORS["panel_bg"]).pack(side="left", padx=4)

        # Auto-compute on open
        self._compute()

    def _compute(self) -> None:
        """Compute checksums."""
        self._listbox.delete(0, "end")
        try:
            start = int(self._start_var.get().strip(), 0)
            end   = int(self._end_var.get().strip(), 0)
            data  = self._data[start:end]
        except ValueError as e:
            self._listbox.insert("end", f"Error: {e}")
            return

        try:
            from core.checksum import ChecksumEngine, ChecksumAlgorithm
            engine = ChecksumEngine()
            results = engine.compute_all(data)
            for r in results:
                self._listbox.insert("end", f"{r.algorithm.name:<20} {r.as_hex}")
        except ImportError:
            import hashlib, zlib
            items = [
                ("CRC-32",   f"{zlib.crc32(data) & 0xFFFFFFFF:08X}"),
                ("Adler-32", f"{zlib.adler32(data) & 0xFFFFFFFF:08X}"),
                ("MD5",      hashlib.md5(data).hexdigest().upper()),
                ("SHA-1",    hashlib.sha1(data).hexdigest().upper()),
                ("SHA-256",  hashlib.sha256(data).hexdigest().upper()),
                ("XOR",      f"{__builtins__['__import__']('functools').reduce(lambda a,b: a^b, data, 0):02X}"),
            ]
            for name, val in items:
                self._listbox.insert("end", f"{name:<20} {val}")

    def _copy_selected(self) -> None:
        sel = self._listbox.curselection()
        if sel:
            self.clipboard_clear()
            self.clipboard_append(self._listbox.get(sel[0]))

    def _copy_all(self) -> None:
        items = [self._listbox.get(i) for i in range(self._listbox.size())]
        self.clipboard_clear()
        self.clipboard_append("\n".join(items))


# =============================================================================
# Patch Dialog
# =============================================================================

class PatchDialog(BaseDialog):
    """Patch apply/create dialog."""

    def __init__(
        self,
        parent,
        on_apply:  Callable[[str], None],
        on_create: Callable[[str, str], None],
    ):
        self._on_apply  = on_apply
        self._on_create = on_create
        super().__init__(parent, "Patch Manager", 480, 320)

    def _build_ui(self) -> None:
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=8, pady=8)

        # Apply tab
        apply_frame = tk.Frame(notebook, bg=COLORS["panel_bg"])
        notebook.add(apply_frame, text="Apply Patch")
        self._build_apply_tab(apply_frame)

        # Create tab
        create_frame = tk.Frame(notebook, bg=COLORS["panel_bg"])
        notebook.add(create_frame, text="Create Patch")
        self._build_create_tab(create_frame)

        _btn(self, "Close", self.destroy, color=COLORS["panel_bg"]).pack(pady=8)

    def _build_apply_tab(self, parent: tk.Frame) -> None:
        _label(parent, "Patch file:").pack(padx=10, anchor="w", pady=(10, 0))

        path_frame = tk.Frame(parent, bg=COLORS["panel_bg"])
        path_frame.pack(fill="x", padx=10, pady=4)

        self._apply_path = tk.StringVar()
        _entry(path_frame, self._apply_path, width=42).pack(side="left")
        _btn(path_frame, "Browse...", self._browse_patch).pack(side="left", padx=4)

        self._verify_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            parent, text="Verify original bytes before applying",
            variable=self._verify_var,
            bg=COLORS["panel_bg"], fg=COLORS["hex_fg"],
            selectcolor=COLORS["hex_bg"], font=FONTS["small"]
        ).pack(padx=10, anchor="w")

        self._apply_result_var = tk.StringVar()
        tk.Label(
            parent, textvariable=self._apply_result_var,
            bg=COLORS["panel_bg"], fg=COLORS["accent"], font=FONTS["small"]
        ).pack(pady=4)

        _btn(parent, "Apply Patch", self._do_apply).pack(pady=4)

    def _build_create_tab(self, parent: tk.Frame) -> None:
        _label(parent, "Original file:").pack(padx=10, anchor="w", pady=(10, 0))
        orig_frame = tk.Frame(parent, bg=COLORS["panel_bg"])
        orig_frame.pack(fill="x", padx=10, pady=4)
        self._orig_path = tk.StringVar()
        _entry(orig_frame, self._orig_path, width=40).pack(side="left")
        _btn(orig_frame, "Browse", lambda: self._browse_file(self._orig_path)).pack(side="left", padx=4)

        _label(parent, "Modified file:").pack(padx=10, anchor="w")
        mod_frame = tk.Frame(parent, bg=COLORS["panel_bg"])
        mod_frame.pack(fill="x", padx=10, pady=4)
        self._mod_path = tk.StringVar()
        _entry(mod_frame, self._mod_path, width=40).pack(side="left")
        _btn(mod_frame, "Browse", lambda: self._browse_file(self._mod_path)).pack(side="left", padx=4)

        fmt_frame = tk.Frame(parent, bg=COLORS["panel_bg"])
        fmt_frame.pack(fill="x", padx=10, pady=4)
        _label(fmt_frame, "Format:").pack(side="left")
        self._patch_fmt = tk.StringVar(value="ips")
        for val, lbl in [("ips", "IPS"), ("ups", "UPS"), ("custom", "Custom JSON")]:
            tk.Radiobutton(
                fmt_frame, text=lbl, variable=self._patch_fmt, value=val,
                bg=COLORS["panel_bg"], fg=COLORS["hex_fg"],
                selectcolor=COLORS["hex_bg"], font=FONTS["small"]
            ).pack(side="left", padx=4)

        _btn(parent, "Create Patch", self._do_create).pack(pady=8)

    def _browse_patch(self) -> None:
        path = filedialog.askopenfilename(
            title="Select Patch File",
            filetypes=[("Patch Files", "*.ips *.ups *.bps *.json"), ("All Files", "*.*")]
        )
        if path:
            self._apply_path.set(path)

    def _browse_file(self, var: tk.StringVar) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("Binary Files", "*.bin"), ("All Files", "*.*")]
        )
        if path:
            var.set(path)

    def _do_apply(self) -> None:
        path = self._apply_path.get().strip()
        if not path:
            self._apply_result_var.set("Please select a patch file")
            return
        try:
            self._on_apply(path)
            self._apply_result_var.set("Patch applied successfully!")
        except Exception as e:
            self._apply_result_var.set(f"Error: {e}")

    def _do_create(self) -> None:
        orig = self._orig_path.get().strip()
        mod  = self._mod_path.get().strip()
        if not orig or not mod:
            messagebox.showwarning("Missing", "Please select both original and modified files")
            return
        try:
            self._on_create(orig, mod)
            messagebox.showinfo("Success", "Patch created successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create patch:\n{e}")


# =============================================================================
# Script Dialog
# =============================================================================

class ScriptDialog(BaseDialog):
    """BSL Script runner dialog."""

    def __init__(self, parent, on_run: Callable[[str], str]):
        self._on_run = on_run
        super().__init__(parent, "Script Runner", 600, 500)

    def _build_ui(self) -> None:
        tk.Label(
            self, text="BinModder Script Language (BSL)",
            font=FONTS["ui_bold"], bg=COLORS["panel_bg"], fg=COLORS["accent"]
        ).pack(pady=(8, 0))

        # Script editor
        editor_frame = tk.Frame(self, bg=COLORS["panel_bg"])
        editor_frame.pack(fill="both", expand=True, padx=10, pady=4)

        _label(editor_frame, "Script:").pack(anchor="w")

        edit_area = tk.Frame(editor_frame, bg=COLORS["panel_bg"])
        edit_area.pack(fill="both", expand=True)

        v_scroll = tk.Scrollbar(edit_area)
        v_scroll.pack(side="right", fill="y")

        self._editor = tk.Text(
            edit_area,
            bg=COLORS["hex_bg"], fg=COLORS["hex_fg"],
            font=FONTS["mono"], relief="flat", bd=4,
            insertbackground=COLORS["accent"],
            yscrollcommand=v_scroll.set,
            height=12
        )
        self._editor.pack(fill="both", expand=True)
        v_scroll.configure(command=self._editor.yview)

        # Insert example script
        self._editor.insert("1.0", "# Example BSL Script\n# open \"firmware.bin\" as f\n# var crc = crc32 f 0x0000 0x8000\n# print hex(crc)\n")

        # Output area
        _label(editor_frame, "Output:").pack(anchor="w", pady=(4, 0))
        self._output = tk.Text(
            editor_frame,
            bg=COLORS["hex_bg"], fg=COLORS["ascii_fg"],
            font=FONTS["mono"], relief="flat", bd=4,
            height=6, state="disabled"
        )
        self._output.pack(fill="both")

        # Buttons
        btn_frame = tk.Frame(self, bg=COLORS["panel_bg"])
        btn_frame.pack(pady=8)

        _btn(btn_frame, "Run Script",  self._run).pack(side="left", padx=4)
        _btn(btn_frame, "Load File...", self._load_script).pack(side="left", padx=4)
        _btn(btn_frame, "Clear",       self._clear).pack(side="left", padx=4)
        _btn(btn_frame, "Close",       self.destroy, color=COLORS["panel_bg"]).pack(side="left", padx=4)

    def _run(self) -> None:
        script = self._editor.get("1.0", "end").strip()
        if not script:
            return
        try:
            result = self._on_run(script)
            self._output.configure(state="normal")
            self._output.delete("1.0", "end")
            self._output.insert("1.0", result or "Script completed.")
            self._output.configure(state="disabled")
        except Exception as e:
            self._output.configure(state="normal")
            self._output.delete("1.0", "end")
            self._output.insert("1.0", f"Error: {e}")
            self._output.configure(state="disabled")

    def _load_script(self) -> None:
        path = filedialog.askopenfilename(
            title="Load BSL Script",
            filetypes=[("BSL Scripts", "*.bsl"), ("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if path:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self._editor.delete("1.0", "end")
            self._editor.insert("1.0", content)

    def _clear(self) -> None:
        self._editor.delete("1.0", "end")
        self._output.configure(state="normal")
        self._output.delete("1.0", "end")
        self._output.configure(state="disabled")


# =============================================================================
# About Dialog
# =============================================================================

class AboutDialog(BaseDialog):
    """About BinModder dialog."""

    def __init__(self, parent):
        super().__init__(parent, "About BinModder", 420, 350)

    def _build_ui(self) -> None:
        tk.Label(
            self, text="BinModder",
            font=("Segoe UI", 22, "bold"),
            bg=COLORS["panel_bg"], fg=COLORS["accent"]
        ).pack(pady=(20, 4))

        tk.Label(
            self, text="Professional Binary File Modifier",
            font=FONTS["ui"], bg=COLORS["panel_bg"], fg=COLORS["hex_fg"]
        ).pack()

        tk.Label(
            self, text="Version 1.0.0",
            font=FONTS["small"], bg=COLORS["panel_bg"], fg=COLORS["offset_fg"]
        ).pack(pady=4)

        tk.Frame(self, bg=COLORS["separator"], height=1).pack(fill="x", padx=20, pady=10)

        features = [
            "IPS / UPS / BPS / Custom patch support",
            "30+ checksum algorithms",
            "AES / DES / RC4 / XOR crypto",
            "RLE / LZ77 / LZSS / zlib compression",
            "ELF / PE / ECU / EEPROM format support",
            "BSL script engine",
        ]
        for feat in features:
            tk.Label(
                self, text=f"• {feat}",
                font=FONTS["small"], bg=COLORS["panel_bg"], fg=COLORS["ascii_fg"],
                anchor="w"
            ).pack(padx=40, anchor="w")

        tk.Frame(self, bg=COLORS["separator"], height=1).pack(fill="x", padx=20, pady=10)

        tk.Label(
            self, text="Author: MSR Electronics",
            font=FONTS["small"], bg=COLORS["panel_bg"], fg=COLORS["hex_fg"]
        ).pack()

        tk.Label(
            self, text="github.com/msrelectronicss",
            font=FONTS["small"], bg=COLORS["panel_bg"], fg=COLORS["offset_fg"],
            cursor="hand2"
        ).pack(pady=2)

        _btn(self, "Close", self.destroy).pack(pady=(10, 0))
