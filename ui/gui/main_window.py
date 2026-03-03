# =============================================================================
# BinModder - Main Application Window
# =============================================================================
# The main tkinter GUI window for BinModder. Contains the hex editor panel,
# menu bar, toolbar, status bar, and coordinates between all UI components.
#
# Author: MSR Electronics
# Version: 1.0.0
# =============================================================================

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, font
from pathlib import Path
from typing import Optional, List, Dict, Any

# Internal imports
try:
    from core.binary_reader import BinaryReader
    from core.binary_writer import BinaryWriter
    from core.checksum import ChecksumEngine, ChecksumAlgorithm
    from core.search_engine import SearchEngine, Pattern
    from core.hex_engine import HexEngine, HexConfig
    from core.patch_engine import PatchEngine
    from core.crypto import CryptoEngine
    from core.compression import CompressionEngine
    from tools.hex_editor import HexEditor
    from tools.comparator import BinaryComparator
    from utils.file_utils import backup_file
    from utils.log_utils import BinModderLogger
except ImportError:
    pass  # Allow running standalone for development


# =============================================================================
# Application Constants
# =============================================================================

APP_NAME    = "BinModder"
APP_VERSION = "1.0.0"
APP_AUTHOR  = "MSR Electronics"

# Color scheme
COLORS = {
    "bg":           "#1E1E2E",   # Main background
    "panel_bg":     "#181825",   # Panel background
    "hex_bg":       "#11111B",   # Hex editor background
    "offset_fg":    "#89DCEB",   # Offset column color
    "hex_fg":       "#CDD6F4",   # Hex values color
    "ascii_fg":     "#A6E3A1",   # ASCII panel color
    "null_fg":      "#45475A",   # Null byte color
    "ff_fg":        "#F9E2AF",   # 0xFF color
    "printable_fg": "#A6E3A1",   # Printable byte color
    "control_fg":   "#F38BA8",   # Control byte color
    "high_fg":      "#89B4FA",   # High byte color
    "selection_bg": "#313244",   # Selection background
    "cursor_bg":    "#CBA6F7",   # Cursor background
    "cursor_fg":    "#1E1E2E",   # Cursor foreground
    "status_bg":    "#313244",   # Status bar background
    "status_fg":    "#CDD6F4",   # Status bar foreground
    "toolbar_bg":   "#181825",   # Toolbar background
    "menu_bg":      "#1E1E2E",   # Menu background
    "accent":       "#CBA6F7",   # Accent color
    "success":      "#A6E3A1",   # Success color
    "warning":      "#F9E2AF",   # Warning color
    "error":        "#F38BA8",   # Error color
    "separator":    "#45475A",   # Separator color
}

FONTS = {
    "hex":     ("Courier New", 11),
    "mono":    ("Courier New", 10),
    "ui":      ("Segoe UI", 10),
    "ui_bold": ("Segoe UI", 10, "bold"),
    "title":   ("Segoe UI", 12, "bold"),
    "small":   ("Segoe UI", 9),
}


# =============================================================================
# File Tab
# =============================================================================

class FileTab:
    """Represents an open file tab."""

    def __init__(
        self,
        path:   Optional[Path],
        data:   bytearray,
        label:  str = "Untitled"
    ):
        self.path     = path
        self.data     = data
        self.label    = label
        self.modified = False
        self.cursor   = 0    # Current cursor byte offset
        self.scroll   = 0    # Scroll offset
        self.selection_start: Optional[int] = None
        self.selection_end:   Optional[int] = None
        self.bookmarks: Dict[str, int] = {}
        self.history:   List[Dict]     = []
        self.redo_stack: List[Dict]    = []

    @property
    def title(self) -> str:
        """Display title for this tab."""
        name = self.path.name if self.path else self.label
        return f"{'*' if self.modified else ''}{name}"

    def mark_modified(self) -> None:
        self.modified = True

    def mark_saved(self) -> None:
        self.modified = False


# =============================================================================
# Main Application Window
# =============================================================================

class MainWindow:
    """
    BinModder main application window.

    Layout:
    ┌─────────────────────────────────────────────────┐
    │  Menu Bar                                        │
    ├─────────────────────────────────────────────────┤
    │  Toolbar (buttons + search bar)                  │
    ├──────────────────────────┬──────────────────────┤
    │  File Tabs               │                       │
    ├──────────────────────────┤  Info Panel           │
    │                          │  (byte info, fields)  │
    │  Hex Panel               │                       │
    │  (offset | hex | ascii)  ├──────────────────────┤
    │                          │  Bookmarks Panel      │
    │                          │                       │
    ├──────────────────────────┴──────────────────────┤
    │  Status Bar                                      │
    └─────────────────────────────────────────────────┘
    """

    def __init__(self):
        self.root    = tk.Tk()
        self.tabs:   List[FileTab] = []
        self.current_tab_idx: int  = -1

        self._engines = {
            "checksum":    ChecksumEngine() if 'ChecksumEngine' in dir() else None,
            "search":      SearchEngine()   if 'SearchEngine'   in dir() else None,
            "patch":       PatchEngine()    if 'PatchEngine'    in dir() else None,
            "crypto":      CryptoEngine()   if 'CryptoEngine'   in dir() else None,
            "compression": CompressionEngine() if 'CompressionEngine' in dir() else None,
        }

        self._setup_window()
        self._setup_menu()
        self._setup_toolbar()
        self._setup_main_area()
        self._setup_status_bar()
        self._bind_keys()
        self._apply_theme()

    # -------------------------------------------------------------------------
    # Window Setup
    # -------------------------------------------------------------------------

    def _setup_window(self) -> None:
        """Configure main window."""
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("1400x900")
        self.root.minsize(800, 600)
        self.root.configure(bg=COLORS["bg"])

        # Center window
        self.root.update_idletasks()
        w = self.root.winfo_screenwidth()
        h = self.root.winfo_screenheight()
        x = (w - 1400) // 2
        y = (h - 900) // 2
        self.root.geometry(f"1400x900+{x}+{y}")

        # Window close handler
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # Application icon (if available)
        try:
            icon_path = Path(__file__).parent.parent.parent / "assets" / "icons" / "binmodder.ico"
            if icon_path.exists():
                self.root.iconbitmap(str(icon_path))
        except Exception:
            pass

    def _setup_menu(self) -> None:
        """Create menu bar."""
        self.menubar = tk.Menu(
            self.root, bg=COLORS["menu_bg"], fg=COLORS["hex_fg"],
            activebackground=COLORS["accent"], activeforeground=COLORS["bg"],
            relief="flat", borderwidth=0
        )
        self.root.configure(menu=self.menubar)

        # File menu
        file_menu = tk.Menu(self.menubar, tearoff=0, **self._menu_style())
        self.menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New File",        command=self._new_file,       accelerator="Ctrl+N")
        file_menu.add_command(label="Open...",          command=self._open_file,       accelerator="Ctrl+O")
        file_menu.add_command(label="Open Recent",      command=self._open_recent)
        file_menu.add_separator()
        file_menu.add_command(label="Save",             command=self._save_file,       accelerator="Ctrl+S")
        file_menu.add_command(label="Save As...",       command=self._save_as,         accelerator="Ctrl+Shift+S")
        file_menu.add_command(label="Save Copy...",     command=self._save_copy)
        file_menu.add_separator()
        file_menu.add_command(label="Close Tab",        command=self._close_tab,       accelerator="Ctrl+W")
        file_menu.add_command(label="Close All",        command=self._close_all)
        file_menu.add_separator()
        file_menu.add_command(label="Exit",             command=self._on_close,        accelerator="Alt+F4")

        # Edit menu
        edit_menu = tk.Menu(self.menubar, tearoff=0, **self._menu_style())
        self.menubar.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="Undo",             command=self._undo,            accelerator="Ctrl+Z")
        edit_menu.add_command(label="Redo",             command=self._redo,            accelerator="Ctrl+Y")
        edit_menu.add_separator()
        edit_menu.add_command(label="Cut",              command=self._cut,             accelerator="Ctrl+X")
        edit_menu.add_command(label="Copy",             command=self._copy,            accelerator="Ctrl+C")
        edit_menu.add_command(label="Copy as Hex",      command=self._copy_as_hex,     accelerator="Ctrl+Shift+C")
        edit_menu.add_command(label="Paste",            command=self._paste,           accelerator="Ctrl+V")
        edit_menu.add_command(label="Paste from Hex",   command=self._paste_from_hex)
        edit_menu.add_separator()
        edit_menu.add_command(label="Select All",       command=self._select_all,      accelerator="Ctrl+A")
        edit_menu.add_command(label="Select Range...",  command=self._select_range)
        edit_menu.add_separator()
        edit_menu.add_command(label="Find...",          command=self._show_find,       accelerator="Ctrl+F")
        edit_menu.add_command(label="Find Next",        command=self._find_next,       accelerator="F3")
        edit_menu.add_command(label="Find Previous",    command=self._find_prev,       accelerator="Shift+F3")
        edit_menu.add_command(label="Replace...",       command=self._show_replace,    accelerator="Ctrl+H")
        edit_menu.add_separator()
        edit_menu.add_command(label="Go to Offset...",  command=self._goto_offset,     accelerator="Ctrl+G")
        edit_menu.add_command(label="Go to End",        command=self._goto_end,        accelerator="Ctrl+End")

        # View menu
        view_menu = tk.Menu(self.menubar, tearoff=0, **self._menu_style())
        self.menubar.add_cascade(label="View", menu=view_menu)

        self._bytes_per_row = tk.IntVar(value=16)
        bpr_menu = tk.Menu(view_menu, tearoff=0, **self._menu_style())
        view_menu.add_cascade(label="Bytes per Row", menu=bpr_menu)
        for bpr in (8, 16, 32, 64):
            bpr_menu.add_radiobutton(
                label=str(bpr), variable=self._bytes_per_row,
                value=bpr, command=self._on_bpr_change
            )

        display_menu = tk.Menu(view_menu, tearoff=0, **self._menu_style())
        view_menu.add_cascade(label="Display Mode", menu=display_menu)
        self._display_mode = tk.StringVar(value="hex_ascii")
        for mode, label in [
            ("hex_ascii", "Hex + ASCII"),
            ("hex_only", "Hex Only"),
            ("ascii_only", "ASCII Only"),
            ("dwords", "32-bit DWORDs"),
            ("qwords", "64-bit QWORDs"),
        ]:
            display_menu.add_radiobutton(
                label=label, variable=self._display_mode,
                value=mode, command=self._on_display_mode_change
            )

        view_menu.add_separator()
        self._show_info_panel = tk.BooleanVar(value=True)
        view_menu.add_checkbutton(
            label="Show Info Panel",
            variable=self._show_info_panel,
            command=self._toggle_info_panel
        )
        self._show_bookmarks = tk.BooleanVar(value=True)
        view_menu.add_checkbutton(
            label="Show Bookmarks",
            variable=self._show_bookmarks,
            command=self._toggle_bookmarks
        )
        view_menu.add_separator()
        view_menu.add_command(label="Zoom In",  command=self._zoom_in,  accelerator="Ctrl++")
        view_menu.add_command(label="Zoom Out", command=self._zoom_out, accelerator="Ctrl+-")
        view_menu.add_command(label="Reset Zoom", command=self._zoom_reset)

        # Patch menu
        patch_menu = tk.Menu(self.menubar, tearoff=0, **self._menu_style())
        self.menubar.add_cascade(label="Patch", menu=patch_menu)
        patch_menu.add_command(label="Apply Patch...",    command=self._apply_patch)
        patch_menu.add_command(label="Create Patch...",   command=self._create_patch)
        patch_menu.add_separator()
        patch_menu.add_command(label="Verify Patch...",   command=self._verify_patch)
        patch_menu.add_command(label="Reverse Patch...",  command=self._reverse_patch)

        # Tools menu
        tools_menu = tk.Menu(self.menubar, tearoff=0, **self._menu_style())
        self.menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Checksums...",        command=self._show_checksums)
        tools_menu.add_command(label="Search Pattern...",   command=self._show_find)
        tools_menu.add_command(label="Compare Files...",    command=self._compare_files)
        tools_menu.add_command(label="Analyze File...",     command=self._analyze_file)
        tools_menu.add_separator()
        tools_menu.add_command(label="Encrypt/Decrypt...", command=self._show_crypto)
        tools_menu.add_command(label="Compress/Decompress...", command=self._show_compress)
        tools_menu.add_separator()
        tools_menu.add_command(label="Fill Region...",      command=self._fill_region)
        tools_menu.add_command(label="Trim File...",        command=self._trim_file)
        tools_menu.add_command(label="Append File...",      command=self._append_file)
        tools_menu.add_separator()
        tools_menu.add_command(label="Run Script...",       command=self._run_script)
        tools_menu.add_command(label="Script Editor...",    command=self._open_script_editor)

        # Help menu
        help_menu = tk.Menu(self.menubar, tearoff=0, **self._menu_style())
        self.menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation",    command=self._open_docs)
        help_menu.add_command(label="Script Reference", command=self._open_script_ref)
        help_menu.add_separator()
        help_menu.add_command(label="About BinModder", command=self._show_about)

    def _menu_style(self) -> dict:
        """Return common menu styling kwargs."""
        return {
            "bg":              COLORS["panel_bg"],
            "fg":              COLORS["hex_fg"],
            "activebackground": COLORS["accent"],
            "activeforeground": COLORS["bg"],
            "relief":          "flat",
        }

    def _setup_toolbar(self) -> None:
        """Create toolbar."""
        self.toolbar = tk.Frame(
            self.root, bg=COLORS["toolbar_bg"], height=40, relief="flat"
        )
        self.toolbar.pack(fill="x", side="top")
        self.toolbar.pack_propagate(False)

        # Toolbar buttons
        btn_style = {
            "bg": COLORS["toolbar_bg"], "fg": COLORS["hex_fg"],
            "relief": "flat", "padx": 8, "pady": 4,
            "cursor": "hand2", "font": FONTS["small"],
            "activebackground": COLORS["selection_bg"],
            "activeforeground": COLORS["accent"],
        }

        buttons = [
            ("📂 Open",    self._open_file),
            ("💾 Save",    self._save_file),
            ("|",          None),
            ("↩ Undo",     self._undo),
            ("↪ Redo",     self._redo),
            ("|",          None),
            ("🔍 Find",    self._show_find),
            ("⟳ Replace",  self._show_replace),
            ("|",          None),
            ("📋 Patch",   self._apply_patch),
            ("✓ Checksum", self._show_checksums),
            ("⚡ Analyze", self._analyze_file),
            ("|",          None),
            ("▶ Script",   self._run_script),
        ]

        for label, cmd in buttons:
            if label == "|":
                sep = tk.Frame(self.toolbar, bg=COLORS["separator"], width=1)
                sep.pack(side="left", fill="y", padx=5, pady=4)
            else:
                btn = tk.Button(self.toolbar, text=label, command=cmd, **btn_style)
                btn.pack(side="left", padx=2)

        # Search box on the right
        search_frame = tk.Frame(self.toolbar, bg=COLORS["toolbar_bg"])
        search_frame.pack(side="right", padx=10)

        self._search_var = tk.StringVar()
        search_entry = tk.Entry(
            search_frame, textvariable=self._search_var,
            width=25, font=FONTS["mono"],
            bg=COLORS["hex_bg"], fg=COLORS["hex_fg"],
            insertbackground=COLORS["accent"],
            relief="flat", bd=2
        )
        search_entry.pack(side="left", padx=4)
        search_entry.bind("<Return>", lambda e: self._quick_search())

        tk.Button(
            search_frame, text="Search",
            command=self._quick_search,
            bg=COLORS["accent"], fg=COLORS["bg"],
            relief="flat", padx=8, pady=2,
            cursor="hand2", font=FONTS["small"]
        ).pack(side="left")

    def _setup_main_area(self) -> None:
        """Setup the main editing area with panels."""
        # Main container
        self.main_pane = tk.PanedWindow(
            self.root, orient="horizontal", bg=COLORS["bg"],
            sashwidth=4, sashrelief="flat"
        )
        self.main_pane.pack(fill="both", expand=True)

        # Left side: tabs + hex editor
        left_frame = tk.Frame(self.main_pane, bg=COLORS["bg"])
        self.main_pane.add(left_frame, minsize=600)

        # Tab bar
        self.tab_bar = tk.Frame(left_frame, bg=COLORS["panel_bg"], height=32)
        self.tab_bar.pack(fill="x", side="top")
        self.tab_bar.pack_propagate(False)

        # New tab button
        tk.Button(
            self.tab_bar, text="+",
            command=self._new_file,
            bg=COLORS["panel_bg"], fg=COLORS["accent"],
            relief="flat", font=("Segoe UI", 14),
            cursor="hand2", padx=8
        ).pack(side="right")

        self._tab_buttons_frame = tk.Frame(self.tab_bar, bg=COLORS["panel_bg"])
        self._tab_buttons_frame.pack(side="left", fill="both", expand=True)

        # Hex editor area
        self.hex_frame = tk.Frame(left_frame, bg=COLORS["hex_bg"])
        self.hex_frame.pack(fill="both", expand=True)

        self._setup_hex_editor()

        # Right side: info panel
        right_frame = tk.Frame(self.main_pane, bg=COLORS["panel_bg"])
        self.main_pane.add(right_frame, minsize=250)

        self._setup_info_panel(right_frame)

    def _setup_hex_editor(self) -> None:
        """Setup the hex editor text widget."""
        # Hex editor is a Text widget with custom tag styling
        self.hex_text = tk.Text(
            self.hex_frame,
            font=FONTS["hex"],
            bg=COLORS["hex_bg"],
            fg=COLORS["hex_fg"],
            insertbackground=COLORS["cursor_bg"],
            selectbackground=COLORS["selection_bg"],
            selectforeground=COLORS["hex_fg"],
            relief="flat",
            bd=0,
            wrap="none",
            state="disabled",
            cursor="arrow",
        )

        # Scrollbars
        v_scroll = tk.Scrollbar(self.hex_frame, orient="vertical",
                                command=self.hex_text.yview)
        h_scroll = tk.Scrollbar(self.hex_frame, orient="horizontal",
                                command=self.hex_text.xview)

        self.hex_text.configure(
            yscrollcommand=v_scroll.set,
            xscrollcommand=h_scroll.set
        )

        h_scroll.pack(side="bottom", fill="x")
        v_scroll.pack(side="right",  fill="y")
        self.hex_text.pack(fill="both", expand=True)

        # Configure text tags
        self._configure_hex_tags()

        # Bind events
        self.hex_text.bind("<Button-1>",   self._on_hex_click)
        self.hex_text.bind("<B1-Motion>",  self._on_hex_drag)
        self.hex_text.bind("<Key>",        self._on_hex_key)
        self.hex_text.bind("<MouseWheel>", self._on_scroll)

    def _configure_hex_tags(self) -> None:
        """Configure syntax-highlighting tags for hex display."""
        self.hex_text.tag_configure("offset",    foreground=COLORS["offset_fg"], font=FONTS["hex"])
        self.hex_text.tag_configure("hex_null",  foreground=COLORS["null_fg"])
        self.hex_text.tag_configure("hex_ff",    foreground=COLORS["ff_fg"])
        self.hex_text.tag_configure("hex_print", foreground=COLORS["printable_fg"])
        self.hex_text.tag_configure("hex_ctrl",  foreground=COLORS["control_fg"])
        self.hex_text.tag_configure("hex_high",  foreground=COLORS["high_fg"])
        self.hex_text.tag_configure("ascii",     foreground=COLORS["ascii_fg"])
        self.hex_text.tag_configure("selection", background=COLORS["selection_bg"])
        self.hex_text.tag_configure("cursor",    background=COLORS["cursor_bg"],
                                                 foreground=COLORS["cursor_fg"])
        self.hex_text.tag_configure("highlight", background=COLORS["warning"],
                                                 foreground=COLORS["bg"])
        self.hex_text.tag_configure("separator", foreground=COLORS["separator_color"
                                                               if "separator_color" in COLORS
                                                               else "separator"])

    def _setup_info_panel(self, parent: tk.Frame) -> None:
        """Setup the right info panel."""
        # Info notebook
        info_notebook = ttk.Notebook(parent)
        info_notebook.pack(fill="both", expand=True, padx=4, pady=4)

        # Byte Info tab
        byte_frame = tk.Frame(info_notebook, bg=COLORS["panel_bg"])
        info_notebook.add(byte_frame, text="Byte Info")
        self._setup_byte_info(byte_frame)

        # Bookmarks tab
        bm_frame = tk.Frame(info_notebook, bg=COLORS["panel_bg"])
        info_notebook.add(bm_frame, text="Bookmarks")
        self._setup_bookmarks_panel(bm_frame)

        # Structure tab
        struct_frame = tk.Frame(info_notebook, bg=COLORS["panel_bg"])
        info_notebook.add(struct_frame, text="Structure")
        self._setup_structure_panel(struct_frame)

    def _setup_byte_info(self, parent: tk.Frame) -> None:
        """Byte info panel showing current byte in various formats."""
        tk.Label(
            parent, text="Current Byte", font=FONTS["ui_bold"],
            bg=COLORS["panel_bg"], fg=COLORS["accent"]
        ).pack(pady=(8, 4))

        self._byte_info_vars = {}
        fields = [
            ("Offset (hex)",  "offset_hex"),
            ("Offset (dec)",  "offset_dec"),
            ("Value (hex)",   "val_hex"),
            ("Value (dec)",   "val_dec"),
            ("Value (bin)",   "val_bin"),
            ("Value (oct)",   "val_oct"),
            ("uint8",         "uint8"),
            ("int8",          "int8"),
            ("uint16 LE",     "u16_le"),
            ("uint16 BE",     "u16_be"),
            ("uint32 LE",     "u32_le"),
            ("uint32 BE",     "u32_be"),
            ("uint64 LE",     "u64_le"),
            ("float32 LE",    "f32_le"),
            ("float64 LE",    "f64_le"),
            ("ASCII",         "ascii"),
        ]

        frame = tk.Frame(parent, bg=COLORS["panel_bg"])
        frame.pack(fill="x", padx=8, pady=4)

        for label, key in fields:
            row = tk.Frame(frame, bg=COLORS["panel_bg"])
            row.pack(fill="x", pady=1)

            tk.Label(
                row, text=f"{label}:", width=14, anchor="w",
                font=FONTS["small"], bg=COLORS["panel_bg"], fg=COLORS["hex_fg"]
            ).pack(side="left")

            var = tk.StringVar(value="--")
            self._byte_info_vars[key] = var
            tk.Label(
                row, textvariable=var, anchor="e",
                font=FONTS["mono"], bg=COLORS["panel_bg"], fg=COLORS["printable_fg"]
            ).pack(side="right", fill="x", expand=True)

    def _setup_bookmarks_panel(self, parent: tk.Frame) -> None:
        """Bookmarks panel."""
        ctrl_frame = tk.Frame(parent, bg=COLORS["panel_bg"])
        ctrl_frame.pack(fill="x", padx=4, pady=4)

        tk.Button(
            ctrl_frame, text="Add Bookmark",
            command=self._add_bookmark,
            bg=COLORS["accent"], fg=COLORS["bg"],
            relief="flat", padx=6, pady=2, font=FONTS["small"]
        ).pack(side="left", padx=2)

        tk.Button(
            ctrl_frame, text="Remove",
            command=self._remove_bookmark,
            bg=COLORS["error"], fg=COLORS["bg"],
            relief="flat", padx=6, pady=2, font=FONTS["small"]
        ).pack(side="left", padx=2)

        # Bookmarks listbox
        self.bm_listbox = tk.Listbox(
            parent,
            bg=COLORS["hex_bg"], fg=COLORS["hex_fg"],
            selectbackground=COLORS["selection_bg"],
            font=FONTS["mono"], relief="flat", bd=0
        )
        self.bm_listbox.pack(fill="both", expand=True, padx=4, pady=4)
        self.bm_listbox.bind("<Double-Button-1>", self._goto_bookmark)

    def _setup_structure_panel(self, parent: tk.Frame) -> None:
        """Structure/template panel."""
        ctrl_frame = tk.Frame(parent, bg=COLORS["panel_bg"])
        ctrl_frame.pack(fill="x", padx=4, pady=4)

        tk.Button(
            ctrl_frame, text="Load Template",
            command=self._load_template,
            bg=COLORS["accent"], fg=COLORS["bg"],
            relief="flat", padx=6, pady=2, font=FONTS["small"]
        ).pack(side="left")

        self.struct_tree = ttk.Treeview(
            parent,
            columns=("offset", "value"),
            show="tree headings"
        )
        self.struct_tree.heading("#0",     text="Field")
        self.struct_tree.heading("offset", text="Offset")
        self.struct_tree.heading("value",  text="Value")
        self.struct_tree.column("#0",     width=120)
        self.struct_tree.column("offset", width=80)
        self.struct_tree.column("value",  width=100)
        self.struct_tree.pack(fill="both", expand=True, padx=4, pady=4)

    def _setup_status_bar(self) -> None:
        """Create status bar."""
        self.status_bar = tk.Frame(
            self.root, bg=COLORS["status_bg"], height=24, relief="flat"
        )
        self.status_bar.pack(fill="x", side="bottom")
        self.status_bar.pack_propagate(False)

        # Status sections
        self._status_vars = {}
        sections = [
            ("main",     30),
            ("offset",   20),
            ("size",     15),
            ("selection", 20),
            ("modified",  8),
        ]

        for key, width in sections:
            var = tk.StringVar()
            self._status_vars[key] = var
            label = tk.Label(
                self.status_bar, textvariable=var, anchor="w",
                width=width, font=FONTS["small"],
                bg=COLORS["status_bg"], fg=COLORS["status_fg"],
                padx=8
            )
            label.pack(side="left")

            # Separator
            if key != sections[-1][0]:
                tk.Frame(
                    self.status_bar, bg=COLORS["separator"], width=1
                ).pack(side="left", fill="y", pady=2)

        self._set_status("Ready")

    # -------------------------------------------------------------------------
    # Theme
    # -------------------------------------------------------------------------

    def _apply_theme(self) -> None:
        """Apply dark theme to ttk widgets."""
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("TNotebook",
                        background=COLORS["panel_bg"], borderwidth=0)
        style.configure("TNotebook.Tab",
                        background=COLORS["panel_bg"],
                        foreground=COLORS["hex_fg"],
                        padding=(10, 4))
        style.map("TNotebook.Tab",
                  background=[("selected", COLORS["bg"])],
                  foreground=[("selected", COLORS["accent"])])

        style.configure("Treeview",
                        background=COLORS["hex_bg"],
                        foreground=COLORS["hex_fg"],
                        fieldbackground=COLORS["hex_bg"])
        style.configure("Treeview.Heading",
                        background=COLORS["panel_bg"],
                        foreground=COLORS["offset_fg"])

    # -------------------------------------------------------------------------
    # Key Bindings
    # -------------------------------------------------------------------------

    def _bind_keys(self) -> None:
        """Bind keyboard shortcuts."""
        root = self.root
        root.bind("<Control-n>",       lambda e: self._new_file())
        root.bind("<Control-o>",       lambda e: self._open_file())
        root.bind("<Control-s>",       lambda e: self._save_file())
        root.bind("<Control-S>",       lambda e: self._save_as())
        root.bind("<Control-w>",       lambda e: self._close_tab())
        root.bind("<Control-z>",       lambda e: self._undo())
        root.bind("<Control-y>",       lambda e: self._redo())
        root.bind("<Control-f>",       lambda e: self._show_find())
        root.bind("<Control-h>",       lambda e: self._show_replace())
        root.bind("<Control-g>",       lambda e: self._goto_offset())
        root.bind("<Control-a>",       lambda e: self._select_all())
        root.bind("<Control-c>",       lambda e: self._copy())
        root.bind("<Control-v>",       lambda e: self._paste())
        root.bind("<Control-x>",       lambda e: self._cut())
        root.bind("<F3>",              lambda e: self._find_next())
        root.bind("<Shift-F3>",        lambda e: self._find_prev())
        root.bind("<Control-End>",     lambda e: self._goto_end())
        root.bind("<Control-Home>",    lambda e: self._goto_begin())
        root.bind("<Control-plus>",    lambda e: self._zoom_in())
        root.bind("<Control-minus>",   lambda e: self._zoom_out())
        root.bind("<Control-Tab>",     lambda e: self._next_tab())
        root.bind("<Control-Shift-Tab>", lambda e: self._prev_tab())

    # -------------------------------------------------------------------------
    # Hex Display
    # -------------------------------------------------------------------------

    def _render_hex(self) -> None:
        """Render the hex view for the current file tab."""
        if self.current_tab_idx < 0 or not self.tabs:
            self._clear_hex()
            return

        tab  = self.tabs[self.current_tab_idx]
        data = tab.data
        bpr  = self._bytes_per_row.get()

        self.hex_text.configure(state="normal")
        self.hex_text.delete("1.0", "end")

        for row_start in range(0, len(data), bpr):
            row_data = data[row_start:row_start + bpr]

            # Offset
            offset_str = f"{row_start:08X}  "
            self.hex_text.insert("end", offset_str, "offset")

            # Hex bytes
            for i, b in enumerate(row_data):
                if i > 0 and i % 8 == 0:
                    self.hex_text.insert("end", " ")

                hex_str = f"{b:02X} "
                tag     = self._byte_tag(b)
                self.hex_text.insert("end", hex_str, tag)

            # Pad short last row
            if len(row_data) < bpr:
                pad = bpr - len(row_data)
                gap = pad * 3 + (1 if pad > 8 else 0)
                self.hex_text.insert("end", " " * gap)

            # ASCII
            self.hex_text.insert("end", " |", "offset")
            for b in row_data:
                ch = chr(b) if 0x20 <= b <= 0x7E else "."
                self.hex_text.insert("end", ch, "ascii")
            self.hex_text.insert("end", "|\n", "offset")

        self.hex_text.configure(state="disabled")
        self._update_status()

    def _byte_tag(self, b: int) -> str:
        """Return the appropriate text tag for a byte value."""
        if b == 0x00:
            return "hex_null"
        elif b == 0xFF:
            return "hex_ff"
        elif 0x20 <= b <= 0x7E:
            return "hex_print"
        elif b < 0x20 or b == 0x7F:
            return "hex_ctrl"
        else:
            return "hex_high"

    def _clear_hex(self) -> None:
        """Clear the hex editor."""
        self.hex_text.configure(state="normal")
        self.hex_text.delete("1.0", "end")
        self.hex_text.configure(state="disabled")

    # -------------------------------------------------------------------------
    # Status Updates
    # -------------------------------------------------------------------------

    def _set_status(self, message: str) -> None:
        """Update main status bar message."""
        self._status_vars["main"].set(message)

    def _update_status(self) -> None:
        """Update all status bar sections."""
        if self.current_tab_idx < 0 or not self.tabs:
            for var in self._status_vars.values():
                var.set("")
            return

        tab = self.tabs[self.current_tab_idx]
        self._status_vars["main"].set("Ready")
        self._status_vars["offset"].set(f"Offset: 0x{tab.cursor:08X}")
        self._status_vars["size"].set(f"Size: {len(tab.data):,}")
        self._status_vars["modified"].set("MOD" if tab.modified else "")

        if tab.selection_start is not None and tab.selection_end is not None:
            sel_size = abs(tab.selection_end - tab.selection_start)
            self._status_vars["selection"].set(f"Sel: {sel_size} bytes")
        else:
            self._status_vars["selection"].set("")

        # Update byte info panel
        self._update_byte_info(tab)

    def _update_byte_info(self, tab: FileTab) -> None:
        """Update the byte info panel for the current cursor position."""
        offset = tab.cursor
        data   = tab.data

        if offset >= len(data):
            for var in self._byte_info_vars.values():
                var.set("--")
            return

        b = data[offset]

        self._byte_info_vars["offset_hex"].set(f"0x{offset:08X}")
        self._byte_info_vars["offset_dec"].set(str(offset))
        self._byte_info_vars["val_hex"].set(f"0x{b:02X}")
        self._byte_info_vars["val_dec"].set(str(b))
        self._byte_info_vars["val_bin"].set(f"{b:08b}")
        self._byte_info_vars["val_oct"].set(f"0o{b:03o}")
        self._byte_info_vars["uint8"].set(str(b))
        self._byte_info_vars["int8"].set(str(b if b < 128 else b - 256))
        self._byte_info_vars["ascii"].set(chr(b) if 0x20 <= b <= 0x7E else f"<{b:02X}>")

        # Multi-byte interpretations
        import struct
        if offset + 2 <= len(data):
            chunk = bytes(data[offset:offset + 2])
            self._byte_info_vars["u16_le"].set(str(struct.unpack_from("<H", chunk)[0]))
            self._byte_info_vars["u16_be"].set(str(struct.unpack_from(">H", chunk)[0]))

        if offset + 4 <= len(data):
            chunk = bytes(data[offset:offset + 4])
            self._byte_info_vars["u32_le"].set(f"0x{struct.unpack_from('<I', chunk)[0]:08X}")
            self._byte_info_vars["u32_be"].set(f"0x{struct.unpack_from('>I', chunk)[0]:08X}")
            self._byte_info_vars["f32_le"].set(f"{struct.unpack_from('<f', chunk)[0]:.6g}")

        if offset + 8 <= len(data):
            chunk = bytes(data[offset:offset + 8])
            self._byte_info_vars["u64_le"].set(f"0x{struct.unpack_from('<Q', chunk)[0]:016X}")
            self._byte_info_vars["f64_le"].set(f"{struct.unpack_from('<d', chunk)[0]:.10g}")

    # -------------------------------------------------------------------------
    # File Operations
    # -------------------------------------------------------------------------

    def _new_file(self) -> None:
        """Create a new empty file tab."""
        tab = FileTab(path=None, data=bytearray(), label=f"Untitled {len(self.tabs) + 1}")
        self.tabs.append(tab)
        self._activate_tab(len(self.tabs) - 1)
        self._refresh_tab_bar()
        self._set_status("New file created")

    def _open_file(self) -> None:
        """Open a file dialog and load a binary file."""
        path = filedialog.askopenfilename(
            title="Open Binary File",
            filetypes=[
                ("Binary Files", "*.bin *.rom *.hex *.elf *.exe *.dll *.fw *.img"),
                ("All Files", "*.*"),
            ]
        )
        if not path:
            return

        self._load_file(Path(path))

    def _load_file(self, path: Path) -> None:
        """Load a file into a new tab."""
        try:
            with open(path, "rb") as f:
                data = bytearray(f.read())

            tab = FileTab(path=path, data=data, label=path.name)
            self.tabs.append(tab)
            self._activate_tab(len(self.tabs) - 1)
            self._refresh_tab_bar()
            self._set_status(f"Opened: {path.name} ({len(data):,} bytes)")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to open file:\n{e}")

    def _save_file(self) -> None:
        """Save current tab to its file."""
        if self.current_tab_idx < 0 or not self.tabs:
            return

        tab = self.tabs[self.current_tab_idx]
        if tab.path is None:
            self._save_as()
            return

        try:
            with open(tab.path, "wb") as f:
                f.write(tab.data)
            tab.mark_saved()
            self._refresh_tab_bar()
            self._set_status(f"Saved: {tab.path.name}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save:\n{e}")

    def _save_as(self) -> None:
        """Save current tab to a new file."""
        if self.current_tab_idx < 0 or not self.tabs:
            return

        path = filedialog.asksaveasfilename(
            title="Save As",
            defaultextension=".bin",
            filetypes=[("Binary Files", "*.bin"), ("All Files", "*.*")],
        )
        if not path:
            return

        tab = self.tabs[self.current_tab_idx]
        try:
            with open(path, "wb") as f:
                f.write(tab.data)
            tab.path = Path(path)
            tab.label = tab.path.name
            tab.mark_saved()
            self._refresh_tab_bar()
            self._set_status(f"Saved as: {tab.path.name}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save:\n{e}")

    def _save_copy(self) -> None:
        """Save a copy without changing the current file's path."""
        if self.current_tab_idx < 0:
            return
        path = filedialog.asksaveasfilename(
            title="Save Copy",
            defaultextension=".bin",
            filetypes=[("Binary Files", "*.bin"), ("All Files", "*.*")],
        )
        if path:
            tab = self.tabs[self.current_tab_idx]
            try:
                with open(path, "wb") as f:
                    f.write(tab.data)
                self._set_status(f"Saved copy: {Path(path).name}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save copy:\n{e}")

    def _open_recent(self) -> None:
        """Show recently opened files."""
        messagebox.showinfo("Recent Files", "Recent files feature coming soon.")

    # -------------------------------------------------------------------------
    # Tab Management
    # -------------------------------------------------------------------------

    def _activate_tab(self, idx: int) -> None:
        """Switch to the specified tab."""
        if 0 <= idx < len(self.tabs):
            self.current_tab_idx = idx
            self._render_hex()
            self._update_status()

    def _close_tab(self) -> None:
        """Close the current tab."""
        if self.current_tab_idx < 0 or not self.tabs:
            return

        tab = self.tabs[self.current_tab_idx]
        if tab.modified:
            answer = messagebox.askyesnocancel(
                "Unsaved Changes",
                f"{tab.label} has unsaved changes. Save before closing?"
            )
            if answer is None:
                return
            if answer:
                self._save_file()

        self.tabs.pop(self.current_tab_idx)
        if self.tabs:
            self.current_tab_idx = max(0, self.current_tab_idx - 1)
        else:
            self.current_tab_idx = -1

        self._refresh_tab_bar()
        self._render_hex()

    def _close_all(self) -> None:
        """Close all tabs."""
        while self.tabs:
            self._close_tab()

    def _refresh_tab_bar(self) -> None:
        """Rebuild the tab buttons."""
        for widget in self._tab_buttons_frame.winfo_children():
            widget.destroy()

        for i, tab in enumerate(self.tabs):
            is_active = (i == self.current_tab_idx)
            btn = tk.Button(
                self._tab_buttons_frame,
                text=f"  {tab.title}  ",
                command=lambda idx=i: self._activate_tab(idx),
                bg=COLORS["bg"] if is_active else COLORS["panel_bg"],
                fg=COLORS["accent"] if is_active else COLORS["hex_fg"],
                relief="flat", bd=0, padx=4, pady=4,
                font=FONTS["small"], cursor="hand2",
            )
            btn.pack(side="left")

    def _next_tab(self) -> None:
        if self.tabs:
            self._activate_tab((self.current_tab_idx + 1) % len(self.tabs))

    def _prev_tab(self) -> None:
        if self.tabs:
            self._activate_tab((self.current_tab_idx - 1) % len(self.tabs))

    # -------------------------------------------------------------------------
    # Edit Operations
    # -------------------------------------------------------------------------

    def _undo(self) -> None:
        self._set_status("Undo")

    def _redo(self) -> None:
        self._set_status("Redo")

    def _cut(self) -> None:
        self._copy()

    def _copy(self) -> None:
        if self.current_tab_idx < 0:
            return
        tab = self.tabs[self.current_tab_idx]
        if tab.selection_start is not None and tab.selection_end is not None:
            start = min(tab.selection_start, tab.selection_end)
            end   = max(tab.selection_start, tab.selection_end)
            data  = bytes(tab.data[start:end])
            self.root.clipboard_clear()
            self.root.clipboard_append(data.decode("latin-1"))

    def _copy_as_hex(self) -> None:
        if self.current_tab_idx < 0:
            return
        tab = self.tabs[self.current_tab_idx]
        if tab.selection_start is not None and tab.selection_end is not None:
            start = min(tab.selection_start, tab.selection_end)
            end   = max(tab.selection_start, tab.selection_end)
            data  = bytes(tab.data[start:end])
            hex_str = " ".join(f"{b:02X}" for b in data)
            self.root.clipboard_clear()
            self.root.clipboard_append(hex_str)
            self._set_status(f"Copied {len(data)} bytes as hex")

    def _paste(self) -> None:
        self._set_status("Paste")

    def _paste_from_hex(self) -> None:
        self._set_status("Paste from hex")

    def _select_all(self) -> None:
        if self.current_tab_idx < 0:
            return
        tab = self.tabs[self.current_tab_idx]
        tab.selection_start = 0
        tab.selection_end   = len(tab.data)
        self._update_status()

    def _select_range(self) -> None:
        self._set_status("Select range")

    # -------------------------------------------------------------------------
    # Navigation
    # -------------------------------------------------------------------------

    def _goto_offset(self) -> None:
        """Show go-to offset dialog."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Go to Offset")
        dialog.geometry("300x120")
        dialog.configure(bg=COLORS["panel_bg"])
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(
            dialog, text="Enter offset (hex or decimal):",
            bg=COLORS["panel_bg"], fg=COLORS["hex_fg"], font=FONTS["ui"]
        ).pack(pady=10)

        entry_var = tk.StringVar()
        entry = tk.Entry(
            dialog, textvariable=entry_var, font=FONTS["mono"],
            bg=COLORS["hex_bg"], fg=COLORS["hex_fg"],
            insertbackground=COLORS["accent"], relief="flat", bd=4, width=20
        )
        entry.pack()
        entry.focus_set()

        def go():
            text = entry_var.get().strip()
            try:
                offset = int(text, 0)  # Handles hex (0x prefix) and decimal
                if self.current_tab_idx >= 0 and self.tabs:
                    tab = self.tabs[self.current_tab_idx]
                    if 0 <= offset < len(tab.data):
                        tab.cursor = offset
                        self._update_status()
                        dialog.destroy()
                    else:
                        messagebox.showerror(
                            "Error",
                            f"Offset 0x{offset:X} is out of bounds (file size: {len(tab.data)})"
                        )
            except ValueError:
                messagebox.showerror("Error", f"Invalid offset: {text!r}")

        tk.Button(
            dialog, text="Go",
            command=go,
            bg=COLORS["accent"], fg=COLORS["bg"],
            relief="flat", padx=20, pady=4, font=FONTS["ui"]
        ).pack(pady=8)

        entry.bind("<Return>", lambda e: go())

    def _goto_end(self) -> None:
        if self.current_tab_idx >= 0 and self.tabs:
            tab = self.tabs[self.current_tab_idx]
            tab.cursor = max(0, len(tab.data) - 1)
            self._update_status()

    def _goto_begin(self) -> None:
        if self.current_tab_idx >= 0 and self.tabs:
            tab = self.tabs[self.current_tab_idx]
            tab.cursor = 0
            self._update_status()

    # -------------------------------------------------------------------------
    # Find / Replace
    # -------------------------------------------------------------------------

    def _show_find(self) -> None:
        """Show find dialog."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Find Pattern")
        dialog.geometry("400x180")
        dialog.configure(bg=COLORS["panel_bg"])
        dialog.transient(self.root)

        tk.Label(
            dialog, text="Hex Pattern (e.g., FF ?? 00 AB):",
            bg=COLORS["panel_bg"], fg=COLORS["hex_fg"], font=FONTS["ui"]
        ).pack(pady=8, padx=10, anchor="w")

        pattern_var = tk.StringVar()
        entry = tk.Entry(
            dialog, textvariable=pattern_var, font=FONTS["mono"],
            bg=COLORS["hex_bg"], fg=COLORS["hex_fg"],
            insertbackground=COLORS["accent"], relief="flat", bd=4, width=40
        )
        entry.pack(padx=10)
        entry.focus_set()

        result_var = tk.StringVar()
        tk.Label(
            dialog, textvariable=result_var,
            bg=COLORS["panel_bg"], fg=COLORS["accent"], font=FONTS["small"]
        ).pack(pady=4)

        def do_find():
            if self.current_tab_idx < 0:
                return
            pat = pattern_var.get().strip()
            tab = self.tabs[self.current_tab_idx]
            try:
                engine  = SearchEngine()
                results = engine.find(bytes(tab.data), pat)
                result_var.set(f"Found {results.count} occurrence(s)")
                if results.count > 0:
                    tab.cursor = results.first.offset
                    self._update_status()
            except Exception as e:
                result_var.set(f"Error: {e}")

        btn_frame = tk.Frame(dialog, bg=COLORS["panel_bg"])
        btn_frame.pack(pady=8)

        tk.Button(
            btn_frame, text="Find All", command=do_find,
            bg=COLORS["accent"], fg=COLORS["bg"],
            relief="flat", padx=12, pady=4
        ).pack(side="left", padx=4)

        tk.Button(
            btn_frame, text="Close", command=dialog.destroy,
            bg=COLORS["panel_bg"], fg=COLORS["hex_fg"],
            relief="flat", padx=12, pady=4
        ).pack(side="left", padx=4)

        entry.bind("<Return>", lambda e: do_find())

    def _quick_search(self) -> None:
        """Quick search from toolbar search box."""
        pattern = self._search_var.get().strip()
        if not pattern or self.current_tab_idx < 0:
            return
        tab = self.tabs[self.current_tab_idx]
        try:
            engine  = SearchEngine()
            results = engine.find(bytes(tab.data), pattern)
            if results.first:
                tab.cursor = results.first.offset
                self._update_status()
                self._set_status(f"Found {results.count} match(es)")
            else:
                self._set_status("Pattern not found")
        except Exception as e:
            self._set_status(f"Search error: {e}")

    def _show_replace(self) -> None:
        messagebox.showinfo("Replace", "Replace dialog - feature coming soon")

    def _find_next(self) -> None:
        self._set_status("Find next")

    def _find_prev(self) -> None:
        self._set_status("Find previous")

    # -------------------------------------------------------------------------
    # View Controls
    # -------------------------------------------------------------------------

    def _on_bpr_change(self) -> None:
        self._render_hex()

    def _on_display_mode_change(self) -> None:
        self._render_hex()

    def _toggle_info_panel(self) -> None:
        pass

    def _toggle_bookmarks(self) -> None:
        pass

    def _zoom_in(self) -> None:
        size = FONTS["hex"][1] + 1
        FONTS["hex"] = (FONTS["hex"][0], size)
        self.hex_text.configure(font=FONTS["hex"])

    def _zoom_out(self) -> None:
        size = max(8, FONTS["hex"][1] - 1)
        FONTS["hex"] = (FONTS["hex"][0], size)
        self.hex_text.configure(font=FONTS["hex"])

    def _zoom_reset(self) -> None:
        FONTS["hex"] = ("Courier New", 11)
        self.hex_text.configure(font=FONTS["hex"])

    # -------------------------------------------------------------------------
    # Event Handlers
    # -------------------------------------------------------------------------

    def _on_hex_click(self, event) -> None:
        pass

    def _on_hex_drag(self, event) -> None:
        pass

    def _on_hex_key(self, event) -> None:
        pass

    def _on_scroll(self, event) -> None:
        pass

    # -------------------------------------------------------------------------
    # Patch Operations
    # -------------------------------------------------------------------------

    def _apply_patch(self) -> None:
        """Apply a patch file to the current file."""
        if self.current_tab_idx < 0:
            messagebox.showwarning("No File", "Please open a file first.")
            return

        path = filedialog.askopenfilename(
            title="Select Patch File",
            filetypes=[
                ("Patch Files", "*.ips *.ups *.bps *.json"),
                ("IPS Patches", "*.ips"),
                ("UPS Patches", "*.ups"),
                ("BPS Patches", "*.bps"),
                ("Custom Patches", "*.json"),
                ("All Files", "*.*"),
            ]
        )
        if not path:
            return

        tab = self.tabs[self.current_tab_idx]
        try:
            engine = PatchEngine()
            result = engine.apply_auto(
                source_path=tab.path,
                patch_path=path,
            )
            tab.data = bytearray(result)
            tab.mark_modified()
            self._render_hex()
            self._set_status(f"Patch applied: {Path(path).name}")
        except Exception as e:
            messagebox.showerror("Patch Error", f"Failed to apply patch:\n{e}")

    def _create_patch(self) -> None:
        messagebox.showinfo("Create Patch", "Create patch feature - coming soon")

    def _verify_patch(self) -> None:
        messagebox.showinfo("Verify Patch", "Verify patch feature - coming soon")

    def _reverse_patch(self) -> None:
        messagebox.showinfo("Reverse Patch", "Reverse patch feature - coming soon")

    # -------------------------------------------------------------------------
    # Tools
    # -------------------------------------------------------------------------

    def _show_checksums(self) -> None:
        """Show checksum calculator dialog."""
        if self.current_tab_idx < 0:
            messagebox.showwarning("No File", "Please open a file first.")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Checksum Calculator")
        dialog.geometry("500x500")
        dialog.configure(bg=COLORS["panel_bg"])
        dialog.transient(self.root)

        tk.Label(
            dialog, text="Checksums",
            font=FONTS["title"], bg=COLORS["panel_bg"], fg=COLORS["accent"]
        ).pack(pady=10)

        frame = tk.Frame(dialog, bg=COLORS["panel_bg"])
        frame.pack(fill="both", expand=True, padx=10)

        tab  = self.tabs[self.current_tab_idx]
        data = bytes(tab.data)

        algorithms = [
            ("CRC-8",       ChecksumAlgorithm.CRC8),
            ("CRC-16",      ChecksumAlgorithm.CRC16),
            ("CRC-16/CCITT",ChecksumAlgorithm.CRC16_CCITT),
            ("CRC-16/MODBUS",ChecksumAlgorithm.CRC16_MODBUS),
            ("CRC-32",      ChecksumAlgorithm.CRC32),
            ("Adler-32",    ChecksumAlgorithm.ADLER32),
            ("Fletcher-16", ChecksumAlgorithm.FLETCHER16),
            ("MD5",         ChecksumAlgorithm.MD5),
            ("SHA-1",       ChecksumAlgorithm.SHA1),
            ("SHA-256",     ChecksumAlgorithm.SHA256),
            ("XOR Sum",     ChecksumAlgorithm.XSUM),
            ("Sum-8",       ChecksumAlgorithm.SUM8),
            ("Sum-32",      ChecksumAlgorithm.SUM32),
        ]

        engine = ChecksumEngine()

        listbox = tk.Listbox(
            frame, bg=COLORS["hex_bg"], fg=COLORS["hex_fg"],
            font=FONTS["mono"], relief="flat", bd=0, width=60
        )
        listbox.pack(fill="both", expand=True)

        for name, algo in algorithms:
            try:
                result = engine.compute(algo, data)
                listbox.insert("end", f"{name:<20} {result.as_hex}")
            except Exception as e:
                listbox.insert("end", f"{name:<20} Error: {e}")

        tk.Button(
            dialog, text="Close", command=dialog.destroy,
            bg=COLORS["accent"], fg=COLORS["bg"],
            relief="flat", padx=20, pady=6
        ).pack(pady=10)

    def _compare_files(self) -> None:
        messagebox.showinfo("Compare Files", "File comparison - coming soon")

    def _analyze_file(self) -> None:
        if self.current_tab_idx < 0:
            messagebox.showwarning("No File", "Please open a file first.")
            return

        tab = self.tabs[self.current_tab_idx]
        data = bytes(tab.data)

        # Simple analysis dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("File Analysis")
        dialog.geometry("400x350")
        dialog.configure(bg=COLORS["panel_bg"])
        dialog.transient(self.root)

        text = tk.Text(
            dialog, bg=COLORS["hex_bg"], fg=COLORS["hex_fg"],
            font=FONTS["mono"], relief="flat", bd=4
        )
        text.pack(fill="both", expand=True, padx=10, pady=10)

        import math

        freq    = [0] * 256
        for b in data:
            freq[b] += 1

        total     = len(data)
        null_count = freq[0]
        ff_count  = freq[255]
        printable = sum(freq[i] for i in range(0x20, 0x7F))

        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)

        info = f"""File Analysis: {tab.label}
{'=' * 40}
Size:         {total:,} bytes ({total / 1024:.1f} KB)
Null bytes:   {null_count:,} ({null_count/total*100:.1f}%)
0xFF bytes:   {ff_count:,} ({ff_count/total*100:.1f}%)
Printable:    {printable:,} ({printable/total*100:.1f}%)
Shannon Entropy: {entropy:.4f} bits/byte

Most common bytes:
"""
        top_bytes = sorted(range(256), key=lambda i: freq[i], reverse=True)[:10]
        for b in top_bytes:
            info += f"  0x{b:02X} ({b:3d}): {freq[b]:6,} occurrences\n"

        text.insert("1.0", info)
        text.configure(state="disabled")

    def _show_crypto(self) -> None:
        messagebox.showinfo("Crypto", "Crypto dialog - coming soon")

    def _show_compress(self) -> None:
        messagebox.showinfo("Compress", "Compression dialog - coming soon")

    def _fill_region(self) -> None:
        messagebox.showinfo("Fill", "Fill region - coming soon")

    def _trim_file(self) -> None:
        messagebox.showinfo("Trim", "Trim file - coming soon")

    def _append_file(self) -> None:
        messagebox.showinfo("Append", "Append file - coming soon")

    def _run_script(self) -> None:
        messagebox.showinfo("Script", "Script runner - coming soon")

    def _open_script_editor(self) -> None:
        messagebox.showinfo("Script Editor", "Script editor - coming soon")

    # -------------------------------------------------------------------------
    # Bookmarks
    # -------------------------------------------------------------------------

    def _add_bookmark(self) -> None:
        if self.current_tab_idx < 0:
            return
        tab    = self.tabs[self.current_tab_idx]
        offset = tab.cursor
        name   = f"BM_{offset:08X}"
        tab.bookmarks[name] = offset
        self.bm_listbox.insert("end", f"{name}: 0x{offset:08X}")
        self._set_status(f"Bookmark added: {name}")

    def _remove_bookmark(self) -> None:
        sel = self.bm_listbox.curselection()
        if sel:
            self.bm_listbox.delete(sel[0])

    def _goto_bookmark(self, event) -> None:
        sel = self.bm_listbox.curselection()
        if not sel or self.current_tab_idx < 0:
            return
        item = self.bm_listbox.get(sel[0])
        # Parse offset from "BM_XXXXXXXX: 0xYYYYYYYY"
        try:
            offset = int(item.split("0x")[1], 16)
            tab = self.tabs[self.current_tab_idx]
            tab.cursor = offset
            self._update_status()
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Template
    # -------------------------------------------------------------------------

    def _load_template(self) -> None:
        messagebox.showinfo("Template", "Template loading - coming soon")

    # -------------------------------------------------------------------------
    # Help
    # -------------------------------------------------------------------------

    def _open_docs(self) -> None:
        import webbrowser
        webbrowser.open("https://github.com/msrelectronicss/app-modd-damos/wiki")

    def _open_script_ref(self) -> None:
        messagebox.showinfo("Script Reference", "BSL Script Language Reference - coming soon")

    def _show_about(self) -> None:
        messagebox.showinfo(
            f"About {APP_NAME}",
            f"{APP_NAME} v{APP_VERSION}\n\n"
            f"Professional Binary File Modifier\n\n"
            f"Author: {APP_AUTHOR}\n\n"
            f"Supports: IPS, UPS, BPS patches\n"
            f"         ELF, PE, ECU, EEPROM formats\n"
            f"         30+ checksum algorithms\n"
            f"         XOR, AES, DES, RC4, Blowfish"
        )

    # -------------------------------------------------------------------------
    # Window Close
    # -------------------------------------------------------------------------

    def _on_close(self) -> None:
        """Handle window close event."""
        modified_tabs = [t for t in self.tabs if t.modified]
        if modified_tabs:
            answer = messagebox.askyesnocancel(
                "Unsaved Changes",
                f"{len(modified_tabs)} file(s) have unsaved changes. Save before exiting?"
            )
            if answer is None:
                return
            if answer:
                for i, tab in enumerate(self.tabs):
                    if tab.modified:
                        self._activate_tab(i)
                        self._save_file()

        self.root.destroy()

    # -------------------------------------------------------------------------
    # Run
    # -------------------------------------------------------------------------

    def run(self) -> None:
        """Start the GUI event loop."""
        self.root.mainloop()


# =============================================================================
# Entry Point
# =============================================================================

def launch_gui(files: Optional[List[str]] = None) -> None:
    """Launch the BinModder GUI."""
    app = MainWindow()

    # Open files passed as arguments
    if files:
        for path in files:
            try:
                app._load_file(Path(path))
            except Exception as e:
                print(f"Failed to open {path}: {e}")

    app.run()


if __name__ == "__main__":
    launch_gui()
