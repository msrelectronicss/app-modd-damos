# =============================================================================
# MSR Electronics – ECU Tuning Panel
# =============================================================================
# Professional automotive ECU tuning panel for the BinModder GUI.
# Features:
#   • ECU Auto-Detection  (VIN / SW / HW)
#   • Stage 1 / 2 / 3    (boost, fuel, ignition, torque, limiters)
#   • Pops & Bang         (overrun crackle, 4 intensity levels)
#   • Anulaciones         (EGR, DPF, Lambda, Speed, AdBlue …)
#   • ME7.5 Patches       (Launch Control, Multi-Map, KFZW swap)
#   • Live operation log
# =============================================================================

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Callable, List, Optional

try:
    from formats.ecu_profiles import (
        Cancellation, ECUProfile, PopsBangLevel, StageLevel, get_profile
    )
    from core.ecu_info    import ECUInfoExtractor, ECUReport
    from core.tune_engine import TuneEngine
    from core.pops_bang   import PopsBangEngine
    from core.anulaciones  import AnulacionEngine
    _TUNING_AVAILABLE = True
except ImportError:
    _TUNING_AVAILABLE = False


# ---------------------------------------------------------------------------
# Design tokens  (Catppuccin Mocha palette + MSR accents)
# ---------------------------------------------------------------------------
BG       = "#0D0D14"   # near-black
PANEL    = "#13131F"   # card background
BORDER   = "#2A2A40"   # border / separator
FG       = "#CDD6F4"   # primary text
FG_DIM   = "#6C7086"   # dimmed / label text
ACCENT   = "#CBA6F7"   # purple accent (MSR brand)
GREEN    = "#A6E3A1"   # Stage 1 / success
YELLOW   = "#F9E2AF"   # Stage 2 / warning
RED      = "#F38BA8"   # Stage 3 / danger
BLUE     = "#89B4FA"   # info / pops
CYAN     = "#89DCEB"   # values
TEAL     = "#94E2D5"   # HW/SW info
ORANGE   = "#FAB387"   # pops medium

FONT_TITLE  = ("Segoe UI", 11, "bold")
FONT_CARD   = ("Segoe UI", 10, "bold")
FONT_BODY   = ("Segoe UI", 9)
FONT_SMALL  = ("Segoe UI", 8)
FONT_MONO   = ("Courier New", 9)
FONT_BADGE  = ("Segoe UI", 8, "bold")

# ---------------------------------------------------------------------------
# Utility widgets
# ---------------------------------------------------------------------------

def _sep(parent, color=BORDER):
    tk.Frame(parent, bg=color, height=1).pack(fill="x", pady=4)


def _card(parent, **kw) -> tk.Frame:
    f = tk.Frame(parent, bg=PANEL, bd=0,
                 highlightbackground=BORDER, highlightthickness=1, **kw)
    return f


def _label(parent, text, fg=FG, font=FONT_BODY, anchor="w", **kw):
    return tk.Label(parent, text=text, bg=PANEL, fg=fg, font=font,
                    anchor=anchor, **kw)


def _badge(parent, text, bg, fg=BG, font=FONT_BADGE):
    return tk.Label(parent, text=f" {text} ", bg=bg, fg=fg, font=font,
                    padx=4, pady=1)


def _flat_btn(parent, text, cmd, bg, fg=BG, font=FONT_CARD, width=0, **kw):
    btn = tk.Button(
        parent, text=text, command=cmd,
        bg=bg, fg=fg,
        activebackground=_lighten(bg), activeforeground=fg,
        relief="flat", font=font, cursor="hand2",
        width=width, **kw
    )
    btn.bind("<Enter>", lambda e: btn.configure(bg=_lighten(bg)))
    btn.bind("<Leave>", lambda e: btn.configure(bg=bg))
    return btn


def _lighten(hex_color: str) -> str:
    """Lighten a hex color slightly for hover effect."""
    try:
        r = min(255, int(hex_color[1:3], 16) + 25)
        g = min(255, int(hex_color[3:5], 16) + 25)
        b = min(255, int(hex_color[5:7], 16) + 25)
        return f"#{r:02X}{g:02X}{b:02X}"
    except Exception:
        return hex_color


def _section_header(parent, title: str, color=ACCENT):
    row = tk.Frame(parent, bg=BG)
    row.pack(fill="x", padx=8, pady=(10, 2))
    tk.Label(row, text="▌", bg=BG, fg=color, font=("Segoe UI", 12, "bold")).pack(side="left")
    tk.Label(row, text=f" {title}", bg=BG, fg=color, font=FONT_TITLE).pack(side="left")


# =============================================================================
# TuningPanel
# =============================================================================

class TuningPanel(tk.Frame):
    """MSR Electronics ECU Tuning Panel.

    Parameters
    ----------
    parent       Parent widget.
    get_data     Callback → bytes | None  (returns current ROM bytes).
    set_data     Callback(bytes)          (pushes modified bytes back).
    width        Panel width in pixels (default 340).
    """

    def __init__(
        self,
        parent,
        get_data: Callable[[], Optional[bytes]],
        set_data: Callable[[bytes], None],
        width: int = 340,
    ) -> None:
        super().__init__(parent, bg=BG, width=width)
        self.pack_propagate(False)

        self._get_data = get_data
        self._set_data = set_data

        self._profile: Optional[ECUProfile] = None
        self._report:  Optional[ECUReport]  = None

        self._cancel_vars: dict = {}

        self._build()

    # ------------------------------------------------------------------
    # Top-level layout
    # ------------------------------------------------------------------

    def _build(self):
        self._build_header()

        # Scrollable body
        outer = tk.Frame(self, bg=BG)
        outer.pack(fill="both", expand=True)

        canvas = tk.Canvas(outer, bg=BG, highlightthickness=0, borderwidth=0)
        vsb    = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)

        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        self._body = tk.Frame(canvas, bg=BG)
        _win = canvas.create_window((0, 0), window=self._body, anchor="nw")

        self._body.bind("<Configure>",
                        lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfig(_win, width=e.width))

        def _wheel(e):
            canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", _wheel)

        self._build_ecu_info()
        self._build_stages()
        self._build_pops()
        self._build_anulaciones()
        self._build_log()

    # ------------------------------------------------------------------
    # Header
    # ------------------------------------------------------------------

    def _build_header(self):
        hdr = tk.Frame(self, bg="#0A0A12", pady=6)
        hdr.pack(fill="x")

        tk.Label(hdr, text="MSR ELECTRONICS",
                 bg="#0A0A12", fg=ACCENT, font=("Segoe UI", 9, "bold"),
                 anchor="center").pack(fill="x")
        tk.Label(hdr, text="ECU Tuning Suite",
                 bg="#0A0A12", fg=FG_DIM, font=FONT_SMALL,
                 anchor="center").pack(fill="x")

        if not _TUNING_AVAILABLE:
            tk.Label(hdr, text="⚠  Módulos no disponibles",
                     bg="#0A0A12", fg=RED, font=FONT_SMALL).pack()

    # ------------------------------------------------------------------
    # Section 1: ECU Info
    # ------------------------------------------------------------------

    def _build_ecu_info(self):
        _section_header(self._body, "Detección ECU", ACCENT)

        card = _card(self._body)
        card.pack(fill="x", padx=8, pady=(0, 4))

        # Detect button
        _flat_btn(card, "⚡  Detectar ECU Automáticamente",
                  self._on_detect, bg=ACCENT, font=FONT_CARD,
                  pady=7).pack(fill="x", padx=8, pady=8)

        _sep(card)

        # Info grid
        grid = tk.Frame(card, bg=PANEL)
        grid.pack(fill="x", padx=8, pady=(0, 8))

        self._ecu_vars: dict = {}

        def _row(label, key, val_color=CYAN):
            tk.Label(grid, text=label, bg=PANEL, fg=FG_DIM,
                     font=FONT_SMALL, anchor="w", width=10).grid(
                row=_row.n, column=0, sticky="w", pady=1)
            var = tk.StringVar(value="—")
            self._ecu_vars[key] = var
            tk.Label(grid, textvariable=var, bg=PANEL, fg=val_color,
                     font=FONT_MONO, anchor="w").grid(
                row=_row.n, column=1, sticky="w", padx=(4, 0))
            _row.n += 1
        _row.n = 0

        _row("Perfil",     "profile",  ACCENT)
        _row("Familia",    "family",   FG)
        _row("Tamaño",     "size",     FG_DIM)
        _row("VIN",        "vin",      GREEN)
        _row("SW  Nº",     "sw",       TEAL)
        _row("HW  Nº",     "hw",       TEAL)
        _row("Cal ID",     "cal",      TEAL)
        _row("Confianza",  "conf",     YELLOW)

        # Confidence bar
        bar_frame = tk.Frame(card, bg=PANEL)
        bar_frame.pack(fill="x", padx=8, pady=(0, 8))
        tk.Label(bar_frame, text="Confianza:", bg=PANEL, fg=FG_DIM,
                 font=FONT_SMALL).pack(side="left")
        self._conf_bar_bg = tk.Frame(bar_frame, bg=BORDER, height=6)
        self._conf_bar_bg.pack(side="left", fill="x", expand=True, padx=(6, 0), pady=6)
        self._conf_bar = tk.Frame(self._conf_bar_bg, bg=FG_DIM, height=6, width=0)
        self._conf_bar.place(x=0, y=0, relheight=1.0)

    def _on_detect(self):
        data = self._get_data()
        if data is None:
            messagebox.showinfo("Sin archivo", "Abre un archivo ECU primero.")
            return
        if not _TUNING_AVAILABLE:
            messagebox.showerror("No disponible", "Módulos de tuning no disponibles.")
            return

        try:
            rep = ECUInfoExtractor().detect(bytes(data))
        except Exception as exc:
            messagebox.showerror("Error detección", str(exc))
            return

        self._report  = rep
        self._profile = rep.profile

        # Update grid
        self._ecu_vars["profile"].set(rep.profile.name if rep.profile else "Desconocido")
        self._ecu_vars["family"].set(rep.family.name)
        self._ecu_vars["size"].set(f"{rep.file_size:,} B  ({rep.file_size//1024} KB)")
        self._ecu_vars["vin"].set(rep.vin or "—")
        self._ecu_vars["sw"].set(rep.sw_version or "—")
        self._ecu_vars["hw"].set(rep.hw_version or "—")
        self._ecu_vars["cal"].set(rep.cal_id or "—")
        self._ecu_vars["conf"].set(f"{rep.confidence:.0%}")

        # Confidence bar
        pct = rep.confidence
        bar_color = GREEN if pct >= 0.7 else YELLOW if pct >= 0.4 else RED
        self._conf_bar.configure(bg=bar_color)
        self._conf_bar_bg.update_idletasks()
        w = self._conf_bar_bg.winfo_width()
        self._conf_bar.place(x=0, y=0, relheight=1.0, width=int(w * pct))

        # Refresh anulaciones checkboxes for this profile
        self._refresh_anulaciones()

        if rep.notes:
            messagebox.showwarning("Notas ECU", "\n".join(rep.notes))

        self._log(f"ECU detectada: {rep.profile.name if rep.profile else 'Desconocida'} | "
                  f"VIN: {rep.vin or 'N/A'} | Confianza: {rep.confidence:.0%}")

    # ------------------------------------------------------------------
    # Section 2: Stage Tuning
    # ------------------------------------------------------------------

    def _build_stages(self):
        _section_header(self._body, "Stage Tuning", GREEN)

        stages = [
            (StageLevel.STAGE1, "STAGE 1",
             "Software only · Hardware stock",
             "+30 hp  /  +55 Nm",
             GREEN, "🟢"),
            (StageLevel.STAGE2, "STAGE 2",
             "Intake · Exhaust · Intercooler",
             "+55 hp  /  +90 Nm",
             YELLOW, "🟡"),
            (StageLevel.STAGE3, "STAGE 3",
             "Turbo upgrade · Full build",
             "+110 hp  /  +160 Nm",
             RED, "🔴"),
        ]

        for stage, label, desc, gains, color, dot in stages:
            self._build_stage_card(stage, label, desc, gains, color, dot)

        # Result line
        self._stage_result = tk.StringVar(value="")
        tk.Label(self._body, textvariable=self._stage_result,
                 bg=BG, fg=GREEN, font=FONT_SMALL,
                 wraplength=310, justify="left").pack(
            fill="x", padx=10, pady=(0, 4))

    def _build_stage_card(self, stage, label, desc, gains, color, dot):
        card = _card(self._body)
        card.pack(fill="x", padx=8, pady=3)

        top = tk.Frame(card, bg=PANEL)
        top.pack(fill="x", padx=8, pady=(8, 2))

        # Color indicator strip on the left
        strip = tk.Frame(card, bg=color, width=4)
        strip.pack(side="left", fill="y")

        content = tk.Frame(card, bg=PANEL)
        content.pack(side="left", fill="x", expand=True, padx=8, pady=8)

        # Header row
        hrow = tk.Frame(content, bg=PANEL)
        hrow.pack(fill="x")
        tk.Label(hrow, text=f"{dot} {label}", bg=PANEL, fg=color,
                 font=FONT_CARD).pack(side="left")
        _badge(hrow, "TUNE", color, BG).pack(side="right")

        tk.Label(content, text=desc, bg=PANEL, fg=FG_DIM,
                 font=FONT_SMALL, anchor="w").pack(fill="x", pady=(1, 0))
        tk.Label(content, text=gains, bg=PANEL, fg=FG,
                 font=FONT_SMALL, anchor="w").pack(fill="x")

        _flat_btn(content,
                  f"Aplicar {label}",
                  lambda s=stage, l=label: self._on_stage(s, l),
                  bg=color, fg=BG,
                  font=("Segoe UI", 9, "bold"),
                  pady=5).pack(fill="x", pady=(6, 0))

    def _on_stage(self, stage, label):
        data = self._get_data()
        if data is None:
            messagebox.showinfo("Sin archivo", "Abre un archivo ECU primero.")
            return

        spec = (self._profile.stages.get(stage) if self._profile else None)
        desc = spec.description if spec else "Modificación de mapas de rendimiento."

        if not messagebox.askyesno(
            f"Confirmar {label}",
            f"{desc}\n\n"
            "• Boost, combustible, encendido y torque serán modificados.\n"
            "• El limitador de velocidad será eliminado.\n\n"
            "¿Tienes backup del archivo original?"
        ):
            return

        try:
            result = TuneEngine().apply_stage(bytes(data), stage, self._profile)
        except Exception as exc:
            messagebox.showerror("Error Stage", str(exc))
            return

        self._set_data(result.data)
        gains = ""
        if result.profile and result.profile.stages.get(stage):
            sp = result.profile.stages[stage]
            if sp.power_gain_hp:
                gains = f" | Est. +{sp.power_gain_hp} hp / +{sp.torque_gain_nm} Nm"

        msg = (f"✓ {label} aplicado — "
               f"{len(result.maps_modified)} mapas modificados{gains}")
        self._stage_result.set(msg)
        self._log(msg)

        if result.warnings:
            messagebox.showwarning(f"{label} completado", "\n".join(result.warnings))

    # ------------------------------------------------------------------
    # Section 3: Pops & Bang
    # ------------------------------------------------------------------

    def _build_pops(self):
        _section_header(self._body, "Pops & Bang", BLUE)

        card = _card(self._body)
        card.pack(fill="x", padx=8, pady=(0, 4))

        tk.Label(card, text="Intensidad de crackle en sobreaceleración:",
                 bg=PANEL, fg=FG_DIM, font=FONT_SMALL).pack(
            anchor="w", padx=8, pady=(8, 4))

        # Level selector — visual tiles
        self._pops_var = tk.IntVar(value=0)
        levels_frame = tk.Frame(card, bg=PANEL)
        levels_frame.pack(fill="x", padx=8, pady=(0, 4))

        levels = [
            (0, "OFF",       FG_DIM, "—"),
            (1, "Suave",     GREEN,  "🔥"),
            (2, "Medio",     ORANGE, "🔥🔥"),
            (3, "Agresivo",  RED,    "🔥🔥🔥"),
        ]

        for val, name, color, icon in levels:
            col = tk.Frame(levels_frame, bg=PANEL)
            col.pack(side="left", expand=True, fill="x", padx=2)
            tile = tk.Frame(col, bg=BORDER, cursor="hand2",
                            highlightthickness=1,
                            highlightbackground=BORDER)
            tile.pack(fill="x")
            tk.Label(tile, text=icon, bg=BORDER, font=("Segoe UI", 14)).pack(pady=(6, 0))
            tk.Label(tile, text=name, bg=BORDER, fg=color,
                     font=FONT_BADGE).pack(pady=(0, 6))
            tile.bind("<Button-1>",
                      lambda e, v=val, t=tile: self._select_pops_tile(v, t))
            tile._level = val
            tile._color = color

        self._pops_tiles = [
            f for f in levels_frame.winfo_children()
            for _ in [None]
        ]

        # Track tile widgets for selection highlight
        self._pops_tile_widgets = {}
        for val, name, color, icon in levels:
            w = levels_frame.winfo_children()[val]  # each col
            inner = w.winfo_children()[0]             # the tile frame
            self._pops_tile_widgets[val] = (inner, color)

        _flat_btn(card, "Aplicar Pops & Bang",
                  self._on_pops, bg=BLUE, fg=BG,
                  font=FONT_CARD, pady=6).pack(
            fill="x", padx=8, pady=(4, 8))

        self._pops_result = tk.StringVar(value="")
        tk.Label(card, textvariable=self._pops_result,
                 bg=PANEL, fg=GREEN, font=FONT_SMALL,
                 wraplength=290).pack(anchor="w", padx=8, pady=(0, 6))

    def _select_pops_tile(self, val, tile):
        self._pops_var.set(val)
        # Reset all tiles
        for v, (w, color) in self._pops_tile_widgets.items():
            is_selected = (v == val)
            w.configure(
                bg=color if is_selected else BORDER,
                highlightbackground=color if is_selected else BORDER,
            )
            for child in w.winfo_children():
                child.configure(bg=color if is_selected else BORDER)

    def _on_pops(self):
        data = self._get_data()
        if data is None:
            messagebox.showinfo("Sin archivo", "Abre un archivo ECU primero.")
            return

        level_int = self._pops_var.get()
        names = {0: "OFF", 1: "Suave", 2: "Medio", 3: "Agresivo"}

        if not messagebox.askyesno(
            "Confirmar Pops & Bang",
            f"¿Aplicar nivel '{names[level_int]}' de Pops & Bang?\n\n"
            "Modifica los mapas de sobreaceleración (NWNS, KFZWOK) "
            "y el encendido en overrun."
        ):
            return

        try:
            level  = PopsBangLevel(level_int)
            result = PopsBangEngine().apply(bytes(data), level, self._profile)
        except Exception as exc:
            messagebox.showerror("Error Pops & Bang", str(exc))
            return

        self._set_data(result.data)
        msg = f"✓ Pops & Bang '{names[level_int]}' aplicado"
        self._pops_result.set(msg)
        self._log(msg)

        if result.warnings:
            messagebox.showwarning("Pops & Bang", "\n".join(result.warnings))

    # ------------------------------------------------------------------
    # Section 4: Anulaciones
    # ------------------------------------------------------------------

    def _build_anulaciones(self):
        _section_header(self._body, "Anulaciones / Deletes", RED)

        card = _card(self._body)
        card.pack(fill="x", padx=8, pady=(0, 4))

        tk.Label(card, text="Selecciona las cancelaciones a aplicar:",
                 bg=PANEL, fg=FG_DIM, font=FONT_SMALL).pack(
            anchor="w", padx=8, pady=(8, 4))

        self._cancel_frame = tk.Frame(card, bg=PANEL)
        self._cancel_frame.pack(fill="x", padx=8)

        self._cancel_vars = {}
        self._all_cancels = [
            (Cancellation.EGR,           "EGR Delete",           YELLOW),
            (Cancellation.DPF,           "DPF / FAP Delete",     YELLOW),
            (Cancellation.LAMBDA,        "Lambda Delete",        YELLOW),
            (Cancellation.SWIRL_FLAP,    "Swirl Flap Delete",    FG),
            (Cancellation.SAP,           "SAP Delete",           FG),
            (Cancellation.SPEED_LIMITER, "Speed Limiter Delete", GREEN),
            (Cancellation.TORQUE_LIMIT,  "Torque Limit Delete",  GREEN),
            (Cancellation.RPM_LIMIT,     "Rev Limit Raise",      GREEN),
            (Cancellation.ADBLUE,        "AdBlue / SCR Delete",  YELLOW),
            (Cancellation.CAT,           "Cat Monitor Delete",   FG),
            (Cancellation.SAI,           "SAI Delete",           FG),
        ]

        self._populate_cancel_checks(self._all_cancels)

        btn_row = tk.Frame(card, bg=PANEL)
        btn_row.pack(fill="x", padx=8, pady=4)
        _flat_btn(btn_row, "Todo", self._sel_all, bg=BORDER, fg=FG,
                  font=FONT_SMALL).pack(side="left", padx=(0, 4))
        _flat_btn(btn_row, "Ninguno", self._sel_none, bg=BORDER, fg=FG,
                  font=FONT_SMALL).pack(side="left")

        _flat_btn(card, "Aplicar Anulaciones",
                  self._on_anular, bg=RED, fg=BG,
                  font=FONT_CARD, pady=6).pack(
            fill="x", padx=8, pady=(4, 4))

        self._cancel_result = tk.StringVar(value="")
        tk.Label(card, textvariable=self._cancel_result,
                 bg=PANEL, fg=GREEN, font=FONT_SMALL,
                 wraplength=290).pack(anchor="w", padx=8, pady=(0, 8))

    def _populate_cancel_checks(self, items):
        for w in self._cancel_frame.winfo_children():
            w.destroy()
        self._cancel_vars.clear()

        # Two-column grid
        left = tk.Frame(self._cancel_frame, bg=PANEL)
        right = tk.Frame(self._cancel_frame, bg=PANEL)
        left.pack(side="left", fill="x", expand=True)
        right.pack(side="left", fill="x", expand=True)

        for i, (cancel, label, color) in enumerate(items):
            var = tk.BooleanVar(value=False)
            self._cancel_vars[cancel] = var
            parent = left if i % 2 == 0 else right
            tk.Checkbutton(
                parent, text=label, variable=var,
                bg=PANEL, fg=color, selectcolor=BORDER,
                activebackground=PANEL, font=FONT_SMALL,
                anchor="w",
            ).pack(anchor="w", pady=1)

    def _refresh_anulaciones(self):
        if not self._profile:
            return
        defined = set(self._profile.cancellations.keys())
        items = [
            (c, lbl, col if c in defined else FG_DIM)
            for c, lbl, col in self._all_cancels
        ]
        self._populate_cancel_checks(items)

    def _sel_all(self):
        for v in self._cancel_vars.values():
            v.set(True)

    def _sel_none(self):
        for v in self._cancel_vars.values():
            v.set(False)

    def _on_anular(self):
        data = self._get_data()
        if data is None:
            messagebox.showinfo("Sin archivo", "Abre un archivo ECU primero.")
            return

        selected = [c for c, v in self._cancel_vars.items() if v.get()]
        if not selected:
            messagebox.showinfo("Sin selección",
                                "Selecciona al menos una anulación.")
            return

        names_map = {c: lbl for c, lbl, _ in self._all_cancels}
        names = "\n  • ".join(names_map.get(c, c.value) for c in selected)

        if not messagebox.askyesno(
            "Confirmar Anulaciones",
            f"¿Aplicar las siguientes anulaciones?\n\n  • {names}\n\n"
            "Asegúrate de tener backup del archivo original."
        ):
            return

        try:
            result = AnulacionEngine().apply(bytes(data), selected, self._profile)
        except Exception as exc:
            messagebox.showerror("Error Anulaciones", str(exc))
            return

        self._set_data(result.data)
        msg = (f"✓ {len(result.applied)} aplicadas / "
               f"{len(result.partial)} parciales / "
               f"{len(result.skipped)} omitidas")
        self._cancel_result.set(msg)
        self._log(msg)

        if result.warnings:
            messagebox.showwarning("Anulaciones", "\n".join(result.warnings))

    # ------------------------------------------------------------------
    # Section 5: Operation Log
    # ------------------------------------------------------------------

    def _build_log(self):
        _section_header(self._body, "Registro de Operaciones", FG_DIM)

        card = _card(self._body)
        card.pack(fill="x", padx=8, pady=(0, 12))

        log_frame = tk.Frame(card, bg=PANEL)
        log_frame.pack(fill="x", padx=8, pady=8)

        self._log_text = tk.Text(
            log_frame, height=5,
            bg="#090910", fg=GREEN,
            font=FONT_MONO, relief="flat",
            state="disabled", wrap="word",
            insertbackground=GREEN,
        )
        sb = ttk.Scrollbar(log_frame, command=self._log_text.yview)
        self._log_text.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._log_text.pack(fill="x")

        _flat_btn(card, "Limpiar log", self._clear_log,
                  bg=BORDER, fg=FG_DIM, font=FONT_SMALL).pack(
            anchor="e", padx=8, pady=(0, 8))

    def _log(self, msg: str):
        self._log_text.configure(state="normal")
        self._log_text.insert("end", f"› {msg}\n")
        self._log_text.see("end")
        self._log_text.configure(state="disabled")

    def _clear_log(self):
        self._log_text.configure(state="normal")
        self._log_text.delete("1.0", "end")
        self._log_text.configure(state="disabled")
