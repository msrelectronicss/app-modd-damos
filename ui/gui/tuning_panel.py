# =============================================================================
# BinModder - ECU Tuning Panel
# =============================================================================
# Right-side panel that exposes ECU-specific tuning features:
#   • ECU Info (auto-detect ECU, show VIN / SW / HW)
#   • Stage Tuning (Stage 1 / 2 / 3)
#   • Pops & Bang (OFF / Mild / Medium / Aggressive)
#   • Anulaciones (EGR, DPF, Lambda, Swirl, Speed, Torque, AdBlue …)
#
# Author: MSR Electronics
# Version: 1.0.0
# =============================================================================

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Callable, List, Optional

try:
    from formats.ecu_profiles import (
        Cancellation, ECUProfile, PopsBangLevel, StageLevel, get_profile
    )
    from core.ecu_info   import ECUInfoExtractor, ECUReport
    from core.tune_engine import TuneEngine
    from core.pops_bang  import PopsBangEngine
    from core.anulaciones import AnulacionEngine, all_cancellations_for
except ImportError:
    ECUInfoExtractor = None  # type: ignore


# ---------------------------------------------------------------------------
# Theme constants (match main_window.py COLORS)
# ---------------------------------------------------------------------------

C = {
    "bg":        "#1E1E2E",
    "panel_bg":  "#181825",
    "section_bg":"#11111B",
    "fg":        "#CDD6F4",
    "fg_dim":    "#6C7086",
    "accent":    "#CBA6F7",
    "green":     "#A6E3A1",
    "yellow":    "#F9E2AF",
    "red":       "#F38BA8",
    "blue":      "#89B4FA",
    "cyan":      "#89DCEB",
    "sep":       "#313244",
    "btn_bg":    "#313244",
    "btn_hover": "#45475A",
}

F = {
    "ui":      ("Segoe UI", 9),
    "bold":    ("Segoe UI", 9, "bold"),
    "title":   ("Segoe UI", 10, "bold"),
    "small":   ("Segoe UI", 8),
    "mono":    ("Courier New", 9),
}


def _btn(parent, text, cmd, bg=None, fg=None, **kw):
    b = tk.Button(
        parent, text=text, command=cmd,
        bg=bg or C["btn_bg"], fg=fg or C["fg"],
        activebackground=C["accent"], activeforeground=C["bg"],
        relief="flat", padx=8, pady=4, font=F["ui"],
        cursor="hand2", **kw
    )
    b.bind("<Enter>", lambda e: b.configure(bg=C["btn_hover"]))
    b.bind("<Leave>", lambda e: b.configure(bg=bg or C["btn_bg"]))
    return b


def _section(parent, title: str) -> tk.LabelFrame:
    return tk.LabelFrame(
        parent, text=f"  {title}  ",
        bg=C["section_bg"], fg=C["accent"],
        font=F["title"], labelanchor="nw",
        relief="flat", bd=1,
        highlightbackground=C["sep"], highlightthickness=1,
    )


def _label(parent, text, color=None, bold=False, **kw):
    return tk.Label(
        parent, text=text,
        bg=C["section_bg"], fg=color or C["fg"],
        font=F["bold"] if bold else F["ui"], **kw
    )


# =============================================================================
# TuningPanel
# =============================================================================

class TuningPanel(tk.Frame):
    """ECU tuning side-panel.

    Parameters
    ----------
    parent : tk.Widget
        Parent widget.
    get_data : Callable[[], bytes | None]
        Callback that returns the currently loaded ROM bytes (or None).
    set_data : Callable[[bytes], None]
        Callback to push modified bytes back into the editor.
    width : int
        Panel width in pixels.
    """

    def __init__(
        self,
        parent,
        get_data: Callable[[], Optional[bytes]],
        set_data: Callable[[bytes], None],
        width: int = 320,
    ) -> None:
        super().__init__(parent, bg=C["bg"], width=width)
        self.pack_propagate(False)

        self._get_data = get_data
        self._set_data = set_data

        self._profile:  Optional[ECUProfile]  = None
        self._report:   Optional["ECUReport"] = None

        self._cancel_vars: dict = {}   # Cancellation → BooleanVar

        self._build_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        # Scrollable canvas so the panel can grow
        canvas = tk.Canvas(self, bg=C["bg"], highlightthickness=0)
        scroll = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)

        scroll.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        self._inner = tk.Frame(canvas, bg=C["bg"])
        win_id = canvas.create_window((0, 0), window=self._inner, anchor="nw")

        def _on_frame_configure(e):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def _on_canvas_configure(e):
            canvas.itemconfig(win_id, width=e.width)

        self._inner.bind("<Configure>", _on_frame_configure)
        canvas.bind("<Configure>", _on_canvas_configure)

        # Mouse-wheel scrolling
        def _on_scroll(e):
            canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", _on_scroll)

        self._build_ecu_info(self._inner)
        self._build_stages(self._inner)
        self._build_pops_bang(self._inner)
        self._build_anulaciones(self._inner)

    # ------------------------------------------------------------------
    # Section: ECU Info
    # ------------------------------------------------------------------

    def _build_ecu_info(self, parent) -> None:
        sec = _section(parent, "ECU Info")
        sec.pack(fill="x", padx=6, pady=(8, 4))

        _btn(sec, "Detectar ECU", self._on_detect, bg=C["accent"], fg=C["bg"]).pack(
            fill="x", padx=8, pady=(6, 4)
        )

        grid = tk.Frame(sec, bg=C["section_bg"])
        grid.pack(fill="x", padx=8, pady=(0, 6))

        def row(label, attr):
            tk.Label(grid, text=label, bg=C["section_bg"], fg=C["fg_dim"],
                     font=F["small"], anchor="w").grid(
                row=row.n, column=0, sticky="w", padx=(0, 6))
            var = tk.StringVar(value="—")
            setattr(self, attr, var)
            tk.Label(grid, textvariable=var, bg=C["section_bg"], fg=C["cyan"],
                     font=F["mono"], anchor="w").grid(
                row=row.n, column=1, sticky="w")
            row.n += 1
        row.n = 0

        row("Perfil ECU :", "_var_profile")
        row("Familia    :", "_var_family")
        row("Tamaño ROM :", "_var_size")
        row("VIN        :", "_var_vin")
        row("SW Nº      :", "_var_sw")
        row("HW Nº      :", "_var_hw")
        row("Cal ID     :", "_var_cal")
        row("Confianza  :", "_var_conf")

    def _on_detect(self) -> None:
        data = self._get_data()
        if data is None:
            messagebox.showinfo("Sin archivo", "Abre un archivo ECU primero.")
            return
        if ECUInfoExtractor is None:
            messagebox.showerror("Error", "Módulos de tuning no disponibles.")
            return

        try:
            ext   = ECUInfoExtractor()
            rep   = ext.detect(bytes(data))
        except Exception as exc:
            messagebox.showerror("Error detección ECU", str(exc))
            return

        self._report  = rep
        self._profile = rep.profile
        self._refresh_profile_dependent()

        self._var_profile.set(rep.profile.name if rep.profile else "Desconocido")
        self._var_family.set(rep.family.name)
        self._var_size.set(f"{rep.file_size:,} B  ({rep.file_size//1024} KB)")
        self._var_vin.set(rep.vin or "—")
        self._var_sw.set(rep.sw_version or "—")
        self._var_hw.set(rep.hw_version or "—")
        self._var_cal.set(rep.cal_id or "—")
        self._var_conf.set(f"{rep.confidence:.0%}")

        if rep.notes:
            messagebox.showwarning("Notas ECU", "\n".join(rep.notes))

    # ------------------------------------------------------------------
    # Section: Stage Tuning
    # ------------------------------------------------------------------

    def _build_stages(self, parent) -> None:
        sec = _section(parent, "Stage Tuning")
        sec.pack(fill="x", padx=6, pady=4)

        desc_frame = tk.Frame(sec, bg=C["section_bg"])
        desc_frame.pack(fill="x", padx=8, pady=(4, 2))
        self._stage_desc = tk.StringVar(value="Selecciona un Stage")
        tk.Label(desc_frame, textvariable=self._stage_desc,
                 bg=C["section_bg"], fg=C["fg_dim"], font=F["small"],
                 wraplength=260, justify="left", anchor="w").pack(fill="x")

        btn_row = tk.Frame(sec, bg=C["section_bg"])
        btn_row.pack(fill="x", padx=8, pady=(2, 6))

        stages = [
            ("Stage 1", StageLevel.STAGE1, C["green"]),
            ("Stage 2", StageLevel.STAGE2, C["yellow"]),
            ("Stage 3", StageLevel.STAGE3, C["red"]),
        ]
        for label, stage, color in stages:
            btn = _btn(btn_row, label, lambda s=stage: self._on_stage(s), bg=color, fg=C["bg"])
            btn.pack(side="left", expand=True, fill="x", padx=2)

        # Progress / result label
        self._stage_result = tk.StringVar(value="")
        tk.Label(sec, textvariable=self._stage_result,
                 bg=C["section_bg"], fg=C["green"], font=F["small"],
                 wraplength=260, justify="left").pack(fill="x", padx=8, pady=(0, 6))

    def _on_stage(self, stage: "StageLevel") -> None:
        data = self._get_data()
        if data is None:
            messagebox.showinfo("Sin archivo", "Abre un archivo ECU primero.")
            return

        spec = (self._profile.stages.get(stage) if self._profile else None)
        if self._profile and spec:
            self._stage_desc.set(spec.description)

        confirm_msg = (
            f"¿Aplicar {stage.name} al archivo cargado?\n\n"
            f"Se modificarán los mapas de boost, combustible, encendido y limitadores.\n"
            f"Guarda un backup del original antes de continuar."
        )
        if not messagebox.askyesno("Confirmar Stage", confirm_msg):
            return

        try:
            eng    = TuneEngine()
            result = eng.apply_stage(bytes(data), stage, self._profile)
        except Exception as exc:
            messagebox.showerror("Error tuning", str(exc))
            return

        self._set_data(result.data)
        gain = ""
        if result.profile and result.profile.stages.get(stage):
            sp = result.profile.stages[stage]
            if sp.power_gain_hp:
                gain = f"\nGanancia estimada: +{sp.power_gain_hp} hp / +{sp.torque_gain_nm} Nm"
        self._stage_result.set(
            f"✓ {stage.name} aplicado — "
            f"{len(result.maps_modified)} mapas modificados{gain}"
        )

        if result.warnings:
            messagebox.showwarning("Resultado Stage", "\n".join(result.warnings))

    # ------------------------------------------------------------------
    # Section: Pops & Bang
    # ------------------------------------------------------------------

    def _build_pops_bang(self, parent) -> None:
        sec = _section(parent, "Pops & Bang")
        sec.pack(fill="x", padx=6, pady=4)

        info = tk.Frame(sec, bg=C["section_bg"])
        info.pack(fill="x", padx=8, pady=(4, 2))
        tk.Label(info, text="Intensidad de crackle al soltar el acelerador:",
                 bg=C["section_bg"], fg=C["fg_dim"], font=F["small"],
                 wraplength=260, justify="left").pack(anchor="w")

        self._pops_var = tk.IntVar(value=0)
        levels = [
            ("OFF",        0),
            ("Suave",      1),
            ("Medio",      2),
            ("Agresivo",   3),
        ]
        rb_frame = tk.Frame(sec, bg=C["section_bg"])
        rb_frame.pack(fill="x", padx=8, pady=2)
        for text, val in levels:
            color = [C["fg_dim"], C["green"], C["yellow"], C["red"]][val]
            tk.Radiobutton(
                rb_frame, text=text, variable=self._pops_var, value=val,
                bg=C["section_bg"], fg=color, selectcolor=C["btn_bg"],
                activebackground=C["section_bg"], font=F["ui"],
                indicatoron=True,
            ).pack(side="left", padx=6)

        _btn(sec, "Aplicar Pops & Bang", self._on_pops_bang,
             bg=C["blue"], fg=C["bg"]).pack(fill="x", padx=8, pady=(4, 6))

        self._pops_result = tk.StringVar(value="")
        tk.Label(sec, textvariable=self._pops_result,
                 bg=C["section_bg"], fg=C["green"], font=F["small"],
                 wraplength=260).pack(fill="x", padx=8, pady=(0, 4))

    def _on_pops_bang(self) -> None:
        data = self._get_data()
        if data is None:
            messagebox.showinfo("Sin archivo", "Abre un archivo ECU primero.")
            return

        level_int = self._pops_var.get()
        level     = PopsBangLevel(level_int)
        level_names = {0: "OFF", 1: "Suave", 2: "Medio", 3: "Agresivo"}

        if not messagebox.askyesno(
            "Confirmar Pops & Bang",
            f"¿Aplicar nivel '{level_names[level_int]}' de Pops & Bang?\n\n"
            "Esto modifica los mapas de sobreaceleración y encendido."
        ):
            return

        try:
            eng    = PopsBangEngine()
            result = eng.apply(bytes(data), level, self._profile)
        except Exception as exc:
            messagebox.showerror("Error Pops & Bang", str(exc))
            return

        self._set_data(result.data)
        self._pops_result.set(
            f"✓ Pops & Bang '{level_names[level_int]}' aplicado — "
            f"{len(result.changes)} operaciones"
        )
        if result.warnings:
            messagebox.showwarning("Pops & Bang", "\n".join(result.warnings))

    # ------------------------------------------------------------------
    # Section: Anulaciones
    # ------------------------------------------------------------------

    def _build_anulaciones(self, parent) -> None:
        sec = _section(parent, "Anulaciones")
        sec.pack(fill="x", padx=6, pady=4)

        tk.Label(sec, text="Selecciona las cancelaciones a aplicar:",
                 bg=C["section_bg"], fg=C["fg_dim"], font=F["small"]).pack(
            anchor="w", padx=8, pady=(4, 2)
        )

        self._cancel_frame = tk.Frame(sec, bg=C["section_bg"])
        self._cancel_frame.pack(fill="x", padx=8, pady=2)

        self._cancel_vars = {}
        self._cancel_labels = {}

        # Show a default set; refreshed after ECU detection
        self._default_cancellations = [
            (Cancellation.EGR,          "EGR Delete",          C["yellow"]),
            (Cancellation.DPF,          "DPF Delete",          C["yellow"]),
            (Cancellation.LAMBDA,       "Lambda Delete",       C["yellow"]),
            (Cancellation.SWIRL_FLAP,   "Swirl Flap Delete",   C["fg"]),
            (Cancellation.SAP,          "SAP Delete",          C["fg"]),
            (Cancellation.SPEED_LIMITER,"Speed Limiter Delete", C["green"]),
            (Cancellation.TORQUE_LIMIT, "Torque Limit Delete", C["green"]),
            (Cancellation.RPM_LIMIT,    "Rev Limit Raise",     C["green"]),
            (Cancellation.ADBLUE,       "AdBlue / SCR Delete", C["yellow"]),
            (Cancellation.CAT,          "Cat Monitor Delete",  C["fg"]),
            (Cancellation.SAI,          "SAI Delete",          C["fg"]),
        ]
        self._populate_cancel_checks(self._default_cancellations)

        row_btns = tk.Frame(sec, bg=C["section_bg"])
        row_btns.pack(fill="x", padx=8, pady=(4, 2))

        _btn(row_btns, "Todo", self._select_all_cancels).pack(side="left", padx=2)
        _btn(row_btns, "Ninguno", self._clear_cancels).pack(side="left", padx=2)

        _btn(sec, "Aplicar Anulaciones", self._on_anular,
             bg=C["red"], fg=C["bg"]).pack(fill="x", padx=8, pady=(4, 4))

        self._cancel_result = tk.StringVar(value="")
        tk.Label(sec, textvariable=self._cancel_result,
                 bg=C["section_bg"], fg=C["green"], font=F["small"],
                 wraplength=260).pack(fill="x", padx=8, pady=(0, 6))

    def _populate_cancel_checks(self, items) -> None:
        for w in self._cancel_frame.winfo_children():
            w.destroy()
        self._cancel_vars.clear()

        for cancel, label, color in items:
            var = tk.BooleanVar(value=False)
            self._cancel_vars[cancel] = var
            tk.Checkbutton(
                self._cancel_frame, text=label, variable=var,
                bg=C["section_bg"], fg=color,
                selectcolor=C["btn_bg"], activebackground=C["section_bg"],
                font=F["ui"],
            ).pack(anchor="w")

    def _refresh_profile_dependent(self) -> None:
        """Re-populate cancellation checkboxes based on detected profile."""
        if self._profile is None:
            return

        spec_items = []
        spec_map = self._profile.cancellations
        # Merge: show profile-supported ones in green, others dimmed
        all_known = {
            Cancellation.EGR:          ("EGR Delete",           C["yellow"]),
            Cancellation.DPF:          ("DPF Delete",           C["yellow"]),
            Cancellation.LAMBDA:       ("Lambda Delete",        C["yellow"]),
            Cancellation.SWIRL_FLAP:   ("Swirl Flap Delete",    C["fg"]),
            Cancellation.SAP:          ("SAP Delete",           C["fg"]),
            Cancellation.SPEED_LIMITER:("Speed Limiter Delete", C["green"]),
            Cancellation.TORQUE_LIMIT: ("Torque Limit Delete",  C["green"]),
            Cancellation.RPM_LIMIT:    ("Rev Limit Raise",      C["green"]),
            Cancellation.ADBLUE:       ("AdBlue / SCR Delete",  C["yellow"]),
            Cancellation.CAT:          ("Cat Monitor Delete",   C["fg"]),
            Cancellation.SAI:          ("SAI Delete",           C["fg"]),
        }
        for cancel, (label, color) in all_known.items():
            eff_color = color if cancel in spec_map else C["fg_dim"]
            spec_items.append((cancel, label, eff_color))

        self._populate_cancel_checks(spec_items)

    def _select_all_cancels(self) -> None:
        for var in self._cancel_vars.values():
            var.set(True)

    def _clear_cancels(self) -> None:
        for var in self._cancel_vars.values():
            var.set(False)

    def _on_anular(self) -> None:
        data = self._get_data()
        if data is None:
            messagebox.showinfo("Sin archivo", "Abre un archivo ECU primero.")
            return

        selected = [c for c, var in self._cancel_vars.items() if var.get()]
        if not selected:
            messagebox.showinfo("Sin selección", "Selecciona al menos una anulación.")
            return

        names = "\n  • ".join(
            self._cancel_vars_label(c) for c in selected
        )
        if not messagebox.askyesno(
            "Confirmar Anulaciones",
            f"¿Aplicar las siguientes anulaciones?\n\n  • {names}\n\n"
            "Asegúrate de tener un backup del original."
        ):
            return

        try:
            eng    = AnulacionEngine()
            result = eng.apply(bytes(data), selected, self._profile)
        except Exception as exc:
            messagebox.showerror("Error Anulaciones", str(exc))
            return

        self._set_data(result.data)
        self._cancel_result.set(
            f"✓ {len(result.applied)} aplicadas, "
            f"{len(result.partial)} parciales, "
            f"{len(result.skipped)} omitidas"
        )
        if result.warnings:
            messagebox.showwarning("Anulaciones", "\n".join(result.warnings))

    def _cancel_vars_label(self, c: "Cancellation") -> str:
        labels = {
            Cancellation.EGR:           "EGR Delete",
            Cancellation.DPF:           "DPF Delete",
            Cancellation.LAMBDA:        "Lambda Delete",
            Cancellation.SWIRL_FLAP:    "Swirl Flap Delete",
            Cancellation.SAP:           "SAP Delete",
            Cancellation.SPEED_LIMITER: "Speed Limiter Delete",
            Cancellation.TORQUE_LIMIT:  "Torque Limit Delete",
            Cancellation.RPM_LIMIT:     "Rev Limit Raise",
            Cancellation.ADBLUE:        "AdBlue / SCR Delete",
            Cancellation.CAT:           "Cat Monitor Delete",
            Cancellation.SAI:           "SAI Delete",
        }
        return labels.get(c, c.value)
