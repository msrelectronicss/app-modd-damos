"""
pops_bang.py - Pops & Bang (anti-lag / exhaust crackle) map configurator.

How it works
------------
Petrol ECUs (ME7, ME9, MED17 …):
  The engine creates exhaust pops by:
  1. Lowering the overrun fuel cut-off threshold (NWNS) so the injectors
     keep firing at lower RPM during lift-off.
  2. Retarding ignition timing significantly during overrun (KFZWOK / KFZWOB)
     so the mixture ignites late and partly in the exhaust.
  3. Optionally enriching injection slightly on the overrun injection maps.

Diesel ECUs (EDC15/16/17):
  Pops are harder to achieve because there is no spark.  The technique is
  to inject a small post-injection at low pulse-width during overrun so
  that unburnt fuel reacts in the hot exhaust / turbo.

Levels
------
  OFF        – Restore stock values (repair pass).
  MILD       – Occasional subtle crackles on lift-off.  Street-friendly.
  MEDIUM     – Noticeable pops.  Good fun without being anti-social.
  AGGRESSIVE – Continuous bangs.  Track / show use.

Usage
-----
>>> eng    = PopsBangEngine()
>>> result = eng.apply(rom_bytes, PopsBangLevel.MEDIUM, profile)
>>> Path("pops.bin").write_bytes(result.data)
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from formats.ecu_profiles import (
    ECUProfile, ECUFamily, MapSpec, MapCategory, PopsBangLevel, get_profile
)
from core.tune_engine import TuneEngine, _with_offset
from utils.log_utils import BinModderLogger

log = BinModderLogger.get("core.pops_bang")


# ---------------------------------------------------------------------------
# Per-level calibration
# ---------------------------------------------------------------------------

@dataclass
class _PBCalibration:
    """Internal tuning knobs for a pops & bang level."""
    # Overrun fuel cut re-enable threshold (lower → keep injecting longer)
    nwns_delta_rpm:     int    = 0      # subtract from current NWNS value
    nwns_abs_min_rpm:   int    = 800    # never go below idle

    # Overrun ignition retard (degrees) — negative = retard from stock
    ign_retard_deg:     float  = 0.0

    # Overrun injection enrichment (% above stock overrun quantity)
    overrun_fuel_pct:   float  = 0.0

    # Post-injection delay for diesel (µs, 0 = disable)
    diesel_post_inj_us: int    = 0

    # Human description
    description:        str    = ""


_CALIBRATIONS: Dict[PopsBangLevel, _PBCalibration] = {
    PopsBangLevel.OFF: _PBCalibration(
        nwns_delta_rpm=0, ign_retard_deg=0.0, overrun_fuel_pct=0.0,
        description="Stock – all overrun values restored to defaults.",
    ),
    PopsBangLevel.MILD: _PBCalibration(
        nwns_delta_rpm=400,
        nwns_abs_min_rpm=1000,
        ign_retard_deg=-8.0,
        overrun_fuel_pct=10.0,
        diesel_post_inj_us=200,
        description="Mild – occasional crackles on lift-off.  Daily-driver friendly.",
    ),
    PopsBangLevel.MEDIUM: _PBCalibration(
        nwns_delta_rpm=700,
        nwns_abs_min_rpm=900,
        ign_retard_deg=-16.0,
        overrun_fuel_pct=25.0,
        diesel_post_inj_us=350,
        description="Medium – noticeable pops & bangs.  Good street/track compromise.",
    ),
    PopsBangLevel.AGGRESSIVE: _PBCalibration(
        nwns_delta_rpm=1100,
        nwns_abs_min_rpm=800,
        ign_retard_deg=-28.0,
        overrun_fuel_pct=50.0,
        diesel_post_inj_us=500,
        description="Aggressive – continuous bangs.  Track/show use only.",
    ),
}


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass
class PopsBangResult:
    """Result of a pops & bang operation.

    Attributes
    ----------
    data : bytes
        Modified ROM.
    level : PopsBangLevel
    profile : ECUProfile | None
    changes : list[str]
        Log of individual changes.
    warnings : list[str]
    checksum_repaired : bool
    """
    data:              bytes
    level:             PopsBangLevel
    profile:           Optional[ECUProfile]
    changes:           List[str]  = field(default_factory=list)
    warnings:          List[str]  = field(default_factory=list)
    checksum_repaired: bool       = False

    @property
    def log(self) -> str:
        return "\n".join(self.changes)


# ---------------------------------------------------------------------------
# PopsBangEngine
# ---------------------------------------------------------------------------

class PopsBangEngine:
    """Configure pops & bang behaviour in an ECU binary.

    Parameters
    ----------
    auto_checksum : bool
        Repair ROM checksum after modification (default True).
    """

    def __init__(self, auto_checksum: bool = True) -> None:
        self._auto_cs  = auto_checksum
        self._tune_eng = TuneEngine(auto_checksum=False)  # we repair ourselves

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def apply(
        self,
        data:    bytes,
        level:   PopsBangLevel,
        profile: Optional[ECUProfile] = None,
    ) -> PopsBangResult:
        """Apply pops & bang settings to *data*.

        Parameters
        ----------
        data : bytes
            Original ROM bytes.
        level : PopsBangLevel
            Desired intensity level.
        profile : ECUProfile | None
            If None, auto-detected.
        """
        data    = bytearray(data)
        profile = profile or get_profile(bytes(data))
        cal     = _CALIBRATIONS[level]
        ops:    List[str] = []
        warns:  List[str] = []

        ops.append(f"▶  Pops & Bang – Level: {level.name}")
        ops.append(f"   {cal.description}")
        ops.append("")

        if profile is None:
            return PopsBangResult(
                data=bytes(data), level=level, profile=None,
                warnings=["Unknown ECU profile – no modifications applied."],
            )

        is_diesel = profile.family in (
            ECUFamily.BOSCH_EDC15, ECUFamily.BOSCH_EDC16,
            ECUFamily.BOSCH_EDC17, ECUFamily.DELPHI_DCM,
        )

        if is_diesel:
            ops += self._apply_diesel(data, cal, profile, warns)
        else:
            ops += self._apply_petrol(data, cal, profile, warns)

        # Checksum
        cs_ok = False
        if self._auto_cs:
            cs_ok = self._tune_eng._repair_checksum(data, profile)
            ops.append(f"   {'✓' if cs_ok else '✗'} Checksum {'repaired' if cs_ok else 'repair not available'}")

        return PopsBangResult(
            data              = bytes(data),
            level             = level,
            profile           = profile,
            changes           = ops,
            warnings          = warns,
            checksum_repaired = cs_ok,
        )

    # ------------------------------------------------------------------
    # Petrol ECU (spark ignition)
    # ------------------------------------------------------------------

    def _apply_petrol(
        self,
        data:    bytearray,
        cal:     _PBCalibration,
        profile: ECUProfile,
        warns:   List[str],
    ) -> List[str]:
        ops: List[str] = []

        # 1. Overrun fuel cut threshold (NWNS)
        ms_nwns = profile.maps.get("NWNS")
        if ms_nwns is not None:
            off = self._tune_eng._locate_map(bytes(data), ms_nwns)
            if off is not None:
                raw      = struct.unpack_from("<H", data, off)[0]
                curr_rpm = int(ms_nwns.raw_to_phys(raw))
                if cal.nwns_delta_rpm == 0:
                    # OFF – write a reasonable stock default
                    new_rpm = 1500
                else:
                    new_rpm = max(curr_rpm - cal.nwns_delta_rpm, cal.nwns_abs_min_rpm)
                struct.pack_into("<H", data, off, ms_nwns.phys_to_raw(float(new_rpm)) & 0xFFFF)
                ops.append(
                    f"   ✓ NWNS (overrun fuel cut) {curr_rpm} → {new_rpm} RPM"
                )
            else:
                ops.append("   ✗ NWNS (overrun cut threshold) – not located")
                warns.append("NWNS scalar not found; overrun fuel cut unchanged.")
        else:
            ops.append("   ─ NWNS not defined for this profile")

        # 2. Overrun ignition retard (KFZWOK)
        ms_ign = profile.maps.get("KFZWOK")
        if ms_ign is None:
            # Try alternate name
            ms_ign = profile.maps.get("KFZWOP")

        if ms_ign is not None and cal.ign_retard_deg != 0.0:
            off = self._tune_eng._locate_map(bytes(data), ms_ign)
            if off is not None:
                ms_located = _with_offset(ms_ign, off)
                data, n = self._tune_eng._add_ignition(data, ms_located, cal.ign_retard_deg)
                ops.append(
                    f"   ✓ {ms_ign.name} (overrun ignition) {cal.ign_retard_deg:+.1f}° → {n} cells"
                )
            else:
                ops.append(f"   ✗ {ms_ign.name} (overrun ignition map) – not located")
        elif ms_ign is None:
            ops.append("   ─ Overrun ignition map not defined for this profile")

        # 3. Overrun fuel enrichment (applies to KFKHFM or similar fuel map)
        if cal.overrun_fuel_pct > 0.0:
            # Only modify the low-load zone of the main fuel map
            ms_fuel = profile.maps.get("KFKHFM")
            if ms_fuel is None:
                ms_fuel = profile.maps.get("IQ_MAP")
            if ms_fuel is not None:
                off = self._tune_eng._locate_map(bytes(data), ms_fuel)
                if off is not None:
                    ms_located = _with_offset(ms_fuel, off)
                    # Only scale values BELOW 30% load (overrun zone)
                    data, n = self._scale_map_partial(
                        data, ms_located, cal.overrun_fuel_pct,
                        row_start=0, row_end=max(1, ms_fuel.rows // 4)
                    )
                    ops.append(
                        f"   ✓ {ms_fuel.name} (overrun enrichment) +{cal.overrun_fuel_pct:.0f}% "
                        f"first {max(1, ms_fuel.rows // 4)} rows → {n} cells"
                    )
                else:
                    ops.append("   ✗ Fuel map for overrun enrichment – not located")

        return ops

    # ------------------------------------------------------------------
    # Diesel ECU (compression ignition)
    # ------------------------------------------------------------------

    def _apply_diesel(
        self,
        data:    bytearray,
        cal:     _PBCalibration,
        profile: ECUProfile,
        warns:   List[str],
    ) -> List[str]:
        ops: List[str] = []
        ops.append("   ℹ  Diesel pops & bang via post-injection technique")

        # For diesel, enrich the overrun injection map
        ms_fuel = profile.maps.get("IQ_MAP")
        if ms_fuel is not None and cal.overrun_fuel_pct > 0.0:
            off = self._tune_eng._locate_map(bytes(data), ms_fuel)
            if off is not None:
                ms_located = _with_offset(ms_fuel, off)
                # Raise the low-load rows (overrun zone)
                rows_to_touch = max(1, ms_fuel.rows // 5)
                data, n = self._scale_map_partial(
                    data, ms_located, cal.overrun_fuel_pct,
                    row_start=0, row_end=rows_to_touch
                )
                ops.append(
                    f"   ✓ IQ_MAP (overrun) +{cal.overrun_fuel_pct:.0f}% "
                    f"bottom {rows_to_touch} rows → {n} cells changed"
                )
            else:
                ops.append("   ✗ IQ_MAP – not located")
                warns.append("Injection map not found; diesel pops effect may be absent.")
        else:
            ops.append("   ─ Diesel post-injection: no changes for OFF level")

        return ops

    # ------------------------------------------------------------------
    # Partial map scaler (first N rows only)
    # ------------------------------------------------------------------

    @staticmethod
    def _scale_map_partial(
        data:       bytearray,
        ms:         MapSpec,
        pct:        float,
        row_start:  int = 0,
        row_end:    int = 0,
    ) -> Tuple[bytearray, int]:
        """Scale only rows [row_start:row_end] of the map."""
        if row_end <= row_start:
            return data, 0

        factor    = 1.0 + pct / 100.0
        fmt_char  = ("h" if ms.signed else "H") if ms.element_size == 2 else (
                     "b" if ms.signed else "B")
        row_bytes = ms.cols * ms.element_size
        changed   = 0

        for r in range(row_start, min(row_end, ms.rows)):
            off = ms.hint_offset + r * row_bytes
            if off + row_bytes > len(data):
                break
            fmt  = f"<{ms.cols}{fmt_char}"
            raws = list(struct.unpack_from(fmt, data, off))
            for i, raw in enumerate(raws):
                phys     = ms.raw_to_phys(raw)
                new_phys = ms.clamp_phys(phys * factor)
                new_raw  = ms.phys_to_raw(new_phys)
                if new_raw != raw:
                    raws[i]  = new_raw
                    changed += 1
            struct.pack_into(fmt, data, off, *raws)

        return data, changed
