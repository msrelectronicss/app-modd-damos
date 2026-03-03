"""
tune_engine.py - Stage 1 / 2 / 3 ECU tuning engine.

Applies performance tuning stages to an ECU binary by:
  1. Locating calibration maps (boost, fuel, ignition, torque, limiters)
     using the profile's hint offsets and/or heuristic pattern search.
  2. Scaling map values by the stage-defined percentages.
  3. Clamping every modified value to the physical safety limits in the
     MapSpec (prevents dangerous values like runaway boost).
  4. Repairing the ROM checksum.
  5. Returning the modified bytes together with a human-readable log.

Usage
-----
>>> eng    = TuneEngine()
>>> result = eng.apply_stage(rom_bytes, StageLevel.STAGE1, profile)
>>> Path("tuned.bin").write_bytes(result.data)
>>> print(result.log)
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from formats.ecu_profiles import (
    ECUProfile, StageLevel, StageSpec, MapSpec, MapCategory, get_profile
)
from utils.log_utils import BinModderLogger

log = BinModderLogger.get("core.tune_engine")


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass
class TuneResult:
    """Output of a tuning operation.

    Attributes
    ----------
    data : bytes
        Modified ROM bytes (write this to disk).
    stage : StageLevel
    profile : ECUProfile | None
    maps_modified : list[str]
        Names of maps that were successfully modified.
    maps_not_found : list[str]
        Maps the engine could not locate (offsets unknown / search failed).
    checksum_repaired : bool
        True if the ROM checksum was updated.
    log : str
        Human-readable summary of every operation performed.
    warnings : list[str]
    """
    data:              bytes
    stage:             StageLevel
    profile:           Optional[ECUProfile]
    maps_modified:     List[str]          = field(default_factory=list)
    maps_not_found:    List[str]          = field(default_factory=list)
    checksum_repaired: bool               = False
    log:               str                = ""
    warnings:          List[str]          = field(default_factory=list)


# ---------------------------------------------------------------------------
# TuneEngine
# ---------------------------------------------------------------------------

class TuneEngine:
    """Apply stage tuning to an ECU binary.

    Parameters
    ----------
    auto_checksum : bool
        If True (default), automatically repair the checksum after
        every operation.
    """

    # Physical safety limits overriding any bad profile values
    _ABSOLUTE_BOOST_MAX  = 3500.0   # mbar  (~2.5 bar gauge)
    _ABSOLUTE_FUEL_MAX   = 250.0    # mg/str
    _ABSOLUTE_TORQUE_MAX = 700.0    # Nm
    _ABSOLUTE_RPM_MAX    = 8500     # RPM
    _ABSOLUTE_VMAX       = 340      # km/h

    def __init__(self, auto_checksum: bool = True) -> None:
        self._auto_cs = auto_checksum

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def apply_stage(
        self,
        data:    bytes,
        stage:   StageLevel,
        profile: Optional[ECUProfile] = None,
    ) -> TuneResult:
        """Apply a tuning stage to *data* and return a :class:`TuneResult`.

        Parameters
        ----------
        data : bytes
            Original ROM bytes.
        stage : StageLevel
            Stage 1, 2, or 3.
        profile : ECUProfile | None
            If None, auto-detected from *data*.
        """
        data    = bytearray(data)
        profile = profile or get_profile(bytes(data))

        ops:            List[str] = []
        maps_modified:  List[str] = []
        maps_not_found: List[str] = []
        warnings:       List[str] = []

        if profile is None:
            return TuneResult(
                data=bytes(data), stage=stage, profile=None,
                log="ECU profile not recognised — no modifications applied.",
                warnings=["Unknown ECU. Load a supported binary to tune."],
            )

        stage_spec = profile.stages.get(stage)
        if stage_spec is None:
            return TuneResult(
                data=bytes(data), stage=stage, profile=profile,
                log=f"Stage {stage.value} not defined for {profile.name}.",
                warnings=[f"No Stage {stage.value} definition in profile."],
            )

        ops.append(f"▶  Applying {stage.name} to {profile.name}")
        ops.append(f"   {stage_spec.description}")
        ops.append("")

        # ── Boost ──────────────────────────────────────────────────────
        if stage_spec.boost_pct is not None:
            names = [n for n, m in profile.maps.items() if m.category == MapCategory.BOOST]
            for name in names:
                ms = profile.maps[name]
                off = self._locate_map(bytes(data), ms)
                if off is None:
                    maps_not_found.append(name)
                    ops.append(f"   ✗ {name} (boost) – not located")
                    continue
                ms_located = _with_offset(ms, off)
                data, n = self._scale_map(data, ms_located, stage_spec.boost_pct)
                maps_modified.append(name)
                ops.append(f"   ✓ {name} (boost) +{stage_spec.boost_pct:.0f}% → {n} cells changed")

        # ── Fuel / Injection ───────────────────────────────────────────
        if stage_spec.fuel_pct is not None:
            names = [n for n, m in profile.maps.items() if m.category == MapCategory.FUEL]
            for name in names:
                ms  = profile.maps[name]
                off = self._locate_map(bytes(data), ms)
                if off is None:
                    maps_not_found.append(name)
                    ops.append(f"   ✗ {name} (fuel) – not located")
                    continue
                ms_located = _with_offset(ms, off)
                data, n = self._scale_map(
                    data, ms_located, stage_spec.fuel_pct,
                    only_above_phys=20.0   # don't raise idle injection
                )
                maps_modified.append(name)
                ops.append(f"   ✓ {name} (fuel) +{stage_spec.fuel_pct:.0f}% → {n} cells changed")

        # ── Ignition ───────────────────────────────────────────────────
        if stage_spec.ignition_deg is not None and stage_spec.ignition_deg != 0:
            names = [n for n, m in profile.maps.items() if m.category == MapCategory.IGNITION]
            for name in names:
                ms  = profile.maps[name]
                off = self._locate_map(bytes(data), ms)
                if off is None:
                    maps_not_found.append(name)
                    ops.append(f"   ✗ {name} (ignition) – not located")
                    continue
                ms_located = _with_offset(ms, off)
                data, n = self._add_ignition(data, ms_located, stage_spec.ignition_deg)
                maps_modified.append(name)
                ops.append(
                    f"   ✓ {name} (ignition) +{stage_spec.ignition_deg:.1f}° → {n} cells changed"
                )

        # ── Torque limiter ─────────────────────────────────────────────
        if stage_spec.torque_pct is not None:
            names = [n for n, m in profile.maps.items() if m.category == MapCategory.TORQUE]
            for name in names:
                ms  = profile.maps[name]
                off = self._locate_map(bytes(data), ms)
                if off is None:
                    maps_not_found.append(name)
                    ops.append(f"   ✗ {name} (torque) – not located")
                    continue
                ms_located = _with_offset(ms, off)
                data, n = self._scale_map(data, ms_located, stage_spec.torque_pct)
                maps_modified.append(name)
                ops.append(f"   ✓ {name} (torque) +{stage_spec.torque_pct:.0f}% → {n} cells changed")

        # ── Speed limiter ──────────────────────────────────────────────
        if stage_spec.remove_vmax:
            changed, new_vmax = self._remove_speed_limiter(data, profile)
            if changed:
                maps_modified.append("VMAX")
                ops.append(f"   ✓ Speed limiter removed (set to {new_vmax} km/h)")
            else:
                maps_not_found.append("VMAX")
                ops.append("   ✗ Speed limiter – VMAX scalar not located")

        # ── Rev limiter ────────────────────────────────────────────────
        if stage_spec.rpm_raise:
            changed, new_rpm = self._raise_rpm_limit(data, profile, stage_spec.rpm_raise)
            if changed:
                maps_modified.append("NMAX")
                ops.append(f"   ✓ Rev limiter raised by {stage_spec.rpm_raise} RPM (→ {new_rpm} RPM)")
            else:
                maps_not_found.append("NMAX")
                ops.append("   ✗ Rev limiter – NMAX scalar not located")

        # ── Checksum ───────────────────────────────────────────────────
        cs_repaired = False
        if self._auto_cs:
            cs_repaired = self._repair_checksum(data, profile)
            ops.append(f"   {'✓' if cs_repaired else '✗'} Checksum {'repaired' if cs_repaired else 'repair skipped (algorithm not supported)'}")

        # ── Summary ────────────────────────────────────────────────────
        ops.append("")
        ops.append(f"   Maps modified  : {len(maps_modified)}")
        ops.append(f"   Maps not found : {len(maps_not_found)}")
        if stage_spec.power_gain_hp:
            ops.append(f"   Expected gains : +{stage_spec.power_gain_hp} hp / +{stage_spec.torque_gain_nm} Nm")
        if maps_not_found:
            warnings.append(
                f"Could not locate {len(maps_not_found)} map(s): {', '.join(maps_not_found)}. "
                "Offset hints needed for this specific ECU firmware version."
            )

        return TuneResult(
            data              = bytes(data),
            stage             = stage,
            profile           = profile,
            maps_modified     = maps_modified,
            maps_not_found    = maps_not_found,
            checksum_repaired = cs_repaired,
            log               = "\n".join(ops),
            warnings          = warnings,
        )

    # ------------------------------------------------------------------
    # Map location
    # ------------------------------------------------------------------

    def _locate_map(self, data: bytes, ms: MapSpec) -> Optional[int]:
        """Return the byte offset of *ms* in *data*, or None.

        Strategy:
        1. If ``ms.hint_offset`` > 0, validate that the offset holds
           plausible values (within phys_min/phys_max) and use it.
        2. Attempt to find a cluster of plausible values for the map's
           dimensions using a sliding-window scan.
        """
        if ms.hint_offset > 0:
            if self._validate_offset(data, ms, ms.hint_offset):
                return ms.hint_offset

        # Heuristic scan
        step     = ms.element_size
        end      = max(0, len(data) - ms.data_bytes)
        raw_min  = ms.phys_to_raw(ms.phys_min)
        raw_max  = ms.phys_to_raw(ms.phys_max)
        n_cells  = ms.rows * ms.cols
        need     = int(n_cells * 0.70)   # ≥70% of cells must be in range
        fmt_char = ("h" if ms.signed else "H") if ms.element_size == 2 else (
                    "b" if ms.signed else "B") if ms.element_size == 1 else (
                    "i" if ms.signed else "I")

        for off in range(0, end, step * ms.cols):   # step by one row at a time
            if off + ms.data_bytes > len(data):
                break
            chunk = data[off : off + ms.data_bytes]
            try:
                raws = struct.unpack_from(f"<{n_cells}{fmt_char}", chunk, 0)
            except struct.error:
                continue
            in_range = sum(1 for v in raws if raw_min <= v <= raw_max)
            if in_range >= need:
                return off

        return None

    def _validate_offset(self, data: bytes, ms: MapSpec, offset: int) -> bool:
        """Return True if the cells at *offset* are mostly in the valid range."""
        if offset + ms.data_bytes > len(data):
            return False
        n     = ms.rows * ms.cols
        fmt   = f"<{n}{'H' if not ms.signed else 'h'}"
        try:
            raws = struct.unpack_from(fmt, data, offset)
        except struct.error:
            return False
        raw_min = ms.phys_to_raw(ms.phys_min)
        raw_max = ms.phys_to_raw(ms.phys_max)
        in_range = sum(1 for v in raws if raw_min <= v <= raw_max)
        return in_range >= len(raws) * 0.65

    # ------------------------------------------------------------------
    # Map modification helpers
    # ------------------------------------------------------------------

    def _scale_map(
        self,
        data:          bytearray,
        ms:            MapSpec,
        pct:           float,
        only_above_phys: float = 0.0,
    ) -> Tuple[bytearray, int]:
        """Scale all cells of map *ms* by *pct* percent.

        Parameters
        ----------
        data : bytearray
            Full ROM buffer (modified in-place).
        ms : MapSpec
            Includes the resolved ``hint_offset``.
        pct : float
            Percentage increase (e.g. 15.0 → ×1.15).
        only_above_phys : float
            Only modify cells whose current physical value exceeds this
            threshold (e.g. skip idle zones for fuel maps).

        Returns
        -------
        (modified_data, n_cells_changed)
        """
        factor    = 1.0 + pct / 100.0
        n_cells   = ms.rows * ms.cols
        fmt_char  = ("h" if ms.signed else "H") if ms.element_size == 2 else (
                     "b" if ms.signed else "B") if ms.element_size == 1 else (
                     "i" if ms.signed else "I")
        fmt       = f"<{n_cells}{fmt_char}"
        size      = struct.calcsize(fmt)
        off       = ms.hint_offset

        if off + size > len(data):
            return data, 0

        raws    = list(struct.unpack_from(fmt, data, off))
        changed = 0

        for i, raw in enumerate(raws):
            phys = ms.raw_to_phys(raw)
            if phys <= only_above_phys:
                continue
            new_phys  = ms.clamp_phys(phys * factor)
            # Apply absolute hardware limits
            new_phys  = self._absolute_limit(new_phys, ms)
            new_raw   = ms.phys_to_raw(new_phys)
            if new_raw != raw:
                raws[i]  = new_raw
                changed += 1

        struct.pack_into(fmt, data, off, *raws)
        return data, changed

    def _add_ignition(
        self, data: bytearray, ms: MapSpec, deg_advance: float
    ) -> Tuple[bytearray, int]:
        """Add *deg_advance* degrees to every cell in the ignition map.

        Positive = more advance. Values are clamped to ms.phys_max.
        """
        n_cells  = ms.rows * ms.cols
        fmt      = f"<{n_cells}{'h' if ms.signed else 'H'}"
        size     = struct.calcsize(fmt)
        off      = ms.hint_offset

        if off + size > len(data):
            return data, 0

        raws    = list(struct.unpack_from(fmt, data, off))
        raw_add = ms.phys_to_raw(deg_advance) - ms.phys_to_raw(0.0)
        changed = 0

        for i, raw in enumerate(raws):
            phys     = ms.raw_to_phys(raw)
            new_phys = ms.clamp_phys(phys + deg_advance)
            new_raw  = ms.phys_to_raw(new_phys)
            if new_raw != raw:
                raws[i]  = new_raw
                changed += 1

        struct.pack_into(fmt, data, off, *raws)
        return data, changed

    def _absolute_limit(self, phys: float, ms: MapSpec) -> float:
        """Apply hard safety caps independent of the profile."""
        if ms.category.value == "boost":
            return min(phys, self._ABSOLUTE_BOOST_MAX)
        if ms.category.value == "fuel":
            return min(phys, self._ABSOLUTE_FUEL_MAX)
        if ms.category.value == "torque":
            return min(phys, self._ABSOLUTE_TORQUE_MAX)
        return phys

    # ------------------------------------------------------------------
    # Limiters
    # ------------------------------------------------------------------

    def _remove_speed_limiter(
        self, data: bytearray, profile: ECUProfile
    ) -> Tuple[bool, int]:
        """Set VMAX scalar to a high value (effectively removing the limit)."""
        ms = profile.maps.get("VMAX")
        if ms is None:
            return False, 0

        new_vmax = min(int(self._ABSOLUTE_VMAX), int(ms.phys_max))
        off      = self._locate_map(bytes(data), ms)
        if off is None:
            return False, 0

        raw = ms.phys_to_raw(float(new_vmax))
        struct.pack_into("<H", data, off, raw & 0xFFFF)
        return True, new_vmax

    def _raise_rpm_limit(
        self, data: bytearray, profile: ECUProfile, extra_rpm: int
    ) -> Tuple[bool, int]:
        """Raise the rev limiter by *extra_rpm* (capped at absolute max)."""
        ms = profile.maps.get("NMAX")
        if ms is None:
            return False, 0

        off = self._locate_map(bytes(data), ms)
        if off is None:
            return False, 0

        current_raw = struct.unpack_from("<H", data, off)[0]
        current_rpm = int(ms.raw_to_phys(current_raw))
        new_rpm     = min(current_rpm + extra_rpm, self._ABSOLUTE_RPM_MAX, int(ms.phys_max))
        struct.pack_into("<H", data, off, ms.phys_to_raw(float(new_rpm)) & 0xFFFF)
        return True, new_rpm

    # ------------------------------------------------------------------
    # Checksum repair
    # ------------------------------------------------------------------

    def _repair_checksum(self, data: bytearray, profile: ECUProfile) -> bool:
        """Recompute and write the ROM checksum.  Returns True on success."""
        algo = profile.checksum_algo
        cs_off = profile.checksum_offset

        if cs_off == 0 or cs_off + 4 > len(data):
            return False

        regions = profile.checksum_regions or [(0, cs_off)]

        if algo == "crc32":
            crc = 0
            for start, end in regions:
                crc = zlib.crc32(bytes(data[start:end]), crc) & 0xFFFFFFFF
            struct.pack_into("<I", data, cs_off, crc)
            return True

        elif algo == "sum32":
            total = 0
            for start, end in regions:
                chunk = bytes(data[start:end])
                for i in range(0, len(chunk) - 3, 4):
                    total = (total + struct.unpack_from("<I", chunk, i)[0]) & 0xFFFFFFFF
            struct.pack_into("<I", data, cs_off, total)
            return True

        elif algo == "xor8":
            xv = 0
            for start, end in regions:
                for b in data[start:end]:
                    xv ^= b
            data[cs_off] = xv & 0xFF
            return True

        elif algo == "add16":
            total = 0
            for start, end in regions:
                chunk = bytes(data[start:end])
                for i in range(0, len(chunk) - 1, 2):
                    total = (total + struct.unpack_from("<H", chunk, i)[0]) & 0xFFFF
            struct.pack_into("<H", data, cs_off, total)
            return True

        return False


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _with_offset(ms: MapSpec, offset: int) -> MapSpec:
    """Return a copy of *ms* with ``hint_offset`` set to *offset*."""
    import dataclasses
    return dataclasses.replace(ms, hint_offset=offset)
