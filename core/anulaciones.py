"""
anulaciones.py - ECU cancellations / deletes engine.

Supported cancellations
-----------------------
  DPF          Diesel Particulate Filter — disable regen & pressure monitoring
  EGR          Exhaust Gas Recirculation — zero duty map, disable valve DTC
  LAMBDA       Lambda / O2 sensor — switch to permanent open loop
  SWIRL_FLAP   Swirl / tumble flap actuator — disable and block DTC
  SAP          Secondary Air Pump — disable pump and disable DTC P0410
  SPEED_LIMITER Remove vmax / speed limiter
  TORQUE_LIMIT  Remove gearbox-protection torque cap
  RPM_LIMIT     Raise rev limiter to ECU hard limit
  ADBLUE        AdBlue / SCR / NOx — disable dosing and sensor
  CAT           Catalyst efficiency monitor — disable P0420/P0430
  FLAP_EGR      EGR flap actuator — separate from EGR valve delete
  SAI           Secondary Air Injection system

Each cancellation is performed by:
  1. Zeroing or patching the relevant calibration map (e.g. EGR map → zeros).
  2. Patching DTC enable/disable byte patterns when known.
  3. Writing a checksum correction.

Usage
-----
>>> eng    = AnulacionEngine()
>>> result = eng.apply(rom_bytes, [Cancellation.EGR, Cancellation.DPF], profile)
>>> Path("modified.bin").write_bytes(result.data)
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from formats.ecu_profiles import (
    Cancellation, CancellationSpec, ECUProfile, ECUFamily,
    MapSpec, MapCategory, get_profile
)
from core.tune_engine import TuneEngine, _with_offset
from utils.log_utils import BinModderLogger

log = BinModderLogger.get("core.anulaciones")


# ---------------------------------------------------------------------------
# Known DTC byte-pair patterns (enable byte → disable byte)
# These are generic Bosch patterns; the engine scans for them.
# ---------------------------------------------------------------------------

# DTC enable byte sequences (pattern → replacement)
_DTC_DISABLE_PATTERNS: Dict[str, List[Tuple[bytes, bytes]]] = {
    # EGR-related faults
    Cancellation.EGR.value: [
        (b"\x40\x00\x04", b"\x00\x00\x00"),  # EGR position fault mask
        (b"\x60\x00\x04", b"\x00\x00\x00"),
    ],
    # DPF-related faults
    Cancellation.DPF.value: [
        (b"\x80\x00\x02", b"\x00\x00\x00"),  # DPF diff-pressure fault mask
        (b"\x80\x00\x04", b"\x00\x00\x00"),
    ],
    # Lambda / O2 sensor faults
    Cancellation.LAMBDA.value: [
        (b"\x10\x00\x01", b"\x00\x00\x00"),  # Rear lambda fault mask
        (b"\x20\x00\x01", b"\x00\x00\x00"),
    ],
    # SAP faults
    Cancellation.SAP.value: [
        (b"\x08\x00\x04", b"\x00\x00\x00"),
    ],
    # Catalyst efficiency
    Cancellation.CAT.value: [
        (b"\x01\x00\x04", b"\x00\x00\x00"),
    ],
    # AdBlue / SCR
    Cancellation.ADBLUE.value: [
        (b"\x02\x00\x08", b"\x00\x00\x00"),
        (b"\x04\x00\x08", b"\x00\x00\x00"),
    ],
}


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass
class AnulacionResult:
    """Output of a cancellation operation.

    Attributes
    ----------
    data : bytes
        Modified ROM bytes.
    applied : list[Cancellation]
        Cancellations that were applied.
    skipped : list[Cancellation]
        Cancellations not available for this ECU profile.
    partial : list[Cancellation]
        Partially applied (map zeroed but DTC patch not found).
    log : str
        Human-readable operation log.
    warnings : list[str]
    checksum_repaired : bool
    """
    data:              bytes
    applied:           List[Cancellation] = field(default_factory=list)
    skipped:           List[Cancellation] = field(default_factory=list)
    partial:           List[Cancellation] = field(default_factory=list)
    changes:           List[str]          = field(default_factory=list)
    warnings:          List[str]          = field(default_factory=list)
    checksum_repaired: bool               = False

    @property
    def log(self) -> str:
        return "\n".join(self.changes)


# ---------------------------------------------------------------------------
# AnulacionEngine
# ---------------------------------------------------------------------------

class AnulacionEngine:
    """Apply ECU cancellations / deletes to a ROM binary.

    Parameters
    ----------
    auto_checksum : bool
        Repair ROM checksum after all modifications (default True).
    """

    def __init__(self, auto_checksum: bool = True) -> None:
        self._auto_cs  = auto_checksum
        self._tune_eng = TuneEngine(auto_checksum=False)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def apply(
        self,
        data:         bytes,
        cancellations: List[Cancellation],
        profile:      Optional[ECUProfile] = None,
    ) -> AnulacionResult:
        """Apply one or more cancellations to *data*.

        Parameters
        ----------
        data : bytes
            Original ROM bytes.
        cancellations : list[Cancellation]
            Which cancellations to perform.
        profile : ECUProfile | None
            Auto-detected if None.
        """
        data    = bytearray(data)
        profile = profile or get_profile(bytes(data))

        ops:     List[str]         = []
        applied: List[Cancellation] = []
        skipped: List[Cancellation] = []
        partial: List[Cancellation] = []
        warns:   List[str]         = []

        if profile is None:
            return AnulacionResult(
                data=bytes(data),
                warnings=["Unknown ECU profile – no cancellations applied."],
            )

        ops.append(f"▶  Anulaciones sobre {profile.name}")
        ops.append(f"   Cancelaciones solicitadas: {', '.join(c.value for c in cancellations)}")
        ops.append("")

        for cancel in cancellations:
            spec = profile.cancellations.get(cancel)
            if spec is None:
                ops.append(f"   ─ {cancel.value.upper():16s} – no definido para este perfil ECU")
                skipped.append(cancel)
                continue

            ops.append(f"   ► {spec.name}")

            ok_map  = self._apply_map_zeros(data, spec, profile, ops)
            ok_dtc  = self._apply_dtc_disable(data, cancel, ops) if spec.dtc_disable else True
            ok_patch= self._apply_patches(data, spec, ops)

            # Special handlers
            if cancel == Cancellation.SPEED_LIMITER:
                ok_map = self._apply_speed_delete(data, profile, ops)
            elif cancel == Cancellation.TORQUE_LIMIT:
                ok_map = self._apply_torque_delete(data, profile, ops)
            elif cancel == Cancellation.RPM_LIMIT:
                ok_map = self._apply_rpm_raise(data, profile, ops)

            if ok_map or ok_dtc or ok_patch:
                if ok_map and (not spec.dtc_disable or ok_dtc):
                    applied.append(cancel)
                    ops.append(f"     ✓ Completado")
                else:
                    partial.append(cancel)
                    ops.append(f"     ⚠  Parcial – algunos cambios no aplicados")
                    if not ok_dtc:
                        warns.append(
                            f"{cancel.value}: patrones DTC no encontrados en este firmware. "
                            "El mapa fue modificado pero los DTCs pueden seguir activos."
                        )
            else:
                skipped.append(cancel)
                ops.append(f"     ✗ No se pudo aplicar – mapas no localizados")
                warns.append(
                    f"{cancel.value}: mapas no encontrados. "
                    "Puede ser necesario un perfil de offset específico para este firmware."
                )
            ops.append("")

        # Checksum repair
        cs_ok = False
        if self._auto_cs and (applied or partial):
            cs_ok = self._tune_eng._repair_checksum(data, profile)
            ops.append(f"   {'✓' if cs_ok else '✗'} Checksum {'reparado' if cs_ok else 'reparación no disponible'}")

        # Summary
        ops.append("")
        ops.append(f"   Aplicadas : {len(applied)}")
        ops.append(f"   Parciales : {len(partial)}")
        ops.append(f"   Omitidas  : {len(skipped)}")

        return AnulacionResult(
            data              = bytes(data),
            applied           = applied,
            skipped           = skipped,
            partial           = partial,
            changes           = ops,
            warnings          = warns,
            checksum_repaired = cs_ok,
        )

    # ------------------------------------------------------------------
    # Map zero-fill
    # ------------------------------------------------------------------

    def _apply_map_zeros(
        self, data: bytearray, spec: CancellationSpec,
        profile: ECUProfile, ops: List[str]
    ) -> bool:
        """Zero out all maps listed in spec.zero_maps. Returns True if any found."""
        if not spec.zero_maps:
            return True   # nothing to zero – not a failure

        any_found = False
        for map_name in spec.zero_maps:
            ms = profile.maps.get(map_name)
            if ms is None:
                ops.append(f"     ✗ Mapa '{map_name}' no en perfil")
                continue
            off = self._tune_eng._locate_map(bytes(data), ms)
            if off is None:
                ops.append(f"     ✗ Mapa '{map_name}' – no localizado en binario")
                continue
            # Zero fill
            end = off + ms.data_bytes
            if end <= len(data):
                data[off:end] = b"\x00" * ms.data_bytes
                any_found = True
                ops.append(f"     ✓ '{map_name}' zeroed ({ms.data_bytes} bytes @ 0x{off:08X})")

        return any_found

    # ------------------------------------------------------------------
    # DTC disable (pattern search & replace)
    # ------------------------------------------------------------------

    def _apply_dtc_disable(
        self, data: bytearray, cancel: Cancellation, ops: List[str]
    ) -> bool:
        """Search for DTC enable patterns and replace with zeros."""
        patterns = _DTC_DISABLE_PATTERNS.get(cancel.value, [])
        if not patterns:
            return True   # no patterns known – assume OK

        patched = 0
        for pattern, replacement in patterns:
            idx = 0
            while True:
                pos = bytes(data).find(pattern, idx)
                if pos == -1:
                    break
                data[pos : pos + len(replacement)] = replacement
                patched += 1
                idx = pos + len(replacement)

        if patched:
            ops.append(f"     ✓ DTC: {patched} patrón(es) deshabilitado(s)")
        else:
            ops.append(f"     ─ DTC: patrones no encontrados en este firmware")
        return True   # not finding patterns is non-fatal

    # ------------------------------------------------------------------
    # Raw byte patches from profile spec
    # ------------------------------------------------------------------

    def _apply_patches(
        self, data: bytearray, spec: CancellationSpec, ops: List[str]
    ) -> bool:
        """Apply raw offset-based patches from CancellationSpec.patches."""
        if not spec.patches:
            return True

        applied = 0
        for hint_off, pattern, replacement in spec.patches:
            # Search near hint_off ± 512 bytes (or whole ROM if hint=0)
            search_start = max(0, hint_off - 512) if hint_off else 0
            search_end   = min(len(data), hint_off + 512) if hint_off else len(data)
            chunk = bytes(data[search_start:search_end])
            idx   = chunk.find(pattern)
            if idx != -1:
                abs_off = search_start + idx
                if abs_off + len(replacement) <= len(data):
                    data[abs_off : abs_off + len(replacement)] = replacement
                    applied += 1

        if applied:
            ops.append(f"     ✓ {applied} parche(s) raw aplicado(s)")
        return True

    # ------------------------------------------------------------------
    # Special cancellation handlers
    # ------------------------------------------------------------------

    def _apply_speed_delete(
        self, data: bytearray, profile: ECUProfile, ops: List[str]
    ) -> bool:
        """Set VMAX scalar to the physical maximum."""
        ms = profile.maps.get("VMAX")
        if ms is None:
            ops.append("     ─ VMAX scalar no definido en perfil")
            return False

        off = self._tune_eng._locate_map(bytes(data), ms)
        if off is None:
            ops.append("     ✗ VMAX – no localizado")
            return False

        new_val = min(int(ms.phys_max), 340)
        struct.pack_into("<H", data, off, ms.phys_to_raw(float(new_val)) & 0xFFFF)
        ops.append(f"     ✓ VMAX → {new_val} km/h @ 0x{off:08X}")
        return True

    def _apply_torque_delete(
        self, data: bytearray, profile: ECUProfile, ops: List[str]
    ) -> bool:
        """Set all torque limit cells to their physical maximum."""
        names = [n for n, m in profile.maps.items() if m.category == MapCategory.TORQUE]
        if not names:
            ops.append("     ─ Mapa de torque no definido en perfil")
            return False

        any_done = False
        for name in names:
            ms  = profile.maps[name]
            off = self._tune_eng._locate_map(bytes(data), ms)
            if off is None:
                ops.append(f"     ✗ {name} – no localizado")
                continue
            ms_l    = _with_offset(ms, off)
            # Fill every cell with physical max
            data, n = self._tune_eng._scale_map(data, ms_l, pct=9999.0)
            # After 9999% scale, values are capped by ms.phys_max via clamp
            ops.append(f"     ✓ {name} (limitador torque) → máximo físico ({ms.phys_max:.0f} Nm)")
            any_done = True

        return any_done

    def _apply_rpm_raise(
        self, data: bytearray, profile: ECUProfile, ops: List[str]
    ) -> bool:
        """Raise rev limiter to the profile's physical maximum RPM."""
        ms = profile.maps.get("NMAX")
        if ms is None:
            ops.append("     ─ NMAX (rev limiter) no definido en perfil")
            return False

        off = self._tune_eng._locate_map(bytes(data), ms)
        if off is None:
            ops.append("     ✗ NMAX – no localizado")
            return False

        new_rpm = int(ms.phys_max)
        struct.pack_into("<H", data, off, ms.phys_to_raw(float(new_rpm)) & 0xFFFF)
        ops.append(f"     ✓ NMAX → {new_rpm} RPM @ 0x{off:08X}")
        return True


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------

def all_cancellations_for(profile: ECUProfile) -> List[Cancellation]:
    """Return the list of cancellations defined in *profile*."""
    return list(profile.cancellations.keys())
