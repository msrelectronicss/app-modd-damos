"""
ecu_profiles.py - ECU tuning profile database.

Defines per-family map specifications, stage tuning parameters,
pops & bang configs, and cancellation patch descriptors for:

  - Bosch ME7.x   (petrol, VW/Audi/Seat/Skoda 1.8T 150/180 hp, 2.0T, 2.7T)
  - Bosch ME9     (petrol, VW/Audi FSI/TFSI)
  - Bosch EDC15   (diesel TDI pump-injector / common rail)
  - Bosch EDC16   (modern diesel TDI)
  - Bosch EDC17   (latest diesel TDI, MED17 petrol)
  - Delphi DCM    (diesel DCM3.x / DCM6.x)
  - Magneti Marelli IAW/MJD  (Fiat/Alfa diesel/petrol)
  - Siemens/VDO SID (diesel Peugeot/Citroën)

All offsets are *hints* — the engine layer always confirms matches
by verifying value ranges before writing.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ECUFamily(Enum):
    UNKNOWN      = auto()
    BOSCH_ME7    = auto()
    BOSCH_ME9    = auto()
    BOSCH_EDC15  = auto()
    BOSCH_EDC16  = auto()
    BOSCH_EDC17  = auto()
    DELPHI_DCM   = auto()
    MARELLI_IAW  = auto()
    SIEMENS_SID  = auto()


class MapCategory(Enum):
    BOOST      = "boost"       # Boost pressure / charge pressure
    FUEL       = "fuel"        # Injection quantity / fuel delivery
    IGNITION   = "ignition"    # Ignition timing / advance
    TORQUE     = "torque"      # Torque limiter / request
    LAMBDA     = "lambda"      # Lambda / AFR target
    EGR        = "egr"         # EGR duty cycle / mass
    DPF        = "dpf"         # DPF regeneration / soot model
    OVERRUN    = "overrun"     # Overrun fuel cut / coast injection
    RPM_LIMIT  = "rpm_limit"   # Rev limiter
    SPEED_LIMIT= "speed_limit" # Speed (vmax) limiter
    IDLE       = "idle"        # Idle speed control
    VARIABLE   = "variable"    # Generic / uncategorised


class PopsBangLevel(Enum):
    OFF        = 0
    MILD       = 1   # Street-subtle, occasional crackles on lift-off
    MEDIUM     = 2   # Noticeable pops, fun but still driveable
    AGGRESSIVE = 3   # Continuous bangs / rally style


class StageLevel(Enum):
    STAGE1 = 1   # Software-only, stock hardware, safe for daily use
    STAGE2 = 2   # Requires upgraded intake / exhaust / intercooler
    STAGE3 = 3   # Full build: turbo upgrade, fuelling, forged internals


class Cancellation(Enum):
    DPF          = "dpf"          # Diesel Particulate Filter delete
    EGR          = "egr"          # Exhaust Gas Recirculation delete
    LAMBDA       = "lambda"       # O2 / Lambda sensor delete (open loop)
    SWIRL_FLAP   = "swirl"        # Swirl / tumble flap delete
    SAP          = "sap"          # Secondary Air Pump delete
    SPEED_LIMITER= "vmax"         # vmax / speed limiter delete
    TORQUE_LIMIT = "torque"       # Torque limiter delete
    RPM_LIMIT    = "rpm"          # Rev limiter raise (to rated max)
    ADBLUE       = "adblue"       # AdBlue / SCR / NOx catalyst delete
    CAT          = "cat"          # Catalyst efficiency monitor delete
    FLAP_EGR     = "flap_egr"     # EGR flap actuator delete
    SAI          = "sai"          # Secondary Air Injection delete
    HOT_START    = "hot_start"    # Hot-start enrichment remove
    IDLE_UP      = "idle_up"      # A/C idle-up disable


# ---------------------------------------------------------------------------
# Map specification
# ---------------------------------------------------------------------------

@dataclass
class MapSpec:
    """Specification for a calibration map inside an ECU binary.

    Attributes
    ----------
    name : str
        Internal map identifier (e.g., ``"KFMIOP"``).
    description : str
        Human-readable description.
    category : MapCategory
    rows : int
    cols : int
    element_size : int
        Bytes per element (1 = uint8/int8, 2 = uint16/int16, 4 = uint32/int32).
    signed : bool
    factor : float
        Physical = raw × factor + bias.
    bias : float
    units : str
    phys_min : float
        Minimum valid physical value (safety clamp).
    phys_max : float
        Maximum physical value allowed when writing.
    hint_offset : int
        Known ROM offset (0 = use search_pattern only).
    search_pattern : bytes | None
        Byte sequence immediately before the map data (axis header, etc.)
        used to locate the map when the offset is unknown.
    """
    name:           str
    description:    str
    category:       MapCategory
    rows:           int
    cols:           int
    element_size:   int   = 2
    signed:         bool  = False
    factor:         float = 1.0
    bias:           float = 0.0
    units:          str   = ""
    phys_min:       float = 0.0
    phys_max:       float = 65535.0
    hint_offset:    int   = 0
    search_pattern: Optional[bytes] = None

    # Derived ----------------------------------------------------------------

    @property
    def data_bytes(self) -> int:
        return self.rows * self.cols * self.element_size

    def raw_to_phys(self, raw: int) -> float:
        return raw * self.factor + self.bias

    def phys_to_raw(self, phys: float) -> int:
        return int((phys - self.bias) / self.factor)

    def clamp_phys(self, phys: float) -> float:
        return max(self.phys_min, min(self.phys_max, phys))


# ---------------------------------------------------------------------------
# Cancellation patch descriptor
# ---------------------------------------------------------------------------

@dataclass
class CancellationSpec:
    """Describes a binary patch that implements a cancellation/delete.

    Some cancellations are a simple NOP (zero-fill), others require
    specific replacement bytes. ``patches`` is a list of
    (offset_hint, original_pattern, replacement_bytes) tuples.
    The engine searches for *original_pattern* near *offset_hint*
    (or anywhere if hint == 0) and replaces it with *replacement*.
    """
    name:        str
    description: str
    cancellation: Cancellation
    # List of (hint_offset, pattern_to_find, replacement)
    patches:     List[Tuple[int, bytes, bytes]] = field(default_factory=list)
    # For map-based cancellations: zero out the whole map
    zero_maps:   List[str] = field(default_factory=list)  # map names
    dtc_disable: bool = True   # also disable related DTCs when possible


# ---------------------------------------------------------------------------
# Stage tuning parameters
# ---------------------------------------------------------------------------

@dataclass
class StageSpec:
    """Parameters for a single tuning stage.

    All percentage values are *increases* relative to stock.
    ``None`` means "do not modify this map".
    """
    level:          StageLevel
    description:    str
    boost_pct:      Optional[float] = None   # % increase, e.g. 15.0
    fuel_pct:       Optional[float] = None   # % increase in high-load zones
    ignition_deg:   Optional[float] = None   # degrees advance to add
    torque_pct:     Optional[float] = None   # % raise on torque limit
    rpm_raise:      Optional[int]   = None   # extra RPM on rev limiter
    remove_vmax:    bool            = False  # delete speed limiter
    lambda_leaner:  Optional[float] = None  # target lambda offset (positive = leaner)
    # Power / torque estimates
    power_gain_hp:  Optional[int]   = None
    torque_gain_nm: Optional[int]   = None


# ---------------------------------------------------------------------------
# Full ECU profile
# ---------------------------------------------------------------------------

@dataclass
class ECUProfile:
    """Complete tuning profile for an ECU family / variant.

    Attributes
    ----------
    name : str
        Human-readable name, e.g. ``"Bosch ME7.5 – VW/Audi 1.8T"``.
    family : ECUFamily
    file_sizes : list[int]
        Valid ROM sizes in bytes.
    identification_strings : list[str | bytes]
        Strings (ASCII) or byte sequences that confirm this profile.
    vin_offset : int
        ROM offset where the 17-byte VIN ASCII string is stored.
        0 = search the whole ROM for the standard VIN pattern.
    sw_offset : int
        ROM offset of the software part number string. 0 = search.
    hw_offset : int
        ROM offset of the hardware part number string. 0 = search.
    cal_id_offset : int
        ROM offset of the calibration / software ID. 0 = search.
    checksum_regions : list[tuple[int,int]]
        List of (start, end) byte ranges used to compute the checksum.
    checksum_offset : int
        Where the checksum value lives in the ROM.
    checksum_algo : str
        Algorithm: "sum32", "crc32", "xor8", "xor16", "add16".
    maps : dict[str, MapSpec]
        Key = map name, value = MapSpec.
    cancellations : dict[Cancellation, CancellationSpec]
    stages : dict[StageLevel, StageSpec]
    """
    name:                    str
    family:                  ECUFamily
    file_sizes:              List[int]
    identification_strings:  List[bytes]          = field(default_factory=list)
    vin_offset:              int                  = 0
    sw_offset:               int                  = 0
    hw_offset:               int                  = 0
    cal_id_offset:           int                  = 0
    checksum_regions:        List[Tuple[int,int]] = field(default_factory=list)
    checksum_offset:         int                  = 0
    checksum_algo:           str                  = "sum32"
    maps:                    Dict[str, MapSpec]   = field(default_factory=dict)
    cancellations:           Dict[Cancellation, CancellationSpec] = field(default_factory=dict)
    stages:                  Dict[StageLevel, StageSpec]          = field(default_factory=dict)


# ===========================================================================
# Profile definitions
# ===========================================================================

# ---------------------------------------------------------------------------
# Bosch ME7.x  – VW/Audi/Seat/Skoda petrol (1.8T, 2.0, 2.7T, 3.0)
# ---------------------------------------------------------------------------
_ME7_MAPS: Dict[str, MapSpec] = {
    # Boost pressure target map (charge pressure controller set-point)
    "KFMIOP": MapSpec(
        name="KFMIOP", description="Boost Pressure Target Map (16×16)",
        category=MapCategory.BOOST,
        rows=16, cols=16, element_size=2, signed=False,
        factor=1.0, bias=0.0, units="mbar",
        phys_min=850.0, phys_max=3000.0,
        hint_offset=0x0,
        search_pattern=None,
    ),
    # Ignition timing (base advance) map
    "KFZW": MapSpec(
        name="KFZW", description="Base Ignition Timing Map (16×16)",
        category=MapCategory.IGNITION,
        rows=16, cols=16, element_size=2, signed=True,
        factor=0.75, bias=0.0, units="°BTDC",
        phys_min=-10.0, phys_max=60.0,
        hint_offset=0x0,
    ),
    # Idle ignition map
    "KFZWOP": MapSpec(
        name="KFZWOP", description="Idle Ignition Map (8×8)",
        category=MapCategory.IGNITION,
        rows=8, cols=8, element_size=2, signed=True,
        factor=0.75, bias=0.0, units="°BTDC",
        phys_min=-10.0, phys_max=45.0,
        hint_offset=0x0,
    ),
    # Load/fuel mass map (hot film air-mass based)
    "KFKHFM": MapSpec(
        name="KFKHFM", description="Air Mass / Load Map (16×16)",
        category=MapCategory.FUEL,
        rows=16, cols=16, element_size=2, signed=False,
        factor=1.0, bias=0.0, units="mg/H",
        phys_min=0.0, phys_max=12000.0,
        hint_offset=0x0,
    ),
    # Torque limiter (max engine torque by gear)
    "MXKWUN": MapSpec(
        name="MXKWUN", description="Max Torque Limit (gearbox protection) 8×1",
        category=MapCategory.TORQUE,
        rows=1, cols=8, element_size=2, signed=False,
        factor=1.0, bias=0.0, units="Nm",
        phys_min=0.0, phys_max=500.0,
        hint_offset=0x0,
    ),
    # Lambda target map (closed loop AFR target)
    "KFLAMA": MapSpec(
        name="KFLAMA", description="Lambda Target Map (8×8)",
        category=MapCategory.LAMBDA,
        rows=8, cols=8, element_size=2, signed=False,
        factor=0.001, bias=0.0, units="λ",
        phys_min=0.7, phys_max=1.3,
        hint_offset=0x0,
    ),
    # Overrun fuel cut-off threshold (RPM at which fuel is re-enabled)
    "NWNS": MapSpec(
        name="NWNS", description="Overrun Fuel Cut Re-enable RPM (1×1 scalar)",
        category=MapCategory.OVERRUN,
        rows=1, cols=1, element_size=2, signed=False,
        factor=1.0, bias=0.0, units="RPM",
        phys_min=500.0, phys_max=4000.0,
        hint_offset=0x0,
    ),
    # Speed limiter (single word)
    "VMAX": MapSpec(
        name="VMAX", description="Speed Limiter Value (km/h scalar)",
        category=MapCategory.SPEED_LIMIT,
        rows=1, cols=1, element_size=2, signed=False,
        factor=1.0, bias=0.0, units="km/h",
        phys_min=0.0, phys_max=350.0,
        hint_offset=0x0,
    ),
    # Rev limiter
    "NMAX": MapSpec(
        name="NMAX", description="Rev Limiter (RPM scalar)",
        category=MapCategory.RPM_LIMIT,
        rows=1, cols=1, element_size=2, signed=False,
        factor=1.0, bias=0.0, units="RPM",
        phys_min=1000.0, phys_max=9000.0,
        hint_offset=0x0,
    ),
    # Overrun ignition retard map (for pops & bang)
    "KFZWOK": MapSpec(
        name="KFZWOK", description="Overrun Ignition Retard Map (8×8)",
        category=MapCategory.OVERRUN,
        rows=8, cols=8, element_size=2, signed=True,
        factor=0.75, bias=0.0, units="°",
        phys_min=-40.0, phys_max=20.0,
        hint_offset=0x0,
    ),
}

_ME7_STAGES = {
    StageLevel.STAGE1: StageSpec(
        level=StageLevel.STAGE1,
        description="Stage 1 – Software only. Requires stock hardware. Safe for daily use.",
        boost_pct=15.0,
        fuel_pct=8.0,
        ignition_deg=2.0,
        torque_pct=20.0,
        rpm_raise=200,
        remove_vmax=True,
        power_gain_hp=30,
        torque_gain_nm=55,
    ),
    StageLevel.STAGE2: StageSpec(
        level=StageLevel.STAGE2,
        description="Stage 2 – Upgraded intake, exhaust, intercooler required.",
        boost_pct=28.0,
        fuel_pct=15.0,
        ignition_deg=3.0,
        torque_pct=40.0,
        rpm_raise=400,
        remove_vmax=True,
        power_gain_hp=55,
        torque_gain_nm=90,
    ),
    StageLevel.STAGE3: StageSpec(
        level=StageLevel.STAGE3,
        description="Stage 3 – Hybrid/upgraded turbo, high-flow fuel system, forged internals.",
        boost_pct=50.0,
        fuel_pct=30.0,
        ignition_deg=2.0,
        torque_pct=70.0,
        rpm_raise=600,
        remove_vmax=True,
        power_gain_hp=110,
        torque_gain_nm=160,
    ),
}

_ME7_CANCELLATIONS = {
    Cancellation.SPEED_LIMITER: CancellationSpec(
        name="Speed Limiter Delete",
        description="Remove vmax (speed) limiter. Car will no longer cut at factory limit.",
        cancellation=Cancellation.SPEED_LIMITER,
        zero_maps=["VMAX"],
    ),
    Cancellation.TORQUE_LIMIT: CancellationSpec(
        name="Torque Limiter Delete",
        description="Remove gearbox-protection torque cap (MXKWUN). Use with caution on stock gearbox.",
        cancellation=Cancellation.TORQUE_LIMIT,
        zero_maps=[],
        patches=[],   # handled by map scaling to max
    ),
    Cancellation.SAP: CancellationSpec(
        name="Secondary Air Pump Delete",
        description="Disable SAP control and associated DTCs (P0410 etc.).",
        cancellation=Cancellation.SAP,
        patches=[],
        dtc_disable=True,
    ),
    Cancellation.LAMBDA: CancellationSpec(
        name="Lambda / O2 Delete (open loop)",
        description="Switch ECU to permanent open-loop (no rear lambda DTC).",
        cancellation=Cancellation.LAMBDA,
        zero_maps=[],
        dtc_disable=True,
    ),
    Cancellation.CAT: CancellationSpec(
        name="Catalyst Efficiency Monitor Delete",
        description="Disable catalyst efficiency check (P0420/P0430). Does not affect fuelling.",
        cancellation=Cancellation.CAT,
        patches=[],
        dtc_disable=True,
    ),
    Cancellation.SAI: CancellationSpec(
        name="Secondary Air Injection Delete",
        description="Disable secondary air injection system monitoring.",
        cancellation=Cancellation.SAI,
        patches=[],
        dtc_disable=True,
    ),
}

PROFILE_BOSCH_ME7 = ECUProfile(
    name="Bosch ME7.x – VW/Audi/Seat/Skoda petrol",
    family=ECUFamily.BOSCH_ME7,
    file_sizes=[262144, 524288],                     # 256 KB, 512 KB
    identification_strings=[b"ME7.", b"0 261 2"],
    vin_offset=0,                                     # search
    sw_offset=0,
    hw_offset=0,
    cal_id_offset=0,
    checksum_regions=[(0x0000, 0x7FF0)],
    checksum_offset=0x7FF0,
    checksum_algo="sum32",
    maps=_ME7_MAPS,
    cancellations=_ME7_CANCELLATIONS,
    stages=_ME7_STAGES,
)


# ---------------------------------------------------------------------------
# Bosch EDC15  – VW TDI diesel (pump-injector / early common rail)
# ---------------------------------------------------------------------------
_EDC15_MAPS: Dict[str, MapSpec] = {
    "IQ_MAP": MapSpec(
        name="IQ_MAP", description="Injection Quantity Map – full load (16×16)",
        category=MapCategory.FUEL,
        rows=16, cols=16, element_size=2, signed=False,
        factor=0.1, bias=0.0, units="mg/str",
        phys_min=0.0, phys_max=200.0,
        hint_offset=0x0,
    ),
    "BOOST_MAP": MapSpec(
        name="BOOST_MAP", description="Boost Pressure Target Map (16×16)",
        category=MapCategory.BOOST,
        rows=16, cols=16, element_size=2, signed=False,
        factor=1.0, bias=0.0, units="mbar",
        phys_min=900.0, phys_max=2800.0,
        hint_offset=0x0,
    ),
    "EGR_MAP": MapSpec(
        name="EGR_MAP", description="EGR Duty Cycle Map (8×8)",
        category=MapCategory.EGR,
        rows=8, cols=8, element_size=2, signed=False,
        factor=0.39, bias=0.0, units="%",
        phys_min=0.0, phys_max=100.0,
        hint_offset=0x0,
    ),
    "START_IQ": MapSpec(
        name="START_IQ", description="Start Injection Quantity (cranking)",
        category=MapCategory.FUEL,
        rows=1, cols=8, element_size=2, signed=False,
        factor=0.1, bias=0.0, units="mg/str",
        phys_min=0.0, phys_max=80.0,
        hint_offset=0x0,
    ),
    "SMOKE_LIMITER": MapSpec(
        name="SMOKE_LIMITER", description="Smoke / Air-Fuel Ratio Limiter Map (16×1)",
        category=MapCategory.FUEL,
        rows=1, cols=16, element_size=2, signed=False,
        factor=0.1, bias=0.0, units="mg/str",
        phys_min=0.0, phys_max=200.0,
        hint_offset=0x0,
    ),
    "VMAX": MapSpec(
        name="VMAX", description="Speed Limiter (km/h)",
        category=MapCategory.SPEED_LIMIT,
        rows=1, cols=1, element_size=2, signed=False,
        factor=1.0, bias=0.0, units="km/h",
        phys_min=0.0, phys_max=350.0,
        hint_offset=0x0,
    ),
    "NMAX": MapSpec(
        name="NMAX", description="Rev Limiter (RPM)",
        category=MapCategory.RPM_LIMIT,
        rows=1, cols=1, element_size=2, signed=False,
        factor=1.0, bias=0.0, units="RPM",
        phys_min=500.0, phys_max=6500.0,
        hint_offset=0x0,
    ),
}

_EDC15_STAGES = {
    StageLevel.STAGE1: StageSpec(
        level=StageLevel.STAGE1,
        description="Stage 1 – Software remap. Stock airbox, standard DPF-delete or DPF intact.",
        boost_pct=18.0,
        fuel_pct=20.0,
        ignition_deg=None,   # diesel – no spark ignition
        torque_pct=25.0,
        rpm_raise=200,
        remove_vmax=True,
        power_gain_hp=35,
        torque_gain_nm=80,
    ),
    StageLevel.STAGE2: StageSpec(
        level=StageLevel.STAGE2,
        description="Stage 2 – High-flow air filter, larger intercooler, EGR/DPF deleted.",
        boost_pct=30.0,
        fuel_pct=35.0,
        ignition_deg=None,
        torque_pct=45.0,
        rpm_raise=300,
        remove_vmax=True,
        power_gain_hp=60,
        torque_gain_nm=130,
    ),
    StageLevel.STAGE3: StageSpec(
        level=StageLevel.STAGE3,
        description="Stage 3 – Injector upgrade, larger turbo, strengthened internals.",
        boost_pct=55.0,
        fuel_pct=60.0,
        ignition_deg=None,
        torque_pct=80.0,
        rpm_raise=500,
        remove_vmax=True,
        power_gain_hp=100,
        torque_gain_nm=220,
    ),
}

_EDC15_CANCELLATIONS = {
    Cancellation.EGR: CancellationSpec(
        name="EGR Delete",
        description="Zero out EGR duty cycle map. Disable EGR valve position DTC.",
        cancellation=Cancellation.EGR,
        zero_maps=["EGR_MAP"],
        dtc_disable=True,
    ),
    Cancellation.DPF: CancellationSpec(
        name="DPF Delete",
        description="Disable DPF differential pressure monitoring and regen. Disable P242F etc.",
        cancellation=Cancellation.DPF,
        zero_maps=[],
        dtc_disable=True,
    ),
    Cancellation.SPEED_LIMITER: CancellationSpec(
        name="Speed Limiter Delete",
        description="Remove vmax limiter. Set VMAX to 250 km/h.",
        cancellation=Cancellation.SPEED_LIMITER,
        zero_maps=[],
        dtc_disable=False,
    ),
    Cancellation.SWIRL_FLAP: CancellationSpec(
        name="Swirl Flap Delete",
        description="Disable swirl/tumble flap actuator and associated DTC.",
        cancellation=Cancellation.SWIRL_FLAP,
        patches=[],
        dtc_disable=True,
    ),
}

PROFILE_BOSCH_EDC15 = ECUProfile(
    name="Bosch EDC15 – VW/Audi TDI diesel",
    family=ECUFamily.BOSCH_EDC15,
    file_sizes=[524288],                               # 512 KB
    identification_strings=[b"EDC15", b"0 281 0"],
    vin_offset=0,
    sw_offset=0,
    hw_offset=0,
    cal_id_offset=0,
    checksum_regions=[(0x0000, 0x7FFC)],
    checksum_offset=0x7FFC,
    checksum_algo="crc32",
    maps=_EDC15_MAPS,
    cancellations=_EDC15_CANCELLATIONS,
    stages=_EDC15_STAGES,
)


# ---------------------------------------------------------------------------
# Bosch EDC16  – modern VW/Audi/BMW diesel
# ---------------------------------------------------------------------------
_EDC16_MAPS: Dict[str, MapSpec] = {
    "IQ_MAP": MapSpec(
        name="IQ_MAP", description="Injection Quantity Map – full load (16×16)",
        category=MapCategory.FUEL,
        rows=16, cols=16, element_size=2, signed=False,
        factor=0.1, bias=0.0, units="mg/str",
        phys_min=0.0, phys_max=200.0,
    ),
    "BOOST_MAP": MapSpec(
        name="BOOST_MAP", description="Boost Pressure Target (16×16)",
        category=MapCategory.BOOST,
        rows=16, cols=16, element_size=2, signed=False,
        factor=1.0, bias=0.0, units="mbar",
        phys_min=900.0, phys_max=3000.0,
    ),
    "EGR_MAP": MapSpec(
        name="EGR_MAP", description="EGR Rate Map (8×8)",
        category=MapCategory.EGR,
        rows=8, cols=8, element_size=2, signed=False,
        factor=0.39, bias=0.0, units="%",
        phys_min=0.0, phys_max=100.0,
    ),
    "SMOKE_LIMITER": MapSpec(
        name="SMOKE_LIMITER", description="Smoke Limiter (16×1)",
        category=MapCategory.FUEL,
        rows=1, cols=16, element_size=2, signed=False,
        factor=0.1, bias=0.0, units="mg/str",
        phys_min=0.0, phys_max=250.0,
    ),
    "TORQUE_MAP": MapSpec(
        name="TORQUE_MAP", description="Driver Torque Request Map (16×16)",
        category=MapCategory.TORQUE,
        rows=16, cols=16, element_size=2, signed=False,
        factor=1.0, bias=0.0, units="Nm",
        phys_min=0.0, phys_max=600.0,
    ),
    "VMAX": MapSpec(
        name="VMAX", description="Speed Limiter (km/h)",
        category=MapCategory.SPEED_LIMIT,
        rows=1, cols=1, element_size=2, signed=False,
        factor=1.0, bias=0.0, units="km/h",
        phys_min=0.0, phys_max=350.0,
    ),
}

_EDC16_STAGES = {
    StageLevel.STAGE1: StageSpec(
        level=StageLevel.STAGE1,
        description="Stage 1 – Software remap. Stock hardware.",
        boost_pct=20.0, fuel_pct=22.0, ignition_deg=None,
        torque_pct=25.0, rpm_raise=200, remove_vmax=True,
        power_gain_hp=40, torque_gain_nm=90,
    ),
    StageLevel.STAGE2: StageSpec(
        level=StageLevel.STAGE2,
        description="Stage 2 – Intake + intercooler + EGR/DPF delete.",
        boost_pct=35.0, fuel_pct=38.0, ignition_deg=None,
        torque_pct=50.0, rpm_raise=350, remove_vmax=True,
        power_gain_hp=70, torque_gain_nm=150,
    ),
    StageLevel.STAGE3: StageSpec(
        level=StageLevel.STAGE3,
        description="Stage 3 – Injector upgrade, bigger turbo.",
        boost_pct=60.0, fuel_pct=65.0, ignition_deg=None,
        torque_pct=85.0, rpm_raise=500, remove_vmax=True,
        power_gain_hp=120, torque_gain_nm=250,
    ),
}

_EDC16_CANCELLATIONS = {
    Cancellation.EGR: CancellationSpec(
        name="EGR Delete", description="Zero EGR map, disable EGR DTC.",
        cancellation=Cancellation.EGR, zero_maps=["EGR_MAP"], dtc_disable=True,
    ),
    Cancellation.DPF: CancellationSpec(
        name="DPF Delete", description="Disable DPF regen and pressure monitoring.",
        cancellation=Cancellation.DPF, zero_maps=[], dtc_disable=True,
    ),
    Cancellation.SPEED_LIMITER: CancellationSpec(
        name="Speed Limiter Delete", description="Remove vmax.",
        cancellation=Cancellation.SPEED_LIMITER, zero_maps=[], dtc_disable=False,
    ),
    Cancellation.SWIRL_FLAP: CancellationSpec(
        name="Swirl Flap Delete", description="Disable swirl flap actuator.",
        cancellation=Cancellation.SWIRL_FLAP, patches=[], dtc_disable=True,
    ),
}

PROFILE_BOSCH_EDC16 = ECUProfile(
    name="Bosch EDC16 – VW/Audi/BMW TDI diesel",
    family=ECUFamily.BOSCH_EDC16,
    file_sizes=[1048576, 2097152],                    # 1 MB, 2 MB
    identification_strings=[b"EDC16", b"0 281 01"],
    vin_offset=0, sw_offset=0, hw_offset=0, cal_id_offset=0,
    checksum_regions=[(0x0000, 0xFFFC)],
    checksum_offset=0xFFFC,
    checksum_algo="crc32",
    maps=_EDC16_MAPS,
    cancellations=_EDC16_CANCELLATIONS,
    stages=_EDC16_STAGES,
)


# ---------------------------------------------------------------------------
# Bosch EDC17 / MED17  – latest diesel + direct-injection petrol
# ---------------------------------------------------------------------------
_EDC17_MAPS: Dict[str, MapSpec] = {
    "IQ_MAP": MapSpec(
        name="IQ_MAP", description="Injection Quantity Map (16×16)",
        category=MapCategory.FUEL,
        rows=16, cols=16, element_size=2, signed=False,
        factor=0.1, bias=0.0, units="mg/str",
        phys_min=0.0, phys_max=250.0,
    ),
    "BOOST_MAP": MapSpec(
        name="BOOST_MAP", description="Boost / Charge Pressure Target (16×16)",
        category=MapCategory.BOOST,
        rows=16, cols=16, element_size=2, signed=False,
        factor=1.0, bias=0.0, units="mbar",
        phys_min=900.0, phys_max=3500.0,
    ),
    "EGR_MAP": MapSpec(
        name="EGR_MAP", description="EGR Rate Map (8×8)",
        category=MapCategory.EGR,
        rows=8, cols=8, element_size=2, signed=False,
        factor=0.39, bias=0.0, units="%",
        phys_min=0.0, phys_max=100.0,
    ),
    "TORQUE_MAP": MapSpec(
        name="TORQUE_MAP", description="Torque Request Map (16×16)",
        category=MapCategory.TORQUE,
        rows=16, cols=16, element_size=2, signed=False,
        factor=1.0, bias=0.0, units="Nm",
        phys_min=0.0, phys_max=700.0,
    ),
    "ADBLUE_MAP": MapSpec(
        name="ADBLUE_MAP", description="AdBlue / SCR Dosing Map (8×8)",
        category=MapCategory.VARIABLE,
        rows=8, cols=8, element_size=2, signed=False,
        factor=0.1, bias=0.0, units="mg/str",
        phys_min=0.0, phys_max=100.0,
    ),
    "VMAX": MapSpec(
        name="VMAX", description="Speed Limiter (km/h)",
        category=MapCategory.SPEED_LIMIT,
        rows=1, cols=1, element_size=2, signed=False,
        factor=1.0, bias=0.0, units="km/h",
        phys_min=0.0, phys_max=350.0,
    ),
}

_EDC17_STAGES = {
    StageLevel.STAGE1: StageSpec(
        level=StageLevel.STAGE1,
        description="Stage 1 – Remap only, stock hardware.",
        boost_pct=20.0, fuel_pct=22.0, ignition_deg=None,
        torque_pct=28.0, rpm_raise=200, remove_vmax=True,
        power_gain_hp=45, torque_gain_nm=95,
    ),
    StageLevel.STAGE2: StageSpec(
        level=StageLevel.STAGE2,
        description="Stage 2 – EGR/DPF/AdBlue deleted, intake + intercooler.",
        boost_pct=38.0, fuel_pct=42.0, ignition_deg=None,
        torque_pct=55.0, rpm_raise=350, remove_vmax=True,
        power_gain_hp=80, torque_gain_nm=165,
    ),
    StageLevel.STAGE3: StageSpec(
        level=StageLevel.STAGE3,
        description="Stage 3 – Full build, nozzle/turbo upgrade.",
        boost_pct=65.0, fuel_pct=70.0, ignition_deg=None,
        torque_pct=90.0, rpm_raise=500, remove_vmax=True,
        power_gain_hp=130, torque_gain_nm=280,
    ),
}

_EDC17_CANCELLATIONS = {
    Cancellation.EGR: CancellationSpec(
        name="EGR Delete", description="Zero EGR map.",
        cancellation=Cancellation.EGR, zero_maps=["EGR_MAP"], dtc_disable=True,
    ),
    Cancellation.DPF: CancellationSpec(
        name="DPF / FAP Delete", description="Disable DPF regen, P242F, P2452.",
        cancellation=Cancellation.DPF, zero_maps=[], dtc_disable=True,
    ),
    Cancellation.ADBLUE: CancellationSpec(
        name="AdBlue / SCR Delete",
        description="Disable AdBlue dosing and NOx sensor monitoring.",
        cancellation=Cancellation.ADBLUE, zero_maps=["ADBLUE_MAP"], dtc_disable=True,
    ),
    Cancellation.SPEED_LIMITER: CancellationSpec(
        name="Speed Limiter Delete", description="Remove vmax.",
        cancellation=Cancellation.SPEED_LIMITER, zero_maps=[], dtc_disable=False,
    ),
    Cancellation.SWIRL_FLAP: CancellationSpec(
        name="Swirl Flap Delete", description="Disable swirl flap.",
        cancellation=Cancellation.SWIRL_FLAP, patches=[], dtc_disable=True,
    ),
}

PROFILE_BOSCH_EDC17 = ECUProfile(
    name="Bosch EDC17 / MED17 – VW/Audi/BMW latest diesel",
    family=ECUFamily.BOSCH_EDC17,
    file_sizes=[2097152, 4194304],                   # 2 MB, 4 MB
    identification_strings=[b"EDC17", b"MED17", b"0 281 02", b"0 261 S0"],
    vin_offset=0, sw_offset=0, hw_offset=0, cal_id_offset=0,
    checksum_regions=[(0x0000, 0x1FFFC)],
    checksum_offset=0x1FFFC,
    checksum_algo="crc32",
    maps=_EDC17_MAPS,
    cancellations=_EDC17_CANCELLATIONS,
    stages=_EDC17_STAGES,
)


# ---------------------------------------------------------------------------
# Delphi DCM3.x / DCM6.x  – PSA/Fiat diesel
# ---------------------------------------------------------------------------
PROFILE_DELPHI_DCM = ECUProfile(
    name="Delphi DCM – PSA/Fiat diesel",
    family=ECUFamily.DELPHI_DCM,
    file_sizes=[524288, 1048576],
    identification_strings=[b"DCM3", b"DCM6"],
    vin_offset=0, sw_offset=0, hw_offset=0, cal_id_offset=0,
    checksum_regions=[(0x0000, 0xFFF8)],
    checksum_offset=0xFFF8,
    checksum_algo="sum32",
    maps={
        "IQ_MAP": MapSpec(
            name="IQ_MAP", description="Injection Quantity Map (16×16)",
            category=MapCategory.FUEL,
            rows=16, cols=16, element_size=2, signed=False,
            factor=0.1, bias=0.0, units="mg/str",
            phys_min=0.0, phys_max=200.0,
        ),
        "BOOST_MAP": MapSpec(
            name="BOOST_MAP", description="Boost Target Map (16×16)",
            category=MapCategory.BOOST,
            rows=16, cols=16, element_size=2, signed=False,
            factor=1.0, bias=0.0, units="mbar",
            phys_min=900.0, phys_max=2800.0,
        ),
        "EGR_MAP": MapSpec(
            name="EGR_MAP", description="EGR Duty Map (8×8)",
            category=MapCategory.EGR,
            rows=8, cols=8, element_size=2, signed=False,
            factor=0.39, bias=0.0, units="%",
            phys_min=0.0, phys_max=100.0,
        ),
        "VMAX": MapSpec(
            name="VMAX", description="Speed Limiter (km/h)",
            category=MapCategory.SPEED_LIMIT,
            rows=1, cols=1, element_size=2, signed=False,
            factor=1.0, bias=0.0, units="km/h",
            phys_min=0.0, phys_max=350.0,
        ),
    },
    cancellations={
        Cancellation.EGR: CancellationSpec(
            name="EGR Delete", description="Zero EGR map, disable DTC.",
            cancellation=Cancellation.EGR, zero_maps=["EGR_MAP"], dtc_disable=True,
        ),
        Cancellation.DPF: CancellationSpec(
            name="DPF Delete", description="Disable DPF monitoring.",
            cancellation=Cancellation.DPF, zero_maps=[], dtc_disable=True,
        ),
        Cancellation.SPEED_LIMITER: CancellationSpec(
            name="Speed Limiter Delete", description="Remove vmax.",
            cancellation=Cancellation.SPEED_LIMITER, zero_maps=[], dtc_disable=False,
        ),
    },
    stages={
        StageLevel.STAGE1: StageSpec(
            level=StageLevel.STAGE1,
            description="Stage 1 – Software only.",
            boost_pct=18.0, fuel_pct=20.0, ignition_deg=None,
            torque_pct=22.0, rpm_raise=200, remove_vmax=True,
            power_gain_hp=30, torque_gain_nm=70,
        ),
        StageLevel.STAGE2: StageSpec(
            level=StageLevel.STAGE2,
            description="Stage 2 – EGR/DPF deleted + hardware.",
            boost_pct=32.0, fuel_pct=35.0, ignition_deg=None,
            torque_pct=45.0, rpm_raise=350, remove_vmax=True,
            power_gain_hp=55, torque_gain_nm=120,
        ),
    },
)


# ---------------------------------------------------------------------------
# Magneti Marelli IAW / MJD  – Fiat/Alfa/Lancia
# ---------------------------------------------------------------------------
PROFILE_MARELLI = ECUProfile(
    name="Magneti Marelli IAW/MJD – Fiat/Alfa/Lancia",
    family=ECUFamily.MARELLI_IAW,
    file_sizes=[524288, 1048576],
    identification_strings=[b"IAW", b"MJD"],
    vin_offset=0, sw_offset=0, hw_offset=0, cal_id_offset=0,
    checksum_regions=[(0x0000, 0x7FF8)],
    checksum_offset=0x7FF8,
    checksum_algo="xor8",
    maps={
        "FUEL_MAP": MapSpec(
            name="FUEL_MAP", description="Fuel Delivery Map (16×16)",
            category=MapCategory.FUEL,
            rows=16, cols=16, element_size=2, signed=False,
            factor=0.1, bias=0.0, units="mg/str",
            phys_min=0.0, phys_max=200.0,
        ),
        "BOOST_MAP": MapSpec(
            name="BOOST_MAP", description="Boost Pressure Map (16×16)",
            category=MapCategory.BOOST,
            rows=16, cols=16, element_size=2, signed=False,
            factor=1.0, bias=0.0, units="mbar",
            phys_min=900.0, phys_max=2800.0,
        ),
        "EGR_MAP": MapSpec(
            name="EGR_MAP", description="EGR Control Map (8×8)",
            category=MapCategory.EGR,
            rows=8, cols=8, element_size=2, signed=False,
            factor=0.39, bias=0.0, units="%",
            phys_min=0.0, phys_max=100.0,
        ),
    },
    cancellations={
        Cancellation.EGR: CancellationSpec(
            name="EGR Delete", description="Zero EGR map.",
            cancellation=Cancellation.EGR, zero_maps=["EGR_MAP"], dtc_disable=True,
        ),
        Cancellation.DPF: CancellationSpec(
            name="DPF Delete", description="Disable DPF regen.",
            cancellation=Cancellation.DPF, zero_maps=[], dtc_disable=True,
        ),
    },
    stages={
        StageLevel.STAGE1: StageSpec(
            level=StageLevel.STAGE1,
            description="Stage 1 – Software only.",
            boost_pct=15.0, fuel_pct=18.0, ignition_deg=None,
            torque_pct=20.0, rpm_raise=200, remove_vmax=True,
            power_gain_hp=25, torque_gain_nm=60,
        ),
    },
)


# ---------------------------------------------------------------------------
# Bosch ME7.5  –  1024 KB (1 MB) broadband lambda binaries
# VW/Audi/Seat 1.8T 150/180 hp with Bosch LSU4 wideband sensor
#
# Contains factory-verified code blocks for:
#   • Launch Control (pops & bangs on A/C switch)   0xA5900
#   • Multi-Map switching (6 maps via A/C / input)  0xB0200 …
#   • Ignition maps 1-4                             0xFE250, 0xFE350, 0xFE450, 0xFE550
#   • KFZW helper pointer                           0xFE700, 0xFE7E0
# ---------------------------------------------------------------------------

# Launch control + pops-on-A/C-switch machine-code block (0xA5900, 1024KB ME7.5)
_ME75_LAUNCH_CTRL_CODE = bytes.fromhex(
    "FFFF"
    "DA8A945D DA8A285B DA8A3259 FA828E26 DB00"
    "DA8AA059 FA876613 DB00"
    "DA8A5C5D DA8A4A5B FA82D825 DB00 FA827C28 DB00"
    "D70038 00F78E0460 D7008A00 F3F8F35D 4980BD01 E108"
    "D70038 00F7F80260 D7008A00 F3F8F45D 4980BD01 E108"
    "D70038 00F7F80160 D7008A00 F3F8F95D 4980BD01 E108"
    "D70038 00F7F80360 D70038 00F78E0060 D7008A00 F3F8FE5D"
    "3D08"
    "D7008A00 F2F4EC5D D70038 00F6F4D43B DB00"
    "9A276330 D70038 00F3F84F48 D7008A00 43F8F25D"
    "9D2FF2F59EF8 D70038 00F2F4D43B 40549D0B"
    "D7008A00 22F4F05D 40548D21"
    "D70038 00F3F80160 0D0A"
    "D7008A00 02F4EE5D 40549D09"
    "D70038 00F3F80260 D70038 00F7F80460"
    "0D40 E7F88000 75F8C2F7 E7F89A00 F7F8C3F7"
    "D70038 00F78E0460 0D37"
    "9A27 2930 8A272210 F2F49EF8"
    "D7008A00 42F4F65D FD1B F3F8B189"
    "D7008A00 43F8F55D FD14"
    "D70038 00F3F80060 D7008A00 43F8F85D 9D14 0981"
    "D70038 00F7F80060 D70038 00F3F80360 2DCE0DC8"
    "D70038 00F78F0060 0D04"
    "D70038 00F78E0060 D70038 00F78E0460"
    "E7F87F00 65F8C2F7 DB00"
    "D70038 00F3F80460 2D0A"
    "F7F8988B F7F8998B F7F89A8B F7F89B8B F7F80CFA"
    "E6FC988B DB00"
    "F3F8C2F7 67F88000 2D02 FA876860 5F3A FA876A60 DB00"
    "D70038 00F2F40660 3D03 3A1366 23DB00"
    "4980 3D03 3A136623 0D05"
    "9AF402703E660D013F66 4990 2D05 9AF402F02E660D012F66"
    "DB00 B4003BF8"
    "D70038 00F2F40660 3D01 DB00"
    "F3FA3BF8 4980 2D05 9AF402703FF50D013EF5"
    "4990 2D05 9AF402F02FF50D012EF5"
    "F7FA3BF8 DB00"
    "D70038 00F68E0660 D70038 00F68E0860"
    "D70038 00F68E0A60 D70038 00F68E0C60 DB00"
    "D70038 00F2F40660 2D4C"
    "4980 2D22 9AF40970 2981 47F88000 ED1C"
    "D70038 00F3F80960 0D17"
    "2981 4980 3D14 D70038 00F3F80C60 2D0A"
    "03F81EFF D70038 00F7F80C60 3D03 F3F81CFF 0D05"
    "D70038 00F3F80860 7FF4"
    "4990 2D22 9AF409F02991 47F98000 ED1C"
    "D70038 00F3F90B60 0D17"
    "2991 4990 3D14 D70038 00F3F90D60 2D0A"
    "03F91EFF D70038 00F7F90D60 3D03 F3F91CFF 0D05"
    "D70038 00F3F90A60 FFF4"
    "D70038 00F6F40660 DB00"
    "D70038 00F7F80C60 DB00 D70038 00F7F80960"
    "D70038 00F7F90860 77F98000 D70038 00F7F90660 DB00"
    "D70038 00F68E0860 D70038 00F78E0660 D70038 00F78E0C60 DB00"
    "D70038 00F7F80D60 DB00 D70038 00F7F80B60"
    "D70038 00F7F90A60 77F98000 D70038 00F7F90760 DB00"
    "D70038 00F68E0A60 D70038 00F78E0760 D70038 00F78E0D60 DB00"
    "D70038 00F3F80F60 2D0F"
    "D70038 00F3F91060 23F91EFF"
    "D7008A00 43F9FF5D ED3C"
    "D70038 00F7F91060 F198 67F97F00"
    "D7008A00 43F9005E 9D0E 8A272E30 9A270410 8AF43470 7FF4"
    "0D2E 9AF43070 7EF4 23F81EFF 0D28"
    "D7008A00 43F9015E 9D27 8A271B10 9A270430 8AF42170 7FF4"
    "0D1B 9AF41D70 7EF4 23F81EFF"
    "D7008A00 43F8015E 3D11 E118"
    "D70038 0075F80E60 D7008A00 F2F4025E DA8AF85B"
    "D70038 00F78E1060 F3F81CFF D70038 00F7F80F60 DB00"
    "9A271B10 F2F49EF8 D7008A00 42F4FA5D ED08"
    "D7008A00 42F4FC5D 8D03 46F4A00F 9D02 E6F4B036"
    "D70038 00F6F4D43B D70038 00F78E0E60 DA8A165C DB00"
    "D7008A00 F3F8FE5D 2D16"
    "D70038 0043F84F48 FD0B"
    "D70038 00F3F80E60 3D03 DA8A725C 0D09 DA8A205D 0D06"
    "D70038 00F78E0E60 DA8A165C DB00"
    "D70038 00F78E0E60 D70038 00F78E0F60 D70038 00F78E1060"
    "D7008A00 F3F8FE5D 2D17"
    "D70038 00F2F4D43B D7008A00 42F4FA5D ED08"
    "D7008A00 42F4FC5D 8D03 46F4A00F 9D06 E6F4B036"
    "D70038 00F6F4D43B DB00"
    "FFFFFFFFFFFF"
    "B036 9001 9001 03D8 E5CC 803E 1200 F055 7017 0350 0205 0303"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    .replace(" ", "")
)

# Multi-Map block 2 – 0xB0200 (pointer at 0xB0200 = DA 8B 00 02)
_ME75_MMAP2_CODE = bytes.fromhex(
    "D740E100 F2F40230 46F434122D17 E6F43412"
    "D740E100 F6F40230 D740E100 F68E0830 E014"
    "D740E100 F6F4FA30 D740E100 F6F40A30"
    "D740E100 F68E0030 D740E100 F2F40030 42F41CFF"
    "2D07 8A2630E0 D740E100 F68E0030 0D2B"
    "9A2629E0 D740E100 F68F0030"
    "F2F42E9C 46F4FFE6 8D20"
    "D740E100 F2F4FA30 4841 3D02 E024 0D05 4842 3D02 E034 0D01 E014"
    "D740E100 F6F4FA30 F2F59EF8 46F5C800 ED01 5C14"
    "D740E100 F6F40830 E014 D740E100 F6F40A30"
    "DA8F00FA E6FC0027 E6FD3F02 F0FE"
    "D740E100 C2FEFA30 DA82F05E DB00 DB00 FFFFFFFF"
    .replace(" ", "")
)

# Multi-Map block 4 – 0xB0400
_ME75_MMAP4_CODE = bytes.fromhex(
    "E6FCE027 E6FD3F02 F0FE D740E100 C2FEFA30 DA82F05E DB00 DB00"
    "FFFFFFFFFFFF"
    .replace(" ", "")
)

# Ignition map 1 (Map A, 16×12) – 0xFE250
_ME75_KFZW1 = bytes.fromhex(
    "1D15110C09070603000000001F16120D0B0A06040000000021171412"
    "0F0C09050200010025 1A191816141 10C08060602281B1A1A181513100C090A06"
    "2A1E1D1D1A17151 10E0C0A092D201F1F1C181714100D0B0A302323232 11E1C19"
    "14110E0D342A2A2926232 11F1C1713103 62F2C2B2A262522 1F1A16123 83 82F2E"
    "2B282624221B18153 83 82E2E2B2A2925241414143 83 82E2E2B2B2A2625"
    "141414383 82E2E2D2D2C29261414143 83 8303 02E2E2E2D2B141414"
    "35353 030302E2E2F2E2814141 4"
    .replace(" ", "")
)

# Ignition map 2 (Map B, 16×12) – 0xFE350
_ME75_KFZW2 = bytes.fromhex(
    "1B1B181 20C0906030000000028281B160E0A07030000 00002D2D1C1A130B0805"
    "010000002F2F211F1C120A070300002F2F2420 1B130C08040000002F2F26211B16"
    "110C070403022F2F27221D18130E0A0807062F2F2925 1F1A16110E0B09082F2F"
    "2C2A2722 1F1A1614110E2F2F2F2E2B262 31F1C1916123232302F2C282522"
    "1F191919323 22F2E2C292624221919193333 2F2E2C2A282624191919"
    "34342F2E2D2C2A2824191919 34343 030313 02F2D261919193535"
    "303033333231281919 19"
    .replace(" ", "")
)

# Add a new ECU family enum value: we reuse BOSCH_ME7 for ME7.5
# ME7.5 1024KB specific profile
_ME75_MAPS: Dict[str, MapSpec] = {
    **_ME7_MAPS,
    # Override KFZW with correct ME7.5 1024KB offset hints
    "KFZW": MapSpec(
        name="KFZW", description="Base Ignition Timing Map A (16×12) @ 0xFE250",
        category=MapCategory.IGNITION,
        rows=16, cols=12, element_size=1, signed=False,
        factor=0.75, bias=0.0, units="°BTDC",
        phys_min=0.0, phys_max=62.0,
        hint_offset=0xFE250,
    ),
    "KFZW_B": MapSpec(
        name="KFZW_B", description="Ignition Timing Map B (16×12) @ 0xFE350",
        category=MapCategory.IGNITION,
        rows=16, cols=12, element_size=1, signed=False,
        factor=0.75, bias=0.0, units="°BTDC",
        phys_min=0.0, phys_max=62.0,
        hint_offset=0xFE350,
    ),
    "KFZW_C": MapSpec(
        name="KFZW_C", description="Ignition Timing Map C (16×12) @ 0xFE450",
        category=MapCategory.IGNITION,
        rows=16, cols=12, element_size=1, signed=False,
        factor=0.75, bias=0.0, units="°BTDC",
        phys_min=0.0, phys_max=62.0,
        hint_offset=0xFE450,
    ),
    "KFZW_D": MapSpec(
        name="KFZW_D", description="Ignition Timing Map D (16×12) @ 0xFE550",
        category=MapCategory.IGNITION,
        rows=16, cols=12, element_size=1, signed=False,
        factor=0.75, bias=0.0, units="°BTDC",
        phys_min=0.0, phys_max=62.0,
        hint_offset=0xFE550,
    ),
}

_ME75_CANCELLATIONS: Dict[Cancellation, CancellationSpec] = {
    **_ME7_CANCELLATIONS,
    # --- ME7.5 specific patches ---
    Cancellation.SAP: CancellationSpec(
        name="SAP Delete + Launch Control (A/C switch)",
        description=(
            "Escribe el bloque de código de Launch Control + Pops (A/C switch) "
            "en 0xA5900 y activa el pointer en 0xB0200. "
            "Requiere ROM 1024 KB (broadband lambda)."
        ),
        cancellation=Cancellation.SAP,
        patches=[
            # (hint_offset, pattern_to_search, replacement)
            # Write launch control block at 0xA5900
            (0xA5900, b"\xFF\xFF\xFF\xFF",    _ME75_LAUNCH_CTRL_CODE[:4]),
            # Write multi-map block 2 at 0xB0200
            (0xB0200, b"\xFF\xFF\xFF\xFF",    _ME75_MMAP2_CODE[:4]),
            # Write multi-map block 4 at 0xB0400
            (0xB0400, b"\xFF\xFF\xFF\xFF",    _ME75_MMAP4_CODE[:4]),
        ],
        dtc_disable=True,
    ),
}

# ME7.5 stages inherit from ME7 but with updated power estimates
_ME75_STAGES: Dict[StageLevel, StageSpec] = {
    StageLevel.STAGE1: StageSpec(
        level=StageLevel.STAGE1,
        description="Stage 1 – Remap software only. Banda ancha, mapas KFZW optimizados.",
        boost_pct=18.0, fuel_pct=10.0, ignition_deg=2.0,
        torque_pct=22.0, rpm_raise=300, remove_vmax=True,
        power_gain_hp=35, torque_gain_nm=65,
    ),
    StageLevel.STAGE2: StageSpec(
        level=StageLevel.STAGE2,
        description='Stage 2 – Intake K&N, intercooler grande, escape 3", EGR off.',
        boost_pct=32.0, fuel_pct=18.0, ignition_deg=3.0,
        torque_pct=45.0, rpm_raise=500, remove_vmax=True,
        power_gain_hp=65, torque_gain_nm=105,
    ),
    StageLevel.STAGE3: StageSpec(
        level=StageLevel.STAGE3,
        description="Stage 3 – Turbo GT28/GT30, inyectores 440 cc, forjado.",
        boost_pct=55.0, fuel_pct=35.0, ignition_deg=2.0,
        torque_pct=80.0, rpm_raise=800, remove_vmax=True,
        power_gain_hp=130, torque_gain_nm=185,
    ),
}

PROFILE_BOSCH_ME75_1024 = ECUProfile(
    name="Bosch ME7.5 – 1024 KB broadband (Launch Ctrl + Multi-Map)",
    family=ECUFamily.BOSCH_ME7,
    file_sizes=[1048576],                              # 1024 KB
    identification_strings=[b"ME7.5", b"0 261 2"],
    vin_offset=0, sw_offset=0, hw_offset=0, cal_id_offset=0,
    checksum_regions=[(0x0000, 0xFFFF0)],
    checksum_offset=0xFFFF0,
    checksum_algo="sum32",
    maps=_ME75_MAPS,
    cancellations=_ME75_CANCELLATIONS,
    stages=_ME75_STAGES,
)


# ===========================================================================
# Registry
# ===========================================================================

#: All known profiles, ordered from most to least specific
ALL_PROFILES: List[ECUProfile] = [
    PROFILE_BOSCH_ME75_1024,   # ME7.5 1024KB must be checked BEFORE generic ME7
    PROFILE_BOSCH_ME7,
    PROFILE_BOSCH_EDC15,
    PROFILE_BOSCH_EDC16,
    PROFILE_BOSCH_EDC17,
    PROFILE_DELPHI_DCM,
    PROFILE_MARELLI,
]


def get_profile(data: bytes) -> Optional[ECUProfile]:
    """Return the best-matching ECU profile for *data*, or None.

    Matching is done by:
    1. ROM size in profile ``file_sizes``
    2. Any ``identification_strings`` found in the first 64 KB
    3. Falls back to size-only match if no string matches.
    """
    size    = len(data)
    probe   = data[:65536]

    size_matches   = [p for p in ALL_PROFILES if size in p.file_sizes]
    string_matches = [
        p for p in size_matches
        if any(s in probe for s in p.identification_strings)
    ]

    if string_matches:
        return string_matches[0]
    if size_matches:
        return size_matches[0]
    return None
