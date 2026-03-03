"""
formats/__init__.py - BinModder file format package.

Exposes all format classes and the global FormatRegistry.
"""

from formats.base_format import (
    BinaryFormat,
    FormatRegistry,
    FormatError,
    ParseError,
    ValidationError,
)
from formats.ecu_bin import ECUBinFormat

# Optional formats — loaded only when the file exists
try:
    from formats.elf_format import ELFFormat
    _has_elf = True
except ImportError:
    ELFFormat = None   # type: ignore
    _has_elf = False

try:
    from formats.firmware_bin import FirmwareBinFormat
    _has_fw = True
except ImportError:
    FirmwareBinFormat = None   # type: ignore
    _has_fw = False

# Register all available formats with the global registry
_registry = FormatRegistry()
_registry.register(ECUBinFormat)
if _has_elf and ELFFormat:
    _registry.register(ELFFormat)
if _has_fw and FirmwareBinFormat:
    _registry.register(FirmwareBinFormat)


def get_registry() -> FormatRegistry:
    """Return the global format registry."""
    return _registry


def detect(data: bytes) -> "BinaryFormat | None":
    """Auto-detect the format of *data* and return an instance, or None."""
    return _registry.detect(data)


__all__ = [
    # Base
    "BinaryFormat",
    "FormatRegistry",
    "FormatError",
    "ParseError",
    "ValidationError",
    # Concrete formats (always present)
    "ECUBinFormat",
    # Optional (None if not installed)
    "ELFFormat",
    "FirmwareBinFormat",
    # Convenience
    "get_registry",
    "detect",
]
