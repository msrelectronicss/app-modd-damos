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
from formats.elf_format import ELFFormat
from formats.ecu_bin import ECUBinFormat
from formats.firmware_bin import FirmwareBinFormat

# Register all bundled formats with the global registry
_registry = FormatRegistry()
_registry.register(ELFFormat)
_registry.register(ECUBinFormat)
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
    # Concrete formats
    "ELFFormat",
    "ECUBinFormat",
    "FirmwareBinFormat",
    # Convenience
    "get_registry",
    "detect",
]
