# =============================================================================
# BinModder - Core Engine Package
# =============================================================================
# This package provides the fundamental binary manipulation engine for BinModder.
# All core operations (reading, writing, searching, patching, checksums, crypto,
# compression, and diff) are implemented here as independent, reusable modules.
#
# Module Overview:
#   binary_reader   - Read binary data with endianness support
#   binary_writer   - Write binary data with transaction support
#   binary_analyzer - Analyze and detect file structure
#   hex_engine      - Hex display and formatting
#   patch_engine    - Apply and create binary patches
#   checksum        - Checksum and hash algorithms
#   crypto          - Encryption and decryption
#   compression     - Compress and decompress binary data
#   diff_engine     - Binary diff and merge
#   search_engine   - Pattern search in binary data
# =============================================================================

from .binary_reader import BinaryReader, Endianness
from .binary_writer import BinaryWriter, WriteTransaction
from .binary_analyzer import BinaryAnalyzer, FileSignature
from .hex_engine import HexEngine, HexColor
from .patch_engine import PatchEngine, IPSPatch, UPSPatch, BPSPatch, CustomPatch
from .checksum import ChecksumEngine, ChecksumAlgorithm
from .crypto import CryptoEngine, CipherMode
from .compression import CompressionEngine, CompressionAlgorithm
from .diff_engine import DiffEngine, DiffBlock, DiffResult
from .search_engine import SearchEngine, SearchResult, SearchAlgorithm

__version__ = "1.0.0"
__author__ = "MSR Electronics"
__all__ = [
    # Reader
    "BinaryReader",
    "Endianness",
    # Writer
    "BinaryWriter",
    "WriteTransaction",
    # Analyzer
    "BinaryAnalyzer",
    "FileSignature",
    # Hex Engine
    "HexEngine",
    "HexColor",
    # Patch Engine
    "PatchEngine",
    "IPSPatch",
    "UPSPatch",
    "BPSPatch",
    "CustomPatch",
    # Checksum
    "ChecksumEngine",
    "ChecksumAlgorithm",
    # Crypto
    "CryptoEngine",
    "CipherMode",
    # Compression
    "CompressionEngine",
    "CompressionAlgorithm",
    # Diff
    "DiffEngine",
    "DiffBlock",
    "DiffResult",
    # Search
    "SearchEngine",
    "SearchResult",
    "SearchAlgorithm",
]
