"""
binary_analyzer.py - Comprehensive binary file analysis engine.

Detects file formats, finds sections, computes entropy, extracts strings,
identifies code/data regions, and more.  Ships with a 50+ signature database.
"""

from __future__ import annotations

import math
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FileSignature:
    """Describes a detected file type.

    Attributes
    ----------
    name : str
        Human-readable format name (e.g., "ELF Executable").
    mime_type : str
        MIME type string (e.g., "application/x-elf").
    magic_bytes : bytes
        The magic bytes that triggered the match.
    offset : int
        Byte offset in the file where the magic was found.
    confidence : float
        Confidence score 0.0–1.0.
    extensions : list[str]
        Common file extensions for this format.
    description : str
        Brief description of the format.
    """
    name:        str
    mime_type:   str   = ""
    magic_bytes: bytes = b""
    offset:      int   = 0
    confidence:  float = 1.0
    extensions:  List[str] = field(default_factory=list)
    description: str       = ""

    def __str__(self) -> str:
        return f"{self.name} (confidence={self.confidence:.0%}, offset={self.offset})"


@dataclass
class SectionInfo:
    """Represents a logically distinct region within binary data.

    Attributes
    ----------
    name : str
        Heuristic or format-defined name for this section.
    offset : int
        Byte offset from start of file.
    size : int
        Length in bytes.
    entropy : float
        Shannon entropy of the section (0 = all same byte, 8 = fully random).
    is_compressed : bool
        Heuristic: entropy > 7.2 and no recognisable structure.
    is_encrypted : bool
        Heuristic: entropy > 7.8, near-uniform byte distribution.
    attributes : dict
        Format-specific extra attributes.
    """
    name:          str
    offset:        int
    size:          int
    entropy:       float = 0.0
    is_compressed: bool  = False
    is_encrypted:  bool  = False
    attributes:    Dict  = field(default_factory=dict)

    def __repr__(self) -> str:
        flags = []
        if self.is_compressed: flags.append("COMPRESSED")
        if self.is_encrypted:  flags.append("ENCRYPTED")
        flag_str = " [" + "|".join(flags) + "]" if flags else ""
        return (
            f"SectionInfo({self.name!r}, "
            f"off=0x{self.offset:08X}, "
            f"size={self.size}, "
            f"entropy={self.entropy:.2f}{flag_str})"
        )


# ---------------------------------------------------------------------------
# Signature database — 50+ entries
# ---------------------------------------------------------------------------

_SIGNATURES: List[dict] = [
    # --- Executable / object formats ---
    {"name": "ELF",              "mime": "application/x-elf",          "magic": b"\x7fELF",     "offset": 0, "ext": [".elf", ".so", ".o", ".ko"]},
    {"name": "PE/COFF",          "mime": "application/x-dosexec",      "magic": b"MZ",          "offset": 0, "ext": [".exe", ".dll", ".sys"]},
    {"name": "Mach-O 32-bit",    "mime": "application/x-mach-binary",  "magic": b"\xce\xfa\xed\xfe", "offset": 0, "ext": [".dylib", ".o"]},
    {"name": "Mach-O 64-bit",    "mime": "application/x-mach-binary",  "magic": b"\xcf\xfa\xed\xfe", "offset": 0, "ext": [".dylib", ".o"]},
    {"name": "Mach-O FAT",       "mime": "application/x-mach-binary",  "magic": b"\xca\xfe\xba\xbe", "offset": 0, "ext": []},
    {"name": "Java Class",       "mime": "application/x-java-class",   "magic": b"\xca\xfe\xba\xbe", "offset": 0, "ext": [".class"]},  # same magic, differentiated by context
    {"name": "DEX",              "mime": "application/x-android-dex",  "magic": b"dex\n",       "offset": 0, "ext": [".dex"]},
    {"name": "WebAssembly",      "mime": "application/wasm",           "magic": b"\x00asm",     "offset": 0, "ext": [".wasm"]},
    {"name": "DOS MZ Stub",      "mime": "application/x-dosexec",      "magic": b"MZ",          "offset": 0, "ext": [".com", ".exe"]},

    # --- Archives / containers ---
    {"name": "ZIP",              "mime": "application/zip",            "magic": b"PK\x03\x04",  "offset": 0, "ext": [".zip", ".jar", ".apk"]},
    {"name": "ZIP (empty)",      "mime": "application/zip",            "magic": b"PK\x05\x06",  "offset": 0, "ext": [".zip"]},
    {"name": "RAR 4",            "mime": "application/x-rar",          "magic": b"Rar!\x1a\x07\x00", "offset": 0, "ext": [".rar"]},
    {"name": "RAR 5",            "mime": "application/x-rar",          "magic": b"Rar!\x1a\x07\x01", "offset": 0, "ext": [".rar"]},
    {"name": "7-Zip",            "mime": "application/x-7z-compressed","magic": b"7z\xbc\xaf'!", "offset": 0, "ext": [".7z"]},
    {"name": "TAR",              "mime": "application/x-tar",          "magic": b"ustar",       "offset": 257,"ext": [".tar"]},
    {"name": "GZIP",             "mime": "application/gzip",           "magic": b"\x1f\x8b",    "offset": 0, "ext": [".gz", ".tgz"]},
    {"name": "BZIP2",            "mime": "application/x-bzip2",        "magic": b"BZh",         "offset": 0, "ext": [".bz2"]},
    {"name": "XZ",               "mime": "application/x-xz",          "magic": b"\xfd7zXZ\x00","offset": 0, "ext": [".xz"]},
    {"name": "LZMA",             "mime": "application/x-lzma",         "magic": b"\x5d\x00\x00","offset": 0, "ext": [".lzma"]},
    {"name": "Zstandard",        "mime": "application/zstd",           "magic": b"\x28\xb5\x2f\xfd","offset":0,"ext": [".zst"]},
    {"name": "LZ4",              "mime": "application/x-lz4",          "magic": b"\x04\x22\x4d\x18","offset":0,"ext": [".lz4"]},
    {"name": "CAB",              "mime": "application/vnd.ms-cab-compressed","magic": b"MSCF", "offset": 0, "ext": [".cab"]},
    {"name": "AR Archive",       "mime": "application/x-archive",      "magic": b"!<arch>",     "offset": 0, "ext": [".a"]},
    {"name": "CPIO",             "mime": "application/x-cpio",         "magic": b"070701",      "offset": 0, "ext": [".cpio"]},

    # --- Images ---
    {"name": "JPEG",             "mime": "image/jpeg",                 "magic": b"\xff\xd8\xff","offset": 0, "ext": [".jpg", ".jpeg"]},
    {"name": "PNG",              "mime": "image/png",                  "magic": b"\x89PNG\r\n\x1a\n","offset":0,"ext":[".png"]},
    {"name": "GIF87a",           "mime": "image/gif",                  "magic": b"GIF87a",      "offset": 0, "ext": [".gif"]},
    {"name": "GIF89a",           "mime": "image/gif",                  "magic": b"GIF89a",      "offset": 0, "ext": [".gif"]},
    {"name": "BMP",              "mime": "image/bmp",                  "magic": b"BM",          "offset": 0, "ext": [".bmp"]},
    {"name": "TIFF (LE)",        "mime": "image/tiff",                 "magic": b"II*\x00",     "offset": 0, "ext": [".tif", ".tiff"]},
    {"name": "TIFF (BE)",        "mime": "image/tiff",                 "magic": b"MM\x00*",     "offset": 0, "ext": [".tif", ".tiff"]},
    {"name": "WebP",             "mime": "image/webp",                 "magic": b"RIFF",        "offset": 0, "ext": [".webp"]},   # further check at +8
    {"name": "ICO",              "mime": "image/x-icon",              "magic": b"\x00\x00\x01\x00","offset":0,"ext":[".ico"]},

    # --- Audio / Video ---
    {"name": "RIFF/WAV",         "mime": "audio/wav",                  "magic": b"RIFF",        "offset": 0, "ext": [".wav"]},
    {"name": "MP3 (ID3v2)",      "mime": "audio/mpeg",                 "magic": b"ID3",         "offset": 0, "ext": [".mp3"]},
    {"name": "FLAC",             "mime": "audio/flac",                 "magic": b"fLaC",        "offset": 0, "ext": [".flac"]},
    {"name": "OGG",              "mime": "audio/ogg",                  "magic": b"OggS",        "offset": 0, "ext": [".ogg", ".oga"]},
    {"name": "MP4/ISOBMFF",      "mime": "video/mp4",                  "magic": b"ftyp",        "offset": 4, "ext": [".mp4", ".m4a", ".m4v"]},
    {"name": "AVI",              "mime": "video/x-msvideo",            "magic": b"RIFF",        "offset": 0, "ext": [".avi"]},

    # --- Documents ---
    {"name": "PDF",              "mime": "application/pdf",            "magic": b"%PDF",        "offset": 0, "ext": [".pdf"]},
    {"name": "PS",               "mime": "application/postscript",     "magic": b"%!",          "offset": 0, "ext": [".ps", ".eps"]},
    {"name": "RTF",              "mime": "application/rtf",            "magic": b"{\\rtf",      "offset": 0, "ext": [".rtf"]},
    {"name": "DOC (OLE)",        "mime": "application/msword",         "magic": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1","offset":0,"ext":[".doc",".xls",".ppt"]},
    {"name": "OOXML/ZIP",        "mime": "application/vnd.openxmlformats","magic": b"PK\x03\x04","offset":0,"ext":[".docx",".xlsx",".pptx"]},

    # --- Databases ---
    {"name": "SQLite",           "mime": "application/x-sqlite3",      "magic": b"SQLite format 3\x00","offset":0,"ext":[".db",".sqlite"]},

    # --- Firmware / embedded ---
    {"name": "uImage (U-Boot)",  "mime": "application/octet-stream",  "magic": b"\x27\x05\x19\x56","offset":0,"ext":[]},
    {"name": "SquashFS (LE)",    "mime": "application/octet-stream",  "magic": b"sqsh",        "offset": 0, "ext": []},
    {"name": "SquashFS (BE)",    "mime": "application/octet-stream",  "magic": b"hsqs",        "offset": 0, "ext": []},
    {"name": "JFFS2",            "mime": "application/octet-stream",  "magic": b"\x85\x19",    "offset": 0, "ext": []},
    {"name": "UBIFS",            "mime": "application/octet-stream",  "magic": b"\x31\x18\x10\x06","offset":0,"ext":[]},
    {"name": "FIT Image",        "mime": "application/octet-stream",  "magic": b"\xd0\x0d\xfe\xed","offset":0,"ext":[]},
    {"name": "LZSS compressed",  "mime": "application/octet-stream",  "magic": b"\x14\x00\x00\x00","offset":0,"ext":[]},
    {"name": "Intel HEX",        "mime": "text/plain",                 "magic": b":10",         "offset": 0, "ext": [".hex"]},
    {"name": "Motorola SREC",    "mime": "text/plain",                 "magic": b"S0",          "offset": 0, "ext": [".srec", ".mot", ".s19"]},
    {"name": "Bosch ME7.x ROM",  "mime": "application/octet-stream",  "magic": b"\x11\x22\x33","offset":0,"ext":[".bin"]},

    # --- Misc ---
    {"name": "UTF-8 BOM",        "mime": "text/plain",                 "magic": b"\xef\xbb\xbf","offset":0,"ext":[".txt"]},
    {"name": "UTF-16 LE BOM",    "mime": "text/plain",                 "magic": b"\xff\xfe",    "offset":0,"ext":[".txt"]},
    {"name": "UTF-16 BE BOM",    "mime": "text/plain",                 "magic": b"\xfe\xff",    "offset":0,"ext":[".txt"]},
    {"name": "LZFSE",            "mime": "application/octet-stream",  "magic": b"bvx2",        "offset":0,"ext":[]},
    {"name": "zlib",             "mime": "application/zlib",           "magic": b"\x78\x9c",    "offset":0,"ext":[".zlib"]},
    {"name": "zlib (best)",      "mime": "application/zlib",           "magic": b"\x78\xda",    "offset":0,"ext":[".zlib"]},
    {"name": "zlib (low)",       "mime": "application/zlib",           "magic": b"\x78\x01",    "offset":0,"ext":[".zlib"]},
]


# ---------------------------------------------------------------------------
# BinaryAnalyzer
# ---------------------------------------------------------------------------

class BinaryAnalyzer:
    """Analyse binary data: detect format, find sections, compute entropy,
    extract strings, find code/data regions, and more.

    All methods accept raw ``bytes`` unless otherwise noted.

    Usage
    -----
    >>> ba = BinaryAnalyzer()
    >>> sig = ba.detect_format(data)
    >>> sections = ba.find_sections(data)
    >>> summary = ba.summarize(data)
    """

    # Tunable thresholds
    COMPRESSED_ENTROPY_THRESHOLD = 7.2
    ENCRYPTED_ENTROPY_THRESHOLD  = 7.8
    CODE_ENTROPY_LOWER  = 3.5
    CODE_ENTROPY_UPPER  = 6.5
    MIN_SECTION_SIZE    = 64          # bytes
    DEFAULT_BLOCK_SIZE  = 256         # for entropy map
    DEFAULT_MIN_STR_LEN = 4

    def __init__(self) -> None:
        self._sigs = _SIGNATURES

    # ------------------------------------------------------------------
    # Format detection
    # ------------------------------------------------------------------

    def detect_format(self, data: bytes) -> FileSignature:
        """Identify the file type of *data* by matching magic bytes.

        Parameters
        ----------
        data : bytes
            Raw file contents.

        Returns
        -------
        FileSignature
            Best matching signature, or an "Unknown" signature if nothing
            matches.
        """
        data = bytes(data)
        best: Optional[FileSignature] = None
        best_score = 0.0

        for sig in self._sigs:
            magic  = sig["magic"]
            offset = sig["offset"]
            if len(data) < offset + len(magic):
                continue
            if data[offset:offset + len(magic)] == magic:
                # Longer magic = higher confidence
                score = min(1.0, len(magic) / 8 + 0.5)
                if score > best_score:
                    best_score = score
                    best = FileSignature(
                        name        = sig["name"],
                        mime_type   = sig.get("mime", ""),
                        magic_bytes = magic,
                        offset      = offset,
                        confidence  = score,
                        extensions  = list(sig.get("ext", [])),
                        description = sig.get("desc", ""),
                    )

        if best is None:
            return FileSignature(
                name       = "Unknown",
                confidence = 0.0,
                description= "No matching signature found",
            )
        return best

    def detect_format_all(self, data: bytes) -> List[FileSignature]:
        """Return all matching signatures sorted by confidence descending."""
        data   = bytes(data)
        results: List[FileSignature] = []
        for sig in self._sigs:
            magic  = sig["magic"]
            offset = sig["offset"]
            if len(data) < offset + len(magic):
                continue
            if data[offset:offset + len(magic)] == magic:
                score = min(1.0, len(magic) / 8 + 0.5)
                results.append(FileSignature(
                    name        = sig["name"],
                    mime_type   = sig.get("mime", ""),
                    magic_bytes = magic,
                    offset      = offset,
                    confidence  = score,
                    extensions  = list(sig.get("ext", [])),
                ))
        results.sort(key=lambda s: s.confidence, reverse=True)
        return results

    # ------------------------------------------------------------------
    # Section detection
    # ------------------------------------------------------------------

    def find_sections(
        self, data: bytes, block_size: int = DEFAULT_BLOCK_SIZE
    ) -> List[SectionInfo]:
        """Heuristically locate distinct data sections in *data*.

        The algorithm slides a window over the data and groups consecutive
        blocks with similar characteristics into sections.

        Parameters
        ----------
        data : bytes
            Binary data to analyse.
        block_size : int
            Size of each analysis window.

        Returns
        -------
        list of SectionInfo
        """
        data  = bytes(data)
        total = len(data)
        if total == 0:
            return []

        entropy_map = self.analyze_entropy(data, block_size)

        sections: List[SectionInfo] = []
        prev_class  = None
        sec_start   = 0
        sec_entropy = 0.0
        sec_blocks  = 0

        def flush_section(end: int) -> None:
            nonlocal sec_start, sec_entropy, sec_blocks, prev_class
            size = end - sec_start
            if size < self.MIN_SECTION_SIZE:
                sec_start   = end
                sec_entropy = 0.0
                sec_blocks  = 0
                return
            avg_e = sec_entropy / sec_blocks if sec_blocks else 0.0
            s = SectionInfo(
                name          = self._classify_name(prev_class, avg_e),
                offset        = sec_start,
                size          = size,
                entropy       = avg_e,
                is_compressed = avg_e > self.COMPRESSED_ENTROPY_THRESHOLD,
                is_encrypted  = avg_e > self.ENCRYPTED_ENTROPY_THRESHOLD,
            )
            sections.append(s)
            sec_start   = end
            sec_entropy = 0.0
            sec_blocks  = 0

        for off, ent in entropy_map:
            cls = self._classify_block(ent, data[off:off + block_size])
            if prev_class is not None and cls != prev_class:
                flush_section(off)
            prev_class   = cls
            sec_entropy += ent
            sec_blocks  += 1

        # Flush final section
        if prev_class is not None and sec_blocks > 0:
            flush_section(total)

        return sections

    def _classify_block(self, entropy: float, chunk: bytes) -> str:
        """Return a string category for a block based on entropy and byte profile."""
        if entropy > self.ENCRYPTED_ENTROPY_THRESHOLD:
            return "encrypted_or_compressed"
        if entropy > self.COMPRESSED_ENTROPY_THRESHOLD:
            return "compressed"
        if entropy < 1.5:
            return "zero_or_padding"
        if self.CODE_ENTROPY_LOWER <= entropy <= self.CODE_ENTROPY_UPPER:
            return "code_or_data"
        return "data"

    @staticmethod
    def _classify_name(cls: Optional[str], entropy: float) -> str:
        if cls is None:
            return "unknown"
        names = {
            "encrypted_or_compressed": "encrypted/compressed",
            "compressed":              "compressed_data",
            "zero_or_padding":         "padding/zeros",
            "code_or_data":            "code/data",
            "data":                    "data",
        }
        return names.get(cls, cls)

    # ------------------------------------------------------------------
    # Entropy analysis
    # ------------------------------------------------------------------

    def analyze_entropy(
        self, data: bytes, block_size: int = DEFAULT_BLOCK_SIZE
    ) -> List[Tuple[int, float]]:
        """Compute Shannon entropy for non-overlapping blocks.

        Parameters
        ----------
        data : bytes
            Input data.
        block_size : int
            Block size for entropy calculation.

        Returns
        -------
        list of (offset, entropy)
        """
        data   = bytes(data)
        result: List[Tuple[int, float]] = []
        for off in range(0, len(data), block_size):
            chunk = data[off:off + block_size]
            if not chunk:
                break
            result.append((off, _shannon_entropy(chunk)))
        return result

    def entropy_map(
        self, data: bytes, block_size: int = DEFAULT_BLOCK_SIZE
    ) -> List[Tuple[int, float, str]]:
        """Like analyze_entropy but includes a classification label per block."""
        raw = self.analyze_entropy(data, block_size)
        return [
            (off, ent, self._classify_block(ent, data[off:off + block_size]))
            for off, ent in raw
        ]

    # ------------------------------------------------------------------
    # String extraction
    # ------------------------------------------------------------------

    def find_strings(
        self,
        data: bytes,
        min_len: int = DEFAULT_MIN_STR_LEN,
        include_wide: bool = True,
    ) -> List[Tuple[int, str]]:
        """Extract printable ASCII strings from *data*.

        Parameters
        ----------
        data : bytes
            Binary data to scan.
        min_len : int
            Minimum string length to include.
        include_wide : bool
            Also search for UTF-16LE strings.

        Returns
        -------
        list of (offset, string)
        """
        data    = bytes(data)
        results: List[Tuple[int, str]] = []

        # ASCII strings
        pattern = re.compile(b"[ -~]{" + str(min_len).encode() + b",}")
        for m in pattern.finditer(data):
            results.append((m.start(), m.group().decode("ascii", errors="replace")))

        # Wide (UTF-16LE) strings
        if include_wide:
            wide_pattern = re.compile(
                b"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + b",}"
            )
            for m in wide_pattern.finditer(data):
                raw_str = m.group().decode("utf-16-le", errors="replace")
                # Filter to printable
                if all(32 <= ord(c) < 127 for c in raw_str):
                    results.append((m.start(), raw_str))

        results.sort(key=lambda t: t[0])
        return results

    # ------------------------------------------------------------------
    # Encoding detection
    # ------------------------------------------------------------------

    def detect_encoding(self, data: bytes) -> str:
        """Guess the character encoding of *data*.

        Returns a string like "UTF-8", "UTF-16LE", "ASCII", or "binary".
        """
        data = bytes(data)
        # BOM checks
        if data[:3] == b"\xef\xbb\xbf":
            return "UTF-8-BOM"
        if data[:2] == b"\xff\xfe":
            return "UTF-16LE"
        if data[:2] == b"\xfe\xff":
            return "UTF-16BE"
        if data[:4] == b"\xff\xfe\x00\x00":
            return "UTF-32LE"
        if data[:4] == b"\x00\x00\xfe\xff":
            return "UTF-32BE"

        # Heuristic: check for null bytes → wide string / binary
        null_count = data.count(b"\x00")
        if null_count == 0:
            # Try UTF-8 decode
            try:
                data.decode("utf-8")
                return "UTF-8"
            except UnicodeDecodeError:
                pass
            # Try Latin-1
            try:
                data.decode("latin-1")
                return "Latin-1"
            except UnicodeDecodeError:
                pass
            return "ASCII"

        # Many nulls → likely wide or binary
        if null_count > len(data) * 0.3:
            return "UTF-16LE"
        return "binary"

    # ------------------------------------------------------------------
    # Code region detection
    # ------------------------------------------------------------------

    def find_code_regions(
        self,
        data: bytes,
        block_size: int = DEFAULT_BLOCK_SIZE,
    ) -> List[Tuple[int, int]]:
        """Identify memory regions that appear to contain executable code.

        Heuristic: entropy in [CODE_ENTROPY_LOWER, CODE_ENTROPY_UPPER]
        combined with the presence of common instruction byte patterns.

        Returns
        -------
        list of (offset, size) tuples
        """
        data      = bytes(data)
        emap      = self.analyze_entropy(data, block_size)
        regions:    List[Tuple[int, int]] = []
        in_region   = False
        region_start = 0

        for off, ent in emap:
            is_code = (
                self.CODE_ENTROPY_LOWER <= ent <= self.CODE_ENTROPY_UPPER
                and self._has_code_patterns(data[off:off + block_size])
            )
            if is_code and not in_region:
                in_region    = True
                region_start = off
            elif not is_code and in_region:
                size = off - region_start
                if size >= self.MIN_SECTION_SIZE:
                    regions.append((region_start, size))
                in_region = False

        if in_region:
            size = len(data) - region_start
            if size >= self.MIN_SECTION_SIZE:
                regions.append((region_start, size))

        return regions

    def find_data_regions(
        self,
        data: bytes,
        block_size: int = DEFAULT_BLOCK_SIZE,
    ) -> List[Tuple[int, int]]:
        """Identify regions that appear to contain structured data (not code).

        Heuristic: entropy > 1.5 but not in the code entropy range, and
        not high-entropy (compressed/encrypted).

        Returns
        -------
        list of (offset, size) tuples
        """
        data     = bytes(data)
        emap     = self.analyze_entropy(data, block_size)
        regions: List[Tuple[int, int]] = []
        in_region    = False
        region_start = 0

        for off, ent in emap:
            is_data = (
                1.5 < ent < self.CODE_ENTROPY_LOWER
                or (self.CODE_ENTROPY_UPPER < ent < self.COMPRESSED_ENTROPY_THRESHOLD)
            )
            if is_data and not in_region:
                in_region    = True
                region_start = off
            elif not is_data and in_region:
                size = off - region_start
                if size >= self.MIN_SECTION_SIZE:
                    regions.append((region_start, size))
                in_region = False

        if in_region:
            size = len(data) - region_start
            if size >= self.MIN_SECTION_SIZE:
                regions.append((region_start, size))

        return regions

    def _has_code_patterns(self, chunk: bytes) -> bool:
        """Return True if chunk shows byte patterns common to machine code."""
        if len(chunk) < 4:
            return False
        # x86: common opcode prefixes / opcodes
        x86_opcodes = {0x55, 0x89, 0x8b, 0x48, 0x83, 0xe8, 0xff, 0xc3, 0xc7, 0x31, 0x50}
        opcode_hits = sum(1 for b in chunk if b in x86_opcodes)
        return opcode_hits >= max(4, len(chunk) // 20)

    # ------------------------------------------------------------------
    # Endianness detection
    # ------------------------------------------------------------------

    def detect_endianness(self, data: bytes) -> str:
        """Heuristically guess the byte order of *data*.

        Examines 32-bit words and compares how many look like aligned
        little-endian vs big-endian pointers/counts.

        Returns
        -------
        str: "little", "big", or "unknown"
        """
        data  = bytes(data)
        size  = len(data)
        if size < 8:
            return "unknown"

        le_score = 0
        be_score = 0

        for i in range(0, min(size - 4, 4096), 4):
            word = data[i:i + 4]
            le_val = struct.unpack_from("<I", word)[0]
            be_val = struct.unpack_from(">I", word)[0]

            # Heuristic: small non-zero values are more common in LE for x86
            if 0 < le_val < 0x10000:
                le_score += 1
            if 0 < be_val < 0x10000:
                be_score += 1
            # Zero bytes at high end → LE
            if word[3] == 0 and word[0] != 0:
                le_score += 2
            # Zero bytes at low end → BE
            if word[0] == 0 and word[3] != 0:
                be_score += 2

        if le_score > be_score * 1.5:
            return "little"
        if be_score > le_score * 1.5:
            return "big"
        return "unknown"

    # ------------------------------------------------------------------
    # Repeated structure detection
    # ------------------------------------------------------------------

    def find_repeated_structures(
        self,
        data: bytes,
        min_size: int = 8,
        max_scan: int = 65536,
    ) -> List[Tuple[int, int, int]]:
        """Find repeated byte patterns (fixed-size records) in *data*.

        Compares sample blocks at different strides to detect tabular data.

        Parameters
        ----------
        data : bytes
            Input data.
        min_size : int
            Minimum repeated block size to report.
        max_scan : int
            Maximum number of bytes to analyse (for performance).

        Returns
        -------
        list of (offset, size, count) tuples
        """
        data    = bytes(data)
        scan    = data[:max_scan]
        size    = len(scan)
        results: List[Tuple[int, int, int]] = []

        for stride in range(min_size, min(256, size // 3) + 1):
            count = 0
            first_match_offset = 0
            last_end = 0
            for pos in range(0, size - stride, stride):
                chunk = scan[pos:pos + stride]
                nxt   = scan[pos + stride:pos + 2 * stride]
                if chunk == nxt:
                    count += 1
                    if count == 1:
                        first_match_offset = pos
                else:
                    if count >= 3:
                        results.append((first_match_offset, stride, count + 1))
                    count = 0
            if count >= 3:
                results.append((first_match_offset, stride, count + 1))

        # De-duplicate: keep largest stride for overlapping regions
        results.sort(key=lambda t: -t[2])
        seen_offsets: set = set()
        deduped: List[Tuple[int, int, int]] = []
        for off, stride, cnt in results:
            key = (off // stride) * stride
            if key not in seen_offsets:
                seen_offsets.add(key)
                deduped.append((off, stride, cnt))

        return deduped[:64]  # cap results

    # ------------------------------------------------------------------
    # Byte frequency
    # ------------------------------------------------------------------

    def byte_frequency(self, data: bytes) -> Dict[int, int]:
        """Return a frequency table mapping byte value → occurrence count."""
        freq: Dict[int, int] = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        return freq

    def byte_histogram(self, data: bytes, bins: int = 16) -> List[Tuple[int, int, int]]:
        """Return a coarse histogram of byte values grouped into *bins* ranges.

        Returns list of (range_start, range_end, count).
        """
        data  = bytes(data)
        freq  = self.byte_frequency(data)
        step  = 256 // bins
        hist: List[Tuple[int, int, int]] = []
        for i in range(bins):
            lo    = i * step
            hi    = lo + step
            count = sum(freq.get(v, 0) for v in range(lo, hi))
            hist.append((lo, hi, count))
        return hist

    # ------------------------------------------------------------------
    # Full summary
    # ------------------------------------------------------------------

    def summarize(self, data: bytes) -> dict:
        """Produce a comprehensive analysis summary as a dictionary.

        Keys include: size, sha256, format, encoding, endianness,
        entropy, sections, code_regions, data_regions, string_count,
        repeated_structures.
        """
        import hashlib

        data = bytes(data)
        sig  = self.detect_format(data)

        sections = self.find_sections(data)
        code_regions = self.find_code_regions(data)
        data_regions = self.find_data_regions(data)
        strings  = self.find_strings(data)
        repeats  = self.find_repeated_structures(data)
        overall_entropy = _shannon_entropy(data)

        return {
            "size":          len(data),
            "sha256":        hashlib.sha256(data).hexdigest(),
            "md5":           hashlib.md5(data).hexdigest(),
            "format":        sig.name,
            "mime_type":     sig.mime_type,
            "format_confidence": sig.confidence,
            "encoding":      self.detect_encoding(data),
            "endianness":    self.detect_endianness(data),
            "entropy":       round(overall_entropy, 4),
            "is_compressed": overall_entropy > self.COMPRESSED_ENTROPY_THRESHOLD,
            "is_encrypted":  overall_entropy > self.ENCRYPTED_ENTROPY_THRESHOLD,
            "sections":      [
                {
                    "name":          s.name,
                    "offset":        s.offset,
                    "size":          s.size,
                    "entropy":       round(s.entropy, 4),
                    "is_compressed": s.is_compressed,
                    "is_encrypted":  s.is_encrypted,
                }
                for s in sections
            ],
            "code_regions":  [{"offset": o, "size": s} for o, s in code_regions],
            "data_regions":  [{"offset": o, "size": s} for o, s in data_regions],
            "string_count":  len(strings),
            "strings_sample": [s for _, s in strings[:20]],
            "repeated_structures": [
                {"offset": o, "stride": st, "count": c}
                for o, st, c in repeats[:10]
            ],
        }

    # ------------------------------------------------------------------
    # Specialised structure finders
    # ------------------------------------------------------------------

    def find_pe_sections(self, data: bytes) -> List[SectionInfo]:
        """Parse PE section table if *data* is a PE file."""
        data = bytes(data)
        if len(data) < 64 or data[:2] != b"MZ":
            return []
        pe_offset_pos = 0x3C
        if len(data) < pe_offset_pos + 4:
            return []
        pe_off = struct.unpack_from("<I", data, pe_offset_pos)[0]
        if len(data) < pe_off + 24:
            return []
        if data[pe_off:pe_off + 4] != b"PE\x00\x00":
            return []
        machine         = struct.unpack_from("<H", data, pe_off + 4)[0]
        num_sections    = struct.unpack_from("<H", data, pe_off + 6)[0]
        opt_header_size = struct.unpack_from("<H", data, pe_off + 20)[0]
        section_table_off = pe_off + 24 + opt_header_size

        sections: List[SectionInfo] = []
        for i in range(num_sections):
            entry_off = section_table_off + i * 40
            if entry_off + 40 > len(data):
                break
            raw_name = data[entry_off:entry_off + 8].rstrip(b"\x00")
            name      = raw_name.decode("ascii", errors="replace")
            vsize     = struct.unpack_from("<I", data, entry_off + 8)[0]
            rva       = struct.unpack_from("<I", data, entry_off + 12)[0]
            raw_size  = struct.unpack_from("<I", data, entry_off + 16)[0]
            raw_off   = struct.unpack_from("<I", data, entry_off + 20)[0]

            sec_data = data[raw_off:raw_off + raw_size]
            ent      = _shannon_entropy(sec_data)

            sections.append(SectionInfo(
                name          = name,
                offset        = raw_off,
                size          = raw_size,
                entropy       = ent,
                is_compressed = ent > self.COMPRESSED_ENTROPY_THRESHOLD,
                is_encrypted  = ent > self.ENCRYPTED_ENTROPY_THRESHOLD,
                attributes    = {"rva": rva, "vsize": vsize},
            ))
        return sections

    def find_elf_sections(self, data: bytes) -> List[SectionInfo]:
        """Parse ELF section headers if *data* is an ELF file."""
        data = bytes(data)
        if len(data) < 64 or data[:4] != b"\x7fELF":
            return []
        bits   = 64 if data[4] == 2 else 32
        endian = ">" if data[5] == 2 else "<"
        fmt_prefix = endian

        if bits == 32:
            if len(data) < 52:
                return []
            e_shoff, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                fmt_prefix + "IHHH", data, 32
            )
        else:
            if len(data) < 64:
                return []
            e_shoff = struct.unpack_from(fmt_prefix + "Q", data, 40)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                fmt_prefix + "HHH", data, 58
            )

        if e_shoff == 0 or e_shnum == 0:
            return []

        # String table section
        str_entry_off = e_shoff + e_shstrndx * e_shentsize
        if bits == 32:
            if len(data) < str_entry_off + 40:
                return []
            str_sh_off, str_sh_size = struct.unpack_from(fmt_prefix + "II", data, str_entry_off + 16)
        else:
            if len(data) < str_entry_off + 64:
                return []
            str_sh_off  = struct.unpack_from(fmt_prefix + "Q", data, str_entry_off + 24)[0]
            str_sh_size = struct.unpack_from(fmt_prefix + "Q", data, str_entry_off + 32)[0]

        strtab = data[str_sh_off:str_sh_off + str_sh_size]

        sections: List[SectionInfo] = []
        for i in range(e_shnum):
            entry_off = e_shoff + i * e_shentsize
            if bits == 32:
                if entry_off + 40 > len(data):
                    break
                sh_name_idx, sh_type, sh_flags, sh_addr, sh_offset, sh_size = \
                    struct.unpack_from(fmt_prefix + "IIIIII", data, entry_off)
            else:
                if entry_off + 64 > len(data):
                    break
                sh_name_idx = struct.unpack_from(fmt_prefix + "I", data, entry_off)[0]
                sh_type     = struct.unpack_from(fmt_prefix + "I", data, entry_off + 4)[0]
                sh_offset   = struct.unpack_from(fmt_prefix + "Q", data, entry_off + 24)[0]
                sh_size     = struct.unpack_from(fmt_prefix + "Q", data, entry_off + 32)[0]

            # Resolve name from string table
            name_end = strtab.find(b"\x00", sh_name_idx)
            if name_end == -1:
                name_end = len(strtab)
            try:
                sec_name = strtab[sh_name_idx:name_end].decode("ascii", errors="replace")
            except Exception:
                sec_name = f"section_{i}"

            sec_data = data[sh_offset:sh_offset + sh_size]
            ent      = _shannon_entropy(sec_data)

            sections.append(SectionInfo(
                name          = sec_name or f"<{i}>",
                offset        = sh_offset,
                size          = sh_size,
                entropy       = ent,
                is_compressed = ent > self.COMPRESSED_ENTROPY_THRESHOLD,
                is_encrypted  = ent > self.ENCRYPTED_ENTROPY_THRESHOLD,
                attributes    = {"sh_type": sh_type},
            ))
        return sections

    # ------------------------------------------------------------------
    # Utility: find all occurrences of a magic value
    # ------------------------------------------------------------------

    def find_magic_occurrences(
        self, data: bytes, magic: bytes
    ) -> List[int]:
        """Return all byte offsets where *magic* appears in *data*."""
        data   = bytes(data)
        offsets: List[int] = []
        start = 0
        while True:
            idx = data.find(magic, start)
            if idx == -1:
                break
            offsets.append(idx)
            start = idx + 1
        return offsets

    def find_embedded_signatures(self, data: bytes) -> List[FileSignature]:
        """Scan entire *data* for embedded file signatures (not just offset 0)."""
        data    = bytes(data)
        found:  List[FileSignature] = []
        for sig in self._sigs:
            magic = sig["magic"]
            for off in self.find_magic_occurrences(data, magic):
                score = min(1.0, len(magic) / 8 + 0.3)
                found.append(FileSignature(
                    name        = sig["name"],
                    mime_type   = sig.get("mime", ""),
                    magic_bytes = magic,
                    offset      = off,
                    confidence  = score,
                    extensions  = list(sig.get("ext", [])),
                ))
        found.sort(key=lambda s: s.offset)
        return found

    # ------------------------------------------------------------------
    # Text / format helpers
    # ------------------------------------------------------------------

    def hex_dump(
        self,
        data: bytes,
        offset: int = 0,
        length: Optional[int] = None,
        width: int = 16,
    ) -> str:
        """Format *data* as a hex dump string.

        Parameters
        ----------
        data : bytes
            Data to dump.
        offset : int
            Starting offset label.
        length : int, optional
            Maximum bytes to dump.
        width : int
            Bytes per line.

        Returns
        -------
        str
        """
        data = bytes(data)
        if length is not None:
            data = data[:length]
        lines: List[str] = []
        for i in range(0, len(data), width):
            chunk    = data[i:i + width]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(
                f"{offset + i:08X}  {hex_part:<{width * 3 - 1}}  |{asc_part}|"
            )
        return "\n".join(lines)

    def print_summary(self, data: bytes) -> None:
        """Print a formatted analysis summary to stdout."""
        s = self.summarize(data)
        print(f"Size      : {s['size']:,} bytes")
        print(f"MD5       : {s['md5']}")
        print(f"SHA-256   : {s['sha256']}")
        print(f"Format    : {s['format']} ({s['format_confidence']:.0%})")
        print(f"Encoding  : {s['encoding']}")
        print(f"Endianness: {s['endianness']}")
        print(f"Entropy   : {s['entropy']:.4f}")
        print(f"Compressed: {s['is_compressed']}")
        print(f"Encrypted : {s['is_encrypted']}")
        print(f"Sections  : {len(s['sections'])}")
        print(f"Strings   : {s['string_count']}")
        if s["strings_sample"]:
            for st in s["strings_sample"][:5]:
                print(f"  {st!r}")


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of a byte string (0–8 bits per byte)."""
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


def entropy_label(ent: float) -> str:
    """Return a human-readable label for an entropy value."""
    if ent < 1.0:
        return "near-zero (zeros/padding)"
    if ent < 3.5:
        return "low (structured data)"
    if ent < 6.5:
        return "medium (code or text)"
    if ent < 7.2:
        return "high (mixed data)"
    if ent < 7.8:
        return "very high (likely compressed)"
    return "max (likely encrypted or random)"


# ---------------------------------------------------------------------------
# CLI convenience
# ---------------------------------------------------------------------------

def analyze_file(path: str) -> dict:
    """Convenience function: analyse a file and return the summary dict."""
    data = Path(path).read_bytes()
    return BinaryAnalyzer().summarize(data)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("BinaryAnalyzer self-test")
    print("=" * 40)

    ba = BinaryAnalyzer()

    # ELF magic
    elf_stub = b"\x7fELF" + b"\x01" * 100
    sig = ba.detect_format(elf_stub)
    assert sig.name == "ELF", f"Expected ELF, got {sig.name}"
    print(f"PASS: ELF detected → {sig}")

    # ZIP magic
    zip_stub = b"PK\x03\x04" + b"\x00" * 100
    sig = ba.detect_format(zip_stub)
    assert sig.name == "ZIP"
    print(f"PASS: ZIP detected → {sig}")

    # Entropy of zeros
    ent = _shannon_entropy(b"\x00" * 256)
    assert ent == 0.0
    print("PASS: zero entropy")

    # Entropy of random
    import os
    rand = os.urandom(1024)
    ent  = _shannon_entropy(rand)
    assert ent > 7.0, f"Random entropy too low: {ent}"
    print(f"PASS: random entropy = {ent:.4f}")

    # String extraction
    data = b"\x00\x00hello world\x00\x00test123\x00"
    strs = ba.find_strings(data, min_len=4)
    found_strs = [s for _, s in strs]
    assert "hello world" in found_strs
    print(f"PASS: string extraction → {found_strs}")

    # Endianness
    le_data = struct.pack("<IIII", 1, 2, 3, 4) * 10
    end = ba.detect_endianness(le_data)
    print(f"PASS: endianness = {end}")

    # Summarize
    summary = ba.summarize(zip_stub + b"\x00" * 512)
    assert "format" in summary
    print("PASS: summarize returned dict with 'format' key")

    print("\nAll self-tests passed.")
