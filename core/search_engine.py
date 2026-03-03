# =============================================================================
# BinModder - Search Engine Module
# =============================================================================
# Implements multiple binary search algorithms including Boyer-Moore,
# Knuth-Morris-Pratt, Rabin-Karp, and regex-based binary pattern search.
# Supports wildcards, masks, and fuzzy matching.
#
# Author: MSR Electronics
# Version: 1.0.0
# =============================================================================

import re
import struct
from enum import Enum
from typing import (
    Optional, Union, List, Tuple, Generator, Iterator, Callable
)
from pathlib import Path


# =============================================================================
# Enumerations
# =============================================================================

class SearchAlgorithm(Enum):
    """Available search algorithms."""
    NAIVE       = "naive"        # Simple linear scan
    BOYER_MOORE = "boyer_moore"  # Boyer-Moore (best for large patterns)
    KMP         = "kmp"          # Knuth-Morris-Pratt (preprocessed pattern)
    RABIN_KARP  = "rabin_karp"   # Rabin-Karp (rolling hash)
    REGEX       = "regex"        # Python regex on binary data
    AUTOMATCH   = "auto"         # Automatically select best algorithm


class SearchDirection(Enum):
    """Direction of search."""
    FORWARD  = "forward"
    BACKWARD = "backward"


# =============================================================================
# Search Result
# =============================================================================

class SearchResult:
    """Represents a single search match."""

    def __init__(
        self,
        offset:    int,
        data:      bytes,
        pattern:   bytes,
        match_len: int
    ):
        self.offset    = offset       # Byte offset of match in file
        self.data      = data         # Matched bytes
        self.pattern   = pattern      # Pattern that was searched
        self.match_len = match_len    # Length of match (may differ for wildcards)

    @property
    def end_offset(self) -> int:
        """Offset of byte after match."""
        return self.offset + self.match_len

    def __repr__(self) -> str:
        return (
            f"SearchResult("
            f"offset=0x{self.offset:08X}, "
            f"data={self.data.hex().upper()}, "
            f"len={self.match_len})"
        )

    def __str__(self) -> str:
        return f"0x{self.offset:08X}: {self.data.hex(' ').upper()}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SearchResult):
            return NotImplemented
        return self.offset == other.offset

    def __hash__(self) -> int:
        return hash(self.offset)

    def to_dict(self) -> dict:
        return {
            "offset":   self.offset,
            "offset_hex": f"0x{self.offset:08X}",
            "data":     self.data.hex().upper(),
            "length":   self.match_len,
        }


class SearchResults:
    """Collection of search results with iteration and filtering."""

    def __init__(self, results: List[SearchResult], pattern: bytes, data_size: int):
        self._results  = results
        self.pattern   = pattern
        self.data_size = data_size

    @property
    def count(self) -> int:
        return len(self._results)

    @property
    def offsets(self) -> List[int]:
        return [r.offset for r in self._results]

    @property
    def first(self) -> Optional[SearchResult]:
        return self._results[0] if self._results else None

    @property
    def last(self) -> Optional[SearchResult]:
        return self._results[-1] if self._results else None

    def __len__(self) -> int:
        return len(self._results)

    def __iter__(self) -> Iterator[SearchResult]:
        return iter(self._results)

    def __getitem__(self, idx: int) -> SearchResult:
        return self._results[idx]

    def __bool__(self) -> bool:
        return len(self._results) > 0

    def filter_range(self, start: int, end: int) -> "SearchResults":
        """Return results within an offset range."""
        filtered = [r for r in self._results if start <= r.offset < end]
        return SearchResults(filtered, self.pattern, self.data_size)

    def __repr__(self) -> str:
        return f"SearchResults(count={self.count}, pattern={self.pattern.hex().upper()!r})"


# =============================================================================
# Pattern Specification
# =============================================================================

class Pattern:
    """
    Binary search pattern with optional wildcard support.

    Supports:
    - Hex strings: "DE AD BE EF"
    - Wildcards: "DE ?? BE EF" (any byte)
    - Byte ranges: "DE [40-4F] BE EF"
    - Regex: compiled re patterns

    Examples:
        Pattern.from_hex("FF FF 00 AB")
        Pattern.from_hex("FF ?? 00 ??")      # with wildcards
        Pattern.from_bytes(b"\xFF\xFF\x00\xAB")
        Pattern.from_string("HELLO", "ascii")
    """

    WILDCARD = 0x100  # Sentinel value for wildcard bytes

    def __init__(self, pattern_bytes: List[int], original: str = ""):
        """
        Args:
            pattern_bytes: List of byte values (0-255) or WILDCARD (256)
            original:      Original pattern string (for display)
        """
        self._pattern  = pattern_bytes
        self._original = original
        self._has_wildcards = any(b == self.WILDCARD for b in pattern_bytes)

    @classmethod
    def from_hex(cls, hex_str: str) -> "Pattern":
        """
        Create pattern from hex string.

        Args:
            hex_str: Hex string with optional wildcards (?? or *)

        Examples:
            Pattern.from_hex("DE AD BE EF")
            Pattern.from_hex("DE ?? BE ??")
        """
        tokens  = hex_str.upper().split()
        pattern = []
        for token in tokens:
            if token in ("??", "**", "__", ".."):
                pattern.append(cls.WILDCARD)
            else:
                pattern.append(int(token, 16))
        return cls(pattern, hex_str)

    @classmethod
    def from_bytes(cls, data: bytes) -> "Pattern":
        """Create pattern from bytes object (no wildcards)."""
        return cls(list(data), data.hex(" ").upper())

    @classmethod
    def from_string(cls, text: str, encoding: str = "utf-8") -> "Pattern":
        """Create pattern from a text string."""
        data = text.encode(encoding)
        return cls.from_bytes(data)

    @classmethod
    def from_uint32_le(cls, value: int) -> "Pattern":
        """Create pattern from a uint32 little endian value."""
        data = struct.pack("<I", value & 0xFFFFFFFF)
        return cls.from_bytes(data)

    @classmethod
    def from_uint32_be(cls, value: int) -> "Pattern":
        """Create pattern from a uint32 big endian value."""
        data = struct.pack(">I", value & 0xFFFFFFFF)
        return cls.from_bytes(data)

    @classmethod
    def from_uint16_le(cls, value: int) -> "Pattern":
        """Create pattern from a uint16 little endian value."""
        data = struct.pack("<H", value & 0xFFFF)
        return cls.from_bytes(data)

    @classmethod
    def from_uint16_be(cls, value: int) -> "Pattern":
        """Create pattern from a uint16 big endian value."""
        data = struct.pack(">H", value & 0xFFFF)
        return cls.from_bytes(data)

    @property
    def length(self) -> int:
        return len(self._pattern)

    @property
    def has_wildcards(self) -> bool:
        return self._has_wildcards

    @property
    def as_bytes(self) -> Optional[bytes]:
        """Return as bytes if no wildcards, else None."""
        if self._has_wildcards:
            return None
        return bytes(self._pattern)

    @property
    def wildcard_positions(self) -> List[int]:
        """Return list of positions that are wildcards."""
        return [i for i, b in enumerate(self._pattern) if b == self.WILDCARD]

    def matches(self, data: bytes, offset: int = 0) -> bool:
        """Check if data at offset matches this pattern."""
        if offset + self.length > len(data):
            return False
        for i, pb in enumerate(self._pattern):
            if pb == self.WILDCARD:
                continue
            if data[offset + i] != pb:
                return False
        return True

    def to_regex(self) -> bytes:
        """Convert pattern to regex bytes for re module."""
        parts = []
        for pb in self._pattern:
            if pb == self.WILDCARD:
                parts.append(b".")
            else:
                parts.append(re.escape(bytes([pb])))
        return b"".join(parts)

    def __len__(self) -> int:
        return self.length

    def __repr__(self) -> str:
        tokens = []
        for pb in self._pattern:
            if pb == self.WILDCARD:
                tokens.append("??")
            else:
                tokens.append(f"{pb:02X}")
        return f"Pattern({' '.join(tokens)!r})"


# =============================================================================
# Search Algorithms
# =============================================================================

class NaiveSearch:
    """Simple linear scan search algorithm."""

    @staticmethod
    def search(data: bytes, pattern: bytes) -> List[int]:
        """Find all occurrences of pattern in data."""
        results = []
        plen    = len(pattern)
        dlen    = len(data)
        for i in range(dlen - plen + 1):
            if data[i:i + plen] == pattern:
                results.append(i)
        return results


class BoyerMooreSearch:
    """Boyer-Moore string search algorithm for binary data."""

    def __init__(self, pattern: bytes):
        self.pattern = pattern
        self._bad_char   = self._build_bad_char_table()
        self._good_suffix = self._build_good_suffix_table()

    def _build_bad_char_table(self) -> List[int]:
        """Build bad character table."""
        table   = [-1] * 256
        pattern = self.pattern
        for i, c in enumerate(pattern):
            table[c] = i
        return table

    def _build_good_suffix_table(self) -> List[int]:
        """Build good suffix shift table."""
        m      = len(self.pattern)
        shift  = [m] * (m + 1)
        border = [0] * (m + 1)

        i = m
        j = m + 1
        border[i] = j

        while i > 0:
            while j <= m and self.pattern[i - 1] != self.pattern[j - 1]:
                if shift[j] == m:
                    shift[j] = j - i
                j = border[j]
            i -= 1
            j -= 1
            border[i] = j

        j = border[0]
        for i in range(m + 1):
            if shift[i] == m:
                shift[i] = j
            if i == j:
                j = border[j]

        return shift

    def search(self, data: bytes) -> List[int]:
        """Find all occurrences of pattern in data."""
        results = []
        m       = len(self.pattern)
        n       = len(data)
        s       = 0  # Shift

        while s <= n - m:
            j = m - 1
            while j >= 0 and self.pattern[j] == data[s + j]:
                j -= 1

            if j < 0:
                results.append(s)
                s += self._good_suffix[0]
            else:
                s += max(
                    self._good_suffix[j + 1],
                    j - self._bad_char[data[s + j]]
                )

        return results


class KMPSearch:
    """Knuth-Morris-Pratt search algorithm."""

    def __init__(self, pattern: bytes):
        self.pattern = pattern
        self._failure = self._build_failure_function()

    def _build_failure_function(self) -> List[int]:
        """Build the KMP failure function."""
        m       = len(self.pattern)
        failure = [0] * m
        j       = 0

        for i in range(1, m):
            while j > 0 and self.pattern[i] != self.pattern[j]:
                j = failure[j - 1]
            if self.pattern[i] == self.pattern[j]:
                j += 1
            failure[i] = j

        return failure

    def search(self, data: bytes) -> List[int]:
        """Find all occurrences of pattern in data."""
        results = []
        m       = len(self.pattern)
        n       = len(data)
        j       = 0

        for i in range(n):
            while j > 0 and data[i] != self.pattern[j]:
                j = self._failure[j - 1]
            if data[i] == self.pattern[j]:
                j += 1
            if j == m:
                results.append(i - m + 1)
                j = self._failure[j - 1]

        return results


class RabinKarpSearch:
    """Rabin-Karp rolling hash search algorithm."""

    BASE  = 256
    MOD   = 1_000_000_007

    def __init__(self, pattern: bytes):
        self.pattern = pattern
        self._m      = len(pattern)
        self._hash_p = self._compute_hash(pattern)
        self._h      = pow(self.BASE, self._m - 1, self.MOD)

    def _compute_hash(self, data: bytes) -> int:
        """Compute rolling hash."""
        h = 0
        for b in data:
            h = (h * self.BASE + b) % self.MOD
        return h

    def search(self, data: bytes) -> List[int]:
        """Find all occurrences using rolling hash."""
        results = []
        m       = self._m
        n       = len(data)

        if n < m:
            return results

        # Compute hash of first window
        hash_w = self._compute_hash(data[:m])

        for i in range(n - m + 1):
            if hash_w == self._hash_p:
                # Verify byte by byte
                if data[i:i + m] == self.pattern:
                    results.append(i)

            if i < n - m:
                # Update rolling hash
                hash_w = (
                    (hash_w - data[i] * self._h) * self.BASE + data[i + m]
                ) % self.MOD
                if hash_w < 0:
                    hash_w += self.MOD

        return results


# =============================================================================
# Search Engine - Main Class
# =============================================================================

class SearchEngine:
    """
    Binary pattern search engine with multiple algorithm support.

    Supports:
    - Exact byte pattern search
    - Wildcard patterns (??)
    - String search (ascii, utf-8, utf-16)
    - Regex binary patterns
    - Case-insensitive string search
    - Multiple file search
    - Streaming large file search

    Usage:
        engine = SearchEngine()

        # Find pattern in binary data
        results = engine.find(data, "DE AD BE EF")

        # Wildcard search
        results = engine.find(data, "DE ?? BE ??")

        # Find all uint32 values matching
        results = engine.find_value(data, 0x12345678)

        # String search
        results = engine.find_string(data, "HELLO WORLD")
    """

    def __init__(self, default_algorithm: SearchAlgorithm = SearchAlgorithm.AUTOMATCH):
        self.default_algorithm = default_algorithm

    def _select_algorithm(self, pattern_len: int) -> SearchAlgorithm:
        """Select the best algorithm based on pattern length."""
        if pattern_len <= 2:
            return SearchAlgorithm.NAIVE
        elif pattern_len <= 16:
            return SearchAlgorithm.KMP
        else:
            return SearchAlgorithm.BOYER_MOORE

    def _do_exact_search(
        self,
        data:      bytes,
        pattern:   bytes,
        algorithm: SearchAlgorithm
    ) -> List[int]:
        """Perform exact byte pattern search."""
        if algorithm == SearchAlgorithm.AUTOMATCH:
            algorithm = self._select_algorithm(len(pattern))

        if algorithm == SearchAlgorithm.NAIVE:
            return NaiveSearch.search(data, pattern)
        elif algorithm == SearchAlgorithm.BOYER_MOORE:
            return BoyerMooreSearch(pattern).search(data)
        elif algorithm == SearchAlgorithm.KMP:
            return KMPSearch(pattern).search(data)
        elif algorithm == SearchAlgorithm.RABIN_KARP:
            return RabinKarpSearch(pattern).search(data)
        else:
            # Fallback
            return NaiveSearch.search(data, pattern)

    def _do_wildcard_search(self, data: bytes, pattern: Pattern) -> List[int]:
        """Search using wildcard pattern matching."""
        results = []
        plen    = pattern.length
        dlen    = len(data)

        for i in range(dlen - plen + 1):
            if pattern.matches(data, i):
                results.append(i)

        return results

    def _do_regex_search(
        self,
        data:    bytes,
        pattern: bytes,
        flags:   int = 0
    ) -> List[int]:
        """Search using binary regex."""
        results = []
        for m in re.finditer(pattern, data, flags | re.DOTALL):
            results.append(m.start())
        return results

    # -------------------------------------------------------------------------
    # Primary Search Methods
    # -------------------------------------------------------------------------

    def find(
        self,
        data:       Union[bytes, bytearray, str, Path],
        pattern:    Union[str, bytes, Pattern],
        start:      int = 0,
        end:        Optional[int] = None,
        algorithm:  SearchAlgorithm = SearchAlgorithm.AUTOMATCH,
        max_results: Optional[int] = None,
    ) -> SearchResults:
        """
        Find all occurrences of a pattern in binary data.

        Args:
            data:        Binary data to search in
            pattern:     Pattern to search for (hex string, bytes, or Pattern)
            start:       Start offset
            end:         End offset
            algorithm:   Search algorithm to use
            max_results: Maximum number of results to return

        Returns:
            SearchResults object

        Examples:
            results = engine.find(data, "DE AD BE EF")
            results = engine.find(data, "FF ?? 00 ??")   # wildcards
            results = engine.find(data, b"\xDE\xAD\xBE\xEF")
        """
        # Normalize data
        if isinstance(data, (str, Path)):
            with open(data, "rb") as f:
                raw = f.read()
        elif isinstance(data, bytearray):
            raw = bytes(data)
        else:
            raw = data

        # Normalize pattern
        if isinstance(pattern, str):
            pat_obj = Pattern.from_hex(pattern)
        elif isinstance(pattern, bytes):
            pat_obj = Pattern.from_bytes(pattern)
        elif isinstance(pattern, Pattern):
            pat_obj = pattern
        else:
            raise TypeError(f"Unsupported pattern type: {type(pattern).__name__}")

        # Apply range
        if end is None:
            end = len(raw)
        search_region = raw[start:end]

        # Search
        if pat_obj.has_wildcards:
            offsets = self._do_wildcard_search(search_region, pat_obj)
        elif algorithm == SearchAlgorithm.REGEX:
            offsets = self._do_regex_search(search_region, pat_obj.as_bytes or b"")
        else:
            offsets = self._do_exact_search(
                search_region,
                pat_obj.as_bytes or b"",
                algorithm
            )

        # Adjust for start offset
        offsets = [o + start for o in offsets]

        # Limit results
        if max_results is not None:
            offsets = offsets[:max_results]

        # Build results
        results = []
        for offset in offsets:
            matched_data = raw[offset:offset + pat_obj.length]
            results.append(SearchResult(
                offset=offset,
                data=matched_data,
                pattern=pat_obj.as_bytes or b"",
                match_len=pat_obj.length
            ))

        return SearchResults(results, pat_obj.as_bytes or b"", len(raw))

    def find_first(
        self,
        data:    Union[bytes, bytearray],
        pattern: Union[str, bytes, Pattern],
        start:   int = 0,
        end:     Optional[int] = None,
    ) -> Optional[SearchResult]:
        """Find first occurrence of pattern. Returns None if not found."""
        results = self.find(data, pattern, start, end, max_results=1)
        return results.first

    def find_last(
        self,
        data:    Union[bytes, bytearray],
        pattern: Union[str, bytes, Pattern],
        start:   int = 0,
        end:     Optional[int] = None,
    ) -> Optional[SearchResult]:
        """Find last occurrence of pattern. Returns None if not found."""
        results = self.find(data, pattern, start, end)
        return results.last

    # -------------------------------------------------------------------------
    # Type-Based Search
    # -------------------------------------------------------------------------

    def find_uint8(
        self, data: bytes, value: int,
        start: int = 0, end: Optional[int] = None
    ) -> SearchResults:
        """Find all occurrences of a uint8 value."""
        pat = Pattern.from_bytes(struct.pack("B", value & 0xFF))
        return self.find(data, pat, start, end)

    def find_uint16_le(
        self, data: bytes, value: int,
        start: int = 0, end: Optional[int] = None
    ) -> SearchResults:
        """Find all occurrences of a uint16 LE value."""
        pat = Pattern.from_bytes(struct.pack("<H", value & 0xFFFF))
        return self.find(data, pat, start, end)

    def find_uint16_be(
        self, data: bytes, value: int,
        start: int = 0, end: Optional[int] = None
    ) -> SearchResults:
        """Find all occurrences of a uint16 BE value."""
        pat = Pattern.from_bytes(struct.pack(">H", value & 0xFFFF))
        return self.find(data, pat, start, end)

    def find_uint32_le(
        self, data: bytes, value: int,
        start: int = 0, end: Optional[int] = None
    ) -> SearchResults:
        """Find all occurrences of a uint32 LE value."""
        pat = Pattern.from_bytes(struct.pack("<I", value & 0xFFFFFFFF))
        return self.find(data, pat, start, end)

    def find_uint32_be(
        self, data: bytes, value: int,
        start: int = 0, end: Optional[int] = None
    ) -> SearchResults:
        """Find all occurrences of a uint32 BE value."""
        pat = Pattern.from_bytes(struct.pack(">I", value & 0xFFFFFFFF))
        return self.find(data, pat, start, end)

    def find_uint64_le(
        self, data: bytes, value: int,
        start: int = 0, end: Optional[int] = None
    ) -> SearchResults:
        """Find all occurrences of a uint64 LE value."""
        pat = Pattern.from_bytes(struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))
        return self.find(data, pat, start, end)

    def find_value(
        self,
        data:  bytes,
        value: int,
        size:  int = 4,
        start: int = 0,
        end:   Optional[int] = None,
    ) -> SearchResults:
        """
        Find all occurrences of an integer value in both LE and BE.

        Args:
            data:  Data to search
            value: Integer value to find
            size:  Width in bytes (1, 2, 4, or 8)
            start: Start offset
            end:   End offset

        Returns:
            Combined results from LE and BE search
        """
        if size == 1:
            return self.find_uint8(data, value, start, end)
        elif size == 2:
            le = self.find_uint16_le(data, value, start, end)
            be = self.find_uint16_be(data, value, start, end)
        elif size == 4:
            le = self.find_uint32_le(data, value, start, end)
            be = self.find_uint32_be(data, value, start, end)
        elif size == 8:
            le = self.find_uint64_le(data, value, start, end)
            be_pat = Pattern.from_bytes(struct.pack(">Q", value & 0xFFFFFFFFFFFFFFFF))
            be = self.find(data, be_pat, start, end)
        else:
            raise ValueError(f"Invalid size: {size}. Must be 1, 2, 4, or 8.")

        # Merge results
        all_results = sorted(
            le._results + be._results,
            key=lambda r: r.offset
        )
        return SearchResults(all_results, b"", len(data))

    # -------------------------------------------------------------------------
    # String Search
    # -------------------------------------------------------------------------

    def find_string(
        self,
        data:      bytes,
        text:      str,
        encoding:  str = "utf-8",
        case_sensitive: bool = True,
        start:     int = 0,
        end:       Optional[int] = None,
    ) -> SearchResults:
        """
        Search for a text string in binary data.

        Args:
            data:           Binary data
            text:           Text to search for
            encoding:       Character encoding
            case_sensitive: Case sensitive search
            start:          Start offset
            end:            End offset
        """
        encoded = text.encode(encoding)

        if not case_sensitive:
            if encoding in ("ascii", "latin-1", "cp1252"):
                # Case insensitive ASCII: search for both cases
                regex_pat = re.escape(text).encode("ascii")
                offsets   = self._do_regex_search(
                    data[start:end or len(data)],
                    regex_pat,
                    flags=re.IGNORECASE
                )
                offsets = [o + start for o in offsets]
                results = [
                    SearchResult(o, data[o:o + len(encoded)], encoded, len(encoded))
                    for o in offsets
                ]
                return SearchResults(results, encoded, len(data))

        pat = Pattern.from_bytes(encoded)
        return self.find(data, pat, start, end)

    def find_string_utf16(
        self,
        data:   bytes,
        text:   str,
        little_endian: bool = True,
        start:  int = 0,
        end:    Optional[int] = None,
    ) -> SearchResults:
        """Search for a UTF-16 string in binary data."""
        encoding = "utf-16-le" if little_endian else "utf-16-be"
        encoded  = text.encode(encoding)
        pat      = Pattern.from_bytes(encoded)
        return self.find(data, pat, start, end)

    def find_all_strings(
        self,
        data:       bytes,
        min_length: int = 4,
        encoding:   str = "ascii",
        start:      int = 0,
        end:        Optional[int] = None,
    ) -> List[Tuple[int, str]]:
        """
        Extract all printable strings from binary data.

        Args:
            data:       Binary data
            min_length: Minimum string length to report
            encoding:   Character encoding to use
            start:      Start offset
            end:        End offset

        Returns:
            List of (offset, string) tuples
        """
        if end is None:
            end = len(data)
        region  = data[start:end]
        strings = []

        # Regex for printable ASCII sequences
        pattern = rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}"
        for m in re.finditer(pattern, region):
            offset = m.start() + start
            try:
                text = m.group(0).decode(encoding)
                strings.append((offset, text))
            except Exception:
                pass

        return strings

    # -------------------------------------------------------------------------
    # Regex Binary Search
    # -------------------------------------------------------------------------

    def find_regex(
        self,
        data:    bytes,
        pattern: Union[str, bytes],
        start:   int = 0,
        end:     Optional[int] = None,
        flags:   int = 0,
    ) -> List[Tuple[int, bytes]]:
        """
        Search using regex on binary data.

        Args:
            data:    Binary data
            pattern: Regex pattern (str or bytes)
            start:   Start offset
            end:     End offset
            flags:   re module flags

        Returns:
            List of (offset, matched_bytes) tuples
        """
        if end is None:
            end = len(data)
        region = data[start:end]

        if isinstance(pattern, str):
            # Convert hex-based regex to binary
            pattern = pattern.encode("latin-1")

        results = []
        for m in re.finditer(pattern, region, flags | re.DOTALL):
            offset = m.start() + start
            results.append((offset, m.group(0)))

        return results

    # -------------------------------------------------------------------------
    # Specialized Searches
    # -------------------------------------------------------------------------

    def find_magic_bytes(
        self,
        data: bytes,
        start: int = 0,
        end: Optional[int] = None,
    ) -> List[Tuple[int, str, bytes]]:
        """
        Scan for known file magic bytes within binary data.

        Returns:
            List of (offset, format_name, magic_bytes) tuples
        """
        KNOWN_MAGIC = [
            (b"\x7FELF",                   "ELF Executable"),
            (b"MZ",                        "PE/DOS Executable"),
            (b"\x89PNG\r\n\x1a\n",        "PNG Image"),
            (b"\xFF\xD8\xFF",              "JPEG Image"),
            (b"GIF87a",                    "GIF87 Image"),
            (b"GIF89a",                    "GIF89 Image"),
            (b"PK\x03\x04",               "ZIP Archive"),
            (b"PK\x05\x06",               "ZIP Empty"),
            (b"\x1f\x8b",                  "GZIP Compressed"),
            (b"BZh",                       "BZIP2 Compressed"),
            (b"\xfd7zXZ\x00",             "XZ Compressed"),
            (b"RIFF",                      "RIFF Container (WAV/AVI)"),
            (b"\x00\x00\x01\xba",          "MPEG Program Stream"),
            (b"\x00\x00\x01\xb3",          "MPEG Video"),
            (b"ftyp",                      "MP4/ISO Base Media"),
            (b"\x25PDF",                   "PDF Document"),
            (b"SQLite format 3",           "SQLite Database"),
            (b"\xCA\xFE\xBA\xBE",          "Java Class File"),
            (b"\xFE\xED\xFA\xCE",          "Mach-O 32-bit Binary"),
            (b"\xFE\xED\xFA\xCF",          "Mach-O 64-bit Binary"),
            (b"\xCE\xFA\xED\xFE",          "Mach-O 32-bit (reversed)"),
            (b"\xCF\xFA\xED\xFE",          "Mach-O 64-bit (reversed)"),
            (b"BOOT",                      "PS2 Boot Sector"),
            (b"\x00\x97\x12\x80",          "PS3 Package"),
            (b"\x80\x00\x00\x01",          "PS1 BIOS"),
            (b"SEGA",                      "SEGA ROM"),
            (b"NROM",                      "NES ROM"),
            (b"\x2E\x6E\x64\x73",          "NDS ROM"),
            (b"\xFF\xFF\xFF\xFF",          "Empty Flash (0xFF fill)"),
            (b"\x00\x00\x00\x00",          "Empty Flash (0x00 fill)"),
        ]

        if end is None:
            end = len(data)
        region  = data[start:end]
        results = []

        for magic, name in KNOWN_MAGIC:
            engine = KMPSearch(magic)
            for offset in engine.search(region):
                results.append((offset + start, name, magic))

        results.sort(key=lambda x: x[0])
        return results

    def find_pointers(
        self,
        data:     bytes,
        base_addr: int,
        ptr_size:  int = 4,
        endian:    str = "little",
        start:     int = 0,
        end:       Optional[int] = None,
    ) -> List[Tuple[int, int]]:
        """
        Find all values that look like valid pointers within a given address space.

        Args:
            data:      Binary data
            base_addr: Base address of the binary
            ptr_size:  Pointer size (4 for 32-bit, 8 for 64-bit)
            endian:    "little" or "big"
            start:     Search start offset
            end:       Search end offset

        Returns:
            List of (file_offset, pointer_value) tuples
        """
        if end is None:
            end = len(data)

        results    = []
        file_size  = end - start
        max_ptr    = base_addr + file_size

        fmt = "<I" if (ptr_size == 4 and endian == "little") else \
              ">I" if (ptr_size == 4 and endian == "big") else \
              "<Q" if (ptr_size == 8 and endian == "little") else ">Q"

        for offset in range(start, end - ptr_size + 1, ptr_size):
            try:
                value = struct.unpack_from(fmt, data, offset)[0]
                if base_addr <= value < max_ptr:
                    results.append((offset, value))
            except struct.error:
                break

        return results

    def find_repeated_byte(
        self,
        data:      bytes,
        byte_val:  int,
        min_count: int = 16,
        start:     int = 0,
        end:       Optional[int] = None,
    ) -> List[Tuple[int, int]]:
        """
        Find runs of a repeated byte value.

        Args:
            data:      Binary data
            byte_val:  Byte to look for (0-255)
            min_count: Minimum run length
            start:     Start offset
            end:       End offset

        Returns:
            List of (offset, count) tuples for each run
        """
        if end is None:
            end = len(data)

        results   = []
        i         = start
        target    = byte_val & 0xFF

        while i < end:
            if data[i] == target:
                run_start = i
                while i < end and data[i] == target:
                    i += 1
                run_len = i - run_start
                if run_len >= min_count:
                    results.append((run_start, run_len))
            else:
                i += 1

        return results

    def find_null_blocks(
        self,
        data:      bytes,
        min_size:  int = 64,
        start:     int = 0,
        end:       Optional[int] = None,
    ) -> List[Tuple[int, int]]:
        """Find blocks of null (0x00) bytes."""
        return self.find_repeated_byte(data, 0x00, min_size, start, end)

    def find_ff_blocks(
        self,
        data:      bytes,
        min_size:  int = 64,
        start:     int = 0,
        end:       Optional[int] = None,
    ) -> List[Tuple[int, int]]:
        """Find blocks of 0xFF bytes (empty flash regions)."""
        return self.find_repeated_byte(data, 0xFF, min_size, start, end)

    # -------------------------------------------------------------------------
    # Streaming Search
    # -------------------------------------------------------------------------

    def find_in_file(
        self,
        path:       Union[str, Path],
        pattern:    Union[str, bytes, Pattern],
        chunk_size: int = 65536,
    ) -> SearchResults:
        """
        Search for a pattern in a large file using chunked reading.
        Handles patterns that span chunk boundaries.

        Args:
            path:       File path to search
            pattern:    Pattern to search for
            chunk_size: Size of each read chunk

        Returns:
            SearchResults
        """
        path = Path(path)

        # Normalize pattern
        if isinstance(pattern, str):
            pat_obj = Pattern.from_hex(pattern)
        elif isinstance(pattern, bytes):
            pat_obj = Pattern.from_bytes(pattern)
        else:
            pat_obj = pattern

        pat_bytes = pat_obj.as_bytes
        pat_len   = pat_obj.length

        results   = []
        offset    = 0
        buffer    = bytearray()

        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                buffer.extend(chunk)

                # Search in buffer
                if pat_obj.has_wildcards:
                    search_end = len(buffer) - pat_len + 1
                    for i in range(search_end):
                        if pat_obj.matches(bytes(buffer), i):
                            results.append(SearchResult(
                                offset + i, bytes(buffer[i:i + pat_len]),
                                b"", pat_len
                            ))
                elif pat_bytes:
                    for pos in KMPSearch(pat_bytes).search(bytes(buffer[:len(buffer) - pat_len + 1])):
                        results.append(SearchResult(
                            offset + pos,
                            bytes(buffer[pos:pos + pat_len]),
                            pat_bytes,
                            pat_len
                        ))

                # Keep overlap for boundary patterns
                overlap = pat_len - 1
                if len(buffer) > overlap:
                    offset += len(buffer) - overlap
                    buffer  = buffer[-overlap:]

        file_size = path.stat().st_size
        return SearchResults(results, pat_bytes or b"", file_size)

    # -------------------------------------------------------------------------
    # Replace
    # -------------------------------------------------------------------------

    def replace_all(
        self,
        data:        bytearray,
        pattern:     Union[str, bytes, Pattern],
        replacement: bytes,
        start:       int = 0,
        end:         Optional[int] = None,
    ) -> Tuple[bytearray, int]:
        """
        Replace all occurrences of pattern with replacement.

        Args:
            data:        Mutable binary data
            pattern:     Pattern to find
            replacement: Replacement bytes
            start:       Start offset
            end:         End offset

        Returns:
            (modified_data, count_replaced) tuple
        """
        results = self.find(bytes(data), pattern, start, end)
        count   = 0

        # Replace in reverse order to maintain offsets
        for result in reversed(results._results):
            offset = result.offset
            plen   = result.match_len
            rlen   = len(replacement)

            if rlen == plen:
                data[offset:offset + plen] = replacement
            elif rlen < plen:
                data[offset:offset + plen] = replacement + bytes(plen - rlen)
            else:
                # Truncate replacement to fit
                data[offset:offset + plen] = replacement[:plen]
            count += 1

        return data, count

    def replace_first(
        self,
        data:        bytearray,
        pattern:     Union[str, bytes, Pattern],
        replacement: bytes,
        start:       int = 0,
        end:         Optional[int] = None,
    ) -> Tuple[bytearray, bool]:
        """Replace only the first occurrence."""
        result = self.find_first(bytes(data), pattern, start, end)
        if result is None:
            return data, False

        offset = result.offset
        plen   = result.match_len
        rlen   = len(replacement)

        if rlen == plen:
            data[offset:offset + plen] = replacement
        elif rlen < plen:
            data[offset:offset + plen] = replacement + bytes(plen - rlen)
        else:
            data[offset:offset + plen] = replacement[:plen]

        return data, True

    # -------------------------------------------------------------------------
    # Cross-Reference
    # -------------------------------------------------------------------------

    def find_xrefs(
        self,
        data:      bytes,
        target_offset: int,
        base_addr:  int = 0,
        ptr_size:   int = 4,
        endian:     str = "little",
    ) -> List[int]:
        """
        Find all cross-references to a given file offset.

        Args:
            data:          Binary data
            target_offset: File offset to find references to
            base_addr:     Base address of the binary
            ptr_size:      Pointer size in bytes
            endian:        Byte order

        Returns:
            List of file offsets that contain a reference
        """
        target_va = base_addr + target_offset

        if ptr_size == 4:
            if endian == "little":
                target_bytes = struct.pack("<I", target_va & 0xFFFFFFFF)
            else:
                target_bytes = struct.pack(">I", target_va & 0xFFFFFFFF)
        else:
            if endian == "little":
                target_bytes = struct.pack("<Q", target_va)
            else:
                target_bytes = struct.pack(">Q", target_va)

        results = self.find(data, Pattern.from_bytes(target_bytes))
        return results.offsets

    # -------------------------------------------------------------------------
    # Representation
    # -------------------------------------------------------------------------

    def __repr__(self) -> str:
        return f"SearchEngine(default_algo={self.default_algorithm.name})"
