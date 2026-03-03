# =============================================================================
# BinModder - Compression Engine Module
# =============================================================================
# Implements compression and decompression algorithms commonly found in
# firmware, ROM, and embedded binary files. Includes RLE variants, LZ77,
# LZSS, LZO, zlib/deflate, and auto-detection.
#
# Author: MSR Electronics
# Version: 1.0.0
# =============================================================================

import zlib
import io
import struct
from enum import Enum
from typing import Optional, Union, List, Tuple
from pathlib import Path


# =============================================================================
# Enumerations
# =============================================================================

class CompressionAlgorithm(Enum):
    """Available compression algorithms."""
    NONE    = "none"
    ZLIB    = "zlib"
    DEFLATE = "deflate"
    GZIP    = "gzip"
    BZIP2   = "bzip2"
    LZMA    = "lzma"
    LZ77    = "lz77"
    LZSS    = "lzss"
    RLE     = "rle"
    RLE_NES = "rle_nes"   # NES/SNES style RLE
    RLE_PS2 = "rle_ps2"   # PS2 style RLE
    RLE_PB  = "rle_pb"    # PackBits (Apple/TIFF) style RLE
    LZO     = "lzo"
    LZ4     = "lz4"
    AUTO    = "auto"


class CompressionError(Exception):
    """Base exception for compression errors."""
    pass


class DecompressionError(CompressionError):
    """Raised when decompression fails."""
    pass


class CompressionResult:
    """Result of a compression operation."""

    def __init__(
        self,
        data:       bytes,
        algorithm:  CompressionAlgorithm,
        original_size: int,
        compressed_size: int,
    ):
        self.data            = data
        self.algorithm       = algorithm
        self.original_size   = original_size
        self.compressed_size = compressed_size

    @property
    def ratio(self) -> float:
        """Compression ratio (compressed/original)."""
        if self.original_size == 0:
            return 1.0
        return self.compressed_size / self.original_size

    @property
    def space_saved(self) -> int:
        """Bytes saved by compression."""
        return self.original_size - self.compressed_size

    @property
    def percent_saved(self) -> float:
        """Percentage of space saved."""
        if self.original_size == 0:
            return 0.0
        return (1 - self.ratio) * 100

    def __repr__(self) -> str:
        return (
            f"CompressionResult("
            f"algo={self.algorithm.name}, "
            f"ratio={self.ratio:.2%}, "
            f"saved={self.space_saved} bytes)"
        )


# =============================================================================
# RLE Implementations
# =============================================================================

class RLEEngine:
    """
    Run-Length Encoding (RLE) with multiple variant support.

    Variants:
    - Standard RLE: [count][byte] pairs
    - PackBits (Apple): 0x80-0xFF = repeat, 0x00-0x7F = literal
    - NES/SNES: various game console formats
    - PS2: PlayStation 2 specific
    """

    # --- Standard RLE ---

    @staticmethod
    def compress(data: bytes, min_run: int = 3) -> bytes:
        """
        Standard RLE compression.

        Format: For each run of 3+ identical bytes:
          - 0xFF followed by count and byte value
        Otherwise: literal bytes

        Args:
            data:    Input bytes
            min_run: Minimum run length to encode

        Returns:
            Compressed bytes
        """
        result = bytearray()
        i      = 0

        while i < len(data):
            # Count run length
            run_start = i
            byte_val  = data[i]
            run_len   = 1

            while (i + run_len < len(data) and
                   data[i + run_len] == byte_val and
                   run_len < 255):
                run_len += 1

            if run_len >= min_run:
                # Encode as RLE run
                result.append(0xFF)
                result.append(run_len)
                result.append(byte_val)
                i += run_len
            else:
                # Literal byte
                if data[i] == 0xFF:
                    # Escape literal 0xFF
                    result.append(0xFF)
                    result.append(0x01)
                    result.append(0xFF)
                else:
                    result.append(data[i])
                i += 1

        return bytes(result)

    @staticmethod
    def decompress(data: bytes) -> bytes:
        """Standard RLE decompression."""
        result = bytearray()
        i      = 0

        while i < len(data):
            if data[i] == 0xFF:
                if i + 2 >= len(data):
                    raise DecompressionError("Truncated RLE sequence")
                count    = data[i + 1]
                byte_val = data[i + 2]
                result.extend([byte_val] * count)
                i += 3
            else:
                result.append(data[i])
                i += 1

        return bytes(result)

    # --- PackBits RLE (Apple/TIFF style) ---

    @staticmethod
    def packbits_compress(data: bytes) -> bytes:
        """
        PackBits compression (used in Apple, TIFF, many game formats).

        Control byte:
        - 0x00 to 0x7F: Copy (n+1) literal bytes
        - 0x81 to 0xFF: Repeat next byte (257-n) times
        - 0x80: No-op
        """
        result = bytearray()
        i      = 0

        while i < len(data):
            # Check for run
            if i + 1 < len(data) and data[i] == data[i + 1]:
                byte_val = data[i]
                run_len  = 2
                while (i + run_len < len(data) and
                       data[i + run_len] == byte_val and
                       run_len < 128):
                    run_len += 1
                result.append(257 - run_len)  # 0x81 to 0xFF
                result.append(byte_val)
                i += run_len
            else:
                # Collect literals
                lit_start = i
                lit_bytes = bytearray([data[i]])
                i += 1
                while (i < len(data) and
                       len(lit_bytes) < 128 and
                       (i + 1 >= len(data) or data[i] != data[i + 1])):
                    lit_bytes.append(data[i])
                    i += 1

                result.append(len(lit_bytes) - 1)  # 0x00 to 0x7F
                result.extend(lit_bytes)

        return bytes(result)

    @staticmethod
    def packbits_decompress(data: bytes, max_size: int = 16 * 1024 * 1024) -> bytes:
        """PackBits decompression."""
        result = bytearray()
        i      = 0

        while i < len(data):
            ctrl = data[i]
            i   += 1

            if ctrl == 0x80:
                continue  # No-op
            elif ctrl <= 0x7F:
                # Copy (ctrl+1) literal bytes
                count = ctrl + 1
                if i + count > len(data):
                    raise DecompressionError("Truncated PackBits literal run")
                result.extend(data[i:i + count])
                i += count
            else:
                # Repeat next byte (257 - ctrl) times
                count = 257 - ctrl
                if i >= len(data):
                    raise DecompressionError("Truncated PackBits run")
                byte_val = data[i]
                i += 1
                result.extend([byte_val] * count)

            if len(result) > max_size:
                raise DecompressionError(f"Decompressed size exceeds limit {max_size}")

        return bytes(result)

    # --- NES/SNES Style RLE ---

    @staticmethod
    def nes_decompress(data: bytes) -> bytes:
        """
        NES-style RLE decompression.
        Used in many NES/SNES games.

        Format:
        - High bit 0: repeat next byte (bits 5-0 = count+1)
        - High bit 1: literal bytes (bits 5-0 = count+1)
        """
        result = bytearray()
        i      = 0

        while i < len(data):
            ctrl = data[i]
            i   += 1

            if ctrl == 0xFF:
                break  # End marker

            if ctrl & 0x80:
                # Literal block
                count = (ctrl & 0x7F) + 1
                if i + count > len(data):
                    raise DecompressionError("Truncated NES RLE literal block")
                result.extend(data[i:i + count])
                i += count
            else:
                # Run
                count = (ctrl & 0x7F) + 1
                if i >= len(data):
                    raise DecompressionError("Truncated NES RLE run")
                byte_val = data[i]
                i += 1
                result.extend([byte_val] * count)

        return bytes(result)

    @staticmethod
    def nes_compress(data: bytes) -> bytes:
        """NES-style RLE compression."""
        result = bytearray()
        i      = 0

        while i < len(data):
            # Check for run
            byte_val = data[i]
            run_len  = 1
            while (i + run_len < len(data) and
                   data[i + run_len] == byte_val and
                   run_len < 128):
                run_len += 1

            if run_len >= 3:
                # Encode as run
                result.append(run_len - 1)  # High bit clear = run
                result.append(byte_val)
                i += run_len
            else:
                # Collect literals
                lits = bytearray()
                j    = i
                while j < len(data) and len(lits) < 128:
                    # Check ahead for run
                    next_run = 1
                    while (j + next_run < len(data) and
                           data[j + next_run] == data[j] and
                           next_run < 3):
                        next_run += 1

                    if next_run >= 3:
                        break
                    lits.append(data[j])
                    j += 1

                if lits:
                    result.append(0x80 | (len(lits) - 1))
                    result.extend(lits)
                    i = j
                else:
                    i += 1

        result.append(0xFF)  # End marker
        return bytes(result)


# =============================================================================
# LZ77 Implementation
# =============================================================================

class LZ77Engine:
    """LZ77 sliding window compression."""

    def __init__(
        self,
        window_size:  int = 4096,
        look_ahead:   int = 18,
        min_match:    int = 3,
    ):
        self.window_size = window_size
        self.look_ahead  = look_ahead
        self.min_match   = min_match

    def compress(self, data: bytes) -> bytes:
        """LZ77 compression."""
        result = bytearray()
        i      = 0
        n      = len(data)

        while i < n:
            best_offset = 0
            best_length = 0

            # Search in the sliding window
            win_start = max(0, i - self.window_size)
            for j in range(win_start, i):
                length = 0
                while (length < self.look_ahead and
                       i + length < n and
                       data[j + length % (i - j)] == data[i + length]):
                    length += 1

                if length > best_length:
                    best_offset = i - j
                    best_length = length

            if best_length >= self.min_match:
                # Encode as back-reference
                # Format: 1 bit flag, 12-bit offset, 4-bit length-min_match
                flag    = 1
                offset  = best_offset & 0xFFF
                length  = (best_length - self.min_match) & 0xF

                # Pack into 2 bytes (simplified LZSS format)
                result.append(0x80 | ((offset >> 4) & 0x7F))
                result.append(((offset & 0xF) << 4) | length)
                i += best_length
            else:
                # Literal byte
                result.append(0x00)
                result.append(data[i])
                i += 1

        return bytes(result)

    def decompress(self, data: bytes) -> bytes:
        """LZ77 decompression."""
        result = bytearray()
        i      = 0

        while i < len(data):
            flag = data[i]
            i   += 1

            if flag == 0x00:
                # Literal byte
                if i >= len(data):
                    break
                result.append(data[i])
                i += 1
            elif flag & 0x80:
                # Back-reference
                if i >= len(data):
                    break
                b2     = data[i]
                i     += 1
                offset = ((flag & 0x7F) << 4) | (b2 >> 4)
                length = (b2 & 0xF) + self.min_match

                if offset == 0:
                    raise DecompressionError("LZ77: zero back-reference offset")

                back_pos = len(result) - offset
                if back_pos < 0:
                    raise DecompressionError(f"LZ77: invalid back-reference offset {offset}")

                for k in range(length):
                    result.append(result[back_pos + k % offset])
            else:
                # Literal byte (alternate encoding)
                result.append(flag)

        return bytes(result)


# =============================================================================
# LZSS Implementation
# =============================================================================

class LZSSEngine:
    """LZSS compression (improvement of LZ77)."""

    def __init__(
        self,
        window_size: int = 4096,
        look_ahead:  int = 18,
        min_match:   int = 2,
    ):
        self.window_size = window_size
        self.look_ahead  = look_ahead
        self.min_match   = min_match

    def compress(self, data: bytes) -> bytes:
        """LZSS compression with flag bytes."""
        result    = bytearray()
        i         = 0
        n         = len(data)
        flag_byte = 0
        flag_pos  = 0
        buffer    = bytearray()
        bit_count = 0

        while i < n:
            # Search window
            win_start    = max(0, i - self.window_size)
            best_offset  = 0
            best_length  = 0

            for j in range(win_start, i):
                length = 0
                while (length < self.look_ahead and
                       i + length < n and
                       data[j + length] == data[i + length]):
                    length += 1
                    if j + length >= i:
                        break

                if length > best_length:
                    best_offset = i - j
                    best_length = length

            if best_length >= self.min_match:
                # Reference: offset and length
                if bit_count == 0:
                    flag_pos = len(result)
                    result.append(0)  # placeholder for flag byte

                # Flag bit = 0 (reference)
                bit_count += 1
                # Encode: 12-bit offset, 4-bit length
                ref_offset = (i - best_offset) & 0xFFF
                ref_length = (best_length - self.min_match) & 0xF
                result.append((ref_offset >> 4) & 0xFF)
                result.append(((ref_offset & 0xF) << 4) | ref_length)
                i += best_length
            else:
                if bit_count == 0:
                    flag_pos = len(result)
                    result.append(0)

                # Literal: flag bit = 1
                result[flag_pos] |= (1 << bit_count)
                result.append(data[i])
                i += 1
                bit_count += 1

            if bit_count == 8:
                bit_count = 0

        return bytes(result)

    def decompress(self, data: bytes, output_size: Optional[int] = None) -> bytes:
        """LZSS decompression."""
        result = bytearray()
        i      = 0

        while i < len(data):
            flag_byte = data[i]
            i        += 1

            for bit in range(8):
                if i >= len(data):
                    break
                if output_size is not None and len(result) >= output_size:
                    return bytes(result[:output_size])

                if flag_byte & (1 << bit):
                    # Literal byte
                    result.append(data[i])
                    i += 1
                else:
                    # Back-reference
                    if i + 1 >= len(data):
                        break
                    b1 = data[i]
                    b2 = data[i + 1]
                    i += 2

                    ref_offset = ((b1 << 4) | (b2 >> 4))
                    ref_length = (b2 & 0xF) + self.min_match

                    back_pos = ref_offset
                    if back_pos == 0 or back_pos > len(result):
                        raise DecompressionError(f"LZSS: invalid reference offset {back_pos}")

                    base = len(result) - back_pos
                    for k in range(ref_length):
                        result.append(result[base + k % back_pos])

        if output_size is not None:
            result = result[:output_size]

        return bytes(result)


# =============================================================================
# Compression Engine - Main Class
# =============================================================================

class CompressionEngine:
    """
    Unified compression and decompression engine.

    Supports:
    - zlib/deflate (standard)
    - gzip
    - bzip2
    - lzma/xz
    - RLE (standard, PackBits, NES style)
    - LZ77, LZSS
    - Auto-detection

    Usage:
        engine = CompressionEngine()

        # Compress with zlib
        result = engine.compress(data, CompressionAlgorithm.ZLIB)
        print(f"Ratio: {result.ratio:.1%}")

        # Decompress
        original = engine.decompress(result.data, CompressionAlgorithm.ZLIB)

        # Auto-detect and decompress
        original = engine.decompress_auto(compressed_data)
    """

    def __init__(self):
        self._rle  = RLEEngine()
        self._lz77 = LZ77Engine()
        self._lzss = LZSSEngine()

    # -------------------------------------------------------------------------
    # Compression Methods
    # -------------------------------------------------------------------------

    def compress_zlib(self, data: bytes, level: int = 6) -> bytes:
        """Compress using zlib (deflate + header)."""
        return zlib.compress(data, level)

    def decompress_zlib(self, data: bytes) -> bytes:
        """Decompress zlib data."""
        return zlib.decompress(data)

    def compress_deflate(self, data: bytes, level: int = 6) -> bytes:
        """Compress using raw deflate (no header)."""
        return zlib.compress(data, level)[2:-4]  # Strip zlib header/trailer

    def decompress_deflate(self, data: bytes) -> bytes:
        """Decompress raw deflate data."""
        return zlib.decompress(data, -15)

    def compress_gzip(self, data: bytes, level: int = 6) -> bytes:
        """Compress using gzip format."""
        import gzip
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=level) as f:
            f.write(data)
        return buf.getvalue()

    def decompress_gzip(self, data: bytes) -> bytes:
        """Decompress gzip data."""
        import gzip
        return gzip.decompress(data)

    def compress_bzip2(self, data: bytes, level: int = 9) -> bytes:
        """Compress using bzip2."""
        import bz2
        return bz2.compress(data, level)

    def decompress_bzip2(self, data: bytes) -> bytes:
        """Decompress bzip2 data."""
        import bz2
        return bz2.decompress(data)

    def compress_lzma(self, data: bytes) -> bytes:
        """Compress using LZMA."""
        import lzma
        return lzma.compress(data)

    def decompress_lzma(self, data: bytes) -> bytes:
        """Decompress LZMA data."""
        import lzma
        return lzma.decompress(data)

    def compress_rle(self, data: bytes, min_run: int = 3) -> bytes:
        """Compress using standard RLE."""
        return RLEEngine.compress(data, min_run)

    def decompress_rle(self, data: bytes) -> bytes:
        """Decompress standard RLE data."""
        return RLEEngine.decompress(data)

    def compress_packbits(self, data: bytes) -> bytes:
        """Compress using PackBits RLE."""
        return RLEEngine.packbits_compress(data)

    def decompress_packbits(self, data: bytes) -> bytes:
        """Decompress PackBits RLE data."""
        return RLEEngine.packbits_decompress(data)

    def compress_nes_rle(self, data: bytes) -> bytes:
        """Compress using NES-style RLE."""
        return RLEEngine.nes_compress(data)

    def decompress_nes_rle(self, data: bytes) -> bytes:
        """Decompress NES-style RLE data."""
        return RLEEngine.nes_decompress(data)

    def compress_lz77(self, data: bytes) -> bytes:
        """Compress using LZ77."""
        return self._lz77.compress(data)

    def decompress_lz77(self, data: bytes) -> bytes:
        """Decompress LZ77 data."""
        return self._lz77.decompress(data)

    def compress_lzss(self, data: bytes) -> bytes:
        """Compress using LZSS."""
        return self._lzss.compress(data)

    def decompress_lzss(self, data: bytes, output_size: Optional[int] = None) -> bytes:
        """Decompress LZSS data."""
        return self._lzss.decompress(data, output_size)

    # -------------------------------------------------------------------------
    # Unified Interface
    # -------------------------------------------------------------------------

    def compress(
        self,
        data:      bytes,
        algorithm: CompressionAlgorithm = CompressionAlgorithm.ZLIB,
        **kwargs
    ) -> CompressionResult:
        """
        Compress data using the specified algorithm.

        Args:
            data:      Input bytes
            algorithm: Compression algorithm
            **kwargs:  Algorithm-specific parameters

        Returns:
            CompressionResult with compressed data and statistics
        """
        original_size = len(data)

        algo_map = {
            CompressionAlgorithm.ZLIB:    self.compress_zlib,
            CompressionAlgorithm.DEFLATE: self.compress_deflate,
            CompressionAlgorithm.GZIP:    self.compress_gzip,
            CompressionAlgorithm.BZIP2:   self.compress_bzip2,
            CompressionAlgorithm.LZMA:    self.compress_lzma,
            CompressionAlgorithm.RLE:     self.compress_rle,
            CompressionAlgorithm.RLE_PB:  self.compress_packbits,
            CompressionAlgorithm.RLE_NES: self.compress_nes_rle,
            CompressionAlgorithm.LZ77:    self.compress_lz77,
            CompressionAlgorithm.LZSS:    self.compress_lzss,
            CompressionAlgorithm.NONE:    lambda d: d,
        }

        compress_func = algo_map.get(algorithm)
        if compress_func is None:
            raise CompressionError(f"Unsupported algorithm: {algorithm}")

        try:
            compressed = compress_func(data)
        except Exception as e:
            raise CompressionError(f"Compression failed: {e}") from e

        return CompressionResult(
            data=compressed,
            algorithm=algorithm,
            original_size=original_size,
            compressed_size=len(compressed),
        )

    def decompress(
        self,
        data:      bytes,
        algorithm: CompressionAlgorithm,
        **kwargs
    ) -> bytes:
        """Decompress data using specified algorithm."""
        algo_map = {
            CompressionAlgorithm.ZLIB:    self.decompress_zlib,
            CompressionAlgorithm.DEFLATE: self.decompress_deflate,
            CompressionAlgorithm.GZIP:    self.decompress_gzip,
            CompressionAlgorithm.BZIP2:   self.decompress_bzip2,
            CompressionAlgorithm.LZMA:    self.decompress_lzma,
            CompressionAlgorithm.RLE:     self.decompress_rle,
            CompressionAlgorithm.RLE_PB:  self.decompress_packbits,
            CompressionAlgorithm.RLE_NES: self.decompress_nes_rle,
            CompressionAlgorithm.LZ77:    self.decompress_lz77,
            CompressionAlgorithm.LZSS:    self.decompress_lzss,
            CompressionAlgorithm.NONE:    lambda d: d,
        }

        decompress_func = algo_map.get(algorithm)
        if decompress_func is None:
            raise DecompressionError(f"Unsupported algorithm: {algorithm}")

        try:
            if algorithm == CompressionAlgorithm.LZSS and "output_size" in kwargs:
                return self._lzss.decompress(data, kwargs["output_size"])
            return decompress_func(data)
        except Exception as e:
            raise DecompressionError(f"Decompression failed: {e}") from e

    # -------------------------------------------------------------------------
    # Auto-Detection
    # -------------------------------------------------------------------------

    def detect_compression(self, data: bytes) -> CompressionAlgorithm:
        """
        Auto-detect compression format from magic bytes.

        Returns:
            Detected algorithm, or NONE if uncompressed
        """
        if len(data) < 2:
            return CompressionAlgorithm.NONE

        # gzip: 1F 8B
        if data[:2] == b"\x1F\x8B":
            return CompressionAlgorithm.GZIP

        # zlib: 78 xx (where xx can be 01, 9C, DA)
        if data[0] == 0x78 and data[1] in (0x01, 0x9C, 0xDA, 0x5E):
            return CompressionAlgorithm.ZLIB

        # bzip2: BZh
        if data[:3] == b"BZh":
            return CompressionAlgorithm.BZIP2

        # xz/lzma: FD 37 7A 58 5A 00
        if data[:6] == b"\xFD7zXZ\x00":
            return CompressionAlgorithm.LZMA

        # LZMA raw: 5D 00 00 xx xx
        if data[0] == 0x5D and data[1] == 0x00 and data[2] == 0x00:
            return CompressionAlgorithm.LZMA

        return CompressionAlgorithm.NONE

    def decompress_auto(self, data: bytes) -> Tuple[bytes, CompressionAlgorithm]:
        """
        Auto-detect and decompress data.

        Returns:
            (decompressed_data, detected_algorithm) tuple
        """
        algo = self.detect_compression(data)
        if algo == CompressionAlgorithm.NONE:
            return data, algo
        try:
            return self.decompress(data, algo), algo
        except Exception as e:
            raise DecompressionError(
                f"Auto-decompression failed with detected algo {algo}: {e}"
            ) from e

    # -------------------------------------------------------------------------
    # Benchmark
    # -------------------------------------------------------------------------

    def benchmark(
        self,
        data:       bytes,
        algorithms: Optional[List[CompressionAlgorithm]] = None,
    ) -> List[CompressionResult]:
        """
        Benchmark multiple compression algorithms on the same data.

        Returns:
            List of CompressionResult sorted by compression ratio
        """
        if algorithms is None:
            algorithms = [
                CompressionAlgorithm.ZLIB,
                CompressionAlgorithm.GZIP,
                CompressionAlgorithm.BZIP2,
                CompressionAlgorithm.LZMA,
                CompressionAlgorithm.RLE,
                CompressionAlgorithm.LZ77,
            ]

        results = []
        for algo in algorithms:
            try:
                result = self.compress(data, algo)
                results.append(result)
            except Exception:
                pass

        results.sort(key=lambda r: r.ratio)
        return results

    # -------------------------------------------------------------------------
    # File Operations
    # -------------------------------------------------------------------------

    def compress_file(
        self,
        input_path:  Union[str, Path],
        output_path: Union[str, Path],
        algorithm:   CompressionAlgorithm = CompressionAlgorithm.ZLIB,
    ) -> CompressionResult:
        """Compress a file."""
        input_path  = Path(input_path)
        output_path = Path(output_path)

        with open(input_path, "rb") as f:
            data = f.read()

        result = self.compress(data, algorithm)

        with open(output_path, "wb") as f:
            f.write(result.data)

        return result

    def decompress_file(
        self,
        input_path:  Union[str, Path],
        output_path: Union[str, Path],
        algorithm:   CompressionAlgorithm = CompressionAlgorithm.AUTO,
    ) -> bytes:
        """Decompress a file."""
        input_path  = Path(input_path)
        output_path = Path(output_path)

        with open(input_path, "rb") as f:
            data = f.read()

        if algorithm == CompressionAlgorithm.AUTO:
            result, _ = self.decompress_auto(data)
        else:
            result = self.decompress(data, algorithm)

        with open(output_path, "wb") as f:
            f.write(result)

        return result

    # -------------------------------------------------------------------------
    # Representation
    # -------------------------------------------------------------------------

    def __repr__(self) -> str:
        return "CompressionEngine(zlib, gzip, bzip2, lzma, RLE, LZ77, LZSS)"
