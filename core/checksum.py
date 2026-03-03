# =============================================================================
# BinModder - Checksum Engine Module
# =============================================================================
# Implements 30+ checksum and hash algorithms for binary file integrity
# verification. Supports CRC variants (8/16/32/64), Adler, Fletcher,
# Longitudinal Redundancy Check (LRC), MD5, SHA-1/224/256/384/512, and more.
#
# Author: MSR Electronics
# Version: 1.0.0
# =============================================================================

import hashlib
import struct
import zlib
from enum import Enum
from typing import Optional, Union, List, Tuple, Callable, Dict, Any
from pathlib import Path


# =============================================================================
# Enumerations
# =============================================================================

class ChecksumAlgorithm(Enum):
    """Available checksum and hash algorithms."""
    # CRC variants
    CRC8          = "crc8"
    CRC8_MAXIM    = "crc8_maxim"
    CRC8_ROHC     = "crc8_rohc"
    CRC16         = "crc16"
    CRC16_CCITT   = "crc16_ccitt"
    CRC16_XMODEM  = "crc16_xmodem"
    CRC16_MODBUS  = "crc16_modbus"
    CRC16_IBM     = "crc16_ibm"
    CRC32         = "crc32"
    CRC32C        = "crc32c"
    CRC32_BZIP2   = "crc32_bzip2"
    CRC32_POSIX   = "crc32_posix"
    CRC64         = "crc64"
    CRC64_ECMA    = "crc64_ecma"
    # Sum variants
    SUM8          = "sum8"
    SUM16         = "sum16"
    SUM32         = "sum32"
    XSUM          = "xsum"   # XOR sum
    NEGSUM        = "negsum" # Negative sum (two's complement)
    # Adler / Fletcher
    ADLER32       = "adler32"
    FLETCHER8     = "fletcher8"
    FLETCHER16    = "fletcher16"
    FLETCHER32    = "fletcher32"
    # LRC
    LRC           = "lrc"
    # Cryptographic hashes
    MD4           = "md4"
    MD5           = "md5"
    SHA1          = "sha1"
    SHA224        = "sha224"
    SHA256        = "sha256"
    SHA384        = "sha384"
    SHA512        = "sha512"
    SHA3_256      = "sha3_256"
    SHA3_512      = "sha3_512"
    BLAKE2B       = "blake2b"
    BLAKE2S       = "blake2s"
    # Simple
    INTERNET      = "internet"  # Internet checksum (RFC 1071)
    ONES_COMP     = "ones_complement"


# =============================================================================
# CRC Tables and Configuration
# =============================================================================

class CRCConfig:
    """Configuration for a CRC algorithm."""

    def __init__(
        self,
        width:   int,
        poly:    int,
        init:    int,
        ref_in:  bool,
        ref_out: bool,
        xor_out: int,
        name:    str = ""
    ):
        self.width   = width
        self.poly    = poly
        self.init    = init
        self.ref_in  = ref_in
        self.ref_out = ref_out
        self.xor_out = xor_out
        self.name    = name
        self.mask    = (1 << width) - 1

    def __repr__(self) -> str:
        return (
            f"CRCConfig({self.name}: width={self.width}, "
            f"poly=0x{self.poly:X}, init=0x{self.init:X})"
        )


# Standard CRC configurations (from CRC Catalogue)
CRC_CONFIGS: Dict[ChecksumAlgorithm, CRCConfig] = {
    ChecksumAlgorithm.CRC8: CRCConfig(
        width=8, poly=0x07, init=0x00, ref_in=False,
        ref_out=False, xor_out=0x00, name="CRC-8"
    ),
    ChecksumAlgorithm.CRC8_MAXIM: CRCConfig(
        width=8, poly=0x31, init=0x00, ref_in=True,
        ref_out=True, xor_out=0x00, name="CRC-8/MAXIM"
    ),
    ChecksumAlgorithm.CRC8_ROHC: CRCConfig(
        width=8, poly=0x07, init=0xFF, ref_in=True,
        ref_out=True, xor_out=0x00, name="CRC-8/ROHC"
    ),
    ChecksumAlgorithm.CRC16: CRCConfig(
        width=16, poly=0x8005, init=0x0000, ref_in=True,
        ref_out=True, xor_out=0x0000, name="CRC-16"
    ),
    ChecksumAlgorithm.CRC16_CCITT: CRCConfig(
        width=16, poly=0x1021, init=0xFFFF, ref_in=False,
        ref_out=False, xor_out=0x0000, name="CRC-16/CCITT-FALSE"
    ),
    ChecksumAlgorithm.CRC16_XMODEM: CRCConfig(
        width=16, poly=0x1021, init=0x0000, ref_in=False,
        ref_out=False, xor_out=0x0000, name="CRC-16/XMODEM"
    ),
    ChecksumAlgorithm.CRC16_MODBUS: CRCConfig(
        width=16, poly=0x8005, init=0xFFFF, ref_in=True,
        ref_out=True, xor_out=0x0000, name="CRC-16/MODBUS"
    ),
    ChecksumAlgorithm.CRC16_IBM: CRCConfig(
        width=16, poly=0x8005, init=0x0000, ref_in=True,
        ref_out=True, xor_out=0x0000, name="CRC-16/IBM"
    ),
    ChecksumAlgorithm.CRC32: CRCConfig(
        width=32, poly=0x04C11DB7, init=0xFFFFFFFF, ref_in=True,
        ref_out=True, xor_out=0xFFFFFFFF, name="CRC-32"
    ),
    ChecksumAlgorithm.CRC32_BZIP2: CRCConfig(
        width=32, poly=0x04C11DB7, init=0xFFFFFFFF, ref_in=False,
        ref_out=False, xor_out=0xFFFFFFFF, name="CRC-32/BZIP2"
    ),
    ChecksumAlgorithm.CRC32_POSIX: CRCConfig(
        width=32, poly=0x04C11DB7, init=0x00000000, ref_in=False,
        ref_out=False, xor_out=0xFFFFFFFF, name="CRC-32/POSIX"
    ),
    ChecksumAlgorithm.CRC64_ECMA: CRCConfig(
        width=64, poly=0x42F0E1EBA9EA3693, init=0xFFFFFFFFFFFFFFFF,
        ref_in=False, ref_out=False, xor_out=0xFFFFFFFFFFFFFFFF,
        name="CRC-64/ECMA-182"
    ),
}


# =============================================================================
# CRC Engine
# =============================================================================

class CRCEngine:
    """
    Generic CRC computation engine using the CRC Catalogue configurations.
    Supports any combination of polynomial, width, init, reflection, and XOR.
    """

    def __init__(self, config: CRCConfig):
        self.config = config
        self._table = self._build_table()

    def _reflect(self, value: int, bits: int) -> int:
        """Reflect (reverse) the bits of a value."""
        result = 0
        for _ in range(bits):
            result = (result << 1) | (value & 1)
            value >>= 1
        return result

    def _build_table(self) -> List[int]:
        """Build the CRC lookup table."""
        table = []
        width = self.config.width
        poly  = self.config.poly
        mask  = self.config.mask
        msb   = 1 << (width - 1)

        for i in range(256):
            crc = i << (width - 8)
            for _ in range(8):
                if crc & msb:
                    crc = ((crc << 1) ^ poly) & mask
                else:
                    crc = (crc << 1) & mask
            table.append(crc)

        return table

    def compute(self, data: bytes) -> int:
        """Compute CRC over the given data."""
        crc    = self.config.init
        width  = self.config.width
        mask   = self.config.mask

        for byte in data:
            if self.config.ref_in:
                byte = self._reflect(byte, 8)
            pos = ((crc >> (width - 8)) ^ byte) & 0xFF
            crc = ((crc << 8) ^ self._table[pos]) & mask

        if self.config.ref_out:
            crc = self._reflect(crc, width)

        return (crc ^ self.config.xor_out) & mask

    def update(self, crc: int, data: bytes) -> int:
        """Update an existing CRC with new data (streaming use)."""
        width = self.config.width
        mask  = self.config.mask

        # Remove XOR_OUT from current state
        crc = (crc ^ self.config.xor_out) & mask

        for byte in data:
            if self.config.ref_in:
                byte = self._reflect(byte, 8)
            pos = ((crc >> (width - 8)) ^ byte) & 0xFF
            crc = ((crc << 8) ^ self._table[pos]) & mask

        if self.config.ref_out:
            crc = self._reflect(crc, width)

        return (crc ^ self.config.xor_out) & mask


# =============================================================================
# Checksum Result
# =============================================================================

class ChecksumResult:
    """Result of a checksum computation."""

    def __init__(
        self,
        algorithm:  ChecksumAlgorithm,
        value:      Union[int, bytes],
        data_size:  int,
        start:      int = 0,
        end:        Optional[int] = None,
    ):
        self.algorithm = algorithm
        self.value     = value
        self.data_size = data_size
        self.start     = start
        self.end       = end if end is not None else data_size

    @property
    def as_int(self) -> int:
        """Return checksum as integer."""
        if isinstance(self.value, bytes):
            return int.from_bytes(self.value, "big")
        return self.value

    @property
    def as_bytes(self) -> bytes:
        """Return checksum as bytes."""
        if isinstance(self.value, bytes):
            return self.value
        # Determine size
        if isinstance(self.value, int):
            bit_len  = self.value.bit_length()
            byte_len = max(1, (bit_len + 7) // 8)
            return self.value.to_bytes(byte_len, "big")
        return b""

    @property
    def as_hex(self) -> str:
        """Return checksum as hex string."""
        return self.as_bytes.hex().upper()

    def __repr__(self) -> str:
        return (
            f"ChecksumResult("
            f"algorithm={self.algorithm.name}, "
            f"value=0x{self.as_hex}, "
            f"data_size={self.data_size})"
        )

    def __str__(self) -> str:
        return f"{self.algorithm.name}: {self.as_hex}"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ChecksumResult):
            return self.as_bytes == other.as_bytes
        if isinstance(other, int):
            return self.as_int == other
        if isinstance(other, bytes):
            return self.as_bytes == other
        return NotImplemented

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm.name,
            "value_hex": self.as_hex,
            "value_int": self.as_int,
            "data_size": self.data_size,
            "start":     self.start,
            "end":       self.end,
        }


# =============================================================================
# Checksum Engine - Main Class
# =============================================================================

class ChecksumEngine:
    """
    Comprehensive checksum and hash computation engine.

    Supports 30+ algorithms including:
    - CRC-8, CRC-16, CRC-32, CRC-64 (with multiple polynomial variants)
    - Adler-32, Fletcher-8/16/32
    - Simple sum (8/16/32), XOR sum, LRC
    - MD4, MD5, SHA-1/224/256/384/512, SHA3-256/512
    - Blake2b, Blake2s
    - Internet Checksum (RFC 1071)

    Usage:
        engine = ChecksumEngine()

        # Compute CRC32
        result = engine.crc32(data)
        print(result.as_hex)   # "DEADBEEF"
        print(result.as_int)   # 3735928559

        # Compute all checksums
        all_results = engine.compute_all(data)
        for r in all_results:
            print(r)
    """

    def __init__(self):
        self._crc_engines: Dict[ChecksumAlgorithm, CRCEngine] = {}
        self._init_crc_engines()

    def _init_crc_engines(self) -> None:
        """Initialize CRC engines from configurations."""
        for algo, config in CRC_CONFIGS.items():
            self._crc_engines[algo] = CRCEngine(config)

    def _get_data(
        self,
        data:  Union[bytes, bytearray, str, "Path"],
        start: int = 0,
        end:   Optional[int] = None
    ) -> Tuple[bytes, int, int]:
        """Normalize input data and return (bytes, start, end)."""
        if isinstance(data, (str, Path)):
            with open(data, "rb") as f:
                raw = f.read()
        elif isinstance(data, bytearray):
            raw = bytes(data)
        elif isinstance(data, bytes):
            raw = data
        else:
            raise TypeError(f"Unsupported data type: {type(data).__name__}")

        if end is None:
            end = len(raw)
        region = raw[start:end]
        return region, start, end

    # -------------------------------------------------------------------------
    # CRC Algorithms
    # -------------------------------------------------------------------------

    def _compute_crc(
        self,
        algo:  ChecksumAlgorithm,
        data:  bytes,
        start: int = 0,
        end:   Optional[int] = None
    ) -> ChecksumResult:
        """Generic CRC computation."""
        region, s, e = self._get_data(data, start, end)
        engine       = self._crc_engines[algo]
        value        = engine.compute(region)
        return ChecksumResult(algo, value, len(data), s, e)

    def crc8(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute CRC-8."""
        return self._compute_crc(ChecksumAlgorithm.CRC8, data, start, end)

    def crc8_maxim(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute CRC-8/MAXIM (Dallas/Maxim 1-Wire)."""
        return self._compute_crc(ChecksumAlgorithm.CRC8_MAXIM, data, start, end)

    def crc8_rohc(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute CRC-8/ROHC."""
        return self._compute_crc(ChecksumAlgorithm.CRC8_ROHC, data, start, end)

    def crc16(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute CRC-16."""
        return self._compute_crc(ChecksumAlgorithm.CRC16, data, start, end)

    def crc16_ccitt(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute CRC-16/CCITT-FALSE."""
        return self._compute_crc(ChecksumAlgorithm.CRC16_CCITT, data, start, end)

    def crc16_xmodem(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute CRC-16/XMODEM."""
        return self._compute_crc(ChecksumAlgorithm.CRC16_XMODEM, data, start, end)

    def crc16_modbus(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute CRC-16/MODBUS."""
        return self._compute_crc(ChecksumAlgorithm.CRC16_MODBUS, data, start, end)

    def crc32(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute CRC-32 (standard PKZip/Ethernet)."""
        region, s, e = self._get_data(data, start, end)
        value        = zlib.crc32(region) & 0xFFFFFFFF
        return ChecksumResult(ChecksumAlgorithm.CRC32, value, len(data), s, e)

    def crc32_bzip2(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute CRC-32/BZIP2."""
        return self._compute_crc(ChecksumAlgorithm.CRC32_BZIP2, data, start, end)

    def crc32_posix(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute CRC-32/POSIX (cksum)."""
        return self._compute_crc(ChecksumAlgorithm.CRC32_POSIX, data, start, end)

    def crc64(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute CRC-64/ECMA-182."""
        return self._compute_crc(ChecksumAlgorithm.CRC64_ECMA, data, start, end)

    # -------------------------------------------------------------------------
    # Sum Algorithms
    # -------------------------------------------------------------------------

    def sum8(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute 8-bit sum (modulo 256)."""
        region, s, e = self._get_data(data, start, end)
        value        = sum(region) & 0xFF
        return ChecksumResult(ChecksumAlgorithm.SUM8, value, len(data), s, e)

    def sum16(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute 16-bit sum (modulo 65536)."""
        region, s, e = self._get_data(data, start, end)
        value        = sum(region) & 0xFFFF
        return ChecksumResult(ChecksumAlgorithm.SUM16, value, len(data), s, e)

    def sum32(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute 32-bit sum."""
        region, s, e = self._get_data(data, start, end)
        value        = sum(region) & 0xFFFFFFFF
        return ChecksumResult(ChecksumAlgorithm.SUM32, value, len(data), s, e)

    def xsum(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute XOR checksum (XOR of all bytes)."""
        region, s, e = self._get_data(data, start, end)
        value        = 0
        for b in region:
            value ^= b
        return ChecksumResult(ChecksumAlgorithm.XSUM, value, len(data), s, e)

    def negsum8(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute 8-bit negative sum (two's complement of sum8)."""
        region, s, e = self._get_data(data, start, end)
        total        = sum(region) & 0xFF
        value        = ((~total) + 1) & 0xFF
        return ChecksumResult(ChecksumAlgorithm.NEGSUM, value, len(data), s, e)

    def lrc(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute LRC (Longitudinal Redundancy Check)."""
        region, s, e = self._get_data(data, start, end)
        lrc_val      = 0
        for b in region:
            lrc_val = (lrc_val + b) & 0xFF
        lrc_val = ((~lrc_val) + 1) & 0xFF
        return ChecksumResult(ChecksumAlgorithm.LRC, lrc_val, len(data), s, e)

    # -------------------------------------------------------------------------
    # Adler / Fletcher Algorithms
    # -------------------------------------------------------------------------

    def adler32(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute Adler-32 checksum."""
        region, s, e = self._get_data(data, start, end)
        value        = zlib.adler32(region) & 0xFFFFFFFF
        return ChecksumResult(ChecksumAlgorithm.ADLER32, value, len(data), s, e)

    def fletcher8(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute Fletcher-8 checksum."""
        region, s, e = self._get_data(data, start, end)
        sum1 = 0
        sum2 = 0
        for b in region:
            sum1 = (sum1 + b) % 15
            sum2 = (sum2 + sum1) % 15
        value = (sum2 << 4) | sum1
        return ChecksumResult(ChecksumAlgorithm.FLETCHER8, value, len(data), s, e)

    def fletcher16(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute Fletcher-16 checksum."""
        region, s, e = self._get_data(data, start, end)
        sum1 = 0
        sum2 = 0
        for b in region:
            sum1 = (sum1 + b) % 255
            sum2 = (sum2 + sum1) % 255
        value = (sum2 << 8) | sum1
        return ChecksumResult(ChecksumAlgorithm.FLETCHER16, value, len(data), s, e)

    def fletcher32(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute Fletcher-32 checksum."""
        region, s, e = self._get_data(data, start, end)
        sum1 = 0
        sum2 = 0
        # Process 2 bytes at a time
        i = 0
        while i < len(region):
            if i + 1 < len(region):
                word = region[i] | (region[i + 1] << 8)
                i += 2
            else:
                word = region[i]
                i += 1
            sum1 = (sum1 + word) % 65535
            sum2 = (sum2 + sum1) % 65535
        value = (sum2 << 16) | sum1
        return ChecksumResult(ChecksumAlgorithm.FLETCHER32, value, len(data), s, e)

    # -------------------------------------------------------------------------
    # Internet Checksum (RFC 1071)
    # -------------------------------------------------------------------------

    def internet_checksum(
        self, data: bytes, start: int = 0, end: Optional[int] = None
    ) -> ChecksumResult:
        """
        Compute Internet Checksum (RFC 1071).
        Used in IP, TCP, UDP headers.
        """
        region, s, e = self._get_data(data, start, end)
        total = 0

        # Pad to even length
        if len(region) % 2 == 1:
            region = region + b"\x00"

        for i in range(0, len(region), 2):
            word = (region[i] << 8) + region[i + 1]
            total += word

        # Fold 32-bit sum into 16 bits
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)

        value = (~total) & 0xFFFF
        return ChecksumResult(ChecksumAlgorithm.INTERNET, value, len(data), s, e)

    # -------------------------------------------------------------------------
    # Cryptographic Hash Functions
    # -------------------------------------------------------------------------

    def _hash(
        self,
        algo:       ChecksumAlgorithm,
        hash_name:  str,
        data:       bytes,
        start:      int = 0,
        end:        Optional[int] = None
    ) -> ChecksumResult:
        """Generic hashlib-based hash computation."""
        region, s, e = self._get_data(data, start, end)
        h = hashlib.new(hash_name)
        h.update(region)
        digest = h.digest()
        return ChecksumResult(algo, digest, len(data), s, e)

    def md5(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute MD5 hash."""
        return self._hash(ChecksumAlgorithm.MD5, "md5", data, start, end)

    def sha1(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute SHA-1 hash."""
        return self._hash(ChecksumAlgorithm.SHA1, "sha1", data, start, end)

    def sha224(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute SHA-224 hash."""
        return self._hash(ChecksumAlgorithm.SHA224, "sha224", data, start, end)

    def sha256(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute SHA-256 hash."""
        return self._hash(ChecksumAlgorithm.SHA256, "sha256", data, start, end)

    def sha384(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute SHA-384 hash."""
        return self._hash(ChecksumAlgorithm.SHA384, "sha384", data, start, end)

    def sha512(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute SHA-512 hash."""
        return self._hash(ChecksumAlgorithm.SHA512, "sha512", data, start, end)

    def sha3_256(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute SHA3-256 hash."""
        return self._hash(ChecksumAlgorithm.SHA3_256, "sha3_256", data, start, end)

    def sha3_512(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute SHA3-512 hash."""
        return self._hash(ChecksumAlgorithm.SHA3_512, "sha3_512", data, start, end)

    def blake2b(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute BLAKE2b hash."""
        return self._hash(ChecksumAlgorithm.BLAKE2B, "blake2b", data, start, end)

    def blake2s(self, data: bytes, start: int = 0, end: Optional[int] = None) -> ChecksumResult:
        """Compute BLAKE2s hash."""
        return self._hash(ChecksumAlgorithm.BLAKE2S, "blake2s", data, start, end)

    # -------------------------------------------------------------------------
    # Compute by Algorithm Enum
    # -------------------------------------------------------------------------

    def compute(
        self,
        algorithm:  ChecksumAlgorithm,
        data:       bytes,
        start:      int = 0,
        end:        Optional[int] = None
    ) -> ChecksumResult:
        """
        Compute a checksum using the specified algorithm.

        Args:
            algorithm: Algorithm to use
            data:      Data to checksum
            start:     Start offset within data
            end:       End offset within data

        Returns:
            ChecksumResult with the computed value
        """
        algo_map = {
            ChecksumAlgorithm.CRC8:         self.crc8,
            ChecksumAlgorithm.CRC8_MAXIM:   self.crc8_maxim,
            ChecksumAlgorithm.CRC8_ROHC:    self.crc8_rohc,
            ChecksumAlgorithm.CRC16:        self.crc16,
            ChecksumAlgorithm.CRC16_CCITT:  self.crc16_ccitt,
            ChecksumAlgorithm.CRC16_XMODEM: self.crc16_xmodem,
            ChecksumAlgorithm.CRC16_MODBUS: self.crc16_modbus,
            ChecksumAlgorithm.CRC32:        self.crc32,
            ChecksumAlgorithm.CRC32_BZIP2:  self.crc32_bzip2,
            ChecksumAlgorithm.CRC32_POSIX:  self.crc32_posix,
            ChecksumAlgorithm.CRC64_ECMA:   self.crc64,
            ChecksumAlgorithm.SUM8:         self.sum8,
            ChecksumAlgorithm.SUM16:        self.sum16,
            ChecksumAlgorithm.SUM32:        self.sum32,
            ChecksumAlgorithm.XSUM:         self.xsum,
            ChecksumAlgorithm.NEGSUM:       self.negsum8,
            ChecksumAlgorithm.LRC:          self.lrc,
            ChecksumAlgorithm.ADLER32:      self.adler32,
            ChecksumAlgorithm.FLETCHER8:    self.fletcher8,
            ChecksumAlgorithm.FLETCHER16:   self.fletcher16,
            ChecksumAlgorithm.FLETCHER32:   self.fletcher32,
            ChecksumAlgorithm.MD5:          self.md5,
            ChecksumAlgorithm.SHA1:         self.sha1,
            ChecksumAlgorithm.SHA224:       self.sha224,
            ChecksumAlgorithm.SHA256:       self.sha256,
            ChecksumAlgorithm.SHA384:       self.sha384,
            ChecksumAlgorithm.SHA512:       self.sha512,
            ChecksumAlgorithm.SHA3_256:     self.sha3_256,
            ChecksumAlgorithm.SHA3_512:     self.sha3_512,
            ChecksumAlgorithm.BLAKE2B:      self.blake2b,
            ChecksumAlgorithm.BLAKE2S:      self.blake2s,
            ChecksumAlgorithm.INTERNET:     self.internet_checksum,
        }
        func = algo_map.get(algorithm)
        if func is None:
            raise ValueError(f"Unknown algorithm: {algorithm}")
        return func(data, start, end)

    def compute_all(
        self,
        data:  bytes,
        start: int = 0,
        end:   Optional[int] = None
    ) -> List[ChecksumResult]:
        """
        Compute all available checksums for the given data.

        Returns:
            List of ChecksumResult objects for all algorithms
        """
        results = []
        for algorithm in ChecksumAlgorithm:
            try:
                result = self.compute(algorithm, data, start, end)
                results.append(result)
            except Exception:
                pass
        return results

    def compute_multiple(
        self,
        algorithms: List[ChecksumAlgorithm],
        data:       bytes,
        start:      int = 0,
        end:        Optional[int] = None
    ) -> Dict[ChecksumAlgorithm, ChecksumResult]:
        """Compute multiple specific checksums."""
        return {
            algo: self.compute(algo, data, start, end)
            for algo in algorithms
        }

    # -------------------------------------------------------------------------
    # File-Based Operations
    # -------------------------------------------------------------------------

    def compute_file(
        self,
        path:      Union[str, Path],
        algorithm: ChecksumAlgorithm,
        start:     int = 0,
        end:       Optional[int] = None
    ) -> ChecksumResult:
        """Compute checksum of a file."""
        path = Path(path)
        with open(path, "rb") as f:
            data = f.read()
        return self.compute(algorithm, data, start, end)

    def compute_file_all(
        self,
        path:  Union[str, Path],
        start: int = 0,
        end:   Optional[int] = None
    ) -> List[ChecksumResult]:
        """Compute all checksums of a file."""
        path = Path(path)
        with open(path, "rb") as f:
            data = f.read()
        return self.compute_all(data, start, end)

    def verify_file(
        self,
        path:      Union[str, Path],
        algorithm: ChecksumAlgorithm,
        expected:  Union[int, bytes, str]
    ) -> bool:
        """
        Verify a file's checksum against an expected value.

        Args:
            path:      Path to file
            algorithm: Algorithm to use
            expected:  Expected checksum (int, bytes, or hex string)

        Returns:
            True if checksum matches
        """
        result = self.compute_file(path, algorithm)

        if isinstance(expected, str):
            expected_bytes = bytes.fromhex(expected.replace(" ", ""))
            return result.as_bytes == expected_bytes
        elif isinstance(expected, int):
            return result.as_int == expected
        elif isinstance(expected, bytes):
            return result.as_bytes == expected
        return False

    # -------------------------------------------------------------------------
    # Streaming Operations
    # -------------------------------------------------------------------------

    class StreamingChecksum:
        """Incrementally compute a checksum over streaming data."""

        def __init__(
            self,
            algorithm:  ChecksumAlgorithm,
            engine:     "ChecksumEngine"
        ):
            self.algorithm = algorithm
            self._engine   = engine
            self._data     = bytearray()

        def update(self, data: bytes) -> None:
            """Add more data to the checksum computation."""
            self._data.extend(data)

        def finalize(self) -> ChecksumResult:
            """Compute the final checksum."""
            return self._engine.compute(self.algorithm, bytes(self._data))

        def reset(self) -> None:
            """Reset for a new computation."""
            self._data.clear()

    def streaming(self, algorithm: ChecksumAlgorithm) -> "ChecksumEngine.StreamingChecksum":
        """Create a streaming checksum object."""
        return self.StreamingChecksum(algorithm, self)

    # -------------------------------------------------------------------------
    # Custom CRC
    # -------------------------------------------------------------------------

    def custom_crc(
        self,
        data:    bytes,
        width:   int,
        poly:    int,
        init:    int,
        ref_in:  bool = False,
        ref_out: bool = False,
        xor_out: int  = 0,
        start:   int  = 0,
        end:     Optional[int] = None
    ) -> int:
        """
        Compute a custom CRC with user-specified parameters.

        Args:
            data:    Input data
            width:   CRC width in bits
            poly:    Generator polynomial
            init:    Initial CRC value
            ref_in:  Reflect input bytes
            ref_out: Reflect output
            xor_out: XOR output with this value
            start:   Start offset in data
            end:     End offset in data

        Returns:
            Integer CRC value
        """
        config = CRCConfig(
            width=width, poly=poly, init=init,
            ref_in=ref_in, ref_out=ref_out, xor_out=xor_out,
            name="custom"
        )
        engine = CRCEngine(config)
        if end is not None:
            data = data[start:end]
        elif start > 0:
            data = data[start:]
        return engine.compute(data)

    # -------------------------------------------------------------------------
    # ECU / Automotive Specific
    # -------------------------------------------------------------------------

    def ecu_checksum_simple(
        self, data: bytes, start: int = 0, end: Optional[int] = None
    ) -> int:
        """
        Simple ECU checksum: sum of all bytes, two's complement.
        Used by many automotive ECUs.
        """
        region, _, _ = self._get_data(data, start, end)
        total        = sum(region) & 0xFF
        return ((~total) + 1) & 0xFF

    def ecu_checksum_bosch(
        self, data: bytes, start: int = 0, end: Optional[int] = None
    ) -> int:
        """
        Bosch ECU checksum: XOR fold of words.
        """
        region, _, _ = self._get_data(data, start, end)
        # Pad to 2-byte alignment
        if len(region) % 2 != 0:
            region = region + b"\x00"

        checksum = 0
        for i in range(0, len(region), 2):
            word = struct.unpack("<H", region[i:i + 2])[0]
            checksum ^= word
        return checksum & 0xFFFF

    def ecu_checksum_motorola(
        self, data: bytes, start: int = 0, end: Optional[int] = None
    ) -> int:
        """Motorola ECU simple checksum (8-bit XOR fold)."""
        region, _, _ = self._get_data(data, start, end)
        result       = 0
        for b in region:
            result ^= b
        return result & 0xFF

    def ecu_checksum_siemens(
        self, data: bytes, start: int = 0, end: Optional[int] = None
    ) -> int:
        """
        Siemens/VDO ECU checksum.
        CRC16 with specific init and poly.
        """
        region, _, _ = self._get_data(data, start, end)
        config = CRCConfig(
            width=16, poly=0x1021, init=0xFFFF,
            ref_in=False, ref_out=False, xor_out=0x0000,
            name="CRC-16/SIEMENS"
        )
        engine = CRCEngine(config)
        return engine.compute(region)

    def ecu_checksum_delphi(
        self, data: bytes, start: int = 0, end: Optional[int] = None
    ) -> int:
        """Delphi ECU checksum (sum32 complement)."""
        region, _, _ = self._get_data(data, start, end)
        total        = sum(region) & 0xFFFFFFFF
        return ((~total) + 1) & 0xFFFFFFFF

    def ecu_checksum_marelli(
        self, data: bytes, start: int = 0, end: Optional[int] = None
    ) -> int:
        """Magneti Marelli ECU checksum."""
        region, _, _ = self._get_data(data, start, end)
        result = 0x00
        for b in region:
            result = (result + b) & 0xFF
        return result

    # -------------------------------------------------------------------------
    # Checksum Repair
    # -------------------------------------------------------------------------

    def find_checksum_byte_position(
        self,
        data:          bytes,
        algorithm:     ChecksumAlgorithm,
        checksum_size: int = 1
    ) -> Optional[int]:
        """
        Find the position of a checksum byte in data by trying each position.
        Useful when the checksum location is unknown.

        Returns:
            Offset of checksum, or None if not found
        """
        for i in range(len(data) - checksum_size + 1):
            # Remove checksum bytes from data
            test_data = data[:i] + data[i + checksum_size:]
            try:
                result = self.compute(algorithm, test_data)
                computed = result.as_bytes[:checksum_size]
                stored   = data[i:i + checksum_size]
                if computed == stored:
                    return i
            except Exception:
                continue
        return None

    def repair_crc32(
        self,
        data:          bytearray,
        checksum_offset: int,
        data_start:    int = 0,
        data_end:      Optional[int] = None
    ) -> bytearray:
        """
        Update CRC32 checksum at checksum_offset based on data region.

        Args:
            data:             Mutable bytearray
            checksum_offset:  Offset where 4-byte CRC32 is stored
            data_start:       Start of data region
            data_end:         End of data region

        Returns:
            Modified bytearray with updated CRC32
        """
        if data_end is None:
            data_end = len(data)

        region = data[data_start:data_end]
        crc    = zlib.crc32(bytes(region)) & 0xFFFFFFFF
        struct.pack_into("<I", data, checksum_offset, crc)
        return data

    # -------------------------------------------------------------------------
    # Representation
    # -------------------------------------------------------------------------

    def list_algorithms(self) -> List[str]:
        """Return list of all supported algorithm names."""
        return [a.name for a in ChecksumAlgorithm]

    def __repr__(self) -> str:
        return f"ChecksumEngine(algorithms={len(ChecksumAlgorithm)})"


# =============================================================================
# Module-level convenience functions
# =============================================================================

_engine = ChecksumEngine()


def crc32(data: bytes, start: int = 0, end: Optional[int] = None) -> int:
    """Quick CRC-32 computation."""
    return _engine.crc32(data, start, end).as_int


def crc16(data: bytes, start: int = 0, end: Optional[int] = None) -> int:
    """Quick CRC-16 computation."""
    return _engine.crc16(data, start, end).as_int


def crc8(data: bytes, start: int = 0, end: Optional[int] = None) -> int:
    """Quick CRC-8 computation."""
    return _engine.crc8(data, start, end).as_int


def md5_hex(data: bytes) -> str:
    """Quick MD5 hex digest."""
    return _engine.md5(data).as_hex


def sha256_hex(data: bytes) -> str:
    """Quick SHA-256 hex digest."""
    return _engine.sha256(data).as_hex


def sha512_hex(data: bytes) -> str:
    """Quick SHA-512 hex digest."""
    return _engine.sha512(data).as_hex


def xor_checksum(data: bytes) -> int:
    """Quick XOR checksum."""
    return _engine.xsum(data).as_int


def sum_checksum(data: bytes) -> int:
    """Quick 8-bit sum checksum."""
    return _engine.sum8(data).as_int
