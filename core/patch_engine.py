# =============================================================================
# BinModder - Patch Engine Module
# =============================================================================
# Implements patch creation and application for multiple formats:
# IPS (International Patching Standard), UPS, BPS, and custom BinModder
# patch format (.bmp). Supports reverse patches and patch verification.
#
# Author: MSR Electronics
# Version: 1.0.0
# =============================================================================

import os
import struct
import zlib
from enum import Enum
from typing import Optional, Union, List, Tuple, Dict, Any, BinaryIO
from pathlib import Path
from dataclasses import dataclass


# =============================================================================
# Patch Format Enumerations
# =============================================================================

class PatchFormat(Enum):
    """Supported patch file formats."""
    IPS    = "ips"     # International Patching Standard
    UPS    = "ups"     # Universal Patching Standard
    BPS    = "bps"     # Binary Patching Standard
    XDELTA = "xdelta"  # xdelta3 delta patches
    CUSTOM = "bmp"     # BinModder Patch format


class PatchError(Exception):
    """Base exception for patch errors."""
    pass


class PatchVerificationError(PatchError):
    """Raised when patch verification fails."""
    pass


class PatchApplicationError(PatchError):
    """Raised when patch application fails."""
    pass


class InvalidPatchError(PatchError):
    """Raised when a patch file is invalid or corrupted."""
    pass


# =============================================================================
# IPS Patch
# =============================================================================

@dataclass
class IPSRecord:
    """A single IPS patch record."""
    offset:  int
    data:    bytes
    rle_val: Optional[int]   = None  # If not None, use RLE fill
    rle_len: Optional[int]   = None  # Length for RLE


class IPSPatch:
    """
    IPS (International Patching Standard) patch handler.

    IPS Format:
    - Header: "PATCH" (5 bytes)
    - Records: [3-byte offset][2-byte size][N bytes data]
               or RLE: [3-byte offset][0x0000][2-byte count][1-byte value]
    - EOF marker: "EOF" (3 bytes)
    - Optional truncate: 3 bytes after EOF
    """

    HEADER    = b"PATCH"
    EOF_MARK  = b"EOF"
    MAX_SIZE  = 0x1000000  # 16MB max

    def __init__(self):
        self.records: List[IPSRecord] = []
        self.truncate_size: Optional[int] = None

    @classmethod
    def load(cls, path: Union[str, Path]) -> "IPSPatch":
        """Load an IPS patch from file."""
        path = Path(path)
        with open(path, "rb") as f:
            data = f.read()
        return cls.parse(data)

    @classmethod
    def parse(cls, data: bytes) -> "IPSPatch":
        """Parse IPS patch from bytes."""
        patch = cls()

        if not data.startswith(cls.HEADER):
            raise InvalidPatchError("Not a valid IPS patch: missing PATCH header")

        pos = len(cls.HEADER)

        while pos < len(data) - 2:
            # Read 3-byte offset
            if data[pos:pos + 3] == cls.EOF_MARK:
                pos += 3
                # Check for truncate extension
                if pos + 3 <= len(data):
                    patch.truncate_size = int.from_bytes(data[pos:pos + 3], "big")
                break

            if pos + 3 > len(data):
                break

            offset = int.from_bytes(data[pos:pos + 3], "big")
            pos += 3

            # Read 2-byte size
            if pos + 2 > len(data):
                raise InvalidPatchError(f"Truncated IPS record at offset {pos}")
            size = int.from_bytes(data[pos:pos + 2], "big")
            pos += 2

            if size == 0:
                # RLE record
                if pos + 3 > len(data):
                    raise InvalidPatchError("Truncated IPS RLE record")
                rle_count = int.from_bytes(data[pos:pos + 2], "big")
                rle_val   = data[pos + 2]
                pos += 3
                record = IPSRecord(
                    offset=offset,
                    data=bytes([rle_val]) * rle_count,
                    rle_val=rle_val,
                    rle_len=rle_count
                )
            else:
                # Normal record
                if pos + size > len(data):
                    raise InvalidPatchError(f"Truncated IPS data at offset {pos}")
                record_data = data[pos:pos + size]
                pos += size
                record = IPSRecord(offset=offset, data=record_data)

            patch.records.append(record)

        return patch

    def apply(self, original: bytearray) -> bytearray:
        """
        Apply this IPS patch to binary data.

        Args:
            original: Original binary data as bytearray

        Returns:
            Patched binary data
        """
        result = bytearray(original)

        for record in self.records:
            offset  = record.offset
            data    = record.data
            end_off = offset + len(data)

            # Extend if needed
            if end_off > len(result):
                result.extend(b"\x00" * (end_off - len(result)))

            result[offset:end_off] = data

        # Apply truncation if present
        if self.truncate_size is not None:
            result = result[:self.truncate_size]

        return result

    def save(self, path: Union[str, Path]) -> None:
        """Save this IPS patch to a file."""
        path = Path(path)
        data = self.build()
        with open(path, "wb") as f:
            f.write(data)

    def build(self) -> bytes:
        """Build IPS patch bytes."""
        out = bytearray(self.HEADER)

        for record in self.records:
            # 3-byte offset (big endian)
            out.extend(record.offset.to_bytes(3, "big"))

            if record.rle_val is not None and record.rle_len is not None:
                # RLE record
                out.extend((0).to_bytes(2, "big"))             # size = 0
                out.extend(record.rle_len.to_bytes(2, "big"))  # count
                out.append(record.rle_val)                       # value
            else:
                # Normal record
                out.extend(len(record.data).to_bytes(2, "big"))
                out.extend(record.data)

        out.extend(self.EOF_MARK)

        if self.truncate_size is not None:
            out.extend(self.truncate_size.to_bytes(3, "big"))

        return bytes(out)

    @classmethod
    def create_from_diff(
        cls,
        original: bytes,
        modified: bytes,
        truncate_if_smaller: bool = True,
    ) -> "IPSPatch":
        """
        Create an IPS patch from the difference between original and modified data.

        Args:
            original: Original binary data
            modified: Modified binary data
            truncate_if_smaller: If modified is smaller, add truncate record

        Returns:
            IPSPatch representing the differences
        """
        patch   = cls()
        max_len = max(len(original), len(modified))
        orig_ex = original + b"\x00" * (max_len - len(original))
        mod_ex  = modified + b"\x00" * (max_len - len(modified))

        i = 0
        while i < max_len:
            if orig_ex[i] != mod_ex[i]:
                # Start of a changed region
                start   = i
                changed = bytearray()

                while i < max_len and orig_ex[i] != mod_ex[i]:
                    changed.append(mod_ex[i])
                    i += 1

                # Check if this can be RLE encoded
                if len(set(changed)) == 1 and len(changed) > 3:
                    record = IPSRecord(
                        offset=start,
                        data=bytes(changed),
                        rle_val=changed[0],
                        rle_len=len(changed)
                    )
                else:
                    record = IPSRecord(offset=start, data=bytes(changed))

                patch.records.append(record)
            else:
                i += 1

        if truncate_if_smaller and len(modified) < len(original):
            patch.truncate_size = len(modified)

        return patch

    @property
    def total_changes(self) -> int:
        """Total bytes changed by this patch."""
        return sum(len(r.data) for r in self.records)

    @property
    def record_count(self) -> int:
        return len(self.records)

    def __repr__(self) -> str:
        return (
            f"IPSPatch(records={self.record_count}, "
            f"changes={self.total_changes} bytes)"
        )


# =============================================================================
# UPS Patch
# =============================================================================

class UPSPatch:
    """
    UPS (Universal Patching Standard) patch handler.

    UPS Format:
    - Header: "UPS1"
    - Input file size: variable length integer
    - Output file size: variable length integer
    - Diff data: encoded diffs with XOR values
    - Input CRC32 (4 bytes)
    - Output CRC32 (4 bytes)
    - Patch CRC32 (4 bytes, covers everything except last 4)
    """

    HEADER = b"UPS1"

    def __init__(
        self,
        input_size:  int,
        output_size: int,
        diffs:       List[Tuple[int, bytes]],
        input_crc:   int = 0,
        output_crc:  int = 0,
    ):
        self.input_size  = input_size
        self.output_size = output_size
        self.diffs       = diffs  # List of (relative_offset, xor_data)
        self.input_crc   = input_crc
        self.output_crc  = output_crc

    @staticmethod
    def _read_varint(data: bytes, pos: int) -> Tuple[int, int]:
        """Read variable-length integer from UPS format."""
        value  = 0
        shift  = 1
        while True:
            b = data[pos]
            pos += 1
            value += (b & 0x7F) * shift
            if b & 0x80:
                break
            shift <<= 7
            value += shift
        return value, pos

    @staticmethod
    def _write_varint(value: int) -> bytes:
        """Write variable-length integer in UPS format."""
        result = bytearray()
        while True:
            x = value & 0x7F
            value >>= 7
            if value == 0:
                result.append(x | 0x80)
                break
            else:
                result.append(x)
        return bytes(result)

    @classmethod
    def parse(cls, data: bytes) -> "UPSPatch":
        """Parse UPS patch from bytes."""
        if not data.startswith(cls.HEADER):
            raise InvalidPatchError("Not a valid UPS patch: missing UPS1 header")

        pos = len(cls.HEADER)

        # Read input/output sizes
        input_size,  pos = cls._read_varint(data, pos)
        output_size, pos = cls._read_varint(data, pos)

        # Read diff data (everything except last 12 bytes = 3 CRC32s)
        diffs   = []
        cur_pos = 0

        while pos < len(data) - 12:
            # Read relative offset
            rel_offset, pos = cls._read_varint(data, pos)
            cur_pos += rel_offset

            # Read XOR bytes until null
            xor_data = bytearray()
            while pos < len(data) - 12:
                b = data[pos]
                pos += 1
                if b == 0:
                    break
                xor_data.append(b)

            diffs.append((cur_pos, bytes(xor_data)))
            cur_pos += len(xor_data) + 1

        # Read CRC32s
        if pos + 12 <= len(data):
            input_crc  = struct.unpack_from("<I", data, len(data) - 12)[0]
            output_crc = struct.unpack_from("<I", data, len(data) - 8)[0]

        return cls(input_size, output_size, diffs, input_crc, output_crc)

    @classmethod
    def load(cls, path: Union[str, Path]) -> "UPSPatch":
        """Load UPS patch from file."""
        with open(path, "rb") as f:
            data = f.read()
        return cls.parse(data)

    def apply(self, original: bytes) -> bytearray:
        """Apply UPS patch to original data."""
        # Verify input size
        if len(original) != self.input_size:
            raise PatchApplicationError(
                f"Input size mismatch: expected {self.input_size}, got {len(original)}"
            )

        # Verify input CRC
        actual_crc = zlib.crc32(original) & 0xFFFFFFFF
        if self.input_crc and actual_crc != self.input_crc:
            raise PatchVerificationError(
                f"Input CRC mismatch: expected 0x{self.input_crc:08X}, got 0x{actual_crc:08X}"
            )

        # Create output buffer
        result = bytearray(original)
        if self.output_size > len(result):
            result.extend(b"\x00" * (self.output_size - len(result)))
        elif self.output_size < len(result):
            result = result[:self.output_size]

        # Apply diffs
        for offset, xor_data in self.diffs:
            for i, xor_byte in enumerate(xor_data):
                if offset + i < len(result):
                    result[offset + i] ^= xor_byte

        return result

    def build(self) -> bytes:
        """Build UPS patch bytes."""
        out = bytearray(self.HEADER)
        out.extend(self._write_varint(self.input_size))
        out.extend(self._write_varint(self.output_size))

        prev_pos = 0
        for offset, xor_data in self.diffs:
            rel_offset = offset - prev_pos
            out.extend(self._write_varint(rel_offset))
            out.extend(xor_data)
            out.append(0)  # Null terminator
            prev_pos = offset + len(xor_data) + 1

        # CRC32s
        out.extend(struct.pack("<I", self.input_crc))
        out.extend(struct.pack("<I", self.output_crc))
        patch_crc = zlib.crc32(bytes(out)) & 0xFFFFFFFF
        out.extend(struct.pack("<I", patch_crc))

        return bytes(out)

    @classmethod
    def create_from_diff(cls, original: bytes, modified: bytes) -> "UPSPatch":
        """Create UPS patch from original and modified data."""
        min_len = min(len(original), len(modified))
        max_len = max(len(original), len(modified))

        orig_ex = original + b"\x00" * (max_len - len(original))
        mod_ex  = modified + b"\x00" * (max_len - len(modified))

        diffs   = []
        i       = 0

        while i < max_len:
            if orig_ex[i] != mod_ex[i]:
                offset   = i
                xor_data = bytearray()
                while i < max_len and orig_ex[i] != mod_ex[i]:
                    xor_data.append(orig_ex[i] ^ mod_ex[i])
                    i += 1
                diffs.append((offset, bytes(xor_data)))
            else:
                i += 1

        input_crc  = zlib.crc32(original) & 0xFFFFFFFF
        output_crc = zlib.crc32(modified) & 0xFFFFFFFF

        return cls(
            input_size=len(original),
            output_size=len(modified),
            diffs=diffs,
            input_crc=input_crc,
            output_crc=output_crc,
        )

    def __repr__(self) -> str:
        return (
            f"UPSPatch("
            f"input_size={self.input_size}, "
            f"output_size={self.output_size}, "
            f"diffs={len(self.diffs)})"
        )


# =============================================================================
# BPS Patch (Binary Patching Standard)
# =============================================================================

class BPSPatch:
    """
    BPS (Binary Patching Standard) patch handler.

    More efficient than IPS/UPS, supports source/target read/write/copy operations.
    Used by modern ROM hacking tools.
    """

    HEADER   = b"BPS1"
    OP_WRITE = 0  # Write raw data
    OP_SRC   = 1  # Copy from source
    OP_DST   = 2  # Copy from destination (already written)
    OP_END   = 3  # End of patch

    def __init__(
        self,
        source_size:     int,
        target_size:     int,
        metadata:        bytes,
        actions:         List[Tuple[int, int, bytes]],
        source_checksum: int = 0,
        target_checksum: int = 0,
    ):
        self.source_size     = source_size
        self.target_size     = target_size
        self.metadata        = metadata
        self.actions         = actions
        self.source_checksum = source_checksum
        self.target_checksum = target_checksum

    @staticmethod
    def _read_varint(data: bytes, pos: int) -> Tuple[int, int]:
        """Read BPS variable-length integer."""
        value = 0
        shift = 1
        while True:
            b = data[pos]
            pos += 1
            value += (b & 0x7F) * shift
            if b & 0x80:
                break
            shift <<= 7
            value += shift
        return value, pos

    @staticmethod
    def _write_varint(value: int) -> bytes:
        """Write BPS variable-length integer."""
        result = bytearray()
        while True:
            x = value & 0x7F
            value >>= 7
            if value == 0:
                result.append(x | 0x80)
                break
            else:
                result.append(x)
        return bytes(result)

    @classmethod
    def parse(cls, data: bytes) -> "BPSPatch":
        """Parse BPS patch."""
        if not data.startswith(cls.HEADER):
            raise InvalidPatchError("Not a valid BPS patch")

        pos = len(cls.HEADER)

        source_size,   pos = cls._read_varint(data, pos)
        target_size,   pos = cls._read_varint(data, pos)
        meta_size,     pos = cls._read_varint(data, pos)
        metadata           = data[pos:pos + meta_size]
        pos               += meta_size

        actions       = []
        patch_end     = len(data) - 12  # 3 x CRC32

        while pos < patch_end:
            op_data, pos = cls._read_varint(data, pos)
            op_type      = op_data & 3
            op_len       = (op_data >> 2) + 1

            if op_type == cls.OP_WRITE:
                payload = data[pos:pos + op_len]
                pos    += op_len
                actions.append((op_type, op_len, payload))
            elif op_type in (cls.OP_SRC, cls.OP_DST):
                src_off, pos = cls._read_varint(data, pos)
                actions.append((op_type, op_len, src_off.to_bytes(4, "little")))
            else:
                break

        checksums = struct.unpack_from("<III", data, len(data) - 12)
        return cls(
            source_size=source_size,
            target_size=target_size,
            metadata=metadata,
            actions=actions,
            source_checksum=checksums[0],
            target_checksum=checksums[1],
        )

    @classmethod
    def load(cls, path: Union[str, Path]) -> "BPSPatch":
        """Load BPS patch from file."""
        with open(path, "rb") as f:
            data = f.read()
        return cls.parse(data)

    def apply(self, source: bytes) -> bytearray:
        """Apply BPS patch to source data."""
        target     = bytearray(self.target_size)
        src_offset = 0
        tgt_offset = 0

        for op_type, op_len, payload in self.actions:
            if op_type == self.OP_WRITE:
                target[tgt_offset:tgt_offset + op_len] = payload
                tgt_offset += op_len

            elif op_type == self.OP_SRC:
                rel = int.from_bytes(payload, "little")
                signed_rel = rel - (rel & 1) * (rel >> 1) * 2
                src_offset += signed_rel
                for i in range(op_len):
                    if src_offset + i < len(source):
                        target[tgt_offset + i] = source[src_offset + i]
                src_offset += op_len
                tgt_offset += op_len

            elif op_type == self.OP_DST:
                rel = int.from_bytes(payload, "little")
                signed_rel = rel - (rel & 1) * (rel >> 1) * 2
                prev_offset = tgt_offset + signed_rel
                for i in range(op_len):
                    if prev_offset + i < tgt_offset:
                        target[tgt_offset + i] = target[prev_offset + i]
                tgt_offset += op_len

        return target

    def build(self) -> bytes:
        """Build BPS patch bytes."""
        out = bytearray(self.HEADER)
        out.extend(self._write_varint(self.source_size))
        out.extend(self._write_varint(self.target_size))
        out.extend(self._write_varint(len(self.metadata)))
        out.extend(self.metadata)

        for op_type, op_len, payload in self.actions:
            op_data = ((op_len - 1) << 2) | op_type
            out.extend(self._write_varint(op_data))
            out.extend(payload)

        out.extend(struct.pack("<I", self.source_checksum))
        out.extend(struct.pack("<I", self.target_checksum))
        patch_crc = zlib.crc32(bytes(out)) & 0xFFFFFFFF
        out.extend(struct.pack("<I", patch_crc))

        return bytes(out)

    def __repr__(self) -> str:
        return (
            f"BPSPatch("
            f"source_size={self.source_size}, "
            f"target_size={self.target_size}, "
            f"actions={len(self.actions)})"
        )


# =============================================================================
# Custom BinModder Patch Format
# =============================================================================

@dataclass
class CustomPatchRecord:
    """A record in the custom BinModder patch format."""
    offset:      int
    original:    bytes   # Original bytes (for verification and reversal)
    replacement: bytes   # New bytes
    description: str = ""
    enabled:     bool = True


class CustomPatch:
    """
    Custom BinModder patch format (.bmp) with:
    - Named records with descriptions
    - Original bytes stored (allows reversal)
    - Record enable/disable support
    - Verification of original content before applying
    - JSON-based serialization
    """

    MAGIC   = b"BMPATCH\x00"
    VERSION = 1

    def __init__(
        self,
        name:        str = "",
        description: str = "",
        author:      str = "",
        version:     str = "1.0.0",
    ):
        self.name        = name
        self.description = description
        self.author      = author
        self.version     = version
        self.records:    List[CustomPatchRecord] = []

    def add_record(
        self,
        offset:      int,
        original:    bytes,
        replacement: bytes,
        description: str = "",
        enabled:     bool = True,
    ) -> None:
        """Add a patch record."""
        if len(original) != len(replacement):
            raise PatchError(
                f"Original ({len(original)}) and replacement ({len(replacement)}) "
                "must be the same length"
            )
        self.records.append(CustomPatchRecord(
            offset=offset,
            original=original,
            replacement=replacement,
            description=description,
            enabled=enabled,
        ))

    def add_record_from_hex(
        self,
        offset:      int,
        original_hex: str,
        replacement_hex: str,
        description: str = "",
    ) -> None:
        """Add a record from hex strings."""
        original    = bytes.fromhex(original_hex.replace(" ", ""))
        replacement = bytes.fromhex(replacement_hex.replace(" ", ""))
        self.add_record(offset, original, replacement, description)

    def verify(self, data: bytes) -> Tuple[bool, List[str]]:
        """
        Verify that original bytes match for all enabled records.

        Returns:
            (all_ok, error_list)
        """
        errors = []
        for rec in self.records:
            if not rec.enabled:
                continue
            end = rec.offset + len(rec.original)
            if end > len(data):
                errors.append(
                    f"Record at 0x{rec.offset:08X}: offset out of bounds"
                )
                continue
            actual = data[rec.offset:end]
            if actual != rec.original:
                errors.append(
                    f"Record at 0x{rec.offset:08X}: "
                    f"expected {rec.original.hex().upper()}, "
                    f"got {actual.hex().upper()}"
                )
        return len(errors) == 0, errors

    def apply(
        self,
        data: bytearray,
        verify: bool = True,
        skip_disabled: bool = True,
    ) -> Tuple[bytearray, int]:
        """
        Apply patch to binary data.

        Args:
            data:          Mutable binary data
            verify:        Verify original bytes before applying
            skip_disabled: Skip disabled records

        Returns:
            (modified_data, applied_count)
        """
        if verify:
            ok, errors = self.verify(bytes(data))
            if not ok:
                raise PatchVerificationError(
                    "Patch verification failed:\n" + "\n".join(errors)
                )

        applied = 0
        for rec in self.records:
            if skip_disabled and not rec.enabled:
                continue
            end = rec.offset + len(rec.replacement)
            data[rec.offset:end] = rec.replacement
            applied += 1

        return data, applied

    def reverse(
        self,
        data: bytearray,
        skip_disabled: bool = True,
    ) -> Tuple[bytearray, int]:
        """Reverse the patch (restore original bytes)."""
        reversed_count = 0
        for rec in self.records:
            if skip_disabled and not rec.enabled:
                continue
            end = rec.offset + len(rec.original)
            if end <= len(data):
                data[rec.offset:end] = rec.original
                reversed_count += 1
        return data, reversed_count

    def save(self, path: Union[str, Path]) -> None:
        """Save patch to JSON file."""
        import json
        data = {
            "format":      "BinModder Patch",
            "version":     self.version,
            "name":        self.name,
            "description": self.description,
            "author":      self.author,
            "records": [
                {
                    "offset":      rec.offset,
                    "offset_hex":  f"0x{rec.offset:08X}",
                    "original":    rec.original.hex().upper(),
                    "replacement": rec.replacement.hex().upper(),
                    "description": rec.description,
                    "enabled":     rec.enabled,
                }
                for rec in self.records
            ],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, path: Union[str, Path]) -> "CustomPatch":
        """Load patch from JSON file."""
        import json
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        patch = cls(
            name=data.get("name", ""),
            description=data.get("description", ""),
            author=data.get("author", ""),
            version=data.get("version", "1.0.0"),
        )

        for rec in data.get("records", []):
            patch.add_record(
                offset=int(rec["offset_hex"], 16) if "offset_hex" in rec else rec["offset"],
                original=bytes.fromhex(rec["original"]),
                replacement=bytes.fromhex(rec["replacement"]),
                description=rec.get("description", ""),
                enabled=rec.get("enabled", True),
            )

        return patch

    @property
    def total_bytes_changed(self) -> int:
        return sum(len(r.replacement) for r in self.records if r.enabled)

    @property
    def enabled_count(self) -> int:
        return sum(1 for r in self.records if r.enabled)

    def __repr__(self) -> str:
        return (
            f"CustomPatch("
            f"name={self.name!r}, "
            f"records={len(self.records)}, "
            f"enabled={self.enabled_count})"
        )


# =============================================================================
# Patch Engine - Main Class
# =============================================================================

class PatchEngine:
    """
    Unified patch engine supporting multiple patch formats.

    Features:
    - Apply IPS, UPS, BPS, and custom patches
    - Create patches from file differences
    - Verify patch compatibility
    - Batch patch application
    - Reverse patch support

    Usage:
        engine = PatchEngine()

        # Apply an IPS patch
        engine.apply_ips("original.bin", "patch.ips", "patched.bin")

        # Create an IPS patch from diff
        engine.create_ips("original.bin", "modified.bin", "output.ips")

        # Apply custom patch
        patch = CustomPatch.load("my_patch.json")
        engine.apply_custom("firmware.bin", patch, "firmware_patched.bin")
    """

    def __init__(self):
        pass

    # -------------------------------------------------------------------------
    # IPS Operations
    # -------------------------------------------------------------------------

    def apply_ips(
        self,
        source_path: Union[str, Path],
        patch_path:  Union[str, Path],
        output_path: Optional[Union[str, Path]] = None,
    ) -> bytes:
        """Apply an IPS patch to a file."""
        source_path = Path(source_path)
        patch_path  = Path(patch_path)

        with open(source_path, "rb") as f:
            original = f.read()

        patch  = IPSPatch.load(patch_path)
        result = patch.apply(bytearray(original))

        if output_path:
            output_path = Path(output_path)
            with open(output_path, "wb") as f:
                f.write(result)

        return bytes(result)

    def create_ips(
        self,
        original_path: Union[str, Path],
        modified_path: Union[str, Path],
        output_path:   Union[str, Path],
    ) -> IPSPatch:
        """Create an IPS patch from the difference between two files."""
        with open(original_path, "rb") as f:
            original = f.read()
        with open(modified_path, "rb") as f:
            modified = f.read()

        patch = IPSPatch.create_from_diff(original, modified)
        patch.save(output_path)
        return patch

    def apply_ips_bytes(self, original: bytes, patch: IPSPatch) -> bytes:
        """Apply IPS patch to bytes object."""
        return bytes(patch.apply(bytearray(original)))

    # -------------------------------------------------------------------------
    # UPS Operations
    # -------------------------------------------------------------------------

    def apply_ups(
        self,
        source_path: Union[str, Path],
        patch_path:  Union[str, Path],
        output_path: Optional[Union[str, Path]] = None,
    ) -> bytes:
        """Apply a UPS patch to a file."""
        with open(source_path, "rb") as f:
            original = f.read()

        patch  = UPSPatch.load(patch_path)
        result = patch.apply(original)

        if output_path:
            with open(output_path, "wb") as f:
                f.write(result)

        return bytes(result)

    def create_ups(
        self,
        original_path: Union[str, Path],
        modified_path: Union[str, Path],
        output_path:   Union[str, Path],
    ) -> UPSPatch:
        """Create a UPS patch."""
        with open(original_path, "rb") as f:
            original = f.read()
        with open(modified_path, "rb") as f:
            modified = f.read()

        patch = UPSPatch.create_from_diff(original, modified)
        with open(output_path, "wb") as f:
            f.write(patch.build())
        return patch

    # -------------------------------------------------------------------------
    # BPS Operations
    # -------------------------------------------------------------------------

    def apply_bps(
        self,
        source_path: Union[str, Path],
        patch_path:  Union[str, Path],
        output_path: Optional[Union[str, Path]] = None,
    ) -> bytes:
        """Apply a BPS patch to a file."""
        with open(source_path, "rb") as f:
            source = f.read()

        patch  = BPSPatch.load(patch_path)
        result = patch.apply(source)

        if output_path:
            with open(output_path, "wb") as f:
                f.write(result)

        return bytes(result)

    # -------------------------------------------------------------------------
    # Custom Patch Operations
    # -------------------------------------------------------------------------

    def apply_custom(
        self,
        source_path: Union[str, Path],
        patch:       CustomPatch,
        output_path: Optional[Union[str, Path]] = None,
        verify:      bool = True,
    ) -> bytes:
        """Apply a custom patch to a file."""
        with open(source_path, "rb") as f:
            data = bytearray(f.read())

        data, count = patch.apply(data, verify=verify)

        if output_path:
            with open(output_path, "wb") as f:
                f.write(data)

        return bytes(data)

    def reverse_custom(
        self,
        source_path: Union[str, Path],
        patch:       CustomPatch,
        output_path: Optional[Union[str, Path]] = None,
    ) -> bytes:
        """Reverse (undo) a custom patch."""
        with open(source_path, "rb") as f:
            data = bytearray(f.read())

        data, count = patch.reverse(data)

        if output_path:
            with open(output_path, "wb") as f:
                f.write(data)

        return bytes(data)

    # -------------------------------------------------------------------------
    # Auto-Detect and Apply
    # -------------------------------------------------------------------------

    def detect_format(self, patch_path: Union[str, Path]) -> PatchFormat:
        """Auto-detect patch file format."""
        path = Path(patch_path)
        ext  = path.suffix.lower()

        if ext == ".ips":
            return PatchFormat.IPS
        elif ext == ".ups":
            return PatchFormat.UPS
        elif ext == ".bps":
            return PatchFormat.BPS
        elif ext in (".bmp", ".json"):
            return PatchFormat.CUSTOM

        # Try to detect by magic bytes
        with open(path, "rb") as f:
            magic = f.read(8)

        if magic[:5] == IPSPatch.HEADER:
            return PatchFormat.IPS
        elif magic[:4] == UPSPatch.HEADER:
            return PatchFormat.UPS
        elif magic[:4] == BPSPatch.HEADER:
            return PatchFormat.BPS

        raise PatchError(f"Cannot detect format for: {path}")

    def apply_auto(
        self,
        source_path: Union[str, Path],
        patch_path:  Union[str, Path],
        output_path: Optional[Union[str, Path]] = None,
    ) -> bytes:
        """Apply a patch with automatic format detection."""
        fmt = self.detect_format(patch_path)

        if fmt == PatchFormat.IPS:
            return self.apply_ips(source_path, patch_path, output_path)
        elif fmt == PatchFormat.UPS:
            return self.apply_ups(source_path, patch_path, output_path)
        elif fmt == PatchFormat.BPS:
            return self.apply_bps(source_path, patch_path, output_path)
        elif fmt == PatchFormat.CUSTOM:
            patch = CustomPatch.load(patch_path)
            return self.apply_custom(source_path, patch, output_path)
        else:
            raise PatchError(f"Unsupported format: {fmt}")

    # -------------------------------------------------------------------------
    # Batch Operations
    # -------------------------------------------------------------------------

    def apply_batch(
        self,
        source_path: Union[str, Path],
        patch_paths: List[Union[str, Path]],
        output_path: Optional[Union[str, Path]] = None,
    ) -> bytes:
        """Apply multiple patches in sequence."""
        with open(source_path, "rb") as f:
            data = f.read()

        for patch_path in patch_paths:
            fmt = self.detect_format(patch_path)
            if fmt == PatchFormat.IPS:
                patch = IPSPatch.load(patch_path)
                data  = bytes(patch.apply(bytearray(data)))
            elif fmt == PatchFormat.UPS:
                patch = UPSPatch.load(patch_path)
                data  = bytes(patch.apply(data))
            elif fmt == PatchFormat.BPS:
                patch = BPSPatch.load(patch_path)
                data  = bytes(patch.apply(data))
            elif fmt == PatchFormat.CUSTOM:
                patch = CustomPatch.load(patch_path)
                data, _ = patch.apply(bytearray(data), verify=False)
                data = bytes(data)

        if output_path:
            with open(output_path, "wb") as f:
                f.write(data)

        return data

    def __repr__(self) -> str:
        return "PatchEngine(formats=[IPS, UPS, BPS, Custom])"
