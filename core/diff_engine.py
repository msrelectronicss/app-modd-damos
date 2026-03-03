"""
diff_engine.py - Byte-level diff engine using Myers algorithm.

Provides DiffBlock, DiffResult, and DiffEngine for computing, representing,
and applying binary diffs. Supports 3-way merge, similarity scoring, and
unified diff format output.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class DiffType(Enum):
    """Type of a diff block."""
    EQUAL  = auto()   # bytes are identical in both sequences
    ADD    = auto()   # bytes present only in new_data (insertion)
    REMOVE = auto()   # bytes present only in old_data (deletion)
    MODIFY = auto()   # bytes differ (conceptually REMOVE + ADD at same position)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class DiffBlock:
    """A single contiguous block produced by the diff algorithm.

    Attributes
    ----------
    diff_type : DiffType
        Classification of this block.
    offset : int
        Byte offset in the *original* (old) data where this block starts.
        For ADD blocks the offset points to the position in old_data *before*
        which the new bytes are inserted (can equal len(old_data)).
    old_data : bytes
        Bytes from the old sequence that this block covers.
        Empty for ADD blocks.
    new_data : bytes
        Bytes from the new sequence that this block covers.
        Empty for REMOVE blocks.
    new_offset : int
        Byte offset in the *new* data where this block starts.
    """
    diff_type: DiffType
    offset: int
    old_data: bytes
    new_data: bytes
    new_offset: int = 0

    # -----------------------------------------------------------------
    # Convenience helpers
    # -----------------------------------------------------------------

    @property
    def size(self) -> int:
        """Return the number of bytes changed / added / removed."""
        if self.diff_type == DiffType.EQUAL:
            return len(self.old_data)
        if self.diff_type == DiffType.ADD:
            return len(self.new_data)
        if self.diff_type == DiffType.REMOVE:
            return len(self.old_data)
        # MODIFY
        return max(len(self.old_data), len(self.new_data))

    def __repr__(self) -> str:
        return (
            f"DiffBlock({self.diff_type.name}, "
            f"off=0x{self.offset:08X}, "
            f"old={len(self.old_data)}B, "
            f"new={len(self.new_data)}B)"
        )


@dataclass
class DiffStats:
    """Statistical summary of a diff result."""
    equal_bytes:   int = 0
    changed_bytes: int = 0   # bytes that were overwritten (MODIFY)
    added_bytes:   int = 0   # bytes that were inserted (ADD)
    removed_bytes: int = 0   # bytes that were deleted (REMOVE)
    block_count:   int = 0   # total number of non-EQUAL blocks
    old_size:      int = 0
    new_size:      int = 0

    @property
    def similarity(self) -> float:
        """Return similarity ratio 0.0..1.0 between the two files."""
        total = self.old_size + self.new_size
        if total == 0:
            return 1.0
        return (2 * self.equal_bytes) / total


@dataclass
class DiffResult:
    """Complete result of a binary diff operation.

    Attributes
    ----------
    blocks : List[DiffBlock]
        Ordered list of diff blocks covering the entire diff.
    stats : DiffStats
        Aggregate statistics.
    old_hash : str
        SHA-256 hex digest of old data.
    new_hash : str
        SHA-256 hex digest of new data.
    """
    blocks:   List[DiffBlock] = field(default_factory=list)
    stats:    DiffStats       = field(default_factory=DiffStats)
    old_hash: str = ""
    new_hash: str = ""

    # -----------------------------------------------------------------

    def changed_blocks(self) -> List[DiffBlock]:
        """Return only blocks that represent a change."""
        return [b for b in self.blocks if b.diff_type != DiffType.EQUAL]

    def equal_blocks(self) -> List[DiffBlock]:
        """Return only EQUAL blocks."""
        return [b for b in self.blocks if b.diff_type == DiffType.EQUAL]

    def is_identical(self) -> bool:
        """True when both files are byte-for-byte identical."""
        return self.stats.changed_bytes == 0 and \
               self.stats.added_bytes   == 0 and \
               self.stats.removed_bytes == 0

    def __len__(self) -> int:
        return len(self.blocks)

    def __repr__(self) -> str:
        return (
            f"DiffResult(blocks={len(self.blocks)}, "
            f"+{self.stats.added_bytes}B, "
            f"-{self.stats.removed_bytes}B, "
            f"~{self.stats.changed_bytes}B)"
        )


# ---------------------------------------------------------------------------
# LCS / Myers helpers
# ---------------------------------------------------------------------------

class _MyersState:
    """Internal state for the Myers diff algorithm over byte sequences."""

    __slots__ = ("a", "b", "n", "m", "_v")

    def __init__(self, a: bytes, b: bytes) -> None:
        self.a = a
        self.b = b
        self.n = len(a)
        self.m = len(b)

    # ------------------------------------------------------------------
    # Myers diff — O(ND) algorithm
    # Reference: E. W. Myers, "An O(ND) Difference Algorithm and Its Variations"
    # ------------------------------------------------------------------

    def _shortest_edit(self) -> List[dict]:
        """Compute the edit graph via Myers O(ND) and return trace."""
        n, m = self.n, self.m
        max_d = n + m
        # v maps diagonal k → furthest reaching x
        v: Dict[int, int] = {1: 0}
        trace: List[dict] = []

        for d in range(0, max_d + 1):
            snap = dict(v)
            trace.append(snap)
            for k in range(-d, d + 1, 2):
                # Choose to move right (delete from a) or down (insert from b)
                if k == -d or (k != d and v.get(k - 1, -1) < v.get(k + 1, -1)):
                    x = v.get(k + 1, 0)
                else:
                    x = v.get(k - 1, 0) + 1
                y = x - k
                # Extend along diagonal (matching bytes)
                while x < n and y < m and self.a[x] == self.b[y]:
                    x += 1
                    y += 1
                v[k] = x
                if x >= n and y >= m:
                    return trace
        return trace  # should not reach here

    def _backtrack(self, trace: List[dict]) -> List[Tuple[int, int, int, int]]:
        """Backtrack through the edit trace to recover the edit script."""
        x, y = self.n, self.m
        edits: List[Tuple[int, int, int, int]] = []  # (prev_x, prev_y, x, y)

        for d in range(len(trace) - 1, 0, -1):
            v = trace[d]
            k = x - y
            if k == -d or (k != d and v.get(k - 1, -1) < v.get(k + 1, -1)):
                prev_k = k + 1
            else:
                prev_k = k - 1
            prev_v = trace[d - 1]
            prev_x = prev_v.get(prev_k, 0)
            prev_y = prev_x - prev_k

            while x > prev_x + 1 and y > prev_y + 1:
                edits.append((x - 1, y - 1, x, y))
                x -= 1
                y -= 1
            edits.append((prev_x, prev_y, prev_x + (1 if x == prev_x + 1 else 0),
                           prev_y + (1 if y == prev_y + 1 else 0)))
            x, y = prev_x, prev_y

        # Remaining diagonal run at the start
        while x > 0 and y > 0 and self.a[x - 1] == self.b[y - 1]:
            edits.append((x - 1, y - 1, x, y))
            x -= 1
            y -= 1

        edits.reverse()
        return edits

    def compute_edits(self) -> List[Tuple[str, int, int, int, int]]:
        """Return list of (op, old_start, old_end, new_start, new_end)."""
        if self.n == 0 and self.m == 0:
            return []
        if self.n == 0:
            return [("insert", 0, 0, 0, self.m)]
        if self.m == 0:
            return [("delete", 0, self.n, 0, 0)]

        trace = self._shortest_edit()
        raw   = self._backtrack(trace)

        ops: List[Tuple[str, int, int, int, int]] = []
        for (px, py, cx, cy) in raw:
            dx = cx - px
            dy = cy - py
            if dx == 1 and dy == 1:
                ops.append(("equal", px, cx, py, cy))
            elif dx == 1 and dy == 0:
                ops.append(("delete", px, cx, py, cy))
            elif dx == 0 and dy == 1:
                ops.append(("insert", px, cx, py, cy))
        return ops


def _merge_ops(
    ops: List[Tuple[str, int, int, int, int]]
) -> List[Tuple[str, int, int, int, int]]:
    """Merge consecutive operations of the same type."""
    if not ops:
        return ops
    merged: List[Tuple[str, int, int, int, int]] = [ops[0]]
    for op, os, oe, ns, ne in ops[1:]:
        last_op, last_os, last_oe, last_ns, last_ne = merged[-1]
        if op == last_op and os == last_oe and ns == last_ne:
            merged[-1] = (op, last_os, oe, last_ns, ne)
        else:
            merged.append((op, os, oe, ns, ne))
    return merged


# ---------------------------------------------------------------------------
# Main DiffEngine class
# ---------------------------------------------------------------------------

class DiffEngine:
    """High-level binary diff/patch/merge engine.

    All public methods accept ``bytes``-like objects.  File paths are
    accepted by the ``_files`` variants which load data automatically.

    Usage
    -----
    >>> engine = DiffEngine()
    >>> result = engine.diff(old_data, new_data)
    >>> patch  = engine.patch_from_diff(result)
    >>> merged, conflicts = engine.merge(base, mod1, mod2)
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def diff(self, data1: bytes, data2: bytes) -> DiffResult:
        """Compute a byte-level diff between *data1* and *data2*.

        Returns a :class:`DiffResult` whose ``blocks`` list covers the
        entire content of both files in order.

        Parameters
        ----------
        data1 : bytes
            Original ("old") data.
        data2 : bytes
            Modified ("new") data.
        """
        data1 = bytes(data1)
        data2 = bytes(data2)

        state = _MyersState(data1, data2)
        raw_ops = state.compute_edits()
        merged  = _merge_ops(raw_ops)

        blocks: List[DiffBlock] = []
        stats = DiffStats(
            old_size=len(data1),
            new_size=len(data2),
        )

        for op, os, oe, ns, ne in merged:
            old_chunk = data1[os:oe]
            new_chunk = data2[ns:ne]
            if op == "equal":
                blocks.append(DiffBlock(DiffType.EQUAL, os, old_chunk, new_chunk, ns))
                stats.equal_bytes += len(old_chunk)
            elif op == "delete":
                blocks.append(DiffBlock(DiffType.REMOVE, os, old_chunk, b"", ns))
                stats.removed_bytes += len(old_chunk)
                stats.block_count   += 1
            elif op == "insert":
                blocks.append(DiffBlock(DiffType.ADD, os, b"", new_chunk, ns))
                stats.added_bytes += len(new_chunk)
                stats.block_count += 1

        # Post-process: collapse adjacent REMOVE+ADD into MODIFY
        blocks = self._coalesce_modify(blocks, stats)

        result = DiffResult(
            blocks   = blocks,
            stats    = stats,
            old_hash = hashlib.sha256(data1).hexdigest(),
            new_hash = hashlib.sha256(data2).hexdigest(),
        )
        return result

    def diff_files(self, path1: str, path2: str) -> DiffResult:
        """Load two files and compute their diff.

        Parameters
        ----------
        path1, path2 : str or Path
            Paths to the original and modified files.
        """
        p1 = Path(path1)
        p2 = Path(path2)
        data1 = p1.read_bytes()
        data2 = p2.read_bytes()
        return self.diff(data1, data2)

    def patch_from_diff(self, diff_result: DiffResult) -> bytes:
        """Generate a compact binary patch from a DiffResult.

        Patch format (custom):
        - 8-byte magic: b"BMPATCH\\x01"
        - 4-byte: old_size (uint32 LE)
        - 4-byte: new_size (uint32 LE)
        - 32-byte: SHA-256 of old data
        - 32-byte: SHA-256 of new data
        - Records until EOF:
            - 1-byte type: 0=EQUAL_SKIP, 1=ADD, 2=REMOVE, 3=MODIFY
            - 4-byte offset (uint32 LE)
            - For EQUAL_SKIP: 4-byte count
            - For ADD: 4-byte count + bytes
            - For REMOVE: 4-byte count
            - For MODIFY: 4-byte old_count + 4-byte new_count + new_bytes
        """
        MAGIC    = b"BMPATCH\x01"
        buf = bytearray()
        buf += MAGIC
        buf += struct.pack("<II", diff_result.stats.old_size, diff_result.stats.new_size)
        buf += bytes.fromhex(diff_result.old_hash)
        buf += bytes.fromhex(diff_result.new_hash)

        for blk in diff_result.blocks:
            if blk.diff_type == DiffType.EQUAL:
                buf += struct.pack("<BII", 0, blk.offset, len(blk.old_data))
            elif blk.diff_type == DiffType.ADD:
                buf += struct.pack("<BII", 1, blk.offset, len(blk.new_data))
                buf += blk.new_data
            elif blk.diff_type == DiffType.REMOVE:
                buf += struct.pack("<BII", 2, blk.offset, len(blk.old_data))
            elif blk.diff_type == DiffType.MODIFY:
                buf += struct.pack("<BIII", 3, blk.offset,
                                   len(blk.old_data), len(blk.new_data))
                buf += blk.new_data

        return bytes(buf)

    @staticmethod
    def apply_patch(data: bytes, patch: bytes) -> bytes:
        """Apply a patch generated by :meth:`patch_from_diff` to *data*.

        Parameters
        ----------
        data : bytes
            Original data (old version).
        patch : bytes
            Patch bytes produced by ``patch_from_diff``.

        Returns
        -------
        bytes
            Patched (new) data.

        Raises
        ------
        ValueError
            If the patch magic is invalid or the data hash does not match.
        """
        MAGIC = b"BMPATCH\x01"
        if not patch[:8] == MAGIC:
            raise ValueError("Invalid patch magic bytes")

        old_size, new_size = struct.unpack_from("<II", patch, 8)
        old_hash_expected  = patch[16:48].hex()
        new_hash_expected  = patch[48:80].hex()

        data = bytes(data)
        if hashlib.sha256(data).hexdigest() != old_hash_expected:
            raise ValueError("Source data hash mismatch; wrong base file?")

        result = bytearray(data)
        pos    = 80   # read cursor in patch
        offset_delta = 0  # cumulative insertion/deletion offset shift

        while pos < len(patch):
            rec_type = patch[pos]; pos += 1
            if rec_type == 0:  # EQUAL_SKIP
                _offset, count = struct.unpack_from("<II", patch, pos); pos += 8
            elif rec_type == 1:  # ADD
                offset, count = struct.unpack_from("<II", patch, pos); pos += 8
                payload = patch[pos:pos + count]; pos += count
                insert_pos = offset + offset_delta
                result = result[:insert_pos] + bytearray(payload) + result[insert_pos:]
                offset_delta += count
            elif rec_type == 2:  # REMOVE
                offset, count = struct.unpack_from("<II", patch, pos); pos += 8
                del_pos = offset + offset_delta
                del result[del_pos:del_pos + count]
                offset_delta -= count
            elif rec_type == 3:  # MODIFY
                offset, old_count, new_count = struct.unpack_from("<III", patch, pos)
                pos += 12
                payload  = patch[pos:pos + new_count]; pos += new_count
                mod_pos  = offset + offset_delta
                result[mod_pos:mod_pos + old_count] = payload
                offset_delta += new_count - old_count
            else:
                raise ValueError(f"Unknown patch record type: {rec_type}")

        result_bytes = bytes(result)
        if hashlib.sha256(result_bytes).hexdigest() != new_hash_expected:
            raise ValueError("Patched data hash mismatch; patch may be corrupt")
        return result_bytes

    def merge(
        self,
        base: bytes,
        modified1: bytes,
        modified2: bytes,
    ) -> Tuple[bytes, List[Tuple[int, bytes, bytes]]]:
        """Perform a 3-way merge of *modified1* and *modified2* against *base*.

        Both modifications are diffed against the common *base*, then the
        two change sets are interleaved.  Overlapping changes produce
        conflicts.

        Parameters
        ----------
        base : bytes
            The common ancestor.
        modified1 : bytes
            First branch modification.
        modified2 : bytes
            Second branch modification.

        Returns
        -------
        merged : bytes
            The merged result.  Conflict regions use the *modified1* data.
        conflicts : list of (offset, mod1_bytes, mod2_bytes)
            Each tuple describes a conflict region.
        """
        base      = bytes(base)
        modified1 = bytes(modified1)
        modified2 = bytes(modified2)

        diff1 = self.diff(base, modified1)
        diff2 = self.diff(base, modified2)

        # Build change maps: offset -> (old_bytes, new_bytes)
        changes1: Dict[int, Tuple[bytes, bytes]] = {}
        for blk in diff1.blocks:
            if blk.diff_type != DiffType.EQUAL:
                changes1[blk.offset] = (blk.old_data, blk.new_data)

        changes2: Dict[int, Tuple[bytes, bytes]] = {}
        for blk in diff2.blocks:
            if blk.diff_type != DiffType.EQUAL:
                changes2[blk.offset] = (blk.old_data, blk.new_data)

        result   = bytearray(base)
        conflicts: List[Tuple[int, bytes, bytes]] = []

        # Collect all change offsets
        all_offsets = sorted(set(changes1) | set(changes2))
        delta = 0  # cumulative byte offset shift due to insertions/deletions

        for off in all_offsets:
            in1 = off in changes1
            in2 = off in changes2

            if in1 and not in2:
                old1, new1 = changes1[off]
                pos = off + delta
                result[pos:pos + len(old1)] = new1
                delta += len(new1) - len(old1)

            elif in2 and not in1:
                old2, new2 = changes2[off]
                pos = off + delta
                result[pos:pos + len(old2)] = new2
                delta += len(new2) - len(old2)

            else:
                # Both branches changed the same region
                old1, new1 = changes1[off]
                _old2, new2 = changes2[off]
                if new1 == new2:
                    # Same change in both — no conflict
                    pos = off + delta
                    result[pos:pos + len(old1)] = new1
                    delta += len(new1) - len(old1)
                else:
                    # Real conflict — use mod1 data, record conflict
                    pos = off + delta
                    result[pos:pos + len(old1)] = new1
                    delta += len(new1) - len(old1)
                    conflicts.append((off, new1, new2))

        return bytes(result), conflicts

    def similarity(self, data1: bytes, data2: bytes) -> float:
        """Return a similarity score between 0.0 (completely different) and 1.0 (identical).

        Uses the ratio of equal bytes to total bytes in both sequences.
        """
        data1 = bytes(data1)
        data2 = bytes(data2)
        if not data1 and not data2:
            return 1.0
        result = self.diff(data1, data2)
        return result.stats.similarity

    def longest_common_subsequence(
        self, data1: bytes, data2: bytes
    ) -> List[Tuple[int, int, int]]:
        """Find matching subsequences between *data1* and *data2*.

        Returns a list of (old_offset, new_offset, length) tuples
        representing common byte blocks.  Uses the diff engine's EQUAL
        blocks as an efficient LCS approximation.
        """
        data1 = bytes(data1)
        data2 = bytes(data2)
        result = self.diff(data1, data2)
        matches: List[Tuple[int, int, int]] = []
        for blk in result.blocks:
            if blk.diff_type == DiffType.EQUAL and len(blk.old_data) > 0:
                matches.append((blk.offset, blk.new_offset, len(blk.old_data)))
        return matches

    def format_diff(
        self,
        diff_result: DiffResult,
        context: int = 3,
        old_label: str = "old",
        new_label: str = "new",
    ) -> str:
        """Format a diff result as a unified-style hex diff.

        Parameters
        ----------
        diff_result : DiffResult
            Result to format.
        context : int
            Number of equal bytes to show before/after each change.
        old_label, new_label : str
            Labels used in the header.

        Returns
        -------
        str
            Human-readable unified diff string.
        """
        lines: List[str] = []
        lines.append(f"--- {old_label}  sha256:{diff_result.old_hash[:16]}...")
        lines.append(f"+++ {new_label}  sha256:{diff_result.new_hash[:16]}...")
        lines.append(
            f"@@ old_size={diff_result.stats.old_size}  "
            f"new_size={diff_result.stats.new_size} @@"
        )

        blocks = diff_result.blocks
        n      = len(blocks)

        # Identify which EQUAL blocks need to be trimmed for context
        i = 0
        while i < n:
            blk = blocks[i]
            if blk.diff_type == DiffType.EQUAL:
                i += 1
                continue
            # Found a change block; collect a hunk
            hunk_start = i
            hunk_end   = i
            # Look ahead for more changes within context distance
            j = i + 1
            while j < n:
                if blocks[j].diff_type != DiffType.EQUAL:
                    hunk_end = j
                    j += 1
                else:
                    # Count equal bytes between changes
                    eq_size = len(blocks[j].old_data) if blocks[j].old_data else len(blocks[j].new_data)
                    if eq_size <= 2 * context:
                        hunk_end = j
                        j += 1
                    else:
                        break
                j += 1 if j == hunk_end + 1 else 0

            # Collect context before hunk_start
            ctx_before_idx = hunk_start - 1
            ctx_before_bytes = b""
            if ctx_before_idx >= 0 and blocks[ctx_before_idx].diff_type == DiffType.EQUAL:
                ctx_before_bytes = blocks[ctx_before_idx].old_data[-context:]

            # Collect context after hunk_end
            ctx_after_idx = hunk_end + 1
            ctx_after_bytes = b""
            if ctx_after_idx < n and blocks[ctx_after_idx].diff_type == DiffType.EQUAL:
                ctx_after_bytes = blocks[ctx_after_idx].old_data[:context]

            # Compute hunk header offsets
            first_blk  = blocks[hunk_start]
            old_start  = first_blk.offset - len(ctx_before_bytes)
            new_start  = first_blk.new_offset - len(ctx_before_bytes)

            lines.append(f"@@ -{old_start:#010x} +{new_start:#010x} @@")

            # Context before
            if ctx_before_bytes:
                lines.append(" " + _hex_line(ctx_before_bytes, old_start))

            # Hunk blocks
            for bi in range(hunk_start, hunk_end + 1):
                b2 = blocks[bi]
                if b2.diff_type == DiffType.EQUAL:
                    # Show trimmed context
                    lines.append(" " + _hex_line(b2.old_data[:context], b2.offset))
                elif b2.diff_type == DiffType.REMOVE:
                    lines.append("-" + _hex_line(b2.old_data, b2.offset))
                elif b2.diff_type == DiffType.ADD:
                    lines.append("+" + _hex_line(b2.new_data, b2.new_offset))
                elif b2.diff_type == DiffType.MODIFY:
                    lines.append("-" + _hex_line(b2.old_data, b2.offset))
                    lines.append("+" + _hex_line(b2.new_data, b2.new_offset))

            # Context after
            if ctx_after_bytes:
                last_blk = blocks[hunk_end]
                after_off = last_blk.offset + len(last_blk.old_data)
                lines.append(" " + _hex_line(ctx_after_bytes, after_off))

            i = hunk_end + 1

        # Summary footer
        lines.append(
            f"\n-- Summary: "
            f"+{diff_result.stats.added_bytes}B  "
            f"-{diff_result.stats.removed_bytes}B  "
            f"~{diff_result.stats.changed_bytes}B  "
            f"={diff_result.stats.equal_bytes}B"
        )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _coalesce_modify(
        blocks: List[DiffBlock], stats: DiffStats
    ) -> List[DiffBlock]:
        """Merge adjacent REMOVE+ADD blocks into MODIFY blocks."""
        out: List[DiffBlock] = []
        i = 0
        while i < len(blocks):
            blk = blocks[i]
            if (
                blk.diff_type == DiffType.REMOVE
                and i + 1 < len(blocks)
                and blocks[i + 1].diff_type == DiffType.ADD
                and blocks[i + 1].offset == blk.offset
            ):
                nxt = blocks[i + 1]
                mod = DiffBlock(
                    diff_type = DiffType.MODIFY,
                    offset    = blk.offset,
                    old_data  = blk.old_data,
                    new_data  = nxt.new_data,
                    new_offset= nxt.new_offset,
                )
                out.append(mod)
                # Update stats
                stats.changed_bytes += max(len(blk.old_data), len(nxt.new_data))
                stats.removed_bytes -= len(blk.old_data)
                stats.added_bytes   -= len(nxt.new_data)
                stats.block_count   -= 1   # was 2 separate blocks, now 1
                i += 2
            else:
                out.append(blk)
                i += 1
        return out


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _hex_line(data: bytes, offset: int, width: int = 16) -> str:
    """Format bytes as a hex+ASCII line for diff output."""
    parts: List[str] = []
    for chunk_start in range(0, len(data), width):
        chunk = data[chunk_start:chunk_start + width]
        hex_part   = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        parts.append(
            f"0x{offset + chunk_start:08X}  {hex_part:<{width * 3 - 1}}  |{ascii_part}|"
        )
    return "\n ".join(parts)


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------

def quick_diff(old: bytes, new: bytes) -> DiffResult:
    """Convenience wrapper: compute a diff without instantiating DiffEngine."""
    return DiffEngine().diff(old, new)


def quick_similarity(data1: bytes, data2: bytes) -> float:
    """Convenience wrapper: return similarity score between two byte strings."""
    return DiffEngine().similarity(data1, data2)


def diff_summary(result: DiffResult) -> str:
    """Return a short one-line summary of a DiffResult."""
    return (
        f"Diff: old={result.stats.old_size}B  new={result.stats.new_size}B  "
        f"added={result.stats.added_bytes}B  removed={result.stats.removed_bytes}B  "
        f"changed={result.stats.changed_bytes}B  "
        f"similarity={result.stats.similarity:.1%}"
    )


# ---------------------------------------------------------------------------
# Extended analysis helpers on DiffResult
# ---------------------------------------------------------------------------

class DiffAnalyzer:
    """Additional analytical methods on top of DiffResult.

    These are factored out of DiffEngine to keep the core class focused
    on computation rather than reporting.
    """

    def __init__(self, result: DiffResult) -> None:
        self.result = result

    # ------------------------------------------------------------------

    def change_density(self, window: int = 256) -> List[Tuple[int, float]]:
        """Compute change density (fraction of modified bytes) in sliding windows.

        Returns
        -------
        list of (offset, density)
        """
        if self.result.stats.old_size == 0:
            return []

        # Build a flat change bitmap over old file offsets
        old_size = self.result.stats.old_size
        bitmap   = bytearray(old_size)
        for blk in self.result.blocks:
            if blk.diff_type in (DiffType.REMOVE, DiffType.MODIFY):
                end = min(blk.offset + len(blk.old_data), old_size)
                for k in range(blk.offset, end):
                    bitmap[k] = 1

        result: List[Tuple[int, float]] = []
        for start in range(0, old_size, window // 2):
            end    = min(start + window, old_size)
            chunk  = bitmap[start:end]
            density = sum(chunk) / len(chunk) if chunk else 0.0
            result.append((start, density))
        return result

    def largest_change(self) -> Optional[DiffBlock]:
        """Return the single largest non-EQUAL block."""
        changed = self.result.changed_blocks()
        if not changed:
            return None
        return max(changed, key=lambda b: b.size)

    def change_offsets(self) -> List[int]:
        """Return sorted list of byte offsets where changes begin."""
        return sorted(
            b.offset for b in self.result.blocks
            if b.diff_type != DiffType.EQUAL
        )

    def run_length_encoding(self) -> List[Tuple[str, int, int]]:
        """Compress the block list into run-length encoded form.

        Returns list of (type_name, start_offset, byte_count).
        """
        runs: List[Tuple[str, int, int]] = []
        for blk in self.result.blocks:
            name = blk.diff_type.name
            size = blk.size
            if runs and runs[-1][0] == name:
                prev = runs[-1]
                runs[-1] = (prev[0], prev[1], prev[2] + size)
            else:
                runs.append((name, blk.offset, size))
        return runs

    def report(self) -> str:
        """Generate a human-readable analysis report."""
        r = self.result
        s = r.stats
        lines = [
            "=" * 60,
            "  DIFF ANALYSIS REPORT",
            "=" * 60,
            f"  Old file : {s.old_size:,} bytes  sha256:{r.old_hash[:16]}...",
            f"  New file : {s.new_size:,} bytes  sha256:{r.new_hash[:16]}...",
            f"  Similarity : {s.similarity:.2%}",
            "-" * 60,
            f"  Equal bytes    : {s.equal_bytes:>10,}",
            f"  Added bytes    : {s.added_bytes:>10,}",
            f"  Removed bytes  : {s.removed_bytes:>10,}",
            f"  Changed bytes  : {s.changed_bytes:>10,}",
            f"  Change blocks  : {s.block_count:>10,}",
            "-" * 60,
        ]
        largest = self.largest_change()
        if largest:
            lines.append(
                f"  Largest change : offset=0x{largest.offset:08X}  "
                f"size={largest.size}B  type={largest.diff_type.name}"
            )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Patch file I/O
# ---------------------------------------------------------------------------

class PatchFile:
    """Helper for serialising/deserialising patch files to disk."""

    EXTENSION = ".bmpatch"

    def __init__(self, engine: Optional[DiffEngine] = None) -> None:
        self._engine = engine or DiffEngine()

    def create(self, old_path: str, new_path: str, patch_path: str) -> None:
        """Create a patch file by diffing *old_path* against *new_path*."""
        result = self._engine.diff_files(old_path, new_path)
        patch  = self._engine.patch_from_diff(result)
        Path(patch_path).write_bytes(patch)

    def apply(self, source_path: str, patch_path: str, output_path: str) -> None:
        """Apply *patch_path* to *source_path* and write result to *output_path*."""
        data  = Path(source_path).read_bytes()
        patch = Path(patch_path).read_bytes()
        patched = DiffEngine.apply_patch(data, patch)
        Path(output_path).write_bytes(patched)

    def verify(self, source_path: str, patch_path: str) -> bool:
        """Return True if *source_path* matches the patch's expected source hash."""
        data  = Path(source_path).read_bytes()
        patch = Path(patch_path).read_bytes()
        HEADER_OLD_HASH_OFFSET = 16
        expected_hash = patch[HEADER_OLD_HASH_OFFSET:HEADER_OLD_HASH_OFFSET + 32].hex()
        return hashlib.sha256(data).hexdigest() == expected_hash

    def info(self, patch_path: str) -> dict:
        """Return metadata dictionary extracted from a patch file header."""
        patch = Path(patch_path).read_bytes()
        if patch[:8] != b"BMPATCH\x01":
            raise ValueError("Not a BinModder patch file")
        old_size, new_size = struct.unpack_from("<II", patch, 8)
        old_hash = patch[16:48].hex()
        new_hash = patch[48:80].hex()
        return {
            "format":   "BMPATCH v1",
            "old_size": old_size,
            "new_size": new_size,
            "old_hash": old_hash,
            "new_hash": new_hash,
            "patch_size": len(patch),
        }


# ---------------------------------------------------------------------------
# Block-level utilities
# ---------------------------------------------------------------------------

def filter_blocks_by_type(
    result: DiffResult, *types: DiffType
) -> List[DiffBlock]:
    """Return only blocks matching the given types."""
    type_set = set(types)
    return [b for b in result.blocks if b.diff_type in type_set]


def blocks_in_range(
    result: DiffResult, start: int, end: int
) -> List[DiffBlock]:
    """Return blocks whose old-file offset overlaps [start, end)."""
    out = []
    for blk in result.blocks:
        blk_end = blk.offset + (len(blk.old_data) or 1)
        if blk.offset < end and blk_end > start:
            out.append(blk)
    return out


def reconstruct_old(result: DiffResult) -> bytes:
    """Reconstruct old data from a DiffResult (EQUAL + REMOVE + MODIFY old sides)."""
    parts: List[bytes] = []
    for blk in result.blocks:
        if blk.diff_type in (DiffType.EQUAL, DiffType.REMOVE, DiffType.MODIFY):
            parts.append(blk.old_data)
    return b"".join(parts)


def reconstruct_new(result: DiffResult) -> bytes:
    """Reconstruct new data from a DiffResult (EQUAL + ADD + MODIFY new sides)."""
    parts: List[bytes] = []
    for blk in result.blocks:
        if blk.diff_type == DiffType.EQUAL:
            parts.append(blk.old_data)
        elif blk.diff_type in (DiffType.ADD, DiffType.MODIFY):
            parts.append(blk.new_data)
    return b"".join(parts)


# ---------------------------------------------------------------------------
# Rolling hash helper (Rabin-Karp style) for large-file optimisation
# ---------------------------------------------------------------------------

class _RollingHash:
    """A simple polynomial rolling hash used to speed up pattern search."""

    BASE  = 257
    MOD   = (1 << 31) - 1   # Mersenne prime

    def __init__(self, window: int) -> None:
        self.window = window
        self._h     = 0
        self._base_n = pow(self.BASE, window - 1, self.MOD)
        self._buf: List[int] = []

    def update(self, byte: int) -> int:
        self._buf.append(byte)
        self._h = (self._h * self.BASE + byte) % self.MOD
        if len(self._buf) > self.window:
            old = self._buf.pop(0)
            self._h = (self._h - old * self._base_n) % self.MOD
        return self._h

    @property
    def value(self) -> int:
        return self._h


def _chunk_hash_map(data: bytes, chunk_size: int) -> Dict[int, List[int]]:
    """Build a map of {rolling_hash: [offset, ...]} for fast substring lookup."""
    rh  = _RollingHash(chunk_size)
    hmap: Dict[int, List[int]] = {}

    for i, b in enumerate(data):
        h = rh.update(b)
        if i >= chunk_size - 1:
            start = i - chunk_size + 1
            hmap.setdefault(h, []).append(start)
    return hmap


# ---------------------------------------------------------------------------
# Self-test (run as script)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import os
    import sys

    print("DiffEngine self-test")
    print("=" * 40)

    engine = DiffEngine()

    # Basic identical
    r = engine.diff(b"hello", b"hello")
    assert r.is_identical(), "Identical data should produce no changes"
    print("PASS: identical data")

    # Basic add
    r = engine.diff(b"hello", b"hello world")
    assert r.stats.added_bytes == 6
    print("PASS: addition detected")

    # Basic remove
    r = engine.diff(b"hello world", b"hello")
    assert r.stats.removed_bytes == 6
    print("PASS: removal detected")

    # Modify
    r = engine.diff(b"AABAA", b"AACAA")
    assert r.stats.changed_bytes > 0
    print("PASS: modification detected")

    # Similarity
    sim = engine.similarity(b"abcdef", b"abcxyz")
    assert 0.0 < sim < 1.0
    print(f"PASS: similarity = {sim:.3f}")

    # Patch round-trip
    old = b"The quick brown fox jumps over the lazy dog"
    new = b"The quick brown cat jumps over the happy dog"
    r   = engine.diff(old, new)
    patch = engine.patch_from_diff(r)
    restored = DiffEngine.apply_patch(old, patch)
    assert restored == new, "Patch round-trip failed"
    print("PASS: patch round-trip")

    # 3-way merge (non-conflicting)
    base = b"AABBCC"
    m1   = b"AAXBCC"
    m2   = b"AABBCY"
    merged, conflicts = engine.merge(base, m1, m2)
    assert len(conflicts) == 0
    print("PASS: 3-way merge non-conflicting")

    # Format diff
    r   = engine.diff(b"old data here", b"new content now")
    out = engine.format_diff(r)
    assert "---" in out and "+++" in out
    print("PASS: format_diff output")

    print("\nAll self-tests passed.")
