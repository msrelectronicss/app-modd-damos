# =============================================================================
# BinModder - Binary Comparator Tool
# =============================================================================
# High-level binary comparison interface built on top of DiffEngine.
# Provides byte-level diff, summary statistics, and export to text or HTML.
#
# Author: MSR Electronics
# Version: 1.0.0
# =============================================================================

from pathlib import Path
from typing import List, Optional, Tuple

from core.diff_engine import DiffEngine, DiffBlock, DiffResult, DiffType
from utils.log_utils  import BinModderLogger

log = BinModderLogger.get("tools.comparator")


# =============================================================================
# BinaryComparator
# =============================================================================

class BinaryComparator:
    """Compare two binary files (or byte buffers) and present the results.

    Usage
    -----
    >>> cmp = BinaryComparator()
    >>> result = cmp.compare_files("original.bin", "modified.bin")
    >>> print(cmp.summary(result))
    >>> cmp.export_text(result, "diff.txt")
    """

    def __init__(self) -> None:
        self._engine = DiffEngine()

    # ------------------------------------------------------------------
    # Comparison entry points
    # ------------------------------------------------------------------

    def compare(self, old: bytes, new: bytes) -> DiffResult:
        """Compute a byte-level diff between *old* and *new*.

        Parameters
        ----------
        old : bytes
            Original / reference data.
        new : bytes
            Modified data to compare against *old*.

        Returns
        -------
        DiffResult
            Structured result containing the list of diff blocks and
            aggregate statistics.
        """
        log.debug("Comparing buffers: %d vs %d bytes", len(old), len(new))
        return self._engine.diff(old, new)

    def compare_files(
        self,
        old_path: "str | Path",
        new_path: "str | Path",
    ) -> DiffResult:
        """Load two files and compare their contents.

        Parameters
        ----------
        old_path : str | Path
            Path to the original file.
        new_path : str | Path
            Path to the modified file.

        Returns
        -------
        DiffResult
            Same as :meth:`compare`.

        Raises
        ------
        FileNotFoundError
            If either file does not exist.
        """
        old_p = Path(old_path)
        new_p = Path(new_path)
        for p in (old_p, new_p):
            if not p.exists():
                raise FileNotFoundError(f"'{p}' not found")

        old_data = old_p.read_bytes()
        new_data = new_p.read_bytes()
        log.info(
            "Comparing '%s' (%d B) vs '%s' (%d B)",
            old_p.name, len(old_data),
            new_p.name, len(new_data),
        )
        return self.compare(old_data, new_data)

    # ------------------------------------------------------------------
    # Reporting helpers
    # ------------------------------------------------------------------

    def summary(self, result: DiffResult) -> str:
        """Return a one-line human-readable summary of *result*."""
        adds    = sum(1 for b in result.blocks if b.diff_type == DiffType.ADD)
        removes = sum(1 for b in result.blocks if b.diff_type == DiffType.REMOVE)
        mods    = sum(1 for b in result.blocks if b.diff_type == DiffType.MODIFY)
        added_bytes   = sum(len(b.new_data) for b in result.blocks if b.diff_type == DiffType.ADD)
        removed_bytes = sum(len(b.old_data) for b in result.blocks if b.diff_type == DiffType.REMOVE)
        mod_bytes     = sum(len(b.old_data) for b in result.blocks if b.diff_type == DiffType.MODIFY)

        lines = [
            f"Similarity : {result.similarity:.1%}",
            f"Changes    : {adds} additions (+{added_bytes} B)  |  "
            f"{removes} deletions (-{removed_bytes} B)  |  "
            f"{mods} modifications (~{mod_bytes} B)",
            f"Total blocks: {len(result.blocks)}",
        ]
        return "\n".join(lines)

    def changed_offsets(self, result: DiffResult) -> List[Tuple[int, int, DiffType]]:
        """Return a list of ``(offset, size, type)`` for all non-equal blocks.

        Useful for quickly building a list of changed regions without
        iterating over :attr:`DiffResult.blocks` manually.
        """
        out: List[Tuple[int, int, DiffType]] = []
        for b in result.blocks:
            if b.diff_type != DiffType.EQUAL:
                size = max(len(b.old_data), len(b.new_data))
                out.append((b.offset, size, b.diff_type))
        return out

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_text(self, result: DiffResult, path: "str | Path") -> None:
        """Write a plain-text diff report to *path*.

        Parameters
        ----------
        result : DiffResult
            Comparison result to export.
        path : str | Path
            Destination file.
        """
        lines = ["BinModder Binary Diff Report", "=" * 60, self.summary(result), ""]
        for blk in result.blocks:
            if blk.diff_type == DiffType.EQUAL:
                continue
            tag = blk.diff_type.name
            lines.append(
                f"[{tag}]  offset=0x{blk.offset:08X}  "
                f"old={blk.old_data.hex(' ') or '(none)'}  "
                f"new={blk.new_data.hex(' ') or '(none)'}"
            )
        Path(path).write_text("\n".join(lines), encoding="utf-8")
        log.info("Diff report written to '%s'", path)

    def export_html(self, result: DiffResult, path: "str | Path") -> None:
        """Write a minimal HTML diff report to *path*.

        Parameters
        ----------
        result : DiffResult
            Comparison result to export.
        path : str | Path
            Destination file.
        """
        _TAG_COLORS = {
            DiffType.ADD:    ("#1a4a1a", "#a6e3a1"),
            DiffType.REMOVE: ("#4a1a1a", "#f38ba8"),
            DiffType.MODIFY: ("#4a3800", "#f9e2af"),
        }
        rows: List[str] = []
        for blk in result.blocks:
            if blk.diff_type == DiffType.EQUAL:
                continue
            bg, fg = _TAG_COLORS.get(blk.diff_type, ("#222", "#ccc"))
            old_hex = blk.old_data.hex(" ").upper() or "&mdash;"
            new_hex = blk.new_data.hex(" ").upper() or "&mdash;"
            rows.append(
                f'<tr style="background:{bg};color:{fg}">'
                f'<td>0x{blk.offset:08X}</td>'
                f'<td>{blk.diff_type.name}</td>'
                f'<td><code>{old_hex}</code></td>'
                f'<td><code>{new_hex}</code></td>'
                f'</tr>'
            )

        html = (
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            "<title>BinModder Diff</title>"
            "<style>body{background:#1e1e2e;color:#cdd6f4;font-family:monospace}"
            "table{border-collapse:collapse;width:100%}"
            "th,td{padding:6px 12px;border:1px solid #45475a;text-align:left}"
            "th{background:#181825}</style></head><body>"
            f"<h2>BinModder Binary Diff</h2><pre>{self.summary(result)}</pre>"
            "<table><tr><th>Offset</th><th>Type</th><th>Old</th><th>New</th></tr>"
            + "".join(rows)
            + "</table></body></html>"
        )
        Path(path).write_text(html, encoding="utf-8")
        log.info("HTML diff report written to '%s'", path)

    # ------------------------------------------------------------------
    # Dunder
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return "BinaryComparator()"
