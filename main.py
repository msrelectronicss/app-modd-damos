#!/usr/bin/env python3
# =============================================================================
# BinModder - Entry Point
# =============================================================================
# Command-line interface and application launcher.
#
# Usage:
#   python main.py gui                          # launch GUI
#   python main.py hex <file>                   # hex view
#   python main.py info <file>                  # file info + hashes
#   python main.py checksum <file> [--algo crc32]
#   python main.py search <file> <hex_pattern>
#   python main.py diff <file_a> <file_b>
#   python main.py extract <file> --offset N --size N [-o out]
#   python main.py inject <file> --offset N --data HEXSTRING
#   python main.py patch apply <file> <patch>
#   python main.py patch create <original> <modified> [-o out.bmp]
#
# Author: MSR Electronics
# Version: 1.0.0
# =============================================================================

import sys
import argparse
from pathlib import Path


# =============================================================================
# Lazy core imports (keep startup fast)
# =============================================================================

def _require_file(*paths: str) -> list:
    """Raise SystemExit if any of the given paths does not exist."""
    result = []
    for p in paths:
        fp = Path(p)
        if not fp.exists():
            sys.exit(f"[ERROR] File not found: '{fp}'")
        result.append(fp)
    return result


# =============================================================================
# Commands
# =============================================================================

def cmd_gui(_args) -> None:
    """Launch the Tkinter graphical interface."""
    try:
        import tkinter as tk
        from ui.gui.main_window import MainWindow
    except ImportError as exc:
        sys.exit(f"[ERROR] Cannot start GUI: {exc}")

    app = MainWindow()
    app.root.mainloop()


def cmd_hex(args) -> None:
    """Display a hex+ASCII view of a binary file."""
    from core.hex_engine import HexEngine, HexConfig

    (fp,) = _require_file(args.file)
    data  = fp.read_bytes()
    start = args.offset
    size  = args.size or len(data) - start
    chunk = data[start : start + size]

    cfg = HexConfig(
        bytes_per_row=args.width,
        use_colors=sys.stdout.isatty(),
    )
    print(HexEngine(cfg).display(chunk, start=start))


def cmd_info(args) -> None:
    """Print file metadata and integrity hashes."""
    from utils.file_utils import get_file_info

    (fp,) = _require_file(args.file)
    info  = get_file_info(fp)

    print(f"Path    : {info['path']}")
    print(f"Size    : {info['size']:,} bytes  ({info['size']:#010x})")
    print(f"MD5     : {info['md5']}")
    print(f"SHA-1   : {info['sha1']}")
    print(f"SHA-256 : {info['sha256']}")
    print(f"Binary  : {info['is_binary']}")


def cmd_checksum(args) -> None:
    """Compute and display checksums of a file."""
    from core.checksum import ChecksumEngine, ChecksumAlgorithm

    (fp,) = _require_file(args.file)
    data  = fp.read_bytes()
    eng   = ChecksumEngine()

    if args.all:
        results = eng.compute_all(data)
        for algo, value in results.items():
            print(f"{algo:<20} {value}")
    else:
        algo = ChecksumAlgorithm(args.algo)
        val  = eng.compute(data, algo)
        print(f"{args.algo:<20} {val}")


def cmd_search(args) -> None:
    """Search for a hex pattern inside a binary file."""
    from core.search_engine import SearchEngine, Pattern

    (fp,) = _require_file(args.file)
    data  = fp.read_bytes()

    try:
        raw = bytes.fromhex(args.pattern.replace(" ", ""))
    except ValueError:
        sys.exit("[ERROR] Pattern must be a hex string, e.g. 'DE AD BE EF'")

    results = SearchEngine().find_all(data, Pattern(raw))
    if not results:
        print("No matches found.")
        return

    print(f"Found {len(results)} match(es):")
    for r in results:
        print(f"  0x{r.offset:08X}  [{r.match.hex(' ').upper()}]")


def cmd_diff(args) -> None:
    """Compare two binary files and print a diff summary."""
    from tools.comparator import BinaryComparator

    cmp    = BinaryComparator()
    result = cmp.compare_files(args.file_a, args.file_b)
    print(cmp.summary(result))

    if args.output:
        out = Path(args.output)
        if out.suffix.lower() == ".html":
            cmp.export_html(result, out)
        else:
            cmp.export_text(result, out)
        print(f"\nReport saved to '{out}'")


def cmd_extract(args) -> None:
    """Extract a byte range from a binary file."""
    (fp,) = _require_file(args.file)
    data  = fp.read_bytes()
    chunk = data[args.offset : args.offset + args.size]

    out = Path(args.output) if args.output else fp.with_suffix(".extracted.bin")
    out.write_bytes(chunk)
    print(f"Extracted {len(chunk)} bytes -> '{out}'")


def cmd_inject(args) -> None:
    """Patch raw bytes into a file at a given offset."""
    from utils.file_utils import backup_file, safe_write

    (fp,) = _require_file(args.file)
    try:
        patch = bytes.fromhex(args.data.replace(" ", ""))
    except ValueError:
        sys.exit("[ERROR] --data must be a hex string")

    data = bytearray(fp.read_bytes())
    end  = args.offset + len(patch)
    if end > len(data):
        sys.exit(f"[ERROR] Patch [{args.offset:#x}:{end:#x}] exceeds file size {len(data):#x}")

    if args.backup:
        bak = backup_file(fp)
        print(f"Backup  : '{bak}'")

    data[args.offset : end] = patch
    safe_write(fp, bytes(data))
    print(f"Injected {len(patch)} bytes at 0x{args.offset:08X} -> '{fp}'")


def cmd_patch(args) -> None:
    """Apply or create binary patches."""
    from core.patch_engine import PatchEngine, PatchFormat

    eng = PatchEngine()

    if args.patch_cmd == "apply":
        (fp, pp) = _require_file(args.file, args.patch)
        data     = fp.read_bytes()
        patched  = eng.apply(data, pp)
        out      = Path(args.output) if args.output else fp.with_suffix(".patched.bin")
        out.write_bytes(patched)
        print(f"Patch applied -> '{out}'")

    elif args.patch_cmd == "create":
        (orig, mod) = _require_file(args.original, args.modified)
        fmt         = PatchFormat(args.format)
        patch_data  = eng.create(orig.read_bytes(), mod.read_bytes(), fmt)
        out         = Path(args.output) if args.output else orig.with_suffix(f".{fmt.value}")
        out.write_bytes(patch_data)
        print(f"Patch created  -> '{out}'  ({len(patch_data)} bytes)")


# =============================================================================
# Argument parser
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="binmodder",
        description="BinModder – Professional Binary File Modifier",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    # --- gui ---
    sub.add_parser("gui", help="Launch the graphical interface")

    # --- hex ---
    p_hex = sub.add_parser("hex", help="Display hex view of a file")
    p_hex.add_argument("file")
    p_hex.add_argument("--offset", type=lambda x: int(x, 0), default=0)
    p_hex.add_argument("--size",   type=lambda x: int(x, 0), default=None)
    p_hex.add_argument("--width",  type=int, default=16, metavar="N",
                       help="Bytes per row (default 16)")

    # --- info ---
    p_info = sub.add_parser("info", help="Show file metadata and hashes")
    p_info.add_argument("file")

    # --- checksum ---
    p_cs = sub.add_parser("checksum", help="Compute file checksums")
    p_cs.add_argument("file")
    p_cs.add_argument("--algo", default="crc32",
                      help="Algorithm name (default: crc32)")
    p_cs.add_argument("--all",  action="store_true",
                      help="Compute all available algorithms")

    # --- search ---
    p_sr = sub.add_parser("search", help="Search for a hex pattern")
    p_sr.add_argument("file")
    p_sr.add_argument("pattern", help='Hex string, e.g. "DE AD BE EF"')

    # --- diff ---
    p_df = sub.add_parser("diff", help="Compare two binary files")
    p_df.add_argument("file_a")
    p_df.add_argument("file_b")
    p_df.add_argument("-o", "--output", default=None,
                      help="Save report to file (.txt or .html)")

    # --- extract ---
    p_ex = sub.add_parser("extract", help="Extract bytes from a file")
    p_ex.add_argument("file")
    p_ex.add_argument("--offset", type=lambda x: int(x, 0), required=True)
    p_ex.add_argument("--size",   type=lambda x: int(x, 0), required=True)
    p_ex.add_argument("-o", "--output", default=None)

    # --- inject ---
    p_inj = sub.add_parser("inject", help="Inject bytes into a file")
    p_inj.add_argument("file")
    p_inj.add_argument("--offset", type=lambda x: int(x, 0), required=True)
    p_inj.add_argument("--data",   required=True, help="Hex string to inject")
    p_inj.add_argument("--backup", action="store_true",
                       help="Create .bak before modifying")

    # --- patch ---
    p_pt = sub.add_parser("patch", help="Apply or create patches")
    pt_sub = p_pt.add_subparsers(dest="patch_cmd", metavar="<apply|create>")
    pt_sub.required = True

    pt_apply = pt_sub.add_parser("apply", help="Apply a patch file")
    pt_apply.add_argument("file")
    pt_apply.add_argument("patch")
    pt_apply.add_argument("-o", "--output", default=None)

    pt_create = pt_sub.add_parser("create", help="Create a patch from two files")
    pt_create.add_argument("original")
    pt_create.add_argument("modified")
    pt_create.add_argument("--format", default="bmp",
                           choices=["ips", "ups", "bps", "bmp"],
                           help="Patch format (default: bmp)")
    pt_create.add_argument("-o", "--output", default=None)

    # --- ecu-info ---
    p_ei = sub.add_parser("ecu-info", help="Detect ECU and show VIN, SW, HW")
    p_ei.add_argument("file", help="ECU ROM binary")
    p_ei.add_argument("--json", action="store_true", help="Output as JSON")

    # --- tune ---
    p_tn = sub.add_parser("tune", help="Apply Stage 1/2/3 performance remap")
    p_tn.add_argument("file", help="ECU ROM binary")
    p_tn.add_argument("--stage", type=int, choices=[1, 2, 3], required=True,
                      help="Tuning stage (1, 2, or 3)")
    p_tn.add_argument("-o", "--output", default=None,
                      help="Output file (default: <file>.staged.bin)")
    p_tn.add_argument("--backup", action="store_true",
                      help="Create a .bak copy before writing")

    # --- pops ---
    p_pb = sub.add_parser("pops", help="Configure Pops & Bang / exhaust crackle")
    p_pb.add_argument("file", help="ECU ROM binary")
    p_pb.add_argument("--level", choices=["off", "mild", "medium", "aggressive"],
                      default="medium", help="Intensity (default: medium)")
    p_pb.add_argument("-o", "--output", default=None)
    p_pb.add_argument("--backup", action="store_true")

    # --- cancel ---
    p_ca = sub.add_parser("cancel", help="Apply ECU cancellations / deletes")
    p_ca.add_argument("file", help="ECU ROM binary")
    p_ca.add_argument("--list", action="store_true",
                      help="List available cancellations for this ECU and exit")
    p_ca.add_argument(
        "--cancels", nargs="+", default=[],
        metavar="CANCEL",
        help=(
            "One or more cancellations to apply: "
            "egr dpf lambda swirl sap vmax torque rpm adblue cat sai"
        )
    )
    p_ca.add_argument("-o", "--output", default=None)
    p_ca.add_argument("--backup", action="store_true")

    return parser


# =============================================================================
# ECU tuning commands
# =============================================================================

def cmd_ecu_info(args) -> None:
    """Detect ECU and display VIN / SW / HW information."""
    from core.ecu_info import ECUInfoExtractor
    import json

    (fp,) = _require_file(args.file)
    data  = fp.read_bytes()
    ext   = ECUInfoExtractor()
    rep   = ext.detect(data)

    if args.json:
        print(json.dumps(rep.to_dict(), indent=2))
    else:
        print(rep)


def cmd_tune(args) -> None:
    """Apply a Stage 1/2/3 remap to an ECU binary."""
    from core.tune_engine import TuneEngine
    from formats.ecu_profiles import StageLevel
    from utils.file_utils import backup_file, safe_write

    (fp,) = _require_file(args.file)
    data  = fp.read_bytes()

    stage = StageLevel(args.stage)
    eng   = TuneEngine()
    result= eng.apply_stage(data, stage)

    print(result.log)
    if result.warnings:
        for w in result.warnings:
            print(f"[WARN] {w}")

    out = Path(args.output) if args.output else fp.with_suffix(f".stage{args.stage}.bin")
    if args.backup and fp.exists():
        bak = backup_file(fp)
        print(f"Backup: '{bak}'")
    safe_write(out, result.data)
    print(f"\nGuardado: '{out}'  ({len(result.data):,} bytes)")


def cmd_pops(args) -> None:
    """Apply Pops & Bang configuration to an ECU binary."""
    from core.pops_bang import PopsBangEngine
    from formats.ecu_profiles import PopsBangLevel
    from utils.file_utils import backup_file, safe_write

    _LEVEL_MAP = {
        "off":        PopsBangLevel.OFF,
        "mild":       PopsBangLevel.MILD,
        "medium":     PopsBangLevel.MEDIUM,
        "aggressive": PopsBangLevel.AGGRESSIVE,
    }

    (fp,) = _require_file(args.file)
    data  = fp.read_bytes()
    level = _LEVEL_MAP[args.level]

    eng    = PopsBangEngine()
    result = eng.apply(data, level)

    print(result.log)
    if result.warnings:
        for w in result.warnings:
            print(f"[WARN] {w}")

    out = Path(args.output) if args.output else fp.with_suffix(".pops.bin")
    if args.backup and fp.exists():
        backup_file(fp)
    safe_write(out, result.data)
    print(f"\nGuardado: '{out}'")


def cmd_cancel(args) -> None:
    """Apply ECU cancellations / deletes."""
    from core.anulaciones import AnulacionEngine, all_cancellations_for
    from formats.ecu_profiles import Cancellation, get_profile
    from utils.file_utils import backup_file, safe_write

    _CANCEL_MAP = {
        "egr":    Cancellation.EGR,
        "dpf":    Cancellation.DPF,
        "lambda": Cancellation.LAMBDA,
        "swirl":  Cancellation.SWIRL_FLAP,
        "sap":    Cancellation.SAP,
        "vmax":   Cancellation.SPEED_LIMITER,
        "torque": Cancellation.TORQUE_LIMIT,
        "rpm":    Cancellation.RPM_LIMIT,
        "adblue": Cancellation.ADBLUE,
        "cat":    Cancellation.CAT,
        "sai":    Cancellation.SAI,
    }

    (fp,) = _require_file(args.file)
    data  = fp.read_bytes()

    if args.list:
        profile = get_profile(data)
        if profile:
            print(f"ECU: {profile.name}")
            print("Cancellaciones disponibles:")
            for c in all_cancellations_for(profile):
                spec = profile.cancellations[c]
                print(f"  {c.value:<16}  {spec.name}")
        else:
            print("ECU no reconocida. Las cancellaciones disponibles son:")
            for key in _CANCEL_MAP:
                print(f"  {key}")
        return

    cancels = []
    for key in args.cancels:
        if key not in _CANCEL_MAP:
            sys.exit(f"[ERROR] Cancellación desconocida: '{key}'. "
                     f"Válidas: {', '.join(_CANCEL_MAP)}")
        cancels.append(_CANCEL_MAP[key])

    if not cancels:
        sys.exit("[ERROR] Especifica al menos una cancellación con --cancels")

    eng    = AnulacionEngine()
    result = eng.apply(data, cancels)

    print(result.log)
    if result.warnings:
        for w in result.warnings:
            print(f"[WARN] {w}")

    out = Path(args.output) if args.output else fp.with_suffix(".cancel.bin")
    if args.backup and fp.exists():
        backup_file(fp)
    safe_write(out, result.data)
    print(f"\nGuardado: '{out}'")


# =============================================================================
# Dispatch table
# =============================================================================

_COMMANDS = {
    "gui":      cmd_gui,
    "hex":      cmd_hex,
    "info":     cmd_info,
    "checksum": cmd_checksum,
    "search":   cmd_search,
    "diff":     cmd_diff,
    "extract":  cmd_extract,
    "inject":   cmd_inject,
    "patch":    cmd_patch,
    "ecu-info": cmd_ecu_info,
    "tune":     cmd_tune,
    "pops":     cmd_pops,
    "cancel":   cmd_cancel,
}


# =============================================================================
# Main
# =============================================================================

def main() -> None:
    from utils.log_utils import BinModderLogger
    BinModderLogger.configure()

    parser = build_parser()
    args   = parser.parse_args()
    fn     = _COMMANDS.get(args.command)
    if fn:
        fn(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
