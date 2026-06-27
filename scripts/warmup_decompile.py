"""Background decompile warmup -- pre-populate cache for all user functions.

Spawned by the lifecycle manager after .i64 is ready. Opens the database,
decompiles every non-library function, writes results to the cache dir.
After this script completes, every decompile MCP call is a cache hit (<1ms).

Usage:
    python warmup_decompile.py --binary-path <workspace/binary.exe> --cache-dir <cache/{sha}> --max-lines 200
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary-path", required=True)
    parser.add_argument("--cache-dir", required=True)
    parser.add_argument("--max-lines", type=int, default=200)
    args = parser.parse_args()

    binary_path = Path(args.binary_path)
    cache_dir = Path(args.cache_dir)
    decompile_dir = cache_dir / "decompile"
    decompile_dir.mkdir(parents=True, exist_ok=True)

    # Bootstrap idalib
    src_dir = Path(__file__).resolve().parents[1] / "src"
    sys.path.insert(0, str(src_dir))

    from ida_headless_mcp.bootstrap import bootstrap_ida
    from ida_headless_mcp.config import load_settings

    settings = load_settings()
    ida_mod = bootstrap_ida(settings)

    # Open the .i64
    rc = ida_mod.open_database(str(binary_path), True)
    if rc != 0:
        print(f"WARMUP_ERROR: open_database returned {rc}", file=sys.stderr)
        return 1

    import ida_funcs
    import ida_hexrays
    import ida_name

    if not ida_hexrays.init_hexrays_plugin():
        print("WARMUP_ERROR: Hex-Rays not available", file=sys.stderr)
        ida_mod.close_database(False)
        return 1

    total = ida_funcs.get_func_qty()
    decompiled = 0
    skipped = 0
    failed = 0

    for i in range(total):
        func = ida_funcs.getn_func(i)
        if func is None:
            continue

        # Skip thunks and tiny functions
        if func.flags & ida_funcs.FUNC_THUNK:
            skipped += 1
            continue
        if func.flags & ida_funcs.FUNC_LIB:
            skipped += 1
            continue

        address = f"0x{func.start_ea:x}"
        cache_file = decompile_dir / f"{address}.json"

        # Skip if already cached
        if cache_file.exists():
            decompiled += 1
            continue

        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
            pseudocode = str(cfunc)
            lines = pseudocode.splitlines()
            truncated = len(lines) > args.max_lines
            if truncated:
                lines = lines[:args.max_lines]

            result = {
                "binary_id": "",  # filled by session manager on read
                "address": address,
                "name": ida_name.get_ea_name(func.start_ea),
                "size_bytes": func.size(),
                "pseudocode": "\n".join(lines),
                "line_count": len(lines),
                "truncated": truncated,
                "cache_hit": False,
            }
            cache_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
            decompiled += 1
        except Exception:
            failed += 1

    ida_mod.close_database(True)

    # Write completion marker
    marker = cache_dir / "warmup_complete.json"
    marker.write_text(json.dumps({
        "total": total,
        "decompiled": decompiled,
        "skipped": skipped,
        "failed": failed,
    }), encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
