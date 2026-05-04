"""Background decompile worker — runs in a separate process, NOT subject to MCP timeout.

Watches a request queue file for decompile requests, processes them one at a time,
writes results to the cache directory. The MCP server only reads from cache.

Usage:
    python -m ida_headless_mcp.decompile_worker --workspace <path/binary.exe> --cache-dir <cache/{sha}>
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

__all__: list[str] = []

QUEUE_FILENAME = "decompile_queue.jsonl"
POLL_INTERVAL = 0.3


def run(workspace_binary: Path, cache_dir: Path, max_lines: int = 200) -> None:
    """Main loop: watch queue, decompile, write cache."""
    # Bootstrap IDA
    src_dir = Path(__file__).resolve().parent.parent
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))

    from ida_headless_mcp.bootstrap import bootstrap_ida
    from ida_headless_mcp.config import load_settings

    settings = load_settings()
    ida_mod = bootstrap_ida(settings)

    try:
        ida_mod.enable_console_messages(False)
    except Exception:
        pass

    # Clean stale locks
    for ext in ('.id0', '.id1', '.id2', '.nam', '.til'):
        stale = workspace_binary.parent / (workspace_binary.name + ext)
        if stale.exists():
            try:
                stale.unlink()
            except OSError:
                pass

    rc = ida_mod.open_database(str(workspace_binary), True)
    if rc != 0:
        sys.exit(1)

    import ida_funcs
    import ida_hexrays
    import ida_name

    if not ida_hexrays.init_hexrays_plugin():
        ida_mod.close_database(False)
        sys.exit(1)

    decompile_dir = cache_dir / "decompile"
    decompile_dir.mkdir(parents=True, exist_ok=True)
    queue_path = cache_dir / QUEUE_FILENAME

    # Process loop
    while True:
        if not queue_path.exists():
            time.sleep(POLL_INTERVAL)
            continue

        # Read and consume queue atomically
        try:
            lines = queue_path.read_text(encoding="utf-8").strip().splitlines()
            queue_path.write_text("", encoding="utf-8")  # clear
        except OSError:
            time.sleep(POLL_INTERVAL)
            continue

        if not lines:
            time.sleep(POLL_INTERVAL)
            continue

        for line in lines:
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                continue

            address = req.get("address", "").strip()
            if not address:
                continue

            cache_file = decompile_dir / f"{address}.json"
            if cache_file.exists():
                continue  # already cached

            # Resolve address
            try:
                if address.startswith(("0x", "0X")):
                    ea = int(address, 16)
                else:
                    ea = int(address)
            except ValueError:
                # Try as name
                import ida_idaapi
                ea_resolved = ida_name.get_name_ea(ida_idaapi.BADADDR, address)
                if ea_resolved == ida_idaapi.BADADDR:
                    continue
                ea = ea_resolved

            func = ida_funcs.get_func(ea)
            if func is None:
                continue

            try:
                cfunc = ida_hexrays.decompile(func.start_ea)
                pseudocode = str(cfunc)
                plines = pseudocode.splitlines()
                truncated = len(plines) > max_lines
                if truncated:
                    plines = plines[:max_lines]

                result = {
                    "binary_id": "",
                    "address": f"0x{func.start_ea:x}",
                    "name": ida_name.get_ea_name(func.start_ea),
                    "size_bytes": func.size(),
                    "pseudocode": "\n".join(plines),
                    "line_count": len(plines),
                    "truncated": truncated,
                    "cache_hit": False,
                }
                cache_file.write_text(
                    json.dumps(result, indent=2), encoding="utf-8",
                )
            except Exception:
                pass


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--cache-dir", required=True)
    parser.add_argument("--max-lines", type=int, default=200)
    args = parser.parse_args()
    run(Path(args.workspace), Path(args.cache_dir), args.max_lines)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
