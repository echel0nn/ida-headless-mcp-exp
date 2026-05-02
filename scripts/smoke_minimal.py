from __future__ import annotations

import argparse
import json
from pathlib import Path

from ida_headless_mcp.config import load_settings
from ida_headless_mcp.session import IDABinarySessionManager

DEFAULT_BINARY = None


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke-test minimal IDA MCP implementation")
    parser.add_argument("--binary", type=Path, required=True, help="Path to a local test binary (not committed)")
    args = parser.parse_args()

    settings = load_settings()
    mgr = IDABinarySessionManager(settings)

    rec = mgr.open_binary(str(args.binary.resolve()))
    funcs = mgr.list_functions(
        rec.binary_id,
        limit=5,
        order_by="complexity_desc",
        min_complexity=2,
        exclude_thunks=True,
    )
    first_target = funcs["functions"][0]["address"] if funcs["functions"] else None
    if first_target is None:
        raise RuntimeError("No functions found in test binary")
    payload = {
        "metadata": mgr.binary_metadata(rec.binary_id),
        "functions": funcs,
        "decompile": mgr.decompile(rec.binary_id, first_target, max_lines=30),
        "batch_decompile": mgr.batch_decompile(
            rec.binary_id,
            min_complexity=5,
            exclude_thunks=True,
            limit=3,
            max_lines=40,
        ),
        "dangerous_function_matches": mgr.search_pattern(
            rec.binary_id,
            "dangerous_function",
            limit=5,
            max_lines=40,
        ),
        "imports": mgr.imports(rec.binary_id),
        "segments": mgr.segments(rec.binary_id),
        "checksec": mgr.checksec(rec.binary_id),
        "stack_frame": mgr.stack_frame(rec.binary_id, first_target),
        "call_graph": mgr.call_graph(rec.binary_id, first_target, depth=1),
    }
    print(json.dumps(payload, indent=2))
    mgr.close_binary(rec.binary_id, save=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
