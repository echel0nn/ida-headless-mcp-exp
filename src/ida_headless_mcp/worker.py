"""IDA worker subprocess — owns one idalib instance, processes commands via stdin/stdout JSON-RPC."""
from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path
from typing import Any

__all__ = ["run_worker"]


def run_worker() -> None:
    """Main loop: read JSON-RPC from stdin, dispatch to session manager, write response to stdout."""
    # Bootstrap IDA in this process
    src_dir = Path(__file__).resolve().parent.parent
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))

    from .config import load_settings
    from .session import IDABinarySessionManager

    settings = load_settings()
    mgr = IDABinarySessionManager(settings)

    # Redirect IDA noise to stderr so stdout stays clean for JSON-RPC
    try:
        mgr._ida.enable_console_messages(False)
    except Exception:
        pass

    # Signal ready
    _send({"jsonrpc": "2.0", "method": "worker/ready", "params": {"pid": __import__("os").getpid()}})

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        msg_id = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params", {})

        try:
            result = _dispatch(mgr, method, params)
            _send({"jsonrpc": "2.0", "id": msg_id, "result": result})
        except Exception as exc:
            _send({
                "jsonrpc": "2.0", "id": msg_id,
                "error": {"code": -1, "message": f"{type(exc).__name__}: {exc}",
                          "data": traceback.format_exc()[-500:]},
            })


def _dispatch(mgr: Any, method: str, params: dict[str, Any]) -> Any:
    """Route a JSON-RPC method call to the session manager.

    Args:
        mgr: The session manager that owns the loaded binaries.
        method: JSON-RPC method name.
        params: JSON-RPC parameters.

    Returns:
        The result of the dispatched call.

    Raises:
        ValueError: If ``method`` is not in the dispatch table.
    """
    # Direct method mapping — every public method on the manager
    dispatch_table = {
        "open_binary": lambda p: _serialize_record(mgr.open_binary(p["path"])),
        "close_binary": lambda p: mgr.close_binary(p["binary_id"], save=p.get("save", False)),
        "list_binaries": lambda p: mgr.list_binaries(),
        "binary_metadata": lambda p: mgr.binary_metadata(p["binary_id"]),
        "poll_analysis": lambda p: mgr.poll_analysis(p["binary_id"]),
        "list_functions": lambda p: mgr.list_functions(
            p["binary_id"], offset=p.get("offset", 0), limit=p.get("limit", 100),
            filter_text=p.get("filter_text", ""), order_by=p.get("order_by", "name"),
            min_size_bytes=p.get("min_size_bytes", 0), min_complexity=p.get("min_complexity", 0),
            exclude_thunks=p.get("exclude_thunks", False),
            exclude_libraries=p.get("exclude_libraries", False),
        ),
        "decompile": lambda p: mgr.decompile(
            p["binary_id"], p["address_or_name"], max_lines=p.get("max_lines", 500),
        ),
        "batch_decompile": lambda p: mgr.batch_decompile(
            p["binary_id"], name_pattern=p.get("name_pattern", ""),
            callers_of=p.get("callers_of"), called_by=p.get("called_by"),
            order_by=p.get("order_by", "complexity_desc"),
            offset=p.get("offset", 0), limit=p.get("limit", 20),
            max_lines=p.get("max_lines", 250),
        ),
        "search_pattern": lambda p: mgr.search_pattern(
            p["binary_id"], p["pattern_type"],
            name_pattern=p.get("name_pattern", ""), limit=p.get("limit", 50),
        ),
        "xrefs_to": lambda p: mgr.xrefs_to(p["binary_id"], p["address_or_name"]),
        "xrefs_from": lambda p: mgr.xrefs_from(p["binary_id"], p["address_or_name"]),
        "imports": lambda p: mgr.imports(p["binary_id"]),
        "exports": lambda p: mgr.exports(p["binary_id"]),
        "segments": lambda p: mgr.segments(p["binary_id"]),
        "checksec": lambda p: mgr.checksec(p["binary_id"]),
        "stack_frame": lambda p: mgr.stack_frame(p["binary_id"], p["address_or_name"]),
        "call_graph": lambda p: mgr.call_graph(
            p["binary_id"], p["address_or_name"],
            depth=p.get("depth", 2), direction=p.get("direction", "both"),
        ),
        "diff_binary": lambda p: mgr.diff_binary(p["binary_id_old"], p["binary_id_new"]),
        "diff_function": lambda p: mgr.diff_function(
            p["binary_id_old"], p["address_or_name_old"],
            p["binary_id_new"], p["address_or_name_new"],
            max_lines=p.get("max_lines", 500),
        ),
        "diff_survey": lambda p: mgr.diff_survey(
            p["binary_id_old"], p["binary_id_new"],
            max_changed=p.get("max_changed", 20),
            include_pseudocode_diff=p.get("include_pseudocode_diff", True),
        ),
        "query_ctree": lambda p: mgr.query_ctree(
            p["binary_id"], p["address_or_name"],
            target_function=p.get("target_function", ""),
            argument_index=p.get("argument_index"),
            contains_operation=p.get("contains_operation", ""),
            operand_type_is=p.get("operand_type_is", ""),
            limit=p.get("limit", 50),
        ),
        "get_microcode": lambda p: mgr.get_microcode(
            p["binary_id"], p["address_or_name"], maturity=p.get("maturity", "current"),
        ),
        "trace_dataflow": lambda p: mgr.trace_dataflow(
            p["binary_id"], p["address_or_name"],
            sink_function=p["sink_function"],
            sink_argument_index=p["sink_argument_index"],
            source_contains=p.get("source_contains"),
            max_steps=p.get("max_steps", 10),
        ),
        "hexrays_warnings": lambda p: mgr.hexrays_warnings(p["binary_id"], p["address_or_name"]),
        "pseudocode_slice": lambda p: mgr.pseudocode_slice_fn(
            p["binary_id"], p["address_or_name"],
            focus_callee=p.get("focus_callee", ""),
            focus_address=p.get("focus_address", ""),
            context_lines=p.get("context_lines", 5),
        ),
        "def_use": lambda p: mgr.def_use(
            p["binary_id"], p["address_or_name"],
            target_callee=p.get("target_callee", ""),
            max_instructions=p.get("max_instructions", 200),
        ),
        "value_ranges": lambda p: mgr.value_ranges(p["binary_id"], p["address_or_name"]),
        "binary_survey": lambda p: mgr.binary_survey(
            p["binary_id"], max_hotspots=p.get("max_hotspots", 10),
        ),
        "classify_behavior": lambda p: mgr.classify_behavior(p["binary_id"]),
        "detect_anti_analysis": lambda p: mgr.detect_anti_analysis(p["binary_id"]),
        "entropy_analysis": lambda p: mgr.entropy_analysis(p["binary_id"]),
        "classify_strings": lambda p: mgr.classify_strings(
            p["binary_id"], limit=p.get("limit", 200),
        ),
        "path_feasibility": lambda p: mgr.path_feasibility(
            p["binary_id"], p["source_address"], p["sink_address"],
            timeout_seconds=p.get("timeout_seconds", 60),
        ),
        "find_paths": lambda p: mgr.find_paths(
            p["binary_id"], p["from_address"], p["to_address"],
            avoid_addresses=p.get("avoid_addresses"),
            timeout_seconds=p.get("timeout_seconds", 60),
            max_paths=p.get("max_paths", 3),
        ),
        "call_chain": lambda p: mgr.call_chain(
            p["binary_id"], p["target_function"],
            depth=p.get("depth", 5), direction=p.get("direction", "callers"),
        ),
        "detect_dynamic_resolution": lambda p: mgr.detect_dynamic_resolution(
            p["binary_id"], limit=p.get("limit", 50),
        ),
        "interprocedural_taint": lambda p: mgr.interprocedural_taint(
            p["binary_id"], p["sink_function"], p["sink_argument_index"],
            source_functions=p.get("source_functions"),
            max_depth=p.get("max_depth", 5),
        ),
        "constrained_reachability": lambda p: mgr.constrained_reachability(
            p["binary_id"], p["address_or_name"], p["sink_address"],
            timeout_seconds=p.get("timeout_seconds", 60),
        ),
        "prove_overflow": lambda p: mgr.prove_overflow(
            p["binary_id"], p["address_or_name"],
            sink_function=p["sink_function"],
            sink_argument_index=p["sink_argument_index"],
        ),
        "assess_exploitability": lambda p: mgr.assess_exploitability(
            p["binary_id"], p["address_or_name"],
            sink_function=p["sink_function"],
            sink_argument_index=p["sink_argument_index"],
        ),
        "ping": lambda p: {"status": "alive", "pid": __import__("os").getpid()},
        "shutdown": lambda p: _shutdown(),
    }

    if method not in dispatch_table:
        raise ValueError(f"Unknown method: {method!r}")
    return dispatch_table[method](params)


def _serialize_record(rec: Any) -> dict[str, Any]:
    return {
        "binary_id": rec.binary_id,
        "sha256": rec.sha256,
        "path": str(rec.path),
        "size_bytes": rec.size_bytes,
        "format": rec.format,
        "arch": rec.arch,
        "bits": rec.bits,
        "function_count": rec.function_count,
        "imports_count": rec.imports_count,
        "exports_count": rec.exports_count,
        "mitigations": rec.mitigations,
    }


def _send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _shutdown() -> dict:
    """Graceful shutdown."""
    import os
    os._exit(0)


if __name__ == "__main__":
    run_worker()
