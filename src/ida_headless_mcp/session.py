from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .bootstrap import bootstrap_ida
from .config import Settings
from .diff import diff_binary_indexes, diff_function_payloads
from .function_index import FunctionIndex, build_function_index
from .guards import requires
from .hexrays_analysis import (
    decompile_cfunc,
    get_argument_names,
    get_hexrays_warnings,
    get_microcode_text,
    microcode_def_use,
    microcode_value_ranges,
    pseudocode_slice,
    query_ctree_call_sequences,
    query_ctree_calls,
    query_ctree_unchecked_calls,
    trace_ctree_dataflow,
)
from .lifecycle import BinaryState, LifecycleManager

__all__ = ["BinaryRecord", "IDABinarySessionManager"]


@dataclass(slots=True)
class BinaryRecord:
    binary_id: str
    path: Path
    sha256: str
    size_bytes: int
    format: str
    arch: str
    bits: int
    entry_points: list[str]
    function_count: int
    segment_count: int
    imports_count: int
    exports_count: int
    strings_count: int
    mitigations: dict[str, Any]
    sections: list[dict[str, Any]]
    active: bool = False
    root_filename: str = ""
    analysis_ready: bool = True


@dataclass(slots=True)
class _CacheEntry:
    address: str
    name: str
    pseudocode: str
    line_count: int
    size: int
    truncated: bool


class IDABinarySessionManager:
    """Logical multi-binary manager over a single-threaded idalib backend.

    IDA 9.0 idalib can have only one database open in the current process at a
    time. We emulate multi-binary sessions by keeping a registry of known
    binaries and reopening the requested binary on demand. The current active
    binary remains hot until another binary is requested.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._ida = bootstrap_ida(settings)
        try:
            self._ida.enable_console_messages(False)
        except Exception:
            pass
        self._records: dict[str, BinaryRecord] = {}
        self._active_binary_id: str | None = None
        self._indices: dict[str, FunctionIndex] = {}
        self._manifest_path = self.settings.cache_dir / "manifest.json"
        self._lifecycle = LifecycleManager(settings.cache_dir, settings.ida_dir)
        # Recover any binaries from prior sessions instantly
        for lc in self._lifecycle.recover_all():
            if lc.binary_id not in self._records:
                self._records[lc.binary_id] = self._record_from_lifecycle(lc)

    def open_binary(self, path: str) -> BinaryRecord:
        """Register a binary for analysis. Returns INSTANTLY (<100ms).

        The actual IDA analysis runs in background via idat64 -B.
        Tools that need IDA (decompile, search_pattern) will block on
        first call until the .i64 is ready (0.65s warm, 25-60s cold).
        Tools that don't need IDA (checksec, entropy) work immediately.
        """
        target = Path(path).resolve()
        if not target.is_file():
            raise FileNotFoundError(f"Binary not found: {target}")
        max_bytes = self.settings.max_binary_size_mb * 1024 * 1024
        size_bytes = target.stat().st_size
        if size_bytes > max_bytes:
            raise ValueError(
                f"Binary too large: {size_bytes} bytes exceeds {self.settings.max_binary_size_mb} MB soft limit"
            )

        sha256 = _sha256_file(target)
        binary_id = f"b_{sha256[:12]}"
        if binary_id in self._records:
            return self._records[binary_id]

        # Register + spawn background analysis (instant)
        lc = self._lifecycle.register(binary_id, sha256, target, size_bytes)
        record = self._record_from_lifecycle(lc)
        self._records[binary_id] = record
        return record

    def _record_from_lifecycle(self, lc: Any) -> BinaryRecord:
        """Build a BinaryRecord from lifecycle state + PE header."""
        target = Path(lc.original_path)
        is_pe = target.suffix.lower() in {'.exe', '.dll', '.sys'}
        mitigations = _pe_mitigations(target) if is_pe and target.exists() else {'type': 'unknown'}
        return BinaryRecord(
            binary_id=lc.binary_id,
            path=target,
            sha256=lc.sha256,
            size_bytes=lc.size_bytes,
            format=('Portable executable for AMD64 (PE)' if is_pe else 'unknown'),
            arch='metapc',
            bits=64,
            entry_points=[],
            function_count=lc.function_count,
            segment_count=0,
            imports_count=0,
            exports_count=0,
            strings_count=0,
            mitigations=mitigations,
            sections=[],
            active=lc.state >= BinaryState.ACTIVE,
            root_filename=lc.root_filename,
            analysis_ready=lc.state >= BinaryState.ACTIVE,
        )

    def close_binary(self, binary_id: str, save: bool = False) -> dict[str, Any]:
        if self._active_binary_id == binary_id:
            # Always save the .i64 so warm reopens work (0.5s vs 17s).
            # The `save` param controls whether user annotations persist.
            self._ida.close_database(True)
            self._active_binary_id = None
        del self._records[binary_id]
        self._indices.pop(binary_id, None)
        return {"binary_id": binary_id, "closed": True}

    def list_binaries(self) -> list[dict[str, Any]]:
        result = []
        for rec in self._records.values():
            lc = self._lifecycle.get(rec.binary_id)
            state = lc.state.name if lc else 'UNKNOWN'
            result.append({
                'binary_id': rec.binary_id,
                'path': str(rec.path),
                'format': rec.format,
                'size_bytes': rec.size_bytes,
                'state': state,
                'analysis_ready': rec.analysis_ready,
                'function_count': rec.function_count,
            })
        return result

    def binary_metadata(self, binary_id: str) -> dict[str, Any]:
        rec = self._require(binary_id)
        lc = self._lifecycle.get(binary_id)
        state = lc.state.name if lc else 'UNKNOWN'
        return {
            'binary_id': rec.binary_id,
            'path': str(rec.path),
            'sha256': rec.sha256,
            'size_bytes': rec.size_bytes,
            'format': rec.format,
            'arch': rec.arch,
            'bits': rec.bits,
            'root_filename': rec.root_filename,
            'state': state,
            'analysis_ready': rec.analysis_ready,
            'function_count': rec.function_count,
            'segment_count': rec.segment_count,
            'imports_count': rec.imports_count,
            'exports_count': rec.exports_count,
            'strings_count': rec.strings_count,
            'mitigations': rec.mitigations,
            'active': rec.binary_id == self._active_binary_id,
        }

    def poll_analysis(self, binary_id: str) -> dict[str, Any]:
        """Check analysis progress.

        Returns:
            Current lifecycle state. One of:

            * ``REGISTERED`` — binary known, background analysis not yet started
            * ``ANALYZING`` — idat64 -B running in background (wait)
            * ``READY`` — .i64 exists, IDA can open in <1s
            * ``ACTIVE`` — idalib has database loaded
            * ``INDEXED`` — function index built, all tools available
        """
        lc = self._lifecycle.get(binary_id)
        if lc is None:
            raise KeyError(f'Unknown binary_id: {binary_id}')
        # Reconcile with filesystem reality
        old_state = lc.state
        self._lifecycle.poll_analysis(binary_id)
        return {
            'binary_id': binary_id,
            'state': lc.state.name,
            'previous_state': old_state.name,
            'analysis_ready': lc.state >= BinaryState.READY,
            'ida_active': lc.state >= BinaryState.ACTIVE,
            'index_ready': lc.state >= BinaryState.INDEXED,
            'function_count': lc.function_count,
            'error': lc.error,
        }

    @requires(BinaryState.INDEXED)
    def list_functions(
        self,
        binary_id: str,
        offset: int = 0,
        limit: int = 100,
        filter_text: str = "",
        order_by: str = "name",
        min_size_bytes: int = 0,
        min_complexity: int = 0,
        exclude_thunks: bool = False,
        exclude_libraries: bool = False,
    ) -> dict[str, Any]:
        self._activate(binary_id)
        self._ensure_indexed(binary_id)
        index = self._indices[binary_id]
        result = index.query(
            name_pattern=filter_text,
            min_size_bytes=min_size_bytes,
            min_complexity=min_complexity,
            exclude_thunks=exclude_thunks,
            exclude_libraries=exclude_libraries,
            order_by=order_by,
            offset=offset,
            limit=limit,
        )

        return result

    def decompile(self, binary_id: str, address_or_name: str, max_lines: int = 500) -> dict[str, Any]:
        """Decompile a function. Returns cached result or queues for background decompilation.

        NEVER blocks on Hex-Rays. If the result isn't cached, it queues the
        request to the background decompile worker and returns status=pending.
        The consumer retries until the result appears in cache.
        """
        rec = self._require(binary_id)
        cache_file = self._cache_file(rec.sha256, address_or_name)
        if cache_file.exists():
            cached = json.loads(cache_file.read_text(encoding="utf-8"))
            cached["cache_hit"] = True
            cached["binary_id"] = binary_id
            cached["status"] = "ready"
            return cached

        # Not cached — queue for background decompilation
        self._queue_decompile(rec.sha256, address_or_name)
        return {
            "binary_id": binary_id,
            "address": address_or_name,
            "status": "pending",
            "message": "Decompilation queued. Retry this call — result will appear in cache.",
        }

    def _decompile_sync(self, binary_id: str, address_or_name: str, max_lines: int = 500) -> dict[str, Any]:
        """Synchronous decompile — used internally by tools that run in-process (search_pattern etc)."""
        rec = self._require(binary_id)
        cache_file = self._cache_file(rec.sha256, address_or_name)
        if cache_file.exists():
            cached = json.loads(cache_file.read_text(encoding="utf-8"))
            cached["cache_hit"] = True
            return cached

        self._activate(binary_id)
        import ida_funcs
        import ida_hexrays
        import ida_name

        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays decompiler not available")

        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")

        cfunc = ida_hexrays.decompile(func.start_ea)
        pseudocode = str(cfunc)
        lines = pseudocode.splitlines()
        truncated = len(lines) > max_lines
        if truncated:
            lines = lines[:max_lines]

        result = {
            "binary_id": binary_id,
            "address": f"0x{func.start_ea:x}",
            "name": ida_name.get_ea_name(func.start_ea),
            "size_bytes": func.size(),
            "pseudocode": "\n".join(lines),
            "line_count": len(lines),
            "truncated": truncated,
            "cache_hit": False,
            "status": "ready",
        }
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result

    def _queue_decompile(self, sha256: str, address_or_name: str) -> None:
        """Append a decompile request to the background worker queue."""
        queue_path = self.settings.cache_dir / sha256 / "decompile_queue.jsonl"
        queue_path.parent.mkdir(parents=True, exist_ok=True)
        entry = json.dumps({"address": address_or_name})
        with queue_path.open("a", encoding="utf-8") as fh:
            fh.write(entry + "\n")

    @requires(BinaryState.ACTIVE)
    def xrefs_to(self, binary_id: str, address_or_name: str) -> dict[str, Any]:
        import ida_funcs
        import idautils

        ea = _resolve_address(address_or_name)
        refs: list[dict[str, Any]] = []
        for xref in idautils.XrefsTo(ea):
            func = ida_funcs.get_func(xref.frm)
            refs.append(
                {
                    "from_address": f"0x{xref.frm:x}",
                    "from_function": ida_funcs.get_func_name(func.start_ea) if func else None,
                    "type": _xref_type_name(xref.type),
                }
            )
        return {"binary_id": binary_id, "address": f"0x{ea:x}", "total": len(refs), "xrefs": refs}

    @requires(BinaryState.ACTIVE)
    def xrefs_from(self, binary_id: str, address_or_name: str) -> dict[str, Any]:
        import ida_funcs
        import idautils

        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")
        refs: list[dict[str, Any]] = []
        seen: set[int] = set()
        for head in idautils.FuncItems(func.start_ea):
            for xref in idautils.XrefsFrom(head, 0):
                if xref.to in seen:
                    continue
                seen.add(xref.to)
                callee = ida_funcs.get_func(xref.to)
                refs.append(
                    {
                        "to_address": f"0x{xref.to:x}",
                        "to_function": ida_funcs.get_func_name(callee.start_ea) if callee else None,
                        "type": _xref_type_name(xref.type),
                    }
                )
        return {
            "binary_id": binary_id,
            "address": f"0x{func.start_ea:x}",
            "name": ida_funcs.get_func_name(func.start_ea),
            "xrefs": refs,
        }

    @requires(BinaryState.ACTIVE)
    def imports(self, binary_id: str) -> dict[str, Any]:
        import ida_nalt

        results: list[dict[str, Any]] = []

        for i in range(ida_nalt.get_import_module_qty()):
            module_name = ida_nalt.get_import_module_name(i)

            def _cb(ea: int, name: str | None, ordinal: int) -> bool:
                results.append(
                    {
                        "address": f"0x{ea:x}",
                        "name": name or f"ordinal_{ordinal}",
                        "ordinal": ordinal,
                        "library": module_name,
                    }
                )
                return True

            ida_nalt.enum_import_names(i, _cb)
        return {"binary_id": binary_id, "total": len(results), "imports": results}

    @requires(BinaryState.ACTIVE)
    def exports(self, binary_id: str) -> dict[str, Any]:
        import idautils

        results = [
            {
                "address": f"0x{ea:x}",
                "name": name,
                "ordinal": ordn,
            }
            for _idx, ordn, ea, name in idautils.Entries()
        ]
        return {"binary_id": binary_id, "total": len(results), "exports": results}

    @requires(BinaryState.ACTIVE)
    def segments(self, binary_id: str) -> dict[str, Any]:
        rec = self._require(binary_id)
        return {"binary_id": binary_id, "total": len(rec.sections), "segments": rec.sections}

    @requires(BinaryState.ACTIVE)
    def checksec(self, binary_id: str) -> dict[str, Any]:
        rec = self._require(binary_id)
        return {"binary_id": binary_id, **rec.mitigations}

    @requires(BinaryState.ACTIVE)
    def stack_frame(self, binary_id: str, address_or_name: str) -> dict[str, Any]:
        import ida_funcs
        import idc

        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")
        start_ea = func.start_ea
        return {
            "binary_id": binary_id,
            "address": f"0x{start_ea:x}",
            "name": ida_funcs.get_func_name(start_ea),
            "frame_size": idc.get_frame_size(start_ea),
            "lvars_size": idc.get_frame_lvar_size(start_ea),
            "regs_size": idc.get_frame_regs_size(start_ea),
            "args_size": idc.get_frame_args_size(start_ea),
        }

    @requires(BinaryState.ACTIVE)
    def call_graph(
        self,
        binary_id: str,
        address_or_name: str,
        depth: int = 2,
        direction: str = "both",
    ) -> dict[str, Any]:
        import ida_funcs
        import idautils

        ea = _resolve_address(address_or_name)
        root_func = ida_funcs.get_func(ea)
        if root_func is None:
            raise ValueError(f"No function at {address_or_name!r}")

        nodes: dict[int, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []

        def add_node(func_ea: int) -> None:
            if func_ea in nodes:
                return
            f = ida_funcs.get_func(func_ea)
            if f is None:
                return
            nodes[func_ea] = {
                "address": f"0x{f.start_ea:x}",
                "name": ida_funcs.get_func_name(f.start_ea),
                "size_bytes": f.size(),
            }

        def walk_callees(func_ea: int, current_depth: int) -> None:
            add_node(func_ea)
            if current_depth >= depth:
                return
            f = ida_funcs.get_func(func_ea)
            if f is None:
                return
            for head in idautils.FuncItems(f.start_ea):
                for callee_ea in idautils.CodeRefsFrom(head, 0):
                    callee = ida_funcs.get_func(callee_ea)
                    if callee and callee.start_ea != f.start_ea:
                        add_node(callee.start_ea)
                        edges.append({
                            "from": f"0x{f.start_ea:x}",
                            "to": f"0x{callee.start_ea:x}",
                            "direction": "callee",
                        })
                        walk_callees(callee.start_ea, current_depth + 1)

        def walk_callers(func_ea: int, current_depth: int) -> None:
            add_node(func_ea)
            if current_depth >= depth:
                return
            for caller_ref in idautils.CodeRefsTo(func_ea, 0):
                caller = ida_funcs.get_func(caller_ref)
                if caller and caller.start_ea != func_ea:
                    add_node(caller.start_ea)
                    edges.append({
                        "from": f"0x{caller.start_ea:x}",
                        "to": f"0x{func_ea:x}",
                        "direction": "caller",
                    })
                    walk_callers(caller.start_ea, current_depth + 1)

        if direction in ("callees", "both"):
            walk_callees(root_func.start_ea, 0)
        if direction in ("callers", "both"):
            walk_callers(root_func.start_ea, 0)

        dedup_edges = []
        seen_edges: set[tuple[str, str, str]] = set()
        for edge in edges:
            key = (edge["from"], edge["to"], edge["direction"])
            if key in seen_edges:
                continue
            seen_edges.add(key)
            dedup_edges.append(edge)

        return {
            "binary_id": binary_id,
            "root": f"0x{root_func.start_ea:x}",
            "direction": direction,
            "depth": depth,
            "nodes": list(nodes.values()),
            "edges": dedup_edges,
        }

    @requires(BinaryState.INDEXED)
    def batch_decompile(
        self,
        binary_id: str,
        *,
        name_pattern: str = "",
        callers_of: list[str] | None = None,
        called_by: list[str] | None = None,
        min_size_bytes: int = 0,
        max_size_bytes: int | None = None,
        min_complexity: int = 0,
        max_complexity: int | None = None,
        has_string_ref_matching: str = "",
        exclude_thunks: bool = True,
        exclude_libraries: bool = True,
        order_by: str = "complexity_desc",
        offset: int = 0,
        limit: int = 20,
        max_lines: int = 250,
    ) -> dict[str, Any]:
        result = self._indices[binary_id].query(
            name_pattern=name_pattern,
            callers_of=callers_of,
            called_by=called_by,
            min_size_bytes=min_size_bytes,
            max_size_bytes=max_size_bytes,
            min_complexity=min_complexity,
            max_complexity=max_complexity,
            has_string_ref_matching=has_string_ref_matching,
            exclude_thunks=exclude_thunks,
            exclude_libraries=exclude_libraries,
            order_by=order_by,
            offset=offset,
            limit=limit,
        )
        decompiled = [
            self._decompile_sync(binary_id, item["address"], max_lines=max_lines)
            for item in result["functions"]
        ]
        payload = {
            "binary_id": binary_id,
            "matched_total": result["total"],
            "returned": len(decompiled),
            "dropped": max(0, result["total"] - offset - len(decompiled)),
            "drop_reason": "max_results" if result["total"] > offset + len(decompiled) else None,
            "results": decompiled,
        }

        return payload

    @requires(BinaryState.INDEXED)
    def search_pattern(
        self,
        binary_id: str,
        pattern_type: str,
        *,
        name_pattern: str = "",
        limit: int = 50,
        max_lines: int = 120,
    ) -> dict[str, Any]:
        rec = self._require(binary_id)
        pattern = pattern_type.strip().lower()

        # Pattern result cache: full results for unfiltered scans
        if not name_pattern:
            cache_path = self._pattern_cache_path(rec.sha256, pattern)
            if cache_path.exists():
                return json.loads(cache_path.read_text(encoding='utf-8'))
        query = self._indices[binary_id].query(
            name_pattern=name_pattern,
            exclude_thunks=True,
            order_by="complexity_desc",
            offset=0,
            limit=max(200, limit * 4),
        )
        candidates = query["functions"]
        matches: list[dict[str, Any]] = []
        dangerous_names = {
            "memcpy", "memmove", "strcpy", "sprintf", "gets", "strcat",
            "system", "popen", "execve", "execl", "execlp", "execvp", "winexec",
        }
        print_like = {"printf", "fprintf", "sprintf", "snprintf", "syslog", "vsnprintf"}
        cmd_like = {"system", "popen", "winexec", "execl", "execlp", "execve", "execvp"}
        check_then_use_first = {"_access", "access", "stat", "lstat", "_stat", "_stat64", "pathfileexists"}
        check_then_use_second = {"fopen", "open", "_open", "createfilea", "createfilew", "_wfopen", "fopen_s"}
        free_like = {"free", "_free", "globalfree", "localfree", "heapfree", "virtualfree"}
        use_sinks = {"printf", "fprintf", "memcpy", "memmove", "strcpy", "strlen", "strcmp", "puts", "fputs", "fwrite"}
        alloc_like = {
            "malloc", "calloc", "realloc", "_malloc", "_calloc", "_realloc",
            "globalalloc", "localalloc", "heapalloc", "virtualalloc",
        }

        for item in candidates:
            if len(matches) >= limit:
                break
            raw_callees = {c.lower() for c in item.get("callees", [])}
            callees = set(raw_callees) | {c[2:] for c in raw_callees if c.startswith("j_")}
            decomp: dict[str, Any] | None = None
            match_detail: str | None = None

            if pattern == "dangerous_function":
                hit = sorted(callees & dangerous_names)
                if hit:
                    match_detail = f"dangerous callees: {', '.join(hit)}"

            elif pattern == "format_string":
                hit = sorted(callees & print_like)
                if hit:
                    import ida_funcs

                    ea = _resolve_address(item["address"])
                    func = ida_funcs.get_func(ea)
                    if func is None:
                        continue
                    cfunc = decompile_cfunc(func)
                    sink_name = hit[0]
                    sink = query_ctree_calls(
                        cfunc,
                        target_function=sink_name,
                        argument_index=0,
                        limit=3,
                    )
                    decomp = self._decompile_sync(binary_id, item["address"], max_lines=max_lines)
                    if sink["returned"] > 0 and sink["matches"]:
                        first = sink["matches"][0]
                        arg_preview = first["args_preview"][0] if first["arg_count"] > 0 else "<arg>"
                        first_literal = (
                            bool(first["args_string_literal"][0]) if first["arg_count"] > 0 else False
                        ) or arg_preview.startswith('"')
                        if not first_literal:
                            match_detail = f"non-literal format argument {arg_preview!r} reaches {sink_name}"

            elif pattern == "command_injection":
                hit = sorted(callees & cmd_like)
                if hit:
                    import ida_funcs

                    ea = _resolve_address(item["address"])
                    func = ida_funcs.get_func(ea)
                    if func is None:
                        continue
                    cfunc = decompile_cfunc(func)
                    sink_name = hit[0]
                    sink = query_ctree_calls(
                        cfunc,
                        target_function=sink_name,
                        argument_index=0,
                        limit=3,
                    )
                    decomp = self._decompile_sync(binary_id, item["address"], max_lines=max_lines)
                    if sink["returned"] > 0 and sink["matches"]:
                        first = sink["matches"][0]
                        arg_preview = first["args_preview"][0] if first["arg_count"] > 0 else "<arg>"
                        first_literal = (
                            bool(first["args_string_literal"][0]) if first["arg_count"] > 0 else False
                        ) or arg_preview.startswith('"')
                        if not first_literal:
                            match_detail = f"non-literal command argument {arg_preview!r} reaches {sink_name}"

            elif pattern == "unchecked_length":
                hit = sorted(callees & dangerous_names)
                if hit:
                    import ida_funcs

                    ea = _resolve_address(item["address"])
                    func = ida_funcs.get_func(ea)
                    if func is None:
                        continue
                    cfunc = decompile_cfunc(func)
                    arg_names = get_argument_names(cfunc)
                    source_terms = arg_names[:2] if arg_names else []
                    sink_name = hit[0]
                    flow = trace_ctree_dataflow(
                        cfunc,
                        sink_function=sink_name,
                        sink_argument_index=2,
                        source_contains=source_terms,
                    )
                    sink = query_ctree_calls(
                        cfunc,
                        target_function=sink_name,
                        argument_index=2,
                        limit=1,
                    )
                    decomp = self._decompile_sync(binary_id, item["address"], max_lines=max_lines)
                    pseudo = decomp["pseudocode"]
                    pseudo_lower = pseudo.lower()
                    sink_line_index = next(
                        (i for i, line in enumerate(pseudo_lower.splitlines()) if sink_name.lower() + "(" in line),
                        -1,
                    )
                    guarded_textually = False
                    if sink_line_index >= 0:
                        lines = pseudo_lower.splitlines()
                        window = lines[max(0, sink_line_index - 3):sink_line_index]
                        guarded_textually = any("if (" in line or "if(" in line for line in window)
                    guarded_by_if = bool(sink["matches"] and sink["matches"][0].get("guarded_by_if"))
                    has_validation = any(
                        t in pseudo_lower for t in ("validate", "bounds", "check", "maximum", "max_")
                    ) or guarded_by_if or guarded_textually
                    if (flow["source_hit"] or flow["chain"]) and not has_validation:
                        chain_len = len(flow["chain"])
                        source = flow["source_term"] or "upstream expression"
                        match_detail = (
                            f"size sink traces back to {source} with {chain_len} "
                            "assignment hop(s) and no obvious validation"
                        )

            elif pattern == "signed_size":
                hit = sorted(callees & dangerous_names)
                if hit:
                    import ida_funcs

                    ea = _resolve_address(item["address"])
                    func = ida_funcs.get_func(ea)
                    if func is None:
                        continue
                    cfunc = decompile_cfunc(func)
                    sink_name = hit[0]
                    sink = query_ctree_calls(
                        cfunc,
                        target_function=sink_name,
                        argument_index=2,
                        operand_type_is="signed",
                        limit=3,
                    )
                    decomp = self._decompile_sync(binary_id, item["address"], max_lines=max_lines)
                    pseudo_lower = decomp["pseudocode"].lower()
                    has_validation = any(
                        t in pseudo_lower for t in ("validate", "bounds", "check", "maximum", "max_", ">= 0", "< 0")
                    )
                    if sink["returned"] > 0 and not has_validation:
                        signed_arg = sink["matches"][0]["args_preview"][2] if sink["matches"] else "<arg>"
                        match_detail = (
                            f"dangerous sink {sink_name} receives signed size expression "
                            f"{signed_arg!r} with no obvious validation"
                        )

            elif pattern == "toctou":
                check_hit = sorted(callees & check_then_use_first)
                use_hit = sorted(callees & check_then_use_second)
                if check_hit and use_hit:
                    import ida_funcs

                    ea = _resolve_address(item["address"])
                    func = ida_funcs.get_func(ea)
                    if func is None:
                        continue
                    cfunc = decompile_cfunc(func)
                    seq = query_ctree_call_sequences(
                        cfunc,
                        first_functions=check_then_use_first,
                        second_functions=check_then_use_second,
                        limit=3,
                    )
                    decomp = self._decompile_sync(binary_id, item["address"], max_lines=max_lines)
                    if seq["pairs_found"] > 0:
                        pair = seq["pairs"][0]
                        match_detail = (
                            f"TOCTOU: {pair['first_callee']}() then {pair['second_callee']}() "
                            f"in same function (check-then-use race window)"
                        )

            elif pattern == "double_free":
                free_hit = sorted(callees & free_like)
                if free_hit:
                    import ida_funcs

                    ea = _resolve_address(item["address"])
                    func = ida_funcs.get_func(ea)
                    if func is None:
                        continue
                    cfunc = decompile_cfunc(func)
                    seq = query_ctree_call_sequences(
                        cfunc,
                        first_functions=free_like,
                        second_functions=free_like,
                        shared_argument_index=0,
                        limit=3,
                    )
                    decomp = self._decompile_sync(binary_id, item["address"], max_lines=max_lines)
                    if seq["pairs_found"] > 0:
                        pair = seq["pairs"][0]
                        match_detail = (
                            f"double free: {pair['first_callee']}() then {pair['second_callee']}() "
                            f"on same pointer {pair['shared_arg']!r}"
                        )

            elif pattern == "use_after_free":
                free_hit = sorted(callees & free_like)
                use_sink_hit = sorted(callees & use_sinks)
                if free_hit and use_sink_hit:
                    import ida_funcs

                    ea = _resolve_address(item["address"])
                    func = ida_funcs.get_func(ea)
                    if func is None:
                        continue
                    cfunc = decompile_cfunc(func)
                    seq = query_ctree_call_sequences(
                        cfunc,
                        first_functions=free_like,
                        second_functions=use_sinks,
                        limit=3,
                    )
                    decomp = self._decompile_sync(binary_id, item["address"], max_lines=max_lines)
                    if seq["pairs_found"] > 0:
                        pair = seq["pairs"][0]
                        match_detail = (
                            f"use-after-free: {pair['first_callee']}() frees then "
                            f"{pair['second_callee']}() uses in same function"
                        )

            elif pattern == "null_deref":
                alloc_hit = sorted(callees & alloc_like)
                if alloc_hit:
                    import ida_funcs

                    ea = _resolve_address(item["address"])
                    func = ida_funcs.get_func(ea)
                    if func is None:
                        continue
                    cfunc = decompile_cfunc(func)
                    unchecked = query_ctree_unchecked_calls(
                        cfunc,
                        target_functions=alloc_like,
                        limit=3,
                    )
                    decomp = self._decompile_sync(binary_id, item["address"], max_lines=max_lines)
                    if unchecked["returned"] > 0:
                        first = unchecked["matches"][0]
                        match_detail = (
                            f"unchecked allocation: {first['callee']}() result stored in "
                            f"{first['variable']!r} with no NULL guard"
                        )

            elif pattern == "integer_overflow":
                alloc_hit = sorted(callees & alloc_like)
                if alloc_hit:
                    import ida_funcs

                    ea = _resolve_address(item["address"])
                    func = ida_funcs.get_func(ea)
                    if func is None:
                        continue
                    cfunc = decompile_cfunc(func)
                    sink_name = alloc_hit[0]
                    sink = query_ctree_calls(
                        cfunc,
                        target_function=sink_name,
                        argument_index=0,
                        contains_operation="mul",
                        limit=3,
                    )
                    decomp = self._decompile_sync(binary_id, item["address"], max_lines=max_lines)
                    if sink["returned"] > 0:
                        first = sink["matches"][0]
                        mul_expr = first["args_preview"][0] if first["arg_count"] > 0 else "<expr>"
                        pseudo_lower = decomp["pseudocode"].lower()
                        has_overflow_check = any(
                            t in pseudo_lower for t in (
                                "overflow", "/ item_size", "/ count", "0xffffffff /",
                                "0xffff /", "size_max", "__builtin_mul_overflow",
                            )
                        )
                        if not has_overflow_check:
                            match_detail = (
                                f"integer overflow: allocation size {mul_expr!r} contains "
                                f"unchecked multiplication before {sink_name}()"
                            )

            else:
                raise ValueError(f"Unknown pattern_type: {pattern_type!r}")

            if match_detail is None:
                continue
            if decomp is None:
                decomp = self._decompile_sync(binary_id, item["address"], max_lines=max_lines)

            # Verification enrichment: assess exploitability
            verification = self._verify_pattern_hit(
                binary_id, item, pattern, match_detail,
            )

            matches.append({
                "address": item["address"],
                "name": item["name"],
                "detail": match_detail,
                "callees": item.get("callees", []),
                "string_refs": item.get("string_refs", [])[:10],
                "decompile_preview": decomp["pseudocode"],
                "trace_dataflow": flow if pattern == "unchecked_length" else None,
                **verification,
            })

        payload = {
            "binary_id": binary_id,
            "pattern_type": pattern_type,
            "count": len(matches),
            "matches": matches,
        }
        # Cache unfiltered results for next time
        if not name_pattern:
            cache_path = self._pattern_cache_path(rec.sha256, pattern)
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps(payload, separators=(',', ':')), encoding='utf-8')

        return payload

    def _verify_pattern_hit(
        self,
        binary_id: str,
        item: dict,
        pattern: str,
        detail: str,
    ) -> dict:
        """Enrich a pattern hit with reachability and source analysis.

        Returns verification fields to merge into the match dict:
        - reachable_from_entry: bool — can this function be reached from exports/entry points?
        - argument_source: str — where does the dangerous input come from?
        - external_input: bool — does data flow from an external source (file/network)?
        - confidence: str — 'high', 'medium', or 'low' exploitability assessment
        - confidence_reason: str — why this confidence level
        """
        import ida_entry

        address = item["address"]
        callers = item.get("callers", [])
        callers_count = item.get("callers_count", 0)

        # 1. Reachability: does this function have callers? (orphan = test/dead code)
        if callers_count == 0 and not callers:
            # Check if it's an entry point itself
            entry_count = ida_entry.get_entry_qty()
            func_ea = int(address, 16) if isinstance(address, str) else address
            is_entry = any(
                ida_entry.get_entry(ida_entry.get_entry_ordinal(i)) == func_ea
                for i in range(min(entry_count, 50))
            )
            if not is_entry:
                return {
                    "reachable_from_entry": False,
                    "argument_source": "unknown",
                    "external_input": False,
                    "confidence": "low",
                    "confidence_reason": (
                        "Function has no callers — possibly dead code"
                        " or only reachable via indirect call."
                    ),
                }

        # 2. Argument source analysis
        # Check if callers pass data from external sources
        external_apis = {
            "readfile", "recv", "recvfrom", "wsarecv", "fread", "fgets",
            "winhttpreaddata", "internetreadfile", "read", "getline",
            "regqueryvalueex", "getwindowtext", "getdlgitemtext",
            "commandlinetoargv", "getcommandline", "getenvironmentvariable",
        }
        file_io_apis = {
            "createfilea", "createfilew", "fopen", "_wfopen", "open",
            "mapviewoffile", "readfile", "fread",
        }

        # Check if any caller uses external input APIs
        caller_uses_external = False
        caller_uses_file_io = False
        for caller_name in callers[:10]:  # check up to 10 callers
            caller_entry = self._indices[binary_id].lookup(caller_name)
            if caller_entry is None:
                continue
            caller_callees = {c.lower() for c in caller_entry.get("callees", [])}
            # Normalize (strip j_ prefix)
            caller_callees |= {c[2:] for c in caller_callees if c.startswith("j_")}
            if caller_callees & external_apis:
                caller_uses_external = True
            if caller_callees & file_io_apis:
                caller_uses_file_io = True

        # 3. Self-check: does THIS function use external input directly?
        own_callees = {c.lower() for c in item.get("callees", [])}
        own_callees |= {c[2:] for c in own_callees if c.startswith("j_")}
        uses_external_directly = bool(own_callees & external_apis)
        uses_file_io_directly = bool(own_callees & file_io_apis)

        # 4. Determine argument source classification
        if uses_external_directly:
            arg_source = "direct_external_input"
            external = True
        elif uses_file_io_directly:
            arg_source = "direct_file_io"
            external = True
        elif caller_uses_external:
            arg_source = "caller_provides_external_input"
            external = True
        elif caller_uses_file_io:
            arg_source = "caller_provides_file_data"
            external = True
        elif callers_count > 0:
            arg_source = "caller_provided"
            external = False  # can't prove it's external
        else:
            arg_source = "unknown"
            external = False

        # 5. Compute confidence
        if external and callers_count > 0:
            confidence = "high"
            reason = (
                f"Function is called by {callers_count} caller(s) and "
                f"{'directly uses' if uses_external_directly else 'receives from callers using'} "
                f"external input APIs. Data likely reaches the sink."
            )
        elif external:
            confidence = "medium"
            reason = (
                "External input APIs detected in the call chain but "
                "path validation has not been verified."
            )
        elif callers_count > 3:
            confidence = "medium"
            reason = (
                f"Function has {callers_count} callers (widely used) but "
                f"could not prove external data reaches the dangerous operation."
            )
        else:
            confidence = "low"
            reason = (
                "Cannot prove attacker-controlled data reaches the dangerous operation. "
                "Input may be validated before reaching this code."
            )

        return {
            "reachable_from_entry": True,
            "argument_source": arg_source,
            "external_input": external,
            "confidence": confidence,
            "confidence_reason": reason,
        }

    @requires(BinaryState.INDEXED)
    def diff_binary(self, binary_id_old: str, binary_id_new: str) -> dict[str, Any]:
        self._activate(binary_id_old)
        old_entries = self._indices[binary_id_old].entries
        self._activate(binary_id_new)
        new_entries = self._indices[binary_id_new].entries
        payload = diff_binary_indexes(old_entries, new_entries)
        payload.update({"binary_id_old": binary_id_old, "binary_id_new": binary_id_new})

        return payload

    @requires(BinaryState.INDEXED)
    def diff_function(
        self,
        binary_id_old: str,
        address_or_name_old: str,
        binary_id_new: str,
        address_or_name_new: str,
        max_lines: int = 500,
    ) -> dict[str, Any]:
        old_payload = self.decompile(binary_id_old, address_or_name_old, max_lines=max_lines)
        new_payload = self.decompile(binary_id_new, address_or_name_new, max_lines=max_lines)
        payload = diff_function_payloads(old_payload, new_payload)
        payload.update({
            "binary_id_old": binary_id_old,
            "binary_id_new": binary_id_new,
        })

        return payload

    @requires(BinaryState.INDEXED)
    def diff_survey(
        self,
        binary_id_old: str,
        binary_id_new: str,
        *,
        max_changed: int = 20,
        include_pseudocode_diff: bool = True,
        max_diff_lines: int = 60,
    ) -> dict[str, Any]:
        """One-call N-day survey: diff summary + per-function diffs + security ranking."""
        binary_diff = self.diff_binary(binary_id_old, binary_id_new)
        changed = binary_diff.get("changed", [])[:max_changed]

        enriched: list[dict[str, Any]] = []
        for entry in changed:
            item: dict[str, Any] = {
                "name_old": entry["name_old"],
                "name_new": entry["name_new"],
                "security_rank": entry.get("security_rank", 0),
                "similarity": entry["similarity"],
                "size_delta": entry["size_delta"],
                "complexity_delta": entry["complexity_delta"],
                "callees_added": entry["callees_added"],
                "callees_removed": entry["callees_removed"],
            }
            if include_pseudocode_diff:
                try:
                    fn_diff = self.diff_function(
                        binary_id_old, entry["address_old"],
                        binary_id_new, entry["address_new"],
                        max_lines=max_diff_lines,
                    )
                    item["summary_signal"] = fn_diff.get("summary_signal", "unknown")
                    item["diff_preview"] = fn_diff.get("diff_unified", "")[:2000]
                except (ValueError, RuntimeError):
                    item["summary_signal"] = "decompile_failed"
                    item["diff_preview"] = None
            enriched.append(item)

        return {
            "binary_id_old": binary_id_old,
            "binary_id_new": binary_id_new,
            "summary": binary_diff["summary"],
            "added": binary_diff.get("added", []),
            "removed": binary_diff.get("removed", []),
            "changed": enriched,
        }

    @requires(BinaryState.ACTIVE)
    def query_ctree(
        self,
        binary_id: str,
        address_or_name: str,
        *,
        target_function: str = "",
        argument_index: int | None = None,
        contains_operation: str = "",
        operand_type_is: str = "",
        limit: int = 50,
    ) -> dict[str, Any]:
        import ida_funcs

        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")
        cfunc = decompile_cfunc(func)
        payload = query_ctree_calls(
            cfunc,
            target_function=target_function,
            argument_index=argument_index,
            contains_operation=contains_operation,
            operand_type_is=operand_type_is,
            limit=limit,
        )
        payload["binary_id"] = binary_id

        return payload

    @requires(BinaryState.ACTIVE)
    def get_microcode(
        self,
        binary_id: str,
        address_or_name: str,
        *,
        maturity: str = "current",
    ) -> dict[str, Any]:
        import ida_funcs

        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")
        cfunc = decompile_cfunc(func)
        payload = get_microcode_text(cfunc, maturity=maturity)
        payload["binary_id"] = binary_id

        return payload

    @requires(BinaryState.ACTIVE)
    def trace_dataflow(
        self,
        binary_id: str,
        address_or_name: str,
        *,
        sink_function: str,
        sink_argument_index: int,
        source_contains: list[str] | None = None,
        max_steps: int = 10,
    ) -> dict[str, Any]:
        import ida_funcs

        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")
        cfunc = decompile_cfunc(func)
        payload = trace_ctree_dataflow(
            cfunc,
            sink_function=sink_function,
            sink_argument_index=sink_argument_index,
            source_contains=source_contains,
            max_steps=max_steps,
        )
        payload["binary_id"] = binary_id

        return payload

    @requires(BinaryState.ACTIVE)
    def interprocedural_taint(
        self,
        binary_id: str,
        sink_function: str,
        sink_argument_index: int,
        *,
        source_functions: list[str] | None = None,
        max_depth: int = 5,
    ) -> dict[str, Any]:
        """Trace data flow from sink backward across function boundaries."""
        from .hexrays_analysis import interprocedural_taint
        result = interprocedural_taint(
            sink_function=sink_function,
            sink_argument_index=sink_argument_index,
            source_functions=source_functions,
            max_depth=max_depth,
        )
        result["binary_id"] = binary_id
        return result

    @requires(BinaryState.ACTIVE)
    def recover_cfg(self, binary_id: str, address_or_name: str) -> dict[str, Any]:
        """Recover true control flow from a flattened function."""
        import ida_funcs
        from .hexrays_analysis import decompile_cfunc, get_microcode_text
        from .recovery import recover_cfg
        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")
        cfunc = decompile_cfunc(func)
        result = recover_cfg(str(cfunc), get_microcode_text(cfunc))
        result["binary_id"] = binary_id
        return result

    @requires(BinaryState.ACTIVE)
    def generate_yara_rule(self, binary_id: str, address_or_name: str) -> dict:
        """Generate a YARA rule from a function's byte pattern."""
        import hashlib

        import ida_bytes
        import ida_funcs
        import ida_name

        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")
        func_bytes = ida_bytes.get_bytes(func.start_ea, min(func.size(), 200))
        if not func_bytes:
            return {"binary_id": binary_id, "error": "Could not read bytes"}
        func_name = ida_name.get_ea_name(func.start_ea) or f"sub_{func.start_ea:x}"
        safe_name = "".join(c if c.isalnum() or c == "_" else "_" for c in func_name)
        hex_string = " ".join(f"{b:02X}" for b in func_bytes)
        sha = hashlib.sha256(func_bytes).hexdigest()[:16]
        rule = (
            f"rule {safe_name}_{sha} {{\n"
            f"    meta:\n"
            f"        description = \"Auto-generated from {func_name}\"\n"
            f"        address = \"0x{func.start_ea:x}\"\n"
            f"        size = {func.size()}\n"
            f"    strings:\n"
            f"        $pattern = {{ {hex_string} }}\n"
            f"    condition:\n"
            f"        $pattern\n"
            f"}}"
        )
        return {
            "binary_id": binary_id, "function": func_name,
            "address": f"0x{func.start_ea:x}", "size": func.size(),
            "rule": rule, "pattern_bytes": len(func_bytes),
        }

    @requires(BinaryState.ACTIVE)
    def patch_assemble(self, binary_id: str, address: str, assembly: str) -> dict:
        """Assemble instructions and patch at address."""
        import ida_bytes
        import ida_idp

        ea = int(address.strip(), 16)
        instructions = [i.strip() for i in assembly.split(";") if i.strip()]
        patched = []
        current_ea = ea
        for insn_text in instructions:
            ok, code_bytes = ida_idp.assemble(current_ea, 0, current_ea, True, insn_text)
            if not ok or not code_bytes:
                return {"binary_id": binary_id, "error": f"Failed: {insn_text}", "patched": patched}
            ida_bytes.patch_bytes(current_ea, bytes(code_bytes))
            patched.append({
                "address": f"0x{current_ea:x}", "instruction": insn_text,
                "bytes": code_bytes.hex(), "size": len(code_bytes),
            })
            current_ea += len(code_bytes)
        return {
            "binary_id": binary_id, "address": address,
            "instructions_patched": len(patched), "patches": patched,
        }

    @requires(BinaryState.INDEXED)
    def capa_scan(self, binary_id: str) -> dict:
        """Evaluate 678 CAPA behavioral rules against the binary."""
        from .capa_rules import capa_scan
        idx = self._indices.get(binary_id)
        if not idx:
            return {"binary_id": binary_id, "matches": 0, "capabilities": []}
        entries = [
            {"name": e.name, "callees": list(e.callees), "string_refs": list(e.string_refs)}
            for e in idx.entries
        ]
        result = capa_scan(entries)
        result["binary_id"] = binary_id
        return result

    @requires(BinaryState.INDEXED)
    def resolve_api_hashes(self, binary_id: str) -> dict:
        """Resolve hash-imported API names by scanning code for constants."""
        import ida_funcs
        import ida_ua
        import idautils

        from .api_hashes import resolve_api_hashes

        hash_candidates: list[int] = []
        idx = self._indices.get(binary_id)
        if not idx:
            return {"binary_id": binary_id, "resolved_count": 0, "resolved": []}

        # Find functions that call GetProcAddress or hash-resolver patterns
        resolver_callers: set[int] = set()
        for entry in idx.entries:
            callees_lower = {c.lower() for c in entry.callees}
            if callees_lower & {"getprocaddress", "ldrgetprocedureaddress"}:
                resolver_callers.add(entry.address)

        # Scan those functions for 32-bit immediate constants
        for func_ea in resolver_callers:
            func = ida_funcs.get_func(func_ea)
            if func is None:
                continue
            for head in idautils.Heads(func.start_ea, func.end_ea):
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, head) <= 0:
                    continue
                for op in insn.ops:
                    if op.type == 0:  # o_void
                        break
                    # Immediate operand with 32-bit value in hash range
                    if op.type == 5:  # o_imm
                        val = op.value & 0xFFFFFFFF
                        if 0x1000 < val < 0xFFFFFFFF:
                            hash_candidates.append(val)

        # Deduplicate
        hash_candidates = sorted(set(hash_candidates))
        result = resolve_api_hashes(hash_candidates)
        result["binary_id"] = binary_id
        result["functions_scanned"] = len(resolver_callers)
        return result

    @requires(BinaryState.INDEXED)
    def detect_library_functions(self, binary_id: str) -> dict:
        """Aggregate library functions by detected library."""
        idx = self._indices.get(binary_id)
        if not idx:
            return {"binary_id": binary_id, "libraries": [], "total_library": 0}
        lib_funcs = [e for e in idx.entries if e.is_library]
        # Group by name prefix
        groups: dict[str, list[str]] = {}
        prefixes = [
            ("_ssl_", "OpenSSL"), ("SSL_", "OpenSSL"), ("EVP_", "OpenSSL"),
            ("_z_", "zlib"), ("deflate", "zlib"), ("inflate", "zlib"),
            ("_png_", "libpng"), ("png_", "libpng"),
            ("_jpeg_", "libjpeg"), ("jpeg_", "libjpeg"),
            ("_xml_", "libxml2"), ("xml", "libxml2"),
            ("curl_", "libcurl"), ("CURL", "libcurl"),
            ("sqlite3_", "SQLite"),
            ("_mbedtls_", "mbedTLS"), ("mbedtls_", "mbedTLS"),
            ("_gcry_", "libgcrypt"),
            ("BIO_", "OpenSSL"), ("X509_", "OpenSSL"),
            ("SHA256", "crypto"), ("MD5", "crypto"), ("AES_", "crypto"),
        ]
        crt_patterns = ["__", "_", "str", "mem", "wcs", "printf", "malloc", "free"]
        for f in lib_funcs:
            assigned = False
            for prefix, lib in prefixes:
                if f.name.startswith(prefix) or f.name.startswith("_" + prefix):
                    groups.setdefault(lib, []).append(f.name)
                    assigned = True
                    break
            if not assigned:
                if any(f.name.startswith(p) for p in crt_patterns):
                    groups.setdefault("CRT", []).append(f.name)
                else:
                    groups.setdefault("unknown", []).append(f.name)
        libraries = [
            {"name": name, "function_count": len(funcs), "functions": funcs[:10]}
            for name, funcs in sorted(groups.items(), key=lambda x: -len(x[1]))
        ]
        return {
            "binary_id": binary_id,
            "total_library": len(lib_funcs),
            "total_application": len(idx.entries) - len(lib_funcs),
            "libraries": libraries,
        }

    @requires(BinaryState.ACTIVE)
    def recover_class_hierarchy(self, binary_id: str) -> dict[str, Any]:
        """Recover C++ class hierarchy via .rdata vtable scan + xref analysis.

        Algorithm:
        1. Scan .rdata for vtable-shaped arrays (consecutive function pointers)
        2. For each vtable, find xrefs TO it (constructors that install it)
        3. Read vtable entries to get virtual method list
        No mass decompilation — uses xrefs and ida_bytes only.
        """
        import ida_bytes
        import ida_funcs
        import ida_name
        import ida_segment
        import idautils

        from .recovery import recover_class_hierarchy

        vtables: list[dict] = []
        constructors: list[dict] = []

        # Step 1: Scan .rdata/.rodata for vtable candidates
        seg = ida_segment.get_first_seg()
        while seg:
            seg_name = ida_segment.get_segm_name(seg) or ""
            if "rdata" in seg_name.lower() or "rodata" in seg_name.lower():
                ea = seg.start_ea
                while ea < seg.end_ea - 16:
                    # Check for consecutive code pointers
                    ptrs: list[str] = []
                    cur = ea
                    while cur < seg.end_ea:
                        val = ida_bytes.get_qword(cur)
                        if val == 0:
                            break
                        fn = ida_funcs.get_func(val)
                        if fn is None:
                            break
                        ptrs.append(f"0x{val:x}")
                        cur += 8
                    if len(ptrs) >= 3:
                        vtables.append({"address": f"0x{ea:x}", "entries": ptrs})
                        # Find constructors via xrefs TO this vtable address
                        for xref in idautils.XrefsTo(ea, 0):
                            ctor_func = ida_funcs.get_func(xref.frm)
                            if ctor_func:
                                constructors.append({
                                    "constructor": ida_name.get_ea_name(ctor_func.start_ea),
                                    "vtable": f"0x{ea:x}",
                                    "xref_from": f"0x{xref.frm:x}",
                                })
                        ea = cur
                    else:
                        ea += 8
            seg = ida_segment.get_next_seg(seg.start_ea)

        idx = self._indices.get(binary_id)
        func_entries = []
        if idx:
            func_entries = [
                {"address": f"0x{e.address:x}", "name": e.name}
                for e in idx.entries
            ]
        result = recover_class_hierarchy(vtables[:100], func_entries)
        result["binary_id"] = binary_id
        result["constructors_found"] = constructors[:50]
        return result

        func_entries = [
            {"address": f"0x{e.address:x}", "name": e.name}
            for e in idx.entries
        ]
        result = recover_class_hierarchy(vtables[:100], func_entries)
        result["binary_id"] = binary_id
        result["constructors_found"] = constructors[:50]
        return result

    @requires(BinaryState.ACTIVE)
    def detect_protocol_state_machine(
        self, binary_id: str, address_or_name: str,
    ) -> dict[str, Any]:
        """Detect network protocol state machine patterns."""
        import ida_funcs
        from .hexrays_analysis import decompile_cfunc
        from .recovery import detect_protocol_state_machine
        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")
        cfunc = decompile_cfunc(func)
        pseudocode = str(cfunc)
        # Get callees from index
        idx = self._indices.get(binary_id)
        callees: list[str] = []
        string_refs: list[str] = []
        if idx:
            entry = idx.lookup(address_or_name)
            if entry:
                callees = entry.get("callees", [])
                string_refs = entry.get("string_refs", [])
        result = detect_protocol_state_machine(pseudocode, callees, string_refs)

        # Taint verification: does recv output actually flow to dispatch?
        if result.get("recv_present") and result.get("has_command_dispatch"):
            from .hexrays_analysis import trace_ctree_dataflow
            # Find recv-like sinks and trace their output forward
            recv_apis = ["recv", "recvfrom", "wsarecv", "winhttpreaddata", "internetreadfile"]
            for api in recv_apis:
                if api in {c.lower() for c in callees}:
                    flow = trace_ctree_dataflow(
                        cfunc, sink_function=api, sink_argument_index=1,
                        source_contains=[], max_steps=10,
                    )
                    if flow.get("sink_found"):
                        result["recv_to_dispatch_verified"] = True
                        result["recv_trace"] = {
                            "api": api,
                            "buffer_expr": flow.get("sink_expression"),
                        }
                        break
            else:
                result["recv_to_dispatch_verified"] = False
        result["binary_id"] = binary_id
        result["function"] = address_or_name
        return result

    @requires(BinaryState.ACTIVE)
    def prove_bounds_sufficient(
        self, binary_id: str, address_or_name: str,
        sink_function: str, sink_argument_index: int,
    ) -> dict[str, Any]:
        """Prove whether validation gates are sufficient to prevent overflow."""
        assess = self.assess_exploitability(
            binary_id, address_or_name, sink_function, sink_argument_index,
        )
        if not assess.get("sink_found"):
            return {**assess, "sufficient": None}
        from .proof import prove_bounds_sufficient
        result = prove_bounds_sufficient(assess)
        result["binary_id"] = binary_id
        result["function"] = assess.get("function", "")
        return result

    @requires(BinaryState.ACTIVE)
    def prove_predicate_opaque(self, binary_id: str, address_or_name: str, condition_address: str) -> dict[str, Any]:
        """Prove whether a branch condition is opaque."""
        import ida_funcs
        import re as _re
        from .hexrays_analysis import decompile_cfunc
        from .proof import prove_predicate_opaque
        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")
        cfunc = decompile_cfunc(func)
        variables = sorted(set(_re.findall(r"\bv\d+\b", str(cfunc))))[:8]
        result = prove_predicate_opaque(condition_address, variables)
        result["binary_id"] = binary_id
        return result

    @requires(BinaryState.ACTIVE)
    def prove_equivalence(self, binary_id: str, expr_a: str, expr_b: str, address_or_name: str) -> dict[str, Any]:
        """Prove two expressions equivalent."""
        import ida_funcs
        import re as _re
        from .hexrays_analysis import decompile_cfunc
        from .proof import prove_equivalence
        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")
        cfunc = decompile_cfunc(func)
        variables = sorted(set(_re.findall(r"\bv\d+\b", str(cfunc))))[:8]
        result = prove_equivalence(expr_a, expr_b, variables)
        result["binary_id"] = binary_id
        return result

    @requires(BinaryState.ACTIVE)
    def detect_obfuscation(self, binary_id: str, address_or_name: str) -> dict[str, Any]:
        """Detect obfuscation techniques in a function."""
        import ida_funcs
        from .detection import detect_obfuscation
        from .hexrays_analysis import decompile_cfunc, get_microcode_text

        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")
        cfunc = decompile_cfunc(func)
        pseudocode = str(cfunc)
        microcode = get_microcode_text(cfunc)
        result = detect_obfuscation(microcode, pseudocode, cfunc=cfunc)
        result["binary_id"] = binary_id
        result["function"] = self._require(binary_id) and address_or_name
        return result

    @requires(BinaryState.INDEXED)
    def detect_crypto_primitives(self, binary_id: str) -> dict[str, Any]:
        """Detect known crypto constants and patterns in the binary."""
        import ida_bytes
        import ida_segment
        from .detection import detect_crypto_primitives

        # Gather data sections
        data_bytes = []
        seg = ida_segment.get_first_seg()
        while seg:
            if seg.perm & 2 == 0:  # not writable = likely .rdata/.rodata
                size = min(seg.size(), 1024 * 1024)  # cap at 1MB
                data = ida_bytes.get_bytes(seg.start_ea, size)
                if data:
                    data_bytes.append((seg.start_ea, data))
            seg = ida_segment.get_next_seg(seg.start_ea)

        # Function entries from index
        idx = self._indices.get(binary_id)
        func_entries = []
        if idx:
            func_entries = [
                {"address": f"0x{e.address:x}", "name": e.name,
                 "size_bytes": e.size_bytes, "cyclomatic_complexity": e.cyclomatic_complexity,
                 "callees": list(e.callees)}
                for e in idx.entries[:500]
            ]

        # String refs
        strings = []
        if idx:
            for e in idx.entries:
                strings.extend(e.string_refs)

        result = detect_crypto_primitives(data_bytes, func_entries, list(set(strings)))
        result["binary_id"] = binary_id
        return result

    @requires(BinaryState.ACTIVE)
    def prove_overflow(
        self,
        binary_id: str,
        address_or_name: str,
        sink_function: str,
        sink_argument_index: int,
    ) -> dict[str, Any]:
        """Prove overflow using CTree-to-SMT encoding + binbit solver."""
        import ida_funcs
        import ida_hexrays

        from .ctree_to_smt import SMTContext, condition_to_smt
        from .hexrays_analysis import (
            decompile_cfunc,
            query_ctree_calls,
        )
        from .smt_prover import binbit_available, solve_smtlib

        # Get the assess result first (for verdict context)
        assess = self.assess_exploitability(
            binary_id, address_or_name, sink_function, sink_argument_index,
        )
        if not assess.get('sink_found'):
            return {**assess, 'proof': 'not_applicable'}
        if not assess.get('has_multiplication'):
            return {**assess, 'verdict': 'no_multiplication'}

        # Decompile and find the sink + gates via CTree
        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            return {**assess, 'verdict': 'decompile_failed'}
        cfunc = decompile_cfunc(func)

        # Find sink call in CTree
        sink_info = query_ctree_calls(
            cfunc, target_function=sink_function,
            argument_index=sink_argument_index, limit=5,
        )
        if not sink_info.get('matches'):
            # Fallback to text-based proof
            from .proof import prove_overflow
            result = prove_overflow(assess)
            result['binary_id'] = binary_id
            result['encoding'] = 'text_fallback'
            return result

        # Build SMT script from CTree
        ctx = SMTContext()
        script_lines = ['; CTree-encoded overflow proof']

        # Encode validation gates from CTree if-conditions
        gates_encoded = 0
        class _GateFinder(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                super().__init__(ida_hexrays.CV_FAST)
                self.gate_smts: list[str] = []
                self.sink_ea = int(sink_info['matches'][0]['address'], 16)

            def visit_insn(self, insn):
                if insn.op != ida_hexrays.cit_if:
                    return 0
                if insn.ea < self.sink_ea or insn.ea == 0:
                    smt = condition_to_smt(insn.cif.expr, ctx)
                    if smt:
                        self.gate_smts.append(smt)
                return 0

        gf = _GateFinder()
        gf.apply_to(cfunc.body, None)

        # Add declarations
        script_lines.append(ctx.get_declarations_smt())
        script_lines.append('')

        # Assert gate negations (at sink, gates did NOT fire)
        for smt in gf.gate_smts:
            script_lines.append(f'(assert (not {smt}))')
            gates_encoded += 1

        # Find multiplication operands from sink expression
        match = sink_info['matches'][0]
        if sink_argument_index < len(match.get('args_preview', [])):
            # Add overflow predicate for all declared vars
            vars_list = sorted(ctx.declarations.keys())
            if len(vars_list) >= 2:
                a, b = vars_list[0], vars_list[1]
                w = ctx.declarations[a]
                script_lines.append('')
                script_lines.append(f'(assert (bvsgt {a} (_ bv0 {w})))')
                script_lines.append(f'(assert (bvsgt {b} (_ bv0 {w})))')
                script_lines.append(f'(declare-const _pf (_ BitVec {w*2}))')
                script_lines.append(
                    f'(assert (= _pf (bvmul '
                    f'((_ sign_extend {w}) {a}) '
                    f'((_ sign_extend {w}) {b}))))'
                )
                script_lines.append(
                    f'(assert (not (= _pf '
                    f'((_ sign_extend {w}) (bvmul {a} {b})))))'
                )
        script_lines.append('')
        script_lines.append('(check-sat)')
        witness_vars = ' '.join(sorted(ctx.declarations.keys()))
        if witness_vars:
            script_lines.append(f'(get-value ({witness_vars}))')

        script = '\n'.join(script_lines)

        if not binbit_available():
            return {
                **assess, 'verdict': 'solver_unavailable',
                'gates_encoded': gates_encoded,
                'encoding': 'ctree',
            }

        result = solve_smtlib(script)
        verdict = 'inconclusive'
        if result['result'] == 'sat':
            verdict = 'proven_exploitable'
        elif result['result'] == 'unsat':
            verdict = 'proven_defended'

        return {
            'binary_id': binary_id,
            'function': assess.get('function', ''),
            'address': assess.get('address', ''),
            'sink_expression': assess.get('sink_expression', ''),
            'verdict': verdict,
            'feasible': result['result'] == 'sat',
            'witness': result.get('model', {}),
            'time_ms': result.get('time_ms', 0),
            'gates_encoded': gates_encoded,
            'encoding': 'ctree',
            'source_type': assess.get('source_type', ''),
            'script': script,
        }

    @requires(BinaryState.ACTIVE)
    def assess_exploitability(
        self,
        binary_id: str,
        address_or_name: str,
        sink_function: str,
        sink_argument_index: int,
    ) -> dict[str, Any]:
        """Assess exploitability of a sink in a specific function."""
        import ida_funcs

        from .hexrays_analysis import assess_exploitability, decompile_cfunc

        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")
        cfunc = decompile_cfunc(func)
        result = assess_exploitability(cfunc, sink_function, sink_argument_index)
        result["binary_id"] = binary_id
        return result

    @requires(BinaryState.ACTIVE)
    def constrained_reachability(
        self,
        binary_id: str,
        address_or_name: str,
        sink_address: str,
        *,
        timeout_seconds: int = 60,
    ) -> dict[str, Any]:
        """Prove path reachability using angr seeded with Hex-Rays value ranges."""
        import ida_funcs

        from .hexrays_analysis import (
            constrained_reachability,
            decompile_cfunc,
            microcode_value_ranges,
        )

        rec = self._require(binary_id)
        ea = _resolve_address(address_or_name)
        sink_ea = int(sink_address.strip(), 16)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")

        # Extract value ranges from Hex-Rays microcode
        cfunc = decompile_cfunc(func)
        vr_data = microcode_value_ranges(cfunc)
        ranges = vr_data.get("range_annotations", [])

        # Run constrained angr exploration
        result = constrained_reachability(
            binary_path=str(rec.path),
            function_ea=func.start_ea,
            sink_ea=sink_ea,
            value_ranges=ranges,
            timeout_seconds=timeout_seconds,
        )
        result["binary_id"] = binary_id
        result["value_ranges_used"] = len(ranges)
        return result

    @requires(BinaryState.ACTIVE)
    def hexrays_warnings(self, binary_id: str, address_or_name: str) -> dict[str, Any]:
        import ida_funcs

        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")
        cfunc = decompile_cfunc(func)
        result = get_hexrays_warnings(cfunc)
        result["binary_id"] = binary_id
        return result

    @requires(BinaryState.ACTIVE)
    def pseudocode_slice_fn(
        self,
        binary_id: str,
        address_or_name: str,
        *,
        focus_callee: str = "",
        focus_address: str = "",
        context_lines: int = 5,
        max_slices: int = 10,
    ) -> dict[str, Any]:
        import ida_funcs

        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")
        cfunc = decompile_cfunc(func)
        result = pseudocode_slice(
            cfunc,
            focus_callee=focus_callee,
            focus_address=focus_address,
            context_lines=context_lines,
            max_slices=max_slices,
        )
        result["binary_id"] = binary_id
        return result

    @requires(BinaryState.ACTIVE)
    def def_use(
        self,
        binary_id: str,
        address_or_name: str,
        *,
        target_callee: str = "",
        max_instructions: int = 200,
    ) -> dict[str, Any]:
        """Microcode-level use/def analysis for a function."""
        import ida_funcs

        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")
        cfunc = decompile_cfunc(func)
        result = microcode_def_use(
            cfunc,
            target_callee=target_callee,
            max_instructions=max_instructions,
        )
        result["binary_id"] = binary_id
        return result

    @requires(BinaryState.ACTIVE)
    def value_ranges(self, binary_id: str, address_or_name: str) -> dict[str, Any]:
        """IR-backed value-range annotations from the decompiler's microcode."""
        import ida_funcs

        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")
        cfunc = decompile_cfunc(func)
        result = microcode_value_ranges(cfunc)
        result["binary_id"] = binary_id
        return result

    @requires(BinaryState.INDEXED)
    def binary_survey(self, binary_id: str, max_hotspots: int = 10) -> dict[str, Any]:
        """One-call orientation: metadata + attack surface + hotspots + pattern hits."""
        rec = self._require(binary_id)
        index = self._indices[binary_id]

        # Attack surface: dangerous and network-related imports
        dangerous_imports = {
            "memcpy", "memmove", "strcpy", "sprintf", "gets", "strcat",
            "system", "popen", "execve", "free", "malloc", "realloc",
        }
        network_imports = {
            "recv", "send", "accept", "bind", "listen", "connect",
            "recvfrom", "sendto", "wsarecv", "wsasend", "read", "write",
        }

        user_funcs = [e for e in index.entries if not e.is_thunk and not e.is_library]
        all_callees: set[str] = set()
        for e in user_funcs:
            all_callees.update(c.lower() for c in e.callees)

        # Hotspots by complexity
        by_complexity = sorted(user_funcs, key=lambda e: -e.cyclomatic_complexity)[:max_hotspots]

        # Pattern hits: run cached patterns if available
        pattern_hits: dict[str, int] = {}
        all_patterns = [
            "dangerous_function", "format_string", "command_injection",
            "unchecked_length", "signed_size", "toctou", "double_free",
            "use_after_free", "null_deref", "integer_overflow",
        ]
        for ptype in all_patterns:
            cache_path = self._pattern_cache_path(rec.sha256, ptype)
            if cache_path.exists():
                cached = json.loads(cache_path.read_text(encoding='utf-8'))
                pattern_hits[ptype] = cached.get("count", 0)

        return {
            "binary_id": binary_id,
            "overview": {
                "root_filename": rec.root_filename,
                "format": rec.format,
                "arch": rec.arch,
                "bits": rec.bits,
                "functions_total": rec.function_count,
                "functions_user": len(user_funcs),
                "functions_library": rec.function_count - len(user_funcs),
                "mitigations": rec.mitigations,
            },
            "attack_surface": {
                "exported_functions": rec.exports_count,
                "imports_dangerous": sorted(all_callees & dangerous_imports),
                "imports_network": sorted(all_callees & network_imports),
            },
            "hotspots": [
                {
                    "name": e.name,
                    "address": f"0x{e.address:x}",
                    "complexity": e.cyclomatic_complexity,
                    "callees_count": len(e.callees),
                    "callers_count": len(e.callers),
                    "string_refs_count": len(e.string_refs),
                }
                for e in by_complexity
            ],
            "pattern_hits": pattern_hits,
        }
    @requires(BinaryState.INDEXED)
    def call_chain(
        self,
        binary_id: str,
        target_function: str,
        *,
        depth: int = 5,
        direction: str = "callers",
    ) -> dict[str, Any]:
        """Walk caller/callee chains from a target function to a given depth.

        Returns the full call tree reaching (or reachable from) the target.
        Uses the function index — no decompilation needed.
        """
        index = self._indices[binary_id]

        # Build lookup maps
        by_name: dict[str, Any] = {}
        for e in index.entries:
            by_name[e.name.lower()] = e
            by_name[f"0x{e.address:x}"] = e

        target_key = target_function.strip().lower()
        root = by_name.get(target_key)
        if root is None:
            # Try partial match
            for name, entry in by_name.items():
                if target_key in name:
                    root = entry
                    break
        if root is None:
            raise ValueError(f"Function not found: {target_function!r}")

        # BFS walk
        visited: set[str] = set()
        layers: list[list[dict[str, Any]]] = []
        current_names = [root.name]
        visited.add(root.name.lower())

        for d in range(depth):
            next_names: list[str] = []
            layer: list[dict[str, Any]] = []
            for name in current_names:
                entry = by_name.get(name.lower())
                if entry is None:
                    continue
                neighbors = entry.callers if direction == "callers" else entry.callees
                for nb in neighbors:
                    if nb.lower() in visited:
                        continue
                    visited.add(nb.lower())
                    nb_entry = by_name.get(nb.lower())
                    layer.append({
                        "name": nb,
                        "address": f"0x{nb_entry.address:x}" if nb_entry else None,
                        "depth": d + 1,
                        "reached_from": name,
                    })
                    next_names.append(nb)
            if not layer:
                break
            layers.append(layer)
            current_names = next_names

        all_nodes = [item for layer in layers for item in layer]
        return {
            "binary_id": binary_id,
            "target": root.name,
            "target_address": f"0x{root.address:x}",
            "direction": direction,
            "depth_searched": len(layers),
            "nodes_found": len(all_nodes),
            "chain": all_nodes,
        }

    @requires(BinaryState.INDEXED)
    def classify_behavior(self, binary_id: str) -> dict[str, Any]:
        """Map imported APIs to ATT&CK-aligned behavioral categories."""
        self._require(binary_id)
        index = self._indices[binary_id]

        # Collect normalized API names from callees AND import table
        all_apis: set[str] = set()
        for e in index.entries:
            if not e.is_thunk:
                for c in e.callees:
                    all_apis.add(_normalize_api_name(c))
        try:
            imp_data = self.imports(binary_id)
            for imp in imp_data.get('imports', []):
                all_apis.add(_normalize_api_name(imp['name']))
        except (RuntimeError, ValueError):
            pass

        # Normalize the dictionary keys too
        categories = {
            'c2_networking': {
                'internetopenurl', 'internetopen', 'internetconnect',
                'httpsendrequest', 'httpopenrequest', 'internetreadfile',
                'urldownloadtofile', 'wininet', 'winhttpopenrequest',
                'wsastartup', 'socket', 'connect', 'send', 'recv',
                'gethostbyname', 'getaddrinfo', 'dnsquery',
            },
            'persistence': {
                'regsetvalue', 'regcreatekey',
                'createservice', 'changeserviceconfig2',
                'schtaskcreate', 'copyfile', 'movefile',
                'writeprocessmemory', 'setwindowshookex',
            },
            'execution': {
                'createprocess', 'shellexecute',
                'system', 'popen', 'winexec',
                'createremotethread', 'ntcreatethreadex',
                'virtualalloc', 'virtualprotect',
            },
            'credential_access': {
                'credssp', 'logonuser', 'lsaenumeratelogonsessions',
                'cryptunprotectdata', 'credread',
            },
            'defense_evasion': {
                'ntunmapviewofsection', 'zwunmapviewofsection',
                'virtualprotect',
                'setthreadcontext', 'ntsetinformationthread',
                'deleteservice', 'deletefile',
                'movefile', 'cryptencrypt',
            },
            'discovery': {
                'getsysteminfo', 'getcomputername', 'getusername',
                'getversionex', 'getadaptersinfo',
                'enumprocesses', 'process32first', 'process32next',
                'createtoolhelp32snapshot', 'gettokeninformation',
                'lookupaccountsid', 'netuserenum', 'netshareenum',
            },
            'exfiltration': {
                'ftpputfile', 'internetwritefile', 'httpsendrequest',
                'writefile', 'sendto', 'transmitfile',
            },
            'privilege_escalation': {
                'adjusttokenprivileges', 'openprocesstoken',
                'lookupprivilegevalue', 'impersonateloggedonuser',
                'ntquerysysteminformation',
            },
        }

        results: dict[str, list[str]] = {}
        for category, apis in categories.items():
            hits = sorted(all_apis & apis)
            if hits:
                results[category] = hits

        return {
            "binary_id": binary_id,
            "categories_detected": len(results),
            "behaviors": results,
            "total_apis_matched": sum(len(v) for v in results.values()),
        }

    @requires(BinaryState.INDEXED)
    def detect_anti_analysis(self, binary_id: str) -> dict[str, Any]:
        """Detect anti-debug, anti-VM, and anti-sandbox techniques."""
        index = self._indices[binary_id]

        all_apis: set[str] = set()
        all_strings: set[str] = set()
        for e in index.entries:
            if not e.is_thunk:
                for c in e.callees:
                    all_apis.add(_normalize_api_name(c))
                all_strings.update(s.lower() for s in e.string_refs)
        # Also scan import table directly
        try:
            imp_data = self.imports(binary_id)
            for imp in imp_data.get('imports', []):
                all_apis.add(_normalize_api_name(imp['name']))
        except (RuntimeError, ValueError):
            pass

        techniques: list[dict[str, Any]] = []

        # Anti-debug APIs
        anti_debug_apis = {
            'isdebuggerpresent', 'checkremotedebuggerpresent',
            'ntqueryinformationprocess', 'outputdebugstring',
        }
        hits = sorted(all_apis & anti_debug_apis)
        if hits:
            techniques.append({
                'technique': 'anti_debug_api',
                'evidence': hits,
                'mitre': 'T1622',
            })

        # Anti-VM strings
        vm_indicators = [
            'vmware', 'virtualbox', 'vbox', 'qemu', 'xen',
            'sandboxie', 'wine', 'virtual hd', 'hyper-v',
            'parallels', 'bochs',
        ]
        vm_hits = [s for s in vm_indicators if any(s in st for st in all_strings)]
        if vm_hits:
            techniques.append({
                'technique': 'vm_detection_strings',
                'evidence': vm_hits,
                'mitre': 'T1497.001',
            })

        # Timing-based detection APIs
        timing_apis = {'gettickcount', 'gettickcount64', 'queryperformancecounter', 'rdtsc'}
        timing_hits = sorted(all_apis & timing_apis)
        if timing_hits:
            techniques.append({
                'technique': 'timing_check',
                'evidence': timing_hits,
                'mitre': 'T1497.003',
            })

        # Process enumeration (sandbox detection)
        process_apis = {'createtoolhelp32snapshot', 'process32first', 'process32next', 'enumprocesses'}
        proc_hits = sorted(all_apis & process_apis)
        if proc_hits:
            techniques.append({
                'technique': 'process_enumeration',
                'evidence': proc_hits,
                'mitre': 'T1057',
            })

        return {
            "binary_id": binary_id,
            "techniques_detected": len(techniques),
            "techniques": techniques,
            "verdict": 'evasive' if len(techniques) >= 2 else ('suspicious' if techniques else 'clean'),
        }

    @requires(BinaryState.ACTIVE)
    def entropy_analysis(self, binary_id: str) -> dict[str, Any]:
        """Compute per-section Shannon entropy for packing/encryption detection."""
        import math

        self._require(binary_id)

        section_entropy: list[dict[str, Any]] = []
        high_entropy_count = 0

        import ida_bytes
        import ida_segment
        import idautils

        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if seg is None:
                continue
            name = ida_segment.get_segm_name(seg)
            size = seg.size()
            if size == 0:
                continue

            # Sample up to 64KB for entropy calculation
            sample_size = min(size, 65536)
            byte_counts = [0] * 256
            for offset in range(sample_size):
                b = ida_bytes.get_byte(seg.start_ea + offset)
                byte_counts[b] += 1

            entropy = 0.0
            for count in byte_counts:
                if count == 0:
                    continue
                p = count / sample_size
                entropy -= p * math.log2(p)

            is_high = entropy > 7.0
            if is_high:
                high_entropy_count += 1

            section_entropy.append({
                'name': name,
                'start': f'0x{seg.start_ea:x}',
                'size': size,
                'entropy': round(entropy, 3),
                'high_entropy': is_high,
            })

        return {
            "binary_id": binary_id,
            "sections": section_entropy,
            "high_entropy_sections": high_entropy_count,
            "verdict": 'likely_packed' if high_entropy_count >= 2 else (
                'partially_encrypted' if high_entropy_count == 1 else 'normal'
            ),
        }

    @requires(BinaryState.INDEXED)
    def classify_strings(self, binary_id: str, limit: int = 200) -> dict[str, Any]:
        """Structurally classify string references by format.

        Returns factual categorization — no suspicion scoring.
        The consumer decides what matters.
        """
        import re

        index = self._indices[binary_id]

        all_strings: list[str] = []
        for e in index.entries:
            if not e.is_thunk and not e.is_library:
                all_strings.extend(e.string_refs)
        unique_strings = sorted(set(all_strings))

        url_re = re.compile(r'https?://\S+', re.IGNORECASE)
        ip_re = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$')
        reg_re = re.compile(r'^(HKEY_|HKLM\\|HKCU\\|SOFTWARE\\)', re.IGNORECASE)
        path_re = re.compile(
            r'^([A-Za-z]:\\|\\\\|/usr/|/etc/|/tmp/|%[A-Z]+%)', re.IGNORECASE
        )
        b64_re = re.compile(r'^[A-Za-z0-9+/]{40,}={0,2}$')

        categories: dict[str, list[str]] = {
            'urls': [],
            'ip_addresses': [],
            'registry_paths': [],
            'file_paths': [],
            'base64_candidates': [],
        }

        for s in unique_strings:
            if url_re.search(s):
                categories['urls'].append(s)
            elif ip_re.match(s):
                categories['ip_addresses'].append(s)
            elif reg_re.match(s):
                categories['registry_paths'].append(s)
            elif path_re.match(s):
                categories['file_paths'].append(s)
            elif b64_re.match(s):
                categories['base64_candidates'].append(s)

        for k in categories:
            categories[k] = categories[k][:limit]

        total = sum(len(v) for v in categories.values())
        return {
            "binary_id": binary_id,
            "unique_strings_total": len(unique_strings),
            "classified_total": total,
            "categories": {k: v for k, v in categories.items() if v},
        }

    @requires(BinaryState.ACTIVE)
    def detect_dynamic_resolution(self, binary_id: str, limit: int = 50) -> dict[str, Any]:
        """Find GetProcAddress/LoadLibrary calls and extract resolved API names.

        Detects runtime API resolution — a key malware evasion technique where
        imports are resolved dynamically to avoid static IAT detection.
        """
        index = self._indices[binary_id]
        import ida_funcs

        # Find functions that call GetProcAddress or LoadLibrary variants
        resolver_names = {'getprocaddress', 'loadlibrary', 'loadlibraryex',
                          'getmodulehandle', 'ldrgetprocedureaddress'}
        candidates = []
        for e in index.entries:
            if e.is_thunk or e.is_library:
                continue
            callees_norm = {_normalize_api_name(c) for c in e.callees}
            if callees_norm & resolver_names:
                candidates.append(e)

        resolved_apis: list[dict[str, Any]] = []
        loaded_libraries: list[dict[str, Any]] = []

        for entry in candidates[:20]:  # cap to avoid timeout
            ea = entry.address
            func = ida_funcs.get_func(ea)
            if func is None:
                continue
            try:
                cfunc = decompile_cfunc(func)
            except (RuntimeError, ValueError):
                continue

            # Query GetProcAddress calls — arg 1 is the API name
            gpa = query_ctree_calls(
                cfunc, target_function='GetProcAddress',
                argument_index=1, limit=limit,
            )
            for match in gpa.get('matches', []):
                if match['arg_count'] >= 2:
                    api_name = match['args_preview'][1].strip('"')
                    resolved_apis.append({
                        'function': entry.name,
                        'address': match['address'],
                        'resolved_api': api_name,
                        'is_literal': (
                            match['args_string_literal'][1]
                            if len(match['args_string_literal']) > 1 else False
                        ),
                    })

            # Query LoadLibrary calls — arg 0 is the DLL name
            for ll_name in ['LoadLibrary', 'LoadLibraryEx', 'GetModuleHandle']:
                ll = query_ctree_calls(
                    cfunc, target_function=ll_name,
                    argument_index=0, limit=10,
                )
                for match in ll.get('matches', []):
                    if match['arg_count'] >= 1:
                        dll_name = match['args_preview'][0].strip('"')
                        loaded_libraries.append({
                            'function': entry.name,
                            'address': match['address'],
                            'library': dll_name,
                            'is_literal': match['args_string_literal'][0] if match['args_string_literal'] else False,
                        })

            if len(resolved_apis) >= limit:
                break

        return {
            'binary_id': binary_id,
            'dynamic_resolution_detected': len(resolved_apis) > 0 or len(loaded_libraries) > 0,
            'resolved_apis': resolved_apis[:limit],
            'loaded_libraries': loaded_libraries[:limit],
            'functions_with_resolution': len(candidates),
        }

    @requires(BinaryState.ACTIVE)
    def path_feasibility(
        self,
        binary_id: str,
        source_address: str,
        sink_address: str,
        *,
        timeout_seconds: int = 60,
        max_steps: int = 200000,
    ) -> dict[str, Any]:
        """Use angr symbolic execution to check if a path from source to sink is feasible."""
        import time

        import angr
        import claripy  # noqa: F401 — used for constraint inspection

        rec = self._require(binary_id)
        source_ea = int(source_address.strip(), 16) if isinstance(source_address, str) else source_address
        sink_ea = int(sink_address.strip(), 16) if isinstance(sink_address, str) else sink_address

        proj = angr.Project(str(rec.path), auto_load_libs=False)
        state = proj.factory.blank_state(addr=source_ea)
        simgr = proj.factory.simulation_manager(state)

        t0 = time.monotonic()
        deadline = t0 + timeout_seconds
        steps_taken = 0
        found = False
        timed_out = False

        try:
            while simgr.active and steps_taken < max_steps:
                if time.monotonic() > deadline:
                    timed_out = True
                    break
                simgr.step()
                steps_taken += 1
                # Check if any state reached the sink
                reached = [s for s in simgr.active if s.addr == sink_ea]
                if reached:
                    found = True
                    break
                # Also check stashes
                simgr.move(from_stash='active', to_stash='found',
                          filter_func=lambda s: s.addr == sink_ea)
                if simgr.found:
                    found = True
                    break
                # Limit active states to prevent explosion
                if len(simgr.active) > 64:
                    simgr.active = simgr.active[:64]
        except (TimeoutError, angr.errors.SimEngineError, Exception) as exc:
            return {
                "binary_id": binary_id,
                "source": f"0x{source_ea:x}",
                "sink": f"0x{sink_ea:x}",
                "feasible": None,
                "verdict": "error",
                "error": f"{type(exc).__name__}: {exc}",
                "steps": steps_taken,
                "elapsed_s": round(time.monotonic() - t0, 2),
            }

        elapsed = round(time.monotonic() - t0, 2)
        constraint_count = 0
        if found:
            winning = simgr.found[0] if simgr.found else reached[0]
            constraint_count = len(winning.solver.constraints)

        return {
            "binary_id": binary_id,
            "source": f"0x{source_ea:x}",
            "sink": f"0x{sink_ea:x}",
            "feasible": found,
            "verdict": "feasible" if found else ("timeout" if timed_out else "infeasible"),
            "steps": steps_taken,
            "elapsed_s": elapsed,
            "constraint_count": constraint_count,
            "active_states_at_end": len(simgr.active),
        }

    @requires(BinaryState.ACTIVE)
    def find_paths(
        self,
        binary_id: str,
        from_address: str,
        to_address: str,
        *,
        avoid_addresses: list[str] | None = None,
        timeout_seconds: int = 60,
        max_paths: int = 3,
    ) -> dict[str, Any]:
        """Use angr exploration to find execution paths between two points."""
        import time

        import angr

        rec = self._require(binary_id)
        from_ea = int(from_address.strip(), 16)
        to_ea = int(to_address.strip(), 16)
        avoid_eas = [int(a.strip(), 16) for a in (avoid_addresses or [])]

        proj = angr.Project(str(rec.path), auto_load_libs=False)
        state = proj.factory.blank_state(addr=from_ea)
        simgr = proj.factory.simulation_manager(state)

        t0 = time.monotonic()
        try:
            simgr.explore(
                find=to_ea,
                avoid=avoid_eas,
                timeout=timeout_seconds,
                num_find=max_paths,
            )
        except (angr.errors.SimEngineError, Exception) as exc:
            return {
                "binary_id": binary_id,
                "from": f"0x{from_ea:x}",
                "to": f"0x{to_ea:x}",
                "paths_found": 0,
                "verdict": "error",
                "error": f"{type(exc).__name__}: {exc}",
                "elapsed_s": round(time.monotonic() - t0, 2),
            }

        elapsed = round(time.monotonic() - t0, 2)
        paths: list[dict[str, Any]] = []
        for found_state in simgr.found[:max_paths]:
            history_addrs = list(found_state.history.bbl_addrs)
            paths.append({
                "block_count": len(history_addrs),
                "blocks": [f"0x{a:x}" for a in history_addrs[:50]],
                "constraint_count": len(found_state.solver.constraints),
                "truncated": len(history_addrs) > 50,
            })

        return {
            "binary_id": binary_id,
            "from": f"0x{from_ea:x}",
            "to": f"0x{to_ea:x}",
            "avoid": [f"0x{a:x}" for a in avoid_eas],
            "paths_found": len(paths),
            "verdict": "found" if paths else ("no_path" if not simgr.active else "exhausted"),
            "paths": paths,
            "elapsed_s": elapsed,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _require(self, binary_id: str) -> BinaryRecord:
        try:
            return self._records[binary_id]
        except KeyError as exc:
            raise KeyError(f"Unknown binary_id: {binary_id}") from exc

    def _activate(self, binary_id: str) -> None:
        """Ensure binary is the active IDA database. Uses lifecycle state machine."""
        rec = self._require(binary_id)
        lc = self._lifecycle.get(binary_id)
        if lc is None:
            raise KeyError(f"No lifecycle for binary_id: {binary_id}")

        # Already active in idalib?
        if self._active_binary_id == binary_id and rec.analysis_ready:
            return

        # Check if .i64 is ready
        self._lifecycle._reconcile(lc)
        if lc.state < BinaryState.READY:
            raise RuntimeError(
                f"Binary {binary_id} is still in state {lc.state.name}. "
                f"Use poll_analysis to check progress. "
                f"Background idat64 is creating the .i64 database."
            )

        # Close whatever is currently open in idalib
        try:
            self._ida.close_database(True)
        except (RuntimeError, OSError):
            pass
        if self._active_binary_id and self._active_binary_id in self._records:
            self._records[self._active_binary_id].active = False

        # Open the .i64 (0.65s warm)
        workspace_binary = self._lifecycle.workspace_binary(lc)
        self._open_database(workspace_binary)

        # Fill in real metadata from IDA
        import ida_funcs
        import ida_strlist
        import idautils
        rec.function_count = ida_funcs.get_func_qty()
        rec.exports_count = len(list(idautils.Entries()))
        rec.strings_count = ida_strlist.get_strlist_qty()
        rec.active = True
        rec.analysis_ready = True
        self._active_binary_id = binary_id

        # Update lifecycle state
        lc.state = BinaryState.ACTIVE
        lc.function_count = rec.function_count
        self._lifecycle._save(lc)

        # Load cached index if available
        index_path = self._index_cache_path(rec.sha256)
        if index_path.exists() and binary_id not in self._indices:
            self._indices[binary_id] = FunctionIndex.load(index_path)

    def _open_database(self, path: Path) -> None:
        # Clean stale lock files from prior hard-kill. IDA uses .id0/.id1/.nam/.til
        # as intermediate format; if the process was killed mid-analysis, these
        # remain and block re-open with error code 4.
        for ext in ('.id0', '.id1', '.id2', '.nam', '.til'):
            stale = path.parent / (path.name + ext)
            if stale.exists():
                try:
                    stale.unlink()
                except OSError:
                    pass
        rc = self._ida.open_database(str(path), True)
        if rc != 0:
            raise RuntimeError(f"open_database failed for {path} with code {rc}")


    def _ensure_analysis(self) -> None:
        """Block until auto-analysis is complete. Call only when full index is needed."""
        import ida_auto
        if not ida_auto.auto_is_ok():
            ida_auto.auto_wait()

    def _ensure_indexed(self, binary_id: str) -> None:
        """Ensure the function index exists for this binary. Blocks on analysis if needed."""
        if binary_id in self._indices:
            return
        self._ensure_analysis()
        rec = self._require(binary_id)
        self._indices[binary_id] = self._load_or_build_index(rec.sha256)

    def _collect_metadata(self, *, binary_id: str, path: Path, sha256: str, size_bytes: int) -> BinaryRecord:
        import ida_funcs
        import ida_loader
        import ida_nalt
        import ida_segment
        import ida_strlist
        import idautils
        import idc

        sections: list[dict[str, Any]] = []
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if seg is None:
                continue
            sections.append(
                {
                    "name": ida_segment.get_segm_name(seg),
                    "start": f"0x{seg.start_ea:x}",
                    "end": f"0x{seg.end_ea:x}",
                    "size_bytes": seg.size(),
                    "permissions": _seg_perms(seg),
                }
            )

        imports_count = 0
        for i in range(ida_nalt.get_import_module_qty()):
            collector: list[int] = []
            ida_nalt.enum_import_names(i, lambda _ea, _name, _ord: collector.append(1) or True)
            imports_count += len(collector)

        exports_count = len(list(idautils.Entries()))
        badaddr = (1 << _bitness()) - 1
        entry_points = [
            f"0x{ea:x}" for ea in (idc.get_entry(i) for i in range(idc.get_entry_qty())) if ea != badaddr
        ]
        mitigations = _pe_mitigations(path) if path.suffix.lower() in {".exe", ".dll", ".sys"} else {"type": "unknown"}

        return BinaryRecord(
            binary_id=binary_id,
            path=path,
            sha256=sha256,
            size_bytes=size_bytes,
            format=str(ida_loader.get_file_type_name()),
            arch=ida_nalt.get_root_filename() and _arch_name() or "unknown",
            bits=_bitness(),
            entry_points=entry_points,
            function_count=ida_funcs.get_func_qty(),
            segment_count=ida_segment.get_segm_qty(),
            imports_count=imports_count,
            exports_count=exports_count,
            strings_count=ida_strlist.get_strlist_qty(),
            mitigations=mitigations,
            sections=sections,
            active=True,
            root_filename=ida_nalt.get_root_filename(),
        )

    def _cache_file(self, sha256: str, address_or_name: str) -> Path:
        safe = address_or_name.replace("/", "_").replace("\\", "_").replace(":", "_")
        return self.settings.cache_dir / sha256 / "decompile" / f"{safe}.json"

    def _index_cache_path(self, sha256: str) -> Path:
        return self.settings.cache_dir / sha256 / "index.json"

    def _workspace_path(self, sha256: str) -> Path:
        return self.settings.cache_dir / sha256 / "workspace"

    def _pattern_cache_path(self, sha256: str, pattern_type: str) -> Path:
        return self.settings.cache_dir / sha256 / "patterns" / f"{pattern_type}_v1.json"

    def _load_or_build_index(self, sha256: str) -> FunctionIndex:
        index_path = self._index_cache_path(sha256)
        if index_path.exists():
            return FunctionIndex.load(index_path)
        index = build_function_index()
        index.save(index_path)
        return index

    def _touch_manifest(self, sha256: str, root_filename: str, function_count: int) -> None:
        import time

        manifest: dict[str, Any] = {}
        if self._manifest_path.exists():
            try:
                manifest = json.loads(self._manifest_path.read_text(encoding='utf-8'))
            except (OSError, json.JSONDecodeError):
                pass
        manifest[sha256] = {
            "last_accessed": time.time(),
            "root_filename": root_filename,
            "function_count": function_count,
        }
        self._manifest_path.write_text(json.dumps(manifest, indent=2), encoding='utf-8')

    def evict_lru(self, keep_n: int = 50) -> list[str]:
        """Remove cache for least-recently-used binaries beyond ``keep_n``.

        Returns:
            List of evicted SHA256 prefixes.
        """
        import shutil

        if not self._manifest_path.exists():
            return []
        manifest: dict[str, Any] = json.loads(self._manifest_path.read_text(encoding='utf-8'))
        by_time = sorted(manifest.items(), key=lambda kv: kv[1].get('last_accessed', 0))
        evicted: list[str] = []
        for sha, _meta in by_time[:-keep_n] if len(by_time) > keep_n else []:
            target = self.settings.cache_dir / sha
            if target.is_dir():
                shutil.rmtree(target, ignore_errors=True)
            del manifest[sha]
            evicted.append(sha)
        if evicted:
            self._manifest_path.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        return evicted


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _resolve_address(address_or_name: str) -> int:
    import ida_idaapi
    import ida_name

    target = address_or_name.strip()
    if target.startswith(("0x", "0X")):
        return int(target, 16)
    try:
        return int(target)
    except ValueError:
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, target)
        if ea == ida_idaapi.BADADDR:
            raise ValueError(f"Cannot resolve address or function name: {address_or_name!r}")
        return ea


def _bitness() -> int:
    import ida_ida

    return 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit_exactly() else 16)


def _arch_name() -> str:
    import ida_ida

    return str(ida_ida.inf_get_procname())


def _xref_type_name(xtype: int) -> str:
    """Convert xref type constant to name. IDA 9.0 removed get_xref_type_name."""
    names = {
        0: 'Data_Unknown', 1: 'Data_Offset', 2: 'Data_Write', 3: 'Data_Read',
        4: 'Data_Text', 5: 'Data_Informational',
        16: 'Code_Far_Call', 17: 'Code_Near_Call', 18: 'Code_Far_Jump',
        19: 'Code_Near_Jump', 20: 'Code_User', 21: 'Ordinary_Flow',
    }
    return names.get(xtype, f'type_{xtype}')


def _seg_perms(seg: Any) -> str:
    import ida_segment

    r = "r" if seg.perm & ida_segment.SEGPERM_READ else "-"
    w = "w" if seg.perm & ida_segment.SEGPERM_WRITE else "-"
    x = "x" if seg.perm & ida_segment.SEGPERM_EXEC else "-"
    return f"{r}{w}{x}"


def _pe_mitigations(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if data[:2] != b"MZ":
        return {"type": "not_pe"}
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off+4] != b"PE\0\0":
        return {"type": "bad_pe"}
    opt_off = pe_off + 4 + 20
    magic = struct.unpack_from("<H", data, opt_off)[0]
    dll_off = opt_off + (70 if magic == 0x20B else 66)
    dll_chars = struct.unpack_from("<H", data, dll_off)[0]
    image_dllcharacteristics_dynamic_base = 0x0040
    image_dllcharacteristics_nx_compat = 0x0100
    image_dllcharacteristics_guard_cf = 0x4000
    return {
        "type": "pe",
        "aslr_pie": bool(dll_chars & image_dllcharacteristics_dynamic_base),
        "nx": bool(dll_chars & image_dllcharacteristics_nx_compat),
        "cfg": bool(dll_chars & image_dllcharacteristics_guard_cf),
        "raw_dll_characteristics": hex(dll_chars),
    }



def _normalize_api_name(name: str) -> str:
    """Normalize a Windows API name for matching.

    Strips the ``j_`` prefix and trailing ``A``/``W``/``Ex`` suffix, then
    lowercases the result.

    Examples:
        ``CreateProcessW`` -> ``createprocess``
        ``j_IsDebuggerPresent`` -> ``isdebuggerpresent``
        ``LoadLibraryExW`` -> ``loadlibrary``
    """
    n = name.strip().lower()
    if n.startswith('j_'):
        n = n[2:]
    # Strip trailing W, A, ExW, ExA (but not single-char names)
    if len(n) > 3:
        if n.endswith('exw') or n.endswith('exa'):
            n = n[:-3]
        elif n.endswith('w') or n.endswith('a'):
            # Only strip if it looks like a suffix (preceded by lowercase)
            if len(n) > 1 and n[-2].islower():
                n = n[:-1]
    return n
