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
from .hexrays_analysis import (
    decompile_cfunc,
    get_argument_names,
    get_hexrays_warnings,
    get_microcode_text,
    pseudocode_slice,
    query_ctree_call_sequences,
    query_ctree_calls,
    query_ctree_unchecked_calls,
    trace_ctree_dataflow,
)

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

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def open_binary(self, path: str) -> BinaryRecord:
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
            self._activate(binary_id)
            record = self._records[binary_id]
            record.active = True
            self._touch_manifest(sha256, record.root_filename, record.function_count)
            return record

        if self._active_binary_id is not None:
            self._ida.close_database(False)
            self._records[self._active_binary_id].active = False

        self._open_database(target)
        record = self._collect_metadata(binary_id=binary_id, path=target, sha256=sha256, size_bytes=size_bytes)
        self._records[binary_id] = record
        self._indices[binary_id] = self._load_or_build_index(sha256)
        self._active_binary_id = binary_id
        self._touch_manifest(sha256, record.root_filename, record.function_count)
        return record

    def close_binary(self, binary_id: str, save: bool = False) -> dict[str, Any]:
        if self._active_binary_id == binary_id:
            self._ida.close_database(save)
            self._active_binary_id = None
        del self._records[binary_id]
        self._indices.pop(binary_id, None)
        return {"binary_id": binary_id, "closed": True}

    def list_binaries(self) -> list[dict[str, Any]]:
        return [
            {
                "binary_id": rec.binary_id,
                "path": str(rec.path),
                "format": rec.format,
                "arch": rec.arch,
                "bits": rec.bits,
                "active": rec.binary_id == self._active_binary_id,
                "function_count": rec.function_count,
            }
            for rec in self._records.values()
        ]

    def binary_metadata(self, binary_id: str) -> dict[str, Any]:
        rec = self._require(binary_id)
        return {
            "binary_id": rec.binary_id,
            "path": str(rec.path),
            "sha256": rec.sha256,
            "size_bytes": rec.size_bytes,
            "format": rec.format,
            "arch": rec.arch,
            "bits": rec.bits,
            "root_filename": rec.root_filename,
            "entry_points": rec.entry_points,
            "function_count": rec.function_count,
            "segment_count": rec.segment_count,
            "imports_count": rec.imports_count,
            "exports_count": rec.exports_count,
            "strings_count": rec.strings_count,
            "mitigations": rec.mitigations,
            "sections": rec.sections,
            "active": rec.binary_id == self._active_binary_id,
        }

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
        }
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(json.dumps(result, indent=2), encoding="utf-8")

        return result

    def xrefs_to(self, binary_id: str, address_or_name: str) -> dict[str, Any]:
        self._activate(binary_id)
        import ida_funcs
        import ida_xref
        import idautils

        ea = _resolve_address(address_or_name)
        refs: list[dict[str, Any]] = []
        for xref in idautils.XrefsTo(ea):
            func = ida_funcs.get_func(xref.frm)
            refs.append(
                {
                    "from_address": f"0x{xref.frm:x}",
                    "from_function": ida_funcs.get_func_name(func.start_ea) if func else None,
                    "type": ida_xref.get_xref_type_name(xref.type),
                }
            )
        return {"binary_id": binary_id, "address": f"0x{ea:x}", "total": len(refs), "xrefs": refs}

    def xrefs_from(self, binary_id: str, address_or_name: str) -> dict[str, Any]:
        self._activate(binary_id)
        import ida_funcs
        import ida_xref
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
                        "type": ida_xref.get_xref_type_name(xref.type),
                    }
                )
        return {
            "binary_id": binary_id,
            "address": f"0x{func.start_ea:x}",
            "name": ida_funcs.get_func_name(func.start_ea),
            "xrefs": refs,
        }

    def imports(self, binary_id: str) -> dict[str, Any]:
        self._activate(binary_id)
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

    def exports(self, binary_id: str) -> dict[str, Any]:
        self._activate(binary_id)
        import idautils

        results = [
            {
                "address": f"0x{ea:x}",
                "name": name,
                "ordinal": ordn,
            }
            for ea, ordn, name in idautils.Entries()
        ]
        return {"binary_id": binary_id, "total": len(results), "exports": results}

    def segments(self, binary_id: str) -> dict[str, Any]:
        rec = self._require(binary_id)
        return {"binary_id": binary_id, "total": len(rec.sections), "segments": rec.sections}

    def checksec(self, binary_id: str) -> dict[str, Any]:
        rec = self._require(binary_id)
        return {"binary_id": binary_id, **rec.mitigations}

    def stack_frame(self, binary_id: str, address_or_name: str) -> dict[str, Any]:
        self._activate(binary_id)
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

    def call_graph(
        self,
        binary_id: str,
        address_or_name: str,
        depth: int = 2,
        direction: str = "both",
    ) -> dict[str, Any]:
        self._activate(binary_id)
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
        self._activate(binary_id)
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
            self.decompile(binary_id, item["address"], max_lines=max_lines)
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

    def search_pattern(
        self,
        binary_id: str,
        pattern_type: str,
        *,
        name_pattern: str = "",
        limit: int = 50,
        max_lines: int = 120,
    ) -> dict[str, Any]:
        self._activate(binary_id)
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
                    decomp = self.decompile(binary_id, item["address"], max_lines=max_lines)
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
                    decomp = self.decompile(binary_id, item["address"], max_lines=max_lines)
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
                    decomp = self.decompile(binary_id, item["address"], max_lines=max_lines)
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
                    decomp = self.decompile(binary_id, item["address"], max_lines=max_lines)
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
                    decomp = self.decompile(binary_id, item["address"], max_lines=max_lines)
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
                    decomp = self.decompile(binary_id, item["address"], max_lines=max_lines)
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
                    decomp = self.decompile(binary_id, item["address"], max_lines=max_lines)
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
                    decomp = self.decompile(binary_id, item["address"], max_lines=max_lines)
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
                    decomp = self.decompile(binary_id, item["address"], max_lines=max_lines)
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
                decomp = self.decompile(binary_id, item["address"], max_lines=max_lines)
            matches.append({
                "address": item["address"],
                "name": item["name"],
                "detail": match_detail,
                "callees": item.get("callees", []),
                "string_refs": item.get("string_refs", [])[:10],
                "decompile_preview": decomp["pseudocode"],
                "trace_dataflow": flow if pattern == "unchecked_length" else None,
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

    def diff_binary(self, binary_id_old: str, binary_id_new: str) -> dict[str, Any]:
        self._activate(binary_id_old)
        old_entries = self._indices[binary_id_old].entries
        self._activate(binary_id_new)
        new_entries = self._indices[binary_id_new].entries
        payload = diff_binary_indexes(old_entries, new_entries)
        payload.update({"binary_id_old": binary_id_old, "binary_id_new": binary_id_new})

        return payload

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
        self._activate(binary_id)
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

    def get_microcode(
        self,
        binary_id: str,
        address_or_name: str,
        *,
        maturity: str = "current",
    ) -> dict[str, Any]:
        self._activate(binary_id)
        import ida_funcs

        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")
        cfunc = decompile_cfunc(func)
        payload = get_microcode_text(cfunc, maturity=maturity)
        payload["binary_id"] = binary_id

        return payload

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
        self._activate(binary_id)
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

    def hexrays_warnings(self, binary_id: str, address_or_name: str) -> dict[str, Any]:
        self._activate(binary_id)
        import ida_funcs

        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")
        cfunc = decompile_cfunc(func)
        result = get_hexrays_warnings(cfunc)
        result["binary_id"] = binary_id
        return result

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
        self._activate(binary_id)
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

    def binary_survey(self, binary_id: str, max_hotspots: int = 10) -> dict[str, Any]:
        """One-call orientation: metadata + attack surface + hotspots + pattern hits."""
        self._activate(binary_id)
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
    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _require(self, binary_id: str) -> BinaryRecord:
        try:
            return self._records[binary_id]
        except KeyError as exc:
            raise KeyError(f"Unknown binary_id: {binary_id}") from exc

    def _activate(self, binary_id: str) -> None:
        if self._active_binary_id == binary_id:
            return
        rec = self._require(binary_id)
        if self._active_binary_id is not None:
            self._ida.close_database(False)
            self._records[self._active_binary_id].active = False
        self._open_database(rec.path)
        self._active_binary_id = binary_id
        if binary_id not in self._indices:
            self._indices[binary_id] = self._load_or_build_index(rec.sha256)
        rec.active = True

    def _open_database(self, path: Path) -> None:
        import ida_auto

        rc = self._ida.open_database(str(path), True)
        if rc != 0:
            raise RuntimeError(f"open_database failed for {path} with code {rc}")
        ida_auto.auto_wait()

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
        """Remove cache for least-recently-used binaries beyond *keep_n*.

        Returns list of evicted SHA256 prefixes.
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
