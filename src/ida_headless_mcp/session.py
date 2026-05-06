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
from .session_proof import ProofMixin
from .session_analysis import AnalysisMixin
from ._resolve import _resolve_address
from .session_detection import DetectionMixin

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


class IDABinarySessionManager(ProofMixin, AnalysisMixin, DetectionMixin):
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
        except (AttributeError, RuntimeError):
            # Best-effort console quietening; the manager works fine if IDA's
            # console-message API is unavailable in this build. The worker
            # subprocess (worker.py) is the only place where stdout cleanliness
            # is load-bearing for JSON-RPC; this in-process manager doesn't share that.
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
            "total_matched": result["total"],
            "returned": len(decompiled),
            "dropped": max(0, result["total"] - offset - len(decompiled)),
            "drop_reason": "max_results" if result["total"] > offset + len(decompiled) else None,
            "results": decompiled,
        }

        return payload


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
            # No database is currently open, or idalib refused the close; the
            # subsequent open_database call will surface any real failure.
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
                    # Best-effort cleanup of a stale IDA lock file from a prior
                    # hard-kill; if unlink fails, open_database below will fail
                    # loudly with the real error code.
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

