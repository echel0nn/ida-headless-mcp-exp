"""Analysis, query, symbolic execution, recovery, and diff tools.

This mixin class is composed into :class:`IDABinarySessionManager`. Methods
access host attributes such as ``self._indices``, ``self._require``,
``self._activate``, ``self._decompile_sync``, ``self._pattern_cache_path``,
``self.decompile``, ``self.diff_binary``, and ``self.diff_function`` -- all
owned by the core class.
"""
from __future__ import annotations

import json
from typing import Any

from ._resolve import _resolve_address
from .diff import diff_binary_indexes, diff_function_payloads
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
from .lifecycle import BinaryState

__all__ = ["AnalysisMixin"]


class AnalysisMixin:
    """Analysis, query, symbolic execution, recovery, and diff tools."""

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
        """Search for vulnerability patterns across indexed functions."""
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
        - reachable_from_entry: bool -- can this function be reached from exports/entry points?
        - argument_source: str -- where does the dangerous input come from?
        - external_input: bool -- does data flow from an external source (file/network)?
        - confidence: str -- 'high', 'medium', or 'low' exploitability assessment
        - confidence_reason: str -- why this confidence level
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
                        "Function has no callers -- possibly dead code"
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
                "Cannot prove externally-controlled data reaches the dangerous operation. "
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
                "total_functions": rec.function_count,
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
        """Query the decompiler CTree for call expressions matching predicates."""
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
        """Return textual Hex-Rays microcode for a function."""
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
    def hexrays_warnings(self, binary_id: str, address_or_name: str) -> dict[str, Any]:
        """Return Hex-Rays decompiler warnings for a function."""
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
        """Return focused pseudocode slices around call sites or addresses."""
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
        import claripy  # noqa: F401 -- used for constraint inspection

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
    def recover_class_hierarchy(self, binary_id: str) -> dict[str, Any]:
        """Recover C++ class hierarchy via .rdata vtable scan + xref analysis.

        Algorithm:
        1. Scan .rdata for vtable-shaped arrays (consecutive function pointers)
        2. For each vtable, find xrefs TO it (constructors that install it)
        3. Read vtable entries to get virtual method list
        No mass decompilation -- uses xrefs and ida_bytes only.
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
        func_entries: list[dict[str, Any]] = []
        if idx:
            func_entries = [
                {
                    "address": f"0x{e.address:x}",
                    "name": e.name,
                    "callees": list(e.callees),
                }
                for e in idx.entries
            ]
        result = recover_class_hierarchy(
            vtables[:100], func_entries, constructors=constructors,
        )
        result["binary_id"] = binary_id
        result["constructors_found"] = constructors[:50]
        return result

    @requires(BinaryState.INDEXED)
    def diff_binary(self, binary_id_old: str, binary_id_new: str) -> dict[str, Any]:
        """Diff two analyzed binaries structurally by function metadata."""
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
        """Diff two functions with side-by-side pseudocode and a unified diff."""
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
