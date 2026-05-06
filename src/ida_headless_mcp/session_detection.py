"""Detection tool implementations for ``IDABinarySessionManager``.

This mixin class is composed into :class:`IDABinarySessionManager` and groups
the malware/behavior/string detection style methods. Methods access host
attributes such as ``self._indices`` and ``self._require``; those are owned by
the core class.
"""

from __future__ import annotations

from typing import Any

from ._resolve import _normalize_api_name, _resolve_address
from .guards import requires
from .hexrays_analysis import decompile_cfunc, query_ctree_calls
from .lifecycle import BinaryState

__all__ = ["DetectionMixin"]


class DetectionMixin:
    """Detection tool implementations for IDABinarySessionManager."""

    @requires(BinaryState.ACTIVE)
    def detect_stack_strings(self, binary_id: str, address_or_name: str) -> dict:
        """Detect strings constructed on the stack at runtime.

        Reconstructs strings written byte/word/dword/qword at a time to stack
        frame slots. Uses the destination displacement (not instruction order)
        to place bytes in a virtual stack buffer keyed by ``(base_reg, offset)``,
        then extracts maximal runs of printable ASCII (and UTF-16LE) of length
        >= 4 -- the same threshold FLOSS uses for its mov heuristic.

        Handles patterns produced by:
            * MSVC-style byte stores: ``mov byte ptr [rbp-X], 'c'``
            * Clang -O1 packed stores: ``mov qword ptr [rbp-X], <imm64>``
            * lea + mov forwarding: ``lea rax, [rbp-X]; mov [rax+N], imm``

        Args:
            binary_id: Opaque binary handle.
            address_or_name: Function address (``0x...``) or name to scan.

        Returns:
            Mapping with ``binary_id``, ``function``, ``stack_strings_found``
            count, and a ``strings`` list of ``{string, address, stack_offset,
            length, encoding}`` entries sorted by source instruction address.
        """
        import ida_funcs
        import ida_idp
        import ida_ua
        import idautils

        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")

        STACK_REGS = {"rsp", "rbp", "esp", "ebp", "sp", "bp"}
        SIGN_MASK_64 = 1 << 63
        SIGN_WRAP_64 = 1 << 64

        def _signed(val: int) -> int:
            """Two's-complement sign-extend a 64-bit displacement."""
            return val - SIGN_WRAP_64 if val & SIGN_MASK_64 else val

        def _reg_canonical(reg_idx: int) -> str:
            """Pick the widest valid name for a register index."""
            for sz in (8, 4, 2, 1):
                name = ida_idp.get_reg_name(reg_idx, sz)
                if name:
                    return name.lower()
            return ""

        width_for_dtype = {
            ida_ua.dt_byte: 1,
            ida_ua.dt_word: 2,
            ida_ua.dt_dword: 4,
            ida_ua.dt_qword: 8,
        }
        mask_for_dtype = {
            ida_ua.dt_byte: 0xFF,
            ida_ua.dt_word: 0xFFFF,
            ida_ua.dt_dword: 0xFFFFFFFF,
            ida_ua.dt_qword: (1 << 64) - 1,
        }

        # Mnemonics whose op0=reg writes to the destination register.  Used to
        # invalidate stale ``lea`` aliases when the alias register is reloaded.
        REG_CLOBBER_MNEMS = {
            "mov", "movsx", "movzx", "movsxd", "lea", "xor", "and", "or",
            "add", "sub", "shl", "shr", "sar", "rol", "ror", "imul", "mul",
            "neg", "not", "inc", "dec", "pop", "xchg", "bswap", "lzcnt",
            "tzcnt", "popcnt", "cmove", "cmovne", "cmovz", "cmovnz",
            "cmovl", "cmovle", "cmovg", "cmovge", "cmova", "cmovae",
            "cmovb", "cmovbe", "cmovs", "cmovns",
        }

        # Virtual stack buffer: (base_reg, signed_offset) -> (byte, source_ea).
        # Last write wins -- mirrors real CPU semantics for overlapping stores.
        buffer: dict[tuple[str, int], tuple[int, int]] = {}

        # Aliases established by ``lea reg, [stack_reg + disp]``.
        aliases: dict[str, tuple[str, int]] = {}

        for head in idautils.Heads(func.start_ea, func.end_ea):
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, head) <= 0:
                continue

            mnem = (ida_ua.ua_mnem(head) or "").lower()
            dst = insn.ops[0]
            src = insn.ops[1]

            # Establish/refresh stack alias from a ``lea``.
            if (
                mnem == "lea"
                and dst.type == ida_ua.o_reg
                and src.type in (ida_ua.o_displ, ida_ua.o_phrase)
            ):
                dst_name = _reg_canonical(dst.reg)
                if dst_name:
                    aliases.pop(dst_name, None)
                    src_base = _reg_canonical(src.reg)
                    if src_base in STACK_REGS:
                        src_disp = (
                            _signed(src.addr) if src.type == ida_ua.o_displ else 0
                        )
                        aliases[dst_name] = (src_base, src_disp)
                continue

            # Any other reg-destination instruction kills a tracked alias.
            if (
                mnem in REG_CLOBBER_MNEMS
                and dst.type == ida_ua.o_reg
            ):
                clobbered = _reg_canonical(dst.reg)
                if clobbered:
                    aliases.pop(clobbered, None)
            elif mnem == "call":
                # Calls clobber volatile regs; flush all aliases conservatively.
                aliases.clear()

            if mnem != "mov":
                continue
            if dst.type not in (ida_ua.o_displ, ida_ua.o_phrase):
                continue
            if src.type != ida_ua.o_imm:
                continue
            if dst.dtype not in width_for_dtype:
                continue

            base_name = _reg_canonical(dst.reg)
            disp = _signed(dst.addr) if dst.type == ida_ua.o_displ else 0

            if base_name in STACK_REGS:
                stack_base, stack_offset = base_name, disp
            elif base_name in aliases:
                alias_base, alias_off = aliases[base_name]
                stack_base, stack_offset = alias_base, alias_off + disp
            else:
                continue

            width = width_for_dtype[dst.dtype]
            value = src.value & mask_for_dtype[dst.dtype]
            try:
                raw = value.to_bytes(width, "little")
            except OverflowError:
                continue

            for i, byte in enumerate(raw):
                buffer[(stack_base, stack_offset + i)] = (byte, head)

        # Group buffer entries by stack base so each frame slot is scanned in
        # offset order, independent of the instruction order that wrote them.
        grouped: dict[str, dict[int, tuple[int, int]]] = {}
        for (base, off), (byte, src_ea) in buffer.items():
            grouped.setdefault(base, {})[off] = (byte, src_ea)

        strings_found: list[dict] = []
        seen: set[tuple[str, int, str]] = set()

        for base, slots in grouped.items():
            offsets = sorted(slots.keys())
            if not offsets:
                continue

            # ASCII pass: maximal runs of consecutive printable bytes.
            i = 0
            while i < len(offsets):
                start_i = i
                run_offset = offsets[i]
                run_bytes: list[int] = []
                run_ea = slots[run_offset][1]
                prev_off = run_offset - 1
                while i < len(offsets):
                    off = offsets[i]
                    byte, _ea = slots[off]
                    if off != prev_off + 1 or not (0x20 <= byte <= 0x7E):
                        break
                    run_bytes.append(byte)
                    prev_off = off
                    i += 1
                if len(run_bytes) >= 4:
                    key = (base, run_offset, "ascii")
                    if key not in seen:
                        seen.add(key)
                        strings_found.append({
                            "string": "".join(chr(b) for b in run_bytes),
                            "address": f"0x{run_ea:x}",
                            "stack_offset": run_offset,
                            "length": len(run_bytes),
                            "encoding": "ascii",
                        })
                if i == start_i:
                    i += 1

            # UTF-16LE pass: pairs of (printable_low, 0x00) for >= 4 chars.
            i = 0
            while i < len(offsets):
                start_i = i
                start_off = offsets[i]
                chars: list[int] = []
                char_ea = slots[start_off][1]
                cur = start_off
                while cur in slots and (cur + 1) in slots:
                    lo, ea_lo = slots[cur]
                    hi, _ea_hi = slots[cur + 1]
                    if hi != 0 or not (0x20 <= lo <= 0x7E):
                        break
                    if not chars:
                        char_ea = ea_lo
                    chars.append(lo)
                    cur += 2
                if len(chars) >= 4:
                    key = (base, start_off, "utf16le")
                    if key not in seen:
                        seen.add(key)
                        strings_found.append({
                            "string": "".join(chr(c) for c in chars),
                            "address": f"0x{char_ea:x}",
                            "stack_offset": start_off,
                            "length": len(chars),
                            "encoding": "utf16le",
                        })
                    while i < len(offsets) and offsets[i] < cur:
                        i += 1
                if i == start_i:
                    i += 1

        strings_found.sort(key=lambda s: (int(s["address"], 16), s["encoding"]))

        return {
            "binary_id": binary_id,
            "function": address_or_name,
            "stack_strings_found": len(strings_found),
            "strings": strings_found,
        }

    @requires(BinaryState.ACTIVE)
    def generate_yara_rule(self, binary_id: str, address_or_name: str) -> dict:
        """Generate a YARA rule from function basic blocks with relocation masking.

        Algorithm (ported from Willi Ballenthin / FLARE team):
        1. Split function into basic blocks via FlowChart
        2. For each BB, iterate instructions
        3. Use ida_fixups to detect relocated bytes -> wildcard them
        4. Wildcard entire call instructions (targets always change)
        5. Drop trailing jumps from each BB
        6. Skip BBs with fewer than 4 unmasked bytes
        7. Condition: 'all of them' for precision, or N-of-M for resilience
        """
        import hashlib

        import ida_bytes
        import ida_funcs
        import ida_name
        import ida_ua
        import idaapi
        import idautils

        MIN_BB_BYTE_COUNT = 4

        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")

        func_name = ida_name.get_ea_name(func.start_ea) or f"sub_{func.start_ea:x}"
        safe_name = "".join(c if c.isalnum() or c == "_" else "_" for c in func_name)

        def _is_jump(va: int) -> bool:
            """Check if instruction at va is a jump."""
            mnem = ida_ua.ua_mnem(va) or ""
            return mnem.startswith("j")

        def _is_call(va: int) -> bool:
            """Check if instruction at va is a call."""
            mnem = ida_ua.ua_mnem(va) or ""
            return mnem == "call"

        def _get_fixup_byte_addrs(va: int, size: int) -> set:
            """Get set of byte addresses that have fixup/relocation info."""
            addrs = set()
            if not idaapi.contains_fixups(va, size):
                return addrs
            fixup_ea = idaapi.get_next_fixup_ea(va)
            while fixup_ea < va + size:
                # Fixup is typically 4 bytes (32-bit reloc) or 8 bytes
                fixup_size = 4  # Conservative default for x86_64 RIP-relative
                for i in range(fixup_size):
                    addrs.add(fixup_ea + i)
                fixup_ea = idaapi.get_next_fixup_ea(fixup_ea + fixup_size)
            return addrs

        def _mask_basic_block(bb_start: int, bb_end: int) -> list:
            """Generate masked hex bytes for one basic block."""
            masked = []
            insn_vas = []
            va = bb_start
            while va < bb_end and va != idaapi.BADADDR:
                insn_vas.append(va)
                va = ida_bytes.next_head(va, bb_end)

            if not insn_vas:
                return masked

            # Drop trailing jump
            if _is_jump(insn_vas[-1]):
                insn_vas = insn_vas[:-1]

            for va in insn_vas:
                size = ida_bytes.get_item_size(va)
                raw = ida_bytes.get_bytes(va, size)
                if not raw:
                    continue

                if _is_call(va):
                    # Wildcard entire call instruction
                    masked.extend(["??"] * size)
                else:
                    fixup_addrs = _get_fixup_byte_addrs(va, size)
                    for i, b in enumerate(raw):
                        if (va + i) in fixup_addrs:
                            masked.append("??")
                        else:
                            masked.append(f"{b:02X}")

            return masked

        # Generate per-basic-block patterns
        bb_rules = []
        for bb in idaapi.FlowChart(func):
            masked = _mask_basic_block(bb.start_ea, bb.end_ea)
            # Count non-masked bytes
            unmasked = sum(1 for b in masked if b != "??")
            if unmasked < MIN_BB_BYTE_COUNT:
                continue
            bb_rules.append((bb.start_ea, masked))

        if not bb_rules:
            return {"binary_id": binary_id, "error": "No suitable basic blocks"}

        # Build rule
        sha = hashlib.sha256(
            ida_bytes.get_bytes(func.start_ea, min(func.size(), 64)) or b""
        ).hexdigest()[:12]

        strings_lines = []
        for i, (bb_va, masked) in enumerate(bb_rules):
            hex_str = " ".join(masked)
            strings_lines.append(
                f"        $bb_{i}_0x{bb_va:x} = {{ {hex_str} }}"
            )
        strings_block = "\n".join(strings_lines)

        # Condition: all BBs for precision, or 2/3 if many blocks
        n_blocks = len(bb_rules)
        if n_blocks <= 3:
            condition = "all of them"
        else:
            threshold = max(2, n_blocks * 2 // 3)
            condition = f"{threshold} of them"

        rule = (
            f"rule {safe_name}_{sha} {{\n"
            f"    meta:\n"
            f"        description = \"Auto-generated from {func_name}\"\n"
            f"        address = \"0x{func.start_ea:x}\"\n"
            f"        size = {func.size()}\n"
            f"        basic_blocks = {n_blocks}\n"
            f"    strings:\n"
            f"{strings_block}\n"
            f"    condition:\n"
            f"        {condition}\n"
            f"}}"
        )

        total_bytes = sum(len(m) for _, m in bb_rules)
        wildcarded = sum(1 for _, m in bb_rules for b in m if b == "??")

        return {
            "binary_id": binary_id, "function": func_name,
            "address": f"0x{func.start_ea:x}", "size": func.size(),
            "rule": rule, "basic_blocks": n_blocks,
            "wildcarded_bytes": wildcarded, "total_bytes": total_bytes,
        }

    @requires(BinaryState.INDEXED)
    def capa_scan(self, binary_id: str) -> dict:
        """Evaluate 678 CAPA behavioral rules against the binary.

        Library functions (CRT helpers, vendor SDKs, FLIRT-tagged code)
        are excluded from rule evaluation so that imported behavior the
        user did not author cannot trigger CAPA matches.

        Args:
            binary_id: Opaque handle from ``open_binary``.

        Returns:
            Dict with matched capabilities, ATT&CK mappings, and per
            capability ``context`` records describing the triggering
            functions (address, name, size, and up to 3 other callees).
        """
        from .capa_rules import capa_scan
        idx = self._indices.get(binary_id)
        if not idx:
            return {"binary_id": binary_id, "matches": 0, "capabilities": []}
        user_entries = [e for e in idx.entries if not e.is_library]
        entries = [
            {"name": e.name, "callees": list(e.callees), "string_refs": list(e.string_refs)}
            for e in user_entries
        ]
        result = capa_scan(entries)
        by_name = {e.name: e for e in user_entries}
        for cap in result.get("capabilities", []):
            matched_apis = {a.lower() for a in cap.get("matched_apis", [])}
            contexts: list[dict[str, Any]] = []
            for fname in cap.get("functions", []):
                entry = by_name.get(fname)
                if entry is None:
                    continue
                other_callees = [
                    c for c in entry.callees if c.lower() not in matched_apis
                ][:3]
                contexts.append({
                    "address": f"0x{entry.address:x}",
                    "name": entry.name,
                    "size": entry.size_bytes,
                    "other_callees": other_callees,
                })
            cap["context"] = contexts
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
            # imports() may fail if the binary isn't fully loaded; behavioral
            # categorization still works on the callee-derived API set alone.
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
            # imports() may fail if the binary isn't fully loaded; anti-analysis
            # detection still runs on the callee-derived API set alone.
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
            "total_unique_strings": len(unique_strings),
            "total_classified": total,
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
