"""Internal helpers for cff_analysis — PE parsing, BlockInfo, dispatcher chain, handler aggregation."""
from __future__ import annotations

import re
import statistics
import struct
from pathlib import Path
from typing import Any

__all__ = [
    "_load_text_section",
    "_detect_arch",
    "_ptr_size",
    "_get_immediate",
    "_branch_targets",
    "_extract_block_info",
    "_aggregate_dispatcher_chain",
    "_dispatcher_chain_addrs",
    "_candidate_dispatchers",
    "_best_match",
    "_classify_handler",
    "_state_threshold",
    "_initial_state",
    "_aggregate_handler",
    "_resolve_opaque_next_states",
]

_DISPATCHER_CHAIN_MNEMS = frozenset(
    {"SUB", "CMP", "JMP", "MOV", "JZ", "JE"})

_BRANCH_MNEMS = frozenset({"JZ", "JE", "JNZ", "JNE"})

_RIP_DISP_RE = re.compile(
    r"\[\s*RIP\s*(?P<sign>[+\-])\s*"
    r"(?P<off>0[xX][0-9a-fA-F]+|[0-9]+)\s*\]", re.IGNORECASE,
)

def _load_text_section(pe_path: Path) -> tuple[bytes, int, int]:
    """Return (section_bytes, base_va, vsize) for the code section."""
    from .binary_formats import load_code_section
    return load_code_section(pe_path)


def _detect_arch(pe_path: Path) -> str:
    """Detect architecture from binary headers."""
    from .binary_formats import detect_arch
    return detect_arch(pe_path)


def _ptr_size(arch: str) -> int:
    """Pointer width in bits."""
    from .binary_formats import ptr_size
    return ptr_size(arch)

def _get_immediate(arg: Any) -> int | None:
    """Extract an integer immediate from a miasm operand (None if absent)."""
    from miasm.expression.expression import ExprInt, ExprMem, ExprOp
    if isinstance(arg, ExprInt):
        return int(arg.arg) & ((1 << arg.size) - 1)
    if isinstance(arg, ExprOp) and arg.op == "+":
        ints = [a for a in arg.args if isinstance(a, ExprInt)]
        if len(ints) == 1 and len(arg.args) == 2:
            return int(ints[0].arg) & ((1 << ints[0].size) - 1)
    if isinstance(arg, ExprMem):
        return _get_immediate(arg.ptr)
    return None

def _branch_targets(line: Any) -> list[int]:
    """Immediate branch destinations for a control-flow instruction."""
    from miasm.expression.expression import ExprInt
    return [int(a.arg) for a in (getattr(line, "args", []) or []) if isinstance(a, ExprInt)]

def _extract_block_info(block: Any, loc_db: Any, cfg: Any, ptr_bits: int,
                        iat_map: dict[int, str] | None = None) -> Any:
    """Convert miasm AsmBlock to BlockInfo. Resolves IAT calls when iat_map given."""
    from miasm.expression.expression import ExprId, ExprInt, ExprLoc, ExprMem
    from .cff_techniques import BlockInfo

    address = loc_db.get_location_offset(block.loc_key) or 0
    instructions: list[dict[str, Any]] = []
    has_call = has_imul = has_div = has_cmp = False
    state_writes: list[int] = []
    cmp_values: list[int] = []
    lea_offsets: list[int] = []
    call_targets: list[int] = []
    call_names: list[str] = []
    stack_byte_writes = 0
    is_ret = False
    for line in block.lines:
        name = (line.name or "").upper()
        args = getattr(line, "args", []) or []
        instructions.append({
            "offset": int(line.offset), "mnemonic": line.name,
            "operands": str(line)[len(line.name):].strip(", "),
            "size": int(line.l),
        })
        if name == "CALL":
            has_call = True
            call_targets.extend(_branch_targets(line))
            for a in args:
                if isinstance(a, ExprLoc) and (o := loc_db.get_location_offset(a.loc_key)) is not None:
                    call_targets.append(o)
            if iat_map:
                ops_str = instructions[-1]["operands"]
                m = _RIP_DISP_RE.search(ops_str)
                if m is not None:
                    disp = int(m.group("off"), 0)
                    if m.group("sign") == "-":
                        disp = -disp
                    iat_va = int(line.offset) + int(line.l) + disp
                    label = iat_map.get(iat_va, "")
                    if label:
                        call_names.append(label)
                        call_targets.append(iat_va)
        if name == "IMUL":
            has_imul = True
        if name in ("DIV", "IDIV"):
            has_div = True
        if name in ("CMP", "TEST", "SUB"):
            for arg in args:
                imm = _get_immediate(arg)
                if imm is not None:
                    cmp_values.append(imm)
            if name in ("CMP", "TEST"):
                has_cmp = True
        if name == "RET":
            is_ret = True
        if (name == "MOV" and len(args) == 2
                and isinstance(args[1], ExprInt)
                and args[1].size <= ptr_bits):
            val = int(args[1].arg) & ((1 << args[1].size) - 1)
            if isinstance(args[0], ExprMem):
                state_writes.append(val)  # MOV [mem], imm (stack state var)
            elif isinstance(args[0], ExprId) and args[0].size == 32:
                # MOV reg32, imm (register state var, e.g. OLLVM's MOV EAX, <const>)
                state_writes.append(val)
        if name == "LEA" and len(args) == 2:
            imm = _get_immediate(args[1])
            if imm is not None:
                lea_offsets.append(imm)
        if (name == "MOV" and len(args) == 2
                and isinstance(args[1], ExprInt) and args[1].size == 8
                and isinstance(args[0], ExprMem)):
            ptr_str = str(args[0].ptr)
            if "RSP" in ptr_str or "RBP" in ptr_str or "ESP" in ptr_str:
                stack_byte_writes += 1

    _ofs = loc_db.get_location_offset
    successors = [s for s in (_ofs(k) for k in cfg.successors(block.loc_key)) if s is not None]
    predecessors = [p for p in (_ofs(k) for k in cfg.predecessors(block.loc_key)) if p is not None]
    return BlockInfo(
        address=address,
        in_degree=len(predecessors), out_degree=len(successors),
        successors=successors, predecessors=predecessors,
        instructions=instructions,
        has_call=has_call, has_imul=has_imul, has_div=has_div, has_cmp=has_cmp,
        call_targets=call_targets, call_names=call_names, cmp_values=cmp_values,
        state_writes=state_writes, lea_rip_offsets=lea_offsets,
        stack_byte_writes=stack_byte_writes, is_ret=is_ret,
        instruction_count=len(instructions),
    )

def _aggregate_dispatcher_chain(entry: Any, addr_to_block: dict[int, Any]) -> Any:
    """Aggregate dispatcher chain blocks into a virtual mega-block with _resolved_target annotations."""
    from .cff_techniques import BlockInfo

    visited: set[int] = set()
    chain_blocks: list[Any] = []
    queue: list[int] = [entry.address]
    while queue:
        addr = queue.pop(0)
        if addr in visited or addr not in addr_to_block:
            continue
        visited.add(addr)
        blk = addr_to_block[addr]
        if len(blk.instructions) > 6 and blk.has_call:
            continue
        chain_blocks.append(blk)
        for s in blk.successors:
            if s in visited or s not in addr_to_block:
                continue
            sb = addr_to_block[s]
            sb_mnems = {(i.get("mnemonic") or "").upper() for i in sb.instructions}
            if (len(sb.instructions) <= 6 and not sb.has_call
                    and sb_mnems & _DISPATCHER_CHAIN_MNEMS):
                queue.append(s)

    if not chain_blocks:
        return entry

    chain_addrs = {b.address for b in chain_blocks}
    chain_insns: list[dict[str, Any]] = []
    for blk in chain_blocks:
        copied = [dict(ins) for ins in blk.instructions]
        if len(blk.successors) == 2:
            non_chain = [s for s in blk.successors if s not in chain_addrs]
            if len(non_chain) == 1:
                target = non_chain[0]
            else:
                # Both successors are in the chain. For conditional branches
                # (JZ/JE), miasm orders successors as [fall-through, taken].
                # The taken branch (successors[1]) is the handler target.
                target = blk.successors[1]
            for ins in reversed(copied):
                if (ins.get('mnemonic') or '').upper() in _BRANCH_MNEMS:
                    ins['_resolved_target'] = target
                    break
        chain_insns.extend(copied)

    return BlockInfo(
        address=entry.address,
        in_degree=entry.in_degree,
        out_degree=entry.out_degree,
        successors=entry.successors,
        predecessors=entry.predecessors,
        instructions=chain_insns,
        has_call=False,
        instruction_count=len(chain_insns),
    )

def _dispatcher_chain_addrs(
    entry: Any, addr_to_block: dict[int, Any],
) -> set[int]:
    """Return VAs of the dispatcher chain rooted at ``entry`` (skip-set for opaque scans)."""
    visited: set[int] = set()
    queue: list[int] = [entry.address]
    while queue:
        addr = queue.pop(0)
        if addr in visited or addr not in addr_to_block:
            continue
        blk = addr_to_block[addr]
        if len(blk.instructions) > 6 and blk.has_call:
            continue
        visited.add(addr)
        for s in blk.successors:
            sb = addr_to_block.get(s)
            if sb is None or s in visited:
                continue
            sb_mnems = {(i.get("mnemonic") or "").upper()
                        for i in sb.instructions}
            if (len(sb.instructions) <= 6 and not sb.has_call
                    and sb_mnems & _DISPATCHER_CHAIN_MNEMS):
                queue.append(s)
    return visited

def _candidate_dispatchers(blocks: list[Any]) -> list[Any]:
    """Pick blocks whose in-degree dwarfs the rest of the function."""
    if not blocks:
        return []
    in_degrees = [b.in_degree for b in blocks]
    median = statistics.median(in_degrees)
    stdev = statistics.pstdev(in_degrees) if len(in_degrees) > 1 else 0.0
    threshold = max(median + 2 * stdev, 3.0)
    chosen = {b.address: b for b in blocks if b.in_degree >= threshold}
    for b in sorted(blocks, key=lambda x: x.in_degree, reverse=True)[:3]:
        if b.in_degree >= 2:
            chosen.setdefault(b.address, b)
    return list(chosen.values())

def _best_match(detectors: list[Any], *args: Any, **kwargs: Any) -> Any:
    """Run every detector, return highest-confidence match. Handles float and object returns."""
    best, best_conf = None, -1.0
    for det in detectors:
        try:
            match = det.detect(*args, **kwargs)
        except (ValueError, KeyError, AttributeError, TypeError, IndexError):
            continue
        if match is None:
            continue
        if isinstance(match, (int, float)):
            conf = float(match)
            if conf <= 0.0:
                continue
            if conf > best_conf:
                class _Wrap:
                    pass
                w = _Wrap()
                w.confidence = conf
                w.name = getattr(det, "name", "unknown")
                w.detector = det
                best, best_conf = w, conf
            continue
        conf = float(getattr(match, "confidence", 0.0))
        if conf <= 0.0:
            continue
        if conf > best_conf:
            if not hasattr(match, "name"):
                match.name = getattr(det, "name", "unknown")
            best, best_conf = match, conf
    return best

def _classify_handler(blk: Any, opaque_addrs: set[int]) -> str:
    """Return ``real`` / ``trampoline`` / ``opaque`` for a handler block."""
    if blk.address in opaque_addrs:
        return "opaque"
    if blk.has_call or blk.has_cmp or blk.lea_rip_offsets:
        return "real"
    if blk.state_writes:
        return "trampoline"
    return "real"

def _state_threshold(state_values: list[int]) -> int:
    """Half the smallest state value (floored at 0); fallback 0xFFFF when empty."""
    if not state_values:
        return 0xFFFF
    return max(min(state_values) // 2, 0)

def _initial_state(prologue: Any, addr_to_block: dict[int, Any],
                   ptr_bits: int, threshold: int = 0xFFFF) -> int | None:
    """First state-slot immediate written near the prologue (BFS, MOV [mem], imm > threshold)."""
    queue = [prologue.address]
    seen: set[int] = set()
    limit = 20
    while queue and limit > 0:
        addr = queue.pop(0)
        if addr in seen or addr not in addr_to_block:
            continue
        seen.add(addr)
        limit -= 1
        blk = addr_to_block[addr]
        for value in blk.state_writes:
            if value > threshold:
                return value
        queue.extend(s for s in blk.successors if s not in seen)
    return None

def _resolve_opaque_next_states(
    start_addr: int, addr_to_block: dict[int, Any],
    disp_chain: set[int], handler_addrs: set[int],
    threshold: int = 0xFFFF,
) -> list[int]:
    """Resolve CMOV next-states using registered opaque patterns' resolve_cmov."""
    from .cff_techniques import load_opaque_patterns
    patterns = load_opaque_patterns()
    out: list[int] = []
    q, seen = [start_addr], set()
    while q:
        a = q.pop(0)
        if a in seen or a not in addr_to_block:
            continue
        if a != start_addr and (a in disp_chain or a in handler_addrs):
            continue
        seen.add(a)
        b = addr_to_block[a]
        q.extend(b.successors)
        cands = [b] + [addr_to_block[p] for p in b.predecessors if p in addr_to_block]
        if not any(c.has_imul and c.has_div for c in cands):
            continue
        matched_pattern = None
        for pat in patterns:
            try:
                conf = pat.detect(b)
            except (ValueError, TypeError, AttributeError):
                continue
            if isinstance(conf, (int, float)) and conf > 0.0:
                matched_pattern = pat
                break
        if matched_pattern is None:
            for pred_blk in cands:
                if pred_blk is b:
                    continue
                for pat in patterns:
                    try:
                        conf = pat.detect(pred_blk)
                    except (ValueError, TypeError, AttributeError):
                        continue
                    if isinstance(conf, (int, float)) and conf > 0.0:
                        matched_pattern = pat
                        break
                if matched_pattern:
                    break
        if matched_pattern is None:
            continue
        # Scan this block AND its immediate successors for MOV+CMOV pattern
        # (some obfuscators split IMUL block and CMOV block with PUSH/POP boundary)
        scan_blocks = [b]
        for s_addr in b.successors:
            if s_addr in addr_to_block and s_addr not in handler_addrs:
                scan_blocks.append(addr_to_block[s_addr])
        last: dict[str, int] = {}
        found = False
        for scan_b in scan_blocks:
            for ins in scan_b.instructions:
                mn = (ins.get('mnemonic') or '').upper()
                ops = ins.get('operands') or ''
                if ',' not in ops:
                    continue
                dst, _, src = ops.partition(',')
                dst_u, src_s = dst.strip().upper(), src.strip()
                if mn == 'MOV' and '[' not in src_s:
                    m = re.findall(r'0[xX]([0-9a-fA-F]+)', src_s)
                    if m:
                        last[dst_u] = int(m[0], 16)
                elif mn in ('CMOVZ', 'CMOVE', 'CMOVNZ', 'CMOVNE'):
                    which = matched_pattern.resolve_cmov(mn)
                    v = last.get(src_s.strip().upper() if which == 'src' else dst_u)
                    if v is not None and v > threshold:
                        out.append(v)
                    found = True
                    break
            if found:
                break
    return out

def _aggregate_handler(
    start_addr: int, addr_to_block: dict[int, Any],
    disp_chain: set[int], handler_addrs: set[int],
    threshold: int = 0xFFFF,
    valid_states: set[int] | None = None,
) -> tuple[list[int], list[int], list[str], list[str]]:
    """Walk handler + successors, return (calls, next_states, ops, call_names)."""
    all_calls: list[int] = []
    all_sw: list[int] = []
    all_ops: list[str] = []
    all_names: list[str] = []
    q = [start_addr]
    visited: set[int] = set()
    while q:
        a = q.pop(0)
        if a in visited or a not in addr_to_block:
            continue
        if a in handler_addrs and a != start_addr:
            continue
        visited.add(a)
        b = addr_to_block[a]
        in_chain = a in disp_chain and a != start_addr
        # Collect state writes — use valid_states membership if available,
        # fall back to threshold for backward compat
        for v in b.state_writes:
            if valid_states is not None:
                if v in valid_states:
                    all_sw.append(v)
            elif v > threshold:
                all_sw.append(v)
        # Only collect ops/calls from non-chain blocks
        if not in_chain:
            all_calls.extend(b.call_targets)
            all_names.extend(getattr(b, 'call_names', []) or [])
            for i in b.instructions:
                mn = (i.get('mnemonic', '') or '').upper()
                ops = i.get('operands', '') or ''
                if mn in ('CMP', 'TEST') and 'RSP' not in ops:
                    all_ops.append(f'{mn} {ops}')
                elif mn == 'LEA' and 'RIP' in ops:
                    all_ops.append(f'{mn} {ops}')
                elif mn == 'CALL':
                    all_ops.append(f'{mn} {ops}')
        for s in b.successors:
            q.append(s)
    # Try static CMOV resolution first, then emulation-based fallback
    static_resolved = [v for v in _resolve_opaque_next_states(
        start_addr, addr_to_block, disp_chain, handler_addrs,
        threshold=threshold) if v not in all_sw]
    all_sw.extend(static_resolved)
    if not static_resolved:
        try:
            from .deobfuscation.cff_resolver import resolve_opaque_block
            # Collect opaque block instructions from visited blocks
            opaque_insns = []
            for a in visited:
                b = addr_to_block.get(a)
                if b and (b.has_imul or any((i.get('mnemonic','').upper()
                        in ('CMOVZ','CMOVE','CMOVNZ','CMOVNE'))
                        for i in b.instructions)):
                    opaque_insns.extend(b.instructions)
            if opaque_insns:
                emu_resolved = resolve_opaque_block(opaque_insns, [], ptr_size=64)
                all_sw.extend(v for v in emu_resolved if v not in all_sw)
        except (ImportError, ValueError, RuntimeError):
            pass  # emulation not available or failed
    return all_calls, all_sw, all_ops, all_names
