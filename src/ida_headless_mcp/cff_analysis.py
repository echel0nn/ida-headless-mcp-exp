"""Control-Flow Flattening (CFF) analysis -- server-side, no idalib needed.

Public helpers: ``disassemble_function``, ``detect_cff``, ``deflat_function``,
``emulate_concrete``. Pattern detectors live in
:mod:`ida_headless_mcp.cff_techniques`; this module is the only consumer.

The whole ``.text`` section is fed to miasm because CFF inflates a single
function across thousands of bytes; ``dontdis_retcall=False`` is required
so the disassembler does not abort at the dispatcher's tail call.

Low-level mechanics (PE parsing, ``BlockInfo`` extraction, dispatcher
chain aggregation, candidate selection, handler classification) live in
:mod:`ida_headless_mcp.cff_helpers` to keep this file under the LOC cap.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from .cff_helpers import (
    _aggregate_dispatcher_chain,
    _aggregate_handler,
    _best_match,
    _candidate_dispatchers,
    _classify_handler,
    _detect_arch,
    _dispatcher_chain_addrs,
    _extract_block_info,
    _initial_state,
    _state_threshold,
    _load_text_section,
    _ptr_size,
)
from .pe_imports import build_iat_map

__all__ = [
    "disassemble_function",
    "detect_cff",
    "deflat_function",
    "emulate_concrete",
]

_COND_JMPS = {"JZ", "JNZ", "JE", "JNE", "JL", "JG", "JLE", "JGE",
              "JA", "JB", "JAE", "JBE", "JS", "JNS", "JC", "JNC"}

def disassemble_function(
    pe_path: Path, func_va: int, arch: str = "",
) -> dict[str, Any]:
    """Disassemble a complete function, returning its CFG.

    Uses ``dis_multiblock`` to follow every intra-function branch with
    ``follow_call=False`` and ``dontdis_retcall=False`` -- the latter is
    required for CFF, whose dispatcher tails are RET trampolines.

    Returns:
        ``{arch, blocks, edges, stats}``. In-process callers reuse the
        live dataclasses via ``_blocks_obj`` / ``_addr_to_block``.
    """
    from miasm.analysis.machine import Machine
    from miasm.core.bin_stream import bin_stream_str
    from miasm.core.locationdb import LocationDB

    if not arch:
        arch = _detect_arch(pe_path)
    if not arch:
        return {'error': 'Unsupported binary format (not PE or unknown machine type)',
                'blocks': [], 'edges': []}
    text_bytes, text_base, text_size = _load_text_section(pe_path)
    if not text_bytes:
        return {"error": "Cannot locate .text section", "blocks": [], "edges": []}
    if not (text_base <= func_va < text_base + text_size):
        return {"error": f"func_va 0x{func_va:x} outside .text", "blocks": [], "edges": []}

    machine = Machine(arch)
    loc_db = LocationDB()
    bs = bin_stream_str(text_bytes, base_address=text_base)
    mdis = machine.dis_engine(bs, loc_db=loc_db)
    mdis.follow_call = False
    mdis.dontdis_retcall = False
    import warnings as _w
    miasm_logger = logging.getLogger('asmblock')
    prev_level = miasm_logger.level
    miasm_logger.setLevel(logging.CRITICAL)
    _w_ctx = _w.catch_warnings()
    _w_ctx.__enter__()
    _w.simplefilter('ignore')
    try:
        cfg = mdis.dis_multiblock(func_va)
    except (ValueError, RuntimeError, KeyError) as exc:
        return {'error': f'Disassembly failed: {exc}', 'blocks': [], 'edges': []}
    finally:
        _w_ctx.__exit__(None, None, None)
        miasm_logger.setLevel(prev_level)

    ptr_bits = _ptr_size(arch)
    iat_map = build_iat_map(pe_path)
    blocks: list[Any] = []
    addr_to_block: dict[int, Any] = {}
    for block in cfg.blocks:
        try:
            info = _extract_block_info(block, loc_db, cfg, ptr_bits, iat_map=iat_map)
        except (AttributeError, TypeError, ValueError):
            # Mixed code/data -- skip; deflattener tolerates missing entries.
            continue
        blocks.append(info)
        addr_to_block[info.address] = info

    edges = [{"from": f"0x{b.address:x}", "to": f"0x{s:x}"}
             for b in blocks for s in b.successors]
    in_degrees = [b.in_degree for b in blocks]
    max_in = max(in_degrees) if in_degrees else 0
    max_in_addr = next((b.address for b in blocks if b.in_degree == max_in), None)
    return {
        "arch": arch, "blocks": [b.to_dict() for b in blocks], "edges": edges,
        "stats": {
            "block_count": len(blocks), "edge_count": len(edges),
            "max_in_degree": max_in,
            "max_in_degree_address": (
                f"0x{max_in_addr:x}" if max_in_addr is not None else None),
            "func_va": f"0x{func_va:x}",
        },
        "_blocks_obj": blocks, "_addr_to_block": addr_to_block,
    }

def _empty_detection(error: str | None = None) -> dict[str, Any]:
    """Build a non-flat ``CffDetectionResult`` payload, optionally with error."""
    from .cff_techniques import CffDetectionResult

    payload = CffDetectionResult(
        is_cff=False, confidence=0.0,
        dispatcher_address=None, dispatcher_in_degree=0,
        dispatcher_pattern=None, state_variable=None,
    ).to_dict()
    if error is not None:
        payload["error"] = error
    return payload

def detect_cff(pe_path: Path, func_va: int, arch: str = "") -> dict[str, Any]:
    """Detect control-flow flattening in a function.

    Returns:
        ``CffDetectionResult.to_dict()``. When detection cannot run the
        result has ``is_cff=False`` and a populated ``error`` field.
    """
    from .cff_techniques import CffDetectionResult, StateVarInfo, load_techniques

    cfg = disassemble_function(pe_path, func_va, arch=arch)
    if "error" in cfg and not cfg.get("blocks"):
        return _empty_detection(error=cfg["error"])

    blocks: list[Any] = cfg["_blocks_obj"]
    addr_to_block: dict[int, Any] = cfg["_addr_to_block"]
    techniques = load_techniques()

    dispatcher_match = None
    dispatcher_block = None
    for cand in _candidate_dispatchers(blocks):
        mega = _aggregate_dispatcher_chain(cand, addr_to_block)
        match = _best_match(techniques["dispatchers"], mega,
                            cfg_blocks=addr_to_block)
        if match is None:
            continue
        if dispatcher_match is None or match.confidence > dispatcher_match.confidence:
            dispatcher_match, dispatcher_block = match, cand

    state_var_match = None
    if dispatcher_block is not None:
        mega_for_sv = _aggregate_dispatcher_chain(dispatcher_block, addr_to_block)
        state_var_match = _best_match(
            techniques['state_variables'], list(addr_to_block.values()),
            dispatcher=mega_for_sv)

    # Scan all non-chain blocks for opaque predicates (LCG ends with JMP, not JZ).
    disp_chain_addrs: set[int] = (
        _dispatcher_chain_addrs(dispatcher_block, addr_to_block)
        if dispatcher_block is not None else set())
    opaque_blocks: list[dict[str, Any]] = []
    for blk in blocks:
        if dispatcher_block is not None and blk.address == dispatcher_block.address:
            continue
        if blk.address in disp_chain_addrs:
            continue
        last_mn = (blk.instructions[-1].get("mnemonic") or "").upper() \
            if blk.instructions else ""
        is_candidate = (
            last_mn in _COND_JMPS
            or (blk.has_imul and blk.has_div and not blk.has_call)
        )
        if not is_candidate:
            continue
        match = _best_match(techniques["opaque_predicates"], blk)
        if match is not None:
            opaque_blocks.append({
                "address": f"0x{blk.address:x}",
                "pattern": getattr(match, "name", "unknown"),
                "confidence": float(getattr(match, "confidence", 0.0)),
            })

    # Build a namespace object for signature matching (expects attribute access)
    class _Payload:
        pass
    payload = _Payload()
    payload.dispatcher_patterns = [getattr(dispatcher_match, 'name', None)] if dispatcher_match else []
    payload.opaque_patterns = sorted({o['pattern'] for o in opaque_blocks})
    payload.state_var_types = [getattr(state_var_match, 'name', None)] if state_var_match else []
    payload.characteristics = {}
    payload.block_count = len(blocks)
    payload.opaque_count = len(opaque_blocks)

    from .cff_techniques.signatures import match_signature
    sig_best, sig_score = match_signature(payload, techniques['signatures'])
    signature_match = sig_best

    is_flat = dispatcher_match is not None and dispatcher_match.confidence >= 0.5
    overall = dispatcher_match.confidence if dispatcher_match is not None else 0.0
    if state_var_match is not None:
        overall = min(1.0, overall + 0.15)
    if opaque_blocks:
        overall = min(1.0, overall + 0.1)
    disp_addr = dispatcher_block.address if dispatcher_block else None
    disp_in_deg = dispatcher_block.in_degree if dispatcher_block else 0
    disp_name = getattr(dispatcher_match, "name", None) if dispatcher_match else None
    sv_info = None
    if state_var_match is not None:
        if isinstance(state_var_match, StateVarInfo):
            sv_info = state_var_match
        else:
            sv_info = StateVarInfo(
                location_type=getattr(state_var_match, "location_type", "unknown"),
                operand_pattern=getattr(state_var_match, "operand_pattern", ""),
                offset=getattr(state_var_match, "offset", None),
                register=getattr(state_var_match, "register", None),
            )
    sig_name = getattr(signature_match, 'name', None) if signature_match else None
    _d = dispatcher_match is not None and dispatcher_match.confidence >= 0.5
    _o = bool(opaque_blocks)
    obs_type = ('CFF+BCF' if _d and _o else 'CFF' if _d else 'BCF' if _o else 'none')
    return CffDetectionResult(
        is_cff=is_flat, confidence=overall,
        dispatcher_address=disp_addr, dispatcher_in_degree=disp_in_deg,
        dispatcher_pattern=disp_name, state_variable=sv_info,
        opaque_predicates=opaque_blocks, matched_signature=sig_name,
        block_count=len(blocks), obfuscation_type=obs_type,
    ).to_dict()

def _parse_hex(value: Any) -> int | None:
    """Parse a ``"0x..."`` hex string; ``None`` for non-string or invalid input."""
    if not isinstance(value, str) or not value.startswith(("0x", "0X")):
        return None
    try:
        return int(value, 16)
    except ValueError:
        return None

def deflat_function(pe_path: Path, func_va: int, arch: str = "") -> dict[str, Any]:
    """Deflat a CFF-obfuscated function into a linearized state graph.

    Pipeline:
        1. Run ``detect_cff`` to find the dispatcher and the matching pattern.
        2. Re-aggregate the dispatcher chain so that ``extract_states`` sees
           the ``_resolved_target`` annotations on conditional branches.
        3. Map every recovered state value to a handler block, classify it
           (``real``/``trampoline``/``opaque``), and record its outgoing
           edges (call targets and state writes).
        4. Trace the inferred execution flow starting at the prologue's
           initial-state immediate.

    Degrades gracefully: when detection fails, the dispatcher block is
    not in the CFG, or ``extract_states`` returns no mapping, the result
    still has the correct shape with empty ``states``/``flow`` lists.
    """
    from .cff_techniques import DeflattedFunction, DeflattedState, load_techniques

    detection = detect_cff(pe_path, func_va, arch=arch)
    cfg = disassemble_function(pe_path, func_va, arch=arch)
    blocks: list[Any] = cfg.get("_blocks_obj", [])
    addr_to_block: dict[int, Any] = cfg.get("_addr_to_block", {})
    arch_used = cfg.get('arch', arch or _detect_arch(pe_path))
    if not arch_used:
        return _empty()
    ptr_bits = _ptr_size(arch_used)

    dispatcher_addr = _parse_hex(detection.get("dispatcher_address"))
    dispatcher_block = (addr_to_block.get(dispatcher_addr)
                        if dispatcher_addr is not None else None)
    dispatcher_in_degree = (dispatcher_block.in_degree
                            if dispatcher_block is not None else 0)
    matched_signature = detection.get("matched_signature")

    def _empty(states: list[DeflattedState] | None = None) -> dict[str, Any]:
        return DeflattedFunction(
            name="", address=func_va,
            block_count=len(blocks), state_count=len(states or []),
            real_count=0, opaque_count=0,
            trampoline_count=0, dispatcher_count=0,
            dispatcher_address=dispatcher_addr or 0,
            dispatcher_in_degree=dispatcher_in_degree,
            initial_state=None,
            prologue_calls=[], prologue_key_bytes=0,
            states=states or [], flow=[],
            matched_signature=matched_signature,
        ).to_dict()

    if not detection.get("is_cff") or dispatcher_block is None:
        return _empty()

    techniques = load_techniques()
    dispatcher_pattern = next(
        (p for p in techniques["dispatchers"]
         if getattr(p, "name", None) == detection.get("dispatcher_pattern")), None)
    if dispatcher_pattern is None:
        return _empty()

    mega = _aggregate_dispatcher_chain(dispatcher_block, addr_to_block)
    state_to_handler: dict[int, int] = {}
    try:
        state_to_handler = dict(dispatcher_pattern.extract_states(
            mega, cfg_blocks=addr_to_block))
    except (AttributeError, ValueError, KeyError, TypeError):
        state_to_handler = {}
    if not state_to_handler:
        return _empty()
    threshold = _state_threshold(list(state_to_handler.keys()))

    opaque_addrs: set[int] = set()
    for entry in detection.get("opaque_predicates", []) or []:
        raw = entry.get("address") if isinstance(entry, dict) else None
        a = raw if isinstance(raw, int) else _parse_hex(raw)
        if a is not None:
            opaque_addrs.add(a)

    # Collect all handler addresses and dispatcher chain addresses
    handler_addrs = set(state_to_handler.values())
    disp_chain = set()
    if dispatcher_block:
        _walk = [dispatcher_block.address]
        _visited = set()
        while _walk:
            a = _walk.pop(0)
            if a in _visited or a not in addr_to_block:
                continue
            _visited.add(a)
            disp_chain.add(a)
            b = addr_to_block[a]
            for s in b.successors:
                if s not in handler_addrs:
                    _walk.append(s)

    # Use helper from cff_helpers for handler chain aggregation

    states: list[DeflattedState] = []
    real_count = opaque_count = trampoline_count = dispatcher_count = 0
    for state_value, handler_addr in state_to_handler.items():
        blk = addr_to_block.get(handler_addr)
        if blk is None:
            continue
        kind = _classify_handler(blk, opaque_addrs)
        if kind == 'real':
            real_count += 1
        elif kind == 'opaque':
            opaque_count += 1
        elif kind == 'trampoline':
            trampoline_count += 1
        elif kind == 'dispatcher':
            dispatcher_count += 1
        calls, next_sw, ops, cnames = _aggregate_handler(
            handler_addr, addr_to_block, disp_chain, handler_addrs,
            threshold=threshold, valid_states=set(state_to_handler.keys()))
        # Merge call_names into ops for display (prefix with IAT!)
        for cn in cnames:
            if cn and cn not in ops:
                ops.append(f'IAT: {cn}')
        states.append(DeflattedState(
            value=state_value, handler_address=handler_addr, block_type=kind,
            calls=calls, ops=ops, next_states=next_sw,
        ))

    prologue_block = addr_to_block.get(func_va)
    initial_state = (
        _initial_state(prologue_block, addr_to_block, ptr_bits, threshold)
        if prologue_block is not None else None)
    prologue_calls = (list(prologue_block.call_targets)
                      if prologue_block is not None else [])
    prologue_key_bytes = (prologue_block.stack_byte_writes
                          if prologue_block is not None else 0)

    state_idx = {s.value: s for s in states}
    flow: list[DeflattedState] = []
    seen: set[int] = set()
    pending: list[int] = [initial_state] if initial_state is not None else []
    while pending and len(flow) < 1024:
        sv = pending.pop(0)
        if sv in seen or sv not in state_idx:
            continue
        seen.add(sv)
        ds = state_idx[sv]
        flow.append(ds)
        pending.extend(n for n in ds.next_states if n not in seen)

    return DeflattedFunction(
        name="", address=func_va,
        block_count=len(blocks), state_count=len(states),
        real_count=real_count, opaque_count=opaque_count,
        trampoline_count=trampoline_count, dispatcher_count=dispatcher_count,
        dispatcher_address=dispatcher_addr or 0,
        dispatcher_in_degree=dispatcher_in_degree,
        initial_state=initial_state,
        prologue_calls=prologue_calls,
        prologue_key_bytes=prologue_key_bytes,
        states=states, flow=flow,
        matched_signature=matched_signature,
    ).to_dict()

def emulate_concrete(
    pe_path: Path, address: int, arch: str = "",
    initial_regs: dict[str, int] | None = None,
    initial_memory: dict[int, bytes] | None = None,
    max_instructions: int = 100,
) -> dict[str, Any]:
    """Concrete (seeded) symbolic emulation.

    Every input has a real integer value, so the engine returns concrete
    outputs suitable for hash verification, crypto identification, and
    predicate evaluation. Catches unsupported instructions (CPUID, RDTSC)
    and returns the partial state with ``aborted_reason``.
    """
    from miasm.analysis.machine import Machine
    from miasm.core.bin_stream import bin_stream_str
    from miasm.core.locationdb import LocationDB
    from miasm.expression.expression import ExprId, ExprInt, ExprMem
    from miasm.ir.symbexec import SymbolicExecutionEngine

    if not arch:
        arch = _detect_arch(pe_path)
    if not arch:
        return {'error': 'Unsupported binary format', 'instructions_run': 0}
    ptr_bits = _ptr_size(arch)
    text_bytes, text_base, text_size = _load_text_section(pe_path)
    if not text_bytes or not (text_base <= address < text_base + text_size):
        return {"error": f"address 0x{address:x} not in .text", "instructions_run": 0}

    machine = Machine(arch)
    loc_db = LocationDB()
    bs = bin_stream_str(text_bytes, base_address=text_base)
    mdis = machine.dis_engine(bs, loc_db=loc_db)
    mdis.follow_call = False
    mdis.dontdis_retcall = False
    lifter = machine.lifter_model_call(loc_db)
    ircfg = lifter.new_ircfg()
    try:
        cfg = mdis.dis_multiblock(address)
        for blk in cfg.blocks:
            lifter.add_asmblock_to_ircfg(blk, ircfg)
    except (ValueError, RuntimeError, KeyError) as exc:
        return {"error": f"Disassembly/lift failed: {exc}", "instructions_run": 0}

    sb = SymbolicExecutionEngine(lifter)
    if initial_regs:
        for name, value in initial_regs.items():
            sb.symbols[ExprId(name, ptr_bits)] = ExprInt(
                value & ((1 << ptr_bits) - 1), ptr_bits)
    if initial_memory:
        for base, data in initial_memory.items():
            for i, byte in enumerate(data):
                sb.symbols[ExprMem(ExprInt(base + i, ptr_bits), 8)] = ExprInt(
                    byte & 0xFF, 8)

    instructions_run = 0
    current_loc = loc_db.get_offset_location(address)
    next_addr: Any = None
    aborted: str | None = None
    while current_loc is not None and instructions_run < max_instructions:
        irblock = ircfg.blocks.get(current_loc)
        if irblock is None:
            break
        instructions_run += sum(len(ab) for ab in irblock)
        try:
            next_addr = sb.run_block_at(ircfg, current_loc)
        except (NotImplementedError, KeyError, ValueError, AttributeError) as exc:
            aborted = f"unsupported instruction: {exc}"
            break
        if next_addr is None:
            break
        if isinstance(next_addr, ExprInt):
            current_loc = loc_db.get_offset_location(int(next_addr.arg))
        else:
            aborted = f"symbolic next address: {next_addr}"
            break

    final_regs: dict[str, Any] = {}
    for sym, val in sb.modified():
        if not isinstance(sym, ExprId):
            continue
        if isinstance(val, ExprInt):
            final_regs[str(sym)] = {"hex": f"0x{int(val.arg):x}", "int": int(val.arg)}
        else:
            final_regs[str(sym)] = {"symbolic": str(val)}

    return {
        "arch": arch, "start_address": f"0x{address:x}",
        "instructions_run": instructions_run,
        "next_address": (
            f"0x{int(next_addr.arg):x}" if isinstance(next_addr, ExprInt)
            else (str(next_addr) if next_addr is not None else None)),
        "aborted_reason": aborted, "final_registers": final_regs,
    }
