"""Generate enriched pseudocode from CFF deflattened state machine.

Resolves call targets through the function index, resolves string
references through decrypted strings cache, shows real conditions.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

__all__ = ["emit_pseudocode"]


def emit_pseudocode(
    deflat: dict[str, Any],
    func_name: str = "",
    cache_dir: Path | None = None,
    sha: str = "",
) -> str:
    """Generate enriched pseudocode from deflat output.

    Args:
        deflat: Result from deflat_function().
        func_name: Override function name.
        cache_dir: Cache root for enrichment data (function index, strings).
        sha: Binary SHA for cache lookup.
    """
    address = deflat.get("address", "0x0")
    if not func_name:
        ea = int(address, 16) if isinstance(address, str) else address
        func_name = f"sub_{ea:X}"

    all_states = {s["value"]: s for s in deflat.get("states", [])}
    initial = deflat.get("initial_state", "")
    key_bytes = deflat.get("prologue_key_bytes", 0)
    exit_state = _find_exit_state(all_states)

    # Load enrichment data
    name_map = _load_function_names(cache_dir, sha)
    string_map = _load_decrypted_strings(cache_dir, sha)

    # Build loc_key -> address mapping from deflat calls+ops
    loc_to_addr = _build_loc_mapping(deflat, all_states)

    ctx = _Ctx(name_map, string_map, loc_to_addr, exit_state)

    # Partition handlers
    handlers = [s for s in all_states.values()
                if s["block_type"] not in ("trampoline", "opaque")
                and (s.get("calls") or any("CALL" in o.upper() for o in s.get("ops", []))
                     or any("CMP" in o.upper() or "TEST" in o.upper() for o in s.get("ops", [])))]

    lines: list[str] = []
    sig = deflat.get("matched_signature", "")
    lines.append(f"// Deflattened: {deflat.get('real_count', '?')} handlers "
                 f"from {deflat.get('block_count', '?')} obfuscated blocks"
                 + (f" [{sig}]" if sig else ""))
    lines.append(f"")
    lines.append(f"void __fastcall {func_name}(void *ctx)")
    lines.append("{")

    if key_bytes > 0:
        lines.append(f"    BYTE key[{key_bytes}];")
        lines.append(f"    init_prologue_key(key, {key_bytes});")
        lines.append("")

    # Startup path
    lines.append("    // ---- initialization ----")
    _emit_path(all_states, initial, ctx, set(), lines, indent=1)
    lines.append("")

    # All handlers with real work
    lines.append("    // ---- handlers ----")
    for state in sorted(handlers, key=lambda s: s.get("handler_address", "")):
        lines.append("")
        _emit_handler_block(state, ctx, lines)

    lines.append("}")
    return "\n".join(lines)


class _Ctx:
    """Enrichment context for the emitter."""
    __slots__ = ("names", "strings", "locs", "exit_state")

    def __init__(self, names, strings, locs, exit_state):
        self.names = names
        self.strings = strings
        self.locs = locs
        self.exit_state = exit_state

    def resolve_call(self, raw: str) -> str:
        """Resolve a call target to a human-readable name."""
        # loc_key_N -> address -> name
        if raw.startswith("loc_key_"):
            addr = self.locs.get(raw)
            if addr:
                name = self.names.get(addr, self.names.get(f"0x{addr:x}", ""))
                if name:
                    return name
                return f"sub_{addr:X}"
        # 0x... address -> name
        if raw.startswith("0x"):
            name = self.names.get(raw, "")
            if name:
                return name
            try:
                a = int(raw, 16)
                name = self.names.get(f"0x{a:x}", "")
                if name:
                    return name
                return f"sub_{a:X}"
            except ValueError:
                pass
        return raw

    def resolve_string(self, rip_offset: str) -> str:
        """Resolve a RIP-relative offset to a decrypted string."""
        s = self.strings.get(rip_offset, "")
        if s:
            safe = s[:60].replace('"', '\\"')
            return f'"{safe}"'
        return f"str_{rip_offset}"


def _find_exit_state(states: dict) -> str:
    counts: Counter[str] = Counter()
    for s in states.values():
        for ns in s.get("next_states", []):
            counts[ns] += 1
    if not counts:
        return ""
    top, count = counts.most_common(1)[0]
    return top if count >= 5 else ""


def _resolve(states: dict, val: str, exit_state: str) -> str:
    seen: set[str] = set()
    cur = val
    for _ in range(10):
        if cur in seen or cur == exit_state:
            return cur
        seen.add(cur)
        s = states.get(cur)
        if s is None:
            return cur
        bt = s.get("block_type", "real")
        ns = s.get("next_states", [])
        has_work = bool(s.get("calls")) or any("CALL" in o.upper() for o in s.get("ops", []))
        has_cond = any("CMP" in o.upper() or "TEST" in o.upper() for o in s.get("ops", []))
        if bt in ("trampoline", "opaque"):
            real = [n for n in ns if n != exit_state]
            cur = real[0] if real else (ns[0] if ns else cur)
            continue
        if not has_work and not has_cond and len(ns) == 1:
            cur = ns[0]
            continue
        if not has_work and not has_cond and len(ns) == 2 and exit_state in ns:
            real = [n for n in ns if n != exit_state]
            cur = real[0] if real else ns[0]
            continue
        return cur
    return cur


def _emit_path(states, current, ctx, visited, lines, indent):
    """Walk the linear startup path."""
    pad = "    " * indent
    for _ in range(30):
        current = _resolve(states, current, ctx.exit_state)
        if current in visited or current == ctx.exit_state:
            return
        visited.add(current)
        state = states.get(current)
        if state is None:
            return
        ns = state.get("next_states", [])
        if state.get("calls") or any("CALL" in o.upper() for o in state.get("ops", [])):
            _emit_ops(state, ctx, lines, pad)
        if not ns:
            lines.append(f"{pad}return;")
            return
        if len(ns) == 1:
            current = ns[0]
            continue
        a = _resolve(states, ns[0], ctx.exit_state)
        b = _resolve(states, ns[1], ctx.exit_state) if len(ns) > 1 else ""
        if b == ctx.exit_state:
            cond = _condition(state)
            if cond:
                lines.append(f"{pad}if (!({cond})) return;  // error")
            current = ns[0]
            continue
        if a == ctx.exit_state:
            cond = _condition(state)
            if cond:
                lines.append(f"{pad}if ({cond}) return;  // error")
            current = ns[1]
            continue
        if a == current or b == current:
            lines.append(f"{pad}// dispatch loop")
            return
        current = ns[0]


def _emit_handler_block(state, ctx, lines):
    """Emit a labeled handler block."""
    val = state["value"]
    handler = state.get("handler_address", "?")
    ns = state.get("next_states", [])

    lines.append(f"handler_{val[:8]}:  // {handler}")
    pad = "    "
    _emit_ops(state, ctx, lines, pad)

    # Transition annotation
    resolved = []
    for n in ns:
        r = _resolve({val: state}, n, ctx.exit_state)  # minimal resolve
        if n == ctx.exit_state:
            resolved.append("error_exit")
        else:
            resolved.append(f"handler_{n[:8]}")

    cond = _condition(state)
    if len(resolved) == 1:
        lines.append(f"{pad}// -> {resolved[0]}")
    elif len(resolved) >= 2 and cond:
        lines.append(f"{pad}if ({cond})")
        lines.append(f"{pad}    goto {resolved[0]};")
        lines.append(f"{pad}else")
        lines.append(f"{pad}    goto {resolved[1]};")
    elif len(resolved) >= 2:
        lines.append(f"{pad}// -> {' | '.join(resolved)}")


def _emit_ops(state, ctx, lines, pad):
    """Emit calls and operations with enriched names."""
    ops = state.get("ops", [])
    calls = state.get("calls", [])
    pending_str: str | None = None
    call_idx = 0

    for op in ops:
        up = op.upper()
        if "LEA" in up and "RIP" in up and "+" in op:
            offset = op.split("+")[-1].strip().rstrip("]").strip()
            pending_str = ctx.resolve_string(offset)
            continue
        if "CALL" in up:
            raw_target = op.split()[-1]
            name = ctx.resolve_call(raw_target)
            # Also try resolving via calls list
            if name.startswith("sub_") and call_idx < len(calls):
                addr_name = ctx.resolve_call(calls[call_idx])
                if not addr_name.startswith("sub_"):
                    name = addr_name
            call_idx += 1
            if pending_str:
                lines.append(f"{pad}{name}({pending_str});")
                pending_str = None
            else:
                lines.append(f"{pad}{name}();")
            continue
        if "CMP" in up or "TEST" in up:
            continue
        lines.append(f"{pad}// {op}")


def _condition(state: dict) -> str:
    for op in state.get("ops", []):
        up = op.upper()
        if "CMP" in up:
            parts = op.split(",", 1)
            if len(parts) == 2:
                lhs = _clean(parts[0].replace("CMP", "").strip())
                rhs = _clean(parts[1].strip())
                if rhs in ("0x0", "0"):
                    return f"{lhs} != NULL"
                if rhs in ("0xFFFFFFFFFFFFFFFF", "-1"):
                    return f"{lhs} != INVALID_HANDLE"
                return f"{lhs} == {rhs}"
        if "TEST" in up:
            parts = op.split(",", 1)
            if len(parts) == 2:
                lhs = _clean(parts[0].replace("TEST", "").strip())
                rhs = _clean(parts[1].strip())
                return f"{lhs} & {rhs}"
    return ""


def _clean(s: str) -> str:
    s = s.strip()
    if "PTR [" in s.upper():
        inner = s.split("[", 1)[1].rstrip("]").strip()
        return f"*({_reg(inner)})"
    return _reg(s)


def _reg(s: str) -> str:
    """Map x86 registers to pseudocode variable names.

    Covers x86_64 (Windows fastcall) and x86_32 (cdecl/stdcall).
    Other architectures pass through unchanged.
    """
    for k, v in [
        # x86_64 Windows fastcall
        ('RAX', 'result'), ('RCX', 'a1'), ('RDX', 'a2'),
        ('R8', 'a3'), ('R9', 'a4'), ('RDI', 'this'),
        # x86_32
        ('EAX', 'result'), ('ECX', 'a1'), ('EDX', 'a2'),
    ]:
        s = s.replace(k, v)
    return s


# ---- enrichment loaders ----

def _load_function_names(cache_dir: Path | None, sha: str) -> dict[str, str]:
    """Load address->name mapping from function index."""
    if not cache_dir or not sha:
        return {}
    idx_path = cache_dir / sha / "index.json"
    if not idx_path.exists():
        return {}
    try:
        data = json.loads(idx_path.read_text(encoding="utf-8"))
        entries = data if isinstance(data, list) else data.get("entries", [])
        result: dict[str, str] = {}
        for e in entries:
            addr = e.get("address", "")
            name = e.get("name", "")
            if addr and name:
                result[addr] = name
                # Also store lowercase hex variant
                try:
                    result[f"0x{int(addr, 16):x}"] = name
                except (ValueError, TypeError):
                    pass
        return result
    except (json.JSONDecodeError, OSError):
        return {}


def _load_decrypted_strings(cache_dir: Path | None, sha: str) -> dict[str, str]:
    """Load RIP-offset->plaintext mapping from decrypted strings cache."""
    if not cache_dir or not sha:
        return {}
    results_dir = cache_dir / sha / "results"
    if not results_dir.exists():
        return {}
    mapping: dict[str, str] = {}
    for f in results_dir.glob("decrypt_*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            for entry in data.get("decrypted", data.get("strings", [])):
                # Map various address formats to plaintext
                plaintext = entry.get("plaintext", entry.get("string", ""))
                if not plaintext:
                    continue
                for key in ("rip_offset", "ciphertext_rip_offset", "address"):
                    val = entry.get(key, "")
                    if val:
                        mapping[str(val)] = plaintext
        except (json.JSONDecodeError, OSError):
            continue
    return mapping


def _build_loc_mapping(deflat: dict, states: dict) -> dict[str, int]:
    """Build loc_key_N -> address mapping from ops CALL targets paired with calls list."""
    mapping: dict[str, int] = {}
    for s in states.values():
        calls = s.get("calls", [])
        ops = s.get("ops", [])
        call_idx = 0
        for op in ops:
            if "CALL" in op.upper():
                target = op.split()[-1]
                if target.startswith("loc_key_") and call_idx < len(calls):
                    addr_raw = calls[call_idx]
                    try:
                        addr = int(addr_raw, 16) if isinstance(addr_raw, str) else int(addr_raw)
                        mapping[target] = addr
                    except (ValueError, TypeError):
                        pass
                call_idx += 1
    return mapping
