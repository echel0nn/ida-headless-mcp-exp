"""Recovery tools — expensive transformations that produce clean analysis output.

These tools restructure obfuscated code into analyzable forms:
- CFG recovery from control-flow-flattened functions
- C++ class hierarchy recovery from vtable analysis
- Protocol state machine extraction
"""
from __future__ import annotations

import re
from typing import Any

__all__ = [
    "recover_cfg",
    "recover_class_hierarchy",
    "detect_protocol_state_machine",
]


def recover_cfg(
    pseudocode: str,
    microcode: str,
    *,
    timeout_ms_per_block: int = 1000,
) -> dict[str, Any]:
    """Recover true control flow from a flattened function.

    Algorithm:
    1. Identify the dispatcher (while/switch pattern)
    2. Extract state variable and case values
    3. For each case block, determine the next state assignment
    4. Build edge list: block_A → block_B (state transition)

    Args:
        pseudocode: Decompiled pseudocode text.
        microcode: Raw microcode text (for deeper analysis).
        timeout_ms_per_block: SMT timeout per block transition solve.

    Returns:
        Dict with dispatcher info, blocks, edges, and recovered CFG.
    """
    # Step 1: Find dispatcher pattern
    dispatcher = _find_dispatcher(pseudocode)
    if not dispatcher["found"]:
        return {
            "recovered": False,
            "reason": "No control-flow-flattening dispatcher detected.",
            "dispatcher": dispatcher,
        }

    state_var = dispatcher["state_variable"]
    cases = dispatcher["cases"]

    # Step 2: For each case, extract the state assignment at the end
    edges: list[dict[str, Any]] = []
    blocks: list[dict[str, Any]] = []

    for case in cases:
        case_value = case["value"]
        case_body = case["body"]

        # Find state variable assignments in this case
        next_states = _extract_next_states(case_body, state_var)

        block_info = {
            "state_value": case_value,
            "body_preview": case_body[:100],
            "next_states": next_states,
            "is_exit": len(next_states) == 0 and ("return" in case_body or "break" in case_body),
        }
        blocks.append(block_info)

        for ns in next_states:
            edges.append({
                "from_state": case_value,
                "to_state": ns["value"],
                "condition": ns.get("condition", "unconditional"),
            })

    # Step 3: Identify entry and exit blocks
    all_targets = {e["to_state"] for e in edges}
    all_sources = {e["from_state"] for e in edges}
    entry_candidates = all_sources - all_targets
    exit_blocks = [b for b in blocks if b["is_exit"]]

    return {
        "recovered": True,
        "dispatcher": dispatcher,
        "state_variable": state_var,
        "total_blocks": len(blocks),
        "total_edges": len(edges),
        "entry_states": sorted(entry_candidates),
        "exit_states": [b["state_value"] for b in exit_blocks],
        "blocks": blocks,
        "edges": edges,
    }


def recover_class_hierarchy(
    vtable_candidates: list[dict[str, Any]],
    function_index: list[dict[str, Any]],
    constructors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Recover C++ class hierarchy from vtable analysis.

    Uses the HexRaysPyTools constructor-store algorithm. Vtable-entry
    set comparison cannot infer inheritance: when a derived class
    overrides a virtual method, the slot holds a different function
    pointer, so the base vtable is *not* a subset of the derived vtable.
    Instead, observe how constructors install vtables.

    Two signals contribute edges:

    1. Multi-vtable constructor. A derived constructor often runs the
       base initializer first (inlined or called), which writes the
       base vtable into ``this``. The derived constructor then
       overwrites it with the derived vtable. Sorting the writes by
       instruction order yields ``base -> derived``.
    2. Constructor chain. If constructor ``A`` calls constructor
       ``B`` and each writes a distinct vtable, ``B``'s vtable is the
       base of ``A``'s.

    Args:
        vtable_candidates: ``[{address, entries: [func_addrs]}]`` from
            the data-section scan.
        function_index: Function index entries, each containing
            ``address``, ``name`` and (optionally) ``callees`` (a list
            of callee names). Used to walk the constructor call graph.
        constructors: ``[{constructor, vtable, xref_from}]`` recorded
            by the worker for every xref to a vtable. ``xref_from`` is
            the instruction address of the store, used to order writes
            within a single constructor.

    Returns:
        Dict with classes, hierarchy edges, and inheritance depth.
    """
    classes: list[dict[str, Any]] = []
    hierarchy_edges: list[dict[str, str]] = []

    # Build a map of function address -> name
    func_map: dict[str, str] = {}
    for f in function_index:
        func_map[f.get("address", "")] = f.get("name", "")

    # Map vtable address -> class_id so constructor analysis can emit
    # edges in the class-id namespace.
    vtable_to_class: dict[str, str] = {}

    for i, vtable in enumerate(vtable_candidates):
        vtable_addr = vtable.get("address", f"vtable_{i}")
        entries = vtable.get("entries", [])
        methods = [func_map.get(e, e) for e in entries]

        # Heuristic: first entry is often the destructor or type_info
        destructor = methods[0] if methods else None
        virtual_methods = methods[1:] if len(methods) > 1 else methods

        class_info = {
            "class_id": f"class_{i}",
            "vtable_address": vtable_addr,
            "method_count": len(entries),
            "destructor": destructor,
            "virtual_methods": virtual_methods[:20],
        }
        classes.append(class_info)
        vtable_to_class[vtable_addr] = f"class_{i}"

    if constructors:
        hierarchy_edges = _detect_inheritance_from_constructors(
            constructors, function_index, vtable_to_class,
        )

    return {
        "classes_found": len(classes),
        "classes": classes,
        "hierarchy_edges": hierarchy_edges,
        "inheritance_depth": _compute_depth(hierarchy_edges),
    }


def detect_protocol_state_machine(
    pseudocode: str,
    callees: list[str],
    string_refs: list[str],
) -> dict[str, Any]:
    """Detect network protocol state machine patterns.

    Args:
        pseudocode: Decompiled function pseudocode.
        callees: List of functions called by this function.
        string_refs: String references in this function.

    Returns:
        Detection result with protocol signals.
    """
    callees_lower = {c.lower() for c in callees}

    # Network API detection
    network_apis = {
        "recv", "recvfrom", "wsarecv", "send", "sendto", "wsasend",
        "winhttpreaddata", "winhttpsendrequest", "internetreadfile",
        "read", "write", "connect", "accept", "listen", "bind",
        "socket", "closesocket", "shutdown",
    }
    net_callees = callees_lower & network_apis
    has_network = bool(net_callees)

    # Command dispatch pattern
    has_switch = "switch" in pseudocode or "case " in pseudocode
    case_count = len(re.findall(r'\bcase\s+\d+', pseudocode))

    # Buffer/message parsing signals
    has_buffer_ops = bool(callees_lower & {
        "memcpy", "memmove", "memset", "malloc", "realloc",
        "ntohs", "ntohl", "htons", "htonl",
    })

    # State variable detection
    state_assigns = re.findall(r'(\w+)\s*=\s*(\d+)\s*;', pseudocode)
    potential_state_vars = [
        v for v, _ in state_assigns
        if sum(1 for v2, _ in state_assigns if v2 == v) >= 3
    ]

    # Protocol-related strings
    protocol_strings = [
        s for s in string_refs
        if any(k in s.lower() for k in (
            "http", "ftp", "smtp", "imap", "dns", "tcp", "udp",
            "connect", "auth", "login", "password", "command",
            "response", "request", "packet", "header", "payload",
        ))
    ]

    is_protocol = has_network and (has_switch or has_buffer_ops)
    if is_protocol and case_count >= 3:
        confidence = "high"
    elif is_protocol:
        confidence = "medium"
    elif has_network:
        confidence = "low"
    else:
        confidence = "none"

    return {
        "is_protocol_handler": is_protocol,
        "confidence": confidence,
        "network_apis": sorted(net_callees),
        "has_command_dispatch": has_switch and case_count >= 2,
        "command_count": case_count,
        "state_variables": sorted(set(potential_state_vars))[:5],
        "has_buffer_parsing": has_buffer_ops,
        "protocol_strings": protocol_strings[:10],
        "recv_present": bool(net_callees & {"recv", "recvfrom", "wsarecv", "winhttpreaddata", "internetreadfile"}),
        "send_present": bool(net_callees & {"send", "sendto", "wsasend", "winhttpsendrequest"}),
    }


# ---- Internal helpers ----


def _detect_inheritance_from_constructors(
    constructors: list[dict[str, Any]],
    function_index: list[dict[str, Any]],
    vtable_to_class: dict[str, str],
) -> list[dict[str, str]]:
    """Emit base/derived edges from constructor vtable-store evidence.

    Args:
        constructors: ``[{constructor, vtable, xref_from}]`` records.
        function_index: Function index entries with optional ``callees``.
        vtable_to_class: Mapping from vtable address to class id.

    Returns:
        Deduplicated list of ``{base, derived, confidence, reason}`` edges.
    """
    edges: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def emit(base_vt: str, derived_vt: str, reason: str, confidence: str) -> None:
        base_id = vtable_to_class.get(base_vt)
        derived_id = vtable_to_class.get(derived_vt)
        if not base_id or not derived_id or base_id == derived_id:
            return
        key = (base_id, derived_id)
        if key in seen:
            return
        seen.add(key)
        edges.append({
            "base": base_id,
            "derived": derived_id,
            "confidence": confidence,
            "reason": reason,
        })

    # Group every vtable store by the constructor that performs it.
    ctor_to_stores: dict[str, list[dict[str, Any]]] = {}
    for c in constructors:
        cname = c.get("constructor") or ""
        vt = c.get("vtable") or ""
        if not cname or not vt:
            continue
        ctor_to_stores.setdefault(cname, []).append(c)

    # Signal 1: a single constructor that stores multiple distinct vtables.
    # Order the stores by instruction address so the first write -- which
    # is the base initializer's write -- is treated as the base.
    for stores in ctor_to_stores.values():
        ordered = sorted(stores, key=lambda s: _parse_hex_addr(s.get("xref_from", "")))
        seen_vts: list[str] = []
        for s in ordered:
            vt = s.get("vtable", "")
            if vt and vt not in seen_vts:
                seen_vts.append(vt)
        for k in range(1, len(seen_vts)):
            emit(
                seen_vts[k - 1], seen_vts[k],
                "Constructor stores base vtable then overwrites with derived vtable.",
                "high",
            )

    # Signal 2: constructor A calls constructor B; B writes the base
    # vtable, A writes the derived vtable. Match callees by name
    # (case-insensitive) since IDA may normalize symbols differently.
    name_to_callees: dict[str, set[str]] = {}
    for f in function_index:
        fname = f.get("name") or ""
        if not fname:
            continue
        callees = f.get("callees") or ()
        name_to_callees[fname.lower()] = {str(c).lower() for c in callees}

    ctor_names_lower = {n.lower(): n for n in ctor_to_stores}
    for caller_name, caller_stores in ctor_to_stores.items():
        callees = name_to_callees.get(caller_name.lower())
        if not callees:
            continue
        for callee_lower in callees:
            callee_orig = ctor_names_lower.get(callee_lower)
            if not callee_orig or callee_orig == caller_name:
                continue
            callee_stores = ctor_to_stores.get(callee_orig, [])
            for caller_store in caller_stores:
                for callee_store in callee_stores:
                    emit(
                        callee_store.get("vtable", ""),
                        caller_store.get("vtable", ""),
                        "Constructor calls a constructor that installs a different vtable.",
                        "high",
                    )

    return edges


def _parse_hex_addr(value: str) -> int:
    """Parse a ``0x...`` or decimal address string. Returns 0 on failure."""
    if not value:
        return 0
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except (TypeError, ValueError):
        return 0


def _find_dispatcher(pseudocode: str) -> dict[str, Any]:
    """Find the CFF dispatcher pattern in pseudocode."""
    # Pattern: while(1) { switch(var) { case N: ... } }
    m = re.search(
        r'while\s*\(\s*1\s*\)\s*\{[^{]*switch\s*\(\s*(\w+)\s*\)',
        pseudocode, re.S,
    )
    if not m:
        # Try do-while
        m = re.search(
            r'do\s*\{[^{]*switch\s*\(\s*(\w+)\s*\)',
            pseudocode, re.S,
        )
    if not m:
        return {"found": False}

    state_var = m.group(1)

    # Extract cases
    cases: list[dict[str, Any]] = []
    case_pattern = re.compile(
        r'case\s+(0x[0-9a-fA-F]+|\d+)\s*:(.*?)(?=case\s+|default\s*:|}\s*})',
        re.S,
    )
    for cm in case_pattern.finditer(pseudocode):
        val_str = cm.group(1)
        val = int(val_str, 16) if val_str.startswith("0x") else int(val_str)
        body = cm.group(2).strip()
        cases.append({"value": val, "body": body})

    return {
        "found": True,
        "state_variable": state_var,
        "case_count": len(cases),
        "cases": cases,
    }


def _extract_next_states(
    case_body: str,
    state_var: str,
) -> list[dict[str, Any]]:
    """Extract state transitions from a case body."""
    transitions: list[dict[str, Any]] = []

    # Pattern: state_var = VALUE;
    for m in re.finditer(
        rf'{re.escape(state_var)}\s*=\s*(0x[0-9a-fA-F]+|\d+)',
        case_body,
    ):
        val_str = m.group(1)
        val = int(val_str, 16) if val_str.startswith("0x") else int(val_str)

        # Check if this assignment is inside an if-block
        # Simple heuristic: look at preceding text for 'if'
        preceding = case_body[:m.start()]
        last_if = preceding.rfind("if")
        if last_if >= 0 and m.start() - last_if < 100:
            # Extract condition
            cond_match = re.search(r'if\s*\(([^)]+)\)', preceding[last_if:])
            condition = cond_match.group(1) if cond_match else "conditional"
            transitions.append({"value": val, "condition": condition})
        else:
            transitions.append({"value": val, "condition": "unconditional"})

    return transitions


def _compute_depth(edges: list[dict[str, str]]) -> int:
    """Compute maximum inheritance depth from hierarchy edges."""
    if not edges:
        return 0
    children: dict[str, list[str]] = {}
    for e in edges:
        children.setdefault(e["base"], []).append(e["derived"])

    def depth(node: str, visited: set) -> int:
        if node in visited:
            return 0
        visited.add(node)
        kids = children.get(node, [])
        if not kids:
            return 0
        return 1 + max(depth(k, visited) for k in kids)

    all_bases = {e["base"] for e in edges}
    all_derived = {e["derived"] for e in edges}
    roots = all_bases - all_derived
    if not roots:
        roots = all_bases
    return max(depth(r, set()) for r in roots) if roots else 0
