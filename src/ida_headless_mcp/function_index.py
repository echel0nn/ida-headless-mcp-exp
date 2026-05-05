from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "FunctionIndexEntry",
    "FunctionIndex",
    "build_function_index",
]


@dataclass(frozen=True, slots=True)
class FunctionIndexEntry:
    address: int
    name: str
    size_bytes: int
    cyclomatic_complexity: int
    is_thunk: bool
    is_library: bool
    callers: tuple[str, ...]
    callees: tuple[str, ...]
    string_refs: tuple[str, ...]


@dataclass(slots=True)
class FunctionIndex:
    entries: list[FunctionIndexEntry]

    def save(self, path: Path) -> None:
        """Persist the index to a JSON file.

        Args:
            path: Destination file path. Parent directories are created if missing.
        """
        data = [_entry_to_json(e) for e in self.entries]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, separators=(',', ':')), encoding='utf-8')

    @classmethod
    def load(cls, path: Path) -> FunctionIndex:
        """Load an index from a JSON file written by ``save``.

        Args:
            path: Source file path.

        Returns:
            The deserialized ``FunctionIndex``.
        """
        raw = json.loads(path.read_text(encoding='utf-8'))
        entries = [
            FunctionIndexEntry(
                address=int(r['address'], 16),
                name=r['name'],
                size_bytes=r['size_bytes'],
                cyclomatic_complexity=r['cyclomatic_complexity'],
                is_thunk=r['is_thunk'],
                is_library=r['is_library'],
                callers=tuple(r['callers']),
                callees=tuple(r['callees']),
                string_refs=tuple(r['string_refs']),
            )
            for r in raw
        ]
        return cls(entries=entries)

    def lookup(self, name: str) -> dict[str, Any] | None:
        """Look up a function by name, returning its entry as a dict or None."""
        name_lower = name.lower()
        for entry in self.entries:
            if entry.name.lower() == name_lower:
                return _entry_to_json(entry)
        return None

    def query(
        self,
        *,
        name_pattern: str = "",
        callers_of: list[str] | None = None,
        called_by: list[str] | None = None,
        min_size_bytes: int = 0,
        max_size_bytes: int | None = None,
        min_complexity: int = 0,
        max_complexity: int | None = None,
        has_string_ref_matching: str = "",
        imports_only: bool = False,
        exclude_thunks: bool = False,
        exclude_libraries: bool = False,
        order_by: str = "name",
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        rows = self.entries
        np = name_pattern.lower().strip()
        string_match = has_string_ref_matching.lower().strip()
        callers_of_set = {x.lower() for x in callers_of or [] if str(x).strip()}
        called_by_set = {x.lower() for x in called_by or [] if str(x).strip()}

        filtered: list[FunctionIndexEntry] = []
        for entry in rows:
            if np and np not in entry.name.lower():
                continue
            if min_size_bytes and entry.size_bytes < min_size_bytes:
                continue
            if max_size_bytes is not None and entry.size_bytes > max_size_bytes:
                continue
            if min_complexity and entry.cyclomatic_complexity < min_complexity:
                continue
            if max_complexity is not None and entry.cyclomatic_complexity > max_complexity:
                continue
            if exclude_thunks and entry.is_thunk:
                continue
            if exclude_libraries and entry.is_library:
                continue
            if imports_only and not entry.is_library:
                continue
            if callers_of_set and not any(callee.lower() in callers_of_set for callee in entry.callees):
                continue
            if called_by_set and not any(caller.lower() in called_by_set for caller in entry.callers):
                continue
            if string_match and not any(string_match in s.lower() for s in entry.string_refs):
                continue
            filtered.append(entry)

        filtered.sort(key=_sort_key(order_by))
        total = len(filtered)
        page = filtered[offset : offset + limit]
        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "functions": [_entry_to_json(e) for e in page],
        }


def build_function_index() -> FunctionIndex:
    import ida_funcs
    import ida_gdl
    import ida_name
    import idautils

    string_eas = {int(s.ea) for s in idautils.Strings()}
    entries: list[FunctionIndexEntry] = []

    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if func is None:
            continue
        name = ida_name.get_ea_name(func.start_ea)
        callers = _collect_callers(func.start_ea)
        callees = _collect_callees(func.start_ea)
        string_refs = _collect_string_refs(func.start_ea, string_eas)
        complexity = _cyclomatic_complexity(func, ida_gdl)
        entries.append(
            FunctionIndexEntry(
                address=func.start_ea,
                name=name,
                size_bytes=func.size(),
                cyclomatic_complexity=complexity,
                is_thunk=bool(func.flags & ida_funcs.FUNC_THUNK),
                is_library=bool(func.flags & ida_funcs.FUNC_LIB),
                callers=tuple(sorted(callers)),
                callees=tuple(sorted(callees)),
                string_refs=tuple(sorted(string_refs)),
            )
        )
    return FunctionIndex(entries=entries)


def _collect_callers(func_ea: int) -> set[str]:
    import ida_funcs
    import idautils

    callers: set[str] = set()
    for ref in idautils.CodeRefsTo(func_ea, 0):
        caller = ida_funcs.get_func(ref)
        if caller and caller.start_ea != func_ea:
            callers.add(ida_funcs.get_func_name(caller.start_ea))
    return callers


def _collect_callees(func_ea: int) -> set[str]:
    import ida_funcs
    import idautils

    func = ida_funcs.get_func(func_ea)
    if func is None:
        return set()
    callees: set[str] = set()
    for head in idautils.FuncItems(func.start_ea):
        for callee_ea in idautils.CodeRefsFrom(head, 0):
            callee = ida_funcs.get_func(callee_ea)
            if callee and callee.start_ea != func.start_ea:
                callees.add(ida_funcs.get_func_name(callee.start_ea))
    return callees


def _collect_string_refs(func_ea: int, string_eas: set[int]) -> set[str]:
    import ida_bytes
    import ida_funcs
    import ida_nalt
    import idautils

    func = ida_funcs.get_func(func_ea)
    if func is None:
        return set()
    out: set[str] = set()
    for head in idautils.FuncItems(func.start_ea):
        for ref in idautils.DataRefsFrom(head):
            if ref not in string_eas:
                continue
            flags = ida_bytes.get_full_flags(ref)
            if not ida_bytes.is_strlit(flags):
                continue
            text = ida_bytes.get_strlit_contents(ref, -1, ida_nalt.STRTYPE_C)
            if isinstance(text, bytes):
                try:
                    out.add(text.decode("utf-8", errors="replace"))
                except Exception:
                    out.add(repr(text))
    return out


def _cyclomatic_complexity(func: Any, ida_gdl: Any) -> int:
    try:
        fc = ida_gdl.FlowChart(func)
    except Exception:
        return 1
    node_count = fc.size
    edge_count = 0
    for bb in fc:
        edge_count += sum(1 for _ in bb.succs())
    if node_count == 0:
        return 1
    return max(1, edge_count - node_count + 2)


def _sort_key(order_by: str):
    if order_by == "size_desc":
        return lambda e: (-e.size_bytes, e.name)
    if order_by == "complexity_desc":
        return lambda e: (-e.cyclomatic_complexity, e.name)
    if order_by == "callers_desc":
        return lambda e: (-len(e.callers), e.name)
    if order_by == "callees_desc":
        return lambda e: (-len(e.callees), e.name)
    if order_by == "strings_desc":
        return lambda e: (-len(e.string_refs), e.name)
    return lambda e: e.name.lower()


def _entry_to_json(entry: FunctionIndexEntry) -> dict[str, Any]:
    return {
        "address": f"0x{entry.address:x}",
        "name": entry.name,
        "size_bytes": entry.size_bytes,
        "cyclomatic_complexity": entry.cyclomatic_complexity,
        "is_thunk": entry.is_thunk,
        "is_library": entry.is_library,
        "callers_count": len(entry.callers),
        "callees_count": len(entry.callees),
        "string_refs_count": len(entry.string_refs),
        "callers": list(entry.callers),
        "callees": list(entry.callees),
        "string_refs": list(entry.string_refs),
    }
