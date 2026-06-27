"""Tests for the control-flow-flattening (CFF) detection stack.

The patterns are pure ``BlockInfo``-shaped detectors, so the suite is
synthetic: every fixture is built in-memory with the same instruction-dict
shape that ``cff_helpers._extract_block_info`` produces from miasm. The
only test that touches a real file optionally parses ``notepad.exe`` and
is skipped when not on Windows.
"""
# Imports follow ``sys.path.insert`` so isort cannot move them up.
# ruff: noqa: E402, I001
from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ida_headless_mcp.cff_helpers import _state_threshold
from ida_headless_mcp.cff_techniques import (
    BlockInfo,
    OpaquePredicatePattern,
    load_signatures,
)
from ida_headless_mcp.cff_techniques.dispatchers import (
    CmpJeTableDispatcher,
    PushRetDispatcher,
    SubJzChainDispatcher,
    SwitchJumpTableDispatcher,
)
from ida_headless_mcp.cff_techniques.opaque_predicates import (
    LcgOpaquePredicate,
    QuadraticOpaquePredicate,
)
from ida_headless_mcp.cff_techniques.signatures import match_signature
from ida_headless_mcp.cff_techniques.state_variables import (
    StackAnyOffsetDetector,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _ins(mnem: str, operands: str = "", *, offset: int = 0, size: int = 4,
         **extra: object) -> dict:
    """Build one instruction dict in the shape ``_extract_block_info`` emits."""
    record: dict = {"mnemonic": mnem, "operands": operands,
                    "offset": offset, "size": size}
    record.update(extra)
    return record


def _sub_jz_pairs(pairs: list[tuple[int, int]], base: int = 0x1000) -> list[dict]:
    """Build a stream of ``SUB EAX, K; JZ handler`` pairs at consecutive VAs."""
    out: list[dict] = []
    addr = base
    for key, target in pairs:
        out.append(_ins("SUB", f"EAX, 0x{key:X}", offset=addr, size=6))
        addr += 6
        out.append(_ins("JZ", f"loc_{target:x}", offset=addr, size=2,
                        _resolved_target=target))
        addr += 2
    return out


def _make_payload(*, dispatcher: str | None = None,
                  opaques: list[str] | None = None,
                  state_var: str | None = None,
                  characteristics: dict | None = None) -> SimpleNamespace:
    """Construct a minimal detection-shaped object for ``match_signature``."""
    return SimpleNamespace(
        dispatcher_patterns=[dispatcher] if dispatcher else [],
        opaque_patterns=list(opaques or []),
        state_var_types=[state_var] if state_var else [],
        characteristics=dict(characteristics or {}),
    )


def _state_write_block(addr: int, offset: int, value: int = 0x12345678) -> BlockInfo:
    """Block whose only instruction writes ``value`` to ``[RSP + offset]``."""
    return BlockInfo(address=addr, instructions=[
        _ins("MOV", f"DWORD PTR [RSP + 0x{offset:X}], 0x{value:X}",
             offset=addr, size=8),
    ])


# ---------------------------------------------------------------------------
# 1. Dispatcher pattern detection
# ---------------------------------------------------------------------------


def test_sub_jz_chain_detects_three_pairs():
    """Three SUB+JZ pairs cross the OLLVM-lowering floor."""
    block = BlockInfo(address=0x1000, instructions=_sub_jz_pairs([
        (0x12345678, 0x2000),
        (0x9ABCDEF0, 0x3000),
        (0xCAFEBABE, 0x4000),
    ]))
    assert SubJzChainDispatcher().detect(block, {}) >= 0.9


def test_sub_jz_chain_detects_five_pairs_high_confidence():
    """Five SUB+JZ pairs reach the near-certain band."""
    pairs = [(0x10000000 + i * 0x11111111, 0x2000 + i * 0x100)
             for i in range(5)]
    block = BlockInfo(address=0x1000, instructions=_sub_jz_pairs(pairs))
    assert SubJzChainDispatcher().detect(block, {}) >= 0.95


def test_sub_jz_chain_rejects_small_immediates():
    """Compiler switches with small ints must not score as CFF."""
    block = BlockInfo(address=0x1000, instructions=[
        _ins("SUB", "EAX, 1", offset=0x1000, size=3),
        _ins("JZ", "loc_2000", offset=0x1003, size=2, _resolved_target=0x2000),
        _ins("SUB", "EAX, 2", offset=0x1005, size=3),
        _ins("JZ", "loc_3000", offset=0x1008, size=2, _resolved_target=0x3000),
        _ins("SUB", "EAX, 3", offset=0x100A, size=3),
        _ins("JZ", "loc_4000", offset=0x100D, size=2, _resolved_target=0x4000),
    ])
    assert SubJzChainDispatcher().detect(block, {}) == 0.0


def test_sub_jz_chain_extract_states_resolves_handlers():
    """``extract_states`` recovers the handler VA for each SUB/JZ pair."""
    block = BlockInfo(address=0x1000, instructions=_sub_jz_pairs([
        (0x12345678, 0x2000),
        (0x9ABCDEF0, 0x3000),
        (0xCAFEBABE, 0x4000),
    ]))
    states = SubJzChainDispatcher().extract_states(block, {})
    assert set(states.values()) == {0x2000, 0x3000, 0x4000}
    assert len(states) == 3


def test_cmp_je_table_detect():
    """Three CMP/JE pairs match the independent-table dispatcher."""
    block = BlockInfo(address=0x1000, instructions=[
        _ins("CMP", "EAX, 0x12345678", offset=0x1000, size=6),
        _ins("JE", "loc_2000", offset=0x1006, size=2, _resolved_target=0x2000),
        _ins("CMP", "EAX, 0x9ABCDEF0", offset=0x1008, size=6),
        _ins("JE", "loc_3000", offset=0x100E, size=2, _resolved_target=0x3000),
        _ins("CMP", "EAX, 0xCAFEBABE", offset=0x1010, size=6),
        _ins("JE", "loc_4000", offset=0x1016, size=2, _resolved_target=0x4000),
    ])
    assert CmpJeTableDispatcher().detect(block, {}) >= 0.9


def test_push_ret_detect():
    """Trailing ``PUSH imm; RET`` is recognised as a push/ret shim."""
    block = BlockInfo(address=0x1000, instructions=[
        _ins("PUSH", "0x4000", offset=0x1000, size=5),
        _ins("RET", "", offset=0x1005, size=1),
    ])
    assert PushRetDispatcher().detect(block, {}) >= 0.85


def test_switch_jump_table_detect():
    """Indexed memory ``JMP [reg*scale + base]`` matches the switch dispatcher."""
    block = BlockInfo(address=0x1000, instructions=[
        _ins("JMP", "QWORD PTR [RAX*8 + 0x140001000]",
             offset=0x1000, size=7),
    ])
    assert SwitchJumpTableDispatcher().detect(block, {}) >= 0.6


# ---------------------------------------------------------------------------
# 2. Opaque-predicate detection
# ---------------------------------------------------------------------------


def test_lcg_detect_cmov_variant():
    """LCG data-flow variant: IMUL+DIV+CMOVZ with a single successor."""
    block = BlockInfo(
        address=0x1000,
        successors=[0x2000],
        has_imul=True, has_div=True, has_call=False,
        instructions=[
            _ins("MOV",   "EAX, EBX",            offset=0x1000),
            _ins("IMUL",  "EAX, EBX, 0x269EC3",  offset=0x1003),
            _ins("MOV",   "ECX, 0x10000",        offset=0x1009),
            _ins("DIV",   "ECX",                 offset=0x100E),
            _ins("CMOVZ", "EAX, EDX",            offset=0x1010),
        ],
    )
    assert LcgOpaquePredicate.detect(block) >= 0.8


def test_lcg_detect_control_flow_variant():
    """LCG control-flow variant: IMUL+DIV+CMP large + Jcc with two successors."""
    block = BlockInfo(
        address=0x1000,
        successors=[0x2000, 0x3000],
        has_imul=True, has_div=True, has_call=False,
        instructions=[
            _ins("IMUL", "EAX, EBX, 0x269EC3", offset=0x1000),
            _ins("MOV",  "ECX, 0x10000",       offset=0x1006),
            _ins("DIV",  "ECX",                offset=0x100B),
            _ins("CMP",  "EAX, 0x12345678",    offset=0x100D),
            _ins("JNZ",  "loc_3000",           offset=0x1013,
                 _resolved_target=0x3000),
        ],
    )
    assert LcgOpaquePredicate.detect(block) >= 0.8


def test_lcg_rejects_call_block():
    """A block that calls something is not an opaque-predicate stub."""
    block = BlockInfo(
        address=0x1000,
        successors=[0x2000],
        has_imul=True, has_div=True, has_call=True,
        instructions=[
            _ins("IMUL",  "EAX, EBX, 0x269EC3", offset=0x1000),
            _ins("DIV",   "ECX",                offset=0x1006),
            _ins("CALL",  "0x500000",           offset=0x1008),
            _ins("CMOVZ", "EAX, EDX",           offset=0x100D),
        ],
    )
    assert LcgOpaquePredicate.detect(block) == 0.0


def test_lcg_rejects_block_without_imul_div():
    """Without both IMUL and DIV the LCG detector must abstain."""
    block = BlockInfo(
        address=0x1000,
        successors=[0x2000, 0x3000],
        has_call=False,
        instructions=[
            _ins("MOV", "EAX, 1",   offset=0x1000),
            _ins("CMP", "EAX, 0",   offset=0x1003),
            _ins("JZ",  "loc_3000", offset=0x1005,
                 _resolved_target=0x3000),
        ],
    )
    assert LcgOpaquePredicate.detect(block) == 0.0


def test_quadratic_detect():
    """Quadratic predicate: IMUL same-reg + AND/TEST 1 + Jcc, no CALL."""
    block = BlockInfo(
        address=0x1000,
        successors=[0x2000, 0x3000],
        has_call=False,
        instructions=[
            _ins("MOV",  "EAX, EBX", offset=0x1000),
            _ins("IMUL", "EAX, EAX", offset=0x1003),
            _ins("AND",  "EAX, 1",   offset=0x1005),
            _ins("JZ",   "loc_2000", offset=0x1008,
                 _resolved_target=0x2000),
        ],
    )
    assert QuadraticOpaquePredicate.detect(block) >= 0.8


def test_quadratic_rejects_no_modulo_two():
    """A block missing the ``AND/TEST 1`` modulo-2 check must score zero."""
    block = BlockInfo(
        address=0x1000,
        successors=[0x2000, 0x3000],
        has_call=False,
        instructions=[
            _ins("IMUL", "EAX, EAX", offset=0x1000),
            _ins("CMP",  "EAX, 5",   offset=0x1003),
            _ins("JZ",   "loc_2000", offset=0x1006,
                 _resolved_target=0x2000),
        ],
    )
    assert QuadraticOpaquePredicate.detect(block) == 0.0


# ---------------------------------------------------------------------------
# 3. State-variable detection
# ---------------------------------------------------------------------------


def test_stack_any_finds_most_written_offset():
    """Highest-frequency stack offset wins."""
    blocks = [
        _state_write_block(0x1000, 0x24, 0x11111111),
        _state_write_block(0x2000, 0x24, 0x22222222),
        _state_write_block(0x3000, 0x24, 0x33333333),
        _state_write_block(0x4000, 0x24, 0x44444444),
        _state_write_block(0x5000, 0x24, 0x55555555),
        _state_write_block(0x6000, 0x30, 0x66666666),
        _state_write_block(0x7000, 0x30, 0x77777777),
    ]
    info = StackAnyOffsetDetector.detect(blocks)
    assert info is not None
    assert info.location_type == "stack"
    assert info.offset == 0x24


def test_stack_any_returns_none_for_single_writer():
    """A single writing block does not pin a state offset."""
    blocks = [_state_write_block(0x1000, 0x24)]
    assert StackAnyOffsetDetector.detect(blocks) is None


def test_stack_any_ignores_scratch_offsets():
    """Stack offsets <= 7 bytes are scratch slots, not state slots."""
    blocks = [
        _state_write_block(0x1000, 0x4, 0x11111111),
        _state_write_block(0x2000, 0x4, 0x22222222),
        _state_write_block(0x3000, 0x4, 0x33333333),
    ]
    assert StackAnyOffsetDetector.detect(blocks) is None


# ---------------------------------------------------------------------------
# 4. Signature matching
# ---------------------------------------------------------------------------


def test_lcg_stack_cff_signature_matches():
    """sub_jz_chain + lcg + stack_fixed uniquely picks the LCG-CFF variant."""
    payload = _make_payload(dispatcher="sub_jz_chain",
                            opaques=["lcg"], state_var="stack_fixed")
    best, score = match_signature(payload, load_signatures())
    assert best is not None
    assert best.name == "lcg_stack_cff"
    assert score >= 0.5


def test_ollvm_signature_matches():
    """sub_jz_chain + quadratic + stack_any picks the OLLVM family."""
    payload = _make_payload(dispatcher="sub_jz_chain",
                            opaques=["quadratic"], state_var="stack_any")
    best, score = match_signature(payload, load_signatures())
    assert best is not None
    # ``ollvm_vanilla`` and ``hikari`` tie at 0.8; the first registered wins.
    assert best.name == "ollvm_vanilla"
    assert score >= 0.5


def test_signature_match_below_threshold_returns_none():
    """A bare dispatcher hit (score 0.3) is below the family-naming floor."""
    payload = _make_payload(dispatcher="sub_jz_chain")
    best, score = match_signature(payload, load_signatures())
    assert best is None
    assert score == 0.0


def test_signature_match_empty_detection_returns_none():
    """An empty detection must not silently latch the weakest signature."""
    payload = _make_payload()
    best, score = match_signature(payload, load_signatures())
    assert best is None
    assert score == 0.0


def test_load_signatures_known_set():
    """The shipped signature database lists the five documented variants."""
    names = {sig.name for sig in load_signatures()}
    assert names == {
        "ollvm_vanilla", "hikari", "lcg_stack_cff",
        "tigress", "themida_cff",
    }


# ---------------------------------------------------------------------------
# 5. resolve_cmov on opaque predicates
# ---------------------------------------------------------------------------


def test_resolve_cmov_always_true_lcg():
    """LCG is always-true (ZF=1): CMOVZ/E fire, CMOVNZ/NE do not."""
    assert LcgOpaquePredicate.resolve_cmov("CMOVZ") == "src"
    assert LcgOpaquePredicate.resolve_cmov("CMOVE") == "src"
    assert LcgOpaquePredicate.resolve_cmov("CMOVNZ") == "dst"
    assert LcgOpaquePredicate.resolve_cmov("CMOVNE") == "dst"


def test_resolve_cmov_always_false_predicate():
    """An always-false predicate inverts the firing logic."""

    class _AlwaysFalse(OpaquePredicatePattern):
        always_true = False

        def detect(self, block):  # pragma: no cover - trivial
            return 0.0

        def extract_constants(self, block):  # pragma: no cover - trivial
            return {}

    assert _AlwaysFalse.resolve_cmov("CMOVZ") == "dst"
    assert _AlwaysFalse.resolve_cmov("CMOVE") == "dst"
    assert _AlwaysFalse.resolve_cmov("CMOVNZ") == "src"
    assert _AlwaysFalse.resolve_cmov("CMOVNE") == "src"


# ---------------------------------------------------------------------------
# 6. _state_threshold
# ---------------------------------------------------------------------------


def test_state_threshold_large_values():
    """Large 32-bit state constants → half the smallest, floored."""
    assert _state_threshold([0x12345678, 0x9ABCDEF0]) == 0x091A2B3C


def test_state_threshold_small_values():
    """Small ints still divide cleanly by two."""
    assert _state_threshold([5, 10, 15]) == 2


def test_state_threshold_empty():
    """Empty input falls back to 0xFFFF (the default state-write filter)."""
    assert _state_threshold([]) == 0xFFFF


def test_state_threshold_zero_input():
    """A zero-valued state is clamped to a non-negative threshold."""
    assert _state_threshold([0, 100]) == 0


# ---------------------------------------------------------------------------
# 7. PE imports -- optional, skipped without a real Windows PE
# ---------------------------------------------------------------------------


_NOTEPAD = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "notepad.exe"


@pytest.mark.skipif(
    sys.platform != "win32" or not _NOTEPAD.exists(),
    reason="requires notepad.exe on Windows",
)
def test_build_iat_map_returns_dict():
    """``build_iat_map`` parses a real PE and returns ``{iat_va: 'DLL!Func'}``."""
    from ida_headless_mcp.pe_imports import build_iat_map

    iat_map = build_iat_map(_NOTEPAD)
    assert isinstance(iat_map, dict)
    assert iat_map, "notepad.exe is expected to import at least one symbol"
    sample_key, sample_val = next(iter(iat_map.items()))
    assert isinstance(sample_key, int)
    assert isinstance(sample_val, str)
    assert "!" in sample_val


def test_build_iat_map_missing_path_returns_empty():
    """Missing files surface as an empty mapping, not an exception."""
    from ida_headless_mcp.pe_imports import build_iat_map

    assert build_iat_map(Path("does_not_exist__cff_test__.bin")) == {}
