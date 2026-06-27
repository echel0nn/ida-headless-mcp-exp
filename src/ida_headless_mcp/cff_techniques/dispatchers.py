"""Dispatcher detection patterns for control-flow flattening (CFF).

Each pattern is a subclass of :class:`DispatcherPattern` that recognises a
specific obfuscation flavour and, when possible, recovers the
``state_value -> handler_address`` mapping that the dispatcher implements.

Patterns operate purely on the abstract :class:`BlockInfo` shape exported by
``_types`` -- they never call into miasm or any disassembler. This keeps the
detection layer fast (millisecond-scale) and lets the same code drive both
static scans and live-decompiler queries.

Patterns implemented
--------------------
- :class:`SubJzChainDispatcher`: OLLVM's vanilla ``SUB reg, K; JZ handler``
  cumulative chain. Found in OLLVM, Hikari and LCG-CFF variants.
- :class:`CmpJeTableDispatcher`: ``CMP reg, K; JE handler`` table where each
  state value is independent (not cumulative). Found in some Themida CFF
  modes and custom OLLVM forks.
- :class:`SwitchJumpTableDispatcher`: Compiler-style indexed jump table
  ``JMP [reg*scale + base]``. Lower confidence -- could be a legitimate
  switch -- and static state extraction needs the binary jump table.
- :class:`IndirectComputedDispatcher`: ``JMP reg`` where the register is
  computed from the state variable. Found in VMProtect's CFF mode and
  bespoke obfuscators. State extraction requires symbolic execution.
- :class:`PushRetDispatcher`: ``PUSH target; RET`` used in place of a
  direct ``JMP``. Common in anti-disassembly tricks and packers.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from ._types import DispatcherPattern

if TYPE_CHECKING:
    from ._types import BlockInfo

__all__ = [
    "SubJzChainDispatcher",
    "CmpJeTableDispatcher",
    "SwitchJumpTableDispatcher",
    "IndirectComputedDispatcher",
    "PushRetDispatcher",
]

# Threshold above which an immediate is treated as a CFF state constant.
# Real-world dispatchers use 32-bit (and occasionally 64-bit) randomised
# constants; legitimate compiler emits at most small switch indices.
_LARGE_IMM_THRESHOLD = 0xFFFF

# Conditional-jump mnemonics that fire when the previous SUB/CMP yielded
# zero -- these are the only branches that complete a state-match dispatch.
_ZERO_BRANCH_MNEMONICS = frozenset({"JZ", "JE"})


def _mnem(instr: object) -> str:
    """Return the upper-case mnemonic of an instruction record."""
    if isinstance(instr, dict):
        name = instr.get("mnemonic", "") or ""
    else:
        name = getattr(instr, "mnemonic", "") or ""
    return name.upper()


def _largest_immediate(instr: object) -> int | None:
    """Return the largest immediate operand on the instruction, if any.

    Handles both structured instruction objects (with .immediates list)
    and dict-style records (with 'operands' string).
    """
    import re
    imms = getattr(instr, "immediates", None) or []
    if not imms:
        # Parse from operands string: '0x882188E4' or decimal
        ops = ""
        if isinstance(instr, dict):
            ops = instr.get("operands", "") or ""
        else:
            ops = getattr(instr, "operands", "") or ""
        # Find hex values
        hex_vals = re.findall(r'0[xX]([0-9a-fA-F]+)', ops)
        for h in hex_vals:
            imms.append(int(h, 16))
        # Find bare decimal values > 255 (skip small register-like numbers)
        dec_vals = re.findall(r'\b(\d+)\b', ops)
        for d in dec_vals:
            v = int(d)
            if v > 255:
                imms.append(v)
    if not imms:
        return None
    return max(imms)


def _jump_target(instr: object) -> int | None:
    """Return the resolved branch target of a jump-style instruction.

    Resolution order:
      1. ``_resolved_target`` annotation populated by the CFG aggregator.
         The aggregator knows which CFG successor of a block is the
         conditional branch destination (handler) versus the
         fallthrough (next dispatcher sub-block).
      2. ``.immediates`` list on structured instruction objects.
      3. The first hexadecimal literal in the operand string.

    Returns:
        Absolute branch target VA, or ``None`` when the operand encodes
        a label (e.g. miasm's ``loc_key_N``) that cannot be resolved
        without a location database.
    """
    import re
    if isinstance(instr, dict):
        resolved = instr.get("_resolved_target")
        if isinstance(resolved, int):
            return resolved
        ops = instr.get("operands", "") or ""
    else:
        imms = getattr(instr, "immediates", None) or []
        if imms:
            return imms[0]
        ops = getattr(instr, "operands", "") or ""
    match = re.search(r'0[xX]([0-9a-fA-F]+)', ops)
    if match:
        return int(match.group(1), 16)
    return None


def _first_arg(instr: object) -> str:
    """Return the first textual operand or an empty string."""
    if isinstance(instr, dict):
        ops = instr.get("operands", "") or ""
        if ',' in ops:
            return ops.split(',', 1)[0].strip()
        return ops.strip()
    args = getattr(instr, "args", None) or []
    return args[0] if args else ""


class SubJzChainDispatcher(DispatcherPattern):
    """OLLVM-style cumulative SUB/JZ dispatcher.

    The dispatcher block contains a chain of ``SUB reg, K; JZ handler``
    pairs. Each ``SUB`` decrements the live state register; the matching
    ``JZ`` fires when the cumulative subtraction has reached zero, i.e.
    when the original state equalled the running sum of all preceding
    constants.
    """

    name = "sub_jz_chain"
    description = (
        "OLLVM standard: chain of SUB reg, K; JZ handler pairs where the "
        "state register is decremented cumulatively"
    )

    def detect(self, block: BlockInfo, cfg_blocks: dict[int, BlockInfo]) -> float:
        """Return a confidence score based on the number of SUB+JZ pairs.

        Counts adjacent ``SUB``/``CMP`` instructions whose immediate is
        large (likely a 32-bit randomised state constant) followed by a
        zero-branch. The OLLVM lowering always emits at least three pairs;
        five or more is a near-certain match.
        """
        instrs = list(getattr(block, "instructions", []) or [])
        pairs = 0
        for i in range(len(instrs) - 1):
            cur, nxt = instrs[i], instrs[i + 1]
            if _mnem(cur) not in {"SUB", "CMP"}:
                continue
            imm = _largest_immediate(cur)
            if imm is None or imm <= _LARGE_IMM_THRESHOLD:
                continue
            if _mnem(nxt) not in _ZERO_BRANCH_MNEMONICS:
                continue
            pairs += 1
        if pairs >= 5:
            return 0.95
        if pairs >= 3:
            return 0.9
        return 0.0

    def extract_states(
        self,
        block: BlockInfo,
        cfg_blocks: dict[int, BlockInfo],
    ) -> dict[int, int]:
        """Return ``{state_value: handler_address}`` for the SUB chain.

        Handles two dispatcher layouts:
        - Single-block cumulative: SUB subtracts from a live register;
          state = running sum of all preceding SUB immediates.
        - Multi-block reload: each comparison block reloads the register
          from the state variable (MOV reg, reg) before SUB; state = raw
          SUB immediate.
        """
        instrs = list(getattr(block, "instructions", []) or [])
        states: dict[int, int] = {}

        # Detect if the chain uses register reloads (MOV reg, reg)
        # between SUBs. If ANY reload exists, all SUBs are non-cumulative.
        has_reload = False
        for instr in instrs:
            if _mnem(instr) == "MOV":
                ops = instr.get("operands", "") if isinstance(instr, dict) else getattr(instr, "operands", "")
                parts = [p.strip() for p in (ops or "").split(",")]
                if (len(parts) == 2
                        and not any(c in parts[1] for c in "[+*")
                        and not any(c in parts[1] for c in "0x")
                        and parts[1].replace(' ', '').isalpha()):
                    has_reload = True
                    break

        cumulative = 0
        for i in range(len(instrs)):
            cur = instrs[i]
            mnem = _mnem(cur)
            if mnem not in {"SUB", "CMP"}:
                continue
            imm = _largest_immediate(cur)
            if imm is None or imm <= _LARGE_IMM_THRESHOLD:
                continue
            # Look ahead for JZ/JE (may be 1-2 instructions after SUB)
            target = None
            for j in range(i + 1, min(i + 3, len(instrs))):
                if _mnem(instrs[j]) in _ZERO_BRANCH_MNEMONICS:
                    target = _jump_target(instrs[j])
                    break
            if target is None:
                if mnem == "SUB" and not has_reload:
                    cumulative += imm
                continue
            if mnem == "CMP" or has_reload:
                states[imm & 0xFFFFFFFF] = target
            else:
                cumulative += imm
                states[cumulative & 0xFFFFFFFF] = target
        return states


class CmpJeTableDispatcher(DispatcherPattern):
    """Independent ``CMP reg, K; JE handler`` table dispatcher.

    Unlike the cumulative SUB chain, every ``CMP`` reads the same register
    without modifying it, so each immediate maps directly to its branch
    target.
    """

    name = "cmp_je_table"
    description = (
        "Independent CMP reg, K; JE handler table where each state value "
        "is matched against an unchanged register"
    )

    def detect(self, block: BlockInfo, cfg_blocks: dict[int, BlockInfo]) -> float:
        """Confidence rises with the number of CMP+JE pairs in the block.

        Pure CMP chains (no SUB) are the discriminator: a SUB+JZ fragment
        belongs to :class:`SubJzChainDispatcher`. We require at least
        three table entries to outweigh ordinary equality testing.
        """
        instrs = list(getattr(block, "instructions", []) or [])
        cmp_pairs = 0
        sub_pairs = 0
        for i in range(len(instrs) - 1):
            cur, nxt = instrs[i], instrs[i + 1]
            mnem = _mnem(cur)
            imm = _largest_immediate(cur)
            if imm is None or imm <= _LARGE_IMM_THRESHOLD:
                continue
            if _mnem(nxt) not in _ZERO_BRANCH_MNEMONICS:
                continue
            if mnem == "CMP":
                cmp_pairs += 1
            elif mnem == "SUB":
                sub_pairs += 1
        # If SUBs dominate we defer to SubJzChainDispatcher -- that pattern
        # already understands how to walk a mixed chain.
        if sub_pairs >= cmp_pairs and sub_pairs >= 3:
            return 0.0
        if cmp_pairs >= 5:
            return 0.95
        if cmp_pairs >= 3:
            return 0.9
        return 0.0

    def extract_states(
        self,
        block: BlockInfo,
        cfg_blocks: dict[int, BlockInfo],
    ) -> dict[int, int]:
        """Return ``{cmp_immediate: handler_address}`` for each CMP+JE pair."""
        instrs = list(getattr(block, "instructions", []) or [])
        states: dict[int, int] = {}
        for i in range(len(instrs) - 1):
            cur, nxt = instrs[i], instrs[i + 1]
            if _mnem(cur) != "CMP":
                continue
            imm = _largest_immediate(cur)
            if imm is None or imm <= _LARGE_IMM_THRESHOLD:
                continue
            if _mnem(nxt) not in _ZERO_BRANCH_MNEMONICS:
                continue
            target = _jump_target(nxt)
            if target is None:
                continue
            states[imm] = target
        return states


class SwitchJumpTableDispatcher(DispatcherPattern):
    """Compiler-style indexed jump-table dispatcher.

    Recognises the ``JMP [base + index*scale]`` shape that the C compiler
    generates for dense switch statements and that several CFF passes
    re-use as a dispatcher. The pattern alone cannot distinguish a
    legitimate switch from an obfuscated dispatcher, so the confidence
    score stays moderate.
    """

    name = "switch_jump_table"
    description = (
        "Indexed memory jump (JMP [reg*scale + base_table]) -- covers both "
        "compiler-emitted switches and table-driven CFF dispatchers"
    )

    def __init__(self) -> None:
        """Initialise the per-instance jump-table base address slot."""
        self.table_base: int | None = None

    def detect(self, block: BlockInfo, cfg_blocks: dict[int, BlockInfo]) -> float:
        """Return 0.7 if the block ends in an indexed memory ``JMP``.

        Looks for the textual ``[..*scale..]`` pattern in the operand of
        the terminating ``JMP``. Scale values 4 and 8 cover the natural
        pointer sizes on 32- and 64-bit targets.
        """
        instrs = list(getattr(block, "instructions", []) or [])
        if not instrs:
            return 0.0
        last = instrs[-1]
        if _mnem(last) != "JMP":
            return 0.0
        operand = _first_arg(last)
        if "[" not in operand or "]" not in operand:
            return 0.0
        if "*" not in operand:
            return 0.0
        # Require an addition to the scaled index (the table base).
        if "+" not in operand:
            return 0.0
        scale_present = any(token in operand for token in ("*4", "*8", "*2", "*scale"))
        if not scale_present:
            return 0.0
        return 0.7

    def extract_states(
        self,
        block: BlockInfo,
        cfg_blocks: dict[int, BlockInfo],
    ) -> dict[int, int]:
        """Record the jump-table base; defer the table read to the caller.

        The table contents live in ``.rdata`` which the abstract
        :class:`BlockInfo` API does not expose. We capture the literal
        base address from the indexed-jump operand and stash it on
        ``self.table_base`` for the binary-aware caller to read.
        """
        import re
        self.table_base = None
        instrs = list(getattr(block, "instructions", []) or [])
        if not instrs:
            return {}
        last = instrs[-1]
        if _mnem(last) != "JMP":
            return {}
        operand = _first_arg(last)
        hex_vals = re.findall(r"0[xX]([0-9a-fA-F]+)", operand)
        if hex_vals:
            self.table_base = max(int(h, 16) for h in hex_vals)
        return {}


class IndirectComputedDispatcher(DispatcherPattern):
    """Indirect ``JMP reg`` where the target is computed from the state.

    The register is loaded from a runtime computation involving the state
    variable (e.g. ``mov rax, [state*8 + table]; xor rax, key; jmp rax``).
    Static state recovery is impossible -- the analysis layer must defer
    to symbolic execution.
    """

    name = "indirect_computed"
    description = (
        "JMP reg where reg is computed at runtime from the state variable; "
        "common in VMProtect CFF mode and bespoke obfuscators"
    )

    # Operand strings that disqualify a register operand. Anything that
    # could parse as a memory reference, immediate, or call target lives
    # here so the heuristic does not double-count compiler patterns.
    _NON_REGISTER_PREFIXES = ("0x", "0X", "[", "+", "-")

    def detect(self, block: BlockInfo, cfg_blocks: dict[int, BlockInfo]) -> float:
        """Confidence 0.6 for terminating ``JMP reg`` (no memory deref)."""
        instrs = list(getattr(block, "instructions", []) or [])
        if not instrs:
            return 0.0
        last = instrs[-1]
        if _mnem(last) != "JMP":
            return 0.0
        operand = _first_arg(last).strip()
        if not operand:
            return 0.0
        if any(operand.startswith(prefix) for prefix in self._NON_REGISTER_PREFIXES):
            return 0.0
        if operand.isdigit():
            return 0.0
        # Anything else is, in practice, a register name (RAX, EAX, R12, ...)
        # because direct labels resolve to immediates in the disassembler
        # and would land in the `0x` branch above.
        return 0.6

    def extract_states(
        self,
        block: BlockInfo,
        cfg_blocks: dict[int, BlockInfo],
    ) -> dict[int, int]:
        """Cannot resolve targets statically -- return an empty mapping.

        The :mod:`cff_analysis` layer interprets an empty result for this
        pattern as a request to fall back to symbolic execution.
        """
        return {}


class PushRetDispatcher(DispatcherPattern):
    """Obfuscated jump implemented as ``PUSH target; RET``.

    Sometimes used as a CFF dispatcher (``push state_handler; ret``) but
    more often as an anti-disassembly trick that hides the control flow
    edge from naive linear sweep tools. The pattern cleanly resolves to a
    single target when the ``PUSH`` operand is a known immediate.
    """

    name = "push_ret"
    description = (
        "PUSH target; RET sequence used in place of a direct JMP; common "
        "in anti-disassembly stubs and a handful of packers"
    )

    def detect(self, block: BlockInfo, cfg_blocks: dict[int, BlockInfo]) -> float:
        """Confidence 0.85 when the block ends with ``PUSH; RET``."""
        instrs = list(getattr(block, "instructions", []) or [])
        if len(instrs) < 2:
            return 0.0
        last = instrs[-1]
        prev = instrs[-2]
        if _mnem(last) != "RET":
            return 0.0
        if _mnem(prev) != "PUSH":
            return 0.0
        return 0.85

    def extract_states(
        self,
        block: BlockInfo,
        cfg_blocks: dict[int, BlockInfo],
    ) -> dict[int, int]:
        """Resolve the ``PUSH`` immediate as the dispatch target.

        Since a ``PUSH/RET`` shim has only a single statically-known
        successor, the recovered map keys it under state ``0`` so the
        downstream analysis treats the block as an unconditional edge.
        ``PUSH reg`` cannot be resolved statically and yields ``{}``.
        """
        instrs = list(getattr(block, "instructions", []) or [])
        if len(instrs) < 2:
            return {}
        last = instrs[-1]
        prev = instrs[-2]
        if _mnem(last) != "RET" or _mnem(prev) != "PUSH":
            return {}
        target = _largest_immediate(prev)
        if target is None:
            return {}
        return {0: target}



# Registry of all dispatcher pattern instances for use by load_dispatchers().
ALL_DISPATCHERS = (
    SubJzChainDispatcher(),
    CmpJeTableDispatcher(),
    SwitchJumpTableDispatcher(),
    IndirectComputedDispatcher(),
    PushRetDispatcher(),
)
