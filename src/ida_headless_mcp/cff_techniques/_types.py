"""Base classes and result types for the CFF technique database.

This module is the foundation of ``cff_techniques``: it declares the abstract
pattern interfaces (dispatchers, opaque predicates, state-variable detectors)
and the dataclasses used to return analysis results to callers.

Conventions:
    - Address-typed fields are stored as ``int`` internally.
    - ``to_dict()`` on every dataclass returns a JSON-serializable mapping
      where addresses are formatted as ``0x``-prefixed lowercase hex strings.
    - The architecture (x86_32 vs x86_64) is encoded by the producer of
      ``BlockInfo``; the dataclass itself is arch-agnostic.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "BlockInfo",
    "CffDetectionResult",
    "CffSignature",
    "DeflattedFunction",
    "DeflattedState",
    "DispatcherPattern",
    "OpaquePredicatePattern",
    "StateVarInfo",
    "StateVariableDetector",
]


def _hex(value: int | None) -> str | None:
    """Format an integer as a ``0x``-prefixed lowercase hex string.

    Args:
        value: Integer value or ``None``.

    Returns:
        ``"0x<hex>"`` for an int, ``None`` when ``value`` is ``None``.
    """
    if value is None:
        return None
    return f"0x{value:x}"


def _hex_list(values: list[int]) -> list[str]:
    """Format a list of integers as ``0x``-prefixed lowercase hex strings."""
    return [f"0x{v:x}" for v in values]


def _serialize_instruction(inst: dict[str, Any]) -> dict[str, Any]:
    """Render one instruction record as a JSON-safe dict.

    ``offset`` is hex-formatted; ``args_raw`` (typically a list of miasm
    expression objects that aren't JSON-serializable) is stringified.
    Other keys are passed through untouched.
    """
    out: dict[str, Any] = dict(inst)
    offset = out.get("offset")
    if isinstance(offset, int):
        out["offset"] = f"0x{offset:x}"
    args_raw = out.get("args_raw")
    if args_raw is not None:
        out["args_raw"] = [str(a) for a in args_raw]
    return out


@dataclass
class BlockInfo:
    """Analyzed basic block with extracted features.

    Attributes:
        address: VA of the first instruction in the block.
        instructions: Per-instruction records of the form
            ``{"offset": int, "mnemonic": str, "operands_str": str,
            "args_raw": list[Any]}``. ``args_raw`` carries miasm operand
            objects which are stringified by ``to_dict``.
        successors: VAs of CFG successor blocks.
        predecessors: VAs of CFG predecessor blocks.
        in_degree: Number of CFG predecessors.
        out_degree: Number of CFG successors.
        has_call: Block contains at least one CALL instruction.
        call_targets: Resolved direct CALL targets, plus IAT-slot VAs
            for indirect imports resolved via ``call_names``; ``0`` for
            unresolved indirect calls.
        call_names: ``DLL!Function`` labels for indirect ``CALL [RIP+N]``
            instructions resolved through the PE import table.
        has_imul: Block contains an IMUL instruction.
        has_div: Block contains a DIV/IDIV instruction.
        has_cmp: Block contains a CMP/SUB used for comparison.
        cmp_values: Immediate operands seen in CMP/SUB instructions.
        state_writes: Immediate values written to the state-variable slot.
        lea_rip_offsets: Resolved targets of RIP-relative LEAs.
        stack_byte_writes: Count of ``MOV BYTE PTR [RSP+N], imm8`` writes.
        is_ret: Block ends in a RET instruction.
        instruction_count: Total instructions in the block.
    """

    address: int
    instructions: list[dict[str, Any]] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)
    in_degree: int = 0
    out_degree: int = 0
    has_call: bool = False
    call_targets: list[int] = field(default_factory=list)
    call_names: list[str] = field(default_factory=list)
    has_imul: bool = False
    has_div: bool = False
    has_cmp: bool = False
    cmp_values: list[int] = field(default_factory=list)
    state_writes: list[int] = field(default_factory=list)
    lea_rip_offsets: list[int] = field(default_factory=list)
    stack_byte_writes: int = 0
    is_ret: bool = False
    instruction_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable view with hex-formatted addresses."""
        return {
            "address": _hex(self.address),
            "instructions": [_serialize_instruction(i) for i in self.instructions],
            "successors": _hex_list(self.successors),
            "predecessors": _hex_list(self.predecessors),
            "in_degree": self.in_degree,
            "out_degree": self.out_degree,
            "has_call": self.has_call,
            "call_targets": _hex_list(self.call_targets),
            "call_names": list(self.call_names),
            "has_imul": self.has_imul,
            "has_div": self.has_div,
            "has_cmp": self.has_cmp,
            "cmp_values": _hex_list(self.cmp_values),
            "state_writes": _hex_list(self.state_writes),
            "lea_rip_offsets": _hex_list(self.lea_rip_offsets),
            "stack_byte_writes": self.stack_byte_writes,
            "is_ret": self.is_ret,
            "instruction_count": self.instruction_count,
        }


class DispatcherPattern(ABC):
    """Abstract pattern that recognises a CFF dispatcher block.

    Subclasses set ``name`` and ``description`` as class attributes and
    implement ``detect`` and ``extract_states``.
    """

    name: str = ""
    description: str = ""

    @abstractmethod
    def detect(self, block: BlockInfo, cfg_blocks: list[BlockInfo]) -> float:
        """Score how strongly ``block`` matches this dispatcher pattern.

        Args:
            block: Candidate block under inspection.
            cfg_blocks: All blocks in the function's CFG.

        Returns:
            Confidence in ``[0.0, 1.0]``. ``0.0`` means no match.
        """

    @abstractmethod
    def extract_states(
        self,
        block: BlockInfo,
        cfg_blocks: list[BlockInfo],
    ) -> dict[int, int]:
        """Recover the state-value to handler-address mapping.

        Args:
            block: A block previously matched by ``detect``.
            cfg_blocks: All blocks in the function's CFG.

        Returns:
            Mapping ``state_value -> handler_va``. Empty when no states
            could be recovered.
        """


class OpaquePredicatePattern(ABC):
    """Abstract pattern that recognises an opaque predicate in a block.

    Subclasses set ``always_true`` to indicate whether the predicate
    condition always evaluates to equality/zero (ZF=1) or always to
    non-zero (ZF=0). ``resolve_cmov`` uses this to determine which
    CMOVZ/CMOVNZ path is taken without re-proving the predicate.
    """

    name: str = ""
    description: str = ""
    always_true: bool = True  # ZF=1 (condition equals / is zero)

    @abstractmethod
    def detect(self, block: BlockInfo) -> float:
        """Return confidence in ``[0.0, 1.0]`` that the block is opaque."""

    @abstractmethod
    def extract_constants(self, block: BlockInfo) -> dict[str, Any]:
        """Return pattern-specific constants (e.g. LCG multiplier)."""

    @classmethod
    def resolve_cmov(cls, mnemonic: str) -> str:
        """Return ``'src'`` if CMOV fires (ZF matches always_true), else ``'dst'``."""
        fires = (mnemonic in ('CMOVZ', 'CMOVE')) == cls.always_true
        return 'src' if fires else 'dst'

@dataclass
class StateVarInfo:
    """Detected state-variable storage location.

    Attributes:
        location_type: One of ``'stack'``, ``'global'``, ``'register'``.
        operand_pattern: Human-readable operand string,
            e.g. ``"DWORD PTR [RSP + 0x24]"``.
        offset: Stack offset for ``'stack'``, absolute VA for ``'global'``,
            ``None`` for ``'register'``.
        register: Register name for ``'register'``, ``None`` otherwise.
    """

    location_type: str
    operand_pattern: str = ""
    offset: int | None = None
    register: str | None = None
    confidence: float = 0.0
    detector_name: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable view with hex-formatted offset."""
        return {
            "location_type": self.location_type,
            "operand_pattern": self.operand_pattern,
            "offset": _hex(self.offset),
            "register": self.register,
            "confidence": self.confidence,
        }


class StateVariableDetector(ABC):
    """Abstract detector for the state-variable storage location."""

    name: str = ""

    @abstractmethod
    def detect(
        self,
        dispatcher: BlockInfo,
        cfg_blocks: list[BlockInfo],
    ) -> StateVarInfo | None:
        """Return state-variable info if recognised, otherwise ``None``."""


@dataclass
class CffSignature:
    """Known obfuscator fingerprint.

    Attributes:
        name: Signature name (e.g. ``"OLLVM-9.0-fla"``).
        family: Obfuscator family (e.g. ``"OLLVM"``).
        dispatcher_patterns: Names of expected dispatcher patterns.
        opaque_patterns: Names of expected opaque-predicate patterns.
        state_var_types: Expected state-variable location types.
        characteristics: Free-form additional fingerprint data.
    """

    name: str
    family: str
    dispatcher_patterns: list[str] = field(default_factory=list)
    opaque_patterns: list[str] = field(default_factory=list)
    state_var_types: list[str] = field(default_factory=list)
    characteristics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable view (no addresses to format)."""
        return {
            "name": self.name,
            "family": self.family,
            "dispatcher_patterns": list(self.dispatcher_patterns),
            "opaque_patterns": list(self.opaque_patterns),
            "state_var_types": list(self.state_var_types),
            "characteristics": dict(self.characteristics),
        }


@dataclass
class CffDetectionResult:
    """Outcome of CFF detection on a single function.

    Attributes:
        is_cff: True when the heuristics conclude the function is flattened.
        confidence: Aggregate confidence in ``[0.0, 1.0]``.
        dispatcher_address: VA of the dispatcher block, if any.
        dispatcher_in_degree: In-degree of the dispatcher in the CFG.
        dispatcher_pattern: Name of the matched dispatcher pattern.
        state_variable: Detected state-variable location, if any.
        opaque_predicates: Per-block opaque-predicate hits as JSON-safe dicts.
        matched_signature: Name of a matched ``CffSignature``, if any.
        block_count: Total CFG blocks analysed.
        state_count: Number of distinct dispatcher states recovered.
    """

    is_cff: bool
    confidence: float
    dispatcher_address: int | None
    dispatcher_in_degree: int
    dispatcher_pattern: str | None
    state_variable: StateVarInfo | None
    opaque_predicates: list[dict[str, Any]] = field(default_factory=list)
    matched_signature: str | None = None
    block_count: int = 0
    state_count: int = 0
    obfuscation_type: str = "none"  # CFF, BCF, CFF+BCF, none

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable view with hex-formatted addresses."""
        return {
            "is_cff": self.is_cff,
            "confidence": self.confidence,
            "dispatcher_address": _hex(self.dispatcher_address),
            "dispatcher_in_degree": self.dispatcher_in_degree,
            "dispatcher_pattern": self.dispatcher_pattern,
            "state_variable": (
                self.state_variable.to_dict() if self.state_variable is not None else None
            ),
            "opaque_predicates": [dict(p) for p in self.opaque_predicates],
            "matched_signature": self.matched_signature,
            "block_count": self.block_count,
            "state_count": self.state_count,
            "obfuscation_type": self.obfuscation_type,
        }


@dataclass
class DeflattedState:
    """One reconstructed state in a deflattened CFF function.

    Attributes:
        value: State-variable value that selects this handler.
        handler_address: VA of the handler block.
        block_type: One of ``'real'``, ``'trampoline'``, ``'opaque'``,
            ``'dispatcher'``.
        calls: Direct CALL targets observed in the handler.
        ops: Free-form short descriptions of the handler's effect.
        next_states: State values reachable from this handler.
    """

    value: int
    handler_address: int
    block_type: str
    calls: list[int] = field(default_factory=list)
    ops: list[str] = field(default_factory=list)
    next_states: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable view with hex-formatted addresses."""
        return {
            "value": _hex(self.value),
            "handler_address": _hex(self.handler_address),
            "block_type": self.block_type,
            "calls": _hex_list(self.calls),
            "ops": list(self.ops),
            "next_states": _hex_list(self.next_states),
        }


@dataclass
class DeflattedFunction:
    """Result of deflattening a single CFF-protected function.

    Attributes:
        name: Symbolic function name (or empty string).
        address: Entry VA of the function.
        block_count: Total CFG blocks.
        state_count: Distinct dispatcher states recovered.
        real_count: Handlers classified as real work.
        opaque_count: Handlers classified as opaque predicate.
        trampoline_count: Handlers classified as trampolines.
        dispatcher_count: Handlers classified as dispatchers.
        dispatcher_address: VA of the primary dispatcher block.
        dispatcher_in_degree: In-degree of the dispatcher.
        initial_state: Initial state value taken on entry, if known.
        prologue_calls: Direct CALL targets seen before the dispatcher.
        prologue_key_bytes: Count of stack key-byte writes in the prologue.
        states: All recovered states.
        flow: Recovered states ordered along the inferred execution path
            beginning at ``initial_state``.
        matched_signature: Name of a matched ``CffSignature``, if any.
    """

    name: str
    address: int
    block_count: int
    state_count: int
    real_count: int
    opaque_count: int
    trampoline_count: int
    dispatcher_count: int
    dispatcher_address: int
    dispatcher_in_degree: int
    initial_state: int | None
    prologue_calls: list[int] = field(default_factory=list)
    prologue_key_bytes: int = 0
    states: list[DeflattedState] = field(default_factory=list)
    flow: list[DeflattedState] = field(default_factory=list)
    matched_signature: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable view with hex-formatted addresses."""
        return {
            "name": self.name,
            "address": _hex(self.address),
            "block_count": self.block_count,
            "state_count": self.state_count,
            "real_count": self.real_count,
            "opaque_count": self.opaque_count,
            "trampoline_count": self.trampoline_count,
            "dispatcher_count": self.dispatcher_count,
            "dispatcher_address": _hex(self.dispatcher_address),
            "dispatcher_in_degree": self.dispatcher_in_degree,
            "initial_state": _hex(self.initial_state),
            "prologue_calls": _hex_list(self.prologue_calls),
            "prologue_key_bytes": self.prologue_key_bytes,
            "states": [s.to_dict() for s in self.states],
            "flow": [s.to_dict() for s in self.flow],
            "matched_signature": self.matched_signature,
        }



# Aliases for shorter names used by sibling modules.
OpaquePattern = OpaquePredicatePattern
StateVarDetector = StateVariableDetector

# Lightweight instruction info type used in type annotations.
InstructionInfo = dict  # Keys: offset, mnemonic, operands_str, args_raw
