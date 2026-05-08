"""Hex-Rays microcode optimizer for CFF deflattening.

Works inside the idalib worker process. Installs an optblock_t handler
that intercepts Hex-Rays' optimization pipeline and simplifies the CFF
dispatcher loop at the microcode level.

Strategy:
1. On first block callback, scan the entire MBA to find the dispatcher
   (block with abnormally high predecessor count)
2. Walk the dispatcher's comparison chain to build state_value -> handler_block
3. For each handler block that writes state_var + jumps to dispatcher,
   rewrite the jump to go directly to the next handler
4. Hex-Rays' dead code elimination handles the rest
"""
from __future__ import annotations

import ida_hexrays
import ida_funcs

__all__ = ["decompile_cff"]

# Microcode opcodes we care about
_M_GOTO = ida_hexrays.m_goto
_M_JZ = ida_hexrays.m_jz
_M_JNZ = ida_hexrays.m_jnz
_M_MOV = ida_hexrays.m_mov
_M_SUB = ida_hexrays.m_sub
_M_STX = ida_hexrays.m_stx
_M_NOP = ida_hexrays.m_nop

# Operand types
_MOP_N = ida_hexrays.mop_n   # number
_MOP_B = ida_hexrays.mop_b   # block reference
_MOP_S = ida_hexrays.mop_S   # stack variable
_MOP_R = ida_hexrays.mop_r   # register

# Minimum predecessor count to consider a block as dispatcher
_DISPATCHER_THRESHOLD = 8


class _CffOptimizer(ida_hexrays.optblock_t):
    """Microcode block optimizer that deflattens CFF in-place."""

    def __init__(self):
        super().__init__()
        self._analyzed: set[int] = set()
        self._mappings: dict[int, dict] = {}  # func_ea -> analysis result

    def func(self, blk):
        """Called by Hex-Rays for each microcode block during optimization."""
        mba = blk.mba
        if mba is None:
            return 0
        func_ea = mba.entry_ea

        # Analyze once per function
        if func_ea not in self._analyzed:
            self._analyzed.add(func_ea)
            result = self._analyze(mba)
            if result:
                self._mappings[func_ea] = result

        mapping = self._mappings.get(func_ea)
        if not mapping:
            return 0

        return self._rewrite_block(blk, mapping)

    def _analyze(self, mba) -> dict | None:
        """Scan MBA to find dispatcher and build state->handler mapping."""
        qty = mba.qty
        if qty < 10:
            return None

        # Find dispatcher: block with highest predecessor count
        best_serial = -1
        best_preds = 0
        for i in range(qty):
            blk = mba.get_mblock(i)
            np = blk.npred()
            if np > best_preds:
                best_preds = np
                best_serial = i

        if best_preds < _DISPATCHER_THRESHOLD:
            return None

        dispatcher = mba.get_mblock(best_serial)

        # Find the state variable: look at what the dispatcher reads
        # The dispatcher chain does: load state_var, sub CONST, jz handler
        # The state_var is the operand that's loaded at the dispatcher entry
        state_var = self._find_state_var(dispatcher, mba)
        if state_var is None:
            return None

        # Build state_value -> handler_serial from the comparison chain
        state_to_handler = self._extract_dispatch_table(
            mba, best_serial, state_var,
        )
        if len(state_to_handler) < 3:
            return None

        return {
            "dispatcher_serial": best_serial,
            "state_var": state_var,
            "state_to_handler": state_to_handler,
        }

    def _find_state_var(self, dispatcher, mba) -> dict | None:
        """Identify the state variable from the dispatcher block.

        Looks for a pattern like: mov REG, [stack_var]; sub REG, CONST; jz
        The stack_var is the state variable.
        """
        insn = dispatcher.head
        while insn is not None:
            # Look for: sub REG, CONST followed by jz
            if insn.opcode == _M_SUB:
                if insn.r.t == _MOP_N and insn.l.t == _MOP_R:
                    # This is sub REG, CONST — the REG holds the state var
                    # Trace backward to find where REG was loaded from
                    reg = insn.l.r
                    sv = self._trace_reg_source(dispatcher, mba, reg)
                    if sv is not None:
                        return sv
                    # Fallback: use the register itself as state var ID
                    return {"type": "reg", "reg": reg}
            insn = insn.next
        return None

    def _trace_reg_source(self, blk, mba, reg) -> dict | None:
        """Trace a register backward to find its stack source."""
        insn = blk.head
        while insn is not None:
            if insn.opcode == _M_MOV and insn.d.t == _MOP_R and insn.d.r == reg:
                if insn.l.t == _MOP_S:
                    off = insn.l.s.off
                    return {"type": "stack", "off": off}
            insn = insn.next
        # Check predecessor blocks
        for i in range(blk.npred()):
            pred = mba.get_mblock(blk.pred(i))
            p_insn = pred.tail
            while p_insn is not None:
                if p_insn.opcode == _M_MOV and p_insn.d.t == _MOP_R and p_insn.d.r == reg:
                    if p_insn.l.t == _MOP_S:
                        off = p_insn.l.s.off
                        return {"type": "stack", "off": off}
                p_insn = p_insn.prev
        return None

    def _extract_dispatch_table(
        self, mba, dispatcher_serial: int, state_var: dict,
    ) -> dict[int, int]:
        """Walk the dispatcher comparison chain to build state->handler mapping.

        The chain is a sequence of blocks:
            sub REG, CONST
            jz handler_block
            (fall through to next comparison)
        """
        mapping: dict[int, int] = {}  # state_value -> handler_block_serial
        visited: set[int] = set()
        queue = [dispatcher_serial]

        while queue:
            serial = queue.pop(0)
            if serial in visited:
                continue
            visited.add(serial)
            blk = mba.get_mblock(serial)

            # Scan instructions for sub CONST; jz pattern
            insn = blk.head
            while insn is not None:
                if insn.opcode == _M_SUB and insn.r.t == _MOP_N:
                    state_val = insn.r.nnn.value
                    # Look for following jz
                    next_insn = insn.next
                    if next_insn and next_insn.opcode == _M_JZ:
                        if next_insn.d.t == _MOP_B:
                            handler = next_insn.d.b
                            mapping[state_val] = handler
                insn = insn.next

            # Follow fall-through successors (the comparison chain continues)
            for i in range(blk.nsucc()):
                s = blk.succ(i)
                if s not in visited and s not in mapping.values():
                    queue.append(s)

        return mapping

    def _rewrite_block(self, blk, mapping: dict) -> int:
        """Rewrite a handler block to jump directly to next handler.

        Pattern: mov [state_var], CONST; goto dispatcher
        Rewrite: goto handler_for_CONST; nop the mov
        """
        dispatcher_serial = mapping["dispatcher_serial"]
        state_to_handler = mapping["state_to_handler"]
        state_var = mapping["state_var"]

        # Check if block ends with goto dispatcher
        tail = blk.tail
        if tail is None or tail.opcode != _M_GOTO:
            return 0
        if tail.l.t != _MOP_B or tail.l.b != dispatcher_serial:
            return 0

        # Find the state variable write before the goto
        state_val = self._find_state_write(blk, state_var)
        if state_val is None:
            return 0

        target = state_to_handler.get(state_val)
        if target is None:
            return 0

        # Redirect: goto dispatcher -> goto handler
        tail.l.b = target
        return 1

    def _find_state_write(self, blk, state_var: dict) -> int | None:
        """Find the constant written to the state variable in this block."""
        insn = blk.tail
        while insn is not None:
            if insn.opcode == _M_MOV:
                # mov [stack_var], CONST
                if state_var["type"] == "stack":
                    if (insn.d.t == _MOP_S
                            and insn.d.s.off == state_var["off"]
                            and insn.l.t == _MOP_N):
                        return insn.l.nnn.value
                elif state_var["type"] == "reg":
                    if (insn.d.t == _MOP_R
                            and insn.d.r == state_var["reg"]
                            and insn.l.t == _MOP_N):
                        return insn.l.nnn.value
            elif insn.opcode == _M_STX:
                # stx CONST, [stack_var]  (store to memory)
                if state_var["type"] == "stack":
                    if insn.l.t == _MOP_N:
                        return insn.l.nnn.value
            insn = insn.prev
        return None


# Module-level singleton so it stays alive while installed
_optimizer: _CffOptimizer | None = None


def install() -> None:
    """Install the CFF microcode optimizer globally."""
    global _optimizer
    if _optimizer is not None:
        return
    _optimizer = _CffOptimizer()
    _optimizer.install()


def remove() -> None:
    """Remove the CFF microcode optimizer."""
    global _optimizer
    if _optimizer is None:
        return
    _optimizer.remove()
    _optimizer = None


def decompile_cff(ea: int, max_lines: int = 500) -> str | None:
    """Decompile a function with CFF optimization enabled.

    Installs the optimizer, runs Hex-Rays, removes the optimizer.
    Returns pseudocode string or None on failure.
    """
    install()
    try:
        func = ida_funcs.get_func(ea)
        if func is None:
            return None
        cfunc = ida_hexrays.decompile(func.start_ea)
        if cfunc is None:
            return None
        return str(cfunc)
    except (RuntimeError, OSError) as exc:
        return None
    finally:
        remove()
