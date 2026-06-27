"""CFF deflattening patcher -- generates byte patches to linearize control flow.

Takes the deflattened state machine and the raw disassembly, computes byte
patches that replace dispatcher-loop jumps with direct handler-to-handler
jumps. After patching, Hex-Rays can decompile the function.

Architecture: x86_64 only (JMP rel32 = E9, Jcc rel32 = 0F 8x).
"""
from __future__ import annotations

import struct
from typing import Any

__all__ = ["compute_patches"]


def _jmp_rel32(from_addr: int, to_addr: int) -> bytes:
    """Encode JMP rel32 (E9 xx xx xx xx). 5 bytes."""
    offset = to_addr - (from_addr + 5)
    return b"\xe9" + struct.pack("<i", offset)


def _jnz_rel32(from_addr: int, to_addr: int) -> bytes:
    """Encode JNZ rel32 (0F 85 xx xx xx xx). 6 bytes."""
    offset = to_addr - (from_addr + 6)
    return b"\x0f\x85" + struct.pack("<i", offset)


def _jz_rel32(from_addr: int, to_addr: int) -> bytes:
    """Encode JZ rel32 (0F 84 xx xx xx xx). 6 bytes."""
    offset = to_addr - (from_addr + 6)
    return b"\x0f\x84" + struct.pack("<i", offset)


def _nop(count: int) -> bytes:
    """Generate NOP sled of given length."""
    return b"\x90" * count


def _build_state_to_handler(blocks: list[dict]) -> dict[int, int]:
    """Build state_value -> handler_address mapping from the SUB/JZ dispatcher chain.

    The dispatcher chain is a sequence of blocks that do:
        MOV ECX, EAX
        SUB ECX, <state_constant>
        JZ <handler_address>

    The JZ target (second successor) is the handler for that state value.
    The fall-through (first successor) continues the chain.
    """
    mapping: dict[int, int] = {}
    for block in blocks:
        instrs = block.get("instructions", [])
        succs = block.get("successors", [])
        if len(succs) != 2 or len(instrs) < 2:
            continue
        # Look for SUB ECX, <const>; JZ pattern
        last = instrs[-1]
        prev = instrs[-2] if len(instrs) >= 2 else None
        if last.get("mnemonic") != "JZ":
            continue
        if prev is None:
            continue
        if prev.get("mnemonic") != "SUB":
            continue
        operands = prev.get("operands", "")
        if "ECX," not in operands:
            continue
        # Extract the state constant from SUB ECX, <hex>
        parts = operands.split(",")
        if len(parts) != 2:
            continue
        val_str = parts[1].strip()
        try:
            state_val = int(val_str, 16) if val_str.startswith("0x") else int(val_str)
        except ValueError:
            continue
        # JZ target is the handler address
        jz_target = int(succs[1], 16) if isinstance(succs[1], str) else succs[1]
        mapping[state_val] = jz_target
    return mapping


def _find_handler_tail(block: dict) -> dict[str, Any] | None:
    """Find the MOV [RSP+0x44], <state>; JMP dispatcher pattern at block end.

    Returns dict with:
        - jmp_addr: address of the JMP instruction
        - jmp_size: size of the JMP instruction (5 bytes for rel32)
        - mov_addr: address of the MOV instruction
        - mov_size: size of the MOV instruction
        - next_state: the state value written
        - is_conditional: False (unconditional)
    Or None if not found.
    """
    instrs = block.get("instructions", [])
    if len(instrs) < 2:
        return None
    last = instrs[-1]
    if last.get("mnemonic") != "JMP":
        return None
    # Find the preceding MOV DWORD PTR [RSP + 0x44], <imm>
    prev = instrs[-2]
    if prev.get("mnemonic") != "MOV":
        return None
    ops = prev.get("operands", "")
    if "DWORD PTR [RSP + 0x44]" not in ops:
        return None
    # Extract immediate value
    parts = ops.split(",")
    if len(parts) != 2:
        return None
    val_str = parts[1].strip()
    try:
        state_val = int(val_str, 16) if val_str.startswith("0x") else int(val_str)
    except ValueError:
        return None
    return {
        "jmp_addr": int(last["offset"], 16),
        "jmp_size": last["size"],
        "mov_addr": int(prev["offset"], 16),
        "mov_size": prev["size"],
        "next_state": state_val,
        "is_conditional": False,
    }


def _find_cmov_tail(block: dict) -> dict[str, Any] | None:
    """Find CMOV-based conditional state transition at block end.

    Pattern:
        MOV EAX, <state_A>
        MOV ECX, <state_B>
        CMP/TEST <condition>
        CMOVcc EAX, ECX
        MOV DWORD PTR [RSP + 0x44], EAX
        JMP dispatcher

    Returns dict with condition details and both state targets.
    """
    instrs = block.get("instructions", [])
    if len(instrs) < 6:
        return None
    last = instrs[-1]
    if last.get("mnemonic") != "JMP":
        return None
    mov_state = instrs[-2]
    if mov_state.get("mnemonic") != "MOV":
        return None
    if "DWORD PTR [RSP + 0x44]" not in mov_state.get("operands", ""):
        return None
    cmov = instrs[-3]
    mnemonic = cmov.get("mnemonic", "")
    if not mnemonic.startswith("CMOV"):
        return None
    # Find the CMP/TEST before CMOV
    cmp_instr = None
    for i in range(len(instrs) - 4, max(len(instrs) - 8, -1), -1):
        if i < 0:
            break
        m = instrs[i].get("mnemonic", "")
        if m in ("CMP", "TEST"):
            cmp_instr = instrs[i]
            break
    if cmp_instr is None:
        return None
    # Find MOV EAX, <state_A> and MOV ECX, <state_B>
    state_a = None
    state_b = None
    for i in range(len(instrs) - 4, max(len(instrs) - 10, -1), -1):
        if i < 0:
            break
        instr = instrs[i]
        if instr.get("mnemonic") != "MOV":
            continue
        ops = instr.get("operands", "")
        if ops.startswith("EAX,") and state_a is None:
            try:
                state_a = int(ops.split(",")[1].strip(), 16)
            except ValueError:
                pass
        elif ops.startswith("ECX,") and state_b is None:
            try:
                state_b = int(ops.split(",")[1].strip(), 16)
            except ValueError:
                pass
    if state_a is None or state_b is None:
        return None
    # Determine which state goes where based on CMOV condition
    # CMOVNZ: if NZ → EAX=ECX (state_b), else EAX stays (state_a)
    # CMOVZ:  if Z  → EAX=ECX (state_b), else EAX stays (state_a)
    is_nz = "NZ" in mnemonic or "NE" in mnemonic
    # state_a = default (condition NOT met), state_b = condition met
    return {
        "jmp_addr": int(last["offset"], 16),
        "jmp_size": last["size"],
        "patch_start": int(cmp_instr["offset"], 16),
        "patch_end": int(last["offset"], 16) + last["size"],
        "cmp_addr": int(cmp_instr["offset"], 16),
        "cmp_size": cmp_instr["size"],
        "cmp_operands": cmp_instr.get("operands", ""),
        "cmp_mnemonic": cmp_instr.get("mnemonic", ""),
        "state_default": state_a,
        "state_taken": state_b,
        "is_nz": is_nz,
        "is_conditional": True,
    }


def compute_patches(
    blocks: list[dict],
    deflat_states: list[dict],
    dispatcher_addr: int,
) -> list[dict[str, Any]]:
    """Compute all byte patches needed to deobfuscate a CFF function.

    Args:
        blocks: Block list from disassemble_function().
        deflat_states: State list from deflat_function().
        dispatcher_addr: Address of the dispatcher block.

    Returns:
        List of {address: hex_str, hex_bytes: hex_str, description: str} patches.
    """
    state_to_handler = _build_state_to_handler(blocks)
    block_map = {int(b["address"], 16) if isinstance(b["address"], str)
                 else b["address"]: b for b in blocks}
    patches: list[dict[str, Any]] = []

    # For each handler block that jumps back to dispatcher, redirect
    for block in blocks:
        addr = int(block["address"], 16) if isinstance(block["address"], str) else block["address"]
        succs = block.get("successors", [])
        if not succs:
            continue
        succ_addrs = [int(s, 16) if isinstance(s, str) else s for s in succs]
        # Only patch blocks that jump to the dispatcher
        if dispatcher_addr not in succ_addrs:
            continue

        # Try unconditional tail first
        tail = _find_handler_tail(block)
        if tail and not tail["is_conditional"]:
            next_state = tail["next_state"]
            target = state_to_handler.get(next_state)
            if target is None:
                continue
            # Patch: NOP the MOV + replace JMP target
            mov_addr = tail["mov_addr"]
            jmp_addr = tail["jmp_addr"]
            total_size = (jmp_addr + tail["jmp_size"]) - mov_addr
            # Build: NOP padding + JMP <target>
            jmp_bytes = _jmp_rel32(jmp_addr, target)
            nop_bytes = _nop(jmp_addr - mov_addr)
            patch_bytes = nop_bytes + jmp_bytes
            assert len(patch_bytes) == total_size, f"Patch size mismatch: {len(patch_bytes)} != {total_size}"
            patches.append({
                "address": f"0x{mov_addr:x}",
                "hex_bytes": patch_bytes.hex(),
                "description": f"Handler 0x{addr:x}: unconditional state 0x{next_state:x} -> direct JMP 0x{target:x}",
            })
            continue

        # Try CMOV conditional tail
        cmov = _find_cmov_tail(block)
        if cmov and cmov["is_conditional"]:
            target_default = state_to_handler.get(cmov["state_default"])
            target_taken = state_to_handler.get(cmov["state_taken"])
            if target_default is None or target_taken is None:
                continue
            # If both targets are the same (opaque predicate), use unconditional JMP
            if target_default == target_taken:
                # Patch from CMP to end: NOP + JMP <target>
                patch_start = cmov["patch_start"]
                patch_end = cmov["patch_end"]
                total_size = patch_end - patch_start
                jmp_from = patch_end - 5  # place JMP at end
                jmp_bytes = _jmp_rel32(jmp_from, target_default)
                nop_count = total_size - 5
                patch_bytes = _nop(nop_count) + jmp_bytes
                patches.append({
                    "address": f"0x{patch_start:x}",
                    "hex_bytes": patch_bytes.hex(),
                    "description": f"Opaque 0x{addr:x}: both targets -> 0x{target_default:x}",
                })
                continue
            # Real conditional: CMP + Jcc <taken> + JMP <default>
            cmp_addr = cmov["cmp_addr"]
            cmp_size = cmov["cmp_size"]
            patch_start = cmp_addr + cmp_size  # after the CMP
            patch_end = cmov["patch_end"]
            total_size = patch_end - patch_start
            if cmov["is_nz"]:
                # CMOVNZ: taken on NZ → JNZ <target_taken>; JMP <target_default>
                jnz_bytes = _jnz_rel32(patch_start, target_taken)
                jmp_from = patch_start + 6
                jmp_bytes = _jmp_rel32(jmp_from, target_default)
                remaining = total_size - 6 - 5
                patch_bytes = jnz_bytes + jmp_bytes + _nop(max(0, remaining))
            else:
                # CMOVZ: taken on Z → JZ <target_taken>; JMP <target_default>
                jz_bytes = _jz_rel32(patch_start, target_taken)
                jmp_from = patch_start + 6
                jmp_bytes = _jmp_rel32(jmp_from, target_default)
                remaining = total_size - 6 - 5
                patch_bytes = jz_bytes + jmp_bytes + _nop(max(0, remaining))
            if len(patch_bytes) != total_size:
                continue  # skip if sizes don't match
            patches.append({
                "address": f"0x{patch_start:x}",
                "hex_bytes": patch_bytes.hex(),
                "description": f"CMOV 0x{addr:x}: {'JNZ' if cmov['is_nz'] else 'JZ'} 0x{target_taken:x} / JMP 0x{target_default:x}",
            })

    # NOP the dispatcher back-edge to break the loop
    disp_block = block_map.get(dispatcher_addr)
    if disp_block:
        instrs = disp_block.get("instructions", [])
        if instrs and instrs[0].get("mnemonic") == "JMP":
            size = instrs[0]["size"]
            patches.append({
                "address": f"0x{dispatcher_addr:x}",
                "hex_bytes": _nop(size).hex(),
                "description": f"NOP dispatcher back-edge at 0x{dispatcher_addr:x}",
            })

    return patches
