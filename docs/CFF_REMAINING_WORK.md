# CFF Tools: Remaining Implementation Work

## Problem 1: Opaque Predicate Resolution (blocks flow tracing)

### Root Cause
CFF handlers don't write the next state as `MOV [state_var], imm`. Instead:
```
; In opaque predicate block (successor of handler):
MOV  ECX, 0x20CF7B27          ; candidate A
MOV  EDX, 0xDD40E928          ; candidate B
CMP  RAX, QWORD PTR [RSP+0x28]  ; opaque: always true (LCG)
CMOVZ ECX, EDX                ; ECX = B (always, since CMP is always-true)
MOV  DWORD PTR [RSP+0x24], ECX  ; next state = B = 0xDD40E928
```

The state write is `MOV [mem], reg` not `MOV [mem], imm`. The register value depends on the CMOVZ, which depends on the opaque predicate.

### Solution
Three-stage pipeline:

**Stage 1: Detect opaque blocks**
Already have the data. Blocks with IMUL+DIV+CMP+CMOVZ pattern, no CALL, exactly 1 successor (JMP back to dispatcher). These are at `0x14002BB5F` and `0x14002BB0B` in main().

In `_aggregate_handler`, when walking successor blocks, detect opaque blocks by pattern:
- Has IMUL and DIV
- No CALL (excluding within the opaque block itself)
- Ends with JMP to dispatcher
- Contains CMOVZ or CMOVNZ + `MOV [state_var], reg`

**Stage 2: Extract both CMOVZ candidates**
From the opaque block, extract:
- The two `MOV reg, imm` before the CMOVZ: these are the two candidate next-states
- The CMOVZ condition register

**Stage 3: Resolve which candidate is always-taken**
The opaque predicate is always-true (LCG proof). For CMOVZ (move if zero):
- If the CMP/predicate is always-true, ZF=1, so CMOVZ IS taken
- The CMOVZ destination gets the EDX value (second operand)
- For CMOVNZ, the logic is reversed

This means: from the opaque block, extract both candidate values, determine CMOVZ vs CMOVNZ, and pick the always-taken one.

### Implementation

Add to `cff_helpers.py`:

```python
def _resolve_opaque_state_write(block, addr_to_block, disp_chain):
    """For a handler's successor chain, find opaque predicate blocks
    and resolve the always-taken next-state value.
    
    Returns list of resolved state values from opaque CMOVZ patterns.
    """
```

This function:
1. Walks the handler's successor blocks (same as `_aggregate_handler`)
2. For blocks with IMUL+DIV pattern:
   - Find `MOV reg1, imm1; MOV reg2, imm2; CMP ...; CMOVZ/CMOVNZ reg1, reg2`
   - For CMOVZ: the always-taken value is `imm2` (because opaque is always-true, ZF=1)
   - For CMOVNZ: the always-taken value is `imm1` (because ZF=1, CMOVNZ not taken)
3. Return the resolved state values

Then in `_aggregate_handler`, after collecting `state_writes` from `MOV [mem], imm`, also call this resolver to get additional state values from opaque CMOVZ patterns. Merge both into `next_states`.

### Files Changed
- `cff_helpers.py`: add `_resolve_opaque_state_write()`
- `cff_helpers.py`: update `_aggregate_handler()` to call the resolver

### Expected Result
Main's flow chain: `0x2538EAC8` -> `0xDD40E928` -> `0xB1125FB4` -> `0x2A36A755` -> `0xCC4744C9` -> exit

---

## Problem 2: Indirect Call Resolution (IAT lookup)

### Root Cause
`CALL QWORD PTR [RIP + 0x906E9]` is an indirect call through the IAT. The target address `RIP + displacement` points to an 8-byte slot in `.rdata` that the PE loader fills with the actual function address at runtime. The raw bytes in the file are RVA values, not the final addresses.

### Solution
Parse the PE import table and build an `IAT_VA -> (dll_name, function_name)` mapping. For each `CALL [RIP+N]`, compute the IAT slot address and look up the import name.

### Implementation

Add to `cff_helpers.py` (or new file `pe_imports.py` if LOC is tight):

```python
def _build_iat_map(pe_path: Path) -> dict[int, tuple[str, str]]:
    """Parse PE import directory and return {iat_va: (dll, func)} map.
    
    Walks IMAGE_IMPORT_DESCRIPTOR chain, then each ILT entry.
    Handles both ordinal and name imports, PE32 and PE32+.
    """
```

Then in `_extract_block_info`, for each `CALL` instruction with `[RIP + N]` operand:
1. Compute `iat_va = instruction_address + instruction_size + displacement`
2. Look up in the IAT map
3. Store the resolved name in a new BlockInfo field or in call_targets as a negative sentinel + name

Better approach: add a `call_names: list[str]` field to `BlockInfo` parallel to `call_targets`. Each entry is either the resolved import name or empty string.

### Files Changed
- `cff_helpers.py` or new `pe_imports.py`: add `_build_iat_map()`
- `cff_helpers.py` `_extract_block_info()`: resolve RIP-relative calls via IAT map
- `cff_techniques/_types.py`: add `call_names: list[str]` to `BlockInfo`
- `cff_analysis.py` `disassemble_function()`: build IAT map once, pass to `_extract_block_info`

### Expected Result
```json
{
  "call_targets": ["0x0", "0x0"],
  "call_names": ["KERNEL32.dll!GetConsoleWindow", "USER32.dll!ShowWindow"]
}
```

---

## Problem 3: Opaque Predicate Detection for Signature Matching

### Root Cause
The opaque predicate detector runs on handler blocks, but IMUL/DIV instructions are in SUCCESSOR blocks of handlers (the opaque predicate evaluation happens AFTER the handler's real logic). The detector never sees them because it only checks the handler entry block.

### Solution
Two approaches:

**Approach A (simple):** Run opaque detection on ALL blocks in the function, not just handlers. Any block with IMUL+DIV+no_CALL+(1 successor to dispatcher) is an opaque predicate block regardless of whether it's a handler entry.

**Approach B (precise):** In `detect_cff`, after finding handler blocks, also scan their successors for the opaque pattern.

Approach A is simpler and correct. The `detect_cff` loop at line ~340 already iterates all blocks and checks for conditional branches. Change it to also check non-conditional blocks for the IMUL+DIV opaque pattern:

```python
for blk in blocks:
    if blk.address in disp_chain:
        continue
    # Check conditional blocks for MBA/quadratic/constant-fold
    if last_mnem in _COND_JMPS:
        match = _best_match(techniques["opaque_predicates"], blk)
    # Also check non-conditional blocks for LCG pattern (IMUL+DIV+CMOVZ)
    elif blk.has_imul and blk.has_div and not blk.has_call:
        match = _best_match(techniques["opaque_predicates"], blk)
```

### Files Changed
- `cff_analysis.py` `detect_cff()`: expand opaque detection to non-conditional blocks

### Expected Result
LCG predicates detected -> signature matches `lcg_stack_cff` -> confidence > 0.8

---

## Implementation Order

1. **Opaque state resolution** (Problem 1) -- unlocks flow tracing
2. **IAT resolution** (Problem 2) -- unlocks call name recovery
3. **Opaque detection expansion** (Problem 3) -- unlocks signature matching

Problems 1 and 2 are independent. Problem 3 depends on neither but its test depends on the opaque patterns working correctly.

## Estimated Scope

| Change | File | Delta LOC |
|--------|------|-----------|
| `_resolve_opaque_state_write()` | cff_helpers.py | +40 |
| Update `_aggregate_handler()` | cff_helpers.py | +5 |
| `_build_iat_map()` | pe_imports.py (new) | +80 |
| Update `_extract_block_info()` | cff_helpers.py | +15 |
| `call_names` field | _types.py | +5 |
| IAT map pass-through | cff_analysis.py | +10 |
| Expand opaque detection | cff_analysis.py | +10 |
| **Total** | | **~165** |
