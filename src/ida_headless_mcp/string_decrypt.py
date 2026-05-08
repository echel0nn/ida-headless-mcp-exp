"""Generic encrypted string recovery - cipher-agnostic, CFG-aware, CFF-tolerant."""
from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any

__all__ = ["decrypt_all_strings", "decrypt_binary_strings"]

_CIPHERS = [
    ("CAST-128", "Crypto.Cipher.CAST", [16, 12, 10, 8, 5], 8),
    ("AES-128-ECB", "Crypto.Cipher.AES", [16], 16),
    ("Blowfish-ECB", "Crypto.Cipher.Blowfish", [16], 8),
]

def _va_to_file(data: bytes, sections: list[tuple], va: int) -> int | None:
    for _, sva, srsz, sroff in sections:
        if sva <= va < sva + srsz:
            return sroff + (va - sva)
    return None

def _parse_pe_sections(data: bytes) -> tuple[int, list[tuple]]:
    """Return (image_base, [(name, va_abs, raw_size, raw_offset), ...])."""
    if len(data) < 0x40:
        return 0, []
    elf = struct.unpack_from("<I", data, 0x3C)[0]
    if data[elf:elf + 4] != b"PE\x00\x00":
        return 0, []
    coff = elf + 4
    ns = struct.unpack_from("<H", data, coff + 2)[0]
    opt_sz = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    ib = struct.unpack_from("<Q", data, opt + 24)[0] if magic == 0x20B else struct.unpack_from("<I", data, opt + 28)[0]
    sects = []
    so = opt + opt_sz
    for i in range(ns):
        s = so + i * 40
        nm = data[s:s + 8].rstrip(b"\x00").decode("ascii", "replace")
        va = ib + struct.unpack_from("<I", data, s + 12)[0]
        rsz = struct.unpack_from("<I", data, s + 16)[0]
        roff = struct.unpack_from("<I", data, s + 20)[0]
        sects.append((nm, va, rsz, roff))
    return ib, sects

def _find_calls_to(data: bytes, text_roff: int, text_rsz: int,
                   text_base: int, target_va: int) -> list[int]:
    """Find all E8 rel32 CALL instructions targeting target_va. Return call VAs."""
    tb = data[text_roff:text_roff + text_rsz]
    calls = []
    for i in range(len(tb) - 5):
        if tb[i] == 0xE8:
            rel = struct.unpack_from("<i", tb, i + 1)[0]
            if text_base + i + 5 + rel == target_va:
                calls.append(text_base + i)
    return calls

def _extract_prologue_keys(func_blocks: list, func_va: int,
                          tb: bytes, text_base: int) -> dict[int, int]:
    """Extract MOV BYTE to stack from prologue using instruction semantics."""
    import re as _re
    key_bytes: dict[int, int] = {}
    visited: set[int] = set()
    queue = [func_va]
    depth = 0
    addr_map = {b.address: b for b in func_blocks}
    while queue and depth < 4:
        next_q = []
        for addr in queue:
            if addr in visited or addr not in addr_map:
                continue
            visited.add(addr)
            blk = addr_map[addr]
            for insn in blk.instructions:
                mn = (insn.get('mnemonic', '') or '').upper()
                ops = insn.get('operands', '') or ''
                if mn == 'MOV' and 'BYTE' in ops.upper() and ('RSP' in ops or 'ESP' in ops):
                    off_m = _re.search(r'[RE]SP\s*\+\s*(?:0[xX])?([0-9a-fA-F]+)', ops)
                    val_m = _re.search(r',\s*(?:0[xX])?([0-9a-fA-F]+)\s*$', ops)
                    if off_m and val_m:
                        try:
                            stack_off = int(off_m.group(1), 16)
                            byte_val = int(val_m.group(1), 16) & 0xFF
                            key_bytes[stack_off] = byte_val
                        except ValueError:
                            pass
            next_q.extend(blk.successors)
        queue = next_q
        depth += 1
    return key_bytes

def _extract_ct_and_key_offset(call_va: int, func_blocks: list,
                              addr_to_block: dict, tb: bytes,
                              text_base: int) -> tuple[int | None, int | None]:
    """Find ciphertext pointer and key offset using instruction semantics."""
    import re as _re
    call_block = None
    for b in func_blocks:
        for insn in b.instructions:
            if insn.get('offset') == call_va:
                call_block = b
                break
        if call_block:
            break
    if call_block is None:
        return None, None
    ct_va: int | None = None
    key_offset: int | None = None
    visited: set[int] = set()
    queue = [call_block.address]
    depth = 0
    while queue and depth < 8:
        next_q = []
        for addr in queue:
            if addr in visited or addr not in addr_to_block:
                continue
            visited.add(addr)
            blk = addr_to_block[addr]
            for insn in blk.instructions:
                mn = (insn.get('mnemonic', '') or '').upper()
                ops = insn.get('operands', '') or ''
                off = insn.get('offset', 0)
                isz = insn.get('size', 0)
                if mn == 'LEA' and 'RIP' in ops and ct_va is None:
                    disp_m = _re.search(r'RIP\s*[+\-]\s*(?:0[xX])?([0-9a-fA-F]+)', ops)
                    sign_m = _re.search(r'RIP\s*([+\-])', ops)
                    if disp_m:
                        disp = int(disp_m.group(1), 16)
                        if sign_m and sign_m.group(1) == '-':
                            disp = -disp
                        ct_va = off + isz + disp
                if mn == 'LEA' and key_offset is None and 'RIP' not in ops:
                    stk_m = _re.search(r'[RE]SP\s*\+\s*(?:0[xX])?([0-9a-fA-F]+)', ops)
                    if stk_m:
                        try:
                            key_offset = int(stk_m.group(1), 16)
                        except ValueError:
                            pass
            next_q.extend(blk.predecessors)
        queue = next_q
        depth += 1
    return ct_va, key_offset

def _extract_key_and_ct(data: bytes, sections: list, tb: bytes,
                        text_base: int, call_va: int,
                        window: int = 4096) -> tuple[dict[int, int], int | None]:
    """Fallback: raw byte scan with split windows for key + ciphertext."""
    off = call_va - text_base
    ct_start = max(0, off - 200)
    ct_chunk = tb[ct_start:off]
    ct_va_raw: int | None = None
    for j in range(len(ct_chunk)-7, -1, -1):
        if ct_chunk[j:j+3] == b'\x4C\x8D\x05':
            disp = struct.unpack_from('<i', ct_chunk, j+3)[0]
            ct_va_raw = text_base + ct_start + j + 7 + disp
            break
    key_start = max(0, off - min(window, 16384))
    key_chunk = tb[key_start:off]
    key_bytes_raw: dict[int, int] = {}
    for j in range(len(key_chunk) - 5):
        if key_chunk[j] == 0xC6 and key_chunk[j+1] == 0x44 and key_chunk[j+2] == 0x24:
            key_bytes_raw[key_chunk[j+3]] = key_chunk[j+4]
        elif (j+7 < len(key_chunk) and key_chunk[j] == 0xC6
              and key_chunk[j+1] == 0x84 and key_chunk[j+2] == 0x24):
            koff = struct.unpack_from('<I', key_chunk, j+3)[0]
            if koff < 0x1000:
                key_bytes_raw[koff] = key_chunk[j+7]
    return key_bytes_raw, ct_va_raw

def _build_key(key_bytes: dict[int, int], key_size: int) -> bytes | None:
    """Build a contiguous key of key_size from scattered stack writes."""
    if len(key_bytes) < key_size:
        return None
    sorted_offs = sorted(key_bytes.keys())
    for si in range(len(sorted_offs)):
        base = sorted_offs[si]
        key = []
        for k in range(key_size):
            if base + k in key_bytes:
                key.append(key_bytes[base + k])
            else:
                break
        if len(key) == key_size:
            return bytes(key)
    return None

def _try_decrypt(ct_data: bytes, key: bytes, cipher_name: str,
                 mod_path: str, block_size: int) -> str | None:
    """Attempt ECB decryption. Return printable string or None."""
    import importlib
    try:
        mod = importlib.import_module(mod_path)
    except ImportError:
        return None
    try:
        cipher = mod.new(key, mod.MODE_ECB)
    except (ValueError, KeyError):
        return None

    pt = b""
    max_blocks = min(64, len(ct_data) // block_size)
    for i in range(max_blocks):
        blk = ct_data[i * block_size:(i + 1) * block_size]
        if len(blk) < block_size:
            break
        dec = cipher.decrypt(blk)
        pad = dec[-1]
        if 1 <= pad <= block_size and all(b == pad for b in dec[-pad:]):
            pt += dec[:-pad]
            break
        if b"\x00" in dec:
            pt += dec[:dec.index(b"\x00")]
            break
        pt += dec

    if not pt:
        return None
    try:
        text = pt.decode("utf-8", "replace").rstrip("\x00")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t ")
    if len(text) >= 2 and printable > len(text) * 0.75:
        return text
    return None

def decrypt_all_strings(
    pe_path: Path,
    func_va: int,
    decryptor_va: int,
    window: int = 4096,
) -> dict[str, Any]:
    """Decrypt all strings in a function that calls a decryptor.

    Args:
        pe_path: Path to the PE binary.
        func_va: Entry VA of the function to analyze.
        decryptor_va: VA of the string decryption function.
        window: Backward scan window in bytes for key extraction.

    Returns:
        Dict with decrypted strings, cipher used, and statistics.
    """
    data = pe_path.read_bytes()
    ib, sections = _parse_pe_sections(data)
    if not sections:
        return {"error": "Cannot parse PE"}

    text_sec = next((s for s in sections if s[0] == ".text"), None)
    if text_sec is None:
        text_sec = next((s for s in sections if s[3] > 0), next(iter(sections), None))
    if text_sec is None:
        return {"error": "No code section"}
    _, text_base, text_rsz, text_roff = text_sec
    tb = data[text_roff:text_roff + text_rsz]

    all_calls = _find_calls_to(data, text_roff, text_rsz, text_base, decryptor_va)

    func_blocks: list = []
    addr_to_block: dict = {}
    cfg_available = False
    try:
        from .cff_analysis import disassemble_function
        cfg = disassemble_function(pe_path, func_va)
        func_blocks = cfg.get('_blocks_obj', [])
        addr_to_block = cfg.get('_addr_to_block', {})
        cfg_available = bool(func_blocks)
    except (ImportError, ValueError, RuntimeError):
        pass

    func_calls = []
    if cfg_available:
        for cv in all_calls:
            for b in func_blocks:
                insn_end = b.address + sum(i.get('size', 0) for i in b.instructions)
                if b.address <= cv < insn_end:
                    func_calls.append(cv)
                    break
    else:
        func_calls = all_calls

    if not func_calls:
        return {'function': f'0x{func_va:x}', 'decryptor': f'0x{decryptor_va:x}',
                'call_sites': 0, 'decrypted': 0, 'strings': []}

    prologue_keys: dict[int, int] = {}
    if cfg_available:
        prologue_keys = _extract_prologue_keys(func_blocks, func_va, tb, text_base)

    results: list[dict[str, Any]] = []
    seen_ct: set[int] = set()
    cipher_used: str | None = None

    for call_va in func_calls:
        ct_va = None
        key_bytes: dict[int, int] = {}
        if cfg_available:
            ct_va, key_off = _extract_ct_and_key_offset(
                call_va, func_blocks, addr_to_block, tb, text_base)
            if key_off is not None and prologue_keys:
                key_bytes = {k: v for k, v in prologue_keys.items()
                             if key_off <= k < key_off + 32}
            else:
                key_bytes = dict(prologue_keys)
        if ct_va is None and cfg_available:
            try:
                from .deobfuscation.cff_resolver import resolve_opaque_block
                call_blk = None
                for b in func_blocks:
                    for insn in b.instructions:
                        if insn.get('offset') == call_va:
                            call_blk = b
                            break
                    if call_blk:
                        break
                if call_blk:
                    pred_insns = []
                    for pa in call_blk.predecessors:
                        pb = addr_to_block.get(pa)
                        if pb:
                            pred_insns.extend(pb.instructions)
                    all_insns = pred_insns + list(call_blk.instructions)
                    from .deobfuscation.emulator import ConcreteEvaluator
                    import re as _re
                    ev = ConcreteEvaluator()
                    for insn in all_insns:
                        mn = (insn.get('mnemonic', '') or '').upper()
                        ops = insn.get('operands', '') or ''
                        if mn == 'MOV' and ',' in ops:
                            dst, _, src = ops.partition(',')
                            dst_u = dst.strip().upper()
                            src_s = src.strip()
                            if '[' not in dst_u and '[' not in src_s:
                                imm_m = _re.findall(r'0[xX]([0-9a-fA-F]+)', src_s)
                                if imm_m:
                                    ev.set_register(dst_u, int(imm_m[0], 16))
                        if mn == 'LEA' and 'RIP' in ops and ',' in ops:
                            dst = ops.split(',')[0].strip().upper()
                            disp_m = _re.search(
                                r'RIP\s*[+\-]\s*(?:0[xX])?([0-9a-fA-F]+)', ops)
                            if disp_m:
                                disp = int(disp_m.group(1), 16)
                                off = insn.get('offset', 0)
                                isz = insn.get('size', 0)
                                ev.set_register(dst, off + isz + disp)
                    for reg in ('R8', 'RDX', 'RCX', 'R9'):
                        val = ev.symbols.get(reg)
                        if val and val > 0x10000:
                            ct_va = val
                            break
            except (ImportError, ValueError, RuntimeError, TypeError):
                pass
        if ct_va is None:  # fallback: linear scan regardless of CFG availability
            key_bytes, ct_va = _extract_key_and_ct(
                data, sections, tb, text_base, call_va, window)
        if ct_va is None or ct_va in seen_ct:
            continue
        seen_ct.add(ct_va)

        ct_foff = _va_to_file(data, sections, ct_va)
        if ct_foff is None or ct_foff >= len(data):
            continue
        ct_data = data[ct_foff:ct_foff + 512]

        decrypted = False
        for cname, cmod, key_sizes, bsz in _CIPHERS:
            for ksz in key_sizes:
                key = _build_key(key_bytes, ksz)
                if key is None:
                    continue
                text = _try_decrypt(ct_data, key, cname, cmod, bsz)
                if text is not None:
                    results.append({
                        "call_address": f"0x{call_va:x}",
                        "ciphertext_address": f"0x{ct_va:x}",
                        "cipher": cname,
                        "key_size": ksz,
                        "plaintext": text,
                    })
                    if cipher_used is None:
                        cipher_used = cname
                    decrypted = True
                    break
            if decrypted:
                break

    return {
        "function": f"0x{func_va:x}",
        "decryptor": f"0x{decryptor_va:x}",
        "cipher_detected": cipher_used,
        "call_sites": len(func_calls),
        "unique_ciphertexts": len(seen_ct),
        "decrypted": len(results),
        "strings": results,
    }

def decrypt_binary_strings(pe_path: Path, decryptor_va: int) -> dict[str, Any]:
    """Decrypt ALL encrypted strings across the entire binary."""
    data = pe_path.read_bytes()
    ib, sections = _parse_pe_sections(data)
    if not sections:
        return {"error": "Cannot parse PE"}
    text_sec = next((s for s in sections if s[0] == '.text'), None)
    if text_sec is None:
        text_sec = next((s for s in sections if s[3] > 0), None)
    if text_sec is None:
        return {'error': 'No executable section'}
    _, text_base, text_rsz, text_roff = text_sec
    tb = data[text_roff:text_roff + text_rsz]
    all_calls = _find_calls_to(data, text_roff, text_rsz, text_base, decryptor_va)
    if not all_calls:
        return {"decryptor": f"0x{decryptor_va:x}", "call_sites": 0,
                "decrypted": 0, "strings": []}
    func_starts: set[int] = set()
    for cv in all_calls:
        off = cv - text_base
        for back in range(0, min(off, 0x20000)):
            o = off - back
            if o < 2:
                break
            if (tb[o] == 0x48 and o + 2 < len(tb)
                    and tb[o + 1] in (0x83, 0x81) and tb[o + 2] == 0xEC):
                func_starts.add(text_base + o)
                break
    all_strings: dict[str, dict[str, Any]] = {}
    cipher_used: str | None = None
    for fva in sorted(func_starts):
        try:
            result = decrypt_all_strings(pe_path, fva, decryptor_va)
        except (ValueError, RuntimeError, KeyError, TypeError, OSError):
            continue
        for s in result.get("strings", []):
            ct = s.get("ciphertext_address", "")
            if ct and ct not in all_strings:
                all_strings[ct] = s
                if cipher_used is None:
                    cipher_used = s.get('cipher')
    processed_cts = set(all_strings.keys())
    for cv in all_calls:
        off = cv - text_base
        ct_start = max(0, off - 200)
        ct_chunk = tb[ct_start:off]
        ctv = None
        for j in range(len(ct_chunk)-7, -1, -1):
            if ct_chunk[j:j+3] == b'\x4C\x8D\x05':
                disp = struct.unpack_from('<i', ct_chunk, j+3)[0]
                ctv = text_base + ct_start + j + 7 + disp
                break
        if ctv is None:
            continue
        ct_hex = f'0x{ctv:x}'
        if ct_hex in processed_cts:
            continue
        kb: dict[int, int] = {}
        for back in range(0, min(off, 0x20000)):
            o = off - back
            if o < 2:
                break
            if tb[o] == 0x48 and o+2 < len(tb) and tb[o+1] in (0x83, 0x81) and tb[o+2] == 0xEC:
                fva = text_base + o
                try:
                    from .cff_analysis import disassemble_function
                    cfg2 = disassemble_function(pe_path, fva)
                    fb2 = cfg2.get('_blocks_obj', [])
                    if fb2:
                        kb = _extract_prologue_keys(fb2, fva, tb, text_base)
                except (ImportError, ValueError, RuntimeError):
                    pass
                break
        if not kb:
            kb2, _ = _extract_key_and_ct(data, sections, tb, text_base, cv, 4096)
            kb = kb2
        ct_foff = _va_to_file(data, sections, ctv)
        if ct_foff is None or ct_foff >= len(data):
            continue
        ct_data = data[ct_foff:ct_foff + 512]
        for cname, cmod, key_sizes, bsz in _CIPHERS:
            for ksz in key_sizes:
                key = _build_key(kb, ksz)
                if key is None:
                    continue
                text = _try_decrypt(ct_data, key, cname, cmod, bsz)
                if text is not None:
                    all_strings[ct_hex] = {
                        'call_address': f'0x{cv:x}', 'ciphertext_address': ct_hex,
                        'cipher': cname, 'key_size': ksz, 'plaintext': text,
                    }
                    if cipher_used is None:
                        cipher_used = cname
                    processed_cts.add(ct_hex)
                    break
    return {
        'decryptor': f'0x{decryptor_va:x}', 'cipher_detected': cipher_used,
        'functions_scanned': len(func_starts), 'call_sites': len(all_calls),
        'unique_strings': len(all_strings),
        'strings': sorted(all_strings.values(), key=lambda s: s.get('call_address', '')),
    }