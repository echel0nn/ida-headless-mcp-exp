# IDA 9.0 idalib Probe Results

Date: 2026-05-01

Probe script: `scripts/probe_idalib.py`

Target binary used for validation:
- local sample PE64 test binary (not committed to the repository)
---

## Verdict

**idalib works on this machine with the installed IDA 9.0.**

The critical path succeeded:
1. Locate IDA 9.0 installation
2. Install the local `ida` Python package from `idalib/python`
3. Activate the package so it can locate the local IDA installation
4. Import `ida` in a clean Python process
5. Open a real PE64 test binary
6. Wait for autoanalysis
7. Initialize Hex-Rays
8. Decompile the first function
9. Close the database cleanly

This is sufficient evidence to proceed with an **idalib-first** implementation.

---

## What Was Verified

### Installation layout

Detected and verified:
- `C:\Program Files\IDA Professional 9.0\ida64.exe`
- `C:\Program Files\IDA Professional 9.0\idat64.exe`
- `C:\Program Files\IDA Professional 9.0\idalib64.dll`
- `C:\Program Files\IDA Professional 9.0\idalib\python\setup.py`
- `C:\Program Files\IDA Professional 9.0\idalib\python\py-activate-idalib.py`

### Python package bootstrap

Important discovery:
- The globally installed `idapro` package in the machine Python environment is **not** the right package for this IDA 9.0 install. It expects `idalib.dll`, while this install ships `idalib64.dll`.
- The **correct package** is IDA's own local `ida` package under `idalib/python`.

The probe therefore:
1. creates a disposable venv (`.probe-venv`)
2. installs the local `idalib/python` package from the configured IDA install
3. activates it against the local IDA install

### Activation behavior on Windows

Important discovery:
- `py-activate-idalib.py` did **not** create the `ida/bin` symlink on this Windows machine.
- The probe had to create a **directory junction** fallback using:
  - `cmd /c mklink /J <site-packages\ida\bin> <IDADIR>`

This means our production bootstrap code should not assume the Python activation script succeeds on Windows. We need:
- try activation script first
- if `ida/bin` link missing, create junction fallback automatically

### Runtime result

Successful runtime facts from the probe:

```json
{
  "kernel_version": "9.0",
  "open_database_rc": 0,
  "root_filename": "sample-test-binary.exe",
  "function_count": 1215,
  "segment_count": 11,
  "entry_qty": 4,
  "hexrays_ready": true,
  "decompile_ok": true,
  "decompile_line_count": 48
}
```

This proves:
- the library initialized
- a real binary opened successfully
- IDA autoanalysis completed
- Hex-Rays is licensed and available in headless mode
- decompilation returns usable pseudocode

---

## Observed Warnings / Edge Cases

### 1. `CodeCoverage64.dll` load errors

IDA printed repeated warnings:

```
LoadLibrary(...\plugins\CodeCoverage64.dll) error: The specified module could not be found.
```

This did **not** prevent analysis or decompilation.

Interpretation:
- a plugin reference exists in the user's IDA installation
- the plugin file or one of its dependencies is missing
- idalib continues successfully

Action:
- treat plugin load errors as non-fatal
- our MCP should log them but not fail startup
- long term: add a plugin diagnostics command if useful, but this is not a blocker

### 2. PDB symbol lookup prompt text appeared in console

During binary load, IDA attempted PDB lookup and emitted:

```
Do you want to browse for the pdb file on disk? -> ~Y~es
```

But the headless load still completed and analysis continued.

Interpretation:
- idalib/headless may still emit interactive-oriented loader text to stdout
- for some binaries, symbol loading may create noise in logs

Action:
- capture and persist loader stdout/stderr in session logs
- do not parse stdout for protocol data
- consider passing loader arguments later to suppress symbol prompts if needed

### 3. SDK version symbol was not populated

`ida_idaapi.IDA_SDK_VERSION` returned `null` in the probe payload.

Action:
- use `ida_kernwin.get_kernel_version()` as the authoritative runtime version check for now
- if we need a build number later, derive it from file metadata or another IDA API

---

## Architectural Consequence

The planned backend decision is now updated from:
- "try idalib first, bridge if needed"

to:
- **idalib is confirmed viable on the target workstation**
- bridge worker path becomes fallback only if we later hit a hard limitation (multi-process licensing, thread affinity, or API gaps)

That means v0.1 implementation should proceed with:
1. `idalib` bootstrap helper
2. main-thread execution discipline
3. one process = one MCP server = many open binaries in-memory
4. no TCP bridge in the first cut

---

## Immediate Next Steps

### Step 2 from V1 scope is now unblocked

Proceed to:
- build the minimal process/session layer
- model an opened binary session around `ida.open_database(...)` / `ida.close_database(...)`
- keep one live binary at a time first, then expand to multi-binary state in the MCP server

Recommended first files to implement:
- `src/ida_headless_mcp/config.py`
- `src/ida_headless_mcp/bootstrap.py`
- `src/ida_headless_mcp/session.py`
- `src/ida_headless_mcp/server.py`

### First commands to implement

In order:
1. `open_binary(path, options)`
2. `close_binary(binary_id, save=False)`
3. `list_binaries()`
4. `binary_metadata(binary_id)`
5. `list_functions(binary_id, offset, limit)`
6. `decompile(binary_id, address_or_name)`

### Bootstrap requirement

The server should own the full bootstrap flow internally:
- detect local `ida` package or install it into a managed venv
- run activation
- if activation doesn't create `ida/bin`, create junction fallback on Windows
- import `ida` as the first IDA import

Do not assume a user has preconfigured `IDADIR` or manually installed anything.

---

## Recommendation

**Proceed with idalib-first implementation now.**

We have enough evidence. No more discovery is required before coding the first server/session layer.
