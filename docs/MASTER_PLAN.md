# IDA Headless MCP — Master Plan

This is the source of truth for what this project is, what it is not, and how it differentiates.

---

## 1. Product Thesis

This project is **not** a generic IDA assistant.
It is **not** a wrapper around the IDA GUI.
It is **not** a plugin bundle.

It is:

> A headless binary-analysis substrate optimized for **autonomous vulnerability research workflows** first, and **malware analysis workflows** second.

The job of this MCP is to give LLM-driven systems and human researchers:
- structured binary facts
- structured decompiler IR access
- deterministic evidence for security claims
- batch analysis over whole binaries
- patch-diffing primitives for N-day research
- a shared substrate for future `vr` and `malware` modules in AILA

---

## 2. Who Uses It

### Primary user
**AILA VR module**
- N-day PoC writer
- later open-ended vulnerability research
- later exploit development support

### Secondary user
**Future AILA malware module**
- capability extraction
- anti-analysis detection
- string/config/resource extraction
- ATT&CK-aligned behavior understanding

### Tertiary user
**Human operator / reverse engineer**
- validate LLM claims
- annotate functions/types/comments
- run operator-only workflows

---

## 3. The Actual Capability Model

The project has three capability bands.

### A. Shared binary-analysis core
These capabilities must exist regardless of consumer module.

- open/close/list binaries
- binary metadata
- imports/exports/segments/strings
- list functions
- decompile
- xrefs / call graph / stack frame
- CTree query surface
- microcode export surface
- diffing
- provenance logging
- decompilation cache

### B. VR-first capabilities
These exist because autonomous vulnerability research needs them.

- batch structural filtering
- deterministic bug-class rules
- patch ranking
- assignment/value-flow tracing
- stronger exploitability evidence
- later coverage-aware research
- later angr-backed path feasibility

### C. Malware-ready capabilities
These are not v0.1 goals, but the architecture must allow them.

- capa integration
- FLOSS integration
- YARA / YARA-X
- anti-analysis detection
- resource / config extraction
- ATT&CK mapping
- behavioral clustering

---

## 4. What Makes This Project Different

Current IDA MCPs optimize for **interactive assistance**:
- decompile one function
- explain one function
- rename a symbol
- browse what the human is already looking at

This project optimizes for **autonomous research loops**:
- "show me all candidate parsers reachable from untrusted input"
- "diff vulnerable vs patched binary and rank likely security fixes"
- "find dangerous sinks with evidence, not guesses"
- "give me the structured call node, not a pretty string"
- "prove this size value comes from attacker input"

The differentiators are:

1. **filter-first, decompile-second**
2. **whole-binary batch workflows**
3. **deterministic evidence generation**
4. **claim-grade structured analysis surfaces**
5. **provenance and auditability**
6. **one substrate for VR and malware modules**

---

## 5. Build Strategy

### We own
Anything that is:
- already inside IDA 9.0
- better expressed as structured MCP output than plugin UX
- central to the differentiator

Examples:
- function index
- batch filtering
- CTree queries
- microcode exports
- stack-frame analysis
- deterministic vulnerability rules
- provenance / cache / annotation system

### We adapt
Anything that is already a mature engine and not worth rebuilding.

Examples:
- angr
- Trailmark
- capa
- FLOSS
- YARA / YARA-X
- Diaphora
- OOAnalyzer

### We borrow ideas from
Anything whose value is real but whose shape is wrong.

Examples:
- HexRaysCodeXplorer
- HexRaysPyTools
- Lighthouse
- XRefer
- Lucid / genmc
- D-810

We are shipping **capabilities**, not **plugin compatibility**.

---

## 6. Backend Policy

### Required backend
- **IDA Pro 9.0**
- **idalib-first**
- **no Ghidra fallback** in v0.x

### Consequences
- one decompiler output model
- one API surface
- one annotation/provenance model
- less abstraction waste

If idalib later proves insufficient for a specific workload, the fallback is `idat64 -A -S` bridge mode. That is a backend fallback, not a product fallback.

---

## 7. Anti-Sprawl Rules

We do not add a capability just because it exists in a plugin.
A new capability must satisfy at least one of these:

1. it is required by the current roadmap phase
2. it directly reduces LLM calls/tokens for a core workflow
3. it provides deterministic evidence for a claim we care about
4. it is shared by both VR and malware directions
5. it replaces a brittle human-UI flow with a structured RPC

If it satisfies none of those, it waits.

---

## 8. Current Build Goal

Current build goal is still:

> make the N-day PoC writer viable

That means the MCP must be able to support this loop:
1. load vulnerable binary
2. load patched binary
3. diff them
4. identify changed function(s)
5. decompile and inspect patch candidates
6. generate deterministic evidence for root cause
7. support crash-PoC construction

Everything that does not improve that loop is secondary until the loop works end-to-end.

---

## 9. Success Criteria

We are successful when a future VR module can answer:

- where is the patch?
- what changed?
- what exact sink is dangerous?
- what proves the sink is attacker-controlled?
- what mitigations exist?
- what function/class/stack/object context matters?

without having to manually click around in IDA.

---

## 10. Current Status

Implemented:
- idalib bootstrap
- function index
- batch decompile
- deterministic pattern search
- diffing
- CTree query
- microcode export
- value-flow tracing
- second strong rule (`signed_size`)

Next likely move:
- stronger IR-backed value-range / def-use proof surface
