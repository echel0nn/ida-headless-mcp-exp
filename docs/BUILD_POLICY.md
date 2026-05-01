# Build Policy

What we reimplement, what we adapt, what we copy ideas from, and what we refuse to depend on.

This project is AGPL and non-commercial. Licensing is permissive enough to port or vendor AGPL/GPL logic where useful. The constraints are **technical**, not legal.

---

## Core Principle

We do **not** ship "an IDA plugin bundle."

We ship a **headless binary-analysis engine** that:
- uses **IDA 9.0 / idalib** directly for core analysis
- exposes **structured MCP commands** for LLM-driven workflows
- owns the **capability surface** that makes vulnerability research and malware analysis possible
- wraps external tools when they are already best-in-class
- ports ideas from GUI plugins when the capability is valuable but the plugin shape is wrong

The project must work with **zero third-party IDA plugins installed**.

Users provide:
- their own IDA Pro 9.0 installation and license
- optional external tools (capa, FLOSS, angr, Diaphora, Trailmark, etc.) if they want the enriched capability set

---

## Four Integration Classes

### Class 1 — Native IDA capabilities (own completely)

These are implemented directly against IDA's APIs. No plugin dependency.

Examples:
- load/open/rebase binary
- imports, exports, segments
- decompile function
- list functions
- xrefs, strings, data refs
- stack frame analysis
- FLIRT/Lumina lookup
- CTree export and queries
- microcode export and queries
- call graph / CFG / dominators / loops
- type usage, struct inspection

**Rule:** if IDA 9.0 can already compute it, we call the API ourselves and define our own output schema.

### Class 2 — Reimplemented capability (plugin idea, our code)

These are capabilities that existing plugins prove are valuable, but whose code or UX is wrong for a headless MCP.

Examples:
- CTree graph / object explorer patterns from HexRaysCodeXplorer
- variable scanning / deep scan / struct reconstruction workflow from HexRaysPyTools
- coverage ingestion model from Lighthouse
- behavioral clustering ideas from XRefer
- deterministic vulnerability pattern engine (dangerous_function, unchecked_length, etc.)
- evidence obligation system and bounded evidence packs (inspired by Metis)

**Rule:** reimplement when the plugin is GUI-first, interactive, version-fragile, or returns output that is not structured enough for autonomous analysis.

### Class 3 — Adapter to external engine (do not reimplement)

These are mature standalone engines. We wrap them.

Examples:
- angr
- Trailmark
- capa
- FLOSS
- YARA / YARA-X
- OOAnalyzer
- Diaphora
- BinDiff (if present)

**Rule:** adapt when the external tool is already an engine, already battle-tested, and reproducing it would take months or years.

### Class 4 — Inspiration only (no direct dependency)

These tools inform our design but are not runtime dependencies.

Examples:
- Lighthouse UI
- XRefer UI
- Lucid / genmc viewers
- D-810 plugin as a package
- HexRaysCodeXplorer as a compiled plugin

**Rule:** if the value is in the analyst UX rather than the underlying analysis primitive, copy the concept and build it natively later only if needed.

---

## Reimplement vs Adapt Decision Matrix

| Capability / Tool | Decision | Why |
|---|---|---|
| IDA loading / metadata / decompilation | Reimplement (native) | Already inside IDA; plugins only wrap it |
| CTree queries | Reimplement (native) | No current MCP exposes them; direct differentiator |
| Microcode queries | Reimplement (native) | Same — direct differentiator |
| Stack frame exploitability math | Reimplement (native) | Simple, deterministic, high-value |
| Function index (complexity, blast radius, reachability) | Reimplement | Cheap to compute, central to filter-first design |
| Pattern search (dangerous_function, unchecked_length, etc.) | Reimplement | Core deterministic evidence for obligations |
| Binary diff API | Reimplement surface, adapt backend | Our surface; Diaphora/BinDiff can back it later |
| Annotation provenance | Reimplement | No existing tool tracks LLM vs operator provenance |
| Coverage ingestion / diff | Reimplement model | Lighthouse GUI is wrong shape; parsers are fine to borrow ideas from |
| Behavioral clustering | Reimplement | XRefer UI not reusable; graph model is |
| angr symbolic execution | Adapt | Mature engine, impossible to beat quickly |
| Trailmark source graph | Adapt | 21 languages already solved |
| capa capability extraction | Adapt | Mature rules corpus |
| FLOSS string recovery | Adapt | Mature deobfuscation engine |
| YARA / YARA-X | Adapt | Existing standard |
| OOAnalyzer | Adapt (optional) | Deep C++ recovery is expensive to rebuild |
| Diaphora | Adapt (optional, high priority) | Best-in-class diff engine |

---

## What “Best” Means Here

We are not trying to be:
- the best general-purpose reverse-engineering assistant
- the best interactive IDA plugin
- the best standalone diff engine
- the best string deobfuscator
- the best capability extractor

We are trying to be:

> **the best IDA headless MCP for autonomous vulnerability research and later malware-analysis workflows**

That means the MCP must win on:
- batch structural filtering
- deterministic evidence generation
- token efficiency
- binary diff as a first-class workflow
- CTree/microcode/data-flow access
- provenance and auditability
- persistence across long-running sessions
- one command surface that works for both VR and malware modules

If a plugin has a better GUI, that does not matter.
If a standalone tool has a better engine, we adapt it.
If IDA can already compute it, we expose it directly.

---

## Shared Core vs Module-Specific Capability Packs

The MCP itself is shared platform infrastructure. It must be useful to more than one future module.

### Shared core
Available to every consumer:
- binary load/open
- metadata, imports/exports/segments
- decompile/list/xrefs/strings
- CTree / microcode / call graph / stack frame
- binary diff / annotations
- coverage import model
- provenance and request logging

### VR pack
Prioritized for `vr/`:
- dangerous-function rules
- unchecked length detection
- mitigation analysis
- stack overflow distance / exploit primitives
- patch ranking / N-day helpers
- angr path and constraint helpers

### Malware pack
Prioritized for future `malware/`:
- capa integration
- FLOSS integration
- YARA scanning
- anti-analysis detection
- config extraction
- ATT&CK mapping
- trace and sandbox artifact ingestion

The **MCP ships the substrate**. Modules decide what workflows to build on top of it.

---

## Provenance and Copying Policy

When we port or vendor logic from another project:
1. keep the original attribution and license notice
2. isolate the borrowed logic into a clearly named module
3. normalize output into our schemas
4. do not inherit a foreign architecture wholesale
5. prefer rewriting small capabilities from scratch when the original code is UI-entangled or easier to understand than to reuse

This repo is AGPL, so copyleft compatibility is acceptable. Still, code ownership and maintainability matter more than legal permissibility.

---

## Negative Policy

We explicitly do **not** do these things:

- No dependency on running IDA GUI windows
- No requirement that users manually click through plugins
- No plugin binary bundles checked into this repo
- No operator-invisible arbitrary script execution available to the LLM
- No dual-backend abstraction for IDA/Ghidra in v0.x
- No architecture built around "maybe a plugin can do this"
- No promise that every feature will work without IDA Pro 9.0 + license

---

## Immediate Consequences for v0.1

1. **idalib-first backend**
   - bridge-worker path remains a fallback only if idalib proves unworkable
2. **No Ghidra fallback**
   - explicitly deferred to a very late version
3. **No plugin compatibility target**
   - we build our own command surface
4. **Adapters are optional**
   - first version should still function without Diaphora, angr, capa, etc.
5. **The first benchmark is against current MCPs, not plugins**
   - especially jtsylve/ida-mcp

---

## Summary

- **Own** the MCP-native analysis surface
- **Reimplement** the capabilities whose value lies in workflow and structure, not in GUI
- **Adapt** the mature external engines
- **Ignore** plugin compatibility as a goal
- **Optimize** for autonomous research workflows, not for human-at-keyboard convenience

This is how we become better than current targets rather than becoming a headless clone of them.
