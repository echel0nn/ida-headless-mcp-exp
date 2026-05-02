# Plugin / Tool Strategy

Explicit decision for every relevant plugin or external engine.

Four buckets:
1. **Own natively**
2. **Adapt / wrap**
3. **Reimplement the idea**
4. **Ignore for now**

---

## 1. Own natively

These are already inside IDA and should not depend on plugins.

- decompilation
- CTree access
- microcode export
- function index
- xrefs / call graph / stack frame
- metadata / mitigations
- provenance / annotation system
- deterministic rules

Reason:
- direct differentiator
- cleaner than plugin UX
- no external dependency

---

## 2. Adapt / wrap

These are mature standalone engines. Do not rebuild them.

| Tool | Why adapt | Phase |
|---|---|---|
| angr | symbolic execution, path feasibility, constraints, angrop | Later |
| Trailmark | source graph for interpreted targets | Later |
| capa | malware capability extraction | Later |
| FLOSS | string deobfuscation | Later |
| YARA / YARA-X | signature scanning | Later |
| OOAnalyzer | C++ object recovery | Later |
| Diaphora | best-in-class diff backend | Later / maybe soon |
| BinDiff | optional commercial diff backend | Much later |

Rule:
- adapt only when the MCP output can be normalized into our evidence/provenance model

---

## 3. Reimplement the idea

These projects prove value, but their current shape is wrong for us.

| Project | What we take | What we do not take |
|---|---|---|
| HexRaysCodeXplorer | ctree export, object/vtable workflow ideas | GUI plugin, C++ plugin architecture |
| HexRaysPyTools | variable scan / deep scan / struct recovery workflow | right-click UX, old plugin assumptions |
| Lighthouse | coverage parsers and coverage model | painting, widgets, combobox UI |
| XRefer | behavioral clustering and trace-enrichment ideas | Gemini UI, navigation interface |
| Lucid / genmc | microcode exposure ideas | interactive viewers |
| D-810 | deobfuscation transform concepts | plugin packaging |
| Metis | evidence obligations, adjudication, bounded evidence packs | SARIF-centric workflow |
| Pharos | OO recovery, path analysis concepts, function hashing ideas | ROSE dependency and full framework |

Reason:
- value is real
- code shape is wrong
- we want structured MCP-native output, not GUI state

---

## 4. Ignore for now

- interactive-only reverse-engineering helper plugins
- plugins whose value is only painting or navigation
- anything that depends on Ghidra fallback assumptions
- anything that does not materially improve N-day or future malware workflows

---

## Decision Rules

### We reimplement when
- the capability is narrow and deterministic
- the plugin is UI-first
- native MCP output is more valuable than reuse
- it directly strengthens our unfair advantage

### We adapt when
- the tool is already a serious engine
- rebuilding would take too long
- output can be normalized cleanly

### We ignore when
- it doesn’t move the current roadmap
- it adds complexity without improving autonomous workflows

---

## Current high-priority plugin/tool strategy

### Immediate
- no plugin dependencies
- own the IDA-native core

### Next likely adapters
1. Diaphora
2. angr
3. Trailmark

### Malware-first adapters later
4. capa
5. FLOSS
6. YARA-X

### Complex research enrichments later
7. OOAnalyzer
8. behavioral clustering
9. coverage ingestion

---

## One-sentence strategy

We ship the capabilities ourselves when they define the product, and adapt external tools only when they already solve a hard engine problem better than we can reasonably reimplement.
