## What this PR does

One-paragraph summary of the change.

## Why

The problem this addresses, or the feature being delivered.

## How to verify

Steps a reviewer can take to confirm the change works as described.
If the change touches a deobfuscation pattern or decompiler pass,
include a before/after on a representative sample (mask anything
proprietary).

## Quality gates

- [ ] `python -m ruff check src/` exits 0
- [ ] `python -m compileall -q src/` exits 0
- [ ] If touching MCP tool contracts: bumped the tool count in README.md
- [ ] If touching the HTTP API: updated request/response examples in docs

## Related issues

Closes #
