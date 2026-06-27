# Security Policy

`ida-headless-mcp` is a batch-oriented MCP server that drives IDA Pro
headless against analyst-supplied binaries. The server is designed to run
on a localhost or trusted-network interface; exposing it to untrusted
input means handing a binary-analysis automation surface to that input.

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a vulnerability

**Preferred channel: GitHub Security Advisories.**
File a private advisory at
[github.com/echel0nn/ida-headless-mcp-exp/security/advisories/new](https://github.com/echel0nn/ida-headless-mcp-exp/security/advisories/new).

**Alternative:** open a GitHub issue labeled `security:private` with
minimal detail and we will follow up by email for full context.

### What to include

- A concrete reproduction (sample binary, MCP request, tool invocation sequence)
- The component affected (server, specific tool name, deobfuscation engine, ...)
- The commit SHA or version you observed it on
- Your assessment of impact

### Response timeline

- Acknowledgment within 5 business days
- Triage within 10 business days
- A fix landed and a public advisory published, with credit, when remediation is ready

### Scope

**In scope:**

- The MCP server itself (`src/ida_headless_mcp/`)
- The HTTP API surface (`http_api.py`)
- The deobfuscation engine and pattern matchers
- The bundled scripts and `run.sh`

**Out of scope:**

- Bugs in IDA Pro itself (report to Hex-Rays)
- Bugs in miasm, capstone, lief, or other third-party libraries (report upstream)
- Findings that require local shell access to the host -- the server trusts the
  process it runs as
- Findings against a deployment you do not own and have no authorization to test

### Credit

Responsible reporters are credited in the published advisory unless you ask us not to.
