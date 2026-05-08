---
name: trusted-clawhub-install-gate
description: Audit a local OpenClaw or ClawHub skill directory before installation, classify it as PASS, REVIEW, or BLOCK, and optionally run the clawhub-install-gate CLI to write a receipt or install after explicit user approval.
version: 0.1.0
homepage: https://github.com/zack-dev-cm/trusted-clawhub-install-gate
license: MIT
user-invocable: true
metadata: {"openclaw":{"homepage":"https://github.com/zack-dev-cm/trusted-clawhub-install-gate","skillKey":"trusted-clawhub-install-gate","requires":{"bins":["clawhub-install-gate"],"anyBins":["python3","python"]}}}
---

# Trusted ClawHub Install Gate

Use this skill when a user wants to inspect a local skill artifact before install.

Workflow:

1. Run `clawhub-install-gate inspect <path>` first.
2. Explain the findings.
3. Do not install on `BLOCK`.
4. Only install on `REVIEW` after explicit user approval.
5. Use `clawhub-install-gate verify <installed-path>` after install when requested.
