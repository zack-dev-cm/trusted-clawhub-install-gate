---
name: trusted-clawhub-install-gate
description: Audit a local OpenClaw or ClawHub skill directory before installation, classify it as PASS, REVIEW, or BLOCK, and optionally run the clawhub-install-gate CLI to write a receipt or install after explicit user approval.
version: 0.2.0
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
6. Use `clawhub-install-gate usage` when the user asks to track install or REVIEW override usage on this machine.

Review policy:

- Treat the verdict as an Auto-review-style boundary decision, not a permission grant.
- `BLOCK` covers private-data transmission, secret-store probing, broad security weakening, denial circumvention, and destructive actions.
- If a risky action is denied, do not route around it; choose a materially safer path or stop for user decision.
