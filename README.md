# Trusted ClawHub Install Gate

`Trusted ClawHub Install Gate` is a local-first install wrapper for OpenClaw and ClawHub skills.

It does five things for `v0.2`:

1. Inspect a local unpacked skill directory.
2. Classify the artifact as `PASS`, `REVIEW`, or `BLOCK`.
3. Refuse installation by default unless the artifact is `PASS`.
4. Write a receipt for what was inspected and installed.
5. Summarize install and approved `REVIEW` usage from local receipts.

This release is intentionally narrow. It only supports local skill directories. It does not pretend to resolve arbitrary ClawHub slugs, guarantee safety, or verify runtime behavior inside the host application yet.

## Why this repo exists

The actual user pain is not "more discovery". It is:

- What exactly am I about to install?
- Does it contain obvious secret theft, destructive behavior, or opaque payloads?
- If I override the warning, can I at least keep a receipt of what I approved?

## Install

```bash
pip install -e .
```

## Commands

```bash
clawhub-install-gate inspect /path/to/skill
clawhub-install-gate inspect /path/to/skill --json

clawhub-install-gate install /path/to/skill --dest ./skills --allow-review

clawhub-install-gate verify ~/.openclaw/workspace/skills/my-skill

clawhub-install-gate usage
clawhub-install-gate usage --json
```

## Install destination

`install` requires an explicit `--dest` path in `v0.1`.

Use the real OpenClaw workspace skill directory, for example `<workspace>/skills`. The tool does not infer a workspace root yet because silently installing into the current shell directory is worse than failing closed.

## Verdict semantics

- `PASS`: no blocking findings and no review findings.
- `REVIEW`: ambiguous or risky patterns were found; installation is denied unless the user explicitly passes `--allow-review`.
- `BLOCK`: clearly unsafe or malformed artifact; installation is denied.

## Receipt location

Receipts are stored under:

```text
~/.local/share/clawhub-install-gate/receipts
```

Override the base directory with `CLAW_INSTALL_GATE_HOME`.

## Verify semantics

`verify` is receipt-aware. It succeeds only when the installed path has a matching receipt, the current installed content hash matches the recorded installed hash, and the current verdict matches the verdict that was approved during install.

An approved `REVIEW` install verifies successfully only if it was installed with `--allow-review` and the installed files have not drifted since the receipt was written.

## Usage tracking

`usage` summarizes the local receipt store so you can see which skills were installed, which verdicts were accepted, and how many `REVIEW` overrides exist on the machine.

The command reads local receipt JSON only. It does not call ClawHub, GitHub, or any external network service.

## Auto-review alignment

This project follows the Codex Auto-review model from the OpenAI developer documentation: review decisions are boundary checks, not permission grants.

The scanner blocks the same high-level risk classes that Auto-review is designed to stop:

- sending private data, secrets, or credentials to untrusted destinations
- probing for credentials, tokens, cookies, or session material
- broad or persistent security weakening
- destructive actions with significant risk of irreversible damage

If a skill asks to route around a denial, weaken sandbox or approval controls, or retry a blocked action indirectly, the gate reports `BLOCK`.

## Development

```bash
python3.10 -m pytest -q
```
