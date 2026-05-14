from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def _write_skill(root: Path, body: str, *, script: str | None = None) -> None:
    root.mkdir()
    (root / "SKILL.md").write_text(body, encoding="utf-8")
    if script is not None:
        scripts = root / "scripts"
        scripts.mkdir()
        (scripts / "helper.py").write_text(script, encoding="utf-8")


def _run(*args: str, gate_home: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    env["CLAW_INSTALL_GATE_HOME"] = str(gate_home)
    return subprocess.run(
        [sys.executable, "-m", "clawhub_install_gate", *args],
        cwd=ROOT,
        env=env,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def test_inspect_json_output(tmp_path: Path) -> None:
    skill = tmp_path / "safe-skill"
    _write_skill(
        skill,
        """---
name: safe-skill
description: Review a local Markdown document and summarize public, non-sensitive findings without network access or shell execution.
---

# Safe Skill
""",
    )

    result = _run("inspect", str(skill), "--json", gate_home=tmp_path / "gate-home")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["verdict"] == "PASS"
    assert payload["skill_name"] == "safe-skill"


def test_install_requires_allow_review(tmp_path: Path) -> None:
    skill = tmp_path / "network-skill"
    _write_skill(
        skill,
        """---
name: network-skill
description: Fetch public release metadata for a repository and summarize the response for open-source maintenance planning without touching any user secrets.
---

# Network Skill
""",
        script="import urllib.request\nprint('ok')\n",
    )

    result = _run(
        "install",
        str(skill),
        "--dest",
        str(tmp_path / "installed"),
        gate_home=tmp_path / "gate-home",
    )

    assert result.returncode == 2
    assert "REVIEW" in result.stderr


def test_install_review_with_override_succeeds(tmp_path: Path) -> None:
    skill = tmp_path / "network-skill"
    _write_skill(
        skill,
        """---
name: network-skill
description: Fetch public release metadata for a repository and summarize the response for open-source maintenance planning without touching any user secrets.
---

# Network Skill
""",
        script="import urllib.request\nprint('ok')\n",
    )

    gate_home = tmp_path / "gate-home"

    result = _run(
        "install",
        str(skill),
        "--dest",
        str(tmp_path / "installed"),
        "--allow-review",
        "--json",
        gate_home=gate_home,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["report"]["verdict"] == "REVIEW"
    assert payload["receipt"]["override_review"] is True
    assert payload["receipt"]["installed_content_sha256"] == payload["report"]["content_sha256"]
    assert len(list((gate_home / "receipts").glob("*.json"))) == 1


def test_verify_review_install_with_receipt_succeeds(tmp_path: Path) -> None:
    skill = tmp_path / "network-skill"
    _write_skill(
        skill,
        """---
name: network-skill
description: Fetch public release metadata for a repository and summarize the response for open-source maintenance planning without touching any user secrets.
---

# Network Skill
""",
        script="import urllib.request\nprint('ok')\n",
    )
    gate_home = tmp_path / "gate-home"

    install_result = _run(
        "install",
        str(skill),
        "--dest",
        str(tmp_path / "installed"),
        "--allow-review",
        "--json",
        gate_home=gate_home,
    )
    assert install_result.returncode == 0
    installed_path = json.loads(install_result.stdout)["receipt"]["installed_path"]

    verify_result = _run("verify", installed_path, "--json", gate_home=gate_home)

    assert verify_result.returncode == 0
    payload = json.loads(verify_result.stdout)
    assert payload["verified"] is True
    assert payload["report"]["verdict"] == "REVIEW"
    assert payload["receipt"]["override_review"] is True


def test_usage_json_summarizes_receipts(tmp_path: Path) -> None:
    skill = tmp_path / "network-skill"
    _write_skill(
        skill,
        """---
name: network-skill
description: Fetch public release metadata for a repository and summarize the response for open-source maintenance planning without touching any user secrets.
---

# Network Skill
""",
        script="import urllib.request\nprint('ok')\n",
    )
    gate_home = tmp_path / "gate-home"
    install_result = _run(
        "install",
        str(skill),
        "--dest",
        str(tmp_path / "installed"),
        "--allow-review",
        "--json",
        gate_home=gate_home,
    )
    assert install_result.returncode == 0

    usage_result = _run("usage", "--json", gate_home=gate_home)

    assert usage_result.returncode == 0
    payload = json.loads(usage_result.stdout)
    assert payload["total_receipts"] == 1
    assert payload["override_review_receipts"] == 1
    assert payload["verdict_counts"]["REVIEW"] == 1
    assert payload["skill_counts"]["network-skill"] == 1
