#!/usr/bin/env python3
"""Repository-local checks for the Ward plugin and management skill."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


manifest_path = ROOT / ".codex-plugin" / "plugin.json"
try:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    fail(f"invalid plugin manifest: {exc}")

if manifest.get("name") != "ward":
    fail("plugin name must be ward")
if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", str(manifest.get("version", ""))):
    fail("plugin version must be semver")
if manifest.get("skills") != "./skills/":
    fail("plugin must expose ./skills/")
if "hooks" in manifest:
    fail("plugin-local hooks are forbidden; the CLI owns the user-global hook")

skill_path = ROOT / "skills" / "ward" / "SKILL.md"
try:
    skill_text = skill_path.read_text(encoding="utf-8")
except OSError as exc:
    fail(f"cannot read Ward skill: {exc}")
if not skill_text.startswith("---\n"):
    fail("Ward skill must start with YAML frontmatter")
parts = skill_text.split("---\n", 2)
if len(parts) != 3:
    fail("Ward skill frontmatter is not closed")
frontmatter = yaml.safe_load(parts[1])
if frontmatter.get("name") != "ward" or not frontmatter.get("description"):
    fail("Ward skill needs name and description")
if "Ward must never output `permissionDecision: allow` or `ask`" not in skill_text:
    fail("Ward skill must explicitly forbid allow and ask hook decisions")
if "On an ordinary `defer`, do nothing" not in skill_text:
    fail("Ward skill must stay inactive for ordinary defer requests")
if "Ward emits no permission decision and defers to the Host" not in skill_text:
    fail("Ward skill must preserve fail-open-to-Host error semantics")
if "retry it without asking the user" not in skill_text:
    fail("Ward skill must guide autonomous recovery after a deny")

print("PASS: Ward plugin and skill contracts are valid")
