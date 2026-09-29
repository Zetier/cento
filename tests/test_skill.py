# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""The agent skill (skills/cento/) stays honest: every recipe runs green, and the
reference's CHK table stays in sync with the library's own catalog."""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys

import pytest

import cento.checks

SKILL_DIR = pathlib.Path(__file__).resolve().parents[1] / "skills" / "cento"


def _require_skill() -> None:
    if not SKILL_DIR.is_dir():
        pytest.skip("skills/ absent (dist-verify scratch runs against the installed package)")


def test_skill_files_exist_ascii_only() -> None:
    _require_skill()
    names = sorted(p.name for p in SKILL_DIR.iterdir())
    assert names == ["SKILL.md", "recipes.md", "reference.md"]
    for p in SKILL_DIR.iterdir():
        p.read_bytes().decode("ascii")


def test_skill_frontmatter_routes() -> None:
    _require_skill()
    text = (SKILL_DIR / "SKILL.md").read_text(encoding="ascii")
    assert text.startswith("---\nname: cento\n")  # the name matches the directory (skills/cento/), per the skill-packaging convention
    head, _, _ = text.partition("\n---\n")
    assert "description:" in head and "CHK" in head  # the router matches on the domain vocabulary


def test_reference_chk_table_matches_the_catalog() -> None:
    _require_skill()
    table_codes = set(re.findall(r"\| (CHK-\d{3}) \|", (SKILL_DIR / "reference.md").read_text(encoding="ascii")))
    assert table_codes == set(cento.checks.CODES), "skill CHK table drifted from cento.checks.CODES"


def test_every_recipe_runs_green(tmp_path: pathlib.Path) -> None:
    """Extract each ```python block from recipes.md and execute it standalone.

    Recipes end in assertions, so rc == 0 is the proof. Changing the library in a way that
    breaks a recipe means updating the recipe in the same change -- the skill never teaches
    an API that no longer exists.
    """
    _require_skill()
    blocks = re.findall(r"```python\n(.*?)```", (SKILL_DIR / "recipes.md").read_text(encoding="ascii"), flags=re.DOTALL)
    assert len(blocks) == 7  # recipes.md block count: update this pin in the same change as the recipe
    # The recipe subprocess must import THIS tree's cento (mirroring conftest's sys.path insert),
    # or a recipe exercising new API would be judged against whatever install shadows it.
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(p for p in (str(SKILL_DIR.parents[1] / "src"), env.get("PYTHONPATH")) if p)
    for i, block in enumerate(blocks, 1):
        script = tmp_path / f"recipe_{i}.py"
        script.write_text(block, encoding="ascii")
        proc = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=120, env=env)
        assert proc.returncode == 0, f"recipe {i} failed:\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}"
