#!/usr/bin/env python3
# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Regenerate examples/*/transcript.txt from the TRANSCRIPTS contract (examples/__init__.py).

Each transcript is the verbatim, deterministic output of its directory's scripts, checked in
so a reader gets the run without running -- and gated: tests/test_examples.py rebuilds every
transcript the same way and asserts byte equality, so a drifted transcript fails CI.

Run: make transcripts (or: python3 config/gen_transcripts.py)
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from examples import TRANSCRIPTS  # noqa: E402


def build(exdir: pathlib.Path, scripts: tuple[str, ...]) -> str:
    """One transcript: each script's stdout under a `$ python3 <script>` line, blank-line separated."""
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src") + os.pathsep + os.environ.get("PYTHONPATH", "")}
    parts = []
    for script in scripts:
        proc = subprocess.run([sys.executable, script], cwd=str(exdir), capture_output=True, text=True, timeout=120, env=env, check=True)
        parts.append(f"$ python3 {script}\n{proc.stdout}")
    return "\n".join(parts).rstrip("\n") + "\n"


def main() -> int:
    for name, scripts in TRANSCRIPTS.items():
        exdir = ROOT / "examples" / name
        (exdir / "transcript.txt").write_text(build(exdir, scripts), encoding="ascii")
        print(f"wrote examples/{name}/transcript.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
