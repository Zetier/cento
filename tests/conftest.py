# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Standalone-suite conftest: make the src-layout package importable without installation.

Inserted at sys.path[0] so `import cento` resolves to <subproject>/src/cento whether the
suite runs from the subproject root (cd cento && python3 -m pytest tests) or from a
parent repo. The repo root is added too so `import examples.exNN_...` resolves to the
runnable examples (which live outside the wheel). No other path is added: the shippable
tests depend on nothing outside the subproject tree.
"""

from __future__ import annotations

import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parents[1]
for _p in (str(_ROOT), str(_ROOT / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
