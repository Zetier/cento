# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""The CI verdict: gate(layout) -> bool, with every blocker narrated to stderr.

Display layer by design: the judgment is exactly layout.preflight().shippable -- the same
gate the final emit applies (check errors, dangling continuations, pending symbols) --
and gate() adds only the failure narration. stdout stays clean for artifacts; the refusal
story rides stderr, only on False. The whole CI step::

    sys.exit(0 if cento.gate(layout) else 1)

Note the facade binding: the package attribute `cento.gate` is this module's `gate` CALLABLE
(the verdict deliberately shadows the submodule, like `cento.golden`).
"""

from __future__ import annotations

import sys

import cento.regions


def gate(layout: cento.regions.Layout) -> bool:
    """True = shippable (silent), False = refuse (blockers printed to stderr).

    On False, stderr carries report.render() verbatim (errors, warnings, pending symbols)
    plus one line per dangling chain -- a dangling continuation is only a WARNING (CHK-206)
    at check() but a refusal at every final gate, so it is named here as the refusal it is.
    Never raises, never emits: the artifact stays the caller's move.
    """
    pf = layout.preflight()
    if pf.shippable:
        return True
    lines = [pf.report.render()]
    for d in pf.dangling:
        lines.append(f"dangling chain {d.chain}: continuation cell {d.cell} never wired -- the final gates refuse on it")
    print("\n".join(lines), file=sys.stderr)
    return False
