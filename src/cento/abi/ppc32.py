# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""PPC32 big-endian register conventions: the EABI volatile/nonvolatile split the chain fold carries."""

from __future__ import annotations

import cento.gadget
import cento.machine

Gadget = cento.gadget.Gadget
Restores = cento.gadget.Restores
Clobbers = cento.gadget.Clobbers

_R = cento.machine.Reg

AbiSpec = cento.machine.AbiSpec  # convenience re-export: ABI modules are self-contained to import from


PPC32 = AbiSpec(
    name="ppc32",
    volatile=frozenset({_R.R0, _R.R3, _R.R4, _R.R5, _R.R6, _R.R7, _R.R8, _R.R9, _R.R10, _R.R11, _R.R12, _R.LR, _R.CTR, _R.XER, _R.CR}),
    nonvolatile=frozenset(
        {
            cento.machine.Role.SP,
            _R.R2,
            _R.R13,
            _R.R14,
            _R.R15,
            _R.R16,
            _R.R17,
            _R.R18,
            _R.R19,
            _R.R20,
            _R.R21,
            _R.R22,
            _R.R23,
            _R.R24,
            _R.R25,
            _R.R26,
            _R.R27,
            _R.R28,
            _R.R29,
            _R.R30,
            _R.R31,
        }
    ),
    endian="big",
    word=4,
)
