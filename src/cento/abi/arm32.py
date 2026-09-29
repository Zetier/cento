# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""ARM32 AAPCS register conventions: the volatile/nonvolatile split the chain fold carries.

Registers are string slots ("r0".."r12", "r14"); Role.SP stands for sp (r13) and Role.PC for
pc (r15) -- and unlike every other shipped arch, `pop {.., pc}` loads PC DIRECTLY from the
frame, so continuation slots are internal (external=False) and frames abut with no aliasing.
sp_align=8 is the AAPCS public-interface contract. Thumb interworking is a spelling: a Thumb
gadget's entry carries bit 0 set (entry=0x8F00460 | 1); the chain emits the address as-is
(the CPU consumes the bit) and the [verify] executor reads it to select Thumb mode.
"""

from __future__ import annotations

import cento.gadget
import cento.machine

Gadget = cento.gadget.Gadget
Restores = cento.gadget.Restores
Clobbers = cento.gadget.Clobbers

AbiSpec = cento.machine.AbiSpec  # convenience re-export: ABI modules are self-contained to import from
Role = cento.machine.Role

ARM32 = AbiSpec(
    name="arm32",
    volatile=frozenset(
        {
            "r0",
            "r1",
            "r2",
            "r3",
            "r12",
            "r14",
        }
    ),
    nonvolatile=frozenset(
        {
            Role.SP,
            "r4",
            "r5",
            "r6",
            "r7",
            "r8",
            "r9",
            "r10",
            "r11",
        }
    ),
    sp_align=8,
    endian="little",
    word=4,
)
