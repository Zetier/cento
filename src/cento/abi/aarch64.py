# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""AArch64 AAPCS64 register conventions: the volatile/nonvolatile split the chain fold carries.

Registers are string slots ("x0".."x30"); Role.SP stands for sp and Role.PC for the x30-fed
`ret` target -- the `ldp x29, x30, [sp], #N; ret` idiom is declared as Restores(Role.PC, ...)
exactly like PPC32's `lwz r0; mtlr r0; blr`. sp_align=16 is a HARDWARE fact on AArch64 (SP
alignment checking faults misaligned SP-based accesses), not a calling-convention courtesy:
gadgets declaring entry_sp_mod are judged at build time (CHK-207). Declare widths explicitly
(width=cento.u64): the u32 default is the ILP32 idiom, not this architecture's.
"""

from __future__ import annotations

import cento.gadget
import cento.machine

Gadget = cento.gadget.Gadget
Restores = cento.gadget.Restores
Clobbers = cento.gadget.Clobbers

AbiSpec = cento.machine.AbiSpec  # convenience re-export: ABI modules are self-contained to import from
Role = cento.machine.Role

AARCH64 = AbiSpec(
    name="aarch64",
    volatile=frozenset(
        {
            "x0",
            "x1",
            "x2",
            "x3",
            "x4",
            "x5",
            "x6",
            "x7",
            "x8",
            "x9",
            "x10",
            "x11",
            "x12",
            "x13",
            "x14",
            "x15",
            "x16",
            "x17",
            "x18",
            "x30",
        }
    ),
    nonvolatile=frozenset(
        {
            Role.SP,
            "x19",
            "x20",
            "x21",
            "x22",
            "x23",
            "x24",
            "x25",
            "x26",
            "x27",
            "x28",
            "x29",
        }
    ),
    sp_align=16,
    endian="little",
    word=8,
)
