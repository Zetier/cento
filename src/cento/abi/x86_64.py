# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""x86-64 System V register conventions: the volatile/nonvolatile split the chain fold carries.

Registers are string slots ("rdi", "rsi", ...); Role.SP stands for rsp and Role.PC for rip
(the legacy Reg.SP/Reg.PC spellings normalize to them). sp_align=16 carries the SysV stack contract: a
function entered by CALL sees SP % 16 == 8, so a gadget declaring entry_sp_mod=8 (system(),
any SSE-using callee) is judged at build time (CHK-207) -- the movaps crash, refused early.
"""

from __future__ import annotations

import cento.gadget
import cento.machine

Gadget = cento.gadget.Gadget
Restores = cento.gadget.Restores
Clobbers = cento.gadget.Clobbers

AbiSpec = cento.machine.AbiSpec  # convenience re-export: ABI modules are self-contained to import from

CALL_ENTRY_SP_MOD = 8  # SP % 16 right after CALL pushes the return address; entering by RET must reproduce it

X86_64 = AbiSpec(
    name="x86_64",
    volatile=frozenset(
        {
            "rax",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "r8",
            "r9",
            "r10",
            "r11",
        }
    ),
    nonvolatile=frozenset(
        {
            cento.machine.Role.SP,
            "rbx",
            "rbp",
            "r12",
            "r13",
            "r14",
            "r15",
        }
    ),
    sp_align=16,
    endian="little",
    word=8,
)
