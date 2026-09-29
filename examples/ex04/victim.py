# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""The ex04 victim: a thirty-one-instruction PPC32 program, assembled by hand.

No cross compiler: this module IS the toolchain -- three instruction encoders, four opcode
constants, and an ELF32-BE writer. ex04_qemu_ret2win.py imports assemble_victim() and runs
the result under qemu-ppc.
"""

from __future__ import annotations

import struct

BASE = 0x10000000  # one RWX PT_LOAD; code starts right after ehdr+phdr
CODE_OFF = 0x54
MSG_WIN = b"win: control of pc\n"
MSG_NORMAL = b"returned normally\n"


def li(d: int, imm: int) -> int:
    return 0x38000000 | d << 21 | (imm & 0xFFFF)


def addi(d: int, a: int, imm: int) -> int:
    return 0x38000000 | d << 21 | a << 16 | (imm & 0xFFFF)


def addis(d: int, a: int, imm: int) -> int:
    return 0x3C000000 | d << 21 | a << 16 | (imm & 0xFFFF)


MFLR_R0, MTLR_R0, BLR, SC = 0x7C0802A6, 0x7C0803A6, 0x4E800020, 0x44000002


def sys_write(buf_va: int, n: int) -> list[int]:
    return [li(0, 4), li(3, 1), addis(4, 0, buf_va >> 16), addi(4, 4, buf_va), li(5, n), SC]


def sys_exit() -> list[int]:
    return [li(0, 1), li(3, 0), SC]


def assemble_victim() -> tuple[bytes, int]:
    """The vulnerable program as an ELF32-BE image; returns (elf_bytes, win_address).

    _start calls vuln; vuln reads 0x100 bytes into a 0x44-byte-away stack slot (the bug), then
    runs the textbook epilogue: lwz r0, 4(r1); mtlr r0; blr -- the saved LR is ours.
    """
    n_start, n_vuln = 10, 12  # word counts, fixed by the lists below
    n_win = 9

    def va(word: int) -> int:  # a label helper: code word index -> virtual address
        return BASE + CODE_OFF + 4 * word

    vuln_va, win_va = va(n_start), va(n_start + n_vuln)
    msg_normal_va = va(n_start + n_vuln + n_win)
    msg_win_va = msg_normal_va + len(MSG_NORMAL)

    start = [0x48000001 | ((vuln_va - va(0)) & 0x03FFFFFC)]  # bl vuln
    start += sys_write(msg_normal_va, len(MSG_NORMAL)) + sys_exit()
    vuln = [
        MFLR_R0,
        0x90010004,  # stw  r0, 4(r1)      -- save LR in the caller's frame (SysV PPC32)
        0x9421FFB0,  # stwu r1, -0x50(r1)  -- open a 0x50-byte frame; saved LR is now at r1+0x54
        li(0, 3),
        li(3, 0),
        addi(4, 1, 0x10),
        li(5, 0x100),
        SC,  # read(0, r1+0x10, 0x100): the bug
        0x38210050,  # addi r1, r1, 0x50
        0x80010004,  # lwz  r0, 4(r1)
        MTLR_R0,
        BLR,
    ]
    win = sys_write(msg_win_va, len(MSG_WIN)) + sys_exit()
    assert (len(start), len(vuln), len(win)) == (n_start, n_vuln, n_win)
    code = b"".join(struct.pack(">I", w) for w in start + vuln + win) + MSG_NORMAL + MSG_WIN

    filesz = CODE_OFF + len(code)
    ehdr = struct.pack(">4s5B7x2H5I6H", b"\x7fELF", 1, 2, 1, 0, 0, 2, 20, 1, va(0), 0x34, 0, 0, 0x34, 0x20, 1, 0, 0, 0)
    phdr = struct.pack(">8I", 1, 0, BASE, BASE, filesz, filesz, 7, 0x10000)
    return ehdr + phdr + code, win_va
