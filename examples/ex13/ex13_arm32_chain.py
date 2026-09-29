# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""cento -- borrowed fragments, arranged deliberately, checked as a whole.

Example 13 -- an ARM32 chain: pop-to-pc frames that abut, and the Thumb bit

The Meridian MK-3 is the family's 32-bit ARM generation: a management controller whose
maintenance service parses records into a fixed stack buffer, and a long record rewrites the
saved r4/lr words below it -- so the parse handler's OWN epilogue, pop {r4, pc}, consumes our
first frame. The signature fact rides every gadget here: unlike every other shipped
architecture, ARM32's pop loads PC DIRECTLY from the frame (no x30 for ret to consume, no
external continuation word beyond the frame like the MK-1's PPC32 tails), so continuation
slots are internal and the frames below abut with no declared aliasing. Thumb interworking is
a spelling, not a mechanism: a Thumb gadget's entry carries bit 0 set (entry=FW_CALLTAIL | 1),
the chain emits the odd address as-is, and the CPU consumes the bit at the branch.

Run: python3 examples/ex13/ex13_arm32_chain.py   (transcript.txt is this run, verbatim)
Next: ex14_port_a_script (and docs/porting-an-abi.md for the moves this ARM32 port took)
"""

from __future__ import annotations

import sys

import cento
from cento.abi.arm32 import ARM32

Role = cento.Role

FW_EPILOGUE = 0x8F00194  # the parse handler's epilogue: execution reaches it on its own; its pops are ours
FW_LOADPAIR = 0x8F001D4  # pop {r4, r5, pc}: fills the callee-saved pair the call tail consumes
FW_CALLTAIL = 0x8F00460  # Thumb: call r5 with r0 = r4, then pop the next frame
SVC_UNLOCK = 0x8F02C50  # firmware: unlock the maintenance port when r0 carries a valid token
CONSOLE_LOOP = 0x8F03E10  # firmware: the maintenance console loop -- never returns
MAINT_TOKEN = 0x00C0FFEE  # fiction: the family's maintenance unlock token (the MK-4 kept it)
REC_VA = 0xE0402000  # fiction: the parse buffer's stack address, leaked by a chatty error path


class Epilogue(cento.Gadget, entry=FW_EPILOGUE, stride=0x8):
    """0x8f00194: pop {r4, pc}

    The parse handler's own epilogue, the entry hop: the overflow rewrote the saved r4/lr
    words, so the function's normal return consumes OUR first frame -- no aiming needed.
    """

    r4 = cento.Restores("r4", at=0x0)  # width defaults to u32: ARM32 is the architecture the default fits (ex12 declared u64 everywhere)
    pc = cento.Restores(Role.PC, at=0x4)  # pop loads PC straight from this word: internal, nothing aliases


class LoadPair(cento.Gadget, entry=FW_LOADPAIR, stride=0xC):
    """0x8f001d4: pop {r4, r5, pc}

    The loader: fills the callee-saved pair the call tail consumes, then pops on.
    """

    r4 = cento.Restores("r4", at=0x0)
    r5 = cento.Restores("r5", at=0x4)
    pc = cento.Restores(Role.PC, at=0x8)


# The Thumb bit: FW_CALLTAIL is where the bytes live; FW_CALLTAIL | 1 is the ENTRY. Bit 0
# selects Thumb state at the branch, the chain emits the odd address as-is, and the CPU
# consumes the bit. AAPCS pins SP % 8 == 0 at the public interface -- the blx boundary -- so
# only this call-shaped gadget declares entry_sp_mod=0 (x86-64's one-boundary rule, not the
# MK-4's every-hop hardware fault).
class CallTail(cento.Gadget, entry=FW_CALLTAIL | 1, stride=0xC, entry_sp_mod=0):
    """0x8f00460: mov r0, r4; blx r5; pop {r4, r5, pc}  (Thumb)

    The call-shaped gadget: blx calls r5 with r0 = r4. The docstring keeps the code address;
    disasm() renders the class's own entry, so the printed line carries the odd Thumb spelling.
    """

    r4 = cento.Restores("r4", at=0x0)
    r5 = cento.Restores("r5", at=0x4)
    pc = cento.Restores(Role.PC, at=0x8)
    needs = {"r5": "the function blx calls", "r4": "-> r0, its one argument"}


def build(*, at: int) -> cento.Layout:
    layout = cento.Layout()  # little-endian by default -- the MK-3 rides it, same as the MK-4
    layout.bind("rec_va", REC_VA, source="fiction: buffer address leaked by a chatty error path")
    rec = layout.region("rec", base="rec_va", max_size=0x40)
    run = rec.chain("maint", at=at, abi=ARM32, arm=False)  # thrown as one record; no staged delivery to gate
    run.enter(Epilogue)  # the smashed function returns through its own epilogue
    run.hop(LoadPair, "load_call")
    # blx is a call: volatiles (r0-r3, r12, r14) die across it. r4/r5 are AAPCS callee-saved --
    # the reason the tail rides THEM -- so the seats below survive the Carry.Clobbered judgment.
    unlock = run.hop(CallTail, "unlock", carry=cento.Carry.Clobbered)
    unlock.r5 = SVC_UNLOCK  # seats land in load_call's frame slots: the cells that feed this hop
    unlock.r4 = MAINT_TOKEN  # -> r0: the one argument svc_unlock takes
    run.finish_in_kernel(pc=CONSOLE_LOOP)  # terminal: the console loop never returns
    return layout


def show_gadgets(*gadgets: type[cento.Gadget]) -> None:
    print("gadgets:")
    for gadget in gadgets:
        print(f"  {gadget.disasm()}")  # the docstring's disassembly, keyed on the gadget's own entry -- the Thumb one renders odd


def show_frames(run: cento.Chain) -> None:
    # The MK-1 contrast: a PPC32 chain records over= aliasing on every frame after the first,
    # because each EXTERNAL continuation slot lives in the NEXT frame's first word. Here the
    # pc words are internal, so placement records no aliasing at all.
    for p in run.region.placements:
        print(f"  {p.name:<15}  +0x{p.offset:04x}..+0x{p.offset + p.extent:04x}  over={p.over!r}")


def main() -> bool:
    # The record header owns +0x0..+0x4; the overflow writes from +0x4, where the handler's
    # saved r4 sits. The geometry puts SP at base+0x18 when blx fires -- 8-aligned, so
    # CallTail's entry_sp_mod=0 judges green against ARM32.sp_align=8 (CHK-207).
    layout = build(at=0x4)
    run = layout.chains["maint"]
    show_gadgets(Epilogue, LoadPair, CallTail)

    print("\nnarrate(): the hop-by-hop story")
    print(run.narrate())

    print("\nplacements: pop {..., pc} is internal, so the three frames abut -- over=() everywhere")
    show_frames(run)

    print("\nseal(), then check(): every need fed, SP % 8 == 0 at the call boundary")
    run.seal()
    report = layout.check()
    print(report.render())
    if report.errors:
        print("check() found errors; the chain above is not safe to throw")
        return False

    print("\nthe final image: three frames of little-endian words (unset r4/r5 slots ride the fill)")
    print(layout.hexdump())
    print(f"(0x{FW_CALLTAIL | 1:07x} staged at +0x14: the Thumb entry, bit 0 kept -- the CPU consumes it at the branch)")
    return True


if __name__ == "__main__":
    if not main():
        sys.exit(1)
