# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""cento -- borrowed fragments, arranged deliberately, checked as a whole.

Example 12 -- an AArch64 chain: ldp/ret frames and the hardware alignment rule

The Meridian MK-4 is the family's AArch64 generation: a 64-bit management controller whose
diagnostic service parses maintenance requests into a leaked buffer. The hijack primitive is a
forged task control block -- the RTOS context switch restores SP from it, so WE aim the stack
pointer at bytes we staged. Every gadget listing below is real A64 shape: ldp/ret epilogues
(x30 is the return register; ret never touches the stack), the csu-style call tail, string
register slots ("x19", "x20") declared width=cento.u64. The alignment rule rides along: on
AArch64, SP % 16 == 0 is a HARDWARE contract (SP alignment checking faults ANY SP-based access
while SP is misaligned), so every SP-run gadget declares entry_sp_mod=0 -- and the fix for a
misaligned chain is geometry, not a ret gadget, because ret does not pop.

Run: python3 examples/ex12/ex12_aarch64_chain.py   (transcript.txt is this run, verbatim)
Next: ex13_arm32_chain
"""

from __future__ import annotations

import sys

import cento
from cento.abi.aarch64 import AARCH64

Role = cento.Role

FW_EPILOGUE = 0x400C48  # the diag handler's own epilogue: the forged TCB aims PC here
FW_LOADPAIR = 0x401B70  # loads the callee-saved pair the call tail consumes
FW_CALLTAIL = 0x402D98  # csu-style: call x19 with x0 = x20, then pop the next frame
SVC_UNLOCK = 0x403E44  # firmware: unlock the maintenance port when x0 carries a valid token
CONSOLE_LOOP = 0x404F00  # firmware: the maintenance console loop -- never returns
MAINT_TOKEN = 0x00C0FFEE  # fiction: the MK-4's maintenance unlock token
REQ_VA = 0xE0801000  # fiction: the leaked diag request buffer (page-mapped, so 16-aligned)


# On AArch64 every one of these declares entry_sp_mod=0, not just the call: SP alignment
# checking is a hardware fact (judged against AARCH64.sp_align=16, CHK-207), and every gadget's
# frame traffic is SP-based loads -- the fault fires at the first SP-based access if
# SP % 16 != 0 (for CallTail that is its callee's own stp, before the tail's ldp). Contrast
# x86-64, where only the call boundary cares (CALL_ENTRY_SP_MOD=8, the movaps rule).
class Epilogue(cento.Gadget, entry=FW_EPILOGUE, stride=0x10, entry_sp_mod=0):
    """0x400c48: ldp x29, x30, [sp], #0x10; ret

    A function epilogue, the entry hop: the forged TCB restores SP to our bytes and PC to
    here; the ldp pops the first frame and ret branches to whatever it loaded into x30.
    """

    x29 = cento.Restores("x29", at=0x0, width=cento.u64)  # the frame-pointer slot the ldp drags along
    pc = cento.Restores(Role.PC, at=0x8, width=cento.u64)  # the x30 slot the ldp loads before ret


class LoadPair(cento.Gadget, entry=FW_LOADPAIR, stride=0x20, entry_sp_mod=0):
    """0x401b70: ldp x19, x20, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret

    The loader: fills the callee-saved pair the call tail consumes, then pops on.
    """

    x29 = cento.Restores("x29", at=0x00, width=cento.u64)
    pc = cento.Restores(Role.PC, at=0x08, width=cento.u64)
    x19 = cento.Restores("x19", at=0x10, width=cento.u64)
    x20 = cento.Restores("x20", at=0x18, width=cento.u64)


class CallTail(cento.Gadget, entry=FW_CALLTAIL, stride=0x20, entry_sp_mod=0):
    """0x402d98: mov x0, x20; blr x19; ldp x19, x20, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret

    The call-shaped gadget: blr calls x19 with x0 = x20, and its callee needs SP 16-aligned
    twice over -- AAPCS64 pins the public interface, and the callee's own stp faults first.
    """

    x29 = cento.Restores("x29", at=0x00, width=cento.u64)
    pc = cento.Restores(Role.PC, at=0x08, width=cento.u64)
    x19 = cento.Restores("x19", at=0x10, width=cento.u64)
    x20 = cento.Restores("x20", at=0x18, width=cento.u64)
    needs = {"x19": "the function blr calls", "x20": "-> x0, its one argument"}


def build(*, at: int) -> cento.Layout:
    layout = cento.Layout()  # endian defaults to little now -- the MK-4 rides the new default (the MK-1 declared endian="big")
    layout.bind("req_va", REQ_VA, source="fiction: leaked diag request buffer")
    req = layout.region("req", base="req_va", max_size=0x80)
    run = req.chain("maint", at=at, abi=AARCH64, arm=False)  # the trigger is the forged TCB, not a buffer word
    run.enter(Epilogue)  # the context switch hands us SP; the epilogue pops the first frame
    run.hop(LoadPair, "load_call")
    # blr is a call: volatiles die across it. x19/x20 are AAPCS64 callee-saved -- the reason
    # the csu idiom rides THEM -- so the seats below survive the Carry.Clobbered judgment.
    unlock = run.hop(CallTail, "unlock", carry=cento.Carry.Clobbered)
    unlock.x19 = SVC_UNLOCK  # seats land in load_call's frame slots: the cells that feed this hop
    unlock.x20 = MAINT_TOKEN  # -> x0: the one argument svc_unlock takes
    run.finish_in_kernel(pc=CONSOLE_LOOP)  # terminal: the console loop never returns
    return layout


def show_gadgets(*gadgets: type[cento.Gadget]) -> None:
    print("gadgets:")
    for gadget in gadgets:
        print(f"  {gadget.disasm()}")  # the docstring's disassembly line, keyed on the gadget's own entry; ropper-colored on a TTY


def show_the_fault() -> None:
    # The x86-64 instinct: start the frames at +0x8, the first byte we control -- why waste
    # pad? On x86-64 a misaligned chain limps until a movaps deep inside libc; on AArch64 the
    # very first `ldp ..., [sp]` is a hardware SP-alignment fault. Same build, aimed 8 low:
    layout = build(at=0x8)
    for issue in layout.check().errors:
        print(f"  {issue.code} [{', '.join(issue.subjects)}]: {issue.msg}")


def main() -> bool:
    # The request header owns bytes +0x0..+0x8; ours start at +0x8. The forged TCB aims SP at
    # +0x10 -- the first ALIGNED byte we control. Eight bytes of pad are AArch64's whole align
    # move: no A64 gadget shifts SP by 8 (every real frame is a 16-multiple; ret pops nothing),
    # so alignment is decided once, where you aim SP -- geometry, not a ret-align hop.
    layout = build(at=0x10)
    run = layout.chains["maint"]
    show_gadgets(Epilogue, LoadPair, CallTail)

    print("\nnarrate(): the hop-by-hop story")
    print(run.narrate())

    print("\nseal(), then check(): every need fed, SP % 16 == 0 at every gadget entry")
    run.seal()
    report = layout.check()
    print(report.render())
    if report.errors:
        print("check() found errors; the chain above is not safe to throw")
        return False

    print("\nthe final image: three frames of little-endian qwords (unset x29 slots ride the fill)")
    print(layout.hexdump())
    print("(0x401b70 staged as 701b40...: the little-endian default at work -- no endian= was declared)")

    print("\nthe same chain aimed at +0x8 -- misaligned by the width of one pad word:")
    show_the_fault()
    print("not a movaps ten calls deep: on AArch64 the FIRST SP-based access faults in")
    print("hardware, so every hop refuses -- realign the chain, not the gadget list")
    return True


if __name__ == "__main__":
    if not main():
        sys.exit(1)
