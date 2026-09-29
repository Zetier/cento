# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""cento -- borrowed fragments, arranged deliberately, checked as a whole.

Example 2 -- a checked gadget chain

ex01 pwned mkcfg, the MK-1's x86 configurator; this is the device itself -- PowerPC-32,
big-endian, and every gadget listing below is real PPC32 -- and the moves are the same,
because layouts do not care what they aim at.

The Meridian MK-1 (a fictional PPC32 MCU running DemoRTOS) has a hijackable
context-restore epilogue and a syscall-return tail. We declare both as Gadgets -- one declaration
yields the frame layout AND the register transfer -- then fold a two-call chain through them:
mint a boot token with demo_syscall op 0x7, spend it with op 0x9. The kernel dispatches on the
arg block's op word; r3 carries the capability -- zero to mint, the minted token itself to
spend. The kernel returns the token through the arg block's out-pointer, into a frame slot we
never stage (a Writeback cell); the fold proves the next hop's R30 is fed by exactly that write.

Imported with `from cento import *`: the facade's __all__ is closed, so the star import is exact
and the declarations read bare -- Gadget, Restores, View, u32.

Run: python3 examples/ex02/ex02_toy_chain.py   (transcript.txt is this run, verbatim)
Next: ex03_local_ret2win
"""
# ruff: noqa: F403, F405 -- the star import below is part of the lesson

from __future__ import annotations

import sys

from cento import *

CTX_RESTORE = 0x40001000  # epilogue: restores pc/sp/r30/r31 from the block r31 points at
RET_TAIL = 0x40002000  # r3=r30; r4=r31; call demo_syscall; pop 0x40 frame; pc from caller frame
DEMO_HALT = 0x40003000  # kernel-side terminal: park the thread, never return
SCRATCH_VA = 0x40200000  # fiction: the DemoRTOS scratch page our primitive can reach
DOORBELL = 0x40031337  # fictional MMIO doorbell (the maintenance-port unlock target)
SYS_MINT = 0x07  # demo_syscall op: mint one boot token (args.out says where the kernel writes it)
SYS_SPEND = 0x09  # demo_syscall op: spend the token presented in r3 (args.a0 says on what)


class CtxRestore(Gadget, entry=CTX_RESTORE, stride=0x58, frame_base=Reg.R31):
    """0x40001000: lwz r0, 0x0(r31); mtlr r0; lwz r1, 0x4(r31); lwz r30, 0x50(r31); lwz r31, 0x54(r31); blr

    Pointer-frame entry (jmp_buf shape): the hijack primitive hands us r31 = &ctx.
    """

    pc = Restores(Reg.PC, at=0x00)
    sp = Restores(Reg.SP, at=0x04)
    r30 = Restores(Reg.R30, at=0x50)
    r31 = Restores(Reg.R31, at=0x54)
    needs = {Reg.R31: "context-block pointer (the hijack primitive)"}


class RetTail(Gadget, entry=RET_TAIL, stride=0x40, reentry_safe=True):
    """0x40002000: mr r3, r30; mr r4, r31; bl demo_syscall; lwz r30, 0x38(r1); lwz r31, 0x3c(r1); lwz r0, 0x44(r1); mtlr r0; addi r1, r1, 0x40; blr

    SP-frame syscall tail; pc slot at +0x44 is EXTERNAL (it lives in the next frame).
    """

    r30 = Restores(Reg.R30, at=0x38)
    r31 = Restores(Reg.R31, at=0x3C)
    pc = Restores(Reg.PC, at=0x44, external=True)
    needs = {Reg.R30: "capability word -> r3 (0 = unprivileged; the minted token to spend)", Reg.R31: "arg-block pointer -> r4"}


class ArgBlock(View, size=0x10):
    op: u32
    a0: u32
    out: u32
    end: u32


def build() -> Layout:
    layout = Layout(endian="big")  # the MK-1 is big-endian PPC32
    layout.bind("scratch_va", SCRATCH_VA, source="fiction: DemoRTOS scratch page")
    scratch = layout.region("scratch", base="scratch_va", max_size=0x400)

    chain = scratch.chain("demo", at=0x100)  # SP frames start at scratch+0x100
    entry = chain.enter(CtxRestore)  # ctx auto-placed; ctx.pc auto-wired to hop 1 and ARM-marked

    mint = chain.hop(RetTail, "mint_token")
    entry.frame.sp = mint.frame  # ctx.sp -> first SP frame (handles coerce to their address)
    mint.r30 = 0  # unprivileged: minting takes no capability; the seat still lands in the UPSTREAM cell (ctx.r30), where hop 1 reads it
    # The mint call returns its token through args.out -- which we aim (below, once the arg block
    # exists) at &frame + 0x38: this frame's OWN r30 restore slot. Declaring that cell a Writeback
    # (never staged, kernel-written) lets the fold thread the runtime value into the NEXT hop's R30.
    mint.frame.r30 = Writeback("boot_token")

    spend = chain.hop(RetTail, "spend_token")
    # spend.r30 is intentionally NOT seated: it is fed by the boot_token writeback.

    chain.finish_in_kernel(pc=DEMO_HALT)  # terminal: execution parks in the kernel, no frame placed

    # Arg blocks are auto-placed AFTER the chain is finished: alloc() bumps past every existing
    # placement, so allocating mid-chain would land a block under the NEXT hop's frame (CHK-001).
    mint_args = scratch.alloc(ArgBlock, "mint_args")
    mint_args.op = SYS_MINT  # the kernel dispatches on args->op
    mint_args.out = mint.frame.r30  # the kernel writes the token through args.out -- aimed at the frame's own r30 restore slot
    mint.r31 = mint_args
    spend_args = scratch.alloc(ArgBlock, "spend_args")
    spend_args.op = SYS_SPEND  # spend the presented token: unlock the maintenance port
    spend_args.a0 = DOORBELL
    spend.r31 = spend_args
    return layout


def show_gadgets(*gadgets: type[Gadget]) -> None:
    print("gadgets:")
    for gadget in gadgets:
        print(f"  {gadget.disasm()}")  # the docstring's disassembly line, keyed on the gadget's own entry; ropper-colored on a TTY


def main() -> bool:
    layout = build()
    chain = layout.chains["demo"]
    show_gadgets(CtxRestore, RetTail)
    print("\nnarrate(): the hop-by-hop story")
    print(chain.narrate())

    print("\ncheck(): the whole layout, judged")
    report = layout.check()
    print(report.render())
    if report.errors:
        print("check() found errors; the chain above is not safe to throw")  # e.g. an edit broke a placement, a seat, or the writeback feed
        return False

    print("\nexplain(): what is this byte?")
    print(layout.explain("scratch.demo.mint_token.r30"))
    fed = chain.state_at("spend_token")[Reg.R30].fed_by
    print(f"spend_token R30 fed by: {fed.kind}:{fed.name}")
    return True


if __name__ == "__main__":
    if not main():
        sys.exit(1)
