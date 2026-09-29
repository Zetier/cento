# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""cento -- borrowed fragments, arranged deliberately, checked as a whole.

Example 9 -- a forged call stack in the heap

The README opens with "forged call stacks in the heap"; this is that claim, literal. The Meridian
MK-1 hijack primitive grants PC control with r31 pointing into a heap slab we filled -- not the
stack -- so the payload IS a call stack (real PPC32, like ex02): a context block, then three syscall-tail frames laid back
to back, each one a return that never happened. demo_syscall #4 maps a scratch page, #7 mints a
capability the kernel writes into the very slot the next frame reloads R30 from, #9 spends it.
The fold proves each hop's inputs, the mid-chain-alloc trap is demonstrated by name, and the
hexdump shows the forged frames as bytes.

Run: python3 examples/ex09/ex09_fake_frame_chain.py   (transcript.txt is this run, verbatim)
Next: ex10_provenance
"""

from __future__ import annotations

import sys

import cento

Reg = cento.Reg

CTX_RESTORE = 0x40001000  # epilogue: restores pc/sp/r30/r31 from the block r31 points at
SYS_TAIL = 0x40002000  # r3=r30; r4=r31; call demo_syscall; pop 0x40 frame; pc from caller frame
HEAP_VA = 0x40208000  # fiction: MPKT reassembly slab; a leak told us where it landed


class CtxRestore(cento.Gadget, entry=CTX_RESTORE, stride=0x58, frame_base=Reg.R31):
    """0x40001000: lwz r0, 0x0(r31); mtlr r0; lwz r1, 0x4(r31); lwz r30, 0x50(r31); lwz r31, 0x54(r31); blr

    Pointer-frame entry (jmp_buf shape): the hijack primitive hands us r31 = &ctx.
    On this run &ctx is HEAP -- the context block and every frame below it share one slab.
    """

    pc = cento.Restores(Reg.PC, at=0x00)
    sp = cento.Restores(Reg.SP, at=0x04)
    r30 = cento.Restores(Reg.R30, at=0x50)
    r31 = cento.Restores(Reg.R31, at=0x54)
    needs = {Reg.R31: "context-block pointer (the hijack primitive)"}


class SysTail(cento.Gadget, entry=SYS_TAIL, stride=0x40, reentry_safe=True):
    """0x40002000: mr r3, r30; mr r4, r31; bl demo_syscall; lwz r30, 0x38(r1); lwz r31, 0x3c(r1); lwz r0, 0x44(r1); mtlr r0; addi r1, r1, 0x40; blr

    ex02's RetTail: same bytes, same frame shape, same demo_syscall ABI (the kernel
    dispatches on args->op; r3 carries the capability word). New here: the kernel
    write is declared as an explicit Effect instead of ex02's field-assignment shorthand.
    """

    r30 = cento.Restores(Reg.R30, at=0x38)
    r31 = cento.Restores(Reg.R31, at=0x3C)
    pc = cento.Restores(Reg.PC, at=0x44, external=True)
    needs = {Reg.R30: "capability word -> r3 (0 = unprivileged)", Reg.R31: "arg-block pointer -> r4"}


class ArgBlock(cento.View, size=0x10):
    op: cento.u32
    a0: cento.u32
    out: cento.u32
    end: cento.u32


def build() -> cento.Layout:
    demo_halt = 0x40003000  # kernel-side terminal: park the thread, never return
    sys_map_scratch = 0x04  # args: a0 = page to map
    sys_mint_token = 0x07  # args: out = where the kernel writes the fresh capability
    sys_spend_token = 0x09  # refuses unless r3 carries a valid capability
    scratch_page = 0x40204000  # what #4 maps
    doorbell = 0x40031337  # what #9 unlocks (the fictional MMIO doorbell, as in ex02)

    layout = cento.Layout(endian="big")  # the MK-1 is big-endian PPC32
    layout.bind("heap_va", HEAP_VA, source="fiction: leaked MPKT reassembly slab")
    heap = layout.region("heap", base="heap_va", max_size=0x200)

    # The forged stack: ctx block at heap+0, SP frames back to back from heap+0x60.
    # When the hijack fires, SP walks these bytes exactly as if three calls had returned.
    run = heap.chain("stack", at=0x60)
    entry = run.enter(CtxRestore)

    mapper = run.hop(SysTail, "map_scratch")
    entry.frame.sp = mapper.frame  # ctx.sp -> first forged frame (handles coerce to their address)
    mapper.r30 = 0  # unprivileged: #4 takes no capability

    minter = run.hop(SysTail, "mint_token")
    minter.r30 = 0  # unprivileged: #7 is the call that MINTS the capability
    # Geometry with a purpose: mint_args.out (below) aims demo_syscall #7's result at
    # &minter.frame + 0x38 -- this frame's OWN r30 restore slot, the exact cell the NEXT
    # hop reloads R30 from. Declaring that kernel write as an Effect supplying a
    # Writeback keeps the slot unstaged (region fill stands in) and lets the fold thread
    # the runtime value into spend_token's R30.
    mint_eff = cento.Effect("mint_result", controls={minter.frame.r30: cento.Writeback("session_token")})
    minter.add_effect(mint_eff)

    spender = run.hop(SysTail, "spend_token")
    # spender.r30 is intentionally NOT seated: #9's capability is fed by the writeback.
    # Say so out loud -- if the plumbing ever drifts, seal() fails CHK-203 by name.
    run.expect(spender.r30, from_=mint_eff.writebacks.session_token)

    run.finish_in_kernel(pc=demo_halt)  # terminal: the last frame's pc slot parks in the kernel

    # Arg blocks are alloc'd only AFTER the chain is finished. alloc() bumps past every
    # placement KNOWN SO FAR, but the chain cursor keeps marching -- an arg block alloc'd
    # mid-chain lands exactly under the NEXT hop's frame. show_the_trap() takes that
    # wrong turn on a throwaway layout so check() can name it.
    map_args = heap.alloc(ArgBlock, "map_args")
    map_args.op = sys_map_scratch
    map_args.a0 = scratch_page
    mapper.r31 = map_args  # seat: lands in ctx.r31, where the first tail reads it

    targs = heap.alloc(ArgBlock, "mint_args")
    targs.op = sys_mint_token
    targs.out = minter.frame.r30  # cell handle -> address: the kernel's write lands in the frame
    minter.r31 = targs

    spend_args = heap.alloc(ArgBlock, "spend_args")
    spend_args.op = sys_spend_token
    spend_args.a0 = doorbell
    spender.r31 = spend_args
    return layout


def show_the_trap() -> None:
    # The same build, wrong order: one arg block alloc'd mid-chain. Both placements are
    # individually legal, so nothing raises at construction; check() judges the whole
    # layout and reports the undeclared collision by name.
    layout = cento.Layout(endian="big")  # the MK-1 is big-endian PPC32
    layout.bind("heap_va", HEAP_VA, source="fiction: leaked MPKT reassembly slab")
    heap = layout.region("heap", base="heap_va", max_size=0x200)
    run = heap.chain("stack", at=0x60)
    entry = run.enter(CtxRestore)
    mapper = run.hop(SysTail, "map_scratch")
    entry.frame.sp = mapper.frame
    map_args = heap.alloc(ArgBlock, "map_args")  # mid-chain: bumps to heap+0xa8, inside the cursor's path
    mapper.r31 = map_args
    run.hop(SysTail, "mint_token")  # frame placed at heap+0xa0..0xe0: right on top of map_args
    for issue in layout.check().errors:
        print(f"  {issue.code} [{', '.join(issue.subjects)}]: {issue.msg}")


def show_gadgets(*gadgets: type[cento.Gadget]) -> None:
    # ropper-style catalog: each gadget's first docstring line is its disassembly,
    # keyed here on the class's own entry so the two cannot drift apart silently
    print("gadgets:")
    for gadget in gadgets:
        print(f"  {gadget.disasm()}")  # the docstring's disassembly line, keyed on the gadget's own entry; ropper-colored on a TTY


def main() -> bool:
    layout = build()
    run = layout.chains["stack"]
    show_gadgets(CtxRestore, SysTail)

    print("narrate(): three calls that never happened, one story")
    print(run.narrate())

    print("the fold, hop by hop: where every input comes from")
    for hop_name in ("map_scratch", "mint_token", "spend_token"):
        st = run.state_at(hop_name)
        r30, r31 = st[Reg.R30].fed_by, st[Reg.R31].fed_by
        print(f"  {hop_name}: R30 <- {r30.kind}:{r30.name}; R31 <- {r31.kind}:{r31.name}")
    print(layout.explain("heap.stack.mint_token.r30"))
    run.seal()
    print("seal(): green -- every hop's inputs accounted for")

    print("the trap NOT taken: alloc an arg block mid-chain and check() names it")
    show_the_trap()

    print("the forged call stack, as bytes: every word attributed ...")
    print(layout.hexdump())

    print("... and flat: the frames at heap+0x60..+0x130, a stack that never was")
    image = layout.image("heap")
    for off in range(0x60, 0x130, 16):
        row = image[off : off + 16]
        words = " ".join(row[i : i + 4].hex() for i in range(0, 16, 4))
        print(f"  0x{HEAP_VA + off:08x}  {words}")
    print("the fill word at 0x402080d8 is the mint slot: the kernel writes the token there at runtime")
    return True


if __name__ == "__main__":
    if not main():
        sys.exit(1)
