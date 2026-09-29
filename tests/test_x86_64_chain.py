# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""x86-64 chain surface: string register slots, the SysV ABI split, and the alignment contract.

String slots: Restores("rdi")/needs on plain names resolve through hop.rdi seat/read sugar,
with typo refusal intact. ABI-aware Carry.Clobbered spares declared-nonvolatile string slots
and degrades volatile ones (a call gadget destroys rdi; reusing it downstream is CHK-201).
Alignment (CHK-207): a gadget's entry_sp_mod judged against abi.sp_align -- an error when the
region base's alignment makes the violation provable, a warning while it is undeclared.
sp_pivot: a leave;ret-style pointer frame moves the SP cursor past itself, so mixed
pivot-then-SP-run chains lay out contiguously. spec_dict stays hash-stable for gadgets that
declare none of this.
"""

from __future__ import annotations

import pytest

import cento
import cento.errors as errors
import cento.gadget as gadget
import cento.machine as machine
from cento.abi.x86_64 import CALL_ENTRY_SP_MOD
from cento.abi.x86_64 import X86_64

Reg = machine.Reg

POP_RDI = 0x7F000002A3E5
LEAVE_RET = 0x7F000004B9D1
RET_ALIGN = 0x7F0000029CD6
SYSTEM = 0x7F0000052290


class PopRdi(gadget.Gadget, entry=POP_RDI, stride=0x10):
    """0x7f000002a3e5: pop rdi; ret"""

    rdi = gadget.Restores("rdi", at=0x0, width=cento.u64)
    pc = gadget.Restores(Reg.PC, at=0x8, width=cento.u64)


class RetAlign(gadget.Gadget, entry=RET_ALIGN, stride=0x8):
    """0x7f0000029cd6: ret"""

    pc = gadget.Restores(Reg.PC, at=0x0, width=cento.u64)


class SystemCall(gadget.Gadget, entry=SYSTEM, stride=0x8, entry_sp_mod=CALL_ENTRY_SP_MOD):
    """0x7f0000052290: system()"""

    pc = gadget.Restores(Reg.PC, at=0x0, width=cento.u64)
    needs = {"rdi": "the command string"}


class LeaveRet(gadget.Gadget, entry=LEAVE_RET, frame_base="rbp", sp_pivot=True, stride=0x10):
    """0x7f000004b9d1: leave; ret"""

    rbp = gadget.Restores("rbp", at=0x0, width=cento.u64)
    pc = gadget.Restores(Reg.PC, at=0x8, width=cento.u64)
    needs = {"rbp": "the frame this pivots into"}


def _stack_chain() -> tuple[cento.Layout, cento.Chain]:
    layout = cento.Layout(endian="little")
    stack = layout.region("stack", max_size=0x100)
    run = stack.chain("rop", at=0x0, abi=X86_64, arm=False)
    return layout, run


def test_string_slots_seat_and_fold() -> None:
    layout, run = _stack_chain()
    ent = run.enter(PopRdi)
    ent.rdi = 0x1337  # string slot through the same sugar as Reg slots
    run.hop(SystemCall, "shell")
    run.finished = True
    assert ent.frame.rdi.read() == 0x1337
    st = run.state_at("shell")["rdi"]
    assert st.kind == "seat" and st.fed_by.name == "stack.rop.enter.rdi"
    assert layout.image("stack", final=False)[0x8:0x10] == SYSTEM.to_bytes(8, "little")  # _wire_pc threaded the entry


def test_typoed_slot_refuses_with_hints() -> None:
    _layout, run = _stack_chain()
    ent = run.enter(PopRdi)
    with pytest.raises(AttributeError, match="no machine slot 'rdx_'"):
        ent.rdx_ = 1  # the typo is the test: unknown names refuse instead of becoming silent slots


def test_string_slot_wins_over_the_ppc_enum_spelling() -> None:
    """hop.r8 on an x86-64 chain must seat the STRING slot "r8" the gadget's transfer keys --
    not PPC Reg.R8, which _REG_BY_ATTR used to resolve first (the latent mis-keying)."""

    class PopR8(gadget.Gadget, entry=0x7F0000003000, stride=0x10):
        """0x7f0000003000: pop r8; ret"""

        r8 = gadget.Restores("r8", at=0x0, width=cento.u64)
        pc = gadget.Restores(Reg.PC, at=0x8, width=cento.u64)

    layout, run = _stack_chain()
    ent = run.enter(PopR8)
    ent.r8 = 0x4242
    run.finished = True
    assert ent.frame.r8.read() == 0x4242  # the seat landed in the frame cell
    st = run.state_at("enter")["r8"]
    assert st.kind == "seat"  # keyed by the string slot, not Reg.R8


def test_abi_clobbered_spares_nonvolatile_string_slots() -> None:
    class CallGadget(gadget.Gadget, entry=0x7F0000010000, stride=0x8):
        """0x7f0000010000: call-through (clobbers volatiles)"""

        pc = gadget.Restores(Reg.PC, at=0x0, width=cento.u64)

    class PopRbp(gadget.Gadget, entry=0x7F0000020000, stride=0x10):
        """0x7f0000020000: pop rbp; ret"""

        rbp = gadget.Restores("rbp", at=0x0, width=cento.u64)
        pc = gadget.Restores(Reg.PC, at=0x8, width=cento.u64)

    _layout, run = _stack_chain()
    ent = run.enter(PopRdi)
    ent.rdi = 4
    prb = run.hop(PopRbp, "keeper")
    prb.rbp = 0x5000
    run.hop(CallGadget, "call", carry=machine.Carry.Clobbered)
    tail = run.hop(SystemCall, "after")
    run.finished = True
    assert tail.rbp.state.kind == "seat"  # nonvolatile string slot: spared by the ABI split
    assert tail.rdi.state.kind == "clobbered"  # volatile: the call destroyed it
    errs, _warns = run.issues()
    assert any(i.code == "CHK-201" and "rdi" in i.msg for i in errs)  # SystemCall's need is no longer fed


def test_chk207_alignment_error_warning_and_fix() -> None:
    # Provable violation: base bound 16-aligned, system's frame at +0x10 -> SP % 16 == 0, wants 8.
    layout, run = _stack_chain()
    layout.bind("stack_base", 0x7FFDDEAD0000, source="test")
    ent = run.enter(PopRdi)
    ent.rdi = 0x404000
    run.hop(SystemCall, "shell")
    run.finished = True
    errs, _warns = run.issues()
    bad = [i for i in errs if i.code == "CHK-207"]
    assert len(bad) == 1 and "uses entry_sp_mod=8" in bad[0].msg and "requires entry_sp_mod=0" in bad[0].msg

    # Undeclared base alignment: the same chain without a bind or expect_sym is a warning, not a guess.
    layout2, run2 = _stack_chain()
    ent2 = run2.enter(PopRdi)
    ent2.rdi = 0x404000
    run2.hop(SystemCall, "shell")
    run2.finished = True
    errs2, warns2 = run2.issues()
    assert not [i for i in errs2 if i.code == "CHK-207"]
    assert any(i.code == "CHK-207" and "undeclared" in i.msg for i in warns2)

    # The fix idiom: one ret-align hop restores SP % 16 == 8 at system's entry.
    layout3, run3 = _stack_chain()
    layout3.expect_sym("stack_base", align=0x10)  # declared alignment is basis enough
    ent3 = run3.enter(PopRdi)
    ent3.rdi = 0x404000
    run3.hop(RetAlign, "align")
    run3.hop(SystemCall, "shell")
    run3.finished = True
    errs3, warns3 = run3.issues()
    assert not [i for i in (*errs3, *warns3) if i.code == "CHK-207"]


def test_sp_pivot_moves_the_cursor_past_the_pointer_frame() -> None:
    layout = cento.Layout(endian="little")
    slab = layout.region("slab", max_size=0x100)
    run = slab.chain("frames", at=0x10, abi=X86_64, arm=False)
    ent = run.enter(LeaveRet)  # pointer frame: alloc'd at 0x0; sp_pivot moves the cursor to 0x10
    assert ent.frame.offset == 0x0 and run.cursor == 0x10
    prd = run.hop(PopRdi, "arg")  # SP run continues exactly past the pivot frame
    assert prd.frame.offset == 0x10
    piv = run.hop(LeaveRet, "next")  # second pivot: alloc'd past everything, cursor jumps again
    assert piv.frame.offset == 0x20 and run.cursor == 0x30
    st = run.state_at("next")["rbp"]
    assert st.kind == "seat"  # the pivot's frame pointer rides the rbp seat LeaveRet restores


def test_pivot_writes_next_frame_address_upstream() -> None:
    layout = cento.Layout(endian="little")
    layout.bind("slab_base", 0x556E00000000, source="test")
    slab = layout.region("slab", max_size=0x100)
    run = slab.chain("frames", at=0x10, abi=X86_64, arm=False)
    ent = run.enter(LeaveRet)
    run.hop(PopRdi, "arg")
    run.hop(LeaveRet, "next")
    assert ent.frame.rbp.read() == 0x556E00000020  # the next pivot frame's absolute address, linked by the machinery


def test_gadget_declaration_guards() -> None:
    with pytest.raises(errors.ChainError, match="sp_pivot=True is a pointer-frame fact"):

        class BadPivot(gadget.Gadget, entry=0x1000, stride=0x8, sp_pivot=True):
            """0x1000: ret"""

            pc = gadget.Restores(Reg.PC, at=0x0, width=cento.u64)

    with pytest.raises(errors.ChainError, match="entry_sp_mod on a pointer frame"):

        class BadMod(gadget.Gadget, entry=0x1000, frame_base="rbp", stride=0x10, entry_sp_mod=8):
            """0x1000: leave; ret"""

            rbp = gadget.Restores("rbp", at=0x0, width=cento.u64)
            pc = gadget.Restores(Reg.PC, at=0x8, width=cento.u64)


def test_spec_dict_is_hash_stable_for_undeclared_gadgets() -> None:
    class Plain(gadget.Gadget, entry=0x2000, stride=0x10):
        """0x2000: pop rdi; ret"""

        rdi = gadget.Restores("rdi", at=0x0, width=cento.u64)
        pc = gadget.Restores(Reg.PC, at=0x8, width=cento.u64)

    spec = gadget.spec_dict(Plain)
    assert "entry_sp_mod" not in spec and "sp_pivot" not in spec  # absent unless declared: checked-in catalog hashes stay valid
    spec2 = gadget.spec_dict(SystemCall)
    assert spec2["entry_sp_mod"] == 8
    spec3 = gadget.spec_dict(LeaveRet)
    assert spec3["sp_pivot"] is True and spec3["frame_base"] == "rbp"


def test_endian_mismatch_refuses_at_chain() -> None:
    layout = cento.Layout(endian="big")  # a big-endian layout meeting a little-endian ABI: the mismatch under test
    stack = layout.region("stack", max_size=0x100)
    with pytest.raises(errors.ChainError, match="little-endian but the layout is big-endian"):
        stack.chain("rop", at=0x0, abi=X86_64, arm=False)


def test_abi_endian_facts() -> None:
    from cento.abi.ppc32 import PPC32

    assert X86_64.endian == "little" and PPC32.endian == "big"
    bare = machine.AbiSpec(name="bare", volatile=frozenset(), nonvolatile=frozenset())
    assert bare.endian is None  # no fact declared: never judged (back-compat for third-party specs)
    layout = cento.Layout(endian="big")  # big-endian layout + endian-free abi: no refusal
    layout.region("r", max_size=0x40).chain("c", at=0x0, abi=bare, arm=False)
