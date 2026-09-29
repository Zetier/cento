# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""End-to-end rides.

A canonical-example-shaped chain e2e plus a bug-class corpus and a seeded fold property test;
chain/machine/catalog rides (arm knob, per-hop carry, ABI-aware Clobbered, freezing,
finish_in_kernel, crosscheck scope); alloc's external-span reservation; golden bytes,
determinism, a perf budget, and a target-less wire micro-example.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
import random
import time

import pytest

import cento
import cento.abi.ppc32 as ppc32
import cento.catalog as catalog_mod
import cento.cells as cells
import cento.chain
import cento.emit
import cento.errors as errors
import cento.gadget as gadget
import cento.machine as machine
import cento.views as views

Reg = machine.Reg
FIXTURE = str(pathlib.Path(__file__).parent / "fixtures" / "catalog_v2.json")

# -- canonical-example chain e2e + bug-class corpus -----------------------------


class SyscallTail(gadget.Gadget, entry=0x40002000, stride=0xB0, reentry_safe=True):
    """0x40002000: mr r3, r30; mr r4, r31; li r5, 0; bl <sc; blr>; cmpwi r3, 0; blt -0x14;
    lwz r0, 0xb4(r1); mtlr r0; lwz r30, 0xa8(r1); lwz r31, 0xac(r1); addi r1, r1, 0xb0; blr"""

    r30 = gadget.Restores(Reg.R30, at=0xA8)
    r31 = gadget.Restores(Reg.R31, at=0xAC)
    pc = gadget.Restores(Reg.PC, at=0xB4, external=True)
    needs = {Reg.R30: "syscall object handle -> r3", Reg.R31: "desc array pointer -> r4"}


class LjBypass(gadget.Gadget, entry=0x40001000, frame_base=Reg.R31):
    pc = gadget.Restores(Reg.PC, at=0x00)
    sp = gadget.Restores(Reg.SP, at=0x04)
    r30 = gadget.Restores(Reg.R30, at=0x50)
    r31 = gadget.Restores(Reg.R31, at=0x54)
    needs = {Reg.R31: "jmp_buf pointer (hijack primitive)"}


class LjRestore(gadget.Gadget, entry=0x40001800, frame_base=Reg.R31):
    pc = gadget.Restores(Reg.PC, at=0x00)
    sp = gadget.Restores(Reg.SP, at=0x04)
    needs = {Reg.R31: "recovery jmp_buf pointer"}


class Desc(views.View, size=0x10):
    dtype = views.Field(0x0, views.u32)
    val = views.Field(0x4, views.u32)
    aux = views.Field(0x8, views.u32)
    res = views.Field(0xC, views.u32)


def build_stage1() -> cento.Layout:
    """The canonical-example shape: enter -> create_task (+writeback overlay) -> kernel_write -> finish."""
    layout = cento.Layout(endian="big")  # a PPC32 exhibit: the byte asserts are big-endian
    page = layout.region("task_page", base="task_page_va", max_size=0x1000)
    run = page.chain("stage1", at=0x100)
    run.enter(LjBypass)

    create_task = run.hop(SyscallTail, "create_task")
    # Overlay geometry: frame at 0x100, r30 restore at 0x1A8. Desc at frame+0xA0 puts
    # kd.aux (offset 0x8) exactly on the restore slot AND keeps the desc extent
    # [0x1A0,0x1B0) inside this frame (no undeclared spill into the next frame).
    kd = create_task.frame.overlay(Desc, at=0xA0, name="create_desc", why="sc24 writeback lands in this frame's r30 restore")
    kd.dtype, kd.val = 0x00, 24
    create_task.r30 = 0x40
    create_task.r31 = kd
    # kd.aux: intentionally UNSET -- target Writeback (it IS the frame's r30 restore cell)
    create_task.add_effect(machine.Effect("sc24_kernel_writeback", controls={kd.aux: machine.Writeback("task_handle")}))

    kernel_write = run.hop(SyscallTail, "kernel_write")
    run.expect(kernel_write.r30, from_=create_task.writebacks.task_handle)

    run.finish(LjRestore, pc=0x40004000, sp="drain_sp")

    # alloc AFTER finish (canonical-example deviation 5): spec order would land write_desc
    # under the kernel_write frame's external pc slot and finish() would rewrite write_kd.val
    # with the continuation -- exactly the different-owner rewrite CHK-008 now catches.
    write_kd = page.alloc(Desc, "write_desc")
    write_kd.dtype, write_kd.val = 0x00, 92
    write_kd.aux = layout.sym("kernel_write_target") - page.addr(0x234)
    kernel_write.r31 = write_kd
    return layout


def test_canonical_shape_checks_clean_and_arms() -> None:
    layout = build_stage1()
    report = layout.check()
    assert [i for i in report.errors] == []
    layout.bind("task_page_va", 0x40005000, source="lifo-predict")
    layout.bind("kernel_write_target", 0x40008154, source="live-probe")
    layout.bind("drain_sp", 0x40007018, source="doc")
    result = layout.emit(cento.Backend.SPARSE)
    arm = [t for t in result.ordered if t[2] is cento.Deliver.ARM]
    assert len(arm) == 1 and result.ordered[-1] is arm[0]  # exactly one trigger cell, delivered last
    assert arm[0][1] == (0x40002000).to_bytes(4, "big")  # jb.pc -> first hop entry
    run = layout.chains["stage1"]
    assert run.state_at("kernel_write")[Reg.R30].fed_by.name == "task_handle"
    text = run.narrate()
    assert "create_task" in text and "task_handle" in text


def test_corpus_clobbered_consumption_named() -> None:
    """Bug-class: a hop clobbers a nonvolatile another hop still needs (the restore-forgotten class)."""

    class ClobbersR30(gadget.Gadget, entry=0x5000, stride=0x10):
        pc = gadget.Restores(Reg.PC, at=0x14, external=True)
        r30_kill = gadget.Clobbers(Reg.R30)  # a gadget that kills r30

    layout = cento.Layout()
    page = layout.region("p", base="pv", max_size=0x1000)
    run = page.chain("c", at=0x100)
    run.enter(LjBypass)
    run.hop(ClobbersR30, "killer")
    run.hop(SyscallTail, "victim")  # unmet needs do not raise at hop(); the fold judges
    with pytest.raises(errors.ChainError, match="R30"):
        run.seal()


def test_corpus_wrong_overlay_offset_named_by_expect() -> None:
    """Bug-class: DESC24 overlay off by 4 -> expect names the mismatch (CHK-203)."""
    layout = cento.Layout()
    page = layout.region("p", base="pv", max_size=0x1000)
    run = page.chain("c", at=0x100)
    run.enter(LjBypass)
    h1 = run.hop(SyscallTail, "h1")
    kd = h1.frame.overlay(Desc, at=0xA8, name="kd", why="WRONG offset")
    h1.add_effect(machine.Effect("wb", controls={kd.val: machine.Writeback("task_handle")}))
    h1.r30, h1.r31 = 0x40, kd
    h2 = run.hop(SyscallTail, "h2")
    h2.r31 = 0x2000  # off-by-4 ALSO made r31 the writeback slot; the conflict is judged at seal(), not at construction
    with pytest.raises(errors.ChainError, match="writeback"):
        run.seal()
    run.expect(h2.r30, from_=h1.writebacks.task_handle)
    report = layout.check()
    assert any(i.code == "CHK-203" for i in report.errors)


def test_corpus_entry_drift_named_by_catalog() -> None:
    """Bug-class: gadget entry drifted from the re-derived catalog (the K_KD/entry-drift class)."""
    cat = catalog_mod.Catalog.load(FIXTURE)
    demo = cat.gadgets("DemoAS")

    class SYSCALL_TAIL(gadget.Gadget, entry=0x40002004, stride=0xB0):
        r30 = gadget.Restores(Reg.R30, at=0xA8)
        r31 = gadget.Restores(Reg.R31, at=0xAC)
        pc = gadget.Restores(Reg.PC, at=0xB4, external=True)
        needs = {Reg.R30: "h", Reg.R31: "k"}

    layout = cento.Layout()
    page = layout.region("p", base="pv", max_size=0x1000)
    run = page.chain("c", at=0x100, gadget_set=demo)
    run.enter(LjBypass)
    h = run.hop(SYSCALL_TAIL, "h")
    h.r30, h.r31 = 1, 2
    report = layout.check()
    assert any(i.code == "CHK-301" for i in report.errors)


def test_property_fold_catches_injected_clobbers() -> None:
    """Seeded property test: for random gadget sequences, a needs-hop after an unrepaired R30
    clobber is ALWAYS reported (CHK-201 naming that hop; seal() raises); with no clobber in
    between it NEVER is. Judged at seal()/issues(), never at hop()."""

    class Needy(gadget.Gadget, entry=0x6000, stride=0x10):
        r30 = gadget.Restores(Reg.R30, at=0x8)
        pc = gadget.Restores(Reg.PC, at=0x14, external=True)
        needs = {Reg.R30: "value"}

    class Neutral(gadget.Gadget, entry=0x7000, stride=0x10):
        pc = gadget.Restores(Reg.PC, at=0x14, external=True)

    class Killer(gadget.Gadget, entry=0x8000, stride=0x10):
        pc = gadget.Restores(Reg.PC, at=0x14, external=True)
        r30_kill = gadget.Clobbers(Reg.R30)

    rng = random.Random(0xC0DE)
    for trial in range(60):
        seq = [rng.choice(["neutral", "killer", "needy"]) for _ in range(rng.randint(1, 6))]
        layout = cento.Layout()
        page = layout.region("p", base="pv", max_size=0x4000)
        run = page.chain("c", at=0x200)
        run.enter(LjBypass)
        r30_alive = True  # enter restores r30
        expected_error_at = None
        for i, kind in enumerate(seq):
            if kind == "needy" and not r30_alive:
                expected_error_at = i
                break
            if kind == "killer":
                r30_alive = False
            if kind == "needy":
                r30_alive = True  # Needy RESTORES r30 too
        for i, kind in enumerate(seq):
            g = {"neutral": Neutral, "killer": Killer, "needy": Needy}[kind]
            run.hop(g, f"s{i}")  # never raises on unmet needs
        errs, _warns = run.issues()
        chk201 = [iss for iss in errs if iss.code == "CHK-201"]
        if expected_error_at is None:
            assert chk201 == [], f"trial {trial}: seq={seq}"
            run.seal()  # NEVER raises for clean sequences
        else:
            assert chk201 and chk201[0].subjects[0] == f"c.s{expected_error_at}", f"trial {trial}: seq={seq}"
            with pytest.raises(errors.ChainError, match="R30"):
                run.seal()  # ALWAYS raises when a starved needy hop exists


# -- chain/machine/catalog rides ----------------------------------------------

CATALOG = str(pathlib.Path(__file__).parent / "fixtures" / "catalog_v2.json")


class Lj(cento.Gadget, entry=0x40001000, frame_base=Reg.R31):
    pc = cento.Restores(Reg.PC, at=0x00)
    sp = cento.Restores(Reg.SP, at=0x04)
    r30 = cento.Restores(Reg.R30, at=0x50)
    r31 = cento.Restores(Reg.R31, at=0x54)
    needs = {Reg.R31: "jmp_buf"}


class Tail(cento.Gadget, entry=0x40002000, stride=0xB0, reentry_safe=True):
    r30 = cento.Restores(Reg.R30, at=0xA8)
    r31 = cento.Restores(Reg.R31, at=0xAC)
    pc = cento.Restores(Reg.PC, at=0xB4, external=True)


def _chain(
    *,
    carry: cento.machine.Carry | None = None,
    abi: cento.machine.AbiSpec | None = None,
    arm: bool = True,
) -> tuple[cento.Layout, cento.chain.Chain]:
    layout = cento.Layout(endian="big")  # a PPC32 exhibit: abi=ppc32.PPC32 chains require a big-endian layout
    page = layout.region("page", base="page_va", max_size=0x2000)
    run = page.chain("c", at=0xF0, carry=carry, abi=abi, arm=arm)
    run.enter(Lj)
    return layout, run


def test_per_hop_carry_override_unknown_then_reverts() -> None:
    _lay, run = _chain()
    h1 = run.hop(Tail, "h1")
    h1.frame.r30 = 0x11
    h1.frame.r31 = 0x22
    h2 = run.hop(Tail, "h2", carry=cento.Carry.Unknown)
    h2.frame.r30 = 0x33
    h2.frame.r31 = 0x44
    run.hop(Tail, "h3")
    # h2 sealed under Unknown: slots h2 does NOT re-establish degrade. SP is the observable one
    # (SpAdd is placement-time, not a Load control), while h2's own restores are seats.
    assert run.state_at("h3")[Reg.SP].kind == "unknown"
    assert run.state_at("h3")[Reg.R30].kind == "seat"
    # h1 sealed under the chain default Passthru: nothing degraded at h2 entry
    assert run.state_at("h2")[Reg.SP].kind == "seat"
    assert run.state_at("h2")[Reg.R30].kind == "seat"


def test_abi_aware_clobbered_spares_nonvolatile() -> None:
    _lay, run = _chain(carry=cento.Carry.Clobbered, abi=ppc32.PPC32)
    run.hop(Tail, "h1")
    run.hop(Tail, "h2")
    # SP is nonvolatile and NOT re-established by Tail's controls (SpAdd is placement-time):
    # under ABI-aware Clobbered it survives; that is THE discriminator vs the no-abi arm below.
    assert run.state_at("h2")[Reg.SP].kind == "seat"
    assert run.state_at("h2")[Reg.R30].kind == "seat"


def test_abi_aware_clobbered_degrades_string_slots() -> None:
    _lay, run = _chain(carry=cento.Carry.Clobbered, abi=ppc32.PPC32)
    run.state["tgt_slot"] = cento.machine.SlotState("seat", None, cento.machine.FedBy("cell", "x"))
    run.hop(Tail, "h1")
    run.hop(Tail, "h2")
    # a string slot has no ABI status: the conservative arm degrades it to clobbered,
    # while the nonvolatile un-reestablished Reg.SP still passes through.
    assert run.state_at("h2")["tgt_slot"].kind == "clobbered"
    assert run.state_at("h2")[Reg.SP].kind == "seat"


def test_clobbered_without_abi_still_clobbers_all() -> None:
    _lay, run = _chain(carry=cento.Carry.Clobbered)
    run.hop(Tail, "h1")
    run.hop(Tail, "h2")
    # the enter-frame SP seat was clobbered at h1 seal and never re-established
    assert run.state_at("h2")[Reg.SP].kind == "clobbered"
    st = run.state_at("h2")
    assert all(s.kind in ("seat", "clobbered") for s in st.values())


def test_transfer_effect_and_slotstate_frozen() -> None:
    """Freezing: Transfer needs/controls, Effect controls, and SlotState all refuse mutation."""
    with pytest.raises(TypeError):
        Tail.transfer.needs[Reg.R3] = "x"  # type: ignore[index]
    st = cento.machine.SlotState("seat", None, cento.machine.FedBy("cell", "p"))
    with pytest.raises(dataclasses.FrozenInstanceError):
        st.kind = "unknown"  # type: ignore[misc]
    with pytest.raises(TypeError):
        Tail.transfer.controls[Reg.R3] = cento.machine.CLOBBER  # type: ignore[index]
    eff = cento.machine.Effect("e", {})
    with pytest.raises(TypeError):
        eff.controls["x"] = cento.machine.CLOBBER  # type: ignore[index]


def test_abispec_lives_in_machine_with_ppc32_alias() -> None:
    assert ppc32.AbiSpec is cento.machine.AbiSpec
    assert isinstance(ppc32.PPC32, cento.machine.AbiSpec)


def test_chain_accepts_abi_name_and_teaches_on_junk() -> None:
    """abi="x86_64" resolves to the shipped spec; a junk name refuses with the vocabulary."""
    r = cento.region("r", max_size=0x100, word=8)
    c = r.chain("c", at=0, abi="x86_64", arm=False)
    assert c.abi is not None and c.abi.name == "x86_64"
    with pytest.raises(errors.PlacementError, match="unknown abi 'amd64'"):
        r.chain("c2", at=0x80, abi="amd64", arm=False)


def test_chk208_catches_default_width_restores_under_a_64bit_abi() -> None:
    """The audited silent-corruption path: u32 Restores + X86_64 + sub-4GiB addresses used to
    emit fill in every qword's top half, judged clean. CHK-208 is a WARNING (narrow restores
    like `mov edi, [rsp]` are legitimate), never an error."""

    class PopRdi(gadget.Gadget, entry=0x401234):
        rdi = gadget.Restores("rdi", at=0x0)  # width defaults u32: contradicts the 8-byte abi word
        pc = gadget.Restores(Reg.PC, at=0x8, width=cento.u64)

    r = cento.region("r", max_size=0x100, abi="x86_64", fill="A")
    c = r.chain("c", at=0, arm=False)
    c.enter(PopRdi)
    errs, warns = c.issues()
    assert "CHK-208" not in [i.code for i in errs]  # warning grade, binding
    chk208 = [i for i in warns if i.code == "CHK-208"]
    assert chk208, [i.code for i in warns]
    assert "rdi" in chk208[0].msg and "4" in chk208[0].msg and "8" in chk208[0].msg  # names the field and both widths


def test_chk208_names_the_overread_when_the_field_is_wider_than_the_word() -> None:
    """The wide direction: a u64 field under a 4-byte word does not fill-pad -- the load overreads the next slot, and the warning must say so."""

    class WidePop(gadget.Gadget, entry=0x40001000):
        r30 = gadget.Restores(Reg.R30, at=0x0, width=cento.u64)  # wider than the 4-byte ppc32 word
        pc = gadget.Restores(Reg.PC, at=0x8)

    r = cento.region("r", max_size=0x100, abi="ppc32")
    c = r.chain("c", at=0, arm=False)
    c.enter(WidePop)
    _errs, warns = c.issues()
    chk208 = [i for i in warns if i.code == "CHK-208"]
    assert chk208, [i.code for i in warns]
    assert "overreads into the next slot" in chk208[0].msg and "come from fill" not in chk208[0].msg


def test_chk208_silent_when_widths_match_the_word_or_no_abi() -> None:
    """Matching widths under an abi are clean; without an abi (or an abi word) nothing is judged."""

    class PopRdi64(gadget.Gadget, entry=0x401234):
        rdi = gadget.Restores("rdi", at=0x0, width=cento.u64)
        pc = gadget.Restores(Reg.PC, at=0x8, width=cento.u64)

    r = cento.region("r", max_size=0x100, abi="x86_64")
    c = r.chain("c", at=0, arm=False)
    c.enter(PopRdi64)
    _errs, warns = c.issues()
    assert "CHK-208" not in [i.code for i in warns]

    class PopR30(gadget.Gadget, entry=0x40001000):
        r30 = gadget.Restores(Reg.R30, at=0x0)  # default u32, and no abi to contradict
        pc = gadget.Restores(Reg.PC, at=0x4)

    r2 = cento.region("r2", max_size=0x100)
    c2 = r2.chain("c2", at=0, arm=False)
    c2.enter(PopR30)
    _errs2, warns2 = c2.issues()
    assert "CHK-208" not in [i.code for i in warns2]


def test_unknown_restores_slot_under_abi_gets_did_you_mean() -> None:
    """A typo'd string Restores slot must refuse at enter/hop time, not become a silent slot the fold never feeds."""

    class Typo(gadget.Gadget, entry=0x401234):
        rdx = gadget.Restores("rdx_typo", at=0x0, width=cento.u64)
        pc = gadget.Restores(Reg.PC, at=0x8, width=cento.u64)

    r = cento.region("r", max_size=0x100, abi="x86_64")
    c = r.chain("c", at=0, arm=False)
    with pytest.raises(errors.ChainError, match=r"restores 'rdx_typo'.*not a register in abi 'x86_64'.*did you mean 'rdx'"):
        c.enter(Typo)


def test_unknown_but_deliberate_restores_slot_is_taught_the_abispec_escape() -> None:
    """A LEGITIMATE non-split register (Restores("rflags"), the popfq genre) hits the same vocabulary guard: the refusal must teach the AbiSpec escape hatch."""

    class Popfq(gadget.Gadget, entry=0x401234):
        rflags = gadget.Restores("rflags", at=0x0, width=cento.u64)
        pc = gadget.Restores(Reg.PC, at=0x8, width=cento.u64)

    r = cento.region("r", max_size=0x100, abi="x86_64")
    c = r.chain("c", at=0, arm=False)
    with pytest.raises(errors.ChainError, match=r"dataclasses\.replace"):
        c.enter(Popfq)


def test_same_name_abi_conflict_teaches_declaring_the_spec_on_the_layout() -> None:
    """A dataclasses.replace'd spec sharing the shipped NAME must not be told 'x86_64 conflicts with x86_64'; the fix is Layout(abi=<your spec>)."""
    custom = dataclasses.replace(cento.abi.X86_64, volatile=cento.abi.X86_64.volatile | {"rflags"})
    r = cento.region("r", max_size=0x100, abi="x86_64")
    with pytest.raises(errors.ChainError, match=r"same name with different facts.*Layout\(abi=<your spec>\)"):
        r.chain("c", at=0, abi=custom, arm=False)


def test_unknown_restores_slot_refuses_at_hop_too_and_reg_slots_are_exempt() -> None:
    """hop() judges the same vocabulary; Reg-enum and Role slots are typed and never judged against string slots."""

    class Entry64(gadget.Gadget, entry=0x401000):
        rbx = gadget.Restores("rbx", at=0x0, width=cento.u64)
        pc = gadget.Restores(Reg.PC, at=0x8, width=cento.u64)

    class Typo(gadget.Gadget, entry=0x401234):
        rdx = gadget.Restores("rdx_typo", at=0x0, width=cento.u64)
        pc = gadget.Restores(Reg.PC, at=0x8, width=cento.u64)

    r = cento.region("r", max_size=0x100, abi="x86_64")
    c = r.chain("c", at=0, arm=False)
    c.enter(Entry64)  # Reg.PC (a Role after norm) under a string-slot abi: exempt, no refusal
    with pytest.raises(errors.ChainError, match=r"restores 'rdx_typo'.*not a register in abi 'x86_64'"):
        c.hop(Typo, "typo")


# -- chain(arm=False) knob ------------------------------------------------------


def test_arm_false_trigger_delivered_in_non_arm_group() -> None:
    layout, run = _chain(arm=False)
    run.hop(Tail, "h1")
    run.finish_in_kernel(0x40003000)  # finalize() refuses dangling continuations
    trigger = run.hops[0].frame.pc
    layout.bind("page_va", 0x1000, source="test")
    plan = layout.plan()
    groups = plan.stage()
    trig_addr = 0x1000 + trigger.offset
    normal_addrs = [a for g in groups if g.deliver is not cento.emit.Deliver.ARM for a, _ in g.items]
    assert trig_addr in normal_addrs
    for g in groups:
        plan.confirm(g)
    final = plan.finalize()
    arm_groups = [g for g in final if g.deliver is cento.emit.Deliver.ARM]
    assert len(arm_groups) == 1 and arm_groups[0].items == []  # finalize's ARM group is empty


def test_arm_default_true_trigger_withheld_until_finalize() -> None:
    layout, run = _chain()
    run.hop(Tail, "h1")
    run.finish_in_kernel(0x40003000)  # finalize() refuses dangling continuations
    trigger = run.hops[0].frame.pc
    layout.bind("page_va", 0x1000, source="test")
    plan = layout.plan()
    groups = plan.stage()
    trig_addr = 0x1000 + trigger.offset
    assert all(a != trig_addr for g in groups for a, _ in g.items)  # withheld from stage()
    for g in groups:
        plan.confirm(g)
    final = plan.finalize()
    arm = final[-1]
    assert arm.deliver is cento.emit.Deliver.ARM
    assert [a for a, _ in arm.items] == [trig_addr]


# -- finish_in_kernel -----------------------------------------------------------


def test_finish_in_kernel_terminal_pc_no_placement() -> None:
    layout, run = _chain()
    run.hop(Tail, "h1")
    h2 = run.hop(Tail, "h2")
    page = layout.regions["page"]
    n_before = len(page.placements)
    run.finish_in_kernel(0x40003000)
    assert len(page.placements) == n_before  # NO frame placed, NO gadget
    pc_cell = h2.frame.pc
    assert layout.force((pc_cell.region.name, pc_cell.offset)) == (0x40003000).to_bytes(4, "big")
    assert layout.check().errors == []  # no CHK-003 zero-extent artifact
    assert run.finished is True
    with pytest.raises(cento.ChainError, match="finished"):
        run.hop(Tail, "h3")


# -- crosscheck scope -----------------------------------------------------------

_CAT_NEEDS = {Reg.R30: "syscall object handle -> r3", Reg.R31: "desc array pointer -> r4"}


def _demo() -> cento.catalog.GadgetSet:
    return cento.catalog.Catalog.load(CATALOG).gadgets("DemoAS")


def _one_302(gadget_cls: cento.gadget.GadgetMeta, field: str) -> cento.Issue:
    errs, warns = _demo().crosscheck(gadget_cls)
    assert warns == []
    assert [i.code for i in errs] == ["CHK-302"], f"expected exactly one CHK-302, got {[(i.code, i.subjects) for i in errs]}"
    assert errs[0].subjects == ("SYSCALL_TAIL", field)
    return errs[0]


def test_crosscheck_scope_field_drift_and_clean() -> None:
    """CHK-302 scope: every crosschecked field (stride, frame_base, reentry_safe, needs) drifts to
    exactly one issue naming catalog-vs-gadget values; the catalog-shaped declaration checks clean."""

    class SYSCALL_TAIL(cento.Gadget, entry=0x40002000, stride=0xC0, reentry_safe=True):
        r30 = cento.Restores(Reg.R30, at=0xA8)
        r31 = cento.Restores(Reg.R31, at=0xAC)
        pc = cento.Restores(Reg.PC, at=0xB4, external=True)
        needs = dict(_CAT_NEEDS)

    issue = _one_302(SYSCALL_TAIL, "stride")
    assert "0xb0" in issue.msg and "0xc0" in issue.msg  # catalog-vs-gadget values named

    class SYSCALL_TAIL(cento.Gadget, entry=0x40002000, stride=0xB0, reentry_safe=True, frame_base=Reg.R30):  # type: ignore[no-redef]  # the class NAME is the crosscheck key: each arm redeclares it
        r30 = cento.Restores(Reg.R30, at=0xA8)
        r31 = cento.Restores(Reg.R31, at=0xAC)
        pc = cento.Restores(Reg.PC, at=0xB4, external=True)
        needs = dict(_CAT_NEEDS)

    issue = _one_302(SYSCALL_TAIL, "frame_base")
    assert "SP" in issue.msg and "R30" in issue.msg

    class SYSCALL_TAIL(cento.Gadget, entry=0x40002000, stride=0xB0, reentry_safe=False):  # type: ignore[no-redef]  # the class NAME is the crosscheck key: each arm redeclares it
        r30 = cento.Restores(Reg.R30, at=0xA8)
        r31 = cento.Restores(Reg.R31, at=0xAC)
        pc = cento.Restores(Reg.PC, at=0xB4, external=True)
        needs = dict(_CAT_NEEDS)

    issue = _one_302(SYSCALL_TAIL, "reentry_safe")
    assert "True" in issue.msg and "False" in issue.msg

    class SYSCALL_TAIL(cento.Gadget, entry=0x40002000, stride=0xB0, reentry_safe=True):  # type: ignore[no-redef]  # the class NAME is the crosscheck key: each arm redeclares it
        r30 = cento.Restores(Reg.R30, at=0xA8)
        r31 = cento.Restores(Reg.R31, at=0xAC)
        pc = cento.Restores(Reg.PC, at=0xB4, external=True)
        needs = {Reg.R30: "DRIFTED doc", Reg.R31: "desc array pointer -> r4"}

    issue = _one_302(SYSCALL_TAIL, "needs")
    assert "DRIFTED doc" in issue.msg and "syscall object handle -> r3" in issue.msg

    class SYSCALL_TAIL(cento.Gadget, entry=0x40002000, stride=0xB0, reentry_safe=True):  # type: ignore[no-redef]  # the class NAME is the crosscheck key: each arm redeclares it
        r30 = cento.Restores(Reg.R30, at=0xA8)
        r31 = cento.Restores(Reg.R31, at=0xAC)
        pc = cento.Restores(Reg.PC, at=0xB4, external=True)
        needs = dict(_CAT_NEEDS)

    errs, warns = _demo().crosscheck(SYSCALL_TAIL)
    assert errs == [] and warns == []


# -- region.alloc reserves external field spans ---------------------------------


class Frame(cento.View, size=0xB0):
    r30 = cento.Field(0xA8, cento.u32)
    pc = cento.Field(0xB4, cento.u32, external=True)  # caller-frame slot: [0xB4, 0xB8)


class Word(cento.View, size=8):
    a = cento.Field(0, cento.u32)


def test_alloc_skips_external_span_by_default() -> None:
    layout = cento.Layout()
    page = layout.region("page", base="p", max_size=0x1000)
    page.at(0, Frame, "f")
    h = page.alloc(Word, "w")
    assert h.offset == 0xB8  # past the external span end, not the 0xB0 extent


def test_alloc_opt_out_restores_bump_behavior() -> None:
    layout = cento.Layout()
    page = layout.region("page", base="p", max_size=0x1000)
    page.at(0, Frame, "f")
    h = page.alloc(Word, "w", reserve_external=False)
    assert h.offset == 0xB0


# -- golden bytes, determinism, perf, wire micro-example -------------------------


class Hdr(cento.View, size=8):
    magic = cento.Field(0, cento.u32)
    length = cento.Field(4, cento.u16)
    csum = cento.Field(6, cento.u16)


def build_wire_packet() -> cento.Layout:
    """Target-less wire-image micro-example (docs example; zero adapter imports)."""
    layout = cento.Layout(endian="big")  # a big-endian wire format: the byte asserts spell network order
    pkt = layout.region("pkt", max_size=24, fill=0)
    h = pkt.at(0, Hdr, "h")
    h.magic = 0xC0DE0001
    h.length = 24
    h.csum = cento.sum16(pkt[0:6])
    body = pkt.cell(8, width=4)
    body.write(layout.sym("peer_addr"))  # bound late, like a live probe
    pkt.cell(20, width=4).write(cento.crc32_mpeg2(pkt[0:20]))
    return layout


def test_wire_micro_example_end_to_end() -> None:
    layout = build_wire_packet()
    partial = layout.emit(cento.Backend.IMAGE, final=False)  # the draft read: the fixup list is the point
    assert {f.missing for f in partial.fixups} == {("peer_addr",)}  # computed fixup list
    layout.bind("peer_addr", 0x0A000001, source="operator")
    final = layout.emit(cento.Backend.IMAGE)
    img = final.artifact["pkt"]
    assert img[0:4] == bytes.fromhex("c0de0001")
    assert img[8:12] == bytes.fromhex("0a000001")
    assert img[20:24] == cells.REDUCERS["crc32_mpeg2"](img[0:20]).to_bytes(4, "big")


def test_determinism_two_builds_identical() -> None:
    a, b = build_wire_packet(), build_wire_packet()
    for layout in (a, b):
        layout.bind("peer_addr", 1)
    assert json.dumps(a.check().to_json(), sort_keys=True) == json.dumps(b.check().to_json(), sort_keys=True)
    assert a.emit(cento.Backend.IMAGE).artifact == b.emit(cento.Backend.IMAGE).artifact
    assert json.dumps(a.emit(cento.Backend.HEXDUMP).artifact) == json.dumps(b.emit(cento.Backend.HEXDUMP).artifact)


def test_determinism_two_builds_with_registrations_identical() -> None:
    """Spec R11: two identical builds with registrations produce byte-identical reports (and final images)."""

    def build() -> cento.Layout:
        layout = cento.Layout()
        pkt = layout.region("pkt", max_size=16, fill=0)
        page = layout.register_xform("pg", lambda v: v >> 12)
        ck = layout.register_reducer("fw_ck", lambda data: sum(data) & 0xFFFF)
        pkt.cell(0, width=4).write(page(layout.sym("libc")))
        pkt.cell(4, width=2).write(ck(pkt[0:4]))
        layout.bind("libc", 0x40069780)
        return layout

    a, b = build(), build()
    assert json.dumps(a.check().to_json(), sort_keys=True) == json.dumps(b.check().to_json(), sort_keys=True)
    assert a.emit(cento.Backend.IMAGE).artifact == b.emit(cento.Backend.IMAGE).artifact


def test_perf_budget_10k_cells_under_2s() -> None:
    layout = cento.Layout()
    reg = layout.region("big")
    for i in range(10_000):
        reg.cell(i * 4).write(i)
    t0 = time.monotonic()
    report = layout.check()
    result = layout.emit(cento.Backend.IMAGE)
    dt = time.monotonic() - t0
    assert not report.errors and result.fixups == []
    assert dt < 2.0, f"perf budget exceeded: {dt:.2f}s"


def test_vocabulary_enumeration_xform_x_width_x_endian() -> None:
    """SDET amendment: exhaustive small-model enumeration of the closed vocabulary."""
    value = 0x40069780
    for endian in ("big", "little"):
        for width_obj, width in ((views.u8, 1), (views.u16, 2), (views.u32, 4), (views.u64, 8)):
            for xform, expected in (
                (cells.Xform.ADDR, value),
                (cells.Xform.LO16, value & 0xFFFF),
                (cells.Xform.HI16, (value >> 16) & 0xFFFF),
                (cells.Xform.HA16, ((value >> 16) + ((value >> 15) & 1)) & 0xFFFF),
            ):
                layout = cento.Layout(endian=endian)
                reg = layout.region("r")
                reg.cell(0, width=width).write(cells.Ref("s", xform=xform))
                layout.bind("s", value)
                if xform is cells.Xform.ADDR and value >= 1 << (8 * width):
                    with pytest.raises(errors.WidthError, match="does not fit"):  # CHK-009: full addresses refuse, they never wrap
                        layout.force(("r", 0))
                    continue
                forced = layout.force(("r", 0))
                assert isinstance(forced, bytes)
                assert forced == (expected % (1 << (8 * width))).to_bytes(width, endian)  # slices keep wrap semantics
                assert width_obj.size == width


def test_external_alias_shape_like_desc24() -> None:
    """The DESC24 idiom shape: an overlay desc-like view over a frame's slots."""

    class Frame(views.View, size=0x10):
        r30 = views.Field(0x8, views.u32)

    class Slot(views.View, size=0x8):
        val = views.Field(0x4, views.u32)

    layout = cento.Layout(endian="big")  # a PPC32 exhibit (the DESC24 shape): the byte asserts are big-endian
    page = layout.region("page")
    page.at(0x0, Frame, "ff")
    ov = page.at(0x4, Slot, "kd", over="ff", why="writeback lands in ff.r30")
    ov.val = 0x1234  # same byte range as ff.r30
    assert not layout.check().errors  # declared alias, agreeing bytes
    ff = page["ff"]
    assert isinstance(ff, cento.ViewHandle)
    assert layout.force(("page", 0x8)) == (0x1234).to_bytes(4, "big")
