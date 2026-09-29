# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Chain unit tests.

Hop-input seating: hop.r30 = value writes the upstream cell; violations raise.
Chain fold: enter/hop wiring, deferred seal, carry, frame placement, ARM.
Chain-internal overlay auto-alias -- no also_over needed inside a chain; foreign overlap still strict.
Effects: the DESC24 writeback-restore flow, expect, conflicts, hazards + waivers.
narrate(): deterministic hop-by-hop story with $sym rendering.
Deferred sealing: effects/overlays attach after later hops exist; the fold judges at check.
Writeback as a CellValue -- never emitted, legal at ARM, derived effect + discard waiver.
"""

from __future__ import annotations

import pytest

import cento
import cento.cells as cells
import cento.chain as chain
import cento.emit as emit
import cento.errors as errors
import cento.gadget as gadget
import cento.machine as machine
import cento.regions as regions
import cento.views as views

Reg = machine.Reg


# Shared by the seating and effects concerns.
class SyscallTail(gadget.Gadget, entry=0x40002000, stride=0xB0, reentry_safe=True):
    r30 = gadget.Restores(Reg.R30, at=0xA8)
    r31 = gadget.Restores(Reg.R31, at=0xAC)
    pc = gadget.Restores(Reg.PC, at=0xB4, external=True)
    needs = {Reg.R30: "handle", Reg.R31: "desc"}


class LjBypass(gadget.Gadget, entry=0x40001000, frame_base=Reg.R31):
    pc = gadget.Restores(Reg.PC, at=0x00)
    sp = gadget.Restores(Reg.SP, at=0x04)
    r30 = gadget.Restores(Reg.R30, at=0x50)
    r31 = gadget.Restores(Reg.R31, at=0x54)
    needs = {Reg.R31: "jb ptr"}


# Shared by the autoalias, late-attach, and writeback-cell concerns.
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


# -- hop-input seating ------------------------------------------------------------


def build_seating() -> tuple[regions.Layout, regions.Region, chain.Chain]:
    layout = regions.Layout(endian="big")  # a PPC32 exhibit: the byte asserts below are big-endian
    page = layout.region("page", base="pv", max_size=0x1000)
    run = page.chain("c", at=0x100)
    run.enter(LjBypass)
    return layout, page, run


def test_hop_input_seating_contract() -> None:
    """Hop-input seating: reading a seat gives a SlotView, unknown attrs teach, and writes land in the upstream cell."""
    layout, page, run = build_seating()
    h1 = run.hop(SyscallTail)
    view = h1.r30
    assert view.fed_by.kind == "cell" and "c.enter" in view.fed_by.name
    with pytest.raises(AttributeError, match="r30"):
        h1.r33 = 1  # Hop.__setattr__ is dynamic (typed object); the runtime AttributeError is the assertion
    h1.r30 = 0x40  # seats into the enter jb s20-equivalent cell
    jb = page["c.enter"]
    assert layout.force(("page", jb.offset + 0x50)) == (0x40).to_bytes(4, "big")
    h1.r31 = jb  # handles coerce to their address
    forced = layout.force(("page", jb.offset + 0x54))
    assert isinstance(forced, cells.Residual)  # Ref to page base: residual until bound
    layout.bind("pv", 0x2000)
    assert layout.force(("page", jb.offset + 0x54)) == (0x2000 + jb.offset).to_bytes(4, "big")


def test_seat_second_hop_writes_first_frame_restore() -> None:
    layout, page, run = build_seating()
    run.hop(SyscallTail)
    h2 = run.hop(SyscallTail)
    h2.r30 = 0x77  # upstream = h1 frame's r30 slot @ 0x100+0xA8
    assert layout.force(("page", 0x1A8)) == (0x77).to_bytes(4, "big")


def test_state_lookup_accepts_both_role_spellings() -> None:
    layout = regions.Layout()
    scratch = layout.region("scratch", max_size=0x400)
    scratch.bind("scratch_base", 0x40200000)
    ch = scratch.chain("c", at=0x40, arm=False)
    ch.enter(SyscallTail)
    ch.finish_in_kernel(pc=0x40003000)
    st = ch.state_at("enter")
    assert st[cento.Role.PC] == st[machine.Reg.PC]  # both spellings find the Role-keyed state


def test_fold_entry_lookup_accepts_both_role_spellings() -> None:
    layout = regions.Layout()
    scratch = layout.region("scratch", max_size=0x400)
    scratch.bind("scratch_base", 0x40200000)
    ch = scratch.chain("c", at=0x40, arm=False)
    ch.enter(SyscallTail)
    ch.finish_in_kernel(pc=0x40003000)
    entry = ch.fold().entry["enter"]
    assert entry[machine.Reg.PC] == entry[cento.Role.PC]  # fold().entry hop maps normalize indexing like state_at


# -- chain fold ---------------------------------------------------------------------


class SyscallTailFold(gadget.Gadget, entry=0x40002000, stride=0xB0, reentry_safe=True):
    r30 = gadget.Restores(Reg.R30, at=0xA8)
    r31 = gadget.Restores(Reg.R31, at=0xAC)
    pc = gadget.Restores(Reg.PC, at=0xB4, external=True)
    needs = {Reg.R30: "handle -> r3", Reg.R31: "desc -> r4"}


class LjBypassFold(gadget.Gadget, entry=0x40001000, frame_base=Reg.R31):
    pc = gadget.Restores(Reg.PC, at=0x00)
    sp = gadget.Restores(Reg.SP, at=0x04)
    r30 = gadget.Restores(Reg.R30, at=0x50)
    r31 = gadget.Restores(Reg.R31, at=0x54)
    needs = {Reg.R31: "jmp_buf pointer (hijack primitive)"}


def build_fold() -> tuple[regions.Layout, regions.Region, chain.Chain]:
    layout = regions.Layout(endian="big")  # a PPC32 exhibit: the byte asserts below are big-endian
    page = layout.region("page", base="page_va", max_size=0x1000)
    run = page.chain("c", at=0x100)
    return layout, page, run


def test_fold_wiring_contract() -> None:
    """The fold end to end: enter builds the jb and arms on first wire, frames chain at the cursor
    with declared aliases, and the dataflow hands each restore to the next hop."""
    layout, page, run = build_fold()
    run.enter(LjBypassFold)
    jb = page["c.enter"]
    assert isinstance(jb, regions.ViewHandle)
    assert run.primitive_needs[Reg.R31] == jb.addr  # primitive must deliver r31 = jb
    h1 = run.hop(SyscallTailFold)  # wires jb.pc = SyscallTailFold.entry
    key = ("page", jb.offset + 0x00)
    entry = layout.cells()[key]
    assert entry.deliver is emit.Deliver.ARM  # first pc-source cell is the trigger
    assert layout.force(key) == (0x40002000).to_bytes(4, "big")
    st = run.state_at(h1.name)
    assert st[Reg.R30].kind == "seat"
    assert st[Reg.R30].fed_by.name == "page.c.enter.r30"
    h2 = run.hop(SyscallTailFold)
    assert h1.frame.offset == 0x100 and h2.frame.offset == 0x1B0
    # h1's external pc slot (0x100+0xB4) was wired to h2's entry at h2 creation
    assert layout.force(("page", 0x1B4)) == (0x40002000).to_bytes(4, "big")
    rec = next(p for p in page.placements if p.offset == 0x1B0)
    assert rec.over and rec.why  # frame-sequence alias declared
    assert "CHK-001" not in {i.code for i in layout.check().errors}
    assert "CHK-003" not in {i.code for i in layout.check().errors}
    st2 = run.state_at(h2.name)
    assert st2[Reg.R30].fed_by.name == f"page.c.{h1.name}.r30"  # now fed by h1's frame restore


def test_enter_needs_semantics() -> None:
    """enter() need seeding: the frame base need is fed by the primitive itself; other needs stay UNSET markers."""

    class LjBypassTwoNeeds(gadget.Gadget, entry=0x40001000, frame_base=Reg.R31):
        pc = gadget.Restores(Reg.PC, at=0x00)
        sp = gadget.Restores(Reg.SP, at=0x04)
        r30 = gadget.Restores(Reg.R30, at=0x50)
        r31 = gadget.Restores(Reg.R31, at=0x54)
        needs = {Reg.R31: "jb ptr", Reg.R30: "initial r30"}

    layout, page, run = build_fold()
    run.enter(LjBypassTwoNeeds)
    jb = page["c.enter"]
    assert run.primitive_needs[Reg.R31] == jb.addr  # the frame base IS given: the frame address
    assert run.primitive_needs[Reg.R30] is machine.UNSET  # the other need is a marker, not the doc string
    assert "(unset)" in run.narrate()

    # A pointer-frame entry whose gadget does NOT reload its own frame-base register (MIPS-style:
    # $a0 hands over the ctx and is never restored) -- the primitive feeds it, so no CHK-201.
    class A0Enter(gadget.Gadget, entry=0x1000, stride=0x8, frame_base=Reg.R4):
        pc = gadget.Restores(Reg.PC, at=0x0)
        sp = gadget.Restores(Reg.SP, at=0x4)
        needs = {Reg.R4: "context pointer"}

    layout = regions.Layout()
    page = layout.region("page", base="p", max_size=0x100)
    run = page.chain("c", at=0x40)
    run.enter(A0Enter)
    st = run.state_at("enter")
    assert st[Reg.R4].fed_by.kind == "primitive" and st[Reg.R4].fed_by.name == "page.c.enter"
    errs, _warns = run.issues()
    assert not [i for i in errs if "R4" in i.msg]  # the satisfied primitive need is not unknown


def test_carry_policies() -> None:
    class NoRestores(gadget.Gadget, entry=0x3000, stride=0x10):
        pc = gadget.Restores(Reg.PC, at=0x14, external=True)

    # Passthru (default): R30 survives an unmentioning hop
    layout, page, run = build_fold()
    run.enter(LjBypassFold)
    run.hop(NoRestores, "gap")
    h = run.hop(SyscallTailFold)  # no error: R30 passed through
    assert run.state_at(h.name)[Reg.R30].kind == "seat"

    # Unknown: the same sequence hard-errors at the needs check (judged at seal(), not at hop())
    lay2 = regions.Layout()
    page2 = lay2.region("page", base="p2", max_size=0x1000)
    run2 = page2.chain("c", at=0x100, carry=machine.Carry.Unknown)
    run2.enter(LjBypassFold)
    run2.hop(NoRestores, "gap")
    run2.hop(SyscallTailFold)
    with pytest.raises(errors.ChainError, match="R30"):
        run2.seal()


# -- chain-internal overlay auto-alias ----------------------------------------------


class Nine(cento.View, size=0x90):  # stands in for DescArray(9): 0x44 + 0x90 crosses the 0xB0 frame boundary
    w = cento.Field(0, cento.u32)


def test_chain_internal_overlay_autoalias() -> None:
    """R3: overlays inside a chain auto-alias its frames (CHK-102 info row); foreign overlap stays a strict error."""
    layout = cento.Layout()
    page = layout.region("page", base="p", max_size=0x2000)
    run = page.chain("c", at=0xF0)
    run.enter(Lj)
    h1 = run.hop(Tail, "h1")
    run.hop(Tail, "h2")
    h1.frame.overlay(Nine, at=0x44, name="kd", why="sc writeback lands in restore slots")  # NO also_over
    report = layout.check()
    assert not any(i.code in ("CHK-001", "CHK-003") for i in report.errors)
    assert any(i.code == "CHK-102" for i in report.warnings)  # the informational auto-alias row
    layout = cento.Layout()
    page = layout.region("page", base="p", max_size=0x2000)
    run = page.chain("c", at=0xF0)
    run.enter(Lj)
    run.hop(Tail, "h1")
    page.at(0xF0 + 0x20, Nine, "intruder")  # hand placement overlapping the chain frame, no over=/why=
    report = layout.check()
    # Adjudicated vs the brief (see the G3 report): the brief asserted CHK-003 here, but the pinned repo
    # semantics (cento/checks.py, tests/cento/test_checks.py) are CHK-001 = undeclared overlap (this case)
    # and CHK-003 = declared-but-disjoint alias. The intent -- foreign overlap still errors -- is CHK-001.
    assert any(i.code == "CHK-001" for i in report.errors)
    assert not any(i.code == "CHK-102" for i in report.warnings)  # chain-vs-hand pairs are never auto-declared


# -- effects: writeback-restore flow, hazards, waivers ------------------------------


class Desc(views.View, size=0x10):
    dtype = views.Field(0x0, views.u32)
    val = views.Field(0x4, views.u32)
    aux = views.Field(0x8, views.u32)
    res = views.Field(0xC, views.u32)


def build_effects() -> tuple[regions.Layout, regions.Region, chain.Chain]:
    layout = regions.Layout()
    page = layout.region("page", base="pv", max_size=0x2000)
    run = page.chain("c", at=0x100)
    run.enter(LjBypass)
    return layout, page, run


def errs_warns(layout: regions.Layout) -> tuple[set[str], set[str]]:
    report = layout.check()
    return {i.code for i in report.errors}, {i.code for i in report.warnings}


def test_desc24_writeback_feeds_next_hop_and_expect_passes() -> None:
    layout, page, run = build_effects()
    h1 = run.hop(SyscallTail, "create_task")
    # desc overlaid so kd[6].val-style slot coincides with h1's r30 restore:
    # frame at 0x100; r30 restore at 0x1A8; overlay a Desc at frame+0xA4 -> .val at 0x1A8.
    kd = h1.frame.overlay(Desc, at=0xA4, name="kd", why="writeback lands in this frame's r30 restore")
    h1.r31 = kd
    h1.r30 = 0x40
    h1.add_effect(machine.Effect("sc24", controls={kd.val: machine.Writeback("task_handle")}))
    h2 = run.hop(SyscallTail, "kernel_write")
    st = run.state_at("kernel_write")
    assert st[Reg.R30].kind == "writeback" and st[Reg.R30].fed_by.name == "task_handle"
    run.expect(h2.r30, from_=h1.writebacks.task_handle)
    h2.r31 = 0x2000
    e, w = errs_warns(layout)
    assert "CHK-203" not in e and "CHK-204" not in e and "CHK-201" not in e


def test_writeback_cell_conflicts_are_named() -> None:
    """A writeback-promised cell refuses competing writes: user staging is CHK-204; a seat landing on it raises at seal()."""
    layout, page, run = build_effects()
    h1 = run.hop(SyscallTail, "h")
    kd = h1.frame.overlay(Desc, at=0xA4, name="kd", why="writeback slot")
    h1.add_effect(machine.Effect("sc24", controls={kd.val: machine.Writeback("task_handle")}))
    kd.val = 0x1234  # WRONG: user stages the writeback cell
    h1.r30, h1.r31 = 0x40, kd
    e, _ = errs_warns(layout)
    assert "CHK-204" in e
    layout, page, run = build_effects()
    h1 = run.hop(SyscallTail, "h")
    kd = h1.frame.overlay(Desc, at=0xA4, name="kd", why="writeback slot")
    h1.add_effect(machine.Effect("sc24", controls={kd.val: machine.Writeback("task_handle")}))
    h1.r31 = kd
    h2 = run.hop(SyscallTail, "h2")
    h2.r30 = 0x99  # kernel supplies it; the seat conflict is judged at seal(), not at construction
    with pytest.raises(errors.ChainError, match="writeback"):
        run.seal()


def test_chk203_expect_mismatch() -> None:
    """expect() names wrong wiring: an off-by-4 overlay offset, and a writeback fed by a DIFFERENT effect."""
    layout, page, run = build_effects()
    h1 = run.hop(SyscallTail, "h")
    kd = h1.frame.overlay(Desc, at=0xA8, name="kd", why="OFF BY 4: val lands at 0x1AC not 0x1A8")
    h1.add_effect(machine.Effect("sc24", controls={kd.val: machine.Writeback("task_handle")}))
    h1.r30, h1.r31 = 0x40, kd
    h2 = run.hop(SyscallTail, "h2")
    run.expect(h2.r30, from_=h1.writebacks.task_handle)  # r30 is NOT fed by it (r31 is!)
    h2.r31 = 0x2000  # the off-by-4 ALSO made r31 the writeback slot; the conflict is judged at seal(), not at construction
    with pytest.raises(errors.ChainError, match="writeback"):
        run.seal()
    e, _ = errs_warns(layout)
    assert "CHK-203" in e
    layout, page, run = build_effects()
    h1 = run.hop(SyscallTail, "h")
    kd = h1.frame.overlay(Desc, at=0xA4, name="kd", why="writeback lands in this frame's r30 restore")
    h1.add_effect(machine.Effect("wb_a", controls={kd.val: machine.Writeback("handle_a")}))
    h1.r30, h1.r31 = 0x40, kd
    h2 = run.hop(SyscallTail, "h2")
    run.expect(h2.r30, from_=machine.WritebackRef("wb_b", "handle_b"))  # r30 IS a writeback, but by wb_a:handle_a
    report = layout.check()
    hits = [i for i in report.errors if i.code == "CHK-203"]
    assert hits and "writeback" in hits[0].msg  # got-kind rendering names the actual feeder kind


def test_chk202_unfed_seat_warns() -> None:
    layout, page, run = build_effects()
    run.hop(SyscallTail, "h")  # r30/r31 seats never written
    _, w = errs_warns(layout)
    assert "CHK-202" in w


def test_chk205_hazard_and_waiver() -> None:
    layout, page, run = build_effects()
    h1 = run.hop(SyscallTail, "h")
    h1.r30, h1.r31 = 0x40, 0x2000
    victim = page.cell(0x900)
    victim.write(0xDEAD)
    run.hazard(machine.Effect("preempt_writeback", controls={victim: machine.CLOBBER}, window="any"))
    e, _ = errs_warns(layout)
    assert "CHK-205" in e
    layout.allow_clobber(victim, "preempt_writeback", reason="dead slot; rewritten before use")
    e2, _ = errs_warns(layout)
    assert "CHK-205" not in e2
    with pytest.raises(errors.ChainError, match="windowed"):
        run.hazard(machine.Effect("x", controls={}, window=None))


# -- narrate() ----------------------------------------------------------------------


def test_narrate_contains_the_story_and_is_deterministic() -> None:
    # This SyscallTail variant (no reentry_safe) is scoped here: its class NAME is pinned in the
    # narration text below, so the collision with the module-level declaration cannot rename it.
    class SyscallTail(gadget.Gadget, entry=0x40002000, stride=0xB0):
        r30 = gadget.Restores(Reg.R30, at=0xA8)
        r31 = gadget.Restores(Reg.R31, at=0xAC)
        pc = gadget.Restores(Reg.PC, at=0xB4, external=True)
        needs = {Reg.R30: "handle", Reg.R31: "desc"}

    layout = regions.Layout()
    page = layout.region("page", base="page_va", max_size=0x1000)
    run = page.chain("c", at=0x100)
    run.enter(LjBypass)
    h1 = run.hop(SyscallTail, "create_task")
    h1.r30 = 0x40
    h1.add_effect(machine.Effect("sc24", controls={h1.frame.r30: machine.Writeback("task_handle")}))
    text = run.narrate()
    assert text == run.narrate()  # deterministic
    assert "chain c" in text and "carry=Passthru" in text
    assert "$page_va" in text  # primitive R31 = jb addr renders as $sym+off
    assert "create_task: SyscallTail @ 0x40002000" in text
    assert "R30" in text and "sc24" in text and "task_handle" in text


# -- dataflow export ----------------------------------------------------------------


def test_chain_dataflow_export() -> None:
    """Chain.dataflow()/to_json(): narrate() as data -- needs with FedBy provenance, effects, derived writebacks, spec_sha16 join keys."""
    layout = regions.Layout()
    scratch = layout.region("scratch", max_size=0x400)
    scratch.bind("scratch_base", 0x40200000)
    ch = scratch.chain("c", at=0x40, arm=False)
    ent = ch.enter(SyscallTail)
    ent.r30 = 0x1337
    ent.add_effect(machine.Effect("sc24", controls={ent.frame.r31: machine.Writeback("task_handle")}))
    h2 = ch.hop(SyscallTail, "h2")
    h2.frame.r30.write(cento.Writeback("kout"))
    ch.finish_in_kernel(pc=0x40003000)
    j = ch.to_json()
    assert j["name"] == "c" and j["region"] == "scratch" and j["finished"] is True and j["abi"] is None
    assert j["carry"] == "Passthru" and j["arm"] is False and j["hazards"] == []
    assert j["primitives"] == [{"slot": "R30", "value": "(unset)"}, {"slot": "R31", "value": "(unset)"}]
    h = j["hops"][0]
    assert h["name"] == "enter" and h["gadget"] == "SyscallTail" and h["entry"] == 0x40002000 and len(h["spec_sha16"]) == 16
    needs = {n["slot"]: n for n in h["needs"]}
    assert needs["R30"] == {"slot": "R30", "fed_kind": "cell", "fed_name": "scratch.c.enter.r30", "fed_detail": "", "doc": "handle"}
    assert h["effects"] == [{"name": "sc24", "window": None, "outputs": ["task_handle"]}]
    # The derived writeback rides the hop the fold attributes the cell to: h2's frame sequences
    # over enter's external continuation span, so the alias attribution lands it on "enter".
    assert h["writebacks"] == [{"region": "scratch", "offset": 0x198, "owner": "scratch.c.h2.r30", "name": "kout", "discarded": False}]
    needs2 = {n["slot"]: n for n in j["hops"][1]["needs"]}  # every hop's needs exported with FedBy provenance
    assert needs2["R30"] == {"slot": "R30", "fed_kind": "cell", "fed_name": "scratch.c.enter.r30", "fed_detail": "", "doc": "handle"}
    assert needs2["R31"] == {"slot": "R31", "fed_kind": "effect", "fed_name": "task_handle", "fed_detail": "sc24", "doc": "desc"}
    flow = ch.dataflow()
    assert flow.hops[0].name == "enter" and flow.to_json() == j
    assert cento.ChainFlow is chain.ChainFlow  # exported at the facade


def test_narrate_handles_symbolic_entries() -> None:
    LIBC = cento.Ref("libc_base")

    class SymG(gadget.Gadget, entry=LIBC + 0x2A3E5, stride=0x10):
        r30 = gadget.Restores(Reg.R30, at=0x0)
        pc = gadget.Restores(Reg.PC, at=0x8)

    layout = regions.Layout()
    scratch = layout.region("scratch", max_size=0x100)
    ch = scratch.chain("c", at=0x0, arm=False)
    ch.enter(SymG)
    ch.finished = True
    assert "@ libc_base+0x2a3e5" in ch.narrate()  # crashed with a TypeError before; entry_str's hex is lowercase


# -- deferred sealing -----------------------------------------------------------------


def _chain() -> tuple[cento.Layout, cento.chain.Chain]:
    layout = cento.Layout()
    page = layout.region("page", base="p", max_size=0x2000)
    run = page.chain("c", at=0xF0)
    run.enter(Lj)
    return layout, run


def test_deferred_seal_late_attach_and_stable_recompute() -> None:
    """Deferred sealing: effects attach after later hops exist, and the fold recomputes identically."""
    _lay, run = _chain()
    h1 = run.hop(Tail, "h1")
    h2 = run.hop(Tail, "h2")
    h2.frame.r30 = 1
    h2.frame.r31 = 2
    # attach AFTER h2 exists: hops are never sealed, so the late effect must still land
    h1.add_effect(cento.machine.Effect("late_wb", {h1.frame.r30: cento.machine.Writeback("out")}))
    assert run.state_at("h2")[Reg.R30].kind == "writeback"
    assert run.state_at("h2")[Reg.R30].fed_by.name == "out"
    _lay, run = _chain()
    h1 = run.hop(Tail, "h1")
    h1.frame.r30 = 0x11
    h1.frame.r31 = 0x22
    run.hop(Tail, "h2")
    first = {r: s.kind for r, s in run.state_at("h2").items()}
    second = {r: s.kind for r, s in run.state_at("h2").items()}  # recompute-from-scratch must be stable
    assert first == second


def test_unmet_needs_no_longer_raises_at_hop() -> None:
    layout = cento.Layout()
    page = layout.region("page", base="p", max_size=0x2000)
    run = page.chain("c", at=0xF0, carry=cento.Carry.Clobbered)  # no abi: everything clobbers

    # Adjudicated vs the brief (see the G2 report): the brief's NeedyTail also RESTORED R30, so
    # h1's own Load re-established R30 and nothing was ever starved (empirically: no raise
    # either). Dropping the r30 restore realizes the test's stated intent ("h1's clobbered carry
    # starves h2's need") -- construction stays silent; the fold names the starvation.
    class NeedyTail(cento.Gadget, entry=0x40002000, stride=0xB0):
        r31 = cento.Restores(Reg.R31, at=0xAC)
        pc = cento.Restores(Reg.PC, at=0xB4, external=True)
        needs = {Reg.R30: "obj handle"}

    run.enter(Lj)
    run.hop(NeedyTail, "h1")
    run.hop(NeedyTail, "h2")  # h1's clobbered carry starves h2's need -- NO raise here
    with pytest.raises(cento.errors.ChainError, match="needs"):
        run.seal()  # the early-errors escape hatch raises
    errs, _warns = run.issues()  # issues() never raises; reports CHK-201
    assert any(i.code == "CHK-201" for i in errs)


# -- Writeback as a CellValue ---------------------------------------------------------


def _built() -> tuple[cento.Layout, cento.Chain, cento.Hop]:
    layout = cento.Layout()
    page = layout.region("page", base="p", max_size=0x2000)
    run = page.chain("c", at=0xF0)
    run.enter(Lj)
    h1 = run.hop(Tail, "h1")
    h2 = run.hop(Tail, "h2")
    h2.frame.r30 = 1
    h2.frame.r31 = 2
    h2.frame.pc = 0x40003000
    return layout, run, h1


def test_writeback_feeds_dataflow_and_is_never_emitted() -> None:
    """A Writeback-valued cell forces to Promised, feeds the fold, and never reaches an emission."""
    layout, run, h1 = _built()
    h1.frame.r30.write(cento.Writeback("task_handle"))  # the comment becomes code
    got = layout.force((h1.frame.r30.region.name, h1.frame.r30.offset))
    assert isinstance(got, cento.cells.Promised) and got.name == "task_handle"
    st = run.state_at("h2")[Reg.R30]
    assert st.kind == "writeback" and st.fed_by.name == "task_handle"
    assert h1.writebacks.task_handle.name == "task_handle"
    layout.bind("p", 0x1000)
    result = layout.emit(cento.emit.Backend.SPARSE)
    key = (h1.frame.r30.region.name, h1.frame.r30.offset)
    # SPARSE artifact is {abs_addr: bytes}; exclusion = absent from artifact AND from fixups
    assert 0x1000 + key[1] not in result.artifact  # excluded from emission entirely
    assert key not in {(f.region, f.offset) for f in result.fixups}  # not deferred as a fixup either
    assert "p" not in layout.pending() and not any("task_handle" in s for s in layout.pending())


def test_writeback_legal_at_arm() -> None:
    layout, _run, h1 = _built()
    h1.frame.r30.write(cento.Writeback("task_handle"))
    layout.bind("p", 0x1000)
    plan = layout.plan()
    for g in plan.stage():
        plan.confirm(g)
    for g in plan.finalize():  # must NOT refuse on the unresolved Writeback
        plan.confirm(g)


def test_discard_is_the_clobber_waiver_scoped_to_the_derived_effect() -> None:
    """Writeback.discard waives the derived clobber -- and ONLY the derived effect's; foreign effects stay judged."""
    layout, run, h1 = _built()
    h1.frame.r30.write(cento.cells.Writeback.discard("preempt"))
    report = layout.check()
    # the unwaived-clobber code in chain.issues() is CHK-205.
    # NOTE (G4 review): the derived clobber lands in the fold's `clobbers` map, NEVER in chain.hazards, and
    # CHK-205 iterates chain.hazards only -- so `assert no CHK-205` would be VACUOUS here (it passes even with
    # the waiver plumbing deleted). The load-bearing assertion is the waiver ROW itself, keyed to the derived
    # effect name f"{hop.name}_writeback" on the exact cell (rows are (region, offset, effect, reason)).
    key = (h1.frame.r30.region.name, h1.frame.r30.offset)
    assert (key[0], key[1], "h1_writeback", "writeback.discard: preempt") in report.waivers
    assert any("preempt" in w[3] for w in report.waivers)  # reason surfaced in the report
    assert any(w[3].startswith("writeback.discard: ") for w in report.waivers)  # tagged source
    # the discard waiver is keyed (cell, "h1_writeback"): a Clobber on the SAME cell from a DIFFERENT windowed effect must still
    # be judged. Grounded trigger (chain.issues() CHK-205 arm): hz in chain.hazards, action is
    # Clobber, cell key in staged (layout.cells() -- a Writeback-valued cell IS staged) or in
    # consumed_seat_keys, and (key, hz.name) not in {allow_clobber waivers} | {derived_waivers}.
    run.hazard(cento.machine.Effect("other_hazard", {h1.frame.r30: cento.machine.CLOBBER}, window="any"))
    report = layout.check()
    hits = [i for i in report.errors if i.code == "CHK-205"]
    assert len(hits) == 1  # the foreign effect's clobber IS judged...
    assert hits[0].subjects == (f"{key[0]}+0x{key[1]:x}", "other_hazard")  # ...named for other_hazard, on this cell
    # ...while the derived-effect path stays waived (row present, and no CHK-205 attributed to it)
    assert (key[0], key[1], "h1_writeback", "writeback.discard: preempt") in report.waivers
    assert not any("h1_writeback" in i.subjects for i in report.errors)
    # and the foreign-effect judgment is suppressible ONLY by its own (cell, effect) waiver
    layout.allow_clobber(h1.frame.r30, "other_hazard", reason="test: foreign effect explicitly waived")
    rep2 = layout.check()
    assert not any(i.code == "CHK-205" for i in rep2.errors)


# -- Writeback naming -----------------------------------------------------------------


def test_writeback_rename_is_canonical() -> None:
    """Writeback is the one name: fold kinds carry it, and no alias exists."""
    wb = cento.machine.Writeback("task_handle")
    assert type(wb).__name__ == "Writeback"
    eff = cento.machine.Effect("e", {object(): wb})
    assert eff.writebacks.task_handle.name == "task_handle"
    assert cento.Writeback is cento.machine.Writeback
    assert not hasattr(cento.machine, "Supplied")
    assert not hasattr(cento.machine, "SuppliedRef")
    assert not hasattr(cento, "Supplied")
    eff = cento.machine.Effect("e", {object(): cento.machine.Writeback("x")})
    assert not hasattr(eff, "supplied")
    # the fold's effect-fed slots carry kind "writeback"
    layout = cento.Layout()
    page = layout.region("page", base="p", max_size=0x2000)

    class Lj(cento.Gadget, entry=0x40001000, frame_base=cento.Reg.R31):
        pc = cento.Restores(cento.Reg.PC, at=0x00)
        sp = cento.Restores(cento.Reg.SP, at=0x04)
        r30 = cento.Restores(cento.Reg.R30, at=0x50)
        r31 = cento.Restores(cento.Reg.R31, at=0x54)
        needs = {cento.Reg.R31: "jmp_buf"}

    class Tail(cento.Gadget, entry=0x40002000, stride=0xB0, reentry_safe=True):
        r30 = cento.Restores(cento.Reg.R30, at=0xA8)
        r31 = cento.Restores(cento.Reg.R31, at=0xAC)
        pc = cento.Restores(cento.Reg.PC, at=0xB4, external=True)

    run = page.chain("c", at=0xF0)
    run.enter(Lj)
    h1 = run.hop(Tail, "h1")
    eff = cento.machine.Effect("wb", {h1.frame.r30: cento.machine.Writeback("out")})
    h1.add_effect(eff)
    run.hop(Tail, "h2")
    assert run.state_at("h2")[cento.Reg.R30].kind == "writeback"
    assert h1.writebacks.out.name == "out"
    assert not hasattr(h1, "supplied")
