# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Adversarial gates: regression pins for proven fail-open constructions.

Every test here reproduces a construction that would emit wrong bytes silently or pass the
final gate while unsound; the refusal (or the correct bytes) pins the defense.
"""

from __future__ import annotations

import pytest

import cento
import cento.cells as cells
import cento.errors as errors
import cento.gadget as gadget
import cento.machine as machine

Reg = machine.Reg


class Entry(gadget.Gadget, entry=0x40001000, frame_base=Reg.R31):
    pc = gadget.Restores(Reg.PC, at=0x0)
    sp = gadget.Restores(Reg.SP, at=0x4)
    r30 = gadget.Restores(Reg.R30, at=0x8)  # the upstream slot later hops' r30 seats write into
    needs = {Reg.R31: "hijack pointer"}


class Tail(gadget.Gadget, entry=0x40002000, stride=0x40, reentry_safe=True):
    r30 = gadget.Restores(Reg.R30, at=0x38)
    r31 = gadget.Restores(Reg.R31, at=0x3C)
    pc = gadget.Restores(Reg.PC, at=0x44, external=True)
    needs = {Reg.R30: "selector"}


def test_image_never_relocates_out_of_cap_cells() -> None:
    # the trap: a bytearray slice-assign past the cap would APPEND, silently moving the cell's bytes
    r = cento.region("r", max_size=0x10)
    r[0x0:0x4] = 0x11111111
    r.cell(0x20, width=4).write(0x41414141)  # past the cap: must never land at 0x10
    img = r.image(final=False)  # the draft read: CHK-002 stands, so the gate would (rightly) refuse
    assert len(img) == 0x10 and img[0x4:] == b"\x00" * 0xC  # no relocation, no growth
    straddle = cento.region("s", max_size=0x10)
    straddle.cell(0xE, width=4).write(0x42424242)  # straddles the cap: clipped, not grown
    assert len(straddle.image(final=False)) == 0x10 and straddle.image(final=False)[0xE:] == b"\x42\x42"
    assert "CHK-002" in {i.code for i in r.layout.check().errors}  # the overrun is still named


def test_dangling_continuation_warns_at_check_and_refuses_at_final() -> None:
    layout = cento.Layout()
    page = layout.region("page", base="p", max_size=0x200)
    run = page.chain("c", at=0x100)
    run.enter(Entry)
    h = run.hop(Tail, "h")
    h.r30 = 1
    report = layout.check()  # advisory mid-build: a warning, not an error
    assert "CHK-206" in {i.code for i in report.warnings} and not report.errors
    layout.bind("p", 0x1000, source="t")
    with pytest.raises(errors.EmitError, match="dangling continuation"):
        layout.emit(cento.Backend.IMAGE)
    run.finish_in_kernel(pc=0x40003000)  # wiring the continuation retires both
    assert "CHK-206" not in {i.code for i in layout.check().warnings}
    assert layout.emit(cento.Backend.IMAGE).artifact["page"]


def test_writeback_slot_overlap_is_chk204_even_off_key() -> None:
    layout = cento.Layout()
    page = layout.region("page", base="p", max_size=0x200)
    run = page.chain("c", at=0x100)
    run.enter(Entry)
    mint = run.hop(Tail, "mint")
    mint.r30 = 7
    mint.frame.r30 = cells.Writeback("handle")
    run.hop(Tail, "spend")
    run.finish_in_kernel(pc=0x40003000)
    wb = mint.frame.r30
    page.cell(wb.offset + 2, width=2).write(0x4545)  # off-key, inside the slot: tears the runtime write
    hits = [i for i in layout.check().errors if i.code == "CHK-204"]
    assert hits and "overlapping" in hits[0].msg


def test_unseated_need_escalates_only_when_finished_and_not_entry() -> None:
    layout = cento.Layout()
    page = layout.region("page", base="p", max_size=0x200)
    run = page.chain("c", at=0x100)
    run.enter(Entry)
    run.hop(Tail, "h")  # h.r30 never seated
    codes_before = {i.code for i in layout.check().errors}
    assert "CHK-202" not in codes_before  # building: provisional
    run.finish_in_kernel(pc=0x40003000)
    report = layout.check()
    assert any(i.code == "CHK-202" and i.subjects[0] == "c.h" for i in report.errors)  # finished: error
    assert all(not (i.code == "CHK-202" and i.subjects[0] == "c.enter") for i in report.errors)  # entry needs stay runtime-fed


def test_pristine_pad_words_are_scaffolding_not_rewrites() -> None:
    class Hdr(cento.View):
        op: cento.u32
        dst: cento.u32

    frame = cento.region("frame", max_size=0x20, pad=4)
    h = frame.at(0x8, Hdr, name="hdr")
    h.op = 1  # over a pristine pad word: the pad exists to be overwritten
    h.dst = 2
    assert "CHK-008" not in {i.code for i in frame.layout.check().errors}
    frame.cell(0x8).write(9)  # over hdr.op -- a REAL belief now: still judged
    assert "CHK-008" in {i.code for i in frame.layout.check().errors}


def test_rewrite_invalidates_symbol_deps_for_dirty() -> None:
    layout = cento.Layout()
    r = layout.region("r", max_size=8)
    r.cell(0).write(layout.sym("a"))
    layout.bind("a", 1, source="t")
    layout.force(("r", 0))
    r.cell(0).write(layout.sym("b"))  # same owner: silent update, deps must follow
    layout.bind("b", 2, source="t")
    layout.force(("r", 0))
    assert layout.dirty("a") == set()  # the replaced symbol must not linger as a ghost dependency
    assert layout.dirty("b")  # the live dependency reports


def test_reduce_span_rewrite_drops_transitive_ghost_dep() -> None:
    # the trap: if a Reduce cell unioned covered-cell deps from a stale store, a covered
    # cell's REPLACED symbol would haunt dirty() through the reduce forever. Resolution
    # snapshots rebuild deps whole: the ghost cannot survive a rewrite.
    layout = cento.Layout()
    r = layout.region("r", max_size=0x20)
    r[0:4] = "a"
    r[4:6] = cento.sum16(r[0:4])
    layout.pending()  # force once: the reduce transitively depends on "a"
    r[0:4] = "b"  # rewrite: "a" is dead everywhere, including transitively
    layout.bind("b", 5, source="t")
    assert layout.dirty("a") == set()
    assert layout.dirty("b") == {("r", 0), ("r", 4)}  # the reduce cell reports its LIVE transitive dep


def test_cell_revalue_does_not_accumulate_deps_monotonically() -> None:
    # the trap: if forcing reused one dependency set across revalues, a cell that once
    # said sym1 would keep saying it after being revalued to sym2.
    layout = cento.Layout()
    q = layout.region("q", max_size=0x10)
    q[0:4] = "sym1"
    layout.pending()
    q[0:4] = "sym2"
    layout.pending()
    assert layout.dirty("sym1") == set()
    assert layout.dirty("sym2") == {("q", 0)}


def test_plan_finalize_refuses_dangling_continuation_like_emit_final() -> None:
    # the trap: finalize() ARMing a chain that the final emit refuses -- gate drift
    layout = cento.Layout()
    page = layout.region("page", base="p", max_size=0x200)
    run = page.chain("c", at=0x100)
    run.enter(Entry)
    h = run.hop(Tail, "h")
    h.r30 = 1
    plan = layout.plan()
    plan.bind("p", 0x1000, source="t")
    for g in plan.stage():
        plan.confirm(g)
    with pytest.raises(errors.EmitError, match="dangling continuation"):
        plan.finalize()
