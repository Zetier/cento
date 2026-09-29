# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Checks and doctrine.

Structural validators: every issue code has a fixture that triggers it.
Rewrite-doctrine closure regressions -- statement-order irrelevance evidence.
Substrate amendments for the chain layer: overlay, ext-span CHK-003, waiver ledger.
Plan-C ledger fixes: SPARSE pending completeness, SP-clobber gate, GadgetSet cache, slice guards.
"""

from __future__ import annotations

import pathlib
import re
import typing

import pytest

import cento
import cento.catalog as catalog_mod
import cento.cells as cells
import cento.chain
import cento.checks as checks
import cento.errors as errors
import cento.gadget as gadget
import cento.machine as machine
import cento.regions as regions
import cento.views as views

# -- structural validators --------------------------------------------------------


class Hdr(views.View, size=8):
    magic = views.Field(0, views.u32)
    csum = views.Field(6, views.u16)


class Frame(views.View, size=0x10):
    a = views.Field(0x8, views.u32)
    lr = views.Field(0x14, views.u32, external=True)


def codes(report: checks.Report) -> set[str]:
    return {i.code for i in report.errors} | {i.code for i in report.warnings}


def test_overlap_declaration_checks() -> None:
    """The overlap-declaration family: CHK-001 undeclared overlap, CHK-003 declared-but-disjoint alias,
    CHK-101 external-span overlap warning."""
    layout = regions.Layout()
    pkt = layout.region("pkt")
    pkt.at(0, Hdr, "a")
    pkt.at(4, Hdr, "b")
    assert "CHK-001" in codes(layout.check())
    lay2 = regions.Layout()
    p2 = lay2.region("pkt")
    p2.at(0, Hdr, "a")
    p2.at(4, Hdr, "b", over="a", why="test alias")
    assert "CHK-001" not in codes(lay2.check())
    layout = regions.Layout()
    pkt = layout.region("pkt")
    pkt.at(0, Hdr, "a")
    pkt.at(0x40, Hdr, "b", over="a", why="wrong: does not intersect")
    assert "CHK-003" in codes(layout.check())
    layout = regions.Layout()
    pkt = layout.region("pkt")
    pkt.at(0, Frame, "f")  # external lr span [0x14,0x18)
    pkt.at(0x10, Hdr, "next")  # overlaps that span, no over=
    report = layout.check()
    assert "CHK-101" in {i.code for i in report.warnings}


def test_chk002_max_size() -> None:
    layout = regions.Layout()
    pkt = layout.region("pkt", max_size=8)
    pkt[0x6] = 0x11223344  # cell end 0xA > 8: raw cells stay constructible (see test_adversarial_gates), judged at check
    assert "CHK-002" in codes(layout.check())


def test_chk012_cross_region_absolute_overlap() -> None:
    layout = regions.Layout()
    a = layout.region("a", max_size=0x20)
    b = layout.region("b", max_size=0x20)
    a[0] = 1
    b[0] = 2
    layout.bind("a_base", 0x1000)
    layout.bind("b_base", 0x1010)  # inside a's [0x1000, 0x1020)
    hits = [i for i in layout.check().errors if i.code == "CHK-012"]
    assert len(hits) == 1 and hits[0].subjects == ("a", "b")
    assert "overlapping absolute ranges" in hits[0].msg
    layout.bind("b_base", 0x2000)  # rebased apart: clean
    assert "CHK-012" not in codes(layout.check())
    lay2 = regions.Layout()  # unbound bases are never judged (fail closed elsewhere: sparse refuses on them)
    lay2.region("a", max_size=0x20)
    lay2.region("b", max_size=0x20)
    assert "CHK-012" not in codes(lay2.check())
    lay3 = regions.Layout()  # no max_size: extent comes from content; an empty bound region (extent 0) is never flagged
    c = lay3.region("c")
    c[0] = 1  # content extent [0, 4): the cell's end
    lay3.region("d", max_size=0x20)
    lay3.region("e")  # bound but empty: extent 0
    lay3.bind("c_base", 0x1000)
    lay3.bind("d_base", 0x1002)  # inside c's content extent [0x1000, 0x1004)
    lay3.bind("e_base", 0x1001)  # strictly inside c's content extent: only the extent-0 skip keeps e out of the flags
    hits3 = [i for i in lay3.check().errors if i.code == "CHK-012"]
    assert len(hits3) == 1 and hits3[0].subjects == ("c", "d")
    lay4 = regions.Layout()  # running cover: a big span keeps covering past a contained neighbor's end
    lay4.region("big", max_size=0x100)
    lay4.region("small", max_size=0x10)
    lay4.region("late", max_size=0x20)
    lay4.bind("big_base", 0x1000)
    lay4.bind("small_base", 0x1010)  # contained inside big
    lay4.bind("late_base", 0x1050)  # past small's end, still under big's cover
    pairs = sorted(i.subjects for i in lay4.check().errors if i.code == "CHK-012")
    assert pairs == [("big", "late"), ("big", "small")]  # a naive adjacent-pairwise sweep would miss ("big", "late")


def test_chk013_useless_bind_warns_with_hint() -> None:
    layout = regions.Layout()
    pkt = layout.region("pkt", max_size=0x10)
    pkt[0] = layout.sym("cookie")
    layout.bind("cokie", 0x1234)  # the typo under test
    hits = [i for i in layout.check().warnings if i.code == "CHK-013"]
    assert len(hits) == 1 and hits[0].subjects == ("cokie",)
    assert "did you mean 'cookie'" in hits[0].hint
    layout.bind("cookie", 0x1234)  # binding the real name too: the typo'd bind still sits there, hint intact
    hits = [i for i in layout.check().warnings if i.code == "CHK-013"]
    assert len(hits) == 1 and "did you mean 'cookie'" in hits[0].hint
    lay2 = regions.Layout()  # base symbols and expect_sym declarations are legitimate bind targets
    lay2.region("pkt", max_size=0x10)
    lay2.bind("pkt_base", 0x1000)
    lay2.expect_sym("win", range=(0x1000, 0x2000))
    lay2.bind("win", 0x1800)
    assert "CHK-013" not in codes(lay2.check())


def test_chk014_cross_layout_xform_leakage() -> None:
    layout = regions.Layout()
    page = layout.register_xform("pg", lambda v: v >> 12)
    other = regions.Layout()
    o = other.region("o", max_size=0x10)
    o[0x0] = page(other.sym("base"))  # the constructor is layout-scoped; this layout never registered it
    other.bind("base", 0x1000)
    hits = [i for i in other.check().errors if i.code == "CHK-014"]
    assert len(hits) == 1 and "pg" in hits[0].msg
    with pytest.raises(errors.XformError, match="unknown xform 'pg'"):
        other.image("o", final=False)  # draft: the cell's own recorded error raises directly (recipe-2 idiom)
    with pytest.raises(errors.EmitError, match="CHK-014"):
        other.image("o")  # final (the default): the gate speaks first, embedding the CHK line


def test_reduce_checks() -> None:
    """Reduce cells are judged structurally: CHK-005 expect mismatch, CHK-007 self-including cycle."""
    layout = regions.Layout()
    pkt = layout.region("pkt", fill=0)
    pkt.cell(0, width=2).write(0xDEAD)
    pkt.cell(2, width=2).write(cells.sum16(pkt[0:2], expect=0x1111))  # actual 0xDEAD
    assert "CHK-005" in codes(layout.check())
    layout = regions.Layout()
    pkt = layout.region("pkt", fill=0)
    pkt.cell(0, width=2).write(cells.sum16(pkt[0:4]))
    assert "CHK-007" in codes(layout.check())


def test_chk006_conflicting_bytes_vs_agreeing() -> None:
    layout = regions.Layout()
    pkt = layout.region("pkt")
    pkt.cell(0, width=4).write(0xDEADBEEF)
    pkt.cell(2, width=2).write(0xDEAD)  # overlaps, same bytes (little-endian: ad de) -> OK
    assert "CHK-006" not in codes(layout.check())
    pkt.cell(2, width=2).write(0x1234)  # overlaps, different bytes
    assert "CHK-006" in codes(layout.check())


def test_report_canonical_and_render() -> None:
    layout = regions.Layout()
    pkt = layout.region("pkt")
    pkt.cell(0).write("unbound")
    report = layout.check()
    j = report.to_json()
    assert j["pending"] == ["unbound"]
    assert isinstance(report.render(), str) and "pending" in report.render()


def test_chk008_rewrite_contract() -> None:
    """CHK-008 rewrite doctrine: same-owner updates are silent; different-owner rewrites error naming
    both owners; allow_rewrite() (by handle or by the error's own path) waives onto its own ledger."""
    layout = regions.Layout()
    pkt = layout.region("pkt")
    pkt.cell(0).write(1)  # owner pkt.raw+0x0
    pkt.cell(0).write(2)  # SAME owner: intra-owner update, not a collision
    assert "CHK-008" not in codes(layout.check())
    assert layout.rewrites == []
    layout = regions.Layout()
    pkt = layout.region("pkt")
    h = pkt.at(0, Hdr, "h")
    h.magic = 1  # owner pkt.h.magic
    pkt.cell(0).write(2)  # owner pkt.raw+0x0: silently clobbers h.magic (last-writer-wins)
    report = layout.check()
    hits = [i for i in report.errors if i.code == "CHK-008"]
    assert len(hits) == 1
    assert hits[0].subjects == ("pkt.h.magic", "pkt.raw+0x0")
    assert "CHK-006" not in codes(report)  # exact-key collision: CHK-006 is structurally blind here
    layout = regions.Layout()
    pkt = layout.region("pkt")
    h = pkt.at(0, Hdr, "h")
    h.magic = 1
    pkt.cell(0).write(2)
    layout.allow_rewrite(pkt.cell(0), reason="intentional override for test")
    report = layout.check()
    assert "CHK-008" not in codes(report)
    j = report.to_json()
    assert j["rewrite_waivers"] == [["pkt", 0, "intentional override for test"]]
    assert j["waivers"] == []  # clobber waivers stay a separate ledger
    layout = regions.Layout()
    pkt = layout.region("pkt")
    h = pkt.at(0, Hdr, "h")
    h.magic = 1
    pkt.cell(0).write(2)  # different owner: CHK-008
    layout.allow_rewrite("pkt.h.magic", reason="test: paste the error's own path")
    report = layout.check()
    assert "CHK-008" not in codes(report)
    assert layout.rewrite_waivers == [(("pkt", 0), "test: paste the error's own path")]


def test_render_waiver_ledger_is_verbose_only() -> None:
    layout = regions.Layout()
    pkt = layout.region("pkt", max_size=8)
    pkt.cell(0).write(1)
    layout.allow_rewrite(pkt.cell(0), reason="deliberate override")
    pkt.at(0, Hdr, "h").magic = 2
    report = layout.check()
    assert "1 waiver on the ledger" in report.render()  # the count is always in the head...
    assert "deliberate override" not in report.render()  # ...but settled business stays quiet by default
    assert "waived rewrite pkt+0x0000: deliberate override" in report.render(verbose=True)  # the review view


def test_chk009_width_judgment() -> None:
    """CHK-009: full addresses that do not fit refuse (wrong chain, not a wrap); slices and Deltas
    keep their documented wrap semantics."""
    layout = regions.Layout()
    pkt = layout.region("pkt")
    pkt.cell(0, width=4).write(layout.sym("base") + 0x10)  # a full address into a u32 cell
    layout.bind("base", 0x1_0000_0000, source="test")  # resolves to 33 bits: wrong chain, not a wrap
    report = layout.check()
    hits = [i for i in report.errors if i.code == "CHK-009"]
    assert len(hits) == 1 and "does not fit the 4-byte cell" in hits[0].msg
    with pytest.raises(errors.WidthError, match="0x100000010 does not fit"):
        layout.force(("pkt", 0))
    layout = regions.Layout()
    pkt = layout.region("pkt")
    pkt.cell(0, width=2).write(cells.lo16(layout.sym("base")))  # deliberate slice: wraps by design
    pkt.cell(2, width=2).write(cells.Delta(layout.sym("base"), layout.sym("site")))  # Delta: documented wrap
    layout.bind("base", 0x1_2345_6789, source="test")
    layout.bind("site", 0x1_2345_0000, source="test")
    assert "CHK-009" not in codes(layout.check())
    assert layout.force(("pkt", 0)) == (0x6789).to_bytes(2, "little")


def test_chk010_density_contract() -> None:
    """CHK-010: dense views refuse unset fields until satisfied, owner-keyed (an alias's bytes do not
    count); sparse views stay silent by design."""

    class DenseHdr(views.View, dense=True):
        a = views.Field(0, views.u32)
        b = views.Field(4, views.u32)
        lr = views.Field(0x10, views.u32, external=True)  # external: not part of the density promise

    layout = regions.Layout()
    pkt = layout.region("pkt")
    h = pkt.at(0, DenseHdr, "h")
    h.a = 1  # b never written
    report = layout.check()
    hits = [i for i in report.errors if i.code == "CHK-010"]
    assert len(hits) == 1
    assert hits[0].subjects == ("pkt.h",) and "another owner: b" in hits[0].msg
    h.b = 2  # density satisfied: the error retires
    assert "CHK-010" not in codes(layout.check())
    layout = regions.Layout()
    pkt = layout.region("pkt")
    hh = pkt.at(0, Hdr, "h")  # not dense: unset fields are fill, by design (the SROP-frame idiom)
    hh.magic = 1
    assert "CHK-010" not in codes(layout.check())

    class DensePair(views.View, dense=True):
        a = views.Field(0, views.u32)
        b = views.Field(4, views.u32)

    layout = regions.Layout()
    pkt = layout.region("pkt")
    hh = pkt.at(0, Hdr, "h")
    hh.magic = 1  # bytes exist at pkt+0 -- but they are h's, not the dense view's
    d = pkt.at(0, DensePair, "d", over=("h",), why="test alias")
    d.b = 2
    report = layout.check()
    hits = [i for i in report.errors if i.code == "CHK-010"]
    assert len(hits) == 1 and "another owner: a" in hits[0].msg  # a is covered by h.magic's bytes, never written by d


# -- rewrite doctrine closure --------------------------------------------------------
#
# (1) chain-flavored spec-order alloc: with the reserve_external=True default, an alloc issued in
# spec order (BEFORE finish) lands past the last chain frame's external continuation span, so
# finish()'s pc wire cannot collide with it; (2) a genuine same-key different-owner rewrite (the
# unreserved shape, forced via reserve_external=False) is a CHK-008 ERROR naming both owners; (3)
# layout.allow_rewrite(cell, reason=...) clears it and the reason surfaces in Report.rewrite_waivers.
# Arms (2)/(3) are doctrine regressions, not bug reproducers: they may pass from birth.

Reg = cento.Reg


class Lj(cento.Gadget, entry=0x40001000, frame_base=Reg.R31):
    pc = cento.Restores(Reg.PC, at=0x00)
    sp = cento.Restores(Reg.SP, at=0x04)
    r30 = cento.Restores(Reg.R30, at=0x50)
    r31 = cento.Restores(Reg.R31, at=0x54)
    needs = {Reg.R31: "jmp_buf"}


class Tail(cento.Gadget, entry=0x40002000, stride=0xB0, reentry_safe=True):
    r30 = cento.Restores(Reg.R30, at=0xA8)
    r31 = cento.Restores(Reg.R31, at=0xAC)
    pc = cento.Restores(Reg.PC, at=0xB4, external=True)  # caller-frame LR slot: finish() wires the next entry here


class Pair(cento.View, size=8):
    lo = cento.Field(0, cento.u32)
    hi = cento.Field(4, cento.u32)  # at frame-end + 4 == the external pc slot when bump-allocated flush against the frame


def _chain(page: cento.Region) -> cento.Chain:
    run = page.chain("c", at=0xF0)
    run.enter(Lj)
    run.hop(Tail, "h1")  # frame [0xF0,0x1A0); external pc span [0x1A4,0x1A8)
    return run


def test_rewrite_doctrine_closure() -> None:
    """Three arms: spec-order alloc lands clear of the external span; the unreserved
    reorder-dodge shape is a CHK-008 ERROR naming both owners; allow_rewrite waives with the reason
    on the ledger."""
    layout = cento.Layout()
    page = layout.region("page", base="p", max_size=0x1000)
    run = _chain(page)
    w = page.alloc(Pair, "w")  # SPEC ORDER: before finish
    assert w.offset == 0x1A8  # past the external span END (0x1A8), not the 0x1A0 frame extent
    w.hi = 0xDEAD0001
    run.finish(Lj, pc=0x40004000, sp=0x100)  # wires h1's external pc slot at 0x1A4 -- disjoint from w
    assert layout.rewrites == []  # no same-key rewrite was even recorded
    report = layout.check()
    assert not any(i.code == "CHK-008" for i in report.errors)
    assert report.errors == []
    # the reorder-dodge shape:
    # reserve_external=False bump-alloc puts w.hi under h1's external pc slot; finish()'s pc wire
    # is a genuine same-key different-owner rewrite -> CHK-008 ERROR.
    layout = cento.Layout()
    page = layout.region("page", base="p", max_size=0x1000)
    run = _chain(page)
    w = page.alloc(Pair, "w", reserve_external=False)
    assert w.offset == 0x1A0  # unreserved bump: flush against the frame extent; w.hi == 0x1A4 == h1's pc slot
    w.hi = 0xDEAD0001
    run.finish(Lj, pc=0x40004000, sp=0x100)  # last-writer-wins over w.hi, silent at construction
    assert ((("page", 0x1A4), "page.w.hi", "page.c.h1.pc")) in layout.rewrites
    report = layout.check()
    hits = [i for i in report.errors if i.code == "CHK-008"]
    assert len(hits) == 1
    assert hits[0].subjects == ("page.w.hi", "page.c.h1.pc")  # both owners named
    layout = cento.Layout()
    page = layout.region("page", base="p", max_size=0x1000)
    run = _chain(page)
    w = page.alloc(Pair, "w", reserve_external=False)
    w.hi = 0xDEAD0001
    run.finish(Lj, pc=0x40004000, sp=0x100)
    layout.allow_rewrite(w.hi, reason="test: pc wire deliberately overrides the staged word")
    report = layout.check()
    assert not any(i.code == "CHK-008" for i in report.errors)
    assert ("page", 0x1A4, "test: pc wire deliberately overrides the staged word") in report.rewrite_waivers


# -- substrate amendments for the chain layer ----------------------------------------


class FrameSubstrate(views.View, size=0x10):
    r30 = views.Field(0x8, views.u32)
    pc = views.Field(0x14, views.u32, external=True)


class Slot(views.View, size=0x8):
    val = views.Field(0x4, views.u32)


def test_overlay_contract() -> None:
    """ViewHandle.overlay(): places with over/why (why keyword-REQUIRED), and also_over covers a
    spill into a second placement -- without it the spill is still CHK-001."""
    layout = regions.Layout()
    page = layout.region("page")
    ff = page.at(0x40, FrameSubstrate, "ff")
    kd = ff.overlay(Slot, at=0x4, name="kd", why="writeback lands in ff.r30")
    assert isinstance(kd, regions.ViewHandle) and kd.offset == 0x44
    rec = next(p for p in page.placements if p.name == "kd")
    assert rec.over == ("ff",) and rec.why is not None
    with pytest.raises(TypeError):
        ff.overlay(Slot, at=0x4)  # type: ignore[call-overload]  # why is keyword-REQUIRED
    layout = regions.Layout()
    page = layout.region("page")
    s0 = page.at(0x00, Slot, "s0")
    page.at(0x08, Slot, "s1")
    kd = s0.overlay(Slot, at=0x4, name="kd", why="kd spills past s0 into s1", also_over=("s1",))
    assert isinstance(kd, regions.ViewHandle) and kd.offset == 0x4
    rec = next(p for p in page.placements if p.name == "kd")
    assert rec.over == ("s0", "s1")
    assert {"CHK-001", "CHK-003"} & codes(layout.check()) == set()
    layout = regions.Layout()
    page = layout.region("page")
    s0 = page.at(0x00, Slot, "s0")
    page.at(0x08, Slot, "s1")
    s0.overlay(Slot, at=0x4, name="kd", why="spills into s1 but does not name it")
    assert "CHK-001" in codes(layout.check())


def test_chk003_ext_span_adjacency() -> None:
    """CHK-003 counts external spans as intersection: ext-span adjacency passes, fully-disjoint still rejects."""
    layout = regions.Layout()
    page = layout.region("page")
    page.at(0x00, FrameSubstrate, "f0")
    page.at(0x10, FrameSubstrate, "f1", over="f0", why="f0.pc external slot lives in f1")
    report = layout.check()
    assert "CHK-003" not in codes(report) and "CHK-101" not in codes(report)
    layout = regions.Layout()
    page = layout.region("page")
    page.at(0x00, FrameSubstrate, "a")
    page.at(0x100, FrameSubstrate, "b", over="a", why="wrong: fully disjoint")
    assert "CHK-003" in codes(layout.check())


def test_allow_clobber_ledger_in_report() -> None:
    layout = regions.Layout()
    page = layout.region("page")
    cellh = page.cell(0x20)
    cellh.write(1)
    layout.allow_clobber(cellh, "preempt_writeback", reason="dead slot")
    assert layout.clobber_waivers == [(("page", 0x20), "preempt_writeback", "dead slot")]
    j = layout.check().to_json()
    assert j["waivers"] == [["page", 32, "preempt_writeback", "dead slot"]]


def test_chains_registry_consumed_by_checks() -> None:
    layout = regions.Layout()

    class FakeChain:
        def issues(self) -> tuple[list[checks.Issue], list[checks.Issue]]:
            return (
                [checks.Issue("CHK-201", ("h1",), "unmet need", "seat it")],
                [checks.Issue("CHK-202", ("h2",), "unfed seat", "stage or supply")],
            )

    # The registry is typed for real Chains; run_checks itself stays structural (issues() +
    # tolerant getattr for fold/hops), so an issues()-only stand-in casts in deliberately.
    layout.chains["c1"] = typing.cast(cento.chain.Chain, FakeChain())
    report = layout.check()
    assert "CHK-201" in {i.code for i in report.errors} and "CHK-202" in {i.code for i in report.warnings}


# -- Plan-C ledger fixes ---------------------------------------------------------------

FIXTURE = str(pathlib.Path(__file__).parent / "fixtures" / "catalog_v2.json")


def test_sparse_pending_includes_base_of_residual_cell() -> None:
    layout = regions.Layout()
    pkt = layout.region("pkt")  # base unbound
    pkt.cell(0).write("late_sym")  # value ALSO unbound
    result = layout.emit(cento.Backend.SPARSE, final=False)  # the draft read: pending is the point, the gate would refuse
    assert "pkt_base" in result.pending and "late_sym" in result.pending


def test_clobbers_sp_on_sp_frame_raises() -> None:
    with pytest.raises(errors.ChainError, match="SpAdd"):

        class Bad(gadget.Gadget, entry=0x1000, stride=0x10):
            pc = gadget.Restores(machine.Reg.PC, at=0x14, external=True)
            spk = gadget.Clobbers(machine.Reg.SP)


def test_gadget_set_cached_across_calls() -> None:
    cat = catalog_mod.Catalog.load(FIXTURE)
    assert cat.gadgets("DemoAS") is cat.gadgets("DemoAS")
    assert cat.gadgets("DemoAS").SYSCALL_TAIL is cat.gadgets("DemoAS").SYSCALL_TAIL


def test_slice_and_key_guards() -> None:
    layout = regions.Layout()
    pkt = layout.region("pkt")
    with pytest.raises(errors.PlacementError, match="end"):
        _ = pkt[4:]
    with pytest.raises(errors.PlacementError, match="int"):
        _ = pkt[3]  # type: ignore[call-overload]  # booby-trap probe: int index is statically banned; runtime raise is the assertion


def test_import_boundary_no_repo_tooling() -> None:
    """cento must not import repo-tooling namespaces (emulation/, config/, scripts/)."""
    pkg = pathlib.Path(cento.__file__).parent
    bad = re.compile(r"^\s*(?:import (?:emulation|scripts|config)\b|from (?:emulation|scripts|config)\b)")
    offenders = [f"{p.relative_to(pkg)}:{n}" for p in sorted(pkg.rglob("*.py")) for n, line in enumerate(p.read_text().splitlines(), 1) if bad.match(line)]
    assert offenders == [], f"cento imports lab namespaces: {offenders}"


# -- CHK-011: transport constraint (region forbid=) ---------------------------


def test_chk011_transport_constraint() -> None:
    """CHK-011 forbid= doctrine: resolved bytes are flagged and gate final emit; symbols are judged
    when they resolve (writebacks never); a conflicting fill refuses at declaration."""
    layout = cento.Layout()
    pkt = layout.region("pkt", max_size=0x10, fill=0x41, forbid=0x00)
    pkt[0:4] = 0x40001000  # little-endian 00 10 00 40: the gadget address itself carries NULs
    report = layout.check()
    bad = [i for i in report.errors if i.code == "CHK-011"]
    assert len(bad) == 1 and bad[0].subjects == ("pkt.raw+0x0",)
    assert "0x00" in bad[0].msg
    with pytest.raises(cento.EmitError, match="CHK-011"):
        layout.emit("image")
    pkt[0:4] = 0x40101010  # a sibling address the transport survives
    assert not [i for i in layout.check().errors if i.code == "CHK-011"]
    layout.emit("image")
    layout = cento.Layout()
    pkt = layout.region("pkt", max_size=0x10, fill=0x41, forbid=b"\x00\x0a")
    pkt[0:4] = "leak"
    pkt.cell(0x8, 4).write(cells.Writeback("kernel_writes"))  # runtime-written: never judged
    assert not [i for i in layout.check().errors if i.code == "CHK-011"]  # residual: judged on resolve
    layout.bind("leak", 0x11223344, source="t")
    assert not [i for i in layout.check().errors if i.code == "CHK-011"]
    layout.bind("leak", 0x1122330A, source="t")  # rebind lands on the forbidden 0x0a
    assert [i for i in layout.check().errors if i.code == "CHK-011"]
    layout = cento.Layout()
    with pytest.raises(errors.PlacementError, match="fill contains forbidden transport byte"):
        layout.region("pkt", max_size=0x10, forbid=0x00)  # default fill 0x00 clashes
    with pytest.raises(errors.PlacementError, match="at least one byte"):
        layout.region("pkt2", fill=0x41, forbid=b"")
