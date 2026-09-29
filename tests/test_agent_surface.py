# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Agent-facing surface: preflight verdicts, the CHK catalog, and fail-closed construction.

These affordances exist so tooling (AI agents included) can drive the fix loop on data
instead of parsing refusal strings. The pins here keep them honest: preflight agrees with
the final gate, the catalog covers every code the library can emit, and the endian-typo and
raw-literal-overflow constructions stay fail-closed.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
import re

import pytest

import cento
import cento.abi
import cento.catalog
import cento.cells
import cento.checks
import cento.errors
import cento.gadget
import cento.machine
import cento.regions

Reg = cento.Reg


class Hdr(cento.View, size=8):
    magic: cento.u32
    target: cento.u32


def test_preflight_agrees_with_the_final_gate() -> None:
    layout = cento.Layout()
    pkt = layout.region("pkt", max_size=0x40)
    h = pkt.at(0, Hdr, "h")
    h.magic = 1
    h.target = "win"
    pf = layout.preflight()
    assert not pf.shippable and pf.pending == ("win",) and not pf.report.errors
    with pytest.raises(cento.EmitError):
        layout.emit("image")
    layout.bind("win", 0x1234, source="test")
    pf = layout.preflight()
    assert pf.shippable and pf.pending == () and pf.dangling == ()
    layout.emit("image")  # the verdict and the gate agree in both directions


def test_preflight_reports_dangling_chain_that_check_only_warns_about() -> None:
    # The motivating case: check().errors == [] is NOT a shippability predicate -- a dangling
    # chain is a CHK-206 WARNING at check() but a refusal at the gate. preflight() must say so.
    class Entry(cento.Gadget, entry=0x40001000, stride=0x10):
        pc = cento.Restores(Reg.PC, at=0x0)

    layout = cento.Layout()
    scratch = layout.region("scratch", max_size=0x100)
    scratch.bind("scratch_base", 0x2000)
    ch = scratch.chain("c", at=0x40)
    ch.enter(Entry)
    pf = layout.preflight()
    assert not pf.report.errors  # check() alone would look clean
    assert not pf.shippable and pf.dangling == (("c", "scratch.c.enter.pc"),)
    j = pf.to_json()
    assert j["shippable"] is False and j["dangling"] == [["c", "scratch.c.enter.pc"]]
    ch.finish_in_kernel(pc=0x40002000)
    assert layout.preflight().shippable


def test_report_diff_is_the_progress_signal() -> None:
    layout = cento.Layout()
    pkt = layout.region("pkt", max_size=0x40)
    a = pkt.at(0, Hdr, "a")
    a.magic = 1
    pkt[0] = 2  # raw rewrite of a.magic's cell: CHK-008
    prev = layout.check()
    assert {i.code for i in prev.errors} == {"CHK-008"}
    layout.allow_rewrite(a.magic, reason="test: the raw patch over a.magic is the point")
    pkt.at(4, Hdr, "b")  # NEW issue: undeclared overlap with a
    cur = layout.check()
    d = cur.diff(prev)
    assert [i.code for i in d.fixed] == ["CHK-008"]
    assert [i.code for i in d.new] == ["CHK-001"]
    assert d.remaining == ()
    assert cur.diff(cur).fixed == () and cur.diff(cur).new == ()
    j = d.to_json()
    assert [i["code"] for i in j["new"]] == ["CHK-001"]


def test_preflight_carries_the_cell_fixup_worklist() -> None:
    layout = cento.Layout()
    pkt = layout.region("pkt", max_size=0x40)
    h = pkt.at(0, Hdr, "h")
    h.magic = 1
    h.target = "win"
    pf = layout.preflight()
    assert [(f.region, f.offset, f.width, f.owner, f.missing) for f in pf.fixups] == [("pkt", 4, 4, "pkt.h.target", ("win",))]
    assert pf.to_json()["fixups"] == [{"region": "pkt", "offset": 4, "width": 4, "owner": "pkt.h.target", "missing": ["win"]}]
    layout.bind("win", 0x1234, source="test")
    assert layout.preflight().fixups == ()


def test_manifest_is_the_dependency_record() -> None:
    layout = cento.Layout()
    pkt = layout.region("pkt", max_size=0x40)
    h = pkt.at(0, Hdr, "h")
    h.magic = 1
    h.target = "win"
    layout.expect_sym("win", align=4)
    layout.bind("other", 0x10, source="test leak")
    j = layout.to_json()
    assert j["name"] is None and j["abi"] == {"endian": "little"}  # auto-named: excluded for determinism; abi block carries the operative endian
    assert j["provenance"]["target_name"] is None  # hand-built: honest nulls
    reg = j["regions"][0]
    assert reg["name"] == "pkt" and reg["base_sym"] == "pkt_base" and reg["base"] is None and reg["max_size"] == 0x40
    assert reg["placements"][0]["path"] == "pkt.h" and reg["placements"][0]["extent"] == 8
    cells = {(c["region"], c["offset"]): c for c in j["cells"]}
    tgt = cells[("pkt", 4)]
    assert tgt["owner"] == "pkt.h.target" and tgt["value"] == "win" and tgt["missing"] == ["win"] and tgt["resolved"] is None
    assert tgt["deps"] == ["win"] and tgt["deliver"] == "NORMAL"
    magic = cells[("pkt", 0)]
    assert magic["resolved"] == "01000000" and magic["missing"] is None  # 1 as u32 little-endian: (1).to_bytes(4, "little").hex()
    assert j["binds"] == [{"sym": "other", "value": 0x10, "source": "test leak"}]
    assert j["expectations"] == [{"sym": "win", "range": None, "align": 4}]
    assert j["pending"] == ["win"]
    layout2 = cento.Layout(name="named")
    assert layout2.to_json()["name"] == "named"


def test_manifest_abi_block_exports_the_declared_facts() -> None:
    """Layout(abi="x86_64"): the abi block carries exactly endian, name, nonvolatile, sp_align, volatile, word -- registers as sorted slot_name strings."""
    block = cento.Layout(abi="x86_64").to_json()["abi"]
    assert sorted(block) == ["endian", "name", "nonvolatile", "sp_align", "volatile", "word"]
    assert block["endian"] == "little" and block["name"] == "x86_64" and block["sp_align"] == 16 and block["word"] == 8
    assert block["volatile"] == sorted(["r10", "r11", "r8", "r9", "rax", "rcx", "rdi", "rdx", "rsi"])
    assert block["nonvolatile"] == sorted(["SP", "r12", "r13", "r14", "r15", "rbp", "rbx"])  # Role.SP renders "SP" per slot_name


def test_manifest_abi_block_omits_null_facts() -> None:
    """No nulls inside the abi block: a custom spec without sp_align omits the key rather than exporting null."""
    spec = dataclasses.replace(cento.abi.X86_64, name="custom", sp_align=None)
    block = cento.Layout(abi=spec).to_json()["abi"]
    assert "sp_align" not in block
    assert sorted(block) == ["endian", "name", "nonvolatile", "volatile", "word"]
    assert block["name"] == "custom" and block["word"] == 8


def test_manifest_region_word_rides_the_abi_block() -> None:
    """Region rows omit "word" only when the abi block makes it recoverable (value equals abi.word); abi-less rows always carry it."""
    lay = cento.Layout(abi="x86_64")
    lay.region("a", max_size=0x10)
    lay.region("b", max_size=0x10, word=4)
    rows = {r["name"]: r for r in lay.to_json()["regions"]}
    assert "word" not in rows["a"]  # equals abi.word 8: reader recovers it from the abi block
    assert rows["b"]["word"] == 4  # explicit word under the abi differs: emitted
    plain = cento.region("p", max_size=0x10)
    assert plain.layout.to_json()["regions"][0]["word"] == 4  # no abi: always emitted (built-in region default)
    fitted = cento.fit({0: [1]})
    assert fitted.layout.to_json()["regions"][0]["word"] == 8  # no abi: always emitted (fit's word=8 default)
    wordless = dataclasses.replace(cento.abi.X86_64, name="wordless", word=None)
    lay2 = cento.Layout(abi=wordless)
    lay2.region("c", max_size=0x10)
    assert lay2.to_json()["regions"][0]["word"] == 4  # abi carries no word: nothing to recover from, so emit


def test_manifest_pins_promised_and_error_cell_rows() -> None:
    """The two CellRow buckets to_json() had not pinned: promised carries the writeback name, error a readable message; the other fields None each time."""
    layout = cento.Layout()
    pkt = layout.region("pkt", max_size=0x40)
    pkt[0] = cento.cells.Writeback("kernel_out")  # runtime-written: no build-time bytes, by design
    pkt[8] = cento.cells.Reduce("nosuch", cento.cells.Span("pkt", 0x10, 0x14))  # unregistered reducer: the cell's own ResolveError
    rows = {(c["region"], c["offset"]): c for c in layout.to_json()["cells"]}
    wb = rows[("pkt", 0)]
    assert wb["promised"] == "kernel_out"
    assert wb["resolved"] is None and wb["missing"] is None and wb["error"] is None
    err = rows[("pkt", 8)]
    assert err["error"] is not None and "unknown reducer 'nosuch'" in err["error"]
    assert err["resolved"] is None and err["missing"] is None and err["promised"] is None


def test_manifest_chain_join_keys_and_determinism() -> None:
    class Entry(cento.Gadget, entry=0x40001000, stride=0x10):
        pc = cento.Restores(Reg.PC, at=0x0)

    def build() -> cento.Layout:
        layout = cento.Layout()
        scratch = layout.region("scratch", max_size=0x100)
        ch = scratch.chain("c", at=0x40, arm=False)
        ch.enter(Entry)
        ch.finish_in_kernel(pc=0x40002000)
        return layout

    a, b = build().to_json(), build().to_json()
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)  # two identical builds, byte-identical
    assert a == json.loads(json.dumps(a))  # the dict itself is json-clean: no tuples survive to_json
    chain = a["chains"][0]
    assert chain["name"] == "c" and chain["region"] == "scratch" and chain["hops"][0]["gadget"] == "Entry"
    assert len(chain["hops"][0]["spec_sha16"]) == 16  # the blast-radius join key, per hop


def test_chain_dataflow_determinism() -> None:
    class Entry(cento.Gadget, entry=0x40001000, stride=0x10):
        pc = cento.Restores(Reg.PC, at=0x0)

    def build() -> cento.Chain:
        layout = cento.Layout()
        scratch = layout.region("scratch", max_size=0x100)
        ch = scratch.chain("c", at=0x40, arm=False)
        ch.enter(Entry)
        ch.finish_in_kernel(pc=0x40002000)
        return ch

    a, b = build().to_json(), build().to_json()
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)  # two identical builds, byte-identical
    assert a == json.loads(json.dumps(a))  # the dict itself is json-clean: no tuples survive to_json


def test_assurance_tiers_never_upgrade() -> None:
    """The binding sentence: absence of a verdict exports as "assumed", never upgraded -- and a FAILED verdict stays visible without raising the tier."""

    class Entry(cento.Gadget, entry=0x40001000, stride=0x10):
        pc = cento.Restores(Reg.PC, at=0x0)

    layout = cento.Layout()
    scratch = layout.region("scratch", max_size=0x100)
    ch = scratch.chain("c", at=0x40, arm=False)
    ch.enter(Entry)
    ch.finish_in_kernel(pc=0x40002000)
    sha = cento.gadget.spec_sha16(Entry)
    a = layout.assurance()
    assert a.gadgets == (cento.regions.GadgetAssurance("Entry", sha, 0x40001000, "assumed", ("c.enter",), None),)  # no set, no verdict: assumed
    assert a.symbols == () and a.waivers == () and a.rewrite_waivers == ()
    assert a.gate == cento.regions.GateFact(shippable=True, errors=0, warnings=0, pending=0, dangling=0)
    j = a.to_json()
    assert j["gadgets"] == [{"gadget": "Entry", "spec_sha16": sha, "entry": 0x40001000, "tier": "assumed", "hops": ["c.enter"], "verdict_ok": None}]
    assert j["gate"] == {"shippable": True, "errors": 0, "warnings": 0, "pending": 0, "dangling": 0}
    assert a.render() == f"assurance: 0 verified, 0 checked, 1 assumed; gate: shippable\ngadgets:\n  Entry  {sha}  assumed  (c.enter)"

    class _Fail:  # a VerdictLike with ok=False: visible via verdict_ok, but the tier does not rise
        ok = False
        bytes_sha16 = "00"

    layout.attach_verdicts({sha: _Fail()})
    a2 = layout.assurance()
    assert a2.gadgets[0].tier == "assumed" and a2.gadgets[0].verdict_ok is False
    assert a2.gate.warnings == 1  # attached verdicts opt in to CHK-304: the FAILED verdict is a warning, not a verified tier
    assert a2.to_json()["gadgets"][0]["verdict_ok"] is False


def test_assurance_failed_verdict_forces_assumed_over_checked(tmp_path: pathlib.Path) -> None:
    """Fail-closed: a FAILED verdict is byte-level evidence of disagreement and outranks catalog agreement -- the crosscheck-clean gadget exports "assumed"."""

    class Entry2(cento.Gadget, entry=0x40005000, stride=0x10):
        pc = cento.Restores(Reg.PC, at=0x0)

    spec = {"schema": 2, "target": "t", "gadget_sets": {"S": {"Entry2": cento.gadget.spec_dict(Entry2)}}}
    p = tmp_path / "cat.json"
    p.write_text(json.dumps(spec, sort_keys=True), encoding="ascii")
    gs = cento.catalog.Catalog.load(str(p)).gadgets("S")
    layout = cento.Layout()
    layout.gadget_set = gs
    scratch = layout.region("scratch", max_size=0x100)
    ch = scratch.chain("c", at=0x40, arm=False)
    ch.enter(gs.Entry2)
    ch.finish_in_kernel(pc=0x40002000)
    assert layout.assurance().gadgets[0].tier == "checked"  # crosscheck-clean by construction: checked while NO verdict is attached

    class _Fail:
        ok = False
        bytes_sha16 = "00"

    layout.attach_verdicts({cento.gadget.spec_sha16(gs.Entry2): _Fail()})
    row = layout.assurance().gadgets[0]
    assert row.tier == "assumed" and row.verdict_ok is False  # a present verdict decides the tier outright; crosscheck is consulted only when none is attached


def test_assurance_checked_and_verified_tiers(tmp_path: pathlib.Path) -> None:
    class Entry2(cento.Gadget, entry=0x40005000, stride=0x10):
        pc = cento.Restores(Reg.PC, at=0x0)

    # checked: a gadget loaded FROM a catalog set crosschecks clean by construction
    spec = {"schema": 2, "target": "t", "gadget_sets": {"S": {"Entry2": cento.gadget.spec_dict(Entry2)}}}
    p = tmp_path / "cat.json"
    p.write_text(json.dumps(spec, sort_keys=True), encoding="ascii")
    gs = cento.catalog.Catalog.load(str(p)).gadgets("S")
    layout = cento.Layout()
    layout.gadget_set = gs
    scratch = layout.region("scratch", max_size=0x100)
    ch = scratch.chain("c", at=0x40, arm=False)
    ch.enter(gs.Entry2)
    ch.finish_in_kernel(pc=0x40002000)
    a = layout.assurance()
    assert a.gadgets[0].tier == "checked" and a.gadgets[0].verdict_ok is None
    assert a.render().startswith("assurance: 0 verified, 1 checked, 0 assumed; gate: shippable\n")

    # verified: an attached PASS verdict for its spec_sha16 -- the ONLY path to the top tier
    class _Pass:
        ok = True
        bytes_sha16 = "ab"

    layout.attach_verdicts({cento.gadget.spec_sha16(gs.Entry2): _Pass()})
    a2 = layout.assurance()
    assert a2.gadgets[0].tier == "verified" and a2.gadgets[0].verdict_ok is True
    assert a2.render().startswith("assurance: 1 verified, 0 checked, 0 assumed; gate: shippable\n")


def test_assurance_multichain_gadget_takes_the_minimum_tier(tmp_path: pathlib.Path) -> None:
    class Entry2(cento.Gadget, entry=0x40005000, stride=0x10):
        pc = cento.Restores(Reg.PC, at=0x0)

    spec = {"schema": 2, "target": "t", "gadget_sets": {"S": {"Entry2": cento.gadget.spec_dict(Entry2)}}}
    p = tmp_path / "cat.json"
    p.write_text(json.dumps(spec, sort_keys=True), encoding="ascii")
    gs = cento.catalog.Catalog.load(str(p)).gadgets("S")

    def build() -> cento.Layout:
        layout = cento.Layout()
        scratch = layout.region("scratch", max_size=0x100)
        bare = scratch.chain("bare", at=0x0, arm=False)  # created BEFORE the set attaches: this chain crosschecks nothing
        bare.enter(gs.Entry2)
        bare.finish_in_kernel(pc=0x40002000)
        layout.gadget_set = gs
        vetted = scratch.chain("vetted", at=0x80, arm=False)  # this use would be "checked" alone
        vetted.enter(gs.Entry2)
        vetted.finish_in_kernel(pc=0x40002000)
        return layout

    a = build().assurance()
    row = a.gadgets[0]
    assert len(a.gadgets) == 1 and row.hops == ("bare.enter", "vetted.enter")
    assert row.tier == "assumed"  # the minimum across uses: one unchecked use drags the row down, never up
    x, y = build().assurance().to_json(), build().assurance().to_json()
    assert json.dumps(x, sort_keys=True) == json.dumps(y, sort_keys=True)  # two identical builds, byte-identical
    assert x == json.loads(json.dumps(x))  # json-clean: no tuples survive to_json


def test_assurance_symbols_waivers_and_gate() -> None:
    layout = cento.Layout()
    pkt = layout.region("pkt", max_size=0x40)
    h = pkt.at(0, Hdr, "h")
    h.magic = 1
    pkt[0] = 2  # raw rewrite of h.magic's cell -> waived below
    layout.allow_rewrite(h.magic, reason="test: the raw patch is the point")
    layout.allow_clobber(h.magic, "dma", "test: dma scribbles here")
    layout.expect_sym("win", align=4)
    layout.expect_sym("base", range=(0x10, 0x20))
    layout.bind("leak", 0x1000, source="somewhere")
    a = layout.assurance()
    assert a.gadgets == ()  # no chains: no gadget rows at all
    assert a.symbols == (
        cento.regions.SymbolAssurance("base", 0x10, 0x20, None, None, None),  # expected-but-unbound is visible
        cento.regions.SymbolAssurance("leak", None, None, None, 0x1000, "somewhere"),  # bound-without-expectation too
        cento.regions.SymbolAssurance("win", None, None, 4, None, None),
    )
    assert a.waivers == (cento.checks.Waiver("pkt", 0, "dma", "test: dma scribbles here"),)
    assert a.rewrite_waivers == (cento.checks.RewriteWaiver("pkt", 0, "test: the raw patch is the point"),)
    assert a.gate == cento.regions.GateFact(shippable=True, errors=0, warnings=1, pending=0, dangling=0)  # CHK-013: 'leak' bound but never consumed
    assert a.render() == (
        "assurance: 0 verified, 0 checked, 0 assumed; gate: shippable\n"
        "symbols:\n"
        "  base range=[0x10 .. 0x20] (unbound)\n"
        "  leak = 0x1000 (source: somewhere)\n"
        "  win align=0x4 (unbound)\n"
        "waivers:\n"
        "  clobber pkt+0x0000 (dma): test: dma scribbles here\n"
        "  rewrite pkt+0x0000: test: the raw patch is the point"
    )
    j = a.to_json()
    assert j["symbols"][0] == {"sym": "base", "lo": 0x10, "hi": 0x20, "align": None, "bound": None, "source": None}
    assert j["symbols"][2] == {"sym": "win", "lo": None, "hi": None, "align": 4, "bound": None, "source": None}
    assert j["waivers"] == [{"region": "pkt", "offset": 0, "effect": "dma", "reason": "test: dma scribbles here"}]
    assert j["rewrite_waivers"] == [{"region": "pkt", "offset": 0, "reason": "test: the raw patch is the point"}]


def test_assurance_carries_the_fold_derived_discard_waiver() -> None:
    """A Writeback.discard staged in a hop frame surfaces as a clobber-waiver ledger row in assurance()."""

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

    layout = cento.Layout()
    page = layout.region("page", base="p", max_size=0x2000)
    run = page.chain("c", at=0xF0)
    run.enter(Lj)
    mint = run.hop(Tail, "mint")
    spend = run.hop(Tail, "spend")
    spend.frame.pc = 0x40003000
    mint.frame.r30 = cento.Writeback.discard("preempt scribbles the saved r30")
    a = layout.assurance()
    key = (mint.frame.r30.region.name, mint.frame.r30.offset)
    assert cento.checks.Waiver(key[0], key[1], "mint_writeback", "writeback.discard: preempt scribbles the saved r30") in a.waivers
    assert a.waivers == layout.preflight().report.waivers  # one ledger: assurance re-exports the report's rows, fold-derived included


def test_chk_catalog_covers_exactly_the_codes_the_library_emits() -> None:
    root = pathlib.Path(__file__).resolve().parents[1] / "src" / "cento"
    if not root.is_dir():
        pytest.skip("repo tree absent (dist-verify scratch runs against the installed package)")
    emitted = set()
    for path in sorted(root.rglob("*.py")):
        emitted |= set(re.findall(r'"(CHK-\d{3})"', path.read_text(encoding="utf-8")))
    assert emitted == set(cento.checks.CODES), "CODES catalog drifted from the codes the source constructs"
    for code, (meaning, fix) in cento.checks.CODES.items():
        assert meaning and fix, code


def test_endian_typo_refuses_at_construction() -> None:
    with pytest.raises(cento.errors.PlacementError, match="endian must be 'big' or 'little'"):
        cento.Layout(endian="littel")  # type: ignore[arg-type]  # the typo under test


def test_raw_cell_literal_overflow_refuses() -> None:
    r = cento.region("r", max_size=0x10)
    with pytest.raises(cento.errors.PlacementError, match="does not fit a 4-byte cell"):
        r[0] = 0x1_0000_0000  # a 64-bit value in a 4-byte raw cell: typo, not wrap
    r[0] = -1  # two's-complement idiom stays legal
    assert r.image()[:4] == b"\xff\xff\xff\xff"


def test_gate_refusal_carries_the_report() -> None:
    layout = cento.Layout()
    pkt = layout.region("pkt", max_size=0x40)
    pkt.at(0, Hdr, "a")
    pkt.at(4, Hdr, "b")  # CHK-001
    with pytest.raises(cento.EmitError) as ei:
        layout.emit("image")
    report = ei.value.report
    assert report is not None and any(i.code == "CHK-001" for i in report.errors)
    assert report.to_json()["errors"]  # the fix loop drives on data
    assert "CHK-001" in str(ei.value)  # the rendered text stays embedded (skill recipes pin this)


def test_pending_gate_refusal_carries_the_report() -> None:
    layout = cento.Layout()
    pkt = layout.region("pkt", max_size=0x10)
    pkt[0] = layout.sym("win")
    with pytest.raises(cento.EmitError) as ei:
        layout.emit("image")
    assert ei.value.report is not None and ei.value.report.pending == ("win",)


def test_seal_refusal_carries_the_issue() -> None:
    class PopTgt(cento.Gadget, entry=0x40001000, stride=0x10):
        tgt = cento.Restores(Reg.R30, at=0x0)
        pc = cento.Restores(Reg.PC, at=0x8)

    class Consumer(cento.Gadget, entry=0x40002000, stride=0x8):
        pc = cento.Restores(Reg.PC, at=0x0)
        needs = {Reg.R30: "unfed on purpose"}

    layout = cento.Layout()
    scratch = layout.region("scratch", max_size=0x100)
    ch = scratch.chain("c", at=0x0, arm=False)
    ch.enter(PopTgt)  # PopTgt restores R30 from an unset cell
    ch.hop(Consumer, "use")
    ch.finish_in_kernel(pc=0x40003000)
    with pytest.raises(cento.ChainError) as ei:
        ch.seal()
    issue = ei.value.issue
    assert issue is not None and issue.code.startswith("CHK-2")
    assert issue.to_json()["code"] == issue.code and issue.code in str(ei.value)


def test_facade_docstring_carries_the_happy_path() -> None:
    assert cento.__doc__ is not None
    assert "buf.image()" in cento.__doc__  # the first help(cento) screen orients a cold reader
