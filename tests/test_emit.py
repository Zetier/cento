# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Emission and explanation.

Emission backends: SPARSE/IMAGE/HEXDUMP, fixups, deliver ordering, final gate.
explain(): path + raw-address forms, bilingual naming, dataflow cross-references.
"""

from __future__ import annotations

import re

import pytest

import cento.cells as cells
import cento.emit as emit
import cento.errors as errors
import cento.gadget as gadget
import cento.machine as machine
import cento.regions as regions
import cento.views as views

# -- emission backends -------------------------------------------------------------


class Hdr(views.View, size=8):
    magic = views.Field(0, views.u32)
    length = views.Field(4, views.u16)
    csum = views.Field(6, views.u16)


def build() -> tuple[regions.Layout, regions.Region]:
    layout = regions.Layout(endian="big")  # a big-endian wire packet: the goldens below spell network order
    pkt = layout.region("pkt", max_size=16, fill=0)
    h = pkt.at(0, Hdr, "h")
    h.magic = 0xDEADBEEF
    h.length = 16
    h.csum = cells.sum16(pkt[0:6])
    return layout, pkt


def test_image_golden() -> None:
    layout, _ = build()
    result = layout.emit(emit.Backend.IMAGE)
    assert result.artifact == {
        "pkt": bytes.fromhex("deadbeef00109dac") + b"\x00" * 8
    }  # 9dac = the u16 BE word-sum of the first 6 bytes (dead+beef+0010, carry dropped)
    assert result.fixups == [] and result.pending == ()


def test_sparse_writes_applied_over_fill_equal_the_image() -> None:
    """The cross-backend invariant: a thrower that lands every SPARSE write over a fill-initialized
    buffer holds exactly the IMAGE artifact. Pins the one-composer property across fill patterns,
    delivery phases, computed cells, and writebacks (which appear in neither backend)."""
    layout = regions.Layout(endian="big")
    pkt = layout.region("pkt", max_size=0x30, fill="AB")
    pkt[0x00:0x04] = 0xDEADBEEF
    pkt[0x08:0x0A] = cells.sum16(pkt[0x00:0x04])
    pkt[0x10:0x14] = "late_sym"
    pkt.cell(0x20, 4).write(cells.Writeback("kernel_fills_this"))
    trigger = pkt.cell(0x14, 4)
    trigger.write(0x41424344)
    layout.mark(trigger, emit.Deliver.ARM)
    layout.bind("late_sym", 0x1122, source="t")
    layout.bind("pkt_base", 0x40000000, source="t")
    image = layout.emit(emit.Backend.IMAGE).artifact["pkt"]
    sparse = layout.emit(emit.Backend.SPARSE)
    buf = bytearray(pkt.fill_at(0, 0x30))
    for addr, data, _phase in sparse.ordered:
        off = addr - 0x40000000
        buf[off : off + len(data)] = data
    assert bytes(buf) == image


def test_sparse_fixups_and_deliver_ordering() -> None:
    """SPARSE needs the base bound, orders ARM last, and carries fixups until a bind retires them."""
    layout, pkt = build()
    result = layout.emit(emit.Backend.SPARSE, final=False)  # the draft read: the unbound base IS the subject
    assert result.artifact == {}  # base unbound: everything is a fixup
    assert {f.missing for f in result.fixups} == {("pkt_base",)}
    layout.bind("pkt_base", 0x2528000)
    trigger = pkt.cell(12, width=4)
    trigger.write(0x41424344)
    layout.mark(trigger, emit.Deliver.ARM)
    result2 = layout.emit(emit.Backend.SPARSE)
    assert result2.artifact[0x2528000] == b"\xde\xad\xbe\xef"
    assert result2.ordered[-1] == (0x252800C, b"\x41\x42\x43\x44", emit.Deliver.ARM)  # ARM sorts last
    assert [a for a, _, _ in result2.ordered] == sorted(a for a, _, _ in result2.ordered[:3]) + [0x252800C]
    # fresh build: its fixup set must not see the trigger above
    layout, pkt = build()
    layout.bind("pkt_base", 0x1000)
    pkt.cell(8).write("late_sym")
    result = layout.emit(emit.Backend.SPARSE, final=False)  # draft again: late_sym still pending
    assert emit.Fixup("pkt", 8, 4, "pkt.raw+0x8", ("late_sym",)) in result.fixups
    layout.bind("late_sym", 0x77)
    assert layout.emit(emit.Backend.SPARSE).fixups == []  # the bind retires the fixup


def test_backend_string_coercion() -> None:
    """Backends accept their lowercase string spellings and refuse unknown names."""
    layout, _ = build()
    layout.bind("pkt_base", 0x1000)  # sparse's final gate needs the base; coercion is the subject here
    assert layout.emit("image").artifact == layout.emit(emit.Backend.IMAGE).artifact
    assert layout.emit("hexdump").artifact == layout.emit(emit.Backend.HEXDUMP).artifact
    assert layout.emit("sparse").backend is emit.Backend.SPARSE  # the result records the coerced member
    with pytest.raises(errors.EmitError, match="unknown backend 'bogus'"):
        layout.emit("bogus")  # type: ignore[arg-type]  # Literal makes this a type error; the runtime gate matches it


def test_hexdump_contract() -> None:
    """HEXDUMP the display layer: deterministic annotated artifact, layout.hexdump() sugar, lossless
    color overlay, fixed-width data column, and deliver tags only when the phase varies."""
    layout, pkt = build()
    d1 = layout.emit(emit.Backend.HEXDUMP).artifact
    d2 = layout.emit(emit.Backend.HEXDUMP).artifact
    assert d1 == d2
    assert "region pkt" in d1 and "h.csum" in d1 and "9dac" in d1
    artifact = layout.emit(emit.Backend.HEXDUMP).artifact
    assert layout.hexdump(color=False) == artifact.removesuffix("\n")  # print()/f-string ready; the artifact keeps its terminator
    plain = layout.hexdump(color=False)
    colored = layout.hexdump(color=True)
    assert "\x1b[" not in plain  # the artifact never carries escapes
    assert "\x1b[" in colored and colored != plain
    assert re.sub(r"\x1b\[[0-9;]*m", "", colored) == plain  # color is a lossless overlay
    pkt.cell(9, 1).write(0x7F)
    dump = layout.hexdump(color=False)
    assert "  +0x0000 w4 deadbeef  " in dump  # 4-byte cells: flush
    assert "  +0x0004 w2     0010  " in dump  # 1-2 byte cells: right-aligned into the same column
    assert "  +0x0009 w1       7f  " in dump
    # fresh build: the phase-less baseline matters
    layout, pkt = build()
    trigger = pkt.cell(12, width=4)
    trigger.write(0x41424344)
    layout.mark(trigger, emit.Deliver.ARM)
    dump = layout.hexdump(color=False)
    assert "NORMAL" not in dump  # the default phase goes unsaid
    assert "[pkt.raw+0xc] ARM" in dump  # non-default phases are the news
    colored = layout.hexdump(color=True)
    assert "ARM" in colored and "NORMAL" not in colored


def test_colorize_disasm_is_ropper_flavored_and_lossless() -> None:
    line = "  0x40001000: lwz r0, 0x0(r31); mtlr r0; blr"
    colored = emit.colorize_disasm(line, color=True)
    assert re.sub(r"\x1b\[[0-9;]*m", "", colored) == line  # color is a lossless overlay
    assert "\x1b[36m0x40001000" in colored  # cyan address, as ropper prints it
    assert "\x1b[93mlwz\x1b[0m \x1b[37mr0, 0x0(r31)\x1b[0m" in colored  # light-yellow mnemonic, gray operands
    assert "\x1b[94m; \x1b[0m" in colored  # light-blue separators
    assert "\x1b[93mblr\x1b[0m" in colored  # operand-less instruction still gets its mnemonic color
    assert emit.colorize_disasm(line, color=False) == line  # plain passthrough (and the auto default under capture)


def test_want_color_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    assert emit.want_color(True) is True and emit.want_color(False) is False  # explicit always wins
    monkeypatch.setenv("NO_COLOR", "1")
    assert emit.want_color(None) is False  # NO_COLOR vetoes auto, TTY or not


def test_final_gate() -> None:
    """The final emit (the bare default) refuses residuals: region-local unbound symbols and layout-wide pending alike."""
    layout, pkt = build()
    pkt.cell(8).write("unbound")
    with pytest.raises(errors.EmitError, match="unbound"):
        layout.emit(emit.Backend.IMAGE)
    layout.bind("unbound", 1)
    layout.bind("pkt_base", 0x1000)
    assert layout.emit(emit.Backend.IMAGE).pending == ()
    layout, pkt = build()
    layout.bind("pkt_base", 0x1000)
    pkt.cell(8).write(7)
    pkt.cell(12).write("layout_wide_unbound")
    with pytest.raises(errors.EmitError, match="layout_wide_unbound"):
        layout.emit(emit.Backend.SPARSE)


def test_hexdump_skip_summarizes_runs() -> None:
    """hexdump(skip=True) presentation: cyclic pad runs summarize by provenance, chosen-byte runs by
    rendered data; artifacts and the default view never summarize."""
    frame = regions.region("frame", max_size=0x20, pad=4)
    dump = frame.layout.hexdump(color=False, skip=True)
    assert "+0x0000 w4 61616161" in dump and "+0x001c w4" in dump  # run endpoints stay
    assert "  * +0x0004..+0x0018: 6 cyclic pad words  [frame.raw+*]" in dump
    assert frame.layout.hexdump(color=False) == frame.layout.hexdump(color=False, skip=False)  # full output is the default
    assert frame.layout.emit("hexdump").artifact.count("+0x00") == 8  # artifacts never summarize
    frame[0x14] = 0xDEADBEEF  # overwriting a pad word ends its provenance: the patch splits the run and stays visible
    patched = frame.layout.hexdump(color=False, skip=True)
    assert "+0x0014 w4 efbeadde" in patched  # the patch value's little-endian bytes (the default endian)
    assert "3 cyclic pad words" in patched  # the 5-cell half before the patch still summarizes...
    assert "+0x0018 w4" in patched and "+0x001c w4" in patched  # ...the 2-cell half after it is under threshold: verbatim
    frame = regions.region("frame", max_size=0x20)
    frame.pad(0x20, data=b"\xff" * 0x20)  # chosen bytes, not cyclic: summarized by the rendered data instead
    dump = frame.layout.hexdump(color=False, skip=True)
    assert "  * +0x0004..+0x0018: 6 words of 0xff  [frame.raw+*]" in dump
    assert dump.count("ffffffff") == 2  # first and last rows only


# -- explain() -----------------------------------------------------------------------

Reg = machine.Reg


class SyscallTail(gadget.Gadget, entry=0x40002000, stride=0xB0):
    r30 = gadget.Restores(Reg.R30, at=0xA8)
    r31 = gadget.Restores(Reg.R31, at=0xAC)
    pc = gadget.Restores(Reg.PC, at=0xB4, external=True)
    needs = {Reg.R30: "handle", Reg.R31: "desc"}


class LjBypass(gadget.Gadget, entry=0x40001000, frame_base=Reg.R31):
    pc = gadget.Restores(Reg.PC, at=0x00)
    sp = gadget.Restores(Reg.SP, at=0x04)
    r30 = gadget.Restores(Reg.R30, at=0x50)
    r31 = gadget.Restores(Reg.R31, at=0x54)
    needs = {Reg.R31: "jb"}


class Desc(views.View, size=0x10):
    dtype = views.Field(0x0, views.u32)
    val = views.Field(0x4, views.u32)
    aux = views.Field(0x8, views.u32)
    res = views.Field(0xC, views.u32)


def build_explain() -> regions.Layout:
    layout = regions.Layout()
    page = layout.region("page", base="pv", max_size=0x1000)
    run = page.chain("c", at=0x100)
    run.enter(LjBypass)
    h1 = run.hop(SyscallTail, "h1")
    kd = h1.frame.overlay(Desc, at=0xA0, name="kd", why="writeback lands on the r30 restore")
    h1.add_effect(machine.Effect("wb", controls={kd.aux: machine.Writeback("th")}))
    h1.r30, h1.r31 = 0x40, kd
    run.hop(SyscallTail, "h2").r31 = 0x2000
    return layout


def test_explain_contract() -> None:
    """explain() answers by path or absolute address with bilingual names, aliases, and dataflow
    cross-references; the raw-cell spelling the library itself prints pastes back in."""
    layout = build_explain()
    text = layout.explain("page.c.h1.r30")
    assert "c.h1[+0xA8]" in text  # bilingual doc-convention name
    assert "kd" in text and "writeback lands" in text  # alias + why
    assert "h2" in text and "R30" in text  # feeds hop h2's need
    assert "writeback" in text and "wb" in text  # effect supply cross-ref
    with pytest.raises(errors.PlacementError, match="bound"):
        layout.explain(0x2128)  # no base bound yet
    layout.bind("pv", 0x2000)
    text = layout.explain(0x2000 + 0x1A8)  # same byte by absolute addr
    assert "c.h1" in text
    with pytest.raises(errors.PlacementError):
        layout.explain("page.nope.field")
    layout = regions.Layout(endian="little")
    stack = layout.region("stack", max_size=0x10)
    stack[0x8:0x10] = layout.sym("base") + 0x40
    text = layout.explain("stack.raw+0x8")  # the owner path from errors/hexdump, pasted back
    assert "stack.raw+0x8 @ stack+0x8" in text and "base + 0x40" in text
    assert "unbound: base -- bind() completes this cell" in text
    layout.bind("base", 0x1000, source="test leak")
    assert "bound: base = 0x1000 (source: test leak)" in layout.explain("stack.raw+0x8")
    with pytest.raises(errors.PlacementError, match="did you mean 'stack'"):
        layout.explain("stak.raw+0x8")


def test_explain_data_is_the_record_explain_renders() -> None:
    layout = build_explain()
    text = layout.explain_data("page.c.h1.r30").render()
    assert layout.explain("page.c.h1.r30") == text
    assert "feeds: hop " in text and "writeback-by: effect " in text  # the chain-line spellings, pinned
    jc = layout.explain_data("page.c.h1.r30").to_json()
    assert jc["feeds"][0]["hop"] == "h2"  # fact records serialize as named dicts, not positional lists
    layout.bind("pv", 0x2000)
    assert layout.explain(0x2000 + 0x1A8) == layout.explain_data(0x2000 + 0x1A8).render()
    layout = regions.Layout(endian="little")
    stack = layout.region("stack", max_size=0x10)
    stack[0x8:0x10] = layout.sym("base") + 0x40
    assert layout.explain("stack.raw+0x8") == layout.explain_data("stack.raw+0x8").render()
    d = layout.explain_data("stack.raw+0x8")
    assert d.region == "stack" and d.offset == 0x8
    j = d.to_json()
    assert j["region"] == "stack" and j["offset"] == 0x8
    assert j["cell"]["width"] == 8 and j["binding"]["sym"] == "base"  # nested records carry their field names
    assert layout.explain_data("stack.raw+0x8").to_json() == j  # deterministic
    layout.bind("base", 0x1000, source="test leak")
    assert layout.explain("stack.raw+0x8") == layout.explain_data("stack.raw+0x8").render()
