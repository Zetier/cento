# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""The regions.py subject: layout, placements, views.

Layout/Region core: naming, symbols, cell store, lazy force, pending/dirty.
Placements: at/alloc/name-lookup, view handles, field assignment, aliases.
View type declaration: fields, size derivation, external, aliases, arrays.
"""

from __future__ import annotations

import typing

import pytest

import cento
import cento.cells as cells
import cento.emit as emit
import cento.errors as errors
import cento.regions as regions
import cento.views as views

# -- Layout/Region core ---------------------------------------------------------


def test_naming_and_addressing() -> None:
    """Layout/region naming (auto and explicit) and the addr()/slice addressing vocabulary."""
    layout = regions.Layout()
    assert layout.name.startswith("layout_")
    r1 = layout.region()
    r2 = layout.region("pkt")
    assert r1.name == "region_1" and r2.name == "pkt"
    assert r2.base_sym == "pkt_base"
    assert layout.regions["pkt"] is r2
    a = r2.addr(0x10)
    assert a == cells.Ref("pkt_base", addend=0x10)
    sp = r2[0:6]
    assert sp == cells.Span("pkt", 0, 6)


def test_provenance_defaults_and_hand_set() -> None:
    layout = regions.Layout()
    assert layout.provenance == cento.Provenance()  # a hand-built layout has no provenance and says so
    layout.provenance = cento.Provenance(target_name="mk4")  # partial hand construction is the contract
    assert layout.provenance.target_name == "mk4" and layout.provenance.catalog_sha256 is None
    assert regions.Layout()._auto_named is True and regions.Layout(name="n")._auto_named is False


def test_cell_write_force_and_resolution() -> None:
    """force() across the cell-value vocabulary: raw ints pack per layout endianness, Refs stay
    residual until bound, Deltas wrap modulo width, Reduces compute over spans and refuse cycles."""
    layout = regions.Layout()
    pkt = layout.region("pkt")
    h = pkt.cell(0, width=4)
    h.write(0xDEADBEEF)
    assert layout.force(("pkt", 0)) == b"\xef\xbe\xad\xde"
    big = regions.Layout(endian="big")
    p2 = big.region("pkt")
    p2.cell(0, width=4).write(0xDEADBEEF)
    assert big.force(("pkt", 0)) == b"\xde\xad\xbe\xef"
    layout = regions.Layout()
    pkt = layout.region("pkt")
    pkt.cell(0).write("target")  # str coerces to Ref
    r = layout.force(("pkt", 0))
    assert isinstance(r, cells.Residual) and r.missing == frozenset({"target"})
    layout.bind("target", 0x40008154)
    assert layout.force(("pkt", 0)) == (0x40008154).to_bytes(4, "little")
    pkt.cell(4).write(layout.sym("a") - layout.sym("b"))  # Delta wraps modulo width
    layout.bind("a", 0x100)
    layout.bind("b", 0x400)
    assert layout.force(("pkt", 4)) == ((0x100 - 0x400) % (1 << 32)).to_bytes(4, "little")
    layout = regions.Layout()
    pkt = layout.region("pkt", fill=0)
    pkt.cell(0, width=2).write(0xDEAD)
    pkt.cell(2, width=2).write(0xBEEF)
    pkt.cell(4, width=2).write(0x0010)
    pkt.cell(6, width=2).write(cells.sum16(pkt[0:6]))
    assert layout.force(("pkt", 6)) == (0xAD9C).to_bytes(2, "little")  # sum16 over the little-packed bytes ad de ef be 10 00
    # self-inclusion: reduce whose span covers its own cell = ResolveError
    bad = layout.region("bad", fill=0)
    bad.cell(0, width=2).write(cells.sum16(bad[0:4]))
    with pytest.raises(errors.ResolveError):
        layout.force(("bad", 0))


def test_pending_and_dirty() -> None:
    layout = regions.Layout()
    pkt = layout.region("pkt")
    pkt.cell(0).write("late_sym")
    pkt.cell(4).write(7)
    assert layout.pending() == {"late_sym"}  # base syms matter only at SPARSE emission, not force
    layout.bind("late_sym", 1)
    assert layout.pending() == set()
    assert layout.dirty("late_sym") == {("pkt", 0)}
    assert layout.dirty("unrelated") == set()


def test_coercion_teaches() -> None:
    layout = regions.Layout()
    pkt = layout.region("pkt")
    with pytest.raises(errors.PlacementError, match="cell value"):
        pkt.cell(0).write(3.14)  # write() takes object; the coercion error is a runtime teach


def test_mark_deliver_and_mutation_bump() -> None:
    """mark() records the deliver phase on the cell and bumps the layout mutation counter."""
    layout = regions.Layout()
    pkt = layout.region("pkt")
    h = pkt.cell(0)
    h.write(1)
    layout.mark(h, emit.Deliver.ARM)
    assert layout.cells()[("pkt", 0)].deliver is emit.Deliver.ARM
    before = layout.mutations
    layout.mark(h, emit.Deliver.LATE)
    assert layout.mutations == before + 1


def test_pad_contract() -> None:
    """Region.pad(): the self-locating cycle round-trips through the image, packs with the layout's
    endianness, takes data= overrides at an offset, and refuses bad length/unit/data shapes."""
    # region in one shot (Region.layout is the back-ref); pad in one call; image == pattern
    frame = regions.Layout().region("frame", max_size=0x50)
    blob = frame.pad(0x50, unit=4)
    image = frame.layout.emit(emit.Backend.IMAGE).artifact["frame"]
    assert image == blob and len(blob) == 0x50
    window = int.from_bytes(image[0x48:0x4C], "little")
    assert cells.cycle_find(window) == 0x48  # the pad is self-locating: any window names its offset
    frame = regions.Layout(endian="big").region("frame")
    blob = frame.pad(0x10, unit=4)
    assert frame.layout.emit(emit.Backend.IMAGE).artifact["frame"] == blob  # packed big, emitted big
    frame = regions.Layout().region("frame", max_size=0x20)
    chosen = bytes(range(0x10))
    assert frame.pad(0x10, at=0x8, data=chosen) == chosen
    image = frame.layout.emit(emit.Backend.IMAGE).artifact["frame"]
    assert image[0x8:0x18] == chosen and image[:0x8] == b"\x00" * 8  # fill covers the unpadded head
    frame = regions.Layout().region("frame", max_size=0x10)
    with pytest.raises(errors.PlacementError, match="multiple of unit"):
        frame.pad(0x6, unit=4)
    with pytest.raises(errors.PlacementError, match="exceeds max_size"):
        frame.pad(0x20, unit=4)
    with pytest.raises(errors.PlacementError, match="length says"):
        frame.pad(0x8, data=b"\x00" * 4)


def test_duplicate_base_symbol_refuses_at_declaration() -> None:
    layout = regions.Layout()
    layout.region("a", base="shared_va")
    with pytest.raises(errors.PlacementError, match="base symbol 'shared_va' already used by region 'a'"):
        layout.region("b", base="shared_va")
    lay2 = regions.Layout()
    lay2.region("pkt")  # default base: pkt_base
    with pytest.raises(errors.PlacementError, match="base symbol 'pkt_base' already used"):
        lay2.region("aux", base="pkt_base")  # an explicit base= colliding with an earlier default


def test_region_forwards_hexdump_and_check() -> None:
    r = cento.fit({0: [0x11223344]})
    assert r.hexdump(skip=True) == r.layout.hexdump(skip=True)
    assert r.hexdump(color=False) == r.layout.hexdump(color=False)
    assert r.check().to_json() == r.layout.check().to_json()


def test_dialect_kwargs_teach() -> None:
    with pytest.raises(errors.PlacementError, match=r"fit spells the cap length="):
        cento.fit({0: [1]}, max_size=0x40)  # type: ignore[arg-type]  # the wrong-guess under test
    with pytest.raises(errors.PlacementError, match=r"fill_default is a Layout fact"):
        cento.Layout().region("r", fill_default=0x41)  # type: ignore[arg-type]  # the wrong-guess under test


def test_region_endian_kwarg_teaches() -> None:
    layout = regions.Layout()
    with pytest.raises(errors.PlacementError, match="endianness is a Layout fact"):
        layout.region("pkt", endian="little")  # type: ignore[arg-type]  # the wrong-guess under test


def test_default_target_is_x86_64_flavored() -> None:
    """The default target flip: little-endian everywhere a default exists (PPC32 stays fully
    supported, just no longer implied)."""
    assert regions.Layout().endian == "little"
    assert cento.region("r").layout.endian == "little"


def test_region_pad_kwarg_contract() -> None:
    """region(pad=) sugar: pads the whole region at creation, keeps the same raw-cell owner for
    patches on top, and refuses without max_size."""
    frame = regions.Layout().region("frame", max_size=0x50, pad=4)
    image = frame.layout.emit(emit.Backend.IMAGE).artifact["frame"]
    assert image == cells.cycle(0x50)  # sugar for Region.pad(max_size, unit=4)
    frame = regions.Layout().region("frame", max_size=0x50, pad=4)
    frame.cell(0x48).write(0x40001000)  # same cell path = same owner: no CHK-008, last write wins
    assert frame.layout.check().errors == []
    image = frame.layout.emit(emit.Backend.IMAGE).artifact["frame"]
    assert image[0x48:0x4C] == b"\x00\x10\x00\x40" and image[:0x48] == cells.cycle(0x50)[:0x48]
    with pytest.raises(errors.PlacementError, match="needs max_size"):
        regions.Layout().region("frame", pad=4)


def test_region_constructor_makes_fresh_isolated_layouts() -> None:
    """regions.region() is the one-region payload: a fresh Layout per call (no shared module state),
    with layout config riding through."""
    a = regions.region("frame", max_size=0x10)
    b = regions.region("frame", max_size=0x10)  # the same name twice: fine, every call gets its own Layout
    assert a.layout is not b.layout
    a[0] = 0x11223344
    assert not b.layout.cells()  # no shared module state: builds stay independent
    assert regions.region("r", endian="little").layout.endian == "little"  # layout config rides through
    a = regions.region("stack", max_size=8, fill=b"A", endian="little")
    assert isinstance(a, regions.Region) and a.layout.endian == "little" and a.fill == b"A"
    b = regions.region("stack", max_size=8, fill=b"A", endian="little")
    assert a.layout is not b.layout  # fresh Layout per call, like cento.region()
    a[0:4] = 0x11223344
    assert not b.layout.cells()
    assert a.image()[:4] == bytes.fromhex("44332211") and a.image()[4:] == b"AAAA"


def test_region_word_sets_the_default_cell_width() -> None:
    layout = regions.Layout()
    wide = layout.region("wide", max_size=0x40, word=8)
    wide[0x8] = 0x1122334455667788  # slice sugar rides the region word
    assert wide.cell(0x8).width == 8 and layout.image("wide")[0x8:0x10] == bytes.fromhex("8877665544332211")
    assert wide.cell(0x20, width=4).width == 4  # explicit width still wins
    legacy = layout.region("legacy", max_size=0x10)
    legacy[0x0] = 1
    assert legacy.cell(0x0).width == 4  # the default did NOT move
    assert cento.region("r", word=8).cell(0).width == 8  # module-level pass-through


def test_fit_is_the_one_shot_on_ramp() -> None:
    POP_RDI, BINSH, SYSTEM = 0x401F2F, 0x404060, 0x401050
    stack = cento.fit({0x88: [POP_RDI, BINSH, SYSTEM]}, fill="A", length=0xA8)
    img = stack.image()
    assert len(img) == 0xA8 and img[:0x88] == b"A" * 0x88
    assert img[0x88:0x90] == POP_RDI.to_bytes(8, "little")  # list values: consecutive word cells
    assert img[0x98:0xA0] == SYSTEM.to_bytes(8, "little")
    assert cento.fit({0x88: [POP_RDI, BINSH, SYSTEM]}, fill="A", length=0xA8).image() == img  # deterministic
    assert cento.fit({0: [1, [2, 3]]}).image() == b"".join(v.to_bytes(8, "little") for v in (1, 2, 3))  # nested lists flatten


def test_fit_flat_form_bytes_and_growth() -> None:
    r = cento.fit([b"AAAA", 0x1122334455667788, b"Z"])  # sequence = flat: cursor from 0; bytes keep their length
    img = r.image()
    assert img[:4] == b"AAAA" and img[4:12] == bytes.fromhex("8877665544332211") and img[12:13] == b"Z"
    assert cento.fit(b"AAAA").image() == b"AAAA"  # top-level bytes: the flat payload (4 bytes out), not per-byte words
    assert cento.fit([b"", b"Z"]).image() == b"Z"  # empty bytes advance the cursor by nothing
    # the growth path: the SAME object takes a symbol, then refuses until bound -- the on-ramp teaching moment
    r2 = cento.fit({0x0: cento.Ref("libc_base") + 0x52290})
    with pytest.raises(errors.EmitError, match="libc_base"):
        r2.image()
    r2.bind("libc_base", 0x7F0000000000)
    assert r2.image()[:8] == (0x7F0000052290).to_bytes(8, "little")


def test_fit_refusals_teach() -> None:
    with pytest.raises(errors.PlacementError, match="bytes"):
        cento.fit({0: "sh"})  # str is a legal object statically; the runtime refusal is the pin (no type: ignore needed)
    with pytest.raises(errors.PlacementError, match=r"b'AAAA'"):
        cento.fit("AAAA")  # a top-level str refuses whole, naming the full-string spelling -- never char-wise
    with pytest.raises(errors.PlacementError, match="int byte offset"):
        cento.fit({"x": 1})  # type: ignore[dict-item]  # the wrong-key shape under test


def test_setitem_contract() -> None:
    """__setitem__ sugar: int index is a cell write with the same raw owner, slices size the cell,
    and malformed indices refuse with the fix named."""
    frame = regions.Layout().region("frame", max_size=0x50, pad=4)
    frame[0x48] = 0x40001000  # same cell path as cell(0x48).write(): same owner, no CHK-008
    assert frame.layout.check().errors == []
    image = frame.layout.emit(emit.Backend.IMAGE).artifact["frame"]
    assert image[0x48:0x4C] == b"\x00\x10\x00\x40" and image[:0x48] == cells.cycle(0x50)[:0x48]
    pkt = regions.Layout().region("pkt", max_size=0x10)
    pkt[0x4:0xC] = 0x1122334455667788  # width 8, from the span
    pkt[:0x2] = 0xBEEF  # omitted start is 0, like Span slices
    image = pkt.layout.emit(emit.Backend.IMAGE).artifact["pkt"]
    assert image[0x4:0xC] == bytes.fromhex("8877665544332211") and image[:0x2] == b"\xef\xbe"
    pkt = regions.Layout().region("pkt", max_size=0x10)
    with pytest.raises(errors.PlacementError, match="no step"):
        pkt[0:8:4] = 0
    with pytest.raises(errors.PlacementError, match="explicit end"):
        pkt[4:] = 0
    with pytest.raises(errors.PlacementError, match="spans no bytes"):
        pkt[4:4] = 0
    with pytest.raises(errors.PlacementError, match="assignment index"):
        pkt["hdr"] = 0  # type: ignore[index]  # placements assign through their fields, not by name


def test_handles_carry_len_and_span() -> None:
    class Hdr(views.View, size=0x10):
        magic = views.Field(0x0, views.u32)

    layout = regions.Layout()
    pkt = layout.region("pkt", max_size=0x40)
    hdr = pkt.at(0, Hdr, name="hdr")
    assert len(Hdr) == 0x10  # the CLASS carries it too: len(SomeView) before any placement exists
    assert len(hdr) == 0x10  # byte size -- so the next placement can start at len(hdr)
    assert hdr.span == cells.Span("pkt", 0, 0x10)
    body = pkt.at(len(hdr), Hdr, name="body")
    assert body.span == cells.Span("pkt", 0x10, 0x20)
    arr = pkt.at(0x20, Hdr * 2, "arr")
    assert len(arr) == 2 and arr.span == cells.Span("pkt", 0x20, 0x40)  # array len = ELEMENTS; span = whole extent
    assert pkt.cell(0x4).span == cells.Span("pkt", 0x4, 0x8)


def test_reducers_accept_span_carriers() -> None:
    class Hdr(views.View, size=0x8):
        a = views.Field(0x0, views.u32)
        b = views.Field(0x4, views.u32)

    layout = regions.Layout()
    pkt = layout.region("pkt", max_size=0x10)
    hdr = pkt.at(0, Hdr, name="hdr")
    hdr.a, hdr.b = 0x11223344, 0x55667788
    by_handle = cells.length(hdr)
    by_slice = cells.length(pkt[0:0x8])
    assert by_handle.span == by_slice.span  # a handle IS its span to every reducer
    pkt.cell(0x8).write(cells.udp_cksum(hdr))
    pkt.cell(0xC).write(cells.crc32_mpeg2(hdr))
    img = layout.emit(emit.Backend.IMAGE).artifact["pkt"]
    assert img[0x8:0xC] != b"\x00\x00\x00\x00"  # the handle-fed reducers resolved over hdr's bytes


def test_register_reducer_contract() -> None:
    """register_reducer(): the constructor works like a builtin's, builtin/duplicate names refuse, and the name is layout-scoped."""

    def fw_ck(data: bytes) -> int:
        return sum(data) & 0xFF

    layout = regions.Layout()
    rec = layout.region("rec", max_size=0x20)
    rec[0x4] = 0x01020304
    ck = layout.register_reducer("fw_ck", fw_ck)
    rec.cell(0x0, width=1).write(ck(rec[0x4:0x8]))
    assert layout.image("rec")[0] == (1 + 2 + 3 + 4) & 0xFF
    # builtin and duplicate names refuse at registration (early, holding the object)
    with pytest.raises(errors.PlacementError, match="builtin reducer"):
        layout.register_reducer("length", fw_ck)
    with pytest.raises(errors.PlacementError, match="already registered"):
        layout.register_reducer("fw_ck", fw_ck)
    # cross-layout leakage: the constructor is layout-scoped; the foreign layout refuses (CHK-007 bucket)
    other = regions.Layout()
    o = other.region("o", max_size=0x10)
    o[0x4] = 1
    o.cell(0x0, width=1).write(ck(o[0x4:0x8]))
    hits = [i for i in other.check().errors if i.code == "CHK-007"]
    assert hits and "unknown reducer 'fw_ck'" in hits[0].msg


def test_register_reducer_invalidates_the_resolution_memo() -> None:
    """Registration bumps mutations: a Reduce staged before its reducer existed re-resolves after."""

    def fw_ck(data: bytes) -> int:
        return len(data)

    layout = regions.Layout()
    rec = layout.region("rec", max_size=0x20)
    rec.cell(0x0, width=1).write(cells.Reduce(fn="late_ck", span=rec[0x4:0x8], expect=None))
    assert (rec.name, 0x0) in layout.resolution().errors  # staged before registration: unknown reducer
    layout.register_reducer("late_ck", fw_ck)
    assert layout.image("rec")[0] == 4  # registration bumped mutations; the memo re-resolved


def test_register_xform_contract() -> None:
    """register_xform(): the constructor works like a builtin's, builtin/duplicate names refuse, and str xforms keep wrap semantics."""
    layout = regions.Layout(endian="little")
    slab = layout.region("slab", max_size=0x10)
    page = layout.register_xform("adrp_page", lambda v: v >> 12)
    slab[0x0] = page(layout.sym("libc"))
    layout.bind("libc", 0x7F1FBABC5678, source="test")
    assert layout.image("slab")[0:4] == ((0x7F1FBABC5678 >> 12) % (1 << 32)).to_bytes(4, "little")
    # rendering matches the builtin shape
    assert "adrp_page(libc)" in layout.explain("slab.raw+0x0")
    with pytest.raises(errors.PlacementError, match="builtin xform"):
        layout.register_xform("lo16", lambda v: v)
    with pytest.raises(errors.PlacementError, match="already registered"):
        layout.register_xform("adrp_page", lambda v: v)
    # custom xforms inherit wrap-at-width semantics (the WidthError guard stays ADDR-only)
    wide = layout.register_xform("wide", lambda v: v | (1 << 40))
    slab[0x4] = wide(layout.sym("libc"))
    assert layout.image("slab")[0x4:0x8] == ((0x7F1FBABC5678 | (1 << 40)) % (1 << 32)).to_bytes(4, "little")


def test_render_value_covers_the_value_algebra() -> None:
    layout = regions.Layout()
    rec = layout.region("rec", max_size=0x20)
    a, b = layout.sym("base"), layout.sym("anchor")
    assert regions._render_value(a + 0x10) == "base + 0x10"  # Ref: unchanged spelling
    assert regions._render_value((a - b) + 4) == "base - anchor + 0x4"
    assert regions._render_value(a - b) == "base - anchor"
    assert regions._render_value(a - (b + 4)) == "base - anchor - 0x4"  # neg addend folds NEGATED into the subtraction
    assert regions._render_value(a - (b - 4)) == "base - anchor + 0x4"
    assert regions._render_value((a - (b + 4)) + 2) == "base - anchor - 0x4 + 0x2"
    assert regions._render_value(a - cento.lo16(b + 4)) == "base - lo16(anchor + 0x4)"  # xform applies to (value + addend); parens keep it exact
    r = cento.length(rec[0x8:0x10])
    assert regions._render_value(r) == "length(rec[0x8:0x10])"
    assert regions._render_value(cento.crc32_mpeg2(rec[0x8:0x10], expect=0x11)) == "crc32_mpeg2(rec[0x8:0x10], expect=0x11)"
    assert regions._render_value(cells.Reduce(fn="length", span=cells.Span("rec", a, 0x10))) == "length(rec[base:0x10])"  # symbolic span endpoint
    assert regions._render_value(cento.Writeback("boot_token")) == "writeback('boot_token')"
    assert regions._render_value(cento.Writeback.discard("noise")) == "writeback('noise', discarded)"
    assert regions._render_value(7) == "7"  # ints stay repr (explain pins hold)


class Mixed(views.View):
    byte: views.u8
    delta: views.i8
    word: views.u32


def test_literal_writes_are_range_checked_by_declared_width() -> None:
    pkt = regions.Layout().region("pkt")
    h = pkt.at(0, Mixed, "h")
    with pytest.raises(errors.PlacementError, match=r"does not fit u8 \[0x0 \.\. 0xff\]"):
        h.byte = 0x100
    with pytest.raises(errors.PlacementError, match="does not fit i8"):
        h.delta = -129
    with pytest.raises(errors.PlacementError, match="does not fit u32"):
        h.word = -1  # unsigned fields refuse negatives instead of silently wrapping
    h.byte, h.delta, h.word = 0xFF, -4, 0xDEADBEEF  # in-range literals, signed emitted two's-complement
    image = pkt.layout.emit(emit.Backend.IMAGE).artifact["pkt"]
    assert image[:6] == bytes.fromhex("fffcefbeadde")
    with pytest.raises(errors.PlacementError, match="does not fit a 1-byte cell"):
        pkt.cell(0x8, 1).write(0x1FF)  # raw literals refuse overflow too; computed values (Delta/Reduce/slices) keep documented wrap
    pkt.cell(0x8, 1).write(-1)  # two's-complement idiom stays legal on raw cells (no declared signedness)
    assert pkt.layout.emit(emit.Backend.IMAGE).artifact["pkt"][0x8] == 0xFF


class Table(views.View):
    regs = views.Field(views.u32 * 4)
    name = views.Field(views.Bytes(8))


def test_array_fields_index_write_and_whole_assignment() -> None:
    blk = regions.Layout().region("blk")
    h = blk.at(0, Table, "t")
    h.regs = [0x11, 0x22, 0x33, 0x44]
    arr = h.regs
    assert isinstance(arr, regions.FieldArrayHandle)  # a CellHandle subclass; the isinstance narrows for indexing
    arr[2] = 0x5EC0DE02  # element write, with its own owner path
    assert len(arr) == 4 and arr[1].path == "blk.t.regs[1]" and arr.span == cells.Span("blk", 0x0, 0x10)
    image = blk.layout.emit(emit.Backend.IMAGE).artifact["blk"]
    assert image[0x0:0x10] == bytes.fromhex("110000002200000002dec05e44000000")
    with pytest.raises(errors.PlacementError, match="3 values for 4 elements"):
        h.regs = [1, 2, 3]
    with pytest.raises(errors.PlacementError, match="list/tuple of 4 values"):
        h.regs = 7
    with pytest.raises(IndexError, match=r"regs\[4\]"):
        arr[4] = 0
    with pytest.raises(errors.PlacementError, match=r"regs\[0\]: .* does not fit u32"):
        h.regs = [1 << 32, 0, 0, 0]


class Attributed(views.View):
    blob = views.Field(views.u8 * 8)
    words = views.Field(views.u32 * 2)


def test_bytes_writes_to_u8_arrays_and_bytes_fields() -> None:
    """bytes-valued writes: u8 arrays take bytes with one attributed cell per byte (wider elements
    refuse the endianness ambush); Bytes(n) fields emit byte-identical on both endians."""
    blk = regions.Layout().region("blk")
    h = blk.at(0, Attributed, "t")
    h.blob = b"MERIDIAN"  # same write type as a Bytes(8) field...
    image = blk.layout.emit(emit.Backend.IMAGE).artifact["blk"]
    assert image[:8] == b"MERIDIAN"
    assert blk.layout.cells()[("blk", 3)].owner == "blk.t.blob[3]"  # ...but with one attributed cell per byte
    with pytest.raises(errors.PlacementError, match=r"bytes writes need a u8-element array"):
        h.words = b"12345678"  # wider elements would be an endianness ambush: assign a list
    with pytest.raises(errors.PlacementError, match="7 values for 8 elements"):
        h.blob = b"MK1-SEC"
    for endian in ("big", "little"):
        blk = regions.region("blk", endian=endian)
        t = blk.at(0, Table, "t")
        t.name = b"MERIDIAN"
        image = blk.layout.emit(emit.Backend.IMAGE).artifact["blk"]
        assert image[0x10:0x18] == b"MERIDIAN"  # Bytes(n) fields are endian-neutral: identical bytes under both layouts
    with pytest.raises(errors.PlacementError, match=r"Bytes\(8\) field got 3 bytes"):
        t.name = b"MK1"
    with pytest.raises(errors.PlacementError, match=r"Bytes\(8\) fields take bytes"):
        t.name = 0x4D4B


def test_read_contract() -> None:
    """CellHandle.read() is fail-closed: literal reads honor signedness and layout endianness;
    residuals, missing cells, and runtime-written cells refuse; arrays redirect to elements."""
    pkt = regions.Layout().region("pkt", max_size=0x10)
    h = pkt.at(0, Mixed, "h")
    h.word = 0xDEADBEEF
    h.delta = -4
    assert h.word.read() == 0xDEADBEEF
    assert h.delta.read(signed=True) == -4 and h.delta.read() == 0xFC  # same bytes, both interpretations
    le = regions.region("le", endian="little")
    le[0] = 0x11223344
    assert le.cell(0).read() == 0x11223344  # read undoes the layout's own endianness, not a fixed one
    pkt.cell(0xC).write("late_sym")
    with pytest.raises(errors.ResolveError, match="awaiting late_sym"):
        pkt.cell(0xC).read()
    with pytest.raises(errors.PlacementError, match="no cell here"):
        pkt.cell(0x8).read()
    w = pkt.cell(0x4)
    w.write(cells.Writeback("token"))
    with pytest.raises(errors.ResolveError, match="runtime-written"):
        w.read()
    blk = regions.Layout().region("blk")
    t = blk.at(0, Table, "t")
    t.regs = [1, 2, 3, 4]
    arr = t.regs
    assert isinstance(arr, regions.FieldArrayHandle)
    assert [arr[i].read() for i in range(4)] == [1, 2, 3, 4]
    with pytest.raises(errors.PlacementError, match=r"read an element \(blk.t.regs\[i\].read\(\)\)"):
        arr.read()


def test_image_sugar_and_naming() -> None:
    """region.image()/bytes() and layout.image(name): fail-closed sugar over emit, with partial=
    fill, writeback tolerance, and did-you-mean naming refusals."""
    frame = regions.region("frame", max_size=0x10, pad=4)
    reference = frame.layout.emit(emit.Backend.IMAGE).artifact["frame"]
    assert frame.image() == reference and bytes(frame) == reference
    assert frame.layout.image() == reference  # single-region layout: the name may be omitted
    assert frame.layout.image("frame") == reference
    frame[0x4] = "leak_sym"  # a pending symbol in this region
    with pytest.raises(errors.ResolveError, match="awaiting leak_sym"):
        frame.image(final=False)  # the draft read names what it awaits
    with pytest.raises(errors.EmitError, match="final emit refused"):
        bytes(frame)  # the bare read is the gate
    with pytest.raises(errors.ResolveError, match="awaiting leak_sym") as exc:
        frame.image(final=False)
    partial = exc.value.partial  # the refusal carries the fill-padded draft bytes
    assert partial is not None and len(partial) == 0x10 and partial[0x4:0x8] == b"\x00" * 4  # fill where the symbol will land
    wb = regions.region("wb", max_size=0x8)
    wb[0] = cells.Writeback("token")
    assert wb.image() == b"\x00" * 0x8  # R1: runtime-written cells never block
    layout = regions.Layout()
    layout.region("alpha", max_size=4)
    layout.region("beta", max_size=4)
    with pytest.raises(errors.PlacementError, match=r"2 regions \(alpha, beta\); image\(name\) needs the name"):
        layout.image()
    with pytest.raises(errors.PlacementError, match="no region named 'alpah'; did you mean 'alpha'"):
        layout.image("alpah")
    assert layout.image("alpha") == b"\x00" * 4  # cell-less region: fill out to max_size


def test_image_final_is_the_default() -> None:
    """image()/emit()/bytes() run the final gate by default; final=False is the draft read whose
    refusal carries the fill-padded bytes as .partial; the removed partial= kwarg teaches."""
    frame = regions.region("frame", max_size=0x10, pad=4)
    frame[0x4] = "leak_sym"  # a pending symbol in this region
    with pytest.raises(errors.EmitError, match=r"final emit refused: layout-wide pending symbols \['leak_sym'\]"):
        frame.image()  # the bare read IS the gate now
    with pytest.raises(errors.EmitError, match="final emit refused"):
        bytes(frame)  # bytes(region) follows image()'s default
    with pytest.raises(errors.EmitError, match="final emit refused"):
        frame.layout.emit(emit.Backend.IMAGE)  # emit() gates by default too
    with pytest.raises(errors.EmitError, match="final emit refused"):
        frame.layout.image()
    with pytest.raises(errors.ResolveError, match="awaiting leak_sym"):
        frame.image(final=False)  # the draft read: symbol-gated, named refusal, no full gate
    draft = frame.layout.emit(emit.Backend.IMAGE, final=False)  # the draft emit still lists the worklist
    assert [sorted(f.missing) for f in draft.fixups] == [["leak_sym"]]
    with pytest.raises(errors.ResolveError, match=r"\.partial on this error") as exc:
        frame.image(final=False)
    partial = exc.value.partial  # the refusal carries what partial= used to return
    assert partial is not None and len(partial) == 0x10 and partial[0x4:0x8] == b"\x00" * 4
    with pytest.raises(errors.PlacementError, match=r"image\(partial=\) is gone"):
        frame.image(partial=True)  # type: ignore[arg-type]  # the wrong-guess under test
    assert errors.ResolveError("plain").partial is None  # raisers without a buffer in hand stay legal
    frame.bind("leak_sym", 0xDEADBEEF)
    assert frame.image() == frame.image(final=False) == bytes(frame)  # resolved: the gate passes, the reads agree


def test_region_fill_contract() -> None:
    """region(fill=): one pattern in four spellings, offset-aligned tiling, and teaching refusals."""
    for fill in (0x41, "A", b"A", [0x41]):
        assert regions.region("r", max_size=4, fill=fill).image() == b"AAAA"  # one fill, four spellings
    tiled = regions.region("r", max_size=8, fill="JUNK")
    tiled[3:5] = 0xBEEF  # a write mid-pattern: the pattern is offset-aligned (byte o = pattern[o % n]), not resumed after the write
    assert tiled.layout.endian == "little" and tiled.image() == b"JUN\xef\xbeUNK"
    assert regions.region("r", max_size=5, fill=[0xDE, 0xAD]).image() == bytes.fromhex("deaddeadde")
    with pytest.raises(errors.PlacementError, match="is not a byte"):
        regions.Layout().region("r", fill=0x100)
    with pytest.raises(errors.PlacementError, match="must be ascii"):
        regions.region("r", max_size=4, fill="\u00e9")
    with pytest.raises(errors.PlacementError, match="at least one byte"):
        regions.region("r", max_size=4, fill=b"")
    with pytest.raises(errors.PlacementError, match="not bool"):
        regions.region("r", max_size=4, fill=True)
    with pytest.raises(errors.PlacementError, match="byte-sized ints"):
        regions.region("r", max_size=4, fill=[0x41, 0x1FF])


def test_region_bind_and_gated_image_final() -> None:
    stack = regions.region("stack", max_size=8, endian="little")
    stack[0:8] = cells.Ref("base", addend=0x10)
    stack.bind("base", 0x1000, source="region-level bind")
    assert stack.image() == (0x1010).to_bytes(8, "little")

    # the gate is real: a cross-owner stomp blocks the bare image(), not the draft image(final=False)
    class W(views.View):
        q: views.u32

    stomp = regions.region("s", max_size=8)
    w = stomp.at(0, W, name="w")
    w.q = 1
    stomp.cell(0).write(2)  # different owner: CHK-008 at the gate
    assert stomp.image(final=False)  # draft mode: symbol-gated only
    with pytest.raises(errors.EmitError, match="CHK-008"):
        stomp.image()


# -- placements: at/alloc/name-lookup, handles, aliases --------------------------


class Hdr(views.View, size=8):
    magic = views.Field(0, views.u32)
    length = views.Field(4, views.u16)
    csum = views.Field(6, views.u16)


class Frame(views.View, size=0x10):
    a = views.Field(0x8, views.u32, alias="restores_r30")
    lr = views.Field(0x14, views.u32, external=True)


def test_place_field_assignment_and_aliases() -> None:
    """at() placements: field assignment writes attributed cells, handles carry addresses, semantic
    aliases write the real field, and typos get did-you-mean."""
    layout = regions.Layout()
    pkt = layout.region("pkt")
    h = pkt.at(0, Hdr)
    h.magic = 0xDEADBEEF
    h.length = 16
    assert layout.force(("pkt", 0)) == b"\xef\xbe\xad\xde"
    assert layout.force(("pkt", 4)) == b"\x10\x00"
    assert h.magic.addr == cells.Ref("pkt_base", addend=0)
    assert h.addr == cells.Ref("pkt_base", addend=0)
    f = pkt.at(0x20, Frame, "ff")
    f.restores_r30 = 7  # semantic alias writes the real field
    assert layout.force(("pkt", 0x28)) == (7).to_bytes(4, "little")
    with pytest.raises(AttributeError, match="restores_r30"):
        _ = f.restores_r3  # typo -> did-you-mean suggestion


def test_array_handle_and_auto_names() -> None:
    layout = regions.Layout()
    pkt = layout.region("pkt")
    arr = pkt.at(0x40, Frame * 2)
    assert len(arr) == 2
    arr[1].a = 5
    assert layout.force(("pkt", 0x40 + 0x10 + 0x8)) == (5).to_bytes(4, "little")
    assert arr.path.endswith("frame_1")  # auto-named from the type
    fr = pkt["frame_1"]
    assert isinstance(fr, regions.ArrayHandle)
    assert fr[0].path.endswith("[0]")
    with pytest.raises(KeyError, match="frame_1"):
        _ = pkt["frame1"]  # did-you-mean in KeyError


def test_placement_records() -> None:
    """Placement records: over= demands why= and both are recorded; external field spans are recorded per element."""
    layout = regions.Layout()
    pkt = layout.region("pkt")
    pkt.at(0, Hdr, "h")
    with pytest.raises(errors.PlacementError, match="why"):
        pkt.at(4, Hdr, "overlay", over=("h",))
    ov = pkt.at(4, Hdr, "overlay", over="h", why="deliberate: kernel writeback lands here")
    rec = next(p for p in pkt.placements if p.name == "overlay")
    assert rec.over == ("h",) and rec.why is not None and ov.offset == 4
    pkt.at(0x40, Frame * 2, "ffs")
    rec = next(p for p in pkt.placements if p.name == "ffs")
    assert rec.extent == 0x20
    assert rec.ext_spans() == [(0x40 + 0x14, 0x40 + 0x18), (0x50 + 0x14, 0x50 + 0x18)]


def test_alloc_first_fit_and_cap() -> None:
    layout = regions.Layout()
    pkt = layout.region("pkt", max_size=0x20)
    pkt.at(0, Hdr, "h")
    auto = pkt.alloc(Hdr)
    assert auto.offset == 8  # first free, align 4
    with pytest.raises(errors.PlacementError, match="max_size"):
        pkt.alloc(Frame * 2)  # 0x20 stride-0x10 x2 does not fit


def test_at_bounds_parity() -> None:
    layout = regions.Layout()
    pkt = layout.region("pkt", max_size=8)
    with pytest.raises(errors.PlacementError, match="negative offset"):
        pkt.at(-4, Hdr, "neg")
    with pytest.raises(errors.PlacementError, match="exceeds max_size"):
        pkt.at(4, Hdr, "h")  # extent [4, 12) > 8
    free = layout.region("free")  # unbounded regions still place anywhere non-negative
    free.at(0x1000, Hdr, "far")


# -- View type declaration -------------------------------------------------------


class FrameView(views.View, size=0xB0):
    saved_r30 = views.Field(0xA8, views.u32, alias="restores_r30")
    saved_r31 = views.Field(0xAC, views.u32)
    saved_lr = views.Field(0xB4, views.u32, external=True, doc="next hop PC; lives in the NEXT frame's extent")


class Auto(views.View):
    a = views.Field(0, views.u16)
    b = views.Field(6, views.u8)


def test_view_class_declaration() -> None:
    """View class declaration: field/alias collection, explicit and derived sizes (externals not
    counted), ArraySpec arithmetic, and the size-must-cover-interior refusal."""
    assert set(FrameView.__fields__) == {"saved_r30", "saved_r31", "saved_lr"}
    assert FrameView.__fields__["saved_lr"].external is True
    assert FrameView.__aliases__ == {"restores_r30": "saved_r30"}
    assert FrameView.__size__ == 0xB0  # explicit; external field NOT counted
    assert Auto.__size__ == 7  # derived: max interior field end
    spec = FrameView * 2
    assert isinstance(spec, views.ArraySpec)
    assert spec.count == 2 and spec.eff_stride == 0xB0 and spec.extent == 0x160
    wide = views.ArraySpec(FrameView, 3, stride=0x100)
    assert wide.extent == 0x300
    with pytest.raises(ValueError, match="Bad.*interior"):

        class Bad(views.View, size=4):
            f = views.Field(8, views.u32)

    # external fields beyond size stay legal (FrameView above declares one)
    assert FrameView.__size__ == 0xB0


def test_offset_packing_contract() -> None:
    """Offset packing: annotations pack in order, auto-offset Fields pack past pinned gaps, width
    arrays and Bytes pack like scalars, and the two auto-packing streams refuse to mix."""

    class Args(views.View, size=0x10):
        op: views.u32
        a0: views.u32
        out: views.u16
        end: views.u8

    assert [(n, f.offset, f.width.size) for n, f in Args.__fields__.items()] == [("op", 0x0, 4), ("a0", 0x4, 4), ("out", 0x8, 2), ("end", 0xA, 1)]
    assert Args.__size__ == 0x10  # explicit size still wins over the packed interior end

    class Blk(views.View):
        op = views.Field(views.u32)  # -> 0x0
        a0 = views.Field(0x8, views.u32)  # pinned: a deliberate gap
        end = views.Field(views.u32)  # -> 0xC: next free after everything above

    assert [(n, f.offset) for n, f in Blk.__fields__.items()] == [("op", 0x0), ("a0", 0x8), ("end", 0xC)]
    assert Blk.__size__ == 0x10  # derived from the packed fields

    class Ok(views.View):  # the sanctioned mix: annotations pack 0..8, the pinned aliased tail sits at their end
        r30: views.u32
        r31: views.u32
        lr = views.Field(0x8, views.u32, alias="pc")

    assert [(n, f.offset) for n, f in Ok.__fields__.items()] == [("r30", 0x0), ("r31", 0x4), ("lr", 0x8)]
    assert Ok.__aliases__ == {"pc": "lr"}

    with pytest.raises(ValueError, match=r"pinned at 0x4, before/inside the annotation-packed run \(which ends at 0x8\)"):

        class Inside(views.View):
            op: views.u32
            a0: views.u32
            gap = views.Field(0x4, views.u32)  # inside the annotation run: source order is unrecoverable

    with pytest.raises(ValueError, match="auto-offset Field assignments cannot mix"):

        class Auto(views.View):
            op: views.u32
            a0 = views.Field(views.u32)  # two auto-packing streams: ambiguous, refused


def test_widths_are_types_and_field_arg_shapes_teach() -> None:
    """Widths are types with size/signedness facts; Field() argument shapes teach their fixes."""
    assert issubclass(views.u32, views.Width) and views.u32.size == 4
    with pytest.raises(TypeError, match="width missing"):
        views.Field(0x0)  # type: ignore[call-overload]
    with pytest.raises(TypeError, match="offset must be an int"):
        views.Field(views.u32, views.u32)  # type: ignore[call-overload]
    with pytest.raises(ValueError, match="explicit offsets by definition"):

        class BadExt(views.View):
            tail = views.Field(views.u32, external=True)

    table = {
        views.u8: (1, False),
        views.u64: (8, False),
        views.i8: (1, True),
        views.i16: (2, True),
        views.i64: (8, True),
    }
    for width, (size, signed) in table.items():
        assert issubclass(width, views.Width) and (width.size, width.signed) == (size, signed)


def test_annotation_spellings_escapes_arrays_and_bytes() -> None:
    """Annotation handling: non-width annotations refuse (with the sanctioned ClassVar/underscore
    escapes), while array and Bytes spellings work at runtime."""
    with pytest.raises(ValueError, match="cannot resolve annotation 'u33'"):

        class Typo(views.View):
            op: u33  # type: ignore[name-defined]  # noqa: F821 -- the typo is the test

    with pytest.raises(ValueError, match="is not width-shaped"):

        class NotAField(views.View):
            op: int

    class Escapes(views.View):  # sanctioned non-field class data passes
        _cursor_hint: int
        kind: typing.ClassVar[str] = "argblock"
        op: views.u32

    assert list(Escapes.__fields__) == ["op"] and Escapes.kind == "argblock"

    # The array/Bytes annotation spellings are expressions, not types: runtime-supported for the
    # mypy-less workflow, [valid-type]-flagged under strict gates like this suite's -- hence the ignores.
    class Rec(views.View):
        kind: views.u8
        regs: views.u32 * 4  # type: ignore[valid-type]
        name: views.Bytes(8)  # type: ignore[valid-type]

    regs = Rec.__fields__["regs"]
    assert isinstance(regs.width, views.WidthArray) and (regs.offset, regs.width.size) == (0x1, 0x10)
    name = Rec.__fields__["name"]
    assert isinstance(name.width, views.Bytes) and (name.offset, name.width.size) == (0x11, 8)
    assert Rec.__size__ == 0x19


def test_width_array_and_bytes_pack_like_scalars() -> None:
    class Blk(views.View):
        regs = views.Field(views.u32 * 4)  # -> 0x0, extent 0x10
        name = views.Field(views.Bytes(8))  # -> 0x10
        tail = views.Field(views.u16)  # -> 0x18

    spec = Blk.__fields__["regs"].width
    assert isinstance(spec, views.WidthArray) and (spec.elem, spec.count, spec.size) == (views.u32, 4, 0x10)
    assert [(n, f.offset) for n, f in Blk.__fields__.items()] == [("regs", 0x0), ("name", 0x10), ("tail", 0x18)]
    assert Blk.__size__ == 0x1A
    with pytest.raises(ValueError, match="at least one element"):
        views.u32 * 0


def test_field_defaults_contract() -> None:
    """Field defaults: the annotation and Field(default=) spellings declare-and-assign at placement
    (arrays stamp every element), and conflicting or unfit defaults refuse."""
    lib = cento.Ref("base")

    class Chain(cento.View, dense=True):
        # the declare-and-assign annotation spelling is runtime-only: mypy --strict flags
        # [assignment] (like `u32 * 4` flags [valid-type]) -- Field(default=) is the typed form
        first: cento.u32 = lib + 0x10  # type: ignore[assignment]
        second: cento.u32 = 7  # type: ignore[assignment]

    layout = cento.Layout()
    pkt = layout.region("pkt", max_size=8)
    h = pkt.at(0, Chain, name="c")  # placing the declaration writes both fields
    assert "CHK-010" not in {i.code for i in layout.check().errors}  # defaults satisfy density
    layout.bind("base", 0x1000, source="test")
    assert layout.image("pkt") == (0x1010).to_bytes(4, "little") + (7).to_bytes(4, "little")
    h.second = 9  # same owner: a later explicit write updates the default silently
    assert "CHK-008" not in {i.code for i in layout.check().errors}
    assert layout.image("pkt")[4:] == (9).to_bytes(4, "little")

    class Slot(cento.View):
        q = cento.Field(cento.u16, default=0xBEEF)

    layout = cento.Layout()
    pkt = layout.region("pkt", max_size=8)
    pkt.at(0, Slot * 4, name="spray")
    assert layout.image("pkt") == bytes.fromhex("efbe") * 4

    with pytest.raises(ValueError, match="pick one spelling"):

        class Both(cento.View):
            x: cento.u32 = cento.Field(0, cento.u32)  # type: ignore[assignment]

    with pytest.raises(TypeError, match="external=True.*no default"):
        cento.Field(0, cento.u32, external=True, default=1)

    class TooBig(cento.View):
        x: cento.u8 = 0x1FF  # type: ignore[assignment]

    layout = cento.Layout()
    pkt = layout.region("pkt", max_size=4)
    with pytest.raises(cento.PlacementError, match="does not fit"):
        pkt.at(0, TooBig, name="t")  # the default is validated at placement, like any write


# -- expect_sym: leak-plausibility guards on bind ------------------------------


def test_expect_sym_contract() -> None:
    """expect_sym(): implausible binds refuse (range/alignment), already-bound values are judged at
    declaration, and vacuous or empty expectations refuse."""
    layout = regions.Layout()
    layout.expect_sym("libc_base", range=(0x40000000, 0x4FFFFFFF), align=0x1000)
    with pytest.raises(errors.PlacementError, match="violates the declared expectation range"):
        layout.bind("libc_base", 0x100, source="mis-parsed leak")
    with pytest.raises(errors.PlacementError, match="violates the declared alignment"):
        layout.bind("libc_base", 0x40000004, source="page-offset leak")
    layout.bind("libc_base", 0x40001000, source="leak")  # plausible: binds normally
    assert layout.env.get("libc_base") == 0x40001000
    layout = regions.Layout()
    layout.bind("base", 0x7, source="t")
    with pytest.raises(errors.PlacementError, match="violates the declared alignment"):
        layout.expect_sym("base", align=4)  # declared after the fact: judged immediately
    with pytest.raises(errors.PlacementError, match="guards nothing"):
        layout.expect_sym("empty")
    with pytest.raises(errors.PlacementError, match="empty range"):
        layout.expect_sym("r", range=(2, 1))


# -- Layout.map(): the ASCII memory map -------------------------------------------


def test_map_renders_the_manifest() -> None:
    """map(): region header facts, placement rows with over=, gap rows, raw-cell rows, and per-region pending symbols -- a display view over manifest()."""
    layout = regions.Layout()
    slab = layout.region("slab", max_size=0x40)
    slab.at(0x0, Hdr, "h")
    slab.at(0x4, Hdr, "h2", over=("h",), why="alias")  # genuine overlap: Hdr is 8 bytes, so [0x4, 0xc) shares [0x4, 0x8) with h
    slab[0x20] = layout.sym("libc")
    layout.bind("slab_base", 0x1000)
    text = layout.map()
    lines = text.splitlines()
    assert lines[0] == "region slab  base slab_base=0x1000  max 0x40  fill 00  word 4"
    assert "  +0x0000..+0x0008  slab.h" in lines
    assert any(line.startswith("  +0x0004..+0x000c  slab.h2") and "over=h" in line for line in lines)
    assert "  +0x0024..+0x0040  (fill)" in lines
    assert "  raw: +0x0020 w4  slab.raw+0x20" in lines
    assert "  pending: libc" in lines
    assert all(line == line.rstrip() for line in lines)  # no trailing whitespace on any line
    # unbound-base spelling; an empty region shows just its header
    layout.region("aux")
    assert "region aux  base aux_base (unbound)" in layout.map()


# -- abi as a construction-time fact carrier ----------------------------------


def test_abi_supplies_word_and_endian_at_every_entry_point() -> None:
    """Precedence: explicit kwarg > abi fact > built-in default, at region(), fit(), and Layout()."""
    import cento.abi

    assert cento.region("a", abi="x86_64").word == 8  # abi fills word
    assert cento.region("b", abi="x86_64", word=4).word == 4  # explicit wins, no refusal
    assert cento.region("c", abi="ppc32").layout.endian == "big"
    assert cento.fit({0: [1]}, abi="ppc32").image() == (1).to_bytes(4, "big")  # word 4, endian big
    lay = cento.Layout(abi=cento.abi.AARCH64)
    assert lay.abi is cento.abi.AARCH64 and lay.endian == "little"
    assert lay.region("r").word == 8


def test_abi_endian_conflict_refuses_and_chain_inherits() -> None:
    """An endian= that contradicts the abi refuses (teaching); region.chain() inherits the layout abi and refuses a conflicting restatement."""
    with pytest.raises(errors.PlacementError, match=r"abi 'ppc32' is big-endian.*endian='little'"):
        cento.Layout(abi="ppc32", endian="little")
    r = cento.region("r", max_size=0x100, abi="x86_64")
    c = r.chain("c", at=0, arm=False)  # no abi= restated
    assert c.abi is not None and c.abi.name == "x86_64"
    with pytest.raises(errors.ChainError, match=r"chain 'c2'.*abi 'ppc32'.*layout carries abi 'x86_64'"):
        r.chain("c2", at=0x80, abi="ppc32", arm=False)
