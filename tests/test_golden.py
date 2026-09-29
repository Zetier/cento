# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Golden-bytes regression helper (cento.golden): owner-attributed divergences, fail-closed compare, deterministic render."""

from __future__ import annotations

import pytest

import cento


class Hdr(cento.View, size=0x8):
    magic: cento.u32
    flags: cento.u32


def _build(*, flags: int = 0x1) -> cento.Region:
    rec = cento.region("rec", max_size=0x10, fill="A", endian="big")
    h = rec.at(0x0, Hdr, name="hdr")
    h.magic = 0x4D4B3031
    h.flags = flags
    rec.cell(0x8).write(0xC0DE0001)
    return rec


REFERENCE = bytes.fromhex("4d4b303100000001c0de000141414141")  # _build(flags=0x1).image(): two cells, a raw word, then fill


def test_identical_bytes_are_ok() -> None:
    diff = cento.golden(REFERENCE).compare(_build())
    assert diff.ok
    assert diff.reference_len == diff.image_len == 0x10
    assert diff.divergences == ()
    assert diff.render() == "golden: OK -- image == reference (16 bytes)"


def test_single_cell_divergence_names_the_exact_owner_path() -> None:
    diff = cento.golden(REFERENCE).compare(_build(flags=0x3))
    assert not diff.ok
    (run,) = diff.divergences
    assert (run.offset, run.length, run.expected, run.got, run.owner) == (0x7, 1, b"\x01", b"\x03", "rec.hdr.flags")
    assert diff.render().splitlines()[0] == "golden: DIVERGED -- first divergent run at +0x0007 in rec.hdr.flags"


def test_fill_divergence_is_attributed_unowned() -> None:
    reference = REFERENCE[:0xC] + b"AAAB"  # the reference expects a tail byte no cell ever wrote
    diff = cento.golden(reference).compare(_build())
    (run,) = diff.divergences
    assert (run.offset, run.expected, run.got, run.owner) == (0xF, b"B", b"A", "(unowned)")


def test_placed_but_unwritten_bytes_attribute_the_placement_as_fill() -> None:
    rec = cento.region("rec", max_size=0x8, fill="A")
    rec.at(0x0, Hdr, name="hdr")  # placed, no field written: every byte under it is region fill
    diff = cento.golden(b"B" * 8).compare(rec)
    (run,) = diff.divergences
    assert run.owner == "rec.hdr (fill)"


def test_length_mismatch_is_a_named_divergence_not_an_exception() -> None:
    diff = cento.golden(REFERENCE + b"TAIL").compare(_build())
    assert not diff.ok
    assert (diff.reference_len, diff.image_len) == (0x14, 0x10)
    tail = diff.divergences[-1]
    assert (tail.offset, tail.length, tail.expected, tail.got, tail.owner) == (0x10, 4, b"TAIL", b"", "(image ends)")
    assert "length: reference 20 bytes, image 16 bytes" in diff.render()


def test_longer_image_tail_attributes_normally() -> None:
    diff = cento.golden(REFERENCE[:0xC]).compare(_build())  # image runs 4 fill bytes past the reference
    tail = diff.divergences[-1]
    assert (tail.offset, tail.length, tail.expected, tail.got, tail.owner) == (0xC, 4, b"", b"AAAA", "(unowned)")


def test_unresolved_region_raises_resolve_error() -> None:
    rec = _build()
    rec.cell(0xC).write("late_leak")
    with pytest.raises(cento.ResolveError, match="late_leak"):
        cento.golden(REFERENCE).compare(rec)


def test_compare_refuses_non_region_and_golden_refuses_non_bytes() -> None:
    with pytest.raises(cento.PlacementError, match="Region handle"):
        cento.golden(REFERENCE).compare(_build().layout)  # type: ignore[arg-type]  # the refusal is the behavior under test
    with pytest.raises(cento.PlacementError, match="must be bytes"):
        cento.golden("41414141")  # type: ignore[arg-type]  # a hex STRING is the classic capture slip
    assert cento.golden(bytearray(b"AB")).reference == b"AB"  # type: ignore[arg-type]  # bytes-like captures normalize at runtime; the TYPE asks for bytes


def test_render_is_deterministic_across_identical_builds() -> None:
    one = cento.golden(REFERENCE).compare(_build(flags=0x3)).render()
    two = cento.golden(REFERENCE).compare(_build(flags=0x3)).render()
    assert one == two
    assert one.encode("ascii")  # plain, presentation-free text


def test_render_caps_long_runs_but_the_record_keeps_them() -> None:
    diff = cento.golden(b"B" * 0x20).compare(cento.region("rec", max_size=0x20, fill="A"))
    (run,) = diff.divergences
    assert run.expected == b"B" * 0x20  # the frozen record is full
    assert "expected 42424242424242424242424242424242.. (32 bytes)" in diff.render()  # the rendering is capped, deterministically
