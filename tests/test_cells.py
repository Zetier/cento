# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""The cells.py subject: values, reducers, de Bruijn.

Value vocabulary + Env + resolve().
Reducer registry: known-answer tests.
de Bruijn cycle pad: de_bruijn() / cycle() / cycle_find() (pwntools-cycle analog).
"""

from __future__ import annotations

import itertools

import pytest

import cento
import cento.cells as cells

# -- value vocabulary + Env + resolve() ----------------------------------------


def test_ref_arithmetic_and_delta() -> None:
    """Ref/Delta arithmetic: addend algebra, Ref - Ref = Delta, non-Ref subtraction refuses."""
    r = cells.Ref("base")
    assert (r + 8).addend == 8  # (int + Ref was dead sugar: removed with __radd__)
    assert (r + 8 - 4).addend == 4
    d = cells.Ref("a") - cells.Ref("b")
    assert isinstance(d, cells.Delta)
    assert (d + 2).addend == 2
    with pytest.raises(TypeError):
        cells.Ref("a") - "x"  # type: ignore[operator]


def test_env_bind_and_resolve_contract() -> None:
    """Env bind/rebind/generation bookkeeping, then resolve(): consts, Refs, dep recording, Delta wrap deferral."""
    env = cells.Env()
    assert env.get("x") is None
    env.bind("x", 0x1000, source="test")
    assert env.get("x") == 0x1000
    g = env.generation
    env.bind("x", 0x2000)  # rebind allowed, bumps generation
    assert env.get("x") == 0x2000 and env.generation == g + 1
    assert env.bindings()["x"].source == "manual"
    env = cells.Env()
    assert cells.resolve(7, env) == 7
    assert cells.resolve(9, env) == 9  # ints resolve as themselves; no wrapper type exists
    r = cells.resolve(cells.Ref("missing"), env)
    assert isinstance(r, cells.Residual) and r.missing == frozenset({"missing"})
    env.bind("missing", 0x100)
    assert cells.resolve(cells.Ref("missing", addend=4), env) == 0x104
    env = cells.Env()
    env.bind("a", 1)
    deps: set[str] = set()
    cells.resolve(cells.Ref("a") - cells.Ref("b"), env, deps)
    assert deps == {"a", "b"}
    env = cells.Env()
    env.bind("t", 0x100)
    env.bind("n", 0x400)
    v = cells.resolve(cells.Ref("t") - cells.Ref("n"), env)
    assert v == -0x300  # masking to width happens at encode time (regions.py)


def test_xforms() -> None:
    env = cells.Env()
    env.bind("s", 0x40069780)
    assert cells.resolve(cells.lo16(cells.Ref("s")), env) == 0x9780
    assert cells.resolve(cells.hi16(cells.Ref("s")), env) == 0x4006
    # HA16: high half adjusted for signed-low (lis/ori vs lis/addi pairing)
    assert cells.resolve(cells.ha16(cells.Ref("s")), env) == 0x4007


def test_registered_xform_names_resolve_via_env() -> None:
    """Ref.xform may be a registered name: Env.xforms resolves it; an unknown name is an XformError (CHK-014 at check time)."""
    env = cells.Env()
    env.bind("s", 0x40069780)
    env.xforms["pg"] = lambda v: v >> 12
    assert cells.resolve(cells.Ref("s", xform="pg"), env) == 0x40069
    with pytest.raises(cento.errors.XformError, match="unknown xform 'nope'"):
        cells.resolve(cells.Ref("s", xform="nope"), env)


# -- reducer registry: known-answer tests ---------------------------------------

SPAN = cells.Span("r", 0, 4)


def test_reducer_known_answers() -> None:
    """The reducer registry: known-answer values for every registered reducer, plus the Reduce-building sugar."""
    # CRC-32/MPEG-2: poly 0x04C11DB7, init 0xFFFFFFFF, no reflect, no xorout.
    # Standard check value for b"123456789" is 0x0376E6E7.
    assert cells.REDUCERS["crc32_mpeg2"](b"123456789") == 0x0376E6E7
    assert cells.REDUCERS["xor_fold"](bytes.fromhex("deadbeef00000010")) == 0xDEADBEFF
    assert cells.REDUCERS["xor_fold"](b"\xde\xad") == 0xDEAD0000  # zero-padded to 4
    data = bytes.fromhex("deadbeef0010")
    assert cells.REDUCERS["sum16"](data) == 0x9DAC  # (0xDEAD+0xBEEF+0x0010) & 0xFFFF
    # udp_cksum: ones-complement of ones-complement sum
    assert cells.REDUCERS["udp_cksum"](b"\x00\x01\xf2\x03") == (~((0x0001 + 0xF203) & 0xFFFF)) & 0xFFFF
    # CRC-8 (poly 0x07, init 0x00): check value for b"123456789" is 0xF4.
    assert cells.REDUCERS["crc8"](b"123456789") == 0xF4
    assert cells.REDUCERS["length"](b"\x00" * 17) == 17
    r = cells.crc32_mpeg2(SPAN, expect=0x1234)
    assert isinstance(r, cells.Reduce) and r.fn == "crc32_mpeg2" and r.expect == 0x1234
    assert cells.sum16(SPAN).expect is None


def test_builtin_reducers_are_frozen() -> None:
    """The builtin reducer table is a read-only mapping: layout-scoped register_reducer is the extension point."""
    with pytest.raises(TypeError):
        cells.REDUCERS["evil"] = len  # type: ignore[index]  # process-global mutation is unrepresentable


# -- de Bruijn cycle pad ---------------------------------------------------------

# Classic B(26, 4) prefix (Lyndon-word concatenation): "a" + "aaab" + "aaac" + ...
KAT_PREFIX = b"aaaabaaacaaadaaaeaaafaaagaaahaaa"


def test_de_bruijn_and_cycle_generation() -> None:
    """de_bruijn()/cycle() generation: KAT prefix, int yield, prefix/length, full period, and generation refusals."""
    got = bytes(itertools.islice(cells.de_bruijn(), len(KAT_PREFIX)))
    assert got == KAT_PREFIX
    first = next(iter(cells.de_bruijn()))
    assert isinstance(first, int) and first == ord("a")
    assert cento.cycle(13) == b"aaaabaaacaaad"
    assert cento.cycle(0) == b""
    assert len(cento.cycle(2048)) == 2048
    pat = cento.cycle(3**2, alphabet=b"abc", n=2)
    assert len(pat) == 9
    # every 2-gram in the linear period is unique
    grams = {pat[i : i + 2] for i in range(len(pat) - 1)}
    assert len(grams) == 8
    with pytest.raises(ValueError, match=r"period"):
        cento.cycle(3**2 + 1, alphabet=b"abc", n=2)
    with pytest.raises(ValueError, match=r"alphabet"):
        cells.de_bruijn(alphabet=b"")
    with pytest.raises(ValueError, match=r"unique"):
        cells.de_bruijn(alphabet=b"aab")
    with pytest.raises(ValueError, match=r"n"):
        cells.de_bruijn(n=0)


def test_cycle_find_contract() -> None:
    """cycle_find(): bytes needles round-trip, int needles both endians, uniqueness across the window."""
    assert cento.cycle_find(b"aaad") == 9
    pat = cento.cycle(512)
    assert cento.cycle_find(pat[100:104]) == 100
    # bytes "aaad" observed as a little-endian u32 register value (the default)
    assert cento.cycle_find(0x64616161) == 9
    assert cento.cycle_find(0x64616161, endian="little") == 9
    # same bytes "aaad" read back as a big-endian u32
    assert cento.cycle_find(0x61616164, endian="big") == 9
    pat = cento.cycle(2048)
    grams = {pat[i : i + 4] for i in range(len(pat) - 3)}
    assert len(grams) == 2045  # all 4-grams in the window are unique
    for off in (0, 1, 511, 2044):
        assert cento.cycle_find(pat[off : off + 4]) == off


def test_cycle_find_defaults_little() -> None:
    pat = cells.cycle(0x40)
    off = 0x1C
    needle = int.from_bytes(pat[off : off + 4], "little")
    assert cells.cycle_find(needle) == off  # no endian= given: the default is the default target's


def test_cycle_find_refusals() -> None:
    """cycle_find() refusals: needle not in the pattern, wrong needle length, over-width int, bool needle."""
    with pytest.raises(ValueError, match=r"not.*found|no offset"):
        cento.cycle_find(b"\x00\x00\x00\x00")
    with pytest.raises(ValueError, match=r"n=4"):
        cento.cycle_find(b"aaa")
    with pytest.raises(ValueError, match=r"width"):
        cento.cycle_find(0x61616164, width=2)
    with pytest.raises(ValueError):
        cento.cycle_find(-1)
    with pytest.raises(ValueError, match=r"bool"):
        cento.cycle_find(True)


def test_region_fill_idiom_and_locate_from_image() -> None:
    """The documented region idiom: cells hold ints, so the pad is written word-by-word."""
    pad = cento.cycle(64)
    layout = cento.Layout()
    page = layout.region("page", max_size=0x100)
    for i in range(0, len(pad), 4):
        page.cell(0x10 + i).write(int.from_bytes(pad[i : i + 4], "little"))
    image = layout.emit(cento.Backend.IMAGE).artifact["page"]
    assert image[0x10 : 0x10 + 64] == pad
    # a "crashed" value observed at some offset inside the pad names that offset
    observed = int.from_bytes(image[0x10 + 36 : 0x10 + 40], "little")
    assert cento.cycle_find(observed) == 36


def test_facade_exports() -> None:
    assert "cycle" in cento.__all__ and "cycle_find" in cento.__all__
    assert cento.cycle is cells.cycle
    assert cento.cycle_find is cells.cycle_find


def test_layout_cycle_find_uses_the_layouts_endian() -> None:
    big = cento.Layout(endian="big")
    assert big.cycle_find(0x61616164) == 9  # "aaad" loaded big-endian: the flip is implicit
    assert cento.Layout().cycle_find(0x64616161) == 9  # the little default, same slot
    assert big.cycle_find(b"aaad") == 9  # bytes needles are endian-neutral
