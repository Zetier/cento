# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Teaching-error coverage for hour-one parameter mistakes (see the 2026-09-28 UX audit).

One test per guard: each entry-point mistake that used to crash raw (TypeError /
AttributeError / ValueError) or detonate later at image() now refuses immediately with a
teaching message. Error classes follow the family the neighboring guards in each function
already raise (PlacementError dominates; chain sites raise ChainError; cycle_find keeps its
documented ValueError family; Field keeps its TypeError family).
"""

import pytest

import cento
import cento.errors


def test_cycle_find_str_needle_teaches_bytes() -> None:
    with pytest.raises(ValueError, match=r"needle is str; pass bytes \(b'aaaa'\) or the int register value"):
        cento.cycle_find("aaaa")  # type: ignore[arg-type]


def test_lo16_on_int_teaches_ref() -> None:
    with pytest.raises(cento.errors.PlacementError, match=r"lo16 takes a Ref.*value & 0xffff"):
        cento.lo16(0x12345678)  # type: ignore[arg-type]


def test_hi16_and_ha16_on_int_teach_ref() -> None:
    with pytest.raises(cento.errors.PlacementError, match=r"hi16 takes a Ref.*\(value >> 16\) & 0xffff"):
        cento.hi16(0x12345678)  # type: ignore[arg-type]
    with pytest.raises(cento.errors.PlacementError, match=r"ha16 takes a Ref"):
        cento.ha16(0x12345678)  # type: ignore[arg-type]


def test_ref_plus_ref_teaches_delta() -> None:
    with pytest.raises(cento.errors.PlacementError, match=r"addresses do not add; subtract \(Ref - Ref\)"):
        cento.Ref("a") + cento.Ref("b")  # type: ignore[operator]


def test_ref_plus_float_refuses_at_the_plus() -> None:
    with pytest.raises(cento.errors.PlacementError, match=r"addend must be an int byte offset, got float"):
        cento.Ref("a") + 0.5  # type: ignore[operator]


def test_delta_plus_and_minus_float_refuse_neutrally() -> None:
    d = cento.Ref("a") - cento.Ref("b")
    with pytest.raises(cento.errors.PlacementError, match=r"Delta offset must be an int byte offset, got float"):
        d + 0.5  # type: ignore[operator]
    with pytest.raises(cento.errors.PlacementError, match=r"Delta offset must be an int byte offset, got float"):
        d - 0.5  # type: ignore[operator]


def test_cell_float_offset_and_bad_width_teach() -> None:
    r = cento.region("r", max_size=0x40)
    with pytest.raises(cento.errors.PlacementError, match=r"offset must be an int byte offset, got float \(did you mean // \?\)"):
        r.cell(8 / 2)  # type: ignore[arg-type]
    with pytest.raises(cento.errors.PlacementError, match=r"width must be a positive int byte count, got 0"):
        r.cell(0, width=0)


def test_bind_non_int_value_names_the_symbol_and_the_parse() -> None:
    r = cento.region("r", max_size=0x40)
    with pytest.raises(cento.errors.PlacementError, match=r"bind libc_base=1.5: symbol values are int addresses \(parse the leak with int\(s, 16\)\?\)"):
        r.bind("libc_base", 1.5)  # type: ignore[arg-type]


def test_region_max_size_typing_and_sign() -> None:
    with pytest.raises(cento.errors.PlacementError, match=r"max_size must be a non-negative int"):
        cento.region("r", max_size=-5)


def test_region_word_typing_teaches() -> None:
    with pytest.raises(cento.errors.PlacementError, match=r"word must be a positive int byte count, got 4.0"):
        cento.region("r", max_size=0x40, word=4.0)  # type: ignore[arg-type]  # the wrong-guess under test
    with pytest.raises(cento.errors.PlacementError, match=r"word must be a positive int byte count, got '8'"):
        cento.region("r", max_size=0x40, word="8")  # type: ignore[arg-type]  # the wrong-guess under test


def test_at_float_offset_teaches() -> None:
    r = cento.region("r", max_size=0x40)

    class W(cento.View):
        a: cento.u32

    with pytest.raises(cento.errors.PlacementError, match=r"offset must be an int byte offset"):
        r.at(1.5, W, "w")  # type: ignore[call-overload]


def test_at_wrong_spec_type_teaches() -> None:
    r = cento.region("r", max_size=0x40)
    with pytest.raises(cento.errors.PlacementError, match=r"takes a View/Gadget-frame class or an ArraySpec, got str"):
        r.at(0, "W", "w")  # type: ignore[call-overload]


def test_hop_address_instead_of_gadget_teaches_declaration() -> None:
    r = cento.region("r", max_size=0x100, abi="x86_64")
    c = r.chain("c", at=0, arm=False)
    with pytest.raises(cento.errors.ChainError, match=r"enter\(\) takes a Gadget class, not an address; declare"):
        c.enter(0x401234)  # type: ignore[arg-type]

    class Entry(cento.Gadget, entry=0x401000):
        rbx = cento.Restores("rbx", at=0x0, width=cento.u64)
        pc = cento.Restores(cento.Reg.PC, at=0x8, width=cento.u64)

    c.enter(Entry)  # a valid first hop: the guard must fire on hop() too, after the chain is live
    with pytest.raises(cento.errors.ChainError, match=r"hop\(\) takes a Gadget class, not an address; declare"):
        c.hop(0x401234)  # type: ignore[arg-type]


def test_gadget_float_entry_refuses_at_class_creation() -> None:
    with pytest.raises(cento.errors.ChainError, match=r"gadget G: entry must be an int address or a symbolic Ref, got float"):

        class G(cento.Gadget, entry=4096.0, stride=0x10):  # metaclass kwargs are unchecked by mypy: the guard is the only net
            pass


def test_field_plain_int_width_gets_the_vocabulary() -> None:
    with pytest.raises(TypeError, match=r"width is not width-shaped \(u8\.\.u64"):
        cento.Field(0, 4)  # type: ignore[call-overload]


def test_length_on_non_span_teaches() -> None:
    with pytest.raises(cento.errors.PlacementError, match=r"takes a Span or a placed handle"):
        cento.length(5)  # type: ignore[arg-type]


def test_chain_str_at_refuses_at_construction() -> None:
    r = cento.region("r", max_size=0x40)
    with pytest.raises(cento.errors.PlacementError, match=r"at= must be an int offset, got str"):
        r.chain("c", at="0x10", arm=False)  # type: ignore[arg-type]


def test_negative_raw_offset_renders_sanely() -> None:
    r = cento.region("r", max_size=0x40)
    with pytest.raises(cento.errors.PlacementError, match=r"r\.raw-0x4: negative offset"):
        r.cell(-4)
