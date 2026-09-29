# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""cento.gate: the CI verdict -- True iff preflight().shippable, blockers narrated to stderr."""

from __future__ import annotations

import pytest

import cento

Reg = cento.Reg


class Hdr(cento.View, size=8):
    magic: cento.u32
    target: cento.u32


class Entry(cento.Gadget, entry=0x40001000, stride=0x10):
    pc = cento.Restores(Reg.PC, at=0x0)


def test_gate_true_on_shippable_layout_and_silent(capsys: pytest.CaptureFixture[str]) -> None:
    layout = cento.Layout()
    pkt = layout.region("pkt", max_size=0x40)
    h = pkt.at(0, Hdr, "h")
    h.magic = 1
    h.target = 2
    assert cento.gate(layout) is True
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""  # silent on green: stdout stays clean for artifacts


def test_gate_false_on_check_error_names_the_code_on_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    layout = cento.Layout()
    pkt = layout.region("pkt", max_size=0x40)
    pkt.at(0x0, Hdr, "a")
    pkt.at(0x4, Hdr, "b")  # undeclared overlap: CHK-001
    assert cento.gate(layout) is False
    captured = capsys.readouterr()
    assert captured.out == ""  # blockers ride stderr, never stdout
    assert "CHK-001" in captured.err and "hint:" in captured.err  # the full teaching report, verbatim


def test_gate_false_on_dangling_chain_that_check_only_warns_about(capsys: pytest.CaptureFixture[str]) -> None:
    # The case ex07's old wrapper only caught at emit time: zero check errors, still not shippable.
    layout = cento.Layout()
    scratch = layout.region("scratch", max_size=0x100)
    scratch.bind("scratch_base", 0x2000)
    ch = scratch.chain("c", at=0x40)
    ch.enter(Entry)
    assert not layout.check().errors  # check() alone would look clean
    assert cento.gate(layout) is False
    err = capsys.readouterr().err
    assert "dangling chain c" in err and "scratch.c.enter.pc" in err  # the blocker named, not just a red bit


def test_gate_false_on_pending_symbols_names_them(capsys: pytest.CaptureFixture[str]) -> None:
    layout = cento.Layout()
    pkt = layout.region("pkt", max_size=0x40)
    h = pkt.at(0, Hdr, "h")
    h.magic = 1
    h.target = "win"  # unbound symbol: pending at the gate
    assert cento.gate(layout) is False
    assert "pending symbols: win" in capsys.readouterr().err  # report.render() carries the worklist
    layout.bind("win", 0x1234, source="test")
    assert cento.gate(layout) is True  # the verdict flips with the bind


def test_gate_agrees_with_the_final_emit_gate_in_both_directions() -> None:
    layout = cento.Layout()
    pkt = layout.region("pkt", max_size=0x40)
    h = pkt.at(0, Hdr, "h")
    h.magic = 1
    h.target = "win"
    assert cento.gate(layout) is False
    with pytest.raises(cento.EmitError):
        layout.emit("image")  # False agrees with the refusing emit
    layout.bind("win", 0x1234, source="test")
    assert cento.gate(layout) is True
    layout.emit("image")  # True agrees with the passing emit
