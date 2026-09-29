# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""The ABI conformance floor: every shipped ABI clears these, and a port adds one AbiCase
(docs/porting-an-abi.md step 4). Deeper arch-specific pins live in the per-arch test files."""

from __future__ import annotations

import typing

import pytest

import cento
import cento.cells
import cento.gadget as gadget
import cento.machine as machine
import cento.regions as regions
import cento.views as views
from cento.abi.aarch64 import AARCH64
from cento.abi.arm32 import ARM32
from cento.abi.ppc32 import PPC32
from cento.abi.x86_64 import X86_64

Reg = machine.Reg
Role = machine.Role


class AbiCase(typing.NamedTuple):
    """One architecture's conformance fixtures: ABI facts plus a minimal entry+run gadget pair."""

    name: str
    abi: machine.AbiSpec
    endian: cento.cells.Endian
    width: type[views.Width]
    entry_gadget: gadget.GadgetMeta  # enter() target: SP-frame with a PC restore
    run_gadget: gadget.GadgetMeta  # SP-run hop: one seatable slot + a PC restore
    seat_attr: str  # the hop.<attr> spelling of the seatable slot
    seat_slot: machine.Slot  # the slot the seat lands on (Reg.R30, "rdi", "x19", "r4")
    seat_slot_name: str  # its expected slot_name spelling


class PpcEntry(cento.Gadget, entry=0x40001000, stride=0x10):
    pc = cento.Restores(Reg.PC, at=0x0)


class PpcRun(cento.Gadget, entry=0x40002000, stride=0x20):
    r30 = cento.Restores(Reg.R30, at=0x18)
    pc = cento.Restores(Reg.PC, at=0x24, external=True)


class X64Entry(cento.Gadget, entry=0x7F0000001000, stride=0x8):
    pc = cento.Restores(Reg.PC, at=0x0, width=views.u64)


class X64Run(cento.Gadget, entry=0x7F0000002000, stride=0x10):
    rdi = cento.Restores("rdi", at=0x0, width=views.u64)
    pc = cento.Restores(Reg.PC, at=0x8, width=views.u64)


class A64Entry(cento.Gadget, entry=0x400800, stride=0x8):
    pc = cento.Restores(Role.PC, at=0x0, width=views.u64)


class A64Run(cento.Gadget, entry=0x400900, stride=0x20):
    x19 = cento.Restores("x19", at=0x0, width=views.u64)
    pc = cento.Restores(Role.PC, at=0x18, width=views.u64)  # the x30 slot ldp'd before ret


class A32Entry(cento.Gadget, entry=0x8000, stride=0x4):
    pc = cento.Restores(Role.PC, at=0x0)


class A32Run(cento.Gadget, entry=0x8100, stride=0x8):
    """0x8100: pop {r4, pc}"""

    r4 = cento.Restores("r4", at=0x0)
    pc = cento.Restores(Role.PC, at=0x4)  # internal: pop loads PC directly; frames abut


CASES: list[AbiCase] = [
    AbiCase("ppc32", PPC32, "big", views.u32, PpcEntry, PpcRun, "r30", Reg.R30, "R30"),
    AbiCase("x86_64", X86_64, "little", views.u64, X64Entry, X64Run, "rdi", "rdi", "rdi"),
    AbiCase("aarch64", AARCH64, "little", views.u64, A64Entry, A64Run, "x19", "x19", "x19"),
    AbiCase("arm32", ARM32, "little", views.u32, A32Entry, A32Run, "r4", "r4", "r4"),
]


def _chain(case: AbiCase) -> tuple[regions.Layout, typing.Any]:
    layout = regions.Layout(endian=case.endian)
    r = layout.region("stack", max_size=0x200)
    run = r.chain("c", at=0x0, abi=case.abi, arm=False)
    return layout, run


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
def test_fold_seat_and_wire(case: AbiCase) -> None:
    """The floor: enter+hop folds, the seat sugar writes the upstream cell, _wire_pc threads
    the next entry into the image, and the seated slot's fold state names its cell."""
    layout, run = _chain(case)
    ent = run.enter(case.entry_gadget)
    hop = run.hop(case.run_gadget, "h")
    tail = run.hop(case.entry_gadget, "t")  # the seat sugar writes the UPSTREAM feeder, so the seat is set at the hop the run gadget's restore feeds
    setattr(tail, case.seat_attr, 0x1337)
    run.finished = True
    assert getattr(hop.frame, case.seat_attr).read() == 0x1337
    st = run.state_at("t")[case.seat_slot]
    assert st.kind == "seat" and st.fed_by.name == f"stack.c.h.{case.seat_attr}"  # the seat's provenance IS the run hop's frame cell
    w = case.width.size
    img = layout.image("stack", final=False)
    entry_off = ent.frame.pc.offset
    run_entry = case.run_gadget.entry
    assert isinstance(run_entry, int)  # conformance gadgets declare literal entries, never Refs
    assert img[entry_off : entry_off + w] == run_entry.to_bytes(w, case.endian)


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
def test_clobbered_carry_respects_the_split(case: AbiCase) -> None:
    """Carry.Clobbered judges the seated slot by the ABI's split: nonvolatile seats survive a
    clobbering hop; volatile seats degrade. Every case exercises the fold, not just the set."""
    layout, run = _chain(case)
    run.enter(case.entry_gadget)
    run.hop(case.run_gadget, "h1")
    hop2 = run.hop(case.entry_gadget, "h2", carry=machine.Carry.Clobbered)
    setattr(hop2, case.seat_attr, 0x1337)  # the seat rides hop1's frame (the upstream feeder); h2's carry judges it
    run.hop(case.entry_gadget, "h3")  # carry applies advancing OVER h2, so the judgment is read at the next hop's entry
    run.finished = True
    st = run.state_at("h3")[case.seat_slot]
    kept = case.seat_slot in case.abi.nonvolatile or (isinstance(case.seat_slot, (Reg, Role)) and case.seat_slot not in case.abi.volatile)
    assert st.kind == ("seat" if kept else "clobbered"), (case.name, st.kind)


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
def test_spec_hash_is_stable(case: AbiCase) -> None:
    a = gadget.spec_sha16(case.run_gadget)
    b = gadget.spec_sha16(case.run_gadget)
    assert a == b and len(a) == 16
    spec = gadget.spec_dict(case.run_gadget)
    assert spec["restores"]["pc"]["reg"] == "PC"
    assert spec["restores"][case.seat_attr]["reg"] == case.seat_slot_name  # the catalog spelling of the seat slot (slot_name: "R30" for Reg.R30, "r4" as-is)


def test_abi_package_reexports_and_registry() -> None:
    """cento.abi.PPC32 is the spelling; SPECS maps every spec by its own name."""
    import cento.abi

    assert cento.abi.PPC32 is cento.abi.ppc32.PPC32
    assert cento.abi.X86_64 is cento.abi.x86_64.X86_64
    assert cento.abi.AARCH64 is cento.abi.aarch64.AARCH64
    assert cento.abi.ARM32 is cento.abi.arm32.ARM32
    assert set(cento.abi.SPECS) == {"x86_64", "aarch64", "arm32", "ppc32"}
    assert all(cento.abi.SPECS[k].name == k for k in cento.abi.SPECS)


def test_abi_resolve_accepts_spec_and_name_and_teaches() -> None:
    import pytest

    import cento.abi
    import cento.errors

    assert cento.abi.resolve("ppc32") is cento.abi.PPC32
    assert cento.abi.resolve(cento.abi.ARM32) is cento.abi.ARM32
    with pytest.raises(cento.errors.PlacementError, match=r"unknown abi 'ppc64'.*arm32.*x86_64"):
        cento.abi.resolve("ppc64")
    with pytest.raises(cento.errors.PlacementError, match=r"abi must be an AbiSpec or one of"):
        cento.abi.resolve(3.14)  # type: ignore[arg-type]


def test_abispec_word_facts() -> None:
    """Each shipped spec carries its architecture's natural register width in bytes."""
    import cento.abi

    assert (cento.abi.X86_64.word, cento.abi.AARCH64.word, cento.abi.ARM32.word, cento.abi.PPC32.word) == (8, 8, 4, 4)
