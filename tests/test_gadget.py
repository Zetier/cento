# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""The machine-model cluster: gadget, machine, abi.

Gadget: a single declaration derives both the frame View and the Transfer.
Machine model: Reg aliasing, Carry, descriptors, Transfer validation, Effect.writebacks.
ABI module: re-exports and the PPC32 register spec.
"""

from __future__ import annotations

import re

import pytest

import cento.abi.ppc32 as ppc32
import cento.cells as cells
import cento.errors as errors
import cento.gadget as gadget
import cento.machine as machine
import cento.views as views

Reg = machine.Reg

# -- Gadget declaration -----------------------------------------------------------


class SyscallTail(gadget.Gadget, entry=0x40002000, stride=0xB0, reentry_safe=True):
    """0x40002000: mr r3, r30; mr r4, r31; li r5, 0; bl <sc; blr>; cmpwi r3, 0; blt -0x14;
    lwz r0, 0xb4(r1); mtlr r0; lwz r30, 0xa8(r1); lwz r31, 0xac(r1); addi r1, r1, 0xb0; blr"""

    r30 = gadget.Restores(Reg.R30, at=0xA8)
    r31 = gadget.Restores(Reg.R31, at=0xAC)
    pc = gadget.Restores(Reg.PC, at=0xB4, external=True)
    needs = {Reg.R30: "syscall object handle -> r3", Reg.R31: "desc array pointer -> r4"}


def test_gadget_declaration_derives_frame_and_transfer() -> None:
    """One Gadget declaration derives the frame View, the Transfer, and (when omitted) the stride."""
    frame = SyscallTail.frame
    assert isinstance(frame, views.ViewMeta) and frame.__name__ == "SyscallTailFrame"
    assert frame.__size__ == 0xB0
    assert frame.__fields__["r30"].offset == 0xA8 and frame.__fields__["r30"].width is views.u32
    assert frame.__fields__["pc"].external is True
    t = SyscallTail.transfer
    assert t.reentry_safe is True and t.frame_base is machine.Role.SP  # Reg.SP normalized at declaration
    assert t.needs == {Reg.R30: "syscall object handle -> r3", Reg.R31: "desc array pointer -> r4"}
    ld = t.controls[Reg.R30]
    assert isinstance(ld, machine.Load) and ld.field is SyscallTail.frame.__fields__["r30"]
    sp = t.controls[machine.Role.SP]
    assert isinstance(sp, machine.SpAdd) and sp.k == 0xB0
    assert isinstance(t.controls[machine.Role.PC], machine.Load)

    class Tiny(gadget.Gadget, entry=0x1000):
        a = gadget.Restores(Reg.R30, at=0x8)

    assert Tiny.stride == 0xC and Tiny.frame.__size__ == 0xC


def test_gadget_frame_base_and_clobbers_roles() -> None:
    """Register frame bases suppress SpAdd; Clobbers role fields derive CLOBBER controls, never frame fields."""

    class JbRestore(gadget.Gadget, entry=0x2000, frame_base=Reg.R31):
        pc = gadget.Restores(Reg.PC, at=0x0)
        sp = gadget.Restores(Reg.SP, at=0x4)

    assert machine.Role.SP not in JbRestore.transfer.controls or isinstance(JbRestore.transfer.controls[machine.Role.SP], machine.Load)
    assert JbRestore.transfer.frame_base is Reg.R31
    assert JbRestore.gname == "JbRestore" and JbRestore.entry == 0x2000

    class Killer(gadget.Gadget, entry=0x8000, stride=0x10):
        pc = gadget.Restores(Reg.PC, at=0x14, external=True)
        r30_kill = gadget.Clobbers(Reg.R30, doc="scratched by the syscall body")

    assert Killer.transfer.controls[Reg.R30] is machine.CLOBBER
    assert "r30_kill" not in Killer.frame.__fields__
    assert not hasattr(Killer, "r30_kill")


def test_gadget_declaration_refusals() -> None:
    """Declaration-time refusals: duplicate role registers and SP restores under an SP frame base."""
    with pytest.raises(errors.ChainError, match="R30"):

        class Dup(gadget.Gadget, entry=0x9000, stride=0x10):
            r30 = gadget.Restores(Reg.R30, at=0x8)
            r30_kill = gadget.Clobbers(Reg.R30)

    with pytest.raises(errors.ChainError, match="SpAdd"):

        class Bad(gadget.Gadget, entry=0xA000, stride=0x10):
            sp = gadget.Restores(Reg.SP, at=0x4)


def test_disasm_renders_the_docstring_line_keyed_on_entry() -> None:
    plain = SyscallTail.disasm(color=False)
    assert plain.startswith("0x40002000: mr r3, r30; ")  # the class's own entry + the docstring's disassembly
    colored = SyscallTail.disasm(color=True)
    assert "\x1b[" in colored and re.sub(r"\x1b\[[0-9;]*m", "", colored) == plain  # ropper palette, lossless

    class Undocumented(gadget.Gadget, entry=0x1000, stride=0x10):
        r30 = gadget.Restores(Reg.R30, at=0x0)

    with pytest.raises(errors.CatalogError, match="no disassembly"):
        Undocumented.disasm()


# -- machine model ----------------------------------------------------------------


def test_machine_model_vocabulary() -> None:
    """The closed machine vocabulary: Reg aliasing, Carry members, frozen descriptors, FedBy/SlotState."""
    sp: machine.Reg = machine.Reg.SP  # widened: enum aliasing is the point; Literal identity check trips strict-equality
    assert sp is machine.Reg.R1
    assert machine.Reg.R30.value == 30 and machine.Reg.PC.value == 36
    assert machine.Carry.Passthru.value == "passthru"
    assert {c.name for c in machine.Carry} == {"Passthru", "Unknown", "Clobbered"}
    f = views.Field(0xA8, views.u32)
    ld = machine.Load(f)
    assert ld.field is f
    assert machine.SpAdd(0xB0).k == 0xB0
    assert isinstance(machine.CLOBBER, machine.Clobber)
    with pytest.raises(Exception):  # noqa: B017 -- frozen-dataclass mutation; exact type is a dataclasses detail
        machine.SpAdd(1).k = 2  # type: ignore[misc]
    fb = machine.FedBy("effect", "task_handle", "sc24_kernel_writeback")
    st = machine.SlotState("writeback", None, fb)
    assert st.fed_by.name == "task_handle" and st.kind == "writeback"


def test_transfer_validation_and_effect_writebacks() -> None:
    """Transfer validates Load fields at construction; Effect exposes its writebacks as a namespace."""
    with pytest.raises(errors.ChainError, match="Load"):
        machine.Transfer(needs={}, controls={machine.Reg.R30: machine.Load("nope")})  # type: ignore[arg-type]
    t = machine.Transfer(needs={machine.Reg.R30: "handle"}, controls={machine.Reg.SP: machine.SpAdd(0x10)})
    assert t.frame_base is machine.Role.SP and t.reentry_safe is False  # Transfer's post_init normalizes the legacy spelling
    eff = machine.Effect("sc24_kernel_writeback", controls={object(): machine.Writeback("task_handle")})
    ref = eff.writebacks.task_handle
    assert ref == machine.WritebackRef("sc24_kernel_writeback", "task_handle")
    assert ref.name == "task_handle"
    with pytest.raises(AttributeError, match="task_handle"):
        _ = eff.writebacks.task_handel  # typo -> did-you-mean
    assert eff.window is None


# -- abi: re-exports + PPC32 spec ---------------------------------------------------


def test_abi_reexports_and_spec() -> None:
    """The abi.ppc32 module re-exports the gadget vocabulary and pins the PPC32 register spec."""
    assert ppc32.Gadget is gadget.Gadget and ppc32.Restores is gadget.Restores
    spec = ppc32.PPC32
    assert spec.name == "ppc32"
    assert Reg.R3 in spec.volatile and Reg.LR in spec.volatile and Reg.R0 in spec.volatile
    assert Reg.R30 in spec.nonvolatile and machine.Role.SP in spec.nonvolatile  # the shipped set keys the role
    assert Reg.PC not in spec.volatile and Reg.PC not in spec.nonvolatile
    assert spec.volatile.isdisjoint(spec.nonvolatile)


# -- the hash wall ------------------------------------------------------------------


def test_spec_sha16_golden_pins() -> None:
    """The hash wall: spec_sha16 anchors checked-in catalog hashes, attached verdicts, and
    Report.verified strings. These pins fail loudly if any refactor moves it."""

    class GoldenPpc(gadget.Gadget, entry=0x40001000, stride=0x20):
        """0x40001000: lwz r30, 0x18(r1); lwz r0, 0x24(r1); mtlr r0; addi r1, r1, 0x20; blr"""

        r30 = gadget.Restores(Reg.R30, at=0x18)
        pc = gadget.Restores(Reg.PC, at=0x24, external=True)
        needs = {Reg.R30: "value the next hop consumes"}

    class GoldenX64(gadget.Gadget, entry=cells.Ref("libc_base") + 0x52290, stride=0, entry_sp_mod=8):
        """libc_base+0x52290: system()"""

        needs = {"rdi": "the command string"}

    class GoldenPivot(gadget.Gadget, entry=0x7F000004B9D1, frame_base="rbp", sp_pivot=True, stride=0x10):
        """0x7f000004b9d1: leave; ret"""

        rbp = gadget.Restores("rbp", at=0x0, width=views.u64)
        pc = gadget.Restores(Reg.PC, at=0x8, width=views.u64)
        needs = {"rbp": "the frame this pivots into"}

    assert gadget.spec_dict(GoldenPpc)["frame_base"] == "SP" and gadget.spec_dict(GoldenPpc)["restores"]["pc"]["reg"] == "PC"
    assert gadget.spec_sha16(GoldenPpc) == "3e6edc4ada94b23d"
    assert gadget.spec_sha16(GoldenX64) == "5ec04f11d60f5a63"
    assert gadget.spec_sha16(GoldenPivot) == "da8fa8e99882c1e8"


def test_role_spelling_is_the_reg_spelling() -> None:
    """Role.SP/Role.PC and the legacy Reg.SP/Reg.PC spellings declare the same gadget: same
    spec (modulo class name), same hashes for identical declarations, same slot_name strings."""

    class RoleSpelled(gadget.Gadget, entry=0x40001000, stride=0x20):
        r30 = gadget.Restores(Reg.R30, at=0x18)
        pc = gadget.Restores(machine.Role.PC, at=0x24, external=True)
        needs = {Reg.R30: "value"}

    class RegSpelled(gadget.Gadget, entry=0x40001000, stride=0x20):
        r30 = gadget.Restores(Reg.R30, at=0x18)
        pc = gadget.Restores(Reg.PC, at=0x24, external=True)
        needs = {Reg.R30: "value"}

    a, b = gadget.spec_dict(RoleSpelled), gadget.spec_dict(RegSpelled)
    a.pop("name"), b.pop("name")
    assert a == b
    assert machine.slot_name(machine.Role.SP) == "SP" and machine.slot_name(machine.Role.PC) == "PC"
    assert machine.norm_slot(Reg.SP) is machine.Role.SP and machine.norm_slot(Reg.R1) is machine.Role.SP  # PPC: r1 IS the stack pointer
    assert machine.norm_slot("rdi") == "rdi" and machine.norm_slot(Reg.R30) is Reg.R30


def test_str_entry_parses_the_catalog_spelling_at_class_creation() -> None:
    """entry="sym+0xK" becomes a Ref immediately (the catalog spelling is legal inline); a typo refuses at the class statement, not at spec_sha16 time."""

    class ViaStr(gadget.Gadget, entry="libc_base+0x1234", stride=0x8):
        pc = gadget.Restores(Reg.PC, at=0x0)

    assert ViaStr.entry == cells.Ref("libc_base", 0x1234)
    assert gadget.spec_sha16(ViaStr)  # the previously-crashing path: canonicalization now sees a Ref
    with pytest.raises(errors.CatalogError, match="cannot parse symbolic entry"):

        class Typo(gadget.Gadget, entry="libc+0x12+0x34", stride=0x8):
            pc = gadget.Restores(Reg.PC, at=0x0)
