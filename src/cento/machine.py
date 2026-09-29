# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Machine model: registers, carry policy, transfer descriptors, effects."""

from __future__ import annotations

import dataclasses
import difflib
import enum
import types
import typing

import cento.cells
import cento.errors
import cento.views

if typing.TYPE_CHECKING:
    import cento.regions


class Reg(enum.Enum):
    """The PPC32 register file plus the legacy role spellings (Reg.SP/Reg.PC normalize to Role.SP/Role.PC)."""

    R0 = 0
    R1 = 1
    SP = 1  # alias: on PPC32, r1 is the stack pointer
    R2 = 2
    R3 = 3
    R4 = 4
    R5 = 5
    R6 = 6
    R7 = 7
    R8 = 8
    R9 = 9
    R10 = 10
    R11 = 11
    R12 = 12
    R13 = 13
    R14 = 14
    R15 = 15
    R16 = 16
    R17 = 17
    R18 = 18
    R19 = 19
    R20 = 20
    R21 = 21
    R22 = 22
    R23 = 23
    R24 = 24
    R25 = 25
    R26 = 26
    R27 = 27
    R28 = 28
    R29 = 29
    R30 = 30
    R31 = 31
    LR = 32
    CTR = 33
    XER = 34
    CR = 35
    PC = 36


class Role(enum.Enum):
    """The two slots frame logic keys on, architecture-blind: the stack cursor and the branch target.

    Reg.SP/Reg.PC (the PPC32 spellings) normalize to these at gadget declaration; slot_name()
    renders them "SP"/"PC", so every existing spec hash, catalog, and transcript is unchanged.
    """

    SP = "SP"
    PC = "PC"


Slot = Role | Reg | str


def norm_slot(slot: Slot) -> Slot:
    """Canonicalize the role spellings: Reg.SP -> Role.SP, Reg.PC -> Role.PC, all else unchanged.

    On PPC32 r1 IS the stack pointer (Reg.SP is an alias of Reg.R1), so Reg.R1 normalizes too --
    that identity is the architecture's fact, not an accident.
    """
    if slot is Reg.SP:
        return Role.SP
    if slot is Reg.PC:
        return Role.PC
    return slot


def slot_name(slot: Slot) -> str:
    """Canonical display/spec name for a machine slot. Role slots and their legacy Reg spellings render "SP"/"PC"."""
    if isinstance(slot, Role):
        return slot.value
    if slot is Reg.SP:
        return "SP"
    if isinstance(slot, Reg):
        return slot.name
    return str(slot)


# The closed kind vocabularies of the fold. Literal, not enum: values are compared and
# constructed as plain strings throughout (including injected white-box entry states), and
# the type checker still refuses a typo'd kind at every construction site.
SlotKind = typing.Literal["seat", "writeback", "const", "unknown", "clobbered"]
FedKind = typing.Literal["cell", "effect", "primitive", "unknown", "clobbered", "const"]


class Carry(enum.Enum):
    """Default fate of machine slots a hop's Transfer does not mention: kept (Passthru),
    degraded to unknown (Unknown), or treated as destroyed (Clobbered)."""

    Passthru = "passthru"
    Unknown = "unknown"
    Clobbered = "clobbered"


@dataclasses.dataclass(frozen=True)
class AbiSpec:
    """Calling-convention register split. Carry.Clobbered with a chain abi= spares nonvolatile slots.

    Slots are Role members (SP/PC), Reg members, or plain strings ("rdi"): the Reg enum carries the PPC32 vocabulary,
    and other architectures name their registers as strings. sp_align, when set, is the ABI's
    stack-alignment modulus (16 on x86-64 SysV): gadgets declaring entry_sp_mod are judged
    against it (CHK-207), turning the classic movaps crash into a build-time refusal. endian,
    when set, is the architecture's byte order: a chain refuses a layout whose endianness
    contradicts it (the silently byte-swapped payload, refused at construction). word, when
    set, is the architecture's natural register width in bytes: abi-aware entry points default
    region word and frame-field judgment (CHK-208) to it.
    """

    name: str
    volatile: frozenset[Slot]
    nonvolatile: frozenset[Slot]
    sp_align: int | None = None
    endian: cento.cells.Endian | None = None
    word: int | None = None


@dataclasses.dataclass(frozen=True)
class Clobber:
    """Sentinel: the gadget/effect destroys this slot/cell."""


CLOBBER = Clobber()


@dataclasses.dataclass(frozen=True)
class Unset:
    """Placeholder for a primitive-supplied input not yet given."""


UNSET = Unset()


@dataclasses.dataclass(frozen=True)
class Load:
    """Control: slot is loaded from a frame field (resolved by Field identity)."""

    field: cento.views.Field


@dataclasses.dataclass(frozen=True)
class SpAdd:
    """Control: SP advances by k (the frame stride)."""

    k: int


Writeback = cento.cells.Writeback  # canonical home is cento.cells (a Writeback is also a cell value); re-exported for effect declarations


@dataclasses.dataclass(frozen=True)
class WritebackRef:
    """Handle to an effect output, for expect()/fed_by comparisons."""

    effect: str
    output: str

    @property
    def name(self) -> str:
        return self.output


class _WritebackNS:
    def __init__(self, effect: Effect) -> None:
        self._effect = effect

    def __getattr__(self, name: str) -> WritebackRef:
        outputs = [v.name for v in self._effect.controls.values() if isinstance(v, Writeback)]
        if name in outputs:
            return WritebackRef(self._effect.name, name)
        hint = difflib.get_close_matches(name, outputs, n=1)
        extra = f"; did you mean {hint[0]!r}?" if hint else ""
        raise AttributeError(f"effect {self._effect.name!r} supplies no output {name!r}{extra}")


class Effect:
    """A target-side write set. window=None: sequenced (fires during its hop, before
    the hop's restores are consumed). window=<any non-None string, conventionally "any">: a
    hazard that may fire between any hops."""

    def __init__(self, name: str, controls: dict[typing.Any, Writeback | Clobber], window: str | None = None) -> None:
        # Keys stay Any on purpose: an effect ATTACHED to a hop targets CellHandles (the fold
        # reads .region/.offset), but a detached effect may carry opaque sentinels (tested
        # behavior) -- a structural key type would outlaw that without buying safety.
        self.name = name
        self.controls: typing.Mapping[typing.Any, Writeback | Clobber] = types.MappingProxyType(dict(controls))
        self.window = window

    @property
    def writebacks(self) -> _WritebackNS:
        return _WritebackNS(self)


@dataclasses.dataclass(frozen=True, eq=False)  # eq=False: mappingproxy fields make the generated __eq__/__hash__ detonate; identity is the contract
class Transfer:
    """Declarative gadget semantics: what it consumes, what it changes. Undeclared slots
    follow the chain's Carry policy (Passthru default)."""

    needs: typing.Mapping[Slot, str]
    controls: typing.Mapping[Slot, Load | SpAdd | Clobber]
    reentry_safe: bool = False
    frame_base: Slot = Reg.SP

    def __post_init__(self) -> None:
        for slot, ctl in self.controls.items():
            if isinstance(ctl, Load) and not isinstance(ctl.field, cento.views.Field):
                raise cento.errors.ChainError(f"Transfer control for {slot}: Load() takes a cento.views.Field, got {type(ctl.field).__name__}")
        object.__setattr__(self, "frame_base", norm_slot(self.frame_base))
        object.__setattr__(self, "needs", types.MappingProxyType({norm_slot(s): d for s, d in self.needs.items()}))
        object.__setattr__(self, "controls", types.MappingProxyType({norm_slot(s): c for s, c in self.controls.items()}))


@dataclasses.dataclass(frozen=True)
class FedBy:
    """Provenance of a slot's value at a hop boundary."""

    kind: FedKind
    name: str
    detail: str = ""


@dataclasses.dataclass(frozen=True)
class SlotState:
    """A machine slot's state in the fold (const: injected entry states only, never produced)."""

    kind: SlotKind
    cell: cento.regions.CellHandle | None  # set when kind is seat/writeback (annotation-only: regions is a TYPE_CHECKING import)
    fed_by: FedBy
