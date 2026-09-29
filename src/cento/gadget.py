# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Unified gadget declaration: role-fields derive both the frame View and the Transfer."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import typing

import cento.cells
import cento.emit
import cento.errors
import cento.machine
import cento.views


@dataclasses.dataclass(frozen=True)
class Restores:
    """Role-field: the gadget restores machine slot `reg` (a Role, a Reg, or a string slot like "rdi") from frame offset `at`."""

    reg: cento.machine.Slot
    _: dataclasses.KW_ONLY
    at: int
    width: type[cento.views.Width] = cento.views.u32
    external: bool = False
    doc: str = ""


@dataclasses.dataclass(frozen=True)
class Clobbers:
    """Role-field: the gadget destroys machine slot `reg` (no frame field is derived)."""

    reg: cento.machine.Slot
    doc: str = ""


class GadgetMeta(type):
    gname: str
    entry: int | cento.cells.Ref
    stride: int
    frame: cento.views.ViewMeta
    transfer: cento.machine.Transfer
    needs: typing.Mapping[cento.machine.Slot, str]
    entry_sp_mod: int | None
    sp_pivot: bool

    def __new__(
        mcls,
        name: str,
        bases: tuple[type, ...],
        ns: dict[str, typing.Any],
        entry: int | cento.cells.Ref | None = None,
        stride: int | None = None,
        reentry_safe: bool = False,
        frame_base: cento.machine.Slot = cento.machine.Reg.SP,
        entry_sp_mod: int | None = None,
        sp_pivot: bool = False,
    ) -> GadgetMeta:
        roles = {attr: val for attr, val in ns.items() if isinstance(val, Restores)}
        clobs = {attr: val for attr, val in ns.items() if isinstance(val, Clobbers)}
        for attr in (*roles, *clobs):
            del ns[attr]
        cls = super().__new__(mcls, name, bases, ns)
        if entry is None:  # the abstract Gadget base itself
            return cls
        if not isinstance(entry, (int, cento.cells.Ref, str)) or isinstance(entry, bool):
            raise cento.errors.ChainError(f"gadget {name}: entry must be an int address or a symbolic Ref, got {type(entry).__name__}")
        if isinstance(entry, str):
            entry = parse_entry(entry)  # the catalog spelling ("libc_base+0x1234") is legal inline too; a typo refuses here, not at spec_sha16 time
        seen_regs: dict[cento.machine.Slot, str] = {}
        all_roles: list[tuple[str, Restores | Clobbers]] = [*roles.items(), *clobs.items()]
        for attr, role in all_roles:
            key = cento.machine.norm_slot(role.reg)
            if key in seen_regs:
                raise cento.errors.ChainError(f"gadget {name}: role-fields {seen_regs[key]!r} and {attr!r} both target {slot_name(role.reg)}")
            seen_regs[key] = attr
        fb = cento.machine.norm_slot(frame_base)
        if sp_pivot and fb is cento.machine.Role.SP:
            raise cento.errors.ChainError(f"gadget {name}: sp_pivot=True is a pointer-frame fact (SP becomes the frame); declare frame_base=<reg>")
        if entry_sp_mod is not None and entry_sp_mod < 0:
            raise cento.errors.ChainError(f"gadget {name}: entry_sp_mod must be a nonnegative residue, got {entry_sp_mod}")
        if entry_sp_mod is not None and fb is not cento.machine.Role.SP:
            raise cento.errors.ChainError(
                f"gadget {name}: entry_sp_mod on a pointer frame is unjudgeable (entry SP is data-dependent); declare it on the SP-run gadgets instead"
            )
        if fb is cento.machine.Role.SP and any(cento.machine.norm_slot(r.reg) is cento.machine.Role.SP for r in roles.values()):
            raise cento.errors.ChainError(
                f"gadget {name}: Restores(Reg.SP) on an SP-based frame; SP is advanced by SpAdd(stride) -- use frame_base=<reg> for pointer frames"
            )
        if fb is cento.machine.Role.SP and any(cento.machine.norm_slot(c.reg) is cento.machine.Role.SP for c in clobs.values()):
            raise cento.errors.ChainError(
                f"gadget {name}: Clobbers(Reg.SP) on an SP-based frame; SP is advanced by SpAdd(stride) -- use frame_base=<reg> for pointer frames"
            )
        field_ns: dict[str, typing.Any] = {attr: cento.views.Field(r.at, r.width, external=r.external, doc=r.doc) for attr, r in roles.items()}
        frame = cento.views.ViewMeta(f"{name}Frame", (cento.views.View,), field_ns, size=stride)
        controls: dict[cento.machine.Slot, cento.machine.Load | cento.machine.SpAdd | cento.machine.Clobber] = {
            cento.machine.norm_slot(r.reg): cento.machine.Load(frame.__fields__[attr]) for attr, r in roles.items()
        }
        for c in clobs.values():
            controls[cento.machine.norm_slot(c.reg)] = cento.machine.CLOBBER
        eff_stride = stride if stride is not None else frame.__size__
        if fb is cento.machine.Role.SP:
            controls[cento.machine.Role.SP] = cento.machine.SpAdd(eff_stride)
        needs: dict[cento.machine.Slot, str] = {cento.machine.norm_slot(k): v for k, v in dict(ns.get("needs", {})).items()}
        cls.gname = name
        cls.entry = entry
        cls.stride = eff_stride
        cls.frame = frame
        cls.transfer = cento.machine.Transfer(needs=needs, controls=controls, reentry_safe=reentry_safe, frame_base=fb)
        cls.needs = needs
        cls.entry_sp_mod = entry_sp_mod
        cls.sp_pivot = sp_pivot
        return cls

    def __init__(
        cls,
        name: str,
        bases: tuple[type, ...],
        ns: dict[str, typing.Any],
        entry: int | cento.cells.Ref | None = None,
        stride: int | None = None,
        reentry_safe: bool = False,
        frame_base: cento.machine.Slot = cento.machine.Reg.SP,
        entry_sp_mod: int | None = None,
        sp_pivot: bool = False,
    ) -> None:
        super().__init__(name, bases, ns)


class Gadget(metaclass=GadgetMeta):
    """Base for declarative gadgets: role-fields in the class body derive both the frame View
    and the register Transfer::

        class LoadR30(Gadget, entry=0x40001234, stride=0x20):
            '0x40001234: lwz r30, 0x18(r1); lwz r0, 0x24(r1); mtlr r0; addi r1, r1, 0x20; blr'
            r30 = Restores(Reg.R30, at=0x18)
            pc = Restores(Reg.PC, at=0x24, external=True)
            needs = {Reg.R30: "value the next hop consumes"}
    """

    @classmethod
    def disasm(cls, *, color: bool | None = None) -> str:
        """The gadget's catalog line, "0xENTRY: mnem args; ...", from its docstring's first line.

        Doc convention: a gadget docstring opens with "0xADDR: <disassembly>". The docstring's own
        address prefix is discarded and the class's `entry` is rendered in its place, so the printed
        address is always authoritative (a stale docstring address is masked, not detected). By
        default the line is colored the way ropper prints it (stdout TTY, NO_COLOR honored).
        """
        doc_lines = (cls.__doc__ or "").strip().splitlines()
        first = doc_lines[0] if doc_lines else ""  # whitespace-only docstrings are "no docstring", not an IndexError
        body = first.partition(": ")[2]
        if not body:
            raise cento.errors.CatalogError(f'{cls.gname}: no disassembly to render -- the docstring should open with "0xADDR: mnem args; ..."')
        return cento.emit.colorize_disasm(f"{entry_str(cls.entry)}: {body}", color=color)


slot_name = cento.machine.slot_name  # canonical home is cento.machine (the fold renders slots too); re-exported for spec consumers


def entry_str(entry: int | cento.cells.Ref) -> str:
    """Canonical rendering of a gadget entry: hex for absolute, sym+off for symbolic (ASLR'd libraries)."""
    if isinstance(entry, int):
        return f"{entry:#x}"
    sign, k = ("-", -entry.addend) if entry.addend < 0 else ("+", entry.addend)
    return f"{entry.sym}{sign}{k:#x}" if k else entry.sym


_ENTRY_RE = re.compile(r"(?P<sym>\w+)(?:(?P<sign>[+-])(?P<k>0[xX][0-9a-fA-F]+))?\Z")


def parse_entry(text: str) -> cento.cells.Ref:
    """The exact inverse of entry_str for symbolic entries: "sym", "sym+0xK", "sym-0xK" -> Ref."""
    m = _ENTRY_RE.fullmatch(text)
    if m is None:
        raise cento.errors.CatalogError(f"cannot parse symbolic entry {text!r} -- the catalog spelling is entry_str's: sym, sym+0xK, or sym-0xK")
    k = int(m["k"], 16) if m["k"] else 0
    return cento.cells.Ref(m["sym"], addend=-k if m["sign"] == "-" else k)


def spec_dict(gadget_cls: GadgetMeta) -> dict[str, typing.Any]:
    """Canonical spec of a gadget CLASS (inline and catalog-loaded gadgets canonicalize identically).

    Restores are recovered by walking transfer.controls Load entries and reverse-mapping each
    Field identity through frame.__fields__. SP's SpAdd control is represented by `stride`
    and is not listed in restores/clobbers.
    """
    frame_fields: dict[str, cento.views.Field] = gadget_cls.frame.__fields__
    restores: dict[str, dict[str, typing.Any]] = {}
    clobbers: list[str] = []
    for slot, ctl in gadget_cls.transfer.controls.items():
        if isinstance(ctl, cento.machine.Load):
            attr = next((a for a, f in frame_fields.items() if f is ctl.field), None)
            if attr is None:
                raise cento.errors.ChainError(f"{gadget_cls.gname}: transfer Load field is not on the gadget's own frame (malformed gadget)")
            restores[attr] = {"reg": slot_name(slot), "at": ctl.field.offset, "width": ctl.field.width.size, "external": ctl.field.external}
        elif isinstance(ctl, cento.machine.Clobber):
            clobbers.append(slot_name(slot))
    spec: dict[str, typing.Any] = {
        "name": gadget_cls.gname,
        "entry": gadget_cls.entry if isinstance(gadget_cls.entry, int) else entry_str(gadget_cls.entry),  # symbolic entries canonicalize as strings
        "stride": gadget_cls.stride,
        "frame_base": slot_name(gadget_cls.transfer.frame_base),
        "reentry_safe": gadget_cls.transfer.reentry_safe,
        "restores": {attr: restores[attr] for attr in sorted(restores)},
        "clobbers": sorted(clobbers),
        "needs": {slot_name(slot): doc for slot, doc in gadget_cls.needs.items()},
    }
    # Alignment/pivot facts join the spec only when declared, so every pre-existing gadget's
    # spec_sha16 (and every checked-in catalog hash) is unchanged by the feature's existence.
    if gadget_cls.entry_sp_mod is not None:
        spec["entry_sp_mod"] = gadget_cls.entry_sp_mod
    if gadget_cls.sp_pivot:
        spec["sp_pivot"] = True
    return spec


def spec_sha16(gadget_cls: GadgetMeta) -> str:
    """sha256 of the canonical-JSON spec_dict, first 16 hex chars."""
    return hashlib.sha256(json.dumps(spec_dict(gadget_cls), sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()[:16]


def bytes_sha16(data: bytes) -> str:
    """sha256 of raw bytes, first 16 hex chars."""
    return hashlib.sha256(data).hexdigest()[:16]
