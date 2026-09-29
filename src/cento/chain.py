# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Chain: the dataflow fold over threaded machine state.

A Chain lives in a Region. Each hop auto-places its gadget's frame (SP-based
frames at the chain cursor; pointer-based frames via alloc plus an auto-seat
of the base register), wires the previous hop's PC-source cell to its entry,
and threads a symbolic machine state forward.

Hops are never sealed at construction: effects, overlays, and seats may attach
to any hop until check time. hop() does only construction-time work (placement,
PC wiring, a provisional state advance for error locality); entry states, needs
checks, and seat judgments are recomputed from scratch by Chain.fold() on every
state_at()/narrate()/issues() call. seal() is the early-errors escape hatch --
it folds and raises on the first error-grade issue -- while issues() never
raises.
"""

from __future__ import annotations

import dataclasses
import difflib
import typing

import cento.abi
import cento.cells
import cento.checks
import cento.emit
import cento.errors
import cento.gadget
import cento.machine

if typing.TYPE_CHECKING:
    import cento.catalog
    import cento.regions

_REG_BY_ATTR: dict[str, cento.machine.Slot] = {r.name.lower(): r for r in cento.machine.Reg}
_REG_BY_ATTR["sp"] = cento.machine.Role.SP
_REG_BY_ATTR["pc"] = cento.machine.Role.PC
_REG_BY_ATTR["r1"] = cento.machine.Role.SP  # on PPC32 r1 IS the stack pointer; the fold keys the role
_CellKey = tuple[str, int]

_slot_name = cento.machine.slot_name


def _require_gadget(chain_name: str, method: str, gadget: object) -> None:
    if not isinstance(gadget, cento.gadget.GadgetMeta):
        got = f"{gadget:#x} ({type(gadget).__name__})" if isinstance(gadget, int) and not isinstance(gadget, bool) else type(gadget).__name__
        raise cento.errors.ChainError(
            f"chain {chain_name!r}: {method}() takes a Gadget class, not an address; declare"
            f" `class G(Gadget, entry=<addr>, stride=...)` with its Restores role-fields, got {got}"
        )


def _reg_hint(name: str, extra: typing.Iterable[str] = ()) -> str:
    hints = difflib.get_close_matches(name, sorted({*_REG_BY_ATTR, *extra}), n=3)
    return f"; did you mean {', '.join(repr(h) for h in hints)}?" if hints else ""


class _SlotStateMap(dict[cento.machine.Slot, cento.machine.SlotState]):
    """Fold-state map with normalized indexing: st[Reg.PC] finds the Role.PC-keyed state.

    Only __getitem__ normalizes (via __missing__); .get()/in with legacy spellings do not --
    the pinned public usage is indexing.
    """

    def __missing__(self, key: cento.machine.Slot) -> cento.machine.SlotState:
        norm = cento.machine.norm_slot(key)
        if norm is key:
            raise KeyError(key)
        return self[norm]


@dataclasses.dataclass(frozen=True)
class FoldResult:
    """One fold, whole: every hop's entry state plus the fold's side judgments, recomputed
    from scratch. Chain.fold() produces it; treat every mapping as read-only.
    """

    entry: dict[str, dict[cento.machine.Slot, cento.machine.SlotState]]  # per-hop maps are _SlotStateMap: entry[hop][Reg.PC] finds the Role.PC-keyed state
    supplies: dict[_CellKey, cento.machine.WritebackRef]  # cell -> the effect output that writes it at runtime
    clobbers: dict[_CellKey, str]  # cell -> effect that destroys it
    derived_by_hop: dict[str, list[tuple[_CellKey, str, cento.cells.Writeback]]]  # hop -> [(cell, owner path, wb)]; see _writeback_cells_by_hop
    derived_waivers: list[tuple[_CellKey, str, str]]  # (cell, derived effect, reason) from Writeback.discard
    issues: list[cento.checks.Issue]  # seat/needs judgments (CHK-201, CHK-204), never raising


class SlotView:
    """Read view of one machine slot at a hop's entry (hop.r30)."""

    def __init__(self, hop: Hop, reg: cento.machine.Slot, state: cento.machine.SlotState) -> None:
        self.hop = hop
        self.reg = reg
        self.state = state

    @property
    def fed_by(self) -> cento.machine.FedBy:
        return self.state.fed_by


class _HopWritebackNS:
    def __init__(self, hop: Hop) -> None:
        self._hop = hop

    def __getattr__(self, name: str) -> cento.machine.WritebackRef:
        fold = self._hop._chain.fold()  # fold-derived writebacks: derived outputs resolve here too
        outs: list[cento.machine.WritebackRef] = []
        for eff in self._hop.effects:
            for v in eff.controls.values():
                if isinstance(v, cento.machine.Writeback):
                    outs.append(cento.machine.WritebackRef(eff.name, v.name))
        for _key, _owner, wb in fold.derived_by_hop.get(self._hop.name, []):
            if not wb.discarded:
                outs.append(cento.machine.WritebackRef(f"{self._hop.name}_writeback", wb.name))
        for ref in outs:
            if ref.output == name:
                return ref
        hint = difflib.get_close_matches(name, [r.output for r in outs], n=1)
        extra = f"; did you mean {hint[0]!r}?" if hint else ""
        raise AttributeError(f"hop {self._hop.name!r} supplies no output {name!r}{extra}")


class Hop:
    """One gadget invocation in a chain. Seating an input (hop.r30 = value) writes the value
    into the frame cell the gadget restores that register from; reach frame cells directly
    via .frame.<field>.

    The fold justifies every consumed register or names the gap.
    """

    __slots__ = ("name", "gadget", "frame", "effects", "_chain", "_carry", "_pending_seats", "_prov_entry")

    name: str
    gadget: cento.gadget.GadgetMeta
    frame: cento.regions.ViewHandle
    effects: list[cento.machine.Effect]
    _chain: Chain
    _carry: cento.machine.Carry | None
    _pending_seats: list[tuple[cento.machine.Slot, bool]]  # (slot, immediate-write-happened); values live in cells; the fold only judges
    _prov_entry: dict[cento.machine.Slot, cento.machine.SlotState]  # provisional entry snapshot at construction (fold slot-set seed)

    def __init__(
        self,
        chain: Chain,
        name: str,
        gadget: cento.gadget.GadgetMeta,
        frame: cento.regions.ViewHandle,
        prov_entry: dict[cento.machine.Slot, cento.machine.SlotState],
        carry: cento.machine.Carry | None = None,
    ) -> None:
        for attr, val in (
            ("name", name),
            ("gadget", gadget),
            ("frame", frame),
            ("effects", []),
            ("_chain", chain),
            ("_carry", carry),
            ("_pending_seats", []),
            ("_prov_entry", prov_entry),
        ):
            object.__setattr__(self, attr, val)

    @property
    def entry_state(self) -> dict[cento.machine.Slot, cento.machine.SlotState]:
        """This hop's entry state per the latest fold (recomputed from scratch on each read)."""
        return self._chain.fold().entry[self.name]

    def add_effect(self, effect: cento.machine.Effect) -> None:
        """Attach a sequenced effect to this hop (any time until check); windowed effects also register as chain hazards."""
        self.effects.append(effect)
        if effect.window is not None:
            self._chain.hazards.append(effect)

    @property
    def writebacks(self) -> _HopWritebackNS:
        return _HopWritebackNS(self)

    def _slot_for(self, name: str) -> cento.machine.Slot | None:
        """Resolve an attribute name to a machine slot: this gadget's own transfer slots first,
        then string slots the chain abi vouches for, then the Reg-attr fallback. Order matters:
        string-slot architectures (x86-64 r8..r15, arm32 r0..r12) share spellings with the PPC32
        enum, and the gadget's own vocabulary must win. Unknown names stay AttributeError -- a
        typo'd register must refuse, not become a silent slot."""
        t = self.gadget.transfer
        if name in t.needs or name in t.controls:
            return name
        abi = self._chain.abi
        if abi is not None and (name in abi.volatile or name in abi.nonvolatile):
            return name
        return _REG_BY_ATTR.get(name)

    def _slot_hints(self) -> list[str]:
        abi = self._chain.abi
        named = {s for s in (*self.gadget.transfer.needs, *self.gadget.transfer.controls) if isinstance(s, str)}
        if abi is not None:
            named |= {s for s in (*abi.volatile, *abi.nonvolatile) if isinstance(s, str)}
        return sorted(named)

    def __getattr__(self, name: str) -> SlotView:
        slot = self._slot_for(name)
        if slot is None:
            raise AttributeError(f"hop {self.name!r}: no machine slot {name!r}{_reg_hint(name, self._slot_hints())}")
        state = self.entry_state.get(slot)
        if state is None:
            state = cento.machine.SlotState("unknown", None, cento.machine.FedBy("unknown", _slot_name(slot)))
        return SlotView(self, slot, state)

    def __setattr__(self, name: str, value: object) -> None:
        if name in Hop.__slots__:
            object.__setattr__(self, name, value)
            return
        slot = self._slot_for(name)
        if slot is None:
            raise AttributeError(f"hop {self.name!r}: no machine slot {name!r}{_reg_hint(name, self._slot_hints())}")
        self._chain._seat(self, slot, value)


class NeedFlow(typing.NamedTuple):
    """One hop need with its FedBy provenance."""

    slot: str
    fed_kind: cento.machine.FedKind
    fed_name: str
    fed_detail: str
    doc: str


class EffectFlow(typing.NamedTuple):
    """One attached effect: its outputs and window."""

    name: str
    window: str | None
    outputs: tuple[str, ...]


class WritebackFlow(typing.NamedTuple):
    """One derived writeback cell: where the runtime writes, and what."""

    region: str
    offset: int
    owner: str
    name: str
    discarded: bool


class HopFlow(typing.NamedTuple):
    """One hop of the dataflow export: identity plus needs/effects/writebacks."""

    name: str
    gadget: str
    entry: int | str
    spec_sha16: str
    needs: tuple[NeedFlow, ...]
    effects: tuple[EffectFlow, ...]
    writebacks: tuple[WritebackFlow, ...]


class PrimitiveFlow(typing.NamedTuple):
    """One primitive-supplied input: the hijack's own contribution."""

    slot: str
    value: str


@dataclasses.dataclass(frozen=True)
class ChainFlow:
    """narrate() as data: the chain's identity and its dataflow, hop by hop in chain order."""

    name: str
    region: str
    abi: str | None
    carry: str
    finished: bool
    arm: bool
    hazards: tuple[str, ...]
    primitives: tuple[PrimitiveFlow, ...]
    hops: tuple[HopFlow, ...]

    def to_json(self) -> dict[str, typing.Any]:
        """The dataflow export as a plain json-clean dict (sorted, deterministic)."""
        return {
            "name": self.name,
            "region": self.region,
            "abi": self.abi,
            "carry": self.carry,
            "finished": self.finished,
            "arm": self.arm,
            "hazards": list(self.hazards),
            "primitives": [p._asdict() for p in self.primitives],
            "hops": [
                {
                    **h._asdict(),
                    "needs": [n._asdict() for n in h.needs],
                    "effects": [{**e._asdict(), "outputs": list(e.outputs)} for e in h.effects],
                    "writebacks": [w._asdict() for w in h.writebacks],
                }
                for h in self.hops
            ],
        }


class Chain:
    """A checked gadget chain: enter() the hijack, hop() each gadget, finish()/finish_in_kernel().

    The fold recomputes every hop's register state from declared transfers; seal() proves the
    chain whole (or raises the CHK-2xx/3xx that says why); narrate() tells the dataflow story.
    """

    def __init__(
        self,
        region: cento.regions.Region,
        name: str,
        *,
        at: int,
        abi: cento.machine.AbiSpec | str | None = None,
        carry: cento.machine.Carry = cento.machine.Carry.Passthru,
        gadget_set: cento.catalog.GadgetSet | None = None,
        arm: bool = True,
    ) -> None:
        abi = cento.abi.resolve(abi) if abi is not None else None
        self.region = region
        self.layout = region.layout
        self.name = name
        if abi is not None and abi.endian is not None and abi.endian != region.layout.endian:
            raise cento.errors.ChainError(
                f"chain {name!r}: abi {abi.name!r} is {abi.endian}-endian but the layout is {region.layout.endian}-endian"
                f" -- endianness is a Layout fact; construct Layout(endian={abi.endian!r})"
            )
        if abi is not None:
            abi = dataclasses.replace(
                abi,
                volatile=frozenset(cento.machine.norm_slot(s) for s in abi.volatile),
                nonvolatile=frozenset(cento.machine.norm_slot(s) for s in abi.nonvolatile),
            )
        self.abi = abi
        self.carry = carry
        self.gadget_set = gadget_set
        self.arm = arm
        self.cursor = at
        self.hops: list[Hop] = []
        self._by_name: dict[str, Hop] = {}
        self.state: dict[cento.machine.Slot, cento.machine.SlotState] = {}  # PROVISIONAL wiring state (construction-time error locality)
        self.hazards: list[cento.machine.Effect] = []
        self.primitive_needs: dict[cento.machine.Slot, object] = {}
        self.finished = False
        self._pending_pc: cento.regions.CellHandle | None = None  # the cell whose value is the NEXT gadget's entry
        self._armed = False
        self._expectations: list[tuple[str, cento.machine.Slot, cento.machine.WritebackRef]] = []
        self._last_sp_frame_pname: str | None = None

    # -- internals ---------------------------------------------------------
    def _cell_key(self, cell: cento.regions.CellHandle) -> _CellKey:
        return (cell.region.name, cell.offset)

    def _place_frame(self, gadget: cento.gadget.GadgetMeta, hop_name: str) -> cento.regions.ViewHandle:
        frame_pname = f"{self.name}.{hop_name}"  # dotted: paths read region.chain.hop.field
        if gadget.transfer.frame_base is cento.machine.Role.SP:
            over: tuple[str, ...] = ()
            why = None
            if self._last_sp_frame_pname is not None:
                prev = next((p for p in self.region.placements if p.name == self._last_sp_frame_pname), None)
                if prev is None:
                    raise cento.errors.ChainError(f"chain {self.name!r}: previous SP frame {self._last_sp_frame_pname!r} vanished from the region")
                prev_end = max([prev.offset + prev.extent] + [end for _s, end in prev.ext_spans()])
                if (
                    self.cursor < prev_end
                ):  # only alias frames that actually interleave (external pc slots, PPC-style); MIPS-style internal-pc frames abut cleanly
                    over = (self._last_sp_frame_pname,)
                    why = "chain frame sequence: previous frame's external continuation slot lives here"
            handle = self.region.at(self.cursor, gadget.frame, frame_pname, over=over, why=why, chain=self.name)
            self._last_sp_frame_pname = frame_pname
            spadd = gadget.transfer.controls.get(cento.machine.Role.SP)
            self.cursor += spadd.k if isinstance(spadd, cento.machine.SpAdd) else gadget.stride
        else:
            handle = self.region.alloc(gadget.frame, frame_pname, chain=self.name)
            if gadget.sp_pivot:  # leave;ret-style: SP becomes this frame, so the SP run continues right past it
                self.cursor = handle.offset + gadget.stride
        return handle

    def _check_restores_vocab(self, gadget: cento.gadget.GadgetMeta, hop_name: str) -> None:
        """Refuse a typo'd string Restores slot at enter/hop time: under an abi, a string slot the
        abi does not name is a register nothing will ever ask about -- the seat would sit unread
        while the real register emits as fill. Reg-enum and Role slots are typed and exempt."""
        if self.abi is None:
            return
        known = sorted(s for s in (*self.abi.volatile, *self.abi.nonvolatile) if isinstance(s, str))
        for slot, ctl in gadget.transfer.controls.items():
            if not isinstance(ctl, cento.machine.Load) or not isinstance(slot, str) or slot in self.abi.volatile or slot in self.abi.nonvolatile:
                continue
            hint = difflib.get_close_matches(slot, known, n=1, cutoff=0.5)
            extra = f"; did you mean {hint[0]!r}?" if hint else ""
            raise cento.errors.ChainError(
                f"chain {self.name!r} hop {hop_name!r}: gadget {gadget.gname} restores {slot!r} but that is not a register in abi {self.abi.name!r}{extra}"
                "; a deliberate non-ABI slot needs an AbiSpec that names it (dataclasses.replace the shipped spec, adding it to volatile= or nonvolatile=)"
            )

    def _wire_pc(self, entry: int | cento.cells.Ref) -> None:
        if self._pending_pc is None:
            return
        self._pending_pc.write(entry)
        if self.arm and not self._armed:
            self.layout.mark(self._pending_pc, cento.emit.Deliver.ARM)
            self._armed = True
        self._pending_pc = None

    def _effect_maps(self) -> tuple[dict[_CellKey, cento.machine.WritebackRef], dict[_CellKey, str]]:
        """Fresh supplies/clobbers maps from every sequenced effect currently attached, in hop order."""
        supplies: dict[_CellKey, cento.machine.WritebackRef] = {}
        clobbers: dict[_CellKey, str] = {}
        for hop in self.hops:
            self._apply_hop_effects(hop, supplies, clobbers)
        return supplies, clobbers

    def _apply_hop_effects(self, hop: Hop, supplies: dict[_CellKey, cento.machine.WritebackRef], clobbers: dict[_CellKey, str]) -> None:
        for eff in hop.effects:
            if eff.window is not None:
                continue  # windowed effects are hazards (attached once at add_effect time), not dataflow supplies
            for target, action in eff.controls.items():
                key = self._cell_key(target)
                if isinstance(action, cento.machine.Writeback):
                    supplies[key] = cento.machine.WritebackRef(eff.name, action.name)
                else:
                    clobbers[key] = eff.name

    def _writeback_cells_by_hop(self) -> dict[str, list[tuple[_CellKey, str, cento.cells.Writeback]]]:
        """Attribution rule: a Writeback-valued cell belongs to the first hop (in hop order) whose frame
        placement extent contains it. It also belongs to a hop when a chain-owned overlay covering the
        cell is anchored to that hop's frame (over= names the frame). A cell in a frame's external
        continuation span belongs to the later frame that covers it (chain frames sequence over those
        spans)."""
        wb_cells: list[tuple[_CellKey, str, cento.cells.Writeback]] = []
        for key, entry in sorted(self.layout.cells().items()):
            if isinstance(entry.value, cento.cells.Writeback) and key[0] == self.region.name:
                wb_cells.append((key, entry.owner, entry.value))
        out: dict[str, list[tuple[_CellKey, str, cento.cells.Writeback]]] = {}
        if not wb_cells:
            return out
        claimed: set[_CellKey] = set()
        for hop in self.hops:
            frame_pname = hop.frame.path.partition(".")[2]  # strip the region prefix; pnames are dotted
            spans = [
                (rec.offset, rec.offset + rec.extent)
                for rec in self.region.placements
                if rec.chain == self.name and (rec.name == frame_pname or frame_pname in rec.over)
            ]
            got = [(key, owner, wb) for key, owner, wb in wb_cells if key not in claimed and any(s0 <= key[1] < s1 for s0, s1 in spans)]
            if got:
                claimed.update(key for key, _o, _w in got)
                out[hop.name] = got
        return out

    def _apply_derived_writebacks(
        self,
        hop: Hop,
        derived: dict[str, list[tuple[_CellKey, str, cento.cells.Writeback]]],
        supplies: dict[_CellKey, cento.machine.WritebackRef],
        clobbers: dict[_CellKey, str],
        waivers: list[tuple[_CellKey, str, str]],
    ) -> None:
        """Fold-derived effect: this hop's Writeback-valued cells act as one Effect(f"{hop}_writeback", ...)
        for fold purposes only (hop.effects is never mutated -- refolds stay idempotent). Consumed cells become
        supplies; discarded cells become clobbers plus an auto clobber-waiver carrying the discard reason."""
        for key, _owner, wb in derived.get(hop.name, []):
            eff_name = f"{hop.name}_writeback"
            if wb.discarded:
                clobbers[key] = eff_name
                waivers.append((key, eff_name, f"writeback.discard: {wb.name}"))
            else:
                supplies[key] = cento.machine.WritebackRef(eff_name, wb.name)

    def _resolve_load(
        self,
        hop_name: str,
        frame: cento.regions.ViewHandle,
        ctl: cento.machine.Load,
        gadget: cento.gadget.GadgetMeta,
        supplies: dict[_CellKey, cento.machine.WritebackRef],
        clobbers: dict[_CellKey, str],
    ) -> cento.machine.SlotState:
        fname = next((n for n, f in gadget.frame.__fields__.items() if f is ctl.field), None)
        if fname is None:
            raise cento.errors.ChainError(f"{hop_name}: Load field not found on {gadget.frame.__name__}")
        cell = getattr(frame, fname)
        key = self._cell_key(cell)
        ref = supplies.get(key)
        if ref is not None:
            return cento.machine.SlotState("writeback", cell, cento.machine.FedBy("effect", ref.output, ref.effect))
        if key in clobbers:
            return cento.machine.SlotState("clobbered", cell, cento.machine.FedBy("clobbered", clobbers[key]))
        return cento.machine.SlotState("seat", cell, cento.machine.FedBy("cell", cell.path))

    def _advance_state(
        self,
        state: dict[cento.machine.Slot, cento.machine.SlotState],
        hop: Hop,
        supplies: dict[_CellKey, cento.machine.WritebackRef],
        clobbers: dict[_CellKey, str],
    ) -> dict[cento.machine.Slot, cento.machine.SlotState]:
        """Advance the wiring state through `hop`: carry policy (incl. per-hop override), Load resolution, Clobber."""
        t = hop.gadget.transfer
        carry = hop._carry if hop._carry is not None else self.carry
        new_state = dict(state) if carry is cento.machine.Carry.Passthru else {}
        if carry is not cento.machine.Carry.Passthru:
            kind: typing.Literal["unknown", "clobbered"] = "unknown" if carry is cento.machine.Carry.Unknown else "clobbered"
            for slot, prev in state.items():
                if carry is cento.machine.Carry.Clobbered and self.abi is not None and self._abi_spares(slot):
                    new_state[slot] = prev  # ABI-aware Clobbered: nonvolatile slots pass through; slots the ABI does not name degrade (conservative)
                else:
                    new_state[slot] = cento.machine.SlotState(kind, None, cento.machine.FedBy(kind, str(slot)))
        for slot, ctl in t.controls.items():
            if isinstance(ctl, cento.machine.Load):
                new_state[slot] = self._resolve_load(hop.name, hop.frame, ctl, hop.gadget, supplies, clobbers)
            elif isinstance(ctl, cento.machine.Clobber):
                new_state[slot] = cento.machine.SlotState("clobbered", None, cento.machine.FedBy("clobbered", hop.name))
            # SpAdd handled at placement time
        return new_state

    def _abi_spares(self, slot: cento.machine.Slot) -> bool:
        """Whether Carry.Clobbered passes this slot through under the chain's ABI: declared nonvolatile
        (Reg or string), or a Reg the ABI does not list as volatile (the pre-string-slot behavior)."""
        assert self.abi is not None
        return slot in self.abi.nonvolatile or (isinstance(slot, (cento.machine.Reg, cento.machine.Role)) and slot not in self.abi.volatile)

    def _judge_seat(self, hop: Hop, reg: cento.machine.Slot, wrote: bool, st: cento.machine.SlotState | None) -> cento.checks.Issue | None:
        """Fold-time seat judgment. Never writes cells: the immediate seat already wrote the (construction-stable)
        upstream cell, so re-judging against the fold's kinds is idempotent and cannot trip CHK-008 rewrites."""
        rname = _slot_name(reg)
        sub = (f"{self.name}.{hop.name}", rname)
        if st is not None and st.kind == "writeback":
            return cento.checks.Issue(
                "CHK-204",
                sub,
                f"hop {hop.name!r}: {rname} is a target writeback ({st.fed_by.detail}:{st.fed_by.name}); seating would conflict (CHK-204)",
                "leave writeback cells UNSET; the runtime writes them",
            )
        if st is not None and st.kind == "const":
            return cento.checks.Issue(
                "CHK-201", sub, f"hop {hop.name!r}: {rname} is fed by the entry primitive; set it via enter()", "set entry inputs via enter()"
            )
        if st is None or st.cell is None or st.kind in ("unknown", "clobbered") or not wrote:
            return cento.checks.Issue(
                "CHK-201", sub, f"hop {hop.name!r}: cannot seat {rname}: no upstream slot feeds it", "seat the input or fix the upstream transfer"
            )
        return None

    def fold(self) -> FoldResult:
        """Recompute every hop's entry state from scratch: recorded seats, currently-attached
        effects, seat/needs checks (CHK-201/CHK-204 Issues, never raising), then the state
        advance -- in hop order. Returns one FoldResult value; nothing is cached on the chain."""
        entry: dict[str, dict[cento.machine.Slot, cento.machine.SlotState]] = {}
        fold_issues: list[cento.checks.Issue] = []
        supplies: dict[_CellKey, cento.machine.WritebackRef] = {}
        clobbers: dict[_CellKey, str] = {}
        derived = self._writeback_cells_by_hop()
        derived_waivers: list[tuple[_CellKey, str, str]] = []
        state: dict[cento.machine.Slot, cento.machine.SlotState] = {}
        for hop in self.hops:
            for slot, prov in hop._prov_entry.items():
                state.setdefault(slot, prov)  # adopt slots injected into the provisional stream (white-box chain inputs)
            snap = _SlotStateMap(state)  # user-reachable via fold().entry: normalized indexing at construction
            entry[hop.name] = snap
            for reg, wrote in hop._pending_seats:
                issue = self._judge_seat(hop, reg, wrote, snap.get(reg))
                if issue is not None:
                    fold_issues.append(issue)
            self._apply_hop_effects(hop, supplies, clobbers)
            self._apply_derived_writebacks(hop, derived, supplies, clobbers, derived_waivers)
            for slot, doc in hop.gadget.transfer.needs.items():
                st = snap.get(slot)
                kind = st.kind if st is not None else "unknown"
                if kind in ("unknown", "clobbered"):
                    fold_issues.append(
                        cento.checks.Issue(
                            "CHK-201",
                            (f"{self.name}.{hop.name}",),
                            f"hop {hop.name!r} needs {getattr(slot, 'name', slot)} ({doc}) but it is {kind}",
                            "seat the input or fix the upstream transfer",
                        )
                    )
            state = self._advance_state(state, hop, supplies, clobbers)
        return FoldResult(entry=entry, supplies=supplies, clobbers=clobbers, derived_by_hop=derived, derived_waivers=derived_waivers, issues=fold_issues)

    def _seat(self, hop: Hop, reg: cento.machine.Slot, value: object) -> None:
        """Record the seat and attempt immediate resolution, so the value lands in the upstream
        cell right away when one exists (error locality). A missing or ineligible upstream slot
        never raises here -- the fold judges -- but a bad value still raises from the cell write."""
        st = hop.entry_state.get(reg)
        wrote = False
        if st is not None and st.cell is not None and st.kind not in ("unknown", "clobbered", "writeback", "const"):
            st.cell.write(value)
            wrote = True
        hop._pending_seats.append((reg, wrote))

    # -- public ------------------------------------------------------------
    def enter(self, gadget: cento.gadget.GadgetMeta) -> Hop:
        """The first hop: the gadget your hijack primitive lands in. Its needs are fed at runtime by the primitive itself."""
        _require_gadget(self.name, "enter", gadget)
        if self.hops:
            raise cento.errors.ChainError(f"chain {self.name!r}: enter() must be the first hop")
        hop_name = "enter"
        self._check_restores_vocab(gadget, hop_name)
        pname = f"{self.name}.{hop_name}"  # dotted, like every hop frame
        if gadget.transfer.frame_base is cento.machine.Role.SP:
            frame = self.region.at(self.cursor, gadget.frame, pname, chain=self.name)
            self._last_sp_frame_pname = pname
            spadd = gadget.transfer.controls.get(cento.machine.Role.SP)
            self.cursor += spadd.k if isinstance(spadd, cento.machine.SpAdd) else gadget.stride
        else:
            frame = self.region.alloc(gadget.frame, pname, chain=self.name)
            if gadget.sp_pivot:  # leave;ret-style: SP becomes this frame, so the SP run continues right past it
                self.cursor = frame.offset + gadget.stride
        state: dict[cento.machine.Slot, cento.machine.SlotState] = {}
        for slot, ctl in gadget.transfer.controls.items():
            if isinstance(ctl, cento.machine.Load):
                fname = next((n for n, f in gadget.frame.__fields__.items() if f is ctl.field), None)
                if fname is None:
                    raise cento.errors.ChainError(f"{gadget.gname}: transfer Load field is not on the gadget's own frame (malformed gadget)")
                cell = getattr(frame, fname)
                state[slot] = cento.machine.SlotState("seat", cell, cento.machine.FedBy("cell", cell.path))
        for slot in gadget.transfer.needs:
            if slot == gadget.transfer.frame_base:
                self.primitive_needs[slot] = frame.addr
                # The primitive itself feeds this slot (it handed us the frame pointer); gadgets
                # that do not also RELOAD it get their fold state seeded here, not via a Load.
                state.setdefault(slot, cento.machine.SlotState("seat", None, cento.machine.FedBy("primitive", frame.path)))
            else:
                self.primitive_needs[slot] = cento.machine.UNSET
        pc_state = state.get(cento.machine.Role.PC)
        if pc_state is None or pc_state.cell is None:
            raise cento.errors.ChainError(f"enter gadget {gadget.gname} has no PC-source (Restores(Reg.PC, ...))")
        self._pending_pc = pc_state.cell
        self.state = state
        hop = Hop(self, hop_name, gadget, frame, dict(state))
        self.hops.append(hop)
        self._by_name[hop_name] = hop
        return hop

    def hop(self, gadget: cento.gadget.GadgetMeta, name: str | None = None, *, carry: cento.machine.Carry | None = None) -> Hop:
        """Append a gadget: places its frame, wires the previous continuation, and advances the provisional state (fold() recomputes the real judgment)."""
        _require_gadget(self.name, "hop", gadget)
        if not self.hops:
            raise cento.errors.ChainError(f"chain {self.name!r}: call enter() first")
        if self.finished:
            raise cento.errors.ChainError(f"chain {self.name!r} is finished")
        hop_name = name if name is not None else f"hop_{len(self.hops)}"
        self._check_restores_vocab(gadget, hop_name)
        supplies, clobbers = self._effect_maps()  # the previous hop's effects as of construction (provisional advance only)
        self.state = self._advance_state(self.state, self.hops[-1], supplies, clobbers)
        if hop_name in self._by_name:
            raise cento.errors.ChainError(f"chain {self.name!r}: hop name {hop_name!r} already used")
        self._wire_pc(gadget.entry)
        frame = self._place_frame(gadget, hop_name)
        if gadget.transfer.frame_base is not cento.machine.Role.SP:
            base_st = self.state.get(gadget.transfer.frame_base)
            if base_st is None or base_st.kind != "seat" or base_st.cell is None:
                raise cento.errors.ChainError(f"hop {hop_name!r}: frame base {gadget.transfer.frame_base} is not seatable upstream")
            base_st.cell.write(frame.addr)
        pc_ctl = gadget.transfer.controls.get(cento.machine.Role.PC)
        if isinstance(pc_ctl, cento.machine.Load):
            fname = next((n for n, f in gadget.frame.__fields__.items() if f is pc_ctl.field), None)
            if fname is None:
                raise cento.errors.ChainError(f"{gadget.gname}: PC-source Load field is not on the gadget's own frame (malformed gadget)")
            self._pending_pc = getattr(frame, fname)
        hop = Hop(self, hop_name, gadget, frame, dict(self.state), carry)
        self.hops.append(hop)
        self._by_name[hop_name] = hop
        return hop

    def finish(self, gadget: cento.gadget.GadgetMeta, **frame_fields: object) -> Hop:
        """Terminal hop: wires the dangling continuation into a final gadget (kwargs preset its frame fields)."""
        hop = self.hop(gadget, "finish")
        for k, v in frame_fields.items():
            setattr(hop.frame, k, v)
        self.finished = True
        return hop

    def finish_in_kernel(self, pc: int | cento.cells.Ref) -> None:
        """Terminal continuation: execution ends in the kernel at `pc` (never returns) -- no frame placed, no gadget."""
        if not self.hops:
            raise cento.errors.ChainError(f"chain {self.name!r}: finish_in_kernel() needs at least one hop")
        if self.finished:
            raise cento.errors.ChainError(f"chain {self.name!r} is finished")
        if self._pending_pc is None:
            raise cento.errors.ChainError(f"chain {self.name!r}: finish_in_kernel(): the last hop has no PC-source cell to write")
        self._wire_pc(pc)
        self.finished = True

    def hazard(self, effect: cento.machine.Effect) -> None:
        """Register a chain-wide windowed effect: a hazard judged against every live cell (CHK-205)."""
        if effect.window is None:
            raise cento.errors.ChainError("hazard() takes windowed effects (window='any'); sequenced effects attach to a hop via add_effect")
        self.hazards.append(effect)

    def seal(self) -> None:
        """Early-errors escape hatch: fold and raise ChainError on the first error-grade issue (issues() never raises); the Issue rides as .issue."""
        errs, _warns = self.issues()
        if errs:
            i = errs[0]
            raise cento.errors.ChainError(f"{i.code} [{', '.join(i.subjects)}]: {i.msg}  hint: {i.hint}", issue=i)

    def dangling(self) -> cento.regions.CellHandle | None:
        """The unwired continuation cell (the last hop's PC-source, a CellHandle), or None once wired.

        Both the CHK-206 warning and the final gates read this, so they cannot drift apart.
        """
        pc = self._pending_pc
        if pc is not None and (pc.region.name, pc.offset) not in self.layout.cells():
            return pc
        return None

    def issues(self) -> tuple[list[cento.checks.Issue], list[cento.checks.Issue]]:
        """Judge the chain: (errors, warnings) as CHK-2xx/3xx Issues, never raising -- layout.check() aggregates these per chain."""
        fold = self.fold()
        entry = fold.entry
        errs: list[cento.checks.Issue] = list(fold.issues)
        warns: list[cento.checks.Issue] = []
        staged = self.layout.cells()
        pc = self.dangling()
        if pc is not None:
            warns.append(  # a warning at check() (chains are built incrementally); the final emit refuses on it
                cento.checks.Issue(
                    "CHK-206",
                    (self.name, pc.path),
                    "dangling continuation: the last hop's PC-source cell was never wired (it would emit as fill)",
                    "call finish(gadget, ...) / finish_in_kernel(pc=...), or write the pending cell deliberately",
                )
            )
        for hop in self.hops:  # the alignment contract: SP at a gadget's entry, judged against the ABI's modulus
            mod = hop.gadget.entry_sp_mod
            if mod is None or hop.gadget.transfer.frame_base is not cento.machine.Role.SP:
                continue
            asub = (f"{self.name}.{hop.name}", hop.gadget.gname)
            if self.abi is None or self.abi.sp_align is None:
                warns.append(
                    cento.checks.Issue(
                        "CHK-207",
                        asub,
                        f"{hop.gadget.gname} declares entry_sp_mod={mod} but the chain has no ABI stack-alignment modulus to judge it against",
                        "pass abi=<AbiSpec with sp_align> to region.chain()",
                    )
                )
                continue
            align = self.abi.sp_align
            base_sym = self.region.base_sym
            base = self.layout.env.get(base_sym)
            base_mod: int | None = base % align if base is not None else None
            if base_mod is None:
                exp = self.layout._sym_expectations.get(base_sym)
                if exp is not None and exp.align is not None and exp.align % align == 0:
                    base_mod = 0
            if base_mod is None:
                warns.append(
                    cento.checks.Issue(
                        "CHK-207",
                        asub,
                        f"{hop.gadget.gname} wants SP % {align} == {mod} at entry, but {base_sym}'s alignment is undeclared",
                        f"bind {base_sym} or declare layout.expect_sym({base_sym!r}, align=0x{align:x})",
                    )
                )
                continue
            got_mod = (base_mod + hop.frame.offset) % align
            if got_mod != mod:
                errs.append(
                    cento.checks.Issue(
                        "CHK-207",
                        asub,
                        f"{hop.gadget.gname} uses entry_sp_mod={mod}, but this position in the chain requires entry_sp_mod={got_mod} (SP % {align} at entry)",
                        "insert a ret-align gadget before this hop (or fix the frame offsets)",
                    )
                )
        if self.abi is not None and self.abi.word is not None:  # the width contract: a frame field feeds a register the abi sizes (CHK-208)
            word = self.abi.word
            for hop in self.hops:
                for slot, ctl in hop.gadget.transfer.controls.items():
                    if not isinstance(ctl, cento.machine.Load) or ctl.field.size == word:
                        continue
                    fname = next((n for n, f in hop.gadget.frame.__fields__.items() if f is ctl.field), _slot_name(slot))
                    mech = "the register's other bytes would come from fill" if ctl.field.size < word else "the load overreads into the next slot"
                    warns.append(  # warning, not error: narrow restores (mov edi, [rsp]) are legitimate -- but the default-width qword tear starts here
                        cento.checks.Issue(
                            "CHK-208",
                            (f"{self.name}.{hop.name}", fname),
                            f"hop {hop.name!r}: {hop.gadget.gname}.{fname} restores {_slot_name(slot)} as {ctl.field.size} bytes"
                            f" but abi {self.abi.name!r} words are {word} bytes ({mech})",
                            "declare the intended width (width=cento.u32/u64) or drop abi= if the mismatch is deliberate",
                        )
                    )
        consumed_seat_keys: set[_CellKey] = set()
        for hop in self.hops:
            st_map = entry[hop.name]
            for slot in hop.gadget.transfer.needs:
                st = st_map.get(slot)
                sub = (f"{self.name}.{hop.name}",)
                slot_name = getattr(slot, "name", str(slot))
                if st is not None and st.kind == "seat" and st.cell is not None:
                    key = self._cell_key(st.cell)
                    consumed_seat_keys.add(key)
                    if key not in staged and key not in fold.supplies:
                        warns.append(
                            cento.checks.Issue(
                                "CHK-202",
                                sub + (st.cell.path,),
                                f"need {slot_name} is fed by an unset cell",
                                "seat a value (hop.<reg> = ...) or declare the supplying effect",
                            )
                        )
                        if self.finished and hop is not self.hops[0]:
                            # While building this is a warning, and the entry hop's needs are fed at
                            # runtime by the hijack primitive itself -- but a FINISHED chain shipping
                            # fill into a register a later hop consumes is an error, not a warning.
                            errs.append(warns.pop())
        for hop_name, reg, ref in self._expectations:
            st = entry[hop_name].get(reg)
            ok = st is not None and st.kind == "writeback" and st.fed_by.detail == ref.effect and st.fed_by.name == ref.output
            if not ok:
                got = f"{st.kind}:{st.fed_by.name}" if st is not None else "unknown"
                errs.append(
                    cento.checks.Issue(
                        "CHK-203",
                        (f"{self.name}.{hop_name}", _slot_name(reg)),
                        f"expected {_slot_name(reg)} fed by {ref.effect}:{ref.output}, got {got}",
                        "check the effect attachment and the overlay arithmetic",
                    )
                )
        for key, ref in sorted(fold.supplies.items(), key=lambda kv: kv[0]):
            decl = staged.get(key)
            lo, hi = key[1], key[1] + (decl.width if decl is not None else 4)
            for ckey, centry in sorted(staged.items()):  # span intersection: an off-by-two staged cell tears the slot just as surely
                if ckey[0] != key[0] or isinstance(centry.value, cento.cells.Writeback):
                    continue
                if ckey[1] < hi and lo < ckey[1] + centry.width:
                    what = "user-staged" if ckey == key else f"user-staged overlapping [{key[0]}+0x{lo:x},{key[0]}+0x{hi:x})"
                    errs.append(
                        cento.checks.Issue(
                            "CHK-204",
                            (centry.owner,),
                            f"cell is target-writeback ({ref.effect}:{ref.output}) but also {what}",
                            "leave writeback slots UNSET; the runtime writes them",
                        )
                    )
        waived = {(k, e) for (k, e, _r) in self.layout.clobber_waivers} | {(k, e) for (k, e, _r) in fold.derived_waivers}
        for hz in self.hazards:
            for target, action in hz.controls.items():
                key = self._cell_key(target)
                if not isinstance(action, cento.machine.Clobber):
                    continue
                if (key in staged or key in consumed_seat_keys) and (key, hz.name) not in waived:
                    errs.append(
                        cento.checks.Issue(
                            "CHK-205",
                            (f"{key[0]}+0x{key[1]:x}", hz.name),
                            "windowed effect may clobber a live cell",
                            "move the cell, or layout.allow_clobber(cell, effect, reason=...)",
                        )
                    )
        if self.gadget_set is not None:
            seen: set[str] = set()
            for hop in self.hops:
                if hop.gadget.gname in seen:
                    continue
                seen.add(hop.gadget.gname)
                c_errs, c_warns = self.gadget_set.crosscheck(hop.gadget)
                errs.extend(c_errs)
                warns.extend(c_warns)
        return errs, warns

    def expect(self, view: SlotView, *, from_: cento.machine.WritebackRef) -> None:
        """Pin a slot's provenance: at this hop, the viewed register must arrive writeback-fed by `from_` (CHK-203 on mismatch)."""
        self._expectations.append((view.hop.name, view.reg, from_))

    def state_at(self, name: str) -> dict[cento.machine.Slot, cento.machine.SlotState]:
        """The folded register state entering a hop: every slot's kind (seat/writeback/unknown/clobbered) and who feeds it."""
        hop = self._by_name.get(name)
        if hop is None:
            hint = difflib.get_close_matches(name, sorted(self._by_name), n=1)
            extra = f"; did you mean {hint[0]!r}?" if hint else ""
            raise KeyError(f"chain {self.name!r}: no hop named {name!r}{extra}")
        return self.fold().entry[hop.name]

    def _render_value(self, v: object) -> str:
        if isinstance(v, cento.machine.Unset):
            return "(unset)"
        if isinstance(v, cento.cells.Ref):
            return f"${v.sym}+0x{v.addend:x}" if v.addend else f"${v.sym}"
        if isinstance(v, int):
            return hex(v)
        path = getattr(v, "path", None)
        return path if isinstance(path, str) else str(v)

    def dataflow(self) -> ChainFlow:
        """narrate() as data: one fold, exported hop by hop -- needs with FedBy provenance, effects, derived writebacks, spec_sha16 join keys."""
        fold = self.fold()
        hops: list[HopFlow] = []
        for hop in self.hops:
            needs: list[NeedFlow] = []
            for slot, doc in sorted(hop.gadget.transfer.needs.items(), key=lambda kv: _slot_name(kv[0])):
                st = fold.entry[hop.name].get(slot)
                fed = st.fed_by if st is not None else cento.machine.FedBy("unknown", "")
                needs.append(NeedFlow(_slot_name(slot), fed.kind, fed.name, fed.detail, doc))
            effects = tuple(
                EffectFlow(eff.name, eff.window, tuple(sorted(v.name for v in eff.controls.values() if isinstance(v, cento.machine.Writeback))))
                for eff in hop.effects
            )
            writebacks = tuple(
                WritebackFlow(region, offset, owner, wb.name, wb.discarded) for (region, offset), owner, wb in fold.derived_by_hop.get(hop.name, [])
            )
            entry = hop.gadget.entry if isinstance(hop.gadget.entry, int) else cento.gadget.entry_str(hop.gadget.entry)
            hops.append(HopFlow(hop.name, hop.gadget.gname, entry, cento.gadget.spec_sha16(hop.gadget), tuple(needs), effects, writebacks))
        primitives = tuple(sorted(PrimitiveFlow(_slot_name(slot), self._render_value(v)) for slot, v in self.primitive_needs.items()))
        return ChainFlow(
            name=self.name,
            region=self.region.name,
            abi=self.abi.name if self.abi is not None else None,
            carry=self.carry.name,
            finished=self.finished,
            arm=self.arm,
            hazards=tuple(e.name for e in self.hazards),
            primitives=primitives,
            hops=tuple(hops),
        )

    def to_json(self) -> dict[str, typing.Any]:
        """The dataflow export as a plain json-clean dict: Chain.dataflow().to_json()."""
        return self.dataflow().to_json()

    def narrate(self) -> str:
        """The chain's dataflow story, hop by hop, in prose -- what each register carries and who wrote it."""
        fold = self.fold()
        entry = fold.entry
        lines = [f"chain {self.name} in {self.region.name} (carry={self.carry.name})"]
        for slot, v in sorted(self.primitive_needs.items(), key=lambda kv: str(kv[0])):
            lines.append(f"  primitive: {getattr(slot, 'name', str(slot))} = {self._render_value(v)}")
        for hop in self.hops:
            lines.append(f"  hop {hop.name}: {hop.gadget.gname} @ {cento.gadget.entry_str(hop.gadget.entry)}")
            for slot, doc in sorted(hop.gadget.transfer.needs.items(), key=lambda kv: str(kv[0])):
                st = entry[hop.name].get(slot)
                fed = f"{st.fed_by.kind}:{st.fed_by.name}" if st is not None else "unknown"
                lines.append(f"    needs {getattr(slot, 'name', str(slot))} <- {fed}  ({doc})")
            for eff in hop.effects:
                outs = sorted(v.name for v in eff.controls.values() if isinstance(v, cento.machine.Writeback))
                lines.append(f"    effect {eff.name}: supplies {', '.join(outs) if outs else '(clobbers only)'}")
            for _key, owner, wb in fold.derived_by_hop.get(hop.name, []):
                if not wb.discarded:
                    lines.append(f"    cell {owner} <- writeback '{wb.name}' (by effect {hop.name}_writeback)")
        if self.finished:
            lines.append("  (finished)")
        return "\n".join(lines)
