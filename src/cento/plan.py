# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""DeliveryPlan: payload-delivery semantics a throwing framework executes.

cento ends here: ordered Deliver-class groups, ARM gating (write-ahead intent,
withheld until checks are clean, nothing is residual, and every group is
confirmed), computed fixup groups on late binds, and an append-only ledger. Transports live
in the thrower -- any code that writes (addr, bytes) pairs and confirms -- never in this
library.

Delivered-ness is keyed on each cell's RESOLVED (address, bytes) pair, never on
data alone: a re-bind that changes a confirmed cell's resolution INVALIDATES the
confirmation and stage()/finalize() re-yield the cell at its new resolution.

Staleness forensics run at a single choke point, consulted at every stage() and
finalize() entry, at confirm() exit (after the group is recorded, so a
confirm-after-rebind is caught), and (with symbol attribution) from plan.bind(). Each stored confirmation whose (addr, bytes) pair diverges from
the current resolution appends one forensic row to ``DeliveryPlan.stale``
(``{"sym", "key", "old_addr", "new_addr"}``) and, per batch, one ledger event
``{"ev": "stale", "sym", "cells", "old", "new"}``. On the eager path
(plan.bind), the event's sym/old/new are the bound symbol and its old/new
value, and each row's sym is that symbol. On the lazy paths -- a bind made
through layout.bind() bypassing the plan, or a confirm() of a group whose
writes landed at a since-superseded resolution -- the event carries
``sym=None, old=None, new=None``. Each row's sym is then the cell's region
base sym when the address moved or the cell no longer resolves, else None.
Divergences are deduplicated on the
(cell, old-pair, new-pair) triple: repeated stage() calls log a given
divergence once, while a further re-bind that changes the resolution again is
a new triple and is logged again. The writes already made at the stale
addresses cannot be unwritten -- these rows are the operator's record.
"""

from __future__ import annotations

import dataclasses
import json
import time
import typing

import cento.cells
import cento.emit
import cento.errors

if typing.TYPE_CHECKING:
    import cento.regions

_CellKey = tuple[str, int]
_ORDER = (cento.emit.Deliver.NORMAL, cento.emit.Deliver.LATE)  # ARM is deliberately absent: the trigger ships only from finalize()


class _Delivered(typing.NamedTuple):
    """A confirmed landing: the resolved address and bytes a thrower reported down."""

    addr: int
    data: bytes


class _Resolved(typing.NamedTuple):
    """One cell's current resolution: where it lands, what it holds, and its delivery phase."""

    addr: int
    data: bytes
    deliver: cento.emit.Deliver


class _StagedCell(typing.NamedTuple):
    """One cell of a DeliveryGroup under assembly: its CellKey plus its resolved landing."""

    key: _CellKey
    addr: int
    data: bytes


@dataclasses.dataclass(frozen=True)
class DeliveryGroup:
    """One deliverable batch: .items are resolved (addr, bytes) pairs for the thrower, .keys the matching cells, .deliver the phase."""

    gid: int
    deliver: cento.emit.Deliver
    keys: list[_CellKey]
    items: list[tuple[int, bytes]]

    def describe(self) -> str:
        head = f"group {self.gid} [{self.deliver.name}] {len(self.items)} cells"
        body = "".join(f"\n  0x{addr:08x} <- {data.hex()}" for addr, data in self.items)
        return head + body


class Ledger:
    def __init__(self, real_hw: bool) -> None:
        self.events: list[dict[str, typing.Any]] = []
        self._real_hw = real_hw

    def append(self, ev: str, **payload: typing.Any) -> None:
        self.events.append({"ev": ev, "ts": time.time(), "real_hw": self._real_hw, **payload})

    def save(self, path: str) -> None:
        with open(path, "w", encoding="ascii") as fh:
            for e in self.events:
                fh.write(json.dumps(e, sort_keys=True) + "\n")


class DeliveryPlan:
    """The ordered write campaign.

    stage() yields deliverable groups (NORMAL first, LATE after, the ARM trigger only from
    finalize()), confirm() records each group your thrower lands, and finalize() refuses
    while groups are unconfirmed or symbols unbound. Every event is an append-only ledger
    row (real_hw= is recorded there).
    """

    def __init__(self, layout: cento.regions.Layout, *, real_hw: bool = False) -> None:
        self.layout = layout
        self.real_hw = real_hw
        self.ledger = Ledger(real_hw)
        self._delivered: dict[_CellKey, _Delivered] = {}  # confirmed at this resolution
        self.stale: list[dict[str, typing.Any]] = []  # append-only: confirmations invalidated by re-binds
        self._stale_logged: set[tuple[_CellKey, _Delivered, _Delivered | None]] = set()
        self._outstanding: dict[int, DeliveryGroup] = {}
        self._gid = 0
        self._finalized = False

    # -- helpers -------------------------------------------------------------
    def _resolved_items(self) -> dict[_CellKey, _Resolved]:
        resolved = self.layout.resolution().resolved  # residual (unresolved), promised (runtime-written), and erroring cells are not deliverable
        out: dict[_CellKey, _Resolved] = {}
        for key, entry in sorted(self.layout.cells().items()):
            data = resolved.get(key)
            if data is None:
                continue
            base = self.layout.env.get(self.layout.regions[key[0]].base_sym)
            if base is None:
                continue
            out[key] = _Resolved(base + key[1], data, entry.deliver)
        return out

    def _group(self, deliver: cento.emit.Deliver, cells: list[_StagedCell]) -> DeliveryGroup:
        self._gid += 1
        cells = sorted(cells, key=lambda c: c.addr)
        g = DeliveryGroup(gid=self._gid, deliver=deliver, keys=[c.key for c in cells], items=[(c.addr, c.data) for c in cells])
        self._outstanding[g.gid] = g
        return g

    def _log_stale(
        self,
        *,
        sym: str | None = None,
        old: str | None = None,
        new: str | None = None,
        resolved: dict[_CellKey, _Resolved] | None = None,
    ) -> None:
        """Forensic choke point: log every not-yet-recorded confirmation/resolution divergence.

        Consulted at stage()/finalize() entry and confirm() exit (lazy: sym/old/new
        None) and from bind() (eager: attributed to the bound symbol). Dedupe is
        on the (cell, old-pair, new-pair) triple -- see the module docstring.
        """
        if not self._delivered:
            return
        if resolved is None:
            resolved = self._resolved_items()
        fresh: list[tuple[_CellKey, _Delivered, _Delivered | None]] = []
        for key, pair in sorted(self._delivered.items()):
            cur = resolved.get(key)
            new_pair = None if cur is None else _Delivered(cur.addr, cur.data)
            if new_pair == pair:
                continue
            triple = (key, pair, new_pair)
            if triple in self._stale_logged:
                continue
            self._stale_logged.add(triple)
            fresh.append(triple)
        if not fresh:
            return
        for key, pair, new_pair in fresh:
            row_sym = sym
            if row_sym is None and (new_pair is None or new_pair.addr != pair.addr):
                row_sym = self.layout.regions[key[0]].base_sym  # address moved: base sym derivable
            self.stale.append(
                {
                    "sym": row_sym,
                    "key": key,
                    "old_addr": pair.addr,
                    "new_addr": None if new_pair is None else new_pair.addr,
                }
            )
        self.ledger.append("stale", sym=sym, cells=len(fresh), old=old, new=new)

    # -- public ---------------------------------------------------------------
    def bind(self, sym: str, value: int, *, source: str = "manual") -> None:
        """Layout.bind through the plan: recorded in the ledger; a rebind marks confirmed cells stale for re-delivery."""
        if self._finalized:
            raise cento.errors.PlanError("plan already finalized")
        old = self.layout.env.get(sym)
        self.layout.bind(sym, value, source=source)
        self.ledger.append("bind", sym=sym, value=hex(value), source=source)
        self._log_stale(sym=sym, old=None if old is None else hex(old), new=hex(value))

    def stage(self) -> list[DeliveryGroup]:
        """Deliverable groups in phase order (never the ARM trigger). Each group's .items are (addr, bytes) pairs for your thrower.

        Gated like every delivery verb (refuses on check errors). Only cells not yet confirmed
        at their current resolution are yielded: a clean re-stage returns [], and a re-bind
        re-yields exactly the moved cells. Staged-but-unconfirmed cells are yielded again by a
        re-stage (a new group; finalize() refuses until every yielded group is confirmed).
        """
        if self._finalized:
            raise cento.errors.PlanError("plan already finalized")
        cento.emit.gate(self.layout, cento.emit.Req.STAGE, "stage()")
        resolved = self._resolved_items()
        self._log_stale(resolved=resolved)
        groups: list[DeliveryGroup] = []
        for dv in _ORDER:
            fresh = [_StagedCell(k, addr, data) for k, (addr, data, d) in resolved.items() if d is dv and self._delivered.get(k) != _Delivered(addr, data)]
            if fresh:
                g = self._group(dv, fresh)
                self.ledger.append("stage", gid=g.gid, deliver=dv.name, n=len(g.items))
                groups.append(g)
        return groups

    def confirm(self, group: DeliveryGroup) -> None:
        """Record that your thrower landed a group (a ledger row). finalize() refuses until every staged group is confirmed."""
        if self._outstanding.get(group.gid) is not group:
            raise cento.errors.PlanError(f"confirm: unknown, stale, or foreign group {group.gid}")
        del self._outstanding[group.gid]
        for key, (addr, data) in zip(group.keys, group.items, strict=True):
            self._delivered[key] = _Delivered(addr, data)  # honest: stored as delivered even if since superseded
        self.ledger.append("confirm", gid=group.gid)
        self._log_stale()  # wrong-address deliveries (confirm-after-rebind) logged at confirm time

    def finalize(self) -> list[DeliveryGroup]:
        """The gate, then the trigger: refuses on check errors, dangling chains, unconfirmed groups, or unresolved symbols.

        The unresolved refusal names pending cell symbols and unbound region base symbols alike;
        only runtime-written Writeback cells never block. Otherwise yields any still-undelivered
        NORMAL/LATE groups, then the ARM group last, by contract.
        """
        if self._finalized:
            raise cento.errors.PlanError("plan already finalized")
        report = cento.emit.gate(self.layout, cento.emit.Req.FINALIZE, "finalize()")  # the ARM trigger must never ship while a chain dangles
        resolved = self._resolved_items()
        self._log_stale(resolved=resolved)  # forensics land even if the refusal below fires
        if self._outstanding:
            gids = sorted(self._outstanding)
            raise cento.errors.EmitError(f"finalize() refused: unconfirmed groups {gids}", report=report)
        cells = self.layout.cells()
        promised = {k for k, e in cells.items() if isinstance(e.value, cento.cells.Writeback)}  # runtime-written: finalize never blocks on these
        blocked = sorted(
            set(report.pending)
            | {
                self.layout.regions[k[0]].base_sym
                for k in cells
                if k not in resolved and k not in promised and self.layout.env.get(self.layout.regions[k[0]].base_sym) is None
            }
        )
        non_arm_unresolved = [k for k in cells if k not in resolved and k not in promised and cells[k].deliver is not cento.emit.Deliver.ARM]
        if non_arm_unresolved or blocked:
            raise cento.errors.EmitError(f"finalize() refused: unresolved symbols {blocked}", report=report)
        groups: list[DeliveryGroup] = []
        for dv in _ORDER:
            fresh = [_StagedCell(k, addr, data) for k, (addr, data, d) in resolved.items() if d is dv and self._delivered.get(k) != _Delivered(addr, data)]
            if fresh:
                groups.append(self._group(dv, fresh))
        arm_cells = [_StagedCell(k, addr, data) for k, (addr, data, d) in resolved.items() if d is cento.emit.Deliver.ARM]
        arm = self._group(cento.emit.Deliver.ARM, arm_cells)
        self.ledger.append("arm_intent", gid=arm.gid)  # write-ahead: recorded BEFORE the groups are handed to the thrower
        groups.append(arm)
        self.ledger.append("finalize", n_groups=len(groups))
        self._finalized = True
        return groups
