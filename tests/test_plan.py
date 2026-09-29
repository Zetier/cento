# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""The plan.py subject.

DeliveryPlan: staging groups, confirm bookkeeping, fixups on bind, ARM gating, ledger.
Re-bind invalidates stale confirmations (panel P0.1).
"""

from __future__ import annotations

import json

import pytest

import cento
import cento.errors as errors
import cento.regions as regions

# -- staging, confirm, fixups, ARM gating, ledger --------------------------------


def build() -> tuple[regions.Layout, regions.Region]:
    layout = regions.Layout()
    pkt = layout.region("pkt", max_size=0x40)
    pkt.cell(0).write(0x11111111)
    pkt.cell(4).write("late_sym")
    trigger = pkt.cell(8)
    trigger.write(0x22222222)
    layout.mark(trigger, cento.Deliver.ARM)
    tail = pkt.cell(12)
    tail.write(0x33333333)
    layout.mark(tail, cento.Deliver.LATE)
    return layout, pkt


def test_stage_confirm_finalize_contract() -> None:
    """The delivery ride: stage() yields ordered groups withholding ARM and residuals; finalize()
    refuses residuals, then yields fixups with ARM last; a finalized plan is terminal."""
    layout, pkt = build()
    plan = layout.plan()
    plan.bind("pkt_base", 0x1000, source="test")
    groups = plan.stage()
    assert [g.deliver for g in groups] == [cento.Deliver.NORMAL, cento.Deliver.LATE]
    normal = groups[0]
    assert (0x1000, (0x11111111).to_bytes(4, "little")) in normal.items
    assert all(a != 0x1008 for a, _ in normal.items)  # ARM withheld
    assert all(a != 0x1004 for a, _ in normal.items)  # residual not staged
    for g in groups:
        plan.confirm(g)
    layout, pkt = build()
    plan = layout.plan()
    plan.bind("pkt_base", 0x1000)
    for g in plan.stage():
        plan.confirm(g)
    with pytest.raises(errors.EmitError, match="late_sym"):
        plan.finalize()  # residual non-ARM cell
    plan.bind("late_sym", 0x44444444, source="live-probe")
    final = plan.finalize()
    assert final[-1].deliver is cento.Deliver.ARM
    assert final[-1].items == [(0x1008, (0x22222222).to_bytes(4, "little"))]
    fixup_addrs = [a for g in final[:-1] for a, _ in g.items]
    assert 0x1004 in fixup_addrs  # the late-bound cell
    with pytest.raises(errors.PlanError, match="finalized"):
        plan.finalize()
    with pytest.raises(errors.PlanError, match="finalized"):
        plan.stage()
    with pytest.raises(errors.PlanError, match="finalized"):
        plan.bind("x", 1)


def test_confirm_discipline() -> None:
    """Confirmation is identity-gated per group: unconfirmed groups block finalize, foreign groups refuse."""
    layout, pkt = build()
    plan = layout.plan()
    plan.bind("pkt_base", 0x1000)
    plan.bind("late_sym", 1)
    plan.stage()  # yielded, never confirmed
    with pytest.raises(errors.EmitError, match="unconfirmed"):
        plan.finalize()
    lay_a, _ = build()
    lay_b, _ = build()
    plan_a = lay_a.plan()
    plan_b = lay_b.plan()
    plan_a.bind("pkt_base", 0x1000)
    plan_b.bind("pkt_base", 0x2000)
    groups_a = plan_a.stage()
    groups_b = plan_b.stage()
    # gids collide across plans (both counters start at 0); identity must gate.
    with pytest.raises(errors.PlanError, match="foreign|stale|unknown"):
        plan_a.confirm(groups_b[0])
    plan_a.confirm(groups_a[0])  # own group still confirms cleanly


def test_rebind_makes_fixup_group_for_delivered_cell() -> None:
    layout, pkt = build()
    plan = layout.plan()
    plan.bind("pkt_base", 0x1000)
    plan.bind("late_sym", 0xAAAA0001)
    for g in plan.stage():
        plan.confirm(g)
    plan.bind("late_sym", 0xAAAA0002, source="corrected")  # delivered bytes now stale
    final = plan.finalize()
    assert any((0x1004, (0xAAAA0002).to_bytes(4, "little")) in g.items for g in final[:-1])


def test_ledger_jsonl_schema(tmp_path) -> None:  # type: ignore[no-untyped-def]
    layout, pkt = build()
    plan = layout.plan(real_hw=False)
    plan.bind("pkt_base", 0x1000, source="lifo-predict")
    plan.bind("late_sym", 5)
    for g in plan.stage():
        plan.confirm(g)
    plan.finalize()
    out = tmp_path / "ledger.jsonl"
    plan.ledger.save(str(out))
    lines = [json.loads(ln) for ln in out.read_text().splitlines()]
    kinds = [ln["ev"] for ln in lines]
    assert kinds[0] == "bind" and "confirm" in kinds and "arm_intent" in kinds
    assert kinds.index("arm_intent") < kinds.index("finalize")
    assert all("ts" in ln and ln["real_hw"] is False for ln in lines)
    bind0 = lines[0]
    assert bind0["sym"] == "pkt_base" and bind0["source"] == "lifo-predict"


def test_plan_end_to_end_without_a_thrower() -> None:
    # a thrower is any code that writes (addr, bytes) pairs and then confirms
    layout, pkt = build()
    plan = layout.plan()
    plan.bind("pkt_base", 0x1000)
    delivered: list[str] = []
    for g in plan.stage():
        delivered.append(g.deliver.name)
        plan.confirm(g)
    plan.bind("late_sym", 7)
    for g in plan.finalize():
        delivered.append(g.deliver.name)
        plan.confirm(g)
    assert delivered.count("ARM") == 1 and delivered[-1] == "ARM"


# -- re-bind invalidates stale confirmations (panel P0.1) --------------------------
#
# Delivered-ness must key on the RESOLVED (address, bytes) pair, not cell data
# alone: a bind that moves a confirmed cell's resolved address re-yields it at
# the new resolution, records a ledger "stale" event, and exposes the
# invalidation on the plan. All addresses fictional.


def build_page() -> regions.Layout:
    layout = regions.Layout()
    page = layout.region("page", base="p", max_size=0x100)
    page.cell(0).write(0x11111111)
    page.cell(4).write(0x22222222)
    return layout


def test_rebind_invalidation_contract() -> None:
    """Panel P0.1 reproducer end to end: a wrong prediction re-bound after confirm logs one stale
    event with forensic rows, and re-yields every invalidated cell at the new addresses."""
    layout = build_page()
    plan = layout.plan()
    plan.bind("p", 0x1000)
    for g in plan.stage():
        plan.confirm(g)  # 2 cells delivered @0x1000
    assert plan.stale == []  # no invalidation yet
    plan.bind("p", 0x2000)  # prediction was wrong
    stale_evs = [e for e in plan.ledger.events if e["ev"] == "stale"]
    assert len(stale_evs) == 1
    ev = stale_evs[0]
    assert ev["sym"] == "p" and ev["cells"] == 2
    assert ev["old"] == hex(0x1000) and ev["new"] == hex(0x2000)
    # plan-level forensic record: one row per invalidated cell, old->new addr
    assert len(plan.stale) == 2
    by_key = {r["key"]: r for r in plan.stale}
    assert by_key[("page", 0)]["old_addr"] == 0x1000
    assert by_key[("page", 0)]["new_addr"] == 0x2000
    assert by_key[("page", 4)]["old_addr"] == 0x1004
    assert by_key[("page", 4)]["new_addr"] == 0x2004
    groups = plan.stage()
    assert sum(len(g.items) for g in groups) == 2
    addrs = sorted(a for g in groups for a, _ in g.items)
    assert addrs == [0x2000, 0x2004]
    data = {a: d for g in groups for a, d in g.items}
    assert data[0x2000] == (0x11111111).to_bytes(4, "little")
    assert data[0x2004] == (0x22222222).to_bytes(4, "little")


def test_stale_event_accounting() -> None:
    """Stale events track divergence exactly: none without a prior confirm, one per resolution change."""
    layout = build_page()
    plan = layout.plan()
    plan.bind("p", 0x1000)
    plan.bind("p", 0x2000)  # nothing confirmed yet: a plain correction
    assert plan.stale == []
    assert not any(e["ev"] == "stale" for e in plan.ledger.events)
    # a second re-bind of the SAME sym that changes the resolution again is a NEW divergence
    # triple and must be logged too
    layout = build_page()
    plan = layout.plan()
    plan.bind("p", 0x1000)
    for g in plan.stage():
        plan.confirm(g)
    plan.bind("p", 0x2000)
    plan.bind("p", 0x3000)
    stale_evs = [e for e in plan.ledger.events if e["ev"] == "stale"]
    assert len(stale_evs) == 2
    assert stale_evs[0]["old"] == hex(0x1000) and stale_evs[0]["new"] == hex(0x2000)
    assert stale_evs[1]["old"] == hex(0x2000) and stale_evs[1]["new"] == hex(0x3000)
    # rows are append-only: the intermediate resolution stays on record,
    # and the further change adds rows at the final resolution
    new_addrs = sorted(r["new_addr"] for r in plan.stale)
    assert new_addrs == [0x2000, 0x2004, 0x3000, 0x3004]


def test_finalize_after_rebind() -> None:
    """finalize() after a re-bind: refuses while the re-yielded group sits unconfirmed, then yields
    fixups + ARM at the NEW addresses, ARM exactly once."""
    layout = build_page()
    plan = layout.plan()
    plan.bind("p", 0x1000)
    for g in plan.stage():
        plan.confirm(g)
    plan.bind("p", 0x2000)
    plan.stage()  # re-yielded, never confirmed
    with pytest.raises(errors.EmitError, match="unconfirmed"):
        plan.finalize()
    # ARM withholding means the trigger cannot have fired pre-rebind; after the re-bind,
    # finalize must yield fixups + ARM at NEW addresses, ARM exactly once
    layout = build_page()
    trigger = layout.regions["page"].cell(8)
    trigger.write(0x33333333)
    layout.mark(trigger, cento.Deliver.ARM)
    plan = layout.plan()
    plan.bind("p", 0x1000)
    for g in plan.stage():
        plan.confirm(g)
    plan.bind("p", 0x2000)  # after stage-confirm, before finalize
    final = plan.finalize()
    arm_groups = [g for g in final if g.deliver is cento.Deliver.ARM]
    assert len(arm_groups) == 1 and final[-1] is arm_groups[0]
    assert arm_groups[0].items == [(0x2008, (0x33333333).to_bytes(4, "little"))]
    fixup_items = [(a, d) for g in final[:-1] for a, d in g.items]
    assert (0x2000, (0x11111111).to_bytes(4, "little")) in fixup_items
    assert (0x2004, (0x22222222).to_bytes(4, "little")) in fixup_items
    assert all(a >= 0x2000 for a, _ in fixup_items)  # nothing at the stale base


def test_value_only_rebind_reyields_via_stage() -> None:
    # guard the pre-existing behavior: a sym used in a cell VALUE re-yields on re-bind
    layout = regions.Layout()
    page = layout.region("page", base="p", max_size=0x100)
    page.cell(0).write("val_sym")
    plan = layout.plan()
    plan.bind("p", 0x1000)
    plan.bind("val_sym", 0xAAAA0001)
    for g in plan.stage():
        plan.confirm(g)
    plan.bind("val_sym", 0xAAAA0002)
    groups = plan.stage()
    assert sum(len(g.items) for g in groups) == 1
    assert groups[0].items == [(0x1000, (0xAAAA0002).to_bytes(4, "little"))]
    # value-only invalidation is visible too (addr unchanged)
    ev = [e for e in plan.ledger.events if e["ev"] == "stale"][-1]
    assert ev["sym"] == "val_sym" and ev["cells"] == 1


def test_layout_bind_bypass_logs_stale_lazily_and_dedupes() -> None:
    """Review I-1: a bind through layout.bind() (bypassing plan.bind) still produces the forensic
    record -- lazily, at the next stage() entry -- and repeated stage() calls never duplicate it."""
    layout = build_page()
    plan = layout.plan()
    plan.bind("p", 0x1000)
    for g in plan.stage():
        plan.confirm(g)
    layout.bind("p", 0x2000)  # bypass: no plan.bind, no eager detection
    groups = plan.stage()
    assert sum(len(g.items) for g in groups) == 2  # re-yield (already correct)
    stale_evs = [e for e in plan.ledger.events if e["ev"] == "stale"]
    assert len(stale_evs) == 1
    ev = stale_evs[0]
    assert ev["sym"] is None and ev["old"] is None and ev["new"] is None  # lazy: no bound sym
    assert ev["cells"] == 2
    assert len(plan.stale) == 2
    by_key = {r["key"]: r for r in plan.stale}
    assert by_key[("page", 0)]["old_addr"] == 0x1000
    assert by_key[("page", 0)]["new_addr"] == 0x2000
    assert by_key[("page", 0)]["sym"] == "p"  # address moved: region base sym derivable
    assert by_key[("page", 4)]["old_addr"] == 0x1004
    assert by_key[("page", 4)]["new_addr"] == 0x2004
    # one divergence -> exactly one event set, no matter how many stage() calls observe it
    plan.stage()
    plan.stage()
    assert len([e for e in plan.ledger.events if e["ev"] == "stale"]) == 1
    assert len(plan.stale) == 2


def test_confirm_after_rebind_logs_stale_at_confirm_time() -> None:
    # review I-2: stage() -> thrower writes at old addrs -> bind(new) ->
    # confirm(old group). The delivered pair is stored AS DELIVERED (honest:
    # the write happened) and staleness is logged AT CONFIRM TIME.
    layout = build_page()
    plan = layout.plan()
    plan.bind("p", 0x1000)
    groups = plan.stage()
    plan.bind("p", 0x2000)  # nothing delivered yet: no eager stale event
    assert not any(e["ev"] == "stale" for e in plan.ledger.events)
    for g in groups:
        plan.confirm(g)  # honest: the writes happened at 0x1000
    stale_evs = [e for e in plan.ledger.events if e["ev"] == "stale"]
    assert len(stale_evs) == 1 and stale_evs[0]["cells"] == 2
    by_key = {r["key"]: r for r in plan.stale}
    assert by_key[("page", 0)]["old_addr"] == 0x1000
    assert by_key[("page", 0)]["new_addr"] == 0x2000
    # re-yield at the new resolution still happens, with no duplicate event
    assert sum(len(g.items) for g in plan.stage()) == 2
    assert len([e for e in plan.ledger.events if e["ev"] == "stale"]) == 1
