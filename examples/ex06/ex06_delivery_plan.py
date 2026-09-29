# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""cento -- borrowed fragments, arranged deliberately, checked as a whole.

Example 6 -- the delivery plan: ARM gates, the ledger, and the leak that moves everything

Building bytes is half the job; landing them on the Meridian MK-1 in the right order is the other
half. Part 1: a DeliveryPlan turns a layout into ordered groups a thrower executes -- stage()
yields everything EXCEPT the trigger, finalize() refuses while anything is unconfirmed or
unresolved, and every bind/stage/confirm/arm lands in an append-only ledger. Part 2: the real
leak arrives AFTER delivery started and moves the base by a page -- the plan's stale-forensics
rows name every cell delivered at the wrong address, stage() re-yields them, and the ARM gate
holds until the re-delivery is confirmed.

Run: python3 examples/ex06/ex06_delivery_plan.py   (transcript.txt is this run, verbatim)
Next: ex07_guardrails
"""

from __future__ import annotations

import json
import sys

import cento

Reg = cento.Reg


CTX_LAUNCH = 0x40001000  # fictional epilogue: restores pc/r30/r31 from the block r31 points at
DEMO_HALT = 0x40003000  # kernel-side terminal: its service loop reads r30 as a BootCfg pointer


class CtxLaunch(cento.Gadget, entry=CTX_LAUNCH, stride=0x10, frame_base=Reg.R31):
    """0x40001000: lwz r0, 0x0(r31); mtlr r0; lwz r30, 0x4(r31); lwz r31, 0x8(r31); blr"""

    pc = cento.Restores(Reg.PC, at=0x0)
    r30 = cento.Restores(Reg.R30, at=0x4)
    r31 = cento.Restores(Reg.R31, at=0x8)
    needs = {Reg.R31: "context-block pointer (the hijack primitive)"}


class BootCfg(cento.View, size=0x10):
    mode: cento.u32
    probe: cento.u32
    limit: cento.u32


def build_launch() -> cento.Layout:
    layout = cento.Layout(endian="big")  # the MK-1 is big-endian PPC32
    page = layout.region("staging", base="staging_va", max_size=0x80)
    run = page.chain("launch", at=0x40)
    entry = run.enter(CtxLaunch)  # ctx auto-placed at staging+0; ctx.pc is the trigger word
    run.finish_in_kernel(pc=DEMO_HALT)  # wires ctx.pc = DEMO_HALT and marks it Deliver.ARM

    cfg = page.at(0x20, BootCfg, name="cfg")
    cfg.mode = 3
    cfg.probe = layout.sym("probe_addr")  # late-bound: a live probe supplies it mid-delivery
    cfg.limit = 0x1000
    # LATE: the limit gates consumers of cfg -- like a vptr on an object still being
    # staged, it must not go live until every NORMAL cell around it has landed.
    layout.mark(cfg.limit, cento.Deliver.LATE)
    entry.frame.r30 = cfg  # ctx.r30 -> &cfg: DEMO_HALT's service loop consumes it (handles coerce to their address)
    return layout


def show_gadgets(*gadgets: type[cento.Gadget]) -> None:
    print("gadgets:")
    for gadget in gadgets:
        print(f"  {gadget.disasm()}")  # the docstring's disassembly line, keyed on the gadget's own entry; ropper-colored on a TTY


def part_gates() -> bool:
    layout = build_launch()
    plan = layout.plan()
    show_gadgets(CtxLaunch)
    # a thrower is any code that writes (addr, bytes) pairs and then confirms
    plan.bind("staging_va", 0x40600000, source="fiction: staging page")

    print("stage(): every resolved non-ARM cell, in Deliver order (NORMAL < LATE)")
    groups = plan.stage()
    for group in groups:
        print(group.describe())

    # Gate 1: delivery alone is not enough -- the plan wants confirmation per group.
    try:
        plan.finalize()
    except cento.EmitError as e:
        print(f"refused (unconfirmed): {e}")
    for group in groups:
        plan.confirm(group)

    # Gate 2: the late symbol is still unbound; finalize() refuses to compute the fixups.
    try:
        plan.finalize()
    except cento.EmitError as e:
        print(f"refused (unresolved): {e}")

    print("late bind, then finalize(): fixup groups first, the ARM group LAST")
    plan.bind("probe_addr", 0x40007C00, source="live-probe")
    for group in plan.finalize():  # ordering guarantee: ARM is always the final group yielded
        print(group.describe())
        plan.confirm(group)

    print("ledger: append-only, in memory; plan.ledger.save(path) writes the JSONL a CI job archives")
    for event in plan.ledger.events:
        if event["ev"] in ("bind", "arm_intent", "finalize"):
            row = {k: v for k, v in event.items() if k != "ts"}  # ts dropped for a deterministic print
            print(f"  {json.dumps(row, sort_keys=True)}")  # arm_intent is write-ahead: logged BEFORE the group yields
    return True


class LaunchCtx(cento.View, size=0x10):
    pc: cento.u32
    arg: cento.u32


def build_spray() -> cento.Layout:
    entry_pc = 0x40001000  # where the launch context sends execution
    arg_block = 0x40200000  # fictional DemoRTOS scratch page the payload reads
    layout = cento.Layout(endian="big")  # the MK-1 is big-endian PPC32
    page = layout.region("spray", base="spray_va", max_size=0x40)
    ctx = page.at(0x0, LaunchCtx, name="ctx")
    ctx.pc = entry_pc
    ctx.arg = arg_block
    trigger = page.cell(0x10)
    trigger.write(1)  # the doorbell word: whoever reads it nonzero consumes ctx
    layout.mark(trigger, cento.Deliver.ARM)  # withheld from stage(); finalize() yields it LAST
    return layout


def part_rebind() -> bool:
    predicted = 0x40610000  # heap-spray guess: plausible, wrong by exactly one page
    actual = 0x40611000  # what the MK-1's leaked pointer actually says
    layout = build_spray()
    plan = layout.plan()

    print("step 1: stage against the PREDICTED base, confirm -- 'delivered'")
    plan.bind("spray_va", predicted, source="prediction: heap-spray geometry")
    old_addr: dict[tuple[str, int], int] = {}
    for group in plan.stage():
        print(group.describe())
        for key, (addr, _data) in zip(group.keys, group.items, strict=True):
            old_addr[key] = addr
        plan.confirm(group)
    # As far as the plan knows, the payload landed. It did -- at the wrong address.

    print("\nstep 2: the real leak lands -- the prediction was off by +0x1000")
    print(f"leak: MPKT status reply carries the spray page pointer: {actual:#010x}")
    plan.bind("spray_va", actual, source="info leak: MPKT status reply")
    # The plan does NOT silently keep believing the old deliveries: a bind that
    # moves a confirmed cell's resolution invalidates the confirmation on the spot.
    for event in plan.ledger.events:
        if event["ev"] == "stale":
            print(f"ledger: stale sym={event['sym']} cells={event['cells']} old={event['old']} new={event['new']}")
    for row in plan.stale:  # forensics: the writes at the stale base cannot be unwritten
        rname, off = row["key"]
        print(f"plan.stale: {rname}+0x{off:x} confirmed @0x{row['old_addr']:08x} -> now resolves @0x{row['new_addr']:08x}")

    print("\nstep 3: stage() re-yields the invalidated cells; finalize() still refuses")
    regroups = plan.stage()
    for group in regroups:
        print(group.describe())
        for key, (addr, _data) in zip(group.keys, group.items, strict=True):
            print(f"  re-yield {key[0]}+0x{key[1]:x}: 0x{old_addr[key]:08x} -> 0x{addr:08x}")
    try:
        plan.finalize()  # re-delivered groups exist but are unconfirmed: the ARM gate holds
    except cento.EmitError as e:
        print(f"refused (re-delivery unconfirmed): {e}")

    print("\nstep 4: confirm the re-delivery, then finalize -- ARM last, new address")
    for group in regroups:
        plan.confirm(group)
    for group in plan.finalize():
        print(group.describe())
        plan.confirm(group)
    print("the trigger never aimed at the stale base: delivered-ness is keyed on (address, bytes)")
    return True


def main() -> bool:
    print("---- part 1: stage, confirm, refuse, arm ----")
    if not part_gates():
        return False
    print("\n---- part 2: the leak moves the base mid-delivery ----")
    return part_rebind()


if __name__ == "__main__":
    if not main():
        sys.exit(1)
