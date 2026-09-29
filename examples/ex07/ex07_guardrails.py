# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""cento -- borrowed fragments, arranged deliberately, checked as a whole.

Example 7 -- the library pushes back, and CI listens

Seven mistakes, deliberately planted on the Meridian MK-1, each caught BY NAME before any
byte ships; then the same refusals consumed by a machine. Every scene below is real captured output:
the mistake is built, check() or seal() or the constructor refuses with a code + subjects + hint,
and the fix idiom follows. The finale is the CI story: check() -> Report -> to_json() (sorted, no
timestamps), waiver rows as code-reviewable intent, and cento.gate() reading the whole judgment as one CI
verdict (True = ship; blockers print to stderr).

Run: python3 examples/ex07/ex07_guardrails.py   (transcript.txt is this run, verbatim)
Next: ex08_borrowed_structures
"""

from __future__ import annotations

import json
import sys

import cento

Reg = cento.Reg


class MsgHdr(cento.View, size=0x10):
    magic: cento.u32
    status: cento.u32


class Trailer(cento.View, size=0x8):
    crc: cento.u32
    end: cento.u32


class BootCfg(cento.View, size=0x8):
    mode: cento.u32
    limit: cento.u32


class Patch(cento.View, size=0x4):
    limit: cento.u32


class StatusLo(cento.View, size=0x2):
    half: cento.u16


class LaunchCfg(cento.View, size=0x10):
    mode: cento.u32
    probe: cento.u32
    go: cento.u32


class CtxRestore(cento.Gadget, entry=0x40001000, stride=0x58, frame_base=Reg.R31):
    """0x40001000: lwz r0, 0x0(r31); mtlr r0; lwz r1, 0x4(r31); lwz r30, 0x50(r31); lwz r31, 0x54(r31); blr"""

    pc = cento.Restores(Reg.PC, at=0x00)
    sp = cento.Restores(Reg.SP, at=0x04)
    r30 = cento.Restores(Reg.R30, at=0x50)
    r31 = cento.Restores(Reg.R31, at=0x54)
    needs = {Reg.R31: "context-block pointer (the hijack primitive)"}


class LeanTail(cento.Gadget, entry=0x40002000, stride=0x40):
    """0x40002000: mr r3, r30; bl demo_syscall; lwz r31, 0x3c(r1); lwz r0, 0x44(r1); mtlr r0; addi r1, r1, 0x40; blr

    Syscall tail that never re-establishes R30 -- fine standalone, starving mid-chain.
    """

    r31 = cento.Restores(Reg.R31, at=0x3C)
    pc = cento.Restores(Reg.PC, at=0x44, external=True)
    needs = {Reg.R30: "syscall selector -> r3"}


class FullTail(cento.Gadget, entry=0x40002080, stride=0x40, reentry_safe=True):
    """0x40002080: mr r3, r30; bl demo_syscall; lwz r30, 0x38(r1); lwz r31, 0x3c(r1); lwz r0, 0x44(r1); mtlr r0; addi r1, r1, 0x40; blr"""

    r30 = cento.Restores(Reg.R30, at=0x38)
    r31 = cento.Restores(Reg.R31, at=0x3C)
    pc = cento.Restores(Reg.PC, at=0x44, external=True)
    needs = {Reg.R30: "syscall selector -> r3"}


def banner(n: int, title: str) -> None:
    print(f"scene {n}: {title}")


def scene_1_overlap_without_intent() -> None:
    banner(1, "an overlapping placement, undeclared -> CHK-001")
    layout = cento.Layout()
    pkt = layout.region("pkt", max_size=0x40)
    pkt.at(0x0, MsgHdr, name="hdr")
    pkt.at(0xC, Trailer, name="trailer")  # drifted 4 bytes left in an edit: silently under hdr's last word
    print(layout.check().render())
    # The drift-bug class: two placements sharing bytes by ACCIDENT is how layouts rot -- one
    # moves, the other keeps writing. The fix is declared intent, reviewable in the diff:
    fixed = cento.Layout()
    pkt2 = fixed.region("pkt", max_size=0x40)
    pkt2.at(0x0, MsgHdr, name="hdr")
    pkt2.at(0xC, Trailer, name="trailer", over="hdr", why="trailer CRC deliberately overlays the header pad word")
    print(f"fixed with over=/why=: errors = {fixed.check().errors}")


def scene_2_same_cell_rewrite() -> None:
    banner(2, "a second owner rewrites a live cell -> CHK-008")
    layout = cento.Layout()
    cfg = layout.region("cfg", max_size=0x40)
    boot = cfg.at(0x0, BootCfg, name="boot")
    boot.mode = 1
    boot.limit = 0x1000
    patch = cfg.at(0x4, Patch, name="patch", over="boot", why="maintenance patch view of the boot limit")
    patch.limit = 0x2000  # last-writer-wins: silent at construction, judged at check()
    print(layout.check().render())
    layout.allow_rewrite(patch.limit, reason="maintenance override wins over the boot default")
    report = layout.check()
    print(f"waived: errors = {report.errors}; rewrite_waivers = {report.rewrite_waivers}")
    # The waiver ships in the report for reviewers. The BETTER fix is usually one writer per
    # byte: move the patch to its own cell and let the boot view keep sole ownership.


def scene_3_starved_hop_input() -> None:
    banner(3, "a starved hop input under Carry.Clobbered -> CHK-201 at seal()")
    layout = cento.Layout()
    layout.bind("scratch_va", 0x40200000, source="fiction: DemoRTOS scratch page")
    ram = layout.region("scratch", base="scratch_va", max_size=0x400)
    run = ram.chain("demo", at=0x100, carry=cento.Carry.Clobbered)  # paranoid: assume every hop trashes registers
    run.enter(CtxRestore)
    run.hop(LeanTail, "first")  # LeanTail never re-establishes R30 ...
    run.hop(LeanTail, "second")  # ... so under Clobbered the second hop's need starves
    try:
        run.seal()  # early-errors escape hatch: raises on the first error-grade issue
    except cento.ChainError as e:
        print(f"seal() raised: {e}")
    # The hint names both halves of the fix: an upstream transfer that re-establishes R30
    # (FullTail restores it from its own frame), then seat the value into that slot.
    fixed = cento.Layout()
    fixed.bind("scratch_va", 0x40200000, source="fiction: DemoRTOS scratch page")
    ram2 = fixed.region("scratch", base="scratch_va", max_size=0x400)
    run2 = ram2.chain("demo", at=0x100, carry=cento.Carry.Clobbered)
    run2.enter(CtxRestore)
    first = run2.hop(FullTail, "first")
    first.r30 = 0x7
    second = run2.hop(FullTail, "second")
    second.r30 = 0x9  # seat: lands in first's frame slot, exactly where hop 'second' reads it
    run2.seal()
    print(f"fixed: seal() passed; second R30 <- {run2.state_at('second')[Reg.R30].fed_by.name}")


def scene_4_aliases_disagree() -> None:
    banner(4, "aliased cells disagree on shared bytes -> CHK-006")
    layout = cento.Layout(endian="big")  # the MK-1 is big-endian: the overlay arithmetic below reads big
    msg = layout.region("msg", max_size=0x20)
    status = msg.at(0x0, MsgHdr, name="word")
    status.magic = 0x11223344
    lo = msg.at(0x2, StatusLo, name="lo16", over="word", why="16-bit alias of the magic word's low half")
    lo.half = 0x9999  # overlay arithmetic slip: the true low half (big-endian) is 0x3344
    print(layout.check().render())
    lo.half = 0x3344  # agree byte-for-byte -- or redeclare: drop the alias and give lo16 its own bytes
    print(f"fixed by agreeing: errors = {layout.check().errors}")


def scene_5_placement_past_cap() -> None:
    banner(5, "auto-placement past max_size -> PlacementError, eagerly")
    layout = cento.Layout()
    page = layout.region("page", max_size=0xC)  # a deliberate cap: the whole window is 12 bytes
    page.alloc(Trailer, "job_a")
    try:
        page.alloc(Trailer, "job_b")  # bump-allocates past the cap: refused AT CONSTRUCTION
    except cento.PlacementError as e:
        print(f"PlacementError: {e}")
    # Two guard classes, one posture: eager PlacementError catches malformed construction on
    # the spot; the deferred judges (check()/seal()) catch whole-layout properties. Neither truncates.


def scene_6_transport_forbidden_bytes() -> None:
    banner(6, "the transport will not carry that byte -- the gadget address itself has NULs")
    layout = cento.Layout(endian="big")  # the MK-1 is big-endian: the NUL bytes below ride in wire order
    # The MK-1 config channel is a C string: the first NUL ends the copy. Declare that fact
    # once on the region; every resolved byte is judged against it. (A fill of 0x00 would
    # refuse at declaration for the same reason -- the padding has to survive the ride too.)
    cmd = layout.region("cmd", max_size=0x10, fill=0x41, forbid=0x00)
    cmd[0x0:0x4] = 0x40001000  # CTX_LAUNCH's entry: big-endian 40 00 10 00 -- two NULs ride along
    print(layout.check().render())
    cmd[0x0:0x4] = 0x40104C90  # the fix idiom: a sibling gadget whose address is NUL-free
    print(f"fixed with a string-safe sibling gadget: errors = {layout.check().errors}")


def scene_7_plan_gates() -> None:
    banner(7, "the delivery gates -- finalize() refuses, twice")
    layout = cento.Layout()
    staging = layout.region("staging", base="staging_va", max_size=0x40)
    cfg = staging.at(0x0, LaunchCfg, name="cfg")
    cfg.mode = 3
    cfg.probe = layout.sym("probe_addr")  # late-bound: a live probe supplies it mid-delivery
    cfg.go = 1
    layout.mark(cfg.go, cento.Deliver.ARM)  # the trigger word: withheld from stage(), yielded last
    plan = layout.plan()
    plan.bind("staging_va", 0x40600000, source="fiction: staging page")
    groups = plan.stage()
    try:
        plan.finalize()  # gate 1: staged groups exist but nothing is confirmed
    except cento.EmitError as e:
        print(f"refused: {e}")
    for group in groups:
        plan.confirm(group)
    try:
        plan.finalize()  # gate 2: the late symbol is still unbound
    except cento.EmitError as e:
        print(f"refused: {e}")
    plan.bind("probe_addr", 0x40007C00, source="live-probe")
    order = [group.deliver.name for group in plan.finalize()]
    print(f"both gates cleared: finalize() yields {order} -- example 06 (ex06_delivery_plan) walks the full happy path")


def part_refusals() -> bool:
    scene_1_overlap_without_intent()
    scene_2_same_cell_rewrite()
    scene_3_starved_hop_input()
    scene_4_aliases_disagree()
    scene_5_placement_past_cap()
    scene_6_transport_forbidden_bytes()
    scene_7_plan_gates()
    print("waivers are code-reviewable intent: every escape hatch requires a reason")
    return True


class FrameHdr(cento.View, size=0x10):
    magic: cento.u32
    seq: cento.u32
    limit: cento.u32
    resv: cento.u32


class HotfixPatch(cento.View, size=0x4):
    limit: cento.u32


class CiTrailer(cento.View, size=0x8):
    crc: cento.u32
    end: cento.u32


def build_locked() -> cento.Layout:
    """The regression-locked layout: one deliberate, WAIVED rewrite rides along."""
    layout = cento.Layout()
    pkt = layout.region("pkt", max_size=0x20)
    hdr = pkt.at(0x0, FrameHdr, name="hdr")
    hdr.magic = 0x4D504B54  # 'MPKT'
    hdr.seq = 1
    hdr.limit = 0x1000  # the v1 default, kept in place for the record
    hdr.resv = 0
    trailer = pkt.at(0x10, CiTrailer, name="trailer")
    trailer.crc = cento.crc32_mpeg2(pkt[0x0:0x10])  # computed cell: recomputes if anyone moves a byte
    trailer.end = 0xFFFFFFFF
    patch = pkt.at(0x8, HotfixPatch, name="patch", over="hdr", why="hotfix view of the shipped limit word")
    patch.limit = 0x2000  # a second owner rewriting a live cell: CHK-008 unless waived
    layout.allow_rewrite(patch.limit, reason="hotfix limit supersedes the v1 default (review: MK1-217)")
    return layout


def build_broken() -> cento.Layout:
    """The teammate's edit: trailer nudged 4 bytes left, now under hdr -- undeclared."""
    layout = cento.Layout()
    pkt = layout.region("pkt", max_size=0x20)
    hdr = pkt.at(0x0, FrameHdr, name="hdr")
    hdr.magic = 0x4D504B54
    hdr.seq = 1
    hdr.limit = 0x1000
    trailer = pkt.at(0xC, CiTrailer, name="trailer")  # drifted: shares hdr's last word, no over=/why=
    trailer.crc = 0x0BADF00D
    trailer.end = 0xFFFFFFFF
    return layout


def part_ci_gate() -> bool:
    locked = build_locked()

    print("artifact (a): check() -> Report, the machine-readable half")
    report = locked.check()
    # to_json() also carries the full issue rows; a CI job archives the whole thing. We print the subset a reviewer greps --
    # deterministically (sort_keys; a Report holds no timestamps).
    j = report.to_json()
    ci_view = {
        "error_codes": sorted(i["code"] for i in j["errors"]),
        "warning_codes": sorted(i["code"] for i in j["warnings"]),
        "pending": j["pending"],
        "rewrite_waivers": j["rewrite_waivers"],
    }
    print(json.dumps(ci_view, indent=2, sort_keys=True))
    # The waiver row IS the point: the deliberate rewrite ships in the report with
    # its reason, so a reviewer approves intent instead of guessing at a diff.
    # render(verbose=True) is the same ledger for humans (quiet by default: settled business).
    print(report.render(verbose=True))

    print("artifact (b): the fail-closed path -- the final emit refuses")
    broken = build_broken()
    loose = broken.emit("image", final=False)
    print(f"emit(final=False) still built {len(loose.artifact['pkt'])} bytes -- prototyping is not gated")
    try:
        broken.emit("image")  # the shippable artifact IS gated
    except cento.EmitError as e:
        print(f"refused: {e}")

    print("artifact (c): cento.gate() -- the whole judgment as one CI verdict")
    ok = cento.gate(locked)
    locked.emit("image")  # the gate said True: the shippable artifact emits cleanly
    print(f"cento.gate(locked) -> {ok}   (green: the job ships; the image emitted cleanly after)")
    ok_broken = cento.gate(broken)  # False: the full report prints to stderr; stdout stays clean
    print(f"cento.gate(broken) -> {ok_broken}   (red: the drifted edit cannot merge)")
    print("the whole CI step is one line: sys.exit(0 if cento.gate(layout) else 1)")
    print("named codes are half the story; the report + the refusing final emit are the CI half")
    return True


def main() -> bool:
    if not part_refusals():
        return False
    print("\n---- scene 7: the machine reads the refusals ----")
    return part_ci_gate()


if __name__ == "__main__":
    if not main():
        sys.exit(1)
