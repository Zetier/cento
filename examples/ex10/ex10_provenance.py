# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""cento -- borrowed fragments, arranged deliberately, checked as a whole.

Example 10 -- provenance: catalog facts, verified bytes, drift by name

The campaign capstone: where do gadget facts LIVE, and how do you know they are still true?
Part 1: one payload program against two devices -- the MK-1 (fw v1.0, PPC32) and the MK-2
gateway (fw v2.3, MIPS32; note its catalog's delay-slot stride and inside-the-frame pc slot) --
with the facts in versioned catalog JSONs, seats written by ROLE, and last month's hand-copied
gadget caught drifting +4 (CHK-301). Part 2: the declaration checked against the SILICON --
cento's verify layer runs the gadget's real PPC32 bytes under Unicorn, a firmware rebuild that
moved one restore slot is caught by its stable divergence name, and attached verdicts make
"unverified" a warning (CHK-304). Requires the [verify] extra for part 2; it explains itself
and continues without it.

This directory's before/after pair is the same lesson in miniature: before.py is the
session-notes offset-poke script (one device, offsets in comments, "keep BOTH in sync by
hand. forever."), after.py derives the identical image from the checked-in catalog -- run
check.py and compare.

Run: python3 examples/ex10/ex10_provenance.py
Next: ex11_the_thrower
"""

from __future__ import annotations

import dataclasses
import pathlib
import sys
import typing

import cento
import cento.abi.ppc32
import cento.verify

Reg = cento.Reg

SUPPORT = pathlib.Path(__file__).parent  # catalogs, profiles, and firmware fixtures live next to this script

# The per-device facts -- re-derived from each firmware image -- live in versioned JSON under
# this directory: one schema-2 catalog + one profile per device, shaped exactly like
# tests/fixtures/. Same gadget NAMES on both sides; nothing else survives the ISA boundary.
# The op words live in out-of-band arg blocks (unshown); both calls here are unprivileged, so
# every capability seat is zero. What stays inline is the narrative minimum per device: its
# ISA, halt vector, and staging page.


class Device(typing.NamedTuple):
    """One device's inline narrative minimum; everything else lives in its catalog/profile JSON."""

    isa: str
    halt: int
    scratch: int


DEVICES: dict[str, Device] = {
    "mk1-v1.0": Device(isa="PPC32", halt=0x40003000, scratch=0x40200000),
    "mk2-v2.3": Device(isa="MIPS32", halt=0x00400F00, scratch=0x00462000),
}


def profile_path(dev: str) -> pathlib.Path:
    """The device's checked-in profile JSON; its catalog resolves relative to the same directory."""
    return SUPPORT / f"profile_{dev.replace('.', '_').replace('-', '_')}.json"


def seat(hop: cento.Hop, role: str, value: object) -> None:
    """Seat by ROLE, not by register: the catalog's needs docs carry the role tag for THIS build.

    On the MK-1 the capability rides r3 (seated upstream as r30); on the MK-2 it rides $a0
    (seated as r16 -- $s0 is register 16). The payload program should not have to know.
    """
    reg = next(r for r, doc in hop.gadget.transfer.needs.items() if doc.startswith(role))
    assert isinstance(reg, cento.Reg)  # role-tagged needs ride registers in these catalogs
    setattr(hop, reg.name.lower(), value)


def build_chain(t: cento.Target, halt: int, scratch_va: int) -> cento.Layout:
    """The ONE declaration: map a scratch page, mint a token, park. Both calls unprivileged.

    Nothing here names an address, a frame offset, or even a register -- gadget NAMES and need
    ROLES only. The target's catalog supplies the rest, so this function survives a re-link
    and an ISA swap alike.
    """
    layout = t.layout()  # endian/fill/gadget_set all come from the profile
    layout.bind("scratch_va", scratch_va, source="fiction: the per-device staging page")
    ram = layout.region("scratch", base="scratch_va", max_size=0x400)

    run = ram.chain("relay", at=0x100)  # gadget_set defaults from the target's layout
    ent = run.enter(t.gadgets.CTX_RESTORE)
    mapper = run.hop(t.gadgets.SYSCALL_TAIL, "map_scratch")
    ent.frame.sp = mapper.frame  # ctx.sp -> first SP frame (handles coerce to their address)
    seat(mapper, "capability", 0)
    seat(mapper, "arg-block", layout.sym("scratch_va") + 0x380)  # Ref arithmetic: device-relative, ISA-neutral
    mint = run.hop(t.gadgets.SYSCALL_TAIL, "mint_token")
    seat(mint, "capability", 0)
    seat(mint, "arg-block", layout.sym("scratch_va") + 0x3C0)
    run.finish_in_kernel(pc=halt)
    return layout


def emit_and_show(dev: str, layout: cento.Layout) -> bool:
    report = layout.check()
    if report.errors:
        print(f"[{dev}] check() found errors; not emitting")  # e.g. a catalog edit broke a placement or a seat
        print(report.render())
        return False
    run = layout.chains["relay"]
    ent, mapper, mint = run.hops
    image = layout.image("scratch")

    def row(label: str, cell: cento.CellHandle, note: str) -> None:
        value = int.from_bytes(image[cell.offset : cell.offset + 4], "big")
        print(f"[{dev}] {label:<12} scratch+0x{cell.offset:03x} = 0x{value:08x}  {note}")

    row("ctx.pc (ARM)", ent.frame.pc, "<- trigger: SYSCALL_TAIL entry")
    row("ctx.sp", ent.frame.sp, "<- first SP frame")
    row("map ret pc", mapper.frame.pc, "<- hop 2: SYSCALL_TAIL entry again")
    row("mint ret pc", mint.frame.pc, "<- terminal: this device's halt vector")
    print(f"[{dev}] check: 0 errors (catalog-loaded gadgets match their own catalog)")
    return True


def scene_drift(t: cento.Target) -> None:
    # Last month's session notes said 0x40002004. This month's catalog -- re-derived from the
    # v1.0 image -- says 0x40002000. Declare the stale gadget by hand; the layout judges it.
    class SYSCALL_TAIL(cento.Gadget, entry=0x40002004, stride=0x40, reentry_safe=True):
        """0x40002004: mr r3, r30; mr r4, r31; bl demo_syscall; ... (hand-copied, STALE)"""

        r30 = cento.Restores(cento.Reg.R30, at=0x38)
        r31 = cento.Restores(cento.Reg.R31, at=0x3C)
        pc = cento.Restores(cento.Reg.PC, at=0x44, external=True)
        needs = {cento.Reg.R30: "capability word -> r3 (0 = unprivileged)", cento.Reg.R31: "arg-block pointer -> r4"}

    layout = t.layout()
    layout.bind("scratch_va", 0x40200000, source="fiction: the per-device staging page")
    ram = layout.region("scratch", base="scratch_va", max_size=0x400)
    run = ram.chain("stale", at=0x100)
    ent = run.enter(t.gadgets.CTX_RESTORE)
    h = run.hop(SYSCALL_TAIL, "mint_token")
    ent.frame.sp = h.frame
    seat(h, "capability", 0)
    seat(h, "arg-block", layout.sym("scratch_va") + 0x3C0)
    run.finish_in_kernel(pc=0x40003000)
    # crosscheck runs inside check(): any hop gadget whose NAME the catalog knows is compared
    # against the catalog geometry. entry+4 would land mid-instruction at runtime; here it is
    # a named diff, subjects and hint included, before any byte ships.
    for issue in layout.check().errors:
        print(f"ERROR {issue.code} [{', '.join(issue.subjects)}]: {issue.msg}")
        print(f"  hint: {issue.hint}")


def part_catalogs() -> bool:
    targets = {dev: cento.target(str(profile_path(dev))) for dev in DEVICES}

    print("two devices, one gadget vocabulary: the catalogs hold the facts")
    for dev, t in targets.items():
        cr, st = t.gadgets.CTX_RESTORE, t.gadgets.SYSCALL_TAIL
        isa = DEVICES[dev].isa
        print(f"[{dev}] {isa}: CTX_RESTORE @ 0x{cr.entry:08x} (stride 0x{cr.stride:x})   SYSCALL_TAIL @ 0x{st.entry:08x} (stride 0x{st.stride:x})")

    print("\nbuild_chain(target) twice: one declaration, different correct bytes -- different ISA")
    for dev, t in targets.items():
        device = DEVICES[dev]
        layout = build_chain(t, device.halt, device.scratch)
        if not emit_and_show(dev, layout):
            return False
        if dev == "mk1-v1.0":
            print(f"after  mk1 image: {layout.image('scratch').hex()}")  # the labeled emission check.py compares vs before.py

    print("\nprovenance crosscheck: a hand-declared gadget that drifted +4")
    scene_drift(targets["mk1-v1.0"])
    print("gadget facts live in versioned JSON; the chain is declared once; drift is a named error.")
    return True


CTX_RESTORE = 0x40001000  # ex02's context-restore epilogue, verified here against its bytes

# The gadget's real machine code, dumped from each firmware (big-endian PPC32); the annotated
# per-instruction listings live next to this script (fw_v10.lst, fw_v11.lst).
FW_V10 = (SUPPORT / "fw_v10.bin").read_bytes()
# v1.1 rebuilt the function: r30 now restores from 0x4C. Nobody updated the declaration.
FW_V11 = (SUPPORT / "fw_v11.bin").read_bytes()


class CtxRestore(cento.Gadget, entry=CTX_RESTORE, stride=0x58, frame_base=Reg.R31):
    """0x40001000: lwz r0, 0x0(r31); mtlr r0; lwz r1, 0x4(r31); lwz r30, 0x50(r31); lwz r31, 0x54(r31); blr

    The declaration under test: ex02's pointer-frame entry, geometry included.
    """

    pc = cento.Restores(Reg.PC, at=0x00)
    sp = cento.Restores(Reg.SP, at=0x04)
    r30 = cento.Restores(Reg.R30, at=0x50)
    r31 = cento.Restores(Reg.R31, at=0x54)
    needs = {Reg.R31: "context-block pointer (the hijack primitive)"}


@dataclasses.dataclass(frozen=True)
class FirmwareDump:
    """A dumped code window. verify_transfer takes any CodeSource -- two methods: read() hands
    back the hashed window, text_window() tells the emulator what to map where. The shipped
    ElfCodeSource reads real ELFs through an address-space map; this is the teaching stand-in."""

    base: int
    code: bytes

    def read(self, name: str, addr: int, length: int) -> bytes:
        off = addr - self.base
        return self.code[off : off + length].ljust(length, b"\x00")  # zero tail: never executed past blr

    def text_window(self, name: str) -> tuple[int, bytes]:
        return self.base, self.code


def part_verify() -> bool:
    if not cento.verify.HAVE_UNICORN:
        print("verify layer: unicorn not installed -- pip install 'cento[verify]' to run this example")
        print("(everything below needs emulation; the merge gate never does)")
        return True

    print("step 1: verify the declaration against firmware v1.0 -- the bytes agree")
    good = cento.verify.verify_transfer(CtxRestore, FirmwareDump(CTX_RESTORE, FW_V10), "mk1-fw-v1.0", abi=cento.abi.ppc32.PPC32)
    print(f"verdict: {'PASS' if good.ok else 'FAIL'} gadget={good.gadget} spec={good.spec_sha16} bytes={good.bytes_sha16}")

    print("\nstep 2: firmware v1.1 moved r30 -- the emulator catches the stale declaration by name")
    drifted = cento.verify.verify_transfer(CtxRestore, FirmwareDump(CTX_RESTORE, FW_V11), "mk1-fw-v1.1", abi=cento.abi.ppc32.PPC32)
    print(f"verdict: {'PASS' if drifted.ok else 'FAIL'}")
    for d in drifted.divergences:  # stable prefixes: pc-source:, restore:<REG>, sp-policy, needs:<REG>
        print(f"  divergence: {d}")

    print("\nstep 3: attach the verdict -- CHK-304 makes 'unverified' a named warning")
    layout = cento.Layout(endian="big")  # the MK-1 is big-endian PPC32
    layout.bind("scratch_va", 0x40200000, source="fiction: DemoRTOS scratch page")
    scratch = layout.region("scratch", base="scratch_va", max_size=0x100)
    chain = scratch.chain("probe", at=0x60)
    chain.enter(CtxRestore)  # a one-hop chain: enough for provenance to have a subject
    chain.finish_in_kernel(pc=0x40003000)
    report = layout.check()  # no verdicts attached yet: silence (provenance is opt-in)
    print(f"before attach: {len([w for w in report.warnings if w.code == 'CHK-304'])} CHK-304 warnings (opt-in: none expected)")
    layout.attach_verdicts({good.spec_sha16: good})
    report = layout.check()
    print(f"after attach: verified = {list(report.verified)}")
    layout.attach_verdicts({drifted.spec_sha16: drifted})  # a FAILED verdict does not count as verified
    for w in layout.check().warnings:
        if w.code == "CHK-304":
            print(f"WARN {w.code} [{', '.join(w.subjects)}]: {w.msg}")
    return True


def main() -> bool:
    print("---- part 1: two devices, one payload program ----")
    if not part_catalogs():
        return False
    print("\n---- part 2: the bytes, verified ----")
    return part_verify()


if __name__ == "__main__":
    if not main():
        sys.exit(1)
