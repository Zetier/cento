# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""cento -- borrowed fragments, arranged deliberately, checked as a whole.

Example 5 -- computed cells: lengths, checksums, split relocations

One lesson, three escalations, all reducers: cells whose values DERIVE from spans, so they cannot
go stale. Part 1 (MK-1, MPKT): a datagram whose body length and checksum are computed, with a
late-bound session key -- emit-before-bind returns fixups. Part 2: the TLV extension message,
where the same length lives in three places and every one derives, plus the fuzz case that lies
on purpose. Part 3 (MK-2, MIPS32): split relocations, where lui/addiu %hi/%lo halves of a leaked
base derive from ONE symbol and the ha16 carry is the bug you never hand-patch again.

Part 2's message is also this directory's before/after pair: before.py hand-packs the same
bytes with a dated CRC constant and a disabled self-check -- run check.py and watch after.py's
derived cells match it byte for byte. Part 1 is imported with `from cento import *`: the
facade's __all__ is closed, so the star import is exact and the declarations read bare -- View,
u8, u16, u32, length, udp_cksum.

Run: python3 examples/ex05/ex05_computed_cells.py   (transcript.txt is this run, verbatim)
Next: ex06_delivery_plan
"""

# ruff: noqa: F403, F405 -- part 1's star import is part of the lesson

from __future__ import annotations

import sys

import cento
from cento import *


class MpktHdr(View, size=0x10):
    magic: u32
    version: u8
    flags: u8
    body_len: u16
    seq: u32
    cksum: u16
    resv: u16


class MpktBody(View, size=0xC):
    session: u32
    tag: u32
    nonce: u32


def build_datagram() -> Layout:
    layout = Layout(endian="big")  # the MK-1 wire format is big-endian; fill 0x00
    pkt = layout.region("pkt", max_size=0x1C)

    hdr = pkt.at(0x0, MpktHdr, name="hdr")
    hdr.magic = 0x4D504B54  # "MPKT"
    hdr.version = 1
    hdr.flags = 0x80  # SYN
    hdr.seq = 1

    body = pkt.at(len(hdr), MpktBody, name="body")  # len(hdr) = the view's declared size: body starts right after
    body.session = layout.sym("session_key")  # late-bound: the handshake supplies it
    body.tag = 0x48454C4F  # "HELO"
    body.nonce = 0x4D4B2D31  # "MK-1"

    # Design choice: length and checksum cover the BODY span only. A span that included the
    # length/cksum cells themselves would be a self-inclusion cycle, which cento rejects
    # (CHK-007 / ResolveError) -- so the MPKT format keeps them out of scope.
    hdr.body_len = length(body)  # reducers take a handle (its whole span) or a slice like pkt[0x10:0x1C]
    hdr.cksum = udp_cksum(body)
    return layout


def part_datagram() -> bool:
    layout = build_datagram()
    print("MPKT datagram, before the session key exists")
    print(f"pending symbols: {sorted(layout.pending())}\n{layout.hexdump()}")  # hexdump(): colored on a TTY, plain when piped
    for f in layout.emit("hexdump", final=False).fixups:  # the killer artifact: deliver these cells later, once the symbol binds
        print(f"fixup: {f.owner} ({f.region}+0x{f.offset:04x} w{f.width}) awaits {', '.join(f.missing)}")

    layout.bind("session_key", 0x5EC0DE01, source="handshake")
    print(f"\nbind session_key -> emit again, byte-complete\n{layout.hexdump()}")
    print(f"fixups now: {layout.emit('hexdump').fixups}")

    image = layout.emit("image").artifact["pkt"]
    print(f"image ({len(image)} bytes): {image.hex()}")
    return True


REC_COUNT = 3
RECS_OFF = 0xC  # records start right after the header
REC_SIZE = 0x10
PAY_OFF = 0x8  # each record's payload words start here, inside the record
MSG_END = RECS_OFF + REC_COUNT * REC_SIZE  # 0x3C


class TlvHdr(cento.View, size=0xC):
    magic: cento.u32
    msg_type: cento.u16
    total_len: cento.u16
    crc: cento.u32


class TlvRecord(cento.View, size=REC_SIZE):
    rtype: cento.u16
    flags: cento.u16
    payload_len: cento.u16
    resv: cento.u16
    pay0: cento.u32
    pay1: cento.u32


def build_records() -> cento.Layout:
    magic = 0x4D504B58  # "MPKX": MPKT's TLV extension message (part 1 built the base datagram)
    msg_tlv_ext = 0x0102
    layout = cento.Layout(endian="big")  # the MK-1 wire format is big-endian; fill 0x00
    msg = layout.region("msg", max_size=MSG_END)

    hdr = msg.at(0x0, TlvHdr, name="hdr")
    hdr.magic = magic
    hdr.msg_type = msg_tlv_ext

    # TlvRecord * 3 is ONE placement with three elements; recs[i] is a full ViewHandle per element.
    recs = msg.at(RECS_OFF, TlvRecord * REC_COUNT, name="recs")
    recs[0].rtype = 0x0001  # CAPS
    recs[0].pay0 = 0x00010003
    recs[0].pay1 = 0x00000000
    recs[1].rtype = 0x0002  # AUTH
    recs[1].flags = 0x8000  # TOKEN_PRESENT
    recs[1].pay0 = layout.sym("session_token")  # late-bound: the live handshake supplies it
    recs[1].pay1 = 0x4D4B2D31  # "MK-1"
    recs[2].rtype = 0x0003  # ECHO
    recs[2].pay0 = 0x41414141
    recs[2].pay1 = 0x42424242

    # One source of truth for every length. Each record's payload_len is a reducer over ITS OWN
    # payload span; the outer total_len covers the whole records span. Nobody types a length, so
    # the three copies cannot drift apart -- until scene 3 lies to one on purpose.
    for i in range(len(recs)):
        pay = recs[i].offset + PAY_OFF
        recs[i].payload_len = cento.length(msg[pay : recs[i].offset + REC_SIZE])
        recs[i].resv = 0
    hdr.total_len = cento.length(msg[RECS_OFF:MSG_END])
    hdr.crc = cento.crc32_mpeg2(msg[RECS_OFF:MSG_END])  # covers the records, never itself (self-inclusion is CHK-007; see part 1)
    return layout


def part_records() -> bool:
    layout = build_records()
    msg = layout.regions["msg"]
    hdr = msg["hdr"]
    recs = msg["recs"]
    # Name lookup returns whichever handle kind the placement was; narrow before field access.
    assert isinstance(hdr, cento.ViewHandle) and isinstance(recs, cento.ArrayHandle)

    print("scene 1: before the token binds -- fixups name every waiting cell")
    print(f"pending symbols: {sorted(layout.pending())}")
    result = layout.emit("hexdump", final=False)
    print(layout.hexdump())
    for f in result.fixups:
        print(f"fixup: {f.owner} ({f.region}+0x{f.offset:04x} w{f.width}) awaits {', '.join(f.missing)}")
    # Four cells wait on ONE symbol: the raw payload word, record 1's own payload_len, the outer
    # total_len, and the outer CRC. A reducer's span must materialize before it may answer, so
    # even a pure length over an unresolved span stays pending -- cento refuses to claim an answer
    # it has not computed. The fixup list is the exact post-bind worklist.

    print("\nscene 2: bind, emit, prove -- CHK-005 pins the CRC to a fresh recompute")
    layout.bind("session_token", 0x5EC0DE42, source="handshake")
    image = layout.image("msg")
    print(f"image ({len(image)} bytes): {image.hex()}")  # the exact bytes before.py hand-packs; after.py is the artifact, check.py compares them
    lens = [int.from_bytes(image[recs[i].offset + 4 : recs[i].offset + 6], "big") for i in range(len(recs))]
    total = int.from_bytes(image[6:8], "big")
    wire_crc = int.from_bytes(image[8:12], "big")
    print(f"lengths, all derived: total_len=0x{total:x}, per-record payload_len={lens}")
    # The proof: re-declare the CRC cell with expect= pinned to the wire value we just emitted.
    # check() recomputes the reducer over the span and refuses (CHK-005) if the two disagree.
    hdr.crc = cento.crc32_mpeg2(msg[RECS_OFF:MSG_END], expect=wire_crc)
    report = layout.check()
    print(f"crc32_mpeg2 recomputed over msg[0x{RECS_OFF:x}:0x{MSG_END:x}] == 0x{wire_crc:08x}; check() errors = {report.errors}")

    print("\nscene 3: the fuzz case -- record 2's length lies about its payload, ON PURPOSE")
    recs[2].payload_len = 0x40  # deliberate override: a wrong CONSTANT replaces the reducer
    try:
        layout.emit("image")  # the CHK-005 pin catches even our own lie
    except cento.EmitError as e:
        print(f"refused: {e}")
    # cento builds correct bytes by default; crafted-wrong bytes happen only when you write the
    # wrong value yourself -- and the pinned expectation above made even that a named, refusing
    # step instead of silent drift. Acknowledge the new truth and ship the malformed testcase:
    hdr.crc = cento.crc32_mpeg2(msg[RECS_OFF:MSG_END])  # the reducer recomputes: correct CRC over the lying record
    crafted = layout.emit("image").artifact["msg"]
    print(f"crafted image: {crafted.hex()}")
    claimed = int.from_bytes(crafted[recs[2].offset + 4 : recs[2].offset + 6], "big")
    total2 = int.from_bytes(crafted[6:8], "big")
    print(f"record 2 claims 0x{claimed:x} payload bytes; its span holds {REC_SIZE - PAY_OFF}.")
    print(f"total_len=0x{total2:x} and crc=0x{int.from_bytes(crafted[8:12], 'big'):08x} stay true to the wire bytes:")
    print("only the ONE field we overrode lies -- the parser's length-vs-CRC disagreement is the testcase.")
    return True


CFG_VA = 0x40204000  # the config page: a fixed RAM address, known from the MK-2 firmware image
FUNC_OFF = 0x1A50  # the dispatch handler's offset inside the leaked module (from the disassembly)


class RelocRecords(cento.View, size=0x8):
    handler_abs: cento.u32  # pointer-table entry: the full 32-bit address
    handler_rel: cento.u32  # self-relative word: target - &this_word (PIC-style)


class Insn(cento.View, size=0x4):
    op: cento.u16  # the instruction's fixed half
    imm: cento.u16  # the immediate a relocation patches


def build_page(adjust_high: bool) -> cento.Layout:
    """The config page, declared once from ONE symbol. adjust_high=False reproduces the carry bug."""
    lui_op = 0x3C0C  # lui $t4, IMM   -- opcode|register half, fixed at build_page time
    addiu_op = 0x258C  # addiu $t4, $t4, IMM
    layout = cento.Layout(endian="big")  # big-endian, like the MK-2's MIPS core
    layout.bind("cfg_va", CFG_VA, source="firmware image: loader config page")
    cfg = layout.region("cfg", base="cfg_va", max_size=0x18)

    # Ref arithmetic: symbol + constant offset. Every relocation below is a view of THIS value,
    # so there is no second place for the target address to live (and therefore to drift).
    entry = layout.sym("mk2_lib_base") + FUNC_OFF

    recs = cfg.at(0x0, RelocRecords, name="recs")
    recs.handler_abs = entry
    # Delta (Ref - Ref): a self-relative pointer, target minus the slot's own address. The slot
    # address is cfg_va+4 -- bound already -- so the pre-bind fixup names only the leaked symbol.
    recs.handler_rel = entry - recs.handler_rel.addr

    # The lui/addiu veneer. %lo is added SIGNED at runtime, so the high half uses ha16 (hi16
    # plus the carry when lo16 >= 0x8000 -- the assembler's %hi). The buggy build_page uses plain hi16.
    lui = cfg.at(0x10, Insn, name="lui")
    lui.op = lui_op
    lui.imm = cento.ha16(entry) if adjust_high else cento.hi16(entry)
    addiu = cfg.at(0x14, Insn, name="addiu")
    addiu.op = addiu_op
    addiu.imm = cento.lo16(entry)
    return layout


def sext16(v: int) -> int:
    """Sign-extend a 16-bit immediate: what the MK-2's addiu actually does with it."""
    return v - 0x10000 if v >= 0x8000 else v


def veneer_lands_at(image: bytes) -> int:
    """Decode the emitted lui/addiu pair and compute where the veneer's $t4 ends up."""
    hi = int.from_bytes(image[0x12:0x14], "big")
    lo = int.from_bytes(image[0x16:0x18], "big")
    return ((hi << 16) + sext16(lo)) & 0xFFFFFFFF


def part_relocations() -> bool:
    leaked_base = 0x40017000  # what the info leak reports at runtime: the module's load base

    print("step 1: declare the page from one symbol; emit BEFORE the leak exists")
    layout = build_page(adjust_high=True)
    print(f"pending symbols: {sorted(layout.pending())}")
    result = layout.emit("hexdump", final=False)
    print(layout.hexdump())
    for f in result.fixups:  # all four relocation cells wait on the SAME symbol -- by construction
        print(f"fixup: {f.owner} ({f.region}+0x{f.offset:04x} w{f.width}) awaits {', '.join(f.missing)}")
    try:
        layout.emit("image")  # the library refuses to call this shippable
    except cento.EmitError as e:
        print(f"refused: {e}")

    print(f"\nstep 2: the leak arrives (base={leaked_base:#010x}); bind, emit complete")
    layout.bind("mk2_lib_base", leaked_base, source="info leak: MPKT debug endpoint")
    result2 = layout.emit("hexdump")
    print(layout.hexdump())
    print(f"fixups now: {result2.fixups}")
    image = layout.image("cfg")
    target = leaked_base + FUNC_OFF
    rel = int.from_bytes(image[0x4:0x8], "big")
    print(f"handler_abs = {int.from_bytes(image[0x0:0x4], 'big'):#010x} (target {target:#010x})")
    print(f"handler_rel = {rel:#010x} = target - (cfg_va+4), wrapped: a negative displacement")
    print(f"  proof: (cfg_va+4 + handler_rel) mod 2^32 = {(CFG_VA + 4 + rel) & 0xFFFFFFFF:#010x}")
    print(f"veneer lands at {veneer_lands_at(image):#010x}")

    print("\nstep 3: the drift bug, reproduced -- the same page built with hi16")
    # By hand this is the classic split-relocation bug: patch the low half, forget that the
    # signed add just subtracted 0x10000 from your high half. lo16(target) here is >= 0x8000,
    # so hi16 and ha16 genuinely disagree -- compare the two emitted immediates.
    buggy = build_page(adjust_high=False)
    buggy.bind("mk2_lib_base", leaked_base, source="info leak: MPKT debug endpoint")
    bimage = buggy.emit("image").artifact["cfg"]
    lo = int.from_bytes(image[0x16:0x18], "big")
    print(f"lo16(target) = {lo:#06x} (>= 0x8000: the signed addiu SUBTRACTS {0x10000 - lo:#x})")
    print(f"hi16(target) = {int.from_bytes(bimage[0x12:0x14], 'big'):#06x}   <- the buggy lui immediate")
    print(f"ha16(target) = {int.from_bytes(image[0x12:0x14], 'big'):#06x}   <- hi16 plus the carry")
    print(f"buggy veneer lands at {veneer_lands_at(bimage):#010x} -- {target - veneer_lands_at(bimage):#x} short of the handler")
    print("one symbol, four derived cells: the halves cannot drift apart, because neither is stored")
    return True


def main() -> bool:
    print("---- part 1: a wire image with lazy values ----")
    if not part_datagram():
        return False
    print("\n---- part 2: records that cannot drift ----")
    if not part_records():
        return False
    print("\n---- part 3: split relocations from one symbol ----")
    return part_relocations()


if __name__ == "__main__":
    if not main():
        sys.exit(1)
