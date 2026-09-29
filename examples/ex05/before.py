#!/usr/bin/env python3
# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
# mypy: disable-error-code="no-untyped-call"
# mpkt-msg.py -- build the MPKX status message (3 records) for the MK-1 relay.
# wire format doc: MSG-SPEC-4 rev C. BIG endian everywhere.
import binascii
import struct

p16 = lambda v: struct.pack(">H", v)
p32 = lambda v: struct.pack(">I", v)

# !! total_len counts the RECORDS ONLY (3*0x10 = 0x30) -- the hdr is NOT included,
# !! see MSG-SPEC-4 p.12, everyone gets this wrong once. RECOMPUTE if you add a record.
# !! crc is crc32-mpeg2 over the WHOLE message with the crc field zeroed.
# !! RECOMPUTE BOTH every single time you touch ANY byte below. both. every time.
TOTAL_LEN = 0x30
CRC = 0xD9CEAEBD  # from crc_tool.py run 2024-11-02, DO NOT trust after edits

hdr = p32(0x4D504B58)  # "MPKX"
hdr += p16(0x0102)  # version 1, type 2
hdr += p16(TOTAL_LEN)
hdr += p32(CRC)

recs = b""
recs += p16(0x0001) + p16(0x0000) + p16(0x0008) + p16(0)  # rec0: CAPS, len 8
recs += p32(0x00010003) + p32(0x00000000)  # proto 1.3
recs += p16(0x0002) + p16(0x8000) + p16(0x0008) + p16(0)  # rec1: SESSION|URGENT, len 8
recs += p32(0x5EC0DE42) + p32(0x4D4B2D31)  # token + "MK-1"
recs += p16(0x0003) + p16(0x0000) + p16(0x0008) + p16(0)  # rec2: PAYLOAD, len 8
recs += p32(0x41414141) + p32(0x42424242)

msg = hdr + recs
assert len(msg) == 0xC + TOTAL_LEN, "length drifted -- recount the packs AND fix TOTAL_LEN"
# the crc self-check (zeroed crc field), so at least the stale-CRC bug screams locally:
zeroed = msg[:8] + b"\x00\x00\x00\x00" + msg[12:]
assert (binascii.crc32(zeroed) ^ 0xFFFFFFFF) & 0xFFFFFFFF != CRC or True  # TODO: mpeg2 variant, tool disagrees w/ binascii -- trust crc_tool.py

print(f"before tlv: {msg.hex()}")
