#!/usr/bin/env python3
# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
# mypy: disable-error-code="no-untyped-call"
# mk1-wake.py -- build the MKWK wake record for the MK-1 doorbell relay (fw 1.0).
# wire doc: WAKE-SPEC-2 rev A. BIG endian everywhere. DO NOT reorder the packs.
import struct

p16 = lambda v: struct.pack(">H", v)
p32 = lambda v: struct.pack(">I", v)

# !! handler addr is fw 1.0 ONLY -- 1.1 relinked, grep the new map file and update BOTH
# !! copies (this one and the one in poke_notes.txt). last checked against 1.0: 2024-08-19.
HANDLER = 0x40203E10  # wake_dispatch() per the fw 1.0 map

rec = p32(0x4D4B574B)  # "MKWK"
rec += p16(0x0102)  # version 1.2
rec += p16(0x0001)  # flags: WAKE_ONCE (0x2 = LOUD, do NOT set on shared rails)
rec += p32(0x00000004)  # wake slot 4 = the camera rail
rec += p32(HANDLER)

# commands, 8 bytes each: (op, arg). op 3 = spin up rail, op 7 = arm sensor, op 2 = ack+sleep.
# offset of cmd[1].arg is 0x1c -- counted BY HAND, recount everything if you add a cmd!!
rec += p32(0x00000003) + p32(0x00000FA0)  # spin: 4000 ms settle
rec += p32(0x00000007) + p32(0x00000001)  # arm: channel 1
rec += p32(0x00000002) + p32(0x00000000)  # ack
rec += p32(0x454E4452)  # "ENDR" trailer, the parser stops here

assert len(rec) == 0x2C, "len drifted: fix the offsets in poke_notes.txt FIRST, then here"
print(f"before wake: {rec.hex()}")
