#!/usr/bin/env python3
# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
# mypy: disable-error-code="no-untyped-call"
# mk1-relay-chain.py -- scratch-page image for the MK-1 relay chain (fw v1.0).
# session notes 2024-10: offsets from the v1.0 dump, verified by hand. BE32.
import struct

p32 = lambda v: struct.pack(">I", v)

SCRATCH_LEN = 0x400
FF1 = 0x100  # frame 1 offset in the scratch window

# !! the offset table. stride of the tail is 0x40 -- the +0x44 continuation pc
# !! lands IN THE NEXT FRAME. keep every row in sync w/ the stride BY HAND.
# !! fw 4.2 allegedly moved r30 -- NOT retuned here, we still fly v1.0.
POKES = {
    0x000: 0x40002000,  # ctx.pc -> tail entry (the trigger. write LAST on the box!)
    0x004: 0x40200100,  # ctx.sp -> FF1
    0x054: 0x40200380,  # ctx.r31 -> map arg block (scratch+0x380)
    FF1 + 0x3C: 0x402003C0,  # FF1 r31 -> mint arg block (scratch+0x3c0)
    FF1 + 0x44: 0x40002000,  # FF1 continuation pc -- IN FF2's frame, see stride note!!
    FF1 + 0x84: 0x40003000,  # FF2 continuation pc -> halt vector (park the core)
}
# (arg-block op words are poked out-of-band by the throw script, not staged here)

img = bytearray(SCRATCH_LEN)
for off, val in POKES.items():
    img[off : off + 4] = p32(val)

# this is ONE device. the MK-2 gateway needs this whole file again with the
# MIPS offsets (stride 0x20, pc INSIDE the frame) -- see mk2-relay-chain.py,
# and keep BOTH in sync with the fw dumps by hand. forever.
print(f"before mk1 image: {bytes(img).hex()}")
