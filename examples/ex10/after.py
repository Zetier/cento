#!/usr/bin/env python3
# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
# mk1-relay-chain, mapped to cento: the same scratch page as before.py, byte for
# byte (run check.py and see). Every offset before.py pokes by hand -- the entry
# pcs, the 0x40 frame stride, the +0x44 continuation slot IN THE NEXT FRAME --
# is a fact of the firmware, so it lives in the checked-in catalog; this file
# names gadgets and seats their needs, nothing more. The MK-2 gateway is this
# same declaration against profile_mk2_v2_3.json -- no second file to hand-sync.
import pathlib

import cento

HERE = pathlib.Path(__file__).parent
t = cento.target(str(HERE / "profile_mk1_v1_0.json"))  # endian, fill, gadget catalog: the device's facts

HALT = 0x40003000  # this device's halt vector: park the core after the mint
SCRATCH_VA = 0x40200000  # the staging page (before.py's 0x402xxxxx constants, once)

layout = t.layout()
layout.bind("scratch_va", SCRATCH_VA, source="fw v1.0 memory map: scratch window")
ram = layout.region("scratch", base="scratch_va", max_size=0x400)

# The chain: map a scratch page, mint a token, park. Both calls unprivileged
# (capability 0); the op words ride out-of-band arg blocks at +0x380 / +0x3c0.
run = ram.chain("relay", at=0x100)
ent = run.enter(t.gadgets.CTX_RESTORE)
mapper = run.hop(t.gadgets.SYSCALL_TAIL, "map_scratch")
ent.frame.sp = mapper.frame  # ctx.sp -> the first SP frame (the handle IS its address)
mapper.r30 = 0  # catalog: capability word -> r3 (0 = unprivileged)
mapper.r31 = layout.sym("scratch_va") + 0x380  # catalog: arg-block pointer -> r4
mint = run.hop(t.gadgets.SYSCALL_TAIL, "mint_token")
mint.r30 = 0
mint.r31 = layout.sym("scratch_va") + 0x3C0
run.finish_in_kernel(pc=HALT)  # the terminal continuation pc, placed by stride -- not by hand

if __name__ == "__main__":
    report = layout.check()  # a catalog edit that breaks a placement or a seat refuses here
    if report.errors:
        raise SystemExit(report.render())
    print(f"after mk1 image: {layout.image('scratch').hex()}")
