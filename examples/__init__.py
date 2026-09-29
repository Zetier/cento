# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""cento (n.) -- a poem stitched together from other poets' lines.
This library builds chains the same way: borrowed fragments, arranged
deliberately, checked as a whole.

Runnable examples, one directory each (examples/exNN/), in reading order:

  00  ex00 (before/after)      -- START HERE: the exploit that grows (heap frames + rbp pivot): hand-rolled, declared, checked; check.py compares all three

  01  ex01_find_your_offset   -- the on-ramp: cycle/cycle_find on mkcfg (x86-32), plus the textbook-ret2libc pair and ctf/ (live)
  02  ex02_toy_chain          -- the MK-1's checked gadget chain (real PPC32): enter/hop/finish, seats, writebacks
  03  ex03_local_ret2win      -- throw it for real: compile a local x86-64 toy, crash it, land win()
  04  ex04_qemu_ret2win       -- big-endian for real: a hand-assembled PPC32 victim under qemu-ppc, nip from the gdb stub
  05  ex05_computed_cells     -- reducers three ways: wire image, TLV records that cannot drift, split relocations (with a before/after pair)
  06  ex06_delivery_plan      -- ARM-gated delivery: stage/confirm, the ledger, and the leak that moves the base
  07  ex07_guardrails         -- seven planted mistakes, seven named refusals -- then CI consumes them (to_json, gate())
  08  ex08_borrowed_structures -- bytes the target trusts: forged chunk, forged object/vtable, patched flash record
  09  ex09_fake_frame_chain   -- a forged call stack in the heap: three frames, a kernel-minted token threaded hop to hop
  10  ex10_provenance         -- catalogs absorb re-links and ISAs; emulation verifies the bytes; drift is named (with a before/after pair)
  11  ex11_the_thrower        -- your tube, cento's plan: the same DeliveryPlan thrown live through a stdlib pipe AND a pwntools tube
  12  ex12_aarch64_chain      -- the MK-4's AArch64 chain: ldp/ret frames, a csu-style call, and the hardware alignment rule (CHK-207)
  13  ex13_arm32_chain        -- the MK-3's ARM32 chain: pop-to-pc frames that abut, and a Thumb entry carrying bit 0
  14  ex14_port_a_script      -- porting an existing script: golden bytes first, one raw region, typed views carved in, symbols last (with a before exhibit)

Each runs standalone: python3 examples/exNN/<name>.py (or `make exNN` from the repo root; a
directory with a before/after pair runs its exhibit scripts in order: before, after, enhanced
where present, check, refusal where present). Non-Python inputs
live next to their scripts: ex03's C source, ex04's victim assembler, ex10's catalog/profile
JSONs and firmware fixtures (each with a Makefile where builds apply); ex01 additionally
carries ctf/, its ret2libc pair live against a binary you build from source.

These examples target the fictional Meridian family (PPC32 MK-1, MIPS32 MK-2, ARM32 MK-3, AArch64 MK-4, x86 mkcfg) except
ex00/ex01 (synthetic textbook constants; ex01's ctf/ builds a real victim from source) and
ex03/ex04, which build their own toy victims; adapting the pattern to a real target is your
engagement's business, not the tutorial's.
"""

# The transcript contract: for every directory whose output is fully deterministic (no host
# compiler, emulator, or optional [verify] extra involved), transcript.txt is the checked-in
# verbatim run of these scripts, in this order -- the reading-first artifact. `make transcripts`
# regenerates them; tests/test_examples.py rebuilds each one the same way and asserts byte
# equality, so a drifted transcript fails CI. ex03/ex04/ex11 (host toolchains) have no transcript by
# design; ex10's tutorial needs unicorn to show its full output, so only its pair is listed.
TRANSCRIPTS: dict[str, tuple[str, ...]] = {
    "ex00": ("before.py", "after.py", "enhanced.py", "check.py", "refusal.py"),
    "ex01": ("before.py", "after.py", "check.py", "refusal.py", "ex01_find_your_offset.py"),
    "ex02": ("ex02_toy_chain.py",),
    "ex05": ("before.py", "after.py", "check.py", "ex05_computed_cells.py"),
    "ex06": ("ex06_delivery_plan.py",),
    "ex07": ("ex07_guardrails.py",),
    "ex08": ("ex08_borrowed_structures.py",),
    "ex09": ("ex09_fake_frame_chain.py",),
    "ex10": ("before.py", "after.py", "check.py"),
    "ex12": ("ex12_aarch64_chain.py",),
    "ex13": ("ex13_arm32_chain.py",),
    "ex14": ("before.py", "ex14_port_a_script.py"),
}
