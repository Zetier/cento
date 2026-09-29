# Porting an ABI to cento

What it takes to teach cento a new architecture, in the order you will do it. The AArch64 port
(`src/cento/abi/aarch64.py`, `examples/ex12/`) is the worked example every step cites; the whole
port is one data declaration, one conformance record, and -- optionally -- one example. Nothing
in `src/cento/chain.py` or the fold changes: the machinery is architecture-blind and reads
everything it needs from your `AbiSpec` and your gadget declarations.

## 1. Name your registers

Registers are plain strings: AArch64 names its file `"x0"`..`"x30"`, exactly the spellings that
appear in disassembly. There is no enum to extend and no registration step -- a string slot
becomes real the moment a gadget declares `Restores("x19", ...)` or a hop seats `hop.x19 = ...`,
and typos refuse at the seat site (`AttributeError: no machine slot 'x19_'`, with hints). The
two slots every architecture shares ride `Role`, not strings: `Role.SP` is the stack cursor the
chain advances, and `Role.PC` is the branch target the continuation writes. Declare your PC
restore as `Restores(Role.PC, ...)` and the fold, `_wire_pc`, and CHK-207 all key on it.

Never import the `Reg` enum for a new port: `cento.machine.Reg` is the PPC32 register file plus
the legacy role spellings (`Reg.SP`/`Reg.PC` normalize to `Role.SP`/`Role.PC` -- see
`norm_slot()` in `src/cento/machine.py`). It exists so PPC32 and its
catalogs keep their vocabulary, not as a template. `src/cento/abi/x86_64.py` and
`src/cento/abi/aarch64.py` never touch it.

## 2. Declare the AbiSpec facts

Your ABI module is a single `AbiSpec` value (`src/cento/machine.py`): `name`, the
`volatile`/`nonvolatile` split, `sp_align`, `endian`, and `word`. The split is what `Carry.Clobbered`
judges -- a call-shaped hop destroys volatile seats and spares nonvolatile ones -- so copy it
from the ABI supplement, not from intuition. `cento/abi/aarch64.py` puts `"x0"`..`"x18"` and
`"x30"` in `volatile`, and `Role.SP` plus `"x19"`..`"x29"` in `nonvolatile`; note that the SP
role itself belongs in the split, spelled as `Role.SP`.

`sp_align` is the stack-alignment modulus CHK-207 judges `entry_sp_mod` declarations against,
and your module's docstring should say WHAT enforces it on your architecture, because that is
what the error means to a user. On x86-64 it is an SSE fact (the classic movaps crash deep in
libc); on AArch64 it is a HARDWARE fact (SP alignment checking faults any SP-based access while
SP is misaligned -- `cento/abi/aarch64.py` says so, and ex12's refusal scene shows every hop
refusing, not just the call). On PPC32 it is convention, and `PPC32` declares no `sp_align` at
all: an undeclarable fact is better left unjudged than guessed.

`endian` is the architecture's byte order, and it buys a refusal: a chain built with your ABI
on a layout whose endianness contradicts it raises at `region.chain()` (the silently
byte-swapped payload, refused at construction -- `test_endian_mismatch_refuses_at_chain` in
`tests/test_x86_64_chain.py`). Leave it `None` only if your architecture genuinely runs both
ways and the Target profile carries the fact instead.

`word` is the architecture's natural register width in bytes (8 on AArch64, 4 on ARM32):
abi-aware entry points default the region word to it, and CHK-208 judges frame-field widths
against it (the default-u32 restore under a 64-bit ABI would load half a register from fill).
A shipped port also earns its registry entry: a re-export and a `SPECS` line in
`src/cento/abi/__init__.py`, so `cento.abi.AARCH64` and `abi="aarch64"` both spell your spec.
An out-of-tree `AbiSpec` needs no registration -- pass the value itself.

## 3. Map your continuation idiom onto Restores(Role.PC)

The fold's one abstraction over control flow: PC is restored from a frame slot. Every
architecture has an idiom that lands there. PPC32: `lwz r0, 0x44(r1); mtlr r0; blr` -- the slot
is wherever the `lwz` reads. AArch64: `ldp x29, x30, [sp], #0x10; ret` -- the slot is the x30
half of the pair the `ldp` loads before `ret` branches to it (see ex12's `Epilogue`, or
`A64Run` in `tests/test_abi_conformance.py`). ARM32: `pop {r4, pc}` loads PC directly. Spell
whichever you have as `pc = Restores(Role.PC, at=<offset>, width=...)`, and the chain machinery
does the rest: `hop()` wires the previous hop's PC cell to the next gadget's entry, and
`finish_in_kernel()`/`finish()` close the last one.

One geometric fact to get right: whether the pc slot is internal or external to the frame the
gadget pops. An AArch64 epilogue loads x30 from inside the bytes its own SP post-index consumes
(`at=0x8`, stride `0x10`: internal). A PPC32 syscall tail loads the continuation from BEYOND its
own frame -- `lwz r0, 0x44(r1)` on a `0x40`-stride frame reads the next frame's second word,
the LR save slot (`+0x0` is the back chain) -- and that is declared
`Restores(Role.PC, at=0x44, external=True)`. `external=` is not
decoration: chain placement knows an external continuation slot lives inside the NEXT frame's
bytes and records the overlap as declared frame aliasing instead of refusing it as CHK-001 (see
the frame-sequence aliasing comment in `src/cento/chain.py`). Internal-pc frames abut cleanly
and need nothing -- `src/cento/abi/arm32.py` is the internal-pc worked example: ARM32's
`pop {..., pc}` loads PC directly from the frame it pops (`A32Run` in
`tests/test_abi_conformance.py` is the whole declaration, and every frame in ex13's chain
abuts the next).

## 4. Add your AbiCase

`tests/test_abi_conformance.py` is the cross-arch floor: one `AbiCase` record buys your port
every test in the file. The record names the ABI and its endian/width facts plus a minimal
gadget pair -- an entry gadget (SP-frame with a PC restore) and a run gadget (one seatable slot
plus a PC restore) -- and the seatable slot three ways: `seat_attr` (the `hop.<attr>` spelling),
`seat_slot` (the machine slot), `seat_slot_name` (its rendered name). The A64 gadgets there are
a few declaration lines between them; yours will be too. The floor's scope is deliberate: it
covers fold/seat/wire, the carry split, and hash stability; pointer/pivot behavior and
declaration guards are pinned in the per-arch test files, not the floor.

Read the seat geometry in `test_fold_seat_and_wire` before copying it: the chain is
enter + run + tail, and the seat is set on the TAIL hop, because the seat sugar writes the
UPSTREAM cell that feeds the seated hop's entry state -- the run gadget's restore slot, in the
run hop's frame. The test then asserts all three legs of the floor: the value landed in that
frame cell, the fold reports the slot as a `"seat"` at the tail, and `_wire_pc` threaded the
run gadget's entry into the emitted image at the entry frame's pc offset.
`test_clobbered_carry_respects_the_split` exercises the volatile/nonvolatile judgment through
the fold (the carry applies advancing OVER the clobbering hop, so it reads the verdict at the
NEXT hop's entry), and `test_spec_hash_is_stable` pins `spec_sha16` so catalogs built against
your gadgets cannot drift silently. If your split is right, all three pass with no
per-arch code.

## 5. Optional: executor and example

Emulation verification (the `[verify]` extra, GPL unicorn) is per-architecture executor work:
`verify_transfer` in `src/cento/verify.py` dispatches on `abi.name` to a descriptor -- one
`_ArchExec` record of unicorn arch/mode facts, register-id mappings, word/pack widths, and an
optional syscall probe, registered in `_executors()`. x86-64, AArch64, ARM32, and PPC32-BE ship
descriptors today; any other ABI is refused with a teaching error rather than guessed register
mappings. Adding yours is one registry entry plus a probe, but a port without an executor is
still a complete port: verification is opt-in provenance (CHK-304), not part of the build-time
contract. `python -m cento.import_catalog` is the fast path from a ropper/ROPgadget listing to
a starter catalog -- x86-64 pop/ret gadgets arrive auto-specced, and everything else (including
every gadget on your new architecture) lands in the unspecced block for hand promotion.

An example is how a port teaches. `examples/ex12/` is the template: one directory, one script
with the numbered docstring header, a `Run:` block, and a `Next:` pointer; gadget declarations
whose docstrings open with real disassembly (`disasm()` renders them as the catalog); and a
refusal scene that shows your architecture's characteristic mistake as a named check. If the
run is fully deterministic (no host compiler or emulator), register it in `TRANSCRIPTS`
(`examples/__init__.py`), regenerate with `make transcripts`, and check the transcript in --
tests assert byte currency. Then add the README examples-table row and pin the signature output
lines in `tests/test_examples.py`, so the example cannot drift from what it claims to show.
