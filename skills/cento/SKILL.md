---
name: cento
description: Use when building, packing, or validating exploit payload bytes in a project that uses (or should use) the cento Python library -- declarative payload layout, stack frame or fake-object forging, ROP/gadget chain construction, offset finding with cyclic pads, length/checksum/CRC header cells, late-bound leak symbols, staged multi-write delivery plans, or when diagnosing a cento refusal (a CHK-* error code, PlacementError, ResolveError, EmitError, or a refused emit/finalize). Trigger phrases include "payload layout", "exploit bytes", "ROP chain", "gadget chain", "fake stack frame", "cyclic offset", "CHK-001" (or any CHK code), "fixup", "delivery plan", "arm trigger".
---

# cento: declarative exploit-payload layout

cento builds and validates exploit payloads offline: regions of bytes, typed
views (structs) over them, symbols that resolve when the leak lands, computed
cells (lengths/CRCs) that re-derive on every emit, gadget chains checked by a
dataflow fold, and staged delivery plans with a trigger-last ARM gate. It
emits bytes and plans; it never touches a target. Zero runtime deps,
Python 3.10+, `import cento` is the whole API (a closed `__all__`).

Reach for cento when a payload outlives one session: offsets churn, leaks
land mid-exploit, delivery is multi-stage, or the bytes must be auditable.
For a one-shot `fit()` + `ROP()` throwaway, plain pwntools is fine.

## The core loop

0. One-shot? `cento.fit({off: [gadgets...]}, fill="A")` -> a Region; `.image()` for the bytes. Everything below grows from that same object.
1. Declare structure: `layout = cento.Layout(endian=...)`, `reg = layout.region(name, max_size=...)`, place `View` subclasses with `reg.at(off, MyView, name=...)`, write fields.
2. Use symbols for unknowns: `field = layout.sym("leak")`; computed cells for derived values: `hdr.len = cento.length(reg[a:b])`.
3. Bind as facts arrive: `layout.bind("leak", value, source="why you believe it")`.
4. Check: `layout.check().render()` -- fix every ERROR line by its hint.
5. Emit final: `layout.image(name)` or `layout.emit("image")` -- final by default, the gate refuses while errors, dangling chains, or unbound symbols stand.

For tooling loops, `layout.preflight()` returns the same verdict as data:
`.shippable` plus the blockers (`.report`, `.dangling`, `.pending`) -- fix the
named causes and re-run until shippable, then emit final.

Emitting early is normal and useful: `emit(backend, final=False)` is the
ungated draft read, and `res.fixups` names exactly which cells await which
symbols. `layout.hexdump(skip=True)` is the human view; artifacts stay
plain and deterministic.

## Doctrine (respect these; do not code around them)

- Fail closed means DO NOT catch-and-guess. Never wrap `image()`/`emit()`/`finalize()` in try/except to substitute defaults, and never "fill in" an unresolved symbol with a placeholder to make emit pass. The refusal is the feature: fix the named cause.
- Overlapping placements are declared intent: `region.at(..., over=("other",), why="reason")`. Never nudge offsets to dodge CHK-001 if the overlap is the design.
- Rewriting a cell another owner wrote needs `layout.allow_rewrite(cell, reason=...)`. Waiver reasons are ledger lines a human reviews -- write real reasons, not "fix check".
- Writeback cells (`cento.Writeback("name")`) are runtime-written: leave them UNSET. Seating or staging one is CHK-204, and the fix is to delete your write, not the writeback.
- One Layout per build; `cento.region()` makes a fresh layout per call. No module-global state; two identical builds must emit identical bytes.
- Endianness is per-layout (`Layout(endian="big")`; default is little, the x86-64-flavored default target). Better: declare the target once with `Layout(abi="ppc32")` (or `cento.abi.PPC32`) and endian/word flow from it. `cycle_find` takes `endian=` too -- mismatched endian is the classic silent offset bug.

## Workflow index

Verified, runnable recipes live in [recipes.md](recipes.md); the API
cheatsheet and full CHK table in [reference.md](reference.md).

| Task | Recipe |
|---|---|
| Find an overflow offset (cycle pad in, crash value out) | recipes.md recipe 1 |
| Pack a struct with typed views + late-bound symbols | recipes.md recipe 2 |
| Length/CRC header cells that never drift | recipes.md recipe 3 |
| A checked gadget chain (fold, seats, writebacks) | recipes.md recipe 4 |
| An x86-64 SysV ret2libc chain (string slots, sp_pivot, movaps alignment) | recipes.md recipe 4b |
| Multi-stage delivery with a trigger-last ARM gate | recipes.md recipe 5 |
| Diagnose and fix a refusal (CHK triage) | recipes.md recipe 6 |

Scope limits to know before promising things: the chain fold ships four
machine models -- x86-64 SysV, AArch64 AAPCS64, ARM32 AAPCS, and PPC32-BE
EABI (`cento.Reg` is the PPC32 register file; the other architectures use
string slots, and Role.SP/Role.PC are the arch-blind spellings);
layout/views/symbols/cells/plans are architecture-neutral. No gadget
discovery (declare gadgets you found with ropper etc.; `python -m
cento.import_catalog` converts a listing you already have), no transport
bad-byte checking, no delivery execution (your thrower writes the
`(addr, bytes)` pairs).

## When things refuse: the CHK triage loop

Every refusal is a named, greppable error: `CHK-NNN [subjects]: message
hint: what to do instead`. The loop:

1. Run `print(layout.check().render())` (or read the refusal text -- gates embed the same report).
2. Look the code up: `cento.checks.CODES["CHK-001"]` returns (meaning, fix) programmatically; [reference.md](reference.md) has the same table with severities.
3. Apply the fix the hint teaches. Declared-intent fixes (`over=`/`why=`, `allow_rewrite(reason=)`, `allow_clobber(reason=)`) require honest reasons.
4. Re-run `check()` until zero errors, then emit final. `render(verbose=True)` shows the waiver ledger for review.

Never suppress: do not except-and-continue past `EmitError`, do not delete
the check call, do not waive without a real reason. If `finalize()` refuses
with unconfirmed groups or unresolved symbols, that is sequencing feedback:
confirm delivered groups and bind the missing symbols, in that order. A
CHK-206 dangling continuation means the chain was never finished -- call
`finish()`/`finish_in_kernel(pc=...)`.

For CI: `layout.check().to_json()` is machine-readable, and
the final emit failing loudly is the intended gate.
