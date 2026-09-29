# cento reference (v0.2.0)

API cheatsheet organized by workflow, then the CHK code table. The facade
`import cento` exports everything below (closed `__all__`; `from cento
import *` is exact). Everything is documented in docstrings: `help(cento.X)`
for details.

## Layout and regions

- `Layout(*, endian=None, name=None, fill_default=0, abi=None)` -- one build's isolation unit; never shared state. `abi=` takes a spec (`cento.abi.X86_64`) or a name string (`"x86_64"`) and carries endian/word into everything the layout makes; endian defaults from the abi, else little.
- `Layout.region(name=None, *, base=None, max_size=None, fill=None, pad=None, forbid=None) -> Region` -- `base=` names the base symbol (default `<name>_base`); `pad=UNIT` cycle-pads the whole region at creation.
- `cento.region(name, *, base, max_size, fill, pad, forbid, word=None, endian=None, fill_default=0, abi=None) -> Region` -- one-region shortcut on a FRESH anonymous layout; reach the layout via `region.layout`.
- `cento.fit(spec, *, fill=0, length=None, word=None, endian=None, abi=None) -> Region` -- pwntools' fit, except you keep the region (dict offset->value|list, or a flat sequence; bytes keep their length, ints/Refs take word; word/endian default from `abi=`, else 8/little).
- `Region.at(offset, spec, name=None, *, over=(), why=None) -> ViewHandle | ArrayHandle` -- named placement; overlaps require `over=` + `why=` (`over=` takes a bare name or a tuple).
- `Region.alloc(spec, name=None, *, align=4, reserve_external=True)` -- bump-allocate past every placement and staged cell.
- `Region.cell(offset, width=4) -> CellHandle` -- a raw cell.
- `Region.pad(length, *, unit=4, at=0, data=None) -> bytes` -- cycle pad (or given data).
- `Region.chain(name=None, *, at, abi=None, carry=None, gadget_set=None, arm=True) -> Chain` -- `abi=` takes a spec or a name string and defaults to the layout's declared abi.
- `region[off] = value` (raw word), `region[a:b] -> Span` (for reducers), `bytes(region)` / `Region.image(*, final=True)` (the gate by default; `final=False` is the draft read).
- `Region.addr(offset=0) -> Ref`; `Region.bind(...)` forwards to the layout.

## Views (typed structs over bytes)

- `class Hdr(cento.View, size=0x10, dense=False):` with fields either gap-free annotations (`magic: cento.u32`) or explicit `Field(offset, width, *, external=False, doc="", alias=None, default=None)` (`alias=` names an alternate attribute spelling). `dense=True` demands every field be written (CHK-010).
- Widths: `u8 u16 u32 u64 i8 i16 i32 i64`, `Bytes(n)`, arrays `u32 * 4` (WidthArray) and `Hdr * 4` (ArraySpec).
- `ViewHandle.<field>` reads/writes the cell; `.addr`, `.span`, `len()`; `.overlay(spec, at, name=None, *, why, also_over=())` places a view over this one (declared alias).
- `CellHandle.read(*, signed=False) / .write(value) / .addr / .span`.
- Handles coerce: assigning a ViewHandle to a pointer-shaped cell writes its address.

## Symbols, refs, computed cells

- `Layout.sym(name) -> Ref` -- lazy symbol; `Layout.bind(sym, value, *, source="manual")` resolves every dependent cell (rebinding re-resolves).
- `Layout.expect_sym(sym, *, range=(lo, hi), align=N)` -- declare what a plausible bind looks like; an implausible bind (mis-parsed leak) refuses on the spot.
- Ref algebra: `layout.sym("base") + 0x40`, transforms `lo16(ref) hi16(ref) ha16(ref)` for split relocations.
- Reducers over spans (recomputed on every emit; `expect=N` pins the value, CHK-005 on mismatch): `length(span)`, `crc32_mpeg2(span)`, `crc8(span)`, `sum16(span)`, `udp_cksum(span)` (RFC 1071, span only -- no pseudo-header), `xor_fold(span)`.
- `Layout.register_reducer(name, fn) -> constructor` -- layout-scoped custom reducer (`fn: bytes -> int`); builtin names reserved, re-registration refused; the returned constructor is used like `cento.length`.
- `Layout.register_xform(name, fn) -> constructor` -- layout-scoped value transform (`fn: int -> int`); builtin names reserved, re-registration refused; the returned constructor is used like `cento.lo16`.
- `cycle(length, *, alphabet=..., n=4) -> bytes` and `cycle_find(needle, *, width=4, endian="little") -> int` -- pwntools-cyclic parity; `Layout.cycle_find(...)` uses the layout's endian.
- `Writeback("name")` -- cell value the TARGET writes at runtime: excluded from emission, a producer in the fold. `Writeback.discard(reason)` for a landed-but-unconsumed write.

## Gadgets and chains (the checked fold; four machine models -- see Scope limits in SKILL.md)

- `class G(cento.Gadget, entry=0x..., stride=0x..., reentry_safe=False, frame_base=Role.SP, entry_sp_mod=None, sp_pivot=False):` -- one declaration yields the frame View AND the register Transfer. Body: `pc = Restores(Reg.PC, at=0x44, external=True)` (external = the slot lives in the NEXT frame), `Clobbers(Reg.X)`, `needs = {Reg.R31: "why this input"}`. Docstring first line = `disasm()` catalog line. `entry` may be symbolic (`cento.Ref("libc_base") + off`) for ASLR'd libraries; `entry_sp_mod=8` declares the SysV call-entry alignment contract (CHK-207 against `abi.sp_align`); `sp_pivot=True` on a pointer frame (leave;ret) moves the SP cursor past it.
- `Chain` verbs: `enter(G)` (where the hijack lands), `hop(G, name)`, `finish(G, **frame_fields)`, `finish_in_kernel(pc=...)` (terminal, no frame).
- `Hop`: seat inputs `hop.r30 = value` (lands in the upstream cell); `hop.frame.<field>`; `hop.writebacks.<name> -> WritebackRef`; `hop.add_effect(Effect)`; `hop.<reg>.fed_by`.
- Judgment: `chain.seal()` (raise on first error), `chain.issues() -> (errors, warnings)` (never raises), `chain.narrate()` (prose dataflow story), `chain.state_at(hop_name)`, `chain.expect(hop.r30, from_=ref)` (pin provenance, CHK-203), `chain.dangling()`.
- `Chain.dataflow() -> ChainFlow` / `Chain.to_json() -> dict` -- narrate() as data: hops in order with FedBy provenance, effects, writebacks, spec_sha16 join keys.
- `Effect(name, controls={cell: Writeback("out") | CLOBBER}, window=None)`; `Carry.Passthru/Clobbered/Unknown`; `Reg` (PPC32: R0-R31, SP=R1, LR, CTR, XER, CR, PC); other architectures use string slots ("rdi") -- `cento.abi.X86_64` is the SysV split (sp_align=16), and `abi="x86_64"` spells it anywhere an abi is taken (`cento.abi.resolve` is the registry); `CLOBBER`, `UNSET`, `Transfer`.
- `cento.Role` (SP/PC): the architecture-blind role slots frame logic keys on; Reg.SP/Reg.PC are the legacy spellings and normalize to them.
- Catalogs/profiles: `Catalog.load(path).gadgets(set_name) -> GadgetSet` (attribute access materializes Gadget classes; `crosscheck` judges inline declarations -- CHK-301/302/303); `cento.target(profile, set_name=None) -> Target`; `Target.layout()` / `Target.region(...)` carry endian/fill/gadget facts (profiles take an `"abi"` key -- a name string -- that flows into every layout the Target makes).
- `python -m cento.import_catalog` -- ropper/ROPgadget listings to schema-2 catalogs: x86-64 pop/ret gadgets auto-specced (named in `provenance.auto_specced`), the rest unspecced until promoted (write the restores, move the entry into the set).
- Verification extra: `pip install 'cento[verify]'` (unicorn; executors for x86-64, AArch64, ARM32, and PPC32-BE); `layout.attach_verdicts(...)` enables CHK-304 provenance.

## Check, emit, deliver

- `Layout.check() -> Report`; `Layout.preflight() -> Preflight` -- shippability as data: `.shippable`, `.report`, `.dangling`, `.pending`, `.fixups`, `.to_json()` (everything the final emit would refuse on, without raising).
- `cento.gate(layout) -> bool` -- the CI verdict: True exactly when `preflight().shippable`; on False the blockers (the rendered report plus each dangling chain) print to stderr; the CI step is `sys.exit(0 if cento.gate(layout) else 1)`. Never raises, never emits.
- `cento.checks.CODES: dict[code, (meaning, fix)]` -- the programmatic CHK catalog (same table as below).
- `Report.render(*, verbose=False)` (verbose lists the waiver ledger), `.to_json()`, `.errors/.warnings/.pending/.waivers/.rewrite_waivers/.verified`, `.diff(prev) -> cento.checks.ReportDiff` (fixed/new/remaining, keyed on (code, subjects)). `Issue(code, subjects, msg, hint)`.
- Refusals carry their data: `EmitError.report` is the gate's `Report` (None when no report was computed), `ChainError.issue` is seal()'s refusing `Issue` (both have `.to_json()`), and the draft read's `ResolveError.partial` is the fill-padded bytes.
- `Layout.emit(backend, *, final=None) -> EmitResult` -- backends `"image"` (`dict[str, bytes]`), `"sparse"` (`dict[int, bytes]` + `.ordered`), `"hexdump"` (str). Final by default -- check errors, dangling chains, pending symbols all refuse; `final=False` is the ungated draft read (its `.fixups` is the worklist).
- `EmitResult.fixups: list[Fixup(region, offset, width, owner, missing)]` -- cells awaiting symbols; `.pending` the symbol names.
- `Layout.image(name=None, *, final=True) -> bytes` -- fail-closed (the gate by default, refusing as `EmitError`; `final=False` is the draft read, `ResolveError` on unresolved with the fill-padded bytes riding as `.partial`); `Layout.hexdump(*, color=None, skip=False)` -- display only, `skip=True` summarizes pad runs.
- `Layout.explain(path_or_addr) -> str` -- what is this byte and why; `Layout.explain_data(path_or_addr) -> Explanation` is the same judgment as a frozen record (`.render()`, `.to_json()`).
- `Layout.manifest() -> Manifest` / `Layout.to_json() -> dict` -- the layout as data: regions, placements, cells with resolution state, chain spec_sha16 join keys, provenance/binds/expectations, and the abi facts block (always present, carrying the operative endian; declared-abi facts inline, null facts omitted; region rows omit "word" when it equals the abi's).
- `Layout.map()` -- ASCII memory map (a display view over manifest()).
- `Layout.assurance() -> Assurance` -- verified/checked/assumed tiers per gadget, symbol expectations + bind sources, the waiver ledger, and the gate verdict; absence of a verdict exports as "assumed" (`.render()`, `.to_json()`).
- Escape hatches (reason mandatory): `Layout.allow_rewrite(cell_or_path, reason)`, `Layout.allow_clobber(cell, effect, reason)`.
- Delivery phases: `Layout.mark(cell, Deliver.LATE | Deliver.ARM)` -- NORMAL < LATE < ARM; ARM ships only from `finalize()`, last.
- `Layout.plan(*, real_hw=None) -> DeliveryPlan` (or `DeliveryPlan(layout, *, real_hw=False)`): `.bind(sym, value, *, source)` (rebind invalidates confirmations -> stale forensics in `.stale`), `.stage() -> list[DeliveryGroup]` (never ARM), `.confirm(group)`, `.finalize()` (refuses on unconfirmed groups / unresolved symbols; yields ARM last). `DeliveryGroup.items` are `(addr, bytes)` pairs; `.describe()`. `plan.ledger.events` / `.save(path)` -- append-only JSONL.
- `cento.golden(reference: bytes) -> Golden`; `Golden.compare(region) -> GoldenDiff` -- byte-regression pinning against a captured emission: `.ok`, `.divergences` (owner-attributed runs; a length mismatch is a named run), `.render()`; the pytest idiom is `assert diff.ok, diff.render()`; fail-closed via the draft read `region.image(final=False)` (ResolveError on unresolved), never auto-regenerates.
- Errors (all subclass `CentoError`): `PlacementError WidthError XformError ResolveError EmitError PlanError ChainError CatalogError VerifyError`.
- Display helpers: `colorize_disasm(line)`, `Gadget.disasm()`.

## CHK code table

Severity: E = error (blocks final gates), W = warning.

| Code | Sev | Meaning | Fix (what the hint teaches) |
|---|---|---|---|
| CHK-001 | E | placement extents overlap without a declared alias | declare intent: `region.at(..., over=("other",), why="...")` |
| CHK-002 | E | placement or cell end exceeds region `max_size` | grow `max_size` or move it; the cap is deliberate |
| CHK-003 | E | `over=` alias declared but extents do not intersect | make the alias name the placement that actually overlaps |
| CHK-005 | E | computed reducer value differs from its `expect=` pin | fix the expectation or the span contents |
| CHK-006 | E | overlapping (aliased) cells disagree on shared bytes | aliased cells must agree byte-for-byte; check overlay arithmetic |
| CHK-007 | E | reducer dependency cycle (or unregistered reducer) | break the cycle or register the reducer |
| CHK-008 | E | cell rewritten by a different owner (last-writer-wins) | if intended: `layout.allow_rewrite(cell, reason=...)`; else fix the collision |
| CHK-009 | E | resolved value does not fit the cell width (WidthError) | widen the cell, or slice deliberately (`lo16`/`hi16`/`ha16`) |
| CHK-010 | E | `dense=True` view has fields unset (or claimed by another owner) | write them (or resolve the foreign rewrite); drop `dense=True` if fill is deliberate |
| CHK-011 | E | resolved cell bytes contain a forbidden transport byte (`region(forbid=...)`) | pick a value/address/gadget the transport survives, or slice around the byte |
| CHK-012 | E | two bound regions occupy overlapping absolute address ranges | rebase one region; sparse emission would land silently colliding writes |
| CHK-013 | W | bound symbol that no cell, region base, or expectation references | fix the symbol name (a typo'd bind is a silent no-op) or drop the bind |
| CHK-014 | E | cell names an xform this layout never registered | register_xform() on the layout that resolves the cell (constructors are layout-scoped) |
| CHK-101 | W | external field span overlaps another placement | declare `over=`/`why=` if intended (array neighbors are the common benign case) |
| CHK-102 | W | chain-internal overlay alias (auto-declared) | informational; chain-owned frames may interleave |
| CHK-201 | E | hop consumes a register nothing feeds (unknown/clobbered/unseatable) | seat the input (`hop.<reg> = value`) or fix the upstream transfer; entry inputs go via `enter()` |
| CHK-202 | W/E | a hop's need is fed by an unset cell (error once the chain is finished, past the entry hop) | seat a value or declare the supplying effect |
| CHK-203 | E | `chain.expect()` provenance mismatch: register not fed by the pinned writeback | check the effect attachment and the overlay arithmetic |
| CHK-204 | E | cell is a target writeback but also user-staged/seated | leave writeback cells UNSET; the runtime writes them |
| CHK-205 | E | windowed effect may clobber a live cell | move the cell, or `layout.allow_clobber(cell, effect, reason=...)` |
| CHK-206 | W | dangling continuation: last hop's PC-source never wired (final gates REFUSE on it) | call `finish(...)`/`finish_in_kernel(pc=...)`, or write the pending cell deliberately |
| CHK-207 | W/E | call-entry stack alignment violated (SP % `abi.sp_align` != the gadget's `entry_sp_mod`; warning while the base alignment is undeclared) | insert a ret-align gadget before the hop -- the movaps-in-system crash, refused at build time |
| CHK-208 | W | frame field width contradicts the chain abi's word (field narrower than the word: the register's other bytes come from fill; field wider: the load overreads into the next slot) | declare the intended width (`width=cento.u32/u64`) or drop `abi=` if the mismatch is deliberate |
| CHK-301 | E | gadget entry address drifts from the catalog | the catalog is authoritative; update the inline gadget |
| CHK-302 | E | gadget spec drift vs the catalog (geometry, widths, stride, frame_base, reentry_safe, needs, entry_sp_mod, sp_pivot) | update the inline gadget to match the catalog geometry |
| CHK-303 | W | gadget not in the catalog (unverified) | add it to the catalog, or load it FROM the catalog |
| CHK-304 | W | chain hop's gadget has no PASS emulation verdict (judged only once verdicts are attached) | run `verify_transfer` (needs `[verify]`) and `layout.attach_verdicts(...)` |

Codes are stable grep targets: existing codes keep their meaning; new checks
get new codes. Non-CHK refusals carry their own named exceptions:
`PlacementError` (bad placement at construction), `ResolveError`
(fail-closed `image()`/`read()` on unresolved symbols), `EmitError` (a gate
refused -- the message is verb-prefixed, e.g. `final emit refused:`),
`PlanError` (plan protocol misuse), `ChainError` (chain construction or
`seal()`).
