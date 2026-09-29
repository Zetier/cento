# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Structural validators over a Layout. Pure and offline: no emulator, no target.

The CHK-code catalog (CODES) is closed and stable: existing codes keep their meaning; new
checks get new codes.
"""

from __future__ import annotations

import dataclasses
import difflib
import typing

import cento.cells
import cento.errors
import cento.gadget

if typing.TYPE_CHECKING:
    import cento.regions


@dataclasses.dataclass(frozen=True)
class Issue:
    code: str
    subjects: tuple[str, ...]
    msg: str
    hint: str

    def to_json(self) -> dict[str, typing.Any]:
        """This issue as a plain dict (the shape Report.to_json embeds)."""
        return dataclasses.asdict(self)


class VerdictLike(typing.Protocol):
    # structural on purpose: the dependency stays one-way (regions and checks never import verify)
    """The two facts CHK-304 reads off an attached verdict (read-only: frozen verdicts conform).
    cento.verify.Verdict satisfies this structurally."""

    @property
    def ok(self) -> bool: ...

    @property
    def bytes_sha16(self) -> str: ...


class Waiver(typing.NamedTuple):
    """One clobber-waiver ledger row: a tolerated windowed-effect clobber and who tolerated it."""

    region: str
    offset: int
    effect: str
    reason: str


class RewriteWaiver(typing.NamedTuple):
    """One rewrite-waiver ledger row: a tolerated same-cell different-owner rewrite."""

    region: str
    offset: int
    reason: str


@dataclasses.dataclass(frozen=True)
class ReportDiff:
    """Progress between two checks, keyed on (code, subjects): fixed (in prev only), new (in this report only), remaining (in both)."""

    fixed: tuple[Issue, ...]
    new: tuple[Issue, ...]
    remaining: tuple[Issue, ...]

    def to_json(self) -> dict[str, typing.Any]:
        return {
            "fixed": [i.to_json() for i in self.fixed],
            "new": [i.to_json() for i in self.new],
            "remaining": [i.to_json() for i in self.remaining],
        }


@dataclasses.dataclass(frozen=True)
class Report:
    """The check() output: errors/warnings as Issues, the pending unbound symbols, and the waiver ledger."""

    errors: list[Issue]
    warnings: list[Issue]
    pending: tuple[str, ...]
    waivers: tuple[Waiver, ...] = ()
    rewrite_waivers: tuple[RewriteWaiver, ...] = ()
    verified: tuple[str, ...] = ()  # "gname:spec_sha16:bytes_sha16" per chain hop with an attached PASS verdict (CHK-304 provenance)

    def to_json(self) -> dict[str, typing.Any]:
        def issues(items: list[Issue]) -> list[dict[str, typing.Any]]:
            return [dataclasses.asdict(i) for i in sorted(items, key=lambda i: (i.code, i.subjects))]

        return {
            "errors": issues(self.errors),
            "warnings": issues(self.warnings),
            "pending": sorted(self.pending),
            "waivers": [list(w) for w in sorted(self.waivers)],
            "rewrite_waivers": [list(w) for w in sorted(self.rewrite_waivers)],
            "verified": sorted(self.verified),
        }

    def render(self, *, verbose: bool = False) -> str:
        """The human judgment: a one-line summary, greppable ERROR/WARN lines, and pending symbols (only when any).

        Waivers are settled business -- declared intent, not outstanding issues -- so the default
        shows only their count in the summary head; verbose=True renders the ledger lines (the
        review view: every waiver with its mandatory reason).
        """

        def plural(n: int, noun: str) -> str:
            return f"{n} {noun}{'' if n == 1 else 's'}"

        head = f"check: {plural(len(self.errors), 'error')}, {plural(len(self.warnings), 'warning')}, {len(self.pending)} pending"
        ledger = len(self.waivers) + len(self.rewrite_waivers)
        if ledger:
            head += f"; {plural(ledger, 'waiver')} on the ledger"
        lines = [head]
        for label, items in (("ERROR", self.errors), ("WARN", self.warnings)):
            for i in sorted(items, key=lambda i: (i.code, i.subjects)):
                lines.append(f"{label} {i.code} [{', '.join(i.subjects)}]: {i.msg}  hint: {i.hint}")
        if self.pending:
            lines.append(f"pending symbols: {', '.join(sorted(self.pending))}")
        if verbose:
            for rname, off, reason in sorted(self.rewrite_waivers):
                lines.append(f"waived rewrite {rname}+0x{off:04x}: {reason}")
            for rname, off, name, reason in sorted(self.waivers):
                lines.append(f"waived clobber {rname}+0x{off:04x} ({name}): {reason}")
        return "\n".join(lines)

    def diff(self, prev: Report) -> ReportDiff:
        """The agent-loop progress signal: this report against a previous one, errors and warnings together, keyed on (code, subjects)."""

        def keyed(report: Report) -> dict[tuple[str, tuple[str, ...]], Issue]:
            return {(i.code, i.subjects): i for i in [*report.errors, *report.warnings]}

        mine, theirs = keyed(self), keyed(prev)
        return ReportDiff(
            fixed=tuple(theirs[k] for k in sorted(theirs.keys() - mine.keys())),
            new=tuple(mine[k] for k in sorted(mine.keys() - theirs.keys())),
            remaining=tuple(mine[k] for k in sorted(mine.keys() & theirs.keys())),
        )


# The closed CHK-code catalog: code -> (meaning, fix). Every Issue the library constructs
# uses a code from this table (test-enforced), so an agent or a script can look a refusal
# up without grepping source. Entries are summaries; the constructed Issue's own hint is
# the authoritative fix text. Existing codes keep their meaning; new checks get new codes.
class CodeInfo(typing.NamedTuple):
    """One CHK-catalog entry: what the code means and what the fix is."""

    meaning: str
    fix: str


CODES: dict[str, CodeInfo] = {
    "CHK-001": CodeInfo("placement extents overlap without a declared alias", "declare intent: region.at(..., over=(other,), why=...)"),
    "CHK-002": CodeInfo("placement or cell end exceeds the region's max_size", "grow max_size or move it; the cap is deliberate"),
    "CHK-003": CodeInfo("over= alias declared but extents do not intersect", "make the alias name the placement that actually overlaps"),
    "CHK-005": CodeInfo("computed reducer value differs from its expect= pin", "fix the expectation or the span contents"),
    "CHK-006": CodeInfo("overlapping (aliased) cells disagree on shared bytes", "aliased cells must agree byte-for-byte; check the overlay arithmetic"),
    "CHK-007": CodeInfo("reducer dependency cycle, or an unregistered reducer", "break the cycle or register the reducer"),
    "CHK-008": CodeInfo(
        "cell rewritten by a different owner (last-writer-wins)", "if intended: layout.allow_rewrite(cell, reason=...); else fix the collision"
    ),
    "CHK-009": CodeInfo("resolved value does not fit the cell width", "widen the cell, or take a slice deliberately (lo16/hi16/ha16)"),
    "CHK-010": CodeInfo(
        "dense=True view has fields unset or claimed by another owner",
        "write them (or resolve the foreign rewrite); drop dense=True if fill is deliberate",
    ),
    "CHK-011": CodeInfo(
        "resolved cell bytes contain a forbidden transport byte (region forbid=)",
        "pick a value/address/gadget the transport survives, or slice around the byte",
    ),
    "CHK-012": CodeInfo(
        "two bound regions occupy overlapping absolute address ranges", "rebase one region; sparse emission would land silently colliding writes"
    ),
    "CHK-013": CodeInfo(
        "bound symbol that no cell, region base, or expectation references", "fix the symbol name (a typo'd bind is a silent no-op) or drop the bind"
    ),
    "CHK-014": CodeInfo(
        "cell names an xform this layout never registered", "register_xform() on the layout that resolves the cell (constructors are layout-scoped)"
    ),
    "CHK-101": CodeInfo("external field span overlaps another placement", "declare over=/why= if intended (array neighbors are the common benign case)"),
    "CHK-102": CodeInfo("chain-internal overlay alias (auto-declared)", "informational; chain-owned frames may interleave"),
    "CHK-201": CodeInfo(
        "hop consumes a register nothing feeds", "seat the input (hop.<reg> = value) or fix the upstream transfer; entry inputs go via enter()"
    ),
    "CHK-202": CodeInfo("a hop's need is fed by an unset cell", "seat a value or declare the supplying effect (error once the chain is finished)"),
    "CHK-203": CodeInfo("expect() provenance mismatch: register not fed by the pinned writeback", "check the effect attachment and the overlay arithmetic"),
    "CHK-204": CodeInfo("cell is a target writeback but also user-staged or seated", "leave writeback cells UNSET; the runtime writes them"),
    "CHK-205": CodeInfo("windowed effect may clobber a live cell", "move the cell, or layout.allow_clobber(cell, effect, reason=...)"),
    "CHK-206": CodeInfo("dangling continuation: the last hop's PC-source was never wired", "call finish()/finish_in_kernel(pc=...); final gates refuse on it"),
    "CHK-207": CodeInfo(
        "call-entry stack alignment violated (SP % abi.sp_align != the gadget's entry_sp_mod)",
        "insert a ret-align gadget before the hop; the movaps-in-system crash, refused at build time",
    ),
    "CHK-208": CodeInfo(
        "frame field width contradicts the chain abi's word",
        "declare the intended width (width=cento.u32/u64) or drop abi= if the mismatch is deliberate",
    ),
    "CHK-301": CodeInfo("gadget entry address drifts from the catalog", "the catalog is authoritative; update the inline gadget"),
    "CHK-302": CodeInfo(
        "gadget spec drift vs the catalog (geometry, widths, stride, frame_base, reentry_safe, needs, entry_sp_mod, sp_pivot)",
        "update the inline gadget to match the catalog",
    ),
    "CHK-303": CodeInfo("gadget not in the catalog (unverified)", "add it to the catalog, or load it FROM the catalog"),
    "CHK-304": CodeInfo("chain hop's gadget has no PASS verification verdict", "run verify_transfer (needs [verify]) and layout.attach_verdicts(...)"),
}


def _intersects(a0: int, a1: int, b0: int, b1: int) -> bool:
    return a0 < b1 and b0 < a1


class _AbsSpan(typing.NamedTuple):
    """One bound region's absolute footprint, for the CHK-012 overlap sweep."""

    start: int
    end: int
    region: str


def run_checks(layout: cento.regions.Layout) -> Report:
    errs: list[Issue] = []
    warns: list[Issue] = []
    pending: set[str] = set()
    auto_aliased: set[tuple[str, str]] = set()  # CHK-102 pairs already emitted (dedupe across the extent and ext-span arms)

    def _chain_auto_alias(a: cento.regions.PlacementRec, b: cento.regions.PlacementRec) -> bool:
        """Same-chain placement pairs auto-declare their overlaps -- one informational CHK-102 row per pair, never an error."""
        if a.chain is None or a.chain != b.chain:
            return False
        pair = (a.path, b.path) if a.path <= b.path else (b.path, a.path)
        if pair not in auto_aliased:
            auto_aliased.add(pair)
            warns.append(
                Issue("CHK-102", pair, "chain-internal overlay alias (auto-declared)", "chain-owned placements may interleave; declared automatically")
            )
        return True

    for reg in layout.regions.values():
        pls = reg.placements
        # CHK-001 / CHK-003: pairwise extents vs declared aliases
        for i, a in enumerate(pls):
            for b in pls[i + 1 :]:
                inter = _intersects(a.offset, a.offset + a.extent, b.offset, b.offset + b.extent)
                declared = a.name in b.over or b.name in a.over
                if inter and not declared and not _chain_auto_alias(a, b):
                    errs.append(
                        Issue(
                            "CHK-001",
                            (a.path, b.path),
                            "placement extents overlap without a declared alias",
                            "declare intent: region.at(..., over=(other,), why=...)",
                        )
                    )
                ext_inter = any(_intersects(s0, s1, b.offset, b.offset + b.extent) for (s0, s1) in a.ext_spans()) or any(
                    _intersects(s0, s1, a.offset, a.offset + a.extent) for (s0, s1) in b.ext_spans()
                )
                if declared and not (inter or ext_inter):
                    errs.append(
                        Issue(
                            "CHK-003",
                            (a.path, b.path),
                            "over= alias declared but extents do not intersect",
                            "alias must name the placement it actually overlaps",
                        )
                    )
        # CHK-002: caps
        if reg.max_size is not None:
            for p in pls:  # unreachable via at()/alloc() since they refuse at declaration; kept as defense in depth
                if p.offset + p.extent > reg.max_size:
                    errs.append(
                        Issue(
                            "CHK-002",
                            (p.path,),
                            f"placement end {p.offset + p.extent:#x} exceeds max_size {reg.max_size:#x}",
                            "grow max_size or move the placement; max_size is a deliberate cap",
                        )
                    )
            for (rname, off), entry in sorted(layout.cells().items()):  # a cells() copy per capped region: regions are few, cmap does not exist yet here
                if rname == reg.name and off + entry.width > reg.max_size:
                    errs.append(
                        Issue(
                            "CHK-002",
                            (entry.owner,),
                            f"cell end {off + entry.width:#x} exceeds max_size {reg.max_size:#x}",
                            "grow max_size or move the cell",
                        )
                    )
        # CHK-101: external field spans vs other placements
        for p in pls:
            for s0, s1 in p.ext_spans():
                for q in pls:
                    if q is p or p.name in q.over or q.name in p.over:
                        continue
                    if _intersects(s0, s1, q.offset, q.offset + q.extent) and not _chain_auto_alias(p, q):
                        warns.append(
                            Issue(
                                "CHK-101",
                                (p.path, q.path),
                                f"external field span [{s0:#x},{s1:#x}) overlaps placement",
                                "declare over=/why= if intended (array neighbors are the common benign case)",
                            )
                        )

    cmap = layout.cells()  # snapshot once (cells() copies; never call it in a loop)

    # CHK-012: bound region bases whose absolute extents overlap -- SPARSE emission would land
    # silently colliding writes (last write wins at the thrower). Judged only once bases bind;
    # extent is the declared cap when there is one, else the content extent (placements + cells).
    spans: list[_AbsSpan] = []
    for rname in sorted(layout.regions):
        sreg = layout.regions[rname]
        rbase = layout.env.get(sreg.base_sym)
        if rbase is None:
            continue
        ends = [p.offset + p.extent for p in sreg.placements] + [off + e.width for (rn, off), e in cmap.items() if rn == rname]
        extent = sreg.max_size if sreg.max_size is not None else max(ends, default=0)
        if extent > 0:
            spans.append(_AbsSpan(rbase, rbase + extent, rname))
    spans.sort()
    if spans:
        cover_end, cover_name = spans[0].end, spans[0].region
        for span in spans[1:]:
            if span.start < cover_end:
                errs.append(
                    Issue(
                        "CHK-012",
                        (cover_name, span.region),
                        f"regions {cover_name!r} and {span.region!r} occupy overlapping absolute ranges (both cover 0x{span.start:x})",
                        "rebase one region, or make the shared bytes one region with declared aliases (over=/why=)",
                    )
                )
            if span.end > cover_end:
                cover_end, cover_name = span.end, span.region

    # CHK-010: dense views promise every field is written BY THIS VIEW; owner-keyed, so an
    # aliased placement's bytes at the same offsets do not silently satisfy the promise
    def _owned(p: cento.regions.PlacementRec, key: tuple[str, int]) -> bool:
        entry = cmap.get(key)
        return entry is not None and (entry.owner.startswith(p.path + ".") or entry.owner.startswith(p.path + "["))

    for region in layout.regions.values():
        for p in region.placements:
            for base, vt in p._elems():
                if not vt.__dense__:
                    continue
                unset = [fname for fname, f in vt.__fields__.items() if not f.external and not _owned(p, (region.name, base + f.offset))]
                if unset:
                    errs.append(
                        Issue(
                            "CHK-010",
                            (p.path,),
                            f"dense view fields unset or claimed by another owner: {', '.join(unset)}",
                            "write them (or resolve the foreign rewrite); drop dense=True if fill is deliberate",
                        )
                    )
    res = layout.resolution()
    pending |= res.pending()

    # CHK-013: a bound symbol nothing references is a silent no-op (the classic typo'd bind).
    # Base symbols and expect_sym declarations count as references: binding those early is the idiom.
    referenced: set[str] = set()
    for dep_syms in res.deps.values():
        referenced |= dep_syms
    referenced |= {r.base_sym for r in layout.regions.values()}
    referenced |= set(layout._sym_expectations)
    for sym in sorted(set(layout.env.bindings()) - referenced):
        close = difflib.get_close_matches(sym, sorted(referenced), n=1)
        warns.append(
            Issue(
                "CHK-013",
                (sym,),
                f"bound symbol {sym!r} is referenced by nothing (no cell, region base, or expectation)",
                (f"did you mean {close[0]!r}? " if close else "") + "a bind nothing reads is a no-op: fix the name or drop the bind",
            )
        )
    forced = res.resolved  # read-only: the snapshot's bytes bucket feeds the byte-level judgments (CHK-005/CHK-006/CHK-011)

    # CHK-011: transport constraint -- a region's declared forbidden byte set vs every resolved
    # cell's bytes. Residual cells are judged when they resolve (the final gate blocks on pending
    # anyway); promised (Writeback) cells are runtime-written and not ours to judge; the fill was
    # validated at region declaration.
    for key in sorted(forced):
        forbid = layout.regions[key[0]].forbid
        if not forbid:
            continue
        hits = sorted(set(forced[key]) & set(forbid))
        if hits:
            errs.append(
                Issue(
                    "CHK-011",
                    (cmap[key].owner,),
                    f"cell bytes contain forbidden transport byte(s) {', '.join(f'0x{b:02x}' for b in hits)}",
                    "the transport will not carry these bytes: pick a different value/address/gadget, or slice around them",
                )
            )
    for key in sorted(res.errors):  # promised (Writeback) cells never error and never carry build-time bytes; the buckets skip them
        exc = res.errors[key]
        if isinstance(exc, cento.errors.WidthError):
            errs.append(Issue("CHK-009", (cmap[key].owner,), str(exc), "widen the cell, or take a slice deliberately (lo16/hi16/ha16)"))
        elif isinstance(exc, cento.errors.XformError):
            errs.append(
                Issue("CHK-014", (cmap[key].owner,), str(exc), "register_xform() on the layout that resolves the cell (constructors are layout-scoped)")
            )
        else:
            errs.append(Issue("CHK-007", (cmap[key].owner,), str(exc), "break the cycle or register the reducer"))
    for key in sorted(forced):
        entry = cmap[key]
        r = forced[key]
        value = entry.value
        if isinstance(value, cento.cells.Reduce) and value.expect is not None:
            actual = int.from_bytes(r, layout.endian)
            if actual != value.expect % (1 << (8 * entry.width)):
                errs.append(
                    Issue("CHK-005", (entry.owner,), f"reduce {value.fn} = {actual:#x}, expected {value.expect:#x}", "fix the expectation or the span contents")
                )
    # Overlap sweep over resolved cells sorted by (region, offset): every kb starts at or after ka,
    # so the inner scan stops at the first kb past ka's end -- each overlapping pair is visited once,
    # and the slice below compares only the shared window [ov0, ov1).
    keys = sorted(forced)
    for i, ka in enumerate(keys):
        ra, wa = ka[0], cmap[ka].width
        for kb in keys[i + 1 :]:
            if kb[0] != ra or kb[1] >= ka[1] + wa:
                break
            ov0, ov1 = kb[1], min(ka[1] + wa, kb[1] + cmap[kb].width)
            if forced[ka][ov0 - ka[1] : ov1 - ka[1]] != forced[kb][0 : ov1 - ov0]:
                errs.append(
                    Issue(
                        "CHK-006",
                        (cmap[ka].owner, cmap[kb].owner),
                        f"overlapping cells disagree on bytes [{ov0:#x},{ov1:#x})",
                        "aliased cells must agree byte-for-byte; check the overlay arithmetic",
                    )
                )

    # CHK-008: same-key different-owner rewrites (last-writer-wins is silent at construction; judged here)
    rewrite_waived = {key for (key, _reason) in layout.rewrite_waivers}
    for key, old_owner, new_owner in layout.rewrites:
        if key in rewrite_waived:
            continue
        errs.append(
            Issue(
                "CHK-008",
                (old_owner, new_owner),
                "cell rewritten by a different owner (last-writer-wins)",
                "if intended: layout.allow_rewrite(cell, reason=...); else fix the collision",
            )
        )

    derived_waivers: list[Waiver] = []
    for chain in layout.chains.values():
        c_errs, c_warns = chain.issues()
        errs.extend(c_errs)
        warns.extend(c_warns)
        # Discard-as-waiver: fold-derived clobber waivers (Writeback.discard) surface next to allow_clobber entries.
        # the registry may hold issues()-only test doubles; the callable guard tolerates them
        fold = getattr(chain, "fold", None)
        if callable(fold):
            derived_waivers.extend(Waiver(k[0], k[1], eff, why) for (k, eff, why) in fold().derived_waivers)

    # CHK-304: verdict provenance (opt-in -- judged only when verdicts are attached)
    verified: list[str] = []
    if layout.verdicts:
        for cname in sorted(layout.chains):
            for hop in getattr(layout.chains[cname], "hops", ()):  # test doubles without hops have nothing to verify
                sha = cento.gadget.spec_sha16(hop.gadget)
                v = layout.verdicts.get(sha)
                if v is None or not v.ok:
                    warns.append(
                        Issue(
                            "CHK-304",
                            (cname, hop.name, hop.gadget.gname),
                            "gadget transfer spec has no PASS verdict (unverified)",
                            "run verify_transfer (or a verdict-artifact producer) and attach_verdicts()",
                        )
                    )
                else:
                    verified.append(f"{hop.gadget.gname}:{sha}:{v.bytes_sha16}")

    waivers = tuple(sorted([Waiver(r, o, e, why) for ((r, o), e, why) in layout.clobber_waivers] + derived_waivers))
    rewrite_waivers = tuple(sorted(RewriteWaiver(r, o, why) for ((r, o), why) in layout.rewrite_waivers))

    return Report(
        errors=errs,
        warnings=warns,
        pending=tuple(sorted(pending)),
        waivers=waivers,
        rewrite_waivers=rewrite_waivers,
        verified=tuple(verified),
    )
