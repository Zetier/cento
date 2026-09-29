# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Emission: delivery metadata, the SPARSE/IMAGE/HEXDUMP backends, fixups, and the final gate."""

from __future__ import annotations

import dataclasses
import enum
import os
import re
import sys
import typing

import cento.cells
import cento.errors

if typing.TYPE_CHECKING:
    import cento.checks
    import cento.regions


class Deliver(enum.Enum):
    """Delivery ordering class for a cell: NORMAL < LATE < ARM. The SPARSE backend's ordered
    list and DeliveryPlan honor it (IMAGE/HEXDUMP only tag).

    LATE: written after every NORMAL cell; for cells that must not go live early (canonical
    case: a vptr whose object is still being written). ARM (the arming write -- no relation
    to the ISA): the trigger, withheld by DeliveryPlan until finalize(). The three-phase
    sequence is fixed, and the values are rank only -- a plain Enum on purpose (no IntEnum:
    nothing consumes the ints but the phase sort, and int interop would let a bare number
    pass where a phase belongs). A new phase would be gate semantics, not a number.
    """

    NORMAL = 0
    LATE = 1
    ARM = 2


class Backend(enum.Enum):
    SPARSE = "sparse"
    IMAGE = "image"
    HEXDUMP = "hexdump"


# What emit() accepts: a Backend member or its lowercase string value ("image" over Backend.IMAGE);
# Literal keeps string typos a type error under mypy --strict.
BackendLike = Backend | typing.Literal["sparse", "image", "hexdump"]

# -- hexdump colors (presentation only: emit artifacts never carry escapes) ----


class _Ansi(str, enum.Enum):
    """ANSI SGR escapes for display-layer coloring. str-subclassed so members interpolate
    and concatenate as the escape itself (the __str__ override keeps f-strings honest on 3.10)."""

    RESET = "\x1b[0m"
    DIM = "\x1b[2m"
    BOLD = "\x1b[1m"
    CYAN = "\x1b[36m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    RED = "\x1b[31m"
    BRIGHT_YELLOW = "\x1b[93m"
    LIGHT_GRAY = "\x1b[37m"
    BRIGHT_BLUE = "\x1b[94m"

    __str__ = str.__str__


_PHASE_COLOR = {"LATE": str(_Ansi.YELLOW), "ARM": _Ansi.BOLD + _Ansi.RED}
_HEXDUMP_HEADER = re.compile(r"^region (\S+) \((.+)\)$")
_HEXDUMP_CELL = re.compile(r"^(  \+0x[0-9a-f]+ w(\d+) +)(\S+)  \[(\S+)\](?: (LATE|ARM))?$")
_HEXDUMP_RAW_OWNER = re.compile(r"^(.+)\+0x[0-9a-f]+$")  # anonymous raw cells (name.raw+0xNN); named fields never match
_DISASM_ADDR = re.compile(r"^(\s*)(0x[0-9a-fA-F]+)(:\s+)(.*)$")


def want_color(color: bool | None = None) -> bool:
    """Resolve a color choice: an explicit bool wins; None means auto (stdout is a TTY and NO_COLOR is unset)."""
    if color is not None:
        return color
    return "NO_COLOR" not in os.environ and sys.stdout.isatty()


def colorize_disasm(line: str, *, color: bool | None = None) -> str:
    """Ropper-style coloring for a catalog line ("0xADDR: mnem args; mnem args; ...").

    Cyan address, light-yellow mnemonics, light-gray operands, light-blue separators -- the
    palette `ropper --search` prints. color=None auto-detects (stdout TTY, NO_COLOR honored);
    plain lines pass through untouched.
    """
    if not want_color(color):
        return line
    indent, addr, sep = "", "", ""
    body = line
    matched = _DISASM_ADDR.match(line)
    if matched:
        indent, raw_addr, sep, body = matched.groups()
        addr = f"{_Ansi.CYAN}{raw_addr}{_Ansi.RESET}"

    def _instruction(one: str) -> str:
        mnem, _, operands = one.partition(" ")
        colored_mnem = f"{_Ansi.BRIGHT_YELLOW}{mnem}{_Ansi.RESET}"
        return f"{colored_mnem} {_Ansi.LIGHT_GRAY}{operands}{_Ansi.RESET}" if operands else colored_mnem

    colored = f"{_Ansi.BRIGHT_BLUE}; {_Ansi.RESET}".join(_instruction(i) for i in body.split("; "))
    return f"{indent}{addr}{sep}{colored}"


class _RunKey(typing.NamedTuple):
    """Identity of a summarizable hexdump run: consecutive cells sharing one key collapse into a `*` row."""

    kind: typing.Literal["cyclic", "byte"]  # cyclic: pristine pad words (by provenance); byte: one repeated byte (by rendered data)
    region: str
    family: str  # the raw-cell owner prefix (name.raw) -- the summary row's [family+*] label
    width: int
    byte: str | None = None  # the repeated byte's two hex chars ("byte" runs only)


def summarize_hexdump(text: str, layout: cento.regions.Layout, *, threshold: int = 5) -> str:
    """Summarize long runs of noise cells for display, keeping each run's first and last rows.

    Two kinds of run qualify, both reconstructible from their summary: cycle-pad words and
    repeated-byte fillers (0x00/0xff and friends, read off the rendered data). Cycle-pad runs
    are known by provenance -- Region.pad tracks its pristine cells, and any overwrite ends
    membership, so a patched word always stays visible. Named fields, deliver-tagged cells,
    and unresolved cells never summarize; runs shorter than `threshold` stay verbatim.
    Presentation only -- artifacts stay full.
    """
    lines = text.splitlines()
    offs: list[int] = []
    keys: list[_RunKey | None] = []
    current: cento.regions.Region | None = None
    for line in lines:
        header = _HEXDUMP_HEADER.match(line)
        if header:
            current = layout.regions.get(header.group(1))
        key: _RunKey | None = None
        off = -1
        cell = _HEXDUMP_CELL.match(line)
        if cell and cell.group(5) is None and current is not None:
            head, width, shown, owner = cell.group(1), int(cell.group(2)), cell.group(3), cell.group(4)
            family = _HEXDUMP_RAW_OWNER.match(owner)
            if family and "?" not in shown:
                off = int(head.strip().split()[0][1:], 16)
                if off in current._cyclic_cells:
                    key = _RunKey("cyclic", current.name, family.group(1), width)
                elif len({shown[k : k + 2] for k in range(0, len(shown), 2)}) == 1:
                    key = _RunKey("byte", current.name, family.group(1), width, shown[:2])
        offs.append(off)
        keys.append(key)

    out: list[str] = []
    i = 0
    while i < len(lines):
        key = keys[i]
        if key is None:
            out.append(lines[i])
            i += 1
            continue
        width = key.width
        j = i + 1
        while j < len(lines) and keys[j] == key and offs[j] == offs[j - 1] + width:  # same kind, contiguous cells
            j += 1
        run = j - i
        if run >= threshold:
            count = run - 2  # the first and last rows stay: a patch at a run's edge is always visible
            unit = "words" if width == 4 else f"w{width} cells"
            desc = f"{count} cyclic pad {unit}" if key.kind == "cyclic" else f"{count} {unit} of 0x{key.byte}"
            out.append(lines[i])
            out.append(f"  * +0x{offs[i + 1]:04x}..+0x{offs[j - 2]:04x}: {desc}  [{key.family}+*]")
            out.append(lines[j - 1])
        else:
            out.extend(lines[i:j])
        i = j
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def colorize_hexdump(text: str) -> str:
    """ANSI-color a HEXDUMP artifact for terminal display: green resolved bytes, yellow placeholders, phase-colored deliver tags.

    Structure (offsets, widths, headers) stays uncolored on purpose -- the data is the signal.
    """
    out: list[str] = []
    for line in text.splitlines():
        cell = _HEXDUMP_CELL.match(line)
        if cell:
            head, _width, shown, owner, phase = cell.groups()
            data = f"{_Ansi.YELLOW}{shown}{_Ansi.RESET}" if "?" in shown else f"{_Ansi.GREEN}{shown}{_Ansi.RESET}"
            tail = f" {_PHASE_COLOR[phase]}{phase}{_Ansi.RESET}" if phase else ""
            out.append(f"{head}{data}  {_Ansi.CYAN}[{owner}]{_Ansi.RESET}{tail}")
            continue
        header = _HEXDUMP_HEADER.match(line)
        if header:
            name, meta = header.groups()
            out.append(f"region {_Ansi.BOLD}{_Ansi.CYAN}{name}{_Ansi.RESET} ({meta})")
            continue
        if line.startswith("  * "):  # a summarize_hexdump summary row: quiet by design
            out.append(f"{_Ansi.DIM}{line}{_Ansi.RESET}")
            continue
        out.append(line)
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


class OrderedWrite(typing.NamedTuple):
    """One SPARSE-backend write for a thrower to land, ordered by (phase, address)."""

    addr: int
    data: bytes
    deliver: Deliver


@dataclasses.dataclass(frozen=True)
class Fixup:
    """A cell that could not be emitted yet: deliver these after binding `missing`.

    `owner` is the writing placement's path (e.g. "stack.smash.rbp"): the report names the
    waiting cell in the payload's own vocabulary, not just by raw offset.
    """

    region: str
    offset: int
    width: int
    owner: str
    missing: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class EmitResult:
    """One backend run: .artifact (bytes/text per backend) + .fixups naming every cell that awaits a symbol."""

    backend: Backend
    artifact: typing.Any  # per-backend shape (IMAGE: dict[str, bytes]; SPARSE: dict[int, bytes]; HEXDUMP: str) -- a union would force casts on every consumer
    ordered: list[OrderedWrite]  # SPARSE only (empty for other backends)
    fixups: list[Fixup]
    pending: tuple[str, ...]


def refuse_dangling(layout: cento.regions.Layout, verb: str, report: cento.checks.Report | None = None) -> None:
    """The one dangling-continuation refusal, shared by every final gate (emit final, plan finalize).

    The CHK-206 warning becomes a refusal here: no gate ships a fill-valued jump. The optional
    report rides the refusal as EmitError.report.
    """
    for cname, ch in sorted(layout.chains.items()):
        dangling = getattr(ch, "dangling", None)  # tolerant: the registry may hold issues()-only test doubles without dangling()
        pc = dangling() if callable(dangling) else None
        if pc is not None:
            raise cento.errors.EmitError(
                f"{verb} refused: chain {cname!r} has a dangling continuation ({pc.path} is unset) -- call finish()/finish_in_kernel() first",
                report=report,
            )


class Req(enum.Flag):
    """What a final gate requires of the layout.

    The requirement sets nest by construction (STAGE < FINALIZE < FINAL_EMIT), and a shared
    requirement is one flag, so two gates cannot diverge on it -- divergence is
    unrepresentable, not just untested. FINALIZE omits NO_PENDING deliberately:
    plan.finalize() runs its own unresolved-symbol refusal, which also names unbound
    region base symbols (see DeliveryPlan.finalize).
    """

    CHECK_CLEAN = enum.auto()
    NO_DANGLING = enum.auto()
    NO_PENDING = enum.auto()
    STAGE = CHECK_CLEAN
    FINALIZE = CHECK_CLEAN | NO_DANGLING
    FINAL_EMIT = CHECK_CLEAN | NO_DANGLING | NO_PENDING


def gate(layout: cento.regions.Layout, require: Req, verb: str) -> cento.checks.Report:
    """The one refusal gate: check errors, dangling continuations, pending symbols -- per `require`.

    Every refusal is verb-prefixed ("final emit refused: ...") so the operator sees which
    gate spoke. Returns the Report so callers reuse the judgment without re-checking.
    """
    report = layout.check()
    if Req.CHECK_CLEAN in require and report.errors:
        raise cento.errors.EmitError(f"{verb} refused: check errors:\n" + report.render(), report=report)
    if Req.NO_DANGLING in require:
        refuse_dangling(layout, verb, report)
    if Req.NO_PENDING in require and report.pending:
        raise cento.errors.EmitError(f"{verb} refused: layout-wide pending symbols {sorted(report.pending)}", report=report)
    return report


class DanglingChain(typing.NamedTuple):
    """A chain the final gates refuse on: its name and the unset PC-source cell's path."""

    chain: str
    cell: str


@dataclasses.dataclass(frozen=True)
class Preflight:
    """Shippability as data: what the final gate (gate(Req.FINAL_EMIT)) would refuse on, without raising.

    shippable is True exactly when that gate would pass. report is the full check() output;
    dangling names each unfinished chain with its unset continuation cell; pending is the
    unbound cell-symbol worklist; fixups is the same worklist at cell grain -- each waiting
    cell with its owner path and missing symbols, without running a backend. Region base
    symbols are not modeled here: a final sparse emit can additionally refuse on an
    unbound base symbol.
    """

    shippable: bool
    report: cento.checks.Report
    dangling: tuple[DanglingChain, ...]
    pending: tuple[str, ...]
    fixups: tuple[Fixup, ...]

    def to_json(self) -> dict[str, typing.Any]:
        return {
            "shippable": self.shippable,
            "report": self.report.to_json(),
            "dangling": [list(pair) for pair in self.dangling],
            "pending": sorted(self.pending),
            "fixups": [{"region": f.region, "offset": f.offset, "width": f.width, "owner": f.owner, "missing": sorted(f.missing)} for f in self.fixups],
        }


def preflight(layout: cento.regions.Layout) -> Preflight:
    """Build the Preflight for a layout (see Preflight for the exact contract)."""
    report = layout.check()
    dangling: list[DanglingChain] = []
    for cname, ch in sorted(layout.chains.items()):
        probe = getattr(ch, "dangling", None)  # tolerant: the registry may hold issues()-only test doubles
        pc = probe() if callable(probe) else None
        if pc is not None:
            dangling.append(DanglingChain(cname, pc.path))
    res = layout.resolution()
    cells = layout.cells()
    fixups = tuple(
        Fixup(rname, off, cells[(rname, off)].width, cells[(rname, off)].owner, tuple(sorted(residual.missing)))
        for (rname, off), residual in sorted(res.residual.items())
    )
    return Preflight(
        shippable=not report.errors and not dangling and not report.pending,
        report=report,
        dangling=tuple(dangling),
        pending=tuple(sorted(report.pending)),
        fixups=fixups,
    )


def run_emit(layout: cento.regions.Layout, backend: BackendLike, *, final: bool = True) -> EmitResult:
    """Backend dispatch behind Layout.emit: gates when final (the default; final=False is the draft read),
    raises any cell's own recorded error before rendering, and reports holes as fixups."""
    if isinstance(backend, str):
        try:
            backend = Backend(backend)
        except ValueError:
            known = ", ".join(repr(b.value) for b in Backend)
            raise cento.errors.EmitError(f"unknown backend {backend!r}; one of: {known}") from None
    report = gate(layout, Req.FINAL_EMIT, "final emit") if final else None
    res = layout.resolution()
    for key in sorted(res.errors):
        raise res.errors[key]  # a cell's own refusal (WidthError, reduce cycle) blocks every backend, final or not
    fixups: list[Fixup] = []
    pending: set[str] = set()
    # Writeback-valued (promised) cells are runtime-written: excluded from emission entirely (not emitted, not fixups, not pending)
    sel = [(k, e) for k, e in sorted(layout.cells().items()) if k not in res.promised]

    def lookup(key: tuple[str, int], width: int, owner: str) -> bytes | None:
        data = res.resolved.get(key)
        if data is None:
            r = res.residual[key]  # errors raised above; promised filtered from sel: residual is the only other bucket
            fixups.append(Fixup(key[0], key[1], width, owner, tuple(sorted(r.missing))))
            pending.update(r.missing)
        return data

    artifact: typing.Any
    ordered: list[OrderedWrite] = []

    if backend is Backend.SPARSE:
        sparse: dict[int, bytes] = {}
        for (rname, off), entry in sel:
            base = layout.env.get(layout.regions[rname].base_sym)
            if base is None:
                pending.add(layout.regions[rname].base_sym)
            data = lookup((rname, off), entry.width, entry.owner)
            if data is None:
                continue
            if base is None:
                fixups.append(Fixup(rname, off, entry.width, entry.owner, (layout.regions[rname].base_sym,)))
                continue
            sparse[base + off] = data
            ordered.append(OrderedWrite(base + off, data, entry.deliver))
        ordered.sort(key=lambda w: (w.deliver.value, w.addr))
        artifact = dict(sorted(sparse.items()))
    elif backend is Backend.IMAGE:
        images: dict[str, bytes] = {}
        for rname in sorted({k[0] for k, _ in sel}):
            reg = layout.regions[rname]
            ends = [off + e.width for (rn, off), e in sel if rn == rname]
            ends += [p.offset + p.extent for p in reg.placements]
            size = reg.max_size if reg.max_size is not None else (max(ends) if ends else 0)
            # the ONE composer paints this region (holes = fill; cells past the cap never relocate -- CHK-002 names the overrun at check time)
            composed = layout._compose(rname, 0, size, res=res, partial=True)
            assert isinstance(composed, bytes)  # partial=True never returns Residual
            images[rname] = composed
            for (rn, off), entry in sel:
                if rn == rname:
                    lookup((rn, off), entry.width, entry.owner)  # record the holes: fixups + pending, in cell order
        artifact = images
    elif backend is Backend.HEXDUMP:
        lines: list[str] = []
        for rname in sorted({k[0] for k, _ in sel}):
            reg = layout.regions[rname]
            lines.append(f"region {rname} (base={reg.base_sym}, fill=0x{reg.fill.hex()})")
            col = max([entry.width * 2 for (rn, _), entry in sel if rn == rname] + [8])  # align to the widest cell (>= the classic 8)
            for (rn, off), entry in sel:
                if rn != rname:
                    continue
                data = lookup((rn, off), entry.width, entry.owner)
                shown = data.hex() if data is not None else "?" * (entry.width * 2)
                tag = "" if entry.deliver is Deliver.NORMAL else f" {entry.deliver.name}"  # only non-default phases are worth a tag
                lines.append(f"  +0x{off:04x} w{entry.width} {shown:>{col}}  [{entry.owner}]{tag}")
        artifact = "\n".join(lines) + "\n"
    else:  # pragma: no cover - enum is closed
        raise cento.errors.EmitError(f"unknown backend {backend!r}")

    if final and (fixups or pending):
        missing = sorted(pending)
        raise cento.errors.EmitError(f"final emit refused: unresolved symbols {missing}", report=report)
    return EmitResult(
        backend=backend,
        artifact=artifact,
        ordered=ordered,
        fixups=fixups,
        pending=tuple(sorted(pending)),
    )
