# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Layout + Region: named byte regions of lazily-valued cells."""

from __future__ import annotations

import dataclasses
import difflib
import itertools
import re
import typing

import cento.abi
import cento.cells
import cento.chain
import cento.checks
import cento.emit
import cento.errors
import cento.gadget
import cento.machine
import cento.plan
import cento.views

if typing.TYPE_CHECKING:
    import cento.catalog

CellKey = tuple[str, int]

CellValue = int | cento.cells.Ref | cento.cells.Delta | cento.cells.Reduce | cento.cells.Writeback


class _Bounds(typing.NamedTuple):
    """An inclusive plausibility range for a symbol's value (see Layout.expect_sym)."""

    lo: int
    hi: int


class _SymExpectation(typing.NamedTuple):
    """What a plausible bind for one symbol looks like (see Layout.expect_sym)."""

    range: _Bounds | None
    align: int | None


@dataclasses.dataclass(frozen=True)
class Resolution:
    """The result of resolving every cell against the current symbol bindings.

    Each cell lands in exactly one bucket: resolved (its bytes), residual (the symbols it
    still needs), promised (runtime-written Writeback cells, which have no build-time value),
    or errors (the cell's own WidthError/ResolveError, recorded per cell so callers can
    report every failure rather than the first). deps maps each cell to the symbols its
    value was computed from.

    Frozen, and rebuilt whole on any layout mutation or symbol bind (see Layout.resolution),
    so stale dependencies cannot survive a rewrite. Treat the mappings as read-only.
    """

    resolved: dict[CellKey, bytes]
    residual: dict[CellKey, cento.cells.Residual]
    promised: dict[CellKey, cento.cells.Promised]
    errors: dict[CellKey, cento.errors.ResolveError]
    deps: dict[CellKey, set[str]]

    def pending(self) -> set[str]:
        """Cell-value symbols still unbound anywhere in the layout -- the bind() worklist.
        Region base symbols are not tracked here; sparse emission and plan.finalize() name them."""
        out: set[str] = set()
        for r in self.residual.values():
            out |= set(r.missing)
        return out

    def dirty(self, *syms: str) -> set[CellKey]:
        """Cells whose values depend on the given symbols -- the re-delivery worklist after a rebind."""
        want = set(syms)
        return {key for key, deps in self.deps.items() if deps & want}


class _ResolutionMemo(typing.NamedTuple):
    """One cached Resolution and the (mutations, env.generation) stamp it was computed at (see Layout.resolution)."""

    stamp: tuple[int, int]
    res: Resolution


@dataclasses.dataclass
class CellEntry:
    value: CellValue
    width: int
    owner: str
    deliver: cento.emit.Deliver = cento.emit.Deliver.NORMAL


@dataclasses.dataclass(frozen=True)
class CellHandle:
    """Handle to one cell: write() stages a value, read() resolves it, and .addr is the
    cell's address as a symbolic Ref usable as another cell's value."""

    region: Region
    offset: int
    width: int
    path: str

    @property
    def addr(self) -> cento.cells.Ref:
        return cento.cells.Ref(self.region.base_sym, addend=self.offset)

    @property
    def span(self) -> cento.cells.Span:
        return cento.cells.Span(self.region.name, self.offset, self.offset + self.width)

    def write(self, value: object) -> None:
        """Write a value into this cell: int, symbol str, sym()/Ref arithmetic, a reducer, a
        Writeback, or a handle (its address). Literal ints that do not fit the cell width refuse
        here; symbolic values stay fail-closed at emit, judged at check()."""
        self.region.layout._set_cell(self.region, self.offset, value, self.width, owner=self.path)

    def read(self, *, signed: bool = False) -> int:
        """The cell's resolved value as an int (layout endianness). Fail-closed, like emit: unresolved cells raise; they never guess."""
        layout = self.region.layout
        try:
            data = layout.force((self.region.name, self.offset))
        except KeyError:
            raise cento.errors.PlacementError(f"{self.path}: no cell here (nothing was written)") from None
        if isinstance(data, cento.cells.Residual):
            raise cento.errors.ResolveError(f"{self.path}: unresolved -- awaiting {', '.join(sorted(data.missing))}")
        if isinstance(data, cento.cells.Promised):
            raise cento.errors.ResolveError(f"{self.path}: runtime-written (writeback {data.name!r}); it has no build-time value")
        return int.from_bytes(data, layout.endian, signed=signed)


def _validate_scalar(path: str, width: type[cento.views.Width], value: object) -> None:
    """Fail closed on literal writes: an int that does not fit its declared width is a typo, not a wrap.

    Only width-declared fields validate. Computed cells (Reduce/Delta) keep wrapping -- overflow is
    semantic there -- and raw region.cell() writes carry no declared signedness, so they keep the
    documented modulo behavior. Non-int values (symbols, Refs, handles) coerce elsewhere.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return
    bits = 8 * width.size
    lo, hi = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if width.signed else (0, (1 << bits) - 1)
    if not lo <= value <= hi:
        raise cento.errors.PlacementError(f"{path}: {value:#x} does not fit {width.__name__} [{lo:#x} .. {hi:#x}]")


@dataclasses.dataclass(frozen=True)
class FieldArrayHandle(CellHandle):
    """Handle for a Field(u32 * N) array field: len()/index to element CellHandles; handle[i] = v writes one, .write([...]) writes all.

    A CellHandle subclass (width = the whole extent), so addr/span and every CellHandle consumer
    work on the whole array; `assert isinstance(h.regs, FieldArrayHandle)` narrows for indexing.
    """

    spec: cento.views.WidthArray = dataclasses.field(kw_only=True)

    def __len__(self) -> int:
        return self.spec.count

    def __getitem__(self, index: int) -> CellHandle:
        if not 0 <= index < self.spec.count:
            raise IndexError(f"{self.path}[{index}]: array has {self.spec.count} elements")
        return CellHandle(region=self.region, offset=self.offset + index * self.spec.elem.size, width=self.spec.elem.size, path=f"{self.path}[{index}]")

    def __setitem__(self, index: int, value: object) -> None:
        cell = self[index]
        _validate_scalar(cell.path, self.spec.elem, value)
        cell.write(value)

    def read(self, *, signed: bool = False) -> int:
        raise cento.errors.PlacementError(f"{self.path}: the array is {self.spec.count} cells, not one; read an element ({self.path}[i].read())")

    def write(self, value: object) -> None:
        """Write the whole array from a list/tuple of exactly `count` values (each range-checked).

        u8-element arrays also take `bytes` of exactly `count` -- the per-byte-attributed sibling of
        a Bytes(count) field (which stores the same string as one cell).
        """
        if isinstance(value, (bytes, bytearray)):
            if self.spec.elem.size != 1 or self.spec.elem.signed:
                raise cento.errors.PlacementError(
                    f"{self.path}: bytes writes need a u8-element array; this is {self.spec.elem.__name__} * {self.spec.count} (assign a list)"
                )
            value = list(value)
        if not isinstance(value, (list, tuple)):
            raise cento.errors.PlacementError(f"{self.path}: assign a list/tuple of {self.spec.count} values (or index one: handle[i] = value)")
        if len(value) != self.spec.count:
            raise cento.errors.PlacementError(f"{self.path}: {len(value)} values for {self.spec.count} elements (exact count required)")
        for index, item in enumerate(value):
            self[index] = item


def _coerce(value: object) -> CellValue:
    if isinstance(value, bool):  # bool subclasses int: must be rejected before the int arm
        raise cento.errors.PlacementError("bool is not a cell value; use int 0/1")
    if isinstance(value, (int, cento.cells.Ref, cento.cells.Delta, cento.cells.Reduce, cento.cells.Writeback)):
        return value
    if isinstance(value, str):
        return cento.cells.Ref(value)
    addr = getattr(value, "addr", None)
    if isinstance(addr, cento.cells.Ref):  # CellHandle / ViewHandle / ArrayHandle coerce to their address
        return addr
    raise cento.errors.PlacementError(
        f"cannot use {type(value).__name__} as a cell value; use int, symbol str, Ref/Delta arithmetic, or a handle (its address)."
        " For byte strings, declare a Bytes field: cento.Field(off, cento.Bytes(n)) -- or region.pad(len(data), unit=1, at=off, data=data)"
    )


FillLike = int | str | bytes | bytearray | typing.Sequence[int]


def _norm_forbid(forbid: FillLike, owner: str) -> bytes:
    """A transport's forbidden byte set, normalized to sorted unique bytes.

    forbid=0, forbid="\\r\\n", and forbid=b"\\x00" all work; strings are ascii; every int is one
    byte. The set semantics differ from fill: order and repetition carry no meaning.
    """
    if isinstance(forbid, bool):
        raise cento.errors.PlacementError(f"{owner}: forbid takes bytes, not bool")
    if isinstance(forbid, int):
        if not 0 <= forbid <= 0xFF:
            raise cento.errors.PlacementError(f"{owner}: forbidden byte {forbid:#x} is not a byte")
        return bytes([forbid])
    if isinstance(forbid, str):
        try:
            raw = forbid.encode("ascii")
        except UnicodeEncodeError:
            raise cento.errors.PlacementError(f"{owner}: string forbid must be ascii; pass bytes for raw values") from None
    else:
        try:
            raw = bytes(forbid)  # bytes/bytearray pass through; int sequences are range-checked by bytes()
        except (TypeError, ValueError) as exc:
            raise cento.errors.PlacementError(f"{owner}: forbid must be int/str/bytes or a sequence of byte-sized ints ({exc})") from None
    if not raw:
        raise cento.errors.PlacementError(f"{owner}: forbid needs at least one byte (omit it for no transport constraint)")
    return bytes(sorted(set(raw)))


def _norm_fill(fill: FillLike, owner: str) -> bytes:
    """Region fill, normalized to a repeating byte pattern.

    fill=0x41, fill="A", and fill=b"A" are the same one-byte fill; longer strings, bytes, or
    int sequences tile across every unwritten byte, aligned to region offset 0 (byte at offset
    o is pattern[o % len]). Strings are ascii (artifacts stay plain); every int is one byte.
    """
    if isinstance(fill, bool):
        raise cento.errors.PlacementError(f"{owner}: fill takes bytes, not bool")
    if isinstance(fill, int):
        if not 0 <= fill <= 0xFF:
            raise cento.errors.PlacementError(f"{owner}: fill {fill:#x} is not a byte")
        return bytes([fill])
    if isinstance(fill, str):
        try:
            pattern = fill.encode("ascii")
        except UnicodeEncodeError:
            raise cento.errors.PlacementError(f"{owner}: string fill must be ascii; pass bytes for raw patterns") from None
    elif isinstance(fill, (bytes, bytearray)):
        pattern = bytes(fill)
    else:
        try:
            pattern = bytes(fill)  # a sequence of ints: bytes() range-checks each element
        except (TypeError, ValueError) as exc:
            raise cento.errors.PlacementError(f"{owner}: fill pattern must be int/str/bytes or a sequence of byte-sized ints ({exc})") from None
    if not pattern:
        raise cento.errors.PlacementError(f"{owner}: fill pattern must be at least one byte")
    return pattern


class Region:
    """A named byte region of a Layout. Construct with layout.region(...) (or the module-level
    cento.region(...), which makes a fresh anonymous Layout per call, reachable as .layout)."""

    def __init__(self, layout: Layout, name: str, base_sym: str, max_size: int | None, fill: FillLike, forbid: FillLike | None = None, word: int = 4) -> None:
        if isinstance(word, bool) or not isinstance(word, int) or word <= 0:
            raise cento.errors.PlacementError(f"{name}: word must be a positive int byte count, got {word!r}")
        if max_size is not None and (isinstance(max_size, bool) or not isinstance(max_size, int) or max_size < 0):
            raise cento.errors.PlacementError(f"{name}: max_size must be a non-negative int (or None for unbounded), got {max_size!r}")
        self.layout = layout
        self.name = name
        self.base_sym = base_sym
        self.max_size = max_size
        self.word = word  # the default cell width: cell()/slice sugar ride it (callers pick it: region() defaults 4, fit() 8, a declared abi's word beats both)
        self.fill: bytes = _norm_fill(fill, name)
        self.forbid: bytes = b"" if forbid is None else _norm_forbid(forbid, name)
        clash = sorted(set(self.fill) & set(self.forbid))
        if clash:  # fail closed at declaration: the fill would paint forbidden bytes over every unwritten gap
            raise cento.errors.PlacementError(
                f"{name}: fill contains forbidden transport byte(s) {', '.join(f'0x{b:02x}' for b in clash)} -- choose a fill= the transport survives"
            )
        self.placements: list[PlacementRec] = []
        self._auto_pname = itertools.count(1)
        self._cyclic_cells: set[int] = set()  # offsets whose cells still hold pristine cycle-pad words (provenance for hexdump skip=)

    def addr(self, offset: int = 0) -> cento.cells.Ref:
        """This region's base symbol plus an offset, as a Ref -- device-relative arithmetic that survives rebinds."""
        return cento.cells.Ref(self.base_sym, addend=offset)

    def fill_at(self, start: int, length: int) -> bytes:
        """The fill pattern for [start, start+length): tiled from region offset 0, so any slice agrees with any other."""
        if len(self.fill) == 1:
            return self.fill * length
        n = len(self.fill)
        return bytes(self.fill[(start + i) % n] for i in range(length))

    def cell(self, offset: int, width: int | None = None) -> CellHandle:
        """A raw cell handle at an offset (region[a:b] = v is the slice sugar). width defaults to the region's word; named placements come from at()/alloc()."""
        if isinstance(offset, bool) or not isinstance(offset, int):
            hint = " (did you mean // ?)" if isinstance(offset, float) else ""
            raise cento.errors.PlacementError(f"{self.name}: cell offset must be an int byte offset, got {type(offset).__name__}{hint}")
        if offset < 0:
            raise cento.errors.PlacementError(f"{self.name}.raw-0x{-offset:x}: negative offset (region offsets count up from base)")
        if width is not None and (isinstance(width, bool) or not isinstance(width, int) or width <= 0):
            got = width if isinstance(width, int) and not isinstance(width, bool) else type(width).__name__
            raise cento.errors.PlacementError(f"{self.name}: cell width must be a positive int byte count, got {got}")
        w = width if width is not None else self.word
        return CellHandle(region=self, offset=offset, width=w, path=f"{self.name}.raw+0x{offset:x}")

    def pad(self, length: int, *, unit: int = 4, at: int = 0, data: bytes | None = None) -> bytes:
        """Fill [at, at+length) in one call, one raw cell per `unit` bytes; returns the bytes written.

        The default pattern is the self-locating cycle pad (cento.cells.cycle): every `unit`-byte
        window is unique, so a value read back from a crash names its own offset via cycle_find().
        That is why the default is a de Bruijn pad and not random bytes (random tells you nothing
        back). Pass data= to lay down chosen bytes instead (len(data) must equal length).
        Cells are packed with the layout's endianness, so the emitted image equals the pattern.
        """
        if unit <= 0:
            raise cento.errors.PlacementError(f"{self.name}: pad unit must be a positive byte count, got {unit}")
        if length <= 0 or length % unit:
            raise cento.errors.PlacementError(f"{self.name}: pad length 0x{length:x} must be a positive multiple of unit {unit}")
        if self.max_size is not None and at + length > self.max_size:
            raise cento.errors.PlacementError(f"{self.name}: pad of 0x{length:x} at 0x{at:x} exceeds max_size 0x{self.max_size:x}")
        blob = cento.cells.cycle(length) if data is None else data
        if len(blob) != length:
            raise cento.errors.PlacementError(f"{self.name}: pad data is 0x{len(blob):x} bytes but length says 0x{length:x}")
        for off in range(0, length, unit):
            self.cell(at + off, width=unit).write(int.from_bytes(blob[off : off + unit], self.layout.endian))
        if data is None:  # provenance for hexdump(skip=): these cells are the pristine cycle pad (any later write drops membership)
            self._cyclic_cells.update(range(at, at + length, unit))
        return blob

    @typing.overload
    def at(
        self,
        offset: int,
        spec: cento.views.ViewMeta,
        name: str | None = None,
        *,
        over: tuple[str, ...] | str = (),
        why: str | None = None,
        chain: str | None = None,
    ) -> ViewHandle: ...

    @typing.overload
    def at(
        self,
        offset: int,
        spec: cento.views.ArraySpec,
        name: str | None = None,
        *,
        over: tuple[str, ...] | str = (),
        why: str | None = None,
        chain: str | None = None,
    ) -> ArrayHandle: ...

    def at(
        self,
        offset: int,
        spec: cento.views.ViewMeta | cento.views.ArraySpec,
        name: str | None = None,
        *,
        over: tuple[str, ...] | str = (),
        why: str | None = None,
        chain: str | None = None,  # internal: set by cento.chain frame placements, never by hand
    ) -> ViewHandle | ArrayHandle:
        """Place a View (or View * N array) at an offset, as a named placement.

        The name is the placement's identity in every error, ledger row, and explain() path.
        Overlaps with other placements must be declared intent: over=<placement name(s)> with
        a mandatory why= (undeclared byte-sharing is CHK-001 at the gate). Field defaults
        (declare-and-assign) are written through the handle at placement time.
        """
        if isinstance(offset, bool) or not isinstance(offset, int):
            div_hint = " (did you mean // ?)" if isinstance(offset, float) else ""
            raise cento.errors.PlacementError(f"{self.name}: at() offset must be an int byte offset, got {type(offset).__name__}{div_hint}")
        if not isinstance(spec, (cento.views.ViewMeta, cento.views.ArraySpec)):
            raise cento.errors.PlacementError(
                f"{self.name}: at() takes a View/Gadget-frame class or an ArraySpec, got {type(spec).__name__} (arrays spell View * N)"
            )
        size = spec.extent if isinstance(spec, cento.views.ArraySpec) else spec.__size__
        if offset < 0:
            raise cento.errors.PlacementError(f"{self.name}: at({offset:#x}) is a negative offset")
        if self.max_size is not None and offset + size > self.max_size:
            raise cento.errors.PlacementError(f"{self.name}: placement of {size:#x} at {offset:#x} exceeds max_size {self.max_size:#x}")
        over_t = (over,) if isinstance(over, str) else tuple(over)
        if over_t and why is None:
            raise cento.errors.PlacementError(f"{self.name}: over= declares an intentional alias and requires why=")
        # accept the region-qualified spelling CHK errors print: strip our own prefix (over= takes the bare placement name)
        over_t = tuple(o[len(self.name) + 1 :] if o.startswith(f"{self.name}.") else o for o in over_t)
        for o in over_t:
            if not any(p.name == o for p in self.placements):
                hint = difflib.get_close_matches(o, [p.name for p in self.placements], n=1)
                extra = f"; did you mean {hint[0]!r}?" if hint else ""
                raise cento.errors.PlacementError(f"{self.name}: over={o!r} names no existing placement{extra} (over= takes the bare placement name)")
        typename = spec.viewtype.__name__ if isinstance(spec, cento.views.ArraySpec) else spec.__name__
        pname = name if name is not None else f"{typename.lower()}_{next(self._auto_pname)}"
        if any(p.name == pname for p in self.placements):
            raise cento.errors.PlacementError(f"{self.name}: placement name {pname!r} already used")
        rec = PlacementRec(name=pname, offset=offset, spec=spec, over=over_t, why=why, path=f"{self.name}.{pname}", chain=chain)
        self.placements.append(rec)
        self.layout.mutations += 1
        handle: ViewHandle | ArrayHandle
        if isinstance(spec, cento.views.ArraySpec):
            handle = ArrayHandle(self, spec, offset, rec.path)
            defaulted: list[ViewHandle] = (
                [handle[i] for i in range(spec.count)] if any(f.default is not None for f in spec.viewtype.__fields__.values()) else []
            )
        else:
            handle = ViewHandle(self, spec, offset, rec.path)
            defaulted = [handle] if any(f.default is not None for f in spec.__fields__.values()) else []
        for elem in defaulted:  # declare-and-assign: placing the view writes its field defaults (same owner paths as handle writes)
            vt = spec.viewtype if isinstance(spec, cento.views.ArraySpec) else spec
            for fname, f in vt.__fields__.items():
                if f.default is not None:
                    setattr(elem, fname, f.default)
        return handle

    @typing.overload
    def alloc(
        self, spec: cento.views.ViewMeta, name: str | None = None, *, align: int = 4, reserve_external: bool = True, chain: str | None = None
    ) -> ViewHandle: ...

    @typing.overload
    def alloc(
        self, spec: cento.views.ArraySpec, name: str | None = None, *, align: int = 4, reserve_external: bool = True, chain: str | None = None
    ) -> ArrayHandle: ...

    def alloc(
        self,
        spec: cento.views.ViewMeta | cento.views.ArraySpec,
        name: str | None = None,
        *,
        align: int = 4,
        reserve_external: bool = True,
        chain: str | None = None,  # internal: pointer-based chain frames alloc here
    ) -> ViewHandle | ArrayHandle:
        """Bump-allocate spec past every placement and written cell.

        External field spans (e.g. a frame's caller-frame LR slot) are also reserved by default,
        so auto-placement cannot land a view under a continuation slot; reserve_external=False
        skips only those external spans."""
        ends = [p.offset + p.extent for p in self.placements]
        ends += [off + e.width for (rname, off), e in self.layout.cells().items() if rname == self.name]
        if reserve_external:
            ends += [e for p in self.placements for (_s, e) in p.ext_spans()]
        start = max(ends) if ends else 0
        start = (start + align - 1) // align * align
        size = spec.extent if isinstance(spec, cento.views.ArraySpec) else spec.__size__
        if self.max_size is not None and start + size > self.max_size:
            raise cento.errors.PlacementError(f"{self.name}: alloc of {size:#x} at {start:#x} exceeds max_size {self.max_size:#x}")
        return self.at(start, spec, name, chain=chain)

    def chain(
        self,
        name: str | None = None,
        *,
        at: int,
        abi: cento.machine.AbiSpec | str | None = None,
        carry: cento.machine.Carry | None = None,
        gadget_set: cento.catalog.GadgetSet | None = None,
        arm: bool = True,
    ) -> cento.chain.Chain:
        """Start a Chain in this region: hop frames auto-place from region offset `at` (the cursor), each SP-based hop advancing it by its stride.

        abi= takes an AbiSpec or a shipped name string ("x86_64") and defaults to the layout's
        declared abi (precedence: explicit kwarg > abi fact > none); an explicit abi that
        conflicts with a layout-declared one refuses -- one target per layout. carry= defaults
        to Carry.Passthru; gadget_set= defaults to the layout's (a Target profile sets it);
        arm=True marks the chain's trigger cell Deliver.ARM so it ships last (see DeliveryPlan).
        """
        cname = name if name is not None else f"chain_{len(self.layout.chains) + 1}"
        if isinstance(at, bool) or not isinstance(at, int):
            hint = " (parse hex with int(s, 16))" if isinstance(at, str) else ""
            raise cento.errors.PlacementError(f"chain {cname!r}: at= must be an int offset, got {type(at).__name__}{hint}")
        if cname in self.layout.chains:
            raise cento.errors.PlacementError(f"chain name {cname!r} already used")
        abi_spec = cento.abi.resolve(abi) if abi is not None else None
        if abi_spec is not None and self.layout.abi is not None and abi_spec != self.layout.abi:
            if abi_spec.name == self.layout.abi.name:
                raise cento.errors.ChainError(
                    f"chain {cname!r}: abi {abi_spec.name!r} conflicts -- this layout carries a spec of the same name with different facts;"
                    " one target per layout: declare the customized spec on the Layout (Layout(abi=<your spec>)) so every chain shares it"
                )
            raise cento.errors.ChainError(
                f"chain {cname!r}: abi {abi_spec.name!r} conflicts -- this layout carries abi {self.layout.abi.name!r};"
                " one target per layout: make a second Layout for a second target"
            )
        eff_abi = abi_spec if abi_spec is not None else self.layout.abi
        eff_carry = carry if carry is not None else cento.machine.Carry.Passthru
        eff_gset = gadget_set if gadget_set is not None else self.layout.gadget_set
        c = cento.chain.Chain(self, cname, at=at, abi=eff_abi, carry=eff_carry, gadget_set=eff_gset, arm=arm)
        self.layout.chains[cname] = c
        return c

    def bind(self, sym: str, value: int, *, source: str = "manual") -> None:
        """Bind a symbol on the owning layout -- a convenience so one-region builds never touch the layout object."""
        self.layout.bind(sym, value, source=source)

    def hexdump(self, *, color: bool | None = None, skip: bool = False) -> str:
        """Layout.hexdump, from the region handle -- the same one-region convenience as bind()."""
        return self.layout.hexdump(color=color, skip=skip)

    def check(self) -> cento.checks.Report:
        """Layout.check, from the region handle -- the same one-region convenience as bind()."""
        return self.layout.check()

    def image(self, *, final: bool = True, partial: None = None) -> bytes:
        """This region's emitted bytes (the IMAGE backend, this region's slice; bytes(region) is the same call).

        Final by default: image() runs the full gate (exactly emit()) and is the shippable-bytes
        spelling for one-region builds. image(final=False) is the draft read, symbol-gated only:
        check() errors (overlaps, rewrites) do not block, but a cell here still awaiting a symbol
        raises ResolveError naming it -- and the refusal carries the fill-padded draft bytes as
        .partial, so the preview needs no second spelling. Writeback cells are runtime-written and
        never block. max_size is both the placement cap and the emitted length: unwritten tail
        bytes emit as fill. A cell's own WidthError/ResolveError raises regardless -- the draft
        tolerates unbound symbols, not broken cells.
        """
        if partial is not None:  # the retired spelling: the refusal carries the bytes now
            raise cento.errors.PlacementError(
                f"{self.name}: image(partial=) is gone -- catch ResolveError; .partial on the error carries the fill-padded bytes"
            )
        if final:
            art = self.layout.emit(cento.emit.Backend.IMAGE, final=True).artifact
            data_final = art.get(self.name)
            return bytes(data_final) if data_final is not None else self.fill_at(0, self.max_size or 0)  # no cells yet: all fill, gate already passed
        result = cento.emit.run_emit(self.layout, cento.emit.Backend.IMAGE, final=False)
        data: bytes | None = result.artifact.get(self.name)
        if data is None:  # no cells yet: all fill, out to max_size if declared
            data = self.fill_at(0, self.max_size or 0)
        missing = sorted({sym for f in result.fixups if f.region == self.name for sym in f.missing})
        if missing:
            raise cento.errors.ResolveError(
                f"{self.name}: image incomplete -- awaiting {', '.join(missing)}; .partial on this error carries the fill-padded bytes", partial=data
            )
        return data

    def __bytes__(self) -> bytes:
        """bytes(region) is image(): the final gate, refusing while anything is unresolved or wrong."""
        return self.image()

    @typing.overload
    def __getitem__(self, item: slice) -> cento.cells.Span: ...

    @typing.overload
    def __getitem__(self, item: str) -> ViewHandle | ArrayHandle: ...

    def __getitem__(self, item: slice | str) -> cento.cells.Span | ViewHandle | ArrayHandle:
        """region[a:b] is a Span -- a byte-range value for reducers, not a bytes read (resolved
        bytes come from image()/cell().read()); region["name"] is the named placement's handle."""
        if isinstance(item, slice):
            if item.step is not None:
                raise cento.errors.PlacementError("Span slices take no step")
            if item.stop is None:
                raise cento.errors.PlacementError(f"{self.name}: open-ended Span needs an explicit end")
            return cento.cells.Span(self.name, item.start if item.start is not None else 0, item.stop)
        if not isinstance(item, str):
            raise cento.errors.PlacementError(f"{self.name}: index must be a str placement name or a [start:stop] slice, got {type(item).__name__}")
        for p in self.placements:
            if p.name == item:
                if isinstance(p.spec, cento.views.ArraySpec):
                    return ArrayHandle(self, p.spec, p.offset, p.path)
                return ViewHandle(self, p.spec, p.offset, p.path)
        hint = difflib.get_close_matches(item, [p.name for p in self.placements], n=1)
        extra = f"; did you mean {hint[0]!r}?" if hint else ""
        raise KeyError(f"{self.name}: no placement named {item!r}{extra}")

    def __setitem__(self, key: int | slice, value: object) -> None:
        """Raw-cell write sugar: region[0x40] = v is cell(0x40).write(v) -- a word-sized cell (the
        region's word=, default 4), not a one-byte poke; region[a:b] = v sizes the cell from the slice."""
        if isinstance(key, slice):
            if key.step is not None:
                raise cento.errors.PlacementError("cell-assignment slices take no step")
            if key.stop is None:
                raise cento.errors.PlacementError(f"{self.name}: open-ended cell assignment needs an explicit end")
            start = key.start if key.start is not None else 0
            if key.stop - start < 1:
                raise cento.errors.PlacementError(f"{self.name}: cell assignment [{start}:{key.stop}] spans no bytes")
            self.cell(start, key.stop - start).write(value)
            return
        if isinstance(key, bool) or not isinstance(key, int):
            raise cento.errors.PlacementError(
                f"{self.name}: assignment index must be an int byte offset or a [start:stop] slice, got {type(key).__name__}"
                " (placements assign through their fields: region['name'].field = value)"
            )
        self.cell(key).write(value)


class PrimeFact(typing.NamedTuple):
    """The prime covering placement: its name and the byte's offset within it."""

    name: str
    delta: int


class CellFact(typing.NamedTuple):
    """The staged cell at this byte: rendered value spelling, width, delivery phase name."""

    value: str
    width: int
    deliver: str


class BindingFact(typing.NamedTuple):
    """The Ref symbol this cell rides: bound value and provenance once bind() lands (None before)."""

    sym: str
    value: int | None
    source: str | None


class AliasFact(typing.NamedTuple):
    """One non-prime placement covering the byte: its name and declared why (None when undeclared)."""

    name: str
    why: str | None


class FeedFact(typing.NamedTuple):
    """A chain hop whose need this cell feeds: the hop, its slot, and how the cell feeds it."""

    chain: str
    hop: str
    slot: str
    kind: typing.Literal["seat", "writeback"]


class WritebackFact(typing.NamedTuple):
    """The runtime effect that writes this cell."""

    chain: str
    effect: str
    output: str


@dataclasses.dataclass(frozen=True)
class Explanation:
    """explain() as data: placement, cell value, binding, aliases, and chain dataflow for one byte.

    explain() renders exactly this record (render()); to_json() is the tooling shape. Optional
    fields are None when the fact does not exist (unset cell, unbound base, no covering placement).
    """

    path: str
    region: str
    offset: int
    abs_addr: int | None
    prime: PrimeFact | None
    cell: CellFact | None
    binding: BindingFact | None
    aliases: tuple[AliasFact, ...]
    feeds: tuple[FeedFact, ...]
    writebacks: tuple[WritebackFact, ...]

    def to_json(self) -> dict[str, typing.Any]:
        return {
            "path": self.path,
            "region": self.region,
            "offset": self.offset,
            "abs": self.abs_addr,
            "prime": self.prime._asdict() if self.prime is not None else None,
            "cell": self.cell._asdict() if self.cell is not None else None,
            "binding": self.binding._asdict() if self.binding is not None else None,
            "aliases": [a._asdict() for a in self.aliases],
            "feeds": [f._asdict() for f in self.feeds],
            "writebacks": [w._asdict() for w in self.writebacks],
        }

    def render(self) -> str:
        """The human spelling: exactly the lines explain() has always printed."""
        header = self.path
        if self.prime is not None:
            header += f" ({self.prime.name}[+0x{self.prime.delta:X}])"
        header += f" @ {self.region}+0x{self.offset:X}"
        if self.abs_addr is not None:
            header += f" [abs 0x{self.abs_addr:X}]"
        lines = [header]
        c = self.cell
        lines.append(f"cell: {c.value} width={c.width} deliver={c.deliver}" if c is not None else "cell: (unset)")
        b = self.binding
        if b is not None:
            lines.append(f"bound: {b.sym} = {b.value:#x} (source: {b.source})" if b.value is not None else f"unbound: {b.sym} -- bind() completes this cell")
        for a in self.aliases:
            lines.append(f"aliases: {a.name}" + (f" (why: {a.why})" if a.why is not None else ""))
        for cname in sorted({f.chain for f in self.feeds} | {w.chain for w in self.writebacks}):
            lines.extend(f"feeds: hop {f.hop} needs {f.slot} ({f.kind})" for f in self.feeds if f.chain == cname)
            lines.extend(f"writeback-by: effect {w.effect} output {w.output} (chain {w.chain})" for w in self.writebacks if w.chain == cname)
        return "\n".join(lines)


@dataclasses.dataclass(frozen=True)
class Provenance:
    """Where a layout's facts came from: the profile and catalog identities a manifest joins on.

    Every field defaults None -- a hand-built layout has no provenance and says so; users may
    construct partial records (Provenance(target_name="mk4")) and assign layout.provenance.
    Target.layout() composes the full record; catalog_sha256 is the FULL content hash of the
    catalog file (paths can lie after an edit; the digest cannot).
    """

    target_name: str | None = None
    profile_path: str | None = None
    catalog_path: str | None = None
    catalog_sha256: str | None = None
    catalog_target: str | None = None
    gadget_set: str | None = None


class PlacementFact(typing.NamedTuple):
    """One placement row of the manifest: identity, geometry, and declared intent."""

    name: str
    path: str
    offset: int
    extent: int
    over: tuple[str, ...]
    why: str | None
    chain: str | None


class AbiFacts(typing.NamedTuple):
    """The declared abi as manifest data: name, word, sp_align, and the register split as sorted slot_name() strings."""

    name: str
    word: int | None
    sp_align: int | None
    volatile: tuple[str, ...]
    nonvolatile: tuple[str, ...]


class RegionFact(typing.NamedTuple):
    """One region row of the manifest: base facts, the operative word, plus its placements."""

    name: str
    base_sym: str
    base: int | None
    max_size: int | None
    fill: str
    forbid: str
    word: int
    placements: tuple[PlacementFact, ...]


class CellRow(typing.NamedTuple):
    """One cell row: owner, delivery phase, the value as written, and its resolution state.

    Exactly one of resolved/missing/promised/error is non-None (the four Resolution buckets)."""

    region: str
    offset: int
    width: int
    owner: str
    deliver: str
    value: str
    resolved: str | None
    missing: tuple[str, ...] | None
    promised: str | None
    error: str | None
    deps: tuple[str, ...]


class HopRef(typing.NamedTuple):
    """One hop's identity row: the manifest's per-hop join keys (full dataflow is Chain.dataflow())."""

    hop: str
    gadget: str
    entry: int | str
    spec_sha16: str


class ChainRef(typing.NamedTuple):
    """One chain's identity row."""

    name: str
    region: str
    hops: tuple[HopRef, ...]


class _MapRow(typing.NamedTuple):
    """One rendered map row and the region offset it sorts on (render_map plumbing)."""

    start: int
    text: str


class BindFact(typing.NamedTuple):
    """One bound symbol with its provenance."""

    sym: str
    value: int
    source: str


class RangeFact(typing.NamedTuple):
    """An inclusive expectation range."""

    lo: int
    hi: int


class ExpectationFact(typing.NamedTuple):
    """One expect_sym declaration."""

    sym: str
    range: RangeFact | None
    align: int | None


@dataclasses.dataclass(frozen=True)
class Manifest:
    """The layout as data: regions, placements, cells with resolution state, chain join keys,
    and the consumed facts (provenance, binds, expectations). The porter's "what does this PoC
    depend on" and the maintainer's blast-radius join key. Never refuses: unresolved cells
    carry their missing sets; hand-built layouts carry null provenance. abi is the declared
    calling-convention record (None when no abi was declared)."""

    name: str | None
    endian: cento.cells.Endian
    fill_default: int
    abi: AbiFacts | None
    provenance: Provenance
    regions: tuple[RegionFact, ...]
    cells: tuple[CellRow, ...]
    chains: tuple[ChainRef, ...]
    binds: tuple[BindFact, ...]
    expectations: tuple[ExpectationFact, ...]
    pending: tuple[str, ...]

    def _abi_json(self) -> dict[str, typing.Any]:
        """The abi block: always present, always carrying the operative endian; null-valued abi facts are omitted (no nulls inside this block)."""
        block: dict[str, typing.Any] = {"endian": self.endian}
        if self.abi is not None:
            block.update({k: (list(v) if isinstance(v, tuple) else v) for k, v in self.abi._asdict().items() if v is not None})
        return block

    def _region_json(self, r: RegionFact) -> dict[str, typing.Any]:
        """One region row; "word" is omitted exactly when the abi block makes it recoverable (row word = "word" if present else the abi block's "word")."""
        row: dict[str, typing.Any] = {**r._asdict(), "placements": [{**p._asdict(), "over": list(p.over)} for p in r.placements]}
        if self.abi is not None and self.abi.word == r.word:
            del row["word"]
        return row

    def to_json(self) -> dict[str, typing.Any]:
        """The manifest as a plain json-clean dict (sorted, deterministic, no timestamps).

        The abi block is always present and carries the layout's operative endian; within it
        null-valued keys are omitted. Everywhere else nulls are semantic (unresolved, unbound,
        absent provenance) and stay. Region rows omit "word" when it equals the abi's word."""
        return {
            "name": self.name,
            "abi": self._abi_json(),
            "fill_default": self.fill_default,
            "provenance": dataclasses.asdict(self.provenance),
            "regions": [self._region_json(r) for r in self.regions],
            "cells": [{**c._asdict(), "missing": list(c.missing) if c.missing is not None else None, "deps": list(c.deps)} for c in self.cells],
            "chains": [{**ch._asdict(), "hops": [h._asdict() for h in ch.hops]} for ch in self.chains],
            "binds": [b._asdict() for b in self.binds],
            "expectations": [{**e._asdict(), "range": e.range._asdict() if e.range is not None else None} for e in self.expectations],
            "pending": list(self.pending),
        }

    def render_map(self) -> str:
        """The manifest as an ASCII memory map, every fact from this record.

        Per region: a header of base/max/fill/word facts, then placement, gap, and raw-cell rows
        in offset order, then the region's pending symbols."""
        lines: list[str] = []
        for reg in self.regions:
            base = f"{reg.base_sym}={reg.base:#x}" if reg.base is not None else f"{reg.base_sym} (unbound)"
            header = f"region {reg.name}  base {base}"
            if reg.max_size is not None:
                header += f"  max {reg.max_size:#x}"
            header += f"  fill {reg.fill}  word {reg.word}"
            lines.append(header)
            cells = [c for c in self.cells if c.region == reg.name]
            if not reg.placements and not cells:
                continue
            raw = [c for c in cells if not any(p.offset <= c.offset < p.offset + p.extent for p in reg.placements)]
            rows: list[_MapRow] = []
            for p in reg.placements:
                text = f"  +{p.offset:#06x}..+{p.offset + p.extent:#06x}  {p.path}"
                if p.chain is not None:
                    text += f"  [chain {p.chain}]"
                if p.over:
                    text += f"  over={','.join(p.over)}"
                rows.append(_MapRow(p.offset, text))
            rows.extend(_MapRow(c.offset, f"  raw: +{c.offset:#06x} w{c.width}  {c.owner}") for c in raw)
            spans = [(p.offset, p.offset + p.extent) for p in reg.placements] + [(c.offset, c.offset + c.width) for c in raw]
            covered: list[tuple[int, int]] = []
            for start, end in sorted(spans):
                if covered:
                    last_start, last_end = covered[-1]
                    if start <= last_end:
                        covered[-1] = (last_start, max(last_end, end))
                        continue
                covered.append((start, end))
            cursor = 0
            for start, end in covered + ([(reg.max_size, reg.max_size)] if reg.max_size is not None else []):
                if cursor < start:
                    rows.append(_MapRow(cursor, f"  +{cursor:#06x}..+{start:#06x}  (fill)"))
                cursor = max(cursor, end)
            rows.sort(key=lambda row: row.start)  # stable: placements at one offset keep manifest (offset, name) order; other row kinds never share a start
            lines.extend(row.text for row in rows)
            missing = sorted({sym for c in cells if c.missing is not None for sym in c.missing})
            if missing:
                lines.append(f"  pending: {', '.join(missing)}")
        return "\n".join(lines)


Tier = typing.Literal["verified", "checked", "assumed"]
_TIER_RANK: dict[Tier, int] = {"assumed": 0, "checked": 1, "verified": 2}  # the ladder min() takes tiers down


class GadgetAssurance(typing.NamedTuple):
    """One distinct gadget's assurance row. tier: "verified" (an attached PASS verdict for its
    spec_sha16 -- the ONLY path), "checked" (catalog-crosschecked clean, judged only when no
    verdict is attached), or "assumed" (everything else; a FAILED verdict FORCES assumed --
    byte-level disagreement outranks catalog agreement, and verdict_ok says so). A gadget used
    by multiple chains takes the MINIMUM tier across its uses."""

    gadget: str
    spec_sha16: str
    entry: int | str
    tier: Tier
    hops: tuple[str, ...]  # "chain.hop" paths using it, sorted
    verdict_ok: bool | None


class SymbolAssurance(typing.NamedTuple):
    """One symbol's assurance row: expectation facts and bind provenance, either possibly absent."""

    sym: str
    lo: int | None
    hi: int | None
    align: int | None
    bound: int | None
    source: str | None


class GateFact(typing.NamedTuple):
    """The gate verdict summary: preflight's shippability plus the blocker counts."""

    shippable: bool
    errors: int
    warnings: int
    pending: int
    dangling: int


@dataclasses.dataclass
class _GadgetUses:
    """Accumulator for one distinct (gname, spec_sha16) across every chain (assurance() plumbing)."""

    gadget: cento.gadget.GadgetMeta
    hops: list[str]
    tier: Tier


@dataclasses.dataclass(frozen=True)
class Assurance:
    """Checked vs emulator-verified vs assumed vs waived, as one export.

    The tier ladder is evidence, never trust: absence of a verdict exports as "assumed" and is
    never upgraded (see GadgetAssurance). Waiver rows are the check() ledger types
    (cento.checks.Waiver / RewriteWaiver), fold-derived discards included. render() is the
    reviewer's one-screen table; to_json() the tooling shape (named dicts throughout)."""

    gadgets: tuple[GadgetAssurance, ...]
    symbols: tuple[SymbolAssurance, ...]
    waivers: tuple[cento.checks.Waiver, ...]
    rewrite_waivers: tuple[cento.checks.RewriteWaiver, ...]
    gate: GateFact

    def to_json(self) -> dict[str, typing.Any]:
        """The assurance as a plain json-clean dict (sorted, deterministic, no timestamps)."""
        return {
            "gadgets": [{**g._asdict(), "hops": list(g.hops)} for g in self.gadgets],
            "symbols": [s._asdict() for s in self.symbols],
            "waivers": [w._asdict() for w in self.waivers],
            "rewrite_waivers": [w._asdict() for w in self.rewrite_waivers],
            "gate": self.gate._asdict(),
        }

    def render(self) -> str:
        """The reviewer's one-screen table: tier counts and the gate on the header line, then gadget, symbol, and waiver rows (sections only when occupied)."""
        counts = {"verified": 0, "checked": 0, "assumed": 0}
        for g in self.gadgets:
            counts[g.tier] += 1
        gate = "shippable" if self.gate.shippable else "blocked"
        lines = [f"assurance: {counts['verified']} verified, {counts['checked']} checked, {counts['assumed']} assumed; gate: {gate}"]
        if self.gadgets:
            lines.append("gadgets:")
            lines.extend(f"  {g.gadget}  {g.spec_sha16}  {g.tier}  ({', '.join(g.hops)})" for g in self.gadgets)
        if self.symbols:
            lines.append("symbols:")
            for s in self.symbols:
                parts = [s.sym]
                if s.lo is not None and s.hi is not None:
                    parts.append(f"range=[{s.lo:#x} .. {s.hi:#x}]")
                if s.align is not None:
                    parts.append(f"align={s.align:#x}")
                parts.append(f"= {s.bound:#x} (source: {s.source})" if s.bound is not None else "(unbound)")
                lines.append("  " + " ".join(parts))
        if self.waivers or self.rewrite_waivers:
            lines.append("waivers:")
            lines.extend(f"  clobber {w.region}+0x{w.offset:04x} ({w.effect}): {w.reason}" for w in self.waivers)
            lines.extend(f"  rewrite {w.region}+0x{w.offset:04x}: {w.reason}" for w in self.rewrite_waivers)
        return "\n".join(lines)


class Layout:
    """One payload build: named byte regions of lazily-valued cells, emitted deterministically.

    Declare regions/views/chains under it, bind() symbols as facts arrive, check() for the
    judgment, then emit() (or region.image()) for shippable bytes -- the
    final gate refuses while errors stand. Layouts share no state: two identical builds
    emit identical bytes. The endian default is little (the x86-64-flavored default target);
    big-endian targets declare endian="big".
    """

    _counter = itertools.count(1)

    def __init__(
        self, *, endian: cento.cells.Endian | None = None, name: str | None = None, fill_default: int = 0, abi: cento.machine.AbiSpec | str | None = None
    ) -> None:
        """Precedence for every fact an abi can carry: explicit kwarg > abi fact > built-in default.

        endian= left unset takes the abi's byte order (little when neither speaks); an explicit
        endian= that CONTRADICTS the abi refuses -- the fact rides one declaration, not two.
        """
        if endian is not None and endian not in ("big", "little"):  # fail closed at construction: a typo here would otherwise explode deep in resolution
            raise cento.errors.PlacementError(f"endian must be 'big' or 'little', got {endian!r}")
        spec = cento.abi.resolve(abi) if abi is not None else None
        if spec is not None and spec.endian is not None and endian is not None and endian != spec.endian:
            raise cento.errors.PlacementError(
                f"abi {spec.name!r} is {spec.endian}-endian but this layout declares endian={endian!r} -- drop one: the abi already carries the fact"
            )
        self.name = name if name is not None else f"layout_{next(Layout._counter)}"
        self._auto_named = name is None  # the manifest exports the name only when user-supplied (auto-names are a process-global counter)
        self.abi: cento.machine.AbiSpec | None = spec
        self.endian: cento.cells.Endian = endian if endian is not None else (spec.endian if spec is not None and spec.endian is not None else "little")
        self.fill_default = fill_default
        self.gadget_set: cento.catalog.GadgetSet | None = None
        self.real_hw_default: bool = False
        self.provenance = Provenance()  # set-once by convention (Target.layout composes it); hand-assignable
        self.env = cento.cells.Env()
        self.regions: dict[str, Region] = {}
        self.chains: dict[
            str, cento.chain.Chain
        ] = {}  # checks reads fold()/hops via tolerant getattr, so issues()-only test doubles (typing.cast into this dict) stay legal
        self.clobber_waivers: list[tuple[CellKey, str, str]] = []
        self.rewrites: list[tuple[CellKey, str, str]] = []
        self.rewrite_waivers: list[tuple[CellKey, str]] = []
        self.verdicts: dict[str, cento.checks.VerdictLike] = {}  # spec_sha16 -> verdict, structurally (regions never imports verify); judged by CHK-304
        self.mutations = 0
        self._region_counter = itertools.count(1)
        self._cells: dict[CellKey, CellEntry] = {}
        self._resolution: _ResolutionMemo | None = None  # invalidated by any write or bind; see resolution()
        self._sym_expectations: dict[str, _SymExpectation] = {}  # judged at bind; see expect_sym
        self._reducers: dict[str, typing.Callable[[bytes], int]] = {}  # layout-scoped names; builtins are the fallback (see register_reducer)

    # -- construction -------------------------------------------------------
    def region(
        self,
        name: str | None = None,
        *,
        base: str | None = None,
        max_size: int | None = None,
        fill: FillLike | None = None,
        pad: int | None = None,
        forbid: FillLike | None = None,
        word: int | None = None,
        endian: None = None,
        fill_default: None = None,
    ) -> Region:
        """A named byte region under this layout.

        base= names the region's base symbol (default "<name>_base") -- the symbol bind() takes
        for absolute addressing. fill= takes an int, str, or bytes pattern, tiled across every
        unwritten byte from region offset 0 (default: the layout's fill_default). forbid=
        declares the transport's forbidden byte set (e.g. forbid=0 for NUL-free): resolved
        bytes containing one are CHK-011 errors, and a conflicting fill refuses here. pad=UNIT
        cycle-pads the whole region (max_size required) at creation -- sugar for
        Region.pad(max_size, unit=UNIT). word= sets the default raw-cell width for cell() and
        the region[off] = v slice sugar; precedence: explicit kwarg > abi fact > built-in
        default (4). region()/Layout.region() default word=4; fit regions ride word=8 (or the
        abi's word) -- state abi= or word= when moving between them. Endianness is a Layout
        fact, not a region one: the module-level cento.region(..., endian=...) takes it because
        it constructs the Layout.
        """
        if endian is not None:  # the classic wrong guess: endianness rides the Layout, not the region
            raise cento.errors.PlacementError(
                "region(endian=...) is not a thing: endianness is a Layout fact -- Layout(endian=...), cento.region(..., endian=...), or a Target profile"
            )
        if fill_default is not None:  # same wrong guess, fill flavor: the layout owns the default, fill= sets this region's own
            raise cento.errors.PlacementError(
                "fill_default is a Layout fact -- Layout(fill_default=...), cento.region(..., fill_default=...), or a Target profile; fill= is per-region"
            )
        rname = name if name is not None else f"region_{next(self._region_counter)}"
        if rname in self.regions:
            raise cento.errors.PlacementError(f"region name {rname!r} already used")
        bsym = base if base is not None else f"{rname}_base"
        clash = next((r for r in self.regions.values() if r.base_sym == bsym), None)
        if clash is not None:  # fail closed at declaration: two regions on one base emit silently colliding sparse writes
            raise cento.errors.PlacementError(f"region base symbol {bsym!r} already used by region {clash.name!r} -- give each region its own base=")
        eff_word = word if word is not None else (self.abi.word if self.abi is not None and self.abi.word is not None else 4)
        reg = Region(self, rname, bsym, max_size, fill if fill is not None else self.fill_default, forbid, word=eff_word)
        self.regions[rname] = reg
        self.mutations += 1
        if pad is not None:
            if max_size is None:
                raise cento.errors.PlacementError(f"{rname}: region(pad={pad}) needs max_size to know how much to pad")
            reg.pad(max_size, unit=pad)
        return reg

    def sym(self, name: str) -> cento.cells.Ref:
        """A symbolic value (Ref): use it in cells now, bind() the number later; arithmetic (sym + off) rides along."""
        return cento.cells.Ref(name)

    def expect_sym(self, sym: str, *, range: tuple[int, int] | None = None, align: int | None = None) -> None:
        """Declare what a plausible value for `sym` looks like: an inclusive (lo, hi) range and/or an alignment.

        A bind() that violates the expectation refuses with a teaching error -- the classic
        mis-parsed leak explodes when it lands, not as a payload that lands wrong. An already
        bound value is judged immediately.
        """
        if range is None and align is None:
            raise cento.errors.PlacementError(f"expect_sym({sym!r}): declare range= and/or align= (an empty expectation guards nothing)")
        bounds = _Bounds(*range) if range is not None else None
        if bounds is not None and bounds.lo > bounds.hi:
            raise cento.errors.PlacementError(f"expect_sym({sym!r}): empty range {bounds.lo:#x}..{bounds.hi:#x} (lo must not exceed hi)")
        if align is not None and align <= 0:
            raise cento.errors.PlacementError(f"expect_sym({sym!r}): align must be a positive byte count, got {align}")
        self._sym_expectations[sym] = _SymExpectation(bounds, align)
        bound = self.env.get(sym)
        if bound is not None:
            self._judge_sym(sym, bound)

    def register_reducer(self, name: str, fn: typing.Callable[[bytes], int]) -> typing.Callable[..., cento.cells.Reduce]:
        """Register a layout-scoped reducer; returns its constructor (used like cento.length).

        The name resolves layout-first with the builtins as fallback. Builtin names and
        re-registration refuse: a silently replaced checksum is a wrong payload, not a
        convenience. Registration re-resolves every cell (a Reduce staged early completes).
        """
        if name in cento.cells.REDUCERS:
            raise cento.errors.PlacementError(f"register_reducer({name!r}): the name is a builtin reducer; pick another")
        if name in self._reducers:
            raise cento.errors.PlacementError(f"register_reducer({name!r}): already registered on this layout; re-registration is refused")
        self._reducers[name] = fn
        self.mutations += 1  # the resolution memo keys on mutations: cells staged before registration re-resolve

        def ctor(span: cento.cells.Span | cento.cells.HasSpan, expect: int | None = None) -> cento.cells.Reduce:
            return cento.cells.Reduce(fn=name, span=cento.cells._as_span(span), expect=expect)

        return ctor

    _BUILTIN_XFORM_NAMES = frozenset(x.value for x in cento.cells.Xform)

    def register_xform(self, name: str, fn: typing.Callable[[int], int]) -> typing.Callable[[cento.cells.Ref], cento.cells.Ref]:
        """Register a layout-scoped value transform; returns its constructor (used like cento.lo16).

        The constructor takes a Ref and returns it carrying the transform by name; the name
        resolves against this layout at emit time. Builtin names and re-registration refuse.
        """
        if name in Layout._BUILTIN_XFORM_NAMES:
            raise cento.errors.PlacementError(f"register_xform({name!r}): the name is a builtin xform; pick another")
        if name in self.env.xforms:
            raise cento.errors.PlacementError(f"register_xform({name!r}): already registered on this layout; re-registration is refused")
        self.env.xforms[name] = fn
        self.mutations += 1  # cells staged before registration re-resolve

        def ctor(ref: cento.cells.Ref) -> cento.cells.Ref:
            return dataclasses.replace(ref, xform=name)

        return ctor

    def _judge_sym(self, sym: str, value: int) -> None:
        expect = self._sym_expectations.get(sym)
        if expect is None:
            return
        rng, align = expect
        if rng is not None and not rng.lo <= value <= rng.hi:
            raise cento.errors.PlacementError(
                f"bind {sym}={value:#x} violates the declared expectation range [{rng.lo:#x} .. {rng.hi:#x}] -- a mis-parsed leak? (see expect_sym)"
            )
        if align is not None and value % align:
            raise cento.errors.PlacementError(f"bind {sym}={value:#x} violates the declared alignment 0x{align:x} -- a mis-parsed leak? (see expect_sym)")

    def bind(self, sym: str, value: int, *, source: str = "manual") -> None:
        """Bind a symbol to its value (the leak landing). source= is provenance explain() shows; rebinding re-resolves every dependent cell.

        Binds are judged against expect_sym() declarations: an implausible value refuses here.
        """
        if isinstance(value, bool) or not isinstance(value, int):
            raise cento.errors.PlacementError(f"bind {sym}={value!r}: symbol values are int addresses (parse the leak with int(s, 16)?)")
        self._judge_sym(sym, value)
        self.env.bind(sym, value, source=source)

    def cycle_find(self, needle: bytes | int, *, width: int = 4, alphabet: bytes = cento.cells.CYCLE_ALPHABET, n: int = 4) -> int:
        """Find a crash value's pad offset, using this layout's endianness for int needles (see cento.cycle_find).

        A crashed register reads the pad in the target's byte order, and the layout already
        knows that order -- the little-endian flip cannot be forgotten. Bytes needles are
        endian-neutral and pass through unchanged.
        """
        return cento.cells.cycle_find(needle, width=width, endian=self.endian, alphabet=alphabet, n=n)

    def _set_cell(self, region: Region, offset: int, value: object, width: int, owner: str) -> None:
        if offset < 0:
            raise cento.errors.PlacementError(f"{owner}: negative offset")
        was_pristine_pad = offset in region._cyclic_cells
        region._cyclic_cells.discard(offset)  # any write over a pad word ends its cycle-pad provenance (Region.pad re-adds after its own writes)
        key = (region.name, offset)
        prev = self._cells.get(key)
        if prev is not None and prev.owner != owner and not was_pristine_pad:
            # A pristine cycle-pad word is scaffolding laid to be overwritten, not a belief about
            # the bytes: patching over it is the pad's whole purpose, so no rewrite is recorded.
            self.rewrites.append((key, prev.owner, owner))  # same-key different-owner: recorded here, judged at check time (CHK-008)
        coerced = _coerce(value)
        if isinstance(coerced, int) and not -(1 << (8 * width - 1)) <= coerced < (1 << (8 * width)):
            # Fail closed on literals everywhere, not just width-declared fields: a 64-bit address
            # pasted into a 4-byte raw cell is a typo, not a wrap. Computed values (Delta/Reduce/
            # slices) keep their documented modulo semantics -- overflow is meaningful there.
            raise cento.errors.PlacementError(
                f"{owner}: {coerced:#x} does not fit a {width}-byte cell (slice deliberately with lo16/hi16/ha16, or widen the cell)"
            )
        self._cells[key] = CellEntry(value=coerced, width=width, owner=owner)
        self.mutations += 1  # invalidates the resolution() snapshot: the old value's symbol deps vanish with it (no ghost dirty() rows)

    def attach_verdicts(self, verdicts: typing.Mapping[str, cento.checks.VerdictLike]) -> None:
        """Attach verification verdicts, keyed by spec_sha16 (cento.verify.Verdict values, e.g. from verify_transfer).

        Opt-in provenance: once attached, CHK-304 warns for every chain hop whose gadget spec
        has no PASS verdict; verified hops are listed in Report.verified.
        """
        self.verdicts = dict(verdicts)

    def allow_clobber(self, cell: CellHandle, effect: cento.machine.Effect | str, reason: str) -> None:
        """Waive a windowed-effect clobber on one cell (silences CHK-205 for that pair).

        The reason is mandatory and appears in the check() waiver ledger for review."""
        ename = getattr(effect, "name", None) if not isinstance(effect, str) else effect
        if not isinstance(ename, str):
            raise cento.errors.PlacementError("allow_clobber: effect must be an Effect or its name string")
        self.clobber_waivers.append(((cell.region.name, cell.offset), ename, reason))
        self.mutations += 1

    def allow_rewrite(self, cell: CellHandle | str, reason: str) -> None:
        """Waive a same-key different-owner rewrite on one cell (silences CHK-008 for that cell).

        The reason is mandatory and appears in the check() waiver ledger for review. Accepts a
        CellHandle or a path string, so the path a CHK-008 error shows can be pasted straight in.
        """
        if isinstance(cell, str):
            reg, off, _path = self._locate(cell)
            key = (reg.name, off)
        else:
            key = (cell.region.name, cell.offset)
        self.rewrite_waivers.append((key, reason))
        self.mutations += 1

    def mark(self, handle: CellHandle, deliver: cento.emit.Deliver) -> None:
        """Set a cell's delivery phase: NORMAL < LATE < ARM (the trigger ships last; see DeliveryPlan)."""
        key = (handle.region.name, handle.offset)
        entry = self._cells.get(key)
        if entry is None:
            raise cento.errors.PlacementError(f"{handle.path}: cannot mark an unset cell")
        entry.deliver = deliver
        self.mutations += 1

    def cells(self) -> dict[CellKey, CellEntry]:
        """Snapshot of the cell store: a new dict (safe to iterate while mutating the layout)
        of the LIVE CellEntry objects. Treat entries as read-only -- in-place mutation bypasses
        value coercion and change tracking; change cells via CellHandle.write()/mark()."""
        return dict(self._cells)

    # -- lazy resolution ------------------------------------------------------
    def resolution(self) -> Resolution:
        """The layout's forcing snapshot: every cell's resolution outcome, computed once per (cells, env) state.

        Memoized on (mutations, env.generation): any write or bind invalidates, and the next
        call rebuilds the whole snapshot from scratch. force()/pending()/dirty() and every
        backend derive from this one computation.
        """
        stamp = (self.mutations, self.env.generation)
        cached = self._resolution
        if cached is not None and cached.stamp == stamp:
            return cached.res
        res = Resolution(resolved={}, residual={}, promised={}, errors={}, deps={})
        for key in sorted(self._cells):
            try:
                self._force_into(key, frozenset(), res)
            except cento.errors.ResolveError:
                pass  # recorded under its own key in res.errors; consumers judge (CHK-007/CHK-009/CHK-014) or re-raise
        self._resolution = _ResolutionMemo(stamp, res)
        return res

    def _force_into(self, key: CellKey, stack: frozenset[CellKey], res: Resolution) -> bytes | cento.cells.Residual | cento.cells.Promised:
        """Force one cell into the snapshot under construction.

        Memoized in res's buckets, errors included, so re-forcing re-raises the recorded refusal;
        `stack` is the Reduce-coverage path for cycle detection. A covered cell's error propagates
        and is recorded under the covering Reduce's key too, so both owners surface at check().
        """
        if key in stack:
            raise cento.errors.ResolveError(f"reduce cycle through cell {key[0]}+0x{key[1]:x} (a reduce may not cover its own cell)")
        err = res.errors.get(key)
        if err is not None:
            raise err
        if key in res.resolved:
            return res.resolved[key]
        if key in res.residual:
            return res.residual[key]
        if key in res.promised:
            return res.promised[key]
        entry = self._cells[key]
        deps = res.deps.setdefault(key, set())
        try:
            r = self._force_one(key, entry, stack, res, deps)
        except cento.errors.ResolveError as exc:  # WidthError/XformError are ResolveErrors: each is this cell's own refusal
            res.errors[key] = exc
            raise
        if isinstance(r, cento.cells.Residual):
            res.residual[key] = r
        elif isinstance(r, cento.cells.Promised):
            res.promised[key] = r
        else:
            res.resolved[key] = r
        return r

    def _force_one(
        self, key: CellKey, entry: CellEntry, stack: frozenset[CellKey], res: Resolution, deps: set[str]
    ) -> bytes | cento.cells.Residual | cento.cells.Promised:
        value = entry.value
        if isinstance(value, cento.cells.Writeback):
            return cento.cells.Promised(value.name)  # runtime-written cell: no build-time bytes, by design (never an error)
        if isinstance(value, cento.cells.Reduce):
            data = self._span_bytes(value.span, stack | {key}, res, deps)
            if isinstance(data, cento.cells.Residual):
                return data
            fn = self._reducers.get(value.fn) or cento.cells.REDUCERS.get(value.fn)
            if fn is None:
                raise cento.errors.ResolveError(f"unknown reducer {value.fn!r} -- register_reducer() on the layout that resolves this cell")
            return (fn(data) % (1 << (8 * entry.width))).to_bytes(entry.width, self.endian)
        result = cento.cells.resolve(value, self.env, deps)
        if isinstance(result, cento.cells.Residual):
            return result
        if isinstance(value, cento.cells.Ref) and value.xform is cento.cells.Xform.ADDR and not 0 <= result < 1 << (8 * entry.width):
            # Fail closed: a full address that does not fit is a wrong chain, not a wrap.
            # (lo16/hi16/ha16 slices, registered xforms, and Delta arithmetic keep their documented wrap semantics.)
            raise cento.errors.WidthError(f"{entry.owner}: resolved {result:#x} does not fit the {entry.width}-byte cell")
        return (result % (1 << (8 * entry.width))).to_bytes(entry.width, self.endian)

    def _span_bytes(self, span: cento.cells.Span, stack: frozenset[CellKey], res: Resolution, deps: set[str]) -> bytes | cento.cells.Residual:
        start = cento.cells.resolve(span.start, self.env, deps)
        end = cento.cells.resolve(span.end, self.env, deps)
        missing: set[str] = set()
        for part in (start, end):
            if isinstance(part, cento.cells.Residual):
                missing |= set(part.missing)
        if missing:
            return cento.cells.Residual(missing=frozenset(missing))
        assert isinstance(start, int) and isinstance(end, int)
        return self._compose(span.region, start, end, res=res, stack=stack, deps=deps)

    def _compose(
        self,
        region_name: str,
        start: int,
        end: int,
        *,
        res: Resolution,
        stack: frozenset[CellKey] = frozenset(),
        deps: set[str] | None = None,
        partial: bool = False,
    ) -> bytes | cento.cells.Residual:
        """Render [start, end) of a region: the fill pattern with resolved cells painted over it (clipped).

        Both byte-producing consumers run through here, so checksum inputs and emitted images
        agree definitionally. partial=False (Reduce spans): any covered residual cell makes the
        whole window Residual. partial=True (the IMAGE backend): residual/promised cells leave
        fill standing (holes surface as fixups, reported by the caller). A covered cell's own
        WidthError/ResolveError always raises.
        """
        reg = self.regions[region_name]
        buf = bytearray(reg.fill_at(start, end - start))
        missing: set[str] = set()
        for (rname, off), entry in sorted(self._cells.items()):  # sorted: aliased cells paint deterministically; CHK-006 judges any disagreement
            if rname != region_name or off + entry.width <= start or off >= end:
                continue
            forced = self._force_into((rname, off), stack, res)
            if isinstance(forced, cento.cells.Residual):
                missing |= set(forced.missing)
                continue
            if isinstance(forced, cento.cells.Promised):
                continue  # Writeback cells contribute no build-time bytes; the region fill stands in
            for i, b in enumerate(forced):  # clip to [start, end)
                pos = off + i - start
                if 0 <= pos < len(buf):
                    buf[pos] = b
            if deps is not None:
                deps |= res.deps.get((rname, off), set())
        if missing and not partial:
            return cento.cells.Residual(missing=frozenset(missing))
        return bytes(buf)

    def force(self, key: CellKey) -> bytes | cento.cells.Residual | cento.cells.Promised:
        """One cell's build-time value, from the resolution() snapshot.

        bytes when resolvable, Residual naming the missing symbols, Promised for runtime-written
        Writeback cells. Raises the cell's own WidthError/ResolveError; KeyError when no cell
        was ever written here.
        """
        if key not in self._cells:
            raise KeyError(key)
        res = self.resolution()
        err = res.errors.get(key)
        if err is not None:
            raise err
        if key in res.resolved:
            return res.resolved[key]
        if key in res.residual:
            return res.residual[key]
        return res.promised[key]

    def pending(self) -> set[str]:
        """Cell-value symbols still unbound -- the bind() worklist (region base symbols excluded;
        sparse emission and plan.finalize() name those)."""
        return self.resolution().pending()

    def dirty(self, *syms: str) -> set[CellKey]:
        """Cells whose values depend on the given symbols -- the re-delivery worklist after a rebind."""
        return self.resolution().dirty(*syms)

    def check(self) -> cento.checks.Report:
        """Judge the whole layout: a Report of named CHK-* errors and warnings.

        render() for humans, to_json() for CI. Advisory mid-build; emit() is the gate
        that refuses."""
        return cento.checks.run_checks(self)

    def preflight(self) -> cento.emit.Preflight:
        """Shippability as data: what the final gate would refuse on, without raising.

        .shippable is the gate's decision; .report/.dangling/.pending name what it refuses on
        (cento.checks.CODES catalogs the CHK codes). See cento.emit.Preflight for the exact scope.
        """
        return cento.emit.preflight(self)

    def emit(self, backend: cento.emit.BackendLike, *, final: bool = True) -> cento.emit.EmitResult:
        """Run a backend over the layout: 'image' (bytes per region), 'hexdump' (annotated text), 'sparse' (absolute address -> bytes).

        Final by default -- the gate refuses on check() errors, pending symbols, and dangling
        chains. emit(backend, final=False) is the ungated draft read; its EmitResult carries
        .artifact plus .fixups naming every cell still awaiting a symbol.
        """
        return cento.emit.run_emit(self, backend, final=final)

    def image(self, name: str | None = None, *, final: bool = True, partial: None = None) -> bytes:
        """A region's emitted bytes, by name; with exactly one region the name may be omitted.

        Delegates to Region.image, whose refusal behavior applies: final by default (the same
        full gate as emit()); image(name, final=False) is the draft read, raising ResolveError
        while cells here await symbols (the refusal's .partial carries the fill); a cell-less
        region emits max_size bytes of fill.
        """
        if name is None:
            if len(self.regions) != 1:
                names = ", ".join(sorted(self.regions)) or "(none)"
                raise cento.errors.PlacementError(f"layout has {len(self.regions)} regions ({names}); image(name) needs the name")
            name = next(iter(self.regions))
        region = self.regions.get(name)
        if region is None:
            hint = difflib.get_close_matches(name, list(self.regions), n=1)
            raise cento.errors.PlacementError(f"no region named {name!r}" + (f"; did you mean {hint[0]!r}?" if hint else ""))
        return region.image(final=final, partial=partial)

    def hexdump(self, *, color: bool | None = None, skip: bool = False) -> str:
        """The HEXDUMP backend's annotated text (emit("hexdump").artifact, sans trailing newline): a header per region, one line per cell.

        No trailing newline, so it drops into print()/f-strings directly; color=None auto-detects
        (stdout TTY, NO_COLOR honored). skip=True (pwntools' name for the idiom) folds runs of
        cycle-pad and repeated-byte cells into a `*` row -- named cells, patched words, and
        anything tagged or unresolved always show. Full output is the default; the emit artifact
        itself is always plain, full, and newline-terminated.
        """
        text: str = cento.emit.run_emit(self, cento.emit.Backend.HEXDUMP, final=False).artifact  # a diagnostic view: never gated
        text = text.removesuffix("\n")
        if skip:
            text = cento.emit.summarize_hexdump(text, self)
        return cento.emit.colorize_hexdump(text) if cento.emit.want_color(color) else text

    def plan(self, *, real_hw: bool | None = None) -> cento.plan.DeliveryPlan:
        """An ordered delivery campaign over this layout: stage()/confirm()/finalize() with NORMAL < LATE < ARM and an append-only ledger."""
        return cento.plan.DeliveryPlan(self, real_hw=real_hw if real_hw is not None else self.real_hw_default)

    # -- introspection --------------------------------------------------------
    def _locate(self, target: str | int) -> tuple[Region, int, str]:
        """Resolve an explain() target to (region, byte offset, display path)."""
        if isinstance(target, int):
            hits: list[tuple[Region, int]] = []
            bound: list[str] = []
            for rname in sorted(self.regions):
                reg = self.regions[rname]
                base = self.env.get(reg.base_sym)
                if base is None:
                    continue
                bound.append(rname)
                extent = reg.max_size if reg.max_size is not None else max((p.offset + p.extent for p in reg.placements), default=0)
                if base <= target < base + extent:
                    hits.append((reg, target - base))
            if len(hits) != 1:
                kind = "no" if not hits else "multiple"
                raise cento.errors.PlacementError(
                    f"address 0x{target:x}: {kind} bound region covers it; bound regions: {', '.join(bound) if bound else '(none)'}"
                    " (int targets are absolute; region-relative offsets spell as explain('region+0xNN'))"
                )
            reg, off = hits[0]
            return reg, off, f"{reg.name}+0x{off:X}"
        raw = re.fullmatch(r"(\w+)(?:\.raw)?\+0[xX]([0-9A-Fa-f]+)", target)
        if raw is not None:  # the spellings the library itself prints (raw-cell owners, explain headers): paste them back
            raw_region = self.regions.get(raw.group(1))
            if raw_region is None:
                hint = difflib.get_close_matches(raw.group(1), list(self.regions), n=1)
                raise cento.errors.PlacementError(f"no region named {raw.group(1)!r}" + (f"; did you mean {hint[0]!r}?" if hint else ""))
            return raw_region, int(raw.group(2), 16), target
        parts = target.split(".")
        if len(parts) < 3:
            raise cento.errors.PlacementError(f"explain path {target!r}: expected region.placement.field (or the raw-cell spelling, region.raw+0xNN)")
        named_region = self.regions.get(parts[0])
        if named_region is None:
            hint = difflib.get_close_matches(parts[0], list(self.regions), n=1)
            raise cento.errors.PlacementError(f"no region named {parts[0]!r}" + (f"; did you mean {hint[0]!r}?" if hint else ""))
        pname, idx = ".".join(parts[1:-1]), None
        if pname.endswith("]") and "[" in pname:
            pname, _, tail = pname.partition("[")
            idx = int(tail[:-1], 0)
        try:
            handle = named_region[pname]
            if idx is not None:
                if not isinstance(handle, ArrayHandle):
                    raise cento.errors.PlacementError(f"{named_region.name}.{pname} is not an array placement; drop the [{idx}]")
                handle = handle[idx]
            cell = getattr(handle, parts[-1])
        except (KeyError, AttributeError, IndexError) as e:
            raise cento.errors.PlacementError(str(e.args[0]) if e.args else str(e)) from e
        return named_region, cell.offset, cell.path

    def explain_data(self, target: str | int) -> Explanation:
        """explain() as a frozen record (see Explanation); explain() renders exactly this."""
        reg, off, path = self._locate(target)
        base = self.env.get(reg.base_sym)
        key = (reg.name, off)
        covering = sorted(
            (p for p in reg.placements if p.offset <= off < p.offset + p.extent or any(s <= off < e for s, e in p.ext_spans())),
            key=lambda p: (p.offset, p.name),
        )
        prime_name = path[len(reg.name) + 1 : path.rfind(".")].partition("[")[0] if path.count(".") >= 2 else None  # the (possibly dotted) placement name
        prime = next((p for p in covering if p.name == prime_name), covering[0] if covering else None)
        entry = self._cells.get(key)
        binding: BindingFact | None = None
        if entry is not None and isinstance(entry.value, cento.cells.Ref):
            b = self.env.binding(entry.value.sym)
            binding = BindingFact(entry.value.sym, b.value if b is not None else None, b.source if b is not None else None)
        feeds: list[FeedFact] = []
        writebacks: list[WritebackFact] = []
        for cname in sorted(self.chains):
            chain = self.chains[cname]
            if not isinstance(chain, cento.chain.Chain):
                continue  # issues()-only test doubles in the registry have no fold to narrate
            fold = chain.fold()
            for hop in chain.hops:
                for slot, st in sorted(fold.entry[hop.name].items(), key=lambda kv: str(kv[0])):
                    if st.kind in ("seat", "writeback") and st.cell is not None and (st.cell.region.name, st.cell.offset) == key:
                        feeds.append(FeedFact(cname, hop.name, getattr(slot, "name", str(slot)), st.kind))
            sup = fold.supplies.get(key)
            if sup is not None:
                writebacks.append(WritebackFact(cname, str(sup.effect), str(sup.output)))
        return Explanation(
            path=path,
            region=reg.name,
            offset=off,
            abs_addr=base + off if base is not None else None,
            prime=PrimeFact(prime.name, off - prime.offset) if prime is not None else None,
            cell=CellFact(_render_value(entry.value), entry.width, entry.deliver.name) if entry is not None else None,
            binding=binding,
            aliases=tuple(AliasFact(p.name, p.why) for p in covering if p is not prime),
            feeds=tuple(feeds),
            writebacks=tuple(writebacks),
        )

    def explain(self, target: str | int) -> str:
        """One-stop 'what is this byte': placement (path and offset spellings), cell value, aliases, chain dataflow."""
        return self.explain_data(target).render()

    def manifest(self) -> Manifest:
        """The layout as data (see Manifest); to_json() is its dict form."""
        res = self.resolution()
        regions_f: list[RegionFact] = []
        for rname in sorted(self.regions):
            reg = self.regions[rname]
            pls = tuple(
                PlacementFact(p.name, p.path, p.offset, p.extent, p.over, p.why, p.chain) for p in sorted(reg.placements, key=lambda p: (p.offset, p.name))
            )
            regions_f.append(RegionFact(reg.name, reg.base_sym, self.env.get(reg.base_sym), reg.max_size, reg.fill.hex(), reg.forbid.hex(), reg.word, pls))
        rows: list[CellRow] = []
        for key in sorted(self._cells):
            entry = self._cells[key]
            resolved = res.resolved.get(key)
            residual = res.residual.get(key)
            promised = res.promised.get(key)
            err = res.errors.get(key)
            rows.append(
                CellRow(
                    region=key[0],
                    offset=key[1],
                    width=entry.width,
                    owner=entry.owner,
                    deliver=entry.deliver.name,
                    value=_render_value(entry.value),
                    resolved=resolved.hex() if resolved is not None else None,
                    missing=tuple(sorted(residual.missing)) if residual is not None else None,
                    promised=promised.name if promised is not None else None,
                    error=str(err) if err is not None else None,
                    deps=tuple(sorted(res.deps.get(key, set()))),
                )
            )
        chains_f: list[ChainRef] = []
        for cname in sorted(self.chains):
            ch = self.chains[cname]
            if not isinstance(ch, cento.chain.Chain):
                continue  # issues()-only test doubles have no hops to identify
            hops = tuple(
                HopRef(
                    h.name,
                    h.gadget.gname,
                    h.gadget.entry if isinstance(h.gadget.entry, int) else cento.gadget.entry_str(h.gadget.entry),
                    cento.gadget.spec_sha16(h.gadget),
                )
                for h in ch.hops
            )
            chains_f.append(ChainRef(cname, ch.region.name, hops))
        binds = tuple(BindFact(s, b.value, b.source) for s, b in sorted(self.env.bindings().items()))
        expectations = tuple(
            ExpectationFact(s, RangeFact(e.range.lo, e.range.hi) if e.range is not None else None, e.align) for s, e in sorted(self._sym_expectations.items())
        )
        abi_f = (
            AbiFacts(
                name=self.abi.name,
                word=self.abi.word,
                sp_align=self.abi.sp_align,
                volatile=tuple(sorted(cento.machine.slot_name(s) for s in self.abi.volatile)),
                nonvolatile=tuple(sorted(cento.machine.slot_name(s) for s in self.abi.nonvolatile)),
            )
            if self.abi is not None
            else None
        )
        return Manifest(
            name=None if self._auto_named else self.name,
            endian=self.endian,
            fill_default=self.fill_default,
            abi=abi_f,
            provenance=self.provenance,
            regions=tuple(regions_f),
            cells=tuple(rows),
            chains=tuple(chains_f),
            binds=binds,
            expectations=expectations,
            pending=tuple(sorted(res.pending())),
        )

    def to_json(self) -> dict[str, typing.Any]:
        """The manifest as a plain dict (sorted, deterministic, no timestamps) -- see Manifest."""
        return self.manifest().to_json()

    def map(self) -> str:
        """The ASCII memory map: placements, owners, chain frames, gaps, raw cells, pending symbols.

        A display view over manifest() -- plain, deterministic, never an emit artifact."""
        return self.manifest().render_map()

    def assurance(self) -> Assurance:
        """What is actually verified vs checked vs assumed (see Assurance), plus symbols, the waiver ledger, and the gate verdict.

        Never refuses: assurance() reads preflight(), and an unshippable layout exports its
        blocker counts honestly."""
        uses: dict[tuple[str, str], _GadgetUses] = {}
        for cname in sorted(self.chains):
            ch = self.chains[cname]
            if not isinstance(ch, cento.chain.Chain):
                continue  # issues()-only test doubles have no hops to judge
            for hop in ch.hops:
                sha = cento.gadget.spec_sha16(hop.gadget)
                verdict = self.verdicts.get(sha)
                tier: Tier
                if verdict is not None:
                    tier = "verified" if verdict.ok else "assumed"  # a present verdict decides outright: FAILED forces assumed (fail-closed)
                elif ch.gadget_set is not None and ch.gadget_set.crosscheck(hop.gadget) == ([], []):
                    tier = "checked"  # crosscheck is consulted only when no verdict is attached
                else:
                    tier = "assumed"  # no verdict and no clean crosscheck: never upgraded
                use = uses.get((hop.gadget.gname, sha))
                if use is None:
                    uses[(hop.gadget.gname, sha)] = _GadgetUses(hop.gadget, [f"{cname}.{hop.name}"], tier)
                else:
                    use.hops.append(f"{cname}.{hop.name}")
                    use.tier = min(use.tier, tier, key=_TIER_RANK.__getitem__)  # the minimum across uses: one weak use drags the row down, never up
        gadgets: list[GadgetAssurance] = []
        for gname, sha in sorted(uses):
            use = uses[(gname, sha)]
            verdict = self.verdicts.get(sha)
            entry = use.gadget.entry if isinstance(use.gadget.entry, int) else cento.gadget.entry_str(use.gadget.entry)
            gadgets.append(GadgetAssurance(gname, sha, entry, use.tier, tuple(sorted(use.hops)), verdict.ok if verdict is not None else None))
        binds = self.env.bindings()
        symbols = []
        for sym in sorted(set(self._sym_expectations) | set(binds)):
            e = self._sym_expectations.get(sym)
            b = binds.get(sym)
            rng = e.range if e is not None else None
            symbols.append(
                SymbolAssurance(
                    sym,
                    rng.lo if rng is not None else None,
                    rng.hi if rng is not None else None,
                    e.align if e is not None else None,
                    b.value if b is not None else None,
                    b.source if b is not None else None,
                )
            )
        pf = self.preflight()
        return Assurance(
            gadgets=tuple(gadgets),
            symbols=tuple(symbols),
            waivers=pf.report.waivers,
            rewrite_waivers=pf.report.rewrite_waivers,
            gate=GateFact(pf.shippable, len(pf.report.errors), len(pf.report.warnings), len(pf.pending), len(pf.dangling)),
        )


def _render_value(value: object) -> str:
    """Human spelling for explain() and the exports: values read as the author wrote them."""
    if isinstance(value, cento.cells.Ref):
        s = value.sym
        if value.addend:
            s += f" + {value.addend:#x}" if value.addend > 0 else f" - {-value.addend:#x}"
        if value.xform is not cento.cells.Xform.ADDR:
            xname = value.xform.value if isinstance(value.xform, cento.cells.Xform) else value.xform
            s = f"{xname}({s})"
        return s
    if isinstance(value, cento.cells.Delta):
        if value.neg.addend and value.neg.xform is cento.cells.Xform.ADDR:
            # Subtracting (sym + k) subtracts k too: fold the NEGATED neg addend into the term.
            neg = value.neg.sym + (f" - {value.neg.addend:#x}" if value.neg.addend > 0 else f" + {-value.neg.addend:#x}")
        else:
            neg = _render_value(value.neg)  # bare sym, or xform(sym + k): the xform's parens keep the addend inside
        s = f"{_render_value(value.pos)} - {neg}"
        if value.addend:
            s += f" + {value.addend:#x}" if value.addend > 0 else f" - {-value.addend:#x}"
        return s
    if isinstance(value, cento.cells.Reduce):

        def end(v: int | cento.cells.Ref) -> str:
            return f"{v:#x}" if isinstance(v, int) else _render_value(v)

        expect = f", expect={value.expect:#x}" if value.expect is not None else ""
        return f"{value.fn}({value.span.region}[{end(value.span.start)}:{end(value.span.end)}]{expect})"
    if isinstance(value, cento.cells.Writeback):
        return f"writeback({value.name!r}, discarded)" if value.discarded else f"writeback({value.name!r})"
    return repr(value)


@dataclasses.dataclass(frozen=True)
class PlacementRec:
    name: str
    offset: int
    spec: cento.views.ViewMeta | cento.views.ArraySpec
    over: tuple[str, ...]
    why: str | None
    path: str
    chain: str | None = None  # owning chain name for chain-created placements (they auto-alias); None for hand placements

    @property
    def extent(self) -> int:
        if isinstance(self.spec, cento.views.ArraySpec):
            return self.spec.extent
        return self.spec.__size__

    def _elems(self) -> list[tuple[int, cento.views.ViewMeta]]:
        if isinstance(self.spec, cento.views.ArraySpec):
            return [(self.offset + i * self.spec.eff_stride, self.spec.viewtype) for i in range(self.spec.count)]
        return [(self.offset, self.spec)]

    def ext_spans(self) -> list[tuple[int, int]]:
        out: list[tuple[int, int]] = []
        for base, vt in self._elems():
            for f in vt.__fields__.values():
                if f.external:
                    out.append((base + f.offset, base + f.offset + f.width.size))
        return sorted(out)


class ViewHandle:
    __slots__ = ("_region", "_vt", "offset", "path")

    _region: Region
    _vt: cento.views.ViewMeta
    offset: int
    path: str

    def __init__(self, region: Region, vt: cento.views.ViewMeta, offset: int, path: str) -> None:
        object.__setattr__(self, "_region", region)
        object.__setattr__(self, "_vt", vt)
        object.__setattr__(self, "offset", offset)
        object.__setattr__(self, "path", path)

    @property
    def addr(self) -> cento.cells.Ref:
        return cento.cells.Ref(self._region.base_sym, addend=self.offset)

    def __len__(self) -> int:
        """The view's declared byte size -- so a follow-on placement can start at `prev.offset + len(prev)`."""
        return self._vt.__size__

    @property
    def span(self) -> cento.cells.Span:
        """This view's byte range; reducers accept it directly (`cento.length(body)`). Reserved name, like addr/offset/path."""
        return cento.cells.Span(self._region.name, self.offset, self.offset + self._vt.__size__)

    @typing.overload
    def overlay(self, spec: cento.views.ViewMeta, at: int, name: str | None = None, *, why: str, also_over: tuple[str, ...] = ()) -> ViewHandle: ...

    @typing.overload
    def overlay(self, spec: cento.views.ArraySpec, at: int, name: str | None = None, *, why: str, also_over: tuple[str, ...] = ()) -> ArrayHandle: ...

    def overlay(
        self,
        spec: cento.views.ViewMeta | cento.views.ArraySpec,
        at: int,
        name: str | None = None,
        *,
        why: str,
        also_over: tuple[str, ...] = (),
    ) -> ViewHandle | ArrayHandle:
        """Place `spec` over this view (intentional alias): offset self.offset+at, over=(this placement,)+also_over.

        also_over: extra placement names the overlay's extent spills into (alias precision for CHK-001/CHK-003).
        """
        own = self.path.partition(".")[2]  # strip the region prefix; placement names may be dotted (chain frames)
        anchor = next((p for p in self._region.placements if p.name == own), None)  # the overlay inherits the anchor placement's owning chain
        return self._region.at(self.offset + at, spec, name, over=(own,) + tuple(also_over), why=why, chain=anchor.chain if anchor is not None else None)

    def _field(self, name: str) -> cento.views.Field:
        vt = self._vt
        fname = vt.__aliases__.get(name, name)
        f = vt.__fields__.get(fname)
        if f is None:
            candidates = list(vt.__fields__) + list(vt.__aliases__)
            hint = difflib.get_close_matches(name, candidates, n=1)
            extra = f"; did you mean {hint[0]!r}?" if hint else ""
            raise AttributeError(f"{self.path}: view {vt.__name__} has no field {name!r}{extra}")
        return f

    def __getattr__(self, name: str) -> CellHandle:
        """Field access: a CellHandle -- for Field(u32 * N) fields, a FieldArrayHandle (a CellHandle subclass; isinstance narrows for indexing)."""
        f = self._field(name)
        path = f"{self.path}.{name}"
        if isinstance(f.width, cento.views.WidthArray):
            return FieldArrayHandle(region=self._region, offset=self.offset + f.offset, width=f.width.size, path=path, spec=f.width)
        return CellHandle(region=self._region, offset=self.offset + f.offset, width=f.width.size, path=path)

    def __setattr__(self, name: str, value: object) -> None:
        f = self._field(name)
        owner = f"{self.path}.{name}"
        base = self.offset + f.offset
        if isinstance(f.width, cento.views.WidthArray):
            FieldArrayHandle(region=self._region, offset=base, width=f.width.size, path=owner, spec=f.width).write(value)
            return
        if isinstance(f.width, cento.views.Bytes):
            if not isinstance(value, (bytes, bytearray)):
                raise cento.errors.PlacementError(f"{owner}: Bytes({f.width.size}) fields take bytes, got {type(value).__name__}")
            if len(value) != f.width.size:
                raise cento.errors.PlacementError(f"{owner}: Bytes({f.width.size}) field got {len(value)} bytes (exact length required)")
            packed = int.from_bytes(bytes(value), self._region.layout.endian)  # same-endian round-trip: the image is byte-identical
            self._region.layout._set_cell(self._region, base, packed, f.width.size, owner=owner)
            return
        if isinstance(f.width, type):
            _validate_scalar(owner, f.width, value)
        self._region.layout._set_cell(self._region, base, value, f.width.size, owner=owner)


class ArrayHandle:
    __slots__ = ("_region", "_spec", "offset", "path")

    _region: Region
    _spec: cento.views.ArraySpec
    offset: int
    path: str

    def __init__(self, region: Region, spec: cento.views.ArraySpec, offset: int, path: str) -> None:
        object.__setattr__(self, "_region", region)
        object.__setattr__(self, "_spec", spec)
        object.__setattr__(self, "offset", offset)
        object.__setattr__(self, "path", path)

    @property
    def addr(self) -> cento.cells.Ref:
        return cento.cells.Ref(self._region.base_sym, addend=self.offset)

    @property
    def span(self) -> cento.cells.Span:
        """The whole array's byte range (all elements at their stride); reducers accept it directly."""
        return cento.cells.Span(self._region.name, self.offset, self.offset + self._spec.extent)

    def __len__(self) -> int:
        return self._spec.count

    def __getitem__(self, i: int) -> ViewHandle:
        if not 0 <= i < self._spec.count:
            raise IndexError(f"{self.path}[{i}]: array has {self._spec.count} elements")
        return ViewHandle(self._region, self._spec.viewtype, self.offset + i * self._spec.eff_stride, f"{self.path}[{i}]")


def region(
    name: str | None = None,
    *,
    base: str | None = None,
    max_size: int | None = None,
    fill: FillLike | None = None,
    pad: int | None = None,
    forbid: FillLike | None = None,
    word: int | None = None,
    endian: cento.cells.Endian | None = None,
    fill_default: int = 0,
    abi: cento.machine.AbiSpec | str | None = None,
) -> Region:
    """A region on its own fresh anonymous Layout: the one-region payload without naming the layout.

    Every call constructs a new Layout (endian/fill_default/abi configure it) -- no shared
    module state, so independent builds stay independent. Precedence for word and endian:
    explicit kwarg > abi fact > built-in default (word 4, endian little -- the x86-64-flavored
    default target); an explicit endian= that contradicts the abi refuses. The layout is
    reachable as the returned handle's .layout.
    """
    return Layout(endian=endian, fill_default=fill_default, abi=abi).region(name, base=base, max_size=max_size, fill=fill, pad=pad, forbid=forbid, word=word)


def fit(
    spec: typing.Mapping[int, object] | typing.Sequence[object],
    *,
    fill: FillLike = 0,
    length: int | None = None,
    word: int | None = None,
    endian: cento.cells.Endian | None = None,
    name: str = "fit",
    abi: cento.machine.AbiSpec | str | None = None,
    max_size: None = None,
) -> Region:
    """pwntools' fit, except you keep the region: offsets (or a flat sequence, or bytes) to values, on a fresh layout.

    A top-level bytes spec is the whole flat payload (pwntools' flat(b"...")). Dict values may
    be lists -- consecutive word-sized cells from that offset (the flat idiom; nested lists
    flatten). bytes values keep their length; ints and symbolic Refs take the word size; str
    refuses (an implicit encoding would be a guess). length= is the region cap, with fill=
    covering the tail. Precedence for word and endian: explicit kwarg > abi fact > built-in
    default (word 8, endian little); an explicit endian= that contradicts the abi refuses.
    fit regions ride word=8 (or the abi's word); region()/Layout.region() default word=4 --
    state abi= or word= when moving between them. The returned Region is the full library
    surface -- add symbols, placements, or chains later; image() for the bytes now.
    """
    if max_size is not None:  # the region() dialect leaking in: fit's cap has always been length=
        raise cento.errors.PlacementError("fit spells the cap length= (same value); max_size is the region() dialect")
    lay = Layout(endian=endian, abi=abi)
    eff_word = word if word is not None else (lay.abi.word if lay.abi is not None and lay.abi.word is not None else 8)
    reg = lay.region(name, max_size=length, fill=fill, word=eff_word)

    def write(off: int, value: object) -> int:
        if isinstance(value, str):
            raise cento.errors.PlacementError(f"{name}: spell payload text as bytes (b{value!r}) -- an implicit encoding would be a guess")
        if isinstance(value, (bytes, bytearray)):
            if value:
                reg.cell(off, width=len(value)).write(int.from_bytes(value, lay.endian))  # the layout endian round-trips the exact bytes
            return off + len(value)
        if isinstance(value, (list, tuple)):
            for item in value:
                off = write(off, item)
            return off
        reg.cell(off).write(value)  # ints and symbolic values ride the region word
        return off + eff_word

    if isinstance(spec, (str, bytes, bytearray)):
        write(0, spec)  # top-level bytes are the flat payload, not per-byte words; str refuses whole, naming the b'...' spelling
    elif isinstance(spec, typing.Mapping):
        for key in spec:
            if isinstance(key, bool) or not isinstance(key, int):
                raise cento.errors.PlacementError(f"{name}: fit keys are int byte offsets, got {type(key).__name__}")
            write(key, spec[key])
    else:
        off = 0
        for value in spec:
            off = write(off, value)
    return reg
