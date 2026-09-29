# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Cell values and the symbol environment.

The value types a cell can hold (ints, symbolic Refs, Delta arithmetic, Reduce computed
values, runtime Writebacks), the Env that binds symbols with provenance, the reducer
registry, and the de Bruijn cycle pattern. Tool-author surface: normal users touch these
through the facade (cento.length, cento.cycle_find, ...), layout.sym(), and region handles.
"""

from __future__ import annotations

import dataclasses
import enum
import itertools
import types
import typing

import cento.errors

Endian = typing.Literal["big", "little"]


class Xform(enum.Enum):
    ADDR = "addr"
    LO16 = "lo16"
    HI16 = "hi16"
    HA16 = "ha16"


@dataclasses.dataclass(frozen=True)
class Delta:
    """pos - neg + addend. Masked to cell width at encode time (wrap semantics)."""

    pos: Ref
    neg: Ref
    addend: int = 0

    def __add__(self, k: int) -> Delta:
        if isinstance(k, bool) or not isinstance(k, int):
            raise cento.errors.PlacementError(f"Delta offset must be an int byte offset, got {type(k).__name__}")
        return dataclasses.replace(self, addend=self.addend + k)

    def __sub__(self, k: int) -> Delta:
        return self.__add__(-k)


@dataclasses.dataclass(frozen=True)
class Ref:
    """Symbolic reference: xform(value(sym) + addend)."""

    sym: str
    addend: int = 0
    xform: Xform | str = Xform.ADDR  # builtin Xform member, or a layout-registered name (see Layout.register_xform)

    def __add__(self, k: int) -> Ref:
        if isinstance(k, Ref):
            raise cento.errors.PlacementError("Ref + Ref: addresses do not add; subtract (Ref - Ref) for a Delta, or add an int byte offset")
        if isinstance(k, bool) or not isinstance(k, int):
            raise cento.errors.PlacementError(f"Ref + {type(k).__name__}: the addend must be an int byte offset, got {type(k).__name__}")
        return dataclasses.replace(self, addend=self.addend + k)

    @typing.overload
    def __sub__(self, other: int) -> Ref: ...

    @typing.overload
    def __sub__(self, other: Ref) -> Delta: ...

    def __sub__(self, other: object) -> Ref | Delta:
        if isinstance(other, int):
            return self.__add__(-other)
        if not isinstance(other, Ref):
            return NotImplemented
        return Delta(pos=self, neg=other)


@dataclasses.dataclass(frozen=True)
class Span:
    """Byte range [start, end) within a region; ends may be symbolic."""

    region: str
    start: int | Ref
    end: int | Ref


@dataclasses.dataclass(frozen=True)
class Reduce:
    """Computed cell: reducer fn over a span's bytes. expect=None emits the value; expect=N checks it (CHK-005)."""

    fn: str
    span: Span
    expect: int | None = None


def _ref_only(fn: str, ref: Ref, int_hint: str) -> Ref:
    if not isinstance(ref, Ref):
        raise cento.errors.PlacementError(
            f"{fn} takes a Ref (layout.sym(...) / region.addr(...)), got {type(ref).__name__}; for a concrete int compute {int_hint}"
        )
    return ref


def lo16(ref: Ref) -> Ref:
    """Low 16 bits of the resolved value, as a Ref: lo16(layout.sym("x")). Takes a Ref, not a bare symbol string."""
    return dataclasses.replace(_ref_only("lo16", ref, "value & 0xffff"), xform=Xform.LO16)


def hi16(ref: Ref) -> Ref:
    """High 16 bits of the resolved value, as a Ref: hi16(layout.sym("x")). Takes a Ref, not a bare symbol string."""
    return dataclasses.replace(_ref_only("hi16", ref, "(value >> 16) & 0xffff"), xform=Xform.HI16)


def ha16(ref: Ref) -> Ref:
    """High-adjusted 16 bits (carry-compensated, for lis/addi pairs) of the resolved value, as
    a Ref: ha16(layout.sym("x")). Takes a Ref, not a bare symbol string."""
    return dataclasses.replace(_ref_only("ha16", ref, "((value >> 16) + ((value >> 15) & 1)) & 0xffff"), xform=Xform.HA16)


@dataclasses.dataclass(frozen=True)
class Binding:
    """A bound symbol: the value plus its provenance (Env.generation orders rebinds)."""

    value: int
    source: str


class Env:
    """Symbol table with provenance. Bind/rebind bumps the generation counter."""

    def __init__(self) -> None:
        self._bindings: dict[str, Binding] = {}
        self.generation = 0
        self.xforms: dict[str, typing.Callable[[int], int]] = {}  # layout-scoped xform names (see Layout.register_xform)

    def bind(self, sym: str, value: int, *, source: str = "manual") -> None:
        self._bindings[sym] = Binding(value=value, source=source)
        self.generation += 1

    def binding(self, sym: str) -> Binding | None:
        """The full Binding record (value + source provenance), or None while unbound."""
        return self._bindings.get(sym)

    def get(self, sym: str) -> int | None:
        b = self._bindings.get(sym)
        return None if b is None else b.value

    def bindings(self) -> dict[str, Binding]:
        return dict(self._bindings)


@dataclasses.dataclass(frozen=True)
class Residual:
    """What forcing a cell (computing its bytes -- Layout.force()) yields while symbols are
    unbound: the missing names. Returned, never raised."""

    missing: frozenset[str]


@dataclasses.dataclass(frozen=True)
class Writeback:
    """Target-write promise and cell value: the runtime writes this value during execution.

    Lifecycle split: a Writeback-valued cell is EXCLUDED from
    emission (never emitted, never a fixup, never pending) and from layout.pending(), and it
    is legal (ignored) at plan.finalize()/ARM time. Chains derive a per-hop effect from such
    cells at fold time (Chain.fold(), the chain's dataflow recomputation), so downstream
    restores see the value flow (kind "writeback").
    discarded=True (via Writeback.discard(reason)) means the write lands but nobody consumes
    it: the fold records a clobber plus an auto clobber-waiver carrying the reason.
    """

    name: str
    discarded: bool = False

    @classmethod
    def discard(cls, reason: str) -> Writeback:
        return cls(name=reason, discarded=True)


@dataclasses.dataclass(frozen=True)
class Promised:
    """Forcing outcome for a Writeback cell: no build-time bytes, by design (distinct from Residual).

    force() never throws; consumers that need bytes treat Promised like Residual-but-legal.
    """

    name: str


Scalar = int | Ref | Delta


def _apply_xform(value: int, xform: Xform | str, env: Env) -> int:
    if isinstance(xform, str):
        fn = env.xforms.get(xform)
        if fn is None:
            raise cento.errors.XformError(f"unknown xform {xform!r} -- register_xform() on the layout that resolves this cell")
        return fn(value)
    if xform is Xform.LO16:
        return value & 0xFFFF
    if xform is Xform.HI16:
        return (value >> 16) & 0xFFFF
    if xform is Xform.HA16:
        return ((value >> 16) + ((value >> 15) & 1)) & 0xFFFF
    return value


def resolve(value: Scalar, env: Env, deps: set[str] | None = None) -> int | Residual:
    """Resolve a scalar against env, recording every touched symbol into deps."""
    if isinstance(value, bool):
        raise cento.errors.ResolveError("bool is not a cell value")
    if isinstance(value, int):
        return value
    if isinstance(value, Ref):
        if deps is not None:
            deps.add(value.sym)
        v = env.get(value.sym)
        if v is None:
            return Residual(missing=frozenset({value.sym}))
        return _apply_xform(v + value.addend, value.xform, env)
    if isinstance(value, Delta):
        pos = resolve(value.pos, env, deps)
        neg = resolve(value.neg, env, deps)
        if isinstance(pos, Residual) or isinstance(neg, Residual):
            missing = (pos.missing if isinstance(pos, Residual) else frozenset()) | (neg.missing if isinstance(neg, Residual) else frozenset())
            return Residual(missing=missing)
        return pos - neg + value.addend
    raise cento.errors.ResolveError(f"unresolvable value type: {type(value).__name__}")


def _r_crc32_mpeg2(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if crc & 0x80000000 else (crc << 1) & 0xFFFFFFFF
    return crc


def _r_xor_fold(data: bytes) -> int:
    if len(data) % 4:
        data = data + b"\x00" * (4 - len(data) % 4)
    out = 0
    for i in range(0, len(data), 4):
        out ^= int.from_bytes(data[i : i + 4], "big")
    return out


def _r_sum16(data: bytes) -> int:
    if len(data) % 2:
        data = data + b"\x00"
    return sum(int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2)) & 0xFFFF


def _r_udp_cksum(data: bytes) -> int:
    if len(data) % 2:
        data = data + b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += int.from_bytes(data[i : i + 2], "big")
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _r_crc8(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def _r_length(data: bytes) -> int:
    return len(data)


REDUCERS: typing.Mapping[str, typing.Callable[[bytes], int]] = types.MappingProxyType(
    {
        "crc32_mpeg2": _r_crc32_mpeg2,
        "xor_fold": _r_xor_fold,
        "sum16": _r_sum16,
        "udp_cksum": _r_udp_cksum,
        "crc8": _r_crc8,
        "length": _r_length,
    }
)


class HasSpan(typing.Protocol):
    """Anything carrying a byte range -- View/Array/Cell handles all qualify via their .span property."""

    @property
    def span(self) -> Span: ...


def _as_span(span: Span | HasSpan) -> Span:
    if isinstance(span, Span):
        return span
    inner = getattr(span, "span", None)
    if not isinstance(inner, Span):
        raise cento.errors.PlacementError(f"a computed cell takes a Span or a placed handle (region[a:b], or anything with .span), got {type(span).__name__}")
    return inner


def crc32_mpeg2(span: Span | HasSpan, expect: int | None = None) -> Reduce:
    """CRC32/MPEG-2 over a span (or anything with .span), as a lazy cell value; expect= pins it (CHK-005 on mismatch)."""
    return Reduce(fn="crc32_mpeg2", span=_as_span(span), expect=expect)


def xor_fold(span: Span | HasSpan, expect: int | None = None) -> Reduce:
    """XOR of the span's 32-bit words, as a lazy cell value; expect= pins it (CHK-005 on mismatch)."""
    return Reduce(fn="xor_fold", span=_as_span(span), expect=expect)


def sum16(span: Span | HasSpan, expect: int | None = None) -> Reduce:
    """16-bit sum of the span's halfwords, as a lazy cell value; expect= pins it (CHK-005 on mismatch)."""
    return Reduce(fn="sum16", span=_as_span(span), expect=expect)


def udp_cksum(span: Span | HasSpan, expect: int | None = None) -> Reduce:
    """UDP-style ones-complement checksum (RFC 1071 arithmetic) over the span, as a lazy cell value; expect= pins it (CHK-005 on mismatch)."""
    return Reduce(fn="udp_cksum", span=_as_span(span), expect=expect)


def crc8(span: Span | HasSpan, expect: int | None = None) -> Reduce:
    """CRC-8 (poly 0x07) over the span, as a lazy cell value; expect= pins it (CHK-005 on mismatch)."""
    return Reduce(fn="crc8", span=_as_span(span), expect=expect)


def length(span: Span | HasSpan, expect: int | None = None) -> Reduce:
    """The span's byte length, as a lazy cell value (lengths derive, never drift); expect= pins it (CHK-005 on mismatch).

    The span must not cover the length cell itself (a reduce may not cover its own cell):
    measure a sibling placement -- hdr.len = cento.length(body) -- not the view the cell lives in.
    """
    return Reduce(fn="length", span=_as_span(span), expect=expect)


# -- de Bruijn cycle pad (pwntools-cycle analog) ------------------------------
#
# Pure byte-pattern functions, NOT a new CellValue: the value algebra stays
# closed. Region integration is a usage idiom (cells hold ints), documented
# on cycle()/cycle_find() below and verified by test_cycle.py.

CYCLE_ALPHABET = b"abcdefghijklmnopqrstuvwxyz"


def _check_cycle_params(alphabet: bytes, n: int) -> None:
    if not alphabet:
        raise ValueError("de_bruijn: alphabet must be non-empty bytes")
    if len(set(alphabet)) != len(alphabet):
        raise ValueError("de_bruijn: alphabet bytes must be unique -- duplicates would break subsequence uniqueness")
    if n < 1:
        raise ValueError(f"de_bruijn: n must be >= 1 (got {n})")


def _de_bruijn_bytes(alphabet: bytes, n: int) -> typing.Iterator[int]:
    # Standard FKM construction: concatenate, in lexicographic order, every
    # Lyndon word over the alphabet whose length divides n. Recursion depth <= n + 1.
    k = len(alphabet)
    a = [0] * (k * n)

    def db(t: int, p: int) -> typing.Iterator[int]:
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    yield alphabet[a[j]]
        else:
            a[t] = a[t - p]
            yield from db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                yield from db(t + 1, t)

    yield from db(1, 1)


def de_bruijn(alphabet: bytes = CYCLE_ALPHABET, n: int = 4) -> typing.Iterator[int]:
    """Byte stream of the de Bruijn sequence B(k, n) over `alphabet` (k = len(alphabet)).

    Every possible n-byte subsequence over the alphabet appears exactly once per
    k**n-byte period (treating the sequence as cyclic), which is what makes a
    prefix of it a self-locating pad: any n bytes read back name their offset.
    Parameter errors raise ValueError eagerly (before iteration).
    """
    _check_cycle_params(alphabet, n)
    return _de_bruijn_bytes(alphabet, n)


def cycle(length: int, *, alphabet: bytes = CYCLE_ALPHABET, n: int = 4) -> bytes:
    """First `length` bytes of the de Bruijn sequence B(len(alphabet), n).

    The pattern's period is len(alphabet)**n bytes (456976 for the defaults);
    asking for more is refused with ValueError rather than silently repeating,
    because repeated bytes would make cycle_find() offsets ambiguous.

    Region integration is packaged as Region.pad() (one word per cell; cells hold
    ints, not raw bytes -- the value algebra is closed). The hand-rolled equivalent::

        pad = cento.cycle(64)
        for i in range(0, len(pad), 4):
            page.cell(off + i).write(int.from_bytes(pad[i : i + 4], "little"))

    ("little" matches cento's little-endian default; pass the layout's endian for big-endian targets.)
    """
    _check_cycle_params(alphabet, n)
    period = len(alphabet) ** n
    if length < 0:
        raise ValueError(f"cycle: length must be >= 0 (got {length})")
    if length > period:
        raise ValueError(
            f"cycle: length {length} exceeds the pattern period {len(alphabet)}**{n} = {period}; "
            "beyond one period the bytes repeat and cycle_find() offsets become ambiguous -- "
            "use a larger alphabet or a larger n instead"
        )
    return bytes(itertools.islice(_de_bruijn_bytes(alphabet, n), length))


def cycle_find(needle: bytes | int, *, width: int = 4, endian: Endian = "little", alphabet: bytes = CYCLE_ALPHABET, n: int = 4) -> int:
    """Offset of an n-byte subsequence within the cycle() pattern.

    An int needle (e.g. a register value observed in a crash) is converted with
    int.to_bytes(width, endian). cento's default is LITTLE-endian (the x86-64-flavored
    default target); on a big-endian target a register loads the pad bytes in order, so
    pass endian="big" there (the classic pwntools `cyclic_find(..., endian)` flip).

    Raises ValueError with a teaching message when the needle is the wrong
    length, does not fit the width, or does not occur in the pattern.
    """
    if isinstance(needle, str):
        raise ValueError("cycle_find: needle is str; pass bytes (b'aaaa') or the int register value")
    if isinstance(needle, bool):
        raise ValueError("cycle_find: bool is not a needle; pass bytes or an int register value")
    if isinstance(needle, int):
        try:
            needle_bytes = needle.to_bytes(width, endian)
        except OverflowError as exc:
            raise ValueError(f"cycle_find: needle {needle:#x} does not fit in width={width} unsigned bytes ({endian}-endian)") from exc
    else:
        needle_bytes = bytes(needle)
    if len(needle_bytes) != n:
        raise ValueError(f"cycle_find: needle must be exactly n={n} bytes, got {len(needle_bytes)}; for int needles set width= to match n")
    _check_cycle_params(alphabet, n)
    period = len(alphabet) ** n
    sequence = bytes(itertools.islice(_de_bruijn_bytes(alphabet, n), period))
    offset = sequence.find(needle_bytes)
    if offset < 0:
        raise ValueError(
            f"cycle_find: needle {needle_bytes!r} not found in the {period}-byte pattern; "
            "check the alphabet/n match the pad you emitted, and remember little-endian "
            'targets need endian="little" for int needles'
        )
    return offset
