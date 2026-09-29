# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Struct-over-bytes view types: class-declared fields compiling to a data schema."""

from __future__ import annotations

import dataclasses
import sys
import typing


class WidthMeta(type):
    """Width classes multiply into arrays: u32 * 4 is a WidthArray of four cells (like SomeView * 2 -> ArraySpec)."""

    def __mul__(cls, count: int) -> WidthArray:
        if isinstance(count, bool) or not isinstance(count, int):
            raise TypeError(f"{cls.__name__} * count: count must be an int, got {type(count).__name__}")
        if count < 1:
            raise ValueError(f"{cls.__name__} * {count}: an array field needs at least one element")
        return WidthArray(elem=typing.cast("type[Width]", cls), count=count)


class Width(metaclass=WidthMeta):
    """A cell width, as a type: annotate fields (op: u32), or pass to Field (Field(u32) / Field(0x8, u32)).

    Signed widths (i8..i64) accept negative literals and emit them in two's complement; literal
    writes to any width-declared field are range-checked (an overflow is a typo, not a wrap).
    """

    size: typing.ClassVar[int] = 0
    signed: typing.ClassVar[bool] = False
    # Typing surface only, never set here: at runtime an annotation-declared name (`lr: u32`)
    # resolves to a packed Field class attribute, so `View.field.offset` must type-check as an int
    # -- Field mirrors size/signed as properties, keeping the two read surfaces aligned.
    offset: int


class u8(Width):
    size = 1


class u16(Width):
    size = 2


class u32(Width):
    size = 4


class u64(Width):
    size = 8


class i8(Width):
    size = 1
    signed = True


class i16(Width):
    size = 2
    signed = True


class i32(Width):
    size = 4
    signed = True


class i64(Width):
    size = 8
    signed = True


@dataclasses.dataclass(frozen=True)
class WidthArray:
    """N scalar cells at elem-size stride: u32 * 4, as Field(u32 * 4) or the annotation `regs: u32 * 4`.

    The annotation spelling is runtime-only (an expression, not a type): mypy --strict flags it
    [valid-type], so under a typing gate use the Field form or a `# type: ignore[valid-type]`.
    """

    elem: type[Width]
    count: int

    @property
    def size(self) -> int:
        """The field's total extent -- the uniform accessor shared with Width.size and Bytes.size."""
        return self.elem.size * self.count


@dataclasses.dataclass(frozen=True)
class Bytes:
    """A fixed-length byte-string field: name = Field(0x10, Bytes(16)). Writes take exactly
    `size` bytes; field reads return the packed int (cells hold ints) -- read the string back
    from the emitted image.

    Stored as one size-wide cell, packed with the layout's endianness at write time, so the emitted
    image is byte-identical to the string on either endianness and the hexdump shows one attributed
    cell (not `size` fragments). Spelled Field(Bytes(16)) or the annotation `name: Bytes(16)` --
    the annotation is runtime-only (an expression, not a type; mypy --strict flags it [valid-type]).
    """

    size: int


# What a Field's width can be: a scalar Width type, an array of them, or a byte string.
FieldWidth = type[Width] | WidthArray | Bytes


@dataclasses.dataclass(frozen=True, init=False)
class Field:
    """A named cell slot. Field(0x8, u32) pins the offset; Field(u32) packs at the next free one.

    external=True: lies outside the view's extent (e.g. PPC LR-in-caller-frame).
    For gap-free views, the annotation form (op: u32) is the whole declaration; with a value
    (op: u32 = sym + 0x40) it declares AND assigns -- placing the view writes the default.
    Field(..., default=...) is the same thing for pinned/typed spellings.
    """

    offset: int  # None only transiently, for Field(width) autos, until ViewMeta packs the class body
    width: FieldWidth
    external: bool = False
    doc: str = ""
    alias: str | None = None
    default: object | None = None  # written at placement time by Region.at()/alloc(); None = unset

    @typing.overload
    def __init__(
        self, offset: int, width: FieldWidth, /, *, external: bool = False, doc: str = "", alias: str | None = None, default: object | None = None
    ) -> None: ...
    @typing.overload
    def __init__(self, width: FieldWidth, /, *, external: bool = False, doc: str = "", alias: str | None = None, default: object | None = None) -> None: ...
    def __init__(
        self,
        offset: int | FieldWidth,
        width: FieldWidth | None = None,
        /,
        *,
        external: bool = False,
        doc: str = "",
        alias: str | None = None,
        default: object | None = None,
    ) -> None:
        resolved_offset: int | None
        if width is None:  # Field(width): auto-offset, next free slot
            if not (isinstance(offset, (WidthArray, Bytes)) or (isinstance(offset, type) and issubclass(offset, Width))):
                raise TypeError("Field(offset, width): width missing (or use Field(width) / a `name: u32` annotation to auto-pack)")
            resolved_offset, resolved_width = None, offset
        else:
            if isinstance(offset, bool) or not isinstance(offset, int):
                raise TypeError(f"Field(offset, width): offset must be an int when width is given, got {type(offset).__name__}")
            if not (isinstance(width, (WidthArray, Bytes)) or (isinstance(width, type) and issubclass(width, Width))):
                raise TypeError(
                    f"Field(offset, width): width is not width-shaped (u8..u64 / i8..i64, u32 * 4, Bytes(16)), got {width!r}"
                    " -- a bare byte count means Bytes(n); a scalar cell is its width type (u32, not 4)"
                )
            resolved_offset, resolved_width = offset, width
        if external and default is not None:
            raise TypeError("Field(external=True) takes no default: external cells belong to another placement")
        object.__setattr__(self, "offset", resolved_offset)
        object.__setattr__(self, "width", resolved_width)
        object.__setattr__(self, "external", external)
        object.__setattr__(self, "doc", doc)
        object.__setattr__(self, "alias", alias)
        object.__setattr__(self, "default", default)

    @property
    def size(self) -> int:
        """Total byte size (width.size) -- mirrors Width.size, so runtime Fields satisfy the annotation typing surface."""
        return self.width.size

    @property
    def signed(self) -> bool:
        """The scalar width's signedness (arrays/Bytes are unsigned) -- mirrors Width.signed."""
        return self.width.signed if isinstance(self.width, type) else False


@dataclasses.dataclass(frozen=True)
class ArraySpec:
    """N contiguous views at a stride (default: the view size)."""

    viewtype: ViewMeta
    count: int
    stride: int | None = None

    @property
    def eff_stride(self) -> int:
        return self.stride if self.stride is not None else self.viewtype.__size__

    @property
    def extent(self) -> int:
        return self.count * self.eff_stride


def _annotation_widths(name: str, ns: dict[str, typing.Any]) -> dict[str, FieldWidth]:
    """Width-shaped annotations in a class body -- the gap-free field declaration form.

    Accepted: a Width type (op: u32), a width array (regs: u32 * 4), or a byte string
    (name: Bytes(16)). The latter two are runtime-only spellings: they are expressions, not
    types, so mypy --strict flags them [valid-type] -- under a typing gate, use the Field form
    or a `# type: ignore[valid-type]`.

    Under `from __future__ import annotations` the values are strings; they are resolved in the
    class's own module (as typing.get_type_hints would). Every annotation must be width-shaped: a typo
    here would otherwise silently drop a field. Escapes for non-field class data: ClassVar[...]
    or a leading-underscore name.
    """
    out: dict[str, FieldWidth] = {}
    mod = sys.modules.get(ns.get("__module__", ""))
    for attr, ann in ns.get("__annotations__", {}).items():
        if attr.startswith("_"):
            continue
        obj: typing.Any = ann
        if isinstance(ann, str):
            try:
                obj = eval(ann, dict(getattr(mod, "__dict__", {})))  # the class author's own annotation, in their own namespace
            except Exception as e:
                raise ValueError(f"{name}.{attr}: cannot resolve annotation {ann!r} ({e}); fields are `name: u32` or `name = Field(...)`") from e
        if obj is typing.ClassVar or typing.get_origin(obj) is typing.ClassVar:
            continue
        if (isinstance(obj, type) and issubclass(obj, Width)) or isinstance(obj, (WidthArray, Bytes)):
            out[attr] = obj
            continue
        raise ValueError(
            f"{name}.{attr}: annotation {ann!r} is not width-shaped (u8..u64 / i8..i64, u32 * 4, Bytes(16));"
            " fields are `name: u32` or `name = Field(...)`; mark non-field class data ClassVar (or use a leading underscore)"
        )
    return out


class ViewMeta(type):
    __fields__: dict[str, Field]
    __aliases__: dict[str, str]
    __size__: int
    __dense__: bool

    def __new__(mcls, name: str, bases: tuple[type, ...], ns: dict[str, typing.Any], size: int | None = None, dense: bool = False) -> ViewMeta:
        cls = super().__new__(mcls, name, bases, ns)
        reserved = {
            "addr",
            "span",
            "offset",
            "path",
            "overlay",
        }  # the ViewHandle surface: a field by these names would write bytes but read back the handle attribute
        fields: dict[str, Field] = {}
        for base in reversed(bases):  # MRO order: nearer bases override farther ones, like attribute lookup
            fields.update(getattr(base, "__fields__", {}))
        cursor = max((f.offset + f.width.size for f in fields.values() if not f.external), default=0)  # next free offset
        assigned = {attr: val for attr, val in ns.items() if isinstance(val, Field)}
        annotated = _annotation_widths(name, ns)
        for attr, width in annotated.items():
            if attr in reserved:
                raise ValueError(f"{name}.{attr}: field name collides with the handle surface ({attr!r} is reserved); writes would land, reads would lie")
            default = ns.get(attr)  # `op: u32 = value` declares AND assigns; absent means no default
            if isinstance(default, Field):
                raise ValueError(f"{name}.{attr}: both a width annotation and a Field assignment; pick one spelling")
            field = Field(cursor, width, default=default)
            fields[attr] = field
            setattr(cls, attr, field)
            cursor += width.size
        ann_end = cursor  # mixing rule: assigned Fields may join annotations only at or past this point (source order between the streams is unrecoverable)
        for attr, val in assigned.items():
            if attr in reserved:
                raise ValueError(f"{name}.{attr}: field name collides with the handle surface ({attr!r} is reserved); writes would land, reads would lie")
            if val.offset is None:  # Field(u32): pack at the next free offset
                if annotated:
                    raise ValueError(
                        f"{name}.{attr}: auto-offset Field assignments cannot mix with width annotations (their source order is unrecoverable);"
                        f" pin the offset (Field(0x{cursor:x}, ...)) or declare it as an annotation"
                    )
                if val.external:
                    raise ValueError(f"{name}.{attr}: external fields lie at explicit offsets by definition; Field(offset, width, external=True)")
                val = Field(cursor, val.width, doc=val.doc, alias=val.alias, default=val.default)
                setattr(cls, attr, val)  # the resolved Field is the real class attribute
            elif annotated and val.offset < ann_end:
                raise ValueError(
                    f"{name}.{attr}: pinned at 0x{val.offset:x}, before/inside the annotation-packed run (which ends at 0x{ann_end:x});"
                    " mixed pinned Fields may only sit at or past its end"
                )
            fields[attr] = val
            if not val.external:
                cursor = max(cursor, val.offset + val.width.size)
        cls.__fields__ = fields
        cls.__aliases__ = {f.alias: fname for fname, f in fields.items() if f.alias is not None}
        interior = [f.offset + f.width.size for f in fields.values() if not f.external]
        interior_end = max(interior) if interior else 0
        if size is not None and size < 0:
            raise ValueError(f"{name}: size=0x{size:x} is negative")
        if size is None:
            size = interior_end
        elif fields and size < interior_end:
            raise ValueError(f"{name}: size=0x{size:x} does not cover interior fields (interior end 0x{interior_end:x})")
        cls.__size__ = size
        cls.__dense__ = dense  # dense=True: every non-external field must be written (CHK-010 refuses unset ones)
        return cls

    def __init__(cls, name: str, bases: tuple[type, ...], ns: dict[str, typing.Any], size: int | None = None, dense: bool = False) -> None:
        super().__init__(name, bases, ns)

    def __mul__(cls, count: int) -> ArraySpec:
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise TypeError(f"{cls.__name__} * count: count must be a positive int, got {count!r}")
        return ArraySpec(viewtype=cls, count=count)

    def __len__(cls) -> int:
        """The view's declared byte size: len(SomeView) mirrors len(handle) on placements."""
        return cls.__size__

    def __bool__(cls) -> bool:
        return True  # __len__ would otherwise make zero-size views (external-only frames) falsy


class View(metaclass=ViewMeta):
    """A typed window over region bytes: fields are `name: u32` annotations (auto-packed;
    `name: u32 = value` declares and assigns) or Field(offset, width) for pinned/gapped
    layouts. size= is optional (inferred from the fields) and checked when given. Place with
    region.at(off, MyView, name=...); the handle's attributes read/write the named cells."""
