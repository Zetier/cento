# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""cento-native gadget catalog (schema v2): the gadget dialect IS cento.gadget.spec_dict's shape."""

from __future__ import annotations

import difflib
import hashlib
import json
import typing

import cento.cells
import cento.checks
import cento.errors
import cento.gadget
import cento.machine
import cento.views

SCHEMA_SUPPORTED = 2

_WIDTHS: dict[int, type[cento.views.Width]] = {1: cento.views.u8, 2: cento.views.u16, 4: cento.views.u32, 8: cento.views.u64}


def _parse_slot(name: str) -> cento.machine.Slot:
    """Catalog slot spelling -> machine slot: the role names, then the PPC32 enum, then a string slot."""
    if name == "SP":
        return cento.machine.Role.SP
    if name == "PC":
        return cento.machine.Role.PC
    try:
        return cento.machine.norm_slot(cento.machine.Reg[name])
    except KeyError:
        return name


class GadgetSet:
    """Lazy gadget factory over one catalog set: attribute access materializes a Gadget class;
    crosscheck() judges any gadget against the set (CHK-301/302/303)."""

    def __init__(self, set_name: str, entries: dict[str, typing.Any], unspecced: tuple[str, ...] = ()) -> None:
        self.set_name = set_name
        self._entries = entries
        self.unspecced = unspecced  # names present in the catalog's unspecced block: known, refusing, promotable
        self._cache: dict[str, cento.gadget.GadgetMeta] = {}

    def __getattr__(self, name: str) -> cento.gadget.GadgetMeta:
        if name.startswith("_"):
            raise AttributeError(name)
        if name in self._cache:
            return self._cache[name]
        spec = self._entries.get(name)
        if spec is None:
            if name in self.unspecced:
                raise cento.errors.CatalogError(
                    f"gadget set {self.set_name!r}: {name!r} is unspecced in this catalog -- write its restores to promote it into the gadget set"
                )
            hint = difflib.get_close_matches(name, sorted({*self._entries, *self.unspecced}), n=1)
            extra = f"; did you mean {hint[0]!r}?" if hint else ""
            raise AttributeError(f"gadget set {self.set_name!r} has no gadget {name!r}{extra}")
        for req in ("entry", "restores"):
            if req not in spec:
                raise cento.errors.CatalogError(f"gadget set {self.set_name!r}: entry {name!r} is missing {req!r} -- schema-2 gadgets declare it")
        if spec.get("frame_base", "SP") == "SP" and "stride" not in spec:
            raise cento.errors.CatalogError(
                f"gadget set {self.set_name!r}: SP-frame gadget {name!r} has no 'stride' -- deriving it from field extent would fail open on chain math"
            )
        ns: dict[str, typing.Any] = {}
        for attr, r in spec["restores"].items():
            width_n = r.get("width", 4)
            width = _WIDTHS.get(width_n)
            if width is None:
                raise cento.errors.CatalogError(f"gadget set {self.set_name!r}: {name}.{attr} width {width_n!r} is not one of 1/2/4/8")
            ns[attr] = cento.gadget.Restores(_parse_slot(r["reg"]), at=r["at"], width=width, external=bool(r.get("external", False)))
        for i, cslot in enumerate(spec.get("clobbers", [])):
            ns[f"_clob_{i}"] = cento.gadget.Clobbers(_parse_slot(cslot))
        ns["needs"] = {_parse_slot(k): v for k, v in spec.get("needs", {}).items()}
        raw_entry = spec["entry"]
        entry: int | cento.cells.Ref = raw_entry if isinstance(raw_entry, int) else cento.gadget.parse_entry(raw_entry)
        cls = cento.gadget.GadgetMeta(
            str(spec.get("name", name)),
            (cento.gadget.Gadget,),
            ns,
            entry=entry,
            stride=spec.get("stride"),
            reentry_safe=bool(spec.get("reentry_safe", False)),
            frame_base=_parse_slot(str(spec.get("frame_base", "SP"))),
            entry_sp_mod=spec.get("entry_sp_mod"),
            sp_pivot=bool(spec.get("sp_pivot", False)),
        )
        self._cache[name] = cls
        return cls

    def crosscheck(self, gadget_cls: cento.gadget.GadgetMeta) -> tuple[list[cento.checks.Issue], list[cento.checks.Issue]]:
        errs: list[cento.checks.Issue] = []
        warns: list[cento.checks.Issue] = []
        spec = self._entries.get(gadget_cls.gname)
        if spec is None:
            warns.append(
                cento.checks.Issue(
                    "CHK-303", (gadget_cls.gname, self.set_name), "gadget not in catalog (unverified)", "add it to the catalog or load it FROM the catalog"
                )
            )
            return errs, warns

        def _entry_c(e: int | str | cento.cells.Ref) -> int | str:
            return e if isinstance(e, (int, str)) else cento.gadget.entry_str(e)

        def _entry_render(e: int | str) -> str:
            return f"{e:#x}" if isinstance(e, int) else e

        if _entry_c(gadget_cls.entry) != _entry_c(spec["entry"]):
            errs.append(
                cento.checks.Issue(
                    "CHK-301",
                    (gadget_cls.gname,),
                    f"entry {_entry_render(_entry_c(gadget_cls.entry))} != catalog {_entry_render(_entry_c(spec['entry']))}",
                    "the catalog re-derivation is authoritative; update the inline gadget",
                )
            )
        declared_restores = set(gadget_cls.frame.__fields__)
        for attr, r in spec["restores"].items():
            declared_restores.discard(attr)
            f = gadget_cls.frame.__fields__.get(attr)
            rr = None if f is None else _restore_reg(gadget_cls, f)
            reg_ok = rr is not None and cento.machine.slot_name(rr) == r["reg"]
            cat_width = int(r.get("width", 4))
            cat_ext = bool(r.get("external", False))
            if f is None or f.offset != r["at"] or f.external != cat_ext or f.width.size != cat_width or not reg_ok:
                got = (
                    "missing"
                    if f is None
                    else f"reg={cento.machine.slot_name(rr) if rr is not None else None}, at=0x{f.offset:x}, width={f.width.size}, external={f.external}"
                )
                errs.append(
                    cento.checks.Issue(
                        "CHK-302",
                        (gadget_cls.gname, attr),
                        f"restores field drift: catalog reg={r['reg']}, at=0x{r['at']:x}, width={cat_width}, external={cat_ext}; gadget has {got}",
                        "update the inline gadget to match the catalog geometry",
                    )
                )
        for attr in sorted(declared_restores):  # phantom inline restores the catalog never derived: the same drift class, other direction
            errs.append(
                cento.checks.Issue(
                    "CHK-302",
                    (gadget_cls.gname, attr),
                    f"gadget declares restore {attr!r} the catalog does not have -- the bytes were never shown to perform it",
                    "update the inline gadget to match the catalog geometry",
                )
            )
        hint = "update the inline gadget to match the catalog; the catalog re-derivation is authoritative"
        if "stride" in spec and gadget_cls.stride != spec["stride"]:  # pointer-frame entries carry no stride key
            errs.append(
                cento.checks.Issue(
                    "CHK-302", (gadget_cls.gname, "stride"), f"stride drift: catalog 0x{spec['stride']:x}, gadget has 0x{gadget_cls.stride:x}", hint
                )
            )
        cat_fb = str(spec.get("frame_base", "SP"))
        got_fb = gadget_cls.transfer.frame_base
        if cento.machine.slot_name(got_fb) != cat_fb:
            got_fb_name = cento.machine.slot_name(got_fb)
            errs.append(cento.checks.Issue("CHK-302", (gadget_cls.gname, "frame_base"), f"frame_base drift: catalog {cat_fb}, gadget has {got_fb_name}", hint))
        cat_rs = bool(spec.get("reentry_safe", False))
        if gadget_cls.transfer.reentry_safe != cat_rs:
            errs.append(
                cento.checks.Issue(
                    "CHK-302", (gadget_cls.gname, "reentry_safe"), f"reentry_safe drift: catalog {cat_rs}, gadget has {gadget_cls.transfer.reentry_safe}", hint
                )
            )
        if gadget_cls.entry_sp_mod != spec.get("entry_sp_mod"):
            errs.append(
                cento.checks.Issue(
                    "CHK-302",
                    (gadget_cls.gname, "entry_sp_mod"),
                    f"entry_sp_mod drift: catalog {spec.get('entry_sp_mod')}, gadget has {gadget_cls.entry_sp_mod}",
                    hint,
                )
            )
        if gadget_cls.sp_pivot != bool(spec.get("sp_pivot", False)):
            errs.append(
                cento.checks.Issue(
                    "CHK-302",
                    (gadget_cls.gname, "sp_pivot"),
                    f"sp_pivot drift: catalog {bool(spec.get('sp_pivot', False))}, gadget has {gadget_cls.sp_pivot}",
                    hint,
                )
            )
        cat_needs = {cento.machine.slot_name(_parse_slot(str(k))): v for k, v in spec.get("needs", {}).items()}
        got_needs = {cento.machine.slot_name(k): v for k, v in gadget_cls.transfer.needs.items()}
        if got_needs != cat_needs:
            errs.append(cento.checks.Issue("CHK-302", (gadget_cls.gname, "needs"), f"needs drift: catalog {cat_needs!r}, gadget has {got_needs!r}", hint))
        return errs, warns


def _restore_reg(gadget_cls: cento.gadget.GadgetMeta, field: cento.views.Field) -> cento.machine.Slot | None:
    """The register a frame field restores into, per the gadget's own transfer (None if not a Load)."""
    for slot, ctl in gadget_cls.transfer.controls.items():
        if getattr(ctl, "field", None) is field:
            return slot
    return None


class Catalog:
    """A loaded gadget-catalog file (schema v2): Catalog.load(path) parses and version-checks; gadgets(set_name) returns the named GadgetSet."""

    def __init__(self, data: dict[str, typing.Any], path: str) -> None:
        self.data = data
        self.path = path
        self.target = str(data.get("target", ""))
        self.sha256: str | None = None  # FULL content digest of the loaded file; None for dict-built catalogs
        self._sets: dict[str, GadgetSet] = {}

    @classmethod
    def load(cls, path: str) -> Catalog:
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
            data = json.loads(raw.decode("ascii"))
        except OSError as exc:
            raise cento.errors.CatalogError(f"cannot read catalog {path!r}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise cento.errors.CatalogError(f"catalog {path!r} is not valid JSON: {exc}") from exc
        schema = data.get("schema")
        if schema == 1:
            raise cento.errors.CatalogError(
                f"catalog {path!r}: schema 1 unsupported -- regenerate entries from cento.gadget.spec_dict (schema 2 IS that shape)"
            )
        if schema != SCHEMA_SUPPORTED:
            raise cento.errors.CatalogError(f"catalog {path!r}: schema {schema} unsupported (cento supports schema {SCHEMA_SUPPORTED})")
        cat = cls(data, path)
        cat.sha256 = hashlib.sha256(raw).hexdigest()
        return cat

    def gadgets(self, set_name: str) -> GadgetSet:
        if set_name in self._sets:
            return self._sets[set_name]
        sets = self.data.get("gadget_sets", {})
        if set_name not in sets:
            hint = difflib.get_close_matches(set_name, sorted(sets), n=1)
            extra = f"; did you mean {hint[0]!r}?" if hint else ""
            raise cento.errors.CatalogError(f"catalog has no gadget set {set_name!r}{extra}")
        self._sets[set_name] = GadgetSet(set_name, sets[set_name], unspecced=tuple(sorted(self.data.get("unspecced", {}).get(set_name, {}))))
        return self._sets[set_name]
