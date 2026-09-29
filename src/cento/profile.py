# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Target profiles: load device facts once, apply them to every build.

A profile (a JSON file or an inline dict, schema 1) declares a device's endianness, default
fill byte, real-hardware flag, and optionally its abi name, gadget catalog, and set name. cento.target()
parses it into a Target whose layout()/region() constructors pre-configure every build with
those facts, so per-build code never restates them.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
import typing

import cento.abi
import cento.catalog
import cento.cells
import cento.errors
import cento.machine
import cento.regions

PROFILE_SCHEMA = 1


class _NoGadgetsError(cento.errors.CatalogError, AttributeError):
    """Raised when a catalog-less Target is asked for a gadget."""


class _NoGadgets(cento.catalog.GadgetSet):
    """Placeholder gadget set for a Target without a catalog: every gadget lookup raises _NoGadgetsError."""

    def __init__(self) -> None:
        super().__init__("<no catalog>", {})

    def __getattr__(self, name: str) -> typing.NoReturn:
        if name.startswith("_"):
            raise AttributeError(name)
        raise _NoGadgetsError(
            f"target has no catalog: cannot load gadget {name!r} -- add 'catalog' and 'gadget_set' to the profile, or declare the Gadget class by hand"
        )


@dataclasses.dataclass(frozen=True)
class Target:
    """A device profile: build facts (endianness, default fill byte, real-hardware flag) plus
    an optional gadget catalog. layout()/region() construct fresh Layouts pre-configured
    with those facts."""

    name: str
    endian: cento.cells.Endian
    fill: int
    real_hw: bool
    catalog: cento.catalog.Catalog | None = None
    gadgets: cento.catalog.GadgetSet = dataclasses.field(default_factory=_NoGadgets)
    profile_path: str | None = None
    gadget_set_name: str | None = None
    abi: cento.machine.AbiSpec | None = None

    def layout(self, name: str | None = None) -> cento.regions.Layout:
        """A fresh Layout carrying this target's endian, fill, abi, gadget set, and real_hw defaults."""
        layout = cento.regions.Layout(endian=self.endian, name=name, fill_default=self.fill, abi=self.abi)
        layout.gadget_set = None if isinstance(self.gadgets, _NoGadgets) else self.gadgets
        layout.real_hw_default = self.real_hw
        layout.provenance = cento.regions.Provenance(
            target_name=self.name,
            profile_path=self.profile_path,
            catalog_path=self.catalog.path if self.catalog is not None else None,
            catalog_sha256=self.catalog.sha256 if self.catalog is not None else None,
            catalog_target=self.catalog.target if self.catalog is not None else None,
            gadget_set=self.gadget_set_name,
        )
        return layout

    def region(
        self,
        name: str | None = None,
        *,
        base: str | None = None,
        max_size: int | None = None,
        fill: cento.regions.FillLike | None = None,
        pad: int | None = None,
        forbid: cento.regions.FillLike | None = None,
        word: int | None = None,
    ) -> cento.regions.Region:
        """cento.region() with this profile applied: a region on its own fresh Layout.

        Each call constructs a new Layout, reachable as the returned handle's .layout.
        Precedence for word: explicit kwarg > profile abi fact > built-in default (4).
        """
        return self.layout().region(name, base=base, max_size=max_size, fill=fill, pad=pad, forbid=forbid, word=word)


def target(profile: str | pathlib.Path | typing.Mapping[str, object], set_name: str | None = None) -> Target:
    """Bind a target profile: a JSON file path, or an inline dict with the same schema-1 keys.

    The inline form suits targets that need no catalog file::

        T = cento.target({"schema": 1, "name": "local-x86", "endian": "little"})

    "catalog" (with "gadget_set") is optional either way: a profile without one carries device
    facts only, and any gadget access refuses with a teaching error. A file profile resolves
    its "catalog" relative to its own directory; an inline profile has no directory, so a
    catalog path there must be absolute.
    """
    if isinstance(profile, typing.Mapping):
        return _parse_profile(profile, base_dir=None, source="inline profile", set_name=set_name)
    p = pathlib.Path(profile)
    try:
        data = json.loads(p.read_text(encoding="ascii"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise cento.errors.CatalogError(f"cannot read profile {str(profile)!r}: {exc}") from exc
    return _parse_profile(data, base_dir=p.parent, source=f"profile {str(profile)!r}", set_name=set_name, profile_path=str(p))


_PROFILE_KEYS = frozenset({"schema", "name", "endian", "fill", "real_hw", "catalog", "gadget_set", "abi"})


def _parse_profile(
    data: typing.Mapping[str, typing.Any], *, base_dir: pathlib.Path | None, source: str, set_name: str | None, profile_path: str | None = None
) -> Target:
    schema = data.get("schema")
    if schema != PROFILE_SCHEMA:
        raise cento.errors.CatalogError(f"{source}: schema {schema} unsupported (cento supports schema {PROFILE_SCHEMA})")
    unknown = sorted(set(data) - _PROFILE_KEYS)
    if unknown:  # fail closed: a misspelled key ("endain") would otherwise silently take its default
        raise cento.errors.CatalogError(f"{source}: unknown profile keys {unknown}; schema-1 keys are {sorted(_PROFILE_KEYS)}")
    if "name" not in data:
        raise cento.errors.CatalogError(f"{source}: missing 'name' -- a profile names its device")
    abi_spec: cento.machine.AbiSpec | None = None
    if "abi" in data:
        try:
            abi_spec = cento.abi.resolve(data["abi"])
        except cento.errors.PlacementError as exc:  # profile parsing speaks CatalogError; keep the teaching text, add the source
            raise cento.errors.CatalogError(f"{source}: {exc}") from exc
    endian = data.get("endian")
    if "endian" in data and endian not in ("big", "little"):  # presence check, not None check: an explicit null must refuse, not silently default
        raise cento.errors.CatalogError(f"{source}: endian {endian!r} must be 'big' or 'little'")
    if abi_spec is not None and abi_spec.endian is not None:
        if endian is not None and endian != abi_spec.endian:  # fail closed at parse: incoherent device facts never reach a build
            raise cento.errors.CatalogError(
                f"{source}: abi {abi_spec.name!r} is {abi_spec.endian}-endian but the profile declares endian={endian!r}"
                " -- drop one: the abi already carries the fact"
            )
        endian = abi_spec.endian
    if endian is None:
        endian = "little"
    catalog: cento.catalog.Catalog | None = None
    gadgets: cento.catalog.GadgetSet | None = None
    gadget_set_name: str | None = None
    if "catalog" in data:
        cat_path = pathlib.Path(str(data["catalog"]))
        if base_dir is None and not cat_path.is_absolute():
            raise cento.errors.CatalogError(
                f"{source}: catalog {str(cat_path)!r} must be an absolute path -- a file profile resolves it relative to its own directory; a dict has none"
            )
        catalog = cento.catalog.Catalog.load(str(cat_path if base_dir is None else base_dir / cat_path))
        sname = set_name if set_name is not None else data.get("gadget_set")
        if sname is None:
            raise cento.errors.CatalogError(f"{source}: a profile with a catalog names its 'gadget_set' (or pass set_name=)")
        gadget_set_name = str(sname)
        gadgets = catalog.gadgets(gadget_set_name)
    elif set_name is not None:
        raise cento.errors.CatalogError(f"{source}: set_name={set_name!r} given, but the profile has no 'catalog' to select from")
    return Target(
        name=str(data["name"]),
        endian=typing.cast(cento.cells.Endian, endian),
        fill=int(data.get("fill", 0)),
        real_hw=bool(data.get("real_hw", False)),
        catalog=catalog,
        gadgets=gadgets if gadgets is not None else _NoGadgets(),
        profile_path=profile_path,
        gadget_set_name=gadget_set_name,
        abi=abi_spec,
    )
