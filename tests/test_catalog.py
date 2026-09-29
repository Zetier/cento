# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Catalog + profile.

Catalog: schema-v1 load, gadget generation, provenance crosschecks.
Target facade: profile load, target-bound Layout defaults, chain gadget_set default.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import tempfile

import pytest

import cento
import cento.catalog as catalog_mod
import cento.errors as errors
import cento.gadget as gadget
import cento.machine as machine

Reg = machine.Reg
FIXTURE = str(pathlib.Path(__file__).parent / "fixtures" / "catalog_v2.json")

# -- catalog: load, generation, crosschecks ---------------------------------------


def test_load_and_generate_gadget() -> None:
    """Schema-v1 load generates cached gadget classes; unknown names get did-you-mean refusals."""
    cat = catalog_mod.Catalog.load(FIXTURE)
    demo = cat.gadgets("DemoAS")
    st = demo.SYSCALL_TAIL
    assert st is demo.SYSCALL_TAIL  # cached
    assert st.entry == 0x40002000 and st.stride == 0xB0 and st.transfer.reentry_safe is True
    assert st.frame.__fields__["pc"].external is True and st.frame.__fields__["r30"].offset == 0xA8
    assert st.needs[Reg.R30].startswith("syscall")
    with pytest.raises(errors.CatalogError, match="DemoAS"):
        cat.gadgets("DemoAs")
    with pytest.raises(AttributeError, match="SYSCALL_TAIL"):
        _ = demo.SYSCALL_TAI


def test_schema_version_rejected(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"schema": 3, "gadget_sets": {}}))
    with pytest.raises(errors.CatalogError, match="schema 3"):
        catalog_mod.Catalog.load(str(p))


def test_crosscheck_entry_and_field_drift() -> None:
    cat = catalog_mod.Catalog.load(FIXTURE)
    demo = cat.gadgets("DemoAS")

    class SYSCALL_TAIL(gadget.Gadget, entry=0x40002004, stride=0xB0):  # entry DRIFTED +4
        r30 = gadget.Restores(Reg.R30, at=0xAC)  # offset DRIFTED +4
        r31 = gadget.Restores(Reg.R31, at=0xAC)
        pc = gadget.Restores(Reg.PC, at=0xB4, external=True)

    errs, warns = demo.crosscheck(SYSCALL_TAIL)
    codes = {i.code for i in errs}
    assert "CHK-301" in codes and "CHK-302" in codes

    class Unknown(gadget.Gadget, entry=0x1000):
        pc = gadget.Restores(Reg.PC, at=0x4)

    errs2, warns2 = demo.crosscheck(Unknown)
    assert not errs2 and {i.code for i in warns2} == {"CHK-303"}


def test_schema_1_refuses_with_teaching(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "old.json"
    p.write_text(json.dumps({"schema": 1, "gadget_sets": {}}), encoding="ascii")
    with pytest.raises(errors.CatalogError, match="schema 1 unsupported.*spec_dict"):
        catalog_mod.Catalog.load(str(p))


def test_v2_round_trip_is_the_identity(tmp_path: pathlib.Path) -> None:
    """The round-trip law: spec_dict(load(spec_dict(g))) == spec_dict(g), and spec_sha16 equal.
    Representative set: PPC32 SP-frame w/ external pc, PPC32 pointer frame, x86-64 string slots
    with u64 widths + entry_sp_mod, and a symbolic-entry sp_pivot gadget."""

    class RtTail(cento.Gadget, entry=0x40002000, stride=0x40, reentry_safe=True):
        r30 = cento.Restores(Reg.R30, at=0x38)
        pc = cento.Restores(Reg.PC, at=0x44, external=True)
        needs = {Reg.R30: "capability word"}

    class RtCtx(cento.Gadget, entry=0x40001000, stride=0x58, frame_base=Reg.R31):
        pc = cento.Restores(Reg.PC, at=0x00)
        sp = cento.Restores(Reg.SP, at=0x04)
        r31 = cento.Restores(Reg.R31, at=0x54)
        needs = {Reg.R31: "context-block pointer"}

    class RtSystem(cento.Gadget, entry=0x7F0000052290, stride=0x8, entry_sp_mod=8):
        pc = cento.Restores(Reg.PC, at=0x0, width=cento.u64)
        needs = {"rdi": "the command string"}

    class RtPivot(cento.Gadget, entry=cento.Ref("libc_base") + 0x4B9D1, frame_base="rbp", sp_pivot=True, stride=0x10):
        rbp = cento.Restores("rbp", at=0x0, width=cento.u64)
        pc = cento.Restores(Reg.PC, at=0x8, width=cento.u64)
        needs = {"rbp": "the frame this pivots into"}

    originals = [RtTail, RtCtx, RtSystem, RtPivot]
    data = {"schema": 2, "target": "roundtrip", "gadget_sets": {"S": {g.gname: gadget.spec_dict(g) for g in originals}}}
    p = tmp_path / "v2.json"
    p.write_text(json.dumps(data, sort_keys=True), encoding="ascii")
    gs = catalog_mod.Catalog.load(str(p)).gadgets("S")
    for g in originals:
        loaded = getattr(gs, g.gname)
        assert gadget.spec_dict(loaded) == gadget.spec_dict(g), g.gname
        assert gadget.spec_sha16(loaded) == gadget.spec_sha16(g), g.gname


def test_crosscheck_judges_the_v2_fields(tmp_path: pathlib.Path) -> None:
    class CcSystem(cento.Gadget, entry=cento.Ref("libc") + 0x52290, stride=0x8, entry_sp_mod=8):
        pc = cento.Restores(Reg.PC, at=0x0, width=cento.u64)
        needs = {"rdi": "the command string"}

    spec = gadget.spec_dict(CcSystem)
    gs = catalog_mod.GadgetSet("S", {"CcSystem": spec})
    errs, warns = gs.crosscheck(CcSystem)
    assert errs == [] and warns == []  # a gadget agrees with its own spec, symbolic entry included

    drifted = dict(spec, entry="libc+0x99999", entry_sp_mod=0)
    gs2 = catalog_mod.GadgetSet("S", {"CcSystem": drifted})
    errs2, _ = gs2.crosscheck(CcSystem)
    codes2 = {(i.code, i.subjects[-1]) for i in errs2}
    assert ("CHK-301", "CcSystem") in codes2 and ("CHK-302", "entry_sp_mod") in codes2

    widthless = dict(spec, restores={"pc": dict(spec["restores"]["pc"], width=4)})
    gs3 = catalog_mod.GadgetSet("S", {"CcSystem": widthless})
    errs3, _ = gs3.crosscheck(CcSystem)
    assert any(i.code == "CHK-302" and "width" in i.msg for i in errs3)


def test_migrated_fixture_hashes_match_the_inline_twins() -> None:
    """The migration moved file bytes, not identities: materialized spec_sha16 values are the
    same ones schema 1 produced (widths were the u32 defaults those gadgets already declared)."""
    cat = catalog_mod.Catalog.load(FIXTURE)
    tail = cat.gadgets("DemoAS").SYSCALL_TAIL
    assert gadget.spec_dict(tail)["restores"]["pc"]["width"] == 4
    assert gadget.spec_sha16(tail) == "ee5be4e18c55f091"  # equals the pre-migration hash (verified against the base-commit v1 fixture)


_V2_MIN_ENTRY = {"entry": 0x401000, "stride": 0x8, "restores": {"r30": {"reg": "R30", "at": 0x4}}}


def test_unspecced_gadgets_refuse_with_promotion_teaching(tmp_path: pathlib.Path) -> None:
    """Unspecced entries are known-but-refusing: access teaches promotion, typo hints see both populations."""
    data = {
        "schema": 2,
        "target": "t",
        "gadget_sets": {"S": {"PopR30": _V2_MIN_ENTRY}},
        "unspecced": {"S": {"leave_ret": {"entry": 0x401400, "disasm": "leave; ret"}}},
    }
    p = tmp_path / "cat.json"
    p.write_text(json.dumps(data), encoding="ascii")
    gs = catalog_mod.Catalog.load(str(p)).gadgets("S")
    with pytest.raises(errors.CatalogError, match="unspecced.*write its restores"):
        _ = gs.leave_ret
    with pytest.raises(AttributeError, match="did you mean 'leave_ret'"):
        _ = gs.leave_rett  # the typo hint covers the unspecced population too
    assert gs.unspecced == ("leave_ret",)
    assert catalog_mod.GadgetSet("S", {}).unspecced == ()  # back-compat: two-arg construction


def test_parse_entry_inverts_entry_str() -> None:
    for e in (cento.Ref("libc"), cento.Ref("libc") + 0x2A3E5, cento.Ref("libc") - 0x10):
        assert gadget.parse_entry(gadget.entry_str(e)) == e
    with pytest.raises(errors.CatalogError, match="entry"):
        gadget.parse_entry("not a symbol +")


# -- target facade: profile load, set-once defaults --------------------------------

PROFILE = str(pathlib.Path(__file__).parent / "fixtures" / "profile_v1.json")


def test_target_loads_profile_and_layout_defaults() -> None:
    """A profile file loads (str or Path) and its facts ride into every layout the target makes."""
    t = cento.target(PROFILE)
    assert t.name == "test_target" and t.real_hw is False
    assert t.gadgets.SYSCALL_TAIL.entry == 0x40002000
    layout = t.layout()
    assert layout.endian == "big"
    reg = layout.region("r")
    assert reg.fill == b"\x00"
    assert layout.gadget_set is t.gadgets
    plan = layout.plan()
    assert plan.real_hw is False
    assert cento.target(pathlib.Path(PROFILE)).name == "test_target"


def test_target_layout_composes_provenance() -> None:
    """Target.layout() records where its facts came from: profile and catalog identities, content hash included."""
    t = cento.target(PROFILE)
    layout = t.layout()
    p = layout.provenance
    assert p.target_name == "test_target" and p.gadget_set == "DemoAS"
    assert p.profile_path is not None and p.profile_path.endswith("profile_v1.json")
    assert p.catalog_path is not None and p.catalog_path.endswith("catalog_v2.json")
    assert p.catalog_sha256 is not None and len(p.catalog_sha256) == 64
    assert p.catalog_sha256 == hashlib.sha256(pathlib.Path(FIXTURE).read_bytes()).hexdigest()
    assert p.catalog_target == "test_fixture"
    assert layout.gadget_set is not None and layout.gadget_set.set_name == "DemoAS"


def test_chain_defaults_gadget_set_from_layout() -> None:
    t = cento.target(PROFILE)
    layout = t.layout()
    page = layout.region("page", base="pv", max_size=0x1000)
    run = page.chain("c", at=0x100)
    assert run.gadget_set is t.gadgets

    class LjBypass(gadget.Gadget, entry=0x40001000, frame_base=Reg.R31):
        pc = gadget.Restores(Reg.PC, at=0x00)
        sp = gadget.Restores(Reg.SP, at=0x04)
        r30 = gadget.Restores(Reg.R30, at=0x50)
        r31 = gadget.Restores(Reg.R31, at=0x54)
        needs = {Reg.R31: "jb"}

    run.enter(LjBypass)
    h = run.hop(t.gadgets.SYSCALL_TAIL, "h")
    h.r30, h.r31 = 1, 2
    report = layout.check()
    assert not any(i.code == "CHK-301" for i in report.errors)  # catalog-loaded gadget matches itself
    assert any(i.code == "CHK-303" for i in report.warnings)  # LjBypass absent from catalog -> warned


def test_inline_profile_contract() -> None:
    """Inline dict profiles are the set-once idiom: endian rides through, layouts stay fresh per call, absolute catalogs load."""
    t = cento.target({"schema": 1, "name": "local-x86", "endian": "little"})
    assert t.name == "local-x86" and t.endian == "little" and t.catalog is None
    layout = t.layout()
    assert layout.endian == "little" and layout.gadget_set is None  # no catalog -> no crosscheck noise
    frame = t.region("frame", max_size=8, pad=4)
    frame[0] = 0x11223344
    assert frame.image()[:4] == bytes.fromhex("44332211")  # the profile's endian, never repeated
    t = cento.target({"schema": 1, "name": "iso"})
    a = t.region("r", max_size=0x10)
    b = t.region("r", max_size=0x10)  # same name twice: fine, every call gets its own Layout
    assert a.layout is not b.layout
    a[0] = 1
    assert not b.layout.cells()  # build isolation, exactly like cento.region()
    cat = str(pathlib.Path(__file__).parent / "fixtures" / "catalog_v2.json")
    t = cento.target({"schema": 1, "name": "x", "catalog": cat, "gadget_set": "DemoAS"})
    assert t.gadgets.SYSCALL_TAIL.entry == 0x40002000
    with pytest.raises(errors.CatalogError, match="names its 'gadget_set'"):
        cento.target({"schema": 1, "name": "x", "catalog": cat})


def test_profile_endian_defaults_little() -> None:
    """A profile that says nothing about endianness gets the default target's: little."""
    assert cento.target({"schema": 1, "name": "t"}).endian == "little"


def test_profile_refusals_teach() -> None:
    """Profile refusals fail closed with the fix named: bad schema, non-ascii, typoed keys, missing catalog facts."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump({"schema": 9}, fh)
    with pytest.raises(errors.CatalogError, match="schema 9"):
        cento.target(fh.name)
    with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as bfh:
        bfh.write('{"schema": 1, "name": "caf\u00e9"}'.encode())  # profiles are ascii artifacts: a teaching refusal, not a raw UnicodeDecodeError
    with pytest.raises(errors.CatalogError, match="cannot read profile"):
        cento.target(bfh.name)
    with pytest.raises(errors.CatalogError, match=r"unknown profile keys \['endain'\]"):
        cento.target({"schema": 1, "name": "x", "endain": "little"})  # fail closed: a typo must not take a default
    t = cento.target({"schema": 1, "name": "bare"})
    with pytest.raises(errors.CatalogError, match="cannot load gadget 'CTX_RESTORE'"):
        _ = t.gadgets.CTX_RESTORE
    with pytest.raises(errors.CatalogError, match="schema None unsupported"):
        cento.target({"name": "x"})
    with pytest.raises(errors.CatalogError, match="missing 'name'"):
        cento.target({"schema": 1})
    with pytest.raises(errors.CatalogError, match="must be 'big' or 'little'"):
        cento.target({"schema": 1, "name": "x", "endian": "middle"})
    with pytest.raises(errors.CatalogError, match="must be an absolute path"):
        cento.target({"schema": 1, "name": "x", "catalog": "catalog_v2.json", "gadget_set": "DemoAS"})
    with pytest.raises(errors.CatalogError, match="no 'catalog' to select from"):
        cento.target({"schema": 1, "name": "x"}, set_name="DemoAS")


def test_profile_abi_key_carries_the_fact() -> None:
    """A profile's "abi" fills endian and rides into every layout/region the target makes; explicit facts still win when coherent."""
    t = cento.target({"schema": 1, "name": "ppc", "abi": "ppc32"})
    assert t.abi is not None and t.abi.name == "ppc32" and t.endian == "big"
    layout = t.layout()
    assert layout.abi is t.abi and layout.endian == "big"
    assert layout.region("r").word == 4
    reg = t.region("r", max_size=0x10, word=8)  # explicit word wins silently
    assert reg.word == 8
    coherent = cento.target({"schema": 1, "name": "x", "abi": "x86_64", "endian": "little"})  # agreeing endian: no refusal
    assert coherent.endian == "little" and coherent.layout().region("r").word == 8


def test_profile_abi_refusals_teach() -> None:
    """Unknown abi names and endian-vs-abi conflicts refuse at parse, source-prefixed -- fail closed on incoherent device facts."""
    with pytest.raises(errors.CatalogError, match=r"inline profile: unknown abi 'z80'"):
        cento.target({"schema": 1, "name": "x", "abi": "z80"})
    with pytest.raises(errors.CatalogError, match=r"inline profile: abi 'ppc32' is big-endian.*endian='little'"):
        cento.target({"schema": 1, "name": "x", "abi": "ppc32", "endian": "little"})
    with pytest.raises(errors.CatalogError, match="must be 'big' or 'little'"):
        cento.target({"schema": 1, "name": "x", "endian": None})  # an explicit null is present-and-wrong, not absent: fail closed
