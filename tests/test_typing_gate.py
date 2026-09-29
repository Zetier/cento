# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Typing gate: mypy --strict (as a subprocess) on a generated module exercising the descriptor surfaces."""

from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys

import pytest

SRC_ROOT = pathlib.Path(__file__).resolve().parents[1] / "src"
# Repo mypy config: the subprocess runs from tmp_path (hermetic cwd), so it
# won't discover pyproject.toml on its own; without it, following imports
# into cento.verify fails on the absent-by-design [verify] extra (unicorn).
CONFIG = pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml"

MODULE = '''\
"""Generated typing-gate module: regions/views descriptor surfaces under mypy --strict."""

import cento


class Hdr(cento.View, size=8):
    magic = cento.Field(0, cento.u32)
    length = cento.Field(4, cento.u32)


class Ann(cento.View):
    seq: cento.u32


class Packed(cento.View, dense=True):
    tag: cento.u32


class Wired(cento.View, dense=True):
    slot = cento.Field(cento.u64, default=cento.Ref("base"))  # declare-and-assign, strict-typed spelling


class Entry(cento.Gadget, entry=0x40001000, stride=0x10):
    pc = cento.Restores(cento.Reg.PC, at=0x0)


OFF: int = Ann.seq.offset  # annotation-declared fields read back as Fields; Width declares the typing surface
SZ: int = len(Hdr)  # len() on the view CLASS (ViewMeta.__len__): the declared byte size


def exercise() -> None:
    layout = cento.Layout()
    pkt = layout.region("pkt", max_size=0x100)
    h: cento.ViewHandle = pkt.at(0, Hdr, "h")            # at() ViewMeta arm
    c: cento.CellHandle = h.magic                        # field read -> CellHandle
    c.write(0xC0DE0001)
    ov: cento.ViewHandle | cento.ArrayHandle = h.overlay(Hdr, at=0, name="ov", why="typing gate")
    v: cento.ViewHandle = pkt.alloc(Hdr, "v")            # alloc() ViewMeta arm
    arr: cento.ArrayHandle = pkt.alloc(Hdr * 2, "arr")   # alloc() ArraySpec arm
    a: cento.ArrayHandle = pkt.at(0x40, Hdr * 2, "a", over=("h",), why="typing gate")
    e: cento.ViewHandle = arr[0]                         # array element -> ViewHandle
    t: cento.Target = cento.target({"schema": 1, "name": "gate", "endian": "little"})  # inline-profile arm
    _pv: cento.Provenance = cento.Provenance(target_name="tg")  # partial hand construction is the contract
    tr: cento.Region = t.region("tr", max_size=0x10)     # Target.region sugar
    off: int = tr.layout.cycle_find(0x61616161)          # Layout.cycle_find sugar
    sa: cento.Region = cento.region("sa", max_size=8, fill=b"A", endian="little")  # standalone-Region arm
    _ab: cento.Region = cento.region("ab", abi="x86_64")  # abi-carrying arm (str and AbiSpec both type)
    _la: cento.abi.AbiSpec | None = cento.Layout(abi=cento.abi.PPC32).abi  # Layout.abi is typed public surface
    _fit: cento.Region = cento.fit({0: 1}, abi=cento.abi.PPC32)  # the one-shot on-ramp returns the full Region
    sa.bind("base", 0x1000, source="gate")
    img: bytes = sa.image()                              # the gated one-region emit (final by default)
    _draft: bytes = sa.image(final=False)                # the draft read: the None-sentinel takes explicit bools
    ovh: cento.ViewHandle = h.overlay(Hdr, at=0, name="ovh", why="typing gate")  # overlay() ViewMeta arm (overloaded like at())
    ova: cento.ArrayHandle = h.overlay(Hdr * 2, at=0, name="ova", why="typing gate")  # overlay() ArraySpec arm
    _rc: cento.cells.Reduce = layout.register_reducer("tg_ck", len)(pkt[0:4])  # layout-scoped reducer: registration returns a typed constructor
    _xc: cento.Ref = layout.register_xform("tg_pg", lambda v: v >> 12)(layout.sym("s"))  # layout-scoped xform: registration returns a typed constructor
    res: cento.regions.Resolution = layout.resolution()  # the forcing snapshot is typed public surface
    pend: set[str] = res.pending()
    dirty: set[tuple[str, int]] = res.dirty("base")
    err = cento.EmitError("x")
    _r: cento.Report | None = err.report               # structured refusals: the gate's Report rides the exception
    cerr = cento.ChainError("x")
    _i: cento.Issue | None = cerr.issue                # seal()'s refusing Issue rides the exception
    exp: cento.Explanation = layout.explain_data("pkt.h.magic")  # explain() as data
    _s: str = exp.render()
    gd: cento.GoldenDiff = cento.golden(b"A" * 8).compare(sa)  # the golden-bytes regression helper: factory + owner-attributed diff
    _dv: tuple[cento.Divergence, ...] = gd.divergences  # typed records, not bare tuples; gd.ok / gd.render() are the pytest idiom
    _mf: cento.Manifest = layout.manifest()  # the layout as data; layout.to_json() is its dict form
    _as: cento.Assurance = layout.assurance()  # verified/checked/assumed tiers, symbols, waivers, gate as one export
    _gok: bool = cento.gate(layout)  # the CI verdict: True iff preflight().shippable, blockers to stderr
    _d: cento.checks.ReportDiff = layout.check().diff(layout.check())  # the agent-loop progress signal
    _role: cento.Role = cento.Role.SP  # the architecture-blind role slots are typed public surface
    ch: cento.Chain = pkt.chain("cg", at=0x80, arm=False)
    ch.enter(Entry)
    _cf: cento.ChainFlow = ch.dataflow()  # narrate() as data; ch.to_json() is its dict form
    _ = (ov, v, a, e.length, off, img, ovh, ova, pend, dirty, _r, _i, _s, _d, _role, _rc, _xc, _cf, _gok)
'''


def test_descriptor_surfaces_pass_mypy_strict(tmp_path: pathlib.Path) -> None:
    if importlib.util.find_spec("mypy") is None:
        pytest.skip("mypy not available")
    mod = tmp_path / "typing_gate_mod.py"
    mod.write_text(MODULE)
    proc = subprocess.run(
        [sys.executable, "-m", "mypy", "--strict", "--config-file", str(CONFIG), str(mod)],
        cwd=tmp_path,
        env={
            **{k: v for k, v in __import__("os").environ.items() if k != "PYTHONPATH"},
            "MYPYPATH": str(SRC_ROOT),
        },  # filtered, not replaced: block src shadowing, keep HOME/TMPDIR/locale
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, f"mypy --strict failed:\n{proc.stdout}\n{proc.stderr}"


def test_facade_reaches_abi_verify_and_result_types() -> None:
    import cento

    assert cento.abi.PPC32.name == "ppc32"
    assert cento.verify.HAVE_UNICORN in (True, False)
    assert cento.Preflight is cento.emit.Preflight
    assert cento.Verdict is cento.verify.Verdict
    assert "Preflight" in cento.__all__ and "Verdict" in cento.__all__
