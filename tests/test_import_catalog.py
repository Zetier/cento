# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""The catalog importer: listings in (file or stdin), deterministic schema-2 JSON out.

The killer pin: an auto-specced entry equals spec_dict() of a hand-declared twin, so auto
entries load, crosscheck clean, and hash identically to what a human would have written."""

from __future__ import annotations

import io
import json
import pathlib
import typing

import pytest

import cento
import cento.catalog as catalog
import cento.gadget as gadget
import cento.import_catalog as ic
import cento.machine as machine

ROPPER_SAMPLE = (  # ropper prints trailing spaces after the last "; " -- the parser must survive them (spelled by concatenation; W291 hits literals too)
    "0x0000000000401234: pop rdi; ret; \n"
    "0x0000000000401300: pop rsi; pop r15; ret; \n"
    "0x0000000000401400: leave; ret; \n"
    "0x0000000000401500: pop rsp; ret; \n"
    "0x0000000000401600: pop rdi; ret; \n"
)

ROPGADGET_SAMPLE = """\
Gadgets information
============================================================
0x0000000000401234 : pop rdi ; ret
0x0000000000401400 : leave ; ret

Unique gadgets found: 2
"""


def _run(tmp_path: pathlib.Path, listing: str, *args: str) -> dict[str, typing.Any]:
    src = tmp_path / "listing.txt"
    src.write_text(listing, encoding="ascii")
    out = tmp_path / "cat.json"
    rc = ic.main([str(src), "--set", "S", "--out", str(out), *args])
    assert rc == 0
    data: dict[str, typing.Any] = json.loads(out.read_text(encoding="ascii"))
    return data


def test_ropper_listing_imports(tmp_path: pathlib.Path) -> None:
    j = _run(tmp_path, ROPPER_SAMPLE)
    assert j["schema"] == 2
    s = j["gadget_sets"]["S"]
    assert set(s) == {"pop_rdi_ret", "pop_rsi_pop_r15_ret"}  # the auto-specced pair
    assert s["pop_rdi_ret"]["entry"] == 0x401234  # dedup kept the LOWEST address (0x401600 dropped)
    assert s["pop_rsi_pop_r15_ret"]["stride"] == 0x18 and s["pop_rsi_pop_r15_ret"]["restores"]["pc"]["at"] == 0x10
    assert j["unspecced"]["S"] == {
        "leave_ret": {"entry": 0x401400, "disasm": "leave; ret"},
        "pop_rsp_ret": {"entry": 0x401500, "disasm": "pop rsp; ret"},  # pop rsp is a pivot: never auto-specced
    }
    assert not set(j["gadget_sets"]["S"]) & set(j["unspecced"]["S"])  # one name, one block: a specced name would shadow its unspecced twin in the loader
    assert j["provenance"]["tool"] == "ropper" and j["provenance"]["auto_specced"] == ["pop_rdi_ret", "pop_rsi_pop_r15_ret"]


def test_auto_spec_equals_a_hand_declared_twin(tmp_path: pathlib.Path) -> None:
    j = _run(tmp_path, ROPPER_SAMPLE)
    twin = gadget.GadgetMeta(
        "pop_rdi_ret",
        (cento.Gadget,),
        {"rdi": cento.Restores("rdi", at=0x0, width=cento.u64), "pc": cento.Restores(machine.Reg.PC, at=0x8, width=cento.u64)},
        entry=0x401234,
        stride=0x10,
    )
    assert j["gadget_sets"]["S"]["pop_rdi_ret"] == gadget.spec_dict(twin)
    p = tmp_path / "cat.json"
    loaded = catalog.Catalog.load(str(p)).gadgets("S").pop_rdi_ret
    assert gadget.spec_sha16(loaded) == gadget.spec_sha16(twin)
    assert catalog.Catalog.load(str(p)).gadgets("S").crosscheck(twin) == ([], [])


def test_ropgadget_and_stdin_and_determinism(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    j = _run(tmp_path, ROPGADGET_SAMPLE)
    assert j["provenance"]["tool"] == "ropgadget" and "pop_rdi_ret" in j["gadget_sets"]["S"]
    out1 = (tmp_path / "cat.json").read_text(encoding="ascii")
    j2 = _run(tmp_path, ROPGADGET_SAMPLE)
    assert (tmp_path / "cat.json").read_text(encoding="ascii") == out1  # byte-identical across runs
    monkeypatch.setattr("sys.stdin", io.StringIO(ROPGADGET_SAMPLE))
    rc = ic.main(["-", "--set", "S"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out) == j2  # stdin == file, stdout == --out


def test_mixed_tool_shapes_refuse(tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]) -> None:
    src = tmp_path / "mixed.txt"
    src.write_text(ROPPER_SAMPLE + ROPGADGET_SAMPLE, encoding="ascii")
    rc = ic.main([str(src), "--set", "S"])
    cap = capsys.readouterr()
    assert rc != 0 and "mixed" in cap.err and cap.out == ""  # teaching stderr, NO partial JSON
    rg = tmp_path / "rg.txt"
    rg.write_text(ROPGADGET_SAMPLE, encoding="ascii")
    rc = ic.main([str(rg), "--set", "S", "--tool", "ropper"])
    cap = capsys.readouterr()
    assert rc != 0 and "not the detected" in cap.err and cap.out == ""  # a forced --tool mismatch names the shape it saw, not "saw both"


def test_only_sym_base_and_image(tmp_path: pathlib.Path) -> None:
    img = tmp_path / "libc.so"
    img.write_bytes(b"\x7fELF-fake")
    j = _run(tmp_path, ROPPER_SAMPLE, "--only", "pop rdi", "--sym", "libc_base", "--base", "0x400000", "--image", str(img), "--target", "mk4")
    assert set(j["gadget_sets"]["S"]) == {"pop_rdi_ret"} and "unspecced" not in j  # --only filtered everything else
    assert j["gadget_sets"]["S"]["pop_rdi_ret"]["entry"] == "libc_base+0x1234"
    pv = j["provenance"]
    assert pv["sym"] == "libc_base" and pv["base"] == 0x400000 and pv["only"] == "pop rdi" and pv["tool"] == "ropper"
    assert len(pv["image_sha256"]) == 64
    assert j["target"] == "mk4"
    loaded = catalog.Catalog.load(str(tmp_path / "cat.json")).gadgets("S").pop_rdi_ret  # symbolic entries round-trip through the loader
    assert not isinstance(loaded.entry, int)


def test_fail_closed_refusals(tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]) -> None:
    src = tmp_path / "l.txt"
    src.write_text(ROPPER_SAMPLE, encoding="ascii")
    for args, frag in [
        (["--set", "S", "--sym", "x"], "--sym requires --base"),
        (["--set", "S", "--sym", "x", "--base", "0x500000"], "below --base"),
        (["--set", "S", "--only", "nomatch_xyz"], "no gadgets"),
        (["--set", "S", "--only", "("], "not a valid regex"),  # metacharacters are natural filter inputs; a typo'd regex teaches, never tracebacks
        (["--set", "S", "--image", str(tmp_path / "absent.bin")], "cannot read"),
    ]:
        rc = ic.main([str(src), *args])
        cap = capsys.readouterr()
        assert rc != 0 and frag in cap.err and cap.out == "", (args, cap.err)
