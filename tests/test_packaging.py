# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Repo/packaging hygiene.

Packaging invariants: version single-sourcing, the intentional __all__, py.typed.
Facade audit: the normal-case surface imports from cento top-level only.
Selftest smoke: module runs green as a subprocess.
Scaffold: package imports, version, exception hierarchy.

The packaging invariants run in BOTH contexts:
  * source tree (pyproject.toml adjacent): the pyproject [project] version is parsed
    with a targeted scan (requires-python is >=3.10; tomllib landed in 3.11 -- the
    file is ours and static, and a scan miss fails loudly) and compared to
    cento.__version__;
  * installed package (the dist-verify scratch run copies tests/ away from the
    subproject): the comparison falls back to importlib.metadata, and the py.typed
    check verifies package-data actually shipped the marker.
"""

from __future__ import annotations

import importlib.metadata
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import types

import pytest

import cento
import cento.emit
import cento.errors as errors

SUBPROJECT = pathlib.Path(__file__).resolve().parents[1]
PYPROJECT = SUBPROJECT / "pyproject.toml"

# -- packaging invariants ---------------------------------------------------------


def _project_table() -> str:
    text = PYPROJECT.read_text(encoding="utf-8")
    match = re.search(r"^\[project\]\n(.*?)(?=^\[)", text, re.MULTILINE | re.DOTALL)
    assert match is not None, "no [project] table in pyproject.toml"
    return match.group(1)


def test_version_single_sourced() -> None:
    if PYPROJECT.is_file():  # source-tree context
        table = _project_table()
        name = re.search(r'^name = "([^"]+)"', table, re.MULTILINE)
        version = re.search(r'^version = "([^"]+)"', table, re.MULTILINE)
        assert name is not None and name.group(1) == "cento"
        assert version is not None, "no version in [project]"
        assert cento.__version__ == version.group(1)
    else:  # installed context (dist-verify scratch)
        assert cento.__version__ == importlib.metadata.version("cento")


def test_all_is_alphabetized_and_nonempty() -> None:
    assert cento.__all__, "__all__ must be the intentional export set, not empty"
    assert list(cento.__all__) == sorted(cento.__all__), "__all__ must be alphabetized"
    assert len(set(cento.__all__)) == len(cento.__all__), "__all__ has duplicates"


def test_all_names_resolve_and_exclude_modules_and_junk() -> None:
    for name in cento.__all__:
        value = getattr(cento, name)  # raises AttributeError on a stale entry
        assert not isinstance(value, types.ModuleType), f"__all__ entry {name!r} is a module"
    assert "annotations" not in cento.__all__


def test_all_covers_every_public_non_module_attribute() -> None:
    public = {name for name in dir(cento) if not name.startswith("_") and name != "annotations" and not isinstance(getattr(cento, name), types.ModuleType)}
    assert public == set(cento.__all__), f"drift: only-in-dir={sorted(public - set(cento.__all__))} only-in-all={sorted(set(cento.__all__) - public)}"


def test_py_typed_marker_shipped() -> None:
    package_dir = pathlib.Path(cento.__file__).resolve().parent
    assert (package_dir / "py.typed").is_file(), "py.typed marker missing from the package"
    if PYPROJECT.is_file():
        assert 'cento = ["py.typed"]' in PYPROJECT.read_text(encoding="utf-8"), "py.typed not declared as package-data"


def test_copyright_header_on_every_source_file() -> None:
    """Every .py and .c in the tree opens with the Zetier SPDX header; NOTICE maps the rest.

    Headers travel with a copied-out file, so every copyable source carries one -- examples
    included. Fixtures, transcripts, and binaries cannot carry comments; the NOTICE blanket
    covers them, and the logo is reserved (not Apache) -- both facts pinned here. Skips in
    dist-verify's scratch copy, where only tests/ and examples/ are staged (no src/ to audit).
    """
    root = pathlib.Path(__file__).resolve().parents[1]
    if not (root / "src" / "cento").is_dir():
        pytest.skip("repo tree absent (dist-verify scratch runs against the installed package)")
    header = "# Copyright (c) 2026 Zetier\n# SPDX-License-Identifier: Apache-2.0\n"
    c_header = "// Copyright (c) 2026 Zetier\n// SPDX-License-Identifier: Apache-2.0\n"
    missing: list[str] = []
    audited = 0
    for sub in ("src", "tests", "config", "examples"):
        for path in sorted((root / sub).rglob("*")):
            if "__pycache__" in path.parts or path.suffix not in (".py", ".c") or any(part.startswith(".") for part in path.parts):
                continue  # hidden dirs (config/.venv) hold third-party code, never repo sources
            audited += 1
            text = path.read_text(encoding="utf-8")
            if text.startswith("#!"):
                text = text[text.index("\n") + 1 :]
            if not text.startswith(c_header if path.suffix == ".c" else header):
                missing.append(str(path.relative_to(root)))
    assert audited, "the sweep saw no files -- path drift?"
    assert not missing, f"missing the copyright header: {missing}"
    notice = (root / "NOTICE").read_text(encoding="utf-8")
    assert "unless a file header states otherwise" in notice  # the blanket map for headerless fixtures/binaries
    assert "not licensed for reuse" in notice  # the logo reservation
    for svg in sorted((root / "assets").glob("*.svg")):
        assert svg.read_text(encoding="utf-8").startswith("<!-- Copyright (c) 2026 Zetier."), svg.name  # the reservation travels with the file


def test_markdown_relative_links_resolve() -> None:
    """Every relative link in every tracked .md file points at something that exists.

    Relative links resolve from the linking file's own directory. External schemes and pure
    anchors are out of scope; a fragment on a relative target is stripped before the check.
    The file list comes from git, so gitignored scratch (local/, dist/) never gates.
    """
    root = pathlib.Path(__file__).resolve().parents[1]
    if not (root / "src" / "cento").is_dir():
        pytest.skip("repo tree absent (dist-verify scratch runs against the installed package)")
    proc = subprocess.run(["git", "ls-files", "*.md"], cwd=root, capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.skip("git absent -- the tracked-file list is the gate's scope")
    tracked = [root / line for line in proc.stdout.splitlines()]
    assert tracked, "the sweep saw no markdown -- path drift?"
    dead: list[str] = []
    for md in tracked:
        for target in re.findall(r"\]\(([^)\s]+)\)", md.read_text(encoding="utf-8")):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            rel = target.split("#", 1)[0]
            if rel and not (md.parent / rel).exists():
                dead.append(f"{md.relative_to(root)} -> {target}")
    assert not dead, f"dead relative links: {dead}"


def test_readme_lead_example_runs_and_matches_its_output() -> None:
    """Every README output block is regenerated by its code and matched byte-for-byte.

    Three ```python blocks: the pwntools-integration opener (display-only -- it talks to a
    remote, so CI never runs it and it shows no Output), the offline receipt ("the same two
    lines" continuing from the opener's `stack`, so its script is the opener's cento lines
    plus the receipt lines), and the standalone ret2libc View example. Extraction anchors
    each executable pair on the literal "Output:" lead-in, so the README's other ```text
    blocks (refusal quotes, scene output) never pair; the counts are pinned so a block
    drifting away from its Output fails loudly instead of silently dropping out of the sweep.
    A library change that breaks any front-door block breaks the build, in the same change.
    """
    readme = SUBPROJECT / "README.md"
    if not readme.is_file():
        pytest.skip("repo tree absent (dist-verify scratch runs against the installed package)")
    text = readme.read_text(encoding="utf-8")
    blocks = re.findall(r"```python\n(.*?)\n```(\n\nOutput:\n\n```text\n(.*?)\n```)?", text, flags=re.DOTALL)
    assert len(blocks) == 3, "README python blocks moved; update this pin"
    opener, opener_paired, _ = blocks[0]
    assert not opener_paired, "the pwntools opener grew an Output block; CI cannot run a remote"
    preamble = [line for line in opener.splitlines() if line.startswith("import cento") or line.startswith("stack = cento.")]
    assert len(preamble) == 2, "the opener's cento lines moved; update the preamble extraction"
    pairs = [(code, shown) for code, paired, shown in blocks[1:] if paired]
    assert len(pairs) == 2, "README front-door pairs moved; update this pin"
    pairs[0] = ("\n".join(preamble) + "\n" + pairs[0][0], pairs[0][1])  # the receipt continues from the opener's stack
    # This tree's src, first on the path: the front door pins THIS code, not an ambient install.
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SUBPROJECT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    for index, (code, shown) in enumerate(pairs):
        # A real module run (not exec-in-a-dict): View annotations resolve in the defining module.
        script = pathlib.Path(tempfile.mkdtemp(prefix="cento-readme-")) / f"front_door_{index}.py"
        script.write_text(code + "\n", encoding="ascii")
        proc = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=60, env=env)
        assert proc.returncode == 0, proc.stderr[-2000:]
        assert proc.stdout == shown + "\n"  # the script prints; the pipe is non-TTY, so hexdump color never contaminates


# -- facade audit -------------------------------------------------------------------

EXPECTED = [
    "Layout",
    "Region",
    "View",
    "Field",
    "u8",
    "u16",
    "u32",
    "u64",
    "Ref",
    "Delta",
    "Span",
    "Backend",
    "Deliver",
    "EmitResult",
    "Fixup",
    "Report",
    "Issue",
    "Reg",
    "Carry",
    "Effect",
    "Writeback",
    "CLOBBER",
    "UNSET",
    "Transfer",
    "Gadget",
    "Restores",
    "Clobbers",
    "Chain",
    "ChainFlow",
    "Hop",
    "Catalog",
    "CatalogError",
    "ChainError",
    "DeliveryPlan",
    "DeliveryGroup",
    "CentoError",
    "Provenance",
    "Manifest",
    "Assurance",
    "target",
    "Target",
    "lo16",
    "hi16",
    "ha16",
    "crc32_mpeg2",
    "xor_fold",
    "sum16",
    "udp_cksum",
    "crc8",
    "length",
    "fit",
    "golden",
    "Golden",
    "GoldenDiff",
    "Divergence",
]


def test_facade_complete() -> None:
    missing = [n for n in EXPECTED if not hasattr(cento, n)]
    assert missing == [], missing


def test_h1_breaking_pass_surfaces_removed() -> None:
    """Clean surface: no aliases, no shims, no execution vocabulary."""
    assert not hasattr(cento, "DryThrower")
    assert not hasattr(cento, "Supplied")
    assert not hasattr(cento.emit.Deliver, "FIRST")
    assert not hasattr(cento.emit.Deliver, "LAST")
    assert hasattr(cento.emit.Deliver, "LATE")
    assert issubclass(cento.errors.CentoError, Exception)
    assert cento.CentoError is cento.errors.CentoError  # the error base, exported at the facade


# -- selftest smoke -------------------------------------------------------------------

SRC_ROOT = pathlib.Path(__file__).resolve().parents[1] / "src"


def test_selftest_green() -> None:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run([sys.executable, "-m", "cento.selftest"], capture_output=True, text=True, env=env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PASS" in proc.stdout


# -- scaffold ------------------------------------------------------------------------


def test_exception_hierarchy() -> None:
    assert issubclass(errors.PlacementError, errors.CentoError)
    assert issubclass(errors.ResolveError, errors.CentoError)
    assert issubclass(errors.EmitError, errors.CentoError)


def test_pypi_readme_is_current() -> None:
    """README-pypi.md is a generated artifact (the PyPI page has no repo behind its relative links); drift refuses with the regeneration command."""
    root = pathlib.Path(__file__).resolve().parents[1]
    gen = root / "config" / "gen_pypi_readme.py"
    if not gen.is_file():
        pytest.skip("repo tree absent (dist-verify scratch runs against the installed package)")
    proc = subprocess.run([sys.executable, str(gen), "--check"], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
