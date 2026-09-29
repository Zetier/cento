#!/usr/bin/env python3
# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Distribution verification for cento.

Proves the package installs and works FROM THE WHEEL ALONE -- no source tree,
no PYTHONPATH:

  1. fresh venv in a /tmp tempdir
  2. `pip install <abs-repo-root>` (NOT editable) + pytest into the venv
  3. from an EMPTY scratch cwd (repo invisible):
       a. `python -c "import cento; print(cento.__version__)"`
       b. `python -m cento.selftest`
       c. `python <repo>/examples/ex05/ex05_computed_cells.py` smoke (examples live in the
          repo, not the wheel; the import of cento still resolves to the venv)
       d. pytest over a COPY of tests/ (+ the examples/ they exercise) run
          against the INSTALLED package

Path-hygiene design (documented, deliberate):
  * every venv subprocess runs with PYTHONPATH stripped from the environment --
    callers (e.g. `make selftest`, or a downstream consumer's build) may export
    PYTHONPATH pointing at this repo's src/, which would otherwise shadow the
    installed package and void the whole exercise;
  * every check runs with cwd=<scratch>, an empty directory, so `import cento`
    cannot resolve via the current directory;
  * the shipped tests are COPIED to <scratch>/tests. Their conftest.py inserts
    `parents[1]` and `parents[1]/"src"` (= <scratch> and <scratch>/src) into
    sys.path; <scratch>/src does not exist, so `import cento` resolves to the
    installed site-packages copy, while `import examples...` resolves to the
    examples/ copy staged next to tests/. The cento resolution is verified
    explicitly (check `a'` asserts cento.__file__ lives under the venv).

Exit nonzero on any failure. The tempdir is removed on success and KEPT on
failure with its path printed, for post-mortem.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import venv

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
SUBPROJECT = REPO_ROOT  # repo root IS the package root (pyproject.toml lives here)


def run(label: str, cmd: list[str], cwd: pathlib.Path, env: dict[str, str], transcript: list[str]) -> bool:
    proc = subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True, text=True, timeout=600)  # a black-holed pip must fail the gate, not hang it
    ok = proc.returncode == 0
    transcript.append(f"[{'PASS' if ok else 'FAIL'}] {label}: {' '.join(cmd)} (rc={proc.returncode})")
    if not ok:
        transcript.append(proc.stdout[-4000:])
        transcript.append(proc.stderr[-4000:])
    return ok


def main() -> int:
    stale_build = SUBPROJECT / "build"
    if stale_build.is_dir():
        shutil.rmtree(stale_build)  # a stale in-tree PEP 517 build/ merges into the wheel: deleted modules would keep shipping
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="cento-dist-"))
    venv_dir = tmp / "venv"
    scratch = tmp / "scratch"
    scratch.mkdir()
    transcript: list[str] = []

    print(f"cento-dist-verify: workdir {tmp}")
    try:
        return _run_steps(tmp, venv_dir, scratch, transcript)
    except BaseException:
        print(f"cento-dist-verify: EXCEPTION; workdir kept at {tmp}")
        raise


def _run_steps(tmp: pathlib.Path, venv_dir: pathlib.Path, scratch: pathlib.Path, transcript: list[str]) -> int:
    failures = 0
    venv.create(venv_dir, with_pip=True)
    py = str(venv_dir / "bin" / "python")

    env = os.environ.copy()
    env.pop("PYTHONPATH", None)  # callers may export it; it MUST NOT leak into the venv checks
    env.pop("PYTHONHOME", None)

    steps: list[tuple[str, list[str], pathlib.Path]] = []

    # 1. install the package, non-editable, from its absolute path
    steps.append(("pip-install-cento", [py, "-m", "pip", "install", "--quiet", str(SUBPROJECT)], scratch))
    # 2. pytest for the shipped-suite run
    steps.append(("pip-install-pytest", [py, "-m", "pip", "install", "--quiet", "pytest"], scratch))
    # 3a. import + version, from the empty scratch cwd
    steps.append(("import-version", [py, "-c", "import cento; print(cento.__version__)"], scratch))
    # 3a'. paranoia: the imported package must live inside the venv, not the repo
    probe = f"import cento, sys; p = cento.__file__; assert {str(venv_dir)!r} in p, p; print('installed-at', p)"
    steps.append(("installed-package-resolves", [py, "-c", probe], scratch))
    # 3b. stdlib smoke selftest
    steps.append(("module-selftest", [py, "-m", "cento.selftest"], scratch))
    # 3c. example smoke: the script lives in the repo (not the wheel); cento resolves to the venv
    steps.append(("example-computed-cells", [py, str(SUBPROJECT / "examples" / "ex05" / "ex05_computed_cells.py")], scratch))

    for label, cmd, cwd in steps:
        if not run(label, cmd, cwd, env, transcript):
            failures += 1
            break  # later steps are meaningless once install/import breaks

    # 3d. shipped tests against the INSTALLED package (only if everything above held).
    # examples/ rides along because tests/test_examples.py exercises the repo's
    # example scripts; cento itself still imports from the venv (asserted in 3a').
    if failures == 0:
        shutil.copytree(SUBPROJECT / "tests", scratch / "tests", ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
        shutil.copytree(SUBPROJECT / "examples", scratch / "examples", ignore=shutil.ignore_patterns("__pycache__"))
        if not run("pytest-shipped-tests", [py, "-m", "pytest", "tests", "-q", "-p", "no:cacheprovider"], scratch, env, transcript):
            failures += 1

    print("\n".join(transcript))
    if failures:
        print(f"cento-dist-verify: FAIL ({failures} step(s)); workdir kept at {tmp}")
        return 1
    shutil.rmtree(tmp)
    print("cento-dist-verify: PASS -- install/import/selftest/example/shipped-tests all green from a clean venv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
