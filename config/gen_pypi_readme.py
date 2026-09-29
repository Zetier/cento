# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Generate README-pypi.md from README.md: absolute links for a page that has no repo behind it.

PyPI renders the long_description with no working directory, so relative links 404 and the
logo <picture> block is sanitized away (readme_renderer whitelists <img>, not <picture>).
README.md stays the single source: this derives the PyPI variant by rewriting the logo block
to one absolute <img> and every relative link to its github.com/raw.githubusercontent.com
form. Checked in like a transcript; --check refuses on drift (the test runs it).
"""

from __future__ import annotations

import pathlib
import re
import sys

REPO = "https://github.com/zetier/cento"
RAW = "https://raw.githubusercontent.com/zetier/cento/main"
ROOT = pathlib.Path(__file__).resolve().parents[1]
BANNER = "<!-- Generated from README.md by config/gen_pypi_readme.py: edit the source, then regenerate. -->\n"
LOGO = f'<p align="center"><img src="{RAW}/assets/logo.svg" alt="cento logo" width="360"></p>\n'


def _absolute(match: re.Match[str]) -> str:
    target = match.group(1)
    base = f"{REPO}/tree/main" if target.endswith("/") else f"{REPO}/blob/main"
    return f"]({base}/{target})"


def generate() -> str:
    lines = (ROOT / "README.md").read_text(encoding="ascii").splitlines(keepends=True)
    assert lines[0].startswith("<p align=") and "<picture>" in lines[0], "README.md no longer opens on the logo block; retune the generator"
    lines[0] = LOGO
    text = BANNER + "".join(lines)
    return re.sub(r"\]\((?!https?://|mailto:|#)([^)]+)\)", _absolute, text)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    out = ROOT / "config" / "README-pypi.md"
    fresh = generate()
    if args == ["--check"]:
        if not out.is_file() or out.read_text(encoding="ascii") != fresh:
            print("README-pypi.md is stale: README.md moved without it -- run `python config/gen_pypi_readme.py` and commit both.", file=sys.stderr)
            return 1
        print("README-pypi.md is current")
        return 0
    out.write_text(fresh, encoding="ascii")
    print(f"wrote {out.relative_to(ROOT)} ({len(fresh.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
