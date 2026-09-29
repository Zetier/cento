# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Refuse commits without a Developer Certificate of Origin sign-off.

Usage: python config/dco_check.py <rev-range>   (e.g. origin/main..HEAD)

Every commit in the range must carry a Signed-off-by trailer (git commit -s). The refusal
names each offending commit and the fix; an empty range passes (nothing to certify).
"""

from __future__ import annotations

import subprocess
import sys


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: dco_check.py <rev-range>  (e.g. origin/main..HEAD)", file=sys.stderr)
        return 2
    out = subprocess.run(
        ["git", "log", "--format=%H%x00%s%x00%(trailers:key=Signed-off-by,valueonly)", "-z", args[0]],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    records = [r for r in out.split("\x00\x00") if r.strip("\x00\n")]
    missing: list[str] = []
    for rec in records:
        sha, subject, trailer = (rec.strip("\n\x00").split("\x00") + ["", ""])[:3]
        if not trailer.strip():
            missing.append(f"  {sha[:12]}  {subject}")
    if missing:
        print("commits without a Signed-off-by trailer (fix: git commit --amend -s, or git rebase --signoff):", file=sys.stderr)
        print("\n".join(missing), file=sys.stderr)
        print("see CONTRIBUTING.md for what the sign-off certifies.", file=sys.stderr)
        return 1
    print(f"dco: {len(records)} commit(s) signed off")
    return 0


if __name__ == "__main__":
    sys.exit(main())
