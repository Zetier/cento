#!/usr/bin/env python3
# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""check.py -- machine-verified equality between before.py, after.py, AND enhanced.py.

Runs all three as subprocesses, extracts each script's labeled emission lines,
strips the labels, normalizes whitespace, and asserts the emission lists are
equal line-for-line -- the byte-for-byte guarantee, verified by machine so the
exhibits stay honest: the hand-rolled script, the declared views, and the
checked chain all emit the same bytes.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# The example scripts import cento bare; the repo src/ is injected HERE (one place),
# so an installed cento and a fresh clone both work -- and after.py stays clean.
SRC = os.path.abspath(os.path.join(HERE, os.pardir, os.pardir, "src"))
ENV = {**os.environ, "PYTHONPATH": SRC + os.pathsep + os.environ.get("PYTHONPATH", "")}


def emissions(script: str, label: str) -> list[list[str]]:
    proc = subprocess.run(
        [sys.executable, os.path.join(HERE, script)],
        capture_output=True,
        text=True,
        env=ENV,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout + proc.stderr)
        sys.exit(f"{script} exited {proc.returncode}")
    out = []
    for line in proc.stdout.splitlines():
        toks = line.split()
        if toks and toks[0] == label:
            out.append(toks[1:])  # drop the script label (before/after/enhanced)
    return out


def main() -> None:
    b = emissions("before.py", "before")
    for script, label in (("after.py", "after"), ("enhanced.py", "enhanced")):
        a = emissions(script, label)
        if not b or not a:
            sys.exit(f"FAIL: missing labeled emissions (before={len(b)} {label}={len(a)} lines)")
        if a != b:
            print(f"FAIL: before.py and {script} emissions differ:")
            for i in range(max(len(a), len(b))):
                x = " ".join(b[i]) if i < len(b) else "<absent>"
                y = " ".join(a[i]) if i < len(a) else "<absent>"
                if x != y:
                    print(f"  line {i} before  : {x}")
                    print(f"  line {i} {label:8}: {y}")
            sys.exit(1)
    bufs, writes, nbytes = 0, 0, 0
    for toks in b:
        if toks[0].startswith("write_qword"):
            writes += 1
        elif len(toks) == 2 and toks[0].endswith(":"):
            bufs += 1
            nbytes += len(toks[1]) // 2
    verdict = f"byte-for-byte equal: {nbytes} bytes across {bufs} buffer{'s' if bufs != 1 else ''}"
    if writes:
        verdict += f" + {writes} write_qword lines"
    print(verdict + " (after.py and enhanced.py both match before.py)")


if __name__ == "__main__":
    main()
