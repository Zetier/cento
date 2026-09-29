# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""cento -- borrowed fragments, arranged deliberately, checked as a whole.

Example 14 -- porting an existing script: golden bytes first, then the strangler fig

before.py is the legacy artifact: a hand-rolled MK-1 wake-record builder, baked address and
counted-by-hand offsets included. The port never rewrites it in one heave. Capture its output
ONCE as the golden reference, wrap the bytes in ONE raw region, then let typed views strangle
the raw words a slice at a time -- and re-prove byte-equality with cento.golden() after EVERY
move, so a slip is named by the cell that owns it, not discovered on a target. Baked addresses
become symbols last; only then do edits go behind the gate, where the classic mistakes are
named refusals.

Run: python3 examples/ex14/ex14_port_a_script.py   (transcript.txt is this run, verbatim)
Next: docs/porting-an-abi.md (that was porting a script; porting an ARCHITECTURE is the same discipline in five moves)
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import cento

HERE = pathlib.Path(__file__).resolve().parent

MAGIC = 0x4D4B574B  # "MKWK"
VERSION = 0x0102  # version 1.2
FLAG_WAKE_ONCE = 0x0001
FLAG_LOUD = 0x0002  # before.py's comment warns: never on shared rails
CAMERA_RAIL = 4
HANDLER_VA = 0x40203E10  # the one baked address in before.py: wake_dispatch() per the fw 1.0 map
HDR_SIZE = 0x10


class WakeHdr(cento.View, size=HDR_SIZE):
    """The header before.py packs by hand: offsets declared once, named forever."""

    magic: cento.u32
    version: cento.u16
    flags: cento.u16
    wake_slot: cento.u32
    handler: cento.u32


class Word(cento.View, size=0x4):
    word: cento.u32


def capture_legacy() -> bytes:
    """Step 1: run the legacy script UNTOUCHED and capture its labeled emission -- the golden reference."""
    env = {**os.environ, "PYTHONPATH": str(HERE.parents[1] / "src") + os.pathsep + os.environ.get("PYTHONPATH", "")}
    proc = subprocess.run([sys.executable, str(HERE / "before.py")], capture_output=True, text=True, timeout=60, env=env, check=True)
    for line in proc.stdout.splitlines():
        if line.startswith("before wake: "):
            return bytes.fromhex(line.removeprefix("before wake: "))
    raise SystemExit("before.py printed no 'before wake:' line -- the legacy artifact changed shape")


def wrap_raw(reference: bytes) -> cento.Region:
    """Step 2: ONE raw region, every legacy byte in a named word cell. No semantics claimed yet."""
    rec = cento.region("rec", max_size=len(reference), endian="big")
    raw = rec.at(0x0, Word * (len(reference) // 4), name="raw")
    for i in range(len(reference) // 4):
        raw[i].word = int.from_bytes(reference[4 * i : 4 * i + 4], "big")
    return rec


def carve_header(reference: bytes, *, flags: int = FLAG_WAKE_ONCE, symbolic_handler: bool = False) -> cento.Region:
    """Steps 3-4: the strangler fig -- a typed header replaces the first four raw words; the tail stays a raw dump."""
    rec = cento.region("rec", max_size=len(reference), endian="big")
    hdr = rec.at(0x0, WakeHdr, name="hdr")
    hdr.magic = MAGIC
    hdr.version = VERSION
    hdr.flags = flags
    hdr.wake_slot = CAMERA_RAIL
    if symbolic_handler:
        hdr.handler = "wake_dispatch"  # step 4: the baked constant becomes a symbol...
        rec.bind("wake_dispatch", HANDLER_VA, source="fw 1.0 map; fw 1.1 rebinds here, no script edit")  # ...bound where the map fact lives
    else:
        hdr.handler = HANDLER_VA
    tail = rec.at(HDR_SIZE, Word * ((len(reference) - HDR_SIZE) // 4), name="raw")
    for i in range((len(reference) - HDR_SIZE) // 4):
        tail[i].word = int.from_bytes(reference[HDR_SIZE + 4 * i : HDR_SIZE + 4 * i + 4], "big")
    return rec


def main() -> bool:
    print("step 1: run the legacy script, capture its emission as the golden reference")
    legacy = capture_legacy()
    pin = cento.golden(legacy)
    print(f"  captured {len(legacy)} bytes: {legacy.hex()}")

    print("\nstep 2: wrap the bytes in ONE raw region -- same bytes, now with named cells")
    diff = pin.compare(wrap_raw(legacy))
    print(f"  {diff.render()}")
    if not diff.ok:
        return False

    print("\nstep 3: carve a typed header over the first 0x10 -- the tail stays a raw dump")
    print(f"  {pin.compare(carve_header(legacy)).render()}")

    print("\nstep 4: the baked handler address becomes a symbol; the value now cites its source")
    rec = carve_header(legacy, symbolic_handler=True)
    print(f"  {pin.compare(rec).render()}")

    print("\nstep 5a: the payoff -- edits go behind the gate; the old offset-poke idiom is refused by name")
    rec[0x8] = 0x00000005  # the poke_notes.txt habit: re-aim the wake slot by offset, no declared intent
    try:
        rec.image()
    except cento.EmitError as e:
        chk = next(line for line in str(e).splitlines() if "CHK-008" in line)
        print(f"  refused: {chk.strip()}")

    print("\nstep 5b: and golden names semantic drift BY OWNER, not as a mystery byte")
    drifted = pin.compare(carve_header(legacy, flags=FLAG_WAKE_ONCE | FLAG_LOUD, symbolic_handler=True))
    print("  " + drifted.render().replace("\n", "\n  "))
    print("  (rec.hdr.flags, by name: the LOUD bit before.py's comment warns about -- one byte, one owner, zero archaeology)")
    return True


if __name__ == "__main__":
    if not main():
        sys.exit(1)
