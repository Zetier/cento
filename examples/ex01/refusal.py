#!/usr/bin/env python3
# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
# 01-ret2libc-rop, the bonus reel: what after.py's declaration buys.
# Scene 1: pre-leak, every gadget cell reports itself waiting; one bind pays.
# Scene 2: THE REFUSAL -- rev B shrank the buf to 120, the tooling's offset
# didn't move. Placing the SAME declaration at rev-B's belief is one line;
# the final emit refuses the merge, naming every colliding cell.
import sys
import textwrap

import after

import cento


def main() -> None:
    stack = after.stack
    layout = stack.layout

    print("== pre-leak: every gadget cell reports itself waiting ==")
    for f in layout.emit(cento.Backend.IMAGE, final=False).fixups:
        print(f"  {f.owner} (stack+{f.offset:#x} w{f.width}) awaits {', '.join(f.missing)}")
    layout.bind("libc_base", 0x00007F1FBABC0000, source="puts(got.puts) leak")
    print(f"after bind: {len(layout.emit(cento.Backend.IMAGE, final=False).fixups)} fixups left")
    print(layout.explain("stack.frames.rip"))

    print("== THE REFUSAL: rev B shrank the buf; the offset didn't move ==")
    # Rev-B belief: 120-byte buffer, so the frame starts at 128 -- while the
    # rev-A frame still owns 136. In b"A"*136 soup the beliefs merge silently.
    stack.at(128, after.RopFrames, name="revb_frames")  # the whole rev-B chain, one line
    try:
        layout.emit(cento.Backend.IMAGE)
    except cento.EmitError as e:
        # the shape is enforced, not narrated: the extents overlap (CHK-001) plus one
        # stomp per shared qword (3x CHK-008: rev-B's first slot lands in pad)
        msg = str(e)
        assert "CHK-001" in msg and msg.count("CHK-008") == 3, "refusal shape drifted"
        print("refused:")
        print(textwrap.indent(msg, "  "))
    else:
        sys.exit("expected EmitError: the overlap gate did not fire")
    print("two beliefs about where saved-RIP lives cannot coexist past the gate")


if __name__ == "__main__":
    main()
