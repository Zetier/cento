# ex00 -- START HERE: the exploit that grows ("notekeeper", heap frames + rbp pivot), before and after

The rename handler overflows by exactly 16 bytes: saved rbp and saved rip,
nothing else. The chain will not fit on the stack, so it lives in the heap --
three fake frames stashed in a note, linked rbp to rbp, entered by one
`leave; ret` pivot: dup2 the socket to stdin, dup2 to stdout, system("/bin/sh").
Two leaks (libc, the note's address) and a web of addresses that all depend on
them. Three files, the same bytes: `before.py` is the solve script everyone
ships; `after.py` is those bytes as declarations; `enhanced.py` is the
escalation -- the same chain, CHECKED (each ropper line a Gadget, the dataflow
and stack alignment proven by the fold). Don't take any of that on faith: run
`check.py` and watch all three emissions come out byte-for-byte identical.

## The worst lines, side by side

| before.py (the idiom everyone ships) | after.py (cento) |
|---|---|
| `FRAME1 = NOTE + 0x40` ... `BINSH = NOTE + 0xA8` -- four hand-added offsets, each one lore | `slab.alloc(Dup2Frame, "stdin")` ... `slab.alloc(ShellFrame, "shell")` -- the slab map is derived; no offset is ever typed |
| `!! if ANY frame grows, re-add every offset after it ... all of them.` | growth is `slab.alloc(SetuidFrame, "setuid")` plus two re-links; everything downstream re-derives (refusal.py does it) |
| `slab = p64(FRAME1)  # -> rbp: frame1, the NEXT stop` | `stdin.next_rbp = stdout` -- handles ARE addresses; the link names its target |
| `slab += p64(BINSH)  # -> rdi: the string lives right after this frame` | `shell.binsh = slab.alloc(BinShString, "sh")` -- place the string, point at it, one move |
| `assert len(slab) == 0x40, "frame0 grew: FRAME1/FRAME2/BINSH ... ALL stale"` | there is nothing to keep in sync: the assert has no job |
| `payload += p64(FRAME0)  # saved rbp <- the note` (a heap address, baked at write time) | `smash.rbp = stdin` -- a cross-region cell awaiting `slab_base`; emit refuses until the leak binds |

## enhanced.py -- the same bytes, proven

after.py's Views are correct on the honor system: YOU linked the frames and
YOU remembered the aligner. enhanced.py hands both to the machinery: each
ropper line becomes a Gadget declaration (`entry=LIBC + 0x2A3E5`, symbolic
until the leak binds), `run.hop()` lays the frames and wires every gadget
address, pivots link their own rbp slots, and the fold proves every
dup2/system argument fed, nothing ridden across a clobbering call (the SysV
split knows rbp survives and rdi does not), and rsp % 16 == 8 at every libc
call -- `before.py`'s "ask me how I know" movaps comment, as a check.

## The refusals (real captured output)

A teammate poking a frame at a hand-guessed offset collides with the declared
map -- in p64 soup the two beliefs merge silently:

```text
ERROR CHK-001 [slab.shell, slab.setuid2]: placement extents overlap without a declared alias  hint: declare intent: region.at(..., over=(other,), why=...)
ERROR CHK-008 [slab.shell.system, slab.setuid2.hop]: cell rewritten by a different owner (last-writer-wins)  ...
```

And growing the checked chain -- setuid(0) before the shell -- flips rsp's
parity at the calls below the insertion. By hand that is the movaps SIGSEGV
you debug on the target; the fold does the arithmetic:

```text
ERROR CHK-207 [frames.setuid, SetuidCall]: SetuidCall uses entry_sp_mod=8, but this position in the chain requires entry_sp_mod=0 (SP % 16 at entry)
```

## What became reason-able

- **The address web is two facts, not sixteen bakes**: every gadget is
  `libc_base + offset`, every heap pointer is `slab_base + derived offset`;
  the pre-bind emit lists all sixteen waiting cells by name and symbol, and
  two `bind()` calls complete the image.
- **Growth is an edit, not an audit**: append a frame, re-aim two links; the
  slab map, the string address, and the stack's pivot target all re-derive.
  before.py's answer is a comment shouting at you to re-add offsets.
- **The half-done edit is a named error**: a hand-guessed offset in the
  derived layout is CHK-001/CHK-008 at build time; a dropped (or newly
  needed) aligner in the checked chain is CHK-207 -- not a silent stomp or a
  SIGSEGV the target gets to explain.
- **Leak hygiene is declared, not hoped**: `expect_sym("libc_base",
  align=0x1000)` makes the classic mis-parsed leak (a u64 read of a 7-byte
  banner) refuse at `bind()`, the moment it lands.

Run: `python3 before.py && python3 after.py && python3 enhanced.py && python3
check.py` (each script prints its labeled payloads; check.py runs all three as
subprocesses and asserts the emissions byte-for-byte equal), then
`python3 refusal.py` for the bonus reel: the fixup report, the mis-parsed
leak, the growth edit, the collision, and the alignment fold, shape-asserted.

Wanting the gentler on-ramp? ex01 carries the textbook ret2libc as the same
before/after/check/refusal exhibit (plus `ctf/`, the live end-to-end version),
next to the cycle-pad workflow and the pwntools rosetta.
