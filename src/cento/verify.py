# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Verify layer: emulation-backed gadget verification (Verdict + verify_transfer).

Everything here is stdlib; unicorn is import-GUARDED (module import never fails). Executors
(verify_transfer) raise cento.errors.VerifyError with a teaching message when unicorn
is absent.

NOTE (WINDOW_LEN): the hashed gadget window is source.read(as_name, entry, WINDOW_LEN)
-- the hash covers the gadget body from its entry point only. Out-of-window callees (e.g. a
syscall-tail gadget's `bl` to its out-of-line sc stub) are executed from the same ELF but
are NOT covered by bytes_sha16. A Thumb entry (bit 0 set) hashes its window from entry|1 --
spell catalog entries the same way or the bytes_sha16 will differ.

Seeding rule (pointer-frame convention): pointer-frame gadgets (frame_base != SP) receive the frame
pointer conceptually in frame_base AND, on arches with a longjmp-class sibling convention, in the
descriptor's frame_sibling register (PPC32: R3); seed BOTH with the frame address. SP-frame
gadgets: seed SP = frame address.
"""

from __future__ import annotations

import dataclasses
import struct
import typing

import cento.abi
import cento.abi.x86_64
import cento.cells
import cento.emit
import cento.errors
import cento.gadget
import cento.machine

try:
    import unicorn
    import unicorn.ppc_const  # noqa: F401  # availability probe; the executor reads unicorn.ppc_const register ids

    HAVE_UNICORN = True
except ImportError:
    HAVE_UNICORN = False

WINDOW_LEN = 0x200  # hashed gadget window from entry; out-of-window callees are executed but not hashed (see module docstring)

_PT_LOAD = 1


@dataclasses.dataclass(frozen=True)
class Verdict:
    """One gadget verification outcome. observations are sorted key-value string pairs, and
    there are no timestamps -- verdicts must be byte-reproducible."""

    gadget: str
    entry: int
    spec_sha16: str
    bytes_sha16: str
    ok: bool
    divergences: tuple[str, ...]
    warnings: tuple[str, ...]
    observations: tuple[tuple[str, str], ...]

    def to_json(self) -> dict[str, typing.Any]:
        return {
            "gadget": self.gadget,
            "entry": self.entry,
            "spec_sha16": self.spec_sha16,
            "bytes_sha16": self.bytes_sha16,
            "ok": self.ok,
            "divergences": list(self.divergences),
            "warnings": list(self.warnings),
            "observations": [[k, v] for k, v in self.observations],
        }

    @classmethod
    def from_json(cls, d: dict[str, typing.Any]) -> Verdict:
        return cls(
            gadget=d["gadget"],
            entry=d["entry"],
            spec_sha16=d["spec_sha16"],
            bytes_sha16=d["bytes_sha16"],
            ok=d["ok"],
            divergences=tuple(d["divergences"]),
            warnings=tuple(d["warnings"]),
            observations=tuple((str(k), str(v)) for k, v in d["observations"]),
        )


class CodeSource(typing.Protocol):
    """Anything that can hand back gadget code: read(as_name, addr, length) -> bytes for the
    verified window, text_window(as_name) -> (va_base, bytes) for the emulator's mapping.

    A raw firmware dump needs only these two methods (see ex10_provenance's FirmwareDump).
    """

    def read(self, name: str, addr: int, length: int) -> bytes: ...

    def text_window(self, name: str) -> tuple[int, bytes]: ...


_FRAME_PAGE = 0x70000000  # frame scratch page (unmapped-as-code sentinel space); SP-frame SP starts mid-page
_FRAME_SIZE = 0x2000
_SP_FRAME_SP = 0x70000800


@dataclasses.dataclass(frozen=True)
class _ArchExec:
    """One architecture's executor facts: everything verify_transfer's generic loop needs.

    reg_id maps a machine slot (Role/Reg/string) to a unicorn register constant, or None for
    slots this arch cannot verify (every seed_regs member MUST be reg_id-mapped; _executors()
    enforces it at construction); frame_sibling is the longjmp-class register that receives a
    pointer frame's address alongside frame_base (PPC32: R3; None on arches without the
    convention); sc_probe is the syscall-args needs check (None = needs unproven, skipped --
    the pre-descriptor behavior for gadgets without an sc)."""

    name: str
    uc_arch: int
    uc_mode: typing.Callable[[int], int]  # entry -> mode (entry bits may pick the mode, e.g. thumb)
    word: int
    pack: str
    reg_id: typing.Callable[[cento.machine.Slot], int | None]
    pc_read: typing.Callable[[typing.Any], int]
    lr_slot: cento.machine.Slot | None
    frame_sibling: cento.machine.Slot | None
    seed_regs: tuple[cento.machine.Slot, ...]
    sc_probe: typing.Callable[[typing.Any, int], tuple[int, ...] | None] | None  # (uc, address) -> recorded args, or None when not the syscall insn


def _poison(ex: _ArchExec, idx: int) -> int:
    """Default seed for seed_regs[idx]: 0xEE in the top byte, the slot's index in the low bits."""
    return 0xEE << (8 * ex.word - 8) | idx


def _needs(ex: _ArchExec, idx: int) -> int:
    """Needs seed for seed_regs[idx]: 0x5A in the top byte, the slot's index in the low bits."""
    return 0x5A << (8 * ex.word - 8) | idx


def _slot(ex: _ArchExec, off: int) -> int:
    """Frame-slot sentinel (one word, ex.pack, at frame+off): 0xA5 in the top byte, the offset in the low bits."""
    return 0xA5 << (8 * ex.word - 8) | off


def _decode_val(v: int, ex: _ArchExec) -> str:
    """Name the sentinel family an observed word-sized value belongs to (frame slot / needs seed / poison seed / zero / unknown)."""
    if v == 0:
        return "zero"
    top = 8 * ex.word - 8
    fam, low = v >> top, v & ((1 << top) - 1)
    if fam == 0xA5:
        return f"frame[+0x{low:x}]"
    if fam == 0x5A and low < len(ex.seed_regs):
        return f"needs {cento.machine.slot_name(ex.seed_regs[low])}"
    if fam == 0xEE and low < len(ex.seed_regs):
        return f"poison {cento.machine.slot_name(ex.seed_regs[low])}"
    return "unknown"


def _default_abi() -> cento.machine.AbiSpec:
    """The default-target ABI for verify_transfer(abi=None)."""
    return cento.abi.x86_64.X86_64


def _sc_probe_ppc(u: typing.Any, address: int) -> tuple[int, ...] | None:
    """The sc-stub hook idiom: if the word at address is `sc` (0x44000002), record r3..r7, force rc=0, and skip the instruction.

    Returns the recorded syscall args, or None when the instruction is not an sc. Forcing rc=0 means the SYSCALL_TAIL
    reentry `blt` retry never fires (a real negative rc would loop; out of scope for both executors).
    """
    if bytes(u.mem_read(address, 4)) != b"\x44\x00\x00\x02":
        return None
    ppc = unicorn.ppc_const
    args = tuple(int(u.reg_read(int(ppc.UC_PPC_REG_0) + n)) for n in range(3, 8))
    u.reg_write(int(ppc.UC_PPC_REG_3), 0)
    u.reg_write(int(ppc.UC_PPC_REG_PC), address + 4)
    return args


def _sc_probe_x86(u: typing.Any, address: int) -> tuple[int, ...] | None:
    """x86-64 syscall probe: if the bytes at address are `syscall` (0f 05), record the SysV arg registers, force rax=0, and skip the instruction."""
    if bytes(u.mem_read(address, 2)) != b"\x0f\x05":
        return None
    x86 = unicorn.x86_const
    arg_ids = (x86.UC_X86_REG_RDI, x86.UC_X86_REG_RSI, x86.UC_X86_REG_RDX, x86.UC_X86_REG_R10, x86.UC_X86_REG_R8, x86.UC_X86_REG_R9)
    args = tuple(int(u.reg_read(int(r))) for r in arg_ids)
    u.reg_write(int(x86.UC_X86_REG_RAX), 0)
    u.reg_write(int(x86.UC_X86_REG_RIP), address + 2)
    return args


def _sc_probe_a64(u: typing.Any, address: int) -> tuple[int, ...] | None:
    """AArch64 syscall probe: if the word at address is `svc #0` (LE 01 00 00 d4), record x0..x5, force x0=0, and skip the instruction."""
    if bytes(u.mem_read(address, 4)) != b"\x01\x00\x00\xd4":
        return None
    a64 = unicorn.arm64_const
    args = tuple(int(u.reg_read(int(a64.UC_ARM64_REG_X0) + n)) for n in range(6))
    u.reg_write(int(a64.UC_ARM64_REG_X0), 0)
    u.reg_write(int(a64.UC_ARM64_REG_PC), address + 4)
    return args


def _sc_probe_a32(u: typing.Any, address: int) -> tuple[int, ...] | None:
    """ARM32 syscall probe: if the word at address is an ARM-mode `svc` (cond AL: top byte 0xef at LE offset 3), record r0..r6, force r0=0, and skip.

    Thumb-mode svc is out of scope: the probe checks the ARM encoding only, so a Thumb gadget
    with needs simply skips the needs check (the documented no-probe behavior).
    """
    if bytes(u.mem_read(address, 4))[3] != 0xEF:
        return None
    a32 = unicorn.arm_const
    args = tuple(int(u.reg_read(int(a32.UC_ARM_REG_R0) + n)) for n in range(7))
    u.reg_write(int(a32.UC_ARM_REG_R0), 0)
    u.reg_write(int(a32.UC_ARM_REG_PC), address + 4)
    return args


_EXEC_CACHE: dict[str, _ArchExec] = {}


def _validate_exec(ex: _ArchExec) -> None:
    """The seed_regs<->reg_id invariant: every seed slot must be reg_id-mapped, refused before the descriptor is published."""
    unmapped = [cento.machine.slot_name(s) for s in ex.seed_regs if ex.reg_id(s) is None]
    if unmapped:
        raise cento.errors.VerifyError(f"descriptor {ex.name!r}: seed_regs not reg_id-mapped: {', '.join(unmapped)} -- map every seed slot")


def _executors() -> dict[str, _ArchExec]:
    """The descriptor registry, built lazily (unicorn consts exist only once import succeeded).

    Descriptors are built into a local dict and validated (_validate_exec) BEFORE publishing to
    _EXEC_CACHE: a refusal must not leave a broken registry cached for the next caller.
    """
    if _EXEC_CACHE:
        return _EXEC_CACHE
    built: dict[str, _ArchExec] = {}
    ppc = unicorn.ppc_const
    gprs: tuple[cento.machine.Slot, ...] = tuple(cento.machine.Reg(n) for n in range(32)) + (cento.machine.Reg.LR, cento.machine.Reg.CTR)
    ppc_ids: dict[cento.machine.Slot, int] = {cento.machine.Reg(n): int(ppc.UC_PPC_REG_0) + n for n in range(32)}
    ppc_ids[cento.machine.Reg.LR] = int(ppc.UC_PPC_REG_LR)
    ppc_ids[cento.machine.Reg.CTR] = int(ppc.UC_PPC_REG_CTR)
    ppc_ids[cento.machine.Role.SP] = ppc_ids[cento.machine.Reg.SP]

    built["ppc32"] = _ArchExec(
        name="ppc32",
        uc_arch=unicorn.UC_ARCH_PPC,
        uc_mode=lambda _entry: unicorn.UC_MODE_PPC32 | unicorn.UC_MODE_BIG_ENDIAN,
        word=4,
        pack=">I",
        reg_id=ppc_ids.get,
        pc_read=lambda u: int(u.reg_read(int(ppc.UC_PPC_REG_PC))),
        lr_slot=cento.machine.Reg.LR,
        frame_sibling=cento.machine.Reg.R3,
        seed_regs=gprs,
        sc_probe=_sc_probe_ppc,
    )

    # The remaining const modules are guarded individually: a partial unicorn build simply lacks
    # that arch's registry entry, and the dispatch's "no executor for abi ..." error covers it.
    try:
        import unicorn.x86_const as x86
    except ImportError:
        pass
    else:
        x64_names = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
        x64_ids: dict[cento.machine.Slot, int] = {n: int(getattr(x86, f"UC_X86_REG_{n.upper()}")) for n in x64_names}
        x64_ids[cento.machine.Role.SP] = int(x86.UC_X86_REG_RSP)
        built["x86_64"] = _ArchExec(
            name="x86_64",
            uc_arch=unicorn.UC_ARCH_X86,
            uc_mode=lambda _entry: unicorn.UC_MODE_64,
            word=8,
            pack="<Q",
            reg_id=x64_ids.get,
            pc_read=lambda u: int(u.reg_read(int(x86.UC_X86_REG_RIP))),
            lr_slot=None,
            frame_sibling=None,
            seed_regs=tuple(x64_names),
            sc_probe=_sc_probe_x86,
        )

    try:
        import unicorn.arm64_const as a64
    except ImportError:
        pass
    else:
        a64_names = tuple(f"x{i}" for i in range(31))
        a64_ids: dict[cento.machine.Slot, int] = {f"x{i}": int(getattr(a64, f"UC_ARM64_REG_X{i}")) for i in range(31)}
        a64_ids[cento.machine.Role.SP] = int(a64.UC_ARM64_REG_SP)
        built["aarch64"] = _ArchExec(
            name="aarch64",
            uc_arch=unicorn.UC_ARCH_ARM64,
            uc_mode=lambda _entry: unicorn.UC_MODE_ARM,
            word=8,
            pack="<Q",
            reg_id=a64_ids.get,
            pc_read=lambda u: int(u.reg_read(int(a64.UC_ARM64_REG_PC))),
            lr_slot="x30",
            frame_sibling=None,
            seed_regs=a64_names,
            sc_probe=_sc_probe_a64,
        )

    try:
        import unicorn.arm_const as a32
    except ImportError:
        pass
    else:
        a32_names: tuple[cento.machine.Slot, ...] = tuple(f"r{i}" for i in range(13)) + ("r14",)
        a32_ids: dict[cento.machine.Slot, int] = {f"r{i}": int(a32.UC_ARM_REG_R0) + i for i in range(13)}
        a32_ids["r14"] = int(a32.UC_ARM_REG_LR)
        a32_ids[cento.machine.Role.SP] = int(a32.UC_ARM_REG_SP)
        built["arm32"] = _ArchExec(
            name="arm32",
            uc_arch=unicorn.UC_ARCH_ARM,
            uc_mode=lambda entry: unicorn.UC_MODE_THUMB if entry & 1 else unicorn.UC_MODE_ARM,
            word=4,
            pack="<I",
            reg_id=a32_ids.get,
            pc_read=lambda u: int(u.reg_read(int(a32.UC_ARM_REG_PC))),
            lr_slot=None,
            frame_sibling=None,
            seed_regs=a32_names,
            sc_probe=_sc_probe_a32,
        )

    for arch in built.values():  # validate every descriptor pre-publish: a refusal here caches nothing
        _validate_exec(arch)
    _EXEC_CACHE.update(built)
    return _EXEC_CACHE


def verify_transfer(
    gadget_cls: cento.gadget.GadgetMeta,
    source: CodeSource,
    as_name: str,
    *,
    abi: cento.machine.AbiSpec | str | None = None,
    max_insns: int = 512,
) -> Verdict:
    """Execute a gadget's real bytes under Unicorn with sentinel-seeded state; compare against its declared Transfer.

    abi= takes an AbiSpec or a shipped name string ("x86_64"); None means the default target
    (x86-64). Divergence prefixes are stable, like CHK codes -- existing prefixes keep their
    meaning; new checks get new prefixes ("pc-source:", "restore:<REG>", "sp-policy",
    "needs:<REG>", "insn-budget"). Undeclared register writes are warnings (ABI-nonvolatile) or
    observations (ABI-volatile); CR/XER are never compared.
    """
    abi = cento.abi.resolve(abi) if abi is not None else _default_abi()
    if not HAVE_UNICORN:
        raise cento.errors.VerifyError("unicorn not installed -- pip install unicorn>=2.1; the merge gate does not require it")
    ex = _executors().get(abi.name)
    if ex is None:
        raise cento.errors.VerifyError(f"no executor for abi {abi.name!r} -- descriptors exist for: {', '.join(sorted(_executors()))}")
    if not isinstance(gadget_cls.entry, int):
        raise cento.errors.VerifyError(
            f"{gadget_cls.gname}: symbolic entry ({cento.gadget.entry_str(gadget_cls.entry)}) cannot be emulated -- verify a build with absolute addresses"
        )
    entry: int = gadget_cls.entry
    window = source.read(as_name, entry, WINDOW_LEN)
    hexw = 2 * ex.word  # hex digits in a rendered machine word
    idx_of = {slot: i for i, slot in enumerate(ex.seed_regs)}
    seed_by_id: dict[int, cento.machine.Slot] = {rid: s for s in ex.seed_regs if (rid := ex.reg_id(s)) is not None}
    sp_id = ex.reg_id(cento.machine.Role.SP)
    if sp_id is None:
        raise cento.errors.VerifyError(f"descriptor {ex.name!r} maps no unicorn register for Role.SP -- fix its _ArchExec reg_id")

    # -- spec extraction: restores (slot -> frame offset), clobbers ----------------------------
    restores: dict[cento.machine.Slot, int] = {}
    clobbers: set[cento.machine.Slot] = set()
    for slot, ctl in gadget_cls.transfer.controls.items():
        if slot is not cento.machine.Role.PC and ex.reg_id(slot) is None:
            continue  # reg_id=None: the descriptor cannot read this slot, so it is skipped rather than failed; Role.PC stays, judged via pc_read
        if isinstance(ctl, cento.machine.Load):
            restores[slot] = ctl.field.offset
        elif isinstance(ctl, cento.machine.Clobber):
            clobbers.add(slot)
    frame_base: cento.machine.Slot = gadget_cls.transfer.frame_base
    sp_framed = frame_base is cento.machine.Role.SP

    # -- memory: AS text window page-rounded at its va; frame scratch page --------------------
    uc_mod: typing.Any = unicorn  # Any-alias: unicorn ships py.typed but does not re-export Uc/UcError for strict mypy; handles stay Any
    uc = uc_mod.Uc(ex.uc_arch, ex.uc_mode(entry))
    va_base, text = source.text_window(as_name)
    map_base = va_base & ~0xFFF
    map_len = ((va_base - map_base) + len(text) + 0xFFF) & ~0xFFF
    uc.mem_map(map_base, map_len, unicorn.UC_PROT_ALL)
    uc.mem_write(va_base, text)
    uc.mem_map(_FRAME_PAGE, _FRAME_SIZE, unicorn.UC_PROT_ALL)
    frame_addr = _SP_FRAME_SP if sp_framed else _FRAME_PAGE
    for at in restores.values():  # every Restores field, external included (same page)
        uc.mem_write(frame_addr + at, struct.pack(ex.pack, _slot(ex, at)))

    # -- seeding: poison, then needs, then frame pointers (frame seeding wins) ----------------
    seeds: dict[cento.machine.Slot, int] = {slot: _poison(ex, i) for i, slot in enumerate(ex.seed_regs)}
    # SP-frame gadgets carry the frame in SP; pointer-frame ones in frame_base AND the descriptor's
    # frame_sibling (PPC32's longjmp-class convention passes the pointer in r3; see module docstring).
    frame_ids: set[int] = {sp_id} if sp_framed else {i for s in (frame_base, ex.frame_sibling) if s is not None and (i := ex.reg_id(s)) is not None}
    needs_slots = [seed_by_id[i] for s in gadget_cls.needs if (i := ex.reg_id(s)) is not None and i in seed_by_id and i not in frame_ids]
    for slot in needs_slots:
        seeds[slot] = _needs(ex, idx_of[slot])
    for i in frame_ids:  # a frame register may not be a seed slot (x86-64 keeps rsp out of seed_regs): write it directly either way
        if (frame_slot := seed_by_id.get(i)) is not None:
            seeds[frame_slot] = frame_addr
    for slot, val in seeds.items():
        uc.reg_write(ex.reg_id(slot), val)
    for i in frame_ids:
        uc.reg_write(i, frame_addr)

    # -- one UC_HOOK_CODE over the AS range: insn budget + sc detection -----------------------
    divergences: list[str] = []
    insns = [0]
    sc_events: list[tuple[int, ...]] = []
    budget_hit = [False]

    def _hook_code(u: typing.Any, address: int, size: int, _ud: typing.Any) -> None:
        insns[0] += 1
        if insns[0] > max_insns:
            if not budget_hit[0]:
                budget_hit[0] = True
                divergences.append(f"insn-budget: exceeded {max_insns}")
            u.emu_stop()
            return
        if ex.sc_probe is not None:
            args = ex.sc_probe(u, address)
            if args is not None:
                sc_events.append(args)

    uc.hook_add(unicorn.UC_HOOK_CODE, _hook_code, begin=map_base, end=map_base + map_len - 1)

    # -- run ----------------------------------------------------------------------------------
    stop = "clean-exit"
    faulted: str | None = None
    try:
        uc.emu_start(entry, 0)
        if budget_hit[0]:
            stop = "emu-stop"
    except uc_mod.UcError as e:
        if e.errno == unicorn.UC_ERR_FETCH_UNMAPPED:
            stop = "clean-fault"  # the intentional off-the-end fetch: how a completed gadget "exits"
        else:
            stop = f"uc-error: {e}"
            faulted = str(e)  # any other fault mid-flight is a divergence: control never transferred
    final_pc = ex.pc_read(uc)
    final: dict[cento.machine.Slot, int] = {slot: int(uc.reg_read(ex.reg_id(slot))) for slot in seeds}
    if faulted is not None:
        divergences.append(f"stop: gadget faulted mid-flight ({faulted}); control never transferred")

    # -- verdict assembly ----------------------------------------------------------------------
    observations: list[tuple[str, str]] = []
    pc_at = restores.get(cento.machine.Role.PC)
    if pc_at is not None:
        exp = _slot(ex, pc_at)
        if final_pc != exp:
            divergences.append(f"pc-source: expected frame[+0x{pc_at:x}] (0x{exp:0{hexw}x}) observed 0x{final_pc:0{hexw}x} ({_decode_val(final_pc, ex)})")
    for slot in sorted((s for s in restores if s not in (cento.machine.Role.PC, cento.machine.Role.SP)), key=idx_of.__getitem__):
        at = restores[slot]
        exp, obs = _slot(ex, at), final[slot]
        if obs != exp:
            divergences.append(
                f"restore:{cento.machine.slot_name(slot)}: expected frame[+0x{at:x}] (0x{exp:0{hexw}x}) observed 0x{obs:0{hexw}x} ({_decode_val(obs, ex)})"
            )
    sp_exp: int | None = None
    if sp_framed:
        sp_exp = _SP_FRAME_SP + gadget_cls.stride
    elif cento.machine.Role.SP in restores:
        sp_exp = _slot(ex, restores[cento.machine.Role.SP])
    if sp_exp is not None:
        sp_obs = int(uc.reg_read(sp_id))  # via sp_id, not the seed snapshot: SP need not be a seed slot
        if sp_obs != sp_exp:
            divergences.append(f"sp-policy: expected 0x{sp_exp:0{hexw}x} observed 0x{sp_obs:0{hexw}x} ({_decode_val(sp_obs, ex)})")
    if sc_events:  # no sc -> skipped (pointer-frame needs are proven implicitly by the frame reads)
        for slot in needs_slots:
            if _needs(ex, idx_of[slot]) not in sc_events[0]:
                divergences.append(f"needs:{cento.machine.slot_name(slot)} sentinel not observed in syscall args")

    warnings: list[str] = []
    excluded_ids = {ex.reg_id(s) for s in restores} | {ex.reg_id(s) for s in clobbers} | {sp_id}
    for slot in ex.seed_regs:
        if ex.reg_id(slot) in excluded_ids or final[slot] == seeds[slot]:
            continue
        if ex.lr_slot is not None and slot == ex.lr_slot and final[slot] == final_pc and pc_at is not None:
            continue  # LR is the pc-alias of the declared PC restore
        if slot in abi.volatile:
            observations.append(("volatile-write:" + cento.machine.slot_name(slot), hex(final[slot])))
        else:
            warnings.append(f"undeclared-nonvolatile-write:{cento.machine.slot_name(slot)}={_decode_val(final[slot], ex)}")

    observations += [("insns", str(insns[0])), ("sc_count", str(len(sc_events))), ("final_pc", hex(final_pc)), ("stop", stop)]
    if sc_events:
        observations.append(("sc0_args", "(" + ", ".join(hex(a) for a in sc_events[0]) + ")"))
    verdict = Verdict(
        gadget=gadget_cls.gname,
        entry=entry,
        spec_sha16=cento.gadget.spec_sha16(gadget_cls),
        bytes_sha16=cento.gadget.bytes_sha16(window),
        ok=not divergences,
        divergences=tuple(divergences),
        warnings=tuple(warnings),
        observations=tuple(sorted(observations)),
    )
    return verdict
