# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Verify executor contracts: the descriptor dispatch (Task 7, replacing Task 1's interim
guard), the PPC32 golden verdict (Task 6), and the per-arch executors (Task 8)."""

from __future__ import annotations

import pytest

import cento
import cento.abi.aarch64
import cento.abi.arm32
import cento.abi.x86_64
import cento.errors as errors
import cento.machine as machine
import cento.verify as verify

Reg = machine.Reg
X86_64 = cento.abi.x86_64.X86_64
AARCH64 = cento.abi.aarch64.AARCH64
ARM32 = cento.abi.arm32.ARM32


class _MemSource:
    """In-memory CodeSource: a blob mapped at base (the whole verify test fixture surface)."""

    def __init__(self, base: int, blob: bytes) -> None:
        self.base = base
        self.blob = blob

    def read(self, name: str, addr: int, length: int) -> bytes:
        return self.blob[addr - self.base : addr - self.base + length]

    def text_window(self, name: str) -> tuple[int, bytes]:
        return (self.base, self.blob)


HAVE_UNICORN = verify.HAVE_UNICORN


@pytest.mark.skipif(not HAVE_UNICORN, reason="unicorn not installed ([verify] extra)")
def test_unknown_abi_name_refuses() -> None:
    """An AbiSpec whose name has no descriptor is refused by name, with the known names listed."""
    bare = machine.AbiSpec(name="m68k", volatile=frozenset(), nonvolatile=frozenset())

    class G(cento.Gadget, entry=0x1000, stride=0x8):
        pc = cento.Restores(Reg.PC, at=0x0)

    with pytest.raises(errors.VerifyError, match="no executor for abi 'm68k'"):
        verify.verify_transfer(G, _MemSource(0x1000, b"\x00" * 8), "t", abi=bare)


def test_validate_exec_refuses_unmapped_seed_slot() -> None:
    """The fail-closed descriptor invariant: a seed slot with no reg_id mapping refuses in
    _validate_exec, which _executors() runs per descriptor BEFORE publishing to its cache --
    a broken descriptor never becomes the registry a second caller reads."""
    broken = verify._ArchExec(
        name="broken",
        uc_arch=0,
        uc_mode=lambda _entry: 0,
        word=4,
        pack="<I",
        reg_id=lambda _slot: None,
        pc_read=lambda _u: 0,
        lr_slot=None,
        frame_sibling=None,
        seed_regs=("r0",),
        sc_probe=None,
    )
    with pytest.raises(errors.VerifyError, match="descriptor 'broken': seed_regs not reg_id-mapped: r0"):
        verify._validate_exec(broken)


# lwz r30, 0x18(r1); lwz r0, 0x24(r1); mtlr r0; addi r1, r1, 0x20; blr
_PPC_TAIL = bytes.fromhex("83c10018 80010024 7c0803a6 38210020 4e800020")
_PPC_BASE = 0x40001000


class PpcTail(cento.Gadget, entry=_PPC_BASE, stride=0x20):
    """0x40001000: lwz r30, 0x18(r1); lwz r0, 0x24(r1); mtlr r0; addi r1, r1, 0x20; blr"""

    r30 = cento.Restores(Reg.R30, at=0x18)
    pc = cento.Restores(Reg.PC, at=0x24, external=True)
    needs = {Reg.R30: "value the next hop consumes"}


@pytest.mark.skipif(not HAVE_UNICORN, reason="unicorn not installed ([verify] extra)")
def test_ppc32_verdict_golden() -> None:
    """The R15 wall: the descriptor refactor must reproduce this verdict byte-for-byte
    (divergence prefixes and observation strings are contract, like CHK codes)."""
    import cento.abi.ppc32

    v = verify.verify_transfer(PpcTail, _MemSource(_PPC_BASE, _PPC_TAIL), "fw", abi=cento.abi.ppc32.PPC32)
    assert v.ok, v.divergences
    assert v.to_json() == {
        "gadget": "PpcTail",
        "entry": 0x40001000,
        "spec_sha16": "9fe4625269dc60e2",
        "bytes_sha16": "9592a00b27c1d822",
        "ok": True,
        "divergences": [],
        "warnings": [],
        # final_pc 0xa5000024: the frame-slot sentinel (0xA5 top byte, slot offset 0x24 low bits) for the external pc restore
        "observations": [["final_pc", "0xa5000024"], ["insns", "5"], ["sc_count", "0"], ["stop", "clean-fault"], ["volatile-write:R0", "0xa5000024"]],
    }


# pop rdi; ret
_X64_POPRDI = bytes.fromhex("5f c3")
# pop rsi; ret -- the deliberate divergence twin (restores rsi, declared as rdi)
_X64_POPRSI = bytes.fromhex("5e c3")
_X64_BASE = 0x7F0000010000


class X64PopRdi(cento.Gadget, entry=_X64_BASE, stride=0x10):
    """0x7f0000010000: pop rdi; ret"""

    rdi = cento.Restores("rdi", at=0x0, width=cento.u64)
    pc = cento.Restores(Reg.PC, at=0x8, width=cento.u64)


@pytest.mark.skipif(not HAVE_UNICORN, reason="unicorn not installed ([verify] extra)")
def test_x86_64_executor_pass() -> None:
    v = verify.verify_transfer(X64PopRdi, _MemSource(_X64_BASE, _X64_POPRDI), "t", abi=X86_64)
    assert v.ok, v.divergences


@pytest.mark.skipif(not HAVE_UNICORN, reason="unicorn not installed ([verify] extra)")
def test_x86_64_executor_catches_wrong_restore() -> None:
    # declared rdi, bytes pop rsi: the frame sentinel lands in the wrong register
    v = verify.verify_transfer(X64PopRdi, _MemSource(_X64_BASE, _X64_POPRSI), "t", abi=X86_64)
    assert not v.ok and any(d.startswith("restore:rdi") for d in v.divergences)


# Progression endgame: Task 1's interim guard said "only the ppc32 executor"; Task 7's dispatch
# refused abi=None ("no executor for abi 'x86_64'") until the descriptor existed; Task 8 lands
# it, so the default target verifies for real.
@pytest.mark.skipif(not HAVE_UNICORN, reason="unicorn not installed ([verify] extra)")
def test_default_abi_is_x86_64() -> None:
    """abi=None dispatches the x86_64 descriptor: a PASS verdict with no abi= argument."""
    v = verify.verify_transfer(X64PopRdi, _MemSource(_X64_BASE, _X64_POPRDI), "t")
    assert v.ok, v.divergences


@pytest.mark.skipif(not HAVE_UNICORN, reason="unicorn not installed ([verify] extra)")
def test_verify_transfer_accepts_abi_name() -> None:
    v = verify.verify_transfer(X64PopRdi, _MemSource(_X64_BASE, _X64_POPRDI), "t", abi="x86_64")
    assert v.ok, v.divergences


def test_verify_transfer_teaches_on_junk_abi_name() -> None:
    """A junk name refuses at resolve, before the unicorn gate -- no emulator required to learn the vocabulary."""
    with pytest.raises(errors.PlacementError, match="unknown abi 'amd64'"):
        verify.verify_transfer(X64PopRdi, _MemSource(_X64_BASE, _X64_POPRDI), "t", abi="amd64")


# ldp x29, x30, [sp], #0x10; ret
_A64_LDPRET = bytes.fromhex("fd7bc1a8 c0035fd6")
_A64_BASE = 0x7F0000020000


class A64Epilogue(cento.Gadget, entry=_A64_BASE, stride=0x10):
    """0x7f0000020000: ldp x29, x30, [sp], #0x10; ret"""

    x29 = cento.Restores("x29", at=0x0, width=cento.u64)
    pc = cento.Restores(Reg.PC, at=0x8, width=cento.u64)


@pytest.mark.skipif(not HAVE_UNICORN, reason="unicorn not installed ([verify] extra)")
def test_aarch64_executor_pass() -> None:
    v = verify.verify_transfer(A64Epilogue, _MemSource(_A64_BASE, _A64_LDPRET), "t", abi=AARCH64)
    assert v.ok, v.divergences


# pop {r4, pc}  (ARM encoding e8bd8010, little-endian bytes)
_A32_POPR4PC = bytes.fromhex("1080bde8")
# pop {r5, pc} -- the deliberate divergence twin (restores r5, declared as r4)
_A32_POPR5PC = bytes.fromhex("2080bde8")
# Thumb pop {r4, pc} (bd10), entry spelled with bit 0
_A32_THUMB_POP = bytes.fromhex("10bd")
_A32_BASE = 0x00010000


class A32PopR4(cento.Gadget, entry=_A32_BASE, stride=0x8):
    """0x10000: pop {r4, pc}"""

    r4 = cento.Restores("r4", at=0x0)
    pc = cento.Restores(Reg.PC, at=0x4)


class A32ThumbPop(cento.Gadget, entry=_A32_BASE | 1, stride=0x8):
    """0x10001: pop {r4, pc} (Thumb; entry bit 0 selects the mode)"""

    r4 = cento.Restores("r4", at=0x0)
    pc = cento.Restores(Reg.PC, at=0x4)


@pytest.mark.skipif(not HAVE_UNICORN, reason="unicorn not installed ([verify] extra)")
def test_arm32_executor_pass() -> None:
    v = verify.verify_transfer(A32PopR4, _MemSource(_A32_BASE, _A32_POPR4PC), "t", abi=ARM32)
    assert v.ok, v.divergences


@pytest.mark.skipif(not HAVE_UNICORN, reason="unicorn not installed ([verify] extra)")
def test_arm32_executor_catches_wrong_restore() -> None:
    # declared r4, bytes pop {r5, pc}: the frame sentinel lands in the wrong register
    v = verify.verify_transfer(A32PopR4, _MemSource(_A32_BASE, _A32_POPR5PC), "t", abi=ARM32)
    assert not v.ok and any(d.startswith("restore:r4") for d in v.divergences)


@pytest.mark.skipif(not HAVE_UNICORN, reason="unicorn not installed ([verify] extra)")
def test_arm32_thumb_entry_selects_thumb_mode() -> None:
    v = verify.verify_transfer(A32ThumbPop, _MemSource(_A32_BASE, _A32_THUMB_POP), "t", abi=ARM32)
    assert v.ok, v.divergences  # entry bit 0 selected UC_MODE_THUMB; the 16-bit pop executed
