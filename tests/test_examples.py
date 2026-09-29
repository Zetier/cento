# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Smoke tests for the examples/ tree: the ex00 and ex01 before/after pairs are checked end
to end (byte equality + shape-asserted refusal + current transcripts), and each tutorial's
main() runs green and prints its signature artifacts.

Also pins the shareability property structurally: an OPSEC guard asserts the example files
carry no real-target vocabulary (the examples describe a fictional device, the Meridian MK-1).
"""

from __future__ import annotations

import contextlib
import io
import pathlib
import shutil

import pytest

import cento.verify
import examples
import examples.ex01.ex01_find_your_offset
import examples.ex02.ex02_toy_chain
import examples.ex03.ex03_local_ret2win
import examples.ex04.ex04_qemu_ret2win
import examples.ex05.ex05_computed_cells
import examples.ex06.ex06_delivery_plan
import examples.ex07.ex07_guardrails
import examples.ex08.ex08_borrowed_structures
import examples.ex09.ex09_fake_frame_chain
import examples.ex10.ex10_provenance
import examples.ex11.ex11_the_thrower
import examples.ex12.ex12_aarch64_chain
import examples.ex13.ex13_arm32_chain
import examples.ex14.ex14_port_a_script

EXAMPLES_DIR = pathlib.Path(examples.__file__).parent


def _run_main(mod: object, *args: object) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        main = getattr(mod, "main")  # noqa: B009 - explicit: every example module must export main()
        main(*args)
    return buf.getvalue()


def test_find_your_offset_round_trips_cycle_find_and_lands_the_eip() -> None:
    out = _run_main(examples.ex01.ex01_find_your_offset, [])  # argv=[]: parse_args() must not see pytest's argv
    assert "eip=0x61616173" in out  # the "crash": the given segfault-report value, 4 pad bytes ('saaa') little-endian
    assert "-> offset 72 (0x48)" in out  # cycle_find() names the ret offset from the observed value
    assert "e2910408" in out  # the step-3 hexdump carries win (0x080491e2) at that offset, little-endian in memory
    assert "17 cyclic pad words" in out and "[frame.raw+*]" in out  # pad noise summarized; named rows stay
    assert "[frame.pops.ret]" in out  # the closing beat: the ret slot as a named place, no waivers
    assert out.index("eip=0x61616173") < out.index("-> offset 72 (0x48)")  # observe first, THEN locate


def test_wire_image_runs_and_prints_fixups_then_bytes() -> None:
    out = _run_main(examples.ex05.ex05_computed_cells)
    assert "awaits session_key" in out  # pre-bind emit returns fixups naming the missing symbol
    assert "????????" in out  # the unresolved cell renders as placeholders in the hexdump
    assert "region pkt (base=" in out  # hexdump backend header row
    assert "4d504b54" in out  # post-bind image bytes: 'MPKT' magic, big-endian
    assert out.count("fixup:") >= 2  # one late symbol -> BOTH the raw cell and the checksum that covers it


def test_toy_chain_runs_and_narrates_the_writeback() -> None:
    out = _run_main(examples.ex02.ex02_toy_chain)
    assert "writeback 'boot_token'" in out  # narrate(): the kernel-written cell is attributed to its hop
    assert "R30 <- effect:boot_token" in out  # the next hop's need is fed by the writeback, not a seat
    assert "writeback-by: effect mint_token_writeback output boot_token" in out  # explain() names the flow
    assert "check: 0 errors, 0 warnings, 0 pending" in out  # check() report renders clean
    assert "(finished)" in out  # the chain reached its terminal


def test_toy_chain_prints_ropper_style_gadget_lines() -> None:
    out = _run_main(examples.ex02.ex02_toy_chain)
    assert "gadgets:" in out  # main() opens with the disassembly catalog
    assert "0x40001000: lwz r0, 0x0(r31); mtlr r0;" in out  # CtxRestore: pc restored from +0x00(r31)
    assert "0x40002000: mr r3, r30; mr r4, r31; bl demo_syscall;" in out  # RetTail: the needs, then the frame pops


def test_delivery_plan_gates_arm_and_saves_a_ledger() -> None:
    out = _run_main(examples.ex06.ex06_delivery_plan)
    assert "finalize() refused: unconfirmed groups" in out  # ARM gate: outstanding deliveries block final
    assert "finalize() refused: unresolved symbols" in out  # ARM gate: the late bind is mandatory
    assert "(NORMAL < LATE)" in out  # stage() banner names the delivery order
    assert "[LATE]" in out  # the held-back cell delivers after every NORMAL group
    assert "[ARM]" in out  # the trigger group is delivered last, explicitly labelled
    assert '"ev": "arm_intent"' in out  # write-ahead ledger line, recorded BEFORE the ARM group yields
    assert "ledger:" in out  # the audit trail was saved


def test_delivery_plan_prints_ropper_style_gadget_lines() -> None:
    out = _run_main(examples.ex06.ex06_delivery_plan)
    assert "gadgets:" in out
    assert "0x40001000: lwz r0, 0x0(r31); mtlr r0; lwz r30, 0x4(r31); lwz r31, 0x8(r31); blr" in out  # CtxLaunch geometry


def test_guardrails_seven_scenes_print_real_refusals() -> None:
    out = _run_main(examples.ex07.ex07_guardrails)
    assert "CHK-001" in out  # scene 1: undeclared placement overlap, named by check()
    assert "CHK-008" in out  # scene 2: same-cell rewrite by a second owner (last-writer-wins, judged)
    assert "CHK-201" in out  # scene 3: starved hop need under Carry.Clobbered -- seal() raises the issue text
    assert "CHK-006" in out  # scene 4: aliased cells disagreeing on shared bytes
    assert "exceeds max_size" in out  # scene 5: eager PlacementError at construction, not at check()
    assert "CHK-011" in out and "forbidden transport byte(s) 0x00" in out  # scene 6: the gadget address itself carries NULs
    assert "fixed with a string-safe sibling gadget: errors = []" in out  # scene 6: the fix idiom lands
    assert "finalize() refused" in out  # scene 7: the plan gates recap (unconfirmed / unresolved)
    assert "waivers are code-reviewable intent" in out  # the closing line: every escape hatch requires a reason


def test_split_relocations_derives_both_halves_from_one_symbol() -> None:
    out = _run_main(examples.ex05.ex05_computed_cells)
    assert "fixup: cfg.lui.imm (cfg+0x0012 w2) awaits mk2_lib_base" in out  # the lui immediate is itself a fixup awaiting the leak
    assert "hi16(target) = 0x4001" in out  # the buggy high half, printed next to...
    assert "ha16(target) = 0x4002" in out  # ...the carry-adjusted one (lo16 >= 0x8000)
    assert "buggy veneer lands at 0x40008a50" in out  # the lis/addi carry bug, reproduced and measured


def test_fake_heap_chunk_declares_the_hostile_overlap() -> None:
    out = _run_main(examples.ex08.ex08_borrowed_structures)
    assert "CHK-001 [msg.body, msg.fake_chunk]" in out  # the undeclared forgery, refused by name
    assert "fixup: msg.fake_chunk.where (msg+0x0028 w4) awaits write_target" in out  # the WHERE of the unlink write is a late symbol
    assert "size tag, kept twice: head=0x0008 foot=0x0008" in out  # boundary tags reduce one span; no drift
    assert "40200e5440600100" in out  # final bytes: bk = write_target - 0xc, fd = write_value, adjacent


def test_fake_object_vtable_sequences_vptr_late_and_trigger_last() -> None:
    out = _run_main(examples.ex08.ex08_borrowed_structures)
    assert "[LATE] 1 cells" in out  # the vptr held back until every NORMAL cell has landed
    assert "refused (unconfirmed): finalize() refused: unconfirmed groups" in out  # ARM gate 1
    assert "refused (unresolved): finalize() refused: unresolved symbols ['boot_cookie']" in out  # ARM gate 2
    assert "[ARM] 1 cells" in out  # the registry write that makes the forged object live goes last


def test_fake_frame_chain_threads_the_kernel_token_through_heap_frames() -> None:
    out = _run_main(examples.ex09.ex09_fake_frame_chain)
    assert "spend_token: R30 <- effect:session_token" in out  # the fold proves the capability flow, not a seat
    assert "writeback-by: effect mint_result output session_token" in out  # explain() names the runtime write
    assert "seal(): green" in out  # the chain judged whole
    assert "CHK-001 [heap.map_args, heap.stack.mint_token]" in out  # the mid-chain-alloc trap, by name


def test_tlv_records_nested_lengths_and_the_deliberate_lie() -> None:
    out = _run_main(examples.ex05.ex05_computed_cells)
    assert "fixup: msg.hdr.crc (msg+0x0008 w4) awaits session_token" in out  # the outer CRC blocked by one unbound record field
    assert "lengths, all derived: total_len=0x30, per-record payload_len=[8, 8, 8]" in out  # nobody typed a length
    assert "ERROR CHK-005 [msg.hdr.crc]: reduce crc32_mpeg2 = 0x8970f7d2, expected 0xd9ceaebd" in out  # the pin catches our own lie
    assert "record 2 claims 0x40 payload bytes; its span holds 8." in out  # malformed-on-purpose fuzz case


def test_two_firmware_targets_same_declaration_different_bytes() -> None:
    out = _run_main(examples.ex10.ex10_provenance)
    assert "[mk1-v1.0] ctx.pc (ARM) scratch+0x000 = 0x40002000" in out  # the MK-1 trigger, from its catalog
    assert "[mk2-v2.3] ctx.pc (ARM) scratch+0x000 = 0x00401a2c" in out  # same declaration, the MIPS device's entry
    assert "ERROR CHK-301 [SYSCALL_TAIL]: entry 0x40002004 != catalog 0x40002000" in out  # drift is a named error
    assert out.index("[mk1-v1.0] ctx.pc") < out.index("[mk2-v2.3] ctx.pc")  # both devices walked, in order


def test_leak_rebind_stale_reyields_at_the_corrected_base() -> None:
    out = _run_main(examples.ex06.ex06_delivery_plan)
    assert "plan.stale: spray+0x0 confirmed @0x40610000 -> now resolves @0x40611000" in out  # forensic row
    assert "re-yield spray+0x4: 0x40610004 -> 0x40611004" in out  # stage() re-yields old -> new
    assert "refused (re-delivery unconfirmed): finalize() refused: unconfirmed groups" in out  # gate holds post-rebind
    assert "0x40611010 <- 00000001" in out  # the trigger delivers LAST, at the corrected base


def test_ci_gate_reports_waives_and_refuses() -> None:
    out = _run_main(examples.ex07.ex07_guardrails)
    assert "hotfix limit supersedes the v1 default (review: MK1-217)" in out  # the waiver row: reviewable intent
    assert "waived rewrite pkt+0x0008: hotfix limit supersedes the v1 default (review: MK1-217)" in out  # render(verbose=True): the same ledger for humans
    assert '"error_codes": []' in out  # the green path's machine-readable verdict
    assert "refused: final emit refused: check errors:" in out  # the fail-closed final emit
    assert "cento.gate(locked) -> True" in out and "cento.gate(broken) -> False" in out  # the shipped verdict, both directions
    assert "sys.exit(0 if cento.gate(layout) else 1)" in out  # the whole CI step, spelled in the example


def test_image_patch_crc_recomputes_by_construction() -> None:
    out = _run_main(examples.ex08.ex08_borrowed_structures)
    assert "ERROR CHK-005 [bootchk.raw+0x0]: reduce crc32_mpeg2 = 0x5d53cf9e, expected 0xd6485fab" in out  # naive patch rejected
    assert "CHK-008 [flash_rec.raw[2].word, flash_rec.rec.boot_flags]" in out  # overlay patch hits the rewrite check
    assert "words changed: +0x08, +0x0c, +0x3c" in out  # we patched two words; the crc came free
    assert "crc: 0xd6485fab -> 0x5d53cf9e; bootloader replay: errors = []" in out  # valid by construction


def test_verify_chain_verifies_or_explains_the_missing_extra() -> None:
    out = _run_main(examples.ex10.ex10_provenance)
    if cento.verify.HAVE_UNICORN:
        assert "verdict: PASS" in out  # v1.0 bytes match the declaration
        assert "divergence: restore:R30" in out  # v1.1 drift, caught by its stable name
        assert "after attach: verified = " in out  # CHK-304 provenance, opt-in
        assert "WARN CHK-304" in out  # a FAILED verdict does not count as verified
    else:
        assert "unicorn not installed" in out  # the example explains itself and exits cleanly


def test_local_ret2win_lands_or_explains_the_missing_compiler() -> None:
    out = _run_main(examples.ex03.ex03_local_ret2win)
    if shutil.which("cc") or shutil.which("gcc") or shutil.which("clang"):
        assert "stack0=0x" in out  # the fault handler's [rsp] qword: the needle survives the non-canonical ret
        assert "-> offset " in out  # located from the real crash, whatever frame layout the compiler picked
        assert "win: control of rip" in out  # the thrown payload landed
    else:
        assert "no C compiler" in out  # the example explains itself and exits cleanly


def test_qemu_ret2win_lands_or_explains_the_missing_emulator() -> None:
    out = _run_main(examples.ex04.ex04_qemu_ret2win)
    if shutil.which("qemu-ppc") or shutil.which("qemu-ppc-static"):
        assert "stop=T0b" in out  # the gdb stub reported the SIGSEGV
        assert "-> offset " in out  # located from the crashed nip, low bits recovered
        assert "win: control of pc" in out  # the thrown payload landed on real (emulated) PPC32
    else:
        assert "no qemu-ppc found" in out  # the example explains itself and exits cleanly


def test_the_thrower_lands_or_explains_the_missing_compiler() -> None:
    out = _run_main(examples.ex11.ex11_the_thrower)
    if shutil.which("cc") or shutil.which("gcc") or shutil.which("clang"):
        assert "win: doorbell=0x1337" in out  # the hijacked call landed with the staged argument
        assert "leak: 'devmon: win @ 0x" in out  # the live leak was read and bound
        assert "throwers ran: stdlib" in out  # the stdlib tube always runs; ", pwntools" appends when importable
        assert '"ev": "arm_intent"' in out  # the write-ahead ARM row made the printed ledger
        assert "ledger:" in out
    else:
        assert "no C compiler" in out  # the example explains itself and exits cleanly


def test_aarch64_chain_runs_clean_and_names_the_alignment_fault() -> None:
    out = _run_main(examples.ex12.ex12_aarch64_chain)
    assert "0x401b70: ldp x19, x20, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret" in out  # the loader's rendered entry line, straight from its docstring
    assert "needs x20 <- cell:req.maint.load_call.x20" in out  # narrate(): the call's argument is fed by the upstream frame slot the seat wrote
    assert "check: 0 errors, 0 warnings, 0 pending" in out  # the aligned chain renders clean
    assert "701b400000000000  [req.maint.enter.pc]" in out  # the entry frame's x30 slot carries the next gadget, little-endian by default
    assert "CHK-207 [maint.enter, Epilogue]" in out  # the misaligned re-aim refuses at the FIRST SP-based access, not a movaps deep in libc
    assert "uses entry_sp_mod=0, but this position in the chain requires entry_sp_mod=8" in out  # the mod-16 arithmetic, done by the fold
    assert out.index("check: 0 errors") < out.index("CHK-207")  # the clean run first, THEN the refusal scene


def test_arm32_chain_prints_abutting_frames_and_the_thumb_entry() -> None:
    out = _run_main(examples.ex13.ex13_arm32_chain)
    assert "maint.load_call  +0x000c..+0x0018  over=()" in out  # internal-pc frames abut: no declared aliasing on any chain frame
    assert "0x8f00461: mov r0, r4; blx r5; pop {r4, r5, pc}  (Thumb)" in out  # disasm() renders the class's entry: the odd interworking spelling
    assert "check: 0 errors, 0 warnings, 0 pending" in out  # needs fed, SP % 8 == 0 at the blx boundary (CHK-207 green)
    assert "+0x0014 w4 6104f008  [rec.maint.load_call.pc]" in out  # the Thumb entry emitted as-is, bit 0 kept, little-endian


def test_port_a_script_golden_gates_every_step() -> None:
    out = _run_main(examples.ex14.ex14_port_a_script)
    assert out.count("golden: OK -- image == reference (44 bytes)") == 3  # steps 2, 3, 4: byte-equality re-proved after every strangler-fig move
    assert "CHK-008 [rec.hdr.wake_slot, rec.raw+0x8]" in out  # the old offset-poke idiom over typed bytes, refused by name behind the gate
    assert "golden: DIVERGED -- first divergent run at +0x0007 in rec.hdr.flags" in out  # drift is named BY OWNER, not "bytes differ"
    assert "+0x0007 len 1 expected 01, got 03  [rec.hdr.flags]" in out  # ...down to the one drifted byte
    assert out.index("golden: OK") < out.index("CHK-008")  # equality proven FIRST; only then do edits go behind the gate


def test_examples_are_ascii_only() -> None:
    # ASCII-only is a standing property of everything checked in under examples/ (firmware
    # .bin fixtures excepted). Only ambient scratch is skipped -- pyc caches, support-Makefile
    # build/ output, and dotfiles (editor swap files) -- so the guard is deterministic.
    files = sorted(
        p
        for p in EXAMPLES_DIR.rglob("*")
        if p.is_file() and not {"__pycache__", "build"} & set(p.parts) and not p.name.startswith(".") and p.name not in {"vuln", "devmon"}
    )  # gitignored, locally-built victim binaries (examples/ex01/ctf/Makefile, examples/ex11/Makefile)
    # Non-vacuousness, without a hardcoded total (totals go stale): the sweep must see the
    # example scripts, the exhibit pairs, and the non-Python inputs.
    assert any(p.name == "ex01_find_your_offset.py" for p in files)
    assert any(p.name == "before.py" for p in files) and any(p.name == "vuln.c" for p in files)
    for path in files:
        if path.suffix != ".bin":
            path.read_bytes().decode("ascii")


def test_ex05_and_ex10_pairs_byte_equality() -> None:
    """The unmaintainable-before exhibits: hand literals (ex05 TLV) and session-notes offset
    pokes (ex10 mk1 scratch) emit the exact bytes the tutorials derive."""
    import os
    import subprocess
    import sys

    env = {**os.environ, "PYTHONPATH": str(EXAMPLES_DIR.parent / "src") + os.pathsep + os.environ.get("PYTHONPATH", "")}
    for exdir in ("ex05", "ex10"):
        proc = subprocess.run([sys.executable, "check.py"], cwd=str(EXAMPLES_DIR / exdir), capture_output=True, text=True, timeout=120, env=env)
        assert proc.returncode == 0, f"{exdir}/check.py rc={proc.returncode}\n{proc.stdout}{proc.stderr}"
        assert "byte-for-byte equal:" in proc.stdout, f"{exdir}: {proc.stdout}"


@pytest.mark.parametrize(
    ("exdir", "refusal_pins"),
    [
        # ex00: the hand-guessed-offset collision, plus the movaps classic caught by the alignment fold
        ("ex00", ("CHK-001 [slab.shell, slab.setuid2]", "CHK-207 [frames.setuid, SetuidCall]", "uses entry_sp_mod=8")),
        ("ex01", ("CHK-001 [stack.frames, stack.revb_frames]",)),  # the pad-changed-offset-didn't classic, by name
    ],
)
def test_exhibit_pair_byte_equality_and_refusal(exdir: str, refusal_pins: tuple[str, ...]) -> None:
    """The intro exhibits: before.py and after.py emit identical bytes; the refusal holds shape.

    Subprocess-run like a user would (cwd = the example dir; check.py injects the repo src/
    for the scripts it spawns, so this works from a clone and from dist-verify's scratch copy).
    """
    import os
    import subprocess
    import sys

    cwd = EXAMPLES_DIR / exdir
    env = {**os.environ, "PYTHONPATH": str(EXAMPLES_DIR.parent / "src") + os.pathsep + os.environ.get("PYTHONPATH", "")}

    check = subprocess.run([sys.executable, "check.py"], cwd=str(cwd), capture_output=True, text=True, timeout=60, env=env)
    assert check.returncode == 0, f"{exdir}/check.py rc={check.returncode}\n{check.stdout}{check.stderr}"
    assert "byte-for-byte equal:" in check.stdout

    refusal = subprocess.run([sys.executable, "refusal.py"], cwd=str(cwd), capture_output=True, text=True, timeout=60, env=env)
    assert refusal.returncode == 0, f"{exdir}/refusal.py rc={refusal.returncode}\n{refusal.stdout}{refusal.stderr}"
    for pin in refusal_pins:
        assert pin in refusal.stdout


@pytest.mark.parametrize("exdir", sorted(examples.TRANSCRIPTS))
def test_transcripts_are_current(exdir: str) -> None:
    """The checked-in transcript.txt IS a fresh run: the reading-first artifact cannot go stale.

    The TRANSCRIPTS contract (examples/__init__.py) lists only fully deterministic runs (fixed
    fictional leaks, no host facts), so each transcript is regenerable byte-for-byte on any
    machine; a drift here means an example or library output changed without its transcript.
    Regenerate with `make transcripts` and re-read the diff -- the diff IS the review.
    """
    import os
    import subprocess
    import sys

    cwd = EXAMPLES_DIR / exdir
    env = {**os.environ, "PYTHONPATH": str(EXAMPLES_DIR.parent / "src") + os.pathsep + os.environ.get("PYTHONPATH", "")}
    parts = []
    for script in examples.TRANSCRIPTS[exdir]:
        proc = subprocess.run([sys.executable, script], cwd=str(cwd), capture_output=True, text=True, timeout=120, env=env)
        assert proc.returncode == 0, f"{exdir}/{script} rc={proc.returncode}\n{proc.stdout}{proc.stderr}"
        parts.append(f"$ python3 {script}\n{proc.stdout}")
    fresh = "\n".join(parts).rstrip("\n") + "\n"
    assert (cwd / "transcript.txt").read_text(encoding="ascii") == fresh


def test_every_transcript_is_contracted() -> None:
    """Every transcript.txt on disk has a TRANSCRIPTS entry: an uncontracted transcript would never be validated and could sit stale forever."""
    on_disk = {p.parent.name for p in EXAMPLES_DIR.glob("*/transcript.txt")}
    assert on_disk == set(examples.TRANSCRIPTS), f"transcript/contract drift: {sorted(on_disk ^ set(examples.TRANSCRIPTS))}"
