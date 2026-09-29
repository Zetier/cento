# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Stdlib-only smoke selftest: golden layout + determinism. python3 -m cento.selftest"""

from __future__ import annotations

import json
import sys

import cento
import cento.cells
import cento.gadget
import cento.machine


class _Hdr(cento.View, size=8):
    magic = cento.Field(0, cento.u32)
    length = cento.Field(4, cento.u16)
    csum = cento.Field(6, cento.u16)


def _build() -> cento.Layout:
    layout = cento.Layout()
    pkt = layout.region("pkt", max_size=16, fill=0)
    h = pkt.at(0, _Hdr, "h")
    h.magic = 0xDEADBEEF
    h.length = 16
    h.csum = cento.sum16(pkt[0:6])
    return layout


def main() -> int:
    failures: list[str] = []

    layout = _build()
    img = layout.emit(cento.Backend.IMAGE).artifact["pkt"]
    want = bytes.fromhex("efbeadde10009cad") + b"\x00" * 8  # the default target packs little
    if img != want:
        failures.append(f"golden IMAGE mismatch: {img.hex()} != {want.hex()}")

    a, b = _build(), _build()
    if json.dumps(a.check().to_json(), sort_keys=True) != json.dumps(b.check().to_json(), sort_keys=True):
        failures.append("determinism: reports differ across identical builds")
    if json.dumps(a.to_json(), sort_keys=True) != json.dumps(b.to_json(), sort_keys=True):
        failures.append("determinism: manifests differ across identical builds")

    if cento.cells.REDUCERS["crc32_mpeg2"](b"123456789") != 0x0376E6E7:
        failures.append("crc32_mpeg2 KAT failed")

    class _Entry(cento.gadget.Gadget, entry=0x1000, frame_base=cento.machine.Reg.R31):
        pc = cento.gadget.Restores(cento.machine.Reg.PC, at=0x0)
        sp = cento.gadget.Restores(cento.machine.Reg.SP, at=0x4)
        r30 = cento.gadget.Restores(cento.machine.Reg.R30, at=0x8)
        r31 = cento.gadget.Restores(cento.machine.Reg.R31, at=0xC)
        needs = {cento.machine.Reg.R31: "jb"}

    class _Tail(cento.gadget.Gadget, entry=0x2000, stride=0x20):
        r30 = cento.gadget.Restores(cento.machine.Reg.R30, at=0x18)
        pc = cento.gadget.Restores(cento.machine.Reg.PC, at=0x24, external=True)
        needs = {cento.machine.Reg.R30: "v"}

    clay = cento.Layout()
    cpage = clay.region("cp", base="cp_va", max_size=0x1000)
    crun = cpage.chain("smoke", at=0x100)
    crun.enter(_Entry)
    ch = crun.hop(_Tail, "t")
    ch.r30 = 0x41
    crun.finish_in_kernel(pc=0x40003000)  # a finished chain: finalize() refuses dangling continuations
    if clay.check().errors:
        failures.append("chain smoke: unexpected check errors")
    if crun.state_at("t")[cento.machine.Reg.R30].kind != "seat":
        failures.append("chain smoke: fold state wrong")

    # a thrower is any code that writes (addr, bytes) pairs and then confirms
    plan = clay.plan()
    plan.bind("cp_va", 0x1000)
    delivered: list[str] = []
    for group in plan.stage():
        delivered.append(group.deliver.name)
        plan.confirm(group)
    for group in plan.finalize():
        delivered.append(group.deliver.name)
        plan.confirm(group)
    if not delivered or delivered[-1] != "ARM":
        failures.append("plan smoke: last delivered group is not ARM")

    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        return 1
    print("PASS: cento selftest (golden + determinism + reducer KAT + chain smoke + plan smoke)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
