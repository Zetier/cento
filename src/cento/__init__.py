# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""cento: declarative gadget-chain layout library (payload semantics only).

Facade module: normal-case users import only this (and an ABI module).
No deployment mechanisms live here; throwers -- your delivery code, anything that
writes (addr, bytes) pairs -- consume emitted artifacts/plans.

The happy path, end to end::

    import cento

    class Hdr(cento.View, size=8):
        magic: cento.u32
        target: cento.u32

    buf = cento.region("buf", max_size=0x40)    # a fresh one-region Layout
    h = buf.at(0, Hdr, "h")                     # place a typed view
    h.magic = 0xC0DE0001                        # write a field
    h.target = "win_addr"                       # a symbol: bind it when the leak lands
    buf.bind("win_addr", 0x40001234, source="leak")
    print(buf.layout.check().render())          # judge: named CHK-* errors with hints
    payload = buf.image()                       # the final gate: refuses while anything is wrong

Unknowns stay symbolic until bind(); computed cells (cento.length, crc32_mpeg2, ...)
re-derive on every emit; layout.preflight() reports shippability as data; and every
refusal names its cause and fix (cento.checks.CODES is the catalog).
"""

from __future__ import annotations

import cento.abi
import cento.catalog
import cento.cells
import cento.chain
import cento.checks
import cento.emit
import cento.errors
import cento.gadget
import cento.gate
import cento.golden
import cento.machine
import cento.plan
import cento.profile
import cento.regions
import cento.verify
import cento.views

__version__ = "0.2.0"

# The intentional export set (alphabetized): every public class/function/constant the
# facade re-exports below, and nothing else -- no submodules, no import artifacts.
__all__ = [
    "ArrayHandle",
    "ArraySpec",
    "Assurance",
    "Backend",
    "Bytes",
    "CLOBBER",
    "Carry",
    "Catalog",
    "CatalogError",
    "CellHandle",
    "CentoError",
    "Chain",
    "ChainError",
    "ChainFlow",
    "Clobbers",
    "Deliver",
    "DeliveryGroup",
    "DeliveryPlan",
    "Delta",
    "Divergence",
    "Effect",
    "EmitError",
    "EmitResult",
    "Env",
    "Explanation",
    "Field",
    "FieldArrayHandle",
    "Fixup",
    "Gadget",
    "Golden",
    "GoldenDiff",
    "Hop",
    "Issue",
    "Layout",
    "Manifest",
    "PlacementError",
    "PlanError",
    "Preflight",
    "Provenance",
    "Ref",
    "Reg",
    "Region",
    "Report",
    "Residual",
    "ResolveError",
    "Restores",
    "Role",
    "Span",
    "Target",
    "Transfer",
    "UNSET",
    "Verdict",
    "VerifyError",
    "View",
    "ViewHandle",
    "WidthArray",
    "WidthError",
    "Writeback",
    "XformError",
    "colorize_disasm",
    "crc32_mpeg2",
    "crc8",
    "cycle",
    "cycle_find",
    "fit",
    "gate",
    "golden",
    "ha16",
    "hi16",
    "i16",
    "i32",
    "i64",
    "i8",
    "length",
    "lo16",
    "region",
    "sum16",
    "target",
    "u16",
    "u32",
    "u64",
    "u8",
    "udp_cksum",
    "xor_fold",
]

CentoError = cento.errors.CentoError
PlacementError = cento.errors.PlacementError
PlanError = cento.errors.PlanError
ResolveError = cento.errors.ResolveError
VerifyError = cento.errors.VerifyError
WidthError = cento.errors.WidthError
XformError = cento.errors.XformError
EmitError = cento.errors.EmitError

Ref = cento.cells.Ref
Delta = cento.cells.Delta
Span = cento.cells.Span
Residual = cento.cells.Residual
Env = cento.cells.Env
lo16 = cento.cells.lo16
hi16 = cento.cells.hi16
ha16 = cento.cells.ha16
crc32_mpeg2 = cento.cells.crc32_mpeg2
xor_fold = cento.cells.xor_fold
sum16 = cento.cells.sum16
udp_cksum = cento.cells.udp_cksum
crc8 = cento.cells.crc8
length = cento.cells.length
cycle = cento.cells.cycle
cycle_find = cento.cells.cycle_find

View = cento.views.View
Field = cento.views.Field
ArraySpec = cento.views.ArraySpec
u8 = cento.views.u8
u16 = cento.views.u16
u32 = cento.views.u32
u64 = cento.views.u64
i8 = cento.views.i8
i16 = cento.views.i16
i32 = cento.views.i32
i64 = cento.views.i64
Bytes = cento.views.Bytes
WidthArray = cento.views.WidthArray
FieldArrayHandle = cento.regions.FieldArrayHandle

Layout = cento.regions.Layout
Assurance = cento.regions.Assurance
Manifest = cento.regions.Manifest
Provenance = cento.regions.Provenance
Explanation = cento.regions.Explanation
Region = cento.regions.Region
region = cento.regions.region
fit = cento.regions.fit
CellHandle = cento.regions.CellHandle
Deliver = cento.emit.Deliver
ViewHandle = cento.regions.ViewHandle
ArrayHandle = cento.regions.ArrayHandle

Issue = cento.checks.Issue
Report = cento.checks.Report

Backend = cento.emit.Backend
colorize_disasm = cento.emit.colorize_disasm
Fixup = cento.emit.Fixup
EmitResult = cento.emit.EmitResult
Preflight = cento.emit.Preflight
Verdict = cento.verify.Verdict

ChainError = cento.errors.ChainError
Reg = cento.machine.Reg
Role = cento.machine.Role
Carry = cento.machine.Carry
Effect = cento.machine.Effect
Writeback = cento.machine.Writeback
CLOBBER = cento.machine.CLOBBER
UNSET = cento.machine.UNSET
Transfer = cento.machine.Transfer

Gadget = cento.gadget.Gadget
Restores = cento.gadget.Restores
Clobbers = cento.gadget.Clobbers

Golden = cento.golden.Golden
GoldenDiff = cento.golden.GoldenDiff
Divergence = cento.golden.Divergence
golden = cento.golden.golden  # binding the factory shadows the submodule attribute (deliberately: cento.golden(ref) IS the surface), so the classes bind first
gate = cento.gate.gate  # binding the verdict shadows the submodule (deliberately, like golden: cento.gate(layout) IS the surface)

Chain = cento.chain.Chain
ChainFlow = cento.chain.ChainFlow
Hop = cento.chain.Hop

Catalog = cento.catalog.Catalog
CatalogError = cento.errors.CatalogError

DeliveryPlan = cento.plan.DeliveryPlan
DeliveryGroup = cento.plan.DeliveryGroup

Target = cento.profile.Target
target = cento.profile.target  # the module lives at cento.profile, so this binding shadows nothing
