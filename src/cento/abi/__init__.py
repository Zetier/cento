# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Shipped ABI specs and the name registry: cento.abi.X86_64, cento.abi.resolve("ppc32"), SPECS."""

from __future__ import annotations

import types
import typing

import cento.errors
import cento.machine
from cento.abi import aarch64
from cento.abi import arm32
from cento.abi import ppc32
from cento.abi import x86_64

AbiSpec = cento.machine.AbiSpec
X86_64 = x86_64.X86_64
AARCH64 = aarch64.AARCH64
ARM32 = arm32.ARM32
PPC32 = ppc32.PPC32

SPECS: typing.Mapping[str, AbiSpec] = types.MappingProxyType({s.name: s for s in (X86_64, AARCH64, ARM32, PPC32)})


def resolve(abi: AbiSpec | str) -> AbiSpec:
    """The AbiSpec for `abi`: a spec passes through; a name ("ppc32") looks up the shipped registry.

    Unknown names and wrong types refuse with the known vocabulary -- fail closed, never guess.
    """
    if isinstance(abi, AbiSpec):
        return abi
    if isinstance(abi, str):
        spec = SPECS.get(abi)
        if spec is None:
            raise cento.errors.PlacementError(f"unknown abi {abi!r}; shipped abis: {', '.join(sorted(SPECS))} (an AbiSpec of your own also works)")
        return spec
    raise cento.errors.PlacementError(f"abi must be an AbiSpec or one of {', '.join(sorted(SPECS))}, got {type(abi).__name__}")
