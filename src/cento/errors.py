# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""cento exception hierarchy."""

from __future__ import annotations

import typing

if typing.TYPE_CHECKING:
    import cento.checks


class CentoError(Exception):
    """Base class for all cento errors."""


class PlacementError(CentoError):
    """Invalid placement or cell write: bad offset, unknown field, value coercion failure."""


class ResolveError(CentoError):
    """Value cannot be resolved: awaiting symbols, reduce cycles, or an unknown reducer.

    Refusals carry their data: when the refusing surface had a fill-padded draft in hand
    (Region.image's draft read), it rides as .partial. Raisers without a buffer leave it None."""

    def __init__(self, message: str, *, partial: bytes | None = None) -> None:
        super().__init__(message)
        self.partial = partial


class WidthError(ResolveError):
    """A resolved full-address value does not fit its cell width (CHK-009 at check time).

    Raised for plain ADDR Refs only: lo16/hi16/ha16 slices and Delta arithmetic keep
    their documented wrap-at-width semantics.
    """


class XformError(ResolveError):
    """A cell names an xform its layout never registered (CHK-014 at check time).

    Reachable via cross-layout leakage: register_xform constructors are layout-scoped."""


class EmitError(CentoError):
    """The final emit refused: pending symbols, fixups, or failing checks.

    Carries the gate's Report as .report when one was computed (None otherwise), so tooling
    reads the refusal as data (err.report.to_json()) instead of parsing the message. The
    message keeps embedding the rendered report: str(err) is unchanged."""

    def __init__(self, message: str, *, report: cento.checks.Report | None = None) -> None:
        super().__init__(message)
        self.report = report


class ChainError(CentoError):
    """Chain construction or seating violation (seating: writing a register's input into its
    frame cell): unmet need, writeback conflict, bad transfer.

    seal() attaches the refusing Issue as .issue (None for construction-time guards), so
    tooling reads the refusal as data (err.issue.to_json())."""

    def __init__(self, message: str, *, issue: cento.checks.Issue | None = None) -> None:
        super().__init__(message)
        self.issue = issue


class PlanError(CentoError):
    """DeliveryPlan lifecycle violation: staging after finalize, confirming a foreign group."""


class CatalogError(CentoError):
    """Catalog/profile loading failure: missing file, bad JSON, unsupported schema."""


class VerifyError(CentoError):
    """Verification failure: unicorn unavailable, unmapped code read, or executor divergence."""
