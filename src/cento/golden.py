# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Golden-bytes regression pinning: judge a region's image against a captured reference.

The porting/maintenance workflow (examples/ex14 is the recipe): capture a known-good emission
once -- a legacy script's output, a dumped artifact, last release's bytes -- then re-prove
byte-equality after every edit. A divergence is attributed to the CELL OWNER under its first
byte ("rec.hdr.flags"), never just "bytes differ"::

    diff = cento.golden(reference_bytes).compare(region)
    assert diff.ok, diff.render()

That assert is the whole pytest integration: no fixture, no plugin, no dependency -- render()
is the failure message. Regenerating a stale reference is YOUR explicit act (re-run the trusted
producer, capture again); nothing here auto-updates a reference on mismatch.

Fail-closed like every emit surface: compare() reads the draft image (image(final=False) --
byte-judgment, not the shipping gate), so a region still awaiting symbols raises ResolveError
naming them -- an unresolved image is never compared, and a length mismatch is a named
divergence in the report, not an exception.

Note the facade binding: the package attribute `cento.golden` is this module's `golden` CALLABLE
(the factory deliberately shadows the submodule); reach `Golden`/`GoldenDiff`/`Divergence` via
the facade (`cento.Golden`), not attribute access on `cento.golden`.
"""

from __future__ import annotations

import dataclasses
import typing

import cento.errors
import cento.regions

_HEX_CAP = 16  # render() caps each shown run at this many bytes (display trim; the Divergence record keeps them all)


class Divergence(typing.NamedTuple):
    """One maximal run of differing bytes: where, how long, both spellings, and who owns it.

    owner is the cell owner path covering the run's first byte ("rec.hdr.flags"); a byte no
    cell wrote falls back to the covering placement's path plus "(fill)", then to "(unowned)"
    (bare region fill). A length mismatch appears as a final Divergence carrying the unshared
    tail (one side empty; owner "(image ends)" when the image is the shorter one).
    """

    offset: int
    length: int
    expected: bytes
    got: bytes
    owner: str


def _owner_at(region: cento.regions.Region, offset: int) -> str:
    """The name responsible for one byte: innermost covering cell owner, else placement path + (fill), else (unowned)."""
    cells = region.layout.cells()
    best_off, best_width, best_owner = -1, 0, ""
    for key in sorted(cells):
        region_name, cell_off = key
        entry = cells[key]
        if region_name != region.name or not cell_off <= offset < cell_off + entry.width:
            continue
        if not best_owner or cell_off > best_off or (cell_off == best_off and entry.width < best_width):
            best_off, best_width, best_owner = cell_off, entry.width, entry.owner
    if best_owner:
        return best_owner
    covering = [p.path for p in region.placements if p.offset <= offset < p.offset + p.extent]
    if covering:
        return f"{covering[-1]} (fill)"  # placed but never written: the byte is region fill under the newest covering placement
    return "(unowned)"


def _hx(data: bytes) -> str:
    if not data:
        return "(none)"
    if len(data) <= _HEX_CAP:
        return data.hex()
    return f"{data[:_HEX_CAP].hex()}.. ({len(data)} bytes)"


@dataclasses.dataclass(frozen=True)
class GoldenDiff:
    """One compare() verdict: ok, both lengths, and every divergent run with its owner.

    Frozen data, no presentation: render() is the deterministic plain-text spelling, built for
    `assert diff.ok, diff.render()`.
    """

    ok: bool
    reference_len: int
    image_len: int
    divergences: tuple[Divergence, ...]

    def render(self) -> str:
        """The verdict as deterministic plain text: the first divergent run leads with its owner name, the rest listed compactly."""
        if self.ok:
            return f"golden: OK -- image == reference ({self.reference_len} bytes)"
        first = self.divergences[0]
        lines = [f"golden: DIVERGED -- first divergent run at +0x{first.offset:04x} in {first.owner}"]
        for d in self.divergences:
            lines.append(f"  +0x{d.offset:04x} len {d.length} expected {_hx(d.expected)}, got {_hx(d.got)}  [{d.owner}]")
        if self.reference_len != self.image_len:
            lines.append(f"  length: reference {self.reference_len} bytes, image {self.image_len} bytes")
        return "\n".join(lines)


@dataclasses.dataclass(frozen=True)
class Golden:
    """A captured reference emission (construct via cento.golden()); compare() judges regions against it."""

    reference: bytes

    def compare(self, region: cento.regions.Region) -> GoldenDiff:
        """Judge one region's emitted bytes against the reference; every divergent run is owner-attributed.

        Reads the draft image (final=False): compare() judges bytes, not shippability, so
        check() findings do not block a comparison, but an unresolved region raises
        ResolveError naming the missing symbols (bind them first; a comparison against guessed
        bytes teaches nothing). A length mismatch is reported as the final Divergence, not raised.
        """
        if not isinstance(region, cento.regions.Region):
            raise cento.errors.PlacementError(f"golden: compare() takes a cento Region handle, got {type(region).__name__} (pass layout.region(...)'s result)")
        image = region.image(final=False)  # the draft read: compare() judges bytes, not shippability -- the full gate stays emit()'s job
        reference = self.reference
        shared = min(len(reference), len(image))
        runs: list[Divergence] = []
        start = 0
        while start < shared:
            if reference[start] == image[start]:
                start += 1
                continue
            end = start + 1
            while end < shared and reference[end] != image[end]:
                end += 1
            runs.append(Divergence(offset=start, length=end - start, expected=reference[start:end], got=image[start:end], owner=_owner_at(region, start)))
            start = end
        if len(reference) != len(image):
            tail_owner = _owner_at(region, shared) if len(image) > len(reference) else "(image ends)"
            runs.append(Divergence(offset=shared, length=abs(len(reference) - len(image)), expected=reference[shared:], got=image[shared:], owner=tail_owner))
        return GoldenDiff(ok=not runs, reference_len=len(reference), image_len=len(image), divergences=tuple(runs))


def golden(reference: bytes) -> Golden:
    """Capture a trusted emission as the regression reference: cento.golden(ref).compare(region).

    The reference is bytes you already believe in; compare() then names the first divergent
    cell BY OWNER whenever a port or edit drifts. See the module docstring for the one-line
    pytest idiom.
    """
    if isinstance(reference, (bytearray, memoryview)):
        return Golden(bytes(reference))
    if not isinstance(reference, bytes):
        raise cento.errors.PlacementError(f"golden: reference must be bytes, got {type(reference).__name__} (capture the trusted emission and pass it whole)")
    return Golden(reference)
