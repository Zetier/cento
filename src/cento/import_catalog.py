# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
"""Catalog importer: ropper/ROPgadget listings -> schema-2 catalog JSON (python -m cento.import_catalog).

The catalog is the checked-in artifact; the listing never persists as one. Simple x86-64
pop/ret gadgets arrive fully specced and are named in provenance.auto_specced; everything
else lands in the "unspecced" block, promoted by hand (write the restores, move the entry
into the gadget set). Identical input and flags produce byte-identical JSON.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
import typing

_ROPPER = re.compile(r"^(0x[0-9a-fA-F]+): (.+?)\s*$")
_ROPGADGET = re.compile(r"^(0x[0-9a-fA-F]+) : (.+?)\s*$")
_R64 = "rax rbx rcx rdx rsi rdi rbp r8 r9 r10 r11 r12 r13 r14 r15".split()  # rsp excluded: a pop-rsp is a pivot, not "simple"
_R64_ALT = "|".join(_R64)
_POP_RET = re.compile(rf"^pop (?:{_R64_ALT})(?:; pop (?:{_R64_ALT}))*; ret$")


class _Row(typing.NamedTuple):
    """One parsed listing line: address and normalized disasm."""

    addr: int
    disasm: str


def _normalize(body: str) -> str:
    return "; ".join(part.strip() for part in body.split(";") if part.strip())


def _parse(text: str, tool: str) -> tuple[str, list[_Row]]:
    """Parse a listing: (detected tool, rows in listing order). Non-matching lines skip; mixed shapes refuse."""
    detected: str | None = None if tool == "auto" else tool
    rows: list[_Row] = []
    for line in text.splitlines():
        hits = {name: rx.match(line) for name, rx in (("ropper", _ROPPER), ("ropgadget", _ROPGADGET))}
        m_names = [n for n, m in hits.items() if m is not None]
        if not m_names:
            continue  # headers, blanks, progress noise
        name = m_names[0]
        if detected is None:
            detected = name
        elif name != detected and tool == "auto":  # a forced --tool mismatch falls through to the accurate message below
            raise ValueError(f"mixed listing shapes: saw both {detected} and {name} lines -- import one tool's output at a time")
        m = hits[detected]
        if m is None:
            raise ValueError(f"mixed listing shapes: line matches {name}, not the detected {detected} -- import one tool's output at a time")
        rows.append(_Row(int(m.group(1), 16), _normalize(m.group(2))))
    if detected is None or not rows:
        raise ValueError("no gadget lines recognized -- is this a ropper or ROPgadget listing?")
    return detected, rows


def _auto_spec(name: str, entry: int | str, disasm: str) -> dict[str, typing.Any] | None:
    """spec_dict-shaped entry for a simple pop/ret gadget, None for anything else (stays unspecced)."""
    if not _POP_RET.match(disasm):
        return None
    regs = [insn.split()[1] for insn in disasm.split("; ")[:-1]]  # every "pop R"; the trailing "ret" drops
    restores: dict[str, typing.Any] = {r: {"reg": r, "at": 8 * i, "width": 8, "external": False} for i, r in enumerate(regs)}
    restores["pc"] = {"reg": "PC", "at": 8 * len(regs), "width": 8, "external": False}
    return {
        "name": name,
        "entry": entry,
        "stride": 8 * (len(regs) + 1),
        "frame_base": "SP",
        "reentry_safe": False,
        "restores": restores,
        "clobbers": [],
        "needs": {},
    }


def _sym_entry(sym: str, base: int, addr: int) -> str:
    if addr < base:
        raise ValueError(f"entry {addr:#x} is below --base {base:#x} -- wrong base?")
    return f"{sym}+0x{addr - base:x}"


def _slug(disasm: str) -> str:
    return re.sub(r"[^0-9a-z]+", "_", disasm.lower()).strip("_")


def _assemble(args: argparse.Namespace) -> dict[str, typing.Any]:
    """The pipeline: read -> parse -> filter -> dedup -> name -> spec/unspec -> assemble (emit is main's)."""
    if args.listing == "-":
        text = sys.stdin.read()
    else:
        try:
            text = pathlib.Path(args.listing).read_text(encoding="ascii")
        except OSError as exc:
            raise ValueError(f"cannot read listing {args.listing!r}: {exc}") from exc
    base = int(args.base, 16) if args.base else None
    symbolic: tuple[str, int] | None = None
    if args.sym is not None:
        if base is None:
            raise ValueError("--sym requires --base (the offsets subtract from it)")
        symbolic = (args.sym, base)
    image_sha256: str | None = None
    if args.image is not None:
        try:
            image_sha256 = hashlib.sha256(pathlib.Path(args.image).read_bytes()).hexdigest()
        except OSError as exc:
            raise ValueError(f"cannot read --image {args.image!r}: {exc}") from exc
    tool, rows = _parse(text, args.tool)
    if args.only:
        try:
            only = re.compile(args.only)
        except re.error as exc:
            raise ValueError(f"--only {args.only!r} is not a valid regex: {exc}") from exc
        rows = [row for row in rows if only.search(row.disasm)]
        if not rows:
            raise ValueError("no gadgets matched (after --only filtering)")
    lowest: dict[str, int] = {}
    for row in rows:  # dedup: the LOWEST address per distinct disasm wins
        if row.disasm not in lowest or row.addr < lowest[row.disasm]:
            lowest[row.disasm] = row.addr
    specced: dict[str, typing.Any] = {}
    unspecced: dict[str, typing.Any] = {}
    for disasm, addr in sorted(lowest.items(), key=lambda kv: (_slug(kv[0]), kv[1])):
        slug = _slug(disasm)
        name = slug if slug not in specced and slug not in unspecced else f"{slug}_0x{addr:x}"  # the first same-slug entry takes the bare slug
        entry: int | str = addr if symbolic is None else _sym_entry(*symbolic, addr)
        spec = _auto_spec(name, entry, disasm)
        if spec is None:
            unspecced[name] = {"entry": entry, "disasm": disasm}
        else:
            specced[name] = spec
    data: dict[str, typing.Any] = {
        "schema": 2,
        "target": args.target,
        "provenance": {"tool": tool, "base": base, "image_sha256": image_sha256, "only": args.only, "sym": args.sym, "auto_specced": sorted(specced)},
        "gadget_sets": {args.set_name: specced},
    }
    if unspecced:
        data["unspecced"] = {args.set_name: unspecced}
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m cento.import_catalog", description=(__doc__ or "").splitlines()[0])
    parser.add_argument("listing", nargs="?", default="-", help="listing file, or - / omitted for stdin")
    parser.add_argument("--set", required=True, dest="set_name", help="the gadget-set name")
    parser.add_argument("--tool", choices=("auto", "ropper", "ropgadget"), default="auto")
    parser.add_argument("--target", default="", help="the catalog's target string")
    parser.add_argument("--image", help="binary to hash into provenance.image_sha256")
    parser.add_argument("--base", help="load base the listing assumed (hex), recorded in provenance; the subtrahend for --sym")
    parser.add_argument("--sym", help="emit entries as SYM+0xOFF relative to --base (symbolic catalogs)")
    parser.add_argument("--only", help="regex filter over the normalized disasm")
    parser.add_argument("--out", help="output path (default stdout)")
    args = parser.parse_args(argv)
    try:
        rendered = json.dumps(_assemble(args), indent=2, sort_keys=True) + "\n"
        if args.out:
            pathlib.Path(args.out).write_text(rendered, encoding="ascii")
        else:
            sys.stdout.write(rendered)
    except (ValueError, OSError) as exc:
        print(f"import-catalog: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
