# Working on cento

Conventions for contributors and coding agents. The gates are the contract; this file is the
context the gates cannot express.

## Gates

- `make selftest` is the authoritative gate: lint + validate + pytest + source-tree selftest --
  every tracked file class rides a gate. Run it before claiming anything works. `make help`
  lists every target and names each gate's tools; CI (`.github/workflows/ci.yml`,
  `.gitlab-ci.yml`) drives these same make targets and must stay in sync with them.
  `.pre-commit-config.yaml` wires the gates into git (lint + validate at commit, the full
  selftest at push) -- a convenience; the make targets remain the contract.
- Everything under src/, tests/, and examples/ is mypy --strict clean -- exhibits included. An
  exhibit whose authentic idiom trips a specific code carries a scoped
  `# mypy: disable-error-code` header, never an exclusion (see pyproject). New public surface
  gets regression-tested typing (see tests/test_typing_gate.py).

## Style

- Single space after sentence punctuation, in code comments, docstrings, and docs alike.
- One line when it fits (line length is 160): do not spread short calls or signatures across
  lines with a magic trailing comma. Deliberately tabular literals (firmware matrices, __all__)
  stay multi-line.
- ruff format decides docstring spacing: class docstrings are followed by a forced blank line
  (not configurable); function and module docstrings are not -- keep those tight. A `# comment`
  in place of a docstring avoids the blank line but is invisible to help(); the public API is
  documented in docstrings, so prefer docstrings on anything help()-facing.

## Representation audit (a review lens; run it on new or touched code)

Every piece of data rides the primitive that says what it is. Symptoms that it does not:

1. Indexed access into a tuple (`x[0]`, `x[3]`) outside slicing -- the positions have names in
   the author's head.
2. A comment or docstring documenting a shape ("rows are (region, offset, reason)") -- docs
   doing the type system's job.
3. `assert isinstance` / `typing.cast` on an element -- code apologizing for type erasure.
4. A `str` field whose legal values are enumerated in a comment -- a Literal or enum in a
   trench coat.
5. A mutable class nothing mutates after construction -- frozen in fact, so freeze it in type.
6. Parallel collections indexed together (`offs[i]`, `keys[i]`) -- one list of records split
   into columns.
7. Two synthesis mechanisms on one class (a decorator on a NamedTuple, `__slots__` boilerplate
   replicating a dataclass) -- mechanisms fighting.
8. A `(a, b)` pair whose fields match an existing class -- the type already exists; use it.

The fix is the minimal typed replacement that keeps equality/hash/unpack compatibility:
NamedTuple for tuple-contract records, frozen dataclass for non-tuple values, Literal for
closed string vocabularies. Exemption: a tuple whose consumers only ever UNPACK it is
idiomatic -- leave it. Verification: a compatible replacement changes zero test pins.
Recorded deferrals: `CellKey` stays a bare tuple (pervasive dict key; churn > value today);
`DeliveryGroup.items` stays `(addr, bytes)` pairs (unpacking IS the thrower interface);
`fill_at(start)` keeps its naming outlier (`start=`, not `at=`; renaming churns callers for
symmetry alone); `cycle_find(width=4)` keeps its default (the pwntools `cyclic` convention it
mirrors); the catalog loader keeps width defaulting (ex10 catalog hashes pin it; CHK-208
covers the corruption path); `ChainFlow.to_json` keeps its name-string "abi" join key (the
manifest's abi block carries the facts; the chain row is a join key, not a record).

## Doctrine (the short version)

- Fail closed: emit(), image(), read() refuse rather than guess; unresolved is an
  error with the missing names in it, never silent fill.
- Every refusal is a named, greppable teaching error (CHK-* codes in checks; PlacementError /
  ResolveError / EmitError elsewhere) that says what to do instead. Existing codes keep their
  meaning; new checks get new codes.
- Determinism is tested: two identical builds produce byte-identical reports. No shared module
  state -- the Layout object is the isolation unit (cento.region() makes a FRESH layout per call).
  Set-once conveniences stay object-scoped: a Target profile (JSON file or inline dict) carries
  endian/fill/gadget facts into every layout it makes; nothing is ever process-global.
- Presentation never contaminates artifacts: color, run-summarizing (hexdump skip=), and
  catalog formatting live in display-layer functions; emit artifacts stay plain, full, and
  deterministic.
- Overlaps and rewrites are declared intent (over=/why=, allow_rewrite(reason=)), and waiver
  reasons are ledger lines a reviewer reads.

## Examples

- One directory per example (examples/exNN/): the script keeps its explicit exNN_<name>.py
  callout, and non-Python inputs (C sources, assemblers, catalogs, workbench Makefiles) live
  next to it. Numbered docstring header ("Example N -- title"; no total, so adding an example
  renumbers nothing), a Run: block with real command lines, and a Next: pointer. ex01
  additionally opens with a pwntools-to-cento rosetta -- keep it honest if the API moves.
- ex00 is the flagship exhibit, not a tutorial: before.py (authentic hand idiom, the exploit
  with a cross-region address web) vs after.py (the same bytes as declarations), check.py
  asserting the labeled emissions byte-identical, and refusal.py growing the exploit and
  staging the genre's classic mistake with its refusal SHAPE-ASSERTED. after.py answers
  before.py line for line; concepts before.py does not have belong in refusal.py (or in
  enhanced.py, the escalation exhibit: the same bytes as a checked x86-64 chain, its gadget
  catalog split out as gadgets.py). ex01
  carries the gentle 1:1 ret2libc pair (same four-file shape) plus ctf/, its live version.
  Every deterministic example dir checks in a transcript.txt regenerated verbatim -- the
  TRANSCRIPTS contract in examples/__init__.py, `make transcripts` to regenerate, tests
  assert currency.
- Examples run standalone AND in-process (tests call main()); argparse examples take
  `main(argv=None)` and tests pass `[]`. Asserted output lines live in tests/test_examples.py --
  changing example output means updating the pins in the same change.
- examples/*/before.py files are exhibits: authentic PoC style, excluded from lint and from
  style sweeps. Do not modernize them. ex05/ex10 carry before/after pairs too (hand TLV
  literals vs derived cells; session-notes offset pokes vs catalogs), each with a check.py.

## Process

- Commits: lowercase imperative subject, prose body explaining what and why, a "Ripple:"
  paragraph when a change fans out, and a DCO sign-off (`git commit -s`).
- Agent scratch (design specs, implementation plans, session ledgers, review packages) lives
  under `.superpowers/` -- gitignored, never in docs/. docs/ ships.
