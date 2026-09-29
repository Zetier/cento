# Contributing to cento

## Setup and gates

```sh
make setup                # the gate tools (pip) -- shellcheck and cc come from the system
pre-commit install --hook-type pre-commit --hook-type pre-push
make selftest             # the authoritative gate: lint + validate + pytest + source-tree selftest
```

`make selftest` must pass before any claim that something works. Deterministic examples check
in a `transcript.txt` that the tests hold current: if your change moves example output, run
`make transcripts` and commit the regenerated transcripts, and update the asserted lines in
`tests/test_examples.py`, all in the same change. New public API surface gets typing coverage
in `tests/test_typing_gate.py`.

## Commits

Lowercase imperative subject, a prose body explaining what and why, and a Developer
Certificate of Origin sign-off:

```sh
git commit -s
```

CI refuses unsigned commits. The sign-off line is a certification, not a formality: by adding
`Signed-off-by: Your Name <you@example.com>` you certify the
[Developer Certificate of Origin](https://developercertificate.org) -- that you wrote the
contribution, or have the right to submit it under this repository's Apache-2.0 license, using
an identity you can be reached at (an alias you monitor is fine; a noreply address is not).

**Employer authorization.** If you contribute in the course of employment, or your employment
agreement assigns your relevant work to your employer, make sure you are authorized to submit
the contribution before signing off -- that is what DCO clause (a)/(b) has you certify. When in
doubt, ask your employer first; we cannot resolve that on your behalf.

**Third-party code.** Contributions that include someone else's code must keep the original
copyright and license notices intact and name the origin and its license in the commit body.
Only include third-party code whose license is compatible with Apache-2.0; when a file is
substantially third-party, keep its upstream header and add an SPDX line naming its license.

**No CLA.** Contributions arrive under Apache-2.0 §5 (inbound = outbound) with the DCO
certification above. Zetier does not require a contributor license agreement, copyright
assignment, or any relicensing rights beyond what Apache-2.0 already grants.

## Style

See [AGENTS.md](AGENTS.md) for the working conventions: single space after sentence
punctuation, 160-column lines, one line when it fits, teaching errors for every refusal, and
the exhibit rules for `examples/` (before.py files are style-frozen; scoped
`# mypy: disable-error-code` headers instead of exclusions).

## Reporting

Security issues go privately to <security@zetier.com> (see [SECURITY.md](SECURITY.md));
everything else to the [issue tracker](https://github.com/zetier/cento/issues).
