# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities in cento privately to <security@zetier.com>. Include what you found, a reproduction if you have one, and how you would
like to be credited. We will acknowledge receipt, keep you informed, and coordinate disclosure timing with you before anything is published.

Please do not open public issues for suspected vulnerabilities.

## Scope

cento constructs and validates payload bytes; it does not execute targets, open network connections, or ship delivery mechanisms. Reports about the
correctness of the fail-closed gates (a refusal that should have fired and did not) are in scope and especially welcome. The optional `[verify]` extra runs
gadget bytes under the unicorn emulator; issues in unicorn itself belong upstream.

## Supported versions

Pre-1.0: only the latest released version receives fixes.
