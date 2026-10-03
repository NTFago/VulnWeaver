# Binary analysis

Safe, bounded inspection of authorized x86/x64 ELF and PE artifacts. The package never
executes the analyzed sample and invokes external analyzers only through fixed argument
vectors without a shell.

Current coverage limit (2026-10-03 review): `BinaryAnalysisAggregate.merge` stops adding
functions, instructions and other facts when its configured maxima are reached, without
recording an aggregate-level truncation summary. A successful analysis therefore does not
prove that all facts were indexed. The default caps include 20,000 functions and 200,000
instructions. See [CR-08](../../docs/code-review-2026-10-03.md) for the code evidence and
acceptance criteria. Repeated full-graph neighborhood reads in persistence are tracked as
CR-07; their runtime cost has not yet been benchmarked.
