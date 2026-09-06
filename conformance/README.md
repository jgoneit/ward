# Evaluator conformance corpus

`fixtures/evaluator-v1.jsonl` is Ward's independent attack-and-counterexample
corpus. Every row contains normalized evaluator input plus the expected
veto-only result; it is not a public wire protocol.

Changing an existing expected outcome or adding a built-in deny requires the
admission process in `docs/rule-admission.md`. The corpus keeps filesystem and
Git vetoes alongside ordinary counterexamples and database/infrastructure
requests that defer. Mixed-command cases retain the filesystem and Git vetoes.
