# Evaluator conformance corpus

`fixtures/evaluator-v1.jsonl` is Ward's independent attack-and-counterexample
corpus. Every row is a canonical `ward-request/v1` plus the expected
veto-only result.

The legacy review source is frozen at
`jgoneit/harness-legacy@96b42bce7a367583665e94cddb4ba974070d7d7f`.
That source contributed test ideas only. Ward deliberately does not claim
behavioral parity or copy the legacy block list: legacy blocked all `.env*`
templates and allowed several secret/delete cases that Ward defines
differently. Each fixture therefore expresses the Ward Charter, including a
normal-workflow counterexample for narrow deny rules.

Changing an existing expected outcome or adding a built-in deny requires the
admission process in `docs/rule-admission.md`. Additive user policy has its own
tests and cannot relax this corpus.
