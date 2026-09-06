# Evaluator conformance corpus

`fixtures/evaluator-v1.jsonl` is Ward's independent attack-and-counterexample
corpus. Every row contains normalized evaluator input plus the expected
veto-only result; it is not a public wire protocol.

Changing an existing expected outcome or adding a built-in deny requires the
admission process in `docs/rule-admission.md`. The corpus keeps the filesystem
and Git vetoes defined in `README.md`, including mixed commands. Temporary CWD,
repository, worktree, and repository-ancestor cleanup counterexamples defer,
alongside ordinary database/infrastructure requests. Native profile and real
Host cleanup checks are separate from this evaluator corpus.
