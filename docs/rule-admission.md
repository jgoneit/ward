# Built-in rule admission

A proposed built-in deny rule must satisfy every condition below.

1. It protects an actual secret or a high-impact action that is difficult to
   recover from.
2. The tool, operation, and target can be classified with high confidence.
3. The rule blocks the smallest target rather than a whole tool or workflow.
4. Tests include both attacks and ordinary Agent workflow counterexamples.
5. The rule first runs audit-only on real Tasks.
6. Burn-in shows defensive value and zero unresolved false deny.

Otherwise the behavior stays `defer` or audit-only. The frozen
`harness-legacy` cases are an attack corpus, not an inherited policy.
