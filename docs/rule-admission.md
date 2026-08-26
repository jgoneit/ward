# Built-in rule admission

A new default deny must satisfy every condition:

1. It protects a secret-control boundary or state whose loss is difficult to
   recover from.
2. Tool, operation, and target are classified with high confidence.
3. The rule blocks the smallest target rather than a whole workflow.
4. Tests contain both attacks and realistic normal Agent counterexamples.
5. The candidate first remains conformance-only during real Task burn-in.
6. Burn-in demonstrates defensive value with zero unresolved false deny.

Otherwise it stays `defer`. Ward does not provide a record-only rule mode and
does not persist Hook outcomes.
