# Ward Charter

Ward exists to reduce security risk without recreating a human approval
bottleneck.

## Product promise

> Ward installs and verifies a bounded native secret boundary, vetoes a small
> set of high-confidence catastrophic actions, and otherwise defers to the
> user's existing Host permissions.

Ward must satisfy both of these conditions:

1. An Agent can complete normal development work without disabling Ward.
2. Ward adds no approval prompt to work the user has already authorized.

## Authority boundary

- The Host's native permission profile is the secret filesystem boundary for
  paths its policy language can represent without breaking ordinary public
  template workflows.
- Ward hooks are synchronous, veto-only guardrails for supported tool paths.
- The Plugin and Skill provide installation, diagnostics, audit, and
  explanation UX; they are not security boundaries.
- Ward never grants access, never auto-approves a request, and never changes a
  user's approval policy.
- Ward never broadens command network authority during installation. Explicit
  danger-full migration may preserve already-authorized networking; otherwise
  the Host profile remains least privilege.

## Decision vocabulary

- `deny`: a narrow, high-confidence built-in or additive-deny rule matched.
- `defer`: Ward makes no access decision; the Host keeps its normal flow.
- `error`: Ward could not uphold its evaluation contract. The Codex adapter
  maps this to a static deny response.

`allow`, `ask`, and legacy `approve` are not Ward decisions.
`defer` also does not promise that the Host grants filesystem or network
capability; it promises only that Ward adds no decision or prompt.

## Autonomy constraint

Ambiguity is not a deny rule. Unknown tools, unsupported syntax, ordinary file
deletion, normal Git work, builds, tests, package installation, migrations,
and infrastructure planning defer to Host permissions. A new built-in deny
rule is admitted only after audit-only burn-in proves defensive value with no
unresolved false deny.
