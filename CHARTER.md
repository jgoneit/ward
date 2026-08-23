# Ward Charter

Ward exists to reduce security risk without recreating a human approval
bottleneck.

## Product promise

> Ward installs a bounded native secret boundary, vetoes a small set of
> high-confidence destructive actions, and otherwise disappears into the
> user's existing Host permission flow.

Ward succeeds only when both statements are true:

1. An Agent can finish ordinary development without disabling Ward.
2. Ward adds no prompt or model context to work the user already authorized.

## Fixed layers

Ward has no user-selected runtime modes. A Core installation owns:

- a synchronous destructive-action veto for supported tool paths;
- a native profile for reviewed high-confidence workspace secret names;
- privacy-preserving audit events only for attributable `deny` and `error`.

The Plugin and Skill explain health and help the current Agent recover after a
deny. They are not security boundaries and do not approve access.

## Decision vocabulary

- `deny`: a narrow, high-confidence destructive rule matched.
- `defer`: Ward made no decision and produced no prompt, context, or audit
  mutation.
- `error`: Ward could not evaluate reliably; the Codex adapter emits no
  permission decision and the Host remains authoritative.

Ward never returns `allow`, `ask`, or legacy `approve`, and never edits
`approval_policy`.

## Autonomy constraint

Ambiguous syntax, unknown tools, interactive sessions, secret-reading commands,
ordinary deletion, builds, normal Git, migrations, and infrastructure planning
defer. A new built-in deny is admitted only for a recoverability-critical
target that can be identified with high confidence and has attack plus normal
workflow counterexamples.

Harness Legacy fixtures are test input, not inherited policy.
