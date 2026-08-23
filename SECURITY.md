# Security policy

Ward is defense in depth, not an unbypassable sandbox. Native Host permissions
are the actual filesystem boundary for the reviewed names they can represent.
Hooks cover only requests the Host delivers through the trusted definition.

## v0.1 claims

- Ward can install and diagnose one user-global SessionStart hook, one narrow
  PreToolUse hook, and a bounded native permission profile.
- Supported literal high-confidence destructive requests are denied; everything
  else, including evaluator errors, is left to the Host.
- New audit records contain only attributable Pre deny/error metadata in an
  HMAC chain and never raw requests, paths, environment, output, or secrets.
- Public templates and generic certificate/config files remain usable. HOME
  authentication stores remain usable for ordinary project workspaces;
  HOME-as-workspace is unsupported and produces a topology warning.
- Recursive workspace secret-name coverage is bounded to 16 directory levels
  on platforms where Codex pre-expands deny globs.

Hook absence, timeout, trust rejection, session profile changes, hosted tools,
ambiguous command construction, filesystem races, and same-user replacement of
the complete key plus state are outside these claims.

Audit availability is deliberately subordinate to enforcement availability.
If an append fails or exceeds its local budget, Ward returns the already-made
deny (or Host-deferred error) after at most the bounded local audit wait; that
exceptional event may be missing from the chain. Persistent store failure is
diagnosed later, while transient contention is not a durable signal.

Ward cannot verify Codex's user-Hook trust decision. Configuration is not proof
of active PreToolUse enforcement; trusted real-Host dispatch remains a release
gate.

## Reporting

Do not open a public issue containing a credential, private path, command
payload, transcript, or audit key. Use GitHub private vulnerability reporting
when enabled.
