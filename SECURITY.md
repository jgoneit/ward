# Security policy

Ward is defense in depth, not an unbypassable sandbox. Native Host permissions
are the actual filesystem boundary for the reviewed names they can represent.
Hooks cover only requests the Host delivers through the trusted definition.

## v0.1 claims

- Ward can install and diagnose one user-global SessionStart hook, one narrow
  PreToolUse hook, and a bounded native permission profile.
- Supported literal high-confidence destructive requests are denied; everything
  else, including evaluator errors, is left to the Host.
- Hook evaluation writes no persistent Ward data for deny, defer, or error.
- An opt-in separate collector can persist redacted PreToolUse diagnostics.
  Delivery is authenticated IPv4 loopback UDP with a protected per-start key;
  it is best effort and cannot prove Host dispatch, execution, or full coverage.
- Native secret rules cover only reviewed names immediately below each Host
  workspace root on all platforms. Nested secrets are intentionally outside
  this boundary; Ward does not discover or register them.
- Native glob rules deny reads; Ward does not claim write protection for
  wildcard-matched secret names. Exact filename write denials are tested separately.

Hook absence, timeout, trust rejection, session profile changes, hosted tools,
ambiguous command construction, filesystem races, and same-user replacement of
Ward's installation state are outside these claims.

Ward cannot verify Codex's user-Hook trust decision. Configuration is not proof
of active PreToolUse enforcement; trusted real-Host dispatch remains a release
gate.

Diagnostics exclude original commands, patches, paths, output, environment
values, and free-form error messages. Valid call identifiers are pseudonymous
correlation metadata, not proof of identity. A same-user process with access to
the collector key can inject events; HMAC is not tamper-proof security auditing.
Keys and runtime descriptors remain under protected Core state. Log files are
separate from installation ownership records. Only the collector writes and
expires its owned logs; a Hook has no persistent fallback or remote endpoint.

## Reporting

Do not open a public issue containing a credential, private path, command
payload, or transcript. Use GitHub private vulnerability reporting when
enabled.
