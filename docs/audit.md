# Audit evidence

Ward audit is a sparse record of attributable PreToolUse vetoes and evaluator
errors, not a command transcript and not proof of execution.

New writers accept only:

- `phase = pre`;
- `host_disposition = unknown`;
- `ward_decision = deny | error`;
- no coverage-gap detail.

An ordinary `defer` never opens the audit store. PermissionRequest and
PostToolUse are not recorded by the ambient kernel.

`ward-audit-event/v1` remains a historical superset. Older authenticated chains
containing defer, permission-request, or post events continue to verify,
display, and contribute to historical statistics; Ward never rewrites them.

Stored values include schema/version, time, decision, static rule/risk IDs,
engine version, policy digest, and HMAC-derived project/request/session/turn/tool
identifiers. Raw commands, patches, paths, environment variables, tool output,
transcript paths, and secrets are never stored.

Each JSONL record includes the previous record MAC. `ward audit verify`
detects reordering, modification, malformed records, unsafe state permissions,
and truncation relative to the retained signed head. It cannot distinguish an
older internally valid snapshot from current state without an external
monotonic anchor.

An audit append failure never changes an established deny and cannot turn a
defer into a deny. A failed append can therefore leave that exceptional event
absent from the chain. Persistent missing, unsafe, or invalid storage is
reported by Doctor; transient contention is not itself durable evidence. The
one-event-per-deny/error release check applies while the initialized audit
store is healthy, and separate fault tests prove that audit failure cannot
remove the enforcement response or delay it beyond Ward's bounded local audit
budget.

`ward audit repair` is forward-only: it can advance a stale signed head over an
already authenticated tail after a crash. It cannot rewrite events or repair a
bad MAC. Public pruning is excluded from v0.1; Doctor and stats retain size
visibility while real sparse-event volume is measured.
