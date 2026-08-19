# Audit evidence

Ward audit data is intentionally less informative than a command transcript.
It is designed to answer “what decision class was observed?” without retaining
the material that made the request sensitive.

Stored values include schema/version, time, phase, decision, host disposition,
tool family, rule/risk IDs, static coverage-gap codes, policy digest, and
HMAC-derived project, request, session, turn, and tool identifiers. Stored
values exclude raw commands, patches, file paths, environment variables, tool
responses, stdout/stderr, transcript paths, and secrets.

Each JSONL record includes the previous record MAC. `ward audit verify`
recomputes the chain and detects reordering, modification, malformed records,
unsafe state permissions, and tail truncation relative to the retained signed
head. It cannot distinguish restoration of an older, internally valid snapshot
from current state. Preventing valid-snapshot rollback requires an external
monotonic anchor. This is tamper evidence, not protection against an attacker
who can replace the state key and every record.

By default Ward rotates on UTC day or 8 MiB and diagnoses targets of 30 days,
64 MiB per project, and 512 MiB total. `ward audit prune --dry-run` previews
the eligible authenticated prefix. Mutation is disabled in the development
build because the flat segment/head layout cannot make replacement and reader
pinning crash-safe on every target platform. A generation-manifest storage
contract and crash-point tests are required before release.

Audit failure never changes an established `deny` into another result. It also
does not turn a `defer` into a deny; Ward warns and Doctor reports failure so an
availability problem cannot become a new human bottleneck.

An append can be durable before its signed head update. Verification fails in
that state instead of ignoring the tail. `ward audit repair --dry-run` can
preview, and an explicit `ward audit repair` can perform, only a forward head
advance after the complete tail authenticates and extends the prior signed
head. Invalid records, divergent chains, and backward repairs stay failed.
