# Threat model

## Protected assets

- local secret-bearing files and credential stores;
- repository metadata and Ward's state/key;
- roots whose recursive deletion is difficult to recover;
- databases, schemas, namespaces, and volumes targeted by a small set of
  explicit destructive commands.

## In scope

- Codex user-global `PreToolUse`, `PermissionRequest`, and `PostToolUse`
  payloads;
- native Codex filesystem permission configuration;
- literal, high-confidence shell and patch operations;
- privacy-preserving, per-project decision evidence.

## Outside the v0.1 boundary

- hosted or specialized tool paths the Host does not send through hooks;
- arbitrary `.env.<custom>` paths that do not match the bounded native profile
  and reach Ward only through an unobserved or bypassed tool path;
- TOCTOU, hard-link, bind-mount, kernel, and same-user key compromise;
- decoding arbitrary scripts or proving an ambiguous command safe;
- workflow approval, task state, reviewer verdicts, or a separate Agent;
- automatic authorization of any operation.

The Ward Plugin and Skill do not bypass native permissions. Management
commands that need denied control or audit state are outside the ordinary
guarded project process and require a trusted Host-side execution path or local
terminal. Lack of such a path is reported as `Not run`, not treated as proof of
health or failure.

Environment-selected credential locations are protected only after their
absolute paths are captured by installation. Doctor detects a changed or
unrepresentable set, but Ward does not claim protection for a new override
before reinstall. Directory-valued overrides receive a read-only native anchor;
an arbitrary file-valued override can still be relocated by moving a writable
parent when that parent is inside the project being diagnosed, so Doctor
reports that topology as a release-blocking native gap for that project. A
same-user attacker restoring an older valid audit snapshot is also outside the
v0.1 tamper-evidence claim.

Ward protects the immediate audit-state anchor, but an XDG or LocalAppData
ancestor inside the active project can still be relocated without freezing a
much broader project tree. Doctor reports this project-scoped topology and the
development build treats it as a release blocker there; HMAC integrity is not
claimed to prevent that same-user relocation. State outside the current
workspace is not assumed writable through the `:workspace` profile.

When Ward cannot classify a request with high confidence, it records a
coverage gap and returns `defer`. The Host's existing sandbox and approval
policy remain authoritative.

Ward's privacy claim applies to Ward-owned audit state. Codex owns the task
transcript and denial presentation; those surfaces can include the original
command, patch, or path even when Ward returns only a static reason.
