# Releasing Ward

## Development prerelease

Before the RC gates pass, Ward may publish only a `vX.Y.Z-dev.N` GitHub
prerelease for installation and burn-in. A development prerelease must:

- point to an exact, reviewed `main` commit whose pull-request and post-merge
  CI completed successfully;
- remain marked as a prerelease and must not be selected as the latest release;
- state `KEEP + BURN-IN, NOT STABLE` and list the unmet RC gates in its notes;
- publish checksummed artifacts built from the tag and pass an isolated
  installer verification; and
- make no RC, stable, or Harness release-pin claim.

A development prerelease is not promoted or retagged. RC or stable releases
use a new tag after all applicable gates below pass.

## RC entry

No RC or stable release may skip these gates.

- Fresh install, owned-profile refresh, reinstall, uninstall, SessionStart, and
  Doctor E2E pass on macOS, Linux/WSL, and native Windows. Synthetic payloads do
  not substitute for trusted real-Codex Hook dispatch on each supported Host.
- The installed definition contains exactly one narrow PreToolUse hook and one
  SessionStart hook; Ward PermissionRequest/Post hooks are absent.
- Ward-added and duplicate prompts are zero.
- Defer and evaluator-error output is zero. Deny, defer, and evaluator-error
  Hook persistence is zero.
- Root-level protected-secret read denials, exact filename write denials, and
  defined catastrophic-destruction fixtures have zero escapes. Native glob
  rules do not promise write protection. The same fake secret names in nested and depth-10 folders
  remain readable, writable, and removable unless a folder is itself a Host
  workspace root.
- Profile refresh preserves user-added roots, external configuration, Hook
  bytes, line endings, and restoration data. Tampering and duplicate ownership
  are rejected; dry-run writes nothing, repeat install is a no-op, and handled
  write failures restore the original files.
- A fresh macOS Host session verifies candidate permissions, empty/nested folder
  creation, rename, modification, deletion, and small Cargo build/test cleanup.
  Core `defer` and repository checks alone do not prove native `EPERM` resolved.
- Normal workflows have zero unresolved false deny.
- Hook processes do not create or change persistent Ward state. An opt-in
  collector may store the documented diagnostic events separately. Only explicit
  management commands update the integration journal, and uninstall removes it
  after restoring owned Host configuration and stopping the owned collector.
- Hook latency meets the documented p95 targets and the two-second timeout.
- Twenty real Tasks finish without disabling Ward or asking a human to perform
  ordinary development work in Ward's place.
- A denial with a safe alternative is recovered by the current Agent without a
  new human prompt.
- Diagnostics preserve policy stdout/stderr/exit behavior while disabled,
  enabled, unreachable, saturated, or unable to persist. The event corpus
  contains no raw sensitive input. Real-process p95 meets the existing limits
  in disabled, enabled, and unavailable-collector cases on all three platforms.
- Each supported user-service backend passes non-administrator enable/disable,
  repeat activation, login restart, crash recovery, conflict, update rollback,
  and uninstall checks. WSL and systemd user-manager limitations are recorded.
  Backend fixtures and cross-builds are not actual login-service evidence.
- A trusted real Codex invocation reaches the candidate Hook and its collector
  with stable correlation IDs. Synthetic handler/collector tests do not prove
  real Host dispatch or native permission enforcement.

Only then may `v0.1.0-rc.1` be created.

Before RC, Harness Toolkit may pin a reviewed development commit only as an
**Experimental** source module. That pin does not install Ward, activate Core,
or imply that an RC gate passed. A release pin is a later exact-SHA update.
