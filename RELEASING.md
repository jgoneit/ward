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

- Fresh install, reinstall, uninstall, SessionStart, and Doctor E2E pass on
  macOS, Linux/WSL, and native Windows. Handler/profile tests that pipe
  synthetic payloads do not substitute for one trusted real-Codex Hook dispatch
  on each supported Host.
- The installed definition contains exactly one narrow PreToolUse hook and one
  SessionStart hook; Ward PermissionRequest/Post hooks are absent.
- Ward-added and duplicate prompts are zero.
- Defer and evaluator-error output is zero. Deny, defer, and evaluator-error
  Hook persistence is zero.
- Protected-secret and defined catastrophic-destruction fixtures have zero
  escapes within the documented 16-level native expansion bound. The
  max-supported depth and max-plus-one behavior are recorded per platform.
- Normal workflows have zero unresolved false deny.
- Hook requests do not create or change Ward state. Only explicit management
  commands may update the integration journal, and uninstall removes it after
  restoring owned Host configuration.
- Hook latency meets the documented p95 targets and the two-second timeout.
- Twenty real Tasks finish without disabling Ward or asking a human to perform
  ordinary development work in Ward's place.
- A denial with a safe alternative is recovered by the current Agent without a
  new human prompt.

Only then may `v0.1.0-rc.1` be created.

Before RC, Harness Toolkit may pin a reviewed development commit only as an
**Experimental** source module. That pin does not install Ward, activate Core,
or imply that an RC gate passed. A release pin is a later exact-SHA update.
