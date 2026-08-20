# Codex integration contract

## Runtime hooks

Ward installs two user-global command hooks.

| Event | Ward behavior |
| --- | --- |
| `SessionStart` | Run a Host-side health check on startup/resume/clear, excluding automatic compaction; emit nothing when healthy and only redacted check IDs when unhealthy. |
| `PreToolUse` | Evaluate the canonical shell, patch, delete, and move tool-name list with a two-second timeout. |

The Pre matcher is derived from the same exported list used by the Codex
adapter. It is never `*`. Ward does not install PermissionRequest or
PostToolUse, does not emit a normal status message, and does not add context for
a defer.

| Core result | Adapter output |
| --- | --- |
| `deny` | `permissionDecision: "deny"` with static rule and recovery text |
| `defer` | no stdout or stderr |
| `error` | no permission decision; Host flow continues |

Ward never returns `allow`, `ask`, or updated input.

Current Codex runs command hook handlers but cannot use a Hook to create a
separate Agent. The current Agent handles a denial using the Ward Skill and
retries a safer operation when it needs no new authority.

## Installation ownership

The CLI owns only:

- the two Ward command entries in user-global `hooks.json`;
- one marked `ward-baseline` block and its selection in `config.toml`;
- the versioned integration journal and Ward audit state.

Journal v2 records the pre-Ward bytes and Ward-owned digests. An existing
three-Hook installation is upgraded atomically: the wildcard Pre entry is
replaced, Ward PermissionRequest/Post entries are removed, SessionStart is
added, and unrelated configuration is preserved. Rerun and uninstall are
idempotent. Modified owned bytes or an additive user policy are conflicts.

`approval_policy` is never edited. A named active permission profile is a safe
parent only when it directly extends `:workspace` or `:read-only`, has no
filesystem authority, and otherwise contains only string `description`
metadata plus the currently documented Codex network subtree. Those values are
inherited unchanged; unknown authority fields stop installation. With no active
profile the default is `:workspace`. Legacy
`sandbox_mode` requires explicit `--migrate-permissions`. An explicitly
migrated danger-full configuration retains command network access while
filesystem authority is intentionally narrowed. Ambiguous legacy network or
workspace semantics are rejected instead of guessed.

Hook commands use the absolute stable binary path below
`${CODEX_HOME:-$HOME/.codex}/ward/bin`. Control paths, dedicated state anchors,
symlinks/reparse points, ownership, and replacement authority are validated
before integration writes.

The v0.1 lifecycle supports only an absolute `CODEX_HOME` directly below the
actual user HOME. Nested, external, symlinked, or reparse-point layouts are an
explicit install conflict pending a broader control-anchor design.

## Management UX

SessionStart runs Doctor through the Host hook path. A healthy result is exactly
silent. An unhealthy result exposes only bounded check IDs, never paths,
diagnostic messages, or environment values.

The two-second Hook budget uses the bounded structural Doctor subset. Codex
version discovery and the native sandbox probe remain explicit trusted-terminal
Doctor checks; they are not repeated at every SessionStart.

Ward cannot inspect Codex's exact-definition trust decision. `hooks.trust` is
therefore always an unverified warning for user hooks, never a PASS. Ward
rejects `allow_managed_hooks_only = true` when it is visible in the user
configuration it edits. Requirements supplied by MDM, cloud policy, or another
managed configuration layer may not be locally observable, so install and
Doctor do not prove Host dispatch; a trusted real-Codex dispatch remains an RC
gate.

An ordinary guarded project tool does not gain privilege to read Ward control
or audit state. Explicit `ward doctor`, audit, install, uninstall, and repair
commands therefore require an already-authorized Host path or trusted local
terminal. The Plugin reports `Not run` when such a path is unavailable.

## Known limits

- Plugin presence does not prove Core activation.
- Hook absence, timeout, trust rejection, session profile overrides, and
  unobserved hosted tools remain Host coverage gaps.
- The minimal native profile does not claim arbitrary `.env.<custom>`, generic
  PEM/YAML/key names, or HOME authentication stores. HOME stores remain usable
  only when the active workspace is narrower than HOME; HOME-as-workspace is an
  explicitly warned unsupported topology.
- Linux/WSL/native Windows recursive deny expansion is bounded to 16 levels;
  deeper reviewed names are outside the v0.1 native claim.
- If the current workspace can relocate a Ward control/state anchor, Doctor
  reports a project-scoped health warning instead of making the entire home or
  project tree read-only.
- Lexical evaluation does not close kernel, mount, hard-link, or TOCTOU races.
- The Host may retain original tool input in its own transcript even though
  Ward audit does not.
- Repository scripts prove handler behavior and native profile behavior in
  isolation. Actual Codex Hook dispatch/trust is a separate RC gate until a real
  Host session demonstrates it.
