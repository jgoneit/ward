# Codex integration contract

## Runtime hooks

Ward installs two user-global command hooks.

| Event | Ward behavior |
| --- | --- |
| `SessionStart` | Check installation health on startup, resume, and clear, excluding automatic compaction. Healthy is silent; unhealthy emits only redacted check IDs. |
| `PreToolUse` | Classify the canonical shell, patch, delete, and move tool-name list with a two-second timeout. |

The Pre matcher comes from the same exported list used by the Codex adapter. It
is never `*`. Ward does not install PermissionRequest or PostToolUse hooks and
does not add normal-path status or model context.

| Core result | Adapter output | Persistent Hook write |
| --- | --- | --- |
| `deny` | `permissionDecision: "deny"` with static rule and recovery text | none |
| `defer` | no stdout or stderr | none |
| `error` | no permission decision; Host flow continues | none |

Ward never returns `allow`, `ask`, or updated input. A Hook request is never
stored by Ward.

Current Codex runs command handlers but cannot use a Hook to create a separate
Agent. The current Agent handles a denial using the Ward Skill and retries a
safer operation when that needs no new authority.

## Installation ownership

The CLI owns only:

- the two Ward command entries in user-global `hooks.json`;
- one marked `ward` permission-profile block and its selection in `config.toml`;
- one private integration journal below the Ward `core` state directory.

Fresh install requires the current Codex permission-profile configuration.
Ward preserves unrelated Host bytes, refuses unsupported authority, and keeps
rerun and uninstall idempotent. It does not import or translate older Ward
installations.

`approval_policy` is never edited. A named active permission profile is a safe
parent only when it directly extends `:workspace` or `:read-only`, has no
filesystem authority, and otherwise contains only string `description`
metadata plus the currently supported Codex network subtree. Those values are
inherited unchanged; unknown authority fields stop installation. With no active
profile the parent is `:workspace`.

Hook commands use the absolute managed binary path below
`${CODEX_HOME:-$HOME/.codex}/ward/bin`. Control paths, the private integration
journal, dedicated state anchors, symlinks/reparse points, ownership, and
replacement authority are validated before integration writes.

The v0.1 lifecycle supports only an absolute `CODEX_HOME` directly below the
actual user HOME. Nested, external, symlinked, or reparse-point layouts are an
explicit install conflict pending a broader control-anchor design.

## Management UX

SessionStart runs the bounded structural Doctor subset through the Host hook
path. A healthy result is exactly silent. An unhealthy result exposes only
bounded check IDs, never paths, diagnostic messages, or environment values.

Codex version discovery and the native sandbox probe remain explicit
trusted-terminal Doctor checks; they are not repeated at every SessionStart.

Ward cannot inspect Codex's exact-definition trust decision. `hooks.trust` is
therefore always an unverified warning for user hooks, never a PASS. Ward
rejects `allow_managed_hooks_only = true` when it is visible in the user
configuration it edits. Requirements supplied by MDM, cloud policy, or another
managed configuration layer may not be locally observable, so install and
Doctor do not prove Host dispatch; a trusted real-Codex dispatch remains an RC
gate.

An ordinary guarded project tool does not gain privilege to read Ward control
or integration state. Explicit Doctor, install, and uninstall commands require
an already-authorized Host path or trusted local terminal. The Plugin reports
`Not run` when such a path is unavailable.

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
- Lexical classification does not close kernel, mount, hard-link, or TOCTOU
  races.
- The Host may retain original tool input in its own transcript even though
  Ward stores no Hook request or result.
- Repository scripts prove handler behavior and native profile behavior in
  isolation. Actual Codex Hook dispatch/trust remains a separate RC gate until
  a real Host session demonstrates it.
