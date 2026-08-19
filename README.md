# Ward

Ward is a Codex-first, veto-only security guardrail designed to protect secrets
and stop a small set of catastrophic actions without adding a new human
approval bottleneck.

> Ward installs and verifies a bounded native secret boundary, vetoes a small
> set of high-confidence catastrophic actions, and otherwise defers to the
> user's existing Host permissions.

Ward is currently under v0.1 development. It is not released and should not be
treated as an unbypassable sandbox.

## Decision flow

```text
Tool request
    |
    v
  Ward
    |-- high-confidence risk --> deny
    `-- everything else ------> defer
                                  |
                                  v
                         current Host permissions
                         |-- already allowed -> run
                         |-- approval needed -> Host asks once
                         `-- not allowed ----> Host rejects
```

`defer` does not mean allow. Ward emits no permission decision for it, so
Codex retains the user's current permission profile, sandbox, and approval
policy. Ward never returns `allow`, `ask`, or legacy `approve`.

## v0.1 scope

Ward denies only high-confidence cases:

- access to protected secret paths, while exact `.env.example`,
  `.env.sample`, `.env.template`, and `.env.dist` templates remain ordinary;
- recursive deletion of filesystem, home, workspace, or repository roots;
- deletion of `.git`, protected secrets, or Ward state/key;
- `git reset --hard`, destructive `git clean`, and force push;
- explicit `DROP DATABASE`, `DROP SCHEMA ... CASCADE`, `terraform destroy`,
  `kubectl delete namespace`, and `docker compose down -v`;
- a true interactive shell, REPL, or database client started without a command.

Ordinary single-file deletion, refactors, builds, package installation, normal
Git work, migrations, test-data changes, infrastructure planning/apply, unknown
MCP tools, and ambiguous shell expressions defer to Codex.

## Architecture

1. A Codex native permission profile is the filesystem boundary for secret
   paths that the Host permission language can represent without blocking
   public templates.
2. User-global synchronous hooks veto supported high-confidence requests.
3. The Ward Plugin and Skill expose Doctor, audit inspection, and explanations.
4. Per-project HMAC-chained JSONL records decisions without raw commands,
   patches, paths, environment variables, output, transcripts, or secrets.

Hooks are guardrails, not complete security boundaries. Some hosted or
specialized tool paths can bypass them; see [Codex Hooks](https://learn.chatgpt.com/docs/hooks)
and [Codex Permissions](https://learn.chatgpt.com/docs/permissions).

The Plugin is management UX, not a privileged process. After `ward-baseline`
is active, an ordinary project-sandbox command cannot read the Ward control and
audit paths that the profile deliberately denies. `ward doctor`, `ward audit`,
active-policy validation, install, and uninstall must therefore run through an
already-authorized Host-side execution path or a trusted local terminal. When
that path is unavailable, the Plugin reports those checks as `Not run`; it does
not weaken the boundary or create a Ward-specific approval prompt. `ward
--version` and static decision explanations remain usable inside the sandbox.

Codex 0.147 cannot express a broad `.env.*` native deny followed by exact
`.env.example`-style exceptions: a matching deny glob wins. Ward therefore
denies `.env`, reviewed common sensitive suffixes, keys, credential stores, and
other representable paths natively. Arbitrary `.env.<custom>` names are denied
when a supported request reaches Ward's hooks, but remain an explicit native
coverage gap reported by `ward doctor`. This tradeoff preserves normal public
template reads and writes instead of recreating the broad false-deny behavior
of Harness Legacy.

Installation also resolves supported credential path overrides into exact
native denies. It also makes the narrow directories anchoring `config.toml`,
`hooks.json`, the Ward executable, Ward policy/state, and directory-valued
credential overrides sandbox read-only. This prevents a writable parent rename
from relocating a protected file outside its exact rule without denying reads
of unrelated control metadata. The release installers therefore place the
binary in the dedicated `${CODEX_HOME:-$HOME/.codex}/ward/bin` directory; a
custom binary location must remain below that `CODEX_HOME` control root.
Symlinked or locally writable control paths are an install conflict, not
something Ward silently repairs. If a credential path override changes later,
`ward doctor` fails until the integration is reinstalled with the new exact
path set.

For v0.1, `CODEX_HOME` itself must be a direct child of the user home. Ward
rejects a control root nested inside a project because protecting only its
immediate directory would not stop a writable higher ancestor from being
renamed, while freezing the whole project would violate Ward's autonomy goal.

File-valued overrides such as a custom `KUBECONFIG` may point into an arbitrary
project directory. Ward denies the exact file but does not silently make that
whole project directory read-only. Doctor reports this as
`permissions.credential_topology`. The same warning applies to a directory
override nested below a writable ancestor of the project passed to Doctor (or
the current project by default). Until the credential is moved to a dedicated,
stable directory, ancestor relocation is a hook-dependent native coverage gap
and a release blocker for that project, not a hidden claim of complete
isolation. Normal user configuration outside the current workspace does not
produce this warning merely because it is nested below `$HOME`.

The mandated XDG/LocalAppData audit location can likewise have a writable
higher ancestor inside the active project even though Ward protects its
immediate `ward` directory. Doctor reports `permissions.state_topology` for
that project; ancestor relocation can degrade audit continuity and remains a
release blocker there. Ward does not make all of `~/.local` or a custom state
tree read-only merely to hide that limitation.

## Build from source

Requirements: Go 1.25 or newer.

```sh
go build -o bin/ward ./cmd/ward
go test ./...
go vet ./...
```

## CLI

```text
ward --version
ward evaluate --input - --json

ward hook codex-pre-tool-use
ward hook codex-permission-request
ward hook codex-post-tool-use

ward policy validate [--file PATH] [--json]
ward codex install --scope user --profile baseline [--migrate-permissions] [--dry-run]
ward codex uninstall --scope user [--dry-run]
ward doctor [--project PATH] [--json]

ward audit show [--project PATH] [--since DURATION] [--json]
ward audit verify [--project PATH] [--json]
ward audit stats [--project PATH] [--since DURATION] [--json]
ward audit prune [--before DURATION] [--dry-run]
ward audit repair [--project PATH] [--dry-run] [--json]
```

The machine contracts are `ward-request/v1`, `ward-decision/v1`,
`ward-audit-event/v1`, and `ward-doctor/v1`.

## Codex installation

First inspect the proposed change:

```sh
ward codex install --scope user --profile baseline --dry-run
```

If any Codex configuration layer contains the legacy `sandbox_mode`, Ward
refuses installation without changing files. An explicit migration is required:

```sh
ward codex install --scope user --profile baseline --migrate-permissions --dry-run
ward codex install --scope user --profile baseline --migrate-permissions
```

Migration preserves `approval_policy`; it does not turn approvals on or off.
Installation and removal modify only Ward-owned hook/profile entries and keep a
journal for conflict-safe restoration. Audit state is preserved on uninstall.
The installer rejects unsafe control-file ownership, write permissions, and
symbolic links before reading or replacing those files.

Command network authority is not inferred from `defer`. A fresh Ward profile
keeps command networking disabled, matching the least-privilege `:workspace`
default. When—and only when—the user explicitly migrates legacy
`sandbox_mode = "danger-full-access"`, Ward writes `network.enabled = true` so
previously authorized package fetches remain available. Ward refuses the more
ambiguous legacy `[sandbox_workspace_write]` table for manual migration rather
than guessing. Consequently, `defer` means the Host decides; it does not
promise that every safe command has filesystem or network access.

## Audit semantics

A Pre event is an attempted request and a Ward decision, not proof that a tool
ran. A matching PermissionRequest is recorded as `approval_requested`; a
matching Post event is `post_observed`, which still does not prove success.
When neither arrives, disposition remains `unknown`.

On macOS/Linux the state root is
`${XDG_STATE_HOME:-$HOME/.local/state}/ward/v1`. On Windows it is
`%LOCALAPPDATA%\Ward\state\v1`.

The development build supports retention previews with
`ward audit prune --dry-run`, but mutation pruning is intentionally disabled
and exits with an audit error. Crash-safe cross-platform pruning requires a
generation-manifest storage contract and remains a release blocker; Ward will
not revive the earlier non-atomic rewrite path merely to satisfy retention
limits.

`ward audit repair` is deliberately narrow: after a crash between an
authenticated append and head update, it can advance only a stale signed head
to an already verified forward tail. It cannot rewrite events or repair an
invalid MAC. Doctor remains failed until an operator explicitly requests the
repair.

## Rollout gate

Ward may be listed in Harness Toolkit before RC only as an **Experimental**
source pin. That gitlink does not install or activate Ward, satisfy any release
gate, or claim production readiness. Ward will not publish `v0.1.0-rc.1` or
advance beyond Experimental until isolated platform E2E passes, Plugin
Doctor/audit has a reviewed Host-side management path, and twenty real Tasks
complete with zero Ward-added prompts, zero secret or catastrophic escapes,
zero unresolved false deny, and zero need to disable Ward. Requiring a human
to relay routine diagnostics from a terminal is not RC-complete. A later
explicit Toolkit update will pin the reviewed release commit by exact SHA at
`modules/security/ward`; Toolkit pins never follow a branch.

See [CHARTER.md](CHARTER.md), [SECURITY.md](SECURITY.md), and
[RELEASING.md](RELEASING.md).
