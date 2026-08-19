# Codex integration contract

## Hook mapping

| Ward result | Codex adapter output |
| --- | --- |
| `deny` | `permissionDecision: "deny"` with a static catalog reason |
| `defer` | no stdout; Codex continues its normal permission flow |
| `error` | a static deny response; no input is reflected |

The adapter never returns `permissionDecision: "allow"` or `"ask"`.

`PreToolUse` evaluates before Codex's normal permission flow.
`PermissionRequest` evaluates the same request again so a known high-risk
request cannot pass through a user approval; a defer leaves the existing Host
prompt unchanged. `PostToolUse` records only that the Host produced a post
event.

## Installation ownership

The CLI owns only:

- the Ward command entries in user-global `hooks.json`;
- one marked Ward permission-profile block in `config.toml`;
- the Ward installation journal and audit state.

It preserves unrelated hook entries and configuration content. Hook JSON may
be reformatted while its unrelated values stay unchanged. A legacy top-level
`sandbox_mode` is removed only with `--migrate-permissions`, and its exact text
is kept in the Ward journal for conflict-safe uninstall. `approval_policy` is
never edited.

Network permission is migrated narrowly. A fresh or legacy workspace/read-only
source does not gain command network access. An explicitly migrated
`danger-full-access` source retains command network access through
`[permissions.ward-baseline.network] enabled = true`. Ward rejects a legacy
`[sandbox_workspace_write]` table because its combined filesystem/network
meaning cannot be translated without a separate policy choice.

Hook commands use the absolute Ward binary path because Codex executes hooks in
the session working directory and a project must not be able to shadow the
security executable.

Codex invokes lifecycle hooks through its Host hook runner, but a Skill command
launched as an ordinary project tool remains inside the selected permission
profile. Consequently, once `ward-baseline` is active, that ordinary process
cannot read the denied Codex control, Ward policy, or audit-state paths needed
by `ward doctor`, `ward audit`, active-policy validation, install, or uninstall.
Those management commands require an already-authorized Host-side execution
path or a trusted local terminal. If neither is available, the Plugin reports
them as `Not run`; it must not reinterpret `EPERM` as an unhealthy installation
or ask to weaken the profile.

Installation rejects symbolic links, untrusted ownership, and group/other
writable authority for `config.toml`, `hooks.json`, the Ward binary, and their
control parents. It reports a conflict instead of silently changing user ACLs
or modes. The generated native profile denies sandboxed reads of Codex config
and hooks, while keeping the Ward executable and the narrow directories that
anchor all three readable but not writable. This stops a parent-directory
rename from disabling the hooks without turning the whole control tree into a
read-deny. Release installers use the dedicated
`${CODEX_HOME:-$HOME/.codex}/ward/bin` path; a custom binary directory becomes
sandbox read-only only when it remains under that control root. v0.1 rejects a
`CODEX_HOME` nested more deeply than one direct child of the user home: making
every writable ancestor read-only would otherwise freeze an arbitrary project.

Ward resolves credential locations such as `XDG_CONFIG_HOME`, `GH_CONFIG_DIR`,
`AWS_SHARED_CREDENTIALS_FILE`, `KUBECONFIG`, `DOCKER_CONFIG`,
`CLOUDSDK_CONFIG`, and `NPM_CONFIG_USERCONFIG` at installation and writes exact
native denies. Relative values are an install error. Doctor fails when the
currently resolved set differs from the installed profile, so changing an
override requires reinstalling the Ward integration.

## Known boundary limits

- Plugin presence does not prove hooks or native permissions are active.
- The Plugin has no implicit privilege over the project sandbox. Full Doctor,
  audit, and lifecycle commands are not runnable there after activation unless
  the Host already provides a suitable execution path.
- Hook absence, timeout, trust rejection, and unobserved hosted tools cannot be
  made fail-closed by the Ward process.
- Codex 0.147 deny globs take precedence over exact public-template entries, so
  the native profile cannot deny every `.env.*` name while keeping
  `.env.example`-style files usable. Exact `.env` and reviewed sensitive
  suffixes are native denies; arbitrary custom suffixes depend on an observed
  supported hook and produce a Doctor warning.
- Native SSH-key and credential-store denies may interrupt subprocesses that
  do not use an already-loaded keychain, agent, or credential broker. Doctor
  warns until those workflows have completed burn-in.
- Environment-resolved credential paths are a point-in-time installation
  snapshot. A newly changed location is not claimed protected until Doctor
  detects the mismatch and Ward is reinstalled.
- Ward makes directory-valued credential roots and reviewed default credential
  directories themselves sandbox read-only. For an arbitrary file-valued
  override, or a directory override nested below another writable ancestor of
  the project passed to Doctor, Ward does not make an entire project tree
  read-only; Doctor reports
  `permissions.credential_topology` and ancestor relocation remains
  hook-dependent until the credential is moved to a stable dedicated
  directory. Nested user configuration outside the current workspace does not
  trigger this warning by itself.
- Ward reports `permissions.state_topology` only when the audit-state anchor
  has a relocatable higher ancestor inside the project being diagnosed. The
  default user state path is not treated as writable from unrelated projects.
- Lexical path and shell inspection does not close symlink, hard-link, mount,
  or time-of-check/time-of-use races.
- Native permission behavior must be tested on each supported Host/platform.
- `defer` delegates to the complete Host profile; it is not a promise that the
  Host grants filesystem or network capability. Package downloads work without
  a new Ward prompt only when command network access is already represented in
  the migrated profile.
- Ward's audit never stores raw requests, but the Host owns its own transcript
  and denial UI and may retain or display the original tool request.
