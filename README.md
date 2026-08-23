# Ward

Ward is an ambient, veto-only Codex safety kernel. It blocks a small set of
high-confidence destructive actions, installs a bounded native boundary for
high-confidence workspace secret names, and otherwise leaves the user's Host
permissions alone.

Ward is under v0.1 development. It is not an unbypassable sandbox and has not
passed its release burn-in.

## Product contract

Ward has no user-selected runtime modes. One user-global Core installation
provides three fixed layers:

1. a minimal destructive-action evaluator;
2. a native permission profile for a reviewed secret-name set;
3. bounded HMAC audit attempts for `deny` and attributable `error` events only.

```text
tool request
    |
    v
  Ward
    |-- high-confidence destruction --> deny + bounded redacted audit attempt
    |-- evaluator error -------------> no Ward decision; Host decides
    \`-- everything else ------------> no output, no audit write; Host decides
```

`defer` is not an allow. Ward never emits `allow`, `ask`, input replacement, or
an additional approval step.

A healthy initialized audit store appends exactly one event for each
attributable deny/error. Audit unavailability never changes the decision, so a
failed or timed-out exceptional append may be absent as documented below.

The ordinary path makes no model call. A matched shell request starts the local
Go hook process, but a defer produces zero model-visible bytes and performs no
audit I/O.

## What v0.1 denies

- recursive deletion of `/`, the actual user home, the request CWD, the nearest
  Git root, or an ancestor containing one of those boundaries;
- deletion or relocation of `.git` or Ward control, state, and key paths;
- `git reset --hard`, forced directory clean, force/mirror/forced-refspec push;
- literal `DROP DATABASE` and `DROP SCHEMA ... CASCADE`;
- non-dry-run `terraform destroy`, `terraform apply -destroy`,
  `kubectl delete namespace`, and `docker compose down -v/--volumes`.

Ordinary file and directory deletion, build/cache cleanup, normal patch
deletion, `--force-with-lease`, migrations, table or row changes,
infrastructure planning, interactive shells, secret-reading commands, dynamic
expressions, and unknown tools defer to the Host.

Ambiguity is never promoted to a deny.

## Codex integration

Ward installs exactly two user-global command hooks:

| Event | Behavior |
| --- | --- |
| `SessionStart` | Run a Host-side health check on startup/resume/clear (never automatic compaction). Healthy is silent; unhealthy emits only bounded check IDs. |
| `PreToolUse` | Evaluate only reviewed shell, patch, delete, and move tool names before the Host permission flow. |

The Pre matcher is generated from one canonical tool-name list and never uses
`*`. Its timeout is two seconds. Ward does not install PermissionRequest or
PostToolUse hooks and does not emit normal-path status or model context.
SessionStart uses the bounded structural Doctor subset; the Codex version and
native sandbox probes remain explicit trusted-terminal checks rather than
per-session work.

Current Codex command hooks cannot start a separate Agent. A Ward denial is
therefore handled by the current Agent, which should choose a scoped,
recoverable alternative without asking the user when no new authority is
needed. The Plugin and Skill provide that recovery and explicit management UX;
they are not enforcement boundaries.

Hooks remain guardrails. A newly written user Hook is not active until Codex
trusts that exact definition; Ward cannot read or approve that Host decision.
Doctor therefore reports Hook trust as unverified, and installation reports
"configured" rather than claiming activation. Hosted, specialized, disabled,
untrusted, managed-hooks-only, or timed-out paths may bypass them. See [Codex Hooks](https://learn.chatgpt.com/docs/hooks)
and [Codex Permissions](https://learn.chatgpt.com/docs/permissions).

## Native secret boundary

The `ward-baseline` profile protects a deliberately small workspace-relative
set:

- `.env` and reviewed local/development/test/production/staging/secret suffixes;
- `*.key.json` and exact key, credentials, and service-account JSON basenames;
- exact `secrets` and `credentials` YAML basenames;
- canonical SSH/private-key basenames and reviewed private-key PEM basenames;
- `*.p12` and `*.pfx`;
- Ward control and audit state.

Public templates (`.env.example`, `.env.sample`, `.env.template`,
`.env.dist`), arbitrary custom `.env.*` suffixes, generic PEM/YAML/key names,
and HOME credential stores for SSH, GitHub, Docker, Kubernetes, clouds, and
package managers remain usable when the active workspace is a normal project
subdirectory. Opening HOME itself as the workspace is unsupported in v0.1:
workspace-relative recursive rules can then overlap those Host stores, so
Doctor and SessionStart report `permissions.home_workspace_topology`. Ward does
not claim the excluded paths or this topology are protected without workflow
impact.

On Linux/WSL/native Windows, Codex pre-expands recursive deny globs. Ward sets
`glob_scan_max_depth = 16`; reviewed names at greater depth are outside the v0.1
native claim. The platform E2E corpus exercises a depth-10 secret and a custom
dotenv counterexample.

The installer preserves `approval_policy`. A named existing permission profile
is inherited only when it directly extends `:workspace` or `:read-only` and
contains no filesystem authority. Its string `description` metadata and the
currently documented Codex network subtree are inherited unchanged; unknown
authority fields stop installation instead of being guessed. With no active
profile Ward uses `:workspace`. Legacy
`sandbox_mode` requires explicit `--migrate-permissions`, because it cannot be
composed with permission profiles. Danger-full migration preserves previously
available command networking while intentionally narrowing filesystem access.
Unrepresentable permission or network semantics are a conflict, not a guess.

Ward protects dedicated control/state anchors and reports a SessionStart health
warning when the active project topology can relocate them. Opening the user
home itself as a writable workspace remains an unsupported, explicitly warned
boundary rather than a reason to freeze the entire home directory.

## Build and install from source

Requirements: Go 1.25 or newer.

The v0.1 installer supports an absolute `CODEX_HOME` that is a direct child of
the actual user HOME (the default `~/.codex` topology). Other enterprise or
nested layouts stop as an unsafe/unsupported topology rather than being
rewritten or silently accepted.

This source flow is fresh-install-only. It stops before creating a directory or
building when the stable Ward binary already exists, because replacing that
path would immediately change any trusted Hook that references it. Update an
existing installation with the tagged transactional installer instead:

```sh
./install.sh --version vX.Y.Z
```

```powershell
.\install.ps1 -Version vX.Y.Z
```

```sh
set -eu

ward_bin="${CODEX_HOME:-$HOME/.codex}/ward/bin/ward"
if [ -e "$ward_bin" ] || [ -L "$ward_bin" ]; then
  printf '%s\n' 'Ward is already installed; use ./install.sh --version vX.Y.Z for a transactional update.' >&2
  exit 1
fi

go test ./...
go vet ./...

ward_dir=$(dirname "$ward_bin")
mkdir -p "$ward_dir"
ward_candidate=$(mktemp "$ward_dir/.ward-source-build.XXXXXX")
cleanup_source_build() {
  if [ -n "${ward_candidate:-}" ] && { [ -e "$ward_candidate" ] || [ -L "$ward_candidate" ]; }; then
    unlink "$ward_candidate" 2>/dev/null || :
  fi
}
trap cleanup_source_build 0
trap 'exit 1' 1 2 15

go build -o "$ward_candidate" ./cmd/ward
if ! ln "$ward_candidate" "$ward_bin"; then
  printf '%s\n' 'Ward appeared during the source build; the existing binary was preserved.' >&2
  exit 1
fi
unlink "$ward_candidate"
ward_candidate=

"$ward_bin" codex install --scope user --dry-run
"$ward_bin" codex install --scope user
```

PowerShell:

```powershell
$ErrorActionPreference = 'Stop'
$codexDir = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $HOME '.codex' }
$wardBin = Join-Path $codexDir 'ward\bin\ward.exe'
$existingWard = Get-Item -Force -LiteralPath $wardBin -ErrorAction SilentlyContinue
if ($null -ne $existingWard) {
    throw 'Ward is already installed; use .\install.ps1 -Version vX.Y.Z for a transactional update.'
}

$wardDir = Split-Path $wardBin
New-Item -ItemType Directory -Force -Path $wardDir | Out-Null
$wardCandidate = Join-Path $wardDir ('.ward-source-build-' + [guid]::NewGuid().ToString('N') + '.exe')
try {
    go build -o $wardCandidate ./cmd/ward
    if ($LASTEXITCODE -ne 0) { throw 'Ward source build failed.' }
    try {
        [System.IO.File]::Move($wardCandidate, $wardBin)
    }
    catch {
        throw 'Ward appeared during the source build; the existing binary was preserved.'
    }
}
finally {
    if (Test-Path -LiteralPath $wardCandidate) {
        Remove-Item -Force -LiteralPath $wardCandidate
    }
}

& $wardBin codex install --scope user --dry-run
if ($LASTEXITCODE -ne 0) { throw 'Ward integration dry run failed.' }
& $wardBin codex install --scope user
if ($LASTEXITCODE -ne 0) { throw 'Ward integration install failed.' }
```

If the dry run reports legacy sandbox settings, repeat it and the installation
with `--migrate-permissions` only after reviewing the permission change.

Remove the user-global integration and source-installed binary with the
repository-owned uninstaller. Audit state and its key are preserved.

```sh
./uninstall.sh
```

```powershell
.\uninstall.ps1
```

Tagged releases use the checksum-verifying `install.sh` or `install.ps1`.
Those installers activate compatible Core configuration automatically. When
legacy migration is required they leave the verified binary installed and
print exact dry-run and activation commands instead of changing permissions.

The first exact Hook definition requires Host trust unless the Host supplies a
managed trusted definition. Ward cannot verify that trust from `hooks.json`.
Ward keeps a
stable binary path and Hook definition so binary updates do not intentionally
create repeated Ward approval work.

## CLI

```text
ward --version
ward evaluate --input - --json

ward hook codex-pre-tool-use
ward hook codex-session-start

ward codex install --scope user [--migrate-permissions] [--dry-run]
ward codex uninstall --scope user [--dry-run]
ward doctor [--project PATH] [--json]

ward audit show [--project PATH] [--since DURATION] [--json]
ward audit verify [--project PATH] [--json]
ward audit stats [--project PATH] [--since DURATION] [--json]
ward audit repair [--project PATH] [--dry-run] [--json]
```

Legacy hook subcommands and `--profile baseline` are accepted only as hidden
transition inputs and are never installed or advertised.

Machine contracts remain `ward-request/v1`, `ward-decision/v1`,
`ward-audit-event/v1`, and `ward-doctor/v1`.

| Exit | Meaning |
| --- | --- |
| `0` | Command completed; a valid decision may still be deny or defer. |
| `1` | Runtime or operating-system failure. |
| `2` | Invalid CLI usage. |
| `3` | Malformed or unavailable machine input for direct CLI commands such as `ward evaluate`. |
| `4` | Reserved policy compatibility failure. |
| `5` | Audit storage, integrity, or repair failure. |
| `6` | Codex integration or Doctor health failure. |

Malformed event payloads delivered to recognized Hook commands are handled by
the adapter instead of exit `3`. Malformed `PreToolUse` input is silent, records
no audit event, returns the request to the Host permission flow, and exits `0`.
Malformed `SessionStart` input emits one bounded, redacted warning and exits `0`
unless writing that warning itself fails with runtime exit `1`. The hidden
legacy PermissionRequest and PostToolUse commands are silent exit-`0` no-ops.
Hook name or argument errors remain CLI usage exit `2`. These Hook semantics do
not turn malformed input into a Ward permission decision.

## Audit semantics

New runtime records are only attributable Pre `deny` and `error` attempts.
They are not proof that a tool executed. A defer does not open or mutate the
audit store.

`ward-audit-event/v1` remains a historical superset so older defer,
PermissionRequest, and Post records continue to verify and display. Ward never
rewrites those chains. Stored data excludes raw commands, patches, paths,
environment, output, transcripts, and secrets.

`ward audit repair` can only advance a stale signed head over an already
authenticated forward tail. Public pruning is excluded from v0.1; sparse event
volume and retention status are monitored before a crash-safe generation
format is justified.

## Rollout

Harness Toolkit may pin a reviewed development commit only as an
**Experimental** source module at `modules/security/ward`. That pin neither
installs Ward nor proves any release gate.

`v0.1.0-rc.1` remains blocked until actual trusted Codex Hook dispatch plus
macOS, Linux/WSL, and native Windows permission-profile E2E
pass and twenty real Tasks complete with zero Ward-added prompts, zero
destructive or protected-secret escapes, zero unresolved normal-workflow false
deny, zero defer audit mutations, and zero need to disable Ward.

See [CHARTER.md](CHARTER.md), [SECURITY.md](SECURITY.md),
[docs/codex-integration.md](docs/codex-integration.md), and
[RELEASING.md](RELEASING.md).
