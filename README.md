# Ward

Ward is an ambient, veto-only Codex safety kernel. It blocks a small set of
high-confidence destructive actions, installs a bounded native boundary for
reviewed workspace secret names, and otherwise leaves the Host's permission
flow alone.

Ward is under v0.1 development. It is not an unbypassable sandbox and has not
passed its release burn-in.

## Product contract

A user-global Core installation has two fixed responsibilities:

1. veto supported high-confidence destructive actions before Host permission
   handling;
2. install a native permission profile for a reviewed secret-name set and Ward
   control state.

```text
tool request
    |
    v
  Ward
    |-- high-confidence destruction --> deny; no persistent Hook write
    |-- evaluator error -------------> no Ward decision; Host decides
    \`-- everything else ------------> no output; Host decides
```

`defer` is not an allow. Ward never emits `allow`, `ask`, input replacement, or
an additional approval step. Deny, defer, and evaluator error create no
persistent Ward record. The ordinary path makes no model call, produces no
model-visible bytes, and performs no persistent Hook write.

## What v0.1 denies

- recursive deletion of a filesystem root, the actual user home, or an
  ancestor containing the actual home;
- direct deletion or relocation of `.git`, its internal paths and physical aliases;
- deletion or relocation of Ward control and integration-state paths or their
  containing directories;
- `git reset --hard`, forced directory clean, force/mirror/forced-refspec push.

Ordinary file and directory deletion, temporary CWD and repository cleanup,
worktree creation/removal, normal patch deletion, `--force-with-lease`, SQL and
infrastructure operations (including database/schema deletion and resource
teardown), interactive shells, secret-reading commands, dynamic expressions,
and unknown tools defer to the
Host in any environment. Ward does not classify environments or prove these
operations safe. Ambiguity is never promoted to a deny.

Parent-removal options still deny when they reach HOME or a filesystem root.

## Codex integration

Ward installs exactly two user-global command hooks:

| Event | Behavior |
| --- | --- |
| `SessionStart` | Check installation health on startup, resume, and clear. Healthy is silent; unhealthy emits only bounded check IDs. |
| `PreToolUse` | Classify only reviewed shell, patch, delete, and move tool names before the Host permission flow. |

The Pre matcher comes from one canonical tool-name list and never uses `*`. Its
timeout is two seconds. Ward does not install PermissionRequest or PostToolUse
hooks and does not emit normal-path status or context.

Current Codex command hooks cannot start a separate Agent. The current Agent
handles a Ward denial by choosing a scoped, recoverable alternative without
asking the user when no new authority is needed. The Plugin and Skill provide
that recovery and explicit management UX; they are not enforcement boundaries.

A newly written user Hook is not active until Codex trusts that exact
definition. Ward cannot read or approve the Host's trust decision. Doctor
therefore reports Hook trust as unverified, and installation reports
"configured" rather than claiming activation. Hosted, specialized, disabled,
untrusted, managed-hooks-only, or timed-out paths may bypass the Hook.

See [Codex Hooks](https://learn.chatgpt.com/docs/hooks) and
[Codex Permissions](https://learn.chatgpt.com/docs/permissions).

## Native secret boundary

The `ward` permission profile protects a deliberately small set immediately
below each Host-effective workspace root on every supported platform:

- `.env` and reviewed local/development/test/production/staging/secret suffixes;
- `*.key.json` and exact key, credentials, and service-account JSON basenames;
- exact `secrets` and `credentials` YAML basenames;
- canonical SSH/private-key basenames and reviewed private-key PEM basenames;
- `*.p12` and `*.pfx`.

These rules deny reads. Wildcard matches do not guarantee write protection:
Codex 0.147.0 on macOS permits overwriting `*.key.json`, `*.p12`, and `*.pfx`
in both the previous recursive and current root-only profiles. Exact filename
write denials are checked separately. See the [Codex configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference).

Public templates (`.env.example`, `.env.sample`, `.env.template`, `.env.dist`),
arbitrary custom `.env.*` suffixes, and generic PEM/YAML/key names remain outside
this set. Nested files, including the same secret names and HOME credential
stores in subdirectories, are deliberately outside Ward's native secret
boundary. Ward does not discover or register them automatically. A nested
directory explicitly added as a Host workspace root receives the same direct
root rules.

The installer preserves `approval_policy`. It accepts only the current Codex
permission-profile configuration, inherits a safe modern parent, and stops on
unsupported authority instead of guessing or rewriting it. With no active
profile the parent is `:workspace`.

Ward separately protects dedicated control/state anchors and reports a
SessionStart health warning when the active project topology can relocate them.
It does not freeze the entire home directory.

## Build and install from source

Requirements: Go 1.25 or newer.

The v0.1 installer supports an absolute `CODEX_HOME` that is a direct child of
the actual user HOME, including the default `~/.codex`. Other enterprise or
nested layouts stop as unsupported instead of being rewritten.

This source flow is fresh-install-only. It stops before building when the
managed Ward binary already exists. Update an existing installation with the
tagged transactional installer:

```sh
./install.sh --version vX.Y.Z
```

```powershell
.\install.ps1 -Version vX.Y.Z
```

For a fresh POSIX source install:

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

Remove the user-global integration and source-installed binary with the
repository-owned uninstaller:

```sh
./uninstall.sh
```

```powershell
.\uninstall.ps1
```

Tagged releases use checksum-verifying installers. The first exact Hook
definition still requires Host trust unless the Host supplies a managed trusted
definition. Ward keeps a fixed binary path and Hook definition so binary
updates do not intentionally create repeated trust work.

## CLI

```text
ward --version

ward hook codex-pre-tool-use
ward hook codex-session-start

ward codex install --scope user [--dry-run]
ward codex uninstall --scope user [--dry-run]
ward doctor [--project PATH] [--json]
```

Doctor JSON follows the retained
[`ward-doctor/v1`](contracts/ward-doctor-v1.schema.json) contract. The safe
PreToolUse process budget is p95 50 ms on POSIX and 100 ms on Windows, below
the two-second Hook timeout.

Install also refreshes an intact journal-owned profile; Doctor flags an older
recursive profile as unhealthy. Dry-run writes nothing; an up-to-date rerun is a
no-op. See the [ownership contract](docs/codex-integration.md#installation-ownership).

Malformed input delivered to `codex-pre-tool-use` is silent, makes no Ward
permission decision, and exits `0`. Malformed SessionStart input emits one
bounded redacted warning and exits `0` unless writing the warning fails. Hook
name or argument errors remain CLI usage errors.

## Rollout

Harness Toolkit may pin a reviewed development commit only as an
**Experimental** source module at `modules/security/ward`. That pin neither
installs Ward nor proves a release gate.

`v0.1.0-rc.1` remains blocked until trusted Codex Hook dispatch plus macOS,
Linux/WSL, and native Windows permission-profile E2E pass and twenty real Tasks
complete with zero Ward-added prompts, zero destructive or protected-secret
escapes, zero unresolved normal-workflow false deny, zero persistent Hook
writes, and zero need to disable Ward.

See [CHARTER.md](CHARTER.md), [SECURITY.md](SECURITY.md),
[docs/codex-integration.md](docs/codex-integration.md), and
[RELEASING.md](RELEASING.md).
