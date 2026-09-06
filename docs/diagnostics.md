# Local diagnostics

Ward can collect its own PreToolUse results in an opt-in, per-user local
collector. Enable it from the trusted Host management path after reviewing the
binary and the dry run:

```sh
ward diagnostics enable --dry-run
ward diagnostics enable
ward diagnostics status --json
ward diagnostics disable --dry-run
ward diagnostics disable
```

`enable` checks the service environment and existing ownership before making
changes, installs a real `ward-diagnostics` (`.exe` on Windows) copy beside Core,
registers the per-user service, starts it, and checks authenticated readiness.
Repeating it with the same binary and a ready service is a no-op. After upgrading
Core, run `enable` again to update the collector. Equality is determined by the
binary SHA-256, including builds that share a version string. The separate copy
keeps a running Windows collector from locking the main Ward executable.

`disable` stops the collector and removes only its owned registration, copy,
manifest, and runtime descriptor after confirming termination. Logs remain.
Disabling diagnostics leaves Ward's protection enabled. Ward uninstall first
disables diagnostics; it retains Core when service removal cannot be confirmed.
An ownership conflict requires restoring the known files before retrying. Ward
does not overwrite another service or a changed owned file.

## Login scope

| Platform | Registration | Availability |
| --- | --- | --- |
| macOS | User LaunchAgent | While logged in; restarted after failure |
| Linux | systemd user service | While the user manager runs; no linger setup |
| Windows | Current-user logon scheduled task | While logged in; no administrator account, execution time limit, or battery stop condition |

On Windows, registration and logon triggers repeat every minute with
`IgnoreNew`, so a running collector is not duplicated and a stopped collector
can start again. Registration starts this recovery schedule for the current
login; the logon trigger starts it after later logins. This supplements Task
Scheduler's failure retries, which did not recover a terminated collector in
native testing. Recovery can leave a gap of a minute or longer under scheduler
load. Disabling the task stops repetition before process and file cleanup.
Rollback suppresses registration-trigger execution when restoring a previously
stopped task.

Linux requires an available systemd user manager and `busctl` with JSON output.
The unit directory is `${XDG_CONFIG_HOME:-~/.config}/systemd/user`; preflight
verifies that the running manager actually searches that directory. WSL
collection is limited to the distribution's running lifetime. Unsupported environments fail preflight
without partially installing a service. No system service or collection before
login is installed. `ward diagnostics serve` is the foreground collector entry
point used by the service manager. The registration fixes absolute state, home,
and Core binary paths so login environment differences cannot redirect them.

## Records and privacy

Each JSONL row has schema `ward-diagnostic-record/v1`, a collector receipt time,
generation and sequence, and a `ward-diagnostic-event/v1` event. Its allowed
fields are Ward version, normalized tool kind, processing stage, Ward outcome,
static rule/error/coverage-gap codes, processing microseconds, and optional
`session_id`, `turn_id`, and `tool_use_id`. IDs are bounded ASCII identifiers;
invalid or absent IDs are JSON `null` and do not affect policy. Unknown tools
use `unknown`. Input failures use `not_evaluated`, separately from evaluator
errors and actual `defer`/`deny` results.

Commands, patches, paths, environment values, prompts, raw error messages, and
tool outputs are excluded at the sender and rejected at the receiver. There is
no remote transmission, hostname, custom server, dashboard, or transcript read.
The receiver validates the versioned field allowlist and authenticates every
packet with HMAC. A protected runtime descriptor contains an ephemeral port,
generation, and key; status never prints the key. Transport uses only IPv4
`127.0.0.1` UDP on all three platforms.

These are best-effort observations of Ward's own handler. They do not prove that
the Host ran a Hook or tool, accepted a request, or denied native access. Missing
records have no inferred meaning. IDs are correlation hints, not trusted
identities; a process that can read the collector key can forge a local event.
This is not a tamper-proof or complete audit trail.

## Bounded collection

The evaluator runs once. After determining the existing policy output, the Hook
starts one diagnostic goroutine and waits at most a 5 ms timer budget. Slow I/O
does not keep the Hook process alive. OS scheduling can extend observed elapsed
time. The worker emits at most one datagram, without child processes, retries,
acknowledgement waits, extra stdout/stderr, or persistent writes. The collector
alone writes the log. Diagnostic loss cannot change a Ward decision.

Datagrams are limited to 4 KiB and the collector's event queue to 256 records.
Queue overflow, malformed or unauthenticated packets, stopped collectors, and
storage failures lose records. Status reports received/dropped counters, storage
errors, heartbeat, readiness, log location, and whether the collector copy needs
updating. Counters are for the current collector generation; they are not the
total number of Hook calls. UDP losses before reception are uncounted.

| Platform | Log directory |
| --- | --- |
| POSIX | `${XDG_STATE_HOME:-~/.local/state}/ward/diagnostics` |
| Windows | `%LOCALAPPDATA%\Ward\state\diagnostics` |

Service ownership and runtime files live under Core's protected
`core/diagnostics` directory, separate from the existing integration journal.
Files use private permissions and reject links or unexpected ownership. JSONL
segments rotate before exceeding 1 MiB. The collector caps its recognized
segments at a total of 10 MiB and prunes those older than seven days at startup,
event writes, and heartbeat maintenance. Storage stalls can delay maintenance.
Unrelated files are not deleted. When the collector is disabled, retained logs
are not automatically pruned.

## Verification boundaries

Automated tests cover policy-output parity, input and evaluator failures,
metadata validation, canary exclusion, HMAC rejection, packet/queue bounds,
storage errors, rotation, stale descriptors, and service management fixtures.
`scripts/bench-pre-hook.go` measures absent, enabled, and unavailable collector
states against the existing POSIX 50 ms / Windows 100 ms p95 target. The Hook
integration timeout remains two seconds.

Native service registration, login restart, failure recovery, and a selected
Codex Hook must also be checked on each target platform before a release claims
that behavior. A synthetic payload or cross-compiled binary is not proof of a
live Host Hook. For a trusted Host smoke, record a harmless request's supplied
call identifiers, compare Ward's policy output with diagnostics disabled and
enabled, and correlate only the corresponding received event. Do not use a
destructive command or treat missing records as proof of a Host failure.

The opt-in `native_diagnostics` input on the CI workflow runs
`scripts/test-native-diagnostics.py` on actual macOS, Ubuntu, and Windows runners. It
requires a working user service environment; an unavailable systemd user
manager or interactive Windows task session fails the check and is recorded
in the JSON result. It does not enable linger, install a system service, or
elevate privileges. On Linux the temporary collector uses the existing user
unit directory, while its binary, Core state, and logs are isolated. Cleanup
uses Ward's ownership checks and retains the fixture if termination cannot be
confirmed.

For a native machine with the same prerequisites, run:

```sh
python scripts/test-native-diagnostics.py --candidate /absolute/path/to/ward --updated-candidate /absolute/path/to/ward-refresh --report /absolute/path/to/result.json
```

Use `.exe` binary paths on Windows. Both candidates must report the same Ward
version and have different SHA-256 hashes (for example, build the second with
`go build -ldflags=-buildid=ward-diagnostics-native-refresh`). The helper checks
actual service lifecycle and collector delivery using a direct Hook payload;
that payload remains a synthetic replay. CI does not prove a new user login,
Codex Hook dispatch or trust, or activation of the real user installation.
