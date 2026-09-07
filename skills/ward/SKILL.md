---
name: ward
description: Recover safely from a Ward WARD_* denial, explain a Ward session-health warning, or perform explicitly requested Ward status, doctor, install, uninstall, or local diagnostics management. Do not invoke for ordinary deferred tool requests or use Ward to grant access.
---

# Ward

Ward is an ambient veto-only guardrail. `defer` means Ward made no decision;
the Host's existing permission profile, sandbox, and approval policy remain
authoritative.

## Respond only when Ward is relevant

- On a `WARD_*` denial, cite only the stable rule ID and static reason. Choose
  the narrowest recoverable alternative and retry it without asking the user
  when that retry stays within the original task and needs no new authority.
- On a Ward session-health warning, explain the reported check IDs. Do not
  weaken permissions or disable Ward. Use a deeper Doctor flow only when the
  user asks or the warning blocks the requested work.
- On an ordinary `defer`, do nothing: do not invoke this Skill, run Doctor,
  add an approval prompt, or describe Ward to the user.

Never reflect raw commands, patches, paths, environment variables, output, or
secret material from a denial. Do not repeat a blocked destructive request in
a different spelling merely to evade the rule.

## Diagnose through a trusted path

Plugin presence does not prove that the user-global Core, SessionStart hook,
PreToolUse hook, or native permission profile is active. For an explicit
status or Doctor request:

1. Locate `ward` and run `ward --version`.
2. Prefer the redacted SessionStart health result already supplied by the Host.
3. Run `ward doctor --project <current-project> --json` only through an
   already-authorized Host path or trusted local terminal.

An ordinary guarded tool process intentionally cannot read Ward's protected
control or integration state. If no trusted execution path exists, report the
check as `Not run (trusted Host execution required)` and provide the exact
terminal command. Do not reinterpret `EPERM` as an unhealthy installation or
request weaker permissions. Report `PASS`, `FAIL`, and `Not run` separately.

## Explain the narrow contract

- `deny`: a high-confidence destructive rule matched. Ward emits only the
  canonical denial and performs no persistent Hook write.
- `defer`: Ward emits no output, performs no persistent Hook write, and adds no
  prompt.
- `error`: Ward emits no permission decision and defers to the Host. It emits no
  output and performs no persistent Hook write.

The native profile protects reviewed secret names immediately below each Host
workspace root, plus Ward control state. Nested secrets, custom `.env.*`
suffixes, generic PEM/YAML, and HOME credential stores in subdirectories are
outside this boundary. Ward does not discover or register nested secrets.
Native glob rules deny reads; do not claim write protection for wildcard secret
names. Exact filename write denials are checked separately.
Temporary CWD and repository cleanup defer unless a retained protected boundary
matches. Direct `.git` paths and aliases, actual HOME, filesystem roots, Ward
control paths, and destructive Git commands remain protected. Hosted or unknown
tools not delivered to Ward remain outside the Hook boundary.

Treat `hooks.trust` as unverified until the Host has trusted the exact Hook
definition. Never describe installation or Plugin presence alone as active
enforcement.

## Optional local diagnostics

Only manage diagnostics when explicitly requested. `ward diagnostics status
--json` is read-only; `enable` and `disable` support `--dry-run` and require the
same trusted local management path as installation. Never enable collection
in response to an ordinary defer or use diagnostic records to grant permission.

The Hook process remains persistence-free. An explicitly enabled separate
collector can store redacted PreToolUse events on the local machine. Missing
records do not prove a defer or a successful tool call. `not_evaluated` is an
input-processing failure, distinct from an evaluator error. Correlation IDs
and authenticated local delivery do not prove trusted Host origin or complete
coverage. Never request, display, or inspect collector keys or raw descriptors.

Disable preserves logs and Ward protection. Repeated enable refreshes the
separate collector binary when its digest differs; updating Core alone does
not prove the collector was updated. Report service registration, readiness,
and actual Host collection separately. Unsupported service environments are
not a reason to weaken permissions or install a privileged service.

## Mutation boundary

Never install or uninstall Core during a health explanation or read-only
diagnostics request. Perform those mutations only when the user explicitly
requests them. Show a dry run
when supported, preserve `approval_policy` exactly, and stop on unsupported
Host permission configuration instead of rewriting it.

Install refreshes intact journal-owned profiles; it rejects modified or
duplicate managed areas. After applying it, verify permissions and actual cleanup
in a fresh Host session. Core `defer` does not prove native `EPERM` is resolved.

Ward must never output `permissionDecision: allow` or `ask`, create a separate
approval step, or suggest disabling Ward to finish ordinary development work.
