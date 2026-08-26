---
name: ward
description: Recover safely from a Ward WARD_* denial, explain a Ward session-health warning, or perform an explicitly requested Ward status, doctor, install, or uninstall workflow. Do not invoke for ordinary deferred tool requests or use Ward to grant access.
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

The native profile protects a bounded set of high-confidence workspace secret
names plus Ward control state. It intentionally does not claim every custom
`.env.*` suffix, generic PEM/YAML, or HOME credential store. Recursive native
coverage is bounded to 16 levels where Codex pre-expands globs, and HOME itself
as the workspace is unsupported because workspace rules can overlap Host
credential stores. Surface `permissions.home_workspace_topology` without
suggesting weaker permissions. Hosted or unknown
tools that the Host does not send through Ward remain outside the Hook
boundary.

Treat `hooks.trust` as unverified until the Host has trusted the exact Hook
definition. Never describe installation or Plugin presence alone as active
enforcement.

## Mutation boundary

Never install or uninstall during a diagnostic or explanation request. Perform
those mutations only when the user explicitly requests them. Show a dry run
when supported, preserve `approval_policy` exactly, and stop on unsupported
Host permission configuration instead of rewriting it.

Ward must never output `permissionDecision: allow` or `ask`, create a separate
approval step, or suggest disabling Ward to finish ordinary development work.
