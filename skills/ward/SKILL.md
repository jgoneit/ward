---
name: ward
description: Diagnose Ward installation and audit integrity, inspect privacy-preserving Ward decision events, or explain why Ward denied or deferred a Codex tool request. Use for explicit Ward status, doctor, audit, policy explanation, install, or uninstall requests. Do not use it to approve access or as a replacement for the Host permission model.
---

# Ward

Ward is a veto-only guardrail. Treat `defer` as no Ward decision, never as an
allow. The Host's current permission profile, sandbox, and approval policy stay
authoritative.

## Start safely

For status, explanation, review, or audit requests, run read-only checks first:

1. Locate `ward` and run `ward --version`.
2. Determine whether the Host already provides an execution path outside the
   guarded project sandbox. Do not create a new approval step for Ward.
3. Only through that already-authorized Host path, run `ward doctor --project
   <current-project> --json`.
4. If audit evidence is relevant, use the same path for `ward audit verify
   --project <current-project> --json` before `ward audit show` or `ward audit
   stats`.

An ordinary guarded tool process intentionally cannot read Ward's denied
`config.toml`, `hooks.json`, policy, or audit state. If no Host-side diagnostic
path is already available, report Doctor and audit as `Not run (trusted Host
execution required)` and give the user the exact local-terminal command. Do
not call the resulting `EPERM` an unhealthy Ward installation, request weaker
permissions, or bypass the native profile.

Report `PASS`, `FAIL`, and `Not run` separately. Do not infer enforcement from
the Plugin being present; the native profile and user-global hooks must both be
verified.

Treat the native boundary as bounded. Codex cannot currently combine a broad
`.env.*` deny with exact public-template exceptions, so Doctor must report
arbitrary `.env.<custom>` suffixes as a hook-dependent coverage gap. Also
surface the credential-broker warning when native SSH-key or credential-store
denies may interrupt ordinary authentication workflows. Treat a failed
environment-resolved credential-path check or control-file authority check as
an open security gate; also surface `permissions.credential_topology` when a
file-valued override has a relocatable ancestor inside the project being
diagnosed. Surface `permissions.state_topology` under the same project-scoped
condition. Do not suggest bypassing these checks or weakening file modes.

## Explain decisions

- `deny`: cite the stable rule ID and its static reason. Never echo raw tool
  input, paths, patches, environment variables, or secret material.
- `defer`: explain that Ward added no prompt and made no access decision. The
  Host chose whether to execute, ask, or reject.
- `error`: explain that the Codex adapter converts evaluator integrity failure
  to a static deny, while hook absence or timeout remains a Host coverage gap.

Do not call a Pre event an execution log. Only describe a matching Post event
as `post_observed`, which does not prove success.

## Mutation boundary

Never install, uninstall, migrate permissions, prune or repair audit data, or
edit Codex configuration during a diagnostic or explanation request. Perform
those operations only when the user explicitly requests the matching change.
Show a dry run first when supported. Preserve `approval_policy` exactly and
require an explicit `--migrate-permissions` choice before replacing a legacy
`sandbox_mode` setting.

Ward must never output `permissionDecision: allow` or `ask`, create a separate
approval step, or suggest disabling Ward to finish ordinary development work.
