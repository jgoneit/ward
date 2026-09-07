# Threat model

## Protected assets

- reviewed high-confidence secret names directly below each Host workspace root;
- directly targeted `.git` paths and aliases, and Ward control/integration-state paths;
- filesystem roots and the actual user home;
- Git state targeted by a small literal destructive-command set.

## In scope

- user-global SessionStart health and PreToolUse command hooks;
- Codex native filesystem permissions;
- literal high-confidence POSIX, PowerShell/CMD, patch, and structured
  operations.
- explicitly enabled local PreToolUse diagnostics and owned per-user collector
  services, independently of policy evaluation.

## Outside v0.1

- hosted or specialized tools not delivered to Ward;
- database/schema deletion and container, cluster, or infrastructure teardown;
- nested secrets and arbitrary custom secret names outside the minimal native
  profile, without automatic discovery or registration;
- write protection for wildcard-matched secret names; native glob rules deny reads;
- ambiguous scripts, aliases, dynamic expressions, or proving a command safe;
- kernel, mount, hard-link, symlink race, TOCTOU, and same-user total compromise;
- session-profile overrides or a user disabling/untrusting the Hook;
- automatic cleanup protection for CWD, repositories, worktrees, and their
  containing directories when no retained protected boundary matches;
- workflow approval, task state, reviewer verdicts, or a separate Agent;
- automatic authorization of any operation.

Runtime evaluator errors fail open to the Host by explicit product choice. They
emit no permission decision and the Hook process writes no persistent state.
An enabled collector may record a bounded error code. SessionStart reports
structural installation health without turning an operational problem into a
new approval bottleneck.

The native control boundary is bounded. Ward protects dedicated immediate
anchors, but does not freeze every ancestor of HOME. When the current project
can relocate a control or state anchor, Doctor reports it and SessionStart
warns; Ward does not claim full relocation protection for that topology.

Root-only secret rules deliberately permit nested artifact cleanup on every
platform. Nested secret confidentiality and repository/worktree lifecycle
permissions remain the user's and Host's responsibility.

Ward never stores original Hook requests or paths. The opt-in collector stores
only the reviewed diagnostic fields, including valid call identifiers, and
does not infer Host permission outcomes. Codex owns its transcript and denial
UI and may show or retain the original request.

The collector accepts bounded HMAC-authenticated packets on 127.0.0.1 only.
The key rotates on collector restart and is never logged or sent in plaintext.
This reduces accidental or cross-user injection; it does not authenticate a
Host against a same-user process that can read the key. Forgery by such a
process, replay, collector loss, and complete delivery are outside the diagnostic
claim. Missing records never count as a successful evaluation or tool execution.

The Hook waits at most five milliseconds for the diagnostic worker. Filesystem
reads are not themselves given a hard OS deadline; the process abandons the
worker rather than waiting indefinitely. The worker spawns no child process,
does not persist data, and never changes the policy stdout/stderr or exit code.
The collector alone handles queue limits, storage failure, retention, and user
service state. Data loss and stale health are exposed only on explicit status.
