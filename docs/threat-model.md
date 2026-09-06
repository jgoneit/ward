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
emit no permission decision and are not persisted by Ward. SessionStart reports
structural installation health without turning an operational problem into a
new approval bottleneck.

The native control boundary is bounded. Ward protects dedicated immediate
anchors, but does not freeze every ancestor of HOME. When the current project
can relocate a control or state anchor, Doctor reports it and SessionStart
warns; Ward does not claim full relocation protection for that topology.

Root-only secret rules deliberately permit nested artifact cleanup on every
platform. Nested secret confidentiality and repository/worktree lifecycle
permissions remain the user's and Host's responsibility.

Ward does not store Hook requests, decisions, paths, or identifiers. Codex owns
its transcript and denial UI and may show or retain the original request.
