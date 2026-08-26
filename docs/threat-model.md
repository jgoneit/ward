# Threat model

## Protected assets

- reviewed high-confidence workspace secret names;
- repository metadata and Ward control/integration-state paths;
- filesystem, home, current-work, and repository roots;
- Git state, databases, schemas, namespaces, and volumes targeted by a small
  literal destructive-command set.

## In scope

- user-global SessionStart health and PreToolUse command hooks;
- Codex native filesystem permissions;
- literal high-confidence POSIX, PowerShell/CMD, patch, and structured
  operations.

## Outside v0.1

- hosted or specialized tools not delivered to Ward;
- arbitrary custom secret names outside the minimal native profile;
- ambiguous scripts, aliases, dynamic expressions, or proving a command safe;
- kernel, mount, hard-link, symlink race, TOCTOU, and same-user total compromise;
- session-profile overrides or a user disabling/untrusting the Hook;
- HOME used as the active workspace, and reviewed secret names deeper than the
  configured 16-level native glob expansion bound;
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

The minimal workspace Secret profile cannot reopen HOME credential stores
after a recursive workspace deny on current Codex. Ward therefore supports
ordinary project-subdirectory workspaces and reports HOME-as-workspace as an
unsupported topology instead of claiming both properties simultaneously.

Ward does not store Hook requests, decisions, paths, or identifiers. Codex owns
its transcript and denial UI and may show or retain the original request.
