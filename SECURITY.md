# Security policy

Ward is a defense-in-depth guardrail. It is not an unbypassable sandbox.
Codex hooks do not observe every hosted or specialized tool path, and a hook
that is absent, disabled, timed out, or untrusted cannot veto a call. Native
Host permissions are therefore the actual boundary for paths the Host policy
can represent. Ward does not claim that hooks turn an unrepresentable path into
an unbypassable boundary.

## Supported claims for v0.1

- Ward can install and diagnose a Codex user-global hook configuration and a
  bounded native permission profile.
- For supported hook payloads, Ward denies narrow, high-confidence secret and
  catastrophic operations and otherwise defers.
- Ward stores privacy-preserving decision metadata in an HMAC-chained audit
  log without raw commands, patches, paths, environment variables, output, or
  secret values.

HMAC chaining detects modification while the installation key remains
trusted. It does not stop a process with the user's full filesystem authority
from replacing both the key and the log. It also cannot distinguish replay of
an older, internally valid state snapshot without an external monotonic
anchor.

Codex deny globs cannot currently be reopened by exact public-template rules.
To keep `.env.example`, `.env.sample`, `.env.template`, and `.env.dist` usable,
the native profile denies exact `.env` and reviewed common sensitive suffixes
instead of all `.env.*` names. A supported Ward hook still vetoes an arbitrary
`.env.<custom>` request, and Doctor reports the native coverage gap.

Native denies for SSH keys and credential stores can also interrupt tools that
read credentials directly. Ward reports this as a burn-in warning; an OS
keychain, `ssh-agent`, or equivalent broker is the preferred workflow.

Ward snapshots supported environment-selected credential paths into exact
native denies during installation. Doctor requires reinstall when the active
path set changes. The installer refuses symlinked or locally writable Codex
control files rather than silently rewriting their ownership or permissions.
The native profile makes the direct `CODEX_HOME` control root and narrow
credential anchors read-only. Ward rejects a control root nested inside a
project. Arbitrary file-valued overrides and directory overrides with a
writable higher ancestor inside the project being diagnosed keep an explicit
Doctor warning rather than making a potentially broad project tree read-only;
ancestor relocation there remains a documented release blocker for that
project. Nested user configuration outside the current workspace is not
treated as writable merely because it is below the user home.

## Reporting

Do not open a public issue containing a credential, private path, command
payload, transcript, or audit key. Use GitHub's private vulnerability reporting
for the repository when it is enabled.
