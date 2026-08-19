# Releasing Ward

No release may skip the acceptance gates in this file.

## RC entry gate

- Isolated install, reinstall, uninstall, and doctor tests pass on macOS,
  Linux/WSL, and native Windows.
- Ward-added prompt count is zero and duplicate approval prompts are zero.
- Secret access and catastrophic destruction fixtures have zero escapes.
- Normal workflows have zero unresolved false deny.
- Raw commands, paths, outputs, and canary secrets are absent from audit files.
- Audit chain verification and Doctor have zero false PASS.
- Cross-platform retention pruning uses a crash-safe generation contract;
  preview-only or disabled mutation is not RC-complete.
- Twenty real Tasks finish without disabling Ward or asking a human to perform
  ordinary development work in Ward's place.
- Guarded Plugin sessions report unavailable privileged diagnostics as `Not
  run`, while the same Doctor and audit checks pass from a trusted Host-side or
  local-terminal path.
- A reviewed Host-side management capability makes Doctor and audit available
  to the Plugin without weakening protected paths or adding a Ward-specific
  prompt. Requiring the user to relay routine diagnostics from a terminal is
  not RC-complete.

Only then may `v0.1.0-rc.1` be created. Toolkit integration pins the reviewed
release commit by exact Git SHA; it never follows a branch.
