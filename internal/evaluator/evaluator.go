// Package evaluator applies Ward policy to canonical pre-tool requests.
package evaluator

import (
	"errors"
	"path"
	"strings"

	"github.com/jgoneit/ward/internal/contract"
	"github.com/jgoneit/ward/internal/policy"
)

const (
	deferReason = "Ward did not veto this request; host policy remains authoritative."
	gapReason   = "Ward could not safely classify this request; host policy remains authoritative."

	secretReason         = "Protected secret path access is denied."
	destructiveFSReason  = "Catastrophic filesystem deletion is denied."
	destructiveGitReason = "Destructive version-control operation is denied."
	destructiveDBReason  = "Explicit destructive database operation is denied."
	destructiveOpsReason = "Explicit destructive infrastructure operation is denied."
	additiveReason       = "Command is denied by additive Ward policy."
)

// Evaluator is deterministic and performs no filesystem or network I/O.
type Evaluator struct {
	policy       policy.Policy
	commandRules []policy.CommandRule
}

// New constructs an evaluator from a policy created by the policy package.
func New(active policy.Policy) (*Evaluator, error) {
	if !active.Valid() {
		return nil, errors.New("invalid Ward policy")
	}
	return &Evaluator{policy: active, commandRules: active.CommandRules()}, nil
}

// Evaluate returns deny, defer, or error. A defer is not permission to run;
// the host's sandbox, approval, and permission layers remain authoritative.
func (e *Evaluator) Evaluate(req contract.Request) contract.Decision {
	if e == nil || !e.policy.Valid() {
		return contract.ErrorDecision("evaluator_unavailable", "Ward evaluator is unavailable.")
	}
	if err := contract.ValidateRequest(req); err != nil {
		return contract.ErrorDecision("invalid_request", "Canonical Ward request is invalid.")
	}

	tool := strings.ToLower(strings.TrimSpace(req.Tool))
	var result scanResult
	switch tool {
	case "bash", "sh", "zsh", "shell", "exec_command", "unified_exec":
		if strings.TrimSpace(req.Input.Command) == "" {
			result.gap = gap("missing_command", "A shell request has no normalized command.")
		} else {
			result = e.evaluatePOSIX(req.Input.Command, req.CWD, 0)
		}
	case "apply_patch":
		result = e.evaluatePatch(req.Input.Command, req.CWD)
	case "powershell", "pwsh":
		result = e.evaluatePowerShell(req.Input.Command, req.CWD)
	case "cmd", "cmd.exe":
		result = e.evaluateCMD(req.Input.Command, req.CWD)
	default:
		if isStructuredFilesystemTool(tool) {
			result = e.evaluateStructuredPaths(tool, req.Input, req.CWD)
		} else {
			result.gap = gap("unsupported_tool", "This tool does not have a Ward evaluator yet.")
		}
	}
	if result.deny != nil {
		return *result.deny
	}
	if result.gap != nil {
		return contract.DeferWithGap(gapReason, result.gap.Code, result.gap.Detail)
	}
	return contract.Defer(deferReason)
}

func isStructuredFilesystemTool(tool string) bool {
	switch tool {
	case "read", "write", "edit", "read_file", "read_text_file", "read_media_file", "read_multiple_files",
		"write_file", "edit_file", "multi_edit", "delete_file", "move_file", "copy_file",
		"search_files", "view_image", "grep", "glob",
		"mcp__filesystem__read_file", "mcp__filesystem__read_text_file",
		"mcp__filesystem__read_media_file", "mcp__filesystem__read_multiple_files",
		"mcp__filesystem__write_file", "mcp__filesystem__edit_file",
		"mcp__filesystem__move_file", "mcp__filesystem__copy_file",
		"mcp__filesystem__delete_file", "mcp__filesystem__search_files":
		return true
	default:
		return false
	}
}

func (e *Evaluator) evaluateStructuredPaths(tool string, input contract.Input, cwd string) scanResult {
	result := scanResult{}
	paths := input.Paths
	if len(paths) == 0 {
		result.gap = gap("missing_structured_path", "A filesystem tool request has no normalized path.")
		return result
	}
	moveOperation := isStructuredMoveTool(tool)
	if moveOperation && (input.SourcePath == "" || input.DestinationPath == "") {
		result.addGap(gap("missing_structured_move_roles", "A move request does not preserve both source and destination roles."))
	}
	for _, candidate := range paths {
		if isDynamicPath(candidate) {
			result.addGap(gap("dynamic_path", "A structured path still contains unresolved expansion syntax."))
			continue
		}
		deleteOperation := isStructuredDeleteTool(tool)
		moveSource := moveOperation && input.SourcePath != "" && candidate == input.SourcePath
		var ruleID string
		var protected bool
		ruleID, protected = e.matchProtectedPath(candidate, cwd, deleteOperation || moveSource)
		if protected {
			return denied(ruleID, secretReason)
		}
		if isStructuredDeleteTool(tool) &&
			(isProtectedDeleteTarget(candidate) || isCatastrophicStructuredTarget(candidate, cwd)) {
			return denied("WARD_DESTRUCTIVE_FILESYSTEM", destructiveFSReason)
		}
	}
	return result
}

// matchProtectedPath first preserves policy matching against the literal tool
// input, then resolves a relative literal against the request CWD. Runtime
// exact paths are absolute by construction; without this second comparison a
// command issued from its parent directory could bypass the same exact anchor.
// No environment variables, symlinks, or filesystem state are resolved here.
func (e *Evaluator) matchProtectedPath(candidate, cwd string, includeAncestors bool) (string, bool) {
	match := e.policy.MatchProtectedPath
	if includeAncestors {
		match = e.policy.MatchProtectedPathOrAncestor
	}
	if ruleID, protected := match(candidate); protected {
		return ruleID, true
	}
	resolved := resolveLiteralPath(candidate, cwd)
	if resolved == "" || resolved == candidate {
		return "", false
	}
	return match(resolved)
}

func resolveLiteralPath(candidate, cwd string) string {
	value := strings.TrimSpace(strings.ReplaceAll(candidate, `\`, "/"))
	base := strings.TrimSpace(strings.ReplaceAll(cwd, `\`, "/"))
	if value == "" || base == "" || strings.ContainsAny(value, "\x00\r\n") ||
		path.IsAbs(value) || isWindowsAbsolutePath(value) || strings.HasPrefix(value, "~/") || value == "~" {
		return ""
	}
	// Drive-relative paths (C:secret) depend on per-drive process state and are
	// deliberately left as a coverage gap rather than guessed from request CWD.
	if len(value) >= 2 && value[1] == ':' {
		return ""
	}
	if !path.IsAbs(base) && !isWindowsAbsolutePath(base) {
		return ""
	}
	return path.Clean(path.Join(base, value))
}

func isStructuredMoveTool(tool string) bool {
	return tool == "move_file" || tool == "mcp__filesystem__move_file"
}

func isStructuredDeleteTool(tool string) bool {
	return tool == "delete_file" || tool == "mcp__filesystem__delete_file"
}

func isCatastrophicStructuredTarget(candidate, cwd string) bool {
	normalized := strings.ReplaceAll(strings.TrimSpace(candidate), `\`, "/")
	if isWindowsAbsolutePath(normalized) || isWindowsAbsolutePath(strings.ReplaceAll(cwd, `\`, "/")) {
		return hasCatastrophicWindowsTarget([]string{candidate}, cwd)
	}
	return isCatastrophicTarget(candidate, cwd)
}

type scanResult struct {
	deny *contract.Decision
	gap  *contract.CoverageGap
}

func denied(ruleID, reason string) scanResult {
	decision := contract.Deny(ruleID, reason)
	return scanResult{deny: &decision}
}

func gap(code, detail string) *contract.CoverageGap {
	return &contract.CoverageGap{Code: code, Detail: detail}
}

func (r *scanResult) addGap(candidate *contract.CoverageGap) {
	if r.gap == nil && candidate != nil {
		r.gap = candidate
	}
}

func (r *scanResult) merge(other scanResult) {
	if r.deny != nil {
		return
	}
	if other.deny != nil {
		r.deny = other.deny
		return
	}
	r.addGap(other.gap)
}

func isDynamicPath(value string) bool {
	return strings.ContainsAny(value, "$%*?[]{}\x60")
}
