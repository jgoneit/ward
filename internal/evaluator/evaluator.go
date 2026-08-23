// Package evaluator applies Ward policy to canonical pre-tool requests.
package evaluator

import (
	"errors"
	"strings"

	"github.com/jgoneit/ward/internal/contract"
)

const (
	deferReason = "Ward did not veto this request; host policy remains authoritative."
	gapReason   = "Ward could not safely classify this request; host policy remains authoritative."

	destructiveFSReason  = "Catastrophic filesystem deletion or relocation is denied."
	destructiveGitReason = "Destructive version-control operation is denied."
	destructiveDBReason  = "Explicit destructive database operation is denied."
	destructiveOpsReason = "Explicit destructive infrastructure operation is denied."
)

// Evaluator is deterministic and performs no filesystem or network I/O.
type Evaluator struct {
	boundaries BoundarySet
}

// New constructs a request-scoped evaluator from immutable trusted boundaries.
func New(boundaries BoundarySet) (*Evaluator, error) {
	if !boundaries.valid {
		return nil, errors.New("invalid Ward boundary set")
	}
	return &Evaluator{boundaries: boundaries}, nil
}

// Evaluate returns deny, defer, or error. A defer is not permission to run;
// the host's sandbox, approval, and permission layers remain authoritative.
func (e *Evaluator) Evaluate(req contract.Request) contract.Decision {
	if e == nil || !e.boundaries.valid {
		return contract.ErrorDecision("evaluator_unavailable", "Ward evaluator is unavailable.")
	}
	if err := contract.ValidateRequest(req); err != nil {
		return contract.ErrorDecision("invalid_request", "Canonical Ward request is invalid.")
	}
	if !e.boundaries.validFor(req.CWD) {
		return contract.ErrorDecision("boundary_mismatch", "Ward boundary context does not match the request.")
	}

	tool := strings.ToLower(strings.TrimSpace(req.Tool))
	var result scanResult
	switch tool {
	case "bash", "sh", "zsh", "shell", "exec_command", "unified_exec":
		if strings.TrimSpace(req.Input.Command) == "" {
			result.gap = gap("missing_command", "A shell request has no normalized command.")
		} else if e.boundaries.goos == "windows" {
			result = e.evaluateCanonicalWindowsShell(req.Input.Command, req.CWD)
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

func (e *Evaluator) evaluateCanonicalWindowsShell(command, cwd string) scanResult {
	results := []scanResult{
		e.evaluatePowerShell(command, cwd),
		e.evaluateCMD(command, cwd),
		e.evaluatePOSIX(command, cwd, 0),
	}
	allAmbiguous := true
	var firstGap *contract.CoverageGap
	for _, candidate := range results {
		if candidate.deny != nil {
			return candidate
		}
		if candidate.gap == nil {
			allAmbiguous = false
		} else if firstGap == nil {
			firstGap = candidate.gap
		}
	}
	if allAmbiguous {
		return scanResult{gap: firstGap}
	}
	return scanResult{}
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
	deleteOperation := isStructuredDeleteTool(tool)
	for _, candidate := range paths {
		if isDynamicPath(candidate) {
			result.addGap(gap("dynamic_path", "A structured path still contains unresolved expansion syntax."))
			continue
		}
		moveSource := moveOperation && input.SourcePath != "" && candidate == input.SourcePath
		if deleteOperation && e.boundaries.protectsCriticalMetadata(candidate) || moveSource && e.boundaries.protectsCriticalRelocation(candidate) {
			return denied("WARD_DESTRUCTIVE_FILESYSTEM", destructiveFSReason)
		}
	}
	return result
}

func isStructuredMoveTool(tool string) bool {
	return tool == "move_file" || tool == "mcp__filesystem__move_file"
}

func isStructuredDeleteTool(tool string) bool {
	return tool == "delete_file" || tool == "mcp__filesystem__delete_file"
}

type scanResult struct {
	deny *contract.Decision
	gap  *contract.CoverageGap
}

func denied(ruleID, reason string) scanResult {
	decision := contract.Deny(ruleID, reason, recoveryForRule(ruleID))
	return scanResult{deny: &decision}
}

func recoveryForRule(ruleID string) string {
	switch ruleID {
	case "WARD_DESTRUCTIVE_FILESYSTEM":
		return "Use a narrower target or a recoverable filesystem operation."
	case "WARD_DESTRUCTIVE_GIT":
		return "Use a non-destructive Git operation or preserve a recoverable ref first."
	case "WARD_DESTRUCTIVE_DATABASE":
		return "Use a scoped migration or another reversible database operation."
	case "WARD_DESTRUCTIVE_INFRASTRUCTURE":
		return "Use a plan or dry-run and target a narrower recoverable resource."
	default:
		return "Use a narrower recoverable operation."
	}
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
