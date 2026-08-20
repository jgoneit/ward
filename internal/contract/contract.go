// Package contract defines the host-neutral request and decision wire contract.
package contract

import (
	"errors"
	"fmt"
	"strings"
)

const (
	RequestSchemaV1    = "ward-request/v1"
	DecisionSchemaV1   = "ward-decision/v1"
	AuditEventSchemaV1 = "ward-audit-event/v1"
	DoctorSchemaV1     = "ward-doctor/v1"

	maxCommandBytes = 1 << 20
	maxPaths        = 256
	maxPathBytes    = 16 << 10
)

// Outcome is deliberately veto-only. Ward never grants permission to a host.
type Outcome string

const (
	OutcomeDeny  Outcome = "deny"
	OutcomeDefer Outcome = "defer"
	OutcomeError Outcome = "error"
)

// Request is the canonical request produced by a host adapter.
type Request struct {
	Schema string `json:"schema"`
	Host   string `json:"host"`
	Event  string `json:"event"`
	Tool   string `json:"tool"`
	CWD    string `json:"cwd"`
	Input  Input  `json:"input"`
}

// Input contains only normalized fields the evaluator understands. Adapters
// must not place host-specific opaque payloads here and call them evaluated.
type Input struct {
	Command         string   `json:"command,omitempty"`
	Paths           []string `json:"paths,omitempty"`
	SourcePath      string   `json:"source_path,omitempty"`
	DestinationPath string   `json:"destination_path,omitempty"`
}

// CoverageGap explains why Ward could not classify a request. Details must be
// static, redacted text and must never echo command or path input.
type CoverageGap struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// Decision is the canonical evaluator output. RuleID, Reason, Recovery, and
// ErrorCode come from static catalogs so decisions do not reflect sensitive
// input.
type Decision struct {
	Schema      string       `json:"schema"`
	Outcome     Outcome      `json:"outcome"`
	RuleID      string       `json:"rule_id,omitempty"`
	Reason      string       `json:"reason,omitempty"`
	Recovery    string       `json:"recovery,omitempty"`
	ErrorCode   string       `json:"error_code,omitempty"`
	CoverageGap *CoverageGap `json:"coverage_gap,omitempty"`
}

// ValidateRequest rejects malformed canonical requests. Ambiguous but valid
// tool input is not an error; the evaluator returns defer with a coverage gap.
func ValidateRequest(req Request) error {
	if req.Schema != RequestSchemaV1 {
		return fmt.Errorf("unsupported request schema %q", req.Schema)
	}
	if strings.TrimSpace(req.Host) == "" {
		return errors.New("host is required")
	}
	if req.Event != "PreToolUse" && req.Event != "PermissionRequest" {
		return fmt.Errorf("unsupported event %q", req.Event)
	}
	if strings.TrimSpace(req.Tool) == "" {
		return errors.New("tool is required")
	}
	if strings.TrimSpace(req.CWD) == "" {
		return errors.New("cwd is required")
	}
	if len(req.Input.Command) > maxCommandBytes {
		return errors.New("command exceeds size limit")
	}
	if strings.IndexByte(req.Input.Command, 0) >= 0 {
		return errors.New("command contains NUL")
	}
	if len(req.Input.Paths) > maxPaths {
		return errors.New("too many paths")
	}
	for _, candidate := range req.Input.Paths {
		if err := validatePath(candidate); err != nil {
			return err
		}
	}
	pathSet := make(map[string]struct{}, len(req.Input.Paths))
	for _, candidate := range req.Input.Paths {
		pathSet[candidate] = struct{}{}
	}
	for _, candidate := range []string{req.Input.SourcePath, req.Input.DestinationPath} {
		if candidate == "" {
			continue
		}
		if err := validatePath(candidate); err != nil {
			return fmt.Errorf("role-specific %w", err)
		}
		if _, exists := pathSet[candidate]; !exists {
			return errors.New("role-specific path is absent from paths")
		}
	}
	if strings.TrimSpace(req.Input.Command) == "" && len(req.Input.Paths) == 0 {
		return errors.New("command or paths are required")
	}
	return nil
}

func validatePath(candidate string) error {
	if strings.TrimSpace(candidate) == "" {
		return errors.New("path must not be empty")
	}
	if len(candidate) > maxPathBytes {
		return errors.New("path exceeds size limit")
	}
	if strings.IndexByte(candidate, 0) >= 0 {
		return errors.New("path contains NUL")
	}
	return nil
}

// Deny constructs a static hard-deny decision.
func Deny(ruleID, reason string, recovery ...string) Decision {
	decision := Decision{
		Schema:  DecisionSchemaV1,
		Outcome: OutcomeDeny,
		RuleID:  ruleID,
		Reason:  reason,
	}
	if len(recovery) > 0 {
		decision.Recovery = recovery[0]
	}
	return decision
}

// Defer constructs a recognized no-veto decision. Host policy remains
// authoritative and Ward does not approve the operation.
func Defer(reason string) Decision {
	return Decision{
		Schema:  DecisionSchemaV1,
		Outcome: OutcomeDefer,
		Reason:  reason,
	}
}

// DeferWithGap constructs a no-veto decision for ambiguous or unsupported
// input while making the coverage limitation explicit.
func DeferWithGap(reason, code, detail string) Decision {
	decision := Defer(reason)
	decision.CoverageGap = &CoverageGap{Code: code, Detail: detail}
	return decision
}

// ErrorDecision constructs an evaluator error without exposing raw input.
func ErrorDecision(code, reason string) Decision {
	return Decision{
		Schema:    DecisionSchemaV1,
		Outcome:   OutcomeError,
		Reason:    reason,
		ErrorCode: code,
	}
}
