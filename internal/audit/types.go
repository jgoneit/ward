package audit

import (
	"errors"
	"fmt"
	"time"
)

const (
	// EventSchemaV1 is the on-disk schema for audit events.
	EventSchemaV1  = "ward-audit-event/v1"
	anchorSchemaV1 = "ward-audit-anchor/v1"

	DefaultSegmentMaxBytes int64 = 8 << 20
	DefaultRetentionDays         = 30
	DefaultProjectMaxBytes int64 = 64 << 20
	DefaultTotalMaxBytes   int64 = 512 << 20
)

var (
	ErrInvalidEvent            = errors.New("invalid audit event")
	ErrIntegrity               = errors.New("audit log integrity failure")
	ErrLockTimeout             = errors.New("audit log lock timeout")
	ErrNotInitialized          = errors.New("audit store is not initialized")
	ErrPruneDisabled           = errors.New("audit pruning is disabled")
	ErrGlobalRetentionRequired = errors.New("global audit retention requires a cross-project operation")
)

type Phase string

const (
	PhasePre Phase = "pre"
	// PhasePermissionRequest and PhasePost remain part of the historical v1
	// read contract. The current sparse writer accepts PhasePre only.
	PhasePermissionRequest Phase = "permission_request"
	PhasePost              Phase = "post"
)

type HostDisposition string

const (
	HostApprovalRequested HostDisposition = "approval_requested"
	HostPostObserved      HostDisposition = "post_observed"
	HostUnknown           HostDisposition = "unknown"
)

type Decision string

const (
	DecisionDeny Decision = "deny"
	// DecisionDefer remains part of the historical v1 read contract. The
	// current sparse writer accepts DecisionDeny and DecisionError only.
	DecisionDefer Decision = "defer"
	DecisionError Decision = "error"
)

type ToolKind string

const (
	ToolShell   ToolKind = "shell"
	ToolPatch   ToolKind = "patch"
	ToolMCP     ToolKind = "mcp"
	ToolLocal   ToolKind = "local"
	ToolUnknown ToolKind = "unknown"
)

// PermissionMode is a privacy-safe catalog value. Hook adapters may accept
// future host values, but audit persistence must never copy arbitrary host
// strings into the evidence log.
type PermissionMode string

const (
	PermissionDefault           PermissionMode = "default"
	PermissionAcceptEdits       PermissionMode = "acceptEdits"
	PermissionPlan              PermissionMode = "plan"
	PermissionDontAsk           PermissionMode = "dontAsk"
	PermissionBypassPermissions PermissionMode = "bypassPermissions"
	PermissionUnknown           PermissionMode = "unknown"
)

// CoverageGapCode is a privacy-safe, evaluator-owned catalog value. Audit
// persistence never copies arbitrary evaluator or host text into this field.
type CoverageGapCode string

const (
	CoverageGapAmbiguousCMD                   CoverageGapCode = "ambiguous_cmd"
	CoverageGapAmbiguousPowerShell            CoverageGapCode = "ambiguous_powershell"
	CoverageGapAmbiguousPowerShellOptions     CoverageGapCode = "ambiguous_powershell_options"
	CoverageGapBuiltinDispatch                CoverageGapCode = "builtin_dispatch"
	CoverageGapComplexCommandWrapper          CoverageGapCode = "complex_command_wrapper"
	CoverageGapComplexEnvWrapper              CoverageGapCode = "complex_env_wrapper"
	CoverageGapComplexFileOperands            CoverageGapCode = "complex_file_operands"
	CoverageGapComplexNohupWrapper            CoverageGapCode = "complex_nohup_wrapper"
	CoverageGapComplexSudoWrapper             CoverageGapCode = "complex_sudo_wrapper"
	CoverageGapDynamicAdditivePrefix          CoverageGapCode = "dynamic_additive_prefix"
	CoverageGapDynamicFindPath                CoverageGapCode = "dynamic_find_path"
	CoverageGapDynamicGlobalOption            CoverageGapCode = "dynamic_global_option"
	CoverageGapDynamicInterpreterPayload      CoverageGapCode = "dynamic_interpreter_payload"
	CoverageGapDynamicPatchPath               CoverageGapCode = "dynamic_patch_path"
	CoverageGapDynamicPath                    CoverageGapCode = "dynamic_path"
	CoverageGapDynamicShellWord               CoverageGapCode = "dynamic_shell_word"
	CoverageGapDynamicWrapper                 CoverageGapCode = "dynamic_wrapper"
	CoverageGapEmptyWindowsCommand            CoverageGapCode = "empty_windows_command"
	CoverageGapFindCommandAction              CoverageGapCode = "find_command_action"
	CoverageGapInlineShellInput               CoverageGapCode = "inline_shell_input"
	CoverageGapInterpreterPayload             CoverageGapCode = "interpreter_payload"
	CoverageGapMalformedPatchPath             CoverageGapCode = "malformed_patch_path"
	CoverageGapMissingCommand                 CoverageGapCode = "missing_command"
	CoverageGapMissingStructuredMoveRoles     CoverageGapCode = "missing_structured_move_roles"
	CoverageGapMissingStructuredPath          CoverageGapCode = "missing_structured_path"
	CoverageGapNestedShellLimit               CoverageGapCode = "nested_shell_limit"
	CoverageGapNohupStdinSemantics            CoverageGapCode = "nohup_stdin_semantics"
	CoverageGapOpaqueCommandDispatch          CoverageGapCode = "opaque_command_dispatch"
	CoverageGapShellFunction                  CoverageGapCode = "shell_function"
	CoverageGapShellParseError                CoverageGapCode = "shell_parse_error"
	CoverageGapUnrecognizedPatch              CoverageGapCode = "unrecognized_patch"
	CoverageGapUnresolvedHomeTarget           CoverageGapCode = "unresolved_home_target"
	CoverageGapUnsupportedDockerGlobalOption  CoverageGapCode = "unsupported_docker_global_option"
	CoverageGapUnsupportedGitGlobalOption     CoverageGapCode = "unsupported_git_global_option"
	CoverageGapUnsupportedGlobalOption        CoverageGapCode = "unsupported_global_option"
	CoverageGapUnsupportedKubectlGlobalOption CoverageGapCode = "unsupported_kubectl_global_option"
	CoverageGapUnsupportedTool                CoverageGapCode = "unsupported_tool"
	CoverageGapUnknown                        CoverageGapCode = "unknown"
)

// RecordInput contains transient hook data for a current sparse audit write.
// Record accepts only a Pre phase with unknown host disposition, a deny or
// error decision, and no coverage gap. CWD, raw identifiers, ToolInput, and
// CorrelationInput are used only to derive keyed fingerprints; they are never
// stored in an Event. A nil CorrelationInput falls back to ToolInput.
//
// Record returns an audit error independently of Decision. Callers retain full
// ownership of the evaluator decision, so an audit failure cannot turn a deny
// into a defer (or the reverse).
type RecordInput struct {
	CWD              string
	Timestamp        time.Time
	Phase            Phase
	HostDisposition  HostDisposition
	SessionID        string
	TurnID           string
	ToolUseID        string
	ToolName         string
	ToolKind         ToolKind
	ToolInput        []byte
	CorrelationInput []byte
	Decision         Decision
	RuleID           string
	RiskClass        string
	CoverageGapCode  string
	PermissionMode   string
	PolicyMaterial   []byte
	EngineVersion    string
}

// Event is the persisted, metadata-only audit record. It deliberately has no
// field capable of storing a command, path, environment, transcript, or tool
// response.
type Event struct {
	Schema             string          `json:"schema"`
	Sequence           uint64          `json:"seq"`
	Timestamp          time.Time       `json:"timestamp"`
	Phase              Phase           `json:"phase"`
	HostDisposition    HostDisposition `json:"host_disposition"`
	ProjectID          string          `json:"project_id"`
	SessionFingerprint string          `json:"session_fp,omitempty"`
	TurnFingerprint    string          `json:"turn_fp,omitempty"`
	ToolUseFingerprint string          `json:"tool_use_fp,omitempty"`
	InputFingerprint   string          `json:"input_fp"`
	ToolFingerprint    string          `json:"tool_fp"`
	RequestFingerprint string          `json:"request_fp"`
	ToolKind           ToolKind        `json:"tool_kind"`
	Decision           Decision        `json:"ward_decision,omitempty"`
	RuleID             string          `json:"rule_id,omitempty"`
	RiskClass          string          `json:"risk_class,omitempty"`
	CoverageGapCode    CoverageGapCode `json:"coverage_gap_code,omitempty"`
	PermissionMode     PermissionMode  `json:"permission_mode,omitempty"`
	PolicyFingerprint  string          `json:"policy_fp,omitempty"`
	EngineVersion      string          `json:"engine_version,omitempty"`
	PreviousMAC        string          `json:"prev_mac,omitempty"`
	RecordMAC          string          `json:"record_mac"`
}

type Filter struct {
	Since           time.Time
	Until           time.Time
	Phase           Phase
	Decision        Decision
	HostDisposition HostDisposition
	RuleID          string
	Limit           int
}

type Verification struct {
	ProjectID             string    `json:"project_id"`
	Valid                 bool      `json:"valid"`
	Records               int       `json:"records"`
	FirstSequence         uint64    `json:"first_sequence,omitempty"`
	LastSequence          uint64    `json:"last_sequence,omitempty"`
	LastMAC               string    `json:"last_mac,omitempty"`
	PrunedThroughSequence uint64    `json:"pruned_through_sequence,omitempty"`
	PrunedThroughTime     time.Time `json:"pruned_through_time,omitempty"`
}

type Stats struct {
	ProjectID             string                     `json:"project_id"`
	Total                 uint64                     `json:"total"`
	ByPhase               map[Phase]uint64           `json:"by_phase"`
	ByDecision            map[Decision]uint64        `json:"by_decision"`
	ByHostDisposition     map[HostDisposition]uint64 `json:"by_host_disposition"`
	ByRule                map[string]uint64          `json:"by_rule"`
	ByCoverageGapCode     map[CoverageGapCode]uint64 `json:"by_coverage_gap_code"`
	FirstTimestamp        time.Time                  `json:"first_timestamp,omitempty"`
	LastTimestamp         time.Time                  `json:"last_timestamp,omitempty"`
	PrunedThroughSequence uint64                     `json:"pruned_through_seq,omitempty"`
}

type PruneResult struct {
	ProjectID             string    `json:"project_id"`
	Removed               int       `json:"removed"`
	Remaining             int       `json:"remaining"`
	PrunedThroughSequence uint64    `json:"pruned_through_sequence,omitempty"`
	PrunedThroughTime     time.Time `json:"pruned_through_time,omitempty"`
}

type RetentionPolicy struct {
	Days            int   `json:"days"`
	SegmentMaxBytes int64 `json:"segment_max_bytes"`
	ProjectMaxBytes int64 `json:"project_max_bytes"`
	TotalMaxBytes   int64 `json:"total_max_bytes"`
}

type RetentionStatus struct {
	ProjectID       string          `json:"project_id"`
	Policy          RetentionPolicy `json:"policy"`
	ProjectBytes    int64           `json:"project_bytes"`
	TotalBytes      int64           `json:"total_bytes"`
	ProjectExceeded bool            `json:"project_exceeded"`
	TotalExceeded   bool            `json:"total_exceeded"`
}

type RetentionPruneResult struct {
	ProjectID             string    `json:"project_id"`
	DryRun                bool      `json:"dry_run"`
	Cutoff                time.Time `json:"cutoff"`
	Removed               int       `json:"removed"`
	Remaining             int       `json:"remaining"`
	PrunedThroughSequence uint64    `json:"pruned_through_sequence,omitempty"`
	PrunedThroughTime     time.Time `json:"pruned_through_time,omitempty"`
	ProjectBytesBefore    int64     `json:"project_bytes_before"`
	ProjectBytesAfter     int64     `json:"project_bytes_after"`
	TotalBytesBefore      int64     `json:"total_bytes_before"`
	TotalBytesAfter       int64     `json:"total_bytes_after"`
	ProjectLimitSatisfied bool      `json:"project_limit_satisfied"`
	TotalLimitSatisfied   bool      `json:"total_limit_satisfied"`
}

// RecoveryResult reports an explicit head-recovery operation. Recovery never
// runs as part of Verify or Record: the caller must request it after observing
// an integrity failure.
type RecoveryResult struct {
	ProjectID    string `json:"project_id"`
	Needed       bool   `json:"needed"`
	Repaired     bool   `json:"repaired"`
	FromSequence uint64 `json:"from_sequence,omitempty"`
	ToSequence   uint64 `json:"to_sequence,omitempty"`
}

// IntegrityError identifies a structural or authentication failure without
// embedding record contents in an error message.
type IntegrityError struct {
	Line int
	Code string
}

func (e *IntegrityError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("%v at line %d (%s)", ErrIntegrity, e.Line, e.Code)
	}
	return fmt.Sprintf("%v (%s)", ErrIntegrity, e.Code)
}

func (e *IntegrityError) Unwrap() error { return ErrIntegrity }
