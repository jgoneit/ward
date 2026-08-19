package codex

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/jgoneit/ward/internal/contract"
)

const (
	staticDenyReason = "Ward blocked this request because it could not be evaluated safely."
	policyDenyReason = "Ward blocked this request by policy."
)

var safeRuleID = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,96}$`)

// Output translates a Ward decision to Codex hook stdout. A nil or empty byte
// slice means the hook must write nothing. Ward intentionally never emits
// Codex allow, ask, updatedInput, or approval-bypass output.
func Output(event string, decision contract.Decision) ([]byte, error) {
	if event == EventPostToolUse {
		// A post hook cannot undo side effects. Ward treats it as audit-only.
		return nil, nil
	}
	if event != EventPreToolUse && event != EventPermissionRequest {
		return nil, fmt.Errorf("unsupported Codex hook event %q", event)
	}
	if decision.Schema != contract.DecisionSchemaV1 {
		return marshalDeny(event, staticDenyReason)
	}

	switch decision.Outcome {
	case contract.OutcomeDefer:
		return nil, nil
	case contract.OutcomeDeny:
		return marshalDeny(event, policyMessage(decision.RuleID))
	case contract.OutcomeError:
		return marshalDeny(event, staticDenyReason)
	default:
		// Unknown outcomes fail closed and must never become an implicit
		// allow because the wire contract evolved unexpectedly.
		return marshalDeny(event, staticDenyReason)
	}
}

// StaticDeny is used when payload decoding or evaluator invocation fails
// before a normal Ward Decision exists.
func StaticDeny(event string) ([]byte, error) {
	if event == EventPostToolUse {
		return nil, nil
	}
	return marshalDeny(event, staticDenyReason)
}

func policyMessage(ruleID string) string {
	ruleID = strings.TrimSpace(ruleID)
	if safeRuleID.MatchString(ruleID) {
		return policyDenyReason + " Rule: " + ruleID + "."
	}
	return policyDenyReason
}

func marshalDeny(event, message string) ([]byte, error) {
	var value any
	switch event {
	case EventPreToolUse:
		value = preToolUseOutput{
			HookSpecificOutput: preToolUseSpecific{
				HookEventName:            EventPreToolUse,
				PermissionDecision:       "deny",
				PermissionDecisionReason: message,
			},
		}
	case EventPermissionRequest:
		value = permissionRequestOutput{
			HookSpecificOutput: permissionRequestSpecific{
				HookEventName: EventPermissionRequest,
				Decision: permissionRequestDecision{
					Behavior: "deny",
					Message:  message,
				},
			},
		}
	default:
		return nil, fmt.Errorf("unsupported Codex hook event %q", event)
	}
	return json.Marshal(value)
}

type preToolUseOutput struct {
	HookSpecificOutput preToolUseSpecific `json:"hookSpecificOutput"`
}

type preToolUseSpecific struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

type permissionRequestOutput struct {
	HookSpecificOutput permissionRequestSpecific `json:"hookSpecificOutput"`
}

type permissionRequestSpecific struct {
	HookEventName string                    `json:"hookEventName"`
	Decision      permissionRequestDecision `json:"decision"`
}

type permissionRequestDecision struct {
	Behavior string `json:"behavior"`
	Message  string `json:"message"`
}
