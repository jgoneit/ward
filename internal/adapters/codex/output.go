package codex

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/jgoneit/ward/internal/contract"
)

const (
	policyDenyReason      = "Ward blocked this request by policy."
	maxSessionHealthIDs   = 8
	maxSessionHealthBytes = 512
)

var (
	safeRuleID  = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,96}$`)
	safeCheckID = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
)

// Output translates a Ward decision to Codex hook stdout. A nil or empty byte
// slice means the hook must write nothing. Ward intentionally never emits
// Codex allow, ask, updatedInput, or approval-bypass output.
func Output(decision contract.Decision) ([]byte, error) {
	switch decision.Outcome {
	case contract.OutcomeDefer:
		return nil, nil
	case contract.OutcomeDeny:
		return marshalDeny(policyMessage(decision.RuleID, decision.Recovery))
	case contract.OutcomeError:
		return nil, nil
	default:
		return nil, nil
	}
}

// SessionStartHealthOutput emits no bytes for a healthy installation. For an
// unhealthy installation it exposes only a sorted, bounded set of safe Doctor
// check identifiers; paths, commands, and diagnostic messages never enter the
// model context.
func SessionStartHealthOutput(failedCheckIDs []string) ([]byte, error) {
	if len(failedCheckIDs) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(failedCheckIDs))
	ids := make([]string, 0, min(len(failedCheckIDs), maxSessionHealthIDs))
	for _, candidate := range failedCheckIDs {
		candidate = strings.TrimSpace(candidate)
		if !safeCheckID.MatchString(candidate) {
			candidate = "ward.health.redacted"
		}
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		ids = append(ids, candidate)
	}
	sort.Strings(ids)
	if len(ids) > maxSessionHealthIDs {
		ids = ids[:maxSessionHealthIDs]
	}
	message := "Ward health warning: " + strings.Join(ids, ",") + ". Use the Ward session-health workflow."
	if len(message) > maxSessionHealthBytes {
		message = message[:maxSessionHealthBytes]
	}
	return json.Marshal(struct {
		SystemMessage string `json:"systemMessage"`
	}{SystemMessage: message})
}

func policyMessage(ruleID, recovery string) string {
	ruleID = strings.TrimSpace(ruleID)
	guidance := staticRecovery(ruleID, recovery)
	if safeRuleID.MatchString(ruleID) {
		return policyDenyReason + " Rule: " + ruleID + ". Recovery: " + guidance
	}
	return policyDenyReason + " Recovery: " + guidance
}

// staticRecovery accepts only evaluator catalog strings. Unknown or modified
// values are replaced by a rule-scoped constant and never reflected verbatim.
func staticRecovery(ruleID, candidate string) string {
	catalog := map[string]string{
		"WARD_DESTRUCTIVE_FILESYSTEM":     "Use a narrower target or a recoverable filesystem operation.",
		"WARD_DESTRUCTIVE_GIT":            "Use a non-destructive Git operation or preserve a recoverable ref first.",
		"WARD_DESTRUCTIVE_DATABASE":       "Use a scoped migration or another reversible database operation.",
		"WARD_DESTRUCTIVE_INFRASTRUCTURE": "Use a plan or dry-run and target a narrower recoverable resource.",
	}
	if expected, ok := catalog[ruleID]; ok && (candidate == "" || candidate == expected) {
		return expected
	}
	return "Use a narrower recoverable operation."
}

func marshalDeny(message string) ([]byte, error) {
	return json.Marshal(preToolUseOutput{
		HookSpecificOutput: preToolUseSpecific{
			HookEventName:            EventPreToolUse,
			PermissionDecision:       "deny",
			PermissionDecisionReason: message,
		},
	})
}

type preToolUseOutput struct {
	HookSpecificOutput preToolUseSpecific `json:"hookSpecificOutput"`
}

type preToolUseSpecific struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}
