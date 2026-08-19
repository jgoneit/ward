package codex

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jgoneit/ward/internal/contract"
)

func TestOutputPreToolUseDenyUsesOnlyCanonicalDeny(t *testing.T) {
	out, err := Output(EventPreToolUse, contract.Decision{Schema: contract.DecisionSchemaV1, Outcome: contract.OutcomeDeny, RuleID: "delete.root"})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONValue(t, out, []string{"hookSpecificOutput", "permissionDecision"}, "deny")
	text := string(out)
	for _, forbidden := range []string{`"allow"`, `"ask"`, `"updatedInput"`, `"decision":"block"`} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("output contains forbidden shape %q: %s", forbidden, text)
		}
	}
}

func TestOutputPermissionRequestDenyDoesNotApprove(t *testing.T) {
	out, err := Output(EventPermissionRequest, contract.Decision{Schema: contract.DecisionSchemaV1, Outcome: contract.OutcomeDeny})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONValue(t, out, []string{"hookSpecificOutput", "decision", "behavior"}, "deny")
	if strings.Contains(string(out), "allow") || strings.Contains(string(out), "ask") {
		t.Fatalf("permission output can bypass approval: %s", out)
	}
}

func TestOutputDeferIsExactlyNoStdout(t *testing.T) {
	for _, event := range []string{EventPreToolUse, EventPermissionRequest, EventPostToolUse} {
		out, err := Output(event, contract.Decision{Schema: contract.DecisionSchemaV1, Outcome: contract.OutcomeDefer})
		if err != nil {
			t.Fatalf("Output(%s) error = %v", event, err)
		}
		if len(out) != 0 {
			t.Fatalf("Output(%s) = %q, want no stdout", event, out)
		}
	}
}

func TestOutputEvaluatorErrorIsStaticDeny(t *testing.T) {
	decision := contract.Decision{
		Schema:    contract.DecisionSchemaV1,
		Outcome:   contract.OutcomeError,
		RuleID:    "attacker-controlled",
		Reason:    "SECRET VALUE",
		ErrorCode: "details",
	}
	for _, event := range []string{EventPreToolUse, EventPermissionRequest} {
		out, err := Output(event, decision)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), staticDenyReason) {
			t.Fatalf("error output lacks static reason: %s", out)
		}
		for _, leaked := range []string{"SECRET VALUE", "attacker-controlled", "details"} {
			if strings.Contains(string(out), leaked) {
				t.Fatalf("error output leaked %q: %s", leaked, out)
			}
		}
	}
}

func TestOutputPostToolUseNeverBlocks(t *testing.T) {
	for _, outcome := range []contract.Outcome{contract.OutcomeDeny, contract.OutcomeDefer, contract.OutcomeError} {
		out, err := Output(EventPostToolUse, contract.Decision{Schema: contract.DecisionSchemaV1, Outcome: outcome})
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 0 {
			t.Fatalf("post output for %s = %s, want empty", outcome, out)
		}
	}
}

func TestOutputUnknownDecisionSchemaFailsClosed(t *testing.T) {
	out, err := Output(EventPreToolUse, contract.Decision{Schema: "future", Outcome: contract.OutcomeDefer})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONValue(t, out, []string{"hookSpecificOutput", "permissionDecision"}, "deny")
}

func assertJSONValue(t *testing.T, raw []byte, path []string, want string) {
	t.Helper()
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("invalid JSON %q: %v", raw, err)
	}
	current := value
	for _, part := range path {
		obj, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("%v is not an object in %s", path, raw)
		}
		current = obj[part]
	}
	if current != want {
		t.Fatalf("value at %v = %#v, want %q", path, current, want)
	}
}
