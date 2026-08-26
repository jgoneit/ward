package codex

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jgoneit/ward/internal/contract"
)

func TestOutputPreToolUseDenyUsesOnlyCanonicalDeny(t *testing.T) {
	out, err := Output(contract.Decision{Outcome: contract.OutcomeDeny, RuleID: "delete.root"})
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

func TestOutputDeferIsExactlyNoStdout(t *testing.T) {
	out, err := Output(contract.Decision{Outcome: contract.OutcomeDefer})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("Output() = %q, want no stdout", out)
	}
}

func TestOutputEvaluatorErrorIsExactlyNoStdout(t *testing.T) {
	decision := contract.Decision{
		Outcome:   contract.OutcomeError,
		RuleID:    "attacker-controlled",
		Reason:    "SECRET VALUE",
		ErrorCode: "details",
	}
	out, err := Output(decision)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("error output = %q, want no stdout", out)
	}
}

func TestOutputDenyUsesOnlyCatalogRecovery(t *testing.T) {
	decision := contract.Decision{
		Outcome: contract.OutcomeDeny,
		RuleID:  "WARD_DESTRUCTIVE_FILESYSTEM", Recovery: "ATTACKER CONTROLLED",
	}
	out, err := Output(decision)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if strings.Contains(text, decision.Recovery) || !strings.Contains(text, "Use a narrower recoverable operation.") {
		t.Fatalf("recovery was reflected or missing fallback: %s", out)
	}
}

func TestOutputDenyIncludesValidatedRuleRecovery(t *testing.T) {
	recovery := "Use a non-destructive Git operation or preserve a recoverable ref first."
	out, err := Output(contract.Decision{
		Outcome: contract.OutcomeDeny,
		RuleID:  "WARD_DESTRUCTIVE_GIT", Recovery: recovery,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "WARD_DESTRUCTIVE_GIT") || !strings.Contains(string(out), recovery) {
		t.Fatalf("validated recovery missing: %s", out)
	}
}

func TestSessionStartHealthOutputIsBoundedAndRedacted(t *testing.T) {
	if out, err := SessionStartHealthOutput(nil); err != nil || len(out) != 0 {
		t.Fatalf("healthy output = %q, %v", out, err)
	}
	out, err := SessionStartHealthOutput([]string{"hooks.PreToolUse", "/Users/private/config", "hooks.PreToolUse", "journal"})
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if strings.Contains(text, "/Users/private") || !strings.Contains(text, "ward.health.redacted") || !strings.Contains(text, "hooks.PreToolUse") {
		t.Fatalf("unhealthy output was not bounded/redacted: %s", out)
	}
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
