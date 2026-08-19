package evaluator

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jgoneit/ward/internal/contract"
	"github.com/jgoneit/ward/internal/policy"
)

type conformanceFixture struct {
	Name    string           `json:"name"`
	Request contract.Request `json:"request"`
	Want    struct {
		Outcome contract.Outcome `json:"outcome"`
		RuleID  string           `json:"rule_id"`
		GapCode string           `json:"gap_code"`
	} `json:"want"`
}

func TestEvaluatorConformanceFixtures(t *testing.T) {
	t.Parallel()

	active, err := New(policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "fixtures", "evaluator-v1.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	seen := map[string]struct{}{}
	line := 0
	for scanner.Scan() {
		line++
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var fixture conformanceFixture
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&fixture); err != nil {
			t.Fatalf("fixture line %d: %v", line, err)
		}
		if fixture.Name == "" {
			t.Fatalf("fixture line %d has no name", line)
		}
		if _, exists := seen[fixture.Name]; exists {
			t.Fatalf("duplicate fixture name %q", fixture.Name)
		}
		seen[fixture.Name] = struct{}{}

		t.Run(fixture.Name, func(t *testing.T) {
			t.Parallel()
			decision := active.Evaluate(fixture.Request)
			if decision.Schema != contract.DecisionSchemaV1 {
				t.Fatalf("schema = %q", decision.Schema)
			}
			if decision.Outcome != fixture.Want.Outcome {
				t.Fatalf("outcome = %q, want %q (decision %#v)", decision.Outcome, fixture.Want.Outcome, decision)
			}
			if decision.RuleID != fixture.Want.RuleID {
				t.Fatalf("rule_id = %q, want %q", decision.RuleID, fixture.Want.RuleID)
			}
			if fixture.Want.GapCode == "" {
				if decision.CoverageGap != nil {
					t.Fatalf("unexpected coverage gap: %#v", decision.CoverageGap)
				}
			} else if decision.CoverageGap == nil || decision.CoverageGap.Code != fixture.Want.GapCode {
				t.Fatalf("coverage gap = %#v, want code %q", decision.CoverageGap, fixture.Want.GapCode)
			}
		})
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(seen) < 60 {
		t.Fatalf("fixture corpus unexpectedly small: %d", len(seen))
	}
}

func TestEvaluatorNeverReflectsSensitiveInput(t *testing.T) {
	t.Parallel()

	active, err := New(policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	canary := "WARD_CANARY_DO_NOT_LOG"
	requests := []contract.Request{
		request("bash", "cat $"+canary),
		request("bash", "cat .env # "+canary),
		request("unknown_"+canary, canary),
	}
	for _, req := range requests {
		encoded, err := json.Marshal(active.Evaluate(req))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), canary) {
			t.Fatalf("decision reflected sensitive input: %s", encoded)
		}
	}
}

func TestEvaluatorInvalidRequestAndNilReceiverAreErrors(t *testing.T) {
	t.Parallel()

	active, err := New(policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	invalid := request("bash", "true")
	invalid.Schema = "ward-request/v999"
	if got := active.Evaluate(invalid); got.Outcome != contract.OutcomeError || got.ErrorCode != "invalid_request" {
		t.Fatalf("invalid request decision: %#v", got)
	}
	var unavailable *Evaluator
	if got := unavailable.Evaluate(request("bash", "true")); got.Outcome != contract.OutcomeError || got.ErrorCode != "evaluator_unavailable" {
		t.Fatalf("nil evaluator decision: %#v", got)
	}
	if _, err := New(policy.Policy{}); err == nil {
		t.Fatal("zero-value policy initialized an evaluator")
	}
}

func TestAdditiveCommandRuleOnlyAddsDeny(t *testing.T) {
	t.Parallel()

	activePolicy, err := policy.LoadAdditive(strings.NewReader(`
schema = "ward.policy.v1"

[[deny.commands]]
id = "CUSTOM_ACME_DESTROY"
executable = "acme"
args_prefix = ["destroy"]
`))
	if err != nil {
		t.Fatal(err)
	}
	active, err := New(activePolicy)
	if err != nil {
		t.Fatal(err)
	}
	if got := active.Evaluate(request("bash", "acme destroy project")); got.Outcome != contract.OutcomeDeny || got.RuleID != "CUSTOM_ACME_DESTROY" {
		t.Fatalf("additive rule decision: %#v", got)
	}
	if got := active.Evaluate(request("bash", "acme plan project")); got.Outcome != contract.OutcomeDefer {
		t.Fatalf("ordinary additive near-miss: %#v", got)
	}
}

func TestEvaluatorUsesRuntimeExactCredentialPaths(t *testing.T) {
	t.Parallel()

	activePolicy, err := policy.WithExactProtectedPaths(policy.Default(), []string{"/tmp/custom-credential-file"})
	if err != nil {
		t.Fatal(err)
	}
	active, err := New(activePolicy)
	if err != nil {
		t.Fatal(err)
	}
	if got := active.Evaluate(request("bash", "cat /tmp/custom-credential-file")); got.Outcome != contract.OutcomeDeny || got.RuleID != "WARD_SECRET_PATH" {
		t.Fatalf("runtime exact credential decision: %#v", got)
	}
	if got := active.Evaluate(request("bash", "cat testdata/custom-credential-file")); got.Outcome != contract.OutcomeDefer {
		t.Fatalf("runtime exact credential near-miss: %#v", got)
	}
}

func TestEvaluatorProtectsRuntimeExactCredentialAncestorsOnMoveAndDelete(t *testing.T) {
	t.Parallel()

	activePolicy, err := policy.WithExactProtectedPaths(policy.Default(), []string{
		"/home/example/.config/gh/hosts.yml",
		"C:/Users/Example/.docker/config.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	active, err := New(activePolicy)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		"mv /home/example/.config /tmp/config.bak",
		"rm -rf /home/example/.config",
		"git mv /home/example/.config /tmp/config.bak",
	} {
		if got := active.Evaluate(request("bash", command)); got.Outcome != contract.OutcomeDeny || got.RuleID != "WARD_SECRET_PATH" {
			t.Errorf("ancestor command %q decision: %#v", command, got)
		}
	}
	for _, command := range []string{
		"rm -rf .config",
		"rm .config/gh/hosts.yml",
		"mv .config /tmp/config.bak",
		"mv -t /tmp .config",
		"git mv -k .config /tmp/config.bak",
		"find .config -delete",
	} {
		req := request("bash", command)
		req.CWD = "/home/example"
		if got := active.Evaluate(req); got.Outcome != contract.OutcomeDeny || got.RuleID != "WARD_SECRET_PATH" {
			t.Errorf("relative ancestor command %q decision: %#v", command, got)
		}
	}
	for _, test := range []struct {
		tool    string
		command string
	}{
		{tool: "powershell", command: "Move-Item C:/Users/Example/.docker C:/Temp/docker.bak"},
		{tool: "cmd.exe", command: "move C:/Users/Example/.docker C:/Temp/docker.bak"},
	} {
		req := request(test.tool, test.command)
		req.CWD = "C:/workspace"
		if got := active.Evaluate(req); got.Outcome != contract.OutcomeDeny || got.RuleID != "WARD_SECRET_PATH" {
			t.Errorf("Windows ancestor command %q decision: %#v", test.command, got)
		}
	}
	structured := request("mcp__filesystem__move_file", "structured-tool-input")
	structured.Input.Paths = []string{"/home/example/.config", "/tmp/config.bak"}
	structured.Input.SourcePath = "/home/example/.config"
	structured.Input.DestinationPath = "/tmp/config.bak"
	if got := active.Evaluate(structured); got.Outcome != contract.OutcomeDeny || got.RuleID != "WARD_SECRET_PATH" {
		t.Errorf("structured ancestor move decision: %#v", got)
	}
	structuredRelative := request("mcp__filesystem__delete_file", "structured-tool-input")
	structuredRelative.CWD = "/home/example"
	structuredRelative.Input.Paths = []string{".config"}
	if got := active.Evaluate(structuredRelative); got.Outcome != contract.OutcomeDeny || got.RuleID != "WARD_SECRET_PATH" {
		t.Errorf("structured relative ancestor delete decision: %#v", got)
	}
	structuredDestination := request("mcp__filesystem__move_file", "structured-tool-input")
	structuredDestination.Input.Paths = []string{"/tmp/ordinary.txt", "/home/example/.config"}
	structuredDestination.Input.SourcePath = "/tmp/ordinary.txt"
	structuredDestination.Input.DestinationPath = "/home/example/.config"
	if got := active.Evaluate(structuredDestination); got.Outcome != contract.OutcomeDefer {
		t.Errorf("structured protected-parent destination near-miss: %#v", got)
	}
	rolelessMove := request("mcp__filesystem__move_file", "structured-tool-input")
	rolelessMove.Input.Paths = []string{"/home/example/.config", "/tmp/config.bak"}
	if got := active.Evaluate(rolelessMove); got.Outcome != contract.OutcomeDefer || got.CoverageGap == nil || got.CoverageGap.Code != "missing_structured_move_roles" {
		t.Errorf("roleless structured move decision: %#v", got)
	}
	for _, command := range []string{
		"mv /home/example/.cache /tmp/cache.bak",
		"rm -rf /tmp/unrelated-cache",
	} {
		if got := active.Evaluate(request("bash", command)); got.Outcome != contract.OutcomeDefer {
			t.Errorf("unrelated parent command %q decision: %#v", command, got)
		}
	}
	windowsOrdinary := request("powershell", "Move-Item C:/Users/Example/fixtures C:/Temp/fixtures.bak")
	windowsOrdinary.CWD = "C:/workspace"
	if got := active.Evaluate(windowsOrdinary); got.Outcome != contract.OutcomeDefer {
		t.Errorf("unrelated Windows parent move decision: %#v", got)
	}
	for _, test := range []struct {
		tool    string
		command string
	}{
		{tool: "powershell", command: "Move-Item .docker C:/Temp/docker.bak"},
		{tool: "cmd.exe", command: "move .docker C:/Temp/docker.bak"},
	} {
		req := request(test.tool, test.command)
		req.CWD = "C:/Users/Example"
		if got := active.Evaluate(req); got.Outcome != contract.OutcomeDeny || got.RuleID != "WARD_SECRET_PATH" {
			t.Errorf("relative Windows ancestor command %q decision: %#v", test.command, got)
		}
	}
}

func TestSQLStatementSplitterKeepsBackslashEscapedQuote(t *testing.T) {
	t.Parallel()

	statements := splitLiteralSQLStatements(`SELECT E'quote \' ; DROP DATABASE prod;'; SELECT 2;`)
	if len(statements) != 2 {
		t.Fatalf("statement count = %d: %#v", len(statements), statements)
	}
	for _, statement := range statements {
		if dropDatabaseSQL.MatchString(statement) || dropSchemaCascadeSQL.MatchString(statement) {
			t.Fatalf("quoted SQL text became destructive statement: %q", statement)
		}
	}
}

func request(tool, command string) contract.Request {
	return contract.Request{
		Schema: contract.RequestSchemaV1,
		Host:   "codex",
		Event:  "PreToolUse",
		Tool:   tool,
		CWD:    "/workspace",
		Input:  contract.Input{Command: command},
	}
}
