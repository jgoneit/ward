package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jgoneit/ward/internal/audit"
)

func TestValidateRequest(t *testing.T) {
	t.Parallel()

	valid := Request{
		Schema: RequestSchemaV1,
		Host:   "codex",
		Event:  "PreToolUse",
		Tool:   "bash",
		CWD:    "/workspace",
		Input:  Input{Command: "cat README.md"},
	}
	if err := ValidateRequest(valid); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	valid.Event = "PermissionRequest"
	if err := ValidateRequest(valid); err != nil {
		t.Fatalf("valid permission request rejected: %v", err)
	}
	roleAware := valid
	roleAware.Tool = "mcp__filesystem__move_file"
	roleAware.Input = Input{
		Command: "structured-tool-input", Paths: []string{"a/source", "z/destination"},
		SourcePath: "a/source", DestinationPath: "z/destination",
	}
	if err := ValidateRequest(roleAware); err != nil {
		t.Fatalf("valid role-aware move rejected: %v", err)
	}
	encoded, err := json.Marshal(roleAware)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip Request
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if roundTrip.Input.SourcePath != "a/source" || roundTrip.Input.DestinationPath != "z/destination" {
		t.Fatalf("move roles lost in JSON round trip: %#v", roundTrip.Input)
	}

	cases := map[string]Request{
		"schema":  {Host: "codex", Event: "PreToolUse", Tool: "bash", CWD: "/workspace", Input: Input{Command: "true"}},
		"host":    {Schema: RequestSchemaV1, Event: "PreToolUse", Tool: "bash", CWD: "/workspace", Input: Input{Command: "true"}},
		"event":   {Schema: RequestSchemaV1, Host: "codex", Event: "post_tool_use", Tool: "bash", CWD: "/workspace", Input: Input{Command: "true"}},
		"tool":    {Schema: RequestSchemaV1, Host: "codex", Event: "PreToolUse", CWD: "/workspace", Input: Input{Command: "true"}},
		"cwd":     {Schema: RequestSchemaV1, Host: "codex", Event: "PreToolUse", Tool: "bash", Input: Input{Command: "true"}},
		"payload": {Schema: RequestSchemaV1, Host: "codex", Event: "PreToolUse", Tool: "bash", CWD: "/workspace"},
		"blank_path": {
			Schema: RequestSchemaV1,
			Host:   "codex",
			Event:  "PreToolUse",
			Tool:   "read_file",
			CWD:    "/workspace",
			Input:  Input{Paths: []string{" \t"}},
		},
		"blank_source_path": {
			Schema: RequestSchemaV1, Host: "codex", Event: "PreToolUse", Tool: "move_file", CWD: "/workspace",
			Input: Input{Command: "structured-tool-input", Paths: []string{" \t", "out"}, SourcePath: " \t", DestinationPath: "out"},
		},
		"role_path_not_projected": {
			Schema: RequestSchemaV1, Host: "codex", Event: "PreToolUse", Tool: "move_file", CWD: "/workspace",
			Input: Input{Command: "structured-tool-input", Paths: []string{"out"}, SourcePath: "source", DestinationPath: "out"},
		},
		"nul_destination_path": {
			Schema: RequestSchemaV1, Host: "codex", Event: "PreToolUse", Tool: "move_file", CWD: "/workspace",
			Input: Input{Command: "structured-tool-input", Paths: []string{"source", "out\x00"}, SourcePath: "source", DestinationPath: "out\x00"},
		},
	}
	for name, req := range cases {
		req := req
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateRequest(req); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestAuditSchemaDecisionKeyMatchesPersistedEvent(t *testing.T) {
	t.Parallel()

	field, ok := reflect.TypeOf(audit.Event{}).FieldByName("Decision")
	if !ok {
		t.Fatal("audit.Event.Decision is missing")
	}
	key := strings.Split(field.Tag.Get("json"), ",")[0]
	if key != "ward_decision" {
		t.Fatalf("audit decision key = %q", key)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "ward-audit-event-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if _, exists := document.Properties[key]; !exists {
		t.Fatalf("audit schema lacks persisted key %q", key)
	}
	if _, exists := document.Properties["decision"]; exists {
		t.Fatal("audit schema contains stale decision key")
	}
	var permissionMode struct {
		Enum []string `json:"enum"`
	}
	if err := json.Unmarshal(document.Properties["permission_mode"], &permissionMode); err != nil {
		t.Fatal(err)
	}
	wantPermissionModes := []string{"default", "acceptEdits", "plan", "dontAsk", "bypassPermissions", "unknown"}
	if !reflect.DeepEqual(permissionMode.Enum, wantPermissionModes) {
		t.Fatalf("permission_mode enum = %q, want %q", permissionMode.Enum, wantPermissionModes)
	}
	for _, forbidden := range []string{"command", "path", "paths", "cwd", "environment", "tool_input", "tool_response", "transcript"} {
		if _, exists := document.Properties[forbidden]; exists {
			t.Errorf("audit schema permits raw field %q", forbidden)
		}
	}
}

func TestMachineSchemaNames(t *testing.T) {
	t.Parallel()

	want := map[string]string{
		"request":     "ward-request/v1",
		"decision":    "ward-decision/v1",
		"audit_event": "ward-audit-event/v1",
		"doctor":      "ward-doctor/v1",
	}
	got := map[string]string{
		"request":     RequestSchemaV1,
		"decision":    DecisionSchemaV1,
		"audit_event": AuditEventSchemaV1,
		"doctor":      DoctorSchemaV1,
	}
	for name, expected := range want {
		if got[name] != expected {
			t.Errorf("%s schema = %q, want %q", name, got[name], expected)
		}
	}
}

func TestMachineSchemaDocumentsUseCanonicalNames(t *testing.T) {
	t.Parallel()

	documents := map[string]string{
		"ward-request-v1.schema.json":     RequestSchemaV1,
		"ward-decision-v1.schema.json":    DecisionSchemaV1,
		"ward-audit-event-v1.schema.json": AuditEventSchemaV1,
		"ward-doctor-v1.schema.json":      DoctorSchemaV1,
	}
	for filename, expected := range documents {
		filename, expected := filename, expected
		t.Run(filename, func(t *testing.T) {
			t.Parallel()
			raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", filename))
			if err != nil {
				t.Fatal(err)
			}
			var document struct {
				Properties struct {
					Schema struct {
						Const string `json:"const"`
					} `json:"schema"`
				} `json:"properties"`
			}
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatal(err)
			}
			if document.Properties.Schema.Const != expected {
				t.Fatalf("schema const = %q, want %q", document.Properties.Schema.Const, expected)
			}
		})
	}
}

func TestReadmeFreshSourceInstallGuardsStableBinaryBeforeBuild(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	readme := string(raw)
	sectionStart := strings.Index(readme, "## Build and install from source")
	sectionEnd := strings.Index(readme, "## CLI")
	if sectionStart < 0 || sectionEnd <= sectionStart {
		t.Fatal("README source-install section is missing")
	}
	section := readme[sectionStart:sectionEnd]
	normalizedSection := strings.Join(strings.Fields(section), " ")
	for _, required := range []string{
		"This source flow is fresh-install-only.",
		"Update an existing installation with the tagged transactional installer instead:",
		"./install.sh --version vX.Y.Z",
		`.\install.ps1 -Version vX.Y.Z`,
	} {
		if !strings.Contains(normalizedSection, required) {
			t.Fatalf("README source-install contract lacks %q", required)
		}
	}

	assertOrder := func(name string, markers ...string) {
		t.Helper()
		cursor := 0
		for _, marker := range markers {
			index := strings.Index(section[cursor:], marker)
			if index < 0 {
				t.Fatalf("%s source-install contract lacks %q", name, marker)
			}
			cursor += index + len(marker)
		}
	}
	assertOrder("POSIX",
		`ward_bin="${CODEX_HOME:-$HOME/.codex}/ward/bin/ward"`,
		`if [ -e "$ward_bin" ] || [ -L "$ward_bin" ]; then`,
		"exit 1",
		`ward_dir=$(dirname "$ward_bin")`,
		`ward_candidate=$(mktemp "$ward_dir/.ward-source-build.XXXXXX")`,
		`go build -o "$ward_candidate" ./cmd/ward`,
		`ln "$ward_candidate" "$ward_bin"`,
	)
	assertOrder("PowerShell",
		`$wardBin = Join-Path $codexDir 'ward\bin\ward.exe'`,
		`Get-Item -Force -LiteralPath $wardBin -ErrorAction SilentlyContinue`,
		`if ($null -ne $existingWard)`,
		"throw 'Ward is already installed;",
		`$wardCandidate = Join-Path $wardDir`,
		`go build -o $wardCandidate ./cmd/ward`,
		`[System.IO.File]::Move($wardCandidate, $wardBin)`,
	)
	for _, forbidden := range []string{
		`go build -o "$ward_bin"`,
		`go build -o $wardBin`,
	} {
		if strings.Contains(section, forbidden) {
			t.Fatalf("README source-install contract writes directly to the stable binary with %q", forbidden)
		}
	}
}

func TestReadmeDistinguishesDirectCLIAndHookMalformedInput(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	normalized := strings.Join(strings.Fields(string(raw)), " ")
	for _, required := range []string{
		"Malformed or unavailable machine input for direct CLI commands such as `ward evaluate`.",
		"Malformed event payloads delivered to recognized Hook commands are handled by the adapter instead of exit `3`.",
		"Malformed `PreToolUse` input is silent, records no audit event, returns the request to the Host permission flow, and exits `0`.",
		"Malformed `SessionStart` input emits one bounded, redacted warning and exits `0` unless writing that warning itself fails with runtime exit `1`.",
		"The hidden legacy PermissionRequest and PostToolUse commands are silent exit-`0` no-ops.",
		"Hook name or argument errors remain CLI usage exit `2`.",
	} {
		if !strings.Contains(normalized, required) {
			t.Fatalf("README malformed-input contract lacks %q", required)
		}
	}
}

func TestDecisionJSONNeverHasAllowOutcome(t *testing.T) {
	t.Parallel()

	decisions := []Decision{
		Deny("WARD_TEST", "Denied by test."),
		Defer("Host policy remains authoritative."),
		DeferWithGap("Coverage gap.", "dynamic_input", "Dynamic input is not classified."),
		ErrorDecision("invalid_request", "Canonical request is invalid."),
	}
	for _, decision := range decisions {
		encoded, err := json.Marshal(decision)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded["outcome"] == "allow" {
			t.Fatalf("Ward must never grant host permission: %s", encoded)
		}
	}
}

func TestDenyRecoveryRemainsWireOptional(t *testing.T) {
	t.Parallel()

	legacy, err := json.Marshal(Deny("WARD_TEST", "Denied by test."))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(legacy), `"recovery"`) {
		t.Fatalf("legacy deny unexpectedly requires recovery: %s", legacy)
	}
	current, err := json.Marshal(Deny("WARD_TEST", "Denied by test.", "Use a reversible test operation."))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(current), `"recovery":"Use a reversible test operation."`) {
		t.Fatalf("deny recovery was not serialized: %s", current)
	}
}
