package contract

import (
	"encoding/json"
	"testing"
)

func TestValidateRequest(t *testing.T) {
	t.Parallel()

	valid := Request{
		Tool:  "bash",
		CWD:   "/workspace",
		Input: Input{Command: "cat README.md"},
	}
	if err := ValidateRequest(valid); err != nil {
		t.Fatalf("valid request rejected: %v", err)
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
		"tool":    {CWD: "/workspace", Input: Input{Command: "true"}},
		"cwd":     {Tool: "bash", Input: Input{Command: "true"}},
		"payload": {Tool: "bash", CWD: "/workspace"},
		"blank_path": {
			Tool:  "delete_file",
			CWD:   "/workspace",
			Input: Input{Paths: []string{" \t"}},
		},
		"blank_source_path": {
			Tool: "move_file", CWD: "/workspace",
			Input: Input{Command: "structured-tool-input", Paths: []string{" \t", "out"}, SourcePath: " \t", DestinationPath: "out"},
		},
		"role_path_not_projected": {
			Tool: "move_file", CWD: "/workspace",
			Input: Input{Command: "structured-tool-input", Paths: []string{"out"}, SourcePath: "source", DestinationPath: "out"},
		},
		"nul_destination_path": {
			Tool: "move_file", CWD: "/workspace",
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

func TestDecisionJSONNeverHasAllowOrAskOutcome(t *testing.T) {
	t.Parallel()

	decisions := []Decision{
		Deny("WARD_TEST", "Denied by test.", "Use a reversible test operation."),
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
		for _, forbidden := range []string{"allow", "ask"} {
			if decoded["outcome"] == forbidden {
				t.Fatalf("Ward must never emit %q: %s", forbidden, encoded)
			}
		}
	}
}
