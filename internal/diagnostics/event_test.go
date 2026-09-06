package diagnostics

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func exampleEvent() Event {
	return Event{Schema: EventSchema, Version: "0.1.0-dev.0", Tool: "bash", Stage: "evaluate", Outcome: "defer", DurationUS: 42}
}

func TestEventRedactionAndStrictFields(t *testing.T) {
	event := exampleEvent()
	path := "/home/person/private.env"
	id := "call_123-abc"
	event.SessionID = &path
	event.ToolUseID = &id
	data, err := marshalEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(path)) || !bytes.Contains(data, []byte(`"session_id":null`)) || !bytes.Contains(data, []byte(`"turn_id":null`)) {
		t.Fatalf("unsafe/missing null metadata: %s", data)
	}
	decoded, err := decodeEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.ToolUseID == nil || *decoded.ToolUseID != id {
		t.Fatal("lost bounded identifier")
	}
	for _, mutate := range []func(*Event){
		func(e *Event) { e.ErrorCode = "secret_password" },
		func(e *Event) { e.GapCode = "custom_payload" },
		func(e *Event) { e.RuleID = "WARD_UNKNOWN" },
		func(e *Event) { e.Tool = "curl https://example.test/private" },
		func(e *Event) { e.DurationUS = -1 },
	} {
		event := exampleEvent()
		mutate(&event)
		if _, err := marshalEvent(event); err == nil {
			t.Fatal("accepted non-catalog event")
		}
	}
	bad := [][]byte{
		bytes.Replace(data, []byte(`"tool":"bash"`), []byte(`"tool":"bash","tool":"cmd"`), 1),
		bytes.Replace(data, []byte(`"duration_us":42`), []byte(`"duration_us":null`), 1),
		append(append([]byte(nil), data...), []byte("{}")...),
		bytes.Replace(data, []byte(`"schema":`), []byte(`"command":"private","schema":`), 1),
		bytes.Replace(data, []byte(`"schema":`), []byte(`"Rule_ID":"WARD_DESTRUCTIVE_GIT","schema":`), 1),
		bytes.Replace(data, []byte(`"schema":`), []byte(`"ERROR_CODE":"input_read","schema":`), 1),
		bytes.Replace(data, []byte(`"schema":`), []byte(`"error_code":null,"schema":`), 1),
		[]byte(`{"schema":"ward-diagnostic-event/v1"}`),
	}
	for _, payload := range bad {
		if _, err := decodeEvent(payload); err == nil {
			t.Fatalf("accepted invalid event: %s", payload)
		}
	}
}

func TestDiagnosticCatalogCoversEvaluator(t *testing.T) {
	paths, err := filepath.Glob("../evaluator/*.go")
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`(gap|ErrorDecision)\("([^"]+)"`)
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range pattern.FindAllSubmatch(data, -1) {
			catalog := gapsAllowed
			if string(match[1]) == "ErrorDecision" {
				catalog = errorsAllowed
			}
			if !catalog[string(match[2])] {
				t.Errorf("%s diagnostic code missing: %s", path, match[2])
			}
		}
	}
}

func TestPacketAuthenticatesBoundedPayloadAndGeneration(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	generation := strings.Repeat("a", 32)
	payload, err := marshalEvent(exampleEvent())
	if err != nil {
		t.Fatal(err)
	}
	data, err := encodePacket(key, generation, "event", payload)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodePacket(data, key, generation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeEvent(decoded.Payload); err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(data, []byte(`"outcome":"defer"`), []byte(`"outcome":"error"`), 1)
	if _, err := decodePacket(changed, key, generation); err == nil {
		t.Fatal("accepted modified event")
	}
	if _, err := decodePacket(data, key, strings.Repeat("b", 32)); err == nil {
		t.Fatal("accepted stale generation")
	}
	if _, err := decodePacket(bytes.Repeat([]byte{'x'}, MaxPacketBytes+1), key, generation); err == nil {
		t.Fatal("accepted oversized packet")
	}
	large, _ := json.Marshal(strings.Repeat("x", MaxPacketBytes))
	if _, err := encodePacket(key, generation, "event", large); err == nil {
		t.Fatal("encoded oversized packet")
	}
}
