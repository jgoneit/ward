package diagnostics

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

const packetSchema = "ward-diagnostic-packet/v1"

type packet struct {
	Schema     string          `json:"schema"`
	Generation string          `json:"generation"`
	Kind       string          `json:"kind"`
	Payload    json.RawMessage `json:"payload"`
	MAC        string          `json:"mac"`
}

func packetMAC(key []byte, generation, kind string, payload []byte) []byte {
	hash := hmac.New(sha256.New, key)
	_, _ = hash.Write([]byte(packetSchema + "\x00" + generation + "\x00" + kind + "\x00"))
	_, _ = hash.Write(payload)
	return hash.Sum(nil)
}

func encodePacket(key []byte, generation, kind string, payload []byte) ([]byte, error) {
	if len(key) != 32 || !validHex(generation, 16) {
		return nil, errors.New("invalid_packet_identity")
	}
	data, err := json.Marshal(packet{packetSchema, generation, kind, payload, hex.EncodeToString(packetMAC(key, generation, kind, payload))})
	if err != nil {
		return nil, err
	}
	if len(data) > MaxPacketBytes {
		return nil, errors.New("packet_too_large")
	}
	return data, nil
}

func decodePacket(data, key []byte, generation string) (packet, error) {
	var result packet
	if len(data) > MaxPacketBytes || len(key) != 32 {
		return result, errors.New("invalid_packet")
	}
	if err := strictJSON(data, &result); err != nil {
		return result, errors.New("invalid_packet")
	}
	if result.Schema != packetSchema || result.Generation != generation ||
		(result.Kind != "event" && result.Kind != "probe" && result.Kind != "probe_reply") {
		return packet{}, errors.New("invalid_packet")
	}
	mac, err := hex.DecodeString(result.MAC)
	if err != nil || len(mac) != sha256.Size || !hmac.Equal(mac, packetMAC(key, result.Generation, result.Kind, result.Payload)) {
		return packet{}, errors.New("invalid_packet_mac")
	}
	return result, nil
}

func decodeEvent(data []byte) (Event, error) {
	var event Event
	if err := strictJSON(data, &event); err != nil {
		return event, errors.New("invalid_diagnostic_event")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return Event{}, err
	}
	allowed := stringSet("schema", "ward_version", "tool", "stage", "outcome", "rule_id", "error_code", "gap_code", "duration_us", "session_id", "turn_id", "tool_use_id")
	for name, value := range fields {
		if !allowed[name] {
			return Event{}, errors.New("unknown_event_field")
		}
		if (name == "rule_id" || name == "error_code" || name == "gap_code") && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return Event{}, errors.New("invalid_diagnostic_event")
		}
	}
	for _, name := range []string{"schema", "ward_version", "tool", "stage", "outcome", "duration_us", "session_id", "turn_id", "tool_use_id"} {
		if _, exists := fields[name]; !exists {
			return Event{}, errors.New("missing_event_field")
		}
	}
	if event.Schema != EventSchema || event.Tool == "" || bytes.Equal(bytes.TrimSpace(fields["duration_us"]), []byte("null")) {
		return Event{}, errors.New("invalid_diagnostic_event")
	}
	return normalizeEvent(event)
}

func validHex(value string, bytes int) bool {
	if len(value) != bytes*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == bytes
}

// strictJSON rejects duplicate keys, extra fields, trailing values, and deeply
// nested values before typed decoding. All callers separately bound input size.
func strictJSON(data []byte, into any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := checkJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing_json")
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(into)
}

func checkJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 8 {
		return errors.New("json_depth")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := map[string]bool{}
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok || keys[key] {
				return errors.New("duplicate_json_key")
			}
			keys[key] = true
			if err := checkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid_json")
		}
	case '[':
		for decoder.More() {
			if err := checkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid_json")
		}
	default:
		return errors.New("invalid_json")
	}
	return nil
}
