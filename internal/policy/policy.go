// Package policy validates Ward's fixed v0.1 kernel policy document.
//
// The ambient kernel is intentionally not runtime-extensible: command and
// path deny lists caused broad false denials in the legacy harness. The only
// accepted document is therefore the versioned, schema-only marker shipped
// with Ward. Boundary inputs are supplied directly to the evaluator instead
// of being read from TOML.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/pelletier/go-toml/v2"
)

const (
	SchemaV1       = "ward.policy.v1"
	maxPolicyBytes = 1 << 20
)

// Policy is an opaque validation result for the fixed kernel policy.
type Policy struct {
	schema string
}

type policyFile struct {
	Schema string `toml:"schema"`
}

// Default returns Ward's fixed, non-configurable kernel policy marker.
func Default() Policy {
	return Policy{schema: SchemaV1}
}

// Load validates a schema-only Ward kernel policy document. Unknown fields,
// including the former deny.paths and deny.commands extensions, are rejected.
func Load(r io.Reader) (Policy, error) {
	if r == nil {
		return Policy{}, errors.New("policy input is unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(r, maxPolicyBytes+1))
	if err != nil {
		return Policy{}, fmt.Errorf("read policy: %w", err)
	}
	if len(data) > maxPolicyBytes {
		return Policy{}, errors.New("policy exceeds size limit")
	}
	var raw policyFile
	decoder := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return Policy{}, fmt.Errorf("decode policy: %w", err)
	}
	if raw.Schema != SchemaV1 {
		return Policy{}, fmt.Errorf("unsupported policy schema %q", raw.Schema)
	}
	return Default(), nil
}

// LoadAdditive is retained as a source-compatible validator for callers from
// the pre-kernel prototype. It no longer accepts or applies additive rules.
func LoadAdditive(r io.Reader) (Policy, error) {
	return Load(r)
}

// Valid reports whether a policy was constructed by this package.
func (p Policy) Valid() bool {
	return p.schema == SchemaV1
}
