package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultPolicyDocumentLoads(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "policies", "default.toml"))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Valid() {
		t.Fatal("default policy document produced invalid policy")
	}
}

func TestDefaultPolicyIsFixed(t *testing.T) {
	t.Parallel()

	if !Default().Valid() {
		t.Fatal("embedded policy is invalid")
	}
	for _, input := range []string{
		"schema = 'ward.policy.v1'\n[deny]\npaths = ['**/.env']\n",
		"schema = 'ward.policy.v1'\n[[deny.commands]]\nid = 'CUSTOM_ACME_DESTROY'\nexecutable = 'acme'\nargs_prefix = ['destroy']\n",
		"schema = 'ward.policy.v1'\n[allow]\npaths = ['**/.env']\n",
		"schema = 'ward.policy.v1'\nmode = 'disabled'\n",
	} {
		if _, err := Load(strings.NewReader(input)); err == nil {
			t.Fatalf("runtime policy extension was accepted:\n%s", input)
		}
	}
}

func TestLoadAdditiveCompatibilityNameCannotExtendPolicy(t *testing.T) {
	t.Parallel()

	loaded, err := LoadAdditive(strings.NewReader("schema = 'ward.policy.v1'\n"))
	if err != nil || !loaded.Valid() {
		t.Fatalf("schema-only compatibility load failed: policy=%#v err=%v", loaded, err)
	}
	if _, err := LoadAdditive(strings.NewReader("schema = 'ward.policy.v1'\n[deny]\npaths = ['**/.env']\n")); err == nil {
		t.Fatal("compatibility loader accepted an additive deny")
	}
}

func TestPolicyRejectsMalformedUnsupportedAndOversizedDocuments(t *testing.T) {
	t.Parallel()

	for _, input := range []string{
		"",
		"schema = 'ward.policy.v999'\n",
		"schema = [\n",
	} {
		if _, err := Load(strings.NewReader(input)); err == nil {
			t.Fatalf("invalid policy was accepted: %q", input)
		}
	}
	if _, err := Load(strings.NewReader(strings.Repeat("x", maxPolicyBytes+1))); err == nil {
		t.Fatal("oversized policy was accepted")
	}
	if _, err := Load(nil); err == nil {
		t.Fatal("nil policy reader was accepted")
	}
}
