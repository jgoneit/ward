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
	loaded, err := LoadAdditive(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Valid() {
		t.Fatal("default policy document produced invalid policy")
	}
}

func TestDefaultPolicyExactEnvTemplateExceptions(t *testing.T) {
	t.Parallel()

	policy := Default()
	allowed := []string{
		".env.example",
		"config/.env.sample",
		"deep/.env.template",
		".env.dist",
	}
	for _, candidate := range allowed {
		if ruleID, denied := policy.MatchProtectedPath(candidate); denied {
			t.Errorf("public template %q denied by %s", candidate, ruleID)
		}
	}

	denied := []string{
		".env",
		".env.local",
		"deep/.env.production",
		".env.example.bak",
		"key.json",
		"tls/private.pem",
		"tls/private-key.pem",
		"tls/privkey1.pem",
		"~/.ssh/id_ecdsa",
		"~/.aws/credentials",
		"/Users/example/.aws/credentials",
		"~/.config/gh/hosts.yml",
		"/home/example/.config/gh/hosts.yml",
		"~/.config/gcloud/credentials.db",
		"~/.config/gcloud/application_default_credentials.json",
		"~/.docker/config.json",
		"C:/Users/example/.docker/config.json",
		"~/.npmrc",
		"/Users/example/.pypirc",
		"/home/example/.netrc",
		"C:/Users/example/.git-credentials",
		"build/customer-service_account-prod.json",
		"deploy/prod-credentials.yaml",
		"certs/server-key.pem",
		"certs/server.key",
		"certs/client.p12",
		"certs/client.pfx",
		"keys/id_rsa",
		"keys/id_dsa",
		"keys/id_ed25519",
		"deploy/acme-service-account-prod.json",
		"deploy/acme_service_account_prod.json",
		"deploy/acme.key.json",
	}
	for _, candidate := range denied {
		if _, protected := policy.MatchProtectedPath(candidate); !protected {
			t.Errorf("protected path %q was not denied", candidate)
		}
	}
}

func TestOrdinaryConfigFilesRemainUnclassified(t *testing.T) {
	t.Parallel()

	policy := Default()
	for _, candidate := range []string{
		"config.json",
		"application.yml",
		"docker-compose.yml",
		"config/hosts.yml",
		"project/.npmrc",
		"project/.pypirc",
		"keys/id_rsa.pub",
		"certs/public.pem.example",
		"certs/server.pem",
		"certs/ca.pem",
		"certs/public-key.pem",
		"certs/private-notes.pem",
		"certs/private-certificate.pem",
		"docs/credentials-format.md",
		"schemas/user-credential.json",
		".aws/credentials",
		"testdata/gh/hosts.yml",
		"fixtures/docker/config.json",
		"fixtures/.docker/config.json",
		"testdata/kube/config",
		"repo/root/.npmrc",
		"@.env",
	} {
		if ruleID, denied := policy.MatchProtectedPath(candidate); denied {
			t.Errorf("ordinary config %q denied by %s", candidate, ruleID)
		}
	}
}

func TestRuntimeExactProtectedPathsAreAbsoluteAndExact(t *testing.T) {
	t.Parallel()

	active, err := WithExactProtectedPaths(Default(), []string{
		"/tmp/custom-gh/hosts.yml",
		"C:/Users/Example/AppData/Roaming/gcloud/credentials.db",
		"/tmp/custom-gh/hosts.yml",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{
		"/tmp/custom-gh/hosts.yml",
		"c:/users/example/appdata/roaming/gcloud/credentials.db",
	} {
		if ruleID, denied := active.MatchProtectedPath(candidate); !denied || ruleID != "WARD_SECRET_PATH" {
			t.Errorf("runtime exact path %q was not denied: %q", candidate, ruleID)
		}
	}
	for _, candidate := range []string{
		"testdata/custom-gh/hosts.yml",
		"/tmp/custom-gh/hosts.yml.example",
		"/tmp/other/hosts.yml",
	} {
		if ruleID, denied := active.MatchProtectedPath(candidate); denied {
			t.Errorf("runtime exact near-miss %q denied by %s", candidate, ruleID)
		}
	}
	for _, candidate := range []string{"relative/hosts.yml", "~/hosts.yml", ""} {
		if _, err := WithExactProtectedPaths(Default(), []string{candidate}); err == nil {
			t.Errorf("non-absolute runtime path %q was accepted", candidate)
		}
	}
}

func TestRuntimeExactProtectedPathAncestorsAreNarrow(t *testing.T) {
	t.Parallel()

	active, err := WithExactProtectedPaths(Default(), []string{
		"/home/example/.config/gh/hosts.yml",
		"C:/Users/Example/.docker/config.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{
		"/home/example/.config/gh",
		"/home/example/.config",
		"c:/users/example/.DOCKER",
	} {
		if ruleID, denied := active.MatchProtectedPathOrAncestor(candidate); !denied || ruleID != "WARD_SECRET_PATH" {
			t.Errorf("runtime exact ancestor %q was not denied: %q", candidate, ruleID)
		}
	}
	for _, candidate := range []string{
		"/home/example/.cache",
		"/home/example/.config-other",
		"C:/Users/Example/docker-fixture",
	} {
		if ruleID, denied := active.MatchProtectedPathOrAncestor(candidate); denied {
			t.Errorf("unrelated runtime path %q denied by %s", candidate, ruleID)
		}
	}
}

func TestRuntimeExactProtectedPathsSurviveAdditiveExtension(t *testing.T) {
	t.Parallel()

	active, err := WithExactProtectedPaths(Default(), []string{"/tmp/runtime-credential"})
	if err != nil {
		t.Fatal(err)
	}
	active, err = ExtendAdditive(active, strings.NewReader(`
schema = "ward.policy.v1"

[deny]
paths = ["**/company-secret.json"]
`))
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{"/tmp/runtime-credential", "nested/company-secret.json"} {
		if _, denied := active.MatchProtectedPath(candidate); !denied {
			t.Errorf("protected path %q was lost after extension", candidate)
		}
	}
}

func TestAdditivePolicyCannotExpressAllowOrException(t *testing.T) {
	t.Parallel()

	bad := []string{
		"schema = 'ward.policy.v1'\n[allow]\npaths = ['**/.env']\n",
		"schema = 'ward.policy.v1'\npublic_templates = ['**/.env.local']\n",
		"schema = 'ward.policy.v1'\nmode = 'disabled'\n",
	}
	for _, input := range bad {
		if _, err := LoadAdditive(strings.NewReader(input)); err == nil {
			t.Fatalf("non-additive policy was accepted:\n%s", input)
		}
	}
}

func TestAdditivePolicyIsMonotonic(t *testing.T) {
	t.Parallel()

	first, err := LoadAdditive(strings.NewReader(`
schema = "ward.policy.v1"

[deny]
paths = ["**/company-secret.json"]
`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := ExtendAdditive(first, strings.NewReader(`
schema = "ward.policy.v1"

[deny]
paths = ["**/.env.example"]

[[deny.commands]]
id = "CUSTOM_ACME_DESTROY"
executable = "acme"
args_prefix = ["destroy"]
`))
	if err != nil {
		t.Fatal(err)
	}

	for _, candidate := range []string{".env", "nested/company-secret.json", "nested/.env.example"} {
		if _, denied := second.MatchProtectedPath(candidate); !denied {
			t.Errorf("monotonic deny was lost for %q", candidate)
		}
	}
	rules := second.CommandRules()
	if len(rules) != 1 || rules[0].ID != "CUSTOM_ACME_DESTROY" {
		t.Fatalf("unexpected command rules: %#v", rules)
	}
}

func TestAdditiveCommandValidation(t *testing.T) {
	t.Parallel()

	input := `
schema = "ward.policy.v1"

[[deny.commands]]
id = "WARD_MAY_NOT_OVERRIDE_BUILTIN"
executable = "acme"
args_prefix = ["destroy"]
`
	if _, err := LoadAdditive(strings.NewReader(input)); err == nil {
		t.Fatal("reserved/non-custom rule id was accepted")
	}
}
