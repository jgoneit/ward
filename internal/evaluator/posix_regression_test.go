package evaluator

import (
	"testing"

	"github.com/jgoneit/ward/internal/contract"
)

func staticArgs(values ...string) []literalArg {
	args := make([]literalArg, len(values))
	for index, value := range values {
		args[index] = literalArg{value: value, static: true}
	}
	return args
}

func TestReviewedGitNegatedOptionPrecedence(t *testing.T) {
	tests := []struct {
		name string
		args []literalArg
		want bool
	}{
		{"clean final dry run", staticArgs("clean", "-fd", "--no-dry-run", "--dry-run"), false},
		{"clean final non dry run", staticArgs("clean", "-fd", "--dry-run", "--no-dry-run"), true},
		{"clean final no force", staticArgs("clean", "-fd", "--no-force"), false},
		{"clean final force", staticArgs("clean", "-d", "--no-force", "--force"), true},
		{"push final no force", staticArgs("push", "--force", "--no-force", "origin", "main"), false},
		{"push final force", staticArgs("push", "--no-force", "--force", "origin", "main"), true},
		{"push final no mirror", staticArgs("push", "--mirror", "--no-mirror", "origin"), false},
		{"push final mirror", staticArgs("push", "--no-mirror", "--mirror", "origin"), true},
		{"push final dry run", staticArgs("push", "--force", "--no-dry-run", "--dry-run", "origin", "main"), false},
		{"push final non dry run", staticArgs("push", "--force", "--dry-run", "--no-dry-run", "origin", "main"), true},
		{"push progress does not hide forced refspec", staticArgs("push", "--no-progress", "origin", "+main"), true},
		{"push no recurse submodules preserves force", staticArgs("push", "--no-recurse-submodules", "--force", "origin", "main"), true},
		{"push signed true preserves force", staticArgs("push", "--signed=true", "--force", "origin", "main"), true},
		{"push recurse submodules only preserves force", staticArgs("push", "--recurse-submodules=only", "--force", "origin", "main"), true},
		{"push no repo resets repository position", staticArgs("push", "--repo=origin", "--no-repo", "+main"), false},
		{"push short cluster preserves force", staticArgs("push", "-vf", "origin", "main"), true},
		{"push short cluster preserves dry run", staticArgs("push", "-vfn", "origin", "main"), false},
		{"force with lease remains host controlled", staticArgs("push", "--no-progress", "--force-with-lease", "origin", "main"), false},
		{"reset no patch", staticArgs("reset", "--hard", "--no-patch"), true},
		{"reset canceled patch", staticArgs("reset", "--patch", "--no-patch", "--hard"), true},
		{"reset final hard mode", staticArgs("reset", "--soft", "--hard", "HEAD"), true},
		{"reset final soft mode", staticArgs("reset", "--hard", "--soft", "HEAD"), false},
		{"reset final canceled patch", staticArgs("reset", "--hard", "--patch", "--no-patch", "HEAD"), true},
		{"reset patch conflicts with hard", staticArgs("reset", "--hard", "--patch", "HEAD"), false},
		{"reset negated pathspec options", staticArgs("reset", "--hard", "--no-pathspec-from-file", "--no-pathspec-file-nul"), true},
		{"reset empty separate pathspec file", staticArgs("reset", "--hard", "--pathspec-from-file", "", "--pathspec-file-nul"), false},
		{"reset empty assigned pathspec file", staticArgs("reset", "--hard", "--pathspec-from-file=", "--pathspec-file-nul"), false},
		{"reset empty separate pathspec without nul", staticArgs("reset", "--hard", "--pathspec-from-file", ""), true},
		{"reset empty assigned pathspec without nul", staticArgs("reset", "--hard", "--pathspec-from-file="), true},
		{"reset positive pathspec nul without source", staticArgs("reset", "--hard", "--pathspec-file-nul"), false},
		{"reset negated pathspec nul without source", staticArgs("reset", "--hard", "--no-pathspec-file-nul"), true},
		{"reset final negated pathspec nul without source", staticArgs("reset", "--hard", "--pathspec-file-nul", "--no-pathspec-file-nul"), true},
		{"reset final absent pathspec source", staticArgs("reset", "--hard", "--pathspec-from-file=x", "--no-pathspec-from-file", "--pathspec-file-nul"), false},
		{"reset final no auto advance requires patch", staticArgs("reset", "--hard", "--auto-advance", "--no-auto-advance"), false},
		{"reset final auto advance permits hard", staticArgs("reset", "--hard", "--no-auto-advance", "--auto-advance"), true},
		{"reset recurse submodules yes", staticArgs("reset", "--hard", "--recurse-submodules=YES"), true},
		{"reset recurse submodules off", staticArgs("reset", "--hard", "--recurse-submodules=off"), true},
		{"reset empty recurse submodules", staticArgs("reset", "--hard", "--recurse-submodules="), true},
		{"reset invalid recurse submodules", staticArgs("reset", "--hard", "--recurse-submodules=future"), false},
		{"reset abbreviated recurse submodules", staticArgs("reset", "--hard", "--recurse-submodules=t"), false},
		{"reset separate unified requires patch", staticArgs("reset", "--hard", "--unified", "3"), false},
		{"reset attached unified requires patch", staticArgs("reset", "--hard", "-U5"), false},
		{"reset inter hunk context requires patch", staticArgs("reset", "--hard", "--inter-hunk-context=2"), false},
		{"reset invalid unified", staticArgs("reset", "--hard", "--unified=future"), false},
		{"reset missing unified", staticArgs("reset", "--hard", "-U"), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := destructiveGit(test.args); got != test.want {
				t.Fatalf("destructiveGit() = %t, want %t", got, test.want)
			}
		})
	}

	args, optionGap := unwrapOperationGlobalOptions("git", staticArgs("--no-advice", "reset", "--hard"))
	if optionGap != nil || !destructiveGit(args) {
		t.Fatalf("reviewed Git global option lost hard reset: args=%#v gap=%#v", args, optionGap)
	}
}

func TestReviewedComposeGlobalOptions(t *testing.T) {
	tests := []struct {
		name    string
		args    []literalArg
		want    bool
		gapCode string
	}{
		{"compatibility", staticArgs("--compatibility", "down", "-v"), true, ""},
		{"all resources", staticArgs("--all-resources", "down", "-v"), true, ""},
		{"compatibility short true", staticArgs("--compatibility=t", "down", "-v"), true, ""},
		{"all resources short false", staticArgs("--all-resources=f", "down", "-v"), true, ""},
		{"progress separate", staticArgs("--progress", "plain", "down", "-v"), true, ""},
		{"progress assigned", staticArgs("--progress=json", "down", "-v"), true, ""},
		{"dry run remains non mutating", staticArgs("--compatibility", "--dry-run", "down", "-v"), false, ""},
		{"short false dry run remains mutating", staticArgs("--dry-run=f", "down", "-v"), true, ""},
		{"short true dry run remains non mutating", staticArgs("--dry-run=t", "down", "-v"), false, ""},
		{"short false remove orphans remains mutating", staticArgs("down", "-v", "--remove-orphans=f"), true, ""},
		{"invalid progress", staticArgs("--progress", "future", "down", "-v"), false, "unsupported_compose_option"},
		{"invalid compatibility", staticArgs("--compatibility=maybe", "down", "-v"), false, "unsupported_compose_option"},
		{"ansi case insensitive", staticArgs("--ansi", "Always", "down", "-v"), true, ""},
		{"parallel signed", staticArgs("--parallel", "+1", "down", "-v"), true, ""},
		{"empty default globals", staticArgs("--ansi=", "--progress=", "--project-directory=", "--project-name=", "--profile=", "down", "-v"), true, ""},
		{"terminator", staticArgs("down", "-v", "--"), true, ""},
		{"terminator service", staticArgs("down", "-v", "--", "-web"), true, ""},
		{"leading punctuation service", staticArgs("down", "-v", "_web", ".web"), true, ""},
		{"signed timeout", staticArgs("down", "-v", "--timeout", "+1"), true, ""},
		{"short volume timeout cluster", staticArgs("down", "-vt1"), true, ""},
		{"short volume timeout separate cluster", staticArgs("down", "-vt", "1"), true, ""},
		{"assigned short timeout", staticArgs("down", "-v", "-t=1"), true, ""},
		{"repeated volume cluster true", staticArgs("down", "-vv=true"), true, ""},
		{"repeated volume cluster false", staticArgs("down", "-vv=false"), false, ""},
		{"unescaped leading hyphen service", staticArgs("down", "-v", "-web"), false, "unsupported_compose_option"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, optionGap := destructiveCompose(test.args)
			if got != test.want {
				t.Fatalf("destructiveCompose() = %t, want %t", got, test.want)
			}
			if test.gapCode == "" && optionGap != nil || test.gapCode != "" && (optionGap == nil || optionGap.Code != test.gapCode) {
				t.Fatalf("gap = %#v, want %q", optionGap, test.gapCode)
			}
		})
	}
}

func TestDropSchemaCascadeAcceptsOnlyStrictSchemaLists(t *testing.T) {
	tests := []struct {
		statement string
		want      bool
	}{
		{"DROP SCHEMA one, two CASCADE", true},
		{"DROP SCHEMA IF EXISTS one, \"two words\" CASCADE;", true},
		{"DROP SCHEMA \"one,two\", three CASCADE", true},
		{"DROP SCHEMA \"a\"\"b\", c CASCADE", true},
		{"DROP SCHEMA one, two RESTRICT", false},
		{"DROP SCHEMA one-two CASCADE", false},
		{"DROP SCHEMA one.two CASCADE", false},
		{"DROP SCHEMA \"\" CASCADE", false},
		{"DROP SCHEMA one, CASCADE", false},
	}
	for _, test := range tests {
		if got := dropSchemaCascadeSQL.MatchString(test.statement); got != test.want {
			t.Errorf("dropSchemaCascadeSQL.MatchString(%q) = %t, want %t", test.statement, got, test.want)
		}
	}
}

func TestFindMindepthZeroAndOneDoNotNarrowWholeTreeDelete(t *testing.T) {
	tests := []struct {
		name string
		args []literalArg
		want bool
	}{
		{"zero", staticArgs(".", "-mindepth", "0", "-delete"), false},
		{"one", staticArgs(".", "-mindepth", "1", "-delete"), false},
		{"two", staticArgs(".", "-mindepth", "2", "-delete"), true},
		{"maximum depth", staticArgs(".", "-mindepth", "1", "-maxdepth", "1", "-delete"), true},
		{"name predicate", staticArgs(".", "-mindepth", "1", "-name", "*.tmp", "-delete"), true},
		{"final whole tree depth", staticArgs(".", "-mindepth", "2", "-mindepth", "0", "-delete"), false},
		{"final narrowed depth", staticArgs(".", "-mindepth", "0", "-mindepth", "2", "-delete"), true},
		{"leading zero one", staticArgs(".", "-mindepth", "0001", "-delete"), false},
		{"signed plus one", staticArgs(".", "-mindepth", "+1", "-delete"), false},
		{"signed plus two", staticArgs(".", "-mindepth", "+2", "-delete"), true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := findHasNarrowingExpression(test.args, "darwin"); got != test.want {
				t.Fatalf("findHasNarrowingExpression() = %t, want %t", got, test.want)
			}
		})
	}
	if findHasNarrowingExpression(staticArgs(".", "-mindepth", "18446744073709551616", "-delete"), "darwin") {
		t.Fatal("Darwin overflowing mindepth was treated as narrowing")
	}
	if !findHasNarrowingExpression(staticArgs(".", "-mindepth", "18446744073709551616", "-delete"), "linux") {
		t.Fatal("Linux overflowing mindepth was promoted to a whole-tree delete")
	}
}

func TestFindMindepthSignedValuesFollowHostSemantics(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		goos        string
		wantNarrows bool
		wantValid   bool
	}{
		{"Darwin plus zero", "+0", "darwin", false, true},
		{"Darwin plus one", "+1", "darwin", false, true},
		{"Darwin plus two", "+2", "darwin", true, true},
		{"Linux plus one", "+1", "linux", false, false},
		{"Linux plus two", "+2", "linux", false, false},
		{"Windows plus one", "+1", "windows", false, false},
		{"Windows plus two", "+2", "windows", false, false},
		{"Linux unsigned zero", "0", "linux", false, true},
		{"Linux unsigned one", "1", "linux", false, true},
		{"Linux unsigned two", "2", "linux", true, true},
		{"Darwin overflow", "18446744073709551616", "darwin", false, true},
		{"Linux overflow", "18446744073709551616", "linux", true, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotNarrows, gotValid := findMindepthNarrows(test.value, test.goos)
			if gotNarrows != test.wantNarrows || gotValid != test.wantValid {
				t.Fatalf("findMindepthNarrows(%q, %q) = (%t, %t), want (%t, %t)", test.value, test.goos, gotNarrows, gotValid, test.wantNarrows, test.wantValid)
			}
		})
	}
}

func TestLinuxFindSignedMindepthDefersUnsupportedValue(t *testing.T) {
	boundaries, err := ResolveBoundarySet(BoundaryOptions{
		CWD:              "/workspace",
		HomeDir:          "/home/alice",
		WardControlPaths: []string{"/home/alice/.local/state/ward/core"},
		GOOS:             "linux",
	})
	if err != nil {
		t.Fatal(err)
	}
	active, err := New(boundaries)
	if err != nil {
		t.Fatal(err)
	}

	unsigned := request("bash", "find . -mindepth 1 -delete")
	if got := active.Evaluate(unsigned); got.Outcome != contract.OutcomeDeny || got.RuleID != "WARD_DESTRUCTIVE_FILESYSTEM" {
		t.Fatalf("unsigned mindepth decision = %#v", got)
	}

	signed := request("bash", "find . -mindepth +1 -delete")
	if got := active.Evaluate(signed); got.Outcome != contract.OutcomeDefer || got.RuleID != "" || got.CoverageGap == nil || got.CoverageGap.Code != "find_command_action" {
		t.Fatalf("signed mindepth decision = %#v", got)
	}
}

func TestLinuxGNUmoveOptionsPreserveCriticalSourceClassification(t *testing.T) {
	boundaries, err := ResolveBoundarySet(BoundaryOptions{
		CWD:              "/workspace",
		HomeDir:          "/home/alice",
		WardControlPaths: []string{"/home/alice/.local/state/ward/core"},
		GOOS:             "linux",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Cross-platform tests cannot discover a Linux repository using the host
	// filesystem, so retain the trusted Git metadata boundary explicitly.
	boundaries.gitPaths = []string{"/workspace/.git"}
	active, err := New(boundaries)
	if err != nil {
		t.Fatal(err)
	}
	commands := []string{
		"mv --backup .git /tmp/x",
		"mv --backup= .git /tmp/x",
		"mv --backup=numbered .git /tmp/x",
		"mv --suffix .bak .git /tmp/x",
		"mv --suffix '' .git /tmp/x",
		"mv --suffix= .git /tmp/x",
		"mv --suffix=.bak .git /tmp/x",
		"mv --target-directory /tmp .git",
		"mv --target-directory=/tmp .git",
		"mv --target-d /tmp .git",
		"mv --target-di=/tmp .git",
		"mv -S.bak .git /tmp/x",
		"mv -S '' .git /tmp/x",
		"mv -vS '' .git /tmp/x",
		"mv -t/tmp .git",
		"mv -bv .git /tmp/x",
		"mv --backup /home/alice/.local/state/ward/core /tmp/x",
		"mv --exchange .git ordinary",
		"mv --exchange ordinary .git",
		"mv --exchange -T ordinary .git",
		"mv --exchange --target-directory=/tmp .git ordinary",
		"mv --exchange --target-directory=/workspace /tmp/.git",
		"mv -T .git ordinary",
		"mv -vT .git ordinary",
		"mv --backup=nu .git /tmp/x",
		"mv --update=o .git /tmp/x",
		"mv --update=none .git /tmp/x",
		"mv --update=none-fail .git /tmp/x",
		"mv --backup=none .git /tmp/x",
		"mv --backup -n -f .git /tmp/x",
		"mv --backup --update=none --update=all .git /tmp/x",
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			req := request("bash", command)
			req.CWD = "/workspace"
			if got := active.Evaluate(req); got.Outcome != contract.OutcomeDeny || got.RuleID != "WARD_DESTRUCTIVE_FILESYSTEM" {
				t.Fatalf("decision = %#v", got)
			}
		})
	}

	for _, command := range []string{
		"mv --backup build /tmp/x",
		"mv --backup=future .git /tmp/x",
		"mv --target-directory .git",
		"mv --exchange one two",
		"mv --backup=n .git /tmp/x",
		"mv --update=n .git /tmp/x",
		"mv --backup --exchange .git ordinary",
		"mv --backup -f -n .git /tmp/x",
		"mv --backup --update=all --update=none .git /tmp/x",
		"mv -t /tmp -t /var/tmp .git",
		"mv --exchange .git",
		"mv -T .git ordinary extra",
		"mv -vT .git ordinary extra",
		"mv -T .git",
		"mv --suffix",
		"mv --context= .git /tmp/x",
		"mv --context=foo .git /tmp/x",
	} {
		t.Run("defer "+command, func(t *testing.T) {
			req := request("bash", command)
			req.CWD = "/workspace"
			if got := active.Evaluate(req); got.Outcome != contract.OutcomeDefer {
				t.Fatalf("decision = %#v", got)
			}
		})
	}
}

func TestGNUmoveOptionsRemainUnsupportedOnDarwin(t *testing.T) {
	boundaries, err := ResolveBoundarySet(BoundaryOptions{CWD: "/workspace", HomeDir: "/Users/alice", GOOS: "darwin"})
	if err != nil {
		t.Fatal(err)
	}
	boundaries.gitPaths = []string{"/workspace/.git"}
	active, err := New(boundaries)
	if err != nil {
		t.Fatal(err)
	}
	req := request("bash", "mv --backup .git /tmp/x")
	if got := active.Evaluate(req); got.Outcome != contract.OutcomeDefer || got.CoverageGap == nil || got.CoverageGap.Code != "complex_move_operands" {
		t.Fatalf("decision = %#v", got)
	}
}

func TestReviewedKubectlDeleteOptionsAndResourceLists(t *testing.T) {
	tests := []struct {
		name    string
		args    []literalArg
		want    bool
		gapCode string
	}{
		{"namespace first", staticArgs("delete", "namespace,pod", "demo"), true, ""},
		{"namespace later", staticArgs("delete", "pod,namespace", "demo"), true, ""},
		{"interactive false", staticArgs("delete", "namespace", "demo", "--interactive=false"), true, ""},
		{"interactive short false", staticArgs("delete", "namespace", "demo", "-i=false"), true, ""},
		{"interactive short bare", staticArgs("delete", "namespace", "demo", "-i"), true, ""},
		{"interactive numeric false", staticArgs("delete", "namespace", "demo", "--interactive=0"), true, ""},
		{"boolean short cluster", staticArgs("delete", "namespace", "demo", "-Ai=false"), true, ""},
		{"boolean and verbosity cluster", staticArgs("delete", "namespace", "demo", "-iv4"), true, ""},
		{"attached namespace global", staticArgs("delete", "namespace", "demo", "-ndefault"), true, ""},
		{"interactive separate false remains positional", staticArgs("delete", "--interactive", "false", "namespace", "demo"), false, ""},
		{"cascade foreground", staticArgs("delete", "namespace", "demo", "--cascade=foreground"), true, ""},
		{"cascade separate", staticArgs("delete", "namespace", "demo", "--cascade", "orphan"), true, ""},
		{"all namespaces false", staticArgs("delete", "--all-namespaces=false", "namespace", "demo"), true, ""},
		{"bare dry run", staticArgs("delete", "namespace", "demo", "--dry-run"), false, ""},
		{"bare dry run leaves client positional", staticArgs("delete", "namespace", "demo", "--dry-run", "client"), false, ""},
		{"bare dry run leaves none positional", staticArgs("delete", "namespace", "demo", "--dry-run", "none"), false, ""},
		{"separate boolean remains bare dry run", staticArgs("delete", "namespace", "demo", "--dry-run", "false"), false, ""},
		{"final none dry run", staticArgs("delete", "namespace", "demo", "--dry-run=client", "--dry-run=none"), true, ""},
		{"numeric false dry run", staticArgs("delete", "namespace", "demo", "--dry-run=0"), true, ""},
		{"case variant dry run", staticArgs("delete", "namespace", "demo", "--dry-run=None"), false, "unsupported_kubectl_delete_option"},
		{"resource name tuples", staticArgs("delete", "pod/foo", "namespace/demo"), true, ""},
		{"mixed type and tuple", staticArgs("delete", "pod", "namespace/demo"), false, "unsupported_kubectl_resource_type"},
		{"ordinary list", staticArgs("delete", "pod,service", "demo"), false, ""},
		{"custom namespace group", staticArgs("delete", "namespace.example.com", "demo"), false, ""},
		{"invalid list", staticArgs("delete", "namespace,,pod", "demo"), false, "unsupported_kubectl_resource_type"},
		{"invalid interactive short", staticArgs("delete", "namespace", "demo", "-i=maybe"), false, "unsupported_kubectl_delete_option"},
		{"invalid cascade", staticArgs("delete", "namespace", "demo", "--cascade=future"), false, "unsupported_kubectl_delete_option"},
		{"invalid dry run", staticArgs("delete", "namespace", "demo", "--dry-run=future"), false, "unsupported_kubectl_delete_option"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, optionGap := destructiveKubectl(test.args)
			if got != test.want {
				t.Fatalf("destructiveKubectl() = %t, want %t", got, test.want)
			}
			if test.gapCode == "" && optionGap != nil || test.gapCode != "" && (optionGap == nil || optionGap.Code != test.gapCode) {
				t.Fatalf("gap = %#v, want %q", optionGap, test.gapCode)
			}
		})
	}

	for _, args := range [][]literalArg{
		staticArgs("-v", "4", "delete", "namespace", "demo"),
		staticArgs("-v4", "delete", "namespace", "demo"),
		staticArgs("-ndefault", "delete", "namespace", "demo"),
		staticArgs("-shttps://example.invalid", "delete", "namespace", "demo"),
		staticArgs("--namespace=", "delete", "namespace", "demo"),
		staticArgs("--profile-output=", "delete", "namespace", "demo"),
		staticArgs("--kuberc", "/tmp/kuberc", "delete", "namespace", "demo"),
		staticArgs("--profile", "trace", "delete", "namespace", "demo"),
		staticArgs("--insecure-skip-tls-verify=1", "delete", "namespace", "demo"),
	} {
		unwrapped, optionGap := unwrapOperationGlobalOptions("kubectl", args)
		if optionGap != nil {
			t.Fatalf("kubectl global options gap = %#v for %#v", optionGap, args)
		}
		if destructive, deleteGap := destructiveKubectl(unwrapped); !destructive || deleteGap != nil {
			t.Fatalf("kubectl global options lost namespace delete: destructive=%t gap=%#v args=%#v", destructive, deleteGap, args)
		}
	}
}
