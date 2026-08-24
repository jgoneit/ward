package evaluator

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jgoneit/ward/internal/contract"
)

func TestPowerShellStableCommonParametersPreserveRemoveTargetScanning(t *testing.T) {
	parameters := []string{
		"-Debug",
		"-db:$false",
		"-Verbose:$true",
		"-vb",
		"-ErrorAction Stop",
		"-ea:1",
		"-ErrorVariable wardError",
		"-ev:+wardError",
		"-ErrorVariable global:ward-error",
		"-ev:save-items",
		"-InformationAction Continue",
		"-infa:0",
		"-InformationVariable wardInformation",
		"-iv:+wardInformation",
		"-OutBuffer 1",
		"-ob:0",
		"-OutVariable wardOutput",
		"-ov:+wardOutput",
		"-PipelineVariable wardPipeline",
		"-pv:+ward-pipe",
		"-WarningAction SilentlyContinue",
		"-wa:6",
		"-WarningVariable wardWarning",
		"-wv:+wardWarning",
		"-Confirm:$false",
		"-cf",
		"-WhatIf:$false",
		"-wi:$false",
	}
	target := `C:\workspace\.git\config`
	for index, parameter := range parameters {
		t.Run(parameter, func(t *testing.T) {
			command := fmt.Sprintf("Remove-Item %s %s", parameter, target)
			if index%2 == 1 {
				command = fmt.Sprintf("Remove-Item %s %s", target, parameter)
			}
			assertPowerShellDecision(t, command, contract.OutcomeDeny, "WARD_DESTRUCTIVE_FILESYSTEM", "")
		})
	}
}

func TestPowerShellStableCommonParametersPreserveMoveSourceScanning(t *testing.T) {
	source := `C:\workspace\.git`
	destination := `D:\backup\git-metadata`
	for _, command := range []string{
		fmt.Sprintf("Move-Item -Verbose %s %s", source, destination),
		fmt.Sprintf("Move-Item %s -db:$false %s", source, destination),
		fmt.Sprintf("Move-Item %s %s -ea Stop", source, destination),
		fmt.Sprintf("mi -vb %s %s", source, destination),
		fmt.Sprintf("Move-Item -Destination %s -Path %s", destination, source),
		fmt.Sprintf("Move-Item -Destination %s %s", destination, source),
		fmt.Sprintf("Move-Item -Path %s %s", source, destination),
	} {
		t.Run(command, func(t *testing.T) {
			assertPowerShellDecision(t, command, contract.OutcomeDeny, "WARD_DESTRUCTIVE_FILESYSTEM", "")
		})
	}
}

func TestPowerShellStaticCommonVariableNamesPreserveScanning(t *testing.T) {
	target := `C:\workspace\.git\config`
	for _, command := range []string{
		fmt.Sprintf("Remove-Item -ErrorVariable 'global:ward-error' %s", target),
		fmt.Sprintf("Remove-Item -ev:save-items %s", target),
		fmt.Sprintf("Remove-Item -PipelineVariable '+ward-pipe' %s", target),
		fmt.Sprintf("Remove-Item -ErrorVariable '$' %s", target),
		fmt.Sprintf("Remove-Item -WarningVariable '^' %s", target),
		fmt.Sprintf("Remove-Item -ErrorVariable '-ward-error' %s", target),
		fmt.Sprintf("Remove-Item -ErrorVariable:'$choice' %s", target),
	} {
		t.Run(command, func(t *testing.T) {
			assertPowerShellDecision(t, command, contract.OutcomeDeny, "WARD_DESTRUCTIVE_FILESYSTEM", "")
		})
	}

	for _, command := range []string{
		fmt.Sprintf("Remove-Item -ErrorVariable $wardError %s", target),
		fmt.Sprintf(`Remove-Item -ErrorVariable "$wardError" %s`, target),
	} {
		t.Run(command, func(t *testing.T) {
			assertPowerShellDecision(t, command, contract.OutcomeDefer, "", "ambiguous_powershell")
		})
	}
}

func TestPowerShellOutBufferDecimalAndHexInt32(t *testing.T) {
	target := `C:\workspace\.git\config`
	for _, value := range []string{"0", "+1", "0x1", "0X7fffffff", "2147483647"} {
		t.Run(value, func(t *testing.T) {
			assertPowerShellDecision(t, fmt.Sprintf("Remove-Item -OutBuffer %s %s", value, target), contract.OutcomeDeny, "WARD_DESTRUCTIVE_FILESYSTEM", "")
		})
	}
	for _, value := range []string{"-1", "0x80000000", "2147483648", "0xz"} {
		t.Run(value, func(t *testing.T) {
			assertPowerShellDecision(t, fmt.Sprintf("Remove-Item -OutBuffer %s %s", value, target), contract.OutcomeDefer, "", "ambiguous_powershell_options")
		})
	}
}

func TestPowerShellCommandSwitchBooleanFormsPreserveScanning(t *testing.T) {
	for _, command := range []string{
		`Remove-Item -Force:$false C:\workspace\.git\config`,
		`Remove-Item C:\workspace\.git\config -Force:$true`,
		`Move-Item -PassThru:$false C:\workspace\.git D:\backup\git-metadata`,
		`Move-Item C:\workspace\.git D:\backup\git-metadata -PassThru:$true`,
	} {
		t.Run(command, func(t *testing.T) {
			assertPowerShellDecision(t, command, contract.OutcomeDeny, "WARD_DESTRUCTIVE_FILESYSTEM", "")
		})
	}
	for _, command := range []string{
		`Remove-Item -Force:false C:\workspace\.git\config`,
		`Move-Item -PassThru:$choice C:\workspace\.git D:\backup\git-metadata`,
	} {
		t.Run(command, func(t *testing.T) {
			gap := "ambiguous_powershell_options"
			if command == `Move-Item -PassThru:$choice C:\workspace\.git D:\backup\git-metadata` {
				gap = "ambiguous_powershell"
			}
			assertPowerShellDecision(t, command, contract.OutcomeDefer, "", gap)
		})
	}
}

func TestPowerShellWhatIfExactBooleanForms(t *testing.T) {
	target := `C:\workspace\.git\config`
	tests := []struct {
		name, command, gap string
		outcome            contract.Outcome
	}{
		{"canonical switch", fmt.Sprintf("Remove-Item -WhatIf %s", target), "", contract.OutcomeDefer},
		{"canonical true", fmt.Sprintf("Remove-Item %s -WhatIf:$true", target), "", contract.OutcomeDefer},
		{"alias switch", fmt.Sprintf("Remove-Item -wi %s", target), "", contract.OutcomeDefer},
		{"alias true", fmt.Sprintf("Remove-Item %s -wi:$true", target), "", contract.OutcomeDefer},
		{"canonical false", fmt.Sprintf("Remove-Item -WhatIf:$false %s", target), "", contract.OutcomeDeny},
		{"alias false", fmt.Sprintf("Remove-Item %s -wi:$false", target), "", contract.OutcomeDeny},
		{"true with narrowing", fmt.Sprintf("Remove-Item -Filter '*.tmp' -WhatIf %s", target), "", contract.OutcomeDefer},
		{"invalid static boolean", fmt.Sprintf("Remove-Item -WhatIf:true %s", target), "ambiguous_powershell_options", contract.OutcomeDefer},
		{"dynamic boolean", fmt.Sprintf("Remove-Item -WhatIf:$choice %s", target), "ambiguous_powershell", contract.OutcomeDefer},
		{"single quoted boolean is a string", fmt.Sprintf("Remove-Item -WhatIf:'$false' %s", target), "ambiguous_powershell", contract.OutcomeDefer},
		{"double quoted boolean is dynamic", fmt.Sprintf(`Remove-Item -WhatIf:"$false" %s`, target), "ambiguous_powershell", contract.OutcomeDefer},
		{"duplicate binding", fmt.Sprintf("Remove-Item -WhatIf -wi:$false %s", target), "ambiguous_powershell_options", contract.OutcomeDefer},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ruleID := ""
			if test.outcome == contract.OutcomeDeny {
				ruleID = "WARD_DESTRUCTIVE_FILESYSTEM"
			}
			assertPowerShellDecision(t, test.command, test.outcome, ruleID, test.gap)
		})
	}
}

func TestPowerShellInvalidOrVersionSpecificCommonParametersDefer(t *testing.T) {
	target := `C:\workspace\.git\config`
	for _, command := range []string{
		fmt.Sprintf("Remove-Item -Unknown %s", target),
		fmt.Sprintf("Remove-Item %s -Unknown", target),
		fmt.Sprintf("Remove-Item -ErrorAction NotAnAction %s", target),
		fmt.Sprintf("Remove-Item %s -ea:NotAnAction", target),
		fmt.Sprintf("Remove-Item -ErrorAction Suspend %s", target),
		fmt.Sprintf("Remove-Item -ErrorAction 5 %s", target),
		fmt.Sprintf("Remove-Item -Credential ward-user %s", target),
		fmt.Sprintf("Remove-Item -ErrorVariable '' %s", target),
		fmt.Sprintf("Remove-Item -PipelineVariable:'' %s", target),
		fmt.Sprintf("Remove-Item -InformationVariable 'env:ward/name' %s", target),
		fmt.Sprintf("Remove-Item -OutVariable '+' %s", target),
		fmt.Sprintf("Remove-Item -ErrorVariable 'global:' %s", target),
		fmt.Sprintf("Remove-Item -ErrorVariable 'env:ward' %s", target),
		fmt.Sprintf("Remove-Item -PipelineVariable '+' %s", target),
		fmt.Sprintf("Remove-Item -OutBuffer -1 %s", target),
		fmt.Sprintf("Remove-Item %s -ob:2147483648", target),
		fmt.Sprintf("Remove-Item -ProgressAction Continue %s", target),
		fmt.Sprintf("Remove-Item %s -proga:Continue", target),
		fmt.Sprintf("Remove-Item -UseTransaction %s", target),
	} {
		t.Run(command, func(t *testing.T) {
			assertPowerShellDecision(t, command, contract.OutcomeDefer, "", "ambiguous_powershell_options")
		})
	}
}

func TestPowerShellDuplicateAndCrossCommandParametersDefer(t *testing.T) {
	for _, command := range []string{
		`Remove-Item -Path .git -Path ordinary.txt`,
		`Remove-Item -Path .git -LiteralPath ordinary.txt`,
		`Remove-Item -LiteralPath .git -LP ordinary.txt`,
		`Move-Item -Path .git -Destination ../x -Destination ../y`,
		`Remove-Item -Recurse -rec C:\workspace`,
		`Remove-Item -Raw .git`,
		`Move-Item -Container .git ../x`,
		`Get-Content -Recurse .git/config`,
		`Get-Content -WhatIf .git/config`,
		`Copy-Item -Raw .git ../x`,
		`Clear-Content -PassThru .git/config`,
	} {
		t.Run(command, func(t *testing.T) {
			assertPowerShellDecision(t, command, contract.OutcomeDefer, "", "ambiguous_powershell_options")
		})
	}
}

func TestPowerShellCommonParametersDoNotTurnReadsIntoDenies(t *testing.T) {
	target := `C:\workspace\.git\config`
	for _, command := range []string{
		fmt.Sprintf("Get-Content -Verbose -Path %s", target),
		fmt.Sprintf("Get-Content %s -db:$false", target),
		fmt.Sprintf("gc -ea Stop -LiteralPath %s", target),
	} {
		t.Run(command, func(t *testing.T) {
			assertPowerShellDecision(t, command, contract.OutcomeDefer, "", "")
		})
	}
}

func TestPowerShellQuotedCommandNameRequiresCallOperator(t *testing.T) {
	assertPowerShellDecision(t, `'Remove-Item' -Path C:\workspace\.git\config`, contract.OutcomeDefer, "", "ambiguous_powershell")
	assertPowerShellDecision(t, `& 'Remove-Item' -Path C:\workspace\.git\config`, contract.OutcomeDeny, "WARD_DESTRUCTIVE_FILESYSTEM", "")
}

func TestPowerShellAdjacentQuotedTokensDefer(t *testing.T) {
	for _, command := range []string{
		`Remove-Item -Recurse 'C:/work''space'`,
		`Remove-Item -Recurse "C:/work""space"`,
		`Remove-Item -Recurse "C:/work"'space'`,
	} {
		t.Run(command, func(t *testing.T) {
			assertPowerShellDecision(t, command, contract.OutcomeDefer, "", "ambiguous_powershell")
		})
	}
}

func TestPowerShellActiveBackticksAndBlockCommentsDefer(t *testing.T) {
	for _, command := range []string{
		"Remove-Item -ErrorVariable \"safe`\" C:/workspace/.git/config",
		"Remove-Item -Recurse C:/workspace <# reviewed #>",
	} {
		t.Run(command, func(t *testing.T) {
			assertPowerShellDecision(t, command, contract.OutcomeDefer, "", "ambiguous_powershell")
		})
	}
}

func TestPowerShellLineCommentsPreserveLiteralStatements(t *testing.T) {
	tests := []struct {
		name    string
		command string
		outcome contract.Outcome
		ruleID  string
		gapCode string
	}{
		{
			name:    "destructive prefix",
			command: `Remove-Item -Recurse C:\workspace # cleanup`,
			outcome: contract.OutcomeDeny,
			ruleID:  "WARD_DESTRUCTIVE_FILESYSTEM",
		},
		{
			name:    "destructive prefix before CRLF",
			command: "Remove-Item -Recurse C:\\workspace # cleanup\r\nWrite-Output safe",
			outcome: contract.OutcomeDeny,
			ruleID:  "WARD_DESTRUCTIVE_FILESYSTEM",
		},
		{
			name:    "comment before destructive statement",
			command: "# reviewed\r\nRemove-Item -Recurse C:\\workspace",
			outcome: contract.OutcomeDeny,
			ruleID:  "WARD_DESTRUCTIVE_FILESYSTEM",
		},
		{
			name:    "quoted target before comment",
			command: `Remove-Item -Recurse 'C:\workspace'# cleanup`,
			outcome: contract.OutcomeDeny,
			ruleID:  "WARD_DESTRUCTIVE_FILESYSTEM",
		},
		{
			name:    "comment contents are ignored",
			command: "Write-Output safe # ignored; Remove-Item C:/workspace/.git/config ` $env:WARD_PATH",
			outcome: contract.OutcomeDefer,
		},
		{
			name:    "quoted hash stays literal",
			command: `Write-Output 'safe # literal'`,
			outcome: contract.OutcomeDefer,
		},
		{
			name:    "token hash stays literal",
			command: `Write-Output safe#literal`,
			outcome: contract.OutcomeDefer,
		},
		{
			name:    "target hash stays literal",
			command: `Remove-Item -Recurse C:\workspace#cleanup`,
			outcome: contract.OutcomeDefer,
		},
		{
			name:    "all comment remains ambiguous",
			command: `# cleanup only`,
			outcome: contract.OutcomeDefer,
			gapCode: "ambiguous_powershell",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertPowerShellDecision(t, test.command, test.outcome, test.ruleID, test.gapCode)
		})
	}
}

func TestPowerShellNativeBinderAssumptions(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native PowerShell binder regression runs on Windows")
	}
	pwsh, err := exec.LookPath("pwsh.exe")
	if err != nil {
		pwsh, err = exec.LookPath("pwsh")
	}
	if err != nil {
		t.Skip("PowerShell 7 is not on PATH")
	}

	testDir := t.TempDir()
	source := filepath.Join(testDir, "source.txt")
	destination := filepath.Join(testDir, "destination.txt")
	if err := os.WriteFile(source, []byte("ward binder fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	environment := append(os.Environ(), "WARD_BIND_SOURCE="+source, "WARD_BIND_DESTINATION="+destination)
	validScript := `$ErrorActionPreference = 'Stop'
Move-Item -Destination $env:WARD_BIND_DESTINATION -Path $env:WARD_BIND_SOURCE -WhatIf -PassThru:$false -ErrorVariable 'global:ward-error' -PipelineVariable '+ward-pipe' -OutBuffer 0x1 | Out-Null
Remove-Item -Path $env:WARD_BIND_SOURCE -WhatIf -Force:$false -ErrorVariable '$' -OutBuffer 0x1 | Out-Null
Remove-Item -Path $env:WARD_BIND_SOURCE -WhatIf -ErrorVariable '-ward-error' | Out-Null`
	command := exec.Command(pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", validScript)
	command.Env = environment
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("valid native binder forms failed: %v\n%s", err, output)
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("WhatIf mutated source: %v", err)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("WhatIf created destination: %v", err)
	}

	invalidScript := `$ErrorActionPreference = 'Stop'
Remove-Item -Path $env:WARD_BIND_SOURCE -LiteralPath $env:WARD_BIND_SOURCE -WhatIf`
	command = exec.Command(pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", invalidScript)
	command.Env = environment
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("binder accepted mutually exclusive Path and LiteralPath:\n%s", output)
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("binder-invalid WhatIf command mutated source: %v", err)
	}

	quotedSwitchScript := `$ErrorActionPreference = 'Stop'
Remove-Item -Path $env:WARD_BIND_SOURCE -WhatIf:'$false'`
	command = exec.Command(pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", quotedSwitchScript)
	command.Env = environment
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("binder accepted a quoted String as a SwitchParameter boolean:\n%s", output)
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("quoted-switch binder failure mutated source: %v", err)
	}

	invalidVariableScript := `$ErrorActionPreference = 'Stop'
$invalidNames = @('env:ward/name', '+', 'global:', 'env:ward')
foreach ($name in $invalidNames) {
    $accepted = $true
    try { Remove-Item -Path $env:WARD_BIND_SOURCE -WhatIf -ErrorVariable $name | Out-Null } catch { $accepted = $false }
    if ($accepted) { throw "binder accepted invalid ErrorVariable" }
}
$accepted = $true
try { Remove-Item -Path $env:WARD_BIND_SOURCE -WhatIf -PipelineVariable '+' | Out-Null } catch { $accepted = $false }
if ($accepted) { throw "binder accepted invalid PipelineVariable" }
foreach ($action in @('Suspend', '5')) {
    $accepted = $true
    try { Remove-Item -Path $env:WARD_BIND_SOURCE -WhatIf -ErrorAction $action | Out-Null } catch { $accepted = $false }
    if ($accepted) { throw "binder accepted invalid action preference" }
}
$accepted = $true
try { Remove-Item -Path $env:WARD_BIND_SOURCE -WhatIf -Credential 'ward-user' | Out-Null } catch { $accepted = $false }
if ($accepted) { throw "noninteractive binder accepted literal Credential" }`
	command = exec.Command(pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", invalidVariableScript)
	command.Env = environment
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("invalid native variable-name probes failed: %v\n%s", err, output)
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("binder-invalid variable command mutated source: %v", err)
	}

	backtickScript := "Remove-Item -ErrorVariable \"safe`\" $env:WARD_BIND_SOURCE"
	command = exec.Command(pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", backtickScript)
	command.Env = environment
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("PowerShell accepted an unterminated backtick-escaped quote:\n%s", output)
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("backtick parser failure mutated source: %v", err)
	}

	commentScript := `Write-Output safe # ignored; Remove-Item -Path $env:WARD_BIND_SOURCE`
	command = exec.Command(pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", commentScript)
	command.Env = environment
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("PowerShell comment probe failed: %v\n%s", err, output)
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("PowerShell comment remainder mutated source: %v", err)
	}

	commentDeleteSource := filepath.Join(testDir, "comment-delete-source.txt")
	if err := os.WriteFile(commentDeleteSource, []byte("ward comment fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	commentDeleteEnvironment := append(environment, "WARD_COMMENT_DELETE_SOURCE="+commentDeleteSource)
	commentDeleteScript := `Remove-Item -LiteralPath $env:WARD_COMMENT_DELETE_SOURCE # reviewed trailing comment`
	command = exec.Command(pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", commentDeleteScript)
	command.Env = commentDeleteEnvironment
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("PowerShell destructive-prefix comment probe failed: %v\n%s", err, output)
	}
	if _, err := os.Stat(commentDeleteSource); !os.IsNotExist(err) {
		t.Fatalf("PowerShell did not execute the command before the comment: %v", err)
	}
}

func assertPowerShellDecision(t *testing.T, command string, outcome contract.Outcome, ruleID, gapCode string) {
	t.Helper()
	req := request("powershell", command)
	req.CWD = "C:/workspace"
	decision := evaluatorForRequest(t, req).Evaluate(req)
	if decision.Outcome != outcome || decision.RuleID != ruleID {
		t.Fatalf("decision = %#v, want outcome %q rule %q", decision, outcome, ruleID)
	}
	if gapCode == "" {
		if decision.CoverageGap != nil {
			t.Fatalf("coverage gap = %#v, want none", decision.CoverageGap)
		}
		return
	}
	if decision.CoverageGap == nil || decision.CoverageGap.Code != gapCode {
		t.Fatalf("coverage gap = %#v, want %q", decision.CoverageGap, gapCode)
	}
}
