//go:build windows

package diagnostics

import (
	"context"
	"encoding/json"
	"os/user"
	"strings"
	"testing"
	"time"
)

func TestScheduledTaskAccountNormalizationUsesCurrentWindowsIdentity(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal("current Windows identity is unavailable")
	}
	paths, _, _ := lifecycleFixture(t)
	d, err := makeServiceDefinition(paths, "windows", current.Uid)
	if err != nil {
		t.Fatal("cannot construct the current-user task fixture")
	}
	expected := string(d.Content)
	const prefix = "<LogonTrigger><Enabled>true</Enabled><Repetition><Interval>PT1M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>"
	userLeaf := "<UserId>" + xmlText(current.Uid) + "</UserId>"
	const account = "__WARD_CURRENT_ACCOUNT__"
	cases := []struct {
		Name string
		XML  string
		Want bool
	}{
		{"current_account_name", "<UserId>" + account + "</UserId>", true},
		{"current_sid", userLeaf, true},
		{"system_account", "<UserId>__WARD_SYSTEM_ACCOUNT__</UserId>", current.Uid == "S-1-5-18"},
		{"other_sid", "<UserId>S-1-5-21-0-0-0-4294967294</UserId>", false},
		{"empty", "<UserId></UserId>", false},
		{"attribute", `<UserId marker="changed">` + account + "</UserId>", false},
		{"child", "<UserId>" + account + "<Unknown/></UserId>", false},
		{"duplicate", "<UserId>" + account + "</UserId>" + userLeaf, false},
		{"foreign_namespace", `<UserId xmlns="urn:foreign">` + account + "</UserId>", false},
		{"unknown_parent", "<Unknown><UserId>" + account + "</UserId></Unknown>", false},
		{"unknown_local_account", "<UserId>__WARD_UNKNOWN_ACCOUNT__</UserId>", false},
	}
	for i := range cases {
		cases[i].XML = replaceTaskFixture(t, expected, prefix+userLeaf, prefix+cases[i].XML)
	}
	// Resolving a trigger name must not normalize or otherwise weaken the
	// separately declared execution principal.
	changedPrincipal := replaceTaskFixture(t, cases[0].XML,
		`<Principal id="CurrentUser">`+userLeaf,
		`<Principal id="CurrentUser"><UserId>S-1-5-21-0-0-0-4294967294</UserId>`)
	cases = append(cases, struct {
		Name string
		XML  string
		Want bool
	}{"different_execution_principal", changedPrincipal, false})

	input, err := json.Marshal(struct {
		ExpectedSID string
		Cases       any
	}{current.Uid, cases})
	if err != nil {
		t.Fatal("cannot encode the identity fixtures")
	}
	// One native Windows PowerShell process runs every fixture. Real .NET
	// identity translation is exercised; no Task Scheduler registration occurs.
	script := windowsTaskUserNormalization + `$ErrorActionPreference='Stop'
$utf8=[System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding=$utf8
[Console]::OutputEncoding=$utf8
$OutputEncoding=$utf8
$request=[Console]::In.ReadToEnd()|ConvertFrom-Json
$identity=[System.Security.Principal.WindowsIdentity]::GetCurrent()
if($identity.User.Value -cne $request.ExpectedSID){throw 'current identity mismatch'}
$account=[System.Security.SecurityElement]::Escape($identity.Name)
$systemSID=[System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$systemAccount=[System.Security.SecurityElement]::Escape($systemSID.Translate([System.Security.Principal.NTAccount]).Value)
$unknownAccount=[System.Security.SecurityElement]::Escape($env:COMPUTERNAME+'\WardDiagnosticsMissingAccount-4fb07dd7')
$results=@(foreach($case in $request.Cases){
 $xml=$case.XML.Replace('__WARD_CURRENT_ACCOUNT__',$account).Replace('__WARD_SYSTEM_ACCOUNT__',$systemAccount).Replace('__WARD_UNKNOWN_ACCOUNT__',$unknownAccount)
 @{Name=$case.Name;XML=(Normalize-WardTaskUser $xml $request.ExpectedSID)}
})
@{CurrentSID=$identity.User.Value;Results=$results}|ConvertTo-Json -Depth 5 -Compress
`
	program, err := servicePowerShellPath()
	if err != nil {
		t.Fatal("native Windows PowerShell is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := runServiceCommand(ctx, program,
		[]string{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script}, input)
	if err != nil {
		t.Fatal("native Windows identity normalization failed")
	}
	var reply struct {
		CurrentSID string
		Results    []struct{ Name, XML string }
	}
	if json.Unmarshal(out, &reply) != nil || reply.CurrentSID != current.Uid || len(reply.Results) != len(cases) {
		t.Fatal("invalid identity normalization response")
	}
	for i, fixture := range cases {
		t.Run(fixture.Name, func(t *testing.T) {
			result := reply.Results[i]
			if result.Name != fixture.Name || strings.Contains(result.XML, "__WARD_") {
				t.Fatal("identity fixture was not evaluated")
			}
			if scheduledTaskMatches([]byte(result.XML), d.Content) != fixture.Want {
				t.Fatal("identity normalization changed the task ownership result")
			}
		})
	}
}
