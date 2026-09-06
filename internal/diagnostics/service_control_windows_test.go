//go:build windows

package diagnostics

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestScheduledTaskControlPreservesRunningAndStoppedStates(t *testing.T) {
	// Exercise the production helpers in one native Windows PowerShell process.
	// ScriptMethod fixtures model COM state transitions without registering tasks.
	script := windowsTaskControlHelpers + `$ErrorActionPreference='Stop'
$utf8=[System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=$utf8
$OutputEncoding=$utf8
function New-WardTaskMock($state,$behavior) {
 $task=[pscustomobject]@{Enabled=$false;State=$state;Calls=0;Behavior=$behavior}
 $task|Add-Member -MemberType ScriptMethod -Name Run -Value {
  param($parameters)
  $this.Calls+=1
  switch($this.Behavior) {
   'success' {$this.State=4;return}
   'race_running' {$this.State=4;throw 'fixture run failure'}
   'race_queued' {$this.State=2;throw 'fixture run failure'}
   default {throw 'fixture run failure'}
  }
 }
 return $task
}
$cases=@(
 @{Name='already_running';State=4;Behavior='failure'},
 @{Name='already_queued';State=2;Behavior='failure'},
 @{Name='ready_starts';State=3;Behavior='success'},
 @{Name='run_race_running';State=3;Behavior='race_running'},
 @{Name='run_race_queued';State=3;Behavior='race_queued'},
 @{Name='run_failure_ready';State=3;Behavior='failure'}
)
$results=@(foreach($case in $cases) {
 $task=New-WardTaskMock $case.State $case.Behavior
 $failed=$false
 try {Start-WardScheduledTask $task} catch {$failed=$true}
 @{Name=$case.Name;Enabled=$task.Enabled;State=$task.State;RunCalls=$task.Calls;Failed=$failed}
})
@{Results=$results;StoppedFlags=(Get-WardRestoreRegistrationFlags $false);RunningFlags=(Get-WardRestoreRegistrationFlags $true)}|ConvertTo-Json -Depth 4 -Compress
`
	program, err := servicePowerShellPath()
	if err != nil {
		t.Fatal("native Windows PowerShell is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := runServiceCommand(ctx, program,
		[]string{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script}, nil)
	if err != nil {
		t.Fatal("native Windows task control fixtures failed")
	}
	type controlResult struct {
		Name     string
		Enabled  bool
		State    int
		RunCalls int
		Failed   bool
	}
	var reply struct {
		Results                    []controlResult
		StoppedFlags, RunningFlags int
	}
	want := []controlResult{
		{"already_running", true, 4, 0, false},
		{"already_queued", true, 2, 0, false},
		{"ready_starts", true, 4, 1, false},
		{"run_race_running", true, 4, 1, false},
		{"run_race_queued", true, 2, 1, false},
		{"run_failure_ready", true, 3, 1, true},
	}
	if json.Unmarshal(out, &reply) != nil || len(reply.Results) != len(want) {
		t.Fatal("invalid task control fixture response")
	}
	for i, expected := range want {
		t.Run(expected.Name, func(t *testing.T) {
			if reply.Results[i] != expected {
				t.Fatal("task control did not preserve the expected state transition")
			}
		})
	}
	// Suppress registration-trigger execution when restoring a stopped task,
	// including an enabled task that was not running before the operation.
	if reply.StoppedFlags != 38 || reply.RunningFlags != 6 {
		t.Fatal("restore registration flags do not preserve the previous running state")
	}
}
