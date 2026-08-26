[CmdletBinding()]
param(
    [string]$WardBinary = $(Join-Path (Get-Location) 'bin\ward.exe'),
    [string]$CodexBinary = 'codex'
)

$ErrorActionPreference = 'Stop'
$wardE2ETemp = Join-Path ([System.IO.Path]::GetTempPath()) ("ward-codex-e2e-" + [guid]::NewGuid())
$wardE2EHome = Join-Path $wardE2ETemp 'home'
$wardE2ECodexDir = Join-Path $wardE2EHome '.codex'
$wardE2EStateDir = Join-Path $wardE2ETemp 'state'
$wardE2EConfigDir = Join-Path $wardE2EHome 'AppData\Roaming'
$wardE2ECustomGHDir = Join-Path $wardE2EHome 'custom-gh'
$wardE2EWorkspace = Join-Path $wardE2EHome 'project-a'
$wardE2ESibling = Join-Path $wardE2EHome 'project-b'
$wardE2EDeepRelative = 'd1\d2\d3\d4\d5\d6\d7\d8\d9\d10'
$wardE2EDeep = Join-Path $wardE2EWorkspace $wardE2EDeepRelative
$wardE2EManagedBinDir = Join-Path $wardE2ECodexDir 'ward\bin'
$wardE2EManagedBin = Join-Path $wardE2EManagedBinDir 'ward.exe'
$wardOldCodexHome = $env:CODEX_HOME
$wardOldLocalAppData = $env:LOCALAPPDATA
$wardOldAppData = $env:APPDATA
$wardOldHome = $env:HOME
$wardOldUserProfile = $env:USERPROFILE
$wardOldGHConfigDir = $env:GH_CONFIG_DIR

function Invoke-WardSandbox {
    param([string]$Script)
    $arguments = @('sandbox', '-P', 'ward', '-C', $wardE2EWorkspace, 'powershell', '-NoProfile', '-Command', $Script)
    & $CodexBinary @arguments
    return $LASTEXITCODE
}

function Get-WardStateSnapshot {
    $state = Join-Path $wardE2EStateDir 'Ward\state\core'
    if (-not (Test-Path -LiteralPath $state)) { return '' }
    return ((Get-ChildItem -LiteralPath $state -File -Recurse | Sort-Object FullName | ForEach-Object {
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash
        '{0}|{1}|{2}|{3}' -f $hash, $_.Length, $_.LastWriteTimeUtc.Ticks, $_.FullName
    }) -join "`n")
}

try {
    if (-not (Test-Path -LiteralPath $WardBinary -PathType Leaf)) { throw 'Ward E2E: build bin\ward.exe first' }
    if (-not (Get-Command $CodexBinary -ErrorAction SilentlyContinue)) { throw 'Ward E2E: codex CLI is required' }

    $directories = @(
        $wardE2ECodexDir,
        $wardE2EManagedBinDir,
        (Join-Path $wardE2EWorkspace 'nested'),
        (Join-Path $wardE2EWorkspace 'fixtures'),
        $wardE2EDeep,
        $wardE2ESibling,
        $wardE2ECustomGHDir,
        (Join-Path $wardE2EHome '.ssh'),
        (Join-Path $wardE2EHome '.docker'),
        (Join-Path $wardE2EHome '.kube'),
        (Join-Path $wardE2EConfigDir 'gcloud')
    )
    New-Item -ItemType Directory -Force -Path $directories | Out-Null
    Copy-Item -LiteralPath $WardBinary -Destination $wardE2EManagedBin

    $configPath = Join-Path $wardE2ECodexDir 'config.toml'
    @('approval_policy = "never"', 'model = "gpt-test"') | Set-Content -Encoding utf8NoBOM $configPath
    $originalConfig = [System.IO.File]::ReadAllBytes($configPath)

    $protectedFixtures = @{
        '.env' = 'WARD_SECRET_CANARY_7d10f7'
        'nested\.env.local' = 'WARD_LOCAL_CANARY_2b98e1'
        'app.key.json' = 'WARD_KEY_JSON_CANARY_95d4bd'
        'nested\credentials.json' = 'WARD_CREDENTIALS_CANARY_7f8d21'
        'service-account.json' = 'WARD_SERVICE_CANARY_6259a1'
        'nested\secrets.yml' = 'WARD_YAML_CANARY_f04052'
        'id_ed25519' = 'WARD_SSH_CANARY_a44071'
        'private-key.pem' = 'WARD_KEY_CANARY_f8aa11'
        'privkey1.pem' = 'WARD_NUMBERED_KEY_CANARY_2f0b77'
        'nested\client.p12' = 'WARD_P12_CANARY_3f277a'
        "$wardE2EDeepRelative\.env.production" = 'WARD_DEEP_CANARY_b7f441'
    }
    foreach ($entry in $protectedFixtures.GetEnumerator()) {
        Set-Content -Encoding utf8NoBOM (Join-Path $wardE2EWorkspace $entry.Key) $entry.Value
    }

    $ordinaryFixtures = @{
        '.env.example' = 'PUBLIC_TEMPLATE=1'
        'nested\.env.sample' = 'PUBLIC_SAMPLE=1'
        '.env.customer' = 'CUSTOM_ENV=1'
        '.env.customer.local' = 'CUSTOM_LOCAL_ENV=1'
        'ordinary.txt' = 'ordinary'
        'server.pem' = 'PUBLIC CERTIFICATE FIXTURE'
        'private-notes.pem' = 'PUBLIC NOTES FIXTURE'
        'deployment-secret.yml' = 'ordinary: true'
        'fixtures\user-credential.json' = '{"type":"ordinary"}'
        '.npmrc' = 'registry=https://example.invalid'
    }
    foreach ($entry in $ordinaryFixtures.GetEnumerator()) {
        Set-Content -Encoding utf8NoBOM (Join-Path $wardE2EWorkspace $entry.Key) $entry.Value
    }

    $authFixtures = @{
        (Join-Path $wardE2ESibling '.env') = 'SIBLING_ENV=1'
        (Join-Path $wardE2ECustomGHDir 'hosts.yml') = 'github.com: oauth_token'
        (Join-Path $wardE2EHome '.ssh\config') = 'Host github.com'
        (Join-Path $wardE2EHome '.ssh\known_hosts') = 'github.com ssh-ed25519 PUBLIC'
        (Join-Path $wardE2EHome '.ssh\id_ed25519.pub') = 'ssh-ed25519 PUBLIC'
        (Join-Path $wardE2EHome '.docker\config.json') = '{"auths":{}}'
        (Join-Path $wardE2EHome '.kube\config') = 'apiVersion: v1'
        (Join-Path $wardE2EConfigDir 'gcloud\application_default_credentials.json') = '{}'
    }
    foreach ($entry in $authFixtures.GetEnumerator()) {
        Set-Content -Encoding utf8NoBOM -LiteralPath $entry.Key $entry.Value
    }

    $env:CODEX_HOME = $wardE2ECodexDir
    $env:LOCALAPPDATA = $wardE2EStateDir
    $env:APPDATA = $wardE2EConfigDir
    $env:HOME = $wardE2EHome
    $env:USERPROFILE = $wardE2EHome
    $env:GH_CONFIG_DIR = $wardE2ECustomGHDir

    & $wardE2EManagedBin codex install --scope user
    if ($LASTEXITCODE -ne 0) { throw 'Ward E2E: install failed' }
    $wardJournal = Join-Path $wardE2EStateDir 'Ward\state\core\integration-journal.json'
    if (-not (Test-Path -LiteralPath $wardJournal -PathType Leaf)) { throw 'Ward E2E: v3 integration journal is missing' }
    $stateFiles = @(Get-ChildItem -LiteralPath (Split-Path $wardJournal) -File -Recurse)
    if ($stateFiles.Count -ne 1 -or $stateFiles[0].FullName -cne $wardJournal) { throw 'Ward E2E: install wrote unexpected persistent state' }

    $configText = Get-Content -Raw $configPath
    if ($configText -notmatch 'approval_policy\s*=\s*"never"') { throw 'Ward E2E: approval_policy changed' }
    if ($configText -notmatch 'default_permissions\s*=\s*"ward"') { throw 'Ward E2E: ward profile was not selected' }
    if ($configText -notmatch '\[permissions\.ward\]') { throw 'Ward E2E: ward profile was not installed' }
    $hooksText = Get-Content -Raw (Join-Path $wardE2ECodexDir 'hooks.json')
    if ($hooksText -notmatch '"SessionStart"' -or $hooksText -notmatch '"PreToolUse"') { throw 'Ward E2E: ambient hooks are incomplete' }
    if ($hooksText -match '"PermissionRequest"|"PostToolUse"|"matcher"\s*:\s*"\*"') { throw 'Ward E2E: unexpected or wildcard hook was installed' }

    foreach ($relativePath in $protectedFixtures.Keys) {
        $escaped = $relativePath.Replace("'", "''")
        $exitCode = Invoke-WardSandbox "Get-Content -LiteralPath '$escaped' | Out-Null"
        if ($exitCode -eq 0) { throw "Ward E2E: reviewed workspace Secret escaped: $relativePath" }
    }

    foreach ($relativePath in $ordinaryFixtures.Keys) {
        $escaped = $relativePath.Replace("'", "''")
        $exitCode = Invoke-WardSandbox "Get-Content -LiteralPath '$escaped' | Out-Null; Set-Content -LiteralPath '$escaped' -Value 'updated'"
        if ($exitCode -ne 0) { throw "Ward E2E: ordinary workspace operation failed: $relativePath" }
    }
    foreach ($authPath in $authFixtures.Keys) {
        $escaped = $authPath.Replace("'", "''")
        $exitCode = Invoke-WardSandbox "Get-Content -LiteralPath '$escaped' | Out-Null"
        if ($exitCode -ne 0) { throw "Ward E2E: existing authentication workflow was blocked: $authPath" }
    }

    foreach ($controlPath in @($configPath, (Join-Path $wardE2ECodexDir 'hooks.json'), ([System.IO.Path]::GetFullPath($wardE2EManagedBin)))) {
        $escaped = $controlPath.Replace("'", "''")
        $exitCode = Invoke-WardSandbox "Set-Content -LiteralPath '$escaped' -Value 'tampered'"
        if ($exitCode -eq 0) { throw "Ward E2E: control-plane overwrite escaped: $controlPath" }
    }
    foreach ($anchor in @($wardE2EManagedBinDir, (Join-Path $wardE2EStateDir 'Ward\state'))) {
        $escaped = $anchor.Replace("'", "''")
        $destination = ($anchor + '.moved').Replace("'", "''")
        $exitCode = Invoke-WardSandbox "Move-Item -LiteralPath '$escaped' -Destination '$destination'"
        if ($exitCode -eq 0) { throw "Ward E2E: protected directory relocation escaped: $anchor" }
        if (-not (Test-Path -LiteralPath $anchor)) { throw "Ward E2E: protected directory disappeared: $anchor" }
    }

    $before = Get-WardStateSnapshot
    $safePayload = '{"cwd":"' + ($wardE2EWorkspace -replace '\\', '\\\\') + '","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"Get-Content .env"}}'
    $safeError = Join-Path $wardE2ETemp 'safe.stderr'
    $safeOutput = @($safePayload | & $wardE2EManagedBin hook codex-pre-tool-use 2> $safeError)
    if ($LASTEXITCODE -ne 0 -or $safeOutput.Count -ne 0 -or (Get-Item $safeError).Length -ne 0) { throw 'Ward E2E: safe matched request was not a silent defer' }
    if ($before -ne (Get-WardStateSnapshot)) { throw 'Ward E2E: safe defer changed persistent Ward state' }

    $denyPayload = '{"cwd":"' + ($wardE2EWorkspace -replace '\\', '\\\\') + '","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"Remove-Item -Recurse -Force .; Write-Output done"}}'
    $denyError = Join-Path $wardE2ETemp 'deny.stderr'
    $denyOutput = @($denyPayload | & $wardE2EManagedBin hook codex-pre-tool-use 2> $denyError)
    if ($LASTEXITCODE -ne 0 -or $denyOutput.Count -ne 1 -or ($denyOutput -join '') -notmatch '"permissionDecision"\s*:\s*"deny"' -or (Get-Item $denyError).Length -ne 0) { throw 'Ward E2E: catastrophic request was not denied cleanly' }
    if ($before -ne (Get-WardStateSnapshot)) { throw 'Ward E2E: deny changed persistent Ward state' }

    $errorPayload = '{"cwd":"' + ($wardE2EWorkspace -replace '\\', '\\\\') + '","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{}}'
    $errorOutputPath = Join-Path $wardE2ETemp 'error.stderr'
    $errorOutput = @($errorPayload | & $wardE2EManagedBin hook codex-pre-tool-use 2> $errorOutputPath)
    if ($LASTEXITCODE -ne 0 -or $errorOutput.Count -ne 0 -or (Get-Item $errorOutputPath).Length -ne 0) { throw 'Ward E2E: evaluator error was not a silent Host defer' }
    if ($before -ne (Get-WardStateSnapshot)) { throw 'Ward E2E: evaluator error changed persistent Ward state' }

    $sessionPayload = '{"cwd":"' + ($wardE2EWorkspace -replace '\\', '\\\\') + '","hook_event_name":"SessionStart"}'
    $sessionError = Join-Path $wardE2ETemp 'session.stderr'
    $sessionOutput = @($sessionPayload | & $wardE2EManagedBin hook codex-session-start 2> $sessionError)
    if ($LASTEXITCODE -ne 0 -or $sessionOutput.Count -ne 0 -or (Get-Item $sessionError).Length -ne 0) { throw 'Ward E2E: healthy SessionStart was not silent' }
    if ($before -ne (Get-WardStateSnapshot)) { throw 'Ward E2E: SessionStart changed persistent Ward state' }

    $doctor = (& $wardE2EManagedBin doctor --project $wardE2EWorkspace --json | Out-String | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0 -or -not $doctor.healthy) { throw 'Ward E2E: trusted Host-side Doctor failed' }
    foreach ($checkID in @('permissions.state_topology', 'permissions.control_topology')) {
        $check = $doctor.checks | Where-Object { $_.id -eq $checkID } | Select-Object -First 1
        if (-not $check -or $check.status -ne 'pass') { throw "Ward E2E: default project topology did not pass: $checkID" }
    }
    if ($before -ne (Get-WardStateSnapshot)) { throw 'Ward E2E: Doctor changed persistent Ward state' }
    $managedBinEscaped = $wardE2EManagedBin.Replace("'", "''")
    $workspaceEscaped = $wardE2EWorkspace.Replace("'", "''")
    $exitCode = Invoke-WardSandbox "& '$managedBinEscaped' doctor --project '$workspaceEscaped' --json | Out-Null; exit `$LASTEXITCODE"
    if ($exitCode -eq 0) { throw 'Ward E2E: guarded process unexpectedly gained Doctor access to denied state' }
    if ($before -ne (Get-WardStateSnapshot)) { throw 'Ward E2E: guarded Doctor attempt changed persistent Ward state' }

    $escapedJournal = $wardJournal.Replace("'", "''")
    $exitCode = Invoke-WardSandbox "Get-Content -LiteralPath '$escapedJournal' | Out-Null"
    if ($exitCode -eq 0) { throw 'Ward E2E: Ward integration journal read escaped the native profile' }

    & $wardE2EManagedBin codex uninstall --scope user
    if ($LASTEXITCODE -ne 0) { throw 'Ward E2E: uninstall failed' }
    $restored = [System.IO.File]::ReadAllBytes($configPath)
    if ([Convert]::ToBase64String($originalConfig) -ne [Convert]::ToBase64String($restored)) { throw 'Ward E2E: config bytes were not restored' }
    if (Test-Path -LiteralPath (Join-Path $wardE2ECodexDir 'hooks.json')) { throw 'Ward E2E: hooks.json was not restored to absent' }
    if (Test-Path -LiteralPath $wardJournal) { throw 'Ward E2E: uninstall left the integration journal' }
    $coreState = Join-Path $wardE2EStateDir 'Ward\state\core'
    if (Test-Path -LiteralPath $coreState) {
        $remaining = @(Get-ChildItem -LiteralPath $coreState -File -Recurse)
        if ($remaining.Count -ne 0) { throw 'Ward E2E: uninstall left persistent Ward files' }
    }
    Write-Output 'PASS: isolated native Windows Codex ambient-kernel install/defer/deny/uninstall zero-persistence E2E'
}
finally {
    $env:CODEX_HOME = $wardOldCodexHome
    $env:LOCALAPPDATA = $wardOldLocalAppData
    $env:APPDATA = $wardOldAppData
    $env:HOME = $wardOldHome
    $env:USERPROFILE = $wardOldUserProfile
    $env:GH_CONFIG_DIR = $wardOldGHConfigDir
    if (Test-Path -LiteralPath $wardE2ETemp) { Remove-Item -Recurse -Force -LiteralPath $wardE2ETemp }
}
