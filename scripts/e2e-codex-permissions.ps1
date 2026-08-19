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
    $arguments = @('sandbox', '-P', 'ward-baseline', '-C', $wardE2EWorkspace, 'powershell', '-NoProfile', '-Command', $Script)
    & $CodexBinary @arguments
    return $LASTEXITCODE
}

try {
    if (-not (Test-Path -LiteralPath $WardBinary -PathType Leaf)) { throw 'Ward E2E: build bin\ward.exe first' }
    if (-not (Get-Command $CodexBinary -ErrorAction SilentlyContinue)) { throw 'Ward E2E: codex CLI is required' }
    New-Item -ItemType Directory -Force -Path $wardE2ECodexDir, $wardE2EManagedBinDir, (Join-Path $wardE2EWorkspace 'nested'), (Join-Path $wardE2EWorkspace 'schemas'), $wardE2ESibling, $wardE2ECustomGHDir | Out-Null
    Copy-Item -LiteralPath $WardBinary -Destination $wardE2EManagedBin
    $configPath = Join-Path $wardE2ECodexDir 'config.toml'
    @('approval_policy = "never"', 'sandbox_mode = "danger-full-access"') | Set-Content -Encoding utf8NoBOM $configPath
    $originalConfig = [System.IO.File]::ReadAllBytes($configPath)
    Set-Content -Encoding utf8NoBOM (Join-Path $wardE2EWorkspace '.env') 'WARD_SECRET_CANARY_7d10f7'
    Set-Content -Encoding utf8NoBOM (Join-Path $wardE2EWorkspace 'nested\.env.local') 'WARD_LOCAL_CANARY_2b98e1'
    Set-Content -Encoding utf8NoBOM (Join-Path $wardE2EWorkspace 'private-key.pem') 'WARD_KEY_CANARY_95d4bd'
    Set-Content -Encoding utf8NoBOM (Join-Path $wardE2EWorkspace 'privkey1.pem') 'WARD_NUMBERED_KEY_CANARY_2f0b77'
    Set-Content -Encoding utf8NoBOM (Join-Path $wardE2EWorkspace '.env.example') 'PUBLIC_TEMPLATE=1'
    Set-Content -Encoding utf8NoBOM (Join-Path $wardE2EWorkspace 'nested\.env.sample') 'PUBLIC_SAMPLE=1'
    Set-Content -Encoding utf8NoBOM (Join-Path $wardE2EWorkspace 'ordinary.txt') 'ordinary'
    Set-Content -Encoding utf8NoBOM (Join-Path $wardE2ESibling '.env') 'WARD_SIBLING_CANARY_f1a7b3'
    Set-Content -Encoding utf8NoBOM (Join-Path $wardE2ESibling '.env.production') 'WARD_PRODUCTION_CANARY_6b0d42'
    Set-Content -Encoding utf8NoBOM (Join-Path $wardE2ESibling '.env.example') 'PUBLIC_SIBLING=1'
    Set-Content -Encoding utf8NoBOM (Join-Path $wardE2ECustomGHDir 'hosts.yml') 'WARD_CUSTOM_GH_CANARY_4c8b21'
    Set-Content -Encoding utf8NoBOM (Join-Path $wardE2EWorkspace 'server.pem') 'PUBLIC CERTIFICATE FIXTURE'
    Set-Content -Encoding utf8NoBOM (Join-Path $wardE2EWorkspace 'private-notes.pem') 'PUBLIC NOTES FIXTURE'
    Set-Content -Encoding utf8NoBOM (Join-Path $wardE2EWorkspace 'private-certificate.pem') 'PUBLIC CERTIFICATE FIXTURE'
    Set-Content -Encoding utf8NoBOM (Join-Path $wardE2EWorkspace 'privkey1-notes.pem') 'PUBLIC NOTES FIXTURE'
    Set-Content -Encoding utf8NoBOM (Join-Path $wardE2EWorkspace 'schemas\user-credential.json') '{"type":"schema"}'
    Set-Content -Encoding utf8NoBOM (Join-Path $wardE2EWorkspace 'schemas\credential-format.json') '{"type":"schema"}'

    $env:CODEX_HOME = $wardE2ECodexDir
    $env:LOCALAPPDATA = $wardE2EStateDir
    $env:APPDATA = $wardE2EConfigDir
    $env:HOME = $wardE2EHome
    $env:USERPROFILE = $wardE2EHome
    $env:GH_CONFIG_DIR = $wardE2ECustomGHDir
    & $wardE2EManagedBin codex install --scope user --profile baseline --migrate-permissions
    if ($LASTEXITCODE -ne 0) { throw 'Ward E2E: install failed' }

    $configText = Get-Content -Raw $configPath
    if ($configText -notmatch 'approval_policy\s*=\s*"never"') { throw 'Ward E2E: approval_policy changed' }
    if ($configText -match '(?m)^\s*sandbox_mode\s*=') { throw 'Ward E2E: sandbox_mode remained active' }

    foreach ($script in @('Get-Content .env | Out-Null', 'Get-Content nested\.env.local | Out-Null', 'Get-Content private-key.pem | Out-Null', 'Get-Content privkey1.pem | Out-Null')) {
        $exitCode = Invoke-WardSandbox $script
        if ($exitCode -eq 0) { throw "Ward E2E: protected read escaped: $script" }
    }
    foreach ($path in @((Join-Path $wardE2ESibling '.env'), (Join-Path $wardE2ESibling '.env.production'))) {
        $escaped = $path.Replace("'", "''")
        $exitCode = Invoke-WardSandbox "Get-Content -LiteralPath '$escaped' | Out-Null"
        if ($exitCode -eq 0) { throw "Ward E2E: sibling secret escaped: $path" }
    }
    $customGHHosts = Join-Path $wardE2ECustomGHDir 'hosts.yml'
    $exitCode = Invoke-WardSandbox "Get-Content -LiteralPath '$($customGHHosts.Replace("'", "''"))' | Out-Null"
    if ($exitCode -eq 0) { throw 'Ward E2E: custom GH credential location escaped the native profile' }
    foreach ($controlPath in @($configPath, (Join-Path $wardE2ECodexDir 'hooks.json'), ([System.IO.Path]::GetFullPath($wardE2EManagedBin)))) {
        $escaped = $controlPath.Replace("'", "''")
        $exitCode = Invoke-WardSandbox "Set-Content -LiteralPath '$escaped' -Value 'tampered'"
        if ($exitCode -eq 0) { throw "Ward E2E: control-plane overwrite escaped: $controlPath" }
    }
    foreach ($anchor in @($wardE2ECodexDir, $wardE2EManagedBinDir, $wardE2ECustomGHDir, (Join-Path $wardE2EStateDir 'Ward\state'))) {
        $escaped = $anchor.Replace("'", "''")
        $destination = ($anchor + '.moved').Replace("'", "''")
        $exitCode = Invoke-WardSandbox "Move-Item -LiteralPath '$escaped' -Destination '$destination'"
        if ($exitCode -eq 0) { throw "Ward E2E: protected directory relocation escaped: $anchor" }
        if (-not (Test-Path -LiteralPath $anchor)) { throw "Ward E2E: protected directory disappeared: $anchor" }
    }
    $exitCode = Invoke-WardSandbox "Get-Content -LiteralPath '$($customGHHosts.Replace("'", "''"))' | Out-Null"
    if ($exitCode -eq 0) { throw 'Ward E2E: custom credential became readable after denied directory relocation' }
    $hookPayload = '{"session_id":"ward-e2e-session","cwd":"' + ($wardE2EWorkspace -replace '\\', '\\\\') + '","model":"gpt-test","permission_mode":"never","turn_id":"ward-e2e-turn","transcript_path":null,"tool_name":"Bash","tool_input":{"command":"Get-Content .env"},"tool_use_id":"ward-e2e-tool"}'
    $hookOutput = $hookPayload | & $wardE2EManagedBin hook codex-pre-tool-use
    if ($LASTEXITCODE -ne 0 -or ($hookOutput -join '') -notmatch '"permissionDecision"\s*:\s*"deny"') { throw 'Ward E2E: hook continuity failed after denied relocation' }
    $doctor = (& $wardE2EManagedBin doctor --project $wardE2EWorkspace --json | Out-String | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0 -or -not $doctor.healthy) { throw 'Ward E2E: trusted Host-side Doctor failed' }
    foreach ($checkID in @('permissions.state_topology', 'permissions.credential_topology')) {
        $check = $doctor.checks | Where-Object { $_.id -eq $checkID } | Select-Object -First 1
        if (-not $check -or $check.status -ne 'pass') { throw "Ward E2E: default project topology did not pass: $checkID" }
    }
    $managedBinEscaped = $wardE2EManagedBin.Replace("'", "''")
    $workspaceEscaped = $wardE2EWorkspace.Replace("'", "''")
    $exitCode = Invoke-WardSandbox "& '$managedBinEscaped' doctor --project '$workspaceEscaped' --json | Out-Null; exit `$LASTEXITCODE"
    if ($exitCode -eq 0) { throw 'Ward E2E: guarded project process unexpectedly gained Doctor access to denied control state' }
    foreach ($script in @(
        'Get-Content .env.example | Out-Null',
        'Get-Content nested\.env.sample | Out-Null',
        'Set-Content .env.example ''PUBLIC_TEMPLATE=2''',
        'Set-Content nested\.env.sample ''PUBLIC_SAMPLE=2''',
        'Get-Content ordinary.txt | Out-Null; Set-Content ordinary.txt ''edited''',
        'Get-Content server.pem | Out-Null; Set-Content server.pem ''PUBLIC CERTIFICATE FIXTURE 2''',
        'Get-Content private-notes.pem | Out-Null; Set-Content private-notes.pem ''PUBLIC NOTES FIXTURE 2''',
        'Get-Content private-certificate.pem | Out-Null; Set-Content private-certificate.pem ''PUBLIC CERTIFICATE FIXTURE 2''',
        'Get-Content privkey1-notes.pem | Out-Null; Set-Content privkey1-notes.pem ''PUBLIC NOTES FIXTURE 2''',
        'Get-Content schemas\user-credential.json | Out-Null; Set-Content schemas\user-credential.json ''{"type":"schema2"}''',
        'Get-Content schemas\credential-format.json | Out-Null; Set-Content schemas\credential-format.json ''{"type":"schema2"}'''
    )) {
        $exitCode = Invoke-WardSandbox $script
        if ($exitCode -ne 0) { throw "Ward E2E: ordinary operation failed: $script" }
    }
    $siblingTemplate = (Join-Path $wardE2ESibling '.env.example').Replace("'", "''")
    $exitCode = Invoke-WardSandbox "Get-Content -LiteralPath '$siblingTemplate' | Out-Null"
    if ($exitCode -ne 0) { throw 'Ward E2E: sibling public template was blocked' }

    $wardKey = Join-Path $wardE2EStateDir 'Ward\state\v1\master.key'
    $exitCode = Invoke-WardSandbox "Get-Content -LiteralPath '$($wardKey.Replace("'", "''"))' | Out-Null"
    if ($exitCode -eq 0) { throw 'Ward E2E: Ward master key read escaped the native profile' }

    & $wardE2EManagedBin codex uninstall --scope user --profile baseline
    if ($LASTEXITCODE -ne 0) { throw 'Ward E2E: uninstall failed' }
    $restored = [System.IO.File]::ReadAllBytes($configPath)
    if ([Convert]::ToBase64String($originalConfig) -ne [Convert]::ToBase64String($restored)) { throw 'Ward E2E: config bytes were not restored' }
    if (Test-Path -LiteralPath (Join-Path $wardE2ECodexDir 'hooks.json')) { throw 'Ward E2E: hooks.json was not restored to absent' }
    if (-not (Test-Path -LiteralPath $wardKey -PathType Leaf)) { throw 'Ward E2E: uninstall removed audit key' }
    Write-Output 'PASS: isolated native Windows Codex permission install/read/write/uninstall E2E'
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
