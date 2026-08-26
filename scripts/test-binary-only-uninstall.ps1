[CmdletBinding()]
param(
    [string]$WardBinary = $(Join-Path (Split-Path $PSScriptRoot -Parent) 'ward.exe')
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$uninstaller = Join-Path $repoRoot 'uninstall.ps1'
$testTemp = Join-Path ([System.IO.Path]::GetTempPath()) ('ward-binary-only-uninstall-' + [guid]::NewGuid())
$testHome = Join-Path $testTemp 'home'
$testCodexHome = Join-Path $testHome '.codex'
$testInstallDir = Join-Path $testCodexHome 'ward\bin'
$testBinary = Join-Path $testInstallDir 'ward.exe'
$testStateHome = Join-Path $testTemp 'state'
$testConfig = Join-Path $testCodexHome 'config.toml'
$testHooks = Join-Path $testCodexHome 'hooks.json'
$testJournal = Join-Path $testStateHome 'Ward\state\core\integration-journal.json'
$savedEnvironment = @{
    HOME = $env:HOME
    USERPROFILE = $env:USERPROFILE
    CODEX_HOME = $env:CODEX_HOME
    WARD_INSTALL_DIR = $env:WARD_INSTALL_DIR
    LOCALAPPDATA = $env:LOCALAPPDATA
}

try {
    $sourceBinary = [System.IO.Path]::GetFullPath($WardBinary)
    if (-not (Test-Path -LiteralPath $sourceBinary -PathType Leaf)) {
        throw "Ward binary-only uninstall test: executable is unavailable: $sourceBinary"
    }

    New-Item -ItemType Directory -Force -Path $testInstallDir | Out-Null
    Copy-Item -LiteralPath $sourceBinary -Destination $testBinary
    $configBytes = ([System.Text.UTF8Encoding]::new($false)).GetBytes("approval_policy = `"never`"`nmodel = `"gpt-test`"`n")
    [System.IO.File]::WriteAllBytes($testConfig, $configBytes)

    if (Test-Path -LiteralPath $testHooks) { throw 'Ward binary-only uninstall test: hooks fixture must start absent' }
    if (Test-Path -LiteralPath $testJournal) { throw 'Ward binary-only uninstall test: journal fixture must start absent' }

    $env:HOME = $testHome
    $env:USERPROFILE = $testHome
    $env:CODEX_HOME = $testCodexHome
    $env:WARD_INSTALL_DIR = $testInstallDir
    $env:LOCALAPPDATA = $testStateHome
    $pwsh = (Get-Process -Id $PID).Path
    $output = @(& $pwsh -NoLogo -NoProfile -NonInteractive -File $uninstaller -InstallDir $testInstallDir 2>&1)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "Ward binary-only uninstall test: uninstaller exited $exitCode`: $($output -join [Environment]::NewLine)"
    }

    if (Test-Path -LiteralPath $testBinary) { throw 'Ward binary-only uninstall test: Ward binary was not removed' }
    $afterConfig = [System.IO.File]::ReadAllBytes($testConfig)
    if ([Convert]::ToBase64String($configBytes) -cne [Convert]::ToBase64String($afterConfig)) {
        throw 'Ward binary-only uninstall test: unrelated config bytes changed'
    }
    if (Test-Path -LiteralPath $testHooks) { throw 'Ward binary-only uninstall test: hooks.json was created' }
    if (Test-Path -LiteralPath $testJournal) { throw 'Ward binary-only uninstall test: integration journal was created' }
    if (Test-Path -LiteralPath $testStateHome) { throw 'Ward binary-only uninstall test: persistent state was created' }

    $legacyHooksBytes = ([System.Text.UTF8Encoding]::new($false)).GetBytes('{"hooks":{"PostToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"ward.exe hook codex-post-tool-use","timeout":10}]}]}}')
    [System.IO.File]::WriteAllBytes($testHooks, $legacyHooksBytes)
    $legacyOutput = @(& $pwsh -NoLogo -NoProfile -NonInteractive -File $uninstaller -InstallDir $testInstallDir 2>&1)
    $legacyExitCode = $LASTEXITCODE
    if ($legacyExitCode -eq 0) {
        throw 'Ward binary-only uninstall test: missing binary ignored a legacy Ward hook'
    }
    $legacyHooksAfter = [System.IO.File]::ReadAllBytes($testHooks)
    if ([Convert]::ToBase64String($legacyHooksBytes) -cne [Convert]::ToBase64String($legacyHooksAfter)) {
        throw 'Ward binary-only uninstall test: legacy hook bytes changed'
    }
    if (($legacyOutput -join [Environment]::NewLine) -notmatch 'Ward hook or config references remain') {
        throw "Ward binary-only uninstall test: legacy refusal was not reported: $($legacyOutput -join [Environment]::NewLine)"
    }

    [System.IO.File]::WriteAllText($testHooks, '{"hooks":{}}', [System.Text.UTF8Encoding]::new($false))
    $legacyConfigBytes = ([System.Text.UTF8Encoding]::new($false)).GetBytes("default_permissions = `"ward-baseline`"`n[permissions.ward-baseline]`n")
    [System.IO.File]::WriteAllBytes($testConfig, $legacyConfigBytes)
    $legacyConfigOutput = @(& $pwsh -NoLogo -NoProfile -NonInteractive -File $uninstaller -InstallDir $testInstallDir 2>&1)
    $legacyConfigExitCode = $LASTEXITCODE
    if ($legacyConfigExitCode -eq 0) {
        throw 'Ward binary-only uninstall test: missing binary ignored legacy Ward config'
    }
    $legacyConfigAfter = [System.IO.File]::ReadAllBytes($testConfig)
    if ([Convert]::ToBase64String($legacyConfigBytes) -cne [Convert]::ToBase64String($legacyConfigAfter)) {
        throw 'Ward binary-only uninstall test: legacy config bytes changed'
    }
    if (($legacyConfigOutput -join [Environment]::NewLine) -notmatch 'Ward hook or config references remain') {
        throw "Ward binary-only uninstall test: legacy config refusal was not reported: $($legacyConfigOutput -join [Environment]::NewLine)"
    }

    Write-Output 'PASS: Windows binary-only uninstall detected legacy hooks and config'
}
finally {
    foreach ($name in $savedEnvironment.Keys) {
        [System.Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
    }
    if (Test-Path -LiteralPath $testTemp) { Remove-Item -Recurse -Force -LiteralPath $testTemp }
}
