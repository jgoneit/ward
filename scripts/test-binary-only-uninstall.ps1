[CmdletBinding()]
param(
    [string]$WardBinary = $(Join-Path (Split-Path $PSScriptRoot -Parent) 'ward.exe')
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
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
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$savedEnvironment = @{
    HOME = $env:HOME
    USERPROFILE = $env:USERPROFILE
    CODEX_HOME = $env:CODEX_HOME
    WARD_INSTALL_DIR = $env:WARD_INSTALL_DIR
    LOCALAPPDATA = $env:LOCALAPPDATA
}

function Assert-NoPersistentState {
    param([string]$Description)

    if (Test-Path -LiteralPath $testJournal) {
        throw "Ward binary-only uninstall test: $Description created an integration journal"
    }
    if (Test-Path -LiteralPath $testStateHome) {
        throw "Ward binary-only uninstall test: $Description created persistent state"
    }
}

function Assert-ConfigOutcome {
    param(
        [string]$Description,
        [string]$Content,
        [bool]$ShouldRefuse
    )

    $configCaseBytes = $utf8NoBom.GetBytes($Content)
    $emptyHooksBytes = $utf8NoBom.GetBytes('{"hooks":{}}')
    [System.IO.File]::WriteAllBytes($testConfig, $configCaseBytes)
    [System.IO.File]::WriteAllBytes($testHooks, $emptyHooksBytes)

    $caseOutput = @(& $pwsh -NoLogo -NoProfile -NonInteractive -File $uninstaller -InstallDir $testInstallDir 2>&1)
    $caseExitCode = $LASTEXITCODE
    if ($ShouldRefuse -and $caseExitCode -ne 1) {
        throw "Ward binary-only uninstall test: $Description returned $caseExitCode, want 1: $($caseOutput -join [Environment]::NewLine)"
    }
    if (-not $ShouldRefuse -and $caseExitCode -ne 0) {
        throw "Ward binary-only uninstall test: $Description was falsely refused: $($caseOutput -join [Environment]::NewLine)"
    }
    if ($ShouldRefuse -and (($caseOutput -join [Environment]::NewLine) -notmatch 'Ward hook or config references remain')) {
        throw "Ward binary-only uninstall test: $Description refusal was not reported: $($caseOutput -join [Environment]::NewLine)"
    }
    if (-not $ShouldRefuse -and (($caseOutput -join [Environment]::NewLine) -notmatch 'Ward integration is already absent')) {
        throw "Ward binary-only uninstall test: $Description absence was not reported: $($caseOutput -join [Environment]::NewLine)"
    }
    $configCaseAfter = [System.IO.File]::ReadAllBytes($testConfig)
    if ([Convert]::ToBase64String($configCaseBytes) -cne [Convert]::ToBase64String($configCaseAfter)) {
        throw "Ward binary-only uninstall test: $Description config bytes changed"
    }
    $emptyHooksAfter = [System.IO.File]::ReadAllBytes($testHooks)
    if ([Convert]::ToBase64String($emptyHooksBytes) -cne [Convert]::ToBase64String($emptyHooksAfter)) {
        throw "Ward binary-only uninstall test: $Description hook bytes changed"
    }
    Assert-NoPersistentState $Description
}

try {
    $sourceBinary = [System.IO.Path]::GetFullPath($WardBinary)
    if (-not (Test-Path -LiteralPath $sourceBinary -PathType Leaf)) {
        throw "Ward binary-only uninstall test: executable is unavailable: $sourceBinary"
    }

    New-Item -ItemType Directory -Force -Path $testInstallDir | Out-Null
    Copy-Item -LiteralPath $sourceBinary -Destination $testBinary
    $configBytes = $utf8NoBom.GetBytes("approval_policy = `"never`"`nmodel = `"gpt-test`"`n")
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

    $legacyHooksBytes = $utf8NoBom.GetBytes('{"hooks":{"PostToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"ward.exe hook codex-post-tool-use","timeout":10}]}]}}')
    [System.IO.File]::WriteAllBytes($testHooks, $legacyHooksBytes)
    $legacyOutput = @(& $pwsh -NoLogo -NoProfile -NonInteractive -File $uninstaller -InstallDir $testInstallDir 2>&1)
    $legacyExitCode = $LASTEXITCODE
    if ($legacyExitCode -ne 1) {
        throw "Ward binary-only uninstall test: legacy Ward hook returned $legacyExitCode, want 1"
    }
    $legacyHooksAfter = [System.IO.File]::ReadAllBytes($testHooks)
    if ([Convert]::ToBase64String($legacyHooksBytes) -cne [Convert]::ToBase64String($legacyHooksAfter)) {
        throw 'Ward binary-only uninstall test: legacy hook bytes changed'
    }
    $legacyConfigAfter = [System.IO.File]::ReadAllBytes($testConfig)
    if ([Convert]::ToBase64String($configBytes) -cne [Convert]::ToBase64String($legacyConfigAfter)) {
        throw 'Ward binary-only uninstall test: legacy hook changed config bytes'
    }
    if (($legacyOutput -join [Environment]::NewLine) -notmatch 'Ward hook or config references remain') {
        throw "Ward binary-only uninstall test: legacy refusal was not reported: $($legacyOutput -join [Environment]::NewLine)"
    }
    Assert-NoPersistentState 'legacy Ward hook refusal'

    Assert-ConfigOutcome 'legacy Ward selector and bare profile table' "default_permissions = `"ward-baseline`"`n[permissions.ward-baseline]`n" $true
    Assert-ConfigOutcome 'single-quoted Ward selector' "default_permissions = 'ward'`n" $true
    Assert-ConfigOutcome 'double-quoted Ward profile table key with whitespace' "[ permissions . `"ward`" ]`n" $true
    Assert-ConfigOutcome 'single-quoted Ward profile table key with whitespace' "[ 'permissions' . 'ward-baseline' ]`n" $true
    Assert-ConfigOutcome 'Ward child profile path' "[permissions.ward.child]`n" $true
    Assert-ConfigOutcome 'legacy v1 Ward marker' "# ward:migrated-sandbox-mode:v1`n" $true
    Assert-ConfigOutcome 'version-independent Ward marker' "# >>> ward future-profile v99 >>>`n" $true
    $nearMisses = @(
        '[projects."/Users/name/plugins/ward"]'
        'enabled_plugins = ["ward@personal"]'
        'note = "hospital ward config"'
        'name = "forward"'
        'other = "wardrobe"'
        'profile = "my_ward"'
        'permission = "ward-extra"'
        'default_permissions = "WARD"'
        '[permissions.ward-baseline-extra]'
    ) -join "`n"
    Assert-ConfigOutcome 'non-Ward near matches' ($nearMisses + "`n") $false

    Write-Output 'PASS: Windows binary-only uninstall detected structural Ward references without near-miss refusals'
}
finally {
    foreach ($name in $savedEnvironment.Keys) {
        [System.Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
    }
    if (Test-Path -LiteralPath $testTemp) { Remove-Item -Recurse -Force -LiteralPath $testTemp }
}

# Expected refusal probes leave a nonzero native status behind. Reaching this
# point means every assertion and cleanup operation succeeded.
exit 0
