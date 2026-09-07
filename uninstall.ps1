[CmdletBinding()]
param(
    [string]$InstallDir = $(if ($env:WARD_INSTALL_DIR) { $env:WARD_INSTALL_DIR } elseif ($env:CODEX_HOME) { Join-Path $env:CODEX_HOME 'ward\bin' } else { Join-Path $HOME '.codex\ward\bin' })
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$codexDir = if ($env:CODEX_HOME) { [System.IO.Path]::GetFullPath($env:CODEX_HOME) } else { [System.IO.Path]::GetFullPath((Join-Path $HOME '.codex')) }
$homeDir = [System.IO.Path]::GetFullPath($HOME)
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
if (-not [string]::Equals([System.IO.Directory]::GetParent($codexDir).FullName, $homeDir, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'Ward uninstaller: v0.1 requires CODEX_HOME directly below HOME' }
$codexPrefix = $codexDir.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
if (-not $InstallDir.StartsWith($codexPrefix, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'Ward uninstaller: InstallDir must remain below CODEX_HOME' }
$controlCursor = $InstallDir
while ($true) {
    if (Test-Path -LiteralPath $controlCursor) {
        $controlItem = Get-Item -Force -LiteralPath $controlCursor
        if (($controlItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Ward uninstaller: control path must not contain a reparse point: $controlCursor"
        }
    }
    if ([string]::Equals($controlCursor, $codexDir, [System.StringComparison]::OrdinalIgnoreCase)) { break }
    $controlParent = [System.IO.Directory]::GetParent($controlCursor)
    if (-not $controlParent) { throw 'Ward uninstaller: could not validate the CODEX_HOME control chain' }
    $controlCursor = $controlParent.FullName
}
$binary = Join-Path $InstallDir 'ward.exe'
$hooksFile = Join-Path $codexDir 'hooks.json'
$configFile = Join-Path $codexDir 'config.toml'
if (Test-Path -LiteralPath $binary) {
    $item = Get-Item -Force -LiteralPath $binary
    if (-not $item.PSIsContainer -and $item.LinkType) {
        throw "Ward uninstaller: refusing linked binary at $binary; restore the exact Ward binary, then retry"
    }
    if ($item.PSIsContainer) { throw "Ward uninstaller: refusing non-file binary path at $binary" }
    & $binary codex uninstall --scope user
    if ($LASTEXITCODE -ne 0) { throw 'Ward uninstaller: Core integration removal failed; binary was preserved' }
    Remove-Item -LiteralPath $binary
    Write-Output "removed $binary"
} else {
    # Core verifies ownership and termination. Never remove service artifacts
    # with a fallback parser or claim absence while a collector survives.
    # Detect the fixed locator without parsing paths or deleting owned state.
    $diagnosticLocator = Join-Path $InstallDir '.ward-diagnostics\installation.json'
    if (Test-Path -LiteralPath $diagnosticLocator) {
        throw 'Ward uninstaller: Core binary is missing while diagnostics artifacts remain; reinstall the same version, then retry'
    }
    $diagnosticArtifacts = @((Join-Path $InstallDir 'ward-diagnostics.exe'))
    if (-not $env:LOCALAPPDATA -or -not [System.IO.Path]::IsPathRooted($env:LOCALAPPDATA)) {
        throw 'Ward uninstaller: LOCALAPPDATA must be absolute to inspect diagnostics'
    }
    $diagnosticState = Join-Path $env:LOCALAPPDATA 'Ward\state\core\diagnostics'
    foreach ($name in @('service-owner.json', 'runtime.json', 'heartbeat.json')) {
        $diagnosticArtifacts += Join-Path $diagnosticState $name
    }
    foreach ($artifact in $diagnosticArtifacts) {
        if (Test-Path -LiteralPath $artifact) {
            throw 'Ward uninstaller: Core binary is missing while diagnostics artifacts remain; reinstall the same version, then retry'
        }
    }
    $diagnosticTasks = & "$env:SystemRoot\System32\schtasks.exe" /Query /FO CSV /NH 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Ward uninstaller: cannot confirm diagnostics task absence; reinstall Core, then retry' }
    $diagnosticSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $diagnosticHash = [System.Security.Cryptography.SHA256]::Create()
    try {
        $diagnosticIdentity = [System.Text.Encoding]::UTF8.GetBytes($diagnosticSID + [char]0 + $binary)
        $diagnosticSuffix = ([System.BitConverter]::ToString($diagnosticHash.ComputeHash($diagnosticIdentity))).Replace('-', '').ToLowerInvariant().Substring(0, 24)
    } finally { $diagnosticHash.Dispose() }
    $diagnosticTaskPattern = '"\\WardDiagnostics-' + $diagnosticSuffix + '"'
    if (($diagnosticTasks -join "`n") -match $diagnosticTaskPattern) {
        throw 'Ward uninstaller: Core binary is missing while diagnostics task references remain; reinstall the same version, then retry'
    }
    $wardRefs = $false
    if (Test-Path -LiteralPath $hooksFile) {
        $hooksItem = Get-Item -Force -LiteralPath $hooksFile
        if ($hooksItem.PSIsContainer) {
            $wardRefs = $true
        }
        else {
            $hooksText = Get-Content -Raw -LiteralPath $hooksFile
            $escapedBinary = $binary.Replace('\', '\\')
            $wardRefs = $hooksText.Contains($binary) -or $hooksText.Contains($escapedBinary) -or $hooksText -match 'hook codex-(session-start|pre-tool-use|permission-request|post-tool-use)'
        }
    }
    if (Test-Path -LiteralPath $configFile) {
        $configItem = Get-Item -Force -LiteralPath $configFile
        if ($configItem.PSIsContainer) {
            $wardRefs = $true
        }
        else {
            $configText = Get-Content -Raw -LiteralPath $configFile
            # Detection-only fallback when Core is unavailable: recognize Ward's
            # reserved profile-key shapes and owned markers without depending on
            # a particular migration version or TOML quoting style.
            $wardConfigReferencePattern = '(?m)"ward(-baseline)?"|''ward(-baseline)?''|(\[|\.)[ \t]*ward(-baseline)?[ \t]*(\.|\])|^[ \t]*#[ \t<>]*ward([ \t:]|$)'
            if ($configText -cmatch $wardConfigReferencePattern) {
                $wardRefs = $true
            }
        }
    }
    if ($wardRefs) {
        throw "Ward uninstaller: binary is missing at $binary while Ward hook or config references remain; reinstall the same version, then retry"
    }
    Write-Output 'Ward integration is already absent; no Ward hook or config references were found.'
}
Write-Output 'Ward state directory was preserved.'
