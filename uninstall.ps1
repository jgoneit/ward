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
            if ($configText -match '# >>> ward (default permissions|permission profile) v[12] >>>|# ward:migrated-sandbox-(mode|workspace-write):v2|default_permissions\s*=\s*"ward-baseline"|\[permissions\.ward-baseline\]') {
                $wardRefs = $true
            }
        }
    }
    if ($wardRefs) {
        throw "Ward uninstaller: binary is missing at $binary while Ward hook or config references remain; reinstall the same version, then retry"
    }
    Write-Output 'Ward integration is already absent; no Ward hook or config references were found.'
}
Write-Output 'Ward audit state and key were preserved.'
