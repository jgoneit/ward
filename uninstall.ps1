[CmdletBinding()]
param(
    [string]$InstallDir = $(if ($env:WARD_INSTALL_DIR) { $env:WARD_INSTALL_DIR } elseif ($env:CODEX_HOME) { Join-Path $env:CODEX_HOME 'ward\bin' } else { Join-Path $HOME '.codex\ward\bin' })
)

$ErrorActionPreference = 'Stop'
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
    throw "Ward uninstaller: binary not found at $binary; reinstall the same version before removing the Codex integration"
}
Write-Output 'Ward audit state and key were preserved.'
