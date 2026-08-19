[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$')]
    [string]$Version,
    [string]$InstallDir = $(if ($env:WARD_INSTALL_DIR) { $env:WARD_INSTALL_DIR } elseif ($env:CODEX_HOME) { Join-Path $env:CODEX_HOME 'ward\bin' } else { Join-Path $HOME '.codex\ward\bin' })
)

$ErrorActionPreference = 'Stop'
$codexDir = if ($env:CODEX_HOME) { [System.IO.Path]::GetFullPath($env:CODEX_HOME) } else { [System.IO.Path]::GetFullPath((Join-Path $HOME '.codex')) }
$homeDir = [System.IO.Path]::GetFullPath($HOME)
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
if (-not [string]::Equals([System.IO.Directory]::GetParent($codexDir).FullName, $homeDir, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'ward installer: v0.1 requires CODEX_HOME directly below HOME' }
$codexPrefix = $codexDir.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
if (-not $InstallDir.StartsWith($codexPrefix, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'ward installer: InstallDir must remain below CODEX_HOME' }
$controlCursor = $InstallDir
while ($true) {
    if (Test-Path -LiteralPath $controlCursor) {
        $controlItem = Get-Item -Force -LiteralPath $controlCursor
        if (($controlItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "ward installer: control path must not contain a reparse point: $controlCursor"
        }
    }
    if ([string]::Equals($controlCursor, $codexDir, [System.StringComparison]::OrdinalIgnoreCase)) { break }
    $controlParent = [System.IO.Directory]::GetParent($controlCursor)
    if (-not $controlParent) { throw 'ward installer: could not validate the CODEX_HOME control chain' }
    $controlCursor = $controlParent.FullName
}
$arch = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
    'X64' { 'amd64' }
    'Arm64' { 'arm64' }
    default { throw 'ward installer: unsupported architecture' }
}
$plainVersion = $Version.TrimStart('v')
$archive = "ward_${plainVersion}_windows_${arch}.zip"
$baseUrl = "https://github.com/jgoneit/ward/releases/download/$Version"
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ward-install-" + [guid]::NewGuid())

try {
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    Invoke-WebRequest -Uri "$baseUrl/$archive" -OutFile (Join-Path $tempDir $archive)
    Invoke-WebRequest -Uri "$baseUrl/checksums.txt" -OutFile (Join-Path $tempDir 'checksums.txt')
    $checksumLine = Get-Content (Join-Path $tempDir 'checksums.txt') | Where-Object { $_ -match "\s\*?$([regex]::Escape($archive))$" } | Select-Object -First 1
    if (-not $checksumLine) { throw 'ward installer: archive checksum is missing' }
    $expected = ($checksumLine -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $tempDir $archive)).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { throw 'ward installer: checksum mismatch' }

    Expand-Archive -Path (Join-Path $tempDir $archive) -DestinationPath $tempDir
    $source = Join-Path $tempDir 'ward.exe'
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'ward installer: archive does not contain ward.exe' }
    $reported = [string](& $source --version)
    if ($reported -cne "ward $plainVersion") { throw 'ward installer: binary version does not match requested tag' }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $candidate = Join-Path $InstallDir ('.ward.new.' + $PID + '.exe')
    Copy-Item -LiteralPath $source -Destination $candidate
    Move-Item -Force -LiteralPath $candidate -Destination (Join-Path $InstallDir 'ward.exe')
    Write-Output "installed Ward $Version at $(Join-Path $InstallDir 'ward.exe')"
    Write-Output "run: $(Join-Path $InstallDir 'ward.exe') codex install --scope user --profile baseline --dry-run"
}
finally {
    if (Test-Path -LiteralPath $tempDir) { Remove-Item -Recurse -Force -LiteralPath $tempDir }
}
