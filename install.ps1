[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$')]
    [string]$Version,
    [string]$InstallDir = $(if ($env:WARD_INSTALL_DIR) { $env:WARD_INSTALL_DIR } elseif ($env:CODEX_HOME) { Join-Path $env:CODEX_HOME 'ward\bin' } else { Join-Path $HOME '.codex\ward\bin' })
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$codexDir = if ($env:CODEX_HOME) { [System.IO.Path]::GetFullPath($env:CODEX_HOME) } else { [System.IO.Path]::GetFullPath((Join-Path $HOME '.codex')) }
$homeDir = [System.IO.Path]::GetFullPath($HOME)
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
$localAppData = ([string]$env:LOCALAPPDATA).Trim()
if (-not $localAppData -or $localAppData -notmatch '^(?:[A-Za-z]:[\\/]|[\\/]{2})') { throw 'ward installer: LOCALAPPDATA must be absolute' }
$localAppData = [System.IO.Path]::GetFullPath($localAppData)
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

function New-WardFileSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Backup
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{ Path = $Path; Backup = $Backup; Present = $false }
    }
    $item = Get-Item -Force -LiteralPath $Path
    if ($item.PSIsContainer -or (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "ward installer: refusing non-regular integration file at $Path"
    }
    Copy-Item -Force -LiteralPath $Path -Destination $Backup
    $acl = Get-Acl -LiteralPath $Path
    return [pscustomobject]@{
        Path = $Path
        Backup = $Backup
        Present = $true
        Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Backup).Hash
        Attributes = $item.Attributes
        CreationTimeUtc = $item.CreationTimeUtc
        LastWriteTimeUtc = $item.LastWriteTimeUtc
        LastAccessTimeUtc = $item.LastAccessTimeUtc
        Acl = $acl
        AclSddl = $acl.Sddl
    }
}

function Restore-WardFileSnapshot {
    param(
        [Parameter(Mandatory = $true)]$Snapshot
    )
    $path = [string]$Snapshot.Path
    if (-not $Snapshot.Present) {
        if (Test-Path -LiteralPath $path) {
            $current = Get-Item -Force -LiteralPath $path
            if (-not $current.PSIsContainer) {
                [System.IO.File]::SetAttributes($path, [System.IO.FileAttributes]::Normal)
            }
            Remove-Item -Force -LiteralPath $path
        }
        if (Test-Path -LiteralPath $path) { throw "absence was not restored for $path" }
        return
    }
    $parent = [System.IO.Path]::GetDirectoryName($path)
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $candidate = "$path.ward-restore.$PID"
    Copy-Item -Force -LiteralPath ([string]$Snapshot.Backup) -Destination $candidate
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $candidate).Hash -cne [string]$Snapshot.Hash) {
        throw "snapshot bytes changed for $path"
    }
    if (Test-Path -LiteralPath $path) {
        $current = Get-Item -Force -LiteralPath $path
        if (-not $current.PSIsContainer) {
            [System.IO.File]::SetAttributes($path, [System.IO.FileAttributes]::Normal)
        }
        Remove-Item -Force -LiteralPath $path
    }
    Move-Item -Force -LiteralPath $candidate -Destination $path
    Set-Acl -LiteralPath $path -AclObject $Snapshot.Acl
    [System.IO.File]::SetCreationTimeUtc($path, $Snapshot.CreationTimeUtc)
    [System.IO.File]::SetLastWriteTimeUtc($path, $Snapshot.LastWriteTimeUtc)
    [System.IO.File]::SetLastAccessTimeUtc($path, $Snapshot.LastAccessTimeUtc)
    [System.IO.File]::SetAttributes($path, $Snapshot.Attributes)
    $restored = Get-Item -Force -LiteralPath $path
    $restoredAcl = Get-Acl -LiteralPath $path
    if ($restored.Attributes -ne $Snapshot.Attributes -or
        $restored.CreationTimeUtc -ne $Snapshot.CreationTimeUtc -or
        $restored.LastWriteTimeUtc -ne $Snapshot.LastWriteTimeUtc -or
        $restoredAcl.Sddl -cne [string]$Snapshot.AclSddl) {
        throw "snapshot metadata was not restored for $path"
    }
}

function Restore-WardInstallationSnapshot {
    param(
        [Parameter(Mandatory = $true)]$Hooks,
        [Parameter(Mandatory = $true)]$Config,
        [Parameter(Mandatory = $true)]$Journal,
        [Parameter(Mandatory = $true)]$Binary
    )
    try {
        # Restore integration bytes first. If that fails, keep the new verified
        # binary runnable for recovery from any surviving hook definition.
        Restore-WardFileSnapshot -Snapshot $Hooks
        Restore-WardFileSnapshot -Snapshot $Config
        Restore-WardFileSnapshot -Snapshot $Journal
        Restore-WardFileSnapshot -Snapshot $Binary
    }
    catch {
        throw "ward installer: exact snapshot restoration failed; the new binary was preserved when possible: $($_.Exception.Message)"
    }
}

$wardBinary = Join-Path $InstallDir 'ward.exe'
$previousBinary = Join-Path $tempDir 'ward.previous.exe'
$hooksFile = Join-Path $codexDir 'hooks.json'
$configFile = Join-Path $codexDir 'config.toml'
$journalFile = Join-Path (Join-Path (Join-Path $localAppData 'Ward') 'state\core') 'integration-journal.json'
$previousHooks = Join-Path $tempDir 'hooks.previous'
$previousConfig = Join-Path $tempDir 'config.previous'
$previousJournal = Join-Path $tempDir 'journal.previous'
$binaryReplaced = $false
$failureHandled = $false

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
    $binarySnapshot = New-WardFileSnapshot -Path $wardBinary -Backup $previousBinary
    $hooksSnapshot = New-WardFileSnapshot -Path $hooksFile -Backup $previousHooks
    $configSnapshot = New-WardFileSnapshot -Path $configFile -Backup $previousConfig
    $journalSnapshot = New-WardFileSnapshot -Path $journalFile -Backup $previousJournal
    $candidate = Join-Path $InstallDir ('.ward.new.' + $PID + '.exe')
    Copy-Item -LiteralPath $source -Destination $candidate
    $binaryReplaced = $true
    Move-Item -Force -LiteralPath $candidate -Destination $wardBinary
    Write-Output "installed Ward $Version at $wardBinary"

    $preflight = @(& $wardBinary codex install --scope user --dry-run 2>&1)
    $preflightCode = $LASTEXITCODE
    if ($preflightCode -eq 0) {
        & $wardBinary codex install --scope user
        if ($LASTEXITCODE -ne 0) {
            $failureHandled = $true
            Restore-WardInstallationSnapshot -Hooks $hooksSnapshot -Config $configSnapshot -Journal $journalSnapshot -Binary $binarySnapshot
            throw 'ward installer: Core configuration failed; the exact Core and binary snapshot was restored'
        }
        & $wardBinary doctor --project (Get-Location).Path --json | Out-Null
        if ($LASTEXITCODE -ne 0) {
            $failureHandled = $true
            Restore-WardInstallationSnapshot -Hooks $hooksSnapshot -Config $configSnapshot -Journal $journalSnapshot -Binary $binarySnapshot
            throw 'ward installer: Doctor reported an unhealthy check; the exact Core and binary snapshot was restored'
        }
        Write-Output 'Ward Core configured. Hook definition trust is required and was not verified; confirm it once in Codex /hooks.'
    }
    else {
        $preflight | Select-Object -First 20 | ForEach-Object { [Console]::Error.WriteLine($_) }
        $failureHandled = $true
        Restore-WardInstallationSnapshot -Hooks $hooksSnapshot -Config $configSnapshot -Journal $journalSnapshot -Binary $binarySnapshot
        throw 'ward installer: Core preflight failed; the exact Core and binary snapshot was restored'
    }
}
catch {
    $failure = $_
    if ($binaryReplaced -and -not $failureHandled) {
        $failureHandled = $true
        Restore-WardInstallationSnapshot -Hooks $hooksSnapshot -Config $configSnapshot -Journal $journalSnapshot -Binary $binarySnapshot
    }
    throw $failure
}
finally {
    if (Test-Path -LiteralPath $tempDir) { Remove-Item -Recurse -Force -LiteralPath $tempDir }
}
