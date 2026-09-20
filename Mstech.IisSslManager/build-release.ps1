[CmdletBinding()]
param(
    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    # Windows PowerShell 5.1 does not reliably populate $PSScriptRoot while
    # default parameter expressions are evaluated. Resolve the default only
    # after parameter binding, when the script root is available.
    $OutputRoot = Join-Path $PSScriptRoot 'artifacts'
}

$projectRootFull = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
$outputRootFull = [IO.Path]::GetFullPath($OutputRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
if (-not $outputRootFull.StartsWith($projectRootFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputRoot must be a directory inside the project folder.'
}

$OutputRoot = $outputRootFull
$projectPath = Join-Path $PSScriptRoot 'Mstech.IisSslManager.csproj'
[xml]$projectMetadata = Get-Content -LiteralPath $projectPath -Raw -Encoding UTF8
$version = [string]$projectMetadata.Project.PropertyGroup.Version
if ($version -notmatch '^([0-9]+)\.([0-9]+)\.0$') {
    throw 'Expected a major.minor.0 project version.'
}
$artifactVersion = 'v' + $Matches[1] + '.' + $Matches[2]
$artifactName = 'MSTECH-IisSslManager-' + $artifactVersion + '-win-x64'
$publishPath = Join-Path $OutputRoot $artifactName
$archivePath = Join-Path $OutputRoot ($artifactName + '.zip')
$buildId = [Guid]::NewGuid().ToString('N')
$stagingPath = Join-Path $OutputRoot ('.building-' + $artifactVersion + '-' + $buildId)
$stagingArchive = Join-Path $OutputRoot ('.building-' + $artifactVersion + '-' + $buildId + '.zip')
$manualDirectory = Join-Path $PSScriptRoot 'output\pdf'
$installManuals = @(Get-ChildItem -LiteralPath $manualDirectory -Filter '*.pdf' -File -ErrorAction SilentlyContinue)

if ($installManuals.Count -ne 1) {
    throw "Expected exactly one install manual PDF in: $manualDirectory"
}
$installManualPath = $installManuals[0].FullName

foreach ($target in @($publishPath, $archivePath, ($archivePath + '.sha256.txt'))) {
    if (Test-Path -LiteralPath $target) {
        throw "Existing release is preserved. Choose another OutputRoot inside the project: $target"
    }
}

New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null

# Never follow a junction/symlink when publishing or moving a release directory.
$ancestor = Get-Item -LiteralPath $OutputRoot -Force
while ($null -ne $ancestor) {
    if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Release path contains a reparse point: $($ancestor.FullName)"
    }
    $ancestor = $ancestor.Parent
}

$smokeProject = Join-Path (Split-Path -Parent $PSScriptRoot) 'Mstech.IisSslManager.SmokeTests\Mstech.IisSslManager.SmokeTests.csproj'
dotnet run --project $smokeProject --configuration Release -p:TreatWarningsAsErrors=true
if ($LASTEXITCODE -ne 0) {
    throw 'Smoke tests failed. No existing release was changed.'
}

dotnet publish $projectPath `
    --configuration Release `
    --runtime win-x64 `
    --self-contained true `
    -p:DebugType=None `
    -p:DebugSymbols=false `
    -p:TreatWarningsAsErrors=true `
    --output $stagingPath

if ($LASTEXITCODE -ne 0) {
    throw 'dotnet publish failed.'
}

Copy-Item -LiteralPath $installManualPath -Destination $stagingPath

Compress-Archive -Path (Join-Path $stagingPath '*') -DestinationPath $stagingArchive -CompressionLevel Optimal

# Both recursive directory-move targets are explicit, validated direct children.
foreach ($target in @($stagingPath, $publishPath, $stagingArchive, $archivePath)) {
    $fullTarget = [IO.Path]::GetFullPath($target)
    if (-not [string]::Equals([IO.Path]::GetDirectoryName($fullTarget), $outputRootFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Release move target is outside OutputRoot: $fullTarget"
    }
    if ((Test-Path -LiteralPath $target) -and (((Get-Item -LiteralPath $target -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Release move target is a reparse point: $fullTarget"
    }
}
Move-Item -LiteralPath $stagingPath -Destination $publishPath
Move-Item -LiteralPath $stagingArchive -Destination $archivePath

$hash = Get-FileHash -LiteralPath $archivePath -Algorithm SHA256
$hashLine = "$($hash.Hash)  $([IO.Path]::GetFileName($archivePath))"
Set-Content -LiteralPath ($archivePath + '.sha256.txt') -Value $hashLine -Encoding ascii

Write-Host "Publish: $publishPath"
Write-Host "Archive: $archivePath"
Write-Host "SHA-256: $($hash.Hash)"
