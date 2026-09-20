[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$handoffRoot = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
$workRoot = [IO.Path]::GetFullPath((Join-Path $handoffRoot '..')).TrimEnd([IO.Path]::DirectorySeparatorChar)
$projectRoot = Join-Path $workRoot 'Mstech.IisSslManager'
$testsRoot = Join-Path $workRoot 'Mstech.IisSslManager.SmokeTests'
$archiveName = 'MSTECH-IisSslManager-1.1v-開發移交.zip'
$archivePath = Join-Path $handoffRoot $archiveName
$hashPath = $archivePath + '.sha256.txt'
$stageRoot = Join-Path $handoffRoot ('.handoff-stage-' + [Guid]::NewGuid().ToString('N'))
$payloadRoot = Join-Path $stageRoot 'MSTECH-IisSslManager-1.1v-Source'

function Assert-DirectChild([string]$Parent, [string]$Child) {
    $parentFull = [IO.Path]::GetFullPath($Parent).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $childFull = [IO.Path]::GetFullPath($Child)
    if (-not [string]::Equals(
            [IO.Path]::GetDirectoryName($childFull),
            $parentFull,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "拒絕操作不在預期目錄下的路徑：$childFull"
    }
}

function Copy-FilteredTree(
    [string]$Source,
    [string]$Destination,
    [string[]]$ExcludedTopDirectories) {
    $sourceFull = [IO.Path]::GetFullPath($Source).TrimEnd([IO.Path]::DirectorySeparatorChar)
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    foreach ($file in Get-ChildItem -LiteralPath $sourceFull -Recurse -Force -File) {
        $relative = [IO.Path]::GetRelativePath($sourceFull, $file.FullName)
        $top = $relative.Split([IO.Path]::DirectorySeparatorChar, 2)[0]
        if ($ExcludedTopDirectories -contains $top) {
            continue
        }

        $target = Join-Path $Destination $relative
        $targetParent = [IO.Path]::GetDirectoryName($target)
        New-Item -ItemType Directory -Path $targetParent -Force | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $target
    }
}

Assert-DirectChild $handoffRoot $stageRoot
Assert-DirectChild $handoffRoot $archivePath
Assert-DirectChild $handoffRoot $hashPath

try {
    New-Item -ItemType Directory -Path $payloadRoot -Force | Out-Null
    Copy-FilteredTree $projectRoot (Join-Path $payloadRoot 'Mstech.IisSslManager') @('bin', 'obj', 'artifacts')
    Copy-FilteredTree $testsRoot (Join-Path $payloadRoot 'Mstech.IisSslManager.SmokeTests') @('bin', 'obj')

    $referenceRoot = Join-Path $payloadRoot 'references'
    New-Item -ItemType Directory -Path $referenceRoot -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $workRoot 'win-acme.v2.2.9.1701.x64.trimmed.zip') -Destination $referenceRoot
    Copy-Item -LiteralPath (Join-Path $workRoot 'win-acme-source-3f6d83b.zip') -Destination $referenceRoot

    $documentRoot = Join-Path $payloadRoot '移交文件'
    New-Item -ItemType Directory -Path $documentRoot -Force | Out-Null
    foreach ($document in Get-ChildItem -LiteralPath $handoffRoot -Force -File) {
        if ($document.Name.EndsWith('.zip', [StringComparison]::OrdinalIgnoreCase) -or
            $document.Name.EndsWith('.zip.sha256.txt', [StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        Copy-Item -LiteralPath $document.FullName -Destination $documentRoot
    }

    $manifestPath = Join-Path $payloadRoot 'SOURCE-FILES.sha256.txt'
    $manifestLines = foreach ($file in Get-ChildItem -LiteralPath $payloadRoot -Recurse -Force -File | Sort-Object FullName) {
        $relative = [IO.Path]::GetRelativePath($payloadRoot, $file.FullName).Replace('\', '/')
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        "$hash  $relative"
    }
    Set-Content -LiteralPath $manifestPath -Value $manifestLines -Encoding utf8

    if (Test-Path -LiteralPath $archivePath) {
        Remove-Item -LiteralPath $archivePath -Force
    }
    if (Test-Path -LiteralPath $hashPath) {
        Remove-Item -LiteralPath $hashPath -Force
    }

    Compress-Archive -Path $payloadRoot -DestinationPath $archivePath -CompressionLevel Optimal
    $archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
    Set-Content -LiteralPath $hashPath -Value "$archiveHash  $archiveName" -Encoding utf8

    Write-Host "Archive: $archivePath"
    Write-Host "SHA-256: $archiveHash"
}
finally {
    if (Test-Path -LiteralPath $stageRoot) {
        Assert-DirectChild $handoffRoot $stageRoot
        Remove-Item -LiteralPath $stageRoot -Recurse -Force
    }
}
