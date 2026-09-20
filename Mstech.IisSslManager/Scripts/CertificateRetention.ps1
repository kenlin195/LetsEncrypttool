[CmdletBinding()]
param(
    [string] $OldThumbprint = '',
    [string] $NewThumbprint = '',
    [ValidateRange(1, 365)]
    [int] $RetentionDays = 30,
    [switch] $Cleanup
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Normalize-Thumbprint([string] $Value) {
    if ($Value -match '^\{.+\}$') {
        return ''
    }

    $normalized = ($Value -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($normalized.Length -ne 0 -and $normalized.Length -ne 40) {
        throw '憑證指紋格式錯誤。'
    }
    return $normalized
}

$old = Normalize-Thumbprint $OldThumbprint
$new = Normalize-Thumbprint $NewThumbprint
if ([string]::IsNullOrWhiteSpace($old) -or $old -eq $new) {
    exit 0
}

$taskName = "MSTECH IIS SSL Cleanup $($old.Substring(0, 16))"

if (-not $Cleanup) {
    $scriptPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($scriptPath)) {
        throw '無法判斷憑證保留腳本路徑。'
    }

    $actionArguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
        $scriptPath + '" -Cleanup -OldThumbprint "' + $old +
        '" -NewThumbprint "' + $new + '" -RetentionDays ' + $RetentionDays
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $actionArguments
    $trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddDays($RetentionDays))
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    exit 0
}

# Never delete a certificate that is still referenced by any IIS HTTPS binding.
$iisAssembly = Join-Path $env:SystemRoot 'System32\inetsrv\Microsoft.Web.Administration.dll'
if (-not (Test-Path -LiteralPath $iisAssembly -PathType Leaf)) {
    throw '找不到 Microsoft.Web.Administration.dll，保留舊憑證。'
}

[void][System.Reflection.Assembly]::LoadFrom($iisAssembly)
$serverManager = New-Object Microsoft.Web.Administration.ServerManager
try {
    foreach ($site in $serverManager.Sites) {
        foreach ($binding in $site.Bindings) {
            if ($binding.Protocol -ne 'https' -or $null -eq $binding.CertificateHash) {
                continue
            }

            $boundThumbprint = ([System.BitConverter]::ToString($binding.CertificateHash) -replace '-', '').ToUpperInvariant()
            if ($boundThumbprint -eq $old) {
                # Safety wins over cleanup timing. A later administrator review can
                # remove a certificate that intentionally remains bound.
                exit 0
            }
        }
    }
}
finally {
    $serverManager.Dispose()
}

# IIS is not the only consumer of HTTP.sys SSL certificate mappings. Fail closed
# when netsh cannot be inspected, and retain the certificate when its thumbprint
# still appears in any non-IIS HTTP.sys sslcert registration.
$netshPath = Join-Path $env:SystemRoot 'System32\netsh.exe'
if (-not (Test-Path -LiteralPath $netshPath -PathType Leaf)) {
    throw '找不到 netsh.exe，無法確認 HTTP.sys SSL 使用狀態，保留舊憑證。'
}

$netshOutput = @(& $netshPath http show sslcert 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw "netsh http show sslcert 失敗（ExitCode=$LASTEXITCODE），保留舊憑證。"
}

$netshText = ($netshOutput | Out-String)
$hashPattern = '(?i)(?<![0-9A-F])(?:[0-9A-F]{2}[-:\s]?){19}[0-9A-F]{2}(?![0-9A-F])'
foreach ($match in [System.Text.RegularExpressions.Regex]::Matches($netshText, $hashPattern)) {
    $httpSysThumbprint = ($match.Value -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($httpSysThumbprint -eq $old) {
        exit 0
    }
}

$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('WebHosting', 'LocalMachine')
try {
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $matches = @($store.Certificates | Where-Object { $_.Thumbprint -eq $old })
    foreach ($certificate in $matches) {
        $store.Remove($certificate)
        $certificate.Dispose()
    }
}
finally {
    $store.Close()
}

# Best-effort removal of this completed one-time task.
try {
    & "$env:SystemRoot\System32\schtasks.exe" /Delete /TN $taskName /F | Out-Null
}
catch {
    # Leaving a completed task behind is safer than treating successful
    # certificate cleanup as a renewal failure.
}

exit 0
