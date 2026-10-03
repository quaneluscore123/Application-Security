# Khôi phục máy về trạng thái trước khi làm lab (PowerShell quyền Administrator):
#   powershell -ExecutionPolicy Bypass -File tools\restore.ps1

$ErrorActionPreference = "Stop"
$root = Join-Path $PSScriptRoot ".."
$data = Join-Path $root "data"

Push-Location $root
try { python -m simulator --cleanup --yes } finally { Pop-Location }

$auditBackup = Join-Path $data "auditpol_backup.csv"
if (Test-Path $auditBackup) {
    auditpol /restore /file:$auditBackup | Out-Null
    Write-Host "[+] Đã khôi phục audit policy"
}

$acctBackup = Join-Path $data "net_accounts_backup.json"
if (Test-Path $acctBackup) {
    $b = Get-Content $acctBackup -Raw | ConvertFrom-Json
    net accounts /minpwlen:$($b.minpwlen) | Out-Null
    net accounts /lockoutthreshold:$($b.lockoutthreshold) | Out-Null
    if ($b.lockoutthreshold -gt 0) {
        net accounts /lockoutwindow:$($b.lockoutwindow) /lockoutduration:$($b.lockoutduration) | Out-Null
    }
    Write-Host "[+] Đã khôi phục chính sách tài khoản"
}
Write-Host "Hoàn tất."
