# Chuẩn bị lab (chạy 1 lần, PowerShell quyền Administrator):
#   powershell -ExecutionPolicy Bypass -File tools\prepare.ps1
# - Tạo System Restore Point
# - Sao lưu cấu hình audit + chính sách tài khoản vào data\
# - Bật audit cần thiết để Windows ghi Event 4624/4625/4720/4732/4740

$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Cần chạy PowerShell bằng quyền Administrator."
}

$data = Join-Path $PSScriptRoot "..\data"
New-Item -ItemType Directory -Force $data | Out-Null

try {
    Checkpoint-Computer -Description "WinGuard lab" -RestorePointType MODIFY_SETTINGS
    Write-Host "[+] Đã tạo System Restore Point"
} catch {
    Write-Warning "Không tạo được Restore Point (System Protection có thể đang tắt): $_"
}

$auditBackup = Join-Path $data "auditpol_backup.csv"
if (-not (Test-Path $auditBackup)) {
    auditpol /backup /file:$auditBackup | Out-Null
    Write-Host "[+] Đã sao lưu audit policy -> $auditBackup"
}

$acctBackup = Join-Path $data "net_accounts_backup.json"
if (-not (Test-Path $acctBackup)) {
    # Đọc theo vị trí dòng để không phụ thuộc ngôn ngữ hiển thị
    $v = @(net accounts | Where-Object { $_ -match ":" } | ForEach-Object { ($_ -split ":", 2)[1].Trim() })
    $toNum = { param($s) if ($s -match '^\d+$') { [int]$s } else { 0 } }
    @{ minpwlen = (& $toNum $v[3]); lockoutthreshold = (& $toNum $v[5]);
       lockoutduration = (& $toNum $v[6]); lockoutwindow = (& $toNum $v[7]) } |
        ConvertTo-Json | Set-Content -Encoding utf8 $acctBackup
    Write-Host "[+] Đã sao lưu chính sách tài khoản -> $acctBackup"
}

# Dùng GUID subcategory để không phụ thuộc ngôn ngữ Windows
$subcategories = @{
    "Logon"                     = "{0CCE9215-69AE-11D9-BED3-505054503030}"
    "Account Lockout"           = "{0CCE9217-69AE-11D9-BED3-505054503030}"
    "User Account Management"   = "{0CCE9235-69AE-11D9-BED3-505054503030}"
    "Security Group Management" = "{0CCE9237-69AE-11D9-BED3-505054503030}"
}
foreach ($name in $subcategories.Keys) {
    auditpol /set /subcategory:"$($subcategories[$name])" /success:enable /failure:enable | Out-Null
    Write-Host "[+] Bật audit: $name"
}
Write-Host "`nHoàn tất. Tiếp theo: python -m winguard --baseline"
