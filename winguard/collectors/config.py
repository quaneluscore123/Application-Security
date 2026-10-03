"""Thu thập cấu hình bảo mật của máy (chỉ đọc, không thay đổi gì)."""
import winreg

from winguard.collectors import persistence
from winguard.utils import powershell_json, run


def _num(value: str) -> int:
    return int(value) if value.isdigit() else 0  # "Never" / "None" -> 0


def net_accounts() -> dict:
    out = run(["net", "accounts"]).stdout
    # Thứ tự dòng của `net accounts` cố định -> đọc theo vị trí để không phụ thuộc ngôn ngữ hiển thị
    values = [line.split(":", 1)[1].strip() for line in out.splitlines() if ":" in line]
    if len(values) < 8:
        return {}
    return {
        "min_password_length": _num(values[3]),
        "lockout_threshold": _num(values[5]),
        "lockout_duration_min": _num(values[6]),
    }


def firewall_profiles() -> dict:
    data = powershell_json(
        "@(Get-NetFirewallProfile | Select-Object Name,@{n='Enabled';e={[bool]$_.Enabled}})"
    ) or []
    return {p["Name"]: p["Enabled"] for p in data}


def defender_status() -> dict:
    data = powershell_json(
        "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,AntivirusSignatureAge"
    )
    return data or {}


def uac_enabled() -> bool | None:
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            return winreg.QueryValueEx(key, "EnableLUA")[0] == 1
    except OSError:
        return None


ADMINS_SID = "S-1-5-32-544"  # nhóm Administrators, cố định trên mọi ngôn ngữ Windows


def local_users() -> list[dict]:
    return powershell_json(
        "@(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | Select-Object Name,SID,Disabled)"
    ) or []


def admin_members() -> list[dict]:
    """Thành viên nhóm Administrators (Name, SID). Tìm nhóm theo SID để không phụ thuộc ngôn ngữ."""
    # Phải là MỘT biểu thức (powershell_json gán `$r = ...`).
    # [char]92 = '\' (ký tự '\' và '"' bị hỏng khi truyền qua dòng lệnh Windows)
    group = (f"(New-Object Security.Principal.SecurityIdentifier '{ADMINS_SID}')"
             ".Translate([Security.Principal.NTAccount]).Value.Split([char]92)[1]")
    return powershell_json(
        f"@(([ADSI]('WinNT://./' + {group} + ',group')).Invoke('Members') | ForEach-Object {{ $t = $_.GetType(); "
        "[pscustomobject]@{Name = $t.InvokeMember('Name','GetProperty',$null,$_,$null); "
        "SID = (New-Object Security.Principal.SecurityIdentifier("
        "$t.InvokeMember('objectSid','GetProperty',$null,$_,$null), 0)).Value} })"
    ) or []


def collect() -> dict:
    return {
        "accounts_policy": net_accounts(),
        "firewall": firewall_profiles(),
        "defender": defender_status(),
        "uac_enabled": uac_enabled(),
        "local_users": local_users(),
        "admin_members": admin_members(),
        "run_keys": persistence.run_keys(),
        "scheduled_tasks": persistence.scheduled_tasks(),
    }
