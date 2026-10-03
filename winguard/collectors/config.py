"""Thu thập cấu hình bảo mật của máy (chỉ đọc, không thay đổi gì)."""
import winreg

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


def collect() -> dict:
    return {
        "accounts_policy": net_accounts(),
        "firewall": firewall_profiles(),
        "defender": defender_status(),
        "uac_enabled": uac_enabled(),
    }
