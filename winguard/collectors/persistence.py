"""Thu thập các vị trí tự khởi động (persistence) - chỉ đọc."""
import winreg

from winguard.utils import powershell_json

RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
]


def run_keys() -> list[dict]:
    entries = []
    for hive, hive_name, path in RUN_KEYS:
        try:
            with winreg.OpenKey(hive, path) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    entries.append({"location": f"{hive_name}\\{path}", "name": name, "command": str(value)})
                    i += 1
        except OSError:
            continue
    return entries


def scheduled_tasks() -> list[dict]:
    return powershell_json(
        "@(Get-ScheduledTask | Select-Object TaskPath,TaskName,State,@{n='Actions';e={"
        "(@($_.Actions | ForEach-Object { ($_.Execute + ' ' + $_.Arguments).Trim() })) -join '; '}})"
    ) or []
