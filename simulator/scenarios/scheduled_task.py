"""Kịch bản 5 - Mô phỏng persistence qua Scheduled Task (MITRE T1053.005).

Kẻ tấn công tạo tác vụ định kỳ để chạy lại mã độc. Mô phỏng: tạo task
`SIM_WinGuardTest` mở Notepad, hẹn giờ 5 năm sau (không bao giờ thực sự chạy).
Windows ghi Event 4698 nếu bật audit "Other Object Access Events".
"""
from winguard.utils import powershell

NAME = "scheduled_task"
DESCRIPTION = "Tạo Scheduled Task SIM_WinGuardTest mở Notepad (T1053.005)"
TASK = "SIM_WinGuardTest"


def run_scenario(**_) -> dict:
    r = powershell(
        f"Register-ScheduledTask -TaskName '{TASK}' -Force -ErrorAction Stop "
        "-Description 'WinGuard simulator - safe to delete' "
        "-Action (New-ScheduledTaskAction -Execute 'C:\\Windows\\System32\\notepad.exe') "
        "-Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddYears(5)) | Out-Null"
    )
    if r.returncode != 0:
        raise RuntimeError(f"Không tạo được task: {r.stderr.strip()}")
    print(f"  + Đã tạo Scheduled Task \\{TASK} (mở Notepad, hẹn giờ 5 năm sau)")
    return {"task": f"\\{TASK}"}


def cleanup() -> None:
    r = powershell(f"Unregister-ScheduledTask -TaskName '{TASK}' -Confirm:$false -ErrorAction Stop")
    if r.returncode == 0:
        print(f"  - Đã xóa Scheduled Task {TASK}")
