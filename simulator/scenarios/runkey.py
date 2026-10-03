"""Kịch bản 4 - Mô phỏng persistence qua Registry Run key (MITRE T1547.001).

Mã độc thường ghi đường dẫn của mình vào Run key để tự chạy mỗi khi đăng nhập.
Mô phỏng: thêm giá trị `SIM_WinGuard` trỏ tới Notepad vào HKCU Run.
(Nếu quên cleanup và khởi động lại máy, chỉ có Notepad mở lên.)
"""
import winreg

NAME = "runkey"
DESCRIPTION = "Thêm Run key SIM_WinGuard mở Notepad khi đăng nhập (T1547.001)"
KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE = "SIM_WinGuard"
COMMAND = r"C:\Windows\System32\notepad.exe"


def run_scenario(**_) -> dict:
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, VALUE, 0, winreg.REG_SZ, COMMAND)
    print(f"  + Đã thêm HKCU\\{KEY}\\{VALUE} = {COMMAND}")
    return {"key": f"HKCU\\{KEY}", "value": VALUE, "command": COMMAND}


def cleanup() -> None:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, VALUE)
        print(f"  - Đã xóa Run key {VALUE}")
    except FileNotFoundError:
        pass
