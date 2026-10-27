"""Hàm dùng chung cho các kịch bản: tạo/xóa tài khoản và thử đăng nhập (vô hại)."""
import ctypes
import secrets
from ctypes import wintypes

from winguard.utils import run

# LogonUserW: thử đăng nhập để Windows ghi Event 4625 (sai) giống tấn công thật,
# nhưng KHÔNG mở phiên, không chạy gì -> hoàn toàn vô hại.
LOGON32_LOGON_NETWORK = 3
LOGON32_PROVIDER_DEFAULT = 0
ERROR_ACCOUNT_LOCKED_OUT = 1909

_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_LogonUserW = _advapi32.LogonUserW
_LogonUserW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
                        wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
_LogonUserW.restype = wintypes.BOOL


def try_logon(user: str, password: str) -> int:
    """Trả về 0 nếu đăng nhập thành công, ngược lại là mã lỗi Win32."""
    token = wintypes.HANDLE()
    if _LogonUserW(user, ".", password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT,
                   ctypes.byref(token)):
        _kernel32.CloseHandle(token)
        return 0
    return ctypes.get_last_error()


def user_exists(name: str) -> bool:
    return run(["net", "user", name]).returncode == 0


def create_user(name: str) -> None:
    """Tạo lại tài khoản thử nghiệm với mật khẩu ngẫu nhiên (không lưu lại)."""
    delete_user(name)
    # Tối đa 14 ký tự: dài hơn thì `net user` hỏi xác nhận (Y/N)
    password = secrets.token_urlsafe(8)[:10] + "Aa1!"
    r = run(["net", "user", name, password, "/add", "/comment:WinGuard simulator - safe to delete"])
    if r.returncode != 0:
        raise RuntimeError(f"Không tạo được {name}: {r.stderr.strip() or r.stdout.strip()}")
    print(f"  + Đã tạo tài khoản thử nghiệm {name}")


def delete_user(name: str) -> None:
    if user_exists(name):
        run(["net", "user", name, "/delete"])
        print(f"  - Đã xóa tài khoản {name}")
