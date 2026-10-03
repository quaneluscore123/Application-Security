"""Kịch bản 1 - Mô phỏng Brute Force (MITRE T1110) một cách vô hại.

- Tạo tài khoản thử nghiệm cục bộ `sim_testuser` với mật khẩu ngẫu nhiên.
- Gọi API LogonUserW với mật khẩu SAI nhiều lần -> Windows ghi Event 4625
  (và 4740 nếu chính sách khóa tài khoản được bật).
- cleanup() xóa tài khoản thử nghiệm.
Không có kết nối mạng, không đụng tới tài khoản thật.
"""
import ctypes
import secrets
from ctypes import wintypes

from winguard.utils import run

NAME = "bruteforce"
DESCRIPTION = "Đăng nhập sai nhiều lần vào tài khoản thử nghiệm sim_testuser (T1110)"
USER = "sim_testuser"

LOGON32_LOGON_NETWORK = 3
LOGON32_PROVIDER_DEFAULT = 0
ERROR_LOGON_FAILURE = 1326
ERROR_ACCOUNT_LOCKED_OUT = 1909

_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_LogonUserW = _advapi32.LogonUserW
_LogonUserW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
                        wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
_LogonUserW.restype = wintypes.BOOL


def _user_exists() -> bool:
    return run(["net", "user", USER]).returncode == 0


def _try_logon(password: str) -> int:
    """Trả về 0 nếu đăng nhập thành công, ngược lại là mã lỗi Win32."""
    token = wintypes.HANDLE()
    if _LogonUserW(USER, ".", password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT,
                   ctypes.byref(token)):
        _kernel32.CloseHandle(token)
        return 0
    return ctypes.get_last_error()


def setup() -> None:
    if _user_exists():
        return
    # Tối đa 14 ký tự: dài hơn thì `net user` hỏi xác nhận (Y/N) và bị treo.
    # Không lưu lại, không cần dùng tới.
    password = secrets.token_urlsafe(8)[:10] + "Aa1!"
    r = run(["net", "user", USER, password, "/add", "/comment:WinGuard simulator - safe to delete"])
    if r.returncode != 0:
        raise RuntimeError(f"Không tạo được {USER}: {r.stderr.strip() or r.stdout.strip()}")
    print(f"  + Đã tạo tài khoản thử nghiệm {USER}")


def run_scenario(attempts: int = 6) -> dict:
    setup()
    results = []
    for i in range(1, attempts + 1):
        code = _try_logon("wrong-" + secrets.token_hex(4))
        status = {0: "THÀNH CÔNG (bất thường)", ERROR_LOGON_FAILURE: "sai mật khẩu",
                  ERROR_ACCOUNT_LOCKED_OUT: "TÀI KHOẢN BỊ KHÓA"}.get(code, f"lỗi {code}")
        print(f"  - Lần {i}: {status}")
        results.append(code)
        if code == ERROR_ACCOUNT_LOCKED_OUT:
            break
    locked_at = results.index(ERROR_ACCOUNT_LOCKED_OUT) + 1 if ERROR_ACCOUNT_LOCKED_OUT in results else None
    return {"user": USER, "attempts": len(results), "locked_at_attempt": locked_at}


def cleanup() -> None:
    if _user_exists():
        run(["net", "user", USER, "/delete"])
        print(f"  - Đã xóa tài khoản {USER}")
