"""Hàm dùng chung cho các kịch bản: tạo/xóa tài khoản thử nghiệm."""
import secrets

from winguard.utils import run


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
