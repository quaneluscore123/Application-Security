"""Kịch bản 6 - Mô phỏng Password Spraying (MITRE T1110.003) một cách vô hại.

Khác brute force: thay vì thử nhiều mật khẩu vào MỘT tài khoản, kẻ tấn công thử
ÍT mật khẩu (ở đây 2) vào NHIỀU tài khoản, để né ngưỡng khóa tài khoản.

Mục đích demo "thử né luật": vì mỗi tài khoản chỉ sai 2 lần (< ngưỡng 5), luật
brute force theo từng tài khoản sẽ BỎ SÓT; luật spraying theo nguồn mới bắt được.
"""
import secrets

from simulator.scenarios._common import create_user, delete_user, try_logon

NAME = "spray"
DESCRIPTION = "Password spraying: 1 nguồn thử sai vào nhiều tài khoản (T1110.003)"
USERS = [f"sim_spray{i}" for i in range(1, 7)]  # 6 tài khoản
ATTEMPTS_EACH = 2  # dưới ngưỡng brute force (5) -> luật cũ bỏ sót


def run_scenario(**_) -> dict:
    for user in USERS:
        create_user(user)
    print(f"  * Thử {ATTEMPTS_EACH} mật khẩu sai vào {len(USERS)} tài khoản (né ngưỡng khóa)")
    for user in USERS:
        for _i in range(ATTEMPTS_EACH):
            try_logon(user, "wrong-" + secrets.token_hex(4))
    print("  - Xong: mỗi tài khoản chỉ sai 2 lần nên không bị khóa")
    return {"users": USERS, "attempts_each": ATTEMPTS_EACH}


def cleanup() -> None:
    for user in USERS:
        delete_user(user)
