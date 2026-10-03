"""Kịch bản 2 - Mô phỏng tạo tài khoản cục bộ (MITRE T1136.001).

Kẻ tấn công thường tạo tài khoản riêng để quay lại máy về sau (persistence).
Mô phỏng: tạo tài khoản `sim_user` -> Windows ghi Event 4720.
"""
from simulator.scenarios._common import create_user, delete_user

NAME = "new_account"
DESCRIPTION = "Tạo tài khoản cục bộ sim_user (T1136.001)"
USER = "sim_user"


def run_scenario(**_) -> dict:
    create_user(USER)
    return {"user": USER}


def cleanup() -> None:
    delete_user(USER)
