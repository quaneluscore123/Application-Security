"""Kịch bản 3 - Mô phỏng thêm tài khoản vào nhóm Administrators (MITRE T1098).

Kẻ tấn công nâng quyền cho tài khoản đã tạo để toàn quyền điều khiển máy.
Mô phỏng: tạo `sim_user` rồi thêm vào Administrators -> Event 4720 + 4732.
"""
from simulator.scenarios._common import create_user, delete_user
from winguard.collectors.config import ADMINS_SID
from winguard.utils import powershell

NAME = "admin_group"
DESCRIPTION = "Tạo sim_user và thêm vào nhóm Administrators (T1098)"
USER = "sim_user"


def run_scenario(**_) -> dict:
    create_user(USER)
    # Chỉ định nhóm theo SID để chạy được trên Windows mọi ngôn ngữ
    r = powershell(f"Add-LocalGroupMember -SID '{ADMINS_SID}' -Member '{USER}' -ErrorAction Stop")
    if r.returncode != 0:
        raise RuntimeError(f"Không thêm được {USER} vào Administrators: {r.stderr.strip()}")
    print(f"  + Đã thêm {USER} vào nhóm Administrators")
    return {"user": USER, "group_sid": ADMINS_SID}


def cleanup() -> None:
    delete_user(USER)  # xóa tài khoản cũng xóa luôn tư cách thành viên nhóm
