"""Phát hiện tạo tài khoản mới (MITRE T1136) và thêm vào nhóm Administrators (T1098).

Hai lớp phát hiện, gộp theo SID để không báo trùng:
- Event Log: 4720 (tạo tài khoản), 4732 (thêm thành viên vào nhóm)
- So với baseline: vẫn phát hiện được nếu kẻ tấn công đã xóa log
"""
from winguard.collectors.config import ADMINS_SID
from winguard.models import Alert

ACCOUNT_CREATED = 4720
MEMBER_ADDED = 4732
# Tài khoản tạo mới đã được phê duyệt (giảm báo động giả). sim_testuser phục vụ kịch bản 1.
# Allowlist chỉ áp dụng cho việc TẠO tài khoản, không áp dụng khi tài khoản được thêm vào Admin.
ALLOWED_NEW_ACCOUNTS = {"sim_testuser"}


def _event_note(ev: dict) -> str:
    who = ev["data"].get("SubjectUserName", "?")
    return f"Event {ev['id']} lúc {ev['time'].astimezone():%H:%M:%S} (thực hiện bởi '{who}')"


def detect(events: list[dict], cfg: dict, baseline_cfg: dict | None) -> list[Alert]:
    names: dict[str, str] = {}
    new_users: dict[str, list[str]] = {}
    new_admins: dict[str, list[str]] = {}

    for ev in events:
        d = ev["data"]
        if ev["id"] == ACCOUNT_CREATED:
            sid = d.get("TargetSid", "?")
            names[sid] = d.get("TargetUserName", sid)
            new_users.setdefault(sid, []).append(_event_note(ev))
        elif ev["id"] == MEMBER_ADDED and d.get("TargetSid") == ADMINS_SID:
            new_admins.setdefault(d.get("MemberSid", "?"), []).append(_event_note(ev))

    for item in cfg.get("local_users", []) + cfg.get("admin_members", []):
        names.setdefault(item["SID"], item["Name"])

    if baseline_cfg and "local_users" in baseline_cfg:
        known = {u["SID"] for u in baseline_cfg["local_users"]}
        for u in cfg.get("local_users", []):
            if u["SID"] not in known:
                new_users.setdefault(u["SID"], []).append("Không có trong baseline")
    if baseline_cfg and "admin_members" in baseline_cfg:
        known = {m["SID"] for m in baseline_cfg["admin_members"]}
        for m in cfg.get("admin_members", []):
            if m["SID"] not in known:
                new_admins.setdefault(m["SID"], []).append("Thành viên Administrators mới so với baseline")

    alerts = []
    for sid, notes in new_admins.items():
        name = names.get(sid, sid)
        alerts.append(Alert("HIGH", f"Tài khoản '{name}' được thêm vào nhóm Administrators",
                            "; ".join(notes) + f". SID: {sid}",
                            f"Nếu không phải bạn làm: net localgroup Administrators {name} /delete ; "
                            "dùng tài khoản Standard hằng ngày (quyền tối thiểu), giữ UAC bật.",
                            "T1098 Account Manipulation"))
    for sid, notes in new_users.items():
        name = names.get(sid, sid)
        if name in ALLOWED_NEW_ACCOUNTS:
            continue
        alerts.append(Alert("MEDIUM", f"Tài khoản mới '{name}' được tạo",
                            "; ".join(notes) + f". SID: {sid}",
                            f"Xác minh tài khoản; nếu lạ: net user {name} /delete",
                            "T1136.001 Create Account: Local Account"))
    return alerts
