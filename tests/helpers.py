"""Dữ liệu giả lập dùng chung cho test (không gọi PowerShell, không cần quyền Admin)."""
from datetime import datetime, timedelta, timezone

T0 = datetime(2026, 10, 28, 3, 0, 0, tzinfo=timezone.utc)
ADMINS_SID = "S-1-5-32-544"


def ev(event_id: int, seconds: float = 0, computer: str = "LAB-PC", record_id: int | None = None,
       **data) -> dict:
    """Sự kiện ở dạng mà collectors.eventlog trả về."""
    e = {"id": event_id, "time": T0 + timedelta(seconds=seconds), "data": dict(data)}
    e["computer"] = computer
    e["record_id"] = record_id
    return e


def failed_logon(user: str, seconds: float = 0, source: str = "LAB-PC", **kw) -> dict:
    return ev(4625, seconds, TargetUserName=user, WorkstationName=source, IpAddress="-", **kw)


def base_cfg(**over) -> dict:
    """Cấu hình "sạch" theo dạng config.collect() tại mốc 80fa1c1."""
    cfg = {
        "accounts_policy": {"min_password_length": 8, "lockout_threshold": 5, "lockout_duration_min": 10},
        "firewall": {"Domain": True, "Private": True, "Public": True},
        "defender": {"RealTimeProtectionEnabled": True, "AntivirusEnabled": True,
                     "AntivirusSignatureAge": 0},
        "local_users": [{"Name": "quan", "SID": "S-1-5-21-1-1001", "Disabled": False}],
        "admin_members": [{"Name": "quan", "SID": "S-1-5-21-1-1001"}],
        "run_keys": [],
        "scheduled_tasks": [],
        "uac_enabled": True,
        "_errors": [],
    }
    cfg.update(over)
    return cfg


EVENT_XML = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
             "<EventID>4720</EventID><TimeCreated SystemTime='2026-10-28T03:00:00.1234567Z'/>"
             "<EventRecordID>42</EventRecordID><Computer>LAB-PC</Computer></System>"
             "<EventData><Data Name='TargetSid'>S-1-5-21-1-2002</Data></EventData></Event>")
