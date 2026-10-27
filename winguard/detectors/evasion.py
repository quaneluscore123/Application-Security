"""Phát hiện hành vi né tránh phòng thủ / xóa dấu vết.

- Event 1102: Security Event Log bị xóa (MITRE T1070.001 Clear Windows Event Logs).
  Đây là dấu hiệu giai đoạn 5 (xóa dấu vết). 1102 được Windows tự ghi lại ngay
  sau khi log bị xóa nên không cần bật audit riêng.
"""
from winguard.models import Alert

LOG_CLEARED = 1102
MITRE = "T1070.001 Clear Windows Event Logs"


def detect(events: list[dict]) -> list[Alert]:
    alerts = []
    for ev in events:
        if ev["id"] == LOG_CLEARED:
            who = ev["data"].get("SubjectUserName", "?")
            alerts.append(Alert(
                "HIGH", "Security Event Log đã bị xóa (Event 1102)",
                f"Lúc {ev['time'].astimezone():%Y-%m-%d %H:%M:%S}"
                + (f", thực hiện bởi '{who}'" if who != "?" else "") + ".",
                "Điều tra ngay; lưu log tập trung để không mất dấu vết khi log cục bộ bị xóa.",
                MITRE))
    return alerts
