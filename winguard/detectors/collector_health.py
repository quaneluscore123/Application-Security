"""Báo UNKNOWN khi một collector lỗi hoặc không đọc được dữ liệu.

Điểm mù giám sát (không biết trạng thái) cũng là rủi ro: thay vì im lặng
trả về rỗng rồi tính như "an toàn", WinGuard báo UNKNOWN và trừ điểm.
"""
from winguard.models import Alert


def detect(cfg: dict) -> list[Alert]:
    alerts = []
    for name in cfg.get("_errors", []):
        alerts.append(Alert(
            "UNKNOWN", f"Không thu thập được dữ liệu: {name}",
            "Collector lỗi hoặc trả về rỗng; không thể kết luận trạng thái mục này.",
            "Chạy lại bằng quyền Administrator; kiểm tra PowerShell và dịch vụ liên quan.",
            category="config"))
    return alerts
