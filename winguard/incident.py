"""WinGuard Incident Severity = 100 x T x C x W (kế hoạch v7.2 §5).

Đây là mô hình NỘI BỘ của WinGuard, không phải công thức của MITRE. Các trọng số là
quy tắc nội bộ, chưa được hiệu chỉnh thực nghiệm (chưa có bộ dữ liệu gán nhãn).
T = mức nghiêm trọng của hành vi; C = độ tin cậy rằng bằng chứng/tương quan đúng
(không phải độ tin cậy về ý đồ); W = trọng số tactic của hành vi quan sát được.
"""
from decimal import Decimal

from winguard.models import Alert
from winguard.utils import round_half_up

KIND = "WinGuard Incident Severity (nội bộ)"

T = {
    "privileged_group_change": 1.00,  # thay đổi thành viên Administrators
    "log_cleared": 0.90,              # xóa Security Event Log
    "autostart": 0.75,                # Run key / Scheduled Task
    "account_created": 0.75,          # tạo tài khoản cục bộ (duy trì truy cập)
    "credential_guessing": 0.60,      # brute force / password spraying
}
C = {
    "corroborated": 1.00,   # chuỗi tương quan đầy đủ + baseline xác nhận
    "single_source": 0.95,  # một nguồn (event HOẶC baseline) với đủ trường
    "heuristic": 0.80,      # vượt ngưỡng thống kê (người dùng thật cũng có thể gõ sai)
    "unverified": 0.60,     # thiếu SID / trường quan trọng hoặc các nguồn mâu thuẫn
}
W = {
    "Privilege Escalation": 1.00,
    "Defense Impairment": 0.90,
    "Persistence": 0.85,
    "Credential Access": 0.75,
}


def _factor(name: str, value) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        raise ValueError(f"{name} phải là số, nhận {value!r}")
    d = Decimal(str(value))
    if not Decimal(0) < d <= Decimal(1):
        raise ValueError(f"{name} phải thuộc (0, 1], nhận {value}")
    return d


def severity(t, c, w) -> float:
    """100 x T x C x W, làm tròn 1 chữ số (half-up). Hệ số ngoài (0, 1] hoặc thiếu -> ValueError."""
    return round_half_up(Decimal(100) * _factor("T", t) * _factor("C", c) * _factor("W", w), 1)


def apply(alert: Alert, behaviour: str, confidence: str, tactic: str, reason: str,
          events=()) -> Alert:
    """Gắn điểm + breakdown giải thích được T, C, W vào cảnh báo sự kiện."""
    t, c, w = T[behaviour], C[confidence], W[tactic]
    alert.score = severity(t, c, w)
    alert.score_kind = KIND
    alert.score_breakdown = {
        "model": KIND, "formula": "100 x T x C x W",
        "T": t, "C": c, "W": w,
        "behaviour": behaviour, "confidence": confidence, "tactic": tactic, "reason": reason,
        "event_ids": sorted({e["id"] for e in events}),
        "record_ids": sorted(r for r in {e.get("record_id") for e in events} if r is not None),
    }
    alert.unverified = confidence == "unverified"
    return alert
