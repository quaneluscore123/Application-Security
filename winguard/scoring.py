"""Tính điểm bảo mật /100 từ các cảnh báo đang hoạt động."""
from winguard.models import Alert

# UNKNOWN bị trừ điểm: điểm mù giám sát cũng là rủi ro, không được "im lặng cho qua".
PENALTY = {"HIGH": 15, "MEDIUM": 8, "LOW": 3, "UNKNOWN": 5, "INFO": 0}


def score(alerts: list[Alert]) -> int:
    return max(0, 100 - sum(PENALTY[a.severity] for a in alerts if a.status == "active"))
