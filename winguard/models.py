"""Mô hình dữ liệu cảnh báo."""
from dataclasses import dataclass, asdict

# UNKNOWN: không thu thập/đo được -> coi là rủi ro (điểm mù), vẫn bị trừ điểm.
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "UNKNOWN": 3, "INFO": 4}


@dataclass
class Alert:
    severity: str            # HIGH | MEDIUM | LOW | INFO
    title: str
    detail: str
    recommendation: str = ""
    mitre: str = ""          # VD: "T1110 Brute Force"
    category: str = "event"  # event | config
    status: str = "active"   # active | mitigated

    def to_dict(self) -> dict:
        return asdict(self)
