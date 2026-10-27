"""Mô hình dữ liệu cảnh báo."""
from dataclasses import asdict, dataclass, field

# UNKNOWN: không thu thập/đo được -> coi là rủi ro (điểm mù), vẫn bị trừ điểm.
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "UNKNOWN": 3, "INFO": 4}

# Ba trụ cột (kế hoạch v7.2 §1)
CONFIRMED_WEAKNESS = "CONFIRMED_WEAKNESS"  # điểm yếu cấu hình có bằng chứng -> CWE + CWSS
ATTACK_OBSERVED = "ATTACK_OBSERVED"        # hành vi trong Event Log -> ATT&CK + Incident Severity
NEEDS_REVIEW = "NEEDS_REVIEW"              # thiếu dữ liệu / lỗi / bất thường -> Investigation Priority
PILLARS = (CONFIRMED_WEAKNESS, ATTACK_OBSERVED, NEEDS_REVIEW)


@dataclass
class Alert:
    severity: str            # HIGH | MEDIUM | LOW | UNKNOWN | INFO (dùng cho Legacy Score)
    title: str
    detail: str
    recommendation: str = ""
    mitre: str = ""          # VD: "T1110 Brute Force" (chỉ mã trong attack.ATTACK_MAP)
    category: str = "event"  # event | config
    status: str = "active"   # active | mitigated
    # --- v7.2: các trường thêm sau, đều có mặc định để không đổi API cũ ---
    pillar: str = ""                 # một trong PILLARS; sự kiện mặc định là ATTACK_OBSERVED
    root_cause: str = ""             # VD "firewall", "uac", "T1098:<sid>"
    evidence: dict = field(default_factory=dict)   # observed, expected, profile, source, raw, missing
    cwe: str = ""
    cwe_status: str = ""             # proposed | verified
    cwe_rationale: str = ""
    attack_candidates: list = field(default_factory=list)  # ứng viên chưa xác nhận, không phải phát hiện
    score: float | None = None       # CWSS / Incident Severity / Investigation Priority tùy trụ cột
    score_kind: str = ""
    score_breakdown: dict = field(default_factory=dict)
    scoring_error: str = ""          # bộ tính điểm lỗi: phát hiện vẫn giữ nguyên
    alert_required: bool = False     # quy tắc phân loại nội bộ, tách khỏi điểm
    unverified: bool = False         # bằng chứng tương quan chưa đủ

    def __post_init__(self):
        if not self.pillar and self.category == "event":
            self.pillar = ATTACK_OBSERVED

    def to_dict(self) -> dict:
        return asdict(self)
