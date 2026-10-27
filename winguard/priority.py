"""WinGuard Investigation Priority = 100 x OperationalImpact x UncertaintyMultiplier (kế hoạch v7.2 §10).

Chỉ số NỘI BỘ cho các mục NEEDS_REVIEW, không phải điểm MITRE. Trọng số chưa hiệu chỉnh thực nghiệm.
Mỗi mục NEEDS_REVIEW mang mã lý do trong evidence["review_code"].
"""
from decimal import Decimal

from winguard.models import NEEDS_REVIEW, Alert
from winguard.utils import round_half_up

KIND = "WinGuard Investigation Priority (nội bộ)"

# mã -> (OperationalImpact, UncertaintyMultiplier, mô tả)
TABLE = {
    "HMAC_MISMATCH": (0.80, 1.0, "Chữ ký HMAC của baseline không khớp"),
    "PRIVILEGED_UNVERIFIED": (0.70, 1.0, "Thay đổi nhóm đặc quyền chưa xác minh được"),
    "BASELINE_UNSIGNED": (0.60, 1.0, "Baseline chưa ký / mất khóa"),
    "PASSWORD_NOT_REQUIRED": (0.60, 1.0, "Tài khoản có cờ PasswordRequired=False"),
    "SCORING_ERROR": (0.60, 1.0, "Không tính được điểm CWSS cho phát hiện đã xác nhận"),
    "COLLECTOR_ERROR": (0.50, 1.0, "Collector lỗi - điểm mù giám sát"),
    "PROFILE_UNDEFINED": (0.50, 1.0, "Profile/ngưỡng chưa xác định"),
    "NETWORK_CATEGORY_UNKNOWN": (0.50, 1.0, "Kết nối có NetworkCategory không ánh xạ được"),
    "INSUFFICIENT_EVIDENCE": (0.50, 1.0, "Không đủ dữ liệu để kết luận"),
    "DEFENDER_SIGNATURE_OLD": (0.40, 1.0, "Chữ ký Defender cũ"),
    "FIREWALL_INACTIVE_PROFILE_OFF": (0.30, 1.0, "Profile firewall tắt nhưng đang không dùng"),
    "OTHER_PRODUCT_ACTIVE": (0.20, 1.0, "Có sản phẩm bảo vệ khác thay thế - cần xác nhận"),
}


def priority(code: str) -> tuple[float, dict]:
    impact, uncertainty, label = TABLE[code]
    score = round_half_up(Decimal(100) * Decimal(str(impact)) * Decimal(str(uncertainty)), 1)
    return score, {"model": KIND, "formula": "100 x OperationalImpact x UncertaintyMultiplier",
                   "review_code": code, "OperationalImpact": impact,
                   "UncertaintyMultiplier": uncertainty, "reason": label}


def assign(alerts: list[Alert]) -> list[Alert]:
    """Gắn Investigation Priority cho mọi mục NEEDS_REVIEW chưa có điểm. Mã lạ -> INSUFFICIENT_EVIDENCE."""
    for a in alerts:
        if a.pillar != NEEDS_REVIEW or a.score is not None:
            continue
        code = a.evidence.get("review_code") or a.root_cause
        if code not in TABLE:
            code = "INSUFFICIENT_EVIDENCE"
        a.score, a.score_breakdown = priority(code)
        a.score_kind = KIND
    return alerts
