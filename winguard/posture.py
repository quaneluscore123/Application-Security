"""WinGuard Posture Score (kế hoạch v7.2 §11) - chỉ số NỘI BỘ, không phải điểm MITRE CWSS.

Posture = max(0, 100 - Peak CWSS - 0.1 x tổng CWSS các cụm độc lập còn lại)
Cụm = một nguyên nhân gốc (root_cause, VD 'firewall'); nhiều phát hiện cùng cụm chỉ lấy CWSS cao nhất.
"""
from decimal import Decimal

from winguard.models import CONFIRMED_WEAKNESS, Alert
from winguard.utils import round_half_up

KIND = "WinGuard Posture Score (nội bộ)"
FORMULA = "max(0, 100 - Peak CWSS - 0.1 x tổng CWSS các cụm độc lập còn lại)"


def posture(alerts: list[Alert]) -> dict:
    confirmed = [a for a in alerts if a.pillar == CONFIRMED_WEAKNESS and a.status == "active"]
    unscored = [a.title for a in confirmed if a.score is None or a.scoring_error]
    result = {"kind": KIND, "formula": FORMULA, "clusters": {}, "peak": None, "others": [],
              "unscored": unscored, "score": None}
    if unscored:
        return result  # không lặng lẽ bỏ qua phát hiện chưa có điểm
    for a in confirmed:
        best = result["clusters"].get(a.root_cause)
        result["clusters"][a.root_cause] = a.score if best is None else max(best, a.score)
    scores = sorted(result["clusters"].values(), reverse=True)
    if not scores:
        result["score"] = 100.0
        return result
    result["peak"], result["others"] = scores[0], scores[1:]
    value = Decimal(100) - Decimal(str(scores[0])) - Decimal("0.1") * sum(Decimal(str(s)) for s in scores[1:])
    result["score"] = round_half_up(max(Decimal(0), value), 1)
    return result
