"""Bộ tính MITRE CWSS v1.0.1 (công thức giữ nguyên theo tài liệu gốc).

Base = [(10*TI + 5*(AP+AL) + 5*FC) * f(TI) * IC] * 4
AS   = [20*(RP+RL+AV) + 20*SC + 15*IN + 5*AS] / 100
Env  = [(10*BI + 3*DI + 4*EX + 3*P) * f(BI) * EC] / 20
CWSS = Base * AS * Env        (f(x) = 0 nếu x = 0, ngược lại 1)

Tính bằng Decimal để kết quả tái lập được; làm tròn điểm cuối 1 chữ số (ROUND_HALF_UP).
"""
from decimal import Decimal

from winguard.cwss_weights import WEIGHTS, manual_check_status
from winguard.utils import round_half_up

METRICS = ("TI", "AP", "AL", "IC", "FC", "RP", "RL", "AV", "AS", "IN", "SC", "BI", "DI", "EX", "EC", "P")
IGNORED = {"RE"}  # có trong Example 4.2 nhưng không phải metric của CWSS 1.0


def parse(vector) -> dict:
    """'TI:H/AP:RU/...' hoặc dict -> {metric: mã}. Thiếu/thừa/sai mã/None -> ValueError.
    Chấp nhận dạng 'TI:H,0.9' của tài liệu (bỏ phần trọng số in kèm)."""
    if isinstance(vector, str):
        items = {}
        for part in filter(None, vector.strip().strip("()").split("/")):
            if ":" not in part:
                raise ValueError(f"metric sai định dạng: {part!r}")
            metric, code = part.split(":", 1)
            items[metric.strip()] = code.split(",")[0].strip()
        vector = items
    if not isinstance(vector, dict):
        raise ValueError("vector phải là chuỗi hoặc dict")
    codes = {}
    for metric, code in vector.items():
        if metric in IGNORED:
            continue
        if metric not in WEIGHTS:
            raise ValueError(f"metric không thuộc CWSS v1.0.1: {metric!r}")
        if code is None or code not in WEIGHTS[metric]:
            raise ValueError(f"mã không hợp lệ cho {metric}: {code!r}")
        codes[metric] = code
    missing = [m for m in METRICS if m not in codes]
    if missing:
        raise ValueError(f"thiếu metric: {', '.join(missing)}")
    return codes


def vector_string(codes: dict) -> str:
    return "/".join(f"{m}:{codes[m]}" for m in METRICS)


def compute(vector) -> dict:
    codes = parse(vector)
    w = {m: Decimal(str(WEIGHTS[m][codes[m]])) for m in METRICS}
    f_ti = 0 if w["TI"] == 0 else 1
    f_bi = 0 if w["BI"] == 0 else 1
    base = (10 * w["TI"] + 5 * (w["AP"] + w["AL"]) + 5 * w["FC"]) * f_ti * w["IC"] * 4
    surface = (20 * (w["RP"] + w["RL"] + w["AV"]) + 20 * w["SC"] + 15 * w["IN"] + 5 * w["AS"]) / 100
    env = (10 * w["BI"] + 3 * w["DI"] + 4 * w["EX"] + 3 * w["P"]) * f_bi * w["EC"] / 20
    exact = base * surface * env
    return {
        "standard": "MITRE CWSS v1.0.1",
        "vector_chosen_by": "WinGuard",
        "weights_manual_check": manual_check_status(),
        "vector_string": vector_string(codes),
        "weights": {m: float(w[m]) for m in METRICS},
        "base": float(base),
        "attack_surface": float(surface),
        "environmental": float(env),
        "score_exact": str(exact),
        "score": round_half_up(exact, 1),
    }
