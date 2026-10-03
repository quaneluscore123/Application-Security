"""Luật phát hiện Brute Force (MITRE T1110) dựa trên Event 4625 và 4740.

- 4625: đăng nhập thất bại
- 4740: tài khoản bị khóa (biện pháp phòng thủ đã có tác dụng)
"""
from collections import defaultdict
from datetime import timedelta

from winguard.models import Alert

FAILED_LOGON = 4625
ACCOUNT_LOCKED = 4740
MITRE = "T1110 Brute Force"


def _max_burst(times: list, window: timedelta) -> tuple[int, int, int]:
    """Cửa sổ trượt: trả về (số lần nhiều nhất trong `window`, chỉ số đầu, chỉ số cuối)."""
    best, start_best, end_best, start = 0, 0, 0, 0
    for end, t in enumerate(times):
        while t - times[start] > window:
            start += 1
        if end - start + 1 > best:
            best, start_best, end_best = end - start + 1, start, end
    return best, start_best, end_best


def _source(ev: dict) -> str:
    """Nguồn đăng nhập: IP nếu có, nếu không thì tên máy ("-" nghĩa là trống)."""
    for key in ("IpAddress", "WorkstationName"):
        value = ev["data"].get(key, "")
        if value and value != "-":
            return value
    return "local"


def detect(events: list[dict], threshold: int = 5, window_min: int = 5) -> list[Alert]:
    failures, lockouts = defaultdict(list), defaultdict(list)
    for ev in events:
        user = ev["data"].get("TargetUserName", "?")
        if ev["id"] == FAILED_LOGON:
            failures[user].append(ev)
        elif ev["id"] == ACCOUNT_LOCKED:
            lockouts[user].append(ev)

    alerts = []
    for user, evs in failures.items():
        times = [e["time"] for e in evs]
        count, i, j = _max_burst(times, timedelta(minutes=window_min))
        if count < threshold:
            continue
        first, last = times[i], times[j]
        sources = sorted({_source(e) for e in evs[i:j + 1]})
        detail = (f"{count} lần đăng nhập thất bại vào tài khoản '{user}' "
                  f"từ {first.astimezone():%H:%M:%S} đến {last.astimezone():%H:%M:%S} "
                  f"(nguồn: {', '.join(sources)}).")
        if any(l["time"] >= first for l in lockouts[user]):
            alerts.append(Alert("LOW", f"Brute force bị chặn: '{user}' đã bị khóa (Event 4740)",
                                detail, "Chính sách khóa tài khoản đang hoạt động.", MITRE,
                                status="mitigated"))
        else:
            alerts.append(Alert("HIGH", f"Nghi ngờ Brute Force vào tài khoản '{user}'", detail,
                                "Bật khóa tài khoản: net accounts /lockoutthreshold:5 ; "
                                "dùng mật khẩu mạnh hoặc Windows Hello.", MITRE))

    for user, evs in lockouts.items():
        if user not in failures:
            alerts.append(Alert("MEDIUM", f"Tài khoản '{user}' bị khóa (Event 4740)",
                                f"{len(evs)} lần khóa, lần cuối lúc {evs[-1]['time'].astimezone():%H:%M:%S}.",
                                "Kiểm tra nguồn đăng nhập sai.", MITRE))
    return alerts
