"""Luật phát hiện Brute Force và Password Spraying dựa trên Event 4625 và 4740.

- 4625: đăng nhập thất bại
- 4740: tài khoản bị khóa (biện pháp phòng thủ đã có tác dụng)

Brute Force (T1110):           nhiều lần sai vào MỘT tài khoản.
Password Spraying (T1110.003): MỘT nguồn thử sai vào NHIỀU tài khoản (ít lần mỗi
tài khoản để né ngưỡng khóa) -> luật brute force theo từng tài khoản sẽ bỏ sót.
"""
from collections import Counter, defaultdict
from datetime import timedelta

from winguard.models import Alert

FAILED_LOGON = 4625
ACCOUNT_LOCKED = 4740
MITRE = "T1110 Brute Force"
SPRAY_MITRE = "T1110.003 Password Spraying"


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


def detect(events: list[dict], threshold: int = 5, window_min: int = 5,
           spray: bool = True) -> list[Alert]:
    """spray=False: chỉ dùng luật brute force theo từng tài khoản (bộ luật v1, trước khi vá)."""
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

    if spray:
        alerts += _detect_spray(events, window_min)
    return alerts


def _spray_burst(samples: list[dict], window: timedelta) -> tuple[int, object, object]:
    """Cửa sổ trượt: số TÀI KHOẢN khác nhau nhiều nhất bị cùng một nguồn thử trong `window`."""
    samples = sorted(samples, key=lambda s: s["time"])
    counts: Counter = Counter()
    best, start = (0, None, None), 0
    for s in samples:
        counts[s["user"]] += 1
        while s["time"] - samples[start]["time"] > window:
            su = samples[start]["user"]
            counts[su] -= 1
            if counts[su] == 0:
                del counts[su]
            start += 1
        distinct = len(counts)
        if distinct > best[0]:
            best = (distinct, samples[start]["time"], s["time"])
    return best


def _detect_spray(events: list[dict], window_min: int, spray_accounts: int = 5) -> list[Alert]:
    """Một nguồn thử sai vào >= spray_accounts tài khoản khác nhau trong cửa sổ thời gian."""
    by_source: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        if ev["id"] == FAILED_LOGON:
            by_source[_source(ev)].append(
                {"time": ev["time"], "user": ev["data"].get("TargetUserName", "?")})

    alerts = []
    for source, samples in by_source.items():
        count, first, last = _spray_burst(samples, timedelta(minutes=window_min))
        if count < spray_accounts:
            continue
        users = sorted({s["user"] for s in samples})
        shown = ", ".join(users[:6]) + (" …" if len(users) > 6 else "")
        alerts.append(Alert(
            "HIGH", f"Nghi ngờ Password Spraying từ nguồn '{source}'",
            f"{count} tài khoản khác nhau bị thử sai từ {first.astimezone():%H:%M:%S} "
            f"đến {last.astimezone():%H:%M:%S} (tài khoản: {shown}).",
            "Bật khóa tài khoản + MFA; theo dõi đăng nhập sai theo NGUỒN, không chỉ theo tài khoản.",
            SPRAY_MITRE))
    return alerts
