"""Gom cụm / tương quan sự kiện theo máy (kế hoạch v7.2 §6).

Trường dùng: asset_id = Computer, target_sid (4720), member_sid / group_sid (4732),
record_id = EventRecordID. Không ghép chỉ vì gần nhau về thời gian; SID là khóa chính.
"""
import hashlib
from datetime import timedelta

CORRELATION_WINDOW_S = 300


def dedupe(events: list[dict]) -> list[dict]:
    """Bỏ bản ghi trùng theo (asset_id, record_id); sự kiện thiếu record_id giữ nguyên. Sắp theo thời gian."""
    seen, out = set(), []
    for ev in sorted(events, key=lambda e: e["time"]):
        key = (ev.get("computer"), ev.get("record_id"))
        if ev.get("record_id") is not None:
            if key in seen:
                continue
            seen.add(key)
        out.append(ev)
    return out


def valid_sid(sid: str | None) -> bool:
    return bool(sid) and sid not in ("-", "?") and sid.startswith("S-")


def match_creation(addition: dict, creations: list[dict], window_s: int = CORRELATION_WINDOW_S):
    """Tìm 4720 cùng máy, cùng SID, xảy ra TRƯỚC 4732 trong cửa sổ.
    -> (sự kiện 4720 | None, ghi chú). 4720 đến sau 4732 -> không ghép, ghi chú bất thường."""
    asset, sid = addition.get("computer"), addition["data"].get("MemberSid")
    if not asset or not valid_sid(sid):
        return None, "thiếu asset_id hoặc SID - không tương quan"
    window = timedelta(seconds=window_s)
    same = [c for c in creations if c.get("computer") == asset and c["data"].get("TargetSid") == sid]
    before = [c for c in same if timedelta(0) <= addition["time"] - c["time"] <= window]
    if before:
        return before[-1], ""
    if any(timedelta(0) < c["time"] - addition["time"] <= window for c in same):
        return None, "4720 xuất hiện SAU 4732 (thứ tự bất thường) - giữ riêng"
    return None, ""


def root_cause_id(asset: str, sid: str, first_time) -> str:
    return hashlib.sha1(f"{asset}|{sid}|{first_time.isoformat()}".encode()).hexdigest()[:12]
