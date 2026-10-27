"""Phát hiện tạo tài khoản mới (MITRE T1136.001) và thêm vào nhóm Administrators (T1098).

Hai lớp phát hiện, gộp theo SID để không báo trùng:
- Event Log: 4720 (tạo tài khoản), 4732 (thêm thành viên vào nhóm)
- So với baseline: vẫn phát hiện được nếu kẻ tấn công đã xóa log
Tương quan 4720 -> 4732 theo cùng máy + cùng SID trong cửa sổ thời gian (winguard.correlation);
độ tin cậy C của Incident Severity phản ánh có bao nhiêu nguồn xác nhận.
"""
from winguard import correlation, incident
from winguard.attack import label
from winguard.collectors.config import ADMINS_SID
from winguard.models import NEEDS_REVIEW, Alert

ACCOUNT_CREATED = 4720
MEMBER_ADDED = 4732
# Tài khoản lab đã được phê duyệt (giảm báo động giả): sim_testuser (kịch bản brute force)
# và sim_spray* (kịch bản password spraying). Allowlist chỉ áp dụng cho việc TẠO tài khoản,
# KHÔNG áp dụng khi tài khoản được thêm vào nhóm Admin.
ALLOWED_NEW_ACCOUNTS = {"sim_testuser"}
ALLOWED_PREFIXES = ("sim_spray",)


def _is_allowed(name: str) -> bool:
    return name in ALLOWED_NEW_ACCOUNTS or name.startswith(ALLOWED_PREFIXES)


def _event_note(ev: dict) -> str:
    who = ev["data"].get("SubjectUserName", "?")
    return f"Event {ev['id']} lúc {ev['time'].astimezone():%H:%M:%S} (thực hiện bởi '{who}')"


def _sids(items: list[dict] | None) -> set | None:
    return None if items is None else {i["SID"] for i in items}


def detect(events: list[dict], cfg: dict, baseline_cfg: dict | None) -> list[Alert]:
    events = correlation.dedupe(events)
    creations = [e for e in events if e["id"] == ACCOUNT_CREATED]
    additions = [e for e in events if e["id"] == MEMBER_ADDED and e["data"].get("TargetSid") == ADMINS_SID]

    names: dict[str, str] = {}
    for ev in creations:
        names[ev["data"].get("TargetSid", "?")] = ev["data"].get("TargetUserName", "?")
    for item in cfg.get("local_users", []) + cfg.get("admin_members", []):
        names.setdefault(item["SID"], item["Name"])

    # Lớp baseline: SID mới so với baseline (None = không có baseline để so)
    new_users = new_admins = None
    if baseline_cfg and "local_users" in baseline_cfg:
        new_users = (_sids(cfg.get("local_users")) or set()) - _sids(baseline_cfg["local_users"])
    if baseline_cfg and "admin_members" in baseline_cfg:
        new_admins = (_sids(cfg.get("admin_members")) or set()) - _sids(baseline_cfg["admin_members"])
    admins_ok = cfg.get("_status", {}).get("admin_members", "ok") == "ok" and "admin_members" in cfg
    current_admins = _sids(cfg.get("admin_members")) if admins_ok else None

    alerts = _admin_alerts(additions, creations, names, new_admins or set(), current_admins)
    alerts += _creation_alerts(creations, names, new_users or set())
    return alerts


def _admin_alerts(additions, creations, names, new_admins, current_admins) -> list[Alert]:
    alerts, seen = [], set()
    by_sid: dict[str, list[dict]] = {}
    for ev in additions:
        by_sid.setdefault(ev["data"].get("MemberSid") or "", []).append(ev)

    for sid, evs in by_sid.items():
        notes = [_event_note(e) for e in evs]
        name = names.get(sid, sid or "?")
        if not correlation.valid_sid(sid):
            alerts += _privileged_unverified(evs, notes, "Event 4732 thiếu MemberSid")
            continue
        seen.add(sid)
        creation, corr_note = correlation.match_creation(evs[0], creations)
        if corr_note:
            notes.append(corr_note)
        if creation:
            notes.append(f"tương quan với {_event_note(creation)} (cùng máy, cùng SID, "
                         f"Δt = {(evs[0]['time'] - creation['time']).total_seconds():.0f} s)")
        in_baseline = sid in new_admins
        if in_baseline:
            notes.append("Thành viên Administrators mới so với baseline")
        if current_admins is not None and sid not in current_admins:
            notes.append("mâu thuẫn: danh sách Administrators hiện tại không có SID này")
            confidence = "unverified"
        elif creation and in_baseline:
            confidence = "corroborated"
        else:
            confidence = "single_source"
        alert = _admin_alert(name, sid, notes, confidence, evs + ([creation] if creation else []))
        if creation:
            alert.score_breakdown["root_cause_id"] = correlation.root_cause_id(
                creation.get("computer"), sid, creation["time"])
        alerts.append(alert)
        if confidence == "unverified":
            alerts += _privileged_unverified(evs, notes, "Nguồn bằng chứng mâu thuẫn", add_attack=False)

    for sid in new_admins - seen:  # chỉ baseline thấy (log có thể đã bị xóa)
        alerts.append(_admin_alert(names.get(sid, sid), sid,
                                   ["Thành viên Administrators mới so với baseline"], "single_source", []))
    return alerts


def _admin_alert(name, sid, notes, confidence, evs) -> Alert:
    alert = Alert("HIGH", f"Tài khoản '{name}' được thêm vào nhóm Administrators",
                  "; ".join(notes) + f". SID: {sid}",
                  f"Nếu không phải bạn làm: net localgroup Administrators {name} /delete ; "
                  "dùng tài khoản Standard hằng ngày (quyền tối thiểu), giữ UAC bật.",
                  label("T1098"), root_cause=f"T1098:{sid}",
                  evidence={"member_sid": sid, "group_sid": ADMINS_SID, "notes": notes},
                  alert_required=True)  # quy tắc nội bộ PRIVILEGED_GROUP_CHANGE, không ghi đè điểm
    incident.apply(alert, "privileged_group_change", confidence, "Privilege Escalation",
                   "Thay đổi thành viên Administrators", evs)
    alert.score_breakdown["policy"] = "PRIVILEGED_GROUP_CHANGE"
    return alert


def _privileged_unverified(evs, notes, why, add_attack=True) -> list[Alert]:
    out = []
    if add_attack:
        alert = Alert("HIGH", "Có tài khoản được thêm vào nhóm Administrators (chưa xác định được tài khoản)",
                      "; ".join(notes) + f". {why}.", "Kiểm tra thủ công nhóm Administrators.",
                      label("T1098"), root_cause="T1098:?",
                      evidence={"member_sid": None, "group_sid": ADMINS_SID, "notes": notes},
                      alert_required=True)
        incident.apply(alert, "privileged_group_change", "unverified", "Privilege Escalation", why, evs)
        alert.score_breakdown["policy"] = "PRIVILEGED_GROUP_CHANGE"
        out.append(alert)
    out.append(Alert("INFO", "Cần xem xét: thay đổi nhóm Administrators chưa xác minh được", why,
                     "Đối chiếu Event 4732 với danh sách Administrators hiện tại.", category="config",
                     pillar=NEEDS_REVIEW, root_cause="PRIVILEGED_UNVERIFIED",
                     evidence={"notes": notes, "review_code": "PRIVILEGED_UNVERIFIED"}))
    return out


def _creation_alerts(creations, names, new_users) -> list[Alert]:
    alerts, seen = [], set()
    for ev in creations:
        sid = ev["data"].get("TargetSid", "?")
        key = (ev.get("computer"), sid)
        if key in seen:
            continue
        seen.add(key)
        if _is_allowed(names.get(sid, sid)):
            continue
        notes = [_event_note(ev)]
        confidence = "single_source"
        if sid in new_users:
            notes.append("Không có trong baseline")
            confidence = "corroborated"
        alerts.append(_creation_alert(names.get(sid, sid), sid, notes, confidence, [ev]))
    for sid in new_users - {k[1] for k in seen}:
        if not _is_allowed(names.get(sid, sid)):
            alerts.append(_creation_alert(names.get(sid, sid), sid, ["Không có trong baseline"],
                                          "single_source", []))
    return alerts


def _creation_alert(name, sid, notes, confidence, evs) -> Alert:
    alert = Alert("MEDIUM", f"Tài khoản mới '{name}' được tạo", "; ".join(notes) + f". SID: {sid}",
                  f"Xác minh tài khoản; nếu lạ: net user {name} /delete", label("T1136.001"),
                  root_cause=f"T1136.001:{sid}", evidence={"target_sid": sid, "notes": notes})
    return incident.apply(alert, "account_created", confidence, "Persistence", "Tạo tài khoản cục bộ", evs)
