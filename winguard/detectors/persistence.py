"""Phát hiện cơ chế bám trụ (persistence) bằng so sánh với baseline.

- Run key mới (MITRE T1547.001)
- Scheduled Task mới (MITRE T1053.005), bổ sung bằng chứng từ Event 4698
Lệnh khởi chạy có dấu hiệu đáng ngờ (chạy từ thư mục người dùng ghi được,
dùng trình thông dịch script...) được nâng mức cảnh báo.
"""
import re

from winguard.attack import label
from winguard.models import Alert

TASK_CREATED = 4698

SUSPICIOUS = re.compile(
    r"\\(appdata|temp|users\\public|downloads)\\|powershell|cmd(\.exe)?\s+/c|wscript|cscript|mshta|rundll32"
    r"|-enc(odedcommand)?\b|https?://",
    re.IGNORECASE,
)


def _suspicious_reason(command: str) -> str:
    m = SUSPICIOUS.search(command)
    return f" Lệnh có dấu hiệu đáng ngờ ('{m.group(0)}')." if m else ""


def _task_id(task: dict) -> str:
    return task["TaskPath"] + task["TaskName"]


def detect(events: list[dict], cfg: dict, baseline_cfg: dict | None) -> list[Alert]:
    alerts = []
    if not baseline_cfg:
        return alerts

    if "run_keys" in baseline_cfg:
        known = {(e["location"], e["name"], e["command"]) for e in baseline_cfg["run_keys"]}
        for e in cfg.get("run_keys", []):
            if (e["location"], e["name"], e["command"]) in known:
                continue
            alerts.append(Alert(
                "HIGH", f"Mục tự khởi động mới trong Run key: '{e['name']}'",
                f"{e['location']} -> {e['command']}. Không có trong baseline.{_suspicious_reason(e['command'])}",
                f"Nếu lạ: reg delete \"{e['location']}\" /v \"{e['name']}\" /f ; "
                "rà soát định kỳ bằng Sysinternals Autoruns.",
                label("T1547.001")))

    if "scheduled_tasks" in baseline_cfg:
        known = {_task_id(t) for t in baseline_cfg["scheduled_tasks"]}
        created = {ev["data"].get("TaskName"): ev for ev in events if ev["id"] == TASK_CREATED}
        for t in cfg.get("scheduled_tasks", []):
            tid = _task_id(t)
            if tid in known:
                continue
            notes = ["Không có trong baseline"]
            if tid in created:
                ev = created[tid]
                notes.insert(0, f"Event 4698 lúc {ev['time'].astimezone():%H:%M:%S} "
                                f"(thực hiện bởi '{ev['data'].get('SubjectUserName', '?')}')")
            reason = _suspicious_reason(t["Actions"])
            alerts.append(Alert(
                "HIGH" if reason else "MEDIUM", f"Scheduled Task mới: '{tid}'",
                f"Hành động: {t['Actions']}. {'; '.join(notes)}.{reason}",
                f"Nếu lạ: Unregister-ScheduledTask -TaskName '{t['TaskName']}' -TaskPath '{t['TaskPath']}' "
                "-Confirm:$false ; giám sát Task Scheduler.",
                label("T1053.005")))
    return alerts
