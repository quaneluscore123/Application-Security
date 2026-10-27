"""Thu thập sự kiện từ Windows Security Event Log (cần quyền Admin)."""
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from winguard.utils import powershell_json

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _parse_time(value: str) -> datetime:
    # VD: 2026-10-03T09:15:02.1234567Z -> cắt phần lẻ còn 6 chữ số
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?", value)
    frac = (m.group(2) or "0")[:6].ljust(6, "0")
    return datetime.strptime(f"{m.group(1)}.{frac}", "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc)


def parse_event(xml_str: str) -> dict:
    root = ET.fromstring(xml_str)
    system = root.find("e:System", NS)
    record = system.findtext("e:EventRecordID", default="", namespaces=NS)
    return {
        "id": int(system.find("e:EventID", NS).text),
        "time": _parse_time(system.find("e:TimeCreated", NS).get("SystemTime")),
        "data": {d.get("Name"): (d.text or "") for d in root.iterfind("e:EventData/e:Data", NS)},
        # Định danh máy và bản ghi: dùng để gom cụm theo máy và khử trùng (kế hoạch §6)
        "computer": system.findtext("e:Computer", default="", namespaces=NS) or None,
        "record_id": int(record) if record.isdigit() else None,
    }


def query_security(event_ids: list[int], since: datetime) -> list[dict]:
    """Lấy các sự kiện Security có ID trong event_ids kể từ thời điểm `since` (giờ máy)."""
    ids = ",".join(str(i) for i in event_ids)
    expr = (
        f"@(Get-WinEvent -FilterHashtable @{{LogName='Security';Id={ids};"
        f"StartTime=[datetime]'{since:%Y-%m-%dT%H:%M:%S}'}} -ErrorAction SilentlyContinue "
        "| ForEach-Object { $_.ToXml() })"
    )
    raw = powershell_json(expr) or []
    if isinstance(raw, str):
        raw = [raw]
    return sorted((parse_event(x) for x in raw), key=lambda ev: ev["time"])
