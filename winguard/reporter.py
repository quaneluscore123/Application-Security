"""Xuất kết quả ra console và file HTML."""
from datetime import datetime
from html import escape

from winguard.models import SEVERITY_ORDER, Alert
from winguard.utils import DATA_DIR

ICON = {"HIGH": "[!!]", "MEDIUM": "[! ]", "LOW": "[ .]", "INFO": "[ i]"}


def _sorted(alerts: list[Alert]) -> list[Alert]:
    return sorted(alerts, key=lambda a: (a.status != "active", SEVERITY_ORDER[a.severity]))


def print_console(alerts: list[Alert], score: int, baseline_score: int | None = None) -> None:
    delta = f" (baseline: {baseline_score})" if baseline_score is not None else ""
    print(f"\n=== WinGuard - Điểm bảo mật: {score}/100{delta} ===\n")
    if not alerts:
        print("Không có cảnh báo.")
    for a in _sorted(alerts):
        tag = " (đã chặn)" if a.status == "mitigated" else ""
        print(f"{ICON[a.severity]} {a.severity:<6} {a.title}{tag}")
        if a.detail:
            print(f"         {a.detail}")
        if a.mitre:
            print(f"         MITRE: {a.mitre}")
        if a.recommendation:
            print(f"         -> {a.recommendation}")
    print()


def write_html(alerts: list[Alert], score: int, baseline_score: int | None = None) -> str:
    rows = "".join(
        f"<tr class='{a.severity.lower()}{' done' if a.status == 'mitigated' else ''}'>"
        f"<td><span class='sev'>{a.severity}</span></td>"
        f"<td><b>{escape(a.title)}</b><br><small>{escape(a.detail)}</small></td>"
        f"<td>{escape(a.mitre)}</td><td><code>{escape(a.recommendation)}</code></td>"
        f"<td>{'Đã chặn' if a.status == 'mitigated' else 'Đang tồn tại'}</td></tr>"
        for a in _sorted(alerts)
    ) or "<tr><td colspan='5'>Không có cảnh báo.</td></tr>"
    base = f" <small>(baseline: {baseline_score})</small>" if baseline_score is not None else ""
    html = f"""<!doctype html><html lang="vi"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>WinGuard Report</title>
<style>
body{{font-family:Segoe UI,sans-serif;margin:24px;background:#f6f7f9;color:#1d2330}}
h1{{margin:0 0 4px}} .score{{font-size:40px;font-weight:700}}
table{{border-collapse:collapse;width:100%;background:#fff;margin-top:16px}}
td,th{{border:1px solid #dde1e7;padding:8px;vertical-align:top;text-align:left}}
.sev{{padding:2px 8px;border-radius:4px;color:#fff;font-weight:600}}
.high .sev{{background:#c62828}} .medium .sev{{background:#ef6c00}}
.low .sev{{background:#558b2f}} .info .sev{{background:#546e7a}} .done{{opacity:.7}}
code{{white-space:pre-wrap}}
</style></head><body>
<h1>WinGuard - Báo cáo bảo mật</h1><div>{datetime.now():%Y-%m-%d %H:%M:%S}</div>
<div class="score">{score}/100{base}</div>
<table><tr><th>Mức</th><th>Cảnh báo</th><th>MITRE ATT&amp;CK</th><th>Đề xuất phòng thủ</th><th>Trạng thái</th></tr>
{rows}</table></body></html>"""
    DATA_DIR.mkdir(exist_ok=True)
    path = DATA_DIR / "report.html"
    path.write_text(html, encoding="utf-8")
    return str(path)
