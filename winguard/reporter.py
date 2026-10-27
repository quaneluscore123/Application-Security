"""Xuất kết quả ra console, HTML và JSON từ CÙNG một báo cáo (build_report) để ba đầu ra nhất quán.

Ba trụ cột (kế hoạch v7.2 §1, §13.3):
[1] CONFIRMED_WEAKNESS - công thức MITRE CWSS v1.0.1, vector do WinGuard chọn
[2] ATTACK_OBSERVED    - WinGuard Incident Severity (nội bộ)
[3] NEEDS_REVIEW       - WinGuard Investigation Priority (nội bộ)
"""
from datetime import datetime
from html import escape

from winguard import posture, profiles
from winguard.attack import ATTACK_VERSION
from winguard.cwss_weights import manual_check_status
from winguard.models import ATTACK_OBSERVED, CONFIRMED_WEAKNESS, NEEDS_REVIEW, PILLARS, SEVERITY_ORDER, Alert
from winguard.utils import DATA_DIR

ICON = {"HIGH": "[!!]", "MEDIUM": "[! ]", "LOW": "[ .]", "UNKNOWN": "[ ?]", "INFO": "[ i]"}
SECTION_TITLE = {
    CONFIRMED_WEAKNESS: "[1] CONFIRMED WEAKNESSES - công thức MITRE CWSS v1.0.1, vector do WinGuard chọn",
    ATTACK_OBSERVED: "[2] ATTACK OBSERVED - Incident Severity (nội bộ WinGuard)",
    NEEDS_REVIEW: "[3] NEEDS REVIEW - Investigation Priority (nội bộ WinGuard)",
}
LEGACY_LABEL = "Legacy Score (quy ước minh họa nội bộ WinGuard)"
POSTURE_LABEL = "Posture Score (nội bộ WinGuard)"
CANDIDATE_LABEL = "Ứng viên tham khảo - chưa phát hiện hành vi"


def _sorted(alerts: list[Alert]) -> list[Alert]:
    return sorted(alerts, key=lambda a: (PILLARS.index(a.pillar) if a.pillar in PILLARS else len(PILLARS),
                                         a.status != "active", -(a.score or 0), SEVERITY_ORDER[a.severity]))


def build_report(alerts: list[Alert], score: int, baseline_score: int | None = None,
                 profile: str | None = None) -> dict:
    """Dữ liệu báo cáo duy nhất; console/HTML/JSON đều sinh từ đây."""
    items = []
    for i, a in enumerate(_sorted(alerts), 1):
        pillar = a.pillar if a.pillar in PILLARS else NEEDS_REVIEW  # không để cảnh báo nào "mất" khỏi báo cáo
        items.append({"id": f"A{i:02d}", **a.to_dict(), "pillar": pillar})
    prof = profiles.get(profile)
    return {
        "time": datetime.now(),
        "attack_version": ATTACK_VERSION,
        "profile": {"name": profile, **prof} if prof else {"name": profile, "status": "chưa xác định"},
        "cwss_weights_manual_check": manual_check_status(),
        "posture": posture.posture(alerts),
        "score": score,  # Legacy Score (giữ khóa cũ của alerts.json)
        "legacy_score": {"label": LEGACY_LABEL, "value": score, "baseline": baseline_score},
        "alerts": items,
    }


def _weights_note(report: dict) -> str:
    status = report["cwss_weights_manual_check"]
    if status == "VERIFIED":
        return "bảng trọng số đã được kiểm tra thủ công"
    return f"bảng trọng số chưa được kiểm tra thủ công ({status})"


def _cwe(a: dict) -> str:
    if not a["cwe"]:
        return "CWE: chưa có căn cứ"
    return a["cwe"] + (" (đề xuất)" if a["cwe_status"] != "verified" else "")


def _score_line(a: dict) -> str:
    b = a["score_breakdown"]
    if a["pillar"] == CONFIRMED_WEAKNESS:
        if a["score"] is None:
            return f"CWSS: chưa tính được ({a['scoring_error'] or 'không có vector'})"
        unknown = [m for m, src in b.get("metric_sources", {}).items() if src == "unknown"]
        return (f"CWSS {a['score']:.1f} (Base {b['base']:.1f}, AS {b['attack_surface']:.3f}, "
                f"Env {b['environmental']:.3f}; Unknown: {', '.join(unknown) or 'không'}) "
                f"vector {b['vector_string']}")
    if a["pillar"] == ATTACK_OBSERVED:
        if a["score"] is None:
            return "Incident Severity (nội bộ WinGuard): chưa tính"
        return (f"Incident Severity (nội bộ WinGuard) {a['score']:.1f} = 100 x T {b['T']:.2f} "
                f"x C {b['C']:.2f} x W {b['W']:.2f} ({b['confidence']}, {b['tactic']})")
    if a["score"] is None:
        return "Investigation Priority (nội bộ WinGuard): chưa tính"
    return (f"Investigation Priority (nội bộ WinGuard) {a['score']:.1f} "
            f"[{b.get('review_code', '?')}]")


def _evidence_line(a: dict) -> str:
    e = a["evidence"]
    parts = []
    if "observed" in e:
        parts.append(f"Quan sát: {e['observed']}")
    if e.get("expected") is not None:
        parts.append(f"Yêu cầu: {e['expected']}")
    if e.get("profile"):
        parts.append(f"Profile: {e['profile']}")
    if e.get("source"):
        parts.append(f"Nguồn: {e['source']}")
    if e.get("missing") and "; ".join(e["missing"]) != a["detail"]:
        parts.append(f"Thiếu: {'; '.join(e['missing'])}")
    if e.get("notes"):
        parts.append(f"Bằng chứng: {'; '.join(e['notes'])}")
    return " | ".join(parts)


def _header(report: dict) -> list[str]:
    prof = report["profile"]
    if "min_password_length" in prof:
        prof_text = (f"Profile: {prof['name']} (min password >= {prof['min_password_length']}, "
                     f"lockout <= {prof['lockout_threshold_max'] or 'chưa đối chiếu'})")
    else:
        prof_text = f"Profile: {prof['name']} (chưa xác định)"
    p = report["posture"]
    posture_text = (f"{p['score']:.1f} / 100" if p["score"] is not None
                    else f"không xác định (chưa có điểm: {', '.join(p['unscored'])})")
    legacy = report["legacy_score"]
    base = f" (baseline: {legacy['baseline']})" if legacy["baseline"] is not None else ""
    return [f"ATT&CK {report['attack_version']} | {prof_text}",
            f"{POSTURE_LABEL}: {posture_text}",
            f"{LEGACY_LABEL}: {legacy['value']}/100{base}"]


def render_console(report: dict) -> str:
    lines = ["", "=" * 78, "WINGUARD SECURITY ASSESSMENT REPORT", *_header(report), "=" * 78]
    for pillar in PILLARS:
        items = [a for a in report["alerts"] if a["pillar"] == pillar]
        title = SECTION_TITLE[pillar]
        if pillar == CONFIRMED_WEAKNESS:
            title += f" ({_weights_note(report)})"
        lines += ["", title]
        if not items:
            lines.append("    Không có mục nào.")
        for a in items:
            tag = " (đã chặn)" if a["status"] == "mitigated" else ""
            lines.append(f"  {ICON[a['severity']]} [{a['id']}] {a['title']}{tag}")
            if pillar == CONFIRMED_WEAKNESS:
                lines.append(f"         {_cwe(a)}")
            lines.append(f"         {_score_line(a)}")
            if a["detail"]:
                lines.append(f"         {a['detail']}")
            ev = _evidence_line(a)
            if ev:
                lines.append(f"         {ev}")
            if a["mitre"]:
                lines.append(f"         ATT&CK {report['attack_version']}: {a['mitre']}")
            for c in a["attack_candidates"]:
                lines.append(f"         {CANDIDATE_LABEL}: {c['technique']} ({c['reason']})")
            if a["recommendation"]:
                lines.append(f"         -> {a['recommendation']}")
    lines.append("")
    return "\n".join(lines)


def print_console(alerts: list[Alert], score: int, baseline_score: int | None = None,
                  profile: str | None = None, report: dict | None = None) -> None:
    print(render_console(report or build_report(alerts, score, baseline_score, profile)))


def render_html(report: dict) -> str:
    sections = []
    for pillar in PILLARS:
        rows = []
        for a in (a for a in report["alerts"] if a["pillar"] == pillar):
            extra = []
            if pillar == CONFIRMED_WEAKNESS:
                extra.append(escape(_cwe(a)))
            ev = _evidence_line(a)
            if ev:
                extra.append(escape(ev))
            attack = escape(a["mitre"]) if a["mitre"] else ""
            for c in a["attack_candidates"]:
                extra.append(escape(f"{CANDIDATE_LABEL}: {c['technique']} ({c['reason']})"))
            rows.append(
                f"<tr class='{a['severity'].lower()}{' done' if a['status'] == 'mitigated' else ''}'>"
                f"<td>{a['id']}</td><td><span class='sev'>{a['severity']}</span></td>"
                f"<td><b>{escape(a['title'])}</b><br><small>{escape(a['detail'])}</small>"
                f"<br><small>{'<br>'.join(extra)}</small></td>"
                f"<td>{escape(_score_line(a))}</td><td>{attack}</td>"
                f"<td><code>{escape(a['recommendation'])}</code></td>"
                f"<td>{'Đã chặn' if a['status'] == 'mitigated' else 'Đang tồn tại'}</td></tr>")
        title = SECTION_TITLE[pillar] + (f" ({_weights_note(report)})" if pillar == CONFIRMED_WEAKNESS else "")
        body = "".join(rows) or "<tr><td colspan='7'>Không có mục nào.</td></tr>"
        sections.append(f"<h2>{escape(title)}</h2><table><tr><th>ID</th><th>Mức</th><th>Phát hiện</th>"
                        f"<th>Điểm</th><th>ATT&amp;CK {escape(report['attack_version'])}</th>"
                        f"<th>Đề xuất</th><th>Trạng thái</th></tr>{body}</table>")
    header = "".join(f"<div>{escape(line)}</div>" for line in _header(report))
    return f"""<!doctype html><html lang="vi"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>WinGuard Report</title>
<style>
body{{font-family:Segoe UI,sans-serif;margin:24px;background:#f6f7f9;color:#1d2330}}
h1{{margin:0 0 4px}} h2{{margin:24px 0 0;font-size:18px}}
table{{border-collapse:collapse;width:100%;background:#fff;margin-top:8px}}
td,th{{border:1px solid #dde1e7;padding:8px;vertical-align:top;text-align:left}}
.sev{{padding:2px 8px;border-radius:4px;color:#fff;font-weight:600}}
.high .sev{{background:#c62828}} .medium .sev{{background:#ef6c00}}
.low .sev{{background:#558b2f}} .unknown .sev{{background:#8e6c17}}
.info .sev{{background:#546e7a}} .done{{opacity:.7}}
code{{white-space:pre-wrap}}
</style></head><body>
<h1>WinGuard - Báo cáo bảo mật</h1><div>{report['time']:%Y-%m-%d %H:%M:%S}</div>
{header}
{''.join(sections)}</body></html>"""


def write_html(alerts: list[Alert], score: int, baseline_score: int | None = None,
               profile: str | None = None, report: dict | None = None) -> str:
    html = render_html(report or build_report(alerts, score, baseline_score, profile))
    DATA_DIR.mkdir(exist_ok=True)
    path = DATA_DIR / "report.html"
    path.write_text(html, encoding="utf-8")
    return str(path)
