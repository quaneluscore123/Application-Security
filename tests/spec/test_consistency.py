"""Kiểm tra tính nhất quán toàn hệ thống (kế hoạch §12) - console, HTML, JSON sinh từ cùng báo cáo."""
import json
import re
import unittest

from tests.helpers import ADMINS_SID, base_cfg, ev, failed_logon
from winguard import cwss, cwss_weights, integrity, priority, reporter, scoring
from winguard.attack import ATTACK_LEGACY, ATTACK_MAP
from winguard.cwss_weights import WEIGHTS
from winguard.detectors import accounts, bruteforce, collector_health, config_audit, evasion, persistence
from winguard.models import CONFIRMED_WEAKNESS, NEEDS_REVIEW, PILLARS

PROFILE = "WINGUARD_LAB"
TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def scenario(compute=None, profile=PROFILE):
    """Một lần quét giả lập có đủ ba trụ cột, có cả lỗi collector và ứng viên ATT&CK."""
    cfg = base_cfg(
        accounts_policy={"min_password_length": 0, "lockout_threshold": 0, "lockout_duration_min": 0},
        firewall={"Domain": False, "Private": False, "Public": True}, uac_enabled=False,
        network_profiles=[{"InterfaceAlias": "Wi-Fi", "NetworkCategory": "Private"}],
        security_center={"antivirus": [], "firewall": []},
        admin_members=[{"Name": "quan", "SID": "S-1-5-21-1-1001"}, {"Name": "evil", "SID": "S-1-5-21-9"}],
        run_keys=[{"location": "HKCU\\Run", "name": "SIM", "command": "notepad.exe"}],
        _errors=["scheduled_tasks"])
    events = ([failed_logon(f"s{u}", u * 4 + k) for u in range(6) for k in range(2)]
              + [ev(1102, record_id=1), ev(4720, record_id=2, TargetSid="S-1-5-21-9", TargetUserName="evil"),
                 ev(4732, 10, record_id=3, TargetSid=ADMINS_SID, MemberSid="S-1-5-21-9")])
    original = config_audit.COMPUTE
    if compute:
        config_audit.COMPUTE = compute
    try:
        alerts = (config_audit.detect(cfg, profile) + collector_health.detect(cfg)
                  + bruteforce.detect(events) + evasion.detect(events)
                  + integrity.check({"config": base_cfg(), "signature": "sai"})
                  + accounts.detect(events, cfg, base_cfg()) + persistence.detect(events, cfg, base_cfg()))
    finally:
        config_audit.COMPUTE = original
    priority.assign(alerts)
    report = reporter.build_report(alerts, scoring.score(alerts), 84, profile)
    return report, reporter.render_console(report), reporter.render_html(report), \
        json.loads(json.dumps(report, ensure_ascii=False, default=str))


def sections(console: str) -> dict:
    """Tách console theo ba tiêu đề trụ cột."""
    out, current = {}, None
    for line in console.splitlines():
        for p in PILLARS:
            if line.startswith(reporter.SECTION_TITLE[p]):
                current = p
                out[p] = []
        if current and line.strip().startswith(("[!", "[ ")) and "[A" in line:
            out[current].append(re.search(r"\[(A\d+)\]", line).group(1))
    return out


class Consistency(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report, cls.console, cls.html, cls.json = scenario()

    def test_1_all_attack_ids_in_map(self):
        for text in (self.console, self.html, json.dumps(self.json, ensure_ascii=False)):
            found = set(TECH.findall(text))
            self.assertTrue(found)
            self.assertLessEqual(found, set(ATTACK_MAP))

    def test_2_no_legacy_ids(self):
        for text in (self.console, self.html):
            self.assertFalse(set(TECH.findall(text)) & set(ATTACK_LEGACY))

    def test_3_profile_matches_detector(self):
        self.assertEqual(self.report["profile"]["name"], PROFILE)
        self.assertIn(f"Profile: {PROFILE}", self.console)
        for a in self.report["alerts"]:
            if a["evidence"].get("profile"):
                self.assertEqual(a["evidence"]["profile"], PROFILE)

    def test_4_cwss_breakdown_independent(self):
        confirmed = [a for a in self.report["alerts"] if a["pillar"] == CONFIRMED_WEAKNESS]
        self.assertTrue(confirmed)
        for a in confirmed:
            b = a["score_breakdown"]
            w = {m: WEIGHTS[m][c] for m, c in b["vector"].items()}
            base = (10 * w["TI"] + 5 * (w["AP"] + w["AL"]) + 5 * w["FC"]) * w["IC"] * 4
            surface = (20 * (w["RP"] + w["RL"] + w["AV"]) + 20 * w["SC"] + 15 * w["IN"] + 5 * w["AS"]) / 100
            env = (10 * w["BI"] + 3 * w["DI"] + 4 * w["EX"] + 3 * w["P"]) * w["EC"] / 20
            self.assertAlmostEqual(base * surface * env, float(b["score_exact"]), places=9)
            self.assertEqual(a["score"], cwss.compute(b["vector"])["score"])

    def test_5_internal_metrics_not_called_mitre(self):
        for line in self.console.splitlines():
            if any(k in line for k in ("Incident Severity", "Investigation Priority", "Posture Score",
                                       "Legacy Score")):
                self.assertIn("nội bộ", line)
                self.assertNotIn("MITRE", line)

    def test_6_review_items_only_in_review_section(self):
        sec = sections(self.console)
        review_ids = {a["id"] for a in self.report["alerts"] if a["pillar"] == NEEDS_REVIEW}
        self.assertTrue(review_ids)
        self.assertEqual(set(sec[NEEDS_REVIEW]), review_ids)
        self.assertFalse(review_ids & set(sec[CONFIRMED_WEAKNESS]))

    def test_7_console_html_json_same(self):
        self.assertEqual([a["id"] for a in self.json["alerts"]], [a["id"] for a in self.report["alerts"]])
        for a in self.report["alerts"]:
            for text in (self.console, self.html):
                self.assertIn(f"[{a['id']}]" if text is self.console else f"<td>{a['id']}</td>", text)
            if a["score"] is not None:
                shown = f"{a['score']:.1f}"
                self.assertIn(shown, self.console)
                self.assertIn(shown, self.html)
            j = next(x for x in self.json["alerts"] if x["id"] == a["id"])
            self.assertEqual((j["pillar"], j["score"], j["title"]), (a["pillar"], a["score"], a["title"]))
            self.assertEqual(json.dumps(j["evidence"], sort_keys=True, default=str),
                             json.dumps(a["evidence"], sort_keys=True, default=str))

    def test_8_collector_error_not_safe(self):
        errors = [a for a in self.report["alerts"] if a["root_cause"] == "COLLECTOR_ERROR"]
        self.assertEqual([a["pillar"] for a in errors], [NEEDS_REVIEW])
        self.assertIn("scheduled_tasks", errors[0]["title"])
        self.assertIsNotNone(errors[0]["score"])  # có Investigation Priority, không bị coi là "an toàn"

    def test_9_scoring_error_keeps_finding_everywhere(self):
        def broken(vector):
            raise ValueError("bảng trọng số hỏng")
        report, console, html, data = scenario(compute=broken)
        uac = [a for a in report["alerts"] if a["root_cause"] == "uac"]
        self.assertEqual(len(uac), 1)
        self.assertIsNone(uac[0]["score"])
        self.assertEqual(uac[0]["evidence"]["observed"], {"EnableLUA": 0})
        for text in (console, html):
            self.assertIn(uac[0]["title"], text)
            self.assertIn("chưa tính được", text)
        self.assertIsNone(report["posture"]["score"])
        self.assertIn("SCORING_ERROR", [a["root_cause"] for a in data["alerts"]])

    def test_10_candidates_not_shown_as_attack(self):
        for line in self.console.splitlines():
            if "T1548.002" in line:
                self.assertIn(reporter.CANDIDATE_LABEL, line)
        uac = [a for a in self.report["alerts"] if a["root_cause"] == "uac"][0]
        self.assertEqual(uac["mitre"], "")

    def test_11_cwss_not_called_verified_while_pending(self):
        if cwss_weights.CWSS_MANUAL_CHECK["status"] != "VERIFIED":
            self.assertNotIn("đã được kiểm tra thủ công", self.console)
            self.assertIn("chưa được kiểm tra thủ công", self.console)
            self.assertIn("chưa được kiểm tra thủ công", self.html)

    def test_12_proposed_cwe_labelled(self):
        for a in self.report["alerts"]:
            if a["cwe"] and a["cwe_status"] == "proposed":
                self.assertIn(f"{a['cwe']} (đề xuất)", self.console)


class ReportContent(unittest.TestCase):
    def test_header_shows_version_profile_and_threshold(self):
        report, console, html, _ = scenario(profile="CIS_WINDOWS_11_ENTERPRISE_V3_L1")
        for text in (console, html):
            self.assertIn("Enterprise v20.0", text)
            self.assertIn("CIS_WINDOWS_11_ENTERPRISE_V3_L1", text)
            self.assertIn("min password &gt;= 14" if text is html else "min password >= 14", text)

    def test_missing_profile_shown(self):
        report, console, *_ = scenario(profile=None)
        self.assertIn("chưa xác định", console)

    def test_every_alert_has_pillar_and_evidence_or_score(self):
        report, *_ = scenario()
        for a in report["alerts"]:
            self.assertIn(a["pillar"], PILLARS)
            self.assertTrue(a["evidence"] or a["score_breakdown"], a["title"])


if __name__ == "__main__":
    unittest.main()
