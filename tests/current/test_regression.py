"""Mô tả hành vi hiện tại của các luật phát hiện (mốc 80fa1c1)."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from simulator import benchmark
from tests.helpers import ADMINS_SID, EVENT_XML, base_cfg, ev, failed_logon
from winguard import integrity, scoring
from winguard.attack import label
from winguard.collectors import eventlog
from winguard.detectors import (accounts, bruteforce, collector_health, config_audit, evasion,
                                persistence)
from winguard.models import Alert


def codes(alerts):
    return [a.mitre.split()[0] for a in alerts if a.mitre]


class BruteForceAndSpray(unittest.TestCase):
    def test_bruteforce_one_account(self):
        events = [failed_logon("sim_testuser", i * 2) for i in range(6)]
        alerts = bruteforce.detect(events)
        self.assertEqual(codes(alerts), ["T1110"])
        self.assertEqual(alerts[0].severity, "HIGH")

    def test_bruteforce_below_threshold(self):
        self.assertEqual(bruteforce.detect([failed_logon("u", i) for i in range(4)]), [])

    def test_bruteforce_blocked_by_lockout(self):
        events = [failed_logon("sim_testuser", i) for i in range(5)]
        events.append(ev(4740, 6, TargetUserName="sim_testuser"))
        alerts = bruteforce.detect(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual((alerts[0].severity, alerts[0].status), ("LOW", "mitigated"))

    def test_spray_detected_only_as_spray(self):
        events = [failed_logon(f"sim_spray{u}", u * 4 + k) for u in range(1, 7) for k in range(2)]
        self.assertEqual(codes(bruteforce.detect(events)), ["T1110.003"])

    def test_spray_spread_over_window_not_detected(self):
        events = [failed_logon(f"sim_spray{u}", u * 120) for u in range(1, 7)]  # 2 phút/tài khoản
        self.assertEqual(bruteforce.detect(events), [])

    def test_rules_v1_misses_spray(self):
        events = [failed_logon(f"sim_spray{u}", u * 4 + k) for u in range(1, 7) for k in range(2)]
        self.assertEqual(bruteforce.detect(events, spray=False), [])

    def test_sporadic_failures_no_alert(self):  # test âm tính
        events = [failed_logon("quan", 0), failed_logon("quan", 900), failed_logon("khach", 1800)]
        self.assertEqual(bruteforce.detect(events), [])


class Evasion(unittest.TestCase):
    def test_1102_high(self):
        alerts = evasion.detect([ev(1102, 0)])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "HIGH")
        # KNOWN-ISSUE-1 đã sửa ở P1: T1070.001 (revoked) -> T1685.005 (ATT&CK v20.0)
        self.assertEqual(alerts[0].mitre, label("T1685.005"))

    def test_other_events_ignored(self):
        self.assertEqual(evasion.detect([ev(1100, 0), failed_logon("u")]), [])


class CollectorHealth(unittest.TestCase):
    def test_error_becomes_unknown(self):
        alerts = collector_health.detect(base_cfg(_errors=["firewall"]))
        self.assertEqual([(a.severity, a.category) for a in alerts], [("UNKNOWN", "config")])

    def test_no_error_no_alert(self):
        self.assertEqual(collector_health.detect(base_cfg()), [])


class Integrity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.patch = mock.patch.object(integrity, "DATA_DIR", Path(self.tmp.name))
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def test_signed_ok(self):
        cfg = base_cfg()
        self.assertEqual(integrity.check({"config": cfg, "signature": integrity.sign(cfg)}), [])

    def test_tampered_high(self):
        cfg = base_cfg()
        baseline = {"config": cfg, "signature": integrity.sign(cfg)}
        baseline["config"] = base_cfg(uac_enabled=False)
        alerts = integrity.check(baseline)
        self.assertEqual([a.severity for a in alerts], ["HIGH"])
        self.assertEqual(codes(alerts), ["T1565.001"])

    def test_unsigned_unknown(self):
        self.assertEqual([a.severity for a in integrity.check({"config": base_cfg()})], ["UNKNOWN"])


class Accounts(unittest.TestCase):
    def test_allowlisted_creation_no_alert(self):
        events = [ev(4720, 0, TargetSid="S-1-5-21-1-2001", TargetUserName="sim_testuser")]
        self.assertEqual(accounts.detect(events, base_cfg(), None), [])

    def test_new_account_medium(self):
        events = [ev(4720, 0, TargetSid="S-1-5-21-1-2002", TargetUserName="sim_user")]
        alerts = accounts.detect(events, base_cfg(), None)
        self.assertEqual([(a.severity, codes([a])[0]) for a in alerts], [("MEDIUM", "T1136.001")])

    def test_allowlisted_added_to_admins_still_alerts(self):
        # P5: fixture có tài khoản trong admin_members lúc quét (nếu không, P5 coi là mâu thuẫn)
        events = [ev(4720, 0, TargetSid="S-1-5-21-1-2001", TargetUserName="sim_testuser"),
                  ev(4732, 5, TargetSid=ADMINS_SID, MemberSid="S-1-5-21-1-2001")]
        cfg = base_cfg(admin_members=[{"Name": "quan", "SID": "S-1-5-21-1-1001"},
                                      {"Name": "sim_testuser", "SID": "S-1-5-21-1-2001"}])
        alerts = accounts.detect(events, cfg, None)
        self.assertEqual([(a.severity, codes([a])[0]) for a in alerts], [("HIGH", "T1098")])

    def test_baseline_diff_without_events(self):
        cfg = base_cfg(admin_members=[{"Name": "quan", "SID": "S-1-5-21-1-1001"},
                                      {"Name": "evil", "SID": "S-1-5-21-1-3000"}])
        alerts = accounts.detect([], cfg, base_cfg())
        self.assertIn("T1098", codes(alerts))

    def test_non_admin_group_ignored(self):
        events = [ev(4732, 0, TargetSid="S-1-5-32-555", MemberSid="S-1-5-21-1-1001")]
        self.assertEqual(accounts.detect(events, base_cfg(), None), [])


class Persistence(unittest.TestCase):
    def test_new_run_key_high(self):
        cfg = base_cfg(run_keys=[{"location": "HKCU\\Run", "name": "SIM", "command": "notepad.exe"}])
        alerts = persistence.detect([], cfg, base_cfg())
        self.assertEqual([(a.severity, codes([a])[0]) for a in alerts], [("HIGH", "T1547.001")])

    def test_known_task_no_alert(self):  # test âm tính
        task = {"TaskPath": "\\", "TaskName": "Updater", "Actions": "C:\\Program Files\\u.exe"}
        cfg = base_cfg(scheduled_tasks=[task])
        self.assertEqual(persistence.detect([], cfg, base_cfg(scheduled_tasks=[task])), [])

    def test_new_task_with_event(self):
        task = {"TaskPath": "\\", "TaskName": "SIM_WinGuardTest", "Actions": "notepad.exe"}
        events = [ev(4698, 0, TaskName="\\SIM_WinGuardTest", SubjectUserName="quan")]
        alerts = persistence.detect(events, base_cfg(scheduled_tasks=[task]), base_cfg())
        self.assertEqual([(a.severity, codes([a])[0]) for a in alerts], [("MEDIUM", "T1053.005")])
        self.assertIn("Event 4698", alerts[0].detail)


class ConfigAudit(unittest.TestCase):
    """Cập nhật có chủ đích ở P4: ngưỡng theo profile (KNOWN-ISSUE-5), firewall theo profile đang
    hoạt động (KNOWN-ISSUE-4), Defender kiểm tra SecurityCenter2 (KNOWN-ISSUE-7)."""
    LAB = "WINGUARD_LAB"

    def lan(self, **over):
        cfg = base_cfg(network_profiles=[{"InterfaceAlias": "Wi-Fi", "NetworkCategory": "Private"}],
                       security_center={"antivirus": [], "firewall": []})
        cfg.update(over)
        return cfg

    def test_clean_config_no_alert(self):
        self.assertEqual(config_audit.detect(self.lan(), profile=self.LAB), [])

    def test_no_profile_is_review_not_guess(self):
        alerts = config_audit.detect(self.lan())
        self.assertEqual({(a.root_cause, a.pillar) for a in alerts},
                         {("lockout_threshold", "NEEDS_REVIEW"), ("min_password_length", "NEEDS_REVIEW")})

    def test_min_password_lab_profile(self):
        policy = {"min_password_length": 7, "lockout_threshold": 5, "lockout_duration_min": 10}
        alerts = config_audit.detect(self.lan(accounts_policy=policy), profile=self.LAB)
        self.assertEqual([a.severity for a in alerts], ["MEDIUM"])
        policy["min_password_length"] = 13
        self.assertEqual(config_audit.detect(self.lan(accounts_policy=policy), profile=self.LAB), [])

    def test_lockout_zero_high(self):
        policy = {"min_password_length": 8, "lockout_threshold": 0, "lockout_duration_min": 0}
        alerts = config_audit.detect(self.lan(accounts_policy=policy), profile=self.LAB)
        self.assertEqual([a.severity for a in alerts], ["HIGH"])

    def test_active_firewall_profile_off_is_high(self):
        alerts = config_audit.detect(self.lan(firewall={"Domain": True, "Private": False, "Public": True}),
                                     profile=self.LAB)
        self.assertEqual([(a.severity, a.mitre) for a in alerts], [("HIGH", label("T1686.003"))])

    def test_inactive_firewall_profile_off_is_low_review(self):
        alerts = config_audit.detect(self.lan(firewall={"Domain": False, "Private": True, "Public": True}),
                                     profile=self.LAB)
        self.assertEqual([(a.severity, a.pillar) for a in alerts], [("LOW", "NEEDS_REVIEW")])

    def test_defender_off(self):
        cfg = self.lan(defender={"RealTimeProtectionEnabled": False, "AntivirusSignatureAge": 0})
        self.assertEqual([a.mitre for a in config_audit.detect(cfg, profile=self.LAB)], [label("T1685")])

    def test_uac_off(self):
        # KNOWN-ISSUE-2 đã sửa ở P1-P2: không gắn T1548.002 (QĐ1)
        alerts = config_audit.detect(self.lan(uac_enabled=False), profile=self.LAB)
        self.assertEqual([(a.mitre, a.cwe) for a in alerts], [("", "CWE-250")])


class Scoring(unittest.TestCase):
    def test_penalties(self):
        alerts = [Alert("HIGH", "a", ""), Alert("MEDIUM", "b", ""), Alert("LOW", "c", ""),
                  Alert("UNKNOWN", "d", ""), Alert("INFO", "e", ""),
                  Alert("HIGH", "f", "", status="mitigated")]
        self.assertEqual(scoring.score(alerts), 100 - 15 - 8 - 3 - 5)

    def test_floor_zero(self):
        self.assertEqual(scoring.score([Alert("HIGH", "x", "")] * 10), 0)


class EventLogParser(unittest.TestCase):
    def test_parse(self):
        e = eventlog.parse_event(EVENT_XML)
        self.assertEqual((e["id"], e["data"]["TargetSid"]), (4720, "S-1-5-21-1-2002"))
        # KNOWN-ISSUE-6 đã sửa ở P4: giữ Computer / EventRecordID
        self.assertEqual(set(e), {"id", "time", "data", "computer", "record_id"})


class Benchmark(unittest.TestCase):
    def test_codes_ignore_config_alerts(self):
        alerts = [Alert("HIGH", "x", "", mitre="T1110 Brute Force", category="config"),
                  Alert("HIGH", "y", "", mitre="T1110.003 Password Spraying")]
        self.assertEqual(benchmark._codes(alerts), ["T1110.003"])

    def test_expected_codes(self):
        self.assertEqual({k: v[0] for k, v in benchmark.EXPECTED.items()},
                         {"bruteforce": "T1110", "spray": "T1110.003", "new_account": "T1136.001",
                          "admin_group": "T1098", "runkey": "T1547.001",
                          "scheduled_task": "T1053.005"})


if __name__ == "__main__":
    unittest.main()
