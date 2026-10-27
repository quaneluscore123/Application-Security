"""Mapping ATT&CK theo phiên bản đã chốt (kế hoạch §4)."""
import unittest

from simulator import benchmark
from tests.helpers import ADMINS_SID, base_cfg, ev, failed_logon
from winguard import integrity
from winguard.attack import ATTACK_LEGACY, ATTACK_MAP, ATTACK_VERSION, label, technique_id
from winguard.detectors import accounts, bruteforce, config_audit, evasion, persistence


def lan_cfg(**over):
    cfg = base_cfg(network_profiles=[{"InterfaceAlias": "Wi-Fi", "NetworkCategory": "Private"}],
                   security_center={"antivirus": [{"displayName": "Windows Defender",
                                                   "productState": 397568}], "firewall": []})
    cfg.update(over)
    return cfg


class Event1102(unittest.TestCase):
    def test_1102_maps_to_v20(self):  # KNOWN-ISSUE-1 (đã sửa ở P1)
        self.assertTrue(evasion.detect([ev(1102)])[0].mitre.startswith("T1685.005"))

    def test_event_1100_is_not_log_clearing(self):
        # Event 1100 (dịch vụ log tắt) không được gán là "xóa log"; chưa có detector T1685.001
        self.assertEqual(evasion.detect([ev(1100)]), [])


class AttackMap(unittest.TestCase):
    def test_version_pinned(self):
        self.assertEqual(ATTACK_VERSION, "Enterprise v20.0")

    def test_entries_complete_and_windows(self):
        for tid, info in ATTACK_MAP.items():
            self.assertTrue(info["name"] and info["tactics"] and info["windows"], tid)

    def test_no_legacy_id_in_current_map(self):
        self.assertFalse(set(ATTACK_LEGACY) & set(ATTACK_MAP))

    def test_label_rejects_unknown_and_legacy(self):
        for tid in ("T1070.001", "T1562.004", "T9999"):
            with self.assertRaises(KeyError):
                label(tid)

    def test_all_detector_codes_in_map(self):
        cfg_bad = base_cfg(accounts_policy={"min_password_length": 0, "lockout_threshold": 0},
                           firewall={"Domain": False, "Private": False, "Public": False},
                           defender={"RealTimeProtectionEnabled": False}, uac_enabled=False,
                           run_keys=[{"location": "HKCU", "name": "x", "command": "y"}],
                           scheduled_tasks=[{"TaskPath": "\\", "TaskName": "t", "Actions": "a"}],
                           admin_members=[{"Name": "evil", "SID": "S-1-5-21-9"}])
        events = ([failed_logon("a", i) for i in range(6)]
                  + [failed_logon(f"s{u}", u) for u in range(6)]
                  + [ev(1102), ev(4720, TargetSid="S-1-5-21-9", TargetUserName="evil"),
                     ev(4732, TargetSid=ADMINS_SID, MemberSid="S-1-5-21-9")])
        alerts = (config_audit.detect(cfg_bad) + bruteforce.detect(events) + evasion.detect(events)
                  + accounts.detect(events, cfg_bad, base_cfg())
                  + persistence.detect(events, cfg_bad, base_cfg())
                  + integrity.check({"config": base_cfg(), "signature": "x"}))
        found = {technique_id(a.mitre) for a in alerts if a.mitre}
        self.assertTrue(found)
        self.assertLessEqual(found, set(ATTACK_MAP))
        self.assertFalse(found & set(ATTACK_LEGACY))

    def test_benchmark_expected_in_map(self):
        for primary, extra in benchmark.EXPECTED.values():
            self.assertLessEqual({primary, *extra}, set(ATTACK_MAP))


class ConfigReferences(unittest.TestCase):
    @unittest.expectedFailure  # KNOWN-ISSUE-3
    def test_firewall_reference_v20(self):
        cfg = lan_cfg(firewall={"Domain": True, "Private": False, "Public": True})
        alerts = config_audit.detect(cfg, profile="WINGUARD_LAB")
        self.assertEqual([a.mitre.split()[0] for a in alerts if a.pillar == "CONFIRMED_WEAKNESS"],
                         ["T1686.003"])

    @unittest.expectedFailure  # KNOWN-ISSUE-3
    def test_defender_reference_v20(self):
        cfg = lan_cfg(defender={"RealTimeProtectionEnabled": False, "AntivirusSignatureAge": 0},
                      security_center={"antivirus": [{"displayName": "Windows Defender",
                                                      "productState": 393472}], "firewall": []})
        alerts = config_audit.detect(cfg, profile="WINGUARD_LAB")
        self.assertEqual([a.mitre.split()[0] for a in alerts if a.pillar == "CONFIRMED_WEAKNESS"],
                         ["T1685"])

    @unittest.expectedFailure  # KNOWN-ISSUE-2
    def test_uac_has_no_direct_attack_mapping(self):
        alerts = config_audit.detect(lan_cfg(uac_enabled=False), profile="WINGUARD_LAB")
        uac = [a for a in alerts if a.root_cause == "uac"]
        self.assertEqual(len(uac), 1)
        self.assertEqual(uac[0].pillar, "CONFIRMED_WEAKNESS")
        self.assertEqual(uac[0].mitre, "")
        self.assertEqual(uac[0].attack_candidates,
                         [{"technique": "T1548.002", "status": "unconfirmed",
                           "reason": uac[0].attack_candidates[0]["reason"]}])
        self.assertEqual((uac[0].cwe, uac[0].cwe_status), ("CWE-250", "proposed"))


if __name__ == "__main__":
    unittest.main()
