"""Mapping ATT&CK theo phiên bản đã chốt (kế hoạch §4)."""
import unittest

from tests.helpers import base_cfg, ev
from winguard.detectors import config_audit, evasion


def lan_cfg(**over):
    cfg = base_cfg(network_profiles=[{"InterfaceAlias": "Wi-Fi", "NetworkCategory": "Private"}],
                   security_center={"antivirus": [{"displayName": "Windows Defender",
                                                   "productState": 397568}], "firewall": []})
    cfg.update(over)
    return cfg


class Event1102(unittest.TestCase):
    @unittest.expectedFailure  # KNOWN-ISSUE-1
    def test_1102_maps_to_v20(self):
        self.assertTrue(evasion.detect([ev(1102)])[0].mitre.startswith("T1685.005"))

    def test_event_1100_is_not_log_clearing(self):
        # Event 1100 (dịch vụ log tắt) không được gán là "xóa log"; chưa có detector T1685.001
        self.assertEqual(evasion.detect([ev(1100)]), [])


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
