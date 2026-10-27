"""Firewall theo profile đang hoạt động (kế hoạch §9)."""
import unittest

from tests.spec.test_attack_mapping import lan_cfg
from winguard.detectors import config_audit


def fw(cfg):
    return [a for a in config_audit.detect(cfg, profile="WINGUARD_LAB") if a.root_cause == "firewall"]


class FirewallActiveProfile(unittest.TestCase):
    @unittest.expectedFailure  # KNOWN-ISSUE-4
    def test_inactive_profile_off_is_only_review(self):
        alerts = fw(lan_cfg(firewall={"Domain": False, "Private": True, "Public": True}))
        self.assertEqual([a.pillar for a in alerts], ["NEEDS_REVIEW"])


if __name__ == "__main__":
    unittest.main()
