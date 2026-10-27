"""Collector phân biệt ok / empty / error (kế hoạch §2 bước 1)."""
import unittest
from unittest import mock

from winguard.collectors import config

DEFAULTS = {"net_accounts": {"min_password_length": 8}, "firewall_profiles": {"Public": True},
            "network_profiles": [], "security_center": {"antivirus": [], "firewall": []},
            "defender_status": {"RealTimeProtectionEnabled": True}, "local_users": [{"SID": "x"}],
            "admin_members": [{"SID": "x"}], "uac_enabled": True}


def fake_collect(**returns):
    """config.collect() với mọi collector giả lập; returns[name] = giá trị trả về hoặc Exception."""
    patches = []
    for name, default in DEFAULTS.items():
        value = returns.get(name, default)
        if isinstance(value, Exception):
            patches.append(mock.patch.object(config, name, side_effect=value))
        else:
            patches.append(mock.patch.object(config, name, return_value=value))
    patches += [mock.patch.object(config.persistence, "run_keys", return_value=[]),
                mock.patch.object(config.persistence, "scheduled_tasks", return_value=[{"TaskName": "t"}])]
    for p in patches:
        p.start()
    try:
        return config.collect()
    finally:
        for p in patches:
            p.stop()


class CollectorStatus(unittest.TestCase):
    def test_all_ok(self):
        cfg = fake_collect()
        self.assertEqual(cfg["_errors"], [])
        self.assertEqual(cfg["_status"]["firewall"], "ok")
        self.assertEqual(cfg["_status"]["network_profiles"], "empty")  # không có kết nối: hợp lệ

    def test_none_is_error(self):
        cfg = fake_collect(network_profiles=None, security_center=None)
        self.assertEqual((cfg["_status"]["network_profiles"], cfg["_status"]["security_center"]),
                         ("error", "error"))
        self.assertIn("network_profiles", cfg["_errors"])

    def test_exception_is_error(self):
        cfg = fake_collect(firewall_profiles=RuntimeError("WMI"))
        self.assertEqual(cfg["_status"]["firewall"], "error")
        self.assertTrue(any(e.startswith("firewall") for e in cfg["_errors"]))

    def test_required_empty_is_error(self):
        cfg = fake_collect(firewall_profiles={})
        self.assertEqual(cfg["_status"]["firewall"], "empty")
        self.assertIn("firewall", cfg["_errors"])

    def test_uac_unreadable(self):
        self.assertEqual(fake_collect(uac_enabled=None)["_status"]["uac_enabled"], "error")


if __name__ == "__main__":
    unittest.main()
