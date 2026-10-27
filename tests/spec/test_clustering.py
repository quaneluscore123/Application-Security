"""Trường gom cụm và tương quan sự kiện (kế hoạch §6)."""
import unittest

from tests.helpers import EVENT_XML
from winguard.collectors import eventlog


class EventFields(unittest.TestCase):
    def test_parse_keeps_computer_and_record_id(self):  # KNOWN-ISSUE-6 (đã sửa ở P4)
        e = eventlog.parse_event(EVENT_XML)
        self.assertEqual((e["computer"], e["record_id"]), ("LAB-PC", 42))


if __name__ == "__main__":
    unittest.main()
