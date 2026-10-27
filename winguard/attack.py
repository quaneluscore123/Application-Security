"""Bảng MITRE ATT&CK tập trung — mọi detector lấy mã kỹ thuật từ đây.

Phiên bản: ATT&CK Enterprise v20.0 (phát hành 13/10/2026).
Nguồn: STIX https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v20.0/enterprise-attack/enterprise-attack.json
Đối chiếu ngày 2026-10-28 bằng script đọc STIX (tên, tactic, nền tảng Windows, revoked,
quan hệ revoked-by); không tải mạng khi chạy chương trình hay test.
"""

ATTACK_VERSION = "Enterprise v20.0"
ATTACK_SOURCE = {
    "url": "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v20.0/enterprise-attack/enterprise-attack.json",
    "sha256": "66f3fe3f07ef1a2de0bd2fe4b3e8a9ea06c1d0bb2c46171bdbb57c7f7b666524",
    "verified": "2026-10-28",
}

# Mã kỹ thuật -> tên đầy đủ, tactic (ID TA), có áp dụng Windows. Chỉ chứa mã còn hiệu lực ở v20.0.
ATTACK_MAP = {
    "T1110": {"name": "Brute Force", "tactics": ["TA0006 Credential Access"], "windows": True},
    "T1110.003": {"name": "Brute Force: Password Spraying",
                  "tactics": ["TA0006 Credential Access"], "windows": True},
    "T1136.001": {"name": "Create Account: Local Account", "tactics": ["TA0003 Persistence"],
                  "windows": True},
    "T1098": {"name": "Account Manipulation",
              "tactics": ["TA0003 Persistence", "TA0004 Privilege Escalation"], "windows": True},
    "T1547.001": {"name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
                  "tactics": ["TA0003 Persistence", "TA0004 Privilege Escalation"], "windows": True},
    "T1053.005": {"name": "Scheduled Task/Job: Scheduled Task",
                  "tactics": ["TA0002 Execution", "TA0003 Persistence", "TA0004 Privilege Escalation"],
                  "windows": True},
    "T1685.005": {"name": "Disable or Modify Tools: Clear Windows Event Logs",
                  "tactics": ["TA0112 Defense Impairment"], "windows": True},
    "T1685.001": {"name": "Disable or Modify Tools: Disable or Modify Windows Event Log",
                  "tactics": ["TA0112 Defense Impairment"], "windows": True},
    "T1685": {"name": "Disable or Modify Tools", "tactics": ["TA0112 Defense Impairment"],
              "windows": True},
    "T1686.003": {"name": "Disable or Modify System Firewall: Windows Host Firewall",
                  "tactics": ["TA0112 Defense Impairment"], "windows": True},
    "T1548.002": {"name": "Abuse Elevation Control Mechanism: Bypass User Account Control",
                  "tactics": ["TA0004 Privilege Escalation"], "windows": True},
    "T1565.001": {"name": "Data Manipulation: Stored Data Manipulation", "tactics": ["TA0040 Impact"],
                  "windows": True},
}

# Ứng viên tham khảo CHƯA xác nhận (QĐ1): không hiển thị như kỹ thuật đã phát hiện, không tính benchmark.
ATTACK_CANDIDATES = {
    "uac": [{"technique": "T1548.002", "status": "unconfirmed",
             "reason": "UAC tắt làm giảm rào cản nâng quyền; chưa có bằng chứng hành vi bypass UAC"}],
}

# Mã cũ (<= v18.1) -> mã thay thế theo quan hệ revoked-by trong STIX v20.0. Chỉ để đọc dữ liệu cũ.
ATTACK_LEGACY = {
    "T1070.001": "T1685.005",
    "T1562.001": "T1685",
    "T1562.002": "T1685.001",
    "T1562.004": "T1686",  # revoked-by T1686; WinGuard dùng sub-technique T1686.003 (Windows Host Firewall)
}


def label(technique: str) -> str:
    """'T1685.005' -> 'T1685.005 Disable or Modify Tools: Clear Windows Event Logs'.
    Ném KeyError nếu mã không có trong ATTACK_MAP (không cho phép mã lạ/mã cũ lọt vào kết quả)."""
    return f"{technique} {ATTACK_MAP[technique]['name']}"


def technique_id(text: str) -> str:
    """Lấy mã kỹ thuật từ chuỗi nhãn ('T1110 Brute Force' -> 'T1110')."""
    return text.split()[0] if text else ""
