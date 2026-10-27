"""Bước 4: ánh xạ thiết lập cấu hình -> CWE. Tất cả đang ở trạng thái 'proposed'
(đề xuất của WinGuard, chưa xác minh) — kế hoạch v7.2 §3.4, §16."""

CWE_MAP = {
    "lockout_threshold": {"cwe": "CWE-307", "status": "proposed",
                          "rationale": "Improper Restriction of Excessive Authentication Attempts: "
                                       "không khóa/khóa quá muộn khi đăng nhập sai liên tục."},
    "min_password_length": {"cwe": "CWE-521", "status": "proposed",
                            "rationale": "Weak Password Requirements: độ dài tối thiểu dưới ngưỡng profile."},
    "firewall": {"cwe": "CWE-284", "status": "proposed",
                 "rationale": "Improper Access Control: lớp lọc lưu lượng của profile đang dùng bị tắt "
                              "(ứng viên khác: CWE-693)."},
    "defender_rtp": {"cwe": "CWE-693", "status": "proposed",
                     "rationale": "Protection Mechanism Failure: bảo vệ thời gian thực tắt và không có "
                                  "sản phẩm chống mã độc khác đang bật."},
    "uac": {"cwe": "CWE-250", "status": "proposed",
            "rationale": "Execution with Unnecessary Privileges: Admin Approval Mode tắt, tài khoản "
                         "Administrators chạy với token đầy đủ."},
}


def lookup(root_cause: str) -> dict | None:
    return CWE_MAP.get(root_cause)
