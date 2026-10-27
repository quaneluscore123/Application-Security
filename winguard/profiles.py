"""Profile ngưỡng cấu hình (kế hoạch v7.2 §8). Không tự đoán ngưỡng khi thiếu/sai profile."""

PROFILES = {
    "WINGUARD_LAB": {
        "min_password_length": 8,
        "lockout_threshold_max": 5,
        "source": "Chính sách nội bộ WinGuard (không phải CIS)",
        "external_standard": False,
    },
    "CIS_WINDOWS_11_ENTERPRISE_V3_L1": {
        "min_password_length": 14,
        # Giá trị lockout của CIS chưa đối chiếu bản PDF -> để None (đánh giá sẽ ra NEEDS_REVIEW)
        "lockout_threshold_max": None,
        "source": "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0, Recommendation 1.1.4 (L1) "
                  "- số hiệu cần đối chiếu bản PDF CIS",
        "external_standard": True,
    },
}
DEFAULT_PROFILE = "WINGUARD_LAB"  # giá trị mặc định khai báo rõ của CLI, hiển thị trong báo cáo


def get(name: str | None) -> dict | None:
    """Profile theo tên; None nếu thiếu hoặc không tồn tại (người gọi phải báo NEEDS_REVIEW)."""
    return PROFILES.get(name) if name else None
