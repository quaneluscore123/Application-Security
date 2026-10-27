"""Bước 5: WinGuard chọn vector CWSS cho từng điểm yếu cấu hình (kế hoạch v7.2 §3.3-§3.4).

Mỗi metric có nguồn: collected (dữ liệu collector), assumed (giả định threat model công bố),
unknown (không kiểm chứng được -> mã Unknown, trọng số chính thức 0.5).
MITRE không chứng nhận các vector này; đây là phương pháp áp dụng của WinGuard.
"""
from winguard.evidence import Finding

C, A, U = "collected", "assumed", "unknown"

# Threat model chung: kẻ tấn công cùng mạng LAN/Wi-Fi hoặc người dùng chạy tệp tải về, máy trạm cá nhân.
_COMMON = {
    "AL": ("S", A, "Tác động ở tầng hệ điều hành."),
    "RL": ("S", A, "Khai thác ở tầng hệ điều hành."),
    "SC": ("A", A, "Thiết lập áp dụng cho toàn máy/profile."),
    "DI": ("H", A, "Trạng thái này dễ bị phát hiện bằng công cụ phổ biến."),
    "EX": ("H", A, "Khai thác không cần kỹ thuật đặc biệt."),
    "P": ("NA", A, "Targeted scoring cho một máy cụ thể."),
    "FC": ("T", C, "Đọc trực tiếp giá trị cấu hình."),
}

TEMPLATES = {
    "firewall": {
        "TI": ("H", A, "Mất lớp lọc lưu lượng của profile đang dùng."),
        "AP": ("RU", A, "Tương tác được với dịch vụ chạy dưới quyền người dùng."),
        "IC": ("UK", U, "Chưa kiểm tra được lớp lọc khác (SecurityCenter2)."),
        "RP": ("N", A, "Gửi gói tin không cần quyền trước."),
        "AV": ("A", A, "Kẻ tấn công ở mạng liền kề (LAN/Wi-Fi)."),
        "AS": ("N", A, "Lọc gói không có bước xác thực."),
        "IN": ("A", A, "Quét và khai thác tự động."),
        "BI": ("H", A, "Máy trạm lộ dịch vụ trước mạng cục bộ."),
        "EC": ("UK", U, "Không kiểm chứng được firewall biên/NAT."),
    },
    "lockout_threshold": {
        "TI": ("M", A, "Cho phép đoán mật khẩu nhiều lần."),
        "AP": ("RU", A, "Chiếm tài khoản người dùng."),
        "IC": ("N", C, "Không có cơ chế khóa (lockout = 0)."),
        "RP": ("N", A, "Kẻ tấn công chưa có quyền."),
        "AV": ("A", A, "Thử qua giao thức mạng (SMB/RDP)."),
        "AS": ("W", A, "Xác thực bằng mật khẩu tĩnh."),
        "IN": ("A", A, "Script gửi đăng nhập liên tục."),
        "BI": ("M", A, "Lộ tài khoản người dùng."),
        "EC": ("UK", U, "Không kiểm chứng được IDS/IPS hay kiểm soát bên ngoài."),
    },
    "min_password_length": {
        "TI": ("M", A, "Thu hẹp không gian tìm kiếm mật khẩu."),
        "AP": ("RU", A, "Chiếm tài khoản người dùng."),
        "IC": ("L", C, "Có chính sách độ dài nhưng dưới ngưỡng profile."),
        "RP": ("N", A, "Không cần quyền trước."),
        "AV": ("A", A, "Thử qua mạng LAN."),
        "AS": ("W", A, "Mật khẩu ngắn dễ đoán."),
        "IN": ("A", A, "Tự động thử từ điển."),
        "BI": ("M", A, "Mất an toàn thông tin xác thực."),
        "EC": ("UK", U, "Không kiểm chứng được kiểm soát bên ngoài."),
    },
    "defender_rtp": {
        "TI": ("H", A, "Mã độc thực thi không bị chặn tức thời."),
        "AP": ("A", A, "Mã độc có thể leo thang quyền."),
        "IC": ("N", C, "Bảo vệ thời gian thực đang tắt."),
        "RP": ("L", A, "Người dùng/kẻ tấn công đưa tệp vào máy."),
        "AV": ("L", A, "Thực thi trên máy cục bộ."),
        "AS": ("N", A, "Không có xác thực với bộ quét."),
        "IN": ("T", A, "Người dùng mở tệp tải về."),
        "BI": ("H", A, "Nguy cơ ransomware/trojan."),
        "EC": ("UK", U, "Chưa xác nhận trạng thái sản phẩm chống mã độc khác."),
    },
    "uac": {
        "TI": ("H", A, "Tài khoản Administrators chạy token đầy đủ không cần xác nhận."),
        "AP": ("A", A, "Tiến trình của quản trị viên có toàn quyền."),
        "IC": ("N", C, "EnableLUA = 0."),
        "RP": ("RU", A, "Cần có phiên đăng nhập trên máy."),
        "AV": ("L", A, "Chạy ứng dụng cục bộ."),
        "AS": ("N", A, "Không còn bước xác nhận nâng quyền."),
        "IN": ("A", A, "Thực thi không cần tương tác."),
        "BI": ("H", A, "Mã độc sửa hệ thống không cảnh báo."),
        "EC": ("UK", U, "Không kiểm chứng được AppLocker/WDAC hay cơ chế thay thế."),
    },
}


def _dynamic(f: Finding, metrics: dict) -> None:
    """Thay giả định bằng dữ liệu khi collector có."""
    if f.root_cause == "lockout_threshold" and f.observed:
        metrics["IC"] = ("L", C, f"Có khóa nhưng ngưỡng ({f.observed}) cao hơn profile.")
    if f.root_cause == "firewall" and f.context.get("other_firewall") is False:
        metrics["IC"] = ("N", C, "SecurityCenter2: không có firewall khác đăng ký.")
    if f.root_cause == "defender_rtp" and f.context.get("other_av") is False:
        metrics["EC"] = ("N", C, "SecurityCenter2: không có sản phẩm chống mã độc khác đang bật.")


def build(f: Finding) -> dict:
    """-> {'vector': {metric: mã}, 'metric_sources': {...}, 'rationale': {...}}. Không có mẫu -> KeyError."""
    metrics = {**_COMMON, **TEMPLATES[f.root_cause]}
    _dynamic(f, metrics)
    return {"vector": {m: v[0] for m, v in metrics.items()},
            "metric_sources": {m: v[1] for m, v in metrics.items()},
            "rationale": {m: v[2] for m, v in metrics.items()}}
