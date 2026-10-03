"""Luật đánh giá cấu hình bảo mật."""
from winguard.models import Alert


def detect(cfg: dict) -> list[Alert]:
    alerts = []

    policy = cfg.get("accounts_policy", {})
    threshold = policy.get("lockout_threshold")
    if threshold == 0:
        alerts.append(Alert("HIGH", "Chưa bật khóa tài khoản khi đăng nhập sai",
                            "Lockout threshold = Never: kẻ tấn công có thể đoán mật khẩu không giới hạn.",
                            "net accounts /lockoutthreshold:5", "T1110 Brute Force", "config"))
    elif threshold and threshold > 5:
        alerts.append(Alert("MEDIUM", f"Ngưỡng khóa tài khoản cao ({threshold} lần)",
                            "Nên khóa sau tối đa 5 lần đăng nhập sai.",
                            "net accounts /lockoutthreshold:5", "T1110 Brute Force", "config"))

    min_len = policy.get("min_password_length")
    if min_len is not None and min_len < 8:
        alerts.append(Alert("MEDIUM", f"Độ dài mật khẩu tối thiểu thấp ({min_len})",
                            "Mật khẩu ngắn dễ bị đoán hoặc bẻ khóa.",
                            "net accounts /minpwlen:8", "T1110 Brute Force", "config"))

    for profile, enabled in cfg.get("firewall", {}).items():
        if not enabled:
            alerts.append(Alert("HIGH", f"Tường lửa profile {profile} đang TẮT", "",
                                f"Set-NetFirewallProfile -Name {profile} -Enabled True",
                                "T1562.004 Disable or Modify System Firewall", "config"))

    defender = cfg.get("defender", {})
    if defender and not defender.get("RealTimeProtectionEnabled"):
        alerts.append(Alert("HIGH", "Microsoft Defender Real-time protection đang TẮT", "",
                            "Bật lại trong Windows Security > Virus & threat protection.",
                            "T1562.001 Disable or Modify Tools", "config"))
    age = defender.get("AntivirusSignatureAge")
    if age is not None and age > 7:
        alerts.append(Alert("MEDIUM", f"Chữ ký Defender cũ {age} ngày", "",
                            "Chạy Windows Update.", category="config"))

    if cfg.get("uac_enabled") is False:
        alerts.append(Alert("HIGH", "UAC đang bị tắt", "Mọi chương trình chạy với quyền cao nhất.",
                            "Bật lại UAC (EnableLUA = 1).", "T1548.002 Bypass UAC", "config"))
    return alerts
