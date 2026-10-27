"""Luật đánh giá cấu hình bảo mật, chạy theo luồng bằng chứng của winguard.evidence.

Mỗi hàm assess_* làm bước 2-3 (đủ dữ liệu chưa, có vi phạm không) và trả Finding;
detect() làm bước 4-6 rồi đổi thành Alert.
"""
from winguard import cwe_map, cwss, cwss_vectors
from winguard.attack import ATTACK_CANDIDATES, label
from winguard.evidence import NOT_PRESENT, Finding, classify, score
from winguard.models import CONFIRMED_WEAKNESS, NEEDS_REVIEW, Alert

# Trình bày cho từng thiết lập: (mức Legacy Score, đề xuất, mã ATT&CK tham chiếu)
PRESENTATION = {
    "lockout_threshold": ("HIGH", "net accounts /lockoutthreshold:5", "T1110"),
    "min_password_length": ("MEDIUM", "net accounts /minpwlen:8", "T1110"),
    "firewall": ("HIGH", "Set-NetFirewallProfile -Name {profile} -Enabled True", "T1686.003"),
    "defender_rtp": ("HIGH", "Bật lại trong Windows Security > Virus & threat protection.", "T1685"),
    "uac": ("HIGH", "Bật lại UAC (EnableLUA = 1).", ""),
}
COMPUTE = cwss.compute  # bước 6; test có thể thay bằng bộ tính lỗi để kiểm nhánh SCORING_ERROR


def assess_lockout(cfg: dict) -> Finding:
    policy = cfg.get("accounts_policy") or {}
    f = Finding("lockout_threshold", "lockout_threshold", "Chưa bật khóa tài khoản khi đăng nhập sai",
                observed=policy.get("lockout_threshold"), expected="1-5", source="net accounts",
                raw=policy)
    if f.observed is None:
        f.missing.append("không đọc được lockout threshold")
        return classify(f, None)
    if f.observed > 5:
        f.title = f"Ngưỡng khóa tài khoản cao ({f.observed} lần)"
        f.context["severity"] = "MEDIUM"
    return classify(f, f.observed == 0 or f.observed > 5)


def assess_min_password(cfg: dict) -> Finding:
    policy = cfg.get("accounts_policy") or {}
    min_len = policy.get("min_password_length")
    f = Finding("min_password_length", "min_password_length",
                f"Độ dài mật khẩu tối thiểu thấp ({min_len})", observed=min_len, expected=">= 8",
                source="net accounts", raw=policy)
    if min_len is None:
        f.missing.append("không đọc được độ dài mật khẩu tối thiểu")
        return classify(f, None)
    return classify(f, min_len < 8)


def assess_firewall(cfg: dict) -> list[Finding]:
    out = []
    for profile, enabled in (cfg.get("firewall") or {}).items():
        f = Finding("firewall", f"firewall:{profile}", f"Tường lửa profile {profile} đang TẮT",
                    observed={"Enabled": enabled}, expected={"Enabled": True},
                    source="Get-NetFirewallProfile", raw={profile: enabled},
                    context={"profile": profile})
        out.append(classify(f, not enabled))
    return out


def assess_defender(cfg: dict) -> Finding | None:
    defender = cfg.get("defender") or {}
    rtp = defender.get("RealTimeProtectionEnabled") if defender else None
    f = Finding("defender_rtp", "defender_rtp", "Microsoft Defender Real-time protection đang TẮT",
                observed={"RealTimeProtectionEnabled": rtp}, expected={"RealTimeProtectionEnabled": True},
                source="Get-MpComputerStatus", raw=defender)
    if not defender:
        return None  # collector lỗi đã được collector_health báo
    return classify(f, not rtp)


def assess_uac(cfg: dict) -> Finding | None:
    uac = cfg.get("uac_enabled")
    if uac is None:
        return None  # collector lỗi đã được collector_health báo
    f = Finding("uac", "uac", "UAC đang bị tắt", observed={"EnableLUA": 1 if uac else 0},
                expected={"EnableLUA": 1},
                source=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
                raw={"uac_enabled": uac})
    return classify(f, not uac)


DETAIL = {
    "lockout_threshold": "Kẻ tấn công có thể thử mật khẩu nhiều lần mà tài khoản không bị khóa.",
    "min_password_length": "Mật khẩu ngắn dễ bị đoán hoặc bẻ khóa.",
    "firewall": "Lớp lọc lưu lượng của Windows Firewall cho profile này đang tắt; dịch vụ đang lắng "
                "nghe có thể tiếp nhận kết nối nếu không có lớp lọc khác.",
    "defender_rtp": "Lớp bảo vệ chống mã độc thời gian thực của Windows đang tắt.",
    "uac": "Admin Approval Mode tắt: tài khoản thuộc Administrators chạy với token đầy đủ không cần "
           "xác nhận; một số cơ chế bảo vệ liên quan bị suy yếu.",
}


def _confirmed_alert(f: Finding) -> list[Alert]:
    sev, rec, attack = PRESENTATION[f.root_cause]
    scored = score(f, cwe_map.lookup, cwss_vectors.build, COMPUTE)
    cwss = scored["cwss"]
    alert = Alert(f.context.get("severity", sev), f.title, DETAIL[f.root_cause], rec.format(profile=f.context.get("profile", "")),
                  label(attack) if attack else "", "config",
                  pillar=CONFIRMED_WEAKNESS, root_cause=f.root_cause, evidence=f.evidence(),
                  cwe=scored["cwe"], cwe_status=scored["cwe_status"],
                  cwe_rationale=scored["cwe_rationale"],
                  attack_candidates=[dict(c) for c in ATTACK_CANDIDATES.get(f.root_cause, [])],
                  score=cwss.get("score"), score_kind="CWSS" if cwss else "",
                  score_breakdown=cwss, scoring_error=scored["scoring_error"])
    alerts = [alert]
    if alert.scoring_error:
        alerts.append(Alert("INFO", f"Chưa tính được điểm CWSS: {f.title}", alert.scoring_error,
                            "Kiểm tra vector/bảng trọng số CWSS.", category="config",
                            pillar=NEEDS_REVIEW, root_cause="SCORING_ERROR",
                            evidence={"finding": f.key, "error": alert.scoring_error}))
    return alerts


def _review_alert(f: Finding) -> Alert:
    return Alert("INFO", f"Chưa đủ dữ liệu để kết luận: {f.title}", "; ".join(f.missing),
                 "Chạy lại bằng quyền Administrator; kiểm tra collector liên quan.", category="config",
                 pillar=NEEDS_REVIEW, root_cause=f.root_cause, evidence=f.evidence())


def detect(cfg: dict, profile: str | None = None) -> list[Alert]:
    findings = [assess_lockout(cfg), assess_min_password(cfg), *assess_firewall(cfg),
                assess_defender(cfg), assess_uac(cfg)]
    alerts = []
    for f in findings:
        if f is None or f.status == NOT_PRESENT:
            continue
        if f.status == CONFIRMED_WEAKNESS:
            alerts += _confirmed_alert(f)
        else:
            alerts.append(_review_alert(f))

    defender = cfg.get("defender") or {}
    age = defender.get("AntivirusSignatureAge")
    if age is not None and age > 7:
        alerts.append(Alert("MEDIUM", f"Chữ ký Defender cũ {age} ngày", "", "Chạy Windows Update.",
                            category="config", pillar=NEEDS_REVIEW, root_cause="defender_signature",
                            evidence={"observed": age, "expected": "<= 7",
                                      "source": "Get-MpComputerStatus"}))
    return alerts
