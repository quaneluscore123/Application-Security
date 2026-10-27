"""Luật đánh giá cấu hình bảo mật, chạy theo luồng bằng chứng của winguard.evidence.

Mỗi hàm assess_* làm bước 2-3 (đủ dữ liệu chưa, có vi phạm không) và trả Finding;
detect() làm bước 4-6 rồi đổi thành Alert. Ngưỡng lấy từ profile (winguard.profiles).
"""
from winguard import cwe_map, cwss, cwss_vectors, profiles
from winguard.attack import ATTACK_CANDIDATES, label
from winguard.evidence import NOT_PRESENT, Finding, classify, score
from winguard.models import CONFIRMED_WEAKNESS, NEEDS_REVIEW, Alert

# Trình bày cho từng thiết lập: (mức Legacy Score, đề xuất, mã ATT&CK tham chiếu)
PRESENTATION = {
    "lockout_threshold": ("HIGH", "net accounts /lockoutthreshold:{lockout_max}", "T1110"),
    "min_password_length": ("MEDIUM", "net accounts /minpwlen:{min_len}", "T1110"),
    "firewall": ("HIGH", "Set-NetFirewallProfile -Name {profile} -Enabled True", "T1686.003"),
    "defender_rtp": ("HIGH", "Bật lại trong Windows Security > Virus & threat protection.", "T1685"),
    "uac": ("HIGH", "Bật lại UAC (EnableLUA = 1).", ""),
}
COMPUTE = cwss.compute  # bước 6; test có thể thay bằng bộ tính lỗi để kiểm nhánh SCORING_ERROR

# NetworkCategory (tên hoặc số mà PowerShell trả về) -> profile Windows Firewall
CATEGORY_TO_PROFILE = {"DomainAuthenticated": "Domain", "Private": "Private", "Public": "Public",
                       2: "Domain", 1: "Private", 0: "Public"}


def _status(cfg: dict, name: str) -> str:
    """ok | empty | error | missing (cfg cũ không có trường này)."""
    if name not in cfg:
        return "missing"
    return cfg.get("_status", {}).get(name, "ok" if cfg[name] else "empty")


def _review(f: Finding, reason: str, code: str = "INSUFFICIENT_EVIDENCE") -> Finding:
    f.missing.append(reason)
    f.context["review_code"] = code
    return classify(f, None)


def assess_lockout(cfg: dict, profile_name: str | None) -> Finding:
    policy = cfg.get("accounts_policy") or {}
    prof = profiles.get(profile_name)
    observed = policy.get("lockout_threshold")
    title = ("Chưa bật khóa tài khoản khi đăng nhập sai" if observed == 0
             else f"Ngưỡng khóa tài khoản (lockout threshold = {observed})")
    f = Finding("lockout_threshold", "lockout_threshold", title, observed=observed,
                profile=profile_name or "", source="net accounts", raw=policy)
    if prof is None:
        return _review(f, f"profile chưa xác định: {profile_name!r}", "PROFILE_UNDEFINED")
    limit = prof["lockout_threshold_max"]
    f.expected = f"1-{limit}" if limit else None
    f.context["lockout_max"] = limit
    if f.observed is None:
        return _review(f, "không đọc được lockout threshold", "COLLECTOR_ERROR")
    if limit is None:
        return _review(f, f"ngưỡng lockout của profile {profile_name} chưa được đối chiếu nguồn",
                       "PROFILE_UNDEFINED")
    if f.observed > limit:
        f.title = f"Ngưỡng khóa tài khoản cao ({f.observed} lần, profile {profile_name} yêu cầu <= {limit})"
        f.context["severity"] = "MEDIUM"
    return classify(f, f.observed == 0 or f.observed > limit)


def assess_min_password(cfg: dict, profile_name: str | None) -> Finding:
    policy = cfg.get("accounts_policy") or {}
    prof = profiles.get(profile_name)
    min_len = policy.get("min_password_length")
    f = Finding("min_password_length", "min_password_length", "Độ dài mật khẩu tối thiểu thấp",
                observed=min_len, profile=profile_name or "", source="net accounts", raw=policy)
    if prof is None:
        return _review(f, f"profile chưa xác định: {profile_name!r}", "PROFILE_UNDEFINED")
    threshold = prof["min_password_length"]
    f.expected, f.context["min_len"] = f">= {threshold}", threshold
    if min_len is None:
        f.title = "Độ dài mật khẩu tối thiểu (không đọc được)"
        return _review(f, "không đọc được độ dài mật khẩu tối thiểu", "COLLECTOR_ERROR")
    f.title = f"Độ dài mật khẩu tối thiểu thấp ({min_len} < {threshold}, profile {profile_name})"
    return classify(f, min_len < threshold)


def _other_products(cfg: dict, kind: str, exclude: str | None = None) -> bool | None:
    """Có sản phẩm `kind` (antivirus|firewall) khác đang bật trong SecurityCenter2? None = không biết.
    Trạng thái bật đọc từ productState: nhóm 4 bit thứ 4 = 1 (cách giải mã phổ biến, Microsoft
    không công bố chính thức - xem kế hoạch §16)."""
    if _status(cfg, "security_center") != "ok":
        return None
    for product in cfg["security_center"].get(kind) or []:
        name = product.get("displayName", "")
        if exclude and exclude.lower() in name.lower():
            continue
        if (int(product.get("productState") or 0) >> 12) & 0xF == 1:
            return True
    return False


def assess_firewall(cfg: dict) -> list[Finding]:
    """Chỉ kết luận vi phạm cho profile ĐANG ĐƯỢC DÙNG bởi ít nhất một kết nối (kế hoạch §9.3)."""
    fw = cfg.get("firewall") or {}
    if _status(cfg, "firewall") != "ok" or not fw:
        return [_review(Finding("firewall", "firewall", "Không xác định được trạng thái Windows Firewall",
                                source="Get-NetFirewallProfile", raw=fw),
                        "Get-NetFirewallProfile lỗi hoặc rỗng", "COLLECTOR_ERROR")]
    net_status = _status(cfg, "network_profiles")
    nets = cfg.get("network_profiles") or []
    out, active = [], {}
    for net in nets:
        prof = CATEGORY_TO_PROFILE.get(net.get("NetworkCategory"))
        if prof is None:
            alias = net.get("InterfaceAlias", "?")
            out.append(_review(Finding("firewall", f"firewall:unmapped:{alias}",
                                       f"Kết nối '{alias}' có NetworkCategory không ánh xạ được",
                                       source="Get-NetConnectionProfile", raw=net),
                               f"NetworkCategory {net.get('NetworkCategory')!r} không thuộc "
                               "DomainAuthenticated/Private/Public", "NETWORK_CATEGORY_UNKNOWN"))
            continue
        active.setdefault(prof, []).append(net.get("InterfaceAlias", "?"))
    other_fw = _other_products(cfg, "firewall")

    for profile, enabled in fw.items():
        if enabled is None:  # không đọc được: không được coi là "tắt"
            out.append(_review(Finding("firewall", f"firewall:{profile}",
                                       f"Không đọc được trạng thái tường lửa profile {profile}",
                                       source="Get-NetFirewallProfile", raw={profile: enabled}),
                               "Get-NetFirewallProfile không trả về Enabled", "COLLECTOR_ERROR"))
            continue
        if bool(enabled):
            continue
        f = Finding("firewall", f"firewall:{profile}", f"Tường lửa profile {profile} đang TẮT",
                    observed={"Enabled": False}, expected={"Enabled": True},
                    source="Get-NetFirewallProfile, Get-NetConnectionProfile, SecurityCenter2",
                    raw={"firewall": fw, "network_profiles": nets},
                    context={"profile": profile, "interfaces": active.get(profile, []),
                             "other_firewall": other_fw})
        if net_status in ("error", "missing"):
            out.append(_review(f, "không xác định được profile mạng đang hoạt động", "COLLECTOR_ERROR"))
        elif profile not in active:
            why = "không có kết nối mạng nào" if not nets else "không có kết nối nào dùng profile này"
            out.append(_review(f, f"profile tắt nhưng đang không hoạt động ({why})",
                               "FIREWALL_INACTIVE_PROFILE_OFF"))
        elif other_fw:
            out.append(_review(f, "có firewall khác đang bật (SecurityCenter2) - cần xác nhận phạm vi lọc",
                               "OTHER_PRODUCT_ACTIVE"))
        else:
            f.title += f" (đang dùng bởi: {', '.join(active[profile])})"
            out.append(classify(f, True))
    return out


def assess_defender(cfg: dict) -> Finding | None:
    defender = cfg.get("defender") or {}
    if not defender:
        return None  # collector lỗi đã được collector_health báo
    rtp = defender.get("RealTimeProtectionEnabled")
    other_av = _other_products(cfg, "antivirus", exclude="Defender")
    f = Finding("defender_rtp", "defender_rtp", "Microsoft Defender Real-time protection đang TẮT",
                observed={"RealTimeProtectionEnabled": rtp}, expected={"RealTimeProtectionEnabled": True},
                source="Get-MpComputerStatus, SecurityCenter2",
                raw={"defender": defender, "security_center": cfg.get("security_center")},
                context={"other_av": other_av})
    if rtp:
        return classify(f, False)
    if rtp is None:
        return _review(f, "Get-MpComputerStatus không trả về RealTimeProtectionEnabled", "COLLECTOR_ERROR")
    if other_av is None:
        return _review(f, "không đọc được SecurityCenter2 để biết có sản phẩm chống mã độc khác",
                       "COLLECTOR_ERROR")
    if other_av:
        return _review(f, "có sản phẩm chống mã độc khác đang bật - RTP của Defender tắt là bình thường",
                       "OTHER_PRODUCT_ACTIVE")
    return classify(f, True)


def assess_uac(cfg: dict) -> Finding | None:
    uac = cfg.get("uac_enabled")
    if uac is None:
        return None  # collector lỗi đã được collector_health báo
    f = Finding("uac", "uac", "UAC đang bị tắt", observed={"EnableLUA": 1 if uac else 0},
                expected={"EnableLUA": 1},
                source=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
                raw={"uac_enabled": uac})
    return classify(f, not uac)


def assess_password_required(cfg: dict) -> list[Finding]:
    """PasswordRequired=False chỉ là cờ chính sách -> NEEDS_REVIEW, KHÔNG chứng minh mật khẩu rỗng."""
    out = []
    for user in cfg.get("local_users") or []:
        if user.get("PasswordRequired") is False and not user.get("Disabled"):
            f = Finding("password_required", f"password_required:{user.get('SID')}",
                        f"Tài khoản '{user.get('Name')}' có cờ PasswordRequired=False",
                        observed={"PasswordRequired": False}, expected={"PasswordRequired": True},
                        source="Win32_UserAccount", raw=user)
            out.append(_review(f, "cờ chính sách không bắt buộc mật khẩu; chưa kiểm chứng mật khẩu thực tế",
                               "PASSWORD_NOT_REQUIRED"))
    return out


DETAIL = {
    "lockout_threshold": "Kẻ tấn công có thể thử mật khẩu nhiều lần mà tài khoản không bị khóa.",
    "min_password_length": "Mật khẩu ngắn dễ bị đoán hoặc bẻ khóa.",
    "firewall": "Lớp lọc lưu lượng của Windows Firewall cho profile này đang tắt; dịch vụ đang lắng "
                "nghe có thể tiếp nhận kết nối nếu không có lớp lọc khác.",
    "defender_rtp": "Lớp bảo vệ chống mã độc thời gian thực của Windows đang tắt và SecurityCenter2 "
                    "không ghi nhận sản phẩm chống mã độc khác đang bật.",
    "uac": "Admin Approval Mode tắt: tài khoản thuộc Administrators chạy với token đầy đủ không cần "
           "xác nhận; một số cơ chế bảo vệ liên quan bị suy yếu.",
}
# Legacy Score cho mục NEEDS_REVIEW: chỉ trừ điểm khi chưa có luật khác báo cùng vấn đề
REVIEW_SEVERITY = {"FIREWALL_INACTIVE_PROFILE_OFF": "LOW"}


def _confirmed_alert(f: Finding) -> list[Alert]:
    sev, rec, attack = PRESENTATION[f.root_cause]
    scored = score(f, cwe_map.lookup, cwss_vectors.build, COMPUTE)
    result = scored["cwss"]
    rec = rec.format(profile=f.context.get("profile", ""), min_len=f.context.get("min_len", ""),
                     lockout_max=f.context.get("lockout_max", ""))
    alert = Alert(f.context.get("severity", sev), f.title, DETAIL[f.root_cause], rec,
                  label(attack) if attack else "", "config",
                  pillar=CONFIRMED_WEAKNESS, root_cause=f.root_cause, evidence=f.evidence(),
                  cwe=scored["cwe"], cwe_status=scored["cwe_status"],
                  cwe_rationale=scored["cwe_rationale"],
                  attack_candidates=[dict(c) for c in ATTACK_CANDIDATES.get(f.root_cause, [])],
                  score=result.get("score"), score_kind="CWSS" if result else "",
                  score_breakdown=result, scoring_error=scored["scoring_error"])
    alerts = [alert]
    if alert.scoring_error:
        alerts.append(Alert("INFO", f"Chưa tính được điểm CWSS: {f.title}", alert.scoring_error,
                            "Kiểm tra vector/bảng trọng số CWSS.", category="config",
                            pillar=NEEDS_REVIEW, root_cause="SCORING_ERROR",
                            evidence={"finding": f.key, "error": alert.scoring_error,
                                      "review_code": "SCORING_ERROR"}))
    return alerts


def _review_alert(f: Finding) -> Alert:
    code = f.context.get("review_code", "INSUFFICIENT_EVIDENCE")
    return Alert(REVIEW_SEVERITY.get(code, "INFO"), f"Cần xem xét: {f.title}", "; ".join(f.missing),
                 "Kiểm tra thủ công thiết lập này; chạy lại bằng quyền Administrator nếu do lỗi thu thập.",
                 category="config", pillar=NEEDS_REVIEW, root_cause=f.root_cause,
                 evidence={**f.evidence(), "review_code": code})


def detect(cfg: dict, profile: str | None = None) -> list[Alert]:
    """profile: tên trong winguard.profiles.PROFILES; thiếu/sai -> các mục phụ thuộc ngưỡng ra NEEDS_REVIEW."""
    findings = [assess_lockout(cfg, profile), assess_min_password(cfg, profile), *assess_firewall(cfg),
                assess_defender(cfg), assess_uac(cfg), *assess_password_required(cfg)]
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
                            evidence={"observed": age, "expected": "<= 7", "source": "Get-MpComputerStatus",
                                      "review_code": "DEFENDER_SIGNATURE_OLD"}))
    return alerts
