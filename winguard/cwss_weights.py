"""Bảng trọng số MITRE CWSS v1.0.1 và trạng thái kiểm tra thủ công (kế hoạch v7.2 §3.2, §3.2a).

Bảng dưới đây do AI trích từ trang gốc bằng công cụ đọc web ngày 2026-10-28.
Đây KHÔNG phải kiểm tra thủ công: CWSS_MANUAL_CHECK giữ PENDING cho tới khi một
người thật mở trang gốc, đối chiếu theo checklist §3.2a và điền kết quả.
"""
CWSS_SOURCE = "https://cwe.mitre.org/cwss/cwss_v1.0.1.html"
CWSS_EXTRACTED = {"by": "AI (công cụ đọc web)", "date": "2026-10-28"}

# Kết quả do người kiểm tra báo lại (AI chỉ ghi chép, không tự kiểm tra). Ảnh trong docs/audit/ do người
# kiểm tra chụp. VERIFIED: công thức + bảng trọng số khớp nguồn; mâu thuẫn của Example 4.1 nằm trong
# chính tài liệu MITRE (ghi ở example_4_1), không phải sai lệch giữa nguồn và code.
CWSS_MANUAL_CHECK = {
    "status": "VERIFIED",       # PENDING | VERIFIED | DISCREPANCY
    "reviewer": "Hoàng Minh Quân",
    "date": "2026-10-28",       # ban đầu báo 27/10; sửa thành 28/10 với sự đồng ý của người kiểm tra
    "source_url": CWSS_SOURCE,
    "formulas": "MATCH",
    "weight_table": "MATCH",
    "example_4_1": {
        "status": "DISCREPANCY",  # mâu thuẫn nằm trong chính tài liệu nguồn, không sửa số
        "vector_as_published": "(TI:H,0.9/AP:A,1.0/AL:A,1.0/IC:N,1.0/FC:T,1.0/RP:L,0.9/RL:A,1.0/AV:I,1.0/"
                               "AS:N,1.0/IN:T,0.9/SC:A,1.0/BI:C,0.9/DI:H,1.0/EX:H,1.0/EC:N,1.0/P:NA,1.0)",
        "base": 96.0, "attack_surface": 0.965, "environmental": 1.0, "score": 92.6,
        "bi_value_in_vector": 0.9,
        "bi_value_in_calculation": 1.0,  # phần tính của tài liệu: (10*1.0 + 3*1.0 + 4*1.0 + 3*1.0)
        "screenshot": "docs/audit/cwss_example_4_1.png",
        "calculation_screenshot": "docs/audit/cwss_example_4_1_calculation.png",
    },
    "example_4_2": {
        "status": "MATCH",
        "vector_as_published": "(TI:M,0.6/AP:A,1.0/AL:A,1.0/IC:N,1.0/FC:T,1.0/RP:RU,0.7/RL:A,1.0/AV:I,1.0/"
                               "AS:W,0.9/IN:A,1.0/SC:NA,1.0/BI:L,0.3/DI:NA,1.0/EX:NA,1.0/EC:N,1.0/RE:NA,1.0/"
                               "P:NA,1.0)",
        "base": 84.0, "attack_surface": 0.935, "environmental": 0.65, "score": 51.1,
        "re_handling": "Phần ví dụ 4.2 không giải thích RE:NA; RE không thuộc 16 metric nên parser bỏ qua",
        "screenshot": "docs/audit/cwss_example_4_2.png",
    },
    "weight_table_screenshots": ["docs/audit/cwss_weights_av.png", "docs/audit/cwss_weights_ti.png"],
    "notes": "Ví dụ 4.1: vector in BI:C,0.9 nhưng bảng trọng số ghi C = 1.0 và Environmental = 1.0, "
             "điểm 92.6 chỉ đúng với BI = 1.0 (với 0.9: Env 0.95, điểm 88.0). "
             "Mã Unknown của AV là U (khác UK của các metric khác) - đã xác nhận bằng ảnh "
             "docs/audit/cwss_weights_av.png. Ảnh bảng trọng số có AV và TI; các bảng còn lại người "
             "kiểm tra đối chiếu trực tiếp trên trang (MATCH) nhưng không chụp. "
             "Ví dụ 4.1: phần tính trong tài liệu dùng BI = 1.0 (ảnh cwss_example_4_1_calculation.png).",
}

# metric -> {mã: trọng số}. "Q" (Quantified) không hỗ trợ.
WEIGHTS = {
    "TI": {"C": 1.0, "H": 0.9, "M": 0.6, "L": 0.3, "N": 0.0, "D": 0.6, "UK": 0.5, "NA": 1.0},
    "AP": {"A": 1.0, "P": 0.9, "RU": 0.7, "L": 0.6, "N": 0.1, "D": 0.7, "UK": 0.5, "NA": 1.0},
    "AL": {"A": 1.0, "S": 0.9, "N": 0.7, "E": 1.0, "D": 0.9, "UK": 0.5, "NA": 1.0},
    "IC": {"N": 1.0, "L": 0.9, "M": 0.7, "I": 0.5, "B": 0.3, "C": 0.0, "D": 0.6, "UK": 0.5, "NA": 1.0},
    "FC": {"T": 1.0, "LT": 0.8, "F": 0.0, "D": 0.8, "UK": 0.5, "NA": 1.0},
    "RP": {"N": 1.0, "L": 0.9, "RU": 0.7, "P": 0.6, "A": 0.1, "D": 0.7, "UK": 0.5, "NA": 1.0},
    "RL": {"A": 1.0, "S": 0.9, "N": 0.7, "E": 1.0, "D": 0.9, "UK": 0.5, "NA": 1.0},
    # Mã Unknown của AV là "U" (không phải "UK") - người kiểm tra xác nhận, ảnh docs/audit/cwss_weights_av.png
    "AV": {"I": 1.0, "R": 0.8, "V": 0.8, "A": 0.7, "L": 0.5, "P": 0.2, "D": 0.75, "U": 0.5, "NA": 1.0},
    "AS": {"S": 0.7, "M": 0.8, "W": 0.9, "N": 1.0, "D": 0.85, "UK": 0.5, "NA": 1.0},
    "IN": {"A": 1.0, "T": 0.9, "M": 0.8, "O": 0.3, "H": 0.1, "NI": 0.0, "D": 0.55, "UK": 0.5, "NA": 1.0},
    "SC": {"A": 1.0, "M": 0.9, "R": 0.5, "P": 0.1, "D": 0.7, "UK": 0.5, "NA": 1.0},
    "BI": {"C": 1.0, "H": 0.9, "M": 0.6, "L": 0.3, "N": 0.0, "D": 0.6, "UK": 0.5, "NA": 1.0},
    "DI": {"H": 1.0, "M": 0.6, "L": 0.2, "D": 0.6, "UK": 0.5, "NA": 1.0},
    "EX": {"H": 1.0, "M": 0.6, "L": 0.2, "N": 0.0, "D": 0.6, "UK": 0.5, "NA": 1.0},
    "EC": {"N": 1.0, "L": 0.9, "M": 0.7, "I": 0.5, "B": 0.3, "C": 0.1, "D": 0.6, "UK": 0.5, "NA": 1.0},
    "P": {"W": 1.0, "H": 0.9, "C": 0.8, "L": 0.7, "D": 0.85, "UK": 0.5, "NA": 1.0},
}

# Ví dụ trong tài liệu gốc. 4.2 là chuẩn chính; 4.1 có mâu thuẫn trong chính tài liệu (người kiểm tra
# xác nhận vector in "BI:C,0.9") nhưng Environmental = 1.0 chỉ đúng khi BI = 1.0 (trọng số của mã C).
EXAMPLES = {
    "4.2": {"vector": "TI:M/AP:A/AL:A/IC:N/FC:T/RP:RU/RL:A/AV:I/AS:W/IN:A/SC:NA/"
                      "BI:L/DI:NA/EX:NA/EC:N/RE:NA/P:NA",
            "base": 84.0, "attack_surface": 0.935, "environmental": 0.65, "score": 51.1},
    "4.1": {"vector": "TI:H/AP:A/AL:A/IC:N/FC:T/RP:L/RL:A/AV:I/AS:N/IN:T/SC:A/"
                      "BI:C/DI:H/EX:H/EC:N/P:NA",
            "base": 96.0, "attack_surface": 0.965, "environmental": 1.0, "score": 92.6,
            "printed_bi_weight": 0.9, "status": "DISCREPANCY_CONFIRMED_BY_REVIEWER"},
}

_REQUIRED_FOR_VERIFIED = ("reviewer", "date", "formulas", "weight_table")


def manual_check_problems(check: dict, root=None) -> list[str]:
    """Lý do CWSS_MANUAL_CHECK chưa được phép mang trạng thái VERIFIED (rỗng = hợp lệ)."""
    problems = [f"{k} còn PENDING" for k in _REQUIRED_FOR_VERIFIED if check.get(k) in (None, "", "PENDING")]
    if check.get("example_4_2", {}).get("status") in (None, "", "PENDING"):
        problems.append("example_4_2.status còn PENDING")
    for ex in ("example_4_1", "example_4_2"):
        shot = check.get(ex, {}).get("screenshot")
        if shot in (None, "", "PENDING"):
            problems.append(f"{ex}.screenshot còn PENDING")
        elif root is not None and not (root / shot).exists():
            problems.append(f"{ex}.screenshot không tồn tại: {shot}")
    return problems


def manual_check_status() -> str:
    """Trạng thái dùng để hiển thị: VERIFIED chỉ khi đủ điều kiện, nếu không thì như đã ghi (PENDING...)."""
    from winguard.utils import ROOT
    status = CWSS_MANUAL_CHECK["status"]
    if status == "VERIFIED" and manual_check_problems(CWSS_MANUAL_CHECK, ROOT):
        return "INVALID_VERIFIED"
    return status
