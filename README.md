# WinGuard – Giám sát và đánh giá bảo mật Windows

Bài tập giữa kỳ môn **Bảo mật ứng dụng và hệ thống**.

Đề tài: *Phòng lab nhỏ để kiểm chứng luật phát hiện (detection engineering) trên máy Windows cá nhân: viết luật → mô phỏng tấn công vô hại → đo xem luật có bắt được không → vá luật.*

Dự án gồm hai thành phần:

| Thành phần | Vai trò |
|---|---|
| `winguard/` | Thu thập Event Log và cấu hình, phát hiện, chấm điểm theo ba trụ cột, xuất báo cáo console/HTML/JSON |
| `simulator/` | Mô phỏng **vô hại** các hành vi tấn công (theo MITRE ATT&CK) và bộ đo `simulator.benchmark`; mọi thay đổi đều có `cleanup` |

> ⚠️ Simulator chỉ dùng thao tác vô hại trên **chính máy của mình** (tài khoản thử nghiệm, Notepad). Không chứa mã độc hay công cụ tấn công.

Đặc tả chi tiết, quyết định thiết kế và nhật ký kiểm thử: [`cwss_implementation_plan.md`](cwss_implementation_plan.md).

## Quy trình hoạt động

```
Chuẩn bị → Baseline → Mô phỏng → Phát hiện → Phòng thủ → Kiểm tra lại → Dọn dẹp
```

| Bước | Lệnh (terminal **Run as Administrator**) |
|---|---|
| 0. Chuẩn bị (1 lần) | `powershell -ExecutionPolicy Bypass -File tools\prepare.ps1` |
| 1. Baseline | `python -m winguard --baseline` |
| 2. Mô phỏng | `python -m simulator --run bruteforce` |
| 3. Phát hiện | `python -m winguard --scan` → `data\report.html`, `data\alerts.json` |
| 4. Phòng thủ | Áp dụng đề xuất trong báo cáo, VD `net accounts /lockoutthreshold:5` |
| 5. Kiểm tra lại | Chạy lại bước 2 và 3, so sánh trước/sau |
| 6. Dọn dẹp | `powershell -ExecutionPolicy Bypass -File tools\restore.ps1` |

Tùy chọn của `python -m winguard`:

| Tùy chọn | Ý nghĩa |
|---|---|
| `--profile WINGUARD_LAB` (mặc định) | Ngưỡng nội bộ: mật khẩu ≥ 8, khóa tài khoản sau ≤ 5 lần sai |
| `--profile CIS_WINDOWS_11_ENTERPRISE_V3_L1` | Ngưỡng CIS: mật khẩu ≥ 14 (ngưỡng lockout CIS chưa đối chiếu → `NEEDS_REVIEW`) |
| `--rules v1` / `v2` (mặc định) | Bộ luật trước / sau khi vá — so sánh "thử né luật" trên cùng bộ log |

## Ba trụ cột đánh giá

| Trụ cột | Đối tượng | Mã | Điểm |
|---|---|---|---|
| `CONFIRMED_WEAKNESS` | Cấu hình yếu có bằng chứng | CWE (đề xuất) | Công thức **MITRE CWSS v1.0.1**, vector do WinGuard chọn |
| `ATTACK_OBSERVED` | Hành vi trong Security Event Log | **ATT&CK Enterprise v20.0** | Incident Severity = 100 × T × C × W (**nội bộ**) |
| `NEEDS_REVIEW` | Thiếu dữ liệu, collector lỗi, bằng chứng mâu thuẫn | Mã nội bộ | Investigation Priority (**nội bộ**) |

- **Posture Score** (nội bộ) = max(0, 100 − CWSS cao nhất − 0.1 × tổng CWSS các cụm độc lập còn lại).
- **Legacy Score** /100 (trừ 15/8/3/5 theo mức) được giữ lại như quy ước minh họa cũ.
- Bảng trọng số CWSS do AI trích từ trang gốc; **kiểm tra thủ công bởi người: đang PENDING** (`winguard/cwss_weights.py`).
- Các trọng số nội bộ chưa được hiệu chỉnh thực nghiệm.

## Kiến trúc WinGuard

```
collectors/ (chỉ đọc)  →  evidence.py (bằng chứng → trạng thái)  →  cwe_map / cwss_vectors / cwss.py
  eventlog.py   4625 4740 4720 4732 4698 1102 (+ Computer, EventRecordID)
  config.py     net accounts, firewall + kết nối mạng, SecurityCenter2, Defender, UAC, tài khoản, Administrators
detectors/  bruteforce (brute force + spraying) · accounts (tương quan 4720→4732) · persistence · evasion (1102)
            config_audit (theo profile) · collector_health
incident.py · correlation.py · priority.py · posture.py · attack.py (ATTACK_MAP v20.0)  →  reporter.py
```

## Kịch bản mô phỏng

| # | Kịch bản | ATT&CK v20.0 | Mô phỏng vô hại | Phát hiện | Phòng thủ |
|---|---|---|---|---|---|
| 1 | Brute Force | T1110 | Đăng nhập sai vào `sim_testuser` | Event 4625 vượt ngưỡng; 4740 | Account lockout, mật khẩu mạnh |
| 2 | Password Spraying | T1110.003 | 6 tài khoản `sim_spray*` × 2 lần sai | Một nguồn sai vào ≥ 5 tài khoản / 5 phút | Lockout + theo dõi theo nguồn |
| 3 | Tạo tài khoản | T1136.001 | Tạo `sim_user` | Event 4720 + so sánh baseline | Giám sát tài khoản |
| 4 | Thêm vào nhóm Admin | T1098 | Thêm `sim_user` vào Administrators | Event 4732 (tương quan 4720) + baseline | Quyền tối thiểu, UAC |
| 5 | Run key | T1547.001 | Run key `SIM_WinGuard` mở Notepad | So sánh baseline | Rà soát Autoruns |
| 6 | Scheduled Task | T1053.005 | Task `SIM_WinGuardTest` mở Notepad | Event 4698 + so sánh baseline | Giám sát Task Scheduler |

Luật bổ sung không có kịch bản mô phỏng: xóa Security Log (Event 1102 → **T1685.005**, trước v19 là T1070.001), toàn vẹn baseline (HMAC-SHA256).

## Kiểm thử

```powershell
python -m unittest discover -s tests -t . -v        # không cần quyền Admin
python -m simulator.benchmark --runs 3              # cần Admin + tools\prepare.ps1
```

- `tests/current/`: mô tả hành vi tại mốc `80fa1c1`; `tests/spec/`: kiểm tra theo đặc tả.
- Benchmark 27/10/2026 (commit `80fa1c1`, mã ATT&CK ≤ v18.1): phát hiện 18/18 lần chạy 6 kịch bản; 0 cảnh báo sự kiện trong 3 lần quét sạch; thử né luật spraying: v1 0/3, v2 3/3. Kết quả **chỉ áp dụng cho 6 kịch bản tự mô phỏng** trên một máy, không phải tỷ lệ báo động giả/bỏ sót tổng quát.

## Hướng phát triển

- Chạy luật trên bộ log công khai (EVTX-ATTACK-SAMPLES, OTRF Security-Datasets) để đo trên dữ liệu không tự tạo
- Đọc thêm log của Microsoft Defender và Windows Firewall; giám sát cổng đang lắng nghe
- Gửi log về SIEM (ví dụ Wazuh) để giám sát nhiều máy

## Yêu cầu

- Windows 10/11 (chạy được trên bản Home), Python 3.10+
- Terminal chạy quyền Administrator để đọc Security Event Log
