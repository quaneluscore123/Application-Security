# WinGuard – Giám sát và đánh giá bảo mật Windows

Bài tập giữa kỳ môn **Bảo mật ứng dụng và hệ thống**.

Đề tài: *Xây dựng công cụ giám sát và đánh giá bảo mật cho máy Windows cá nhân, kết hợp mô phỏng tấn công vô hại để kiểm chứng khả năng phát hiện và phòng thủ.*

Dự án gồm hai thành phần:

| Thành phần | Vai trò |
|---|---|
| `winguard/` | Thu thập Event Log và cấu hình, phát hiện bất thường, chấm điểm bảo mật /100, xuất báo cáo HTML |
| `simulator/` | Mô phỏng **vô hại** các hành vi tấn công (theo MITRE ATT&CK) để kiểm tra WinGuard; mọi thay đổi đều có `cleanup` |

> ⚠️ Simulator chỉ dùng thao tác vô hại trên **chính máy của mình** (tài khoản thử nghiệm, Notepad, cổng localhost...). Không chứa mã độc hay công cụ tấn công.

## Quy trình hoạt động

```
Chuẩn bị → Baseline → Mô phỏng → Phát hiện → Phòng thủ → Kiểm tra lại → Dọn dẹp
```

| Bước | Lệnh (terminal **Run as Administrator**) |
|---|---|
| 0. Chuẩn bị (1 lần) | `powershell -ExecutionPolicy Bypass -File tools\prepare.ps1` |
| 1. Baseline | `python -m winguard --baseline` |
| 2. Mô phỏng | `python -m simulator --run bruteforce` |
| 3. Phát hiện | `python -m winguard --scan` → `data\report.html` |
| 4. Phòng thủ | Áp dụng đề xuất trong báo cáo, VD `net accounts /lockoutthreshold:5` |
| 5. Kiểm tra lại | Chạy lại bước 2 và 3, so sánh trước/sau |
| 6. Dọn dẹp | `powershell -ExecutionPolicy Bypass -File tools\restore.ps1` |

`prepare.ps1` tạo System Restore Point, sao lưu audit policy và chính sách tài khoản vào `data\`, rồi bật audit đăng nhập. `restore.ps1` xóa tài khoản thử nghiệm và khôi phục cấu hình gốc.

## Kiến trúc WinGuard

```
collectors/  (thu thập, chỉ đọc)  →  detectors/ (luật)  →  scoring.py  →  reporter.py
  eventlog.py  Security Event Log      bruteforce.py         điểm /100     console + HTML
  config.py    net accounts, firewall, config_audit.py
               Defender, UAC, tài      accounts.py (Event Log + so sánh baseline)
               khoản, nhóm Admin       persistence.py (Run key, Scheduled Task)
  persistence.py  Run key, Scheduled Task
```

## Kịch bản mô phỏng

| # | Kịch bản | MITRE ATT&CK | Mô phỏng vô hại | Phát hiện | Phòng thủ | Trạng thái |
|---|---|---|---|---|---|---|
| 1 | Brute Force | T1110 | Đăng nhập sai vào `sim_testuser` | Event 4625 vượt ngưỡng; 4740 | Account lockout, mật khẩu mạnh | ✅ Xong |
| 2 | Tạo tài khoản | T1136 | Tạo `sim_user` | Event 4720 + so sánh baseline | Giám sát tài khoản | ✅ Xong |
| 3 | Thêm vào nhóm Admin | T1098 | Thêm `sim_user` vào Administrators | Event 4732 + so sánh baseline | Quyền tối thiểu, UAC | ✅ Xong |
| 4 | Run key | T1547.001 | Run key `SIM_WinGuard` mở Notepad | So sánh baseline | Rà soát Autoruns | ✅ Xong |
| 5 | Scheduled Task | T1053.005 | Task `SIM_WinGuardTest` mở Notepad | Event 4698 + so sánh baseline | Giám sát Task Scheduler | ✅ Xong |
Ngoài ra, WinGuard đánh giá cấu hình (chính sách mật khẩu, khóa tài khoản, tường lửa, Defender, UAC) ở mọi lần quét.

## Kế hoạch

- [x] **Giai đoạn 1:** khung dự án, module cấu hình, kịch bản 1 (Brute Force) trọn vòng, báo cáo HTML
- [x] **Giai đoạn 2:** kịch bản 2–3 (tài khoản, nhóm Admin – Event 4720/4732)
- [x] **Giai đoạn 3:** kịch bản 4–5 (persistence: Run key, Scheduled Task, so sánh baseline)
- [ ] **Giai đoạn 4:** thử nghiệm trọn vòng, viết báo cáo và slide, tập demo

## Hướng phát triển

- Đọc thêm log của Microsoft Defender và Windows Firewall
- Giám sát cổng mạng đang lắng nghe so với baseline
- Gửi log về hệ thống SIEM (ví dụ Wazuh) để giám sát nhiều máy

## Yêu cầu

- Windows 10/11 (chạy được trên bản Home), Python 3.10+
- Terminal chạy quyền Administrator để đọc Security Event Log
