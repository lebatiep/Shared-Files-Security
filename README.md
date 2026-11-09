# Chia sẻ tệp an toàn (SFILE v1)

Ứng dụng desktop cục bộ để gửi một tệp cho một người nhận đã xác minh. Người gửi mã hóa tệp và ký gói `.sfile`; người nhận kiểm tra chữ ký trước khi giải mã. Không có máy chủ và không có mật khẩu dùng chung. Đây là dự án học tập/nghiên cứu: chỉ dùng dữ liệu giả.

Phạm vi bản này: một người nhận mỗi gói, tệp tối đa 10 MiB (10.485.760 byte), AES-256-GCM, RSA-3072 OAEP, RSA-3072 PSS, xác minh bằng fingerprint. Không có thu hồi gói, forward secrecy hay chứng thư PKI; xem `docs/threat_model.md`.

## Yêu cầu

Windows, Python 3.12 trở lên (CI và `requirements.txt` dùng 3.12). Tkinter đi kèm bản cài Python chuẩn.

## Cài và chạy

```powershell
# Cách nhanh: tự tạo .venv, cài thư viện rồi mở ứng dụng
.\start.cmd

# Hoặc làm tay
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m secure_share
```

Hồ sơ và danh bạ nằm ở `%LOCALAPPDATA%\Shared-Files-Security` (không nằm trong thư mục mã nguồn). Giao diện có ba tab: **Khóa của tôi**, **Người liên hệ**, **Gửi / nhận tệp**.

Quy trình dùng lần đầu: tạo hồ sơ (mật khẩu tối thiểu 12 ký tự) → xuất public bundle gửi cho người kia → nhập bundle của họ → so cả hai fingerprint qua kênh độc lập (gặp mặt hoặc cuộc gọi) → xác minh → gửi/nhận.

## Kiểm tra

```powershell
python -m secure_share --check          # môi trường và các module tích hợp
python -m pytest -q                     # toàn bộ test (xem lưu ý về tốc độ bên dưới)
python -m tools.demo                    # gửi/nhận trong thư mục tạm, khóa giả
python -m tools.benchmark --repeats 3   # đo thời gian, chậm với tệp lớn
python -m tools.make_fixtures --out DIR # gói lỗi có manifest để kiểm thử
python -m tools.case_report             # ID nghiệm thu nào đã có test gắn
```

`tools.case_report` chỉ liệt kê test được gắn marker `case`; nó không chạy test và không ghi ca nào là đạt. Test đơn vị không thay ca nghiệm thu do người chạy độc lập thực hiện.

## Lưu ý về tốc độ

AES-GCM, OAEP, PSS và SHA-256 được cài bằng Python thuần từ công thức, không dùng thư viện mật mã cho thuật toán dữ liệu, nên chậm: đo thô khoảng 14 KiB/s, tức một tệp 10 MiB mất hàng chục phút mỗi chiều (chưa đo trực tiếp ở 10 MiB). Dùng tệp nhỏ khi thử tay. Ca test 10 MiB (`max-10MiB`) rất lâu; chạy riêng khi cần.

Phần sinh và lưu khóa RSA (PEM mã hóa, fingerprint DER SPKI) vẫn dùng thư viện `cryptography` (`keys.py`).

## Cấu trúc

```text
secure_share/   ứng dụng: config, models, errors, ports, service, history,
                keys, trust_store, storage, crypto_ops, envelope, application, ui/
tests/          unit/, integration/, rsa_fixtures.py (khóa test công khai)
tools/          demo, benchmark, make_fixtures, case_report
docs/           đặc tả, mô hình đe dọa, báo cáo
```

Hướng phụ thuộc và ranh giới module: `docs/architecture.md`. Hợp đồng API và mã lỗi: `docs/interfaces.md`.

## Quy tắc an toàn khi dùng và phát triển

- Không đưa khóa thật, mật khẩu thật hay tài liệu cá nhân vào repo; khóa trong `tests/rsa_fixtures.py` chỉ dành cho test.
- `*.pem`, `*.key`, `*.sfile`, `runtime/` bị `.gitignore` loại.
- Mã mật mã tự cài chưa được kiểm toán và không chống tấn công đo thời gian; không dùng cho dữ liệu thật.

Quy tắc đóng góp: `CONTRIBUTING.md`.
