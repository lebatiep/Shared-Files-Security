# Kiến trúc và chiều phụ thuộc

Mô tả cấu trúc `secure_share/` đúng như mã hiện tại. Đồ thị import dưới đây lấy từ các dòng `import` thật của từng module, không phải từ thiết kế dự kiến.

## Các lớp

```text
ui/app.py                         giao diện Tkinter, chỉ gọi application/service
    |
application.py                    lắp các phần: KeyStore, TrustStore, LocalStorage, History, CryptoOps, EnvelopeCodec
    |
service.py                        điều khiển gửi / nhận; chỉ biết ports, models, config, errors
    |
keys.py   trust_store.py   crypto_ops.py   envelope.py   storage.py   history.py
    |
config.py   models.py   errors.py   ports.py                 hằng số, kiểu dữ liệu, mã lỗi, giao diện cổng
```

`service.py` không import module cụ thể nào của lớp dưới. Nó nhận các bộ cộng tác (`keys`, `trust`, `crypto`, `envelope`, `storage`, `history`) qua `ports.py`, nên có thể thay bằng bản giả trong test (`tests/unit/test_service.py`).

## Đồ thị import thực tế

| Module | Import từ nội bộ |
|---|---|
| `config`, `errors`, `__init__` | (không có) |
| `models` | `errors` |
| `ports` | `models` |
| `crypto_ops` | `errors` (và `cryptography.rsa` chỉ để đọc kiểu khóa của `keys.py`) |
| `envelope` | `config`, `errors`, `models` |
| `storage` | `errors`, `models` |
| `history` | `config`, `errors`, `models` |
| `keys` | `config`, `crypto_ops`, `envelope`, `errors`, `models`, `storage` |
| `trust_store` | `envelope`, `errors`, `keys`, `models`, `storage` |
| `service` | `config`, `errors`, `models`, `ports` |
| `application` | `crypto_ops`, `envelope`, `history`, `keys`, `service`, `storage`, `trust_store` |
| `ui/app` | `application`, `errors`, `models` |

Quy tắc giữ nguyên:

- `crypto_ops` và `envelope` **không import nhau**. Service chuyển AAD và dữ liệu ký từ envelope sang crypto.
- `crypto_ops` và `envelope` không đọc danh bạ, không mở hộp thoại, không tự lưu tệp.
- `storage` không import service hay giao diện.
- Giao diện không gọi thẳng mật mã; nó chỉ gọi service và các store qua `application`.

## Trách nhiệm từng module

| Module | Vai trò |
|---|---|
| `config.py` | Hằng số SHA-256/RSA/giới hạn dùng chung. Chỉ là giá trị, không tạo thư mục khi import |
| `models.py` | Kiểu dữ liệu `SendRequest`, `ReceiveRequest`, `OperationResult`, `PackageHeader`, `Payload`, `RawEnvelope`, `TrustedContact`, `ProfileSummary`... |
| `errors.py` | `ErrorCode`, `ShareError`, thông báo an toàn do ứng dụng sở hữu |
| `ports.py` | Giao diện (Protocol) của `StoragePort`, `KeyProvider`, `TrustProvider`, `CryptoProvider`, `EnvelopeCodec`, `HistoryPort` |
| `service.py` | `FileShareService`: `send_file`, `prepare_receive`, `save_received`, `discard_prepared`, `close` |
| `history.py` | `JsonHistoryStore`, `MemoryHistoryStore`: cảnh báo `transfer_id` đã nhận, ghi sau khi lưu tệp thành công |
| `keys.py` | Hồ sơ, hai cặp RSA-3072 theo vai trò, PEM PKCS8 mã hóa, fingerprint, public bundle, xoay/sao lưu/khôi phục khóa |
| `trust_store.py` | Liên hệ chưa xác minh / đã xác minh / vô hiệu, đối chiếu fingerprint, cảnh báo trùng tên |
| `crypto_ops.py` | SHA-256, MGF1, AES-256-GCM, RSA-OAEP, RSA-PSS tự cài; số học và sinh khóa RSA; `CryptoOps` làm bộ nối cho service |
| `envelope.py` | Framing, AAD, dữ liệu ký, header, JSON ngoài, payload; `EnvelopeCodec` làm bộ nối cho service |
| `storage.py` | `LocalStorage.read_limited`, `save_atomic`: đọc có giới hạn, ghi nguyên tử, chặn đường dẫn được bảo vệ |
| `application.py` | `create_application(root)` lắp mọi phần với thư mục gốc dữ liệu |
| `ui/app.py` | Cửa sổ chính với ba tab: Khóa của tôi, Người liên hệ, Gửi / nhận tệp; tác vụ chạy ở luồng nền |

## Luồng gửi

1. Đọc nguồn có giới hạn (`read_limited`, tối đa 10 MiB + 1 byte để biết vượt giới hạn).
2. Chọn người nhận **đã xác minh** trong đúng hồ sơ.
3. Mở khóa ký bằng mật khẩu, khớp vai trò và fingerprint.
4. Tạo `transfer_id`, khóa AES và nonce mới; dựng header và payload.
5. Bọc khóa AES (OAEP), mã hóa payload với AAD, ký M (PSS).
6. Ghi gói bằng `save_atomic`; báo thành công **sau** khi ghi xong.

## Luồng nhận (thứ tự bắt buộc)

```text
giới hạn/parse -> tin người ký (danh bạ) -> PSS -> tìm khóa nhận -> mở khóa riêng
-> OAEP -> kiểm tra khóa AES = 32 B -> GCM -> payload -> chọn/lưu tệp -> ghi lịch sử
```

`prepare_receive` làm đến hết bước payload và giữ bản rõ trong bộ nhớ; giao diện mở Save As; `save_received(handle, đích)` mới ghi tệp; `discard_prepared(handle)` hủy mà không tạo tệp. Một snapshot gói duy nhất dùng cho parse, verify và decrypt.

## Dữ liệu cục bộ

`create_application(root)` dùng `%LOCALAPPDATA%\Shared-Files-Security` khi không truyền `root`: `profiles/` (khóa), `contacts/<hồ sơ>/` (danh bạ), `history/`. Tệp khóa và danh bạ là đường dẫn được bảo vệ: không thể chọn làm nơi lưu bản rõ.

## Giới hạn kiến trúc đã biết

- `keys.py` sinh và lưu khóa bằng thư viện `cryptography`; chỉ các thuật toán dữ liệu (SHA-256, AES-GCM, OAEP, PSS) là tự cài.
- `crypto_ops.py` import `cryptography.rsa` để nhận biết và đọc số của khóa do `keys.py` đưa vào.
- Giao diện đang nằm trong một tệp `ui/app.py`; cây thư mục đã chốt ban đầu chia thành nhiều màn hình.
