# Hợp đồng API và mã lỗi

Tài liệu mô tả giao diện hiện có trong `secure_share/ports.py`, `models.py`, `errors.py` và các module cài đặt. Khi đổi API cần Tiệp, Nhật, Hoàng đồng ý; Quang cập nhật test, Việt cập nhật giao diện nếu bị ảnh hưởng. Tên hàm là hợp đồng nhóm; không giữ hai bộ tên song song.

## Service (`FileShareService`)

| Hàm | Vào → ra | Ghi chú |
|---|---|---|
| `send_file(SendRequest)` | `profile_id`, `recipient_contact_id`, `source_path`, `destination_path`, `passphrase`, `overwrite_confirmed` → `OperationResult` | Chỉ báo `SUCCESS` sau khi gói đã ghi xong; nguồn không bị sửa |
| `prepare_receive(ReceiveRequest)` | `profile_id`, `package_path`, `passphrase` → `OperationResult` có `PreparedReceive` | Dừng sau khi payload hợp lệ; bản rõ chỉ nằm trong bộ nhớ của service |
| `save_received(handle, destination, overwrite_confirmed=False)` | → `OperationResult` | Giao diện mở Save As rồi gọi hàm này; ghi nguyên tử; chặn đường dẫn được bảo vệ |
| `discard_prepared(handle)` | → `OperationResult` (`CANCELLED`) | Không tạo tệp; handle hết hiệu lực |
| `close()` | | Hủy bản chờ lưu, không ghi gì |

`OperationResult` mang `status` (`SUCCESS`, `PREPARED`, `CANCELLED`, `FAILED`), `error` (`ErrorInfo` với `code` và `stage`), `warnings` (`WarningCode`: `DUPLICATE_TRANSFER`, `HISTORY_UNAVAILABLE`, `HISTORY_NOT_SAVED`). Chỉ một tác vụ chạy tại một thời điểm; yêu cầu thứ hai nhận `BUSY`. Handle hết hiệu lực sau khi lưu hoặc hủy.

Service đi theo đúng thứ tự: giới hạn/parse, tin người ký, PSS, tìm khóa nhận, mở khóa riêng, OAEP, kiểm tra khóa AES, GCM, payload, lưu, ghi lịch sử.

## Cổng cộng tác (`ports.py`)

| Cổng | Hàm chính | Lưu ý |
|---|---|---|
| `StoragePort` | `read_limited(path, max_bytes)`, `save_atomic(data, destination, overwrite_confirmed, protected_paths)` | Lỗi đã biết không commit và giữ tệp cũ; ngoại lệ lạ coi là kết quả không chắc chắn (`SAVE_STATE_UNKNOWN`) |
| `KeyProvider` | `get_profile`, `protected_paths`, `resolve_decryption_key(profile, fp)`, `unlock_private_key(profile, role, fp, passphrase)` | Giải mã tìm theo fingerprint, gồm khóa cũ còn giữ; không dùng khóa ký thay khóa giải mã |
| `TrustProvider` | `resolve_recipient(profile, contact_id)`, `resolve_sender(profile, signing_fp)` | Chỉ trả liên hệ đã xác minh; không tin khóa tự khai trong gói |
| `CryptoProvider` | `generate_aes_key`, `generate_nonce`, `wrap_key`, `unwrap_key`, `encrypt_payload`, `decrypt_payload`, `sign_package`, `verify_signature` | `verify_signature` trả `None` khi đúng và **ném `ShareError` mọi lần sai**; trả `False` là vi phạm hợp đồng |
| `EnvelopeCodec` | `build_header`, `build_payload`, `parse_payload`, `build_aad`, `build_signature_input`, `serialize_envelope`, `parse_envelope` | `parse_envelope` giữ nguyên byte H; parse chưa xác thực người gửi |
| `HistoryPort` | `has_seen(profile, transfer_id)`, `record(profile, transfer_id)` | Ghi sau khi lưu tệp thành công |

## Hàm mật mã và định dạng (không phụ thuộc cổng)

Trong `secure_share/crypto_ops.py`: `encrypt_payload`, `decrypt_payload`, `wrap_key(aes_key, n, e, seed=None)`, `unwrap_key`, `sign_package(message, n, d)`, `verify_signature(message, signature, n, e)`, `generate_key_nonce`, `generate_rsa_key`, `sha256`, `mgf1`. Lớp `CryptoOps` bọc các hàm này, nhận đối tượng khóa của `keys.py`, và đổi lỗi thành `ShareError`. `unwrap_key` ném `AESKeyLengthError` riêng khi khóa AES mở ra không dài 32 byte.

Trong `secure_share/envelope.py`: `frame`, `build_aad`, `build_signature_input`, `build_header`, `parse_header`, `serialize_envelope`, `parse_envelope`, `build_payload`, `parse_payload`, `read_json`, `encode_json`. Lớp `EnvelopeCodec` bọc các hàm này và trả các kiểu trong `models.py`. Chi tiết byte: `docs/package_format.md` và `docs/crypto_design.md`.

## Mã lỗi (`ErrorCode`)

| Nhóm | Mã |
|---|---|
| Đọc và đầu vào | `READ_FAILED`, `INPUT_TOO_LARGE`, `INVALID_REQUEST`, `INVALID_LENGTH` |
| Cấu trúc gói | `INVALID_JSON`, `INVALID_SCHEMA`, `INVALID_BASE64`, `UNSUPPORTED_VERSION`, `UNSUPPORTED_SUITE` |
| Tin cậy và khóa | `UNTRUSTED_RECIPIENT`, `UNTRUSTED_SENDER`, `PROFILE_INVALID`, `RECIPIENT_KEY_NOT_FOUND`, `KEY_UNLOCK_FAILED` |
| Mật mã | `SIGNATURE_INVALID`, `UNWRAP_FAILED`, `AES_KEY_LENGTH_INVALID`, `GCM_AUTH_FAILED`, `PAYLOAD_INVALID` |
| Lưu tệp | `SAVE_FAILED`, `DESTINATION_EXISTS`, `PROTECTED_PATH`, `SAVE_STATE_UNKNOWN` |
| Trạng thái | `INVALID_HANDLE`, `BUSY` |
| Lịch sử | `HISTORY_INVALID`, `HISTORY_TOO_LARGE` |
| Khác | `INTEGRATION_UNAVAILABLE`, `INTERNAL_ERROR` |

`ProcessingStage` ghi bước xử lý: `READ`, `PARSE`, `TRUST`, `SIGNATURE`, `RECIPIENT`, `KEY_UNLOCK`, `UNWRAP`, `GCM`, `PAYLOAD`, `SAVE`, `HISTORY`. Thông báo cho người dùng chỉ lấy từ `safe_message(code)`; `ShareError` cố ý bỏ nội dung ngoại lệ gốc để không lộ đường dẫn hay dữ liệu bí mật. Hủy là trạng thái `CANCELLED`, không phải lỗi.

## Ánh xạ tầng mật mã sang mã lỗi

| Tầng | Điều kiện | `ErrorCode` |
|---|---|---|
| Parse | gói vượt cap; JSON, schema, Base64, độ dài, phiên bản, suite | `INPUT_TOO_LARGE`, `INVALID_JSON`, `INVALID_SCHEMA`, `INVALID_BASE64`, `INVALID_LENGTH`, `UNSUPPORTED_VERSION`, `UNSUPPORTED_SUITE` |
| Chữ ký | PSS không đạt | `SIGNATURE_INVALID` |
| OAEP | W không mở được | `UNWRAP_FAILED` |
| Khóa AES | mở ra không đủ 32 byte | `AES_KEY_LENGTH_INVALID` |
| GCM | thẻ hoặc AAD sai | `GCM_AUTH_FAILED` |
| Payload | framing/metadata/tên tệp sai | `PAYLOAD_INVALID` |
