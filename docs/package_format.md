# Định dạng gói .sfile v1 (T3.5–T3.6)

Phần tham số mật mã, framing, AAD, dữ liệu ký và payload nằm trong
`docs/crypto_design.md`. Tài liệu này chỉ mô tả JSON ngoài, header và các
giới hạn mà `secure_share/envelope.py` kiểm tra. Hàm trong mã: `serialize_envelope`,
`parse_envelope`, `build_header`, `parse_header`, `build_payload`, `parse_payload`.

## JSON ngoài

Đúng 5 trường chuỗi Base64: `header_b64`, `wrapped_key_b64`, `nonce_b64`,
`ciphertext_b64`, `signature_b64`. Đọc nghiêm ngặt:

- Từ chối trường thiếu, lạ, trùng, sai kiểu; gốc JSON phải là object; không có
  dữ liệu thừa sau JSON; không `NaN`/`Infinity`; không nhận byte không phải UTF-8.
- Base64 phải đúng bảng chữ, đúng padding, không khoảng trắng/xuống dòng và
  mã hóa lại phải trùng chuỗi gốc (loại bit thừa).
- Độ dài chuỗi Base64 của từng trường được kiểm theo giới hạn trước khi giải mã.
- Byte H được trả về nguyên bản (`RawEnvelope.header_raw`); không parse rồi
  serialize lại trước khi verify.
- Đổi thụt dòng hoặc thứ tự thuộc tính của JSON ngoài mà năm chuỗi sau giải mã
  không đổi thì gói vẫn hợp lệ (ca R02).

## Header H (UTF-8 JSON, thô ≤ 4.096 byte)

| Trường | Giá trị |
| --- | --- |
| `format` | đúng `"SFILE"` |
| `version` | số nguyên đúng `1` (bool và số thực bị từ chối) |
| `suite` | đúng `"A256GCM_RSA3072OAEP256_PSS256"` |
| `transfer_id` | 32 ký tự hex thường |
| `sender_sig_fp`, `recipient_enc_fp` | 64 ký tự hex thường |

Không có trường nào khác. Giá trị trong H chưa được xác thực cho tới khi PSS
đạt; trước đó chỉ dùng để chọn khóa và kiểm schema.

## Giới hạn

| Mục | Giá trị | Lỗi |
| --- | --- | --- |
| Gói ngoài | ≤ 15.728.640 byte, kiểm trước khi parse | `PARSE` |
| H | ≤ 4.096 byte | `PARSE` |
| W, S | đúng 384 byte | `PARSE` |
| N | đúng 12 byte | `PARSE` |
| C | 16 đến 10.489.876 byte | `PARSE` |
| Metadata | 1 đến 4.096 byte; chỉ có `filename` | `PAYLOAD` |
| Tệp | ≤ 10.485.760 byte | `PAYLOAD` |

Lỗi cấu trúc là `EnvelopeError` (kế thừa `ValueError`) có thuộc tính `code`
là `PARSE` hoặc `PAYLOAD`. Service ánh xạ sang mã lỗi chung của Tiệp.

## Chưa làm

Chưa có: ánh xạ mã lỗi chung (`errors.py` của Tiệp), hằng số chung (`config.py`),
fingerprint từ DER SPKI (Nhật). Hằng số hiện nằm trong `envelope.py`.
