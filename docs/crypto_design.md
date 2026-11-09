# Đặc tả mật mã SFILE1 — T3.1 đến T3.4

Tài liệu bàn giao cho phần service, quản lý khóa và envelope. Phạm vi là một
tệp cho một người nhận, xử lý trong bộ nhớ. Không thêm thuật toán tùy chọn.
Nguồn yêu cầu: kế hoạch mẫu phiên bản 1.1, ngày 09/11/2026, trang 4–6, 11–12
và các ca liên quan ở trang 22–25.

## 1. Trạng thái hợp đồng

- Tham số và công thức dưới đây giữ theo kế hoạch mẫu.
- Theo yêu cầu triển khai riêng, AES/GCM, RSA/OAEP, PSS, SHA-256 và MGF1 tự
  cài bằng Python, thay cho hướng dẫn gọi thư viện ở T3.3 trong PDF.
- `int`, `pow` và `os.urandom` được phép dùng. JSON/Base64 là định dạng dữ
  liệu, không phải thư viện triển khai thuật toán mật mã.
- Hằng số SHA-256 (căn bậc hai và bậc ba của các số nguyên tố đầu tiên) và
  S-box AES (nghịch đảo trong GF(2^8) rồi biến đổi affine) được tính khi nạp
  mô-đun, không chép bảng. Test so kết quả với bảng chuẩn FIPS 180-4 và FIPS 197.
- Mã tự cài phục vụ nghiên cứu/học tập. Tốc độ không phải yêu cầu của dự án
  này; xem `Document/issues.md` về giới hạn và lý do.
- Chưa có `config.py`, `models.py`, `errors.py` của phần tích hợp hoặc
  giao diện khóa chính thức. Hằng số đang nằm tại nơi dùng; khi tích hợp
  cần đối chiếu và chuyển sang config chung của dự án.
- Chưa có proposal 22 trang mà PDF dẫn tới. Không coi schema header,
  biểu diễn ID/fingerprint hoặc toàn bộ expected của 60 ca là đã chốt.
  Đặc tả này cần Tiệp/Nhật/Hoàng review trước khi coi là hợp đồng chung.

## 2. Tham số và giới hạn

| Thành phần | Giá trị |
| --- | --- |
| AES | AES-256-GCM, khóa 32 byte |
| Nonce | 12 byte |
| Tag GCM | 16 byte, nối cuối ciphertext |
| RSA | Modulus 3072 bit, public exponent 65537 |
| OAEP | SHA-256, MGF1-SHA256, label rỗng |
| PSS | SHA-256, MGF1-SHA256, salt đúng 32 byte |
| Tệp gốc | Tối đa 10.485.760 byte |
| Header H | Tối đa 4.096 byte |
| Metadata JSON | Tối đa 4.096 byte UTF-8 |
| Payload | Tối đa 10.489.860 byte |
| Gói JSON ngoài | Tối đa 15.728.640 byte; parser T3.5–T3.6 kiểm tra |

Mỗi lần gửi gọi `generate_key_nonce()` để tạo khóa và nonce mới. Không tái
sử dụng nonce với cùng khóa. Không dùng `random` cho khóa, nonce hay salt.

## 3. Các trường gói

| Ký hiệu | Ý nghĩa | Ràng buộc |
| --- | --- | --- |
| H | Header JSON UTF-8 ở dạng byte gốc | 1–4.096 byte tại helper framing; schema do parser kiểm tra |
| W | Khóa AES được RSA-OAEP bọc cho người nhận | Đúng 384 byte |
| N | Nonce AES-GCM | Đúng 12 byte |
| C | Ciphertext nối tag GCM | 16–10.489.876 byte ở kiểm tra cấu trúc |
| S | Chữ ký RSA-PSS của người gửi | Đúng 384 byte |

Gói JSON ngoài có đúng năm field chuỗi Base64:
`header_b64`, `wrapped_key_b64`, `nonce_b64`, `ciphertext_b64`, `signature_b64`.
Việc serialize/parse, từ chối field trùng/thiếu/lạ, Base64 lỗi, phiên bản,
suite, ID và fingerprint (T3.5–T3.6) do `envelope.py` thực hiện; xem
`docs/package_format.md`. Không được hiểu kết quả helper framing hay
`parse_header` là xác nhận header hợp lệ hay đáng tin: chỉ PSS đạt mới cho
phép dùng giá trị trong H.

Giới hạn C là kiểm tra ngoài, không chứng minh payload hợp lệ. C đủ tag vẫn
có thể chứa payload bị cắt hoặc metadata sai. Tên tệp gốc nằm trong phần mã hóa.

## 4. Framing, AAD và byte ký

`||` là nối byte; `u32be` là số nguyên không dấu 4 byte big-endian.

```text
frame(X) = u32be(len(X)) || X
AAD = b"SFILE1-AAD" || frame(H) || frame(W)
M = b"SFILE1-SIGN" || frame(H) || frame(W) || frame(N) || frame(C)
S = RSA-PSS-SIGN(M)
```

Context dùng nguyên byte ASCII, không thêm NUL, dấu cách hoặc dấu phân cách.
Độ dài được tính trên byte, không phải số ký tự Unicode.

- `frame(b"")` có hex `00000000`.
- `frame(b"ABC")` có hex `00000003414243`.
- Prefix của W dài 384 byte là `00000180`.
- Prefix của N dài 12 byte là `0000000c`.
- `SFILE1-AAD` dài 10 byte, hex `5346494c45312d414144`.
- `SFILE1-SIGN` dài 11 byte, hex `5346494c45312d5349474e`.

Phải giữ H nguyên byte khi nhận. Thay đổi khoảng trắng bên trong H làm thay
đổi chữ ký/AAD. Đổi thứ tự field hoặc khoảng trắng của JSON ngoài có thể
vẫn hợp lệ nếu năm chuỗi sau giải mã Base64 giữ nguyên H/W/N/C/S.

S không nằm trong M vì chữ ký không tự ký chính nó. Tag thuộc C nên đã
được PSS bảo vệ cùng ciphertext. AAD không chứa N/C; GCM xử lý nonce và
ciphertext theo cơ chế của GCM.

## 5. Payload

```text
payload = u32be(meta_len) || metadata_json_utf8 || raw_file
```

Schema metadata tối thiểu của bản triển khai này:

```json
{"filename":"a.txt"}
```

Hiện chỉ nhận đúng field `filename`, kiểu string, không rỗng, không chứa
NUL và mã hóa được UTF-8. Đây là lựa chọn schema tối thiểu để nhóm review;
PDF chỉ nói metadata có filename, chưa liệt kê toàn bộ schema.
JSON xuất compact, UTF-8 trực tiếp. Khi đọc không yêu cầu khoảng trắng hay
thứ tự cố định nhưng từ chối khóa trùng, field lạ, NaN/Infinity và JSON lỗi.
Tên là metadata, không áp đặt thư mục đích. Các tên chứa đường dẫn vẫn
được giữ như dữ liệu; Việt xử lý tên gợi ý/Save As và chặn đường dẫn nguy hiểm.

Ví dụ `filename="a.txt"`, `raw_file=b"\x00\xff"`:

```text
metadata = b'{"filename":"a.txt"}'       # 20 byte
meta_len = 00 00 00 14
payload hex = 000000147b2266696c656e616d65223a22612e747874227d00ff
payload dài 26 byte; C sau mã hóa dài 42 byte (thêm tag 16 byte).
```

Với H dài 2 byte, W dài 384 byte, N dài 12 byte và C dài 42 byte:
AAD dài `10 + 4 + 2 + 4 + 384 = 404` byte;
M dài `11 + 4 + 2 + 4 + 384 + 4 + 12 + 4 + 42 = 467` byte.
Đây là ví dụ tính độ dài, không phải một gói có header/khóa hợp lệ.

Khi đọc phải kiểm tra kích thước tổng, prefix metadata, phần metadata có
đủ byte, UTF-8/JSON/schema và kích thước raw_file. Không suy diễn raw_file
là text hoặc từ chối một kiểu nội dung chỉ vì nó là binary.

## 6. Giao diện bàn giao

Tên hàm theo hợp đồng nhóm (`PROJECT_STRUCTURE_AND_TASKS.md`). Mã nằm đúng
cấu trúc đã chốt: `secure_share/crypto_ops.py` và `secure_share/envelope.py`.
Hai module không import nhau; service chuyển AAD/M từ envelope sang crypto.

| Module/hàm | Đầu vào → đầu ra |
| --- | --- |
| `crypto_ops.generate_key_nonce()` | Không có đầu vào → `(key32, nonce12)` |
| `crypto_ops.encrypt_payload(payload, key, nonce, aad)` | bytes → C có tag |
| `crypto_ops.decrypt_payload(C, key, nonce, aad)` | bytes → payload sau xác thực |
| `crypto_ops.wrap_key(key, n, e=65537, seed=None)` | Khóa AES 32 byte, public key → W (`seed` chỉ cho test) |
| `crypto_ops.unwrap_key(W, n, d)` | W, private key → khóa AES đúng 32 byte hoặc lỗi |
| `crypto_ops.sign_package(M, n, d)` | M, private key ký → S |
| `crypto_ops.verify_signature(M, S, n, e=65537)` | M, public key ký → bool |
| `crypto_ops.generate_rsa_key(bits=3072)` | → `(n, e, d, p, q)`; cho Nhật dùng khi sinh hồ sơ |
| `envelope.build_payload(filename, raw_file)` | Tên + bytes tệp → payload |
| `envelope.parse_payload(payload)` | payload → `(filename, raw_file)` |
| `envelope.frame(X)` | bytes → prefix độ dài + bytes gốc |
| `envelope.build_aad(H, W)` | H/W → AAD |
| `envelope.build_signature_input(H, W, N, C)` | H/W/N/C → M |
| `envelope.build_header(id, sender_fp, recipient_fp)` / `parse_header(H)` | Tạo / kiểm schema header |
| `envelope.serialize_envelope(RawEnvelope)` / `parse_envelope(bytes)` | 5 phần ↔ JSON ngoài |

SHA-256 và MGF1 nằm trong `crypto_ops` (`sha256`, `mgf1`). Hằng số SHA-256 và
S-box AES được sinh bằng toán lúc nạp mô-đun, không chép bảng. `pow(a, e, n)`
của Python được phép dùng. Định dạng gói chi tiết: `docs/package_format.md`.

Khóa hiện được truyền bằng số nguyên `n/e/d`; Nhật cần cung cấp các thành
phần từ khóa đã mở và đã kiểm tra. Module RSA chỉ kiểm tra hình dạng n/số
mũ và exponent công khai, không chứng minh n là tích hai nguyên tố hay
cặp khóa hợp lệ. Không tự sinh khóa thay khi thiếu hoặc dùng sai khóa.
Hai cặp khóa mã hóa/ký phải khác nhau; quản lý vai trò, fingerprint và
đối chiếu private/public thuộc Nhật và service, không thể suy ra từ n/d.

Kiểu đầu vào là `bytes`; lỗi kiểu gây `TypeError` hoặc `ValueError` ở
primitive hiện có. Dữ liệu sai định dạng/độ dài gây `ValueError`.
`verify` trả `False` cho chữ ký không hợp lệ, không cho service bỏ qua.
Service chuyển lỗi theo bước: PSS → SIGNATURE, OAEP/khóa mở bọc sai độ dài
→ UNWRAP, xác thực GCM → GCM, payload → PAYLOAD. Mã lỗi chung cuối cùng
vẫn phải khớp `errors.py` của Tiệp, chưa có trong repo hiện tại.

## 7. Thứ tự sử dụng

Gửi:

1. Service chọn người nhận tin cậy và mở khóa ký đúng vai trò.
2. Đóng payload; tạo khóa AES/nonce mới; bọc khóa cho người nhận để có W.
3. Tạo H theo schema chung, dựng AAD từ H/W, mã hóa payload để có C.
4. Dựng M từ H/W/N/C; ký bằng private key ký để có S.
5. Serialize gói và lưu qua storage; báo thành công sau lưu.

Nhận theo đúng thứ tự trang 6:

```text
Giới hạn/parse → tin người ký → PSS → tìm khóa nhận → mở khóa riêng
→ OAEP → kiểm tra khóa AES → GCM → payload → chọn/lưu tệp → lịch sử
```

Parse, verify và decrypt phải dùng cùng snapshot gói. Header trước PSS chỉ
dùng để chọn khóa/check schema. GCM kiểm tra tag trước khi giải mã và trả
plaintext; không đưa bản rõ vào UI/log hoặc lưu tệp khi bước xác thực lỗi.
Các module ở đây không đọc danh bạ, gọi UI, tự lưu tệp hoặc ghi lịch sử.

## 8. Kiểm tra và giới hạn bằng chứng

Chạy từ thư mục repo, không cần cài thư viện:

```powershell
python -m pytest -q
python -m unittest discover -s tests -t .
```

Các test gồm vector AES/GCM/SHA-256; OAEP/PSS đúng và sai; salt PSS sai độ
dài; sửa từng trường ký; đổi vỏ JSON; payload rỗng/binary/Unicode; biên
10 MiB/4.096 byte; metadata và framing lỗi; gửi/nhận bằng hai cặp khóa test.
Fixture khóa test được lưu công khai trong test, không dùng cho dữ liệu thật.
Việc sinh fixture test động theo T5.2 chưa nằm trong phạm vi này.

Ca signed_bad dùng private key test để ký dữ liệu lỗi nhằm đi tới tầng
OAEP/GCM/payload. Không mô tả đây là khả năng của kẻ không có khóa ký.
Các test hiện chỉ là unit và tích hợp các primitive trong bộ nhớ, không
thay thế nghiệm thu service/UI hoặc xác nhận đạt toàn bộ 60 ID.

Kết quả chạy (10/11/2026, Python 3.12 trên máy của Hoàng):
`python -m pytest -q -k "not max-10MiB"` cho 296 test đạt, 190 subtest, 105 giây.
**Ca gửi-nhận đúng 10 MiB (`max-10MiB`) bị loại khỏi lần chạy này vì quá lâu với
AES tự cài; kết quả của ca đó chưa được xác nhận trong tài liệu này.** Trước đó,
lần chạy ngày 09/11/2026 có 284 đạt và 2 lỗi của chính bộ test (id tham số 10 MiB
vượt giới hạn biến môi trường Windows 32.767 ký tự); lỗi này đã được sửa bằng
`ids=` trong `tests/integration/test_desktop_app.py` (các id còn lại thu thập
bình thường).

**Đối chiếu độc lập (10/11/2026).** Script chạy ngoài repo, so mã tự cài
(`crypto_ops.py` hiện tại, sau khi gộp và sau khi sinh hằng số bằng toán) với
`hashlib` và thư viện `cryptography` cài riêng. Thư viện chỉ làm chuẩn so sánh,
không được import trong mã ứng dụng hay trong test của phần mật mã. Kết quả:

- SHA-256: khớp `hashlib` ở 204 độ dài (0–199, 1.000, 4.095, 4.096, 65.535).
- AES-256-GCM: mã hóa khớp từng byte với `AESGCM` ở 96 tổ hợp (16 độ dài dữ
  liệu × 6 độ dài AAD, gồm 0, 15, 16, 17, 100 byte) và giải mã bản của thư viện
  đúng ở cả 96 tổ hợp.
- Lật 1 bit ở từng vị trí của một gói 56 byte: cả hai phía đều từ chối.
- OAEP: 20 lần, tôi bọc thì thư viện mở và thư viện bọc thì tôi mở.
- PSS: 8 kích thước thông điệp (0 đến 100.000 byte), tôi ký thì thư viện xác minh
  và thư viện ký thì tôi xác minh; thông điệp bị sửa bị từ chối.

Phạm vi và giới hạn của đối chiếu: một khóa RSA-3072 mỗi vai trò (khóa test), một
lần chạy, dữ liệu ngẫu nhiên; không có vector NIST đầy đủ cho GCM, không kiểm thời
gian hằng, không phải kiểm toán bảo mật. Script không nằm trong repo.

**Gói lỗi có manifest.** `python -m tools.make_fixtures --out DIR` sinh 28 gói
(`good`, A02, A03, A05, A07–A12, P01–P04, P06) và `manifest.json` ghi trường đã
đổi, tầng dự kiến dừng và SHA-256. `tests/unit/test_make_fixtures.py` kiểm từng
gói dừng đúng tầng (PARSE, SIGNATURE, UNWRAP, UNWRAP_KEY_LENGTH, GCM, PAYLOAD,
OK) bằng đường nhận ở mức mô-đun, không qua service. Gói lỗi sâu được ký lại bằng
khóa ký test (`tests/rsa_fixtures.py`); đó là fixture của người kiểm thử.

**Bộ nối.** `CryptoOps` (trong `crypto_ops.py`) và `EnvelopeCodec` (trong
`envelope.py`) bọc các hàm trên để service dùng: nhận đối tượng khóa của
`keys.py`, đổi lỗi sang `ErrorCode`, và `verify_signature` trả `None` khi đúng,
ném lỗi khi sai. `unwrap_key` ném `AESKeyLengthError` để phân biệt khóa AES sai
độ dài (ca A08) với OAEP hỏng (ca A07).

Liên hệ các ID ở mức module: S01/S02/S03/S04/S08, R02,
A02/A03/A07/A08/A09/A10/A11/A12. Các ca cần trust/recipient, parser đầy đủ,
I/O và UI chỉ được nghiệm thu khi có phần tích hợp tương ứng.

Chưa tích hợp app và chưa kiểm toán bảo mật. Chưa có số đo benchmark chính
thức (T5.7 của Quang); một phép đo thô cho thấy AES-GCM tự cài rất chậm, xem
`Document/issues.md`. Python không bảo đảm thời gian hằng, kể cả lũy thừa RSA
với private key (`pow`, không CRT, không blinding), so sánh khối OAEP và tra
bảng AES. Mã phục vụ học tập; không cam kết bảo mật 256 bit toàn hệ thống,
forward secrecy, thu hồi gói offline hoặc ngăn người nhận chuyển tiếp.
