# Mô hình đe dọa và giới hạn (T3.8)

Người viết: Hoàng (phần mật mã, định dạng). Tiệp (phần phạm vi, tích hợp) chưa duyệt;
không coi tài liệu này là hợp đồng chung cho tới khi Tiệp và Nhật đọc xong.
Nguồn: proposal 1.0 (phần "Mô hình đe dọa và giới hạn"), `docs/crypto_design.md`,
`docs/package_format.md`.

## 1. Tài sản và giả định

Cần bảo vệ: nội dung và tên tệp (nằm trong phần mã hóa), khóa AES từng gói,
hai khóa riêng RSA của mỗi hồ sơ (mã hóa và ký), danh bạ tin cậy cục bộ.

Giả định: thiết bị và danh bạ cục bộ không do kẻ tấn công kiểm soát; hai
bên đối chiếu fingerprint qua một kênh độc lập; khóa riêng được bảo vệ bằng
passphrase mạnh. Kênh truyền gói (USB, ứng dụng nhắn tin) được coi là không đáng tin.

## 2. Kẻ tấn công và mức ngăn chặn

Mallory có thể đọc, giữ, sửa, ghép, phát lại và tự tạo gói. Mallory không có
khóa riêng của Alice hay Bob, trừ các ca giới hạn ở mục 4.

| Hành vi của Mallory | Cơ chế chặn | Bước dừng | Ca / test liên quan |
| --- | --- | --- | --- |
| Giữ bản sao gói, đọc nội dung | AES-256-GCM; khóa AES chỉ mở được bằng khóa riêng của người nhận (RSA-OAEP) | `UNWRAP` | A06, `test_wrong_recipient_cannot_open` |
| Sửa một byte của H, W, N hoặc C | PSS trên M gồm đủ H, W, N, C | `SIGNATURE` | A02, A03; `test_tampering_any_part_breaks_signature`, `test_signature_protects_each_field` |
| Lật byte chữ ký S | PSS thất bại | `SIGNATURE` | A02 |
| Ghép các phần của hai gói hợp lệ | Chữ ký ràng buộc cả bốn phần | `SIGNATURE` | A05 |
| Tạo gói mới bằng public key Bob, tự xưng Alice | Chữ ký phải khớp khóa ký Alice đã ghim; header tự khai không phải nguồn tin cậy | `TRUST`/`SIGNATURE` | A04 (service và trust của Nhật/Tiệp) |
| Gửi JSON sai cấu trúc, trường trùng/lạ, Base64 lỗi, gói quá lớn | Parser nghiêm ngặt, kiểm giới hạn trước khi giải mã | `PARSE` | P01–P07; `tests/unit/test_envelope.py` |
| Nhét tên tệp độc hại vào metadata | `filename` chỉ là gợi ý; storage (Việt) quyết định đường dẫn lưu | `SAVE` | R04, R05 (storage) |
| Gửi lại gói cũ | Chỉ cảnh báo trùng `transfer_id`; không chặn tuyệt đối | lịch sử (Tiệp) | L04 |
| Đổi khoảng trắng/thứ tự thuộc tính của JSON ngoài | Không phải sửa nội dung được bảo vệ; gói vẫn hợp lệ | — | R02; `test_outer_json_reformatting_stays_valid` |

Thứ tự kiểm tra khi nhận (đã chốt): giới hạn/parse, tin người ký, PSS, tìm khóa
nhận, mở khóa riêng, OAEP, kiểm tra khóa AES 32 byte, GCM, payload, lưu, lịch sử.
Sửa C thông thường dừng ở PSS; để tới được OAEP/GCM/payload phải dùng fixture
do bộ test tạo và ký bằng khóa test (`SignedBadFixtureTests`), không phải khả
năng của kẻ không có khóa ký.

## 3. Lựa chọn thiết kế để giảm rủi ro

- Hai cặp khóa RSA riêng (mã hóa, ký), `e = 65537`; một khóa lộ không kéo theo vai trò kia.
- Khóa AES và nonce mới ngẫu nhiên (`os.urandom`) cho mỗi gói; không dùng `random`.
- Mọi lỗi giải OAEP trả cùng một thông báo, không phân biệt nguyên nhân (giảm
  nguy cơ oracle kiểu Manger ở tầng ứng dụng).
- Chỉ trả plaintext khi thẻ GCM khớp; so sánh thẻ bằng cộng dồn XOR, không dừng sớm.
- Parser kiểm cap trước khi giải mã Base64 hoặc cấp phát; không đọc vô hạn.
- `version` phải là số nguyên đúng 1 (bool và số thực bị từ chối); khóa JSON trùng bị từ chối.
- Không log khóa, nonce kèm khóa, passphrase hay plaintext (service/UI phải giữ quy tắc này).

## 4. Giới hạn của mô hình (phải nói khi bảo vệ)

1. **Người nhận chuyển tiếp bản rõ** được. Không có thu hồi, DRM hay hết hạn offline (L05).
2. **Người gửi chọn nhầm liên hệ hợp lệ** thì gói mở được bởi người đó; giao diện xác nhận chỉ giảm sai sót (S09).
3. **Xác minh fingerprint sai hoặc bỏ qua** có thể dẫn tới gửi bí mật cho Mallory, ghim sai khóa (L06).
4. **Lộ khóa**: lộ khóa nhận mở được các gói cũ đã thu; lộ khóa ký cho phép tạo gói giả được tin khi pin còn hiệu lực. Không có forward secrecy.
5. **Không có dấu thời gian tin cậy**: không kết luận gói được ký trước hay sau sự cố khi vô hiệu hóa một liên hệ (L02).
6. **Lộ siêu dữ liệu**: gói lộ dung lượng gần đúng, hai fingerprint và mối liên hệ giữa các lần trao đổi.
7. **Không chống** thiết bị nhiễm mã độc, trộm khóa đã mở, sửa danh bạ tin cậy cục bộ, hoặc người nhận cố ý chia sẻ.
8. **Mất khóa hoặc passphrase**: không có đường bỏ qua; chỉ phục hồi được nếu còn bản sao khóa mã hóa và passphrase (L03).
9. **Không có xác nhận đã đọc** hay chứng thư PKI; tin cậy dựa trên ghim fingerprint thủ công.
10. Bộ test hữu hạn không chứng minh an toàn toàn diện; chỉ nghiệm thu các nhánh và ca trong phạm vi.

## 5. Giới hạn riêng của bản triển khai tự cài

Các điểm sau không có trong thiết kế proposal mà do việc tự cài bằng Python:

- **Không bảo đảm thời gian hằng.** Python không cho phép điều khiển thời gian
  thực thi: tra S-box theo chỉ số phụ thuộc khóa, nhân GHASH rẽ nhánh theo bit,
  và `pow(c, d, n)` với khóa riêng có thể rò rỉ qua đo thời gian hoặc kênh bên
  nếu kẻ tấn công đo được lặp lại cục bộ.
- **RSA không dùng CRT và không blinding**; `check_key` chỉ kiểm hình dạng
  (3072 bit, lẻ, số mũ), không chứng minh `n` là tích hai số nguyên tố.
- So sánh khối `DB` khi giải OAEP dùng `!=` trên `bytes` (dừng ở byte khác đầu
  tiên), không phải phép so sánh thời gian hằng.
- **Chưa kiểm toán**, chưa đối chiếu độc lập sau lần gộp mã mới nhất (xem `crypto_design.md`, mục 8).
- Nguồn ngẫu nhiên là `os.urandom` (bộ sinh của hệ điều hành); không tự viết bộ sinh ngẫu nhiên vì sẽ cho khóa đoán được.
- Không nên dùng cho dữ liệu thật. Mã phục vụ nghiên cứu và học tập.

Các giới hạn này chỉ áp dụng cho kẻ tấn công có thể chạy mã hoặc đo thời gian
trên cùng máy, mà mô hình đã loại trừ ở mục 4.7. Không dùng để tuyên bố an toàn
trước kẻ tấn công cục bộ.
