# Chương 2. Khóa, danh tính và tin cậy

**Bản nháp** do Hoàng soạn từ mã và tài liệu hiện có để Nhật (chủ chương) đọc, sửa và nhận. Người kiểm theo kế hoạch: Hoàng và Việt. Chưa ai duyệt. Mọi tuyên bố về hành vi dựa trên `secure_share/keys.py`, `secure_share/trust_store.py`, `docs/key_spec.md` và test hiện có; kết quả test là kết quả ở mức module, không phải nghiệm thu các ca I01–I10 và L01–L03.

## 2.1. Vấn đề

Mã hóa công khai tự nó không cho biết public key thuộc về ai: ai cũng có thể tạo gói mới bằng public key của người nhận, và ai cũng có thể đưa cho bạn một public key mang tên người khác. Nếu người gửi nhận nhầm khóa của Mallory thì bí mật đến tay Mallory dù mọi thuật toán đều đúng. Vì vậy cần gắn khóa với con người bằng một bước đối chiếu độc lập, và ghi nhớ kết quả cục bộ.

## 2.2. Thiết kế

**Hai cặp khóa theo vai trò.** Mỗi hồ sơ có một cặp RSA-3072 để mã hóa và một cặp khác để ký (`e = 65537`). Lộ hoặc đổi khóa này không kéo theo vai trò kia. Hồ sơ nào có hai vai trò dùng chung một khóa công khai đều bị từ chối.

**Lưu khóa riêng.** PEM PKCS8 mã hóa bằng mật khẩu (tối thiểu 12 ký tự). Ghi nguyên tử; schema, giới hạn kích thước và số thế hệ khóa (tối đa 10) được kiểm khi đọc. Hồ sơ hỏng không bị tự thay thế hay đặt lại.

**Fingerprint.** SHA-256 của DER SubjectPublicKeyInfo của khóa công khai, hex 64 ký tự, tính một chỗ duy nhất trong `keys.py`. Một liên hệ có hai fingerprint (mã hóa, ký) và phải đối chiếu cả hai theo đúng vai trò.

**Public bundle.** JSON có đúng bốn trường (`version`, `display_name`, `encryption_public_key`, `signing_public_key`), không chứa khóa riêng. Khi nhập, kiểm loại khóa, kích thước 3072 bit, `e = 65537`, và hai khóa phải khác nhau.

**Danh bạ tin cậy.** Mỗi hồ sơ có danh bạ riêng. Liên hệ có ba trạng thái: chưa xác minh, đã xác minh, vô hiệu. Nhập liên hệ luôn bắt đầu ở chưa xác minh; chỉ đối chiếu đúng cả hai fingerprint mới chuyển sang đã xác minh. Gửi tới liên hệ và chấp nhận người gửi chỉ dùng liên hệ đã xác minh. Liên hệ vô hiệu không tự bật lại khi nhập hay xác minh lại.

**Đổi khóa.** Nhập bundle khác khóa cho một liên hệ đã có bị từ chối trừ khi thay thế rõ ràng; thay thế đưa liên hệ về chưa xác minh. Giao diện dùng mã liên hệ mới để giữ pin cũ. Khi có hai liên hệ cùng tên khác khóa, giao diện cảnh báo (trùng tên chỉ là cảnh báo).

**Khóa của mình.** Tạo thêm thế hệ khóa mới mà vẫn giữ các thế hệ cũ, nên khóa mã hóa cũ vẫn mở được gói đã gửi cho nó; gói mới dùng khóa hiện tại. Giải mã tìm khóa theo fingerprint của người nhận trong gói, không thử mọi khóa và không dùng khóa ký thay khóa giải mã.

**Sao lưu, khôi phục.** Bản sao lưu chứa khóa riêng đã mã hóa. Trước khi sao lưu, đổi khóa hoặc khôi phục, mọi khóa riêng còn giữ đều được mở thử bằng mật khẩu. Khôi phục không ghi đè hồ sơ đang có và không khôi phục danh bạ.

## 2.3. Kiểm thử hiện có

| Nội dung | Ca | Test |
|---|---|---|
| Hai cặp khóa khác nhau, PEM mã hóa | I01 | `test_generated_keys_are_distinct_encrypted_rsa3072` |
| Mật khẩu không hợp lệ khi tạo không để lại hồ sơ | I02 | `test_invalid_creation_inputs_do_not_write` |
| Xác minh đúng cả hai fingerprint | I04 | `test_correct_fingerprints_verify_and_make_the_contact_usable` |
| Fingerprint sai không xác minh | I05 | `test_wrong_fingerprint_does_not_verify` |
| Đổi khóa cùng tên phải xác minh lại | I06 | `test_changed_pair_requires_replacement_and_reverification` |
| Sai mật khẩu không làm hỏng hồ sơ | I07 | `test_wrong_password_does_not_change_profile` |
| PEM riêng không đầy đủ bị từ chối | I08 | `test_incomplete_private_pem_is_rejected` |
| Khóa công khai sai tham số bị từ chối | I09 | `test_public_key_boundary_rejects_wrong_parameters_and_private_pem` |
| Sai vai trò, trùng khóa, đảo fingerprint | I10 | `test_wrong_role_and_duplicate_keys_are_rejected`, `test_swapped_role_fingerprints_do_not_verify` |
| Giữ khóa cũ qua khởi động lại | L01 | `test_rotation_preserves_old_keys_across_restart_and_restore` |
| Liên hệ vô hiệu không dùng được | L02, A01 | `test_disabled_contact_cannot_be_verified_or_resolved` |

Test dùng hồ sơ tạm và khóa test. Các ca chưa có test gắn: I03 (mở lại khóa đã lưu), L03 (mất khóa), và các ca cần người chạy độc lập. `python -m tools.case_report` liệt kê trạng thái liên kết hiện tại.

## 2.4. Giới hạn

- **Tin cậy thủ công, không phải PKI.** Đúng hay sai phụ thuộc vào việc người dùng đối chiếu đúng. Xác minh nhầm hoặc bỏ qua có thể gửi bí mật cho Mallory (ca L06).
- **Không có dấu thời gian tin cậy.** Vô hiệu hóa một liên hệ chặn từ thời điểm đó theo chính sách cục bộ; không kết luận gói cũ được ký trước hay sau sự cố (ca L02).
- **Mất khóa hoặc mật khẩu không có cách bỏ qua.** Chỉ phục hồi khi còn bản sao lưu và mật khẩu (ca L03).
- **Đổi khóa không thu hồi** gói cũ và không ngăn người nhận chuyển tiếp bản rõ.
- **Danh bạ cục bộ không tự bảo vệ trước kẻ tấn công có quyền ghi:** sửa tệp liên hệ sang đã xác minh không bị phát hiện bằng kiểm tra schema. Cần quyền truy cập hệ điều hành đúng.
- **Phần khóa dùng thư viện:** sinh khóa RSA, mã hóa PEM và fingerprint DER dùng `cryptography`; chỉ các thuật toán dữ liệu (SHA-256, AES-GCM, OAEP, PSS) là tự cài.
- **Python không bảo đảm xóa bí mật khỏi bộ nhớ** hay phép toán khóa riêng thời gian hằng.

## 2.5. Câu hỏi bảo vệ chương này

1. **Fingerprint giải quyết gì?** Gắn public key với người dự kiến bằng đối chiếu độc lập; tên tự khai hoặc public key trong gói không đủ.
2. **Vì sao hai cặp khóa?** Tách vai trò để lộ hoặc đổi một khóa không ảnh hưởng vai trò còn lại.
3. **Đổi khóa thì gói cũ ra sao?** Vẫn mở được bằng khóa cũ đã giữ; khóa mới không mở được gói cũ.
4. **Mất khóa thì sao?** Không có đường bỏ qua; chỉ còn sao lưu và mật khẩu.
5. **Có phải PKI không?** Không; ghim thủ công, không chứng thư, không thu hồi.
