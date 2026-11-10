# Chương 3. Thiết kế mật mã, định dạng gói và giới hạn

Người viết: Hoàng. Người kiểm: Nhật (mật mã), Tiệp (tích hợp). Chưa có ai duyệt.
Mọi kết quả kiểm thử nêu trong chương là kết quả đã chạy ngày 09/11/2026 trên
máy của Hoàng (Python 3.12, 50 test đạt). Không có số đo hiệu năng chính thức;
benchmark thuộc phần của Quang (T5.7).

## 3.1. Vì sao cần ba cơ chế

Mục tiêu: người có bản sao gói không đọc được nội dung nếu thiếu khóa của người
nhận, và người nhận xác minh được người ký, phát hiện dữ liệu bị sửa.

| Cơ chế | Việc đảm nhận | Việc không đảm nhận |
| --- | --- | --- |
| AES-256-GCM | Mã hóa nội dung tệp; phát hiện sửa ciphertext, nonce hoặc AAD | Không cho biết ai tạo ra gói |
| RSA-3072-OAEP | Bọc khóa AES 32 byte để chỉ khóa riêng đúng người nhận mở được | Không xác thực người gửi, vì ai cũng biết public key của người nhận |
| RSA-3072-PSS | Chữ ký của người gửi trên toàn bộ gói, đối chiếu với khóa đã ghim | Không thay được việc đối chiếu fingerprint |

RSA không mã hóa cả tệp vì RSA chỉ xử lý thông điệp ngắn hơn modulus (tối đa
318 byte với OAEP-SHA-256 và k = 384) và chậm với dữ liệu lớn; hệ lai dùng RSA để
chuyển một khóa ngắn. GCM đã phát hiện sửa nhưng không chống người lạ tạo gói
mới bằng public key của người nhận, nên cần chữ ký PSS.

Mỗi hồ sơ có hai cặp khóa RSA khác nhau, một để mã hóa, một để ký, `e = 65537`.
Lộ hoặc đổi khóa này không kéo theo vai trò kia và tránh dùng một khóa cho hai
mục đích.

## 3.2. Tham số

| Thành phần | Giá trị |
| --- | --- |
| AES | AES-256-GCM, khóa 32 byte mới mỗi gói, nonce 12 byte mới mỗi gói, thẻ 16 byte nối cuối ciphertext |
| OAEP | RSA-3072, SHA-256, MGF1-SHA-256, label rỗng; chỉ bọc khóa AES 32 byte; W dài 384 byte |
| PSS | RSA-3072, SHA-256, MGF1-SHA-256, salt 32 byte; S dài 384 byte |
| Giới hạn | Tệp ≤ 10.485.760 byte; H ≤ 4.096; metadata ≤ 4.096; gói ngoài ≤ 15.728.640 |

## 3.3. Công thức cài đặt

Các thuật toán được cài bằng Python từ công thức, không gọi thư viện mật mã.
`pow(a, e, n)` và `os.urandom` của Python được dùng. Nguồn: FIPS 180-4, FIPS 197,
NIST SP 800-38D, RFC 8017.

**SHA-256.** Hằng số không chép bảng mà tính từ toán:
`H0[i] = ⌊frac(√pᵢ)·2³²⌋` với 8 số nguyên tố đầu và
`K[t] = ⌊frac(∛pₜ)·2³²⌋` với 64 số nguyên tố đầu. Trong số nguyên:
`⌊√p·2³²⌋ = isqrt(p·2⁶⁴)`, `⌊∛p·2³²⌋ = icbrt(p·2⁹⁶)`, lấy 32 bit thấp. Căn bậc ba
nguyên tính bằng lặp Newton `x ← ⌊(2x + ⌊n/x²⌋)/3⌋` từ cận trên.
Lịch thông điệp `W[t] = σ₁(W[t−2]) + W[t−7] + σ₀(W[t−15]) + W[t−16] (mod 2³²)`.

**AES-256.** Trường GF(2⁸) với đa thức `x⁸ + x⁴ + x³ + x + 1`. S-box được sinh:
`S(a) = b ⊕ rotl(b,1) ⊕ rotl(b,2) ⊕ rotl(b,3) ⊕ rotl(b,4) ⊕ 0x63` với
`b = a⁻¹ = a²⁵⁴` trong GF(2⁸) và `0⁻¹ := 0`. Khóa mở rộng 60 từ (`Nk = 8`,
`Nr = 14`); mỗi vòng gồm SubBytes, ShiftRows, MixColumns, AddRoundKey (vòng cuối
bỏ MixColumns).

**GCM.** `H = E_K(0¹²⁸)`; `J₀ = IV ‖ 0³¹ ‖ 1` với IV 96 bit; `Cᵢ = Pᵢ ⊕ E_K(inc₃₂ⁱ(J₀))`
với `i ≥ 1`. `GHASH` nhân trong GF(2¹²⁸) với đa thức `x¹²⁸ + x⁷ + x² + x + 1`
theo thứ tự bit của GCM: `Xᵢ = (Xᵢ₋₁ ⊕ Blockᵢ)·H` trên `A ‖ C ‖ [|A|]₆₄ ‖ [|C|]₆₄`
(độ dài tính bằng bit). Thẻ `T = E_K(J₀) ⊕ GHASH`. Giải mã tính lại `T`, so sánh
bằng cộng dồn XOR rồi mới giải mã.

**RSA.** Khóa: `n = p·q`, `λ = lcm(p−1, q−1)`, `d = e⁻¹ mod λ` bằng Euclid mở rộng
(`g = a·x + b·y`). Số nguyên tố sinh bằng Miller-Rabin: viết `n−1 = 2ˢ·d` (d lẻ),
`n` qua vòng với cơ sở `a` nếu `aᵈ ≡ 1` hoặc `a^(2ʳ·d) ≡ −1 (mod n)` với một
`r < s`; dùng 40 vòng với cơ sở ngẫu nhiên sau khi chia thử số nguyên tố nhỏ.

**OAEP** (k = 384, hLen = 32): `DB = SHA256("") ‖ 0…0 ‖ 0x01 ‖ M`,
`maskedDB = DB ⊕ MGF1(seed)`, `maskedSeed = seed ⊕ MGF1(maskedDB)`,
`EM = 0x00 ‖ maskedSeed ‖ maskedDB`, `c = EM^e mod n`. MGF1:
`MGF1(seed, L) = (H(seed‖0₄) ‖ H(seed‖1₄) ‖ …)[0:L]`.

**PSS** (emBits = 3071, emLen = 384, sLen = 32): `M′ = 0⁸ ‖ SHA256(M) ‖ salt`,
`H = SHA256(M′)`, `DB = 0…0 ‖ 0x01 ‖ salt`, `maskedDB = DB ⊕ MGF1(H)` với bit cao
đầu tiên xóa về 0, `EM = maskedDB ‖ H ‖ 0xBC`, `S = EM^d mod n`. Dữ liệu ký là M
nguyên, băm đúng một lần bên trong PSS.

## 3.4. Định dạng gói .sfile

Gói là JSON UTF-8 ngoài với đúng 5 trường chuỗi Base64: `header_b64`,
`wrapped_key_b64`, `nonce_b64`, `ciphertext_b64`, `signature_b64`. Ký hiệu H
(header), W (khóa đã bọc), N (nonce), C (ciphertext cộng thẻ), S (chữ ký).

```text
frame(X) = u32be(len(X)) ‖ X
AAD      = "SFILE1-AAD"  ‖ frame(H) ‖ frame(W)
M        = "SFILE1-SIGN" ‖ frame(H) ‖ frame(W) ‖ frame(N) ‖ frame(C)
S        = RSA-PSS(M)
payload  = u32be(meta_len) ‖ metadata_json_utf8 ‖ raw_file
```

Đóng khung bằng độ dài tránh nhập nhằng khi nối: `build_aad(b"ab", b"c")` khác
`build_aad(b"a", b"bc")` (có test). Header H giữ nguyên byte thô khi nhận; đổi khoảng
trắng trong H làm đổi chữ ký. Đổi thụt dòng hoặc thứ tự thuộc tính của JSON ngoài
mà năm chuỗi sau giải mã không đổi thì gói vẫn hợp lệ, đó là đúng thiết kế (ca R02),
không phải lỗi. Tên tệp gốc nằm trong payload đã mã hóa, không đặt làm tên gói.

Parser đọc nghiêm ngặt: đúng 5 trường, từ chối trường thiếu/lạ/trùng/sai kiểu,
Base64 phải chuẩn (kể cả bit thừa), không NaN/Infinity, không dữ liệu dư, gốc JSON
phải là object, `version` là số nguyên đúng 1 (không nhận `true`). Giới hạn và mã
lỗi chi tiết ở `docs/package_format.md`.

## 3.5. Thứ tự kiểm tra khi nhận

```text
Giới hạn/parse → tin người ký → PSS → tìm khóa nhận → mở khóa riêng
→ OAEP → kiểm tra khóa AES 32 byte → GCM → payload → chọn/lưu tệp → lịch sử
```

Thông tin trong H trước PSS chỉ dùng để chọn khóa và kiểm schema, chưa phải dữ
liệu đã xác thực. Sửa C, W, N hoặc H thông thường dừng ở PSS. Để kiểm tra các tầng
sâu hơn (OAEP, độ dài khóa AES, GCM, AAD, payload), bộ test tạo gói lỗi rồi ký lại
bằng khóa ký **của test**. Đó là fixture của người kiểm thử, không phải khả năng giả
chữ ký của Quang.

## 3.6. Kiểm thử đã chạy

Kết quả ngày 09/11/2026: `python -m pytest -q` cho 50 test đạt (119 subtest);
`python -m unittest discover -s tests -t .` cho 50 test đạt. Gồm:

- Vector chuẩn: SHA-256 của chuỗi rỗng, `"abc"` và 56 byte `a`; AES-256 một khối theo
  FIPS-197 C.3; GCM với khóa 0, nonce 0 cho dữ liệu rỗng và 16 byte 0.
- Hằng số SHA-256 (72 giá trị) và S-box AES (256 giá trị) do code sinh bằng toán khớp bảng
  chuẩn; S-box là hoán vị của 0–255.
- Miller-Rabin loại số Carmichael 561 và 41041; sinh khóa 512 bit round-trip.
- GCM từ chối sai khóa, nonce, AAD và byte ciphertext; OAEP từ chối khóa bọc sai độ
  dài, bytes sai, và khóa AES 0/16/31/33 byte; PSS từ chối salt dài 0/31/33.
- Luồng gửi/nhận qua `envelope` và `crypto_ops` với hai cặp khóa khác nhau cho tệp
  0, 256 và 5.000 byte và nội dung ngẫu nhiên; sửa từng phần H/W/N/C/S làm chữ ký sai.
- Giới hạn biên: payload 0 và 10 MiB (+1 byte bị từ chối); header 4.096/4.097 byte;
  gói ngoài 15.728.640/+1 byte; W, S ≠ 384, N ≠ 12, C ngoài 16–10.489.876.

Các test này là unit và tích hợp trong bộ nhớ. Chúng **không** thay nghiệm thu 60 ID
do runner thực hiện và không thay kiểm thử service, giao diện hay lưu tệp. Các ID có
liên hệ trực tiếp ở mức module: S01, S02, S04, S08, R02, A02, A03, A05, A07–A12,
P01–P07. Chưa ca nào trong 60 ID được ghi là đạt.

## 3.7. Giới hạn

Giới hạn của thiết kế: người nhận chuyển tiếp được bản rõ; gửi nhầm một liên hệ hợp lệ
vẫn mở được; xác minh fingerprint sai có thể gửi bí mật cho kẻ khác; lộ khóa riêng làm lộ
gói cũ (không có forward secrecy); không có dấu thời gian tin cậy; gói lộ dung lượng
gần đúng và hai fingerprint. Không tuyên bố bảo mật 256 bit cho cả hệ thống.

Giới hạn của bản tự cài: Python không bảo đảm thời gian hằng nên khóa riêng và bảng AES có
thể rò rỉ qua đo thời gian cục bộ; RSA dùng `pow` không CRT, không blinding; `check_key`
không chứng minh `n` là tích hai nguyên tố; mã chưa kiểm toán; AES-GCM chậm hơn nhiều so với
thư viện đã tối ưu. Mã phục vụ nghiên cứu, không dùng cho dữ liệu thật. Chi tiết ở
`docs/threat_model.md`.

## 3.8. Câu hỏi bảo vệ chương này

1. **Vì sao RSA chỉ bọc khóa?** RSA-OAEP chỉ mã hóa được thông điệp ngắn hơn modulus và chậm
   với tệp lớn.
2. **Vì sao vẫn cần chữ ký khi đã có GCM?** Ai cũng biết public key người nhận nên có thể tạo
   gói mới tự xưng người gửi; chữ ký gắn gói với khóa ký đã ghim.
3. **Vì sao sửa ciphertext dừng ở PSS?** PSS được kiểm trước GCM trong thứ tự nhận; muốn tới
   GCM phải dùng fixture ký lại bằng khóa test.
4. **Vì sao hai cặp khóa?** Mỗi vai trò dùng một khóa riêng để lộ hoặc đổi khóa này không ảnh
   hưởng vai trò kia.
5. **Mất khóa thì sao?** Không có đường bỏ qua; chỉ phục hồi khi còn bản sao khóa mã hóa
   và passphrase.
6. **Người nhận chuyển tiếp được không?** Được. Bản mẫu không thu hồi, không DRM.
