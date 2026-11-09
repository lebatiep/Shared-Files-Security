"""SHA-256 và các hàm hỗ trợ, cài đặt thuần Python."""

_MASK = 0xFFFFFFFF
_INITIAL = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)
_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


def _rotate_right(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & _MASK


def sha256(data: bytes) -> bytes:
    """Trả về giá trị băm SHA-256 gồm 32 byte."""
    if not isinstance(data, bytes):
        raise TypeError("data phải là bytes")
    bit_length = len(data) * 8
    if bit_length >= 1 << 64:
        raise ValueError("Dữ liệu quá dài cho SHA-256")
    padded = data + b"\x80" + b"\x00" * ((55 - len(data)) % 64)
    padded += bit_length.to_bytes(8, "big")
    state = list(_INITIAL)

    for offset in range(0, len(padded), 64):
        block = padded[offset:offset + 64]
        words = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
        for i in range(16, 64):
            x, y = words[i - 15], words[i - 2]
            s0 = _rotate_right(x, 7) ^ _rotate_right(x, 18) ^ (x >> 3)
            s1 = _rotate_right(y, 17) ^ _rotate_right(y, 19) ^ (y >> 10)
            words.append((words[i - 16] + s0 + words[i - 7] + s1) & _MASK)

        a, b, c, d, e, f, g, h = state
        for constant, word in zip(_K, words):
            sigma1 = _rotate_right(e, 6) ^ _rotate_right(e, 11) ^ _rotate_right(e, 25)
            choose = (e & f) ^ (~e & g)
            temp1 = (h + sigma1 + choose + constant + word) & _MASK
            sigma0 = _rotate_right(a, 2) ^ _rotate_right(a, 13) ^ _rotate_right(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (sigma0 + majority) & _MASK
            h, g, f, e, d, c, b, a = (
                g, f, e, (d + temp1) & _MASK, c, b, a, (temp1 + temp2) & _MASK
            )
        state = [(old + new) & _MASK for old, new in zip(state, (a, b, c, d, e, f, g, h))]

    return b"".join(word.to_bytes(4, "big") for word in state)


def mgf1(seed: bytes, length: int) -> bytes:
    """Sinh mặt nạ MGF1 dùng SHA-256 và bộ đếm 4 byte."""
    if not isinstance(seed, bytes):
        raise TypeError("seed phải là bytes")
    if not isinstance(length, int) or isinstance(length, bool):
        raise TypeError("length phải là số nguyên")
    if not 0 <= length <= (1 << 32) * 32:
        raise ValueError("length phải nằm trong [0, 2**32 * 32]")
    mask = bytearray()
    for counter in range((length + 31) // 32):
        mask.extend(sha256(seed + counter.to_bytes(4, "big")))
    return bytes(mask[:length])


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR hai chuỗi byte có cùng độ dài."""
    if not isinstance(left, bytes) or not isinstance(right, bytes):
        raise TypeError("Hai toán hạng phải là bytes")
    if len(left) != len(right):
        raise ValueError("Hai toán hạng phải có cùng độ dài")
    return bytes(a ^ b for a, b in zip(left, right))
