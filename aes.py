"""AES-256-GCM thuần Python, dùng nonce 12 byte và thẻ xác thực 16 byte.

Không tái sử dụng nonce với cùng khóa. Python không bảo đảm thời gian thực thi
hằng định; mã này phục vụ học tập, không thay thế thư viện đã được kiểm toán.
"""


_SBOX = bytes.fromhex(
    '637c777bf26b6fc53001672bfed7ab76'
    'ca82c97dfa5947f0add4a2af9ca472c0'
    'b7fd9326363ff7cc34a5e5f171d83115'
    '04c723c31896059a071280e2eb27b275'
    '09832c1a1b6e5aa0523bd6b329e32f84'
    '53d100ed20fcb15b6acbbe394a4c58cf'
    'd0efaafb434d338545f9027f503c9fa8'
    '51a3408f929d38f5bcb6da2110fff3d2'
    'cd0c13ec5f974417c4a77e3d645d1973'
    '60814fdc222a908846eeb814de5e0bdb'
    'e0323a0a4906245cc2d3ac629195e479'
    'e7c8376d8dd54ea96c56f4ea657aae08'
    'ba78252e1ca6b4c6e8dd741f4bbd8b8a'
    '703eb5664803f60e613557b986c11d9e'
    'e1f8981169d98e949b1e87e9ce5528df'
    '8ca1890dbfe6426841992d0fb054bb16'
)


def _xtime(value):
    return ((value << 1) ^ (0x11B if value & 0x80 else 0)) & 255


def _expand_key(key):
    words = [list(key[i:i + 4]) for i in range(0, 32, 4)]
    rcon = 1
    for i in range(8, 60):
        temp = words[i - 1][:]
        if i % 8 == 0:
            temp = [_SBOX[x] for x in temp[1:] + temp[:1]]
            temp[0] ^= rcon
            rcon = _xtime(rcon)
        elif i % 8 == 4:
            temp = [_SBOX[x] for x in temp]
        words.append([a ^ b for a, b in zip(words[i - 8], temp)])
    return [sum(words[i:i + 4], []) for i in range(0, 60, 4)]


def _encrypt_block(block, round_keys):
    state = [a ^ b for a, b in zip(block, round_keys[0])]
    for round_number in range(1, 15):
        state = [_SBOX[x] for x in state]
        state = [state[4 * ((column + row) % 4) + row]
                 for column in range(4) for row in range(4)]
        if round_number != 14:
            for offset in range(0, 16, 4):
                a, b, c, d = state[offset:offset + 4]
                total = a ^ b ^ c ^ d
                state[offset:offset + 4] = [
                    a ^ total ^ _xtime(a ^ b), b ^ total ^ _xtime(b ^ c),
                    c ^ total ^ _xtime(c ^ d), d ^ total ^ _xtime(d ^ a)]
        state = [a ^ b for a, b in zip(state, round_keys[round_number])]
    return bytes(state)


def encrypt_block(block: bytes, key: bytes) -> bytes:
    """Mã hóa một khối 16 byte bằng khóa AES-256."""
    if not isinstance(block, bytes) or len(block) != 16:
        raise ValueError('Khối AES phải là bytes dài 16 byte.')
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError('Khóa AES-256 phải là bytes dài 32 byte.')
    return _encrypt_block(block, _expand_key(key))


def _multiply(x, y):
    result = 0
    for bit in range(127, -1, -1):
        if (x >> bit) & 1:
            result ^= y
        y = (y >> 1) ^ (0xE1000000000000000000000000000000 if y & 1 else 0)
    return result


def _ghash(h, aad, ciphertext):
    value = 0
    for data in (aad, ciphertext):
        for offset in range(0, len(data), 16):
            block = data[offset:offset + 16].ljust(16, b'\0')
            value = _multiply(value ^ int.from_bytes(block, 'big'), h)
    lengths = (len(aad) * 8 << 64) | (len(ciphertext) * 8)
    return _multiply(value ^ lengths, h).to_bytes(16, 'big')


def _validate(data, key, nonce, aad):
    if not isinstance(data, bytes) or not isinstance(aad, bytes):
        raise TypeError('Dữ liệu và AAD phải là bytes.')
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError('Khóa AES-256 phải là bytes dài 32 byte.')
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise ValueError('Nonce GCM phải là bytes dài 12 byte.')
    if len(aad) > (1 << 61) - 1:
        raise ValueError('AAD vượt giới hạn GCM.')


def _check_length(length):
    if length > (1 << 36) - 32:
        raise ValueError('Dữ liệu vượt giới hạn bộ đếm GCM.')


def _ctr(data, nonce, round_keys):
    output = bytearray()
    for offset in range(0, len(data), 16):
        counter = offset // 16 + 2
        stream = _encrypt_block(nonce + counter.to_bytes(4, 'big'), round_keys)
        output.extend(a ^ b for a, b in zip(data[offset:offset + 16], stream))
    return bytes(output)


def _tag(ciphertext, nonce, aad, round_keys):
    h = int.from_bytes(_encrypt_block(bytes(16), round_keys), 'big')
    mask = _encrypt_block(nonce + b'\0\0\0\1', round_keys)
    return bytes(a ^ b for a, b in zip(mask, _ghash(h, aad, ciphertext)))


def seal_payload(payload: bytes, key: bytes, nonce: bytes, aad: bytes = b'') -> bytes:
    """Trả về bản mã nối với thẻ xác thực 16 byte."""
    _validate(payload, key, nonce, aad)
    _check_length(len(payload))
    round_keys = _expand_key(key)
    ciphertext = _ctr(payload, nonce, round_keys)
    return ciphertext + _tag(ciphertext, nonce, aad, round_keys)


def open_payload(ciphertext: bytes, key: bytes, nonce: bytes, aad: bytes = b'') -> bytes:
    """Xác thực toàn bộ bản mã trước khi giải mã; thẻ sai gây ValueError."""
    _validate(ciphertext, key, nonce, aad)
    if len(ciphertext) < 16:
        raise ValueError('Bản mã thiếu thẻ xác thực GCM.')
    _check_length(len(ciphertext) - 16)
    body, supplied_tag = ciphertext[:-16], ciphertext[-16:]
    round_keys = _expand_key(key)
    expected_tag = _tag(body, nonce, aad, round_keys)
    difference = 0
    for actual, expected in zip(supplied_tag, expected_tag):
        difference |= actual ^ expected
    if difference:
        raise ValueError('Thẻ xác thực GCM không hợp lệ.')
    return _ctr(body, nonce, round_keys)


def _self_test():
    """Kiểm tra vector AES-256 và GCM chuẩn cùng phát hiện sửa đổi."""
    key = bytes(range(32))
    block = bytes.fromhex('00112233445566778899aabbccddeeff')
    assert encrypt_block(block, key).hex() == '8ea2b7ca516745bfeafc49904b496089'
    key, nonce = bytes(32), bytes(12)
    assert seal_payload(b'', key, nonce).hex() == '530f8afbc74536b9a963b4f1c4cb738b'
    sealed = seal_payload(bytes(16), key, nonce)
    assert sealed.hex() == ('cea7403d4d606b6e074ec5d3baf39d18'
                            'd0d1c8a799996bf0265b98b5d48ab919')
    assert open_payload(sealed, key, nonce) == bytes(16)
    try:
        open_payload(sealed[:-1] + bytes([sealed[-1] ^ 1]), key, nonce)
    except ValueError:
        pass
    else:
        raise AssertionError('Không phát hiện thẻ bị sửa đổi.')


if __name__ == '__main__':
    _self_test()
    print('AES-256-GCM: OK')
