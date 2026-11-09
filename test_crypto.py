"""Chạy: python -m unittest -v. Khóa dưới đây chỉ là fixture công khai."""

import base64
import json
import unittest

import aes
from rsa import unwrap, wrap
from pss import sign, verify
from sha256 import sha256, mgf1, xor_bytes
from payload import pack_payload, unpack_payload
from envelope import build_aad, build_signature_input

N = 4064694517739837841203029126742023582451564788852971553938893785671296814822731825985542856401044511540581367533424505351953936799626011750514977162543116109851628852119093113972340443172830945137822375158584832804851510659476210085108012685062867976857259706063036799736491991674922576555380947146515228692747488574748250794802184857185834090383475963984183612356903980813948271760045918747364857235631139844671307144004601153508400773372362748823352048014322300194736522952186088245617319944442338947931134246160400505006212232616394340981962821202910452582676209550924190320951913879993983309356880797848052190888609923522440697577408779667118644463085301343635269517876230238999290313780529422510476841946728378356252357140925071811408899686719564684147466970497936156902869012924495542430376637627011925382154308127779339211094157380557537112201154219458731005546146624943961886268437351613694494729040313068316672169523
D = 1713681460433199406005161912910958429512000257845217671256063059721848217677945156444352684648199648688863290593592715490900762176206822370151274493639433749992453591077965153815596573158473922053658256203660195352464251724623608385439933846447496431550948537595171251279722019255900457016852362179101713938614210035012001519535251364824041210832669066677830619363526487966794295174724945571952708971254500655785137434463267042617359164573676990575760696441090257465139694500044199151397501691515899256960354692696746234453607755661696548189540852165521428552285122846800822887431498031928036052753099102397279858318375226455222054408225656500262772581306884541636592070837417228215271626939459196761594354037869686484626484991094485939724902729670979182088195710397472968959308154959961141905032529925149153397104315754199031188621969216354957794751990170596701477390144041405197913972231646881866159594671784462366172159853


# C?p kh?a k? test ri?ng; ??y l? fixture c?ng khai, kh?ng d?ng cho d? li?u th?t.
SIGN_N = 3901652971138816906657581006483283563435736277701684678930469750451451792671241529948317427079952168142930198586090549149802001777715540584993217471869480836926284668110407693358199826013848747115259369423179375911216280061293300559855768293533360003278628755031289106559021224663818498913048720540027719367564024799811481280505435296187023340625439867865088845076991040978969628810197282210522171255005997847976340413632518192058538805268861908969001927623824549654726433074710953419146079326044581405715618289451074022165779354156042847512766152875174967622142577271512202883837619344513500422369804667633324714192419156142883447986296481149718387377712254501772304922048669123987746473005695100377378093501659664618097833864081845148229479040417953570747590158507725139657212853992555402000116904078769844982440574083596223709234542903380694924741106935633109976418216032540705900842175790609366045394995277118604291035293
SIGN_D = 506452260943862481116560746176256058015286151554209554353441661459793710426999278198122226409038453001997454863235611969076485483360942730923559226592515273505529756803259811211959746706437757170903633911881638629731554610089294716918580662421049079876883208249556379289524902852054625177431152869890532197992998748371092226578264767454460954250280253229905409235545764768117164842582789565663855697794162437901257730728776603442970987631753181555446532467093022414706099275144832985050258565846521895657687843686422783212043406269065831479484301620922585797832502259868578866626261735356022893448046400529605184383419475651474632578578767836273690737611377576484241242542020158293426495369699647505860090508085139073861099358480679337309383930167344402177847436518049461644964258834272370716496979887047032477829475811555717876661720074004545204131337152947274981761751568297000992410720515641767942684331753525072123067873


class CryptoTests(unittest.TestCase):
    def test_sha256_vectors(self):
        self.assertEqual(sha256(b"").hex(),
                         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(sha256(b"abc").hex(),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(sha256(b"a" * 56).hex(),
                         "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a")
        self.assertEqual(mgf1(b"seed", 33),
                         sha256(b"seed\0\0\0\0") + sha256(b"seed\0\0\0\1")[:1])
        with self.assertRaises(ValueError):
            mgf1(b"seed", -1)

    def test_aes_standard_vectors(self):
        aes._self_test()

    def test_gcm_rejects_changes(self):
        key, nonce, aad = bytes(range(32)), bytes(range(12)), b"header"
        for size in (0, 1, 15, 16, 17, 128):
            with self.subTest(size=size):
                message = bytes(size)
                encrypted = aes.seal_payload(message, key, nonce, aad)
                self.assertEqual(aes.open_payload(encrypted, key, nonce, aad), message)
                for wrong_key, wrong_nonce, wrong_aad, wrong_data in (
                    (bytes(32), nonce, aad, encrypted),
                    (key, bytes(12), aad, encrypted),
                    (key, nonce, b"changed", encrypted),
                    (key, nonce, aad, bytes([encrypted[0] ^ 1]) + encrypted[1:]),
                ):
                    with self.assertRaises(ValueError):
                        aes.open_payload(wrong_data, wrong_key, wrong_nonce, wrong_aad)

    def test_oaep(self):
        key = bytes(range(32))
        encrypted = wrap(key, N)
        self.assertEqual(len(encrypted), 384)
        self.assertEqual(unwrap(encrypted, N, D), key)
        self.assertNotEqual(wrap(key, N), encrypted)
        for bad in (b"", bytes(384), N.to_bytes(384, "big"), encrypted[:-1]):
            with self.assertRaises(ValueError):
                unwrap(bad, N, D)
        with self.assertRaises(ValueError):
            wrap(bytes(31), N)

    def test_pss(self):
        message = b"SFILE1-SIGN: test bytes"
        signature = sign(message, SIGN_N, SIGN_D)
        self.assertEqual(len(signature), 384)
        self.assertTrue(verify(message, signature, SIGN_N))
        self.assertNotEqual(sign(message, SIGN_N, SIGN_D), signature)
        self.assertFalse(verify(message + b"!", signature, SIGN_N))
        self.assertFalse(verify(message, signature, N))
        for bad in (b"", bytes(384), SIGN_N.to_bytes(384, "big"), signature[:-1]):
            self.assertFalse(verify(message, bad, SIGN_N))

    def test_send_receive(self):
        raw_file = bytes(range(256))
        payload = pack_payload("tệp.bin", raw_file)
        header = b'{"test":"raw header bytes"}'
        key, nonce = aes.generate_key_nonce()
        wrapped = wrap(key, N)
        aad = build_aad(header, wrapped)
        encrypted = aes.seal_payload(payload, key, nonce, aad)
        signed_bytes = build_signature_input(header, wrapped, nonce, encrypted)
        signature = sign(signed_bytes, SIGN_N, SIGN_D)
        self.assertTrue(verify(signed_bytes, signature, SIGN_N))
        recovered_key = unwrap(wrapped, N, D)
        recovered = aes.open_payload(encrypted, recovered_key, nonce, aad)
        self.assertEqual(unpack_payload(recovered), ("tệp.bin", raw_file))

    def test_key_nonce_generation(self):
        first, second = aes.generate_key_nonce(), aes.generate_key_nonce()
        self.assertEqual(tuple(map(len, first)), (32, 12))
        self.assertNotEqual(first[0], second[0])
        self.assertNotEqual(first[1], second[1])

    def test_same_file_twice(self):
        payload = pack_payload("test.bin", bytes(range(32)))
        results = []
        for _ in range(2):
            key, nonce = aes.generate_key_nonce()
            wrapped = wrap(key, N)
            aad = build_aad(b"header", wrapped)
            encrypted = aes.seal_payload(payload, key, nonce, aad)
            self.assertEqual(aes.open_payload(encrypted, unwrap(wrapped, N, D), nonce, aad), payload)
            results.append((wrapped, nonce, encrypted))
        for first, second in zip(*results):
            self.assertNotEqual(first, second)

    def test_signature_protects_each_field(self):
        fields = (b"header", bytes(384), bytes(12), bytes(16))
        signature = sign(build_signature_input(*fields), SIGN_N, SIGN_D)
        for index in range(4):
            with self.subTest(field=index):
                changed = list(fields)
                changed[index] = bytes([changed[index][0] ^ 1]) + changed[index][1:]
                self.assertFalse(verify(build_signature_input(*changed), signature, SIGN_N))

    def test_json_wrapper_does_not_change_signature(self):
        # Chỉ kiểm tra byte ký độc lập vỏ JSON; không thay thế parser T3.5.
        fields = (b'{ "test": 1 }', bytes(384), bytes(12), bytes(16))
        signature = sign(build_signature_input(*fields), SIGN_N, SIGN_D)
        names = ("header_b64", "wrapped_key_b64", "nonce_b64", "ciphertext_b64", "signature_b64")
        wrapper = dict(zip(names, (base64.b64encode(x).decode("ascii") for x in (*fields, signature))))
        compact = json.dumps(wrapper, separators=(",", ":"))
        pretty = json.dumps(dict(reversed(list(wrapper.items()))), indent=2)
        self.assertNotEqual(compact, pretty)
        for encoded in (compact, pretty):
            loaded = json.loads(encoded)
            h, w, n, c, s = (base64.b64decode(loaded[name], validate=True) for name in names)
            self.assertEqual(h, fields[0])
            self.assertTrue(verify(build_signature_input(h, w, n, c), s, SIGN_N))
        self.assertFalse(verify(build_signature_input(b'{"test":1}', *fields[1:]), signature, SIGN_N))

    def test_oaep_rejects_wrong_key_length_after_decode(self):
        # Fixture OAEP hợp lệ nhưng chứa khóa AES sai độ dài, không phải attacker giả chữ ký.
        for length in (0, 16, 31, 33):
            with self.subTest(length=length):
                secret, seed = bytes(length), bytes(32)
                data = sha256(b"") + bytes(384 - length - 66) + b"\x01" + secret
                masked_data = xor_bytes(data, mgf1(seed, len(data)))
                encoded = b"\0" + xor_bytes(seed, mgf1(masked_data, 32)) + masked_data
                wrapped = pow(int.from_bytes(encoded, "big"), 65537, N).to_bytes(384, "big")
                with self.assertRaises(ValueError):
                    unwrap(wrapped, N, D)

    def test_wrong_recipient_key_cannot_unwrap(self):
        with self.assertRaises(ValueError):
            unwrap(wrap(bytes(32), N), SIGN_N, SIGN_D)

    def test_signed_bad_data_reaches_expected_layer(self):
        # Người kiểm thử ký fixture bằng khóa test; không mô phỏng khả năng giả chữ ký.
        header = b"test header"
        key, nonce = aes.generate_key_nonce()
        wrapped = wrap(key, N)
        payload = pack_payload("test.bin", b"file bytes")
        aad = build_aad(header, wrapped)
        encrypted = aes.seal_payload(payload, key, nonce, aad)

        bad_wrapped = bytes(384)
        message = build_signature_input(header, bad_wrapped, nonce, encrypted)
        self.assertTrue(verify(message, sign(message, SIGN_N, SIGN_D), SIGN_N))
        with self.assertRaises(ValueError):
            unwrap(bad_wrapped, N, D)

        for bad_encrypted in (
            encrypted[:-1] + bytes([encrypted[-1] ^ 1]),
            aes.seal_payload(payload, key, nonce, b"wrong AAD"),
        ):
            message = build_signature_input(header, wrapped, nonce, bad_encrypted)
            self.assertTrue(verify(message, sign(message, SIGN_N, SIGN_D), SIGN_N))
            recovered_key = unwrap(wrapped, N, D)
            with self.assertRaises(ValueError):
                aes.open_payload(bad_encrypted, recovered_key, nonce, aad)

        for bad_payload in (b"\0\0\x10\x01{}", b'\0\0\0\x0f{"filename":42}'):
            bad_encrypted = aes.seal_payload(bad_payload, key, nonce, aad)
            message = build_signature_input(header, wrapped, nonce, bad_encrypted)
            self.assertTrue(verify(message, sign(message, SIGN_N, SIGN_D), SIGN_N))
            recovered = aes.open_payload(bad_encrypted, unwrap(wrapped, N, D), nonce, aad)
            with self.assertRaises(ValueError):
                unpack_payload(recovered)

    def test_pss_rejects_wrong_salt_length(self):
        for salt_length in (0, 31, 33):
            message, salt = b"test", bytes(salt_length)
            digest = sha256(bytes(8) + sha256(message) + salt)
            data = bytes(350 - salt_length) + b"\x01" + salt
            masked = bytearray(xor_bytes(data, mgf1(digest, 351)))
            masked[0] &= 0x7f
            encoded = bytes(masked) + digest + b"\xbc"
            signature = pow(int.from_bytes(encoded, "big"), SIGN_D, SIGN_N).to_bytes(384, "big")
            self.assertFalse(verify(message, signature, SIGN_N))

    def test_invalid_parameters(self):
        with self.assertRaises(ValueError):
            wrap(bytes(32), N, 3)
        with self.assertRaises(ValueError):
            sign(b"test", 17, 3)
        with self.assertRaises(ValueError):
            aes.seal_payload(b"", bytes(31), bytes(12))
        with self.assertRaises(ValueError):
            aes.seal_payload(b"", bytes(32), bytes(11))
        with self.assertRaises(ValueError):
            aes.open_payload(bytes(15), bytes(32), bytes(12))
        with self.assertRaises(TypeError):
            sign("not bytes", SIGN_N, SIGN_D)
        with self.assertRaises(TypeError):
            verify("not bytes", bytes(384), SIGN_N)


if __name__ == "__main__":
    unittest.main()
