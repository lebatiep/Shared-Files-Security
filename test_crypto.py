"""Chạy: python -m unittest -v. Khóa dưới đây chỉ là fixture công khai."""

import unittest
from os import urandom

import aes
from rsa import unwrap, wrap
from pss import sign, verify
from sha256 import sha256, mgf1

N = 4064694517739837841203029126742023582451564788852971553938893785671296814822731825985542856401044511540581367533424505351953936799626011750514977162543116109851628852119093113972340443172830945137822375158584832804851510659476210085108012685062867976857259706063036799736491991674922576555380947146515228692747488574748250794802184857185834090383475963984183612356903980813948271760045918747364857235631139844671307144004601153508400773372362748823352048014322300194736522952186088245617319944442338947931134246160400505006212232616394340981962821202910452582676209550924190320951913879993983309356880797848052190888609923522440697577408779667118644463085301343635269517876230238999290313780529422510476841946728378356252357140925071811408899686719564684147466970497936156902869012924495542430376637627011925382154308127779339211094157380557537112201154219458731005546146624943961886268437351613694494729040313068316672169523
D = 1713681460433199406005161912910958429512000257845217671256063059721848217677945156444352684648199648688863290593592715490900762176206822370151274493639433749992453591077965153815596573158473922053658256203660195352464251724623608385439933846447496431550948537595171251279722019255900457016852362179101713938614210035012001519535251364824041210832669066677830619363526487966794295174724945571952708971254500655785137434463267042617359164573676990575760696441090257465139694500044199151397501691515899256960354692696746234453607755661696548189540852165521428552285122846800822887431498031928036052753099102397279858318375226455222054408225656500262772581306884541636592070837417228215271626939459196761594354037869686484626484991094485939724902729670979182088195710397472968959308154959961141905032529925149153397104315754199031188621969216354957794751990170596701477390144041405197913972231646881866159594671784462366172159853


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
        signature = sign(message, N, D)
        self.assertEqual(len(signature), 384)
        self.assertTrue(verify(message, signature, N))
        self.assertNotEqual(sign(message, N, D), signature)
        self.assertFalse(verify(message + b"!", signature, N))
        for bad in (b"", bytes(384), N.to_bytes(384, "big"), signature[:-1]):
            self.assertFalse(verify(message, bad, N))

    def test_send_receive(self):
        payload, aad = "Nội dung tệp của Quang".encode(), b"test header"
        key, nonce = urandom(32), urandom(12)
        wrapped = wrap(key, N)
        encrypted = aes.seal_payload(payload, key, nonce, aad)
        signed_bytes = aad + wrapped + nonce + encrypted
        signature = sign(signed_bytes, N, D)
        self.assertTrue(verify(signed_bytes, signature, N))
        recovered_key = unwrap(wrapped, N, D)
        self.assertEqual(aes.open_payload(encrypted, recovered_key, nonce, aad), payload)

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


if __name__ == "__main__":
    unittest.main()
