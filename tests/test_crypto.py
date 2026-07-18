import pytest

from antirev import crypto


@pytest.mark.parametrize("endian", ["little", "big"])
def test_tea_roundtrip(endian):
    pt = b"NSSCTF{tea_test}"  # 16 字节
    key = bytes(range(16))
    ct = crypto.tea_encrypt_bytes(pt, key, endian=endian)
    assert crypto.tea_decrypt_bytes(ct, key, endian=endian) == pt
    assert ct != pt


@pytest.mark.parametrize("endian", ["little", "big"])
def test_xtea_roundtrip(endian):
    pt = b"flag{xtea_roundtrip_ok!!}"  # 25 → 补齐
    key = b"0123456789abcdef"
    ct = crypto.xtea_encrypt_bytes(pt, key, endian=endian)
    dec = crypto.xtea_decrypt_bytes(ct, key, endian=endian)
    assert dec[:len(pt)] == pt


@pytest.mark.parametrize("rounds", [32, 64])
def test_xtea_rounds(rounds):
    pt = b"12345678"
    key = b"YELLOW SUBMARINE"
    ct = crypto.xtea_encrypt_bytes(pt, key, rounds=rounds)
    assert crypto.xtea_decrypt_bytes(ct, key, rounds=rounds) == pt


def test_xxtea_roundtrip():
    pt = b"NSSCTF{xxtea_variable_len}"
    key = b"secretkey_16byte"
    ct = crypto.xxtea_encrypt_bytes(pt, key)
    dec = crypto.xxtea_decrypt_bytes(ct, key)
    assert dec[:len(pt)] == pt


def test_rc4_known_vector():
    # 经典 RC4 测试向量:key="Key", pt="Plaintext" → BBF316E8D940AF0AD3
    assert crypto.rc4(b"Plaintext", b"Key").hex() == "bbf316e8d940af0ad3"
    # 对称性
    assert crypto.rc4(crypto.rc4(b"hello world", b"k"), b"k") == b"hello world"


def test_xor_bytes():
    assert crypto.xor_bytes(b"AAAA", 0x01) == b"@@@@"  # 'A'^1 = '@'
    assert crypto.xor_bytes(crypto.xor_bytes(b"data", b"key"), b"key") == b"data"


def test_b64_custom_roundtrip():
    alpha = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/"
    data = b"NSSCTF{custom_b64}"
    enc = crypto.b64_custom_encode(data, alpha)
    assert crypto.b64_custom_decode(enc, alpha) == data


def test_aes_ecb_roundtrip():
    key = b"0123456789abcdef"
    pt = b"sixteen byte msg"
    assert crypto.aes_ecb_decrypt(crypto.aes_ecb_encrypt(pt, key), key) == pt
