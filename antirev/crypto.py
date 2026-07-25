"""CTF 逆向常用密码/编码算法库(§5.2/§8「加密/编码」)。

给模型解题时**直接调用**,不必从伪代码手写密码(35B 手写密码易错在轮数/delta/字节序)。
模型只需:识别算法 + 从二进制提取密文/密钥/轮数,然后 `from antirev.crypto import xtea_decrypt_bytes` 调用。

字节序说明:TEA/XTEA/XXTEA 把字节按 4 字节打包成 u32,`endian` 控制('little' 最常见)。
若解出乱码,**先换 endian 再怀疑算法**——这是头号坑。
"""
from __future__ import annotations
import base64 as _b64
import re
import struct

_MASK = 0xFFFFFFFF
_DELTA = 0x9E3779B9


# ——————————————————— 打包辅助 ———————————————————
def _bytes_to_words(data: bytes, endian="little") -> list:
    if len(data) % 4:
        data = data + b"\x00" * (4 - len(data) % 4)
    fmt = ("<" if endian == "little" else ">") + "I" * (len(data) // 4)
    return list(struct.unpack(fmt, data))


def _words_to_bytes(words, endian="little") -> bytes:
    fmt = ("<" if endian == "little" else ">") + "I" * len(words)
    return struct.pack(fmt, *[w & _MASK for w in words])


def _key_words(key: bytes, endian="little") -> list:
    w = _bytes_to_words(key, endian)
    while len(w) < 4:
        w.append(0)
    return w[:4]


# ——————————————————— TEA ———————————————————
def tea_encrypt_block(v0, v1, k, rounds=32, delta=_DELTA):
    s = 0
    for _ in range(rounds):
        s = (s + delta) & _MASK
        v0 = (v0 + ((((v1 << 4) + k[0]) ^ (v1 + s) ^ ((v1 >> 5) + k[1])))) & _MASK
        v1 = (v1 + ((((v0 << 4) + k[2]) ^ (v0 + s) ^ ((v0 >> 5) + k[3])))) & _MASK
    return v0, v1


def tea_decrypt_block(v0, v1, k, rounds=32, delta=_DELTA):
    s = (delta * rounds) & _MASK
    for _ in range(rounds):
        v1 = (v1 - ((((v0 << 4) + k[2]) ^ (v0 + s) ^ ((v0 >> 5) + k[3])))) & _MASK
        v0 = (v0 - ((((v1 << 4) + k[0]) ^ (v1 + s) ^ ((v1 >> 5) + k[1])))) & _MASK
        s = (s - delta) & _MASK
    return v0, v1


def _tea_bytes(data, key, dec, rounds, delta, endian):
    k = _key_words(key, endian)
    words = _bytes_to_words(data, endian)
    out = []
    fn = tea_decrypt_block if dec else tea_encrypt_block
    for i in range(0, len(words), 2):
        v0, v1 = words[i], words[i + 1] if i + 1 < len(words) else 0
        out.extend(fn(v0, v1, k, rounds, delta))
    return _words_to_bytes(out, endian)


def tea_encrypt_bytes(data, key, rounds=32, delta=_DELTA, endian="little"):
    return _tea_bytes(data, key, False, rounds, delta, endian)


def tea_decrypt_bytes(data, key, rounds=32, delta=_DELTA, endian="little"):
    return _tea_bytes(data, key, True, rounds, delta, endian)


# ——————————————————— XTEA ———————————————————
def xtea_encrypt_block(v0, v1, k, rounds=32, delta=_DELTA):
    s = 0
    for _ in range(rounds):
        v0 = (v0 + (((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3])))) & _MASK
        s = (s + delta) & _MASK
        v1 = (v1 + (((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3])))) & _MASK
    return v0, v1


def xtea_decrypt_block(v0, v1, k, rounds=32, delta=_DELTA):
    s = (delta * rounds) & _MASK
    for _ in range(rounds):
        v1 = (v1 - (((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3])))) & _MASK
        s = (s - delta) & _MASK
        v0 = (v0 - (((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3])))) & _MASK
    return v0, v1


def _xtea_bytes(data, key, dec, rounds, delta, endian):
    k = _key_words(key, endian)
    words = _bytes_to_words(data, endian)
    out = []
    fn = xtea_decrypt_block if dec else xtea_encrypt_block
    for i in range(0, len(words), 2):
        v0, v1 = words[i], words[i + 1] if i + 1 < len(words) else 0
        out.extend(fn(v0, v1, k, rounds, delta))
    return _words_to_bytes(out, endian)


def xtea_encrypt_bytes(data, key, rounds=32, delta=_DELTA, endian="little"):
    return _xtea_bytes(data, key, False, rounds, delta, endian)


def xtea_decrypt_bytes(data, key, rounds=32, delta=_DELTA, endian="little"):
    return _xtea_bytes(data, key, True, rounds, delta, endian)


# ——————————————————— XXTEA ———————————————————
def _xxtea_mx(sm, y, z, p, e, k):
    return (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sm ^ y) + (k[(p & 3) ^ e] ^ z))) & _MASK


def xxtea_encrypt_bytes(data, key, delta=_DELTA, endian="little"):
    v = _bytes_to_words(data, endian)
    k = _key_words(key, endian)
    n = len(v)
    if n < 2:
        return data
    rounds = 6 + 52 // n
    sm = 0
    z = v[n - 1]
    for _ in range(rounds):
        sm = (sm + delta) & _MASK
        e = (sm >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            v[p] = (v[p] + _xxtea_mx(sm, y, z, p, e, k)) & _MASK
            z = v[p]
        y = v[0]
        v[n - 1] = (v[n - 1] + _xxtea_mx(sm, y, z, n - 1, e, k)) & _MASK
        z = v[n - 1]
    return _words_to_bytes(v, endian)


def xxtea_decrypt_bytes(data, key, delta=_DELTA, endian="little"):
    v = _bytes_to_words(data, endian)
    k = _key_words(key, endian)
    n = len(v)
    if n < 2:
        return data
    rounds = 6 + 52 // n
    sm = (rounds * delta) & _MASK
    y = v[0]
    for _ in range(rounds):
        e = (sm >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - _xxtea_mx(sm, y, z, p, e, k)) & _MASK
            y = v[p]
        z = v[n - 1]
        v[0] = (v[0] - _xxtea_mx(sm, y, z, 0, e, k)) & _MASK
        y = v[0]
        sm = (sm - delta) & _MASK
    return _words_to_bytes(v, endian)


# ——————————————————— RC4 ———————————————————
def rc4(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


# ——————————————————— AES(pycryptodome) ———————————————————
def aes_ecb_decrypt(data, key):
    from Crypto.Cipher import AES
    return AES.new(key, AES.MODE_ECB).decrypt(data)


def aes_ecb_encrypt(data, key):
    from Crypto.Cipher import AES
    return AES.new(key, AES.MODE_ECB).encrypt(data)


def aes_cbc_decrypt(data, key, iv):
    from Crypto.Cipher import AES
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)


def aes_cbc_encrypt(data, key, iv):
    from Crypto.Cipher import AES
    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)


# ——————————————————— base64 / xor ———————————————————
_STD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def b64_std_decode(data) -> bytes:
    if isinstance(data, str):
        data = data.encode()
    return _b64.b64decode(data)


def b64_custom_decode(data, alphabet: str) -> bytes:
    """自定义字母表 base64 解码(CTF 换表常见)。alphabet 为 64 字符表。"""
    if isinstance(data, bytes):
        data = data.decode("latin1")
    trans = str.maketrans(alphabet, _STD_B64)
    pad = "=" * (-len(data.rstrip("=")) % 4)
    return _b64.b64decode(data.rstrip("=").translate(trans) + pad)


def b64_custom_encode(data: bytes, alphabet: str) -> str:
    trans = str.maketrans(_STD_B64, alphabet)
    return _b64.b64encode(data).decode().translate(trans)


def xor_bytes(data: bytes, key) -> bytes:
    """循环异或。key 可为单字节 int 或 bytes。"""
    if isinstance(key, int):
        key = bytes([key])
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


# ——————————————————— 智能试解(免猜 endian/rounds) ———————————————————
def _flag_like(b: bytes, hint=None) -> bool:
    if not b:
        return False
    s = b.decode("latin1")
    printable = sum(1 for c in b if 32 <= c < 127) / len(b)
    # 通用 flag 格式命中即算(前缀{可打印体},如 NSSCTF{...}/flag{...}):放宽——不苛求 hint 精确匹配、
    # 也忽略尾部标点。7071 教训:XTEA 解出 NSSCTF{xtea_is_also_delicious!!},因模型传 hint='flag'
    # 不匹配 NSSCTF 而被判 False → 正解被丢、白跑 26 步。
    if re.search(r"[A-Za-z0-9_]{2,}\{[\x20-\x7e]{2,}\}", s):
        return True
    if hint:
        return hint.lower() in s.lower()
    return printable > 0.85


def smart_decrypt(algo, ciphertext, key, hint=None,
                  rounds_list=(32, 64), deltas=(_DELTA, 0x61C88647)) -> list:
    """自动遍历 endian×rounds×delta 变体解密,返回候选(flag_like 的排前)。免去模型猜参数。

    algo: 'tea'|'xtea'|'xxtea'|'rc4'。hint: flag 前缀(如 'NSSCTF'),给了则只认含它的候选。
    返回 [{"variant":..., "result":str, "flag_like":bool}, ...]。
    """
    if isinstance(ciphertext, str):
        ciphertext = bytes.fromhex(ciphertext)
    if isinstance(key, str):
        key = bytes.fromhex(key) if all(c in "0123456789abcdefABCDEF" for c in key) else key.encode()
    cands = []
    if algo == "rc4":
        r = rc4(ciphertext, key)
        cands.append({"variant": "rc4", "result": r.decode("latin1"), "flag_like": _flag_like(r, hint)})
    else:
        block_fns = {"tea": tea_decrypt_bytes, "xtea": xtea_decrypt_bytes}
        for endian in ("little", "big"):
            if algo == "xxtea":
                for delta in deltas:
                    try:
                        r = xxtea_decrypt_bytes(ciphertext, key, delta=delta, endian=endian)
                        cands.append({"variant": f"xxtea,{endian},delta={hex(delta)}",
                                      "result": r.decode("latin1"), "flag_like": _flag_like(r, hint)})
                    except Exception:
                        pass
            elif algo in block_fns:
                for rounds in rounds_list:
                    for delta in deltas:
                        try:
                            r = block_fns[algo](ciphertext, key, rounds=rounds, delta=delta, endian=endian)
                            cands.append({"variant": f"{algo},{endian},r={rounds},delta={hex(delta)}",
                                          "result": r.decode("latin1"), "flag_like": _flag_like(r, hint)})
                        except Exception:
                            pass
    cands.sort(key=lambda c: not c["flag_like"])
    return cands
