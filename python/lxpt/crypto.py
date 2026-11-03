"""The primitives lxpt wire v1 uses, in the standard library alone.

- SHA-256 and HMAC-SHA256 come from hashlib and hmac.
- HKDF-SHA256 is RFC 5869 over that HMAC.
- AES-256 is encryption only, which is all CTR mode needs (FIPS-197). It is
  pure Python, written for clarity and checked against FIPS-197 and SP 800-38A
  known answers.
- Ed25519 is RFC 8032, pure Python, with the verification rules
  ``spec/wire-v1.md`` fixes, so all three implementations accept and refuse
  the same signatures.

These are reference implementations. They are not constant-time, so use them
for tools, tests and relays that verify. A phone signs with its own identity's
key, through its own crypto stack.
"""

import hashlib
import hmac as _hmac

__all__ = [
    "sha256", "sha512", "hmac_sha256", "hkdf_sha256", "aes256_ctr",
    "ed25519_public_key", "ed25519_sign", "ed25519_verify",
]


def sha256(data):
    return hashlib.sha256(bytes(data)).digest()


def sha512(data):
    return hashlib.sha512(bytes(data)).digest()


def hmac_sha256(key, data):
    return _hmac.new(bytes(key), bytes(data), hashlib.sha256).digest()


def hkdf_sha256(ikm, salt, info, length):
    """RFC 5869. An empty salt means HashLen zero bytes, as the RFC says."""
    if length < 1 or length > 255 * 32:
        raise ValueError("HKDF length out of range")
    salt = bytes(salt) if salt else bytes(32)
    prk = hmac_sha256(salt, ikm)
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac_sha256(prk, block + bytes(info) + bytes([counter]))
        out += block
        counter += 1
    return out[:length]


# --- AES-256 (encryption direction only) -----------------------------------------


def _xtime(a):
    a <<= 1
    return (a ^ 0x11B) if a & 0x100 else a


def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _make_sbox():
    sbox = [0] * 256
    for x in range(256):
        # Multiplicative inverse in GF(2^8), 0 for 0, then the affine map.
        inv = 0
        if x:
            for y in range(1, 256):
                if _gmul(x, y) == 1:
                    inv = y
                    break
        s = inv
        for shift in range(1, 5):
            s ^= ((inv << shift) | (inv >> (8 - shift))) & 0xFF
        sbox[x] = s ^ 0x63
    return bytes(sbox)


_SBOX = _make_sbox()


def _expand_key(key):
    if len(key) != 32:
        raise ValueError("AES-256 needs a 32-byte key")
    words = [list(key[4 * i:4 * i + 4]) for i in range(8)]
    rcon = 1
    for i in range(8, 60):
        t = list(words[i - 1])
        if i % 8 == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif i % 8 == 4:
            t = [_SBOX[b] for b in t]
        words.append([a ^ b for a, b in zip(words[i - 8], t)])
    return [sum(words[4 * r:4 * r + 4], []) for r in range(15)]


def _encrypt_block(round_keys, block):
    s = [b ^ k for b, k in zip(block, round_keys[0])]
    for rnd in range(1, 15):
        s = [_SBOX[b] for b in s]
        # ShiftRows; the state is column-major, byte i is row i % 4.
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]
        if rnd != 14:
            mixed = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                mixed += [
                    _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3],
                    a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3],
                    a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3),
                    _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2),
                ]
            s = mixed
        s = [b ^ k for b, k in zip(s, round_keys[rnd])]
    return bytes(s)


def aes256_encrypt_block(key, block):
    return _encrypt_block(_expand_key(bytes(key)), bytes(block))


def aes256_ctr(key, iv, data):
    """AES-256-CTR. The counter is the whole 16-byte block, incremented as one
    big-endian 128-bit integer (SP 800-38A); encryption and decryption are the
    same operation."""
    if len(iv) != 16:
        raise ValueError("CTR needs a 16-byte initial counter block")
    rk = _expand_key(bytes(key))
    counter = int.from_bytes(bytes(iv), "big")
    out = bytearray()
    data = bytes(data)
    for at in range(0, len(data), 16):
        ks = _encrypt_block(rk, counter.to_bytes(16, "big"))
        chunk = data[at:at + 16]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
        counter = (counter + 1) % (1 << 128)
    return bytes(out)


# --- Ed25519 (RFC 8032) ------------------------------------------------------------

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _inv(x):
    return pow(x, _P - 2, _P)


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)
_IDENTITY = (0, 1, 1, 0)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, p):
    q = _IDENTITY
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _equal(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _compress(p):
    zinv = _inv(p[2])
    x, y = p[0] * zinv % _P, p[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _expand(seed):
    if len(seed) != 32:
        raise ValueError("an Ed25519 seed is 32 bytes")
    h = sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed25519_public_key(seed):
    a, _ = _expand(bytes(seed))
    return _compress(_mul(a, _G))


def ed25519_sign(seed, message):
    seed, message = bytes(seed), bytes(message)
    a, prefix = _expand(seed)
    public = _compress(_mul(a, _G))
    r = int.from_bytes(sha512(prefix + message), "little") % _L
    rs = _compress(_mul(r, _G))
    h = int.from_bytes(sha512(rs + public + message), "little") % _L
    s = (r + h * a) % _L
    return rs + int.to_bytes(s, 32, "little")


def ed25519_verify(public, message, signature):
    """True only if the signature is valid under the rules of spec/wire-v1.md:
    S below the group order, A and R canonical points, and the cofactorless
    equation [S]B = R + [k]A."""
    public, message, signature = bytes(public), bytes(message), bytes(signature)
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _decompress(public)
    if a is None:
        return False
    r = _decompress(signature[:32])
    if r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(sha512(signature[:32] + public + message), "little") % _L
    return _equal(_mul(s, _G), _add(r, _mul(k, a)))
