"""What needs the channel key, or an identity: channel ids, tags, the per-spurt
keys, sealing and opening FRAMEs and NOTICEs, and CLAIM and RELEASE signatures.

Relays need none of this except :func:`verify_claim` and
:func:`verify_release`; they forward ciphertext and read the clear header.
The derivations are in ``spec/wire-v1.md`` section 3.
"""

import hmac as _hmac
import struct

from . import crypto
from . import wire
from .wire import WireError

__all__ = [
    "normalize_room", "channel_id", "hubless_channel_id", "identity_hash", "ChannelKeys", "SpurtKeys",
    "seal_frame", "open_frame", "seal_notice", "open_notice",
    "sign_claim", "verify_claim", "sign_release", "verify_release", "claim_member_ok",
]

KEY_LEN = 32
CHANNEL_ID_LEN = 8
ROOM_MAX_LEN = 64

CHANNEL_ID_LABEL = b"lxpt/ch/v1"
HUBLESS_ID_LABEL = b"lxpt/hubless/v1"
TAG_LABEL = b"lxpt/v1/tag"
MEMBER_LABEL = b"lxpt/v1/member"
NOTICE_KEY_LABEL = b"lxpt/v1/notice-key"
NOTICE_MAC_LABEL = b"lxpt/v1/notice-mac"
NOTICE_TALKER_LABEL = b"lxpt/v1/notice-talker"
SPURT_LABEL = b"lxpt/v1/spurt"

_SPACE = b" \t\n\v\f\r"


def _utf8_valid(b):
    """Strict UTF-8: no overlong forms, no surrogates, nothing past U+10FFFF."""
    i, n = 0, len(b)
    while i < n:
        c = b[i]
        if c < 0x80:
            i += 1
            continue
        if 0xC2 <= c <= 0xDF:
            need, lo, hi = 1, 0x80, 0xBF
        elif c == 0xE0:
            need, lo, hi = 2, 0xA0, 0xBF
        elif 0xE1 <= c <= 0xEC or 0xEE <= c <= 0xEF:
            need, lo, hi = 2, 0x80, 0xBF
        elif c == 0xED:
            need, lo, hi = 2, 0x80, 0x9F
        elif c == 0xF0:
            need, lo, hi = 3, 0x90, 0xBF
        elif 0xF1 <= c <= 0xF3:
            need, lo, hi = 3, 0x80, 0xBF
        elif c == 0xF4:
            need, lo, hi = 3, 0x80, 0x8F
        else:
            return False
        if i + need >= n:
            return False
        if not lo <= b[i + 1] <= hi:
            return False
        for k in range(2, need + 1):
            if not 0x80 <= b[i + k] <= 0xBF:
                return False
        i += need + 1
    return True


def normalize_room(name):
    """RRC's room normalisation, byte for byte: trim ASCII whitespace at both
    ends, lower-case ASCII letters, leave every other byte alone. The result
    must be 1 to 64 bytes of valid UTF-8, or WireError("field")."""
    if isinstance(name, str):
        name = name.encode("utf-8")
    b = bytes(name)
    start, end = 0, len(b)
    while start < end and b[start] in _SPACE:
        start += 1
    while end > start and b[end - 1] in _SPACE:
        end -= 1
    out = bytes(c + 32 if 0x41 <= c <= 0x5A else c for c in b[start:end])
    if not 1 <= len(out) <= ROOM_MAX_LEN or not _utf8_valid(out):
        raise WireError("field")
    return out


def _hash16(h):
    if not isinstance(h, (bytes, bytearray)) or len(h) != wire.HASH_LEN:
        raise WireError("field")
    return bytes(h)


def channel_id(hub_hash, room):
    """SHA-256("lxpt/ch/v1" || hub hash || normalised room)[:8]."""
    return crypto.sha256(CHANNEL_ID_LABEL + _hash16(hub_hash) + normalize_room(room))[:CHANNEL_ID_LEN]


def hubless_channel_id(creator_hash, name):
    """A phone-only channel: SHA-256("lxpt/hubless/v1" || creator || normalised name)[:8]."""
    return crypto.sha256(HUBLESS_ID_LABEL + _hash16(creator_hash) + normalize_room(name))[:CHANNEL_ID_LEN]


def identity_hash(public_key):
    """A Reticulum identity hash: SHA-256 of the 64-byte public key, first 16 bytes."""
    if len(public_key) != wire.PUBLIC_KEY_LEN:
        raise WireError("field")
    return crypto.sha256(public_key)[:wire.HASH_LEN]


class SpurtKeys:
    """The AES-256 key and the HMAC key of one spurt."""

    def __init__(self, enc_key, mac_key):
        self.enc_key = bytes(enc_key)
        self.mac_key = bytes(mac_key)


class ChannelKeys:
    """Everything derived from one channel key epoch for one channel."""

    def __init__(self, k_epoch, channel_id_):
        if len(k_epoch) != KEY_LEN or len(channel_id_) != CHANNEL_ID_LEN:
            raise WireError("field")
        self.k_epoch = bytes(k_epoch)
        self.channel_id = bytes(channel_id_)
        self.channel_tag = crypto.hmac_sha256(self.k_epoch, TAG_LABEL + self.channel_id)[:wire.TAG_LEN]
        self.notice_key = crypto.hmac_sha256(self.k_epoch, NOTICE_KEY_LABEL + self.channel_id)

    def member_tag(self, identity_hash_):
        return crypto.hmac_sha256(self.k_epoch, MEMBER_LABEL + self.channel_id + _hash16(identity_hash_))[:wire.TAG_LEN]

    def spurt_keys(self, talker_hash, spurt, nonce):
        if len(nonce) != wire.NONCE_LEN or not 1 <= spurt <= 0xFFFFFFFF:
            raise WireError("field")
        info = SPURT_LABEL + self.channel_id + _hash16(talker_hash) + struct.pack(">I", spurt)
        okm = crypto.hkdf_sha256(self.k_epoch, bytes(nonce), info, 64)
        return SpurtKeys(okm[:32], okm[32:])


def _frame_iv(seq):
    return struct.pack(">H", seq) + bytes(14)


def seal_frame(keys, channel_tag, talker_tag, spurt, seq, plaintext):
    """Encrypt a codec frame and MAC it: AES-256-CTR from (seq || 14 zero bytes),
    then HMAC-SHA256 over the header and ciphertext, first 8 bytes."""
    m = {"type": "frame", "channel_tag": channel_tag, "talker_tag": talker_tag, "spurt": spurt, "seq": seq,
         "payload": bytes(plaintext), "mac": bytes(wire.MAC_LEN)}
    wire.encode(m)  # every field checked before any crypto
    m["payload"] = crypto.aes256_ctr(keys.enc_key, _frame_iv(seq), plaintext)
    body = wire.encode(m)[:-wire.MAC_LEN]
    return body + crypto.hmac_sha256(keys.mac_key, body)[:wire.MAC_LEN]


def open_frame(keys, data):
    """(message, plaintext) for a frame whose MAC holds, else WireError("mac")."""
    data = bytes(data)
    m = wire.decode(data)
    if m["type"] != "frame":
        raise WireError("type")
    expect = crypto.hmac_sha256(keys.mac_key, data[:-wire.MAC_LEN])[:wire.MAC_LEN]
    if not _hmac.compare_digest(expect, m["mac"]):
        raise WireError("mac")
    return m, crypto.aes256_ctr(keys.enc_key, _frame_iv(m["seq"]), m["payload"])


def _notice_mac(notice_key, raw_plain):
    # The hop limit (low nibble of byte 1) is left out, so a later hop may
    # lower it without the channel key.
    covered = raw_plain[0:1] + bytes([raw_plain[1] & 0xF0]) + raw_plain[2:13]
    return crypto.hmac_sha256(notice_key, NOTICE_MAC_LABEL + covered)[:wire.MAC_LEN]


def _talker_pad(notice_key, mac):
    return crypto.hmac_sha256(notice_key, NOTICE_TALKER_LABEL + mac)[:wire.TAG_LEN]


def seal_notice(notice_key, kind, hop_limit, channel_tag, talker_prefix, spurt16, talk_limit_s):
    """A NOTICE with its MAC, and the talker prefix (the first four bytes of the
    talker's identity hash) encrypted with a pad derived from that MAC."""
    n = {"kind": kind, "hop_limit": hop_limit, "channel_tag": channel_tag, "talker": talker_prefix,
         "spurt16": spurt16, "talk_limit_s": talk_limit_s, "mac": bytes(wire.MAC_LEN)}
    plain = wire.encode_notice(n)
    mac = _notice_mac(notice_key, plain)
    pad = _talker_pad(notice_key, mac)
    n["talker"] = bytes(a ^ b for a, b in zip(talker_prefix, pad))
    n["mac"] = mac
    return wire.encode_notice(n)


def open_notice(notice_key, data):
    """The notice with ``talker_prefix`` decrypted, or WireError("mac")."""
    n = wire.decode_notice(data)
    pad = _talker_pad(notice_key, n["mac"])
    prefix = bytes(a ^ b for a, b in zip(n["talker"], pad))
    plain = bytearray(bytes(data))
    plain[6:10] = prefix
    if not _hmac.compare_digest(_notice_mac(notice_key, bytes(plain)), n["mac"]):
        raise WireError("mac")
    n["talker_prefix"] = prefix
    return n


def _check_signer(public_key, seed):
    if crypto.ed25519_public_key(seed) != bytes(public_key[32:]):
        raise ValueError("the seed does not belong to the public key's signing half")


def sign_claim(m, seed):
    """A CLAIM's bytes, signed with the Ed25519 seed whose public key is the
    second half of m["public_key"] (Reticulum's layout: X25519 then Ed25519)."""
    _check_signer(m["public_key"], seed)
    unsigned = wire.encode(dict(m, type="claim", signature=bytes(wire.SIGNATURE_LEN)))
    sig = crypto.ed25519_sign(seed, wire.claim_signed_bytes(unsigned))
    return unsigned[:wire.CLAIM_SIGNED_LEN] + sig


def verify_claim(data):
    """The decoded CLAIM if its signature holds, else WireError("signature")."""
    m = wire.decode(data)
    if m["type"] != "claim":
        raise WireError("type")
    if not crypto.ed25519_verify(m["public_key"][32:], wire.claim_signed_bytes(data), m["signature"]):
        raise WireError("signature")
    return m


def sign_release(m, seed):
    _check_signer(m["public_key"], seed)
    unsigned = wire.encode(dict(m, type="release", signature=bytes(wire.SIGNATURE_LEN)))
    sig = crypto.ed25519_sign(seed, wire.release_signed_bytes(unsigned))
    return unsigned[:wire.RELEASE_SIGNED_LEN] + sig


def verify_release(data):
    m = wire.decode(data)
    if m["type"] != "release":
        raise WireError("type")
    if not crypto.ed25519_verify(m["public_key"][32:], wire.release_signed_bytes(data), m["signature"]):
        raise WireError("signature")
    return m


def claim_member_ok(keys, m):
    """Whether a CLAIM's talker tag is its signer's member tag in this channel.
    Only a key holder can tell; a relay cannot."""
    return _hmac.compare_digest(keys.member_tag(identity_hash(m["public_key"])), m["talker_tag"])
