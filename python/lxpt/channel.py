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
    "canonical_room", "channel_id", "hubless_channel_id", "identity_hash", "ChannelKeys", "SpurtKeys",
    "seal_frame", "open_frame", "seal_notice", "open_notice",
    "sign_claim", "verify_claim", "sign_release", "verify_release", "claim_member_ok", "relay_key",
    "release_matches_claim", "seed_signer",
]

KEY_LEN = 32
CHANNEL_ID_LEN = 8
ROOM_MAX_LEN = 255

CHANNEL_ID_LABEL = b"lxpt/ch/v1"
HUBLESS_ID_LABEL = b"lxpt/hubless/v1"
TAG_LABEL = b"lxpt/v1/tag"
MEMBER_LABEL = b"lxpt/v1/member"
NOTICE_KEY_LABEL = b"lxpt/v1/notice-key"
NOTICE_MAC_LABEL = b"lxpt/v1/notice-mac"
NOTICE_TALKER_LABEL = b"lxpt/v1/notice-talker"
SPURT_LABEL = b"lxpt/v1/spurt"

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


def canonical_room(name):
    """A room name exactly as its hub returns it: lxpt never re-normalises.
    Hubs disagree (rrcd lower-cases Unicode and strips whitespace; other
    clients also strip '#'), so the only name every member agrees on is the
    hub's own. It must be 1 to 255 bytes of strict UTF-8, else
    WireError("field"). A str is taken as UTF-8."""
    if isinstance(name, str):
        name = name.encode("utf-8")
    b = bytes(name)
    if not 1 <= len(b) <= ROOM_MAX_LEN or not _utf8_valid(b):
        raise WireError("field")
    return b


def _hash16(h):
    if not isinstance(h, (bytes, bytearray)) or len(h) != wire.HASH_LEN:
        raise WireError("field")
    return bytes(h)


def channel_id(hub_hash, room):
    """SHA-256("lxpt/ch/v1" || hub hash || the hub's canonical room name)[:8]."""
    return crypto.sha256(CHANNEL_ID_LABEL + _hash16(hub_hash) + canonical_room(room))[:CHANNEL_ID_LEN]


def hubless_channel_id(creator_hash, name):
    """A phone-only channel: SHA-256("lxpt/hubless/v1" || creator || name as created)[:8]."""
    return crypto.sha256(HUBLESS_ID_LABEL + _hash16(creator_hash) + canonical_room(name))[:CHANNEL_ID_LEN]


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


def seed_signer(seed, public_key):
    """A signer from a raw Ed25519 seed, for tools and tests. A phone signs
    through its own identity stack instead: any callable that takes the bytes
    and returns Reticulum's Ed25519 signature will do."""
    if crypto.ed25519_public_key(seed) != bytes(public_key[32:]):
        raise ValueError("the seed does not belong to the public key's signing half")
    return lambda message: crypto.ed25519_sign(seed, message)


def _signer(m, signer):
    if isinstance(signer, (bytes, bytearray)):
        signer = seed_signer(signer, m["public_key"])
    return signer


def _signed(unsigned_len, span, public_key, sign):
    sig = bytes(sign(span))
    if len(sig) != wire.SIGNATURE_LEN or not crypto.ed25519_verify(public_key[32:], span, sig):
        raise ValueError("the signer's signature does not verify under the message's public key")
    return sig


def sign_claim(m, signer):
    """A CLAIM's bytes, signed by `signer`: a callable over the signed span
    (the host's identity stack), or an Ed25519 seed. The signature is checked
    against m["public_key"] before it is returned."""
    sign = _signer(m, signer)
    unsigned = wire.encode(dict(m, type="claim", signature=bytes(wire.SIGNATURE_LEN)))
    span = wire.claim_signed_bytes(unsigned)
    return unsigned[:wire.CLAIM_SIGNED_LEN] + _signed(wire.CLAIM_SIGNED_LEN, span, m["public_key"], sign)


def verify_claim(data):
    """The decoded CLAIM if its signature holds, else WireError("signature")."""
    m = wire.decode(data)
    if m["type"] != "claim":
        raise WireError("type")
    if not crypto.ed25519_verify(m["public_key"][32:], wire.claim_signed_bytes(data), m["signature"]):
        raise WireError("signature")
    return m


def sign_release(m, signer):
    sign = _signer(m, signer)
    unsigned = wire.encode(dict(m, type="release", signature=bytes(wire.SIGNATURE_LEN)))
    span = wire.release_signed_bytes(unsigned)
    return unsigned[:wire.RELEASE_SIGNED_LEN] + _signed(wire.RELEASE_SIGNED_LEN, span, m["public_key"], sign)


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


def _verified(data):
    kind = wire.peek_type(data)
    if kind == "claim":
        return verify_claim(data)
    if kind == "release":
        return verify_release(data)
    raise WireError("type")


def relay_key(data):
    """What a relay keys per-talker state on, for a verified CLAIM or RELEASE:
    channel tag || identity hash of the signing key || spurt (24 bytes). Never
    the talker tag alone: a relay cannot tie a tag to a key, so anyone can sign
    a message that carries someone else's tag."""
    m = _verified(data)
    return m["channel_tag"] + identity_hash(m["public_key"]) + struct.pack(">I", m["spurt"])


def release_matches_claim(claim, release):
    """None if the RELEASE ends this CLAIM's spurt: both verify, and they share
    the channel tag, the talker tag, the spurt and the signing key. Else
    WireError("signature") or WireError("identity")."""
    c, r = verify_claim(claim), verify_release(release)
    if (c["channel_tag"], c["talker_tag"], c["spurt"], c["public_key"]) != \
            (r["channel_tag"], r["talker_tag"], r["spurt"], r["public_key"]):
        raise WireError("identity")
