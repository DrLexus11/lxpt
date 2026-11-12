"""lxpt wire v1 and NOTICE v1: structural encode and decode, no keys needed.

The layouts, limits and the order in which errors are reported are fixed by
``spec/wire-v1.md``. The C++ and Kotlin implementations follow this file field
for field and error for error, and ``fixtures/lxpt_wire_v1.json`` holds all
three to it.

Messages are dicts. ``type`` names the message, byte fields are ``bytes``,
enumerations are their lower-case names, and flags are booleans. ``encode``
validates and raises :class:`WireError`; ``decode`` returns the same shape.
Neither checks a MAC or a signature: that needs keys and lives in
:mod:`lxpt.channel`.
"""

import struct

__all__ = [
    "WireError", "ERRORS", "VERSION", "NOTICE_VERSION", "MAX_MESSAGE_LEN",
    "encode", "decode", "peek_type", "encode_notice", "decode_notice",
    "claim_signed_bytes", "release_signed_bytes",
]

ERRORS = ("truncated", "oversize", "version", "type", "field", "mac", "signature", "identity")


class WireError(ValueError):
    """A refused message; ``.code`` is one of ERRORS."""

    def __init__(self, code):
        assert code in ERRORS, code
        super().__init__(code)
        self.code = code


VERSION = 0x01
NOTICE_VERSION = 0x01
MAX_MESSAGE_LEN = 431  # a Reticulum link's MDU; a PLAIN packet's (464) is larger

TAG_LEN = 4
HASH_LEN = 16
NONCE_LEN = 16
PUBLIC_KEY_LEN = 64
SIGNATURE_LEN = 64
MAC_LEN = 8

FRAME_HEADER_LEN = 16
FRAME_MAX_PAYLOAD = 197  # 19 B PLAIN header + 221 B frame + IFAC 16 = 256 B, the relay slot
FRAME_MIN_LEN = FRAME_HEADER_LEN + 1 + MAC_LEN
FRAME_MAX_LEN = FRAME_HEADER_LEN + FRAME_MAX_PAYLOAD + MAC_LEN
CLAIM_LEN = 168
CLAIM_SIGNED_LEN = CLAIM_LEN - SIGNATURE_LEN
GRANT_MIN_LEN = 17
GRANT_MAX_REACHED = 64
BUSY_LEN = 25
YIELD_LEN = 25
RELEASE_LEN = 144
RELEASE_SIGNED_LEN = RELEASE_LEN - SIGNATURE_LEN
TALKING_LEN = 18
SUB_MIN_LEN = 4
SUB_ENTRY_LEN = 9
SUB_MAX_ENTRIES = 32
PEER_MIN_LEN = 21
PEER_CHANNEL_MIN_LEN = 6
PEER_MAX_CHANNELS = 32
PEER_MAX_MEMBERS = 64
HEARD_MIN_LEN = 15
HEARD_ENTRY_LEN = 6
HEARD_MAX_ENTRIES = 64
SPURT_REF_LEN = 10
NOTICE_LEN = 21
NOTICE_MAX_HOP_LIMIT = 15

CLAIM_DOMAIN = b"lxpt/v1/claim"
RELEASE_DOMAIN = b"lxpt/v1/release"

TYPES = {1: "frame", 2: "claim", 3: "grant", 4: "busy", 5: "yield",
         6: "release", 7: "talking", 8: "sub", 9: "peer", 10: "heard"}
TYPE_CODES = {v: k for k, v in TYPES.items()}
TIERS = {1: "commander", 2: "deputy", 3: "leader", 4: "member", 5: "observer"}
TIER_CODES = {v: k for k, v in TIERS.items()}
PROFILES = {0x10: "ulbw", 0x20: "vlbw", 0x30: "lbw", 0x40: "mq", 0x50: "hq"}
PROFILE_CODES = {v: k for k, v in PROFILES.items()}
# Codec2 payloads (spec "Codec payloads"): per profile, the Codec2 frame time in ms, the
# Codec2 frames one FRAME carries, and the bytes libcodec2 gives per Codec2 frame
# (codec2_bytes_per_frame). 700C's 28 bits are byte-aligned to 4 bytes. No mode byte:
# the profile names the mode. Opus profiles are absent: their payload is one Opus packet.
CODEC2 = {"ulbw": (40, 10, 4), "vlbw": (40, 8, 8), "lbw": (20, 10, 8)}


def codec_payload_len(profile):
    """The exact payload length of one FRAME on a Codec2 profile; None on Opus."""
    c = CODEC2.get(profile)
    return None if c is None else c[1] * c[2]


def check_payload(profile, payload):
    """Refuses a FRAME payload the profile cannot carry: a Codec2 payload of another
    length (an LXST mode byte left in, or bit-packed 700C) or an empty or oversize Opus one."""
    if profile not in PROFILE_CODES:
        raise WireError("field")
    n = len(payload)
    want = codec_payload_len(profile)
    if want is not None:
        if n != want:
            raise WireError("field")
        return
    if n == 0:
        raise WireError("field")
    if n > FRAME_MAX_PAYLOAD:
        raise WireError("oversize")


CARRIERS = {1: "ip", 2: "ble", 3: "gfsk", 4: "halow"}
CARRIER_CODES = {v: k for k, v in CARRIERS.items()}
SUB_MODES = {1: "voice", 2: "watch"}
SUB_MODE_CODES = {v: k for k, v in SUB_MODES.items()}
BUSY_REASONS = {1: "busy", 2: "rate_limited"}
BUSY_REASON_CODES = {v: k for k, v in BUSY_REASONS.items()}
YIELD_REASONS = {1: "collision", 2: "preempted"}
YIELD_REASON_CODES = {v: k for k, v in YIELD_REASONS.items()}
NOTICE_KINDS = {1: "start", 2: "preempt", 3: "emergency"}
NOTICE_KIND_CODES = {v: k for k, v in NOTICE_KINDS.items()}

CLAIM_FLAG_EMERGENCY = 0x01
CLAIM_FLAG_CLOCK_VERIFIED = 0x02
REF_FLAG_EMERGENCY = 0x01
PEER_FLAG_NARROW = 0x01


# --- field checks for encode ---------------------------------------------------------


def _bytes(value, size):
    if not isinstance(value, (bytes, bytearray)) or len(value) != size:
        raise WireError("field")
    return bytes(value)


def _uint(value, bits, minimum=0):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value >= (1 << bits):
        raise WireError("field")
    return value


def _flag(value):
    if not isinstance(value, bool):
        raise WireError("field")
    return value


def _enum(codes, value):
    if value not in codes:
        raise WireError("field")
    return codes[value]


def _spurt_ref(ref):
    """A holder or winner: talker tag, spurt, tier, emergency (10 bytes)."""
    if ref is None:
        return bytes(SPURT_REF_LEN)
    if not isinstance(ref, dict):
        raise WireError("field")
    return (_bytes(ref["talker_tag"], TAG_LEN) + struct.pack(">I", _uint(ref["spurt"], 32, 1))
            + bytes([_enum(TIER_CODES, ref["tier"]),
                     REF_FLAG_EMERGENCY if _flag(ref["emergency"]) else 0]))


def _head(kind, channel_tag):
    return bytes([VERSION, TYPE_CODES[kind]]) + _bytes(channel_tag, TAG_LEN)


def _talker(m):
    return _bytes(m["talker_tag"], TAG_LEN) + struct.pack(">I", _uint(m["spurt"], 32, 1))


# --- encode --------------------------------------------------------------------------


def encode(m):
    """A message dict to its bytes. Raises WireError("field"/"oversize")."""
    if not isinstance(m, dict) or m.get("type") not in TYPE_CODES:
        raise WireError("type")
    kind = m["type"]
    out = _ENCODERS[kind](m)
    if len(out) > MAX_MESSAGE_LEN:
        raise WireError("oversize")
    return out


def _encode_frame(m):
    payload = m["payload"]
    if not isinstance(payload, (bytes, bytearray)):
        raise WireError("field")
    if len(payload) == 0:
        raise WireError("field")
    if len(payload) > FRAME_MAX_PAYLOAD:
        raise WireError("oversize")
    return (_head("frame", m["channel_tag"]) + _talker(m) + struct.pack(">H", _uint(m["seq"], 16))
            + bytes(payload) + _bytes(m["mac"], MAC_LEN))


def _claim_body(m):
    flags = (CLAIM_FLAG_EMERGENCY if _flag(m["emergency"]) else 0) | \
            (CLAIM_FLAG_CLOCK_VERIFIED if _flag(m["clock_verified"]) else 0)
    return (_head("claim", m["channel_tag"]) + _talker(m) + struct.pack(">I", _uint(m["epoch"], 32))
            + _bytes(m["nonce"], NONCE_LEN) + bytes([_enum(TIER_CODES, m["tier"]), flags])
            + struct.pack(">I", _uint(m["clock"], 32)) + _bytes(m["public_key"], PUBLIC_KEY_LEN))


def _encode_claim(m):
    return _claim_body(m) + _bytes(m["signature"], SIGNATURE_LEN)


def _tag_list(tags, maximum):
    if not isinstance(tags, (list, tuple)) or len(tags) > maximum:
        raise WireError("field")
    return bytes([len(tags)]) + b"".join(_bytes(t, TAG_LEN) for t in tags)


def _encode_grant(m):
    return (_head("grant", m["channel_tag"]) + _talker(m)
            + bytes([_enum(PROFILE_CODES, m["profile"]), _uint(m["talk_limit_s"], 8, 1)])
            + _tag_list(m["reached"], GRANT_MAX_REACHED))


def _encode_busy(m):
    reason = _enum(BUSY_REASON_CODES, m["reason"])
    if m["holder"] is None and m["reason"] == "busy":
        raise WireError("field")
    return _head("busy", m["channel_tag"]) + _talker(m) + bytes([reason]) + _spurt_ref(m["holder"])


def _encode_yield(m):
    reason = _enum(YIELD_REASON_CODES, m["reason"])
    if m["winner"] is None:
        raise WireError("field")
    return _head("yield", m["channel_tag"]) + _talker(m) + bytes([reason]) + _spurt_ref(m["winner"])


def _release_body(m):
    return (_head("release", m["channel_tag"]) + _talker(m) + struct.pack(">H", _uint(m["frame_count"], 16))
            + _bytes(m["public_key"], PUBLIC_KEY_LEN))


def _encode_release(m):
    return _release_body(m) + _bytes(m["signature"], SIGNATURE_LEN)


def _encode_talking(m):
    if m["holder"] is None:
        raise WireError("field")
    return (_head("talking", m["channel_tag"]) + _spurt_ref(m["holder"])
            + bytes([_enum(PROFILE_CODES, m["profile"]), _uint(m["talk_limit_s"], 8, 1)]))


def _encode_sub(m):
    entries = m["entries"]
    if not isinstance(entries, (list, tuple)) or len(entries) > SUB_MAX_ENTRIES:
        raise WireError("field")
    out = bytes([VERSION, TYPE_CODES["sub"], _enum(CARRIER_CODES, m["carrier"]), len(entries)])
    for e in entries:
        out += _bytes(e["channel_tag"], TAG_LEN) + _bytes(e["member_tag"], TAG_LEN) + \
            bytes([_enum(SUB_MODE_CODES, e["mode"])])
    return out


def _encode_peer(m):
    channels = m["channels"]
    if not isinstance(channels, (list, tuple)) or len(channels) > PEER_MAX_CHANNELS:
        raise WireError("field")
    out = bytes([VERSION, TYPE_CODES["peer"]]) + _bytes(m["relay_hash"], HASH_LEN) + \
        struct.pack(">HB", _uint(m["stall_p99_ms"], 16), len(channels))
    for c in channels:
        members = c["members"]
        if not isinstance(members, (list, tuple)) or len(members) > PEER_MAX_MEMBERS:
            raise WireError("field")
        out += _bytes(c["channel_tag"], TAG_LEN) + bytes([PEER_FLAG_NARROW if _flag(c["narrow"]) else 0]) + \
            _tag_list(members, PEER_MAX_MEMBERS)
    return out


def _encode_heard(m):
    heard = m["heard"]
    if not isinstance(heard, (list, tuple)) or len(heard) > HEARD_MAX_ENTRIES:
        raise WireError("field")
    out = _head("heard", m["channel_tag"]) + _talker(m) + bytes([len(heard)])
    for h in heard:
        out += _bytes(h["member_tag"], TAG_LEN) + struct.pack(">H", _uint(h["frames"], 16))
    return out


_ENCODERS = {"frame": _encode_frame, "claim": _encode_claim, "grant": _encode_grant, "busy": _encode_busy,
             "yield": _encode_yield, "release": _encode_release, "talking": _encode_talking, "sub": _encode_sub,
             "peer": _encode_peer, "heard": _encode_heard}


# --- decode --------------------------------------------------------------------------


def peek_type(data):
    """The message type's name, after the version and type checks."""
    data = bytes(data)
    if len(data) < 1:
        raise WireError("truncated")
    if data[0] != VERSION:
        raise WireError("version")
    if len(data) < 2:
        raise WireError("truncated")
    kind = TYPES.get(data[1])
    if kind is None:
        raise WireError("type")
    return kind


def _exact(data, length):
    if len(data) < length:
        raise WireError("truncated")
    if len(data) > length:
        raise WireError("oversize")


def _lookup(table, code):
    if code not in table:
        raise WireError("field")
    return table[code]


def _read_talker(data, m):
    m["talker_tag"] = data[6:10]
    m["spurt"], = struct.unpack_from(">I", data, 10)
    if m["spurt"] == 0:
        raise WireError("field")


def _read_ref(data, at):
    raw = data[at:at + SPURT_REF_LEN]
    if raw == bytes(SPURT_REF_LEN):
        return None
    spurt, = struct.unpack_from(">I", raw, 4)
    if spurt == 0 or raw[9] & ~REF_FLAG_EMERGENCY:
        raise WireError("field")
    return {"talker_tag": raw[0:4], "spurt": spurt, "tier": _lookup(TIERS, raw[8]),
            "emergency": bool(raw[9] & REF_FLAG_EMERGENCY)}


def decode(data):
    """Bytes to a message dict, or WireError. Errors are reported in the order
    spec/wire-v1.md gives: truncated before the version byte, version, type,
    oversize past MAX_MESSAGE_LEN, then the type's own length and fields."""
    data = bytes(data)
    kind = peek_type(data)
    if len(data) > MAX_MESSAGE_LEN:
        raise WireError("oversize")
    m = {"type": kind}
    _DECODERS[kind](data, m)
    return m


def _decode_frame(data, m):
    if len(data) < FRAME_MIN_LEN:
        raise WireError("truncated")
    if len(data) > FRAME_MAX_LEN:
        raise WireError("oversize")
    m["channel_tag"] = data[2:6]
    _read_talker(data, m)
    m["seq"], = struct.unpack_from(">H", data, 14)
    m["payload"] = data[FRAME_HEADER_LEN:len(data) - MAC_LEN]
    m["mac"] = data[len(data) - MAC_LEN:]


def _decode_claim(data, m):
    _exact(data, CLAIM_LEN)
    m["channel_tag"] = data[2:6]
    _read_talker(data, m)
    m["epoch"], = struct.unpack_from(">I", data, 14)
    m["nonce"] = data[18:34]
    m["tier"] = _lookup(TIERS, data[34])
    flags = data[35]
    if flags & ~(CLAIM_FLAG_EMERGENCY | CLAIM_FLAG_CLOCK_VERIFIED):
        raise WireError("field")
    m["emergency"] = bool(flags & CLAIM_FLAG_EMERGENCY)
    m["clock_verified"] = bool(flags & CLAIM_FLAG_CLOCK_VERIFIED)
    m["clock"], = struct.unpack_from(">I", data, 36)
    m["public_key"] = data[40:104]
    m["signature"] = data[104:168]


def _decode_grant(data, m):
    if len(data) < GRANT_MIN_LEN:
        raise WireError("truncated")
    count = data[16]
    if count > GRANT_MAX_REACHED:
        raise WireError("field")
    _exact(data, GRANT_MIN_LEN + TAG_LEN * count)
    m["channel_tag"] = data[2:6]
    _read_talker(data, m)
    m["profile"] = _lookup(PROFILES, data[14])
    m["talk_limit_s"] = data[15]
    if m["talk_limit_s"] == 0:
        raise WireError("field")
    m["reached"] = [data[17 + 4 * i:21 + 4 * i] for i in range(count)]


def _decode_busy(data, m):
    _exact(data, BUSY_LEN)
    m["channel_tag"] = data[2:6]
    _read_talker(data, m)
    m["reason"] = _lookup(BUSY_REASONS, data[14])
    m["holder"] = _read_ref(data, 15)
    if m["holder"] is None and m["reason"] == "busy":
        raise WireError("field")


def _decode_yield(data, m):
    _exact(data, YIELD_LEN)
    m["channel_tag"] = data[2:6]
    _read_talker(data, m)
    m["reason"] = _lookup(YIELD_REASONS, data[14])
    m["winner"] = _read_ref(data, 15)
    if m["winner"] is None:
        raise WireError("field")


def _decode_release(data, m):
    _exact(data, RELEASE_LEN)
    m["channel_tag"] = data[2:6]
    _read_talker(data, m)
    m["frame_count"], = struct.unpack_from(">H", data, 14)
    m["public_key"] = data[16:80]
    m["signature"] = data[80:144]


def _decode_talking(data, m):
    _exact(data, TALKING_LEN)
    m["channel_tag"] = data[2:6]
    m["holder"] = _read_ref(data, 6)
    if m["holder"] is None:
        raise WireError("field")
    m["profile"] = _lookup(PROFILES, data[16])
    m["talk_limit_s"] = data[17]
    if m["talk_limit_s"] == 0:
        raise WireError("field")


def _decode_sub(data, m):
    if len(data) < SUB_MIN_LEN:
        raise WireError("truncated")
    count = data[3]
    if count > SUB_MAX_ENTRIES:
        raise WireError("field")
    _exact(data, SUB_MIN_LEN + SUB_ENTRY_LEN * count)
    m["carrier"] = _lookup(CARRIERS, data[2])
    m["entries"] = []
    for i in range(count):
        at = SUB_MIN_LEN + SUB_ENTRY_LEN * i
        m["entries"].append({"channel_tag": data[at:at + 4], "member_tag": data[at + 4:at + 8],
                             "mode": _lookup(SUB_MODES, data[at + 8])})


def _decode_peer(data, m):
    if len(data) < PEER_MIN_LEN:
        raise WireError("truncated")
    m["relay_hash"] = data[2:18]
    m["stall_p99_ms"], count = struct.unpack_from(">HB", data, 18)
    if count > PEER_MAX_CHANNELS:
        raise WireError("field")
    at = PEER_MIN_LEN
    m["channels"] = []
    for _ in range(count):
        if len(data) < at + PEER_CHANNEL_MIN_LEN:
            raise WireError("truncated")
        flags, members = data[at + 4], data[at + 5]
        if flags & ~PEER_FLAG_NARROW or members > PEER_MAX_MEMBERS:
            raise WireError("field")
        end = at + PEER_CHANNEL_MIN_LEN + TAG_LEN * members
        if len(data) < end:
            raise WireError("truncated")
        m["channels"].append({"channel_tag": data[at:at + 4], "narrow": bool(flags & PEER_FLAG_NARROW),
                              "members": [data[at + 6 + 4 * i:at + 10 + 4 * i] for i in range(members)]})
        at = end
    if len(data) > at:
        raise WireError("oversize")


def _decode_heard(data, m):
    if len(data) < HEARD_MIN_LEN:
        raise WireError("truncated")
    count = data[14]
    if count > HEARD_MAX_ENTRIES:
        raise WireError("field")
    _exact(data, HEARD_MIN_LEN + HEARD_ENTRY_LEN * count)
    m["channel_tag"] = data[2:6]
    _read_talker(data, m)
    m["heard"] = []
    for i in range(count):
        at = HEARD_MIN_LEN + HEARD_ENTRY_LEN * i
        m["heard"].append({"member_tag": data[at:at + 4], "frames": struct.unpack_from(">H", data, at + 4)[0]})


_DECODERS = {"frame": _decode_frame, "claim": _decode_claim, "grant": _decode_grant, "busy": _decode_busy,
             "yield": _decode_yield, "release": _decode_release, "talking": _decode_talking, "sub": _decode_sub,
             "peer": _decode_peer, "heard": _decode_heard}


# --- signed spans --------------------------------------------------------------------


def claim_signed_bytes(data):
    """What a CLAIM's signature covers: the domain, then every byte before it."""
    data = bytes(data)
    decode(data)
    if data[1] != TYPE_CODES["claim"]:
        raise WireError("type")
    return CLAIM_DOMAIN + data[:CLAIM_SIGNED_LEN]


def release_signed_bytes(data):
    """What a RELEASE's signature covers: the domain, then every byte before it."""
    data = bytes(data)
    decode(data)
    if data[1] != TYPE_CODES["release"]:
        raise WireError("type")
    return RELEASE_DOMAIN + data[:RELEASE_SIGNED_LEN]


# --- NOTICE v1 (to lxpt.notice, LoRa) --------------------------------------------------


def encode_notice(n):
    """A NOTICE dict to its 21 bytes. ``talker`` and ``mac`` are as they travel;
    lxpt.channel.seal_notice computes them under the channel key."""
    kind = _enum(NOTICE_KIND_CODES, n["kind"])
    hop = _uint(n["hop_limit"], 8)
    if hop > NOTICE_MAX_HOP_LIMIT:
        raise WireError("field")
    return (bytes([NOTICE_VERSION, (kind << 4) | hop]) + _bytes(n["channel_tag"], TAG_LEN)
            + _bytes(n["talker"], TAG_LEN) + struct.pack(">HB", _uint(n["spurt16"], 16), _uint(n["talk_limit_s"], 8, 1))
            + _bytes(n["mac"], MAC_LEN))


def decode_notice(data):
    data = bytes(data)
    if len(data) < 1:
        raise WireError("truncated")
    if data[0] != NOTICE_VERSION:
        raise WireError("version")
    _exact(data, NOTICE_LEN)
    n = {"kind": _lookup(NOTICE_KINDS, data[1] >> 4), "hop_limit": data[1] & 0x0F,
         "channel_tag": data[2:6], "talker": data[6:10]}
    n["spurt16"], n["talk_limit_s"] = struct.unpack_from(">HB", data, 10)
    if n["talk_limit_s"] == 0:
        raise WireError("field")
    n["mac"] = data[13:21]
    return n
