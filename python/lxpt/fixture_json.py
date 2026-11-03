"""The fixture's JSON form of a message: byte fields as lower-case hex, the rest as is."""

BYTE_KEYS = frozenset(("channel_tag", "talker_tag", "payload", "mac", "nonce", "public_key", "signature",
                       "member_tag", "relay_hash", "talker", "talker_prefix"))
BYTE_LIST_KEYS = frozenset(("reached", "members"))


def to_json(value, key=None):
    if isinstance(value, dict):
        return {k: to_json(v, k) for k, v in value.items()}
    if isinstance(value, list):
        if key in BYTE_LIST_KEYS:
            return [bytes(v).hex() for v in value]
        return [to_json(v) for v in value]
    if key in BYTE_KEYS and isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    return value


def from_json(value, key=None):
    if isinstance(value, dict):
        return {k: from_json(v, k) for k, v in value.items()}
    if isinstance(value, list):
        if key in BYTE_LIST_KEYS:
            return [bytes.fromhex(v) for v in value]
        return [from_json(v) for v in value]
    if key in BYTE_KEYS and isinstance(value, str):
        return bytes.fromhex(value)
    return value
