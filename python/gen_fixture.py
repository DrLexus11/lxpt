#!/usr/bin/env python3
"""Regenerates fixtures/lxpt_wire_v1.json from the Python reference.

Everything is deterministic: identities, keys and nonces are derived from
fixed labels below and are TEST values only, never a fleet's. Run from
anywhere:

    python3 python/gen_fixture.py            # writes the fixture
    python3 python/gen_fixture.py --check    # exits 1 if the file is stale
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from lxpt import channel as ch  # noqa: E402
from lxpt import crypto, wire  # noqa: E402
from lxpt.fixture_json import to_json  # noqa: E402
from lxpt.wire import WireError  # noqa: E402

FIXTURE = HERE.parent / "fixtures" / "lxpt_wire_v1.json"


def h(label, n=32):
    """Deterministic test bytes."""
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(("lxpt wire v1 TEST " + label + " " + str(i)).encode()).digest()
        i += 1
    return out[:n]


def pattern(n, salt=0):
    return bytes((i * 37 + 11 + salt) & 0xFF for i in range(n))


# --- X25519 (RFC 7748), only to give the test identities real Reticulum public keys ---

_P = 2 ** 255 - 19


def x25519_public(private):
    k = bytearray(private)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")
    x1, x2, z2, x3, z3, swap = 9, 1, 0, 9, 1, 0
    for t in reversed(range(255)):
        bit = (k >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % _P, (x2 - z2) % _P
        aa, bb = a * a % _P, b * b % _P
        e = (aa - bb) % _P
        c, d = (x3 + z3) % _P, (x3 - z3) % _P
        da, cb = d * a % _P, c * b % _P
        x3, z3 = (da + cb) ** 2 % _P, x1 * (da - cb) ** 2 % _P
        x2, z2 = aa * bb % _P, e * (aa + 121665 * e) % _P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


assert x25519_public(bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")) == \
    bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")


def identity(label):
    x_priv, ed_seed = h("identity " + label + " x25519"), h("identity " + label + " ed25519")
    public = x25519_public(x_priv) + crypto.ed25519_public_key(ed_seed)
    return {"x25519_private": x_priv, "ed25519_seed": ed_seed, "public_key": public,
            "hash": ch.identity_hash(public)}


IDS = {name: identity(name) for name in ("commander", "talker", "listener", "relay", "outsider")}
HUB = h("hub hash", 16)
K1 = h("channel key epoch 1")
K2 = h("channel key epoch 2")
CID = ch.channel_id(HUB, "Ops")
KEYS = ch.ChannelKeys(K1, CID)
TAG = KEYS.channel_tag
TALKER = IDS["talker"]
TALKER_TAG = KEYS.member_tag(TALKER["hash"])
LISTENER_TAG = KEYS.member_tag(IDS["listener"]["hash"])
COMMANDER_TAG = KEYS.member_tag(IDS["commander"]["hash"])
NONCE = h("spurt nonce", 16)


def tags(n, salt):
    return [h("member tag %s %d" % (salt, i), 4) for i in range(n)]


def ref(tag, spurt, tier="member", emergency=False):
    return {"talker_tag": tag, "spurt": spurt, "tier": tier, "emergency": emergency}


# --- crypto known answers ------------------------------------------------------------


def crypto_section():
    out = {}
    out["sha256"] = [{"message": m.hex(), "digest": crypto.sha256(m).hex()}
                     for m in (b"", b"abc", pattern(200))]
    hm = [(bytes([0x0b] * 20), b"Hi There"), (b"Jefe", b"what do ya want for nothing?"),
          (bytes([0xaa] * 131), b"Test Using Larger Than Block-Size Key - Hash Key First"), (K1, pattern(64))]
    out["hmac_sha256"] = [{"key": k.hex(), "message": m.hex(), "mac": crypto.hmac_sha256(k, m).hex()} for k, m in hm]
    hk = [(bytes([0x0b] * 22), bytes(range(13)), bytes(range(0xf0, 0xfa)), 42),  # RFC 5869 case 1
          (bytes([0x0b] * 22), b"", b"", 42),  # RFC 5869 case 3
          (K1, NONCE, ch.SPURT_LABEL + CID + TALKER["hash"] + (7).to_bytes(4, "big"), 64)]
    out["hkdf_sha256"] = [{"ikm": i.hex(), "salt": s.hex(), "info": f.hex(), "length": n,
                           "okm": crypto.hkdf_sha256(i, s, f, n).hex()} for i, s, f, n in hk]
    sp = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                       "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
    ctr = [(bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
            bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"), sp),  # SP 800-38A F.5.5
           (K1, b"\xff" * 16, pattern(40)),  # the counter wraps through 2^128
           (K2, (513).to_bytes(2, "big") + bytes(14), pattern(17))]
    out["aes256_ctr"] = [{"key": k.hex(), "iv": iv.hex(), "plaintext": p.hex(),
                          "ciphertext": crypto.aes256_ctr(k, iv, p).hex()} for k, iv, p in ctr]
    assert out["aes256_ctr"][0]["ciphertext"].startswith("601ec313775789a5b7a7f504bbf3d228")
    seeds = [(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"), b""),  # RFC 8032 test 1
             (bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"), b"\x72"),  # test 2
             (TALKER["ed25519_seed"], pattern(104))]
    out["ed25519"] = [{"seed": s.hex(), "public_key": crypto.ed25519_public_key(s).hex(), "message": m.hex(),
                       "signature": crypto.ed25519_sign(s, m).hex()} for s, m in seeds]
    assert out["ed25519"][0]["public_key"] == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    out["ed25519_verify"] = ed25519_verify_cases(seeds[2][0], seeds[2][1])
    return out


_L = 2 ** 252 + 27742317777372353535851937790883648493


def ed25519_verify_cases(seed, msg):
    pk = crypto.ed25519_public_key(seed)
    sig = crypto.ed25519_sign(seed, msg)
    s = int.from_bytes(sig[32:], "little")
    cases = [("valid", pk, msg, sig),
             ("wrong_message", pk, msg + b"\x00", sig),
             ("flipped_r", pk, msg, bytes([sig[0] ^ 1]) + sig[1:]),
             ("flipped_s", pk, msg, sig[:40] + bytes([sig[40] ^ 1]) + sig[41:]),
             ("s_plus_l", pk, msg, sig[:32] + (s + _L).to_bytes(32, "little")),
             ("wrong_key", crypto.ed25519_public_key(IDS["outsider"]["ed25519_seed"]), msg, sig),
             # y = p, not canonical: refused even though it reduces to a point.
             ("key_not_canonical", (2 ** 255 - 19).to_bytes(32, "little"), msg, sig),
             # x = 0 with the sign bit set: not canonical.
             ("key_negative_zero", (1 | (1 << 255)).to_bytes(32, "little"), msg, sig),
             ("r_not_canonical", pk, msg, (2 ** 255 - 19).to_bytes(32, "little") + sig[32:]),
             ("key_not_on_curve", (2).to_bytes(32, "little"), msg, sig)]
    out = []
    for name, p, m, sg in cases:
        valid = crypto.ed25519_verify(p, m, sg)
        assert valid == (name == "valid"), name
        out.append({"name": name, "public_key": p.hex(), "message": m.hex(), "signature": sg.hex(), "valid": valid})
    return out


# --- channel derivations ---------------------------------------------------------------


def channel_section():
    rooms = [b"Ops", b"  #Ops Room \t", b"general", "ŞEHİR Merkez".encode(), b"\x0b\x0cMedEvac\r\n",
             b"a" * 64, b"  " + b"B" * 64 + b"  ", "çay ocağı".encode()]
    out = {"rooms": [{"input": r.hex(), "normalized": ch.normalize_room(r).hex()} for r in rooms]}
    refused = [("empty", b""), ("only_space", b" \t\r\n"), ("too_long", b"a" * 65),
               ("bad_utf8", b"\xc3\x28"), ("overlong", b"\xc0\xaf"), ("surrogate", b"\xed\xa0\x80"),
               ("past_max_code_point", b"\xf4\x90\x80\x80"), ("cut_sequence", b"ab\xe2\x82"),
               ("lone_continuation", b"\x80abc"), ("lone_a0", b"\xa0")]
    out["rooms_refused"] = []
    for name, r in refused:
        try:
            ch.normalize_room(r)
            raise AssertionError(name)
        except WireError as e:
            out["rooms_refused"].append({"name": name, "input": r.hex(), "error": e.code})
    out["channel_ids"] = [{"hub_hash": hub.hex(), "room": r.hex(), "channel_id": ch.channel_id(hub, r).hex()}
                          for hub, r in ((HUB, b"Ops"), (HUB, b"  OPS "), (HUB, b"Logistics"), (h("hub 2", 16), b"Ops"))]
    assert out["channel_ids"][0]["channel_id"] == out["channel_ids"][1]["channel_id"]
    out["hubless_ids"] = [{"creator_hash": c.hex(), "name": n.hex(), "channel_id": ch.hubless_channel_id(c, n).hex()}
                          for c, n in ((IDS["commander"]["hash"], b"Team 1"), (IDS["talker"]["hash"], b"Team 1"))]
    out["channel_keys"] = []
    for k, cid in ((K1, CID), (K2, CID), (K1, ch.channel_id(HUB, "Logistics"))):
        keys = ch.ChannelKeys(k, cid)
        out["channel_keys"].append({
            "k_epoch": k.hex(), "channel_id": cid.hex(), "channel_tag": keys.channel_tag.hex(),
            "notice_key": keys.notice_key.hex(),
            "members": [{"identity_hash": i["hash"].hex(), "member_tag": keys.member_tag(i["hash"]).hex()}
                        for i in IDS.values()]})
    out["spurt_keys"] = []
    for k, talker, spurt, nonce in ((K1, TALKER, 1, NONCE), (K1, TALKER, 2, NONCE), (K1, TALKER, 1, h("nonce b", 16)),
                                    (K2, IDS["commander"], 0xFFFFFFFF, NONCE)):
        sk = ch.ChannelKeys(k, CID).spurt_keys(talker["hash"], spurt, nonce)
        out["spurt_keys"].append({"k_epoch": k.hex(), "channel_id": CID.hex(), "talker_hash": talker["hash"].hex(),
                                  "spurt": spurt, "nonce": nonce.hex(), "enc_key": sk.enc_key.hex(),
                                  "mac_key": sk.mac_key.hex()})
    return out


# --- messages --------------------------------------------------------------------------


def message_cases():
    pk, sig = TALKER["public_key"], pattern(64, 5)
    peer_full = [{"channel_tag": TAG, "narrow": False, "members": tags(64, "full a")},
                 {"channel_tag": h("other tag a", 4), "narrow": True, "members": tags(20, "full b")},
                 {"channel_tag": h("other tag b", 4), "narrow": False, "members": tags(14, "full c")}]
    claim = {"type": "claim", "channel_tag": TAG, "talker_tag": TALKER_TAG, "spurt": 7, "epoch": 1, "nonce": NONCE,
             "tier": "member", "emergency": False, "clock_verified": True, "clock": 1793750400, "public_key": pk,
             "signature": sig}
    cases = [
        ("frame_min", {"type": "frame", "channel_tag": TAG, "talker_tag": TALKER_TAG, "spurt": 1, "seq": 0,
                       "payload": b"\x00", "mac": pattern(8)}),
        ("frame_codec2_lbw", {"type": "frame", "channel_tag": TAG, "talker_tag": TALKER_TAG, "spurt": 7, "seq": 12,
                              "payload": pattern(80, 1), "mac": pattern(8, 2)}),
        ("frame_max", {"type": "frame", "channel_tag": TAG, "talker_tag": TALKER_TAG, "spurt": 0xFFFFFFFF,
                       "seq": 0xFFFF, "payload": pattern(200, 3), "mac": pattern(8, 4)}),
        ("claim_member", claim),
        ("claim_emergency_observer", dict(claim, tier="observer", emergency=True, clock_verified=False, clock=0)),
        ("claim_extremes", dict(claim, tier="commander", spurt=0xFFFFFFFF, epoch=0xFFFFFFFF, clock=0xFFFFFFFF,
                                emergency=True)),
        ("claim_deputy", dict(claim, tier="deputy", epoch=0)),
        ("claim_leader", dict(claim, tier="leader")),
        ("grant_nobody", {"type": "grant", "channel_tag": TAG, "talker_tag": TALKER_TAG, "spurt": 7,
                          "profile": "hq", "talk_limit_s": 30, "reached": []}),
        ("grant_typical", {"type": "grant", "channel_tag": TAG, "talker_tag": TALKER_TAG, "spurt": 7,
                           "profile": "lbw", "talk_limit_s": 30, "reached": [LISTENER_TAG, COMMANDER_TAG]}),
        ("grant_max", {"type": "grant", "channel_tag": TAG, "talker_tag": TALKER_TAG, "spurt": 0xFFFFFFFF,
                       "profile": "ulbw", "talk_limit_s": 255, "reached": tags(64, "grant")}),
        ("grant_vlbw", {"type": "grant", "channel_tag": TAG, "talker_tag": TALKER_TAG, "spurt": 1,
                        "profile": "vlbw", "talk_limit_s": 1, "reached": [LISTENER_TAG]}),
        ("grant_mq", {"type": "grant", "channel_tag": TAG, "talker_tag": TALKER_TAG, "spurt": 2,
                      "profile": "mq", "talk_limit_s": 10, "reached": [LISTENER_TAG]}),
        ("busy_busy", {"type": "busy", "channel_tag": TAG, "talker_tag": LISTENER_TAG, "spurt": 3, "reason": "busy",
                       "holder": ref(TALKER_TAG, 7)}),
        ("busy_emergency_holder", {"type": "busy", "channel_tag": TAG, "talker_tag": LISTENER_TAG, "spurt": 4,
                                   "reason": "busy", "holder": ref(TALKER_TAG, 0xFFFFFFFF, "observer", True)}),
        ("busy_rate_limited", {"type": "busy", "channel_tag": TAG, "talker_tag": LISTENER_TAG, "spurt": 5,
                               "reason": "rate_limited", "holder": None}),
        ("busy_rate_limited_holder", {"type": "busy", "channel_tag": TAG, "talker_tag": LISTENER_TAG, "spurt": 6,
                                      "reason": "rate_limited", "holder": ref(TALKER_TAG, 7, "leader")}),
        ("busy_zero_tag_holder", {"type": "busy", "channel_tag": TAG, "talker_tag": LISTENER_TAG, "spurt": 6,
                                  "reason": "busy", "holder": ref(bytes(4), 1, "member")}),
        ("yield_collision", {"type": "yield", "channel_tag": TAG, "talker_tag": LISTENER_TAG, "spurt": 3,
                             "reason": "collision", "winner": ref(TALKER_TAG, 7)}),
        ("yield_preempted", {"type": "yield", "channel_tag": TAG, "talker_tag": TALKER_TAG, "spurt": 7,
                             "reason": "preempted", "winner": ref(COMMANDER_TAG, 1, "commander")}),
        ("yield_preempted_emergency", {"type": "yield", "channel_tag": TAG, "talker_tag": TALKER_TAG, "spurt": 7,
                                       "reason": "preempted", "winner": ref(LISTENER_TAG, 9, "member", True)}),
        ("release_typical", {"type": "release", "channel_tag": TAG, "talker_tag": TALKER_TAG, "spurt": 7,
                             "frame_count": 150, "public_key": pk, "signature": sig}),
        ("release_no_frames", {"type": "release", "channel_tag": TAG, "talker_tag": TALKER_TAG, "spurt": 8,
                               "frame_count": 0, "public_key": pk, "signature": sig}),
        ("release_extremes", {"type": "release", "channel_tag": TAG, "talker_tag": TALKER_TAG, "spurt": 0xFFFFFFFF,
                              "frame_count": 0xFFFF, "public_key": pk, "signature": sig}),
        ("talking_hq", {"type": "talking", "channel_tag": TAG, "holder": ref(TALKER_TAG, 7), "profile": "hq",
                        "talk_limit_s": 30}),
        ("talking_emergency", {"type": "talking", "channel_tag": TAG,
                               "holder": ref(LISTENER_TAG, 0xFFFFFFFF, "observer", True), "profile": "lbw",
                               "talk_limit_s": 255}),
        ("talking_ulbw", {"type": "talking", "channel_tag": TAG, "holder": ref(COMMANDER_TAG, 1, "commander"),
                          "profile": "ulbw", "talk_limit_s": 1}),
        ("sub_leave_all", {"type": "sub", "carrier": "ip", "entries": []}),
        ("sub_typical", {"type": "sub", "carrier": "ble", "entries": [
            {"channel_tag": TAG, "member_tag": TALKER_TAG, "mode": "voice"},
            {"channel_tag": h("tag b", 4), "member_tag": h("member b", 4), "mode": "voice"},
            {"channel_tag": h("tag watch", 4), "member_tag": h("member watch", 4), "mode": "watch"}]}),
        ("sub_gfsk", {"type": "sub", "carrier": "gfsk", "entries": [
            {"channel_tag": TAG, "member_tag": TALKER_TAG, "mode": "watch"}]}),
        ("sub_max_halow", {"type": "sub", "carrier": "halow", "entries": [
            {"channel_tag": h("sub tag %d" % i, 4), "member_tag": h("sub member %d" % i, 4),
             "mode": "voice" if i % 3 else "watch"} for i in range(32)]}),
        ("peer_empty", {"type": "peer", "relay_hash": IDS["relay"]["hash"], "stall_p99_ms": 0, "channels": []}),
        ("peer_typical", {"type": "peer", "relay_hash": IDS["relay"]["hash"], "stall_p99_ms": 4200, "channels": [
            {"channel_tag": TAG, "narrow": True, "members": [LISTENER_TAG, COMMANDER_TAG]},
            {"channel_tag": h("tag b", 4), "narrow": False, "members": []}]}),
        ("peer_max_channels", {"type": "peer", "relay_hash": IDS["relay"]["hash"], "stall_p99_ms": 0xFFFF,
                               "channels": [{"channel_tag": h("peer tag %d" % i, 4), "narrow": bool(i % 2),
                                             "members": []} for i in range(32)]}),
        ("peer_full", {"type": "peer", "relay_hash": IDS["relay"]["hash"], "stall_p99_ms": 18200,
                       "channels": peer_full}),
        ("heard_none", {"type": "heard", "channel_tag": TAG, "talker_tag": TALKER_TAG, "spurt": 7, "heard": []}),
        ("heard_one", {"type": "heard", "channel_tag": TAG, "talker_tag": TALKER_TAG, "spurt": 7,
                       "heard": [{"member_tag": LISTENER_TAG, "frames": 148}]}),
        ("heard_max", {"type": "heard", "channel_tag": TAG, "talker_tag": TALKER_TAG, "spurt": 0xFFFFFFFF,
                       "heard": [{"member_tag": t, "frames": (i * 1031) & 0xFFFF}
                                 for i, t in enumerate(tags(63, "heard"))] + [{"member_tag": h("last", 4),
                                                                              "frames": 0xFFFF}]}),
    ]
    out = []
    for name, m in cases:
        raw = wire.encode(m)
        back = wire.decode(raw)
        assert back == m, name
        out.append({"name": name, "message": to_json(m), "hex": raw.hex(), "length": len(raw)})
    assert next(c for c in out if c["name"] == "peer_full")["length"] == wire.MAX_MESSAGE_LEN
    return out


def set_at(b, at, value):
    b = bytearray(b)
    b[at:at + len(value)] = value
    return bytes(b)


def decode_refused(messages):
    raw = {c["name"]: bytes.fromhex(c["hex"]) for c in messages}
    frame, claim, grant = raw["frame_codec2_lbw"], raw["claim_member"], raw["grant_typical"]
    busy, yld, release, talking = raw["busy_busy"], raw["yield_collision"], raw["release_typical"], raw["talking_hq"]
    sub, peer, heard = raw["sub_typical"], raw["peer_typical"], raw["heard_one"]
    cases = [
        ("empty", b"", "truncated"),
        ("version_only", b"\x01", "truncated"),
        ("version_zero", set_at(frame, 0, b"\x00"), "version"),
        ("version_two", set_at(claim, 0, b"\x02"), "version"),
        ("version_two_alone", b"\x02", "version"),
        ("type_zero", set_at(frame, 1, b"\x00"), "type"),
        ("type_eleven", set_at(frame, 1, b"\x0b"), "type"),
        ("type_ff", b"\x01\xff", "type"),
        ("over_max_message", b"\x01\x01" + bytes(430), "oversize"),
        ("over_max_message_grant", b"\x01\x03" + bytes(430), "oversize"),
        ("frame_no_payload", frame[:16] + frame[-8:], "truncated"),
        ("frame_header_only", frame[:16], "truncated"),
        ("frame_payload_201", frame[:16] + pattern(201) + frame[-8:], "oversize"),
        ("frame_spurt_zero", set_at(frame, 10, bytes(4)), "field"),
        ("claim_short", claim[:-1], "truncated"),
        ("claim_long", claim + b"\x00", "oversize"),
        ("claim_spurt_zero", set_at(claim, 10, bytes(4)), "field"),
        ("claim_tier_zero", set_at(claim, 34, b"\x00"), "field"),
        ("claim_tier_six", set_at(claim, 34, b"\x06"), "field"),
        ("claim_reserved_flag", set_at(claim, 35, b"\x04"), "field"),
        ("claim_high_flag", set_at(claim, 35, b"\x83"), "field"),
        ("grant_header_short", grant[:16], "truncated"),
        ("grant_missing_tag", grant[:-4], "truncated"),
        ("grant_partial_tag", grant[:-1], "truncated"),
        ("grant_extra_byte", grant + b"\x00", "oversize"),
        ("grant_count_65", set_at(grant[:17], 16, b"\x41") + bytes(4 * 65), "field"),
        ("grant_count_255", set_at(grant[:17], 16, b"\xff"), "field"),
        ("grant_profile_shq", set_at(grant, 14, b"\x60"), "field"),
        ("grant_profile_zero", set_at(grant, 14, b"\x00"), "field"),
        ("grant_talk_limit_zero", set_at(grant, 15, b"\x00"), "field"),
        ("grant_spurt_zero", set_at(grant, 10, bytes(4)), "field"),
        ("busy_short", busy[:-1], "truncated"),
        ("busy_long", busy + b"\x00", "oversize"),
        ("busy_reason_zero", set_at(busy, 14, b"\x00"), "field"),
        ("busy_reason_three", set_at(busy, 14, b"\x03"), "field"),
        ("busy_busy_without_holder", set_at(busy, 15, bytes(10)), "field"),
        ("busy_holder_spurt_zero", set_at(busy, 19, bytes(4)), "field"),
        ("busy_holder_tier_zero", set_at(busy, 23, b"\x00"), "field"),
        ("busy_holder_flag_reserved", set_at(busy, 24, b"\x02"), "field"),
        ("busy_none_holder_with_flag", set_at(set_at(busy, 14, b"\x02"), 15, bytes(9) + b"\x01"), "field"),
        ("yield_short", yld[:-1], "truncated"),
        ("yield_reason_three", set_at(yld, 14, b"\x03"), "field"),
        ("yield_no_winner", set_at(yld, 15, bytes(10)), "field"),
        ("yield_winner_tier_six", set_at(yld, 23, b"\x06"), "field"),
        ("release_short", release[:-1], "truncated"),
        ("release_long", release + b"\x00", "oversize"),
        ("release_spurt_zero", set_at(release, 10, bytes(4)), "field"),
        ("talking_short", talking[:-1], "truncated"),
        ("talking_long", talking + b"\x00", "oversize"),
        ("talking_no_holder", set_at(talking, 6, bytes(10)), "field"),
        ("talking_profile_ll", set_at(talking, 16, b"\x80"), "field"),
        ("talking_talk_limit_zero", set_at(talking, 17, b"\x00"), "field"),
        ("sub_header_short", sub[:3], "truncated"),
        ("sub_missing_entry_byte", sub[:-1], "truncated"),
        ("sub_extra_byte", sub + b"\x00", "oversize"),
        ("sub_count_33", set_at(sub[:4], 3, b"\x21"), "field"),
        ("sub_carrier_zero", set_at(sub, 2, b"\x00"), "field"),
        ("sub_carrier_five", set_at(sub, 2, b"\x05"), "field"),
        ("sub_mode_zero", set_at(sub, 12, b"\x00"), "field"),
        ("sub_mode_three", set_at(sub, 21, b"\x03"), "field"),
        ("peer_header_short", peer[:20], "truncated"),
        ("peer_channel_cut", peer[:21 + 5], "truncated"),
        ("peer_members_cut", peer[:21 + 6 + 7], "truncated"),
        ("peer_second_channel_missing", peer[:21 + 14], "truncated"),
        ("peer_extra_byte", peer + b"\x00", "oversize"),
        ("peer_channels_33", set_at(peer[:21], 20, b"\x21"), "field"),
        ("peer_members_65", set_at(peer, 26, b"\x41"), "field"),
        ("peer_flag_reserved", set_at(peer, 25, b"\x03"), "field"),
        ("heard_header_short", heard[:14], "truncated"),
        ("heard_entry_cut", heard[:-1], "truncated"),
        ("heard_extra_byte", heard + b"\x00", "oversize"),
        ("heard_count_65", set_at(heard[:15], 14, b"\x41"), "field"),
        ("heard_spurt_zero", set_at(heard, 10, bytes(4)), "field"),
    ]
    out = []
    for name, data, code in cases:
        try:
            wire.decode(data)
            raise AssertionError(name + " decoded")
        except WireError as e:
            assert e.code == code, (name, e.code, code)
        out.append({"name": name, "hex": data.hex(), "error": code})
    return out


def encode_refused(messages):
    msg = {c["name"]: c["message"] for c in messages}

    def edit(name, **changes):
        return dict(msg[name], **changes)

    pf = msg["peer_full"]
    over = dict(pf, channels=pf["channels"] + [{"channel_tag": "00000000", "narrow": False, "members": []}])
    cases = [
        ("unknown_type", {"type": "notice"}, "type"),
        ("frame_empty_payload", edit("frame_min", payload=""), "field"),
        ("frame_payload_201", edit("frame_min", payload=pattern(201).hex()), "oversize"),
        ("frame_spurt_zero", edit("frame_min", spurt=0), "field"),
        ("frame_spurt_too_big", edit("frame_min", spurt=1 << 32), "field"),
        ("frame_seq_too_big", edit("frame_min", seq=65536), "field"),
        ("frame_short_tag", edit("frame_min", channel_tag="010203"), "field"),
        ("frame_short_mac", edit("frame_min", mac="00" * 7), "field"),
        ("claim_unknown_tier", edit("claim_member", tier="chief"), "field"),
        ("claim_epoch_too_big", edit("claim_member", epoch=1 << 32), "field"),
        ("claim_short_nonce", edit("claim_member", nonce="00" * 15), "field"),
        ("claim_short_public_key", edit("claim_member", public_key="00" * 32), "field"),
        ("grant_65_reached", edit("grant_max", reached=msg["grant_max"]["reached"] + ["00000000"]), "field"),
        ("grant_profile_shq", edit("grant_typical", profile="shq"), "field"),
        ("grant_talk_limit_zero", edit("grant_typical", talk_limit_s=0), "field"),
        ("grant_talk_limit_256", edit("grant_typical", talk_limit_s=256), "field"),
        ("busy_busy_without_holder", edit("busy_busy", holder=None), "field"),
        ("busy_unknown_reason", edit("busy_busy", reason="later"), "field"),
        ("busy_holder_spurt_zero", edit("busy_busy", holder=dict(msg["busy_busy"]["holder"], spurt=0)), "field"),
        ("yield_without_winner", edit("yield_collision", winner=None), "field"),
        ("yield_winner_unknown_tier", edit("yield_collision", winner=dict(msg["yield_collision"]["winner"],
                                                                           tier="chief")), "field"),
        ("talking_without_holder", edit("talking_hq", holder=None), "field"),
        ("release_frame_count_too_big", edit("release_typical", frame_count=65536), "field"),
        ("sub_33_entries", edit("sub_max_halow", entries=msg["sub_max_halow"]["entries"] +
                                [msg["sub_max_halow"]["entries"][0]]), "field"),
        ("sub_unknown_carrier", edit("sub_typical", carrier="lora"), "field"),
        ("sub_unknown_mode", edit("sub_gfsk", entries=[dict(msg["sub_gfsk"]["entries"][0], mode="listen")]), "field"),
        ("peer_33_channels", edit("peer_max_channels", channels=msg["peer_max_channels"]["channels"] +
                                  [msg["peer_max_channels"]["channels"][0]]), "field"),
        ("peer_65_members", edit("peer_typical", channels=[{"channel_tag": "00000000", "narrow": False,
                                                            "members": ["00000000"] * 65}]), "field"),
        ("peer_over_max_message", over, "oversize"),
        ("peer_stall_too_big", edit("peer_empty", stall_p99_ms=65536), "field"),
        ("peer_short_relay_hash", edit("peer_empty", relay_hash="00" * 15), "field"),
        ("heard_65_entries", edit("heard_max", heard=msg["heard_max"]["heard"] + [msg["heard_max"]["heard"][0]]),
         "field"),
        ("heard_frames_too_big", edit("heard_one", heard=[{"member_tag": "00000000", "frames": 65536}]), "field"),
    ]
    from lxpt.fixture_json import from_json
    out = []
    for name, m, code in cases:
        try:
            wire.encode(from_json(m))
            raise AssertionError(name + " encoded")
        except WireError as e:
            assert e.code == code, (name, e.code, code)
        out.append({"name": name, "message": m, "error": code})
    return out


# --- sealed frames and notices ---------------------------------------------------------


def frames_section():
    cases = [("seq0_one_byte", K1, TALKER, 1, NONCE, 0, b"\x42"),
             ("lbw_80", K1, TALKER, 7, NONCE, 12, pattern(80, 9)),
             ("partial_block_17", K1, TALKER, 7, NONCE, 13, pattern(17, 10)),
             ("max_200_last_seq", K2, IDS["commander"], 0xFFFFFFFF, h("nonce max", 16), 0xFFFF, pattern(200, 11))]
    out, sealed = [], {}
    for name, k, talker, spurt, nonce, seq, plain in cases:
        keys = ch.ChannelKeys(k, CID)
        sk = keys.spurt_keys(talker["hash"], spurt, nonce)
        raw = ch.seal_frame(sk, keys.channel_tag, keys.member_tag(talker["hash"]), spurt, seq, plain)
        m, back = ch.open_frame(sk, raw)
        assert back == plain
        sealed[name] = (raw, k, talker, spurt, nonce)
        out.append({"name": name, "k_epoch": k.hex(), "channel_id": CID.hex(), "talker_hash": talker["hash"].hex(),
                    "spurt": spurt, "nonce": nonce.hex(), "seq": seq, "plaintext": plain.hex(), "hex": raw.hex()})
    raw, k, talker, spurt, nonce = sealed["lbw_80"]
    ref_case = {"k_epoch": k.hex(), "channel_id": CID.hex(), "talker_hash": talker["hash"].hex(), "spurt": spurt}
    bad = [("flipped_ciphertext", set_at(raw, 20, bytes([raw[20] ^ 1])), nonce),
           ("flipped_mac", set_at(raw, len(raw) - 1, bytes([raw[-1] ^ 0x80])), nonce),
           ("flipped_seq", set_at(raw, 15, bytes([raw[15] ^ 1])), nonce),
           ("flipped_talker_tag", set_at(raw, 6, bytes([raw[6] ^ 1])), nonce),
           ("other_nonce", raw, h("nonce b", 16)),
           ("cut_payload", raw[:40] + raw[-8:], nonce)]
    refused = []
    for name, data, n in bad:
        sk = ch.ChannelKeys(k, CID).spurt_keys(talker["hash"], spurt, n)
        try:
            ch.open_frame(sk, data)
            raise AssertionError(name)
        except WireError as e:
            assert e.code == "mac", (name, e.code)
        refused.append(dict(ref_case, name=name, nonce=n.hex(), hex=data.hex(), error="mac"))
    return out, refused


def notices_section():
    keys = ch.ChannelKeys(K1, CID)
    prefix = TALKER["hash"][:4]
    cases = [("start", "start", 1, prefix, 7, 30), ("preempt", "preempt", 1, IDS["commander"]["hash"][:4], 1, 30),
             ("emergency", "emergency", 1, IDS["listener"]["hash"][:4], 0xFFFF, 255),
             ("hop_zero", "start", 0, prefix, 0, 1), ("hop_max", "start", 15, prefix, 8, 20)]
    out, by_name = [], {}
    for name, kind, hop, pre, s16, limit in cases:
        raw = ch.seal_notice(keys.notice_key, kind, hop, keys.channel_tag, pre, s16, limit)
        n = ch.open_notice(keys.notice_key, raw)
        assert n["talker_prefix"] == pre and n["talker"] != pre
        by_name[name] = raw
        out.append({"name": name, "k_epoch": K1.hex(), "channel_id": CID.hex(), "kind": kind, "hop_limit": hop,
                    "talker_prefix": pre.hex(), "spurt16": s16, "talk_limit_s": limit, "hex": raw.hex(),
                    "message": to_json(wire.decode_notice(raw))})
    # A later hop may lower the hop limit without the key; the MAC still holds.
    lowered = set_at(by_name["hop_max"], 1, bytes([(by_name["hop_max"][1] & 0xF0) | 3]))
    assert ch.open_notice(keys.notice_key, lowered)["talker_prefix"] == prefix
    hop_rewritten = [{"name": "hop_lowered", "k_epoch": K1.hex(), "channel_id": CID.hex(), "hex": lowered.hex(),
                      "talker_prefix": prefix.hex(), "hop_limit": 3}]
    start = by_name["start"]
    bad = [("flipped_talker", set_at(start, 7, bytes([start[7] ^ 1])), K1),
           ("flipped_spurt", set_at(start, 11, bytes([start[11] ^ 1])), K1),
           ("flipped_limit", set_at(start, 12, bytes([start[12] ^ 1])), K1),
           ("kind_changed", set_at(start, 1, bytes([0x30 | (start[1] & 0x0F)])), K1),
           ("flipped_mac", set_at(start, 20, bytes([start[20] ^ 1])), K1),
           ("other_epoch", start, K2)]
    refused = []
    for name, data, k in bad:
        try:
            ch.open_notice(ch.ChannelKeys(k, CID).notice_key, data)
            raise AssertionError(name)
        except WireError as e:
            assert e.code == "mac", (name, e.code)
        refused.append({"name": name, "k_epoch": k.hex(), "channel_id": CID.hex(), "hex": data.hex(), "error": "mac"})
    structural = [("empty", b"", "truncated"), ("version_two", set_at(start, 0, b"\x02"), "version"),
                  ("short", start[:-1], "truncated"), ("long", start + b"\x00", "oversize"),
                  ("kind_zero", set_at(start, 1, b"\x01"), "field"), ("kind_four", set_at(start, 1, b"\x41"), "field"),
                  ("kind_f", set_at(start, 1, b"\xf1"), "field"), ("talk_limit_zero", set_at(start, 12, b"\x00"), "field")]
    decode_bad = []
    for name, data, code in structural:
        try:
            wire.decode_notice(data)
            raise AssertionError(name)
        except WireError as e:
            assert e.code == code, (name, e.code)
        decode_bad.append({"name": name, "hex": data.hex(), "error": code})
    enc_bad = []
    base = {"kind": "start", "hop_limit": 1, "channel_tag": TAG.hex(), "talker": prefix.hex(), "spurt16": 7,
            "talk_limit_s": 30, "mac": "00" * 8}
    for name, change, code in (("hop_16", {"hop_limit": 16}, "field"), ("kind_unknown", {"kind": "stop"}, "field"),
                               ("talk_limit_zero", {"talk_limit_s": 0}, "field"),
                               ("spurt16_too_big", {"spurt16": 65536}, "field")):
        m = dict(base, **change)
        from lxpt.fixture_json import from_json
        try:
            wire.encode_notice(from_json(m))
            raise AssertionError(name)
        except WireError as e:
            assert e.code == code
        enc_bad.append({"name": name, "message": m, "error": code})
    return out, hop_rewritten, refused, decode_bad, enc_bad


# --- signatures ------------------------------------------------------------------------


def signed_section():
    claim = {"type": "claim", "channel_tag": TAG, "talker_tag": TALKER_TAG, "spurt": 7, "epoch": 1, "nonce": NONCE,
             "tier": "member", "emergency": False, "clock_verified": True, "clock": 1793750400,
             "public_key": TALKER["public_key"]}
    release = {"type": "release", "channel_tag": TAG, "talker_tag": TALKER_TAG, "spurt": 7, "frame_count": 150,
               "public_key": TALKER["public_key"]}
    cmd = IDS["commander"]
    cases = [("claim_member", "claim", claim, TALKER),
             ("claim_commander_emergency", "claim",
              dict(claim, talker_tag=COMMANDER_TAG, tier="commander", emergency=True, spurt=1,
                   public_key=cmd["public_key"], nonce=h("nonce cmd", 16)), cmd),
             ("release_typical", "release", release, TALKER),
             ("release_no_frames", "release", dict(release, spurt=8, frame_count=0), TALKER)]
    out, good = [], {}
    for name, kind, m, who in cases:
        sign = ch.sign_claim if kind == "claim" else ch.sign_release
        raw = sign(m, who["ed25519_seed"])
        verify = ch.verify_claim if kind == "claim" else ch.verify_release
        verify(raw)
        span = (wire.claim_signed_bytes if kind == "claim" else wire.release_signed_bytes)(raw)
        good[name] = raw
        out.append({"name": name, "kind": kind, "seed": who["ed25519_seed"].hex(), "message": to_json(m),
                    "hex": raw.hex(), "signed_hex": span.hex(), "verify": "ok",
                    "k_epoch": K1.hex(), "channel_id": CID.hex(), "member_ok": True})
    # Tampered: each still decodes, and each fails the signature (or the member check).
    c, r = good["claim_member"], good["release_typical"]
    tampered = [("claim_spurt_changed", "claim", set_at(c, 13, b"\x08"), "signature", True),
                ("claim_emergency_added", "claim", set_at(c, 35, b"\x03"), "signature", True),
                ("claim_tier_raised", "claim", set_at(c, 34, b"\x01"), "signature", True),
                ("claim_flipped_signature", "claim", set_at(c, 110, bytes([c[110] ^ 1])), "signature", True),
                ("claim_other_public_key", "claim", set_at(c, 40, IDS["outsider"]["public_key"]), "signature", False),
                ("release_frame_count_changed", "release", set_at(r, 15, b"\x00"), "signature", True),
                ("release_flipped_signature", "release", set_at(r, 143, bytes([r[143] ^ 1])), "signature", True)]
    keys = KEYS
    for name, kind, raw, code, member_ok in tampered:
        verify = ch.verify_claim if kind == "claim" else ch.verify_release
        try:
            verify(raw)
            raise AssertionError(name)
        except WireError as e:
            assert e.code == code, (name, e.code)
        m = wire.decode(raw)
        assert ch.claim_member_ok(keys, m) == member_ok, name
        span = (wire.claim_signed_bytes if kind == "claim" else wire.release_signed_bytes)(raw)
        out.append({"name": name, "kind": kind, "hex": raw.hex(), "signed_hex": span.hex(), "verify": code,
                    "k_epoch": K1.hex(), "channel_id": CID.hex(), "member_ok": member_ok})
    # A genuine signature by someone whose member tag is not the claim's tag.
    forged = ch.sign_claim(dict(claim, public_key=IDS["outsider"]["public_key"]), IDS["outsider"]["ed25519_seed"])
    m = wire.decode(forged)
    assert not ch.claim_member_ok(keys, m)
    out.append({"name": "claim_outsider_with_talker_tag", "kind": "claim", "seed": IDS["outsider"]["ed25519_seed"].hex(),
                "message": to_json(dict(claim, public_key=IDS["outsider"]["public_key"])), "hex": forged.hex(),
                "signed_hex": wire.claim_signed_bytes(forged).hex(), "verify": "ok", "k_epoch": K1.hex(),
                "channel_id": CID.hex(), "member_ok": False})
    return out


def build():
    messages = message_cases()
    frames, frames_refused = frames_section()
    notices, notices_hop, notices_refused, notice_decode_refused, notice_encode_refused = notices_section()
    fixture = {
        "note": ("lxpt wire v1 and NOTICE v1 (spec/wire-v1.md). Generated by python/gen_fixture.py from the Python "
                 "reference; every value is a TEST value derived from fixed labels, never a fleet key or identity. "
                 "Byte fields are lower-case hex. 'messages': structural encode/decode vectors (signatures and MACs "
                 "there are filler bytes). 'decode_refused'/'encode_refused': the error each must give. 'frames': "
                 "FRAMEs sealed under the spurt keys derived from k_epoch, channel_id, talker_hash, spurt and nonce. "
                 "'notices': NOTICEs sealed under the channel's notice key. 'signed': CLAIMs and RELEASEs signed "
                 "with Ed25519 by the 'seed' given; 'member_ok' is whether the talker tag is the signer's member "
                 "tag under k_epoch and channel_id."),
        "wire_version": wire.VERSION,
        "notice_version": wire.NOTICE_VERSION,
        "limits": {"max_message_len": wire.MAX_MESSAGE_LEN, "frame_max_payload": wire.FRAME_MAX_PAYLOAD,
                   "frame_max_len": wire.FRAME_MAX_LEN, "claim_len": wire.CLAIM_LEN,
                   "release_len": wire.RELEASE_LEN, "busy_len": wire.BUSY_LEN, "yield_len": wire.YIELD_LEN,
                   "talking_len": wire.TALKING_LEN, "notice_len": wire.NOTICE_LEN,
                   "grant_max_reached": wire.GRANT_MAX_REACHED, "sub_max_entries": wire.SUB_MAX_ENTRIES,
                   "peer_max_channels": wire.PEER_MAX_CHANNELS, "peer_max_members": wire.PEER_MAX_MEMBERS,
                   "heard_max_entries": wire.HEARD_MAX_ENTRIES},
        "identities": {name: {"ed25519_seed": i["ed25519_seed"].hex(), "public_key": i["public_key"].hex(),
                              "hash": i["hash"].hex()} for name, i in IDS.items()},
        "crypto": crypto_section(),
        "channel": channel_section(),
        "messages": messages,
        "decode_refused": decode_refused(messages),
        "encode_refused": encode_refused(messages),
        "frames": frames,
        "frames_refused": frames_refused,
        "notices": notices,
        "notices_hop_rewritten": notices_hop,
        "notices_refused": notices_refused,
        "notice_decode_refused": notice_decode_refused,
        "notice_encode_refused": notice_encode_refused,
        "signed": signed_section(),
    }
    return json.dumps(fixture, indent=1, ensure_ascii=True) + "\n"


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--check", action="store_true", help="exit 1 if the fixture on disk differs")
    a = p.parse_args()
    text = build()
    if a.check:
        if FIXTURE.read_text() != text:
            print("fixtures/lxpt_wire_v1.json is stale: run python3 python/gen_fixture.py", file=sys.stderr)
            return 1
        print("fixture up to date")
        return 0
    FIXTURE.write_text(text)
    print("wrote", FIXTURE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
