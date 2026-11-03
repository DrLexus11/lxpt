"""The Python reference against fixtures/lxpt_wire_v1.json.

Every result is also recorded as one "key value" line. With LXPT_CROSSCHECK_OUT
set, the lines are written there, and tools/crosscheck.py compares them with
the Kotlin and C++ suites' lines: the three must be identical.
"""

import json
import os
import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))

from lxpt import channel as ch  # noqa: E402
from lxpt import crypto, wire  # noqa: E402
from lxpt.fixture_json import from_json, to_json  # noqa: E402
from lxpt.wire import WireError  # noqa: E402

FIXTURE = json.loads((ROOT / "fixtures" / "lxpt_wire_v1.json").read_text())
LINES = []


def record(key, value):
    LINES.append("%s %s" % (key, value))


def B(x):
    return bytes.fromhex(x)


def error_of(fn, *args):
    try:
        fn(*args)
    except WireError as e:
        return e.code
    return "ok"


class Crypto(unittest.TestCase):
    def test_known_answers(self):
        c = FIXTURE["crypto"]
        for i, v in enumerate(c["sha256"]):
            got = crypto.sha256(B(v["message"])).hex()
            self.assertEqual(got, v["digest"])
            record("crypto/sha256/%d" % i, got)
        for i, v in enumerate(c["hmac_sha256"]):
            got = crypto.hmac_sha256(B(v["key"]), B(v["message"])).hex()
            self.assertEqual(got, v["mac"])
            record("crypto/hmac_sha256/%d" % i, got)
        for i, v in enumerate(c["hkdf_sha256"]):
            got = crypto.hkdf_sha256(B(v["ikm"]), B(v["salt"]), B(v["info"]), v["length"]).hex()
            self.assertEqual(got, v["okm"])
            record("crypto/hkdf_sha256/%d" % i, got)
        for i, v in enumerate(c["aes256_ctr"]):
            got = crypto.aes256_ctr(B(v["key"]), B(v["iv"]), B(v["plaintext"])).hex()
            self.assertEqual(got, v["ciphertext"])
            record("crypto/aes256_ctr/%d" % i, got)
        for i, v in enumerate(c["ed25519"]):
            self.assertEqual(crypto.ed25519_public_key(B(v["seed"])).hex(), v["public_key"])
            got = crypto.ed25519_sign(B(v["seed"]), B(v["message"])).hex()
            self.assertEqual(got, v["signature"])
            self.assertTrue(crypto.ed25519_verify(B(v["public_key"]), B(v["message"]), B(v["signature"])))
            record("crypto/ed25519/%d" % i, v["public_key"] + got)
        for v in c["ed25519_verify"]:
            got = crypto.ed25519_verify(B(v["public_key"]), B(v["message"]), B(v["signature"]))
            self.assertEqual(got, v["valid"], v["name"])
            record("crypto/ed25519_verify/" + v["name"], int(got))

    def test_against_cryptography(self):
        """An independent oracle, when the package is installed (CI installs it)."""
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            self.skipTest("cryptography not installed")
        rng = random.Random(1)
        for n in (0, 1, 15, 16, 17, 200):
            key, iv, data = rng.randbytes(32), rng.randbytes(16), rng.randbytes(n)
            enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
            self.assertEqual(enc.update(data) + enc.finalize(), crypto.aes256_ctr(key, iv, data))
        for n in (0, 13, 117):
            seed, msg = rng.randbytes(32), rng.randbytes(n)
            sk = Ed25519PrivateKey.from_private_bytes(seed)
            pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.assertEqual(pk, crypto.ed25519_public_key(seed))
            self.assertEqual(sk.sign(msg), crypto.ed25519_sign(seed, msg))


class Channel(unittest.TestCase):
    def test_rooms(self):
        c = FIXTURE["channel"]
        for i, v in enumerate(c["rooms"]):
            got = ch.normalize_room(B(v["input"])).hex()
            self.assertEqual(got, v["normalized"])
            record("channel/rooms/%d" % i, got)
        for v in c["rooms_refused"]:
            got = error_of(ch.normalize_room, B(v["input"]))
            self.assertEqual(got, v["error"], v["name"])
            record("channel/rooms_refused/" + v["name"], got)

    def test_ids_and_keys(self):
        c = FIXTURE["channel"]
        for i, v in enumerate(c["channel_ids"]):
            got = ch.channel_id(B(v["hub_hash"]), B(v["room"])).hex()
            self.assertEqual(got, v["channel_id"])
            record("channel/channel_ids/%d" % i, got)
        for i, v in enumerate(c["hubless_ids"]):
            got = ch.hubless_channel_id(B(v["creator_hash"]), B(v["name"])).hex()
            self.assertEqual(got, v["channel_id"])
            record("channel/hubless_ids/%d" % i, got)
        for i, v in enumerate(c["channel_keys"]):
            keys = ch.ChannelKeys(B(v["k_epoch"]), B(v["channel_id"]))
            self.assertEqual(keys.channel_tag.hex(), v["channel_tag"])
            self.assertEqual(keys.notice_key.hex(), v["notice_key"])
            record("channel/channel_keys/%d" % i, keys.channel_tag.hex() + keys.notice_key.hex())
            for j, mv in enumerate(v["members"]):
                got = keys.member_tag(B(mv["identity_hash"])).hex()
                self.assertEqual(got, mv["member_tag"])
                record("channel/member_tags/%d/%d" % (i, j), got)
        for i, v in enumerate(c["spurt_keys"]):
            sk = ch.ChannelKeys(B(v["k_epoch"]), B(v["channel_id"])).spurt_keys(
                B(v["talker_hash"]), v["spurt"], B(v["nonce"]))
            self.assertEqual(sk.enc_key.hex(), v["enc_key"])
            self.assertEqual(sk.mac_key.hex(), v["mac_key"])
            record("channel/spurt_keys/%d" % i, sk.enc_key.hex() + sk.mac_key.hex())
        for name, v in FIXTURE["identities"].items():
            self.assertEqual(ch.identity_hash(B(v["public_key"])).hex(), v["hash"])
            record("identities/" + name, v["hash"])


class Messages(unittest.TestCase):
    def test_encode_decode(self):
        for v in FIXTURE["messages"]:
            m = from_json(v["message"])
            raw = wire.encode(m)
            self.assertEqual(raw.hex(), v["hex"], v["name"])
            self.assertEqual(len(raw), v["length"])
            self.assertEqual(to_json(wire.decode(B(v["hex"]))), v["message"], v["name"])
            self.assertEqual(wire.peek_type(raw), m["type"])
            record("messages/" + v["name"], raw.hex())

    def test_decode_refused(self):
        for v in FIXTURE["decode_refused"]:
            got = error_of(wire.decode, B(v["hex"]))
            self.assertEqual(got, v["error"], v["name"])
            record("decode_refused/" + v["name"], got)

    def test_encode_refused(self):
        for v in FIXTURE["encode_refused"]:
            got = error_of(wire.encode, from_json(v["message"]))
            self.assertEqual(got, v["error"], v["name"])
            record("encode_refused/" + v["name"], got)

    def test_limits(self):
        lim = FIXTURE["limits"]
        self.assertEqual(lim["max_message_len"], wire.MAX_MESSAGE_LEN)
        self.assertEqual(lim["frame_max_payload"], wire.FRAME_MAX_PAYLOAD)
        self.assertEqual(lim["claim_len"], wire.CLAIM_LEN)
        self.assertEqual(lim["notice_len"], wire.NOTICE_LEN)

    def test_fuzz(self):
        """Mutated and random inputs only ever raise WireError, and whatever
        decodes re-encodes to the same bytes."""
        rng = random.Random(0x1A9E)
        seeds = [B(v["hex"]) for v in FIXTURE["messages"]]
        for i in range(20000):
            base = bytearray(rng.choice(seeds))
            for _ in range(rng.randint(1, 4)):
                op = rng.randrange(3)
                if op == 0 and base:
                    base[rng.randrange(len(base))] = rng.randrange(256)
                elif op == 1 and base:
                    del base[rng.randrange(len(base)):]
                else:
                    base += bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
            data = bytes(base) if i % 10 else bytes(rng.randrange(256) for _ in range(rng.randint(0, 40)))
            try:
                m = wire.decode(data)
            except WireError:
                continue
            self.assertEqual(wire.encode(m), data)
            try:
                n = wire.decode_notice(data[:21])
                self.assertEqual(wire.encode_notice(n), data[:21])
            except WireError:
                pass


class Sealed(unittest.TestCase):
    def test_frames(self):
        for v in FIXTURE["frames"]:
            keys = ch.ChannelKeys(B(v["k_epoch"]), B(v["channel_id"]))
            sk = keys.spurt_keys(B(v["talker_hash"]), v["spurt"], B(v["nonce"]))
            raw = ch.seal_frame(sk, keys.channel_tag, keys.member_tag(B(v["talker_hash"])), v["spurt"], v["seq"],
                                B(v["plaintext"]))
            self.assertEqual(raw.hex(), v["hex"], v["name"])
            m, plain = ch.open_frame(sk, raw)
            self.assertEqual(plain.hex(), v["plaintext"])
            record("frames/" + v["name"], raw.hex())
        for v in FIXTURE["frames_refused"]:
            keys = ch.ChannelKeys(B(v["k_epoch"]), B(v["channel_id"]))
            sk = keys.spurt_keys(B(v["talker_hash"]), v["spurt"], B(v["nonce"]))
            got = error_of(ch.open_frame, sk, B(v["hex"]))
            self.assertEqual(got, v["error"], v["name"])
            record("frames_refused/" + v["name"], got)

    def test_notices(self):
        for v in FIXTURE["notices"]:
            keys = ch.ChannelKeys(B(v["k_epoch"]), B(v["channel_id"]))
            raw = ch.seal_notice(keys.notice_key, v["kind"], v["hop_limit"], keys.channel_tag,
                                 B(v["talker_prefix"]), v["spurt16"], v["talk_limit_s"])
            self.assertEqual(raw.hex(), v["hex"], v["name"])
            self.assertEqual(to_json(wire.decode_notice(raw)), v["message"])
            self.assertEqual(wire.encode_notice(from_json(v["message"])), raw)
            self.assertEqual(ch.open_notice(keys.notice_key, raw)["talker_prefix"].hex(), v["talker_prefix"])
            record("notices/" + v["name"], raw.hex())
        for v in FIXTURE["notices_hop_rewritten"]:
            keys = ch.ChannelKeys(B(v["k_epoch"]), B(v["channel_id"]))
            n = ch.open_notice(keys.notice_key, B(v["hex"]))
            self.assertEqual((n["talker_prefix"].hex(), n["hop_limit"]), (v["talker_prefix"], v["hop_limit"]))
            record("notices_hop_rewritten/" + v["name"], n["talker_prefix"].hex())
        for v in FIXTURE["notices_refused"]:
            keys = ch.ChannelKeys(B(v["k_epoch"]), B(v["channel_id"]))
            got = error_of(ch.open_notice, keys.notice_key, B(v["hex"]))
            self.assertEqual(got, v["error"], v["name"])
            record("notices_refused/" + v["name"], got)
        for v in FIXTURE["notice_decode_refused"]:
            got = error_of(wire.decode_notice, B(v["hex"]))
            self.assertEqual(got, v["error"], v["name"])
            record("notice_decode_refused/" + v["name"], got)
        for v in FIXTURE["notice_encode_refused"]:
            got = error_of(wire.encode_notice, from_json(v["message"]))
            self.assertEqual(got, v["error"], v["name"])
            record("notice_encode_refused/" + v["name"], got)

    def test_signed(self):
        for v in FIXTURE["signed"]:
            raw = B(v["hex"])
            if "seed" in v:
                sign = ch.sign_claim if v["kind"] == "claim" else ch.sign_release
                got = sign(from_json(v["message"]), B(v["seed"]))
                self.assertEqual(got.hex(), v["hex"], v["name"])
                record("signed/" + v["name"], got.hex())
            span = (wire.claim_signed_bytes if v["kind"] == "claim" else wire.release_signed_bytes)(raw)
            self.assertEqual(span.hex(), v["signed_hex"])
            verify = ch.verify_claim if v["kind"] == "claim" else ch.verify_release
            got = error_of(verify, raw)
            self.assertEqual(got, v["verify"], v["name"])
            keys = ch.ChannelKeys(B(v["k_epoch"]), B(v["channel_id"]))
            member_ok = ch.claim_member_ok(keys, wire.decode(raw))
            self.assertEqual(member_ok, v["member_ok"], v["name"])
            record("signed_bytes/" + v["name"], span.hex())
            record("signed_verify/" + v["name"], "%s %d" % (got, member_ok))


class FixtureFresh(unittest.TestCase):
    def test_regenerates_identically(self):
        sys.path.insert(0, str(ROOT / "python"))
        import gen_fixture
        self.assertEqual(gen_fixture.build(), (ROOT / "fixtures" / "lxpt_wire_v1.json").read_text(),
                         "fixture is stale: run python3 python/gen_fixture.py")


def tearDownModule():
    out = os.environ.get("LXPT_CROSSCHECK_OUT")
    if out:
        Path(out).write_text("\n".join(sorted(LINES)) + "\n")


if __name__ == "__main__":
    unittest.main()
