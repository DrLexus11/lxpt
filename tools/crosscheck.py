#!/usr/bin/env python3
"""The cross-language gate: the Python, Kotlin and C++ suites each write one
"key value" line per fixture result (an encoding, a derived key, a signature,
or the error a refused input gave). This checks that

- every file holds exactly the keys the fixture implies, so no suite skipped
  a vector, and
- the three files are identical, so every encoding is byte-identical and every
  refusal is the same refusal in all three languages.

    python3 tools/crosscheck.py fixtures/lxpt_wire_v1.json py.txt kt.txt cpp.txt

The floor and relay fixtures beside the wire fixture are read too: each of
their scenarios is one "floor/<name>" or "relay/<name>" line, the SHA-256 of
every line that implementation's core produced for it.
"""

import json
import sys
from pathlib import Path


def expected_keys(f):
    keys = set()
    c = f["crypto"]
    for section in ("sha256", "hmac_sha256", "hkdf_sha256", "aes256_ctr", "ed25519"):
        keys |= {"crypto/%s/%d" % (section, i) for i in range(len(c[section]))}
    keys |= {"crypto/ed25519_verify/" + v["name"] for v in c["ed25519_verify"]}
    ch = f["channel"]
    for section in ("channel_ids", "hubless_ids", "channel_keys", "spurt_keys"):
        keys |= {"channel/%s/%d" % (section, i) for i in range(len(ch[section]))}
    keys |= {"channel/room_names_refused/" + v["name"] for v in ch["room_names_refused"]}
    for i, v in enumerate(ch["channel_keys"]):
        keys |= {"channel/member_tags/%d/%d" % (i, j) for j in range(len(v["members"]))}
    keys |= {"identities/" + n for n in f["identities"]}
    for section in ("messages", "decode_refused", "encode_refused", "frames", "frames_refused", "notices",
                    "notices_hop_rewritten", "notices_refused", "notice_decode_refused", "notice_encode_refused",
                    "relay_keys", "relay_binding"):
        keys |= {"%s/%s" % (section, v["name"]) for v in f[section]}
    for v in f["signed"]:
        if "seed" in v:
            keys.add("signed/" + v["name"])
        keys |= {"signed_bytes/" + v["name"], "signed_verify/" + v["name"]}
    return keys


def load(path):
    lines = [ln for ln in open(path).read().splitlines() if ln]
    out = {}
    for ln in lines:
        key, _, value = ln.partition(" ")
        if key in out:
            raise SystemExit("%s: key %s twice" % (path, key))
        out[key] = value
    return out


def main(argv):
    if len(argv) < 4:
        print(__doc__, file=sys.stderr)
        return 2
    fixture = json.load(open(argv[1]))
    want = expected_keys(fixture)
    here = Path(argv[1]).resolve().parent
    for kind in ("floor", "relay"):
        cores = json.loads((here / ("lxpt_%s_v1.json" % kind)).read_text())
        want |= {"%s/%s" % (kind, s["name"]) for s in cores["scenarios"]}
    results = {path: load(path) for path in argv[2:]}
    ok = True
    for path, got in results.items():
        missing, extra = want - set(got), set(got) - want
        if missing or extra:
            ok = False
            print("%s: %d keys missing %s, %d unexpected %s" % (path, len(missing), sorted(missing)[:5],
                                                                 len(extra), sorted(extra)[:5]))
    first_path, first = next(iter(results.items()))
    for path, got in results.items():
        diff = sorted(k for k in want if got.get(k) != first.get(k))
        if diff:
            ok = False
            print("%s and %s differ on %d keys, first: %s" % (first_path, path, len(diff), diff[:5]))
            for k in diff[:3]:
                print("  %s\n    %s: %s\n    %s: %s" % (k, first_path, first.get(k), path, got.get(k)))
    if not ok:
        return 1
    print("cross-check: %d results identical across %d implementations (%s)"
          % (len(want), len(results), ", ".join(results)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
