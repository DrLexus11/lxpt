# lxpt wire v1 and NOTICE v1

This is the byte-level contract of lxpt's messages. Three implementations
follow it: the Python reference (`python/lxpt`), Kotlin (`kotlin/`) and
header-only C++ (`cpp/include/lxpt`). `fixtures/lxpt_wire_v1.json` pins it, and
CI checks that all three give the same bytes and the same refusals for every
vector.

This document covers the wire only. It does not cover floor control: when a
relay grants, how claims are ordered, the timers, or what a relay forwards.
Those come in the floor and relay cores. Fields those cores need appear here,
but their meaning beyond the bytes is defined there.

## 1. Conventions

- **Byte order.** Every integer is unsigned and big-endian. `u8`, `u16` and
  `u32` are 1, 2 and 4 bytes.
- **Version byte.** Byte 0 of every message is its format's version: `0x01`
  for wire v1, and `0x01` for NOTICE v1. The two formats travel to different
  destinations, so they never meet in one decoder. A decoder refuses any other
  version with `version`. A new layout gets a new version byte; v1 is never
  reinterpreted.
- **Destinations.** Wire v1 messages are the payloads of Reticulum PLAIN
  packets to `lxpt.talk`, or of a link to a relay's `lxpt.relay`. NOTICE v1
  is the payload of a PLAIN packet to `lxpt.notice`, sent on LoRa only.
- **Maximum length.** A wire v1 message is at most **431 bytes**, which is a
  Reticulum link's MDU, so every message fits on a link leg as well as in a
  PLAIN packet (MDU 464). A NOTICE is exactly 21 bytes.
- **Tags** are 4 bytes and opaque to a relay. A *channel tag* names a channel
  and a *member tag* names a member, both keyed by the channel key (section 3).
- **Spurt ids** are a talker's `u32` counter, one per key-up. **0 is never a
  spurt.** A decoder refuses a spurt field of 0 with `field`, except where a
  holder is absent (SpurtRef, below).
- **Identities** are Reticulum identities. A public key is 64 bytes: the
  X25519 key, then the Ed25519 key. An identity hash is
  `SHA-256(public key)[:16]`. Signatures are Ed25519, made by the second half.

### Errors

Decoders and encoders refuse with one of these codes:

| Code | Meaning |
| --- | --- |
| `truncated` | fewer bytes than the layout needs |
| `oversize` | more bytes than the layout allows, or a message past 431 bytes |
| `version` | byte 0 is not this format's version |
| `type` | byte 1 is not a wire v1 type (or, for an encoder, an unknown message) |
| `field` | a field outside its range, an unknown enumeration value, a reserved bit set, or a count past its limit |
| `mac` | a FRAME's or NOTICE's MAC does not hold under the key given |
| `signature` | a CLAIM's or RELEASE's signature does not verify |

The C++ API adds `buffer` when the caller's output buffer is too small. The
fixture never expects it.

**A decoder checks in this order**, and reports the first failure:

1. empty input: `truncated`;
2. byte 0 not `0x01`: `version`;
3. only one byte: `truncated`;
4. byte 1 not in 1..10: `type`;
5. longer than 431 bytes: `oversize`;
6. the type's own rule (below). Fixed-length types check their exact length
   first (short is `truncated`, long is `oversize`), then fields. Types with a
   count read the count as soon as its byte is present. A count past the
   limit is `field`, before the length is judged against it.

NOTICE decoding is: empty `truncated`, version, exact length 21, then fields.

## 2. Shared pieces

### Enumerations

| Name | Values |
| --- | --- |
| tier | 1 commander, 2 deputy, 3 leader, 4 member, 5 observer (ICS order; a lower number is a higher tier) |
| profile | LXST's profile ids: `0x10` ULBW (Codec2 700C), `0x20` VLBW (Codec2 1600), `0x30` LBW (Codec2 3200), `0x40` MQ (Opus 8 kbit/s), `0x50` HQ (Opus 16 kbit/s) |
| carrier | 1 ip (Wi-Fi, TCP, UDP, Auto), 2 ble, 3 gfsk, 4 halow |
| sub mode | 1 voice, 2 watch |
| busy reason | 1 busy, 2 rate_limited |
| yield reason | 1 collision, 2 preempted |
| notice kind | 1 start, 2 preempt, 3 emergency |

Any other value is `field`. A carrier is the kind of leg, never a bitrate.
`ble` and `gfsk` are narrow, and `ip` and `halow` are wide (HaLow counts as
Wi-Fi for the codec rule).

### SpurtRef (10 bytes)

This names who holds or won a spurt. BUSY, YIELD and TALKING carry it.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | talker tag |
| 4 | u32 | spurt (never 0) |
| 8 | u8 | tier |
| 9 | u8 | flags: bit 0 emergency; bits 1-7 zero |

Ten zero bytes mean *no holder*, and that is the only form an absent
SpurtRef takes. Any other SpurtRef with spurt 0, an unknown tier or a reserved
flag is `field`. A talker tag of four zero bytes is a valid tag, so it is
allowed.

## 3. Derivations

All of these take the 32-byte channel key of one epoch, `k_epoch`, and the
8-byte `channel_id`. Labels are ASCII strings with no terminator. They are
prefix-free among those used under the same key.

| Value | Definition |
| --- | --- |
| normalised room | RRC's `normalize_room`, byte for byte: trim bytes `0x20` and `0x09`-`0x0d` at both ends, map `A`-`Z` to `a`-`z`, keep every other byte. Must then be 1-64 bytes of strict UTF-8 (no overlong forms, no surrogates, nothing past U+10FFFF), else `field` |
| `channel_id` | `SHA-256("lxpt/ch/v1" ‖ hub identity hash ‖ normalised room)[:8]` |
| hubless `channel_id` | `SHA-256("lxpt/hubless/v1" ‖ creator identity hash ‖ normalised name)[:8]` |
| channel tag | `HMAC-SHA256(k_epoch, "lxpt/v1/tag" ‖ channel_id)[:4]` |
| member tag | `HMAC-SHA256(k_epoch, "lxpt/v1/member" ‖ channel_id ‖ identity hash)[:4]` |
| notice key | `HMAC-SHA256(k_epoch, "lxpt/v1/notice-key" ‖ channel_id)` (32 bytes) |
| spurt keys | `HKDF-SHA256(ikm = k_epoch, salt = nonce, info = "lxpt/v1/spurt" ‖ channel_id ‖ talker identity hash ‖ u32 spurt, L = 64)`: bytes 0-31 are the AES-256 key, bytes 32-63 the HMAC key |

**FRAME sealing.** The payload is AES-256-CTR under the spurt's AES key. The
initial counter block is `u16 seq ‖ 14 zero bytes`, and the whole 16-byte
block is incremented as one big-endian integer per 16-byte block (SP 800-38A).
A payload of 200 bytes or fewer takes at most 13 blocks, so the counter never
reaches the sequence bytes. The MAC is
`HMAC-SHA256(spurt HMAC key, the 16-byte header ‖ ciphertext)[:8]`, so the
scheme is encrypt-then-MAC. One key per (talker, spurt, nonce) and one
counter block per sequence number mean keystream never repeats while a
spurt's `seq` does not wrap. The talk limit (at most 255 s) keeps it far from
wrapping: 65,536 frames is over an hour at the shortest v1 frame (60 ms).

**NOTICE sealing.** Let `p` be the 21 bytes with the plain talker prefix in
bytes 6-9 and zeros in the MAC.

- MAC = `HMAC-SHA256(notice key, "lxpt/v1/notice-mac" ‖ p[0] ‖ (p[1] & 0xF0) ‖ p[2:13])[:8]`.
  The hop limit (the low nibble of byte 1) is left out, so a later hop can
  lower it without the key.
- Pad = `HMAC-SHA256(notice key, "lxpt/v1/notice-talker" ‖ MAC)[:4]`. The
  talker field on the wire is the prefix XOR the pad.

This is a synthetic-IV construction. Equal notices give equal bytes, and
anything else gives an unrelated pad. To open a NOTICE, compute the pad from
the received MAC, recover the prefix, and recompute and compare the MAC
(constant-time). The talker prefix is the first 4 bytes of the talker's
identity hash.

**Signatures.** A CLAIM is signed over `"lxpt/v1/claim" ‖ bytes 0-103`, and a
RELEASE over `"lxpt/v1/release" ‖ bytes 0-79`, with the Ed25519 half of the
public key the message carries. Verification follows RFC 8032 with these
rules, the same in all three implementations:

- S must be below the group order L;
- the public key must be a canonical encoding: y below p, and not x = 0 with
  the sign bit set;
- R must equal, byte for byte, the canonical encoding of `[S]B - [k]A`. That
  makes the equation cofactorless and refuses a non-canonical R.

A relay can verify a signature but cannot check that the talker tag belongs
to the signer. A key holder checks that with `member tag(identity hash(public
key)) == talker tag`.

## 4. Wire v1 messages

Byte 1 is the type. Offsets are from the start of the message.

### 0x01 FRAME: one codec frame (talker to relay to listeners)

| Offset | Size | Field |
| --- | --- | --- |
| 0 | u8 | version `0x01` |
| 1 | u8 | type `0x01` |
| 2 | 4 | channel tag |
| 6 | 4 | talker tag (the talker's member tag) |
| 10 | u32 | spurt |
| 14 | u16 | seq, from 0 within the spurt |
| 16 | n | payload: the ciphertext, **1-200 bytes** |
| 16+n | 8 | MAC |

The length is 25-224 bytes. 24 or fewer is `truncated`, and 225 or more is
`oversize`. An encoder refuses an empty payload with `field` and one past 200
bytes with `oversize`. The relay reads only bytes 0-15 and the MAC, which
serves as the dedup prefix. Per listener leg, a frame costs 19 bytes of PLAIN
header plus 24 bytes of lxpt overhead, plus IFAC where configured.

### 0x02 CLAIM: a talker asks for the floor (signed)

| Offset | Size | Field |
| --- | --- | --- |
| 2 | 4 | channel tag |
| 6 | 4 | talker tag |
| 10 | u32 | spurt (must advance per talker; non-zero) |
| 14 | u32 | key epoch |
| 18 | 16 | nonce, random per spurt (the spurt keys' salt) |
| 34 | u8 | tier |
| 35 | u8 | flags: bit 0 emergency, bit 1 clock verified; bits 2-7 zero |
| 36 | u32 | clock, seconds since 1970 (meaningful only when verified) |
| 40 | 64 | public key |
| 104 | 64 | signature |

Always 168 bytes.

### 0x03 GRANT: relay to talker, the floor is yours

| Offset | Size | Field |
| --- | --- | --- |
| 2 | 4 | channel tag |
| 6 | 4 | talker tag |
| 10 | u32 | spurt |
| 14 | u8 | profile for this spurt |
| 15 | u8 | talk limit, seconds, 1-255 |
| 16 | u8 | count, 0-64 |
| 17 | 4 x count | member tags reached |

17-273 bytes.

### 0x04 BUSY: relay to a claimer, refused

| Offset | Size | Field |
| --- | --- | --- |
| 2 | 4 | channel tag |
| 6 | 4 | the claimer's talker tag |
| 10 | u32 | the claimer's spurt |
| 14 | u8 | busy reason |
| 15 | 10 | holder (SpurtRef) |

25 bytes. Reason `busy` requires a holder. With `rate_limited`, the holder
may be absent.

### 0x05 YIELD: stop now, someone orders first

| Offset | Size | Field |
| --- | --- | --- |
| 2 | 4 | channel tag |
| 6 | 4 | the yielding talker's tag |
| 10 | u32 | the yielding spurt |
| 14 | u8 | yield reason |
| 15 | 10 | winner (SpurtRef, required) |

25 bytes. A pre-emption by Emergency is `preempted` with the winner's
emergency flag set.

### 0x06 RELEASE: the talker is done (signed)

| Offset | Size | Field |
| --- | --- | --- |
| 2 | 4 | channel tag |
| 6 | 4 | talker tag |
| 10 | u32 | spurt |
| 14 | u16 | frame count (the last seq + 1; 0 if no frame was sent) |
| 16 | 64 | public key |
| 80 | 64 | signature |

Always 144 bytes. It carries the public key so that a RELEASE overtaking its
CLAIM can still be verified and tombstoned.

### 0x07 TALKING: the floor's heartbeat, relay to listeners and peers

| Offset | Size | Field |
| --- | --- | --- |
| 2 | 4 | channel tag |
| 6 | 10 | holder (SpurtRef, required) |
| 16 | u8 | profile |
| 17 | u8 | talk limit, seconds, 1-255 |

18 bytes.

### 0x08 SUB: a member's subscription lease, phone to relay

| Offset | Size | Field |
| --- | --- | --- |
| 2 | u8 | carrier of this leg |
| 3 | u8 | count, 0-32 |
| 4 | 9 x count | entries |

Each entry is 9 bytes:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | channel tag |
| 4 | 4 | the member's tag in that channel |
| 8 | u8 | sub mode |

4-292 bytes. A SUB replaces the leg's previous one. A count of 0 leaves every
channel.

### 0x09 PEER: a relay's summary, relay to relay

| Offset | Size | Field |
| --- | --- | --- |
| 2 | 16 | the relay's identity hash |
| 18 | u16 | the relay's measured stall p99, ms (saturating) |
| 20 | u8 | channel count, 0-32 |
| 21 | ... | channel entries, in sequence |

Each channel entry is 6 + 4m bytes:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | channel tag |
| 4 | u8 | flags: bit 0 a narrow leg is subscribed; bits 1-7 zero |
| 5 | u8 | member count m, 0-64 |
| 6 | 4 x m | member tags |

The whole message must fit in 431 bytes. An encoder refuses more with
`oversize`. A decoder walks the entries in order. A cut entry is
`truncated`, bytes left after the last entry are `oversize`, and a count past
its limit is `field`.

### 0x0A HEARD: who heard a spurt, listener to relay and aggregated upstream

| Offset | Size | Field |
| --- | --- | --- |
| 2 | 4 | channel tag |
| 6 | 4 | talker tag |
| 10 | u32 | spurt |
| 14 | u8 | count, 0-64 |
| 15 | 6 x count | entries: member tag (4), frames received (u16) |

15-399 bytes. A listener sends one entry. A relay sends one aggregate.

## 5. NOTICE v1: the LoRa talker notice

| Offset | Size | Field |
| --- | --- | --- |
| 0 | u8 | version `0x01` |
| 1 | u8 | kind (high nibble) and hop limit (low nibble, 0-15) |
| 2 | 4 | channel tag |
| 6 | 4 | talker prefix, encrypted (section 3) |
| 10 | u16 | spurt, low 16 bits |
| 12 | u8 | talk limit, seconds, 1-255 |
| 13 | 8 | MAC |

Always 21 bytes, as TalkChannels.md section 4 budgets (49 bytes on air with
the RNode byte, the PLAIN header and IFAC 8). v1 senders set the hop limit to
1, and a receiving board never re-sends. The field exists so that a second
hop needs no new version.

## 6. Conformance

An implementation conforms when, for `fixtures/lxpt_wire_v1.json`:

- every `messages` vector encodes to its `hex` and decodes back to its
  `message`;
- every `decode_refused` and `encode_refused` vector gives its `error`;
- every `frames`, `notices` and `signed` vector seals or signs to its `hex`,
  opens or verifies as stated, and every `*_refused` vector gives its error;
- every crypto, channel id, tag and key vector matches.

`tools/crosscheck.py` compares the result lines of all three implementations
in CI, and `python/gen_fixture.py --check` fails if the fixture is not what the
reference generates.

## 7. Decisions this spec makes

TalkChannels.md names most fields but leaves their layout open. Where it does,
this spec chose the following, conservatively:

1. **Full 32-bit spurt in every message but NOTICE.** The design estimated a
   ~14-byte FRAME header. v1's is 16 bytes, because it carries the whole spurt
   id rather than its low 16 bits, so no message is ambiguous across a wrap.
   The NOTICE keeps the design's 16 bits.
2. **The talker tag in clear headers is the talker's member tag.** Relays key
   dedup and live spurts on (channel tag, talker tag, spurt). A CLAIM carries
   both the tag and the public key. Phones check that they match.
3. **Domain labels and the channel id in every derivation.** The design wrote
   `HMAC(k_epoch, "tag")` and `HMAC(k_epoch, identity hash)`. v1 adds
   prefix-free `lxpt/v1/...` labels and binds the channel id, so a key reused
   across channels or purposes never yields the same tag or key.
4. **The spurt nonce is HKDF's salt**, and the channel id, talker hash and
   spurt are its info.
5. **The NOTICE talker prefix** is the first 4 bytes of the talker's identity
   hash, encrypted with a pad derived from the MAC (synthetic IV). The hop
   limit is outside the MAC, so a later hop can lower it.
6. **Room normalisation is RRC's**, byte for byte, plus strict UTF-8 and the
   1-64 byte bound. **Hubless channels** get their own label,
   `lxpt/hubless/v1`.
7. **Maximum message 431 bytes**, the link MDU, so every message fits both
   PLAIN and link legs. FRAME payloads are capped at 200 bytes, so a frame
   with its PLAIN header and IFAC 8 fits the relay's 256-byte queue slot.
8. **Profiles are LXST's ids**, limited to the five talk uses (ULBW, VLBW,
   LBW, MQ, HQ). SHQ, LL and ULL are refused: SHQ's frames can pass 200 bytes,
   and LL's and ULL's 10-20 ms frames would multiply the per-frame overhead.
9. **Tiers are numbered in ICS order** (commander 1 to observer 5), and the
   Emergency flag is separate.
10. **List limits.** GRANT and HEARD hold up to 64 member tags. SUB holds up
    to 32 entries (12 positions x 2 selectors plus watch tags, matching the
    relay's 32-channel table). PEER holds up to 32 channels of up to 64
    members, within 431 bytes.
11. **Reserved bits and unknown enumeration values are refused** (`field`).
    New meanings get a new version byte rather than being read differently
    by old decoders.
12. **RELEASE carries the public key** (144 bytes, not 80), so a relay can
    verify a RELEASE that overtook its CLAIM. Its "last sequence number" is
    a **frame count**, so a spurt released before any frame is expressible.
13. **BUSY carries the holder and a reason**: `busy`, which needs a holder,
    or `rate_limited`, where the holder is optional. **YIELD carries a reason**,
    `collision` or `preempted`, and the winner. A SpurtRef carries the tier
    and the Emergency flag, so a phone can show `EMERG · Ayse` or
    `Pre-empted · Cmd Ali` without the winner's CLAIM.
14. **TALKING carries the profile and the talk limit**, because GRANT goes to
    the talker only and a listener needs the profile to decode.
15. **SUB entries carry a mode**, voice or watch. The leg's carrier is a
    kind, never a bitrate.
16. **PEER carries the relay's identity hash**, because PLAIN packets have no
    source. It also carries a narrow-leg flag per channel, because the lowest
    common profile is chosen per channel.
17. **Not in v1:** the membership certificate in CLAIM and the commander key
    in SUB (both T8), and any signature on relay-originated messages (GRANT,
    BUSY, YIELD, TALKING, PEER, HEARD). On those, IFAC is the protection where
    the leg has it. T8 adds the certificate with a new version or type.
