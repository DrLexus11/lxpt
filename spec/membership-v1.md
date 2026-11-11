# lxpt membership v1: keys, roster and tiers (T8) -- PROPOSAL

**Status: design decided (section 8, 2026-11-11), not yet implemented.** It becomes the
T8 contract with its fixtures
(`fixtures/lxpt_membership_v1.json`) and the three implementations, held byte-identical
like the wire codecs.

Wire v1 already carries a tier in every CLAIM, and the floor core already orders and
pre-empts by tier (floor-v1.md section 2). What it lacks is a way to **believe** a tier:
until now every claim is `verified = false` at a relay and counts as a Member (floor-v1
choice 4). This document adds what makes a claim verified: a commander who signs, a
roster that says who holds which tier, a channel key per epoch that only the roster
receives, and a certificate a relay can check without the roster.

## 1. Roles

- **Commander.** The channel's creator: the identity that signs its rosters, keys and
  certificates. One per channel at a time. Tiers follow ICS: Commander (1), Deputy (2),
  Leader (3), Member (4), Observer (5) -- wire v1's tier codes.
- **Members** hold the epoch key and a certificate. Phones learn everything from the
  roster; relays learn only certificates and never see the roster or the key.
- **Emergency** is a flag any tier may raise (wire v1 CLAIM flag), not a tier.

## 2. Objects

All integers big-endian, as wire v1. Every object starts with a version byte `0x01` and a
type byte, and ends with an Ed25519 signature by the commander over every byte before it.
`channel_id` is the 8-byte id of TalkChannels.md section 1.

### 2.1 ROSTER (type 0x01): who is on the channel, at which tier

| Offset | Size | Field |
| --- | --- | --- |
| 0 | u8 | version, 0x01 |
| 1 | u8 | type, 0x01 |
| 2 | 8 | channel_id |
| 10 | u32 | epoch (advances by 1 with every new key) |
| 14 | u32 | issued, seconds since 1970 |
| 18 | 64 | commander public key |
| 82 | u8 | talk limit, seconds, 1-255 (default 30) |
| 83 | 5 | rights, one byte per tier 1..5 (section 3) |
| 88 | u16 | count, 1-1024 |
| 90 | 17 x count | entries: identity hash (16), tier (u8) |
| ... | 64 | signature |

Entries are sorted by identity hash, with no duplicates; the commander is on it at tier 1.
A roster travels **only over LXMF** (section 4), never on a voice carrier, so its size is
not bound by the 431-byte MDU.

### 2.2 CERT (type 0x02): one member's tier, for relays

| Offset | Size | Field |
| --- | --- | --- |
| 0 | u8 | version, 0x01 |
| 1 | u8 | type, 0x02 |
| 2 | 8 | channel_id |
| 10 | u32 | epoch |
| 14 | 16 | member identity hash |
| 30 | u8 | tier |
| 31 | u8 | rights of that tier (section 3) |
| 32 | u32 | expires, seconds since 1970 |
| 36 | 64 | signature |

Always 100 bytes. A relay needs the commander's public key to check it (section 5).

### 2.3 KEY (type 0x03): the epoch key for one member

| Offset | Size | Field |
| --- | --- | --- |
| 0 | u8 | version, 0x01 |
| 1 | u8 | type, 0x03 |
| 2 | 8 | channel_id |
| 10 | u32 | epoch |
| 14 | 16 | member identity hash (the recipient) |
| 30 | 32 | k_epoch |
| 62 | 64 | signature |

Always 126 bytes. It carries the key in clear inside the object: it is only ever sent
inside an LXMF message, which is end-to-end encrypted to the recipient's identity.

## 3. Rights

One byte per tier, a bit field. Defaults, which T8b lets the commander change:

| Bit | Right | C | D | L | M | O |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | talk | 1 | 1 | 1 | 1 | 0 |
| 1 | pre-empt lower tiers (floor-v1 section 2's table) | 1 | 1 | 1 | 0 | 0 |
| 2 | Emergency | 1 | 1 | 1 | 1 | 1 |
| 3-7 | reserved (T11: mute, kick, actions), 0 | | | | | |

An Observer without talk may still key with Emergency (TalkChannels.md section 7).
floor-v1's "who cuts whom" stays the table there; bit 1 only switches it off for a tier.

## 4. Issuing over LXMF

The commander's phone sends each member one LXMF message carrying a new field,
`lxpt.member/1`, whose value is the concatenation **ROSTER || CERT || KEY** for that
member. LXMF encrypts it to the member and signs it with the commander's identity; the
objects' own signatures make them checkable once separated from the message.

- **Join (T8 to T11).** A member who enables voice on the channel's room sends the
  commander an LXMF request (`lxpt.join/1`, carrying channel_id). Until T11 the
  commander's phone answers every request with the current epoch at tier Member: the
  same trust as the room's text, accepted on 11-03 for a tactical channel.
- **Tier change, removal.** The commander edits the roster; the phone issues a new epoch
  (new key, new roster, new certificates) to everyone still on it. A removed member keeps
  the old key and cannot decode the next spurt (T8's gate).
- **Expiry (decided 11-11).** An epoch lasts 24 h and the commander's phone renews it
  automatically while it runs. A certificate is valid for 72 h, so the channel keeps
  verified tiers for two days after the commander's phone is gone.

## 5. Verifying a claim

**On phones.** A phone holds the roster. A CLAIM is verified when its public key's
identity hash is on the roster, the claimed tier equals the roster's, the tier has talk
(or the claim has Emergency), and the signature checks (wire v1). A claim failing this is
treated as wire v1 treats an unverified one, and the phone drops the spurt's frames.

**On relays.** A relay never sees the roster. It needs two things:

1. **The commander's key per channel.** Each member's SUB declares it (proposed: a new
   SUB layout under wire version `0x02`, adding a 16-byte commander identity hash per
   entry). A relay accepts a channel's commander only when every subscriber of that
   channel agrees; a disagreement is logged loudly and the channel stays unverified.
2. **The talker's certificate.** A member sends its CERT to its relay with every SUB
   (proposed: a new wire message, `0x0B` CERT, 102 bytes). The relay keeps one per
   (channel, identity) and checks it against the commander key: signature, epoch equal
   to the CLAIM's, not expired, identity equal to the CLAIM key's hash, tier equal to the
   CLAIM's.

A claim passing both is `verified`, and the floor core orders and pre-empts it by its
tier. Everything else stays as wire v1 says: an unverified claim counts as a Member and
never pre-empts.

## 6. Privacy fix before T8 (TalkChannels.md, T3a follow-ups)

The spurt counter is one per identity and in clear in CLAIM, so it links a talker across
channels and epochs. Proposed: one counter per (identity, channel, epoch), starting from
a random 24-bit offset at each epoch. Wire v1's rule ("advances per signing key") becomes
"advances per signing key and channel tag"; relays already keep per-talker state per
channel.

## 7. Gate (TalkChannels.md, T8)

- a removed member cannot decode the next spurt;
- replayed claims and frames, forged names, a tier not on the roster and a forged
  Emergency claim with an observed tag are each rejected or rate-limited, in all three
  implementations, from shared fixtures;
- pre-emption by the commander cuts a member within 300 ms (two phones and the deck's
  Python client).

## 8. Decided by the operator, 2026-11-11

The five questions this proposal asked were answered "as advised", with two
additions (3 and the override in 1):

1. **Commander of a hub room: the first phone to issue a roster for (hub, room)**,
   pinned by its members (trust on first use). Every member sees one line when it
   joins: `Commander · <name>`. The fleet's admin authority (the Fleet Admin
   namespace's Admin Authority) can override a wrong claim with a signed roster
   replacement.
2. **Handover: an explicit signed handover from the commander.** A deputy taking
   command without the commander is a later step.
3. **Lifetimes: key epochs of 24 h**, renewed automatically while the commander is
   present; **membership certificates valid for 72 h**, so a channel does not go
   silent when the commander's phone dies (disaster first). Section 4's "Expiry"
   reads with these values.
4. **Roster cap: 1024 members.**
5. **Observers may raise Emergency** (kept).
