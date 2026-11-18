# lxpt floor and relay cores v1.4

**v1.4** (lxpt 0.5.0) drops a client's CLAIM that a relay processes more than
1200 ms after receiving it, as v1.1 does for FRAMEs and TALKINGs. A relay's
long stall delivered a phone's CLAIM after the phone had given up, and its
give-up RELEASEs were lost; the relay granted the claim and held the floor for
nobody until the lost timer, so a later contest was told BUSY and died (the T2
gate, a line of 3 relays, once a change elsewhere shifted its random stream).
A fresher copy follows a stale one if the phone is still claiming (sections
5.3 and 5.4, choice 30). It adds no message and changes no byte.

**v1.3** (lxpt 0.4.0) lets a RELEASE survive one loss downstream of a relay.
The talker sends its RELEASE twice, 200 ms apart; a relay used to forward only
the first copy it saw, so a single loss past it cost the listener the RELEASE
and the talker the listener's HEARD ("not heard" with every frame delivered,
the talk harness on two RADs, 2026-11-16). A relay now forwards one repeat, from
the spurt's own source only (section 5.4, choice 29). The floors are unchanged.
It adds no message and changes no byte.

**v1.2** (lxpt 0.3.0) judges frames by media time. At a relay, a live spurt's
frame more than 800 ms behind its spurt's schedule is a backlog and is not
forwarded, though it still counts as heard (section 5.4, choice 27). At every
node, a lost spurt comes back, still only within the 2 s resume window, only on
a frame on its schedule: a backlog never resumes it (section 4.2, choice 28).
It adds no message and changes no byte.

**v1.1** (lxpt 0.2.1) bounds how late a lost spurt may come back: within
`RESUME_WINDOW_MS` (2 s) of its loss, not 20 s; a local talker whose spurt
died is told so by YIELD; and at a relay a FRAME or TALKING older than 500 ms
never makes a spurt live (sections 4.2, 5.4, 7, and choices 6 and 24-26). It
adds no message and changes no byte: the wire is [wire-v1.md](wire-v1.md)'s,
and the fixtures keep their `_v1` names.

This is the behavioural contract of lxpt's two pure cores: the **floor core**
(one channel's floor as one node sees it, on a relay or a phone) and the
**relay core** (subscriptions, peers, dedup and forwarding around one floor per
channel). Three implementations follow it: the Python reference
(`python/lxpt/floor.py`, `relay.py`), Kotlin (`Floor.kt`, `Relay.kt`) and
header-only C++ (`cpp/include/lxpt/floor.hpp`, `relay.hpp`).
`fixtures/lxpt_floor_v1.json` and `fixtures/lxpt_relay_v1.json` pin it, and CI
checks that all three produce the same lines for every step of every scenario.

The bytes are [wire-v1.md](wire-v1.md)'s; this document uses its messages and
adds none.

## 1. Conventions

- **Pure.** A core is called with an event and the time; it returns actions.
  It performs no I/O, reads no clock and holds no thread. The time is an
  integer count of **milliseconds** on any monotonic clock the host likes;
  only differences matter. `NEVER` is -1 000 000 000, a time before any clock
  a core is given.
- **Verified upstream.** The host verifies every CLAIM's and RELEASE's
  Ed25519 signature (wire spec section 8) before it hands one to a core. The
  cores never verify; they read the CLAIM's fields and the identity hash of
  its public key (`who` = `SHA-256(public key)[:16]`).
- **Membership.** A claim carries one more input, `verified`: its membership
  certificate verified against the channel's commander key. That is T8's; in
  v1 every host passes `false`. It is a property of the claim, so every node
  passes the same value for the same claim.
- **Deterministic order.** Whenever a rule walks a table, it walks it in a
  fixed order: spurt records in the claim order (section 2), channels in
  ascending channel tag, client legs and peers in ascending index, member tags
  in ascending byte order. Where a rule picks one record, ties break by the
  claim order. No output depends on insertion order or hashing.

## 2. The claim order and the rights

The **order key** of a claim is 34 bytes:

    [0 if emergency else 1] || [effective tier] || SHA-256(who || u32 spurt || nonce)

compared as unsigned bytes; the smaller orders first. The **effective tier** is
the claim's tier if it is `verified`, else `max(tier, 4)`: an unverified claim
never orders, or cuts, above a Member. The key is total, because the digest
covers the identity and the spurt.

A claim `c` **may pre-empt** a live spurt `s` when `c` is verified, `s` has no
Emergency, and either `c` has Emergency or the rights table lets `c`'s
effective tier cut `s`'s:

| Tier (code) | Cuts |
| --- | --- |
| Commander (1) | Deputy, Leader, Member, Observer (2-5) |
| Deputy (2) | Leader, Member, Observer (3-5) |
| Leader (3) | Member (4) |
| Member (4), Observer (5) | nobody |

So two Emergency spurts never cut each other, an equal tier never cuts, and
whatever may pre-empt also orders first.

## 3. Constants

| Name | Value | Meaning |
| --- | --- | --- |
| `SETTLE_CAP_MS` | 300 | the settle window's cap |
| `REMOTE_HOLD_MS` | 600 | how long a relay lets a remote claim with no evidence hold back local claims that order after it |
| `QUIET_MS` | 1200 | silence before `quiet` (max(3 frame times, 1.2 s) is 1.2 s for every v1 profile) |
| `LOST_MIN_MS`, `LOST_MAX_MS` | 5000, 15000 | floor lost is `min(15000, max(5000, stall p99 * 3 // 2))` |
| `RESUME_WINDOW_MS` | 2000 | a lost spurt can come back only on a frame received within this of its loss; then it is dead (v1.1) |
| `RESUME_MS` | 20000 | a yielded spurt can come back within this |
| `TOMBSTONE_MS` | 30000 | an ended record is kept this long |
| `LIMIT_GRACE_MS` | 1000 | a relay ends a spurt this long past its talk limit |
| `CLAIM_RETRY_MS`, `CLAIM_SENDS` | 600, 3 | a phone sends its claim up to 3 times, 600 ms apart |
| `TALK_LIMIT_S` | 30 | the default talk limit |
| `SUB_LEASE_MS` | 60000 | a SUB's lease |
| `PEER_EVERY_MS`, `PEER_LOST_MS` | 5000, 15000 | PEER period; a peer silent this long loses its summary |
| `TALKING_EVERY_MS` | 2000 | the heartbeat (CLAIM + TALKING) period |
| `YIELD_AGAIN_MS` | 1000 | a yielded local talker still sending gets its YIELD again at most once per this |
| `FRAME_MAX_AGE_MS` | 500 | a frame older than this when processed is not forwarded |
| `CLAIM_MAX_AGE_MS` | 1200 | a client's CLAIM older than this when processed is refused (choice 30) |
| `LATE_MS`, `REANCHOR_AFTER` | 800, 5 | a frame this far behind its spurt's schedule is late: a relay does not forward it, and it does not resume a lost spurt; this many late frames in a row at real-time pace re-anchor the schedule, at relays and phones alike (v1.2) |
| frame time | ULBW 400, VLBW 320, LBW 200, MQ and HQ 60 ms | per profile, for the schedule (LXST's frame times) |
| claims per client leg | 2 per 1000 ms | admission (section 5.3) |
| `EMERGENCY_EVERY_MS` | 10000 | one new Emergency claim per identity per channel |

## 4. The floor core

`Floor(role, channel tag, counters, capacity, talk limit)`, where `role` is
`relay` or `phone`, `capacity` is the number of spurt records (C++: at most
32), and `counters` may be shared by every floor of a node.

### 4.1 Records

A record is one spurt as this node knows it: `who`, talker `tag`, `spurt`,
`nonce`, `tier`, `emergency`, `verified`, `local` (a relay's own client sent
the claim), `own` (the phone's own claim), `src` (the leg or peer it came
from), the claim's bytes (`blob`), and the order key. Its clock fields start
at `NEVER`, `last_seq` at -1, `profile` at 0 (unknown), the best offset
unset (4.2, media time), `limit_s` at the floor's talk limit, and `lost_ms` = `min(15000, max(5000, stall_ms * 3 // 2))`
from the claim's `stall_ms` (the path's stall p99, section 5.4).

| State | Meaning |
| --- | --- |
| `pending` | a relay holds a local claim for its settle window, or a remote one for `REMOTE_HOLD_MS`; a phone's own claim awaits its relay |
| `known` | known, not live: refused here, or a remote claim not (yet) shown live |
| `live` | holds, or shares, the floor here |
| `lost` | went silent for `lost_ms`; soft for `RESUME_WINDOW_MS`: a frame received within it, on its spurt's schedule (v1.2), brings it back; then it ends (dead) |
| `yielded` | stopped by the yield rule; soft for `RESUME_MS`, or, if it was lost when it yielded, for the rest of its resume window |
| `ended` | released, superseded, past its limit, given up, or expired; a tombstone |

**Lookups.** `find(who, spurt)` is the record keyed on the signing key (wire
spec section 9). `find_tag(tag, spurt)` is the record a clear header names: of
the non-ended records with that talker tag and spurt, the best by state (live,
lost, yielded, pending, known) and then the claim order; with `ended` asked,
ended ones rank last. The **holder** is the first live record in the claim
order. `own()` is the first non-ended own record.

**Room.** A new record takes a free slot. With none, it replaces the oldest
`ended` (by `ended_at`), else the oldest non-own `known` (by `seen_at`), else
the oldest non-own `yielded`, else the oldest non-own `lost` (both by
`lost_at`), ties by the claim order. Live and pending records are never
replaced; with no candidate, the new claim is dropped **without** advancing
its counter, so a retry can land once there is room.

**Counters** keep, per (channel tag, who), the last spurt and the time of the
last Emergency claim. `advance(now, tag, who, spurt)` sets `last =
max(last, spurt)` and stamps the entry with `now`; a new entry, when the table
is full, replaces the least recently stamped one (ties to the lower
`tag || who`).

### 4.2 Events

**claim(now, c, settle_ms)** — a verified CLAIM. `settle_ms` (clamped to
0..300) is the settle window now.

1. If a record (who, spurt) exists, or the counter says `spurt <= last`, the
   claim is old. Only a relay's own client's retry of its own local record
   does anything: **live** gives `regrant`; **known** gives `busy` with the
   blocker (step 4) if there is one, else goes back to `pending` for a fresh
   window. Everything else is ignored.
2. Every other non-ended, non-own record of the same `who` ends `superseded`:
   a talker has one spurt per channel at a time.
3. The record is inserted (4.1), or the claim dropped. Then the counter
   advances.
4. The **blocker** is the holder if any live spurt is one the claim may not
   pre-empt, else none.
5. On a relay, a **local** claim with a blocker becomes `known` with `busy`;
   without, `pending` until `now + settle window`, with `pending`. A
   **remote** claim with no blocker becomes `pending` until
   `now + REMOTE_HOLD_MS`, with `pending`; with one, `known`, with `known`. On
   a phone, every other member's claim becomes `known`, with `known`.

**talking(now, tag, spurt, profile, limit)** — a TALKING from a peer (relay)
or the relay (phone): evidence that the spurt was granted somewhere. On the
record `find_tag` names, unless it is own or (on a relay) local: set its
profile and limit; if it is `pending` or `known`, it goes **live** (4.3). A
TALKING never refreshes the silence clock and never resumes a lost spurt. On a phone, a TALKING is also its relay's view: the relay heartbeats only
what it holds live, so every other non-own live record that orders before the
named one goes `lost` first (a zombie whose RELEASE was lost), and a named
record that is `lost` or `yielded` here comes back (`resumed`, then the yield
rule): the relay judged the frames, and heartbeats only what it holds live
(media time does not apply to a TALKING, which has no sequence number). If the
TALKING was stale, the retired spurt's next frame brings it back.

**frame(now, rx, tag, spurt, seq)** — a FRAME's clear header, received at `rx`
(`rx <= now` when the host processes a queue late). On the record `find_tag`
names (none, or own: dropped):

- `pending`/`known`: a relay's local record is not promoted by frames (only
  the relay grants it): dropped. Otherwise `last_seq = max(last_seq, seq)` and
  it goes **live**.
- `lost`/`yielded`: if `seq <= last_seq`, or (lost) `rx - lost_at >=
  RESUME_WINDOW_MS`, or (yielded) `now - lost_at >= RESUME_MS`, or the
  frame is **behind** its schedule (v1.2, media time below), dropped: a
  backlog brings back neither a lost nor a yielded spurt. Else
  `last_seq = seq`; if the holder orders before it, it stays down (a
  lost one becomes `yielded`, with `yield`, but keeps its `lost_at` and the
  lost rule: it is still judged by `RESUME_WINDOW_MS` from its loss, here and
  in `tick`) and the frame is dropped;
  otherwise it is live again (`resumed`), then the yield rule runs.
- Then, if it is live: `last_heard = max(last_heard, rx)`,
  `last_seq = max(last_seq, seq)`, the schedule kept and the frame marked
  late or not (below), `unquiet` if it was quiet, and the frame is
  **forwarded**.

**Media time** (v1.2). The frame time of a profile is ULBW 400, VLBW 320, LBW
200, MQ and HQ 60 ms, 0 for an unknown profile. A frame's **offset** is
`rx - seq x frame time`; a talker numbers its frames on its own clock, so on
schedule the offset stays put, and a frame held back anywhere has a larger
one. A frame is **behind** when the profile is known, the record's best
offset is set, and `offset - best offset > LATE_MS`. The floor **keeps the
schedule**, on relays and phones alike, with every frame it forwards once the
profile is known: the first sets the best offset, a smaller offset lowers
it, and the frame is **late** if it is then behind. A late frame arriving at
least half a frame time after the previous forwarded frame adds to a run,
any other frame ends it; at `REANCHOR_AFTER` the best offset is set to this
frame's, the run ends, and the frame is not late (a talker whose numbering
shifted, for instance one whose encoder stalled, is not muted for the rest
of its spurt, while a backlog, which arrives in a burst, never re-anchors).
The record keeps whether the last frame forwarded was late; the relay reads
it (5.4), and a phone's host may too. Only a live spurt's frames keep the
schedule: a lost or yielded one's frames are judged against it, never
re-anchor it. With the profile unknown (no GRANT or TALKING gave it) or no
frame timed yet, nothing is behind or late, and a lost spurt resumes as in
v1.1.

**release(now, who, spurt, tag)** — a verified RELEASE. If record (who, spurt)
exists: already ended, nothing (seen); else it ends `released` (new). If not,
and the counter says `spurt < last`, nothing (seen). Otherwise a tombstone
(state `ended`, `released`) is inserted, but only into a free slot or in place
of the oldest `ended` record, and the result is seen: an overtaking RELEASE
still blocks the CLAIM that follows it here, but one that matches no record
(possibly junk under a fresh key, which costs its sender nothing) never
evicts a record, never advances or evicts a replay counter, and is not
forwarded.

**Going live** sets `live_since = last_heard = now`, clears `quiet`, emits
`live`, then runs the yield rule.

**The yield rule** — whenever two or more records are live, every one but the
first in the claim order yields at once (`yield`, reason `preempted` if the
winner may pre-empt it, else `collision`): a phone's own ends; any other
becomes `yielded` with `lost_at = now`. A yielded spurt is soft so that a node
that let it yield to a winner which then leaves, while the yielded one is
still talking, can bring it back on its next frame, as every other node does;
otherwise a single stale winner (a lost RELEASE plus a stall) splits the mesh
for good.

**tick(now, settle_ms)** — the host's pass, after draining its ingress. In
this order:

1. **Stalls are not silence.** If `now - previous tick > QUIET_MS`, every
   live record's `last_heard = min(now, last_heard + gap)`: time spent in a
   pass longer than the quiet timer is not counted. The first tick sets the
   clock only.
2. **Timers**, each record in the claim order:
   - own live: ends `limit` at `live_since + limit_s * 1000`;
   - other live: ends `limit` at `live_since + limit_s * 1000 + 1000`; else
     `lost` (state `lost`, `lost_at = now`) once `now - last_heard >=
     lost_ms`; else `quiet` once that is `>= QUIET_MS` (once until
     `unquiet`);
   - lost: ends `lost` once `now - lost_at >= RESUME_WINDOW_MS`. It is
     dead: `find_tag` no longer names it, so its later frames are dropped and
     never move the floor, and a TALKING or a repeated CLAIM of it does
     nothing;
   - yielded: ends `yielded` once `now - lost_at >= RESUME_MS`
     (`RESUME_WINDOW_MS` if it was lost when it yielded);
   - own pending: at `retry_at`, `retry` (the host re-sends the claim) while
     fewer than 3 sends, then ends `gave_up`;
   - remote pending: becomes `known` (silently) once `now >= hold_until`.
3. **Settle** (relay only), local pending records whose window is over, in the
   claim order: one waits while any `pending` record orders before it; else,
   with a blocker, it becomes `known` with `busy`; else every live record
   yields to it (`preempted`) and it is granted (`live`, `grant`).
4. **Tombstones**: ended records older than `TOMBSTONE_MS` are freed.

### 4.3 The phone's own claim

- **key(now, c)** — the user keys up. Refused if `spurt <= last` (a spurt id
  is never reused). Otherwise its own and other non-ended records of the same
  `who` end `superseded`, the record goes in (or the key is dropped), the
  counter advances, and the claim is `pending` with one send and
  `retry_at = now + 600` (`pending`).
- **granted(now, tag, spurt, profile, limit)** — a GRANT counts only for the
  own pending claim with that tag and spurt: it goes live (`grant`), then the
  yield rule (a phone that already knows a better live spurt stops itself).
- **busy(now, tag, spurt, holder, rate_limited)** — for the own pending claim
  only, and only if the holder names a non-own record the phone holds, or the
  reason is `rate_limited` with no holder: it ends, with `busy`.
- **yielded(now, tag, spurt, winner, preempted)** — for the own pending or
  live claim, naming a non-own record the phone holds: it ends, with `yield`.
- **end(now)** — the user released the key: the own record ends `released`.

GRANT, BUSY, YIELD and TALKING are unauthenticated (wire spec section 9); the
rules above are what keeps a forged one from moving a phone.

### 4.4 Actions and their lines

Each event returns its actions in the order they were made. A record is
written `<who hex>/<spurt>`.

| Action | Line |
| --- | --- |
| `pending`, `known`, `grant`, `regrant`, `live`, `quiet`, `unquiet`, `lost`, `resumed`, `retry` | `<action> <rec>` |
| `busy` | `busy <rec> <holder or ->` |
| `yield` | `yield <rec> <winner> collision\|preempted` |
| `ended` | `ended <rec> released\|limit\|superseded\|gave_up\|lost\|yielded` |

## 5. The relay core

### 5.1 Tables

`Relay(relay hash, limits, talk limit)`, limits default to 32 channels, 8 client
legs, 4 peers, 4 spurt records per channel, 128 dedup entries and 64 talkers.
In C++ each is a template maximum, the limits in use are set at `init()`, and
nothing allocates after it (`sizeof(Relay<>)` is about 68 KB on a 64-bit host,
less on a 32-bit board: buffers for PSRAM). Tables:

- **legs**: per client leg, its carrier and its SUB entries (channel tag,
  member tag, mode), and its lease end;
- **peers**: per peer slot, `up` (the host said so), its RTT, its last PEER
  (relay hash, stall p99, channel entries) and when anything was last heard
  from it;
- **channels**: per channel tag, a floor and the two last admission times;
- **admission**: per client leg, its two last admitted claims;
- **dedup**: a ring of keys `channel tag || talker tag || u32 spurt || u16 seq
  || MAC[0:4]` (18 bytes): the MAC prefix means a forged frame cannot shadow
  the genuine one;
- **counters**: shared by every channel's floor.

A channel is created when a SUB entry or an accepted PEER entry names it and
there is room; otherwise that entry is ignored. A leg or peer index past its
limit is ignored.

### 5.2 Calls

| Call | What the host passes |
| --- | --- |
| `admit_claim(now, leg, bytes)` | a client's CLAIM, **before** verifying it; returns whether to verify and pass it on |
| `client(now, leg, bytes, rx, verified)` | anything received on a client leg (TCP slot, BLE peer) |
| `peer(now, index, bytes, rx, verified)` | anything received from a peer relay (PLAIN one hop or a link) |
| `leg_down(now, leg)` | the slot or BLE peer was released |
| `peer_up(now, index, rtt)`, `peer_rtt(now, index, rtt)`, `peer_down(now, index)` | a peer relay found, its measured RTT, gone |
| `tick(now, stall_p99)` | once per pass, with the relay's measured stall p99 |

Outputs: **send** (`c<leg>` or `p<index>`, bytes) and **note** (channel tag,
floor action). Notes come first for each floor action, then the sends it
causes.

### 5.3 Admission (before verification)

A copy received more than `CLAIM_MAX_AGE_MS` (1200 ms) before now (the host
passes `rx`, when its leg received it) is refused silently, and counts for
nothing below (v1.4, choice 30). Decode the CLAIM structurally; not a CLAIM, or no such channel: refuse. With
the counter for (channel, who of its key): `spurt < last` is refused silently;
`spurt == last` is a retry and passes uncounted. Otherwise, if the older of
**the leg's** two last admission times is less than 1000 ms ago, refuse with
the holder's CLAIM (if any) then BUSY `rate_limited` (holder optional) to the
leg; else record the admission and pass. The budget is per leg, not per
channel, because admission runs before verification: unsigned junk on one leg
would otherwise use up every leg's allowance. `leg_down` clears it. Peers'
claims are not admitted: only clients'.

### 5.4 Receiving

Undecodable bytes are dropped. From a peer slot that is not up, everything is
dropped; from one that is, anything at all refreshes its `last_heard`.

- **SUB** (client only): replaces the leg's subscription; lease `now +
  60000`. Entries are taken in order, the first per channel tag, each only if
  its channel exists or can be created. **Late joiner**: for every channel
  newly listed, in tag order, the CLAIM then a TALKING of each live spurt whose
  profile is known (not the leg's own).
- **PEER** (peer only): replaces the summary; the first entry per channel tag,
  each only if its channel exists or can be created; members kept sorted and
  distinct. For every channel newly listed, the CLAIM and a TALKING of each
  live spurt with a known profile (not one that came from that peer).
- **CLAIM** (verified): a client's processed more than `CLAIM_MAX_AGE_MS`
  (1200 ms) after it was received (`now - rx`) is dropped, as admission did
  (v1.4, choice 30); a peer's is not. Otherwise, a client's new Emergency claim within 10 s of the
  identity's last on the channel gets the holder's CLAIM (if any) and BUSY
  `rate_limited`. Otherwise it goes to the floor as local (client) or remote
  (peer), with the path's stall p99 (`max(own, the peer's)` for a remote one)
  and the channel's settle window: **the largest RTT of the up peers that list
  the channel**, 0 with none (the floor caps it at 300).
- **FRAME**: first, the record `find_tag` names decides where its frames may
  come from: a local spurt's only from its talker's own leg, a remote spurt's
  only from a peer; anything else is dropped before dedup. (The relay cannot
  check a MAC, so without this a client could promote, resume or keep alive
  someone else's spurt with forged headers.) A frame older than 500 ms when
  processed (`now - rx > FRAME_MAX_AGE_MS`) whose record is `pending` or
  `known` is dropped here too: stale evidence never makes a spurt live (v1.1,
  choice 26). Then dropped if a duplicate (the
  dedup key is inserted otherwise), then to the floor. If the record is a
  local `yielded` one, its talker is still sending, so its YIELD was lost:
  the holder's CLAIM and the YIELD again (reason `preempted` if the holder may
  pre-empt it, else `collision`), at most once per 1000 ms per spurt. The same
  goes for a frame from its talker's own leg of a local spurt that has
  **ended** here (`find_tag` with ended records): its spurt is over (dead past
  the resume window, or ended otherwise), so it is told once anyone holds the
  floor, rather than talking on unheard. A phone ignores a YIELD for a spurt
  it no longer holds. **Media time (v1.2):** the floor judges the frame
  against its spurt's schedule and keeps it (4.2): a frame that resumes
  nothing because it is behind is dropped there, and one the floor forwards
  is marked late or not. A late frame still counts as heard, as a stale one
  does (choice 27); it is only not forwarded. If it is forwarded, not late,
  and `now - rx <= 500`: to every voice
  leg on the channel but its source, skipping a narrow leg (BLE, GFSK) unless
  the spurt's profile is known and Codec2 (ULBW, VLBW, LBW); and to every peer
  whose summary lists the channel **with members**, except its source peer
  and, for a remote spurt, the peer it came from. A stale frame still counts
  as heard (it moved `last_heard`).
- **RELEASE** (verified): to the floor; if new, to every leg on the channel
  (voice or watch) but its source and every peer listing the channel but its
  source. **One repeat** (v1.3, choice 29): a RELEASE that is not new is
  forwarded the same way once, when its spurt was ended here by a RELEASE this
  relay forwarded, and it comes from the spurt's source (its talker's leg for a
  local spurt, the peer its claim came from for a remote one). The record counts
  the copies forwarded (`releases`, relay bookkeeping): at most two per spurt.
- **TALKING** (peer only): dropped if older than 500 ms when processed
  (v1.1, choice 26); otherwise to the floor. If the record is remote and live,
  the CLAIM and a TALKING to the legs if not yet told. A peer's TALKING is
  not passed on: every relay sends its own heartbeat (5.6).
- **HEARD**: forwarded upstream as is: to the talker's leg (local spurt) or
  the peer the claim came from (remote), not back to its source, and not at
  all for a record with no source (a RELEASE tombstone). Aggregation is not
  in v1.
- GRANT, BUSY and YIELD are for phones and are ignored; SUB from a peer, PEER
  or TALKING from a client too.

### 5.5 What the relay sends for each floor action

- `pending`, `known`: the CLAIM to every leg on the channel (voice or watch)
  but its source, and to every peer listing it but its source.
- `grant`: computes the GRANT (below), sends it to the talker's leg, then the
  CLAIM and a TALKING to every other leg on the channel, then to every peer
  listing it; the heartbeat is due in 2000 ms.
- `regrant`: the GRANT again, with the member tags reached now and the profile
  fixed at the grant.
- `busy`: the holder's CLAIM, then BUSY `busy` naming it, to the claimer's leg.
- `live` (remote, on evidence): the heartbeat is due in 2000 ms, and the
  spurt is **announced after the floor call returns, if it is still live**:
  its CLAIM and a TALKING (if the profile is known) to every leg on the
  channel and to every peer listing it but the one the claim came from. A
  relay's TALKING therefore only ever names a spurt live there, which a phone
  relies on (4.2), and evidence crosses a line of relays at once rather than
  at the next heartbeat. (C++ applies actions as they are emitted; the flag
  set by the action and read after the call gives the same output.)
- `yield` of a local spurt: the winner's CLAIM, then YIELD (reason as the
  action's) to the talker's leg, starting its 1000 ms re-send clock. A remote
  loser gets nothing: its own relay tells it.
- Every other action is a note only.

A holder's CLAIM goes before BUSY and YIELD because a phone acts on those only
if it holds the CLAIM they name (wire spec section 9).

**GRANT.** Member tags reached: the member tags of every voice leg on the
channel but the talker's, and every member tag of every peer listing the
channel; distinct, sorted, without the talker's own tag, the first 64.
Profile (fixed for the spurt): LBW if the talker's leg, any voice leg on the
channel, or any peer's entry for it is narrow, else HQ. Talk limit: the
relay's.

**TALKING**: the record's SpurtRef (talker tag, spurt, declared tier,
Emergency), its profile and limit. **PEER** for peer `q` (split horizon): for
every channel in tag order that a leg or another peer lists, its narrow flag
(a narrow voice leg, or another peer's flag) and its member tags (voice legs'
and other peers', distinct, sorted, at most 64); channels are added while the
message stays within 431 bytes and 32 channels, and the first that does not
fit ends the list. The stall p99 saturates at 65535.

### 5.6 tick

1. Legs whose lease is over go; peers silent for 15 s lose their summary.
2. Each channel in tag order: the floor's tick (with the settle window),
   applying its actions as above; then, for each live record in the claim
   order whose heartbeat is due: its CLAIM and a TALKING to every leg on the
   channel but the talker's, and to every peer listing it but the one the
   claim came from; the next is due in 2000 ms. Every relay heartbeats every
   spurt live there, so a TALKING lost on one hop is repeated by the next
   relay too. This cannot loop: a TALKING only makes a pending or known
   record live, never a lost one, and never refreshes the silence clock.
3. Each up peer in index order whose PEER is due: its summary; next in 5000
   ms (`peer_up` makes the first due at once).
4. Channels no leg and no peer lists, whose floor holds only ended records,
   are freed.

## 6. Fixtures and conformance

`fixtures/lxpt_floor_v1.json` holds floor scenarios: a role, a channel tag, a
capacity, a counters size and a talk limit, then steps (`do`, `at`, inputs,
`expect`). `expect` is every line the step produced: the actions (4.4), then
`forward`/`drop` for a frame or `new`/`seen` for a release, then
`holder <rec>` or `holder -`. A `ticks` step is `count` ticks `every` ms apart
from `at`.

`fixtures/lxpt_relay_v1.json` holds relay scenarios: a relay hash, limits and
a talk limit, then steps whose `expect` is `admit ok|no` (for an admit) and
every action line: `send c<leg>|p<index> <hex>` and
`note <channel tag hex> <action line>`. Scenarios named `sim_R0` to `sim_R2`
are every call the simulator's fixture run made into each of its three relays,
so the decisions the simulator gate rests on are replayed by every
implementation; runs of idle ticks are compressed into `ticks` steps whose
every tick produced nothing.

An implementation conforms when every step of every scenario gives its
`expect`. Each suite also records one cross-check line per scenario,
`floor/<name>` or `relay/<name>`, the SHA-256 of its lines joined by newlines,
and `tools/crosscheck.py` requires the three files to be identical.
`python3 python/gen_core_fixtures.py --check` fails if a fixture is not what
the reference generates.

## 7. The simulator gate

`python/sim.py` drives the Python cores in a simulated mesh (Python suffices
because the fixtures pin the other two to the same decisions). It is
deterministic: one seeded generator for everything. A change that shifts
that random stream is also judged by **rates over a wide seed sweep**: seeds
1-200 on both topologies, against the base, with each gated count compared by
an exact one-sided test. The gate's fixed 20 runs cannot tell a regression
from a shifted stream reaching a latent path.

**The mesh.** 3 relays, as a triangle or a line; 8 phones (3, 3, 2 per relay),
all on channel A and four on channel B; one phone on BLE, so both channels run
Codec2 LBW. Every link loses 10% of packets, duplicates 3%, and reorders by
jitter (phone legs 8-28 ms; relay links about RTT/2 with RTT/4 of jitter).
Relays tick every 50 ms and report their measured stall p99 (over the last
60 s of passes); phones tick every 50 ms, SUB every 20 s, and send their
RELEASE twice, 200 ms apart. A 360 s run carries, on channel A in reserved
windows: a talker speaking through a **2, 5 and 18 s stall** at its own relay
and at the next one; two 20 s **partitions** that cut relay 2 off with a
talker on each side, then the merge; two talkers who **vanish** mid-spurt; a
verified commander's **pre-emption** and an unverified Emergency; and the
**bench backlog** of 2026-11-04: a talker's leg holds everything it sends for
16 s and then delivers it at once, in order (a TCP client of an overloaded
board), while a second talker on the same relay keys 8 s into the hold, after
the first spurt was lost; and a **6 s hold** (v1.2): a talker's leg holds its
frames 6 s, so its spurt is lost about 5 s in and the backlog arrives about
1 s after the loss, inside the resume window, followed at once by fresh
frames. Contests (two
or three key-ups within 300 ms, mostly on different relays) fill every other
gap on both channels. The gate is 10 seeds on each topology.

**The invariants, as measured:**

1. **Convergence.** For every collision (two spurts whose talkers both had a
   permit at once, each live at some relay while both talked; a talker still
   holding a permit for a spurt that died before the overlap, `lost` then
   `ended` at every relay that had it live and live nowhere during the
   overlap, because its talker had not yet been told, is not contesting the
   floor: `dead_permit_overlaps`, reported), the winner `W` is the one first in the claim order. A node
   knows the collision once it knows `W`'s claim and, if it ever hears of it,
   the loser's (a node that never learns the loser cannot show it); `T` is
   the latest such time over every node on the channel that knows `W`'s
   claim. For every node that knows `W`, until `W`'s talker stops:
   (a) **deciding**: from its first processing of `W`'s evidence (a FRAME or
   TALKING) after `T`, or `T` if it already shows `W`, plus one settle window
   and a tick (350 ms), it shows `W` and never the loser (a TALKING a relay
   processes more than 500 ms after receiving it is not evidence, nor is such
   a FRAME of a spurt pending or known there: choice 26); (b) **in time,
   whatever the losses**: it shows `W` by `T + 6800` ms (one settle window,
   three heartbeats, 500 ms of delivery). Violations: 0, except one kind,
   reported apart as `convergence_lost_first_grant` (§9, a lost first
   GRANT). The simulator records every GRANT a cut or the loss drops on its way
   to a phone. A violation at node `n` is of that kind if one of these holds:
   - **(a)** the loser's phone lost a GRANT for its claim, after its key-up and
     before it was given the floor; `n` is the loser's own phone; it was given
     the floor after `T`; and it was later yielded to `W`;
   - **(b)** `W`'s phone lost a GRANT for its claim, after its key-up and before
     the loser was given the floor; and the loser was given the floor before
     `W` was.

   And in both, `n` never showed the loser more than 350 ms after its first
   processing of `W`'s evidence after `T`. Every other violation is gated
   (`python/tests/test_sim_lost_first_grant.py`). Reported beside it:
   the time from `T` to each node showing `W` (p50, p95, max), how many took
   longer than one heartbeat (`T + 2800`), nodes that never learnt `W` before
   it stopped (a merge that came too late), and collisions over before
   `T + 350`.
2. **One spurt forwarded.** (a) From a relay's notes, the moment it holds two
   spurts live on a channel (the second goes live while the first is) until
   either truly leaves (ended or lost, not yielded), it must not forward
   frames of both. (b) For every collision and relay: from when it knew both
   claims plus 350 ms, until either ends there or `W` stops, once it has
   forwarded a frame of `W` it must forward no frame of the loser (knowing a
   claim is not knowing it was granted). Violations: 0.
3. **Short stalls never free a speaking talker's floor; long ones end it.**
   Every `lost` a relay notes for a spurt whose talker is still sending must
   be explained: by a partition cutting the talker's relay off, by the
   talker's own leg holding its frames back (the bench backlog), or because
   every relay that had been delivering the spurt's frames to it in the 2 s
   before the silence was itself stalled for at least this relay's floor-lost
   bound, or was fed only through such relays. A relay's own stall never
   excuses it, nor does a feed from the talker's own leg. Unexcused losses
   (`short_stall_frees`, `self_stall_frees`): 0. An explained loss whose
   frames come back within `RESUME_WINDOW_MS` **on schedule** (received at
   most `LATE_MS` after its talker sent it, which the relay's best offset
   cannot make later; v1.2) must resume (or yield, if a spurt that orders
   first is live): `unresumed_in_window` 0. One whose frames come back later,
   or only as a backlog, must end, and none of its frames may be forwarded
   again by that relay: `dead_unended` 0, `dead_forwards` 0. (v1 required
   every explained loss to resume, up to 20 s later; see choice 6.) Across
   every relay's notes, no `lost` spurt resumes `RESUME_WINDOW_MS` or more
   after its loss, unless the relay ran a pass longer than a tick in between
   (its queued frames count from when they arrived): `late_resumes` 0. A lost
   spurt that yields keeps its loss for this check.
   **The bench backlog**: once the held spurt is dead, the talker granted
   after it keeps the floor on every node (`backlog_takeovers` 0) and no
   relay forwards the backlog (`backlog_forwards` 0). With v0.2.0's resume rule
   (a lost spurt back within 20 s) and the rest of v1.1, this part of the
   gate fails: on 3 seeds per topology, 2 takeovers in 6 runs, 6 backlog
   forwards, 18 late resumes and 9 convergence violations.
   **The 6 s hold** (v1.2): no relay forwards a held frame more than
   `LATE_MS` + 500 ms after its talker sent it (`hold_late_forwards` 0); the
   loss is explained by the hold, so its fresh frames must resume it
   (`unresumed_in_window` above). With v1.1's resume rule this part fails:
   the first held frame, 6 s late, resumes the spurt and is forwarded.
4. **A vanished talker's floor is freed in time.** For every relay that had
   the vanished talker's spurt live: noted `lost` or ended by
   `last frame received + floor-lost bound + its longest pass in between + 50`.
   Violations: 0.
5. **No allocation after init (C++).** The C++ fixture replay counts every
   `operator new` inside a core call: 0. The embedded build compiles the cores
   with `-fno-exceptions -fno-rtti`.
6. Every claim resolves (granted, refused, yielded or given up): 0 left
   unresolved.
7. **No dead contest.** A contest is 2-3 key-ups on an idle channel within
   1 s. It is **dead** if none of them gets a GRANT. That is gated: two rival
   claims that each make the other lose are what it counts. Violations: 0.
   Two kinds are reported apart, not gated, because random loss alone makes
   them:
   - **behind a holder** (`dead_contests_behind_holder`): one of them was
     refused by a spurt outside the contest that had held the floor and
     stopped before the refusal. It is still live at the relays, its RELEASE
     lost;
   - **given up** (`dead_contests_given_up`): each claimer either lost its
     own CLAIM, GRANT and retries on its own leg (`gave_up`), or was refused
     by one that did. That claim reached the rival's relay first, so the
     rival got BUSY naming it, and never retried.

   Two direct cases, a lost first GRANT and a slow talker leg, are also checked
   across 10 seeds and every key-up offset (`python/tests/test_sim_contests.py`):
   - never a dead contest;
   - never a talker given the floor, then yielded to a rival never given it;
   - never a talker yielded while a listener played its frames. This holds
     for these direct, lossless cases; with loss, a lost first GRANT can do it
     (§9).

**Reported, not gated:** the share of contests settled before any permit
(exactly one of its claims got a GRANT; until 2026-11-17 a dead contest also
counted as settled) and the dead contests of each kind, swept over relay-to-relay RTT 20-600 ms on contest-only runs; also the convergence time, how far a vanished
talker's floor ran past its bound, the losses during long stalls and the
backlog with how many resumed inside the window and how many ended, whether
the backlogged talker was told (`backlog_talker_told`), how many relays
resumed the 6 s hold's spurt (`hold_resumed`) and whether its talker kept the
floor (`hold_kept_floor`), and how often a PEER summary expired.

## 8. Decisions this spec makes

The talk-channel design fixes the principle; where it left a
rule open or a rule failed the gate, v1 chose:

1. **Remote claims go live on evidence only.** A relay grants only its own
   clients' claims. A peer's claim is pending (holding back local claims that
   order after it) for at most 600 ms, then known; a TALKING or a FRAME of it
   makes it live. TALKING is "the sign that a spurt was granted somewhere".
2. **The settle window is the largest RTT of the peers listing the channel**,
   supplied by the host (wire v1 has no ping), capped at 300 ms, and 0 with no
   peer: one relay alone decides at once.
3. **Pre-emption happens at the end of the window**: a claim that may
   pre-empt is held like any other and cuts the live spurt when its window
   ends, within 300 ms.
4. **Unverified tiers count as Member**, in the order as well as for
   pre-emption, so a forged tier wins nothing. Emergency counts in the order
   whether or not verified; it pre-empts only when verified, so before T8 an
   Emergency claim at a relay only takes an idle floor.
5. **A yield is soft.** A yielded spurt is kept like a lost one, and its
   continuing frames bring it back if no live spurt orders before it. Without
   this, one stale winner (a lost RELEASE through a stall) made a relay end
   the real talker for good while the others kept it.
6. **A lost spurt resumes by the order, not "if no other spurt was granted
   since", but only within the resume window** (v1.1). Within 2 s of the
   loss, frames continuing its sequence bring it back (v1.2: only frames on
   its schedule, choice 28), and if another spurt is live the order
   decides. The design's condition cannot converge when only one side of a
   short stall saw the loss: the stalled relay still holds
   the spurt, the far one has granted another, and each would keep its own
   talker. v1 allowed this for 20 s, and the bench (2026-11-04) showed what
   that costs: a board held a TCP client's frames 16 s, the spurt was lost,
   a second talker was granted, and the backlog arriving 13 s after the loss
   resumed the stale spurt, which ordered first, so the live talker yielded
   to it. Voice that is seconds late is not voice: a stall longer than the
   floor-lost bound ends the spurt, it does not bring it back later.
7. **TALKING does not refresh the silence clock**: only frames do. Otherwise
   each relay's floor-lost timer would start from the heartbeat of the
   previous one, and a vanished talker's floor would be held for the sum of
   the bounds along the path.
8. **Stalls**: time in a pass longer than 1.2 s is not counted as silence
   (each live spurt's `last_heard` moves forward by the gap), and queued
   frames count from when they were received. A relay that keeps making 1.3 s
   passes would never lose a floor: a stated cost.
9. **The path's stall p99** is the relay's own, or the larger of its own and
   the source peer's from PEER, taken when the claim arrives.
10. **Heartbeats carry the CLAIM, and every relay sends them.** Every TALKING
    a relay sends (at a grant, on evidence, to a late joiner, every 2 s) is
    preceded by the spurt's CLAIM, so a listener or relay that lost the CLAIM
    recovers within one heartbeat (it needs the nonce to decrypt, and the
    CLAIM to act on any TALKING). Every relay heartbeats every spurt live
    there to its peers, except back to the spurt's source peer, rather than
    forwarding the origin's: a TALKING lost on one hop is repeated by the
    next.
11. **BUSY and YIELD are preceded by the holder's CLAIM**, so the claimer can
    act on them (wire spec section 9).
12. **Admission**: two new claims per client leg per 1000 ms, before
    verification, so junk on one leg blocks only that leg (the design said
    per channel: that let anyone on BLE keep a channel unclaimable). The
    Emergency limit (1 per 10 s per identity and channel) is applied after
    verification, so a forged key cannot use up a victim's allowance. Peers'
    claims are not rate-limited at the receiver.
13. **The phone's claim**: up to three sends 600 ms apart, then `gave_up`;
    the host then sends a RELEASE.
14. **Replay counters** are kept per (channel tag, identity): the 64 entries
    are 64 channel-talker pairs, not 64 talkers. A dropped claim never
    advances one, and neither does a RELEASE that matches no record. LRU
    eviction re-opens an evicted pair's old spurts to replay (a relay with
    about ten busy channels evicts in normal use): stated, and T4 sizes the
    table.
15. **Late joiners** (a new SUB, or a peer whose PEER newly lists a channel)
    get the CLAIM and TALKING of every live spurt at once.
16. **A peer is silent** only if nothing at all came from it for 15 s, not
    only PEER.
17. **HEARD is forwarded upstream as is.** Aggregation is deferred.
18. **A relay ends a spurt 1 s past its talk limit**, measured from when it
    went live there; a phone ends its own at the limit.
19. **A frame counts only from its spurt's source**: a local spurt's frames
    from its talker's leg, a remote spurt's from a peer. Wire section 9's "a
    FRAME never creates, extends or ends a spurt" holds at every leg the
    talker is not on; between relays, peers are trusted until T7 secures BLE
    peer links.
20. **A RELEASE that matches no record** leaves a tombstone only in free or
    ended room, moves no counter, and is not forwarded: otherwise fresh keys
    could flood a relay's tables.
21. **A yielded local talker that keeps sending gets its YIELD again**, at
    most once a second: a lost YIELD otherwise leaves it talking until the
    next heartbeat reaches its phone.
22. **A BUSY `rate_limited` with no holder** ends a phone's pending claim
    although it names no CLAIM (wire section 9's rule for BUSY otherwise). A
    forged one costs the user a re-key: stated.
23. **A phone takes its relay's TALKING as the relay's view** and retires a
    live spurt that orders before the named one: a phone that missed a
    RELEASE otherwise lets a silent zombie win the order for the floor-lost
    bound. A TALKING also brings back a spurt the phone had let go: a phone
    mirrors its relay (relays do not, so that heartbeats cannot keep a
    vanished talker alive among them). A forged TALKING (on BLE) can blank the real talker until its next
    frame: stated, for T7.

24. **The resume window is 2 s** (`RESUME_WINDOW_MS`), judged on when the
    frame was received (`rx`), like every other silence (choice 8). Against
    the gate's stalls: a 2 s stall is below every floor-lost bound (at least
    5 s), so nothing is lost; a 5 s stall is at the bound, so a starved relay
    may note `lost` just as the stall ends, and the first fresh frame reaches
    it within a frame time (at most 400 ms, ULBW), half an RTT (at most
    300 ms) and a tick (50 ms), well inside 2 s: it resumes; an 18 s stall is
    past every bound (at most 15 s), so the frames come back 3 s or more after
    the loss: the spurt ends. 2 s covers that worst case twice over, is longer
    than the quiet timer (1.2 s), so a hiccup that already showed `quiet`
    still comes back, and is short enough that a stale backlog cannot outlive
    it: a listener has heard 7 s or more of silence by then, and someone else
    may have keyed. A yielded spurt keeps `RESUME_MS`: its talker was still
    sending when it yielded, and choice 5 needs it back when a stale winner
    leaves. Stated costs: a listener phone that hears nothing of a spurt for
    `lost_ms` + 2 s (a long BLE drop-out) loses the rest of that spurt, and a
    relay's TALKING no longer brings it back; and the relay that stalled
    keeps the spurt (choice 8) while the relays beyond the stall have ended
    it, so after a stall longer than the bound the talker is heard only on
    its own relay, and a claim made elsewhere meanwhile is settled by the
    order only where both are known.
25. **A dead local spurt's talker is told** (v1.1): a frame from its own leg
    gets the holder's CLAIM and a YIELD, at most once a second, as a yielded
    talker does (choice 21). With nobody holding the floor there is nothing to
    name, so it is told only once someone else is granted; until then its
    frames are dropped. No new message: a phone already acts on a YIELD for
    its live spurt naming a claim it holds.

26. **Stale evidence never makes a spurt live** (v1.1). At a relay, a FRAME
    or TALKING processed more than 500 ms after it was received (queued
    through the relay's own long pass) does not take a `pending` or `known`
    spurt live; the next heartbeat, at most 2 s later, does if the spurt is
    still live somewhere. A stale frame of a spurt already live still counts
    as heard (choice 8). Without this, a relay leaving an 18 s stall replayed
    its queue: a claim, then frames of a spurt whose RELEASE was lost on the
    way, and the gap rule then held that zombie live for the floor-lost bound,
    so the real talker who keyed after the stall yielded to it there (found
    by the gate once the bench backlog act moved the schedule; the mechanism
    is v1's).

27. **Lateness by media time at a relay** (v1.2). A live spurt's frame more
    than `LATE_MS` (800 ms) behind its schedule (`rx - seq x frame time`
    against the spurt's best offset) is not forwarded. The 500 ms age check
    cannot see a backlog held before the relay's core: it stamps `rx` when
    the host reads the frame, so frames held in a client's TCP stream or in
    the relay's own socket buffer arrive fresh by that clock and seconds late
    by the talker's. The talker's own numbering can: a talker sends one frame
    per frame time, so a frame held back anywhere has a larger offset. A late
    frame **still counts as heard** (it goes to the floor, moves
    `last_heard`, keeps the spurt live): v1's rule is that a relay stall
    never frees the floor of a talker still speaking (choice 8, invariant 3),
    and a late frame is proof that the talker is still speaking, only that
    something between it and the relay held its voice back. Ending or losing
    the spurt on it would hand the floor to someone else in the middle of an
    over because of a stall the talker did not cause, and differently at
    each relay, so the mesh would split. **Only forwarding is gated**: what
    the rule protects is the listener, who would otherwise hear seconds-old
    voice played as live, or the same backlog replayed after the fresh
    speech; and every relay judges for itself, so no listener anywhere gets
    it. Re-anchoring after five late frames at real-time pace keeps a talker
    whose numbering shifted from being muted for the rest of its spurt,
    while a backlog, which arrives in a burst, never re-anchors. Only a live
    spurt's frames re-anchor: a lost spurt's are judged against the schedule
    as it was (choice 28). 800 ms is
    above every profile's frame time and a relay hop's jitter, and is the
    same bound Columba's listener applies.
28. **A lost spurt resumes only on schedule** (v1.2; the operator's
    decision, 2026-11-05). Within the existing resume window (2 s from the
    loss), a lost spurt comes back only on a frame that is not behind its
    schedule (offset at most `LATE_MS` past the best); a backlog never
    resumes it, however soon it arrives, and the spurt ends with the window
    if nothing on schedule comes. The same holds for a yielded spurt that
    was never lost (pre-empted, or out-ordered, while its talker kept
    sending): when the winner leaves, a backlog does not bring it back, the
    next frame on schedule does. The order is unchanged: a resumed spurt
    that orders first still takes the floor back from one granted after the
    loss (choice 6). Under v1.1 a talker's leg that held its frames just
    past the floor-lost bound resumed the spurt on the first held frame,
    seconds late, which was then forwarded as live (the gate's 6 s hold
    shows it); now the backlog is dropped and the fresh frames behind it
    resume the talker. The rule holds at every node: at a relay through the
    floor, at a phone with the frame time of the profile its relay's GRANT
    or TALKING gave; with no profile known yet there is nothing to judge by,
    and v1.1's rule stands. The floor keeps the schedule, re-anchor
    included, on phones as on relays, so a phone that followed a talker
    whose numbering shifted resumes it on the shifted schedule as its relay
    does; a phone cannot count on its relay's TALKING instead, which comes
    every 2 s, as long as the window, and never revives a spurt that has
    ended. The window stays a wall-clock bound beside the schedule, so a
    talker that comes back on schedule after more than `lost_ms` + 2 s of
    silence has still lost the rest of its spurt (section 9). **Stated
    cost:** a lost spurt's frames never re-anchor, so a talker whose own
    stall (its numbering held still, by more than `LATE_MS`) lasts past
    `lost_ms` comes back behind its schedule and its spurt ends with the
    window, where v1.1 resumed it. Re-anchoring inside the window on frames
    at real-time pace would also resume a backlog that drains at that pace
    (a socket buffer emptied by a slow link), which is what this rule
    exists to stop; a talker stalled for 5 s has been silent to everyone for
    5 s, and keys again.

29. **A relay forwards one repeat RELEASE** (v1.3). A phone sends its
    RELEASE twice, 200 ms apart, because a lost RELEASE holds a floor until
    the lost timer. Before v1.3 the second copy died at the first relay (the
    floor had ended the spurt, so the copy was not new): on the bench, the
    single copy that crossed the RAD link was refused by a full ESP-NOW queue,
    the listener's floor went quiet, lost the spurt 5 s later and sent no
    HEARD, and the talker's verdict was "not heard" with 59 frames delivered.
    Now each relay forwards a repeat once, so a RELEASE survives any one loss
    on the path, as it already did on the phone's own leg. **Bounds:** only a
    spurt a RELEASE ended at this relay (a spurt that ended `lost`, `limit` or
    `superseded` has no RELEASE to repeat, and a tombstone none either); only
    from the spurt's source, so a copy echoed by another peer (a triangle) is
    not forwarded and no loop can form; only once, so a relay forwards at most
    two copies of a spurt's RELEASE whatever arrives. **Guarantees:** the
    floors are untouched. A phone or relay whose floor already ended the spurt
    ignores the repeat (no second `ended`, no second HEARD); one that missed
    the first ends it `released` and its host sends HEARD, which is the point.
    No grant comes of a RELEASE, so no double grant can.
    **Considered and not done:** a listener accepting a RELEASE for a spurt
    its floor declared lost and still sending HEARD. On the bench no copy
    reached the listener at all, so it would not have helped, and it needs the
    floor to keep why a spurt ended, a change to every floor's records.

30. **A relay drops a client's CLAIM processed more than 1200 ms after it was
    received** (v1.4). The case (line seed 19 on a shifted random stream):
    - a relay in a long stall (one pass of 18 s in the gate's schedule) took a
      phone's CLAIMs only after the phone had sent its last and given up;
    - both of the phone's give-up RELEASEs (136,650 and 136,850 ms) were lost
      on the way to that relay;
    - the relay granted the claim (142,100), nobody talked, and the relays held
      the floor until the lost timer (147,100; ended at 149,100), about 5 s;
    - a contest of two other phones in that time was told BUSY naming it, and
      died.

    So it takes a stall of more than 1.2 s **and** both RELEASEs lost. A FRAME
    and a TALKING already carry an age check (choice 26, 500 ms); a CLAIM had
    none.

    **Why 1200 ms:** it is the span of a phone's claim, its first send to its
    last (3 sends, 600 ms apart).
    - If the phone is still claiming, a copy no older than that is queued
      behind any stale one, so dropping the stale copy costs nothing. A stall
      shorter than about a second still lets the later copy through, and the
      phone is granted.
    - If every copy is that old, the relay was away for the whole claim, and
      the phone gives up at 1.8 s anyway.
    - The bound is far above a relay's normal processing (a tick of 50 ms), and
      600 ms short of the 1.8 s give-up.

    **Where:**
    - **at admission (5.3):** a stale copy is refused there without counting,
      so stale copies never spend the leg's two admissions a second. Counting
      them made all three copies of a claim after a 2.7 s stall BUSY
      `rate_limited` (review);
    - **again on receipt (5.4),** for a host that admits without `rx`.

    **Client legs only.** A peer sends a CLAIM again only on its 2 s
    heartbeat, so a fresher copy does not follow. Dropping a stale peer CLAIM
    granted a local phone that the next heartbeat then yielded, where v1.3
    answers BUSY and the remote talker is heard. A stale peer CLAIM cannot
    hold a floor for nobody: it is pending, then known, and goes live only on
    evidence (choice 1).

    **For hosts:** `rx` must be when the leg received the bytes, stamped at
    the interface (in a firmware host, the receive callback, not `loop()`),
    or the rule does nothing on the loop stalls it is for.

    **Cost:** a client's claim that reaches a relay only after a stall of more
    than 1.2 s is not granted there; its phone keys again.

## 9. Not in v1

Open after v1.4 (lateness by media time at the relay and resume on schedule
are v1.2's, choices 27 and 28; the repeat RELEASE is v1.3's, choice 29; the
stale CLAIM's age check is v1.4's, choice 30):

- **The floor-lost bound's 5 s minimum** (`LOST_MIN_MS`). A lost spurt now
  resumes only on schedule, but still only within 2 s of its loss, and a
  talker silent past `lost_ms` (at least 5 s) is lost. Tactically 5 s of
  silence may be too long to hold a floor for a talker who has gone, and a
  shorter bound would lose more talkers to board stalls. It is to be
  revisited once the boards' stalls are fixed and measured.
- **A lost first GRANT** (known limit, kept as v1.3 has it). A floor is given
  late, or briefly to the wrong talker, when a first GRANT is lost. It has two
  shapes.

  **Shape 1: the loser's GRANT is lost, and its retry is regranted.**
  1. A relay grants its client's claim, and the GRANT is lost.
  2. Before the client's retry, a peer brings a claim that orders first. The
     grant is live, so that claim is only `known` here (or `pending`, if it
     may pre-empt), and the relay forwards it to the client.
  3. The retry gets the GRANT at once (4.2 step 1), and the phone shows
     itself as holder while it already knows a better claim.

  What happens next depends on the better claim:
  - **It wins.** Its evidence arrives and the yield rule ends the regranted
    talker within about 0.3 s. That talker may have sent a frame or two, and
    nearby listeners may hear them.
  - **It had been refused at its own relay.** That is the usual case below
    450 ms RTT, and the regranted talker keeps the floor.

  Counted as a retry of a live local spurt with `last_seq` < 0 while a
  remote claim that orders first was seen less than 600 ms earlier. How
  often (the simulator, v0.4.0):
  - the gate's 20 runs (7,200 s, 580 contests): 3 times, all of which kept
    the floor;
  - 60 more runs (seeds 11-40, both topologies; 1,760 contests): 8 times; 7
    kept the floor and 1 was yielded later;
  - the RTT sweep's contest-only runs (433 contests per RTT), at 20, 60,
    120, 200, 300, 450 and 600 ms:
    - occurrences: 1, 8, 5, 5, 2, 9 and 11;
    - yielded later: 1, 0, 1, 0, 1, 7 and 11.

  Over the 60 runs and the sweep, 22 were yielded. Each talker was cut 0-258
  ms after it was told to go, having sent 1-2 frames, and in 9 of the 22
  those frames were played to 1-2 listeners, mostly at 300-600 ms RTT. So
  this path does yield a talker who has been heard. §7's "never a talker
  yielded while a listener played its frames" is checked on the direct,
  lossless cases only.

  **Shape 2: the winner's GRANT is lost, and the loser is granted.**
  1. The winner's relay grants it, and the GRANT is lost, so the winner
     sends no evidence until its retry is regranted.
  2. The loser's relay holds the better remote claim its 600 ms
     (4.2 step 5), sees no evidence, and grants its own client.
  3. The loser talks, and listeners show it until the winner's late evidence
     yields it.

  Measured (a relay grants a local claim while a better remote claim it
  holds as `known`, seen less than 2 s ago, has passed its hold):
  - the gate: 3 times, 2 yielded later;
  - seeds 11-40: 14 times, 10 yielded;
  - the sweep at 20, 60, 120, 200, 300, 450 and 600 ms:
    - occurrences: 0, 1, 1, 1, 2, 0 and 3;
    - yielded later: 0, 1, 0, 1, 2, 0 and 3.

  The loser held the floor for 23-795 ms, and its frames were played in 6
  of the 19 cases.

  That count is wider than the gate's category (§7, item 1): it also takes
  in winners whose evidence came late for any reason, a lost TALKING or
  frame as well as a lost GRANT. The gate excuses only a convergence
  violation that followed a GRANT the simulator saw dropped. The one such
  violation seen (line seed 33) comes only on a random stream that another
  change shifted; on v0.4.0's stream that seed has neither.

  **Considered and not done:**
  - **The unheard spurt yields on the retry** (lxpt#9's first draft). Its
    rival had usually been refused at its own relay already (4.2 step 5), so
    both claims lost. Dead contests came in 71 of 216 lost-GRANT collisions
    on a triangle and 47 of 118 on a line at 60 ms RTT, and in 3 of the
    rule's 4 firings in the gate's own runs. On a slow talker leg the GRANT
    had in fact got through, and the talker was cut mid-spurt in 28 of 28
    cases.
  - **The regrant withheld until the rival's 600 ms hold lapses** (its
    redesign: nothing yields without evidence). In the direct collision and
    slow-leg cases its outcomes were exactly v1.3's, and in the gate's runs
    it withheld 3 regrants, all of whose talkers were later granted. It
    bought nothing, and it cost one gated failure (a short stall freed a
    floor).
  - **Changing the gate.** The gate is right: a phone showed the loser after
    knowing the winner.

  A rule worth having here must beat v1.3 without new dead contests, on the
  gate (with its dead-contest count, 2026-11-17) and on
  `python/tests/test_sim_contests.py`. The sweep's one convergence
  violation (600 ms RTT, seed 103) is not this path: the path did not occur
  in that run.

- **A talker's own stall past the floor-lost bound** ends its spurt (choice
  28's stated cost): its frames come back behind the schedule, and a lost
  spurt does not re-anchor. If talker-side stalls of 5 s or more turn out to
  be common, a resume that re-anchors on frames at real-time pace inside the
  window is the rule to weigh, against backlogs that drain at that pace.

- Talk rights at a relay: an Observer's claim without Emergency is treated as
  any other; phones drop it (T8).
- HEARD aggregation, NOTICE sending (T6), and the GFSK lease's talk limit
  (T9).
- Membership certificates and commander keys (T8): `verified` is always false.
- PEER summaries past 431 bytes are cut (T5 measures whether that binds).
