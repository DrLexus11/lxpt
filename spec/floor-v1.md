# lxpt floor and relay cores v1.1

**v1.1** (lxpt 0.2.1) bounds how late a lost spurt may come back: within
`RESUME_WINDOW_MS` (2 s) of its loss, not 20 s, and a local talker whose spurt
died is told so by YIELD (sections 4.2, 5.4, 7, and choices 6, 24 and 25). It
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
at `NEVER`, `last_seq` at -1, `profile` at 0 (unknown), `limit_s` at the
floor's talk limit, and `lost_ms` = `min(15000, max(5000, stall_ms * 3 // 2))`
from the claim's `stall_ms` (the path's stall p99, section 5.4).

| State | Meaning |
| --- | --- |
| `pending` | a relay holds a local claim for its settle window, or a remote one for `REMOTE_HOLD_MS`; a phone's own claim awaits its relay |
| `known` | known, not live: refused here, or a remote claim not (yet) shown live |
| `live` | holds, or shares, the floor here |
| `lost` | went silent for `lost_ms`; soft for `RESUME_WINDOW_MS`: a frame received within it brings it back; then it ends (dead) |
| `yielded` | stopped by the yield rule; soft, as lost |
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
rule). If the TALKING was stale, the retired spurt's next frame brings it
back.

**frame(now, rx, tag, spurt, seq)** — a FRAME's clear header, received at `rx`
(`rx <= now` when the host processes a queue late). On the record `find_tag`
names (none, or own: dropped):

- `pending`/`known`: a relay's local record is not promoted by frames (only
  the relay grants it): dropped. Otherwise `last_seq = max(last_seq, seq)` and
  it goes **live**.
- `lost`/`yielded`: if `seq <= last_seq`, or (lost) `rx - lost_at >=
  RESUME_WINDOW_MS`, or (yielded) `now - lost_at >= RESUME_MS`, dropped.
  Else `last_seq = seq`; if the holder orders before it, it stays down (a
  lost one becomes `yielded`, with `yield`) and the frame is dropped;
  otherwise it is live again (`resumed`), then the yield rule runs.
- Then, if it is live: `last_heard = max(last_heard, rx)`,
  `last_seq = max(last_seq, seq)`, `unquiet` if it was quiet, and the frame is
  **forwarded**.

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
   - yielded: ends `yielded` once `now - lost_at >= RESUME_MS`;
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
nothing allocates after it (`sizeof(Relay<>)` is about 65 KB on a 64-bit host,
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

Decode the CLAIM structurally; not a CLAIM, or no such channel: refuse. With
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
- **CLAIM** (verified): a client's new Emergency claim within 10 s of the
  identity's last on the channel gets the holder's CLAIM (if any) and BUSY
  `rate_limited`. Otherwise it goes to the floor as local (client) or remote
  (peer), with the path's stall p99 (`max(own, the peer's)` for a remote one)
  and the channel's settle window: **the largest RTT of the up peers that list
  the channel**, 0 with none (the floor caps it at 300).
- **FRAME**: first, the record `find_tag` names decides where its frames may
  come from: a local spurt's only from its talker's own leg, a remote spurt's
  only from a peer; anything else is dropped before dedup. (The relay cannot
  check a MAC, so without this a client could promote, resume or keep alive
  someone else's spurt with forged headers.) Then dropped if a duplicate (the
  dedup key is inserted otherwise), then to the floor. If the record is a
  local `yielded` one, its talker is still sending, so its YIELD was lost:
  the holder's CLAIM and the YIELD again (reason `preempted` if the holder may
  pre-empt it, else `collision`), at most once per 1000 ms per spurt. The same
  goes for a frame from its talker's own leg of a local spurt that has
  **ended** here (`find_tag` with ended records): its spurt is over (dead past
  the resume window, or ended otherwise), so it is told once anyone holds the
  floor, rather than talking on unheard. A phone ignores a YIELD for a spurt
  it no longer holds. If it is forwarded and `now - rx <= 500`: to every voice
  leg on the channel but its source, skipping a narrow leg (BLE, GFSK) unless
  the spurt's profile is known and Codec2 (ULBW, VLBW, LBW); and to every peer
  whose summary lists the channel **with members**, except its source peer
  and, for a remote spurt, the peer it came from. A stale frame still counts
  as heard (it moved `last_heard`).
- **RELEASE** (verified): to the floor; if new, to every leg on the channel
  (voice or watch) but its source and every peer listing the channel but its
  source.
- **TALKING** (peer only): to the floor. If the record is remote and live,
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
deterministic: one seeded generator for everything.

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
the first spurt was lost. Contests (two
or three key-ups within 300 ms, mostly on different relays) fill every other
gap on both channels. The gate is 10 seeds on each topology.

**The invariants, as measured:**

1. **Convergence.** For every collision (two spurts whose talkers both had a
   permit at once, each live at some relay while both talked; a talker still
   holding a permit for a spurt that no relay holds live, because it died
   and its talker had not yet been told, is not contesting the floor:
   `dead_permit_overlaps`, reported), the winner `W` is the one first in the claim order. A node
   knows the collision once it knows `W`'s claim and, if it ever hears of it,
   the loser's (a node that never learns the loser cannot show it); `T` is
   the latest such time over every node on the channel that knows `W`'s
   claim. For every node that knows `W`, until `W`'s talker stops:
   (a) **deciding**: from its first processing of `W`'s evidence (a FRAME or
   TALKING) after `T`, or `T` if it already shows `W`, plus one settle window
   and a tick (350 ms), it shows `W` and never the loser; (b) **in time,
   whatever the losses**: it shows `W` by `T + 6800` ms (one settle window,
   three heartbeats, 500 ms of delivery). Violations: 0. Reported beside it:
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
   frames come back within `RESUME_WINDOW_MS` must resume (or yield, if a
   spurt that orders first is live): `unresumed_in_window` 0. One whose
   frames come back later must end, and none of its frames may be forwarded
   again by that relay: `dead_unended` 0, `dead_forwards` 0. (v1 required
   every explained loss to resume, up to 20 s later; see choice 6.) Across
   every relay's notes, no `lost` spurt resumes `RESUME_WINDOW_MS` or more
   after its loss, unless the relay ran a pass longer than a tick in between
   (its queued frames count from when they arrived): `late_resumes` 0.
   **The bench backlog**: once the held spurt is dead, the talker granted
   after it keeps the floor on every node (`backlog_takeovers` 0) and no
   relay forwards the backlog (`backlog_forwards` 0). On v0.2.0's rule this
   part of the gate fails: on 3 seeds per topology, 5 takeovers in 6 runs,
   15 backlog forwards, 27 late resumes and 36 convergence violations.
4. **A vanished talker's floor is freed in time.** For every relay that had
   the vanished talker's spurt live: noted `lost` or ended by
   `last frame received + floor-lost bound + its longest pass in between + 50`.
   Violations: 0.
5. **No allocation after init (C++).** The C++ fixture replay counts every
   `operator new` inside a core call: 0. The embedded build compiles the cores
   with `-fno-exceptions -fno-rtti`.
6. Every claim resolves (granted, refused, yielded or given up): 0 left
   unresolved.

**Reported, not gated:** the share of contests settled before any permit
(at most one of its claims got a GRANT), swept over relay-to-relay RTT 20-600
ms on contest-only runs; also the convergence time, how far a vanished
talker's floor ran past its bound, the losses during long stalls and the
backlog with how many resumed inside the window and how many ended, whether
the backlogged talker was told (`backlog_talker_told`), and how often a PEER
summary expired.

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
   loss, frames continuing its sequence bring it back, and if another spurt
   is live the order decides. The design's condition cannot converge when
   only one side of a short stall saw the loss: the stalled relay still holds
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

## 9. Not in v1

- Talk rights at a relay: an Observer's claim without Emergency is treated as
  any other; phones drop it (T8).
- HEARD aggregation, NOTICE sending (T6), and the GFSK lease's talk limit
  (T9).
- Membership certificates and commander keys (T8): `verified` is always false.
- PEER summaries past 431 bytes are cut (T5 measures whether that binds).
