"""The lxpt floor core v1: one channel's floor as one node sees it.

Pure: events in, actions out, the clock passed in as integer milliseconds, no
I/O and no crypto beyond the SHA-256 of the claim order. ``spec/floor-v1.md``
is the contract; the C++ (``cpp/include/lxpt/floor.hpp``) and Kotlin
(``Floor.kt``) cores follow this file rule for rule, and
``fixtures/lxpt_floor_v1.json`` holds all three to it.

A floor runs in one of two roles:

- ``relay``: claims from the relay's own clients (``local``) are held for the
  settle window and then granted or refused here; claims from peer relays are
  remote and become live only on evidence (a TALKING or a FRAME of theirs).
- ``phone``: every other member's claim is remote, the phone's own claim
  (``key``) waits for its relay's GRANT, BUSY or YIELD.

Both apply the same total order and the same yield rule, so every node that
knows the same live spurts picks the same talker.

The host verifies every CLAIM and RELEASE signature before it calls the core
(wire spec section 8); the core never sees an unverified one.
"""

import hashlib

__all__ = ["Floor", "Counters", "Claim", "Rec", "fmt_action", "order_key", "NEVER",
           "PENDING", "KNOWN", "LIVE", "LOST", "YIELDED", "ENDED"]

# --- timers, in milliseconds (spec/floor-v1.md section 3) ---------------------------

SETTLE_CAP_MS = 300
REMOTE_HOLD_MS = 600
QUIET_MS = 1200
LOST_MIN_MS = 5000
LOST_MAX_MS = 15000
RESUME_MS = 20000         # a yielded spurt can come back within this
RESUME_WINDOW_MS = 2000   # a lost spurt can come back only within this (v1.1)
LATE_MS = 800             # a frame this far behind its spurt's schedule is a backlog (v1.2)
TOMBSTONE_MS = 30000
LIMIT_GRACE_MS = 1000
CLAIM_RETRY_MS = 600
CLAIM_SENDS = 3
TALK_LIMIT_S = 30

NEVER = -1000000000  # a time before any clock the core is given

PENDING, KNOWN, LIVE, LOST, YIELDED, ENDED = "pending", "known", "live", "lost", "yielded", "ended"

TIER_MEMBER = 4


def eff_tier(tier, verified):
    """A tier counts only from a verified membership; an unverified claim never
    orders, or cuts, above a Member."""
    return tier if verified else max(tier, TIER_MEMBER)


def order_key(who, spurt, nonce, tier, emergency, verified):
    """The claim order: Emergency first, then the higher (effective) tier, then
    the lower SHA-256(identity hash || u32 spurt || nonce). Smaller sorts first.
    It is total: the digest covers the identity and the spurt."""
    digest = hashlib.sha256(bytes(who) + spurt.to_bytes(4, "big") + bytes(nonce)).digest()
    return bytes([0 if emergency else 1, eff_tier(tier, verified)]) + digest


def _cuts(c, s):
    """The default rights table: which effective tier cuts which."""
    return (c == 1 and s >= 2) or (c == 2 and s >= 3) or (c == 3 and s == 4)


def can_preempt(c, s):
    """Whether claim ``c`` may make live spurt ``s`` yield at once. Only from a
    verified membership; Emergency cuts anything without Emergency; two
    Emergency spurts never cut each other."""
    if not c.verified or s.emergency:
        return False
    return c.emergency or _cuts(eff_tier(c.tier, True), eff_tier(s.tier, s.verified))


def lost_ms_for(stall_ms):
    """Floor lost: max(5 s, 1.5 x the path's stall p99), at most 15 s."""
    return min(LOST_MAX_MS, max(LOST_MIN_MS, stall_ms * 3 // 2))


# Frame time per profile code (LXST's): ULBW, VLBW, LBW, MQ, HQ.
_FRAME_MS = {0x10: 400, 0x20: 320, 0x30: 200, 0x40: 60, 0x50: 60}


def frame_ms(profile):
    """A profile's frame time in ms; 0 for an unknown profile (nothing to judge by)."""
    return _FRAME_MS.get(profile, 0)


def behind(rec, seq, rx):
    """Whether frame ``seq`` of ``rec``, received at ``rx``, is more than LATE_MS
    behind the spurt's schedule: its offset ``rx - seq x frame time`` against the
    spurt's best offset (v1.2). False with no schedule yet (profile unknown, or no
    frame timed)."""
    fm = frame_ms(rec.profile)
    if fm == 0 or rec.best_offset is None:
        return False
    return rx - seq * fm - rec.best_offset > LATE_MS


class Claim:
    """What the core needs from a verified CLAIM."""

    __slots__ = ("who", "tag", "spurt", "nonce", "tier", "emergency", "verified", "local", "src",
                 "stall_ms", "blob")

    def __init__(self, who, tag, spurt, nonce, tier=TIER_MEMBER, emergency=False, verified=False,
                 local=False, src=-1, stall_ms=0, blob=b""):
        self.who = bytes(who)
        self.tag = bytes(tag)
        self.spurt = spurt
        self.nonce = bytes(nonce)
        self.tier = tier
        self.emergency = emergency
        self.verified = verified
        self.local = local
        self.src = src
        self.stall_ms = stall_ms
        self.blob = bytes(blob)


class Rec:
    """One spurt as this node knows it."""

    __slots__ = ("who", "tag", "spurt", "nonce", "tier", "emergency", "verified", "local", "own", "src",
                 "blob", "order", "state", "seen_at", "hold_until", "live_since", "last_heard", "last_seq",
                 "quiet", "lost_at", "lost_window", "ended_at", "lost_ms", "limit_s", "profile", "sends", "retry_at",
                 "reached", "hb_next", "told", "nudge_at", "announce", "best_offset", "last_arrival", "late_run")

    def __init__(self, c, now, own=False):
        self.who, self.tag, self.spurt, self.nonce = c.who, c.tag, c.spurt, c.nonce
        self.tier, self.emergency, self.verified = c.tier, c.emergency, c.verified
        self.local, self.own, self.src, self.blob = c.local, own, c.src, c.blob
        self.order = order_key(c.who, c.spurt, c.nonce, c.tier, c.emergency, c.verified)
        self.state = KNOWN
        self.seen_at = now
        self.hold_until = now
        self.live_since = NEVER
        self.last_heard = NEVER
        self.last_seq = -1
        self.quiet = False
        self.lost_at = NEVER
        self.lost_window = False  # a yielded spurt that was lost keeps the lost spurt's window
        self.ended_at = NEVER
        self.lost_ms = lost_ms_for(c.stall_ms)
        self.limit_s = TALK_LIMIT_S
        self.profile = 0  # unknown until a GRANT or TALKING gives it
        self.sends = 0
        self.retry_at = NEVER
        # media time (v1.2): the spurt's best offset, the smallest (rx - seq x frame
        # time) of its live frames, which a lost spurt's frames must keep to resume
        self.best_offset = None
        # relay bookkeeping, unused by the floor's own rules
        self.reached = []
        self.hb_next = NEVER
        self.told = False
        self.nudge_at = NEVER
        self.announce = False
        self.last_arrival = NEVER  # media time at a relay (relay.py's _late)
        self.late_run = 0          # late frames in a row at real-time pace

    def ref(self):
        return "%s/%d" % (self.who.hex(), self.spurt)


def fmt_action(a):
    """The fixture's line for a floor action."""
    kind, rec, other, reason = a
    s = "%s %s" % (kind, rec.ref())
    if kind in ("busy", "yield"):
        s += " " + (other.ref() if other is not None else "-")
    if reason:
        s += " " + reason
    return s


class Counters:
    """The last spurt per (channel tag, identity hash), and the time of its last
    Emergency claim: replay protection that outlives the floor's records.
    ``capacity`` entries; when full, the least recently advanced goes (ties to
    the lower tag || hash)."""

    def __init__(self, capacity=64):
        self.capacity = capacity
        self.e = {}  # (tag, who) -> [last spurt, last emergency at, advanced at]

    def last(self, tag, who):
        e = self.e.get((bytes(tag), bytes(who)))
        return e[0] if e else None

    def emergency_at(self, tag, who):
        e = self.e.get((bytes(tag), bytes(who)))
        return e[1] if e else NEVER

    def set_emergency(self, tag, who, now):
        e = self.e.get((bytes(tag), bytes(who)))
        if e:
            e[1] = now

    def advance(self, now, tag, who, spurt):
        k = (bytes(tag), bytes(who))
        e = self.e.get(k)
        if e:
            e[0] = max(e[0], spurt)
            e[2] = now
            return
        if len(self.e) >= self.capacity:
            victim = min(self.e, key=lambda key: (self.e[key][2], key[0] + key[1]))
            del self.e[victim]
        self.e[k] = [spurt, NEVER, now]


_STATE_RANK = {LIVE: 0, LOST: 1, YIELDED: 2, PENDING: 3, KNOWN: 4, ENDED: 5}


class Floor:
    """One channel's floor at one node. Each call returns the list of actions it
    produced, as (kind, rec, other, reason) tuples, in the order the spec gives."""

    def __init__(self, role, channel_tag, counters, capacity=4, talk_limit_s=TALK_LIMIT_S):
        assert role in ("relay", "phone")
        self.role = role
        self.channel_tag = bytes(channel_tag)
        self.counters = counters
        self.capacity = capacity
        self.talk_limit_s = talk_limit_s
        self.recs = []
        self.last_tick = None
        self.settle_ms = 0
        self.out = []

    # --- lookups -------------------------------------------------------------------

    def _sorted(self, state=None):
        rs = [r for r in self.recs if state is None or r.state == state]
        rs.sort(key=lambda r: r.order)
        return rs

    def find(self, who, spurt):
        for r in self.recs:
            if r.who == who and r.spurt == spurt:
                return r
        return None

    def find_tag(self, tag, spurt, ended=False):
        """The record a clear header (talker tag, spurt) names: live first, then
        lost, pending, known (then ended, if asked); ties by the claim order."""
        rs = [r for r in self.recs if r.tag == tag and r.spurt == spurt and (ended or r.state != ENDED)]
        if not rs:
            return None
        return min(rs, key=lambda r: (_STATE_RANK[r.state], r.order))

    def lives(self):
        return self._sorted(LIVE)

    def holder(self):
        rs = self.lives()
        return rs[0] if rs else None

    def own(self):
        for r in self._sorted():
            if r.own and r.state != ENDED:
                return r
        return None

    def empty(self):
        return all(r.state == ENDED for r in self.recs)

    # --- internals -----------------------------------------------------------------

    def _emit(self, kind, rec, other=None, reason=""):
        self.out.append((kind, rec, other, reason))

    def _take(self):
        out, self.out = self.out, []
        return out

    def _insert(self, rec, tombstone=False):
        if len(self.recs) < self.capacity:
            self.recs.append(rec)
            return True
        classes = ((ENDED, "ended_at"),) if tombstone else \
            ((ENDED, "ended_at"), (KNOWN, "seen_at"), (YIELDED, "lost_at"), (LOST, "lost_at"))
        for state, when in classes:
            cands = [r for r in self.recs if r.state == state and (state == ENDED or not r.own)]
            if cands:
                victim = min(cands, key=lambda r: (getattr(r, when), r.order))
                self.recs.remove(victim)
                self.recs.append(rec)
                return True
        return False

    def _end(self, now, rec, reason):
        rec.state = ENDED
        rec.ended_at = now
        self._emit("ended", rec, None, reason)

    def _make_live(self, now, rec):
        rec.state = LIVE
        rec.live_since = now
        rec.last_heard = now
        rec.quiet = False
        self._emit("live", rec)
        self._yield_rule(now)

    def _yield_one(self, now, loser, w, reason):
        """A yielded spurt stops here at once. The phone's own ends for good; any
        other is kept soft, as a lost one is, so that its frames can bring it
        back if the winner leaves while it is still talking (spec 4.6)."""
        if loser.own:
            loser.state = ENDED
            loser.ended_at = now
        else:
            loser.state = YIELDED
            loser.lost_at = now
            loser.lost_window = False
        self._emit("yield", loser, w, reason)

    def _yield_rule(self, now):
        """Two live spurts on one channel: every one but the first in the order
        stops at once."""
        rs = self.lives()
        if len(rs) < 2:
            return
        w = rs[0]
        for loser in rs[1:]:
            self._yield_one(now, loser, w, "preempted" if can_preempt(w, loser) else "collision")

    def _blocks(self, c):
        """The live spurt a new claim ``c`` cannot cut, if any (the best one)."""
        rs = self.lives()
        for r in rs:
            if not can_preempt(c, r):
                return rs[0]
        return None

    # --- events --------------------------------------------------------------------

    def claim(self, now, c, settle_ms=0):
        """A verified CLAIM, from this relay's client (``c.local``) or from
        elsewhere (a peer relay; at a phone, its relay). ``settle_ms`` is the
        channel's settle window now (a relay's measured peer RTT)."""
        self.settle_ms = min(SETTLE_CAP_MS, max(0, settle_ms))
        last = self.counters.last(self.channel_tag, c.who)
        rec = self.find(c.who, c.spurt)
        if rec is not None or (last is not None and c.spurt <= last):
            if rec is not None and self.role == "relay" and rec.local and c.local:
                self._retry(now, rec)
            return self._take()
        for r in self._sorted():
            if r.who == c.who and r.state != ENDED and not r.own:
                self._end(now, r, "superseded")
        rec = Rec(c, now)
        rec.limit_s = self.talk_limit_s
        if not self._insert(rec):
            return self._take()  # no room: dropped, and the counter not advanced, so a retry can land
        self.counters.advance(now, self.channel_tag, c.who, c.spurt)
        blocker = self._blocks(rec)
        if self.role == "relay" and rec.local:
            if blocker is not None:
                rec.state = KNOWN
                self._emit("busy", rec, blocker)
            else:
                rec.state = PENDING
                rec.hold_until = now + self.settle_ms
                self._emit("pending", rec)
        elif self.role == "relay" and blocker is None:
            rec.state = PENDING
            rec.hold_until = now + REMOTE_HOLD_MS
            self._emit("pending", rec)
        else:
            rec.state = KNOWN
            self._emit("known", rec)
        return self._take()

    def _retry(self, now, rec):
        """The same CLAIM again from the relay's own client: idempotent."""
        if rec.state == LIVE:
            self._emit("regrant", rec)
        elif rec.state == KNOWN:
            blocker = self._blocks(rec)
            if blocker is not None:
                self._emit("busy", rec, blocker)
            else:
                rec.state = PENDING
                rec.hold_until = now + self.settle_ms
                self._emit("pending", rec)

    def talking(self, now, tag, spurt, profile, limit_s):
        """A TALKING: evidence that the spurt was granted somewhere. It makes a
        pending or known spurt live; it never refreshes the silence clock and
        never resumes a lost one. Returns (actions, rec or None)."""
        rec = self.find_tag(tag, spurt)
        if rec is None or rec.own or (self.role == "relay" and rec.local):
            return self._take(), rec
        rec.profile = profile
        rec.limit_s = limit_s
        if self.role == "phone":
            # The phone's relay heartbeats only what it holds live, so it holds
            # nothing live that orders before this one: such a spurt here is a
            # zombie (its RELEASE lost). Soft: a frame brings it back if this
            # TALKING was stale.
            for r in self.lives():
                if r is not rec and not r.own and r.order < rec.order:
                    r.state = LOST
                    r.lost_at = now
                    self._emit("lost", r)
            if rec.state in (LOST, YIELDED):
                rec.state = LIVE
                rec.last_heard = now
                rec.quiet = False
                self._emit("resumed", rec)
                self._yield_rule(now)
        if rec.state in (PENDING, KNOWN):
            self._make_live(now, rec)
        return self._take(), rec

    def frame(self, now, rx, tag, spurt, seq):
        """A FRAME's clear header. Returns (actions, rec or None, forward)."""
        rec = self.find_tag(tag, spurt)
        if rec is None or rec.own:
            return self._take(), rec, False
        if rec.state in (PENDING, KNOWN):
            if self.role == "relay" and rec.local:
                return self._take(), rec, False
            rec.last_seq = max(rec.last_seq, seq)
            self._make_live(now, rec)
        elif rec.state in (LOST, YIELDED):
            # A lost spurt comes back only on a frame received within the resume
            # window: later ones are a backlog, and voice that is seconds late is
            # not voice. A yielded one's talker was still sending when it yielded.
            # Inside the window, only a frame on its spurt's schedule brings a lost
            # one back (v1.2): a backlog never does, however soon it arrives.
            windowed = rec.state == LOST or rec.lost_window
            if seq <= rec.last_seq or (rx - rec.lost_at >= RESUME_WINDOW_MS if windowed
                                       else now - rec.lost_at >= RESUME_MS) or (windowed and behind(rec, seq, rx)):
                return self._take(), rec, False
            rec.last_seq = seq
            w = self.holder()
            if w is not None and w.order < rec.order:
                if rec.state == LOST:
                    # Yielded now, but still a lost spurt: its window runs from the loss.
                    lost_at = rec.lost_at
                    self._yield_one(now, rec, w, "preempted" if can_preempt(w, rec) else "collision")
                    rec.lost_at, rec.lost_window = lost_at, True
                return self._take(), rec, False
            rec.state = LIVE
            rec.last_heard = now
            rec.quiet = False
            self._emit("resumed", rec)
            self._yield_rule(now)
        if rec.state != LIVE:
            return self._take(), rec, False
        rec.last_heard = max(rec.last_heard, rx)
        rec.last_seq = max(rec.last_seq, seq)
        fm = frame_ms(rec.profile)
        if fm:
            offset = rx - seq * fm
            if rec.best_offset is None or offset < rec.best_offset:
                rec.best_offset = offset
        if rec.quiet:
            rec.quiet = False
            self._emit("unquiet", rec)
        return self._take(), rec, True

    def release(self, now, who, spurt, tag):
        """A verified RELEASE, keyed on its signing key. Returns (actions, new):
        new when it ended a spurt. One that matches no record (it overtook its
        CLAIM, or it is junk under a fresh key) leaves a tombstone only in free
        or ended room, advances no counter, and is not new: it can neither
        evict a record nor a talker's replay counter."""
        rec = self.find(who, spurt)
        if rec is not None:
            if rec.state == ENDED:
                return self._take(), False
            self._end(now, rec, "released")
            return self._take(), True
        last = self.counters.last(self.channel_tag, who)
        if last is not None and spurt < last:
            return self._take(), False
        rec = Rec(Claim(who, tag, spurt, bytes(16)), now)
        if self._insert(rec, tombstone=True):
            self._end(now, rec, "released")
        return self._take(), False

    def tick(self, now, settle_ms=0):
        """Judge every timer, after the host has drained its ingress."""
        self.settle_ms = min(SETTLE_CAP_MS, max(0, settle_ms))
        gap = 0 if self.last_tick is None else now - self.last_tick
        self.last_tick = now
        if gap > QUIET_MS:
            # A pass longer than the quiet timer is not silence.
            for r in self.recs:
                if r.state == LIVE:
                    r.last_heard = min(now, r.last_heard + gap)
        for r in self._sorted():
            if r.state == LIVE and r.own:
                if now - r.live_since >= r.limit_s * 1000:
                    self._end(now, r, "limit")
            elif r.state == LIVE:
                if now - r.live_since >= r.limit_s * 1000 + LIMIT_GRACE_MS:
                    self._end(now, r, "limit")
                    continue
                silence = now - r.last_heard
                if silence >= r.lost_ms:
                    r.state = LOST
                    r.lost_at = now
                    self._emit("lost", r)
                elif silence >= QUIET_MS and not r.quiet:
                    r.quiet = True
                    self._emit("quiet", r)
            elif r.state == LOST:
                if now - r.lost_at >= RESUME_WINDOW_MS:
                    self._end(now, r, LOST)  # dead: its late frames are dropped, and never move the floor
            elif r.state == YIELDED:
                if now - r.lost_at >= (RESUME_WINDOW_MS if r.lost_window else RESUME_MS):
                    self._end(now, r, YIELDED)
            elif r.state == PENDING and r.own:
                if now >= r.retry_at:
                    if r.sends < CLAIM_SENDS:
                        r.sends += 1
                        r.retry_at = now + CLAIM_RETRY_MS
                        self._emit("retry", r)
                    else:
                        self._end(now, r, "gave_up")
            elif r.state == PENDING and not r.local:
                if now >= r.hold_until:
                    r.state = KNOWN
        if self.role == "relay":
            for r in self._sorted(PENDING):
                if not r.local or r.state != PENDING or now < r.hold_until:
                    continue
                if any(p.state == PENDING and p.order < r.order for p in self.recs):
                    continue
                blocker = self._blocks(r)
                if blocker is not None:
                    r.state = KNOWN
                    self._emit("busy", r, blocker)
                    continue
                for live in self.lives():
                    self._yield_one(now, live, r, "preempted")
                r.state = LIVE
                r.live_since = now
                r.last_heard = now
                self._emit("grant", r)
        self.recs = [r for r in self.recs if not (r.state == ENDED and now - r.ended_at >= TOMBSTONE_MS)]
        return self._take()

    # --- the phone's own claim -------------------------------------------------------

    def key(self, now, c):
        """The phone keys up: its own signed CLAIM, which the host sends now."""
        assert self.role == "phone"
        last = self.counters.last(self.channel_tag, c.who)
        if last is not None and c.spurt <= last:
            return self._take()  # a spurt id is never reused
        for r in self._sorted():
            if r.who == c.who and r.state != ENDED:
                self._end(now, r, "superseded")
        rec = Rec(c, now, own=True)
        rec.limit_s = self.talk_limit_s
        if not self._insert(rec):
            return self._take()
        self.counters.advance(now, self.channel_tag, c.who, c.spurt)
        rec.state = PENDING
        rec.sends = 1
        rec.retry_at = now + CLAIM_RETRY_MS
        self._emit("pending", rec)
        return self._take()

    def _own_pending(self, tag, spurt, live_too=False):
        r = self.own()
        if r is None or r.tag != tag or r.spurt != spurt:
            return None
        if r.state == PENDING or (live_too and r.state == LIVE):
            return r
        return None

    def _named(self, ref):
        """A SpurtRef that names a verified claim this phone holds (not its own)."""
        if ref is None:
            return None
        r = self.find_tag(ref[0], ref[1])
        return None if r is None or r.own else r

    def granted(self, now, tag, spurt, profile, limit_s):
        """A GRANT: taken only for the phone's own outstanding claim."""
        r = self._own_pending(tag, spurt)
        if r is not None:
            r.state = LIVE
            r.live_since = now
            r.profile = profile
            r.limit_s = limit_s
            self._emit("grant", r)
            self._yield_rule(now)
        return self._take()

    def busy(self, now, tag, spurt, holder, rate_limited=False):
        """A BUSY for the phone's own outstanding claim. ``holder`` is
        (talker tag, spurt) or None. Acted on only if it names a claim the phone
        holds, or is ``rate_limited`` without a holder."""
        r = self._own_pending(tag, spurt)
        if r is None:
            return self._take()
        h = self._named(holder)
        if h is None and not (rate_limited and holder is None):
            return self._take()
        r.state = ENDED
        r.ended_at = now
        self._emit("busy", r, h)
        return self._take()

    def yielded(self, now, tag, spurt, winner, preempted=False):
        """A YIELD for the phone's own claim or spurt, naming a claim it holds."""
        r = self._own_pending(tag, spurt, live_too=True)
        w = self._named(winner)
        if r is None or w is None:
            return self._take()
        r.state = ENDED
        r.ended_at = now
        self._emit("yield", r, w, "preempted" if preempted else "collision")
        return self._take()

    def end(self, now):
        """The user released the key (after the release tail)."""
        r = self.own()
        if r is not None:
            self._end(now, r, "released")
        return self._take()
