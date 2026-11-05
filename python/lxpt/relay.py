"""The lxpt relay core v1: subscriptions, peers, dedup and forwarding choices
around one floor per channel.

Pure: the host hands it wire bytes received on a client leg or from a peer
relay, and ticks it; it answers with ``send`` actions (bytes to one client
leg or one peer) and ``note`` actions (floor decisions, for logs and tests).
``spec/floor-v1.md`` section 5 is the contract; ``cpp/include/lxpt/relay.hpp``
and ``Relay.kt`` follow this file, and ``fixtures/lxpt_relay_v1.json`` holds
all three to it.

The host's duties, which the core cannot do for it:

- call :meth:`Relay.admit_claim` on a CLAIM's bytes **before** verifying its
  signature (the rate limit is the cheap step), and pass to
  :meth:`Relay.client` only CLAIMs and RELEASEs whose signature verified;
- send each ``send`` action's bytes on that leg or peer link only, never
  broadcast, and never on an interface that refuses live streams;
- give the relay its measured stall p99 on every tick, and each peer's
  measured round trip.
"""

import hashlib

from . import wire
from .floor import KNOWN, LIVE, NEVER, PENDING, YIELDED, Claim, Counters, Floor, can_preempt, fmt_action

__all__ = ["Relay", "Limits"]

SUB_LEASE_MS = 60000
PEER_EVERY_MS = 5000
PEER_LOST_MS = 15000
TALKING_EVERY_MS = 2000
FRAME_MAX_AGE_MS = 500
# Lateness by media time (floor-v1.md section 5): a live spurt's frame later than
# LATE_MS behind its schedule is a backlog and is never forwarded; REANCHOR_AFTER
# late frames in a row at real-time pace are a talker whose numbering shifted, and
# re-anchor the schedule. The same rule Columba's listener applies (StaleSpurts).
LATE_MS = 800
REANCHOR_AFTER = 5
FRAME_MS = {"ulbw": 400, "vlbw": 320, "lbw": 200, "mq": 60, "hq": 60}
CLAIMS_PER_S = 2
EMERGENCY_EVERY_MS = 10000
YIELD_AGAIN_MS = 1000
NARROW = ("ble", "gfsk")
CODEC2 = ("ulbw", "vlbw", "lbw")


class Limits:
    """The relay's fixed capacities (spec/floor-v1.md section 5.1)."""

    def __init__(self, channels=32, legs=8, peers=4, spurts=4, dedup=128, talkers=64):
        self.channels, self.legs, self.peers = channels, legs, peers
        self.spurts, self.dedup, self.talkers = spurts, dedup, talkers


def _who(public_key):
    return hashlib.sha256(bytes(public_key)).digest()[:16]


class _Leg:
    __slots__ = ("carrier", "entries", "lease_until")

    def __init__(self):
        self.carrier = "ip"
        self.entries = []  # (channel tag, member tag, mode)
        self.lease_until = NEVER

    def narrow(self):
        return self.carrier in NARROW


class _Peer:
    __slots__ = ("up", "rtt_ms", "next_at", "heard", "relay_hash", "stall_ms", "channels", "last_seen")

    def __init__(self):
        self.up = False
        self.rtt_ms = 0
        self.next_at = NEVER
        self.heard = False
        self.relay_hash = bytes(16)
        self.stall_ms = 0
        self.channels = {}  # channel tag -> (narrow, [member tags])
        self.last_seen = NEVER


class _Channel:
    __slots__ = ("tag", "floor")

    def __init__(self, tag, counters, limits, talk_limit_s):
        self.tag = tag
        self.floor = Floor("relay", tag, counters, limits.spurts, talk_limit_s)


def _late(rec, seq, rx):
    """Whether frame [seq] of a live spurt, received at [rx], is more than LATE_MS
    behind the spurt's schedule. Updates the spurt's schedule as a side effect."""
    frame_ms = FRAME_MS.get(wire.PROFILES.get(rec.profile, ""), 0)
    if frame_ms == 0:
        return False  # no profile yet: nothing to judge by
    offset = rx - seq * frame_ms
    if rec.best_offset is None:
        rec.best_offset = offset
        rec.last_arrival = rx - frame_ms
    if offset < rec.best_offset:
        rec.best_offset = offset
    late = offset - rec.best_offset > LATE_MS
    rec.late_run = rec.late_run + 1 if late and rx - rec.last_arrival >= frame_ms // 2 else 0
    if rec.late_run >= REANCHOR_AFTER:
        rec.best_offset = offset
        rec.late_run = 0
        late = False
    rec.last_arrival = rx
    return late


class Relay:
    def __init__(self, relay_hash, limits=None, talk_limit_s=30):
        self.relay_hash = bytes(relay_hash)
        self.limits = limits or Limits()
        self.talk_limit_s = talk_limit_s
        self.legs = [None] * self.limits.legs
        self.admitted = [[NEVER, NEVER] for _ in range(self.limits.legs)]
        self.peers = [_Peer() for _ in range(self.limits.peers)]
        self.channels = {}
        self.counters = Counters(self.limits.talkers)
        self.dedup = {}
        self.dedup_ring = []
        self.dedup_at = 0
        self.stall_ms = 0
        self.out = []
        self.on_floor_action = None  # a test hook: called with (channel tag, floor action)

    # --- output --------------------------------------------------------------------

    def _take(self):
        out, self.out = self.out, []
        return out

    def _send(self, kind, index, data):
        self.out.append(("send", "%s%d" % (kind, index), bytes(data)))

    def _note(self, ch, a):
        self.out.append(("note", ch.tag, fmt_action(a)))

    # --- tables --------------------------------------------------------------------

    def _channel(self, tag, create):
        ch = self.channels.get(tag)
        if ch is None and create and len(self.channels) < self.limits.channels:
            ch = _Channel(tag, self.counters, self.limits, self.talk_limit_s)
            self.channels[tag] = ch
        return ch

    def _legs_on(self, tag, voice_only):
        """(leg index, leg, member tag, mode) of every live leg subscribed to tag."""
        out = []
        for i, leg in enumerate(self.legs):
            if leg is None:
                continue
            for ctag, mtag, mode in leg.entries:
                if ctag == tag and (mode == "voice" or not voice_only):
                    out.append((i, leg, mtag, mode))
                    break
        return out

    def _peers_on(self, tag, members_only):
        out = []
        for j, p in enumerate(self.peers):
            if p.up and p.heard and tag in p.channels and (not members_only or p.channels[tag][1]):
                out.append((j, p))
        return out

    def _settle(self, tag):
        """The settle window: the largest measured RTT of the peers listing the
        channel (the floor caps it at 300 ms); 0 with no peer."""
        settle = 0
        for _, p in self._peers_on(tag, False):
            settle = max(settle, p.rtt_ms)
        return settle

    def _dedup_seen(self, key):
        if key in self.dedup:
            return True
        if len(self.dedup_ring) < self.limits.dedup:
            self.dedup_ring.append(key)
        else:
            del self.dedup[self.dedup_ring[self.dedup_at]]
            self.dedup_ring[self.dedup_at] = key
            self.dedup_at = (self.dedup_at + 1) % self.limits.dedup
        self.dedup[key] = True
        return False

    # --- messages the relay builds ---------------------------------------------------

    def _ref(self, rec):
        return {"talker_tag": rec.tag, "spurt": rec.spurt, "tier": wire.TIERS[rec.tier],
                "emergency": rec.emergency}

    def _talking(self, ch, rec):
        return wire.encode({"type": "talking", "channel_tag": ch.tag, "holder": self._ref(rec),
                            "profile": wire.PROFILES[rec.profile], "talk_limit_s": rec.limit_s})

    def _grant_fields(self, ch, rec, profile_too=True):
        """The member tags reached and, at the first grant, the lowest common
        profile, which then stays the spurt's."""
        talker_leg = self.legs[rec.src] if 0 <= rec.src < len(self.legs) else None
        narrow = talker_leg is not None and talker_leg.narrow()
        reached = set()
        for i, leg, mtag, _ in self._legs_on(ch.tag, True):
            if i == rec.src:
                continue
            reached.add(mtag)
            narrow = narrow or leg.narrow()
        for _, p in self._peers_on(ch.tag, False):
            pn, members = p.channels[ch.tag]
            narrow = narrow or pn
            reached.update(members)
        reached.discard(rec.tag)
        rec.reached = sorted(reached)[:wire.GRANT_MAX_REACHED]
        if profile_too:
            rec.profile = wire.PROFILE_CODES["lbw" if narrow else "hq"]
            rec.limit_s = self.talk_limit_s

    def _grant(self, ch, rec):
        return wire.encode({"type": "grant", "channel_tag": ch.tag, "talker_tag": rec.tag, "spurt": rec.spurt,
                            "profile": wire.PROFILES[rec.profile], "talk_limit_s": rec.limit_s,
                            "reached": rec.reached})

    def _busy(self, ch, rec, holder, reason="busy"):
        return wire.encode({"type": "busy", "channel_tag": ch.tag, "talker_tag": rec.tag, "spurt": rec.spurt,
                            "reason": reason, "holder": self._ref(holder) if holder is not None else None})

    def _peer_summary(self, q):
        """PEER for peer q: every channel a live leg or another peer lists, its
        narrow flag and its member tags (split horizon: nothing learnt from q)."""
        entries, size = [], wire.PEER_MIN_LEN
        for tag in sorted(self.channels):
            listed, narrow, members = False, False, set()
            for _, leg, mtag, mode in self._legs_on(tag, False):
                listed = True
                if mode == "voice":
                    members.add(mtag)
                    narrow = narrow or leg.narrow()
            for j, p in self._peers_on(tag, False):
                if j == q:
                    continue
                listed = True
                pn, pm = p.channels[tag]
                narrow = narrow or pn
                members.update(pm)
            if not listed:
                continue
            members = sorted(members)[:wire.PEER_MAX_MEMBERS]
            need = wire.PEER_CHANNEL_MIN_LEN + 4 * len(members)
            if size + need > wire.MAX_MESSAGE_LEN or len(entries) == wire.PEER_MAX_CHANNELS:
                break
            size += need
            entries.append({"channel_tag": tag, "narrow": narrow, "members": members})
        return wire.encode({"type": "peer", "relay_hash": self.relay_hash,
                            "stall_p99_ms": min(0xFFFF, self.stall_ms), "channels": entries})

    # --- fan-out -------------------------------------------------------------------

    def _to_clients(self, ch, data, voice_only, skip=-1, rec=None):
        for i, leg, _, _ in self._legs_on(ch.tag, voice_only):
            if i == skip:
                continue
            if rec is not None and leg.narrow() and (rec.profile == 0 or wire.PROFILES[rec.profile] not in CODEC2):
                continue
            self._send("c", i, data)

    def _to_peers(self, ch, data, members_only, skip=-1):
        for j, _ in self._peers_on(ch.tag, members_only):
            if j != skip:
                self._send("p", j, data)

    def _pair_to_clients(self, ch, rec):
        """A live spurt's CLAIM, then its TALKING, to every leg on the channel but
        the talker's own: late joiners and lost CLAIMs recover from it."""
        if rec.profile == 0:
            return
        skip = rec.src if rec.local else -1
        talking = self._talking(ch, rec)
        for i, _, _, _ in self._legs_on(ch.tag, False):
            if i != skip:
                self._send("c", i, rec.blob)
                self._send("c", i, talking)
        rec.told = True

    def _pair_to_peers(self, ch, rec, skip):
        if rec.profile == 0:
            return
        talking = self._talking(ch, rec)
        for j, _ in self._peers_on(ch.tag, False):
            if j != skip:
                self._send("p", j, rec.blob)
                self._send("p", j, talking)

    def _apply(self, now, ch, actions):
        for a in actions:
            kind, rec, other, reason = a
            self._note(ch, a)
            if self.on_floor_action is not None:
                self.on_floor_action(ch.tag, a)
            src_leg = rec.src if rec.local else -1
            src_peer = rec.src if not rec.local else -1
            if kind in ("pending", "known"):
                self._to_clients(ch, rec.blob, False, src_leg)
                self._to_peers(ch, rec.blob, False, src_peer)
            elif kind == "grant":
                self._grant_fields(ch, rec)
                self._send("c", rec.src, self._grant(ch, rec))
                self._pair_to_clients(ch, rec)
                self._pair_to_peers(ch, rec, -1)
                rec.hb_next = now + TALKING_EVERY_MS
            elif kind == "regrant":
                self._grant_fields(ch, rec, False)
                self._send("c", rec.src, self._grant(ch, rec))
            elif kind == "busy":
                self._send("c", rec.src, other.blob)
                self._send("c", rec.src, self._busy(ch, rec, other))
            elif kind == "live":
                rec.hb_next = now + TALKING_EVERY_MS
                rec.announce = True
            elif kind == "yield" and rec.local:
                rec.nudge_at = now
                self._send("c", rec.src, other.blob)
                self._send("c", rec.src, wire.encode({
                    "type": "yield", "channel_tag": ch.tag, "talker_tag": rec.tag, "spurt": rec.spurt,
                    "reason": reason, "winner": self._ref(other)}))
        self._announce(ch)

    def _announce(self, ch):
        """After a floor call: a spurt that went live on evidence and is still
        live is announced, its CLAIM and TALKING to the legs and to the peers
        but its source. A relay's TALKING thus only ever names a spurt live
        there, which a phone relies on (spec 4.2)."""
        for rec in ch.floor.lives():
            if rec.announce:
                rec.announce = False
                self._pair_to_clients(ch, rec)
                self._pair_to_peers(ch, rec, rec.src)
        for rec in ch.floor.recs:
            rec.announce = False

    # --- events --------------------------------------------------------------------

    def admit_claim(self, now, leg, data):
        """The cheap check on a client's CLAIM, before its signature is verified:
        refuse a stale spurt silently, let a retry through, and admit at most
        two new claims per channel per second (else BUSY rate_limited).
        Returns (whether the host should verify it and pass it on, actions)."""
        return self._admit(now, leg, data), self._take()

    def _admit(self, now, leg, data):
        try:
            m = wire.decode(data)
        except wire.WireError:
            return False
        if m["type"] != "claim":
            return False
        ch = self.channels.get(m["channel_tag"])
        if ch is None:
            return False
        last = self.counters.last(ch.tag, _who(m["public_key"]))
        if last is not None and m["spurt"] < last:
            return False
        if last is not None and m["spurt"] == last:
            return True
        adm = self.admitted[leg]
        if now - adm[0] < 1000:
            holder = ch.floor.holder()
            if holder is not None:
                self._send("c", leg, holder.blob)
            self._send("c", leg, wire.encode({
                "type": "busy", "channel_tag": ch.tag, "talker_tag": m["talker_tag"], "spurt": m["spurt"],
                "reason": "rate_limited", "holder": self._ref(holder) if holder is not None else None}))
            return False
        self.admitted[leg] = [adm[1], now]
        return True

    def client(self, now, leg, data, rx=None, verified=False):
        """Bytes received on client leg ``leg`` (a TCP slot, a BLE peer). A CLAIM
        must have passed admit_claim and signature verification; ``verified``
        is whether its membership certificate verified (always False in v1)."""
        self._rx(now, "c", leg, data, now if rx is None else rx, verified)
        return self._take()

    def peer(self, now, index, data, rx=None, verified=False):
        """Bytes received from peer relay ``index`` (PLAIN one hop or a link)."""
        self._rx(now, "p", index, data, now if rx is None else rx, verified)
        return self._take()

    def leg_down(self, now, leg):
        """The TCP slot or BLE peer was released: its subscription goes at once."""
        self.legs[leg] = None
        self.admitted[leg] = [NEVER, NEVER]
        return self._take()

    def peer_up(self, now, index, rtt_ms=0):
        p = self.peers[index]
        p.up = True
        p.rtt_ms = rtt_ms
        p.next_at = now
        return self._take()

    def peer_rtt(self, now, index, rtt_ms):
        self.peers[index].rtt_ms = rtt_ms
        return self._take()

    def peer_down(self, now, index):
        self.peers[index] = _Peer()
        return self._take()

    def _rx(self, now, kind, idx, data, rx, verified):
        try:
            m = wire.decode(data)
        except wire.WireError:
            return
        t = m["type"]
        from_peer = kind == "p"
        if from_peer and not self.peers[idx].up:
            return
        if from_peer and self.peers[idx].heard:
            self.peers[idx].last_seen = now  # any message: the peer is not silent
        if t == "sub" and not from_peer:
            self._on_sub(now, idx, m)
        elif t == "peer" and from_peer:
            self._on_peer(now, idx, m)
        elif t == "claim":
            self._on_claim(now, kind, idx, m, data, verified)
        elif t == "frame":
            self._on_frame(now, kind, idx, m, data, rx)
        elif t == "release":
            self._on_release(now, kind, idx, m, data)
        elif t == "talking" and from_peer:
            self._on_talking(now, idx, m, data, rx)
        elif t == "heard":
            self._on_heard(kind, idx, m, data)

    def _on_sub(self, now, i, m):
        old = self.legs[i]
        before = set(e[0] for e in old.entries) if old is not None else set()
        leg = _Leg()
        leg.carrier = m["carrier"]
        leg.lease_until = now + SUB_LEASE_MS
        seen = set()
        for e in m["entries"]:
            tag = e["channel_tag"]
            if tag in seen or self._channel(tag, True) is None:
                continue
            seen.add(tag)
            leg.entries.append((tag, e["member_tag"], e["mode"]))
        self.legs[i] = leg
        for tag in sorted(seen - before):
            ch = self.channels[tag]
            for rec in ch.floor.lives():
                if rec.profile == 0 or (rec.local and rec.src == i):
                    continue
                self._send("c", i, rec.blob)
                self._send("c", i, self._talking(ch, rec))

    def _on_peer(self, now, j, m):
        p = self.peers[j]
        before = set(p.channels) if p.heard else set()
        p.heard = True
        p.relay_hash = m["relay_hash"]
        p.stall_ms = m["stall_p99_ms"]
        p.last_seen = now
        p.channels = {}
        for c in m["channels"]:
            if c["channel_tag"] not in p.channels and self._channel(c["channel_tag"], True) is not None:
                p.channels[c["channel_tag"]] = (c["narrow"], sorted(set(c["members"])))
        for tag in sorted(set(p.channels) - before):
            ch = self.channels[tag]
            for rec in ch.floor.lives():
                if rec.profile == 0 or (not rec.local and rec.src == j):
                    continue
                self._send("p", j, rec.blob)
                self._send("p", j, self._talking(ch, rec))

    def _on_claim(self, now, kind, idx, m, data, verified):
        ch = self.channels.get(m["channel_tag"])
        if ch is None:
            return
        who = _who(m["public_key"])
        local = kind == "c"
        last = self.counters.last(ch.tag, who)
        new = last is None or m["spurt"] > last
        if local and m["emergency"] and new and \
                now - self.counters.emergency_at(ch.tag, who) < EMERGENCY_EVERY_MS:
            holder = ch.floor.holder()
            if holder is not None:
                self._send("c", idx, holder.blob)
            self._send("c", idx, self._busy(ch, _Ref(m), holder, "rate_limited"))
            return
        stall = self.stall_ms if local else max(self.stall_ms, self.peers[idx].stall_ms)
        c = Claim(who, m["talker_tag"], m["spurt"], m["nonce"], wire.TIER_CODES[m["tier"]], m["emergency"],
                  verified, local, idx, stall, data)
        actions = ch.floor.claim(now, c, self._settle(ch.tag))
        if local and m["emergency"] and new:
            self.counters.set_emergency(ch.tag, who, now)
        self._apply(now, ch, actions)

    def _on_frame(self, now, kind, idx, m, data, rx):
        ch = self.channels.get(m["channel_tag"])
        if ch is None:
            return
        # A frame counts only from where its spurt's frames can come: a local
        # spurt's from its talker's own leg, a remote spurt's from a peer. The
        # relay cannot check the MAC, so a client can never move another's floor.
        named = ch.floor.find_tag(m["talker_tag"], m["spurt"])
        if named is not None and (named.local != (kind == "c") or (named.local and idx != named.src)):
            return
        if named is not None and named.state in (PENDING, KNOWN) and now - rx > FRAME_MAX_AGE_MS:
            return  # stale evidence never makes a spurt live: a backlog is not a talker
        key = m["channel_tag"] + m["talker_tag"] + m["spurt"].to_bytes(4, "big") + m["seq"].to_bytes(2, "big") + \
            m["mac"][:4]
        if self._dedup_seen(key):
            return
        # Judged on the spurt as it was live before this frame: a late one is held
        # back somewhere (a stalled pass, a socket buffer) -- a backlog, not voice. It
        # still counts as heard, as a stale one does; it is only not forwarded.
        late = named is not None and named.state == LIVE and _late(named, m["seq"], rx)
        actions, rec, forward = ch.floor.frame(now, rx, m["talker_tag"], m["spurt"], m["seq"])
        self._apply(now, ch, actions)
        nudge = rec if rec is not None and rec.local and rec.state == YIELDED else None
        if rec is None and kind == "c":
            # A spurt that is over here (lost past the resume window, or ended
            # otherwise) whose talker is still sending on its own leg: it is told
            # the same way, so a talker whose spurt died does not talk on unheard.
            dead = ch.floor.find_tag(m["talker_tag"], m["spurt"], ended=True)
            if dead is not None and dead.local and dead.src == idx:
                nudge = dead
        if nudge is not None and now - nudge.nudge_at >= YIELD_AGAIN_MS:
            # Its talker is still sending: the YIELD was lost (or never due). At most once a second.
            w = ch.floor.holder()
            if w is not None:
                nudge.nudge_at = now
                self._send("c", nudge.src, w.blob)
                self._send("c", nudge.src, wire.encode({
                    "type": "yield", "channel_tag": ch.tag, "talker_tag": nudge.tag, "spurt": nudge.spurt,
                    "reason": "preempted" if can_preempt(w, nudge) else "collision", "winner": self._ref(w)}))
        if not forward or late or now - rx > FRAME_MAX_AGE_MS:
            return
        self._to_clients(ch, data, True, idx if kind == "c" else -1, rec)
        for j, _ in self._peers_on(ch.tag, True):
            if not (kind == "p" and j == idx) and not (not rec.local and j == rec.src):
                self._send("p", j, data)

    def _on_release(self, now, kind, idx, m, data):
        ch = self.channels.get(m["channel_tag"])
        if ch is None:
            return
        actions, new = ch.floor.release(now, _who(m["public_key"]), m["spurt"], m["talker_tag"])
        self._apply(now, ch, actions)
        if new:
            self._to_clients(ch, data, False, idx if kind == "c" else -1)
            self._to_peers(ch, data, False, idx if kind == "p" else -1)

    def _on_talking(self, now, j, m, data, rx):
        ch = self.channels.get(m["channel_tag"])
        if ch is None or now - rx > FRAME_MAX_AGE_MS:
            return  # a stale TALKING (queued through a pass) says nothing about now; the next heartbeat will
        h = m["holder"]
        actions, rec = ch.floor.talking(now, h["talker_tag"], h["spurt"], wire.PROFILE_CODES[m["profile"]],
                                        m["talk_limit_s"])
        self._apply(now, ch, actions)
        if rec is None or rec.local or rec.state != LIVE:
            return
        if not rec.told:
            self._pair_to_clients(ch, rec)

    def _on_heard(self, kind, idx, m, data):
        ch = self.channels.get(m["channel_tag"])
        if ch is None:
            return
        rec = ch.floor.find_tag(m["talker_tag"], m["spurt"], ended=True)
        if rec is None or rec.src < 0:
            return
        if rec.local and not (kind == "c" and idx == rec.src):
            self._send("c", rec.src, data)
        elif not rec.local and not (kind == "p" and idx == rec.src):
            self._send("p", rec.src, data)

    def tick(self, now, stall_p99_ms=0):
        """Judge every timer and send what is due. Call it once per pass, after
        draining ingress, with the relay's measured stall p99."""
        self.stall_ms = max(0, stall_p99_ms)
        for i, leg in enumerate(self.legs):
            if leg is not None and now >= leg.lease_until:
                self.legs[i] = None
        for p in self.peers:
            if p.up and p.heard and now - p.last_seen >= PEER_LOST_MS:
                p.heard = False
                p.channels = {}
        for tag in sorted(self.channels):
            ch = self.channels[tag]
            self._apply(now, ch, ch.floor.tick(now, self._settle(tag)))
            for rec in ch.floor.lives():
                if now < rec.hb_next:
                    continue
                rec.hb_next = now + TALKING_EVERY_MS
                self._pair_to_clients(ch, rec)
                self._pair_to_peers(ch, rec, -1 if rec.local else rec.src)
        for j, p in enumerate(self.peers):
            if p.up and now >= p.next_at:
                p.next_at = now + PEER_EVERY_MS
                self._send("p", j, self._peer_summary(j))
        for tag in sorted(self.channels):
            ch = self.channels[tag]
            if not self._legs_on(tag, False) and not self._peers_on(tag, False) and ch.floor.empty():
                del self.channels[tag]
        return self._take()


class _Ref:
    """A claim not yet in the floor, as BUSY names it."""

    def __init__(self, m):
        self.tag = m["talker_tag"]
        self.spurt = m["spurt"]


def fmt_relay_action(a):
    """The fixture's line for a relay action."""
    if a[0] == "send":
        return "send %s %s" % (a[1], a[2].hex())
    return "note %s %s" % (a[1].hex(), a[2])
