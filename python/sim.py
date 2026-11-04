#!/usr/bin/env python3
"""The T2 simulator gate: a simulated mesh of 3 relays and 8 phones driving the
Python floor and relay cores, with loss, reordering, duplication, partitions
and injected relay stalls of 2, 5 and 18 s, checked against the invariants of
the talk-channel design's T2 gate (spec/floor-v1.md section 7 states them exactly).

Deterministic: every random choice comes from a seeded generator, so a run is
reproducible bit for bit. The C++ and Kotlin cores are held to the same
decisions by fixtures/lxpt_relay_v1.json, which carries traces recorded here.

    python3 python/sim.py                 # the gate: every scenario, every seed
    python3 python/sim.py --quick         # fewer seeds
    python3 python/sim.py --json out.json # also write the numbers
"""

import argparse
import hashlib
import heapq
import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from lxpt import floor as fl  # noqa: E402
from lxpt import wire  # noqa: E402
from lxpt.channel import ChannelKeys, channel_id  # noqa: E402
from lxpt.relay import Limits, Relay  # noqa: E402

TICK_MS = 50
# Convergence, after T (both claims known everywhere): a node must decide within
# one settle window and a tick of holding the winner's evidence (DECIDE_MS);
# and whatever the losses, every node must show the winner by ABSOLUTE_MS (one
# settle window, three heartbeats, half a second of delivery). Reported: how
# many took longer than one heartbeat (ONE_HEARTBEAT_MS).
DECIDE_MS = 300 + 50
ONE_HEARTBEAT_MS = 300 + 2000 + 500
ABSOLUTE_MS = 300 + 3 * 2000 + 500
FRAME_MS = {"hq": 60, "mq": 60, "lbw": 200, "vlbw": 320, "ulbw": 400}
STALLS_S = (2, 5, 18)


def H(label, n=32):
    out, i = b"", 0
    while len(out) < n:
        out += hashlib.sha256(("lxpt sim TEST %s %d" % (label, i)).encode()).digest()
        i += 1
    return out[:n]


class Net:
    """The event queue and the links. A link has a one-way delay, a jitter
    (which reorders), a loss and a duplication probability; partitions cut
    named relay pairs for a time window."""

    def __init__(self, rng):
        self.rng = rng
        self.q = []
        self.seq = 0
        self.now = 0
        self.links = {}
        self.cuts = []  # (t0, t1, frozenset({a, b}))

    def at(self, t, fn, *args):
        heapq.heappush(self.q, (t, self.seq, fn, args))
        self.seq += 1

    def run(self, until):
        while self.q and self.q[0][0] <= until:
            t, _, fn, args = heapq.heappop(self.q)
            self.now = t
            fn(*args)
        self.now = until

    def link(self, a, b, delay, jitter, loss, dup):
        self.links[(a.name, b.name)] = (b, delay, jitter, loss, dup)
        self.links[(b.name, a.name)] = (a, delay, jitter, loss, dup)

    def cut_at(self, t, a, b):
        pair = frozenset((a, b))
        return any(t0 <= t < t1 and p == pair for t0, t1, p in self.cuts)

    def transmit(self, src, dst_name, data):
        dst, delay, jitter, loss, dup = self.links[(src.name, dst_name)]
        if self.cut_at(self.now, src.name, dst_name):
            return
        r = self.rng.random()
        if r < loss:
            return
        copies = 2 if self.rng.random() < dup else 1
        for _ in range(copies):
            self.at(self.now + delay + int(self.rng.random() * jitter), dst.deliver, src.name, bytes(data))


class Log:
    def __init__(self):
        self.seq = 0
        self.holder = {}      # (node, ch) -> [(t, seq, ref)]
        self.known = {}       # (node, ch, ref) -> t
        self.evidence = {}    # (node, ch, ref) -> [t]
        self.notes = {}       # (relay, ch) -> [(t, seq, kind, ref, other)]
        self.forwards = {}    # (relay, ch, ref) -> [(t, seq)]
        self.frame_rx = {}    # (relay, ref) -> last delivery time
        self.frame_src = {}   # (relay, ref) -> [(delivery time, source node)]
        self.lost_ms = {}     # (relay, ref) -> the bound the relay applied
        self.passes = {}      # relay -> [(start, end)] of passes longer than a tick
        self.counts = {"frames_sent": 0, "frames_played": 0, "peer_summary_expiries": 0}

    def next(self):
        self.seq += 1
        return self.seq


def ref_of(rec):
    return (rec.who, rec.spurt)


class RelayNode:
    def __init__(self, net, log, name, core, trace=None):
        self.net, self.log, self.name, self.core = net, log, name, core
        self.legs = {}    # node name -> leg index
        self.peers = {}   # node name -> peer index
        self.by_leg = {}
        self.by_peer = {}
        self.stalled_until = -1
        self.queue = []
        self.last_pass = 0
        self.pass_hist = []
        self.trace = trace
        core.on_floor_action = self._floor_action

    def _floor_action(self, tag, a):
        kind, rec, other, _ = a
        ref = ref_of(rec)
        s = self.log.next()
        self.log.notes.setdefault((self.name, tag), []).append(
            (self.net.now, s, kind, ref, ref_of(other) if other is not None else None))
        self.log.known.setdefault((self.name, tag, ref), self.net.now)
        if kind == "lost":
            self.log.lost_ms[(self.name, ref)] = rec.lost_ms

    def start(self):
        for name, j in sorted(self.peers.items(), key=lambda x: x[1]):
            self._do("peer_up", j)
        self.net.at(TICK_MS, self.tick)

    def stall(self, start, dur):
        def begin():
            self.stalled_until = start + dur
            self.net.at(start + dur, end)

        def end():
            self.stalled_until = -1
            q, self.queue = self.queue, []
            for src, data, rx in q:
                self._process(src, data, rx)
            self._tick()
        self.net.at(start, begin)

    def deliver(self, src, data):
        if self.net.now < self.stalled_until:
            self.queue.append((src, data, self.net.now))
            return
        self._process(src, data, self.net.now)

    def _do(self, what, *args):
        now = self.net.now
        fn = getattr(self.core, what)
        acts = fn(now, *args)
        if self.trace is not None:
            self.trace.append((now, what, args, acts))
        self._emit(acts)
        return acts

    def _process(self, src, data, rx):
        try:
            kind = wire.peek_type(data)
        except wire.WireError:
            return
        if kind in ("frame", "talking"):
            try:
                m = wire.decode(data)
            except wire.WireError:
                m = None
            if m is not None:
                tag = m["channel_tag"]
                ch = self.core.channels.get(tag)
                if ch is not None:
                    tt, sp = (m["talker_tag"], m["spurt"]) if kind == "frame" else \
                        (m["holder"]["talker_tag"], m["holder"]["spurt"])
                    rec = ch.floor.find_tag(tt, sp)
                    if rec is not None:
                        self.log.evidence.setdefault((self.name, tag, ref_of(rec)), []).append(self.net.now)
                        if kind == "frame":
                            self.log.frame_rx[(self.name, ref_of(rec))] = rx
                            self.log.frame_src.setdefault((self.name, ref_of(rec)), []).append((rx, src))
        if src in self.legs:
            leg = self.legs[src]
            if kind == "claim":
                ok, acts = self.core.admit_claim(self.net.now, leg, data)
                if self.trace is not None:
                    self.trace.append((self.net.now, "admit", (leg, data, ok), acts))
                self._emit(acts)
                if not ok:
                    return
            self._do("client", leg, data, rx, self._verified(data, kind))
        else:
            self._do("peer", self.peers[src], data, rx, self._verified(data, kind))
        self._holders()

    @staticmethod
    def _verified(data, kind):
        """The host's membership check (T8's certificates): here, a fixed set."""
        if kind != "claim":
            return False
        return hashlib.sha256(wire.decode(data)["public_key"]).digest()[:16] in PhoneNode.verified_whos

    def _emit(self, acts):
        for a in acts:
            if a[0] != "send":
                continue
            target = a[1]
            data = a[2]
            idx = int(target[1:])
            dst = self.by_leg[idx] if target[0] == "c" else self.by_peer[idx]
            if wire.peek_type(data) == "frame":
                m = wire.decode(data)
                ch = self.core.channels.get(m["channel_tag"])
                rec = ch.floor.find_tag(m["talker_tag"], m["spurt"]) if ch else None
                if rec is not None:
                    self.log.forwards.setdefault((self.name, m["channel_tag"], ref_of(rec)), []).append(
                        (self.net.now, self.log.next()))
            self.net.transmit(self, dst, data)

    def _holders(self):
        for tag, ch in self.core.channels.items():
            h = ch.floor.holder()
            ref = ref_of(h) if h is not None else None
            hist = self.log.holder.setdefault((self.name, tag), [])
            if not hist or hist[-1][2] != ref:
                hist.append((self.net.now, self.log.next(), ref))

    def p99(self):
        now = self.net.now
        self.pass_hist = [(t, d) for t, d in self.pass_hist if now - t < 60000]
        if not self.pass_hist:
            return TICK_MS
        ds = sorted(d for _, d in self.pass_hist)
        return ds[max(0, -(-99 * len(ds) // 100) - 1)]

    def tick(self):
        self.net.at(self.net.now + TICK_MS, self.tick)
        if self.net.now < self.stalled_until:
            return
        self._tick()

    def _tick(self):
        now = self.net.now
        gap = now - self.last_pass
        self.pass_hist.append((now, gap))
        if gap > 2 * TICK_MS:
            self.log.passes.setdefault(self.name, []).append((self.last_pass, now))
        self.last_pass = now
        before = [p.heard for p in self.core.peers]
        self._do("tick", self.p99())
        self.log.counts["peer_summary_expiries"] += sum(
            1 for b, p in zip(before, self.core.peers) if b and not p.heard)
        self._holders()


class PhoneNode:
    def __init__(self, net, log, name, relay_name, carrier, channels, keys, cid_of):
        self.net, self.log, self.name, self.relay_name = net, log, name, relay_name
        self.carrier = carrier
        self.public_key = H("phone key " + name, 64)
        self.who = hashlib.sha256(self.public_key).digest()[:16]
        self.counters = fl.Counters(64)
        self.channels = channels  # channel tags
        self.keys = keys
        self.floors = {t: fl.Floor("phone", t, self.counters, 8) for t in channels}
        self.member = {t: keys[t].member_tag(self.who) for t in channels}
        self.alive = True
        self.spurt = 0
        self.sessions = {}  # tag -> session
        self.all_sessions = []
        self.rng = None

    def start(self, rng):
        self.rng = rng
        self.net.at(int(rng.random() * 200), self.sub)
        self.net.at(TICK_MS, self.tick)

    def send(self, data):
        if self.alive:
            self.net.transmit(self, self.relay_name, data)

    def sub(self):
        self.net.at(self.net.now + 20000, self.sub)
        if not self.alive:
            return
        self.send(wire.encode({"type": "sub", "carrier": self.carrier, "entries": [
            {"channel_tag": t, "member_tag": self.member[t], "mode": "voice"} for t in self.channels]}))

    def vanish(self, until):
        self.alive = False
        for s in self.sessions.values():
            s["stop_at"] = self.net.now
            s["vanished"] = True
        self.sessions = {}

        def back():
            self.alive = True
            self.sub()
        self.net.at(until, back)

    def key(self, tag, hold_ms, tier=4, emergency=False, verified=False):
        if not self.alive or tag in self.sessions:
            return
        self.spurt += 1
        nonce = bytes(int(self.rng.random() * 256) for _ in range(16))
        claim = wire.encode({"type": "claim", "channel_tag": tag, "talker_tag": self.member[tag],
                             "spurt": self.spurt, "epoch": 1, "nonce": nonce, "tier": wire.TIERS[tier],
                             "emergency": emergency, "clock_verified": False, "clock": 0,
                             "public_key": self.public_key, "signature": bytes(64)})
        c = fl.Claim(self.who, self.member[tag], self.spurt, nonce, tier, emergency, verified)
        s = {"phone": self.name, "relay": self.relay_name, "tag": tag, "ref": (self.who, self.spurt),
             "order": fl.order_key(self.who, self.spurt, nonce, tier, emergency, verified),
             "key_at": self.net.now, "hold_ms": hold_ms, "permit_at": None, "stop_at": None,
             "vanished": False, "claim": claim, "seq": 0, "outcome": None, "verified": verified}
        acts = self.floors[tag].key(self.net.now, c)
        if not any(a[0] == "pending" and a[1].own for a in acts):
            return
        self.sessions[tag] = s
        self.all_sessions.append(s)
        self._handle(tag, acts)
        self.send(claim)

    def _stop(self, tag, outcome, release=True):
        s = self.sessions.pop(tag, None)
        if s is None:
            return
        s["stop_at"] = self.net.now
        s["outcome"] = outcome
        if release:
            data = wire.encode({"type": "release", "channel_tag": tag, "talker_tag": self.member[tag],
                                "spurt": s["ref"][1], "frame_count": s["seq"],
                                "public_key": self.public_key, "signature": bytes(64)})
            self.send(data)
            self.net.at(self.net.now + 200, self.send, data)  # once more: a lost RELEASE holds a floor

    def _frame(self, tag, s, interval):
        if self.sessions.get(tag) is not s or not self.alive:
            return
        if self.net.now >= s["key_at"] + s["hold_ms"]:
            self._handle(tag, self.floors[tag].end(self.net.now))
            self._stop(tag, "released")
            return
        self.send(wire.encode({"type": "frame", "channel_tag": tag, "talker_tag": self.member[tag],
                               "spurt": s["ref"][1], "seq": s["seq"], "payload": bytes(8),
                               "mac": bytes(int(self.rng.random() * 256) for _ in range(8))}))
        self.log.counts["frames_sent"] += 1
        s["seq"] += 1
        self.net.at(self.net.now + interval, self._frame, tag, s, interval)

    def _handle(self, tag, acts):
        for kind, rec, other, reason in acts:
            ref = ref_of(rec)
            self.log.known.setdefault((self.name, tag, ref), self.net.now)
            if not rec.own:
                continue
            s = self.sessions.get(tag)
            if s is None or s["ref"] != ref:
                continue
            if kind == "retry":
                self.send(s["claim"])
            elif kind == "grant":
                s["permit_at"] = self.net.now
                interval = FRAME_MS[wire.PROFILES[rec.profile]]
                self.net.at(self.net.now + 1, self._frame, tag, s, interval)
            elif kind == "busy":
                self._stop(tag, "busy", release=False)
            elif kind == "yield":
                self._stop(tag, "yield")
            elif kind == "ended" and reason in ("gave_up", "limit"):
                self._stop(tag, reason)
        h = self.floors[tag].holder()
        href = ref_of(h) if h is not None else None
        hist = self.log.holder.setdefault((self.name, tag), [])
        if not hist or hist[-1][2] != href:
            hist.append((self.net.now, self.log.next(), href))

    def deliver(self, src, data):
        if not self.alive:
            return
        try:
            m = wire.decode(data)
        except wire.WireError:
            return
        t = m["type"]
        tag = m.get("channel_tag")
        if tag not in self.floors:
            return
        f = self.floors[tag]
        now = self.net.now
        if t == "claim":
            who = hashlib.sha256(m["public_key"]).digest()[:16]
            c = fl.Claim(who, m["talker_tag"], m["spurt"], m["nonce"], wire.TIER_CODES[m["tier"]], m["emergency"],
                         self._verified(who))
            self._handle(tag, f.claim(now, c))
        elif t == "talking":
            h = m["holder"]
            rec = f.find_tag(h["talker_tag"], h["spurt"])
            if rec is not None:
                self.log.evidence.setdefault((self.name, tag, ref_of(rec)), []).append(now)
            acts, _ = f.talking(now, h["talker_tag"], h["spurt"], wire.PROFILE_CODES[m["profile"]],
                                m["talk_limit_s"])
            self._handle(tag, acts)
        elif t == "frame":
            rec = f.find_tag(m["talker_tag"], m["spurt"])
            if rec is not None:
                self.log.evidence.setdefault((self.name, tag, ref_of(rec)), []).append(now)
            acts, _, play = f.frame(now, now, m["talker_tag"], m["spurt"], m["seq"])
            if play:
                self.log.counts["frames_played"] += 1
            self._handle(tag, acts)
        elif t == "release":
            who = hashlib.sha256(m["public_key"]).digest()[:16]
            acts, _ = f.release(now, who, m["spurt"], m["talker_tag"])
            self._handle(tag, acts)
        elif t == "grant":
            self._handle(tag, f.granted(now, m["talker_tag"], m["spurt"], wire.PROFILE_CODES[m["profile"]],
                                        m["talk_limit_s"]))
        elif t == "busy":
            h = m["holder"]
            self._handle(tag, f.busy(now, m["talker_tag"], m["spurt"],
                                     (h["talker_tag"], h["spurt"]) if h else None, m["reason"] == "rate_limited"))
        elif t == "yield":
            w = m["winner"]
            self._handle(tag, f.yielded(now, m["talker_tag"], m["spurt"], (w["talker_tag"], w["spurt"]),
                                        m["reason"] == "preempted"))

    verified_whos = frozenset()

    def _verified(self, who):
        return who in self.verified_whos

    def tick(self):
        self.net.at(self.net.now + TICK_MS, self.tick)
        if not self.alive:
            return
        for tag in self.channels:
            self._handle(tag, self.floors[tag].tick(self.net.now))


# --- the mesh and its scenarios ----------------------------------------------------------


class Mesh:
    def __init__(self, seed, rtt_ms=60, topology="triangle", loss=0.10, dup=0.03, trace=False,
                 narrow_phone=True):
        self.rng = random.Random(seed)
        self.net = Net(self.rng)
        self.log = Log()
        self.rtt_ms = rtt_ms
        self.topology = topology
        hub = H("hub", 16)
        self.tags = []
        self.keys = {}
        for room in ("ops", "medic"):
            cid = channel_id(hub, room)
            k = ChannelKeys(H("key " + room), cid)
            self.keys[k.channel_tag] = k
            self.tags.append(k.channel_tag)
        self.A, self.B = self.tags
        self.traces = {} if trace else None
        self.relays = []
        for i in range(3):
            tr = [] if trace else None
            r = RelayNode(self.net, self.log, "R%d" % i, Relay(H("relay %d" % i, 16), Limits()), tr)
            if trace:
                self.traces[r.name] = tr
            self.relays.append(r)
        on = {0: (0, 1, 2), 1: (3, 4, 5), 2: (6, 7)}
        self.phones = []
        for ri, ps in on.items():
            for pi in ps:
                chans = [self.A] + ([self.B] if pi in (0, 3, 6, 7) else [])
                carrier = "ble" if (narrow_phone and pi == 7) else "ip"
                p = PhoneNode(self.net, self.log, "P%d" % pi, "R%d" % ri, carrier, chans, self.keys, None)
                self.phones.append(p)
        self.phone = {p.name: p for p in self.phones}
        for p in self.phones:
            r = self.relays[int(p.relay_name[1])]
            leg = len(r.legs)
            r.legs[p.name] = leg
            r.by_leg[leg] = p.name
            self.net.link(p, r, 8, 20, loss, dup)
        pairs = [(0, 1), (1, 2), (0, 2)] if topology == "triangle" else [(0, 1), (1, 2)]
        d = rtt_ms // 2
        for a, b in pairs:
            ra, rb = self.relays[a], self.relays[b]
            ra.peers[rb.name] = len(ra.peers)
            ra.by_peer[ra.peers[rb.name]] = rb.name
            rb.peers[ra.name] = len(rb.peers)
            rb.by_peer[rb.peers[ra.name]] = ra.name
            self.net.link(ra, rb, max(1, d - d // 4), max(1, d // 2), loss, dup)
        self.pairs = pairs
        self.stalls = []
        self.partitions = []

    def start(self):
        for r in self.relays:
            r.start()
            for name, j in sorted(r.peers.items(), key=lambda x: x[1]):
                r._do("peer_rtt", j, self.rtt_ms)
        for p in self.phones:
            p.start(self.rng)

    def key(self, t, phone, tag, hold_ms, **kw):
        p = self.phone[phone]
        self.net.at(t, lambda: p.key(tag, hold_ms, **kw))

    def stall(self, t, relay, dur):
        self.stalls.append((relay, t, dur))
        self.relays[relay].stall(t, dur)

    def partition(self, t0, t1, a, b):
        self.partitions.append((t0, t1, a, b))
        self.net.cuts.append((t0, t1, frozenset(("R%d" % a, "R%d" % b))))

    def vanish(self, t, phone, back_at):
        self.net.at(t, self.phone[phone].vanish, back_at)

    def sessions(self):
        out = []
        for p in self.phones:
            out.extend(p.all_sessions)
        for s in out:
            if s["stop_at"] is None:
                s["stop_at"] = self.net.now
        return out

    def on_simple_paths(self, t, a, b):
        """Every relay on some simple path from relay a to relay b at time t
        (excluding b): a relay's forwarding can use any of them."""
        adj = {i: set() for i in range(3)}
        for x, y in self.pairs:
            if not self.net.cut_at(t, "R%d" % x, "R%d" % y):
                adj[x].add(y)
                adj[y].add(x)
        on = set()
        for p in _simple_paths(adj, a, b):
            on.update(p[:-1])
        return on

    def reachable(self, t, a, b):
        """Whether relay a reaches relay b at time t, and the relays on every
        shortest path (excluding b)."""
        up = [(x, y) for x, y in self.pairs if not self.net.cut_at(t, "R%d" % x, "R%d" % y)]
        adj = {i: set() for i in range(3)}
        for x, y in up:
            adj[x].add(y)
            adj[y].add(x)
        dist = {a: 0}
        frontier = [a]
        while frontier:
            nxt = []
            for u in frontier:
                for v in adj[u]:
                    if v not in dist:
                        dist[v] = dist[u] + 1
                        nxt.append(v)
            frontier = nxt
        if b not in dist:
            return False, set()
        on = set()
        back = {b}
        while back:
            nb = set()
            for v in back:
                for u in adj[v]:
                    if u in dist and dist[u] == dist[v] - 1:
                        on.add(u)
                        nb.add(u)
            back = nb
        return True, on


def _simple_paths(adj, a, b, seen=()):
    if a == b:
        yield (b,)
        return
    for v in sorted(adj[a]):
        if v not in seen and v != a:
            for p in _simple_paths(adj, v, b, seen + (a,)):
                yield (a,) + p


def schedule(m, rng, duration_ms, acts=True):
    """Acts on channel A, each in its own reserved window: a talker speaking
    through a stall of 2, 5 and 18 s at its own relay and at the next one; two
    partitions with a talker on each side, then the merge; two talkers who
    vanish mid-spurt; a verified commander's pre-emption, then an unverified
    Emergency. Contests (two or three key-ups within 300 ms, usually on
    different relays) fill every gap, on both channels."""
    reserved = {m.A: [], m.B: []}
    t = 3000
    plan = []
    if acts:
        for dur in STALLS_S:
            plan += [("stall", dur, "self"), ("stall", dur, "upstream")]
        plan += [("partition",), ("vanish", "P4"), ("partition",), ("vanish", "P1"), ("preempt",)]
    gap = (duration_ms - 10000 - sum(_span(a) for a in plan)) // (len(plan) + 1) if plan else 0
    for i, a in enumerate(plan):
        t += gap
        t0 = t
        if a[0] == "stall":
            talker = ("P0", "P3", "P6")[i % 3]
            ri = int(m.phone[talker].relay_name[1])
            hold = a[1] * 1000 + 6000
            m.key(t0, talker, m.A, hold)
            m.stall(t0 + 2000, ri if a[2] == "self" else (ri + 1) % 3, a[1] * 1000)
        elif a[0] == "partition":
            if m.topology == "triangle":
                m.partition(t0, t0 + 20000, 0, 2)
                m.partition(t0, t0 + 20000, 1, 2)
            else:
                m.partition(t0, t0 + 20000, 1, 2)
            left, right = (("P4", "P7"), ("P2", "P6"))[sum(1 for x in plan[:i] if x[0] == "partition") % 2]
            m.key(t0 + 3000, left, m.A, 22000)
            m.key(t0 + 3000 + int(rng.random() * 400), right, m.A, 22000)
        elif a[0] == "vanish":
            m.key(t0, a[1], m.A, 15000)
            m.vanish(t0 + 3000, a[1], t0 + 30000)
        elif a[0] == "preempt":
            m.key(t0, "P2", m.A, 10000)
            m.key(t0 + 2500, "P5", m.A, 3000, tier=1, verified=True)
            m.key(t0 + 7000, "P6", m.A, 2000, emergency=True)
        t += _span(a)
        reserved[m.A].append((t0 - 1500, t + 1500))
        if a[0] == "partition":
            reserved[m.B].append((t0 - 1500, t + 1500))
    end = duration_ms - 8000
    for tag in (m.A, m.B):
        t = 3000 + int(rng.random() * 2000)
        while t < end:
            hold = 1500 + int(rng.random() * 4500)
            span = (t, t + hold + 3500)
            if any(not (span[1] <= x or span[0] >= y) for x, y in reserved[tag]):
                t += 500
                continue
            pool = [p.name for p in m.phones if tag in p.channels]
            k = 1 + (rng.random() < 0.75) + (rng.random() < 0.3)
            chosen = []
            while len(chosen) < k:
                c = pool[int(rng.random() * len(pool))]
                if c not in chosen:
                    chosen.append(c)
            for c in chosen:
                m.key(t + int(rng.random() * 300), c, tag, hold + int(rng.random() * 1000))
            t = span[1] + int(rng.random() * 3000)


def _span(a):
    return {"stall": lambda: a[1] * 1000 + 9000, "partition": lambda: 30000, "vanish": lambda: 14000,
            "preempt": lambda: 13000}[a[0]]()


# --- the invariants ------------------------------------------------------------------------


def live_intervals(notes):
    """Per ref, from a relay's notes: [(start seq, start t, end seq, end t)]."""
    out = {}
    open_ = {}
    for t, s, kind, ref, other in notes:
        if kind in ("grant", "live", "resumed"):
            open_[ref] = (s, t)
        elif kind in ("yield", "ended", "lost") and ref in open_:
            s0, t0 = open_.pop(ref)
            out.setdefault(ref, []).append((s0, t0, s, t))
    for ref, (s0, t0) in open_.items():
        out.setdefault(ref, []).append((s0, t0, 1 << 60, 1 << 60))
    return out


def holder_at(hist, t):
    h = None
    for ht, _, ref in hist:
        if ht > t:
            break
        h = ref
    return h


def evaluate(m):
    log = m.log
    sessions = m.sessions()
    by_ref = {s["ref"]: s for s in sessions}
    res = {"collisions": 0, "collisions_checked": 0, "convergence_violations": 0, "convergence_max_ms": 0,
           "double_forward_violations": 0, "short_stall_frees": 0, "self_stall_frees": 0,
           "long_stall_losses": 0, "long_stall_resumes": 0, "vanish_checked": 0, "vanish_violations": 0,
           "vanish_max_over_ms": None, "contests": 0, "contests_settled": 0, "cross_contests": 0,
           "cross_settled": 0, "details": [], "conv_ms": [], "vanish_over": [], "winner_never_known": 0,
           "collisions_over_before_bound": 0, "double_forward_checked": 0, "converged_after_one_heartbeat": 0}
    nodes_for = {}
    for tag in m.tags:
        nodes_for[tag] = [r.name for r in m.relays] + [p.name for p in m.phones if tag in p.channels]
    vanished_phones = {s["phone"] for s in sessions if s["vanished"]}

    # 1. Convergence after a collision. T is when the last node to learn
    # them knew the winner's claim and (if it ever heard of it) the loser's;
    # from T + CONVERGE_MS on, until the winner stops, every node that knows
    # the winner shows the winner and never the loser.
    permitted = [s for s in sessions if s["permit_at"] is not None]
    collisions = []
    for i, a in enumerate(permitted):
        for b in permitted[i + 1:]:
            if a["tag"] != b["tag"]:
                continue
            if not (a["permit_at"] < b["stop_at"] and b["permit_at"] < a["stop_at"]):
                continue
            res["collisions"] += 1
            w, l_ = (a, b) if a["order"] < b["order"] else (b, a)
            collisions.append((w, l_))
            nodes = [n for n in nodes_for[a["tag"]] if n not in vanished_phones]
            knowing = {}
            for n in nodes:
                kw = log.known.get((n, a["tag"], w["ref"]))
                kl = log.known.get((n, a["tag"], l_["ref"]))
                if kw is None or kw >= w["stop_at"]:
                    if kl is not None or n.startswith("R"):
                        res["winner_never_known"] += 1  # e.g. W stopped before a merge reached n
                    continue
                knowing[n] = max(kw, kl if kl is not None and kl < w["stop_at"] else kw)
            if not knowing:
                continue
            t_known = max(knowing.values())
            if t_known + DECIDE_MS >= w["stop_at"]:
                res["collisions_over_before_bound"] += 1
                continue
            res["collisions_checked"] += 1
            for n in knowing:
                hist = log.holder.get((n, a["tag"]), [])
                shown_at = t_known if holder_at(hist, t_known) == w["ref"] else \
                    min([ht for ht, _, ref in hist if ref == w["ref"] and ht >= t_known] or [None]) \
                    if any(ref == w["ref"] and ht >= t_known for ht, _, ref in hist) else None
                evs = [t for t in log.evidence.get((n, a["tag"], w["ref"]), []) if t >= t_known]
                e = t_known if holder_at(hist, t_known) == w["ref"] else (evs[0] if evs else None)
                bad = None
                if any(ref == l_["ref"] and ht > (e if e is not None else t_known) + DECIDE_MS and ht < w["stop_at"]
                       for ht, _, ref in hist) or \
                        (e is not None and e + DECIDE_MS < w["stop_at"] and
                         holder_at(hist, e + DECIDE_MS) == l_["ref"]):
                    bad = "loser shown after the winner's evidence"
                elif e is not None and e + DECIDE_MS < w["stop_at"] and (shown_at is None or
                                                                          shown_at > e + DECIDE_MS):
                    bad = "winner not shown on its evidence"
                elif t_known + ABSOLUTE_MS < w["stop_at"] and (shown_at is None or shown_at > t_known + ABSOLUTE_MS):
                    bad = "winner not shown by T + %d ms" % ABSOLUTE_MS
                if bad:
                    res["convergence_violations"] += 1
                    res["details"].append(("convergence", bad, n, w["phone"], w["ref"][1], l_["phone"],
                                           l_["ref"][1], t_known))
                    continue
                if shown_at is None:
                    continue  # W stopped before it reached this node, within the bounds
                res["convergence_max_ms"] = max(res["convergence_max_ms"], shown_at - t_known)
                res["conv_ms"].append(shown_at - t_known)
                if shown_at - t_known > ONE_HEARTBEAT_MS:
                    res["converged_after_one_heartbeat"] += 1

    # 2. No relay forwards two spurts on one channel after it knows both:
    # (a) from the moment it holds both live, until either truly leaves;
    # (b) from when it knows both claims plus one settle window, until either
    #     ends there or the winner stops.
    for (rname, tag), notes in log.notes.items():
        iv = live_intervals(notes)
        refs = list(iv)
        for i, x in enumerate(refs):
            for y in refs[i + 1:]:
                for xs0, _, xs1, _ in iv[x]:
                    for ys0, _, ys1, _ in iv[y]:
                        if xs0 < ys1 and ys0 < xs1:  # live together: the second start is the moment
                            both = max(xs0, ys0)
                            until = min([n[1] for n in notes if n[1] > both and n[3] in (x, y)
                                         and n[2] in ("ended", "lost")] + [1 << 60])
                            fx = [s for _, s in log.forwards.get((rname, tag, x), []) if both < s < until]
                            fy = [s for _, s in log.forwards.get((rname, tag, y), []) if both < s < until]
                            if fx and fy:
                                res["double_forward_violations"] += 1
                                res["details"].append(("double forward", rname, x[1], y[1]))
    for w, l_ in collisions:
        tag = w["tag"]
        for r in m.relays:
            kw = log.known.get((r.name, tag, w["ref"]))
            kl = log.known.get((r.name, tag, l_["ref"]))
            if kw is None or kl is None:
                continue
            t0 = max(kw, kl) + fl.SETTLE_CAP_MS + TICK_MS
            notes = log.notes.get((r.name, tag), [])
            t1 = min([n[0] for n in notes if n[0] > t0 and n[3] in (w["ref"], l_["ref"])
                      and n[2] in ("ended", "lost")] + [w["stop_at"]])
            fw = [t for t, _ in log.forwards.get((r.name, tag, w["ref"]), []) if t0 < t < t1]
            fl_ = [t for t, _ in log.forwards.get((r.name, tag, l_["ref"]), []) if t0 < t < t1]
            res["double_forward_checked"] += 1
            # Knowing a claim is not knowing it was granted: the relay must stop
            # the loser once it holds the winner's evidence, i.e. once it has
            # forwarded a winner frame.
            if fw and any(t > fw[0] for t in fl_):
                res["double_forward_violations"] += 1
                res["details"].append(("forwarded both after knowing both", r.name, w["phone"], l_["phone"]))

    # 3. Stalls: no "lost" while the talker is still speaking, unless every
    # relay that had been delivering its frames to this one stalled for at
    # least this relay's floor-lost bound, or a partition cut the talker's
    # relay off. A relay's own stall never excuses it (nor does its talker's leg).
    for (rname, tag), notes in log.notes.items():
        n_idx = int(rname[1])
        for t, _, kind, ref, _ in notes:
            if kind != "lost":
                continue
            s = by_ref.get(ref)
            if s is None or s["permit_at"] is None or not (s["permit_at"] <= t < s["stop_at"]) or s["vanished"]:
                continue
            bound = log.lost_ms.get((rname, ref), fl.LOST_MIN_MS)
            t_idx = int(s["relay"][1])
            last_rx = max([rx for rx, _ in log.frame_src.get((rname, ref), []) if rx <= t] or [t - bound])
            if any(not m.reachable(probe, t_idx, n_idx)[0] for probe in range(last_rx - 500, t + 1, 100)):
                continue  # partitioned
            stalled = {ri for (ri, st, d) in m.stalls if d >= bound and st < t and st + d > last_rx}
            own = [d for (ri, st, d) in m.stalls if ri == n_idx and st < t and st + d > last_rx]

            def starved(x, seen):
                """Whether everything relay x was fed for this spurt came through a long stall."""
                if x in stalled and x != n_idx:
                    return True
                srcs = {src for rx, src in log.frame_src.get(("R%d" % x, ref), [])
                        if last_rx - 2000 <= rx <= last_rx}
                if not srcs or any(y.startswith("P") for y in srcs):
                    return False  # the talker's own relay, unstalled, or no feed seen
                # A feed that loops back to a relay being judged adds nothing.
                return all(starved(int(y[1]), seen | {x}) for y in srcs if int(y[1]) not in seen)
            if starved(n_idx, {n_idx}):
                res["long_stall_losses"] += 1
                if any(x[3] == ref and x[0] > t and x[2] == "resumed" for x in notes):
                    res["long_stall_resumes"] += 1
                else:
                    res["details"].append(("not resumed", rname, s["phone"], ref[1], t))
            elif own:
                res["self_stall_frees"] += 1
                res["details"].append(("self stall", rname, s["phone"], ref[1], t, own))
            else:
                res["short_stall_frees"] += 1
                res["details"].append(("short stall", rname, s["phone"], ref[1], t, last_rx, bound, sorted({x for _, x in log.frame_src.get((rname, ref), []) if last_rx - 2000 <= _ <= last_rx})))

    # 4. A vanished talker's floor is freed by floor-lost plus one pass.
    for s in sessions:
        if not s["vanished"] or s["permit_at"] is None:
            continue
        for r in m.relays:
            notes = log.notes.get((r.name, s["tag"]), [])
            live_before = any(x[3] == s["ref"] and x[2] in ("grant", "live", "resumed") and x[0] <= s["stop_at"]
                              for x in notes)
            if not live_before:
                continue
            ends = [x[0] for x in notes if x[3] == s["ref"] and x[2] in ("lost", "ended", "yield")
                    and x[0] >= s["stop_at"]]
            res["vanish_checked"] += 1
            last_rx = log.frame_rx.get((r.name, s["ref"]), s["stop_at"])
            bound = log.lost_ms.get((r.name, s["ref"]), fl.LOST_MIN_MS)
            longest = TICK_MS
            for a, b in log.passes.get(r.name, []):
                if b > last_rx and a < last_rx + bound + 20000:
                    longest = max(longest, b - a)
            limit = last_rx + bound + longest + TICK_MS
            if not ends or ends[0] > limit:
                res["vanish_violations"] += 1
                res["details"].append(("vanish", r.name, s["phone"], s["ref"][1], last_rx, bound, ends[:1]))
            if ends:
                over = ends[0] - (last_rx + bound)
                res["vanish_max_over_ms"] = over if res["vanish_max_over_ms"] is None else \
                    max(res["vanish_max_over_ms"], over)
                res["vanish_over"].append((over, longest))

    # Reported: contests settled before any permit.
    for tag in m.tags:
        ss = sorted((s for s in sessions if s["tag"] == tag), key=lambda s: s["key_at"])
        i = 0
        while i < len(ss):
            group = [ss[i]]
            j = i + 1
            while j < len(ss) and ss[j]["key_at"] < ss[i]["key_at"] + 1000:
                group.append(ss[j])
                j += 1
            idle = not any(o["permit_at"] is not None and o["permit_at"] <= ss[i]["key_at"] < o["stop_at"]
                           for o in ss if o not in group)
            if len(group) >= 2 and idle and not any(g["verified"] for g in group):
                permits = sum(1 for g in group if g["permit_at"] is not None)
                cross = len({g["relay"] for g in group}) > 1
                res["contests"] += 1
                res["contests_settled"] += permits <= 1
                if cross:
                    res["cross_contests"] += 1
                    res["cross_settled"] += permits <= 1
            i = j
    res["long_stall_unresumed"] = res["long_stall_losses"] - res["long_stall_resumes"]
    res["unresolved_claims"] = sum(1 for s in sessions if s["outcome"] is None and not s["vanished"]
                                   and s["key_at"] < m.net.now - 40000)
    res["peer_summary_expiries"] = log.counts["peer_summary_expiries"]
    res["frames_sent"] = log.counts["frames_sent"]
    res["frames_played"] = log.counts["frames_played"]
    return res


def run(seed, rtt_ms=60, topology="triangle", duration_ms=360000, trace=False, acts=True):
    m = Mesh(seed, rtt_ms=rtt_ms, topology=topology, trace=trace)
    PhoneNode.verified_whos = frozenset({m.phone["P5"].who})
    m.start()
    schedule(m, random.Random(seed * 7919 + 1), duration_ms, acts)
    m.net.run(duration_ms)
    return m, evaluate(m)


GATED = ("convergence_violations", "double_forward_violations", "short_stall_frees", "self_stall_frees",
         "vanish_violations", "unresolved_claims", "long_stall_unresumed")


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, max(0, -(-q * len(xs) // 100) - 1))] if xs else None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--quick", action="store_true", help="3 seeds instead of 10")
    ap.add_argument("--json", help="also write the numbers here")
    a = ap.parse_args()
    seeds = list(range(1, 4) if a.quick else range(1, 11))
    total, conv, over, details = {}, [], [], []
    for topo in ("triangle", "line"):
        for seed in seeds:
            _, r = run(seed, topology=topo)
            details += [(topo, seed) + d for d in r.pop("details")]
            conv += r.pop("conv_ms")
            over += r.pop("vanish_over")
            for k, v in r.items():
                if v is None:
                    continue
                total[k] = max(total.get(k, 0), v) if k.endswith("_max_ms") or k.endswith("_over_ms") else \
                    total.get(k, 0) + v
            print("%-8s seed %2d: %s" % (topo, seed, " ".join("%s=%s" % kv for kv in sorted(r.items()))))
    sweep = []
    for rtt in (20, 60, 120, 200, 300, 450, 600):
        c = st = cc = cs = 0
        for seed in seeds:
            _, r = run(100 + seed, rtt_ms=rtt, duration_ms=240000, acts=False)
            c += r["contests"]
            st += r["contests_settled"]
            cc += r["cross_contests"]
            cs += r["cross_settled"]
        sweep.append({"rtt_ms": rtt, "contests": c, "settled": st, "share": round(st / c, 3) if c else None,
                      "cross_relay": cc, "cross_settled": cs, "cross_share": round(cs / cc, 3) if cc else None})
    total["convergence_p50_ms"] = pct(conv, 50)
    total["convergence_p95_ms"] = pct(conv, 95)
    total["vanish_over_bound_p95_ms"] = pct([o for o, _ in over], 95)
    print("\n%d runs of 360 s (3 relays, 8 phones, 10%% loss, 3%% duplication, jitter, 2 partitions, stalls %s s)"
          % (2 * len(seeds), "/".join(str(x) for x in STALLS_S)))
    for k in sorted(total):
        print("  %-28s %s" % (k, total[k]))
    print("settled before any permit (contests of 2-3 key-ups within 300 ms), by relay-to-relay RTT:")
    for row in sweep:
        print("  RTT %3d ms: %3d/%3d contests (%s), cross-relay %3d/%3d (%s)" % (
            row["rtt_ms"], row["settled"], row["contests"], row["share"], row["cross_settled"],
            row["cross_relay"], row["cross_share"]))
    if a.json:
        Path(a.json).write_text(json.dumps({"totals": total, "sweep": sweep}, indent=1, sort_keys=True) + "\n")
    failed = [k for k in GATED if total.get(k, 0)]
    for d in details[:20]:
        print("  violation:", d)
    if failed:
        print("GATE FAILED:", ", ".join("%s=%d" % (k, total[k]) for k in failed))
        return 1
    print("gate: every invariant held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
