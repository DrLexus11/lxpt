#!/usr/bin/env python3
"""Regenerates fixtures/lxpt_floor_v1.json and fixtures/lxpt_relay_v1.json from
the Python reference cores (spec/floor-v1.md section 6).

Each scenario is a script of steps (an event and its inputs) with the lines the
reference produced for it: floor actions, relay sends and notes. The relay
fixture also carries traces recorded at the three relays of a short simulator
run (python/sim.py), so every decision the simulator gate rests on is replayed
by the C++ and Kotlin cores too. Every value is a TEST value.

    python3 python/gen_core_fixtures.py            # writes both fixtures
    python3 python/gen_core_fixtures.py --check    # exits 1 if either is stale
"""

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from lxpt import floor as fl  # noqa: E402
from lxpt import relay as rl  # noqa: E402
from lxpt import wire  # noqa: E402
from lxpt.channel import ChannelKeys, channel_id  # noqa: E402

ROOT = HERE.parent
FLOOR_FIXTURE = ROOT / "fixtures" / "lxpt_floor_v1.json"
RELAY_FIXTURE = ROOT / "fixtures" / "lxpt_relay_v1.json"


def h(label, n=32):
    out, i = b"", 0
    while len(out) < n:
        out += hashlib.sha256(("lxpt cores v1 TEST %s %d" % (label, i)).encode()).digest()
        i += 1
    return out[:n]


# --- the floor fixture -----------------------------------------------------------------

TAG = h("channel tag", 4)
WHO = {n: h("who " + n, 16) for n in ("ayse", "deniz", "cmd", "emre", "outsider", "phone")}
MTAG = {n: h("member tag " + n, 4) for n in WHO}
MTAG["outsider"] = MTAG["ayse"]  # an outsider signs a claim that carries Ayse's tag


def claim_ev(name, spurt, nonce_label=None, tier=4, emergency=False, verified=False, local=True, src=0,
             stall_ms=0, tag=None):
    return {"do": "claim", "who": WHO[name].hex(), "tag": (tag or MTAG[name]).hex(), "spurt": spurt,
            "nonce": h("nonce %s %d %s" % (name, spurt, nonce_label or ""), 16).hex(), "tier": tier,
            "emergency": emergency, "verified": verified, "local": local, "src": src, "stall_ms": stall_ms}


def ev_claim(e):
    return fl.Claim(bytes.fromhex(e["who"]), bytes.fromhex(e["tag"]), e["spurt"], bytes.fromhex(e["nonce"]),
                    e["tier"], e["emergency"], e["verified"], e["local"], e["src"], e["stall_ms"])


def floor_step(f, at, e):
    """Applies one step to a Python floor and returns its lines."""
    d = e["do"]
    lines = []
    if d == "ticks":
        # 'count' ticks 'every' ms apart from 'at', as a host's passes come.
        acts = []
        for k in range(e["count"]):
            acts += f.tick(at + k * e["every"], e.get("settle_ms", 0))
    elif d == "claim":
        acts = f.claim(at, ev_claim(e))
    elif d == "key":
        acts = f.key(at, ev_claim(e))
    elif d == "talking":
        acts, _ = f.talking(at, bytes.fromhex(e["tag"]), e["spurt"], e["profile"], e["limit_s"])
    elif d == "frame":
        acts, _, fwd = f.frame(at, e.get("rx", at), bytes.fromhex(e["tag"]), e["spurt"], e["seq"])
        lines.append("forward" if fwd else "drop")
    elif d == "release":
        acts, new = f.release(at, bytes.fromhex(e["who"]), e["spurt"], bytes.fromhex(e["tag"]))
        lines.append("new" if new else "seen")
    elif d == "tick":
        acts = f.tick(at, e.get("settle_ms", 0))
    elif d == "granted":
        acts = f.granted(at, bytes.fromhex(e["tag"]), e["spurt"], e["profile"], e["limit_s"])
    elif d == "busy":
        holder = (bytes.fromhex(e["holder"][0]), e["holder"][1]) if e["holder"] else None
        acts = f.busy(at, bytes.fromhex(e["tag"]), e["spurt"], holder, e["rate_limited"])
    elif d == "yielded":
        acts = f.yielded(at, bytes.fromhex(e["tag"]), e["spurt"], (bytes.fromhex(e["winner"][0]), e["winner"][1]),
                         e["preempted"])
    elif d == "end":
        acts = f.end(at)
    else:
        raise ValueError(d)
    out = [fl.fmt_action(a) for a in acts] + lines
    hd = f.holder()
    out.append("holder " + (hd.ref() if hd else "-"))
    return out


def ref_ev(name, spurt):
    return [MTAG[name].hex(), spurt]


def frame_ev(name, spurt, seq, rx=None):
    e = {"do": "frame", "tag": MTAG[name].hex(), "spurt": spurt, "seq": seq}
    if rx is not None:
        e["rx"] = rx
    return e


def talking_ev(name, spurt, profile=0x50, limit_s=30):
    return {"do": "talking", "tag": MTAG[name].hex(), "spurt": spurt, "profile": profile, "limit_s": limit_s}


def release_ev(name, spurt):
    return {"do": "release", "who": WHO[name].hex(), "spurt": spurt, "tag": MTAG[name].hex()}


def tick(settle_ms=0):
    return {"do": "tick", "settle_ms": settle_ms}


def ticks(count, every=50, settle_ms=0):
    return {"do": "ticks", "every": every, "count": count, "settle_ms": settle_ms}


def label_first(a, sa, b, sb):
    """A nonce label that makes (a, sa) order before (b, sb), both Members."""
    for i in range(1000):
        lab = "o%d" % i
        ka = fl.order_key(WHO[a], sa, h("nonce %s %d %s" % (a, sa, lab), 16), 4, False, False)
        kb = fl.order_key(WHO[b], sb, h("nonce %s %d %s" % (b, sb, lab), 16), 4, False, False)
        if ka < kb:
            return lab
    raise AssertionError


def floor_scenarios():
    S = []

    def sc(name, note, steps, role="relay", capacity=4, talkers=64, talk_limit_s=30):
        S.append({"name": name, "note": note, "role": role, "channel_tag": TAG.hex(), "capacity": capacity,
                  "talkers": talkers, "talk_limit_s": talk_limit_s, "steps": steps})

    sc("settle_then_grant", "a local claim is held for the settle window, then granted", [
        (0, tick(120)), (10, claim_ev("ayse", 1)), (50, tick(120)), (129, tick(120)), (130, tick(120)),
        (180, claim_ev("ayse", 1)), (200, frame_ev("ayse", 1, 0)), (260, frame_ev("ayse", 1, 1))])
    sc("busy_and_retries", "a claim on a held floor gets BUSY, a retry BUSY again, the holder's retry a GRANT", [
        (0, claim_ev("ayse", 1)), (0, tick()), (100, claim_ev("deniz", 1, src=1)), (300, claim_ev("deniz", 1, src=1)),
        (400, claim_ev("ayse", 1)), (500, release_ev("ayse", 1)), (600, claim_ev("deniz", 1, src=1)),
        (600, tick()), (700, tick())])
    lab = label_first("deniz", 1, "ayse", 1)
    sc("settle_orders_by_hash", "two local claims inside the window: the order decides, not arrival", [
        (0, tick(200)), (0, claim_ev("ayse", 1, lab)), (50, claim_ev("deniz", 1, lab, src=1)), (200, tick(200)),
        (250, tick(200)), (300, tick(200))])
    sc("remote_pending_blocks", "a remote claim that orders first holds a local one until its TALKING", [
        (0, claim_ev("deniz", 1, lab, local=False, src=0)), (10, claim_ev("ayse", 1, lab)),
        (10, tick(100)), (120, tick(100)), (200, talking_ev("deniz", 1)), (250, tick(100))])
    sc("remote_hold_expires", "with no evidence, a remote claim stops blocking after 600 ms", [
        (0, claim_ev("deniz", 1, lab, local=False)), (10, claim_ev("ayse", 1, lab)),
        (120, tick(100)), (599, tick(100)), (600, tick(100)), (650, tick(100))])
    sc("remote_after_order_does_not_block", "a remote claim that orders later does not hold a local one", [
        (0, claim_ev("ayse", 1, lab, local=False)), (10, claim_ev("deniz", 1, lab)), (10, tick(100)),
        (110, tick(100)), (150, talking_ev("ayse", 1))])
    sc("remote_live_by_frame", "a known remote claim goes live on its first FRAME", [
        (0, claim_ev("deniz", 1, local=False)), (40, frame_ev("deniz", 1, 0)), (100, frame_ev("deniz", 1, 1)),
        (150, frame_ev("deniz", 1, 1))])
    sc("merge_yield_soft", "two live spurts: the one that orders later yields, and comes back if the winner leaves "
       "while it is still talking", [
        (0, claim_ev("ayse", 1, lab)), (0, tick()), (100, frame_ev("ayse", 1, 0)),
        (200, claim_ev("deniz", 1, lab, local=False)), (210, frame_ev("deniz", 1, 0)),
        (300, frame_ev("ayse", 1, 1)), (400, frame_ev("deniz", 1, 1)), (500, release_ev("deniz", 1)),
        (600, frame_ev("ayse", 1, 2)), (650, frame_ev("ayse", 1, 2))])
    sc("preempt_verified", "a verified commander's claim cuts a member at the end of its window", [
        (0, claim_ev("ayse", 1)), (0, tick(50)), (1000, claim_ev("cmd", 1, tier=1, verified=True, src=2)),
        (1030, tick(50)), (1050, tick(50)), (1100, frame_ev("ayse", 1, 5))])
    sc("rights_table", "leader cuts member, deputy cuts leader, commander cuts deputy; equal tiers never cut, "
       "nobody cuts upward", [
        (0, claim_ev("emre", 1, tier=4, verified=True, src=2)), (0, tick()),
        (10, claim_ev("ayse", 1, tier=3, verified=True)), (10, tick()),
        (20, claim_ev("deniz", 1, tier=3, verified=True, src=1)), (20, tick()),
        (30, claim_ev("emre", 2, tier=4, verified=True, src=2)), (30, tick()),
        (40, claim_ev("cmd", 1, tier=2, verified=True, src=3)), (40, tick()),
        (50, claim_ev("ayse", 2, tier=1, verified=True)), (50, tick()),
        (60, claim_ev("deniz", 2, tier=2, verified=True, src=1)), (60, tick())])
    sc("unverified_tiers", "an unverified commander orders as a member and cuts nobody", [
        (0, claim_ev("ayse", 1)), (0, tick()), (100, claim_ev("cmd", 1, tier=1, src=2)), (100, tick())])
    sc("emergency", "unverified Emergency takes only an idle floor; two Emergency spurts never cut; a verified "
       "Emergency cuts any spurt without it", [
        (0, claim_ev("ayse", 1)), (0, tick()), (100, claim_ev("emre", 1, emergency=True, src=3)),
        (200, release_ev("ayse", 1)), (300, claim_ev("emre", 2, emergency=True, src=3)), (300, tick()),
        (400, claim_ev("deniz", 1, emergency=True, verified=True, src=1)), (400, tick()),
        (500, release_ev("emre", 2)), (600, claim_ev("ayse", 2)), (600, tick()),
        (700, claim_ev("deniz", 2, emergency=True, verified=True, src=1)), (700, tick())])
    sc("quiet_lost_resume", "silence: quiet at 1.2 s, lost at 5 s; continuing frames within the resume window "
       "resume; old ones do not", [
        (0, claim_ev("ayse", 1)), (0, tick()), (50, tick()), (100, frame_ev("ayse", 1, 0)), (100, ticks(22)),
        (1200, ticks(2)), (1400, frame_ev("ayse", 1, 1)), (1450, ticks(100)), (7350, frame_ev("ayse", 1, 1)),
        (7400, frame_ev("ayse", 1, 2)), (7450, ticks(3))])
    sc("lost_expires", "a lost spurt not resumed within the 2 s resume window ends; its later frames are dropped", [
        (0, claim_ev("ayse", 1)), (0, tick()), (100, ticks(100, 100)), (10100, ticks(160, 100)),
        (26100, frame_ev("ayse", 1, 3))])
    sc("resume_window_edges", "a frame received 1999 ms after the loss resumes; one received 2000 ms after it is "
       "dropped, and the spurt ends at that tick", [
        (0, claim_ev("ayse", 1)), (0, tick()), (100, ticks(50, 100)), (6999, frame_ev("ayse", 1, 0)),
        (7000, ticks(60, 100)), (14000, frame_ev("ayse", 1, 1)), (14000, tick()), (14100, frame_ev("ayse", 1, 2)),
        (14200, tick())])
    sc("resume_window_counts_rx", "the window is judged on when a frame was received: one queued during the relay's "
       "own stall, received inside the window, still resumes", [
        (0, claim_ev("ayse", 1)), (0, tick()), (100, ticks(50, 100)), (8000, frame_ev("ayse", 1, 0, rx=6500)),
        (8000, tick()), (8050, frame_ev("ayse", 1, 1))])
    labw = label_first("ayse", 1, "deniz", 1)
    sc("lost_resumes_in_window", "inside the window a lost spurt that orders first comes back over a spurt granted "
       "after the loss (a sub-second hiccup)", [
        (0, claim_ev("ayse", 1, labw)), (0, tick()), (100, frame_ev("ayse", 1, 0)), (150, ticks(51, 100)),
        (5250, claim_ev("deniz", 1, labw, src=1)), (5250, tick()), (5300, frame_ev("deniz", 1, 0)),
        (5900, frame_ev("ayse", 1, 1)), (6000, frame_ev("deniz", 1, 1)), (6000, tick())])
    sc("lost_dead_newer_keeps", "past the window a lost spurt is dead: its frames are dropped, and a spurt granted "
       "after the loss keeps the floor although the dead one orders first", [
        (0, claim_ev("ayse", 1, labw)), (0, tick()), (100, frame_ev("ayse", 1, 0)), (150, ticks(51, 100)),
        (5250, claim_ev("deniz", 1, labw, src=1)), (5250, tick()), (5300, frame_ev("deniz", 1, 0)),
        (6000, frame_ev("deniz", 1, 1)), (6000, ticks(13, 100)), (7300, frame_ev("ayse", 1, 1)),
        (7350, frame_ev("ayse", 1, 2)), (7400, frame_ev("deniz", 1, 2)), (7500, tick())])
    labd = label_first("deniz", 1, "ayse", 1)
    sc("lost_yield_keeps_window", "a lost spurt whose frame comes back inside the window while a spurt that "
       "orders first holds the floor yields, but keeps the lost spurt's window: a backlog after it is dropped and "
       "the spurt ends", [
        (0, claim_ev("ayse", 1, labd)), (0, tick()), (100, frame_ev("ayse", 1, 0)), (150, ticks(51, 100)),
        (5250, claim_ev("deniz", 1, labd, src=1)), (5250, tick()), (5300, frame_ev("deniz", 1, 0)),
        (6500, frame_ev("ayse", 1, 1)), (6600, release_ev("deniz", 1)), (6600, tick()),
        (7200, frame_ev("ayse", 1, 2)), (7200, tick()), (7300, frame_ev("ayse", 1, 3))])
    # The bench, 2026-11-04: two phones were TCP clients of an overloaded board.
    # It held Ayse's frames 16 s; the floor marked her spurt quiet, then lost;
    # Deniz keyed and was granted; her held frames arrived 13 s after the loss.
    # v0.2.0 resumed her stale spurt and Deniz, live, yielded to it by the order.
    bench = [(0, claim_ev("ayse", 1, labw)), (0, tick())]
    bench += [(500 * k, frame_ev("ayse", 1, k)) for k in range(9)]
    bench += [(4050, ticks(50, 100)), (9000, ticks(30, 100)), (12000, claim_ev("deniz", 1, labw, src=1)),
              (12000, tick())]
    seq = 0
    for t in range(12500, 24001, 500):
        if t == 22000:
            bench += [(22000, frame_ev("ayse", 1, 9 + k)) for k in range(4)]
        bench += [(t, frame_ev("deniz", 1, seq)), (t + 100, ticks(4, 100))]
        seq += 1
    bench += [(24500, release_ev("deniz", 1)), (24500, tick())]
    sc("bench_2026_11_04", "the bench failure: held 16 s, lost, another talker granted, the backlog arrives 13 s "
       "after the loss; the live talker keeps the floor and the backlog is not forwarded", bench)
    sc("stall_is_not_silence", "a pass longer than the quiet timer is not counted as silence; frames queued "
       "during it count from when they were received", [
        (0, claim_ev("ayse", 1)), (0, tick()), (50, ticks(10)), (500, frame_ev("ayse", 1, 0)),
        (4550, frame_ev("ayse", 1, 30, rx=1000)), (4550, ticks(100)), (9550, ticks(4))])
    sc("lost_bound_local_stall", "floor lost is max(5 s, 1.5 x stall p99): 6 s gives 9 s", [
        (0, claim_ev("ayse", 1, stall_ms=6000)), (0, tick()), (50, ticks(178)), (8950, ticks(2))])
    sc("lost_bound_capped", "and at most 15 s", [
        (0, claim_ev("deniz", 1, local=False, stall_ms=20000, src=1)), (10, frame_ev("deniz", 1, 0)),
        (10, ticks(300)), (15010, ticks(2))])
    sc("talk_limit", "a spurt is ended 1 s past its talk limit", [
        (0, claim_ev("ayse", 1)), (0, tick()), (500, frame_ev("ayse", 1, 0))]
        + [(1000 * k + 500, frame_ev("ayse", 1, k)) for k in range(1, 12)]
        + [(11999, tick()), (12000, tick()), (12100, frame_ev("ayse", 1, 13))], talk_limit_s=11)
    sc("release_tombstones", "a release ends the spurt; a late claim and frames are refused; an overtaking "
       "release blocks its claim", [
        (0, claim_ev("ayse", 1)), (0, tick()), (100, release_ev("ayse", 1)), (150, release_ev("ayse", 1)),
        (200, claim_ev("ayse", 1)), (210, frame_ev("ayse", 1, 4)), (300, release_ev("deniz", 7)),
        (310, claim_ev("deniz", 7, src=1)), (320, claim_ev("deniz", 6, src=1)), (330, release_ev("deniz", 3)),
        (340, claim_ev("deniz", 8, src=1)), (340, tick()), (30339, tick()), (30340, tick()),
        (30400, claim_ev("ayse", 1))])
    sc("keyed_on_identity", "an outsider's claim with a victim's tag is its own record; frames go to the live one", [
        (0, claim_ev("ayse", 5)), (0, tick()), (100, claim_ev("outsider", 5, src=4)),
        (200, frame_ev("ayse", 5, 0)), (300, claim_ev("outsider", 0xFFFFFFFF, src=4)),
        (400, release_ev("outsider", 5)), (500, frame_ev("ayse", 5, 1)), (600, release_ev("ayse", 5)),
        (700, claim_ev("ayse", 6)), (700, tick())])
    sc("superseded", "a talker's new spurt ends its old one", [
        (0, claim_ev("ayse", 1)), (0, tick()), (500, claim_ev("ayse", 2)), (500, tick()),
        (600, frame_ev("ayse", 1, 3)), (600, frame_ev("ayse", 2, 0))])
    sc("capacity_eviction", "a full table evicts ended, then known, then yielded and lost; never live or pending", [
        (0, claim_ev("ayse", 1)), (0, tick()), (10, claim_ev("deniz", 1, local=False, src=1)),
        (20, release_ev("ayse", 1)), (30, claim_ev("emre", 1, local=False, src=2)),
        (40, claim_ev("cmd", 1, local=False, src=3)), (700, tick()), (710, claim_ev("ayse", 2)),
        (720, claim_ev("outsider", 1, local=False, src=4)), (730, tick()), (740, claim_ev("deniz", 2, src=1)),
        (750, release_ev("emre", 9))], capacity=2)
    sc("counters_evict_lru", "replay counters keep the most recently advanced talkers", [
        (0, claim_ev("ayse", 3)), (0, tick()), (10, release_ev("ayse", 3)), (20, claim_ev("deniz", 3, src=1)),
        (20, tick()), (30, release_ev("deniz", 3)), (40, claim_ev("emre", 3, src=2)), (40, tick()),
        (50, release_ev("emre", 3)), (30100, tick()), (30200, claim_ev("ayse", 2)), (30210, claim_ev("emre", 2, src=2)),
        (30220, tick())], talkers=2)
    # The phone's side.
    own = lambda spurt, **kw: dict(claim_ev("phone", spurt, local=False, **kw), do="key")  # noqa: E731
    sc("phone_grant_limit", "a phone's claim, its GRANT, and its talk limit", [
        (0, own(1)), (100, {"do": "granted", "tag": MTAG["deniz"].hex(), "spurt": 1, "profile": 0x50, "limit_s": 5}),
        (150, {"do": "granted", "tag": MTAG["phone"].hex(), "spurt": 1, "profile": 0x30, "limit_s": 5}),
        (200, {"do": "granted", "tag": MTAG["phone"].hex(), "spurt": 1, "profile": 0x30, "limit_s": 5}),
        (5149, tick()), (5150, tick())], role="phone")
    sc("phone_retry_give_up", "no answer: two retries 600 ms apart, then the phone gives up", [
        (0, own(1)), (599, tick()), (600, tick()), (1200, tick()), (1800, tick()), (1850, tick())], role="phone")
    sc("phone_busy_needs_the_claim", "a BUSY counts only if it names a claim the phone holds", [
        (0, own(1)), (100, {"do": "busy", "tag": MTAG["phone"].hex(), "spurt": 1, "holder": ref_ev("ayse", 4),
                            "rate_limited": False}),
        (110, claim_ev("ayse", 4, local=False)),
        (120, {"do": "busy", "tag": MTAG["phone"].hex(), "spurt": 1, "holder": ref_ev("ayse", 4),
               "rate_limited": False}),
        (130, own(2)), (140, {"do": "busy", "tag": MTAG["phone"].hex(), "spurt": 2, "holder": None,
                             "rate_limited": True})], role="phone")
    sc("phone_yield", "a YIELD naming a held claim stops the talker; a forged one does not", [
        (0, own(1)), (100, {"do": "granted", "tag": MTAG["phone"].hex(), "spurt": 1, "profile": 0x50, "limit_s": 30}),
        (200, {"do": "yielded", "tag": MTAG["phone"].hex(), "spurt": 1, "winner": ref_ev("ayse", 9),
               "preempted": False}),
        (300, claim_ev("cmd", 2, local=False, tier=1, verified=True)),
        (310, {"do": "yielded", "tag": MTAG["phone"].hex(), "spurt": 1, "winner": ref_ev("cmd", 2),
               "preempted": True}), (320, talking_ev("cmd", 2))], role="phone")
    labp = label_first("ayse", 1, "phone", 1)
    sc("phone_self_yield", "a phone that learns a better live spurt stops by itself", [
        (0, own(1, nonce_label=labp)), (50, claim_ev("ayse", 1, local=False, nonce_label=labp)),
        (100, {"do": "granted", "tag": MTAG["phone"].hex(), "spurt": 1, "profile": 0x50, "limit_s": 30}),
        (200, talking_ev("ayse", 1)), (300, frame_ev("ayse", 1, 0))], role="phone")
    sc("phone_listener", "a listener: claim, TALKING, frames, quiet, release", [
        (0, claim_ev("ayse", 3, local=False)), (10, frame_ev("deniz", 1, 0)), (20, talking_ev("ayse", 3, 0x30, 20)),
        (30, frame_ev("ayse", 3, 0)), (50, ticks(26)), (1400, frame_ev("ayse", 3, 1)),
        (1500, release_ev("ayse", 3)), (1600, frame_ev("ayse", 3, 2)), (1700, {"do": "end"})], role="phone")
    labz = label_first("ayse", 1, "deniz", 1)
    sc("phone_relay_view", "a TALKING from the phone's relay retires a zombie that orders first (its RELEASE "
       "was lost); a frame of it brings it back if the TALKING was stale", [
        (0, claim_ev("ayse", 1, labz, local=False)), (10, talking_ev("ayse", 1)), (20, frame_ev("ayse", 1, 0)),
        (30, claim_ev("deniz", 1, labz, local=False)), (40, talking_ev("deniz", 1)), (50, frame_ev("deniz", 1, 0)),
        (60, frame_ev("ayse", 1, 1)), (70, frame_ev("deniz", 1, 1)), (80, talking_ev("deniz", 1))], role="phone")
    sc("phone_stale_backlog", "a phone drops a lost spurt's frames and TALKING once the window is over: a newer "
       "live spurt is never yielded to it", [
        (0, claim_ev("ayse", 1, labz, local=False)), (10, talking_ev("ayse", 1)), (20, frame_ev("ayse", 1, 0)),
        (50, ticks(100, 100)), (10000, claim_ev("deniz", 1, labz, local=False)), (10010, talking_ev("deniz", 1)),
        (10020, frame_ev("deniz", 1, 0)), (15000, frame_ev("ayse", 1, 1)), (15010, talking_ev("ayse", 1)),
        (15020, frame_ev("deniz", 1, 1))], role="phone")
    sc("phone_end", "the user releases the key", [
        (0, own(1)), (100, {"do": "granted", "tag": MTAG["phone"].hex(), "spurt": 1, "profile": 0x50, "limit_s": 30}),
        (900, {"do": "end"}), (950, own(1)), (960, own(2))], role="phone")
    return S


def build_floor():
    out = []
    for s in floor_scenarios():
        counters = fl.Counters(s["talkers"])
        f = fl.Floor(s["role"], bytes.fromhex(s["channel_tag"]), counters, s["capacity"], s["talk_limit_s"])
        steps = []
        clock = 0
        for at, e in s["steps"]:
            assert at >= clock, (s["name"], at, clock)
            clock = at + (e["count"] - 1) * e["every"] if e["do"] == "ticks" else at
            step = dict(e, at=at)
            step["expect"] = floor_step(f, at, e)
            steps.append(step)
        out.append(dict(s, steps=steps))
    fixture = {
        "note": ("lxpt floor core v1 (spec/floor-v1.md). Generated by python/gen_core_fixtures.py from the Python "
                 "reference; every value is a TEST value. Each scenario builds one Floor (role, channel_tag, "
                 "capacity, talk_limit_s) over Counters of 'talkers' entries, then runs its steps in order: 'do' "
                 "names the event, 'at' is the clock in ms, the other fields are its inputs (byte fields as hex). "
                 "'expect' is every line the step produced: the floor actions in order, then 'forward'/'drop' for a "
                 "frame and 'new'/'seen' for a release, then 'holder <who>/<spurt>' or 'holder -'."),
        "version": 1,
        "constants": constants(),
        "scenarios": out,
    }
    return json.dumps(fixture, indent=1, ensure_ascii=True) + "\n"


def constants():
    return {"settle_cap_ms": fl.SETTLE_CAP_MS, "remote_hold_ms": fl.REMOTE_HOLD_MS, "quiet_ms": fl.QUIET_MS,
            "lost_min_ms": fl.LOST_MIN_MS, "lost_max_ms": fl.LOST_MAX_MS, "resume_ms": fl.RESUME_MS,
            "resume_window_ms": fl.RESUME_WINDOW_MS,
            "tombstone_ms": fl.TOMBSTONE_MS, "limit_grace_ms": fl.LIMIT_GRACE_MS,
            "claim_retry_ms": fl.CLAIM_RETRY_MS, "claim_sends": fl.CLAIM_SENDS, "talk_limit_s": fl.TALK_LIMIT_S,
            "sub_lease_ms": rl.SUB_LEASE_MS, "peer_every_ms": rl.PEER_EVERY_MS, "peer_lost_ms": rl.PEER_LOST_MS,
            "talking_every_ms": rl.TALKING_EVERY_MS, "yield_again_ms": rl.YIELD_AGAIN_MS,
            "frame_max_age_ms": rl.FRAME_MAX_AGE_MS, "emergency_every_ms": rl.EMERGENCY_EVERY_MS}


# --- the relay fixture -----------------------------------------------------------------

HUB = h("hub", 16)
KEYS = {room: ChannelKeys(h("key " + room), channel_id(HUB, room)) for room in ("ops", "medic", "logistics")}
CT = {room: k.channel_tag for room, k in KEYS.items()}
PK = {n: h("public key " + n, 64) for n in ("ayse", "deniz", "cmd", "emre", "farid", "outsider")}
WHO_R = {n: hashlib.sha256(pk).digest()[:16] for n, pk in PK.items()}


def mt(n, room="ops"):
    return KEYS[room].member_tag(WHO_R[n])


def m_sub(entries, carrier="ip"):
    return wire.encode({"type": "sub", "carrier": carrier, "entries": [
        {"channel_tag": CT[room], "member_tag": mt(n, room), "mode": mode} for n, room, mode in entries]})


def m_claim(n, spurt, room="ops", tier="member", emergency=False, tag_of=None):
    return wire.encode({"type": "claim", "channel_tag": CT[room], "talker_tag": mt(tag_of or n, room),
                        "spurt": spurt, "epoch": 1, "nonce": h("nonce %s %d" % (n, spurt), 16), "tier": tier,
                        "emergency": emergency, "clock_verified": False, "clock": 0, "public_key": PK[n],
                        "signature": bytes(64)})


def m_frame(n, spurt, seq, room="ops", mac=None):
    return wire.encode({"type": "frame", "channel_tag": CT[room], "talker_tag": mt(n, room), "spurt": spurt,
                        "seq": seq, "payload": bytes([seq & 0xFF]) * 6,
                        "mac": mac or h("mac %s %d %d" % (n, spurt, seq), 8)})


def m_release(n, spurt, room="ops", count=0):
    return wire.encode({"type": "release", "channel_tag": CT[room], "talker_tag": mt(n, room), "spurt": spurt,
                        "frame_count": count, "public_key": PK[n], "signature": bytes(64)})


def m_talking(n, spurt, room="ops", profile="hq", limit=30, tier="member"):
    return wire.encode({"type": "talking", "channel_tag": CT[room], "holder": {
        "talker_tag": mt(n, room), "spurt": spurt, "tier": tier, "emergency": False},
        "profile": profile, "talk_limit_s": limit})


def m_peer(label, channels, stall=40):
    return wire.encode({"type": "peer", "relay_hash": h("relay " + label, 16), "stall_p99_ms": stall,
                        "channels": [{"channel_tag": CT[room], "narrow": narrow, "members": [mt(n, room) for n in ms]}
                                     for room, narrow, ms in channels]})


def m_heard(n, spurt, entries, room="ops"):
    return wire.encode({"type": "heard", "channel_tag": CT[room], "talker_tag": mt(n, room), "spurt": spurt,
                        "heard": [{"member_tag": mt(x, room), "frames": c} for x, c in entries]})


def relay_step(r, at, e):
    d = e["do"]
    if d == "ticks":
        # A run of idle ticks, 'every' ms apart from 'at': each must produce nothing.
        out = []
        for k in range(e["count"]):
            out += [rl.fmt_relay_action(a) for a in r.tick(at + k * e["every"], e["stall_ms"])]
        return out
    if d == "admit":
        ok, acts = r.admit_claim(at, e["leg"], bytes.fromhex(e["hex"]))
        return ["admit " + ("ok" if ok else "no")] + [rl.fmt_relay_action(a) for a in acts]
    if d == "client":
        acts = r.client(at, e["leg"], bytes.fromhex(e["hex"]), e.get("rx", at), e.get("verified", False))
    elif d == "peer":
        acts = r.peer(at, e["index"], bytes.fromhex(e["hex"]), e.get("rx", at), e.get("verified", False))
    elif d == "tick":
        acts = r.tick(at, e.get("stall_ms", 0))
    elif d == "leg_down":
        acts = r.leg_down(at, e["leg"])
    elif d == "peer_up":
        acts = r.peer_up(at, e["index"], e.get("rtt_ms", 0))
    elif d == "peer_rtt":
        acts = r.peer_rtt(at, e["index"], e["rtt_ms"])
    elif d == "peer_down":
        acts = r.peer_down(at, e["index"])
    else:
        raise ValueError(d)
    return [rl.fmt_relay_action(a) for a in acts]


def C(leg, data, **kw):
    return dict({"do": "client", "leg": leg, "hex": data.hex()}, **kw)


def A(leg, data):
    return {"do": "admit", "leg": leg, "hex": data.hex()}


def P(index, data, **kw):
    return dict({"do": "peer", "index": index, "hex": data.hex()}, **kw)


def T(stall_ms=0):
    return {"do": "tick", "stall_ms": stall_ms}


def spurt_first(a, b, sb):
    """A spurt for `a` whose claim orders before `b`'s spurt `sb` (both Members)."""
    kb = fl.order_key(WHO_R[b], sb, h("nonce %s %d" % (b, sb), 16), 4, False, False)
    for sa in range(1, 1000):
        if fl.order_key(WHO_R[a], sa, h("nonce %s %d" % (a, sa), 16), 4, False, False) < kb:
            return sa
    raise AssertionError


def claim_steps(at, leg, data):
    """A client's CLAIM as a host passes it: admitted first, then (verified) handed in."""
    return [(at, A(leg, data)), (at, C(leg, data))]


def relay_scenarios():
    S = []

    def sc(name, note, steps, limits=None, talk_limit_s=30):
        lim = limits or {}
        S.append({"name": name, "note": note, "relay_hash": h("this relay", 16).hex(),
                  "limits": {"channels": lim.get("channels", 32), "legs": lim.get("legs", 8),
                             "peers": lim.get("peers", 4), "spurts": lim.get("spurts", 4),
                             "dedup": lim.get("dedup", 128), "talkers": lim.get("talkers", 64)},
                  "talk_limit_s": talk_limit_s, "steps": steps})

    subs = [(0, C(0, m_sub([("ayse", "ops", "voice")]))), (0, C(1, m_sub([("deniz", "ops", "voice")]))),
            (0, C(2, m_sub([("emre", "ops", "watch"), ("emre", "medic", "voice")])))]
    sc("one_relay_spurt", "SUBs, a CLAIM forwarded, granted, frames to voice legs only, a duplicate dropped, "
       "HEARD upstream, RELEASE forwarded, heartbeats", subs + claim_steps(10, 0, m_claim("ayse", 1)) + [
        (10, T()), (60, C(0, m_frame("ayse", 1, 0))), (60, C(0, m_frame("ayse", 1, 0))),
        (120, C(0, m_frame("ayse", 1, 1))), (2010, T()), (2100, C(0, m_frame("ayse", 1, 2))), (4010, T()),
        (4100, C(0, m_release("ayse", 1, count=3))), (4200, C(1, m_heard("ayse", 1, [("deniz", 3)]))),
        (4300, C(0, m_frame("ayse", 1, 3))), (4400, T())])
    sc("narrow_leg_profile", "a BLE leg makes the spurt Codec2 and gets its frames; an Opus spurt skips it", [
        (0, C(0, m_sub([("ayse", "ops", "voice")]))), (0, C(1, m_sub([("deniz", "ops", "voice")], "ble")))]
        + claim_steps(10, 0, m_claim("ayse", 1)) + [(10, T()), (50, C(0, m_frame("ayse", 1, 0))),
                                                    (100, C(0, m_release("ayse", 1))), (100, T()),
                                                    (200, C(1, m_sub([("deniz", "medic", "voice")], "ble"))),
                                                    (200, C(2, m_sub([("emre", "ops", "voice")])))]
        + claim_steps(300, 0, m_claim("ayse", 2)) + [(300, T()), (310, C(1, m_sub([("deniz", "ops", "voice")], "ble"))),
                                                     (350, C(0, m_frame("ayse", 2, 0)))])
    sc("admission_rate_limit", "two new claims per client leg per second, so junk on one leg blocks only that "
       "leg; retries pass; stale ones are dropped", subs + [
        (100, C(3, m_sub([("cmd", "ops", "voice")]))), (100, C(4, m_sub([("farid", "ops", "voice")])))]
        + claim_steps(200, 0, m_claim("ayse", 5)) + claim_steps(300, 1, m_claim("deniz", 2))
        + [(400, A(3, m_claim("cmd", 1))), (450, A(0, m_claim("ayse", 5))), (460, A(0, m_claim("ayse", 4))),
           (470, A(4, m_claim("outsider", 1))), (480, A(4, m_claim("outsider", 2))), (490, A(4, m_claim("outsider", 3))),
           (500, T()), (1469, A(4, m_claim("farid", 1))), (1470, A(4, m_claim("farid", 1))),
           (1480, A(3, m_claim("outsider", 1, room="logistics")))])
    sc("emergency_rate_limit", "one Emergency claim per identity per channel per 10 s", subs + claim_steps(
        0, 0, m_claim("ayse", 1, emergency=True)) + [(0, T()), (100, C(0, m_release("ayse", 1)))]
        + claim_steps(5000, 0, m_claim("ayse", 2, emergency=True)) + claim_steps(10000, 0, m_claim("ayse", 3, emergency=True))
        + [(10000, T())])
    sc("busy_yield_carry_the_claim", "BUSY and YIELD are preceded by the holder's CLAIM", subs
        + claim_steps(0, 0, m_claim("ayse", 1)) + [(0, T())] + claim_steps(100, 1, m_claim("deniz", 1))
        + [(200, C(0, m_frame("ayse", 1, 0)))] + claim_steps(300, 1, m_claim("deniz", 1))
        + claim_steps(400, 2, m_claim("emre", 1, room="medic")) + [(400, T()), (500, T())]
        + [(600, C(2, m_frame("emre", 1, 0, room="medic")))]
        + [(700, {"do": "peer_up", "index": 0, "rtt_ms": 30}), (700, T()),
           (710, P(0, m_peer("north", [("ops", False, ["farid"])]))),
           (720, P(0, m_claim("cmd", 4, tier="commander"), verified=True)), (721, P(0, m_talking("cmd", 4, tier="commander")))])
    sc("peers", "peer up, PEER summaries with split horizon, a remote claim and its TALKING, frames both ways, "
       "TALKING forwarded at most once a second, peer lost after 15 s", subs + [
        (0, {"do": "peer_up", "index": 0, "rtt_ms": 80}), (0, {"do": "peer_up", "index": 1, "rtt_ms": 140}),
        (0, T(30)), (100, P(0, m_peer("north", [("ops", False, ["farid"]), ("medic", True, ["cmd"])], 900))),
        (110, P(1, m_peer("south", [("ops", False, [])]))), (200, P(0, m_claim("farid", 3))),
        (250, P(0, m_talking("farid", 3, profile="lbw"))), (260, P(0, m_frame("farid", 3, 0))),
        (300, P(0, m_talking("farid", 3, profile="lbw"))), (1300, P(0, m_talking("farid", 3, profile="lbw"))),
        (1400, P(1, m_frame("farid", 3, 1))), (2300, T(30)), (5000, T(30)),
        (5100, P(0, m_release("farid", 3)))] + claim_steps(5200, 0, m_claim("ayse", 7)) + [
        (5200, T(30)), (5279, T(30)), (5280, T(30)), (5340, C(0, m_frame("ayse", 7, 0))),
        (16000, P(0, m_peer("north", [("ops", False, ["farid"])]))), (20100, T(30)), (31000, T(30)),
        (31100, {"do": "peer_down", "index": 1}), (31200, C(0, m_frame("ayse", 7, 1))), (31300, T(30))])
    sc("late_joiners", "a leg or a peer that newly lists a channel with a live spurt gets its CLAIM and TALKING", subs
        + claim_steps(0, 0, m_claim("ayse", 1)) + [(0, T()), (50, C(3, m_sub([("cmd", "ops", "voice")]))),
                                                   (60, C(3, m_sub([("cmd", "ops", "voice")]))),
                                                   (70, {"do": "peer_up", "index": 2}),
                                                   (80, P(2, m_peer("east", [("medic", False, ["cmd"])]))),
                                                   (90, P(2, m_peer("east", [("ops", False, ["cmd"]),
                                                                             ("ops", True, ["farid"])])))])
    sc("leases", "a SUB lease runs 60 s; a released leg goes at once; an empty channel is freed", subs + [
        (30000, C(1, m_sub([("deniz", "ops", "voice")]))), (59999, T()), (60000, T()),
        (60010, {"do": "leg_down", "leg": 1}), (60015, A(2, m_claim("emre", 1, room="medic")))]
        + claim_steps(60020, 1, m_claim("deniz", 1)) + [(60030, T()), (90000, T())])
    sc("stale_frames_count_as_heard", "a frame older than 500 ms is not forwarded but still counts as heard", subs
        + claim_steps(0, 0, m_claim("ayse", 1)) + [(0, T()), (100, C(0, m_frame("ayse", 1, 0))),
                                                   (4000, C(0, m_frame("ayse", 1, 1), rx=3400)), (4000, T()),
                                                   (4100, C(0, m_frame("ayse", 1, 2), rx=3700)),
                                                   (8000, T()), (8500, T())])
    sc("settle_from_peer_rtt", "the settle window is the largest RTT of peers on the channel, capped at 300 ms", subs + [
        (0, {"do": "peer_up", "index": 0, "rtt_ms": 120}), (0, {"do": "peer_up", "index": 1, "rtt_ms": 900}),
        (5, P(0, m_peer("north", [("ops", False, ["farid"])]))), (5, P(1, m_peer("south", [("medic", False, ["cmd"])])))]
        + claim_steps(10, 0, m_claim("ayse", 1)) + [(100, T()), (129, T()), (130, T()),
                                                    (140, P(1, m_peer("south", [("ops", False, ["cmd"])]))),
                                                    (150, {"do": "peer_rtt", "index": 1, "rtt_ms": 250})]
        + claim_steps(160, 1, m_claim("deniz", 1, room="ops")) + [(160, C(0, m_release("ayse", 1)))]
        + claim_steps(1200, 1, m_claim("deniz", 2)) + [(1300, T()), (1449, T()), (1450, T())])
    sc("garbage_and_misdirected", "undecodable bytes and messages on the wrong side are ignored", subs + [
        (10, C(0, b"\x01")), (10, C(0, b"\x02\x01")), (10, C(0, bytes(30))), (20, C(0, m_talking("ayse", 1))),
        (30, C(0, m_peer("x", []))), (40, P(0, m_frame("ayse", 1, 0))), (50, {"do": "peer_up", "index": 0}),
        (60, P(0, m_sub([("ayse", "ops", "voice")]))), (70, A(0, m_frame("ayse", 1, 0))),
        (80, C(0, m_frame("ayse", 9, 0))), (90, C(0, m_claim("ayse", 1, room="logistics"))), (100, T())])
    sc("small_tables", "channels, spurts and dedup at their limits", [
        (0, C(0, m_sub([("ayse", "ops", "voice"), ("ayse", "medic", "voice")]))),
        (0, C(1, m_sub([("deniz", "ops", "voice"), ("deniz", "ops", "watch")])))]
        + claim_steps(10, 0, m_claim("ayse", 1)) + [(10, T()), (20, C(0, m_frame("ayse", 1, 0))),
                                                    (30, C(0, m_frame("ayse", 1, 1))), (40, C(0, m_frame("ayse", 1, 0))),
                                                    (50, C(0, m_frame("ayse", 1, 2))), (60, C(0, m_frame("ayse", 1, 0)))]
        + claim_steps(70, 1, m_claim("deniz", 1)), limits={"channels": 1, "spurts": 2, "dedup": 2})
    sb = spurt_first("farid", "ayse", 1)
    sc("frames_only_from_their_source", "a client cannot move a floor with a forged FRAME: a local spurt's frames "
       "count only from its talker's leg, a remote spurt's only from a peer", subs + [
        (0, {"do": "peer_up", "index": 0, "rtt_ms": 20}), (5, P(0, m_peer("north", [("ops", False, ["farid"])])))]
        + claim_steps(10, 0, m_claim("ayse", 1)) + [(40, T()), (50, C(1, m_frame("ayse", 1, 0))),
                                                    (60, C(0, m_frame("ayse", 1, 0))),
                                                    (70, P(0, m_claim("farid", sb))),
                                                    (80, C(1, m_frame("farid", sb, 65535))),
                                                    (90, C(0, m_frame("ayse", 1, 1))),
                                                    (100, P(0, m_frame("farid", sb, 0))),
                                                    (110, P(0, m_frame("ayse", 1, 2)))])
    # The bench, 2026-11-04, at the relay: two TCP clients of an overloaded
    # board. Ayse's frames are held back; her spurt goes quiet, lost, then dead
    # 2 s later; Deniz is granted; Ayse's backlog arrives 12.6 s and 13.6 s
    # after the loss.
    # It is not forwarded, Deniz keeps the floor, and Ayse's leg is told: the
    # holder's CLAIM and a YIELD, at most once a second.
    sa = spurt_first("ayse", "deniz", 1)
    bench = subs + claim_steps(10, 0, m_claim("ayse", sa)) + [(10, T())]
    bench += [(100 + 500 * k, C(0, m_frame("ayse", sa, k))) for k in range(9)]
    bench += [(1000 * k, T()) for k in range(5, 13)]
    bench += claim_steps(12500, 1, m_claim("deniz", 1)) + [(12500, T())]
    for k, t in enumerate(range(12600, 25000, 1000)):
        bench.append((t, C(1, m_frame("deniz", 1, k))))
        if t in (22600, 23600):
            bench += [(t + 10 * j + 10, C(0, m_frame("ayse", sa, 9 + 4 * (t == 23600) + j))) for j in range(4)]
        bench.append((t + 400, T()))
    bench += [(25000, C(1, m_release("deniz", 1))), (25000, T())]
    sc("bench_2026_11_04", "the bench failure at a relay: a backlog 13 s after the loss neither takes the floor "
       "from the live talker nor is forwarded; the dead spurt's talker gets the holder's CLAIM and a YIELD", bench)
    sc("stale_evidence_never_promotes", "a FRAME or TALKING queued through a pass (older than 500 ms) does not make "
       "a pending or known spurt live: after a relay's own stall, a backlog is not a talker", subs + [
        (0, {"do": "peer_up", "index": 0, "rtt_ms": 20}), (5, P(0, m_peer("north", [("ops", False, ["farid"])]))),
        (100, P(0, m_claim("farid", 3))), (1000, P(0, m_frame("farid", 3, 0), rx=300)),
        (1000, P(0, m_talking("farid", 3), rx=400)), (1000, T()), (1001, P(0, m_frame("farid", 3, 1), rx=500)),
        (1100, P(0, m_talking("farid", 3))), (1200, P(0, m_frame("farid", 3, 2)))])
    sc("stale_frames_and_foreign_legs", "a stale frame of a live local spurt still counts as heard, and one of a "
       "lost spurt received inside the window still resumes it (neither is forwarded); a frame naming an ended "
       "local spurt from another client leg gets no YIELD, its talker's own leg does", subs
        + claim_steps(10, 0, m_claim("ayse", 1)) + [
        (10, T()), (100, C(0, m_frame("ayse", 1, 0)))] + [(1000 * k, T()) for k in range(1, 5)] + [
        (5000, C(0, m_frame("ayse", 1, 1), rx=4400))] + [(1000 * k, T()) for k in range(5, 11)] + [
        (11000, C(0, m_frame("ayse", 1, 2), rx=10400)), (11000, T()),
        (12000, C(0, m_release("ayse", 1)))] + claim_steps(12100, 1, m_claim("deniz", 1)) + [
        (12100, T()), (12500, C(2, m_frame("ayse", 1, 3))), (12600, C(0, m_frame("ayse", 1, 4)))])
    sc("yield_again_while_the_talker_sends", "a yielded local talker that keeps sending gets the YIELD again, "
       "at most once a second", subs + [
        (0, {"do": "peer_up", "index": 0, "rtt_ms": 20}), (5, P(0, m_peer("north", [("ops", False, ["farid"])])))]
        + claim_steps(10, 0, m_claim("ayse", 1)) + [(40, T()), (50, C(0, m_frame("ayse", 1, 0))),
                                                    (60, P(0, m_claim("farid", sb))),
                                                    (70, P(0, m_talking("farid", sb, profile="lbw"))),
                                                    (500, C(0, m_frame("ayse", 1, 1))),
                                                    (1069, C(0, m_frame("ayse", 1, 2))),
                                                    (1070, C(0, m_frame("ayse", 1, 3))),
                                                    (1500, C(0, m_frame("ayse", 1, 4)))])
    sc("unmatched_release_and_heard", "a RELEASE that matches no record is not forwarded and moves no counter; "
       "it still blocks its own CLAIM; a HEARD for it goes nowhere", subs + [
        (0, C(0, m_release("deniz", 4))), (10, C(1, m_heard("deniz", 4, [("ayse", 0)])))]
        + claim_steps(20, 1, m_claim("deniz", 4)) + [(30, T())] + claim_steps(40, 1, m_claim("deniz", 3))
        + [(50, T())], limits={"spurts": 2})

    for name, trace in sim_traces():
        sc(name, "a trace recorded at this relay in python/sim.py's fixture run", trace)
        S[-1]["recorded"] = True
    return S


def sim_traces():
    """A short run of the simulator (a contest, a stall, a partition and its
    merge, a vanishing talker), recorded at each relay."""
    import sim
    m = sim.Mesh(77, rtt_ms=80, topology="triangle", trace=True)
    sim.PhoneNode.verified_whos = frozenset({m.phone["P5"].who})
    m.start()
    m.key(1500, "P0", m.A, 2500)
    m.key(1600, "P3", m.A, 2500)
    m.key(1650, "P6", m.A, 2500)
    m.key(6000, "P4", m.A, 5000)
    m.stall(7000, 1, 2000)
    m.partition(12000, 18000, 0, 2)
    m.partition(12000, 18000, 1, 2)
    m.key(13000, "P1", m.A, 7000)
    m.key(13100, "P7", m.A, 7000)
    m.key(22000, "P2", m.B if False else m.A, 4000)
    m.vanish(23000, "P2", 40000)
    m.key(24000, "P3", m.B, 1500)
    m.key(24100, "P6", m.B, 1500, emergency=True)
    m.key(26000, "P5", m.A, 1500, tier=1, verified=True)
    m.net.run(32000)
    out = []
    for r in m.relays:
        steps = []
        for now, what, args, acts in r.trace:
            lines = [rl.fmt_relay_action(a) for a in acts]
            if what == "peer_up":
                e = {"do": "peer_up", "index": args[0]}
            elif what == "admit":
                e = A(args[0], args[1])
                lines = ["admit " + ("ok" if args[2] else "no")] + lines
            elif what in ("client", "peer"):
                e = C(args[0], args[1]) if what == "client" else P(args[0], args[1])
                if args[2] != now:
                    e["rx"] = args[2]
                if args[3]:
                    e["verified"] = True
            elif what == "tick":
                prev = steps[-1] if steps else None
                if not lines and prev is not None and prev[1]["do"] == "ticks" and \
                        prev[1]["stall_ms"] == args[0] and now - prev[0] == prev[1]["every"] * prev[1]["count"]:
                    prev[1]["count"] += 1
                    continue
                if not lines:
                    steps.append((now, {"do": "ticks", "every": TICK_EVERY, "count": 1, "stall_ms": args[0]}, None))
                    continue
                e = T(args[0])
            elif what == "peer_rtt":
                e = {"do": "peer_rtt", "index": args[0], "rtt_ms": args[1]}
            else:
                raise ValueError(what)
            steps.append((now, e, lines))
        out.append(("sim_" + r.name, steps))
    return out


TICK_EVERY = 50


def build_relay():
    out = []
    for s in relay_scenarios():
        lim = s["limits"]
        hash_ = bytes.fromhex(s["relay_hash"])
        if s["name"].startswith("sim_R"):
            hash_ = sim_relay_hash(s["name"])
            s["relay_hash"] = hash_.hex()
        r = rl.Relay(hash_, rl.Limits(**lim), s["talk_limit_s"])
        steps = []
        recorded = s.pop("recorded", False)
        clock = 0
        for item in s["steps"]:
            at, e = item[0], item[1]
            assert at >= clock, (s["name"], at, clock)
            clock = at + (e["count"] - 1) * e["every"] if e["do"] == "ticks" else at
            step = dict(e, at=at)
            step["expect"] = relay_step(r, at, e)
            if recorded:
                want = item[2] if item[2] is not None else []
                assert step["expect"] == want, (s["name"], at, e["do"], step["expect"][:3], want[:3])
            steps.append(step)
        out.append(dict(s, steps=steps))
    fixture = {
        "note": ("lxpt relay core v1 (spec/floor-v1.md section 5). Generated by python/gen_core_fixtures.py from the "
                 "Python reference; every value is a TEST value and every signature a filler (the host verifies "
                 "before the core sees a CLAIM or RELEASE). Each scenario builds one Relay (relay_hash, limits, "
                 "talk_limit_s) and runs its steps in order: 'do' is admit, client, peer, tick, leg_down, peer_up, "
                 "peer_rtt or peer_down; 'at' is the clock in ms; 'hex' the bytes received; 'rx' when they were "
                 "received if not 'at'. 'expect' is every line the step produced, in order: 'admit ok|no' for an "
                 "admit, 'send c<leg>|p<peer> <hex>' and 'note <channel tag> <floor action>'. Scenarios named "
                 "sim_R<n> are traces recorded at relay n of python/sim.py's fixture run. A 'ticks' step is a run of "
                 "'count' ticks 'every' ms apart from 'at', none of which produced a line."),
        "version": 1,
        "constants": constants(),
        "scenarios": out,
    }
    return json.dumps(fixture, indent=1, ensure_ascii=True) + "\n"


def sim_relay_hash(name):
    import sim
    return sim.H("relay %d" % int(name[-1]), 16)


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--check", action="store_true", help="exit 1 if a fixture on disk differs")
    a = p.parse_args()
    random.seed(0)
    texts = {FLOOR_FIXTURE: build_floor(), RELAY_FIXTURE: build_relay()}
    if a.check:
        stale = [p.name for p, t in texts.items() if not p.exists() or p.read_text() != t]
        if stale:
            print("stale: %s; run python3 python/gen_core_fixtures.py" % ", ".join(stale), file=sys.stderr)
            return 1
        print("core fixtures up to date")
        return 0
    for path, text in texts.items():
        path.write_text(text)
        print("wrote %s (%d bytes, %d scenarios)" % (path, len(text), len(json.loads(text)["scenarios"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
