"""The gate's lost-first-GRANT category (spec 7, item 1; spec 9): a convergence
violation is reported apart only in the two shapes of v1's known limit, and any
other is still gated.

The classifier is checked on constructed sessions: both shapes, and each way of
almost matching. Simulator runs whose phones are made to show the loser show
that a violation of another shape, with no GRANT dropped, is still counted as a
violation. On a tree whose random stream reaches the limit (lxpt#8's, line
seeds 9 and 33), the gate classes exactly those two and nothing else.
"""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))

import sim  # noqa: E402
from lxpt import floor as fl  # noqa: E402

TAG = b"\x01\x02\x03\x04"
MT = {"W": b"\x0a\x0a\x0a\x0a", "L": b"\x0b\x0b\x0b\x0b", "X": b"\x0c\x0c\x0c\x0c"}


def mesh(drops, holder=None, evidence=None):
    """drops: (t, to phone, whose GRANT (phone), spurt); holder: {node: [(t, ref)]}, what
    each node showed; evidence: {node: [t]}, when it processed the winner's evidence."""
    phones = {n: SimpleNamespace(member={TAG: MT[n]}) for n in MT}
    w_ref = ref("W")
    log = SimpleNamespace(holder={(n, TAG): [(t, i, r) for i, (t, r) in enumerate(h)] for n, h in (holder or {}).items()},
                          evidence={(n, TAG, w_ref): ts for n, ts in (evidence or {}).items()})
    return SimpleNamespace(phone=phones, log=log, net=SimpleNamespace(
        dropped_grants=[(t, "R", to, MT[who], sp) for t, to, who, sp in drops]))


def ref(name, spurt=1):
    return (name.encode() * 16, spurt)


def session(name, key_at, permit_at, spurt=1, refused_by=None, stop_at=9000):
    return {"phone": name, "tag": TAG, "ref": ref(name, spurt), "key_at": key_at, "permit_at": permit_at,
            "refused_by": refused_by, "stop_at": stop_at}


class LostFirstGrantClassifier(unittest.TestCase):
    def setUp(self):
        self.w = session("W", 1000, 1300)
        self.l = session("L", 1050, 1500, refused_by=ref("W"))
        self.t_known = 1200

    def lfg(self, drops, n, w=None, l_=None, holder=None, evidence=None):
        return sim.lost_first_grant(mesh(drops, holder, evidence), w or self.w, l_ or self.l, n, self.t_known)

    def test_a_the_losers_first_grant_lost_and_the_loser_shown_after_knowing_the_winner(self):
        self.assertTrue(self.lfg([(1100, "L", "L", 1)], "L"))

    def test_b_the_winners_first_grant_lost_and_the_loser_given_the_floor_first(self):
        l_ = session("L", 1050, 1250)
        w = session("W", 1000, 1600)
        self.assertTrue(self.lfg([(1100, "W", "W", 1)], "X", w=w, l_=l_))

    def test_no_grant_dropped_is_gated(self):
        self.assertFalse(self.lfg([], "L"))
        self.assertFalse(self.lfg([], "X"))

    def test_a_grant_dropped_after_the_floor_was_given_is_not_a_first_grant(self):
        self.assertFalse(self.lfg([(1600, "L", "L", 1)], "L"))

    def test_a_grant_for_another_spurt_or_phone_does_not_count(self):
        self.assertFalse(self.lfg([(1100, "L", "L", 2)], "L"))
        self.assertFalse(self.lfg([(1100, "X", "L", 1)], "L"))
        self.assertFalse(self.lfg([(900, "L", "L", 1)], "L"))   # before its key-up: an older claim's

    def test_a_shape_needs_the_loser_yielded_to_the_winner(self):
        other = session("L", 1050, 1500, refused_by=ref("X"))
        self.assertFalse(self.lfg([(1100, "L", "L", 1)], "L", l_=other))
        never = session("L", 1050, 1500)
        self.assertFalse(self.lfg([(1100, "L", "L", 1)], "L", l_=never))

    def test_b_shape_needs_the_winners_grant_dropped_before_the_loser_held_the_floor(self):
        # Review of #12: triangle seed 11, yields off, the winner's GRANT dropped 2.5 s
        # after the loser already held the floor -- not this limit.
        l_ = session("L", 1050, 1250)
        w = session("W", 1000, 4000)
        self.assertFalse(self.lfg([(3750, "W", "W", 1)], "X", w=w, l_=l_))
        self.assertTrue(self.lfg([(1100, "W", "W", 1)], "X", w=w, l_=l_))

    def test_neither_shape_once_the_loser_is_shown_well_after_the_winners_evidence(self):
        l_ = session("L", 1050, 1250)
        w = session("W", 1000, 1600)
        late = {"X": [(1700, ref("W")), (1700 + sim.DECIDE_MS + 100, ref("L"))]}
        self.assertFalse(self.lfg([(1100, "W", "W", 1)], "X", w=w, l_=l_, holder=late, evidence={"X": [1650]}))
        soon = {"X": [(1660, ref("L"))]}
        self.assertTrue(self.lfg([(1100, "W", "W", 1)], "X", w=w, l_=l_, holder=soon, evidence={"X": [1650]}))
        self.assertFalse(self.lfg([(1100, "L", "L", 1)], "L", holder={"L": [(1600 + sim.DECIDE_MS + 50, ref("L"))]},
                                  evidence={"L": [1500]}))

    def test_a_shape_needs_the_loser_itself_shown_after_knowing_the_winner(self):
        self.assertFalse(self.lfg([(1100, "L", "L", 1)], "X"))   # a listener, and the winner's GRANT was not lost
        early = session("L", 1050, 1150, refused_by=ref("W"))     # given the floor before it knew the winner
        self.assertFalse(self.lfg([(1100, "L", "L", 1)], "L", l_=early))

    def test_b_shape_needs_the_loser_given_the_floor_before_the_winner(self):
        self.assertFalse(self.lfg([(1100, "W", "W", 1)], "X"))   # the winner first (1300 < 1500)
        never = session("W", 1000, None)
        self.assertFalse(self.lfg([(1100, "W", "W", 1)], "X", w=never))


class OtherShapesStayGated(unittest.TestCase):
    def test_phones_that_show_the_loser_are_still_violations(self):
        # Colliding key-ups at two relays, no loss, a 600 ms RTT so both are
        # granted: no GRANT is dropped. With yields off and phones made to show the
        # live spurt last in the claim order (a broken floor), the loser is shown
        # after the winner's evidence: that must count as a violation, not as the
        # known limit.
        orig, orig_yield = fl.Floor.holder, fl.Floor._yield_one

        def worst_on_phones(self):
            rs = self.lives()
            if self.role == "phone" and rs:
                return rs[-1]
            return orig(self)

        def never(self, now, loser, w, reason):
            return None

        fl.Floor.holder, fl.Floor._yield_one = worst_on_phones, never
        try:
            gated = 0
            for dt in range(-100, 101, 50):
                m = sim.Mesh(1, topology="triangle", loss=0.0, dup=0.0, rtt_ms=600, narrow_phone=False)
                m.start()
                m.key(5000, "P6", m.A, 4000)
                m.key(5000 + dt, "P0", m.A, 4000)
                m.net.run(12000)
                r = sim.evaluate(m)
                self.assertEqual(m.net.dropped_grants, [])
                self.assertEqual(r["convergence_lost_first_grant"], 0)
                gated += r["convergence_violations"]
            self.assertGreater(gated, 0)
        finally:
            fl.Floor.holder, fl.Floor._yield_one = orig, orig_yield


class DroppedGrantsAreRecorded(unittest.TestCase):
    def key_up(self, cut=False, loss=0.0):
        m = sim.Mesh(1, topology="triangle", loss=0.0, dup=0.0, rtt_ms=60, narrow_phone=False)
        if loss:   # one way only, relay to phone: the CLAIM still gets through
            dst, delay, jitter, _, dup = m.net.links[("R2", "P6")]
            m.net.links[("R2", "P6")] = (dst, delay, jitter, loss, dup)
        if cut:    # from just after the key-up: the CLAIM has left, the GRANT has not
            m.net.cuts.append((5001, 6000, frozenset({"R2", "P6"})))
        m.start()
        m.key(5000, "P6", m.A, 1000)
        m.net.run(6500)
        tag = m.phone["P6"].member[m.A]
        return [d for d in m.net.dropped_grants if d[1] == "R2" and d[2] == "P6" and d[3] == tag]

    def test_a_cut_link_records_the_grant_it_drops(self):
        self.assertTrue(self.key_up(cut=True))

    def test_a_lossy_link_records_the_grant_it_drops(self):
        self.assertTrue(self.key_up(loss=1.0))

    def test_a_clean_link_records_none(self):
        self.assertEqual(self.key_up(), [])


class LossOnRunsStayGated(unittest.TestCase):
    def test_triangle_seed_11_with_yields_off(self):
        # With loss on, GRANTs are dropped all through a run: a broken floor's
        # violations must still be gated, not taken for the known limit (review of #12).
        orig = fl.Floor._yield_one
        fl.Floor._yield_one = lambda self, now, loser, w, reason: None
        try:
            _, r = sim.run(11, topology="triangle")
        finally:
            fl.Floor._yield_one = orig
        self.assertGreater(r["convergence_violations"], 0)
        self.assertEqual(r["convergence_lost_first_grant"], 0)


if __name__ == "__main__":
    unittest.main()
