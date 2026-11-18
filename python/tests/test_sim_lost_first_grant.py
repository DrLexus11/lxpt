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


def mesh(drops):
    """drops: (t, to phone, whose GRANT (phone), spurt)."""
    phones = {n: SimpleNamespace(member={TAG: MT[n]}) for n in MT}
    return SimpleNamespace(phone=phones, net=SimpleNamespace(
        dropped_grants=[(t, "R", to, MT[who], sp) for t, to, who, sp in drops]))


def session(name, key_at, permit_at, spurt=1):
    return {"phone": name, "tag": TAG, "ref": (name.encode() * 16, spurt), "key_at": key_at, "permit_at": permit_at}


class LostFirstGrantClassifier(unittest.TestCase):
    def setUp(self):
        self.w = session("W", 1000, 1300)
        self.l = session("L", 1050, 1500)
        self.t_known = 1200

    def lfg(self, drops, n, w=None, l_=None):
        return sim.lost_first_grant(mesh(drops), w or self.w, l_ or self.l, n, self.t_known)

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

    def test_a_shape_needs_the_loser_itself_shown_after_knowing_the_winner(self):
        self.assertFalse(self.lfg([(1100, "L", "L", 1)], "X"))   # a listener, and the winner's GRANT was not lost
        early = session("L", 1050, 1150)                          # given the floor before it knew the winner
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


if __name__ == "__main__":
    unittest.main()
