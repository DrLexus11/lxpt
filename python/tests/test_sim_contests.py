"""Two key-ups that collide across relays, in the simulator, with no random loss.

These are the cases a floor rule must get right that the T2 gate's seeded runs
reach only now and then (review of #9, 2026-11-17):

- **A lost first GRANT.** L keys at relay R2, W at relay R0, W's claim orders
  first, and R2's first GRANT to L is lost, so L retries.
- **A slow talker leg.** L's leg to R2 is 320 ms one way, so L's GRANT arrives
  after its 600 ms retry has left.

For every seed and key-up offset, a floor rule must keep two things:

- **the contest is not dead:** at least one of the two is given the floor;
- **nobody who held the floor is yielded to a rival never given it;**
- **no talker whose frames a listener played is yielded:** cutting a spurt that
  is being heard is what the first draft of #9 did on the slow leg.

v0.4.0 keeps both in every case here.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))

import sim  # noqa: E402
from lxpt import wire  # noqa: E402

SEEDS = range(1, 11)


def contest(seed, dt, lost_first_grant=False, slow_leg_ms=0):
    """L (P6, at R2) keys at 5 s; W (P0, at R0) dt ms later. Returns the (L, W)
    sessions and how many of L's frames phones played, or None when the case is not
    one W orders first in, or the GRANT was not lost."""
    m = sim.Mesh(seed, topology="triangle", loss=0.0, dup=0.0, rtt_ms=60, narrow_phone=False)
    dropped = [not lost_first_grant]
    if lost_first_grant:
        transmit = m.net.transmit

        def tx(src, dst_name, data):
            if src.name == "R2" and dst_name == "P6" and not dropped[0]:
                try:
                    if wire.decode(data)["type"] == "grant":
                        dropped[0] = True
                        return
                except wire.WireError:
                    pass
            return transmit(src, dst_name, data)

        m.net.transmit = tx
    if slow_leg_ms:
        m.net.link(m.phone["P6"], m.relays[2], slow_leg_ms, 1, 0.0, 0.0)
    m.start()
    m.key(5000, "P6", m.A, 3000)
    m.key(5000 + dt, "P0", m.A, 3000)
    m.net.run(8000)
    ls, ws = m.phone["P6"].all_sessions, m.phone["P0"].all_sessions
    if not ls or not ws or not dropped[0] or not ws[0]["order"] < ls[0]["order"]:
        return None
    return ls[0], ws[0], m.log.played.get(ls[0]["ref"], 0)


class CollidingKeyUps(unittest.TestCase):
    def check(self, offsets, **kw):
        cases = 0
        for seed in SEEDS:
            for dt in offsets:
                r = contest(seed, dt, **kw)
                if r is None:
                    continue
                cases += 1
                L, W, l_played = r
                l_permit, w_permit = L["permit_at"] is not None, W["permit_at"] is not None
                where = "seed %d, W %+d ms: L %s/%s, W %s/%s, L's frames played %d" % (
                    seed, dt, l_permit, L["outcome"], w_permit, W["outcome"], l_played)
                self.assertTrue(l_permit or w_permit, "a dead contest: " + where)
                self.assertFalse(l_permit and L["outcome"] == "yield" and not w_permit,
                                 "a talker yielded to a rival never given the floor: " + where)
                self.assertFalse(L["outcome"] == "yield" and l_played > 0, "a talker cut while heard: " + where)
        self.assertGreater(cases, 50)

    def test_a_lost_first_grant(self):
        self.check(range(-120, 241, 15), lost_first_grant=True)

    def test_a_slow_talker_leg(self):
        self.check(range(-120, 481, 30), slow_leg_ms=320)


if __name__ == "__main__":
    unittest.main()
