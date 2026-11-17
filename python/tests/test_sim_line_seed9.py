"""The T2 simulator gate's line run, seed 9, pinned (spec/floor-v1.md choice 30).

With the late listener's GRANT (choice 31) shifting the run's random stream, this
run met the v1.0 path choice 30 closes: a relay's GRANT lost, a better remote
claim arriving before the talker's retry, and the retry regranted, so the phone
showed itself as holder 360 ms after knowing a claim that orders first. Every
gated count must stay 0 here, whatever else changes the stream. A full run of
the simulator (about a minute).
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))

import sim  # noqa: E402


class LineSeed9(unittest.TestCase):
    def test_every_gated_count_is_zero(self):
        _, r = sim.run(9, topology="line")
        for k in sim.GATED:
            self.assertEqual(r[k], 0, (k, [d for d in r["details"]]))


if __name__ == "__main__":
    unittest.main()
