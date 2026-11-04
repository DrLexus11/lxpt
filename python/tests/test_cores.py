"""The Python floor and relay cores against fixtures/lxpt_floor_v1.json and
fixtures/lxpt_relay_v1.json, and the simulator gate in brief.

Every scenario's lines are recorded as one "floor/<name>" or "relay/<name>"
cross-check line (the SHA-256 of every line it produced, joined by newlines),
the same lines the Kotlin and C++ suites record.
"""

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))

import gen_core_fixtures as gen  # noqa: E402
from lxpt import floor as fl  # noqa: E402
from lxpt import relay as rl  # noqa: E402
from tests.lines import record  # noqa: E402

FLOOR = json.loads((ROOT / "fixtures" / "lxpt_floor_v1.json").read_text())
RELAY = json.loads((ROOT / "fixtures" / "lxpt_relay_v1.json").read_text())


def digest(lines):
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


class FloorFixture(unittest.TestCase):
    def test_scenarios(self):
        for s in FLOOR["scenarios"]:
            f = fl.Floor(s["role"], bytes.fromhex(s["channel_tag"]), fl.Counters(s["talkers"]), s["capacity"],
                         s["talk_limit_s"])
            lines = []
            for k, e in enumerate(s["steps"]):
                got = gen.floor_step(f, e["at"], e)
                self.assertEqual(got, e["expect"], "%s step %d (%s at %d)" % (s["name"], k, e["do"], e["at"]))
                lines += got
            record("floor/" + s["name"], digest(lines))

    def test_constants(self):
        self.assertEqual(FLOOR["constants"], gen.constants())


class RelayFixture(unittest.TestCase):
    def test_scenarios(self):
        for s in RELAY["scenarios"]:
            r = rl.Relay(bytes.fromhex(s["relay_hash"]), rl.Limits(**s["limits"]), s["talk_limit_s"])
            lines = []
            for k, e in enumerate(s["steps"]):
                got = gen.relay_step(r, e["at"], e)
                self.assertEqual(got, e["expect"], "%s step %d (%s at %d)" % (s["name"], k, e["do"], e["at"]))
                lines += got
            record("relay/" + s["name"], digest(lines))


class FixturesFresh(unittest.TestCase):
    def test_regenerate_identically(self):
        self.assertEqual(gen.build_floor(), (ROOT / "fixtures" / "lxpt_floor_v1.json").read_text(),
                         "floor fixture is stale: run python3 python/gen_core_fixtures.py")
        self.assertEqual(gen.build_relay(), (ROOT / "fixtures" / "lxpt_relay_v1.json").read_text(),
                         "relay fixture is stale: run python3 python/gen_core_fixtures.py")


class SimulatorSmoke(unittest.TestCase):
    """One seed of the gate, so a unit-test run sees a regression early. CI
    runs the whole gate (python/sim.py) as its own job."""

    def test_one_seed(self):
        import sim
        _, r = sim.run(1, topology="line", duration_ms=240000)
        for k in sim.GATED:
            self.assertEqual(r[k], 0, (k, r["details"][:3]))
        self.assertGreater(r["contests"], 0)

    def test_deterministic(self):
        import sim
        a = sim.run(5, duration_ms=60000, acts=False)[1]
        b = sim.run(5, duration_ms=60000, acts=False)[1]
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
