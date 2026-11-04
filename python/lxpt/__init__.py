"""lxpt: Lightweight Extensible Push-to-Talk, the Python reference implementation.

- :mod:`lxpt.wire` -- wire v1 and NOTICE v1, structural encode and decode.
- :mod:`lxpt.channel` -- channel ids, tags, spurt keys, sealing, signatures.
- :mod:`lxpt.crypto` -- the primitives, standard library only.
- :mod:`lxpt.floor` -- the floor core: one channel's floor at one node, pure.
- :mod:`lxpt.relay` -- the relay core: subscriptions, peers, forwarding, pure.
- :mod:`lxpt.fixture_json` -- the fixture's JSON form of a message.
"""

from .wire import WireError  # noqa: F401

__version__ = "0.2.0"
WIRE_VERSION = 1
