# lxpt

**Lightweight Extensible Push-to-Talk**: a group talk-channel protocol over
[Reticulum](https://reticulum.network). It covers one talker per channel, floor
control, and a short "who is talking" notice for members on narrow carriers.

> lxpt is an independent project. It is not affiliated with or endorsed by the
> authors of Reticulum, LXMF or LXST.

## Status

**Wire v1 is implemented.** Since v0.3.1 the spec fixes what a FRAME carries for each codec: one Opus packet, or the exact Codec2 frames libcodec2 writes, with no LXST header (40, 64 and 80 B for ULBW, VLBW and LBW), and `check_payload` refuses anything else. That covers every message (FRAME, CLAIM, GRANT,
BUSY, YIELD, RELEASE, TALKING, SUB, PEER and HEARD) and the LoRa NOTICE, along
with channel ids, tags, per-spurt keys, frame and notice sealing, and claim
signatures. The format is in [spec/wire-v1.md](spec/wire-v1.md), and
[fixtures/lxpt_wire_v1.json](fixtures/lxpt_wire_v1.json) pins it.

**The floor and relay cores are implemented (v0.3.0, spec v1.2).** The floor
core decides who talks on one channel: claims, the settle window, GRANT, BUSY,
YIELD, pre-emption by tier and Emergency, quiet, lost and resume (within a 2 s
window and only on frames on the talker's schedule: a backlog never takes the
floor), and tombstones. It runs on relays and on phones. The relay core adds
subscriptions, peer summaries, dedup and forwarding choices, and does not
forward a frame more than 800 ms behind its spurt's schedule. Both are pure: events in, actions
out, the clock passed in, no I/O. The C++ cores do not allocate after
`init()`. The behaviour is in [spec/floor-v1.md](spec/floor-v1.md), and
[fixtures/lxpt_floor_v1.json](fixtures/lxpt_floor_v1.json) and
[fixtures/lxpt_relay_v1.json](fixtures/lxpt_relay_v1.json) pin it, including
traces recorded at the relays of a simulated run.

CI checks that Python, Kotlin and C++ give the same bytes for every wire
vector and the same decisions for every core scenario. It also runs the
simulator gate, [python/sim.py](python/sim.py): 3 relays and 8 phones with 10%
loss, reordering, duplication, partitions and relay stalls of 2, 5 and 18 s,
checked for convergence on one talker, one spurt forwarded, no floor freed by
a short stall, no lost spurt resumed past the window or by a backlog
(including the bench's 16 s TCP backlog and a 6 s one inside the window) and
no floor held past its bound.

Nothing has run over a radio.

## Scope

lxpt is the protocol layer only. It contains:

- the wire formats, each starting with a version byte and fixed by shared test fixtures;
- the floor-control logic, pure and testable without a radio;
- the talker-notice format;
- a small transport interface, so it runs over any Reticulum carrier.

Out of scope:

- audio capture, playout and codecs, which belong to an LXST implementation;
- user interface, which belongs to the applications that use lxpt.

## Implementations

The same protocol is implemented three times, kept byte-identical by one set of
fixtures and one CI:

| Language | For | Where |
|---|---|---|
| Kotlin | Android applications | `kotlin/`, pure JVM, no Android dependency |
| C++ (header-only, no platform dependencies) | embedded nodes and relays | `cpp/include/lxpt/`, C++11, no heap, no exceptions |
| Python | reference implementation, tools and tests | `python/lxpt/`, standard library only |

## Usage

- **Kotlin**, through JitPack: add `maven("https://jitpack.io")` and
  `implementation("com.github.DrLexus11:lxpt:<tag>")`. Use `Wire.encode`,
  `Wire.decode`, `ChannelKeys` and `Channel.sealFrame` / `openFrame`. CLAIMs
  and RELEASEs are signed through a `Signer`, backed by the host's identity
  stack, so lxpt never holds the private key. A phone's floor is
  `Floor(FloorRole.PHONE, ...)`; a phone hosting a channel runs `Relay`.
- **C++**: put `cpp/include` on the include path and include `<lxpt/lxpt.hpp>`.
  Every call writes into buffers the caller provides. A relay needs only
  `wire.hpp`, plus `verify_claim` and `relay_key` from `channel.hpp`. On a
  microcontroller, signature verification is the costly step, estimated at
  0.3-0.6 s on an ESP32-S3. Rate-limit before verifying, and verify outside
  the service's `poll()`. You can pass in the board's own Ed25519 once it
  gives the fixture's verify results ([spec section 8](spec/wire-v1.md)).
  The relay core is `lxpt::Relay<>` in `relay.hpp`: give it static storage,
  call `init()`, then `admit_claim()` before verifying a CLAIM, `client()`,
  `peer()` and `tick()` once per pass; actions come through a `RelaySink`.
- **Python** 3.9+:
  `pip install "git+https://github.com/DrLexus11/lxpt@<tag>#subdirectory=python"`.
  Then use `lxpt.wire.encode` / `decode` on dicts, `lxpt.channel` for keys, and
  `lxpt.floor` / `lxpt.relay` for the cores.

To run the tests from the repository root:

```sh
python3 -m unittest discover -s python/tests -t python   # Python
make -C cpp test                                          # C++11 and C++17, ASan+UBSan, 10^5 fuzz, cores
(cd kotlin && ./gradlew test)                             # Kotlin
python3 python/sim.py                                     # the simulator gate (about 4 min; --quick for 3 seeds)
python3 python/gen_fixture.py                             # regenerate the wire fixture after a change
python3 python/gen_core_fixtures.py                       # regenerate the floor and relay fixtures
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
