# lxpt

**Lightweight Extensible Push-to-Talk**: a group talk-channel protocol over
[Reticulum](https://reticulum.network). It covers one talker per channel, floor
control, and a short "who is talking" notice for members on narrow carriers.

> lxpt is an independent project. It is not affiliated with or endorsed by the
> authors of Reticulum, LXMF or LXST.

## Status

**Wire v1 is implemented.** That covers every message (FRAME, CLAIM, GRANT,
BUSY, YIELD, RELEASE, TALKING, SUB, PEER and HEARD) and the LoRa NOTICE, along
with channel ids, tags, per-spurt keys, frame and notice sealing, and claim
signatures. The format is in [spec/wire-v1.md](spec/wire-v1.md), and
[fixtures/lxpt_wire_v1.json](fixtures/lxpt_wire_v1.json) pins it. CI checks
that Python, Kotlin and C++ give byte-identical results for every vector.

The floor and relay cores come next and are not here yet. These decide who
talks and what is forwarded. Nothing has run over a radio.

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
  stack, so lxpt never holds the private key.
- **C++**: put `cpp/include` on the include path and include `<lxpt/lxpt.hpp>`.
  Every call writes into buffers the caller provides. A relay needs only
  `wire.hpp`, plus `verify_claim` and `relay_key` from `channel.hpp`. On a
  microcontroller, signature verification is the costly step, estimated at
  0.3-0.6 s on an ESP32-S3. Rate-limit before verifying, and verify outside
  the service's `poll()`. You can pass in the board's own Ed25519 once it
  gives the fixture's verify results ([spec section 8](spec/wire-v1.md)).
- **Python** 3.9+:
  `pip install "git+https://github.com/DrLexus11/lxpt@<tag>#subdirectory=python"`.
  Then use `lxpt.wire.encode` / `decode` on dicts and `lxpt.channel` for keys.

To run the tests from the repository root:

```sh
python3 -m unittest discover -s python/tests -t python   # Python
make -C cpp test                                          # C++11 and C++17, ASan+UBSan, 10^5 fuzz
(cd kotlin && ./gradlew test)                             # Kotlin
python3 python/gen_fixture.py                             # regenerate the fixture after a change
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
