# lxpt

**Lightweight Extensible Push-to-Talk**: a group talk-channel protocol over
[Reticulum](https://reticulum.network). It covers one talker per channel, floor
control, and a short "who is talking" notice for members on narrow carriers.

> lxpt is an independent project. It is not affiliated with or endorsed by the
> authors of Reticulum, LXMF or LXST.

## Status

Design stage. Nothing here is usable yet. The protocol is being designed in
the open, and code arrives with the first step (the wire codecs).

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

| Language | For |
|---|---|
| Kotlin | Android applications |
| C++ (header-only, no platform dependencies) | embedded nodes and relays |
| Python | reference implementation, tools and tests |

## License

Apache License 2.0. See [LICENSE](LICENSE).
