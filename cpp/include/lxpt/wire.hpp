// lxpt wire v1 and NOTICE v1 -- structural encode and decode. Header-only,
// C++11, no heap, no exceptions, no platform headers, and no crypto: what
// needs a key or an identity is in channel.hpp.
//
// The layouts, limits and the order of errors are spec/wire-v1.md's; the
// Python reference (python/lxpt/wire.py) and the Kotlin implementation give
// the same bytes and the same errors, held by fixtures/lxpt_wire_v1.json.
//
// Encoders write into a caller's buffer and return the length through
// `written`. Decoders read in place: the byte-list fields of a decoded message
// (a FRAME's payload, GRANT's and PEER's member tags) point into the input, so
// they are valid while the input is. Lists of entries (SUB, PEER, HEARD) are
// decoded into a caller's array; passing a null array with capacity 0
// validates without storing them.
//
// SPDX-License-Identifier: Apache-2.0

#ifndef LXPT_WIRE_HPP
#define LXPT_WIRE_HPP

#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace lxpt {

enum class Error : uint8_t { Ok = 0, Truncated, Oversize, Version, Type, Field, Mac, Signature, Identity, Buffer };

inline const char* error_name(Error e) {
  switch (e) {
    case Error::Ok: return "ok";
    case Error::Truncated: return "truncated";
    case Error::Oversize: return "oversize";
    case Error::Version: return "version";
    case Error::Type: return "type";
    case Error::Field: return "field";
    case Error::Mac: return "mac";
    case Error::Signature: return "signature";
    case Error::Identity: return "identity";
    case Error::Buffer: return "buffer";
  }
  return "?";
}

static const uint8_t VERSION = 0x01;
static const uint8_t NOTICE_VERSION = 0x01;
static const size_t MAX_MESSAGE_LEN = 431;  // a Reticulum link's MDU

static const size_t TAG_LEN = 4;
static const size_t HASH_LEN = 16;
static const size_t NONCE_LEN = 16;
static const size_t PUBLIC_KEY_LEN = 64;
static const size_t SIGNATURE_LEN = 64;
static const size_t MAC_LEN = 8;

static const size_t FRAME_HEADER_LEN = 16;
static const size_t FRAME_MAX_PAYLOAD = 197;  // 19 + 221 + IFAC 16 = a 256-byte relay slot
static const size_t FRAME_MIN_LEN = FRAME_HEADER_LEN + 1 + MAC_LEN;
static const size_t FRAME_MAX_LEN = FRAME_HEADER_LEN + FRAME_MAX_PAYLOAD + MAC_LEN;
static const size_t CLAIM_LEN = 168;
static const size_t CLAIM_SIGNED_LEN = CLAIM_LEN - SIGNATURE_LEN;
static const size_t GRANT_MIN_LEN = 17;
static const size_t GRANT_MAX_REACHED = 64;
static const size_t BUSY_LEN = 25;
static const size_t YIELD_LEN = 25;
static const size_t RELEASE_LEN = 144;
static const size_t RELEASE_SIGNED_LEN = RELEASE_LEN - SIGNATURE_LEN;
static const size_t TALKING_LEN = 18;
static const size_t SUB_MIN_LEN = 4;
static const size_t SUB_ENTRY_LEN = 9;
static const size_t SUB_MAX_ENTRIES = 32;
static const size_t PEER_MIN_LEN = 21;
static const size_t PEER_CHANNEL_MIN_LEN = 6;
static const size_t PEER_MAX_CHANNELS = 32;
static const size_t PEER_MAX_MEMBERS = 64;
static const size_t HEARD_MIN_LEN = 15;
static const size_t HEARD_ENTRY_LEN = 6;
static const size_t HEARD_MAX_ENTRIES = 64;
static const size_t SPURT_REF_LEN = 10;
static const size_t NOTICE_LEN = 21;
static const uint8_t NOTICE_MAX_HOP_LIMIT = 15;

static const char CLAIM_DOMAIN[] = "lxpt/v1/claim";      // 13 bytes, no terminator signed
static const char RELEASE_DOMAIN[] = "lxpt/v1/release";  // 15 bytes
static const size_t CLAIM_DOMAIN_LEN = sizeof(CLAIM_DOMAIN) - 1;
static const size_t RELEASE_DOMAIN_LEN = sizeof(RELEASE_DOMAIN) - 1;

enum class Type : uint8_t {
  Frame = 1, Claim = 2, Grant = 3, Busy = 4, Yield = 5, Release = 6, Talking = 7, Sub = 8, Peer = 9, Heard = 10
};
enum class Tier : uint8_t { Commander = 1, Deputy = 2, Leader = 3, Member = 4, Observer = 5 };
// LXST's profile ids; v1 carries the five that talk uses.
enum class Profile : uint8_t { Ulbw = 0x10, Vlbw = 0x20, Lbw = 0x30, Mq = 0x40, Hq = 0x50 };
enum class Carrier : uint8_t { Ip = 1, Ble = 2, Gfsk = 3, Halow = 4 };
enum class SubMode : uint8_t { Voice = 1, Watch = 2 };
enum class BusyReason : uint8_t { Busy = 1, RateLimited = 2 };
enum class YieldReason : uint8_t { Collision = 1, Preempted = 2 };
enum class NoticeKind : uint8_t { Start = 1, Preempt = 2, Emergency = 3 };

inline bool valid(Tier t) { return uint8_t(t) >= 1 && uint8_t(t) <= 5; }
inline bool valid(Profile p) {
  const uint8_t v = uint8_t(p);
  return v == 0x10 || v == 0x20 || v == 0x30 || v == 0x40 || v == 0x50;
}
inline bool valid(Carrier c) { return uint8_t(c) >= 1 && uint8_t(c) <= 4; }
inline bool valid(SubMode m) { return uint8_t(m) == 1 || uint8_t(m) == 2; }
inline bool valid(BusyReason r) { return uint8_t(r) == 1 || uint8_t(r) == 2; }
inline bool valid(YieldReason r) { return uint8_t(r) == 1 || uint8_t(r) == 2; }
inline bool valid(NoticeKind k) { return uint8_t(k) >= 1 && uint8_t(k) <= 3; }

// A holder or a winner: who holds which spurt, at which tier.
struct SpurtRef {
  uint8_t talker_tag[4];
  uint32_t spurt;  // never 0
  Tier tier;
  bool emergency;
};

struct Frame {
  uint8_t channel_tag[4];
  uint8_t talker_tag[4];
  uint32_t spurt;
  uint16_t seq;
  const uint8_t* payload;  // ciphertext, 1..197 bytes
  size_t payload_len;
  uint8_t mac[8];
};

struct Claim {
  uint8_t channel_tag[4];
  uint8_t talker_tag[4];
  uint32_t spurt;
  uint32_t epoch;
  uint8_t nonce[16];
  Tier tier;
  bool emergency;
  bool clock_verified;
  uint32_t clock;
  uint8_t public_key[64];  // Reticulum layout: X25519 then Ed25519
  uint8_t signature[64];
};

struct Grant {
  uint8_t channel_tag[4];
  uint8_t talker_tag[4];
  uint32_t spurt;
  Profile profile;
  uint8_t talk_limit_s;
  size_t reached_count;   // 0..64
  const uint8_t* reached;  // reached_count * 4 bytes of member tags
};

struct Busy {
  uint8_t channel_tag[4];
  uint8_t talker_tag[4];  // the refused claimer
  uint32_t spurt;
  BusyReason reason;
  bool has_holder;  // required for Busy, optional for RateLimited
  SpurtRef holder;
};

struct Yield {
  uint8_t channel_tag[4];
  uint8_t talker_tag[4];  // the talker who must stop
  uint32_t spurt;
  YieldReason reason;
  SpurtRef winner;
};

struct Release {
  uint8_t channel_tag[4];
  uint8_t talker_tag[4];
  uint32_t spurt;
  uint16_t frame_count;
  uint8_t public_key[64];
  uint8_t signature[64];
};

struct Talking {
  uint8_t channel_tag[4];
  SpurtRef holder;
  Profile profile;
  uint8_t talk_limit_s;
};

struct SubEntry {
  uint8_t channel_tag[4];
  uint8_t member_tag[4];
  SubMode mode;
};

struct Sub {
  Carrier carrier;
  size_t count;  // 0..32
  const SubEntry* entries;
};

struct PeerChannel {
  uint8_t channel_tag[4];
  bool narrow;
  size_t member_count;     // 0..64
  const uint8_t* members;  // member_count * 4 bytes
};

struct Peer {
  uint8_t relay_hash[16];
  uint16_t stall_p99_ms;
  size_t count;  // 0..32
  const PeerChannel* channels;
};

struct HeardEntry {
  uint8_t member_tag[4];
  uint16_t frames;
};

struct Heard {
  uint8_t channel_tag[4];
  uint8_t talker_tag[4];
  uint32_t spurt;
  size_t count;  // 0..64
  const HeardEntry* entries;
};

struct Notice {
  NoticeKind kind;
  uint8_t hop_limit;  // 0..15
  uint8_t channel_tag[4];
  uint8_t talker[4];  // as it travels: encrypted (channel.hpp)
  uint16_t spurt16;
  uint8_t talk_limit_s;
  uint8_t mac[8];
};

namespace wire_detail {

inline void put16(uint8_t* p, uint16_t v) {
  p[0] = uint8_t(v >> 8);
  p[1] = uint8_t(v);
}
inline void put32(uint8_t* p, uint32_t v) {
  p[0] = uint8_t(v >> 24);
  p[1] = uint8_t(v >> 16);
  p[2] = uint8_t(v >> 8);
  p[3] = uint8_t(v);
}
inline uint16_t get16(const uint8_t* p) { return uint16_t((uint16_t(p[0]) << 8) | p[1]); }
inline uint32_t get32(const uint8_t* p) {
  return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

inline bool ref_valid(const SpurtRef& r) { return r.spurt != 0 && valid(r.tier); }

inline void put_ref(uint8_t* p, const SpurtRef* r) {
  if (!r) {
    memset(p, 0, SPURT_REF_LEN);
    return;
  }
  memcpy(p, r->talker_tag, 4);
  put32(p + 4, r->spurt);
  p[8] = uint8_t(r->tier);
  p[9] = r->emergency ? 0x01 : 0x00;
}

// Ok and *present = false for ten zero bytes; Field for anything else invalid.
inline Error get_ref(const uint8_t* p, SpurtRef* r, bool* present) {
  bool zero = true;
  for (size_t i = 0; i < SPURT_REF_LEN; i++)
    if (p[i]) zero = false;
  if (zero) {
    *present = false;
    memset(r, 0, sizeof(*r));
    return Error::Ok;
  }
  *present = true;
  memcpy(r->talker_tag, p, 4);
  r->spurt = get32(p + 4);
  r->tier = Tier(p[8]);
  if (r->spurt == 0 || !valid(r->tier) || (p[9] & ~0x01)) return Error::Field;
  r->emergency = (p[9] & 0x01) != 0;
  return Error::Ok;
}

inline void head(uint8_t* out, Type t, const uint8_t channel_tag[4]) {
  out[0] = VERSION;
  out[1] = uint8_t(t);
  memcpy(out + 2, channel_tag, 4);
}

inline void talker(uint8_t* out, const uint8_t tag[4], uint32_t spurt) {
  memcpy(out + 6, tag, 4);
  put32(out + 10, spurt);
}

inline Error room(size_t need, size_t cap, size_t* written) {
  if (need > MAX_MESSAGE_LEN) return Error::Oversize;
  if (need > cap) return Error::Buffer;
  *written = need;
  return Error::Ok;
}

inline Error exact(size_t len, size_t want) {
  if (len < want) return Error::Truncated;
  if (len > want) return Error::Oversize;
  return Error::Ok;
}

inline Error read_talker(const uint8_t* in, uint8_t tag[4], uint32_t* spurt) {
  memcpy(tag, in + 6, 4);
  *spurt = get32(in + 10);
  return *spurt == 0 ? Error::Field : Error::Ok;
}

}  // namespace wire_detail

// --- encode ---------------------------------------------------------------------------

inline Error encode(const Frame& m, uint8_t* out, size_t cap, size_t* written) {
  using namespace wire_detail;
  if (m.payload_len == 0 || !m.payload) return Error::Field;
  if (m.payload_len > FRAME_MAX_PAYLOAD) return Error::Oversize;
  if (m.spurt == 0) return Error::Field;
  const size_t n = FRAME_HEADER_LEN + m.payload_len + MAC_LEN;
  const Error e = room(n, cap, written);
  if (e != Error::Ok) return e;
  head(out, Type::Frame, m.channel_tag);
  talker(out, m.talker_tag, m.spurt);
  put16(out + 14, m.seq);
  memmove(out + FRAME_HEADER_LEN, m.payload, m.payload_len);
  memcpy(out + FRAME_HEADER_LEN + m.payload_len, m.mac, MAC_LEN);
  return Error::Ok;
}

inline Error encode(const Claim& m, uint8_t* out, size_t cap, size_t* written) {
  using namespace wire_detail;
  if (m.spurt == 0 || !valid(m.tier)) return Error::Field;
  const Error e = room(CLAIM_LEN, cap, written);
  if (e != Error::Ok) return e;
  head(out, Type::Claim, m.channel_tag);
  talker(out, m.talker_tag, m.spurt);
  put32(out + 14, m.epoch);
  memcpy(out + 18, m.nonce, 16);
  out[34] = uint8_t(m.tier);
  out[35] = uint8_t((m.emergency ? 0x01 : 0) | (m.clock_verified ? 0x02 : 0));
  put32(out + 36, m.clock);
  memcpy(out + 40, m.public_key, 64);
  memcpy(out + 104, m.signature, 64);
  return Error::Ok;
}

inline Error encode(const Grant& m, uint8_t* out, size_t cap, size_t* written) {
  using namespace wire_detail;
  if (m.spurt == 0 || !valid(m.profile) || m.talk_limit_s == 0 || m.reached_count > GRANT_MAX_REACHED ||
      (m.reached_count && !m.reached))
    return Error::Field;
  const Error e = room(GRANT_MIN_LEN + TAG_LEN * m.reached_count, cap, written);
  if (e != Error::Ok) return e;
  head(out, Type::Grant, m.channel_tag);
  talker(out, m.talker_tag, m.spurt);
  out[14] = uint8_t(m.profile);
  out[15] = m.talk_limit_s;
  out[16] = uint8_t(m.reached_count);
  if (m.reached_count) memcpy(out + 17, m.reached, TAG_LEN * m.reached_count);
  return Error::Ok;
}

inline Error encode(const Busy& m, uint8_t* out, size_t cap, size_t* written) {
  using namespace wire_detail;
  if (m.spurt == 0 || !valid(m.reason)) return Error::Field;
  if (m.has_holder ? !ref_valid(m.holder) : m.reason == BusyReason::Busy) return Error::Field;
  const Error e = room(BUSY_LEN, cap, written);
  if (e != Error::Ok) return e;
  head(out, Type::Busy, m.channel_tag);
  talker(out, m.talker_tag, m.spurt);
  out[14] = uint8_t(m.reason);
  put_ref(out + 15, m.has_holder ? &m.holder : nullptr);
  return Error::Ok;
}

inline Error encode(const Yield& m, uint8_t* out, size_t cap, size_t* written) {
  using namespace wire_detail;
  if (m.spurt == 0 || !valid(m.reason) || !ref_valid(m.winner)) return Error::Field;
  const Error e = room(YIELD_LEN, cap, written);
  if (e != Error::Ok) return e;
  head(out, Type::Yield, m.channel_tag);
  talker(out, m.talker_tag, m.spurt);
  out[14] = uint8_t(m.reason);
  put_ref(out + 15, &m.winner);
  return Error::Ok;
}

inline Error encode(const Release& m, uint8_t* out, size_t cap, size_t* written) {
  using namespace wire_detail;
  if (m.spurt == 0) return Error::Field;
  const Error e = room(RELEASE_LEN, cap, written);
  if (e != Error::Ok) return e;
  head(out, Type::Release, m.channel_tag);
  talker(out, m.talker_tag, m.spurt);
  put16(out + 14, m.frame_count);
  memcpy(out + 16, m.public_key, 64);
  memcpy(out + 80, m.signature, 64);
  return Error::Ok;
}

inline Error encode(const Talking& m, uint8_t* out, size_t cap, size_t* written) {
  using namespace wire_detail;
  if (!ref_valid(m.holder) || !valid(m.profile) || m.talk_limit_s == 0) return Error::Field;
  const Error e = room(TALKING_LEN, cap, written);
  if (e != Error::Ok) return e;
  head(out, Type::Talking, m.channel_tag);
  put_ref(out + 6, &m.holder);
  out[16] = uint8_t(m.profile);
  out[17] = m.talk_limit_s;
  return Error::Ok;
}

inline Error encode(const Sub& m, uint8_t* out, size_t cap, size_t* written) {
  using namespace wire_detail;
  if (!valid(m.carrier) || m.count > SUB_MAX_ENTRIES || (m.count && !m.entries)) return Error::Field;
  for (size_t i = 0; i < m.count; i++)
    if (!valid(m.entries[i].mode)) return Error::Field;
  const Error e = room(SUB_MIN_LEN + SUB_ENTRY_LEN * m.count, cap, written);
  if (e != Error::Ok) return e;
  out[0] = VERSION;
  out[1] = uint8_t(Type::Sub);
  out[2] = uint8_t(m.carrier);
  out[3] = uint8_t(m.count);
  for (size_t i = 0; i < m.count; i++) {
    uint8_t* p = out + SUB_MIN_LEN + SUB_ENTRY_LEN * i;
    memcpy(p, m.entries[i].channel_tag, 4);
    memcpy(p + 4, m.entries[i].member_tag, 4);
    p[8] = uint8_t(m.entries[i].mode);
  }
  return Error::Ok;
}

inline Error encode(const Peer& m, uint8_t* out, size_t cap, size_t* written) {
  using namespace wire_detail;
  if (m.count > PEER_MAX_CHANNELS || (m.count && !m.channels)) return Error::Field;
  size_t n = PEER_MIN_LEN;
  for (size_t i = 0; i < m.count; i++) {
    const PeerChannel& c = m.channels[i];
    if (c.member_count > PEER_MAX_MEMBERS || (c.member_count && !c.members)) return Error::Field;
    n += PEER_CHANNEL_MIN_LEN + TAG_LEN * c.member_count;
  }
  const Error e = room(n, cap, written);
  if (e != Error::Ok) return e;
  out[0] = VERSION;
  out[1] = uint8_t(Type::Peer);
  memcpy(out + 2, m.relay_hash, 16);
  put16(out + 18, m.stall_p99_ms);
  out[20] = uint8_t(m.count);
  size_t at = PEER_MIN_LEN;
  for (size_t i = 0; i < m.count; i++) {
    const PeerChannel& c = m.channels[i];
    memcpy(out + at, c.channel_tag, 4);
    out[at + 4] = c.narrow ? 0x01 : 0x00;
    out[at + 5] = uint8_t(c.member_count);
    if (c.member_count) memcpy(out + at + 6, c.members, TAG_LEN * c.member_count);
    at += PEER_CHANNEL_MIN_LEN + TAG_LEN * c.member_count;
  }
  return Error::Ok;
}

inline Error encode(const Heard& m, uint8_t* out, size_t cap, size_t* written) {
  using namespace wire_detail;
  if (m.spurt == 0 || m.count > HEARD_MAX_ENTRIES || (m.count && !m.entries)) return Error::Field;
  const Error e = room(HEARD_MIN_LEN + HEARD_ENTRY_LEN * m.count, cap, written);
  if (e != Error::Ok) return e;
  head(out, Type::Heard, m.channel_tag);
  talker(out, m.talker_tag, m.spurt);
  out[14] = uint8_t(m.count);
  for (size_t i = 0; i < m.count; i++) {
    uint8_t* p = out + HEARD_MIN_LEN + HEARD_ENTRY_LEN * i;
    memcpy(p, m.entries[i].member_tag, 4);
    put16(p + 4, m.entries[i].frames);
  }
  return Error::Ok;
}

// --- decode ---------------------------------------------------------------------------

// The version and type checks every decoder starts with.
inline Error peek_type(const uint8_t* in, size_t len, Type* type) {
  if (len < 1) return Error::Truncated;
  if (in[0] != VERSION) return Error::Version;
  if (len < 2) return Error::Truncated;
  if (in[1] < 1 || in[1] > 10) return Error::Type;
  *type = Type(in[1]);
  return Error::Ok;
}

namespace wire_detail {
inline Error start(const uint8_t* in, size_t len, Type want) {
  Type t;
  const Error e = peek_type(in, len, &t);
  if (e != Error::Ok) return e;
  if (t != want) return Error::Type;
  if (len > MAX_MESSAGE_LEN) return Error::Oversize;
  return Error::Ok;
}
}  // namespace wire_detail

inline Error decode(const uint8_t* in, size_t len, Frame* m) {
  using namespace wire_detail;
  Error e = start(in, len, Type::Frame);
  if (e != Error::Ok) return e;
  if (len < FRAME_MIN_LEN) return Error::Truncated;
  if (len > FRAME_MAX_LEN) return Error::Oversize;
  memcpy(m->channel_tag, in + 2, 4);
  if ((e = read_talker(in, m->talker_tag, &m->spurt)) != Error::Ok) return e;
  m->seq = get16(in + 14);
  m->payload = in + FRAME_HEADER_LEN;
  m->payload_len = len - FRAME_MIN_LEN + 1;
  memcpy(m->mac, in + len - MAC_LEN, MAC_LEN);
  return Error::Ok;
}

inline Error decode(const uint8_t* in, size_t len, Claim* m) {
  using namespace wire_detail;
  Error e = start(in, len, Type::Claim);
  if (e != Error::Ok || (e = exact(len, CLAIM_LEN)) != Error::Ok) return e;
  memcpy(m->channel_tag, in + 2, 4);
  if ((e = read_talker(in, m->talker_tag, &m->spurt)) != Error::Ok) return e;
  m->epoch = get32(in + 14);
  memcpy(m->nonce, in + 18, 16);
  m->tier = Tier(in[34]);
  if (!valid(m->tier) || (in[35] & ~0x03)) return Error::Field;
  m->emergency = (in[35] & 0x01) != 0;
  m->clock_verified = (in[35] & 0x02) != 0;
  m->clock = get32(in + 36);
  memcpy(m->public_key, in + 40, 64);
  memcpy(m->signature, in + 104, 64);
  return Error::Ok;
}

inline Error decode(const uint8_t* in, size_t len, Grant* m) {
  using namespace wire_detail;
  Error e = start(in, len, Type::Grant);
  if (e != Error::Ok) return e;
  if (len < GRANT_MIN_LEN) return Error::Truncated;
  const size_t count = in[16];
  if (count > GRANT_MAX_REACHED) return Error::Field;
  if ((e = exact(len, GRANT_MIN_LEN + TAG_LEN * count)) != Error::Ok) return e;
  memcpy(m->channel_tag, in + 2, 4);
  if ((e = read_talker(in, m->talker_tag, &m->spurt)) != Error::Ok) return e;
  m->profile = Profile(in[14]);
  m->talk_limit_s = in[15];
  if (!valid(m->profile) || m->talk_limit_s == 0) return Error::Field;
  m->reached_count = count;
  m->reached = in + GRANT_MIN_LEN;
  return Error::Ok;
}

inline Error decode(const uint8_t* in, size_t len, Busy* m) {
  using namespace wire_detail;
  Error e = start(in, len, Type::Busy);
  if (e != Error::Ok || (e = exact(len, BUSY_LEN)) != Error::Ok) return e;
  memcpy(m->channel_tag, in + 2, 4);
  if ((e = read_talker(in, m->talker_tag, &m->spurt)) != Error::Ok) return e;
  m->reason = BusyReason(in[14]);
  if (!valid(m->reason)) return Error::Field;
  if ((e = get_ref(in + 15, &m->holder, &m->has_holder)) != Error::Ok) return e;
  if (!m->has_holder && m->reason == BusyReason::Busy) return Error::Field;
  return Error::Ok;
}

inline Error decode(const uint8_t* in, size_t len, Yield* m) {
  using namespace wire_detail;
  Error e = start(in, len, Type::Yield);
  if (e != Error::Ok || (e = exact(len, YIELD_LEN)) != Error::Ok) return e;
  memcpy(m->channel_tag, in + 2, 4);
  if ((e = read_talker(in, m->talker_tag, &m->spurt)) != Error::Ok) return e;
  m->reason = YieldReason(in[14]);
  if (!valid(m->reason)) return Error::Field;
  bool present = false;
  if ((e = get_ref(in + 15, &m->winner, &present)) != Error::Ok) return e;
  return present ? Error::Ok : Error::Field;
}

inline Error decode(const uint8_t* in, size_t len, Release* m) {
  using namespace wire_detail;
  Error e = start(in, len, Type::Release);
  if (e != Error::Ok || (e = exact(len, RELEASE_LEN)) != Error::Ok) return e;
  memcpy(m->channel_tag, in + 2, 4);
  if ((e = read_talker(in, m->talker_tag, &m->spurt)) != Error::Ok) return e;
  m->frame_count = get16(in + 14);
  memcpy(m->public_key, in + 16, 64);
  memcpy(m->signature, in + 80, 64);
  return Error::Ok;
}

inline Error decode(const uint8_t* in, size_t len, Talking* m) {
  using namespace wire_detail;
  Error e = start(in, len, Type::Talking);
  if (e != Error::Ok || (e = exact(len, TALKING_LEN)) != Error::Ok) return e;
  memcpy(m->channel_tag, in + 2, 4);
  bool present = false;
  if ((e = get_ref(in + 6, &m->holder, &present)) != Error::Ok) return e;
  if (!present) return Error::Field;
  m->profile = Profile(in[16]);
  m->talk_limit_s = in[17];
  if (!valid(m->profile) || m->talk_limit_s == 0) return Error::Field;
  return Error::Ok;
}

inline Error decode(const uint8_t* in, size_t len, Sub* m, SubEntry* entries, size_t cap) {
  using namespace wire_detail;
  Error e = start(in, len, Type::Sub);
  if (e != Error::Ok) return e;
  if (len < SUB_MIN_LEN) return Error::Truncated;
  const size_t count = in[3];
  if (count > SUB_MAX_ENTRIES) return Error::Field;
  if ((e = exact(len, SUB_MIN_LEN + SUB_ENTRY_LEN * count)) != Error::Ok) return e;
  m->carrier = Carrier(in[2]);
  if (!valid(m->carrier)) return Error::Field;
  for (size_t i = 0; i < count; i++)
    if (!valid(SubMode(in[SUB_MIN_LEN + SUB_ENTRY_LEN * i + 8]))) return Error::Field;
  if (entries && count > cap) return Error::Buffer;
  for (size_t i = 0; entries && i < count; i++) {
    const uint8_t* p = in + SUB_MIN_LEN + SUB_ENTRY_LEN * i;
    memcpy(entries[i].channel_tag, p, 4);
    memcpy(entries[i].member_tag, p + 4, 4);
    entries[i].mode = SubMode(p[8]);
  }
  m->count = count;
  m->entries = entries;
  return Error::Ok;
}

inline Error decode(const uint8_t* in, size_t len, Peer* m, PeerChannel* channels, size_t cap) {
  using namespace wire_detail;
  Error e = start(in, len, Type::Peer);
  if (e != Error::Ok) return e;
  if (len < PEER_MIN_LEN) return Error::Truncated;
  memcpy(m->relay_hash, in + 2, 16);
  m->stall_p99_ms = get16(in + 18);
  const size_t count = in[20];
  if (count > PEER_MAX_CHANNELS) return Error::Field;
  size_t at = PEER_MIN_LEN;
  for (size_t i = 0; i < count; i++) {
    if (len < at + PEER_CHANNEL_MIN_LEN) return Error::Truncated;
    const uint8_t flags = in[at + 4], members = in[at + 5];
    if ((flags & ~0x01) || members > PEER_MAX_MEMBERS) return Error::Field;
    const size_t end = at + PEER_CHANNEL_MIN_LEN + TAG_LEN * members;
    if (len < end) return Error::Truncated;
    if (channels && i < cap) {
      memcpy(channels[i].channel_tag, in + at, 4);
      channels[i].narrow = (flags & 0x01) != 0;
      channels[i].member_count = members;
      channels[i].members = in + at + 6;
    }
    at = end;
  }
  if (len > at) return Error::Oversize;
  if (channels && count > cap) return Error::Buffer;
  m->count = count;
  m->channels = channels;
  return Error::Ok;
}

inline Error decode(const uint8_t* in, size_t len, Heard* m, HeardEntry* entries, size_t cap) {
  using namespace wire_detail;
  Error e = start(in, len, Type::Heard);
  if (e != Error::Ok) return e;
  if (len < HEARD_MIN_LEN) return Error::Truncated;
  const size_t count = in[14];
  if (count > HEARD_MAX_ENTRIES) return Error::Field;
  if ((e = exact(len, HEARD_MIN_LEN + HEARD_ENTRY_LEN * count)) != Error::Ok) return e;
  memcpy(m->channel_tag, in + 2, 4);
  if ((e = read_talker(in, m->talker_tag, &m->spurt)) != Error::Ok) return e;
  if (entries && count > cap) return Error::Buffer;
  for (size_t i = 0; entries && i < count; i++) {
    const uint8_t* p = in + HEARD_MIN_LEN + HEARD_ENTRY_LEN * i;
    memcpy(entries[i].member_tag, p, 4);
    entries[i].frames = get16(p + 4);
  }
  m->count = count;
  m->entries = entries;
  return Error::Ok;
}

// Validates any wire v1 message without storing it: what a relay runs before
// forwarding bytes it does not otherwise need to read.
inline Error check(const uint8_t* in, size_t len, Type* type) {
  const Error e = peek_type(in, len, type);
  if (e != Error::Ok) return e;
  switch (*type) {
    case Type::Frame: { Frame m; return decode(in, len, &m); }
    case Type::Claim: { Claim m; return decode(in, len, &m); }
    case Type::Grant: { Grant m; return decode(in, len, &m); }
    case Type::Busy: { Busy m; return decode(in, len, &m); }
    case Type::Yield: { Yield m; return decode(in, len, &m); }
    case Type::Release: { Release m; return decode(in, len, &m); }
    case Type::Talking: { Talking m; return decode(in, len, &m); }
    case Type::Sub: { Sub m; return decode(in, len, &m, nullptr, 0); }
    case Type::Peer: { Peer m; return decode(in, len, &m, nullptr, 0); }
    case Type::Heard: { Heard m; return decode(in, len, &m, nullptr, 0); }
  }
  return Error::Type;
}

// --- signed spans ---------------------------------------------------------------------

// The bytes a CLAIM's signature covers are CLAIM_DOMAIN then these: every byte
// before the signature. Checked structurally first.
inline Error claim_signed_part(const uint8_t* in, size_t len, const uint8_t** part, size_t* part_len) {
  Claim m;
  const Error e = decode(in, len, &m);
  if (e != Error::Ok) return e;
  *part = in;
  *part_len = CLAIM_SIGNED_LEN;
  return Error::Ok;
}

inline Error release_signed_part(const uint8_t* in, size_t len, const uint8_t** part, size_t* part_len) {
  Release m;
  const Error e = decode(in, len, &m);
  if (e != Error::Ok) return e;
  *part = in;
  *part_len = RELEASE_SIGNED_LEN;
  return Error::Ok;
}

// --- NOTICE v1 ------------------------------------------------------------------------

inline Error encode(const Notice& n, uint8_t out[NOTICE_LEN]) {
  using namespace wire_detail;
  if (!valid(n.kind) || n.hop_limit > NOTICE_MAX_HOP_LIMIT || n.talk_limit_s == 0) return Error::Field;
  out[0] = NOTICE_VERSION;
  out[1] = uint8_t((uint8_t(n.kind) << 4) | n.hop_limit);
  memcpy(out + 2, n.channel_tag, 4);
  memcpy(out + 6, n.talker, 4);
  put16(out + 10, n.spurt16);
  out[12] = n.talk_limit_s;
  memcpy(out + 13, n.mac, 8);
  return Error::Ok;
}

inline Error decode(const uint8_t* in, size_t len, Notice* n) {
  using namespace wire_detail;
  if (len < 1) return Error::Truncated;
  if (in[0] != NOTICE_VERSION) return Error::Version;
  const Error e = exact(len, NOTICE_LEN);
  if (e != Error::Ok) return e;
  n->kind = NoticeKind(in[1] >> 4);
  if (!valid(n->kind)) return Error::Field;
  n->hop_limit = in[1] & 0x0F;
  memcpy(n->channel_tag, in + 2, 4);
  memcpy(n->talker, in + 6, 4);
  n->spurt16 = get16(in + 10);
  n->talk_limit_s = in[12];
  if (n->talk_limit_s == 0) return Error::Field;
  memcpy(n->mac, in + 13, 8);
  return Error::Ok;
}

}  // namespace lxpt

#endif  // LXPT_WIRE_HPP
