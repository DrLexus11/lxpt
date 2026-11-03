// The C++ implementation against fixtures/lxpt_wire_v1.json, then a fuzz run.
//
//   test_lxpt <fixture.json> [crosscheck-out.txt] [fuzz-iterations]
//
// Every result is recorded as one "key value" line, the same lines the Python
// and Kotlin suites record; tools/crosscheck.py compares the three files.
// The fuzz run (10^5 inputs by default, fixed seed) feeds mutated fixture
// messages and random bytes to every decoder, each input in a heap block of
// exactly its length so ASan sees any read past it, and checks that the
// library never calls operator new.

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "../include/lxpt/lxpt.hpp"
#include "json.hpp"

// --- allocation counter -------------------------------------------------------------

// Not inlinable, so GCC does not pair the malloc and free across them and warn.
#if defined(__GNUC__)
#define LXPT_TEST_NOINLINE __attribute__((noinline))
#else
#define LXPT_TEST_NOINLINE
#endif
static size_t g_allocs = 0;
LXPT_TEST_NOINLINE void* operator new(size_t n) {
  g_allocs++;
  void* p = std::malloc(n ? n : 1);
  if (!p) std::abort();
  return p;
}
LXPT_TEST_NOINLINE void operator delete(void* p) noexcept { std::free(p); }
LXPT_TEST_NOINLINE void operator delete(void* p, size_t) noexcept { std::free(p); }

using namespace lxpt;
using json::Value;
typedef std::vector<uint8_t> Bytes;

static int g_failures = 0;
static int g_checks = 0;
static std::vector<std::string> g_lines;

static void check(bool ok, const std::string& what) {
  g_checks++;
  if (!ok) {
    g_failures++;
    std::fprintf(stderr, "FAIL %s\n", what.c_str());
  }
}

static void record(const std::string& key, const std::string& value) { g_lines.push_back(key + " " + value); }

static std::string hex(const uint8_t* p, size_t n) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; i++) {
    s += d[p[i] >> 4];
    s += d[p[i] & 15];
  }
  return s;
}
static std::string hex(const Bytes& b) { return hex(b.data(), b.size()); }

static Bytes unhex(const std::string& s) {
  Bytes b;
  for (size_t i = 0; i + 1 < s.size(); i += 2) b.push_back(uint8_t(std::strtoul(s.substr(i, 2).c_str(), nullptr, 16)));
  return b;
}
static Bytes B(const Value& v) { return unhex(v.s); }

static std::string err(Error e) { return error_name(e); }

// --- fixture JSON to structs --------------------------------------------------------

struct Bad {
  std::string code;
};

static void fill(const Value& v, uint8_t* out, size_t n) {
  const Bytes b = B(v);
  if (b.size() != n) throw Bad{"field"};
  std::memcpy(out, b.data(), n);
}

static uint64_t num(const Value& v, uint64_t max) {
  if (v.kind != Value::Int || v.i < 0 || uint64_t(v.i) > max) throw Bad{"field"};
  return uint64_t(v.i);
}

template <typename E>
static E named(const Value& v, const char* const* names, const uint8_t* codes, size_t n) {
  for (size_t i = 0; i < n; i++)
    if (v.s == names[i]) return E(codes[i]);
  return E(0);
}

static const char* const TIER_NAMES[] = {"commander", "deputy", "leader", "member", "observer"};
static const uint8_t TIER_CODES[] = {1, 2, 3, 4, 5};
static const char* const PROFILE_NAMES[] = {"ulbw", "vlbw", "lbw", "mq", "hq"};
static const uint8_t PROFILE_CODES[] = {0x10, 0x20, 0x30, 0x40, 0x50};
static const char* const CARRIER_NAMES[] = {"ip", "ble", "gfsk", "halow"};
static const uint8_t CARRIER_CODES[] = {1, 2, 3, 4};
static const char* const MODE_NAMES[] = {"voice", "watch"};
static const uint8_t MODE_CODES[] = {1, 2};
static const char* const BUSY_NAMES[] = {"busy", "rate_limited"};
static const uint8_t BUSY_CODES[] = {1, 2};
static const char* const YIELD_NAMES[] = {"collision", "preempted"};
static const uint8_t YIELD_CODES[] = {1, 2};
static const char* const KIND_NAMES[] = {"start", "preempt", "emergency"};
static const uint8_t KIND_CODES[] = {1, 2, 3};

static std::string name_of(uint8_t code, const char* const* names, const uint8_t* codes, size_t n) {
  for (size_t i = 0; i < n; i++)
    if (codes[i] == code) return names[i];
  return "?";
}

// Storage for one message of any type and the lists it points to.
struct Holder {
  Type type;
  Frame frame;
  Claim claim;
  Grant grant;
  Busy busy;
  Yield yld;
  Release release;
  Talking talking;
  Sub sub;
  Peer peer;
  Heard heard;
  Bytes payload, reached;
  std::vector<SubEntry> entries;
  std::vector<PeerChannel> channels;
  std::vector<Bytes> members;
  std::vector<HeardEntry> heard_entries;
};

static void ref_from(const Value& v, SpurtRef* r, bool* present) {
  std::memset(r, 0, sizeof(*r));
  *present = v.kind != Value::Null;
  if (!*present) return;
  fill(v["talker_tag"], r->talker_tag, 4);
  r->spurt = uint32_t(num(v["spurt"], 0xFFFFFFFFu));
  r->tier = named<Tier>(v["tier"], TIER_NAMES, TIER_CODES, 5);
  r->emergency = v["emergency"].b;
}

static void talker_from(const Value& v, uint8_t* ctag, uint8_t* ttag, uint32_t* spurt) {
  fill(v["channel_tag"], ctag, 4);
  fill(v["talker_tag"], ttag, 4);
  *spurt = uint32_t(num(v["spurt"], 0xFFFFFFFFu));
}

static void from_json(const Value& v, Holder& h) {
  const std::string t = v["type"].s;
  if (t == "frame") {
    h.type = Type::Frame;
    talker_from(v, h.frame.channel_tag, h.frame.talker_tag, &h.frame.spurt);
    h.frame.seq = uint16_t(num(v["seq"], 0xFFFF));
    h.payload = B(v["payload"]);
    h.frame.payload = h.payload.empty() ? nullptr : h.payload.data();
    h.frame.payload_len = h.payload.size();
    fill(v["mac"], h.frame.mac, 8);
  } else if (t == "claim") {
    h.type = Type::Claim;
    Claim& c = h.claim;
    talker_from(v, c.channel_tag, c.talker_tag, &c.spurt);
    c.epoch = uint32_t(num(v["epoch"], 0xFFFFFFFFu));
    fill(v["nonce"], c.nonce, 16);
    c.tier = named<Tier>(v["tier"], TIER_NAMES, TIER_CODES, 5);
    c.emergency = v["emergency"].b;
    c.clock_verified = v["clock_verified"].b;
    c.clock = uint32_t(num(v["clock"], 0xFFFFFFFFu));
    fill(v["public_key"], c.public_key, 64);
    if (v.has("signature")) fill(v["signature"], c.signature, 64);
    else std::memset(c.signature, 0, 64);
  } else if (t == "grant") {
    h.type = Type::Grant;
    Grant& g = h.grant;
    talker_from(v, g.channel_tag, g.talker_tag, &g.spurt);
    g.profile = named<Profile>(v["profile"], PROFILE_NAMES, PROFILE_CODES, 5);
    g.talk_limit_s = uint8_t(num(v["talk_limit_s"], 255));
    for (size_t i = 0; i < v["reached"].size(); i++) {
      const Bytes b = B(v["reached"][i]);
      if (b.size() != 4) throw Bad{"field"};
      h.reached.insert(h.reached.end(), b.begin(), b.end());
    }
    g.reached_count = v["reached"].size();
    g.reached = h.reached.empty() ? nullptr : h.reached.data();
  } else if (t == "busy") {
    h.type = Type::Busy;
    talker_from(v, h.busy.channel_tag, h.busy.talker_tag, &h.busy.spurt);
    h.busy.reason = named<BusyReason>(v["reason"], BUSY_NAMES, BUSY_CODES, 2);
    ref_from(v["holder"], &h.busy.holder, &h.busy.has_holder);
  } else if (t == "yield") {
    h.type = Type::Yield;
    talker_from(v, h.yld.channel_tag, h.yld.talker_tag, &h.yld.spurt);
    h.yld.reason = named<YieldReason>(v["reason"], YIELD_NAMES, YIELD_CODES, 2);
    bool present;
    ref_from(v["winner"], &h.yld.winner, &present);
  } else if (t == "release") {
    h.type = Type::Release;
    Release& r = h.release;
    talker_from(v, r.channel_tag, r.talker_tag, &r.spurt);
    r.frame_count = uint16_t(num(v["frame_count"], 0xFFFF));
    fill(v["public_key"], r.public_key, 64);
    if (v.has("signature")) fill(v["signature"], r.signature, 64);
    else std::memset(r.signature, 0, 64);
  } else if (t == "talking") {
    h.type = Type::Talking;
    fill(v["channel_tag"], h.talking.channel_tag, 4);
    bool present;
    ref_from(v["holder"], &h.talking.holder, &present);
    h.talking.profile = named<Profile>(v["profile"], PROFILE_NAMES, PROFILE_CODES, 5);
    h.talking.talk_limit_s = uint8_t(num(v["talk_limit_s"], 255));
  } else if (t == "sub") {
    h.type = Type::Sub;
    h.sub.carrier = named<Carrier>(v["carrier"], CARRIER_NAMES, CARRIER_CODES, 4);
    for (size_t i = 0; i < v["entries"].size(); i++) {
      const Value& e = v["entries"][i];
      SubEntry s;
      fill(e["channel_tag"], s.channel_tag, 4);
      fill(e["member_tag"], s.member_tag, 4);
      s.mode = named<SubMode>(e["mode"], MODE_NAMES, MODE_CODES, 2);
      h.entries.push_back(s);
    }
    h.sub.count = h.entries.size();
    h.sub.entries = h.entries.empty() ? nullptr : h.entries.data();
  } else if (t == "peer") {
    h.type = Type::Peer;
    fill(v["relay_hash"], h.peer.relay_hash, 16);
    h.peer.stall_p99_ms = uint16_t(num(v["stall_p99_ms"], 0xFFFF));
    const Value& cs = v["channels"];
    h.members.resize(cs.size());
    for (size_t i = 0; i < cs.size(); i++) {
      PeerChannel c;
      fill(cs[i]["channel_tag"], c.channel_tag, 4);
      c.narrow = cs[i]["narrow"].b;
      for (size_t j = 0; j < cs[i]["members"].size(); j++) {
        const Bytes b = B(cs[i]["members"][j]);
        if (b.size() != 4) throw Bad{"field"};
        h.members[i].insert(h.members[i].end(), b.begin(), b.end());
      }
      c.member_count = cs[i]["members"].size();
      c.members = h.members[i].empty() ? nullptr : h.members[i].data();
      h.channels.push_back(c);
    }
    h.peer.count = h.channels.size();
    h.peer.channels = h.channels.empty() ? nullptr : h.channels.data();
  } else if (t == "heard") {
    h.type = Type::Heard;
    talker_from(v, h.heard.channel_tag, h.heard.talker_tag, &h.heard.spurt);
    for (size_t i = 0; i < v["heard"].size(); i++) {
      HeardEntry e;
      fill(v["heard"][i]["member_tag"], e.member_tag, 4);
      e.frames = uint16_t(num(v["heard"][i]["frames"], 0xFFFF));
      h.heard_entries.push_back(e);
    }
    h.heard.count = h.heard_entries.size();
    h.heard.entries = h.heard_entries.empty() ? nullptr : h.heard_entries.data();
  } else {
    throw Bad{"type"};
  }
}

static Error encode_holder(const Holder& h, uint8_t* out, size_t cap, size_t* n) {
  switch (h.type) {
    case Type::Frame: return encode(h.frame, out, cap, n);
    case Type::Claim: return encode(h.claim, out, cap, n);
    case Type::Grant: return encode(h.grant, out, cap, n);
    case Type::Busy: return encode(h.busy, out, cap, n);
    case Type::Yield: return encode(h.yld, out, cap, n);
    case Type::Release: return encode(h.release, out, cap, n);
    case Type::Talking: return encode(h.talking, out, cap, n);
    case Type::Sub: return encode(h.sub, out, cap, n);
    case Type::Peer: return encode(h.peer, out, cap, n);
    case Type::Heard: return encode(h.heard, out, cap, n);
  }
  return Error::Type;
}

// --- structs to canonical JSON --------------------------------------------------------

static std::string q(const std::string& s) { return "\"" + s + "\""; }

static std::string dump(const Value& v) {
  std::ostringstream o;
  switch (v.kind) {
    case Value::Null: return "null";
    case Value::Bool: return v.b ? "true" : "false";
    case Value::Int: o << v.i; return o.str();
    case Value::Str: return q(v.s);
    case Value::Arr: {
      std::string s = "[";
      for (size_t i = 0; i < v.a.size(); i++) s += (i ? "," : "") + dump(v.a[i]);
      return s + "]";
    }
    case Value::Obj: {
      std::string s = "{";
      bool first = true;
      for (auto& kv : v.o) {
        s += (first ? "" : ",") + q(kv.first) + ":" + dump(kv.second);
        first = false;
      }
      return s + "}";
    }
  }
  return "";
}

// A tiny builder: keys sorted by std::map, as dump() of the fixture's object.
struct Obj {
  std::map<std::string, std::string> f;
  Obj& set(const std::string& k, const std::string& raw) {
    f[k] = raw;
    return *this;
  }
  Obj& h(const std::string& k, const uint8_t* p, size_t n) { return set(k, q(hex(p, n))); }
  Obj& n(const std::string& k, uint64_t v) {
    std::ostringstream o;
    o << v;
    return set(k, o.str());
  }
  Obj& b(const std::string& k, bool v) { return set(k, v ? "true" : "false"); }
  Obj& s(const std::string& k, const std::string& v) { return set(k, q(v)); }
  std::string str() const {
    std::string s = "{";
    bool first = true;
    for (auto& kv : f) {
      s += (first ? "" : ",") + q(kv.first) + ":" + kv.second;
      first = false;
    }
    return s + "}";
  }
};

static std::string tags_json(const uint8_t* p, size_t count) {
  std::string s = "[";
  for (size_t i = 0; i < count; i++) s += (i ? "," : "") + q(hex(p + 4 * i, 4));
  return s + "]";
}

static std::string ref_json(const SpurtRef& r) {
  return Obj().h("talker_tag", r.talker_tag, 4).n("spurt", r.spurt).s("tier", name_of(uint8_t(r.tier), TIER_NAMES,
                                                                                       TIER_CODES, 5))
      .b("emergency", r.emergency).str();
}

// Decodes any message to canonical JSON; returns the error name on failure.
static std::string decode_json(const uint8_t* in, size_t len, bool* ok) {
  *ok = false;
  Type t;
  Error e = peek_type(in, len, &t);
  if (e != Error::Ok) return err(e);
  if (len > MAX_MESSAGE_LEN) return err(Error::Oversize);
  Obj o;
  switch (t) {
    case Type::Frame: {
      Frame m;
      if ((e = decode(in, len, &m)) != Error::Ok) return err(e);
      o.s("type", "frame").h("channel_tag", m.channel_tag, 4).h("talker_tag", m.talker_tag, 4).n("spurt", m.spurt)
          .n("seq", m.seq).h("payload", m.payload, m.payload_len).h("mac", m.mac, 8);
      break;
    }
    case Type::Claim: {
      Claim m;
      if ((e = decode(in, len, &m)) != Error::Ok) return err(e);
      o.s("type", "claim").h("channel_tag", m.channel_tag, 4).h("talker_tag", m.talker_tag, 4).n("spurt", m.spurt)
          .n("epoch", m.epoch).h("nonce", m.nonce, 16).s("tier", name_of(uint8_t(m.tier), TIER_NAMES, TIER_CODES, 5))
          .b("emergency", m.emergency).b("clock_verified", m.clock_verified).n("clock", m.clock)
          .h("public_key", m.public_key, 64).h("signature", m.signature, 64);
      break;
    }
    case Type::Grant: {
      Grant m;
      if ((e = decode(in, len, &m)) != Error::Ok) return err(e);
      o.s("type", "grant").h("channel_tag", m.channel_tag, 4).h("talker_tag", m.talker_tag, 4).n("spurt", m.spurt)
          .s("profile", name_of(uint8_t(m.profile), PROFILE_NAMES, PROFILE_CODES, 5)).n("talk_limit_s", m.talk_limit_s)
          .set("reached", tags_json(m.reached, m.reached_count));
      break;
    }
    case Type::Busy: {
      Busy m;
      if ((e = decode(in, len, &m)) != Error::Ok) return err(e);
      o.s("type", "busy").h("channel_tag", m.channel_tag, 4).h("talker_tag", m.talker_tag, 4).n("spurt", m.spurt)
          .s("reason", name_of(uint8_t(m.reason), BUSY_NAMES, BUSY_CODES, 2))
          .set("holder", m.has_holder ? ref_json(m.holder) : "null");
      break;
    }
    case Type::Yield: {
      Yield m;
      if ((e = decode(in, len, &m)) != Error::Ok) return err(e);
      o.s("type", "yield").h("channel_tag", m.channel_tag, 4).h("talker_tag", m.talker_tag, 4).n("spurt", m.spurt)
          .s("reason", name_of(uint8_t(m.reason), YIELD_NAMES, YIELD_CODES, 2)).set("winner", ref_json(m.winner));
      break;
    }
    case Type::Release: {
      Release m;
      if ((e = decode(in, len, &m)) != Error::Ok) return err(e);
      o.s("type", "release").h("channel_tag", m.channel_tag, 4).h("talker_tag", m.talker_tag, 4).n("spurt", m.spurt)
          .n("frame_count", m.frame_count).h("public_key", m.public_key, 64).h("signature", m.signature, 64);
      break;
    }
    case Type::Talking: {
      Talking m;
      if ((e = decode(in, len, &m)) != Error::Ok) return err(e);
      o.s("type", "talking").h("channel_tag", m.channel_tag, 4).set("holder", ref_json(m.holder))
          .s("profile", name_of(uint8_t(m.profile), PROFILE_NAMES, PROFILE_CODES, 5)).n("talk_limit_s", m.talk_limit_s);
      break;
    }
    case Type::Sub: {
      Sub m;
      SubEntry es[SUB_MAX_ENTRIES];
      if ((e = decode(in, len, &m, es, SUB_MAX_ENTRIES)) != Error::Ok) return err(e);
      std::string list = "[";
      for (size_t i = 0; i < m.count; i++)
        list += (i ? "," : "") + Obj().h("channel_tag", es[i].channel_tag, 4).h("member_tag", es[i].member_tag, 4)
                                     .s("mode", name_of(uint8_t(es[i].mode), MODE_NAMES, MODE_CODES, 2)).str();
      o.s("type", "sub").s("carrier", name_of(uint8_t(m.carrier), CARRIER_NAMES, CARRIER_CODES, 4))
          .set("entries", list + "]");
      break;
    }
    case Type::Peer: {
      Peer m;
      PeerChannel cs[PEER_MAX_CHANNELS];
      if ((e = decode(in, len, &m, cs, PEER_MAX_CHANNELS)) != Error::Ok) return err(e);
      std::string list = "[";
      for (size_t i = 0; i < m.count; i++)
        list += (i ? "," : "") + Obj().h("channel_tag", cs[i].channel_tag, 4).b("narrow", cs[i].narrow)
                                     .set("members", tags_json(cs[i].members, cs[i].member_count)).str();
      o.s("type", "peer").h("relay_hash", m.relay_hash, 16).n("stall_p99_ms", m.stall_p99_ms)
          .set("channels", list + "]");
      break;
    }
    case Type::Heard: {
      Heard m;
      HeardEntry hs[HEARD_MAX_ENTRIES];
      if ((e = decode(in, len, &m, hs, HEARD_MAX_ENTRIES)) != Error::Ok) return err(e);
      std::string list = "[";
      for (size_t i = 0; i < m.count; i++)
        list += (i ? "," : "") + Obj().h("member_tag", hs[i].member_tag, 4).n("frames", hs[i].frames).str();
      o.s("type", "heard").h("channel_tag", m.channel_tag, 4).h("talker_tag", m.talker_tag, 4).n("spurt", m.spurt)
          .set("heard", list + "]");
      break;
    }
  }
  *ok = true;
  return o.str();
}

static std::string notice_json(const Notice& n) {
  return Obj().s("kind", name_of(uint8_t(n.kind), KIND_NAMES, KIND_CODES, 3)).n("hop_limit", n.hop_limit)
      .h("channel_tag", n.channel_tag, 4).h("talker", n.talker, 4).n("spurt16", n.spurt16)
      .n("talk_limit_s", n.talk_limit_s).h("mac", n.mac, 8).str();
}

// --- fixture sections -----------------------------------------------------------------

static void test_crypto(const Value& c) {
  for (size_t i = 0; i < c["sha256"].size(); i++) {
    const Value& v = c["sha256"][i];
    const Bytes m = B(v["message"]);
    uint8_t d[32];
    crypto::sha256(m.data(), m.size(), d);
    check(hex(d, 32) == v["digest"].s, "sha256");
    record("crypto/sha256/" + std::to_string(i), hex(d, 32));
  }
  for (size_t i = 0; i < c["hmac_sha256"].size(); i++) {
    const Value& v = c["hmac_sha256"][i];
    const Bytes k = B(v["key"]), m = B(v["message"]);
    uint8_t d[32];
    crypto::hmac_sha256(k.data(), k.size(), m.data(), m.size(), d);
    check(hex(d, 32) == v["mac"].s, "hmac");
    record("crypto/hmac_sha256/" + std::to_string(i), hex(d, 32));
  }
  for (size_t i = 0; i < c["hkdf_sha256"].size(); i++) {
    const Value& v = c["hkdf_sha256"][i];
    const Bytes ikm = B(v["ikm"]), salt = B(v["salt"]), info = B(v["info"]);
    Bytes okm(size_t(v["length"].i));
    crypto::hkdf_sha256(ikm.data(), ikm.size(), salt.data(), salt.size(), info.data(), info.size(), okm.data(),
                        okm.size());
    check(hex(okm) == v["okm"].s, "hkdf");
    record("crypto/hkdf_sha256/" + std::to_string(i), hex(okm));
  }
  for (size_t i = 0; i < c["aes256_ctr"].size(); i++) {
    const Value& v = c["aes256_ctr"][i];
    const Bytes k = B(v["key"]), iv = B(v["iv"]), p = B(v["plaintext"]);
    Bytes out(p.size());
    crypto::aes256_ctr(k.data(), iv.data(), p.data(), p.size(), out.data());
    check(hex(out) == v["ciphertext"].s, "aes256_ctr");
    record("crypto/aes256_ctr/" + std::to_string(i), hex(out));
  }
  for (size_t i = 0; i < c["ed25519"].size(); i++) {
    const Value& v = c["ed25519"][i];
    const Bytes seed = B(v["seed"]), m = B(v["message"]);
    uint8_t pk[32], sig[64];
    crypto::ed25519_public_key(seed.data(), pk);
    crypto::ed25519_sign(sig, m.data(), m.size(), seed.data());
    check(hex(pk, 32) == v["public_key"].s, "ed25519 public key");
    check(hex(sig, 64) == v["signature"].s, "ed25519 signature");
    check(crypto::ed25519_verify(sig, m.data(), m.size(), pk), "ed25519 verify");
    record("crypto/ed25519/" + std::to_string(i), hex(pk, 32) + hex(sig, 64));
  }
  for (size_t i = 0; i < c["ed25519_verify"].size(); i++) {
    const Value& v = c["ed25519_verify"][i];
    const Bytes pk = B(v["public_key"]), m = B(v["message"]), sig = B(v["signature"]);
    const bool got = crypto::ed25519_verify(sig.data(), m.data(), m.size(), pk.data());
    check(got == v["valid"].b, "ed25519_verify " + v["name"].s);
    record("crypto/ed25519_verify/" + v["name"].s, got ? "1" : "0");
  }
}

static void test_channel(const Value& c, const Value& ids) {
  for (size_t i = 0; i < c["room_names_refused"].size(); i++) {
    const Value& v = c["room_names_refused"][i];
    const Bytes in = B(v["input"]);
    const std::string got = err(check_room_name(in.empty() ? nullptr : in.data(), in.size()));
    check(got == v["error"].s, "room refused " + v["name"].s);
    record("channel/room_names_refused/" + v["name"].s, got);
  }
  for (size_t i = 0; i < c["channel_ids"].size(); i++) {
    const Value& v = c["channel_ids"][i];
    const Bytes hub = B(v["hub_hash"]), room = B(v["room"]);
    uint8_t id[8];
    check(channel_id(hub.data(), room.data(), room.size(), id) == Error::Ok && hex(id, 8) == v["channel_id"].s,
          "channel id");
    record("channel/channel_ids/" + std::to_string(i), hex(id, 8));
  }
  for (size_t i = 0; i < c["hubless_ids"].size(); i++) {
    const Value& v = c["hubless_ids"][i];
    const Bytes cr = B(v["creator_hash"]), name = B(v["name"]);
    uint8_t id[8];
    check(hubless_channel_id(cr.data(), name.data(), name.size(), id) == Error::Ok && hex(id, 8) == v["channel_id"].s,
          "hubless id");
    record("channel/hubless_ids/" + std::to_string(i), hex(id, 8));
  }
  for (size_t i = 0; i < c["channel_keys"].size(); i++) {
    const Value& v = c["channel_keys"][i];
    ChannelKeys k;
    channel_keys(B(v["k_epoch"]).data(), B(v["channel_id"]).data(), &k);
    check(hex(k.channel_tag, 4) == v["channel_tag"].s, "channel tag");
    check(hex(k.notice_key, 32) == v["notice_key"].s, "notice key");
    record("channel/channel_keys/" + std::to_string(i), hex(k.channel_tag, 4) + hex(k.notice_key, 32));
    for (size_t j = 0; j < v["members"].size(); j++) {
      uint8_t tag[4];
      member_tag(k, B(v["members"][j]["identity_hash"]).data(), tag);
      check(hex(tag, 4) == v["members"][j]["member_tag"].s, "member tag");
      record("channel/member_tags/" + std::to_string(i) + "/" + std::to_string(j), hex(tag, 4));
    }
  }
  for (size_t i = 0; i < c["spurt_keys"].size(); i++) {
    const Value& v = c["spurt_keys"][i];
    ChannelKeys k;
    channel_keys(B(v["k_epoch"]).data(), B(v["channel_id"]).data(), &k);
    SpurtKeys sk;
    check(spurt_keys(k, B(v["talker_hash"]).data(), uint32_t(v["spurt"].i), B(v["nonce"]).data(), &sk) == Error::Ok,
          "spurt keys");
    check(hex(sk.enc_key, 32) == v["enc_key"].s && hex(sk.mac_key, 32) == v["mac_key"].s, "spurt key values");
    record("channel/spurt_keys/" + std::to_string(i), hex(sk.enc_key, 32) + hex(sk.mac_key, 32));
  }
  for (auto& kv : ids.o) {
    uint8_t id[16];
    identity_hash(B(kv.second["public_key"]).data(), id);
    check(hex(id, 16) == kv.second["hash"].s, "identity hash " + kv.first);
    record("identities/" + kv.first, hex(id, 16));
  }
}

static void test_messages(const Value& f) {
  for (size_t i = 0; i < f["messages"].size(); i++) {
    const Value& v = f["messages"][i];
    const std::string name = v["name"].s;
    Holder h;
    from_json(v["message"], h);
    uint8_t out[MAX_MESSAGE_LEN];
    size_t n = 0;
    const Error e = encode_holder(h, out, sizeof(out), &n);
    check(e == Error::Ok && hex(out, n) == v["hex"].s, "encode " + name + " " + err(e));
    record("messages/" + name, hex(out, n));
    // A buffer one byte short is refused, and nothing is claimed written.
    size_t m = 0;
    check(encode_holder(h, out, n - 1, &m) == Error::Buffer, "short buffer " + name);
    const Bytes raw = B(v["hex"]);
    bool ok;
    const std::string got = decode_json(raw.data(), raw.size(), &ok);
    check(ok && got == dump(v["message"]), "decode " + name + " " + got);
    Type t;
    check(lxpt::check(raw.data(), raw.size(), &t) == Error::Ok && t == h.type, "check " + name);
  }
  for (size_t i = 0; i < f["decode_refused"].size(); i++) {
    const Value& v = f["decode_refused"][i];
    const Bytes raw = B(v["hex"]);
    bool ok;
    const std::string got = decode_json(raw.data(), raw.size(), &ok);
    check(!ok && got == v["error"].s, "decode refused " + v["name"].s + " got " + got);
    Type t;
    check(err(lxpt::check(raw.data(), raw.size(), &t)) == v["error"].s, "check refused " + v["name"].s);
    record("decode_refused/" + v["name"].s, got);
  }
  for (size_t i = 0; i < f["encode_refused"].size(); i++) {
    const Value& v = f["encode_refused"][i];
    std::string got;
    try {
      Holder h;
      from_json(v["message"], h);
      uint8_t out[1024];
      size_t n = 0;
      got = err(encode_holder(h, out, sizeof(out), &n));
    } catch (const Bad& b) {
      got = b.code;  // a value the struct's type cannot hold
    }
    check(got == v["error"].s, "encode refused " + v["name"].s + " got " + got);
    record("encode_refused/" + v["name"].s, got);
  }
}

static void test_sealed(const Value& f) {
  for (size_t i = 0; i < f["frames"].size(); i++) {
    const Value& v = f["frames"][i];
    ChannelKeys k;
    channel_keys(B(v["k_epoch"]).data(), B(v["channel_id"]).data(), &k);
    const Bytes talker = B(v["talker_hash"]), plain = B(v["plaintext"]);
    SpurtKeys sk;
    spurt_keys(k, talker.data(), uint32_t(v["spurt"].i), B(v["nonce"]).data(), &sk);
    uint8_t ttag[4], out[FRAME_MAX_LEN];
    member_tag(k, talker.data(), ttag);
    size_t n = 0;
    const Error e = seal_frame(sk, k.channel_tag, ttag, uint32_t(v["spurt"].i), uint16_t(v["seq"].i), plain.data(),
                               plain.size(), out, sizeof(out), &n);
    check(e == Error::Ok && hex(out, n) == v["hex"].s, "seal " + v["name"].s);
    Frame fr;
    uint8_t back[FRAME_MAX_PAYLOAD];
    size_t bn = 0;
    check(open_frame(sk, out, n, &fr, back, sizeof(back), &bn) == Error::Ok && hex(back, bn) == v["plaintext"].s,
          "open " + v["name"].s);
    record("frames/" + v["name"].s, hex(out, n));
  }
  for (size_t i = 0; i < f["frames_refused"].size(); i++) {
    const Value& v = f["frames_refused"][i];
    ChannelKeys k;
    channel_keys(B(v["k_epoch"]).data(), B(v["channel_id"]).data(), &k);
    SpurtKeys sk;
    spurt_keys(k, B(v["talker_hash"]).data(), uint32_t(v["spurt"].i), B(v["nonce"]).data(), &sk);
    const Bytes raw = B(v["hex"]);
    Frame fr;
    uint8_t back[FRAME_MAX_PAYLOAD];
    size_t bn = 0;
    const std::string got = err(open_frame(sk, raw.data(), raw.size(), &fr, back, sizeof(back), &bn));
    check(got == v["error"].s, "frame refused " + v["name"].s);
    record("frames_refused/" + v["name"].s, got);
  }
  for (size_t i = 0; i < f["notices"].size(); i++) {
    const Value& v = f["notices"][i];
    ChannelKeys k;
    channel_keys(B(v["k_epoch"]).data(), B(v["channel_id"]).data(), &k);
    uint8_t out[NOTICE_LEN];
    const Error e = seal_notice(k.notice_key, named<NoticeKind>(v["kind"], KIND_NAMES, KIND_CODES, 3),
                                uint8_t(v["hop_limit"].i), k.channel_tag, B(v["talker_prefix"]).data(),
                                uint16_t(v["spurt16"].i), uint8_t(v["talk_limit_s"].i), out);
    check(e == Error::Ok && hex(out, NOTICE_LEN) == v["hex"].s, "notice " + v["name"].s);
    Notice n;
    uint8_t prefix[4];
    check(open_notice(k.notice_key, out, NOTICE_LEN, &n, prefix) == Error::Ok &&
              hex(prefix, 4) == v["talker_prefix"].s,
          "open notice " + v["name"].s);
    check(notice_json(n) == dump(v["message"]), "notice decode " + v["name"].s);
    uint8_t again[NOTICE_LEN];
    check(encode(n, again) == Error::Ok && std::memcmp(again, out, NOTICE_LEN) == 0, "notice re-encode");
    record("notices/" + v["name"].s, hex(out, NOTICE_LEN));
  }
  for (size_t i = 0; i < f["notices_hop_rewritten"].size(); i++) {
    const Value& v = f["notices_hop_rewritten"][i];
    ChannelKeys k;
    channel_keys(B(v["k_epoch"]).data(), B(v["channel_id"]).data(), &k);
    const Bytes raw = B(v["hex"]);
    Notice n;
    uint8_t prefix[4];
    check(open_notice(k.notice_key, raw.data(), raw.size(), &n, prefix) == Error::Ok &&
              hex(prefix, 4) == v["talker_prefix"].s && n.hop_limit == v["hop_limit"].i,
          "hop rewritten");
    record("notices_hop_rewritten/" + v["name"].s, hex(prefix, 4));
  }
  for (size_t i = 0; i < f["notices_refused"].size(); i++) {
    const Value& v = f["notices_refused"][i];
    ChannelKeys k;
    channel_keys(B(v["k_epoch"]).data(), B(v["channel_id"]).data(), &k);
    const Bytes raw = B(v["hex"]);
    Notice n;
    uint8_t prefix[4];
    const std::string got = err(open_notice(k.notice_key, raw.data(), raw.size(), &n, prefix));
    check(got == v["error"].s, "notice refused " + v["name"].s);
    record("notices_refused/" + v["name"].s, got);
  }
  for (size_t i = 0; i < f["notice_decode_refused"].size(); i++) {
    const Value& v = f["notice_decode_refused"][i];
    const Bytes raw = B(v["hex"]);
    Notice n;
    const std::string got = err(decode(raw.data(), raw.size(), &n));
    check(got == v["error"].s, "notice decode refused " + v["name"].s);
    record("notice_decode_refused/" + v["name"].s, got);
  }
  for (size_t i = 0; i < f["notice_encode_refused"].size(); i++) {
    const Value& v = f["notice_encode_refused"][i];
    const Value& m = v["message"];
    std::string got;
    try {
      Notice n;
      n.kind = named<NoticeKind>(m["kind"], KIND_NAMES, KIND_CODES, 3);
      n.hop_limit = uint8_t(num(m["hop_limit"], 255));
      fill(m["channel_tag"], n.channel_tag, 4);
      fill(m["talker"], n.talker, 4);
      n.spurt16 = uint16_t(num(m["spurt16"], 0xFFFF));
      n.talk_limit_s = uint8_t(num(m["talk_limit_s"], 255));
      fill(m["mac"], n.mac, 8);
      uint8_t out[NOTICE_LEN];
      got = err(encode(n, out));
    } catch (const Bad& b) {
      got = b.code;
    }
    check(got == v["error"].s, "notice encode refused " + v["name"].s);
    record("notice_encode_refused/" + v["name"].s, got);
  }
}

static void test_signed(const Value& f) {
  for (size_t i = 0; i < f["signed"].size(); i++) {
    const Value& v = f["signed"][i];
    const std::string name = v["name"].s;
    const bool claim = v["kind"].s == "claim";
    const Bytes raw = B(v["hex"]);
    if (v.has("seed")) {
      Holder h;
      from_json(v["message"], h);
      uint8_t out[CLAIM_LEN];
      const Error e = claim ? sign_claim(h.claim, B(v["seed"]).data(), out)
                            : sign_release(h.release, B(v["seed"]).data(), out);
      const size_t n = claim ? CLAIM_LEN : RELEASE_LEN;
      check(e == Error::Ok && hex(out, n) == v["hex"].s, "sign " + name);
      record("signed/" + name, hex(out, n));
    }
    const uint8_t* part = nullptr;
    size_t part_len = 0;
    const Error pe = claim ? claim_signed_part(raw.data(), raw.size(), &part, &part_len)
                           : release_signed_part(raw.data(), raw.size(), &part, &part_len);
    const std::string span = (claim ? hex(reinterpret_cast<const uint8_t*>(CLAIM_DOMAIN), CLAIM_DOMAIN_LEN)
                                    : hex(reinterpret_cast<const uint8_t*>(RELEASE_DOMAIN), RELEASE_DOMAIN_LEN)) +
                             hex(part, part_len);
    check(pe == Error::Ok && span == v["signed_hex"].s, "signed span " + name);
    record("signed_bytes/" + name, span);
    ChannelKeys k;
    channel_keys(B(v["k_epoch"]).data(), B(v["channel_id"]).data(), &k);
    std::string got;
    bool mok;
    if (claim) {
      Claim m;
      got = err(verify_claim(raw.data(), raw.size(), &m));
      mok = member_ok(k, m.public_key, m.talker_tag);
    } else {
      Release m;
      got = err(verify_release(raw.data(), raw.size(), &m));
      mok = member_ok(k, m.public_key, m.talker_tag);
    }
    check(got == v["verify"].s, "verify " + name + " got " + got);
    check(mok == v["member_ok"].b, "member_ok " + name);
    record("signed_verify/" + name, got + (mok ? " 1" : " 0"));
  }
}

static void test_relay(const Value& f) {
  for (size_t i = 0; i < f["relay_keys"].size(); i++) {
    const Value& v = f["relay_keys"][i];
    const Bytes raw = B(v["hex"]);
    uint8_t key[RELAY_KEY_LEN];
    const Error e = relay_key(raw.data(), raw.size(), key);
    check(e == Error::Ok && hex(key, RELAY_KEY_LEN) == v["relay_key"].s, "relay key " + v["name"].s);
    record("relay_keys/" + v["name"].s, hex(key, RELAY_KEY_LEN));
  }
  for (size_t i = 0; i < f["relay_binding"].size(); i++) {
    const Value& v = f["relay_binding"][i];
    const Bytes c = B(v["claim"]), r = B(v["release"]);
    const std::string got = err(release_matches_claim(c.data(), c.size(), r.data(), r.size()));
    check(got == v["error"].s, "relay binding " + v["name"].s + " got " + got);
    record("relay_binding/" + v["name"].s, got);
  }
}

// --- fuzz -------------------------------------------------------------------------------

static uint64_t g_rng = 0x1a9e5eedull;
static uint32_t rnd() {
  g_rng ^= g_rng << 13;
  g_rng ^= g_rng >> 7;
  g_rng ^= g_rng << 17;
  return uint32_t(g_rng >> 16);
}

// Every decoder over one input; what decodes must re-encode to the same bytes.
static bool fuzz_one(const uint8_t* in, size_t len, const SpurtKeys& sk, const uint8_t notice_key[32],
                     size_t* verifies) {
  uint8_t out[512];
  size_t n = 0;
  Type t;
  const Error ce = check(in, len, &t);
  bool same = true;
  if (ce == Error::Ok) {
    Error e = Error::Type;
    switch (t) {
      case Type::Frame: { Frame m; if (decode(in, len, &m) == Error::Ok) e = encode(m, out, sizeof(out), &n); break; }
      case Type::Claim: {
        Claim m;
        if (decode(in, len, &m) == Error::Ok) e = encode(m, out, sizeof(out), &n);
        if (*verifies < 300) {
          ++*verifies;
          verify_claim(in, len, &m);
        }
        break;
      }
      case Type::Grant: { Grant m; if (decode(in, len, &m) == Error::Ok) e = encode(m, out, sizeof(out), &n); break; }
      case Type::Busy: { Busy m; if (decode(in, len, &m) == Error::Ok) e = encode(m, out, sizeof(out), &n); break; }
      case Type::Yield: { Yield m; if (decode(in, len, &m) == Error::Ok) e = encode(m, out, sizeof(out), &n); break; }
      case Type::Release: {
        Release m;
        if (decode(in, len, &m) == Error::Ok) e = encode(m, out, sizeof(out), &n);
        if (*verifies < 300) {
          ++*verifies;
          verify_release(in, len, &m);
        }
        break;
      }
      case Type::Talking: { Talking m; if (decode(in, len, &m) == Error::Ok) e = encode(m, out, sizeof(out), &n); break; }
      case Type::Sub: {
        Sub m;
        SubEntry es[SUB_MAX_ENTRIES];
        if (decode(in, len, &m, es, SUB_MAX_ENTRIES) == Error::Ok) e = encode(m, out, sizeof(out), &n);
        break;
      }
      case Type::Peer: {
        Peer m;
        PeerChannel cs[PEER_MAX_CHANNELS];
        if (decode(in, len, &m, cs, PEER_MAX_CHANNELS) == Error::Ok) e = encode(m, out, sizeof(out), &n);
        break;
      }
      case Type::Heard: {
        Heard m;
        HeardEntry hs[HEARD_MAX_ENTRIES];
        if (decode(in, len, &m, hs, HEARD_MAX_ENTRIES) == Error::Ok) e = encode(m, out, sizeof(out), &n);
        break;
      }
    }
    same = e == Error::Ok && n == len && std::memcmp(out, in, len) == 0;
  }
  Frame fr;
  uint8_t plain[FRAME_MAX_PAYLOAD];
  size_t pn = 0;
  open_frame(sk, in, len, &fr, plain, sizeof(plain), &pn);
  Notice nt;
  if (decode(in, len, &nt) == Error::Ok) {
    uint8_t again[NOTICE_LEN];
    same = same && encode(nt, again) == Error::Ok && std::memcmp(again, in, NOTICE_LEN) == 0;
  }
  uint8_t prefix[4];
  open_notice(notice_key, in, len, &nt, prefix);
  check_room_name(in, len);
  return same;
}

static void fuzz(const Value& f, long iterations) {
  std::vector<Bytes> seeds;
  for (size_t i = 0; i < f["messages"].size(); i++) seeds.push_back(B(f["messages"][i]["hex"]));
  for (size_t i = 0; i < f["frames"].size(); i++) seeds.push_back(B(f["frames"][i]["hex"]));
  for (size_t i = 0; i < f["notices"].size(); i++) seeds.push_back(B(f["notices"][i]["hex"]));
  for (size_t i = 0; i < f["signed"].size(); i++) seeds.push_back(B(f["signed"][i]["hex"]));
  const Value& fv = f["frames"][1];
  ChannelKeys k;
  channel_keys(B(fv["k_epoch"]).data(), B(fv["channel_id"]).data(), &k);
  SpurtKeys sk;
  spurt_keys(k, B(fv["talker_hash"]).data(), uint32_t(fv["spurt"].i), B(fv["nonce"]).data(), &sk);
  uint8_t work[600];
  long bad = 0, decoded = 0;
  size_t verifies = 0;
  const size_t allocs_before = g_allocs;
  for (long it = 0; it < iterations; it++) {
    size_t len;
    if (it % 10 == 9) {
      len = rnd() % 48;
      for (size_t i = 0; i < len; i++) work[i] = uint8_t(rnd());
      if (len > 1 && rnd() % 2) work[0] = 0x01;
    } else {
      const Bytes& s = seeds[rnd() % seeds.size()];
      len = s.size();
      std::memcpy(work, s.data(), len);
      const int edits = 1 + int(rnd() % 4);
      for (int e = 0; e < edits; e++) {
        const uint32_t op = rnd() % 4;
        if (op == 0 && len) work[rnd() % len] = uint8_t(rnd());
        else if (op == 1 && len) len = rnd() % len;
        else if (op == 2 && len + 8 < sizeof(work)) {
          const size_t extra = 1 + rnd() % 8;
          for (size_t i = 0; i < extra; i++) work[len + i] = uint8_t(rnd());
          len += extra;
        } else if (len) work[rnd() % len] ^= uint8_t(1u << (rnd() % 8));
      }
    }
    // An exact-size block, so a read past the end is a heap overflow ASan sees.
    uint8_t* exact = static_cast<uint8_t*>(std::malloc(len ? len : 1));
    std::memcpy(exact, work, len);
    Type t;
    if (check(exact, len, &t) == Error::Ok) decoded++;
    if (!fuzz_one(exact, len, sk, k.notice_key, &verifies)) bad++;
    std::free(exact);
  }
  const size_t allocs = g_allocs - allocs_before;
  check(bad == 0, "fuzz: decoded inputs re-encode to the same bytes");
  check(allocs == 0, "fuzz: the library never called operator new");
  std::printf("# fuzz: %ld inputs, %ld decoded as messages, %zu signatures checked, %ld round-trip failures, "
              "%zu allocations\n",
              iterations, decoded, verifies, bad, allocs);
}

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: %s fixture.json [crosscheck-out] [fuzz-iterations]\n", argv[0]);
    return 2;
  }
  std::ifstream in(argv[1]);
  std::stringstream ss;
  ss << in.rdbuf();
  const std::string text = ss.str();
  const Value f = json::Parser(text).parse();
  check(f["wire_version"].i == VERSION && f["notice_version"].i == NOTICE_VERSION, "versions");
  check(f["limits"]["max_message_len"].i == long(MAX_MESSAGE_LEN), "max message");
  check(f["limits"]["frame_max_payload"].i == long(FRAME_MAX_PAYLOAD), "frame payload");
  check(f["limits"]["claim_len"].i == long(CLAIM_LEN) && f["limits"]["release_len"].i == long(RELEASE_LEN), "lens");
  test_crypto(f["crypto"]);
  test_channel(f["channel"], f["identities"]);
  test_messages(f);
  test_sealed(f);
  test_signed(f);
  test_relay(f);
  if (argc > 2 && std::string(argv[2]) != "-") {
    std::sort(g_lines.begin(), g_lines.end());
    std::ofstream out(argv[2]);
    for (size_t i = 0; i < g_lines.size(); i++) out << g_lines[i] << "\n";
  }
  fuzz(f, argc > 3 ? std::atol(argv[3]) : 100000);
  std::printf("# %d checks, %d failures, %zu cross-check lines\n", g_checks, g_failures, g_lines.size());
  return g_failures ? 1 : 0;
}
