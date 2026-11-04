// The C++ floor and relay cores against fixtures/lxpt_floor_v1.json and
// fixtures/lxpt_relay_v1.json.
//
//   test_cores <floor.json> <relay.json> [crosscheck-out.txt]
//
// Every step's lines must equal the fixture's. One "floor/<name> <digest>" or
// "relay/<name> <digest>" line per scenario is appended to the cross-check
// file (the SHA-256 of every line the scenario produced), the same lines the
// Python and Kotlin suites record. The cores are called with every output
// going into fixed buffers, and the test checks that no core call ever reaches
// operator new: no allocation after init().

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "../include/lxpt/floor.hpp"
#include "../include/lxpt/relay.hpp"
#include "json.hpp"

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

static int g_failures = 0;
static int g_checks = 0;
static size_t g_core_allocs = 0;
static std::vector<std::string> g_lines;

static void check(bool ok, const std::string& what) {
  g_checks++;
  if (!ok) {
    g_failures++;
    if (g_failures < 40) std::fprintf(stderr, "FAIL %s\n", what.c_str());
  }
}

static std::string hex(const uint8_t* p, size_t n) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; i++) {
    s += d[p[i] >> 4];
    s += d[p[i] & 15];
  }
  return s;
}

static std::vector<uint8_t> unhex(const std::string& s) {
  std::vector<uint8_t> b;
  for (size_t i = 0; i + 1 < s.size(); i += 2) b.push_back(uint8_t(std::strtoul(s.substr(i, 2).c_str(), nullptr, 16)));
  return b;
}

static void fill(const Value& v, uint8_t* out, size_t n) {
  const std::vector<uint8_t> b = unhex(v.s);
  if (b.size() != n) throw std::runtime_error("hex field of the wrong size");
  std::memcpy(out, b.data(), n);
}

// --- what a core call produced, captured without allocating ---------------------------

struct Captured {
  enum Kind { Note, Send } kind;
  uint8_t tag[TAG_LEN];
  Act act;
  Why why;
  uint8_t who[HASH_LEN];
  uint32_t spurt;
  bool has_other;
  uint8_t other_who[HASH_LEN];
  uint32_t other_spurt;
  char target;
  size_t index;
  size_t at, len;  // into g_arena
};

static const size_t MAX_CAPTURED = 1 << 14;
static Captured g_cap[MAX_CAPTURED];
static size_t g_ncap = 0;
static uint8_t g_arena[1 << 22];
static size_t g_arena_used = 0;
static bool g_overflow = false;

static void capture_action(const uint8_t* tag, const FloorAction& a) {
  if (g_ncap == MAX_CAPTURED) {
    g_overflow = true;
    return;
  }
  Captured& c = g_cap[g_ncap++];
  c.kind = Captured::Note;
  if (tag) std::memcpy(c.tag, tag, TAG_LEN);
  c.act = a.act;
  c.why = a.why;
  std::memcpy(c.who, a.rec->who, HASH_LEN);
  c.spurt = a.rec->spurt;
  c.has_other = a.other != nullptr;
  if (a.other) {
    std::memcpy(c.other_who, a.other->who, HASH_LEN);
    c.other_spurt = a.other->spurt;
  }
}

static std::string action_line(const Captured& c) {
  std::string s = std::string(act_name(c.act)) + " " + hex(c.who, HASH_LEN) + "/" + std::to_string(c.spurt);
  if (c.act == Act::Busy || c.act == Act::Yield)
    s += " " + (c.has_other ? hex(c.other_who, HASH_LEN) + "/" + std::to_string(c.other_spurt) : std::string("-"));
  if (c.why != Why::None) s += std::string(" ") + why_name(c.why);
  return s;
}

static std::string captured_line(const Captured& c) {
  if (c.kind == Captured::Note) return "note " + hex(c.tag, TAG_LEN) + " " + action_line(c);
  return std::string("send ") + c.target + std::to_string(c.index) + " " + hex(g_arena + c.at, c.len);
}

static std::vector<std::string> take_captured(bool notes_with_tag) {
  std::vector<std::string> out;
  for (size_t i = 0; i < g_ncap; i++)
    out.push_back(notes_with_tag || g_cap[i].kind == Captured::Send ? captured_line(g_cap[i]) : action_line(g_cap[i]));
  g_ncap = 0;
  g_arena_used = 0;
  return out;
}

class FloorCapture : public FloorSink {
 public:
  void floor_action(const FloorAction& a) { capture_action(nullptr, a); }
};

class RelayCapture : public RelaySink {
 public:
  void send(char kind, size_t index, const uint8_t* data, size_t len) {
    if (g_ncap == MAX_CAPTURED || g_arena_used + len > sizeof(g_arena)) {
      g_overflow = true;
      return;
    }
    Captured& c = g_cap[g_ncap++];
    c.kind = Captured::Send;
    c.target = kind;
    c.index = index;
    c.at = g_arena_used;
    c.len = len;
    std::memcpy(g_arena + g_arena_used, data, len);
    g_arena_used += len;
  }
  void note(const uint8_t channel_tag[TAG_LEN], const FloorAction& a) { capture_action(channel_tag, a); }
};

// Every core call goes through here, so the allocation count covers exactly them.
template <class F>
static void core(F f) {
  const size_t before = g_allocs;
  f();
  g_core_allocs += g_allocs - before;
}

static std::string digest(const std::vector<std::string>& lines) {
  crypto::Sha256 h;
  crypto::sha256_init(h);
  for (size_t i = 0; i < lines.size(); i++) {
    if (i) crypto::sha256_update(h, reinterpret_cast<const uint8_t*>("\n"), 1);
    crypto::sha256_update(h, reinterpret_cast<const uint8_t*>(lines[i].data()), lines[i].size());
  }
  uint8_t d[32];
  crypto::sha256_final(h, d);
  return hex(d, 32);
}

static void compare(const std::string& where, const std::vector<std::string>& got, const Value& want) {
  bool same = got.size() == want.size();
  for (size_t i = 0; same && i < got.size(); i++) same = got[i] == want[i].s;
  if (!same) {
    std::string msg = where + ": got " + std::to_string(got.size()) + " lines, want " + std::to_string(want.size());
    for (size_t i = 0; i < got.size() || i < want.size(); i++) {
      const std::string g = i < got.size() ? got[i] : "(none)";
      const std::string w = i < want.size() ? want[i].s : "(none)";
      if (g != w) {
        msg += "\n    first difference at line " + std::to_string(i) + "\n      got  " + g.substr(0, 160) +
               "\n      want " + w.substr(0, 160);
        break;
      }
    }
    check(false, msg);
  } else {
    check(true, where);
  }
}

// --- the floor fixture --------------------------------------------------------------------

static FloorClaim claim_of(const Value& e) {
  FloorClaim c;
  std::memset(&c, 0, sizeof(c));
  fill(e["who"], c.who, HASH_LEN);
  fill(e["tag"], c.tag, TAG_LEN);
  c.spurt = uint32_t(e["spurt"].i);
  fill(e["nonce"], c.nonce, NONCE_LEN);
  c.tier = uint8_t(e["tier"].i);
  c.emergency = e["emergency"].b;
  c.verified = e["verified"].b;
  c.local = e["local"].b;
  c.src = int32_t(e["src"].i);
  c.stall_ms = e["stall_ms"].i;
  return c;
}

static std::string ref_line(SpurtRec* r) {
  return r ? "holder " + hex(r->who, HASH_LEN) + "/" + std::to_string(r->spurt) : std::string("holder -");
}

static void run_floor(const Value& f) {
  const Value& sc = f["scenarios"];
  for (size_t s = 0; s < sc.size(); s++) {
    const Value& v = sc[s];
    const std::string name = v["name"].s;
    std::vector<CounterEntry> cstore(size_t(v["talkers"].i));
    std::vector<SpurtRec> rstore(size_t(v["capacity"].i));
    Counters counters;
    Floor floor;
    uint8_t tag[TAG_LEN];
    fill(v["channel_tag"], tag, TAG_LEN);
    counters.init(cstore.data(), cstore.size());
    check(floor.init(v["role"].s == "phone" ? Role::Phone : Role::Relay, tag, &counters, rstore.data(), rstore.size(),
                     uint8_t(v["talk_limit_s"].i)),
          name + ": init");
    FloorCapture sink;
    std::vector<std::string> all;
    const Value& steps = v["steps"];
    for (size_t k = 0; k < steps.size(); k++) {
      const Value& e = steps[k];
      const std::string d = e["do"].s;
      const int64_t at = e["at"].i;
      std::vector<std::string> extra;
      if (d == "claim" || d == "key") {
        const FloorClaim c = claim_of(e);
        if (d == "claim") core([&] { floor.claim(at, c, 0, sink); });
        else core([&] { floor.key(at, c, sink); });
      } else if (d == "talking") {
        uint8_t t[TAG_LEN];
        fill(e["tag"], t, TAG_LEN);
        const uint32_t sp = uint32_t(e["spurt"].i);
        const uint8_t pr = uint8_t(e["profile"].i), li = uint8_t(e["limit_s"].i);
        core([&] { floor.talking(at, t, sp, pr, li, sink); });
      } else if (d == "frame") {
        uint8_t t[TAG_LEN];
        fill(e["tag"], t, TAG_LEN);
        bool fwd = false;
        const int64_t rx = e.has("rx") ? e["rx"].i : at;
        const uint32_t sp = uint32_t(e["spurt"].i);
        const uint16_t seq = uint16_t(e["seq"].i);
        core([&] { floor.frame(at, rx, t, sp, seq, &fwd, sink); });
        extra.push_back(fwd ? "forward" : "drop");
      } else if (d == "release") {
        uint8_t w[HASH_LEN], t[TAG_LEN];
        fill(e["who"], w, HASH_LEN);
        fill(e["tag"], t, TAG_LEN);
        bool fresh = false;
        const uint32_t sp = uint32_t(e["spurt"].i);
        core([&] { fresh = floor.release(at, w, sp, t, sink); });
        extra.push_back(fresh ? "new" : "seen");
      } else if (d == "tick") {
        const int64_t st = e["settle_ms"].i;
        core([&] { floor.tick(at, st, sink); });
      } else if (d == "ticks") {
        const int64_t st = e["settle_ms"].i, count = e["count"].i, every = e["every"].i;
        for (int64_t n = 0; n < count; n++) core([&] { floor.tick(at + n * every, st, sink); });
      } else if (d == "granted") {
        uint8_t t[TAG_LEN];
        fill(e["tag"], t, TAG_LEN);
        const uint32_t sp = uint32_t(e["spurt"].i);
        const uint8_t pr = uint8_t(e["profile"].i), li = uint8_t(e["limit_s"].i);
        core([&] { floor.granted(at, t, sp, pr, li, sink); });
      } else if (d == "busy") {
        uint8_t t[TAG_LEN], h[TAG_LEN];
        fill(e["tag"], t, TAG_LEN);
        const bool has_holder = e["holder"].kind == Value::Arr;
        uint32_t hs = 0;
        if (has_holder) {
          fill(e["holder"][0], h, TAG_LEN);
          hs = uint32_t(e["holder"][1].i);
        }
        const uint32_t sp = uint32_t(e["spurt"].i);
        const bool rl = e["rate_limited"].b;
        core([&] { floor.busy(at, t, sp, has_holder ? h : nullptr, hs, rl, sink); });
      } else if (d == "yielded") {
        uint8_t t[TAG_LEN], w[TAG_LEN];
        fill(e["tag"], t, TAG_LEN);
        fill(e["winner"][0], w, TAG_LEN);
        const uint32_t sp = uint32_t(e["spurt"].i), ws = uint32_t(e["winner"][1].i);
        const bool pre = e["preempted"].b;
        core([&] { floor.yielded(at, t, sp, w, ws, pre, sink); });
      } else if (d == "end") {
        core([&] { floor.end(at, sink); });
      } else {
        check(false, name + ": unknown step " + d);
      }
      std::vector<std::string> got = take_captured(false);
      got.insert(got.end(), extra.begin(), extra.end());
      got.push_back(ref_line(floor.holder()));
      compare("floor/" + name + " step " + std::to_string(k) + " (" + d + " at " + std::to_string(at) + ")", got,
              e["expect"]);
      all.insert(all.end(), got.begin(), got.end());
    }
    g_lines.push_back("floor/" + name + " " + digest(all));
  }
}

// --- the relay fixture ---------------------------------------------------------------------

typedef Relay<32, 8, 4, 8, 128, 64> TestRelay;

static void run_relay(const Value& f) {
  const Value& sc = f["scenarios"];
  TestRelay* relay = new TestRelay();  // before init: the only allocation a host makes
  std::printf("# sizeof(Relay<32, 8, 4, 8, 128, 64>) = %zu bytes; sizeof(Relay<>) = %zu bytes\n", sizeof(TestRelay),
              sizeof(Relay<>));
  for (size_t s = 0; s < sc.size(); s++) {
    const Value& v = sc[s];
    const std::string name = v["name"].s;
    RelayLimits lim;
    const Value& l = v["limits"];
    lim.channels = size_t(l["channels"].i);
    lim.legs = size_t(l["legs"].i);
    lim.peers = size_t(l["peers"].i);
    lim.spurts = size_t(l["spurts"].i);
    lim.dedup = size_t(l["dedup"].i);
    lim.talkers = size_t(l["talkers"].i);
    uint8_t h[HASH_LEN];
    fill(v["relay_hash"], h, HASH_LEN);
    check(relay->init(h, lim, uint8_t(v["talk_limit_s"].i)), name + ": init");
    RelayCapture sink;
    std::vector<std::string> all;
    const Value& steps = v["steps"];
    for (size_t k = 0; k < steps.size(); k++) {
      const Value& e = steps[k];
      const std::string d = e["do"].s;
      const int64_t at = e["at"].i;
      std::vector<std::string> head;
      std::vector<uint8_t> bytes;
      if (e.has("hex")) bytes = unhex(e["hex"].s);
      const uint8_t* data = bytes.empty() ? nullptr : bytes.data();
      const int64_t rx = e.has("rx") ? e["rx"].i : at;
      const bool verified = e.has("verified") && e["verified"].b;
      const size_t leg = e.has("leg") ? size_t(e["leg"].i) : 0, index = e.has("index") ? size_t(e["index"].i) : 0;
      const size_t n = bytes.size();
      if (d == "admit") {
        bool ok = false;
        core([&] { ok = relay->admit_claim(at, leg, data, n, sink); });
        head.push_back(ok ? "admit ok" : "admit no");
      } else if (d == "client") {
        core([&] { relay->client(at, leg, data, n, rx, verified, sink); });
      } else if (d == "peer") {
        core([&] { relay->peer(at, index, data, n, rx, verified, sink); });
      } else if (d == "tick") {
        const int64_t st = e["stall_ms"].i;
        core([&] { relay->tick(at, st, sink); });
      } else if (d == "ticks") {
        const int64_t st = e["stall_ms"].i, count = e["count"].i, every = e["every"].i;
        for (int64_t c = 0; c < count; c++) core([&] { relay->tick(at + c * every, st, sink); });
      } else if (d == "leg_down") {
        core([&] { relay->leg_down(at, leg, sink); });
      } else if (d == "peer_up") {
        const int64_t rtt = e.has("rtt_ms") ? e["rtt_ms"].i : 0;
        core([&] { relay->peer_up(at, index, rtt, sink); });
      } else if (d == "peer_rtt") {
        const int64_t rtt = e["rtt_ms"].i;
        core([&] { relay->peer_rtt(at, index, rtt, sink); });
      } else if (d == "peer_down") {
        core([&] { relay->peer_down(at, index, sink); });
      } else {
        check(false, name + ": unknown step " + d);
      }
      std::vector<std::string> got = take_captured(true);
      got.insert(got.begin(), head.begin(), head.end());
      compare("relay/" + name + " step " + std::to_string(k) + " (" + d + " at " + std::to_string(at) + ")", got,
              e["expect"]);
      all.insert(all.end(), got.begin(), got.end());
    }
    g_lines.push_back("relay/" + name + " " + digest(all));
  }
  delete relay;
}

static Value load(const char* path) {
  std::ifstream in(path);
  std::stringstream ss;
  ss << in.rdbuf();
  return json::Parser(ss.str()).parse();
}

int main(int argc, char** argv) {
  if (argc < 3) {
    std::fprintf(stderr, "usage: %s floor.json relay.json [crosscheck-out]\n", argv[0]);
    return 2;
  }
  const Value floor = load(argv[1]);
  const Value relay = load(argv[2]);
  check(floor["constants"]["settle_cap_ms"].i == SETTLE_CAP_MS && floor["constants"]["quiet_ms"].i == QUIET_MS &&
            floor["constants"]["lost_min_ms"].i == LOST_MIN_MS && floor["constants"]["resume_ms"].i == RESUME_MS &&
            floor["constants"]["remote_hold_ms"].i == REMOTE_HOLD_MS &&
            floor["constants"]["sub_lease_ms"].i == SUB_LEASE_MS,
        "constants");
  run_floor(floor);
  run_relay(relay);
  check(!g_overflow, "capture buffers large enough");
  check(g_core_allocs == 0, "no core call reached operator new");
  if (argc > 3 && std::string(argv[3]) != "-") {
    std::ofstream out(argv[3], std::ios::app);
    for (size_t i = 0; i < g_lines.size(); i++) out << g_lines[i] << "\n";
  }
  std::printf("# cores: %d checks, %d failures, %zu scenarios, %zu allocations inside core calls\n", g_checks,
              g_failures, g_lines.size(), g_core_allocs);
  return g_failures ? 1 : 0;
}
