// Compiled with -fno-exceptions -fno-rtti and every warning as an error, the
// way an embedded build sees the headers. It links nothing but the headers and
// returns 0 when a FRAME seals, opens and round-trips through check(), and a
// relay core built on static storage grants a claim and forwards its frame.

#include "../include/lxpt/lxpt.hpp"

namespace {

class Count : public lxpt::RelaySink {
 public:
  void send(char, size_t, const uint8_t*, size_t) { sends++; }
  void note(const uint8_t*, const lxpt::FloorAction&) { notes++; }
  int sends = 0, notes = 0;
};

lxpt::Relay<> g_relay;  // static storage: what a board's service does in init()

int relay_check() {
  using namespace lxpt;
  uint8_t hash[HASH_LEN] = {7};
  if (!g_relay.init(hash, RelayLimits())) return 10;
  Count out;
  uint8_t buf[MAX_MESSAGE_LEN];
  size_t n = 0;
  SubEntry e[1];
  memset(e, 0, sizeof(e));
  e[0].channel_tag[0] = 1;
  e[0].member_tag[0] = 2;
  e[0].mode = SubMode::Voice;
  Sub sub;
  sub.carrier = Carrier::Ip;
  sub.count = 1;
  sub.entries = e;
  if (encode(sub, buf, sizeof(buf), &n) != Error::Ok) return 11;
  g_relay.client(0, 1, buf, n, 0, false, out);
  Claim c;
  memset(&c, 0, sizeof(c));
  c.channel_tag[0] = 1;
  c.talker_tag[0] = 3;
  c.spurt = 1;
  c.tier = Tier::Member;
  if (encode(c, buf, sizeof(buf), &n) != Error::Ok) return 12;
  if (!g_relay.admit_claim(0, 0, buf, n, out)) return 13;
  g_relay.client(0, 0, buf, n, 0, false, out);
  g_relay.tick(10, 0, out);
  const uint8_t payload[8] = {1};
  Frame f;
  memset(&f, 0, sizeof(f));
  f.channel_tag[0] = 1;
  f.talker_tag[0] = 3;
  f.spurt = 1;
  f.payload = payload;
  f.payload_len = sizeof(payload);
  if (encode(f, buf, sizeof(buf), &n) != Error::Ok) return 14;
  const int before = out.sends;
  g_relay.client(20, 0, buf, n, 20, false, out);
  return (out.notes == 2 && out.sends == before + 1) ? 0 : 15;
}

}  // namespace

int main() {
  using namespace lxpt;
  uint8_t k_epoch[KEY_LEN] = {1};
  uint8_t hub[HASH_LEN] = {2};
  uint8_t talker[HASH_LEN] = {3};
  uint8_t nonce[NONCE_LEN] = {4};
  const uint8_t room[] = {'O', 'p', 's'};
  uint8_t cid[CHANNEL_ID_LEN];
  if (channel_id(hub, room, sizeof(room), cid) != Error::Ok) return 1;
  ChannelKeys k;
  channel_keys(k_epoch, cid, &k);
  uint8_t tag[TAG_LEN];
  member_tag(k, talker, tag);
  SpurtKeys sk;
  if (spurt_keys(k, talker, 1, nonce, &sk) != Error::Ok) return 2;
  const uint8_t codec[80] = {9};
  uint8_t frame[FRAME_MAX_LEN];
  size_t n = 0;
  if (seal_frame(sk, k.channel_tag, tag, 1, 0, codec, sizeof(codec), frame, sizeof(frame), &n) != Error::Ok) return 3;
  Type t;
  if (check(frame, n, &t) != Error::Ok || t != Type::Frame) return 4;
  Frame f;
  uint8_t plain[FRAME_MAX_PAYLOAD];
  size_t pn = 0;
  if (open_frame(sk, frame, n, &f, plain, sizeof(plain), &pn) != Error::Ok || pn != sizeof(codec)) return 5;
  if (memcmp(plain, codec, pn) != 0) return 6;
  return relay_check();
}
