// Compiled with -fno-exceptions -fno-rtti and every warning as an error, the
// way an embedded build sees the headers. It links nothing but the headers and
// returns 0 when a FRAME seals, opens and round-trips through check().

#include "../include/lxpt/lxpt.hpp"

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
  return memcmp(plain, codec, pn) == 0 ? 0 : 6;
}
