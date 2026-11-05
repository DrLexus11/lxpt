// lxpt relay core v1 -- subscriptions, peers, dedup and forwarding choices
// around one floor per channel. Header-only, C++11, no heap, no exceptions, no
// platform headers.
//
// Pure: the host hands it wire bytes received on a client leg or from a peer
// relay and ticks it; it answers through a RelaySink with sends (bytes to one
// client leg or one peer) and notes (floor decisions), in the order
// spec/floor-v1.md section 5 gives. Every table is a member array sized by the
// template parameters; init() sets the capacities in use (at most those), and
// nothing allocates after it. The Python reference (python/lxpt/relay.py) and
// Kotlin (Relay.kt) give the same lines, held by fixtures/lxpt_relay_v1.json.
//
// The host must call admit_claim() on a CLAIM's bytes before verifying its
// signature, and pass to client()/peer() only CLAIMs and RELEASEs whose
// signature verified (wire spec section 8).
//
// SPDX-License-Identifier: Apache-2.0

#ifndef LXPT_RELAY_HPP
#define LXPT_RELAY_HPP

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto.hpp"
#include "floor.hpp"
#include "wire.hpp"

namespace lxpt {

static const int64_t SUB_LEASE_MS = 60000;
static const int64_t PEER_EVERY_MS = 5000;
static const int64_t PEER_LOST_MS = 15000;
static const int64_t TALKING_EVERY_MS = 2000;
static const int64_t YIELD_AGAIN_MS = 1000;
static const int64_t FRAME_MAX_AGE_MS = 500;
// Lateness by media time (floor-v1.md section 5): a live spurt's frame later than
// LATE_MS behind its schedule is a backlog and is never forwarded; REANCHOR_AFTER
// late frames in a row at real-time pace re-anchor the schedule.
static const int64_t LATE_MS = 800;
static const uint8_t REANCHOR_AFTER = 5;

namespace relay_detail {
inline int64_t frame_ms(uint8_t profile) {
  switch (profile) {
    case 0x10: return 400;  // ULBW
    case 0x20: return 320;  // VLBW
    case 0x30: return 200;  // LBW
    case 0x40:
    case 0x50: return 60;   // MQ, HQ
    default: return 0;
  }
}

// Whether frame seq of a live spurt, received at rx, is more than LATE_MS behind
// the spurt's schedule. Updates the spurt's schedule as a side effect.
inline bool late(SpurtRec& rec, uint16_t seq, int64_t rx) {
  const int64_t fm = frame_ms(rec.profile);
  if (fm == 0) return false;  // no profile yet: nothing to judge by
  const int64_t offset = rx - int64_t(seq) * fm;
  if (!rec.timed) {
    rec.timed = true;
    rec.best_offset = offset;
    rec.last_arrival = rx - fm;
  }
  if (offset < rec.best_offset) rec.best_offset = offset;
  bool is_late = offset - rec.best_offset > LATE_MS;
  rec.late_run = (is_late && rx - rec.last_arrival >= fm / 2) ? uint8_t(rec.late_run + 1) : uint8_t(0);
  if (rec.late_run >= REANCHOR_AFTER) {
    rec.best_offset = offset;
    rec.late_run = 0;
    is_late = false;
  }
  rec.last_arrival = rx;
  return is_late;
}
}  // namespace relay_detail
static const int64_t EMERGENCY_EVERY_MS = 10000;
static const size_t DEDUP_KEY_LEN = 18;

class RelaySink {
 public:
  // kind 'c' for a client leg, 'p' for a peer relay.
  virtual void send(char kind, size_t index, const uint8_t* data, size_t len) = 0;
  virtual void note(const uint8_t channel_tag[TAG_LEN], const FloorAction& a) = 0;

 protected:
  ~RelaySink() {}
};

struct RelayLimits {
  size_t channels, legs, peers, spurts, dedup, talkers;
  RelayLimits() : channels(32), legs(8), peers(4), spurts(4), dedup(128), talkers(64) {}
};

template <size_t MaxChannels = 32, size_t MaxLegs = 8, size_t MaxPeers = 4, size_t MaxSpurts = 4,
          size_t MaxDedup = 128, size_t MaxTalkers = 64>
class Relay {
 public:
  // False if a limit is 0 or past its template maximum.
  bool init(const uint8_t relay_hash[HASH_LEN], const RelayLimits& lim, uint8_t talk_limit_s = TALK_LIMIT_S) {
    if (!lim.channels || lim.channels > MaxChannels || !lim.legs || lim.legs > MaxLegs || !lim.peers ||
        lim.peers > MaxPeers || !lim.spurts || lim.spurts > MaxSpurts || lim.spurts > FLOOR_MAX_SPURTS ||
        !lim.dedup || lim.dedup > MaxDedup || !lim.talkers || lim.talkers > MaxTalkers || talk_limit_s == 0)
      return false;
    lim_ = lim;
    memcpy(hash_, relay_hash, HASH_LEN);
    talk_limit_s_ = talk_limit_s;
    counters_.init(counter_store_, lim_.talkers);
    for (size_t i = 0; i < MaxChannels; i++) chans_[i].used = false;
    for (size_t i = 0; i < MaxLegs; i++) {
      legs_[i].used = false;
      admitted_[i][0] = admitted_[i][1] = NEVER;
    }
    for (size_t i = 0; i < MaxPeers; i++) reset_peer(peers_[i]);
    dedup_n_ = 0;
    dedup_at_ = 0;
    stall_ms_ = 0;
    return true;
  }

  // The cheap check on a client's CLAIM, before its signature is verified.
  // Returns whether the host should verify it and pass it on.
  bool admit_claim(int64_t now, size_t leg, const uint8_t* data, size_t len, RelaySink& out) {
    if (leg >= lim_.legs) return false;
    Claim m;
    if (decode(data, len, &m) != Error::Ok) return false;
    Chan* ch = chan(m.channel_tag, false);
    if (!ch) return false;
    uint8_t who[HASH_LEN];
    who_of(m.public_key, who);
    uint32_t last = 0;
    const bool has = counters_.last(ch->tag, who, &last);
    if (has && m.spurt < last) return false;
    if (has && m.spurt == last) return true;
    if (now - admitted_[leg][0] < 1000) {
      const SpurtRec* h = ch->floor.holder();
      if (h) out.send('c', leg, h->blob, h->blob_len);
      Busy b;
      memcpy(b.channel_tag, ch->tag, TAG_LEN);
      memcpy(b.talker_tag, m.talker_tag, TAG_LEN);
      b.spurt = m.spurt;
      b.reason = BusyReason::RateLimited;
      b.has_holder = h != nullptr;
      if (h) b.holder = ref(*h);
      send_msg(out, 'c', leg, b);
      return false;
    }
    admitted_[leg][0] = admitted_[leg][1];
    admitted_[leg][1] = now;
    return true;
  }

  // Bytes received on client leg `leg`. `verified`: the CLAIM's membership
  // certificate verified (always false in v1).
  void client(int64_t now, size_t leg, const uint8_t* data, size_t len, int64_t rx, bool verified, RelaySink& out) {
    if (leg < lim_.legs) rx_msg(now, 'c', leg, data, len, rx, verified, out);
  }

  // Bytes received from peer relay `index` (PLAIN one hop or a link).
  void peer(int64_t now, size_t index, const uint8_t* data, size_t len, int64_t rx, bool verified, RelaySink& out) {
    if (index < lim_.peers) rx_msg(now, 'p', index, data, len, rx, verified, out);
  }

  // The TCP slot or BLE peer was released: its subscription goes at once.
  void leg_down(int64_t, size_t leg, RelaySink&) {
    if (leg >= lim_.legs) return;
    legs_[leg].used = false;
    admitted_[leg][0] = admitted_[leg][1] = NEVER;
  }

  void peer_up(int64_t now, size_t index, int64_t rtt_ms, RelaySink&) {
    if (index >= lim_.peers) return;
    peers_[index].up = true;
    peers_[index].rtt_ms = rtt_ms;
    peers_[index].next_at = now;
  }

  void peer_rtt(int64_t, size_t index, int64_t rtt_ms, RelaySink&) {
    if (index < lim_.peers) peers_[index].rtt_ms = rtt_ms;
  }

  void peer_down(int64_t, size_t index, RelaySink&) {
    if (index < lim_.peers) reset_peer(peers_[index]);
  }

  // Judge every timer and send what is due: once per pass, after draining
  // ingress, with the relay's measured stall p99.
  void tick(int64_t now, int64_t stall_p99_ms, RelaySink& out) {
    stall_ms_ = stall_p99_ms < 0 ? 0 : stall_p99_ms;
    for (size_t i = 0; i < lim_.legs; i++)
      if (legs_[i].used && now >= legs_[i].lease_until) legs_[i].used = false;
    for (size_t j = 0; j < lim_.peers; j++) {
      PeerSlot& p = peers_[j];
      if (p.up && p.heard && now - p.last_seen >= PEER_LOST_MS) {
        p.heard = false;
        p.n = 0;
      }
    }
    Chan* cs[MaxChannels];
    const size_t nc = sorted_chans(cs);
    for (size_t c = 0; c < nc; c++) {
      Chan& ch = *cs[c];
      Apply ap(this, &ch, now, &out);
      ch.floor.tick(now, settle(ch.tag), ap);
      announce(ch, out);
      SpurtRec* ls[FLOOR_MAX_SPURTS];
      const size_t nl = ch.floor.sorted(ls, SpurtState::Live);
      for (size_t k = 0; k < nl; k++) {
        SpurtRec* rec = ls[k];
        if (now < rec->hb_next) continue;
        rec->hb_next = now + TALKING_EVERY_MS;
        pair_to_clients(ch, *rec, out);
        pair_to_peers(ch, *rec, rec->local ? -1 : int64_t(rec->src), out);
      }
    }
    for (size_t j = 0; j < lim_.peers; j++) {
      PeerSlot& p = peers_[j];
      if (p.up && now >= p.next_at) {
        p.next_at = now + PEER_EVERY_MS;
        send_peer_summary(j, out);
      }
    }
    for (size_t c = 0; c < nc; c++) {
      Chan& ch = *cs[c];
      if (!any_leg_on(ch.tag) && !any_peer_on(ch.tag) && ch.floor.empty()) ch.used = false;
    }
  }

  // For tests and hosts: the floor of a channel, or null.
  Floor* floor_of(const uint8_t tag[TAG_LEN]) {
    Chan* ch = chan(tag, false);
    return ch ? &ch->floor : nullptr;
  }

 private:
  struct Leg {
    bool used;
    Carrier carrier;
    size_t n;
    SubEntry e[SUB_MAX_ENTRIES];
    int64_t lease_until;
    bool narrow() const { return carrier == Carrier::Ble || carrier == Carrier::Gfsk; }
  };

  struct PeerSlot {
    bool up;
    int64_t rtt_ms;
    int64_t next_at;
    bool heard;
    uint8_t relay_hash[HASH_LEN];
    uint16_t stall_ms;
    int64_t last_seen;
    uint8_t raw[MAX_MESSAGE_LEN];
    size_t n;  // channel entries decoded into ch
    PeerChannel ch[PEER_MAX_CHANNELS];
    bool accepted[PEER_MAX_CHANNELS];
  };

  struct Chan {
    bool used;
    uint8_t tag[TAG_LEN];
    Floor floor;
    SpurtRec recs[MaxSpurts];
  };

  // The floor's actions, applied as they come (spec 5.6).
  class Apply : public FloorSink {
   public:
    Apply(Relay* r, Chan* ch, int64_t now, RelaySink* out) : r_(r), ch_(ch), now_(now), out_(out) {}
    void floor_action(const FloorAction& a) { r_->apply(now_, *ch_, a, *out_); }

   private:
    Relay* r_;
    Chan* ch_;
    int64_t now_;
    RelaySink* out_;
  };

  static void reset_peer(PeerSlot& p) {
    p.up = false;
    p.rtt_ms = 0;
    p.next_at = NEVER;
    p.heard = false;
    memset(p.relay_hash, 0, HASH_LEN);
    p.stall_ms = 0;
    p.last_seen = NEVER;
    p.n = 0;
  }

  static void who_of(const uint8_t public_key[PUBLIC_KEY_LEN], uint8_t who[HASH_LEN]) {
    uint8_t d[32];
    crypto::sha256(public_key, PUBLIC_KEY_LEN, d);
    memcpy(who, d, HASH_LEN);
  }

  static SpurtRef ref(const SpurtRec& r) {
    SpurtRef s;
    memcpy(s.talker_tag, r.tag, TAG_LEN);
    s.spurt = r.spurt;
    s.tier = Tier(r.tier);
    s.emergency = r.emergency;
    return s;
  }

  static bool codec2(uint8_t profile) { return profile == 0x10 || profile == 0x20 || profile == 0x30; }

  template <class M>
  void send_msg(RelaySink& out, char kind, size_t index, const M& m) {
    size_t n = 0;
    if (encode(m, msg_, sizeof(msg_), &n) == Error::Ok) out.send(kind, index, msg_, n);
  }

  // --- tables --------------------------------------------------------------------------

  Chan* chan(const uint8_t tag[TAG_LEN], bool create) {
    size_t used = 0;
    Chan* free_slot = nullptr;
    for (size_t i = 0; i < MaxChannels; i++) {
      Chan& c = chans_[i];
      if (c.used) {
        used++;
        if (memcmp(c.tag, tag, TAG_LEN) == 0) return &c;
      } else if (!free_slot) {
        free_slot = &c;
      }
    }
    if (!create || used >= lim_.channels || !free_slot) return nullptr;
    Chan& c = *free_slot;
    c.used = true;
    memcpy(c.tag, tag, TAG_LEN);
    c.floor.init(Role::Relay, tag, &counters_, c.recs, lim_.spurts, talk_limit_s_);
    return &c;
  }

  size_t sorted_chans(Chan** out) {
    size_t n = 0;
    for (size_t i = 0; i < MaxChannels; i++) {
      Chan* c = &chans_[i];
      if (!c->used) continue;
      size_t j = n++;
      while (j > 0 && memcmp(c->tag, out[j - 1]->tag, TAG_LEN) < 0) {
        out[j] = out[j - 1];
        j--;
      }
      out[j] = c;
    }
    return n;
  }

  // The leg's entry for a channel (voice only if asked), or null.
  const SubEntry* leg_entry(size_t i, const uint8_t tag[TAG_LEN], bool voice_only) const {
    const Leg& l = legs_[i];
    if (!l.used) return nullptr;
    for (size_t k = 0; k < l.n; k++)
      if (memcmp(l.e[k].channel_tag, tag, TAG_LEN) == 0)
        return (l.e[k].mode == SubMode::Voice || !voice_only) ? &l.e[k] : nullptr;
    return nullptr;
  }

  bool any_leg_on(const uint8_t tag[TAG_LEN]) const {
    for (size_t i = 0; i < lim_.legs; i++)
      if (leg_entry(i, tag, false)) return true;
    return false;
  }

  const PeerChannel* peer_chan(size_t j, const uint8_t tag[TAG_LEN]) const {
    const PeerSlot& p = peers_[j];
    if (!p.up || !p.heard) return nullptr;
    for (size_t k = 0; k < p.n; k++)
      if (p.accepted[k] && memcmp(p.ch[k].channel_tag, tag, TAG_LEN) == 0) return &p.ch[k];
    return nullptr;
  }

  const PeerChannel* peer_on(size_t j, const uint8_t tag[TAG_LEN], bool members_only) const {
    const PeerChannel* c = peer_chan(j, tag);
    return (c && (!members_only || c->member_count > 0)) ? c : nullptr;
  }

  bool any_peer_on(const uint8_t tag[TAG_LEN]) const {
    for (size_t j = 0; j < lim_.peers; j++)
      if (peer_on(j, tag, false)) return true;
    return false;
  }

  int64_t settle(const uint8_t tag[TAG_LEN]) const {
    int64_t s = 0;
    for (size_t j = 0; j < lim_.peers; j++)
      if (peer_on(j, tag, false) && peers_[j].rtt_ms > s) s = peers_[j].rtt_ms;
    return s;
  }

  bool dedup_seen(const uint8_t key[DEDUP_KEY_LEN]) {
    for (size_t i = 0; i < dedup_n_; i++)
      if (memcmp(dedup_[i], key, DEDUP_KEY_LEN) == 0) return true;
    if (dedup_n_ < lim_.dedup) {
      memcpy(dedup_[dedup_n_++], key, DEDUP_KEY_LEN);
    } else {
      memcpy(dedup_[dedup_at_], key, DEDUP_KEY_LEN);
      dedup_at_ = (dedup_at_ + 1) % lim_.dedup;
    }
    return false;
  }

  // Sorted, distinct 4-byte tags in tags_[0..n); returns the new count.
  static size_t sort_unique(uint8_t* t, size_t n) {
    for (size_t i = 1; i < n; i++) {
      uint8_t x[TAG_LEN];
      memcpy(x, t + TAG_LEN * i, TAG_LEN);
      size_t j = i;
      while (j > 0 && memcmp(x, t + TAG_LEN * (j - 1), TAG_LEN) < 0) {
        memcpy(t + TAG_LEN * j, t + TAG_LEN * (j - 1), TAG_LEN);
        j--;
      }
      memcpy(t + TAG_LEN * j, x, TAG_LEN);
    }
    size_t m = 0;
    for (size_t i = 0; i < n; i++)
      if (m == 0 || memcmp(t + TAG_LEN * i, t + TAG_LEN * (m - 1), TAG_LEN) != 0) {
        if (m != i) memcpy(t + TAG_LEN * m, t + TAG_LEN * i, TAG_LEN);
        m++;
      }
    return m;
  }

  // --- messages the relay builds --------------------------------------------------------

  void send_talking(const Chan& ch, const SpurtRec& rec, char kind, size_t index, RelaySink& out) {
    Talking t;
    memcpy(t.channel_tag, ch.tag, TAG_LEN);
    t.holder = ref(rec);
    t.profile = Profile(rec.profile);
    t.talk_limit_s = rec.limit_s;
    send_msg(out, kind, index, t);
  }

  // The member tags reached into reached_, and at the first grant the lowest
  // common profile, which then stays the spurt's.
  void grant_fields(const Chan& ch, SpurtRec& rec, bool profile_too) {
    bool narrow = rec.src >= 0 && size_t(rec.src) < lim_.legs && legs_[rec.src].used && legs_[rec.src].narrow();
    size_t n = 0;
    for (size_t i = 0; i < lim_.legs; i++) {
      const SubEntry* e = leg_entry(i, ch.tag, true);
      if (!e || int32_t(i) == rec.src) continue;
      memcpy(tags_ + TAG_LEN * n++, e->member_tag, TAG_LEN);
      narrow = narrow || legs_[i].narrow();
    }
    for (size_t j = 0; j < lim_.peers; j++) {
      const PeerChannel* c = peer_on(j, ch.tag, false);
      if (!c) continue;
      narrow = narrow || c->narrow;
      memcpy(tags_ + TAG_LEN * n, c->members, TAG_LEN * c->member_count);
      n += c->member_count;
    }
    n = sort_unique(tags_, n);
    size_t m = 0;
    for (size_t i = 0; i < n; i++)
      if (memcmp(tags_ + TAG_LEN * i, rec.tag, TAG_LEN) != 0) {
        if (m != i) memcpy(tags_ + TAG_LEN * m, tags_ + TAG_LEN * i, TAG_LEN);
        m++;
      }
    reached_n_ = m > GRANT_MAX_REACHED ? GRANT_MAX_REACHED : m;
    memcpy(reached_, tags_, TAG_LEN * reached_n_);
    if (profile_too) {
      rec.profile = narrow ? uint8_t(Profile::Lbw) : uint8_t(Profile::Hq);
      rec.limit_s = talk_limit_s_;
    }
  }

  void send_grant(const Chan& ch, const SpurtRec& rec, RelaySink& out) {
    Grant g;
    memcpy(g.channel_tag, ch.tag, TAG_LEN);
    memcpy(g.talker_tag, rec.tag, TAG_LEN);
    g.spurt = rec.spurt;
    g.profile = Profile(rec.profile);
    g.talk_limit_s = rec.limit_s;
    g.reached_count = reached_n_;
    g.reached = reached_;
    send_msg(out, 'c', size_t(rec.src), g);
  }

  void send_busy(const Chan& ch, const uint8_t talker_tag[TAG_LEN], uint32_t spurt, const SpurtRec* holder,
                 BusyReason reason, size_t leg, RelaySink& out) {
    Busy b;
    memcpy(b.channel_tag, ch.tag, TAG_LEN);
    memcpy(b.talker_tag, talker_tag, TAG_LEN);
    b.spurt = spurt;
    b.reason = reason;
    b.has_holder = holder != nullptr;
    if (holder) b.holder = ref(*holder);
    send_msg(out, 'c', leg, b);
  }

  // PEER for peer q: every channel a live leg or another peer lists, its narrow
  // flag and its member tags (split horizon: nothing learnt from q).
  void send_peer_summary(size_t q, RelaySink& out) {
    Chan* cs[MaxChannels];
    const size_t nc = sorted_chans(cs);
    PeerChannel entries[PEER_MAX_CHANNELS];
    size_t ne = 0, size = PEER_MIN_LEN, used = 0;
    for (size_t c = 0; c < nc; c++) {
      const uint8_t* tag = cs[c]->tag;
      bool listed = false, narrow = false;
      size_t n = 0;
      for (size_t i = 0; i < lim_.legs; i++) {
        const SubEntry* e = leg_entry(i, tag, false);
        if (!e) continue;
        listed = true;
        if (e->mode == SubMode::Voice) {
          memcpy(tags_ + TAG_LEN * n++, e->member_tag, TAG_LEN);
          narrow = narrow || legs_[i].narrow();
        }
      }
      for (size_t j = 0; j < lim_.peers; j++) {
        if (j == q) continue;
        const PeerChannel* pc = peer_on(j, tag, false);
        if (!pc) continue;
        listed = true;
        narrow = narrow || pc->narrow;
        memcpy(tags_ + TAG_LEN * n, pc->members, TAG_LEN * pc->member_count);
        n += pc->member_count;
      }
      if (!listed) continue;
      n = sort_unique(tags_, n);
      if (n > PEER_MAX_MEMBERS) n = PEER_MAX_MEMBERS;
      const size_t need = PEER_CHANNEL_MIN_LEN + TAG_LEN * n;
      if (size + need > MAX_MESSAGE_LEN || ne == PEER_MAX_CHANNELS) break;
      size += need;
      memcpy(members_ + used, tags_, TAG_LEN * n);
      PeerChannel& pc = entries[ne++];
      memcpy(pc.channel_tag, tag, TAG_LEN);
      pc.narrow = narrow;
      pc.member_count = n;
      pc.members = members_ + used;
      used += TAG_LEN * n;
    }
    Peer m;
    memcpy(m.relay_hash, hash_, HASH_LEN);
    m.stall_p99_ms = stall_ms_ > 0xFFFF ? uint16_t(0xFFFF) : uint16_t(stall_ms_);
    m.count = ne;
    m.channels = entries;
    send_msg(out, 'p', q, m);
  }

  // --- fan-out -------------------------------------------------------------------------

  void to_clients(const Chan& ch, const uint8_t* data, size_t len, bool voice_only, int64_t skip,
                  const SpurtRec* rec, RelaySink& out) {
    for (size_t i = 0; i < lim_.legs; i++) {
      if (!leg_entry(i, ch.tag, voice_only) || int64_t(i) == skip) continue;
      if (rec && legs_[i].narrow() && (rec->profile == 0 || !codec2(rec->profile))) continue;
      out.send('c', i, data, len);
    }
  }

  void to_peers(const Chan& ch, const uint8_t* data, size_t len, bool members_only, int64_t skip, RelaySink& out) {
    for (size_t j = 0; j < lim_.peers; j++)
      if (peer_on(j, ch.tag, members_only) && int64_t(j) != skip) out.send('p', j, data, len);
  }

  // A live spurt's CLAIM, then its TALKING, to every leg on the channel but the
  // talker's own.
  void pair_to_clients(const Chan& ch, SpurtRec& rec, RelaySink& out) {
    if (rec.profile == 0) return;
    const int64_t skip = rec.local ? int64_t(rec.src) : -1;
    for (size_t i = 0; i < lim_.legs; i++) {
      if (!leg_entry(i, ch.tag, false) || int64_t(i) == skip) continue;
      out.send('c', i, rec.blob, rec.blob_len);
      send_talking(ch, rec, 'c', i, out);
    }
    rec.told = true;
  }

  void pair_to_peers(const Chan& ch, const SpurtRec& rec, int64_t skip, RelaySink& out) {
    if (rec.profile == 0) return;
    for (size_t j = 0; j < lim_.peers; j++) {
      if (!peer_on(j, ch.tag, false) || int64_t(j) == skip) continue;
      out.send('p', j, rec.blob, rec.blob_len);
      send_talking(ch, rec, 'p', j, out);
    }
  }

  void send_yield(const Chan& ch, SpurtRec& rec, const SpurtRec& w, YieldReason reason, int64_t now, RelaySink& out) {
    rec.nudge_at = now;
    out.send('c', size_t(rec.src), w.blob, w.blob_len);
    Yield y;
    memcpy(y.channel_tag, ch.tag, TAG_LEN);
    memcpy(y.talker_tag, rec.tag, TAG_LEN);
    y.spurt = rec.spurt;
    y.reason = reason;
    y.winner = ref(w);
    send_msg(out, 'c', size_t(rec.src), y);
  }

  // After a floor call: a spurt that went live on evidence and is still live
  // is announced to the legs and to the peers but its source.
  void announce(Chan& ch, RelaySink& out) {
    SpurtRec* ls[FLOOR_MAX_SPURTS];
    const size_t n = ch.floor.sorted(ls, SpurtState::Live);
    for (size_t i = 0; i < n; i++) {
      if (!ls[i]->announce) continue;
      ls[i]->announce = false;
      pair_to_clients(ch, *ls[i], out);
      pair_to_peers(ch, *ls[i], int64_t(ls[i]->src), out);
    }
    for (size_t i = 0; i < lim_.spurts; i++) ch.recs[i].announce = false;
  }

  void apply(int64_t now, Chan& ch, const FloorAction& a, RelaySink& out) {
    out.note(ch.tag, a);
    SpurtRec& rec = *a.rec;
    const int64_t src_leg = rec.local ? int64_t(rec.src) : -1;
    const int64_t src_peer = rec.local ? -1 : int64_t(rec.src);
    switch (a.act) {
      case Act::Pending:
      case Act::Known:
        to_clients(ch, rec.blob, rec.blob_len, false, src_leg, nullptr, out);
        to_peers(ch, rec.blob, rec.blob_len, false, src_peer, out);
        break;
      case Act::Grant:
        grant_fields(ch, rec, true);
        send_grant(ch, rec, out);
        pair_to_clients(ch, rec, out);
        pair_to_peers(ch, rec, -1, out);
        rec.hb_next = now + TALKING_EVERY_MS;
        break;
      case Act::Regrant:
        grant_fields(ch, rec, false);
        send_grant(ch, rec, out);
        break;
      case Act::Busy:
        out.send('c', size_t(rec.src), a.other->blob, a.other->blob_len);
        send_busy(ch, rec.tag, rec.spurt, a.other, BusyReason::Busy, size_t(rec.src), out);
        break;
      case Act::Live:
        rec.hb_next = now + TALKING_EVERY_MS;
        rec.announce = true;
        break;
      case Act::Yield:
        if (rec.local)
          send_yield(ch, rec, *a.other, a.why == Why::Preempted ? YieldReason::Preempted : YieldReason::Collision, now,
                     out);
        break;
      default:
        break;
    }
  }

  // --- events --------------------------------------------------------------------------

  void rx_msg(int64_t now, char kind, size_t idx, const uint8_t* data, size_t len, int64_t rx, bool verified,
              RelaySink& out) {
    Type t;
    if (check(data, len, &t) != Error::Ok) return;
    const bool from_peer = kind == 'p';
    if (from_peer && !peers_[idx].up) return;
    if (from_peer && peers_[idx].heard) peers_[idx].last_seen = now;
    switch (t) {
      case Type::Sub:
        if (!from_peer) on_sub(now, idx, data, len, out);
        break;
      case Type::Peer:
        if (from_peer) on_peer(now, idx, data, len, out);
        break;
      case Type::Claim:
        on_claim(now, kind, idx, data, len, verified, out);
        break;
      case Type::Frame:
        on_frame(now, kind, idx, data, len, rx, out);
        break;
      case Type::Release:
        on_release(now, kind, idx, data, len, out);
        break;
      case Type::Talking:
        if (from_peer) on_talking(now, idx, data, len, rx, out);
        break;
      case Type::Heard:
        on_heard(kind, idx, data, len, out);
        break;
      default:
        break;
    }
  }

  static bool tag_in(const uint8_t* tags, size_t n, const uint8_t tag[TAG_LEN]) {
    for (size_t i = 0; i < n; i++)
      if (memcmp(tags + TAG_LEN * i, tag, TAG_LEN) == 0) return true;
    return false;
  }

  void on_sub(int64_t now, size_t i, const uint8_t* data, size_t len, RelaySink& out) {
    SubEntry in[SUB_MAX_ENTRIES];
    Sub m;
    if (decode(data, len, &m, in, SUB_MAX_ENTRIES) != Error::Ok) return;
    uint8_t before[TAG_LEN * SUB_MAX_ENTRIES];
    size_t nb = 0;
    if (legs_[i].used)
      for (size_t k = 0; k < legs_[i].n; k++) memcpy(before + TAG_LEN * nb++, legs_[i].e[k].channel_tag, TAG_LEN);
    Leg& leg = legs_[i];
    leg.used = true;
    leg.carrier = m.carrier;
    leg.lease_until = now + SUB_LEASE_MS;
    leg.n = 0;
    for (size_t k = 0; k < m.count; k++) {
      bool dup = false;
      for (size_t x = 0; x < leg.n; x++)
        if (memcmp(leg.e[x].channel_tag, in[k].channel_tag, TAG_LEN) == 0) dup = true;
      if (dup || !chan(in[k].channel_tag, true)) continue;
      leg.e[leg.n++] = in[k];
    }
    // Late joiner: every channel newly listed, in tag order.
    uint8_t fresh[TAG_LEN * SUB_MAX_ENTRIES];
    size_t nf = 0;
    for (size_t k = 0; k < leg.n; k++)
      if (!tag_in(before, nb, leg.e[k].channel_tag)) memcpy(fresh + TAG_LEN * nf++, leg.e[k].channel_tag, TAG_LEN);
    nf = sort_unique(fresh, nf);
    for (size_t k = 0; k < nf; k++) {
      Chan* ch = chan(fresh + TAG_LEN * k, false);
      SpurtRec* ls[FLOOR_MAX_SPURTS];
      const size_t nl = ch->floor.sorted(ls, SpurtState::Live);
      for (size_t r = 0; r < nl; r++) {
        if (ls[r]->profile == 0 || (ls[r]->local && ls[r]->src == int32_t(i))) continue;
        out.send('c', i, ls[r]->blob, ls[r]->blob_len);
        send_talking(*ch, *ls[r], 'c', i, out);
      }
    }
  }

  void on_peer(int64_t now, size_t j, const uint8_t* data, size_t len, RelaySink& out) {
    PeerSlot& p = peers_[j];
    uint8_t before[TAG_LEN * PEER_MAX_CHANNELS];
    size_t nb = 0;
    if (p.heard)
      for (size_t k = 0; k < p.n; k++)
        if (p.accepted[k]) memcpy(before + TAG_LEN * nb++, p.ch[k].channel_tag, TAG_LEN);
    memcpy(p.raw, data, len);
    Peer m;
    if (decode(p.raw, len, &m, p.ch, PEER_MAX_CHANNELS) != Error::Ok) {
      p.n = 0;
      return;
    }
    p.heard = true;
    memcpy(p.relay_hash, m.relay_hash, HASH_LEN);
    p.stall_ms = m.stall_p99_ms;
    p.last_seen = now;
    p.n = m.count;
    for (size_t k = 0; k < p.n; k++) {
      bool dup = false;
      for (size_t x = 0; x < k; x++)
        if (p.accepted[x] && memcmp(p.ch[x].channel_tag, p.ch[k].channel_tag, TAG_LEN) == 0) dup = true;
      p.accepted[k] = !dup && chan(p.ch[k].channel_tag, true) != nullptr;
    }
    uint8_t fresh[TAG_LEN * PEER_MAX_CHANNELS];
    size_t nf = 0;
    for (size_t k = 0; k < p.n; k++)
      if (p.accepted[k] && !tag_in(before, nb, p.ch[k].channel_tag))
        memcpy(fresh + TAG_LEN * nf++, p.ch[k].channel_tag, TAG_LEN);
    nf = sort_unique(fresh, nf);
    for (size_t k = 0; k < nf; k++) {
      Chan* ch = chan(fresh + TAG_LEN * k, false);
      SpurtRec* ls[FLOOR_MAX_SPURTS];
      const size_t nl = ch->floor.sorted(ls, SpurtState::Live);
      for (size_t r = 0; r < nl; r++) {
        if (ls[r]->profile == 0 || (!ls[r]->local && ls[r]->src == int32_t(j))) continue;
        out.send('p', j, ls[r]->blob, ls[r]->blob_len);
        send_talking(*ch, *ls[r], 'p', j, out);
      }
    }
  }

  void on_claim(int64_t now, char kind, size_t idx, const uint8_t* data, size_t len, bool verified, RelaySink& out) {
    Claim m;
    if (decode(data, len, &m) != Error::Ok) return;
    Chan* ch = chan(m.channel_tag, false);
    if (!ch) return;
    FloorClaim c;
    who_of(m.public_key, c.who);
    const bool local = kind == 'c';
    uint32_t last = 0;
    const bool has = counters_.last(ch->tag, c.who, &last);
    const bool fresh = !has || m.spurt > last;
    if (local && m.emergency && fresh && now - counters_.emergency_at(ch->tag, c.who) < EMERGENCY_EVERY_MS) {
      const SpurtRec* h = ch->floor.holder();
      if (h) out.send('c', idx, h->blob, h->blob_len);
      send_busy(*ch, m.talker_tag, m.spurt, h, BusyReason::RateLimited, idx, out);
      return;
    }
    memcpy(c.tag, m.talker_tag, TAG_LEN);
    c.spurt = m.spurt;
    memcpy(c.nonce, m.nonce, NONCE_LEN);
    c.tier = uint8_t(m.tier);
    c.emergency = m.emergency;
    c.verified = verified;
    c.local = local;
    c.src = int32_t(idx);
    c.stall_ms = local ? stall_ms_ : (stall_ms_ > peers_[idx].stall_ms ? stall_ms_ : int64_t(peers_[idx].stall_ms));
    c.blob = data;
    c.blob_len = len;
    Apply ap(this, ch, now, &out);
    ch->floor.claim(now, c, settle(ch->tag), ap);
    announce(*ch, out);
    if (local && m.emergency && fresh) counters_.set_emergency(ch->tag, c.who, now);
  }

  void on_frame(int64_t now, char kind, size_t idx, const uint8_t* data, size_t len, int64_t rx, RelaySink& out) {
    Frame m;
    if (decode(data, len, &m) != Error::Ok) return;
    Chan* ch = chan(m.channel_tag, false);
    if (!ch) return;
    // A frame counts only from where its spurt's frames can come: a local
    // spurt's from its talker's own leg, a remote spurt's from a peer.
    SpurtRec* named = ch->floor.find_tag(m.talker_tag, m.spurt);
    if (named && (named->local != (kind == 'c') || (named->local && int32_t(idx) != named->src))) return;
    // Stale evidence never makes a spurt live: a backlog is not a talker.
    if (named && (named->state == SpurtState::Pending || named->state == SpurtState::Known) &&
        now - rx > FRAME_MAX_AGE_MS)
      return;
    uint8_t key[DEDUP_KEY_LEN];
    memcpy(key, m.channel_tag, TAG_LEN);
    memcpy(key + 4, m.talker_tag, TAG_LEN);
    wire_detail::put32(key + 8, m.spurt);
    wire_detail::put16(key + 12, m.seq);
    memcpy(key + 14, m.mac, 4);
    if (dedup_seen(key)) return;
    // Judged on the spurt as it was live before this frame: a late one is held back
    // somewhere (a stalled pass, a socket buffer) -- a backlog, not voice. It still
    // counts as heard, as a stale one does; it is only not forwarded.
    const bool is_late = named && named->state == SpurtState::Live && relay_detail::late(*named, m.seq, rx);
    bool forward = false;
    Apply ap(this, ch, now, &out);
    SpurtRec* rec = ch->floor.frame(now, rx, m.talker_tag, m.spurt, m.seq, &forward, ap);
    announce(*ch, out);
    SpurtRec* nudge = rec && rec->local && rec->state == SpurtState::Yielded ? rec : nullptr;
    if (!rec && kind == 'c') {
      // A spurt that is over here (lost past the resume window, or ended
      // otherwise) whose talker is still sending on its own leg is told the same way.
      SpurtRec* dead = ch->floor.find_tag(m.talker_tag, m.spurt, true);
      if (dead && dead->local && dead->src == int32_t(idx)) nudge = dead;
    }
    if (nudge && now - nudge->nudge_at >= YIELD_AGAIN_MS) {
      // Its talker is still sending: the YIELD was lost (or never due). At most once a second.
      const SpurtRec* w = ch->floor.holder();
      if (w)
        send_yield(*ch, *nudge, *w,
                   floor_detail::can_preempt(*w, *nudge) ? YieldReason::Preempted : YieldReason::Collision, now, out);
    }
    if (!forward || is_late || now - rx > FRAME_MAX_AGE_MS) return;
    to_clients(*ch, data, len, true, kind == 'c' ? int64_t(idx) : -1, rec, out);
    for (size_t j = 0; j < lim_.peers; j++) {
      if (!peer_on(j, ch->tag, true)) continue;
      if ((kind == 'p' && j == idx) || (!rec->local && int32_t(j) == rec->src)) continue;
      out.send('p', j, data, len);
    }
  }

  void on_release(int64_t now, char kind, size_t idx, const uint8_t* data, size_t len, RelaySink& out) {
    Release m;
    if (decode(data, len, &m) != Error::Ok) return;
    Chan* ch = chan(m.channel_tag, false);
    if (!ch) return;
    uint8_t who[HASH_LEN];
    who_of(m.public_key, who);
    Apply ap(this, ch, now, &out);
    const bool fresh = ch->floor.release(now, who, m.spurt, m.talker_tag, ap);
    announce(*ch, out);
    if (fresh) {
      to_clients(*ch, data, len, false, kind == 'c' ? int64_t(idx) : -1, nullptr, out);
      to_peers(*ch, data, len, false, kind == 'p' ? int64_t(idx) : -1, out);
    }
  }

  void on_talking(int64_t now, size_t, const uint8_t* data, size_t len, int64_t rx, RelaySink& out) {
    Talking m;
    if (decode(data, len, &m) != Error::Ok) return;
    Chan* ch = chan(m.channel_tag, false);
    // A stale TALKING (queued through a pass) says nothing about now; the next heartbeat will.
    if (!ch || now - rx > FRAME_MAX_AGE_MS) return;
    Apply ap(this, ch, now, &out);
    SpurtRec* rec = ch->floor.talking(now, m.holder.talker_tag, m.holder.spurt, uint8_t(m.profile), m.talk_limit_s, ap);
    announce(*ch, out);
    if (!rec || rec->local || rec->state != SpurtState::Live) return;
    if (!rec->told) pair_to_clients(*ch, *rec, out);
  }

  void on_heard(char kind, size_t idx, const uint8_t* data, size_t len, RelaySink& out) {
    Heard m;
    if (decode(data, len, &m, nullptr, 0) != Error::Ok) return;
    Chan* ch = chan(m.channel_tag, false);
    if (!ch) return;
    const SpurtRec* rec = ch->floor.find_tag(m.talker_tag, m.spurt, true);
    if (!rec || rec->src < 0) return;
    if (rec->local && !(kind == 'c' && int32_t(idx) == rec->src)) {
      out.send('c', size_t(rec->src), data, len);
    } else if (!rec->local && !(kind == 'p' && int32_t(idx) == rec->src)) {
      out.send('p', size_t(rec->src), data, len);
    }
  }

  RelayLimits lim_;
  uint8_t hash_[HASH_LEN] = {0};
  uint8_t talk_limit_s_ = TALK_LIMIT_S;
  int64_t stall_ms_ = 0;
  Counters counters_;
  CounterEntry counter_store_[MaxTalkers];
  Chan chans_[MaxChannels];
  Leg legs_[MaxLegs];
  int64_t admitted_[MaxLegs][2];  // the two last admitted claims per leg
  PeerSlot peers_[MaxPeers];
  uint8_t dedup_[MaxDedup][DEDUP_KEY_LEN];
  size_t dedup_n_ = 0;
  size_t dedup_at_ = 0;
  uint8_t msg_[MAX_MESSAGE_LEN];
  uint8_t tags_[TAG_LEN * (MaxLegs + MaxPeers * PEER_MAX_MEMBERS)];
  uint8_t members_[MAX_MESSAGE_LEN];
  uint8_t reached_[TAG_LEN * GRANT_MAX_REACHED];
  size_t reached_n_ = 0;
};

}  // namespace lxpt

#endif  // LXPT_RELAY_HPP
