// lxpt floor core v1 -- one channel's floor as one node sees it. Header-only,
// C++11, no heap, no exceptions, no platform headers.
//
// Pure: events in, actions out (through a FloorSink, in the order
// spec/floor-v1.md gives), the clock passed in as int64 milliseconds. The
// records live in storage the caller provides at init(); nothing allocates.
// The Python reference (python/lxpt/floor.py) and Kotlin (Floor.kt) give the
// same actions, held by fixtures/lxpt_floor_v1.json.
//
// The host verifies every CLAIM and RELEASE signature before calling the core.
//
// SPDX-License-Identifier: Apache-2.0

#ifndef LXPT_FLOOR_HPP
#define LXPT_FLOOR_HPP

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto.hpp"
#include "wire.hpp"

namespace lxpt {

// Timers, in milliseconds (spec/floor-v1.md section 3).
static const int64_t SETTLE_CAP_MS = 300;
static const int64_t REMOTE_HOLD_MS = 600;
static const int64_t QUIET_MS = 1200;
static const int64_t LOST_MIN_MS = 5000;
static const int64_t LOST_MAX_MS = 15000;
static const int64_t RESUME_MS = 20000;        // a yielded spurt can come back within this
static const int64_t RESUME_WINDOW_MS = 2000;  // a lost spurt can come back only within this (v1.1)
static const int64_t LATE_MS = 800;            // a frame this far behind its spurt's schedule is a backlog (v1.2)
static const int64_t TOMBSTONE_MS = 30000;
static const int64_t LIMIT_GRACE_MS = 1000;
static const int64_t CLAIM_RETRY_MS = 600;
static const uint8_t CLAIM_SENDS = 3;
static const uint8_t TALK_LIMIT_S = 30;
static const int64_t NEVER = -1000000000;  // before any clock the core is given
static const size_t FLOOR_MAX_SPURTS = 32;  // the most records one floor may be given
static const size_t ORDER_LEN = 34;

enum class Role : uint8_t { Relay, Phone };
enum class SpurtState : uint8_t { Free = 0, Pending, Known, Live, Lost, Yielded, Ended };
enum class Act : uint8_t { Pending, Known, Grant, Regrant, Busy, Live, Yield, Quiet, Unquiet, Lost, Resumed, Ended, Retry };
enum class Why : uint8_t { None, Released, Limit, Superseded, GaveUp, Lost, Yielded, Collision, Preempted };

inline const char* act_name(Act a) {
  static const char* const n[] = {"pending", "known", "grant", "regrant", "busy", "live", "yield",
                                  "quiet", "unquiet", "lost", "resumed", "ended", "retry"};
  return n[uint8_t(a)];
}
inline const char* why_name(Why w) {
  static const char* const n[] = {"", "released", "limit", "superseded", "gave_up", "lost", "yielded",
                                  "collision", "preempted"};
  return n[uint8_t(w)];
}

// What the core needs from a verified CLAIM.
struct FloorClaim {
  uint8_t who[HASH_LEN];  // identity hash of the verified signing key
  uint8_t tag[TAG_LEN];   // talker tag
  uint32_t spurt;
  uint8_t nonce[NONCE_LEN];
  uint8_t tier;  // 1..5
  bool emergency;
  bool verified;  // its membership verified (T8); always false in v1
  bool local;     // from this relay's own client
  int32_t src;    // the client leg or peer index it came from
  int64_t stall_ms;
  const uint8_t* blob;  // the CLAIM's bytes, kept to re-send; may be null
  size_t blob_len;
};

// One spurt as this node knows it.
struct SpurtRec {
  SpurtState state;
  uint8_t who[HASH_LEN];
  uint8_t tag[TAG_LEN];
  uint32_t spurt;
  uint8_t nonce[NONCE_LEN];
  uint8_t tier;
  bool emergency, verified, local, own;
  int32_t src;
  uint8_t order[ORDER_LEN];
  int64_t seen_at, hold_until, live_since, last_heard;
  int32_t last_seq;
  bool quiet;
  int64_t lost_at, ended_at, lost_ms;
  bool lost_window;  // a yielded spurt that was lost keeps the lost spurt's window
  uint8_t limit_s, profile, sends;
  int64_t retry_at;
  // relay bookkeeping, unused by the floor's own rules
  int64_t hb_next, nudge_at;
  bool told, announce;
  // media time (v1.2): best_offset is the smallest (rx - seq x frame time) of the
  // spurt's live frames, timed whether it is set yet; a lost spurt's frames must
  // keep to it to resume. last_arrival (the last frame's arrival) and late_run
  // (late frames in a row at real-time pace) are the relay's (relay.hpp's late()).
  int64_t best_offset, last_arrival;
  bool timed;
  uint8_t late_run;
  uint8_t blob_len;
  uint8_t blob[CLAIM_LEN];
};

struct FloorAction {
  Act act;
  SpurtRec* rec;
  const SpurtRec* other;  // BUSY's holder, YIELD's winner; may be null
  Why why;
};

class FloorSink {
 public:
  virtual void floor_action(const FloorAction& a) = 0;

 protected:
  ~FloorSink() {}
};

namespace floor_detail {

inline uint8_t eff_tier(uint8_t tier, bool verified) { return verified ? tier : (tier > 4 ? tier : uint8_t(4)); }

inline void order_key(const uint8_t who[HASH_LEN], uint32_t spurt, const uint8_t nonce[NONCE_LEN], uint8_t tier,
                      bool emergency, bool verified, uint8_t out[ORDER_LEN]) {
  uint8_t buf[HASH_LEN + 4 + NONCE_LEN];
  memcpy(buf, who, HASH_LEN);
  wire_detail::put32(buf + HASH_LEN, spurt);
  memcpy(buf + HASH_LEN + 4, nonce, NONCE_LEN);
  out[0] = emergency ? 0 : 1;
  out[1] = eff_tier(tier, verified);
  crypto::sha256(buf, sizeof(buf), out + 2);
}

inline bool cuts(uint8_t c, uint8_t s) { return (c == 1 && s >= 2) || (c == 2 && s >= 3) || (c == 3 && s == 4); }

inline bool can_preempt(const SpurtRec& c, const SpurtRec& s) {
  if (!c.verified || s.emergency) return false;
  return c.emergency || cuts(eff_tier(c.tier, true), eff_tier(s.tier, s.verified));
}

inline int64_t lost_ms_for(int64_t stall_ms) {
  int64_t v = stall_ms * 3 / 2;
  if (v < LOST_MIN_MS) v = LOST_MIN_MS;
  if (v > LOST_MAX_MS) v = LOST_MAX_MS;
  return v;
}

inline int before(const SpurtRec* a, const SpurtRec* b) { return memcmp(a->order, b->order, ORDER_LEN) < 0; }

inline int rank(SpurtState s) {
  switch (s) {
    case SpurtState::Live: return 0;
    case SpurtState::Lost: return 1;
    case SpurtState::Yielded: return 2;
    case SpurtState::Pending: return 3;
    case SpurtState::Known: return 4;
    default: return 5;
  }
}

// A profile's frame time in ms (LXST's); 0 for an unknown profile.
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

// Whether frame seq of rec, received at rx, is more than LATE_MS behind the
// spurt's schedule (v1.2). False with no schedule yet (profile unknown, or no
// frame timed).
inline bool behind(const SpurtRec& rec, uint16_t seq, int64_t rx) {
  const int64_t fm = frame_ms(rec.profile);
  if (fm == 0 || !rec.timed) return false;
  return rx - int64_t(seq) * fm - rec.best_offset > LATE_MS;
}

}  // namespace floor_detail

// The last spurt per (channel tag, identity hash) and the time of its last
// Emergency claim: replay protection that outlives the floor's records.
struct CounterEntry {
  bool used;
  uint8_t tag[TAG_LEN];
  uint8_t who[HASH_LEN];
  uint32_t last;
  int64_t emergency_at;
  int64_t used_at;
};

class Counters {
 public:
  void init(CounterEntry* storage, size_t capacity) {
    e_ = storage;
    cap_ = capacity;
    for (size_t i = 0; i < cap_; i++) e_[i].used = false;
  }
  bool last(const uint8_t tag[TAG_LEN], const uint8_t who[HASH_LEN], uint32_t* out) const {
    const CounterEntry* c = find(tag, who);
    if (!c) return false;
    *out = c->last;
    return true;
  }
  int64_t emergency_at(const uint8_t tag[TAG_LEN], const uint8_t who[HASH_LEN]) const {
    const CounterEntry* c = find(tag, who);
    return c ? c->emergency_at : NEVER;
  }
  void set_emergency(const uint8_t tag[TAG_LEN], const uint8_t who[HASH_LEN], int64_t now) {
    CounterEntry* c = const_cast<CounterEntry*>(find(tag, who));
    if (c) c->emergency_at = now;
  }
  void advance(int64_t now, const uint8_t tag[TAG_LEN], const uint8_t who[HASH_LEN], uint32_t spurt) {
    CounterEntry* c = const_cast<CounterEntry*>(find(tag, who));
    if (c) {
      if (spurt > c->last) c->last = spurt;
      c->used_at = now;
      return;
    }
    CounterEntry* slot = nullptr;
    size_t n = 0;
    for (size_t i = 0; i < cap_; i++) {
      if (e_[i].used) {
        n++;
      } else if (!slot) {
        slot = &e_[i];
      }
    }
    if (n >= cap_ || !slot) {
      // The least recently advanced goes; ties to the lower tag || hash.
      CounterEntry* victim = nullptr;
      for (size_t i = 0; i < cap_; i++) {
        CounterEntry* x = &e_[i];
        if (!x->used) continue;
        if (!victim || x->used_at < victim->used_at || (x->used_at == victim->used_at && key_less(*x, *victim)))
          victim = x;
      }
      if (!victim) return;
      slot = victim;
    }
    slot->used = true;
    memcpy(slot->tag, tag, TAG_LEN);
    memcpy(slot->who, who, HASH_LEN);
    slot->last = spurt;
    slot->emergency_at = NEVER;
    slot->used_at = now;
  }

 private:
  static bool key_less(const CounterEntry& a, const CounterEntry& b) {
    const int t = memcmp(a.tag, b.tag, TAG_LEN);
    if (t != 0) return t < 0;
    return memcmp(a.who, b.who, HASH_LEN) < 0;
  }
  const CounterEntry* find(const uint8_t tag[TAG_LEN], const uint8_t who[HASH_LEN]) const {
    for (size_t i = 0; i < cap_; i++)
      if (e_[i].used && memcmp(e_[i].tag, tag, TAG_LEN) == 0 && memcmp(e_[i].who, who, HASH_LEN) == 0) return &e_[i];
    return nullptr;
  }
  CounterEntry* e_ = nullptr;
  size_t cap_ = 0;
};

class Floor {
 public:
  // `storage` holds `capacity` records (at most FLOOR_MAX_SPURTS); `counters`
  // may be shared by every floor of a node. False if capacity is out of range.
  bool init(Role role, const uint8_t channel_tag[TAG_LEN], Counters* counters, SpurtRec* storage, size_t capacity,
            uint8_t talk_limit_s = TALK_LIMIT_S) {
    if (capacity == 0 || capacity > FLOOR_MAX_SPURTS || !counters || !storage) return false;
    role_ = role;
    memcpy(tag_, channel_tag, TAG_LEN);
    counters_ = counters;
    recs_ = storage;
    cap_ = capacity;
    talk_limit_s_ = talk_limit_s;
    for (size_t i = 0; i < cap_; i++) recs_[i].state = SpurtState::Free;
    has_tick_ = false;
    last_tick_ = 0;
    settle_ms_ = 0;
    return true;
  }

  const uint8_t* channel_tag() const { return tag_; }

  // --- lookups ----------------------------------------------------------------------

  SpurtRec* find(const uint8_t who[HASH_LEN], uint32_t spurt) {
    for (size_t i = 0; i < cap_; i++) {
      SpurtRec& r = recs_[i];
      if (r.state != SpurtState::Free && r.spurt == spurt && memcmp(r.who, who, HASH_LEN) == 0) return &r;
    }
    return nullptr;
  }

  // The record a clear header (talker tag, spurt) names: live first, then lost,
  // yielded, pending, known (then ended, if asked); ties by the claim order.
  SpurtRec* find_tag(const uint8_t tag[TAG_LEN], uint32_t spurt, bool ended = false) {
    SpurtRec* best = nullptr;
    for (size_t i = 0; i < cap_; i++) {
      SpurtRec* r = &recs_[i];
      if (r->state == SpurtState::Free || r->spurt != spurt || memcmp(r->tag, tag, TAG_LEN) != 0) continue;
      if (!ended && r->state == SpurtState::Ended) continue;
      if (!best) {
        best = r;
        continue;
      }
      const int a = floor_detail::rank(r->state), b = floor_detail::rank(best->state);
      if (a < b || (a == b && floor_detail::before(r, best))) best = r;
    }
    return best;
  }

  // Records in the claim order, optionally only one state. Returns the count.
  size_t sorted(SpurtRec** out, SpurtState only = SpurtState::Free) {
    size_t n = 0;
    for (size_t i = 0; i < cap_; i++) {
      SpurtRec* r = &recs_[i];
      if (r->state == SpurtState::Free || (only != SpurtState::Free && r->state != only)) continue;
      size_t j = n++;
      while (j > 0 && floor_detail::before(r, out[j - 1])) {
        out[j] = out[j - 1];
        j--;
      }
      out[j] = r;
    }
    return n;
  }

  SpurtRec* holder() {
    SpurtRec* best = nullptr;
    for (size_t i = 0; i < cap_; i++) {
      SpurtRec* r = &recs_[i];
      if (r->state == SpurtState::Live && (!best || floor_detail::before(r, best))) best = r;
    }
    return best;
  }

  SpurtRec* own() {
    SpurtRec* best = nullptr;
    for (size_t i = 0; i < cap_; i++) {
      SpurtRec* r = &recs_[i];
      if (r->state != SpurtState::Free && r->own && r->state != SpurtState::Ended && (!best || floor_detail::before(r, best)))
        best = r;
    }
    return best;
  }

  bool empty() const {
    for (size_t i = 0; i < cap_; i++)
      if (recs_[i].state != SpurtState::Free && recs_[i].state != SpurtState::Ended) return false;
    return true;
  }

  // --- events -------------------------------------------------------------------------

  // A verified CLAIM, from this relay's client (c.local) or from elsewhere.
  void claim(int64_t now, const FloorClaim& c, int64_t settle_ms, FloorSink& out) {
    set_settle(settle_ms);
    uint32_t last = 0;
    const bool has_last = counters_->last(tag_, c.who, &last);
    SpurtRec* rec = find(c.who, c.spurt);
    if (rec || (has_last && c.spurt <= last)) {
      if (rec && role_ == Role::Relay && rec->local && c.local) retry(now, rec, out);
      return;
    }
    supersede(now, c.who, false, out);
    rec = insert(c, now, false);
    if (!rec) return;
    counters_->advance(now, tag_, c.who, c.spurt);
    const SpurtRec* blocker = blocks(*rec);
    if (role_ == Role::Relay && rec->local) {
      if (blocker) {
        rec->state = SpurtState::Known;
        emit(out, Act::Busy, rec, blocker);
      } else {
        rec->state = SpurtState::Pending;
        rec->hold_until = now + settle_ms_;
        emit(out, Act::Pending, rec);
      }
    } else if (role_ == Role::Relay && !blocker) {
      rec->state = SpurtState::Pending;
      rec->hold_until = now + REMOTE_HOLD_MS;
      emit(out, Act::Pending, rec);
    } else {
      rec->state = SpurtState::Known;
      emit(out, Act::Known, rec);
    }
  }

  // A TALKING: evidence the spurt was granted somewhere. Returns its record.
  SpurtRec* talking(int64_t now, const uint8_t tag[TAG_LEN], uint32_t spurt, uint8_t profile, uint8_t limit_s,
                    FloorSink& out) {
    SpurtRec* rec = find_tag(tag, spurt);
    if (!rec || rec->own || (role_ == Role::Relay && rec->local)) return rec;
    rec->profile = profile;
    rec->limit_s = limit_s;
    if (role_ == Role::Phone) {
      // The phone's relay holds nothing live that orders before this one.
      SpurtRec* ls[FLOOR_MAX_SPURTS];
      const size_t n = sorted(ls, SpurtState::Live);
      for (size_t i = 0; i < n; i++) {
        if (ls[i] == rec || ls[i]->own || !floor_detail::before(ls[i], rec)) continue;
        ls[i]->state = SpurtState::Lost;
        ls[i]->lost_at = now;
        emit(out, Act::Lost, ls[i]);
      }
      if (rec->state == SpurtState::Lost || rec->state == SpurtState::Yielded) {
        rec->state = SpurtState::Live;
        rec->last_heard = now;
        rec->quiet = false;
        emit(out, Act::Resumed, rec);
        yield_rule(now, out);
      }
    }
    if (rec->state == SpurtState::Pending || rec->state == SpurtState::Known) make_live(now, rec, out);
    return rec;
  }

  // A FRAME's clear header. Returns its record; *forward says whether it goes on.
  SpurtRec* frame(int64_t now, int64_t rx, const uint8_t tag[TAG_LEN], uint32_t spurt, uint16_t seq, bool* forward,
                  FloorSink& out) {
    *forward = false;
    SpurtRec* rec = find_tag(tag, spurt);
    if (!rec || rec->own) return rec;
    if (rec->state == SpurtState::Pending || rec->state == SpurtState::Known) {
      if (role_ == Role::Relay && rec->local) return rec;
      if (int32_t(seq) > rec->last_seq) rec->last_seq = seq;
      make_live(now, rec, out);
    } else if (rec->state == SpurtState::Lost || rec->state == SpurtState::Yielded) {
      // A lost spurt comes back only on a frame received within the resume
      // window: later ones are a backlog. A yielded one's talker was still sending.
      // Inside the window, only a frame on its spurt's schedule brings a lost one
      // back (v1.2): a backlog never does, however soon it arrives.
      const bool windowed = rec->state == SpurtState::Lost || rec->lost_window;
      const bool late = windowed ? rx - rec->lost_at >= RESUME_WINDOW_MS : now - rec->lost_at >= RESUME_MS;
      if (int32_t(seq) <= rec->last_seq || late || (windowed && floor_detail::behind(*rec, seq, rx))) return rec;
      rec->last_seq = seq;
      const SpurtRec* w = holder();
      if (w && floor_detail::before(w, rec)) {
        if (rec->state == SpurtState::Lost) {
          // Yielded now, but still a lost spurt: its window runs from the loss.
          const int64_t lost_at = rec->lost_at;
          yield_one(now, rec, w, floor_detail::can_preempt(*w, *rec) ? Why::Preempted : Why::Collision, out);
          rec->lost_at = lost_at;
          rec->lost_window = true;
        }
        return rec;
      }
      rec->state = SpurtState::Live;
      rec->last_heard = now;
      rec->quiet = false;
      emit(out, Act::Resumed, rec);
      yield_rule(now, out);
    }
    if (rec->state != SpurtState::Live) return rec;
    if (rx > rec->last_heard) rec->last_heard = rx;
    if (int32_t(seq) > rec->last_seq) rec->last_seq = seq;
    const int64_t fm = floor_detail::frame_ms(rec->profile);
    if (fm != 0) {
      const int64_t offset = rx - int64_t(seq) * fm;
      if (!rec->timed || offset < rec->best_offset) rec->best_offset = offset;
      rec->timed = true;
    }
    if (rec->quiet) {
      rec->quiet = false;
      emit(out, Act::Unquiet, rec);
    }
    *forward = true;
    return rec;
  }

  // A verified RELEASE, keyed on its signing key. True when it ended a spurt.
  // One that matches no record leaves a tombstone only in free or ended room,
  // advances no counter, and is not new.
  bool release(int64_t now, const uint8_t who[HASH_LEN], uint32_t spurt, const uint8_t tag[TAG_LEN], FloorSink& out) {
    SpurtRec* rec = find(who, spurt);
    if (rec) {
      if (rec->state == SpurtState::Ended) return false;
      end_rec(now, rec, Why::Released, out);
      return true;
    }
    uint32_t last = 0;
    if (counters_->last(tag_, who, &last) && spurt < last) return false;
    FloorClaim c;
    memset(&c, 0, sizeof(c));
    memcpy(c.who, who, HASH_LEN);
    memcpy(c.tag, tag, TAG_LEN);
    c.spurt = spurt;
    c.tier = 4;
    c.src = -1;
    rec = insert(c, now, false, true);
    if (rec) end_rec(now, rec, Why::Released, out);
    return false;
  }

  // Judge every timer, after the host has drained its ingress.
  void tick(int64_t now, int64_t settle_ms, FloorSink& out) {
    set_settle(settle_ms);
    const int64_t gap = has_tick_ ? now - last_tick_ : 0;
    has_tick_ = true;
    last_tick_ = now;
    if (gap > QUIET_MS) {
      // A pass longer than the quiet timer is not silence.
      for (size_t i = 0; i < cap_; i++) {
        SpurtRec& r = recs_[i];
        if (r.state == SpurtState::Live) r.last_heard = (r.last_heard + gap < now) ? r.last_heard + gap : now;
      }
    }
    SpurtRec* rs[FLOOR_MAX_SPURTS];
    const size_t n = sorted(rs);
    for (size_t i = 0; i < n; i++) {
      SpurtRec* r = rs[i];
      if (r->state == SpurtState::Live && r->own) {
        if (now - r->live_since >= int64_t(r->limit_s) * 1000) end_rec(now, r, Why::Limit, out);
      } else if (r->state == SpurtState::Live) {
        if (now - r->live_since >= int64_t(r->limit_s) * 1000 + LIMIT_GRACE_MS) {
          end_rec(now, r, Why::Limit, out);
          continue;
        }
        const int64_t silence = now - r->last_heard;
        if (silence >= r->lost_ms) {
          r->state = SpurtState::Lost;
          r->lost_at = now;
          emit(out, Act::Lost, r);
        } else if (silence >= QUIET_MS && !r->quiet) {
          r->quiet = true;
          emit(out, Act::Quiet, r);
        }
      } else if (r->state == SpurtState::Lost) {
        if (now - r->lost_at >= RESUME_WINDOW_MS) end_rec(now, r, Why::Lost, out);  // dead: late frames never move it
      } else if (r->state == SpurtState::Yielded) {
        if (now - r->lost_at >= (r->lost_window ? RESUME_WINDOW_MS : RESUME_MS)) end_rec(now, r, Why::Yielded, out);
      } else if (r->state == SpurtState::Pending && r->own) {
        if (now >= r->retry_at) {
          if (r->sends < CLAIM_SENDS) {
            r->sends++;
            r->retry_at = now + CLAIM_RETRY_MS;
            emit(out, Act::Retry, r);
          } else {
            end_rec(now, r, Why::GaveUp, out);
          }
        }
      } else if (r->state == SpurtState::Pending && !r->local) {
        if (now >= r->hold_until) r->state = SpurtState::Known;
      }
    }
    if (role_ == Role::Relay) {
      SpurtRec* ps[FLOOR_MAX_SPURTS];
      const size_t np = sorted(ps, SpurtState::Pending);
      for (size_t i = 0; i < np; i++) {
        SpurtRec* r = ps[i];
        if (!r->local || r->state != SpurtState::Pending || now < r->hold_until) continue;
        bool waits = false;
        for (size_t k = 0; k < cap_; k++)
          if (recs_[k].state == SpurtState::Pending && floor_detail::before(&recs_[k], r)) waits = true;
        if (waits) continue;
        const SpurtRec* blocker = blocks(*r);
        if (blocker) {
          r->state = SpurtState::Known;
          emit(out, Act::Busy, r, blocker);
          continue;
        }
        SpurtRec* ls[FLOOR_MAX_SPURTS];
        const size_t nl = sorted(ls, SpurtState::Live);
        for (size_t k = 0; k < nl; k++) yield_one(now, ls[k], r, Why::Preempted, out);
        r->state = SpurtState::Live;
        r->live_since = now;
        r->last_heard = now;
        emit(out, Act::Grant, r);
      }
    }
    for (size_t i = 0; i < cap_; i++) {
      SpurtRec& r = recs_[i];
      if (r.state == SpurtState::Ended && now - r.ended_at >= TOMBSTONE_MS) r.state = SpurtState::Free;
    }
  }

  // --- the phone's own claim ------------------------------------------------------------

  // The phone keys up: its own signed CLAIM, which the host sends now.
  void key(int64_t now, const FloorClaim& c, FloorSink& out) {
    uint32_t last = 0;
    if (counters_->last(tag_, c.who, &last) && c.spurt <= last) return;  // a spurt id is never reused
    supersede(now, c.who, true, out);
    SpurtRec* rec = insert(c, now, true);
    if (!rec) return;
    counters_->advance(now, tag_, c.who, c.spurt);
    rec->state = SpurtState::Pending;
    rec->sends = 1;
    rec->retry_at = now + CLAIM_RETRY_MS;
    emit(out, Act::Pending, rec);
  }

  // A GRANT: taken only for the phone's own outstanding claim.
  void granted(int64_t now, const uint8_t tag[TAG_LEN], uint32_t spurt, uint8_t profile, uint8_t limit_s,
               FloorSink& out) {
    SpurtRec* r = own_pending(tag, spurt, false);
    if (!r) return;
    r->state = SpurtState::Live;
    r->live_since = now;
    r->profile = profile;
    r->limit_s = limit_s;
    emit(out, Act::Grant, r);
    yield_rule(now, out);
  }

  // A BUSY for the phone's own outstanding claim; holder_tag null if absent.
  void busy(int64_t now, const uint8_t tag[TAG_LEN], uint32_t spurt, const uint8_t* holder_tag, uint32_t holder_spurt,
            bool rate_limited, FloorSink& out) {
    SpurtRec* r = own_pending(tag, spurt, false);
    if (!r) return;
    const SpurtRec* h = holder_tag ? named(holder_tag, holder_spurt) : nullptr;
    if (!h && !(rate_limited && !holder_tag)) return;
    r->state = SpurtState::Ended;
    r->ended_at = now;
    emit(out, Act::Busy, r, h);
  }

  // A YIELD for the phone's own claim or spurt, naming a claim it holds.
  void yielded(int64_t now, const uint8_t tag[TAG_LEN], uint32_t spurt, const uint8_t winner_tag[TAG_LEN],
               uint32_t winner_spurt, bool preempted, FloorSink& out) {
    SpurtRec* r = own_pending(tag, spurt, true);
    const SpurtRec* w = named(winner_tag, winner_spurt);
    if (!r || !w) return;
    r->state = SpurtState::Ended;
    r->ended_at = now;
    emit(out, Act::Yield, r, w, preempted ? Why::Preempted : Why::Collision);
  }

  // The user released the key (after the release tail).
  void end(int64_t now, FloorSink& out) {
    SpurtRec* r = own();
    if (r) end_rec(now, r, Why::Released, out);
  }

 private:
  void set_settle(int64_t settle_ms) {
    settle_ms_ = settle_ms < 0 ? 0 : (settle_ms > SETTLE_CAP_MS ? SETTLE_CAP_MS : settle_ms);
  }

  static void emit(FloorSink& out, Act a, SpurtRec* rec, const SpurtRec* other = nullptr, Why why = Why::None) {
    FloorAction x;
    x.act = a;
    x.rec = rec;
    x.other = other;
    x.why = why;
    out.floor_action(x);
  }

  void end_rec(int64_t now, SpurtRec* r, Why why, FloorSink& out) {
    r->state = SpurtState::Ended;
    r->ended_at = now;
    emit(out, Act::Ended, r, nullptr, why);
  }

  void supersede(int64_t now, const uint8_t who[HASH_LEN], bool own_too, FloorSink& out) {
    SpurtRec* rs[FLOOR_MAX_SPURTS];
    const size_t n = sorted(rs);
    for (size_t i = 0; i < n; i++) {
      SpurtRec* r = rs[i];
      if (memcmp(r->who, who, HASH_LEN) == 0 && r->state != SpurtState::Ended && (own_too || !r->own))
        end_rec(now, r, Why::Superseded, out);
    }
  }

  // A slot for a new record: a free one, else the oldest ended, then known,
  // then yielded, then lost (ties by the order); never live or pending.
  SpurtRec* slot(bool tombstone) {
    for (size_t i = 0; i < cap_; i++)
      if (recs_[i].state == SpurtState::Free) return &recs_[i];
    const SpurtState classes[4] = {SpurtState::Ended, SpurtState::Known, SpurtState::Yielded, SpurtState::Lost};
    for (int k = 0; k < (tombstone ? 1 : 4); k++) {
      SpurtRec* victim = nullptr;
      for (size_t i = 0; i < cap_; i++) {
        SpurtRec* r = &recs_[i];
        if (r->state != classes[k] || (classes[k] != SpurtState::Ended && r->own)) continue;
        const int64_t t = classes[k] == SpurtState::Ended ? r->ended_at
                          : classes[k] == SpurtState::Known ? r->seen_at : r->lost_at;
        const int64_t tv = !victim ? 0
                           : classes[k] == SpurtState::Ended ? victim->ended_at
                           : classes[k] == SpurtState::Known ? victim->seen_at : victim->lost_at;
        if (!victim || t < tv || (t == tv && floor_detail::before(r, victim))) victim = r;
      }
      if (victim) return victim;
    }
    return nullptr;
  }

  SpurtRec* insert(const FloorClaim& c, int64_t now, bool own_rec, bool tombstone = false) {
    SpurtRec* r = slot(tombstone);
    if (!r) return nullptr;
    memset(r, 0, sizeof(*r));
    memcpy(r->who, c.who, HASH_LEN);
    memcpy(r->tag, c.tag, TAG_LEN);
    r->spurt = c.spurt;
    memcpy(r->nonce, c.nonce, NONCE_LEN);
    r->tier = c.tier;
    r->emergency = c.emergency;
    r->verified = c.verified;
    r->local = c.local;
    r->own = own_rec;
    r->src = c.src;
    floor_detail::order_key(c.who, c.spurt, c.nonce, c.tier, c.emergency, c.verified, r->order);
    r->state = SpurtState::Known;
    r->seen_at = now;
    r->hold_until = now;
    r->live_since = NEVER;
    r->last_heard = NEVER;
    r->last_seq = -1;
    r->lost_at = NEVER;
    r->lost_window = false;
    r->ended_at = NEVER;
    r->lost_ms = floor_detail::lost_ms_for(c.stall_ms);
    r->limit_s = talk_limit_s_;
    r->retry_at = NEVER;
    r->hb_next = NEVER;
    r->nudge_at = NEVER;
    r->best_offset = 0;
    r->last_arrival = NEVER;
    r->timed = false;
    r->late_run = 0;
    if (c.blob && c.blob_len <= CLAIM_LEN) {
      memcpy(r->blob, c.blob, c.blob_len);
      r->blob_len = uint8_t(c.blob_len);
    }
    return r;
  }

  void retry(int64_t now, SpurtRec* rec, FloorSink& out) {
    if (rec->state == SpurtState::Live) {
      emit(out, Act::Regrant, rec);
    } else if (rec->state == SpurtState::Known) {
      const SpurtRec* blocker = blocks(*rec);
      if (blocker) {
        emit(out, Act::Busy, rec, blocker);
      } else {
        rec->state = SpurtState::Pending;
        rec->hold_until = now + settle_ms_;
        emit(out, Act::Pending, rec);
      }
    }
  }

  void make_live(int64_t now, SpurtRec* rec, FloorSink& out) {
    rec->state = SpurtState::Live;
    rec->live_since = now;
    rec->last_heard = now;
    rec->quiet = false;
    emit(out, Act::Live, rec);
    yield_rule(now, out);
  }

  void yield_one(int64_t now, SpurtRec* loser, const SpurtRec* w, Why why, FloorSink& out) {
    if (loser->own) {
      loser->state = SpurtState::Ended;
      loser->ended_at = now;
    } else {
      loser->state = SpurtState::Yielded;
      loser->lost_at = now;
      loser->lost_window = false;
    }
    emit(out, Act::Yield, loser, w, why);
  }

  void yield_rule(int64_t now, FloorSink& out) {
    SpurtRec* ls[FLOOR_MAX_SPURTS];
    const size_t n = sorted(ls, SpurtState::Live);
    if (n < 2) return;
    const SpurtRec* w = ls[0];
    for (size_t i = 1; i < n; i++)
      yield_one(now, ls[i], w, floor_detail::can_preempt(*w, *ls[i]) ? Why::Preempted : Why::Collision, out);
  }

  // The best live spurt, if any live spurt cannot be cut by c.
  const SpurtRec* blocks(const SpurtRec& c) {
    SpurtRec* ls[FLOOR_MAX_SPURTS];
    const size_t n = sorted(ls, SpurtState::Live);
    for (size_t i = 0; i < n; i++)
      if (!floor_detail::can_preempt(c, *ls[i])) return ls[0];
    return nullptr;
  }

  SpurtRec* own_pending(const uint8_t tag[TAG_LEN], uint32_t spurt, bool live_too) {
    SpurtRec* r = own();
    if (!r || r->spurt != spurt || memcmp(r->tag, tag, TAG_LEN) != 0) return nullptr;
    if (r->state == SpurtState::Pending || (live_too && r->state == SpurtState::Live)) return r;
    return nullptr;
  }

  const SpurtRec* named(const uint8_t tag[TAG_LEN], uint32_t spurt) {
    SpurtRec* r = find_tag(tag, spurt);
    return (r && !r->own) ? r : nullptr;
  }

  Role role_ = Role::Relay;
  uint8_t tag_[TAG_LEN] = {0};
  Counters* counters_ = nullptr;
  SpurtRec* recs_ = nullptr;
  size_t cap_ = 0;
  uint8_t talk_limit_s_ = TALK_LIMIT_S;
  bool has_tick_ = false;
  int64_t last_tick_ = 0;
  int64_t settle_ms_ = 0;
};

}  // namespace lxpt

#endif  // LXPT_FLOOR_HPP
