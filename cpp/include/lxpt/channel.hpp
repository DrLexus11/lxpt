// lxpt -- what needs the channel key or an identity: channel ids, channel and
// member tags, the per-spurt keys, sealing and opening FRAMEs and NOTICEs,
// and CLAIM and RELEASE signatures. Header-only, C++11, no heap, no
// exceptions. The derivations are spec/wire-v1.md section 3.
//
// A relay needs only verify_claim and verify_release from this file: it holds
// no channel keys and forwards ciphertext.
//
// SPDX-License-Identifier: Apache-2.0

#ifndef LXPT_CHANNEL_HPP
#define LXPT_CHANNEL_HPP

#include "crypto.hpp"
#include "wire.hpp"

namespace lxpt {

static const size_t KEY_LEN = 32;
static const size_t CHANNEL_ID_LEN = 8;
static const size_t ROOM_MAX_LEN = 255;

namespace channel_detail {
static const char CHANNEL_ID_LABEL[] = "lxpt/ch/v1";
static const char HUBLESS_ID_LABEL[] = "lxpt/hubless/v1";
static const char TAG_LABEL[] = "lxpt/v1/tag";
static const char MEMBER_LABEL[] = "lxpt/v1/member";
static const char NOTICE_KEY_LABEL[] = "lxpt/v1/notice-key";
static const char NOTICE_MAC_LABEL[] = "lxpt/v1/notice-mac";
static const char NOTICE_TALKER_LABEL[] = "lxpt/v1/notice-talker";
static const char SPURT_LABEL[] = "lxpt/v1/spurt";

inline const uint8_t* u8(const char* s) { return reinterpret_cast<const uint8_t*>(s); }

template <size_t N>
inline void hmac_label(crypto::HmacSha256& h, const uint8_t* key, size_t key_len, const char (&label)[N]) {
  crypto::hmac_sha256_init(h, key, key_len);
  crypto::hmac_sha256_update(h, u8(label), N - 1);
}

// Strict UTF-8: no overlong forms, no surrogates, nothing past U+10FFFF.
inline bool utf8_valid(const uint8_t* b, size_t n) {
  size_t i = 0;
  while (i < n) {
    const uint8_t c = b[i];
    if (c < 0x80) {
      i++;
      continue;
    }
    size_t need;
    uint8_t lo = 0x80, hi = 0xbf;
    if (c >= 0xc2 && c <= 0xdf) need = 1;
    else if (c == 0xe0) { need = 2; lo = 0xa0; }
    else if ((c >= 0xe1 && c <= 0xec) || c == 0xee || c == 0xef) need = 2;
    else if (c == 0xed) { need = 2; hi = 0x9f; }
    else if (c == 0xf0) { need = 3; lo = 0x90; }
    else if (c >= 0xf1 && c <= 0xf3) need = 3;
    else if (c == 0xf4) { need = 3; hi = 0x8f; }
    else return false;
    if (i + need >= n) return false;
    if (b[i + 1] < lo || b[i + 1] > hi) return false;
    for (size_t k = 2; k <= need; k++)
      if (b[i + k] < 0x80 || b[i + k] > 0xbf) return false;
    i += need + 1;
  }
  return true;
}

template <size_t N>
inline Error id(const char (&label)[N], const uint8_t hash[16], const uint8_t* name, size_t len, uint8_t out[8]);
}  // namespace channel_detail

// A room name exactly as its hub returns it: lxpt never re-normalises (hubs
// and clients disagree on case folding, whitespace and '#'). It must be 1 to
// 255 bytes of strict UTF-8, else Field.
inline Error check_room_name(const uint8_t* name, size_t len) {
  if (len < 1 || len > ROOM_MAX_LEN || !channel_detail::utf8_valid(name, len)) return Error::Field;
  return Error::Ok;
}

template <size_t N>
inline Error channel_detail::id(const char (&label)[N], const uint8_t hash[16], const uint8_t* name, size_t len,
                                uint8_t out[8]) {
  const Error e = check_room_name(name, len);
  if (e != Error::Ok) return e;
  crypto::Sha256 c;
  crypto::sha256_init(c);
  crypto::sha256_update(c, u8(label), N - 1);
  crypto::sha256_update(c, hash, 16);
  crypto::sha256_update(c, name, len);
  uint8_t digest[32];
  crypto::sha256_final(c, digest);
  memcpy(out, digest, CHANNEL_ID_LEN);
  return Error::Ok;
}

// SHA-256("lxpt/ch/v1" || hub hash || the hub's canonical room name)[:8].
inline Error channel_id(const uint8_t hub_hash[16], const uint8_t* room, size_t len, uint8_t out[8]) {
  return channel_detail::id(channel_detail::CHANNEL_ID_LABEL, hub_hash, room, len, out);
}

// A phone-only channel: SHA-256("lxpt/hubless/v1" || creator || the name as created)[:8].
inline Error hubless_channel_id(const uint8_t creator_hash[16], const uint8_t* name, size_t len, uint8_t out[8]) {
  return channel_detail::id(channel_detail::HUBLESS_ID_LABEL, creator_hash, name, len, out);
}

// A Reticulum identity hash: SHA-256 of the 64-byte public key, first 16 bytes.
inline void identity_hash(const uint8_t public_key[64], uint8_t out[16]) {
  uint8_t d[32];
  crypto::sha256(public_key, 64, d);
  memcpy(out, d, 16);
}

struct ChannelKeys {
  uint8_t k_epoch[32];
  uint8_t channel_id[8];
  uint8_t channel_tag[4];
  uint8_t notice_key[32];
};

struct SpurtKeys {
  uint8_t enc_key[32];
  uint8_t mac_key[32];
};

inline void channel_keys(const uint8_t k_epoch[32], const uint8_t channel_id_[8], ChannelKeys* k) {
  using namespace channel_detail;
  memcpy(k->k_epoch, k_epoch, 32);
  memcpy(k->channel_id, channel_id_, 8);
  crypto::HmacSha256 h;
  uint8_t d[32];
  hmac_label(h, k_epoch, 32, TAG_LABEL);
  crypto::hmac_sha256_update(h, channel_id_, 8);
  crypto::hmac_sha256_final(h, d);
  memcpy(k->channel_tag, d, 4);
  hmac_label(h, k_epoch, 32, NOTICE_KEY_LABEL);
  crypto::hmac_sha256_update(h, channel_id_, 8);
  crypto::hmac_sha256_final(h, k->notice_key);
}

inline void member_tag(const ChannelKeys& k, const uint8_t identity_hash_[16], uint8_t out[4]) {
  using namespace channel_detail;
  crypto::HmacSha256 h;
  uint8_t d[32];
  hmac_label(h, k.k_epoch, 32, MEMBER_LABEL);
  crypto::hmac_sha256_update(h, k.channel_id, 8);
  crypto::hmac_sha256_update(h, identity_hash_, 16);
  crypto::hmac_sha256_final(h, d);
  memcpy(out, d, 4);
}

// HKDF-SHA256(ikm = k_epoch, salt = nonce, info = "lxpt/v1/spurt" || channel id
// || talker hash || spurt, 64 bytes): the AES key, then the HMAC key.
inline Error spurt_keys(const ChannelKeys& k, const uint8_t talker_hash[16], uint32_t spurt, const uint8_t nonce[16],
                        SpurtKeys* out) {
  using namespace channel_detail;
  if (spurt == 0) return Error::Field;
  const size_t label_len = sizeof(SPURT_LABEL) - 1;
  uint8_t info[sizeof(SPURT_LABEL) - 1 + 8 + 16 + 4];
  memcpy(info, SPURT_LABEL, label_len);
  memcpy(info + label_len, k.channel_id, 8);
  memcpy(info + label_len + 8, talker_hash, 16);
  wire_detail::put32(info + label_len + 24, spurt);
  uint8_t okm[64];
  crypto::hkdf_sha256(k.k_epoch, 32, nonce, 16, info, sizeof(info), okm, 64);
  memcpy(out->enc_key, okm, 32);
  memcpy(out->mac_key, okm + 32, 32);
  return Error::Ok;
}

namespace channel_detail {
inline void frame_iv(uint16_t seq, uint8_t iv[16]) {
  memset(iv, 0, 16);
  wire_detail::put16(iv, seq);
}
}  // namespace channel_detail

// Encrypts a codec frame (AES-256-CTR from seq || 14 zero bytes) and MACs
// header and ciphertext (HMAC-SHA256, first 8 bytes). `plain` may not overlap
// `out`.
inline Error seal_frame(const SpurtKeys& keys, const uint8_t channel_tag[4], const uint8_t talker_tag[4],
                        uint32_t spurt, uint16_t seq, const uint8_t* plain, size_t plain_len, uint8_t* out,
                        size_t cap, size_t* written) {
  Frame f;
  memcpy(f.channel_tag, channel_tag, 4);
  memcpy(f.talker_tag, talker_tag, 4);
  f.spurt = spurt;
  f.seq = seq;
  f.payload = plain;
  f.payload_len = plain_len;
  memset(f.mac, 0, MAC_LEN);
  const Error e = encode(f, out, cap, written);
  if (e != Error::Ok) return e;
  uint8_t iv[16];
  channel_detail::frame_iv(seq, iv);
  crypto::aes256_ctr(keys.enc_key, iv, out + FRAME_HEADER_LEN, plain_len, out + FRAME_HEADER_LEN);
  uint8_t mac[32];
  crypto::hmac_sha256(keys.mac_key, 32, out, FRAME_HEADER_LEN + plain_len, mac);
  memcpy(out + FRAME_HEADER_LEN + plain_len, mac, MAC_LEN);
  return Error::Ok;
}

// Checks the MAC, then decrypts into `plain` (at least the payload's length).
inline Error open_frame(const SpurtKeys& keys, const uint8_t* in, size_t len, Frame* f, uint8_t* plain, size_t cap,
                        size_t* plain_len) {
  Error e = decode(in, len, f);
  if (e != Error::Ok) return e;
  uint8_t mac[32];
  crypto::hmac_sha256(keys.mac_key, 32, in, len - MAC_LEN, mac);
  if (!crypto::equal(mac, f->mac, MAC_LEN)) return Error::Mac;
  if (cap < f->payload_len) return Error::Buffer;
  uint8_t iv[16];
  channel_detail::frame_iv(f->seq, iv);
  crypto::aes256_ctr(keys.enc_key, iv, f->payload, f->payload_len, plain);
  *plain_len = f->payload_len;
  return Error::Ok;
}

namespace channel_detail {
// The MAC leaves the hop limit (low nibble of byte 1) out, so a later hop can
// lower it without the key.
inline void notice_mac(const uint8_t key[32], const uint8_t plain[NOTICE_LEN], uint8_t out[8]) {
  uint8_t covered[13];
  memcpy(covered, plain, 13);
  covered[1] &= 0xF0;
  crypto::HmacSha256 h;
  hmac_label(h, key, 32, NOTICE_MAC_LABEL);
  crypto::hmac_sha256_update(h, covered, 13);
  uint8_t d[32];
  crypto::hmac_sha256_final(h, d);
  memcpy(out, d, 8);
}

inline void talker_pad(const uint8_t key[32], const uint8_t mac[8], uint8_t pad[4]) {
  crypto::HmacSha256 h;
  hmac_label(h, key, 32, NOTICE_TALKER_LABEL);
  crypto::hmac_sha256_update(h, mac, 8);
  uint8_t d[32];
  crypto::hmac_sha256_final(h, d);
  memcpy(pad, d, 4);
}
}  // namespace channel_detail

// A NOTICE with its MAC, the talker prefix (first four bytes of the talker's
// identity hash) encrypted with a pad derived from that MAC.
inline Error seal_notice(const uint8_t notice_key[32], NoticeKind kind, uint8_t hop_limit,
                         const uint8_t channel_tag[4], const uint8_t talker_prefix[4], uint16_t spurt16,
                         uint8_t talk_limit_s, uint8_t out[NOTICE_LEN]) {
  Notice n;
  n.kind = kind;
  n.hop_limit = hop_limit;
  memcpy(n.channel_tag, channel_tag, 4);
  memcpy(n.talker, talker_prefix, 4);
  n.spurt16 = spurt16;
  n.talk_limit_s = talk_limit_s;
  memset(n.mac, 0, 8);
  const Error e = encode(n, out);
  if (e != Error::Ok) return e;
  uint8_t mac[8], pad[4];
  channel_detail::notice_mac(notice_key, out, mac);
  channel_detail::talker_pad(notice_key, mac, pad);
  for (int i = 0; i < 4; i++) out[6 + i] = uint8_t(talker_prefix[i] ^ pad[i]);
  memcpy(out + 13, mac, 8);
  return Error::Ok;
}

// The notice with its talker prefix decrypted, or Mac.
inline Error open_notice(const uint8_t notice_key[32], const uint8_t* in, size_t len, Notice* n,
                         uint8_t talker_prefix[4]) {
  const Error e = decode(in, len, n);
  if (e != Error::Ok) return e;
  uint8_t pad[4], plain[NOTICE_LEN], mac[8];
  channel_detail::talker_pad(notice_key, n->mac, pad);
  memcpy(plain, in, NOTICE_LEN);
  for (int i = 0; i < 4; i++) plain[6 + i] = uint8_t(in[6 + i] ^ pad[i]);
  channel_detail::notice_mac(notice_key, plain, mac);
  if (!crypto::equal(mac, n->mac, 8)) return Error::Mac;
  memcpy(talker_prefix, plain + 6, 4);
  return Error::Ok;
}

namespace channel_detail {
inline bool signer_matches(const uint8_t public_key[64], const uint8_t seed[32]) {
  uint8_t pk[32];
  crypto::ed25519_public_key(seed, pk);
  return memcmp(pk, public_key + 32, 32) == 0;
}
}  // namespace channel_detail

// Signs a CLAIM with the Ed25519 seed whose public key is the second half of
// m.public_key; m.signature is ignored. Field if the seed is not that key's.
// For tools and tests. A host that keeps its key in its own identity stack
// encodes the CLAIM, signs CLAIM_DOMAIN || the claim_signed_part() bytes
// itself, and writes the signature into the last 64 bytes.
inline Error sign_claim(const Claim& m, const uint8_t seed[32], uint8_t out[CLAIM_LEN]) {
  if (!channel_detail::signer_matches(m.public_key, seed)) return Error::Field;
  size_t n = 0;
  const Error e = encode(m, out, CLAIM_LEN, &n);
  if (e != Error::Ok) return e;
  crypto::ed25519_sign2(out + CLAIM_SIGNED_LEN, channel_detail::u8(CLAIM_DOMAIN), CLAIM_DOMAIN_LEN, out,
                        CLAIM_SIGNED_LEN, seed);
  return Error::Ok;
}

// The Ed25519 verifier the signature checks use. The default is crypto.hpp's.
// A build may pass its own (a board's library Ed25519, say) once it gives the
// fixture's crypto.ed25519_verify results, small-order and non-canonical
// cases included: that is what keeps relays and phones agreeing.
typedef bool (*Ed25519Verify)(const uint8_t sig[64], const uint8_t* m1, size_t n1, const uint8_t* m2, size_t n2,
                              const uint8_t pk[32]);

// Verification costs a few hundred milliseconds on a microcontroller (spec
// section 8): rate-limit before calling it, and call it outside poll().
inline Error verify_claim(const uint8_t* in, size_t len, Claim* m, Ed25519Verify verify = crypto::ed25519_verify2) {
  const Error e = decode(in, len, m);
  if (e != Error::Ok) return e;
  return verify(m->signature, channel_detail::u8(CLAIM_DOMAIN), CLAIM_DOMAIN_LEN, in, CLAIM_SIGNED_LEN,
                m->public_key + 32)
             ? Error::Ok
             : Error::Signature;
}

inline Error sign_release(const Release& m, const uint8_t seed[32], uint8_t out[RELEASE_LEN]) {
  if (!channel_detail::signer_matches(m.public_key, seed)) return Error::Field;
  size_t n = 0;
  const Error e = encode(m, out, RELEASE_LEN, &n);
  if (e != Error::Ok) return e;
  crypto::ed25519_sign2(out + RELEASE_SIGNED_LEN, channel_detail::u8(RELEASE_DOMAIN), RELEASE_DOMAIN_LEN, out,
                        RELEASE_SIGNED_LEN, seed);
  return Error::Ok;
}

inline Error verify_release(const uint8_t* in, size_t len, Release* m,
                            Ed25519Verify verify = crypto::ed25519_verify2) {
  const Error e = decode(in, len, m);
  if (e != Error::Ok) return e;
  return verify(m->signature, channel_detail::u8(RELEASE_DOMAIN), RELEASE_DOMAIN_LEN, in, RELEASE_SIGNED_LEN,
                m->public_key + 32)
             ? Error::Ok
             : Error::Signature;
}

static const size_t RELAY_KEY_LEN = TAG_LEN + HASH_LEN + 4;

// What a relay keys every per-talker state on (live spurts, tombstones, the
// last spurt, replay): channel tag || identity hash of the VERIFIED key ||
// spurt. Never the talker tag alone: a relay cannot tie a tag to a key, so
// anyone can sign a message that carries someone else's tag.
inline Error relay_key(const uint8_t* in, size_t len, uint8_t out[RELAY_KEY_LEN],
                       Ed25519Verify verify = crypto::ed25519_verify2) {
  Type t;
  Error e = peek_type(in, len, &t);
  if (e != Error::Ok) return e;
  const uint8_t* tag;
  const uint8_t* pk;
  uint32_t spurt;
  Claim c;
  Release r;
  if (t == Type::Claim) {
    if ((e = verify_claim(in, len, &c, verify)) != Error::Ok) return e;
    tag = c.channel_tag; pk = c.public_key; spurt = c.spurt;
  } else if (t == Type::Release) {
    if ((e = verify_release(in, len, &r, verify)) != Error::Ok) return e;
    tag = r.channel_tag; pk = r.public_key; spurt = r.spurt;
  } else {
    return Error::Type;
  }
  memcpy(out, tag, TAG_LEN);
  identity_hash(pk, out + TAG_LEN);
  wire_detail::put32(out + TAG_LEN + HASH_LEN, spurt);
  return Error::Ok;
}

// Ok if the RELEASE ends this CLAIM's spurt: both verify, and they share the
// channel tag, the talker tag, the spurt and the signing key. Otherwise
// Signature, or Identity.
inline Error release_matches_claim(const uint8_t* claim, size_t claim_len, const uint8_t* release,
                                   size_t release_len, Ed25519Verify verify = crypto::ed25519_verify2) {
  Claim c;
  Release r;
  Error e = verify_claim(claim, claim_len, &c, verify);
  if (e != Error::Ok) return e;
  if ((e = verify_release(release, release_len, &r, verify)) != Error::Ok) return e;
  if (memcmp(c.channel_tag, r.channel_tag, TAG_LEN) != 0 || memcmp(c.talker_tag, r.talker_tag, TAG_LEN) != 0 ||
      c.spurt != r.spurt || memcmp(c.public_key, r.public_key, PUBLIC_KEY_LEN) != 0)
    return Error::Identity;
  return Error::Ok;
}

// Whether a talker tag is the member tag of the identity whose public key is
// given. Only a key holder can tell; a relay cannot.
inline bool member_ok(const ChannelKeys& k, const uint8_t public_key[64], const uint8_t talker_tag[4]) {
  uint8_t id[16], tag[4];
  identity_hash(public_key, id);
  member_tag(k, id, tag);
  return crypto::equal(tag, talker_tag, 4);
}

}  // namespace lxpt

#endif  // LXPT_CHANNEL_HPP
