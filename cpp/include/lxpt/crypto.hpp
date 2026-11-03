// lxpt -- portable crypto primitives for wire v1. Header-only, C++11, no heap,
// no exceptions, no platform headers.
//
//   - SHA-256, SHA-512 (FIPS 180-4) and HMAC-SHA256 (RFC 2104), streaming;
//   - HKDF-SHA256 (RFC 5869);
//   - AES-256, encryption direction only, and CTR mode with the whole 16-byte
//     counter block incremented as one big-endian integer (SP 800-38A);
//   - Ed25519 (RFC 8032): a transcription of TweetNaCl's crypto_sign (public
//     domain; Bernstein, van Gastel, Janssen, Lange, Schwabe, Smetsers),
//     detached and streaming, with the verification rules of spec/wire-v1.md
//     added: S below the group order, the public key a canonical encoding
//     and not of small order.
//
// These are reference implementations, checked against the published known
// answers and the shared fixture. They are not constant-time-reviewed (the AES
// uses a table S-box; Ed25519 is TweetNaCl's, which is). A build with hardware
// or audited crypto can use its own: nothing in wire.hpp depends on this file,
// and channel.hpp needs only the functions below.
//
// SPDX-License-Identifier: Apache-2.0

#ifndef LXPT_CRYPTO_HPP
#define LXPT_CRYPTO_HPP

#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace lxpt {
namespace crypto {

// --- SHA-256 -----------------------------------------------------------------------

struct Sha256 {
  uint32_t h[8];
  uint8_t block[64];
  size_t used;
  uint64_t bytes;
};

namespace detail {
inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
inline uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

inline void sha256_compress(Sha256& c) {
  static const uint32_t K[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
  uint32_t w[64];
  for (int i = 0; i < 16; i++)
    w[i] = (uint32_t(c.block[4 * i]) << 24) | (uint32_t(c.block[4 * i + 1]) << 16) |
           (uint32_t(c.block[4 * i + 2]) << 8) | uint32_t(c.block[4 * i + 3]);
  for (int i = 16; i < 64; i++) {
    const uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = c.h[0], b = c.h[1], cc = c.h[2], d = c.h[3], e = c.h[4], f = c.h[5], g = c.h[6], h = c.h[7];
  for (int i = 0; i < 64; i++) {
    const uint32_t t1 = h + (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
    const uint32_t t2 = (rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) + ((a & b) ^ (a & cc) ^ (b & cc));
    h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
  }
  c.h[0] += a; c.h[1] += b; c.h[2] += cc; c.h[3] += d; c.h[4] += e; c.h[5] += f; c.h[6] += g; c.h[7] += h;
}
}  // namespace detail

inline void sha256_init(Sha256& c) {
  static const uint32_t H0[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  memcpy(c.h, H0, sizeof(H0));
  c.used = 0;
  c.bytes = 0;
}

inline void sha256_update(Sha256& c, const uint8_t* p, size_t n) {
  for (size_t i = 0; i < n; i++) {
    c.block[c.used++] = p[i];
    c.bytes++;
    if (c.used == 64) {
      detail::sha256_compress(c);
      c.used = 0;
    }
  }
}

inline void sha256_final(Sha256& c, uint8_t out[32]) {
  const uint64_t bits = c.bytes * 8;
  const uint8_t one = 0x80, zero = 0;
  sha256_update(c, &one, 1);
  while (c.used != 56) sha256_update(c, &zero, 1);
  uint8_t len[8];
  for (int i = 0; i < 8; i++) len[i] = uint8_t(bits >> (56 - 8 * i));
  sha256_update(c, len, 8);
  for (int i = 0; i < 8; i++)
    for (int j = 0; j < 4; j++) out[4 * i + j] = uint8_t(c.h[i] >> (24 - 8 * j));
}

inline void sha256(const uint8_t* p, size_t n, uint8_t out[32]) {
  Sha256 c;
  sha256_init(c);
  sha256_update(c, p, n);
  sha256_final(c, out);
}

// --- HMAC-SHA256 ---------------------------------------------------------------------

struct HmacSha256 {
  Sha256 inner;
  uint8_t opad[64];
};

inline void hmac_sha256_init(HmacSha256& c, const uint8_t* key, size_t key_len) {
  uint8_t k[64];
  memset(k, 0, sizeof(k));
  if (key_len > 64) {
    sha256(key, key_len, k);
  } else if (key_len > 0) {
    memcpy(k, key, key_len);
  }
  uint8_t ipad[64];
  for (int i = 0; i < 64; i++) {
    ipad[i] = uint8_t(k[i] ^ 0x36);
    c.opad[i] = uint8_t(k[i] ^ 0x5c);
  }
  sha256_init(c.inner);
  sha256_update(c.inner, ipad, 64);
}

inline void hmac_sha256_update(HmacSha256& c, const uint8_t* p, size_t n) { sha256_update(c.inner, p, n); }

inline void hmac_sha256_final(HmacSha256& c, uint8_t out[32]) {
  uint8_t inner[32];
  sha256_final(c.inner, inner);
  Sha256 outer;
  sha256_init(outer);
  sha256_update(outer, c.opad, 64);
  sha256_update(outer, inner, 32);
  sha256_final(outer, out);
}

inline void hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t msg_len, uint8_t out[32]) {
  HmacSha256 c;
  hmac_sha256_init(c, key, key_len);
  hmac_sha256_update(c, msg, msg_len);
  hmac_sha256_final(c, out);
}

// HKDF-SHA256. An empty salt means 32 zero bytes, as RFC 5869 says. Returns
// false for a length of 0 or past 255 * 32.
inline bool hkdf_sha256(const uint8_t* ikm, size_t ikm_len, const uint8_t* salt, size_t salt_len, const uint8_t* info,
                        size_t info_len, uint8_t* out, size_t out_len) {
  if (out_len == 0 || out_len > 255 * 32) return false;
  static const uint8_t zero_salt[32] = {0};
  uint8_t prk[32];
  if (salt_len == 0) hmac_sha256(zero_salt, 32, ikm, ikm_len, prk);
  else hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
  uint8_t block[32];
  size_t done = 0;
  for (uint8_t counter = 1; done < out_len; counter++) {
    HmacSha256 c;
    hmac_sha256_init(c, prk, 32);
    if (counter > 1) hmac_sha256_update(c, block, 32);
    hmac_sha256_update(c, info, info_len);
    hmac_sha256_update(c, &counter, 1);
    hmac_sha256_final(c, block);
    const size_t take = (out_len - done) < 32 ? (out_len - done) : 32;
    memcpy(out + done, block, take);
    done += take;
  }
  return true;
}

// Constant-time comparison.
inline bool equal(const uint8_t* a, const uint8_t* b, size_t n) {
  uint8_t d = 0;
  for (size_t i = 0; i < n; i++) d = uint8_t(d | (a[i] ^ b[i]));
  return d == 0;
}

// --- SHA-512 -------------------------------------------------------------------------

struct Sha512 {
  uint64_t h[8];
  uint8_t block[128];
  size_t used;
  uint64_t bytes;
};

namespace detail {
inline void sha512_compress(Sha512& c) {
  static const uint64_t K[80] = {
      0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
      0x3956c25bf348b538ull, 0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
      0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
      0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
      0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
      0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
      0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
      0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull, 0x06ca6351e003826full, 0x142929670a0e6e70ull,
      0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
      0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
      0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
      0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
      0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
      0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
      0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
      0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
      0xca273eceea26619cull, 0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
      0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
      0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
      0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull};
  uint64_t w[80];
  for (int i = 0; i < 16; i++) {
    w[i] = 0;
    for (int j = 0; j < 8; j++) w[i] = (w[i] << 8) | c.block[8 * i + j];
  }
  for (int i = 16; i < 80; i++) {
    const uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
    const uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint64_t a = c.h[0], b = c.h[1], cc = c.h[2], d = c.h[3], e = c.h[4], f = c.h[5], g = c.h[6], h = c.h[7];
  for (int i = 0; i < 80; i++) {
    const uint64_t t1 = h + (rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
    const uint64_t t2 = (rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)) + ((a & b) ^ (a & cc) ^ (b & cc));
    h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
  }
  c.h[0] += a; c.h[1] += b; c.h[2] += cc; c.h[3] += d; c.h[4] += e; c.h[5] += f; c.h[6] += g; c.h[7] += h;
}
}  // namespace detail

inline void sha512_init(Sha512& c) {
  static const uint64_t H0[8] = {0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull,
                                 0xa54ff53a5f1d36f1ull, 0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
                                 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull};
  memcpy(c.h, H0, sizeof(H0));
  c.used = 0;
  c.bytes = 0;
}

inline void sha512_update(Sha512& c, const uint8_t* p, size_t n) {
  for (size_t i = 0; i < n; i++) {
    c.block[c.used++] = p[i];
    c.bytes++;
    if (c.used == 128) {
      detail::sha512_compress(c);
      c.used = 0;
    }
  }
}

inline void sha512_final(Sha512& c, uint8_t out[64]) {
  const uint64_t bits = c.bytes * 8;
  const uint8_t one = 0x80, zero = 0;
  sha512_update(c, &one, 1);
  while (c.used != 112) sha512_update(c, &zero, 1);
  uint8_t len[16];
  memset(len, 0, sizeof(len));
  for (int i = 0; i < 8; i++) len[8 + i] = uint8_t(bits >> (56 - 8 * i));
  sha512_update(c, len, 16);
  for (int i = 0; i < 8; i++)
    for (int j = 0; j < 8; j++) out[8 * i + j] = uint8_t(c.h[i] >> (56 - 8 * j));
}

// --- AES-256 (encryption only) and CTR -------------------------------------------------

namespace detail {
static const uint8_t AES_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

inline uint8_t xtime(uint8_t a) { return uint8_t((a << 1) ^ ((a & 0x80) ? 0x1b : 0x00)); }
}  // namespace detail

struct Aes256 {
  uint8_t round_keys[240];
};

inline void aes256_init(Aes256& a, const uint8_t key[32]) {
  memcpy(a.round_keys, key, 32);
  uint8_t rcon = 1;
  for (int i = 8; i < 60; i++) {
    uint8_t t[4];
    memcpy(t, a.round_keys + 4 * (i - 1), 4);
    if (i % 8 == 0) {
      const uint8_t first = t[0];
      t[0] = uint8_t(detail::AES_SBOX[t[1]] ^ rcon);
      t[1] = detail::AES_SBOX[t[2]];
      t[2] = detail::AES_SBOX[t[3]];
      t[3] = detail::AES_SBOX[first];
      rcon = detail::xtime(rcon);
    } else if (i % 8 == 4) {
      for (int j = 0; j < 4; j++) t[j] = detail::AES_SBOX[t[j]];
    }
    for (int j = 0; j < 4; j++) a.round_keys[4 * i + j] = uint8_t(a.round_keys[4 * (i - 8) + j] ^ t[j]);
  }
}

inline void aes256_encrypt_block(const Aes256& a, const uint8_t in[16], uint8_t out[16]) {
  uint8_t s[16];
  for (int i = 0; i < 16; i++) s[i] = uint8_t(in[i] ^ a.round_keys[i]);
  for (int round = 1; round < 15; round++) {
    uint8_t t[16];
    // SubBytes and ShiftRows; the state is column-major (byte i is row i % 4).
    for (int i = 0; i < 16; i++) t[i] = detail::AES_SBOX[s[(i + 4 * (i % 4)) % 16]];
    if (round != 14) {
      for (int c = 0; c < 4; c++) {
        const uint8_t a0 = t[4 * c], a1 = t[4 * c + 1], a2 = t[4 * c + 2], a3 = t[4 * c + 3];
        const uint8_t all = uint8_t(a0 ^ a1 ^ a2 ^ a3);
        t[4 * c] = uint8_t(a0 ^ all ^ detail::xtime(uint8_t(a0 ^ a1)));
        t[4 * c + 1] = uint8_t(a1 ^ all ^ detail::xtime(uint8_t(a1 ^ a2)));
        t[4 * c + 2] = uint8_t(a2 ^ all ^ detail::xtime(uint8_t(a2 ^ a3)));
        t[4 * c + 3] = uint8_t(a3 ^ all ^ detail::xtime(uint8_t(a3 ^ a0)));
      }
    }
    for (int i = 0; i < 16; i++) s[i] = uint8_t(t[i] ^ a.round_keys[16 * round + i]);
  }
  memcpy(out, s, 16);
}

// AES-256-CTR: out may equal in. The counter block is incremented as one
// 128-bit big-endian integer.
inline void aes256_ctr(const uint8_t key[32], const uint8_t iv[16], const uint8_t* in, size_t n, uint8_t* out) {
  Aes256 a;
  aes256_init(a, key);
  uint8_t counter[16], ks[16];
  memcpy(counter, iv, 16);
  for (size_t at = 0; at < n; at += 16) {
    aes256_encrypt_block(a, counter, ks);
    const size_t take = (n - at) < 16 ? (n - at) : 16;
    for (size_t i = 0; i < take; i++) out[at + i] = uint8_t(in[at + i] ^ ks[i]);
    for (int i = 15; i >= 0; i--)
      if (++counter[i] != 0) break;
  }
}

// --- Ed25519 ---------------------------------------------------------------------------

namespace ed25519_detail {
typedef int64_t gf[16];

static const gf GF0 = {0};
static const gf GF1 = {1};
static const gf D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
                     0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203};
static const gf D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
                      0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406};
static const gf BX = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
                      0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169};
static const gf BY = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
                      0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666};
static const gf SQRTM1 = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
                          0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};
// The group order L, little-endian bytes.
static const uint8_t L_BYTES[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                                    0xa2, 0xde, 0xf9, 0xde, 0x14, 0,    0,    0,    0,    0,    0,
                                    0,    0,    0,    0,    0,    0,    0,    0,    0,    0x10};
static const int64_t L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                              0xa2, 0xde, 0xf9, 0xde, 0x14, 0,    0,    0,    0,    0,    0,
                              0,    0,    0,    0,    0,    0,    0,    0,    0,    0x10};

inline void set(gf r, const gf a) {
  for (int i = 0; i < 16; i++) r[i] = a[i];
}

inline void car(gf o) {
  for (int i = 0; i < 16; i++) {
    o[i] += 65536;
    const int64_t c = o[i] >> 16;
    if (i < 15) o[i + 1] += c - 1;
    else o[0] += 38 * (c - 1);
    o[i] -= c * 65536;
  }
}

inline void sel(gf p, gf q, int b) {
  const int64_t c = ~(int64_t(b) - 1);
  for (int i = 0; i < 16; i++) {
    const int64_t t = c & (p[i] ^ q[i]);
    p[i] ^= t;
    q[i] ^= t;
  }
}

inline void pack25519(uint8_t* o, const gf n) {
  gf m, t;
  set(t, n);
  car(t);
  car(t);
  car(t);
  for (int j = 0; j < 2; j++) {
    m[0] = t[0] - 0xffed;
    for (int i = 1; i < 15; i++) {
      m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
      m[i - 1] &= 0xffff;
    }
    m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
    const int b = int((m[15] >> 16) & 1);
    m[14] &= 0xffff;
    sel(t, m, 1 - b);
  }
  for (int i = 0; i < 16; i++) {
    o[2 * i] = uint8_t(t[i] & 0xff);
    o[2 * i + 1] = uint8_t((t[i] >> 8) & 0xff);
  }
}

inline bool neq(const gf a, const gf b) {
  uint8_t c[32], d[32];
  pack25519(c, a);
  pack25519(d, b);
  return memcmp(c, d, 32) != 0;
}

inline uint8_t par(const gf a) {
  uint8_t d[32];
  pack25519(d, a);
  return d[0] & 1;
}

inline void unpack25519(gf o, const uint8_t* n) {
  for (int i = 0; i < 16; i++) o[i] = n[2 * i] + (int64_t(n[2 * i + 1]) << 8);
  o[15] &= 0x7fff;
}

inline void A(gf o, const gf a, const gf b) {
  for (int i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

inline void Z(gf o, const gf a, const gf b) {
  for (int i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

inline void M(gf o, const gf a, const gf b) {
  int64_t t[31];
  for (int i = 0; i < 31; i++) t[i] = 0;
  for (int i = 0; i < 16; i++)
    for (int j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
  for (int i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
  for (int i = 0; i < 16; i++) o[i] = t[i];
  car(o);
  car(o);
}

inline void S(gf o, const gf a) { M(o, a, a); }

inline void inv25519(gf o, const gf i) {
  gf c;
  set(c, i);
  for (int a = 253; a >= 0; a--) {
    S(c, c);
    if (a != 2 && a != 4) M(c, c, i);
  }
  set(o, c);
}

inline void pow2523(gf o, const gf i) {
  gf c;
  set(c, i);
  for (int a = 250; a >= 0; a--) {
    S(c, c);
    if (a != 1) M(c, c, i);
  }
  set(o, c);
}

inline void add(gf p[4], gf q[4]) {
  gf a, b, c, d, t, e, f, g, h;
  Z(a, p[1], p[0]);
  Z(t, q[1], q[0]);
  M(a, a, t);
  A(b, p[0], p[1]);
  A(t, q[0], q[1]);
  M(b, b, t);
  M(c, p[3], q[3]);
  M(c, c, D2);
  M(d, p[2], q[2]);
  A(d, d, d);
  Z(e, b, a);
  Z(f, d, c);
  A(g, d, c);
  A(h, b, a);
  M(p[0], e, f);
  M(p[1], h, g);
  M(p[2], g, f);
  M(p[3], e, h);
}

inline void cswap(gf p[4], gf q[4], uint8_t b) {
  for (int i = 0; i < 4; i++) sel(p[i], q[i], b);
}

inline void pack(uint8_t* r, gf p[4]) {
  gf tx, ty, zi;
  inv25519(zi, p[2]);
  M(tx, p[0], zi);
  M(ty, p[1], zi);
  pack25519(r, ty);
  r[31] = uint8_t(r[31] ^ (par(tx) << 7));
}

inline void scalarmult(gf p[4], gf q[4], const uint8_t* s) {
  set(p[0], GF0);
  set(p[1], GF1);
  set(p[2], GF1);
  set(p[3], GF0);
  for (int i = 255; i >= 0; --i) {
    const uint8_t b = (s[i / 8] >> (i & 7)) & 1;
    cswap(p, q, b);
    add(q, p);
    add(p, p);
    cswap(p, q, b);
  }
}

inline void scalarbase(gf p[4], const uint8_t* s) {
  gf q[4];
  set(q[0], BX);
  set(q[1], BY);
  set(q[2], GF1);
  M(q[3], BX, BY);
  scalarmult(p, q, s);
}

inline void modL(uint8_t* r, int64_t x[64]) {
  int64_t carry;
  for (int i = 63; i >= 32; --i) {
    carry = 0;
    int j;
    for (j = i - 32; j < i - 12; ++j) {
      x[j] += carry - 16 * x[i] * L[j - (i - 32)];
      carry = (x[j] + 128) >> 8;
      x[j] -= carry * 256;
    }
    x[j] += carry;
    x[i] = 0;
  }
  carry = 0;
  for (int j = 0; j < 32; j++) {
    x[j] += carry - (x[31] >> 4) * L[j];
    carry = x[j] >> 8;
    x[j] &= 255;
  }
  for (int j = 0; j < 32; j++) x[j] -= carry * L[j];
  for (int i = 0; i < 32; i++) {
    x[i + 1] += x[i] >> 8;
    r[i] = uint8_t(x[i] & 255);
  }
}

inline void reduce(uint8_t* r) {
  int64_t x[64];
  for (int i = 0; i < 64; i++) x[i] = r[i];
  for (int i = 0; i < 64; i++) r[i] = 0;
  modL(r, x);
}

// Whether a little-endian 32-byte value is below a little-endian bound.
inline bool below(const uint8_t v[32], const uint8_t bound[32]) {
  for (int i = 31; i >= 0; i--) {
    if (v[i] < bound[i]) return true;
    if (v[i] > bound[i]) return false;
  }
  return false;
}

// Decodes -A from a public key; false unless the encoding is canonical: y
// below p, and not x = 0 with the sign bit set.
inline bool unpackneg(gf r[4], const uint8_t p[32]) {
  static const uint8_t P_BYTES[32] = {0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};
  uint8_t y[32];
  memcpy(y, p, 32);
  y[31] &= 0x7f;
  if (!below(y, P_BYTES)) return false;
  gf t, chk, num, den, den2, den4, den6;
  set(r[2], GF1);
  unpack25519(r[1], p);
  S(num, r[1]);
  M(den, num, D);
  Z(num, num, r[2]);
  A(den, r[2], den);
  S(den2, den);
  S(den4, den2);
  M(den6, den4, den2);
  M(t, den6, num);
  M(t, t, den);
  pow2523(t, t);
  M(t, t, num);
  M(t, t, den);
  M(t, t, den);
  M(r[0], t, den);
  S(chk, r[0]);
  M(chk, chk, den);
  if (neq(chk, num)) M(r[0], r[0], SQRTM1);
  S(chk, r[0]);
  M(chk, chk, den);
  if (neq(chk, num)) return false;
  uint8_t x[32];
  pack25519(x, r[0]);
  bool zero = true;
  for (int i = 0; i < 32; i++)
    if (x[i]) zero = false;
  if (zero && (p[31] >> 7)) return false;
  if (par(r[0]) == (p[31] >> 7)) Z(r[0], GF0, r[0]);
  M(r[3], r[0], r[1]);
  return true;
}

// [8]P is the identity: P is in the torsion subgroup (order 1, 2, 4 or 8).
inline bool small_order(gf p[4]) {
  static const uint8_t IDENTITY[32] = {1};
  gf t[4];
  for (int i = 0; i < 4; i++) set(t[i], p[i]);
  add(t, t);
  add(t, t);
  add(t, t);
  uint8_t e[32];
  pack(e, t);
  return memcmp(e, IDENTITY, 32) == 0;
}

inline void expand(const uint8_t seed[32], uint8_t d[64]) {
  Sha512 c;
  sha512_init(c);
  sha512_update(c, seed, 32);
  sha512_final(c, d);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;
}
}  // namespace ed25519_detail

inline void ed25519_public_key(const uint8_t seed[32], uint8_t pk[32]) {
  using namespace ed25519_detail;
  uint8_t d[64];
  gf p[4];
  expand(seed, d);
  scalarbase(p, d);
  pack(pk, p);
}

// Signs the concatenation of up to two parts (a domain and a message), so a
// caller needs no buffer to join them.
inline void ed25519_sign2(uint8_t sig[64], const uint8_t* m1, size_t n1, const uint8_t* m2, size_t n2,
                          const uint8_t seed[32]) {
  using namespace ed25519_detail;
  uint8_t d[64], r[64], h[64], pk[32];
  gf p[4];
  expand(seed, d);
  scalarbase(p, d);
  pack(pk, p);
  Sha512 c;
  sha512_init(c);
  sha512_update(c, d + 32, 32);
  sha512_update(c, m1, n1);
  sha512_update(c, m2, n2);
  sha512_final(c, r);
  reduce(r);
  scalarbase(p, r);
  pack(sig, p);
  sha512_init(c);
  sha512_update(c, sig, 32);
  sha512_update(c, pk, 32);
  sha512_update(c, m1, n1);
  sha512_update(c, m2, n2);
  sha512_final(c, h);
  reduce(h);
  int64_t x[64];
  for (int i = 0; i < 64; i++) x[i] = 0;
  for (int i = 0; i < 32; i++) x[i] = r[i];
  for (int i = 0; i < 32; i++)
    for (int j = 0; j < 32; j++) x[i + j] += int64_t(h[i]) * d[j];
  modL(sig + 32, x);
}

inline void ed25519_sign(uint8_t sig[64], const uint8_t* m, size_t n, const uint8_t seed[32]) {
  ed25519_sign2(sig, m, n, m, 0, seed);
}

// Verifies under spec/wire-v1.md's rules: S < L, A canonical and not of small
// order, R compared as bytes with the canonical encoding of [S]B - [k]A
// (cofactorless).
inline bool ed25519_verify2(const uint8_t sig[64], const uint8_t* m1, size_t n1, const uint8_t* m2, size_t n2,
                            const uint8_t pk[32]) {
  using namespace ed25519_detail;
  if (!below(sig + 32, L_BYTES)) return false;
  gf p[4], q[4];
  uint8_t t[32], h[64];
  if (!unpackneg(q, pk) || small_order(q)) return false;
  Sha512 c;
  sha512_init(c);
  sha512_update(c, sig, 32);
  sha512_update(c, pk, 32);
  sha512_update(c, m1, n1);
  sha512_update(c, m2, n2);
  sha512_final(c, h);
  reduce(h);
  scalarmult(p, q, h);
  scalarbase(q, sig + 32);
  add(p, q);
  pack(t, p);
  return memcmp(sig, t, 32) == 0;
}

inline bool ed25519_verify(const uint8_t sig[64], const uint8_t* m, size_t n, const uint8_t pk[32]) {
  return ed25519_verify2(sig, m, n, m, 0, pk);
}

}  // namespace crypto
}  // namespace lxpt

#endif  // LXPT_CRYPTO_HPP
