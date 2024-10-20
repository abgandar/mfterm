/**
 * Copyright (C) 2024 Alexander Wittig <abgandar@gmail.com>
 *
 * This file is part of mfterm.
 *
 * mfterm is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * mfterm is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with mfterm.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "crypto1.h"

// calculate normal (odd) parity
static inline void crypto1_parity(uint8_t *x, uint8_t *x_p, size_t l) {
  for(size_t i = 0; i < l; i++)
    x_p[i] = !__builtin_parity(x[i]);
}

// convert from byte order to LFSR bit order
static inline uint64_t get48(const uint8_t x[6]) {
  return (((uint64_t)x[0])<<0) | (((uint64_t)x[1])<<8) | (((uint64_t)x[2])<<16) | (((uint64_t)x[3])<<24) | (((uint64_t)x[4])<<32) | (((uint64_t)x[5])<<40);
}

// convert from byte order to LFSR bit order
static inline uint32_t get32(const uint8_t x[4]) {
  return (((uint32_t)x[0])<<0) | (((uint32_t)x[1])<<8) | (((uint32_t)x[2])<<16) | (((uint32_t)x[3])<<24);
}

// convert from LFSR bit order to byte order
static inline void put32(uint8_t x[4], uint32_t y) {
  x[0] = (uint8_t)(y>>0);
  x[1] = (uint8_t)(y>>8);
  x[2] = (uint8_t)(y>>16);
  x[3] = (uint8_t)(y>>24);
}

static inline uint32_t L16(const uint32_t x) {
  return (uint32_t)__builtin_parity(x & 0b1011010000000000000000);
}

static inline uint32_t suc(const uint32_t x) {
    return (x >> 1) | (L16(x) << 31);
}

static void crypto1_ar(const uint8_t nt[4], uint8_t ar[4]) {
  uint32_t x = get32(nt);
  for(int i = 0; i < 64; i++)
      x = suc(x);
  put32(ar, x);
}

static void crypto1_at(const uint8_t nt[4], uint8_t at[4]) {
  uint32_t x = get32(nt);
  for(int i = 0; i < 96; i++)
      x = suc(x);
  put32(at, x);
}

static inline uint64_t L(const uint64_t x) {
  return (uint64_t)__builtin_parityll(x & 0b000011101000100000101011000010101101011000100001ll);
}

static inline uint64_t fa(const uint64_t y0, const uint64_t y1, const uint64_t y2, const uint64_t y3) {
  return (((y0 | y1) ^ (y0 & y3)) ^ (y2 & ((y0 ^ y1) | y3))) & 1;
}

static inline uint64_t fb(const uint64_t y0, const uint64_t y1, const uint64_t y2, const uint64_t y3) {
  return (((y0 & y1) | y2) ^ ((y0 ^ y1) & (y2 | y3))) & 1;
}

static inline uint64_t fc(const uint64_t y0, const uint64_t y1, const uint64_t y2, const uint64_t y3, const uint64_t y4) {
  return ((y0 | ((y1 | y4) & (y3 ^ y4))) ^ ((y0 ^ (y1 & y3)) & ((y2 ^ y3) | (y1 & y4)))) & 1;
}

static inline uint64_t f(const uint64_t x) {
    return fc(fa(x>> 9, x>>11, x>>13, x>>15),
              fb(x>>17, x>>19, x>>21, x>>23),
              fb(x>>25, x>>27, x>>29, x>>31),
              fa(x>>33, x>>35, x>>37, x>>39),
              fb(x>>41, x>>43, x>>45, x>>47));
}

static inline uint8_t crypto1_keystream_bit(crypto1_ctx_t *ctx) {
  const uint64_t bit = f(ctx->x);
  ctx->x = (ctx->x >> 1) | ((L(ctx->x) ^ (ctx->f & 1) ^ (bit & ctx->fb)) << 47);
  ctx->f >>= 1;
  return (uint8_t)bit;
}

static inline uint8_t crypto1_keystream_peek(crypto1_ctx_t *ctx) {
  return (uint8_t)f(ctx->x);
}

static uint8_t crypto1_decrypt_8(crypto1_ctx_t *ctx, const uint8_t d) {
  uint8_t k = 0;
  for(int i = 0; i < 8; i++)
    k |= crypto1_keystream_bit(ctx) << i;
  return d ^ k;
}

static uint8_t crypto1_encrypt_8(crypto1_ctx_t *ctx, const uint8_t d, uint8_t *p) {
  uint8_t k = 0;
  for(int i = 0; i < 8; i++)
    k |= crypto1_keystream_bit(ctx) << i;
  *p = (uint8_t)((!__builtin_parity(d)) ^ crypto1_keystream_peek(ctx));
  return d ^ k;
}

void crypto1_decrypt_bits(crypto1_ctx_t *ctx, uint8_t *data, size_t len) {
  uint8_t k = 0;
  for(int i = 0; i < len; i++)
    k |= crypto1_keystream_bit(ctx) << i;
  *data ^= k;
}

void crypto1_encrypt_bits(crypto1_ctx_t *ctx, uint8_t *data, size_t len) {
  crypto1_decrypt_bits(ctx, data, len);   // same thing, no parity for individual bits
}

void crypto1_decrypt(crypto1_ctx_t *ctx, uint8_t *data, size_t len) {
  for(int i = 0; i < len; i++)
    data[i] = crypto1_decrypt_8(ctx, data[i]);
}

void crypto1_encrypt(crypto1_ctx_t *ctx, uint8_t *data, const size_t len, uint8_t *parity) {
  for(int i = 0; i < len; i++)
    data[i] = crypto1_encrypt_8(ctx, data[i], &parity[i]);
}

// input: key, UID, (un-encrypted) nt
// output: encrypted nt+parity to send to reader, unencrypted at, expected ar
void crypto1_auth_tag1(crypto1_ctx_t *ctx, const uint8_t key[6], const uint8_t uid[4], crypto1_auth_t *a) {
  crypto1_ar(a->nt, a->a_ref);
  crypto1_at(a->nt, a->at);
  ctx->x = get48(key);
  ctx->f = get32(uid)^get32(a->nt);  // 32 bit feed
  if(ctx->state != CRYPTO1_OFF) {
    crypto1_encrypt(ctx, a->nt, sizeof(a->nt), a->nt_p);
  } else {
    for(int i = 0; i < 32; i++)
      crypto1_keystream_bit(ctx);   // just cycling the LFSR to load ctx->f
    crypto1_parity(a->nt, a->nt_p, sizeof(a->nt));   // return unencrypted parity bits
  }
}

// inut: encrypted nr, encrypted ar received from reader
// output: un-encrypted nr, unencrypted ar
void crypto1_auth_tag2(crypto1_ctx_t *ctx, crypto1_auth_t *a) {
  ctx->f = get32(a->nr);          // 32 bit feed
  ctx->fb = 1;                    // feedback (decrypts nr in feed)
  crypto1_decrypt(ctx, a->nr, sizeof(a->nr));
  ctx->fb = 0;                    // feedback off
  crypto1_decrypt(ctx, a->ar, sizeof(a->ar));
}

// input: key, UID, nt received from reader, nr
// output: un-encrypted nt, encrypted nr+parity, encrypted ar+parity to send to tag, expected at
void crypto1_auth_reader(crypto1_ctx_t *ctx, const uint8_t key[6], const uint8_t uid[4], crypto1_auth_t *a) {
  ctx->x = get48(key);
  ctx->f = get32(uid)^get32(a->nt);  // 32 bit feed

  if(ctx->state != CRYPTO1_OFF) {
    ctx->fb = 1;                    // feedback (decrypts nt in feed)
    crypto1_decrypt(ctx, a->nt, sizeof(a->nr));
    ctx->fb = 0;                    // feedback off
  } else {
    for(int i = 0; i < 32; i++)
      crypto1_keystream_bit(ctx);   // just cycling the LFSR to load ctx->f
  }
  ctx->state = CRYPTO1_OFF;
  crypto1_ar(a->nt, a->ar);
  crypto1_at(a->nt, a->a_ref);
  ctx->f = get32(a->nr);             // 32 bit feed
  crypto1_encrypt(ctx, a->nr, sizeof(a->nr), a->nr_p);
  crypto1_encrypt(ctx, a->ar, sizeof(a->ar), a->ar_p);
}
