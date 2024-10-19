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

#include <stdio.h>    // remove after debugging
#include "crypto1.h"

// calculate normal (odd) parity
uint32_t crypto1_parity(uint32_t x) {
  uint32_t p = 0;
  for(int i = 0; i < 4; i++) {
    p <<= 8;
    p |= !__builtin_parity(x>>24);
    x <<= 8;
  }
  return p;
}

// reverse bits in each byte so they can be fed from left to right
static inline uint32_t feedbits(uint32_t x) {
  x = ((x<<1)&0xAAAAAAAA) | ((x>>1)&0x55555555);
  x = ((x<<2)&0xCCCCCCCC) | ((x>>2)&0x33333333);
  x = ((x<<4)&0xF0F0F0F0) | ((x>>4)&0x0F0F0F0F);
  return x;
}

// reverse bits in each byte so they are like fed in
static inline uint64_t keybits(uint64_t x) {
  x = ((x<<1)&0xAAAAAAAAAAAAAAAA) | ((x>>1)&0x5555555555555555);
  x = ((x<<2)&0xCCCCCCCCCCCCCCCC) | ((x>>2)&0x3333333333333333);
  x = ((x<<4)&0xF0F0F0F0F0F0F0F0) | ((x>>4)&0x0F0F0F0F0F0F0F0F);
  return x;
}

/*
static inline uint32_t L16(const uint32_t x) {
  return ((x >> 15) ^ (x >> 13) ^ (x >> 12) ^ (x >> 10)) & 1;
}
*/

static inline uint32_t L16(const uint32_t x) {
  return (uint32_t)__builtin_parity(x & 0b1011010000000000);
}

static inline uint32_t suc(const uint32_t x) {
    return (x << 1) | L16(x);
}

uint32_t crypto1_ar(uint32_t nt) {
    nt = feedbits(nt);
    for(int i = 0; i < 64; i++)
        nt = suc(nt);
    nt = feedbits(nt);
    return nt;
}

uint32_t crypto1_at(uint32_t nt) {
    nt = feedbits(nt);
    for(int i = 0; i < 96; i++)
        nt = suc(nt);
    nt = feedbits(nt);
    return nt;
}

/*
static inline uint64_t xL(const uint64_t x) {
  return ((x >> 47) ^ (x >> 42) ^ (x >> 38) ^ (x >> 37) ^ (x >> 35) ^ (x >> 33) ^
          (x >> 32) ^ (x >> 30) ^ (x >> 28) ^ (x >> 23) ^ (x >> 22) ^ (x >> 20) ^
          (x >> 18) ^ (x >> 12) ^ (x >>  8) ^ (x >>  6) ^ (x >>  5) ^ (x >>  4)) & 1;
}
*/

static inline uint64_t L(const uint64_t x) {
  return (uint64_t)__builtin_parityll(x & 0b100001000110101101010000110101000001000101110000ll);
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

/*
static inline uint64_t fa(uint64_t y0, uint64_t y1, uint64_t y2, uint64_t y3) {
  y0 &= 1; y1 &= 1; y2 &= 1; y3 &= 1;
  return (0x26c7 >> (y0<<3 | y1<<2 | y2<<1 | y3)) & 1;
}

static inline uint64_t fb(uint64_t y0, uint64_t y1, uint64_t y2, uint64_t y3) {
  y0 &= 1; y1 &= 1; y2 &= 1; y3 &= 1;
  return (0x0dd3 >> (y0<<3 | y1<<2 | y2<<1 | y3)) & 1;
}

static inline uint64_t fc(uint64_t y0, uint64_t y1, uint64_t y2, uint64_t y3, uint64_t y4) {
  y0 &= 1; y1 &= 1; y2 &= 1; y3 &= 1; y4 &= 1;
  return (0x4457c3b3 >> (y0<<4 | y1<<3 | y2<<2 | y3<<1 | y4)) & 1;
}
*/

static inline uint64_t f(const uint64_t x) {
    return fc(fa(x>>38, x>>36, x>>34, x>>32),
              fb(x>>30, x>>28, x>>26, x>>24),
              fb(x>>22, x>>20, x>>18, x>>16),
              fa(x>>14, x>>12, x>>10, x>> 8),
              fb(x>> 6, x>> 4, x>> 2, x    ));
}

static inline uint8_t crypto1_keystream_bit(crypto1_ctx_t *ctx) {
  const uint64_t bit = f(ctx->x);
  ctx->x = (ctx->x << 1) | L(ctx->x);
  ctx->x ^= ctx->f >> 31;   // feeding 0 is no-op, so we can just always do this
  ctx->f <<= 1;
  ctx->x ^= bit & ctx->fb;  // feed back bit (if fb=1), else feeding 0 is no-op

  return (uint8_t)bit;
}

static inline uint8_t crypto1_keystream_peek(crypto1_ctx_t *ctx) {
  return (uint8_t)f(ctx->x);
}

// input: key, UID, (un-encrypted) nt
// output: encrypted nt, encrypted parity bits
void crypto1_auth1_nested_tag(crypto1_ctx_t *ctx, const uint8_t key[6], uint32_t uid, uint32_t *nt, uint32_t *nt_p) {
  ctx->x = keybits((((uint64_t)key[0])<<40) | (((uint64_t)key[1])<<32) | (((uint64_t)key[2])<<24) | (((uint64_t)key[3])<<16) | (((uint64_t)key[4])<<8) | (((uint64_t)key[5])));
  ctx->f = feedbits(uid^(*nt));   // 32 bit feed
  ctx->fb = 0;                    // no feedback
  uint32_t k = 0;
  for(int i = 31; i >= 0; i--) {
    k |= (uint32_t)(crypto1_keystream_bit(ctx) << (i ^ 7));
    if(i%8 == 0) {
      *nt_p <<= 8;
      *nt_p |= (!__builtin_parity(*nt >> 24)) ^ crypto1_keystream_peek(ctx);
      *nt = __builtin_rotateleft32(*nt, 8);
    }
  }
  *nt ^= k;
}

// input: key, UID, received (encrypted) nt
// output: decrypted nt
void crypto1_auth1_nested_reader(crypto1_ctx_t *ctx, const uint8_t key[6], uint32_t uid, uint32_t *nt) {
  ctx->x = keybits((((uint64_t)key[0])<<40) | (((uint64_t)key[1])<<32) | (((uint64_t)key[2])<<24) | (((uint64_t)key[3])<<16) | (((uint64_t)key[4])<<8) | (((uint64_t)key[5])));
  ctx->f = feedbits(uid^(*nt));   // 32 bit feed
  ctx->fb = 1;                    // feedback (decrypts nt in feed)
  uint32_t k = 0;
  for(int i = 31; i >= 0; i--)
    k |= (uint32_t)(crypto1_keystream_bit(ctx) << (i ^ 7));
  *nt ^= k;
  ctx->fb = 0;                    // feedback off
}

// input: key, UID, (un-encrypted) nt
void crypto1_auth1_plain(crypto1_ctx_t *ctx, const uint8_t key[6], uint32_t uid, uint32_t nt) {
  ctx->x = keybits((((uint64_t)key[0])<<40) | (((uint64_t)key[1])<<32) | (((uint64_t)key[2])<<24) | (((uint64_t)key[3])<<16) | (((uint64_t)key[4])<<8) | (((uint64_t)key[5])));
  ctx->f = feedbits(uid^nt);      // 32 bit feed
  ctx->fb = 0;                    // no feedback
  for(int i = 0; i < 32; i++)
    crypto1_keystream_bit(ctx); // result ignored
}

// input: key, UID, (un-encrypted) nt
// output: nt and parity bits to send to reader
void crypto1_auth1_tag(crypto1_ctx_t *ctx, const uint8_t key[6], const uint32_t uid, uint32_t *nt, uint32_t *nt_p) {
  if(ctx->state != CRYPTO1_OFF)
    crypto1_auth1_nested_tag(ctx, key, uid, nt, nt_p);   // uses both encrypted nt and encrypted parity bits
  else
  {
    crypto1_auth1_plain(ctx, key, uid, *nt);
    *nt_p = crypto1_parity(*nt);   // return unencrypted parity bits
  }
}

// input: key, UID, nt received from tag
// output: un-encrypted nt
void crypto1_auth1_reader(crypto1_ctx_t *ctx, const uint8_t key[6], const uint32_t uid, uint32_t *nt) {
  if(ctx->state != CRYPTO1_OFF)
    crypto1_auth1_nested_reader(ctx, key, uid, nt);
  else
    crypto1_auth1_plain(ctx, key, uid, *nt);
}

// inut: nr, ar(=suc64(nt))
// output: encrypted nr, ar and their parity bits to send to tag
void crypto1_auth2_reader(crypto1_ctx_t *ctx, uint32_t *nr, uint32_t *nr_p, uint32_t *ar, uint32_t *ar_p) {
  ctx->f = feedbits(*nr);         // 32 bit feed
  ctx->fb = 0;                    // no feedback
  uint32_t k = 0;
  for(int i = 31; i >= 0; i--) {
    k |= (uint32_t)(crypto1_keystream_bit(ctx) << (i ^ 7));
    if(i%8 == 0) {
      *nr_p <<= 8;
      *nr_p |= (!__builtin_parity(*nr >> 24)) ^ crypto1_keystream_peek(ctx);
      *nr = __builtin_rotateleft32(*nr, 8);
    }
  }
  *nr ^= k;

  k = 0;
  for(int i = 31; i >= 0; i--) {
    k |= (uint32_t)(crypto1_keystream_bit(ctx) << (i ^ 7));
    if(i%8 == 0) {
      *ar_p <<= 8;
      *ar_p |= (!__builtin_parity(*ar >> 24)) ^ crypto1_keystream_peek(ctx);
      *ar = __builtin_rotateleft32(*ar, 8);
    }
  }
  *ar ^= k;
}

// inut: encrypted nr, ar received from reader
// output: un-encrypted nr, ar
void crypto1_auth2_tag(crypto1_ctx_t *ctx, uint32_t *nr, uint32_t *ar) {
  ctx->f = feedbits(*nr);         // 32 bit feed
  ctx->fb = 1;                    // feedback (decrypts nr in feed)
  uint32_t k = 0;
  for(int i = 31; i >= 0; i--)
    k |= (uint32_t)(crypto1_keystream_bit(ctx) << (i ^ 7));
  *nr ^= k;
  ctx->fb = 0;                    // feedback off

  k = 0;
  for(int i = 0; i < 32; i++)
    k |= (uint32_t)(crypto1_keystream_bit(ctx) << (i ^ 7));
  *ar ^= k;
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

void crypto1_decrypt(crypto1_ctx_t *ctx, uint8_t *data, size_t len) {
  for(int i = 0; i < len; i++)
    data[i] = crypto1_decrypt_8(ctx, data[i]);
}

void crypto1_encrypt(crypto1_ctx_t *ctx, uint8_t *data, const size_t len, uint8_t *parity) {
  for(int i = 0; i < len; i++)
    data[i] = crypto1_encrypt_8(ctx, data[i], &parity[i]);
}
