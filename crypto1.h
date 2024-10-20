#ifndef CRYPTO1__H
#define CRYPTO1__H

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

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

typedef enum {
  CRYPTO1_OFF = 0,
  CRYPTO1_REAUTH = 1,
  CRYPTO1_ON_A = 2,     // bit 1 = on(1), bit 0 = A(0)
  CRYPTO1_ON_B = 3      // bit 1 = on(1), bit 0 = B(1)
} crypto1_state_t;

typedef struct {
  uint64_t x;
  uint32_t f, fb;       // feed bits, feedback flag
  crypto1_state_t state;
} crypto1_ctx_t;

void crypto1_ar(uint8_t nt[4]);
void crypto1_at(uint8_t ar[4]);

void crypto1_decrypt_bits(crypto1_ctx_t *ctx, uint8_t *data, size_t len);
void crypto1_encrypt_bits(crypto1_ctx_t *ctx, uint8_t *data, size_t len);
void crypto1_decrypt(crypto1_ctx_t *ctx, uint8_t *data, const size_t len);
void crypto1_encrypt(crypto1_ctx_t *ctx, uint8_t *data, const size_t len, uint8_t *parity);

// input: key, UID, received (encrypted) nt
// output: decrypted nt
void crypto1_auth1_nested_reader(crypto1_ctx_t *ctx, const uint8_t key[6], const uint8_t uid[4], uint8_t nt[4]);

// input: key, UID, (un-encrypted) nt
// output: encrypted nt, encrypted parity bits
void crypto1_auth1_nested_tag(crypto1_ctx_t *ctx, const uint8_t key[6], const uint8_t uid[4], uint8_t nt[4], uint8_t nt_p[4]);

// input: key, UID, (un-encrypted) nt
void crypto1_auth1_plain(crypto1_ctx_t *ctx, const uint8_t key[6], const uint8_t uid[4], const uint8_t nt[4]);

// input: key, UID, (un-encrypted) nt
// output: nt to send to reader
void crypto1_auth1_tag(crypto1_ctx_t *ctx, const uint8_t key[6], const uint8_t uid[4], uint8_t nt[4], uint8_t nt_p[4]);

// input: key, UID, nt received from reader
// output: un-encrypted nt
void crypto1_auth1_reader(crypto1_ctx_t *ctx, const uint8_t key[6], const uint8_t uid[4], uint8_t nt[4]);

// inut: nr, ar(=suc64(nt))
// output: encrypted nr, ar to send to tag
void crypto1_auth2_reader(crypto1_ctx_t *ctx, uint8_t nr[4], uint8_t nr_p[4], uint8_t ar[4], uint8_t ar_p[4]);

// inut: encrypted nr, ar received from reader
// output: un-encrypted nr, ar
void crypto1_auth2_tag(crypto1_ctx_t *ctx, uint8_t nr[4], uint8_t ar[4]);

#endif