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

#pragma pack(push,1)
typedef struct {
  uint8_t nt[4];
  uint8_t nr[4];
  uint8_t ar[4];
  uint8_t at[4];
  uint8_t a_ref[4];
  uint8_t nt_p[4];
  uint8_t nr_p[4];
  uint8_t ar_p[4];
  uint8_t at_p[4];
} crypto1_auth_t;
#pragma pack(pop)

void crypto1_decrypt_bits(crypto1_ctx_t *ctx, uint8_t *data, size_t len);
void crypto1_encrypt_bits(crypto1_ctx_t *ctx, uint8_t *data, size_t len);
void crypto1_decrypt(crypto1_ctx_t *ctx, uint8_t *data, const size_t len);
void crypto1_encrypt(crypto1_ctx_t *ctx, uint8_t *data, const size_t len, uint8_t *parity);

// input: key, UID, nt received from reader, nr
// output: un-encrypted nt, encrypted nr+parity, encrypted ar+parity to send to tag, expected at
void crypto1_auth_reader(crypto1_ctx_t *ctx, const uint8_t key[6], const uint8_t uid[4], crypto1_auth_t *a);

// inut: encrypted nr, encrypted ar received from reader
// output: un-encrypted nr, unencrypted ar
void crypto1_auth_tag1(crypto1_ctx_t *ctx, const uint8_t key[6], const uint8_t uid[4], crypto1_auth_t *a);

// inut: encrypted nr, ar received from reader
// output: un-encrypted nr, unencrypted ar, encrypted at+parity to send to tag, expected ar
void crypto1_auth_tag2(crypto1_ctx_t *ctx, crypto1_auth_t *a);

#endif