/**
 * Copyright (C) 2011 Anders Sundman <anders@4zm.org>
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
 */

#include <openssl/evp.h>
#include <openssl/provider.h>
#include <string.h>
#include "util.h"
#include "mac.h"
#include "tag.h"

// The DES MAC key in use
unsigned char current_mac_key[8] = { 0 };


/**
 * Compute a DES MAC, use DES in CBC mode.
 * The length specifies the length of the input in bytes and must be a multiple of 8.
 */
int compute_mac(const unsigned char* input, unsigned char output[8], const unsigned char key[8], size_t length) {
  static int init = 0;
  static OSSL_PROVIDER *deflt, *legacy;
  if(!init) {
    legacy = OSSL_PROVIDER_load(NULL, "legacy");
    deflt = OSSL_PROVIDER_load(NULL, "default");
    init = 1;
    (void)legacy;
    (void)deflt;
    // OSSL_PROVIDER_unload(legacy);
    // OSSL_PROVIDER_unload(deflt);
  }

  if(length%8) return -1;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "DES-CBC", NULL);
  if(!ctx || !cipher) return -1;

  int res = -1, len;
  unsigned char ivec[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };      // IV is all zeroes
  if(!EVP_EncryptInit(ctx, cipher, key, ivec)) goto error;
  for(; length > 0; length -= 8, input += 8)
    if(!EVP_EncryptUpdate(ctx, output, &len, input, 8)) goto error;
  res = 0;
error:
  EVP_CIPHER_free(cipher);
  EVP_CIPHER_CTX_free(ctx);
  return res;
}

/**
 * Compute the MAC of a given block with the specified 8 byte key. Return a 8 byte MAC value.
 * If update is nonzero, the mac of the current tag is updated.
 */
unsigned char* compute_block_mac(uint8_t block, const unsigned char key[8], bool update) {
  static unsigned char output[8];

  // Input to MAC algo [ 4 serial | 14 data | 6 0-pad ]
  unsigned char input[24];
  memcpy(&input, current_tag.amb[0].mbm.abtUID, 4);
  memcpy(&input[4], current_tag.amb[block].mbd.abtData, 14);
  memset(&input[18], 0, 6);

  if(compute_mac(input, output, key, sizeof(input))) return NULL;
  if(update)
    memcpy(&current_tag.amb[block].mbd.abtData[14], output, 2);

  return output;
}
