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

/**
 * @file nfc-emulate-tag.c
 * @brief Emulates a simple tag
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <nfc/nfc.h>

#include "emulator.h"
#include "tag.h"
#include "crypto1.h"
#include "util.h"

#define DEBUG 1

int nfc_target_send_crypto1_bytes(nfc_device *device, crypto1_ctx_t *ctx, uint8_t *data_out, size_t len, const bool crc) {
  uint8_t tx[len+2], ptx[len+2];
  memcpy(tx, data_out, len);
  if(crc) {
    iso14443a_crc_append(tx, len);
    len += 2;
  }
  if(ctx->state == CRYPTO1_OFF)
  {
    for(int i = 0; i < len; i++)
      ptx[i] = (uint8_t)(!__builtin_parity(tx[i]));
  }
  else
    crypto1_encrypt(ctx, tx, len, ptx);
  return nfc_target_send_bits(device, data_out, 8*len, ptx);
}

int nfc_target_receive_crypto1_bytes(nfc_device *device, crypto1_ctx_t *ctx, uint8_t *data_in, size_t len, const bool crc) {
  uint8_t prx[len];
  int rx_len = nfc_target_receive_bits(device, data_in, 8*len, prx);
  if(rx_len < 0) return rx_len;
  if(rx_len%8 != 0) printf("Did not receive full bytes: %u bits left\n", rx_len%8);
  if(ctx->state != CRYPTO1_OFF)
    crypto1_decrypt(ctx, data_in, (size_t)rx_len/8);
  return rx_len/8 - (crc ? 2 : 0);
}

static inline void put32(const uint32_t u, uint8_t *p) {
  p[0] = (uint8_t)(u >> 24);
  p[1] = (uint8_t)(u >> 16);
  p[2] = (uint8_t)(u >>  8);
  p[3] = (uint8_t)(u);
}

static inline uint32_t get32(const uint8_t *p) {
  return (((uint32_t)p[0])<<24) | (((uint32_t)p[1])<<16) | (((uint32_t)p[2])<<8) | ((uint32_t)p[3]);
}

int emulate_auth(emulator_data_t *ed, const uint8_t *data_in, uint8_t *data_out) {
  uint32_t nt0 = (uint32_t)random(), nt = nt0, nt_p = 0;
  uint8_t *key = (data_in[0] == 0x60) ? ed->tag->amb[block_to_trailer(data_in[1])].mbt.abtKeyA : ed->tag->amb[block_to_trailer(data_in[1])].mbt.abtKeyB;
  uint32_t uid = get32(ed->tag->amb[0].mbm.abtUID);

  // initialize
  crypto1_auth1_tag(&ed->ctx, key, uid, &nt, &nt_p);
  ed->ctx.state = CRYPTO1_OFF;

  // send (possibly encrypted) nt and receive response
  uint8_t par_out[8];
  put32(nt, data_out);
  put32(nt_p, par_out);
  printf("    Sending nonce 0x%0x (original: 0x%0x): ", nt, nt0);
  print_hex_array_sep(data_out, 4, " ");
  printf("\n");
  int rx_len = 0;
  if (nfc_target_send_bits(ed->device, data_out, 4*8, par_out) < 0 ||
      (rx_len = nfc_target_receive_bits(ed->device, data_out, 8*8, par_out)) < 0) {
    nfc_perror(ed->device, "auth1");
    return 0;
  }
  //if(rx_len != 64) return 0;
  printf("    Received (%u bits): ", rx_len);
  rx_len /= 8;
  print_hex_array_sep(data_out, (size_t)rx_len, " ");
  printf("\n");
  // interpret received encrypted nr, ar
  uint32_t nr = get32(data_out);
  uint32_t ar = get32(data_out+4);
  crypto1_auth2_tag(&ed->ctx, &nr, &ar);
  if(crypto1_ar(nt0) != ar) {
    printf("Error: ar does not match: got 0x%0x expected 0x%0x\n", ar, crypto1_ar(nt0));
    return 0;
  }
  // return at to complete the authentication
  uint32_t at = crypto1_at(nr);
  put32(at, data_out);
  ed->ctx.state = (data_in[0] == 0x60) ? CRYPTO1_ON_A : CRYPTO1_ON_B;
  if (nfc_target_send_crypto1_bytes(ed->device, &ed->ctx, data_out, 4, false) < 0) {
    ed->ctx.state = CRYPTO1_OFF;
    nfc_perror(ed->device, "auth2");
    return 0;
  }

  return 0;
}

int emulate_target_io(emulator_data_t *ed, const uint8_t *data_in, const size_t data_in_len, uint8_t *data_out, const size_t data_out_len)
{
  nfc_target *nt = ed->target;
  mf_tag_t *tag = ed->tag;

  int res = 0;  // number of bytes to write or negative to end loop

  if (data_in_len) {
    if (DEBUG) {
      printf("    In: ");
      print_hex_array_sep(data_in, data_in_len, " ");
      printf("\n");
    }
    switch (data_in[0]) {
      case 0x30: // Mifare read, block address in data_in[1]
        // XXX check crypto is on, access permissions, blank out key data
        res = 16;
        memcpy(data_out, tag->amb[data_in[1]].mbd.abtData, 16);
        break;
      case 0x50: // HLTA (ISO14443-3)
        if (DEBUG) {
          printf("Initiator HLTA me. Bye!\n");
        }
        res = -1;
        break;
      case 0x60: // Mifare authA
      case 0x61: // Mifare authB
        res = emulate_auth(ed, data_in, data_out);
        break;
      case 0xe0: // RATS (ISO14443-4)
        res = (int)(nt->nti.nai.szAtsLen + 1);
        data_out[0] = (uint8_t)(nt->nti.nai.szAtsLen + 1); // ISO14443-4 says that ATS contains ATS_Length as first byte
        if (nt->nti.nai.szAtsLen) {
          memcpy(data_out + 1, nt->nti.nai.abtAts, nt->nti.nai.szAtsLen);
        }
        break;
      case 0xc2: // S-block DESELECT
        if (DEBUG) {
          printf("Initiator DESELECT. Bye!\n");
        }
        res = -1;
        break;
      default: // Unknown
        if (DEBUG) {
          printf("Unknown frame, emulated target abort.\n");
        }
        res = -1;
    }
  }
  // Show transmitted command
  if ((DEBUG) && res > 0) {
    printf("    Out: ");
    print_hex_array_sep(data_out, (size_t)res, " ");
    printf("\n");
  }
  return res;
}



#define ISO7816_C_APDU_COMMAND_HEADER_LEN 4
#define ISO7816_SHORT_APDU_MAX_DATA_LEN 256
#define ISO7816_SHORT_C_APDU_MAX_OVERHEAD 2
#define ISO7816_SHORT_R_APDU_RESPONSE_TRAILER_LEN 2

#define ISO7816_SHORT_C_APDU_MAX_LEN (ISO7816_C_APDU_COMMAND_HEADER_LEN + ISO7816_SHORT_APDU_MAX_DATA_LEN + ISO7816_SHORT_C_APDU_MAX_OVERHEAD)
#define ISO7816_SHORT_R_APDU_MAX_LEN (ISO7816_SHORT_APDU_MAX_DATA_LEN + ISO7816_SHORT_R_APDU_RESPONSE_TRAILER_LEN)

int emulate_target(emulator_data_t *ed)
{
  uint8_t abtRx[ISO7816_SHORT_R_APDU_MAX_LEN];
  uint8_t abtTx[ISO7816_SHORT_C_APDU_MAX_LEN];

  int res;
  if ((res = nfc_target_init(ed->device, ed->target, abtRx, sizeof(abtRx), 0)) < 0) {
    return res;
  }

  // switch to bare metal communication
  if (nfc_device_set_property_bool(ed->device, NP_HANDLE_CRC, false) < 0 ||
      nfc_device_set_property_bool(ed->device, NP_ACCEPT_INVALID_FRAMES, true) < 0 ||
      nfc_device_set_property_bool(ed->device, NP_AUTO_ISO14443_4, false) < 0 ||
      nfc_device_set_property_bool(ed->device, NP_ACTIVATE_CRYPTO1, false) < 0 ||
      nfc_device_set_property_bool(ed->device, NP_EASY_FRAMING, false) < 0 ||
      nfc_device_set_property_bool(ed->device, NP_HANDLE_PARITY, false) < 0 ) {
    return 0;
  }

  size_t szRx = (size_t)res;
  int io_res = res;
  while (io_res >= 0) {
    io_res = emulate_target_io(ed, abtRx, szRx, abtTx, sizeof(abtTx));
    if (io_res > 0) {
      if ((res = nfc_target_send_crypto1_bytes(ed->device, &ed->ctx, abtTx, (size_t)io_res, true)) < 0) {
        return res;
      }
    }
    if (io_res >= 0) {
      if ((res = nfc_target_receive_crypto1_bytes(ed->device, &ed->ctx, abtRx, sizeof(abtRx), true)) < 0) {
        return res;
      }
      szRx = (size_t)res;
    }
  }
  return io_res;
}




















int nfc_initiator_transceive_crypto1_bytes(nfc_device *device, crypto1_ctx_t *ctx, uint8_t *data_out, size_t len, uint8_t *data_in, size_t max_len, const bool crc) {
  uint8_t tx[len+2], ptx[len+2], prx[max_len];
  memcpy(tx, data_out, len);
  if(crc) {
    iso14443a_crc_append(tx, len);
    len += 2;
  }
  if(ctx->state == CRYPTO1_OFF)
  {
    for(int i = 0; i < len; i++)
      ptx[i] = (uint8_t)(!__builtin_parity(tx[i]));
  }
  else
    crypto1_encrypt(ctx, tx, len, ptx);
  int rx_len = nfc_initiator_transceive_bits(device, tx, 8*len, ptx, data_in, max_len, prx);
  if(rx_len < 0) return rx_len;
  if(rx_len%8 != 0) printf("Did not receive full bytes: %u, %u bits left\n", rx_len, rx_len%8);
  if(ctx->state != CRYPTO1_OFF)
    crypto1_decrypt(ctx, data_in, (size_t)rx_len/8);
  return rx_len/8 - (crc ? 2 : 0);
}

int emulate_reader_auth(emulator_data_t *ed, mf_key_type_t key_type, uint8_t block) {
  uint8_t *key = (key_type == MF_KEY_A) ? ed->tag->amb[block_to_trailer(block)].mbt.abtKeyA : ed->tag->amb[block_to_trailer(block)].mbt.abtKeyB;
  uint32_t uid = get32(ed->target->nti.nai.abtUid);

  printf("    Key: ");
  print_hex_array_sep(key, (size_t)6, " ");
  printf("\n");

  uint8_t data[16], pdata[16], datb[16], pdatb[16];

  // send read command
  data[0] = (key_type == MF_KEY_A) ? 0x60 : 0x61;
  data[1] = block;
  iso14443a_crc_append(data, 2);
  int rx_len = nfc_initiator_transceive_crypto1_bytes(ed->device, &ed->ctx, data, 4, data, sizeof(data), false);
  if(rx_len < 4) return 0;

  printf("    Received: ");
  print_hex_array_sep(data, (size_t)rx_len, " ");
  printf("\n");

  // initialize with nt sent by tag
  uint32_t nt = get32(data);
  printf("nt (enc): %08x ", nt);
  crypto1_auth1_reader(&ed->ctx, key, uid, &nt);
  printf("  (dec): %08x\n", nt);
  ed->ctx.state = CRYPTO1_OFF;

  // send encrypted nr, ar
  uint32_t ar = crypto1_ar(nt), ar_p = 0;
  //uint32_t nr = (uint32_t)random(), nr_p = 0;
  uint32_t nr = 0, nr_p = 0;
  printf("nr: %08x       ar: %08x\n", nr, ar);
  crypto1_auth2_reader(&ed->ctx, &nr, &nr_p, &ar, &ar_p);
  printf("nr (enc): %08x (%08x)       ar (enc): %08x (%08x)\n", nr, nr_p, ar, ar_p);
  put32(nr, data);
  put32(ar, data+4);
  put32(nr_p, pdata);
  put32(ar_p, pdata+4);
  rx_len = nfc_initiator_transceive_bits(ed->device, data, 8*8, pdata, datb, sizeof(datb)*8, pdatb);  // fails here (meaning parity bits are wrong?)
  if(rx_len < 0) return 0;

  printf("    Received (%i bits): ", rx_len);
  print_hex_array_sep(datb, (size_t)rx_len/8, " ");
  printf("\n");

  if(rx_len < 4*8) return 0;
  crypto1_decrypt(&ed->ctx, datb, 4);
  // check received encrypted at
  uint32_t at = get32(datb);
  if(crypto1_at(nt) != at) {  // nt or nr?
    printf("Error: ar does not match: got 0x%0x expected 0x%0x\n", at, crypto1_at(nt));
    return 0;
  }

  ed->ctx.state = (key_type == MF_KEY_A) ? CRYPTO1_ON_A : CRYPTO1_ON_B;
  printf("Successfully authenticated\n");
  return 0;
}

int emulate_reader(emulator_data_t *ed)
{
  //uint8_t abtRx[ISO7816_SHORT_R_APDU_MAX_LEN];
  //uint8_t abtTx[ISO7816_SHORT_C_APDU_MAX_LEN];

  // switch to bare metal communication
  if (nfc_device_set_property_bool(ed->device, NP_HANDLE_CRC, false) < 0 ||
      nfc_device_set_property_bool(ed->device, NP_ACCEPT_INVALID_FRAMES, true) < 0 ||
      nfc_device_set_property_bool(ed->device, NP_AUTO_ISO14443_4, false) < 0 ||
      nfc_device_set_property_bool(ed->device, NP_ACTIVATE_CRYPTO1, false) < 0 ||
      nfc_device_set_property_bool(ed->device, NP_EASY_FRAMING, false) < 0 ||
      nfc_device_set_property_int(ed->device, NP_TIMEOUT_COM, 100) < 0 || //   up from 52ms
      nfc_device_set_property_bool(ed->device, NP_HANDLE_PARITY, false) < 0 ) {
    return 0;
  }

  bzero(&ed->ctx, sizeof(ed->ctx));

  emulate_reader_auth(ed, MF_KEY_A, 0);

  uint8_t tx[48], rx[48];
  int rx_len;
  tx[0] = 48; tx[1] = 0;
  rx_len = nfc_initiator_transceive_crypto1_bytes(ed->device, &ed->ctx, tx, 2, rx, sizeof(rx), true);
  printf("    Received (%i bytes): ", rx_len);
  print_hex_array_sep(rx, (size_t)rx_len, " ");
  printf("\n");

  emulate_reader_auth(ed, MF_KEY_A, 4);
  rx_len = nfc_initiator_transceive_crypto1_bytes(ed->device, &ed->ctx, tx, 2, rx, sizeof(rx), true);
  printf("    Received (%i bytes): ", rx_len);
  print_hex_array_sep(rx, (size_t)rx_len, " ");
  printf("\n");

  return 0;
}