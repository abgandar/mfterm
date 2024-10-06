/**
 * Copyright (C) 2024 Alexander Wittig <abgandar@gmail.com>
 *
 * This file is part of mfterm.
 *
 * mfterm is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mfterm is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with mfterm.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "mad.h"

const aid_t AIDs[] = {
  {"NDEF",      0xe103},
  {"FREE",      0x0000},
  {"DEF",       0x0001},    // alias
  {"DEFECT",    0x0001},
  {"RES",       0x0002},    // alias
  {"RESERVED",  0x0002},
  {"DIR",       0x0003},    // alias
  {"DIRECTORY", 0x0003},
  {"INFO",      0x0004},
  {"VOID",      0x0005},    // alias
  {"UNUSED",    0x0005},
  {NULL,        0x0000}
};

static const uint8_t mad_key_A[] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5};

static uint8_t do_crc(uint8_t c, const uint8_t v) {
  c ^= v;
  for (int i = 0; i < 8; i++) {
    if (c&0x80) {
      c = (uint8_t)((c<<1) ^ 0x1d);
    } else {
      c <<= 1;
    }
  }
  return c;
}

void mad_calc_crc(mf_tag_t* tag, uint8_t crcs[2]) {
  uint8_t crc = 0xc7;
  for (int i = 1; i < 16; i++)
    crc = do_crc(crc, tag->amb[0x01].mbd.abtData[i]);
  for (int i = 0; i < 16; i++)
    crc = do_crc(crc, tag->amb[0x02].mbd.abtData[i]);
  crcs[0] = crc;

  crc = 0xc7;
  for (int i = 1; i < 16; i++)
    crc = do_crc(crc, tag->amb[0x40].mbd.abtData[i]);
  for (int i = 0; i < 16; i++)
    crc = do_crc(crc, tag->amb[0x41].mbd.abtData[i]);
  for (int i = 0; i < 16; i++)
    crc = do_crc(crc, tag->amb[0x42].mbd.abtData[i]);
  crcs[1] = crc;
}

int mad_crc(mf_tag_t* tag) {
  uint8_t crcs[2];
  mad_calc_crc(tag, crcs);
  tag->amb[0x01].mbd.abtData[0] = crcs[0];
  // version 2 MAD?
  if ((tag->amb[3].mbt.abtAccessBits[3] & 0x03) == 0x02)
    tag->amb[0x40].mbd.abtData[0] = crcs[1];

  return 0;
}

int mad_set_info(mf_tag_t* tag, size_t sector) {
  if (sector < 0 || sector > 0x27 || sector == 0x10)
    return -1;

  tag->amb[0x01].mbd.abtData[1] = (uint8_t)sector;

  // version 2 MAD?
  if ((tag->amb[0x03].mbt.abtAccessBits[3] & 0x03) == 0x02)
    tag->amb[0x40].mbd.abtData[1] = (uint8_t)sector;

  return mad_crc(tag);
}

int mad_put_aid(mf_tag_t* tag, size_t sector, uint16_t aid) {
  if (sector < 1 || sector > 0x20 || sector == 0x10)
    return -1;

  if (sector <= 0x0F) {
    int byte = (int)sector*2;
    tag->amb[0x01+byte/16].mbd.abtData[byte%16] = (uint8_t)(aid&0xFF);
    tag->amb[0x01+byte/16].mbd.abtData[byte%16+1] = (uint8_t)((aid>>8)&0xFF);
  } else {
    int byte = (int)(sector-0x10)*2;
    tag->amb[0x40+byte/16].mbd.abtData[byte%16] = (uint8_t)(aid&0xFF);
    tag->amb[0x40+byte/16].mbd.abtData[byte%16+1] = (uint8_t)((aid>>8)&0xFF);
  }

  return mad_crc(tag);
}

int mad_init(mf_tag_t* tag, mf_size_t size) {
  uint8_t mad_ac[] = {0x78, 0x77, 0x88, size == MF_1K ? 0b11000001 : 0b11000010 };

  memset(tag->amb[0x01].mbd.abtData, 0, 16);
  memset(tag->amb[0x02].mbd.abtData, 0, 16);
  memcpy(tag->amb[0x03].mbt.abtKeyA, mad_key_A, sizeof(mad_key_A));
  memcpy(tag->amb[0x03].mbt.abtAccessBits, mad_ac, sizeof(mad_ac));

  if (size == MF_4K) {
    memset(tag->amb[0x40].mbd.abtData, 0, 16);
    memset(tag->amb[0x41].mbd.abtData, 0, 16);
    memset(tag->amb[0x42].mbd.abtData, 0, 16);
    memcpy(tag->amb[0x43].mbt.abtKeyA, mad_key_A, sizeof(mad_key_A));
    mad_ac[3] = 0;
    memcpy(tag->amb[0x43].mbt.abtAccessBits, mad_ac, sizeof(mad_ac));
  }

  return mad_crc(tag);
}

int mad_size(mf_tag_t* tag, mf_size_t size) {
  uint8_t flag = (size == MF_4K) ? 2 : 1;

  tag->amb[0x03].mbt.abtAccessBits[3] = (tag->amb[0x03].mbt.abtAccessBits[3] & 0xfc) | flag;
  if (size == MF_4K)
    tag->amb[0x43].mbt.abtAccessBits[3] = 0;

  printf("MAD version set to %hhd\n", flag);
  return mad_crc(tag);
}

static const char* find_AID(const uint16_t val) {
  static char str[5];
  for (const aid_t *aid = AIDs; aid->name; aid++ ) {
    if (aid->val == val) return aid->name;
  }
  snprintf(str, 5, "%04hX", val);
  str[4] = '\0';
  return str;
}

int mad_print(mf_tag_t* tag) {
  const uint8_t gpb1 = tag->amb[0x03].mbt.abtAccessBits[3];
  if (!(gpb1 & 0x80)) {
    printf("MAD not in use\n");
    return 0;
  }
  const uint8_t version = gpb1 & 0x03;
  printf("MAD version: %s\n", version == 1 ? "1" : (version == 2 ? "2" : "invalid"));
  printf("Card type:   %s\n", gpb1 & 0x40 ? "multi application" : "single application");
  const int key = memcmp(tag->amb[0x03].mbt.abtKeyA, mad_key_A, 6);
  printf("MAD1 key:    %s\n\n", key == 0 ? "MAD public key A" : "proprietary");
  uint8_t crcs[2];
  mad_calc_crc(tag, crcs);
  const uint8_t crc1 = tag->amb[0x01].mbd.abtData[0];
  printf("MAD1 CRC:    %s (tag: %02hhx, crc: %02hhx)\n", crcs[0] == crc1 ? "valid" : "invalid", crc1, crcs[0]);
  const uint8_t info1 = tag->amb[0x01].mbd.abtData[1];
  printf("MAD1 info:   %02hhx\n", info1 & 0x3f);

  if (version == 2) {
    const int key = memcmp(tag->amb[0x43].mbt.abtKeyA, mad_key_A, 6);
    printf("\nMAD2 key:    %s\n", key == 0 ? "MAD public key A" : "proprietary");
    const uint8_t crc2 = tag->amb[0x40].mbd.abtData[0];
    printf("MAD2 CRC:    %s (tag: %02hhx, crc: %02hhx)\n", crcs[1] == crc2 ? "valid" : "invalid", crc2, crcs[1]);
    const uint8_t info2 = tag->amb[0x41].mbd.abtData[1];
    printf("MAD2 info:   %02hhx\n", info2 & 0x3f);
  }

  // print MAD1 allocation
  printf("\n      00      01      02      03      04      05      06      07\n00   MAD1    ");
  for (int i = 1; i < 16; i++) {
    if (i%8 == 0) printf("\n%02x   ", i);
    uint16_t val;
    val = (uint16_t)(tag->amb[0x01+(2*i)/16].mbd.abtData[(2*i)%16] | tag->amb[0x01+(2*i)/16].mbd.abtData[(2*i)%16+1]<<8);
    printf("%-6s  ", find_AID(val));
  }
  printf("\n");

  if (version == 2) {
    // print MAD2 allocation
    printf("\n10   MAD2    ");
    for (int i = 1; i < 24; i++) {
      if (i%8 == 0) printf("\n%02x   ", i+16);
      uint16_t val;
      val = (uint16_t)(tag->amb[0x40+(2*i)/16].mbd.abtData[(2*i)%16] | tag->amb[0x40+(2*i)/16].mbd.abtData[(2*i)%16+1]<<8);
      printf("%-6s  ", find_AID(val));
    }
    printf("\n");
  }

  return 0;
}