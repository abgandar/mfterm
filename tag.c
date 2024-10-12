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
#include "mifare.h"
#include "util.h"
#include "tag.h"
#include "mad.h"

mf_tag_t current_tag;
mf_tag_t current_auth;

void clear_non_auth_data(mf_tag_t* tag);

int load_mfd(const char* fn, mf_tag_t* tag) {
  mf_tag_t temp;
  FILE* mfd_file = fopen(fn, "rb");

  if (mfd_file == NULL) {
    return -1;
  }

  if (fread(&temp, 1, sizeof(mf_tag_t), mfd_file) != sizeof(mf_tag_t)) {
    fclose(mfd_file);
    return -2;
  }

  fclose(mfd_file);
  memcpy(tag, &temp, sizeof(mf_tag_t));
  return 0;
}

int save_mfd(const char* fn, const mf_tag_t* tag) {
  FILE* mfd_file = fopen(fn, "w");

  if (mfd_file == NULL) {
    return -1;
  }

  if (fwrite(tag, 1, sizeof(mf_tag_t), mfd_file) != sizeof(mf_tag_t)) {
    fclose(mfd_file);
    return -2;
  }

  fclose(mfd_file);
  return 0;
}

int load_txt(const char* fn, mf_tag_t* tag) {
  mf_tag_t temp;
  FILE* key_file = fopen(fn, "r");

  if (key_file == NULL) {
    return -1;
  }

  for (size_t sector = 0; sector < sector_count(MF_4K); sector++) {
    uint8_t k[12];
    if( fscanf( key_file, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx %2hhx%2hhx%2hhx%2hhx%2hhx%2hhx", k, k+1, k+2, k+3, k+4, k+5, k+6, k+7, k+8, k+9, k+10, k+11 ) != 12 )
    {
      fclose(key_file);
      return -2;
    }

    size_t block = sector_to_trailer(sector);
    key_to_tag(&temp, k, MF_KEY_A, block);
    key_to_tag(&temp, k+6, MF_KEY_B, block);
  }

  fclose(key_file);
  memcpy(tag, &temp, sizeof(mf_tag_t));
  return 0;
}

int save_txt(const char* fn, const mf_tag_t* tag) {
 FILE* key_file = fopen(fn, "w");

  if (key_file == NULL) {
    return -1;
  }

  for (size_t sector = 0; sector < sector_count(MF_4K); sector++) {
    size_t block = sector_to_trailer(sector);

    const uint8_t* key = key_from_tag(tag, MF_KEY_A, block);
    const int r1 = fprintf(key_file, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\t", key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], key[8], key[9], key[10], key[11]);

    key = key_from_tag(tag, MF_KEY_B, block);
    const int r2 = fprintf(key_file, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], key[8], key[9], key[10], key[11]);

    if (r1 < 0 || r2 < 0) {
      fclose(key_file);
      return -2;
    }
  }

  fclose(key_file);
  return 0;
}

int load_tag(const char* fn) {
  return load_mfd(fn, &current_tag);
}

int save_tag(const char* fn) {
  return save_mfd(fn, &current_tag);
}

int load_auth(const char* fn) {
  if (load_txt(fn, &current_auth) == 0)
    return 0;

  if (load_mfd(fn, &current_auth))
      return 1;

  clear_non_auth_data(&current_auth);
  return 0;
}

int save_auth(const char* fn) {
  return save_txt(fn, &current_tag);
}

int import_auth(mf_key_type_t key_type, size_t s1, size_t s2) {
  for( size_t sector = s1; sector <= s2; sector++ ) {
    size_t block = sector_to_trailer(sector);

    if( key_type == MF_KEY_A || key_type == MF_KEY_AB ) {
      const uint8_t* key = key_from_tag(&current_tag, MF_KEY_A, block);
      key_to_tag(&current_auth, key, MF_KEY_A, block);
    }

    if( key_type == MF_KEY_B || key_type == MF_KEY_AB ) {
      const uint8_t* key = key_from_tag(&current_tag, MF_KEY_B, block);
      key_to_tag(&current_auth, key, MF_KEY_B, block);
    }
  }
  return 0;
}

int export_auth(mf_key_type_t key_type, size_t s1, size_t s2) {
  for( size_t sector = s1; sector <= s2; sector++ ) {
    size_t block = sector_to_trailer(sector);

    if( key_type == MF_KEY_A || key_type == MF_KEY_AB ) {
      const uint8_t* key = key_from_tag(&current_auth, MF_KEY_A, block);
      key_to_tag(&current_tag, key, MF_KEY_A, block);
    }

    if( key_type == MF_KEY_B || key_type == MF_KEY_AB ) {
      const uint8_t* key = key_from_tag(&current_auth, MF_KEY_B, block);
      key_to_tag(&current_tag, key, MF_KEY_B, block);
    }
  }
  return 0;
}

void print_tag_byte_bits(size_t byte, size_t first_bit, size_t last_bit) {
  uint8_t data = current_tag.amb[byte / 16].mbd.abtData[byte % 16];

  printf("[");

  for (size_t i = 0; i < 8; ++i) {
    // Separate nibbles
    if (i == 4)
      printf(" ");

    // Outside mask
    if (i < first_bit || i > last_bit) {
      printf("-");
      continue;
    }

    // Inside mask
    if ((1<<i) & data)
      printf("1");
    else
      printf("0");
  }

  printf("]");
}

void print_tag_bytes(size_t first_byte, size_t last_byte) {
  while (first_byte <= last_byte) {
    size_t byte_len = last_byte - first_byte;

    // Fill up start with spaces
    size_t block_offset = first_byte % 16;
    for (size_t i = 0; i < block_offset; ++i)
      printf("-- ");

    // Print the data
    uint8_t* block_data = current_tag.amb[first_byte / 16].mbd.abtData;
    size_t block_last = block_offset + byte_len;
    if (block_last > 15)
      block_last = 15;
    print_hex_array_sep(block_data  + block_offset, block_last - block_offset + 1, " ");
    printf(" ");

    // Fill up end with spaces
    for (size_t i = block_last; i < 15; ++i)
      printf("-- ");

    printf("\n");

    first_byte += block_last - block_offset + 1;
  }
}

void print_tag_data_range(size_t byte_offset, size_t bit_offset, size_t byte_len, size_t bit_len) {
  printf("Offset: [%zu, %zu] Length: [%zu, %zu]\n", byte_offset, bit_offset, byte_len, bit_len);

  // Print partial first byte
  if (bit_offset) {
    size_t total_bits = byte_len * 8 + bit_len;
    size_t last_bit = bit_offset + total_bits - 1;
    if (last_bit > 7)
      last_bit = 7;

    print_tag_byte_bits(byte_offset, bit_offset, last_bit);
    printf("\n");

    total_bits -= last_bit - bit_offset + 1;

    // Update data to be printed
    byte_offset++;
    bit_offset = 0;
    byte_len = total_bits / 8;
    bit_len = total_bits % 8;
  }

  // Print bytes
  if (byte_len) {
    print_tag_bytes(byte_offset, byte_offset + byte_len - 1);

    // Update data to be printed
    byte_offset += byte_len;
    byte_len = 0;
  }

  // Print trailing bits
  if (bit_len) {
    print_tag_byte_bits(byte_offset, 0, bit_len);
    printf("\n");
  }
}

void print_tag_block_range(size_t first, size_t last) {
  if( last > sizeof(mf_tag_t)/sizeof(mf_block_t) )
    last = sizeof(mf_tag_t)/sizeof(mf_block_t);

  printf("xS  xB  00                   07 08                   0f        ASCII       \n");
  printf("---------------------------------------------------------------------------\n");

  for (size_t block = first; block <= last; block++) {
    printf("%02zx  %02zx  ", block_to_sector(block), block);

    print_hex_array_sep(current_tag.amb[block].mbd.abtData, sizeof(mf_block_t), " ");

    printf("  [");
    print_ascii_rendering(current_tag.amb[block].mbd.abtData, sizeof(mf_block_t), '.');
    printf("]\n");

    if (block < last && is_trailer_block(block))
      printf("\n");
  }
}

void print_keys(const mf_tag_t* tag, size_t s1, size_t s2) {
  printf("xS  xB  KeyA          KeyB\n");
  printf("----------------------------------\n");

  for (size_t sector = s1; sector <= s2; sector++) {
    size_t block = sector_to_trailer(sector);

    printf("%02zx  %02zx  ", sector, block);
    print_hex_array(tag->amb[block].mbt.abtKeyA, 6);
    printf("  ");
    print_hex_array(tag->amb[block].mbt.abtKeyB, 6);
    printf("\n");

    if (sector == 0x0f && s2 > 0x0f) printf("\n");
  }
}

void print_ac(const mf_tag_t* tag, size_t b1, size_t b2) {
  static const char* ac_data_str[8] = {
    /* 0 0 0 */ "   A|B A|B A|B A|B   .   .   .   .   .   .",
    /* 0 0 1 */ "   A|B  x   x  A|B   .   .   .   .   .   .",
    /* 0 1 0 */ "   A|B  x   x   x    .   .   .   .   .   .",
    /* 0 1 1 */ "    B   B   x   x    .   .   .   .   .   .",
    /* 1 0 0 */ "   A|B  B   x   x    .   .   .   .   .   .",
    /* 1 0 1 */ "    B   x   x   x    .   .   .   .   .   .",
    /* 1 1 0 */ "   A|B  B   B  A|B   .   .   .   .   .   .",
    /* 1 1 1 */ "    x   x   x   x    .   .   .   .   .   .",
  };

  static const char* ac_trailer_str[8] = {
    /* 0 0 0 */ "    .   .   .   .    x   A   A   x   A   A",
    /* 0 0 1 */ "    .   .   .   .    x   A   A   A   A   A",
    /* 0 1 0 */ "    .   .   .   .    x   x   A   x   A   x",
    /* 0 1 1 */ "    .   .   .   .    x   B  A|B  B   x   B",
    /* 1 0 0 */ "    .   .   .   .    x   B  A|B  x   x   B",
    /* 1 0 1 */ "    .   .   .   .    x   x  A|B  B   x   x",
    /* 1 1 0 */ "    .   .   .   .    x   x  A|B  x   x   x",
    /* 1 1 1 */ "    .   .   .   .    x   x  A|B  x   x   x",
  };

  // Print header
  printf("xS  xB  Raw       C1 C2 C3    R   W   I   D   AR  AW  ACR ACW BR  BW\n");
  printf("--------------------------------------------------------------------\n");

  // Iterate over all requested blocks
  for (size_t block = b1; block <= b2; block++) {
    size_t trailer = block_to_trailer(block);
    const uint8_t* ac = tag->amb[trailer].mbt.abtAccessBits;

    printf("%02zx  %02zx  ", block_to_sector(block), block);
    print_hex_array(ac, 4);

    // Extract and print the C1, C2, C3 bits
    uint32_t bits = (uint32_t)ac[0] | (uint32_t)ac[1]<<8 | (uint32_t)ac[2]<<16 | (uint32_t)ac[3]<<24;
    int offset = 12 + ((block < 0x80) ? ((int)block%4) : (((int)block%16)/5));
    int c1 = (bits>>(offset)) & 1;
    int c2 = (bits>>(offset+4)) & 1;
    int c3 = (bits>>(offset+8)) & 1;
    printf("   %d  %d  %d", c1, c2, c3);

    // Print interpretation
    int c123 = (c1<<2) | (c2<<1) | c3;
    if (block < trailer) {
      // Data block
      printf("%s\n", ac_data_str[c123]);
    }
    else {
      // Trailer block
      printf("%s\n", ac_trailer_str[c123]);
    }

    if (block == trailer && b2 > block)
      printf("\n");
  }
}

void clear_blocks(mf_tag_t* tag, size_t b1, size_t b2) {
  for (size_t block = b1; block <= b2; block++) {
    if (block == 0 || is_trailer_block(block))
      continue;
    memset((void*)tag->amb[block].mbd.abtData, 0x00, 0x10);
  }
}

void clear_tag(mf_tag_t* tag) {
  memset((void*)tag, 0x00, MF_4K);
}

void reset_tag(mf_tag_t* tag) {
  clear_tag(tag);

  const uint8_t block0[] = {0x11, 0x22, 0x33, 0x44, 0x44, 0x08, 0x04, 0x00, 0xda, 0xba, 0xbe, 0x20, 0xfe, 0xed, 0xf0, 0x0d};
  memcpy((void*)tag->amb[0].mbd.abtData, block0, 0x10);

  const uint8_t trailer[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x07, 0x80, 0x69, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  for (size_t sector = 0; sector < sector_count(MF_4K); sector++) {
    memcpy((void*)tag->amb[sector_to_trailer(sector)].mbd.abtData, trailer, 0x10);
  }
}

void clear_non_auth_data(mf_tag_t* tag) {
  // Clear first 32 4-block sector data
  for (size_t i = 0; i < 32; ++i)
    memset(((void*)tag) + i*64, 0x00, 48);

  // Clear last 8 16-block sector data
  for (size_t i = 0; i < 8; ++i)
    memset(((void*)tag) + 2048 + i*256, 0x00, 240);
}

size_t block_count(mf_size_t size) {
  return size / 0x10;
}

size_t sector_count(mf_size_t size) {
  return size == MF_1K ? 0x10 : 0x28;
}

int is_trailer_block(size_t block) {
  return is_header_block(block + 1);
}

int is_header_block(size_t block) {
  return (block) % (block < 0x80 ? 4 : 0x10) == 0;
}

size_t block_to_sector(size_t block) {
  if (block < 0x80)
    return block / 4;

  return 0x20 + (block - 0x80) / 0x10;
}

size_t block_to_header(size_t block) {
  if (block < 0x80)
    return block - (block % 4);

  return block - (block % 0x10);
}

// Return the trailer block for the specified block
size_t block_to_trailer(size_t block)
{
  if (block < 0x80)
    return block - (block % 4) + 3;

  return block - (block % 0x10) + 0x0f;
}

// Return the header block for the specified sector
size_t sector_to_header(size_t sector) {
  if (sector < 0x20)
    return sector * 4;
  else
    return 0x80 + (sector - 0x20) * 0x10;
}

// Return the trailer block for the specified sector
size_t sector_to_trailer(size_t sector) {
  if (sector < 0x20)
    return sector * 4 + 3;
  else
    return 0x80 + (sector - 0x20) * 0x10 + 0x0f;
}

// Return the sector size (in blocks) that contains the block
size_t sector_size(size_t block) {
  return block < 0x80 ? 4 : 16;
}

// Extract the key for the block parameters sector of the tag and return it
uint8_t* key_from_tag(const mf_tag_t* tag, mf_key_type_t key_type, size_t block) {
  static uint8_t key[6];
  size_t trailer_block = block_to_trailer(block);

  if (key_type == MF_KEY_A)
    memcpy(key, tag->amb[trailer_block].mbt.abtKeyA, 6);
  else
    memcpy(key, tag->amb[trailer_block].mbt.abtKeyB, 6);

  return key;
}

// Write key to the sector of a tag, where the sector is specified by the block.
void key_to_tag(mf_tag_t* tag, const uint8_t* key, mf_key_type_t key_type, size_t block) {
  size_t trailer_block = block_to_trailer(block);

  if (key_type == MF_KEY_A)
    memcpy(tag->amb[trailer_block].mbt.abtKeyA, key, 6);
  else
    memcpy(tag->amb[trailer_block].mbt.abtKeyB, key, 6);
}

// Set permission bits for given block
void set_ac(mf_tag_t* tag, size_t block, uint32_t c1, uint32_t c2, uint32_t c3) {
  const size_t trailer = block_to_trailer(block);

  // extract access bits (little endian)
  uint32_t ac = ((uint32_t)tag->amb[trailer].mbt.abtAccessBits[0]     | (uint32_t)tag->amb[trailer].mbt.abtAccessBits[1]<<8 |
                 (uint32_t)tag->amb[trailer].mbt.abtAccessBits[2]<<16 | (uint32_t)tag->amb[trailer].mbt.abtAccessBits[3]<<24)>>12;

  // Set the correct C1, C2, C3 bits
  const uint32_t offset = ((block < 0x80) ? ((uint32_t)block%4) : (((uint32_t)block%16)/5));
  const uint32_t mask = ((1u) | (1u<<4) | (1u<<8))<<offset;
  const uint32_t bits = ((c1) | (c2<<4) | (c3<<8))<<offset;
  ac = (ac&(~mask)) | (bits&mask);
  ac = (ac<<12) | ((~ac)&0b111111111111);

  // Write permission bits
  tag->amb[trailer].mbt.abtAccessBits[0] = (uint8_t)(ac&0xFF);
  tag->amb[trailer].mbt.abtAccessBits[1] = (uint8_t)((ac>>8)&0xFF);
  tag->amb[trailer].mbt.abtAccessBits[2] = (uint8_t)((ac>>16)&0xFF);
  tag->amb[trailer].mbt.abtAccessBits[3] = (uint8_t)((ac>>24)&0xFF);
}

// check and possibly fix tag
void check_tag(mf_tag_t* tag, bool fix) {
  int errors;
  uint8_t* d;

  printf("Checking BCC [");
  errors = 0;
  d = tag->amb[0].mbd.abtData;
  if ((d[0] ^ d[1] ^ d[2] ^ d[3]) != d[4]) {
    if (fix) {
      printf("00] 1 warning: %02x instead of %02x fixed\n", d[4], d[0] ^ d[1] ^ d[2] ^ d[3]);
      d[4] = d[0] ^ d[1] ^ d[2] ^ d[3];
    } else {
      printf("00] 1 warning: %02x instead of %02x\n", d[4], d[0] ^ d[1] ^ d[2] ^ d[3]);
    }
  } else {
    printf(".]\n");
  }

  printf("Checking sector access codes [");
  errors = 0;
  for (size_t sector = 0; sector < sector_count(MF_4K); sector++) {
    size_t trailer = sector_to_trailer(sector);
    d = tag->amb[trailer].mbt.abtAccessBits;
    uint32_t nac = (uint32_t)d[0] | (uint32_t)(d[1]&0x0F)<<8;
    uint32_t  ac = (uint32_t)(d[1]>>4) | (uint32_t)(d[2])<<4;
    if ((ac^nac) != 0xFFF) {
      errors++;
      if (sector == 0) {
        printf("%02zx", sector);
      } else {
        printf(" %02zx", sector);
      }
      if (fix) {
        ac = (ac<<12) | ((~ac)&0b111111111111);
        d[0] = (uint8_t)(ac&0xFF);
        d[1] = (uint8_t)((ac>>8)&0xFF);
        d[2] = (uint8_t)((ac>>16)&0xFF);
        d[3] = (uint8_t)((ac>>24)&0xFF);
      }
    } else {
      printf(".");
    }
    if (sector == 0x0f) printf(" ");
    fflush(stdout);
  }
  if (errors > 0) {
    if (fix)
      printf("] %d errors fixed\n", errors);
    else
      printf("] %d errors\n", errors);
  } else {
    printf("]\n");
  }

  printf("Checking MAD CRCs [");
  const uint8_t gpb1 = tag->amb[0x03].mbt.abtAccessBits[3];
  if (gpb1 & 0x80) {
    const uint8_t version = gpb1 & 0x03;
    uint8_t crcs[2];
    mad_calc_crc(tag, crcs);
    const uint8_t crc1 = tag->amb[0x01].mbd.abtData[0];
    if (crc1 == crcs[0]) {
      printf(".");
    } else {
      if (fix) tag->amb[0x01].mbd.abtData[0] = crc1;
      printf("x");
    }
    if (version == 2) {
      const uint8_t crc2 = tag->amb[0x40].mbd.abtData[0];
      if (crc2 == crcs[1]) {
        printf(".");
      } else {
        if (fix) tag->amb[0x40].mbd.abtData[0] = crc2;
        printf("x");
      }
    }
  }
  printf("]\n");
}
