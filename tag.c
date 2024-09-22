/**
 * Copyright (C) 2011 Anders Sundman <anders@4zm.org>
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

mf_tag_t current_tag;
mf_tag_t current_auth;

void clear_non_auth_data(mf_tag_t* tag);
int load_mfd(const char* fn, mf_tag_t* tag);
int save_mfd(const char* fn, const mf_tag_t* tag);
int load_txt(const char* fn, mf_tag_t* tag);
int save_txt(const char* fn, const mf_tag_t* tag);

int load_mfd(const char* fn, mf_tag_t* tag) {
  mf_tag_t temp;
  FILE* mfd_file = fopen(fn, "rb");

  if (mfd_file == NULL) {
    return 1;
  }

  if (fread(&temp, 1, sizeof(mf_tag_t), mfd_file) != sizeof(mf_tag_t)) {
    fclose(mfd_file);
    return 2;
  }

  fclose(mfd_file);
  memcpy(tag, &temp, sizeof(mf_tag_t));
  return 0;
}

int save_mfd(const char* fn, const mf_tag_t* tag) {
  FILE* mfd_file = fopen(fn, "w");

  if (mfd_file == NULL) {
    return 1;
  }

  if (fwrite(tag, 1, sizeof(mf_tag_t), mfd_file) != sizeof(mf_tag_t)) {
    fclose(mfd_file);
    return 2;
  }

  fclose(mfd_file);
  return 0;
}

int load_txt(const char* fn, mf_tag_t* tag) {
  mf_tag_t temp;
  FILE* key_file = fopen(fn, "r");

  if (key_file == NULL) {
    return 1;
  }

  for (size_t sector = 0; sector < sector_count(MF_4K); sector++) {
    uint8_t k[12];
    if( fscanf( key_file, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx %2hhx%2hhx%2hhx%2hhx%2hhx%2hhx", k, k+1, k+2, k+3, k+4, k+5, k+6, k+7, k+8, k+9, k+10, k+11 ) != 12 )
    {
      fclose(key_file);
      return 2;
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
    return 1;
  }

  for (size_t sector = 0; sector < sector_count(MF_4K); sector++) {
    size_t block = sector_to_trailer(sector);

    const uint8_t* key = key_from_tag(tag, MF_KEY_A, block);
    const int r1 = fprintf(key_file, "%s\t", sprint_key(key));

    key = key_from_tag(tag, MF_KEY_B, block);
    const int r2 = fprintf(key_file, "%s\n", sprint_key(key));
 
    if (r1 < 0 || r2 < 0) {
      fclose(key_file);
      return 2;
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

    printf(" [");
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

const char* sprint_key(const uint8_t* key) {
  static char str_buff[13];

  if (!key)
    return NULL;

  sprintf(str_buff, "%02x%02x%02x%02x%02x%02x",
          (unsigned int)(key[0]),
          (unsigned int)(key[1]),
          (unsigned int)(key[2]),
          (unsigned int)(key[3]),
          (unsigned int)(key[4]),
          (unsigned int)(key[5]));

  return str_buff;
}

// Return a string describing the tag type 1k|4k
const char* sprint_size(mf_size_t size) {
  if (size == MF_1K)
    return "1K";

  if (size == MF_4K)
    return "4K";

  return NULL;
}

uint8_t* read_key(uint8_t* key, const char* str) {
  if (!key || !str)
    return NULL;

  char byte_tok[] = {0, 0, 0};
  char* byte_tok_end;
  for (int i = 0; i < 6; ++i) {
    byte_tok[0] = str[i*2];
    byte_tok[1] = str[i*2+1];
    key[i] = (uint8_t)strtol(byte_tok, &byte_tok_end, 16);
    if (*byte_tok_end != '\0') {
      return NULL;
    }
  }

  return key;
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

// Write key to the sector of a tag, where the sector is specified by
// the block.
void key_to_tag(mf_tag_t* tag, const uint8_t* key, mf_key_type_t key_type, size_t block) {
  size_t trailer_block = block_to_trailer(block);

  if (key_type == MF_KEY_A)
    memcpy(tag->amb[trailer_block].mbt.abtKeyA, key, 6);
  else
    memcpy(tag->amb[trailer_block].mbt.abtKeyB, key, 6);
}
