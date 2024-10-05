#ifndef TAG__H
#define TAG__H

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
 *
 * Parts of code used in this file are from the GNU readline library file
 * fileman.c (GPLv3). Copyright (C) 1987-2009 Free Software Foundation, Inc
 */

#include "mifare.h"

typedef enum {
  MF_INVALID_SIZE = 0,
  MF_1K = 1024,
  MF_4K = 4096
} mf_size_t;

typedef enum {
  MF_INVALID_KEY_TYPE = 0,
  MF_KEY_A = 'a',
  MF_KEY_B = 'b',
  MF_KEY_AB = 'x',
  MF_KEY_UNLOCKED = '*'
} mf_key_type_t;

// Convenience typedefs
typedef mifare_classic_tag mf_tag_t;
typedef mifare_classic_block mf_block_t;

// The active tag
extern mf_tag_t current_tag;

// The ACL + keys used for authentication
extern mf_tag_t current_auth;

// Load/Save tag or keys from file
int load_tag(const char* fn);
int load_auth(const char* fn);
int save_tag(const char* fn);
int save_auth(const char* fn);

// Copy key data between 'current_tag' and 'current_auth'
int import_auth(mf_key_type_t key_type, size_t s1, size_t s2);
int export_auth(mf_key_type_t key_type, size_t s1, size_t s2);

// Output tag data
void print_tag_block_range(size_t first, size_t last);
void print_tag_data_range(size_t byte_offset, size_t bit_offset, size_t byte_len, size_t bit_len);
void print_tag_bytes(size_t first_byte, size_t last_byte);
void print_keys(const mf_tag_t* tag, size_t s1, size_t s2);
void print_ac(const mf_tag_t* tag, size_t b1, size_t b2);

// Return a hex string representationon of the key
const char* sprint_key(const uint8_t* key);

// Parse the string and set the key. Return the key, or NULL on error.
uint8_t* read_key(uint8_t* key, const char* str);

// Return a string describing the tag type 1k|4k
const char* sprint_size(mf_size_t size);

// Set the contents of a tag to zeroes
void clear_tag(mf_tag_t* tag);
void reset_tag(mf_tag_t* tag);
void clear_blocks(mf_tag_t* tag, size_t b1, size_t b2);

// Return number of blocks for size
size_t block_count(mf_size_t size);

// Return number of sectors for size
size_t sector_count(mf_size_t size);

// Return > 0 if the block is a trailer, 0 otherwise.
int is_trailer_block(size_t block);

// Return > 0 if the block is a header, 0 otherwise.
int is_header_block(size_t block);

// Return the sector index of the block
size_t block_to_sector(size_t block);

// Return the head block for the specified block
size_t block_to_header(size_t block);

// Return the trailer block for the specified block
size_t block_to_trailer(size_t block);

// Return the header block for the specified sector
size_t sector_to_header(size_t sector);

// Return the trailer block for the specified sector
size_t sector_to_trailer(size_t sector);

// Return the sector size (in blocks) that contains the block
size_t sector_size(size_t block);

// Extract the key for the block parameters sector of the tag and return it
uint8_t* key_from_tag(const mf_tag_t* tag, mf_key_type_t key_type, size_t block);

// Write key to the sector of a tag, where the sector is specified by
// the block (anywhere in the sector).
void key_to_tag(mf_tag_t* tag, const uint8_t* key, mf_key_type_t key_type, size_t block);

void set_ac(mf_tag_t* tag, size_t block, uint32_t c1, uint32_t c2, uint32_t c3);

void check_tag(mf_tag_t* tag, bool fix);

int ndef_put_sectors(mf_tag_t* tag, size_t s1, size_t s2, const uint8_t* ndef, const size_t size);
int ndef_URI_record(const char* uri, uint8_t** ndef, size_t* size);

int mad_crc(mf_tag_t* tag);
int mad_set_info(mf_tag_t* tag, size_t sector);
int mad_put_aid(mf_tag_t* tag, size_t sector, uint16_t aid);
int mad_init(mf_tag_t* tag, mf_size_t size);
int mad_size(mf_tag_t* tag, mf_size_t size);


#endif
