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
 *
 * Parts of code used in this file are based on the Public platform
 * independent Near Field Communication (NFC) library example
 * nfc-mfclassic.c. It is thus covered by that license as well:
 *
 * Copyright (C) 2009, Roel Verdult
 * Copyright (C) 2010, Romuald Conty, Romain Tartière
 * Copyright (C) 2011, Adam Laurie
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *  1) Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *  2 )Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <nfc/nfc.h>
#include "config.h"
#include "mifare.h"
#include "tag.h"
#include "util.h"
#include "mifare_ctrl.h"
#include "emulator.h"

settings_t settings = { "", "AB", "1K" };

// State of the device/tag - should be NULL between high level calls.
static nfc_device* device = NULL;
static nfc_target target;
static mf_size_t size;
static nfc_context* context;

static const nfc_modulation mf_nfc_modulation = {
  .nmt = NMT_ISO14443A,
  .nbr = NBR_106,
};

// Buffers used for raw bit/byte writes
#define MAX_FRAME_LEN 264
static uint8_t abtRx[MAX_FRAME_LEN];
static int szRxBits;

typedef struct {
  const char* mfc;
  const char* name;
  const char* id;
  unsigned int len;
} card_ident_t;

// list of known cards
static const card_ident_t cards[] = {
  { "NXP",        "Mifare mini",         "\x00\x04\x09", 3 },
  { "NXP",        "Mifare Classic 1k",   "\x00\x04\x08", 3 },
  { "NXP",        "Mifare Classic 4k",   "\x00\x02\x18", 3 },
  { "NXP",        "Mifare Ultralight",   "\x00\x44\x00", 3 },
  { "NXP",        "Mifare DESFire",      "\x03\x44\x20\x75\x77\x81\x02\x80", 8 },
  { "IBM",        "JCOP31",              "\x03\x04\x28\x38\x77\xb1\x4a\x43\x4f\x50\x33\x31", 12 },
  { "IBM",        "JCOP31 v2.4.1",       "\x00\x48\x20\x78\x77\xb1\x02\x4a\x43\x4f\x50\x76\x32\x34\x31", 15 },
  { "IBM",        "JCOP41 v2.2",         "\x00\x48\x20\x38\x33\xb1\x4a\x43\x4f\x50\x34\x31\x56\x32\x32", 15 },
  { "IBM",        "JCOP41 v2.3.1",       "\x00\x04\x28\x38\x33\xb1\x4a\x43\x4f\x50\x34\x31\x56\x32\x33\x31", 16 },
  { "Infineon",   "Mifare Classic 1k",   "\x00\x04\x88", 3 },
  { "Gemplus",    "MPCOS",               "\x00\x02\x98", 3 },
  { "Nokia",      "Mifare Classic 4k",   "\x00\x02\x38", 3 },
  { "Nokia",      "Mifare Classic 4k",   "\x00\x08\x38", 3 },
  { "Unknown",    "Unknown",             "", 0 }
};

// some constants taken from libnfc
const int ISO7816_C_APDU_COMMAND_HEADER_LEN = 4;
const int ISO7816_SHORT_APDU_MAX_DATA_LEN = 256;
const int ISO7816_SHORT_C_APDU_MAX_OVERHEAD = 2;
const int ISO7816_SHORT_R_APDU_RESPONSE_TRAILER_LEN = 2;
const int ISO7816_SHORT_C_APDU_MAX_LEN = ISO7816_C_APDU_COMMAND_HEADER_LEN + ISO7816_SHORT_APDU_MAX_DATA_LEN + ISO7816_SHORT_C_APDU_MAX_OVERHEAD;
const int ISO7816_SHORT_R_APDU_MAX_LEN = ISO7816_SHORT_APDU_MAX_DATA_LEN + ISO7816_SHORT_R_APDU_RESPONSE_TRAILER_LEN;

int mf_connect_internal();
int mf_connect();
int mf_disconnect(int ret_state);
bool mf_configure_device();
bool mf_select_target();
bool mf_authenticate(size_t block, const uint8_t* key, mf_key_type_t key_type);
bool mf_gen1_unlock();
bool mf_read_blocks_internal(mf_tag_t* tag, const mf_tag_t* keys, mf_key_type_t key_type, size_t a, size_t b);
bool mf_write_blocks_internal(const mf_tag_t* tag, const mf_tag_t* keys, mf_key_type_t key_type, size_t a, size_t b);
bool mf_dictionary_attack_internal(mf_tag_t* tag);
bool mf_test_auth_internal(const mf_tag_t* keys, size_t size1, size_t size2, mf_key_type_t key_type);
bool transmit_bits(const uint8_t *pbtTx, const size_t szTxBits);
bool transmit_bytes(const uint8_t *pbtTx, const size_t szTx);

void mf_signal_handler(int sig)
{
  static time_t last = 0;
  time_t curr = time(NULL);
  if (sig == SIGINT) {
    if (device) {
      mf_disconnect(0);
    }
    if(curr-last <= 1) {
      exit(EXIT_FAILURE);
    }
    last = curr;
  }
}

int mf_disconnect(int ret_state) {
  if(nfc_device_get_last_error(device) != 0)
    nfc_perror(device, "NFC error");
  nfc_close(device);
  nfc_exit(context);
  device = NULL;
  memset(&target, 0, sizeof(target));
  return ret_state;
}

int mf_connect_internal() {
  // Initialize libnfc and set the nfc_context
  nfc_init(&context);

  // Connect to (any) NFC reader
  device = nfc_open(context, settings.device[0] == '\0' ? NULL : settings.device);
  if (device == NULL) {
    printf ("Could not connect to NFC device\n");
    nfc_exit(context);
    return -1; // Don't need to disconnect
  }

  // Initialize the device as a reader
  if (!mf_configure_device()) {
    printf("Error initializing NFC device\n");
    return mf_disconnect(-1);
  }

  // Try to find a tag
  if (!mf_select_target() || target.nti.nai.btSak == 0) {
    printf("Connected to device, but no tag found.\n");
    return mf_disconnect(-1);
  }

  return 0;
}

int mf_connect() {
  const int res = mf_connect_internal();
  if (res != 0) return res;

  // Allow SAK & ATQA == 0. Assume 1k pirate card.
  if (target.nti.nai.btSak == 0 && target.nti.nai.abtAtqa[1] == 0) {
    size = MF_1K;
    return 0;
  }

  // Test if we are dealing with a Mifare Classic compatible tag
  if ((target.nti.nai.btSak & 0x08) == 0) {
    printf("Incompatible tag type: 0x%02x (i.e. not Mifare Classic).\n", target.nti.nai.btSak);
    return mf_disconnect(-1);
  }

  // Guessing tag size
  if ((target.nti.nai.abtAtqa[1] & 0x02)) {
    size = MF_4K;
  }
  else if ((target.nti.nai.abtAtqa[1] & 0x04)) {
    size = MF_1K;
  }
  else {
    printf("Unsupported tag size. ATQA 0x%02x 0x%02x (i.e. not [1|4]K.)\n", target.nti.nai.abtAtqa[0], target.nti.nai.abtAtqa[1]);
    return mf_disconnect(-1);
  }

  return 0;
}

int mf_devices() {
  nfc_connstring devs[8];

  nfc_init(&context);
  size_t n = nfc_list_devices(context, devs, 0);
  if (n == 0) {
    printf("No devices found.\n");
    nfc_exit(context);
    return -1;
  }
  printf("%u devices found:\n", (unsigned int)n);
  for (size_t i = 0; i < n; i++)
    printf("%s\n", devs[i]);

  nfc_exit(context);
  return 0;
}

int mf_read_blocks(mf_tag_t* tag, mf_key_type_t key_type, size_t a, size_t b) {
  if (mf_connect())
    return -1;

  if (key_type == MF_KEY_UNLOCKED && !mf_gen1_unlock()) {
    printf("Unlocked read requested, but unlock failed!\n");
    return false;
  }

  if (!mf_read_blocks_internal(tag, &current_auth, key_type, a, b)) {
    printf("Read failed!\n");
    return mf_disconnect(-1);
  }

  return mf_disconnect(0);
}

int mf_write_blocks(const mf_tag_t* tag, mf_key_type_t key_type, size_t a, size_t b) {
  if (mf_connect())
    return -1;

  if (key_type == MF_KEY_UNLOCKED && !mf_gen1_unlock()) {
    printf("Unlocked read requested, but unlock failed!\n");
    return false;
  }

  if (!mf_write_blocks_internal(tag, &current_auth, key_type, a, b)) {
    printf("Write failed!\n");
    return mf_disconnect(-1);
  }

  return mf_disconnect(0);
}

int mf_dictionary_attack(mf_tag_t* tag) {
  if (mf_connect()) {
    return -1; // No need to disconnect here
  }

  if (!mf_dictionary_attack_internal(tag)) {
    printf("Dictionary attack failed!\n");
    return mf_disconnect(-1);
  }

  return mf_disconnect(0);
}


int mf_test_auth(const mf_tag_t* keys, size_t size1, size_t size2, mf_key_type_t key_type) {
  if (mf_connect()) {
    return -1; // No need to disconnect here
  }

  if (!mf_test_auth_internal(keys, size1, size2, key_type)) {
    printf("Test authentication failed!\n");
    return mf_disconnect(-1);
  }

  return mf_disconnect(0);
}


bool mf_configure_device() {
  // Disallow invalid frame
  if (nfc_device_set_property_bool(device, NP_ACCEPT_INVALID_FRAMES, false) < 0)
    return false;

  // Disallow multiple frames
  if (nfc_device_set_property_bool(device, NP_ACCEPT_MULTIPLE_FRAMES, false) < 0)
    return false;

  // Make sure we reset the CRC and parity to chip handling.
  if (nfc_device_set_property_bool(device, NP_HANDLE_CRC, true) < 0)
    return false;

  if (nfc_device_set_property_bool(device, NP_HANDLE_PARITY, true) < 0)
    return false;

  // Disable ISO14443-4 switching in order to read devices that emulate
  // Mifare Classic with ISO14443-4 compliance.
  if (nfc_device_set_property_bool(device, NP_AUTO_ISO14443_4, false) < 0)
    return false;

  // Activate "easy framing" feature by default
  if (nfc_device_set_property_bool(device, NP_EASY_FRAMING, true) < 0)
    return false;

  // Deactivate the CRYPTO1 cipher, it may could cause problems when
  // still active
  if (nfc_device_set_property_bool(device, NP_ACTIVATE_CRYPTO1, false) < 0)
    return false;

  // Drop explicitely the field
  if (nfc_device_set_property_bool(device, NP_ACTIVATE_FIELD, false) < 0)
    return false;

  // Override default initialization option, only try to select a tag once.
  if (nfc_device_set_property_bool(device, NP_INFINITE_SELECT, false) < 0)
    return false;

  return true;
}

bool mf_select_target() {
  if (nfc_initiator_select_passive_target(device, mf_nfc_modulation, NULL, 0, &target) < 0) {
    return false;
  }
  return true;
}

/**
 * Unlocking the card allows writing to block 0 of some pirate cards.
 */
bool mf_gen1_unlock() {
  uint8_t abtHalt[4] = { 0x50, 0x00, 0x00, 0x00 };

  // Special unlock command
  const uint8_t abtUnlock1[1] = { 0x40 };
  const uint8_t abtUnlock2[1] = { 0x43 };

  // Disable CRC and parity checking
  if (nfc_device_set_property_bool(device, NP_HANDLE_CRC, false) < 0)
    return false;

  // Disable easy framing. Use raw send/receive methods
  if (nfc_device_set_property_bool (device, NP_EASY_FRAMING, false) < 0)
    return false;

  // Initialize transmision
  iso14443a_crc_append(abtHalt, 2);
  transmit_bytes(abtHalt, 4);

  // Send unlock
  if (!transmit_bits (abtUnlock1, 7))
    return false;

  if (!transmit_bytes (abtUnlock2, 1))
    return false;

  // Reset reader configuration. CRC and easy framing.
  if (nfc_device_set_property_bool (device, NP_HANDLE_CRC, true) < 0)
    return false;
  if (nfc_device_set_property_bool (device, NP_EASY_FRAMING, true) < 0)
    return false;

  return true;
}

/**
 * This command wipes the entire card for GEN2 CUID cards.
 */
int mf_gen1_wipe() {
  uint8_t abtHalt[4] = { 0x50, 0x00, 0x00, 0x00 };

  // Special unlock command
  const uint8_t abtUnlock1[1] = { 0x40 };
  const uint8_t abtUnlock2[1] = { 0x41 };

  if (mf_connect())
    return -1; // No need to disconnect here

  // Disable CRC and parity checking
  if (nfc_device_set_property_bool(device, NP_HANDLE_CRC, false) < 0)
    return mf_disconnect(-1);

  // Disable easy framing. Use raw send/receive methods
  if (nfc_device_set_property_bool (device, NP_EASY_FRAMING, false) < 0)
    return mf_disconnect(-1);

  // Initialize transmision
  iso14443a_crc_append(abtHalt, 2);
  transmit_bytes(abtHalt, 4);

  // Send unlock
  if (!transmit_bits (abtUnlock1, 7))
    return mf_disconnect(-1);

  if (!transmit_bytes (abtUnlock2, 1))
    return mf_disconnect(-1);

  // Reset reader configuration. CRC and easy framing.
  if (nfc_device_set_property_bool (device, NP_HANDLE_CRC, true) < 0)
    return mf_disconnect(-1);
  if (nfc_device_set_property_bool (device, NP_EASY_FRAMING, true) < 0)
    return mf_disconnect(-1);

  return mf_disconnect(0);
}

/**
 * This command sets the 7 byte UID used in card selection without changing block0 for GEN3 CUID cards.
 */
int mf_gen3_setuid(const uint8_t uid[7]) {
  // Special set UID command
  uint8_t abtUID[12] = { 0x90, 0xFB, 0xCC, 0xCC, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  if (mf_connect())
    return -1; // No need to disconnect here

  // Disable easy framing. Use raw send/receive methods
  if (nfc_device_set_property_bool (device, NP_EASY_FRAMING, false) < 0)
    return mf_disconnect(-1);

  // Send command
  memcpy(abtUID+5, uid, 7);
  if (!transmit_bytes (abtUID, 12))
    return mf_disconnect(-1);

  printf("UID set to %02x%02x%02x%02x%02x%02x%02x\n", uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6]);

  // Reset reader configuration. CRC and easy framing. Not really needed as we disconnect right away.
  if (nfc_device_set_property_bool (device, NP_EASY_FRAMING, true) < 0)
    return mf_disconnect(-1);

  return mf_disconnect(0);
}

/**
 * This command writes the 16 byte block0 and sets the UID for GEN3 CUID cards.
 * ATQA and SAK bytes are automatically replaced by fixed values. On 4-byte UID cards, BCC byte is automatically corrected.
 */
int mf_gen3_setblock0(const uint8_t data[16]) {
  // Special write block 0 command
  uint8_t abtBlock0[21] = { 0x90, 0xF0, 0xCC, 0xCC, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  if (mf_connect())
    return -1; // No need to disconnect here

  // Disable easy framing. Use raw send/receive methods
  if (nfc_device_set_property_bool (device, NP_EASY_FRAMING, false) < 0)
    return mf_disconnect(-1);

  // Send command
  memcpy(abtBlock0+5, data, 16);
  if (!transmit_bytes (abtBlock0, 21))
    return mf_disconnect(-1);

  printf("Block 0 written\n");

  // Reset reader configuration. CRC and easy framing. Not really needed as we disconnect right away.
  if (nfc_device_set_property_bool (device, NP_EASY_FRAMING, true) < 0)
    return mf_disconnect(-1);

  return mf_disconnect(0);
}

/**
 * This command locks the card permanently for GEN3 CUID cards.
 */
int mf_gen3_lock() {
  // Special lock command
  uint8_t abtLock[5] = { 0x90, 0xFD, 0x11, 0x11, 0x00 };

  if (mf_connect())
    return -1; // No need to disconnect here

  // Disable easy framing. Use raw send/receive methods
  if (nfc_device_set_property_bool (device, NP_EASY_FRAMING, false) < 0)
    return mf_disconnect(-1);

  // Send command
  if (!transmit_bytes (abtLock, 5))
    return mf_disconnect(-1);

  printf("Block 0 permanently locked\n");

  // Reset reader configuration. CRC and easy framing. Not really needed as we disconnect right away.
  if (nfc_device_set_property_bool (device, NP_EASY_FRAMING, true) < 0)
    return mf_disconnect(-1);

  return mf_disconnect(0);
}

bool mf_read_blocks_internal(mf_tag_t* tag, const mf_tag_t* keys, mf_key_type_t key_type, size_t a, size_t b) {
  mifare_param mp;
  int error = 0;

  if( b >= block_count(size) ) {
    b = block_count(size)-1;
    printf("\nTruncating read to tag size.\n");
  }

  printf("Reading: ["); fflush(stdout);

  // Read the card
  for (size_t block = a; block <= b; block++) {
    bzero(mp.mpd.abtData, 0x10);

    // Print sector progress
    if (is_header_block(block)) {
      printf("%02zx", block_to_sector(block)); fflush(stdout);
    }

    // Authenticate for every block in case they differ in A/B access rights
    bool authA = 0, authB = 0, read = 0;
    // do unauthenticated read
    if( !read && key_type == MF_KEY_UNLOCKED ) {
      if( mf_gen1_unlock() )
        read = nfc_initiator_mifare_cmd(device, MC_READ, (uint8_t)block, &mp);
    }
    // test key A
    uint8_t* key = key_from_tag(keys, MF_KEY_A, block);
    authA = mf_authenticate(block, key, MF_KEY_A);
    if (authA && !read && (key_type == MF_KEY_A || key_type == MF_KEY_AB)) {
      read = nfc_initiator_mifare_cmd(device, MC_READ, (uint8_t)block, &mp);
    }
    // test key B
    key = key_from_tag(keys, MF_KEY_B, block);
    authB = mf_authenticate(block, key, MF_KEY_B);
    if (authB && !read && (key_type == MF_KEY_B || key_type == MF_KEY_AB)) {
      read = nfc_initiator_mifare_cmd(device, MC_READ, (uint8_t)block, &mp);
    }
    // skip rest of sector if all authentication failed
    if (key_type != MF_KEY_UNLOCKED && !authA && !authB) {
      size_t end = block_to_trailer(block);
      for(; block <= end && block <= b; block++, error++)
        printf("?");
      fflush(stdout);
      block = end;    // block needs to point to last failed block so outer loop continues with next sector header
      continue;
    }

    // store block
    if (!read) {
      printf ("!");
      error++;
    } else {
      printf(".");
      memcpy(tag->amb[block].mbd.abtData, mp.mpd.abtData, 0x10);
      if (is_trailer_block(block)) {
        // Set known keys that worked
        if (authA) key_to_tag(tag, keys->amb[block].mbt.abtKeyA, MF_KEY_A, block);
        if (authB) key_to_tag(tag, keys->amb[block].mbt.abtKeyB, MF_KEY_B, block);
      }
    }
    fflush(stdout);
  }

  // Terminate progress indicator
  if (error)
    printf("] %d error(s).\n", error);
  else
    printf("] Success!\n");

  return true;
}

bool mf_write_blocks_internal(const mf_tag_t* tag, const mf_tag_t* keys, mf_key_type_t key_type, size_t a, size_t b) {
  mifare_param mp;
  int error = 0;

  // do not write a block 0 with incorrect BCC - card will be made invalid!
  if (a == 0 &&
     (tag->amb[0].mbd.abtData[0] ^ tag->amb[0].mbd.abtData[1] ^ tag->amb[0].mbd.abtData[2] ^
      tag->amb[0].mbd.abtData[3] ^ tag->amb[0].mbd.abtData[4]) != 0x00) {
    printf ("\nError: incorrect BCC in block 0! Use check/fix commands to fix.\n");
    return false;
  }

  if( b >= block_count(size) ) {
    b = block_count(size)-1;
    printf("\nTruncating write to tag size.\n");
  }

  printf("Writing ["); fflush(stdout);

  for (size_t block = a; block <= b; block++) {
    // Print sector progress
    if (is_header_block(block)) {
      printf("%02zx", block_to_sector(block)); fflush(stdout);
    }

    // prepare data to write
    memcpy (mp.mpd.abtData, tag->amb[block].mbd.abtData, 0x10);

    // Authenticate for every block in case they differ in A/B access rights
    bool authA = 0, authB = 0, write = 0;
    // try unauthenticated write
    if (!write && key_type == MF_KEY_UNLOCKED) {
      if( mf_gen1_unlock() )
        write = nfc_initiator_mifare_cmd(device, MC_WRITE, (uint8_t)block, &mp);
    }
    if (!write && (key_type == MF_KEY_A || key_type == MF_KEY_AB)) {
      uint8_t* key = key_from_tag(keys, MF_KEY_A, block);
      authA = mf_authenticate(block, key, MF_KEY_A);
      if( authA )
        write = nfc_initiator_mifare_cmd(device, MC_WRITE, (uint8_t)block, &mp);
    }
    if (!write && (key_type == MF_KEY_B || key_type == MF_KEY_AB)) {
      uint8_t* key = key_from_tag(keys, MF_KEY_B, block);
      authB = mf_authenticate(block, key, MF_KEY_B);
      if( authB )
        write = nfc_initiator_mifare_cmd(device, MC_WRITE, (uint8_t)block, &mp);
    }
    if (key_type != MF_KEY_UNLOCKED && !authA && !authB) {
      // both auth failed, report and skip rest of sector
      size_t trailer = block_to_trailer(block);
      for(; block <= trailer && block <= b; block++, error++)
        printf("?");
      block--;
      continue;
    }

    // Progress report
    if (!write) {
      error++;
      printf("!");
    } else {
      printf(".");
    }
    fflush(stdout);
  }

  // Terminate progress indicator
  if (error)
    printf("] %d error(s).\n", error);
  else
    printf("] Success!\n");

  return true;
}

int mf_write_mod(const mf_tag_t* tag, const mf_tag_t* keys) {
  // Special set UID command
  uint8_t abtSET_MOD_TYPE[] = { 0x43, 0x00, 0x00, 0x00 };

  if (mf_connect())
    return -1; // No need to disconnect here

  // authenticate for sector 0 with key A (needed for EV1 cards)
  const uint8_t* key = key_from_tag(keys, MF_KEY_A, 0);
  if (!mf_authenticate(0, key, MF_KEY_A))
    return mf_disconnect(-1);

  // Disable CRC and parity checking
  if (nfc_device_set_property_bool(device, NP_HANDLE_CRC, false) < 0)
    return mf_disconnect(-1);

  // Disable easy framing. Use raw send/receive methods
  if (nfc_device_set_property_bool (device, NP_EASY_FRAMING, false) < 0)
    return mf_disconnect(-1);

  // Initialize transmision
  abtSET_MOD_TYPE[1] = tag->amb[0].mbd.abtData[11] == 0x20 ? 0x01 : 0x00;
  iso14443a_crc_append(abtSET_MOD_TYPE, 2);
  if (!transmit_bytes(abtSET_MOD_TYPE, 4))
    return mf_disconnect(-1);

  // Reset reader configuration. CRC and easy framing.
  if (nfc_device_set_property_bool (device, NP_HANDLE_CRC, true) < 0)
    return mf_disconnect(-1);
  if (nfc_device_set_property_bool (device, NP_EASY_FRAMING, true) < 0)
    return mf_disconnect(-1);

  return mf_disconnect(0);
}

bool mf_dictionary_attack_internal(mf_tag_t* tag) {
  int all_keys_found = 1;

  // Iterate over the start blocks in all sectors
  for (size_t sector = 0; sector < sector_count(size); sector++) {
    size_t block = sector_to_header(sector);

    printf("Working on sector: %02zx [", sector);

    const uint8_t* key_a = NULL;
    const uint8_t* key_b = NULL;

    // Iterate we run out of dictionary keys or the sector is cracked
    const key_list_t* key_it = dictionary_get();
    while(key_it && (key_a == NULL || key_b == NULL)) {      // Try to authenticate for the current sector
      if (key_a == NULL && mf_authenticate(block, key_it->key, MF_KEY_A)) {
        key_a = key_it->key;
      }

      if (key_b == NULL && mf_authenticate(block, key_it->key, MF_KEY_B)) {
        key_b = key_it->key;
      }

      key_it = key_it->next;

      printf("."); fflush(stdout); // Progress indicator
    }

    printf("]\n");

    printf("  A Key: ");
    if (key_a) {
      print_hex_array(key_a, 6);
      printf("\n");

      // Optimize dictionary by moving key to the front
      dictionary_add(key_a);

      // Save key in the tag
      key_to_tag(tag, key_a, MF_KEY_A, block);
    }
    else {
      all_keys_found = 0;
      printf("Not found\n");
    }

    printf("  B Key: ");
    if (key_b) {
      print_hex_array(key_b, 6);
      printf("\n");

      // Optimize dictionary by moving key to the front
      dictionary_add(key_b);

      // Save key in the buffer
      key_to_tag(tag, key_b, MF_KEY_B, block);
    }
    else {
      all_keys_found = 0;
      printf("Not found\n");
    }
  }

  if (all_keys_found)
    printf("All keys were found\n");

  return true;
}

bool mf_test_auth_internal(const mf_tag_t* keys, size_t s1, size_t s2, mf_key_type_t key_type) {
  printf("xS  T  Key           Status\n");
  printf("----------------------------\n");

  for (size_t sector = s1; sector < s2; sector++) {
    size_t block = sector_to_header(sector);

    uint8_t* key = NULL;
    if( key_type == MF_KEY_A || key_type == MF_KEY_AB )
    {
      key = key_from_tag(keys, MF_KEY_A, block);
      printf("%02zx  A  ", sector);
      print_hex_array(key, 6);
      printf("  %s\n", mf_authenticate(block, key, MF_KEY_A) ? "Success" : "Failure");
    }
    if( key_type == MF_KEY_B || key_type == MF_KEY_AB )
    {
      key = key_from_tag(keys, MF_KEY_B, block);
      printf("%02zx  B  ", sector);
      print_hex_array(key, 6);
      printf("  %s\n", mf_authenticate(block, key, MF_KEY_B) ? "Success" : "Failure");
    }
  }

  return true;
}

bool mf_authenticate(size_t block, const uint8_t* key, mf_key_type_t key_type) {
  mifare_param mp;

  // Set the authentication information (uid, key)
  memcpy(mp.mpa.abtAuthUid, target.nti.nai.abtUid + target.nti.nai.szUidLen - 4, 4);
  memcpy(mp.mpa.abtKey, key, 6);

  if (nfc_initiator_mifare_cmd(device, (key_type == MF_KEY_A) ? MC_AUTH_A : MC_AUTH_B, (uint8_t)block, &mp))
    return true;

  // Do the handshake again if auth failed
  nfc_initiator_select_passive_target(device, mf_nfc_modulation, NULL, 0, &target);
  return false;
}

// print public card information
int mf_ident_tag()
{
  if(mf_connect_internal())
    return -1;

  char* str;
  str_nfc_target(&str, &target, true);
  printf("%s\n", str);
  nfc_free(str);

  const card_ident_t* c;
  uint8_t id[32];
  id[0] = target.nti.nai.abtAtqa[0];
  id[1] = target.nti.nai.abtAtqa[1];
  id[2] = target.nti.nai.btSak;
  memcpy(id+3, target.nti.nai.abtAts, sizeof(id)-3);
  for( c = cards; c->len > 0 && memcmp(id, c->id, c->len) != 0; c++ );

  printf("MFTerm identification:\nATQA: %02x %02x  SAK: %02x\n", target.nti.nai.abtAtqa[0], target.nti.nai.abtAtqa[1], target.nti.nai.btSak);
  if( target.nti.nai.szAtsLen > 0 ) {
    printf("ATS:");
    for( size_t i = 0; i < target.nti.nai.szAtsLen; i++ )
      printf(" %02x", target.nti.nai.abtAts[i]);
    printf("\n");
  }

  printf("UID:");
  for( size_t i = 0; i < target.nti.nai.szUidLen; i++ )
    printf(" %02x", target.nti.nai.abtUid[i]);
  if (target.nti.nai.szUidLen == 4) {
    if (target.nti.nai.abtUid[0] == 0x08)
      printf(" (RID)");
    else if ((target.nti.nai.abtUid[0]&0x0F) == 0x0F)
      printf(" (FNUID)");
    else if (target.nti.nai.abtUid[0] == 0x88)
      printf(" (cascade)");
    else if (target.nti.nai.abtUid[0] == 0xF8)
      printf(" (RFU)");
  }

  printf("\n   Manufacturer: %s\n   Type: %s\n", c->mfc, c->name);

  if( target.nti.nai.btSak & 0x08 ) {
    printf("   Mifare Classic: yes\n");
    if( target.nti.nai.abtAtqa[1] & 0x02 ) {
      printf("   Size: 4K\n");
      settings.size = "4K";
    }
    else if( target.nti.nai.abtAtqa[1] & 0x04 ) {
      printf("   Size: 1K\n");
      settings.size = "1K";
    }
    else {
      printf("   Size: unknown\n");
      settings.size = "";
    }
  } else {
    printf("   Mifare Classic: no\n");
  }

  printf("   GEN1: %s\n", mf_gen1_unlock() ? "yes" : "no");

  return mf_disconnect(0);
}

// print version info
int mf_version()
{
  printf("%s\t\tlibnfc %s\n", PACKAGE_STRING, nfc_version() );
  return 0;
}

int mf_remulade(mf_tag_t* keys) {
  if (mf_connect())
    return -1; // No need to disconnect here

  emulator_data_t emulator = {
    .device = device,
    .target = &target,
    .tag = keys
  };

  if (emulate_reader(&emulator) < 0) {
    return mf_disconnect(-1);
  }

  return mf_disconnect(0);
}

// emulate tag
int mf_emulate(mf_tag_t* tag, mf_size_t size)
{
  // Initialize libnfc and set the nfc_context
  nfc_init(&context);

  // Connect to NFC reader
  device = nfc_open(context, settings.device[0] == '\0' ? NULL : settings.device);
  if (device == NULL) {
    printf ("Could not connect to NFC device\n");
    nfc_exit(context);
    return -1; // Don't need to disconnect
  }

  // Notes for ISO14443-A emulated tags:
  // * Only short UIDs are supported
  //   If your UID is longer it will be truncated
  //   Therefore e.g. an UltraLight can only have short UID, which is
  //   typically badly handled by readers who still try to send their "0x95"
  // * First byte of UID will be masked by 0x08 by the PN53x firmware
  //   as security countermeasure against real UID emulation

  const uint8_t atqa_1k[] = { 0x00, 0x04 }, atqa_4k[] = { 0x00, 0x02 };
  nfc_target nt = {
    .nm = {
      .nmt = NMT_ISO14443A,
      .nbr = NBR_UNDEFINED,
    },
    .nti = {
      .nai = {
        .btSak = size == MF_1K ? 0x08 : 0x18,
        .szUidLen = 4,
        .szAtsLen = 0,
      },
    },
  };
  memcpy(nt.nti.nai.abtAtqa, size == MF_1K ? atqa_1k : atqa_4k, 2);
  memcpy(nt.nti.nai.abtUid, tag->amb[0].mbm.abtUID, 4);
  nt.nti.nai.abtUid[0] = 0x08;  // enforced by libnfc

  printf("Emulating this ISO14443-A tag:\n");
  char *s;
  str_nfc_target(&s, &nt, true);
  printf("%s", s);
  nfc_free(s);

  emulator_data_t emulator = {
    .device = device,
    .target = &nt,
    .tag = tag
  };

  if (emulate_target(&emulator) < 0) {
    return mf_disconnect(-1);
  }

  return mf_disconnect(0);
}

// stupid libnfc ignores output length and can overwrite following memory (sometimes even if received length fits?!)
// tx_len is given in bytes here (unclear in libnfc docs)!
int nfc_initiator_transceive_bits_safe(nfc_device *device, const uint8_t *tx, const size_t tx_len, const uint8_t *ptx, uint8_t *rx, const size_t rx_len, uint8_t *prx) {
  uint8_t prx1[ISO7816_SHORT_C_APDU_MAX_LEN], rx1[ISO7816_SHORT_C_APDU_MAX_LEN];
  int res = nfc_initiator_transceive_bits(device, tx, tx_len, ptx, rx1, rx_len, prx1);
  if(res <= 0) return res;
  if( rx_len*8 < res )
    return NFC_EOVFLOW;   // behaves as libnfc docs claim libnfc behaves (but doesn't)
  memcpy(rx, rx1, (res+1)/8);
  memcpy(prx, prx1, (res+1)/8);
  return res;
}

bool transmit_bits(const uint8_t *pbtTx, const size_t szTxBits)
{
  // Transmit the bit frame command, we don't use the arbitrary parity feature
  if ((szRxBits = nfc_initiator_transceive_bits_safe(device, pbtTx, szTxBits, NULL, abtRx, sizeof(abtRx), NULL)) < 0)
    return false;

  return true;
}

bool transmit_bytes(const uint8_t *pbtTx, const size_t szTx)
{
  // Transmit the command bytes
  if (nfc_initiator_transceive_bytes(device, pbtTx, szTx, abtRx, sizeof(abtRx), 0) < 0)
    return false;

  return true;
}
