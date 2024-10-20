#ifndef MIFARE_CTRL__H
#define MIFARE_CTRL__H

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
 */

#include <nfc/nfc-types.h>
#include "tag.h"
#include "dictionary.h"

// some constants taken from libnfc
extern const int ISO7816_C_APDU_COMMAND_HEADER_LEN ;
extern const int ISO7816_SHORT_APDU_MAX_DATA_LEN ;
extern const int ISO7816_SHORT_C_APDU_MAX_OVERHEAD;
extern const int ISO7816_SHORT_R_APDU_RESPONSE_TRAILER_LEN;
extern const int ISO7816_SHORT_C_APDU_MAX_LEN;
extern const int ISO7816_SHORT_R_APDU_MAX_LEN;

/**
 * Settings
 */
typedef struct {
  nfc_connstring device;
  const char* auth;
  const char* size;
} settings_t;

extern settings_t settings;

// print list of all available NFC devices
int mf_devices();

// signal handler to abort current operation on interrupt
void mf_signal_handler(int sig);

/**
 * Connect to an nfc device. Then read the tag data, authenticating with the
 * 'current_auth' keys of specified type, and store it in the
 * 'current_tag' state variable. Finally, disconnect from the device.
 * If there are authentication errors, those sectors will be set to
 * all zeroes.
 * Return 0 on success != 0 on failure.
 */
int mf_read_blocks(mf_tag_t* tag, mf_key_type_t key_type, size_t a, size_t b);

/**
 * Connect to an nfc device. The write the tag data, authenticating with
 * the 'current_auth' keys of specified type. Finally, disconnect from
 * the device.  If there are authentication errors, those sectors will
 * not be written.
 * If the key type is set to MF_UNLOCKED, try to unlock the card prior to
 * write. This allows some pirate cards to write block 0.
 * Return 0 on success != 0 on failure.
 */
int mf_write_blocks(const mf_tag_t* tag, mf_key_type_t key_type, size_t a, size_t b);

/**
 * Connect to an nfc device.  Then, for each sector in turn, try keys in the
 * dictionary for authentication. Report success or failure. If a key
 * is found, set it in the state variable 'current_auth'. Finally,
 * disconnect from the device.
 * Return 0 on success != 0 on failure.
 */
int mf_dictionary_attack(mf_tag_t* tag);

/**
 * Connect to an nfc device. Then test the keys in the 'current_auth'
 * by trying to authenticate to the sectors of the tag. Report success
 * or failure for each sector. Finally, disconnect from the device.
 * Return 0 on success != 0 on failure.
 */
int mf_test_auth(const mf_tag_t* keys, size_t size1, size_t size2, mf_key_type_t key_type);

/**
 * GEN2 special commands
 */
int mf_gen1_wipe();

/**
 * GEN3 special commands
 */
int mf_gen3_setuid(const uint8_t uid[7]);
int mf_gen3_setblock0(const uint8_t data[16]);
int mf_gen3_lock();

int mf_ident_tag();

int mf_version();

int mf_write_mod(const mf_tag_t* tag, const mf_tag_t* keys);

int mf_emulate(mf_tag_t* tag, mf_size_t size);
int mf_remulade(mf_tag_t* keys);

int nfc_initiator_transceive_bits_safe(nfc_device *device, const uint8_t *tx, const size_t tx_len, const uint8_t *ptx, uint8_t *rx, const size_t rx_len, uint8_t *prx);

#endif
