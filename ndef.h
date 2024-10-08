#ifndef NDEF__H
#define NDEF__H

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

#include "tag.h"

// NDEF flags
typedef enum {
  TNF_EMPTY = 0x00,
  TNF_WELL_KNOWN = 0x01,
  TNF_MIME = 0x02,
  TNF_URI = 0x03,
  TNF_EXTERNAL = 0x04,
  TNF_UNKNOWN = 0x05,
  TNF_UNCHANGED = 0x06,
  TNF_RESERVED = 0x07,
  NDEF_IL = 0x08,
  NDEF_SR = 0x10,
  NDEF_CF = 0x20,
  NDEF_ME = 0x40,
  NDEF_MB = 0x80
} NDEF_flags;

// NDEF functions
int ndef_put_sectors(mf_tag_t* tag, size_t s1, size_t s2, const uint8_t* ndef, const size_t size, bool ro);
int ndef_URI_record(const char* uri, uint8_t** ndef, size_t* size);
int ndef_text_record(const char* lang, const char* text, uint8_t** ndef, size_t* size);
int ndef_mime_record(const char* mime, const uint8_t* data, size_t dl, uint8_t** ndef, size_t* size);
int ndef_external_record(const char* type, const uint8_t* data, size_t dl, uint8_t** ndef, size_t* size);
int ndef_android_app_record(const char* app, uint8_t** ndef, size_t* size);
int ndef_wifi_record(const char* ssid, const char* password, uint8_t** ndef, size_t* size);
int ndef_perm(mf_tag_t* tag, size_t s1, size_t s2, bool ro);
int ndef_print(mf_tag_t* tag, size_t sector);

#endif