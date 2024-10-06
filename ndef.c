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
#include "mifare.h"
#include "util.h"
#include "ndef.h"

// access bits for RW and RO NDEF sectors (VVvvRRWW)
static const uint8_t ndef_ac_rw[] = {0x7F, 0x07, 0x88, 0b01000000 };
static const uint8_t ndef_ac_ro[] = {0x07, 0x8F, 0x0F, 0b01000011 };
static const uint8_t ndef_key_A[] = {0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7};

const char* NDEF_uri_prefix[] = {
  "",
  "http://www.",
  "https://www.",
  "http://",
  "https://",
  "tel:",
  "mailto:",
  "ftp://anonymous:anonymous@",
  "ftp://ftp.",
  "ftps://",
  "sftp://",
  "smb://",
  "nfs://",
  "ftp://",
  "dav://",
  "news:",
  "telnet://",
  "imap:",
  "rtsp://",
  "urn:",
  "pop:",
  "sip:",
  "sips:",
  "tftp:",
  "btspp://",
  "btl2cap://",
  "btgoep://",
  "tcpobex://",
  "irdaobex://",
  "file://",
  "urn:epc:id:",
  "urn:epc:tag:",
  "urn:epc:pat:",
  "urn:epc:raw:",
  "urn:epc:",
  "urn:nfc:",
  NULL
};

static int ndef_uri_prefix(const char** uri) {
  int len = 0, res = 0, i = 0;
  for( const char** prefix = NDEF_uri_prefix; *prefix; prefix++, i++ )
  {
    const int l = (int)strlen(*prefix);
    if (len <= l && strncmp(*prefix, *uri, (size_t)l) == 0) {
      len = l;
      res = i;
    }
  }
  *uri += len;
  return res;
}

int ndef_URI_record(const char* uri, uint8_t** ndef, size_t* size) {
  const char* data = uri;
  uint8_t uri_prefix = (uint8_t)ndef_uri_prefix(&data);

  size_t pl = strlen(data)+1;
  bool sr = pl <= 0xFF;
  *size = pl + (sr ? 4 : 7);
  *ndef = malloc(*size);
  if (!*ndef) {
    *size = 0;
    return -1;
  }

  uint8_t* p = *ndef;
  *p++ = sr ? (NDEF_MB | NDEF_ME | NDEF_SR | TNF_WELL_KNOWN) : (NDEF_MB | NDEF_ME | TNF_WELL_KNOWN);  // flags
  *p++ = 1;                 // type length
  if (sr) {
    *p++ = (uint8_t)pl;     // payload length
  } else {
    *p++ = (uint8_t)((pl>>24) & 0xFF);
    *p++ = (uint8_t)((pl>>16) & 0xFF);
    *p++ = (uint8_t)((pl>> 8) & 0xFF);
    *p++ = (uint8_t)((pl    ) & 0xFF);
  }
  *p++ = NDEF_URI;          // type
  *p++ = uri_prefix;        // payload: prefix code
  memcpy(p, data, pl-1);    // payload: uri

  return 0;
}

int ndef_text_record(const char* lang, const char* text, uint8_t** ndef, size_t* size) {
  size_t tl = strlen(text), ll = strlen(lang), pl = tl+ll+1;
  if (ll > 63) {
    *size = 0;
    *ndef = NULL;
    return -1;
  }
  bool sr = pl <= 0xFF;
  *size = pl + (sr ? 4 : 7);
  *ndef = malloc(*size);
  if (!*ndef) {
    *size = 0;
    return -1;
  }

  uint8_t* p = *ndef;
  *p++ = sr ? (NDEF_MB | NDEF_ME | NDEF_SR | TNF_WELL_KNOWN) : (NDEF_MB | NDEF_ME | TNF_WELL_KNOWN);  // flags
  *p++ = 1;                 // type length
  if (sr) {
    *p++ = (uint8_t)pl;     // payload length
  } else {
    *p++ = (uint8_t)((pl>>24) & 0xFF);
    *p++ = (uint8_t)((pl>>16) & 0xFF);
    *p++ = (uint8_t)((pl>> 8) & 0xFF);
    *p++ = (uint8_t)((pl    ) & 0xFF);
  }
  *p++ = NDEF_TEXT;         // type
  *p++ = (uint8_t)(0x00 | ll);  // payload: header (UTF-8)
  memcpy(p, lang, ll);          // payload: lang
  p += ll;
  memcpy(p, text, tl);          // payload: text

  return 0;
}

int ndef_mime_record(const char* mime, const char* data, uint8_t** ndef, size_t* size) {
  size_t ml = strlen(mime), dl = strlen(data), pl = ml+dl;
  if (ml > 255) {
    *size = 0;
    *ndef = NULL;
    return -1;
  }
  bool sr = pl <= 0xFF;
  *size = pl + (sr ? 3 : 6);
  *ndef = malloc(*size);
  if (!*ndef) {
    *size = 0;
    return -1;
  }

  uint8_t* p = *ndef;
  *p++ = sr ? (NDEF_MB | NDEF_ME | NDEF_SR | TNF_MIME) : (NDEF_MB | NDEF_ME | TNF_MIME);  // flags
  *p++ = (uint8_t)ml;       // type length
  if (sr) {
    *p++ = (uint8_t)dl;     // payload length
  } else {
    *p++ = (uint8_t)((dl>>24) & 0xFF);
    *p++ = (uint8_t)((dl>>16) & 0xFF);
    *p++ = (uint8_t)((dl>> 8) & 0xFF);
    *p++ = (uint8_t)((dl    ) & 0xFF);
  }
  memcpy(p, mime, ml);          // type: mime-type
  p += ml;
  memcpy(p, data, dl);          // payload: data

  return 0;
}

int ndef_put_sectors(mf_tag_t* tag, size_t s1, size_t s2, const uint8_t* ndef, const size_t size, bool ro) {
  // check size
  bool short_tlv = size <= 0xfe;
  size_t ss = 0, tlv_size = size + (short_tlv ? 2 : 4) + 1; // final closing tlv
  for (size_t s = s1; s <= s2; s++) {
    if (s==0 || s==0x10) continue;    // reserved sectors
    ss += (sector_size(sector_to_header(s))-1)*16;
  }
  if (ss < tlv_size)
    return -1;

  // combined data
  uint8_t* tlv = malloc(tlv_size);
  if (!tlv)
    return -1;
  if (short_tlv) {
    tlv[0] = 0x03;
    tlv[1] = (uint8_t)size;
    memcpy(tlv+2, ndef, size);
  } else {
    tlv[0] = 0x03;
    tlv[1] = 0xFF;
    tlv[2] = (uint8_t)((size>>8) & 0x0F);
    tlv[3] = (uint8_t)(size & 0x0F);
    memcpy(tlv+4, ndef, size);
  }
  tlv[tlv_size-1] = 0xfe;   // NDEF terminal TLV

  // copy tlv and adjust access bits
  uint8_t* data = tlv;
  for (size_t s = s1; s <= s2 && tlv_size > 0; s++) {
    if (s==0 || s==0x10) continue;    // reserved sectors
    size_t header = sector_to_header(s);
    size_t trailer = sector_to_trailer(s);
    for (size_t b = header; b < trailer && tlv_size > 0; b++) {
      for (size_t i=0; i < 16 && tlv_size > 0; i++) {
        tag->amb[b].mbd.abtData[i] = *data;
        tlv_size--; data++;
      }
    }
    // adjust keys and access bits
    memcpy(tag->amb[trailer].mbt.abtKeyA, ndef_key_A, sizeof(ndef_key_A));
    memcpy(tag->amb[trailer].mbt.abtAccessBits, ro ? ndef_ac_ro : ndef_ac_rw, sizeof(ndef_ac_rw));
  }

  free(tlv);
  return 0;
}

int ndef_perm(mf_tag_t* tag, size_t s1, size_t s2, bool ro) {
  for (size_t s = s1; s <= s2; s++) {
    if (s==0 || s==0x10) continue;    // reserved sectors
    size_t trailer = sector_to_trailer(s);
    memcpy(tag->amb[trailer].mbt.abtAccessBits, ro ? ndef_ac_ro : ndef_ac_rw, sizeof(ndef_ac_rw));
  }
  return 0;
}

int ndef_print(mf_tag_t* tag) {
  printf("Not yet implemented\n");
  return -1;
}
