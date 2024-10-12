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
#include "mad.h"

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
  *p++ = 'U';               // type
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
  *p++ = 'T';                   // type
  *p++ = (uint8_t)(0x00 | ll);  // payload: header (UTF-8)
  memcpy(p, lang, ll);          // payload: lang
  p += ll;
  memcpy(p, text, tl);          // payload: text

  return 0;
}

int ndef_mime_record(const char* mime, const uint8_t* data, size_t dl, uint8_t** ndef, size_t* size) {
  size_t ml = strlen(mime);
  if (ml > 255) {
    *size = 0;
    *ndef = NULL;
    return -1;
  }
  const size_t pl = ml+dl;
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

int ndef_external_record(const char* type, const uint8_t* data, size_t dl, uint8_t** ndef, size_t* size) {
  size_t tl = strlen(type), pl = tl+dl;
  bool sr = pl <= 0xFF;
  *size = pl + (sr ? 3 : 6);
  *ndef = malloc(*size);
  if (!*ndef) {
    *size = 0;
    return -1;
  }

  uint8_t* p = *ndef;
  *p++ = sr ? (NDEF_MB | NDEF_ME | NDEF_SR | TNF_EXTERNAL) : (NDEF_MB | NDEF_ME | TNF_EXTERNAL);  // flags
  *p++ = (uint8_t)tl;       // type length
  if (sr) {
    *p++ = (uint8_t)dl;     // payload length
  } else {
    *p++ = (uint8_t)((dl>>24) & 0xFF);
    *p++ = (uint8_t)((dl>>16) & 0xFF);
    *p++ = (uint8_t)((dl>> 8) & 0xFF);
    *p++ = (uint8_t)((dl    ) & 0xFF);
  }
  memcpy(p, type, tl);          // type
  p += tl;
  memcpy(p, data, dl);          // payload

  return 0;
}

int ndef_android_app_record(const char* app, uint8_t** ndef, size_t* size) {
  return ndef_external_record("android.com:pkg", (uint8_t*)app, strlen(app), ndef, size);
}

static inline void put_uint16(uint8_t** p, const uint16_t v) {
  *((*p)++) = (uint8_t)(v>>8);
  *((*p)++) = (uint8_t)(v);
}

int ndef_wifi_record(const char* ssid, const char* password, uint8_t** ndef, size_t* size) {
  const char* mime = "application/vnd.wfa.wsc";
  const uint8_t mac[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
  const size_t ssid_l = strlen(ssid), password_l = strlen(password);
  if (password_l > 64) {
    *size = 0;
    *ndef = NULL;
    return -1;
  }
  const size_t len = ssid_l+password_l+34;
  uint8_t* data = malloc(len);
  if (!data) {
    *size = 0;
    *ndef = NULL;
    return -1;
  }

  uint8_t* p = data;
  put_uint16(&p, 0x100e);   // credential tag
  put_uint16(&p, (uint16_t)(len-4));   // payload length w/o credential tag & length
  put_uint16(&p, 0x1003);   // auth type tag
  put_uint16(&p, 2);
  put_uint16(&p, 0x0020);   // WPA2 PSK (0x0001 = open, 0x0010 = WPA2 EAP, 0x0020 = WPA2 PSK)
  put_uint16(&p, 0x100F);   // encryption type tag
  put_uint16(&p, 2);
  put_uint16(&p, 0x0008);   // AES
  put_uint16(&p, 0x1045);   // ssid tag
  put_uint16(&p, (uint16_t)ssid_l);
  memcpy(p, ssid, ssid_l);
  p += ssid_l;
  put_uint16(&p, 0x1027);   // network key tag
  put_uint16(&p, (uint16_t)password_l);
  memcpy(p, password, password_l);
  p += password_l;
  put_uint16(&p, 0x1020);   // MAC (multicast)
  put_uint16(&p, sizeof(mac));
  memcpy(p, mac, sizeof(mac));
  p += sizeof(mac);

  const int res = ndef_mime_record(mime, data, len, ndef, size);

  free(data);
  return res;
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

void ndef_print_unknown_record(const ndef_record_t* r) {
  if(r->type_len > 0) {
    printf("type:\n");
    print_hex_array_ascii(r->type, r->type_len, 19);
  }
  if(r->id_len > 0) {
    printf("id:\n");
    print_hex_array_ascii(r->id, r->id_len, 19);
  }
  if(r->len > 0) {
    printf("data:\n");
    print_hex_array_ascii(r->data, r->len, 19);
  }
}

void ndef_print_external_record(const ndef_record_t* r) {
  if(r->type_len == strlen("android.com:pkg") && memcmp(r->type, "android.com:pkg", r->type_len) == 0) {
    printf("Android Application NDEF record\n");
    printf("Application: ");
    fwrite(r->data, r->len, 1, stdout);
    printf("\n");
  } else {
    printf("External NDEF record\n");
    if(r->type_len > 0) {
      printf("type: ");
      fwrite(r->type, r->type_len, 1, stdout);
      printf("\n");
    }
    if(r->id_len > 0) {
      printf("id:\n");
      print_hex_array_ascii(r->id, r->id_len, 19);
    }
    if(r->len > 0) {
      printf("data:\n");
      print_hex_array_ascii(r->data, r->len, 19);
    }
  }
}

void ndef_print_wk_record(const ndef_record_t* r) {
  const uint8_t type = r->type[0];
  switch(type) {
    case 'T':
      printf("Well-known NDEF TEXT record\n");
      if(r->len > 1){
        const uint8_t header = r->data[0], ll = header&0x3F;
        if(r->len >= ll) {
          printf("language: ");
          fwrite(r->data+1, ll, 1, stdout);
          printf("\ntext: ");
          fwrite(r->data+1+ll, r->len-ll, 1, stdout);
          printf("\n");
        }
      }
      break;
    case 'U':
      printf("Well-known NDEF URI record\n");
      if(r->len > 1){
        uint8_t prefix = r->data[0];
        printf("%s", prefix < sizeof(NDEF_uri_prefix)/sizeof(NDEF_uri_prefix[0]) ? NDEF_uri_prefix[prefix] : "[unknown prefix code]");
        fwrite(r->data+1, r->len-1, 1, stdout);
        printf("\n");
      }
      break;
    default:
      printf("Unknown well-known NDEF record\n");
      ndef_print_unknown_record(r);
  }
}

void ndef_print_uri_record(const ndef_record_t* r) {
  printf("URI NDEF record\n");
  if(r->type_len > 0) {
    printf("URI type: ");
    fwrite(r->type, r->type_len, 1, stdout);
    printf("\n");
  }
  if(r->id_len > 0) {
    printf("id:\n");
    print_hex_array_ascii(r->id, r->id_len, 19);
  }
  if(r->len > 0) {
    printf("data:\n");
    print_hex_array_ascii(r->data, r->len, 19);
  }
}

static inline uint16_t get_uint16(uint8_t** p) {
  return (uint16_t)((*((*p)++)<<8) | *((*p)++));
}

void ndef_print_wifi_record(const ndef_record_t* r) {
  printf("Wifi credentials record\n");
  uint8_t *p = (uint8_t*)r->data;
  size_t len;

  // check first two TL starting entire record
  if(r->len < 4 || get_uint16(&p) != 0x100e || (len = get_uint16(&p)) > r->len-4) {
    printf("Defective.\n");
    return;
  }
  const uint8_t *end = r->data + r->len;

  // read TLVs, needs at least 4 bytes for TL
  while(p+3 < end) {
    uint16_t t = get_uint16(&p);
    uint16_t l = get_uint16(&p);
    uint16_t v;
    if(p+l > end) {
      printf("Defective\n");
      return;
    }
    switch(t) {
      case 0x1003:  // auth type
        v = get_uint16(&p);
        printf("Authentication type: 0x%04hx\n", v);
        break;
      case 0x100F:  // enc type
        v = get_uint16(&p);
        printf("Encryption type: 0x%04hx\n", v);
        break;
      case 0x1045:  // ssid
        printf("SSID: ");
        fwrite(p, l, 1, stdout);
        printf("\n");
        p += l;
        break;
      case 0x1027:  // password
        printf("password: ");
        fwrite(p, l, 1, stdout);
        printf("\n");
        p += l;
        break;
      case 0x1020:  // MAC
        printf("MAC: ");
        print_hex_array_sep(p, l, ":");
        printf("\n");
        p += l;
        break;
      default:
        printf("unknown tag: %hd\n", t);
        p += l;
        break;
    }
  }
}

void ndef_print_mime_record(const ndef_record_t* r) {
  if(r->type_len == strlen("application/vnd.wfa.wsc") && memcmp(r->type, "application/vnd.wfa.wsc", r->type_len) == 0) {
    ndef_print_wifi_record(r);
  } else {
    printf("MIME NDEF record\n");
    if(r->type_len > 0) {
      printf("mime-type: ");
      fwrite(r->type, r->type_len, 1, stdout);
      printf("\n");
    }
    if(r->id_len > 0) {
      printf("id:\n");
      print_hex_array_ascii(r->id, r->id_len, 19);
    }
    if(r->len > 0) {
      printf("data:\n");
      print_hex_array_ascii(r->data, r->len, 19);
    }
  }
}

int ndef_print_records(const uint8_t* ndef, size_t len) {
  // parse stream of records, printing them one by one
  printf("NDEF records found\n");
  const uint8_t *p = ndef, *end = ndef+len;
  ndef_record_t r;
  do {
    memset(&r, 0, sizeof(r));
    r.flags = p[0];
    if(r.flags & NDEF_SR) {
      if(end-p < 3) return -1;
      r.type_len = p[1];
      r.len = p[2];
      p += 3;
    } else {
      if(end-p < 6) return -1;
      r.type_len = p[1];
      r.len = (uint32_t)(p[2]<<24 | p[3]<<16 | p[4]<<8 | p[5]);
      p += 6;
    }
    if(r.flags & NDEF_IL) {
      if(end-p < 1) return -1;
      r.id_len = p[0];
      p++;
    }
    if(end-p < r.id_len+r.len+r.type_len) return -1;
    if(r.type_len > 0) {
      r.type = p;
      p += r.type_len;
    }
    if(r.id_len > 0) {
      r.id = p;
      p += r.id_len;
    }
    if(r.len > 0) {
      r.data = p;
      p += r.len;
    }
    printf("\n");
    switch(r.flags & 0x07) {
      case TNF_EXTERNAL:
        ndef_print_external_record(&r);
        break;
      case TNF_MIME:
        ndef_print_mime_record(&r);
        break;
      case TNF_URI:
        ndef_print_uri_record(&r);
        break;
      case TNF_WELL_KNOWN:
        ndef_print_wk_record(&r);
        break;
      case TNF_EMPTY:
        printf("Empty record\n");
        continue;
      case TNF_UNCHANGED:
        printf("Chunked record (not supported)\n");
        break;
      case TNF_RESERVED:
      case TNF_UNKNOWN:
      default:
        printf("Unknown NDEF record\n");
        ndef_print_unknown_record(&r);
    }
  } while(!(r.flags & NDEF_ME) && p<end);
  return 0;
}

int ndef_print(mf_tag_t* tag, size_t sector) {
  if (sector == 0)
    sector = mad_find_sector(tag, 0xe103);  // find first NDEF sector
  if (sector == 0) {
    printf("No NDEF sectors found in MAD\n");
    return -1;
  }

  // copy out data from tag into contiguous buffer for simplicity
  uint8_t buf[4096] = {0}, *p = buf, *end;
  for (size_t s = sector; s < 0x28; s++) {
    if (s == 0x10) continue;
    size_t h = sector_to_header(s), c = sector_size(h);
    memcpy(p, tag->amb[h].mbd.abtData, 16*(c-1));
    p += 16*(c-1);
  }
  end = p;

  // find first NDEF TLV tag by iterating through all data bytes
  p = buf;
  size_t len;
  while (p < end) {
    const uint8_t tag = *p++;
    switch(tag) {
      case 0x00:
        continue;   // empty TLV, just skip
      case 0xfe:
        // end of records TLV, we're done
        printf("No NDEF TLV found in sector\n");
        return -1;
    }
    // any other TLV: read size (potentially read 3 bytes past end, OK as over-allocated)
    if (*p < 0xFF) {
      len = *p++;
    } else {
      len = (p[1]<<8) & (p[2]);
      p += 3;
    }
    if (tag == 0x03) break;    // found it!
    p += len; // not what we want, skip
  }

  if(p >= end) {
    // end of records TLV, we're done
    printf("No NDEF TLV found in sector\n");
    return -1;
  }

  return ndef_print_records(p, len);
}
