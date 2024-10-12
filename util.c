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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "util.h"

void print_hex_array(const unsigned char* data, size_t nbytes) {
  print_hex_array_sep(data, nbytes, NULL);
}

void print_hex_array_sep(const unsigned char* data, size_t nbytes, const char* sep) {
  for (int i = 0; i < nbytes; i++) {
    printf("%02x%s", data[i], sep?sep:"");
  }
}

void print_ascii_rendering(const unsigned char* data, size_t nbytes, const char nonascii) {
    for (int i = 0; i < nbytes; i++) {
      printf("%c", (data[i] >= 32 && data[i] < 127) ? data[i] : nonascii);
    }
}

#define MIN(a,b) ((a) < (b) ? (a) : (b))

void print_hex_array_ascii(const unsigned char* data, size_t nbytes, size_t width) {
  const uint8_t* d = data;
  for(ssize_t s = (ssize_t)nbytes; s > 0; s -= width, d += width) {
    print_hex_array_sep(d, MIN(width, (size_t)s), " ");
    for(size_t i = MIN(width, (size_t)s); i < width; i++) {
      printf("   ");
    }
    printf(" [");
    print_ascii_rendering(d, MIN(width, (size_t)s), '.');
    for(size_t i = MIN(width, (size_t)s); i < width; i++) {
      putc(' ', stdout);
    }
    printf("]\n");
  }
}

#undef MIN

// Parse a string of hex bytes in the form xx
// returns 1 if more bytes available, -1 if invalid character
int parse_hex_str(const char* str, uint8_t res[], size_t* len) {
  const char* s = str + strspn(str, " ");
  size_t c = 0;

  while (*s != '\0' && c < *len) {
    if (s[1] == '\0') {
      *len = c;
      return -1;  // incomplete byte
    }
    char* end;
    char tmp[3] = {0};
    tmp[0] = s[0];
    tmp[1] = s[1];
    long v = strtol(tmp, &end, 16);
    if (*end != '\0') {
      *len = c;
      return -1;  // invalid character
    }
    res[c++] = (uint8_t)v;
    s += 2;
    s += strspn(s, " ");
  }
  *len = c;
  return *s == '\0' ? 0 : 1;
}

// convert hex character to value
static uint8_t hexdigit(const unsigned char c) {
  if(c >= '0' && c <= '9')
    return c-'0';
  else if(c >= 'a' && c <= 'f')
    return c-'a'+10;
  else if(c >= 'A' && c <= 'F')
    return c-'A'+10;
  else if(isspace(c))
    return 254;
  else
    return 255;
}

// Read next quoted string argument
// (ret,len,end)
// NULL,0,NULL: end of string or no string
// x,l,NULL: quoted string not terminated
char* strqtok(char* str, size_t* len, char** end) {
  if(!str) {
    if(end) *end = NULL;
    if(len) *len = 0;
    return NULL;
  }

  str += strspn(str, " ");
  if(*str == '\0') {
    if (end) *end = NULL;
    if(len) *len = 0;
    return NULL;
  }

  char delim;
  if(*str == '\'') {
    // read hex string and return
    delim = '\'';
    str++;
    int digits = 0;
    char* b = str, *res = str;
    for(uint8_t x = hexdigit((unsigned char)*str); x != 255; x = hexdigit((unsigned char)*(++str)) ) {
      if(x == 254) {    // whitespace
        if(digits > 0) {
          b++;
          digits = 0;
        }
      } else {          // hex digit
        if(digits > 0) {
          *b = (char)(*b<<4 | x);
          b++;
          digits = 0;
        } else {
          *b = (char)x;
          digits = 1;
        }
      }
    }
    if(digits) b++;
    if(end) {
      if (*str != delim) {
        *end = NULL;   // unclosed quotes or invalid hex character: return NULL
      } else {
        *end = str + 1 + strspn(str+1, " ");
      }
    }
    if(len) *len = (size_t)(b-res);
    *b = '\0';    // null terminate for good measure (not counted in len, of course)
    return res;
  }

  // read possibly quoted ASCII string with escapes
  if(*str == '"') {
    delim = '"';
    str++;
  } else {
    delim = ' ';
  }
  char* b = str, *res = str;
  int escape = 0, hex = 0;
  while(*str != '\0') {
    if(hex > 0) {
      const uint8_t x = hexdigit((unsigned char)*str);
      if(x > 15) {  // not a hex char?
        if(hex > 1) b++;
        hex = 0;
      } else {
        *b = (char)(*b<<4 | x);
        hex++;
        str++;
        continue;
      }
    }
    if(!escape && *str == delim) {
      break;
    }
    if(!escape && *str == '\\') {
      escape = 1;
      str++;
      continue;
    }
    if(escape) {
      escape = 0;
      switch(*str) {
        case 'a':
          *b++ = '\a';
          break;
        case 'b':
          *b++ = '\b';
          break;
        case 'e':
          *b++ = '\e';
          break;
        case 'f':
          *b++ = '\f';
          break;
        case 'n':
          *b++ = '\n';
          break;
        case 'r':
          *b++ = '\r';
          break;
        case 't':
          *b++ = '\t';
          break;
        case 'v':
          *b++ = '\v';
          break;
        case 'x':
          hex = 1;
          *b = 0;
          break;
        default:
          *b++ = *str;
          break;
      }
      str++;
    } else {
      *b++ = *str++;
    }
  };
  if(hex > 1) b++;
  if(end) {
    if (*str == '\0') {
      *end = delim==' ' ? str : NULL;   // unclosed quotes: return NULL
    } else {
      *end = str + 1 + strspn(str+1, " ");
    }
  }
  if(len) *len = (size_t)(b-res);
  *b = '\0';
  return res;
}
