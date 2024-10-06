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

/* Strip whitespace from the start and end of STRING.  Return a pointer
   into STRING. */
char* trim(char* string) {
  char* s = string;
  while (isspace(*s))
    ++s;

  if (*s == 0)
    return s;

  char* t = s + strlen(s) - 1;
  while (t > s && isspace(*t))
    --t;
  *++t = '\0';

  return s;
}

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

// helper function to read a key ignoring any extra characters
uint8_t* parse_key(uint8_t* key, const char* str) {
  if (!key || !str)
    return NULL;

  size_t len = 6;
  parse_hex_str(str, key, &len);
  if (len != 6)
    return NULL;
  else
    return key;
}

// Read next quoted string argument
// (ret,end)
// NULL,NULL: end of string
// x,NULL: quoted string not terminated
char* strqtok(char* str, char** end) {
  if (!str) {
    if (end) *end = NULL;
    return NULL;
  }
  str += strspn(str, " ");
  if (*str == '\0') {
    if (end) *end = NULL;
    return NULL;
  }
  char delim;
  if (*str == '"') {
    delim = '"';
    str++;
  } else {
    delim = ' ';
  }
  char* b = str, *res = str;
  int escape = 0;
  while (*str != '\0') {
    if (!escape && *str == delim) {
      break;
    }
    if (!escape && *str == '\\') {
      escape = 1;
      str++;
      continue;
    }
    *b++ = *str++;
    escape = 0;
  };
  if (end) {
    if (*str == '\0') {
      *end = delim==' ' ? str : NULL;   // unclosed quotes: return NULL
    } else {
      *end = str + 1 + strspn(str+1, " ");
    }
  }
  *b = '\0';
  return res;
}
