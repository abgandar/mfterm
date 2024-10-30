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

void print_hex_array(const unsigned char* data, const size_t nbytes) {
  print_hex_array_sep(data, nbytes, NULL);
}

void print_hex_array_sep(const unsigned char* data, const size_t nbytes, const char* sep) {
  for (int i = 0; i < nbytes; i++) {
    printf("%02x%s", data[i], (sep && i < nbytes-1) ? sep : "");
  }
}

void print_ascii_rendering(const unsigned char* data, const size_t nbytes, const char nonascii) {
    for (int i = 0; i < nbytes; i++) {
      printf("%c", (data[i] >= 32 && data[i] < 127) ? data[i] : nonascii);
    }
}

#define MIN(a,b) ((a) < (b) ? (a) : (b))

void print_hex_array_ascii(const unsigned char* data, const size_t nbytes, const size_t width) {
  const uint8_t* d = data;
  for(ssize_t s = (ssize_t)nbytes; s > 0; s -= width, d += width) {
    print_hex_array_sep(d, MIN(width, (size_t)s), " ");
    for(size_t i = MIN(width, (size_t)s); i < width; i++) {
      printf("   ");
    }
    printf("  [");
    print_ascii_rendering(d, MIN(width, (size_t)s), '.');
    for(size_t i = MIN(width, (size_t)s); i < width; i++) {
      putc(' ', stdout);
    }
    printf("]\n");
  }
}

#undef MIN

// convert hex character to value
static inline uint8_t hexdigit(const unsigned char c) {
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

// read hex string
static int hexstr(char* str, size_t* len) {
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
  if(len) *len = (size_t)(b-res);
  int r = *str;
  *b = '\0';    // null terminate for good measure (not counted in len, of course)
  return r;     // conversion worked if *str == '\0' (before we possibly set it to 0)
}

// read a file and replace res with pointer to file content
static int readfile(char** res, size_t* len) {
  FILE *f = fopen(*res, "r");
  if(!f) return -1;
  fseek(f, 0, SEEK_END);
  long flen = ftell(f);
  if(flen < 0) {
    fclose(f);
    return -2;
  }
  if(flen > 1024*4) flen = 1024*4;    // only read up to 4kB
  fseek(f, 0, SEEK_SET);
  char* data = malloc((size_t)flen + 1);
  if(!data) {
    fclose(f);
    return -3;
  }
  const size_t rlen = fread(data, 1, (size_t)flen, f);
  fclose(f);
  if(rlen != flen) {
    free(data);
    return -4;
  }
  data[rlen] = '\0';    // null terminate for good measure (not counted in len, of course)
  *res = data;
  if(len) *len = rlen;
  return 0;
}

// Read next quoted string argument
// (ret,len,end)
// NULL,0,NULL: end of string or no string
// x,l,NULL: quoted string not terminated or error in type conversion
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

  char delim, type = '\0';

  // type modifiers
  switch(*str) {
    case '$':
    case '<':
      type = *str;
      str++;
      break;
  }

  // read possibly quoted ASCII string with possible escapes
  if(*str == '"') {
    delim = '"';
    str++;
  } else if(*str == '\'') {
    delim = '\'';
    str++;
  } else {
    delim = ' ';
  }
  char* b = str, *res = str;
  int escape = 0, hex = 0;
  while(*str != '\0') {
    // within a hex escape?
    if(hex > 0) {
      const uint8_t x = hexdigit((unsigned char)*str);
      if(x > 15) {  // not a hex char? End of hex escape, handle normally
        if(hex > 1) b++;
        hex = 0;
      } else {
        *b = (char)(*b<<4 | x);
        hex++;
        str++;
        continue;
      }
    }
    // end of string?
    if(!escape && *str == delim) {
      break;
    }
    // entering an escape?
    if(delim == '"' && !escape && *str == '\\') {
      escape = 1;
      str++;
      continue;
    }
    // within an escape?
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
      // copy character verbatim
      *b++ = *str++;
    }
  };

  // end any open hex escape
  if(hex > 1) b++;

  // close result string
  if(end) {
    if (*str == '\0') {
      *end = delim==' ' ? str : NULL;   // unclosed quotes: return NULL
    } else {
      *end = str + 1 + strspn(str+1, " ");
    }
  }
  if(len) *len = (size_t)(b-res);
  *b = '\0';

  // Handle type modifiers of result string
  int r;
  switch(type) {
    case '$':
      r = hexstr(res, len);
      if(end && r) *end = NULL;  // invalid character in hex string
      break;
    case '<':
      r = readfile(&res, len);
      if(end && r) *end = NULL;  // unable to read file
      break;
  }

  return res;
}
