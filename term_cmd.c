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
 * Parts of code used in this file are from the GNU readline library file
 * fileman.c (GPLv3). Copyright (C) 1987-2009 Free Software Foundation, Inc
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include "mfterm.h"
#include "tag.h"
#include "ndef.h"
#include "mad.h"
#include "term_cmd.h"
#include "mifare_ctrl.h"
#include "dictionary.h"
#include "spec_syntax.h"
#include "util.h"
#include "mac.h"

const command_t commands[] = {
  { "help",         com_help,          0, 0, "Display this text for all commands" },
  { "?",            com_help,          0, 0, "Alias of help" },
  { "version",      com_version,       0, 1, "Show version information" },
  { "devices",      com_devices,       0, 1, "List all connected NFC devices" },

  { "quit",         com_quit,          0, 1, "Exit the program" },
  { "q",            com_quit,          0, 0, "Alias of quit" },
  { "exit",         com_quit,          0, 0, "Alias of quit" },

  { "load",         com_load_tag,      1, 1, "Load tag data from a file" },
  { "save",         com_save_tag,      1, 1, "Save tag data to a file" },

  { "reset",        com_reset_tag,     0, 1, "Reset all tag data including keys and permissions" },
  { "clear",        com_clear_sector,  0, 1, "Clear the sector user data" },
  { "clear block",  com_clear_block,   0, 1, "Clear the block user data" },
  { "clear all",    com_clear_all,     0, 1, "Clear all data" },

  { "read",         com_read_sector,   0, 1, "#sector: Read sector from a physical tag" },
  { "read block",   com_read_block,    0, 1, "#sector: Read block from a physical tag" },
  { "write!",       com_write_sector,  0, 1, "#sector: Write sector to a physical tag" },
  { "write! block", com_write_block,   0, 1, "#block: Write block to a physical tag" },
  { "write! mod",   com_write_mod,     0, 1, "Set load modulation strength on a physical tag" },

  { "gen1 wipe!",   com_gen1_wipe,     0, 1, "On GEN1 cards, wipe entire card without keys" },

  { "gen3 setuid!", com_gen3_writeuid, 0, 1, "On GEN3 cards, set UID without modifying block 0" },
  { "gen3 write0!", com_gen3_write0,   0, 1, "On GEN3 cards, write block 0 and set UID" },
  { "gen3 lock!",   com_gen3_lock,     0, 1, "On GEN3 cards, lock card UID/block0 permanently" },

  { "ident",        com_ident,         0, 1, "Identify card and print public information" },
  { "check",        com_check_tag,     0, 1, "Check the current tag data" },
  { "fix",          com_fix_tag,       0, 1, "Try to fix errors in current tag data" },

  { "print",        com_print_sectors, 0, 1, "#sector: Print tag sector data" },
  { "p",            com_print_sectors, 0, 0, "Alias of print" },
  { "print block",  com_print_blocks,  0, 1, "#block: Print tag block data" },
  { "print keys",   com_print_keys,    0, 1, "#sector: Print tag sector keys" },
  { "print perm",   com_print_perm,    0, 1, "#sector: Print tag sector permissions" },

  { "edit",         com_edit,          0, 1, "#block #offset ASCII: Set tag block data" },
  { "edit hex",     com_edit_hex,      0, 1, "#block #offset hex: Set tag block data" },
  { "edit uid",     com_edit_uid,      0, 1, "xxxxxxxx[xxxxxx]: Set tag UID" },
  { "edit key",     com_edit_key,      0, 1, "#sector A|B|AB xxxxxxxxxxxx: Set tag sector key" },
  { "edit perm",    com_edit_perm,     0, 1, "#block C1C2C3: Set tag block permissions" },
  { "edit mod",     com_edit_mod,      0, 1, "1|0: Set load modulation strength (1=strong, 0=normal)" },

  { "ndef",         com_ndef,          0, 1, "#sector: Show NDEF record(s) in sector(s)" },
  { "ndef put",     com_ndef_put,      0, 1, "#sector (U URL | T LANG TEXT | M MIME CONTENT)...: Place NDEF record(s) in sector(s)" },

  { "mad",          com_mad,           0, 1, "Print tag MAD" },
  { "mad put",      com_mad_put,       0, 1, "#sector AID: Set 16-bit AID for given sector(s)" },
  { "mad size",     com_mad_size,      0, 1, "1K|4K: Set tag MAD size/version (v1=1K, v2=4K)" },
  { "mad init",     com_mad_init,      0, 1, "1K|4K: Initialize tag MAD (v1=1K, v2=4K)" },
  { "mad crc",      com_mad_crc,       0, 1, "Update tag MAD CRC" },

  { "set",          com_set,           0, 1, "Print current settings" },
  { "set auth",     com_set_auth,      0, 1, "A|B|AB|*: Set keys for authentication (* = gen1 unlock)" },
  { "set size",     com_set_size,      0, 1, "1K|4K: Set the default tag size" },
  { "set device",   com_set_device,    0, 1, "Set NFC device to use" },

  { "auth",         com_auth_print,    0, 1, "#sector: Print sector auth keys" },
  { "auth load",    com_auth_load,     1, 1, "Load auth keys from file" },
  { "auth save",    com_auth_save,     1, 1, "Save auth keys to file" },
  { "auth clear",   com_auth_clear,    0, 1, "Clear auth keys" },
  { "auth put",     com_auth_put,      0, 1, "#sector A|B|AB xxxxxxxxxxxx: Set auth key" },
  { "auth import",  com_auth_import,   0, 1, "#sector A|B|AB: Import sector auth keys from tag" },
  { "auth export",  com_auth_export,   0, 1, "#sector A|B|AB: Export sector auth keys to tag" },
  { "auth test",    com_auth_test,     0, 1, "#sector A|B|AB: Try to authenticate with auth keys" },

  { "dict",         com_dict_print,    0, 1, "Print the key dictionary" },
  { "dict load",    com_dict_load,     1, 1, "Load a dictionary key file" },
  { "dict add",     com_dict_add,      0, 1, "Add key to key dictionary" },
  { "dict clear",   com_dict_clear,    0, 1, "Clear the key dictionary" },
  { "dict attack",  com_dict_attack,   0, 1, "Find keys of a physical tag"},

  { "spec",         com_spec_print,    0, 1, "Print the specification" },
  { "spec load",    com_spec_load,     1, 1, "Load a specification file" },
  { "spec clear",   com_spec_clear,    0, 1, "Unload the specification" },

  { "mac key",      com_mac_key_get_set,   0, 1, "<k0..k7> : Get or set MAC key" },
  { "mac compute",  com_mac_block_compute, 0, 1, "#block : Compute block MAC" },
  { "mac update",   com_mac_block_update,  0, 1, "#block : Update block MAC" },
  { "mac validate", com_mac_validate,      0, 1, "1k|4k : Validates block MAC of the whole tag" },

  { (char *)NULL,   (cmd_func_t)NULL,      0, 0, (char *)NULL }
};

// Parse a range of positive numbers in given base A-B (with either number ommitted leaving corresponding a and b unchanged)
int parse_range(const char* str, size_t* a, size_t* b, int base);

// Parse a range of sectors
int parse_sectors(const char* str, size_t* a, size_t* b, const char* def);

// Parse a range of blocks
int parse_blocks(const char* str, size_t* a, size_t* b, const char* def);

// Parse a Mifare key type argument (A|B|AB|*)
mf_key_type_t parse_key_type(const char* str, const char* def);

// Parse a key size (1K|4K)
mf_size_t parse_size(const char* str, const char* def);

// Compute the MAC using the current_mac_key
int com_mac_block_compute_impl(char* argv[], size_t argc, int update);

// edit implementation
int com_edit_impl(char* argv[], size_t argc, bool hex);


/**
 * Helper functions
 */

const command_t* find_command(const char *name) {
  const command_t* cmd = NULL;
  size_t cmd_len = 0;

  for (size_t i = 0; commands[i].name; ++i) {
    size_t l = strlen(commands[i].name);
    if (l > cmd_len && strncmp(name, commands[i].name, l) == 0) {
      cmd = &commands[i];
      cmd_len = l;
    }
  }

  return cmd;
}

void print_help_(size_t cmd) {
  // Find longest command (and cache the result)
  static size_t cmd_len_max = 0;
  if (cmd_len_max == 0) {
    for (int i = 0; commands[i].name; ++i) {
      size_t cmd_len = strlen(commands[i].name);
      cmd_len_max = cmd_len > cmd_len_max ? cmd_len : cmd_len_max;
    }
  }
  // Format: 4x' ' | cmd | ' '-pad-to-longest-cmd | 4x' ' | doc
  printf ("    %s", commands[cmd].name);
  for (int j = (int)(cmd_len_max - strlen(commands[cmd].name)); j >= 0; --j)
    printf(" ");
  printf ("    %s.\n", commands[cmd].doc);
}

// Any command starting with '.' - path spec
int exec_path_command(const char *line) {
  instance_t* inst = parse_spec_path(line);

  if (inst)
    print_tag_data_range(inst->offset_bytes, inst->offset_bits, inst->size_bytes, inst->size_bits);
  else
    printf("Invalid Path\n");

  return 0;
}

/**
 * Command functions
 */

int com_help(char* argv[], size_t argc) {
  if (argc > 0) {
    int found = 0;
    for (char** arg = argv; *arg; arg++) {
      bool ok = false;
      for (size_t i = 0; commands[i].name; ++i) {
        if (strcmp(*arg, commands[i].name) == 0) {
          print_help_(i);
          found++;
          ok = true;
          break;
        }
      }
      if (!ok) printf ("No commands match '%s'\n", *arg);
    }
    return found == argc ? 0 : -1;
  }

  for (size_t i = 0; commands[i].name; i++) {
    if (commands[i].document)
      print_help_(i);
  }

  return 0;
}

int com_quit(char* argv[], size_t argc) {
  stop_input_loop();
  return 0;
}

int com_load_tag(char* argv[], size_t argc) {
  if (argc != 1 || *argv[0] == '\0') {
    printf("Expecting a single file name\n");
    return -1;
  }

  int res = load_tag(argv[0]);
  if (res == 0)
    printf("Successfully loaded tag from: %s\n", argv[0]);
  else
    printf("Failed to load tag from: %s\n", argv[0]);
  return res;
}

int com_save_tag(char* argv[], size_t argc) {
  if (argc != 1 || *argv[0] == '\0') {
    printf("Expecting a single file name\n");
    return -1;
  }

  int res = save_tag(argv[0]);
  if (res == 0)
    printf("Successfully wrote tag to: %s\n", argv[0]);
  else
    printf("Failed to write tag to: %s\n", argv[0]);
  return res;
}

int com_reset_tag(char* argv[], size_t argc) {
  if (argc > 0) {
    printf("Too many arguments\n");
    return -1;
  }

  reset_tag(&current_tag);
  return 0;
}

int com_clear_all(char* argv[], size_t argc) {
  if (argc > 0) {
    printf("Too many arguments\n");
    return -1;
  }

  clear_tag(&current_tag);
  return 0;
}

int com_clear_block(char* argv[], size_t argc) {
  if (argc > 1) {
    printf("Expecting a single block range\n");
    return -1;
  }

  size_t b1, b2;
  if( parse_blocks( argv[0], &b1, &b2, settings.size ) != 0 ) {
    printf("Invalid block range: %s\n", argv[0] ? argv[0] : settings.size);
    return -1;
  }
  if (b2 > 0xff || b1 > b2) {
    printf("Invalid block range: %lu-%lu\n", b1, b2);
    return -1;
  }

  clear_blocks(&current_tag, b1, b2);
  return 0;
}

int com_clear_sector(char* argv[], size_t argc) {
  if (argc > 1) {
    printf("Expecting a single sector range\n");
    return -1;
  }

  size_t s1, s2;
  if( parse_sectors( argv[0], &s1, &s2, settings.size ) != 0 ) {
    printf("Invalid sector range: %s\n", argv[0] ? argv[0] : settings.size);
    return -1;
  }
  if (s2 > 39 || s1 > s2) {
    printf("Invalid sector range: %lu-%lu\n", s1, s2);
    return -1;
  }
  s1 = sector_to_header(s1);
  s2 = sector_to_trailer(s2);

  clear_blocks(&current_tag, s1, s2);
  return 0;
}

int com_read_block(char* argv[], size_t argc) {
  if (argc > 1) {
    printf("Expecting a single block range\n");
    return -1;
  }

  size_t b1, b2;
  if( parse_blocks( argv[0], &b1, &b2, settings.size ) != 0 ) {
    printf("Invalid block range: %s\n", argv[0] ? argv[0] : settings.size);
    return -1;
  }
  if (b2 > 0xff || b1 > b2) {
    printf("Invalid block range: %lu-%lu\n", b1, b2);
    return -1;
  }

  return mf_read_blocks(&current_tag, parse_key_type(settings.auth, NULL), b1, b2);
}

int com_read_sector(char* argv[], size_t argc) {
  if (argc > 1) {
    printf("Expecting a single sector range\n");
    return -1;
  }

  size_t s1, s2;
  if( parse_sectors( argv[0], &s1, &s2, settings.size ) != 0 ) {
    printf("Invalid sector range: %s\n", argv[0] ? argv[0] : settings.size);
    return -1;
  }
  if (s2 > 39 || s1 > s2) {
    printf("Invalid sector range: %lu-%lu\n", s1, s2);
    return -1;
  }
  s1 = sector_to_header(s1);
  s2 = sector_to_trailer(s2);

  return mf_read_blocks(&current_tag, parse_key_type(settings.auth, NULL), s1, s2);
}

int com_write_block(char* argv[], size_t argc) {
  if (argc > 1) {
    printf("Expecting a single block range\n");
    return -1;
  }

  size_t b1, b2;
  if( parse_blocks( argv[0], &b1, &b2, settings.size ) != 0 ) {
    printf("Invalid block range: %s\n", argv[0] ? argv[0] : settings.size);
    return -1;
  }
  if (b2 > 0xff || b1 > b2) {
    printf("Invalid block range: %lu-%lu\n", b1, b2);
    return -1;
  }

  return mf_write_blocks(&current_tag, parse_key_type(settings.auth, NULL), b1, b2);
}

int com_write_sector(char* argv[], size_t argc) {
  if (argc > 1) {
    printf("Expecting a single sector range\n");
    return -1;
  }

  size_t s1, s2;
  if( parse_sectors( argv[0], &s1, &s2, settings.size ) != 0 ) {
    printf("Invalid sector range: %s\n", argv[0] ? argv[0] : settings.size);
    return -1;
  }
  if (s2 > 39 || s1 > s2) {
    printf("Invalid sector range: %lu-%lu\n", s1, s2);
    return -1;
  }
  s1 = sector_to_header(s1);
  s2 = sector_to_trailer(s2);

  return mf_write_blocks(&current_tag, parse_key_type(settings.auth, NULL), s1, s2);
}

int com_write_mod(char* argv[], size_t argc) {
  if (argc > 0) {
    printf("Too many arguments\n");
    return -1;
  }

  int res = mf_write_mod(&current_tag, &current_auth);
  if (res == 0)
    printf("Load modulation set.\n");

  return res;
}

int com_ident(char* argv[], size_t argc) {
  if (argc > 0) {
    printf("Too many arguments\n");
    return -1;
  }

  return mf_ident_tag();
}

int com_check_tag(char* argv[], size_t argc) {
  if (argc > 0) {
    printf("Too many arguments\n");
    return -1;
  }

  check_tag(&current_tag, false);
  return 0;
}

int com_fix_tag(char* argv[], size_t argc) {
  if (argc > 0) {
    printf("Too many arguments\n");
    return -1;
  }

  check_tag(&current_tag, true);
  return 0;
}

int com_devices(char* argv[], size_t argc) {
  if (argc > 0) {
    printf("Too many arguments\n");
    return -1;
  }

  return mf_devices();
}

int com_version(char* argv[], size_t argc) {
  if (argc > 0) {
    printf("Too many arguments\n");
    return -1;
  }

  return mf_version();
}

int com_print_blocks(char* argv[], size_t argc) {
  if (argc > 1) {
    printf("Expecting a single block range\n");
    return -1;
  }

  size_t b1, b2;
  if( parse_blocks( argv[0], &b1, &b2, settings.size ) != 0 ) {
    printf("Invalid block range: %s\n", argv[0] ? argv[0] : settings.size);
    return -1;
  }
  if (b2 > 0xff || b1 > b2) {
    printf("Invalid block range: %lu-%lu\n", b1, b2);
    return -1;
  }

  print_tag_block_range(b1, b2);
  return 0;
}

int com_print_sectors(char* argv[], size_t argc) {
  if (argc > 1) {
    printf("Expecting a single sector range\n");
    return -1;
  }

  size_t s1, s2;
  if( parse_sectors( argv[0], &s1, &s2, settings.size ) != 0 ) {
    printf("Invalid sector range: %s\n", argv[0] ? argv[0] : settings.size);
    return -1;
  }
  if (s2 > 39 || s1 > s2) {
    printf("Invalid sector range: %lu-%lu\n", s1, s2);
    return -1;
  }
  s1 = sector_to_header(s1);
  s2 = sector_to_trailer(s2);

  print_tag_block_range(s1, s2);
  return 0;
}

int com_edit(char* argv[], size_t argc) {
  return com_edit_impl(argv, argc, false);
}

int com_edit_hex(char* argv[], size_t argc) {
  return com_edit_impl(argv, argc, true);
}

int com_edit_impl(char* argv[], size_t argc, bool hex) {
  if (argc != 3) {
    printf("Expecting three arguments: #block offset hex\n");
    return -1;
  }

  size_t b1, b2;
  if( parse_blocks( argv[0], &b1, &b2, settings.size ) != 0 ) {
    printf("Invalid block range: %s\n", argv[0]);
    return -1;
  }
  if (b2 > 0xff || b1 > b2) {
    printf("Invalid block range: %lu-%lu\n", b1, b2);
    return -1;
  }

  char* offset_str = argv[1];
  size_t offset = strtoul(offset_str, &offset_str, 0);
  if (*offset_str != '\0') {
    printf("Invalid offset: %s\n", argv[1]);
    return -1;
  }
  if (offset > 15) {
    printf("Invalid offset [0,15]: %lu\n", offset);
    return -1;
  }

  uint8_t bytes[0x10];
  size_t count = 0x10;
  if (hex) {
    if (parse_hex_str(argv[2], bytes, &count) != 0 || count+offset > 16) {
      printf("Hex string invalid or too long: %s\n", argv[2]);
      return -1;
    }
  } else {
    count = strlen(argv[2]);
    if (count+offset > 16) {
      printf("ASCII string too long: %s\n", argv[2]);
      return -1;
    }
    memcpy(bytes, argv[2], count);
  }

  if (count == 0) {
    printf("No bytes specified.\n");
    return -1;
  }

  for( size_t block = b1; block <= b2; block++ )
    memcpy( current_tag.amb[block].mbd.abtData+offset, bytes, count );

  return 0;
}

int com_edit_key(char* argv[], size_t argc) {
  if (argc != 3) {
    printf("Expecting three arguments: #sector A|B|AB key\n");
    return -1;
  }

  size_t s1, s2;
  if( parse_sectors( argv[0], &s1, &s2, settings.size ) != 0 ) {
    printf("Invalid sector range: %s\n", argv[0]);
    return -1;
  }
  if (s2 > 39 || s1 > s2) {
    printf("Invalid sector range: %lu-%lu\n", s1, s2);
    return -1;
  }

  mf_key_type_t key_type = parse_key_type(argv[1], NULL);
  if (key_type != MF_KEY_A && key_type != MF_KEY_B && key_type != MF_KEY_AB) {
    printf("Invalid argument (A|B|AB): %s\n", argv[1]);
    return -1;
  }

  uint8_t key[6];
  size_t len = 6;
  if (parse_hex_str(argv[2], key, &len) != 0 || len != 6) {
    printf("Invalid key (expecting 6 bytes): %s\n", argv[2]);
    return -1;
  }

  for( size_t sector = s1; sector <= s2; sector++ ) {
    size_t block = sector_to_trailer(sector);

    // copy to appropriate keys
    if (key_type == MF_KEY_A || key_type == MF_KEY_AB)
      memcpy( current_tag.amb[block].mbt.abtKeyA, key, sizeof(key) );

    if (key_type == MF_KEY_B || key_type == MF_KEY_AB)
      memcpy( current_tag.amb[block].mbt.abtKeyB, key, sizeof(key) );
  }

  return 0;
}

int com_edit_perm(char* argv[], size_t argc) {
  if (argc != 2) {
    printf("Expecting two arguments: #block C1C2C3\n");
    printf("C1 C2 C3  !   R   W   I   D   !  AR  AW  ACR ACW BR  BW\n"
           "----------+-------------------+------------------------\n"
           "0  0  0   !  A|B A|B A|B A|B  !   x   A   A   x   A   A\n"
           "0  0  1   !  A|B  x   x  A|B  !   x   A   A   A   A   A\n"
           "0  1  0   !  A|B  x   x   x   !   x   x   A   x   A   x\n"
           "0  1  1   !   B   B   x   x   !   x   B  A|B  B   x   B\n"
           "1  0  0   !  A|B  B   x   x   !   x   B  A|B  x   x   B\n"
           "1  0  1   !   B   x   x   x   !   x   x  A|B  B   x   x\n"
           "1  1  0   !  A|B  B   B  A|B  !   x   x  A|B  x   x   x\n"
           "1  1  1   !   x   x   x   x   !   x   x  A|B  x   x   x\n");
    return -1;
  }

  // parse block
  size_t block1, block2;
  if (parse_blocks(argv[0], &block1, &block2, settings.size) != 0) {
    printf("Unknown argument: %s\n", argv[0] ? argv[0] : settings.size);
    return -1;
  }
  if (block2 > 0xff || block1 > block2) {
    printf("Invalid block [0,ff]: %lu - %lu\n", block1, block2);
    return -1;
  }

  // parse permission bits
  if (strspn(argv[1], "01") < 3 || argv[1][3] != '\0') {
    printf("Invalid permissions C1C2C3: %s\n", argv[1]);
    printf("C1 C2 C3  !   R   W   I   D   !  AR  AW  ACR ACW BR  BW\n"
           "----------+-------------------+------------------------\n"
           "0  0  0   !  A|B A|B A|B A|B  !   x   A   A   x   A   A\n"
           "0  0  1   !  A|B  x   x  A|B  !   x   A   A   A   A   A\n"
           "0  1  0   !  A|B  x   x   x   !   x   x   A   x   A   x\n"
           "0  1  1   !   B   B   x   x   !   x   B  A|B  B   x   B\n"
           "1  0  0   !  A|B  B   x   x   !   x   B  A|B  x   x   B\n"
           "1  0  1   !   B   x   x   x   !   x   x  A|B  B   x   x\n"
           "1  1  0   !  A|B  B   B  A|B  !   x   x  A|B  x   x   x\n"
           "1  1  1   !   x   x   x   x   !   x   x  A|B  x   x   x\n");
    return -1;
  }
  uint32_t c1 = (uint32_t)(argv[1][0]-'0');
  uint32_t c2 = (uint32_t)(argv[1][1]-'0');
  uint32_t c3 = (uint32_t)(argv[1][2]-'0');

  // set bits for all blocks
  for (size_t block =  block1; block <= block2; block++ )
    set_ac(&current_tag, block, c1, c2, c3);
  return 0;
}

int com_edit_uid(char* argv[], size_t argc) {
  uint8_t uid[7];
  size_t len = 7;
  int i = parse_hex_str(argv[0], uid, &len);
  if (argc != 1 || i != 0 || (len != 4 && len != 7)) {
    printf("Expecting a single 4 or 7 byte hex string: %s\n", argv[0] ? argv[0] : "");
    return -1;
  }

  if( len == 4 ) {
    uid[4] = uid[0] ^ uid[1] ^ uid[2] ^ uid[3];
    len = 5;
  }

  memcpy( current_tag.amb[0].mbd.abtData, uid, len );
  return 0;
}

int com_edit_mod(char* argv[], size_t argc) {
  if (argc != 1) {
    printf("Expecting a single argument: 0|1\n");
    return -1;
  }

  char* mod_str = argv[0];
  long int val = strtol(mod_str, &mod_str, 0);
  if (val < 0 || val > 1 || *mod_str != '\0') {
    printf("Invalid load modulation strength [0,1]: %lx\n", val);
    return -1;
  }

  current_tag.amb[0].mbd.abtData[11] = val ? 0x20 : 0x00;
  printf("Load modulation strength set to: %hhx\n", current_tag.amb[0].mbd.abtData[11]);
  return 0;
}

int com_ndef(char* argv[], size_t argc) {
  if (argc > 0) {
    printf("Too many arguments\n");
    return -1;
  }
  ndef_print(&current_tag);
  return -1;
}

int com_ndef_put(char* argv[], size_t argc) {
  if (argc < 3) {
    printf("Expecting at least three argument: #sector type data...\n");
    printf("  T language text\n  U url\n  M mime-type content\n");
    return -1;
  }

  size_t s1, s2;
  if( parse_sectors( argv[0], &s1, &s2, settings.size ) != 0 ) {
    printf("Invalid sector range: %s\n", argv[0]);
    return -1;
  }
  if (s2 > 39 || s1 > s2) {
    printf("Invalid sector range: %lu-%lu\n", s1, s2);
    return -1;
  }

  uint8_t ndef[2048];
  size_t size = 0;

  // parse remaining arguments as NDEF records
  argv++;
  while (*argv) {
    char *type_str = *argv, type = type_str[0];
    if (type_str[1] != '\0') {
      printf("Invalid type (U|T|M): %s\n", type_str);
      return -1;
    }
    argv++;

    uint8_t *buf = NULL;
    size_t bsize = 0;
    switch (type) {
      case 'U':
        if (!argv[0]) {
          printf("Not enough arguments for record type %c\n", type);
          return -1;
        }
        ndef_URI_record(argv[0], &buf, &bsize);
        argv++;
        break;
      case 'T':
        if (!argv[0] || !argv[1]) {
          printf("Not enough arguments for record type %c\n", type);
          return -1;
        }
        ndef_text_record(argv[0], argv[1], &buf, &bsize);
        argv += 2;
        break;
      case 'M':
        if (!argv[0] || !argv[1]) {
          printf("Not enough arguments for record type %c\n", type);
          return -1;
        }
        ndef_mime_record(argv[0], argv[1], &buf, &bsize);
        argv += 2;
        break;
      default:
        printf("Invalid type (U|T|M): %s\n", type_str);
        return -1;
    };

    if (buf) {
      if (size+bsize >= sizeof(ndef)) {
       printf("Record too long\n");
       free(buf);
       return -1;
      }
      if (size > 0)
        buf[0] &= ~NDEF_MB;   // not the first message
      if (*argv)
        buf[0] &= ~NDEF_ME;   // not the last message
      memcpy(ndef+size, buf, bsize);
      size += bsize;
      free(buf);
    }
  }

  // Write to given sectors
  if (size > 0)
  {
    int res = ndef_put_sectors(&current_tag, s1, s2, ndef, size);
    if (res != 0)
      printf("Not enough memory in sectors (payload: %ld bytes)\n", size);
    return res;
  }

  return 0;
}

// MAD functions
int com_mad(char* argv[], size_t argc) {
  if (argc > 0) {
    printf("Too many arguments\n");
    return -1;
  }

  return mad_print(&current_tag);
}

int com_mad_size(char* argv[], size_t argc) {
  if (argc > 1) {
    printf("Expecting a single argument: 1K|4K\n");
    return -1;
  }

  mf_size_t s = parse_size(argv[0], settings.size);
  if (s == MF_INVALID_SIZE) {
    printf("Invalid size: %s\n", argv[0] ? argv[0] : settings.size);
    return -1;
  }
  return mad_size(&current_tag, s);
}

int com_mad_put(char* argv[], size_t argc) {
  if (argc != 2) {
    printf("Expecting two arguments: #sector AID\n   AID name  value\n");
    for (const aid_t* aid = AIDs; aid->name; aid++)
      printf(" %10s  0x%04hX\n", aid->name, aid->val);
    return -1;
  }

  char* sector_str = argv[0];
  char* aid_str = argv[1];

  size_t sector1, sector2;
  if( parse_sectors( sector_str, &sector1, &sector2, NULL ) != 0 ) {
    printf("Invalid sector range: %s\n", sector_str);
    return -1;
  }
  if (sector2 > 0x27 || sector1 > sector2) {
    printf("Invalid sector range: %lu-%lu\n", sector1, sector2);
    return -1;
  }

  // parse AID
  long aidval = -1;
  for (const aid_t* aid = AIDs; aid->name; aid++) {
    if (strcasecmp(aid->name, aid_str) == 0) {
      aidval = aid->val;
      break;
    }
  }
  if (aidval == -1) {
    aidval = strtol(aid_str, &aid_str, 0);
    if (*aid_str != '\0' || aidval < 0 || aidval > 0xFFFF) {
      printf("Invalid AID: %s\n", aid_str);
      return -1;
    }
  }

  for (size_t s = sector1; s <= sector2; s++)
    mad_put_aid(&current_tag, s, (uint16_t)aidval);

  return 0;
}

int com_mad_info(char* argv[], size_t argc) {
  if (argc != 1) {
    printf("Expecting a single argument: #sector\n");
    return -1;
  }

  char* a = argv[0];
  long s = strtol(a, &a, 0);
  if (*a != '\0' || s < 0 || s > 0x27) {
    printf("Invalid info sector: %s\n", a);
    return -1;
  }

  return mad_set_info(&current_tag, (size_t)s);
}

int com_mad_init(char* argv[], size_t argc) {
  if (argc > 1) {
    printf("Expecting a single argument: 1K|4K\n");
    return -1;
  }

  mf_size_t s = parse_size(argv[0], settings.size);
  if (s == MF_INVALID_SIZE) {
    printf("Invalid size: %s\n", argv[0] ? argv[0] : settings.size);
    return -1;
  }
  return mad_init(&current_tag, s);
}

int com_mad_crc(char* argv[], size_t argc) {
  if (argc > 0) {
    printf("Too many arguments\n");
    return -1;
  }

  return mad_crc(&current_tag);
}

int com_gen1_wipe(char* argv[], size_t argc) {
  if (argc != 1 || strcmp(argv[0], "YES!") != 0) {
    printf("This command permanently wipes the entire card! Provide a single argument saying YES! to proceed.\n");
    return -1;
  }

  return mf_gen1_wipe();
}

int com_gen3_writeuid(char* argv[], size_t argc) {
  if (argc > 0) {
    printf("Too many arguments\n");
    return -1;
  }

  return mf_gen3_setuid(current_tag.amb[0].mbd.abtData);
}

int com_gen3_write0(char* argv[], size_t argc) {
  if (argc > 0) {
    printf("Too many arguments\n");
    return -1;
  }

  return mf_gen3_setblock0(current_tag.amb[0].mbd.abtData);
}

int com_gen3_lock(char* argv[], size_t argc) {
  if (argc != 1 || strcmp(argv[0], "YES!") != 0) {
    printf("This command permanently locks the card! Provide a single argument saying YES! to proceed.\n");
    return -1;
  }

  return mf_gen3_lock();
}

int com_print_keys(char* argv[], size_t argc) {
  if (argc > 1) {
    printf("Expecting a single sector range\n");
    return -1;
  }

  size_t s1, s2;
  if( parse_sectors( argv[0], &s1, &s2, settings.size ) != 0 ) {
    printf("Invalid sector range: %s\n", argv[0] ? argv[0] : settings.size);
    return -1;
  }
  if (s2 > 39 || s1 > s2) {
    printf("Invalid sector range: %lu-%lu\n", s1, s2);
    return -1;
  }

  print_keys(&current_tag, s1, s2);
  return 0;
}

int com_print_perm(char* argv[], size_t argc) {
  if (argc > 1) {
    printf("Expecting a single sector range\n");
    return -1;
  }

  size_t s1, s2;
  if( parse_sectors( argv[0], &s1, &s2, settings.size ) != 0 ) {
    printf("Invalid sector range: %s\n", argv[0] ? argv[0] : settings.size);
    return -1;
  }
  if (s2 > 39 || s1 > s2) {
    printf("Invalid sector range: %lu-%lu\n", s1, s2);
    return -1;
  }
  s1 = sector_to_header(s1);
  s2 = sector_to_trailer(s2);

  print_ac(&current_tag, s1, s2 );
  return 0;
}

int com_set(char* argv[], size_t argc) {
  if (argc > 0) {
    printf("Too many arguments\n");
    return -1;
  }

  printf("Device: %s\n", settings.device);
  printf("Auth:   %s\n", settings.auth);
  printf("Size:   %s\n", settings.size);
  return 0;
}

int com_set_auth(char* argv[], size_t argc) {
  if (argc != 1) {
    printf("Expecting a single argument: A|B|AB|*\n");
    return -1;
  }

  mf_key_type_t key_type = parse_key_type(argv[0], NULL);
  if( key_type == MF_KEY_A )
    settings.auth = "A";
  else if( key_type == MF_KEY_B )
    settings.auth = "B";
  else if( key_type == MF_KEY_AB )
    settings.auth = "AB";
  else if( key_type == MF_KEY_UNLOCKED )
    settings.auth = "*";
  else {
    printf("Invalid authentication key type %s\n", argv[0]);
    return -1;
  }

  return 0;
}

int com_set_device(char* argv[], size_t argc) {
  if (argc > 1) {
    printf("Expecting a single argument: device\n");
    return -1;
  }

  if( argc == 0 || argv[0][0] == '\0' ) {
    settings.device[0] = '\0';
  } else {
    strncpy(settings.device, argv[0], sizeof(settings.device));
    settings.device[sizeof(settings.device)-1] = '\0';
  }

  return 0;
}

int com_set_size(char* argv[], size_t argc) {
  if (argc != 1) {
    printf("Expecting a single argument: 1K|4K\n");
    return -1;
  }

  size_t s = parse_size(argv[0], NULL);
  if( s == MF_1K )
    settings.size = "1K";
  else if( s == MF_4K )
    settings.size = "4K";
  else {
    printf("Invalid size %s\n", argv[0]);
    return -1;
  }

  return 0;
}

int com_auth_load(char* argv[], size_t argc) {
  if (argc != 1) {
    printf("Expecting one single argument: filename\n");
    return -1;
  }

  int res = load_auth(argv[0]);
  if (res == 0)
    printf("Successfully loaded keys from: %s\n", argv[0]);
  else
    printf("Failed to load keys from: %s\n", argv[0]);

  return res;
}

int com_auth_save(char* argv[], size_t argc) {
  if (argc != 1) {
    printf("Expecting one single argument: filename\n");
    return -1;
  }

  int res = save_auth(argv[0]);
  if (res == 0)
    printf("Successfully wrote keys to: %s\n", argv[0]);
  else
    printf("Failed to write keys to: %s\n", argv[0]);
  return res;
}

int com_auth_clear(char* argv[], size_t argc) {
  if (argc > 0) {
    printf("Too many arguments\n");
    return -1;
  }

  clear_tag(&current_auth);
  return 0;
}

int com_auth_put(char* argv[], size_t argc) {
  if (argc != 3) {
    printf("Expecting three arguments: #sector A|B|AB key\n");
    return -1;
  }
  char* sector_str = argv[0];
  char* ab_str = argv[1];
  char* key_str = argv[2];

  size_t s1, s2;
  if( parse_sectors( sector_str, &s1, &s2, settings.size ) != 0 ) {
    printf("Invalid sector range: %s\n", sector_str ? sector_str : settings.size);
    return -1;
  }
  if (s2 > 39 || s1 > s2) {
    printf("Invalid sector range: %lu-%lu\n", s1, s2);
    return -1;
  }

  mf_key_type_t key_type = parse_key_type(ab_str, "AB");
  if (key_type != MF_KEY_A && key_type != MF_KEY_B && key_type != MF_KEY_AB) {
    printf("Invalid key type (A|B|AB): %s\n", ab_str);
    return -1;
  }

  uint8_t key[6];
  size_t len = 6;
  if (parse_hex_str(key_str, key, &len) != 0 || len != 6) {
    printf("Invalid key (expecting 6 bytes): %s\n", key_str);
    return -1;
  }

  for( size_t sector = s1; sector <= s2; sector++ ) {
    size_t block = sector_to_trailer(sector);

    if (key_type == MF_KEY_A || key_type == MF_KEY_AB)
      memcpy( current_auth.amb[block].mbt.abtKeyA, key, sizeof(key) );

    if (key_type == MF_KEY_B || key_type == MF_KEY_AB)
      memcpy( current_auth.amb[block].mbt.abtKeyB, key, sizeof(key) );
  }

  return 0;
}

int com_auth_import(char* argv[], size_t argc) {
  if (argc > 2) {
    printf("Expecting two arguments: #sector A|B|AB\n");
    return -1;
  }
  char* sector_str = argc > 0 ? argv[0] : NULL;
  char* ab_str = argc > 1 ? argv[1] : NULL;

  size_t s1, s2;
  if( parse_sectors( sector_str, &s1, &s2, settings.size ) != 0 ) {
    printf("Invalid sector range: %s\n", sector_str ? sector_str : settings.size);
    return -1;
  }
  if (s2 > 39 || s1 > s2) {
    printf("Invalid sector range: %lu-%lu\n", s1, s2);
    return -1;
  }

  mf_key_type_t key_type = parse_key_type(ab_str, "AB");
  if (key_type != MF_KEY_A && key_type != MF_KEY_B && key_type != MF_KEY_AB) {
    printf("Invalid key type (A|B|AB): %s\n", ab_str);
    return -1;
  }

  return import_auth(key_type, s1, s2);
}

int com_auth_export(char* argv[], size_t argc) {
  if (argc > 2) {
    printf("Expecting two arguments: #sector A|B|AB\n");
    return -1;
  }
  char* sector_str = argc > 0 ? argv[0] : NULL;
  char* ab_str = argc > 1 ? argv[1] : NULL;

  size_t s1, s2;
  if( parse_sectors( sector_str, &s1, &s2, settings.size ) != 0 ) {
    printf("Invalid sector range: %s\n", sector_str ? sector_str : settings.size);
    return -1;
  }
  if (s2 > 39 || s1 > s2) {
    printf("Invalid sector range: %lu-%lu\n", s1, s2);
    return -1;
  }

  // parse key type
  mf_key_type_t key_type = parse_key_type(ab_str, "AB");
  if (key_type != MF_KEY_A && key_type != MF_KEY_B && key_type != MF_KEY_AB) {
    printf("Invalid key type (A|B|AB): %s\n", ab_str);
    return -1;
  }

  return export_auth(key_type, s1, s2);
}

int com_auth_test(char* argv[], size_t argc) {
  if (argc > 2) {
    printf("Expecting two arguments: #sector A|B|AB\n");
    return -1;
  }
  char* sector_str = argc > 0 ? argv[0] : NULL;
  char* ab_str = argc > 1 ? argv[1] : NULL;

  size_t s1, s2;
  if( parse_sectors( sector_str, &s1, &s2, settings.size ) != 0 ) {
    printf("Invalid sector range: %s\n", sector_str ? sector_str : settings.size);
    return -1;
  }
  if (s2 > 39 || s1 > s2) {
    printf("Invalid sector range: %lu-%lu\n", s1, s2);
    return -1;
  }

  // parse key type
  mf_key_type_t key_type = parse_key_type(ab_str, "AB");
  if (key_type != MF_KEY_A && key_type != MF_KEY_B && key_type != MF_KEY_AB) {
    printf("Invalid key type (A|B|AB): %s\n", ab_str);
    return -1;
  }

  return mf_test_auth(&current_auth, s1, s2, key_type);
}

int com_auth_print(char* argv[], size_t argc) {
  if (argc > 1) {
    printf("Expecting a single sector range\n");
    return -1;
  }

  size_t s1, s2;
  if( parse_sectors( argv[0], &s1, &s2, settings.size ) != 0 ) {
    printf("Invalid sector range: %s\n", argv[0] ? argv[0] : settings.size);
    return -1;
  }
  if (s2 > 39 || s1 > s2) {
    printf("Invalid sector range: %lu-%lu\n", s1, s2);
    return -1;
  }

  print_keys(&current_auth, s1, s2);
  return 0;
}

int com_dict_load(char* argv[], size_t argc) {
  if (argc != 1) {
    printf("Expecting one single argument: filename\n");
    return -1;
  }

  FILE* dict_file = fopen(argv[0], "r");
  if (dict_file == NULL) {
    printf("Could not open file: %s\n", argv[0]);
    return -1;
  }

  int res = dictionary_import(dict_file);
  fclose(dict_file);
  return res;
}

int com_dict_clear(char* argv[], size_t argc) {
  if (argc > 0) {
    printf("Too many arguments\n");
    return -1;
  }

  dictionary_clear();
  return 0;
}

int com_dict_attack(char* argv[], size_t argc) {
  if (argc > 0) {
    printf("Too many arguments\n");
    return -1;
  }

  if (!dictionary_get()) {
    printf("Dictionary is empty!\n");
    return -1;
  }

  return mf_dictionary_attack(&current_auth);
}

int com_dict_add(char* argv[], size_t argc) {
  if (argc != 1) {
    printf("Expecting one single argument: key\n");
    return -1;
  }

  uint8_t key[6];
  size_t len = 6;
  if (parse_hex_str(argv[0], key, &len) != 0 || len != 6) {
    printf("Invalid key (expecting 6 bytes): %s\n", argv[0]);
    return -1;
  }

  if (!dictionary_add(key)) {
    printf("Duplicate key (moved to front of dict)\n");
  }

  return 0;
}

int com_dict_print(char* argv[], size_t argc) {
  if (argc > 0) {
    printf("Too many arguments\n");
    return -1;
  }

  key_list_t* kl = dictionary_get();
  int count = 0;
  while (kl) {
    print_hex_array(kl->key, 6);
    printf("\n");
    kl = kl->next;
    ++count;
  }

  printf("Dictionary contains: %d keys\n", count);
  return 0;
}


int com_spec_print(char* argv[], size_t argc) {
  if (argc > 0) {
    printf("Too many arguments\n");
    return -1;
  }

  print_instance_tree();
  return 0;
}

int com_spec_load(char* argv[], size_t argc) {
  if (argc != 1) {
    printf("Expecting one single argument: filename\n");
    return -1;
  }

  // Start by clearing the current hierarchy
  clear_instance_tree();
  tt_clear();

  FILE* spec_file = fopen(argv[0], "r");
  if (spec_file == NULL) {
    printf("Could not open file: %s\n", argv[0]);
    return 1;
  }
  int res = spec_import(spec_file);
  fclose(spec_file);
  return res;
}

int com_spec_clear(char* argv[], size_t argc) {
  if (argc > 0) {
    printf("Too many arguments\n");
    return -1;
  }

  clear_instance_tree();
  tt_clear();
  return 0;
}

int com_mac_key_get_set(char* argv[], size_t argc) {
  if (argc > 1) {
    printf("Expecting one single argument: key\n");
    return -1;
  } else if (argc == 0) {
    printf("Current MAC key: \n");
    print_hex_array_sep(current_mac_key, 8, " ");
    printf("\n");
    return 0;
  }

  uint8_t key[8];
  size_t len = 8;
  if (parse_hex_str(argv[0], key, &len) != 0 || len != 8) {
    printf("Invalid MAC key (expecting 8 bytes): %s\n", argv[0]);
    return -1;
  }

  // Everything ok, so update the global
  memcpy(current_mac_key, key, 8);
  return 0;
}

int com_mac_block_compute(char* argv[], size_t argc) {
  return com_mac_block_compute_impl(argv, argc, 0);
}

int com_mac_block_update(char* argv[], size_t argc) {
  return com_mac_block_compute_impl(argv, argc, 1);
}

int com_mac_block_compute_impl(char* argv[], size_t argc, int update) {
  if (argc > 1) {
    printf("Expecting a single block range\n");
    return -1;
  }

  size_t b1, b2;
  if( parse_blocks( argv[0], &b1, &b2, settings.size ) != 0 ) {
    printf("Invalid block range: %s\n", argv[0] ? argv[0] : settings.size);
    return -1;
  }
  if (b2 > 0xff || b1 > b2) {
    printf("Invalid block range: %lu-%lu\n", b1, b2);
    return -1;
  }

  int res = 0;
  for (size_t b = b1; b <= b2; b++) {
    if (is_trailer_block(b) || b == 0) continue;
    unsigned char* mac = compute_block_mac((unsigned int)b, current_mac_key, update);
    if (mac == 0)
    {
      printf("Block %2.2x, MAC : error\n", (unsigned int)b);
      res = -1;
    }

    printf("Block %2.2x, MAC : ", (unsigned int)b);
    print_hex_array_sep(mac, 2, " ");
    printf("\n");
  }

  return res;
}

int com_mac_validate(char* argv[], size_t argc) {
  if (argc > 1) {
    printf("Expecting a single block range\n");
    return -1;
  }

  size_t b1, b2;
  if( parse_blocks( argv[0], &b1, &b2, settings.size ) != 0 ) {
    printf("Invalid block range: %s\n", argv[0] ? argv[0] : settings.size);
    return -1;
  }
  if (b2 > 0xff || b1 > b2) {
    printf("Invalid block range: %lu-%lu\n", b1, b2);
    return -1;
  }

  for (size_t b = b1; b <= b2; b++) {
    if (is_trailer_block(b) || b == 0) continue;

    unsigned char* mac = compute_block_mac((unsigned int)b, current_mac_key, 0);
    printf("Block: %2x ", (unsigned int)b);
    printf("Tag: ");
    print_hex_array_sep(&current_tag.amb[b].mbd.abtData[14], 2, " ");
    printf(" Computed: ");
    print_hex_array_sep(mac, 2, " ");
    printf(" Result: ");

    if (memcmp(mac, &current_tag.amb[b].mbd.abtData[14], 2) == 0)
      printf("VALID");
    else
      printf("INVALID");

    printf("\n");
  }
  return 0;
}


/**
 * Parser functions
 */

mf_size_t parse_size(const char* str, const char* def) {
  if (str == NULL) {
    str = def;
    if (str == NULL)
      return MF_INVALID_SIZE;
  }

  if (strcasecmp(str, "1k") == 0)
    return MF_1K;

  if (strcasecmp(str, "4k") == 0)
    return MF_4K;

  return MF_INVALID_SIZE;
}

mf_key_type_t parse_key_type(const char* str, const char* def) {
  if (str == NULL) {
    str = def;
    if (str == NULL)
      return MF_INVALID_KEY_TYPE;
  }

  if (strcasecmp(str, "a") == 0)
    return MF_KEY_A;

  if (strcasecmp(str, "b") == 0)
    return MF_KEY_B;

  if (strcasecmp(str, "ab") == 0 || strcasecmp(str, "x") == 0)
    return MF_KEY_AB;

  if (strcasecmp(str, "*") == 0)
    return MF_KEY_UNLOCKED;

  return MF_INVALID_KEY_TYPE;
}

// read (positive) number range
// D (a=b=D), D- (a=D, b unchanged), -D (a unchanged, b=D), D1-D2 (a=D1,b=D2) , - (a and b unchanged)
int parse_range(const char* str, size_t* a, size_t* b, int base) {
  if (str == NULL || *str == '\0')
    return -1;
  const char* s = str;
  if (*s != '-')
  {
    // read first number
    *a = (unsigned int)strtol(s, (char**)&s, base);
    if (*s == '\0') {
      *b = *a;
      return 0;
    }
  }
  if (*s != '-') return -1;
  s++;
  if (*s == '\0') return 0;
  // read second number
  *b = (unsigned int)strtol(s, (char**)&s, base);
  return (*s == '\0') ? 0 : -1;
}

// Parse a range of sectors
int parse_sectors(const char* str, size_t* a, size_t* b, const char* def) {
  if (str == NULL) {
    str = def;
  }

  const mf_size_t size = parse_size(str, settings.size);
  if( size != MF_INVALID_SIZE ) {
    *a = 0;
    *b = sector_count(size)-1;
    return 0;
  }
  *a = 0;
  *b = sector_count(parse_size(settings.size, NULL))-1;
  return parse_range(str, a, b, 0);
}

// Parse a range of blocks
int parse_blocks(const char* str, size_t* a, size_t* b, const char* def) {
  if (str == NULL) {
    str = def;
  }

  const mf_size_t size = parse_size(str, settings.size);
  if( size != MF_INVALID_SIZE ) {
    *a = 0;
    *b = block_count(size)-1;
    return 0;
  }
  *a = 0;
  *b = block_count(parse_size(settings.size, NULL))-1;
  return parse_range(str, a, b, 0);
}
