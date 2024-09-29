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
#include "term_cmd.h"
#include "mifare_ctrl.h"
#include "dictionary.h"
#include "spec_syntax.h"
#include "util.h"
#include "mac.h"

command_t commands[] = {
  { "help",         com_help,          0, 0, "Display this text" },
  { "?",            com_help,          0, 0, "Synonym for 'help'" },
  { "version",      com_version,       0, 1, "Show version information" },
  { "devices",      com_devices,       0, 1, "List all connected NFC devices" },

  { "q",            com_quit,          0, 0, "Exit the program" },
  { "quit",         com_quit,          0, 1, "Exit the program" },
  { "exit",         com_quit,          0, 0, "Synonym for 'quit'" },

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

  { "gen1 wipe!",   com_gen1_wipe,     0, 1, "On GEN1 cards, wipe entire card without keys" },

  { "gen3 setuid!", com_gen3_writeuid, 0, 1, "On GEN3 cards, set UID without modifying block 0" },
  { "gen3 write0!", com_gen3_write0,   0, 1, "On GEN3 cards, write block 0 and set UID" },
  { "gen3 lock!",   com_gen3_lock,     0, 1, "On GEN3 cards, lock card UID/block0 permanently" },

  { "ident",        com_ident,         0, 1, "Identify card and print public information" },
  { "check",        com_check_tag,     0, 1, "Check the current tag data" },
  { "fix",          com_fix_tag,       0, 1, "Try to fix errors in current tag data" },

  { "print",        com_print_sectors, 0, 1, "#sector: Print tag sector data" },
  { "print block",  com_print_blocks,  0, 1, "#block: Print tag block data" },
  { "print keys",   com_print_keys,    0, 1, "#sector: Print tag sector keys" },
  { "print perm",   com_print_perm,    0, 1, "#sector: Print tag sector permissions" },

  { "put",          com_put,           0, 1, "#block #offset xx xx xx|\"ASCII\": Set tag block data" },
  { "put uid",      com_put_uid,       0, 1, "xx xx xx xx [xx xx xx]: Set tag UID" },
  { "put key",      com_put_key,       0, 1, "#sector A|B|AB xxxxxxxxxxxx: Set tag sector key" },
  { "put perm",     com_put_perm,      0, 1, "#block C1C2C3: Set tag block permissions" },

  { "set",          com_set,           0, 1, "Print current settings" },
  { "set auth",     com_set_auth,      0, 1, "A|B|AB|*: Set keys for authentication (* = gen1 unlock)" },
  { "set size",     com_set_size,      0, 1, "1K|4K: Set the default tag size" },
  { "set device",   com_set_device,    0, 1, "Set NFC device to use" },

  { "keys",         com_keys_print,    0, 1, "#sector: Print sector keys" },
  { "keys load",    com_keys_load,     1, 1, "Load keys from file" },
  { "keys save",    com_keys_save,     1, 1, "Save keys to file" },
  { "keys clear",   com_keys_clear,    0, 1, "Clear keys" },
  { "keys put",     com_keys_put,      0, 1, "#sector A|B|AB xxxxxxxxxxxx: Set authorization key" },
  { "keys import",  com_keys_import,   0, 1, "#sector A|B|AB: Import sector keys from tag" },
  { "keys export",  com_keys_export,   0, 1, "#sector A|B|AB: Export sector keys to tag" },
  { "keys test",    com_keys_test,     0, 1, "#sector A|B|AB: Try to authenticate with the keys" },

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

// Compute the MAC using the current_mac_key. If update is nonzero,
// the mac of the current tag is updated. If not, the MAC is simply
// printed.
int com_mac_block_compute_impl(char* arg, int update);

/* Look up NAME as the name of a command, and return a pointer to that
   command.  Return a NULL pointer if NAME isn't a command name. */
command_t* find_command(const char *name) {
  command_t* cmd = NULL;
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

/**
 * Helper function to print the specified command alligned with the longest
 * command name.
 */
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

int com_help(char* arg) {
  // Help request for specific command?
  if (arg && *arg != '\0') {
    for (size_t i = 0; commands[i].name; ++i) {
      if (strcmp(arg, commands[i].name) == 0) {
        print_help_(i);
        return 0;
      }
    }
    printf ("No commands match '%s'\n", arg);
  }

  // Help for all commands (with doc flag)
  for (size_t i = 0; commands[i].name; i++) {
    if (commands[i].document)
      print_help_(i);
  }

  return 0;
}

int com_quit(char *arg) {
  stop_input_loop();
  return 0;
}

int com_load_tag(char *arg) {
  if (*arg == '\0') {
    printf("Missing file name\n");
    return -1;
  }

  int res = load_tag(arg);
  if (res == 0)
    printf("Successfully loaded tag from: %s\n", arg);
  else
    printf("Failed to load tag from: %s\n", arg);
  return 0;
}

int com_save_tag(char* arg) {
  if (*arg == '\0') {
    printf("Missing file name\n");
    return -1;
  }

  int res = save_tag(arg);
  if (res == 0)
    printf("Successfully wrote tag to: %s\n", arg);
  else
    printf("Failed to write tag to: %s\n", arg);
  return 0;
}

int com_reset_tag(char* arg) {
  if (strtok(arg, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  reset_tag(&current_tag);
  return 0;
}

int com_clear_all(char* arg) {
  if (strtok(arg, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  clear_tag(&current_tag);
  return 0;
}

int com_clear_block(char* arg) {
  char* block = strtok(arg, " ");

  if (block && strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  size_t b1, b2;
  if( parse_blocks( block, &b1, &b2, settings.size ) != 0 ) {
    printf("Invalid block range: %s\n", block);
    return -1;
  }
  if (b2 > 0xff || b1 > b2) {
    printf("Invalid block range: %lu - %lu\n", b1, b2);
    return -1;
  }

  clear_blocks(&current_tag, b1, b2);
  return 0;
}

int com_clear_sector(char* arg) {
  char* sector = strtok(arg, " ");

  if (sector && strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  size_t s1, s2;
  if( parse_sectors( sector, &s1, &s2, settings.size ) != 0 ) {
    printf("Invalid sector range: %s\n", sector);
    return -1;
  }
  if (s2 > 39 || s1 > s2) {
    printf("Invalid sector range: %lu - %lu\n", s1, s2);
    return -1;
  }
  s1 = sector_to_header(s1);
  s2 = sector_to_trailer(s2);

  clear_blocks(&current_tag, s1, s2);
  return 0;
}

int com_read_block(char* arg) {
  char* block = strtok(arg, " ");

  if (block && strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  size_t b1, b2;
  if( parse_blocks( block, &b1, &b2, settings.size ) != 0 ) {
    printf("Invalid block range: %s\n", block);
    return -1;
  }
  if (b2 > 0xff || b1 > b2) {
    printf("Invalid block range: %lu - %lu\n", b1, b2);
    return -1;
  }

  // Issue the read request
  mf_read_blocks(&current_tag, parse_key_type(settings.auth, NULL), b1, b2);
  return 0;
}

int com_read_sector(char* arg) {
  char* sector = strtok(arg, " ");

  if (sector && strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  size_t s1, s2;
  if( parse_sectors( sector, &s1, &s2, settings.size ) != 0 ) {
    printf("Invalid sector range: %s\n", sector);
    return -1;
  }
  if (s2 > 39 || s1 > s2) {
    printf("Invalid sector range: %lu - %lu\n", s1, s2);
    return -1;
  }
  s1 = sector_to_header(s1);
  s2 = sector_to_trailer(s2);

  mf_read_blocks(&current_tag, parse_key_type(settings.auth, NULL), s1, s2);
  return 0;
}

int com_write_block(char* arg) {
  char* block = strtok(arg, " ");

  if (block && strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  size_t b1, b2;
  if( parse_blocks( block, &b1, &b2, settings.size ) != 0 ) {
    printf("Invalid block range: %s\n", block);
    return -1;
  }
  if (b2 > 0xff || b1 > b2) {
    printf("Invalid block range: %lu - %lu\n", b1, b2);
    return -1;
  }

  mf_write_blocks(&current_tag, parse_key_type(settings.auth, NULL), b1, b2);
  return 0;
}

int com_write_sector(char* arg) {
  char* sector = strtok(arg, " ");

  if (sector && strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  size_t s1, s2;
  if( parse_sectors( sector, &s1, &s2, settings.size ) != 0 ) {
    printf("Invalid sector range: %s\n", sector);
    return -1;
  }
  if (s2 > 39 || s1 > s2) {
    printf("Invalid sector range: %lu - %lu\n", s1, s2);
    return -1;
  }
  s1 = sector_to_header(s1);
  s2 = sector_to_trailer(s2);

  // Issue the read request
  mf_write_blocks(&current_tag, parse_key_type(settings.auth, NULL), s1, s2);
  return 0;
}

int com_ident(char* arg) {
  char* a = strtok(arg, " ");

  if (a && strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  mf_ident_tag();
  return 0;
}

int com_check_tag(char* arg) {
  char* a = strtok(arg, " ");

  if (a && strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  check_tag(&current_tag, false);
  return 0;
}

int com_fix_tag(char* arg) {
  char* a = strtok(arg, " ");

  if (a && strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  check_tag(&current_tag, true);
  return 0;
}

int com_devices(char* arg) {
  char* a = strtok(arg, " ");

  if (a && strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  return mf_devices();
}

int com_version(char* arg) {
  char* a = strtok(arg, " ");

  if (a && strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  return mf_version();
}

int com_print_blocks(char* arg) {
  char* a = strtok(arg, " ");

  if (a && strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  size_t size1, size2;
  if( parse_blocks( a, &size1, &size2, settings.size ) != 0 ) {
    printf("Unknown argument: %s\n", a);
    return -1;
  }

  print_tag_block_range(size1, size2);

  return 0;
}

int com_print_sectors(char* arg) {
  char* a = strtok(arg, " ");

  if (a && strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  size_t size1, size2;
  if( parse_sectors( a, &size1, &size2, settings.size ) != 0 ) {
    printf("Unknown argument: %s\n", a);
    return -1;
  }

  print_tag_block_range(sector_to_header(size1), sector_to_trailer(size2));

  return 0;
}

int com_put(char* arg) {
  char* block_str = strtok(arg, " ");
  char* offset_str = strtok(NULL, " ");
  char* arg_str = strtok(NULL, "");   // remainder of string

  if (!block_str || !offset_str || !arg_str) {
    printf("Too few arguments: #block #offset xx .. xx|\"ASCII\"\n");
    return -1;
  }

  size_t block1, block2;
  if( parse_blocks( block_str, &block1, &block2, settings.size ) != 0 ) {
    printf("Invalid block range: %s\n", block_str);
    return -1;
  }
  if (block2 > 0xff || block1 > block2) {
    printf("Invalid block range: %lu - %lu\n", block1, block2);
    return -1;
  }

  size_t offset = strtoul(offset_str, &offset_str, 0);
  if (*offset_str != '\0') {
    printf("Invalid offset: %s\n", offset_str);
    return -1;
  }
  if (offset > 0x0f) {
    printf("Invalid offset [0,15]: %lu\n", offset);
    return -1;
  }

  // Consume the byte tokens or ASCII string
  uint8_t bytes[16];
  uint8_t* b = bytes+offset;
  size_t count = 0;
  if( *arg_str == '"' ) {
    // ASCII string
    arg_str++;
    int escape = 0;
    do {
      if( !escape && *arg_str == '"' ) {
        break;
      }
      if( !escape && *arg_str == '\\' ) {
        escape = 1;
        arg_str++;
        continue;
      }

      // store value
      if (count+offset > 15) {
        printf("Too many bytes specified.\n");
        return -1;
      }
      *b++ = (uint8_t)*arg_str++;
      count++;
      escape = 0;
    } while(*arg_str != '\0');
    if(*arg_str != '"') {
      printf("Unterminated string.\n");
      return -1;
    }
    if(strtok(NULL, " ") != (char*)NULL) {
      printf("Too many arguments.\n");
      return -1;
    }
  }
  else {
    // byte tokens
    for (char* byte_str = strtok(arg_str, " "); byte_str; byte_str = strtok(NULL, " ")) {
      long int byte = strtol(byte_str, &byte_str, 16);
      if (*byte_str != '\0') {
        printf("Invalid byte character (non hex): %s\n", byte_str);
        return -1;
      }
      if (byte < 0 || byte > 0xff) {
        printf("Invalid byte value [0,ff]: %lx\n", byte);
        return -1;
      }

      // Save the data
      if (count+offset > 15) {
        printf("Too many bytes specified.\n");
        return -1;
      }
      *b++ = (uint8_t)byte;
      count++;
    }
  }

  if (count == 0) {
    printf("No bytes specified.\n");
    return -1;
  }

  // Write the data to each block in the given range
  for( size_t block = block1; block <= block2; block++ )
  {
    memcpy( current_tag.amb[block].mbd.abtData+offset, bytes+offset, count );
  }

  return 0;
}

int com_put_key(char* arg) {
  char* sector_str = strtok(arg, " ");
  char* ab = strtok(NULL, " ");
  char* key_str = strtok(NULL, " ");

  if (strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  if (!ab || !sector_str || !key_str) {
    printf("Too few arguments: #sector (A|B|AB) key\n");
    return -1;
  }

  // parse sector
  size_t sector1, sector2;
  if( parse_sectors(sector_str, &sector1, &sector2, settings.size) != 0 ) {
    printf("Unknown argument: %s\n", sector_str);
    return -1;
  }
  if (sector2 > 39 || sector1 > sector2) {
    printf("Invalid sectors [0,39]: %lu - %lu\n", sector1, sector2);
    return -1;
  }

  // parse key type
  mf_key_type_t key_type = parse_key_type(ab, NULL);
  if (key_type != MF_KEY_A && key_type != MF_KEY_B && key_type != MF_KEY_AB) {
    printf("Invalid argument (A|B|AB): %s\n", ab);
    return -1;
  }

  // Parse the key
  uint8_t key[6];
  if (strncmp(key_str, "0x", 2) == 0)
    key_str += 2;
  if (strlen(key_str) != 12) {
    printf("Invalid key (6 byte hex): %s\n", key_str);
    return -1;
  }
  if (read_key(key, key_str) == NULL) {
    printf("Invalid key character (non hex)\n");
    return -1;
  }

  for( size_t sector = sector1; sector <= sector2; sector++ ) {
    size_t block = sector_to_trailer(sector);

    // copy to appropriate keys
    if (key_type == MF_KEY_A || key_type == MF_KEY_AB)
      memcpy( current_tag.amb[block].mbt.abtKeyA, key, sizeof(key) );

    if (key_type == MF_KEY_B || key_type == MF_KEY_AB)
      memcpy( current_tag.amb[block].mbt.abtKeyB, key, sizeof(key) );
  }

  return 0;
}

int com_put_perm(char* arg) {
  char* block_str = strtok(arg, " ");
  char* perm_str = strtok(NULL, " ");

  if (strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  if (!block_str || !perm_str) {
    printf("Too few arguments: #block C1C2C3\n");
    printf("C1 C2 C3  !   R   W   I   D   !  AR  AW  ACR ACW BR  BW\n"
           "----------+-------------------+------------------------\n"
           "0  0  0   !  A|B A|B A|B A|B  !   x   A   A   x   A   A\n"
           "0  0  1   !  A|B  x   x  A|B  !   x   A   A   A   A   A\n"
           "0  1  0   !  A|B  x   x   x   !   x   x   A   x   A   x\n"
           "0  1  1   !   B   B   x   x   !   x   B  A|B  B   x   B\n"
           "1  0  0   !  A|B  B   x   x   !   x   B  A|B  x   x   B\n"
           "1  0  1   !   B   x   x   x   !   x   x  A|B  B   x   x\n"
           "1  1  0   !  A|B  B   B  A|B  !   x   x  A|B  x   x   x\n"
           "1  1  1   !   x   x   x   x   !   x   x  A|B  x   x   x\n"
    );
    return -1;
  }

  // parse block
  size_t block1, block2;
  if (parse_blocks(block_str, &block1, &block2, settings.size) != 0) {
    printf("Unknown argument: %s\n", block_str);
    return -1;
  }
  if (block2 > 0xff || block1 > block2) {
    printf("Invalid block [0,ff]: %lu - %lu\n", block1, block2);
    return -1;
  }

  // parse permission bits
  if (strspn(perm_str, "01") < 3 || perm_str[3] != '\0') {
    printf("Invalid permissions C1C2C3\n");
    printf("C1 C2 C3  !   R   W   I   D   !  AR  AW  ACR ACW BR  BW\n"
           "----------+-------------------+------------------------\n"
           "0  0  0   !  A|B A|B A|B A|B  !   x   A   A   x   A   A\n"
           "0  0  1   !  A|B  x   x  A|B  !   x   A   A   A   A   A\n"
           "0  1  0   !  A|B  x   x   x   !   x   x   A   x   A   x\n"
           "0  1  1   !   B   B   x   x   !   x   B  A|B  B   x   B\n"
           "1  0  0   !  A|B  B   x   x   !   x   B  A|B  x   x   B\n"
           "1  0  1   !   B   x   x   x   !   x   x  A|B  B   x   x\n"
           "1  1  0   !  A|B  B   B  A|B  !   x   x  A|B  x   x   x\n"
           "1  1  1   !   x   x   x   x   !   x   x  A|B  x   x   x\n"
    );
    return -1;
  }
  uint32_t c1 = (uint32_t)(perm_str[0]-'0');
  uint32_t c2 = (uint32_t)(perm_str[1]-'0');
  uint32_t c3 = (uint32_t)(perm_str[2]-'0');

  // set bits for all blocks
  for (size_t block =  block1; block <= block2; block++ ) {
    set_ac(&current_tag, block, c1, c2, c3);
  }

  return 0;
}

int com_put_uid(char* arg) {
  char* byte_str = strtok(arg, " ");
  uint8_t uid[7];
  unsigned int i = 0;

  // Consume the byte tokens
  while((byte_str != (char*)NULL) && (i < 7)) {
    long int byte = strtol(byte_str, &byte_str, 16);

    if (byte < 0 || byte > 0xff) {
      printf("Invalid byte value [0,ff]: %lx\n", byte);
      return -1;
    }

    uid[i] = (uint8_t)byte;
    i++;
    byte_str = strtok(NULL, " ");
  };

  if((byte_str != (char*)NULL) || ((i != 4) && (i != 7))) {
    printf("Expected exactly 4 or 7 arguments in hex: xx xx xx xx [xx xx xx]\n");
    return -1;
  }

  if( i == 4 ) {
    // Compute BCC
    uid[4] = uid[0] ^ uid[1] ^ uid[2] ^ uid[3];
    i = 5;
  }

  // Write data to tag
  memcpy( current_tag.amb[0].mbd.abtData, uid, i );

  return 0;
}

int com_gen1_wipe(char* arg) {
  char* yes_str = strtok(arg, " ");

  if (!yes_str || strncmp( yes_str, "YES!", 4 ) != 0 || strtok(NULL, " ") != (char*)NULL) {
    printf("This command permanently wipes the entire card! Provide a single argument saying YES! to proceed.\n");
    return -1;
  }

  return mf_gen1_wipe();
}

int com_gen3_writeuid(char* arg) {
  char* a = strtok(arg, " ");

  if (a && strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  return mf_gen3_setuid(current_tag.amb[0].mbd.abtData);
}

int com_gen3_write0(char* arg) {
  char* a = strtok(arg, " ");

  if (a && strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  return mf_gen3_setblock0(current_tag.amb[0].mbd.abtData);
}

int com_gen3_lock(char* arg) {
  char* yes_str = strtok(arg, " ");

  if (!yes_str || strncmp( yes_str, "YES!", 4 ) != 0 || strtok(NULL, " ") != (char*)NULL) {
    printf("This command permanently locks the card! Provide a single argument saying YES! to proceed.\n");
    return -1;
  }

  return mf_gen3_lock();
}

int com_print_keys(char* arg) {
  char* sector = strtok(arg, " ");

  if (sector && strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  size_t s1, s2;
  if( parse_sectors( sector, &s1, &s2, settings.size ) != 0 ) {
    printf("Invalid sector range: %s\n", sector);
    return -1;
  }
  if (s2 > 39 || s1 > s2) {
    printf("Invalid sector range: %lu - %lu\n", s1, s2);
    return -1;
  }

  print_keys(&current_tag, s1, s2);

  return 0;
}

int com_print_perm(char* arg) {
  char* sector = strtok(arg, " ");

  if (sector && strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  size_t s1, s2;
  if( parse_sectors( sector, &s1, &s2, settings.size ) != 0 ) {
    printf("Invalid sector range: %s\n", sector);
    return -1;
  }
  if (s2 > 39 || s1 > s2) {
    printf("Invalid sector range: %lu - %lu\n", s1, s2);
    return -1;
  }
  s1 = sector_to_header(s1);
  s2 = sector_to_trailer(s2);

  print_ac(&current_tag, s1, s2 );

  return 0;
}

int com_set(char* arg) {
  printf("Device: %s\n", settings.device);
  printf("Auth:   %s\n", settings.auth);
  printf("Size:   %s\n", settings.size);
  return 0;
}

int com_set_auth(char* arg) {
  char* a = strtok(arg, " ");

  if (a && strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  mf_key_type_t key_type = parse_key_type(a, NULL);
  if( key_type == MF_KEY_A )
    settings.auth = "A";
  else if( key_type == MF_KEY_B )
    settings.auth = "B";
  else if( key_type == MF_KEY_AB )
    settings.auth = "AB";
  else if( key_type == MF_KEY_UNLOCKED )
    settings.auth = "*";
  else
    printf("Invalid authentication key type %s\n", a);
  return 0;
}

int com_set_device(char* arg) {
  char* a = strtok(arg, " ");

  if (a && strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  if( !a || a[0] == '\0' ) {
    settings.device[0] = '\0';
  } else {
    strncpy(settings.device, a, sizeof(settings.device));
    settings.device[sizeof(settings.device)-1] = '\0';
  }

  return 0;
}

int com_set_size(char* arg) {
  char* a = strtok(arg, " ");

  if (a && strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  size_t s = parse_size(a, NULL);
  if( s == MF_1K )
    settings.size = "1K";
  else if( s == MF_4K )
    settings.size = "4K";
  else
    printf("Invalid size %s\n", a);

  return 0;
}

int com_keys_load(char* arg) {
  if (*arg == '\0') {
    printf("Missing file name\n");
    return -1;
  }

  int res = load_auth(arg);
  if (res == 0)
    printf("Successfully loaded keys from: %s\n", arg);
  else
    printf("Failed to load keys from: %s\n", arg);
  return 0;
}

int com_keys_save(char* arg) {
  if (*arg == '\0') {
    printf("Missing file name\n");
    return -1;
  }

  int res = save_auth(arg);
  if (res == 0)
    printf("Successfully wrote keys to: %s\n", arg);
  else
    printf("Failed to write keys to: %s\n", arg);
  return 0;
}

int com_keys_clear(char* arg) {
  clear_tag(&current_auth);
  return 0;
}

int com_keys_put(char* arg) {
  char* sector_str = strtok(arg, " ");
  char* ab = strtok(NULL, " ");
  char* key_str = strtok(NULL, " ");

  if (strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  if (!ab || !sector_str || !key_str) {
    printf("Too few arguments: #sector (A|B|AB) key\n");
    return -1;
  }

  // parse sector
  size_t sector1, sector2;
  if( parse_sectors(sector_str, &sector1, &sector2, settings.size) != 0 ) {
    printf("Unknown argument: %s\n", sector_str);
    return -1;
  }
  if (sector2 > 39 || sector1 > sector2) {
    printf("Invalid sectors [0,39]: %lu - %lu\n", sector1, sector2);
    return -1;
  }

  // parse key type
  mf_key_type_t key_type = parse_key_type(ab, NULL);
  if (key_type != MF_KEY_A && key_type != MF_KEY_B && key_type != MF_KEY_AB) {
    printf("Invalid argument (A|B|AB): %s\n", ab);
    return -1;
  }

  // Parse the key
  uint8_t key[6];
  if (strncmp(key_str, "0x", 2) == 0)
    key_str += 2;
  if (strlen(key_str) != 12) {
    printf("Invalid key (6 byte hex): %s\n", key_str);
    return -1;
  }
  if (read_key(key, key_str) == NULL) {
    printf("Invalid key character (non hex)\n");
    return -1;
  }

  for( size_t sector = sector1; sector <= sector2; sector++ ) {
    size_t block = sector_to_trailer(sector);

    // copy to appropriate keys
    if (key_type == MF_KEY_A || key_type == MF_KEY_AB)
      memcpy( current_auth.amb[block].mbt.abtKeyA, key, sizeof(key) );

    if (key_type == MF_KEY_B || key_type == MF_KEY_AB)
      memcpy( current_auth.amb[block].mbt.abtKeyB, key, sizeof(key) );
  }

  return 0;
}

int com_keys_import(char* arg) {
  char* sector_str = strtok(arg, " ");
  char* ab = strtok(NULL, " ");

  if (strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  // parse sector
  size_t s1, s2;
  if( parse_sectors(sector_str, &s1, &s2, settings.size) != 0 ) {
    printf("Unknown argument: %s\n", sector_str ? sector_str : "");
    return -1;
  }
  if (s2 > 39 || s1 > s2) {
    printf("Invalid sectors [0,39]: %lu - %lu\n", s1, s2);
    return -1;
  }

  // parse key type
  mf_key_type_t key_type = parse_key_type(ab, "AB");
  if (key_type != MF_KEY_A && key_type != MF_KEY_B && key_type != MF_KEY_AB) {
    printf("Invalid argument (A|B|AB): %s\n", ab ? ab : "");
    return -1;
  }

  import_auth(key_type, s1, s2);
  return 0;
}

int com_keys_export(char* arg) {
  char* sector_str = strtok(arg, " ");
  char* ab = strtok(NULL, " ");

  if (strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  // parse sector
  size_t s1, s2;
  if( parse_sectors(sector_str, &s1, &s2, settings.size) != 0 ) {
    printf("Unknown argument: %s\n", sector_str ? sector_str : "");
    return -1;
  }
  if (s2 > 39 || s1 > s2) {
    printf("Invalid sectors [0,39]: %lu - %lu\n", s1, s2);
    return -1;
  }

  // parse key type
  mf_key_type_t key_type = parse_key_type(ab, "AB");
  if (key_type != MF_KEY_A && key_type != MF_KEY_B && key_type != MF_KEY_AB) {
    printf("Invalid argument (A|B|AB): %s\n", ab ? ab : "");
    return -1;
  }

  export_auth(key_type, s1, s2);
  return 0;
}

int com_keys_test(char* arg) {
  char* sector_str = strtok(arg, " ");
  char* ab = strtok(NULL, " ");

  if (strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  // parse sector
  size_t s1, s2;
  if( parse_sectors(sector_str, &s1, &s2, settings.size) != 0 ) {
    printf("Unknown argument: %s\n", sector_str ? sector_str : "");
    return -1;
  }
  if (s2 > 39 || s1 > s2) {
    printf("Invalid sectors [0,39]: %lu - %lu\n", s1, s2);
    return -1;
  }

  // parse key type
  mf_key_type_t key_type = parse_key_type(ab, "AB");
  if (key_type != MF_KEY_A && key_type != MF_KEY_B && key_type != MF_KEY_AB) {
    printf("Invalid argument (A|B|AB): %s\n", ab ? ab : "");
    return -1;
  }

  mf_test_auth(&current_auth, s1, s2, key_type);
  return 0;
}

int com_keys_print(char* arg) {
  char* sector_str = strtok(arg, " ");

  if (strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  // parse sector
  size_t s1, s2;
  if( parse_sectors(sector_str, &s1, &s2, settings.size) != 0 ) {
    printf("Unknown argument: %s\n", sector_str ? sector_str : "");
    return -1;
  }
  if (s2 > 39 || s1 > s2) {
    printf("Invalid sectors [0,39]: %lu - %lu\n", s1, s2);
    return -1;
  }

  print_keys(&current_auth, s1, s2);
  return 0;
}

int com_dict_load(char* arg) {
  if (*arg == '\0') {
    printf("Missing file name\n");
    return -1;
  }

  FILE* dict_file = fopen(arg, "r");

  if (dict_file == NULL) {
    printf("Could not open file: %s\n", arg);
    return 1;
  }

  dictionary_import(dict_file);

  fclose(dict_file);
  return 0;
}

int com_dict_clear(char* arg) {
  dictionary_clear();
  return 0;
}

int com_dict_attack(char* arg) {
  if (!dictionary_get()) {
    printf("Dictionary is empty!\n");
    return -1;
  }

  mf_dictionary_attack(&current_auth);
  return 0;
}

int com_dict_add(char* arg) {
  char* key_str = strtok(arg, " ");

  if (strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  if (!key_str) {
    printf("Too few arguments: key\n");
    return -1;
  }

  // Sanity check key length
  if (strncmp(key_str, "0x", 2) == 0)
    key_str += 2;
  if (strlen(key_str) != 12) {
    printf("Invalid key (6 byte hex): %s\n", key_str);
    return -1;
  }

  // Parse the key
  uint8_t key[6];
  if (read_key(key, key_str) == NULL) {
    printf("Invalid key character (non hex)\n");
    return -1;
  }

  if (!dictionary_add(key)) {
    printf("Duplicate key (moved to front of dict)\n");
    return -1;
  }

  return 0;
}

int com_dict_print(char* arg) {
  key_list_t* kl = dictionary_get();

  int count = 0;
  while(kl) {
    printf("%s\n", sprint_key(kl->key));
    kl = kl->next;
    ++count;
  }

  printf("Dictionary contains: %d keys\n", count);

  return 0;
}


int com_spec_print(char* arg) {
  print_instance_tree();

  return 0;
}

int com_spec_load(char* arg) {
  if (*arg == '\0') {
    printf("Missing file name\n");
    return -1;
  }

  // Start by clearing the current hierarchy
  clear_instance_tree();
  tt_clear();

  // Open the file
  FILE* spec_file = fopen(arg, "r");
  if (spec_file == NULL) {
    printf("Could not open file: %s\n", arg);
    return 1;
  }

  // Parse the specification
  spec_import(spec_file);

  fclose(spec_file);

  return 0;
}

int com_spec_clear(char* arg) {

  clear_instance_tree();
  tt_clear();

  return 0;
}

int com_mac_key_get_set(char* arg) {
  char* key_str = strtok(arg, " ");

  if (key_str == 0) {
    printf("Current MAC key: \n");
    print_hex_array_sep(current_mac_key, 8, " ");
    printf("\n");
    return 0;
  }

  uint8_t key[8];
  int key_ptr = 0;

  // Consume the key tokens
  do {
    long int byte = strtol(key_str, &key_str, 16);
    if (*key_str != '\0') {
      printf("Invalid key character (non hex): %s\n", key_str);
      return -1;
    }
    if (byte < 0 || byte > 0xff) {
      printf("Invalid byte value [0,ff]: %lx\n", byte);
      return -1;
    }

    if (key_ptr > sizeof(key)) {
      printf("Too many bytes specified in key (should be 8).\n");
      return -1;
    }

    // Accept the byte and add it to the key
    key[key_ptr++] = (uint8_t)byte;

  } while((key_str = strtok(NULL, " ")) != (char*)NULL);

  if (key_ptr != sizeof(key)) {
    printf("Too few bytes specified in key (should be 8).\n");
    return -1;
  }

  // Everything ok, so update the global
  memcpy(current_mac_key, key, 8);
  return 0;
}

int com_mac_block_compute(char* arg) {
  return com_mac_block_compute_impl(arg, 0);
}

int com_mac_block_update(char* arg) {
  return com_mac_block_compute_impl(arg, 1);
}

int com_mac_block_compute_impl(char* arg, int update) {
  char* block_str = strtok(arg, " ");

  if (!block_str) {
    printf("Too few arguments: #block\n");
    return -1;
  }

  unsigned int block = (unsigned int) strtoul(block_str, &block_str, 16);
  if (*block_str != '\0') {
    printf("Invalid block character (non hex): %s\n", block_str);
    return -1;
  }
  if (block > 0xff) {
    printf("Invalid block [0,ff]: %x\n", block);
    return -1;
  }

  // Use the key
  unsigned char* mac = compute_block_mac(block, current_mac_key, update);

  // MAC is null on error, else 8 bytes
  if (mac == 0)
    return -1;

  // Only need 16 MSBs.
  printf("Block %2.2x, MAC : ", block);
  print_hex_array_sep(mac, 2, " ");
  printf("\n");

  return 0;
}

int com_mac_validate(char* arg) {
  char* a = strtok(arg, " ");

  if (a && strtok(NULL, " ") != (char*)NULL) {
    printf("Too many arguments\n");
    return -1;
  }

  mf_size_t size = parse_size(a, settings.size);

  if (size == MF_INVALID_SIZE) {
    printf("Unknown argument: %s\n", a);
    return -1;
  }

  for (unsigned int i = 1; i < block_count(size); ++i) {
    if (is_trailer_block(i))
      continue;

    unsigned char* mac = compute_block_mac(i, current_mac_key, 0);
    printf("Block: %2x ", i);
    printf("Tag: ");
    print_hex_array_sep(&current_tag.amb[i].mbd.abtData[14], 2, " ");
    printf(" Computed: ");
    print_hex_array_sep(mac, 2, " ");
    printf(" Result: ");

    if (memcmp(mac, &current_tag.amb[i].mbd.abtData[14], 2) == 0)
      printf("VALID");
    else
      printf("IN-VALID");

    printf("\n");
  }
  return 0;
}

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

// Any command starting with '.' - path spec
int exec_path_command(const char *line) {

  instance_t* inst = parse_spec_path(line);

  if (inst)
    print_tag_data_range(inst->offset_bytes, inst->offset_bits,
                         inst->size_bytes, inst->size_bits);
  else
    printf("Invalid Path\n");


  return 0;
}
