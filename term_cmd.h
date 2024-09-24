#ifndef TERM_CMD__H
#define TERM_CMD__H

/**
 * Copyright (C) 2011 Anders Sundman <anders@4zm.org>
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
 */

typedef int (*cmd_func_t)(char*);

// Print help command
int com_help(char* arg);

// Exit mfterm command
int com_quit(char* arg);

// Misc routines
int com_version(char* arg);
int com_devices(char* arg);

// Settings
int com_set(char* arg);
int com_set_keys(char* arg);
int com_set_size(char* arg);
int com_set_device(char* arg);

// Load/Save tag file operations
int com_load_tag(char* arg);
int com_save_tag(char* arg);

// Safely clear (zero) commands (preserve keys, access bits, block0)
int com_reset_tag(char* arg);
int com_clear_sector(char* arg);
int com_clear_block(char* arg);

// Read/Write tag NFC operations
int com_read_block(char* arg);
int com_read_sector(char* arg);
int com_write_block(char* arg);
int com_write_sector(char* arg);

// Ident card
int com_ident(char* arg);
int com_check_tag(char* arg);

// Tag print commands
int com_print_blocks(char* arg);
int com_print_sectors(char* arg);
int com_print_keys(char* arg);
int com_print_perm(char* arg);

// Tag set (value) command
int com_put(char* arg);
int com_put_uid(char* arg);
int com_put_key(char* arg);
int com_put_perm(char* arg);

// setting functions
int com_set(char* arg);
int com_set_auth(char* arg);
int com_set_device(char* arg);
int com_set_size(char* arg);

// GEN1 card commands
int com_gen1_wipe(char* arg);

// GEN3 card commands
int com_gen3_writeuid(char* arg);
int com_gen3_write0(char* arg);
int com_gen3_lock(char* arg);

// Key operations
int com_keys_load(char* arg);
int com_keys_save(char* arg);
int com_keys_clear(char* arg);
int com_keys_put(char* arg);
int com_keys_import(char* arg);
int com_keys_export(char* arg);
int com_keys_print(char* arg);
int com_keys_test(char* arg);

// Dictionary operations
int com_dict_load(char* arg);
int com_dict_clear(char* arg);
int com_dict_attack(char* arg);
int com_dict_add(char* arg);
int com_dict_print(char* arg);

// Specification operations
int com_spec_load(char* arg);
int com_spec_clear(char* arg);
int com_spec_print(char* arg);

// MAC operations
int com_mac_key_get_set(char* arg);
int com_mac_block_compute(char* arg);
int com_mac_block_update(char* arg);
int com_mac_validate(char* arg);

typedef struct {
  char *name;       // The command
  cmd_func_t func;  // Function to call on command
  int fn_arg;       // File name completion if > 0
  int document;     // Show in documentation if > 0
  char *doc;        // String documenting the command
} command_t;

extern command_t commands[];

// Lookup a command by name. Return a ptr to the command function, or
// NULL if the command isn't found.
command_t* find_command(const char *name);

// Any command starting with '.' - path spec
int exec_path_command(const char *line);

#endif
