#ifndef TERM_CMD__H
#define TERM_CMD__H

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
 */

typedef int (*cmd_func_t)(char**,size_t);

typedef struct {
  char *name;       // The command
  cmd_func_t func;  // Function to call on command
  int fn_arg;       // File name completion if > 0
  int document;     // Show in documentation if > 0
  char *doc;        // String documenting the command
} command_t;

extern const command_t commands[];


// Lookup a command by name. Return a ptr to the command function, or
// NULL if the command isn't found.
const command_t* find_command(const char *name);

// Any command starting with '.' - path spec
int exec_path_command(const char *line);


// Print help command
int com_help(char* argv[], size_t argc);

// Exit mfterm command
int com_quit(char* argv[], size_t argc);

// Misc routines
int com_version(char* argv[], size_t argc);
int com_devices(char* argv[], size_t argc);

// Settings
int com_set(char* argv[], size_t argc);
int com_set_keys(char* argv[], size_t argc);
int com_set_size(char* argv[], size_t argc);
int com_set_device(char* argv[], size_t argc);

// Load/Save tag file operations
int com_load_tag(char* argv[], size_t argc);
int com_save_tag(char* argv[], size_t argc);

// Safely clear (zero) commands (preserve keys, access bits, block0)
int com_reset_tag(char* argv[], size_t argc);
int com_clear_all(char* argv[], size_t argc);
int com_clear_sector(char* argv[], size_t argc);
int com_clear_block(char* argv[], size_t argc);

// Read/Write tag NFC operations
int com_read_block(char* argv[], size_t argc);
int com_read_sector(char* argv[], size_t argc);
int com_write_block(char* argv[], size_t argc);
int com_write_sector(char* argv[], size_t argc);
int com_write_mod(char* argv[], size_t argc);

// Ident card
int com_ident(char* argv[], size_t argc);
int com_check_tag(char* argv[], size_t argc);
int com_fix_tag(char* argv[], size_t argc);

// Tag print commands
int com_print_blocks(char* argv[], size_t argc);
int com_print_sectors(char* argv[], size_t argc);
int com_print_keys(char* argv[], size_t argc);
int com_print_perm(char* argv[], size_t argc);

// Tag set (value) command
int com_edit(char* argv[], size_t argc);
int com_edit_hex(char* argv[], size_t argc);
int com_edit_uid(char* argv[], size_t argc);
int com_edit_key(char* argv[], size_t argc);
int com_edit_perm(char* argv[], size_t argc);
int com_edit_mod(char* argv[], size_t argc);

// NDEF commands
int com_ndef(char* argv[], size_t argc);
int com_ndef_put(char* argv[], size_t argc);

// MAD commands
int com_mad(char* argv[], size_t argc);
int com_mad_size(char* argv[], size_t argc);
int com_mad_put(char* argv[], size_t argc);
int com_mad_info(char* argv[], size_t argc);
int com_mad_init(char* argv[], size_t argc);
int com_mad_crc(char* argv[], size_t argc);

// setting commands
int com_set(char* argv[], size_t argc);
int com_set_auth(char* argv[], size_t argc);
int com_set_device(char* argv[], size_t argc);
int com_set_size(char* argv[], size_t argc);

// GEN1 card commands
int com_gen1_wipe(char* argv[], size_t argc);

// GEN3 card commands
int com_gen3_writeuid(char* argv[], size_t argc);
int com_gen3_write0(char* argv[], size_t argc);
int com_gen3_lock(char* argv[], size_t argc);

// Key operations
int com_auth_load(char* argv[], size_t argc);
int com_auth_save(char* argv[], size_t argc);
int com_auth_clear(char* argv[], size_t argc);
int com_auth_put(char* argv[], size_t argc);
int com_auth_import(char* argv[], size_t argc);
int com_auth_export(char* argv[], size_t argc);
int com_auth_print(char* argv[], size_t argc);
int com_auth_test(char* argv[], size_t argc);

// Dictionary operations
int com_dict_load(char* argv[], size_t argc);
int com_dict_clear(char* argv[], size_t argc);
int com_dict_attack(char* argv[], size_t argc);
int com_dict_add(char* argv[], size_t argc);
int com_dict_print(char* argv[], size_t argc);

// Specification operations
int com_spec_load(char* argv[], size_t argc);
int com_spec_clear(char* argv[], size_t argc);
int com_spec_print(char* argv[], size_t argc);

// MAC operations
int com_mac_key_get_set(char* argv[], size_t argc);
int com_mac_block_compute(char* argv[], size_t argc);
int com_mac_block_update(char* argv[], size_t argc);
int com_mac_validate(char* argv[], size_t argc);

#endif
