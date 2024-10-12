/**
 * Copyright (C) 2011-2013 Anders Sundman <anders@4zm.org>
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
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <signal.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <getopt.h>
#include <nfc/nfc.h>
#include "mfterm.h"
#include "mifare_ctrl.h"
#include "term_cmd.h"
#include "tag.h"
#include "util.h"
#include "spec_syntax.h"

#include "config.h"

static int stop_input_loop_ = 0;
void stop_input_loop() {
  stop_input_loop_ = 1;
}

char* completion_cmd_generator(const char* text, int state);
char* completion_sub_cmd_generator(const char* text, int state);
char* completion_spec_generator(const char* text, int state);
int perform_filename_completion();
char** mft_completion(char* text, int start, int end);
int execute_line(char* line);
void initialize_readline();
void free_readline();
void parse_cmdline(int argc, char** argv);

void print_help();
void print_version();

int main(int argc, char** argv) {
  struct sigaction act = { .sa_handler = &mf_signal_handler };
  sigaction(SIGINT, &act, NULL);
  parse_cmdline(argc, argv);
  initialize_readline();
  reset_tag(&current_tag);
  reset_tag(&current_auth);
  input_loop();
  free_readline();
  return 0;
}

void parse_cmdline(int argc, char** argv) {
  static struct option long_options[] = {
    {"help",      no_argument,       0,  'h' },
    {"version",   no_argument,       0,  'v' },
    {"tag",       required_argument, 0,  't' },
    {"keys",      required_argument, 0,  'k' },
    {"dict",      required_argument, 0,  'd' },
    {0,           0,                 0,  0   }
  };

  char* tag_file = NULL;
  char* keys_file = NULL;
  char* dict_file = NULL;

  int opt = 0;
  int long_index = 0;
  while ((opt = getopt_long(argc, argv,"hvt:k:d:", long_options, &long_index )) != -1) {
    switch (opt) {
      case 'h' :
        print_help();
        exit(0);
      case 'v' :
        print_version();
        exit(0);
      case 't' : tag_file = optarg;
        break;
      case 'k' : keys_file = optarg;
        break;
      case 'd' : dict_file = optarg;
        break;
      default :
        exit(1);
    }
  }

  char* av[2] = { 0 };
  size_t al[2] = { 0 };

  // If a tag file was specified, load it
  if(tag_file) {
    av[0] = tag_file;
    al[0] = strlen(tag_file);
    if (com_load_tag(av, al, 1))
      exit(0);
  }

  // If a keys file was specified, load it
  if(keys_file) {
    av[0] = keys_file;
    al[0] = strlen(keys_file);
    if (keys_file != NULL && com_auth_load(av, al, 1))
      exit(0);
  }

  // If a dictionary file was specified, load it
  if(dict_file) {
    av[0] = dict_file;
    al[0] = strlen(dict_file);
    if (dict_file != NULL && com_dict_load(av, al, 1))
      exit(0);
  }
}

// Request user input until stop_intput_loop_ == 0
void input_loop() {
  char *line, *s, *prev = NULL;
  int res = 0;
  while (stop_input_loop_ == 0) {
    line = readline (res == 0 ? "\x01\e[32m\x02$ \x01\e[0m\x02" : "\x01\e[31m\x02$ \x01\e[0m\x02");
    if (!line)
      break;
    s = line + strspn(line, " \t\n\r"); // skip leading whitespace

    if (*s) {
      if(!prev || strcmp(s, prev) != 0)
        add_history(s);
      if(prev)
        free(prev);
      prev = strdup(s);
      res = execute_line(s);
    }
    free(line);
  }
  if(prev)
    free(prev);
}

/* Execute a command line. */
int execute_line (char* line) {
  if (strncmp(line, ".", 1) == 0)
    return exec_path_command(line);

  const command_t* command = find_command(line);

  if (!command) {
    fprintf (stderr, "%s: No such command.\n", line);
    return -1;
  }

  // Skip past command and ws to the arguments
  line += strlen(command->name);
  line += strspn(line, " \t\n\r");

  // pre-parse arguments
  char* argv[128], *next;
  size_t argc = 0, argl[128];
  while (argc < 128 && (argv[argc] = strqtok(line, argl+argc, &next))) {
    if (!next) {
      fprintf (stderr, "Unbalanced quotes or invalid hex string.\n");
      return -1;
    }
    argc++;
    line = next;
  }
  if (argc == 128) {
    fprintf (stderr, "Too many arguments: %s\n", line);
    return -1;
  }

  return (*(command->func))(argv, argl, argc);
}

void initialize_readline()
{
  rl_readline_name = "MFT";
  rl_filename_quote_characters = " ";
  rl_completer_quote_characters = "\"";
  rl_attempted_completion_function = (rl_completion_func_t*)mft_completion;
  using_history();
  // read history file
  const char* home = getenv("HOME");
  const char* histfile = ".mfterm_history";
  char* fn;
  if( home ) {
    fn = malloc(strlen(home)+strlen(histfile)+2);
    strcpy(fn, home);
    strcat(fn, "/");
    strcat(fn, histfile);
  } else {
    fn = malloc(strlen(histfile)+1);
    strcpy(fn, histfile);
  }
  read_history(fn);
  free(fn);
}

void free_readline()
{
  const char* home = getenv("HOME");
  const char* histfile = ".mfterm_history";
  char* fn;
  if( home ) {
    fn = malloc(strlen(home)+strlen(histfile)+2);
    strcpy(fn, home);
    strcat(fn, "/");
    strcat(fn, histfile);
  } else {
    fn = malloc(strlen(histfile)+1);
    strcpy(fn, histfile);
  }
  write_history(fn);
  free(fn);
}

/* Attempt to complete on the contents of TEXT. START and END bound the
   region of rl_line_buffer that contains the word to complete. TEXT is
   the word to complete. We can use the entire contents of rl_line_buffer
   in case we want to do some simple parsing. Return the array of matches,
   or NULL if there aren't any. */
char** mft_completion(char* text, int start, int end) {
  char **matches = (char **)NULL;

  // Don't complete on files for most cases
  rl_attempted_completion_over = 1;

  // Add the trailing space unless told otherwise
#ifdef HAVE_RL_COMPLETION_SUPPRESS_APPEND
    rl_completion_suppress_append = 0;
#endif

  // Complete strings starting with '.' as specification paths
  if (text[0] == '.' && instance_root) {
#ifdef HAVE_RL_COMPLETION_SUPPRESS_APPEND
    rl_completion_suppress_append = 1; // no trailing space on paths
#endif
    return rl_completion_matches(text, completion_spec_generator);
  }

  // Commands start at 0
  if (start == 0)
    return rl_completion_matches(text, completion_cmd_generator);

  // else: Sub commands and file arguments start at > 0

  // Try to match sub commands
  matches = rl_completion_matches(text, completion_sub_cmd_generator);
  if (matches)
      return matches;

  if (perform_filename_completion()) {
    // Do complete on filenames
    rl_attempted_completion_over = 0;
    return matches;
  }

  return matches;
}

int perform_filename_completion() {
  for (int i = 0; commands[i].name; ++i) {
    if (commands[i].fn_arg && strncmp(rl_line_buffer, commands[i].name, strlen(commands[i].name)) == 0) {
      return 1;
    }
  }
  return 0;
}

/**
  Called to generate completion suggestions.
  state == 0 on first call.
 */
char* completion_cmd_generator(const char* text, int state) {
  static int cmd_index;
  static size_t len;

  // First call?
  if (!state) {
    cmd_index = 0;
    len = strlen(text); // Cached for performance
  }

  // Return next suggestion
  char *name;
  while ((name = commands[cmd_index].name)) {
    ++cmd_index;

    // Check if the command is applicable
    if (strncmp(name, text, len) == 0) {
      char* r = malloc(strlen(name) + 1);
      strcpy(r, name);
      return r;
    }
  }

  // No (more) matches
  return (char*) NULL;
}

char* completion_sub_cmd_generator(const char* text, int state) {
  static int cmd_index;
  static size_t len, full_len;

  // First call?
  if (!state) {
    cmd_index = 0;
    len = strlen(text); // Cached for performance
    full_len = strlen(rl_line_buffer);
  }

  // Return next suggestion
  char* name;
  while ((name = commands[cmd_index].name)) {
    ++cmd_index;

    // Extract command and sub-command
    char buff[128];
    strncpy(buff, name, sizeof(buff));
    char* cmd = strtok(buff, " ");
    char* sub = strtok(NULL, " ");

    // Make sure the command *has* a sub command
    // and that we have the right command.
    if (cmd && sub && strncmp(rl_line_buffer, name, full_len) == 0) {
      // Check if the sub command is applicable
      if (strncmp(sub, text, len) == 0) {
        char* r = malloc(strlen(sub) + 1);
        strcpy(r, sub);
        return r;
      }
    }
  }

  // No (more) matches
  return (char*) NULL;
}

/**
 * Called to generate completion suggestions.
 * state == 0 on first call.
 */
char* completion_spec_generator(const char* text, int state) {
  // Parent context is initialized on the first call
  static instance_t* parent_inst;
  static const char* parent_end;
  static size_t parent_end_len;

  // Instace iter is advanced on each repeated call
  static instance_list_t* inst_iter;

  // First call?
  if (!state) {

    // Set the parent context
    if (parse_partial_spec_path(text, &parent_end, &parent_inst) != 0)
      return NULL; // on error

    parent_end_len = strlen(parent_end);

    // The instance iter points to the first fields
    inst_iter = parent_inst->fields;
  }

  while (inst_iter) {
    instance_t* inst = inst_iter->instance;
    inst_iter = inst_iter->next_;

    // Anonymous filler field
    if (inst->field->name == NULL)
      continue;

    char* fname = inst->field->name;
    size_t fname_len = strlen(fname);

    // Check if the field is applicable - right prefix
    if (fname_len >= parent_end_len && strncmp(fname, parent_end, parent_end_len) == 0) {

      if (parent_end - text <= 0)
        return NULL;
      size_t parent_len = (size_t)(parent_end - text);
      char* str = malloc(parent_len + fname_len + 1);

      // The parent part ending with '.'
      strncpy(str, text, parent_len);

      // The field
      strncpy(str + parent_len, fname, fname_len);

      // Null termination
      *(str + parent_len + fname_len) = '\0';

      return str;
    }
  }

  // No (more) matches
  return NULL;
}

void print_help() {
  printf("A terminal interface for working with Mifare Classic tags.\n");
  printf("Usage: mfterm [-v] [-h] [-k keyfile] [-t tagfile] [-d dictfile]\n");
  printf("\n");
  printf("Options: \n");
  printf("  --help          (-h)   Show this help message.\n");
  printf("  --version       (-v)   Display version information.\n");
  printf("  --tag=tagfile   (-t)   Load a tag from the specified file.\n");
  printf("  --keys=keyfile  (-k)   Load keys from the specified file.\n");
  printf("  --dict=dictfile (-d)   Load dictionary from the specified file.\n");
  printf("\n");
  printf(PACKAGE_NAME); printf(" home page: <https://github.com/abgandar/mfterm>\n");
}

void print_version() {
  printf(PACKAGE_STRING "\n");
  printf("Copyright (C) 2011-2013 Anders Sundman <anders@4zm.org>\n");
  printf("Copyright (C) 2024 Alexander Wittig <abgandar@gmal.com>\n");
  printf("License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n");
  printf("This is free software: you are free to change and redistribute it.\n");
  printf("There is NO WARRANTY, to the extent permitted by law.\n");
}
