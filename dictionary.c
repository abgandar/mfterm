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
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "dictionary.h"

static key_list_t* key_list = NULL;

key_list_t* kl_add(key_list_t** list, const uint8_t* key);
void kl_clear(key_list_t** list);
key_list_t* kl_make_node(const uint8_t* key);
int key_cmp(const uint8_t* k1, const uint8_t* k2);

void dictionary_clear() {
  kl_clear(&key_list);
}

int dictionary_add(const uint8_t* key) {
  return kl_add(&key_list, key) != NULL;
}

key_list_t* dictionary_get() {
  return key_list;
}

key_list_t* kl_add(key_list_t** list, const uint8_t* key) {
  if (list == NULL)
    return NULL;

  // A new list
  if (*list == NULL)
    return *list = kl_make_node(key);

  // Append
  key_list_t* it = *list;
  key_list_t* last = NULL;
  while(it) {
    // Don't add duplicates, but move the key first in the list
    if (key_cmp(it->key, key) == 0) {
      if (last) {
        last->next = it->next;
        it->next = *list;
        *list = it;
      }

      return NULL;
    }
    last = it;
    it = it->next;
  }

  return last->next = kl_make_node(key);
}

void kl_clear(key_list_t** list) {
  if (list == NULL || *list == NULL)
    return;

  key_list_t* it = *list;
  do {
    key_list_t* next = it->next;
    free(it);
    it = next;
  } while(it);

  *list = NULL;
}

key_list_t* kl_make_node(const uint8_t* key) {
  key_list_t* new_node = (key_list_t*) malloc(sizeof(key_list_t));
  memcpy((void*)new_node, key, 6);
  new_node->next = NULL;
  return new_node;
}

int key_cmp(const uint8_t* k1, const uint8_t* k2) {
  for (int i = 0; i < 6; ++i) {
    if (k1[i] != k2[i])
      return -1;
  }
  return 0;
}
