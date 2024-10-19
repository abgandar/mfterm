#ifndef EMULATE__H
#define EMULATE__H

/**
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
 */

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <nfc/nfc-types.h>
#include <nfc/nfc-emulation.h>

#include "tag.h"
#include "crypto1.h"


typedef struct {
  nfc_device *device;
  nfc_target *target;
  mf_tag_t *tag;
  crypto1_ctx_t ctx;
} emulator_data_t;

int emulate_target_io(emulator_data_t *ed, const uint8_t *data_in, const size_t data_in_len, uint8_t *data_out, const size_t data_out_len);
int emulate_target(emulator_data_t *ed);
int emulate_reader(emulator_data_t *ed);

#endif