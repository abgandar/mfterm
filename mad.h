#ifndef MAD__H
#define MAD__H

/**
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

#include "tag.h"

typedef struct {
 char* name;
 uint16_t val;
} aid_t;

extern const aid_t AIDs[];

void mad_calc_crc(mf_tag_t* tag, uint8_t crcs[2]);
int mad_crc(mf_tag_t* tag);
int mad_set_info(mf_tag_t* tag, size_t sector);
int mad_put_aid(mf_tag_t* tag, size_t sector, uint16_t aid);
int mad_init(mf_tag_t* tag, mf_size_t size);
int mad_size(mf_tag_t* tag, mf_size_t size);
int mad_print(mf_tag_t* tag);

#endif