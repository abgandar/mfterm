# Copyright (C) 2012 Anders Sundman <anders@4zm.org>
# Copyright (C) 2024 Alexander Wittig <abgandar@gmail.com>
#
# This file is part of mfterm.
#
# mfterm is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# mfterm is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with mfterm.  If not, see <http://www.gnu.org/licenses/>.

AM_CFLAGS = -g -Wall -Wconversion -std=c99

SUBDIRS = .

bin_PROGRAMS = mfterm

mfterm_SOURCES =                \
  mfterm.h mfterm.c             \
  term_cmd.h term_cmd.c         \
  util.h util.c                 \
  tag.h tag.c                   \
  ndef.h ndef.c                 \
  mad.h mad.c                   \
  mifare.h mifare.c             \
  mifare_ctrl.h mifare_ctrl.c   \
  dictionary.h dictionary.c     \
  spec_syntax.h spec_syntax.c   \
  mac.h mac.c

mfterm_LDADD = libsp.a

man1_MANS = mfterm.man
dist_man1_MANS = mfterm.man

# We create two convenience libraries fot the parser targets. This is
# to allow us to use different flags (since automake doesn't support
# per file, but only per target flags).
noinst_LIBRARIES = libsp.a

libsp_a_SOURCES = spec_tokenizer.l spec_parser.y
libsp_a_LFLAGS = --prefix=sp_ -o$(LEX_OUTPUT_ROOT).c
libsp_a_YFLAGS = --name-prefix=sp_ -d
libsp_a_CFLAGS = -g -std=c99 -Wall -Wno-unused-function -Wno-unused-but-set-variable -Wno-implicit-function-declaration

BUILT_SOURCES = libsp_a-spec_parser.h
