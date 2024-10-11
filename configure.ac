# Copyright (C) 2012 Anders Sundman <anders@4zm.org>
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

AC_PREREQ([2.67])
AC_INIT([mfterm], [1.1.0], [abgandar@gmail.com])
AC_CONFIG_SRCDIR([mfterm.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_YACC
AM_PROG_LEX(noyywrap)
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AM_PROG_CC_C_O

# Checks for libraries.
AC_CHECK_LIB([nfc], [nfc_open], [],
             [AC_MSG_ERROR([libnfc >= 1.7 is required (http://www.libnfc.org/download)])])

AC_CHECK_LIB([readline], [rl_completion_matches], [],
             [AC_MSG_ERROR([libreadline is required])])

if test "x$HAVE_LIBREADLINE" == "xyes"
then
  AC_EGREP_HEADER([int rl_completion_suppress_append],
  [readline/readline.h],
  AC_DEFINE(HAVE_RL_COMPLETION_SUPPRESS_APPEND, 1, [Define if you have rl_completion_suppress_append]),
  AC_MSG_WARN([Command completion support limited by installed readline library]))
fi

AC_CHECK_LIB([crypto], [DES_set_key_unchecked], [],
             [AC_MSG_ERROR([libcrypto is required])])

# Checks for header files.
AC_CHECK_HEADERS([stddef.h stdint.h stdlib.h stdio.h string.h strings.h], [],
                 [AC_MSG_ERROR([A required header file was not found.])])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t time_t])

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_CHECK_FUNCS([memset strcasecmp strchr strdup strspn strcspn strtol strtoul], [],
               [AC_MSG_ERROR([A required function was not found.])])


AC_CONFIG_FILES([Makefile])

AC_OUTPUT
