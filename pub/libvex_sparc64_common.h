/*----------------------------------------------------------------------------*/
/*--- Common definitions for SPARC64               libvex_sparc64_common.h ---*/
/*----------------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2017-2017 Ivo Raisr
      ivosh@ivosh.net

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301, USA.

   The GNU General Public License is contained in the file COPYING.
*/

#ifndef LIBVEX_SPARC64_COMMON_H
#define LIBVEX_SPARC64_COMMON_H

/* This file must be suitable for inclusion in assembler source files. */

#define SPARC64_STACK_BIAS 2047
#define SPARC64_WINDOWSIZE (16 * 8)             /* size of window save area */
#define SPARC64_ARGPUSHSIZE (6 * 8)             /* size of arg dump area */
#define SPARC64_MINFRAME (SPARC64_WINDOWSIZE + SPARC64_ARGPUSHSIZE)

#endif /* LIBVEX_SPARC64_COMMON_H */

/*----------------------------------------------------------------------------*/
/*--- end                                          libvex_sparc64_common.h ---*/
/*----------------------------------------------------------------------------*/
