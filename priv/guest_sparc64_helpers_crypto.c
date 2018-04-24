/*----------------------------------------------------------------------------*/
/*--- begin                                 guest_sparc64_helpers_crypto.c ---*/
/*----------------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2016-2016 Ivo Raisr
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
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.
*/

#include "guest_sparc64_defs.h"
#include "libvex_guest_offsets.h"
#include "main_util.h"

#if defined(VGA_sparc64)

/* Macro games */
#define VG_STRINGIFZ(__str)  #__str
#define VG_STRINGIFY(__str)  VG_STRINGIFZ(__str)

/* Performs an AES encoding round, columns 0 and 1. */

/* Signature: ULong sparc64_aes_eround01(ULong arg1, ULong arg2, ULong arg3); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_aes_eround01\n"
    ".type sparc64_aes_eround01, #function\n"
    "sparc64_aes_eround01:\n"
    "    .byte 0x81, 0xb0, 0x23, 0x08       ! movxtod %o0, %d0\n"
    "    .byte 0x85, 0xb0, 0x23, 0x09       ! movxtod %o1, %d2\n"
    "    .byte 0x89, 0xb0, 0x23, 0x0a       ! movxtod %o2, %d4\n"
    "    .byte 0x8c, 0xc8, 0x08, 0x02       ! aes_eround01 %d0, %d2, %d4, %d6\n"
    "    retl\n"
    "    .byte 0x91, 0xb0, 0x22, 0x06       ! movdtox %d6, %o0\n"
    ".size sparc64_aes_eround01, .-sparc64_aes_eround01\n"
    ".popsection"
);

/* Performs an AES encoding round, columns 2 and 3. */

/* Signature: ULong sparc64_aes_eround23(ULong arg1, ULong arg2, ULong arg3); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_aes_eround23\n"
    ".type sparc64_aes_eround23, #function\n"
    "sparc64_aes_eround23:\n"
    "    .byte 0x81, 0xb0, 0x23, 0x08       ! movxtod %o0, %d0\n"
    "    .byte 0x85, 0xb0, 0x23, 0x09       ! movxtod %o1, %d2\n"
    "    .byte 0x89, 0xb0, 0x23, 0x0a       ! movxtod %o2, %d4\n"
    "    .byte 0x8c, 0xc8, 0x08, 0x22       ! aes_eround23 %d0, %d2, %d4, %d6\n"
    "    retl\n"
    "    .byte 0x91, 0xb0, 0x22, 0x06       ! movdtox %d6, %o0\n"
    ".size sparc64_aes_eround23, .-sparc64_aes_eround23\n"
    ".popsection"
);

/* Performs an AES decoding round, columns 0 and 1. */

/* Signature: ULong sparc64_aes_dround01(ULong arg1, ULong arg2, ULong arg3); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_aes_dround01\n"
    ".type sparc64_aes_dround01, #function\n"
    "sparc64_aes_dround01:\n"
    "    .byte 0x81, 0xb0, 0x23, 0x08       ! movxtod %o0, %d0\n"
    "    .byte 0x85, 0xb0, 0x23, 0x09       ! movxtod %o1, %d2\n"
    "    .byte 0x89, 0xb0, 0x23, 0x0a       ! movxtod %o2, %d4\n"
    "    .byte 0x8c, 0xc8, 0x08, 0x42       ! aes_dround01 %d0, %d2, %d4, %d6\n"
    "    retl\n"
    "    .byte 0x91, 0xb0, 0x22, 0x06       ! movdtox %d6, %o0\n"
    ".size sparc64_aes_dround01, .-sparc64_aes_dround01\n"
    ".popsection"
);

/* Performs an AES decoding round, columns 2 and 3. */

/* Signature: ULong sparc64_aes_dround23(ULong arg1, ULong arg2, ULong arg3); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_aes_dround23\n"
    ".type sparc64_aes_dround23, #function\n"
    "sparc64_aes_dround23:\n"
    "    .byte 0x81, 0xb0, 0x23, 0x08       ! movxtod %o0, %d0\n"
    "    .byte 0x85, 0xb0, 0x23, 0x09       ! movxtod %o1, %d2\n"
    "    .byte 0x89, 0xb0, 0x23, 0x0a       ! movxtod %o2, %d4\n"
    "    .byte 0x8c, 0xc8, 0x08, 0x62       ! aes_dround23 %d0, %d2, %d4, %d6\n"
    "    retl\n"
    "    .byte 0x91, 0xb0, 0x22, 0x06       ! movdtox %d6, %o0\n"
    ".size sparc64_aes_dround23, .-sparc64_aes_dround23\n"
    ".popsection"
);

/* Performs the last AES encoding round, columns 0 and 1. */

/* Signature: ULong sparc64_aes_eround01_l(ULong arg1, ULong arg2,
                                           ULong arg3); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_aes_eround01_l\n"
    ".type sparc64_aes_eround01_l, #function\n"
    "sparc64_aes_eround01_l:\n"
    "    .byte 0x81, 0xb0, 0x23, 0x08     ! movxtod %o0, %d0\n"
    "    .byte 0x85, 0xb0, 0x23, 0x09     ! movxtod %o1, %d2\n"
    "    .byte 0x89, 0xb0, 0x23, 0x0a     ! movxtod %o2, %d4\n"
    "    .byte 0x8c, 0xc8, 0x08, 0x82     ! aes_eround01_l %d0, %d2, %d4, %d6\n"
    "    retl\n"
    "    .byte 0x91, 0xb0, 0x22, 0x06     ! movdtox %d6, %o0\n"
    ".size sparc64_aes_eround01_l, .-sparc64_aes_eround01_l\n"
    ".popsection"
);

/* Performs the last AES encoding round, columns 2 and 3. */

/* Signature: ULong sparc64_aes_eround23_l(ULong arg1, ULong arg2,
                                           ULong arg3); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_aes_eround23_l\n"
    ".type sparc64_aes_eround23_l, #function\n"
    "sparc64_aes_eround23_l:\n"
    "    .byte 0x81, 0xb0, 0x23, 0x08     ! movxtod %o0, %d0\n"
    "    .byte 0x85, 0xb0, 0x23, 0x09     ! movxtod %o1, %d2\n"
    "    .byte 0x89, 0xb0, 0x23, 0x0a     ! movxtod %o2, %d4\n"
    "    .byte 0x8c, 0xc8, 0x08, 0xa2     ! aes_eround23_l %d0, %d2, %d4, %d6\n"
    "    retl\n"
    "    .byte 0x91, 0xb0, 0x22, 0x06     ! movdtox %d6, %o0\n"
    ".size sparc64_aes_eround23_l, .-sparc64_aes_eround23_l\n"
    ".popsection"
);

/* Performs the last AES decoding round, columns 0 and 1. */

/* Signature: ULong sparc64_aes_dround01_l(ULong arg1, ULong arg2,
                                           ULong arg3); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_aes_dround01_l\n"
    ".type sparc64_aes_dround01_l, #function\n"
    "sparc64_aes_dround01_l:\n"
    "    .byte 0x81, 0xb0, 0x23, 0x08     ! movxtod %o0, %d0\n"
    "    .byte 0x85, 0xb0, 0x23, 0x09     ! movxtod %o1, %d2\n"
    "    .byte 0x89, 0xb0, 0x23, 0x0a     ! movxtod %o2, %d4\n"
    "    .byte 0x8c, 0xc8, 0x08, 0xc2     ! aes_dround01_l %d0, %d2, %d4, %d6\n"
    "    retl\n"
    "    .byte 0x91, 0xb0, 0x22, 0x06     ! movdtox %d6, %o0\n"
    ".size sparc64_aes_dround01_l, .-sparc64_aes_dround01_l\n"
    ".popsection"
);

/* Performs the last AES decoding round, columns 2 and 3. */

/* Signature: ULong sparc64_aes_dround23_l(ULong arg1, ULong arg2,
                                           ULong arg3); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_aes_dround23_l\n"
    ".type sparc64_aes_dround23_l, #function\n"
    "sparc64_aes_dround23_l:\n"
    "    .byte 0x81, 0xb0, 0x23, 0x08     ! movxtod %o0, %d0\n"
    "    .byte 0x85, 0xb0, 0x23, 0x09     ! movxtod %o1, %d2\n"
    "    .byte 0x89, 0xb0, 0x23, 0x0a     ! movxtod %o2, %d4\n"
    "    .byte 0x8c, 0xc8, 0x08, 0xe2     ! aes_dround23_l %d0, %d2, %d4, %d6\n"
    "    retl\n"
    "    .byte 0x91, 0xb0, 0x22, 0x06     ! movdtox %d6, %o0\n"
    ".size sparc64_aes_dround23_l, .-sparc64_aes_dround23_l\n"
    ".popsection"
);

/* Performs an AES key expansion without RCON. */

/* Signature: ULong sparc64_aes_kexpand0(ULong argL, ULong argR); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_aes_kexpand0\n"
    ".type sparc64_aes_kexpand0, #function\n"
    "sparc64_aes_kexpand0:\n"
    "    .byte 0x81, 0xb0, 0x23, 0x08       ! movxtod %o0, %d0\n"
    "    .byte 0x85, 0xb0, 0x23, 0x09       ! movxtod %o1, %d2\n"
    "    .byte 0x89, 0xb0, 0x26, 0x02       ! aes_kexpand0 %d0, %d2, %d4\n"
    "    retl\n"
    "    .byte 0x91, 0xb0, 0x22, 0x04       ! movdtox %d4, %o0\n"
    ".size sparc64_aes_kexpand0, .-sparc64_aes_kexpand0\n"
    ".popsection"
);

/* Performs an AES key expansion with RCON 0x01000000. */

/* Signature: ULong sparc64_aes_kexpand1_0(ULong argL, ULong argR); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_aes_kexpand1_0\n"
    ".type sparc64_aes_kexpand1_0, #function\n"
    "sparc64_aes_kexpand1_0:\n"
    "    .byte 0x81, 0xb0, 0x23, 0x08       ! movxtod %o0, %d0\n"
    "    .byte 0x85, 0xb0, 0x23, 0x09       ! movxtod %o1, %d2\n"
    "    .byte 0x88, 0xc8, 0x01, 0x02       ! aes_kexpand1 %d0, %d2, 0, %d4\n"
    "    retl\n"
    "    .byte 0x91, 0xb0, 0x22, 0x04       ! movdtox %d4, %o0\n"
    ".size sparc64_aes_kexpand1_0, .-sparc64_aes_kexpand1_0\n"
    ".popsection"
);

/* Performs an AES key expansion with RCON 0x02000000. */

/* Signature: ULong sparc64_aes_kexpand1_1(ULong argL, ULong argR); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_aes_kexpand1_1\n"
    ".type sparc64_aes_kexpand1_1, #function\n"
    "sparc64_aes_kexpand1_1:\n"
    "    .byte 0x81, 0xb0, 0x23, 0x08       ! movxtod %o0, %d0\n"
    "    .byte 0x85, 0xb0, 0x23, 0x09       ! movxtod %o1, %d2\n"
    "    .byte 0x88, 0xc8, 0x03, 0x02       ! aes_kexpand1 %d0, %d2, 1, %d4\n"
    "    retl\n"
    "    .byte 0x91, 0xb0, 0x22, 0x04       ! movdtox %d4, %o0\n"
    ".size sparc64_aes_kexpand1_1, .-sparc64_aes_kexpand1_1\n"
    ".popsection"
);

/* Performs an AES key expansion with RCON 0x04000000. */

/* Signature: ULong sparc64_aes_kexpand1_2(ULong argL, ULong argR); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_aes_kexpand1_2\n"
    ".type sparc64_aes_kexpand1_2, #function\n"
    "sparc64_aes_kexpand1_2:\n"
    "    .byte 0x81, 0xb0, 0x23, 0x08       ! movxtod %o0, %d0\n"
    "    .byte 0x85, 0xb0, 0x23, 0x09       ! movxtod %o1, %d2\n"
    "    .byte 0x88, 0xc8, 0x05, 0x02       ! aes_kexpand1 %d0, %d2, 2, %d4\n"
    "    retl\n"
    "    .byte 0x91, 0xb0, 0x22, 0x04       ! movdtox %d4, %o0\n"
    ".size sparc64_aes_kexpand1_2, .-sparc64_aes_kexpand1_2\n"
    ".popsection"
);

/* Performs an AES key expansion with RCON 0x08000000. */

/* Signature: ULong sparc64_aes_kexpand1_3(ULong argL, ULong argR); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_aes_kexpand1_3\n"
    ".type sparc64_aes_kexpand1_3, #function\n"
    "sparc64_aes_kexpand1_3:\n"
    "    .byte 0x81, 0xb0, 0x23, 0x08       ! movxtod %o0, %d0\n"
    "    .byte 0x85, 0xb0, 0x23, 0x09       ! movxtod %o1, %d2\n"
    "    .byte 0x88, 0xc8, 0x07, 0x02       ! aes_kexpand1 %d0, %d2, 3, %d4\n"
    "    retl\n"
    "    .byte 0x91, 0xb0, 0x22, 0x04       ! movdtox %d4, %o0\n"
    ".size sparc64_aes_kexpand1_3, .-sparc64_aes_kexpand1_3\n"
    ".popsection"
);

/* Performs an AES key expansion with RCON 0x10000000. */

/* Signature: ULong sparc64_aes_kexpand1_4(ULong argL, ULong argR); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_aes_kexpand1_4\n"
    ".type sparc64_aes_kexpand1_4, #function\n"
    "sparc64_aes_kexpand1_4:\n"
    "    .byte 0x81, 0xb0, 0x23, 0x08       ! movxtod %o0, %d0\n"
    "    .byte 0x85, 0xb0, 0x23, 0x09       ! movxtod %o1, %d2\n"
    "    .byte 0x88, 0xc8, 0x09, 0x02       ! aes_kexpand1 %d0, %d2, 4, %d4\n"
    "    retl\n"
    "    .byte 0x91, 0xb0, 0x22, 0x04       ! movdtox %d4, %o0\n"
    ".size sparc64_aes_kexpand1_4, .-sparc64_aes_kexpand1_4\n"
    ".popsection"
);

/* Performs an AES key expansion with RCON 0x20000000. */

/* Signature: ULong sparc64_aes_kexpand1_5(ULong argL, ULong argR); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_aes_kexpand1_5\n"
    ".type sparc64_aes_kexpand1_5, #function\n"
    "sparc64_aes_kexpand1_5:\n"
    "    .byte 0x81, 0xb0, 0x23, 0x08       ! movxtod %o0, %d0\n"
    "    .byte 0x85, 0xb0, 0x23, 0x09       ! movxtod %o1, %d2\n"
    "    .byte 0x88, 0xc8, 0x0b, 0x02       ! aes_kexpand1 %d0, %d2, 5, %d4\n"
    "    retl\n"
    "    .byte 0x91, 0xb0, 0x22, 0x04       ! movdtox %d4, %o0\n"
    ".size sparc64_aes_kexpand1_5, .-sparc64_aes_kexpand1_5\n"
    ".popsection"
);

/* Performs an AES key expansion with RCON 0x40000000. */

/* Signature: ULong sparc64_aes_kexpand1_6(ULong argL, ULong argR); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_aes_kexpand1_6\n"
    ".type sparc64_aes_kexpand1_6, #function\n"
    "sparc64_aes_kexpand1_6:\n"
    "    .byte 0x81, 0xb0, 0x23, 0x08       ! movxtod %o0, %d0\n"
    "    .byte 0x85, 0xb0, 0x23, 0x09       ! movxtod %o1, %d2\n"
    "    .byte 0x88, 0xc8, 0x0d, 0x02       ! aes_kexpand1 %d0, %d2, 6, %d4\n"
    "    retl\n"
    "    .byte 0x91, 0xb0, 0x22, 0x04       ! movdtox %d4, %o0\n"
    ".size sparc64_aes_kexpand1_6, .-sparc64_aes_kexpand1_6\n"
    ".popsection"
);

/* Performs an AES key expansion with RCON 0x80000000. */

/* Signature: ULong sparc64_aes_kexpand1_7(ULong argL, ULong argR); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_aes_kexpand1_7\n"
    ".type sparc64_aes_kexpand1_7, #function\n"
    "sparc64_aes_kexpand1_7:\n"
    "    .byte 0x81, 0xb0, 0x23, 0x08       ! movxtod %o0, %d0\n"
    "    .byte 0x85, 0xb0, 0x23, 0x09       ! movxtod %o1, %d2\n"
    "    .byte 0x88, 0xc8, 0x0f, 0x02       ! aes_kexpand1 %d0, %d2, 7, %d4\n"
    "    retl\n"
    "    .byte 0x91, 0xb0, 0x22, 0x04       ! movdtox %d4, %o0\n"
    ".size sparc64_aes_kexpand1_7, .-sparc64_aes_kexpand1_7\n"
    ".popsection"
);

/* Performs an AES key expansion with RCON 0x1b000000. */

/* Signature: ULong sparc64_aes_kexpand1_8(ULong argL, ULong argR); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_aes_kexpand1_8\n"
    ".type sparc64_aes_kexpand1_8, #function\n"
    "sparc64_aes_kexpand1_8:\n"
    "    .byte 0x81, 0xb0, 0x23, 0x08       ! movxtod %o0, %d0\n"
    "    .byte 0x85, 0xb0, 0x23, 0x09       ! movxtod %o1, %d2\n"
    "    .byte 0x88, 0xc8, 0x11, 0x02       ! aes_kexpand1 %d0, %d2, 8, %d4\n"
    "    retl\n"
    "    .byte 0x91, 0xb0, 0x22, 0x04       ! movdtox %d4, %o0\n"
    ".size sparc64_aes_kexpand1_8, .-sparc64_aes_kexpand1_8\n"
    ".popsection"
);

/* Performs an AES key expansion with RCON 0x36000000. */

/* Signature: ULong sparc64_aes_kexpand1_9(ULong argL, ULong argR); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_aes_kexpand1_9\n"
    ".type sparc64_aes_kexpand1_9, #function\n"
    "sparc64_aes_kexpand1_9:\n"
    "    .byte 0x81, 0xb0, 0x23, 0x08       ! movxtod %o0, %d0\n"
    "    .byte 0x85, 0xb0, 0x23, 0x09       ! movxtod %o1, %d2\n"
    "    .byte 0x88, 0xc8, 0x13, 0x02       ! aes_kexpand1 %d0, %d2, 9, %d4\n"
    "    retl\n"
    "    .byte 0x91, 0xb0, 0x22, 0x04       ! movdtox %d4, %o0\n"
    ".size sparc64_aes_kexpand1_9, .-sparc64_aes_kexpand1_9\n"
    ".popsection"
);

/* Performs an AES key expansion without SBOX. */

/* Signature: ULong sparc64_aes_kexpand2(ULong argL, ULong argR); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_aes_kexpand2\n"
    ".type sparc64_aes_kexpand2, #function\n"
    "sparc64_aes_kexpand2:\n"
    "    .byte 0x81, 0xb0, 0x23, 0x08       ! movxtod %o0, %d0\n"
    "    .byte 0x85, 0xb0, 0x23, 0x09       ! movxtod %o1, %d2\n"
    "    .byte 0x89, 0xb0, 0x26, 0x22       ! aes_kexpand2 %d0, %d2, %d4\n"
    "    retl\n"
    "    .byte 0x91, 0xb0, 0x22, 0x04       ! movdtox %d4, %o0\n"
    ".size sparc64_aes_kexpand2, .-sparc64_aes_kexpand2\n"
    ".popsection"
);

/* Calculates md5 hash. All input and output is located in the guest state.
   IV is taken from %q0 (128 bits).
   Input data is taken from %q8-%q20 (512 bits in total).
   Result is written into %q0 (128 bits). */

/* Signature: void sparc64_md5(VexGuestSPARC64State *guest_state); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_md5\n"
    ".type sparc64_md5, #function\n"
    "sparc64_md5:\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F0)  "], %q0\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F8)  "], %q8\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F12) "], %q12\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F16) "], %q16\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F20) "], %q20\n"
    "    .byte 0x81, 0xb0, 0x28, 0x00		! md5 (takes no operands)\n"
    "    retl\n"
    "    stq %q0, [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F0) "]\n"
    ".size sparc64_md5, .-sparc64_md5\n"
    ".popsection"
);

/* Calculates sha1 hash. All input and output is located in the guest state.
   IV is taken from %f0-%f4 (160 bits).
   Input data is taken from %q8-%q20 (512 bits in total).
   Result is written into %f0-%f4 (160 bits). */

/* Signature: void sparc64_sha1(VexGuestSPARC64State *guest_state); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_sha1\n"
    ".type sparc64_sha1, #function\n"
    "sparc64_sha1:\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F0)  "], %q0\n"
    "    ld [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F4)  "], %f4\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F8)  "], %q8\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F12) "], %q12\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F16) "], %q16\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F20) "], %q20\n"
    "    .byte 0x81, 0xb0, 0x28, 0x20		! sha1 (takes no operands)\n"
    "    stq %q0, [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F0) "]\n"
    "    retl\n"
    "    st %f4, [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F4) "]\n"
    ".size sparc64_sha1, .-sparc64_sha1\n"
    ".popsection"
);

/* Calculates sha256 hash. All input and output is located in the guest state.
   IV is taken from %q0-%q4 (256 bits).
   Input data is taken from %q8-%q20 (512 bits in total).
   Result is written into %q0-%q4 (256 bits). */

/* Signature: void sparc64_sha256(VexGuestSPARC64State *guest_state); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_sha256\n"
    ".type sparc64_sha256, #function\n"
    "sparc64_sha256:\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F0)  "], %q0\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F4)  "], %q4\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F8)  "], %q8\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F12) "], %q12\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F16) "], %q16\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F20) "], %q20\n"
    "    .byte 0x81, 0xb0, 0x28, 0x40		! sha256 (takes no operands)\n"
    "    stq %q0, [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F0) "]\n"
    "    retl\n"
    "    stq %q4, [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F4) "]\n"
    ".size sparc64_sha256, .-sparc64_sha256\n"
    ".popsection"
);

/* Calculates sha512 hash. All input and output is located in the guest state.
   IV is taken from %q0-%q12 (512 bits).
   Input data is taken from %q16-%q44 (1024 bits in total).
   Result is written into %q0-%q12 (512 bits). */

/* Signature: void sparc64_sha512(VexGuestSPARC64State *guest_state); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_sha512\n"
    ".type sparc64_sha512, #function\n"
    "sparc64_sha512:\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F0)  "], %q0\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F4)  "], %q4\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F8)  "], %q8\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F12) "], %q12\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F16) "], %q16\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F20) "], %q20\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F24) "], %q24\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F28) "], %q28\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_D32) "], %q32\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_D36) "], %q36\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_D40) "], %q40\n"
    "    ldq [%o0 + " VG_STRINGIFY(OFFSET_sparc64_D44) "], %q44\n"
    "    .byte 0x81, 0xb0, 0x28, 0x60		! sha512 (takes no operands)\n"
    "    stq %q0, [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F0) "]\n"
    "    stq %q4, [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F4) "]\n"
    "    stq %q8, [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F8) "]\n"
    "    retl\n"
    "    stq %q12, [%o0 + " VG_STRINGIFY(OFFSET_sparc64_F12) "]\n"
    ".size sparc64_sha512, .-sparc64_sha512\n"
    ".popsection"
);

/* Calculates a 64-bit by 64-bit bitwise (XOR) multiplication. An XOR multiply
   uses the XOR operation instead of the ADD operation when combining partial
   products. Returns the less significant 64 bits of the result. */

/* Signature: ULong sparc64_xmulx(ULong argL, ULong argR); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_xmulx\n"
    ".type sparc64_xmulx, #function\n"
    "sparc64_xmulx:\n"
    "    retl\n"
    "    .byte 0x91, 0xb2, 0x22, 0xa9		! xmulx %o0, %o1, %o0\n"
    ".size sparc64_xmulx, .-sparc64_xmulx\n"
    ".popsection"
);

/* Calculates a 64-bit by 64-bit bitwise (XOR) multiplication. An XOR multiply
   uses the XOR operation instead of the ADD operation when combining partial
   products. Returns the more significant 64 bits of the result. */

/* Signature: ULong sparc64_xmulxhi(ULong argL, ULong argR); */
asm("\n"
    ".pushsection \".text\"\n"
    ".globl sparc64_xmulxhi\n"
    ".type sparc64_xmulxhi, #function\n"
    "sparc64_xmulxhi:\n"
    "    retl\n"
    "    .byte 0x91, 0xb2, 0x22, 0xc9		! xmulxhi %o0, %o1, %o0\n"
    ".size sparc64_xmulxhi, .-sparc64_xmulxhi\n"
    ".popsection"
);

#else

ULong
sparc64_aes_eround01(ULong arg1, ULong arg2, ULong arg3)
{
    vpanic("Unimplemented");
}

ULong
sparc64_aes_eround23(ULong arg1, ULong arg2, ULong arg3)
{
    vpanic("Unimplemented");
}

ULong
sparc64_aes_dround01(ULong arg1, ULong arg2, ULong arg3)
{
    vpanic("Unimplemented");
}

ULong
sparc64_aes_dround23(ULong arg1, ULong arg2, ULong arg3)
{
    vpanic("Unimplemented");
}

ULong
sparc64_aes_eround01_l(ULong arg1, ULong arg2, ULong arg3)
{
    vpanic("Unimplemented");
}

ULong
sparc64_aes_eround23_l(ULong arg1, ULong arg2, ULong arg3)
{
    vpanic("Unimplemented");
}

ULong
sparc64_aes_dround01_l(ULong arg1, ULong arg2, ULong arg3)
{
    vpanic("Unimplemented");
}

ULong
sparc64_aes_dround23_l(ULong arg1, ULong arg2, ULong arg3)
{
    vpanic("Unimplemented");
}

ULong
sparc64_aes_kexpand0(ULong argL, ULong argR)
{
    vpanic("Unimplemented");
}

ULong
sparc64_aes_kexpand1_0(ULong argL, ULong argR)
{
    vpanic("Unimplemented");
}

ULong
sparc64_aes_kexpand1_1(ULong argL, ULong argR)
{
    vpanic("Unimplemented");
}

ULong
sparc64_aes_kexpand1_2(ULong argL, ULong argR)
{
    vpanic("Unimplemented");
}

ULong
sparc64_aes_kexpand1_3(ULong argL, ULong argR)
{
    vpanic("Unimplemented");
}

ULong
sparc64_aes_kexpand1_4(ULong argL, ULong argR)
{
    vpanic("Unimplemented");
}

ULong
sparc64_aes_kexpand1_5(ULong argL, ULong argR)
{
    vpanic("Unimplemented");
}

ULong
sparc64_aes_kexpand1_6(ULong argL, ULong argR)
{
    vpanic("Unimplemented");
}

ULong
sparc64_aes_kexpand1_7(ULong argL, ULong argR)
{
    vpanic("Unimplemented");
}

ULong
sparc64_aes_kexpand1_8(ULong argL, ULong argR)
{
    vpanic("Unimplemented");
}

ULong
sparc64_aes_kexpand1_9(ULong argL, ULong argR)
{
    vpanic("Unimplemented");
}

ULong
sparc64_aes_kexpand2(ULong argL, ULong argR)
{
    vpanic("Unimplemented");
}

void
sparc64_md5(VexGuestSPARC64State *guest_state)
{
    vpanic("Unimplemented");
}

void
sparc64_sha1(VexGuestSPARC64State *guest_state)
{
    vpanic("Unimplemented");
}

void
sparc64_sha256(VexGuestSPARC64State *guest_state)
{
    vpanic("Unimplemented");
}

void
sparc64_sha512(VexGuestSPARC64State *guest_state)
{
    vpanic("Unimplemented");
}

ULong
sparc64_xmulx(ULong argL, ULong argR)
{
    vpanic("Unimplemented");
}

ULong
sparc64_xmulxhi(ULong argL, ULong argR)
{
    vpanic("Unimplemented");
}

#endif /* VGA_sparc64 */

/*----------------------------------------------------------------------------*/
/*--- end                                   guest_sparc64_helpers_crypto.c ---*/
/*----------------------------------------------------------------------------*/
