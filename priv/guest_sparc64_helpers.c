/*----------------------------------------------------------------------------*/
/*--- begin                           guest_sparc64_helpers.c              ---*/
/*----------------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2015-2017 Ivo Raisr
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

/* Copyright 2015-2015, Tomas Jedlicka <jedlickat@gmail.com>. */


#include "sparc64_disasm.h"
#include "libvex_emnote.h"
#include "libvex_ir.h"
#include "libvex.h"
#include "libvex_guest_offsets.h"

#include "main_util.h"
#include "main_globals.h"
#include "guest_generic_bb_to_IR.h"
#include "guest_sparc64_defs.h"

void
LibVEX_GuestSPARC64_initialise(/*OUT*/ VexGuestSPARC64State *vex_state)
{
    /* Event counters */
    vex_state->host_EvC_FAILADDR = 0;
    vex_state->host_EvC_COUNTER = 0;
    vex_state->pad0 = 0;

    /* GPRs */
    vex_state->guest_R0 = 0;
    vex_state->guest_R1 = 0;
    vex_state->guest_R2 = 0;
    vex_state->guest_R3 = 0;
    vex_state->guest_R4 = 0;
    vex_state->guest_R5 = 0;
    vex_state->guest_R6 = 0;
    vex_state->guest_R7 = 0;
    vex_state->guest_R8 = 0;
    vex_state->guest_R9 = 0;
    vex_state->guest_R10 = 0;
    vex_state->guest_R11 = 0;
    vex_state->guest_R12 = 0;
    vex_state->guest_R13 = 0;
    vex_state->guest_R14 = 0;
    vex_state->guest_R15 = 0;
    vex_state->guest_R16 = 0;
    vex_state->guest_R17 = 0;
    vex_state->guest_R18 = 0;
    vex_state->guest_R19 = 0;
    vex_state->guest_R20 = 0;
    vex_state->guest_R21 = 0;
    vex_state->guest_R22 = 0;
    vex_state->guest_R23 = 0;
    vex_state->guest_R24 = 0;
    vex_state->guest_R25 = 0;
    vex_state->guest_R26 = 0;
    vex_state->guest_R27 = 0;
    vex_state->guest_R28 = 0;
    vex_state->guest_R29 = 0;
    vex_state->guest_R30 = 0;
    vex_state->guest_R31 = 0;

    /* FPU */
    vex_state->guest_F0 = 0;
    vex_state->guest_F1 = 0;
    vex_state->guest_F2 = 0;
    vex_state->guest_F3 = 0;
    vex_state->guest_F4 = 0;
    vex_state->guest_F5 = 0;
    vex_state->guest_F6 = 0;
    vex_state->guest_F7 = 0;
    vex_state->guest_F8 = 0;
    vex_state->guest_F9 = 0;
    vex_state->guest_F10 = 0;
    vex_state->guest_F11 = 0;
    vex_state->guest_F12 = 0;
    vex_state->guest_F13 = 0;
    vex_state->guest_F14 = 0;
    vex_state->guest_F15 = 0;
    vex_state->guest_F16 = 0;
    vex_state->guest_F17 = 0;
    vex_state->guest_F18 = 0;
    vex_state->guest_F19 = 0;
    vex_state->guest_F20 = 0;
    vex_state->guest_F21 = 0;
    vex_state->guest_F22 = 0;
    vex_state->guest_F23 = 0;
    vex_state->guest_F24 = 0;
    vex_state->guest_F25 = 0;
    vex_state->guest_F26 = 0;
    vex_state->guest_F27 = 0;
    vex_state->guest_F28 = 0;
    vex_state->guest_F29 = 0;
    vex_state->guest_F30 = 0;
    vex_state->guest_F31 = 0;
    vex_state->guest_D32 = 0;
    vex_state->guest_D34 = 0;
    vex_state->guest_D36 = 0;
    vex_state->guest_D38 = 0;
    vex_state->guest_D40 = 0;
    vex_state->guest_D42 = 0;
    vex_state->guest_D44 = 0;
    vex_state->guest_D46 = 0;
    vex_state->guest_D48 = 0;
    vex_state->guest_D50 = 0;
    vex_state->guest_D52 = 0;
    vex_state->guest_D54 = 0;
    vex_state->guest_D56 = 0;
    vex_state->guest_D58 = 0;
    vex_state->guest_D60 = 0;
    vex_state->guest_D62 = 0;

    /* program counters */
    vex_state->guest_PC = 0;
    vex_state->guest_NPC = 0;

    /* ASI */
    vex_state->guest_Y = 0;
    vex_state->guest_ASI = SPARC64_ASI_PRIMARY_NO_FAULT;
    vex_state->guest_FPRS = SPARC64_FPRS_MASK_FEF; /* FPU support always on */
    vex_state->guest_GSR_align = 0;
    vex_state->guest_GSR_mask = 0;

    /* CC regs */
    vex_state->guest_CC_OP = 0;
    vex_state->guest_CC_DEP1 = 0;
    vex_state->guest_CC_DEP2 = 0;
    vex_state->guest_CC_NDEP = 0;

    /* Initialize FSR thunks. */
    vex_state->guest_FSR_RD = Irrm_NEAREST; /* encoded as per IRRoundingMode */
    vex_state->guest_FSR_FCC = 0;
    vex_state->guest_FSR_CEXC_OP = SPARC64_FSR_CEXC_OP_COPY;
    vex_state->guest_FSR_CEXC_DEP1_LO = 0;
    vex_state->guest_FSR_CEXC_DEP1_HI = 0;
    vex_state->guest_FSR_CEXC_DEP2_LO = 0;
    vex_state->guest_FSR_CEXC_DEP2_HI = 0;
    vex_state->guest_FSR_CEXC_NDEP = 0;

    vex_state->guest_NRADDR = 0;
}

#define VG_STRINGIFZ(__str)  #__str
#define VG_STRINGIFX(__str)  VG_STRINGIFZ(__str)
#define VG_STRINGIFY(__str)  VG_STRINGIFX(OFFSET_sparc64_ ## __str)

/* void LibVEX_GuestSPARC64_LoadGuestRegisters(void); */

__asm__ (
".text\n"
".register %g2, #scratch \n"
".register %g3, #scratch \n"
".globl LibVEX_GuestSPARC64_LoadGuestRegisters\n"
".type LibVEX_GuestSPARC64_LoadGuestRegisters, #function\n"
"LibVEX_GuestSPARC64_LoadGuestRegisters:\n"

/* %g7 is used to hold the pointer to the guest state during the
   execution of the unrecognized instruction. \n*/
"   mov  %g5, %g7 \n"

/* Save %fp and %sp registers across unimplemented instruction. */
"   stx %fp, [ %g7 + "VG_STRINGIFY(host_FP)" ] \n"
"   stx %sp, [ %g7 + "VG_STRINGIFY(host_SP)" ] \n"

/* Save %o7 across calls so we can return from this function. */
"   mov %o7, %i5 \n"

/* Ancillary Registers. Load them into %i1-%i4 across calls. */
/* No need to load/store FPRS as it is set by vgPlain_disp_run_translations. */
/* ASI is only 8 bits, and the rest in the guest state is used for scratch. */
"   ldx [ %g7 + "VG_STRINGIFY(ASI)" ], %o0 \n"
"   mov %o0, %i1 \n"
"   mov %g7, %o0 \n"
"   call LibVEX_GuestSPARC64_get_gsr \n"
"   nop \n"
"   mov %o0, %i2 \n"
"   mov %g7, %o0 \n"
"   call LibVEX_GuestSPARC64_get_fsr \n"
"   nop \n"
"   mov %o0, %i3 \n"
"   mov %g7, %o0 \n"
"   call LibVEX_GuestSPARC64_get_ccr \n"
"   nop \n"
"   mov %o0, %i4 \n"

/* Write values into ancillary registers after calls. */
"   wr  %i1, 0, %asi \n"
"   wr  %i2, 0, %gsr \n"
"   stx %i3, [ %g7 + "VG_STRINGIFY(scratchpad)"] \n" /* FSR scratchpad */
"   ldx [ %g7 + "VG_STRINGIFY(scratchpad)"], %fsr \n"
"   wr  %i4, 0, %ccr \n"

/* Restore return register after calls */
"   mov %i5, %o7 \n"

/* General Purpose Registers */
"   ldx  [ %g7 + "VG_STRINGIFY(R1)" ],  %g1 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R2)" ],  %g2 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R3)" ],  %g3 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R4)" ],  %g4 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R5)" ],  %g5 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R6)" ],  %g6 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R8)" ],  %o0 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R9)" ],  %o1 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R10)" ], %o2 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R11)" ], %o3 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R12)" ], %o4 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R13)" ], %o5 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R14)" ], %o6 \n"  /* %sp stack pointer */
"   ldx  [ %g7 + "VG_STRINGIFY(R16)" ], %l0 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R17)" ], %l1 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R18)" ], %l2 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R19)" ], %l3 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R20)" ], %l4 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R21)" ], %l5 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R22)" ], %l6 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R23)" ], %l7 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R24)" ], %i0 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R25)" ], %i1 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R26)" ], %i2 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R27)" ], %i3 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R28)" ], %i4 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R29)" ], %i5 \n"
"   ldx  [ %g7 + "VG_STRINGIFY(R30)" ], %i6 \n" /* %fp frame pointer */
"   ldx  [ %g7 + "VG_STRINGIFY(R31)" ], %i7 \n"

/* Floating Point Registers */
"   ldd [%g7 + "VG_STRINGIFY(F0)" ],  %d0 \n"
"   ldd [%g7 + "VG_STRINGIFY(F2)" ],  %d2 \n"
"   ldd [%g7 + "VG_STRINGIFY(F4)" ],  %d4 \n"
"   ldd [%g7 + "VG_STRINGIFY(F6)" ],  %d6 \n"
"   ldd [%g7 + "VG_STRINGIFY(F8)" ],  %d8 \n"
"   ldd [%g7 + "VG_STRINGIFY(F10)" ], %d10 \n"
"   ldd [%g7 + "VG_STRINGIFY(F12)" ], %d12 \n"
"   ldd [%g7 + "VG_STRINGIFY(F14)" ], %d14 \n"
"   ldd [%g7 + "VG_STRINGIFY(F16)" ], %d16 \n"
"   ldd [%g7 + "VG_STRINGIFY(F18)" ], %d18 \n"
"   ldd [%g7 + "VG_STRINGIFY(F20)" ], %d20 \n"
"   ldd [%g7 + "VG_STRINGIFY(F22)" ], %d22 \n"
"   ldd [%g7 + "VG_STRINGIFY(F24)" ], %d24 \n"
"   ldd [%g7 + "VG_STRINGIFY(F26)" ], %d26 \n"
"   ldd [%g7 + "VG_STRINGIFY(F28)" ], %d28 \n"
"   ldd [%g7 + "VG_STRINGIFY(F30)" ], %d30 \n"
"   ldd [%g7 + "VG_STRINGIFY(D32)" ], %d32 \n"
"   ldd [%g7 + "VG_STRINGIFY(D34)" ], %d34 \n"
"   ldd [%g7 + "VG_STRINGIFY(D36)" ], %d36 \n"
"   ldd [%g7 + "VG_STRINGIFY(D38)" ], %d38 \n"
"   ldd [%g7 + "VG_STRINGIFY(D40)" ], %d40 \n"
"   ldd [%g7 + "VG_STRINGIFY(D42)" ], %d42 \n"
"   ldd [%g7 + "VG_STRINGIFY(D44)" ], %d44 \n"
"   ldd [%g7 + "VG_STRINGIFY(D46)" ], %d46 \n"
"   ldd [%g7 + "VG_STRINGIFY(D48)" ], %d48 \n"
"   ldd [%g7 + "VG_STRINGIFY(D50)" ], %d50 \n"
"   ldd [%g7 + "VG_STRINGIFY(D52)" ], %d52 \n"
"   ldd [%g7 + "VG_STRINGIFY(D54)" ], %d54 \n"
"   ldd [%g7 + "VG_STRINGIFY(D56)" ], %d56 \n"
"   ldd [%g7 + "VG_STRINGIFY(D58)" ], %d58 \n"
"   ldd [%g7 + "VG_STRINGIFY(D60)" ], %d60 \n"
"   ldd [%g7 + "VG_STRINGIFY(D62)" ], %d62 \n"

"   retl \n"
"   nop \n"
".size LibVEX_GuestSPARC64_LoadGuestRegisters, .-LibVEX_GuestSPARC64_LoadGuestRegisters\n"
".previous\n"
);


/* %g7 holds the guest state pointer (%g5) across an unrecognized instruction.
   The %g7 register is reserved for libc's TLS. Libc+libpthread use
   only the following instructions to access it: add, casx, clr, clrx,
   cmp, ld, ldsw, ldub, ldx, mov, stb, st, stx, and swap. -- Ivo */

/* void LibVEX_GuestSPARC64_StoreGuestRegisters(void) */
__asm__ (
".text\n"
".register %g2, #scratch \n"
".register %g3, #scratch \n"
".globl LibVEX_GuestSPARC64_StoreGuestRegisters\n"
".type LibVEX_GuestSPARC64_StoreGuestRegisters, #function\n"
"LibVEX_GuestSPARC64_StoreGuestRegisters:\n"

/* General Purpose Registers
   Note: %o7, %g1, and %g4 are stored in generated code before this call. */

"   stx  %g2, [ %g7 + "VG_STRINGIFY(R2)" ] \n"
"   stx  %g3, [ %g7 + "VG_STRINGIFY(R3)" ] \n"
"   stx  %g5, [ %g7 + "VG_STRINGIFY(R5)" ] \n"
"   stx  %g6, [ %g7 + "VG_STRINGIFY(R6)" ] \n"
"   stx  %o0, [ %g7 + "VG_STRINGIFY(R8)" ] \n"
"   stx  %o1, [ %g7 + "VG_STRINGIFY(R9)" ] \n"
"   stx  %o2, [ %g7 + "VG_STRINGIFY(R10)" ] \n"
"   stx  %o3, [ %g7 + "VG_STRINGIFY(R11)" ] \n"
"   stx  %o4, [ %g7 + "VG_STRINGIFY(R12)" ] \n"
"   stx  %o5, [ %g7 + "VG_STRINGIFY(R13)" ] \n"
"   stx  %o6, [ %g7 + "VG_STRINGIFY(R14)" ] \n"  /* %sp stack pointer */
"   stx  %l0, [ %g7 + "VG_STRINGIFY(R16)" ] \n"
"   stx  %l1, [ %g7 + "VG_STRINGIFY(R17)" ] \n"
"   stx  %l2, [ %g7 + "VG_STRINGIFY(R18)" ] \n"
"   stx  %l3, [ %g7 + "VG_STRINGIFY(R19)" ] \n"
"   stx  %l4, [ %g7 + "VG_STRINGIFY(R20)" ] \n"
"   stx  %l5, [ %g7 + "VG_STRINGIFY(R21)" ] \n"
"   stx  %l6, [ %g7 + "VG_STRINGIFY(R22)" ] \n"
"   stx  %l7, [ %g7 + "VG_STRINGIFY(R23)" ] \n"
"   stx  %i0, [ %g7 + "VG_STRINGIFY(R24)" ] \n"
"   stx  %i1, [ %g7 + "VG_STRINGIFY(R25)" ] \n"
"   stx  %i2, [ %g7 + "VG_STRINGIFY(R26)" ] \n"
"   stx  %i3, [ %g7 + "VG_STRINGIFY(R27)" ] \n"
"   stx  %i4, [ %g7 + "VG_STRINGIFY(R28)" ] \n"
"   stx  %i5, [ %g7 + "VG_STRINGIFY(R29)" ] \n"
"   stx  %i6, [ %g7 + "VG_STRINGIFY(R30)" ] \n" /* %fp frame pointer */
"   stx  %i7, [ %g7 + "VG_STRINGIFY(R31)" ] \n"

/*     Floating Point Registers */
"   std %d0,  [%g7 + "VG_STRINGIFY(F0)" ]\n"
"   std %d2,  [%g7 + "VG_STRINGIFY(F2)" ]\n"
"   std %d4,  [%g7 + "VG_STRINGIFY(F4)" ]\n"
"   std %d6,  [%g7 + "VG_STRINGIFY(F6)" ]\n"
"   std %d8,  [%g7 + "VG_STRINGIFY(F8)" ]\n"
"   std %d10, [%g7 + "VG_STRINGIFY(F10)" ]\n"
"   std %d12, [%g7 + "VG_STRINGIFY(F12)" ]\n"
"   std %d14, [%g7 + "VG_STRINGIFY(F14)" ]\n"
"   std %d16, [%g7 + "VG_STRINGIFY(F16)" ]\n"
"   std %d18, [%g7 + "VG_STRINGIFY(F18)" ]\n"
"   std %d20, [%g7 + "VG_STRINGIFY(F20)" ]\n"
"   std %d22, [%g7 + "VG_STRINGIFY(F22)" ]\n"
"   std %d24, [%g7 + "VG_STRINGIFY(F24)" ]\n"
"   std %d26, [%g7 + "VG_STRINGIFY(F26)" ]\n"
"   std %d28, [%g7 + "VG_STRINGIFY(F28)" ]\n"
"   std %d30, [%g7 + "VG_STRINGIFY(F30)" ]\n"
"   std %d32, [%g7 + "VG_STRINGIFY(D32)" ]\n"
"   std %d34, [%g7 + "VG_STRINGIFY(D34)" ]\n"
"   std %d36, [%g7 + "VG_STRINGIFY(D36)" ]\n"
"   std %d38, [%g7 + "VG_STRINGIFY(D38)" ]\n"
"   std %d40, [%g7 + "VG_STRINGIFY(D40)" ]\n"
"   std %d42, [%g7 + "VG_STRINGIFY(D42)" ]\n"
"   std %d44, [%g7 + "VG_STRINGIFY(D44)" ]\n"
"   std %d46, [%g7 + "VG_STRINGIFY(D46)" ]\n"
"   std %d48, [%g7 + "VG_STRINGIFY(D48)" ]\n"
"   std %d50, [%g7 + "VG_STRINGIFY(D50)" ]\n"
"   std %d52, [%g7 + "VG_STRINGIFY(D52)" ]\n"
"   std %d54, [%g7 + "VG_STRINGIFY(D54)" ]\n"
"   std %d56, [%g7 + "VG_STRINGIFY(D56)" ]\n"
"   std %d58, [%g7 + "VG_STRINGIFY(D58)" ]\n"
"   std %d60, [%g7 + "VG_STRINGIFY(D60)" ]\n"
"   std %d62, [%g7 + "VG_STRINGIFY(D62)" ]\n"

/* Restore host %fp and %sp registers after unimplemented instruction. */
"   ldx [ %g7 + "VG_STRINGIFY(host_FP)" ], %fp \n"
"   ldx [ %g7 + "VG_STRINGIFY(host_SP)" ], %sp \n"

/* Save %o7 across calls so we can return from this function. */
"   mov %o7, %i5 \n"

/* Ancillary Registers: read into %i1-%i4, then call fxns to set guest state. */
"   rd  %asi, %i1 \n"
"   and %i1, 0xff, %i1 \n"
"   rd  %gsr, %i2 \n"
"   stx %fsr, [ %g7 + "VG_STRINGIFY(scratchpad)" ] \n" /* FSR scratchpad */
"   ldx [ %g7 + "VG_STRINGIFY(scratchpad)" ], %i3 \n"
"   rd  %ccr, %i4 \n"

/* Set ancillary registers in guest state. */
"   stx  %i1, [ %g7 + "VG_STRINGIFY(ASI)" ] \n"
"   mov %i2, %o0 \n"
"   mov %g7, %o1 \n"
"   call LibVEX_GuestSPARC64_put_gsr \n"
"   nop \n"
"   mov %i3, %o0 \n"
"   mov %g7, %o1 \n"
"   call LibVEX_GuestSPARC64_put_fsr \n"
"   nop \n"
"   mov %i4, %o0 \n"
"   mov %g7, %o1 \n"
"   call LibVEX_GuestSPARC64_put_ccr \n"
"   nop \n"

/* %g7 holds the guest state pointer across unrecognized instruction. */
"   mov  %g7, %g5 \n"

/* Restore return register after calls */
"   mov %i5, %o7 \n"

"   retl \n"
"   nop \n"
".size LibVEX_GuestSPARC64_StoreGuestRegisters, .-LibVEX_GuestSPARC64_StoreGuestRegisters\n"
".previous\n"
);

#undef VG_STRINGIFZ
#undef VG_STRINGIFX
#undef VG_STRINGIFY

#define unop(_op, _a1) IRExpr_Unop((_op), (_a1))
#define binop(_op, _a1, _a2) IRExpr_Binop((_op), (_a1), (_a2))
#define mkU64(_n) IRExpr_Const(IRConst_U64(_n))
#define mkU8(_n) IRExpr_Const(IRConst_U8(_n))

static Bool
isU64(IRExpr *e, ULong n)
{
    return toBool(e->tag == Iex_Const &&
                  e->Iex.Const.con->tag == Ico_U64 &&
                  e->Iex.Const.con->Ico.U64 == n);
}

static IRExpr*
mk_icond_bit_test(IRExpr *cc_dep1, ULong shift, ULong expected)
{
    IRExpr *masked = binop(Iop_And64, binop(Iop_Shr64, cc_dep1, mkU8(shift)),
                                      mkU64(1));
    return unop(Iop_1Uto64, binop(Iop_CmpEQ64, masked, mkU64(expected)));
}

IRExpr *
guest_sparc64_spechelper(const HChar *function_name,
                         IRExpr      **args,
                         IRStmt      **precedingStmts,
                         Int         n_precedingStmts)
{
    Int i, arity = 0;

    for (i = 0; args[i] != NULL; i++)
        arity++;

    /* --------- specialising "sparc64_calculate_ICond" --------- */
    if (vex_streq(function_name, "sparc64_calculate_ICond")) {
        vassert(arity == 5);
        IRExpr *cond    = args[0];
        IRExpr *cc_op   = args[1];
        IRExpr *cc_dep1 = args[2];
        IRExpr *cc_dep2 = args[3];
        IRExpr *cc_ndep = args[4];

        /* Branch always/never does not need to call helper. */
        if (isU64(cond, SPARC64_ICOND_A_ICC) ||
            isU64(cond, SPARC64_ICOND_A_XCC)) {
            return IRExpr_Const(IRConst_U64(1));
        }
        if (isU64(cond, SPARC64_ICOND_N_ICC) ||
            isU64(cond, SPARC64_ICOND_N_XCC)) {
            return IRExpr_Const(IRConst_U64(0));
        }

        if (isU64(cc_op, SPARC64_CC_OP_COPY)) {
            /* COPY, then E --> extract Z from dep1, and test (Z == 1). */
            if (isU64(cond, SPARC64_ICOND_E_ICC)) {
                return mk_icond_bit_test(cc_dep1, SPARC64_CCR_SHIFT_I_Z, 1);
            } else if (isU64(cond, SPARC64_ICOND_E_XCC)) {
                return mk_icond_bit_test(cc_dep1, SPARC64_CCR_SHIFT_X_Z, 1);

            /* COPY, then NE --> extract Z from dep1, and test (Z == 0). */
            } else if (isU64(cond, SPARC64_ICOND_NE_ICC)) {
                return mk_icond_bit_test(cc_dep1, SPARC64_CCR_SHIFT_I_Z, 0);
            } else if (isU64(cond, SPARC64_ICOND_NE_XCC)) {
                return mk_icond_bit_test(cc_dep1, SPARC64_CCR_SHIFT_X_Z, 0);
            }
        } else if (isU64(cc_op, SPARC64_CC_OP_LOGIC)) {
            if (isU64(cond, SPARC64_ICOND_E_XCC)) {
                /* and/or/xor, then E --> test result == 0 */
                return unop(Iop_1Uto64, binop(Iop_CmpEQ64, cc_dep1, mkU64(0)));
            } else if (isU64(cond, SPARC64_ICOND_NE_XCC)) {
                /* and/or/xor, then NE --> test result != 0 */
                return unop(Iop_1Uto64, binop(Iop_CmpNE64, cc_dep1, mkU64(0)));
            }
        } else if (isU64(cc_op, SPARC64_CC_OP_ADD)) {
            if (isU64(cond, SPARC64_ICOND_E_XCC)) {
                /* add, then E --> test (argL + argR == 0) */
                return unop(Iop_1Uto64,
                            binop(Iop_CmpEQ64,
                                  binop(Iop_Add64, cc_dep1, cc_dep2),
                                  mkU64(0)));
            }
        } else if (isU64(cc_op, SPARC64_CC_OP_SUB)) {
            if (isU64(cond, SPARC64_ICOND_E_XCC)) {
                /* sub/cmp, then E --> test arL == argR */
                return unop(Iop_1Uto64, binop(Iop_CmpEQ64, cc_dep1, cc_dep2));
            } else if (isU64(cond, SPARC64_ICOND_NE_XCC)) {
                /* sub/cmp, then NE --> test argL != argR */
                return unop(Iop_1Uto64, binop(Iop_CmpNE64, cc_dep1, cc_dep2));
            }
        }

        /* TODO-SPARC: other specialisations */
    } else if (vex_streq(function_name, "sparc64_calculate_FCond_from_FSR")) {
    /* --------- specialising "sparc64_calculate_FCond_from_FSR" --------- */
        vassert(arity == 3);
        IRExpr *cond = args[0];

        /* Branch always/never does not need to call helper. */
        if (isU64(cond, SPARC64_FCOND_A)) {
            return (IRExpr_Const(IRConst_U64(1)));
        }

        if (isU64(cond, SPARC64_FCOND_N)) {
            return (IRExpr_Const(IRConst_U64(0)));
        }

        /* TODO-SPARC: other specialisations */
    }

    return (NULL);
}
#undef unop
#undef binop
#undef mkU64
#undef mkU8

/* Figure out if any part of the guest state contained in minoff..maxoff
   requires precise memory exceptions. If in doubt return True
   (but this generates significantly slower code).

   By default we enforce precise memory exceptions for guest %sp (%o6),
   %fp (%i6) and %pc only.  These are the minimum needed to extract correct
   stack backtraces.

   Only %sp (%o6) is needed in mode VexRegUpdSpAtMemAccess.
*/
Bool
guest_sparc64_state_requires_precise_mem_exns(Int minoff, Int maxoff,
                                              VexRegisterUpdates pxControl)
{
    UInt sp_min = offsetof(VexGuestSPARC64State, guest_R14);
    UInt sp_max = sp_min + 8 - 1;
    UInt fp_min = offsetof(VexGuestSPARC64State, guest_R30);
    UInt fp_max = fp_min + 8 - 1;
    UInt pc_min = offsetof(VexGuestSPARC64State, guest_PC);
    UInt pc_max = pc_min + 8 - 1;

    if ((maxoff < sp_min) || (minoff > sp_max)) {
        /* No overlap with %sp (%o6). */
        if (pxControl == VexRegUpdSpAtMemAccess)
            return False; /* We only need to check stack pointer. */
    } else {
        return True;
    }

    if ((maxoff < fp_min) || (minoff > fp_max)) {
        /* No overlap with %fp (%i6). */
    } else {
        return True;
    }

    if ((maxoff < pc_min) || (minoff > pc_max)) {
        /* No overlap with %pc. */
    } else {
        return True;
    }

    return False;
}

#define ALWAYSDEFD(field) {                        \
    offsetof(VexGuestSPARC64State, field),         \
    (sizeof((VexGuestSPARC64State *) NULL)->field) \
}

VexGuestLayout sparc64Guest_layout = {
    /* Total size of the guest state, in bytes. */
    .total_sizeB = sizeof(VexGuestSPARC64State),

    /* Describe the stack pointer. */
    .offset_SP = offsetof(VexGuestSPARC64State, guest_R14), /* %o6 / %sp */
    .sizeof_SP = 8,

    /* Describe the frame pointer. */
    .offset_FP = offsetof(VexGuestSPARC64State, guest_R30), /* %i6 / %fp */
    .sizeof_FP = 8,

    /* Describe the instruction pointer. */
    .offset_IP = offsetof(VexGuestSPARC64State, guest_PC),
    .sizeof_IP = 8,

    /* Describe any sections to be regarded by Memcheck as 'always-defined'. */
    .n_alwaysDefd = 5,
    .alwaysDefd = {
        /* 0 */ ALWAYSDEFD(guest_CC_OP),
        /* 1 */ ALWAYSDEFD(guest_CC_NDEP),
        /* 2 */ ALWAYSDEFD(guest_FSR_CEXC_OP),
        /* 3 */ ALWAYSDEFD(guest_FSR_CEXC_NDEP),
        /* 4 */ ALWAYSDEFD(guest_PC)
    }
};

/* CALLED FROM GENERATED CODE: CLEAN HELPER */
/* Calculate CCR based on passed arguments. */
ULong
sparc64_calculate_CCR(ULong cc_op, ULong cc_dep1, ULong cc_dep2, ULong cc_ndep)
{
    ULong x_n, x_z, x_v, x_c;
    ULong i_n, i_z, i_v, i_c;
    ULong res, tmp, argR;

    x_n = x_z = x_v = x_c = 0;
    i_n = i_z = i_v = i_c = 0;

    switch (cc_op) {
    /* Return copy of CCR and zero unused bits. */
    case SPARC64_CC_OP_COPY:
        return (cc_dep1 & 0xff);

    /* Logical instructions */
    case SPARC64_CC_OP_LOGIC:
        i_n = (cc_dep1 & 0x80000000) ? 1 : 0;
        x_n = (cc_dep1 & 0x8000000000000000ULL) ? 1 : 0;
        i_z = ((UInt) cc_dep1 == 0) ? 1 : 0;
        x_z = (cc_dep1 == 0) ? 1 : 0;
        break;

    /* Arithmetic instructions */
    case SPARC64_CC_OP_ADD:
        res = cc_dep1 + cc_dep2;
        tmp = ~(cc_dep1 ^ cc_dep2) & (cc_dep1 ^ res);

        i_c = ((UInt)cc_dep1 > 0xffffffff - (UInt)cc_dep2) ? 1 : 0;
        x_c = (cc_dep1 > 0xffffffffffffffffULL - cc_dep2) ? 1 : 0;
        i_v = (tmp & 0x80000000) ? 1 : 0;
        x_v = (tmp & 0x8000000000000000ULL) ? 1 : 0;
        i_n = ((Int) res < 0) ? 1 : 0;
        x_n = ((Long) res < 0) ? 1 : 0;
        i_z = ((UInt) res == 0) ? 1 : 0;
        x_z = (res == 0) ? 1 : 0;
        break;

    case SPARC64_CC_OP_ADDC:
        /* First reconstruct argR from cc_dep2 and cc_ndep (old carry). */
        argR = cc_dep2 ^ cc_ndep;
        res = cc_dep1 + argR + cc_ndep;
        tmp = ~(cc_dep1 ^ cc_dep2) & (cc_dep1 ^ res);

        if (cc_ndep) {
            i_c = ((UInt)cc_dep1 >= 0xffffffff - (UInt)cc_dep2) ? 1 : 0;
            x_c = (cc_dep1 >= 0xffffffffffffffffULL - cc_dep2) ? 1 : 0;
        } else {
            i_c = ((UInt)cc_dep1 > 0xffffffff - (UInt)cc_dep2) ? 1 : 0;
            x_c = (cc_dep1 > 0xffffffffffffffffULL - cc_dep2) ? 1 : 0;
        }

        i_v = (tmp & 0x80000000) ? 1 : 0;
        x_v = (tmp & 0x8000000000000000ULL) ? 1 : 0;
        i_n = ((Int) res < 0) ? 1 : 0;
        x_n = ((Long) res < 0) ? 1 : 0;
        i_z = ((UInt) res == 0) ? 1 : 0;
        x_z = (res == 0) ? 1 : 0;
        break;

    case SPARC64_CC_OP_SDIV: {
        Long dividend = (Long) cc_dep1;
        Int divisor = (Int) cc_dep2;
        Long signed_result = dividend / divisor;

        if (signed_result >= 0x80000000) {
            signed_result = 0x000000007FFFFFFFULL;
            i_v = 1;
        } else if (signed_result <= -0x7FFFFFFF) {
            signed_result = 0xFFFFFFFF80000000ULL;
            i_v = 1;
        } else {
            i_v = 0;
        }

        i_c = 0;
        x_c = 0;
        x_v = 0;
        i_n = (signed_result & 0x0000000080000000ULL) ? 1 : 0;
        x_n = (signed_result & 0x8000000000000000ULL) ? 1 : 0;
        i_z = ((UInt) signed_result == 0) ? 1 : 0;
        x_z = (signed_result == 0) ? 1 : 0;

        break;
    }

    case SPARC64_CC_OP_SMUL:
        cc_dep1 = (Int) cc_dep1;
        cc_dep2 = (Int) cc_dep2;
        res = cc_dep1 * cc_dep2;

        i_c = 0;
        x_c = 0;
        i_v = 0;
        x_v = 0;
        i_n = (res & 0x0000000080000000ULL) ? 1 : 0;
        x_n = (res & 0x8000000000000000ULL) ? 1 : 0;
        i_z = ((UInt) res == 0) ? 1 : 0;
        x_z = (res == 0) ? 1 : 0;
        break;

    case SPARC64_CC_OP_SUB:
        res = cc_dep1 - cc_dep2;
        tmp = (cc_dep1 ^ cc_dep2) & (cc_dep1 ^ res);

        i_c = ((UInt) cc_dep1 < (UInt) cc_dep2) ? 1 : 0;
        x_c = (cc_dep1 < cc_dep2) ? 1 : 0;
        i_v = (tmp & 0x80000000) ? 1 : 0;
        x_v = (tmp & 0x8000000000000000ULL) ? 1 : 0;
        i_n = ((Int) res < 0) ? 1 : 0;
        x_n = ((Long) res < 0) ? 1 : 0;
        i_z = ((UInt) res == 0) ? 1 : 0;
        x_z = (res == 0) ? 1 : 0;
        break;

    case SPARC64_CC_OP_SUBC:
        /* First reconstruct argR from cc_dep2 and cc_ndep (old carry). */
        argR = cc_dep2 ^ cc_ndep;
        res = cc_dep1 - argR - cc_ndep;
        tmp = (cc_dep1 ^ cc_dep2) & (cc_dep1 ^ res);

        if (cc_ndep) {
            i_c = ((UInt) cc_dep1 <= (UInt) argR) ? 1 : 0;
            x_c = (cc_dep1 <= argR) ? 1 : 0;
        } else {
            i_c = ((UInt) cc_dep1 < (UInt) argR) ? 1 : 0;
            x_c = (cc_dep1 < argR) ? 1 : 0;
        }
        i_v = (tmp & 0x80000000) ? 1 : 0;
        x_v = (tmp & 0x8000000000000000ULL) ? 1 : 0;
        i_n = ((Int) res < 0) ? 1 : 0;
        x_n = ((Long) res < 0) ? 1 : 0;
        i_z = ((UInt) res == 0) ? 1 : 0;
        x_z = (res == 0) ? 1 : 0;
        break;

    case SPARC64_CC_OP_UDIV:
        cc_dep2 = (UInt) cc_dep2;
        res = cc_dep1 / cc_dep2;

        if (res > 0xFFFFFFFF) {
            res = 0x00000000FFFFFFFFULL;
            i_v = 1;
        } else {
            i_v = 0;
        }

        i_c = 0;
        x_c = 0;
        x_v = 0;
        i_n = (res & 0x0000000080000000ULL) ? 1 : 0;
        x_n = (res & 0x8000000000000000ULL) ? 1 : 0;
        i_z = ((UInt) res == 0) ? 1 : 0;
        x_z = (res == 0) ? 1 : 0;
        break;

    case SPARC64_CC_OP_UMUL:
        cc_dep1 = (UInt) cc_dep1;
        cc_dep2 = (UInt) cc_dep2;
        res = cc_dep1 * cc_dep2;

        i_c = 0;
        x_c = 0;
        i_v = 0;
        x_v = 0;
        i_n = (res & 0x0000000080000000ULL) ? 1 : 0;
        x_n = (res & 0x8000000000000000ULL) ? 1 : 0;
        i_z = ((UInt) res == 0) ? 1 : 0;
        x_z = (res == 0) ? 1 : 0;
        break;

    default:
        vex_printf("sparc64_calculate_CCR(%llu, 0x%llx, 0x%llx, 0x%llx)\n",
            cc_op, cc_dep1, cc_dep2, cc_ndep);
        vpanic("sparc64_calculate_CCR");
    }

    return ((x_n << SPARC64_CCR_SHIFT_X_N) |
            (x_z << SPARC64_CCR_SHIFT_X_Z) |
            (x_v << SPARC64_CCR_SHIFT_X_V) |
            (x_c << SPARC64_CCR_SHIFT_X_C) |
            (i_n << SPARC64_CCR_SHIFT_I_N) |
            (i_z << SPARC64_CCR_SHIFT_I_Z) |
            (i_v << SPARC64_CCR_SHIFT_I_V) |
            (i_c << SPARC64_CCR_SHIFT_I_C));

}

/* CALLED FROM GENERATED CODE: CLEAN HELPER */
/* Returns 0 or 1. */
ULong
sparc64_calculate_ICond(ULong cond, ULong cc_op, ULong cc_dep1, ULong cc_dep2,
                        ULong cc_ndep)
{
    if (0)
        vex_printf("sparc64_calculate_COND(%llu,%llu,%llx,%llx,%llx)\n", cond, cc_op, cc_dep1,
            cc_dep2, cc_ndep);

    ULong ccr = sparc64_calculate_CCR(cc_op, cc_dep1, cc_dep2, cc_ndep);
    ULong z, c, n, v;

    if (0)
        vex_printf("CCR: 0x%llx\n", ccr);

    /* xcc cond always ends with 1 */
    if (cond & 1) {
        z = ccr >> SPARC64_CCR_SHIFT_X_Z & 1;
        c = ccr >> SPARC64_CCR_SHIFT_X_C & 1;
        n = ccr >> SPARC64_CCR_SHIFT_X_N & 1;
        v = ccr >> SPARC64_CCR_SHIFT_X_V & 1;
    } else {
        z = ccr >> SPARC64_CCR_SHIFT_I_Z & 1;
        c = ccr >> SPARC64_CCR_SHIFT_I_C & 1;
        n = ccr >> SPARC64_CCR_SHIFT_I_N & 1;
        v = ccr >> SPARC64_CCR_SHIFT_I_V & 1;
    }

    if (0)
        vex_printf("CCR(z,c,n,v): %llu, %llu, %llu, %llu\n", z, c, n, v);

    /* evaluate condition */
    switch (cond) {

    /* always */
    case SPARC64_ICOND_A_ICC:
    case SPARC64_ICOND_A_XCC:
        return (1);

    /* never */
    case SPARC64_ICOND_N_ICC:
    case SPARC64_ICOND_N_XCC:
        return (0);

    /* not Z */
    case SPARC64_ICOND_NE_ICC:
    case SPARC64_ICOND_NE_XCC:
        return (1 ^ z);
    /* Z */
    case SPARC64_ICOND_E_ICC:
    case SPARC64_ICOND_E_XCC:
        return (z);
    /* not (Z or (N xor V)) */
    case SPARC64_ICOND_G_ICC:
    case SPARC64_ICOND_G_XCC:
        return (1 ^ (z | (n ^ v)));
    /* Z or (N xor V) */
    case SPARC64_ICOND_LE_ICC:
    case SPARC64_ICOND_LE_XCC:
        return (z | (n ^ v));
    /* not (N xor V) */
    case SPARC64_ICOND_GE_ICC:
    case SPARC64_ICOND_GE_XCC:
        return (1 ^ (n ^ v));
    /* N xor V */
    case SPARC64_ICOND_L_ICC:
    case SPARC64_ICOND_L_XCC:
        return (n ^ v);
    /* not (C or Z) */
    case SPARC64_ICOND_GU_ICC:
    case SPARC64_ICOND_GU_XCC:
        return (1 ^ (c | z));
    /* C or Z */
    case SPARC64_ICOND_LEU_ICC:
    case SPARC64_ICOND_LEU_XCC:
        return (c | z);
    /* not C */
    case SPARC64_ICOND_CC_ICC:
    case SPARC64_ICOND_CC_XCC:
        return (1 ^ c);
    /* C */
    case SPARC64_ICOND_CS_ICC:
    case SPARC64_ICOND_CS_XCC:
        return (c);
    /* not N */
    case SPARC64_ICOND_POS_ICC:
    case SPARC64_ICOND_POS_XCC:
        return (1 ^ n);
    /* N */
    case SPARC64_ICOND_NEG_ICC:
    case SPARC64_ICOND_NEG_XCC:
        return (n);
    /* not V */
    case SPARC64_ICOND_VC_ICC:
    case SPARC64_ICOND_VC_XCC:
        return (1 ^ v);
    /* V */
    case SPARC64_ICOND_VS_ICC:
    case SPARC64_ICOND_VS_XCC:
        return (v);

    default:
        vpanic("Unsupported ICOND.");
    }
}

/* CALLED FROM GENERATED CODE: CLEAN HELPER */
/* Returns value of asr_reg. */
ULong
sparc64_helper_rd(ULong asr_reg) {
    ULong res = 0;

    switch (asr_reg) {
#if defined(VGA_sparc64)
    case SPARC64_ASR_TICK:
        __asm__ __volatile__ ("rd %%tick, %0" : "=r" (res) :: );
        break;
    case SPARC64_ASR_STICK:
        __asm__ __volatile__ ("rd %%stick, %0" : "=r" (res) :: );
        break;
#endif /* VGA_sparc64 */
    default:
        vex_printf("ASR register %llu\n", asr_reg);
        vpanic("sparc64_helper_rd() - unsupported ASR reg.");
    }

    return (res);
}

/* Gets FSR.ver by querying native %fsr.
   Returned value is ready to be ORed to other FSR fields. */
static ULong
get_FSR_ver(void)
{
    ULong fsr_hw;
#if defined(VGA_sparc64)
    __asm__ __volatile__(
        "stx %%fsr, %[fsr_hw]\n"
        : [fsr_hw] "=m" (fsr_hw)
        :
        : "memory");
#else
    fsr_hw = 0;
#endif /* VGA_sparc64 */
    return fsr_hw & SPARC64_FSR_MASK_VER;
}

#if defined(VGA_sparc64)
/* Converts rounding from IRRoundingMode representation to native sparc64.
   Returned value is suitable to be ORed with other components of FSR. */
static ULong
sparc64_convert_IR_rd(ULong ir_rd)
{
    ULong rd;

    switch (ir_rd) {
    case Irrm_NEAREST:
        rd = 0; break;
    case Irrm_NegINF:
        rd = 3; break;
    case Irrm_PosINF:
        rd = 2; break;
    case Irrm_ZERO:
        rd = 1; break;
    default:
        vex_printf("sparc64_convert_IR_rd(%llu)\n", ir_rd);
        vassert(0);
    }

    return rd << SPARC64_FSR_SHIFT_RD;
}
#endif /* VGA_sparc64 */

#define CEXC_FROM_UNARY(opcode, dep1_lo, op_load,                   \
                        srcR, dst, clobber1, clobber2)              \
{                                                                   \
    ULong fsr_orig;                                                 \
    __asm__ __volatile__ (                                          \
        "stx %%fsr, %[fsr_orig]\n"                                  \
        op_load " %[dep1], %" srcR "\n"                             \
        opcode " %" srcR ", %" dst "\n"                             \
        "stx %%fsr, %[fsr_out]\n"                                   \
        "ldx %[fsr_orig], %%fsr\n"                                  \
        : [fsr_orig] "=m" (fsr_orig), [fsr_out] "=m" (fsr_cexc_out) \
        : [dep1] "m" (dep1_lo)                                      \
        : clobber1, clobber2, "memory");                            \
}

#define CEXC_FROM_UNARY_128(opcode, _dep1_hi, _dep1_lo, dst, clobber) \
{                                                                     \
    ULong fsr_orig;                                                   \
    __asm__ __volatile__ (                                            \
        "stx %%fsr, %[fsr_orig]\n"                                    \
        "ldd %[dep1_hi], %%d52\n"                                     \
        "ldd %[dep1_lo], %%d54\n"                                     \
        opcode " %%q52, %" dst "\n"                                   \
        "stx %%fsr, %[fsr_out]\n"                                     \
        "ldx %[fsr_orig], %%fsr\n"                                    \
        : [fsr_orig] "=m" (fsr_orig), [fsr_out] "=m" (fsr_cexc_out)   \
        : [dep1_hi] "m" (_dep1_hi), [dep1_lo] "m" (_dep1_lo)          \
        : "%f52", clobber, "memory");                                 \
}

#define CEXC_FROM_UNARY_RD(opcode, dep1_lo, ndep, op_load,          \
                           srcR, dst, clobber1, clobber2)           \
{                                                                   \
    ULong fsr_orig;                                                 \
    ULong fsr_rd = sparc64_convert_IR_rd(ndep);                     \
    __asm__ __volatile__ (                                          \
        "stx %%fsr, %[fsr_orig]\n"                                  \
        op_load " %[dep1], %" srcR "\n"                             \
        "ldx %[fsr_rd], %%fsr\n"                                    \
        opcode " %" srcR ", %" dst "\n"                             \
        "stx %%fsr, %[fsr_out]\n"                                   \
        "ldx %[fsr_orig], %%fsr\n"                                  \
        : [fsr_orig] "=m" (fsr_orig), [fsr_out] "=m" (fsr_cexc_out) \
        : [dep1] "m" (dep1_lo), [fsr_rd] "m" (fsr_rd)               \
        : clobber1, clobber2, "memory");                            \
}

#define CEXC_FROM_UNARY_128_RD(opcode, _dep1_hi, _dep1_lo, ndep,    \
                               dst, clobber)                        \
{                                                                   \
    ULong fsr_orig;                                                 \
    ULong fsr_rd = sparc64_convert_IR_rd(ndep);                     \
    __asm__ __volatile__ (                                          \
        "stx %%fsr, %[fsr_orig]\n"                                  \
        "ldd %[dep1_hi], %%d52\n"                                   \
        "ldd %[dep1_lo], %%d54\n"                                   \
        "ldx %[fsr_rd], %%fsr\n"                                    \
        opcode " %%q52, %" dst "\n"                                 \
        "stx %%fsr, %[fsr_out]\n"                                   \
        "ldx %[fsr_orig], %%fsr\n"                                  \
        : [fsr_orig] "=m" (fsr_orig), [fsr_out] "=m" (fsr_cexc_out) \
        : [dep1_hi] "m" (_dep1_hi), [dep1_lo] "m" (_dep1_lo),       \
          [fsr_rd] "m" (fsr_rd)                                     \
        : "%f52", clobber, "memory");                               \
}

#define CEXC_FROM_BINARY(opcode, dep1_lo, dep2_lo, op_load,             \
                         srcL, srcR, dst, clobber1, clobber2, clobber3) \
{                                                                       \
    ULong fsr_orig;                                                     \
    __asm__ __volatile__ (                                              \
        "stx %%fsr, %[fsr_orig]\n"                                      \
        op_load " %[dep1], %" srcL "\n"                                 \
        op_load " %[dep2], %" srcR "\n"                                 \
        opcode " %" srcL ", %" srcR ", %" dst "\n"                      \
        "stx %%fsr, %[fsr_out]\n"                                       \
        "ldx %[fsr_orig], %%fsr\n"                                      \
        : [fsr_orig] "=m" (fsr_orig), [fsr_out] "=m" (fsr_cexc_out)     \
        : [dep1] "m" (dep1_lo), [dep2] "m" (dep2_lo)                    \
        : clobber1, clobber2, clobber3, "memory");                      \
}

#define CEXC_FROM_BINARY_32(opcode, dep1_lo, dep2_lo)                \
    CEXC_FROM_BINARY(opcode, dep1_lo, dep2_lo, "ld",                 \
                     "%f26", "%f27", "%f28", "%f26", "%f27", "%f28")

#define CEXC_FROM_BINARY_64(opcode, dep1_lo, dep2_lo)                \
    CEXC_FROM_BINARY(opcode, dep1_lo, dep2_lo, "ldd",                \
                     "%d56", "%d58", "%d60", "%f56", "%f58", "%f60")

#define CEXC_FROM_BINARY_RD(opcode, dep1_lo, dep2_lo, ndep, op_load,       \
                            srcL, srcR, dst, clobber1, clobber2, clobber3) \
{                                                                          \
    ULong fsr_orig;                                                        \
    ULong fsr_rd = sparc64_convert_IR_rd(ndep);                            \
    __asm__ __volatile__ (                                                 \
        "stx %%fsr, %[fsr_orig]\n"                                         \
        op_load " %[dep1], %" srcL "\n"                                    \
        op_load " %[dep2], %" srcR "\n"                                    \
        "ldx %[fsr_rd], %%fsr\n"                                           \
        opcode " %" srcL ", %" srcR ", %" dst "\n"                         \
        "stx %%fsr, %[fsr_out]\n"                                          \
        "ldx %[fsr_orig], %%fsr\n"                                         \
        : [fsr_orig] "=m" (fsr_orig), [fsr_out] "=m" (fsr_cexc_out)        \
        : [dep1] "m" (dep1_lo), [dep2] "m" (dep2_lo),                      \
          [fsr_rd] "m" (fsr_rd)                                            \
        : clobber1, clobber2, clobber3, "memory");                         \
}

#define CEXC_FROM_BINARY_32_RD(opcode, dep1_lo, dep2_lo, ndep)             \
    CEXC_FROM_BINARY_RD(opcode, dep1_lo, dep2_lo, ndep, "ld",              \
                        "%f29", "%f30", "%f31", "%f29", "%f30", "%f31")

#define CEXC_FROM_BINARY_64_RD(opcode, dep1_lo, dep2_lo, ndep)             \
    CEXC_FROM_BINARY_RD(opcode, dep1_lo, dep2_lo, ndep, "ldd",             \
                        "%d58", "%d60", "%d62", "%f58", "%f60", "%f62")

#define CEXC_FROM_BINARY_128_RD(opcode, _dep1_hi, _dep1_lo,         \
                                _dep2_hi, _dep2_lo, ndep)           \
{                                                                   \
    ULong fsr_orig;                                                 \
    ULong fsr_rd = sparc64_convert_IR_rd(ndep);                     \
    __asm__ __volatile__ (                                          \
        "stx %%fsr, %[fsr_orig]\n"                                  \
        "ldd %[dep1_hi], %%d52\n"                                   \
        "ldd %[dep1_lo], %%d54\n"                                   \
        "ldd %[dep2_hi], %%d56\n"                                   \
        "ldd %[dep2_lo], %%d58\n"                                   \
        "ldx %[fsr_rd], %%fsr\n"                                    \
        opcode " %%q52, %%q56, %%q60\n"                             \
        "stx %%fsr, %[fsr_out]\n"                                   \
        "ldx %[fsr_orig], %%fsr\n"                                  \
        : [fsr_orig] "=m" (fsr_orig), [fsr_out] "=m" (fsr_cexc_out) \
        : [dep1_hi] "m" (_dep1_hi), [dep1_lo] "m" (_dep1_lo),       \
          [dep2_hi] "m" (_dep2_hi), [dep2_lo] "m" (_dep2_lo),       \
          [fsr_rd] "m" (fsr_rd)                                     \
        : "%f52", "%f56", "%f60", "memory");                        \
}

#define CEXC_FROM_TERNARY_RD(opcode, dep1, dep2, dep3, ndep, op_load, \
                             frs1, frs2, frs3, frd,                   \
                             clobber1, clobber2, clobber3, clobber4)  \
{                                                                     \
    ULong fsr_orig;                                                   \
    ULong fsr_rd = sparc64_convert_IR_rd(ndep);                       \
    __asm__ __volatile__ (                                            \
        "stx %%fsr, %[fsr_orig]\n"                                    \
        op_load " %[arg1], %" frs1 "\n"                               \
        op_load " %[arg2], %" frs2 "\n"                               \
        op_load " %[arg3], %" frs3 "\n"                               \
        "ldx %[fsr_rd], %%fsr\n"                                      \
        opcode " %" frs1 ", %" frs2 ", %" frs3 ", %" frd "\n"         \
        "stx %%fsr, %[fsr_out]\n"                                     \
        "ldx %[fsr_orig], %%fsr\n"                                    \
        : [fsr_orig] "=m" (fsr_orig), [fsr_out] "=m" (fsr_cexc_out)   \
        : [arg1] "m" (dep1), [arg2] "m" (dep2), [arg3] "m" (dep3),    \
          [fsr_rd] "m" (fsr_rd)                                       \
        : clobber1, clobber2, clobber3, clobber4, "memory");          \
}

#define CEXC_FROM_TERNARY_32_RD(opcode, dep1, dep2, dep3, ndep)       \
    CEXC_FROM_TERNARY_RD(opcode, dep1, dep2, dep3, ndep, "ld",        \
                        "%f28", "%f29", "%f30", "%f31",               \
                        "%f28", "%f29", "%f30", "%f31")

#define CEXC_FROM_TERNARY_64_RD(opcode, dep1, dep2, dep3, ndep)       \
    CEXC_FROM_TERNARY_RD(opcode, dep1, dep2, dep3, ndep, "ldd",       \
                         "%d56", "%d58", "%d60", "%d62",              \
                         "%f56", "%f58", "%f60", "%f62")

#define CEXC_FROM_FCMP(opcode, dep1_lo, dep2_lo, op_load,           \
                       srcL, srcR, clobber1, clobber2)              \
{                                                                   \
    ULong fsr_orig;                                                 \
    __asm__ __volatile__ (                                          \
        "stx %%fsr, %[fsr_orig]\n"                                  \
        op_load " %[dep1], %" srcL "\n"                             \
        op_load " %[dep2], %" srcR "\n"                             \
        opcode " %%fcc0, %" srcL ", %" srcR "\n"                    \
        "stx %%fsr, %[fsr_out]\n"                                   \
        "ldx %[fsr_orig], %%fsr\n"                                  \
        : [fsr_orig] "=m" (fsr_orig), [fsr_out] "=m" (fsr_cexc_out) \
        : [dep1] "m" (dep1_lo), [dep2] "m" (dep2_lo)                \
        : clobber1, clobber2, "memory");                            \
}

#define CEXC_FROM_FCMP_32(opcode, dep1_lo, dep2_lo) \
    CEXC_FROM_FCMP(opcode, dep1_lo, dep2_lo, "ld",  \
                   "%f29", "%f30", "%f29", "%f30")

#define CEXC_FROM_FCMP_64(opcode, dep1_lo, dep2_lo) \
    CEXC_FROM_FCMP(opcode, dep1_lo, dep2_lo, "ldd", \
                   "%d58", "%d60", "%f58", "%f60")


#define CEXC_FROM_FCMP_128(opcode, _dep1_hi, _dep1_lo,              \
                           _dep2_hi, _dep2_lo)                      \
{                                                                   \
    ULong fsr_orig;                                                 \
    __asm__ __volatile__ (                                          \
        "stx %%fsr, %[fsr_orig]\n"                                  \
        "ldd %[dep1_hi], %%d52\n"                                   \
        "ldd %[dep1_lo], %%d54\n"                                   \
        "ldd %[dep2_hi], %%d56\n"                                   \
        "ldd %[dep2_lo], %%d58\n"                                   \
        opcode " %%fcc0, %%q52, %%q56\n"                            \
        "stx %%fsr, %[fsr_out]\n"                                   \
        "ldx %[fsr_orig], %%fsr\n"                                  \
        : [fsr_orig] "=m" (fsr_orig), [fsr_out] "=m" (fsr_cexc_out) \
        : [dep1_hi] "m" (_dep1_hi), [dep1_lo] "m" (_dep1_lo),       \
          [dep2_hi] "m" (_dep2_hi), [dep2_lo] "m" (_dep2_lo)        \
        : "%f52", "%f56", "memory");                                \
}

/* Calculates FSR.cexc. */
static ULong
sparc64_calculate_FSR_cexc(SPARC64_FSR_CEXC_OP fsr_cexc_op,
                           ULong fsr_cexc_dep1_hi, ULong fsr_cexc_dep1_lo,
                           ULong fsr_cexc_dep2_hi, ULong fsr_cexc_dep2_lo,
                           ULong fsr_cexc_ndep)
{
    ULong fsr_cexc_out;

    /* TODO-SPARC: Investigate possibility of using function arguments
       directly in inline assembly. */
    switch (fsr_cexc_op) {
#if defined(VGA_sparc64)
    case SPARC64_FSR_CEXC_OP_COPY:
        fsr_cexc_out = fsr_cexc_dep1_lo;
        break;
    case SPARC64_FSR_CEXC_OP_F32TOF64:
        CEXC_FROM_UNARY("fstod", fsr_cexc_dep1_lo,
                        "ld", "%f30", "%d62", "%f30", "%f62");
        break;
    case SPARC64_FSR_CEXC_OP_F32TOF128:
        CEXC_FROM_UNARY("fstoq", fsr_cexc_dep1_lo,
                        "ld", "%f30", "%q60", "%f30", "%f60");
        break;
    case SPARC64_FSR_CEXC_OP_F64TOF32:
        CEXC_FROM_UNARY_RD("fdtos", fsr_cexc_dep1_lo, fsr_cexc_ndep,
                           "ldd", "%d60", "%f31", "%f60", "%f31");
        break;
    case SPARC64_FSR_CEXC_OP_F64TOF128:
        CEXC_FROM_UNARY("fdtoq", fsr_cexc_dep1_lo,
                        "ldd", "%d56", "%q60", "%f56", "%f60");
        break;
    case SPARC64_FSR_CEXC_OP_F128TOF32:
        CEXC_FROM_UNARY_128_RD("fqtos", fsr_cexc_dep1_hi, fsr_cexc_dep1_lo,
                               fsr_cexc_ndep, "%f31", "%f31");
        break;
    case SPARC64_FSR_CEXC_OP_F128TOF64:
        CEXC_FROM_UNARY_128_RD("fqtod", fsr_cexc_dep1_hi, fsr_cexc_dep1_lo,
                               fsr_cexc_ndep, "%d60", "%f60");
        break;
    case SPARC64_FSR_CEXC_OP_F32TOI32:
        CEXC_FROM_UNARY("fstoi", fsr_cexc_dep1_lo,
                        "ld", "%f30", "%f31", "%f30", "%f31");
        break;
    case SPARC64_FSR_CEXC_OP_F64TOI32:
        CEXC_FROM_UNARY("fdtoi", fsr_cexc_dep1_lo,
                        "ldd", "%d60", "%f31", "%f60", "%f31");
        break;
    case SPARC64_FSR_CEXC_OP_F32TOI64:
        CEXC_FROM_UNARY("fstox", fsr_cexc_dep1_lo,
                        "ld", "%f30", "%d62", "%f30", "%f62");
        break;
    case SPARC64_FSR_CEXC_OP_F64TOI64:
        CEXC_FROM_UNARY("fdtox", fsr_cexc_dep1_lo,
                        "ldd", "%d60", "%d62", "%f60", "%f62");
        break;
    case SPARC64_FSR_CEXC_OP_F128TOI32:
        CEXC_FROM_UNARY_128("fqtoi", fsr_cexc_dep1_hi, fsr_cexc_dep1_lo,
                            "%f31", "%f31");
        break;
    case SPARC64_FSR_CEXC_OP_F128TOI64:
        CEXC_FROM_UNARY_128("fqtox", fsr_cexc_dep1_hi, fsr_cexc_dep1_lo,
                            "%d60", "%f60");
        break;
    case SPARC64_FSR_CEXC_OP_FADD32:
        CEXC_FROM_BINARY_32_RD("fadds", fsr_cexc_dep1_lo,
                               fsr_cexc_dep2_lo, fsr_cexc_ndep);
        break;
    case SPARC64_FSR_CEXC_OP_FADD64:
        CEXC_FROM_BINARY_64_RD("faddd", fsr_cexc_dep1_lo,
                               fsr_cexc_dep2_lo, fsr_cexc_ndep);
        break;
    case SPARC64_FSR_CEXC_OP_FADD128:
        CEXC_FROM_BINARY_128_RD("faddq", fsr_cexc_dep1_hi, fsr_cexc_dep1_lo,
                                fsr_cexc_dep2_hi, fsr_cexc_dep2_lo,
                                fsr_cexc_ndep);
        break;
    case SPARC64_FSR_CEXC_OP_FCMP32:
        CEXC_FROM_FCMP_32("fcmps", fsr_cexc_dep1_lo, fsr_cexc_dep2_lo);
        break;
    case SPARC64_FSR_CEXC_OP_FCMP64:
        CEXC_FROM_FCMP_64("fcmpd", fsr_cexc_dep1_lo, fsr_cexc_dep2_lo);
        break;
    case SPARC64_FSR_CEXC_OP_FCMP128:
        CEXC_FROM_FCMP_128("fcmpq", fsr_cexc_dep1_hi, fsr_cexc_dep1_lo,
                           fsr_cexc_dep2_hi, fsr_cexc_dep2_lo);
        break;
    case SPARC64_FSR_CEXC_OP_FCMPE32:
        CEXC_FROM_FCMP_32("fcmpes", fsr_cexc_dep1_lo, fsr_cexc_dep2_lo);
        break;
    case SPARC64_FSR_CEXC_OP_FCMPE64:
        CEXC_FROM_FCMP_64("fcmped", fsr_cexc_dep1_lo, fsr_cexc_dep2_lo);
        break;
    case SPARC64_FSR_CEXC_OP_FCMPE128:
        CEXC_FROM_FCMP_128("fcmpeq", fsr_cexc_dep1_hi, fsr_cexc_dep1_lo,
                           fsr_cexc_dep2_hi, fsr_cexc_dep2_lo);
        break;
    case SPARC64_FSR_CEXC_OP_FDIV32:
        CEXC_FROM_BINARY_32_RD("fdivs", fsr_cexc_dep1_lo,
                               fsr_cexc_dep2_lo, fsr_cexc_ndep);
        break;
    case SPARC64_FSR_CEXC_OP_FDIV64:
        CEXC_FROM_BINARY_64_RD("fdivd", fsr_cexc_dep1_lo,
                               fsr_cexc_dep2_lo, fsr_cexc_ndep);
        break;
    case SPARC64_FSR_CEXC_OP_FDIV128:
        CEXC_FROM_BINARY_128_RD("fdivq", fsr_cexc_dep1_hi, fsr_cexc_dep1_lo,
                                fsr_cexc_dep2_hi, fsr_cexc_dep2_lo,
                                fsr_cexc_ndep);
        break;
    case SPARC64_FSR_CEXC_OP_FMUL32:
        CEXC_FROM_BINARY_32_RD("fmuls", fsr_cexc_dep1_lo,
                               fsr_cexc_dep2_lo, fsr_cexc_ndep);
        break;
    case SPARC64_FSR_CEXC_OP_FMUL64:
        CEXC_FROM_BINARY_64_RD("fmuld", fsr_cexc_dep1_lo,
                               fsr_cexc_dep2_lo, fsr_cexc_ndep);
        break;
    case SPARC64_FSR_CEXC_OP_FMUL128:
        CEXC_FROM_BINARY_128_RD("fmulq", fsr_cexc_dep1_hi, fsr_cexc_dep1_lo,
                                fsr_cexc_dep2_hi, fsr_cexc_dep2_lo,
                                fsr_cexc_ndep);
        break;
    case SPARC64_FSR_CEXC_OP_F32MUL64:
        CEXC_FROM_BINARY_32("fsmuld", fsr_cexc_dep1_lo, fsr_cexc_dep2_lo);
        break;
    case SPARC64_FSR_CEXC_OP_FMADD32:
        CEXC_FROM_TERNARY_32_RD("fmadds", fsr_cexc_dep1_hi, fsr_cexc_dep1_lo,
                                fsr_cexc_dep2_hi, fsr_cexc_ndep);
        break;
    case SPARC64_FSR_CEXC_OP_FMADD64:
        CEXC_FROM_TERNARY_64_RD("fmaddd", fsr_cexc_dep1_hi, fsr_cexc_dep1_lo,
                                fsr_cexc_dep2_hi, fsr_cexc_ndep);
        break;
    case SPARC64_FSR_CEXC_OP_FMSUB32:
        CEXC_FROM_TERNARY_32_RD("fmsubs", fsr_cexc_dep1_hi, fsr_cexc_dep1_lo,
                                fsr_cexc_dep2_hi, fsr_cexc_ndep);
        break;
    case SPARC64_FSR_CEXC_OP_FMSUB64:
        CEXC_FROM_TERNARY_64_RD("fmsubd", fsr_cexc_dep1_hi, fsr_cexc_dep1_lo,
                                fsr_cexc_dep2_hi, fsr_cexc_ndep);
        break;
    case SPARC64_FSR_CEXC_OP_F64MUL128:
        CEXC_FROM_BINARY_64("fdmulq", fsr_cexc_dep1_lo, fsr_cexc_dep2_lo);
        break;
    case SPARC64_FSR_CEXC_OP_FSQRT32:
        CEXC_FROM_UNARY_RD("fsqrts", fsr_cexc_dep1_lo, fsr_cexc_ndep,
                           "ld", "%f30", "%f31", "%f30", "%f31");
        break;
    case SPARC64_FSR_CEXC_OP_FSQRT64:
        CEXC_FROM_UNARY_RD("fsqrtd", fsr_cexc_dep1_lo, fsr_cexc_ndep,
                           "ldd", "%d60", "%d62", "%f60", "%f62");
        break;
    case SPARC64_FSR_CEXC_OP_FSQRT128:
        CEXC_FROM_UNARY_128_RD("fsqrtq", fsr_cexc_dep1_hi, fsr_cexc_dep1_lo,
                               fsr_cexc_ndep, "%q60", "%f60");
        break;
    case SPARC64_FSR_CEXC_OP_FSUB32:
        CEXC_FROM_BINARY_32_RD("fsubs", fsr_cexc_dep1_lo,
                               fsr_cexc_dep2_lo, fsr_cexc_ndep);
        break;
    case SPARC64_FSR_CEXC_OP_FSUB64:
        CEXC_FROM_BINARY_64_RD("fsubd", fsr_cexc_dep1_lo,
                               fsr_cexc_dep2_lo, fsr_cexc_ndep);
        break;
    case SPARC64_FSR_CEXC_OP_FSUB128:
        CEXC_FROM_BINARY_128_RD("fsubq", fsr_cexc_dep1_hi, fsr_cexc_dep1_lo,
                                fsr_cexc_dep2_hi, fsr_cexc_dep2_lo,
                                fsr_cexc_ndep);
        break;
    case SPARC64_FSR_CEXC_OP_I32TOF32:
        CEXC_FROM_UNARY_RD("fitos", fsr_cexc_dep1_lo, fsr_cexc_ndep,
                           "ld", "%f30", "%f31", "%f30", "%f31");
        break;
    case SPARC64_FSR_CEXC_OP_I32TOF64:
        CEXC_FROM_UNARY("fitod", fsr_cexc_dep1_lo,
                        "ld", "%f30", "%d62", "%f30", "%f62");
        break;
    case SPARC64_FSR_CEXC_OP_I32TOF128:
        CEXC_FROM_UNARY("fitoq", fsr_cexc_dep1_lo,
                        "ld", "%f30", "%q60", "%f30", "%f60");
        break;
    case SPARC64_FSR_CEXC_OP_I64TOF32:
        CEXC_FROM_UNARY_RD("fxtos", fsr_cexc_dep1_lo, fsr_cexc_ndep,
                           "ldd", "%d60", "%f31", "%f60", "%f31");
        break;
    case SPARC64_FSR_CEXC_OP_I64TOF64:
        CEXC_FROM_UNARY_RD("fxtod", fsr_cexc_dep1_lo, fsr_cexc_ndep,
                           "ldd", "%d60", "%d62", "%f60", "%f62");
        break;
    case SPARC64_FSR_CEXC_OP_I64TOF128:
        CEXC_FROM_UNARY("fxtoq", fsr_cexc_dep1_lo, "ldd",
                        "%d52", "%q60", "%f52", "%f60");
        break;
#endif /* VGA_sparc64 */
    default:
        vex_printf("sparc64_calculate_FSR_cexc(%u, 0x%llx:0x%llx, "
                   "0x%llx:0x%llx, 0x%llx)\n", fsr_cexc_op, fsr_cexc_dep1_hi,
                   fsr_cexc_dep1_lo, fsr_cexc_dep2_hi, fsr_cexc_dep2_lo,
                   fsr_cexc_ndep);
        vpanic("sparc64_calculate_FSR_ver_cexc");
        break;
    }

    fsr_cexc_out &= SPARC64_FSR_MASK_CEXC;

    if (0) {
        vex_printf("sparc64_calculate_FSR_cexc(%u, 0x%llx:0x%llx, "
                   "0x%llx:0x%llx, 0x%llx) => 0x%llx\n", fsr_cexc_op,
                   fsr_cexc_dep1_hi, fsr_cexc_dep1_lo, fsr_cexc_dep2_hi,
                   fsr_cexc_dep2_lo, fsr_cexc_ndep, fsr_cexc_out);
    }
    return fsr_cexc_out;
}

/* CALLED FROM GENERATED CODE: CLEAN HELPER */
/* Calculates native FSR.ver and FSR.cexc from the guest state FSR thunks. */
ULong
sparc64_calculate_FSR_ver_cexc(ULong fsr_cexc_op, ULong fsr_cexc_dep1_hi,
                               ULong fsr_cexc_dep1_lo, ULong fsr_cexc_dep2_hi,
                               ULong fsr_cexc_dep2_lo, ULong fsr_cexc_ndep)
{
    return get_FSR_ver() |
           sparc64_calculate_FSR_cexc(
              fsr_cexc_op, fsr_cexc_dep1_hi, fsr_cexc_dep1_lo, fsr_cexc_dep2_hi,
              fsr_cexc_dep2_lo, fsr_cexc_ndep);
}

/* CALLED FROM GENERATED CODE: CLEAN HELPER */
/* Returns 0 or 1. */
ULong
sparc64_calculate_FCond_from_FSR(ULong cond, ULong fccn, ULong fsr_fcc)
{
    vassert(fccn < 4);

    UInt fcc_shifts[] = {SPARC64_FSR_SHIFT_FCC0, SPARC64_FSR_SHIFT_FCC1,
                         SPARC64_FSR_SHIFT_FCC2, SPARC64_FSR_SHIFT_FCC3};
    ULong fcc_masks[] = {SPARC64_FSR_MASK_FCC0, SPARC64_FSR_MASK_FCC1,
                         SPARC64_FSR_MASK_FCC2, SPARC64_FSR_MASK_FCC3};
    UInt fcc = (fsr_fcc & fcc_masks[fccn]) >> fcc_shifts[fccn];
    vassert(fcc < 4);

    /* Evaluate condition. E = 0, L = 1, G = 2, U = 3. */
    switch (cond) {
    case SPARC64_FCOND_A:
        return (1);
    case SPARC64_FCOND_N:
        return (0);
    case SPARC64_FCOND_U:
        return (fcc == 3) ? 1 : 0;
    case SPARC64_FCOND_G:
        return (fcc == 2) ? 1 : 0;
    case SPARC64_FCOND_UG:
        return (fcc == 2 || fcc == 3) ? 1 : 0;
    case SPARC64_FCOND_L:
        return (fcc == 1) ? 1 : 0;
    case SPARC64_FCOND_UL:
        return (fcc == 1 || fcc == 3) ? 1 : 0;
    case SPARC64_FCOND_LG:
        return (fcc == 1 || fcc == 2) ? 1 : 0;
    case SPARC64_FCOND_NE:
        return (fcc == 1 || fcc == 2 || fcc == 3) ? 1 : 0;
    case SPARC64_FCOND_E:
        return (fcc == 0) ? 1 : 0;
    case SPARC64_FCOND_UE:
        return (fcc == 0 || fcc == 3) ? 1 : 0;
    case SPARC64_FCOND_GE:
        return (fcc == 0 || fcc == 2) ? 1 : 0;
    case SPARC64_FCOND_UGE:
        return (fcc == 0 || fcc == 2 || fcc == 3) ? 1 : 0;
    case SPARC64_FCOND_LE:
        return (fcc == 0 || fcc == 1) ? 1 : 0;
    case SPARC64_FCOND_ULE:
        return (fcc == 0 || fcc == 1 || fcc == 3) ? 1 : 0;
    case SPARC64_FCOND_O:
        return (fcc == 0 || fcc == 1 || fcc == 2) ? 1 : 0;
    default:
        vassert(0);
    }
}

/* CALLED FROM GENERATED CODE: CLEAN HELPER */
/* Returns an emulation warning for %fsr or 'EmNote_NONE' on success. */
ULong
sparc64_check_FSR(ULong fsr)
{
    VexEmNote ew = EmNote_NONE;

    if ((fsr & SPARC64_FSR_MASK_TEM) != 0) {
        ew = EmWarn_SPARC64_fp_exns;
    } else if ((fsr & SPARC64_FSR_MASK_NS) != 0) {
        ew = EmWarn_SPARC64_fp_ns;
    }

    return ew;
}

/* Visible to VEX client. */
ULong
LibVEX_GuestSPARC64_get_ccr(/*IN*/ const VexGuestSPARC64State *vex_state)
{
    return sparc64_calculate_CCR(vex_state->guest_CC_OP,
                                 vex_state->guest_CC_DEP1,
                                 vex_state->guest_CC_DEP2,
                                 vex_state->guest_CC_NDEP);
}

/* Visible to VEX client. */
void
LibVEX_GuestSPARC64_put_ccr(ULong ccr, /*MOD*/ VexGuestSPARC64State *vex_state)
{
    UInt mask = SPARC64_CCR_MASK_I_C | SPARC64_CCR_MASK_I_V |
                SPARC64_CCR_MASK_I_Z | SPARC64_CCR_MASK_I_N |
                SPARC64_CCR_MASK_X_C | SPARC64_CCR_MASK_X_V |
                SPARC64_CCR_MASK_X_Z | SPARC64_CCR_MASK_X_N;
    vex_state->guest_CC_OP   = SPARC64_CC_OP_COPY;
    vex_state->guest_CC_DEP1 = ccr & mask;
    vex_state->guest_CC_DEP2 = 0;
    vex_state->guest_CC_NDEP = 0;
}

static void
sparc64_manipulate_carry(Bool set, UInt mask, VexGuestSPARC64State *vex_state)
{
    ULong ccr = sparc64_calculate_CCR(vex_state->guest_CC_OP,
                                      vex_state->guest_CC_DEP1,
                                      vex_state->guest_CC_DEP2,
                                      vex_state->guest_CC_NDEP);
    if (set == 1) {
        ccr |= mask;
    } else {
        ccr &= ~mask;
    }

    vex_state->guest_CC_OP   = SPARC64_CC_OP_COPY;
    vex_state->guest_CC_DEP1 = ccr;
    vex_state->guest_CC_DEP2 = 0;
    vex_state->guest_CC_NDEP = 0;
}

/* Visible to VEX client. */
void
LibVEX_GuestSPARC64_put_icc_c(UChar new_carry,
                              /*MOD*/ VexGuestSPARC64State *vex_state)
{
    vassert((new_carry == 0) || (new_carry == 1));
    sparc64_manipulate_carry(new_carry, SPARC64_CCR_MASK_I_C, vex_state);
}

/* Visible to VEX client. */
void
LibVEX_GuestSPARC64_put_xcc_c(UChar new_carry,
                              /*MOD*/ VexGuestSPARC64State *vex_state)
{
    vassert((new_carry == 0) || (new_carry == 1));
    sparc64_manipulate_carry(new_carry, SPARC64_CCR_MASK_X_C, vex_state);
}

/* Visible to VEX client. */
ULong
LibVEX_GuestSPARC64_get_fsr(/*IN*/ const VexGuestSPARC64State *vex_state)
{
    /* rounding mode | IR | sparc64
       ----------------------------
       to nearest    | 00 | 00
       to -infinity  | 01 | 11
       to +infinity  | 10 | 10
       to zero       | 11 | 01 */

    ULong fsr_rd;
    switch (vex_state->guest_FSR_RD) {
    case Irrm_NEAREST: fsr_rd = 0; break;
    case Irrm_NegINF:  fsr_rd = 3; break;
    case Irrm_PosINF:  fsr_rd = 2; break;
    case Irrm_ZERO:    fsr_rd = 1; break;
    default:
        vassert(0);
    }

    ULong fsr = sparc64_calculate_FSR_ver_cexc(vex_state->guest_FSR_CEXC_OP,
                                              vex_state->guest_FSR_CEXC_DEP1_HI,
                                              vex_state->guest_FSR_CEXC_DEP1_LO,
                                              vex_state->guest_FSR_CEXC_DEP2_HI,
                                              vex_state->guest_FSR_CEXC_DEP2_LO,
                                              vex_state->guest_FSR_CEXC_NDEP);
    fsr |= vex_state->guest_FSR_FCC;
    fsr |= (fsr_rd << SPARC64_FSR_SHIFT_RD);
    return fsr;
}

/* Visible to VEX client. */
void
LibVEX_GuestSPARC64_put_fsr(ULong fsr, /*MOD*/ VexGuestSPARC64State *vex_state)
{
    /* rounding mode | sparc64 | IR
       ----------------------------
       to nearest    | 00      | 00
       to zero       | 01      | 11
       to +infinity  | 10      | 10
       to -infinity  | 11      | 01 */

    switch ((fsr & SPARC64_FSR_MASK_RD) >> SPARC64_FSR_SHIFT_RD) {
    case 0: vex_state->guest_FSR_RD = Irrm_NEAREST; break;
    case 1: vex_state->guest_FSR_RD = Irrm_ZERO;    break;
    case 2: vex_state->guest_FSR_RD = Irrm_PosINF;  break;
    case 3: vex_state->guest_FSR_RD = Irrm_NegINF;  break;
    default:
        vassert(0);
    }

    vex_state->guest_FSR_FCC = fsr & SPARC64_FSR_MASK_FCC;
    vex_state->guest_FSR_CEXC_OP = SPARC64_FSR_CEXC_OP_COPY;
    vex_state->guest_FSR_CEXC_DEP1_HI = 0;
    vex_state->guest_FSR_CEXC_DEP1_LO = fsr & SPARC64_FSR_MASK_CEXC;
    vex_state->guest_FSR_CEXC_DEP2_HI = 0;
    vex_state->guest_FSR_CEXC_DEP2_LO = 0;
    vex_state->guest_FSR_CEXC_NDEP = 0;
}

/* Visible to VEX client. */
ULong
LibVEX_GuestSPARC64_get_gsr(/*IN*/ const VexGuestSPARC64State *vex_state)
{
    ULong gsr = (ULong) vex_state->guest_GSR_mask << SPARC64_GSR_SHIFT_MASK;
    gsr |= (ULong) vex_state->guest_GSR_align << SPARC64_GSR_SHIFT_ALIGN;
    return gsr;
}

/* Visible to VEX client. */
void
LibVEX_GuestSPARC64_put_gsr(ULong gsr, /*MOD*/ VexGuestSPARC64State *vex_state)
{
    vex_state->guest_GSR_align = (UInt) (gsr & SPARC64_GSR_MASK_ALIGN);
    vex_state->guest_GSR_mask  = (UInt) (gsr >> SPARC64_GSR_SHIFT_MASK);
}

/*---------------------------------------------------------------*/
/*--- end                             guest_sparc64_helpers.c ---*/
/*---------------------------------------------------------------*/
