/*----------------------------------------------------------------------------*/
/*--- begin                                           guest_sparc64_defs.h ---*/
/*----------------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2015-2015 Tomas Jedlicka
      jedlickat@gmail.com

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

/* Copyright 2015-2017, Ivo Raisr <ivosh@ivosh.net>. */

#ifndef __VEX_GUEST_SPARC64_DEFS_H
#define __VEX_GUEST_SPARC64_DEFS_H

#include "libvex_basictypes.h"
#include "guest_generic_bb_to_IR.h"
#include "libvex_guest_sparc64.h"

/*----------------------------------------------------------------------------*/
/*--- sparc64 to IR conversion                                             ---*/
/*----------------------------------------------------------------------------*/

/* Converts one SPARC64 insn to IR. See the type DisOneInstrFn in
   guest_generic_bb_to_IR.h */
extern DisResult
disInstr_SPARC64(IRSB              *irbb,
                 Bool              (*resteerOkFn)(void *, Addr),
                 Bool              resteerCisOk,
                 void              *callback_opaque,
                 const UChar       *guest_code,
                 Long              delta,
                 Addr              guest_IP,
                 VexArch           guest_arch,
                 const VexArchInfo *archinfo,
                 const VexAbiInfo  *abiinfo,
                 VexEndness        host_endness,
                 Bool              sigill_diag);

/* Used by the optimiser to specialise calls to helpers. */
extern IRExpr *
guest_sparc64_spechelper(const HChar *function_name,
                         IRExpr      **args,
                         IRStmt      **precedingStmts,
                         Int         n_precedingStmts);

/* Describes to the optimiser which part of the guest state requires
   precise memory exceptions. This is logically part of the guest
   state description. */
extern Bool
guest_sparc64_state_requires_precise_mem_exns(Int minoff, Int maxoff,
                                              VexRegisterUpdates);

extern VexGuestLayout sparc64Guest_layout;

/*----------------------------------------------------------------------------*/
/*--- sparc64 guest helpers                                                ---*/
/*----------------------------------------------------------------------------*/

/*--- CLEAN HELPERS ---*/

extern ULong
sparc64_calculate_CCR(ULong cc_op, ULong cc_dep1, ULong cc_dep2, ULong cc_ndep);

extern ULong
sparc64_calculate_ICond(ULong cond, ULong cc_op, ULong cc_dep1, ULong cc_dep2,
                        ULong cc_ndep);

extern ULong
sparc64_helper_rd(ULong asr_reg);

extern ULong
sparc64_calculate_FSR_ver_cexc(ULong fsr_cexc_op, ULong fsr_cexc_dep1_hi,
                               ULong fsr_cexc_dep1_lo, ULong fsr_cexc_dep2_hi,
                               ULong fsr_cexc_dep2_lo, ULong fsr_cxec_ndep);
extern ULong
sparc64_calculate_FCond_from_FSR(ULong cond, ULong fccn, ULong fsr_fcc);
extern ULong
sparc64_check_FSR(ULong fsr);

extern ULong
sparc64_aes_eround01(ULong arg1, ULong arg2, ULong arg3);
extern ULong
sparc64_aes_eround23(ULong arg1, ULong arg2, ULong arg3);
extern ULong
sparc64_aes_dround01(ULong arg1, ULong arg2, ULong arg3);
extern ULong
sparc64_aes_dround23(ULong arg1, ULong arg2, ULong arg3);
extern ULong
sparc64_aes_eround01_l(ULong arg1, ULong arg2, ULong arg3);
extern ULong
sparc64_aes_eround23_l(ULong arg1, ULong arg2, ULong arg3);
extern ULong
sparc64_aes_dround01_l(ULong arg1, ULong arg2, ULong arg3);
extern ULong
sparc64_aes_dround23_l(ULong arg1, ULong arg2, ULong arg3);
extern ULong
sparc64_aes_kexpand0(ULong argL, ULong argR);
extern ULong
sparc64_aes_kexpand1_0(ULong argL, ULong argR);
extern ULong
sparc64_aes_kexpand1_1(ULong argL, ULong argR);
extern ULong
sparc64_aes_kexpand1_2(ULong argL, ULong argR);
extern ULong
sparc64_aes_kexpand1_3(ULong argL, ULong argR);
extern ULong
sparc64_aes_kexpand1_4(ULong argL, ULong argR);
extern ULong
sparc64_aes_kexpand1_5(ULong argL, ULong argR);
extern ULong
sparc64_aes_kexpand1_6(ULong argL, ULong argR);
extern ULong
sparc64_aes_kexpand1_7(ULong argL, ULong argR);
extern ULong
sparc64_aes_kexpand1_8(ULong argL, ULong argR);
extern ULong
sparc64_aes_kexpand1_9(ULong argL, ULong argR);
extern ULong
sparc64_aes_kexpand2(ULong argL, ULong argR);

extern ULong
sparc64_xmulx(ULong argL, ULong argR);
extern ULong
sparc64_xmulxhi(ULong argL, ULong argR);

/*--- DIRTY HELPERS ---*/

extern void
sparc64_md5(VexGuestSPARC64State *guest_state);
extern void
sparc64_sha1(VexGuestSPARC64State *guest_state);
extern void
sparc64_sha256(VexGuestSPARC64State *guest_state);
extern void
sparc64_sha512(VexGuestSPARC64State *guest_state);


/*----------------------------------------------------------------------------*/
/*--- Condition code stuff                                                 ---*/
/*----------------------------------------------------------------------------*/

#define SPARC64_CCR_SHIFT_I_C    0
#define SPARC64_CCR_SHIFT_I_V    1
#define SPARC64_CCR_SHIFT_I_Z    2
#define SPARC64_CCR_SHIFT_I_N    3
#define SPARC64_CCR_SHIFT_X_C    4
#define SPARC64_CCR_SHIFT_X_V    5
#define SPARC64_CCR_SHIFT_X_Z    6
#define SPARC64_CCR_SHIFT_X_N    7

#define SPARC64_CCR_MASK_I_C     (1ULL << SPARC64_CCR_SHIFT_I_C)
#define SPARC64_CCR_MASK_I_V     (1ULL << SPARC64_CCR_SHIFT_I_V)
#define SPARC64_CCR_MASK_I_Z     (1ULL << SPARC64_CCR_SHIFT_I_Z)
#define SPARC64_CCR_MASK_I_N     (1ULL << SPARC64_CCR_SHIFT_I_N)
#define SPARC64_CCR_MASK_X_C     (1ULL << SPARC64_CCR_SHIFT_X_C)
#define SPARC64_CCR_MASK_X_V     (1ULL << SPARC64_CCR_SHIFT_X_V)
#define SPARC64_CCR_MASK_X_Z     (1ULL << SPARC64_CCR_SHIFT_X_Z)
#define SPARC64_CCR_MASK_X_N     (1ULL << SPARC64_CCR_SHIFT_X_N)

/* Condition Codes Register (%icc,%xcc) thunk descriptors.
   Modelled after x86/amd64/arm/arm64 architectures.
   A four-word thunk is used to record details of the most recent condition code
   setting operation, so that condition code fields can be computed later if
   needed. It is possible to do this a little more efficiently using a 3-word
   thunk, but that makes it impossible to describe the field data dependencies
   sufficiently accurately for Memcheck. Hence 4 words are used, with minimal
   loss of efficiency.

   The four words are:

   CC_OP, which describes the operation.

   CC_DEP1 and CC_DEP2.  These are arguments to the operation.
       We want Memcheck to believe that the resulting condition codes are
       data-dependent on both CC_DEP1 and CC_DEP2, hence the name DEP.

   CC_NDEP. This is a 3rd argument to the operation which is sometimes needed.
       We arrange things so that Memcheck does not believe the resulting flags
       are data-dependent on CC_NDEP ("not dependent").

   To make Memcheck believe that (the definedness of) the encoded condition
   codes depends only on (the definedness of) CC_DEP1 and CC_DEP2 requires two
   things:

   (1) In the guest state layout info (sparc64guest_layout), CC_OP and CC_NDEP
       are marked as always defined.

   (2) When passing the thunk components to an evaluation function
       (calculate_CCR) the IRCallee's mcx_mask must be set so as to exclude from
       consideration all passed args except CC_DEP1 and CC_DEP2.

   Strictly speaking only (2) is necessary for correctness. However, (1) helps
   efficiency in that since (2) means we never ask about the definedness of
   CC_OP or CC_NDEP, we may as well not even bother to track their definedness.

   When building the thunk, it is always necessary to write words into CC_DEP1
   and CC_DEP2, even if those args are not used given the CC_OP field
   (for example CC_DEP2 is not used if CC_OP is CC_OP_LOGIC).
   This is important because otherwise Memcheck could give false positives as
   it does not understand the relationship between the CC_OP field and CC_DEP1
   and CC_DEP2, and so believes that the definedness of the stored flags always
   depends on both CC_DEP1 and CC_DEP2.

   However, it is only necessary to set CC_NDEP when the CC_OP value requires
   it, because Memcheck ignores CC_NDEP, and the evaluation functions do
   understand the CC_OP fields and will only examine CC_NDEP for suitable values
   of CC_OP.

   A summary of the field usages is:

   Operation          DEP1               DEP2               NDEP
   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   CC_OP_LOGIC        result             zero               unused
   CC_OP_ADD          argL               argR               unused
   CC_OP_SMUL         argL               argR               unused
   CC_OP_SUB          argL               argR               unused
   CC_OP_ADDC         argL               argR ^ carry       carry
   CC_OP_SUBC         argL               argR ^ carry       carry
   CC_OP_COPY         old_flags          zero               unused

   argL   ... left input argument of the instruction
   argR   ... right input argument of the instruction
   result ... output argument of the instruction

   See guest_amd64_defs.h for more details about this table and especially
   about meaning of (argR ^ carry).
*/
typedef enum {
    SPARC64_CC_OP_COPY = 0,

    SPARC64_CC_OP_LOGIC,
    SPARC64_CC_OP_ADD,
    SPARC64_CC_OP_ADDC,
    SPARC64_CC_OP_SDIV,
    SPARC64_CC_OP_SMUL,
    SPARC64_CC_OP_SUB,
    SPARC64_CC_OP_SUBC,
    SPARC64_CC_OP_UDIV,
    SPARC64_CC_OP_UMUL,

    SPARC64_CC_OP_NUMBER
} SPARC64_CC_OP;

/* SPARC64 supported integer conditions. XCC related conditions must be an odd
   number and directly after ICC variant. The code expects this layout. */
typedef enum {
    SPARC64_ICOND_A_ICC = 0,
    SPARC64_ICOND_A_XCC,
    SPARC64_ICOND_N_ICC,
    SPARC64_ICOND_N_XCC,
    SPARC64_ICOND_NE_ICC,
    SPARC64_ICOND_NE_XCC,
    SPARC64_ICOND_E_ICC,
    SPARC64_ICOND_E_XCC,
    SPARC64_ICOND_G_ICC,
    SPARC64_ICOND_G_XCC,
    SPARC64_ICOND_LE_ICC,
    SPARC64_ICOND_LE_XCC,
    SPARC64_ICOND_GE_ICC,
    SPARC64_ICOND_GE_XCC,
    SPARC64_ICOND_L_ICC,
    SPARC64_ICOND_L_XCC,
    SPARC64_ICOND_GU_ICC,
    SPARC64_ICOND_GU_XCC,
    SPARC64_ICOND_LEU_ICC,
    SPARC64_ICOND_LEU_XCC,
    SPARC64_ICOND_CC_ICC,
    SPARC64_ICOND_CC_XCC,
    SPARC64_ICOND_CS_ICC,
    SPARC64_ICOND_CS_XCC,
    SPARC64_ICOND_POS_ICC,
    SPARC64_ICOND_POS_XCC,
    SPARC64_ICOND_NEG_ICC,
    SPARC64_ICOND_NEG_XCC,
    SPARC64_ICOND_VC_ICC,
    SPARC64_ICOND_VC_XCC,
    SPARC64_ICOND_VS_ICC,
    SPARC64_ICOND_VS_XCC
} SPARC64ICondcode;

/*----------------------------------------------------------------------------*/
/*--- FPU support stuff                                                    ---*/
/*----------------------------------------------------------------------------*/

#define SPARC64_FPRS_SHIFT_FEF    2
#define SPARC64_FPRS_MASK_FEF     (1ULL << SPARC64_FPRS_SHIFT_FEF)
#define SPARC64_FPRS_MASK_DUDL    (3ULL)

/* See also <sys/fsr.h> */
#define SPARC64_FSR_SHIFT_CEXC    0
#define SPARC64_FSR_SHIFT_AEXC    5
#define SPARC64_FSR_SHIFT_FCC0    10
#define SPARC64_FSR_SHIFT_RES1    12
#define SPARC64_FSR_SHIFT_QNE     13
#define SPARC64_FSR_SHIFT_FTT     14
#define SPARC64_FSR_SHIFT_VER     17
#define SPARC64_FSR_SHIFT_RES2    20
#define SPARC64_FSR_SHIFT_NS      22
#define SPARC64_FSR_SHIFT_TEM     23
#define SPARC64_FSR_SHIFT_RES3    28
#define SPARC64_FSR_SHIFT_RD      30
#define SPARC64_FSR_SHIFT_FCC1    32
#define SPARC64_FSR_SHIFT_FCC2    34
#define SPARC64_FSR_SHIFT_FCC3    36
#define SPARC64_FSR_SHIFT_RES4    38
#define SPARC64_FSR_MASK_CEXC     0x000000000000001FULL
#define SPARC64_FSR_MASK_AEXC     0x00000000000003E0ULL
#define SPARC64_FSR_MASK_FCC0     0x0000000000000C00ULL
#define SPARC64_FSR_MASK_RES1     0x0000000000001000ULL
#define SPARC64_FSR_MASK_QNE      0x0000000000002000ULL
#define SPARC64_FSR_MASK_FTT      0x000000000001c000ULL
#define SPARC64_FSR_MASK_VER      0x00000000000E0000ULL
#define SPARC64_FSR_MASK_RES2     0x0000000000300000ULL
#define SPARC64_FSR_MASK_NS       0x0000000000400000ULL
#define SPARC64_FSR_MASK_TEM      0x000000000F800000ULL
#define SPARC64_FSR_MASK_RES3     0x0000000030000000ULL
#define SPARC64_FSR_MASK_RD       0x00000000C0000000ULL
#define SPARC64_FSR_MASK_FCC1     0x0000000300000000ULL
#define SPARC64_FSR_MASK_FCC2     0x0000000C00000000ULL
#define SPARC64_FSR_MASK_FCC3     0x0000003000000000ULL
#define SPARC64_FSR_MASK_RES4     0xFFFFFFC000000000ULL
#define SPARC64_FSR_MASK_FCC      (SPARC64_FSR_MASK_FCC0 \
                                   | SPARC64_FSR_MASK_FCC1 \
                                   | SPARC64_FSR_MASK_FCC2 \
                                   | SPARC64_FSR_MASK_FCC3)
#define SPARC64_FSR_MASK_RES      (SPARC64_FSR_MASK_RES1 \
                                   | SPARC64_FSR_MASK_RES2 \
                                   | SPARC64_FSR_MASK_RES3 \
                                   | SPARC64_FSR_MASK_RES4)

/* Floating-Point Status Register (%fsr) cexc thunk descriptors.
   Modelled after CC thunk descriptors.
   Used to record details of the most recent FPop operation, so that FSR.cexc
   field can be computed later, if needed. Note that FSR.rd and FSR.fcc fields
   are tracked directly in the guest state.

   FSR_CEXC_OP, which describes the operation.

   FSR_CEXC_DEP1 and FSR_CEXC_DEP2. These are arguments to the operation.
       We want Memcheck to believe that the resulting FSR fields are data
       dependent on both FSR_CEXC_DEP1 and FSR_CEXC_DEP2, hence the name DEP.
       For F32 operations, only the lowest 32 bits of FSR_CEXC_DEPx_LO are used.
       For F64 operations, whole FSR_CEXC_DEPx_LO are used.
       For F128 operations, both FSR_CEXC_DEPx_HI and FSR_CEXC_DEPx_LO are used.

       For 4-operand instructions (such as FMAf), the following scheme is used:
       frs1 - FSR_CEXC_DEP1_HI
       frs2 - FSR_CEXC_DEP1_LO
       frs3 - FSR_CEXC_DEP2_HI

   FSR_CEXC_NDEP. Sometimes necessary to convey for example rounding mode
       valid at the time the operation was performed.

   To make Memcheck believe that (the definedness of) the encoded FSR.cexc field
   depends only on (the definedness of) FSR_CEXC_DEP1 and FSR_CEXC_DEP2 requires
   two things:

   (1) In the guest state layout info (sparc64guest_layout), FSR_CEXC_OP
       and FSR_CEXC_NDEP are marked as always defined.

   (2) When passing the thunk components to an evaluation function
       (calculate_FSR_ver_cexc) the IRCallee's mcx_mask must be set so as to
       exclude from consideration all passed args except FSR_CEXC_DEP1*
       and FSR_CEXC_DEP2*.

   When building the thunk, it is always necessary to write words into
   FSR_CEXC_DEP1_HI, FSR_CEXC_DEP1_LO, FSR_CEXC_DEP2_HI, and FSR_CEXC_DEP2_LO,
   even if those args are not used given the FSR_CEXC_OP field. This is
   important because otherwise Memcheck could give false positives as it does
   not understand the relationship between the FSR_CEXC_OP field
   and FSR_CEXC_DEP1* and FSR_CEXC_DEP2*, and so believes that the definedness
   of the stored flags always depends on both FSR_CEXC_DEP1* and FSR_CEXC_DEP2*.
*/
typedef enum {
    SPARC64_FSR_CEXC_OP_COPY = 0,

    SPARC64_FSR_CEXC_OP_F32TOF64,
    SPARC64_FSR_CEXC_OP_F32TOF128,
    SPARC64_FSR_CEXC_OP_F64TOF32, /* IRRoundingMode in FSR_NDEP */
    SPARC64_FSR_CEXC_OP_F64TOF128,
    SPARC64_FSR_CEXC_OP_F128TOF32, /* IRRoundingMode in FSR_NDEP */
    SPARC64_FSR_CEXC_OP_F128TOF64, /* IRRoundingMode in FSR_NDEP */
    SPARC64_FSR_CEXC_OP_F32TOI32,
    SPARC64_FSR_CEXC_OP_F64TOI32,
    SPARC64_FSR_CEXC_OP_F128TOI32,
    SPARC64_FSR_CEXC_OP_F32TOI64,
    SPARC64_FSR_CEXC_OP_F64TOI64,
    SPARC64_FSR_CEXC_OP_F128TOI64,
    SPARC64_FSR_CEXC_OP_FADD32, /* IRRoundingMode in FSR_NDEP */
    SPARC64_FSR_CEXC_OP_FADD64, /* IRRoundingMode in FSR_NDEP */
    SPARC64_FSR_CEXC_OP_FADD128, /* IRRoundingMode in FSR_NDEP */
    SPARC64_FSR_CEXC_OP_FCMP32,
    SPARC64_FSR_CEXC_OP_FCMP64,
    SPARC64_FSR_CEXC_OP_FCMP128,
    SPARC64_FSR_CEXC_OP_FCMPE32,
    SPARC64_FSR_CEXC_OP_FCMPE64,
    SPARC64_FSR_CEXC_OP_FCMPE128,
    SPARC64_FSR_CEXC_OP_FDIV32, /* IRRoundingMode in FSR_NDEP */
    SPARC64_FSR_CEXC_OP_FDIV64, /* IRRoundingMode in FSR_NDEP */
    SPARC64_FSR_CEXC_OP_FDIV128, /* IRRoundingMode in FSR_NDEP */
    SPARC64_FSR_CEXC_OP_FMUL32, /* IRRoundingMode in FSR_NDEP */
    SPARC64_FSR_CEXC_OP_FMUL64, /* IRRoundingMode in FSR_NDEP */
    SPARC64_FSR_CEXC_OP_FMUL128, /* IRRoundingMode in FSR_NDEP */
    SPARC64_FSR_CEXC_OP_F32MUL64,
    SPARC64_FSR_CEXC_OP_F64MUL128,
    SPARC64_FSR_CEXC_OP_FMADD32, /* IRRoundingMode in FSR_NDEP, 4-operand */
    SPARC64_FSR_CEXC_OP_FMADD64, /* IRRoundingMode in FSR_NDEP, 4-operand */
    SPARC64_FSR_CEXC_OP_FMSUB32, /* IRRoundingMode in FSR_NDEP, 4-operand */
    SPARC64_FSR_CEXC_OP_FMSUB64, /* IRRoundingMode in FSR_NDEP, 4-operand */
    SPARC64_FSR_CEXC_OP_FSQRT32, /* IRRoundingMode in FSR_NDEP */
    SPARC64_FSR_CEXC_OP_FSQRT64, /* IRRoundingMode in FSR_NDEP */
    SPARC64_FSR_CEXC_OP_FSQRT128, /* IRRoundingMode in FSR_NDEP */
    SPARC64_FSR_CEXC_OP_FSUB32, /* IRRoundingMode in FSR_NDEP */
    SPARC64_FSR_CEXC_OP_FSUB64, /* IRRoundingMode in FSR_NDEP */
    SPARC64_FSR_CEXC_OP_FSUB128, /* IRRoundingMode in FSR_NDEP */
    SPARC64_FSR_CEXC_OP_I32TOF32, /* IRRoundingMode in FSR_NDEP */
    SPARC64_FSR_CEXC_OP_I32TOF64,
    SPARC64_FSR_CEXC_OP_I32TOF128,
    SPARC64_FSR_CEXC_OP_I64TOF32, /* IRRoundingMode in FSR_NDEP */
    SPARC64_FSR_CEXC_OP_I64TOF64, /* IRRoundingMode in FSR_NDEP */
    SPARC64_FSR_CEXC_OP_I64TOF128,

    SPARC64_FSR_CEXC_OP_NUMBER
} SPARC64_FSR_CEXC_OP;

/* SPARC64 supported floating-point conditions. */
typedef enum {
    SPARC64_FCOND_A = 0,
    SPARC64_FCOND_N,
    SPARC64_FCOND_U,
    SPARC64_FCOND_G,
    SPARC64_FCOND_UG,
    SPARC64_FCOND_L,
    SPARC64_FCOND_UL,
    SPARC64_FCOND_LG,
    SPARC64_FCOND_NE,
    SPARC64_FCOND_E,
    SPARC64_FCOND_UE,
    SPARC64_FCOND_GE,
    SPARC64_FCOND_UGE,
    SPARC64_FCOND_LE,
    SPARC64_FCOND_ULE,
    SPARC64_FCOND_O
} SPARC64FCondcode;

#define SPARC64_GSR_SHIFT_ALIGN  0
#define SPARC64_GSR_SHIFT_MASK   32

#define SPARC64_GSR_MASK_ALIGN   0x0000000000000007ULL
#define SPARC64_CCR_MASK_MASK    0xFFFFFFFF00000000ULL


#endif /* __VEX_GUEST_SPARC64_DEFS.H */

/*----------------------------------------------------------------------------*/
/*--- end                                             guest_sparc64_defs.h ---*/
/*----------------------------------------------------------------------------*/
