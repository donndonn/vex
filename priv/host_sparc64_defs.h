/*----------------------------------------------------------------------------*/
/*--- begin                                            host_sparc64_defs.h ---*/
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

#ifndef __VEX_HOST_SPARC64_DEFS_H
#define __VEX_HOST_SPARC64_DEFS_H

#include "libvex_basictypes.h"
#include "libvex.h"
#include "host_generic_regs.h"

/* --------- Registers. --------- */

#define ST_IN static inline
ST_IN HReg hregSPARC64_L0(void) { return mkHReg(False, HRcInt64, 16,  0); }
ST_IN HReg hregSPARC64_L1(void) { return mkHReg(False, HRcInt64, 17,  1); }
ST_IN HReg hregSPARC64_L2(void) { return mkHReg(False, HRcInt64, 18,  2); }
ST_IN HReg hregSPARC64_L3(void) { return mkHReg(False, HRcInt64, 19,  3); }
ST_IN HReg hregSPARC64_L4(void) { return mkHReg(False, HRcInt64, 20,  4); }
ST_IN HReg hregSPARC64_L5(void) { return mkHReg(False, HRcInt64, 21,  5); }
ST_IN HReg hregSPARC64_L6(void) { return mkHReg(False, HRcInt64, 22,  6); }
ST_IN HReg hregSPARC64_L7(void) { return mkHReg(False, HRcInt64, 23,  7); }
ST_IN HReg hregSPARC64_I0(void) { return mkHReg(False, HRcInt64, 24,  8); }
ST_IN HReg hregSPARC64_I1(void) { return mkHReg(False, HRcInt64, 25,  9); }
ST_IN HReg hregSPARC64_I2(void) { return mkHReg(False, HRcInt64, 26, 10); }
ST_IN HReg hregSPARC64_I3(void) { return mkHReg(False, HRcInt64, 27, 11); }
ST_IN HReg hregSPARC64_I4(void) { return mkHReg(False, HRcInt64, 28, 12); }
ST_IN HReg hregSPARC64_I5(void) { return mkHReg(False, HRcInt64, 29, 13); }

ST_IN HReg hregSPARC64_O0(void) { return mkHReg(False, HRcInt64,  8, 14); }
ST_IN HReg hregSPARC64_O1(void) { return mkHReg(False, HRcInt64,  9, 15); }
ST_IN HReg hregSPARC64_O2(void) { return mkHReg(False, HRcInt64, 10, 16); }
ST_IN HReg hregSPARC64_O3(void) { return mkHReg(False, HRcInt64, 11, 17); }
ST_IN HReg hregSPARC64_O4(void) { return mkHReg(False, HRcInt64, 12, 18); }
ST_IN HReg hregSPARC64_O5(void) { return mkHReg(False, HRcInt64, 13, 19); }

/* We don't need to add every FPU register that is available. The VEX spill/fill
   mechanism will take care of case where we are lacking registers.
   The reason behind this decision is to have supposedly faster register
   allocator scans and lookups. */
ST_IN HReg hregSPARC64_F0(void) { return mkHReg(False, HRcFlt32,  0, 20); }
ST_IN HReg hregSPARC64_F1(void) { return mkHReg(False, HRcFlt32,  1, 21); }
ST_IN HReg hregSPARC64_F2(void) { return mkHReg(False, HRcFlt32,  2, 22); }
ST_IN HReg hregSPARC64_F3(void) { return mkHReg(False, HRcFlt32,  3, 23); }
ST_IN HReg hregSPARC64_F4(void) { return mkHReg(False, HRcFlt32,  4, 24); }
ST_IN HReg hregSPARC64_F5(void) { return mkHReg(False, HRcFlt32,  5, 25); }
ST_IN HReg hregSPARC64_F6(void) { return mkHReg(False, HRcFlt32,  6, 26); }
ST_IN HReg hregSPARC64_F7(void) { return mkHReg(False, HRcFlt32,  7, 27); }

ST_IN HReg hregSPARC64_D8(void)  { return mkHReg(False, HRcFlt64,  8, 28); }
ST_IN HReg hregSPARC64_D10(void) { return mkHReg(False, HRcFlt64, 10, 29); }
ST_IN HReg hregSPARC64_D12(void) { return mkHReg(False, HRcFlt64, 12, 30); }
ST_IN HReg hregSPARC64_D14(void) { return mkHReg(False, HRcFlt64, 14, 31); }
ST_IN HReg hregSPARC64_D16(void) { return mkHReg(False, HRcFlt64, 16, 32); }
ST_IN HReg hregSPARC64_D18(void) { return mkHReg(False, HRcFlt64, 18, 33); }
ST_IN HReg hregSPARC64_D20(void) { return mkHReg(False, HRcFlt64, 20, 34); }
ST_IN HReg hregSPARC64_D22(void) { return mkHReg(False, HRcFlt64, 22, 35); }

ST_IN HReg hregSPARC64_Q24(void) { return mkHReg(False, HRcFlt128, 24, 36); }
ST_IN HReg hregSPARC64_Q28(void) { return mkHReg(False, HRcFlt128, 28, 37); }
ST_IN HReg hregSPARC64_Q32(void) { return mkHReg(False, HRcFlt128, 32, 38); }
ST_IN HReg hregSPARC64_Q36(void) { return mkHReg(False, HRcFlt128, 36, 39); }
ST_IN HReg hregSPARC64_Q40(void) { return mkHReg(False, HRcFlt128, 40, 40); }
ST_IN HReg hregSPARC64_Q44(void) { return mkHReg(False, HRcFlt128, 44, 41); }
ST_IN HReg hregSPARC64_Q48(void) { return mkHReg(False, HRcFlt128, 48, 42); }
ST_IN HReg hregSPARC64_Q52(void) { return mkHReg(False, HRcFlt128, 52, 43); }

/* Not allocatable registers */
ST_IN HReg hregSPARC64_G0(void) { return mkHReg(False, HRcInt64,  0, 44); }
ST_IN HReg hregSPARC64_G1(void) { return mkHReg(False, HRcInt64,  1, 45); }
ST_IN HReg hregSPARC64_G2(void) { return mkHReg(False, HRcInt64,  2, 46); }
ST_IN HReg hregSPARC64_G3(void) { return mkHReg(False, HRcInt64,  3, 47); }
ST_IN HReg hregSPARC64_G4(void) { return mkHReg(False, HRcInt64,  4, 48); }
ST_IN HReg hregSPARC64_G5(void) { return mkHReg(False, HRcInt64,  5, 49); }
ST_IN HReg hregSPARC64_G6(void) { return mkHReg(False, HRcInt64,  6, 50); }
ST_IN HReg hregSPARC64_G7(void) { return mkHReg(False, HRcInt64,  7, 51); }
ST_IN HReg hregSPARC64_O6(void) { return mkHReg(False, HRcInt64, 14, 52); }
ST_IN HReg hregSPARC64_O7(void) { return mkHReg(False, HRcInt64, 15, 53); }
ST_IN HReg hregSPARC64_I6(void) { return mkHReg(False, HRcInt64, 30, 54); }
ST_IN HReg hregSPARC64_I7(void) { return mkHReg(False, HRcInt64, 31, 55); }

/* PC is readonly ASR5 */
ST_IN HReg hregSPARC64_PC(void) { return mkHReg(False, HRcInt64,  5, 56); }
#undef ST_IN

extern void ppHRegSPARC64(HReg);

#define SPARC64_GuestStatePointer()	hregSPARC64_G5()

#define SPARC64_N_REGPARMS	6

/* --------- Condition codes --------- */

/* Low-level code depends on the order of this enum. */
typedef enum {
    Scc_A,
    Scc_N,
    Scc_NE,
    Scc_E,
    Scc_G,
    Scc_LE,
    Scc_GE,
    Scc_L,
    Scc_GU,
    Scc_LEU,
    Scc_CC,
    Scc_CS,
    Scc_POS,
    Scc_NEG,
    Scc_VC,
    Scc_VS
} SPARC64CondCode;

extern const HChar *showSPARC64CondCode(SPARC64CondCode);

/* Low-level code depends on the order of this enum. */
typedef enum {
   Src_Z   = 1,
   Src_LEZ = 2,
   Src_LZ  = 3,
   Src_NZ  = 5,
   Src_GZ  = 6,
   Src_GEZ = 7
} SPARC64RegCode;

extern const HChar *showSPARC64RegCode(SPARC64RegCode);

/* --------- Memory address expressions (amodes). --------- */

typedef enum {
    Sam_IR,              /* Immediate (signed 13bit) + Reg */
    Sam_RR,              /* Reg1 + Reg 2 */
} SPARC64AModeTag;

typedef struct {
    SPARC64AModeTag tag;
    union {
        struct {
            Int imm;
            HReg reg;
        } IR;
        struct {
            HReg reg1;
            HReg reg2;
        } RR;
    } Sam;
} SPARC64AMode;

extern SPARC64AMode *SPARC64AMode_IR(Int imm, HReg reg);
extern SPARC64AMode *SPARC64AMode_RR(HReg reg1, HReg reg2);

extern void ppSPARC64AMode(SPARC64AMode *am);

/* --------- Instructions. --------- */

#define SPARC64_SIMM10_MAXBITS 9
#define SPARC64_SIMM10_MASK 0x3FF
#define SPARC64_SIMM13_MAXBITS 12
#define SPARC64_SIMM13_MASK 0x1FFF

#define FITS_INTO_MAXBITS_SIGNED(val, maxbits)              \
    ( ( ((val) >= 0) && ((val) <  ((1 << (maxbits)) - 1)) ) \
      ||                                                    \
      ( ((val)  < 0) && ((val) > -((1 << (maxbits)) - 1)) ) \
    )


typedef enum {
    Sri_Imm,
    Sri_Reg
} SPARC64RITag;

typedef struct {
    SPARC64RITag tag;
    union {
        struct {
            Long simm13;
        } Imm;
        struct {
            HReg reg;
        } Reg;
    } Sri;
} SPARC64RI;

extern void ppSPARC64RI(SPARC64RI *ri);
extern SPARC64RI *SPARC64RI_Imm(ULong l);
extern SPARC64RI *SPARC64RI_Reg(HReg reg);

typedef enum {
    Salu_INVALID,
    Salu_ADD,
    Salu_SUB,
    Salu_MULX,
    Salu_SMUL,
    Salu_UMUL,
    Salu_UMULXHI, /* cannot take immediate */
    Salu_UDIVX,
    Salu_SDIVX,
    Salu_SDIV,   /* %y register needs to be set already */
    Salu_UDIV,   /* %y register needs to be set already */
    Salu_SUBcc,
    Salu_AND,
    Salu_ANDcc,
    Salu_OR,
    Salu_ORN,
    Salu_XOR,
    Salu_XNOR
} SPARC64AluOp;

typedef enum {
    AluFp_INVALID,
    AluFp_FADD,
    AluFp_FAND,
    AluFp_FDIV,
    AluFp_FMUL,
    AluFp_FsdMUL,
    AluFp_FNOT,
    AluFp_FOR,
    AluFp_FSUB,
    AluFp_FXOR
} SPARC64AluFpOp;

typedef enum {
    Sshft_INVALID,
    Sshft_SLL,
    Sshft_SRL,
    Sshft_SRA,
    Sshft_SLLX,
    Sshft_SRLX,
    Sshft_SRAX
} SPARC64ShftOp;

typedef enum {
    FusedFp_INVALID,
    FusedFp_MADD,
    FusedFp_MSUB
} SPARC64FusedFpOp;

typedef enum {
    ShftFp_SLL16,
    ShftFp_SRL16,
    ShftFp_SLL32,
    ShftFp_SRL32,
    ShftFp_SLAS16,
    ShftFp_SRA16,
    ShftFp_SLAS32,
    ShftFp_SRA32
} SPARC64ShftFpOp;

typedef enum {
    Sin_LI,          /* load 8/16/32/64 immediate */
    Sin_Alu,         /* integer arithmetic/logical instruction */
    Sin_Shft,        /* shift */

    Sin_Load,        /* zero-extending memory load of 8/16/32/64 memory value */
    Sin_Store,       /* store 8/16/32/64 bit value or %fsr to memory */
    Sin_MoveCond,    /* conditional reg move based on condition codes */
    Sin_MoveReg,     /* conditional reg move based on register content */
    Sin_CAS,         /* compare-and-swap */
    Sin_Ldstub,      /* load-store unsigned byte */
    Sin_Lzcnt,       /* leading zeroes count */
    Sin_Membar,      /* memory barrier */
    Sin_ASR,         /* read/write ancillary state register */

    Sin_Call,        /* call address from register */

    Sin_XDirect,     /* direct transfer to GA */
    Sin_XIndir,      /* indirect transfer to GA */
    Sin_XAssisted,   /* assisted transfer to GA */

    Sin_AlignDataFp, /* align data */
    Sin_AluFp,       /* floating-point arithmetic/logical instruction */
    Sin_AbsFp,       /* floating-point absolute value */
    Sin_CmpFp,       /* floating-point compare */
    Sin_ConvFp,      /* convert floating-point */
    Sin_FusedFp,     /* floating-point fused multiply and add/sub */
    Sin_HalveFp,     /* takes either high or low half of a floating-point reg */
    Sin_MovIRegToFp, /* move integer reg to floating-point */
    Sin_MovFp,       /* move floating-point */
    Sin_MovFpICond,  /* move floating-point reg based on integer cond codes */
    Sin_MovFpToIReg, /* move floating-point reg to integer reg */
    Sin_NegFp,       /* negate floating-point value */
    Sin_ShftFp,      /* shift floating-point */
    Sin_ShuffleFp,   /* byte shuffle */
    Sin_SqrtFp,      /* floating-point square root value */

    Sin_EvCheck,     /* event check */
    Sin_ProfInc,     /* 64bit profile counter increment */

    /* The following are used to handle unrecognized instructions */
    Sin_LoadGuestState, /* load all registers from guest state */
    Sin_StoreGuestState,/* store all registers to guest state */
    Sin_Unrecognized /* unrecognized sparc instruction */

} SPARC64InstrTag;

typedef struct {
    SPARC64InstrTag tag;
    union {
        struct {
            HReg dst;
            ULong imm;
        } LI;
        struct {
            SPARC64AluOp op;
            HReg dst;
            HReg srcL;
            SPARC64RI *srcR;
        } Alu;
        struct {
            SPARC64ShftOp op;
            HReg dst;
            HReg srcL;
            SPARC64RI *srcR;
        } Shft;
        struct {
            UChar sz;
            HReg dst;
            SPARC64AMode *src;
	    SPARC64RI *asi;
            Bool toFsr;
        } Load;
        struct {
            UChar sz;
            SPARC64AMode *dst;
            HReg src;
            SPARC64RI *asi;
            Bool fromFsr;
        } Store;
        struct {
            SPARC64CondCode cond;
            HReg dst;
            HReg src;
        } MoveCond;
        struct {
            SPARC64RegCode cond;
            HReg dst;
            HReg srcL;
            SPARC64RI *srcR;
        } MoveReg;
        struct {
            UChar sz;   /* 4|8 */
            HReg  addr; /* rs1 */
            HReg  src;  /* rs2 */
            HReg  dst;
        } CAS;
        struct {
            SPARC64AMode *src;
            HReg dst;
        } Ldstub;
        struct {
            HReg dst;
            HReg src;
        } Lzcnt;
        struct {
            /* No fields. */
        } Membar;
        struct {
            Bool store;
            HReg srcL;
            SPARC64RI *srcR;
            UInt dst;  /* ASR reg number. VEX does not support it as a HReg. */
        } ASR;
        struct {
            SPARC64CondCode cond;
            HReg tgt;
            UInt argiregs;
            RetLoc rloc;
        } Call;
        struct {
            Addr64 dstGA;
            SPARC64AMode *amPC;
            SPARC64CondCode cond;
            Bool toFastEP;
        } XDirect;
        struct {
            HReg dstGA;
            SPARC64AMode *amPC;
            SPARC64CondCode cond;
        } XIndir;
        struct {
            HReg dstGA;
            SPARC64AMode *amPC;
            SPARC64CondCode cond;
            IRJumpKind jk;
        } XAssisted;
        struct {
            HReg dst;
            HReg srcL;
            HReg srcR;
        } AlignDataFp;
        struct {
            SPARC64AluFpOp op;
            HReg dst;
            HReg srcL;
            HReg srcR;
        } AluFp;
        struct {
            HReg dst;
            HReg src;
        } AbsFp;
        struct {
            HReg srcL;
            HReg srcR;
            UInt fccn;
        } CmpFp;
        struct {
            HReg dst;
            HReg src;
            Bool toInt;
            Bool fromInt;
        } ConvFp;
        struct {
            SPARC64FusedFpOp op;
            HReg dst;
            HReg arg1;
            HReg arg2;
            HReg arg3;
        } FusedFp;
        struct {
            HReg dst;
            HReg src;
            Bool highHalf;
        } HalveFp;
        struct {
            HReg dst;
            HReg src;
        } MovIRegToFp;
        struct {
            HReg dst;
            HReg src;
        } MovFp;
        struct {
            SPARC64CondCode cond;
            HReg dst;
            HReg src;
        } MovFpICond;
        struct {
            HReg dst;
            HReg src;
        } MovFpToIReg;
        struct {
            HReg dst;
            HReg src;
        } NegFp;
        struct {
            SPARC64ShftFpOp op;
            HReg dst;
            HReg srcL;
            HReg srcR;
        } ShftFp;
        struct {
            HReg dst;
            HReg srcL;
            HReg srcR;
        } ShuffleFp;
        struct {
            HReg dst;
            HReg src;
        } SqrtFp;
        struct {
            UInt offFailAddr; /* Offsets to the guest state. */
            UInt offCounter;
        } EvCheck;
        struct {
            /* No fields. */
        } ProfInc;
        struct {
            UInt instr_bits;
        } Unrecognized;
    } Sin;
} SPARC64Instr;

extern SPARC64Instr *SPARC64Instr_XDirect(Addr64 dstGA, SPARC64AMode *amPC,
                                          SPARC64CondCode cond, Bool toFastEP);
extern SPARC64Instr *SPARC64Instr_XIndir(HReg dstGA, SPARC64AMode *amPC,
                                         SPARC64CondCode cond);
extern SPARC64Instr *SPARC64Instr_XAssisted(HReg dstGA, SPARC64AMode *amPC,
                                            SPARC64CondCode cond, IRJumpKind jk);
extern SPARC64Instr *SPARC64Instr_AlignDataFp(HReg dst, HReg srcL, HReg srcR);
extern SPARC64Instr *SPARC64Instr_AluFp(SPARC64AluFpOp op, HReg dst, HReg srcL,
                                        HReg srcR);
extern SPARC64Instr *SPARC64Instr_AbsFp(HReg dst, HReg src);
extern SPARC64Instr *SPARC64Instr_CmpFp(HReg srcL, HReg srcR, UInt fccn);
extern SPARC64Instr *SPARC64Instr_ConvFp(HReg dst, HReg src, Bool fromInt,
                                         Bool toInt);
extern SPARC64Instr *SPARC64Instr_FusedFp(SPARC64FusedFpOp op, HReg dst,
                                          HReg arg1, HReg arg2, HReg arg3);
extern SPARC64Instr *SPARC64Instr_HalveFp(HReg dst, HReg src, Bool highHalf);
extern SPARC64Instr *SPARC64Instr_MovIRegToFp(HReg dst, HReg src);
extern SPARC64Instr *SPARC64Instr_MovFp(HReg dst, HReg src);
extern SPARC64Instr *SPARC64Instr_MovFpICond(SPARC64CondCode cond, HReg dst,
                                             HReg src);
extern SPARC64Instr *SPARC64Instr_MovFpToIReg(HReg dst, HReg src);
extern SPARC64Instr *SPARC64Instr_NegFp(HReg dst, HReg src);
extern SPARC64Instr *SPARC64Instr_ShftFp(SPARC64ShftFpOp op, HReg dst,
                                         HReg srcR, HReg srcL);
extern SPARC64Instr *SPARC64Instr_ShuffleFp(HReg dst, HReg srcL, HReg srcR);
extern SPARC64Instr *SPARC64Instr_SqrtFp(HReg dst, HReg src);
extern SPARC64Instr *SPARC64Instr_EvCheck(UInt offFailAddr, UInt offCounter);
extern SPARC64Instr *SPARC64Instr_ProfInc(void);
extern SPARC64Instr *SPARC64Instr_Unrecognized(UInt instr_bits);
extern SPARC64Instr *SPARC64Instr_LoadGuestState(void);
extern SPARC64Instr *SPARC64Instr_StoreGuestState(void);
extern SPARC64Instr *SPARC64Instr_Load(UChar sz, HReg dst, SPARC64AMode *src);
extern SPARC64Instr *SPARC64Instr_LoadA(UChar sz, HReg dst, SPARC64AMode *src,
    SPARC64RI *ri_asi);
extern SPARC64Instr *SPARC64Instr_LoadFSR(UChar sz, SPARC64AMode *src);
extern SPARC64Instr *SPARC64Instr_Store(UChar sz, SPARC64AMode *dst, HReg src);
extern SPARC64Instr *SPARC64Instr_StoreA(UChar sz, SPARC64AMode *dst, HReg src,
    SPARC64RI *ri_asi);
extern SPARC64Instr *SPARC64Instr_StoreFSR(UChar sz, SPARC64AMode *dst);
extern SPARC64Instr *SPARC64Instr_CAS(UChar sz, HReg addr, HReg src, HReg dst);
extern SPARC64Instr *SPARC64Instr_Ldstub(SPARC64AMode *src, HReg dst);
extern SPARC64Instr *SPARC64Instr_Lzcnt(HReg dst, HReg srcR);
extern SPARC64Instr *SPARC64Instr_Membar(void);
extern SPARC64Instr *SPARC64Instr_ASR(Bool store, UInt dst, HReg srcL,
                                      SPARC64RI *srcR);
extern SPARC64Instr *SPARC64Instr_Alu(SPARC64AluOp op, HReg dst, HReg srcL,
                                      SPARC64RI *srcR);
extern SPARC64Instr *SPARC64Instr_Shft(SPARC64ShftOp op, HReg dst, HReg srcL,
                                       SPARC64RI *srcR);
extern SPARC64Instr *SPARC64Instr_LI(HReg dst, ULong imm);
extern SPARC64Instr *SPARC64Instr_Call(SPARC64CondCode cond, HReg tgt,
                                       UInt argiregs, RetLoc rloc);
extern SPARC64Instr *SPARC64Instr_MoveCond(SPARC64CondCode cond, HReg dst, HReg src);
extern SPARC64Instr *SPARC64Instr_MoveReg(SPARC64RegCode cond, HReg dst,
                                          HReg srcL, SPARC64RI *srcR);
extern void ppSPARC64Instr(const SPARC64Instr *insn);

extern void getRegUsage_SPARC64Instr(HRegUsage *u, const SPARC64Instr *insn);
extern void mapRegs_SPARC64Instr    (HRegRemap *m, SPARC64Instr *insn);
extern Bool isMove_SPARC64Instr     (const SPARC64Instr *insn, HReg *src,
                                     HReg *dst);
extern int emit_SPARC64Instr        (/*MD_MOD*/ Bool *is_profInc,
                                     UChar *buf, Int nbuf,
				     const SPARC64Instr *i,
				     Bool mode64,
				     VexEndness endness_host,
				     const void *disp_cp_chain_me_to_slowEP,
				     const void *disp_cp_chain_me_to_fastEP,
				     const void *disp_cp_xindir,
				     const void *disp_cp_xassisted );
extern void genSpill_SPARC64(/*OUT*/ HInstr **i1, /*OUT*/ HInstr **i2,
                             HReg rreg, Int offset, Bool);
extern void genReload_SPARC64(/*OUT*/ HInstr **i1, /*OUT*/HInstr **i2,
                              HReg rreg, Int offset, Bool);

extern const RRegUniverse *getRRegUniverse_SPARC64(void);
extern HInstrArray *iselSB_SPARC64(const IRSB *bb,
                                   VexArch arch_host,
                                   const VexArchInfo *archinfo_host,
                                   const VexAbiInfo *vbi,
                                   Int offs_Host_EvC_Counter,
                                   Int offs_Host_EvC_FailAddr,
                                   Bool chainingAllowed,
                                   Bool addProfInc,
                                   Addr max_ga);

extern Int evCheckSzB_SPARC64(void);

/* Perform a chaining and unchaining of an XDirect jump. */
extern VexInvalRange chainXDirect_SPARC64(VexEndness endness_host,
                                          void *place_to_chain,
                                          const void *disp_cp_chain_me_EXPECTED,
                                          const void *place_to_jump_to);

extern VexInvalRange unchainXDirect_SPARC64(VexEndness endness_host,
                                            void *place_to_unchain,
                                            const void *place_to_jump_EXPECTED,
                                            const void *disp_cp_chain_me);

extern VexInvalRange patchProfInc_SPARC64(VexEndness endness_host,
                                          void *place_to_patch,
                                          const ULong *location_of_counter);

#endif /* __VEX_HOST_SPARC64_DEFS_H */

/*----------------------------------------------------------------------------*/
/*--- end                                              host_sparc64_defs.h ---*/
/*----------------------------------------------------------------------------*/
