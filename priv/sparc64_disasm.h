/*----------------------------------------------------------------------------*/
/*--- begin                                               sparc64_disasm.h ---*/
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

/* Copyright 2015-2015, Tomas Jedlicka <jedlickat@gmail.com> */

#ifndef __VEX_SPARC64_DISASM_H
#define __VEX_SPARC64_DISASM_H

#include "libvex_basictypes.h"

/* List of supported Ancillary State Register (ASR) codes. */
typedef enum
{
    SPARC64_ASR_Y        = 0,
    SPARC64_ASR_CCR      = 2,
    SPARC64_ASR_ASI      = 3,
    SPARC64_ASR_TICK     = 4,
    SPARC64_ASR_PC       = 5,
    SPARC64_ASR_FPRS     = 6,
    SPARC64_ASR_ENTROPY  = 13,
    SPARC64_ASR_MCDPER   = 14,
    SPARC64_ASR_GSR      = 19, /* TODO-SPARC: supported only partially */
    SPARC64_ASR_STICK    = 24,
    SPARC64_ASR_CFR      = 26,
    SPARC64_ASR_PAUSE    = 27,
    SPARC64_ASR_MWAIT    = 28
} SPARC64_ASR;

/* List of some Address Space Identifiers (ASIs).
   Default (implicit) for userspace is ASI_PRIMARY. */
typedef enum
{
    SPARC64_ASI_PRIMARY          = 0x80, /* implicit primary address space */
    SPARC64_ASI_SECONDARY        = 0x81, /* secondary address space */
    SPARC64_ASI_PRIMARY_NO_FAULT = 0x82, /* primary address space, no fault */
    SPARC64_ASI_FL8_PRIMARY      = 0xD0, /* primary address space, 8-bit float */
    SPARC64_ASI_FL16_PRIMARY     = 0xD2, /* primary address space, 16-bit float */
    SPARC64_ASI_BLOCK_PRIMARY    = 0xF0  /* primary address space, 64 bytes */
} SPARC64_ASI;

/* --------- Operands. --------- */

#define SPARC64_MAX_OPERANDS 4

/* Array sparc64_operands is sorted according to this enum. */
typedef enum
{
    SPARC64_OP_TYPE_FIRST = 0,
    SPARC64_OP_TYPE_RS2_OR_SIMM13,   /* meta: integer rs2_or_simm13 */
    SPARC64_OP_TYPE_RS2_OR_SIMM11,   /* meta: integer rs2_or_simm11 */
    SPARC64_OP_TYPE_RS2_OR_SIMM10,   /* meta: integer rs2_or_simm10 */
    SPARC64_OP_TYPE_RS2_OR_SIMM5,    /* meta: integer rs2_or_simm5 */
    SPARC64_OP_TYPE_RS2_OR_IMM8,     /* meta: integer rs2_or_imm8 */
    SPARC64_OP_TYPE_RS2_OR_SHCNT32,  /* meta: integer rs2_or_shcnt32 */
    SPARC64_OP_TYPE_RS2_OR_SHCNT64,  /* meta: integer rs2_or_shcnt64 */
    SPARC64_OP_TYPE_ASI_IMPL_OR_IMM, /* meta: ASI implicit (%asi) or imm_asi */
    SPARC64_OP_TYPE_IREG_RS1,        /* integer reg_rs1 */
    SPARC64_OP_TYPE_IREG_RS2,        /* integer reg_rs2 */
    SPARC64_OP_TYPE_IREG_RD,         /* integer reg_rd */
    SPARC64_OP_TYPE_IREG_RDIN,       /* integer reg_rd for stores */
    SPARC64_OP_TYPE_IREG_RDINOUT,    /* integer reg_rd for ldstub */
    SPARC64_OP_TYPE_FREG32_RS1,      /* floating-point single-precision rs1 */
    SPARC64_OP_TYPE_FREG64_RS1,      /* floating-point double-precision rs1 */
    SPARC64_OP_TYPE_FREG128_RS1,     /* floating-point quad-precision rs1 */
    SPARC64_OP_TYPE_FREG32_RS2,      /* floating-point single-precision rs2 */
    SPARC64_OP_TYPE_FREG64_RS2,      /* floating-point double-precision rs2 */
    SPARC64_OP_TYPE_FREG128_RS2,     /* floating-point quad-precision rs2 */
    SPARC64_OP_TYPE_FREG32_RS3,      /* floating-point single-precision rs3 */
    SPARC64_OP_TYPE_FREG64_RS3,      /* floating-point double-precision rs3 */
    SPARC64_OP_TYPE_FREG32_RD,       /* floating-point single-precision rd */
    SPARC64_OP_TYPE_FREG64_RD,       /* floating-point double-precision rd */
    SPARC64_OP_TYPE_FREG128_RD,      /* floating-point quad-precision rd */
    SPARC64_OP_TYPE_FREG32_RDIN,     /* floating-point rd for stores */
    SPARC64_OP_TYPE_FREG64_RDIN,     /* floating-point rd for stores */
    SPARC64_OP_TYPE_FREG128_RDIN,    /* floating-point rd for stores */
    SPARC64_OP_TYPE_SIMM13,          /* integer signed immediate on 13 bits */
    SPARC64_OP_TYPE_SIMM11,          /* integer signed immediate on 11 bits */
    SPARC64_OP_TYPE_SIMM10,          /* integer signed immediate on 10 bits */
    SPARC64_OP_TYPE_SIMM5,           /* integer signed immediate on 5 bits */
    SPARC64_OP_TYPE_IMM22,           /* immediate on 22 bits for sethi */
    SPARC64_OP_TYPE_IMM8,            /* integer immediate on 8 bits */
    SPARC64_OP_TYPE_IMM5,            /* integer immediate on 5 bits */
    SPARC64_OP_TYPE_ASI_IMPL,        /* ASI implicit (%asi register) */
    SPARC64_OP_TYPE_ASI_IMM,         /* Alternate Space Identifier on 8 bits */
    SPARC64_OP_TYPE_DISP30,          /* call displacement on 30 bits */
    SPARC64_OP_TYPE_DISP22,          /* branch displacement on 22 bits */
    SPARC64_OP_TYPE_DISP19,          /* branch displacement on 19 bits */
    SPARC64_OP_TYPE_DISP16,          /* branch displacement on 16 bits */
    SPARC64_OP_TYPE_DISP10,          /* CBcond branch displacement on 10 bits */
    SPARC64_OP_TYPE_SHCNT32,         /* integer shift count on 5 bits */
    SPARC64_OP_TYPE_SHCNT64,         /* integer shift count on 6 bits */
    SPARC64_OP_TYPE_I_OR_X_CC_BPcc,  /* CCR.icc (0) or CCR.xcc (1) for BPcc */
    SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc,/* CCR.icc (0) or CCR.xcc (1) for FMOVcc */
    SPARC64_OP_TYPE_I_OR_X_CC_MOVcc, /* CCR.icc (0) or CCR.xcc (1) for MOVcc */
    SPARC64_OP_TYPE_I_OR_X_CC_Tcc,   /* CCR.icc (0) or CCR.xcc (1) for Tcc */
    SPARC64_OP_TYPE_FCCn_FBPfcc,     /* %fccX for FBPfcc */
    SPARC64_OP_TYPE_FCCn_FCMP,       /* %fccX for FCMP */
    SPARC64_OP_TYPE_FCCn_FMOVcc,     /* %fccX (0-3) for FMOVcc */
    SPARC64_OP_TYPE_FCCn_MOVcc,      /* %fccX (0-3) for MOVcc */
    SPARC64_OP_TYPE_MMASK,           /* MEMBAR mmask on 4 bits */
    SPARC64_OP_TYPE_CMASK,           /* MEMBAR cmask on 3 bits */
    SPARC64_OP_TYPE_PREFETCH_FCN,    /* PREFETCH function codes on 5 bits */
    SPARC64_OP_TYPE_ANNUL,           /* annul bit for branches (1 = annulled) */
    SPARC64_OP_TYPE_PREDICTION,      /* prediction bit for branches (1 = pn) */
    SPARC64_OP_TYPE_LAST
} sparc64_operand_type;

/* Logical groups of operand types. Used only for querying operand indexes. */
typedef enum
{
    SPARC64_OP_TYPE_GROUP_NONE = 0,
    SPARC64_OP_TYPE_GROUP_RS1,
    SPARC64_OP_TYPE_GROUP_RS2_OR_IMM,
    SPARC64_OP_TYPE_GROUP_RS3,
    SPARC64_OP_TYPE_GROUP_RD,
    SPARC64_OP_TYPE_GROUP_ASI,
    SPARC64_OP_TYPE_GROUP_DISP,
    SPARC64_OP_TYPE_GROUP_IMM,
    SPARC64_OP_TYPE_GROUP_I_OR_X_CC,
    SPARC64_OP_TYPE_GROUP_FCCn,
    SPARC64_OP_TYPE_GROUP_PREFETCH_FCN,
    SPARC64_OP_TYPE_GROUP_ANNUL,
    SPARC64_OP_TYPE_GROUP_PREDICTION
} sparc64_operand_type_group;

typedef enum
{
    SPARC64_OP_KIND_IREG,
    SPARC64_OP_KIND_FREG,
    SPARC64_OP_KIND_IMM,
    SPARC64_OP_KIND_META
} sparc64_operand_kind;

typedef enum
{
    SPARC64_OP_SIZE_FREG32  =  4, /*  4 bytes, single-precision */
    SPARC64_OP_SIZE_FREG64  =  8, /*  8 bytes, double-precision */
    SPARC64_OP_SIZE_FREG128 = 16  /* 16 bytes, quad-precision */
} sparc64_operand_size;

typedef enum
{
    SPARC64_OP_VEX_TYPE_INT,
    SPARC64_OP_VEX_TYPE_UINT,
    SPARC64_OP_VEX_TYPE_LONG,
    SPARC64_OP_VEX_TYPE_ULONG,
    SPARC64_OP_VEX_TYPE_NONE /* for meta operands */
} sparc64_operand_vex_type;

typedef union
{
    Int   intval;
    UInt  uintval;
    Long  longval;
    ULong ulongval;
} sparc64_operand_value;

typedef struct sparc64_operand
{
    /* Operand type (ireg_rs2, ireg_simm13, ireg_rd, freg_rs1, asr_reg... */
    sparc64_operand_type type;

    /* Operand kind (register, immediate...). */
    sparc64_operand_kind kind;

    /* Operand type in VEX nomenclature (ULong, Int...). */
    sparc64_operand_vex_type vex_type;

    /* Is this operand meta-operand, such as reg_or_imm? */
    UChar is_meta : 1;

    /* How many bits is this value in natural format (not encoded)? */
    UInt num_bits : 6;

    /* Is this operand value signed? */
    UChar is_signed : 1;

    /* Is this operand a source? */
    UChar is_source : 1;

    /* Is this operand a destination? */
    UChar is_destination : 1;

    /* Operand size for floating-point registers.
       Not used for integer registers or immediates. */
    sparc64_operand_size op_size : 5;

    /* Decodes the operand and its value out of the instruction.
       'op_in' is the operand as found in sparc64_opcode.
       'value' is an output argument.
       Operand returned will be different from 'op_in', for example simm13
       instead of reg_or_imm.   */
    const struct sparc64_operand *(*decode)(UInt insn,
                                          const struct sparc64_operand *op_in,
                                          sparc64_operand_value *value);

    /* Returns the operand and its value encoded so it can be ORed with
       the encoded opcode. */
    UInt (*encode)(const struct sparc64_operand *operand,
                   sparc64_operand_value value);

    /* Prints value of the operand using vex_sprintf() into provided buffer.
       The buffer must be large enough. Unfortunately no way to tell
       the correct size. Returns the number bytes printed, excluding
       terminating '\0'. */
    UInt (*sprint)(HChar *buf, sparc64_operand_value value);
} sparc64_operand;

/* --------- Opcodes and instructions. --------- */

/* Array sparc64_opcodes is sorted according to this enum. */
typedef enum
{
    SPARC64_OPC_NONE = 0,
    /* 7.1 */
    SPARC64_OPC_ADD,
    SPARC64_OPC_ADDcc,
    SPARC64_OPC_ADDC,
    SPARC64_OPC_ADDCcc,
    /* 7.2 */
    SPARC64_OPC_ADDXC,
    SPARC64_OPC_ADDXCcc,
    /* 7.3 */
    SPARC64_OPC_AES_EROUND01,
    SPARC64_OPC_AES_EROUND23,
    SPARC64_OPC_AES_DROUND01,
    SPARC64_OPC_AES_DROUND23,
    SPARC64_OPC_AES_EROUND01_LAST,
    SPARC64_OPC_AES_EROUND23_LAST,
    SPARC64_OPC_AES_DROUND01_LAST,
    SPARC64_OPC_AES_DROUND23_LAST,
    SPARC64_OPC_AES_KEXPAND1,
    /* 7.4 */
    SPARC64_OPC_AES_KEXPAND0,
    SPARC64_OPC_AES_KEXPAND2,
    /* 7.5 */
    SPARC64_OPC_ALIGNADDRESS,
    /* 7.7 */
    SPARC64_OPC_AND,
    SPARC64_OPC_ANDcc,
    SPARC64_OPC_ANDN,
    SPARC64_OPC_ANDNcc,
    /* 7.9 */
    SPARC64_OPC_BA,
    SPARC64_OPC_BN,
    SPARC64_OPC_BNE,
    SPARC64_OPC_BE,
    SPARC64_OPC_BG,
    SPARC64_OPC_BLE,
    SPARC64_OPC_BGE,
    SPARC64_OPC_BL,
    SPARC64_OPC_BGU,
    SPARC64_OPC_BLEU,
    SPARC64_OPC_BCC,
    SPARC64_OPC_BCS,
    SPARC64_OPC_BPOS,
    SPARC64_OPC_BNEG,
    SPARC64_OPC_BVC,
    SPARC64_OPC_BVS,
    /* 7.10 */
    SPARC64_OPC_BMASK,
    SPARC64_OPC_BSHUFFLE,
    /* 7.11 */
    SPARC64_OPC_BPA,
    SPARC64_OPC_BPN,
    SPARC64_OPC_BPNE,
    SPARC64_OPC_BPE,
    SPARC64_OPC_BPG,
    SPARC64_OPC_BPLE,
    SPARC64_OPC_BPGE,
    SPARC64_OPC_BPL,
    SPARC64_OPC_BPGU,
    SPARC64_OPC_BPLEU,
    SPARC64_OPC_BPCC,
    SPARC64_OPC_BPCS,
    SPARC64_OPC_BPPOS,
    SPARC64_OPC_BPNEG,
    SPARC64_OPC_BPVC,
    SPARC64_OPC_BPVS,
    /* 7.12 */
    SPARC64_OPC_BRZ,
    SPARC64_OPC_BRLEZ,
    SPARC64_OPC_BRLZ,
    SPARC64_OPC_BRNZ,
    SPARC64_OPC_BRGZ,
    SPARC64_OPC_BRGEZ,
    /* 7.13 */
    SPARC64_OPC_CALL,
    /* 7.16 */
    SPARC64_OPC_CASA,
    SPARC64_OPC_CASXA,
    /* 7.17 */
    SPARC64_OPC_CWBNE,
    SPARC64_OPC_CWBE,
    SPARC64_OPC_CWBG,
    SPARC64_OPC_CWBLE,
    SPARC64_OPC_CWBGE,
    SPARC64_OPC_CWBL,
    SPARC64_OPC_CWBGU,
    SPARC64_OPC_CWBLEU,
    SPARC64_OPC_CWBCC,
    SPARC64_OPC_CWBCS,
    SPARC64_OPC_CWBPOS,
    SPARC64_OPC_CWBNEG,
    SPARC64_OPC_CWBVC,
    SPARC64_OPC_CWBVS,
    SPARC64_OPC_CXBNE,
    SPARC64_OPC_CXBE,
    SPARC64_OPC_CXBG,
    SPARC64_OPC_CXBLE,
    SPARC64_OPC_CXBGE,
    SPARC64_OPC_CXBL,
    SPARC64_OPC_CXBGU,
    SPARC64_OPC_CXBLEU,
    SPARC64_OPC_CXBCC,
    SPARC64_OPC_CXBCS,
    SPARC64_OPC_CXBPOS,
    SPARC64_OPC_CXBNEG,
    SPARC64_OPC_CXBVC,
    SPARC64_OPC_CXBVS,
    /* 7.25 */
    SPARC64_OPC_FABSs,
    SPARC64_OPC_FABSd,
    SPARC64_OPC_FABSq,
    /* 7.26 */
    SPARC64_OPC_FADDs,
    SPARC64_OPC_FADDd,
    SPARC64_OPC_FADDq,
    /* 7.27 */
    SPARC64_OPC_FALIGNDATAg,
    /* 7.30 */
    SPARC64_OPC_FBPA,
    SPARC64_OPC_FBPN,
    SPARC64_OPC_FBPU,
    SPARC64_OPC_FBPG,
    SPARC64_OPC_FBPUG,
    SPARC64_OPC_FBPL,
    SPARC64_OPC_FBPUL,
    SPARC64_OPC_FBPLG,
    SPARC64_OPC_FBPNE,
    SPARC64_OPC_FBPE,
    SPARC64_OPC_FBPUE,
    SPARC64_OPC_FBPGE,
    SPARC64_OPC_FBPUGE,
    SPARC64_OPC_FBPLE,
    SPARC64_OPC_FBPULE,
    SPARC64_OPC_FBPO,
    /* 7.32 */
    SPARC64_OPC_FCMPs,
    SPARC64_OPC_FCMPd,
    SPARC64_OPC_FCMPq,
    SPARC64_OPC_FCMPEs,
    SPARC64_OPC_FCMPEd,
    SPARC64_OPC_FCMPEq,
    /* 7.33 */
    SPARC64_OPC_FDIVs,
    SPARC64_OPC_FDIVd,
    SPARC64_OPC_FDIVq,
    /* 7.37 */
    SPARC64_OPC_FiTOs,
    SPARC64_OPC_FiTOd,
    SPARC64_OPC_FiTOq,
    /* 7.39 */
    SPARC64_OPC_FLUSH,
    /* 7.40 */
    SPARC64_OPC_FLUSHW,
    /* 7.41 */
    SPARC64_OPC_FMADDs,
    SPARC64_OPC_FMADDd,
    SPARC64_OPC_FMSUBs,
    SPARC64_OPC_FMSUBd,
    SPARC64_OPC_FNMSUBs,
    SPARC64_OPC_FNMSUBd,
    SPARC64_OPC_FNMADDs,
    SPARC64_OPC_FNMADDd,
    /* 7.43 */
    SPARC64_OPC_FMOVs,
    SPARC64_OPC_FMOVd,
    SPARC64_OPC_FMOVq,
    /* 7.44 */
    /* First operand is SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc. */
    SPARC64_OPC_FMOVSiccA,
    SPARC64_OPC_FMOVSiccN,
    SPARC64_OPC_FMOVSiccNE,
    SPARC64_OPC_FMOVSiccE,
    SPARC64_OPC_FMOVSiccG,
    SPARC64_OPC_FMOVSiccLE,
    SPARC64_OPC_FMOVSiccGE,
    SPARC64_OPC_FMOVSiccL,
    SPARC64_OPC_FMOVSiccGU,
    SPARC64_OPC_FMOVSiccLEU,
    SPARC64_OPC_FMOVSiccCC,
    SPARC64_OPC_FMOVSiccCS,
    SPARC64_OPC_FMOVSiccPOS,
    SPARC64_OPC_FMOVSiccNEG,
    SPARC64_OPC_FMOVSiccVC,
    SPARC64_OPC_FMOVSiccVS,
    SPARC64_OPC_FMOVDiccA,
    SPARC64_OPC_FMOVDiccN,
    SPARC64_OPC_FMOVDiccNE,
    SPARC64_OPC_FMOVDiccE,
    SPARC64_OPC_FMOVDiccG,
    SPARC64_OPC_FMOVDiccLE,
    SPARC64_OPC_FMOVDiccGE,
    SPARC64_OPC_FMOVDiccL,
    SPARC64_OPC_FMOVDiccGU,
    SPARC64_OPC_FMOVDiccLEU,
    SPARC64_OPC_FMOVDiccCC,
    SPARC64_OPC_FMOVDiccCS,
    SPARC64_OPC_FMOVDiccPOS,
    SPARC64_OPC_FMOVDiccNEG,
    SPARC64_OPC_FMOVDiccVC,
    SPARC64_OPC_FMOVDiccVS,
    SPARC64_OPC_FMOVQiccA,
    SPARC64_OPC_FMOVQiccN,
    SPARC64_OPC_FMOVQiccNE,
    SPARC64_OPC_FMOVQiccE,
    SPARC64_OPC_FMOVQiccG,
    SPARC64_OPC_FMOVQiccLE,
    SPARC64_OPC_FMOVQiccGE,
    SPARC64_OPC_FMOVQiccL,
    SPARC64_OPC_FMOVQiccGU,
    SPARC64_OPC_FMOVQiccLEU,
    SPARC64_OPC_FMOVQiccCC,
    SPARC64_OPC_FMOVQiccCS,
    SPARC64_OPC_FMOVQiccPOS,
    SPARC64_OPC_FMOVQiccNEG,
    SPARC64_OPC_FMOVQiccVC,
    SPARC64_OPC_FMOVQiccVS,
    /* First operand is SPARC64_OP_TYPE_FCCn_FMOVcc. */
    SPARC64_OPC_FMOVSfccA,
    SPARC64_OPC_FMOVSfccN,
    SPARC64_OPC_FMOVSfccU,
    SPARC64_OPC_FMOVSfccG,
    SPARC64_OPC_FMOVSfccUG,
    SPARC64_OPC_FMOVSfccL,
    SPARC64_OPC_FMOVSfccUL,
    SPARC64_OPC_FMOVSfccLG,
    SPARC64_OPC_FMOVSfccNE,
    SPARC64_OPC_FMOVSfccE,
    SPARC64_OPC_FMOVSfccUE,
    SPARC64_OPC_FMOVSfccGE,
    SPARC64_OPC_FMOVSfccUGE,
    SPARC64_OPC_FMOVSfccLE,
    SPARC64_OPC_FMOVSfccULE,
    SPARC64_OPC_FMOVSfccO,
    SPARC64_OPC_FMOVDfccA,
    SPARC64_OPC_FMOVDfccN,
    SPARC64_OPC_FMOVDfccU,
    SPARC64_OPC_FMOVDfccG,
    SPARC64_OPC_FMOVDfccUG,
    SPARC64_OPC_FMOVDfccL,
    SPARC64_OPC_FMOVDfccUL,
    SPARC64_OPC_FMOVDfccLG,
    SPARC64_OPC_FMOVDfccNE,
    SPARC64_OPC_FMOVDfccE,
    SPARC64_OPC_FMOVDfccUE,
    SPARC64_OPC_FMOVDfccGE,
    SPARC64_OPC_FMOVDfccUGE,
    SPARC64_OPC_FMOVDfccLE,
    SPARC64_OPC_FMOVDfccULE,
    SPARC64_OPC_FMOVDfccO,
    SPARC64_OPC_FMOVQfccA,
    SPARC64_OPC_FMOVQfccN,
    SPARC64_OPC_FMOVQfccU,
    SPARC64_OPC_FMOVQfccG,
    SPARC64_OPC_FMOVQfccUG,
    SPARC64_OPC_FMOVQfccL,
    SPARC64_OPC_FMOVQfccUL,
    SPARC64_OPC_FMOVQfccLG,
    SPARC64_OPC_FMOVQfccNE,
    SPARC64_OPC_FMOVQfccE,
    SPARC64_OPC_FMOVQfccUE,
    SPARC64_OPC_FMOVQfccGE,
    SPARC64_OPC_FMOVQfccUGE,
    SPARC64_OPC_FMOVQfccLE,
    SPARC64_OPC_FMOVQfccULE,
    SPARC64_OPC_FMOVQfccO,
    /* 7.47 */
    SPARC64_OPC_FMULs,
    SPARC64_OPC_FMULd,
    SPARC64_OPC_FMULq,
    SPARC64_OPC_FsMULd,
    SPARC64_OPC_FdMULq,
    /* 7.49 */
    SPARC64_OPC_FNEGs,
    SPARC64_OPC_FNEGd,
    SPARC64_OPC_FNEGq,
    /* 7.63 */
    SPARC64_OPC_FZEROs,
    SPARC64_OPC_FZEROd,
    SPARC64_OPC_FONEs,
    SPARC64_OPC_FONEd,
    /* 7.64 */
    SPARC64_OPC_FSRC1d,
    SPARC64_OPC_FSRC1s,
    SPARC64_OPC_FSRC2d,
    SPARC64_OPC_FSRC2s,
    SPARC64_OPC_FNOT1d,
    SPARC64_OPC_FNOT1s,
    SPARC64_OPC_FNOT2d,
    SPARC64_OPC_FNOT2s,
    /* 7.65 */
    SPARC64_OPC_FORd,
    SPARC64_OPC_FORs,
    SPARC64_OPC_FNORd,
    SPARC64_OPC_FNORs,
    SPARC64_OPC_FANDd,
    SPARC64_OPC_FANDs,
    SPARC64_OPC_FNANDd,
    SPARC64_OPC_FNANDs,
    SPARC64_OPC_FXORd,
    SPARC64_OPC_FXORs,
    SPARC64_OPC_FXNORd,
    SPARC64_OPC_FXNORs,
    SPARC64_OPC_FORNOT1d,
    SPARC64_OPC_FORNOT1s,
    SPARC64_OPC_FORNOT2d,
    SPARC64_OPC_FORNOT2s,
    SPARC64_OPC_FANDNOT1d,
    SPARC64_OPC_FANDNOT1s,
    SPARC64_OPC_FANDNOT2d,
    SPARC64_OPC_FANDNOT2s,
    /* 7.66 */
    SPARC64_OPC_FSLL16,
    SPARC64_OPC_FSRL16,
    SPARC64_OPC_FSLL32,
    SPARC64_OPC_FSRL32,
    SPARC64_OPC_FSLAS16,
    SPARC64_OPC_FSRA16,
    SPARC64_OPC_FSLAS32,
    SPARC64_OPC_FSRA32,
    /* 7.67 */
    SPARC64_OPC_FSQRTs,
    SPARC64_OPC_FSQRTd,
    SPARC64_OPC_FSQRTq,
    /* 7.68 */
    SPARC64_OPC_FsTOx,
    SPARC64_OPC_FdTOx,
    SPARC64_OPC_FqTOx,
    SPARC64_OPC_FsTOi,
    SPARC64_OPC_FdTOi,
    SPARC64_OPC_FqTOi,
    /* 7.69 */
    SPARC64_OPC_FsTOd,
    SPARC64_OPC_FsTOq,
    SPARC64_OPC_FdTOs,
    SPARC64_OPC_FdTOq,
    SPARC64_OPC_FqTOs,
    SPARC64_OPC_FqTOd,
    /* 7.70 */
    SPARC64_OPC_FSUBs,
    SPARC64_OPC_FSUBd,
    SPARC64_OPC_FSUBq,
    /* 7.71 */
    SPARC64_OPC_FxTOs,
    SPARC64_OPC_FxTOd,
    SPARC64_OPC_FxTOq,
    /* 7.75 */
    SPARC64_OPC_JMPL,
    /* 7.77 */
    SPARC64_OPC_LDSB,
    SPARC64_OPC_LDSH,
    SPARC64_OPC_LDSW,
    SPARC64_OPC_LDUB,
    SPARC64_OPC_LDUH,
    SPARC64_OPC_LDUW,
    SPARC64_OPC_LDX,
    /* 7.78 */
    SPARC64_OPC_LDSBA,
    SPARC64_OPC_LDSHA,
    SPARC64_OPC_LDSWA,
    SPARC64_OPC_LDUBA,
    SPARC64_OPC_LDUHA,
    SPARC64_OPC_LDUWA,
    SPARC64_OPC_LDXA,
    /* 7.79 */
    SPARC64_OPC_LDBLOCKF,
    /* 7.80 */
    SPARC64_OPC_LDF,
    SPARC64_OPC_LDDF,
    SPARC64_OPC_LDQF,
    /* 7.81 */
    SPARC64_OPC_LDFA,
    SPARC64_OPC_LDDFA,
    SPARC64_OPC_LDQFA,
    /* 7.82 - use '0' for the third operand (rd). */
    SPARC64_OPC_LDFSR,
    /* 7.81 */
    SPARC64_OPC_LDSHORTF,
    /* 7.84 */
    SPARC64_OPC_LDSTUB,
    /* 7.89 - use '1' for the third operand (rd). */
    SPARC64_OPC_LDXFSR,
    /* 7.90 */
    SPARC64_OPC_LZCNT,
    /* 7.91 */
    SPARC64_OPC_MD5,
    /* 7.92 */
    SPARC64_OPC_MEMBAR,
    /* 7.95 */
    /* First operand is SPARC64_OP_TYPE_I_OR_X_CC_MOVcc. */
    SPARC64_OPC_MOVA,
    SPARC64_OPC_MOVN,
    SPARC64_OPC_MOVNE,
    SPARC64_OPC_MOVE,
    SPARC64_OPC_MOVG,
    SPARC64_OPC_MOVLE,
    SPARC64_OPC_MOVGE,
    SPARC64_OPC_MOVL,
    SPARC64_OPC_MOVGU,
    SPARC64_OPC_MOVLEU,
    SPARC64_OPC_MOVCC,
    SPARC64_OPC_MOVCS,
    SPARC64_OPC_MOVPOS,
    SPARC64_OPC_MOVNEG,
    SPARC64_OPC_MOVVC,
    SPARC64_OPC_MOVVS,
    /* First operand is SPARC64_OP_TYPE_FCCn_MOVcc. */
    SPARC64_OPC_MOVFA,
    SPARC64_OPC_MOVFN,
    SPARC64_OPC_MOVFU,
    SPARC64_OPC_MOVFG,
    SPARC64_OPC_MOVFUG,
    SPARC64_OPC_MOVFL,
    SPARC64_OPC_MOVFUL,
    SPARC64_OPC_MOVFLG,
    SPARC64_OPC_MOVFNE,
    SPARC64_OPC_MOVFE,
    SPARC64_OPC_MOVFUE,
    SPARC64_OPC_MOVFGE,
    SPARC64_OPC_MOVFUGE,
    SPARC64_OPC_MOVFLE,
    SPARC64_OPC_MOVFULE,
    SPARC64_OPC_MOVFO,
    /* 7.96 */
    SPARC64_OPC_MOVRZ,
    SPARC64_OPC_MOVRLEZ,
    SPARC64_OPC_MOVRLZ,
    SPARC64_OPC_MOVRNZ,
    SPARC64_OPC_MOVRGZ,
    SPARC64_OPC_MOVRGEZ,
    /* 7.97 */
    SPARC64_OPC_MOVsTOsw,
    SPARC64_OPC_MOVsTOuw,
    SPARC64_OPC_MOVdTOx,
    /* 7.98 */
    SPARC64_OPC_MOVwTOs,
    SPARC64_OPC_MOVxTOd,
    /* 7.101 */
    SPARC64_OPC_MULX,
    SPARC64_OPC_SDIVX,
    SPARC64_OPC_UDIVX,
    /* 7.103 */
    SPARC64_OPC_NOP,
    /* 7.105 */
    SPARC64_OPC_OR,
    SPARC64_OPC_ORcc,
    SPARC64_OPC_ORN,
    SPARC64_OPC_ORNcc,
    /* 7.111 */
    SPARC64_OPC_PREFETCH,
    SPARC64_OPC_PREFETCHA,
    /* 7.112 */
    /* Use sparc64_get_asr_value() or corresponding SPARC64_ASR value
       for the first operand. */
    SPARC64_OPC_RDY,
    SPARC64_OPC_RDCCR,
    SPARC64_OPC_RDASI,
    SPARC64_OPC_RDTICK,
    SPARC64_OPC_RDPC,
    SPARC64_OPC_RDFPRS,
    SPARC64_OPC_RDENTROPY,
    SPARC64_OPC_RDMCDPER,
    SPARC64_OPC_RDGSR,
    SPARC64_OPC_RDSTICK,
    SPARC64_OPC_RDCFR,
    /* 7.115 */
    SPARC64_OPC_RESTORE,
    /* 7.118 */
    SPARC64_OPC_RETURN,
    /* 7.119 */
    SPARC64_OPC_SAVE,
    /* 7.121 */
    SPARC64_OPC_SDIV,
    SPARC64_OPC_SDIVcc,
    /* 7.122 */
    SPARC64_OPC_SETHI,
    /* 7.124 */
    SPARC64_OPC_SHA1,
    SPARC64_OPC_SHA256,
    SPARC64_OPC_SHA512,
    /* 7.127 */
    SPARC64_OPC_SLL,
    SPARC64_OPC_SRL,
    SPARC64_OPC_SRA,
    SPARC64_OPC_SLLX,
    SPARC64_OPC_SRLX,
    SPARC64_OPC_SRAX,
    /* 7.128 */
    SPARC64_OPC_SMUL,
    SPARC64_OPC_SMULcc,
    /* 7.129 */
    SPARC64_OPC_STB,
    SPARC64_OPC_STH,
    SPARC64_OPC_STW,
    SPARC64_OPC_STX,
    /* 7.130 */
    SPARC64_OPC_STBA,
    SPARC64_OPC_STHA,
    SPARC64_OPC_STWA,
    SPARC64_OPC_STXA,
    /* 7.133 */
    SPARC64_OPC_STF,
    SPARC64_OPC_STDF,
    SPARC64_OPC_STQF,
    /* 7.135 - use '0' for the first operand (rd). */
    SPARC64_OPC_STFSR,
    /* 7.140 - use '1' for the first operand (rd). */
    SPARC64_OPC_STXFSR,
    /* 7.141 */
    SPARC64_OPC_SUB,
    SPARC64_OPC_SUBcc,
    SPARC64_OPC_SUBC,
    SPARC64_OPC_SUBCcc,
    /* 7.144 */
    SPARC64_OPC_SWAP,
    /* 7.147 */
    SPARC64_OPC_TA,
    SPARC64_OPC_TN,
    SPARC64_OPC_TNE,
    SPARC64_OPC_TE,
    SPARC64_OPC_TG,
    SPARC64_OPC_TLE,
    SPARC64_OPC_TGE,
    SPARC64_OPC_TL,
    SPARC64_OPC_TGU,
    SPARC64_OPC_TLEU,
    SPARC64_OPC_TCC,
    SPARC64_OPC_TCS,
    SPARC64_OPC_TPOS,
    SPARC64_OPC_TNEG,
    SPARC64_OPC_TVC,
    SPARC64_OPC_TVS,
    /* 7.151 */
    SPARC64_OPC_UDIV,
    SPARC64_OPC_UDIVcc,
    /* 7.152 */
    SPARC64_OPC_UMUL,
    SPARC64_OPC_UMULcc,
    /* 7.152 */
    SPARC64_OPC_UMULXHI,
    /* 7.153 */
    /* Use sparc64_get_asr_value() or corresponding SPARC64_ASR value
       for the first operand. */
    SPARC64_OPC_WRY,
    SPARC64_OPC_WRCCR,
    SPARC64_OPC_WRASI,
    SPARC64_OPC_WRFPRS,
    SPARC64_OPC_WRMCDPER,
    SPARC64_OPC_WRGSR,
    SPARC64_OPC_WRPAUSE,
    SPARC64_OPC_WRMWAIT,
    /* 7.159 */
    SPARC64_OPC_XMULX,
    SPARC64_OPC_XMULXHI,
    /* 7.160 */
    SPARC64_OPC_XOR,
    SPARC64_OPC_XORcc,
    SPARC64_OPC_XNOR,
    SPARC64_OPC_XNORcc,

    SPARC64_OPC_LAST
} sparc64_mnemonic;

typedef enum
{
    /* Takes no side inputs and produces no side outputs. */
    SPARC64_OPF_NONE = 0x0,
    /* Updates %ccr, that is ccr.icc and ccr.xcc. */
    SPARC64_OPF_CCR_OUT = 0x1,
    /* Control transfer instruction. Updates PC/NPC explicitly. */
    SPARC64_OPF_CTI = 0x2,
    /* Delayed control transfer instruction (has branch delay slot). */
    SPARC64_OPF_dCTI = 0x4 | SPARC64_OPF_CTI,
    /* Updates %o7 (register 15). */
    SPARC64_OPF_O7_OUT = 0x8,
    /* Takes %ccr carry bit (either icc.c or xcc.c) on input. */
    SPARC64_OPF_CCR_CARRY_IN = 0x10,
    /* Takes %ccr overflow bit (either icc.v or xcc.v) on input. */
    SPARC64_OPF_CCR_OVERFLOW_IN = 0x20,
    /* Takes %ccr zero bit (either icc.z or xcc.z) on input. */
    SPARC64_OPF_CCR_ZERO_IN = 0x40,
    /* Takes %ccr negative bit (either icc.n or xcc.n) on input. */
    SPARC64_OPF_CCR_NEGATIVE_IN = 0x80,
    /* Updates %y. */
    SPARC64_OPF_Y_OUT = 0x100,
    /* Takes %y on input. */
    SPARC64_OPF_Y_IN = 0x200,
    /* Affects the current register window pointer. */
    SPARC64_OPF_CWP = 0x400,
    /* Updates %fsr. */
    SPARC64_OPF_FSR_OUT = 0x800,
    /* Takes %fsr rounding mode (FSR.rd) on input. */
    SPARC64_OPF_FSR_RD_IN = 0x1000,
    /* Takes one of FSR.fccX condition codes (E,L,G,U) on input. */
    SPARC64_OPF_FSR_FCC_IN = 0x2000,
    /* Updates %gsr. */
    SPARC64_OPF_GSR_OUT = 0x4000,
    /* Takes %gsr align field (GSR.align) on input. */
    SPARC64_OPF_GSR_ALIGN_IN = 0x8000,
    /* Takes %gsr mask field (GSR.mask) on input. */
    SPARC64_OPF_GSR_MASK_IN = 0x10000
} sparc64_opcode_flags;

#define SPARC64_OPF_CCR_IN \
    (SPARC64_OPF_CCR_CARRY_IN | SPARC64_OPF_CCR_OVERFLOW_IN | \
     SPARC64_OPF_CCR_ZERO_IN | SPARC64_OPF_CCR_NEGATIVE_IN)

/* Forward declaration. */
typedef struct sparc64_insn sparc64_insn;

typedef struct sparc64_opcode
{
    const HChar *name; /* textual mnemonic */
    sparc64_mnemonic mnemonic;  /* enum value for the mnemonic */

    /* Opcode encoding. Ready to be ORed with encoded operands. */
    UInt encoding;

    /* The lowest hwcaps necessary to run this instruction.
       One of VEX_HWCAPS_SPARC64_* values; see libvex.h. */
    UInt hwcaps;

    /* Side inputs or outputs of the opcode. */
    sparc64_opcode_flags flags;

    UChar num_operands; /* how many operands? */

    /* Index into array of operands sparc64_operands. */
    sparc64_operand_type operands[SPARC64_MAX_OPERANDS];

    /* Prints an instruction using vex_sprintf() into provided buffer.
       The buffer must be large enough. Unfortunately no way to tell
       the correct size. Returns the number bytes printed, excluding
       terminating '\0'. */
    UInt (*sprint)(HChar *buf, const sparc64_insn *insn);
} sparc64_opcode;

/* A decoded sparc64 instruction. This is a generic representation.
   For ease of use, there are overlay type definitions for the most common
   instructions, such as loads, stores, arithmetic and logic ones.
   See below. */
struct sparc64_insn
{
    const sparc64_opcode *opcode; /* opcode */

    /* Pointers into array of operands sparc64_operands. */
    const sparc64_operand *operands[SPARC64_MAX_OPERANDS];

    /* Actual operand values. */
    sparc64_operand_value operand_values[SPARC64_MAX_OPERANDS];
};

/* Overlay for arithmetic and logic instructions (add, addcc, addc, addccc, and,
   andcc, andn, andncc, mulx, or, orcc, orn, orncc, restore, save, sll, srl,
   sra, srllx, srlx, srax, sdivx, sub, subcc, subc, subccc, udivx, umulxhi,
   xmulx, xmulxhi, xor, xorcc, xnor, xnorcc). */
typedef struct
{
    const sparc64_opcode *opcode;

    const sparc64_operand *op_rs1;
    const sparc64_operand *op_rs2_imm;
    const sparc64_operand *op_rd;
    const sparc64_operand *unused_1;

    sparc64_operand_value val_rs1;    /* uintval */
    /* uintval for rs2 and shcnt, longval for simm13 */
    sparc64_operand_value val_rs2_imm;
    sparc64_operand_value val_rd;     /* uintval */
    sparc64_operand_value unused_2;
} sparc64_insn_al;

/* Overlay for integer loads (ldsb, ldsh, ldsw, ldub, lduh, lduh, ldx, ldfsr,
   ldxfsr). */
typedef struct
{
    const sparc64_opcode *opcode;

    const sparc64_operand *op_rs1;
    const sparc64_operand *op_rs2_imm;
    const sparc64_operand *op_rd;
    const sparc64_operand *unused_1;

    sparc64_operand_value val_rs1;     /* uintval */
    sparc64_operand_value val_rs2_imm; /* uintval for rs2, longval for simm13 */
    sparc64_operand_value val_rd;      /* uintval */
    sparc64_operand_value unused_2;
} sparc64_insn_load;

/* Overlay for integer stores (stb, sth, stw, stx, stfsr, stxfsr). */
typedef struct
{
    const sparc64_opcode *opcode;

    const sparc64_operand *op_rdin;
    const sparc64_operand *op_rs1;
    const sparc64_operand *op_rs2_imm;
    const sparc64_operand *unused_1;

    sparc64_operand_value val_rdin;    /* uintval */
    sparc64_operand_value val_rs1;     /* uintval */
    sparc64_operand_value val_rs2_imm; /* uintval for rs2, longval for simm13 */
    sparc64_operand_value unused_2;
} sparc64_insn_store;


/* --------- Public API functions. --------- */

/* Decodes a single instruction into the provided structure.
   Returns 'False' if the instruction cannot be decoded, and decoded->opcode
   points to an opcode with SPARC64_OPC_NONE mnemonic. If the instruction is
   not recognized, and is not a call, branch, SIAM, or other cases,
   we may be able to execute it in an isolated block, so
   *handle_unrecognized is set to True.

   Returns 'True' on success. Regardless, the caller should check hwcaps
   if this instruction is allowed to execute on the current hardware. */
extern Bool sparc64_decode_insn(UInt insn, sparc64_insn *decoded,
                                Bool *handle_unrecognized);

/* Prints a decoded instruction into provided buffer using vex_sprintf().
   The buffer must be large enough. Unfortunately no way to tell the correct
   size. Returns the number bytes printed, excluding terminating '\0'. */
extern UInt sparc64_sprint_insn(HChar *buf, const sparc64_insn *insn);

/* Combines sparc64_decode_insn() and sparc64_sprint_insn(). */
extern UInt sparc64_decode_and_sprint_insn(HChar *buf, UInt insn);

/* Encodes a single instruction from the provided structure. */
extern UInt sparc64_encode_insn(const sparc64_insn *insn);

/* Constructs a sparc64 instruction out of its mnemonic and a list of operands.
   Takes a variadic number of operand types and their values - exact number
   depends on the opcode. In case the opcode does not take any operands just
   pass in some garbage for the first operand type and value. */
extern void sparc64_make_insn(sparc64_insn *insn,
                              sparc64_mnemonic mnemonic,
                              ...);

/* Compares two sparc64 instructions, their operands and values.
   Beware that the following instructions share the same opcode and are
   distinguished by ASI: LDBLOCKF, LDDFA, LDSHORTF.
   This function considers these instructions as indistinguishable if they
   refer to implicit %asi. */
extern Bool sparc64_cmp_insn(const sparc64_insn *a, const sparc64_insn *b);

/* Gets ASR value for the given RDasr or WRasr mnemonic. */
extern SPARC64_ASR sparc64_get_asr_value(sparc64_mnemonic mnemonic);

/* Gets index of the corresponding operand for the given opcode mnemonic.
   Returns an index in range [0..SPARC64_MAX_OPERANDS].
   Returns (UInt) -1 when the operand type group is not applicable for
   the given mnemonic.

   Note that for ease of use, there are also type definition overlays for
   the most common instructions. See for example sparc64_insn_load and
   sparc64_insn_store. */
extern UInt sparc64_get_operand_index(sparc64_mnemonic mnemonic,
                                      sparc64_operand_type_group op_type_group);

/* Finds opcode of an instruction.
   Returns opcode on success; 'NULL' on failure. */
extern const sparc64_opcode *sparc64_find_opcode(UInt insn);

/* Returns a textual representation suitable for tossing at gcc compiler;
   or NULL if not found. */
extern const HChar *sparc64_asi_name(SPARC64_ASI asi);

/* --------- Private functions (for testing only). --------- */

/* Gets an opcode corresponding to the mnemonic. Returns NULL if not found. */
extern const sparc64_opcode *sparc64_get_opcode(sparc64_mnemonic mnemonic);

/* Gets an operand corresponding to the operand type.
   Returns NULL if not found. */
extern const sparc64_operand *sparc64_get_operand(sparc64_operand_type type);

#endif /* __VEX_SPARC64_DISASM_H */

/*----------------------------------------------------------------------------*/
/*--- end                                                 sparc64_disasm.h ---*/
/*----------------------------------------------------------------------------*/
