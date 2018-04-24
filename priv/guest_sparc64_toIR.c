/*----------------------------------------------------------------------------*/
/*--- begin                                           guest_sparc64_toIR.c ---*/
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

/* Translates SPARC64 code to IR */

#include "sparc64_disasm.h"
#include "libvex_ir.h"
#include "libvex.h"
#include "libvex_guest_sparc64.h"
#include "libvex_guest_offsets.h"

#include "main_util.h"
#include "main_globals.h"
#include "guest_generic_bb_to_IR.h"
#include "guest_sparc64_defs.h"

/* "Special" instructions.

   One special instruction is recognized which means nothing natively
   (is a no-op as far as regs/mem are concerned) but have meaning for supporting
   Valgrind. A special instruction is flagged by this 4-byte preamble:
       81 39 90 07  (srax %g6, %g7, %g0)

   Following that, one of the following 4 instructions are allowed:
       80 12 00 09  (or %o0, %o1, %g0)     %o0 = client_request ( %o1 )
       80 12 40 0a  (or %o1, %o2, %g0)     %o0 = guest_NRADDR
       80 12 80 0b  (or %o2, %o3, %g0)     jump-and-link-to-noredir %g1
       80 12 c0 0c  (or %o3, %o4, %g0)     IR injection

   Any other bytes following the 4-byte preamble are illegal and constitute
   a failure in instruction decoding. This all assumes that the preamble will
   never occur except in specific code fragments designed for Valgrind to catch.
 */

/*--------------------------------------------------------------------*/
/*--- Globals                                                      ---*/
/*--------------------------------------------------------------------*/

#define INSN_LENGTH 4

/* CONST: Host endianess */
static VexEndness host_endness;

/* CONST: Address of instruction currently being translated. */
static Addr guest_PC_curr_instr;

/* CONST: The IRSB into which we are generating code. */
static IRSB *irsb;


/*--------------------------------------------------------------------*/
/*--- Debugging output                                             ---*/
/*--------------------------------------------------------------------*/

#define DIP(format, args...)           \
    if (vex_traceflags & VEX_TRACE_FE) \
        vex_printf(format, ## args);

static void
print_insn(const sparc64_insn *insn)
{
    HChar insn_text[200];    // large enough
    UInt written = sparc64_sprint_insn(insn_text, insn);
    vassert(written < sizeof(insn_text));

    vex_printf("%s\n", insn_text);
}

/*--------------------------------------------------------------------*/
/*--- Helpers for accessing guest registers.                       ---*/
/*--------------------------------------------------------------------*/

#define SPARC64_STACKBIAS                         0x7ff

/* global registers */
#define REG_G1            1
#define REG_O0            8
#define REG_O7            15
#define OFFSET_sparc64_O0 OFFSET_sparc64_R8
#define OFFSET_sparc64_O6 OFFSET_sparc64_R14
#define OFFSET_sparc64_O7 OFFSET_sparc64_R15
#define OFFSET_sparc64_I6 OFFSET_sparc64_R30

/*--------------------------------------------------------------------*/
/*--- IR fragment helpers                                          ---*/
/*--------------------------------------------------------------------*/

/* Handles general purpose registers only.
   Ancillary state registers are handled in offsetAsrReg64(). */
static UInt
offsetIReg64(UInt iregNo)
{
    switch (iregNo) {
    case  0: return (OFFSET_sparc64_R0);
    case REG_G1: return (OFFSET_sparc64_R1);
    case  2: return (OFFSET_sparc64_R2);
    case  3: return (OFFSET_sparc64_R3);
    case  4: return (OFFSET_sparc64_R4);
    case  5: return (OFFSET_sparc64_R5);
    case  6: return (OFFSET_sparc64_R6);
    case  7: return (OFFSET_sparc64_R7);
    case REG_O0: return (OFFSET_sparc64_R8);
    case  9: return (OFFSET_sparc64_R9);
    case 10: return (OFFSET_sparc64_R10);
    case 11: return (OFFSET_sparc64_R11);
    case 12: return (OFFSET_sparc64_R12);
    case 13: return (OFFSET_sparc64_R13);
    case 14: return (OFFSET_sparc64_R14);
    case REG_O7: return (OFFSET_sparc64_R15);
    case 16: return (OFFSET_sparc64_R16);
    case 17: return (OFFSET_sparc64_R17);
    case 18: return (OFFSET_sparc64_R18);
    case 19: return (OFFSET_sparc64_R19);
    case 20: return (OFFSET_sparc64_R20);
    case 21: return (OFFSET_sparc64_R21);
    case 22: return (OFFSET_sparc64_R22);
    case 23: return (OFFSET_sparc64_R23);
    case 24: return (OFFSET_sparc64_R24);
    case 25: return (OFFSET_sparc64_R25);
    case 26: return (OFFSET_sparc64_R26);
    case 27: return (OFFSET_sparc64_R27);
    case 28: return (OFFSET_sparc64_R28);
    case 29: return (OFFSET_sparc64_R29);
    case 30: return (OFFSET_sparc64_R30);
    case 31: return (OFFSET_sparc64_R31);
    }

    vpanic("Unsupported register index.");
}

/* Takes decoded register number (full 6 bits).
   Use decodeFRegNo() to decode it. */
static UInt
offsetFReg64(UInt fregNo, UInt opSize)
{
    switch (opSize) {
    case 4:
        switch (fregNo) {
        case  0: return (OFFSET_sparc64_F0);
        case  1: return (OFFSET_sparc64_F1);
        case  2: return (OFFSET_sparc64_F2);
        case  3: return (OFFSET_sparc64_F3);
        case  4: return (OFFSET_sparc64_F4);
        case  5: return (OFFSET_sparc64_F5);
        case  6: return (OFFSET_sparc64_F6);
        case  7: return (OFFSET_sparc64_F7);
        case  8: return (OFFSET_sparc64_F8);
        case  9: return (OFFSET_sparc64_F9);
        case 10: return (OFFSET_sparc64_F10);
        case 11: return (OFFSET_sparc64_F11);
        case 12: return (OFFSET_sparc64_F12);
        case 13: return (OFFSET_sparc64_F13);
        case 14: return (OFFSET_sparc64_F14);
        case 15: return (OFFSET_sparc64_F15);
        case 16: return (OFFSET_sparc64_F16);
        case 17: return (OFFSET_sparc64_F17);
        case 18: return (OFFSET_sparc64_F18);
        case 19: return (OFFSET_sparc64_F19);
        case 20: return (OFFSET_sparc64_F20);
        case 21: return (OFFSET_sparc64_F21);
        case 22: return (OFFSET_sparc64_F22);
        case 23: return (OFFSET_sparc64_F23);
        case 24: return (OFFSET_sparc64_F24);
        case 25: return (OFFSET_sparc64_F25);
        case 26: return (OFFSET_sparc64_F26);
        case 27: return (OFFSET_sparc64_F27);
        case 28: return (OFFSET_sparc64_F28);
        case 29: return (OFFSET_sparc64_F29);
        case 30: return (OFFSET_sparc64_F30);
        case 31: return (OFFSET_sparc64_F31);
        default:
            vpanic("Unsupported register index for operand size 4.");
        }
    case 8:
        switch (fregNo) {
        case  0: return (OFFSET_sparc64_F0);
        case  2: return (OFFSET_sparc64_F2);
        case  4: return (OFFSET_sparc64_F4);
        case  6: return (OFFSET_sparc64_F6);
        case  8: return (OFFSET_sparc64_F8);
        case 10: return (OFFSET_sparc64_F10);
        case 12: return (OFFSET_sparc64_F12);
        case 14: return (OFFSET_sparc64_F14);
        case 16: return (OFFSET_sparc64_F16);
        case 18: return (OFFSET_sparc64_F18);
        case 20: return (OFFSET_sparc64_F20);
        case 22: return (OFFSET_sparc64_F22);
        case 24: return (OFFSET_sparc64_F24);
        case 26: return (OFFSET_sparc64_F26);
        case 28: return (OFFSET_sparc64_F28);
        case 30: return (OFFSET_sparc64_F30);
        case 32: return (OFFSET_sparc64_D32);
        case 34: return (OFFSET_sparc64_D34);
        case 36: return (OFFSET_sparc64_D36);
        case 38: return (OFFSET_sparc64_D38);
        case 40: return (OFFSET_sparc64_D40);
        case 42: return (OFFSET_sparc64_D42);
        case 44: return (OFFSET_sparc64_D44);
        case 46: return (OFFSET_sparc64_D46);
        case 48: return (OFFSET_sparc64_D48);
        case 50: return (OFFSET_sparc64_D50);
        case 52: return (OFFSET_sparc64_D52);
        case 54: return (OFFSET_sparc64_D54);
        case 56: return (OFFSET_sparc64_D56);
        case 58: return (OFFSET_sparc64_D58);
        case 60: return (OFFSET_sparc64_D60);
        case 62: return (OFFSET_sparc64_D62);
        default:
            vpanic("Unsupported register index for operand size 8.");
        }
    case 16:
        switch (fregNo) {
        case  0: return (OFFSET_sparc64_F0);
        case  4: return (OFFSET_sparc64_F4);
        case  8: return (OFFSET_sparc64_F8);
        case 12: return (OFFSET_sparc64_F12);
        case 16: return (OFFSET_sparc64_F16);
        case 20: return (OFFSET_sparc64_F20);
        case 24: return (OFFSET_sparc64_F24);
        case 28: return (OFFSET_sparc64_F28);
        case 32: return (OFFSET_sparc64_D32);
        case 36: return (OFFSET_sparc64_D36);
        case 40: return (OFFSET_sparc64_D40);
        case 44: return (OFFSET_sparc64_D44);
        case 48: return (OFFSET_sparc64_D48);
        case 52: return (OFFSET_sparc64_D52);
        case 56: return (OFFSET_sparc64_D56);
        case 60: return (OFFSET_sparc64_D60);
        default:
            vpanic("Unsupported register index for operand size 16.");
        }
    default:
        vpanic("Unsupported FPU register number.");
    }
}

/* Handles Ancillary State Registers (ASRs) only.
   ASR 2 (CCR) and ASR 19 (GSR) are not represented as simple guest state
   registers. */
static UInt
offsetAsrReg64(SPARC64_ASR asrRegNo)
{
    switch (asrRegNo) {
    case SPARC64_ASR_Y:    return (OFFSET_sparc64_Y);
    case SPARC64_ASR_ASI:  return (OFFSET_sparc64_ASI);
    case SPARC64_ASR_PC:   return (OFFSET_sparc64_PC);
    case SPARC64_ASR_FPRS: return (OFFSET_sparc64_FPRS);
    default:
        vpanic("Unsupported ASR register index.");
    }
}

static IRExpr *
mkU8(UInt i)
{
    vassert(i <= 0xff);
    return IRExpr_Const(IRConst_U8((UChar) i));
}

static IRExpr *
mkU32(UInt i)
{
    vassert(i <= 0xFFFFFFFF);
    return IRExpr_Const(IRConst_U32(i));
}

static IRExpr *
mkU64(ULong i)
{
    return (IRExpr_Const(IRConst_U64(i)));
}

static IRType
mkFpType(UInt opSize)
{
    switch (opSize) {
    case  4: return Ity_F32;
    case  8: return Ity_F64;
    case 16: return Ity_F128;
    default: vpanic("Unsupported floating-point operand size.");
    }
}

static void
stmt(IRStmt *st)
{
    addStmtToIRSB(irsb, st);
}

static void
assign(IRTemp dst, IRExpr *e)
{
    stmt(IRStmt_WrTmp(dst, e));
}

static IRTemp
newTemp(IRType ty)
{
    vassert(isPlausibleIRType(ty));
    return (newIRTemp(irsb->tyenv, ty));
}

static IRExpr *
unop(IROp op, IRExpr *e)
{
    return (IRExpr_Unop(op, e));
}

static IRExpr *
binop(IROp op, IRExpr *l, IRExpr *r)
{
    return (IRExpr_Binop(op, l, r));
}

static IRExpr *
triop(IROp op, IRExpr *arg1, IRExpr *arg2, IRExpr *arg3)
{
    return (IRExpr_Triop(op, arg1, arg2, arg3));
}

static IRExpr *
qop(IROp op, IRExpr *arg1, IRExpr *arg2, IRExpr *arg3, IRExpr *arg4)
{
    return IRExpr_Qop(op, arg1, arg2, arg3, arg4);
}

static IRExpr *
getIRegOrZR(UInt iregNo)
{
    vassert((iregNo >= 0) && (iregNo <= 31));
    if (iregNo == 0 ) {
        return (mkU64(0));
    }
   
    return (IRExpr_Get(offsetIReg64(iregNo), Ity_I64));
}

static void
putIRegOrZR(UInt iregNo, IRExpr *e)
{
    vassert(typeOfIRExpr(irsb->tyenv, e) == Ity_I64);
    /* write to %g0 is ignored */
    if (iregNo == 0) {
       return;
    }

    stmt(IRStmt_Put(offsetIReg64(iregNo), e));
}

static void
putPC(IRExpr *e)
{
    vassert(typeOfIRExpr(irsb->tyenv, e) == Ity_I64);

    stmt(IRStmt_Put(OFFSET_sparc64_PC, e));
}

static void
putNPC(IRExpr *e)
{
    vassert(typeOfIRExpr(irsb->tyenv, e) == Ity_I64);

    stmt(IRStmt_Put(OFFSET_sparc64_NPC, e));
}

#define GET_FREG(insn, op_index)                        \
    getFReg((insn)->operand_values[(op_index)].uintval, \
            (insn)->operands[(op_index)]->op_size)

static IRExpr *
getFReg(UInt fregNo, UInt size)
{
    return (IRExpr_Get(offsetFReg64(fregNo, size), mkFpType(size)));
}

#define PUT_FREG(insn, op_index, expr)                  \
    putFReg((insn)->operand_values[(op_index)].uintval, \
            (insn)->operands[(op_index)]->op_size,      \
            expr)

static void
putFReg(UInt fregNo, UInt size, IRExpr *e)
{
    vassert(sizeofIRType(typeOfIRExpr(irsb->tyenv, e)) == size);

    stmt(IRStmt_Put(offsetFReg64(fregNo, size), e));
}

static IRExpr *
getIRRoundMode(void)
{
    /* FSR.rd kept in the standard encoding as per IRRoundingMode. */
    return unop(Iop_64to32, IRExpr_Get(OFFSET_sparc64_FSR_RD, Ity_I64));
}

static IRExpr *
mkexpr(IRTemp tmp)
{
    return (IRExpr_RdTmp(tmp));
}

static void
narrow_store(UInt sz, IRExpr *addr, IRExpr *data, IRExpr *asi)
{
    IRExpr *tdata = data;
    switch (sz) {
    case 8:
        tdata = data;
        break;
    case 4:
        tdata = unop(Iop_64to32, data);
        break;
    case 2:
        tdata = unop(Iop_64to16, data);
        break;
    case 1:
        tdata = unop(Iop_64to8, data);
        break;
    default:
        vpanic("Unsupported store size");
    }
    return (stmt(IRStmt_StoreA(Iend_BE, addr, tdata, asi)));
}

static IRExpr *
narrow_load(UInt sz, Bool sext, IRExpr *addr, IRExpr *asi)
{
    IRExpr *result_exp;
    switch (sz) {
    case 8:
        result_exp = IRExpr_LoadA(Iend_BE, Ity_I64, addr, asi);
        break;
    case 4:
        result_exp = unop((sext) ? Iop_32Sto64 : Iop_32Uto64,
                          IRExpr_LoadA(Iend_BE, Ity_I32, addr, asi));
        break;
    case 2:
        result_exp = unop((sext) ? Iop_16Sto64 : Iop_16Uto64,
                          IRExpr_LoadA(Iend_BE, Ity_I16, addr, asi));
        break;
    case 1:
        result_exp = unop((sext) ? Iop_8Sto64 : Iop_8Uto64,
                          IRExpr_LoadA(Iend_BE, Ity_I8, addr, asi));
        break;
    default:
        vpanic("Unsupported load size/sign");
    }
    return (result_exp);
}

static void
savearea_store(Int vex_state_off, IRTemp sa_base, Int sa_off)
{
    stmt(IRStmt_Store(Iend_BE,
        binop(Iop_Add64, mkexpr(sa_base), mkU64(sa_off + SPARC64_STACKBIAS)),
        IRExpr_Get(vex_state_off, Ity_I64))
    );
}

static void
savearea_restore(Int vex_state_off, IRTemp sa_base, Int sa_off)
{
    stmt(IRStmt_Put(vex_state_off,
        IRExpr_Load(Iend_BE, Ity_I64,
          binop(Iop_Add64, mkexpr(sa_base), mkU64(sa_off + SPARC64_STACKBIAS))))
    );
}

/* Sets CC_OP and CC_DEP1; zeroes CC_DEP2. */
static void
setFlags_DEP1(SPARC64_CC_OP cc_op, IRExpr *dep1)
{
    stmt(IRStmt_Put(OFFSET_sparc64_CC_OP, mkU64(cc_op)));
    stmt(IRStmt_Put(OFFSET_sparc64_CC_DEP1, dep1));
    stmt(IRStmt_Put(OFFSET_sparc64_CC_DEP2, mkU64(0)));
}

static void
setFlags_DEP1_DEP2(SPARC64_CC_OP cc_op, IRTemp dep1, IRTemp dep2)
{
    stmt(IRStmt_Put(OFFSET_sparc64_CC_OP,   mkU64(cc_op)));
    stmt(IRStmt_Put(OFFSET_sparc64_CC_DEP1, mkexpr(dep1)));
    stmt(IRStmt_Put(OFFSET_sparc64_CC_DEP2, mkexpr(dep2)));
}

/* Carry needs to be either 0 or 1. */
static void
setFlags_DEP1_DEP2_NDEP(SPARC64_CC_OP cc_op, IRTemp dep1, IRTemp dep2,
                        IRTemp carry)
{
    stmt(IRStmt_Put(OFFSET_sparc64_CC_OP, mkU64(cc_op)));
    stmt(IRStmt_Put(OFFSET_sparc64_CC_DEP1, mkexpr(dep1)));
    stmt(IRStmt_Put(OFFSET_sparc64_CC_DEP2,
                    binop(Iop_Xor64, mkexpr(dep2), mkexpr(carry))));
    stmt(IRStmt_Put(OFFSET_sparc64_CC_NDEP, mkexpr(carry)));
}

static void
do_set_FSR_CEXC_DEP1(IRExpr *fsr_cexc_dep1)
{
    switch (typeOfIRExpr(irsb->tyenv, fsr_cexc_dep1)) {
    case Ity_F32:
    case Ity_F64:
        stmt(IRStmt_Put(OFFSET_sparc64_FSR_CEXC_DEP1_HI, mkU64(0)));
        stmt(IRStmt_Put(OFFSET_sparc64_FSR_CEXC_DEP1_LO, fsr_cexc_dep1));
        break;
    case Ity_F128:
        /* Sets DEP1_LO as well. */
        stmt(IRStmt_Put(OFFSET_sparc64_FSR_CEXC_DEP1_HI, fsr_cexc_dep1));
        break;
    case Ity_I64:
        stmt(IRStmt_Put(OFFSET_sparc64_FSR_CEXC_DEP1_HI, mkU64(0)));
        stmt(IRStmt_Put(OFFSET_sparc64_FSR_CEXC_DEP1_LO, fsr_cexc_dep1));
        break;
    default:
        vassert(0);
    }
}

static void
do_set_FSR_CEXC_DEP2(IRExpr *fsr_cexc_dep2)
{
    switch (typeOfIRExpr(irsb->tyenv, fsr_cexc_dep2)) {
    case Ity_F32:
    case Ity_F64:
        stmt(IRStmt_Put(OFFSET_sparc64_FSR_CEXC_DEP2_HI, mkU64(0)));
        stmt(IRStmt_Put(OFFSET_sparc64_FSR_CEXC_DEP2_LO, fsr_cexc_dep2));
        break;
    case Ity_F128:
        /* Sets DEP2_LO as well. */
        stmt(IRStmt_Put(OFFSET_sparc64_FSR_CEXC_DEP2_HI, fsr_cexc_dep2));
        break;
    case Ity_I64:
        stmt(IRStmt_Put(OFFSET_sparc64_FSR_CEXC_DEP2_HI, mkU64(0)));
        stmt(IRStmt_Put(OFFSET_sparc64_FSR_CEXC_DEP2_LO, fsr_cexc_dep2));
        break;
    default:
        vassert(0);
    }
}

static void
set_FSR_CEXC_DEP1(SPARC64_FSR_CEXC_OP fsr_cexc_op, IRExpr *fsr_cexc_dep1)
{
    stmt(IRStmt_Put(OFFSET_sparc64_FSR_CEXC_OP, mkU64(fsr_cexc_op)));
    do_set_FSR_CEXC_DEP1(fsr_cexc_dep1);
    stmt(IRStmt_Put(OFFSET_sparc64_FSR_CEXC_DEP2_HI, mkU64(0)));
    stmt(IRStmt_Put(OFFSET_sparc64_FSR_CEXC_DEP2_LO, mkU64(0)));
}

static void
set_FSR_CEXC_DEP1_NDEP(SPARC64_FSR_CEXC_OP fsr_cexc_op, IRExpr *fsr_cexc_dep1,
                       IRExpr *fsr_cexc_ndep)
{
    set_FSR_CEXC_DEP1(fsr_cexc_op, fsr_cexc_dep1);
    stmt(IRStmt_Put(OFFSET_sparc64_FSR_CEXC_NDEP, fsr_cexc_ndep));
}

static void
set_FSR_CEXC_DEP1_DEP2(SPARC64_FSR_CEXC_OP fsr_cexc_op, IRExpr *fsr_cexc_dep1,
                       IRExpr *fsr_cexc_dep2)
{
    stmt(IRStmt_Put(OFFSET_sparc64_FSR_CEXC_OP, mkU64(fsr_cexc_op)));
    do_set_FSR_CEXC_DEP1(fsr_cexc_dep1);
    do_set_FSR_CEXC_DEP2(fsr_cexc_dep2);
}

static void
set_FSR_CEXC_DEP1_DEP2_NDEP(SPARC64_FSR_CEXC_OP fsr_cexc_op,
                            IRExpr *fsr_cexc_dep1, IRExpr *fsr_cexc_dep2,
                            IRExpr *fsr_cexc_ndep)
{
    set_FSR_CEXC_DEP1_DEP2(fsr_cexc_op, fsr_cexc_dep1, fsr_cexc_dep2);
    stmt(IRStmt_Put(OFFSET_sparc64_FSR_CEXC_NDEP, fsr_cexc_ndep));
}

static void
set_FSR_CEXC_DEP_NDEP_for_FMAf(SPARC64_FSR_CEXC_OP fsr_cexc_op,
                           IRExpr *fsr_cexc_dep_arg1, IRExpr *fsr_cexc_dep_arg2,
                           IRExpr *fsr_cexc_dep_arg3, IRExpr *fsr_cexc_ndep)
{
    stmt(IRStmt_Put(OFFSET_sparc64_FSR_CEXC_OP, mkU64(fsr_cexc_op)));
    stmt(IRStmt_Put(OFFSET_sparc64_FSR_CEXC_DEP1_HI, fsr_cexc_dep_arg1));
    stmt(IRStmt_Put(OFFSET_sparc64_FSR_CEXC_DEP1_LO, fsr_cexc_dep_arg2));
    stmt(IRStmt_Put(OFFSET_sparc64_FSR_CEXC_DEP2_HI, fsr_cexc_dep_arg3));
    stmt(IRStmt_Put(OFFSET_sparc64_FSR_CEXC_DEP2_LO, mkU64(0)));
    stmt(IRStmt_Put(OFFSET_sparc64_FSR_CEXC_NDEP, fsr_cexc_ndep));
}

static void
clear_FSR_cexc(void)
{
    set_FSR_CEXC_DEP1_DEP2(SPARC64_FSR_CEXC_OP_COPY, mkU64(0), mkU64(0));
}

/*----------------------------------------------------------------------------*/
/*--- SPARC64 disasm helpers                                               ---*/
/*----------------------------------------------------------------------------*/

static inline UInt
getUIntBE(const UInt *p)
{
    if (host_endness == VexEndnessBE) {
        return (*p);
    } else {
        /* TODO-SPARC: Implement this. */
        vpanic("SPARC64: Little endian not supported yet.");
    }
}

static SPARC64ICondcode
sparc64_icond_for_mnemonic(sparc64_mnemonic mnemonic)
{
    switch (mnemonic) {
    case SPARC64_OPC_BA:
    case SPARC64_OPC_BPA:
    case SPARC64_OPC_FMOVSiccA:
    case SPARC64_OPC_FMOVDiccA:
    case SPARC64_OPC_FMOVQiccA:
    case SPARC64_OPC_MOVA:
    case SPARC64_OPC_TA:
        return SPARC64_ICOND_A_ICC;
    case SPARC64_OPC_BN:
    case SPARC64_OPC_BPN:
    case SPARC64_OPC_FMOVSiccN:
    case SPARC64_OPC_FMOVDiccN:
    case SPARC64_OPC_FMOVQiccN:
    case SPARC64_OPC_MOVN:
    case SPARC64_OPC_TN:
        return SPARC64_ICOND_N_ICC;
    case SPARC64_OPC_BNE:
    case SPARC64_OPC_BPNE:
    case SPARC64_OPC_CWBNE:
    case SPARC64_OPC_CXBNE:
    case SPARC64_OPC_FMOVSiccNE:
    case SPARC64_OPC_FMOVDiccNE:
    case SPARC64_OPC_FMOVQiccNE:
    case SPARC64_OPC_MOVNE:
    case SPARC64_OPC_TNE:
        return SPARC64_ICOND_NE_ICC;
    case SPARC64_OPC_BE:
    case SPARC64_OPC_BPE:
    case SPARC64_OPC_CWBE:
    case SPARC64_OPC_CXBE:
    case SPARC64_OPC_FMOVSiccE:
    case SPARC64_OPC_FMOVDiccE:
    case SPARC64_OPC_FMOVQiccE:
    case SPARC64_OPC_MOVE:
    case SPARC64_OPC_TE:
        return SPARC64_ICOND_E_ICC;
    case SPARC64_OPC_BG:
    case SPARC64_OPC_BPG:
    case SPARC64_OPC_CWBG:
    case SPARC64_OPC_CXBG:
    case SPARC64_OPC_FMOVSiccG:
    case SPARC64_OPC_FMOVDiccG:
    case SPARC64_OPC_FMOVQiccG:
    case SPARC64_OPC_MOVG:
    case SPARC64_OPC_TG:
        return SPARC64_ICOND_G_ICC;
    case SPARC64_OPC_BLE:
    case SPARC64_OPC_BPLE:
    case SPARC64_OPC_CWBLE:
    case SPARC64_OPC_CXBLE:
    case SPARC64_OPC_FMOVSiccLE:
    case SPARC64_OPC_FMOVDiccLE:
    case SPARC64_OPC_FMOVQiccLE:
    case SPARC64_OPC_MOVLE:
    case SPARC64_OPC_TLE:
        return SPARC64_ICOND_LE_ICC;
    case SPARC64_OPC_BGE:
    case SPARC64_OPC_BPGE:
    case SPARC64_OPC_CWBGE:
    case SPARC64_OPC_CXBGE:
    case SPARC64_OPC_FMOVSiccGE:
    case SPARC64_OPC_FMOVDiccGE:
    case SPARC64_OPC_FMOVQiccGE:
    case SPARC64_OPC_MOVGE:
    case SPARC64_OPC_TGE:
        return SPARC64_ICOND_GE_ICC;
    case SPARC64_OPC_BL:
    case SPARC64_OPC_BPL:
    case SPARC64_OPC_CWBL:
    case SPARC64_OPC_CXBL:
    case SPARC64_OPC_FMOVSiccL:
    case SPARC64_OPC_FMOVDiccL:
    case SPARC64_OPC_FMOVQiccL:
    case SPARC64_OPC_MOVL:
    case SPARC64_OPC_TL:
        return SPARC64_ICOND_L_ICC;
    case SPARC64_OPC_BGU:
    case SPARC64_OPC_BPGU:
    case SPARC64_OPC_CWBGU:
    case SPARC64_OPC_CXBGU:
    case SPARC64_OPC_FMOVSiccGU:
    case SPARC64_OPC_FMOVDiccGU:
    case SPARC64_OPC_FMOVQiccGU:
    case SPARC64_OPC_MOVGU:
    case SPARC64_OPC_TGU:
        return SPARC64_ICOND_GU_ICC;
    case SPARC64_OPC_BLEU:
    case SPARC64_OPC_BPLEU:
    case SPARC64_OPC_CWBLEU:
    case SPARC64_OPC_CXBLEU:
    case SPARC64_OPC_FMOVSiccLEU:
    case SPARC64_OPC_FMOVDiccLEU:
    case SPARC64_OPC_FMOVQiccLEU:
    case SPARC64_OPC_MOVLEU:
    case SPARC64_OPC_TLEU:
        return SPARC64_ICOND_LEU_ICC;
    case SPARC64_OPC_BCC:
    case SPARC64_OPC_BPCC:
    case SPARC64_OPC_CWBCC:
    case SPARC64_OPC_CXBCC:
    case SPARC64_OPC_FMOVSiccCC:
    case SPARC64_OPC_FMOVDiccCC:
    case SPARC64_OPC_FMOVQiccCC:
    case SPARC64_OPC_MOVCC:
    case SPARC64_OPC_TCC:
        return SPARC64_ICOND_CC_ICC;
    case SPARC64_OPC_BCS:
    case SPARC64_OPC_BPCS:
    case SPARC64_OPC_CWBCS:
    case SPARC64_OPC_CXBCS:
    case SPARC64_OPC_FMOVSiccCS:
    case SPARC64_OPC_FMOVDiccCS:
    case SPARC64_OPC_FMOVQiccCS:
    case SPARC64_OPC_MOVCS:
    case SPARC64_OPC_TCS:
        return SPARC64_ICOND_CS_ICC;
    case SPARC64_OPC_BPOS:
    case SPARC64_OPC_BPPOS:
    case SPARC64_OPC_CWBPOS:
    case SPARC64_OPC_CXBPOS:
    case SPARC64_OPC_FMOVSiccPOS:
    case SPARC64_OPC_FMOVDiccPOS:
    case SPARC64_OPC_FMOVQiccPOS:
    case SPARC64_OPC_MOVPOS:
    case SPARC64_OPC_TPOS:
        return SPARC64_ICOND_POS_ICC;
    case SPARC64_OPC_BNEG:
    case SPARC64_OPC_BPNEG:
    case SPARC64_OPC_CWBNEG:
    case SPARC64_OPC_CXBNEG:
    case SPARC64_OPC_FMOVSiccNEG:
    case SPARC64_OPC_FMOVDiccNEG:
    case SPARC64_OPC_FMOVQiccNEG:
    case SPARC64_OPC_MOVNEG:
    case SPARC64_OPC_TNEG:
        return SPARC64_ICOND_NEG_ICC;
    case SPARC64_OPC_BVC:
    case SPARC64_OPC_BPVC:
    case SPARC64_OPC_CWBVC:
    case SPARC64_OPC_CXBVC:
    case SPARC64_OPC_FMOVSiccVC:
    case SPARC64_OPC_FMOVDiccVC:
    case SPARC64_OPC_FMOVQiccVC:
    case SPARC64_OPC_MOVVC:
    case SPARC64_OPC_TVC:
        return SPARC64_ICOND_VC_ICC;
    case SPARC64_OPC_BVS:
    case SPARC64_OPC_BPVS:
    case SPARC64_OPC_CWBVS:
    case SPARC64_OPC_CXBVS:
    case SPARC64_OPC_FMOVSiccVS:
    case SPARC64_OPC_FMOVDiccVS:
    case SPARC64_OPC_FMOVQiccVS:
    case SPARC64_OPC_MOVVS:
    case SPARC64_OPC_TVS:
        return SPARC64_ICOND_VS_ICC;
    default:
        vassert(0);
    }
}

static IRExpr *
mk_rcond_expr(sparc64_mnemonic mnemonic, IRExpr *reg, Bool negate)
{
    IRExpr *cond;

    switch (mnemonic) {
    /* R[rs1] == 0 */
    case SPARC64_OPC_BRZ:
    case SPARC64_OPC_MOVRZ:
        cond = binop(Iop_CmpEQ64, reg, mkU64(0));
        break;
    /* R[rs1] <= 0 */
    case SPARC64_OPC_BRLEZ:
    case SPARC64_OPC_MOVRLEZ:
        cond = binop(Iop_CmpLE64S, reg, mkU64(0));
        break;
    /* R[rs1] < 0 */
    case SPARC64_OPC_BRLZ:
    case SPARC64_OPC_MOVRLZ:
        cond = binop(Iop_CmpLT64S, reg, mkU64(0));
        break;
    /* R[rs1] != 0 */
    case SPARC64_OPC_BRNZ:
    case SPARC64_OPC_MOVRNZ:
        cond = binop(Iop_CmpNE64, reg, mkU64(0));
        break;
    /* R[rs1] > 0 */
    case SPARC64_OPC_BRGZ:
    case SPARC64_OPC_MOVRGZ:
        cond = binop(Iop_CmpLT64S, mkU64(0), reg);
        break;
    /* R[rs1] >= 0 */
    case SPARC64_OPC_BRGEZ:
    case SPARC64_OPC_MOVRGEZ:
        cond = binop(Iop_CmpLE64S, mkU64(0), reg);
        break;
    default:
        vassert(0);
    }

    if (negate) {
        return (unop(Iop_Not1, cond));
    } else {
        return (cond);
    }
}

static SPARC64FCondcode
sparc64_fcond_for_mnemonic(sparc64_mnemonic mnemonic)
{
    switch (mnemonic) {
    case SPARC64_OPC_FBPA:
    case SPARC64_OPC_FMOVSfccA:
    case SPARC64_OPC_FMOVDfccA:
    case SPARC64_OPC_FMOVQfccA:
    case SPARC64_OPC_MOVFA:
        return SPARC64_FCOND_A;
    case SPARC64_OPC_FBPN:
    case SPARC64_OPC_FMOVSfccN:
    case SPARC64_OPC_FMOVDfccN:
    case SPARC64_OPC_FMOVQfccN:
    case SPARC64_OPC_MOVFN:
        return SPARC64_FCOND_N;
    case SPARC64_OPC_FBPU:
    case SPARC64_OPC_FMOVSfccU:
    case SPARC64_OPC_FMOVDfccU:
    case SPARC64_OPC_FMOVQfccU:
    case SPARC64_OPC_MOVFU:
         return SPARC64_FCOND_U;
    case SPARC64_OPC_FBPG:
    case SPARC64_OPC_FMOVSfccG:
    case SPARC64_OPC_FMOVDfccG:
    case SPARC64_OPC_FMOVQfccG:
    case SPARC64_OPC_MOVFG:
        return SPARC64_FCOND_G;
    case SPARC64_OPC_FBPUG:
    case SPARC64_OPC_FMOVSfccUG:
    case SPARC64_OPC_FMOVDfccUG:
    case SPARC64_OPC_FMOVQfccUG:
    case SPARC64_OPC_MOVFUG:
        return SPARC64_FCOND_UG;
    case SPARC64_OPC_FBPL:
    case SPARC64_OPC_FMOVSfccL:
    case SPARC64_OPC_FMOVDfccL:
    case SPARC64_OPC_FMOVQfccL:
    case SPARC64_OPC_MOVFL:
        return SPARC64_FCOND_L;
    case SPARC64_OPC_FBPUL:
    case SPARC64_OPC_FMOVSfccUL:
    case SPARC64_OPC_FMOVDfccUL:
    case SPARC64_OPC_FMOVQfccUL:
    case SPARC64_OPC_MOVFUL:
        return SPARC64_FCOND_UL;
    case SPARC64_OPC_FBPLG:
    case SPARC64_OPC_FMOVSfccLG:
    case SPARC64_OPC_FMOVDfccLG:
    case SPARC64_OPC_FMOVQfccLG:
    case SPARC64_OPC_MOVFLG:
        return SPARC64_FCOND_LG;
    case SPARC64_OPC_FBPNE:
    case SPARC64_OPC_FMOVSfccNE:
    case SPARC64_OPC_FMOVDfccNE:
    case SPARC64_OPC_FMOVQfccNE:
    case SPARC64_OPC_MOVFNE:
        return SPARC64_FCOND_NE;
    case SPARC64_OPC_FBPE:
    case SPARC64_OPC_FMOVSfccE:
    case SPARC64_OPC_FMOVDfccE:
    case SPARC64_OPC_FMOVQfccE:
    case SPARC64_OPC_MOVFE:
        return SPARC64_FCOND_E;
    case SPARC64_OPC_FBPUE:
    case SPARC64_OPC_FMOVSfccUE:
    case SPARC64_OPC_FMOVDfccUE:
    case SPARC64_OPC_FMOVQfccUE:
    case SPARC64_OPC_MOVFUE:
        return SPARC64_FCOND_UE;
    case SPARC64_OPC_FBPGE:
    case SPARC64_OPC_FMOVSfccGE:
    case SPARC64_OPC_FMOVDfccGE:
    case SPARC64_OPC_FMOVQfccGE:
    case SPARC64_OPC_MOVFGE:
        return SPARC64_FCOND_GE;
    case SPARC64_OPC_FBPUGE:
    case SPARC64_OPC_FMOVSfccUGE:
    case SPARC64_OPC_FMOVDfccUGE:
    case SPARC64_OPC_FMOVQfccUGE:
    case SPARC64_OPC_MOVFUGE:
        return SPARC64_FCOND_UGE;
    case SPARC64_OPC_FBPLE:
    case SPARC64_OPC_FMOVSfccLE:
    case SPARC64_OPC_FMOVDfccLE:
    case SPARC64_OPC_FMOVQfccLE:
    case SPARC64_OPC_MOVFLE:
        return SPARC64_FCOND_LE;
    case SPARC64_OPC_FBPULE:
    case SPARC64_OPC_FMOVSfccULE:
    case SPARC64_OPC_FMOVDfccULE:
    case SPARC64_OPC_FMOVQfccULE:
    case SPARC64_OPC_MOVFULE:
        return SPARC64_FCOND_ULE;
    case SPARC64_OPC_FBPO:
    case SPARC64_OPC_FMOVSfccO:
    case SPARC64_OPC_FMOVDfccO:
    case SPARC64_OPC_FMOVQfccO:
    case SPARC64_OPC_MOVFO:
        return SPARC64_FCOND_O;
    default:
        vassert(0);
    }
}

/* Invokes clean helper to calculate all condition codes.
 * Invoked lazily, only when really needed. */
static IRExpr *
calculate_CCR(void)
{
    IRExpr **args = mkIRExprVec_4(IRExpr_Get(OFFSET_sparc64_CC_OP,   Ity_I64),
                                  IRExpr_Get(OFFSET_sparc64_CC_DEP1, Ity_I64),
                                  IRExpr_Get(OFFSET_sparc64_CC_DEP2, Ity_I64),
                                  IRExpr_Get(OFFSET_sparc64_CC_NDEP, Ity_I64));

    IRExpr *call = mkIRExprCCall(Ity_I64, 0, "sparc64_calculate_CCR",
                                 &sparc64_calculate_CCR, args);

    /* Exclude OP and NDEP from definedness checking. */
    call->Iex.CCall.cee->mcx_mask = (1<<0) | (1<<3);
    return (call);
}

static IRExpr *
getAsrReg(SPARC64_ASR asrRegNo)
{
    switch (asrRegNo) {
    case SPARC64_ASR_CCR:
        return calculate_CCR();
    case SPARC64_ASR_GSR: {
        IRExpr *gsr_hi = binop(Iop_Shl64,
                               unop(Iop_32Uto64,
                                  IRExpr_Get(OFFSET_sparc64_GSR_mask, Ity_I32)),
                               mkU8(SPARC64_GSR_SHIFT_MASK));
        IRExpr *gsr_low = unop(Iop_32Uto64,
                               IRExpr_Get(OFFSET_sparc64_GSR_align, Ity_I32));
        return binop(Iop_Or64, gsr_hi, gsr_low);
    }
    default:
        return IRExpr_Get(offsetAsrReg64(asrRegNo), Ity_I64);
    }
}

static void
putAsrReg(SPARC64_ASR asrRegNo, IRExpr *e)
{
    vassert(typeOfIRExpr(irsb->tyenv, e) == Ity_I64);

    switch (asrRegNo) {
    case SPARC64_ASR_Y:
        /* High 32 bits of Y are always 0. */
        stmt(IRStmt_Put(offsetAsrReg64(asrRegNo),
                        binop(Iop_And64, e, mkU64(0xffffffff))));
        break;
    case SPARC64_ASR_CCR:
        setFlags_DEP1(SPARC64_CC_OP_COPY, e);
        break;
    case SPARC64_ASR_ASI:
        /* ASI is always 8 bits wide. */
        stmt(IRStmt_Put(offsetAsrReg64(asrRegNo),
                        binop(Iop_And64, e, mkU64(0xff))));
        break;
    case SPARC64_ASR_GSR: {
        IRExpr *gsr_align
         = unop(Iop_64to32, binop(Iop_And64, e, mkU64(SPARC64_GSR_MASK_ALIGN)));
        stmt(IRStmt_Put(OFFSET_sparc64_GSR_align, gsr_align));

        IRExpr *gsr_mask
          = unop(Iop_64to32, binop(Iop_Shr64, e, mkU8(SPARC64_GSR_SHIFT_MASK)));
        stmt(IRStmt_Put(OFFSET_sparc64_GSR_mask, gsr_mask));
        break;
    }
    default:
        stmt(IRStmt_Put(offsetAsrReg64(asrRegNo), e));
        break;
    }
}

static void
set_fprs_dirty(void)
{
    /* Always leave the 'fef' bit on so as to permanently enable FPU.
       Thus we don't need to check for FPU support before any FPop. */
    putAsrReg(SPARC64_ASR_FPRS,
              mkU64(SPARC64_FPRS_MASK_DUDL | SPARC64_FPRS_MASK_FEF));
}

/* cc_op is of type SPARC64_CC_OP. */
static IRExpr *
calculate_ICond(SPARC64ICondcode cond, IRExpr *cc_op, IRExpr *cc_dep1,
                IRExpr *cc_dep2, IRExpr *cc_ndep, Bool negate)
{
    IRExpr **args = mkIRExprVec_5(mkU64(cond), cc_op, cc_dep1, cc_dep2,
                                  cc_ndep);
    IRExpr *call = mkIRExprCCall(Ity_I64, 0, "sparc64_calculate_ICond",
                                 &sparc64_calculate_ICond, args);

    /* Exclude COND, OP and NDEP from definedness checking. */
    call->Iex.CCall.cee->mcx_mask = (1<<0) | (1<<1) | (1<<4);

    if (negate) {
        return (unop(Iop_64to1, unop(Iop_Not64, call)));
    } else {
        return (unop(Iop_64to1, call));
    }
}

static IRExpr *
calculate_ICond_from_CCR(SPARC64ICondcode cond, Bool negate)
{
    return calculate_ICond(cond,
                           IRExpr_Get(OFFSET_sparc64_CC_OP,   Ity_I64),
                           IRExpr_Get(OFFSET_sparc64_CC_DEP1, Ity_I64),
                           IRExpr_Get(OFFSET_sparc64_CC_DEP2, Ity_I64),
                           IRExpr_Get(OFFSET_sparc64_CC_NDEP, Ity_I64),
                           negate);
}

static IRExpr *
calculate_FCond_from_FSR(SPARC64FCondcode cond, UInt fccn, Bool negate)
{
    IRExpr **args = mkIRExprVec_3(mkU64(cond), mkU64(fccn),
                                  IRExpr_Get(OFFSET_sparc64_FSR_FCC, Ity_I64));
    IRExpr *call = mkIRExprCCall(Ity_I64, 0, "sparc64_calculate_FCond_from_FSR",
                                 &sparc64_calculate_FCond_from_FSR, args);
    if (negate) {
        return (unop(Iop_64to1, unop(Iop_Not64, call)));
    } else {
        return (unop(Iop_64to1, call));
    }
}

/* Compare and Branch instructions are non-delayed. */
static Bool
insn_CBcond(sparc64_mnemonic mnemonic, const sparc64_insn *insn,
            DisResult *dres)
{
    Addr64 curPC = guest_PC_curr_instr;
    Addr64 jmp_addr = curPC + insn->operand_values[2].longval;

    /* Handle the second operand. */
    IRExpr *argR;
    if (insn->operands[1]->type == SPARC64_OP_TYPE_IREG_RS2) {
        argR = getIRegOrZR(insn->operand_values[1].uintval);
    } else {
        vassert(insn->operands[1]->type == SPARC64_OP_TYPE_SIMM5);
        argR = mkU64(insn->operand_values[1].longval);
    }

    /* Calculate SUBcc into temporary CCR. */
    IRTemp dep1 = newTemp(Ity_I64);
    IRTemp dep2 = newTemp(Ity_I64);
    assign(dep1, getIRegOrZR(insn->operand_values[0].uintval));
    assign(dep2, argR);

    /* Process condition. */
    SPARC64ICondcode cond_code = sparc64_icond_for_mnemonic(mnemonic);
    switch (mnemonic) {
    case SPARC64_OPC_CWBNE ... SPARC64_OPC_CWBVS:
        break;
    case SPARC64_OPC_CXBNE ... SPARC64_OPC_CXBVS:
        cond_code++;
        break;
    default:
        vassert(0);
    }

    /* No delay slot for CBcond. */
    vassert(dres->whatNext == Dis_Continue);
    vassert(dres->jk_StopHere == Ijk_INVALID);
    dres->whatNext = Dis_StopHere;
    dres->jk_StopHere = Ijk_Boring;

    stmt(IRStmt_Exit(calculate_ICond(cond_code, mkU64(SPARC64_CC_OP_SUB),
                                     mkexpr(dep1), mkexpr(dep2), mkU64(0),
                                     False),
                     Ijk_Boring, IRConst_U64(jmp_addr), OFFSET_sparc64_PC));
    putNPC(mkU64(curPC + 2 * INSN_LENGTH));
    putPC(mkU64(curPC + INSN_LENGTH));
    return (True);
}

static Bool
insn_Bicc_BPcc(sparc64_mnemonic mnemonic, const sparc64_insn *insn,
               DisResult *dres, IRStmt **jmp_stmt, IRExpr **pc_tgt)
{
    Addr64 curPC = guest_PC_curr_instr;
    SPARC64ICondcode cond_code = sparc64_icond_for_mnemonic(mnemonic);
    SPARC64ICondcode icc_cond_code = cond_code;

    UInt disp_idx = sparc64_get_operand_index(mnemonic,
                                              SPARC64_OP_TYPE_GROUP_DISP);
    vassert(disp_idx != -1);
    Addr64 jmp_addr = curPC + insn->operand_values[disp_idx].longval;

    switch (mnemonic) {
    case SPARC64_OPC_BA ... SPARC64_OPC_BVS:
        break;
    case SPARC64_OPC_BPA ... SPARC64_OPC_BPVS:
        /* There is no way to translate prediction bit to IR so don't bother. */

        /* Determine %icc or %xcc. */
        vassert(insn->operands[2]->type == SPARC64_OP_TYPE_I_OR_X_CC_BPcc);
        if (insn->operand_values[2].uintval == 1) {
            cond_code++;
        }
        break;
    default:
        vassert(0);
    }

    /* Annul-bit handling is similar to MIPS branch likely. The main difference
       is that MIPS's likely behavior has annul bit always 1. On SPARC64 this
       can be tuned in the opcode.
       If a conditional branch is taken, the delay slot instruction is always
       executed regardless of the value of the annul bit. If a conditional
       branch is not taken and the annul bit is set, the delay slot instruction
       is annulled (not executed). */
    vassert(jmp_stmt != NULL);
    vassert(pc_tgt != NULL);

    if (insn->operand_values[0].uintval == 1) {
        if ((icc_cond_code == SPARC64_ICOND_A_ICC)
            || (icc_cond_code == SPARC64_ICOND_N_ICC)) {
            /* Unconditional branches with annul bit set behave differently.
               The delay slot instruction is annulled.
               We simply change the flow and stop the disassembler. */
            dres->jk_StopHere = Ijk_Boring;
            dres->whatNext = Dis_StopHere;
            putNPC((icc_cond_code == SPARC64_ICOND_A_ICC) ?
                   mkU64(jmp_addr + INSN_LENGTH) :
                   mkU64(curPC + 3 * INSN_LENGTH));
            putPC((icc_cond_code == SPARC64_ICOND_A_ICC) ?
                  mkU64(jmp_addr) : mkU64(curPC + 2 * INSN_LENGTH));
        } else {
            /* Calculate negated condition. */
            IRExpr *cond = calculate_ICond_from_CCR(cond_code, True);

            /* Exit statement is generated in place and forces Exit on negated
               condition. If a conditional branch with the annul bit set is not
               taken we skip the delay slot instruction. */
            stmt(IRStmt_Exit(cond, Ijk_Boring,
                      IRConst_U64(curPC + 2 * INSN_LENGTH), OFFSET_sparc64_PC));

            /* Modify pc_tgt so that disassembly will continue from branch
               target address. */
            *pc_tgt = mkU64(jmp_addr);
        }
    } else {
        /* BN/BPN is an instruction prefetch which does not make sense to be
           emulated. Thus behave as nop and continue towards delay slot
           instruction. */
        if (icc_cond_code == SPARC64_ICOND_N_ICC)
            return (True);

        /* Calculate condition and store in temp for later reuse. */
        IRTemp cond = newTemp(Ity_I1);
        assign(cond, calculate_ICond_from_CCR(cond_code, False));

        /* The delay slot instruction will be executed (annul bit is clear).
           Exit statement is attached to the delay slot instruction, pointing
           towards branch target. */
        *jmp_stmt = IRStmt_Exit(mkexpr(cond), Ijk_Boring, IRConst_U64(jmp_addr),
                                OFFSET_sparc64_PC);

        /* No need to change flow via pc_tgt. It will automatically pick the
           next instruction after the delay slot. */
    }

    return (True);
}

static Bool
insn_FBPfcc(sparc64_mnemonic mnemonic, const sparc64_insn *insn,
            DisResult *dres, IRStmt **jmp_stmt, IRExpr **pc_tgt)
{
    Addr64 curPC = guest_PC_curr_instr;
    SPARC64FCondcode cond_code = sparc64_fcond_for_mnemonic(mnemonic);
    UInt fccn = insn->operand_values[2].uintval;
    Addr64 jmp_addr = curPC + insn->operand_values[3].longval;

    /* Prediction-bit handling same as for Bicc/BPcc (in short: ignored). */

    vassert(jmp_stmt != NULL);
    vassert(pc_tgt != NULL);

    /* Annul bit handling, for more details see Bicc/BPcc. */
    if (insn->operand_values[0].uintval == 1) {
        if ((cond_code == SPARC64_FCOND_A)
            || (cond_code == SPARC64_FCOND_N)) {
            /* Unconditional branches with annul bit set behave differently.
               The delay slot instruction is annulled.
               We simply change the flow and stop the disassembler. */
            dres->jk_StopHere = Ijk_Boring;
            dres->whatNext = Dis_StopHere;
            putNPC((cond_code == SPARC64_FCOND_A) ?
                   mkU64(jmp_addr + INSN_LENGTH) :
                   mkU64(curPC + 3 * INSN_LENGTH));
            putPC((cond_code == SPARC64_FCOND_A) ?
                  mkU64(jmp_addr) : mkU64(curPC + 2 * INSN_LENGTH));
        } else {
            /* Calculate negated condition. */
            IRExpr *cond = calculate_FCond_from_FSR(cond_code, fccn, True);

            /* Exit statement is generated in place and forces Exit on negated
               condition. If a conditional branch with the annul bit set is not
               taken we skip the delay slot instruction. */
            stmt(IRStmt_Exit(cond, Ijk_Boring,
                      IRConst_U64(curPC + 2 * INSN_LENGTH), OFFSET_sparc64_PC));

            /* Modify pc_tgt so that disassembly will continue from branch
               target address. */
            *pc_tgt = mkU64(jmp_addr);
        }
    } else {
        /* FBPN is an instruction prefetch which does not make sense to be
           emulated. Thus behave as nop and continue towards delay slot
           instruction. */
        if (cond_code == SPARC64_FCOND_N)
            return (True);

        /* Calculate condition and store in temp for later reuse. */
        IRTemp cond = newTemp(Ity_I1);
        assign(cond, calculate_FCond_from_FSR(cond_code, fccn, False));

        /* The delay slot instruction will be executed (annul bit is clear).
           Exit statement is attached to the delay slot instruction, pointing
           towards branch target. */
        *jmp_stmt = IRStmt_Exit(mkexpr(cond), Ijk_Boring, IRConst_U64(jmp_addr),
                                OFFSET_sparc64_PC);

        /* No need to change flow via pc_tgt. It will automatically pick the
           next instruction after the delay slot. */
    }

    return (True);
}

static Bool
insn_BPr(sparc64_mnemonic mnemonic, const sparc64_insn *insn,
         DisResult *dres, IRStmt **jmp_stmt, IRExpr **pc_tgt)
{
    Addr64 curPC = guest_PC_curr_instr;
    Addr64 jmp_addr = curPC + insn->operand_values[3].longval;

    /* Prediction-bit handling same as for Bicc/BPcc (in short: ignored). */

    /* Annul bit handling, for more details see Bicc/BPcc. */
    UInt rs1 = insn->operand_values[2].uintval;
    vassert(jmp_stmt != NULL);
    vassert(pc_tgt != NULL);

    if (insn->operand_values[0].uintval == 1) {
        IRExpr *cond = mk_rcond_expr(mnemonic, getIRegOrZR(rs1), True);
        stmt(IRStmt_Exit(cond, Ijk_Boring, IRConst_U64(curPC + 2 * INSN_LENGTH),
                         OFFSET_sparc64_PC));
        *pc_tgt = mkU64(jmp_addr);
    } else {
        IRTemp cond = newTemp(Ity_I1);
        assign(cond, mk_rcond_expr(mnemonic, getIRegOrZR(rs1), False));
        *jmp_stmt = IRStmt_Exit(mkexpr(cond), Ijk_Boring, IRConst_U64(jmp_addr),
                                OFFSET_sparc64_PC);
    }

    return (True);
}

static Bool
insn_alignaddress(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IRExpr *argL = getIRegOrZR(insn->operand_values[0].uintval);
    IRExpr *argR = getIRegOrZR(insn->operand_values[1].uintval);

    IRTemp res = newTemp(Ity_I64);
    assign(res, binop(Iop_Add64, argL, argR));

    putIRegOrZR(insn->operand_values[2].uintval,
                binop(Iop_And64, mkexpr(res), mkU64(0xFFFFFFFFFFFFFFF8)));

    stmt(IRStmt_Put(OFFSET_sparc64_GSR_align,
                  unop(Iop_64to32, binop(Iop_And64, mkexpr(res), mkU64(0x7)))));

    return (True);
}

static Bool
insn_bshuffle(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    PUT_FREG(insn, 2,
             triop(Iop_ShuffleF64, IRExpr_Get(OFFSET_sparc64_GSR_mask, Ity_I32),
                   GET_FREG(insn, 0), GET_FREG(insn, 1)));

    set_fprs_dirty();
    return (True);
}

static Bool
insn_sethi(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    putIRegOrZR(insn->operand_values[1].uintval,
                mkU64(insn->operand_values[0].ulongval));

    return (True);
}

static Bool
insn_call(sparc64_mnemonic mnemonic, const sparc64_insn *insn, IRExpr **pc_tgt)
{
    Addr64 curPC = guest_PC_curr_instr;
    Addr64 call_tgt = curPC + insn->operand_values[0].longval;

    stmt(IRStmt_Put(OFFSET_sparc64_O7, mkU64(guest_PC_curr_instr)));

    /* Exit logic is the same as for any branch delay slot instruction. */
    vassert(pc_tgt != NULL);
    *pc_tgt = mkU64(call_tgt);

    return (True);
}

static Bool
insn_logic(sparc64_mnemonic mnemonic, const sparc64_insn_al *insn)
{
    IROp ir_op;
    Bool is_neg;
    Bool is_cc;

#   define ASSIGN(_ir_op, _is_neg, _is_cc) \
    ir_op = Iop_##_ir_op;                  \
    is_neg = _is_neg;                      \
    is_cc = _is_cc;

    switch (mnemonic) {
    case SPARC64_OPC_AND:    ASSIGN(And64, False, False); break;
    case SPARC64_OPC_ANDN:   ASSIGN(And64, True,  False); break;
    case SPARC64_OPC_ANDcc:  ASSIGN(And64, False, True);  break;
    case SPARC64_OPC_ANDNcc: ASSIGN(And64, True,  True);  break;
    case SPARC64_OPC_OR:     ASSIGN(Or64,  False, False); break;
    case SPARC64_OPC_ORN:    ASSIGN(Or64,  True,  False); break;
    case SPARC64_OPC_ORcc:   ASSIGN(Or64,  False, True);  break;
    case SPARC64_OPC_ORNcc:  ASSIGN(Or64,  True,  True);  break;
    case SPARC64_OPC_XOR:    ASSIGN(Xor64, False, False); break;
    case SPARC64_OPC_XNOR:   ASSIGN(Xor64, True,  False); break;
    case SPARC64_OPC_XORcc:  ASSIGN(Xor64, False, True);  break;
    case SPARC64_OPC_XNORcc: ASSIGN(Xor64, True,  True);  break;
    default:
        vassert(0);
    }
#   undef ASSIGN

    /* Handle the second operand. */
    IRExpr *argR;
    if (insn->op_rs2_imm->type == SPARC64_OP_TYPE_IREG_RS2) {
        argR = getIRegOrZR(insn->val_rs2_imm.uintval);
    } else {
        vassert(insn->op_rs2_imm->type == SPARC64_OP_TYPE_SIMM13);
        argR = mkU64(insn->val_rs2_imm.longval);
    }

    /* Negate the second operand if required. */
    if (is_neg) {
        argR = unop(Iop_Not64, argR);
    }

    /* Calculate the result and update the CCR thunk. */
    IRTemp res = newTemp(Ity_I64);
    assign(res, binop(ir_op, getIRegOrZR(insn->val_rs1.uintval), argR));
    if (is_cc) {
        setFlags_DEP1(SPARC64_CC_OP_LOGIC, mkexpr(res));
    }
    putIRegOrZR(insn->val_rd.uintval, mkexpr(res));

    return (True);
}

static IRExpr *
get_load_store_effective_address(sparc64_mnemonic mnemonic,
                                 const sparc64_insn *insn)
{
    /* Handle the right argument. */
    UInt rs2_imm_idx = sparc64_get_operand_index(
                           mnemonic, SPARC64_OP_TYPE_GROUP_RS2_OR_IMM);
    IRExpr *argR;
    if (insn->operands[rs2_imm_idx]->type == SPARC64_OP_TYPE_IREG_RS2) {
        argR = getIRegOrZR(insn->operand_values[rs2_imm_idx].uintval);
    } else {
        vassert(insn->operands[rs2_imm_idx]->type == SPARC64_OP_TYPE_SIMM13);
        argR = mkU64(insn->operand_values[rs2_imm_idx].longval);
    }

    /* Calcute effective address. */
    UInt rs1_idx = sparc64_get_operand_index(
                       mnemonic, SPARC64_OP_TYPE_GROUP_RS1);
    return binop(Iop_Add64, getIRegOrZR(insn->operand_values[rs1_idx].uintval),
                 argR);
}

static IRExpr *
get_load_store_asi(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    UInt asi_idx = sparc64_get_operand_index(mnemonic,
                                             SPARC64_OP_TYPE_GROUP_ASI);
    if (insn->operands[asi_idx]->type == SPARC64_OP_TYPE_ASI_IMM) {
        return mkU8(insn->operand_values[asi_idx].uintval);
    } else {
        vassert(insn->operands[asi_idx]->type == SPARC64_OP_TYPE_ASI_IMPL);
        return unop(Iop_64to8, getAsrReg(SPARC64_ASR_ASI));
    }
}

static Bool
insn_load(sparc64_mnemonic mnemonic, const sparc64_insn *insn,
          Bool is_asi, Bool is_fp)
{
    UInt size;
    Bool is_sext;

#   define ASSIGN(_size, _is_sext) \
    size = _size;                  \
    is_sext = _is_sext;

    switch (mnemonic) {
    case SPARC64_OPC_LDSB:  ASSIGN( 1, True);  break;
    case SPARC64_OPC_LDSH:  ASSIGN( 2, True);  break;
    case SPARC64_OPC_LDSW:  ASSIGN( 4, True);  break;
    case SPARC64_OPC_LDUB:  ASSIGN( 1, False); break;
    case SPARC64_OPC_LDUH:  ASSIGN( 2, False); break;
    case SPARC64_OPC_LDUW:  ASSIGN( 4, False); break;
    case SPARC64_OPC_LDX:   ASSIGN( 8, False); break;
    case SPARC64_OPC_LDSBA: ASSIGN( 1, True);  break;
    case SPARC64_OPC_LDSHA: ASSIGN( 2, True);  break;
    case SPARC64_OPC_LDSWA: ASSIGN( 4, True);  break;
    case SPARC64_OPC_LDUBA: ASSIGN( 1, False); break;
    case SPARC64_OPC_LDUHA: ASSIGN( 2, False); break;
    case SPARC64_OPC_LDUWA: ASSIGN( 4, False); break;
    case SPARC64_OPC_LDXA:  ASSIGN( 8, False); break;
    case SPARC64_OPC_LDF:   ASSIGN( 4, False); break;
    case SPARC64_OPC_LDDF:  ASSIGN( 8, False); break;
    case SPARC64_OPC_LDQF:  ASSIGN(16, False); break;
    default:
        vassert(0);
    }
#   undef ASSIGN

    IRExpr *ea_expr = get_load_store_effective_address(mnemonic, insn);

    IRExpr *asi_expr = (is_asi) ? get_load_store_asi(mnemonic, insn) : NULL;

    UInt rd_idx = sparc64_get_operand_index(mnemonic, SPARC64_OP_TYPE_GROUP_RD);
    if (is_fp) {
        putFReg(insn->operand_values[rd_idx].uintval, size,
                IRExpr_LoadA(Iend_BE, mkFpType(size), ea_expr, asi_expr));
        set_fprs_dirty();
    } else {
        putIRegOrZR(insn->operand_values[rd_idx].uintval,
                    narrow_load(size, is_sext, ea_expr, asi_expr));
    }

    return (True);
}

static Bool
insn_store(sparc64_mnemonic mnemonic, const sparc64_insn *insn,
           Bool is_asi, Bool is_fp)
{
    UInt size;

#   define ASSIGN(_size) \
    size = _size;

    switch (mnemonic) {
    case SPARC64_OPC_STB:  ASSIGN( 1); break;
    case SPARC64_OPC_STH:  ASSIGN( 2); break;
    case SPARC64_OPC_STW:  ASSIGN( 4); break;
    case SPARC64_OPC_STX:  ASSIGN( 8); break;
    case SPARC64_OPC_STBA: ASSIGN( 1); break;
    case SPARC64_OPC_STHA: ASSIGN( 2); break;
    case SPARC64_OPC_STWA: ASSIGN( 4); break;
    case SPARC64_OPC_STXA: ASSIGN( 8); break;
    case SPARC64_OPC_STF:  ASSIGN( 4); break;
    case SPARC64_OPC_STDF: ASSIGN( 8); break;
    case SPARC64_OPC_STQF: ASSIGN(16); break;
    default:
        vassert(0);
    }
#   undef ASSIGN

    IRExpr *ea_expr = get_load_store_effective_address(mnemonic, insn);

    IRExpr *asi_expr = (is_asi) ? get_load_store_asi(mnemonic, insn) : NULL;

    UInt rd_idx = sparc64_get_operand_index(mnemonic, SPARC64_OP_TYPE_GROUP_RD);
    if (is_fp) {
        stmt(IRStmt_StoreA(Iend_BE, ea_expr,
                           getFReg(insn->operand_values[rd_idx].uintval, size),
                           asi_expr));
    } else {
        narrow_store(size, ea_expr,
                     getIRegOrZR(insn->operand_values[rd_idx].uintval),
                     asi_expr);
    }

    return (True);
}

static Bool
insn_load_block(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IRExpr *ea_expr = get_load_store_effective_address(mnemonic, insn);

    if (insn->operands[2]->type == SPARC64_OP_TYPE_ASI_IMM) {
        if (insn->operand_values[2].uintval != SPARC64_ASI_BLOCK_PRIMARY) {
            print_insn(insn);
            DIP("SPARC64: Unsupported block-load with an ASI != ASI_BLK_P\n");
            return False;
        }
    } else {
        vassert(insn->operands[2]->type == SPARC64_OP_TYPE_ASI_IMPL);
        print_insn(insn);
        DIP("SPARC64: Unsupported block-load with implicit ASI register\n");
        return False;
    }

    UInt rd = insn->operand_values[3].uintval;
    for (UInt i = 0; i < 8; i++) {
        putFReg(rd + i * 2, 8,
                IRExpr_Load(Iend_BE, Ity_F64,
                            binop(Iop_Add64, ea_expr, mkU64(i * 8))));
    }

    set_fprs_dirty();
    return True;
}

static Bool
insn_load_short_float(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IRExpr *ea_expr = get_load_store_effective_address(mnemonic, insn);

    IRType ty;
    IROp widening;
    if (insn->operands[2]->type == SPARC64_OP_TYPE_ASI_IMM) {
        switch (insn->operand_values[2].uintval) {
        case SPARC64_ASI_FL8_PRIMARY:
            ty = Ity_I8;  widening = Iop_8Uto64;  break;
        case SPARC64_ASI_FL16_PRIMARY:
            ty = Ity_I16; widening = Iop_16Uto64; break;
        default:
            print_insn(insn);
            DIP("SPARC64: Unsupported short-float-load with an ASI != "
                "ASI_FL8_P or ASI_FL16_P\n");
            return False;
        }
    } else {
        vassert(insn->operands[2]->type == SPARC64_OP_TYPE_ASI_IMPL);
        print_insn(insn);
        DIP("SPARC64: Unsupported short-float-load with implicit ASI "
            "register\n");
        return False;
    }

    IRExpr *arg = unop(Iop_ReinterpI64asF64,
                       unop(widening, IRExpr_Load(Iend_BE, ty, ea_expr)));
    putFReg(insn->operand_values[3].uintval, 8, arg);

    set_fprs_dirty();
    return True;
}


/* Converts FSR.rd from the native sparc64 format to IRRoundingMode
   representation. */
static IRExpr *
convert_fsr_rd_to_ir(IRExpr *fsr)
{
    /* Mask and shift rd out of raw %fsr. */
    IRTemp fsr_rd = newTemp(Ity_I64);
    assign(fsr_rd, binop(Iop_Shr64,
                         binop(Iop_And64, fsr, mkU64(SPARC64_FSR_MASK_RD)),
                         mkU8(SPARC64_FSR_SHIFT_RD)));

    /* rounding mode | sparc64 | IR
       ----------------------------
       to nearest    | 00      | 00
       to zero       | 01      | 11
       to +infinity  | 10      | 10
       to -infinity  | 11      | 01

       So the formula is XOR(fsr_rd, (fsr_rd << 1) & 2) */

    return binop(Iop_Xor64,
                 mkexpr(fsr_rd),
                 binop(Iop_And64,
                       binop(Iop_Shl64, mkexpr(fsr_rd), mkU8(1)),
                       mkU64(2)));
}

/* Converts rd from IRRoundingMode representation to native sparc64 format,
   shifted accordingly. */
static IRExpr *
convert_ir_rd_to_fsr(IRExpr *ir_rd)
{
    /* rounding mode | IR | sparc64
       ----------------------------
       to nearest    | 00 | 00
       to -infinity  | 01 | 11
       to +infinity  | 10 | 10
       to zero       | 11 | 01

       So the formula is (~(ir_rd << 62)) >> 62      [kudos to superopt] */

    return binop(Iop_Shr64,
                 binop(Iop_Sub64, /* this would be Iop_Neg64 */
                       mkU64(0),
                       binop(Iop_Shl64, ir_rd, mkU8(62))),
                 mkU8(62 - SPARC64_FSR_SHIFT_RD));
}

static Bool
insn_ldfsr(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IRExpr *ea_expr = get_load_store_effective_address(mnemonic, insn);
    IRTemp fsr = newTemp(Ity_I64);

    switch (mnemonic) {
    case SPARC64_OPC_LDFSR:
        assign(fsr, unop(Iop_32Uto64, IRExpr_Load(Iend_BE, Ity_I32, ea_expr)));
        break;
    case SPARC64_OPC_LDXFSR:
        assign(fsr, IRExpr_Load(Iend_BE, Ity_I64, ea_expr));
        break;
    default:
        vassert(0);
    }

    /* Disallow setting FSR.tem and FSR.ns. */
    IRExpr *call = mkIRExprCCall(Ity_I64, 0, "sparc64_check_FSR",
                                 &sparc64_check_FSR,
                                 mkIRExprVec_1(mkexpr(fsr)));
    IRTemp ew = newTemp(Ity_I32);
    assign(ew, unop(Iop_64to32, call));
    stmt(IRStmt_Put(OFFSET_sparc64_EMNOTE, mkexpr(ew)));

    /* Only FSR.rd, FSR.fcc and FSR.cexc are observed.
       FSR.aexc is silently ignored. */
    stmt(IRStmt_Put(OFFSET_sparc64_FSR_RD, convert_fsr_rd_to_ir(mkexpr(fsr))));

    IRTemp fcc = newTemp(Ity_I64);
    switch (mnemonic) {
    case SPARC64_OPC_LDFSR:
        assign(fcc, binop(Iop_And64, mkexpr(fsr),
                          mkU64(SPARC64_FSR_MASK_FCC0)));
        break;
    case SPARC64_OPC_LDXFSR:
        assign(fcc, binop(Iop_And64, mkexpr(fsr), mkU64(SPARC64_FSR_MASK_FCC)));
        break;
    default:
        vassert(0);
    }
    stmt(IRStmt_Put(OFFSET_sparc64_FSR_FCC, mkexpr(fcc)));

    IRTemp cexc = newTemp(Ity_I64);
    assign(cexc, binop(Iop_And64, mkexpr(fsr), mkU64(SPARC64_FSR_MASK_CEXC)));
    set_FSR_CEXC_DEP1(SPARC64_FSR_CEXC_OP_COPY, mkexpr(cexc));

    /* Side-exit to the next instruction if an emulation warning is reported.
       So that Valgrind's dispatcher sees the warning. */
    stmt(IRStmt_Exit(binop(Iop_CmpNE32, mkexpr(ew), mkU32(EmNote_NONE)),
                     Ijk_EmWarn, IRConst_U64(guest_PC_curr_instr + INSN_LENGTH),
                     OFFSET_sparc64_PC));

    return (True);
}

static Bool
insn_stfsr(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IRExpr **args = mkIRExprVec_6(
                           IRExpr_Get(OFFSET_sparc64_FSR_CEXC_OP,      Ity_I64),
                           IRExpr_Get(OFFSET_sparc64_FSR_CEXC_DEP1_HI, Ity_I64),
                           IRExpr_Get(OFFSET_sparc64_FSR_CEXC_DEP1_LO, Ity_I64),
                           IRExpr_Get(OFFSET_sparc64_FSR_CEXC_DEP2_HI, Ity_I64),
                           IRExpr_Get(OFFSET_sparc64_FSR_CEXC_DEP2_LO, Ity_I64),
                           IRExpr_Get(OFFSET_sparc64_FSR_CEXC_NDEP,    Ity_I64));
    IRExpr *call = mkIRExprCCall(Ity_I64, 0, "sparc64_calculate_FSR_ver_cexc",
                                 &sparc64_calculate_FSR_ver_cexc, args);
    /* Exclude OP and NDEP from definedness checking. */
    call->Iex.CCall.cee->mcx_mask = (1<<0) | (1<<5);

    /* Combine FSR from FSR_RD, FSR_FCC, FSR.ver and FSR cexc thunks. */
    IRTemp fsr = newTemp(Ity_I64);
    assign(fsr, binop(Iop_Or64,
                      binop(Iop_Or64,
                            IRExpr_Get(OFFSET_sparc64_FSR_FCC, Ity_I64), call),
                      convert_ir_rd_to_fsr(IRExpr_Get(OFFSET_sparc64_FSR_RD,
                                           Ity_I64))));

    IRExpr *ea_expr = get_load_store_effective_address(mnemonic, insn);
    switch (mnemonic) {
    case SPARC64_OPC_STFSR:
        stmt(IRStmt_Store(Iend_BE, ea_expr, unop(Iop_64to32, mkexpr(fsr))));
        break;
    case SPARC64_OPC_STXFSR:
        stmt(IRStmt_Store(Iend_BE, ea_expr, mkexpr(fsr)));
        break;
    default:
        vassert(0);
    }

    return (True);
}

static Bool
insn_ldstub(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    /* Handle the right operand. */
    IRExpr *argR;
    if (insn->operands[1]->type == SPARC64_OP_TYPE_IREG_RS2) {
        argR = getIRegOrZR(insn->operand_values[1].uintval);
    } else {
        vassert(insn->operands[1]->type == SPARC64_OP_TYPE_SIMM13);
        argR = mkU64(insn->operand_values[1].longval);
    }

    /* Calculate final effective address. */
    IRExpr *addr = binop(Iop_Add64,
                         getIRegOrZR(insn->operand_values[0].uintval), argR);

    IRTemp dst = newTemp(Ity_I8);
    stmt(IRStmt_CAS(mkIRCAS(IRTemp_INVALID, dst, Iend_BE,
                            addr, NULL, IRExpr_Load(Iend_BE, Ity_I8, addr),
                            NULL, mkU8(0xFF))));

    /* TODO-SPARC: Remove the widening in sparc64 isel if IRCAS is
       implemented via 'ldstub'. */
    putIRegOrZR(insn->operand_values[2].uintval, unop(Iop_8Uto64, mkexpr(dst)));

    return (True);
}

static Bool
insn_casa_casxa(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    if (insn->operands[1]->type == SPARC64_OP_TYPE_ASI_IMPL) {
        print_insn(insn);
        DIP("SPARC64: Unsupported compare-and-swap with implicit ASI "
            "register\n");
        return (False);
    }

    if (insn->operand_values[1].uintval != SPARC64_ASI_PRIMARY) {
        print_insn(insn);
        DIP("SPARC64: Unsupported compare-and-swap with non-default ASI\n");
        return (False);
    }

    IRExpr *addr = getIRegOrZR(insn->operand_values[0].uintval);
    IRType ty = (mnemonic == SPARC64_OPC_CASA) ? Ity_I32 : Ity_I64;
    IRTemp dst = newTemp(ty);
    IRTemp exp = newTemp(ty);
    IRTemp new = newTemp(ty);

    UInt rs2 = insn->operand_values[2].uintval;
    UInt rd = insn->operand_values[3].uintval;
    if (ty == Ity_I32) {
        assign(exp, unop(Iop_64to32, getIRegOrZR(rs2)));
        assign(new, unop(Iop_64to32, getIRegOrZR(rd)));
    } else {
        assign(exp, getIRegOrZR(rs2));
        assign(new, getIRegOrZR(rd));
    }

    stmt(IRStmt_CAS(mkIRCAS(IRTemp_INVALID, dst, Iend_BE,
                            addr, NULL, mkexpr(exp), NULL, mkexpr(new))));

    if (ty == Ity_I32) {
        /* TODO-SPARC: Remove the widening in sparc64 isel if IRCAS is
           implemented via 32-bit 'cas'. */
        putIRegOrZR(rd, unop(Iop_32Uto64, mkexpr(dst)));
    } else {
        putIRegOrZR(rd, mkexpr(dst));
    }

    return (True);
}

static Bool
insn_swap(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    /* Handle the left operand. */
    IRExpr *argL;
    if (insn->operands[1]->type == SPARC64_OP_TYPE_IREG_RS2) {
        argL = getIRegOrZR(insn->operand_values[1].uintval);
    } else {
        vassert(insn->operands[1]->type == SPARC64_OP_TYPE_SIMM13);
        argL = mkU64(insn->operand_values[1].longval);
    }

    /* Calculate final effective address. */
    IRExpr *addr = binop(Iop_Add64,
                         getIRegOrZR(insn->operand_values[0].uintval), argL);

    IRTemp argR = newTemp(Ity_I32);
    assign(argR,
           unop(Iop_64to32, getIRegOrZR(insn->operand_values[2].uintval)));

    IRTemp dst = newTemp(Ity_I32);
    stmt(IRStmt_CAS(mkIRCAS(IRTemp_INVALID, dst, Iend_BE,
                            addr, NULL, IRExpr_Load(Iend_BE, Ity_I32, addr),
                            NULL, mkexpr(argR))));

    /* TODO-SPARC: Remove the widening in sparc64 isel if this IRCAS is
       implemented via 'swap'. */
    putIRegOrZR(insn->operand_values[2].uintval,
                unop(Iop_32Uto64, mkexpr(dst)));

    return (True);
}

static Bool
insn_save_restore(sparc64_mnemonic mnemonic, const sparc64_insn_al *insn)
{
    /* Handle the second operand. */
    IRExpr *argR;
    if (insn->op_rs2_imm->type == SPARC64_OP_TYPE_IREG_RS2) {
        argR = getIRegOrZR(insn->val_rs2_imm.uintval);
    } else {
        vassert(insn->op_rs2_imm->type == SPARC64_OP_TYPE_SIMM13);
        argR = mkU64(insn->val_rs2_imm.longval);
    }

    /* Calculate "ADD rs1, rs2, rd" where rs1, rs2 come from the old window.
       However destination register rd targets new window. */
    IRTemp res = newTemp(Ity_I64);
    assign(res, binop(Iop_Add64, getIRegOrZR(insn->val_rs1.uintval), argR));

    if (mnemonic == SPARC64_OPC_SAVE) {
        /* Emulate immediate spill. */
        IRTemp sa_base = newTemp(Ity_I64);
        assign(sa_base, IRExpr_Get(OFFSET_sparc64_O6, Ity_I64));

        savearea_store(OFFSET_sparc64_R16, sa_base,   0); /* %l0 */
        savearea_store(OFFSET_sparc64_R17, sa_base,   8);
        savearea_store(OFFSET_sparc64_R18, sa_base,  16);
        savearea_store(OFFSET_sparc64_R19, sa_base,  24);
        savearea_store(OFFSET_sparc64_R20, sa_base,  32);
        savearea_store(OFFSET_sparc64_R21, sa_base,  40);
        savearea_store(OFFSET_sparc64_R22, sa_base,  48);
        savearea_store(OFFSET_sparc64_R23, sa_base,  56);
        savearea_store(OFFSET_sparc64_R24, sa_base,  64); /* %i0 */
        savearea_store(OFFSET_sparc64_R25, sa_base,  72);
        savearea_store(OFFSET_sparc64_R26, sa_base,  80);
        savearea_store(OFFSET_sparc64_R27, sa_base,  88);
        savearea_store(OFFSET_sparc64_R28, sa_base,  96);
        savearea_store(OFFSET_sparc64_R29, sa_base, 104);
        savearea_store(OFFSET_sparc64_R31, sa_base, 120);
        savearea_store(OFFSET_sparc64_R30, sa_base, 112);

        /* %o -> %i */
        stmt(IRStmt_Put(OFFSET_sparc64_R24, IRExpr_Get(OFFSET_sparc64_R8,  Ity_I64)));
        stmt(IRStmt_Put(OFFSET_sparc64_R25, IRExpr_Get(OFFSET_sparc64_R9,  Ity_I64)));
        stmt(IRStmt_Put(OFFSET_sparc64_R26, IRExpr_Get(OFFSET_sparc64_R10, Ity_I64)));
        stmt(IRStmt_Put(OFFSET_sparc64_R27, IRExpr_Get(OFFSET_sparc64_R11, Ity_I64)));
        stmt(IRStmt_Put(OFFSET_sparc64_R28, IRExpr_Get(OFFSET_sparc64_R12, Ity_I64)));
        stmt(IRStmt_Put(OFFSET_sparc64_R29, IRExpr_Get(OFFSET_sparc64_R13, Ity_I64)));
        stmt(IRStmt_Put(OFFSET_sparc64_R30, IRExpr_Get(OFFSET_sparc64_R14, Ity_I64)));
        stmt(IRStmt_Put(OFFSET_sparc64_R31, IRExpr_Get(OFFSET_sparc64_R15, Ity_I64)));
    } else {
        /* %i -> %o */
        stmt(IRStmt_Put(OFFSET_sparc64_R8,  IRExpr_Get(OFFSET_sparc64_R24, Ity_I64)));
        stmt(IRStmt_Put(OFFSET_sparc64_R9,  IRExpr_Get(OFFSET_sparc64_R25, Ity_I64)));
        stmt(IRStmt_Put(OFFSET_sparc64_R10, IRExpr_Get(OFFSET_sparc64_R26, Ity_I64)));
        stmt(IRStmt_Put(OFFSET_sparc64_R11, IRExpr_Get(OFFSET_sparc64_R27, Ity_I64)));
        stmt(IRStmt_Put(OFFSET_sparc64_R12, IRExpr_Get(OFFSET_sparc64_R28, Ity_I64)));
        stmt(IRStmt_Put(OFFSET_sparc64_R13, IRExpr_Get(OFFSET_sparc64_R29, Ity_I64)));
        stmt(IRStmt_Put(OFFSET_sparc64_R14, IRExpr_Get(OFFSET_sparc64_R30, Ity_I64)));
        stmt(IRStmt_Put(OFFSET_sparc64_R15, IRExpr_Get(OFFSET_sparc64_R31, Ity_I64)));

        /* Emulate immediate restore. */
        IRTemp sa_base = newTemp(Ity_I64);
        assign(sa_base, IRExpr_Get(OFFSET_sparc64_I6, Ity_I64));

        savearea_restore(OFFSET_sparc64_R16, sa_base,   0); /* %l0 */
        savearea_restore(OFFSET_sparc64_R17, sa_base,   8);
        savearea_restore(OFFSET_sparc64_R18, sa_base,  16);
        savearea_restore(OFFSET_sparc64_R19, sa_base,  24);
        savearea_restore(OFFSET_sparc64_R20, sa_base,  32);
        savearea_restore(OFFSET_sparc64_R21, sa_base,  40);
        savearea_restore(OFFSET_sparc64_R22, sa_base,  48);
        savearea_restore(OFFSET_sparc64_R23, sa_base,  56);
        savearea_restore(OFFSET_sparc64_R24, sa_base,  64); /* %i0 */
        savearea_restore(OFFSET_sparc64_R25, sa_base,  72);
        savearea_restore(OFFSET_sparc64_R26, sa_base,  80);
        savearea_restore(OFFSET_sparc64_R27, sa_base,  88);
        savearea_restore(OFFSET_sparc64_R28, sa_base,  96);
        savearea_restore(OFFSET_sparc64_R29, sa_base, 104);
        savearea_restore(OFFSET_sparc64_R31, sa_base, 120);
	/* %fp is used to locate save area on the stack and reload
	   other registers thus it must be restored as the last register. */
        savearea_restore(OFFSET_sparc64_I6, sa_base, 112);
    }

    /* %rd is from the new window */
    putIRegOrZR(insn->val_rd.uintval, mkexpr(res));

    /* IR optimizer can rearrange code so that effect of save/restore is not
       immediately visible. This seriously impacts stack unwinding and core
       dumping. Tell the IR optimizer to stop playing tricks at this point. */
    stmt(IRStmt_MBE(Imbe_Fence));

    return (True);
}

static Bool
insn_arithmetic(sparc64_mnemonic mnemonic, const sparc64_insn_al *insn)
{
    IROp ir_op;
    SPARC64_CC_OP cc_op;
    Bool takes_ic; /* carry from %ccr.icc.c */
    Bool takes_xc; /* carry from %ccr.xcc.c */
    Bool outputs_cc = (insn->opcode->flags & SPARC64_OPF_CCR_OUT) != 0;
    Bool has_32bit_op;

#   define ASSIGN(_ir_op, _cc_op, _takes_ic, _takes_xc, _has_32bit_op) \
    ir_op = Iop_##_ir_op;                                              \
    cc_op = SPARC64_CC_OP_##_cc_op;                                    \
    takes_ic = _takes_ic;                                              \
    takes_xc = _takes_xc;                                              \
    has_32bit_op = _has_32bit_op;

    switch (mnemonic) {
    case SPARC64_OPC_ADD:     ASSIGN(Add64,      ADD,  False, False, False); break;
    case SPARC64_OPC_ADDcc:   ASSIGN(Add64,      ADD,  False, False, False); break;
    case SPARC64_OPC_ADDC:    ASSIGN(Add64,      ADDC, True,  False, False); break;
    case SPARC64_OPC_ADDCcc:  ASSIGN(Add64,      ADDC, True,  False, False); break;
    case SPARC64_OPC_ADDXC:   ASSIGN(Add64,      ADDC, False, True,  False); break;
    case SPARC64_OPC_ADDXCcc: ASSIGN(Add64,      ADDC, False, True,  False); break;
    case SPARC64_OPC_BMASK:   ASSIGN(Add64,      ADD,  False, False, False); break;
    case SPARC64_OPC_MULX:    ASSIGN(Mul64,      COPY, False, False, False); break;
    case SPARC64_OPC_SDIVX:   ASSIGN(DivS64,     COPY, False, False, False); break;
    case SPARC64_OPC_UDIVX:   ASSIGN(DivU64,     COPY, False, False, False); break;
    case SPARC64_OPC_SDIV:    ASSIGN(DivS64to32, COPY, False, False, True);  break;
    case SPARC64_OPC_SDIVcc:  ASSIGN(DivS64to32, SDIV, False, False, True);  break;
    case SPARC64_OPC_SMUL:    ASSIGN(MullS32,    COPY, False, False, True);  break;
    case SPARC64_OPC_SMULcc:  ASSIGN(MullS32,    SMUL, False, False, True);  break;
    case SPARC64_OPC_SUB:     ASSIGN(Sub64,      SUB,  False, False, False); break;
    case SPARC64_OPC_SUBcc:   ASSIGN(Sub64,      SUB,  False, False, False); break;
    case SPARC64_OPC_SUBC:    ASSIGN(Sub64,      SUBC, True,  False, False); break;
    case SPARC64_OPC_SUBCcc:  ASSIGN(Sub64,      SUBC, True,  False, False); break;
    case SPARC64_OPC_UDIV:    ASSIGN(DivU64to32, COPY, False, False, True);  break;
    case SPARC64_OPC_UDIVcc:  ASSIGN(DivU64to32, UDIV, False, False, True);  break;
    case SPARC64_OPC_UMUL:    ASSIGN(MullU32,    COPY, False, False, True);  break;
    case SPARC64_OPC_UMULcc:  ASSIGN(MullU32,    UMUL, False, False, True);  break;
    case SPARC64_OPC_UMULXHI: ASSIGN(MulHiU64,   COPY, False, False, False); break;
    default:
        vassert(0);
    }
#   undef ASSIGN

    /* Stay sane. */
    vassert(!((takes_ic == takes_xc) && (takes_xc == True)));

    /* In the following code src<L|R> denotes 64-bit wide
       while arg<L|R> could be 64-bit or 32-bit wide. */
    IRExpr *srcL = getIRegOrZR(insn->val_rs1.uintval);
    IRExpr *argL = srcL;
    if (has_32bit_op) {
        argL = unop(Iop_64to32, srcL);

        if ((insn->opcode->flags & SPARC64_OPF_Y_IN) != 0) {
            argL = binop(Iop_Or64, unop(Iop_32Uto64, argL),
                         binop(Iop_Shl64, getAsrReg(SPARC64_ASR_Y), mkU8(32)));
            srcL = argL;
        }
    }

    /* Handle the second operand (rs2 or imm). */
    IRExpr *srcR, *argR;
    if (insn->op_rs2_imm->type == SPARC64_OP_TYPE_IREG_RS2) {
        srcR = getIRegOrZR(insn->val_rs2_imm.uintval);
        argR = srcR;
        if (has_32bit_op) {
            argR = unop(Iop_64to32, srcR);
        }
    } else {
        vassert(insn->op_rs2_imm->type == SPARC64_OP_TYPE_SIMM13);

        srcR = mkU64(insn->val_rs2_imm.longval);
        argR = srcR;
        if (has_32bit_op) {
            argR = mkU32(insn->val_rs2_imm.longval);
        }
    }

    /* Update the CCR thunk. */
    IRTemp dep1 = newTemp(Ity_I64);
    IRTemp dep2 = newTemp(Ity_I64);
    IRTemp carry = newTemp(Ity_I64);

    if (takes_ic) {
        assign(carry, binop(Iop_And64, getAsrReg(SPARC64_ASR_CCR), mkU64(1)));
    }
    if (takes_xc) {
        assign(carry,
               binop(Iop_Shr64,
                     binop(Iop_And64, getAsrReg(SPARC64_ASR_CCR), mkU64(0x10)),
                     mkU8(4)));
    }

    if (outputs_cc) {
        assign(dep1, srcL);
        assign(dep2, srcR);

        if (takes_ic || takes_xc) {
            setFlags_DEP1_DEP2_NDEP(cc_op, dep1, dep2, carry);
        } else {
            setFlags_DEP1_DEP2(cc_op, dep1, dep2);
        }
    }

    /* Calculate the result. */
    IRTemp result = newTemp(Ity_I64);
    if (takes_ic || takes_xc) {
        assign(result, binop(ir_op, binop(ir_op, argL, argR), mkexpr(carry)));
    } else {
        assign(result, binop(ir_op, argL, argR));
    }
    putIRegOrZR(insn->val_rd.uintval, mkexpr(result));

    if ((insn->opcode->flags & SPARC64_OPF_Y_OUT) != 0) {
        putAsrReg(SPARC64_ASR_Y, binop(Iop_Shr64, mkexpr(result), mkU8(32)));
    } else if (mnemonic == SPARC64_OPC_BMASK) {
        IRExpr *gsr_mask = unop(Iop_64to32, mkexpr(result));
        stmt(IRStmt_Put(OFFSET_sparc64_GSR_mask, gsr_mask));
    }

    return (True);
}

static Bool
insn_aes_round(UInt hwcaps, sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    void *helper_fn;
    const HChar *helper_name;

#   define VG_STRINGIFY(__str)  #__str
#   define ASSIGN(_helper_fn)                            \
    helper_fn   = sparc64_aes_##_helper_fn;              \
    helper_name = VG_STRINGIFY(sparc64_aes_##_helper_fn);

    switch (mnemonic) {
    case SPARC64_OPC_AES_EROUND01:      ASSIGN(eround01);   break;
    case SPARC64_OPC_AES_EROUND23:      ASSIGN(eround23);   break;
    case SPARC64_OPC_AES_DROUND01:      ASSIGN(dround01);   break;
    case SPARC64_OPC_AES_DROUND23:      ASSIGN(dround23);   break;
    case SPARC64_OPC_AES_EROUND01_LAST: ASSIGN(eround01_l); break;
    case SPARC64_OPC_AES_EROUND23_LAST: ASSIGN(eround23_l); break;
    case SPARC64_OPC_AES_DROUND01_LAST: ASSIGN(dround01_l); break;
    case SPARC64_OPC_AES_DROUND23_LAST: ASSIGN(dround23_l); break;
    default:
        vassert(0);
    }
#   undef ASSIGN
#   undef VG_STRINGIFY

    if ((hwcaps & VEX_HWCAPS_SPARC64_SPARC4) != VEX_HWCAPS_SPARC64_SPARC4) {
        /* Our clean helpers leverage corresponding hw instructions directly. */
        return (False);
    }

    IRExpr **args = mkIRExprVec_3(unop(Iop_ReinterpF64asI64, GET_FREG(insn, 0)),
                                 unop(Iop_ReinterpF64asI64, GET_FREG(insn, 1)),
                                 unop(Iop_ReinterpF64asI64, GET_FREG(insn, 2)));
    IRExpr *call = mkIRExprCCall(Ity_I64, 0, helper_name, helper_fn, args);
    PUT_FREG(insn, 3, unop(Iop_ReinterpI64asF64, call));

    set_fprs_dirty();
    return (True);
}

static Bool
insn_aes_kexpand(UInt hwcaps, sparc64_mnemonic mnemonic,
                 const sparc64_insn *insn)
{
    void *helper_fn;
    const HChar *helper_name;

    switch (mnemonic) {
    case SPARC64_OPC_AES_KEXPAND0:
       helper_fn   = sparc64_aes_kexpand0;
       helper_name = "sparc64_aes_kexpand0";
       break;
    case SPARC64_OPC_AES_KEXPAND2:
       helper_fn   = sparc64_aes_kexpand2;
       helper_name = "sparc64_aes_kexpand2";
       break;
    default:
        vassert(0);
    }

    if ((hwcaps & VEX_HWCAPS_SPARC64_SPARC4) != VEX_HWCAPS_SPARC64_SPARC4) {
        /* Our clean helpers leverage corresponding hw instructions directly. */
        return (False);
    }

    IRExpr **args = mkIRExprVec_2(unop(Iop_ReinterpF64asI64, GET_FREG(insn, 0)),
                                 unop(Iop_ReinterpF64asI64, GET_FREG(insn, 1)));
    IRExpr *call = mkIRExprCCall(Ity_I64, 0, helper_name, helper_fn, args);
    PUT_FREG(insn, 2, unop(Iop_ReinterpI64asF64, call));

    set_fprs_dirty();
    return (True);
}

static Bool
insn_aes_kexpand_rcon(UInt hwcaps, sparc64_mnemonic mnemonic,
                      const sparc64_insn *insn)
{
    void *helper_fn;
    const HChar *helper_name;

#   define VG_STRINGIFY(__str)  #__str
#   define ASSIGN(_helper_fn)                                      \
    helper_fn   = sparc64_aes_kexpand1_##_helper_fn;               \
    helper_name = VG_STRINGIFY(sparc64_aes_kexpand1_##_helper_fn);

    UInt imm5 = insn->operand_values[2].ulongval;
    switch (imm5) {
    case 0: ASSIGN(0); break;
    case 1: ASSIGN(1); break;
    case 2: ASSIGN(2); break;
    case 3: ASSIGN(3); break;
    case 4: ASSIGN(4); break;
    case 5: ASSIGN(5); break;
    case 6: ASSIGN(6); break;
    case 7: ASSIGN(7); break;
    case 8: ASSIGN(8); break;
    case 9: ASSIGN(9); break;
    default:
        print_insn(insn);
        DIP("Unsupported imm5 for aes_kexpand1.\n");
        return False;
    }
#   undef ASSIGN
#   undef VG_STRINGIFY

    if ((hwcaps & VEX_HWCAPS_SPARC64_SPARC4) != VEX_HWCAPS_SPARC64_SPARC4) {
        /* Our clean helpers leverage corresponding hw instructions directly. */
        return (False);
    }

    IRExpr **args = mkIRExprVec_2(unop(Iop_ReinterpF64asI64, GET_FREG(insn, 0)),
                                 unop(Iop_ReinterpF64asI64, GET_FREG(insn, 1)));
    IRExpr *call = mkIRExprCCall(Ity_I64, 0, helper_name, helper_fn, args);
    PUT_FREG(insn, 3, unop(Iop_ReinterpI64asF64, call));

    set_fprs_dirty();
    return (True);
}

static Bool
insn_shift(sparc64_mnemonic mnemonic, const sparc64_insn_al *insn)
{
    IROp shift_ir_op;
    Bool is_x;
    Bool needs_narrowing;
    IROp widening_ir_op;

#   define ASSIGN(_shift_ir_op, _is_x, _needs_narrowing, _widening_ir_op) \
    shift_ir_op = Iop_##_shift_ir_op;                                     \
    is_x = _is_x;                                                         \
    needs_narrowing = _needs_narrowing;                                   \
    widening_ir_op = Iop_##_widening_ir_op

    switch (mnemonic) {
    case SPARC64_OPC_SLL:  ASSIGN(Shl64, 0, 0, INVALID); break;
    case SPARC64_OPC_SRL:  ASSIGN(Shr32, 0, 1, 32Uto64); break;
    case SPARC64_OPC_SRA:  ASSIGN(Sar32, 0, 1, 32Sto64); break;
    case SPARC64_OPC_SLLX: ASSIGN(Shl64, 1, 0, INVALID); break;
    case SPARC64_OPC_SRLX: ASSIGN(Shr64, 1, 0, INVALID); break;
    case SPARC64_OPC_SRAX: ASSIGN(Sar64, 1, 0, INVALID); break;
    default:
        vassert(0);
    }
#   undef ASSIGN

    /* Handle the second operand (rs2 or imm). */
    IRExpr *argR;
    if (insn->op_rs2_imm->type == SPARC64_OP_TYPE_IREG_RS2) {
        argR = getIRegOrZR(insn->val_rs2_imm.uintval);

        /* Ensure we use only 5 or 6 bits according to the specification. */
        if (is_x) {
            argR = unop(Iop_64to8, binop(Iop_And64, argR, mkU64(0x3f)));
        } else {
            argR = unop(Iop_64to8, binop(Iop_And64, argR, mkU64(0x1f)));
        }
    } else {
        vassert((insn->op_rs2_imm->type == SPARC64_OP_TYPE_SHCNT32)
                || (insn->op_rs2_imm->type == SPARC64_OP_TYPE_SHCNT64));
        argR = mkU8(insn->val_rs2_imm.uintval);
    }

    /* Generate shift operation. */
    IRExpr *rs1_expr = getIRegOrZR(insn->val_rs1.uintval);
    if (needs_narrowing) {
        rs1_expr = unop(Iop_64to32, rs1_expr);
    }
    IRExpr *shift_expr = binop(shift_ir_op, rs1_expr, argR);
    if (needs_narrowing) {
        shift_expr = unop(widening_ir_op, shift_expr);
    }
    putIRegOrZR(insn->val_rd.uintval, shift_expr);

    return (True);
}

static Bool
insn_trap(sparc64_mnemonic mnemonic, const sparc64_insn *insn, DisResult *dres)
{
    /* We support only Trap Always (ta) variant. */
    if (mnemonic != SPARC64_OPC_TA) {
        print_insn(insn);
        vpanic("Unsupported Tcc variant.");
    }

    /* Likewise, we support only variant with imm_trap_#. */
    if (insn->operands[2]->type != SPARC64_OP_TYPE_IMM8) {
        print_insn(insn);
        vpanic("Unsupported Tcc variant with trap number in rs2.");
    }

    /* And finaly, rs1 must be %g0. */
    if (insn->operand_values[1].uintval != 0) {
        print_insn(insn);
        vpanic("Unsupported Tcc variant with rs1 != %%g0.");
    }

    vassert(dres->whatNext == Dis_Continue);
    vassert(dres->jk_StopHere == Ijk_INVALID);
    dres->whatNext = Dis_StopHere;

    UInt trap_imm = insn->operand_values[2].ulongval;
#   if defined(VGO_linux)
    switch (trap_imm) {
    case 0x6d:
        /* Normal sparc64 "syscall" on Linux. */
        dres->jk_StopHere = Ijk_Sys_syscall;
        break;
    case 0x6e:
        /* Special getcontext() syscall on Linux. */
        dres->jk_StopHere = Ijk_Sys_syscall110;
        break;
    case 0x6f:
        /* Special setcontext() syscall on Linux. */
        dres->jk_StopHere = Ijk_Sys_syscall111;
        break;
    default:
        print_insn(insn);
        vpanic("Unsupported Tcc variant with trap_imm != {0x6d, 0x6e, 0x6f}.");
    }
#   elif defined(VGO_solaris)
    if (trap_imm == 0x40) {
        /* Normal sparc64 "syscall" on Solaris. */
        dres->jk_StopHere = Ijk_Sys_syscall;
    } else {
        /* TODO-SPARC: Convey the fasttrap number in %o0 which will be clobbered
           anyway. Maybe a better solution can be found... */
        stmt(IRStmt_Put(OFFSET_sparc64_O0, mkU64(trap_imm)));
        dres->jk_StopHere = Ijk_Sys_fasttrap;
    }
#   else
#   error Unsupported OS!
#   endif

    putNPC(mkU64(guest_PC_curr_instr + 2 * INSN_LENGTH));
    putPC(mkU64(guest_PC_curr_instr + INSN_LENGTH));
    return (True);
}

static Bool
insn_RDasr(UInt hwcaps, sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    UInt asr = insn->operand_values[0].uintval;
    UInt rd = insn->operand_values[1].uintval;

    switch (asr) {
    case SPARC64_ASR_Y:
    case SPARC64_ASR_CCR:
    case SPARC64_ASR_ASI:
    case SPARC64_ASR_PC:
    case SPARC64_ASR_FPRS:
    case SPARC64_ASR_GSR:
        putIRegOrZR(rd, getAsrReg(asr));
        break;
    case SPARC64_ASR_CFR: {
        ULong cfr = 0;
        if ((hwcaps & VEX_HWCAPS_SPARC64_SPARC6) == VEX_HWCAPS_SPARC64_SPARC6) {
            cfr |= 0x3F8000;
        } else if ((hwcaps & VEX_HWCAPS_SPARC64_SPARC5)
                   == VEX_HWCAPS_SPARC64_SPARC5) {
            cfr |= 0x7000;
        } else if ((hwcaps & VEX_HWCAPS_SPARC64_SPARC4)
                   == VEX_HWCAPS_SPARC64_SPARC4) {
            cfr |= 0xFFB; /* Support everything apart from Kasumi. */
        }
        putIRegOrZR(rd, mkU64(cfr));
        break;
    }
    /* Special cases are handled by a clean helper. */
    case SPARC64_ASR_TICK:
    case SPARC64_ASR_STICK: {
        IRExpr *call = mkIRExprCCall(Ity_I64, 0, "sparc64_helper_rd",
                           &sparc64_helper_rd, mkIRExprVec_1(mkU64(asr)));
        /* Exclude ASR register number from definedness checking. */
        call->Iex.CCall.cee->mcx_mask = 1;
        putIRegOrZR(rd, call);
        break;
    }
    default:
        print_insn(insn);
        vpanic("Unsupported source register for RDasr.");
    }

    return (True);
}

static Bool
insn_WRasr(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    /* Handle the second operand. */
    IRExpr *argR;
    if (insn->operands[1]->type == SPARC64_OP_TYPE_IREG_RS2) {
        argR = getIRegOrZR(insn->operand_values[1].uintval);
    } else {
        vassert(insn->operands[1]->type == SPARC64_OP_TYPE_SIMM13);
        argR = mkU64(insn->operand_values[1].longval);
    }
    argR = binop(Iop_Xor64, getIRegOrZR(insn->operand_values[0].uintval), argR);

    UInt asr = insn->operand_values[2].uintval;
    switch (asr) {
    case SPARC64_ASR_Y:
    case SPARC64_ASR_CCR:
    case SPARC64_ASR_ASI:
    case SPARC64_ASR_GSR:
        putAsrReg(asr, argR);
        break;
    case SPARC64_ASR_FPRS:
        /* Always leave the 'fef' bit on so as to permanently enable FPU.
           Thus we don't need to check for FPU support before any FPop. */
        putAsrReg(asr, binop(Iop_Or64, argR, mkU64(SPARC64_FPRS_MASK_FEF)));
        break;
    case SPARC64_ASR_PAUSE:
        /* Continue after conditionally yielding to scheduler. */
        stmt(IRStmt_Exit(IRExpr_Const(IRConst_U1(1)), Ijk_Yield,
                         IRConst_U64(guest_PC_curr_instr + INSN_LENGTH),
                         OFFSET_sparc64_PC));
        break;
    default:
        print_insn(insn);
        vpanic("Unsupported WRasr destination register.");
    }

    return (True);
}

static Bool
insn_lzcnt(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IRTemp argR = newTemp(Ity_I64);
    assign(argR, getIRegOrZR(insn->operand_values[0].uintval));

    /* Iop_Clz64 is undefined if the input value is 0. Work with this. */
    putIRegOrZR(insn->operand_values[1].uintval,
                IRExpr_ITE(binop(Iop_CmpNE64, mkexpr(argR), mkU64(0)),
                           unop(Iop_Clz64, mkexpr(argR)), mkU64(64)));
    return (True);
}

static Bool
insn_hash(UInt hwcaps,
          void (*dirty_helper)(VexGuestSPARC64State *guest_state),
          const HChar *dirty_helper_name,
          SizeT iv_reg_start_offset,
          UInt iv_size, /* in UInt units */
          SizeT data_reg_start_offset,
          UInt data_size /* in UInt units */)
{
    if ((hwcaps & VEX_HWCAPS_SPARC64_VIS3) != VEX_HWCAPS_SPARC64_VIS3) {
        /* Our dirty helpers leverage corresponding hw instruction directly. */
        return (False);
    }

    IRDirty *d = unsafeIRDirty_0_N(1, dirty_helper_name, dirty_helper,
                                   mkIRExprVec_1(IRExpr_GSPTR()));

    vex_bzero(&d->fxState, sizeof(d->fxState));
    d->nFxState = 2;
    d->fxState[0].fx = Ifx_Modify;
    d->fxState[0].offset = iv_reg_start_offset;
    d->fxState[0].size = iv_size * sizeof(UInt);
    d->fxState[1].fx = Ifx_Read;
    d->fxState[1].offset = data_reg_start_offset;
    d->fxState[1].size = data_size * sizeof(UInt);

    stmt(IRStmt_Dirty(d));

    return (True);
}

static Bool
insn_membar(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    /* All membar variants are translated into one Ist_MBE. */
    stmt(IRStmt_MBE(Imbe_Fence));

    return (True);
}

static Bool
insn_MOVicc(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    /* Handle the right operand. */
    IRExpr *argR;
    if (insn->operands[1]->type == SPARC64_OP_TYPE_IREG_RS2) {
        argR = getIRegOrZR(insn->operand_values[1].uintval);
    } else {
        vassert(insn->operands[1]->type == SPARC64_OP_TYPE_SIMM11);
        argR = mkU64(insn->operand_values[1].longval);
    }

    /* Determine %icc or %xcc. */
    SPARC64ICondcode cond_code = sparc64_icond_for_mnemonic(mnemonic);
    vassert(insn->operands[0]->type == SPARC64_OP_TYPE_I_OR_X_CC_MOVcc);
    if (insn->operand_values[0].uintval == 1) {
        cond_code++;
    }

    putIRegOrZR(insn->operand_values[2].uintval,
                IRExpr_ITE(calculate_ICond_from_CCR(cond_code, False),
                           argR, getIRegOrZR(insn->operand_values[2].uintval)));

    return (True);
}

static Bool
insn_MOVfcc(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    /* Handle the right operand. */
    IRExpr *argR;
    if (insn->operands[1]->type == SPARC64_OP_TYPE_IREG_RS2) {
        argR = getIRegOrZR(insn->operand_values[1].uintval);
    } else {
        vassert(insn->operands[1]->type == SPARC64_OP_TYPE_SIMM11);
        argR = mkU64(insn->operand_values[1].longval);
    }

    SPARC64FCondcode cond_code = sparc64_fcond_for_mnemonic(mnemonic);
    UInt fccn = insn->operand_values[0].uintval;

    putIRegOrZR(insn->operand_values[2].uintval,
                IRExpr_ITE(calculate_FCond_from_FSR(cond_code, fccn, False),
                           argR, getIRegOrZR(insn->operand_values[2].uintval)));

    return (True);
}

static Bool
insn_MOVr(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    /* Handle the right operand. */
    IRExpr *argR;
    if (insn->operands[1]->type == SPARC64_OP_TYPE_IREG_RS2) {
        argR = getIRegOrZR(insn->operand_values[1].uintval);
    } else {
        vassert(insn->operands[1]->type == SPARC64_OP_TYPE_SIMM10);
        argR = mkU64(insn->operand_values[1].longval);
    }

    IRExpr *rcond = mk_rcond_expr(mnemonic,
                                  getIRegOrZR(insn->operand_values[0].uintval),
                                  False);
    putIRegOrZR(insn->operand_values[2].uintval,
                IRExpr_ITE(rcond, argR,
                           getIRegOrZR(insn->operand_values[2].uintval)));

    return (True);
}

static Bool
insn_MOVfTOi(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IROp ir_op;
    IRType ir_type;

#   define ASSIGN(_ir_op, _ir_type)  \
    ir_op = Iop_##_ir_op;            \
    ir_type = Ity_##_ir_type;

    switch (mnemonic) {
    case SPARC64_OPC_MOVsTOsw: ASSIGN(32Sto64, I32); break;
    case SPARC64_OPC_MOVsTOuw: ASSIGN(32Uto64, I32); break;
    case SPARC64_OPC_MOVdTOx:  ASSIGN(INVALID, I64); break;
    default:
        vassert(0);
    }
#   undef ASSIGN

    /* Retrieve a floating-point register value from the guest state directly
       as an integer one, to avoid Iop_Reinterp hassle. */
    IRExpr *srcR = IRExpr_Get(offsetFReg64(insn->operand_values[0].uintval,
                                           insn->operands[0]->op_size),
                              ir_type);

    if (ir_op != Iop_INVALID) {
        srcR = unop(ir_op, srcR);
    }

    putIRegOrZR(insn->operand_values[1].uintval, srcR);
    return (True);
}

static Bool
insn_MOViTOf(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IRExpr *srcR = getIRegOrZR(insn->operand_values[0].uintval);
    if (mnemonic == SPARC64_OPC_MOVwTOs) {
        srcR = unop(Iop_64to32, srcR);
    }

    PUT_FREG(insn, 1, srcR);

    set_fprs_dirty();
    return (True);
}

static Bool
insn_xmulx(UInt hwcaps, sparc64_mnemonic mnemonic, const sparc64_insn_al *insn)
{
    if ((hwcaps & VEX_HWCAPS_SPARC64_VIS3) != VEX_HWCAPS_SPARC64_VIS3) {
        /* Our clean helper leverages corresponding hw instruction directly. */
        return (False);
    }

    IRExpr **args = mkIRExprVec_2(getIRegOrZR(insn->val_rs1.uintval),
                                  getIRegOrZR(insn->val_rs2_imm.uintval));
    const HChar *helper_name;
    void *helper_fn;
    switch (mnemonic) {
    case SPARC64_OPC_XMULX:
        helper_name = "sparc64_xmulx";   helper_fn = sparc64_xmulx;
        break;
    case SPARC64_OPC_XMULXHI:
        helper_name = "sparc64_xmulxhi"; helper_fn = sparc64_xmulxhi;
        break;
    default:
        vassert(0);
    }

    putIRegOrZR(insn->val_rd.uintval,
                mkIRExprCCall(Ity_I64, 0, helper_name, helper_fn, args));

    return (True);
}

static Bool
insn_fabs_fneg(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IROp ir_op;

#   define ASSIGN(_ir_op) \
    ir_op = Iop_##_ir_op;

    switch (mnemonic) {
    case SPARC64_OPC_FABSs: ASSIGN(AbsF32);  break;
    case SPARC64_OPC_FABSd: ASSIGN(AbsF64);  break;
    case SPARC64_OPC_FABSq: ASSIGN(AbsF128); break;
    case SPARC64_OPC_FNEGs: ASSIGN(NegF32);  break;
    case SPARC64_OPC_FNEGd: ASSIGN(NegF64);  break;
    case SPARC64_OPC_FNEGq: ASSIGN(NegF128); break;
    default:
        vassert(0);
    }
#   undef ASSIGN

    IRExpr *srcR = GET_FREG(insn, 0);
    PUT_FREG(insn, 1, unop(ir_op, srcR));
    clear_FSR_cexc();

    set_fprs_dirty();
    return (True);
}

static Bool
insn_fzero_fone(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IRExpr *expr;

#   define ASSIGN(_expr) \
    expr = _expr;

    switch (mnemonic) {
    case SPARC64_OPC_FZEROs: ASSIGN(mkU32(0));                  break;
    case SPARC64_OPC_FZEROd: ASSIGN(mkU64(0));                  break;
    case SPARC64_OPC_FONEs:  ASSIGN(mkU32(0xFFFFFFFF));         break;
    case SPARC64_OPC_FONEd:  ASSIGN(mkU64(0xFFFFFFFFFFFFFFFF)); break;
    default:
        vassert(0);
    }
#   undef ASSIGN

    PUT_FREG(insn, 0, expr);
    set_fprs_dirty();
    return (True);
}

static Bool
insn_fsrc(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IRExpr *src = GET_FREG(insn, 0);

    switch (mnemonic) {
    case SPARC64_OPC_FSRC1d ... SPARC64_OPC_FSRC2s:
        break;
    case SPARC64_OPC_FNOT1d:
    case SPARC64_OPC_FNOT2d:
        src = unop(Iop_NotF64, src);
        break;
    case SPARC64_OPC_FNOT1s:
    case SPARC64_OPC_FNOT2s:
        src = unop(Iop_NotF32, src);
        break;
    default:
        vassert(0);
    }

    PUT_FREG(insn, 1, src);

    set_fprs_dirty();
    return (True);
}

static Bool
insn_fshift(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IROp ir_op;

#   define ASSIGN(_ir_op) \
    ir_op = Iop_##_ir_op;

    switch (mnemonic) {
    case SPARC64_OPC_FSLL16:  ASSIGN(ShlF16x4);  break;
    case SPARC64_OPC_FSRL16:  ASSIGN(ShrF16x4);  break;
    case SPARC64_OPC_FSLL32:  ASSIGN(ShlF32x2);  break;
    case SPARC64_OPC_FSRL32:  ASSIGN(ShrF32x2);  break;
    case SPARC64_OPC_FSLAS16: ASSIGN(QSalF16x4); break;
    case SPARC64_OPC_FSRA16:  ASSIGN(SarF16x4);  break;
    case SPARC64_OPC_FSLAS32: ASSIGN(QSalF32x2); break;
    case SPARC64_OPC_FSRA32:  ASSIGN(SarF32x2);  break;
    default:
        vassert(0);
    }
#   undef ASSIGN

    PUT_FREG(insn, 2, binop(ir_op, GET_FREG(insn, 0), GET_FREG(insn, 1)));

    set_fprs_dirty();
    return (True);
}

static Bool
insn_farithmetic(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IROp ir_op;
    SPARC64_FSR_CEXC_OP fsr_cexc_op;
    Bool rounds;

#   define ASSIGN(_ir_op, _fsr_cexc_op, _rounds)      \
    ir_op = Iop_##_ir_op;                             \
    fsr_cexc_op = SPARC64_FSR_CEXC_OP_##_fsr_cexc_op; \
    rounds = _rounds;

    switch (mnemonic) {
    case SPARC64_OPC_FADDs:  ASSIGN(AddF32,  FADD32,    True);  break;
    case SPARC64_OPC_FADDd:  ASSIGN(AddF64,  FADD64,    True);  break;
    case SPARC64_OPC_FADDq:  ASSIGN(AddF128, FADD128,   True);  break;
    case SPARC64_OPC_FDIVs:  ASSIGN(DivF32,  FDIV32,    True);  break;
    case SPARC64_OPC_FDIVd:  ASSIGN(DivF64,  FDIV64,    True);  break;
    case SPARC64_OPC_FDIVq:  ASSIGN(DivF128, FDIV128,   True);  break;
    case SPARC64_OPC_FMULs:  ASSIGN(MulF32,  FMUL32,    True);  break;
    case SPARC64_OPC_FMULd:  ASSIGN(MulF64,  FMUL64,    True);  break;
    case SPARC64_OPC_FMULq:  ASSIGN(MulF128, FMUL128,   True);  break;
    case SPARC64_OPC_FsMULd: ASSIGN(MullF32, F32MUL64,  False); break;
    case SPARC64_OPC_FdMULq: ASSIGN(MullF64, F64MUL128, False); break;
    case SPARC64_OPC_FSUBs:  ASSIGN(SubF32,  FSUB32,    True);  break;
    case SPARC64_OPC_FSUBd:  ASSIGN(SubF64,  FSUB64,    True);  break;
    case SPARC64_OPC_FSUBq:  ASSIGN(SubF128, FSUB128,   True);  break;
    default:
        vassert(0);
    }
#   undef ASSIGN

    IRTemp srcL = newTemp(mkFpType(insn->operands[0]->op_size));
    assign(srcL, GET_FREG(insn, 0));

    IRTemp srcR = newTemp(mkFpType(insn->operands[1]->op_size));
    assign(srcR, GET_FREG(insn, 1));

    if (rounds) {
        set_FSR_CEXC_DEP1_DEP2_NDEP(fsr_cexc_op, mkexpr(srcL), mkexpr(srcR),
                                    IRExpr_Get(OFFSET_sparc64_FSR_RD, Ity_I64));
        PUT_FREG(insn, 2, triop(ir_op, getIRRoundMode(), mkexpr(srcL),
                                mkexpr(srcR)));
    } else {
        set_FSR_CEXC_DEP1_DEP2(fsr_cexc_op, mkexpr(srcL), mkexpr(srcR));
        PUT_FREG(insn, 2, binop(ir_op, mkexpr(srcL), mkexpr(srcR)));
    }

    set_fprs_dirty();
    return (True);
}

static Bool
insn_flogic(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IROp ir_op;
    IROp neg_rs1, neg_rs2, neg_rd;

#   define ASSIGN(_ir_op, _neg_rs1, _neg_rs2, _neg_rd) \
    ir_op   = Iop_##_ir_op;                            \
    neg_rs1 = Iop_##_neg_rs1;                          \
    neg_rs2 = Iop_##_neg_rs2;                          \
    neg_rd  = Iop_##_neg_rd;

    switch (mnemonic) {
    case SPARC64_OPC_FORd:      ASSIGN(OrF64,  INVALID, INVALID, INVALID); break;
    case SPARC64_OPC_FORs:      ASSIGN(OrF32,  INVALID, INVALID, INVALID); break;
    case SPARC64_OPC_FNORd:     ASSIGN(OrF64,  INVALID, INVALID, NotF64);  break;
    case SPARC64_OPC_FNORs:     ASSIGN(OrF32,  INVALID, INVALID, NotF32);  break;
    case SPARC64_OPC_FANDd:     ASSIGN(AndF64, INVALID, INVALID, INVALID); break;
    case SPARC64_OPC_FANDs:     ASSIGN(AndF32, INVALID, INVALID, INVALID); break;
    case SPARC64_OPC_FNANDd:    ASSIGN(AndF64, INVALID, INVALID, NotF64);  break;
    case SPARC64_OPC_FNANDs:    ASSIGN(AndF32, INVALID, INVALID, NotF32);  break;
    case SPARC64_OPC_FXORd:     ASSIGN(XorF64, INVALID, INVALID, INVALID); break;
    case SPARC64_OPC_FXORs:     ASSIGN(XorF32, INVALID, INVALID, INVALID); break;
    case SPARC64_OPC_FXNORd:    ASSIGN(XorF64, INVALID, INVALID, NotF64);  break;
    case SPARC64_OPC_FXNORs:    ASSIGN(XorF32, INVALID, INVALID, NotF32);  break;
    case SPARC64_OPC_FORNOT1d:  ASSIGN(OrF64,  NotF64,  INVALID, INVALID); break;
    case SPARC64_OPC_FORNOT1s:  ASSIGN(OrF32,  NotF32,  INVALID, INVALID); break;
    case SPARC64_OPC_FORNOT2d:  ASSIGN(OrF64,  INVALID, NotF64,  INVALID); break;
    case SPARC64_OPC_FORNOT2s:  ASSIGN(OrF32,  INVALID, NotF32,  INVALID); break;
    case SPARC64_OPC_FANDNOT1d: ASSIGN(AndF64, NotF64,  INVALID, INVALID); break;
    case SPARC64_OPC_FANDNOT1s: ASSIGN(AndF32, NotF32,  INVALID, INVALID); break;
    case SPARC64_OPC_FANDNOT2d: ASSIGN(AndF64, INVALID, NotF64,  INVALID); break;
    case SPARC64_OPC_FANDNOT2s: ASSIGN(AndF32, INVALID, NotF32,  INVALID); break;
    default:
        vassert(0);
    }
#   undef ASSIGN

    IRExpr *srcL = GET_FREG(insn, 0);
    if (neg_rs1 != Iop_INVALID) {
        srcL = unop(neg_rs1, srcL);
    }

    IRExpr *srcR = GET_FREG(insn, 1);
    if (neg_rs2 != Iop_INVALID) {
        srcR = unop(neg_rs2, srcR);
    }

    IRExpr *res = binop(ir_op, srcL, srcR);
    if (neg_rd != Iop_INVALID) {
        res = unop(neg_rd, res);
    }
    PUT_FREG(insn, 2, res);

    set_fprs_dirty();
    return True;
}

static Bool
insn_faligndata(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IRExpr *align = unop(Iop_32Uto64,
                         IRExpr_Get(OFFSET_sparc64_GSR_align, Ity_I32));
    PUT_FREG(insn, 2, triop(Iop_AlignF64, align,
                            GET_FREG(insn, 0), GET_FREG(insn, 1)));

    set_fprs_dirty();
    return (True);
}

/* Converts IRCmpFResult to native sparc64 fcc encoding for FCMP. */
static IRExpr *
convert_fcmp_ir_to_fcc(IRTemp fcmp_ir_32)
{
    IRTemp fcmp_ir = newTemp(Ity_I64);
    assign(fcmp_ir, unop(Iop_32Uto64, mkexpr(fcmp_ir_32)));

    /*
       FP cmp result | IR   | ix | fcc
       ----------------------------------
       EQ            | 0x40 | 10 | 00
       LT            | 0x01 | 01 | 01
       GT            | 0x00 | 00 | 10
       UN            | 0x45 | 11 | 11      */

    /* First convert IRCmpFResult encoding to something more useful,
       where bits 6 and 0 are put side by side.
       This is depicted by 'ix' above. */
    IRTemp ix = newTemp(Ity_I64);
    assign(ix, binop(Iop_Or64,
                     binop(Iop_And64,
                           binop(Iop_Shr64, mkexpr(fcmp_ir), mkU8(5)),
                           mkU64(3)),
                     binop(Iop_And64, mkexpr(fcmp_ir), mkU64(1))));

    /* The following term converts ix to an almost correct fcc value
       (incredibly), except for UN where it produces 00 instead of the
       required 11. */
    IRTemp fcc = newTemp(Ity_I64);
    assign(fcc, binop(Iop_Shr64, mkU64(2), unop(Iop_64to8, mkexpr(ix))));

    /* This is the correction term which produces 1 only when ix is 11. */
    IRTemp carry = newTemp(Ity_I64);
    assign(carry, binop(Iop_Shr64,
                        binop(Iop_And64,
                              binop(Iop_Add64, mkexpr(ix), mkU64(1)),
                              mkU64(4)),
                        mkU8(2)));

    /* The correction term is applied twice to get the final correct value. */
    return binop(Iop_Or64,
                 binop(Iop_Or64,
                       binop(Iop_Shl64, mkexpr(carry), mkU8(1)),
                       mkexpr(carry)),
                 mkexpr(fcc));
}

static Bool
insn_fcmp(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IROp ir_op;
    SPARC64_FSR_CEXC_OP fsr_cexc_op;

#   define ASSIGN(_ir_op, _fsr_cexc_op)               \
    ir_op = Iop_##_ir_op;                             \
    fsr_cexc_op = SPARC64_FSR_CEXC_OP_##_fsr_cexc_op;

    switch (mnemonic) {
    case SPARC64_OPC_FCMPs:  ASSIGN(CmpF32,  FCMP32);   break;
    case SPARC64_OPC_FCMPd:  ASSIGN(CmpF64,  FCMP64);   break;
    case SPARC64_OPC_FCMPq:  ASSIGN(CmpF128, FCMP128);  break;
    case SPARC64_OPC_FCMPEs: ASSIGN(CmpF32,  FCMPE32);  break;
    case SPARC64_OPC_FCMPEd: ASSIGN(CmpF64,  FCMPE64);  break;
    case SPARC64_OPC_FCMPEq: ASSIGN(CmpF128, FCMPE128); break;
    default:
        vassert(0);
    }
#   undef ASSIGN

    IRExpr *srcL = GET_FREG(insn, 1);
    IRExpr *srcR = GET_FREG(insn, 2);

    IRTemp irRes = newTemp(Ity_I32);
    assign(irRes, binop(ir_op, srcL, srcR));

    UInt fccn = insn->operand_values[0].uintval;
    vassert(fccn < 4);
    UInt fcc_shifts[] = {SPARC64_FSR_SHIFT_FCC0, SPARC64_FSR_SHIFT_FCC1,
                         SPARC64_FSR_SHIFT_FCC2, SPARC64_FSR_SHIFT_FCC3};
    ULong fcc_masks[] = {SPARC64_FSR_MASK_FCC0, SPARC64_FSR_MASK_FCC1,
                         SPARC64_FSR_MASK_FCC2, SPARC64_FSR_MASK_FCC3};

    /* Convert the computed result to native sparc64 representation. */
    IRExpr *fcc = convert_fcmp_ir_to_fcc(irRes);

    /* And put it to the corresponding place together with other fcc fields. */
    IRTemp fcc_old = newTemp(Ity_I64);
    assign(fcc_old, binop(Iop_And64,
                          IRExpr_Get(OFFSET_sparc64_FSR_FCC, Ity_I64),
                          mkU64(~fcc_masks[fccn])));

    IRTemp fcc_new = newTemp(Ity_I64);
    assign(fcc_new, binop(Iop_Or64,
                          mkexpr(fcc_old),
                          binop(Iop_Shl64, fcc, mkU8(fcc_shifts[fccn]))));
    stmt(IRStmt_Put(OFFSET_sparc64_FSR_FCC, mkexpr(fcc_new)));

    set_FSR_CEXC_DEP1_DEP2(fsr_cexc_op, srcL, srcR);

    return (True);
}

static Bool
insn_fito(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IROp ir_op;
    SPARC64_FSR_CEXC_OP fsr_cexc_op;
    Bool needs_rd = (insn->opcode->flags & SPARC64_OPF_FSR_RD_IN) != 0;

#   define ASSIGN(_ir_op, _fsr_cexc_op)              \
    ir_op = Iop_##_ir_op;                            \
    fsr_cexc_op = SPARC64_FSR_CEXC_OP_##_fsr_cexc_op;

    switch (mnemonic) {
    case SPARC64_OPC_FiTOs: ASSIGN(I32StoF32,  I32TOF32);  break;
    case SPARC64_OPC_FiTOd: ASSIGN(I32StoF64,  I32TOF64);  break;
    case SPARC64_OPC_FiTOq: ASSIGN(I32StoF128, I32TOF128); break;
    default:
        vassert(0);
    }
#   undef ASSIGN

    IRTemp srcR = newTemp(mkFpType(insn->operands[0]->op_size));
    assign(srcR, GET_FREG(insn, 0));

    if (needs_rd) {
        set_FSR_CEXC_DEP1_NDEP(fsr_cexc_op, mkexpr(srcR),
                               IRExpr_Get(OFFSET_sparc64_FSR_RD, Ity_I64));
    } else {
        set_FSR_CEXC_DEP1(fsr_cexc_op, mkexpr(srcR));
    }

    IRExpr *op;
    if (needs_rd) {
        op = binop(ir_op, getIRRoundMode(), unop(Iop_ReinterpF32asI32,
                                                 mkexpr(srcR)));
    } else {
        op = unop(ir_op, unop(Iop_ReinterpF32asI32, mkexpr(srcR)));
    }
    PUT_FREG(insn, 1, op);

    set_fprs_dirty();
    return (True);
}

static Bool
insn_fmaf(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IROp ir_op;
    SPARC64_FSR_CEXC_OP fsr_cexc_op;

#   define ASSIGN(_ir_op, _fsr_cexc_op)               \
    ir_op = Iop_##_ir_op;                             \
    fsr_cexc_op = SPARC64_FSR_CEXC_OP_##_fsr_cexc_op;

    switch (mnemonic) {
    case SPARC64_OPC_FMADDs: ASSIGN(MAddF32, FMADD32); break;
    case SPARC64_OPC_FMADDd: ASSIGN(MAddF64, FMADD64); break;
    case SPARC64_OPC_FMSUBs: ASSIGN(MSubF32, FMSUB32); break;
    case SPARC64_OPC_FMSUBd: ASSIGN(MSubF64, FMSUB64); break;
    case SPARC64_OPC_FNMADDs:
    case SPARC64_OPC_FNMADDd:
    case SPARC64_OPC_FNMSUBs:
    case SPARC64_OPC_FNMSUBd:
        return False;
    default:
        vassert(0);
    }
#   undef ASSIGN

    IRTemp arg1 = newTemp(mkFpType(insn->operands[0]->op_size));
    assign(arg1, GET_FREG(insn, 0));

    IRTemp arg2 = newTemp(mkFpType(insn->operands[1]->op_size));
    assign(arg2, GET_FREG(insn, 1));

    IRTemp arg3 = newTemp(mkFpType(insn->operands[2]->op_size));
    assign(arg3, GET_FREG(insn, 2));

    set_FSR_CEXC_DEP_NDEP_for_FMAf(fsr_cexc_op, mkexpr(arg1), mkexpr(arg2),
                      mkexpr(arg3), IRExpr_Get(OFFSET_sparc64_FSR_RD, Ity_I64));
    PUT_FREG(insn, 3, qop(ir_op, getIRRoundMode(), mkexpr(arg1), mkexpr(arg2),
                          mkexpr(arg3)));

    set_fprs_dirty();
    return (True);
}


static Bool
insn_fmov(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    PUT_FREG(insn, 1, GET_FREG(insn, 0));
    clear_FSR_cexc();

    set_fprs_dirty();
    return (True);
}

static Bool
insn_FMOVicc(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IRExpr *srcR = GET_FREG(insn, 1);

    /* Determine %icc or %xcc. */
    SPARC64ICondcode cond_code = sparc64_icond_for_mnemonic(mnemonic);
    vassert(insn->operands[0]->type == SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc);
    if (insn->operand_values[0].uintval == 1) {
        cond_code++;
    }

    PUT_FREG(insn, 2, IRExpr_ITE(calculate_ICond_from_CCR(cond_code, False),
                                 srcR, GET_FREG(insn, 2)));
    clear_FSR_cexc();

    set_fprs_dirty();
    return (True);
}

static Bool
insn_FMOVfcc(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IRExpr *srcR = GET_FREG(insn, 1);

    SPARC64FCondcode cond_code = sparc64_fcond_for_mnemonic(mnemonic);
    UInt fccn = insn->operand_values[0].uintval;

    PUT_FREG(insn, 2, 
             IRExpr_ITE(calculate_FCond_from_FSR(cond_code, fccn, False),
                        srcR, GET_FREG(insn, 2)));
    clear_FSR_cexc();

    set_fprs_dirty();
    return (True);
}

static Bool
insn_fpconvert(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IROp ir_op;
    SPARC64_FSR_CEXC_OP fsr_cexc_op;
    Bool needs_rd = (insn->opcode->flags & SPARC64_OPF_FSR_RD_IN) != 0;

#   define ASSIGN(_ir_op, _fsr_cexc_op)               \
    ir_op = Iop_##_ir_op;                             \
    fsr_cexc_op = SPARC64_FSR_CEXC_OP_##_fsr_cexc_op;

    switch (mnemonic) {
    case SPARC64_OPC_FsTOd: ASSIGN(F32toF64,  F32TOF64);  break;
    case SPARC64_OPC_FsTOq: ASSIGN(F32toF128, F32TOF128); break;
    case SPARC64_OPC_FdTOs: ASSIGN(F64toF32,  F64TOF32);  break;
    case SPARC64_OPC_FdTOq: ASSIGN(F64toF128, F64TOF128); break;
    case SPARC64_OPC_FqTOs: ASSIGN(F128toF32, F128TOF32); break;
    case SPARC64_OPC_FqTOd: ASSIGN(F128toF64, F128TOF64); break;
    default:
        vassert(0);
    }
#   undef ASSIGN

    IRTemp srcR = newTemp(mkFpType(insn->operands[0]->op_size));
    assign(srcR, GET_FREG(insn, 0));

    if (needs_rd) {
        set_FSR_CEXC_DEP1_NDEP(fsr_cexc_op, mkexpr(srcR),
                               IRExpr_Get(OFFSET_sparc64_FSR_RD, Ity_I64));
    } else {
        set_FSR_CEXC_DEP1(fsr_cexc_op, mkexpr(srcR));
    }

    IRExpr *op;
    if (needs_rd) {
        op = binop(ir_op, getIRRoundMode(), mkexpr(srcR));
    } else {
        op = unop(ir_op, mkexpr(srcR));
    }
    PUT_FREG(insn, 1, op);

    set_fprs_dirty();
    return (True);
}

static Bool
insn_fsqrt(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IROp ir_op;
    SPARC64_FSR_CEXC_OP fsr_cexc_op;

#   define ASSIGN(_ir_op, _fsr_cexc_op)               \
    ir_op = Iop_##_ir_op;                             \
    fsr_cexc_op = SPARC64_FSR_CEXC_OP_##_fsr_cexc_op;

    switch (mnemonic) {
    case SPARC64_OPC_FSQRTs: ASSIGN(SqrtF32,  FSQRT32);  break;
    case SPARC64_OPC_FSQRTd: ASSIGN(SqrtF64,  FSQRT64);  break;
    case SPARC64_OPC_FSQRTq: ASSIGN(SqrtF128, FSQRT128); break;
    default:
        vassert(0);
    }
#   undef ASSIGN

    IRTemp srcR = newTemp(mkFpType(insn->operands[0]->op_size));
    assign(srcR, GET_FREG(insn, 0));

    set_FSR_CEXC_DEP1_NDEP(fsr_cexc_op, mkexpr(srcR),
                           IRExpr_Get(OFFSET_sparc64_FSR_RD, Ity_I64));
    IRExpr *op = binop(ir_op, getIRRoundMode(), mkexpr(srcR));
    PUT_FREG(insn, 1, op);

    set_fprs_dirty();
    return (True);
}

static Bool
insn_ftox(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IROp ir_op;
    SPARC64_FSR_CEXC_OP fsr_cexc_op;

#   define ASSIGN(_ir_op, _fsr_cexc_op)               \
    ir_op = Iop_##_ir_op;                             \
    fsr_cexc_op = SPARC64_FSR_CEXC_OP_##_fsr_cexc_op;

    switch (mnemonic) {
    case SPARC64_OPC_FsTOx: ASSIGN(F32toI64U,  F32TOI64);  break;
    case SPARC64_OPC_FdTOx: ASSIGN(F64toI64U,  F64TOI64);  break;
    case SPARC64_OPC_FqTOx: ASSIGN(F128toI64U, F128TOI64); break;
    case SPARC64_OPC_FsTOi: ASSIGN(F32toI32U,  F32TOI32);  break;
    case SPARC64_OPC_FdTOi: ASSIGN(F64toI32U,  F64TOI32);  break;
    case SPARC64_OPC_FqTOi: ASSIGN(F128toI32U, F128TOI32); break;
    default:
        vassert(0);
    }
#   undef ASSIGN

    IRTemp srcR = newTemp(mkFpType(insn->operands[0]->op_size));
    assign(srcR, GET_FREG(insn, 0));

    set_FSR_CEXC_DEP1(fsr_cexc_op, mkexpr(srcR));
    /* These instructions always round toward zero. */
    PUT_FREG(insn, 1, binop(ir_op, mkU32(Irrm_ZERO), mkexpr(srcR)));

    set_fprs_dirty();
    return (True);
}


static Bool
insn_fxto(sparc64_mnemonic mnemonic, const sparc64_insn *insn)
{
    IROp ir_op;
    SPARC64_FSR_CEXC_OP fsr_cexc_op;
    Bool needs_rd = (insn->opcode->flags & SPARC64_OPF_FSR_RD_IN) != 0;

#   define ASSIGN(_ir_op, _fsr_cexc_op)               \
    ir_op = Iop_##_ir_op;                             \
    fsr_cexc_op = SPARC64_FSR_CEXC_OP_##_fsr_cexc_op;

    switch (mnemonic) {
    case SPARC64_OPC_FxTOs: ASSIGN(I64StoF32,  I64TOF32);  break;
    case SPARC64_OPC_FxTOd: ASSIGN(I64StoF64,  I64TOF64);  break;
    case SPARC64_OPC_FxTOq: ASSIGN(I64StoF128, I64TOF128); break;
    default:
        vassert(0);
    }
#   undef ASSIGN

    IRTemp srcR = newTemp(mkFpType(insn->operands[0]->op_size));
    assign(srcR, GET_FREG(insn, 0));

    if (needs_rd) {
        set_FSR_CEXC_DEP1_NDEP(fsr_cexc_op, mkexpr(srcR),
                               IRExpr_Get(OFFSET_sparc64_FSR_RD, Ity_I64));
    } else {
        set_FSR_CEXC_DEP1(fsr_cexc_op, mkexpr(srcR));
    }

    IRExpr *op;
    if (needs_rd) {
        op = binop(ir_op, getIRRoundMode(), unop(Iop_ReinterpF64asI64,
                                                 mkexpr(srcR)));
    } else {
        op = unop(ir_op, unop(Iop_ReinterpF64asI64, mkexpr(srcR)));
    }
    PUT_FREG(insn, 1, op);

    set_fprs_dirty();
    return (True);
}

static Bool
insn_return(sparc64_mnemonic mnemonic, const sparc64_insn *insn,
            DisResult *dres, IRExpr **pc_tgt)
{
    /* Handle the right argument. */
    IRExpr *argR;
    if (insn->operands[1]->type == SPARC64_OP_TYPE_IREG_RS2) {
        argR = getIRegOrZR(insn->operand_values[1].uintval);
    } else {
        vassert(insn->operands[1]->type == SPARC64_OP_TYPE_SIMM13);
        argR = mkU64(insn->operand_values[1].longval);
    }

    /* Calculate effective address. */
    IRTemp tgt = newTemp(Ity_I64);
    assign(tgt, binop(Iop_Add64, getIRegOrZR(insn->operand_values[0].uintval),
                      argR));

    /* Exit logic is the same as for branch delay slot. */
    *pc_tgt = mkexpr(tgt);

    /* Restore window - keep in sync with insn_save_restore(). */
    /* %i -> %o */
    stmt(IRStmt_Put(OFFSET_sparc64_R8,  IRExpr_Get(OFFSET_sparc64_R24, Ity_I64)));
    stmt(IRStmt_Put(OFFSET_sparc64_R9,  IRExpr_Get(OFFSET_sparc64_R25, Ity_I64)));
    stmt(IRStmt_Put(OFFSET_sparc64_R10, IRExpr_Get(OFFSET_sparc64_R26, Ity_I64)));
    stmt(IRStmt_Put(OFFSET_sparc64_R11, IRExpr_Get(OFFSET_sparc64_R27, Ity_I64)));
    stmt(IRStmt_Put(OFFSET_sparc64_R12, IRExpr_Get(OFFSET_sparc64_R28, Ity_I64)));
    stmt(IRStmt_Put(OFFSET_sparc64_R13, IRExpr_Get(OFFSET_sparc64_R29, Ity_I64)));
    stmt(IRStmt_Put(OFFSET_sparc64_R14, IRExpr_Get(OFFSET_sparc64_R30, Ity_I64)));
    stmt(IRStmt_Put(OFFSET_sparc64_R15, IRExpr_Get(OFFSET_sparc64_R31, Ity_I64)));

    /* Emulate immediate restore. */
    IRTemp sa_base = newTemp(Ity_I64);
    assign(sa_base, IRExpr_Get(OFFSET_sparc64_I6, Ity_I64));
    savearea_restore(OFFSET_sparc64_R16, sa_base,   0); /* %l0 */
    savearea_restore(OFFSET_sparc64_R17, sa_base,   8);
    savearea_restore(OFFSET_sparc64_R18, sa_base,  16);
    savearea_restore(OFFSET_sparc64_R19, sa_base,  24);
    savearea_restore(OFFSET_sparc64_R20, sa_base,  32);
    savearea_restore(OFFSET_sparc64_R21, sa_base,  40);
    savearea_restore(OFFSET_sparc64_R22, sa_base,  48);
    savearea_restore(OFFSET_sparc64_R23, sa_base,  56);
    savearea_restore(OFFSET_sparc64_R24, sa_base,  64); /* %i0 */
    savearea_restore(OFFSET_sparc64_R25, sa_base,  72);
    savearea_restore(OFFSET_sparc64_R26, sa_base,  80);
    savearea_restore(OFFSET_sparc64_R27, sa_base,  88);
    savearea_restore(OFFSET_sparc64_R28, sa_base,  96);
    savearea_restore(OFFSET_sparc64_R29, sa_base, 104);
    savearea_restore(OFFSET_sparc64_R31, sa_base, 120);
    /* %fp is used to locate save area on the stack and reload
       other registers thus it must be restored as the last register. */
    savearea_restore(OFFSET_sparc64_I6, sa_base, 112);

    return (True);
}

static Bool
insn_jmpl(sparc64_mnemonic mnemonic, const sparc64_insn *insn,
          DisResult *dres, IRExpr **pc_tgt)
{
    /* Handle the right argument. */
    IRExpr *argR;
    if (insn->operands[1]->type == SPARC64_OP_TYPE_IREG_RS2) {
        argR = getIRegOrZR(insn->operand_values[1].uintval);
    } else {
        vassert(insn->operands[1]->type == SPARC64_OP_TYPE_SIMM13);
        argR = mkU64(insn->operand_values[1].longval);
    }

    /* Calculate effective address. */
    IRTemp tgt = newTemp(Ity_I64);
    assign(tgt, binop(Iop_Add64, getIRegOrZR(insn->operand_values[0].uintval),
                      argR));

    /* %pc -> $rd */
    putIRegOrZR(insn->operand_values[2].uintval, mkU64(guest_PC_curr_instr));

    /* Exit logic is the same as for branch delay slot. */
    *pc_tgt = mkexpr(tgt);

    return (True);
}

static Bool
insn_flush(sparc64_mnemonic mnemonic, const sparc64_insn *insn,
           DisResult *dres)
{
    /* Calculate effective address. */
    IRExpr *tgt;
    if (insn->operands[1]->type == SPARC64_OP_TYPE_IREG_RS2) {
        tgt = binop(Iop_Add64, getIRegOrZR(insn->operand_values[0].uintval),
                               getIRegOrZR(insn->operand_values[1].uintval));
    } else {
        vassert(insn->operands[1]->type == SPARC64_OP_TYPE_SIMM13);
        tgt = binop(Iop_Add64, getIRegOrZR(insn->operand_values[0].uintval),
                               mkU64(insn->operand_values[1].longval));
    }

    /* Ask for cache invalidation. */
    stmt(IRStmt_Put(OFFSET_sparc64_CMSTART, tgt));
    stmt(IRStmt_Put(OFFSET_sparc64_CMLEN, mkU64(8)));
    putNPC(mkU64(guest_PC_curr_instr + 2 * INSN_LENGTH));
    putPC(mkU64(guest_PC_curr_instr + INSN_LENGTH));

    /* Exit to scheduler. */
    dres->whatNext = Dis_StopHere;
    dres->jk_StopHere = Ijk_InvalICache;

    return (True);
}

static Bool
insn_unrecognized(UInt insn)
{
   /* the unrecognized instruction */
   stmt(IRStmt_Unrecognized(insn));

   return True;
}


static DisResult
disInstr_SPARC64_WRK(Bool              (*resteerOkFn)(void *, Addr),
                     Bool              resteerCisOk,
                     void              *callback_opaque,
                     const UInt        *guest_instr,
                     UInt              delta_IN,
                     const VexArchInfo *archinfo,
                     const VexAbiInfo  *abiinfo,
                     Bool              sigill_diag_IN)
{
    /* Hints for delay slot processing. We must remember a jump statement
       attached to the delay instruction and target PC for disassembly. */
    static IRStmt *jmp_stmt = NULL;
    static IRExpr *pc_tgt = NULL;
    static IRJumpKind jk = Ijk_INVALID;
    Bool delay_slot = False;
    Bool annul_or_call = False;

    /* This early test ensures that we must be in delay-slot when
       we hit these conditions. */
    if (jmp_stmt != NULL)
        delay_slot = True;
    if (pc_tgt != NULL)
        annul_or_call = True;

    vassert((jmp_stmt && pc_tgt) == False);

    /* Set default result. */
    DisResult dres;
    vex_bzero(&dres, sizeof(DisResult));
    dres.whatNext    = Dis_Continue;
    dres.len         = INSN_LENGTH;
    dres.continueAt  = 0;
    dres.jk_StopHere = Ijk_INVALID;
    dres.hint        = Dis_HintNone;

    /* Read instruction and make sure it is 32bit only. */
    DIP("[0x%lx] %x\n", (Addr) guest_instr, *guest_instr);
    UInt insn = getUIntBE(guest_instr);

    Bool ok = False;
    Bool handle_unrecognized = False;

    /* Spot "special" instructions (see comment at top of file). */
    UInt special = 0x81399007; /* srax %g6, %g7, %g0 */
    if (insn == special) {
        /* Got a "special" instruction preamble. Which one is it? */
        insn = getUIntBE(guest_instr + 1);
        if (insn == 0x80120009) { /* or %o0, %o1, %g0 */
            /* %o0 = client_request ( %o1 ) */
            DIP("%%o0 = client_request ( %%o1 )\n");
            putNPC(mkU64(guest_PC_curr_instr + 3 * INSN_LENGTH));
            putPC(mkU64(guest_PC_curr_instr + 2 * INSN_LENGTH));
            dres.jk_StopHere = Ijk_ClientReq;
            dres.whatNext    = Dis_StopHere;
            ok = True;
        } else if (insn == 0x8012400a /* or %o1, %o2, %g0 */ ) {
            /* %o0 = guest_NRADDR */
            DIP("%%o0 = guest_NRADDR\n");
            dres.len = 2 * INSN_LENGTH;
            putIRegOrZR(REG_O0, IRExpr_Get(OFFSET_sparc64_NRADDR, Ity_I64));
            ok = True;
        } else if (insn == 0x8012800b /* or %o2, %o3, %g0 */ ) {
            /* jump-and-link-to-noredir %g1 */
            DIP("jump-and-link-to-noredir %%g1\n");
            /* Subtle detail about the return adress:
               We'd be tempted to use (guest_PC_curr_instr + 2 * INSN_LENGTH)
               and assign it to %o7. But when the wrapped function returns, it
               uses something like 'return %i7 + 8'. So don't stray away! */
            putIRegOrZR(REG_O7, mkU64(guest_PC_curr_instr));
            IRTemp target = newTemp(Ity_I64);
            assign(target, getIRegOrZR(REG_G1));
            putNPC(binop(Iop_Add64, mkexpr(target), mkU64(4)));
            putPC(mkexpr(target));
            dres.jk_StopHere = Ijk_NoRedir;
            dres.whatNext    = Dis_StopHere;
            ok = True;
        } else if (insn == 0x8012c00c /* or %o3, %o4, %g0 */ ) {
            /* IR injection */
            DIP("IR injection\n");
            vex_inject_ir(irsb, Iend_BE);
            stmt(IRStmt_Put(OFFSET_sparc64_CMSTART, mkU64(guest_PC_curr_instr)));
            stmt(IRStmt_Put(OFFSET_sparc64_CMLEN, mkU64(2 * INSN_LENGTH)));
            putNPC(mkU64(guest_PC_curr_instr + 3 * INSN_LENGTH));
            putPC(mkU64(guest_PC_curr_instr + 2 * INSN_LENGTH));
            dres.whatNext    = Dis_StopHere;
            dres.jk_StopHere = Ijk_InvalICache;
            dres.len = 2 * INSN_LENGTH;
            ok = True;
        } else {
            /* We don't know what it is. Decode failure should print the insn
               following the special instruction preamble. */
            dres.len = INSN_LENGTH;
        }
    } else {
        sparc64_insn decoded;
        Bool found_unrecognized = False;
        ok = sparc64_decode_insn(insn, &decoded, &found_unrecognized);

        if (!ok && found_unrecognized &&
            !abiinfo->guest_sparc64_dont_handle_unrecognized_insn) {
            if (!delay_slot) {
                /* Unrecognized instruction, but can handle it */
                handle_unrecognized = True;
            }
            if (vex_traceflags & VEX_TRACE_FE) {
                vex_printf("<unrecognized> 0x%x\n",insn);
            }
        }

        if (ok) {
            sparc64_mnemonic mnemonic = decoded.opcode->mnemonic;
            switch (mnemonic) {
            case SPARC64_OPC_ADD ... SPARC64_OPC_ADDCcc:
            case SPARC64_OPC_ADDXC ... SPARC64_OPC_ADDXCcc:
            case SPARC64_OPC_BMASK:
            case SPARC64_OPC_MULX ... SPARC64_OPC_UDIVX:
            case SPARC64_OPC_SDIV ... SPARC64_OPC_SDIVcc:
            case SPARC64_OPC_SMUL ... SPARC64_OPC_SMULcc:
            case SPARC64_OPC_SUB ... SPARC64_OPC_SUBCcc:
            case SPARC64_OPC_UDIV ... SPARC64_OPC_UDIVcc:
            case SPARC64_OPC_UMUL ... SPARC64_OPC_UMULcc:
            case SPARC64_OPC_UMULXHI:
                ok = insn_arithmetic(mnemonic, (sparc64_insn_al *) &decoded);
                break;
            case SPARC64_OPC_AES_EROUND01 ... SPARC64_OPC_AES_DROUND23_LAST:
                ok = insn_aes_round(archinfo->hwcaps, mnemonic, &decoded);
                break;
            case SPARC64_OPC_AES_KEXPAND1:
                ok = insn_aes_kexpand_rcon(archinfo->hwcaps, mnemonic,
                                           &decoded);
                break;
            case SPARC64_OPC_AES_KEXPAND0:
            case SPARC64_OPC_AES_KEXPAND2:
                ok = insn_aes_kexpand(archinfo->hwcaps, mnemonic, &decoded);
                break;
            case SPARC64_OPC_ALIGNADDRESS:
                ok = insn_alignaddress(mnemonic, &decoded);
                break;
            case SPARC64_OPC_AND ... SPARC64_OPC_ANDNcc:
                ok = insn_logic(mnemonic, (sparc64_insn_al *) &decoded);
                break;
            case SPARC64_OPC_BA ... SPARC64_OPC_BVS:
            case SPARC64_OPC_BPA ... SPARC64_OPC_BPVS:
                ok = insn_Bicc_BPcc(mnemonic, &decoded, &dres, &jmp_stmt,
                                    &pc_tgt);
                jk = Ijk_Boring;
                break;
            case SPARC64_OPC_BSHUFFLE:
                ok = insn_bshuffle(mnemonic, &decoded);
                break;
            case SPARC64_OPC_BRZ ... SPARC64_OPC_BRGEZ:
                ok = insn_BPr(mnemonic, &decoded, &dres, &jmp_stmt, &pc_tgt);
                jk = Ijk_Boring;
                break;
            case SPARC64_OPC_CALL:
                ok = insn_call(mnemonic, &decoded, &pc_tgt);
                jk = Ijk_Call;
                break;
            case SPARC64_OPC_CASA ... SPARC64_OPC_CASXA:
                ok = insn_casa_casxa(mnemonic, &decoded);
                break;
            case SPARC64_OPC_CWBNE ... SPARC64_OPC_CXBVS:
                ok = insn_CBcond(mnemonic, &decoded, &dres);
                jk = Ijk_Boring;
                break;
            case SPARC64_OPC_FABSs ... SPARC64_OPC_FABSq:
            case SPARC64_OPC_FNEGs ... SPARC64_OPC_FNEGq:
                ok = insn_fabs_fneg(mnemonic, &decoded);
                break;
            case SPARC64_OPC_FADDs ... SPARC64_OPC_FADDq:
            case SPARC64_OPC_FDIVs ... SPARC64_OPC_FDIVq:
            case SPARC64_OPC_FMULs ... SPARC64_OPC_FdMULq:
            case SPARC64_OPC_FSUBs ... SPARC64_OPC_FSUBq:
                ok = insn_farithmetic(mnemonic, &decoded);
                break;
            case SPARC64_OPC_FALIGNDATAg:
                ok = insn_faligndata(mnemonic, &decoded);
                break;
            case SPARC64_OPC_FORd ... SPARC64_OPC_FNORs:
            case SPARC64_OPC_FANDd ... SPARC64_OPC_FNANDs:
            case SPARC64_OPC_FXORd ... SPARC64_OPC_FXNORs:
            case SPARC64_OPC_FORNOT1d ... SPARC64_OPC_FORNOT2s:
            case SPARC64_OPC_FANDNOT1d ... SPARC64_OPC_FANDNOT2s:
                ok = insn_flogic(mnemonic, &decoded);
                break;
            case SPARC64_OPC_FBPA ... SPARC64_OPC_FBPO:
                ok = insn_FBPfcc(mnemonic, &decoded, &dres, &jmp_stmt, &pc_tgt);
                jk = Ijk_Boring;
                break;
            case SPARC64_OPC_FCMPs ... SPARC64_OPC_FCMPEq:
                ok = insn_fcmp(mnemonic, &decoded);
                break;
            case SPARC64_OPC_FiTOs ... SPARC64_OPC_FiTOq:
                ok = insn_fito(mnemonic, &decoded);
                break;
            case SPARC64_OPC_FLUSH:
                ok = insn_flush(mnemonic, &decoded, &dres);
                break;
            case SPARC64_OPC_FLUSHW:
                /* This is safe to ignore as our windows are always flushed. */
                ok = True;
                break;
            case SPARC64_OPC_FMADDs ... SPARC64_OPC_FMSUBd:
                ok = insn_fmaf(mnemonic, &decoded);
                break;
            case SPARC64_OPC_FMOVs ... SPARC64_OPC_FMOVq:
                ok = insn_fmov(mnemonic, &decoded);
                break;
            case SPARC64_OPC_FMOVSiccA ... SPARC64_OPC_FMOVQiccVS:
                ok = insn_FMOVicc(mnemonic, &decoded);
                break;
            case SPARC64_OPC_FMOVSfccA ... SPARC64_OPC_FMOVQfccO:
                ok = insn_FMOVfcc(mnemonic, &decoded);
                break;
            case SPARC64_OPC_FZEROs ... SPARC64_OPC_FZEROd:
            case SPARC64_OPC_FONEs ... SPARC64_OPC_FONEd:
                ok = insn_fzero_fone(mnemonic, &decoded);
                break;
            case SPARC64_OPC_FSRC1d ... SPARC64_OPC_FNOT2s:
                ok = insn_fsrc(mnemonic, &decoded);
                break;
            case SPARC64_OPC_FSLL16 ... SPARC64_OPC_FSRA32:
                ok = insn_fshift(mnemonic, &decoded);
                break;
            case SPARC64_OPC_FSQRTs ... SPARC64_OPC_FSQRTq:
                ok = insn_fsqrt(mnemonic, &decoded);
                break;
            case SPARC64_OPC_FsTOx ... SPARC64_OPC_FqTOx:
            case SPARC64_OPC_FsTOi ... SPARC64_OPC_FqTOi:
                ok = insn_ftox(mnemonic, &decoded);
                break;
            case SPARC64_OPC_FsTOd ... SPARC64_OPC_FqTOd:
                ok = insn_fpconvert(mnemonic, &decoded);
                break;
            case SPARC64_OPC_FxTOs ... SPARC64_OPC_FxTOq:
                ok = insn_fxto(mnemonic, &decoded);
                break;
            case SPARC64_OPC_JMPL:
                ok = insn_jmpl(mnemonic, &decoded, &dres, &pc_tgt);
                jk = Ijk_Ret;
                break;
            case SPARC64_OPC_LDSB ... SPARC64_OPC_LDX:
                ok = insn_load(mnemonic, &decoded, False, False);
                break;
            case SPARC64_OPC_LDSBA ... SPARC64_OPC_LDXA:
                ok = insn_load(mnemonic, &decoded, True, False);
                break;
            case SPARC64_OPC_LDBLOCKF:
                ok = insn_load_block(mnemonic, &decoded);
                break;
            case SPARC64_OPC_LDF ... SPARC64_OPC_LDQF:
                ok = insn_load(mnemonic, &decoded, False, True);
                break;
            case SPARC64_OPC_LDFSR:
            case SPARC64_OPC_LDXFSR:
                ok = insn_ldfsr(mnemonic, &decoded);
                break;
            case SPARC64_OPC_LDSHORTF:
                ok = insn_load_short_float(mnemonic, &decoded);
                break;
            case SPARC64_OPC_LDSTUB:
                ok = insn_ldstub(mnemonic, &decoded);
                break;
            case SPARC64_OPC_LZCNT:
                ok = insn_lzcnt(mnemonic, &decoded);
                break;
            case SPARC64_OPC_MD5:
                ok = insn_hash(archinfo->hwcaps, sparc64_md5, "sparc64_md5",
                               OFFSET_sparc64_F0, 4, OFFSET_sparc64_F8, 16);
                break;
            case SPARC64_OPC_MEMBAR:
                ok = insn_membar(mnemonic, &decoded);
                break;
            case SPARC64_OPC_MOVA ... SPARC64_OPC_MOVVS:
                ok = insn_MOVicc(mnemonic, &decoded);
                break;
            case SPARC64_OPC_MOVFA ... SPARC64_OPC_MOVFO:
                ok = insn_MOVfcc(mnemonic, &decoded);
                break;
            case SPARC64_OPC_MOVRZ ... SPARC64_OPC_MOVRGEZ:
                ok = insn_MOVr(mnemonic, &decoded);
                break;
            case SPARC64_OPC_MOVsTOsw ... SPARC64_OPC_MOVdTOx:
                ok = insn_MOVfTOi(mnemonic, &decoded);
                break;
            case SPARC64_OPC_MOVwTOs ... SPARC64_OPC_MOVxTOd:
                ok = insn_MOViTOf(mnemonic, &decoded);
                break;
            case SPARC64_OPC_NOP:
                break;
            case SPARC64_OPC_OR ... SPARC64_OPC_ORNcc:
                ok = insn_logic(mnemonic, (sparc64_insn_al *) &decoded);
                break;
            case SPARC64_OPC_PREFETCH ... SPARC64_OPC_PREFETCHA:
                /* ignored */
                break;
            case SPARC64_OPC_RDY ... SPARC64_OPC_RDCFR:
                ok = insn_RDasr(archinfo->hwcaps, mnemonic, &decoded);
                break;
            case SPARC64_OPC_RESTORE:
            case SPARC64_OPC_SAVE:
                ok = insn_save_restore(mnemonic, (sparc64_insn_al *) &decoded);
                break;
            case SPARC64_OPC_RETURN:
                ok = insn_return(mnemonic, &decoded, &dres, &pc_tgt);
                jk = Ijk_Ret;
                break;
            case SPARC64_OPC_SETHI:
                ok = insn_sethi(mnemonic, &decoded);
                break;
            case SPARC64_OPC_SHA1:
                ok = insn_hash(archinfo->hwcaps, sparc64_sha1, "sparc64_sha1",
                               OFFSET_sparc64_F0, 5, OFFSET_sparc64_F8, 16);
                break;
            case SPARC64_OPC_SHA256:
                ok = insn_hash(archinfo->hwcaps, sparc64_sha256,
                               "sparc64_sha256", OFFSET_sparc64_F0, 8,
                               OFFSET_sparc64_F8, 16);
                break;
            case SPARC64_OPC_SHA512:
                ok = insn_hash(archinfo->hwcaps, sparc64_sha512,
                               "sparc64_sha512", OFFSET_sparc64_F0, 16,
                               OFFSET_sparc64_F16, 32);
                break;
            case SPARC64_OPC_SLL ... SPARC64_OPC_SRAX:
                ok = insn_shift(mnemonic, (sparc64_insn_al *) &decoded);
                break;
            case SPARC64_OPC_STB ... SPARC64_OPC_STX:
                ok = insn_store(mnemonic, &decoded, False, False);
                break;
            case SPARC64_OPC_STBA ... SPARC64_OPC_STXA:
                ok = insn_store(mnemonic, &decoded, True, False);
                break;
            case SPARC64_OPC_STF ... SPARC64_OPC_STQF:
                ok = insn_store(mnemonic, &decoded, False, True);
                break;
            case SPARC64_OPC_STFSR ... SPARC64_OPC_STXFSR:
                ok = insn_stfsr(mnemonic, &decoded);
                break;
            case SPARC64_OPC_SWAP:
                ok = insn_swap(mnemonic, &decoded);
                break;
            case SPARC64_OPC_TA ... SPARC64_OPC_TVS:
                ok = insn_trap(mnemonic, &decoded, &dres);
                break;
            case SPARC64_OPC_WRY ... SPARC64_OPC_WRMWAIT:
                ok = insn_WRasr(mnemonic, &decoded);
                break;
            case SPARC64_OPC_XMULX ... SPARC64_OPC_XMULXHI:
                ok = insn_xmulx(archinfo->hwcaps, mnemonic,
                                (sparc64_insn_al *) &decoded);
                break;
            case SPARC64_OPC_XOR ... SPARC64_OPC_XNORcc:
                ok = insn_logic(mnemonic, (sparc64_insn_al *) &decoded);
                break;
            default:
                ok = False;
                break;
            }

            if (vex_traceflags & VEX_TRACE_FE) {
                print_insn(&decoded);
            }
        }
    }

    /* (Non annulled) delay slot handling:
         1) Disassembly of jump prepares exit statement.
         2) Delay slot instruction is translated to IR.
         3) Statement prepared in jmp_stmt is appended at the end of IR stream.
     */
    if (delay_slot) {
        dres.jk_StopHere = Ijk_Boring;
        dres.whatNext = Dis_StopHere;
        stmt(jmp_stmt);
        putNPC(mkU64(guest_PC_curr_instr + 2 * INSN_LENGTH));
        putPC(mkU64(guest_PC_curr_instr + INSN_LENGTH));

        delay_slot = False;
        jmp_stmt = NULL;
    }

    /* (Annuled) delay slot handling:
         1) Exit statement has been already inserted to IR stream.
         2) Next PC has been provided by the disassembler. */
    if (annul_or_call) {
        dres.jk_StopHere = jk;
        dres.whatNext = Dis_StopHere;
        putNPC(binop(Iop_Add64, pc_tgt, mkU64(4)));
        putPC(pc_tgt);

        annul_or_call = False;
        jk = Ijk_INVALID;
        pc_tgt = NULL;
    }

    /* Post-handling depending on disassembly result. */
    if (ok) {
        vassert((dres.len == INSN_LENGTH) || (dres.len == 2 * INSN_LENGTH));

        switch (dres.whatNext) {
        case Dis_Continue:
            if (pc_tgt != NULL) {
                putNPC(pc_tgt);
            } else {
                putNPC(mkU64(guest_PC_curr_instr + 2 * INSN_LENGTH));
            }
            putPC(mkU64(guest_PC_curr_instr + INSN_LENGTH));
            break;
        case Dis_ResteerU:
        case Dis_ResteerC:
            /* TODO-SPARC: Implement this. */
            vpanic("SPARC64: Dis_ResteerU/C not implemented yet.");
            break;
        case Dis_StopHere:
            break;
        default:
            vassert(0);
        }
    }

    if (ok) {
        /* We need to check if the last instruction in a basic block will have
           a branch delay slot. If yes then we stop now because bb_to_IR()
           will split branch insn and delayed insn into two basic blocks.
           That would break our stuff horribly. */
        if (((vex_control.guest_max_insns - 1) ==
             (delta_IN + INSN_LENGTH) / INSN_LENGTH)
            && (dres.whatNext != Dis_StopHere)) {

            const sparc64_opcode *opcode =
                sparc64_find_opcode(*(guest_instr + 1));
            if ((opcode->flags & SPARC64_OPF_dCTI) != 0) {
                dres.whatNext = Dis_StopHere;
                dres.jk_StopHere = Ijk_Boring;
                putNPC(mkU64(guest_PC_curr_instr + 2 * INSN_LENGTH));
                putPC(mkU64(guest_PC_curr_instr + INSN_LENGTH));
            }
        }
    } else {
        /* Valgrind can handle unrecognized non control flow instructions
           as long as they are not in a delay slot. */
        if (handle_unrecognized) {
            dres.len         = INSN_LENGTH;
            dres.continueAt  = 0;
            dres.hint        = Dis_HintNone;

            /* The unrecognized instruction needs to be in its own IRSB.
               To do this, if the bad instruction is not the first one,
               stop the current block at the previous insn. Then the next
               time this function is called, the unrecognized insn will
               be encountered again and it will be the first in the IRSB. */
            if (delta_IN == 0) {
                /* Report emulation warning. */
                stmt(IRStmt_Put(OFFSET_sparc64_EMNOTE,
                             mkU32(EmWarn_SPARC64_handling_unrecognized_insn)));
                dres.whatNext    = Dis_StopHere;
                dres.jk_StopHere = Ijk_EmWarn;

                (void) insn_unrecognized(insn);
                irsb->has_unrecognized = True;
                vex_printf("Unrecognized SPARC instruction 0x%08x.\n", insn);
                vex_printf("More information can be obtained by running with "
                           "--show-emwarns=yes command line option.\n");
                putNPC(mkU64(guest_PC_curr_instr + 2 * INSN_LENGTH));
                putPC(mkU64(guest_PC_curr_instr + INSN_LENGTH));
            } else {
                dres.whatNext    = Dis_BackUp;
                dres.jk_StopHere = Ijk_Boring;
            }
            return dres;
        }

        if (sigill_diag_IN) {
           vex_printf("disInstr(sparc64): unhandled instruction 0x%08x.\n",
                      insn);
           vex_printf("More information can be obtained by running with "
                      "--trace-flags=10000000 --trace-notbelow=0 flags.\n");
        }

        /* Tell the dispatcher that this instruction cannot be decoded, and so
           has not been executed, and (is currently) the next to be executed. */
        putNPC(mkU64(guest_PC_curr_instr + INSN_LENGTH));
        putPC(mkU64(guest_PC_curr_instr));
        dres.len         = 0;
        dres.whatNext    = Dis_StopHere;
        dres.jk_StopHere = Ijk_NoDecode;
        dres.continueAt  = 0;
        dres.hint        = Dis_HintNone;
    }

    return (dres);
}

/*----------------------------------------------------------------------------*/
/*--- Top-level fn                                                         ---*/
/*----------------------------------------------------------------------------*/

DisResult
disInstr_SPARC64(IRSB              *irsb_IN,
                 Bool              (*resteerOkFn)(void *, Addr),
                 Bool              resteerCisOk,
                 void              *callback_opaque,
                 const UChar       *guest_code_IN,
                 Long              delta_IN,
                 Addr              guest_IP,
                 VexArch           guest_arch,
                 const VexArchInfo *archinfo,
                 const VexAbiInfo  *abiinfo,
                 VexEndness        host_endness_IN,
                 Bool              sigill_diag_IN)
{
    /* Check that instruction buffer is sufficiently aligned; placate gcc. */
    if ((Addr) guest_code_IN % INSN_LENGTH != 0) {
        vpanic("disInstr_SPARC64: guest instruction buffer is misaligned!");
    }
    const UInt *guest_code_aligned = __builtin_assume_aligned(guest_code_IN,
                                                              INSN_LENGTH);

    vassert(delta_IN % INSN_LENGTH == 0);
    vassert(guest_IP % INSN_LENGTH == 0);

    /* Setup globals. */
    vassert(guest_arch == VexArchSPARC64);
    irsb = irsb_IN;
    host_endness = host_endness_IN;
    guest_PC_curr_instr = guest_IP;

    /* Decode the instruction. */
    return disInstr_SPARC64_WRK(resteerOkFn, resteerCisOk, callback_opaque,
                                &guest_code_aligned[delta_IN / INSN_LENGTH],
                                delta_IN, archinfo, abiinfo, sigill_diag_IN);
}

/*----------------------------------------------------------------------------*/
/*--- end                                             guest_sparc64_toIR.c ---*/
/*----------------------------------------------------------------------------*/
