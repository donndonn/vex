//*--- begin                                            host_sparc64_isel.c ---*/
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

#include "libvex_basictypes.h"
#include "libvex_ir.h"
#include "libvex.h"
#include "libvex_guest_sparc64.h"
#include "libvex_guest_offsets.h"

#include "main_util.h"
#include "main_globals.h"
#include "host_generic_regs.h"
#include "host_sparc64_defs.h"
#include "sparc64_disasm.h"


#define DIP(format, args...)           \
    if (vex_traceflags & VEX_TRACE_FE) \
        vex_printf(format, ## args);

/*----------------------------------------------------------------------------*/
/*--- ISelEnv                                                              ---*/
/*----------------------------------------------------------------------------*/

/* This carries around:

   - A mapping from IRTemp to IRType, giving the type of any IRTemp we
     might encounter.  This is computed before insn selection starts,
     and does not change.

   - A mapping from IRTemp to HReg.  This tells the insn selector
     which virtual register is associated with each IRTemp
     temporary.  This is computed before insn selection starts, and
     does not change.  We expect this mapping to map precisely the
     same set of IRTemps as the type mapping does.

         - vregmap   holds the primary register for the IRTemp.
         - vregmapHI holds the secondary register for the IRTemp,
              if any is needed. That's only for Ity_I128 temps.
     The reason we support Ity_I128 at all is because memcheck instrumentation
     layer tracks Ity_F128 (those %q.. registers) as shadow Ity_I128.
     There is just a minimal support for Get/Put/RdTmp/WrTmp/DirtyCall.

   - The host subarchitecture we are selecting insns for.
     This is set at the start and does not change.

   - The code array, that is, the insns selected so far.

   - A counter, for generating new virtual registers.

   - A Bool for indicating whether we may generate chain-me
     instructions for control flow transfers, or whether we must use
     XAssisted.

   - The maximum guest address of any guest insn in this block.
     Actually, the address of the highest-addressed byte from any insn
     in this block.  Is set at the start and does not change.  This is
     used for detecting jumps which are definitely forward-edges from
     this block, and therefore can be made (chained) to the fast entry
     point of the destination, thereby avoiding the destination's
     event check.

   Note, this is all host-independent.  (JRS 20050201: well, kinda
   ... not completely.  Compare with ISelEnv for X86.)
*/

typedef struct {
    /* Constant -- are set at the start and do not change. */
    IRTypeEnv     *type_env;

    HReg          *vregmap;
    HReg          *vregmapHI;
    Int           n_vregmap;

    UInt          hwcaps;

    Bool          chainingAllowed;
    Addr64        max_ga;

    /* These are modified as we go along. */
    HInstrArray   *code;
    Int           vreg_ctr;

    const IRExpr *previous_rd;
} ISelEnv;

static HReg
lookupIRTemp(ISelEnv *env, IRTemp tmp)
{
    vassert(tmp >= 0);
    vassert(tmp < env->n_vregmap);
    return (env->vregmap[tmp]);
}

/* Return the two virtual registers to which the IRTemp is mapped. */
static void
lookupIRTemp128(ISelEnv *env, IRTemp tmp, HReg *hi, HReg *lo)
{
    vassert(tmp >= 0);
    vassert(tmp < env->n_vregmap);

    *lo = env->vregmap[tmp];
    *hi = env->vregmapHI[tmp];
}

#define ADD_INSTR(instr_name, args...)                  \
    do {                                                \
        addInstr(env, SPARC64Instr_##instr_name(args)); \
    } while (0)

static void
addInstr(ISelEnv *env, SPARC64Instr *instr)
{
    addHInstr(env->code, instr);
    if (vex_traceflags & VEX_TRACE_VCODE) {
        ppSPARC64Instr(instr);
        vex_printf("\n");
    }
}

static HReg
newVRegI(ISelEnv *env)
{
    return (mkHReg(True, HRcInt64, 0, env->vreg_ctr++));
}

static HReg
newVRegF(ISelEnv *env, UChar sz)
{
    switch (sz) {
    case 4:
        return mkHReg(True, HRcFlt32, 0, env->vreg_ctr++);
    case 8:
        return mkHReg(True, HRcFlt64, 0, env->vreg_ctr++);
    case 16:
        return mkHReg(True, HRcFlt128, 0, env->vreg_ctr++);
    default:
        vpanic("sparc64 newVRegF: Unsupported reg size");
    }
}

static HReg
newVRegF_from_IRType(ISelEnv *env, IRType ty)
{
    switch (ty) {
    case Ity_F32:
        return mkHReg(True, HRcFlt32, 0, env->vreg_ctr++);
    case Ity_F64:
        return mkHReg(True, HRcFlt64, 0, env->vreg_ctr++);
    case Ity_F128:
        return mkHReg(True, HRcFlt128, 0, env->vreg_ctr++);
    default:
        vpanic("sparc64 newVRegF: Unsupported IR type");
    }
}

static HReg iselExpr_R(ISelEnv *env, const IRExpr *e);
static void iselExpr_128_R(ISelEnv *env, const IRExpr *e,
                           HReg *r_dst_hi, HReg *r_dst_lo);
static SPARC64AMode *iselExpr_AMode(ISelEnv *env, const IRExpr *e);
static SPARC64RI *iselImm_RI(ISelEnv *env, ULong u, UInt maxbits, Bool sext);
static SPARC64RI *iselExpr_RI(ISelEnv *env, const IRExpr *e, UInt maxbits,
                              Bool sext);

/*---------------------------------------------------------*/
/*--- ISEL: FP rounding mode helpers                    ---*/
/*---------------------------------------------------------*/

/* Set the FP rounding mode: 'rd' is an I32-typed expression
   denoting a value in the range 0..3, indicating rounding mode
   encoded as per type IRRoundingMode -- the first four values only
   (Irrm_NEAREST, Irrm_NegINF, Irrm_PosINF, Irrm_ZERO).  Set the sparc64
   FSR.rd to have the same rounding.

   For speed & simplicity, we're setting the *entire* FSR here.

   Setting the rounding mode is expensive.  So this function tries to
   avoid repeatedly setting the rounding mode to the same thing by
   first comparing 'rd' to the 'rd' tree supplied in the previous
   call to this function, if any.  (The previous value is stored in
   env->previous_rm.)  If 'rd' is a single IR temporary 't' and
   env->previous_rm is also just 't', then the setting is skipped.

   This is safe because of the SSA property of IR: an IR temporary can
   only be defined once and so will have the same value regardless of
   where it appears in the block.  Cool stuff, SSA.

   A safety condition: all attempts to set the RM must be aware of
   this mechanism - by being routed through the functions here.

   Of course this only helps if blocks where the RM is set more than
   once and it is set to the same value each time, *and* that value is
   held in the same IR temporary each time.  In order to assure the
   latter as much as possible, the IR optimiser takes care to do CSE
   on any block with any sign of floating point activity.
 */
/* TODO-SPARC: Use GSR.im = 1 and GSR.irnd in conjuction with 'siam' instruction
   to have much better performance when setting FP rounding mode. */
static void set_FSR_rounding_mode(ISelEnv *env, const IRExpr *rd)
{
    vassert(typeOfIRExpr(env->type_env, rd) == Ity_I32);

    /* Do we need to do anything? */
    if ((env->previous_rd != NULL) && (env->previous_rd->tag == Iex_RdTmp) &&
        (rd->tag == Iex_RdTmp) &&
        (env->previous_rd->Iex.RdTmp.tmp == rd->Iex.RdTmp.tmp)) {
        /* Nothing to be done. */
        vassert(typeOfIRExpr(env->type_env, env->previous_rd) == Ity_I32);
        return;
    }

    /* No luck - we better set it, and remember what we set it to. */
    env->previous_rd = rd;

    /* Only supporting the rounding-mode bits - the rest of FSR is set
       to zero - so we can set the whole register at once (faster).
       But first convert 'rd' from IR encoding to sparc64 encoding.

       rounding mode | IR | sparc64
       ----------------------------
       to nearest    | 00 | 00
       to -infinity  | 01 | 11
       to +infinity  | 10 | 10
       to zero       | 11 | 01

       So the formula is (~(r_irrd << 62)) >> 62      [kudos to superopt] */

    HReg r_irrd = iselExpr_R(env, rd);
    HReg r_dst = newVRegI(env);
    ADD_INSTR(Shft, Sshft_SLLX, r_dst, r_irrd, SPARC64RI_Imm(62));
    ADD_INSTR(Alu, Salu_SUB, r_dst, hregSPARC64_G0(), SPARC64RI_Reg(r_dst));
    ADD_INSTR(Shft, Sshft_SRLX, r_dst, r_dst, SPARC64RI_Imm(62 - 30));

    SPARC64AMode *am =
        SPARC64AMode_IR(OFFSET_sparc64_scratchpad, SPARC64_GuestStatePointer());
    ADD_INSTR(Store, 8, am, r_dst);
    ADD_INSTR(LoadFSR, 8, am);
}

/*----------------------------------------------------------------------------*/
/*--- ISEL: Misc helpers                                                   ---*/
/*----------------------------------------------------------------------------*/

/* IMPORTANT NOTE: Do not trash the condition codes (CCR) set by this function.
   For example, evaluate arguments before invoking iselCondCode(). */
static SPARC64CondCode
iselCondCode(ISelEnv *env, const IRExpr *e)
{
    vassert(e != NULL);
    vassert(typeOfIRExpr(env->type_env, e) == Ity_I1);

    /* A past statement stored the result of a compare operation in a temporary.
       So test the last bit now and set CCR accordingly. */
    if (e->tag == Iex_RdTmp) {
        HReg r_var = lookupIRTemp(env, e->Iex.RdTmp.tmp);
        ADD_INSTR(Alu, Salu_ANDcc, hregSPARC64_G0(), r_var, SPARC64RI_Imm(1));
        return (Scc_NE);
    }

    /* constant */
    if (e->tag == Iex_Const) {
        IRConst *con = e->Iex.Const.con;
        vassert(con->tag == Ico_U1);
        vassert(con->Ico.U1 == True || con->Ico.U1 == False);
        /* We do not emit any instruction here, because Scc_A/Scc_N is handled
           directly at emitor code level and does not involve any CCR checking.
         */
        return (con->Ico.U1 ? Scc_A : Scc_N);
    }

    /* not */
    if ((e->tag == Iex_Unop) && (e->Iex.Unop.op == Iop_Not1)) {
        return (1 ^ iselCondCode(env, e->Iex.Unop.arg));
    }

    /* 1-bit value - this is result of a helper call. */
    if ((e->tag == Iex_Unop) && (e->Iex.Unop.op == Iop_64to1)) {
        HReg r_arg = iselExpr_R(env, e->Iex.Unop.arg);
        ADD_INSTR(Alu, Salu_ANDcc, hregSPARC64_G0(), r_arg, SPARC64RI_Imm(1));
        return (Scc_NE);
    }

    if (e->tag == Iex_Unop) {
        IRExpr *src = e->Iex.Unop.arg;
        HReg r_arg = iselExpr_R(env, src);

        switch (e->Iex.Unop.op) {
        case Iop_CmpNEZ32:
            vassert(typeOfIRExpr(env->type_env, src) == Ity_I32);

            SPARC64RI *ri_mask = iselImm_RI(env, 0xFFFFFFFF,
                                            SPARC64_SIMM13_MAXBITS, True);
            ADD_INSTR(Alu, Salu_ANDcc, hregSPARC64_G0(), r_arg, ri_mask);
            return (Scc_NE);
        case Iop_CmpNEZ64:
            vassert(typeOfIRExpr(env->type_env, src) == Ity_I64);

            ADD_INSTR(Alu, Salu_SUBcc, hregSPARC64_G0(), r_arg,
                           SPARC64RI_Reg(hregSPARC64_G0()));
            return (Scc_NE);
        default:
            break;
        }

    } else if (e->tag == Iex_Binop) {
        IRExpr *srcL = e->Iex.Binop.arg1;
        IRExpr *srcR = e->Iex.Binop.arg2;
        IROp op = e->Iex.Binop.op;

        switch (op) {
        /* Cmp*8* (x,y) */
        case Iop_CasCmpEQ8:
        case Iop_CmpNE8: {
            vassert(typeOfIRExpr(env->type_env, srcL) == Ity_I8);
            vassert(typeOfIRExpr(env->type_env, srcR) == Ity_I8);

            HReg r_argL = iselExpr_R(env, srcL);
            HReg r_argR = iselExpr_R(env, srcR);
            HReg r_maskedL = newVRegI(env);
            HReg r_maskedR = newVRegI(env);

            ADD_INSTR(Alu, Salu_AND, r_maskedL, r_argL, SPARC64RI_Imm(0xFF));
            ADD_INSTR(Alu, Salu_AND, r_maskedR, r_argR, SPARC64RI_Imm(0xFF));
            ADD_INSTR(Alu, Salu_SUBcc, hregSPARC64_G0(), r_maskedL,
                           SPARC64RI_Reg(r_maskedR));

            switch (op) {
            case Iop_CasCmpEQ8:
                return (Scc_E);
            case Iop_CmpNE8:
                return (Scc_NE);
            default:
                vassert(0);
            }
        }

        /* Cmp*32* (x,y) */
        case Iop_CasCmpEQ32:
        case Iop_CmpNE32: {
            vassert(typeOfIRExpr(env->type_env, srcL) == Ity_I32);
            vassert(typeOfIRExpr(env->type_env, srcR) == Ity_I32);

            HReg r_argL = iselExpr_R(env, srcL);
            HReg r_argR = iselExpr_R(env, srcR);
            HReg r_maskedL = newVRegI(env);
            HReg r_maskedR = newVRegI(env);

            ADD_INSTR(Shft, Sshft_SRL, r_maskedL, r_argL, SPARC64RI_Imm(0));
            ADD_INSTR(Shft, Sshft_SRL, r_maskedR, r_argR, SPARC64RI_Imm(0));
            ADD_INSTR(Alu, Salu_SUBcc, hregSPARC64_G0(), r_maskedL,
                           SPARC64RI_Reg(r_maskedR));

            switch (op) {
            case Iop_CasCmpEQ32:
                return (Scc_E);
            case Iop_CmpNE32:
                return (Scc_NE);
            default:
                vassert(0);
            }
        }

        /* Cmp*64* (x,y) */
        case Iop_CasCmpEQ64:
        case Iop_CmpEQ64:
        case Iop_CmpNE64:
        case Iop_CmpLT64S:
        case Iop_CmpLT64U:
        case Iop_CmpLE64S:
        case Iop_CmpLE64U: {
            vassert(typeOfIRExpr(env->type_env, srcL) == Ity_I64);
            vassert(typeOfIRExpr(env->type_env, srcR) == Ity_I64);

            HReg r_argL = iselExpr_R(env, srcL);
            SPARC64RI *ri_argR = iselExpr_RI(env, srcR, SPARC64_SIMM13_MAXBITS,
                                             True);
            ADD_INSTR(Alu, Salu_SUBcc, hregSPARC64_G0(), r_argL, ri_argR);
            switch (op) {
            case Iop_CasCmpEQ64:
            case Iop_CmpEQ64:
                return (Scc_E);
            case Iop_CmpNE64:
                return (Scc_NE);
            case Iop_CmpLT64S:
                return (Scc_L);
            case Iop_CmpLT64U:
                return (Scc_CS);
            case Iop_CmpLE64S:
                return (Scc_LE);
            case Iop_CmpLE64U:
                return (Scc_LEU);
            default:
                vassert(0);
            }
        }

        default:
            break;
        }
    }

    ppIRExpr(e);
    vpanic("iselCondCode(sparc64): Not implemented yet.");
}

static SPARC64Instr *
iselExpr_Get_insn(const IRExpr *e, IRType ty, HReg r_dst)
{
    SPARC64AMode *am = SPARC64AMode_IR(e->Iex.Get.offset,
                                       SPARC64_GuestStatePointer());
    return SPARC64Instr_Load(toUChar(sizeofIRType(ty)), r_dst, am);
}

static SPARC64Instr *
iselExpr_Const_insn(const IRExpr *e, HReg r_dst)
{
    IRConst *con = e->Iex.Const.con;
    Long l;

    switch (con->tag) {
    case Ico_U64:
        l = (Long) con->Ico.U64;
        break;
    case Ico_U32:
        l = (Long) (Int) con->Ico.U32;
        break;
    case Ico_U16:
        l = (Long) (Int) (Short) con->Ico.U16;
        break;
    case Ico_U8:
        l = (Long) (Int) (Char) con->Ico.U8;
        break;
    default:
        vpanic("sparc64: unsupported literal");
    }

    return SPARC64Instr_LI(r_dst, (ULong) l);
}

/* Produces one or more instructions which compute 'e' into 'r_dst'.
   Any of these instructions must not use any fixed registers.
   If more than one instruction is produced, these should ideally operate
   just on the destination register.
   If not possible, return just 0 instructions. */
static void
iselExpr_helper_arg(ISelEnv *env, const IRExpr *e, HReg r_dst,
                    HInstrArray *insns)
{

#define APPEND_INSN(insns, instr_name, args...)              \
    do {                                                     \
        addHInstr((insns), SPARC64Instr_##instr_name(args)); \
    } while (0)

    if (UNLIKELY(e->tag == Iex_GSPTR)) {
        APPEND_INSN(insns, Alu, Salu_OR, r_dst, hregSPARC64_G0(),
                                SPARC64RI_Reg(SPARC64_GuestStatePointer()));
        return;
    }

    vassert(typeOfIRExpr(env->type_env, e) == Ity_I64);

    switch (e->tag) {
    case Iex_RdTmp:
        APPEND_INSN(insns, Alu, Salu_OR, r_dst, hregSPARC64_G0(),
                            SPARC64RI_Reg(lookupIRTemp(env, e->Iex.RdTmp.tmp)));
        return;
    case Iex_Get:
        addHInstr(insns, iselExpr_Get_insn(e, Ity_I64, r_dst));
        return;
    case Iex_Const:
        addHInstr(insns, iselExpr_Const_insn(e, r_dst));
        return;
    case Iex_Unop: {
        const IRExpr *arg = e->Iex.Unop.arg;

        switch (e->Iex.Unop.op) {
        case Iop_32Uto64: {
            if ((arg->tag == Iex_Unop) && (arg->Iex.Unop.op == Iop_64to32)) {
                /* 32Uto64(64to32(arg)) -> 32Uto64(arg) */
                arg = arg->Iex.Unop.arg;
            }

            HReg r_srcL;
            if (arg->tag == Iex_RdTmp) {
                r_srcL = lookupIRTemp(env, arg->Iex.RdTmp.tmp);
            } else if ((arg->tag == Iex_Get) && (arg->Iex.Get.ty == Ity_I64)) {
                iselExpr_helper_arg(env, arg, r_dst, insns);
                r_srcL = r_dst;
            } else {
                break;
            }

            APPEND_INSN(insns, Shft, Sshft_SRL, r_dst, r_srcL,
                                     SPARC64RI_Imm(0));
            return;
        }
        case Iop_8Uto64: {
            if ((arg->tag == Iex_Unop) && (arg->Iex.Unop.op == Iop_64to8)) {
                /* 8Uto64(64to8(arg)) -> 8Uto64(arg) */
                arg = arg->Iex.Unop.arg;
            }

            HReg r_srcL;
            if (arg->tag == Iex_RdTmp) {
                r_srcL = lookupIRTemp(env, arg->Iex.RdTmp.tmp);
            } else if ((arg->tag == Iex_Get) && (arg->Iex.Get.ty == Ity_I64)) {
                iselExpr_helper_arg(env, arg, r_dst, insns);
                r_srcL = r_dst;
            } else {
                break;
            }

            APPEND_INSN(insns, Alu, Salu_AND, r_dst, r_srcL,
                                    SPARC64RI_Imm(0xFF));
            return;
        }
        case Iop_ReinterpF64asI64:
            if (arg->tag == Iex_RdTmp) {
                /* ReinterpF64asI64(t1) */
                APPEND_INSN(insns, MovFpToIReg, r_dst,
                                   lookupIRTemp(env, arg->Iex.RdTmp.tmp));
                return;
            }
            break;
        default:
            break;
        }
        break;
    }
    case Iex_Binop: {
        const IRExpr *arg1 = e->Iex.Binop.arg1;
        const IRExpr *arg2 = e->Iex.Binop.arg2;

        switch (e->Iex.Binop.op) {
        case Iop_Add64:
            if ((arg1->tag == Iex_Get) && (arg2->tag == Iex_Const)
                && (arg2->Iex.Const.con->tag == Ico_U64)) {
                IRConst *con = arg2->Iex.Const.con;

                if (FITS_INTO_MAXBITS_SIGNED(con->Ico.U64,
                                             SPARC64_SIMM13_MAXBITS)) {
                    /* Add64(GET, I64 < 0xFFF) */
                    addHInstr(insns, iselExpr_Get_insn(arg1, Ity_I64, r_dst));
                    APPEND_INSN(insns, Alu, Salu_ADD, r_dst, r_dst,
                                            SPARC64RI_Imm(con->Ico.U64));
                    return;
                }
            }
            if ((arg1->tag == Iex_RdTmp) && (arg2->tag == Iex_Const)
                && (arg2->Iex.Const.con->tag == Ico_U64)) {
                IRConst *con = arg2->Iex.Const.con;

                if (FITS_INTO_MAXBITS_SIGNED(con->Ico.U64,
                                             SPARC64_SIMM13_MAXBITS)) {
                    /* Add64(t1, I64 < 0xFFF) */
                    APPEND_INSN(insns, Alu, Salu_ADD, r_dst,
                                         lookupIRTemp(env, arg1->Iex.RdTmp.tmp),
                                         SPARC64RI_Imm(con->Ico.U64));
                    return;
                }
            }
            break;
        case Iop_And64:
            if ((arg1->tag == Iex_RdTmp) && (arg2->tag == Iex_RdTmp)) {
                /* And64(t1, t2) */
                HReg r_srcL = lookupIRTemp(env, arg1->Iex.RdTmp.tmp);
                HReg r_srcR = lookupIRTemp(env, arg2->Iex.RdTmp.tmp);
                APPEND_INSN(insns, Alu, Salu_AND, r_dst, r_srcL,
                                        SPARC64RI_Reg(r_srcR));
                return;
            }
            if ((arg1->tag == Iex_Get) && (arg2->tag == Iex_Const)
                && (arg2->Iex.Const.con->tag == Ico_U64)) {
                IRConst *con = arg2->Iex.Const.con;

                if (FITS_INTO_MAXBITS_SIGNED(con->Ico.U64,
                                             SPARC64_SIMM13_MAXBITS)) {
                    /* And64(GET, I64 < 0xFFF) */
                    addHInstr(insns, iselExpr_Get_insn(arg1, Ity_I64, r_dst));
                    APPEND_INSN(insns, Alu, Salu_AND, r_dst, r_dst,
                                            SPARC64RI_Imm(con->Ico.U64));
                    return;
                }
            }
            if ((arg1->tag == Iex_RdTmp) && (arg2->tag == Iex_Const)
                && (arg2->Iex.Const.con->tag == Ico_U64)) {
                IRConst *con = arg2->Iex.Const.con;

                if (FITS_INTO_MAXBITS_SIGNED(con->Ico.U64,
                                             SPARC64_SIMM13_MAXBITS)) {
                    /* And64(t1, I64 < 0xFFF) */
                    APPEND_INSN(insns, Alu, Salu_AND, r_dst,
                                         lookupIRTemp(env, arg1->Iex.RdTmp.tmp),
                                         SPARC64RI_Imm(con->Ico.U64));
                    return;
                }
            }
            break;
        default:
            break;
        }
        break;
    }
    default:
        break;
    }

    /* TODO-SPARC: Place for optimization is here. We might return several
       instructions and we might use temporary %g1 and %g4. */
    if (0) {
        vex_printf("Cannot compute directly into a real register: ");
        ppIRExpr(e);
        vex_printf("\n");
    }
    return;

#undef APPEND_INSN
}

static void
doHelperCall(UInt *stackAdjustAfterCall, RetLoc *retloc, ISelEnv *env,
             const IRExpr *guard, IRCallee *cee, IRType retTy, IRExpr **args)
{
    /* Set defaults. */
    *stackAdjustAfterCall = 0;
    *retloc = mk_RetLoc_INVALID();

    /* Marshal args for a call and do the call.

       This function only deals with a tiny set of possibilities, which cover
       all helpers in practice. The restrictions are that only arguments in
       registers are supported, hence only SPARC64_N_REGPARMS x 64 integer bits
       in total can be passed. In fact the only supported arg type is I64.

       The return type can be I1, I8, I16, I32, I64 or I128. In the I128 case,
       two output registers (%o0 and %o1) are used to convey the return value.

       |args| may also contain IRExpr_GSPTR(), in which case the value in %g5
       is passed as the corresponding argument.

       Generating code which is both efficient and correct when parameters are
       to be passed in registers is difficult, for the reasons elaborated in
       detail in comments attached to doHelperCall() in priv/host-x86/isel.c.
       Here, we use a variant of the method described in those comments.

       The problem is split into two cases: the fast scheme and the slow scheme.
       In the fast scheme, arguments are computed directly into the target
       (real) registers. This is only safe when we can be sure that computation
       of each argument will not trash any real registers set by computation of
       any other argument.

       In the slow scheme, all args are first computed into vregs, and once they
       are all done, they are moved to the relevant real regs. This always gives
       correct code, but it also gives a bunch of vreg-to-rreg moves which are
       usually redundant but are hard for the register allocator to get rid of.

       To decide which scheme to use, all argument expressions are first
       examined. If they are all so simple that it is clear they will be
       evaluated without use of any fixed registers, use the fast scheme, else
       use the slow scheme. Note also that only unconditional calls may use the
       fast scheme, since having to compute a condition expression could itself
       trash real registers.

       Note this requires being able to examine an expression and determine
       whether or not evaluation of it might use a fixed register. That requires
       knowledge of how the rest of this insn selector works. Currently just
       a handful are regarded as safe -- hopefully they cover the majority of
       arguments in practice: Iex_RdTmp, Iex_Const, Iex_Get and some simple
       cases of Iex_Unop and Iex_Binop. */

    UInt nargs = 0;
    UInt nVECRETs = 0;
    UInt nGSPTRs = 0;
    for (UInt i = 0; args[i] != NULL; i++) {
        if (UNLIKELY(args[i]->tag == Iex_VECRET))
            nVECRETs++;
        if (UNLIKELY(args[i]->tag == Iex_GSPTR))
            nGSPTRs++;
        nargs++;
    }

    if (nargs > SPARC64_N_REGPARMS)
        vpanic("doHelperCall(sparc64): Helpers with args > 6 are not "
               "supported.");

    vassert(nGSPTRs <= 1);
    vassert(nVECRETs == 0);

    /* TODO-SPARC: Better way to init static reg mappings */
    HReg argregs[SPARC64_N_REGPARMS];
    argregs[0] = hregSPARC64_O0();
    argregs[1] = hregSPARC64_O1();
    argregs[2] = hregSPARC64_O2();
    argregs[3] = hregSPARC64_O3();
    argregs[4] = hregSPARC64_O4();
    argregs[5] = hregSPARC64_O5();

    HInstrArray *fast_insns[SPARC64_N_REGPARMS];
    for (UInt i = 0; i < nargs; i++) {
        fast_insns[i] = newHInstrArray();
    }

    /* First decide which scheme (slow or fast) is to be used. First assume the
       fast scheme, and select slow if any contraindications (wow) appear. */
    Bool go_fast = True;

    if (guard != NULL) {
        if ((guard->tag == Iex_Const) && (guard->Iex.Const.con->tag == Ico_U1)
            && (guard->Iex.Const.con->Ico.U1 == True)) {
            /* unconditional */
        } else {
            /* Not manifestly unconditional - be conservative. */
            go_fast = False;
        }
    }

    if (go_fast) {
        for (UInt i = 0; i < nargs; i++) {
            iselExpr_helper_arg(env, args[i], argregs[i], fast_insns[i]);
            if (fast_insns[i]->arr_used == 0) {
                go_fast = False;
                break;
            }
        }
    }

    /* At this point the scheme to use has been established. Generate code to
       get the arg values into the argument argregs. If we run out of registers,
       give up. */
    SPARC64CondCode cond = Scc_A;
    if (go_fast) {
        for (UInt i = 0; i < nargs; i++) {
            vassert(fast_insns[i]->arr_used > 0);

            for (UInt j = 0; j < fast_insns[i]->arr_used; j++) {
                addInstr(env, fast_insns[i]->arr[j]);
            }
        }

        /* Fast scheme only applies to unconditional calls (Scc_A).
           No need to emit any code for cond. */
    } else {
        HReg tmpregs[SPARC64_N_REGPARMS];
        tmpregs[0] = tmpregs[1] = tmpregs[2] = INVALID_HREG;
        tmpregs[3] = tmpregs[4] = tmpregs[5] = INVALID_HREG;

        /* Process arguments into temporary regs. */
        for (UInt i = 0; i < nargs; i++) {
            IRType ty = Ity_INVALID;
            if (LIKELY(!is_IRExpr_VECRET_or_GSPTR(args[i])))
                ty = typeOfIRExpr(env->type_env, args[i]);

            if (ty == Ity_I64) {
                tmpregs[i] = iselExpr_R(env, args[i]);
            } else if (args[i]->tag == Iex_GSPTR) {
                tmpregs[i] = SPARC64_GuestStatePointer();
            } else {
                vassert(args[i]->tag != Iex_VECRET);
                vpanic("doHelperCall(sparc64): Unsupported argument type");
            }
        }

        /* Calculate guard if provided. Do not do that earlier as the calculated
           condition codes may get trashed. */
        if (guard != NULL) {
            if ((guard->tag == Iex_Const)
                && (guard->Iex.Const.con->tag == Ico_U1)
                && (guard->Iex.Const.con->Ico.U1 == True)) {
                /* No need to emit any code. */
            } else {
                cond = iselCondCode(env, guard);
            }
        }

        /* Move temporaries to real registers. */
        for (UInt i = 0; i < nargs; i++) {
            ADD_INSTR(Alu, Salu_OR, argregs[i], hregSPARC64_G0(),
                           SPARC64RI_Reg(tmpregs[i]));
        }
    }

    /* Should be assured by checks above */
    vassert(nargs <= SPARC64_N_REGPARMS);

    /* Setup return value. */
    switch (retTy) {
    case Ity_INVALID:
        *retloc = mk_RetLoc_simple(RLPri_None);
        break;
    case Ity_I8:
    case Ity_I16:
    case Ity_I32:
    case Ity_I64:
        *retloc = mk_RetLoc_simple(RLPri_Int);
        break;
    case Ity_I128:
        *retloc = mk_RetLoc_simple(RLPri_2Int);
        break;
    default:
        ppIRType(retTy);
        vpanic("doHelperCall(sparc64): Unsupported return value.");
    }

    /* Generete call instruction. */
    HReg r_tgt = hregSPARC64_G4();
    ADD_INSTR(LI, r_tgt, (ULong) cee->addr);
    ADD_INSTR(Call, cond, r_tgt, nargs, *retloc);
}

/* Register r_reg is used:
   - for loads as a destination register
   - for stores as a register containing data. */
static void
doStoreLoad(ISelEnv *env, const IRExpr *addr, const IRExpr *asi, IRType ty,
            Bool isStore, HReg r_reg)
{
    SPARC64AMode *am_addr = iselExpr_AMode(env, addr);
    UChar tySize = toUChar(sizeofIRType(ty));

    if (asi != NULL) {
        SPARC64RI *ri_asi = iselExpr_RI(env, asi, SPARC64_SIMM13_MAXBITS,
                                        False);

        /* TODO-SPARC: encode ASI directly into opcode if ri_asi is Sri_Imm */
        if (am_addr->tag == Sam_IR) {
            HReg r_asi = newVRegI(env);

            ADD_INSTR(ASR, False, SPARC64_ASR_ASI, r_asi, NULL);
            ADD_INSTR(ASR, True, SPARC64_ASR_ASI, hregSPARC64_G0(), ri_asi);
            if (isStore) {
                ADD_INSTR(StoreA, tySize, am_addr, r_reg, ri_asi);
            } else {
                ADD_INSTR(LoadA, tySize, r_reg, am_addr, ri_asi);
            }
            ADD_INSTR(ASR, True, SPARC64_ASR_ASI, hregSPARC64_G0(),
                           SPARC64RI_Reg(r_asi));
        } else {
            /* Opcode can't represent [%reg + %reg] address and ASI value
               calculated into %reg. */
            if (ri_asi->tag == Sri_Reg) {
                vpanic("sparc64 isel: ASI load/store: Addressing mode is not "
                       "compatible with ASI value.");
            }

            if (isStore) {
                ADD_INSTR(StoreA, tySize, am_addr, r_reg, ri_asi);
            } else {
                ADD_INSTR(LoadA, tySize, r_reg, am_addr, ri_asi);
            }
        }
    } else {
        if (isStore) {
            ADD_INSTR(Store, tySize, am_addr, r_reg);
        } else {
            ADD_INSTR(Load, tySize, r_reg, am_addr);
        }
    }
}

/* TODO-SPARC: Could be replaced with the following pattern:
       DEFINE_PATTERN(p_LDbe_F64, IRExpr_Load(Iend_BE, Ity_F64, bind(0))); */
static Bool
is_load_f64_be(const IRExpr *e)
{
    if ((e->tag == Iex_Load) && (e->Iex.Load.end == Iend_BE) &&
        (e->Iex.Load.ty == Ity_F64) && (e->Iex.Load.asi == NULL)) {
        return True;
    }
    return False;
}

static Bool
is_addr_u64_const(const IRExpr *e)
{
    if ((e->tag == Iex_Const) && (e->Iex.Const.con->tag == Ico_U64)) {
        return True;
    }
    return False;
}

/*----------------------------------------------------------------------------*/
/*--- ISEL: Integer expressions                                            ---*/
/*----------------------------------------------------------------------------*/

static SPARC64RI *
iselImm_RI(ISelEnv *env, ULong u, UInt maxbits, Bool sext)
{
    if (sext) {
        ULong m2 = (1 << (maxbits + 1)) - 1;

        if (FITS_INTO_MAXBITS_SIGNED((Long) u, maxbits)) {
            return (SPARC64RI_Imm(u & m2));
        }
    } else {
        ULong m = (1 << maxbits) - 1;
        if ((u & ~m) == 0) {
            return (SPARC64RI_Imm(u & m));
        }
    }

    /* Value does not fit to immediate so pass it via a temporary register. */
    HReg r_dst = newVRegI(env);
    ADD_INSTR(LI, r_dst, u);
    return SPARC64RI_Reg(r_dst);
}

static SPARC64RI *
iselExpr_RI(ISelEnv *env, const IRExpr *e, UInt maxbits, Bool sext)
{
    if (e->tag == Iex_Const) {
        IRConst *con = e->Iex.Const.con;
        ULong u;

        switch (con->tag) {
        case Ico_U64:
            u = con->Ico.U64;
            break;
        case Ico_U32:
            u = con->Ico.U32 & 0xffffffff;
            break;
        case Ico_U16:
            u = con->Ico.U16 & 0x0000ffff;
            break;
        case Ico_U8:
            u = con->Ico.U8 & 0x000000ff;
            return (SPARC64RI_Imm(u));
        default:
            vpanic("sparc64 isel: Unsupported constant type");
        }

        return iselImm_RI(env, u, maxbits, sext);
    }

    return (SPARC64RI_Reg(iselExpr_R(env, e)));
}

static SPARC64AMode *
iselExpr_AMode(ISelEnv *env, const IRExpr *e)
{
    /* Detect pattern Add64(e1, imm). Used heavily for save/restore. */
    if ((e->tag == Iex_Binop) && (e->Iex.Binop.op == Iop_Add64)
        && (e->Iex.Binop.arg2->tag == Iex_Const)) {

        const IRConst *con = e->Iex.Binop.arg2->Iex.Const.con;
        ULong imm;
        switch (con->tag) {
        case Ico_U64:
            imm = con->Ico.U64;
            break;
        default:
            vpanic("sparc64 isel: Unsupported constant type");
        }

        if (FITS_INTO_MAXBITS_SIGNED((Long) imm, SPARC64_SIMM13_MAXBITS)) {
            HReg r_argL = iselExpr_R(env, e->Iex.Binop.arg1);
            return SPARC64AMode_IR((Int) imm, r_argL);
        }
    }

    /* TODO-SPARC: Place for other optimisation is here. */

    return (SPARC64AMode_IR(0, iselExpr_R(env, e)));
}

/* Returns true for Iop_Cmp* or Iop_CasCmp* ops which return only {0, 1}. */
static Bool
is_int_cmp(IROp op)
{
    switch (op) {
    case Iop_CmpEQ8:   case Iop_CmpEQ16:  case Iop_CmpEQ32:  case Iop_CmpEQ64:
    case Iop_CmpNE8:   case Iop_CmpNE16:  case Iop_CmpNE32:  case Iop_CmpNE64:
    case Iop_CmpLT32S: case Iop_CmpLT64S: case Iop_CmpLE32S: case Iop_CmpLE64S:
    case Iop_CmpLT32U: case Iop_CmpLT64U: case Iop_CmpLE32U: case Iop_CmpLE64U:
    case Iop_CmpNEZ8:  case Iop_CmpNEZ16: case Iop_CmpNEZ32:
    case Iop_CmpNEZ64:
    case Iop_CasCmpEQ8:  case Iop_CasCmpEQ16: case Iop_CasCmpEQ32:
    case Iop_CasCmpEQ64: case Iop_CasCmpNE8:  case Iop_CasCmpNE16:
    case Iop_CasCmpNE32: case Iop_CasCmpNE64:
        return True;
    default:
        return False;
    }
}

static HReg
iselExpr_R_alu(ISelEnv *env, const IRExpr *e, SPARC64AluOp aluOp)
{
    vassert(aluOp != Salu_INVALID);

    HReg r_dst = newVRegI(env);
    HReg r_src = iselExpr_R(env, e->Iex.Binop.arg1);

    SPARC64RI *ri_src;
    if (aluOp == Salu_UMULXHI) {
        /* umulxhi cannot take an immediate. */
        ri_src = SPARC64RI_Reg(iselExpr_R(env, e->Iex.Binop.arg2));
    } else {
        ri_src = iselExpr_RI(env, e->Iex.Binop.arg2, SPARC64_SIMM13_MAXBITS,
                             True);
    }
    if ((aluOp == Salu_SDIV) || (aluOp == Salu_UDIV)) {
        HReg r_tmp = newVRegI(env);
        ADD_INSTR(Shft, Sshft_SRLX, r_tmp, r_src, SPARC64RI_Imm(32));
        ADD_INSTR(ASR, True, SPARC64_ASR_Y, hregSPARC64_G0(),
                       SPARC64RI_Reg(r_tmp));
    }
    ADD_INSTR(Alu, aluOp, r_dst, r_src, ri_src);
    return (r_dst);
}

static HReg
iselExpr_R_alufp(ISelEnv *env, const IRExpr *e, UChar sz,
                 SPARC64AluFpOp aluFpOp)
{
    vassert(aluFpOp != AluFp_INVALID);
    HReg r_dst = newVRegF(env, sz);
    HReg r_srcL, r_srcR;

    switch (e->tag) {
    case Iex_Triop:
        r_srcL = iselExpr_R(env, e->Iex.Triop.details->arg2);
        r_srcR = iselExpr_R(env, e->Iex.Triop.details->arg3);

        set_FSR_rounding_mode(env, e->Iex.Triop.details->arg1);
        break;
    case Iex_Binop:
        r_srcL = iselExpr_R(env, e->Iex.Binop.arg1);
        r_srcR = iselExpr_R(env, e->Iex.Binop.arg2);
        break;
    case Iex_Unop:
        r_srcL = iselExpr_R(env, e->Iex.Unop.arg);
        r_srcR = INVALID_HREG;
        break;
    default:
         vpanic("iselExpr_R_alufp(sparc64)");
    }

    ADD_INSTR(AluFp, aluFpOp, r_dst, r_srcL, r_srcR);
    return (r_dst);
}

static HReg
iselExpr_R_fusedfp(ISelEnv *env, const IRExpr *e, UChar sz,
                   SPARC64FusedFpOp fusedFpOp)
{
    vassert(fusedFpOp != FusedFp_INVALID);

    HReg r_dst = newVRegF(env, sz);
    HReg r_arg1 = iselExpr_R(env, e->Iex.Qop.details->arg2);
    HReg r_arg2 = iselExpr_R(env, e->Iex.Qop.details->arg3);
    HReg r_arg3 = iselExpr_R(env, e->Iex.Qop.details->arg4);

    set_FSR_rounding_mode(env, e->Iex.Qop.details->arg1);
    ADD_INSTR(FusedFp, fusedFpOp, r_dst, r_arg1, r_arg2, r_arg3);
    return r_dst;
}

static HReg
iselExpr_R_fshft(ISelEnv *env, const IRExpr *e, SPARC64ShftFpOp shft_op)
{
    vassert(e->tag == Iex_Binop);

    HReg r_dst = newVRegF(env, 8);
    HReg r_srcL = iselExpr_R(env, e->Iex.Binop.arg1);
    HReg r_srcR = iselExpr_R(env, e->Iex.Binop.arg2);

    ADD_INSTR(ShftFp, shft_op, r_dst, r_srcL, r_srcR);
    return (r_dst);
}

static HReg
iselExpr_R_fsqrt(ISelEnv *env, const IRExpr *e, UChar sz)
{
    vassert(e->tag == Iex_Binop);

    HReg r_dst = newVRegF(env, sz);
    HReg r_srcR = iselExpr_R(env, e->Iex.Binop.arg2);

    set_FSR_rounding_mode(env, e->Iex.Binop.arg1);
    ADD_INSTR(SqrtFp, r_dst, r_srcR);
    return (r_dst);
}

static HReg
iselExpr_R_ftoi(ISelEnv *env, const IRExpr *e, UInt fregSize, IRType ty)
{
    HReg r_dst = newVRegF(env, fregSize);
    HReg r_src = iselExpr_R(env, e->Iex.Binop.arg2);

    /* These instructions always round toward zero. */
    ADD_INSTR(ConvFp, r_dst, r_src, False, True);

    if ((ty == Ity_I64) || (ty == Ity_I32)) {
        /* Result ends up in a host register, such as that from IRTemp. */
        HReg r_int = newVRegI(env);
        ADD_INSTR(MovFpToIReg, r_int, r_dst);
        return r_int;
    } else {
        return r_dst;
    }
}

static HReg
iselExpr_R_shft(ISelEnv *env, const IRExpr *e, SPARC64ShftOp shftOp)
{
    vassert(shftOp != Sshft_INVALID);

    HReg r_dst = newVRegI(env);
    HReg r_src = iselExpr_R(env, e->Iex.Binop.arg1);
    SPARC64RI *ri_src = iselExpr_RI(env, e->Iex.Binop.arg2, 5, False);
    ADD_INSTR(Shft, shftOp, r_dst, r_src, ri_src);
    return (r_dst);
}

static HReg
iselExpr_R_cmp8(ISelEnv *env, const IRExpr *e, SPARC64CondCode cond)
{
    HReg r_dst = newVRegI(env);
    HReg r_srcL = iselExpr_R(env, e->Iex.Binop.arg1);
    HReg r_srcR = iselExpr_R(env, e->Iex.Binop.arg2);
    HReg r_maskedL = newVRegI(env);
    HReg r_maskedR = newVRegI(env);

    /* TODO-SPARC: No need to mask if ldub was used to pull the value. */
    ADD_INSTR(Alu, Salu_AND, r_maskedL, r_srcL, SPARC64RI_Imm(0xff));
    ADD_INSTR(Alu, Salu_AND, r_maskedR, r_srcR, SPARC64RI_Imm(0xff));
    ADD_INSTR(Alu, Salu_SUBcc, hregSPARC64_G0(), r_maskedL,
                   SPARC64RI_Reg(r_maskedR));
    ADD_INSTR(Alu, Salu_OR, r_dst, hregSPARC64_G0(), SPARC64RI_Imm(1));
    ADD_INSTR(MoveCond, 1 ^ cond, r_dst, hregSPARC64_G0());
    return (r_dst);
}

static HReg
iselExpr_R_cmp32(ISelEnv *env, const IRExpr *e, SPARC64CondCode cond)
{
    HReg r_dst = newVRegI(env);
    HReg r_srcL = iselExpr_R(env, e->Iex.Binop.arg1);
    HReg r_srcR = iselExpr_R(env, e->Iex.Binop.arg2);
    HReg r_maskedL = newVRegI(env);
    HReg r_maskedR = newVRegI(env);

    /* TODO-SPARC: No need to mask if lduw was used to pull the value. */
    ADD_INSTR(Shft, Sshft_SRL, r_maskedL, r_srcL, SPARC64RI_Imm(0));
    ADD_INSTR(Shft, Sshft_SRL, r_maskedR, r_srcR, SPARC64RI_Imm(0));
    ADD_INSTR(Alu, Salu_SUBcc, hregSPARC64_G0(), r_maskedL,
                   SPARC64RI_Reg(r_maskedR));
    ADD_INSTR(Alu, Salu_OR, r_dst, hregSPARC64_G0(), SPARC64RI_Imm(1));
    ADD_INSTR(MoveCond, 1 ^ cond, r_dst, hregSPARC64_G0());
    return (r_dst);
}

static HReg
iselExpr_R_cmp64(ISelEnv *env, const IRExpr *e, SPARC64CondCode cond)
{
    HReg r_dst = newVRegI(env);
    HReg r_srcL = iselExpr_R(env, e->Iex.Binop.arg1);
    SPARC64RI *ri_srcR = iselExpr_RI(env, e->Iex.Binop.arg2,
                                     SPARC64_SIMM13_MAXBITS, True);
    ADD_INSTR(Alu, Salu_SUBcc, hregSPARC64_G0(), r_srcL, ri_srcR);
    ADD_INSTR(Alu, Salu_OR, r_dst, hregSPARC64_G0(), SPARC64RI_Imm(1));
    ADD_INSTR(MoveCond, 1 ^ cond, r_dst, hregSPARC64_G0());
    return (r_dst);
}

static HReg
iselExpr_R_sext64(ISelEnv *env, const IRExpr *e, SizeT shift_count)
{
    HReg r_dst = newVRegI(env);
    HReg r_srcL = iselExpr_R(env, e->Iex.Unop.arg);

    /* sign extend to 64 bits */
    ADD_INSTR(Shft, Sshft_SLLX, r_dst, r_srcL, SPARC64RI_Imm(shift_count));
    ADD_INSTR(Shft, Sshft_SRAX, r_dst, r_dst, SPARC64RI_Imm(shift_count));
    return (r_dst);
}

static HReg
iselExpr_R_narrow(ISelEnv *env, const IRExpr *e, UInt mask)
{
    HReg r_dst = newVRegI(env);
    HReg r_srcL = iselExpr_R(env, e->Iex.Unop.arg);

    SPARC64RI *ri_mask = iselImm_RI(env, mask, SPARC64_SIMM13_MAXBITS, True);
    ADD_INSTR(Alu, Salu_AND, r_dst, r_srcL, ri_mask);
    return (r_dst);
}

static HReg
iselExpr_R(ISelEnv *env, const IRExpr *e)
{
    IRType ty = typeOfIRExpr(env->type_env, e);
    vassert(ty == Ity_I1 || ty == Ity_I8 || ty == Ity_I16 ||
            ty == Ity_I32 || ty == Ity_I64 || ty == Ity_F32 ||
            ty == Ity_F64 || ty == Ity_F128);

    switch (e->tag) {
    /* --------- TEMP --------- */
    case Iex_RdTmp:
        return (lookupIRTemp(env, e->Iex.RdTmp.tmp));
    /* --------- GET --------- */
    case Iex_Get: {
        HReg r_dst = INVALID_HREG;

        switch (ty) {
        case Ity_F32 ... Ity_F128:
            r_dst = newVRegF_from_IRType(env, ty);
            break;
        default:
            r_dst = newVRegI(env);
        }

        addInstr(env, iselExpr_Get_insn(e, ty, r_dst));
        return (r_dst);
    }
    /* --------- LOAD --------- */
    case Iex_Load: {
        if (e->Iex.Load.end != Iend_BE)
            vpanic("sparc64 isel: Loads other than BE are currently "
                   "unsupported.");

        HReg r_dst;
        switch (ty) {
        case Ity_F32 ... Ity_F128:
            r_dst = newVRegF_from_IRType(env, ty);
            break;
        default:
            r_dst = newVRegI(env);
            break;
        }

        doStoreLoad(env, e->Iex.Load.addr, e->Iex.Load.asi, ty, False, r_dst);
        return r_dst;
    }
    /* --------- QUATERNARY OP --------- */
    case Iex_Qop:
        switch (e->Iex.Qop.details->op) {
        case Iop_MAddF32:
            return iselExpr_R_fusedfp(env, e, 4, FusedFp_MADD);
        case Iop_MAddF64:
            return iselExpr_R_fusedfp(env, e, 8, FusedFp_MADD);
        case Iop_MSubF32:
            return iselExpr_R_fusedfp(env, e, 4, FusedFp_MSUB);
        case Iop_MSubF64:
            return iselExpr_R_fusedfp(env, e, 8, FusedFp_MSUB);
        default:
            ppIROp(e->Iex.Qop.details->op);
            vpanic("sparc64 isel: Unsupported quaternary operation");
        }
    /* --------- TERNARY OP --------- */
    case Iex_Triop: {
        const IRTriop *triop = e->Iex.Triop.details;
        switch (triop->op) {
        case Iop_AddF32:
            return iselExpr_R_alufp(env, e, 4, AluFp_FADD);
        case Iop_AddF64:
            return iselExpr_R_alufp(env, e, 8, AluFp_FADD);
        case Iop_AddF128:
            return iselExpr_R_alufp(env, e, 16, AluFp_FADD);
        case Iop_AlignF64: {
            HReg r_dst = newVRegF(env, 8);
            HReg r_selector = iselExpr_R(env, triop->arg1);
            HReg r_srcL = iselExpr_R(env, triop->arg2);
            HReg r_srcR = iselExpr_R(env, triop->arg3);

            /* Copy srcL to dst as AlignDataFp destroys it. */
            ADD_INSTR(MovFp, r_dst, r_srcL);

            if ((env->hwcaps & VEX_HWCAPS_SPARC64_SPARC5)
                != VEX_HWCAPS_SPARC64_SPARC5) {
                vpanic("FALIGNDATAi is unsupported on sparc64 < SPARC5");
            }
            ADD_INSTR(AlignDataFp, r_dst, r_selector, r_srcR);
            return (r_dst);
        }
        case Iop_DivF32:
            return iselExpr_R_alufp(env, e, 4, AluFp_FDIV);
        case Iop_DivF64:
            return iselExpr_R_alufp(env, e, 8, AluFp_FDIV);
        case Iop_DivF128:
            return iselExpr_R_alufp(env, e, 16, AluFp_FDIV);
        case Iop_MulF32:
            return iselExpr_R_alufp(env, e, 4, AluFp_FMUL);
        case Iop_MulF64:
            return iselExpr_R_alufp(env, e, 8, AluFp_FMUL);
        case Iop_MulF128:
            return iselExpr_R_alufp(env, e, 16, AluFp_FMUL);
        case Iop_ShuffleF64: {
            HReg r_dst = newVRegF(env, 8);
            HReg r_mask = iselExpr_R(env, triop->arg1);
            HReg r_srcL = iselExpr_R(env, triop->arg2);
            HReg r_srcR = iselExpr_R(env, triop->arg3);

            if ((env->hwcaps & VEX_HWCAPS_SPARC64_VIS2)
                != VEX_HWCAPS_SPARC64_VIS2) {
                vpanic("BSHUFFLE is unsupported on sparc64 < VIS2");
            }

            ADD_INSTR(Shft, Sshft_SLLX, r_mask, r_mask, SPARC64RI_Imm(32));
            ADD_INSTR(ASR, True, SPARC64_ASR_GSR, hregSPARC64_G0(),
                           SPARC64RI_Reg(r_mask));
            ADD_INSTR(ShuffleFp, r_dst, r_srcL, r_srcR);
            return r_dst;
        }
        case Iop_SubF32:
            return iselExpr_R_alufp(env, e, 4, AluFp_FSUB);
        case Iop_SubF64:
            return iselExpr_R_alufp(env, e, 8, AluFp_FSUB);
        case Iop_SubF128:
            return iselExpr_R_alufp(env, e, 16, AluFp_FSUB);
        default:
            ppIROp(e->Iex.Triop.details->op);
            vpanic("sparc64 isel: Unsupported ternary operation");
        }
    }
    /* --------- BINARY OP --------- */
    case Iex_Binop: {
        const IRExpr *arg1 = e->Iex.Binop.arg1;
        const IRExpr *arg2 = e->Iex.Binop.arg2;

        switch (e->Iex.Binop.op) {
        /* arithmetic */
        case Iop_Add64:
            return (iselExpr_R_alu(env, e, Salu_ADD));
        case Iop_DivS64:
            return (iselExpr_R_alu(env, e, Salu_SDIVX));
        case Iop_DivU64:
            return (iselExpr_R_alu(env, e, Salu_UDIVX));
        case Iop_DivS64to32:
            return (iselExpr_R_alu(env, e, Salu_SDIV));
        case Iop_DivU64to32:
            return (iselExpr_R_alu(env, e, Salu_UDIV));
        case Iop_MullS32:
            return (iselExpr_R_alu(env, e, Salu_SMUL));
        case Iop_MullU32:
            return (iselExpr_R_alu(env, e, Salu_UMUL));
        case Iop_Mul64:
            return (iselExpr_R_alu(env, e, Salu_MULX));
        case Iop_MulHiU64:
            return (iselExpr_R_alu(env, e, Salu_UMULXHI));
        case Iop_Max32U: {
            HReg r_srcL = iselExpr_R(env, arg1);
            HReg r_srcR = iselExpr_R(env, arg2);
            HReg r_dst = newVRegI(env);

            ADD_INSTR(Alu, Salu_OR, r_dst, r_srcL,
                           SPARC64RI_Reg(hregSPARC64_G0()));
            ADD_INSTR(Alu, Salu_SUBcc, hregSPARC64_G0(), r_srcL,
                           SPARC64RI_Reg(r_srcR));
            ADD_INSTR(MoveCond, Scc_LEU, r_dst, r_srcR);
            return (r_dst);
        }
        case Iop_Sub64:
            return (iselExpr_R_alu(env, e, Salu_SUB));
        /* logic */
        case Iop_And32:
        case Iop_And64:
            return (iselExpr_R_alu(env, e, Salu_AND));
        case Iop_Or32:
        case Iop_Or64:
            return (iselExpr_R_alu(env, e, Salu_OR));
        case Iop_Xor64:
            return (iselExpr_R_alu(env, e, Salu_XOR));
        /* shift */
        case Iop_Shl32:
            return (iselExpr_R_shft(env, e, Sshft_SLL));
        case Iop_Shl64:
            return (iselExpr_R_shft(env, e, Sshft_SLLX));
        case Iop_Shr32:
            return (iselExpr_R_shft(env, e, Sshft_SRL));
        case Iop_Shr64:
            return (iselExpr_R_shft(env, e, Sshft_SRLX));
        case Iop_Sar32:
            return (iselExpr_R_shft(env, e, Sshft_SRA));
        case Iop_Sar64:
            return (iselExpr_R_shft(env, e, Sshft_SRAX));
        /* compare */
        case Iop_CasCmpEQ8:
            return (iselExpr_R_cmp8(env, e, Scc_E));
        case Iop_CasCmpEQ32:
            return (iselExpr_R_cmp32(env, e, Scc_E));
        case Iop_CasCmpEQ64:
        case Iop_CmpEQ64:
            return (iselExpr_R_cmp64(env, e, Scc_E));
        case Iop_CmpNE64:
            return (iselExpr_R_cmp64(env, e, Scc_NE));
        case Iop_CmpLT64S:
            return (iselExpr_R_cmp64(env, e, Scc_L));
        case Iop_CmpLT64U:
            return (iselExpr_R_cmp64(env, e, Scc_CS));
        case Iop_CmpLE64S:
            return (iselExpr_R_cmp64(env, e, Scc_LE));
        case Iop_CmpLE64U:
            return (iselExpr_R_cmp64(env, e, Scc_LEU));
        /* narrowing and widening */
        case Iop_32HLto64: {
            HReg r_srcL = iselExpr_R(env, arg1);
            HReg r_srcR = iselExpr_R(env, arg2);
            HReg r_lo32 = newVRegI(env);
            HReg r_dst = newVRegI(env);

            /* TODO-SPARC: No need to mask if lduw was used to pull
                           either arg1 or arg2 value. */
            ADD_INSTR(Shft, Sshft_SRL, r_lo32, r_srcR, SPARC64RI_Imm(0));
            ADD_INSTR(Shft, Sshft_SLLX, r_dst, r_srcL, SPARC64RI_Imm(32));
            ADD_INSTR(Alu, Salu_OR, r_dst, r_lo32, SPARC64RI_Reg(r_dst));
            return (r_dst);
        }
        /* floats */
        case Iop_AndF32:
            return iselExpr_R_alufp(env, e, 4, AluFp_FAND);
        case Iop_AndF64:
            return iselExpr_R_alufp(env, e, 8, AluFp_FAND);
        case Iop_CmpF32:
        case Iop_CmpF64:
        case Iop_CmpF128: {
            HReg r_srcL = iselExpr_R(env, arg1);
            HReg r_srcR = iselExpr_R(env, arg2);

            /* Do the compare (FCMP), which sets %fcc0 in %fsr. Then
               create the IRCmpF64Result encoded result in dst. */
            ADD_INSTR(CmpFp, r_srcL, r_srcR, 0);
            SPARC64AMode *am = SPARC64AMode_IR(
                        OFFSET_sparc64_scratchpad, SPARC64_GuestStatePointer());
            ADD_INSTR(StoreFSR, 8, am);

            HReg r_fsr = newVRegI(env);
            ADD_INSTR(Load, 8, r_fsr, am);
            ADD_INSTR(Shft, Sshft_SRLX, r_fsr, r_fsr, SPARC64RI_Imm(10));
            ADD_INSTR(Alu, Salu_AND, r_fsr, r_fsr, SPARC64RI_Imm(0x3));

            HReg r_dst = newVRegI(env);
            ADD_INSTR(LI, r_dst, Ircr_GT); // the default
            ADD_INSTR(MoveReg, Src_Z, r_dst, r_fsr, SPARC64RI_Imm(Ircr_EQ));
            ADD_INSTR(Alu, Salu_SUB, r_fsr, r_fsr, SPARC64RI_Imm(1));
            ADD_INSTR(MoveReg, Src_Z, r_dst, r_fsr, SPARC64RI_Imm(Ircr_LT));
            ADD_INSTR(Alu, Salu_SUB, r_fsr, r_fsr, SPARC64RI_Imm(1));
            ADD_INSTR(MoveReg, Src_Z, r_dst, r_fsr, SPARC64RI_Imm(Ircr_GT));
            ADD_INSTR(Alu, Salu_SUB, r_fsr, r_fsr, SPARC64RI_Imm(1));
            ADD_INSTR(MoveReg, Src_Z, r_dst, r_fsr, SPARC64RI_Imm(Ircr_UN));
            return (r_dst);
        }
        case Iop_I32StoF32: {
            HReg r_dst = newVRegF(env, 4);
            HReg r_tmp;
            if ((arg2->tag == Iex_Unop) &&
                (arg2->Iex.Unop.op == Iop_ReinterpF32asI32)) {
                r_tmp = iselExpr_R(env, arg2->Iex.Unop.arg);
            } else {
                HReg r_src = iselExpr_R(env, arg2);
                r_tmp = newVRegF(env, 4);

                if ((env->hwcaps & VEX_HWCAPS_SPARC64_VIS3)
                    != VEX_HWCAPS_SPARC64_VIS3) {
                    vpanic("movwtos is unsupported on sparc64 < OSA 2011");
                }
                ADD_INSTR(MovIRegToFp, r_tmp, r_src);
            }
            set_FSR_rounding_mode(env, arg1);
            ADD_INSTR(ConvFp, r_dst, r_tmp, True, False);
            return (r_dst);
        }
        case Iop_I64StoF32: {
            HReg r_dst = newVRegF(env, 4);
            HReg r_tmp;
            if ((arg2->tag == Iex_Unop) &&
                (arg2->Iex.Unop.op == Iop_ReinterpF64asI64)) {
                r_tmp = iselExpr_R(env, arg2->Iex.Unop.arg);
            } else {
                HReg r_src = iselExpr_R(env, arg2);
                r_tmp = newVRegF(env, 8);

                if ((env->hwcaps & VEX_HWCAPS_SPARC64_VIS3)
                    != VEX_HWCAPS_SPARC64_VIS3) {
                    vpanic("movxtod is unsupported on sparc64 < OSA 2011");
                }
                ADD_INSTR(MovIRegToFp, r_tmp, r_src);
            }
            set_FSR_rounding_mode(env, arg1);
            ADD_INSTR(ConvFp, r_dst, r_tmp, True, False);
            return (r_dst);
        }
        case Iop_I64StoF64: {
            HReg r_dst = newVRegF(env, 8);
            HReg r_tmp;
            if ((arg2->tag == Iex_Unop) &&
                (arg2->Iex.Unop.op == Iop_ReinterpF64asI64)) {
                r_tmp = iselExpr_R(env, arg2->Iex.Unop.arg);
            } else {
                HReg r_src = iselExpr_R(env, arg2);
                r_tmp = newVRegF(env, 8);

                if ((env->hwcaps & VEX_HWCAPS_SPARC64_VIS3)
                    != VEX_HWCAPS_SPARC64_VIS3) {
                    vpanic("movxtod is unsupported on sparc64 < OSA 2011");
                }
                ADD_INSTR(MovIRegToFp, r_tmp, r_src);
            }
            set_FSR_rounding_mode(env, arg1);
            ADD_INSTR(ConvFp, r_dst, r_tmp, True, False);
            return (r_dst);
        }
        case Iop_F32toI32U:
            return iselExpr_R_ftoi(env, e, 4, ty);
        case Iop_F32toI64U:
            return iselExpr_R_ftoi(env, e, 8, ty);
        case Iop_F64toF32: {
            HReg r_dst = newVRegF(env, 4);
            HReg r_src = iselExpr_R(env, arg2);
            set_FSR_rounding_mode(env, arg1);
            ADD_INSTR(ConvFp, r_dst, r_src, False, False);
            return (r_dst);
        }
        case Iop_F64HLtoF128:
            if (is_load_f64_be(arg1) && is_load_f64_be(arg2)
                && is_addr_u64_const(arg1->Iex.Load.addr)
                && is_addr_u64_const(arg2->Iex.Load.addr)
                && (arg1->Iex.Load.addr->Iex.Const.con->Ico.U64 + 8
                    == arg2->Iex.Load.addr->Iex.Const.con->Ico.U64)) {
                /* Load from two adjacent addresses. */
                HReg r_dst = newVRegF(env, 16);
                ADD_INSTR(Load, 16, r_dst,
                                iselExpr_AMode(env, arg1->Iex.Load.addr));
                return (r_dst);
            } else {
                vpanic("sparc64 isel: Unsupported generic F64HLtoF128");
            }
        case Iop_F128toF32: {
            HReg r_dst = newVRegF(env, 4);
            HReg r_src = iselExpr_R(env, arg2);
            set_FSR_rounding_mode(env, arg1);
            ADD_INSTR(ConvFp, r_dst, r_src, False, False);
            return (r_dst);
        }
        case Iop_F128toF64: {
            HReg r_dst = newVRegF(env, 8);
            HReg r_src = iselExpr_R(env, arg2);
            set_FSR_rounding_mode(env, arg1);
            ADD_INSTR(ConvFp, r_dst, r_src, False, False);
            return (r_dst);
        }
        case Iop_F64toI32U:
            return iselExpr_R_ftoi(env, e, 4, ty);
        case Iop_F64toI64U:
            return iselExpr_R_ftoi(env, e, 8, ty);
        case Iop_F128toI32U:
            return iselExpr_R_ftoi(env, e, 4, ty);
        case Iop_F128toI64U:
            return iselExpr_R_ftoi(env, e, 8, ty);
        case Iop_MullF32:
        case Iop_MullF64: {
            HReg r_srcL = iselExpr_R(env, arg1);
            HReg r_srcR = iselExpr_R(env, arg2);
            HReg r_dst = newVRegF(env,
                                 (e->Iex.Binop.op == Iop_MullF32) ? 8 : 16);

            ADD_INSTR(AluFp, AluFp_FsdMUL, r_dst, r_srcL, r_srcR);
            return (r_dst);
        }
        case Iop_OrF32:
            return iselExpr_R_alufp(env, e, 4, AluFp_FOR);
        case Iop_OrF64:
            return iselExpr_R_alufp(env, e, 8, AluFp_FOR);
        case Iop_ShlF16x4:
            return iselExpr_R_fshft(env, e, ShftFp_SLL16);
        case Iop_ShrF16x4:
            return iselExpr_R_fshft(env, e, ShftFp_SRL16);
        case Iop_ShlF32x2:
            return iselExpr_R_fshft(env, e, ShftFp_SLL32);
        case Iop_ShrF32x2:
            return iselExpr_R_fshft(env, e, ShftFp_SRL32);
        case Iop_QSalF16x4:
            return iselExpr_R_fshft(env, e, ShftFp_SLAS16);
        case Iop_SarF16x4:
            return iselExpr_R_fshft(env, e, ShftFp_SRA16);
        case Iop_QSalF32x2:
            return iselExpr_R_fshft(env, e, ShftFp_SLAS32);
        case Iop_SarF32x2:
            return iselExpr_R_fshft(env, e, ShftFp_SRA32);
        case Iop_SqrtF32:
            return iselExpr_R_fsqrt(env, e, 4);
        case Iop_SqrtF64:
            return iselExpr_R_fsqrt(env, e, 8);
        case Iop_SqrtF128:
            return iselExpr_R_fsqrt(env, e, 16);
        case Iop_XorF32:
            return iselExpr_R_alufp(env, e, 4, AluFp_FXOR);
        case Iop_XorF64:
            return iselExpr_R_alufp(env, e, 8, AluFp_FXOR);
        default:
            ppIROp(e->Iex.Binop.op);
            vpanic("sparc64 isel: Unsupported binary operation");
        }
    }
    /* --------- UNARY OP --------- */
    case Iex_Unop: {
        IROp op_unop = e->Iex.Unop.op;
        const IRExpr *arg = e->Iex.Unop.arg;
        HReg r_dst, r_srcL, r_masked;

        switch (op_unop) {
        case Iop_1Sto32:
        case Iop_1Sto64:
            return iselExpr_R_sext64(env, e, 63);
        case Iop_1Uto32:
        case Iop_1Uto64:
            /* Cmp* and CasCmp* always return {0, 1}. No need to mask that. */
            if ((arg->tag == Iex_Unop) && is_int_cmp(arg->Iex.Unop.op)) {
                return iselExpr_R(env, arg);
            } else if ((arg->tag == Iex_Binop) &&
                       is_int_cmp(arg->Iex.Binop.op)) {
                return iselExpr_R(env, arg);
            } else {
                r_dst = newVRegI(env);
                r_srcL = iselExpr_R(env, arg);
                ADD_INSTR(Alu, Salu_AND, r_dst, r_srcL, SPARC64RI_Imm(1));
                return (r_dst);
            }
        case Iop_8Sto64:
            /* TODO-SPARC: If arg is a Load we can optimize this because ldsb
               sign extends by definition. */
            return iselExpr_R_sext64(env, e, 56);
        case Iop_8Uto32:
        case Iop_8Uto64:
            /* TODO-SPARC: If arg is a Load we can optimize this because ldub
               zero extends by definition. */
            r_dst = newVRegI(env);
            r_srcL = iselExpr_R(env, arg);
            ADD_INSTR(Alu, Salu_AND, r_dst, r_srcL, SPARC64RI_Imm(0xFF));
            return (r_dst);
        case Iop_16Sto64:
            /* TODO-SPARC: If arg is a Load we can optimize this because ldsh
               sign extends by definition. */
            return iselExpr_R_sext64(env, e, 48);
        case Iop_16Uto64:
            /* TODO-SPARC: If arg is a Load we can optimize this because lduh
               zero extends by definition. */
            r_dst = newVRegI(env);
            r_srcL = iselExpr_R(env, arg);
            ADD_INSTR(Shft, Sshft_SLLX, r_dst, r_srcL, SPARC64RI_Imm(48));
            ADD_INSTR(Shft, Sshft_SRLX, r_dst, r_dst, SPARC64RI_Imm(48));
            return (r_dst);
        case Iop_32to1:
            return iselExpr_R_narrow(env, e, 0x1);
        case Iop_32Sto64:
            /* TODO-SPARC: If arg is a Load we can optimize this because ldsw
               sign extends by definition. */
            r_dst = newVRegI(env);
            r_srcL = iselExpr_R(env, arg);
            /* sign extend to 64 bits */
            ADD_INSTR(Shft, Sshft_SRA, r_dst, r_srcL, SPARC64RI_Imm(0));
            return (r_dst);
        case Iop_32Uto64:
            /* TODO-SPARC: If arg is a Load we can optimize this because lduw
               zero extends by definition. */
            if ((arg->tag == Iex_Unop) && (arg->Iex.Unop.op == Iop_64to32)) {
                /* 32Uto64(64to32(arg)) -> 32Uto64(arg) */
                arg = arg->Iex.Unop.arg;
            }
            r_dst = newVRegI(env);
            r_srcL = iselExpr_R(env, arg);
            ADD_INSTR(Shft, Sshft_SRL, r_dst, r_srcL, SPARC64RI_Imm(0));
            return (r_dst);
        case Iop_64to1:
            return iselExpr_R_narrow(env, e, 0x1);
        case Iop_64to8:
            return iselExpr_R_narrow(env, e, 0xFF);
        case Iop_64to16:
            return iselExpr_R_narrow(env, e, 0xFFFF);
        case Iop_64to32:
            r_dst = newVRegI(env);
            r_srcL = iselExpr_R(env, arg);

            /* Compilers use single instruction trick: srl %reg, 0, %reg. */
            ADD_INSTR(Shft, Sshft_SRL, r_dst, r_srcL, SPARC64RI_Imm(0));
            return (r_dst);
        case Iop_128to64:
            if (arg->tag == Iex_RdTmp) {
                return lookupIRTemp(env, arg->Iex.RdTmp.tmp);
            } else if ((arg->tag == Iex_Binop) &&
                       (arg->Iex.Binop.op == Iop_64HLto128)) {
                return iselExpr_R(env, arg->Iex.Binop.arg2);
            } else {
                ppIRExpr(e);
                vpanic("sparc64 isel: Unsupported generic 128to64");
            }
        case Iop_128HIto64:
            if (arg->tag == Iex_RdTmp) {
                HReg r_hi, r_lo;
                lookupIRTemp128(env, arg->Iex.RdTmp.tmp, &r_hi, &r_lo);
                return (r_hi);
            } else if ((arg->tag == Iex_Binop) &&
                       (arg->Iex.Binop.op == Iop_64HLto128)) {
                return iselExpr_R(env, arg->Iex.Binop.arg1);
            } else {
                ppIRExpr(e);
                vpanic("sparc64 isel: Unsupported generic 128HIto64");
            }
        case Iop_AbsF32:
            r_dst = newVRegF(env, 4);
            r_srcL = iselExpr_R(env, arg);
            ADD_INSTR(AbsFp, r_dst, r_srcL);
            return (r_dst);
        case Iop_AbsF64:
            r_dst = newVRegF(env, 8);
            r_srcL = iselExpr_R(env, arg);
            ADD_INSTR(AbsFp, r_dst, r_srcL);
            return (r_dst);
        case Iop_AbsF128:
            r_dst = newVRegF(env, 16);
            r_srcL = iselExpr_R(env, arg);
            ADD_INSTR(AbsFp, r_dst, r_srcL);
            return (r_dst);
        case Iop_CmpNEZ8:
            r_dst = newVRegI(env);
            if ((arg->tag == Iex_Unop) && (arg->Iex.Unop.op == Iop_64to8)) {
                /* CmpNEZ8(64to8(arg)) -> CmpNEZ8(arg) */
                arg = arg->Iex.Unop.arg;
            }
            r_srcL = iselExpr_R(env, arg);
            r_masked = newVRegI(env);
            ADD_INSTR(Alu, Salu_AND, r_masked, r_srcL, SPARC64RI_Imm(0xFF));
            ADD_INSTR(Alu, Salu_OR, r_dst, hregSPARC64_G0(), SPARC64RI_Imm(1));
            ADD_INSTR(MoveReg, Src_Z, r_dst, r_masked,
                               SPARC64RI_Reg(hregSPARC64_G0()));
            return (r_dst);
        case Iop_CmpNEZ32:
            r_dst = newVRegI(env);
            r_srcL = iselExpr_R(env, arg);
            r_masked = newVRegI(env);
            ADD_INSTR(Shft, Sshft_SRL, r_masked, r_srcL, SPARC64RI_Imm(0));
            ADD_INSTR(Alu, Salu_OR, r_dst, hregSPARC64_G0(), SPARC64RI_Imm(1));
            ADD_INSTR(MoveReg, Src_Z, r_dst, r_masked,
                               SPARC64RI_Reg(hregSPARC64_G0()));
            return (r_dst);
        case Iop_CmpNEZ64:
            r_dst = newVRegI(env);
            r_srcL = iselExpr_R(env, arg);
            ADD_INSTR(Alu, Salu_OR, r_dst, hregSPARC64_G0(), SPARC64RI_Imm(1));
            ADD_INSTR(MoveReg, Src_Z, r_dst, r_srcL,
                               SPARC64RI_Reg(hregSPARC64_G0()));
            return (r_dst);
        case Iop_CmpNEZ16x4: {
            r_dst = newVRegI(env);
            r_srcL = iselExpr_R(env, arg);
            r_masked = newVRegI(env);
            HReg r_lane0 = newVRegI(env);
            HReg r_lane1 = newVRegI(env);
            HReg r_lane2 = newVRegI(env);
            HReg r_lane3 = newVRegI(env);
            HReg r_mask16 = newVRegI(env);
            ADD_INSTR(LI, r_mask16, 0xFFFF);
            ADD_INSTR(Alu, Salu_AND, r_masked, r_srcL, SPARC64RI_Reg(r_mask16));
            ADD_INSTR(Alu, Salu_OR, r_lane0, hregSPARC64_G0(), SPARC64RI_Imm(1));
            ADD_INSTR(MoveReg, Src_Z, r_lane0, r_masked,
                               SPARC64RI_Reg(hregSPARC64_G0()));
            ADD_INSTR(Shft, Sshft_SRLX, r_masked, r_srcL, SPARC64RI_Imm(16));
            ADD_INSTR(Alu, Salu_AND, r_masked, r_srcL, SPARC64RI_Reg(r_mask16));
            ADD_INSTR(Alu, Salu_OR, r_lane1, hregSPARC64_G0(), SPARC64RI_Imm(1));
            ADD_INSTR(MoveReg, Src_Z, r_lane1, r_masked,
                               SPARC64RI_Reg(hregSPARC64_G0()));
            ADD_INSTR(Shft, Sshft_SRLX, r_masked, r_srcL, SPARC64RI_Imm(32));
            ADD_INSTR(Alu, Salu_AND, r_masked, r_srcL, SPARC64RI_Reg(r_mask16));
            ADD_INSTR(Alu, Salu_OR, r_lane2, hregSPARC64_G0(), SPARC64RI_Imm(1));
            ADD_INSTR(MoveReg, Src_Z, r_lane2, r_masked,
                               SPARC64RI_Reg(hregSPARC64_G0()));
            ADD_INSTR(Shft, Sshft_SRLX, r_masked, r_srcL, SPARC64RI_Imm(48));
            ADD_INSTR(Alu, Salu_AND, r_masked, r_srcL, SPARC64RI_Reg(r_mask16));
            ADD_INSTR(Alu, Salu_OR, r_lane3, hregSPARC64_G0(), SPARC64RI_Imm(1));
            ADD_INSTR(MoveReg, Src_Z, r_lane3, r_masked,
                               SPARC64RI_Reg(hregSPARC64_G0()));
            ADD_INSTR(Shft, Sshft_SLLX, r_lane1, r_lane1, SPARC64RI_Imm(16));
            ADD_INSTR(Shft, Sshft_SLLX, r_lane2, r_lane2, SPARC64RI_Imm(32));
            ADD_INSTR(Shft, Sshft_SLLX, r_lane3, r_lane3, SPARC64RI_Imm(48));
            ADD_INSTR(Alu, Salu_OR, r_dst, r_lane1, SPARC64RI_Reg(r_lane0));
            ADD_INSTR(Alu, Salu_OR, r_dst, r_dst, SPARC64RI_Reg(r_lane2));
            ADD_INSTR(Alu, Salu_OR, r_dst, r_dst, SPARC64RI_Reg(r_lane3));
            return (r_dst);
        }
        case Iop_CmpNEZ32x2: {
            /* Unfortunately FPCMP cannot be used because it places results
               in the least significant bits of the destination. Valgrind
               expects them to stay in their lanes, though.
               Viz h_generic_calc_CmpNEZ32x2(). */
            r_dst = newVRegI(env);
            r_srcL = iselExpr_R(env, arg);
            r_masked = newVRegI(env);
            HReg r_lane0 = newVRegI(env);
            HReg r_lane1 = newVRegI(env);
            ADD_INSTR(Shft, Sshft_SRL, r_masked, r_srcL, SPARC64RI_Imm(0));
            ADD_INSTR(Alu, Salu_OR, r_lane0, hregSPARC64_G0(), SPARC64RI_Imm(1));
            ADD_INSTR(MoveReg, Src_Z, r_lane0, r_masked,
                               SPARC64RI_Reg(hregSPARC64_G0()));
            ADD_INSTR(Shft, Sshft_SRLX, r_masked, r_srcL, SPARC64RI_Imm(32));
            ADD_INSTR(Alu, Salu_OR, r_lane1, hregSPARC64_G0(), SPARC64RI_Imm(1));
            ADD_INSTR(MoveReg, Src_Z, r_lane1, r_masked,
                               SPARC64RI_Reg(hregSPARC64_G0()));
            ADD_INSTR(Shft, Sshft_SLLX, r_lane1, r_lane1, SPARC64RI_Imm(32));
            ADD_INSTR(Alu, Salu_OR, r_dst, r_lane1, SPARC64RI_Reg(r_lane0));
            return (r_dst);
        }
        case Iop_Clz64:
            r_dst = newVRegI(env);
            r_srcL = iselExpr_R(env, arg);
            ADD_INSTR(Lzcnt, r_dst, r_srcL);
            return (r_dst);
        case Iop_CmpwNEZ32:
            /* CmpwNEZ32(src) = CmpwNEZ64(src & 0xFFFFFFFF)
                              = Left64(src & 0xFFFFFFFF) >>s 63.
               Use the fact that x | -x == 0 iff x == 0. Otherwise, either x
               or -x will have a 1 in bit 63. */
            r_dst = newVRegI(env);
            r_srcL = iselExpr_R(env, arg);
            r_masked = newVRegI(env);
            ADD_INSTR(Shft, Sshft_SRL, r_masked, r_srcL, SPARC64RI_Imm(0));
            ADD_INSTR(Alu, Salu_SUB, r_dst, hregSPARC64_G0(),
                           SPARC64RI_Reg(r_masked));
            ADD_INSTR(Alu, Salu_OR, r_dst, r_dst, SPARC64RI_Reg(r_masked));
            ADD_INSTR(Shft, Sshft_SRAX, r_dst, r_dst, SPARC64RI_Imm(63));
            return (r_dst);
        case Iop_CmpwNEZ64:
            /* CmpwNEZ64(src) = (src == 0) ? 0...0 : 1...1
                              = Left64(src) >>s 63 */
            r_dst = newVRegI(env);
            r_srcL = iselExpr_R(env, arg);
            ADD_INSTR(Alu, Salu_SUB, r_dst, hregSPARC64_G0(), SPARC64RI_Imm(1));
            ADD_INSTR(MoveReg, Src_Z, r_dst, r_srcL,
                               SPARC64RI_Reg(hregSPARC64_G0()));
            return (r_dst);
        case Iop_F32toF64:
            r_dst = newVRegF(env, 8);
            r_srcL = iselExpr_R(env, arg);
            ADD_INSTR(ConvFp, r_dst, r_srcL, False, False);
            return (r_dst);
        case Iop_F32toF128:
        case Iop_F64toF128:
            r_dst = newVRegF(env, 16);
            r_srcL = iselExpr_R(env, arg);
            ADD_INSTR(ConvFp, r_dst, r_srcL, False, False);
            return (r_dst);
        case Iop_F128HItoF64:
            if ((arg->tag == Iex_Binop) &&
                (arg->Iex.Binop.op == Iop_F64HLtoF128)) {
                return iselExpr_R(env, arg->Iex.Binop.arg1);
            } else {
                r_dst = newVRegF(env, 8);
                r_srcL = iselExpr_R(env, arg);
                ADD_INSTR(HalveFp, r_dst, r_srcL, True);
                return (r_dst);
            }
        case Iop_F128LOtoF64:
            if ((arg->tag == Iex_Binop) &&
                (arg->Iex.Binop.op == Iop_F64HLtoF128)) {
                return iselExpr_R(env, arg->Iex.Binop.arg2);
            } else {
                r_dst = newVRegF(env, 8);
                r_srcL = iselExpr_R(env, arg);
                ADD_INSTR(HalveFp, r_dst, r_srcL, False);
                return (r_dst);
            }
        case Iop_I32StoF64: {
            r_dst = newVRegF(env, 8);
            HReg r_tmp;
            if ((arg->tag == Iex_Unop) &&
                (arg->Iex.Unop.op == Iop_ReinterpF32asI32)) {
                r_tmp = r_srcL = iselExpr_R(env, arg->Iex.Unop.arg);
            } else {
                r_srcL = iselExpr_R(env, arg);
                r_tmp = newVRegF(env, 4);

                if ((env->hwcaps & VEX_HWCAPS_SPARC64_VIS3)
                    != VEX_HWCAPS_SPARC64_VIS3) {
                    vpanic("movwtos is unsupported on sparc64 < OSA 2011");
                }
                ADD_INSTR(MovIRegToFp, r_tmp, r_srcL);
            }
            ADD_INSTR(ConvFp, r_dst, r_tmp, True, False);
            return (r_dst);
        }
        case Iop_I32StoF128: {
            r_dst = newVRegF(env, 16);
            HReg r_tmp;
            if ((arg->tag == Iex_Unop) &&
                (arg->Iex.Unop.op == Iop_ReinterpF32asI32)) {
                r_tmp = r_srcL = iselExpr_R(env, arg->Iex.Unop.arg);
            } else {
                r_srcL = iselExpr_R(env, arg);
                r_tmp = newVRegF(env, 4);

                if ((env->hwcaps & VEX_HWCAPS_SPARC64_VIS3)
                    != VEX_HWCAPS_SPARC64_VIS3) {
                    vpanic("movwtos is unsupported on sparc64 < OSA 2011");
                }
                ADD_INSTR(MovIRegToFp, r_tmp, r_srcL);
            }
            ADD_INSTR(ConvFp, r_dst, r_tmp, True, False);
            return (r_dst);
        }
        case Iop_I64StoF128: {
            r_dst = newVRegF(env, 16);
            HReg r_tmp;
            if ((arg->tag == Iex_Unop) &&
                (arg->Iex.Unop.op == Iop_ReinterpF64asI64)) {
                r_tmp = r_srcL = iselExpr_R(env, arg->Iex.Unop.arg);
            } else {
                r_srcL = iselExpr_R(env, arg);
                r_tmp = newVRegF(env, 8);

                if ((env->hwcaps & VEX_HWCAPS_SPARC64_VIS3)
                    != VEX_HWCAPS_SPARC64_VIS3) {
                    vpanic("movxtod is unsupported on sparc64 < OSA 2011");
                }
                ADD_INSTR(MovIRegToFp, r_tmp, r_srcL);
            }
            ADD_INSTR(ConvFp, r_dst, r_tmp, True, False);
            return (r_dst);
        }
        case Iop_Left32:
        case Iop_Left64:
            /* Left64(src) = src | -src. Left32 can use the same implementation
               as in that case we don't care what the upper 32 bits become. */
            r_dst = newVRegI(env);
            r_srcL = iselExpr_R(env, arg);
            ADD_INSTR(Alu, Salu_SUB, r_dst, hregSPARC64_G0(),
                           SPARC64RI_Reg(r_srcL));
            ADD_INSTR(Alu, Salu_OR, r_dst, r_dst, SPARC64RI_Reg(r_srcL));
            return (r_dst);
        case Iop_NegF32:
            r_dst = newVRegF(env, 4);
            r_srcL = iselExpr_R(env, arg);
            ADD_INSTR(NegFp, r_dst, r_srcL);
            return (r_dst);
        case Iop_NegF64:
            r_dst = newVRegF(env, 8);
            r_srcL = iselExpr_R(env, arg);
            ADD_INSTR(NegFp, r_dst, r_srcL);
            return (r_dst);
        case Iop_NegF128:
            r_dst = newVRegF(env, 16);
            r_srcL = iselExpr_R(env, arg);
            ADD_INSTR(NegFp, r_dst, r_srcL);
            return (r_dst);
        case Iop_Not1:
            r_dst = newVRegI(env);
            r_srcL = iselExpr_R(env, arg);
            ADD_INSTR(LI, r_dst, 1);
            ADD_INSTR(Alu, Salu_SUB, r_dst, r_dst, SPARC64RI_Reg(r_srcL));
            return (r_dst);
        case Iop_Not8:
        case Iop_Not16:
        case Iop_Not32:
        case Iop_Not64:
            r_dst = newVRegI(env);
            r_srcL = iselExpr_R(env, arg);
            ADD_INSTR(Alu, Salu_XNOR, r_dst, hregSPARC64_G0(),
                           SPARC64RI_Reg(r_srcL));
            return (r_dst);
        case Iop_NotF32:
            return iselExpr_R_alufp(env, e, 4, AluFp_FNOT);
        case Iop_NotF64:
            return iselExpr_R_alufp(env, e, 8, AluFp_FNOT);
        case Iop_ReinterpF64asI64:
        case Iop_ReinterpF32asI32:
            r_dst = newVRegI(env);
            r_srcL = iselExpr_R(env, arg);

            if ((env->hwcaps & VEX_HWCAPS_SPARC64_VIS3)
                != VEX_HWCAPS_SPARC64_VIS3) {
                vpanic("movstouw/movdtox are unsupported on sparc64 < OSA 2011");
            }
            ADD_INSTR(MovFpToIReg, r_dst, r_srcL);
            return (r_dst);
        case Iop_ReinterpI64asF64:
            r_dst = newVRegF(env, 8);
            r_srcL = iselExpr_R(env, arg);

            if ((env->hwcaps & VEX_HWCAPS_SPARC64_VIS3)
                != VEX_HWCAPS_SPARC64_VIS3) {
                vpanic("movxtod is unsupported on sparc64 < OSA 2011");
            }
            ADD_INSTR(MovIRegToFp, r_dst, r_srcL);
            return (r_dst);
        default:
            ppIROp(op_unop);
            vpanic("sparc64 isel: Unsupported unary op");
        }
    }
    /* --------- LITERAL --------- */
    case Iex_Const: {
        HReg r_dst = newVRegI(env);
        addInstr(env, iselExpr_Const_insn(e, r_dst));
        return (r_dst);
    }
    /* --------- CCALL --------- */
    case Iex_CCall: {
        HReg r_dst = newVRegI(env);
        UInt addToSP = 0;
        RetLoc rloc = mk_RetLoc_INVALID();

        vassert(ty == e->Iex.CCall.retty);

        doHelperCall(&addToSP, &rloc, env, NULL, e->Iex.CCall.cee,
            e->Iex.CCall.retty, e->Iex.CCall.args);

        vassert(is_sane_RetLoc(rloc));
        vassert(rloc.pri == RLPri_Int);
        vassert(addToSP == 0);
        ADD_INSTR(Alu, Salu_OR, r_dst, hregSPARC64_G0(),
                       SPARC64RI_Reg(hregSPARC64_O0()));
        return (r_dst);
    }
    /* --------- ITE --------- */
    case Iex_ITE:
        if (typeOfIRExpr(env->type_env, e->Iex.ITE.cond) == Ity_I1) {
            switch (ty) {
            case Ity_I8 ... Ity_I64: {
                HReg r_dst = newVRegI(env);

                SPARC64RI *ri_false = iselExpr_RI(env, e->Iex.ITE.iffalse,
                                                 SPARC64_SIMM13_MAXBITS, True);
                HReg r_true = iselExpr_R(env, e->Iex.ITE.iftrue);
                /* We must create copy of the result otherwise MoveCond would
                   modify value of the false branch and break stuff. */
                ADD_INSTR(Alu, Salu_OR, r_dst, hregSPARC64_G0(), ri_false);

                SPARC64CondCode cond_code = iselCondCode(env, e->Iex.ITE.cond);
                ADD_INSTR(MoveCond, cond_code, r_dst, r_true);
                return (r_dst);
            }
            case Ity_F32 ... Ity_F128: {
                HReg r_dst = newVRegF_from_IRType(env, ty);

                HReg r_false = iselExpr_R(env, e->Iex.ITE.iffalse);
                HReg r_true  = iselExpr_R(env, e->Iex.ITE.iftrue);
                /* We must create copy of the result otherwise MovFpICond would
                   modify value of the false branch and break stuff. */
                ADD_INSTR(MovFp, r_dst, r_false);

                SPARC64CondCode cond_code = iselCondCode(env, e->Iex.ITE.cond);
                ADD_INSTR(MovFpICond, cond_code, r_dst, r_true);
                return (r_dst);
            }
            default:
                ppIRType(ty);
                break;
            }
        }
        vpanic("sparc64 isel: Unsupported ITE type");
        break;
    default:
        ppIRExpr(e);
        vpanic("sparc64 isel: Unsupported expression");
    }
}

/* Do not call this directly! Call iselExpr_128_R() instead. */
static void
iselExpr_128_R_do(ISelEnv *env, const IRExpr *e, HReg *r_dst_hi, HReg *r_dst_lo)
{
    IRType ty = typeOfIRExpr(env->type_env, e);
    vassert(ty == Ity_I128);

    switch (e->tag) {
    /* --------- TEMP --------- */
    case Iex_RdTmp:
        lookupIRTemp128(env, e->Iex.RdTmp.tmp, r_dst_hi, r_dst_lo);
        break;
    /* --------- GET --------- */
    case Iex_Get: {
        *r_dst_hi = newVRegI(env);
        *r_dst_lo = newVRegI(env);
        SPARC64AMode *am_hi = SPARC64AMode_IR(e->Iex.Get.offset,
            SPARC64_GuestStatePointer());
        SPARC64AMode *am_lo = SPARC64AMode_IR(e->Iex.Get.offset + 8,
            SPARC64_GuestStatePointer());

        ADD_INSTR(Load, 8, *r_dst_hi, am_hi);
        ADD_INSTR(Load, 8, *r_dst_lo, am_lo);
        break;
    }
    /* --------- BINARY OP --------- */
    case Iex_Binop: {
        const IRExpr *arg1 = e->Iex.Binop.arg1;
        const IRExpr *arg2 = e->Iex.Binop.arg2;

        switch (e->Iex.Binop.op) {
        case Iop_64HLto128: {
            *r_dst_hi = iselExpr_R(env, arg1);
            *r_dst_lo = iselExpr_R(env, arg2);
            break;
        }
        default:
            ppIROp(e->Iex.Binop.op);
            vpanic("sparc64 isel: Unsupported binary op");
        }
        break;
    }
    default:
        ppIRExpr(e);
        vpanic("sparc64 isel: Unsupported expression");
    }
}

/* Compute a 128-bit value into a register pair.
   As with IselExpr_R(), they must not be changed by subsequent code emitted
   by the caller.  */
static void
iselExpr_128_R(ISelEnv *env, const IRExpr *e, HReg *r_dst_hi, HReg *r_dst_lo)
{
    *r_dst_hi = *r_dst_lo = INVALID_HREG;

    iselExpr_128_R_do(env, e, r_dst_hi, r_dst_lo);

    vassert(!hregIsInvalid(*r_dst_hi));
    vassert(hregClass(*r_dst_hi) == HRcInt64);
    vassert(!hregIsInvalid(*r_dst_lo));
    vassert(hregClass(*r_dst_lo) == HRcInt64);
}

/*----------------------------------------------------------------------------*/
/*--- ISEL: Statements                                                     ---*/
/*----------------------------------------------------------------------------*/

static void
iselStmt(ISelEnv *env, IRStmt *stmt)
{
    if (vex_traceflags & VEX_TRACE_VCODE) {
        vex_printf("\n-- ");
        ppIRStmt(stmt);
        vex_printf("\n");
    }

    switch (stmt->tag) {
    /* --------- NO-OP --------- */
    case Ist_NoOp:
        break;
    /* --------- INSTR MARK --------- */
    /* Does not generate any executable code ... */
    case Ist_IMark:
        break;
    /* --------- ABI HINT --------- */
    case Ist_AbiHint:
        break;
    /* --------- PUT --------- */
    case Ist_Put: {
        HReg r_src = INVALID_HREG;
        const IRExpr *data = stmt->Ist.Put.data;
        IRType ty = typeOfIRExpr(env->type_env, data);
        SPARC64AMode *am_addr = SPARC64AMode_IR(stmt->Ist.Put.offset,
                                                SPARC64_GuestStatePointer());

        switch (ty) {
        case Ity_I8 ... Ity_I64:
        case Ity_F32 ... Ity_F128:
            if ((data->tag == Iex_Const) &&
                (data->Iex.Const.con->tag == Ico_U64) &&
                (data->Iex.Const.con->Ico.U64 == 0)) {
                /* Put of constant '0' can leverage %g0 directly. */
                r_src = hregSPARC64_G0();
            } else {
                r_src = iselExpr_R(env, data);
            }
            ADD_INSTR(Store, toUChar(sizeofIRType(ty)), am_addr, r_src);
            break;
        case Ity_I128: {
            HReg r_src_hi, r_src_lo;
            iselExpr_128_R(env, data, &r_src_hi, &r_src_lo);
            SPARC64AMode *am_addr_lo = SPARC64AMode_IR(stmt->Ist.Put.offset + 8,
                                                   SPARC64_GuestStatePointer());
            ADD_INSTR(Store, 8, am_addr,    r_src_hi);
            ADD_INSTR(Store, 8, am_addr_lo, r_src_lo);
            break;
        }
        default:
            vpanic("iselStmt(sparc64): Unsupported PUT type.");
        }
        break;
    }
    /* -------- STORE --------- */
    case Ist_Store: {
        if (stmt->Ist.Store.end != Iend_BE)
            vpanic("sparc64 isel: Stores other than BE are currently "
                   "unsupported.");

        HReg r_src = iselExpr_R(env, stmt->Ist.Store.data);
        IRType ty = typeOfIRExpr(env->type_env, stmt->Ist.Store.data);

        switch (ty) {
        case Ity_I8 ... Ity_I64:
        case Ity_F32 ... Ity_F128:
            doStoreLoad(env, stmt->Ist.Store.addr, stmt->Ist.Store.asi, ty,
                        True, r_src);
            break;
        default:
            vpanic("iselStmt(sparc64): Unsupported STORE type.");
        }
        break;
    }
    /* --------- TMP --------- */
    case Ist_WrTmp: {
        IRTemp tmp = stmt->Ist.WrTmp.tmp;
        IRType ty = typeOfIRTemp(env->type_env, tmp);
        HReg r_dst, r_src;

        switch (ty) {
        case Ity_I1:
        case Ity_I8:
        case Ity_I16:
        case Ity_I32:
        case Ity_I64:
            r_dst = lookupIRTemp(env, tmp);
            r_src = iselExpr_R(env, stmt->Ist.WrTmp.data);

            vassert(hregClass(r_dst) == hregClass(r_src));
            ADD_INSTR(Alu, Salu_OR, r_dst, hregSPARC64_G0(),
                           SPARC64RI_Reg(r_src));
            break;
        case Ity_I128: {
            HReg r_dst_hi, r_dst_lo, r_src_hi, r_src_lo;

            lookupIRTemp128(env, tmp, &r_dst_hi, &r_dst_lo);
            iselExpr_128_R(env, stmt->Ist.WrTmp.data, &r_src_hi, &r_src_lo);

            vassert(hregClass(r_dst_hi) == hregClass(r_src_hi));
            vassert(hregClass(r_dst_lo) == hregClass(r_src_lo));
            ADD_INSTR(Alu, Salu_OR, r_dst_hi, hregSPARC64_G0(),
                           SPARC64RI_Reg(r_src_hi));
            ADD_INSTR(Alu, Salu_OR, r_dst_lo, hregSPARC64_G0(),
                           SPARC64RI_Reg(r_src_lo));
            break;
        }
        case Ity_F32 ... Ity_F128:
            r_dst = lookupIRTemp(env, tmp);
            r_src = iselExpr_R(env, stmt->Ist.WrTmp.data);

            vassert(hregClass(r_dst) == hregClass(r_src));
            ADD_INSTR(MovFp, r_dst, r_src);
            break;
        default:
            vpanic("iselStmt(sparc64): Unsupported WrTmp type.");
        }
        break;
    }
    case Ist_PutI:
        vpanic("iselStmt(sparc64): Ist_PutI is unsupported.");
    case Ist_LoadG:
        vpanic("iselStmt(sparc64): Ist_LoadG is unsupported.");
    case Ist_StoreG:
        vpanic("iselStmt(sparc64): Ist_StoreG is unsupported.");
    case Ist_CAS:
        if (stmt->Ist.CAS.details->oldHi == IRTemp_INVALID) {
            IRCAS *cas = stmt->Ist.CAS.details;
            IRType ty  = typeOfIRExpr(env->type_env, cas->dataLo);
            HReg r_old = lookupIRTemp(env, cas->oldLo);

            if (ty == Ity_I8) {
                /* Insn 'ldstub' operates on 8 bits only with a constant. */
                vassert(cas->dataLo->tag == Iex_Const);
                vassert(cas->dataLo->Iex.Const.con->tag == Ico_U8);
                vassert(cas->dataLo->Iex.Const.con->tag == Ico_U8);
                vassert(cas->dataLo->Iex.Const.con->Ico.U8 == 0xff);

                SPARC64AMode *am_addr = iselExpr_AMode(env, cas->addr);
                ADD_INSTR(Ldstub, am_addr, r_old);
                return;
            }

            /* Instructions cas/casx expect that 'data' is in the same
               register as 'old'. As 'old' will be overwritten anyway,
               load 'data' there. */
            HReg r_addr  = iselExpr_R(env, cas->addr);
            HReg r_exp   = iselExpr_R(env, cas->expdLo);
            HReg r_data  = iselExpr_R(env, cas->dataLo);
            ADD_INSTR(Alu, Salu_OR, r_old, hregSPARC64_G0(),
                           SPARC64RI_Reg(r_data));
            /* TODO-SPARC: check for specializations leading to 'swap'. */
            switch (ty) {
            case Ity_I32:
                ADD_INSTR(CAS, 4, r_addr, r_exp, r_old);
                break;
            case Ity_I64:
                ADD_INSTR(CAS, 8, r_addr, r_exp, r_old);
                break;
            default:
                vpanic("iselStmt(sparc64): Unsupported CAS type.");
            }
        } else {
            vpanic("iselStmt(sparc64): double Ist_CAS is unsupported.");
        }
        break;
    case Ist_LLSC:
        vpanic("iselStmt(sparc64): Ist_LLSC is unsupported.");
    /* --------- DIRTY --------- */
    case Ist_Dirty: {
        IRDirty *d = stmt->Ist.Dirty.details;
        HReg r_dst;

        /* Check return type. */
        IRType retty = Ity_INVALID;
        if (d->tmp != IRTemp_INVALID)
            retty = typeOfIRTemp(env->type_env, d->tmp);

        switch (retty) {
        case Ity_INVALID:
        case Ity_I128:
        case Ity_I64:
        case Ity_I32:
        case Ity_I16:
        case Ity_I8:
        case Ity_I1:
            break;
        default:
            vpanic("iselStmt(sparc64): Ist_Dirty unsupported return type.");
        }

        /* Call the dirty helper. */
        UInt addToSp = 0;
        RetLoc rloc = mk_RetLoc_INVALID();
        doHelperCall(&addToSp, &rloc, env, d->guard, d->cee, retty, d->args);
        vassert(is_sane_RetLoc(rloc));

        /* Handle the returned value. */
        switch (retty) {
        case Ity_INVALID:
            vassert(d->tmp == IRTemp_INVALID);
            vassert(rloc.pri == RLPri_None);
            vassert(addToSp == 0);
            return;
        case Ity_I128: {
            HReg r_dst_hi, r_dst_lo;
            lookupIRTemp128(env, d->tmp, &r_dst_hi, &r_dst_lo);
            ADD_INSTR(Alu, Salu_OR, r_dst_hi, hregSPARC64_O0(),
                           SPARC64RI_Reg(hregSPARC64_G0()));
            ADD_INSTR(Alu, Salu_OR, r_dst_lo, hregSPARC64_O1(),
                           SPARC64RI_Reg(hregSPARC64_G0()));
            vassert(rloc.pri == RLPri_2Int);
            vassert(addToSp == 0);
            return;
        }
        case Ity_I64:
        case Ity_I32:
        case Ity_I16:
        case Ity_I8:
        case Ity_I1:
            r_dst = lookupIRTemp(env, d->tmp);
            ADD_INSTR(Alu, Salu_OR, r_dst, hregSPARC64_O0(),
                           SPARC64RI_Reg(hregSPARC64_G0()));
            vassert(rloc.pri == RLPri_Int);
            vassert(addToSp == 0);
            return;
        default:
            vpanic("iselStmt(sparc64): Ist_Dirty can't handle return value.");
        }
    }
    case Ist_MBE:
        ADD_INSTR(Membar);
        return;
    /* --------- EXIT --------- */
    case Ist_Exit: {
        IRJumpKind jk = stmt->Ist.Exit.jk;
        IRConst *cdst = stmt->Ist.Exit.dst;
        vassert(cdst->tag == Ico_U64);

        SPARC64AMode *amPC = SPARC64AMode_IR(stmt->Ist.Exit.offsIP,
                                             hregSPARC64_G5());
        SPARC64CondCode cond = iselCondCode(env, stmt->Ist.Exit.guard);

        /* Boring transfers */
        if (jk == Ijk_Boring) {
            if (env->chainingAllowed) {
                Bool toFastEP = ((Addr64)cdst->Ico.U64) > env->max_ga;
                ADD_INSTR(XDirect, cdst->Ico.U64, amPC, cond, toFastEP);
            } else {
                HReg r = iselExpr_R(env, IRExpr_Const(cdst));
                ADD_INSTR(XAssisted, r, amPC, cond, Ijk_Boring);
            }
            return;
        }

        /* Assisted transfers. Keep in sync with iselNext! */
        switch (jk) {
        case Ijk_ClientReq:
        case Ijk_EmFail:
        case Ijk_EmWarn:
        case Ijk_InvalICache:
        case Ijk_NoDecode:
        case Ijk_NoRedir:
        case Ijk_SigBUS:
        case Ijk_SigILL:
        case Ijk_SigTRAP:
        case Ijk_SigFPE_IntDiv:
        case Ijk_SigFPE_IntOvf:
        case Ijk_Sys_syscall:  /* normal syscall (ta 0x40 or ta 0x6d) */
        case Ijk_Sys_syscall110: /* Linux getcontext (ta 0x6e) syscall. */
        case Ijk_Sys_syscall111: /* Linux setcontext (ta 0x6f) syscall. */
        case Ijk_Sys_fasttrap: /* fast trap */
        case Ijk_Yield: {
            HReg r = iselExpr_R(env, IRExpr_Const(cdst));
            ADD_INSTR(XAssisted, r, amPC, cond, jk);
            return;
        }
        default:
            break;
        }

        vpanic("iselStmt(sparc64): Unsupported exit statement.");
        break;
    }

    /* --------- UNRECOGNIZED INSTRUCTION --------- */
    case Ist_Unrecognized:
        /* load all registers from guest state */
        ADD_INSTR(LoadGuestState);

        /* add an unrecognized instruction */
        ADD_INSTR(Unrecognized, stmt->Ist.Unrecognized.instr_bits);

        /* store all registers back to the guest state */
        ADD_INSTR(StoreGuestState);
        break;

    default:
        vpanic("iselStmt(sparc64): Unsupported statement.");
    }
}

/*----------------------------------------------------------------------------*/
/*--- ISEL: Basic block terminators (Nexts)                                ---*/
/*----------------------------------------------------------------------------*/

static void
iselNext(ISelEnv *env, IRExpr *next, IRJumpKind jk, Int offsIP)
{
    SPARC64AMode *amPC;
    HReg r;

    if (vex_traceflags & VEX_TRACE_VCODE) {
        vex_printf("\n-- PUT(%d) = ", offsIP);
        ppIRExpr(next);
        vex_printf("; exit-");
        ppIRJumpKind(jk);
        vex_printf("\n");
    }

    amPC = SPARC64AMode_IR(offsIP, hregSPARC64_PC());

    /* Boring transfer to known address. */
    if (next->tag == Iex_Const) {
        IRConst *cdst = next->Iex.Const.con;
        vassert(cdst->tag == Ico_U64);
        if ((jk == Ijk_Boring) || (jk == Ijk_Call)) {
            if (env->chainingAllowed) {
                /* .. almost always true .. */
                Bool toFastEP = ((Addr64) cdst->Ico.U64) > env->max_ga;
                ADD_INSTR(XDirect, cdst->Ico.U64, amPC, Scc_A, toFastEP);
            } else {
                /* .. very occasionally .. */
                r = iselExpr_R(env, next);
                ADD_INSTR(XAssisted, r, amPC, Scc_A, Ijk_Boring);
            }
            return;
        }
    }

    switch (jk) {
    /* Case: call/return (==boring) transfer to any address */
    case Ijk_Boring:
    case Ijk_Ret:
    case Ijk_Call:
        r = iselExpr_R(env, next);

        if (env->chainingAllowed) {
            ADD_INSTR(XIndir, r, amPC, Scc_A);
        } else {
            ADD_INSTR(XAssisted, r, amPC, Scc_A, Ijk_Boring);
        }
        break;
    /* Case: assisted transfer to arbitrary address.
       Keep in sync with iselStmt! */
    case Ijk_ClientReq:
    case Ijk_EmFail:
    case Ijk_EmWarn:
    case Ijk_InvalICache:
    case Ijk_NoDecode:
    case Ijk_NoRedir:
    case Ijk_SigBUS:
    case Ijk_SigILL:
    case Ijk_SigTRAP:
    case Ijk_SigFPE_IntDiv:
    case Ijk_SigFPE_IntOvf:
    case Ijk_Sys_syscall:  /* normal syscall (ta 0x40 or ta 0x6d) */
    case Ijk_Sys_syscall110: /* Linux getcontext (ta 0x6e) syscall. */
    case Ijk_Sys_syscall111: /* Linux setcontext (ta 0x6f) syscall. */
    case Ijk_Sys_fasttrap: /* fast trap */
    case Ijk_Yield:
        r = iselExpr_R(env, next);
        ADD_INSTR(XAssisted, r, amPC, Scc_A, jk);
        break;
    default:
        vex_printf("\n-- PUT(%d) = ", offsIP);
        ppIRExpr(next);
        vex_printf("; exit-");
        ppIRJumpKind(jk);
        vex_printf("\n");
        vassert(0);
        break;
    }
}

/*----------------------------------------------------------------------------*/
/*--- Top level instruction selector                                       ---*/
/*----------------------------------------------------------------------------*/

HInstrArray *
iselSB_SPARC64(const IRSB *bb,
               VexArch arch_host,
               const VexArchInfo *archinfo_host,
               const VexAbiInfo *vbi,
               Int offs_Host_EvC_Counter,
               Int offs_Host_EvC_FailAddr,
               Bool chainingAllowed,
               Bool addProfInc,
               Addr max_ga)
{
    /* Sanity checks */
    /* TODO-SPARC: Finish this. */
    vassert(arch_host == VexArchSPARC64);
    vassert(archinfo_host->endness == VexEndnessBE);

    /* Setup initial environment to use. */
    ISelEnv *env = LibVEX_Alloc_inline(sizeof(ISelEnv));
    env->vreg_ctr = 0;
    env->code = newHInstrArray();
    env->type_env = bb->tyenv;
    env->n_vregmap = bb->tyenv->types_used;
    env->vregmap = LibVEX_Alloc_inline(env->n_vregmap * sizeof(HReg));
    env->vregmapHI = LibVEX_Alloc_inline(env->n_vregmap * sizeof(HReg));
    env->chainingAllowed = chainingAllowed;
    env->hwcaps = archinfo_host->hwcaps;
    env->max_ga = max_ga;
    env->previous_rd = NULL;

    /* For each IR temporary, allocate a suitably-kinded virtual register. */
    UInt j = 0;
    for (UInt i = 0; i < env->n_vregmap; i++) {
        HReg hreg = INVALID_HREG, hregHI = INVALID_HREG;
        switch (bb->tyenv->types[i]) {
        case Ity_I1:
        case Ity_I8:
        case Ity_I16:
        case Ity_I32:
        case Ity_I64:
            hreg = mkHReg(True, HRcInt64, 0, j++);
            break;
        case Ity_I128:
            hreg   = mkHReg(True, HRcInt64, 0, j++);
            hregHI = mkHReg(True, HRcInt64, 0, j++);
         break;
        case Ity_F32:
            hreg = mkHReg(True, HRcFlt32, 0, j++);
            break;
        case Ity_F64:
            hreg = mkHReg(True, HRcFlt64, 0, j++);
            break;
        case Ity_F128:
            hreg = mkHReg(True, HRcFlt128, 0, j++);
            break;
        default:
            ppIRType(bb->tyenv->types[i]);
            vpanic("iselBB(sparc64): IRTemp type");
        }
        env->vregmap[i]   = hreg;
        env->vregmapHI[i] = hregHI;
    }
    env->vreg_ctr = j;

    /* The very first instruction must be an event check. */
    ADD_INSTR(EvCheck, offsetof(VexGuestSPARC64State, host_EvC_FAILADDR),
                       offsetof(VexGuestSPARC64State, host_EvC_COUNTER));

    /* Possibly a block counter increment (for profiling). At this point we
       don't know the address of the counter, so just pretend it is zero.
       It will have to be patched later, but before this translation is used,
       by a call to LibVEX_patchProfCtr. */
    if (addProfInc)
        ADD_INSTR(ProfInc);

    /* Ok, finally we can iterate over the statements. */
    for (UInt i = 0; i < bb->stmts_used; i++)
        if (bb->stmts[i])
            iselStmt(env, bb->stmts[i]);

    iselNext(env, bb->next, bb->jumpkind, bb->offsIP);

    /* Record the number of vregs we used. */
    env->code->n_vregs = env->vreg_ctr;
    return (env->code);
}

/*----------------------------------------------------------------------------*/
/*--- end                                              host_sparc64_isel.c ---*/
/*----------------------------------------------------------------------------*/
