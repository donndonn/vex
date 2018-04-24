/*----------------------------------------------------------------------------*/
/*--- begin                                            host_sparc64_defs.c ---*/
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
#include "libvex.h"
#include "libvex_trc_values.h"
#include "libvex_guest_sparc64.h"
#include "libvex_guest_offsets.h"
#include "libvex_sparc64_common.h"

#include "main_util.h"
#include "main_globals.h"
#include "host_sparc64_defs.h"
#include "sparc64_disasm.h"


/* --------- Registers. --------- */
/* Due to various ABI restrictions only g1, g4, g5 are available.
   See comments in getRRegUniverse_SPARC64(). */
#define REG_G1  1
#define REG_G2  2
#define REG_G3  3
#define REG_G4  4
#define REG_G5  5
#define REG_G7  7
#define REG_O0  8
#define REG_O6 14
#define REG_O7 15

void
ppHRegSPARC64(HReg reg)
{
    Int r;
    static const HChar *gpr_names[33] = {
        "%g0", "%g1", "%g2", "%g3", "%g4", "%g5", "%g6", "%g7",
        "%o0", "%o1", "%o2", "%o3", "%o4", "%o5", "%o6", "%o7",
        "%l0", "%l1", "%l2", "%l3", "%l4", "%l5", "%l6", "%l7",
        "%i0", "%i1", "%i2", "%i3", "%i4", "%i5", "%i6", "%i7",
        "%pc"
    };

    static const HChar *fpr_names[56] = {
        "%f0", "%f1", "%f2", "%f3", "%f4", "%f5", "%f6", "%f7",
        "%d8",  NULL, "%d10", NULL, "%d12", NULL, "%d14", NULL,
        "%d16", NULL, "%d18", NULL, "%d20", NULL, "%d22", NULL,
        "%q24", NULL,   NULL, NULL, "%q28", NULL,   NULL, NULL,
        "%q32", NULL,   NULL, NULL, "%q36", NULL,   NULL, NULL,
        "%q40", NULL,   NULL, NULL, "%q44", NULL,   NULL, NULL,
        "%q48", NULL,   NULL, NULL, "%q52", NULL,   NULL, NULL
    };

    if (hregIsVirtual(reg)) {
        ppHReg(reg);
        return;
    }

    switch (hregClass(reg)) {
    case HRcInt64:
        r = hregEncoding(reg);
        vassert(r >= 0 && r < 32);
        vex_printf("%s", gpr_names[r]);
        break;
    case HRcFlt32:
    case HRcFlt64:
    case HRcFlt128:
        r = hregEncoding(reg);
        vassert(r >= 0 && r <= 52);
        vassert(fpr_names[r] != NULL);
        vex_printf("%s", fpr_names[r]);
        break;
    default:
        vpanic("ppHRegSPARC64 wrong register class.\n");
    }
}

const RRegUniverse *
getRRegUniverse_SPARC64(void)
{
    /* The real-register universe is a big constant, so we just want to
       initialise it once. */
    static RRegUniverse rRegUniverse_SPARC64;
    static Bool         rRegUniverse_SPARC64_initted = False;

    /* Handy shorthand, nothing more */
    RRegUniverse *ru = &rRegUniverse_SPARC64;

    /* This isn't thread-safe. Sigh. */
    if (LIKELY(rRegUniverse_SPARC64_initted))
        return ru;

    RRegUniverse__init(ru);

    /* Add the registers. The initial segment of this array must be
       those available for allocation by reg-alloc, and those that
       follow are not available for allocation. */
    /* Non-volatile (callee saved) regs first. */
    ru->regs[ru->size++] = hregSPARC64_L0();
    ru->regs[ru->size++] = hregSPARC64_L1();
    ru->regs[ru->size++] = hregSPARC64_L2();
    ru->regs[ru->size++] = hregSPARC64_L3();
    ru->regs[ru->size++] = hregSPARC64_L4();
    ru->regs[ru->size++] = hregSPARC64_L5();
    ru->regs[ru->size++] = hregSPARC64_L6();
    ru->regs[ru->size++] = hregSPARC64_L7();

    ru->regs[ru->size++] = hregSPARC64_I0();
    ru->regs[ru->size++] = hregSPARC64_I1();
    ru->regs[ru->size++] = hregSPARC64_I2();
    ru->regs[ru->size++] = hregSPARC64_I3();
    ru->regs[ru->size++] = hregSPARC64_I4();
    ru->regs[ru->size++] = hregSPARC64_I5();

    /* Volatile registers in case we need them. */
    ru->regs[ru->size++] = hregSPARC64_O0();
    ru->regs[ru->size++] = hregSPARC64_O1();
    ru->regs[ru->size++] = hregSPARC64_O2();
    ru->regs[ru->size++] = hregSPARC64_O3();
    ru->regs[ru->size++] = hregSPARC64_O4();
    ru->regs[ru->size++] = hregSPARC64_O5();

    /* 32-bit/64-bit/128-bit float registers. */
    ru->regs[ru->size++] = hregSPARC64_F0();
    ru->regs[ru->size++] = hregSPARC64_F1();
    ru->regs[ru->size++] = hregSPARC64_F2();
    ru->regs[ru->size++] = hregSPARC64_F3();
    ru->regs[ru->size++] = hregSPARC64_F4();
    ru->regs[ru->size++] = hregSPARC64_F5();
    ru->regs[ru->size++] = hregSPARC64_F6();
    ru->regs[ru->size++] = hregSPARC64_F7();
    ru->regs[ru->size++] = hregSPARC64_D8();
    ru->regs[ru->size++] = hregSPARC64_D10();
    ru->regs[ru->size++] = hregSPARC64_D12();
    ru->regs[ru->size++] = hregSPARC64_D14();
    ru->regs[ru->size++] = hregSPARC64_D16();
    ru->regs[ru->size++] = hregSPARC64_D18();
    ru->regs[ru->size++] = hregSPARC64_D20();
    ru->regs[ru->size++] = hregSPARC64_D22();
    ru->regs[ru->size++] = hregSPARC64_Q24();
    ru->regs[ru->size++] = hregSPARC64_Q28();
    ru->regs[ru->size++] = hregSPARC64_Q32();
    ru->regs[ru->size++] = hregSPARC64_Q36();
    ru->regs[ru->size++] = hregSPARC64_Q40();
    ru->regs[ru->size++] = hregSPARC64_Q44();
    ru->regs[ru->size++] = hregSPARC64_Q48();
    ru->regs[ru->size++] = hregSPARC64_Q52();

    ru->allocable = ru->size;

    /* From "SPARC Assembly Language Reference Manual":
       Global registers %g6 and %g7 are always reserved for the operating
       system (%g6 for kernel, %g7 for libc).

       Global registers %g1-%g5 are caller saves, and are usable by applications
       code. But note that %g1 and %g5 may be used in the program
       linkage table (PLT) or other interposition code, and thus cannot be used
       to pass parameters from caller to callee.

       Also note that all modules using %g2 and %g3 must declare its type
       consistently (-mapp-regs or #scratch). See also comment
       in dispatch-sparc64-solaris.S.

       TODO-SPARC: For now, global registers are not allocatable. This may
       change in future when Sin_Call is sufficiently annotated. */

    /* Reserve at least two non-allocatable registers for loading immediate
       values. See mkLoadImmWord(). */
    ru->regs[ru->size++] = hregSPARC64_G0(); /* hw zero */
    ru->regs[ru->size++] = hregSPARC64_G1(); /* temporary for imm loading */
    ru->regs[ru->size++] = hregSPARC64_G2(); /* allocatable */
    ru->regs[ru->size++] = hregSPARC64_G3(); /* allocatable */
    ru->regs[ru->size++] = hregSPARC64_G4(); /* temporary for imm loading */
    ru->regs[ru->size++] = hregSPARC64_G5(); /* guest state pointer */
    ru->regs[ru->size++] = hregSPARC64_G6(); /* reserved for OS */
    ru->regs[ru->size++] = hregSPARC64_G7(); /* reserved for OS */
    ru->regs[ru->size++] = hregSPARC64_O6(); /* %sp */
    ru->regs[ru->size++] = hregSPARC64_O7(); /* calee return */
    ru->regs[ru->size++] = hregSPARC64_I6(); /* %fp */
    ru->regs[ru->size++] = hregSPARC64_I7(); /* return addr */
    ru->regs[ru->size++] = hregSPARC64_PC();

    rRegUniverse_SPARC64_initted = True;

    RRegUniverse__check_is_sane(ru);
    return (ru);
}

inline static UInt
iregNo(HReg reg)
{
    UInt n;

    vassert(hregClass(reg) == HRcInt64);
    vassert(!hregIsVirtual(reg));
    n = hregEncoding(reg);
    vassert(n <= 32);

    return (n);
}

static UInt
fregNo(HReg reg, Bool encode)
{
    UInt n;

    HRegClass hrc = hregClass(reg);
    vassert(hrc == HRcFlt32 || hrc == HRcFlt64 || hrc == HRcFlt128);
    vassert(!hregIsVirtual(reg));
    n = hregEncoding(reg);

    /* Perform 5-bit encoding when asked to. */
    if (encode) {
        UInt b5 = n & 0x20;
        if (b5) {
          n &= ~(0x20);
          n |= 1;
        }
    }

    return (n);
}

/*
 * Simple version of mkLoadImm that operates on word size immediates. The
 * function uses two registers to assemble the final value.
 * These two registers are not available to the register allocator.
 * See getRRegUniverse_SPARC64().
 */
static UInt *
mkLoadImmWord(UInt *p, UInt r_tmp, UInt r_dst, ULong imm)
{
    ULong hi_imm, lo_imm, tmp;
    UInt insn = 0;

    /* Load immediate upper 32bits. */
    tmp = imm >> 32;
    hi_imm = tmp >> 10;
    lo_imm = tmp & 0x3FF;

    /* sethi %hi(imm_up), %tmp */
    insn |= (r_tmp & 0x1F) << 25;
    insn |= 0x4 << 22;
    insn |= hi_imm;
    *p++ = insn;

    /* or %tmp, %hi(imm_up), %tmp */
    insn = 0x80102000;
    insn |= (r_tmp & 0x1F) << 25;
    insn |= (r_tmp & 0x1F) << 14;
    insn |= lo_imm;
    *p++ = insn;

    /* Load immediate lower 32bits. */
    tmp = imm & 0xFFFFFFFF;
    hi_imm = tmp >> 10;
    lo_imm = tmp & 0x3FF;

    /* sethi %hi(imm_lo), %dst */
    insn = 0;
    insn |= (r_dst & 0x1F) << 25;
    insn |= 0x4 << 22;
    insn |= hi_imm;
    *p++ = insn;

    /* or %dst, %hi(imm_lo), %dst */
    insn = 0x80102000;
    insn |= (r_dst & 0x1F) << 25;
    insn |= (r_dst & 0x1F) << 14;
    insn |= lo_imm;
    *p++ = insn;

    /* sll %tmp, 32, %tmp */
    insn = 0x81283000;
    insn |= (r_tmp & 0x1F) << 25;
    insn |= (r_tmp & 0x1F) << 14;
    insn |= 32;
    *p++ = insn;

    /* or %tmp, %dst, %dst */
    insn = 0x80100000;
    insn |= (r_dst & 0x1F) << 25;
    insn |= (r_tmp & 0x1F) << 14;
    insn |= (r_dst & 0x1F);
    *p++ = insn;

    return (p);
}

/* TODO-SPARC: Make this more clever.
   We can use for example sign extending to load some immediates
   which could help with loading pointers starting with 0xfffff......
   See for example sparc_emit_set_const64() in gcc/config/sparc/sparc.c. */
static UInt *
mkLoadImm(UInt *p, UInt r_dst, ULong imm)
{
    ULong hi_imm, lo_imm;
    UInt insn = 0;

    /* For 64-bit loads use existing code. */
    if (imm >> 32 > 0)
        return (mkLoadImmWord(p, REG_G1, r_dst, imm));

    /* 32-bit load */
    if (imm > 0xfff) {
        hi_imm = imm >> 10;
        lo_imm = imm & 0x3FF;

        insn |= (r_dst & 0x1F) << 25;
        insn |= 0x4 << 22;
        insn |= hi_imm;

        *p++ = insn;

        insn = 0x80102000;
        insn |= (r_dst & 0x1F) << 25;
        insn |= (r_dst & 0x1F) << 14;
        insn |= lo_imm;

        *p++ = insn;
        return (p);
    }

    /* Generate 'or' and put constant in its immediate field.
       Works for 12bit immediates only otherwise we would sign extend
       small constants and break stuff. */
    insn = 0x80102000;
    insn |= (r_dst & 0x1F) << 25;
    insn |= imm & 0xfff;
    *p++ = insn;

    return (p);
}

static UInt *
mkASR(UInt *p, const SPARC64Instr *i)
{
    UInt insn;
    SPARC64RI *ri = i->Sin.ASR.srcR;

    if (i->Sin.ASR.store) {
        insn = 0x81800000;
        insn |= (i->Sin.ASR.dst & 0x1f) << 25;
        insn |= (iregNo(i->Sin.ASR.srcL) & 0x1f) << 14;

        if (ri->tag == Sri_Imm) {
            insn |= (1 << 13);
            insn |= (ri->Sri.Imm.simm13 & SPARC64_SIMM13_MASK);
        } else {
            insn |= (iregNo(ri->Sri.Reg.reg) & 0x1F);
        }
    } else {
        insn = 0x8140C000;
        insn |= (iregNo(i->Sin.ASR.srcL) & 0x1f) << 25;
        insn |= (i->Sin.ASR.dst & 0x1f) << 14;
    }

    *p++ = insn;
    return (p);
}

static UInt *
mkStoreLoad(UInt *p, const SPARC64Instr *i)
{
    UInt insn = 0;
    UChar sz;
    HReg r_dst;
    UInt rn_dst;
    SPARC64AMode *am;
    SPARC64RI *ri_asi = NULL;
    Bool isFsr = False;

    vassert((i->tag == Sin_Store) || (i->tag == Sin_Load));

    static struct {
        SPARC64InstrTag tag;
        UChar sz;
        HRegClass hrc;
        Bool isFsr;
        UInt insn;
    } vals[] = {
        /* Normal loads/stores */
        { Sin_Store,  1, HRcInt64,   False, 0xC0280000 },
        { Sin_Store,  2, HRcInt64,   False, 0xC0300000 },
        { Sin_Store,  4, HRcInt64,   False, 0xC0200000 },
        { Sin_Store,  8, HRcInt64,   False, 0xC0700000 },
        { Sin_Store,  4, HRcFlt32,   False, 0xC1200000 },
        { Sin_Store,  8, HRcFlt64,   False, 0xC1380000 },
        { Sin_Store, 16, HRcFlt128,  False, 0xC1300000 },
        { Sin_Load,   1, HRcInt64,   False, 0xC0080000 },
        { Sin_Load,   2, HRcInt64,   False, 0xC0100000 },
        { Sin_Load,   4, HRcInt64,   False, 0xC0000000 },
        { Sin_Load,   8, HRcInt64,   False, 0xC0580000 },
        { Sin_Load,   4, HRcFlt32,   False, 0xC1000000 },
        { Sin_Load,   8, HRcFlt64,   False, 0xC1180000 },
        { Sin_Load,  16, HRcFlt128,  False, 0xC1100000 },
        /* ASI loads/stores */
        { Sin_Store,  1, HRcInt64,   False, 0xC0A80000 },
        { Sin_Store,  2, HRcInt64,   False, 0xC0B00000 },
        { Sin_Store,  4, HRcInt64,   False, 0xC0A00000 },
        { Sin_Store,  8, HRcInt64,   False, 0xC0F00000 },
        { Sin_Load,   1, HRcInt64,   False, 0xC0880000 },
        { Sin_Load,   2, HRcInt64,   False, 0xC0900000 },
        { Sin_Load,   4, HRcInt64,   False, 0xC0800000 },
        { Sin_Load,   8, HRcInt64,   False, 0xC0D80000 },
        /* FSR loads/stores */
        { Sin_Store,  8, HRcINVALID, True,  0xC1280000 },
        { Sin_Load,   8, HRcINVALID, True,  0xC1080000 }
    };

    if (i->tag == Sin_Store) {
        sz = i->Sin.Store.sz;
        am = i->Sin.Store.dst;
        if (i->Sin.Store.fromFsr) {
            r_dst = INVALID_HREG;
            isFsr = True;
        } else {
            r_dst = i->Sin.Store.src;
            if (i->Sin.Store.asi != NULL) {
                ri_asi = i->Sin.Store.asi;
            }
        }
    } else {
        sz = i->Sin.Load.sz;
        am = i->Sin.Load.src;
        if (i->Sin.Load.toFsr) {
            r_dst = INVALID_HREG;
            isFsr = True;
        } else {
            r_dst = i->Sin.Load.dst;
            if (i->Sin.Load.asi != NULL) {
                ri_asi = i->Sin.Load.asi;
            }
        }
    }

    HRegClass hrc = (isFsr) ? HRcINVALID : hregClass(r_dst);
    UInt j = (isFsr) ? 22 : (ri_asi == NULL) ? 0 : 14;
    for (; j < sizeof(vals)/sizeof(vals[0]); j++) {
        if ((i->tag == vals[j].tag) && (sz == vals[j].sz)
            && (isFsr == vals[j].isFsr) && (hrc == vals[j].hrc)) {
            insn = vals[j].insn;
            break;
        }
    }

    vassert(insn != 0);

    /* Encode destination reg number. */
    if (vals[j].isFsr) {
        rn_dst = 1;
    } else if (vals[j].hrc == HRcInt64) {
        rn_dst = iregNo(r_dst);
    } else {
        rn_dst = fregNo(r_dst, True);
    }

    /* emit load/store */
    if (am->tag == Sam_IR) {
        insn |= (1 << 13);
        insn |= (iregNo(am->Sam.IR.reg) & 0x1F) << 14;
        insn |= (am->Sam.IR.imm & 0x1FFF);

        /* The ASI value can't be encoded into opcode so don't bother about
           it. It is VEX's isel responsibility to setup %asi register for us. */
    } else {
        insn |= (iregNo(am->Sam.RR.reg1) & 0x1F) << 14;
        insn |= (iregNo(am->Sam.RR.reg2) & 0x1F);

        /* Encode ASI value directly into opcode. Only ASI value represented
           as immediate constant can be used here. If we ever land here with
           ASI value represented as a register then there is something broken
           at the VEX isel layer. */
        if (ri_asi != NULL) {
            if (ri_asi->tag == Sri_Imm)
                insn |= (ri_asi->Sri.Imm.simm13 & 0xff) << 5;
            else
                vpanic("Can't encode ASI passed via register.");
        }
    }

    insn |= (rn_dst & 0x1F) << 25;

    *p++ = insn;
    return (p);
}

static UInt *
mkAlu(UInt *p, const SPARC64Instr *i)
{
    UInt insn;
    SPARC64RI *ri = i->Sin.Alu.srcR;

    switch (i->Sin.Alu.op) {
    case Salu_ADD:     insn = 0x80000000; break;
    case Salu_SUB:     insn = 0x80200000; break;
    case Salu_SUBcc:   insn = 0x80A00000; break;
    case Salu_AND:     insn = 0x80080000; break;
    case Salu_ANDcc:   insn = 0x80880000; break;
    case Salu_OR:      insn = 0x80100000; break;
    case Salu_ORN:     insn = 0x80B00000; break;
    case Salu_XOR:     insn = 0x80180000; break;
    case Salu_XNOR:    insn = 0x80380000; break;
    case Salu_MULX:    insn = 0x80480000; break;
    case Salu_SMUL:    insn = 0x80580000; break;
    case Salu_UMUL:    insn = 0x80500000; break;
    case Salu_UMULXHI: insn = 0x81B002C0; vassert(ri->tag == Sri_Reg); break;
    case Salu_UDIVX:   insn = 0x80680000; break;
    case Salu_SDIVX:   insn = 0x81680000; break;
    case Salu_SDIV:    insn = 0x80780000; break;
    case Salu_UDIV:    insn = 0x80700000; break;
    default:
        vassert(0);
    }

    if (ri->tag == Sri_Imm) {
        insn |= (1 << 13);
        insn |= (ri->Sri.Imm.simm13 & SPARC64_SIMM13_MASK);
    } else {
        insn |= (iregNo(ri->Sri.Reg.reg) & 0x1F);
    }

    insn |= (iregNo(i->Sin.Alu.srcL) & 0x1F) << 14;
    insn |= (iregNo(i->Sin.Alu.dst) & 0x1F) << 25;

    *p++ = insn;
    return (p);
}

static UInt *
mkShft(UInt *p, const SPARC64Instr *i)
{
    UInt insn = 0, j;
    SPARC64RI *ri = i->Sin.Shft.srcR;

    struct {
        SPARC64ShftOp op;
        UInt insn;
    } vals[] = {
        { Sshft_SLL,  0x81280000 },
        { Sshft_SRL,  0x81300000 },
        { Sshft_SRA,  0x81380000 },
        { Sshft_SLLX, 0x81281000 },
        { Sshft_SRLX, 0x81301000 },
        { Sshft_SRAX, 0x81381000 }
    };

    for (j = 0; j < sizeof(vals)/sizeof(vals[0]); j++)
        if (i->Sin.Shft.op == vals[j].op) {
            insn = vals[j].insn;
            break;
        }

    vassert(insn != 0);

    if (ri->tag == Sri_Imm) {
        insn |= (1 << 13);
        if (insn & (1 << 12)) {
            insn |= (ri->Sri.Imm.simm13 & 0x3F);
        }
        else {
            insn |= (ri->Sri.Imm.simm13 & 0x1F);
        }
    } else {
        insn |= (iregNo(ri->Sri.Reg.reg) & 0x1F);
    }

    insn |= (iregNo(i->Sin.Alu.srcL) & 0x1F) << 14;
    insn |= (iregNo(i->Sin.Alu.dst) & 0x1F) << 25;
    *p++ = insn;
    return (p);
}

/* HW encoding of SPARC64CondCode. This array must be kept in sync with
   SPARC64CondCode enum values and ordering. */
static UInt cond_codes[] = {
    0x8,   /* Scc_A */
    0x0,   /* Scc_N */
    0x9,   /* Scc_NE */
    0x1,   /* Scc_E */
    0xA,   /* Scc_G */
    0x2,   /* Scc_LE */
    0xB,   /* Scc_GE */
    0x3,   /* Scc_L */
    0xC,   /* Scc_GU */
    0x4,   /* Scc_LEU */
    0xD,   /* Scc_CC */
    0x5,   /* Scc_CS */
    0xE,   /* Scc_POS */
    0x6,   /* Scc_NEG */
    0xF,   /* Scc_VC */
    0x7,   /* Scc_VS */
};

static UInt *
mkMoveCond(UInt *p, const SPARC64Instr *i)
{
    UInt insn = 0x81641000;
    insn |= (iregNo(i->Sin.MoveCond.dst) & 0x1F) << 25;
    insn |= cond_codes[i->Sin.MoveCond.cond] << 14;
    insn |= (iregNo(i->Sin.MoveCond.src) & 0x1F);

    *p++ = insn;
    return (p);
}

static UInt *
mkMoveReg(UInt *p, const SPARC64Instr *i)
{
    UInt insn = 0x81780000;
    insn |= (iregNo(i->Sin.MoveReg.dst) & 0x1F) << 25;
    insn |= i->Sin.MoveReg.cond << 10;
    insn |= (iregNo(i->Sin.MoveReg.srcL) & 0x1F) << 14;

    SPARC64RI *ri = i->Sin.MoveReg.srcR;
    if (ri->tag == Sri_Imm) {
        insn |= (1 << 13);
        insn |= (ri->Sri.Imm.simm13 & SPARC64_SIMM10_MASK);
    } else {
        insn |= (iregNo(ri->Sri.Reg.reg) & 0x1F);
    }

    *p++ = insn;
    return (p);
}

static UInt *
mkCall(UInt *p, const SPARC64Instr *i)
{
    UInt insn = 0;
    UInt *ptmp;

    /* Simple case where the call always happens or does not return a value. */
    if ((i->Sin.Call.cond == Scc_A) || (i->Sin.Call.rloc.pri == RLPri_None)) {
        /* When condition is not A, generate jump over the call. Whether the
           jump is taken or not depends on negated condition. */
        if (i->Sin.Call.cond != Scc_A) {
            ptmp = p;
            p += 2;
        }

        /* jmpl %g4, %o7 */
        *p++ = 0x9FC10000;
        /* nop */
        *p++ = 0x1000000;
        /* Restore guest state that may have been trashed. */
        /* ldx [%fp + SPARC64_STACK_BIAS - 16], %g5 */
        *p++ = 0xCA5FA7EF;

        if (i->Sin.Call.cond != Scc_A) {
            Int delta = p - ptmp;
            insn = 0x600000; /* b<!cond>,pn %xcc, delta */
            insn |= cond_codes[1 ^ i->Sin.Call.cond] << 25;
            insn |= delta;
            *ptmp++ = insn;

            /* nop */
            *ptmp++ = 0x1000000; /* nop */
        }
    } else {
        /* The complex case where a conditional call returns a value needs to
           store 0x55...55 into return register in case the call does not
           happen. */
        vpanic("Conditional call returning a value is unsupported.");
    }

    return (p);
}

static UInt *
mkStoreLoadWord(UInt *p, Bool isStore, UInt r_src, SPARC64AMode *am)
{
    UInt insn = (isStore) ? 0xC0700000 : 0xC0580000;

    if (am->tag == Sam_IR) {
       insn |= (1 << 13);
       insn |= (iregNo(am->Sam.IR.reg) & 0x1F) << 14;
       insn |= (am->Sam.IR.imm & 0x1FFF);
       vassert(am->Sam.IR.imm <= 0x1FFF);
    } else {
       insn |= (iregNo(am->Sam.RR.reg1) & 0x1F) << 14;
       insn |= (iregNo(am->Sam.RR.reg2) & 0x1F);
    }

    insn |= (r_src & 0x1F) << 25;
    *p++ = insn;

    return (p);
}

static UInt *
mkLdstub(UInt *p, const SPARC64Instr *i)
{
    SPARC64AMode *src = i->Sin.Ldstub.src;
    UInt insn = 0xC0680000;

    if (src->tag == Sam_IR) {
       insn |= (1 << 13);
       insn |= (iregNo(src->Sam.IR.reg) & 0x1F) << 14;
       insn |= (src->Sam.IR.imm & 0x1FFF);
       vassert(src->Sam.IR.imm <= 0x1FFF);
    } else {
       insn |= (iregNo(src->Sam.RR.reg1) & 0x1F) << 14;
       insn |= (iregNo(src->Sam.RR.reg2) & 0x1F);
    }

    insn |= (iregNo(i->Sin.Ldstub.dst) & 0x1F) << 25;
    *p++ = insn;

    return (p);
}

static UInt *
mkCas(UInt *p, const SPARC64Instr *i)
{
    vassert((i->Sin.CAS.sz == 4) || (i->Sin.CAS.sz == 8));
    UInt insn = (i->Sin.CAS.sz == 4) ? 0xC1E00000 : 0xC1F00000;

    insn |= (iregNo(i->Sin.CAS.addr) & 0x1F) << 14;
    insn |= (iregNo(i->Sin.CAS.src) & 0x1F);
    insn |= (iregNo(i->Sin.CAS.dst) & 0x1F) << 25;
    insn |= (SPARC64_ASI_PRIMARY & 0xFF) << 5;
    *p++ = insn;

    return (p);
}

static UInt *
mkLzcnt(UInt *p, const SPARC64Instr *i)
{
    UInt insn = 0x81B002E0;

    insn |= (iregNo(i->Sin.Lzcnt.src) & 0x1F);
    insn |= (iregNo(i->Sin.Lzcnt.dst) & 0x1F) << 25;
    *p++ = insn;

    return (p);
}

static UInt *
mkMembar(UInt *p, const SPARC64Instr *i)
{
    UInt insn = 0x8143E000;
    UInt cmask = 1 << 5; /* membar #Sync */

    insn |= cmask;
    *p++ = insn;

    return (p);
}

static UInt *
mkXDirectIndirect(UInt *p, const SPARC64Instr *i, const void *target_pc)
{
    UInt insn = 0;
    UInt *ptmp = NULL;
    SPARC64CondCode cond;
    SPARC64AMode *amPC;

    switch (i->tag) {
    case Sin_XDirect:
        cond = i->Sin.XDirect.cond;
        amPC = i->Sin.XDirect.amPC;
        break;
    case Sin_XIndir:
        cond = i->Sin.XIndir.cond;
        amPC = i->Sin.XIndir.amPC;
        break;
    default:
        vpanic("Not an XDirect/XIndir instruction");
    }

    /* Condition N never emits any instructions. */
    if (cond == Scc_N)
        return (p);

    /* Reserve space for condition code. */
    if (cond != Scc_A) {
        ptmp = p;
        p += 2;
    }

    /*
     * Update guest's PC:
     *  (xDirect) load immediate value and store it in guest->PC.
     *  (xIndir) store value from provided reg to guest->PC.
     */
    if (i->tag == Sin_XDirect) {
        p = mkLoadImmWord(p, REG_G1, REG_G4, i->Sin.XDirect.dstGA);
        p = mkStoreLoadWord(p, True, REG_G4, amPC);
    } else {
        p = mkStoreLoadWord(p, True, iregNo(i->Sin.XIndir.dstGA), amPC);
    }

    p = mkLoadImmWord(p, REG_G1, REG_G4, (Addr64)target_pc);
    *p++ = 0x9FC10000; /* jmpl %g4, %o7 */
    *p++ = 0x01000000; /* nop */

    /* Backpatch condition code. */
    if (cond != Scc_A) {
        UInt delta = p - ptmp;
        insn = 0x600000; /* b<!cond>,pn %xcc, delta */
        insn |= cond_codes[1 ^ cond] << 25;
        insn |= delta;
        *ptmp++ = insn;
        *ptmp++ = 0x01000000; /* nop */
    }

    return (p);
}

static UInt *
mkAlignDataFp(UInt *p, const SPARC64Instr *i)
{
    UInt insn = 0x81B00920;

    vassert(hregClass(i->Sin.AlignDataFp.dst) == HRcFlt64);
    vassert(hregClass(i->Sin.AlignDataFp.srcL) == HRcInt64);
    vassert(hregClass(i->Sin.AlignDataFp.srcR) == HRcFlt64);

    insn |= (fregNo(i->Sin.AlignDataFp.dst, True) & 0x1f) << 25;
    insn |= (iregNo(i->Sin.AlignDataFp.srcL) & 0x1f) << 14;
    insn |= (fregNo(i->Sin.AlignDataFp.srcR, True) & 0x1f);

    *p++ = insn;
    return (p);
}

static UInt *
mkAluFp(UInt *p, const SPARC64Instr *i)
{
    HRegClass hrc_src = hregClass(i->Sin.AluFp.srcL);
    HRegClass hrc_dst = hregClass(i->Sin.AluFp.dst);
    if (i->Sin.AluFp.op != AluFp_FNOT) {
        vassert(hrc_src == hregClass(i->Sin.AluFp.srcR));
    }

    UInt insn;
    switch (i->Sin.AluFp.op) {
    case AluFp_FADD:   insn = 0x81A00800; break;
    case AluFp_FAND:   insn = 0x81B00E00; break;
    case AluFp_FDIV:   insn = 0x81A00980; break;
    case AluFp_FMUL:   insn = 0x81A00900; break;
    case AluFp_FsdMUL: insn = 0x81A00D00; break;
    case AluFp_FNOT:   insn = 0x81B00D40; break;
    case AluFp_FOR:    insn = 0x81B00F80; break;
    case AluFp_FSUB:   insn = 0x81A00880; break;
    case AluFp_FXOR:   insn = 0x81B00D80; break;
    default: vassert(0);
    }

    switch (i->Sin.AluFp.op) {
    case AluFp_FADD: case AluFp_FDIV: case AluFp_FMUL: case AluFp_FSUB:
        vassert(hrc_src == hrc_dst);

        switch (hrc_src) {
        case HRcFlt32:
            insn |= 0x20;
            break;
        case HRcFlt64:
            insn |= 0x40;
            break;
        case HRcFlt128:
            insn |= 0x60;
            break;
        default:
            vpanic("Unsupported host register class");
        }
        break;
    case AluFp_FsdMUL:
        switch (hrc_src) {
        case HRcFlt32:
            vassert(hrc_dst == HRcFlt64);
            insn |= 0x20;
            break;
        case HRcFlt64:
            vassert(hrc_dst == HRcFlt128);
            insn |= 0xC0;
            break;
        default:
            vpanic("Unsupported host register class");
        }
        break;
    case AluFp_FAND: case AluFp_FNOT: case AluFp_FOR: case AluFp_FXOR:
        vassert(hrc_src == hrc_dst);

        switch (hrc_src) {
        case HRcFlt32:
            insn |= 0x20;
            break;
        case HRcFlt64:
            break;
        default:
            vpanic("Unsupported host register class");
        }
        break;
    default:
        vassert(0);
    }

    insn |= (fregNo(i->Sin.AluFp.dst, True) & 0x1f) << 25;
    insn |= (fregNo(i->Sin.AluFp.srcL, True) & 0x1f) << 14;
    if (i->Sin.AluFp.op != AluFp_FNOT) {
        insn |= (fregNo(i->Sin.AluFp.srcR, True) & 0x1f);
    }

    *p++ = insn;
    return (p);
}

static UInt *
mkAbsFp(UInt *p, const SPARC64Instr *i)
{
    HRegClass hrc = hregClass(i->Sin.AbsFp.dst);
    UInt insn = 0x81A00100;

    vassert(hrc == hregClass(i->Sin.AbsFp.src));

    switch (hrc) {
    case HRcFlt32:
        insn |= 0x20;
        break;
    case HRcFlt64:
        insn |= 0x40;
        break;
    case HRcFlt128:
        insn |= 0x60;
        break;
    default:
        vpanic("Unsupported host register class");
    }

    insn |= (fregNo(i->Sin.AbsFp.dst, True) & 0x1f) << 25;
    insn |= (fregNo(i->Sin.AbsFp.src, True) & 0x1f);

    *p++ = insn;
    return (p);
}

static UInt *
mkCmpFp(UInt *p, const SPARC64Instr *i)
{
    HReg r_srcL = i->Sin.CmpFp.srcL;
    HReg r_srcR = i->Sin.CmpFp.srcR;

    HRegClass hrc = hregClass(r_srcL);
    vassert(hrc == hregClass(r_srcR));

    UInt insn = 0x81A80A00;
    switch (hrc) {
    case HRcFlt32:
        insn |= 0x20;
        break;
    case HRcFlt64:
        insn |= 0x40;
        break;
    case HRcFlt128:
        insn |= 0x60;
        break;
    default:
        vpanic("Unsupported host register class");
    }

    vassert(i->Sin.CmpFp.fccn < 4);

    insn |= (fregNo(i->Sin.CmpFp.srcL, True) & 0x1f) << 14;
    insn |= (fregNo(i->Sin.CmpFp.srcR, True) & 0x1f);
    insn |= (i->Sin.CmpFp.fccn & 0x3) << 25;

    *p++ = insn;
    return (p);
}

static UInt *
mkConvFp(UInt *p, const SPARC64Instr *i)
{
    UInt insn = 0, j;
    HReg r_dst = i->Sin.ConvFp.dst;
    HReg r_src = i->Sin.ConvFp.src;

    static struct {
        HRegClass hrc_src;
        HRegClass hrc_dst;
        Bool fromInt;
        Bool toInt;
        UInt insn;
    } vals[] = {
        /* int -> float */
        { HRcFlt32,  HRcFlt32,  True,  False, 0x81A01880 },
        { HRcFlt32,  HRcFlt64,  True,  False, 0x81A01900 },
        { HRcFlt32,  HRcFlt128, True,  False, 0x81A01980 },
        { HRcFlt64,  HRcFlt32,  True,  False, 0x81A01080 },
        { HRcFlt64,  HRcFlt64,  True,  False, 0x81A01100 },
        { HRcFlt64,  HRcFlt128, True,  False, 0x81A01180 },
        /* float -> int */
        { HRcFlt32,  HRcFlt32,  False,  True, 0x81A01A20 },
        { HRcFlt32,  HRcFlt64,  False,  True, 0x81A01020 },
        { HRcFlt64,  HRcFlt32,  False,  True, 0x81A01A40 },
        { HRcFlt64,  HRcFlt64,  False,  True, 0x81A01040 },
        { HRcFlt128, HRcFlt32,  False,  True, 0x81A01A60 },
        { HRcFlt128, HRcFlt64,  False,  True, 0x81A01060 },
        /* float -> float */
        { HRcFlt32,  HRcFlt64,  False, False, 0x81A01920 },
        { HRcFlt32,  HRcFlt128, False, False, 0x81A019A0 },
        { HRcFlt64,  HRcFlt32,  False, False, 0x81A018C0 },
        { HRcFlt64,  HRcFlt128, False, False, 0x81A019C0 },
        { HRcFlt128, HRcFlt32,  False, False, 0x81A018E0 },
        { HRcFlt128, HRcFlt64,  False, False, 0x81A01960 }
    };

    for (j = 0; j < sizeof(vals)/sizeof(vals[0]); j++)
        if (i->Sin.ConvFp.fromInt == vals[j].fromInt &&
            i->Sin.ConvFp.toInt == vals[j].toInt &&
            hregClass(r_src) == vals[j].hrc_src &&
            hregClass(r_dst) == vals[j].hrc_dst) {
            insn = vals[j].insn;
            break;
        }

    vassert(insn != 0);

    insn |= (fregNo(r_dst, True) & 0x1f) << 25;
    insn |= fregNo(r_src, True) & 0x1f;

    *p++ = insn;
    return (p);
}

static UInt *
mkFusedFp(UInt *p, const SPARC64Instr *i)
{
    HRegClass hrc_arg1 = hregClass(i->Sin.FusedFp.arg1);
    HRegClass hrc_dst  = hregClass(i->Sin.FusedFp.dst);
    vassert(hrc_arg1 == hrc_dst);
    vassert(hrc_arg1 == hregClass(i->Sin.FusedFp.arg2));
    vassert(hrc_arg1 == hregClass(i->Sin.FusedFp.arg3));

    UInt insn;
    switch (i->Sin.FusedFp.op) {
    case FusedFp_MADD: insn = 0x81B80000; break;
    case FusedFp_MSUB: insn = 0x81B80080; break;
    default: vassert(0);
    }

    switch (hrc_dst) {
    case HRcFlt32:
        insn |= 0x20;
        break;
    case HRcFlt64:
        insn |= 0x40;
        break;
    default:
        vpanic("Unsupported host register class");
    }

    insn |= (fregNo(i->Sin.FusedFp.dst, True) & 0x1f) << 25;
    insn |= (fregNo(i->Sin.FusedFp.arg1, True) & 0x1f) << 14;
    insn |= (fregNo(i->Sin.FusedFp.arg2, True) & 0x1f);
    insn |= (fregNo(i->Sin.FusedFp.arg3, True) & 0x1f) << 9;

    *p++ = insn;
    return (p);
}

static UInt *
mkHalveFp(UInt *p, const SPARC64Instr *i)
{
    UInt insn = 0x81B00F00;
    HRegClass hrc_src = hregClass(i->Sin.HalveFp.src);
    HRegClass hrc_dst = hregClass(i->Sin.HalveFp.dst);

    switch (hrc_src) {
    case HRcFlt128:
        vassert(hrc_dst == HRcFlt64);
        insn |= 0x00;
        break;
    case HRcFlt64:
        vassert(hrc_dst == HRcFlt32);
        insn |= 0x20;
        break;
    default:
        vpanic("Unsupported host register class");
    }

    insn |= (fregNo(i->Sin.HalveFp.dst, True) & 0x1f) << 25;
    insn |= (fregNo(i->Sin.HalveFp.src, True) & 0x1f);

    if (i->Sin.HalveFp.highHalf) {
        switch (hrc_src) {
        case HRcFlt128:
            insn |= 0x04; /* Set b{2} in fp register encoding. */
            break;
        case HRcFlt64:
            insn |= 0x02; /* Set b{1] in fp register encoding. */
            break;
        default:
            vpanic("Unsupported host register class");
        }
    }

    *p++ = insn;
    return (p);
}

static UInt *
mkMovIRegToFp(UInt *p, const SPARC64Instr *i)
{
    UInt insn = 0x81B02300;
    HRegClass hrc = hregClass(i->Sin.MovIRegToFp.dst);
    vassert(hregClass(i->Sin.MovIRegToFp.src) == HRcInt64);

    switch (hrc) {
    case HRcFlt32:
        insn |= 0x20;
        break;
    case HRcFlt64:
        insn |= 0x00;
        break;
    default:
        vpanic("Unsupported host register class");
    }

    insn |= (fregNo(i->Sin.MovIRegToFp.dst, True) & 0x1f) << 25;
    insn |= (iregNo(i->Sin.MovIRegToFp.src) & 0x1f);

    *p++ = insn;
    return (p);
}

static UInt *
mkMovFp(UInt *p, const SPARC64Instr *i)
{
    UInt insn = 0x81A00000;
    HRegClass hrc = hregClass(i->Sin.MovFp.dst);
    vassert(hregClass(i->Sin.MovFp.dst) == hregClass(i->Sin.MovFp.src));

    switch (hrc) {
    case HRcFlt32:
        insn |= 0x20;
        break;
    case HRcFlt64:
        insn |= 0x40;
        break;
    case HRcFlt128:
        insn |= 0x60;
        break;
    default:
        vpanic("Unsupported host register class");
    }

    insn |= (fregNo(i->Sin.MovFp.dst, True) & 0x1f) << 25;
    insn |= (fregNo(i->Sin.MovFp.src, True) & 0x1f);

    *p++ = insn;
    return (p);
}

static UInt *
mkMovFpICond(UInt *p, const SPARC64Instr *i)
{
    UInt insn = 0x81A83000;
    HRegClass hrc = hregClass(i->Sin.MovFpICond.dst);
    vassert(hrc == hregClass(i->Sin.MovFpICond.src));

    switch (hrc) {
    case HRcFlt32:
        insn |= 0x20;
        break;
    case HRcFlt64:
        insn |= 0x40;
        break;
    case HRcFlt128:
        insn |= 0x60;
        break;
    default:
        vpanic("Unsupported host register class");
    }

    insn |= (fregNo(i->Sin.MovFpICond.dst, True) & 0x1f) << 25;
    insn |= cond_codes[i->Sin.MovFpICond.cond] << 14;
    insn |= (fregNo(i->Sin.MovFpICond.src, True) & 0x1F);

    *p++ = insn;
    return (p);
}

static UInt *
mkMovFpToIReg(UInt *p, const SPARC64Instr *i)
{
    UInt insn = 0x81B02200;
    HRegClass hrc = hregClass(i->Sin.MovFpToIReg.src);
    vassert(hregClass(i->Sin.MovFpToIReg.dst) == HRcInt64);

    switch (hrc) {
    case HRcFlt32:
        insn |= 0x20;
        break;
    case HRcFlt64:
        insn |= 0x00;
        break;
    default:
        vpanic("Unsupported host register class");
    }

    insn |= (iregNo(i->Sin.MovFpToIReg.dst) & 0x1f) << 25;
    insn |= (fregNo(i->Sin.MovFpToIReg.src, True) & 0x1f);

    *p++ = insn;
    return (p);
}

static UInt *
mkNegFp(UInt *p, const SPARC64Instr *i)
{
    UInt insn = 0x81A00080;
    HRegClass hrc = hregClass(i->Sin.NegFp.dst);
    vassert(hregClass(i->Sin.NegFp.dst) == hregClass(i->Sin.NegFp.src));

    switch (hrc) {
    case HRcFlt32:
        insn |= 0x20;
        break;
    case HRcFlt64:
        insn |= 0x40;
        break;
    case HRcFlt128:
        insn |= 0x60;
        break;
    default:
        vpanic("Unsupported host register class");
    }

    insn |= (fregNo(i->Sin.NegFp.dst, True) & 0x1f) << 25;
    insn |= (fregNo(i->Sin.NegFp.src, True) & 0x1f);

    *p++ = insn;
    return (p);
}

static UInt *
mkShftFp(UInt *p, const SPARC64Instr *i)
{
    UInt insn;
    switch (i->Sin.ShftFp.op) {
    case ShftFp_SLL16:  insn = 0x81B00420; break;
    case ShftFp_SRL16:  insn = 0x81B00460; break;
    case ShftFp_SLL32:  insn = 0x81B004A0; break;
    case ShftFp_SRL32:  insn = 0x81B004E0; break;
    case ShftFp_SLAS16: insn = 0x81B00520; break;
    case ShftFp_SRA16:  insn = 0x81B00560; break;
    case ShftFp_SLAS32: insn = 0x81B005A0; break;
    case ShftFp_SRA32:  insn = 0x81B005E0; break;
    default: vassert(0);
    }

    vassert(hregClass(i->Sin.ShftFp.dst) == HRcFlt64);
    vassert(hregClass(i->Sin.ShftFp.srcL) == HRcFlt64);
    vassert(hregClass(i->Sin.ShftFp.srcR) == HRcFlt64);

    insn |= (fregNo(i->Sin.ShftFp.dst, True) & 0x1f) << 25;
    insn |= (fregNo(i->Sin.ShftFp.srcL, True) & 0x1f) << 14;
    insn |= (fregNo(i->Sin.ShftFp.srcR, True) & 0x1f);

    *p++ = insn;
    return (p);
}

static UInt *
mkShuffleFp(UInt *p, const SPARC64Instr *i)
{
    UInt insn = 0x81B00980;

    vassert(hregClass(i->Sin.ShuffleFp.dst) == HRcFlt64);
    vassert(hregClass(i->Sin.ShuffleFp.srcL) == HRcFlt64);
    vassert(hregClass(i->Sin.ShuffleFp.srcR) == HRcFlt64);

    insn |= (fregNo(i->Sin.ShuffleFp.dst, True) & 0x1f) << 25;
    insn |= (fregNo(i->Sin.ShuffleFp.srcL, True) & 0x1f) << 14;
    insn |= (fregNo(i->Sin.ShuffleFp.srcR, True) & 0x1f);

    *p++ = insn;
    return (p);
}

static UInt *
mkSqrtFp(UInt *p, const SPARC64Instr *i)
{
    HRegClass hrc = hregClass(i->Sin.SqrtFp.dst);
    UInt insn = 0x81A00500;

    vassert(hrc == hregClass(i->Sin.SqrtFp.src));

    switch (hrc) {
    case HRcFlt32:
        insn |= 0x20;
        break;
    case HRcFlt64:
        insn |= 0x40;
        break;
    case HRcFlt128:
        insn |= 0x60;
        break;
    default:
        vpanic("Unsupported host register class");
    }

    insn |= (fregNo(i->Sin.SqrtFp.dst, True) & 0x1f) << 25;
    insn |= (fregNo(i->Sin.SqrtFp.src, True) & 0x1f);

    *p++ = insn;
    return (p);
}

static UInt *
mkEvCheck(UInt *p, const SPARC64Instr *i)
{
    UInt *p0 = p;

    /* We emit the following code:
         lduw [%g5 + offCounter], %g4
         subcc %g4, 1, %g4
         bpos,pt %icc, nofail
         stw %g4, [%g5 + offCounter]    ! in branch delay slot
         ldx [%g5 + offFailAddr], %g4
         jmpl %g4, %o7
         nop
       nofail:
    */
    *p++ = 0xC8016000 | (i->Sin.EvCheck.offCounter & SPARC64_SIMM13_MASK);
    *p++ = 0x88A12001;
    *p++ = 0x1C480005;
    *p++ = 0xC8216000 | (i->Sin.EvCheck.offCounter & SPARC64_SIMM13_MASK);
    *p++ = 0xC8596000 | (i->Sin.EvCheck.offFailAddr & SPARC64_SIMM13_MASK);
    *p++ = 0x9FC10000;
    *p++ = 0x01000000;

    /* Crosscheck */
    vassert(evCheckSzB_SPARC64() == ((UChar *) p - (UChar *) p0));
    return (p);
}

static UInt *
mkLoadGuestState(UInt *p, const SPARC64Instr *i)
{
    /* Load all registers from guest state before unrecognized instruction. */

    /* Save host %o7 across call and unimplemented instruction. It will
       be restored after the guest state is stored in code generated by
       mkStoreGuestState, below. */
    /* stx  %o7, [ %g5 + 736 ] */
    SPARC64AMode *dest =
       SPARC64AMode_IR(OFFSET_sparc64_host_O7, hregSPARC64_G5());
    p = mkStoreLoadWord(p, True, REG_O7, dest);

    /* Save all host callee-save registers prior to calling a function that
       will load all of the guest registers. They will get restored after
       the unimplemented instruction is executed and the guest registers
       are stored back into the guest state. Use the minimum frame size. */
    /* save  %sp, -176, %sp */
    UInt save_instr = 0x9de3a000 | (-SPARC64_MINFRAME & SPARC64_SIMM13_MASK);
    *p++ = save_instr;

    /* Call function to load guest state into real registers before
       executing unrecognized instruction. */

    p = mkLoadImmWord(p, REG_G1, REG_G4,
                      (Addr64)&LibVEX_GuestSPARC64_LoadGuestRegisters);
    *p++ = 0x9fc10000; /* jmpl %g4, %o7 */
    *p++ = 0x01000000; /* nop */

    /* Load %o7 after it has been used in the call. */
    /* ldx [ %g7 + 136 ], %o7 */
    SPARC64AMode *src = SPARC64AMode_IR(OFFSET_sparc64_R15, hregSPARC64_G7());
    p = mkStoreLoadWord(p, False, REG_O7, src);

    return p;
}

static UInt *
mkStoreGuestState(UInt *p, const SPARC64Instr *i)
{
    /* Store all registers to guest state after unrecognized instruction. */

    /* %g7 holds the guest state pointer across the unrecognized instruction.
       This register is reserved for libc's TLS. Libc+libpthread use
       only the following instructions to access it: add, casx, clr, clrx,
       cmp, ld, ldsw, ldub, ldx, mov, stb, st, stx, and swap. -- Ivo */

    /* Store %o7 which cannot be stored in the call as it's used to return */
    /* stx %o7, [ %g7 + 136 ] */
    SPARC64AMode *dest = SPARC64AMode_IR(OFFSET_sparc64_R15, hregSPARC64_G7());
    p = mkStoreLoadWord(p, True, REG_O7, dest);

    /* Store %g1 and %g4 now because we're about to use them for a call. */
    /* stx  %g1, [ %g7 + 0x18 ] */
    dest = SPARC64AMode_IR(OFFSET_sparc64_R1, hregSPARC64_G7());
    p = mkStoreLoadWord(p, True, REG_G1, dest);

    /* stx  %g4, [ %g7 + 0x30 ] */
    dest = SPARC64AMode_IR(OFFSET_sparc64_R4, hregSPARC64_G7());
    p = mkStoreLoadWord(p, True, REG_G4, dest);

    /* Call function to store guest state back to real registers. */
    p = mkLoadImmWord(p, REG_G1, REG_G4,
                      (Addr64)&LibVEX_GuestSPARC64_StoreGuestRegisters);
    *p++ = 0x9FC10000; /* jmpl %g4, %o7 */
    *p++ = 0x01000000; /* nop */

    /* Restore all host callee-save registers. */
    *p++ = 0x81e80000;  /* restore */

    /* Restore host %o7 after calls. */
    /* ldx [ %g5 + 736 ], %o7 */
    SPARC64AMode *source =
       SPARC64AMode_IR(OFFSET_sparc64_host_O7, hregSPARC64_G5());
    p = mkStoreLoadWord(p, False, REG_O7, source);

    return p;
}

static UInt *
mkUnrecognized(UInt *p, const SPARC64Instr *i)
{
    *p++ = i->Sin.Unrecognized.instr_bits;
    return p;
}

static UInt *
mkXAssisted(UInt *p, const SPARC64Instr *i, const void *target_pc)
{
    UInt trcval = 0;
    UInt *ptmp = NULL;
    UInt insn;

    /* Set TRC value */
    switch (i->Sin.XAssisted.jk) {
    case Ijk_ClientReq:
        trcval = VEX_TRC_JMP_CLIENTREQ;
        break;
    case Ijk_Sys_syscall: /* normal syscall (ta 0x40 or ta 0x6d) */
        trcval = VEX_TRC_JMP_SYS_SYSCALL;
        break;
    case Ijk_Sys_syscall110:
        trcval = VEX_TRC_JMP_SYS_SYSCALL110;
        break;
    case Ijk_Sys_syscall111:
        trcval = VEX_TRC_JMP_SYS_SYSCALL111;
        break;
    case Ijk_Sys_fasttrap: /* fasttrap */
        trcval = VEX_TRC_JMP_SYS_FASTTRAP;
        break;
    case Ijk_Yield:
        trcval = VEX_TRC_JMP_YIELD;
        break;
    case Ijk_EmWarn:
        trcval = VEX_TRC_JMP_EMWARN;
        break;
    case Ijk_EmFail:
        trcval = VEX_TRC_JMP_EMFAIL;
        break;
    case Ijk_NoDecode:
        trcval = VEX_TRC_JMP_NODECODE;
        break;
    case Ijk_InvalICache:
        trcval = VEX_TRC_JMP_INVALICACHE;
        break;
    case Ijk_NoRedir:
        trcval = VEX_TRC_JMP_NOREDIR;
        break;
    case Ijk_SigILL:
        trcval = VEX_TRC_JMP_SIGILL;
        break;
    case Ijk_SigTRAP:
        trcval = VEX_TRC_JMP_SIGTRAP;
        break;
    case Ijk_SigBUS:
        trcval = VEX_TRC_JMP_SIGBUS;
        break;
    case Ijk_SigFPE_IntDiv:
        trcval = VEX_TRC_JMP_SIGFPE_INTDIV;
        break;
    case Ijk_SigFPE_IntOvf:
        trcval = VEX_TRC_JMP_SIGFPE_INTOVF;
        break;
    case Ijk_Boring:
        trcval = VEX_TRC_JMP_BORING;
        break;
    case Ijk_Call:
        /* Should not be assisted transfer. Fall through. */
    case Ijk_Ret:
        /* Should not be assisted transfer. Fall through. */
    default:
        ppIRJumpKind(i->Sin.XAssisted.jk);
        vpanic("XAssisted: unsupported jump kind");
    }

    /* Condition 'N' does not emit any instruction. */
    if (i->Sin.XAssisted.cond == Scc_N)
        return (p);

    /* Reserve space for condition code. */
    if (i->Sin.XAssisted.cond != Scc_A) {
        ptmp = p;
        p += 2;
    }

    /* Update guest PC. */
    p = mkStoreLoadWord(p, True, iregNo(i->Sin.XAssisted.dstGA),
                        i->Sin.XAssisted.amPC);

    /* Pass trcval via %g5. */
    vassert(trcval != 0);
    p = mkLoadImmWord(p, REG_G1, REG_G5, trcval);

    /* Call the handler. */
    p = mkLoadImmWord(p, REG_G1, REG_G4, (Addr64)target_pc);
    *p++ = 0x9FC10000; /* jmpl %g4, %o7 */
    *p++ = 0x01000000; /* nop */

    /* Backpatch condition code. */
    if (i->Sin.XAssisted.cond != Scc_A) {
        UInt delta = p - ptmp;
        insn = 0x600000; /* b<!cond>,pn %xcc, delta */
        insn |= cond_codes[1 ^ i->Sin.XAssisted.cond] << 25;
        insn |= delta;
        *ptmp++ = insn;
        *ptmp++ = 0x01000000; /* nop */
    }

    return (p);
}

/* Final location of an instruction can change. Generate PIC only! */
Int
emit_SPARC64Instr(/*MB_MOD*/ Bool *is_profInc,
                  UChar *buf, Int nbuf, const SPARC64Instr *i,
                  Bool mode64, VexEndness endness_host,
                  const void *disp_cp_chain_me_to_slowEP,
                  const void *disp_cp_chain_me_to_fastEP,
                  const void *disp_cp_xindir,
                  const void *disp_cp_xassisted)
{
    /* Check that instruction buffer is sufficiently aligned and placate gcc. */
    if ((Addr) buf % 4 != 0) {
        vpanic("emit_SPARC64: instruction buffer is misaligned!");
    }
    UInt *p = __builtin_assume_aligned(buf, 4);

    vassert(nbuf >= 32); /* TODO-SPARC: update this once emit is finished */

    switch (i->tag) {
    case Sin_LI:
        p = mkLoadImm(p, iregNo(i->Sin.LI.dst), i->Sin.LI.imm);
        break;
    case Sin_Alu:
        p = mkAlu(p, i);
        break;
    case Sin_Shft:
        p = mkShft(p, i);
        break;
    case Sin_Load:
    case Sin_Store:
        p = mkStoreLoad(p, i);
        break;
    case Sin_CAS:
        p = mkCas(p, i);
        break;
    case Sin_Ldstub:
        p = mkLdstub(p, i);
        break;
    case Sin_Lzcnt:
        p = mkLzcnt(p, i);
        break;
    case Sin_Membar:
        p = mkMembar(p, i);
        break;
    case Sin_ASR:
        p = mkASR(p, i);
        break;
    case Sin_Call:
        p = mkCall(p, i);
        break;
    case Sin_XDirect: {
        vassert(disp_cp_chain_me_to_slowEP != NULL);
        vassert(disp_cp_chain_me_to_fastEP != NULL);
        const void *disp_cp_chain_me = (i->Sin.XDirect.toFastEP) ?
            disp_cp_chain_me_to_fastEP : disp_cp_chain_me_to_slowEP;
        p = mkXDirectIndirect(p, i, disp_cp_chain_me);
        break;
    }
    case Sin_XIndir:
        vassert(disp_cp_xindir != NULL);
        p = mkXDirectIndirect(p, i, disp_cp_xindir);
        break;
    case Sin_XAssisted:
        p = mkXAssisted(p, i, disp_cp_xassisted);
        break;
    case Sin_EvCheck:
        p = mkEvCheck(p, i);
        break;
    case Sin_ProfInc:
        break;
    case Sin_MoveCond:
        p = mkMoveCond(p, i);
        break;
    case Sin_LoadGuestState:
        p = mkLoadGuestState(p, i);
        break;
    case Sin_StoreGuestState:
        p = mkStoreGuestState(p, i);
        break;
    case Sin_Unrecognized:
        p = mkUnrecognized(p, i);
        break;
    case Sin_MoveReg:
        p = mkMoveReg(p, i);
        break;
    case Sin_AlignDataFp:
        p = mkAlignDataFp(p, i);
        break;
    case Sin_AluFp:
        p = mkAluFp(p, i);
        break;
    case Sin_AbsFp:
        p = mkAbsFp(p, i);
        break;
    case Sin_CmpFp:
        p = mkCmpFp(p, i);
        break;
    case Sin_ConvFp:
        p = mkConvFp(p, i);
        break;
    case Sin_FusedFp:
        p = mkFusedFp(p, i);
        break;
    case Sin_HalveFp:
        p = mkHalveFp(p, i);
        break;
    case Sin_MovIRegToFp:
        p = mkMovIRegToFp(p, i);
        break;
    case Sin_MovFp:
        p = mkMovFp(p, i);
        break;
    case Sin_MovFpICond:
        p = mkMovFpICond(p, i);
        break;
    case Sin_MovFpToIReg:
        p = mkMovFpToIReg(p, i);
        break;
    case Sin_NegFp:
        p = mkNegFp(p, i);
        break;
    case Sin_ShftFp:
        p = mkShftFp(p, i);
        break;
    case Sin_ShuffleFp:
        p = mkShuffleFp(p, i);
        break;
    case Sin_SqrtFp:
        p = mkSqrtFp(p, i);
        break;
    default:
        ppSPARC64Instr(i);
        vpanic("emit: invalid instruction");
    }

    UInt instr_size = (UChar *) p - buf;
    if (instr_size > nbuf) {
        /* overflowed instruction buffer */
        vpanic("emit: too many bytes emitted for instruction");
    }

    return ((UChar *) p - buf);
}

void
genSpill_SPARC64(/*OUT*/ HInstr **i1, /*OUT*/ HInstr **i2,
                 HReg rreg, Int offsetB, Bool mode64)
{
    SPARC64AMode *am;

    vassert(!hregIsVirtual(rreg));
    am = SPARC64AMode_IR(offsetB, SPARC64_GuestStatePointer());

    switch (hregClass(rreg)) {
    case HRcInt64:
        *i1 = SPARC64Instr_Store(8, am, rreg);
        break;
    case HRcFlt32:
        *i1 = SPARC64Instr_Store(4, am, rreg);
        break;
    case HRcFlt64:
        *i1 = SPARC64Instr_Store(8, am, rreg);
        break;
    case HRcFlt128:
        *i1 = SPARC64Instr_Store(16, am, rreg);
        break;
    default:
        ppHRegClass(hregClass(rreg));
        vpanic("genSpill_SPARC64: unsupported register class");
    }
}

void
genReload_SPARC64(/*OUT*/ HInstr **i1, /*OUT*/ HInstr**i2,
                  HReg rreg, Int offsetB, Bool mode64)
{
    SPARC64AMode *am;

    vassert(!hregIsVirtual(rreg));
    am = SPARC64AMode_IR(offsetB, SPARC64_GuestStatePointer());

    switch (hregClass(rreg)) {
    case HRcInt64:
        *i1 = SPARC64Instr_Load(8, rreg, am);
        break;
    case HRcFlt32:
        *i1 = SPARC64Instr_Load(4, rreg, am);
        break;
    case HRcFlt64:
        *i1 = SPARC64Instr_Load(8, rreg, am);
        break;
    case HRcFlt128:
        *i1 = SPARC64Instr_Load(16, rreg, am);
        break;
    default:
        ppHRegClass(hregClass(rreg));
        vpanic("genReload_SPARC64: unsupported register class");
    }
}

static void
addHRegUse_SPARC64RI(HRegUsage *u, const SPARC64RI *ri)
{
    switch (ri->tag) {
    case Sri_Imm:
        return;
    case Sri_Reg:
        addHRegUse(u, HRmRead, ri->Sri.Reg.reg);
        return;
    default:
        vpanic("addHRegUse_SPARC64RI");
    }
}

static void
addHRegUse_SPARC64AMode(HRegUsage *u, const SPARC64AMode *am)
{
    switch (am->tag) {
    case Sam_IR:
        addHRegUse(u, HRmRead, am->Sam.IR.reg);
        return;
    case Sam_RR:
        addHRegUse(u, HRmRead, am->Sam.RR.reg1);
        addHRegUse(u, HRmRead, am->Sam.RR.reg2);
        return;
    default:
        vpanic("addHRegUse_SPARC64AMode");
    }
}

void
getRegUsage_SPARC64Instr(HRegUsage *u, const SPARC64Instr *i)
{
    initHRegUsage(u);

    switch (i->tag) {
    case Sin_LI:
        addHRegUse(u, HRmWrite, i->Sin.LI.dst);
        return;
    case Sin_Alu:
        addHRegUse(u, HRmRead, i->Sin.Alu.srcL);
        addHRegUse_SPARC64RI(u, i->Sin.Alu.srcR);
        addHRegUse(u, HRmWrite, i->Sin.Alu.dst);
        return;
    case Sin_Shft:
        addHRegUse(u, HRmRead, i->Sin.Shft.srcL);
        addHRegUse_SPARC64RI(u, i->Sin.Shft.srcR);
        addHRegUse(u, HRmWrite, i->Sin.Shft.dst);
        return;
    case Sin_Load:
        addHRegUse_SPARC64AMode(u, i->Sin.Load.src);
        if (!i->Sin.Load.toFsr) {
            addHRegUse(u, HRmWrite, i->Sin.Load.dst);
        }
        return;
    case Sin_Store:
        if (!i->Sin.Store.fromFsr) {
            addHRegUse(u, HRmRead, i->Sin.Store.src);
        }
        addHRegUse_SPARC64AMode(u, i->Sin.Store.dst);
        return;
    case Sin_MoveCond:
        addHRegUse(u, HRmModify, i->Sin.MoveCond.dst);
        addHRegUse(u, HRmRead, i->Sin.MoveCond.src);
        return;
    case Sin_MoveReg:
        addHRegUse(u, HRmModify, i->Sin.MoveReg.dst);
        addHRegUse(u, HRmRead, i->Sin.MoveReg.srcL);
        addHRegUse_SPARC64RI(u, i->Sin.MoveReg.srcR);
        return;
    case Sin_CAS:
        addHRegUse(u, HRmRead, i->Sin.CAS.addr);
        addHRegUse(u, HRmRead, i->Sin.CAS.src);
        addHRegUse(u, HRmModify, i->Sin.CAS.dst);
        return;
    case Sin_Ldstub:
        addHRegUse_SPARC64AMode(u, i->Sin.Ldstub.src);
        addHRegUse(u, HRmWrite, i->Sin.Ldstub.dst);
        return;
    case Sin_Lzcnt:
        addHRegUse(u, HRmRead, i->Sin.Lzcnt.src);
        addHRegUse(u, HRmWrite, i->Sin.Lzcnt.dst);
        return;
    case Sin_Membar:
        return;
    case Sin_ASR:
        if (i->Sin.ASR.store) {
            addHRegUse_SPARC64RI(u, i->Sin.ASR.srcR);
            addHRegUse(u, HRmRead, i->Sin.ASR.srcL);
        } else {
            addHRegUse(u, HRmWrite, i->Sin.ASR.srcL);
        }
        return;
    case Sin_Call:
        addHRegUse(u, HRmRead, i->Sin.Call.tgt);

        /* Invalidate all caller-saved registers that are under register
           allocator's jurisdiction. */
        /* TODO-SPARC: State only caller-save regs, not *all* of them.
           Allocatable caller saved regs are only: %o0 .. %o5. */
        addHRegUse(u, HRmWrite, hregSPARC64_O0());
        addHRegUse(u, HRmWrite, hregSPARC64_O1());
        addHRegUse(u, HRmWrite, hregSPARC64_O2());
        addHRegUse(u, HRmWrite, hregSPARC64_O3());
        addHRegUse(u, HRmWrite, hregSPARC64_O4());
        addHRegUse(u, HRmWrite, hregSPARC64_O5());
        addHRegUse(u, HRmWrite, hregSPARC64_O6());
        addHRegUse(u, HRmWrite, hregSPARC64_O7());
        addHRegUse(u, HRmWrite, hregSPARC64_I0());
        addHRegUse(u, HRmWrite, hregSPARC64_I1());
        addHRegUse(u, HRmWrite, hregSPARC64_I2());
        addHRegUse(u, HRmWrite, hregSPARC64_I3());
        addHRegUse(u, HRmWrite, hregSPARC64_I4());
        addHRegUse(u, HRmWrite, hregSPARC64_I5());
        addHRegUse(u, HRmWrite, hregSPARC64_I6());
        addHRegUse(u, HRmWrite, hregSPARC64_I7());
        addHRegUse(u, HRmWrite, hregSPARC64_L0());
        addHRegUse(u, HRmWrite, hregSPARC64_L1());
        addHRegUse(u, HRmWrite, hregSPARC64_L2());
        addHRegUse(u, HRmWrite, hregSPARC64_L3());
        addHRegUse(u, HRmWrite, hregSPARC64_L4());
        addHRegUse(u, HRmWrite, hregSPARC64_L5());
        addHRegUse(u, HRmWrite, hregSPARC64_L6());
        addHRegUse(u, HRmWrite, hregSPARC64_L7());

        /* Now we have to state any parameter-carrying registers which might be
           read. This depends on argiregs. */
        switch (i->Sin.Call.argiregs) {
        case 6: addHRegUse(u, HRmRead, hregSPARC64_O5()); /* fallthru */
        case 5: addHRegUse(u, HRmRead, hregSPARC64_O4()); /* fallthru */
        case 4: addHRegUse(u, HRmRead, hregSPARC64_O3()); /* fallthru */
        case 3: addHRegUse(u, HRmRead, hregSPARC64_O2()); /* fallthru */
        case 2: addHRegUse(u, HRmRead, hregSPARC64_O1()); /* fallthru */
        case 1: addHRegUse(u, HRmRead, hregSPARC64_O0()); break;
        case 0: break;
        default: vpanic("getRegUsage: Unsupported number of argiregs");
        }
        return;
    case Sin_XDirect:
        addHRegUse_SPARC64AMode(u, i->Sin.XDirect.amPC);
        return;
    case Sin_XIndir:
        addHRegUse(u, HRmRead, i->Sin.XIndir.dstGA);
        addHRegUse_SPARC64AMode(u, i->Sin.XIndir.amPC);
        return;
    case Sin_XAssisted:
        addHRegUse(u, HRmRead, i->Sin.XAssisted.dstGA);
        addHRegUse_SPARC64AMode(u, i->Sin.XAssisted.amPC);
        return;
    case Sin_AlignDataFp:
        addHRegUse(u, HRmRead, i->Sin.AlignDataFp.srcL);
        addHRegUse(u, HRmRead, i->Sin.AlignDataFp.srcR);
        addHRegUse(u, HRmModify, i->Sin.AlignDataFp.dst);
        return;
    case Sin_AluFp:
        addHRegUse(u, HRmRead, i->Sin.AluFp.srcL);
        if (i->Sin.AluFp.op != AluFp_FNOT) {
            addHRegUse(u, HRmRead, i->Sin.AluFp.srcR);
        }
        addHRegUse(u, HRmWrite, i->Sin.AluFp.dst);
        return;
    case Sin_AbsFp:
        addHRegUse(u, HRmRead, i->Sin.AbsFp.src);
        addHRegUse(u, HRmWrite, i->Sin.AbsFp.dst);
        return;
    case Sin_CmpFp:
        addHRegUse(u, HRmRead, i->Sin.CmpFp.srcL);
        addHRegUse(u, HRmRead, i->Sin.CmpFp.srcR);
        return;
    case Sin_ConvFp:
        addHRegUse(u, HRmRead, i->Sin.ConvFp.src);
        addHRegUse(u, HRmWrite, i->Sin.ConvFp.dst);
        return;
    case Sin_FusedFp:
        addHRegUse(u, HRmRead, i->Sin.FusedFp.arg1);
        addHRegUse(u, HRmRead, i->Sin.FusedFp.arg2);
        addHRegUse(u, HRmRead, i->Sin.FusedFp.arg3);
        addHRegUse(u, HRmWrite, i->Sin.FusedFp.dst);
        return;
    case Sin_HalveFp:
        addHRegUse(u, HRmRead, i->Sin.HalveFp.src);
        addHRegUse(u, HRmWrite, i->Sin.HalveFp.dst);
        return;
    case Sin_MovIRegToFp:
        addHRegUse(u, HRmRead, i->Sin.MovIRegToFp.src);
        addHRegUse(u, HRmWrite, i->Sin.MovIRegToFp.dst);
        return;
    case Sin_MovFp:
        addHRegUse(u, HRmRead, i->Sin.MovFp.src);
        addHRegUse(u, HRmWrite, i->Sin.MovFp.dst);
        return;
    case Sin_MovFpICond:
        addHRegUse(u, HRmModify, i->Sin.MovFpICond.dst);
        addHRegUse(u, HRmRead, i->Sin.MovFpICond.src);
        return;
    case Sin_MovFpToIReg:
        addHRegUse(u, HRmRead, i->Sin.MovFpToIReg.src);
        addHRegUse(u, HRmWrite, i->Sin.MovFpToIReg.dst);
        return;
    case Sin_NegFp:
        addHRegUse(u, HRmRead, i->Sin.NegFp.src);
        addHRegUse(u, HRmWrite, i->Sin.NegFp.dst);
        return;
    case Sin_ShftFp:
        addHRegUse(u, HRmRead, i->Sin.ShftFp.srcL);
        addHRegUse(u, HRmRead, i->Sin.ShftFp.srcR);
        addHRegUse(u, HRmWrite, i->Sin.ShftFp.dst);
        return;
    case Sin_ShuffleFp:
        addHRegUse(u, HRmRead, i->Sin.ShuffleFp.srcL);
        addHRegUse(u, HRmRead, i->Sin.ShuffleFp.srcR);
        addHRegUse(u, HRmWrite, i->Sin.ShuffleFp.dst);
        return;
    case Sin_SqrtFp:
        addHRegUse(u, HRmRead, i->Sin.SqrtFp.src);
        addHRegUse(u, HRmWrite, i->Sin.SqrtFp.dst);
        return;
    case Sin_EvCheck:
        /* We should mention %g4 but it is not allocatable anyway. */
        return;
    case Sin_ProfInc:
        return;
    case Sin_LoadGuestState:
    case Sin_StoreGuestState:
    case Sin_Unrecognized: {
        /* Invalidate all allocatable registers. */
        const RRegUniverse *univ = getRRegUniverse_SPARC64();
        for (UInt r = 0; r < univ->allocable; r++) {
            addHRegUse(u, HRmWrite, univ->regs[r]);
        }
        return;
    }
    default:
        ppSPARC64Instr(i);
        vpanic("getRegUsage: Unsupported instruction");
    }
}

Bool
isMove_SPARC64Instr(const SPARC64Instr *i, HReg *src, HReg *dst)
{
    switch (i->tag) {
    case Sin_Alu:
        if (i->Sin.Alu.op != Salu_OR)
            return (False);
        if (i->Sin.Alu.srcR->tag != Sri_Reg)
            return (False);
        /* or %g0, %src, %dst */
        if (sameHReg(i->Sin.Alu.srcL, hregSPARC64_G0())) {
            *src = i->Sin.Alu.srcR->Sri.Reg.reg;
            *dst = i->Sin.Alu.dst;
            return (True);
        }
        /* or %src, %g0, %dst */
        if (sameHReg(i->Sin.Alu.srcR->Sri.Reg.reg, hregSPARC64_G0())) {
            *src = i->Sin.Alu.srcL;
            *dst = i->Sin.Alu.dst;
            return (True);
        }
        break;
    case Sin_MovFp:
        *src = i->Sin.MovFp.src;
        *dst = i->Sin.MovFp.dst;
        return (True);
    default:
        break;
    }

    return (False);
}

void
ppSPARC64RI(SPARC64RI *ri)
{
    switch (ri->tag) {
    case Sri_Imm:
        vex_printf("%lld", ri->Sri.Imm.simm13);
        return;
    case Sri_Reg:
        ppHRegSPARC64(ri->Sri.Reg.reg);
        return;
    default:
        vpanic("Unsupported RI tag");
    }
}

SPARC64RI *
SPARC64RI_Imm(ULong l)
{
    SPARC64RI *ri = LibVEX_Alloc_inline(sizeof(SPARC64RI));
    ri->tag = Sri_Imm;
    ri->Sri.Imm.simm13 = l;

    return (ri);
}

SPARC64RI *
SPARC64RI_Reg(HReg reg)
{
    SPARC64RI *ri = LibVEX_Alloc_inline(sizeof(SPARC64RI));
    ri->tag = Sri_Reg;
    ri->Sri.Reg.reg = reg;

    return (ri);
}

static const HChar *
getAluOpName(SPARC64AluOp op)
{
    switch (op) {
    case Salu_ADD:     return ("add");
    case Salu_SUB:     return ("sub");
    case Salu_MULX:    return ("mulx");
    case Salu_SMUL:    return ("smul");
    case Salu_UMUL:    return ("umul");
    case Salu_UMULXHI: return ("umulxhi");
    case Salu_UDIVX:   return ("udivx");
    case Salu_SDIVX:   return ("sdivx");
    case Salu_SDIV:    return ("sdiv");
    case Salu_UDIV:    return ("udiv");
    case Salu_SUBcc:   return ("subcc");
    case Salu_AND:     return ("and");
    case Salu_ANDcc:   return ("andcc");
    case Salu_OR:      return ("or");
    case Salu_ORN:     return ("orn");
    case Salu_XOR:     return ("xor");
    case Salu_XNOR:    return ("xnor");
    default:
        vpanic("getAluOpName");
    }
}

static const HChar *
getAluFpOpName(SPARC64AluFpOp op)
{
    switch (op) {
    case AluFp_FADD:   return ("fadd");
    case AluFp_FAND:   return ("fand");
    case AluFp_FDIV:   return ("fdiv");
    case AluFp_FMUL:   return ("fmul");
    case AluFp_FsdMUL: return ("fsdmul");
    case AluFp_FNOT:   return ("fnot");
    case AluFp_FOR:    return ("for");
    case AluFp_FSUB:   return ("fsub");
    case AluFp_FXOR:   return ("fxor");
    default:
        vpanic("getAluFpOpName");
    }
}

static const HChar *
getFusedFpOpName(SPARC64FusedFpOp op)
{
    switch (op) {
    case FusedFp_MADD: return ("fmadd");
    case FusedFp_MSUB: return ("fmsub");
    default:
        vpanic("getFusedFpOpName");
    }
}

static const HChar *
getShftOpName(SPARC64ShftOp op)
{
    switch (op) {
    case Sshft_SLL:
        return ("sll");
    case Sshft_SRL:
        return ("srl");
    case Sshft_SRA:
        return ("sra");
    case Sshft_SLLX:
        return ("sllx");
    case Sshft_SRLX:
        return ("srlx");
    case Sshft_SRAX:
        return ("srax");
    default:
        vpanic("getShftOpName");
    }
}

static const HChar *
getShftFpOpName(SPARC64ShftFpOp op)
{
    switch (op) {
    case ShftFp_SLL16:  return "fsll16";
    case ShftFp_SRL16:  return "fsrl16";
    case ShftFp_SLL32:  return "fsll32";
    case ShftFp_SRL32:  return "fsrl32";
    case ShftFp_SLAS16: return "fslas16";
    case ShftFp_SRA16:  return "fsra16";
    case ShftFp_SLAS32: return "fslas32";
    case ShftFp_SRA32:  return "fsra32";
    default:
        vpanic("getShftFpOpName");
    }
}

const HChar *
showSPARC64CondCode(SPARC64CondCode cond)
{
    switch (cond) {
    case Scc_A:
        return ("A");
    case Scc_N:
        return ("N");
    case Scc_NE:
        return ("NE");
    case Scc_E:
        return ("E");
    case Scc_G:
        return ("G");
    case Scc_LE:
        return ("LE");
    case Scc_GE:
        return ("GE");
    case Scc_L:
        return ("L");
    case Scc_GU:
        return ("GU");
    case Scc_LEU:
        return ("LEU");
    case Scc_CC:
        return ("CC");
    case Scc_CS:
        return ("CS");
    case Scc_POS:
        return ("POS");
    case Scc_NEG:
        return ("NEG");
    case Scc_VC:
        return ("VC");
    case Scc_VS:
        return ("VS");
    default:
        vpanic("showSPARC64CondCode");
    }
}

const HChar *
showSPARC64RegCode(SPARC64RegCode cond)
{
    switch (cond) {
    case Src_Z:
        return ("Z");
    case Src_LEZ:
        return ("LEZ");
    case Src_LZ:
        return ("LZ");
    case Src_NZ:
        return ("NZ");
    case Src_GZ:
        return ("GZ");
    case Src_GEZ:
        return ("GEZ");
    default:
        vpanic("showSPARC64RegCode");
    }
}

void
ppSPARC64Instr(const SPARC64Instr *i)
{
    switch (i->tag) {
    case Sin_LI:
        vex_printf("setx 0x%llx, ", i->Sin.LI.imm);
        ppHRegSPARC64(i->Sin.LI.dst);
        return;
    case Sin_Alu:
        vex_printf("%s ", getAluOpName(i->Sin.Alu.op));
        ppHRegSPARC64(i->Sin.Alu.srcL);
        vex_printf(", ");
        ppSPARC64RI(i->Sin.Alu.srcR);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.Alu.dst);
        return;
    case Sin_Shft:
        vex_printf("%s ", getShftOpName(i->Sin.Shft.op));
        ppHRegSPARC64(i->Sin.Shft.srcL);
        vex_printf(", ");
        ppSPARC64RI(i->Sin.Shft.srcR);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.Shft.dst);
        return;
    case Sin_Load:
        vex_printf("%s%d ", (i->Sin.Load.asi != NULL) ? "lda" : "ld",
                   i->Sin.Load.sz);
        ppSPARC64AMode(i->Sin.Load.src);
        vex_printf(", ");
        if (i->Sin.Load.toFsr) {
            vex_printf("%%fsr");
        } else {
            ppHRegSPARC64(i->Sin.Load.dst);
        }
        if (i->Sin.Load.asi != NULL) {
            vex_printf(" ");
            if (i->Sin.Load.src->tag == Sam_IR)
                vex_printf("%%asi");
            else
                ppSPARC64RI(i->Sin.Load.asi);
        }
        return;
    case Sin_Store:
        vex_printf("%s%d ", (i->Sin.Store.asi != NULL) ? "sta" : "st",
                   i->Sin.Store.sz);
        if (i->Sin.Store.fromFsr) {
            vex_printf("%%fsr");
        } else {
            ppHRegSPARC64(i->Sin.Store.src);
        }
        vex_printf(", ");
        ppSPARC64AMode(i->Sin.Store.dst);
        if (i->Sin.Store.asi != NULL) {
            vex_printf(" ");
            if (i->Sin.Store.dst->tag == Sam_IR)
                vex_printf("%%asi");
            else
                ppSPARC64RI(i->Sin.Store.asi);
        }
        return;
    case Sin_CAS:
        vex_printf("cas%d [", i->Sin.CAS.sz);
        ppHRegSPARC64(i->Sin.CAS.addr);
        vex_printf("], ");
        ppHRegSPARC64(i->Sin.CAS.src);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.CAS.dst);
        return;
    case Sin_Ldstub:
        vex_printf("ldstub ");
        ppSPARC64AMode(i->Sin.Ldstub.src);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.Ldstub.dst);
        return;
    case Sin_Lzcnt:
        vex_printf("lzcnt ");
        ppHRegSPARC64(i->Sin.Lzcnt.src);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.Lzcnt.dst);
        return;
    case Sin_Membar:
        vex_printf("membar");
        return;
    case Sin_ASR:
        if (i->Sin.ASR.store) {
            vex_printf("wrasr ");
            ppHRegSPARC64(i->Sin.ASR.srcL);
            vex_printf(", ");
            ppSPARC64RI(i->Sin.ASR.srcR);
            vex_printf(", %d", i->Sin.ASR.dst);
        } else {
            vex_printf("rdasr %d, ", i->Sin.ASR.dst);
            ppHRegSPARC64(i->Sin.ASR.srcL);
        }
        return;
    case Sin_Call:
        vex_printf("call: ");
        vex_printf("if (%s) { ", showSPARC64CondCode(i->Sin.Call.cond));
        vex_printf("jmpl %%g4, %%o7; [#args=%u]; nop; }", i->Sin.Call.argiregs);
        return;
    case Sin_XDirect:
        vex_printf("(xDirect) ");
        vex_printf("if (%s) {",
            showSPARC64CondCode(i->Sin.XDirect.cond));
        vex_printf("setx 0x%llx, ", i->Sin.XDirect.dstGA);
        ppSPARC64AMode(i->Sin.XDirect.amPC);
        vex_printf("; setx $disp_cp_chain_me_to_%sEP, %%g4;",
            (i->Sin.XDirect.toFastEP) ? "fast" : "slow" );
        vex_printf(" jmpl %%g4, %%o7; nop }");
        return;
    case Sin_XIndir:
        vex_printf("(xIndir) ");
        vex_printf("if (%s) {",
            showSPARC64CondCode(i->Sin.XDirect.cond));
        vex_printf("stx ");
        ppHRegSPARC64(i->Sin.XIndir.dstGA);
        vex_printf(", ");
        ppSPARC64AMode(i->Sin.XIndir.amPC);
        vex_printf("; setx $disp_cp_xindir, %%g4; jmpl %%g4, %%o7; nop }");
        return;
    case Sin_XAssisted:
        vex_printf("(xAssisted) ");
        vex_printf("if (%s) {",
            showSPARC64CondCode(i->Sin.XDirect.cond));
        vex_printf("stx ");
        ppHRegSPARC64(i->Sin.XAssisted.dstGA);
        vex_printf(", ");
        ppSPARC64AMode(i->Sin.XAssisted.amPC);
        vex_printf("; setx $IRJumpKind(%u), %%g5; "
                   "setx $disp_cp_xassisted, %%g4; jmpl %%g4, %%o7; nop }",
                   i->Sin.XAssisted.jk);
        return;
    case Sin_AlignDataFp:
        vex_printf("faligndata ");
        ppHRegSPARC64(i->Sin.AlignDataFp.srcL);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.AlignDataFp.dst);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.AlignDataFp.srcR);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.AlignDataFp.dst);
        return;
    case Sin_AluFp:
        vex_printf("%s ", getAluFpOpName(i->Sin.AluFp.op));
        ppHRegSPARC64(i->Sin.AluFp.srcL);
        if (i->Sin.AluFp.op != AluFp_FNOT) {
            vex_printf(", ");
            ppHRegSPARC64(i->Sin.AluFp.srcR);
        }
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.AluFp.dst);
        return;
    case Sin_AbsFp:
        vex_printf("fabs ");
        ppHRegSPARC64(i->Sin.AbsFp.src);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.AbsFp.dst);
        return;
    case Sin_CmpFp:
        vex_printf("fcmp %%fcc%u, ", i->Sin.CmpFp.fccn);
        ppHRegSPARC64(i->Sin.CmpFp.srcL);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.CmpFp.srcR);
        return;
    case Sin_ConvFp:
        if (i->Sin.ConvFp.toInt)
            vex_printf("fsdqtoxi ");
        else if (i->Sin.ConvFp.fromInt)
            vex_printf("fixtosdq ");
        else
            vex_printf("fsdqtosdq ");
        ppHRegSPARC64(i->Sin.ConvFp.src);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.ConvFp.dst);
        return;
    case Sin_FusedFp:
        vex_printf("%s ", getFusedFpOpName(i->Sin.FusedFp.op));
        ppHRegSPARC64(i->Sin.FusedFp.arg1);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.FusedFp.arg2);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.FusedFp.arg3);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.FusedFp.dst);
        return;
    case Sin_HalveFp:
        vex_printf("fsrc2sd ");
        ppHRegSPARC64(i->Sin.HalveFp.src);
        vex_printf("[%s], ", (i->Sin.HalveFp.highHalf) ? "hi" : "lo");
        ppHRegSPARC64(i->Sin.HalveFp.dst);
        return;
    case Sin_MovIRegToFp:
        vex_printf("movitof ");
        ppHRegSPARC64(i->Sin.MovIRegToFp.src);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.MovIRegToFp.dst);
        return;
    case Sin_MovFp:
        vex_printf("fmov ");
        ppHRegSPARC64(i->Sin.MovFp.src);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.MovFp.dst);
        return;
    case Sin_MovFpICond:
        vex_printf("fmov%s %%xcc, ",
                   showSPARC64CondCode(i->Sin.MovFpICond.cond));
        ppHRegSPARC64(i->Sin.MovFpICond.src);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.MovFpICond.dst);
        return;
    case Sin_MovFpToIReg:
        vex_printf("movftoi ");
        ppHRegSPARC64(i->Sin.MovFpToIReg.src);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.MovFpToIReg.dst);
        return;
    case Sin_NegFp:
        vex_printf("fneg ");
        ppHRegSPARC64(i->Sin.NegFp.src);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.NegFp.dst);
        return;
    case Sin_ShftFp:
        vex_printf("%s ", getShftFpOpName(i->Sin.ShftFp.op));
        ppHRegSPARC64(i->Sin.ShftFp.srcL);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.ShftFp.srcR);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.ShftFp.dst);
        return;
    case Sin_ShuffleFp:
        vex_printf("fshuffle ");
        ppHRegSPARC64(i->Sin.ShuffleFp.srcL);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.ShuffleFp.srcR);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.ShuffleFp.dst);
        return;
    case Sin_SqrtFp:
        vex_printf("fsqrt ");
        ppHRegSPARC64(i->Sin.SqrtFp.src);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.SqrtFp.dst);
        return;
    case Sin_EvCheck:
        vex_printf("(evCheck) lduw [%%g5 + %u], %%g4; ",
                   i->Sin.EvCheck.offCounter);
        vex_printf("subcc %%g4, 1, %%g4; bpos,pt %%icc, nofail; ");
        vex_printf("stw %%g4, [%%g5 + %u]; ", i->Sin.EvCheck.offCounter);
        vex_printf("ldx [%%g5 + %u], %%g4; ", i->Sin.EvCheck.offFailAddr);
        vex_printf("jmpl %%g4, %%o7; nop; nofail:");
        return;
    case Sin_ProfInc:
        vex_printf("(profInc) ... TODO-SPARC ...");
        return;
    case Sin_LoadGuestState:
        vex_printf("LoadGuestState");
        return;
    case Sin_StoreGuestState:
        vex_printf("StoreGuestState");
        return;
    case Sin_Unrecognized:
        vex_printf("Unrecognized 0x%x", i->Sin.Unrecognized.instr_bits);
        return;
    case Sin_MoveCond:
        vex_printf("mov%s %%xcc, ", showSPARC64CondCode(i->Sin.MoveCond.cond));
        ppHRegSPARC64(i->Sin.MoveCond.src);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.MoveCond.dst);
        return;
    case Sin_MoveReg:
        vex_printf("mov%s ", showSPARC64RegCode(i->Sin.MoveReg.cond));
        ppHRegSPARC64(i->Sin.MoveReg.srcL);
        vex_printf(", ");
        ppSPARC64RI(i->Sin.MoveReg.srcR);
        vex_printf(", ");
        ppHRegSPARC64(i->Sin.MoveReg.dst);
        return;
    default:
        vpanic("ppSPARC64Instr: unsupported instruction");
    }
}

static void
mapReg(HRegRemap *m, HReg *r)
{
    *r = lookupHRegRemap(m, *r);
}

static void
mapRegs_SPARC64RI(HRegRemap *m, SPARC64RI *ri)
{
    switch (ri->tag) {
    case Sri_Imm:
        return;
    case Sri_Reg:
        ri->Sri.Reg.reg = lookupHRegRemap(m, ri->Sri.Reg.reg);
        return;
    default:
        vpanic("mapRegs_SPARC64RI");
    }
}

static void
mapRegs_SPARC64AMode(HRegRemap *m, SPARC64AMode *am)
{
    switch (am->tag) {
    case Sam_IR:
        am->Sam.IR.reg = lookupHRegRemap(m, am->Sam.IR.reg);
        return;
    case Sam_RR:
        am->Sam.RR.reg1 = lookupHRegRemap(m, am->Sam.RR.reg1);
        am->Sam.RR.reg2 = lookupHRegRemap(m, am->Sam.RR.reg2);
        return;
    default:
        vpanic("mapRegs_SPARC64AMode");
    }
}

void
mapRegs_SPARC64Instr(HRegRemap *m, SPARC64Instr *i)
{
    switch (i->tag) {
    case Sin_LI:
        mapReg(m, &i->Sin.LI.dst);
        return;
    case Sin_Alu:
        mapReg(m, &i->Sin.Alu.srcL);
        mapRegs_SPARC64RI(m, i->Sin.Alu.srcR);
        mapReg(m, &i->Sin.Alu.dst);
        return;
    case Sin_Shft:
        mapReg(m, &i->Sin.Shft.srcL);
        mapRegs_SPARC64RI(m, i->Sin.Shft.srcR);
        mapReg(m, &i->Sin.Shft.dst);
        return;
    case Sin_Load:
        mapRegs_SPARC64AMode(m, i->Sin.Load.src);
        if (!i->Sin.Load.toFsr) {
            mapReg(m, &i->Sin.Load.dst);
        }
        return;
    case Sin_Store:
        if (!i->Sin.Store.fromFsr) {
            mapReg(m, &i->Sin.Store.src);
        }
        mapRegs_SPARC64AMode(m, i->Sin.Store.dst);
        return;
    case Sin_MoveCond:
        mapReg(m, &i->Sin.MoveCond.dst);
        mapReg(m, &i->Sin.MoveCond.src);
        return;
    case Sin_MoveReg:
        mapReg(m, &i->Sin.MoveReg.dst);
        mapReg(m, &i->Sin.MoveReg.srcL);
        mapRegs_SPARC64RI(m, i->Sin.MoveReg.srcR);
        return;
    case Sin_CAS:
        mapReg(m, &i->Sin.CAS.addr);
        mapReg(m, &i->Sin.CAS.src);
        mapReg(m, &i->Sin.CAS.dst);
        return;
    case Sin_Ldstub:
        mapRegs_SPARC64AMode(m, i->Sin.Ldstub.src);
        mapReg(m, &i->Sin.Ldstub.dst);
        return;
    case Sin_Lzcnt:
        mapReg(m, &i->Sin.Lzcnt.src);
        mapReg(m, &i->Sin.Lzcnt.dst);
        return;
    case Sin_Membar:
        return;
    case Sin_ASR:
        if (i->Sin.ASR.store)
            mapRegs_SPARC64RI(m, i->Sin.ASR.srcR);
        mapReg(m, &i->Sin.ASR.srcL);
        return;
    case Sin_Call:
        mapReg(m, &i->Sin.Call.tgt);
        return;
    case Sin_XDirect:
        mapRegs_SPARC64AMode(m, i->Sin.XDirect.amPC);
        return;
    case Sin_XIndir:
        mapReg(m, &i->Sin.XIndir.dstGA);
        mapRegs_SPARC64AMode(m, i->Sin.XIndir.amPC);
        return;
    case Sin_XAssisted:
        mapReg(m, &i->Sin.XAssisted.dstGA);
        mapRegs_SPARC64AMode(m, i->Sin.XAssisted.amPC);
        return;
    case Sin_AlignDataFp:
        mapReg(m, &i->Sin.AlignDataFp.dst);
        mapReg(m, &i->Sin.AlignDataFp.srcL);
        mapReg(m, &i->Sin.AlignDataFp.srcR);
        return;
    case Sin_AluFp:
        mapReg(m, &i->Sin.AluFp.dst);
        mapReg(m, &i->Sin.AluFp.srcL);
        if (i->Sin.AluFp.op != AluFp_FNOT) {
            mapReg(m, &i->Sin.AluFp.srcR);
        }
        return;
    case Sin_AbsFp:
        mapReg(m, &i->Sin.AbsFp.dst);
        mapReg(m, &i->Sin.AbsFp.src);
        return;
    case Sin_CmpFp:
        mapReg(m, &i->Sin.CmpFp.srcL);
        mapReg(m, &i->Sin.CmpFp.srcR);
        return;
    case Sin_ConvFp:
        mapReg(m, &i->Sin.ConvFp.dst);
        mapReg(m, &i->Sin.ConvFp.src);
        return;
    case Sin_FusedFp:
        mapReg(m, &i->Sin.FusedFp.dst);
        mapReg(m, &i->Sin.FusedFp.arg1);
        mapReg(m, &i->Sin.FusedFp.arg2);
        mapReg(m, &i->Sin.FusedFp.arg3);
        return;
    case Sin_HalveFp:
        mapReg(m, &i->Sin.HalveFp.dst);
        mapReg(m, &i->Sin.HalveFp.src);
        return;
    case Sin_MovIRegToFp:
        mapReg(m, &i->Sin.MovIRegToFp.dst);
        mapReg(m, &i->Sin.MovIRegToFp.src);
        return;
    case Sin_MovFp:
        mapReg(m, &i->Sin.MovFp.dst);
        mapReg(m, &i->Sin.MovFp.src);
        return;
    case Sin_MovFpICond:
        mapReg(m, &i->Sin.MovFpICond.dst);
        mapReg(m, &i->Sin.MovFpICond.src);
        return;
    case Sin_MovFpToIReg:
        mapReg(m, &i->Sin.MovFpToIReg.dst);
        mapReg(m, &i->Sin.MovFpToIReg.src);
        return;
    case Sin_NegFp:
        mapReg(m, &i->Sin.NegFp.dst);
        mapReg(m, &i->Sin.NegFp.src);
        return;
    case Sin_ShftFp:
        mapReg(m, &i->Sin.ShftFp.dst);
        mapReg(m, &i->Sin.ShftFp.srcL);
        mapReg(m, &i->Sin.ShftFp.srcR);
        return;
    case Sin_ShuffleFp:
        mapReg(m, &i->Sin.ShuffleFp.dst);
        mapReg(m, &i->Sin.ShuffleFp.srcL);
        mapReg(m, &i->Sin.ShuffleFp.srcR);
        return;
    case Sin_SqrtFp:
        mapReg(m, &i->Sin.SqrtFp.dst);
        mapReg(m, &i->Sin.SqrtFp.src);
        return;
    case Sin_EvCheck:
        /* Uses %g4 which is not allocatable. */
        return;
    case Sin_ProfInc:
        return;
    case Sin_LoadGuestState:
    case Sin_StoreGuestState:
    case Sin_Unrecognized:
        return;
    default:
       vpanic("mapRegs: unsupported instruction");
    }
}

Int evCheckSzB_SPARC64(void)
{
    /* Size of the event check preamble. */
    return (7 * 4);
}

/*
 * Performs chaining of an XDirect jump. This code is tightly coupled with
 * XDirect instruction emitor. Changes must be coordinated between both
 * places!!
 */
VexInvalRange chainXDirect_SPARC64(VexEndness endness_host,
                                   void *place_to_chain,
                                   const void *disp_cp_chain_me_EXPECTED,
                                   const void *place_to_jump_to)
{
    vassert(endness_host == VexEndnessBE);
    UInt *p = (UInt *) place_to_chain;
    VexInvalRange vir;
    Int len, i;
    UInt tmp[6];

    /*
     * The current layout of instructions emitted for XDirect:
     *   1) Load 64-bit immediate $disp_cp_chain_me_to_EXPECTED, %g4
     *   2) jmpl %g4, %o7
     *   3) nop
     */
    mkLoadImmWord(tmp, REG_G1, REG_G4, (Addr64)disp_cp_chain_me_EXPECTED);
    for (i = 0; i < 6; i++)
        vassert(p[i] == tmp[i]);

    /*
     * We are hot-patching the instruction sequence to do the following:
     *   1) Load 64-bit immediate $place_to_jump_to, %g4
     *   2) jmpl %g4, %o7
     *   3) nop
     * Note: The size of patch is same as the original instructions and
     *       we just patch the immediate value.
     */
    p = mkLoadImmWord(p, REG_G1, REG_G4, (Addr64)place_to_jump_to);
    len = (UChar *)p - (UChar *)place_to_chain;
    vassert(len == 24);
    vir.start = (HWord)place_to_chain;
    vir.len =  len;
    return (vir);
}

/*
 * Performs unchaining of an XDirect jump. This code is tightly coupled with
 * XDirect instruction emitor. Changes must be coordinated between both
 * places!!
 */
VexInvalRange unchainXDirect_SPARC64(VexEndness endness_host,
                                     void *place_to_unchain,
                                     const void *place_to_jump_EXPECTED,
                                     const void *disp_cp_chain_me)
{
    vassert(endness_host == VexEndnessBE);
    UInt *p = (UInt *) place_to_unchain;
    VexInvalRange vir;
    Int len, i;
    UInt tmp[6];

    /*
     * The current layout of instructions emitted for XDirect:
     *   1) Load 64-bit immediate $place_to_jump_EXPECTED, %g4
     *   2) jmpl %g4, %o7
     *   3) nop
     */
    mkLoadImmWord(tmp, REG_G1, REG_G4, (Addr64)place_to_jump_EXPECTED);
    for (i = 0; i < 6; i++)
        vassert(p[i] == tmp[i]);

    /*
     * We are hot-patching the instruction sequence to do the following:
     *   1) Load 64-bit immediate $disp_cp_chain_me, %g4
     *   2) jmpl %g4, %o7
     *   3) nop
     * Note: The size of patch is same as the original instructions and
     *       we just patch the immediate value.
     */
    p = mkLoadImmWord(p, REG_G1, REG_G4, (Addr64)disp_cp_chain_me);
    len = (UChar *)p - (UChar *)place_to_unchain;
    vassert(len == 24);
    vir.start = (HWord)place_to_unchain;
    vir.len =  len;
    return (vir);
}

VexInvalRange patchProfInc_SPARC64(VexEndness endness_host,
                                   void *place_to_patch,
                                   const ULong *location_of_counter)
{
    vpanic("SPARC64: patchProfInc not implemented yet.");
}

/* --------- SPARC64AMode: memory address expressions. --------- */

SPARC64AMode *
SPARC64AMode_IR(Int imm, HReg reg)
{
    SPARC64AMode *am = LibVEX_Alloc_inline(sizeof(SPARC64AMode));
    am->tag = Sam_IR;
    am->Sam.IR.imm = imm;
    am->Sam.IR.reg = reg;

    return (am);
}

SPARC64AMode *
SPARC64AMode_RR(HReg reg1, HReg reg2)
{
    SPARC64AMode *am = LibVEX_Alloc_inline(sizeof(SPARC64AMode));
    am->tag = Sam_RR;
    am->Sam.RR.reg1 = reg1;
    am->Sam.RR.reg2 = reg2;

    return (am);
}

void
ppSPARC64AMode(SPARC64AMode *am)
{
    switch (am->tag) {
    case Sam_IR:
        vex_printf("[");
        ppHRegSPARC64(am->Sam.IR.reg);
        if (am->Sam.IR.imm != 0)
            vex_printf(" + %d]", am->Sam.IR.imm);
        else
            vex_printf("]");
        return;
    case Sam_RR:
        ppHRegSPARC64(am->Sam.RR.reg1);
        vex_printf(", ");
        ppHRegSPARC64(am->Sam.RR.reg2);
        return;
    default:
        vpanic("ppSPARC64AMode: unsupported mode");
    }
}

SPARC64Instr *
SPARC64Instr_EvCheck(UInt offFailAddr, UInt offCounter)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_EvCheck;
    i->Sin.EvCheck.offFailAddr = offFailAddr;
    i->Sin.EvCheck.offCounter = offCounter;

    return (i);
}

SPARC64Instr *
SPARC64Instr_ProfInc(void)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_ProfInc;

    return (i);
}

SPARC64Instr *
SPARC64Instr_LoadGuestState(void)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_LoadGuestState;

    return (i);
}

SPARC64Instr *
SPARC64Instr_StoreGuestState(void)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_StoreGuestState;

    return (i);
}

SPARC64Instr *
SPARC64Instr_Unrecognized(UInt instr_bits)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_Unrecognized;
    i->Sin.Unrecognized.instr_bits = instr_bits;

    return (i);
}

SPARC64Instr *
SPARC64Instr_Load(UChar sz, HReg dst, SPARC64AMode *src)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_Load;
    i->Sin.Load.sz = sz;
    i->Sin.Load.dst = dst;
    i->Sin.Load.src = src;
    i->Sin.Load.asi = NULL;
    i->Sin.Load.toFsr = False;

    return (i);
}

SPARC64Instr *
SPARC64Instr_LoadA(UChar sz, HReg dst, SPARC64AMode *src, SPARC64RI *ri_asi)
{
    if (ri_asi->tag == Sri_Imm) {
        vassert(ri_asi->Sri.Imm.simm13 <= SPARC64_SIMM13_MASK);
    }

    SPARC64Instr *i = SPARC64Instr_Load(sz, dst, src);
    i->Sin.Load.asi = ri_asi;

    return (i);
}

SPARC64Instr *
SPARC64Instr_LoadFSR(UChar sz, SPARC64AMode *src)
{
    SPARC64Instr *i = SPARC64Instr_Load(sz, INVALID_HREG, src);
    i->Sin.Load.toFsr = True;

    return (i);
}

SPARC64Instr *
SPARC64Instr_Store(UChar sz, SPARC64AMode *dst, HReg src)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_Store;
    i->Sin.Store.sz = sz;
    i->Sin.Store.dst = dst;
    i->Sin.Store.src = src;
    i->Sin.Store.asi = NULL;
    i->Sin.Store.fromFsr = False;

    return (i);
}

SPARC64Instr *
SPARC64Instr_StoreA(UChar sz, SPARC64AMode *dst, HReg src, SPARC64RI *ri_asi)
{
    if (ri_asi->tag == Sri_Imm) {
        vassert(ri_asi->Sri.Imm.simm13 <= SPARC64_SIMM13_MASK);
    }

    SPARC64Instr *i = SPARC64Instr_Store(sz, dst, src);
    i->Sin.Store.asi = ri_asi;

    return (i);
}

SPARC64Instr *
SPARC64Instr_StoreFSR(UChar sz, SPARC64AMode *dst)
{
    SPARC64Instr *i = SPARC64Instr_Store(sz, dst, INVALID_HREG);
    i->Sin.Store.fromFsr = True;

    return (i);
}

SPARC64Instr *
SPARC64Instr_CAS(UChar sz, HReg addr, HReg src, HReg dst)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_CAS;
    i->Sin.CAS.sz = sz;
    i->Sin.CAS.addr = addr;
    i->Sin.CAS.src = src;
    i->Sin.CAS.dst = dst;

    return (i);
}

SPARC64Instr *
SPARC64Instr_Ldstub(SPARC64AMode *src, HReg dst)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_Ldstub;
    i->Sin.Ldstub.src = src;
    i->Sin.Ldstub.dst = dst;

    return (i);
}

SPARC64Instr *
SPARC64Instr_Lzcnt(HReg dst, HReg srcR)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_Lzcnt;
    i->Sin.Lzcnt.dst = dst;
    i->Sin.Lzcnt.src = srcR;

    return (i);
}

SPARC64Instr *
SPARC64Instr_Membar(void)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_Membar;

    return (i);
}

SPARC64Instr *
SPARC64Instr_ASR(Bool store, UInt dst, HReg srcL, SPARC64RI *srcR)
{
    if ((srcR != NULL) && (srcR->tag == Sri_Imm)) {
        vassert(srcR->Sri.Imm.simm13 <= SPARC64_SIMM13_MASK);
    }

    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_ASR;
    i->Sin.ASR.dst = dst;
    i->Sin.ASR.store = store;
    i->Sin.ASR.srcL = srcL;
    i->Sin.ASR.srcR = srcR;

    return (i);
}

SPARC64Instr *
SPARC64Instr_Alu(SPARC64AluOp op, HReg dst, HReg srcL, SPARC64RI *srcR)
{
    if (srcR->tag == Sri_Imm) {
        vassert(srcR->Sri.Imm.simm13 <= SPARC64_SIMM13_MASK);
    }

    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_Alu;
    i->Sin.Alu.op = op;
    i->Sin.Alu.dst = dst;
    i->Sin.Alu.srcL = srcL;
    i->Sin.Alu.srcR = srcR;

    return (i);
}

SPARC64Instr *
SPARC64Instr_LI(HReg dst, ULong imm)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_LI;
    i->Sin.LI.dst = dst;
    i->Sin.LI.imm = imm;

    return (i);
}

SPARC64Instr *
SPARC64Instr_XDirect(Addr64 dstGA, SPARC64AMode *amPC, SPARC64CondCode cond,
                     Bool toFastEP)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_XDirect;
    i->Sin.XDirect.dstGA = dstGA;
    i->Sin.XDirect.amPC = amPC;
    i->Sin.XDirect.cond = cond;
    i->Sin.XDirect.toFastEP = toFastEP;

    return (i);
}

SPARC64Instr *
SPARC64Instr_XIndir(HReg dstGA, SPARC64AMode *amPC, SPARC64CondCode cond)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_XIndir;
    i->Sin.XIndir.dstGA = dstGA;
    i->Sin.XIndir.amPC = amPC;
    i->Sin.XIndir.cond = cond;

    return (i);
}

SPARC64Instr *
SPARC64Instr_XAssisted(HReg dstGA, SPARC64AMode *amPC, SPARC64CondCode cond,
                       IRJumpKind jk)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_XAssisted;
    i->Sin.XAssisted.dstGA = dstGA;
    i->Sin.XAssisted.amPC = amPC;
    i->Sin.XAssisted.cond = cond;
    i->Sin.XAssisted.jk = jk;

    return (i);
}

SPARC64Instr *
SPARC64Instr_Call(SPARC64CondCode cond, HReg tgt, UInt argiregs,
                  RetLoc rloc)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_Call;
    i->Sin.Call.cond = cond;
    i->Sin.Call.tgt = tgt;
    i->Sin.Call.argiregs = argiregs;
    i->Sin.Call.rloc = rloc;

    vassert(argiregs <= SPARC64_N_REGPARMS);
    vassert(is_sane_RetLoc(rloc));
    return (i);
}

SPARC64Instr *
SPARC64Instr_Shft(SPARC64ShftOp op, HReg dst, HReg srcL, SPARC64RI *srcR)
{
    if (srcR->tag == Sri_Imm) {
        switch (op) {
        case Sshft_SLL:
        case Sshft_SRL:
        case Sshft_SRA:
            vassert(srcR->Sri.Imm.simm13 <= 0x1F);
            break;
        case Sshft_SLLX:
        case Sshft_SRLX:
        case Sshft_SRAX:
            vassert(srcR->Sri.Imm.simm13 <= 0x3F);
            break;
        default:
            vassert(0);
        }
    }

    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_Shft;
    i->Sin.Shft.op = op;
    i->Sin.Shft.dst = dst;
    i->Sin.Shft.srcL = srcL;
    i->Sin.Shft.srcR = srcR;

    return (i);
}

SPARC64Instr *
SPARC64Instr_MoveCond(SPARC64CondCode cond, HReg dst, HReg src)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_MoveCond;
    i->Sin.MoveCond.cond = cond;
    i->Sin.MoveCond.dst = dst;
    i->Sin.MoveCond.src = src;

    return (i);
}

SPARC64Instr *
SPARC64Instr_MoveReg(SPARC64RegCode cond, HReg dst, HReg srcL, SPARC64RI *srcR)
{
    if (srcR->tag == Sri_Imm) {
        vassert(srcR->Sri.Imm.simm13 <= SPARC64_SIMM10_MASK);
    }

    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_MoveReg;
    i->Sin.MoveReg.cond = cond;
    i->Sin.MoveReg.dst = dst;
    i->Sin.MoveReg.srcL = srcL;
    i->Sin.MoveReg.srcR = srcR;

    return (i);
}

SPARC64Instr *
SPARC64Instr_AlignDataFp(HReg dst, HReg srcL, HReg srcR)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_AlignDataFp;
    i->Sin.AlignDataFp.dst = dst;
    i->Sin.AlignDataFp.srcL = srcL;
    i->Sin.AlignDataFp.srcR = srcR;

    return (i);
}

SPARC64Instr *
SPARC64Instr_AluFp(SPARC64AluFpOp op, HReg dst, HReg srcL, HReg srcR)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_AluFp;
    i->Sin.AluFp.op = op;
    i->Sin.AluFp.dst = dst;
    i->Sin.AluFp.srcL = srcL;
    if (op == AluFp_FNOT) {
        vassert(hregIsInvalid(srcR));
    }
    i->Sin.AluFp.srcR = srcR;

    return (i);
}

SPARC64Instr *
SPARC64Instr_AbsFp(HReg dst, HReg src)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_AbsFp;
    i->Sin.AbsFp.dst = dst;
    i->Sin.AbsFp.src = src;

    return (i);
}

SPARC64Instr *
SPARC64Instr_CmpFp(HReg srcL, HReg srcR, UInt fccn)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_CmpFp;
    i->Sin.CmpFp.srcL = srcL;
    i->Sin.CmpFp.srcR = srcR;
    i->Sin.CmpFp.fccn = fccn;

    return (i);
}

SPARC64Instr *
SPARC64Instr_ConvFp(HReg dst, HReg src, Bool fromInt, Bool toInt)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_ConvFp;
    i->Sin.ConvFp.dst = dst;
    i->Sin.ConvFp.src = src;
    i->Sin.ConvFp.fromInt = fromInt;
    i->Sin.ConvFp.toInt = toInt;

    return (i);
}

SPARC64Instr *
SPARC64Instr_FusedFp(SPARC64FusedFpOp op, HReg dst, HReg arg1, HReg arg2,
                     HReg arg3)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_FusedFp;
    i->Sin.FusedFp.op = op;
    i->Sin.FusedFp.dst = dst;
    i->Sin.FusedFp.arg1 = arg1;
    i->Sin.FusedFp.arg2 = arg2;
    i->Sin.FusedFp.arg3 = arg3;

    return (i);
}

SPARC64Instr *
SPARC64Instr_HalveFp(HReg dst, HReg src, Bool highHalf)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_HalveFp;
    i->Sin.HalveFp.dst = dst;
    i->Sin.HalveFp.src = src;
    i->Sin.HalveFp.highHalf = highHalf;

    return (i);
}

SPARC64Instr *
SPARC64Instr_MovIRegToFp(HReg dst, HReg src)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_MovIRegToFp;
    i->Sin.MovIRegToFp.dst = dst;
    i->Sin.MovIRegToFp.src = src;

    return (i);
}

SPARC64Instr *
SPARC64Instr_MovFp(HReg dst, HReg src)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_MovFp;
    i->Sin.MovFp.dst = dst;
    i->Sin.MovFp.src = src;

    return (i);
}

SPARC64Instr *
SPARC64Instr_MovFpICond(SPARC64CondCode cond, HReg dst, HReg src)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_MovFpICond;
    i->Sin.MovFpICond.cond = cond;
    i->Sin.MovFpICond.dst = dst;
    i->Sin.MovFpICond.src = src;

    return (i);
}

SPARC64Instr *
SPARC64Instr_MovFpToIReg(HReg dst, HReg src)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_MovFpToIReg;
    i->Sin.MovFpToIReg.dst = dst;
    i->Sin.MovFpToIReg.src = src;

    return (i);
}

SPARC64Instr *
SPARC64Instr_NegFp(HReg dst, HReg src)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_NegFp;
    i->Sin.NegFp.dst = dst;
    i->Sin.NegFp.src = src;

    return (i);
}

SPARC64Instr *
SPARC64Instr_ShftFp(SPARC64ShftFpOp op, HReg dst, HReg srcL, HReg srcR)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_ShftFp;
    i->Sin.ShftFp.op = op;
    i->Sin.ShftFp.dst = dst;
    i->Sin.ShftFp.srcL = srcL;
    i->Sin.ShftFp.srcR = srcR;

    return (i);
}

SPARC64Instr *
SPARC64Instr_ShuffleFp(HReg dst, HReg srcL, HReg srcR)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_ShuffleFp;
    i->Sin.ShuffleFp.dst = dst;
    i->Sin.ShuffleFp.srcL = srcL;
    i->Sin.ShuffleFp.srcR = srcR;

    return (i);
}

SPARC64Instr *
SPARC64Instr_SqrtFp(HReg dst, HReg src)
{
    SPARC64Instr *i = LibVEX_Alloc_inline(sizeof(SPARC64Instr));
    i->tag = Sin_SqrtFp;
    i->Sin.SqrtFp.dst = dst;
    i->Sin.SqrtFp.src = src;

    return (i);
}

/*----------------------------------------------------------------------------*/
/*--- end                                              host_sparc64_defs.c ---*/
/*----------------------------------------------------------------------------*/
