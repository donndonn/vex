/*--- begin                                               sparc64_disasm.c ---*/
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

#include "sparc64_disasm.h"
#include "libvex.h"
#include "main_util.h"

#include <stdarg.h>

/*----------------------------------------------------------------------------*/
/*--- Disassembly helpers.                                                 ---*/
/*----------------------------------------------------------------------------*/

#define BITS2(b1, b0)                                \
    (((b1) << 1) | (b0))

#define BITS3(b2, b1, b0)                            \
    (((b2) << 2) | ((b1) << 1) | (b0))

#define BITS4(b3, b2, b1, b0)                        \
    (((b3) << 3) | ((b2) << 2) | ((b1) << 1) | (b0))

#define BITS8(b7, b6, b5, b4, b3, b2, b1, b0)        \
    ((BITS4(b7, b6, b5, b4) << 4)                    \
     | BITS4(b3, b2, b1, b0))

#define BITS5(b4, b3, b2, b1, b0)                    \
    (BITS8(0, 0, 0, b4, b3, b2, b1, b0))

#define BITS6(b5, b4, b3, b2, b1, b0)                \
    (BITS8(0, 0, b5, b4, b3, b2, b1, b0))

#define BITS7(b6, b5, b4, b3, b2, b1, b0)            \
    (BITS8(0, b6, b5, b4, b3, b2, b1, b0))

#define BITS9(b8, b7, b6, b5, b4, b3, b2, b1, b0)    \
    ((BITS8(b8, b7, b6, b5, b4, b3, b2, b1) << 1)    \
     | (b0))

/* insn is a 32-bit unsigned value (UInt). */
#define BITS(insn, max, min)                      \
    (((insn) >> (min)) & ((1 << (((max) - (min)) + 1)) - 1))

static inline ULong
se64(ULong x, UChar n)
{
    vassert(n > 1 && n < 64);
    Long r = (Long) x;
    r = (r << (64 - n)) >> (64 - n);
    return (ULong) r;
}

static const HChar *
ireg_name(UInt iregNo)
{
    switch (iregNo) {
    case  0: return "%g0";
    case  1: return "%g1";
    case  2: return "%g2";
    case  3: return "%g3";
    case  4: return "%g4";
    case  5: return "%g5";
    case  6: return "%g6";
    case  7: return "%g7";
    case  8: return "%o0";
    case  9: return "%o1";
    case 10: return "%o2";
    case 11: return "%o3";
    case 12: return "%o4";
    case 13: return "%o5";
    case 14: return "%o6";
    case 15: return "%o7";
    case 16: return "%l0";
    case 17: return "%l1";
    case 18: return "%l2";
    case 19: return "%l3";
    case 20: return "%l4";
    case 21: return "%l5";
    case 22: return "%l6";
    case 23: return "%l7";
    case 24: return "%i0";
    case 25: return "%i1";
    case 26: return "%i2";
    case 27: return "%i3";
    case 28: return "%i4";
    case 29: return "%i5";
    case 30: return "%i6";
    case 31: return "%i7";
    }

    vpanic("Unsupported integer register index.");
}

static const HChar *
asr_name(SPARC64_ASR asr)
{
    switch (asr) {
    case SPARC64_ASR_Y:       return "%y";
    case SPARC64_ASR_CCR:     return "%ccr";
    case SPARC64_ASR_ASI:     return "%asi";
    case SPARC64_ASR_TICK:    return "%tick";
    case SPARC64_ASR_PC:      return "%pc";
    case SPARC64_ASR_FPRS:    return "%fprs";
    case SPARC64_ASR_ENTROPY: return "%entropy";
    case SPARC64_ASR_MCDPER:  return "%mcdper";
    case SPARC64_ASR_GSR:     return "%gsr";
    case SPARC64_ASR_STICK:   return "%stick";
    case SPARC64_ASR_CFR:     return "%cfr";
    case SPARC64_ASR_PAUSE:   return "%pause";
    case SPARC64_ASR_MWAIT:   return "%mwait";
    }

    vpanic("Unsupported ASR register.");
}

static const HChar *
freg32_name(UInt fregNo)
{
    switch (fregNo) {
    case  0: return "%f0";
    case  1: return "%f1";
    case  2: return "%f2";
    case  3: return "%f3";
    case  4: return "%f4";
    case  5: return "%f5";
    case  6: return "%f6";
    case  7: return "%f7";
    case  8: return "%f8";
    case  9: return "%f9";
    case 10: return "%f10";
    case 11: return "%f11";
    case 12: return "%f12";
    case 13: return "%f13";
    case 14: return "%f14";
    case 15: return "%f15";
    case 16: return "%f16";
    case 17: return "%f17";
    case 18: return "%f18";
    case 19: return "%f19";
    case 20: return "%f20";
    case 21: return "%f21";
    case 22: return "%f22";
    case 23: return "%f23";
    case 24: return "%f24";
    case 25: return "%f25";
    case 26: return "%f26";
    case 27: return "%f27";
    case 28: return "%f28";
    case 29: return "%f29";
    case 30: return "%f30";
    case 31: return "%f31";
    default:
        vpanic("Unsupported floating-point register index.");
    }
}

static const HChar *
freg64_name(UInt fregNo)
{
    switch (fregNo) {
    case  0: return "%d0";
    case  2: return "%d2";
    case  4: return "%d4";
    case  6: return "%d6";
    case  8: return "%d8";
    case 10: return "%d10";
    case 12: return "%d12";
    case 14: return "%d14";
    case 16: return "%d16";
    case 18: return "%d18";
    case 20: return "%d20";
    case 22: return "%d22";
    case 24: return "%d24";
    case 26: return "%d26";
    case 28: return "%d28";
    case 30: return "%d30";
    case 32: return "%d32";
    case 34: return "%d34";
    case 36: return "%d36";
    case 38: return "%d38";
    case 40: return "%d40";
    case 42: return "%d42";
    case 44: return "%d44";
    case 46: return "%d46";
    case 48: return "%d48";
    case 50: return "%d50";
    case 52: return "%d52";
    case 54: return "%d54";
    case 56: return "%d56";
    case 58: return "%d58";
    case 60: return "%d60";
    case 62: return "%d62";
    default:
        vpanic("Unsupported floating-point register index.");
    }
}

static const HChar *
freg128_name(UInt fregNo)
{
    switch (fregNo) {
    case  0: return "%q0";
    case  4: return "%q4";
    case  8: return "%q8";
    case 12: return "%q12";
    case 16: return "%q16";
    case 20: return "%q20";
    case 24: return "%q24";
    case 28: return "%q28";
    case 32: return "%q32";
    case 36: return "%q36";
    case 40: return "%q40";
    case 44: return "%q44";
    case 48: return "%q48";
    case 52: return "%q52";
    case 56: return "%q56";
    case 60: return "%q60";
    default:
        vpanic("Unsupported floating-point register index.");
    }
}

const HChar *sparc64_asi_name(SPARC64_ASI asi)
{
    switch (asi) {
    case SPARC64_ASI_PRIMARY:
        return "ASI_PRIMARY";
    case SPARC64_ASI_SECONDARY:
        return "ASI_SECONDARY";
    case SPARC64_ASI_PRIMARY_NO_FAULT:
        return "ASI_PRIMARY_NOFAULT";
    case SPARC64_ASI_FL8_PRIMARY:
        return "ASI_FL8_P";
    case SPARC64_ASI_FL16_PRIMARY:
        return "ASI_FL16_P";
    case SPARC64_ASI_BLOCK_PRIMARY:
        return "ASI_BLK_P";
    default:
        return NULL;
    }
}

static UInt
sprint_bitmask(HChar *buf, HChar separator, const HChar *names[], UInt width,
               UInt bitmask)
{
    vassert(width <= 32);
    vassert(width >= 1);

    Bool include_separator = False;
    UInt nout = 0;

    for (Int bit = width - 1; bit >= 0; bit--) {
        if (bitmask & (1 << bit)) {
            if (include_separator) {
                buf[nout] = separator;
                nout += 1;
            }

            nout += vex_sprintf(buf + nout, "%s", names[bit]);
            include_separator = True;
        }
    }

    return nout;
}

/*----------------------------------------------------------------------------*/
/*--- Operands.                                                            ---*/
/*----------------------------------------------------------------------------*/

#define INSN_FMT_DISP30(insn)               BITS(insn, 29, 0)
#define INSN_FMT_DISP22(insn)               BITS(insn, 21, 0)
#define INSN_FMT_DISP19(insn)               BITS(insn, 18, 0)
#define INSN_FMT_D16_HI(insn)               BITS(insn, 21, 20)
#define INSN_FMT_D16_LO(insn)               BITS(insn, 13, 0)
#define INSN_FMT_DISP16(insn)               ((INSN_FMT_D16_HI(insn) << 14) \
                                            | INSN_FMT_D16_LO(insn))
#define INSN_FMT_D10_HI(insn)               BITS(insn, 20, 19)
#define INSN_FMT_D10_LO(insn)               BITS(insn, 12, 5)
#define INSN_FMT_DISP10(insn)               ((INSN_FMT_D10_HI(insn) << 8) \
                                            | INSN_FMT_D10_LO(insn))
#define INSN_FMT_I(insn)                    BITS(insn, 13, 13)
#define INSN_FMT_RD(insn)                   BITS(insn, 29, 25)
#define INSN_FMT_RS1(insn)                  BITS(insn, 18, 14)
#define INSN_FMT_RS2(insn)                  BITS(insn, 4, 0)
#define INSN_FMT_RS3(insn)                  BITS(insn, 13, 9)
#define INSN_FMT_SHCNT32(insn)              BITS(insn, 4, 0)
#define INSN_FMT_SHCNT64(insn)              BITS(insn, 5, 0)
#define INSN_FMT_SIMM13(insn)               BITS(insn, 12, 0)
#define INSN_FMT_SIMM11(insn)               BITS(insn, 10, 0)
#define INSN_FMT_SIMM10(insn)               BITS(insn, 9, 0)
#define INSN_FMT_SIMM5(insn)                BITS(insn, 4, 0)
#define INSN_FMT_IMM22(insn)                BITS(insn, 21, 0)
#define INSN_FMT_IMM8(insn)                 BITS(insn, 7, 0)
#define INSN_FMT_IMM5(insn)                 BITS(insn, 13, 9)
#define INSN_FMT_IMM_ASI(insn)              BITS(insn, 12, 5)
#define INSN_FMT_X(insn)                    BITS(insn, 12, 12)
#define INSN_FMT_CC0(insn)                  BITS(insn, 11, 11)
#define INSN_FMT_CC1(insn)                  BITS(insn, 12, 12)
#define INSN_FMT_CC2(insn)                  BITS(insn, 18, 18)
#define INSN_FMT_CC_Tcc(insn)               BITS(insn, 12, 11)
#define INSN_FMT_CC_BPcc(insn)              BITS(insn, 21, 20)
#define INSN_FMT_OPF_CC_FMOVcc(insn)        BITS(insn, 13, 11)
#define INSN_FMT_FCCn_FBPfcc(insn)          BITS(insn, 21, 20)
#define INSN_FMT_FCCn_FCMP(insn)            BITS(insn, 26, 25)
#define INSN_FMT_MMASK(insn)                BITS(insn, 3, 0)
#define INSN_FMT_CMASK(insn)                BITS(insn, 6, 4)
#define INSN_FMT_PREFETCH_FCN(insn)         BITS(insn, 29, 25)
#define INSN_FMT_ANNUL(insn)                BITS(insn, 29, 29)
#define INSN_FMT_PREDICTION(insn)           BITS(insn, 19, 19)


/* Forward declaration. */
static const sparc64_operand sparc64_operands[SPARC64_OP_TYPE_LAST];

static Bool
sparc64_cmp_opvalue(sparc64_operand_vex_type vex_type, sparc64_operand_value a,
                    sparc64_operand_value b)
{
    switch (vex_type) {
    case SPARC64_OP_VEX_TYPE_INT:
        return (a.intval == b.intval) ? True : False;
    case SPARC64_OP_VEX_TYPE_UINT:
        return (a.uintval == b.uintval) ? True : False;
    case SPARC64_OP_VEX_TYPE_LONG:
        return (a.longval == b.longval) ? True : False;
    case SPARC64_OP_VEX_TYPE_ULONG:
        return (a.ulongval == b.ulongval) ? True : False;
    default:
        vassert(0);
    }
}

/* -------------------------- Integer registers ----------------------------- */
static const sparc64_operand *
decode_ireg_rs1(UInt insn, const sparc64_operand *op_in,
                sparc64_operand_value *value)
{
    value->uintval = INSN_FMT_RS1(insn);
    return &sparc64_operands[SPARC64_OP_TYPE_IREG_RS1];
}

static UInt
encode_ireg_rs1(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval < 32);

    return (value.uintval & 0x1F) << 14;
}

static UInt
sprint_ireg(HChar *buf, sparc64_operand_value value)
{
    vassert(value.uintval < 32);

    return vex_sprintf(buf, "%s", ireg_name(value.uintval));
}

static const sparc64_operand *
decode_ireg_rs2(UInt insn, const sparc64_operand *op_in,
                sparc64_operand_value *value)
{
    value->uintval = INSN_FMT_RS2(insn);
    return &sparc64_operands[SPARC64_OP_TYPE_IREG_RS2];
}

static UInt
encode_ireg_rs2(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval < 32);

    return (value.uintval & 0x1F);
}

static const sparc64_operand *
decode_ireg_rd(UInt insn, const sparc64_operand *op_in,
                sparc64_operand_value *value)
{
    value->uintval = INSN_FMT_RD(insn);
    return &sparc64_operands[SPARC64_OP_TYPE_IREG_RD];
}

static UInt
encode_ireg_rd(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval < 32);

    return (value.uintval & 0x1F) << 25;
}

static const sparc64_operand *
decode_ireg_rdin(UInt insn, const sparc64_operand *op_in,
                  sparc64_operand_value *value)
{
    value->uintval = INSN_FMT_RD(insn);
    return &sparc64_operands[SPARC64_OP_TYPE_IREG_RDIN];
}

static const sparc64_operand *
decode_ireg_rdinout(UInt insn, const sparc64_operand *op_in,
                    sparc64_operand_value *value)
{
    value->uintval = INSN_FMT_RD(insn);
    return &sparc64_operands[SPARC64_OP_TYPE_IREG_RDINOUT];
}

/* ----------------------- Floating-point registers ------------------------- */
static inline UInt
decode_freg64(UInt fregNo)
{
    return ((fregNo >> 1) | ((fregNo & 0x01) << 4)) << 1;
}

static inline UInt
decode_freg128(UInt fregNo)
{
    return ((fregNo >> 2) | ((fregNo & 0x01) << 3)) << 2;
}

static inline UInt
encode_freg64_128(UInt fregNo)
{
    UInt b5 = fregNo & 0x20;
    return (fregNo & ~0x20) | (b5 ? 0x1 : 0);
}

static const sparc64_operand *
decode_freg32_rs1(UInt insn, const sparc64_operand *op_in,
                  sparc64_operand_value *value)
{
    value->uintval = INSN_FMT_RS1(insn);
    return &sparc64_operands[SPARC64_OP_TYPE_FREG32_RS1];
}

static UInt
encode_freg32_rs1(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval < 32);

    return (value.uintval & 0x1F) << 14;
}

static const sparc64_operand *
decode_freg64_rs1(UInt insn, const sparc64_operand *op_in,
                  sparc64_operand_value *value)
{
    value->uintval = decode_freg64(INSN_FMT_RS1(insn));
    return &sparc64_operands[SPARC64_OP_TYPE_FREG64_RS1];
}

static UInt
encode_freg64_rs1(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval < 64);
    vassert(value.uintval % 2 == 0);

    return (encode_freg64_128(value.uintval & 0x3F)) << 14;
}

static const sparc64_operand *
decode_freg128_rs1(UInt insn, const sparc64_operand *op_in,
                  sparc64_operand_value *value)
{
    value->uintval = decode_freg128(INSN_FMT_RS1(insn));
    return &sparc64_operands[SPARC64_OP_TYPE_FREG128_RS1];
}

static UInt
encode_freg128_rs1(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval < 64);
    vassert(value.uintval % 4 == 0);

    return (encode_freg64_128(value.uintval & 0x3F)) << 14;
}

static const sparc64_operand *
decode_freg32_rs2(UInt insn, const sparc64_operand *op_in,
                  sparc64_operand_value *value)
{
    value->uintval = INSN_FMT_RS2(insn);
    return &sparc64_operands[SPARC64_OP_TYPE_FREG32_RS2];
}

static UInt
encode_freg32_rs2(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval < 32);

    return (value.uintval & 0x1F);
}

static const sparc64_operand *
decode_freg64_rs2(UInt insn, const sparc64_operand *op_in,
                  sparc64_operand_value *value)
{
    value->uintval = decode_freg64(INSN_FMT_RS2(insn));
    return &sparc64_operands[SPARC64_OP_TYPE_FREG64_RS2];
}

static UInt
encode_freg64_rs2(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval < 64);
    vassert(value.uintval % 2 == 0);

    return encode_freg64_128(value.uintval & 0x3F);
}

static const sparc64_operand *
decode_freg128_rs2(UInt insn, const sparc64_operand *op_in,
                  sparc64_operand_value *value)
{
    value->uintval = decode_freg128(INSN_FMT_RS2(insn));
    return &sparc64_operands[SPARC64_OP_TYPE_FREG128_RS2];
}

static UInt
encode_freg128_rs2(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval < 64);
    vassert(value.uintval % 4 == 0);

    return encode_freg64_128(value.uintval & 0x3F);
}

static const sparc64_operand *
decode_freg32_rs3(UInt insn, const sparc64_operand *op_in,
                  sparc64_operand_value *value)
{
    value->uintval = INSN_FMT_RS3(insn);
    return &sparc64_operands[SPARC64_OP_TYPE_FREG32_RS3];
}

static UInt
encode_freg32_rs3(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval < 32);

    return (value.uintval & 0x1F) << 9;
}

static const sparc64_operand *
decode_freg64_rs3(UInt insn, const sparc64_operand *op_in,
                  sparc64_operand_value *value)
{
    value->uintval = decode_freg64(INSN_FMT_RS3(insn));
    return &sparc64_operands[SPARC64_OP_TYPE_FREG64_RS3];
}

static UInt
encode_freg64_rs3(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval < 64);
    vassert(value.uintval % 2 == 0);

    return (encode_freg64_128(value.uintval & 0x3F)) << 9;
}

static const sparc64_operand *
decode_freg32_rd(UInt insn, const sparc64_operand *op_in,
                 sparc64_operand_value *value)
{
    value->uintval = INSN_FMT_RD(insn);
    return &sparc64_operands[SPARC64_OP_TYPE_FREG32_RD];
}

static UInt
encode_freg32_rd(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval < 32);

    return (value.uintval & 0x1F) << 25;
}

static const sparc64_operand *
decode_freg64_rd(UInt insn, const sparc64_operand *op_in,
                 sparc64_operand_value *value)
{
    value->uintval = decode_freg64(INSN_FMT_RD(insn));
    return &sparc64_operands[SPARC64_OP_TYPE_FREG64_RD];
}

static UInt
encode_freg64_rd(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval < 64);
    vassert(value.uintval % 2 == 0);

    return (encode_freg64_128(value.uintval & 0x3F)) << 25;
}

static const sparc64_operand *
decode_freg128_rd(UInt insn, const sparc64_operand *op_in,
                  sparc64_operand_value *value)
{
    value->uintval = decode_freg128(INSN_FMT_RD(insn));
    return &sparc64_operands[SPARC64_OP_TYPE_FREG128_RD];
}

static UInt
encode_freg128_rd(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval < 64);
    vassert(value.uintval % 4 == 0);

    return (encode_freg64_128(value.uintval & 0x3F)) << 25;
}

static const sparc64_operand *
decode_freg32_rdin(UInt insn, const sparc64_operand *op_in,
                   sparc64_operand_value *value)
{
    value->uintval = INSN_FMT_RD(insn);
    return &sparc64_operands[SPARC64_OP_TYPE_FREG32_RDIN];
}

static const sparc64_operand *
decode_freg64_rdin(UInt insn, const sparc64_operand *op_in,
                   sparc64_operand_value *value)
{
    value->uintval = decode_freg64(INSN_FMT_RD(insn));
    return &sparc64_operands[SPARC64_OP_TYPE_FREG64_RDIN];
}

static const sparc64_operand *
decode_freg128_rdin(UInt insn, const sparc64_operand *op_in,
                    sparc64_operand_value *value)
{
    value->uintval = decode_freg128(INSN_FMT_RD(insn));
    return &sparc64_operands[SPARC64_OP_TYPE_FREG128_RDIN];
}

static UInt
sprint_freg32(HChar *buf, sparc64_operand_value value)
{
    vassert(value.uintval < 32);

    return vex_sprintf(buf, "%s", freg32_name(value.uintval));
}

static UInt
sprint_freg64(HChar *buf, sparc64_operand_value value)
{
    vassert(value.uintval < 64);

    return vex_sprintf(buf, "%s", freg64_name(value.uintval));
}

static UInt
sprint_freg128(HChar *buf, sparc64_operand_value value)
{
    vassert(value.uintval < 64);

    return vex_sprintf(buf, "%s", freg128_name(value.uintval));
}

/* ------------------------------ Immediates -------------------------------- */
static const sparc64_operand *
decode_simm13(UInt insn, const sparc64_operand *op_in,
             sparc64_operand_value *value)
{
    value->longval = se64(INSN_FMT_SIMM13(insn), 13);
    return &sparc64_operands[SPARC64_OP_TYPE_SIMM13];
}

static UInt
encode_simm13(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.longval >= -0x1000);
    vassert(value.longval <= +0x0FFF);

    return (1 << 13) | (value.longval & 0x1FFF);
}

static UInt
sprint_simm13(HChar *buf, sparc64_operand_value value)
{
    vassert(value.longval >= -0x1000);
    vassert(value.longval <= +0x0FFF);

    return vex_sprintf(buf, "%c0x%llx", (value.longval < 0) ? '-' : '+',
                       (value.longval < 0) ? -value.longval : value.longval);
}

static const sparc64_operand *
decode_simm11(UInt insn, const sparc64_operand *op_in,
             sparc64_operand_value *value)
{
    value->longval = se64(INSN_FMT_SIMM11(insn), 11);
    return &sparc64_operands[SPARC64_OP_TYPE_SIMM11];
}

static UInt
encode_simm11(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.longval >= -0x400);
    vassert(value.longval <= +0x3FF);

    return (1 << 13) | (value.longval & 0x7FF);
}

static UInt
sprint_simm11(HChar *buf, sparc64_operand_value value)
{
    vassert(value.longval >= -0x400);
    vassert(value.longval <= +0x3FF);

    return vex_sprintf(buf, "%c0x%llx", (value.longval < 0) ? '-' : '+',
                       (value.longval < 0) ? -value.longval : value.longval);
}

static const sparc64_operand *
decode_simm10(UInt insn, const sparc64_operand *op_in,
             sparc64_operand_value *value)
{
    value->longval = se64(INSN_FMT_SIMM10(insn), 10);
    return &sparc64_operands[SPARC64_OP_TYPE_SIMM10];
}

static UInt
encode_simm10(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.longval >= -0x200);
    vassert(value.longval <= +0x1FF);

    return (1 << 13) | (value.longval & 0x3FF);
}

static UInt
sprint_simm10(HChar *buf, sparc64_operand_value value)
{
    vassert(value.longval >= -0x200);
    vassert(value.longval <= +0x1FF);

    return vex_sprintf(buf, "%c0x%llx", (value.longval < 0) ? '-' : '+',
                       (value.longval < 0) ? -value.longval : value.longval);
}

static const sparc64_operand *
decode_simm5(UInt insn, const sparc64_operand *op_in,
             sparc64_operand_value *value)
{
    value->longval = se64(INSN_FMT_SIMM5(insn), 5);
    return &sparc64_operands[SPARC64_OP_TYPE_SIMM5];
}

static UInt
encode_simm5(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.longval >= -0x10);
    vassert(value.longval <= +0x0F);

    return (1 << 13) | (value.longval & 0x1F);
}

static UInt
sprint_simm5(HChar *buf, sparc64_operand_value value)
{
    vassert(value.longval >= -0x10);
    vassert(value.longval <= +0x0F);

    return vex_sprintf(buf, "%c0x%llx", (value.longval < 0) ? '-' : '+',
                       (value.longval < 0) ? -value.longval : value.longval);
}

static const sparc64_operand *
decode_imm22(UInt insn, const sparc64_operand *op_in,
             sparc64_operand_value *value)
{
    value->ulongval = INSN_FMT_IMM22(insn) << 10;
    return &sparc64_operands[SPARC64_OP_TYPE_IMM22];
}

static UInt
encode_imm22(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.ulongval <= 0xFFFFFFFFULL);
    vassert((value.ulongval & 0x3FF) == 0);

    return (value.ulongval >> 10) & 0x3FFFFF;
}

static UInt
sprint_imm22(HChar *buf, sparc64_operand_value value)
{
    vassert(value.ulongval <= 0xFFFFFFFFULL);
    vassert((value.ulongval & 0x3FF) == 0);

    return vex_sprintf(buf, "%%hi(0x%llx)", value.ulongval);
}

static const sparc64_operand *
decode_imm8(UInt insn, const sparc64_operand *op_in,
            sparc64_operand_value *value)
{
    value->ulongval = INSN_FMT_IMM8(insn);
    return &sparc64_operands[SPARC64_OP_TYPE_IMM8];
}

static UInt
encode_imm8(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.ulongval <= 0xFF);

    return (1 << 13) | (value.ulongval & 0xFF);
}

static UInt
sprint_imm8(HChar *buf, sparc64_operand_value value)
{
    vassert(value.ulongval <= 0xFF);

    return vex_sprintf(buf, "0x%llx", value.ulongval);
}

static const sparc64_operand *
decode_imm5(UInt insn, const sparc64_operand *op_in,
            sparc64_operand_value *value)
{
    value->ulongval = INSN_FMT_IMM5(insn);
    return &sparc64_operands[SPARC64_OP_TYPE_IMM5];
}

static UInt
encode_imm5(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.ulongval <= 0x1F);

    return (value.ulongval & 0x1F) << 9;
}

static UInt
sprint_imm5(HChar *buf, sparc64_operand_value value)
{
    vassert(value.ulongval <= 0x1F);

    return vex_sprintf(buf, "0x%llx", value.ulongval);
}

static const sparc64_operand *
decode_asi_imm(UInt insn, const sparc64_operand *op_in,
               sparc64_operand_value *value)
{
    value->uintval = INSN_FMT_IMM_ASI(insn);
    return &sparc64_operands[SPARC64_OP_TYPE_ASI_IMM];
}

static UInt
encode_asi_imm(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval <= 0xFF);

    return (value.uintval & 0xFF) << 5;
}

static UInt
sprint_asi_imm(HChar *buf, sparc64_operand_value value)
{
    vassert(value.uintval <= 0xFF);

    const HChar *asi_name = sparc64_asi_name(value.uintval);
    if (asi_name != NULL) {
        return vex_sprintf(buf, "#%s", asi_name);
    } else {
        return vex_sprintf(buf, "0x%x", value.uintval);
    }
}

static const sparc64_operand *
decode_asi_impl(UInt insn, const sparc64_operand *op_in,
               sparc64_operand_value *value)
{
    value->uintval = 0;
    return &sparc64_operands[SPARC64_OP_TYPE_ASI_IMPL];
}

static UInt
encode_asi_impl(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval == 0);

    return (1 << 13);
}

static UInt
sprint_asi_impl(HChar *buf, sparc64_operand_value value)
{
    vassert(value.uintval == 0);

    return vex_sprintf(buf, "%%asi");
}

static const sparc64_operand *
decode_disp30(UInt insn, const sparc64_operand *op_in,
              sparc64_operand_value *value)
{
    value->longval = 4 * se64(INSN_FMT_DISP30(insn), 30);
    return &sparc64_operands[SPARC64_OP_TYPE_DISP30];
}

static UInt
encode_disp30(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.longval % 4 == 0);

    long encoded = value.longval / 4;
    vassert(encoded >= -0x20000000);
    vassert(encoded <=  0x1FFFFFFF);

    return (encoded & 0x3FFFFFFF);
}

static UInt
sprint_disp30(HChar *buf, sparc64_operand_value value)
{
    vassert(value.longval >= -0x80000000LL);
    vassert(value.longval <=  0x7FFFFFFFLL);

    return vex_sprintf(buf, "%c0x%llx", (value.longval < 0) ? '-' : '+',
                       (value.longval < 0) ? -value.longval : value.longval);
}

static const sparc64_operand *
decode_disp22(UInt insn, const sparc64_operand *op_in,
              sparc64_operand_value *value)
{
    value->longval = 4 * se64(INSN_FMT_DISP22(insn), 22);
    return &sparc64_operands[SPARC64_OP_TYPE_DISP22];
}

static UInt
encode_disp22(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.longval % 4 == 0);

    long encoded = value.longval / 4;
    vassert(encoded >= -0x200000);
    vassert(encoded <=  0x1FFFFF);

    return (encoded & 0x3FFFFF);
}

static UInt
sprint_disp22(HChar *buf, sparc64_operand_value value)
{
    vassert(value.longval >= -0x800000LL);
    vassert(value.longval <=  0x7FFFFFLL);

    return vex_sprintf(buf, "%c0x%llx", (value.longval < 0) ? '-' : '+',
                       (value.longval < 0) ? -value.longval : value.longval);
}

static const sparc64_operand *
decode_disp19(UInt insn, const sparc64_operand *op_in,
              sparc64_operand_value *value)
{
    value->longval = 4 * se64(INSN_FMT_DISP19(insn), 19);
    return &sparc64_operands[SPARC64_OP_TYPE_DISP19];
}

static UInt
encode_disp19(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.longval % 4 == 0);

    long encoded = value.longval / 4;
    vassert(encoded >= -0x40000);
    vassert(encoded <=  0x3FFFF);

    return (encoded & 0x7FFFF);
}

static UInt
sprint_disp19(HChar *buf, sparc64_operand_value value)
{
    vassert(value.longval >= -0x100000LL);
    vassert(value.longval <=  0x0FFFFFLL);

    return vex_sprintf(buf, "%c0x%llx", (value.longval < 0) ? '-' : '+',
                       (value.longval < 0) ? -value.longval : value.longval);
}

static const sparc64_operand *
decode_disp16(UInt insn, const sparc64_operand *op_in,
              sparc64_operand_value *value)
{
    value->longval = 4 * se64(INSN_FMT_DISP16(insn), 16);
    return &sparc64_operands[SPARC64_OP_TYPE_DISP16];
}

static UInt
encode_disp16(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.longval % 4 == 0);

    long encoded = value.longval / 4;
    vassert(encoded >= -0x8000);
    vassert(encoded <=  0x7FFF);

    encoded &= 0xFFFF;
    return ((encoded >> 14) << 20) | (encoded & 0x3FFF);
}

static UInt
sprint_disp16(HChar *buf, sparc64_operand_value value)
{
    vassert(value.longval >= -0x20000LL);
    vassert(value.longval <=  0x1FFFFLL);

    return vex_sprintf(buf, "%c0x%llx", (value.longval < 0) ? '-' : '+',
                       (value.longval < 0) ? -value.longval : value.longval);
}

static const sparc64_operand *
decode_disp10(UInt insn, const sparc64_operand *op_in,
              sparc64_operand_value *value)
{
    value->longval = 4 * se64(INSN_FMT_DISP10(insn), 10);
    return &sparc64_operands[SPARC64_OP_TYPE_DISP10];
}

static UInt
encode_disp10(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.longval % 4 == 0);

    long encoded = value.longval / 4;
    vassert(encoded >= -0x200);
    vassert(encoded <=  0x1FF);

    encoded &= 0x3FF;
    return ((encoded >> 8) << 19) | ((encoded & 0xFF) << 5);
}

static UInt
sprint_disp10(HChar *buf, sparc64_operand_value value)
{
    vassert(value.longval >= -0x800LL);
    vassert(value.longval <=  0x7FFLL);

    return vex_sprintf(buf, "%c0x%llx", (value.longval < 0) ? '-' : '+',
                       (value.longval < 0) ? -value.longval : value.longval);
}

static const sparc64_operand *
decode_shcnt32(UInt insn, const sparc64_operand *op_in,
               sparc64_operand_value *value)
{
    value->uintval = INSN_FMT_SHCNT32(insn);
    return &sparc64_operands[SPARC64_OP_TYPE_SHCNT32];
}

static UInt
encode_shcnt32(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval < 32);

    return (1 << 13) | (value.uintval & 0x1F);
}

static UInt
sprint_shcnt32(HChar *buf, sparc64_operand_value value)
{
    vassert(value.uintval < 32);

    return vex_sprintf(buf, "%u", value.uintval);
}

static const sparc64_operand *
decode_shcnt64(UInt insn, const sparc64_operand *op_in,
               sparc64_operand_value *value)
{
    value->uintval = INSN_FMT_SHCNT64(insn);
    return &sparc64_operands[SPARC64_OP_TYPE_SHCNT64];
}

static UInt
encode_shcnt64(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval < 64);

    return (1 << 13) | (value.uintval & 0x3F);
}

static UInt
sprint_shcnt64(HChar *buf, sparc64_operand_value value)
{
    vassert(value.uintval < 64);

    return vex_sprintf(buf, "%u", value.uintval);
}

static const sparc64_operand *
decode_i_or_x_cc_BPcc(UInt insn, const sparc64_operand *op_in,
                      sparc64_operand_value *value)
{
    UInt i_cc = INSN_FMT_CC_BPcc(insn);

    if (i_cc == 0) {
        value->uintval = 0;
    } else if (i_cc == 2) {
        value->uintval = 1;
    } else {
        vpanic("Unsupported cond code");
    }
    return &sparc64_operands[SPARC64_OP_TYPE_I_OR_X_CC_BPcc];
}

static UInt
encode_i_or_x_cc_BPcc(const sparc64_operand *operand,
                      sparc64_operand_value value)
{
    vassert(value.uintval <= 1);

    if (value.uintval == 0) {
        return 0;
    } else {
        return (1 << 21);
    }
}

static UInt
sprint_i_or_x_cc(HChar *buf, sparc64_operand_value value)
{
    vassert(value.uintval <= 1);

    return vex_sprintf(buf, "%s", (value.uintval == 0) ? "%icc" : "%xcc");
}

static const sparc64_operand *
decode_i_or_x_cc_FMOVcc(UInt insn, const sparc64_operand *op_in,
                        sparc64_operand_value *value)
{
    UInt icc_xcc = INSN_FMT_OPF_CC_FMOVcc(insn);

    value->uintval = (icc_xcc & 2) >> 1;
    vassert((value->uintval == 0) || (value->uintval == 1));

    return &sparc64_operands[SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc];
}

static UInt
encode_i_or_x_cc_FMOVcc(const sparc64_operand *operand,
                        sparc64_operand_value value)
{
    vassert((value.uintval == 0) || (value.uintval == 1));

    return (1 << 13) | ((value.uintval & 0x1) << (11 + 1));
}

static const sparc64_operand *
decode_i_or_x_cc_MOVcc(UInt insn, const sparc64_operand *op_in,
                       sparc64_operand_value *value)
{
    vassert(INSN_FMT_CC2(insn) == 1);

    switch (INSN_FMT_CC0(insn)) {
    case 0:
        value->uintval = INSN_FMT_CC1(insn);
        break;
    default:
        vpanic("Unsupported MOVcc code");
    }
    vassert((value->uintval == 0) || (value->uintval == 1));

    return &sparc64_operands[SPARC64_OP_TYPE_I_OR_X_CC_MOVcc];
}

static UInt
encode_i_or_x_cc_MOVcc(const sparc64_operand *operand,
                       sparc64_operand_value value)
{
    vassert((value.uintval == 0) || (value.uintval == 1));

    return (value.uintval & 0x1) << (11 + 1);
}

static const sparc64_operand *
decode_i_or_x_cc_Tcc(UInt insn, const sparc64_operand *op_in,
                       sparc64_operand_value *value)
{
    UInt i_cc = INSN_FMT_CC_Tcc(insn);

    if (i_cc == 0) {
        value->uintval = 0;
    } else if (i_cc == 2) {
        value->uintval = 1;
    } else {
        vpanic("Unsupported cond code");
    }
    return &sparc64_operands[SPARC64_OP_TYPE_I_OR_X_CC_Tcc];
}

static UInt
encode_i_or_x_cc_Tcc(const sparc64_operand *operand,
                     sparc64_operand_value value)
{
    vassert(value.uintval <= 1);

    if (value.uintval == 0) {
        return 0;
    } else {
        return (1 << 12);
    }
}

static const sparc64_operand *
decode_fccn_FBPFcc(UInt insn, const sparc64_operand *op_in,
                   sparc64_operand_value *value)
{
    value->uintval = INSN_FMT_FCCn_FBPfcc(insn);
    vassert(value->uintval <= 3);

    return &sparc64_operands[SPARC64_OP_TYPE_FCCn_FBPfcc];
}

static UInt
encode_fccn_FBPFcc(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval <= 3);

    return ((value.uintval & 0x3) << 20);
}

static UInt
sprint_fccn(HChar *buf, sparc64_operand_value value)
{
    vassert(value.uintval <= 3);

    return vex_sprintf(buf, "%%fcc%u", value.uintval);
}

static const sparc64_operand *
decode_fccn_FCMP(UInt insn, const sparc64_operand *op_in,
                 sparc64_operand_value *value)
{
    value->uintval = INSN_FMT_FCCn_FCMP(insn);
    vassert(value->uintval <= 3);

    return &sparc64_operands[SPARC64_OP_TYPE_FCCn_FCMP];
}

static UInt
encode_fccn_FCMP(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval <= 3);

    return ((value.uintval & 0x3) << 25);
}

static const sparc64_operand *
decode_fccn_FMOVcc(UInt insn, const sparc64_operand *op_in,
                   sparc64_operand_value *value)
{
    value->uintval = INSN_FMT_OPF_CC_FMOVcc(insn) & 0x3;
    vassert(value->uintval <= 3);

    return &sparc64_operands[SPARC64_OP_TYPE_FCCn_FMOVcc];
}

static UInt
encode_fccn_FMOVcc(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval <= 3);

    return ((value.uintval & 0x3) << 11);
}

static const sparc64_operand *
decode_fccn_MOVcc(UInt insn, const sparc64_operand *op_in,
                  sparc64_operand_value *value)
{
    vassert(INSN_FMT_CC2(insn) == 0);

    value->uintval = (INSN_FMT_CC1(insn) << 1) | INSN_FMT_CC0(insn);
    vassert(value->uintval <= 3);

    return &sparc64_operands[SPARC64_OP_TYPE_FCCn_MOVcc];
}

static UInt
encode_fccn_MOVcc(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval <= 3);

    return ((value.uintval & 0x3) << 11);
}

static const sparc64_operand *
decode_mmask(UInt insn, const sparc64_operand *op_in,
             sparc64_operand_value *value)
{
    value->uintval = INSN_FMT_MMASK(insn);
    return &sparc64_operands[SPARC64_OP_TYPE_MMASK];
}

static UInt
encode_mmask(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval < 16);

    return (value.uintval & 0xf);
}

static UInt
sprint_mmask(HChar *buf, sparc64_operand_value value)
{
    vassert(value.uintval < 16);

    const HChar *names[] = {"#LoadLoad", "#StoreLoad", "#LoadStore",
                            "#StoreStore"};
    return sprint_bitmask(buf, '|', names, 4, value.uintval);
}

static const sparc64_operand *
decode_cmask(UInt insn, const sparc64_operand *op_in,
             sparc64_operand_value *value)
{
    value->uintval = INSN_FMT_CMASK(insn);
    return &sparc64_operands[SPARC64_OP_TYPE_CMASK];
}

static UInt
encode_cmask(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval < 8);

    return (value.uintval & 0x7) << 4;
}

static UInt
sprint_cmask(HChar *buf, sparc64_operand_value value)
{
    vassert(value.uintval < 8);

    const HChar *names[] = {"#Lookaside", "#MemIssue", "#Sync"};
    return sprint_bitmask(buf, '|', names, 3, value.uintval);
}

static const sparc64_operand *
decode_prefetch_fcn(UInt insn, const sparc64_operand *op_in,
                    sparc64_operand_value *value)
{
    value->uintval = INSN_FMT_PREFETCH_FCN(insn);
    return &sparc64_operands[SPARC64_OP_TYPE_PREFETCH_FCN];
}

static UInt
encode_prefetch_fcn(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval < 32);

    return (value.uintval & 0x1f) << 25;
}

static UInt
sprint_prefetch_fcn(HChar *buf, sparc64_operand_value value)
{
    vassert(value.uintval < 32);

    return vex_sprintf(buf, "%u", value.uintval);
}

static const sparc64_operand *
decode_annul(UInt insn, const sparc64_operand *op_in,
             sparc64_operand_value *value)
{
    value->uintval = INSN_FMT_ANNUL(insn);
    return &sparc64_operands[SPARC64_OP_TYPE_ANNUL];
}

static UInt
encode_annul(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval <= 1);

    if (value.uintval == 0) {
        return 0;
    } else {
        return (1 << 29);
    }
}

static UInt
sprint_annul(HChar *buf, sparc64_operand_value value)
{
    vassert(value.uintval <= 1);

    if (value.uintval == 0) {
        buf[0] = '\0';
        return 0;
    } else {
        return vex_sprintf(buf, ",a");
    }
}

static const sparc64_operand *
decode_prediction(UInt insn, const sparc64_operand *op_in,
                  sparc64_operand_value *value)
{
    value->uintval = INSN_FMT_PREDICTION(insn);
    return &sparc64_operands[SPARC64_OP_TYPE_PREDICTION];
}

static UInt
encode_prediction(const sparc64_operand *operand, sparc64_operand_value value)
{
    vassert(value.uintval <= 1);

    if (value.uintval == 0) {
        return 0;
    } else {
        return (1 << 19);
    }
}

static UInt
sprint_prediction(HChar *buf, sparc64_operand_value value)
{
    vassert(value.uintval <= 1);

    return vex_sprintf(buf, (value.uintval == 0) ? "pt" : "pn");
}


static const sparc64_operand *
decode_rs2_or_simm13(UInt insn, const sparc64_operand *op_in,
                     sparc64_operand_value *value)
{
    if (INSN_FMT_I(insn) == 0) {
        return decode_ireg_rs2(insn, op_in, value);
    } else {
        return decode_simm13(insn, op_in, value);
    }
}

static const sparc64_operand *
decode_rs2_or_simm11(UInt insn, const sparc64_operand *op_in,
                     sparc64_operand_value *value)
{
    if (INSN_FMT_I(insn) == 0) {
        return decode_ireg_rs2(insn, op_in, value);
    } else {
        return decode_simm11(insn, op_in, value);
    }
}

static const sparc64_operand *
decode_rs2_or_simm10(UInt insn, const sparc64_operand *op_in,
                     sparc64_operand_value *value)
{
    if (INSN_FMT_I(insn) == 0) {
        return decode_ireg_rs2(insn, op_in, value);
    } else {
        return decode_simm10(insn, op_in, value);
    }
}

static const sparc64_operand *
decode_rs2_or_simm5(UInt insn, const sparc64_operand *op_in,
                    sparc64_operand_value *value)
{
    if (INSN_FMT_I(insn) == 0) {
        return decode_ireg_rs2(insn, op_in, value);
    } else {
        return decode_simm5(insn, op_in, value);
    }
}

static const sparc64_operand *
decode_rs2_or_imm8(UInt insn, const sparc64_operand *op_in,
                   sparc64_operand_value *value)
{
    if (INSN_FMT_I(insn) == 0) {
        return decode_ireg_rs2(insn, op_in, value);
    } else {
        return decode_imm8(insn, op_in, value);
    }
}

static const sparc64_operand *
decode_rs2_or_shcnt32(UInt insn, const sparc64_operand *op_in,
                      sparc64_operand_value *value)
{
    if (INSN_FMT_I(insn) == 0) {
        return decode_ireg_rs2(insn, op_in, value);
    } else {
        return decode_shcnt32(insn, op_in, value);
    }
}

static const sparc64_operand *
decode_rs2_or_shcnt64(UInt insn, const sparc64_operand *op_in,
                      sparc64_operand_value *value)
{
    if (INSN_FMT_I(insn) == 0) {
        return decode_ireg_rs2(insn, op_in, value);
    } else {
        return decode_shcnt64(insn, op_in, value);
    }
}

static const sparc64_operand *
decode_asi_impl_or_imm(UInt insn, const sparc64_operand *op_in,
                       sparc64_operand_value *value)
{
    if (INSN_FMT_I(insn) == 0) {
        return decode_asi_imm(insn, op_in, value);
    } else {
        return decode_asi_impl(insn, op_in, value);
    }
}

/* Array of sparc64 operands sorted according to sparc64_operand_type enum. */
static const sparc64_operand sparc64_operands[SPARC64_OP_TYPE_LAST] = {
{SPARC64_OP_TYPE_FIRST, SPARC64_OP_KIND_META, SPARC64_OP_VEX_TYPE_NONE,
 1, 0, 0, 0, 0, 0, NULL, NULL, NULL},
{SPARC64_OP_TYPE_RS2_OR_SIMM13, SPARC64_OP_KIND_META, SPARC64_OP_VEX_TYPE_NONE,
 1, 0, 0, 0, 0, 0, decode_rs2_or_simm13, NULL, NULL},
{SPARC64_OP_TYPE_RS2_OR_SIMM11, SPARC64_OP_KIND_META, SPARC64_OP_VEX_TYPE_NONE,
 1, 0, 0, 0, 0, 0, decode_rs2_or_simm11, NULL, NULL},
{SPARC64_OP_TYPE_RS2_OR_SIMM10, SPARC64_OP_KIND_META, SPARC64_OP_VEX_TYPE_NONE,
 1, 0, 0, 0, 0, 0, decode_rs2_or_simm10, NULL, NULL},
{SPARC64_OP_TYPE_RS2_OR_SIMM5, SPARC64_OP_KIND_META, SPARC64_OP_VEX_TYPE_NONE,
 1, 0, 0, 0, 0, 0, decode_rs2_or_simm5, NULL, NULL},
{SPARC64_OP_TYPE_RS2_OR_IMM8, SPARC64_OP_KIND_META, SPARC64_OP_VEX_TYPE_NONE,
 1, 0, 0, 0, 0, 0, decode_rs2_or_imm8, NULL, NULL},
{SPARC64_OP_TYPE_RS2_OR_SHCNT32, SPARC64_OP_KIND_META, SPARC64_OP_VEX_TYPE_NONE,
 1, 0, 0, 0, 0, 0, decode_rs2_or_shcnt32, NULL, NULL},
{SPARC64_OP_TYPE_RS2_OR_SHCNT64, SPARC64_OP_KIND_META, SPARC64_OP_VEX_TYPE_NONE,
 1, 0, 0, 0, 0, 0, decode_rs2_or_shcnt64, NULL, NULL},
{SPARC64_OP_TYPE_ASI_IMPL_OR_IMM, SPARC64_OP_KIND_META, SPARC64_OP_VEX_TYPE_NONE,
 1, 0, 0, 0, 0, 0, decode_asi_impl_or_imm, NULL, NULL},
{SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_KIND_IREG, SPARC64_OP_VEX_TYPE_UINT,
 0, 5, 0, 1, 0, 0, decode_ireg_rs1, encode_ireg_rs1, sprint_ireg},
{SPARC64_OP_TYPE_IREG_RS2, SPARC64_OP_KIND_IREG, SPARC64_OP_VEX_TYPE_UINT,
 0, 5, 0, 1, 0, 0, decode_ireg_rs2, encode_ireg_rs2, sprint_ireg},
{SPARC64_OP_TYPE_IREG_RD, SPARC64_OP_KIND_IREG, SPARC64_OP_VEX_TYPE_UINT,
 0, 5, 0, 0, 1, 0, decode_ireg_rd, encode_ireg_rd, sprint_ireg},
{SPARC64_OP_TYPE_IREG_RDIN, SPARC64_OP_KIND_IREG, SPARC64_OP_VEX_TYPE_UINT,
 0, 5, 0, 1, 0, 0, decode_ireg_rdin, encode_ireg_rd, sprint_ireg},
{SPARC64_OP_TYPE_IREG_RDINOUT, SPARC64_OP_KIND_IREG, SPARC64_OP_VEX_TYPE_UINT,
 0, 5, 0, 1, 1, 0, decode_ireg_rdinout, encode_ireg_rd, sprint_ireg},
{SPARC64_OP_TYPE_FREG32_RS1, SPARC64_OP_KIND_FREG, SPARC64_OP_VEX_TYPE_UINT,
 0, 6, 0, 1, 0, SPARC64_OP_SIZE_FREG32, decode_freg32_rs1, encode_freg32_rs1,
 sprint_freg32},
{SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_KIND_FREG, SPARC64_OP_VEX_TYPE_UINT,
 0, 6, 0, 1, 0, SPARC64_OP_SIZE_FREG64, decode_freg64_rs1, encode_freg64_rs1,
 sprint_freg64},
{SPARC64_OP_TYPE_FREG128_RS1, SPARC64_OP_KIND_FREG, SPARC64_OP_VEX_TYPE_UINT,
 0, 6, 0, 1, 0, SPARC64_OP_SIZE_FREG128, decode_freg128_rs1, encode_freg128_rs1,
 sprint_freg128},
{SPARC64_OP_TYPE_FREG32_RS2, SPARC64_OP_KIND_FREG, SPARC64_OP_VEX_TYPE_UINT,
 0, 6, 0, 1, 0, SPARC64_OP_SIZE_FREG32, decode_freg32_rs2, encode_freg32_rs2,
 sprint_freg32},
{SPARC64_OP_TYPE_FREG64_RS2, SPARC64_OP_KIND_FREG, SPARC64_OP_VEX_TYPE_UINT,
 0, 6, 0, 1, 0, SPARC64_OP_SIZE_FREG64, decode_freg64_rs2, encode_freg64_rs2,
 sprint_freg64},
{SPARC64_OP_TYPE_FREG128_RS2, SPARC64_OP_KIND_FREG, SPARC64_OP_VEX_TYPE_UINT,
 0, 6, 0, 1, 0, SPARC64_OP_SIZE_FREG128, decode_freg128_rs2, encode_freg128_rs2,
 sprint_freg128},
{SPARC64_OP_TYPE_FREG32_RS3, SPARC64_OP_KIND_FREG, SPARC64_OP_VEX_TYPE_UINT,
 0, 6, 0, 1, 0, SPARC64_OP_SIZE_FREG32, decode_freg32_rs3, encode_freg32_rs3,
 sprint_freg32},
{SPARC64_OP_TYPE_FREG64_RS3, SPARC64_OP_KIND_FREG, SPARC64_OP_VEX_TYPE_UINT,
 0, 6, 0, 1, 0, SPARC64_OP_SIZE_FREG64, decode_freg64_rs3, encode_freg64_rs3,
 sprint_freg64},
{SPARC64_OP_TYPE_FREG32_RD, SPARC64_OP_KIND_FREG, SPARC64_OP_VEX_TYPE_UINT,
 0, 6, 0, 0, 1, SPARC64_OP_SIZE_FREG32, decode_freg32_rd, encode_freg32_rd,
 sprint_freg32},
{SPARC64_OP_TYPE_FREG64_RD, SPARC64_OP_KIND_FREG, SPARC64_OP_VEX_TYPE_UINT,
 0, 6, 0, 0, 1, SPARC64_OP_SIZE_FREG64, decode_freg64_rd, encode_freg64_rd,
 sprint_freg64},
{SPARC64_OP_TYPE_FREG128_RD, SPARC64_OP_KIND_FREG, SPARC64_OP_VEX_TYPE_UINT,
 0, 6, 0, 0, 1, SPARC64_OP_SIZE_FREG128, decode_freg128_rd, encode_freg128_rd,
 sprint_freg128},
{SPARC64_OP_TYPE_FREG32_RDIN, SPARC64_OP_KIND_FREG, SPARC64_OP_VEX_TYPE_UINT,
 0, 6, 0, 1, 0, SPARC64_OP_SIZE_FREG32, decode_freg32_rdin, encode_freg32_rd,
 sprint_freg32},
{SPARC64_OP_TYPE_FREG64_RDIN, SPARC64_OP_KIND_FREG, SPARC64_OP_VEX_TYPE_UINT,
 0, 6, 0, 1, 0, SPARC64_OP_SIZE_FREG64, decode_freg64_rdin, encode_freg64_rd,
 sprint_freg64},
{SPARC64_OP_TYPE_FREG128_RDIN, SPARC64_OP_KIND_FREG, SPARC64_OP_VEX_TYPE_UINT,
 0, 6, 0, 1, 0, SPARC64_OP_SIZE_FREG128, decode_freg128_rdin, encode_freg128_rd,
 sprint_freg128},
{SPARC64_OP_TYPE_SIMM13, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_LONG,
 0, 13, 1, 1, 0, 0, decode_simm13, encode_simm13, sprint_simm13},
{SPARC64_OP_TYPE_SIMM11, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_LONG,
 0, 11, 1, 1, 0, 0, decode_simm11, encode_simm11, sprint_simm11},
{SPARC64_OP_TYPE_SIMM10, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_LONG,
 0, 10, 1, 1, 0, 0, decode_simm10, encode_simm10, sprint_simm10},
{SPARC64_OP_TYPE_SIMM5, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_LONG,
 0, 5, 1, 1, 0, 0, decode_simm5, encode_simm5, sprint_simm5},
{SPARC64_OP_TYPE_IMM22, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_ULONG,
 0, 22, 0, 1, 0, 0, decode_imm22, encode_imm22, sprint_imm22},
{SPARC64_OP_TYPE_IMM8, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_ULONG,
 0, 8, 0, 1, 0, 0, decode_imm8, encode_imm8, sprint_imm8},
{SPARC64_OP_TYPE_IMM5, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_ULONG,
 0, 5, 0, 1, 0, 0, decode_imm5, encode_imm5, sprint_imm5},
{SPARC64_OP_TYPE_ASI_IMPL, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_UINT,
 0, 0, 0, 1, 0, 0, decode_asi_impl, encode_asi_impl, sprint_asi_impl},
{SPARC64_OP_TYPE_ASI_IMM, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_UINT,
 0, 8, 0, 1, 0, 0, decode_asi_imm, encode_asi_imm, sprint_asi_imm},
{SPARC64_OP_TYPE_DISP30, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_LONG,
 0, 32, 1, 1, 0, 0, decode_disp30, encode_disp30, sprint_disp30},
{SPARC64_OP_TYPE_DISP22, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_LONG,
 0, 24, 1, 1, 0, 0, decode_disp22, encode_disp22, sprint_disp22},
{SPARC64_OP_TYPE_DISP19, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_LONG,
 0, 21, 1, 1, 0, 0, decode_disp19, encode_disp19, sprint_disp19},
{SPARC64_OP_TYPE_DISP16, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_LONG,
 0, 18, 1, 1, 0, 0, decode_disp16, encode_disp16, sprint_disp16},
{SPARC64_OP_TYPE_DISP10, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_LONG,
 0, 11, 1, 1, 0, 0, decode_disp10, encode_disp10, sprint_disp10},
{SPARC64_OP_TYPE_SHCNT32, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_UINT,
 0, 5, 0, 1, 0, 0, decode_shcnt32, encode_shcnt32, sprint_shcnt32},
{SPARC64_OP_TYPE_SHCNT64, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_UINT,
 0, 6, 0, 1, 0, 0, decode_shcnt64, encode_shcnt64, sprint_shcnt64},
{SPARC64_OP_TYPE_I_OR_X_CC_BPcc, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_UINT,
 0, 1, 0, 1, 0, 0, decode_i_or_x_cc_BPcc, encode_i_or_x_cc_BPcc,
 sprint_i_or_x_cc},
{SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_UINT,
 0, 1, 0, 1, 0, 0, decode_i_or_x_cc_FMOVcc, encode_i_or_x_cc_FMOVcc,
 sprint_i_or_x_cc},
{SPARC64_OP_TYPE_I_OR_X_CC_MOVcc, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_UINT,
 0, 1, 0, 1, 0, 0, decode_i_or_x_cc_MOVcc, encode_i_or_x_cc_MOVcc,
 sprint_i_or_x_cc},
{SPARC64_OP_TYPE_I_OR_X_CC_Tcc, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_UINT,
 0, 1, 0, 1, 0, 0, decode_i_or_x_cc_Tcc, encode_i_or_x_cc_Tcc,
 sprint_i_or_x_cc},
{SPARC64_OP_TYPE_FCCn_FBPfcc, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_UINT,
 0, 2, 0, 1, 0, 0, decode_fccn_FBPFcc, encode_fccn_FBPFcc, sprint_fccn},
{SPARC64_OP_TYPE_FCCn_FCMP, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_UINT,
 0, 2, 0, 1, 0, 0, decode_fccn_FCMP, encode_fccn_FCMP, sprint_fccn},
{SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_UINT,
 0, 2, 0, 1, 0, 0, decode_fccn_FMOVcc, encode_fccn_FMOVcc, sprint_fccn},
{SPARC64_OP_TYPE_FCCn_MOVcc, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_UINT,
 0, 2, 0, 1, 0, 0, decode_fccn_MOVcc, encode_fccn_MOVcc, sprint_fccn},
{SPARC64_OP_TYPE_MMASK, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_UINT,
 0, 4, 0, 1, 0, 0, decode_mmask, encode_mmask, sprint_mmask},
{SPARC64_OP_TYPE_CMASK, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_UINT,
 0, 3, 0, 1, 0, 0, decode_cmask, encode_cmask, sprint_cmask},
{SPARC64_OP_TYPE_PREFETCH_FCN, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_UINT,
 0, 5, 0, 1, 0, 0, decode_prefetch_fcn, encode_prefetch_fcn,
 sprint_prefetch_fcn},
{SPARC64_OP_TYPE_ANNUL, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_UINT,
 0, 1, 0, 1, 0, 0, decode_annul, encode_annul, sprint_annul},
{SPARC64_OP_TYPE_PREDICTION, SPARC64_OP_KIND_IMM, SPARC64_OP_VEX_TYPE_UINT,
 0, 1, 0, 1, 0, 0, decode_prediction, encode_prediction, sprint_prediction}
};

/*----------------------------------------------------------------------------*/
/*--- Instructions.                                                        ---*/
/*----------------------------------------------------------------------------*/

/* Forward declaration. */
static const sparc64_opcode sparc64_opcodes[SPARC64_OPC_LAST];

/* Bicc, BPcc, CBcond, FMOVcc(icc), MOVcc(icc), and Tcc condition codes. */
enum
{
    I_COND_A   = BITS4(1, 0, 0, 0),
    I_COND_N   = BITS4(0, 0, 0, 0),
    I_COND_NE  = BITS4(1, 0, 0, 1),
    I_COND_E   = BITS4(0, 0, 0, 1),
    I_COND_G   = BITS4(1, 0, 1, 0),
    I_COND_LE  = BITS4(0, 0, 1, 0),
    I_COND_GE  = BITS4(1, 0, 1, 1),
    I_COND_L   = BITS4(0, 0, 1, 1),
    I_COND_GU  = BITS4(1, 1, 0, 0),
    I_COND_LEU = BITS4(0, 1, 0, 0),
    I_COND_CC  = BITS4(1, 1, 0, 1),
    I_COND_CS  = BITS4(0, 1, 0, 1),
    I_COND_POS = BITS4(1, 1, 1, 0),
    I_COND_NEG = BITS4(0, 1, 1, 0),
    I_COND_VC  = BITS4(1, 1, 1, 1),
    I_COND_VS  = BITS4(0, 1, 1, 1)
} I_COND;

/* BPr and MOVr condition codes. */
enum
{
    I_RCOND_Z   = BITS3(0, 0, 1),
    I_RCOND_LEZ = BITS3(0, 1, 0),
    I_RCOND_LZ  = BITS3(0, 1, 1),
    I_RCOND_NZ  = BITS3(1, 0, 1),
    I_RCOND_GZ  = BITS3(1, 1, 0),
    I_RCOND_GEZ = BITS3(1, 1, 1)
} I_RCOND;

/* FBfcc, FBPfcc, FMOVcc(fcc), and MOVcc(fcc) condition codes. */
enum
{
    F_COND_A   = BITS4(1, 0, 0, 0),
    F_COND_N   = BITS4(0, 0, 0, 0),
    F_COND_U   = BITS4(0, 1, 1, 1),
    F_COND_G   = BITS4(0, 1, 1, 0),
    F_COND_UG  = BITS4(0, 1, 0, 1),
    F_COND_L   = BITS4(0, 1, 0, 0),
    F_COND_UL  = BITS4(0, 0, 1, 1),
    F_COND_LG  = BITS4(0, 0, 1, 0),
    F_COND_NE  = BITS4(0, 0, 0, 1),
    F_COND_E   = BITS4(1, 0, 0, 1),
    F_COND_UE  = BITS4(1, 0, 1, 0),
    F_COND_GE  = BITS4(1, 0, 1, 1),
    F_COND_UGE = BITS4(1, 1, 0, 0),
    F_COND_LE  = BITS4(1, 1, 0, 1),
    F_COND_ULE = BITS4(1, 1, 1, 0),
    F_COND_O   = BITS4(1, 1, 1, 1)
} F_COND;

/*----------------------------------------------------------------------------*/
/*--- Disassembly of branch and sethi/nop instructions.                    ---*/
/*----------------------------------------------------------------------------*/

static const sparc64_opcode *
find_opcode_Bicc(UInt insn)
{
    UInt i_cond = BITS(insn, 28, 25); /* same as for BPcc, MOVcc and Tcc */

    switch (i_cond) {
    case I_COND_A:
        return &sparc64_opcodes[SPARC64_OPC_BA];
    case I_COND_N:
        return &sparc64_opcodes[SPARC64_OPC_BN];
    case I_COND_NE:
        return &sparc64_opcodes[SPARC64_OPC_BNE];
    case I_COND_E:
        return &sparc64_opcodes[SPARC64_OPC_BE];
    case I_COND_G:
        return &sparc64_opcodes[SPARC64_OPC_BG];
    case I_COND_LE:
        return &sparc64_opcodes[SPARC64_OPC_BLE];
    case I_COND_GE:
        return &sparc64_opcodes[SPARC64_OPC_BGE];
    case I_COND_L:
        return &sparc64_opcodes[SPARC64_OPC_BL];
    case I_COND_GU:
        return &sparc64_opcodes[SPARC64_OPC_BGU];
    case I_COND_LEU:
        return &sparc64_opcodes[SPARC64_OPC_BLEU];
    case I_COND_CC:
        return &sparc64_opcodes[SPARC64_OPC_BCC];
    case I_COND_CS:
        return &sparc64_opcodes[SPARC64_OPC_BCS];
    case I_COND_POS:
        return &sparc64_opcodes[SPARC64_OPC_BPOS];
    case I_COND_NEG:
        return &sparc64_opcodes[SPARC64_OPC_BNEG];
    case I_COND_VC:
        return &sparc64_opcodes[SPARC64_OPC_BVC];
    case I_COND_VS:
        return &sparc64_opcodes[SPARC64_OPC_BVS];
    default:
        vassert(0);
    }
}

static const sparc64_opcode *
find_opcode_BPcc(UInt insn)
{
    UInt i_cond = BITS(insn, 28, 25); /* same as for Bicc, MOVcc and Tcc */

    switch (i_cond) {
    case I_COND_A:
        return &sparc64_opcodes[SPARC64_OPC_BPA];
    case I_COND_N:
        return &sparc64_opcodes[SPARC64_OPC_BPN];
    case I_COND_NE:
        return &sparc64_opcodes[SPARC64_OPC_BPNE];
    case I_COND_E:
        return &sparc64_opcodes[SPARC64_OPC_BPE];
    case I_COND_G:
        return &sparc64_opcodes[SPARC64_OPC_BPG];
    case I_COND_LE:
        return &sparc64_opcodes[SPARC64_OPC_BPLE];
    case I_COND_GE:
        return &sparc64_opcodes[SPARC64_OPC_BPGE];
    case I_COND_L:
        return &sparc64_opcodes[SPARC64_OPC_BPL];
    case I_COND_GU:
        return &sparc64_opcodes[SPARC64_OPC_BPGU];
    case I_COND_LEU:
        return &sparc64_opcodes[SPARC64_OPC_BPLEU];
    case I_COND_CC:
        return &sparc64_opcodes[SPARC64_OPC_BPCC];
    case I_COND_CS:
        return &sparc64_opcodes[SPARC64_OPC_BPCS];
    case I_COND_POS:
        return &sparc64_opcodes[SPARC64_OPC_BPPOS];
    case I_COND_NEG:
        return &sparc64_opcodes[SPARC64_OPC_BPNEG];
    case I_COND_VC:
        return &sparc64_opcodes[SPARC64_OPC_BPVC];
    case I_COND_VS:
        return &sparc64_opcodes[SPARC64_OPC_BPVS];
    default:
        vassert(0);
    }
}

static const sparc64_opcode *
find_opcode_BPr(UInt insn)
{
    UInt i_rcond = BITS(insn, 27, 25);

    switch (i_rcond) {
    case I_RCOND_Z:
        return &sparc64_opcodes[SPARC64_OPC_BRZ];
    case I_RCOND_LEZ:
        return &sparc64_opcodes[SPARC64_OPC_BRLEZ];
    case I_RCOND_LZ:
        return &sparc64_opcodes[SPARC64_OPC_BRLZ];
    case I_RCOND_NZ:
        return &sparc64_opcodes[SPARC64_OPC_BRNZ];
    case I_RCOND_GZ:
        return &sparc64_opcodes[SPARC64_OPC_BRGZ];
    case I_RCOND_GEZ:
        return &sparc64_opcodes[SPARC64_OPC_BRGEZ];
    default:
        vpanic("Invalid BPr opcode");
    }
}

static const sparc64_opcode *
find_opcode_CBcond(UInt insn)
{
    UInt i_cond = (BITS(insn, 29, 29) << 3) | BITS(insn, 27, 25);

    switch (BITS(insn, 21, 21)) {
    case 0:
        switch (i_cond) {
        case I_COND_A:
            vpanic("Invalid CBcond opcode");
        case I_COND_N:
            vpanic("Invalid CBcond opcode");
        case I_COND_NE:
            return &sparc64_opcodes[SPARC64_OPC_CWBNE];
        case I_COND_E:
            return &sparc64_opcodes[SPARC64_OPC_CWBE];
        case I_COND_G:
            return &sparc64_opcodes[SPARC64_OPC_CWBG];
        case I_COND_LE:
            return &sparc64_opcodes[SPARC64_OPC_CWBLE];
        case I_COND_GE:
            return &sparc64_opcodes[SPARC64_OPC_CWBGE];
        case I_COND_L:
            return &sparc64_opcodes[SPARC64_OPC_CWBL];
        case I_COND_GU:
            return &sparc64_opcodes[SPARC64_OPC_CWBGU];
        case I_COND_LEU:
            return &sparc64_opcodes[SPARC64_OPC_CWBLEU];
        case I_COND_CC:
            return &sparc64_opcodes[SPARC64_OPC_CWBCC];
        case I_COND_CS:
            return &sparc64_opcodes[SPARC64_OPC_CWBCS];
        case I_COND_POS:
            return &sparc64_opcodes[SPARC64_OPC_CWBPOS];
        case I_COND_NEG:
            return &sparc64_opcodes[SPARC64_OPC_CWBNEG];
        case I_COND_VC:
            return &sparc64_opcodes[SPARC64_OPC_CWBVC];
        case I_COND_VS:
            return &sparc64_opcodes[SPARC64_OPC_CWBVS];
        default:
            vassert(0);
        }
        break;
    case 1:
        switch (i_cond) {
        case I_COND_A:
            vpanic("Invalid CBcond opcode");
        case I_COND_N:
            vpanic("Invalid CBcond opcode");
        case I_COND_NE:
            return &sparc64_opcodes[SPARC64_OPC_CXBNE];
        case I_COND_E:
            return &sparc64_opcodes[SPARC64_OPC_CXBE];
        case I_COND_G:
            return &sparc64_opcodes[SPARC64_OPC_CXBG];
        case I_COND_LE:
            return &sparc64_opcodes[SPARC64_OPC_CXBLE];
        case I_COND_GE:
            return &sparc64_opcodes[SPARC64_OPC_CXBGE];
        case I_COND_L:
            return &sparc64_opcodes[SPARC64_OPC_CXBL];
        case I_COND_GU:
            return &sparc64_opcodes[SPARC64_OPC_CXBGU];
        case I_COND_LEU:
            return &sparc64_opcodes[SPARC64_OPC_CXBLEU];
        case I_COND_CC:
            return &sparc64_opcodes[SPARC64_OPC_CXBCC];
        case I_COND_CS:
            return &sparc64_opcodes[SPARC64_OPC_CXBCS];
        case I_COND_POS:
            return &sparc64_opcodes[SPARC64_OPC_CXBPOS];
        case I_COND_NEG:
            return &sparc64_opcodes[SPARC64_OPC_CXBNEG];
        case I_COND_VC:
            return &sparc64_opcodes[SPARC64_OPC_CXBVC];
        case I_COND_VS:
            return &sparc64_opcodes[SPARC64_OPC_CXBVS];
        default:
            vassert(0);
        }
        break;
    default:
        vassert(0);
    }
}

static const sparc64_opcode *
find_opcode_FBPfcc(UInt insn)
{
    UInt f_cond = BITS(insn, 28, 25);

    switch (f_cond) {
    case F_COND_A:
        return &sparc64_opcodes[SPARC64_OPC_FBPA];
    case F_COND_N:
        return &sparc64_opcodes[SPARC64_OPC_FBPN];
    case F_COND_U:
        return &sparc64_opcodes[SPARC64_OPC_FBPU];
    case F_COND_G:
        return &sparc64_opcodes[SPARC64_OPC_FBPG];
    case F_COND_UG:
        return &sparc64_opcodes[SPARC64_OPC_FBPUG];
    case F_COND_L:
        return &sparc64_opcodes[SPARC64_OPC_FBPL];
    case F_COND_UL:
        return &sparc64_opcodes[SPARC64_OPC_FBPUL];
    case F_COND_LG:
        return &sparc64_opcodes[SPARC64_OPC_FBPLG];
    case F_COND_NE:
        return &sparc64_opcodes[SPARC64_OPC_FBPNE];
    case F_COND_E:
        return &sparc64_opcodes[SPARC64_OPC_FBPE];
    case F_COND_UE:
        return &sparc64_opcodes[SPARC64_OPC_FBPUE];
    case F_COND_GE:
        return &sparc64_opcodes[SPARC64_OPC_FBPGE];
    case F_COND_UGE:
        return &sparc64_opcodes[SPARC64_OPC_FBPUGE];
    case F_COND_LE:
        return &sparc64_opcodes[SPARC64_OPC_FBPLE];
    case F_COND_ULE:
        return &sparc64_opcodes[SPARC64_OPC_FBPULE];
    case F_COND_O:
        return &sparc64_opcodes[SPARC64_OPC_FBPO];
    default:
        vassert(0);
    }
}

/* op3 codes for branches (LDST) instructions with op=0. */
enum
{
    I_OP3_ILLTRAP    =       BITS3(0, 0, 0),
    I_OP3_BPcc       =       BITS3(0, 0, 1),
    I_OP3_Bicc       =       BITS3(0, 1, 0),
    I_OP3_BPr_CBcond =       BITS3(0, 1, 1),
    I_OP3_SETHI_NOP  =       BITS3(1, 0, 0),
    I_OP3_FBPfcc     =       BITS3(1, 0, 1),
    I_OP3_FBfcc      =       BITS3(1, 1, 0),
    I_OP3_RESERVED_1 =       BITS3(1, 1, 1),
} I_OP3_FMT_BRANCH;

static const sparc64_opcode *
find_opcode_op0(UInt insn)
{
    /* TODO-SPARC: perhaps use a jump table with some exceptions? */
    switch (BITS(insn, 24, 22)) {
    case I_OP3_ILLTRAP:
        vpanic("Unimplemented - illtrap");
        break;
    case I_OP3_BPcc:
        return find_opcode_BPcc(insn);
    case I_OP3_Bicc:
        return find_opcode_Bicc(insn);
    case I_OP3_BPr_CBcond:
        switch (BITS(insn, 28, 28)) {
        case 0:
            return find_opcode_BPr(insn);
        case 1:
            return find_opcode_CBcond(insn);
        default:
            vassert(0);
        }
    case I_OP3_SETHI_NOP:
        if (INSN_FMT_RD(insn) == 0) {
            if (INSN_FMT_IMM22(insn) == 0) {
                return &sparc64_opcodes[SPARC64_OPC_NOP];
            } else {
                vpanic("Invalid SETHI/NOP opcode");
            }
        } else {
            return &sparc64_opcodes[SPARC64_OPC_SETHI];
        }
    case I_OP3_FBPfcc:
        return find_opcode_FBPfcc(insn);
    case I_OP3_FBfcc:
        vpanic("Unimplemented - FBfcc");
        break;
    case I_OP3_RESERVED_1:
        vpanic("Unimplemented - reserved");
        break;
    default:
        vassert(0);
    }
}

/*----------------------------------------------------------------------------*/
/*--- Disassembly of arithmetic, logic & miscellaneous instructions.       ---*/
/*----------------------------------------------------------------------------*/

static const sparc64_opcode *
find_opcode_MOVr(UInt insn)
{
    UInt i_rcond = BITS(insn, 12, 10);

    switch (i_rcond) {
    case I_RCOND_Z:
        return &sparc64_opcodes[SPARC64_OPC_MOVRZ];
    case I_RCOND_LEZ:
        return &sparc64_opcodes[SPARC64_OPC_MOVRLEZ];
    case I_RCOND_LZ:
        return &sparc64_opcodes[SPARC64_OPC_MOVRLZ];
    case I_RCOND_NZ:
        return &sparc64_opcodes[SPARC64_OPC_MOVRNZ];
    case I_RCOND_GZ:
        return &sparc64_opcodes[SPARC64_OPC_MOVRGZ];
    case I_RCOND_GEZ:
        return &sparc64_opcodes[SPARC64_OPC_MOVRGEZ];
    default:
        return NULL;
    }
}

static const sparc64_opcode *
find_opcode_RDasr_MEMBAR(UInt insn)
{
    UInt i_rs1 = INSN_FMT_RS1(insn);

    switch (i_rs1) {
    case SPARC64_ASR_Y:
        return &sparc64_opcodes[SPARC64_OPC_RDY];
    case SPARC64_ASR_CCR:
        return &sparc64_opcodes[SPARC64_OPC_RDCCR];
    case SPARC64_ASR_ASI:
        return &sparc64_opcodes[SPARC64_OPC_RDASI];
    case SPARC64_ASR_TICK:
        return &sparc64_opcodes[SPARC64_OPC_RDTICK];
    case SPARC64_ASR_PC:
        return &sparc64_opcodes[SPARC64_OPC_RDPC];
    case SPARC64_ASR_FPRS:
        return &sparc64_opcodes[SPARC64_OPC_RDFPRS];
    case SPARC64_ASR_ENTROPY:
        return &sparc64_opcodes[SPARC64_OPC_RDENTROPY];
    case SPARC64_ASR_MCDPER:
        return &sparc64_opcodes[SPARC64_OPC_RDMCDPER];
    case SPARC64_ASR_GSR:
        return &sparc64_opcodes[SPARC64_OPC_RDGSR];
    case SPARC64_ASR_STICK:
        return &sparc64_opcodes[SPARC64_OPC_RDSTICK];
    case SPARC64_ASR_CFR:
        return &sparc64_opcodes[SPARC64_OPC_RDCFR];
    case 15:
        return &sparc64_opcodes[SPARC64_OPC_MEMBAR];
    default:
        vpanic("Invalid RDasr opcode");
    }
}

static const sparc64_opcode *
find_opcode_WRasr(UInt insn)
{
    UInt i_rd = INSN_FMT_RD(insn);

    switch (i_rd) {
    case SPARC64_ASR_Y:
        return &sparc64_opcodes[SPARC64_OPC_WRY];
    case SPARC64_ASR_CCR:
        return &sparc64_opcodes[SPARC64_OPC_WRCCR];
    case SPARC64_ASR_ASI:
        return &sparc64_opcodes[SPARC64_OPC_WRASI];
    case SPARC64_ASR_FPRS:
        return &sparc64_opcodes[SPARC64_OPC_WRFPRS];
    case SPARC64_ASR_MCDPER:
        return &sparc64_opcodes[SPARC64_OPC_WRMCDPER];
    case SPARC64_ASR_GSR:
        return &sparc64_opcodes[SPARC64_OPC_WRGSR];
    case SPARC64_ASR_PAUSE:
        return &sparc64_opcodes[SPARC64_OPC_WRPAUSE];
    case SPARC64_ASR_MWAIT:
        return &sparc64_opcodes[SPARC64_OPC_WRMWAIT];
    default:
        vpanic("Invalid WRasr opcode");
    }
}

static const sparc64_opcode *
find_opcode_Tcc(UInt insn)
{
    UInt i_cond = BITS(insn, 28, 25); /* same as for BPcc, Bicc and MOVcc */

    switch (i_cond) {
    case I_COND_A:
        return &sparc64_opcodes[SPARC64_OPC_TA];
    case I_COND_N:
        return &sparc64_opcodes[SPARC64_OPC_TN];
    case I_COND_NE:
        return &sparc64_opcodes[SPARC64_OPC_TNE];
    case I_COND_E:
        return &sparc64_opcodes[SPARC64_OPC_TE];
    case I_COND_G:
        return &sparc64_opcodes[SPARC64_OPC_TG];
    case I_COND_LE:
        return &sparc64_opcodes[SPARC64_OPC_TLE];
    case I_COND_GE:
        return &sparc64_opcodes[SPARC64_OPC_TGE];
    case I_COND_L:
        return &sparc64_opcodes[SPARC64_OPC_TL];
    case I_COND_GU:
        return &sparc64_opcodes[SPARC64_OPC_TGU];
    case I_COND_LEU:
        return &sparc64_opcodes[SPARC64_OPC_TLEU];
    case I_COND_CC:
        return &sparc64_opcodes[SPARC64_OPC_TCC];
    case I_COND_CS:
        return &sparc64_opcodes[SPARC64_OPC_TCS];
    case I_COND_POS:
        return &sparc64_opcodes[SPARC64_OPC_TPOS];
    case I_COND_NEG:
        return &sparc64_opcodes[SPARC64_OPC_TNEG];
    case I_COND_VC:
        return &sparc64_opcodes[SPARC64_OPC_TVC];
    case I_COND_VS:
        return &sparc64_opcodes[SPARC64_OPC_TVS];
    default:
        vassert(0);
    }
}

/* FPop1 opf codes. */
enum
{
    I_FMOVs  = BITS9(0, 0, 0, 0, 0, 0, 0, 0, 1),
    I_FMOVd  = BITS9(0, 0, 0, 0, 0, 0, 0, 1, 0),
    I_FMOVq  = BITS9(0, 0, 0, 0, 0, 0, 0, 1, 1),
    I_FNEGs  = BITS9(0, 0, 0, 0, 0, 0, 1, 0, 1),
    I_FNEGd  = BITS9(0, 0, 0, 0, 0, 0, 1, 1, 0),
    I_FNEGq  = BITS9(0, 0, 0, 0, 0, 0, 1, 1, 1),
    I_FABSs  = BITS9(0, 0, 0, 0, 0, 1, 0, 0, 1),
    I_FABSd  = BITS9(0, 0, 0, 0, 0, 1, 0, 1, 0),
    I_FABSq  = BITS9(0, 0, 0, 0, 0, 1, 0, 1, 1),
    I_FSQRTs = BITS9(0, 0, 0, 1, 0, 1, 0, 0, 1),
    I_FSQRTd = BITS9(0, 0, 0, 1, 0, 1, 0, 1, 0),
    I_FSQRTq = BITS9(0, 0, 0, 1, 0, 1, 0, 1, 1),
    I_FADDs  = BITS9(0, 0, 1, 0, 0, 0, 0, 0, 1),
    I_FADDd  = BITS9(0, 0, 1, 0, 0, 0, 0, 1, 0),
    I_FADDq  = BITS9(0, 0, 1, 0, 0, 0, 0, 1, 1),
    I_FSUBs  = BITS9(0, 0, 1, 0, 0, 0, 1, 0, 1),
    I_FSUBd  = BITS9(0, 0, 1, 0, 0, 0, 1, 1, 0),
    I_FSUBq  = BITS9(0, 0, 1, 0, 0, 0, 1, 1, 1),
    I_FMULs  = BITS9(0, 0, 1, 0, 0, 1, 0, 0, 1),
    I_FMULd  = BITS9(0, 0, 1, 0, 0, 1, 0, 1, 0),
    I_FMULq  = BITS9(0, 0, 1, 0, 0, 1, 0, 1, 1),
    I_FsMULd = BITS9(0, 0, 1, 1, 0, 1, 0, 0, 1),
    I_FdMULq = BITS9(0, 0, 1, 1, 0, 1, 1, 1, 0),
    I_FDIVs  = BITS9(0, 0, 1, 0, 0, 1, 1, 0, 1),
    I_FDIVd  = BITS9(0, 0, 1, 0, 0, 1, 1, 1, 0),
    I_FDIVq  = BITS9(0, 0, 1, 0, 0, 1, 1, 1, 1),
    I_FsTOx  = BITS9(0, 1, 0, 0, 0, 0, 0, 0, 1),
    I_FdTOx  = BITS9(0, 1, 0, 0, 0, 0, 0, 1, 0),
    I_FqTOx  = BITS9(0, 1, 0, 0, 0, 0, 0, 1, 1),
    I_FxTOs  = BITS9(0, 1, 0, 0, 0, 0, 1, 0, 0),
    I_FxTOd  = BITS9(0, 1, 0, 0, 0, 1, 0, 0, 0),
    I_FxTOq  = BITS9(0, 1, 0, 0, 0, 1, 1, 0, 0),
    I_FsTOi  = BITS9(0, 1, 1, 0, 1, 0, 0, 0, 1),
    I_FdTOi  = BITS9(0, 1, 1, 0, 1, 0, 0, 1, 0),
    I_FqTOi  = BITS9(0, 1, 1, 0, 1, 0, 0, 1, 1),
    I_FiTOs  = BITS9(0, 1, 1, 0, 0, 0, 1, 0, 0),
    I_FiTOd  = BITS9(0, 1, 1, 0, 0, 1, 0, 0, 0),
    I_FiTOq  = BITS9(0, 1, 1, 0, 0, 1, 1, 0, 0),
    I_FqTOs  = BITS9(0, 1, 1, 0, 0, 0, 1, 1, 1),
    I_FdTOs  = BITS9(0, 1, 1, 0, 0, 0, 1, 1, 0),
    I_FsTOd  = BITS9(0, 1, 1, 0, 0, 1, 0, 0, 1),
    I_FqTOd  = BITS9(0, 1, 1, 0, 0, 1, 0, 1, 1),
    I_FsTOq  = BITS9(0, 1, 1, 0, 0, 1, 1, 0, 1),
    I_FdTOq  = BITS9(0, 1, 1, 0, 0, 1, 1, 1, 0)
} I_FPop1;

static const sparc64_opcode *
find_opcode_FPop1(UInt insn)
{
    UInt i_opf = BITS(insn, 13, 5);

    switch (i_opf) {
    case I_FMOVs:
        return &sparc64_opcodes[SPARC64_OPC_FMOVs];
    case I_FMOVd:
        return &sparc64_opcodes[SPARC64_OPC_FMOVd];
    case I_FMOVq:
        return &sparc64_opcodes[SPARC64_OPC_FMOVq];
    case I_FNEGs:
        return &sparc64_opcodes[SPARC64_OPC_FNEGs];
    case I_FNEGd:
        return &sparc64_opcodes[SPARC64_OPC_FNEGd];
    case I_FNEGq:
        return &sparc64_opcodes[SPARC64_OPC_FNEGq];
    case I_FABSs:
        return &sparc64_opcodes[SPARC64_OPC_FABSs];
    case I_FABSd:
        return &sparc64_opcodes[SPARC64_OPC_FABSd];
    case I_FABSq:
        return &sparc64_opcodes[SPARC64_OPC_FABSq];
    case I_FSQRTs:
        return &sparc64_opcodes[SPARC64_OPC_FSQRTs];
    case I_FSQRTd:
        return &sparc64_opcodes[SPARC64_OPC_FSQRTd];
    case I_FSQRTq:
        return &sparc64_opcodes[SPARC64_OPC_FSQRTq];
    case I_FADDs:
        return &sparc64_opcodes[SPARC64_OPC_FADDs];
    case I_FADDd:
        return &sparc64_opcodes[SPARC64_OPC_FADDd];
    case I_FADDq:
        return &sparc64_opcodes[SPARC64_OPC_FADDq];
    case I_FSUBs:
        return &sparc64_opcodes[SPARC64_OPC_FSUBs];
    case I_FSUBd:
        return &sparc64_opcodes[SPARC64_OPC_FSUBd];
    case I_FSUBq:
        return &sparc64_opcodes[SPARC64_OPC_FSUBq];
    case I_FMULs:
        return &sparc64_opcodes[SPARC64_OPC_FMULs];
    case I_FMULd:
        return &sparc64_opcodes[SPARC64_OPC_FMULd];
    case I_FMULq:
        return &sparc64_opcodes[SPARC64_OPC_FMULq];
    case I_FsMULd:
        return &sparc64_opcodes[SPARC64_OPC_FsMULd];
    case I_FdMULq:
        return &sparc64_opcodes[SPARC64_OPC_FdMULq];
    case I_FDIVs:
        return &sparc64_opcodes[SPARC64_OPC_FDIVs];
    case I_FDIVd:
        return &sparc64_opcodes[SPARC64_OPC_FDIVd];
    case I_FDIVq:
        return &sparc64_opcodes[SPARC64_OPC_FDIVq];
    case I_FsTOx:
        return &sparc64_opcodes[SPARC64_OPC_FsTOx];
    case I_FdTOx:
        return &sparc64_opcodes[SPARC64_OPC_FdTOx];
    case I_FqTOx:
        return &sparc64_opcodes[SPARC64_OPC_FqTOx];
    case I_FxTOs:
        return &sparc64_opcodes[SPARC64_OPC_FxTOs];
    case I_FxTOd:
        return &sparc64_opcodes[SPARC64_OPC_FxTOd];
    case I_FxTOq:
        return &sparc64_opcodes[SPARC64_OPC_FxTOq];
    case I_FsTOi:
        return &sparc64_opcodes[SPARC64_OPC_FsTOi];
    case I_FdTOi:
        return &sparc64_opcodes[SPARC64_OPC_FdTOi];
    case I_FqTOi:
        return &sparc64_opcodes[SPARC64_OPC_FqTOi];
    case I_FiTOs:
        return &sparc64_opcodes[SPARC64_OPC_FiTOs];
    case I_FiTOd:
        return &sparc64_opcodes[SPARC64_OPC_FiTOd];
    case I_FiTOq:
        return &sparc64_opcodes[SPARC64_OPC_FiTOq];
    case I_FqTOs:
        return &sparc64_opcodes[SPARC64_OPC_FqTOs];
    case I_FdTOs:
        return &sparc64_opcodes[SPARC64_OPC_FdTOs];
    case I_FsTOd:
        return &sparc64_opcodes[SPARC64_OPC_FsTOd];
    case I_FqTOd:
        return &sparc64_opcodes[SPARC64_OPC_FqTOd];
    case I_FsTOq:
        return &sparc64_opcodes[SPARC64_OPC_FsTOq];
    case I_FdTOq:
        return &sparc64_opcodes[SPARC64_OPC_FdTOq];
    default:
        return NULL;
    }
}

/* FPop2 opf codes. */
enum
{
    I_FMOVSfcc = BITS9(0, 0, 0, 0, 0, 0, 0, 0, 1),
    I_FMOVDfcc = BITS9(0, 0, 0, 0, 0, 0, 0, 1, 0),
    I_FMOVQfcc = BITS9(0, 0, 0, 0, 0, 0, 0, 1, 1),
    I_FMOVSicc = BITS9(1, 0, 0, 0, 0, 0, 0, 0, 1),
    I_FMOVDicc = BITS9(1, 0, 0, 0, 0, 0, 0, 1, 0),
    I_FMOVQicc = BITS9(1, 0, 0, 0, 0, 0, 0, 1, 1),
    I_FCMPs    = BITS9(0, 0, 1, 0, 1, 0, 0, 0, 1),
    I_FCMPd    = BITS9(0, 0, 1, 0, 1, 0, 0, 1, 0),
    I_FCMPq    = BITS9(0, 0, 1, 0, 1, 0, 0, 1, 1),
    I_FCMPEs   = BITS9(0, 0, 1, 0, 1, 0, 1, 0, 1),
    I_FCMPEd   = BITS9(0, 0, 1, 0, 1, 0, 1, 1, 0),
    I_FCMPEq   = BITS9(0, 0, 1, 0, 1, 0, 1, 1, 1)
} I_FPop2;

/* Finds opcode for FMOVcc(icc), and MOVcc(icc). */
static const sparc64_opcode *
find_opcode_MOVicc(UInt insn, sparc64_mnemonic base)
{
    vassert((base == SPARC64_OPC_FMOVSiccA) || (base == SPARC64_OPC_FMOVDiccA)
            || (base == SPARC64_OPC_FMOVQiccA) || (base == SPARC64_OPC_MOVA));

    UInt i_cond = BITS(insn, 17, 14);

    switch (i_cond) {
    case I_COND_A:
        return &sparc64_opcodes[base + 0];
    case I_COND_N:
        return &sparc64_opcodes[base + 1];
    case I_COND_NE:
        return &sparc64_opcodes[base + 2];
    case I_COND_E:
        return &sparc64_opcodes[base + 3];
    case I_COND_G:
        return &sparc64_opcodes[base + 4];
    case I_COND_LE:
        return &sparc64_opcodes[base + 5];
    case I_COND_GE:
        return &sparc64_opcodes[base + 6];
    case I_COND_L:
        return &sparc64_opcodes[base + 7];
    case I_COND_GU:
        return &sparc64_opcodes[base + 8];
    case I_COND_LEU:
        return &sparc64_opcodes[base + 9];
    case I_COND_CC:
        return &sparc64_opcodes[base + 10];
    case I_COND_CS:
        return &sparc64_opcodes[base + 11];
    case I_COND_POS:
        return &sparc64_opcodes[base + 12];
    case I_COND_NEG:
        return &sparc64_opcodes[base + 13];
    case I_COND_VC:
        return &sparc64_opcodes[base + 14];
    case I_COND_VS:
        return &sparc64_opcodes[base + 15];
    default:
        vassert(0);
    }
}

static const sparc64_opcode *
find_opcode_MOVfcc(UInt insn, sparc64_mnemonic base)
{
    vassert((base == SPARC64_OPC_FMOVSfccA) || (base == SPARC64_OPC_FMOVDfccA)
            || (base == SPARC64_OPC_FMOVQfccA) || (base == SPARC64_OPC_MOVFA));

    UInt f_cond = BITS(insn, 17, 14);

    switch (f_cond) {
    case F_COND_A:
        return &sparc64_opcodes[base + 0];
    case F_COND_N:
        return &sparc64_opcodes[base + 1];
    case F_COND_U:
        return &sparc64_opcodes[base + 2];
    case F_COND_G:
        return &sparc64_opcodes[base + 3];
    case F_COND_UG:
        return &sparc64_opcodes[base + 4];
    case F_COND_L:
        return &sparc64_opcodes[base + 5];
    case F_COND_UL:
        return &sparc64_opcodes[base + 6];
    case F_COND_LG:
        return &sparc64_opcodes[base + 7];
    case F_COND_NE:
        return &sparc64_opcodes[base + 8];
    case F_COND_E:
        return &sparc64_opcodes[base + 9];
    case F_COND_UE:
        return &sparc64_opcodes[base + 10];
    case F_COND_GE:
        return &sparc64_opcodes[base + 11];
    case F_COND_UGE:
        return &sparc64_opcodes[base + 12];
    case F_COND_LE:
        return &sparc64_opcodes[base + 13];
    case F_COND_ULE:
        return &sparc64_opcodes[base + 14];
    case F_COND_O:
        return &sparc64_opcodes[base + 15];
    default:
        vassert(0);
    }
}

static const sparc64_opcode *
find_opcode_FPop2(UInt insn)
{
    UInt i_opf = BITS(insn, 13, 5);

    switch (i_opf) {
    case I_FCMPs:
        return &sparc64_opcodes[SPARC64_OPC_FCMPs];
    case I_FCMPd:
        return &sparc64_opcodes[SPARC64_OPC_FCMPd];
    case I_FCMPq:
        return &sparc64_opcodes[SPARC64_OPC_FCMPq];
    case I_FCMPEs:
        return &sparc64_opcodes[SPARC64_OPC_FCMPEs];
    case I_FCMPEd:
        return &sparc64_opcodes[SPARC64_OPC_FCMPEd];
    case I_FCMPEq:
        return &sparc64_opcodes[SPARC64_OPC_FCMPEq];
    default:
        i_opf &= 0x13F; /* mask out 2 lower bits of opf_cc */
        switch (i_opf) {
        case I_FMOVSfcc:
            return find_opcode_MOVfcc(insn, SPARC64_OPC_FMOVSfccA);
        case I_FMOVDfcc:
            return find_opcode_MOVfcc(insn, SPARC64_OPC_FMOVDfccA);
        case I_FMOVQfcc:
            return find_opcode_MOVfcc(insn, SPARC64_OPC_FMOVQfccA);
        case I_FMOVSicc:
            return find_opcode_MOVicc(insn, SPARC64_OPC_FMOVSiccA);
        case I_FMOVDicc:
            return find_opcode_MOVicc(insn, SPARC64_OPC_FMOVDiccA);
        case I_FMOVQicc:
            return find_opcode_MOVicc(insn, SPARC64_OPC_FMOVQiccA);
        }
        return NULL;
    }
}

/* VIS opf codes. */
enum
{
    I_ADDXC        = BITS9(0, 0, 0, 0, 1, 0, 0, 0, 1),
    I_ADDXCcc      = BITS9(0, 0, 0, 0, 1, 0, 0, 1, 1),
    I_UMULXHI      = BITS9(0, 0, 0, 0, 1, 0, 1, 1, 0),
    I_LZCNT        = BITS9(0, 0, 0, 0, 1, 0, 1, 1, 1),
    I_ALIGNADDRESS = BITS9(0, 0, 0, 0, 1, 1, 0, 0, 0),
    I_BMASK        = BITS9(0, 0, 0, 0, 1, 1, 0, 0, 1),
    I_FSLL16       = BITS9(0, 0, 0, 1, 0, 0, 0, 0, 1),
    I_FSRL16       = BITS9(0, 0, 0, 1, 0, 0, 0, 1, 1),
    I_FSLL32       = BITS9(0, 0, 0, 1, 0, 0, 1, 0, 1),
    I_FSRL32       = BITS9(0, 0, 0, 1, 0, 0, 1, 1, 1),
    I_FSLAS16      = BITS9(0, 0, 0, 1, 0, 1, 0, 0, 1),
    I_FSRA16       = BITS9(0, 0, 0, 1, 0, 1, 0, 1, 1),
    I_FSLAS32      = BITS9(0, 0, 0, 1, 0, 1, 1, 0, 1),
    I_FSRA32       = BITS9(0, 0, 0, 1, 0, 1, 1, 1, 1),
    I_FALIGNDATAg  = BITS9(0, 0, 1, 0, 0, 1, 0, 0, 0),
    I_BSHUFFLE     = BITS9(0, 0, 1, 0, 0, 1, 1, 0, 0),
    I_FZEROd       = BITS9(0, 0, 1, 1, 0, 0, 0, 0, 0),
    I_FZEROs       = BITS9(0, 0, 1, 1, 0, 0, 0, 0, 1),
    I_FNORd        = BITS9(0, 0, 1, 1, 0, 0, 0, 1, 0),
    I_FNORs        = BITS9(0, 0, 1, 1, 0, 0, 0, 1, 1),
    I_FANDNOT2d    = BITS9(0, 0, 1, 1, 0, 0, 1, 0, 0),
    I_FANDNOT2s    = BITS9(0, 0, 1, 1, 0, 0, 1, 0, 1),
    I_FANDNOT1d    = BITS9(0, 0, 1, 1, 0, 1, 0, 0, 0),
    I_FANDNOT1s    = BITS9(0, 0, 1, 1, 0, 1, 0, 0, 1),
    I_FXORd        = BITS9(0, 0, 1, 1, 0, 1, 1, 0, 0),
    I_FXORs        = BITS9(0, 0, 1, 1, 0, 1, 1, 0, 1),
    I_FNANDd       = BITS9(0, 0, 1, 1, 0, 1, 1, 1, 0),
    I_FNANDs       = BITS9(0, 0, 1, 1, 0, 1, 1, 1, 1),
    I_FXNORd       = BITS9(0, 0, 1, 1, 1, 0, 0, 1, 0),
    I_FXNORs       = BITS9(0, 0, 1, 1, 1, 0, 0, 1, 1),
    I_FANDd        = BITS9(0, 0, 1, 1, 1, 0, 0, 0, 0),
    I_FANDs        = BITS9(0, 0, 1, 1, 1, 0, 0, 0, 1),
    I_FSRC1d       = BITS9(0, 0, 1, 1, 1, 0, 1, 0, 0),
    I_FSRC1s       = BITS9(0, 0, 1, 1, 1, 0, 1, 0, 1),
    I_FSRC2d       = BITS9(0, 0, 1, 1, 1, 1, 0, 0, 0),
    I_FSRC2s       = BITS9(0, 0, 1, 1, 1, 1, 0, 0, 1),
    I_FNOT1d       = BITS9(0, 0, 1, 1, 0, 1, 0, 1, 0),
    I_FNOT1s       = BITS9(0, 0, 1, 1, 0, 1, 0, 1, 1),
    I_FNOT2d       = BITS9(0, 0, 1, 1, 0, 0, 1, 1, 0),
    I_FNOT2s       = BITS9(0, 0, 1, 1, 0, 0, 1, 1, 1),
    I_FORNOT2d     = BITS9(0, 0, 1, 1, 1, 0, 1, 1, 0),
    I_FORNOT2s     = BITS9(0, 0, 1, 1, 1, 0, 1, 1, 1),
    I_FORNOT1d     = BITS9(0, 0, 1, 1, 1, 1, 0, 1, 0),
    I_FORNOT1s     = BITS9(0, 0, 1, 1, 1, 1, 0, 1, 1),
    I_FORd         = BITS9(0, 0, 1, 1, 1, 1, 1, 0, 0),
    I_FORs         = BITS9(0, 0, 1, 1, 1, 1, 1, 0, 1),
    I_FONEd        = BITS9(0, 0, 1, 1, 1, 1, 1, 1, 0),
    I_FONEs        = BITS9(0, 0, 1, 1, 1, 1, 1, 1, 1),
    I_SIAM         = BITS9(0, 1, 0, 0, 0, 0, 0, 0, 1),
    I_MOVdTOx      = BITS9(1, 0, 0, 0, 1, 0, 0, 0, 0),
    I_MOVsTOuw     = BITS9(1, 0, 0, 0, 1, 0, 0, 0, 1),
    I_MOVsTOsw     = BITS9(1, 0, 0, 0, 1, 0, 0, 1, 1),
    I_XMULX        = BITS9(1, 0, 0, 0, 1, 0, 1, 0, 1),
    I_XMULXHI      = BITS9(1, 0, 0, 0, 1, 0, 1, 1, 0),
    I_MOVxTOd      = BITS9(1, 0, 0, 0, 1, 1, 0, 0, 0),
    I_MOVwTOs      = BITS9(1, 0, 0, 0, 1, 1, 0, 0, 1),
    I_AES_KEXPAND0 = BITS9(1, 0, 0, 1, 1, 0, 0, 0, 0),
    I_AES_KEXPAND2 = BITS9(1, 0, 0, 1, 1, 0, 0, 0, 1),
    I_MD5          = BITS9(1, 0, 1, 0, 0, 0, 0, 0, 0),
    I_SHA1         = BITS9(1, 0, 1, 0, 0, 0, 0, 0, 1),
    I_SHA256       = BITS9(1, 0, 1, 0, 0, 0, 0, 1, 0),
    I_SHA512       = BITS9(1, 0, 1, 0, 0, 0, 0, 1, 1)
} I_VIS;

static const sparc64_opcode *
find_opcode_VIS(UInt insn)
{
    UInt i_opf = BITS(insn, 13, 5);

    switch (i_opf) {
    case I_ADDXC:
        return &sparc64_opcodes[SPARC64_OPC_ADDXC];
    case I_ADDXCcc:
        return &sparc64_opcodes[SPARC64_OPC_ADDXCcc];
    case I_UMULXHI:
        return &sparc64_opcodes[SPARC64_OPC_UMULXHI];
    case I_LZCNT:
        return &sparc64_opcodes[SPARC64_OPC_LZCNT];
    case I_ALIGNADDRESS:
        return &sparc64_opcodes[SPARC64_OPC_ALIGNADDRESS];
    case I_BMASK:
        return &sparc64_opcodes[SPARC64_OPC_BMASK];
    case I_FSLL16:
        return &sparc64_opcodes[SPARC64_OPC_FSLL16];
    case I_FSRL16:
        return &sparc64_opcodes[SPARC64_OPC_FSRL16];
    case I_FSLL32:
        return &sparc64_opcodes[SPARC64_OPC_FSLL32];
    case I_FSRL32:
        return &sparc64_opcodes[SPARC64_OPC_FSRL32];
    case I_FSLAS16:
        return &sparc64_opcodes[SPARC64_OPC_FSLAS16];
    case I_FSRA16:
        return &sparc64_opcodes[SPARC64_OPC_FSRA16];
    case I_FSLAS32:
        return &sparc64_opcodes[SPARC64_OPC_FSLAS32];
    case I_FSRA32:
        return &sparc64_opcodes[SPARC64_OPC_FSRA32];
    case I_FALIGNDATAg:
        return &sparc64_opcodes[SPARC64_OPC_FALIGNDATAg];
    case I_BSHUFFLE:
        return &sparc64_opcodes[SPARC64_OPC_BSHUFFLE];
    case I_FZEROs:
        return &sparc64_opcodes[SPARC64_OPC_FZEROs];
    case I_FZEROd:
        return &sparc64_opcodes[SPARC64_OPC_FZEROd];
    case I_FNORd:
        return &sparc64_opcodes[SPARC64_OPC_FNORd];
    case I_FNORs:
        return &sparc64_opcodes[SPARC64_OPC_FNORs];
    case I_FANDNOT1d:
        return &sparc64_opcodes[SPARC64_OPC_FANDNOT1d];
    case I_FANDNOT1s:
        return &sparc64_opcodes[SPARC64_OPC_FANDNOT1s];
    case I_FANDNOT2d:
        return &sparc64_opcodes[SPARC64_OPC_FANDNOT2d];
    case I_FANDNOT2s:
        return &sparc64_opcodes[SPARC64_OPC_FANDNOT2s];
    case I_FXORd:
        return &sparc64_opcodes[SPARC64_OPC_FXORd];
    case I_FXORs:
        return &sparc64_opcodes[SPARC64_OPC_FXORs];
    case I_FNANDd:
        return &sparc64_opcodes[SPARC64_OPC_FNANDd];
    case I_FNANDs:
        return &sparc64_opcodes[SPARC64_OPC_FNANDs];
    case I_FXNORd:
        return &sparc64_opcodes[SPARC64_OPC_FXNORd];
    case I_FXNORs:
        return &sparc64_opcodes[SPARC64_OPC_FXNORs];
    case I_FANDd:
        return &sparc64_opcodes[SPARC64_OPC_FANDd];
    case I_FANDs:
        return &sparc64_opcodes[SPARC64_OPC_FANDs];
    case I_FSRC1d:
        return &sparc64_opcodes[SPARC64_OPC_FSRC1d];
    case I_FSRC1s:
        return &sparc64_opcodes[SPARC64_OPC_FSRC1s];
    case I_FSRC2d:
        return &sparc64_opcodes[SPARC64_OPC_FSRC2d];
    case I_FSRC2s:
        return &sparc64_opcodes[SPARC64_OPC_FSRC2s];
    case I_FNOT1d:
        return &sparc64_opcodes[SPARC64_OPC_FNOT1d];
    case I_FNOT1s:
        return &sparc64_opcodes[SPARC64_OPC_FNOT1s];
    case I_FNOT2d:
        return &sparc64_opcodes[SPARC64_OPC_FNOT2d];
    case I_FNOT2s:
        return &sparc64_opcodes[SPARC64_OPC_FNOT2s];
    case I_FORNOT1d:
        return &sparc64_opcodes[SPARC64_OPC_FORNOT1d];
    case I_FORNOT1s:
        return &sparc64_opcodes[SPARC64_OPC_FORNOT1s];
    case I_FORNOT2d:
        return &sparc64_opcodes[SPARC64_OPC_FORNOT2d];
    case I_FORNOT2s:
        return &sparc64_opcodes[SPARC64_OPC_FORNOT2s];
    case I_FORd:
        return &sparc64_opcodes[SPARC64_OPC_FORd];
    case I_FORs:
        return &sparc64_opcodes[SPARC64_OPC_FORs];
    case I_FONEs:
        return &sparc64_opcodes[SPARC64_OPC_FONEs];
    case I_FONEd:
        return &sparc64_opcodes[SPARC64_OPC_FONEd];
    case I_MOVdTOx:
        return &sparc64_opcodes[SPARC64_OPC_MOVdTOx];
    case I_MOVsTOuw:
        return &sparc64_opcodes[SPARC64_OPC_MOVsTOuw];
    case I_MOVsTOsw:
        return &sparc64_opcodes[SPARC64_OPC_MOVsTOsw];
    case I_XMULX:
        return &sparc64_opcodes[SPARC64_OPC_XMULX];
    case I_XMULXHI:
        return &sparc64_opcodes[SPARC64_OPC_XMULXHI];
    case I_MOVwTOs:
        return &sparc64_opcodes[SPARC64_OPC_MOVwTOs];
    case I_MOVxTOd:
        return &sparc64_opcodes[SPARC64_OPC_MOVxTOd];
    case I_AES_KEXPAND0:
        return &sparc64_opcodes[SPARC64_OPC_AES_KEXPAND0];
    case I_AES_KEXPAND2:
        return &sparc64_opcodes[SPARC64_OPC_AES_KEXPAND2];
    case I_MD5:
        return &sparc64_opcodes[SPARC64_OPC_MD5];
    case I_SHA1:
        return &sparc64_opcodes[SPARC64_OPC_SHA1];
    case I_SHA256:
        return &sparc64_opcodes[SPARC64_OPC_SHA256];
    case I_SHA512:
        return &sparc64_opcodes[SPARC64_OPC_SHA512];
    case I_SIAM:
        /* SIAM instruction sets rounding modes in GSR register. VEX IR cannot
           accomodate that at the moment. We cannot handle this as an
           ordinary unrecognized instruction because valgrind would 
           execute the program incorrectly without setting the rounding
           mode properly. */
        vpanic("SIAM instruction unimplemented");
    default:
        return NULL;
    }
}

/* FMAf op5 codes. */
enum
{
    I_OP5_FMADDs =  BITS4(0, 0, 0, 1),
    I_OP5_FMADDd =  BITS4(0, 0, 1, 0),
    I_OP5_FMSUBs =  BITS4(0, 1, 0, 1),
    I_OP5_FMSUBd =  BITS4(0, 1, 1, 0),
    I_OP5_FNMSUBs = BITS4(1, 0, 0, 1),
    I_OP5_FNMSUBd = BITS4(1, 0, 1, 0),
    I_OP5_FNMADDs = BITS4(1, 1, 0, 1),
    I_OP5_FNMADDd = BITS4(1, 1, 1, 0)
} I_OP5_FMAf;

static const sparc64_opcode *
find_opcode_FMAf(UInt insn)
{
    UInt i_op5 = BITS(insn, 8, 5);

    switch (i_op5) {
    case I_OP5_FMADDs:
        return &sparc64_opcodes[SPARC64_OPC_FMADDs];
    case I_OP5_FMADDd:
        return &sparc64_opcodes[SPARC64_OPC_FMADDd];
    case I_OP5_FMSUBs:
        return &sparc64_opcodes[SPARC64_OPC_FMSUBs];
    case I_OP5_FMSUBd:
        return &sparc64_opcodes[SPARC64_OPC_FMSUBd];
    case I_OP5_FNMSUBs:
        return &sparc64_opcodes[SPARC64_OPC_FNMSUBs];
    case I_OP5_FNMSUBd:
        return &sparc64_opcodes[SPARC64_OPC_FNMSUBd];
    case I_OP5_FNMADDs:
        return &sparc64_opcodes[SPARC64_OPC_FNMADDs];
    case I_OP5_FNMADDd:
        return &sparc64_opcodes[SPARC64_OPC_FNMADDd];
    default:
        return NULL;
    }
}

/* AES, DES, CAMELLIA op5 codes. */
enum
{
    I_OP5_AES_EROUND01      = BITS4(0, 0, 0, 0),
    I_OP5_AES_EROUND23      = BITS4(0, 0, 0, 1),
    I_OP5_AES_DROUND01      = BITS4(0, 0, 1, 0),
    I_OP5_AES_DROUND23      = BITS4(0, 0, 1, 1),
    I_OP5_AES_EROUND01_LAST = BITS4(0, 1, 0, 0),
    I_OP5_AES_EROUND23_LAST = BITS4(0, 1, 0, 1),
    I_OP5_AES_DROUND01_LAST = BITS4(0, 1, 1, 0),
    I_OP5_AES_DROUND23_LAST = BITS4(0, 1, 1, 1),
    I_OP5_AES_KEXPAND1      = BITS4(1, 0, 0, 0)
} I_OP5_AES_DES_CAMELLIA;

static const sparc64_opcode *
find_opcode_AES_DES_CAMELLIA(UInt insn)
{
    UInt i_op5 = BITS(insn, 8, 5);

    switch (i_op5) {
    case I_OP5_AES_EROUND01:
        return &sparc64_opcodes[SPARC64_OPC_AES_EROUND01];
    case I_OP5_AES_EROUND23:
        return &sparc64_opcodes[SPARC64_OPC_AES_EROUND23];
    case I_OP5_AES_DROUND01:
        return &sparc64_opcodes[SPARC64_OPC_AES_DROUND01];
    case I_OP5_AES_DROUND23:
        return &sparc64_opcodes[SPARC64_OPC_AES_DROUND23];
    case I_OP5_AES_EROUND01_LAST:
        return &sparc64_opcodes[SPARC64_OPC_AES_EROUND01_LAST];
    case I_OP5_AES_EROUND23_LAST:
        return &sparc64_opcodes[SPARC64_OPC_AES_EROUND23_LAST];
    case I_OP5_AES_DROUND01_LAST:
        return &sparc64_opcodes[SPARC64_OPC_AES_DROUND01_LAST];
    case I_OP5_AES_DROUND23_LAST:
        return &sparc64_opcodes[SPARC64_OPC_AES_DROUND23_LAST];
    case I_OP5_AES_KEXPAND1:
        return &sparc64_opcodes[SPARC64_OPC_AES_KEXPAND1];
    default:
        return NULL;
    }
}

/* op3 codes for arithmetic & logic (SAR) instructions with op=2. */
enum
{
    I_OP3_ADD =              BITS6(0, 0, 0, 0, 0, 0),
    I_OP3_AND =              BITS6(0, 0, 0, 0, 0, 1),
    I_OP3_OR =               BITS6(0, 0, 0, 0, 1, 0),
    I_OP3_XOR =              BITS6(0, 0, 0, 0, 1, 1),
    I_OP3_SUB =              BITS6(0, 0, 0, 1, 0, 0),
    I_OP3_ANDN =             BITS6(0, 0, 0, 1, 0, 1),
    I_OP3_ORN =              BITS6(0, 0, 0, 1, 1, 0),
    I_OP3_XNOR =             BITS6(0, 0, 0, 1, 1, 1),
    I_OP3_ADDC =             BITS6(0, 0, 1, 0, 0, 0),
    I_OP3_MULX =             BITS6(0, 0, 1, 0, 0, 1),
    I_OP3_UMUL =             BITS6(0, 0, 1, 0, 1, 0),
    I_OP3_SMUL =             BITS6(0, 0, 1, 0, 1, 1),
    I_OP3_SUBC =             BITS6(0, 0, 1, 1, 0, 0),
    I_OP3_UDIVX =            BITS6(0, 0, 1, 1, 0, 1),
    I_OP3_UDIV =             BITS6(0, 0, 1, 1, 1, 0),
    I_OP3_SDIV =             BITS6(0, 0, 1, 1, 1, 1),
    I_OP3_ADDcc =            BITS6(0, 1, 0, 0, 0, 0),
    I_OP3_ANDcc =            BITS6(0, 1, 0, 0, 0, 1),
    I_OP3_ORcc =             BITS6(0, 1, 0, 0, 1, 0),
    I_OP3_XORcc =            BITS6(0, 1, 0, 0, 1, 1),
    I_OP3_SUBcc =            BITS6(0, 1, 0, 1, 0, 0),
    I_OP3_ANDNcc =           BITS6(0, 1, 0, 1, 0, 1),
    I_OP3_ORNcc =            BITS6(0, 1, 0, 1, 1, 0),
    I_OP3_XNORcc =           BITS6(0, 1, 0, 1, 1, 1),
    I_OP3_ADDCcc =           BITS6(0, 1, 1, 0, 0, 0),
    I_OP3_AES_DES_CAMELLIA = BITS6(0, 1, 1, 0, 0, 1), /* composite */
    I_OP3_UMULcc =           BITS6(0, 1, 1, 0, 1, 0),
    I_OP3_SMULcc =           BITS6(0, 1, 1, 0, 1, 1),
    I_OP3_SUBCcc =           BITS6(0, 1, 1, 1, 0, 0),
    I_OP3_RESERVED_2 =       BITS6(0, 1, 1, 1, 0, 1), /* reserved */
    I_OP3_UDIVcc =           BITS6(0, 1, 1, 1, 1, 0),
    I_OP3_SDIVcc =           BITS6(0, 1, 1, 1, 1, 1),
    I_OP3_TADDcc =           BITS6(1, 0, 0, 0, 0, 0),
    I_OP3_TSUBcc =           BITS6(1, 0, 0, 0, 0, 1),
    I_OP3_TADDccTV =         BITS6(1, 0, 0, 0, 1, 0),
    I_OP3_TSUBccTV =         BITS6(1, 0, 0, 0, 1, 1),
    I_OP3_MULScc =           BITS6(1, 0, 0, 1, 0, 0),
    I_OP3_SLL_SLLX =         BITS6(1, 0, 0, 1, 0, 1), /* composite */
    I_OP3_SRL_SRLX =         BITS6(1, 0, 0, 1, 1, 0), /* composite */
    I_OP3_SRA_SRAX =         BITS6(1, 0, 0, 1, 1, 1), /* composite */
    I_OP3_RDasr_MEMBAR =     BITS6(1, 0, 1, 0, 0, 0), /* composite */
    I_OP3_RDHPR =            BITS6(1, 0, 1, 0, 0, 1),
    I_OP3_RDPR =             BITS6(1, 0, 1, 0, 1, 0),
    I_OP3_FLUSHW =           BITS6(1, 0, 1, 0, 1, 1),
    I_OP3_MOVcc =            BITS6(1, 0, 1, 1, 0, 0),
    I_OP3_SDIVX =            BITS6(1, 0, 1, 1, 0, 1),
    I_OP3_POPC =             BITS6(1, 0, 1, 1, 1, 0),
    I_OP3_MOVr =             BITS6(1, 0, 1, 1, 1, 1),
    I_OP3_WRasr =            BITS6(1, 1, 0, 0, 0, 0), /* composite */
    I_OP3_WIN_P =            BITS6(1, 1, 0, 0, 0, 1), /* composite */
    I_OP3_WRPR =             BITS6(1, 1, 0, 0, 1, 0), /* composite */
    I_OP3_WRHPR_HALT =       BITS6(1, 1, 0, 0, 1, 1), /* composite */
    I_OP3_FPop1 =            BITS6(1, 1, 0, 1, 0, 0), /* composite */
    I_OP3_FPop2 =            BITS6(1, 1, 0, 1, 0, 1), /* composite */
    I_OP3_VIS =              BITS6(1, 1, 0, 1, 1, 0), /* composite */
    I_OP3_FMAf =             BITS6(1, 1, 0, 1, 1, 1), /* composite */
    I_OP3_JMPL =             BITS6(1, 1, 1, 0, 0, 0),
    I_OP3_RETURN =           BITS6(1, 1, 1, 0, 0, 1),
    I_OP3_Tcc =              BITS6(1, 1, 1, 0, 1, 0),
    I_OP3_FLUSH =            BITS6(1, 1, 1, 0, 1, 1),
    I_OP3_SAVE =             BITS6(1, 1, 1, 1, 0, 0),
    I_OP3_RESTORE =          BITS6(1, 1, 1, 1, 0, 1),
    I_OP3_DONE_RETRY_JPRIV = BITS6(1, 1, 1, 1, 1, 0),
    I_OP3_RESERVED_3 =       BITS6(1, 1, 1, 1, 1, 1)  /* reserved */
} I_OP3_FMT_SAR;

static const sparc64_opcode *
find_opcode_op2(UInt insn)
{
    UInt i_op3 = BITS(insn, 24, 19);

    switch (i_op3) {
    case I_OP3_ADD:
        return &sparc64_opcodes[SPARC64_OPC_ADD];
    case I_OP3_AND:
        return &sparc64_opcodes[SPARC64_OPC_AND];
    case I_OP3_OR:
        return &sparc64_opcodes[SPARC64_OPC_OR];
    case I_OP3_XOR:
        return &sparc64_opcodes[SPARC64_OPC_XOR];
    case I_OP3_SUB:
        return &sparc64_opcodes[SPARC64_OPC_SUB];
    case I_OP3_ANDN:
        return &sparc64_opcodes[SPARC64_OPC_ANDN];
    case I_OP3_ORN:
        return &sparc64_opcodes[SPARC64_OPC_ORN];
    case I_OP3_XNOR:
        return &sparc64_opcodes[SPARC64_OPC_XNOR];
    case I_OP3_ADDC:
        return &sparc64_opcodes[SPARC64_OPC_ADDC];
    case I_OP3_MULX:
        return &sparc64_opcodes[SPARC64_OPC_MULX];
    case I_OP3_UMUL:
        return &sparc64_opcodes[SPARC64_OPC_UMUL];
    case I_OP3_SMUL:
        return &sparc64_opcodes[SPARC64_OPC_SMUL];
    case I_OP3_SUBC:
        return &sparc64_opcodes[SPARC64_OPC_SUBC];
    case I_OP3_UDIVX:
        return &sparc64_opcodes[SPARC64_OPC_UDIVX];
    case I_OP3_UDIV:
        return &sparc64_opcodes[SPARC64_OPC_UDIV];
    case I_OP3_SDIV:
        return &sparc64_opcodes[SPARC64_OPC_SDIV];
    case I_OP3_ADDcc:
        return &sparc64_opcodes[SPARC64_OPC_ADDcc];
    case I_OP3_ANDcc:
        return &sparc64_opcodes[SPARC64_OPC_ANDcc];
    case I_OP3_ORcc:
        return &sparc64_opcodes[SPARC64_OPC_ORcc];
    case I_OP3_XORcc:
        return &sparc64_opcodes[SPARC64_OPC_XORcc];
    case I_OP3_SUBcc:
        return &sparc64_opcodes[SPARC64_OPC_SUBcc];
    case I_OP3_ANDNcc:
        return &sparc64_opcodes[SPARC64_OPC_ANDNcc];
    case I_OP3_ORNcc:
        return &sparc64_opcodes[SPARC64_OPC_ORNcc];
    case I_OP3_XNORcc:
        return &sparc64_opcodes[SPARC64_OPC_XNORcc];
    case I_OP3_ADDCcc:
        return &sparc64_opcodes[SPARC64_OPC_ADDCcc];
    case I_OP3_AES_DES_CAMELLIA:
        return find_opcode_AES_DES_CAMELLIA(insn);
    case I_OP3_UMULcc:
        return &sparc64_opcodes[SPARC64_OPC_UMULcc];
    case I_OP3_SMULcc:
        return &sparc64_opcodes[SPARC64_OPC_SMULcc];
    case I_OP3_SUBCcc:
        return &sparc64_opcodes[SPARC64_OPC_SUBCcc];
    case I_OP3_RESERVED_2:
        return NULL;
    case I_OP3_UDIVcc:
        return &sparc64_opcodes[SPARC64_OPC_UDIVcc];
    case I_OP3_SDIVcc:
        return &sparc64_opcodes[SPARC64_OPC_SDIVcc];
    case I_OP3_TADDcc:
    case I_OP3_TSUBcc:
    case I_OP3_TADDccTV:
    case I_OP3_TSUBccTV:
    case I_OP3_MULScc:
        return NULL;
    case I_OP3_SLL_SLLX: /* SLL and SLLX */
        if (INSN_FMT_X(insn) == 0) {
            return &sparc64_opcodes[SPARC64_OPC_SLL];
        } else {
            return &sparc64_opcodes[SPARC64_OPC_SLLX];
        }
    case I_OP3_SRL_SRLX: /* SRL and SRLX */
        if (INSN_FMT_X(insn) == 0) {
            return &sparc64_opcodes[SPARC64_OPC_SRL];
        } else {
            return &sparc64_opcodes[SPARC64_OPC_SRLX];
        }
    case I_OP3_SRA_SRAX: /* SRA and SRAX */
        if (INSN_FMT_X(insn) == 0) {
            return &sparc64_opcodes[SPARC64_OPC_SRA];
        } else {
            return &sparc64_opcodes[SPARC64_OPC_SRAX];
        }
    case I_OP3_RDasr_MEMBAR:
        return find_opcode_RDasr_MEMBAR(insn);
    case I_OP3_RDHPR:
    case I_OP3_RDPR:
        return NULL;
    case I_OP3_FLUSHW:
        return &sparc64_opcodes[SPARC64_OPC_FLUSHW];
    case I_OP3_MOVcc:
        if (INSN_FMT_CC2(insn) == 0) {
            return find_opcode_MOVfcc(insn, SPARC64_OPC_MOVFA);
        } else {
            return find_opcode_MOVicc(insn, SPARC64_OPC_MOVA);
        }
    case I_OP3_SDIVX:
        return &sparc64_opcodes[SPARC64_OPC_SDIVX];
    case I_OP3_POPC:
        return NULL;
    case I_OP3_MOVr:
        return find_opcode_MOVr(insn);
    case I_OP3_WRasr:
        return find_opcode_WRasr(insn);
    case I_OP3_WIN_P:
        vpanic("Unimplemented - windowing privileged instructions");
        break;
    case I_OP3_WRPR:
        vpanic("Unimplemented - wrpr");
        break;
    case I_OP3_WRHPR_HALT:
        vpanic("Unimplemented - wrhpr, halt");
        break;
    case I_OP3_FPop1:
        return find_opcode_FPop1(insn);
    case I_OP3_FPop2:
        return find_opcode_FPop2(insn);
    case I_OP3_VIS:
        return find_opcode_VIS(insn);
    case I_OP3_FMAf:
        return find_opcode_FMAf(insn);
    case I_OP3_JMPL:
        return &sparc64_opcodes[SPARC64_OPC_JMPL];
    case I_OP3_RETURN:
        return &sparc64_opcodes[SPARC64_OPC_RETURN];
    case I_OP3_Tcc:
        return find_opcode_Tcc(insn);
    case I_OP3_FLUSH:
        return &sparc64_opcodes[SPARC64_OPC_FLUSH];
    case I_OP3_SAVE:
        return &sparc64_opcodes[SPARC64_OPC_SAVE];
    case I_OP3_RESTORE:
        return &sparc64_opcodes[SPARC64_OPC_RESTORE];
    case I_OP3_DONE_RETRY_JPRIV:
        vpanic("Unimplemented - done, retry, jpriv");
        break;
    case I_OP3_RESERVED_3:
        return NULL;
    default:
        return NULL;
    }
}

/*----------------------------------------------------------------------------*/
/*--- Disassembly of load & store instructions.                            ---*/
/*----------------------------------------------------------------------------*/

static const sparc64_opcode *
find_opcode_LDDFA(UInt insn)
{
    if (INSN_FMT_I(insn) == 1) {
        /* Uses %asi register, don't know what it really is.
           Could be LDBLOCKF, LDDFA, LDSHORTF... */
        return &sparc64_opcodes[SPARC64_OPC_LDDFA];
    }

    switch (INSN_FMT_IMM_ASI(insn)) {
    case SPARC64_ASI_PRIMARY:
    case SPARC64_ASI_SECONDARY:
    case SPARC64_ASI_PRIMARY_NO_FAULT:
        return &sparc64_opcodes[SPARC64_OPC_LDDFA];
    case SPARC64_ASI_FL8_PRIMARY:
    case SPARC64_ASI_FL16_PRIMARY:
        return &sparc64_opcodes[SPARC64_OPC_LDSHORTF];
    case SPARC64_ASI_BLOCK_PRIMARY:
        return &sparc64_opcodes[SPARC64_OPC_LDBLOCKF];
    default:
        return NULL;
    }
}

/* op3 codes for load & store (LDST) instructions with op=3. */
enum
{
    I_OP3_LDUW =             BITS6(0, 0, 0, 0, 0, 0),
    I_OP3_LDUB =             BITS6(0, 0, 0, 0, 0, 1),
    I_OP3_LDUH =             BITS6(0, 0, 0, 0, 1, 0),
    I_OP3_LDTW =             BITS6(0, 0, 0, 0, 1, 1),
    I_OP3_STW =              BITS6(0, 0, 0, 1, 0, 0),
    I_OP3_STB =              BITS6(0, 0, 0, 1, 0, 1),
    I_OP3_STH =              BITS6(0, 0, 0, 1, 1, 0),
    I_OP3_STTW =             BITS6(0, 0, 0, 1, 1, 1),
    I_OP3_LDSW =             BITS6(0, 0, 1, 0, 0, 0),
    I_OP3_LDSB =             BITS6(0, 0, 1, 0, 0, 1),
    I_OP3_LDSH =             BITS6(0, 0, 1, 0, 1, 0),
    I_OP3_LDX =              BITS6(0, 0, 1, 0, 1, 1),
    I_OP3_RESERVED_4 =       BITS6(0, 0, 1, 1, 0, 0),
    I_OP3_LDSTUB =           BITS6(0, 0, 1, 1, 0, 1),
    I_OP3_STX =              BITS6(0, 0, 1, 1, 1, 0),
    I_OP3_SWAP =             BITS6(0, 0, 1, 1, 1, 1),
    I_OP3_LDUWA =            BITS6(0, 1, 0, 0, 0, 0),
    I_OP3_LDUBA =            BITS6(0, 1, 0, 0, 0, 1),
    I_OP3_LDUHA =            BITS6(0, 1, 0, 0, 1, 0),
    I_OP3_LDTWA_LDTXA =      BITS6(0, 1, 0, 0, 1, 1),
    I_OP3_STWA =             BITS6(0, 1, 0, 1, 0, 0),
    I_OP3_STBA =             BITS6(0, 1, 0, 1, 0, 1),
    I_OP3_STHA =             BITS6(0, 1, 0, 1, 1, 0),
    I_OP3_STTWA =            BITS6(0, 1, 0, 1, 1, 1),
    I_OP3_LDSWA =            BITS6(0, 1, 1, 0, 0, 0),
    I_OP3_LDSBA =            BITS6(0, 1, 1, 0, 0, 1),
    I_OP3_LDSHA =            BITS6(0, 1, 1, 0, 1, 0),
    I_OP3_LDXA =             BITS6(0, 1, 1, 0, 1, 1),
    I_OP3_RESERVED_5 =       BITS6(0, 1, 1, 1, 0, 0),
    I_OP3_LDSTUBA =          BITS6(0, 1, 1, 1, 0, 1),
    I_OP3_STXA =             BITS6(0, 1, 1, 1, 1, 0),
    I_OP3_SWAPA =            BITS6(0, 1, 1, 1, 1, 1),
    I_OP3_LDF =              BITS6(1, 0, 0, 0, 0, 0),
    I_OP3_LDFSR =            BITS6(1, 0, 0, 0, 0, 1),
    I_OP3_LDQF =             BITS6(1, 0, 0, 0, 1, 0),
    I_OP3_LDDF =             BITS6(1, 0, 0, 0, 1, 1),
    I_OP3_STF =              BITS6(1, 0, 0, 1, 0, 0),
    I_OP3_STFSR =            BITS6(1, 0, 0, 1, 0, 1),
    I_OP3_STQF =             BITS6(1, 0, 0, 1, 1, 0),
    I_OP3_STDF =             BITS6(1, 0, 0, 1, 1, 1),
    I_OP3_RESERVED_6 =       BITS6(1, 0, 1, 0, 0, 0),
    I_OP3_RESERVED_7 =       BITS6(1, 0, 1, 0, 0, 1),
    I_OP3_RESERVED_8 =       BITS6(1, 0, 1, 0, 1, 0),
    I_OP3_RESERVED_9 =       BITS6(1, 0, 1, 0, 1, 1),
    I_OP3_RESERVED_10 =      BITS6(1, 0, 1, 1, 0, 0),
    I_OP3_PREFETCH =         BITS6(1, 0, 1, 1, 0, 1),
    I_OP3_RESERVED_11 =      BITS6(1, 0, 1, 1, 1, 0),
    I_OP3_RESERVED_12 =      BITS6(1, 0, 1, 1, 1, 1),
    I_OP3_LDFA =             BITS6(1, 1, 0, 0, 0, 0),
    I_OP3_RESERVED_13 =      BITS6(1, 1, 0, 0, 0, 1),
    I_OP3_LDQFA =            BITS6(1, 1, 0, 0, 1, 0),
    I_OP3_LDDFA =            BITS6(1, 1, 0, 0, 1, 1),
    I_OP3_STFA =             BITS6(1, 1, 0, 1, 0, 0),
    I_OP3_RESERVED_14 =      BITS6(1, 1, 0, 1, 0, 1),
    I_OP3_STQFA =            BITS6(1, 1, 0, 1, 1, 0),
    I_OP3_STDFA =            BITS6(1, 1, 0, 1, 1, 1),
    I_OP3_RESERVED_15 =      BITS6(1, 1, 1, 0, 0, 0),
    I_OP3_RESERVED_16 =      BITS6(1, 1, 1, 0, 0, 1),
    I_OP3_RESERVED_17 =      BITS6(1, 1, 1, 0, 1, 0),
    I_OP3_RESERVED_18 =      BITS6(1, 1, 1, 0, 1, 1),
    I_OP3_CASA =             BITS6(1, 1, 1, 1, 0, 0),
    I_OP3_PREFETCHA =        BITS6(1, 1, 1, 1, 0, 1),
    I_OP3_CASXA =            BITS6(1, 1, 1, 1, 1, 0),
    I_OP3_RESERVED_19 =      BITS6(1, 1, 1, 1, 1, 1)
} I_OP3_FMT_LDST;

static const sparc64_opcode *
find_opcode_op3(UInt insn)
{
    UInt i_op3 = BITS(insn, 24, 19);

    switch (i_op3) {
    case I_OP3_LDUW:
        return &sparc64_opcodes[SPARC64_OPC_LDUW];
    case I_OP3_LDUB:
        return &sparc64_opcodes[SPARC64_OPC_LDUB];
    case I_OP3_LDUH:
        return &sparc64_opcodes[SPARC64_OPC_LDUH];
    case I_OP3_LDTW:
        return NULL;
    case I_OP3_STW:
        return &sparc64_opcodes[SPARC64_OPC_STW];
    case I_OP3_STB:
        return &sparc64_opcodes[SPARC64_OPC_STB];
    case I_OP3_STH:
        return &sparc64_opcodes[SPARC64_OPC_STH];
    case I_OP3_STTW:
        return NULL;
    case I_OP3_LDSW:
        return &sparc64_opcodes[SPARC64_OPC_LDSW];
    case I_OP3_LDSB:
        return &sparc64_opcodes[SPARC64_OPC_LDSB];
    case I_OP3_LDSH:
        return &sparc64_opcodes[SPARC64_OPC_LDSH];
    case I_OP3_LDX:
        return &sparc64_opcodes[SPARC64_OPC_LDX];
    case I_OP3_RESERVED_4:
        return NULL;
    case I_OP3_LDSTUB:
        return &sparc64_opcodes[SPARC64_OPC_LDSTUB];
    case I_OP3_STX:
        return &sparc64_opcodes[SPARC64_OPC_STX];
    case I_OP3_SWAP:
        return &sparc64_opcodes[SPARC64_OPC_SWAP];
    case I_OP3_LDUWA:
        return &sparc64_opcodes[SPARC64_OPC_LDUWA];
    case I_OP3_LDUBA:
        return &sparc64_opcodes[SPARC64_OPC_LDUBA];
    case I_OP3_LDUHA:
        return &sparc64_opcodes[SPARC64_OPC_LDUHA];
    case I_OP3_LDTWA_LDTXA:
        return NULL;
    case I_OP3_STWA:
        return &sparc64_opcodes[SPARC64_OPC_STWA];
    case I_OP3_STBA:
        return &sparc64_opcodes[SPARC64_OPC_STBA];
    case I_OP3_STHA:
        return &sparc64_opcodes[SPARC64_OPC_STHA];
    case I_OP3_STTWA:
        return NULL;
    case I_OP3_LDSWA:
        return &sparc64_opcodes[SPARC64_OPC_LDSWA];
    case I_OP3_LDSBA:
        return &sparc64_opcodes[SPARC64_OPC_LDSBA];
    case I_OP3_LDSHA:
        return &sparc64_opcodes[SPARC64_OPC_LDSHA];
    case I_OP3_LDXA:
        return &sparc64_opcodes[SPARC64_OPC_LDXA];
    case I_OP3_RESERVED_5:
        return NULL;
    case I_OP3_LDSTUBA:
        return NULL;
    case I_OP3_STXA:
        return &sparc64_opcodes[SPARC64_OPC_STXA];
    case I_OP3_SWAPA:
        return NULL;
    case I_OP3_LDF:
        return &sparc64_opcodes[SPARC64_OPC_LDF];
    case I_OP3_LDFSR:
        switch (INSN_FMT_RD(insn)) {
        case 0:
            return &sparc64_opcodes[SPARC64_OPC_LDFSR];
        case 1:
            return &sparc64_opcodes[SPARC64_OPC_LDXFSR];
        default:
            return NULL;
        }
        break;
    case I_OP3_LDQF:
        return &sparc64_opcodes[SPARC64_OPC_LDQF];
    case I_OP3_LDDF:
        return &sparc64_opcodes[SPARC64_OPC_LDDF];
    case I_OP3_STF:
        return &sparc64_opcodes[SPARC64_OPC_STF];
    case I_OP3_STFSR:
        switch (INSN_FMT_RD(insn)) {
        case 0:
            return &sparc64_opcodes[SPARC64_OPC_STFSR];
        case 1:
            return &sparc64_opcodes[SPARC64_OPC_STXFSR];
        default:
            return NULL;
        }
        break;
    case I_OP3_STQF:
        return &sparc64_opcodes[SPARC64_OPC_STQF];
    case I_OP3_STDF:
        return &sparc64_opcodes[SPARC64_OPC_STDF];
    case I_OP3_RESERVED_6 ... I_OP3_RESERVED_10:
        return NULL;
        break;
    case I_OP3_PREFETCH:
        return &sparc64_opcodes[SPARC64_OPC_PREFETCH];
    case I_OP3_RESERVED_11 ... I_OP3_RESERVED_12:
        return NULL;
        break;
    case I_OP3_LDFA:
        return &sparc64_opcodes[SPARC64_OPC_LDFA];
    case I_OP3_RESERVED_13:
        return NULL;
        break;
    case I_OP3_LDQFA:
        return &sparc64_opcodes[SPARC64_OPC_LDQFA];
    case I_OP3_LDDFA:
        return find_opcode_LDDFA(insn);
    case I_OP3_STFA:
        return NULL;
    case I_OP3_RESERVED_14:
        return NULL;
    case I_OP3_STQFA:
    case I_OP3_STDFA:
        return NULL;
    case I_OP3_RESERVED_15 ... I_OP3_RESERVED_18:
        return NULL;
    case I_OP3_CASA:
        return &sparc64_opcodes[SPARC64_OPC_CASA];
    case I_OP3_PREFETCHA:
        return &sparc64_opcodes[SPARC64_OPC_PREFETCHA];
    case I_OP3_CASXA:
        return &sparc64_opcodes[SPARC64_OPC_CASXA];
    case I_OP3_RESERVED_19:
        return NULL;
    default:
        vassert(0);
    }
}

#define SPRINT_CHAR(c)    \
    do {                  \
        buf[nout] = (c);  \
        nout += 1;        \
        buf[nout] = '\0'; \
    } while (0)

static UInt
sprint_insn_0_ops(HChar *buf, const sparc64_insn *insn)
{
    UInt nout = vex_sprintf(buf, "%s", insn->opcode->name);
    return nout;
}

static UInt
sprint_insn_1_op(HChar *buf, const sparc64_insn *insn)
{
    const sparc64_opcode *opcode = insn->opcode;
    UInt nout = vex_sprintf(buf, "%s ", opcode->name);

    const sparc64_operand * const *operands = insn->operands;
    const sparc64_operand_value *values = insn->operand_values;
    vassert(opcode->num_operands == 1);

    nout += operands[0]->sprint(buf + nout, values[0]);

    return nout;
}

static UInt
sprint_insn_2_ops(HChar *buf, const sparc64_insn *insn)
{
    const sparc64_opcode *opcode = insn->opcode;
    UInt nout = vex_sprintf(buf, "%s ", opcode->name);

    const sparc64_operand * const *operands = insn->operands;
    const sparc64_operand_value *values = insn->operand_values;
    vassert(opcode->num_operands == 2);

    nout += operands[0]->sprint(buf + nout, values[0]);
    nout += vex_sprintf(buf + nout, ", ");
    nout += operands[1]->sprint(buf + nout, values[1]);

    return nout;
}

static UInt
sprint_insn_3_ops(HChar *buf, const sparc64_insn *insn)
{
    const sparc64_opcode *opcode = insn->opcode;
    UInt nout = vex_sprintf(buf, "%s ", opcode->name);

    const sparc64_operand * const *operands = insn->operands;
    const sparc64_operand_value *values = insn->operand_values;
    vassert(opcode->num_operands == 3);

    nout += operands[0]->sprint(buf + nout, values[0]);
    nout += vex_sprintf(buf + nout, ", ");
    nout += operands[1]->sprint(buf + nout, values[1]);
    nout += vex_sprintf(buf + nout, ", ");
    nout += operands[2]->sprint(buf + nout, values[2]);

    return nout;
}

static UInt
sprint_insn_4_ops(HChar *buf, const sparc64_insn *insn)
{
    const sparc64_opcode *opcode = insn->opcode;
    UInt nout = vex_sprintf(buf, "%s ", opcode->name);

    const sparc64_operand * const *operands = insn->operands;
    const sparc64_operand_value *values = insn->operand_values;
    vassert(opcode->num_operands == 4);

    nout += operands[0]->sprint(buf + nout, values[0]);
    nout += vex_sprintf(buf + nout, ", ");
    nout += operands[1]->sprint(buf + nout, values[1]);
    nout += vex_sprintf(buf + nout, ", ");
    nout += operands[2]->sprint(buf + nout, values[2]);
    nout += vex_sprintf(buf + nout, ", ");
    nout += operands[3]->sprint(buf + nout, values[3]);

    return nout;
}

static UInt
sprint_insn_bicc(HChar *buf, const sparc64_insn *insn)
{
    const sparc64_opcode *opcode = insn->opcode;
    UInt nout = vex_sprintf(buf, "%s", opcode->name);

    const sparc64_operand * const *operands = insn->operands;
    const sparc64_operand_value *values = insn->operand_values;
    vassert(opcode->num_operands == 2);

    nout += operands[0]->sprint(buf + nout, values[0]);
    SPRINT_CHAR(' ');
    nout += operands[1]->sprint(buf + nout, values[1]);

    return nout;
}

static UInt
sprint_insn_bpcc_bpr_fbpfcc(HChar *buf, const sparc64_insn *insn)
{
    const sparc64_opcode *opcode = insn->opcode;
    UInt nout = vex_sprintf(buf, "%s", opcode->name);

    const sparc64_operand * const *operands = insn->operands;
    const sparc64_operand_value *values = insn->operand_values;
    vassert(opcode->num_operands == 4);

    nout += operands[0]->sprint(buf + nout, values[0]);
    SPRINT_CHAR(',');
    nout += operands[1]->sprint(buf + nout, values[1]);
    SPRINT_CHAR(' ');
    nout += operands[2]->sprint(buf + nout, values[2]);
    nout += vex_sprintf(buf + nout, ", ");
    nout += operands[3]->sprint(buf + nout, values[3]);

    return nout;
}


static UInt
sprint_insn_cas_asi(HChar *buf, const sparc64_insn *insn)
{
    const sparc64_opcode *opcode = insn->opcode;
    UInt nout = vex_sprintf(buf, "%s [", opcode->name);

    const sparc64_operand * const *operands = insn->operands;
    const sparc64_operand_value *values = insn->operand_values;
    vassert(opcode->num_operands == 4);

    nout += operands[0]->sprint(buf + nout, values[0]);
    nout += vex_sprintf(buf + nout, "] ");
    nout += operands[1]->sprint(buf + nout, values[1]);
    nout += vex_sprintf(buf + nout, ", ");
    nout += operands[2]->sprint(buf + nout, values[2]);
    nout += vex_sprintf(buf + nout, ", ");
    nout += operands[3]->sprint(buf + nout, values[3]);

    return nout;
}

static UInt
sprint_insn_flush(HChar *buf, const sparc64_insn *insn)
{
    const sparc64_opcode *opcode = insn->opcode;
    UInt nout = vex_sprintf(buf, "%s [", opcode->name);

    const sparc64_operand * const *operands = insn->operands;
    const sparc64_operand_value *values = insn->operand_values;
    vassert(opcode->num_operands == 2);

    nout += operands[0]->sprint(buf + nout, values[0]);
    nout += vex_sprintf(buf + nout, " + ");
    nout += operands[1]->sprint(buf + nout, values[1]);
    SPRINT_CHAR(']');

    return nout;
}

static UInt
sprint_insn_jmpl(HChar *buf, const sparc64_insn *insn)
{
    const sparc64_opcode *opcode = insn->opcode;
    UInt nout = vex_sprintf(buf, "%s ", opcode->name);

    const sparc64_operand * const *operands = insn->operands;
    const sparc64_operand_value *values = insn->operand_values;
    vassert(opcode->num_operands == 3);

    nout += operands[0]->sprint(buf + nout, values[0]);
    nout += vex_sprintf(buf + nout, " + ");
    nout += operands[1]->sprint(buf + nout, values[1]);
    nout += vex_sprintf(buf + nout, ", ");
    nout += operands[2]->sprint(buf + nout, values[2]);

    return nout;
}

static UInt
sprint_insn_load(HChar *buf, const sparc64_insn *insn)
{
    const sparc64_opcode *opcode = insn->opcode;
    UInt nout = vex_sprintf(buf, "%s [", opcode->name);

    const sparc64_operand * const *operands = insn->operands;
    const sparc64_operand_value *values = insn->operand_values;
    vassert(opcode->num_operands == 3);

    nout += operands[0]->sprint(buf + nout, values[0]);
    nout += vex_sprintf(buf + nout, " + ");
    nout += operands[1]->sprint(buf + nout, values[1]);
    nout += vex_sprintf(buf + nout, "], ");
    nout += operands[2]->sprint(buf + nout, values[2]);

    return nout;
}

static UInt
sprint_insn_load_asi(HChar *buf, const sparc64_insn *insn)
{
    const sparc64_opcode *opcode = insn->opcode;
    UInt nout = vex_sprintf(buf, "%s [", opcode->name);

    const sparc64_operand * const *operands = insn->operands;
    const sparc64_operand_value *values = insn->operand_values;
    vassert(opcode->num_operands == 4);

    nout += operands[0]->sprint(buf + nout, values[0]);
    nout += vex_sprintf(buf + nout, " + ");
    nout += operands[1]->sprint(buf + nout, values[1]);
    nout += vex_sprintf(buf + nout, "] ");
    nout += operands[2]->sprint(buf + nout, values[2]);
    nout += vex_sprintf(buf + nout, ", ");
    nout += operands[3]->sprint(buf + nout, values[3]);

    return nout;
}

static UInt
sprint_insn_ldfsr(HChar *buf, const sparc64_insn *insn)
{
    const sparc64_opcode *opcode = insn->opcode;
    UInt nout = vex_sprintf(buf, "%s [", opcode->name);

    const sparc64_operand * const *operands = insn->operands;
    const sparc64_operand_value *values = insn->operand_values;
    vassert(opcode->num_operands == 3);

    nout += operands[0]->sprint(buf + nout, values[0]);
    nout += vex_sprintf(buf + nout, " + ");
    nout += operands[1]->sprint(buf + nout, values[1]);
    nout += vex_sprintf(buf + nout, "], ");
    switch (values[2].uintval) {
    case 0 ... 1:
        nout += vex_sprintf(buf + nout, "%%fsr");
        break;
    default:
        vassert(0);
    }

    return nout;
}


static UInt
sprint_insn_membar(HChar *buf, const sparc64_insn *insn)
{
    const sparc64_opcode *opcode = insn->opcode;
    UInt nout = vex_sprintf(buf, "%s", opcode->name);

    const sparc64_operand * const *operands = insn->operands;
    const sparc64_operand_value *values = insn->operand_values;
    vassert(opcode->num_operands == 2);

    if ((values[0].uintval != 0) || (values[1].uintval != 0)) {
        SPRINT_CHAR(' ');
    }

    Bool include_separator = False;
    if (values[0].uintval != 0) {
        nout += operands[0]->sprint(buf + nout, values[0]);
        include_separator = True;
    }

    if (values[1].uintval != 0) {
        if (include_separator) {
            SPRINT_CHAR('|');
        }
        nout += operands[1]->sprint(buf + nout, values[1]);
    }

    return nout;
}

static UInt
sprint_insn_rdasr(HChar *buf, const sparc64_insn *insn)
{
    const sparc64_operand * const *operands = insn->operands;
    const sparc64_operand_value *values = insn->operand_values;
    vassert(insn->opcode->num_operands == 2);

    UInt nout = vex_sprintf(buf, "rd %s, ", asr_name(values[0].uintval));
    nout += operands[1]->sprint(buf + nout, values[1]);

    return nout;
}

static UInt
sprint_insn_return(HChar *buf, const sparc64_insn *insn)
{
    const sparc64_opcode *opcode = insn->opcode;
    UInt nout = vex_sprintf(buf, "%s ", opcode->name);

    const sparc64_operand * const *operands = insn->operands;
    const sparc64_operand_value *values = insn->operand_values;
    vassert(opcode->num_operands == 2);

    nout += operands[0]->sprint(buf + nout, values[0]);
    nout += vex_sprintf(buf + nout, " + ");
    nout += operands[1]->sprint(buf + nout, values[1]);

    return nout;
}

static UInt
sprint_insn_store(HChar *buf, const sparc64_insn *insn)
{
    const sparc64_opcode *opcode = insn->opcode;
    UInt nout = vex_sprintf(buf, "%s ", opcode->name);

    const sparc64_operand * const *operands = insn->operands;
    const sparc64_operand_value *values = insn->operand_values;
    vassert(opcode->num_operands == 3);

    nout += operands[0]->sprint(buf + nout, values[0]);
    nout += vex_sprintf(buf + nout, ", [");
    nout += operands[1]->sprint(buf + nout, values[1]);
    nout += vex_sprintf(buf + nout, " + ");
    nout += operands[2]->sprint(buf + nout, values[2]);
    SPRINT_CHAR(']');

    return nout;
}

static UInt
sprint_insn_store_asi(HChar *buf, const sparc64_insn *insn)
{
    const sparc64_opcode *opcode = insn->opcode;
    UInt nout = vex_sprintf(buf, "%s ", opcode->name);

    const sparc64_operand * const *operands = insn->operands;
    const sparc64_operand_value *values = insn->operand_values;
    vassert(opcode->num_operands == 4);

    nout += operands[0]->sprint(buf + nout, values[0]);
    nout += vex_sprintf(buf + nout, ", [");
    nout += operands[1]->sprint(buf + nout, values[1]);
    nout += vex_sprintf(buf + nout, " + ");
    nout += operands[2]->sprint(buf + nout, values[2]);
    nout += vex_sprintf(buf + nout, "] ");
    nout += operands[3]->sprint(buf + nout, values[3]);

    return nout;
}

static UInt
sprint_insn_stfsr(HChar *buf, const sparc64_insn *insn)
{
    const sparc64_opcode *opcode = insn->opcode;
    UInt nout = vex_sprintf(buf, "%s ", opcode->name);

    const sparc64_operand * const *operands = insn->operands;
    const sparc64_operand_value *values = insn->operand_values;
    vassert(opcode->num_operands == 3);

    switch (values[0].uintval) {
    case 0 ... 1:
        nout += vex_sprintf(buf + nout, "%%fsr");
        break;
    default:
        vassert(0);
    }
    nout += vex_sprintf(buf + nout, ", [");
    nout += operands[1]->sprint(buf + nout, values[1]);
    nout += vex_sprintf(buf + nout, " + ");
    nout += operands[2]->sprint(buf + nout, values[2]);
    SPRINT_CHAR(']');

    return nout;
}

static UInt
sprint_insn_wrasr(HChar *buf, const sparc64_insn *insn)
{
    const sparc64_operand * const *operands = insn->operands;
    const sparc64_operand_value *values = insn->operand_values;
    vassert(insn->opcode->num_operands == 3);

    UInt nout = vex_sprintf(buf, "wr ");
    nout += operands[0]->sprint(buf + nout, values[0]);
    nout += vex_sprintf(buf + nout, ", ");
    nout += operands[1]->sprint(buf + nout, values[1]);
    nout += vex_sprintf(buf + nout, ", %s", asr_name(values[2].uintval));

    return nout;
}

/*----------------------------------------------------------------------------*/
/*--- Opcodes.                                                             ---*/
/*----------------------------------------------------------------------------*/

/* Creates an opcode from I_OP3_BRANCH enum. */
#define INSN_BRANCH(op3)          ((op3) << 22)
/* Creates a Bicc opcode from I_COND enum. */
#define INSN_Bicc(cond)           INSN_BRANCH(I_OP3_Bicc) | ((cond) << 25)
/* Creates a BPcc opcode from I_COND enum. */
#define INSN_BPcc(cond)           INSN_BRANCH(I_OP3_BPcc) | ((cond) << 25)
/* Creates a BPr opcode from I_RCOND enum. */
#define INSN_BPr(rcond)           INSN_BRANCH(I_OP3_BPr_CBcond) | ((rcond) << 25)
#define INSN_CBcond_HI(cond)      ((cond) >> 3)
#define INSN_CBcond_LO(cond)      ((cond) & 0x7)
/* Creates a CBcond opcode from I_COND enum and cx/cw designation (cc2). */
#define INSN_CBcond(cond, cc2)    INSN_BRANCH(I_OP3_BPr_CBcond) | \
                                  (1 << 28) | ((cc2) << 21) | \
                                  (INSN_CBcond_HI(cond) << 29) | \
                                  (INSN_CBcond_LO(cond) << 25)
/* Creates a CWBcond or CXBcond opcode from I_COND enum. */
#define INSN_CWBcond(cond)        INSN_CBcond(cond, 0)
#define INSN_CXBcond(cond)        INSN_CBcond(cond, 1)
/* Creates an FBPfcc opcode from F_COND enum. */
#define INSN_FBPfcc(cond)         INSN_BRANCH(I_OP3_FBPfcc) | ((cond) << 25)

/* Creates an opcode from I_OP3_FMT_SAR enum. */
#define INSN_OP3(op3)             (1 << 31) | ((op3) << 19)
#define INSN_OP3_X(x)             ((x) << 12)
#define INSN_OP3_AES_DES(op5)     INSN_OP3(I_OP3_AES_DES_CAMELLIA) | ((op5) << 5)
#define INSN_OP3_FMAf(op5)        INSN_OP3(I_OP3_FMAf) | ((op5) << 5)
/* Creates an FPop1 opcode from I_FPop1 enum. */
#define INSN_FPop1(opf)           INSN_OP3(I_OP3_FPop1) | ((opf) << 5)
/* Creates an FPop2 opcode from I_FPop2 enum. */
#define INSN_FPop2(opf)           INSN_OP3(I_OP3_FPop2) | ((opf) << 5)
/* Creates a VIS opcode from I_VIS enum. */
#define INSN_VIS(opf)             INSN_OP3(I_OP3_VIS) | ((opf) << 5)
/* Creates an FMOVSfcc opcode from F_COND enum. */
#define INSN_FMOVSfcc(cond)       INSN_FPop2(I_FMOVSfcc) | ((cond) << 14)
/* Creates an FMOVDfcc opcode from F_COND enum. */
#define INSN_FMOVDfcc(cond)       INSN_FPop2(I_FMOVDfcc) | ((cond) << 14)
/* Creates an FMOVQfcc opcode from F_COND enum. */
#define INSN_FMOVQfcc(cond)       INSN_FPop2(I_FMOVQfcc) | ((cond) << 14)
/* Creates an FMOVSicc opcode from I_COND enum. */
#define INSN_FMOVSicc(cond)       INSN_FPop2(I_FMOVSicc) | ((cond) << 14)
/* Creates an FMOVDicc opcode from I_COND enum. */
#define INSN_FMOVDicc(cond)       INSN_FPop2(I_FMOVDicc) | ((cond) << 14)
/* Creates an FMOVQicc opcode from I_COND enum. */
#define INSN_FMOVQicc(cond)       INSN_FPop2(I_FMOVQicc) | ((cond) << 14)
/* Creates a MOVcc opcode from F_COND enum. */
#define INSN_MOVfcc(cond)         INSN_OP3(I_OP3_MOVcc) | (0 << 18) | \
                                  ((cond) << 14)
/* Creates a MOVcc opcode from I_COND enum. */
#define INSN_MOVicc(cond)         INSN_OP3(I_OP3_MOVcc) | (1 << 18) | \
                                  ((cond) << 14)
/* Creates a MOVr opcode from I_RCOND enum. */
#define INSN_MOVr(rcond)          INSN_OP3(I_OP3_MOVr) | ((rcond) << 10)
/* Creates a Tcc opcode from I_COND enum. */
#define INSN_Tcc(cond)            INSN_OP3(I_OP3_Tcc) | ((cond) << 25)

/* Creates an opcode from I_OP3_LDST enum (loads & stores). */
#define INSN_LDST(op3)             (0x3 << 30) | ((op3) << 19)

/* Array of sparc64 opcodes sorted according to sparc64_mnemonic enum. */
static const sparc64_opcode sparc64_opcodes[SPARC64_OPC_LAST] = {
{"none-unrecognized", SPARC64_OPC_NONE,
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 0, 0, {}, sprint_insn_0_ops},
{"add", SPARC64_OPC_ADD, INSN_OP3(I_OP3_ADD),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"addcc", SPARC64_OPC_ADDcc, INSN_OP3(I_OP3_ADDcc),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_CCR_OUT,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"addc", SPARC64_OPC_ADDC, INSN_OP3(I_OP3_ADDC),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_CCR_CARRY_IN,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"addccc", SPARC64_OPC_ADDCcc, INSN_OP3(I_OP3_ADDCcc),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_CCR_CARRY_IN | SPARC64_OPF_CCR_OUT,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"addxc", SPARC64_OPC_ADDXC, INSN_VIS(I_ADDXC),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CCR_CARRY_IN,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_IREG_RS2,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"addxccc", SPARC64_OPC_ADDXCcc, INSN_VIS(I_ADDXCcc),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CCR_CARRY_IN | SPARC64_OPF_CCR_OUT,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_IREG_RS2,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"aes_eround01", SPARC64_OPC_AES_EROUND01, INSN_OP3_AES_DES(I_OP5_AES_EROUND01),
 VEX_HWCAPS_SPARC64_SPARC4, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RS3, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_4_ops},
{"aes_eround23", SPARC64_OPC_AES_EROUND23, INSN_OP3_AES_DES(I_OP5_AES_EROUND23),
 VEX_HWCAPS_SPARC64_SPARC4, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RS3, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_4_ops},
{"aes_dround01", SPARC64_OPC_AES_DROUND01, INSN_OP3_AES_DES(I_OP5_AES_DROUND01),
 VEX_HWCAPS_SPARC64_SPARC4, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RS3, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_4_ops},
{"aes_dround23", SPARC64_OPC_AES_DROUND23, INSN_OP3_AES_DES(I_OP5_AES_DROUND23),
 VEX_HWCAPS_SPARC64_SPARC4, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RS3, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_4_ops},
{"aes_eround01_l", SPARC64_OPC_AES_EROUND01_LAST,
 INSN_OP3_AES_DES(I_OP5_AES_EROUND01_LAST),
 VEX_HWCAPS_SPARC64_SPARC4, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RS3, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_4_ops},
{"aes_eround23_l", SPARC64_OPC_AES_EROUND23_LAST,
 INSN_OP3_AES_DES(I_OP5_AES_EROUND23_LAST),
 VEX_HWCAPS_SPARC64_SPARC4, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RS3, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_4_ops},
{"aes_dround01_l", SPARC64_OPC_AES_DROUND01_LAST,
 INSN_OP3_AES_DES(I_OP5_AES_DROUND01_LAST),
 VEX_HWCAPS_SPARC64_SPARC4, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RS3, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_4_ops},
{"aes_dround23_l", SPARC64_OPC_AES_DROUND23_LAST,
 INSN_OP3_AES_DES(I_OP5_AES_DROUND23_LAST),
 VEX_HWCAPS_SPARC64_SPARC4, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RS3, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_4_ops},
{"aes_kexpand1", SPARC64_OPC_AES_KEXPAND1, INSN_OP3_AES_DES(I_OP5_AES_KEXPAND1),
 VEX_HWCAPS_SPARC64_SPARC4, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_IMM5, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_4_ops},
{"aes_kexpand0", SPARC64_OPC_AES_KEXPAND0, INSN_VIS(I_AES_KEXPAND0),
 VEX_HWCAPS_SPARC64_SPARC4, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"aes_kexpand2", SPARC64_OPC_AES_KEXPAND2, INSN_VIS(I_AES_KEXPAND2),
 VEX_HWCAPS_SPARC64_SPARC4, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"alignaddr", SPARC64_OPC_ALIGNADDRESS, INSN_VIS(I_ALIGNADDRESS),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_GSR_OUT,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_IREG_RS2,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"and", SPARC64_OPC_AND, INSN_OP3(I_OP3_AND),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"andcc", SPARC64_OPC_ANDcc, INSN_OP3(I_OP3_ANDcc),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_CCR_OUT,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"andn", SPARC64_OPC_ANDN, INSN_OP3(I_OP3_ANDN),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"andncc", SPARC64_OPC_ANDNcc, INSN_OP3(I_OP3_ANDNcc),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_CCR_OUT,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"ba", SPARC64_OPC_BA, INSN_Bicc(I_COND_A),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI,
 2, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_DISP22}, sprint_insn_bicc},
{"bn", SPARC64_OPC_BN, INSN_Bicc(I_COND_N),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI,
 2, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_DISP22}, sprint_insn_bicc},
{"bne", SPARC64_OPC_BNE, INSN_Bicc(I_COND_NE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_CCR_ZERO_IN,
 2, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_DISP22}, sprint_insn_bicc},
{"be", SPARC64_OPC_BE, INSN_Bicc(I_COND_E),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_CCR_ZERO_IN,
 2, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_DISP22}, sprint_insn_bicc},
{"bg", SPARC64_OPC_BG, INSN_Bicc(I_COND_G),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_CCR_OVERFLOW_IN |
 SPARC64_OPF_CCR_ZERO_IN | SPARC64_OPF_CCR_NEGATIVE_IN,
 2, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_DISP22}, sprint_insn_bicc},
{"ble", SPARC64_OPC_BLE, INSN_Bicc(I_COND_LE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_CCR_OVERFLOW_IN |
 SPARC64_OPF_CCR_ZERO_IN | SPARC64_OPF_CCR_NEGATIVE_IN,
 2, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_DISP22}, sprint_insn_bicc},
{"bge", SPARC64_OPC_BGE, INSN_Bicc(I_COND_GE),
 VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_dCTI | SPARC64_OPF_CCR_OVERFLOW_IN | SPARC64_OPF_CCR_NEGATIVE_IN,
 2, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_DISP22}, sprint_insn_bicc},
{"bl", SPARC64_OPC_BL, INSN_Bicc(I_COND_L),
 VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_dCTI | SPARC64_OPF_CCR_OVERFLOW_IN | SPARC64_OPF_CCR_NEGATIVE_IN,
 2, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_DISP22}, sprint_insn_bicc},
{"bgu", SPARC64_OPC_BGU, INSN_Bicc(I_COND_GU),
 VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_dCTI | SPARC64_OPF_CCR_CARRY_IN | SPARC64_OPF_CCR_ZERO_IN,
 2, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_DISP22}, sprint_insn_bicc},
{"bleu", SPARC64_OPC_BLEU, INSN_Bicc(I_COND_LEU),
 VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_dCTI | SPARC64_OPF_CCR_CARRY_IN | SPARC64_OPF_CCR_ZERO_IN,
 2, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_DISP22}, sprint_insn_bicc},
{"bcc", SPARC64_OPC_BCC, INSN_Bicc(I_COND_CC),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_CCR_CARRY_IN,
 2, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_DISP22}, sprint_insn_bicc},
{"bcs", SPARC64_OPC_BCS, INSN_Bicc(I_COND_CS),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_CCR_CARRY_IN,
 2, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_DISP22}, sprint_insn_bicc},
{"bpos", SPARC64_OPC_BPOS, INSN_Bicc(I_COND_POS),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_CCR_NEGATIVE_IN,
 2, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_DISP22}, sprint_insn_bicc},
{"bneg", SPARC64_OPC_BNEG, INSN_Bicc(I_COND_NEG),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_CCR_NEGATIVE_IN,
 2, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_DISP22}, sprint_insn_bicc},
{"bvc", SPARC64_OPC_BVC, INSN_Bicc(I_COND_VC),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_CCR_OVERFLOW_IN,
 2, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_DISP22}, sprint_insn_bicc},
{"bvs", SPARC64_OPC_BVS, INSN_Bicc(I_COND_VS),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_CCR_OVERFLOW_IN,
 2, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_DISP22}, sprint_insn_bicc},
{"bmask", SPARC64_OPC_BMASK, INSN_VIS(I_BMASK),
 VEX_HWCAPS_SPARC64_VIS2, SPARC64_OPF_GSR_OUT,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_IREG_RS2,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"bshuffle", SPARC64_OPC_BSHUFFLE, INSN_VIS(I_BSHUFFLE),
 VEX_HWCAPS_SPARC64_VIS2, SPARC64_OPF_GSR_MASK_IN,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"ba", SPARC64_OPC_BPA, INSN_BPcc(I_COND_A),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_I_OR_X_CC_BPcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"bn", SPARC64_OPC_BPN, INSN_BPcc(I_COND_N),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_I_OR_X_CC_BPcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"bne", SPARC64_OPC_BPNE, INSN_BPcc(I_COND_NE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_CCR_ZERO_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_I_OR_X_CC_BPcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"be", SPARC64_OPC_BPE, INSN_BPcc(I_COND_E),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_CCR_ZERO_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_I_OR_X_CC_BPcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"bg", SPARC64_OPC_BPG, INSN_BPcc(I_COND_G),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_CCR_OVERFLOW_IN |
 SPARC64_OPF_CCR_ZERO_IN | SPARC64_OPF_CCR_NEGATIVE_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_I_OR_X_CC_BPcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"ble", SPARC64_OPC_BPLE, INSN_BPcc(I_COND_LE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_CCR_OVERFLOW_IN |
 SPARC64_OPF_CCR_ZERO_IN | SPARC64_OPF_CCR_NEGATIVE_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_I_OR_X_CC_BPcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"bge", SPARC64_OPC_BPGE, INSN_BPcc(I_COND_GE),
 VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_dCTI | SPARC64_OPF_CCR_OVERFLOW_IN | SPARC64_OPF_CCR_NEGATIVE_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_I_OR_X_CC_BPcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"bl", SPARC64_OPC_BPL, INSN_BPcc(I_COND_L),
 VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_dCTI | SPARC64_OPF_CCR_OVERFLOW_IN | SPARC64_OPF_CCR_NEGATIVE_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_I_OR_X_CC_BPcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"bgu", SPARC64_OPC_BPGU, INSN_BPcc(I_COND_GU),
 VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_dCTI | SPARC64_OPF_CCR_CARRY_IN | SPARC64_OPF_CCR_ZERO_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_I_OR_X_CC_BPcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"bleu", SPARC64_OPC_BPLEU, INSN_BPcc(I_COND_LEU),
 VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_dCTI | SPARC64_OPF_CCR_CARRY_IN | SPARC64_OPF_CCR_ZERO_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_I_OR_X_CC_BPcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"bcc", SPARC64_OPC_BPCC, INSN_BPcc(I_COND_CC),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_CCR_CARRY_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_I_OR_X_CC_BPcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"bcs", SPARC64_OPC_BPCS, INSN_BPcc(I_COND_CS),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_CCR_CARRY_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_I_OR_X_CC_BPcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"bpos", SPARC64_OPC_BPPOS, INSN_BPcc(I_COND_POS),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_CCR_NEGATIVE_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_I_OR_X_CC_BPcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"bneg", SPARC64_OPC_BPNEG, INSN_BPcc(I_COND_NEG),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_CCR_NEGATIVE_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_I_OR_X_CC_BPcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"bvc", SPARC64_OPC_BPVC, INSN_BPcc(I_COND_VC),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_CCR_OVERFLOW_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_I_OR_X_CC_BPcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"bvs", SPARC64_OPC_BPVS, INSN_BPcc(I_COND_VS),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_CCR_OVERFLOW_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_I_OR_X_CC_BPcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"brz", SPARC64_OPC_BRZ, INSN_BPr(I_RCOND_Z),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_DISP16},
 sprint_insn_bpcc_bpr_fbpfcc},
{"brlez", SPARC64_OPC_BRLEZ, INSN_BPr(I_RCOND_LEZ),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_DISP16},
 sprint_insn_bpcc_bpr_fbpfcc},
{"brlz", SPARC64_OPC_BRLZ, INSN_BPr(I_RCOND_LZ),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_DISP16},
 sprint_insn_bpcc_bpr_fbpfcc},
{"brnz", SPARC64_OPC_BRNZ, INSN_BPr(I_RCOND_NZ),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_DISP16},
 sprint_insn_bpcc_bpr_fbpfcc},
{"brgz", SPARC64_OPC_BRGZ, INSN_BPr(I_RCOND_GZ),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_DISP16},
 sprint_insn_bpcc_bpr_fbpfcc},
{"brgez", SPARC64_OPC_BRGEZ, INSN_BPr(I_RCOND_GEZ),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_DISP16},
 sprint_insn_bpcc_bpr_fbpfcc},
{"call", SPARC64_OPC_CALL, 1 << 30, VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_dCTI | SPARC64_OPF_O7_OUT,
 1, {SPARC64_OP_TYPE_DISP30}, sprint_insn_1_op},
{"casa", SPARC64_OPC_CASA, INSN_LDST(I_OP3_CASA),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_ASI_IMPL_OR_IMM,
     SPARC64_OP_TYPE_IREG_RS2, SPARC64_OP_TYPE_IREG_RDINOUT},
 sprint_insn_cas_asi},
{"casxa", SPARC64_OPC_CASXA, INSN_LDST(I_OP3_CASXA),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_ASI_IMPL_OR_IMM,
     SPARC64_OP_TYPE_IREG_RS2, SPARC64_OP_TYPE_IREG_RDINOUT},
 sprint_insn_cas_asi},
{"cwbne", SPARC64_OPC_CWBNE, INSN_CWBcond(I_COND_NE),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cwbe", SPARC64_OPC_CWBE, INSN_CWBcond(I_COND_E),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cwbg", SPARC64_OPC_CWBG, INSN_CWBcond(I_COND_G),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cwble", SPARC64_OPC_CWBLE, INSN_CWBcond(I_COND_LE),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cwbge", SPARC64_OPC_CWBGE, INSN_CWBcond(I_COND_GE),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cwbl", SPARC64_OPC_CWBL, INSN_CWBcond(I_COND_L),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cwbgu", SPARC64_OPC_CWBGU, INSN_CWBcond(I_COND_GU),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cwbleu", SPARC64_OPC_CWBLEU, INSN_CWBcond(I_COND_LEU),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cwbcc", SPARC64_OPC_CWBCC, INSN_CWBcond(I_COND_CC),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cwbcs", SPARC64_OPC_CWBCS, INSN_CWBcond(I_COND_CS),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cwbpos", SPARC64_OPC_CWBPOS, INSN_CWBcond(I_COND_POS),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cwbneg", SPARC64_OPC_CWBNEG, INSN_CWBcond(I_COND_NEG),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cwbvc", SPARC64_OPC_CWBVC, INSN_CWBcond(I_COND_VC),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cwbvs", SPARC64_OPC_CWBVS, INSN_CWBcond(I_COND_VS),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cxbne", SPARC64_OPC_CXBNE, INSN_CXBcond(I_COND_NE),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cxbe", SPARC64_OPC_CXBE, INSN_CXBcond(I_COND_E),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cxbg", SPARC64_OPC_CXBG, INSN_CXBcond(I_COND_G),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cxble", SPARC64_OPC_CXBLE, INSN_CXBcond(I_COND_LE),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cxbge", SPARC64_OPC_CXBGE, INSN_CXBcond(I_COND_GE),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cxbl", SPARC64_OPC_CXBL, INSN_CXBcond(I_COND_L),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cxbgu", SPARC64_OPC_CXBGU, INSN_CXBcond(I_COND_GU),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cxbleu", SPARC64_OPC_CXBLEU, INSN_CXBcond(I_COND_LEU),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cxbcc", SPARC64_OPC_CXBCC, INSN_CXBcond(I_COND_CC),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cxbcs", SPARC64_OPC_CXBCS, INSN_CXBcond(I_COND_CS),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cxbpos", SPARC64_OPC_CXBPOS, INSN_CXBcond(I_COND_POS),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cxbneg", SPARC64_OPC_CXBNEG, INSN_CXBcond(I_COND_NEG),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cxbvc", SPARC64_OPC_CXBVC, INSN_CXBcond(I_COND_VC),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"cxbvs", SPARC64_OPC_CXBVS, INSN_CXBcond(I_COND_VS),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_CTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM5,
     SPARC64_OP_TYPE_DISP10}, sprint_insn_3_ops},
{"fabss", SPARC64_OPC_FABSs, INSN_FPop1(I_FABSs),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 2, {SPARC64_OP_TYPE_FREG32_RS2, SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_2_ops},
{"fabsd", SPARC64_OPC_FABSd, INSN_FPop1(I_FABSd),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 2, {SPARC64_OP_TYPE_FREG64_RS2, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_2_ops},
{"fabsq", SPARC64_OPC_FABSq, INSN_FPop1(I_FABSq),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 2, {SPARC64_OP_TYPE_FREG128_RS2, SPARC64_OP_TYPE_FREG128_RD},
 sprint_insn_2_ops},
{"fadds", SPARC64_OPC_FADDs, INSN_FPop1(I_FADDs),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_FSR_RD_IN,
 3, {SPARC64_OP_TYPE_FREG32_RS1, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"faddd", SPARC64_OPC_FADDd, INSN_FPop1(I_FADDd),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_FSR_RD_IN,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"faddq", SPARC64_OPC_FADDq, INSN_FPop1(I_FADDq),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_FSR_RD_IN,
 3, {SPARC64_OP_TYPE_FREG128_RS1, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"faligndata", SPARC64_OPC_FALIGNDATAg, INSN_VIS(I_FALIGNDATAg),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_GSR_ALIGN_IN,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fba", SPARC64_OPC_FBPA, INSN_FBPfcc(F_COND_A),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_FCCn_FBPfcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"fbn", SPARC64_OPC_FBPN, INSN_FBPfcc(F_COND_N),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_FCCn_FBPfcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"fbu", SPARC64_OPC_FBPU, INSN_FBPfcc(F_COND_U),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_FSR_FCC_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_FCCn_FBPfcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"fbg", SPARC64_OPC_FBPG, INSN_FBPfcc(F_COND_G),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_FSR_FCC_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_FCCn_FBPfcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"fbug", SPARC64_OPC_FBPUG, INSN_FBPfcc(F_COND_UG),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_FSR_FCC_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_FCCn_FBPfcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"fbl", SPARC64_OPC_FBPL, INSN_FBPfcc(F_COND_L),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_FSR_FCC_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_FCCn_FBPfcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"fbul", SPARC64_OPC_FBPUL, INSN_FBPfcc(F_COND_UL),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_FSR_FCC_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_FCCn_FBPfcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"fblg", SPARC64_OPC_FBPLG, INSN_FBPfcc(F_COND_LG),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_FSR_FCC_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_FCCn_FBPfcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"fbne", SPARC64_OPC_FBPNE, INSN_FBPfcc(F_COND_NE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_FSR_FCC_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_FCCn_FBPfcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"fbe", SPARC64_OPC_FBPE, INSN_FBPfcc(F_COND_E),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_FSR_FCC_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_FCCn_FBPfcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"fbue", SPARC64_OPC_FBPUE, INSN_FBPfcc(F_COND_UE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_FSR_FCC_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_FCCn_FBPfcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"fbge", SPARC64_OPC_FBPGE, INSN_FBPfcc(F_COND_GE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_FSR_FCC_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_FCCn_FBPfcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"fbuge", SPARC64_OPC_FBPUGE, INSN_FBPfcc(F_COND_UGE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_FSR_FCC_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_FCCn_FBPfcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"fble", SPARC64_OPC_FBPLE, INSN_FBPfcc(F_COND_LE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_FSR_FCC_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_FCCn_FBPfcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"fbule", SPARC64_OPC_FBPULE, INSN_FBPfcc(F_COND_ULE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_FSR_FCC_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_FCCn_FBPfcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"fbo", SPARC64_OPC_FBPO, INSN_FBPfcc(F_COND_O),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_FSR_FCC_IN,
 4, {SPARC64_OP_TYPE_ANNUL, SPARC64_OP_TYPE_PREDICTION,
     SPARC64_OP_TYPE_FCCn_FBPfcc, SPARC64_OP_TYPE_DISP19},
 sprint_insn_bpcc_bpr_fbpfcc},
{"fcmps", SPARC64_OPC_FCMPs, INSN_FPop2(I_FCMPs),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FCMP, SPARC64_OP_TYPE_FREG32_RS1,
     SPARC64_OP_TYPE_FREG32_RS2}, sprint_insn_3_ops},
{"fcmpd", SPARC64_OPC_FCMPd, INSN_FPop2(I_FCMPd),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FCMP, SPARC64_OP_TYPE_FREG64_RS1,
     SPARC64_OP_TYPE_FREG64_RS2}, sprint_insn_3_ops},
{"fcmpq", SPARC64_OPC_FCMPq, INSN_FPop2(I_FCMPq),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FCMP, SPARC64_OP_TYPE_FREG128_RS1,
     SPARC64_OP_TYPE_FREG128_RS2}, sprint_insn_3_ops},
{"fcmpes", SPARC64_OPC_FCMPEs, INSN_FPop2(I_FCMPEs),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FCMP, SPARC64_OP_TYPE_FREG32_RS1,
     SPARC64_OP_TYPE_FREG32_RS2}, sprint_insn_3_ops},
{"fcmped", SPARC64_OPC_FCMPEd, INSN_FPop2(I_FCMPEd),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FCMP, SPARC64_OP_TYPE_FREG64_RS1,
     SPARC64_OP_TYPE_FREG64_RS2}, sprint_insn_3_ops},
{"fcmpeq", SPARC64_OPC_FCMPEq, INSN_FPop2(I_FCMPEq),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FCMP, SPARC64_OP_TYPE_FREG128_RS1,
     SPARC64_OP_TYPE_FREG128_RS2}, sprint_insn_3_ops},
{"fdivs", SPARC64_OPC_FDIVs, INSN_FPop1(I_FDIVs),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_FSR_RD_IN,
 3, {SPARC64_OP_TYPE_FREG32_RS1, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fdivd", SPARC64_OPC_FDIVd, INSN_FPop1(I_FDIVd),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_FSR_RD_IN,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fdivq", SPARC64_OPC_FDIVq, INSN_FPop1(I_FDIVq),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_FSR_RD_IN,
 3, {SPARC64_OP_TYPE_FREG128_RS1, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fitos", SPARC64_OPC_FiTOs, INSN_FPop1(I_FiTOs),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_FSR_RD_IN,
 2, {SPARC64_OP_TYPE_FREG32_RS2, SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_2_ops},
{"fitod", SPARC64_OPC_FiTOd, INSN_FPop1(I_FiTOd),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_FREG32_RS2, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_2_ops},
{"fitoq", SPARC64_OPC_FiTOq, INSN_FPop1(I_FiTOq),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_FREG32_RS2, SPARC64_OP_TYPE_FREG128_RD},
 sprint_insn_2_ops},
{"flush", SPARC64_OPC_FLUSH, INSN_OP3(I_OP3_FLUSH),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13},
 sprint_insn_flush},
{"flushw", SPARC64_OPC_FLUSHW, INSN_OP3(I_OP3_FLUSHW),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE, 0, {}, sprint_insn_0_ops},
{"fmadds", SPARC64_OPC_FMADDs, INSN_OP3_FMAf(I_OP5_FMADDs),
 VEX_HWCAPS_SPARC64_FMAF, SPARC64_OPF_FSR_OUT | SPARC64_OPF_FSR_RD_IN,
 4, {SPARC64_OP_TYPE_FREG32_RS1, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RS3, SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_4_ops},
{"fmaddd", SPARC64_OPC_FMADDd, INSN_OP3_FMAf(I_OP5_FMADDd),
 VEX_HWCAPS_SPARC64_FMAF, SPARC64_OPF_FSR_OUT | SPARC64_OPF_FSR_RD_IN,
 4, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RS3, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_4_ops},
{"fmsubs", SPARC64_OPC_FMSUBs, INSN_OP3_FMAf(I_OP5_FMSUBs),
 VEX_HWCAPS_SPARC64_FMAF, SPARC64_OPF_FSR_OUT | SPARC64_OPF_FSR_RD_IN,
 4, {SPARC64_OP_TYPE_FREG32_RS1, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RS3, SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_4_ops},
{"fmsubd", SPARC64_OPC_FMSUBd, INSN_OP3_FMAf(I_OP5_FMSUBd),
 VEX_HWCAPS_SPARC64_FMAF, SPARC64_OPF_FSR_OUT | SPARC64_OPF_FSR_RD_IN,
 4, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RS3, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_4_ops},
{"fnmsubs", SPARC64_OPC_FNMSUBs, INSN_OP3_FMAf(I_OP5_FNMSUBs),
 VEX_HWCAPS_SPARC64_FMAF, SPARC64_OPF_FSR_OUT | SPARC64_OPF_FSR_RD_IN,
 4, {SPARC64_OP_TYPE_FREG32_RS1, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RS3, SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_4_ops},
{"fnmsubd", SPARC64_OPC_FNMSUBd, INSN_OP3_FMAf(I_OP5_FNMSUBd),
 VEX_HWCAPS_SPARC64_FMAF, SPARC64_OPF_FSR_OUT | SPARC64_OPF_FSR_RD_IN,
 4, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RS3, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_4_ops},
{"fnmadds", SPARC64_OPC_FNMADDs, INSN_OP3_FMAf(I_OP5_FNMADDs),
 VEX_HWCAPS_SPARC64_FMAF, SPARC64_OPF_FSR_OUT | SPARC64_OPF_FSR_RD_IN,
 4, {SPARC64_OP_TYPE_FREG32_RS1, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RS3, SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_4_ops},
{"fnmaddd", SPARC64_OPC_FNMADDd, INSN_OP3_FMAf(I_OP5_FNMADDd),
 VEX_HWCAPS_SPARC64_FMAF, SPARC64_OPF_FSR_OUT | SPARC64_OPF_FSR_RD_IN,
 4, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RS3, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_4_ops},
{"fmovs", SPARC64_OPC_FMOVs, INSN_FPop1(I_FMOVs),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 2, {SPARC64_OP_TYPE_FREG32_RS2, SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_2_ops},
{"fmovd", SPARC64_OPC_FMOVd, INSN_FPop1(I_FMOVd),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 2, {SPARC64_OP_TYPE_FREG64_RS2, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_2_ops},
{"fmovq", SPARC64_OPC_FMOVq, INSN_FPop1(I_FMOVq),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 2, {SPARC64_OP_TYPE_FREG128_RS2, SPARC64_OP_TYPE_FREG128_RD},
 sprint_insn_2_ops},
{"fmovsa", SPARC64_OPC_FMOVSiccA, INSN_FMOVSicc(I_COND_A),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovsn", SPARC64_OPC_FMOVSiccN, INSN_FMOVSicc(I_COND_N),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovsne", SPARC64_OPC_FMOVSiccNE, INSN_FMOVSicc(I_COND_NE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_ZERO_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovse", SPARC64_OPC_FMOVSiccE, INSN_FMOVSicc(I_COND_E),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_ZERO_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovsg", SPARC64_OPC_FMOVSiccG, INSN_FMOVSicc(I_COND_G),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_OVERFLOW_IN |
 SPARC64_OPF_CCR_ZERO_IN | SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovsle", SPARC64_OPC_FMOVSiccLE, INSN_FMOVSicc(I_COND_LE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_OVERFLOW_IN |
 SPARC64_OPF_CCR_ZERO_IN | SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovsge", SPARC64_OPC_FMOVSiccGE, INSN_FMOVSicc(I_COND_GE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovsl", SPARC64_OPC_FMOVSiccL, INSN_FMOVSicc(I_COND_L),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_OVERFLOW_IN |
 SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovsgu", SPARC64_OPC_FMOVSiccGU, INSN_FMOVSicc(I_COND_GU),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_CARRY_IN |
 SPARC64_OPF_CCR_ZERO_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovsleu", SPARC64_OPC_FMOVSiccLEU, INSN_FMOVSicc(I_COND_LEU),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_CARRY_IN |
 SPARC64_OPF_CCR_ZERO_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovscc", SPARC64_OPC_FMOVSiccCC, INSN_FMOVSicc(I_COND_CC),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_CARRY_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovscs", SPARC64_OPC_FMOVSiccCS, INSN_FMOVSicc(I_COND_CS),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_CARRY_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovspos", SPARC64_OPC_FMOVSiccPOS, INSN_FMOVSicc(I_COND_POS),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovsneg", SPARC64_OPC_FMOVSiccNEG, INSN_FMOVSicc(I_COND_NEG),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovsvc", SPARC64_OPC_FMOVSiccVC, INSN_FMOVSicc(I_COND_VC),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_OVERFLOW_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovsvs", SPARC64_OPC_FMOVSiccVS, INSN_FMOVSicc(I_COND_VS),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_OVERFLOW_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovda", SPARC64_OPC_FMOVDiccA, INSN_FMOVDicc(I_COND_A),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdn", SPARC64_OPC_FMOVDiccN, INSN_FMOVDicc(I_COND_N),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdne", SPARC64_OPC_FMOVDiccNE, INSN_FMOVDicc(I_COND_NE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_ZERO_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovde", SPARC64_OPC_FMOVDiccE, INSN_FMOVDicc(I_COND_E),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_ZERO_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdg", SPARC64_OPC_FMOVDiccG, INSN_FMOVDicc(I_COND_G),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_OVERFLOW_IN |
 SPARC64_OPF_CCR_ZERO_IN | SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdle", SPARC64_OPC_FMOVDiccLE, INSN_FMOVDicc(I_COND_LE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_OVERFLOW_IN |
 SPARC64_OPF_CCR_ZERO_IN | SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdge", SPARC64_OPC_FMOVDiccGE, INSN_FMOVDicc(I_COND_GE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdl", SPARC64_OPC_FMOVDiccL, INSN_FMOVDicc(I_COND_L),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdgu", SPARC64_OPC_FMOVDiccGU, INSN_FMOVDicc(I_COND_GU),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_CARRY_IN |
 SPARC64_OPF_CCR_ZERO_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdleu", SPARC64_OPC_FMOVDiccLEU, INSN_FMOVDicc(I_COND_LEU),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_CARRY_IN |
 SPARC64_OPF_CCR_ZERO_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdcc", SPARC64_OPC_FMOVDiccCC, INSN_FMOVDicc(I_COND_CC),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_CARRY_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdcs", SPARC64_OPC_FMOVDiccCS, INSN_FMOVDicc(I_COND_CS),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_CARRY_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdpos", SPARC64_OPC_FMOVDiccPOS, INSN_FMOVDicc(I_COND_POS),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdneg", SPARC64_OPC_FMOVDiccNEG, INSN_FMOVDicc(I_COND_NEG),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdvc", SPARC64_OPC_FMOVDiccVC, INSN_FMOVDicc(I_COND_VC),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_OVERFLOW_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdvs", SPARC64_OPC_FMOVDiccVS, INSN_FMOVDicc(I_COND_VS),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_OVERFLOW_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovqa", SPARC64_OPC_FMOVQiccA, INSN_FMOVQicc(I_COND_A),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqn", SPARC64_OPC_FMOVQiccN, INSN_FMOVQicc(I_COND_N),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqne", SPARC64_OPC_FMOVQiccNE, INSN_FMOVQicc(I_COND_NE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_ZERO_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqe", SPARC64_OPC_FMOVQiccE, INSN_FMOVQicc(I_COND_E),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_ZERO_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqg", SPARC64_OPC_FMOVQiccG, INSN_FMOVQicc(I_COND_G),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_OVERFLOW_IN |
 SPARC64_OPF_CCR_ZERO_IN | SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqle", SPARC64_OPC_FMOVQiccLE, INSN_FMOVQicc(I_COND_LE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_OVERFLOW_IN |
 SPARC64_OPF_CCR_ZERO_IN | SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqge", SPARC64_OPC_FMOVQiccGE, INSN_FMOVQicc(I_COND_GE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovql", SPARC64_OPC_FMOVQiccL, INSN_FMOVQicc(I_COND_L),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqgu", SPARC64_OPC_FMOVQiccGU, INSN_FMOVQicc(I_COND_GU),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_CARRY_IN |
 SPARC64_OPF_CCR_ZERO_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqleu", SPARC64_OPC_FMOVQiccLEU, INSN_FMOVQicc(I_COND_LEU),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_CARRY_IN |
 SPARC64_OPF_CCR_ZERO_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqcc", SPARC64_OPC_FMOVQiccCC, INSN_FMOVQicc(I_COND_CC),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_CARRY_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqcs", SPARC64_OPC_FMOVQiccCS, INSN_FMOVQicc(I_COND_CS),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_CARRY_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqpos", SPARC64_OPC_FMOVQiccPOS, INSN_FMOVQicc(I_COND_POS),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqneg", SPARC64_OPC_FMOVQiccNEG, INSN_FMOVQicc(I_COND_NEG),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqvc", SPARC64_OPC_FMOVQiccVC, INSN_FMOVQicc(I_COND_VC),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_OVERFLOW_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqvs", SPARC64_OPC_FMOVQiccVS, INSN_FMOVQicc(I_COND_VS),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_CCR_OVERFLOW_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovsa", SPARC64_OPC_FMOVSfccA, INSN_FMOVSfcc(F_COND_A),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovsn", SPARC64_OPC_FMOVSfccN, INSN_FMOVSfcc(F_COND_N),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovsu", SPARC64_OPC_FMOVSfccU, INSN_FMOVSfcc(F_COND_U),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovsg", SPARC64_OPC_FMOVSfccG, INSN_FMOVSfcc(F_COND_G),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovsug", SPARC64_OPC_FMOVSfccUG, INSN_FMOVSfcc(F_COND_UG),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovsl", SPARC64_OPC_FMOVSfccL, INSN_FMOVSfcc(F_COND_L),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovsul", SPARC64_OPC_FMOVSfccUL, INSN_FMOVSfcc(F_COND_UL),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovslg", SPARC64_OPC_FMOVSfccLG, INSN_FMOVSfcc(F_COND_LG),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovsne", SPARC64_OPC_FMOVSfccNE, INSN_FMOVSfcc(F_COND_NE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovse", SPARC64_OPC_FMOVSfccE, INSN_FMOVSfcc(F_COND_E),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovsue", SPARC64_OPC_FMOVSfccUE, INSN_FMOVSfcc(F_COND_UE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovsge", SPARC64_OPC_FMOVSfccGE, INSN_FMOVSfcc(F_COND_GE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovsuge", SPARC64_OPC_FMOVSfccUGE, INSN_FMOVSfcc(F_COND_UGE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovsle", SPARC64_OPC_FMOVSfccLE, INSN_FMOVSfcc(F_COND_LE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovsule", SPARC64_OPC_FMOVSfccULE, INSN_FMOVSfcc(F_COND_ULE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovso", SPARC64_OPC_FMOVSfccO, INSN_FMOVSfcc(F_COND_O),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmovda", SPARC64_OPC_FMOVDfccA, INSN_FMOVDfcc(F_COND_A),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdn", SPARC64_OPC_FMOVDfccN, INSN_FMOVDfcc(F_COND_N),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdu", SPARC64_OPC_FMOVDfccU, INSN_FMOVDfcc(F_COND_U),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdg", SPARC64_OPC_FMOVDfccG, INSN_FMOVDfcc(F_COND_G),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdug", SPARC64_OPC_FMOVDfccUG, INSN_FMOVDfcc(F_COND_UG),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdl", SPARC64_OPC_FMOVDfccL, INSN_FMOVDfcc(F_COND_L),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdul", SPARC64_OPC_FMOVDfccUL, INSN_FMOVDfcc(F_COND_UL),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdlg", SPARC64_OPC_FMOVDfccLG, INSN_FMOVDfcc(F_COND_LG),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdne", SPARC64_OPC_FMOVDfccNE, INSN_FMOVDfcc(F_COND_NE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovde", SPARC64_OPC_FMOVDfccE, INSN_FMOVDfcc(F_COND_E),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdue", SPARC64_OPC_FMOVDfccUE, INSN_FMOVDfcc(F_COND_UE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdge", SPARC64_OPC_FMOVDfccGE, INSN_FMOVDfcc(F_COND_GE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovduge", SPARC64_OPC_FMOVDfccUGE, INSN_FMOVDfcc(F_COND_UGE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdle", SPARC64_OPC_FMOVDfccLE, INSN_FMOVDfcc(F_COND_LE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdule", SPARC64_OPC_FMOVDfccULE, INSN_FMOVDfcc(F_COND_ULE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovdo", SPARC64_OPC_FMOVDfccO, INSN_FMOVDfcc(F_COND_O),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmovqa", SPARC64_OPC_FMOVQfccA, INSN_FMOVQfcc(F_COND_A),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqn", SPARC64_OPC_FMOVQfccN, INSN_FMOVQfcc(F_COND_N),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqu", SPARC64_OPC_FMOVQfccU, INSN_FMOVQfcc(F_COND_U),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqg", SPARC64_OPC_FMOVQfccG, INSN_FMOVQfcc(F_COND_G),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqug", SPARC64_OPC_FMOVQfccUG, INSN_FMOVQfcc(F_COND_UG),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovql", SPARC64_OPC_FMOVQfccL, INSN_FMOVQfcc(F_COND_L),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqul", SPARC64_OPC_FMOVQfccUL, INSN_FMOVQfcc(F_COND_UL),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqlg", SPARC64_OPC_FMOVQfccLG, INSN_FMOVQfcc(F_COND_LG),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqne", SPARC64_OPC_FMOVQfccNE, INSN_FMOVQfcc(F_COND_NE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqe", SPARC64_OPC_FMOVQfccE, INSN_FMOVQfcc(F_COND_E),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovque", SPARC64_OPC_FMOVQfccUE, INSN_FMOVQfcc(F_COND_UE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqge", SPARC64_OPC_FMOVQfccGE, INSN_FMOVQfcc(F_COND_GE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovquge", SPARC64_OPC_FMOVQfccUGE, INSN_FMOVQfcc(F_COND_UGE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqle", SPARC64_OPC_FMOVQfccLE, INSN_FMOVQfcc(F_COND_LE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqule", SPARC64_OPC_FMOVQfccULE, INSN_FMOVQfcc(F_COND_ULE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmovqo", SPARC64_OPC_FMOVQfccO, INSN_FMOVQfcc(F_COND_O),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FCCn_FMOVcc, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fmuls", SPARC64_OPC_FMULs, INSN_FPop1(I_FMULs),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_RD_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FREG32_RS1, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fmuld", SPARC64_OPC_FMULd, INSN_FPop1(I_FMULd),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_RD_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fmulq", SPARC64_OPC_FMULq, INSN_FPop1(I_FMULq),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_RD_IN | SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FREG128_RS1, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fsmuld", SPARC64_OPC_FsMULd, INSN_FPop1(I_FsMULd),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FREG32_RS1, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fdmulq", SPARC64_OPC_FdMULq, INSN_FPop1(I_FdMULq),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fnegs", SPARC64_OPC_FNEGs, INSN_FPop1(I_FNEGs),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 2, {SPARC64_OP_TYPE_FREG32_RS2, SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_2_ops},
{"fnegd", SPARC64_OPC_FNEGd, INSN_FPop1(I_FNEGd),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 2, {SPARC64_OP_TYPE_FREG64_RS2, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_2_ops},
{"fnegq", SPARC64_OPC_FNEGq, INSN_FPop1(I_FNEGq),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 2, {SPARC64_OP_TYPE_FREG128_RS2, SPARC64_OP_TYPE_FREG128_RD},
 sprint_insn_2_ops},
{"fzeros", SPARC64_OPC_FZEROs, INSN_VIS(I_FZEROs),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 1, {SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_1_op},
{"fzerod", SPARC64_OPC_FZEROd, INSN_VIS(I_FZEROd),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 1, {SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_1_op},
{"fones", SPARC64_OPC_FONEs, INSN_VIS(I_FONEs),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 1, {SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_1_op},
{"foned", SPARC64_OPC_FONEd, INSN_VIS(I_FONEd),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 1, {SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_1_op},
{"fsrc1d", SPARC64_OPC_FSRC1d, INSN_VIS(I_FSRC1d),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_2_ops},
{"fsrc1s", SPARC64_OPC_FSRC1s, INSN_VIS(I_FSRC1s),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_FREG32_RS1, SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_2_ops},
{"fsrc2d", SPARC64_OPC_FSRC2d, INSN_VIS(I_FSRC2d),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_FREG64_RS2, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_2_ops},
{"fsrc2s", SPARC64_OPC_FSRC2s, INSN_VIS(I_FSRC2s),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_FREG32_RS2, SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_2_ops},
{"fnot1d", SPARC64_OPC_FNOT1d, INSN_VIS(I_FNOT1d),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_2_ops},
{"fnot1s", SPARC64_OPC_FNOT1s, INSN_VIS(I_FNOT1s),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_FREG32_RS1, SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_2_ops},
{"fnot2d", SPARC64_OPC_FNOT2d, INSN_VIS(I_FNOT2d),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_FREG64_RS2, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_2_ops},
{"fnot2s", SPARC64_OPC_FNOT2s, INSN_VIS(I_FNOT2s),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_FREG32_RS2, SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_2_ops},
{"ford", SPARC64_OPC_FORd, INSN_VIS(I_FORd),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fors", SPARC64_OPC_FORs, INSN_VIS(I_FORs),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG32_RS1, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fnord", SPARC64_OPC_FNORd, INSN_VIS(I_FNORd),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fnors", SPARC64_OPC_FNORs, INSN_VIS(I_FNORs),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG32_RS1, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fandd", SPARC64_OPC_FANDd, INSN_VIS(I_FANDd),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fands", SPARC64_OPC_FANDs, INSN_VIS(I_FANDs),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG32_RS1, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fnandd", SPARC64_OPC_FNANDd, INSN_VIS(I_FNANDd),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fnands", SPARC64_OPC_FNANDs, INSN_VIS(I_FNANDs),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG32_RS1, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fxord", SPARC64_OPC_FXORd, INSN_VIS(I_FXORd),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fxors", SPARC64_OPC_FXORs, INSN_VIS(I_FXORs),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG32_RS1, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fxnord", SPARC64_OPC_FXNORd, INSN_VIS(I_FXNORd),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fxnors", SPARC64_OPC_FXNORs, INSN_VIS(I_FXNORs),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG32_RS1, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fornot1d", SPARC64_OPC_FORNOT1d, INSN_VIS(I_FORNOT1d),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fornot1s", SPARC64_OPC_FORNOT1s, INSN_VIS(I_FORNOT1s),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG32_RS1, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fornot2d", SPARC64_OPC_FORNOT2d, INSN_VIS(I_FORNOT2d),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fornot2s", SPARC64_OPC_FORNOT2s, INSN_VIS(I_FORNOT2s),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG32_RS1, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fandnot1d", SPARC64_OPC_FANDNOT1d, INSN_VIS(I_FANDNOT1d),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fandnot1s", SPARC64_OPC_FANDNOT1s, INSN_VIS(I_FANDNOT1s),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG32_RS1, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fandnot2d", SPARC64_OPC_FANDNOT2d, INSN_VIS(I_FANDNOT2d),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fandnot2s", SPARC64_OPC_FANDNOT2s, INSN_VIS(I_FANDNOT2s),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG32_RS1, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fsll16", SPARC64_OPC_FSLL16, INSN_VIS(I_FSLL16),
 VEX_HWCAPS_SPARC64_SPARC4, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fsrl16", SPARC64_OPC_FSRL16, INSN_VIS(I_FSRL16),
 VEX_HWCAPS_SPARC64_SPARC4, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fsll32", SPARC64_OPC_FSLL32, INSN_VIS(I_FSLL32),
 VEX_HWCAPS_SPARC64_SPARC4, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fsrl32", SPARC64_OPC_FSRL32, INSN_VIS(I_FSRL32),
 VEX_HWCAPS_SPARC64_SPARC4, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fslas16", SPARC64_OPC_FSLAS16, INSN_VIS(I_FSLAS16),
 VEX_HWCAPS_SPARC64_SPARC4, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fsra16", SPARC64_OPC_FSRA16, INSN_VIS(I_FSRA16),
 VEX_HWCAPS_SPARC64_SPARC4, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fslas32", SPARC64_OPC_FSLAS32, INSN_VIS(I_FSLAS32),
 VEX_HWCAPS_SPARC64_SPARC4, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fsra32", SPARC64_OPC_FSRA32, INSN_VIS(I_FSRA32),
 VEX_HWCAPS_SPARC64_SPARC4, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fsqrts", SPARC64_OPC_FSQRTs, INSN_FPop1(I_FSQRTs),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_RD_IN | SPARC64_OPF_FSR_OUT,
 2, {SPARC64_OP_TYPE_FREG32_RS2, SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_2_ops},
{"fsqrtd", SPARC64_OPC_FSQRTd, INSN_FPop1(I_FSQRTd),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_RD_IN | SPARC64_OPF_FSR_OUT,
 2, {SPARC64_OP_TYPE_FREG64_RS2, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_2_ops},
{"fsqrtq", SPARC64_OPC_FSQRTq, INSN_FPop1(I_FSQRTq),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_RD_IN | SPARC64_OPF_FSR_OUT,
 2, {SPARC64_OP_TYPE_FREG128_RS2, SPARC64_OP_TYPE_FREG128_RD},
 sprint_insn_2_ops},
{"fstox", SPARC64_OPC_FsTOx, INSN_FPop1(I_FsTOx),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 2, {SPARC64_OP_TYPE_FREG32_RS2, SPARC64_OP_TYPE_FREG64_RD},
 sprint_insn_2_ops},
{"fdtox", SPARC64_OPC_FdTOx, INSN_FPop1(I_FdTOx),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 2, {SPARC64_OP_TYPE_FREG64_RS2, SPARC64_OP_TYPE_FREG64_RD},
 sprint_insn_2_ops},
{"fqtox", SPARC64_OPC_FqTOx, INSN_FPop1(I_FqTOx),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 2, {SPARC64_OP_TYPE_FREG128_RS2, SPARC64_OP_TYPE_FREG64_RD},
 sprint_insn_2_ops},
{"fstoi", SPARC64_OPC_FsTOi, INSN_FPop1(I_FsTOi),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 2, {SPARC64_OP_TYPE_FREG32_RS2, SPARC64_OP_TYPE_FREG32_RD},
 sprint_insn_2_ops},
{"fdtoi", SPARC64_OPC_FdTOi, INSN_FPop1(I_FdTOi),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 2, {SPARC64_OP_TYPE_FREG64_RS2, SPARC64_OP_TYPE_FREG32_RD},
 sprint_insn_2_ops},
{"fqtoi", SPARC64_OPC_FqTOi, INSN_FPop1(I_FqTOi),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 2, {SPARC64_OP_TYPE_FREG128_RS2, SPARC64_OP_TYPE_FREG32_RD},
 sprint_insn_2_ops},
{"fstod", SPARC64_OPC_FsTOd, INSN_FPop1(I_FsTOd),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 2, {SPARC64_OP_TYPE_FREG32_RS2, SPARC64_OP_TYPE_FREG64_RD},
 sprint_insn_2_ops},
{"fstoq", SPARC64_OPC_FsTOq, INSN_FPop1(I_FsTOq),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 2, {SPARC64_OP_TYPE_FREG32_RS2, SPARC64_OP_TYPE_FREG128_RD},
 sprint_insn_2_ops},
{"fdtos", SPARC64_OPC_FdTOs, INSN_FPop1(I_FdTOs),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_FSR_RD_IN,
 2, {SPARC64_OP_TYPE_FREG64_RS2, SPARC64_OP_TYPE_FREG32_RD},
 sprint_insn_2_ops},
{"fdtoq", SPARC64_OPC_FdTOq, INSN_FPop1(I_FdTOq),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT,
 2, {SPARC64_OP_TYPE_FREG64_RS2, SPARC64_OP_TYPE_FREG128_RD},
 sprint_insn_2_ops},
{"fqtos", SPARC64_OPC_FqTOs, INSN_FPop1(I_FqTOs),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_FSR_RD_IN,
 2, {SPARC64_OP_TYPE_FREG128_RS2, SPARC64_OP_TYPE_FREG32_RD},
 sprint_insn_2_ops},
{"fqtod", SPARC64_OPC_FqTOd, INSN_FPop1(I_FqTOd),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_FSR_RD_IN,
 2, {SPARC64_OP_TYPE_FREG128_RS2, SPARC64_OP_TYPE_FREG64_RD},
 sprint_insn_2_ops},
{"fsubs", SPARC64_OPC_FSUBs, INSN_FPop1(I_FSUBs),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_FSR_RD_IN,
 3, {SPARC64_OP_TYPE_FREG32_RS1, SPARC64_OP_TYPE_FREG32_RS2,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_3_ops},
{"fsubd", SPARC64_OPC_FSUBd, INSN_FPop1(I_FSUBd),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_FSR_RD_IN,
 3, {SPARC64_OP_TYPE_FREG64_RS1, SPARC64_OP_TYPE_FREG64_RS2,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_3_ops},
{"fsubq", SPARC64_OPC_FSUBq, INSN_FPop1(I_FSUBq),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_FSR_RD_IN,
 3, {SPARC64_OP_TYPE_FREG128_RS1, SPARC64_OP_TYPE_FREG128_RS2,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_3_ops},
{"fxtos", SPARC64_OPC_FxTOs, INSN_FPop1(I_FxTOs),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_FSR_RD_IN,
 2, {SPARC64_OP_TYPE_FREG64_RS2, SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_2_ops},
{"fxtod", SPARC64_OPC_FxTOd, INSN_FPop1(I_FxTOd),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_OUT | SPARC64_OPF_FSR_RD_IN,
 2, {SPARC64_OP_TYPE_FREG64_RS2, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_2_ops},
{"fxtoq", SPARC64_OPC_FxTOq, INSN_FPop1(I_FxTOq),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_FREG64_RS2, SPARC64_OP_TYPE_FREG128_RD},
 sprint_insn_2_ops},
{"jmpl", SPARC64_OPC_JMPL, INSN_OP3(I_OP3_JMPL),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_jmpl},
{"ldsb", SPARC64_OPC_LDSB, INSN_LDST(I_OP3_LDSB),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_load},
{"ldsh", SPARC64_OPC_LDSH, INSN_LDST(I_OP3_LDSH),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_load},
{"ldsw", SPARC64_OPC_LDSW, INSN_LDST(I_OP3_LDSW),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_load},
{"ldub", SPARC64_OPC_LDUB, INSN_LDST(I_OP3_LDUB),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_load},
{"lduh", SPARC64_OPC_LDUH, INSN_LDST(I_OP3_LDUH),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_load},
{"lduw", SPARC64_OPC_LDUW, INSN_LDST(I_OP3_LDUW),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_load},
{"ldx", SPARC64_OPC_LDX, INSN_LDST(I_OP3_LDX),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_load},
{"ldsba", SPARC64_OPC_LDSBA, INSN_LDST(I_OP3_LDSBA),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_ASI_IMPL_OR_IMM, SPARC64_OP_TYPE_IREG_RD},
 sprint_insn_load_asi},
{"ldsha", SPARC64_OPC_LDSHA, INSN_LDST(I_OP3_LDSHA),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_ASI_IMPL_OR_IMM, SPARC64_OP_TYPE_IREG_RD},
 sprint_insn_load_asi},
{"ldswa", SPARC64_OPC_LDSWA, INSN_LDST(I_OP3_LDSWA),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_ASI_IMPL_OR_IMM, SPARC64_OP_TYPE_IREG_RD},
 sprint_insn_load_asi},
{"lduba", SPARC64_OPC_LDUBA, INSN_LDST(I_OP3_LDUBA),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_ASI_IMPL_OR_IMM, SPARC64_OP_TYPE_IREG_RD},
 sprint_insn_load_asi},
{"lduha", SPARC64_OPC_LDUHA, INSN_LDST(I_OP3_LDUHA),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_ASI_IMPL_OR_IMM, SPARC64_OP_TYPE_IREG_RD},
 sprint_insn_load_asi},
{"lduwa", SPARC64_OPC_LDUWA, INSN_LDST(I_OP3_LDUWA),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_ASI_IMPL_OR_IMM, SPARC64_OP_TYPE_IREG_RD},
 sprint_insn_load_asi},
{"ldxa", SPARC64_OPC_LDXA, INSN_LDST(I_OP3_LDXA),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_ASI_IMPL_OR_IMM, SPARC64_OP_TYPE_IREG_RD},
 sprint_insn_load_asi},
{"ldda", SPARC64_OPC_LDBLOCKF, INSN_LDST(I_OP3_LDDFA),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_ASI_IMPL_OR_IMM, SPARC64_OP_TYPE_FREG64_RD},
 sprint_insn_load_asi},
{"ld", SPARC64_OPC_LDF, INSN_LDST(I_OP3_LDF),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_load},
{"ldd", SPARC64_OPC_LDDF, INSN_LDST(I_OP3_LDDF),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_load},
{"ldq", SPARC64_OPC_LDQF, INSN_LDST(I_OP3_LDQF),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_FREG128_RD}, sprint_insn_load},
{"lda", SPARC64_OPC_LDFA, INSN_LDST(I_OP3_LDFA),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_ASI_IMPL_OR_IMM, SPARC64_OP_TYPE_FREG32_RD},
 sprint_insn_load_asi},
{"ldda", SPARC64_OPC_LDDFA, INSN_LDST(I_OP3_LDDFA),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_ASI_IMPL_OR_IMM, SPARC64_OP_TYPE_FREG64_RD},
 sprint_insn_load_asi},
{"ldqa", SPARC64_OPC_LDQFA, INSN_LDST(I_OP3_LDQFA),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_ASI_IMPL_OR_IMM, SPARC64_OP_TYPE_FREG128_RD},
 sprint_insn_load_asi},
{"ld", SPARC64_OPC_LDFSR, INSN_LDST(I_OP3_LDFSR),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RDIN}, sprint_insn_ldfsr},
{"ldda", SPARC64_OPC_LDSHORTF, INSN_LDST(I_OP3_LDDFA),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_ASI_IMPL_OR_IMM, SPARC64_OP_TYPE_FREG64_RD},
 sprint_insn_load_asi},
{"ldstub", SPARC64_OPC_LDSTUB, INSN_LDST(I_OP3_LDSTUB),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RDINOUT}, sprint_insn_load},
{"ldx", SPARC64_OPC_LDXFSR, INSN_LDST(I_OP3_LDFSR),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RDIN}, sprint_insn_ldfsr},
{"lzcnt", SPARC64_OPC_LZCNT, INSN_VIS(I_LZCNT),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_IREG_RS2, SPARC64_OP_TYPE_IREG_RD}, sprint_insn_2_ops},
{"md5", SPARC64_OPC_MD5, INSN_VIS(I_MD5),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_NONE,
 0, {}, sprint_insn_0_ops},
{"membar", SPARC64_OPC_MEMBAR,
 INSN_OP3(I_OP3_RDasr_MEMBAR) | BITS5(0, 1, 1, 1, 1) << 14 | 1 << 13,
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_MMASK, SPARC64_OP_TYPE_CMASK}, sprint_insn_membar},
{"mova", SPARC64_OPC_MOVA, INSN_MOVicc(I_COND_A), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movn", SPARC64_OPC_MOVN, INSN_MOVicc(I_COND_N), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movne", SPARC64_OPC_MOVNE, INSN_MOVicc(I_COND_NE), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_ZERO_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"move", SPARC64_OPC_MOVE, INSN_MOVicc(I_COND_E), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_ZERO_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movg", SPARC64_OPC_MOVG, INSN_MOVicc(I_COND_G), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_OVERFLOW_IN | SPARC64_OPF_CCR_ZERO_IN |
                               SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movle", SPARC64_OPC_MOVLE, INSN_MOVicc(I_COND_LE), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_OVERFLOW_IN | SPARC64_OPF_CCR_ZERO_IN |
                               SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movge", SPARC64_OPC_MOVGE, INSN_MOVicc(I_COND_GE), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_OVERFLOW_IN | SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movl", SPARC64_OPC_MOVL, INSN_MOVicc(I_COND_L), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_OVERFLOW_IN | SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movgu", SPARC64_OPC_MOVGU, INSN_MOVicc(I_COND_GU), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_CARRY_IN | SPARC64_OPF_CCR_ZERO_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movleu", SPARC64_OPC_MOVLEU, INSN_MOVicc(I_COND_LEU), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_CARRY_IN | SPARC64_OPF_CCR_ZERO_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movcc", SPARC64_OPC_MOVCC, INSN_MOVicc(I_COND_CC), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_CARRY_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movcs", SPARC64_OPC_MOVCS, INSN_MOVicc(I_COND_CS), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_CARRY_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movpos", SPARC64_OPC_MOVPOS, INSN_MOVicc(I_COND_POS), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movneg", SPARC64_OPC_MOVNEG, INSN_MOVicc(I_COND_NEG), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movvc", SPARC64_OPC_MOVVC, INSN_MOVicc(I_COND_VC), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_OVERFLOW_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movvs", SPARC64_OPC_MOVVS, INSN_MOVicc(I_COND_VS), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_OVERFLOW_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"mova", SPARC64_OPC_MOVFA, INSN_MOVfcc(F_COND_A), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_FSR_FCC_IN,
 3, {SPARC64_OP_TYPE_FCCn_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movn", SPARC64_OPC_MOVFN, INSN_MOVfcc(F_COND_N), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_FSR_FCC_IN,
 3, {SPARC64_OP_TYPE_FCCn_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movu", SPARC64_OPC_MOVFU, INSN_MOVfcc(F_COND_U), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_FSR_FCC_IN,
 3, {SPARC64_OP_TYPE_FCCn_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movg", SPARC64_OPC_MOVFG, INSN_MOVfcc(F_COND_G), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_FSR_FCC_IN,
 3, {SPARC64_OP_TYPE_FCCn_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movug", SPARC64_OPC_MOVFUG, INSN_MOVfcc(F_COND_UG), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_FSR_FCC_IN,
 3, {SPARC64_OP_TYPE_FCCn_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movl", SPARC64_OPC_MOVFL, INSN_MOVfcc(F_COND_L), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_FSR_FCC_IN,
 3, {SPARC64_OP_TYPE_FCCn_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movul", SPARC64_OPC_MOVFUL, INSN_MOVfcc(F_COND_UL), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_FSR_FCC_IN,
 3, {SPARC64_OP_TYPE_FCCn_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movlg", SPARC64_OPC_MOVFLG, INSN_MOVfcc(F_COND_LG), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_FSR_FCC_IN,
 3, {SPARC64_OP_TYPE_FCCn_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movne", SPARC64_OPC_MOVFNE, INSN_MOVfcc(F_COND_NE), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_FSR_FCC_IN,
 3, {SPARC64_OP_TYPE_FCCn_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"move", SPARC64_OPC_MOVFE, INSN_MOVfcc(F_COND_E), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_FSR_FCC_IN,
 3, {SPARC64_OP_TYPE_FCCn_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movue", SPARC64_OPC_MOVFUE, INSN_MOVfcc(F_COND_UE), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_FSR_FCC_IN,
 3, {SPARC64_OP_TYPE_FCCn_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movge", SPARC64_OPC_MOVFGE, INSN_MOVfcc(F_COND_GE), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_FSR_FCC_IN,
 3, {SPARC64_OP_TYPE_FCCn_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movuge", SPARC64_OPC_MOVFUGE, INSN_MOVfcc(F_COND_UGE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN,
 3, {SPARC64_OP_TYPE_FCCn_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movle", SPARC64_OPC_MOVFLE, INSN_MOVfcc(F_COND_LE), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_FSR_FCC_IN,
 3, {SPARC64_OP_TYPE_FCCn_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movule", SPARC64_OPC_MOVFULE, INSN_MOVfcc(F_COND_ULE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_FSR_FCC_IN,
 3, {SPARC64_OP_TYPE_FCCn_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movo", SPARC64_OPC_MOVFO, INSN_MOVfcc(F_COND_O), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_FSR_FCC_IN,
 3, {SPARC64_OP_TYPE_FCCn_MOVcc, SPARC64_OP_TYPE_RS2_OR_SIMM11,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movrz", SPARC64_OPC_MOVRZ, INSN_MOVr(I_RCOND_Z),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM10,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movrlez", SPARC64_OPC_MOVRLEZ, INSN_MOVr(I_RCOND_LEZ),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM10,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movrlz", SPARC64_OPC_MOVRLZ, INSN_MOVr(I_RCOND_LZ),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM10,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movrnz", SPARC64_OPC_MOVRNZ, INSN_MOVr(I_RCOND_NZ),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM10,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movrgz", SPARC64_OPC_MOVRGZ, INSN_MOVr(I_RCOND_GZ),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM10,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movrgez", SPARC64_OPC_MOVRGEZ, INSN_MOVr(I_RCOND_GEZ),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM10,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"movstosw", SPARC64_OPC_MOVsTOsw, INSN_VIS(I_MOVsTOsw),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_FREG32_RS2, SPARC64_OP_TYPE_IREG_RD}, sprint_insn_2_ops},
{"movstouw", SPARC64_OPC_MOVsTOuw, INSN_VIS(I_MOVsTOuw),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_FREG32_RS2, SPARC64_OP_TYPE_IREG_RD}, sprint_insn_2_ops},
{"movdtox", SPARC64_OPC_MOVdTOx, INSN_VIS(I_MOVdTOx),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_FREG64_RS2, SPARC64_OP_TYPE_IREG_RD}, sprint_insn_2_ops},
{"movwtos", SPARC64_OPC_MOVwTOs, INSN_VIS(I_MOVwTOs),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_IREG_RS2, SPARC64_OP_TYPE_FREG32_RD}, sprint_insn_2_ops},
{"movxtod", SPARC64_OPC_MOVxTOd, INSN_VIS(I_MOVxTOd),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_IREG_RS2, SPARC64_OP_TYPE_FREG64_RD}, sprint_insn_2_ops},
{"mulx", SPARC64_OPC_MULX, INSN_OP3(I_OP3_MULX),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"sdivx", SPARC64_OPC_SDIVX, INSN_OP3(I_OP3_SDIVX),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"udivx", SPARC64_OPC_UDIVX, INSN_OP3(I_OP3_UDIVX),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"nop", SPARC64_OPC_NOP, INSN_BRANCH(I_OP3_SETHI_NOP),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 0, {}, sprint_insn_0_ops},
{"or", SPARC64_OPC_OR, INSN_OP3(I_OP3_OR),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"orcc", SPARC64_OPC_ORcc, INSN_OP3(I_OP3_ORcc),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_CCR_OUT,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"orn", SPARC64_OPC_ORN, INSN_OP3(I_OP3_ORN),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"orncc", SPARC64_OPC_ORNcc, INSN_OP3(I_OP3_ORNcc),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_CCR_OUT,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"prefetch", SPARC64_OPC_PREFETCH, INSN_LDST(I_OP3_PREFETCH),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_PREFETCH_FCN}, sprint_insn_load},
{"prefetcha", SPARC64_OPC_PREFETCHA, INSN_LDST(I_OP3_PREFETCHA),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_ASI_IMPL_OR_IMM, SPARC64_OP_TYPE_PREFETCH_FCN},
 sprint_insn_load_asi},
{"rdy", SPARC64_OPC_RDY, INSN_OP3(I_OP3_RDasr_MEMBAR),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_IREG_RD}, sprint_insn_rdasr},
{"rdccr", SPARC64_OPC_RDCCR, INSN_OP3(I_OP3_RDasr_MEMBAR),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_IREG_RD}, sprint_insn_rdasr},
{"rdasi", SPARC64_OPC_RDASI, INSN_OP3(I_OP3_RDasr_MEMBAR),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_IREG_RD}, sprint_insn_rdasr},
{"rdtick", SPARC64_OPC_RDTICK, INSN_OP3(I_OP3_RDasr_MEMBAR),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_IREG_RD}, sprint_insn_rdasr},
{"rdpc", SPARC64_OPC_RDPC, INSN_OP3(I_OP3_RDasr_MEMBAR),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_IREG_RD}, sprint_insn_rdasr},
{"rdfprs", SPARC64_OPC_RDFPRS, INSN_OP3(I_OP3_RDasr_MEMBAR),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_IREG_RD}, sprint_insn_rdasr},
{"rdentropy", SPARC64_OPC_RDENTROPY, INSN_OP3(I_OP3_RDasr_MEMBAR),
 VEX_HWCAPS_SPARC64_SPARC6, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_IREG_RD}, sprint_insn_rdasr},
{"rdmcdper", SPARC64_OPC_RDMCDPER, INSN_OP3(I_OP3_RDasr_MEMBAR),
 VEX_HWCAPS_SPARC64_SPARC5, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_IREG_RD}, sprint_insn_rdasr},
{"rdgsr", SPARC64_OPC_RDGSR, INSN_OP3(I_OP3_RDasr_MEMBAR),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_IREG_RD}, sprint_insn_rdasr},
{"rdstick", SPARC64_OPC_RDSTICK, INSN_OP3(I_OP3_RDasr_MEMBAR),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_IREG_RD}, sprint_insn_rdasr},
{"rdcfr", SPARC64_OPC_RDCFR, INSN_OP3(I_OP3_RDasr_MEMBAR),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_IREG_RD}, sprint_insn_rdasr},
{"restore", SPARC64_OPC_RESTORE, INSN_OP3(I_OP3_RESTORE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_CWP,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"return", SPARC64_OPC_RETURN, INSN_OP3(I_OP3_RETURN),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_dCTI | SPARC64_OPF_CWP,
 2, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13},
 sprint_insn_return},
{"save", SPARC64_OPC_SAVE, INSN_OP3(I_OP3_SAVE),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_CWP,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"sdiv", SPARC64_OPC_SDIV, INSN_OP3(I_OP3_SDIV),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_Y_IN,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"sdivcc", SPARC64_OPC_SDIVcc, INSN_OP3(I_OP3_SDIVcc),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_CCR_OUT | SPARC64_OPF_Y_IN,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"sethi", SPARC64_OPC_SETHI, INSN_BRANCH(I_OP3_SETHI_NOP),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 2, {SPARC64_OP_TYPE_IMM22, SPARC64_OP_TYPE_IREG_RD}, sprint_insn_2_ops},
{"sha1", SPARC64_OPC_SHA1, INSN_VIS(I_SHA1),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_NONE,
 0, {}, sprint_insn_0_ops},
{"sha256", SPARC64_OPC_SHA256, INSN_VIS(I_SHA256),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_NONE,
 0, {}, sprint_insn_0_ops},
{"sha512", SPARC64_OPC_SHA512, INSN_VIS(I_SHA512),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_NONE,
 0, {}, sprint_insn_0_ops},
{"sll", SPARC64_OPC_SLL, INSN_OP3(I_OP3_SLL_SLLX) | INSN_OP3_X(0),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SHCNT32,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"srl", SPARC64_OPC_SRL, INSN_OP3(I_OP3_SRL_SRLX) | INSN_OP3_X(0),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SHCNT32,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"sra", SPARC64_OPC_SRA, INSN_OP3(I_OP3_SRA_SRAX) | INSN_OP3_X(0),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SHCNT32,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"sllx", SPARC64_OPC_SLLX, INSN_OP3(I_OP3_SLL_SLLX) | INSN_OP3_X(1),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SHCNT64,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"srlx", SPARC64_OPC_SRLX, INSN_OP3(I_OP3_SRL_SRLX) | INSN_OP3_X(1),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SHCNT64,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"srax", SPARC64_OPC_SRAX, INSN_OP3(I_OP3_SRA_SRAX) | INSN_OP3_X(1),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SHCNT64,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"smul", SPARC64_OPC_SMUL, INSN_OP3(I_OP3_SMUL),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_Y_OUT,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"smulcc", SPARC64_OPC_SMULcc, INSN_OP3(I_OP3_SMULcc),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_CCR_OUT | SPARC64_OPF_Y_OUT,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"stb", SPARC64_OPC_STB, INSN_LDST(I_OP3_STB),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RDIN, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_SIMM13}, sprint_insn_store},
{"sth", SPARC64_OPC_STH, INSN_LDST(I_OP3_STH),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RDIN, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_SIMM13}, sprint_insn_store},
{"stw", SPARC64_OPC_STW, INSN_LDST(I_OP3_STW),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RDIN, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_SIMM13}, sprint_insn_store},
{"stx", SPARC64_OPC_STX, INSN_LDST(I_OP3_STX),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RDIN, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_SIMM13}, sprint_insn_store},
{"stba", SPARC64_OPC_STBA, INSN_LDST(I_OP3_STBA),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_IREG_RDIN, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_SIMM13, SPARC64_OP_TYPE_ASI_IMPL_OR_IMM},
 sprint_insn_store_asi},
{"stha", SPARC64_OPC_STHA, INSN_LDST(I_OP3_STHA),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_IREG_RDIN, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_SIMM13, SPARC64_OP_TYPE_ASI_IMPL_OR_IMM},
 sprint_insn_store_asi},
{"stwa", SPARC64_OPC_STWA, INSN_LDST(I_OP3_STWA),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_IREG_RDIN, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_SIMM13, SPARC64_OP_TYPE_ASI_IMPL_OR_IMM},
 sprint_insn_store_asi},
{"stxa", SPARC64_OPC_STXA, INSN_LDST(I_OP3_STXA),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 4, {SPARC64_OP_TYPE_IREG_RDIN, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_SIMM13, SPARC64_OP_TYPE_ASI_IMPL_OR_IMM},
 sprint_insn_store_asi},
{"st", SPARC64_OPC_STF, INSN_LDST(I_OP3_STF),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG32_RDIN, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_SIMM13}, sprint_insn_store},
{"std", SPARC64_OPC_STDF, INSN_LDST(I_OP3_STDF),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG64_RDIN, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_SIMM13}, sprint_insn_store},
{"stq", SPARC64_OPC_STQF, INSN_LDST(I_OP3_STQF),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_FREG128_RDIN, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_SIMM13}, sprint_insn_store},
{"st", SPARC64_OPC_STFSR, INSN_LDST(I_OP3_STFSR),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RDIN, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_SIMM13}, sprint_insn_stfsr},
{"stx", SPARC64_OPC_STXFSR, INSN_LDST(I_OP3_STFSR),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RDIN, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_SIMM13}, sprint_insn_stfsr},
{"sub", SPARC64_OPC_SUB, INSN_OP3(I_OP3_SUB),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"subcc", SPARC64_OPC_SUBcc, INSN_OP3(I_OP3_SUBcc),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_CCR_OUT,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"subc", SPARC64_OPC_SUBC, INSN_OP3(I_OP3_SUBC),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_CCR_CARRY_IN,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"subccc", SPARC64_OPC_SUBCcc, INSN_OP3(I_OP3_SUBCcc),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_CCR_CARRY_IN | SPARC64_OPF_CCR_OUT,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"swap", SPARC64_OPC_SWAP, INSN_LDST(I_OP3_SWAP),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RDINOUT}, sprint_insn_load},
{"ta", SPARC64_OPC_TA, INSN_Tcc(I_COND_A), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_Tcc, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_IMM8}, sprint_insn_3_ops},
{"tn", SPARC64_OPC_TN, INSN_Tcc(I_COND_N), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_Tcc, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_IMM8}, sprint_insn_3_ops},
{"tne", SPARC64_OPC_TNE, INSN_Tcc(I_COND_NE), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_ZERO_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_Tcc, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_IMM8}, sprint_insn_3_ops},
{"te", SPARC64_OPC_TE, INSN_Tcc(I_COND_E), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_ZERO_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_Tcc, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_IMM8}, sprint_insn_3_ops},
{"tg", SPARC64_OPC_TG, INSN_Tcc(I_COND_G), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_OVERFLOW_IN | SPARC64_OPF_CCR_ZERO_IN |
                               SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_Tcc, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_IMM8}, sprint_insn_3_ops},
{"tle", SPARC64_OPC_TLE, INSN_Tcc(I_COND_LE), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_OVERFLOW_IN | SPARC64_OPF_CCR_ZERO_IN |
                               SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_Tcc, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_IMM8}, sprint_insn_3_ops},
{"tge", SPARC64_OPC_TGE, INSN_Tcc(I_COND_GE), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_OVERFLOW_IN | SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_Tcc, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_IMM8}, sprint_insn_3_ops},
{"tl", SPARC64_OPC_TL, INSN_Tcc(I_COND_L), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_OVERFLOW_IN | SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_Tcc, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_IMM8}, sprint_insn_3_ops},
{"tgu", SPARC64_OPC_TGU, INSN_Tcc(I_COND_GU), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_CARRY_IN | SPARC64_OPF_CCR_ZERO_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_Tcc, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_IMM8}, sprint_insn_3_ops},
{"tleu", SPARC64_OPC_TLEU, INSN_Tcc(I_COND_LEU), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_CARRY_IN | SPARC64_OPF_CCR_ZERO_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_Tcc, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_IMM8}, sprint_insn_3_ops},
{"tcc", SPARC64_OPC_TCC, INSN_Tcc(I_COND_CC), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_CARRY_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_Tcc, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_IMM8}, sprint_insn_3_ops},
{"tcs", SPARC64_OPC_TCS, INSN_Tcc(I_COND_CS), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_CARRY_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_Tcc, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_IMM8}, sprint_insn_3_ops},
{"tpos", SPARC64_OPC_TPOS, INSN_Tcc(I_COND_POS), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_Tcc, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_IMM8}, sprint_insn_3_ops},
{"tneg", SPARC64_OPC_TNEG, INSN_Tcc(I_COND_NEG), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_NEGATIVE_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_Tcc, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_IMM8}, sprint_insn_3_ops},
{"tvc", SPARC64_OPC_TVC, INSN_Tcc(I_COND_VC), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_OVERFLOW_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_Tcc, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_IMM8}, sprint_insn_3_ops},
{"tvs", SPARC64_OPC_TVS, INSN_Tcc(I_COND_VS), VEX_HWCAPS_SPARC64_BASE,
 SPARC64_OPF_CCR_OVERFLOW_IN,
 3, {SPARC64_OP_TYPE_I_OR_X_CC_Tcc, SPARC64_OP_TYPE_IREG_RS1,
     SPARC64_OP_TYPE_RS2_OR_IMM8}, sprint_insn_3_ops},
{"udiv", SPARC64_OPC_UDIV, INSN_OP3(I_OP3_UDIV),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_Y_IN,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"udivcc", SPARC64_OPC_UDIVcc, INSN_OP3(I_OP3_UDIVcc),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_CCR_OUT | SPARC64_OPF_Y_IN,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"umul", SPARC64_OPC_UMUL, INSN_OP3(I_OP3_UMUL),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_Y_OUT,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"umulcc", SPARC64_OPC_UMULcc, INSN_OP3(I_OP3_UMULcc),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_CCR_OUT | SPARC64_OPF_Y_OUT,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"umulxhi", SPARC64_OPC_UMULXHI, INSN_VIS(I_UMULXHI),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_IREG_RS2,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"wry", SPARC64_OPC_WRY, INSN_OP3(I_OP3_WRasr),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_wrasr},
{"wrccr", SPARC64_OPC_WRCCR, INSN_OP3(I_OP3_WRasr),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_wrasr},
{"wrasi", SPARC64_OPC_WRASI, INSN_OP3(I_OP3_WRasr),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_wrasr},
{"wrfprs", SPARC64_OPC_WRFPRS, INSN_OP3(I_OP3_WRasr),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_wrasr},
{"wrmcdper", SPARC64_OPC_WRMCDPER, INSN_OP3(I_OP3_WRasr),
 VEX_HWCAPS_SPARC64_SPARC5, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_wrasr},
{"wrgsr", SPARC64_OPC_WRGSR, INSN_OP3(I_OP3_WRasr),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_wrasr},
{"wrpause", SPARC64_OPC_WRPAUSE, INSN_OP3(I_OP3_WRasr),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_wrasr},
{"wrmwait", SPARC64_OPC_WRMWAIT, INSN_OP3(I_OP3_WRasr),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_wrasr},
{"xmulx", SPARC64_OPC_XMULX, INSN_VIS(I_XMULX),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_IREG_RS2,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"xmulxhi", SPARC64_OPC_XMULXHI, INSN_VIS(I_XMULXHI),
 VEX_HWCAPS_SPARC64_VIS3, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_IREG_RS2,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"xor", SPARC64_OPC_XOR, INSN_OP3(I_OP3_XOR),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"xorcc", SPARC64_OPC_XORcc, INSN_OP3(I_OP3_XORcc),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_CCR_OUT,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"xnor", SPARC64_OPC_XNOR, INSN_OP3(I_OP3_XNOR),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_NONE,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops},
{"xnorcc", SPARC64_OPC_XNORcc, INSN_OP3(I_OP3_XNORcc),
 VEX_HWCAPS_SPARC64_BASE, SPARC64_OPF_CCR_OUT,
 3, {SPARC64_OP_TYPE_IREG_RS1, SPARC64_OP_TYPE_RS2_OR_SIMM13,
     SPARC64_OP_TYPE_IREG_RD}, sprint_insn_3_ops}
};


/*----------------------------------------------------------------------------*/
/*--- Generic stuff.                                                       ---*/
/*----------------------------------------------------------------------------*/

const sparc64_opcode *
sparc64_find_opcode(UInt insn)
{
    const sparc64_opcode *opcode = NULL;

    switch (BITS(insn, 31, 30)) {
    case 0: /* branches and nop/sethi */
        opcode = find_opcode_op0(insn);
        if (opcode == NULL) {
            /* unrecognized instruction processing cannot handle branches */
            vpanic("Unrecognized branch instruction");
        }
        return opcode;
    case 1: /* call */
        return &sparc64_opcodes[SPARC64_OPC_CALL];
    case 2: /* arithmetic & miscellaneous */
        return find_opcode_op2(insn);
    case 3: /* loads and stores */
        return find_opcode_op3(insn);
    default:
        vassert(0);
    }
}

Bool
sparc64_decode_insn(UInt insn, sparc64_insn *decoded, Bool *handle_unrecognized)
{
    vassert(decoded != NULL);
    *handle_unrecognized = False;

    const sparc64_opcode *opcode = sparc64_find_opcode(insn);
    if (opcode != NULL) {
        decoded->opcode = opcode;

        for (UInt i = 0; i < opcode->num_operands; i++) {
            const sparc64_operand *op_in =
                &sparc64_operands[opcode->operands[i]];
            decoded->operands[i] = op_in->decode(insn, op_in,
                                                 &decoded->operand_values[i]);
            vassert(decoded->operands[i]->type > SPARC64_OP_TYPE_FIRST);
            vassert(decoded->operands[i]->type < SPARC64_OP_TYPE_LAST);
            vassert(decoded->operands[i]->is_meta == 0);
        }

        return True;

    } else {
        decoded->opcode = &sparc64_opcodes[SPARC64_OPC_NONE];

        /* unrecognized instruction but not a branch, call, SIAM, etc. We can
           safely execute it if not in a delay slot. */
        *handle_unrecognized = True;
        return False;
    }
}

UInt
sparc64_sprint_insn(HChar *buf, const sparc64_insn *insn)
{
    vassert(insn != NULL);
    return insn->opcode->sprint(buf, insn);
}

UInt
sparc64_encode_insn(const sparc64_insn *insn)
{
    vassert(insn != NULL);

    const sparc64_opcode *opcode = insn->opcode;
    UInt encoded = opcode->encoding;

    for (UInt i = 0; i < opcode->num_operands; i++) {
        const sparc64_operand *operand = insn->operands[i];
        encoded |= operand->encode(operand, insn->operand_values[i]);
    }

    return encoded;
}

void
sparc64_make_insn(sparc64_insn *insn,
                  sparc64_mnemonic mnemonic,
                  ...)
{
    vassert(insn != NULL);

    const sparc64_opcode *opcode = sparc64_get_opcode(mnemonic);
    vassert(opcode != NULL);
    insn->opcode = opcode;
    va_list arg_list;

    va_start(arg_list, mnemonic);
    for (UInt i = 0; i < opcode->num_operands; i++) {
        sparc64_operand_type optype;

        optype = va_arg(arg_list, sparc64_operand_type);
        insn->operands[i] = sparc64_get_operand(optype);
        insn->operand_values[i] = va_arg(arg_list, sparc64_operand_value);

        vassert(insn->operands[i] != NULL);
    }
    va_end(arg_list);
}

Bool
sparc64_cmp_insn(const sparc64_insn *a, const sparc64_insn *b)
{
    vassert(a != NULL);
    vassert(b != NULL);

#define LDDFA_LIKE(m) (((m) == SPARC64_OPC_LDBLOCKF) || \
    ((m) == SPARC64_OPC_LDDFA) || ((m) == SPARC64_OPC_LDSHORTF))

    if (a->opcode != b->opcode) {
        /* Check now for LDBLOCKF, LDDFA, LDSHORTF with implicit %asi. */
        if (LDDFA_LIKE(a->opcode->mnemonic) &&
            LDDFA_LIKE(b->opcode->mnemonic) &&
            (a->operands[2]->type == SPARC64_OP_TYPE_ASI_IMPL) &&
            (b->operands[2]->type == SPARC64_OP_TYPE_ASI_IMPL)) {
            ; // Proceed further, these opcodes are consider equal.
        } else {
            return False;
        }
    }

    const sparc64_opcode *opcode = a->opcode;
    for (UInt i = 0; i < opcode->num_operands; i++) {
        if (a->operands[i] != b->operands[i]) {
            return False;
        }
    }

    for (UInt i = 0; i < opcode->num_operands; i++) {
        if (sparc64_cmp_opvalue(a->operands[i]->vex_type, a->operand_values[i],
                                b->operand_values[i]) != True) {
            return False;
        }
    }

    return True;
}

SPARC64_ASR
sparc64_get_asr_value(sparc64_mnemonic mnemonic)
{
    switch (mnemonic) {
    case SPARC64_OPC_RDY:
        return SPARC64_ASR_Y;
    case SPARC64_OPC_RDCCR:
        return SPARC64_ASR_CCR;
    case SPARC64_OPC_RDASI:
        return SPARC64_ASR_ASI;
    case SPARC64_OPC_RDTICK:
        return SPARC64_ASR_TICK;
    case SPARC64_OPC_RDPC:
        return SPARC64_ASR_PC;
    case SPARC64_OPC_RDFPRS:
        return SPARC64_ASR_FPRS;
    case SPARC64_OPC_RDENTROPY:
        return SPARC64_ASR_ENTROPY;
    case SPARC64_OPC_RDMCDPER:
        return SPARC64_ASR_MCDPER;
    case SPARC64_OPC_RDGSR:
        return SPARC64_ASR_GSR;
    case SPARC64_OPC_RDSTICK:
        return SPARC64_ASR_STICK;
    case SPARC64_OPC_RDCFR:
        return SPARC64_ASR_CFR;
    case SPARC64_OPC_WRY:
        return SPARC64_ASR_Y;
    case SPARC64_OPC_WRCCR:
        return SPARC64_ASR_CCR;
    case SPARC64_OPC_WRASI:
        return SPARC64_ASR_ASI;
    case SPARC64_OPC_WRFPRS:
        return SPARC64_ASR_FPRS;
    case SPARC64_OPC_WRMCDPER:
        return SPARC64_ASR_MCDPER;
    case SPARC64_OPC_WRGSR:
        return SPARC64_ASR_GSR;
    case SPARC64_OPC_WRPAUSE:
        return SPARC64_ASR_PAUSE;
    case SPARC64_OPC_WRMWAIT:
        return SPARC64_ASR_MWAIT;
    default:
        vpanic("Unrecognized RDasr or WRasr mnemonic");
    }
}

UInt
sparc64_get_operand_index(sparc64_mnemonic mnemonic,
                          sparc64_operand_type_group op_type_group)
{
    switch (mnemonic) {
    case SPARC64_OPC_NONE:
    case SPARC64_OPC_FLUSHW:
    case SPARC64_OPC_LAST:
    case SPARC64_OPC_MD5:
    case SPARC64_OPC_NOP:
    case SPARC64_OPC_SHA1:
    case SPARC64_OPC_SHA256:
    case SPARC64_OPC_SHA512:
        return (UInt) -1;
    case SPARC64_OPC_ADD ... SPARC64_OPC_ADDCcc:
    case SPARC64_OPC_ADDXC ... SPARC64_OPC_ADDXCcc:
    case SPARC64_OPC_ALIGNADDRESS:
    case SPARC64_OPC_AND ... SPARC64_OPC_ANDNcc:
    case SPARC64_OPC_BMASK:
    case SPARC64_OPC_BSHUFFLE:
    case SPARC64_OPC_JMPL:
    case SPARC64_OPC_LDSB ... SPARC64_OPC_LDX:
    case SPARC64_OPC_LDF ... SPARC64_OPC_LDQF:
    case SPARC64_OPC_LDFSR:
    case SPARC64_OPC_LDSTUB:
    case SPARC64_OPC_LDXFSR:
    case SPARC64_OPC_MOVRZ ... SPARC64_OPC_MOVRGEZ:
    case SPARC64_OPC_MULX ... SPARC64_OPC_UDIVX:
    case SPARC64_OPC_OR ... SPARC64_OPC_ORNcc:
    case SPARC64_OPC_RESTORE:
    case SPARC64_OPC_SAVE:
    case SPARC64_OPC_SLL ... SPARC64_OPC_SRAX:
    case SPARC64_OPC_SMUL ... SPARC64_OPC_SMULcc:
    case SPARC64_OPC_SUB ... SPARC64_OPC_SUBCcc:
    case SPARC64_OPC_SWAP:
    case SPARC64_OPC_SDIV ... SPARC64_OPC_SDIVcc:
    case SPARC64_OPC_UDIV ... SPARC64_OPC_UDIVcc:
    case SPARC64_OPC_UMUL ... SPARC64_OPC_UMULcc:
    case SPARC64_OPC_UMULXHI:
    case SPARC64_OPC_WRY ... SPARC64_OPC_WRMWAIT:
    case SPARC64_OPC_XMULX ... SPARC64_OPC_XMULXHI:
    case SPARC64_OPC_XOR ... SPARC64_OPC_XNORcc:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_RS1:
            return 0;
        case SPARC64_OP_TYPE_GROUP_RS2_OR_IMM:
            return 1;
        case SPARC64_OP_TYPE_GROUP_RD:
            return 2;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_AES_KEXPAND1:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_RS1:
            return 0;
        case SPARC64_OP_TYPE_GROUP_RS2_OR_IMM:
            return 1;
        case SPARC64_OP_TYPE_GROUP_IMM:
            return 2;
        case SPARC64_OP_TYPE_GROUP_RD:
            return 3;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_BA ... SPARC64_OPC_BVS:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_ANNUL:
            return 0;
        case SPARC64_OP_TYPE_GROUP_DISP:
            return 1;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_BPA ... SPARC64_OPC_BPVS:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_ANNUL:
            return 0;
        case SPARC64_OP_TYPE_GROUP_PREDICTION:
            return 1;
        case SPARC64_OP_TYPE_GROUP_I_OR_X_CC:
            return 2;
        case SPARC64_OP_TYPE_GROUP_DISP:
            return 3;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_BRZ ... SPARC64_OPC_BRGEZ:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_ANNUL:
            return 0;
        case SPARC64_OP_TYPE_GROUP_PREDICTION:
            return 1;
        case SPARC64_OP_TYPE_GROUP_RS1:
            return 2;
        case SPARC64_OP_TYPE_GROUP_DISP:
            return 3;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_CALL:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_DISP:
            return 0;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_CASA ... SPARC64_OPC_CASXA:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_RS1:
            return 0;
        case SPARC64_OP_TYPE_GROUP_ASI:
            return 1;
        case SPARC64_OP_TYPE_GROUP_RS2_OR_IMM:
            return 2;
        case SPARC64_OP_TYPE_GROUP_RD:
            return 3;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_CWBNE ... SPARC64_OPC_CXBVS:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_RS1:
            return 0;
        case SPARC64_OP_TYPE_GROUP_RS2_OR_IMM:
            return 1;
        case SPARC64_OP_TYPE_GROUP_DISP:
            return 2;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_FLUSH:
    case SPARC64_OPC_RETURN:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_RS1:
            return 0;
        case SPARC64_OP_TYPE_GROUP_RS2_OR_IMM:
            return 1;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_FABSs ... SPARC64_OPC_FABSq:
    case SPARC64_OPC_FiTOs ... SPARC64_OPC_FiTOq:
    case SPARC64_OPC_FMOVs ... SPARC64_OPC_FMOVq:
    case SPARC64_OPC_FNEGs ... SPARC64_OPC_FNEGq:
    case SPARC64_OPC_FSQRTs ... SPARC64_OPC_FSQRTq:
    case SPARC64_OPC_FSRC2d ... SPARC64_OPC_FSRC2s:
    case SPARC64_OPC_FNOT2d ... SPARC64_OPC_FNOT2s:
    case SPARC64_OPC_FsTOx ... SPARC64_OPC_FqTOx:
    case SPARC64_OPC_FsTOi ... SPARC64_OPC_FqTOi:
    case SPARC64_OPC_FsTOd ... SPARC64_OPC_FqTOd:
    case SPARC64_OPC_FxTOs ... SPARC64_OPC_FxTOq:
    case SPARC64_OPC_MOVsTOsw ... SPARC64_OPC_MOVdTOx:
    case SPARC64_OPC_MOVwTOs ... SPARC64_OPC_MOVxTOd:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_RS2_OR_IMM:
            return 0;
        case SPARC64_OP_TYPE_GROUP_RD:
            return 1;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_AES_KEXPAND0 ... SPARC64_OPC_AES_KEXPAND2:
    case SPARC64_OPC_FADDs ... SPARC64_OPC_FADDq:
    case SPARC64_OPC_FALIGNDATAg:
    case SPARC64_OPC_FORd ... SPARC64_OPC_FNORs:
    case SPARC64_OPC_FANDd ... SPARC64_OPC_FNANDs:
    case SPARC64_OPC_FXORd ... SPARC64_OPC_FXNORs:
    case SPARC64_OPC_FORNOT1d ... SPARC64_OPC_FORNOT2s:
    case SPARC64_OPC_FANDNOT1d ... SPARC64_OPC_FANDNOT2s:
    case SPARC64_OPC_FDIVs ... SPARC64_OPC_FDIVq:
    case SPARC64_OPC_FMULs ... SPARC64_OPC_FdMULq:
    case SPARC64_OPC_FSLL16 ... SPARC64_OPC_FSRA32:
    case SPARC64_OPC_FSUBs ... SPARC64_OPC_FSUBq:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_RS1:
            return 0;
        case SPARC64_OP_TYPE_GROUP_RS2_OR_IMM:
            return 1;
        case SPARC64_OP_TYPE_GROUP_RD:
            return 2;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_FBPA ... SPARC64_OPC_FBPO:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_ANNUL:
            return 0;
        case SPARC64_OP_TYPE_GROUP_PREDICTION:
            return 1;
        case SPARC64_OP_TYPE_GROUP_FCCn:
            return 2;
        case SPARC64_OP_TYPE_GROUP_DISP:
            return 3;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_FCMPs ... SPARC64_OPC_FCMPEq:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_FCCn:
            return 0;
        case SPARC64_OP_TYPE_GROUP_RS1:
            return 1;
        case SPARC64_OP_TYPE_GROUP_RS2_OR_IMM:
            return 2;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_AES_EROUND01 ... SPARC64_OPC_AES_DROUND23_LAST:
    case SPARC64_OPC_FMADDs ... SPARC64_OPC_FNMADDd:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_RS1:
            return 0;
        case SPARC64_OP_TYPE_GROUP_RS2_OR_IMM:
            return 1;
        case SPARC64_OP_TYPE_GROUP_RS3:
            return 2;
        case SPARC64_OP_TYPE_GROUP_RD:
            return 3;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_FMOVSiccA ... SPARC64_OPC_FMOVQiccVS:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_I_OR_X_CC:
            return 0;
        case SPARC64_OP_TYPE_GROUP_RS2_OR_IMM:
            return 1;
        case SPARC64_OP_TYPE_GROUP_RD:
            return 2;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_FMOVSfccA ... SPARC64_OPC_FMOVQfccO:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_FCCn:
            return 0;
        case SPARC64_OP_TYPE_GROUP_RS2_OR_IMM:
            return 1;
        case SPARC64_OP_TYPE_GROUP_RD:
            return 2;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_FZEROs ... SPARC64_OPC_FZEROd:
    case SPARC64_OPC_FONEs ... SPARC64_OPC_FONEd:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_RD:
            return 0;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_FSRC1d ... SPARC64_OPC_FSRC1s:
    case SPARC64_OPC_FNOT1d ... SPARC64_OPC_FNOT1s:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_RS1:
            return 0;
        case SPARC64_OP_TYPE_GROUP_RD:
            return 1;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_LDSBA ... SPARC64_OPC_LDXA:
    case SPARC64_OPC_LDBLOCKF:
    case SPARC64_OPC_LDFA ... SPARC64_OPC_LDQFA:
    case SPARC64_OPC_LDSHORTF:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_RS1:
            return 0;
        case SPARC64_OP_TYPE_GROUP_RS2_OR_IMM:
            return 1;
        case SPARC64_OP_TYPE_GROUP_ASI:
            return 2;
        case SPARC64_OP_TYPE_GROUP_RD:
            return 3;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_LZCNT:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_RS2_OR_IMM:
            return 0;
        case SPARC64_OP_TYPE_GROUP_RD:
            return 1;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_MEMBAR:
        vpanic("Operand type groups not implemented for MEMBAR");
        break;
    case SPARC64_OPC_MOVA ... SPARC64_OPC_MOVVS:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_I_OR_X_CC:
            return 0;
        case SPARC64_OP_TYPE_GROUP_RS2_OR_IMM:
            return 1;
        case SPARC64_OP_TYPE_GROUP_RD:
            return 2;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_MOVFA ... SPARC64_OPC_MOVFO:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_FCCn:
            return 0;
        case SPARC64_OP_TYPE_GROUP_RS2_OR_IMM:
            return 1;
        case SPARC64_OP_TYPE_GROUP_RD:
            return 2;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_PREFETCH:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_RS1:
            return 0;
        case SPARC64_OP_TYPE_GROUP_RS2_OR_IMM:
            return 1;
        case SPARC64_OP_TYPE_GROUP_PREFETCH_FCN:
            return 2;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_PREFETCHA:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_RS1:
            return 0;
        case SPARC64_OP_TYPE_GROUP_RS2_OR_IMM:
            return 1;
        case SPARC64_OP_TYPE_GROUP_ASI:
            return 2;
        case SPARC64_OP_TYPE_GROUP_PREFETCH_FCN:
            return 3;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_RDY ... SPARC64_OPC_RDCFR:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_RS1:
            return 0;
        case SPARC64_OP_TYPE_GROUP_RD:
            return 1;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_SETHI:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_IMM:
            return 0;
        case SPARC64_OP_TYPE_GROUP_RD:
            return 1;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_STB ... SPARC64_OPC_STX:
    case SPARC64_OPC_STF ... SPARC64_OPC_STQF:
    case SPARC64_OPC_STFSR ... SPARC64_OPC_STXFSR:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_RD:
            return 0;
        case SPARC64_OP_TYPE_GROUP_RS1:
            return 1;
        case SPARC64_OP_TYPE_GROUP_RS2_OR_IMM:
            return 2;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_STBA ... SPARC64_OPC_STXA:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_RD:
            return 0;
        case SPARC64_OP_TYPE_GROUP_RS1:
            return 1;
        case SPARC64_OP_TYPE_GROUP_RS2_OR_IMM:
            return 2;
        case SPARC64_OP_TYPE_GROUP_ASI:
            return 3;
        default:
            return (UInt) -1;
        }
        break;
    case SPARC64_OPC_TA ... SPARC64_OPC_TVS:
        switch (op_type_group) {
        case SPARC64_OP_TYPE_GROUP_I_OR_X_CC:
            return 0;
        case SPARC64_OP_TYPE_GROUP_RS1:
            return 1;
        case SPARC64_OP_TYPE_GROUP_RS2_OR_IMM:
            return 2;
        default:
            return (UInt) -1;
        }
        break;
    }

    vassert(0);
}

const sparc64_opcode *
sparc64_get_opcode(sparc64_mnemonic mnemonic)
{
    vassert(mnemonic >= SPARC64_OPC_NONE);
    vassert(mnemonic < SPARC64_OPC_LAST);

    return &sparc64_opcodes[mnemonic];
}

const sparc64_operand *
sparc64_get_operand(sparc64_operand_type type)
{
    vassert(type > SPARC64_OP_TYPE_FIRST);
    vassert(type < SPARC64_OP_TYPE_LAST);

    return &sparc64_operands[type];
}

/*----------------------------------------------------------------------------*/
/*--- end                                                 sparc64_disasm.c ---*/
/*----------------------------------------------------------------------------*/
