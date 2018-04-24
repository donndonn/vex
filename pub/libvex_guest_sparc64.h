/*----------------------------------------------------------------------------*/
/*--- begin                                         libvex_guest_sparc64.h ---*/
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

#ifndef __LIBVEX_PUB_GUEST_SPARC64_H
#define __LIBVEX_PUB_GUEST_SPARC64_H

#include "libvex_basictypes.h"
#include "libvex_emnote.h"

/*----------------------------------------------------------------------------*/
/*--- Vex's representation of the SPARC64 CPU state                        ---*/
/* The CPU state is emulated by VEX and does not correspond 1:1 to the        */
/* underlying hardware. For example windowing registers are emulated          */
/* independently of the hardware ones (in reality, these are privileged       */
/* and therefore cannot be read or written from userspace).                   */
/*----------------------------------------------------------------------------*/

/*
 * The guest state contains only the current register window. We are not
 * emulating full hw windowed mechanism and its spill/fill traps.
 * This means our previous register windows are always spilled.
 *
 * FPU support limitations:
 * - FPRS.fu and FPRS.du are not correctly emulated - fu and du
 *   are always set both.
 * - FSR.aexc is not emulated. When set, it is silently ignored.
 *   When read, it always yields 0.
 * - Setting FSR.tem or FSR.ns to something else then 0 results in an emulation
 *   warning and is ignored anyway.
 */
typedef struct {
    /* --- Event check fail addr and counter --- */
    /*    0 */ ULong host_EvC_FAILADDR;
    /*    8 */ UInt  host_EvC_COUNTER;
    /*   12 */ UInt  pad0;
    /* ---- General purpose registers --- */
    /*   16 */ ULong guest_R0; /* %g0: hardwired to zero */
    /*   24 */ ULong guest_R1; /* %g1 */
    /*   32 */ ULong guest_R2; /* %g2 */
    /*   40 */ ULong guest_R3; /* %g3 */
    /*   48 */ ULong guest_R4; /* %g4 */
    /*   56 */ ULong guest_R5; /* %g5 */
    /*   64 */ ULong guest_R6; /* %g6 */
    /*   72 */ ULong guest_R7; /* %g7 */
    /*   80 */ ULong guest_R8; /* %o0 */
    /*   88 */ ULong guest_R9; /* %o1 */
    /*   96 */ ULong guest_R10; /* %o2 */
    /*  104 */ ULong guest_R11; /* %o3 */
    /*  112 */ ULong guest_R12; /* %o4 */
    /*  120 */ ULong guest_R13; /* %o5 */
    /*  128 */ ULong guest_R14; /* %o6 */
    /*  136 */ ULong guest_R15; /* %o7 */
    /*  144 */ ULong guest_R16; /* %l0 */
    /*  152 */ ULong guest_R17; /* %l1 */
    /*  160 */ ULong guest_R18; /* %l2 */
    /*  168 */ ULong guest_R19; /* %l3 */
    /*  176 */ ULong guest_R20; /* %l4 */
    /*  184 */ ULong guest_R21; /* %l5 */
    /*  192 */ ULong guest_R22; /* %l6 */
    /*  200 */ ULong guest_R23; /* %l7 */
    /*  208 */ ULong guest_R24; /* %i0 */
    /*  216 */ ULong guest_R25; /* %i1 */
    /*  224 */ ULong guest_R26; /* %i2 */
    /*  232 */ ULong guest_R27; /* %i3 */
    /*  240 */ ULong guest_R28; /* %i4 */
    /*  248 */ ULong guest_R29; /* %i5 */
    /*  256 */ ULong guest_R30; /* %i6 */
    /*  264 */ ULong guest_R31; /* %i7 */
    /* ---- FPU regs ----          32-bit      64-bit    128-bit */
    /*  272 */ UInt  guest_F0;   /* %f0         %d0        %q0  */
    /*  276 */ UInt  guest_F1;   /* %f1         -"-        -"-  */
    /*  280 */ UInt  guest_F2;   /* %f2         %d2        -"-  */
    /*  284 */ UInt  guest_F3;   /* %f3         -"-        -"-  */
    /*  288 */ UInt  guest_F4;   /* %f4         %d4        %q4  */
    /*  292 */ UInt  guest_F5;   /* %f5         -"-        -"-  */
    /*  296 */ UInt  guest_F6;   /* %f6         %d6        -"-  */
    /*  300 */ UInt  guest_F7;   /* %f7         -"-        -"-  */
    /*  304 */ UInt  guest_F8;   /* %f8         %d8        %q8  */
    /*  308 */ UInt  guest_F9;   /* %f9         -"-        -"-  */
    /*  312 */ UInt  guest_F10;  /* %f10        %d10       -"-  */
    /*  316 */ UInt  guest_F11;  /* %f11        -"-        -"-  */
    /*  320 */ UInt  guest_F12;  /* %f12        %d12       %q12 */
    /*  324 */ UInt  guest_F13;  /* %f13        -"-        -"-  */
    /*  328 */ UInt  guest_F14;  /* %f14        %d14       -"-  */
    /*  332 */ UInt  guest_F15;  /* %f15        -"-        -"-  */
    /*  336 */ UInt  guest_F16;  /* %f16        %d16       %q16 */
    /*  340 */ UInt  guest_F17;  /* %f17        -"-        -"-  */
    /*  344 */ UInt  guest_F18;  /* %f18        %d18       -"-  */
    /*  348 */ UInt  guest_F19;  /* %f19        -"-        -"-  */
    /*  352 */ UInt  guest_F20;  /* %f20        %d20       %q20 */
    /*  356 */ UInt  guest_F21;  /* %f21        -"-        -"-  */
    /*  360 */ UInt  guest_F22;  /* %f22        %d22       -"-  */
    /*  364 */ UInt  guest_F23;  /* %f23        -"-        -"-  */
    /*  368 */ UInt  guest_F24;  /* %f24        %d24       %q24 */
    /*  372 */ UInt  guest_F25;  /* %f25        -"-        -"-  */
    /*  376 */ UInt  guest_F26;  /* %f26        %d26       -"-  */
    /*  380 */ UInt  guest_F27;  /* %f27        -"-        -"-  */
    /*  384 */ UInt  guest_F28;  /* %f28        %d28       %q28 */
    /*  388 */ UInt  guest_F29;  /* %f29        -"-        -"-  */
    /*  392 */ UInt  guest_F30;  /* %f30        %d30       -"-  */
    /*  396 */ UInt  guest_F31;  /* %f31        -"-        -"-  */
    /*  400 */ ULong guest_D32;  /*             %d32       %q32 */
    /*  408 */ ULong guest_D34;  /*             %d34       -"-  */
    /*  416 */ ULong guest_D36;  /*             %d36       %q36 */
    /*  424 */ ULong guest_D38;  /*             %d38       -"-  */
    /*  432 */ ULong guest_D40;  /*             %d40       %q40 */
    /*  440 */ ULong guest_D42;  /*             %d42       -"-  */
    /*  448 */ ULong guest_D44;  /*             %d44       %q42 */
    /*  456 */ ULong guest_D46;  /*             %d46       -"-  */
    /*  464 */ ULong guest_D48;  /*             %d48       %q48 */
    /*  472 */ ULong guest_D50;  /*             %d50       -"-  */
    /*  480 */ ULong guest_D52;  /*             %d52       %q52 */
    /*  488 */ ULong guest_D54;  /*             %d54       -"-  */
    /*  496 */ ULong guest_D56;  /*             %d56       %q56 */
    /*  504 */ ULong guest_D58;  /*             %d58       -"-  */
    /*  512 */ ULong guest_D60;  /*             %d60       %q60 */
    /*  520 */ ULong guest_D62;  /*             %d62       -"-  */
    /* ---- Program counters --- */
    /*  528 */ ULong guest_PC;
    /*  536 */ ULong guest_NPC;
    /*  544 */ ULong guest_Y; /* high 32 bits always read 0 */
    /* ASI needs only 8 bits, the rest is unused.*/
    /*  552 */ ULong guest_ASI; /* %asi */
    /*  560 */ ULong guest_FPRS; /* %fprs */
    /*  568 */ UInt guest_GSR_align; /* GSR.align (3 bits) */
    /*  572 */ UInt guest_GSR_mask;  /* GSR.mask (32 bits) */
    /* TODO-SPARC: Remaining ASR registers. */

    /* For clflush/clinval: record start and length of area */
    /*  576 */ ULong guest_CMSTART;
    /*  584 */ ULong guest_CMLEN;

    /* CCR helper regs */
    /*  592 */ ULong guest_CC_OP;
    /*  600 */ ULong guest_CC_DEP1;
    /*  608 */ ULong guest_CC_DEP2;
    /*  616 */ ULong guest_CC_NDEP;

    /* FSR helper regs */
    /*  624 */ ULong guest_FSR_RD; /* FSR.rd in IRRoundingMode representation */
    /*  632 */ ULong guest_FSR_FCC; /* all FSR.fcc fields */
    /* FSR.cexc helper regs */
    /*  640 */ ULong guest_FSR_CEXC_OP;
    /*  648 */ ULong guest_FSR_CEXC_DEP1_HI; /* 128-bit wide DEP1 */
    /*  656 */ ULong guest_FSR_CEXC_DEP1_LO;
    /*  664 */ ULong guest_FSR_CEXC_DEP2_HI; /* 128-bit wide DEP2 */
    /*  672 */ ULong guest_FSR_CEXC_DEP2_LO;
    /*  680 */ ULong guest_FSR_CEXC_NDEP; /* FSR.rd valid at that moment */

    /*  688 */ ULong guest_NRADDR;

    /* Emulation notes */
    /*  696 */ UInt guest_EMNOTE;
    /*  700 */ UInt pad1;
    /*  704 */ ULong guest_scratchpad; /* scratchpad for %fsr */

    /* The following are used to save host registers during the execution of
       an unrecognized instruction */
    /*  712 */ ULong guest_host_FP;
    /*  720 */ ULong guest_host_SP;
    /*  728 */ ULong guest_host_O7;        /* return address */

} VexGuestSPARC64State;

/*----------------------------------------------------------------------------*/
/*--- Utility functions for SPARC64 guest stuff                            ---*/
/*----------------------------------------------------------------------------*/

/* ALL THE FOLLOWING ARE VISIBLE TO LIBRARY CLIENT */

/* Initialises a guest SPARC64 state. */
extern void
LibVEX_GuestSPARC64_initialise(/*OUT*/ VexGuestSPARC64State *vex_state);

/* Loads all registers from guest state into real registers prior to
   executing an unrecognized instruction. */
extern void
LibVEX_GuestSPARC64_LoadGuestRegisters(void);

/* Stores all registers to guest state after executing an unrecognized instruction. */
extern void
LibVEX_GuestSPARC64_StoreGuestRegisters(void);

/* Extracts corresponding Condition Code Register (CCR) value.
   Reads fields:
       - guest_CC_OP,
       - guest_CC_DEP1,
       - guest_CC_DEP2, and
       - guest_CC_NDEP */
extern ULong
LibVEX_GuestSPARC64_get_ccr(/*IN*/ const VexGuestSPARC64State *vex_state);

/* Stores new value of Condition Code Register (CCR) in the guest state.
   Writes fields:
       - guest_CC_OP,
       - guest_CC_DEP1,
       - guest_CC_DEP2, and
       - guest_CC_NDEP */
extern void
LibVEX_GuestSPARC64_put_ccr(ULong ccr, /*MOD*/ VexGuestSPARC64State *vex_state);

/* Sets the carry bit of CCR.icc (either 0 or 1) to the guest state.
   Writes fields:
       - guest_CC_OP,
       - guest_CC_DEP1,
       - guest_CC_DEP2, and
       - guest_CC_NDEP */
extern void
LibVEX_GuestSPARC64_put_icc_c(UChar new_carry,
                              /*MOD*/ VexGuestSPARC64State *vex_state);

/* Sets the carry bit of CCR.xcc (either 0 or 1) to the guest state.
   Writes fields:
       - guest_CC_OP,
       - guest_CC_DEP1,
       - guest_CC_DEP2, and
       - guest_CC_NDEP */
extern void
LibVEX_GuestSPARC64_put_xcc_c(UChar new_carry,
                              /*MOD*/ VexGuestSPARC64State *vex_state);

/* Extracts corresponding value of Floating-Point State Register (FSR) value.
   Reads fields:
       - guest_FSR_RD,
       - guest_FSR_FCC,
       - guest_FSR_CEXC_OP,
       - guest_FSR_CEXC_DEP1_HI, guest_FSR_CEXC_DEP1_LO,
       - guest_FSR_CEXC_DEP2_HI, guest_FSR_CEXC_DEP2_LO, and
       - guest_FSR_CEXC_NDEP */
extern ULong
LibVEX_GuestSPARC64_get_fsr(/*IN*/ const VexGuestSPARC64State *vex_state);

/* Stores new value of Floating-Point State Register (FSR) in the guest state.
   Writes fields:
       - guest_FSR_RD,
       - guest_FSR_FCC,
       - guest_FSR_CEXC_OP,
       - guest_FSR_CEXC_DEP1_HI, guest_FSR_CEXC_DEP1_LO,
       - guest_FSR_CEXC_DEP2_HI, guest_FSR_CEXC_DEP2_LO, and
       - guest_FSR_CEXC_NDEP */
extern void
LibVEX_GuestSPARC64_put_fsr(ULong fsr, /*MOD*/ VexGuestSPARC64State *vex_state);

/* Extracts corresponding value of General Status Register (GSR) value.
   Reads fields:
       - guest_GSR_align, and
       - guest_GSR_mask */
extern ULong
LibVEX_GuestSPARC64_get_gsr(/*IN*/ const VexGuestSPARC64State *vex_state);

/* Stores new value of General Status Register (GSR) in the guest state.
   Writes fields:
       - guest_GSR_align, and
       - guest_GSR_mask */
extern void
LibVEX_GuestSPARC64_put_gsr(ULong gsr, /*MOD*/ VexGuestSPARC64State *vex_state);

#endif /* __LIBVEX_PUB_GUEST_SPARC64_H */

/*----------------------------------------------------------------------------*/
/*--- end                                           libvex_guest_sparc64.h ---*/
/*----------------------------------------------------------------------------*/
