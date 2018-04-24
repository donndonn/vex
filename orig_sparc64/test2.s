.section ".data"
.align 4

.section ".text"
.align 4

.register %g2, #scratch
.register %g3, #scratch

!+Bcc/BPcc
!+BPr

.global test
test:
    ! 32-bit CBCond
    cwbne  %i0, %i1, label
    nop
    cwbe   %o1, -12, label
    nop
    cwbe   %g0, %g0, label
    nop
    cwbe   %g0, 0,   label
    nop
    cwbg   %l7, %g3, label
    nop
    cwble  %g2, %g4, label
    nop
    cwbge  %i3, 3,   label
    nop
    cwbl   %g0, g0,  label
    nop
    cwbgu  %i3, %o6, label
    nop
    cwbleu %l6, %g0, label
    nop
    cwbcc  %i4, %g4, label
    nop
    cwbcs  %i4, %g0, label
    nop
    cwbpos %g0, 0,   label
    nop
    cwbneg %g5, -4,  label
    nop
    cwbvc  %l5, %g5, label
    nop
    cwbvs  %o3, %o7, label
    nop

    ! 64-bit CBCond
    cxbne  %i0, %i1, label
    nop
    cxbe   %o1, -12, label
    nop
    cxbe   %g0, %g0, label
    nop
    cxbe   %g0, 0,   label
    nop
    cxbg   %l7, %g3, label
    nop
    cxble  %g2, %g4, label
    nop
    cxbge  %i3, 3,   label
    nop
    cxbl   %g0, g0,  label
    nop
    cxbgu  %i3, %o6, label
    nop
    cxbleu %l6, %g0, label
    nop
    cxbcc  %i4, %g4, label
    nop
    cxbcs  %i4, %g0, label
    nop
    cxbpos %g0, 0,   label
    nop
    cxbneg %g5, -4,  label
    nop
    cxbvc  %l5, %g5, label
    nop
    cxbvs  %o3, %o7, label
    nop

    call label
    nop

label:
    nop
