.section ".data"
.align 4

buffer:
.word 0
.word 1
.word 2
.word 3

.section ".text"
.align 4

.register %g2, #scratch
.register %g3, #scratch

.global test
test:
    add %i0, %i1, %i2
    add %g1, %l2, %o3
    add %l7, %i6, %g0
    add %o4, +153, %sp
    add %o4, -279, %sp
    add %o4,   0, %fp
    add %l3,  +7, %g0

    addcc %i0, %i1, %i2
    addcc %g1, %l2, %o3
    addcc %l7, %i6, %g0
    addcc %o4, +153, %sp
    addcc %o4, -279, %sp
    addcc %o4,   0, %fp
    addcc %l3,  +7, %g0

    addc %i0, %i1, %i2
    addc %g1, %l2, %o3
    addc %l7, %i6, %g0
    addc %o4, +153, %sp
    addc %o4, -279, %sp
    addc %o4,   0, %fp
    addc %l3,  +7, %g0

    addccc %i0, %i1, %i2
    addccc %g1, %l2, %o3
    addccc %l7, %i6, %g0
    addccc %o4, +153, %sp
    addccc %o4, -279, %sp
    addccc %o4,   0, %fp
    addccc %l3,  +7, %g0

    and %i0, %i1, %i2
    and %g1, %l2, %o3
    and %l7, %i6, %g0
    and %o4, +153, %sp
    and %o4, -279, %sp
    and %o4,   0, %fp
    and %l3,  +7, %g0

    andn %i0, %i1, %i2
    andn %g1, %l2, %o3
    andn %l7, %i6, %g0
    andn %o4, +153, %sp
    andn %o4, -279, %sp
    andn %o4,   0, %fp
    andn %l3,  +7, %g0

    andcc %i0, %i1, %i2
    andcc %g1, %l2, %o3
    andcc %l7, %i6, %g0		! a.k.a 'btst %l7, %i6'
    andcc %o4, +153, %sp
    andcc %o4, -279, %sp
    andcc %o4,   0, %fp
    andcc %l3,  +7, %g0		! .a.k.a 'btst 0x7, %l3'

    andncc %i0, %i1, %i2
    andncc %g1, %l2, %o3
    andncc %l7, %i6, %g0
    andncc %o4, +153, %sp
    andncc %o4, -279, %sp
    andncc %o4,   0, %fp
    andncc %l3,  +7, %g0

    cas [%i0], %i1, %i2
    cas [%g1], %l2, %o3
    cas [%l7], %i6, %g0
    cas [%o4], %g0, %fp
    casx [%i0], %i1, %i2
    casx [%g1], %l2, %o3
    casx [%l7], %i6, %g0
    casx [%o4], %g0, %fp

    fmovs %f0, %f15
    fmovd %d24, %d38
    fmovq %q40, %q60

    fmovdne %xcc, %d8, %d10

    ld [%i5 + %g4], %f15
    ld [%l2 - 0x58], %f0
    ldd [%i3 + %g0], %d32
    ldd [%l7 + 0x58], %d8
    ldq [%g0 + %i4], %q20
    ldq [%g0 - 0x58], %q60
    ldq [%g2 + %i4], %q20

    lda [%g0 + %l2] 0x82, %f15
    lda [%i5 + %g4] 0x82, %f0
    lda [%l7 + 0x78] %asi, %f31
    lda [%g5 + 0] %asi, %f4
    ldda [%g0 + %l2] 0x82, %d16
    ldda [%i5 + %g4] 0x82, %d0
    ldda [%l7 + 0x78] %asi, %d32
    ldda [%g5 + 0] %asi, %d62
    ldqa [%g0 + %l2] 0x82, %q16
    ldqa [%i5 + %g4] 0x82, %q0
    ldqa [%l7 + 0x78] %asi, %q32
    ldqa [%g5 + 0] %asi, %q60

    ldstub [%i0 + %i1], %i2
    ldstub [%g1 + %l2], %o3
    ldstub [%l7 + %i6], %g0
    ldstub [%o3], %l2
    ldstub [%o4 + 153], %sp
    ldstub [%o4 - 279], %sp
    ldstub [%o4], %fp
    ldstub [%l3 + 7], %g0

    lduba [%g0 + %l2] 0x82, %g1
    lduba [%l3 + %o7] 0x82, %g3
    lduba [%i1 + 0x78] %asi, %l7
    lduba [%g5 + 0] %asi, %i4

    lduha [%g0 + %l2] 0x82, %g1
    lduha [%l3 + %o7] 0x82, %g3
    lduha [%i1 + 0x78] %asi, %l7
    lduha [%g5 + 0] %asi, %i4

    lduwa [%g0 + %l2] 0x82, %g1
    lduwa [%l3 + %o7] 0x82, %g3
    lduwa [%i1 + 0x78] %asi, %l7
    lduwa [%g5 + 0] %asi, %i4

    ldxa [%g0 + %l2] 0x82, %g1
    ldxa [%l3 + %o7] 0x82, %g3
    ldxa [%i1 + 0x78] %asi, %l7
    ldxa [%g5 + 0] %asi, %i4

    membar #StoreStore
    membar #LoadStore
    membar #StoreLoad
    membar #LoadLoad
    membar #Sync
    membar #MemIssue

    or %i0, %i1, %i2
    or %g1, %l2, %o3
    or %l7, %i6, %g0
    or %o4, +153, %sp
    or %o4, -279, %sp
    or %o4,   0, %fp
    or %l3,  +7, %g0

    orn %i0, %i1, %i2
    orn %g1, %l2, %o3
    orn %l7, %i6, %g0
    orn %o4, +153, %sp
    orn %o4, -279, %sp
    orn %o4,   0, %fp
    orn %l3,  +7, %g0

    orcc %i0, %i1, %i2
    orcc %g1, %l2, %o3
    orcc %l7, %i6, %g0
    orcc %o4, +153, %sp
    orcc %o4, -279, %sp
    orcc %o4,   0, %fp
    orcc %l3,  +7, %g0

    orncc %i0, %i1, %i2
    orncc %g1, %l2, %o3
    orncc %l7, %i6, %g0
    orncc %o4, +153, %sp
    orncc %o4, -279, %sp
    orncc %o4,   0, %fp
    orncc %l3,  +7, %g0

    nop

    rd %asi, %l1
    rd %asi, %g0
    rd %ccr, %l2
    rd %ccr, %g0
    rd %fprs, %l3
    rd %fprs, %g0
    rd %pc, %l4
    rd %pc, %g0

    restore %i1, %l1, %o0
    restore %i5, %o2, %o3
    restore %g3, %o1, %i4
    restore %i2, %o5, %g0
    restore %l4, +987, %l4
    restore %l4, -78, %sp
    restore %l3,  +7, %g0
    restore %g0, %g0, %g0

    save %o0, %g0, %o0
    save %i5, %o2, %l3
    save %g3, %o1, %i4
    save %i2, %o5, %g0
    save %l4, +987, %l4
    save %l4, -80, %sp
    save %l3,  +7, %g0
    save %sp, -32, %sp

    sethi %hi(0x2342), %l4
    sethi %hi(0x2342), %g2
    sethi %hi(0x2342), %g0

    sub %i0, %i1, %i2
    sub %g1, %l2, %o3
    sub %l7, %i6, %g0
    sub %o4, +153, %sp
    sub %o4, -279, %sp
    sub %o4,   0, %fp
    sub %l3,  +7, %g0		! a.k.a. 'cmp %l3, 0x7'

    subcc %i0, %i1, %i2
    subcc %g1, %l2, %o3
    subcc %l7, %i6, %g0
    subcc %o4, +153, %sp
    subcc %o4, -279, %sp
    subcc %o4,   0, %fp
    subcc %l3,  +7, %g0

    subc %i0, %i1, %i2
    subc %g1, %l2, %o3
    subc %l7, %i6, %g0
    subc %o4, +153, %sp
    subc %o4, -279, %sp
    subc %o4,   0, %fp
    subc %l3,  +7, %g0

    subccc %i0, %i1, %i2
    subccc %g1, %l2, %o3
    subccc %l7, %i6, %g0
    subccc %o4, +153, %sp
    subccc %o4, -279, %sp
    subccc %o4,   0, %fp
    subccc %l3,  +7, %g0

    stb %g1, [%g0 + %l2]
    stb %g0, [%l3 + %o7]	! a.k.a. 'clrb [%l3 + %o7]'
    stb %l7, [%i1 + 0x78]
    stb %i4, [%g5 + 0]

    sth %g1, [%g0 + %l2]
    sth %g0, [%l3 + %o7]	! a.k.a. 'clrh [%l3 + %o7]'
    sth %l7, [%i1 + 0x78]
    sth %i4, [%g5 + 0]

    stw %g1, [%g0 + %l2]
    stw %g0, [%l3 + %o7]	! a.k.a. 'clr [%l3 + %o7]'
    stw %l7, [%i1 + 0x78]
    stw %i4, [%g5 + 0]

    stx %g1, [%g0 + %l2]
    stx %g0, [%l3 + %o7]	! a.k.a. 'clrx [%l3 + %o7]'
    stx %l7, [%i1 + 0x78]
    stx %i4, [%g5 + 0]

    ! sttw is a new mnemonic for deprecated std
    sttw %g2, [%g0 + %l2]
    sttw %g0, [%l3 + %o7]
    sttw %l6, [%i1 + 0x78]
    sttw %i4, [%g5 + 0]

    ! load/store with various ASI values
    stba %g1, [%g0 + %l2] 0x82
    stba %g0, [%l3 + %o7] 0x82
    stba %l7, [%i1 + 0x78] %asi
    stba %i4, [%g5 + 0] %asi

    stha %g1, [%g0 + %l2] 0x82
    stha %g0, [%l3 + %o7] 0x82
    stha %l7, [%i1 + 0x78] %asi
    stha %i4, [%g5 + 0] %asi

    stwa %g1, [%g0 + %l2] 0x82
    stwa %g0, [%l3 + %o7] 0x82
    stwa %l7, [%i1 + 0x78] %asi
    stwa %i4, [%g5 + 0] %asi

    stxa %g1, [%g0 + %l2] 0x82
    stxa %g0, [%l3 + %o7] 0x82
    stxa %l7, [%i1 + 0x78] %asi
    stxa %i4, [%g5 + 0] %asi

    st %f15, [%i5 + %g4]
    st %f0, [%l2 - 0x58]
    std %d32, [%i3 + %g0]
    std %d8, [%l7 + 0x58]
    stq %q20, [%g0 + %i4]
    stq %q60, [%g0 - 0x58]
    stq %q20, [%g2 + %i4]

    sta %f15, [%g0 + %l2] 0x82
    sta %f0, [%i5 + %g4] 0x82
    sta %f31, [%l7 + 0x78] %asi
    sta %f4, [%g5 + 0] %asi
    stda %d16, [%g0 + %l2] 0x82
    stda %d0, [%i5 + %g4] 0x82
    stda %d32, [%l7 + 0x78] %asi
    stda %d62, [%g5 + 0] %asi
    stqa %q16, [%g0 + %l2] 0x82
    stqa %q0, [%i5 + %g4] 0x82
    stqa %q32, [%l7 + 0x78] %asi
    stqa %q60, [%g5 + 0] %asi

    taddcc %i0, %i1, %i2
    taddcc %g1, %l2, %o3
    taddcc %l7, %i6, %g0
    taddcc %o4, +153, %sp
    taddcc %o4, -279, %sp
    taddcc %o4,   0, %fp
    taddcc %l3,  +7, %g0

    tsubcc %i0, %i1, %i2
    tsubcc %g1, %l2, %o3
    tsubcc %l7, %i6, %g0
    tsubcc %o4, +153, %sp
    tsubcc %o4, -279, %sp
    tsubcc %o4,   0, %fp
    tsubcc %l3,  +7, %g0

    wr %i0, %i1, %asi
    wr %g1, %l2, %asi
    wr %l7, %g0, %asi
    wr %o4, +153, %asi
    wr %o4, -279, %asi
    wr %o4,   0, %asi

    wr %i0, %i1, %ccr
    wr %g1, %l2, %ccr
    wr %l7, %g0, %ccr
    wr %o4, +153, %ccr
    wr %o4, -279, %ccr
    wr %o4,   0, %ccr

    wr %i0, %i1, %fprs
    wr %g1, %l2, %fprs
    wr %l7, %g0, %fprs
    wr %o4, +153, %fprs
    wr %o4, -279, %fprs
    wr %o4,   0, %fprs

    xor %i0, %i1, %i2
    xor %g1, %l2, %o3
    xor %l7, %i6, %g0
    xor %o4, +153, %sp
    xor %o4, -279, %sp
    xor %o4,   0, %fp
    xor %l3,  +7, %g0

    xnor %i0, %i1, %i2
    xnor %g1, %l2, %o3
    xnor %l7, %i6, %g0
    xnor %o4, +153, %sp
    xnor %o4, -279, %sp
    xnor %o4,   0, %fp		! a.k.a 'not %o4, %fp'
    xnor %l3,  +7, %g0

    xorcc %i0, %i1, %i2
    xorcc %g1, %l2, %o3
    xorcc %l7, %i6, %g0
    xorcc %o4, +153, %sp
    xorcc %o4, -279, %sp
    xorcc %o4,   0, %fp
    xorcc %l3,  +7, %g0

    xnorcc %i0, %i1, %i2
    xnorcc %g1, %l2, %o3
    xnorcc %l7, %i6, %g0
    xnorcc %o4, +153, %sp
    xnorcc %o4, -279, %sp
    xnorcc %o4,   0, %fp
    xnorcc %l3,  +7, %g0
