//
// The eXtended Keccak Code Package (XKCP)
// https://github.com/XKCP/XKCP
//
// The Keccak-p permutations, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.
//
// Implementation by Ronny Van Keer, hereby denoted as "the implementer".
//
// For more information, feedback or questions, please refer to the Keccak Team website:
// https://keccak.team/
//
// To the extent possible under law, the implementer has waived all copyright
// and related or neighboring rights to the source code in this file.
// http://creativecommons.org/publicdomain/zero/1.0/
//
// ---
//
// This file implements Keccak-p[1600] in a SnP-compatible way.
// Please refer to SnP-documentation.h for more details.
//
// This implementation comes with KeccakP-1600-SnP.h in the same folder.
// Please refer to LowLevel.build for the exact list of other files it must be combined with.
//

// WARNING: State must be 256 bit (32 bytes) aligned, better is 64-byte aligned (cache line)

// Modification Stephane Leon 8.4.2016 Change syntax for apple syntax (old gas syntax)
// Modification Stephane Leon 12.5.2016 Use the right register for pxor in macro for simd
// Modification Stephane Leon 4.2.2017 Fix absolute addressing problem for 64 bit mode

    .text

// conditional assembly settings
#define InlinePerm 1

// offsets in state
#define _ba  0*8
#define _be  1*8
#define _bi  2*8
#define _bo  3*8
#define _bu  4*8
#define _ga  5*8
#define _ge  6*8
#define _gi  7*8
#define _go  8*8
#define _gu  9*8
#define _ka 10*8
#define _ke 11*8
#define _ki 12*8
#define _ko 13*8
#define _ku 14*8
#define _ma 15*8
#define _me 16*8
#define _mi 17*8
#define _mo 18*8
#define _mu 19*8
#define _sa 20*8
#define _se 21*8
#define _si 22*8
#define _so 23*8
#define _su 24*8

// arguments passed in registers
#define arg1 %rdi
#define arg2 %rsi
#define arg3 %rdx
#define arg4 %rcx
#define arg5 %r8
#define arg6 %r9

// temporary registers
#define rT1  %rax
#define rT1a rT1
#define rT1e %rbx
#define rT1i %r14
#define rT1o %r15
#define rT1u arg6
#define rT2a %r10
#define rT2e %r11
#define rT2i %r12
#define rT2o %r13
#define rT2u arg5

// round vars
#define rpState arg1
#define rpStack %rsp

#define rDa %rbx
#define rDe %rcx
#define rDi %rdx
#define rDo %r8
#define rDu %r9

#define rBa %r10
#define rBe %r11
#define rBi %r12
#define rBo %r13
#define rBu %r14

#define rCa %rsi
#define rCe %rbp
#define rCi rBi
#define rCo rBo
#define rCu %r15

.macro  mKeccakRound    iState, oState, rc, lastRound

    // prepare Theta bis
    movq    rCe, rDa
    rolq    rDa

    movq    _bi(\iState), rCi
    xorq    _gi(\iState), rDi
    xorq    rCu, rDa
    xorq    _ki(\iState), rCi
    xorq    _mi(\iState), rDi
    xorq    rDi, rCi

    movq    rCi, rDe
    rolq    rDe

    movq    _bo(\iState), rCo
    xorq    _go(\iState), rDo
    xorq    rCa, rDe
    xorq    _ko(\iState), rCo
    xorq    _mo(\iState), rDo
    xorq    rDo, rCo

    movq    rCo, rDi
    rolq    rDi

    movq    rCu, rDo
    xorq    rCe, rDi
    rolq    rDo

    movq    rCa, rDu
    xorq    rCi, rDo
    rolq    rDu

    // Theta Rho Pi Chi Iota, result b
    movq    _ba(\iState), rBa
    movq    _ge(\iState), rBe
    xorq    rCo, rDu
    movq    _ki(\iState), rBi
    movq    _mo(\iState), rBo
    movq    _su(\iState), rBu
    xorq    rDe, rBe
    rolq    $44, rBe
    xorq    rDi, rBi
    xorq    rDa, rBa
    rolq    $43, rBi

    movq    rBe, rCa
    movq    $\rc, rT1
    orq     rBi, rCa
    xorq    rBa, rT1
    xorq    rT1, rCa
    movq    rCa, _ba(\oState)

    xorq    rDu, rBu
    rolq    $14, rBu
    movq    rBa, rCu
    andq    rBe, rCu
    xorq    rBu, rCu
    movq    rCu, _bu(\oState)

    xorq    rDo, rBo
    rolq    $21, rBo
    movq    rBo, rT1
    andq    rBu, rT1
    xorq    rBi, rT1
    movq    rT1, _bi(\oState)

    notq    rBi
    orq     rBa, rBu
    orq     rBo, rBi
    xorq    rBo, rBu
    xorq    rBe, rBi
    movq    rBu, _bo(\oState)
    movq    rBi, _be(\oState)
    .if     \lastRound == 0
    movq    rBi, rCe
    .endif

    // Theta Rho Pi Chi, result g
    movq    _gu(\iState), rBe
    xorq    rDu, rBe
    movq    _ka(\iState), rBi
    rolq    $20, rBe
    xorq    rDa, rBi
    rolq    $3,  rBi
    movq    _bo(\iState), rBa
    movq    rBe, rT1
    orq     rBi, rT1
    xorq    rDo, rBa
    movq    _me(\iState), rBo
    movq    _si(\iState), rBu
    rolq    $28, rBa
    xorq    rBa, rT1
    movq    rT1, _ga(\oState)
    .if     \lastRound == 0
    xorq    rT1, rCa
    .endif

    xorq    rDe, rBo
    rolq    $45, rBo
    movq    rBi, rT1
    andq    rBo, rT1
    xorq    rBe, rT1
    movq    rT1, _ge(\oState)
    .if     \lastRound == 0
    xorq    rT1, rCe
    .endif

    xorq    rDi, rBu
    rolq    $61, rBu
    movq    rBu, rT1
    orq     rBa, rT1
    xorq    rBo, rT1
    movq    rT1, _go(\oState)

    andq    rBe, rBa
    xorq    rBu, rBa
    movq    rBa, _gu(\oState)
    notq    rBu
    .if     \lastRound == 0
    xorq    rBa, rCu
    .endif

    orq     rBu, rBo
    xorq    rBi, rBo
    movq    rBo, _gi(\oState)

    // Theta Rho Pi Chi, result k
    movq    _be(\iState), rBa
    movq    _gi(\iState), rBe
    movq    _ko(\iState), rBi
    movq    _mu(\iState), rBo
    movq    _sa(\iState), rBu
    xorq    rDi, rBe
    rolq    $6,  rBe
    xorq    rDo, rBi
    rolq    $25, rBi
    movq    rBe, rT1
    orq     rBi, rT1
    xorq    rDe, rBa
    rolq    $1,  rBa
    xorq    rBa, rT1
    movq    rT1, _ka(\oState)
    .if     \lastRound == 0
    xorq    rT1, rCa
    .endif

    xorq    rDu, rBo
    rolq    $8,  rBo
    movq    rBi, rT1
    andq    rBo, rT1
    xorq    rBe, rT1
    movq    rT1, _ke(\oState)
    .if     \lastRound == 0
    xorq    rT1, rCe
    .endif

    xorq    rDa, rBu
    rolq    $18, rBu
    notq    rBo
    movq    rBo, rT1
    andq    rBu, rT1
    xorq    rBi, rT1
    movq    rT1, _ki(\oState)

    movq    rBu, rT1
    orq     rBa, rT1
    xorq    rBo, rT1
    movq    rT1, _ko(\oState)

    andq    rBe, rBa
    xorq    rBu, rBa
    movq    rBa, _ku(\oState)
    .if     \lastRound == 0
    xorq    rBa, rCu
    .endif

    // Theta Rho Pi Chi, result m
    movq    _ga(\iState), rBe
    xorq    rDa, rBe
    movq    _ke(\iState), rBi
    rolq    $36, rBe
    xorq    rDe, rBi
    movq    _bu(\iState), rBa
    rolq    $10, rBi
    movq    rBe, rT1
    movq    _mi(\iState), rBo
    andq    rBi, rT1
    xorq    rDu, rBa
    movq    _so(\iState), rBu
    rolq    $27, rBa
    xorq    rBa, rT1
    movq    rT1, _ma(\oState)
    .if     \lastRound == 0
    xorq    rT1, rCa
    .endif

    xorq    rDi, rBo
    rolq    $15, rBo
    movq    rBi, rT1
    orq     rBo, rT1
    xorq    rBe, rT1
    movq    rT1, _me(\oState)
    .if     \lastRound == 0
    xorq    rT1, rCe
    .endif

    xorq    rDo, rBu
    rolq    $56, rBu
    notq    rBo
    movq    rBo, rT1
    orq     rBu, rT1
    xorq    rBi, rT1
    movq    rT1, _mi(\oState)

    orq     rBa, rBe
    xorq    rBu, rBe
    movq    rBe, _mu(\oState)

    andq    rBa, rBu
    xorq    rBo, rBu
    movq    rBu, _mo(\oState)
    .if     \lastRound == 0
    xorq    rBe, rCu
    .endif

    // Theta Rho Pi Chi, result s
    movq    _bi(\iState), rBa
    movq    _go(\iState), rBe
    movq    _ku(\iState), rBi
    xorq    rDi, rBa
    movq    _ma(\iState), rBo
    rolq    $62, rBa
    xorq    rDo, rBe
    movq    _se(\iState), rBu
    rolq    $55, rBe

    xorq    rDu, rBi
    movq    rBa, rDu
    xorq    rDe, rBu
    rolq    $2,  rBu
    andq    rBe, rDu
    xorq    rBu, rDu
    movq    rDu, _su(\oState)

    rolq    $39, rBi
    .if     \lastRound == 0
    xorq    rDu, rCu
    .endif
    notq    rBe
    xorq    rDa, rBo
    movq    rBe, rDa
    andq    rBi, rDa
    xorq    rBa, rDa
    movq    rDa, _sa(\oState)
    .if     \lastRound == 0
    xorq    rDa, rCa
    .endif

    rolq    $41, rBo
    movq    rBi, rDe
    orq     rBo, rDe
    xorq    rBe, rDe
    movq    rDe, _se(\oState)
    .if     \lastRound == 0
    xorq    rDe, rCe
    .endif

    movq    rBo, rDi
    movq    rBu, rDo
    andq    rBu, rDi
    orq     rBa, rDo
    xorq    rBi, rDi
    xorq    rBo, rDo
    movq    rDi, _si(\oState)
    movq    rDo, _so(\oState)

    .endm

.macro      mKeccakPermutation12

    subq    $(200), %rsp // 200 = 8*25

    movq    _ba(rpState), rCa
    movq    _be(rpState), rCe
    movq    _bu(rpState), rCu

    xorq    _ga(rpState), rCa
    xorq    _ge(rpState), rCe
    xorq    _gu(rpState), rCu

    xorq    _ka(rpState), rCa
    xorq    _ke(rpState), rCe
    xorq    _ku(rpState), rCu

    xorq    _ma(rpState), rCa
    xorq    _me(rpState), rCe
    xorq    _mu(rpState), rCu

    xorq    _sa(rpState), rCa
    xorq    _se(rpState), rCe
    movq    _si(rpState), rDi
    movq    _so(rpState), rDo
    xorq    _su(rpState), rCu

    mKeccakRound    rpState, rpStack, 0x000000008000808b, 0
    mKeccakRound    rpStack, rpState, 0x800000000000008b, 0
    mKeccakRound    rpState, rpStack, 0x8000000000008089, 0
    mKeccakRound    rpStack, rpState, 0x8000000000008003, 0
    mKeccakRound    rpState, rpStack, 0x8000000000008002, 0
    mKeccakRound    rpStack, rpState, 0x8000000000000080, 0
    mKeccakRound    rpState, rpStack, 0x000000000000800a, 0
    mKeccakRound    rpStack, rpState, 0x800000008000000a, 0
    mKeccakRound    rpState, rpStack, 0x8000000080008081, 0
    mKeccakRound    rpStack, rpState, 0x8000000000008080, 0
    mKeccakRound    rpState, rpStack, 0x0000000080000001, 0
    mKeccakRound    rpStack, rpState, 0x8000000080008008, 1
    addq    $(200), %rsp // 200 = 8*25
    .endm

.macro      mKeccakPermutation24

    subq    $(200), %rsp // 200 = 8*25

    movq    _ba(rpState), rCa
    movq    _be(rpState), rCe
    movq    _bu(rpState), rCu

    xorq    _ga(rpState), rCa
    xorq    _ge(rpState), rCe
    xorq    _gu(rpState), rCu

    xorq    _ka(rpState), rCa
    xorq    _ke(rpState), rCe
    xorq    _ku(rpState), rCu

    xorq    _ma(rpState), rCa
    xorq    _me(rpState), rCe
    xorq    _mu(rpState), rCu

    xorq    _sa(rpState), rCa
    xorq    _se(rpState), rCe
    movq    _si(rpState), rDi
    movq    _so(rpState), rDo
    xorq    _su(rpState), rCu

    mKeccakRound    rpState, rpStack, 0x0000000000000001, 0
    mKeccakRound    rpStack, rpState, 0x0000000000008082, 0
    mKeccakRound    rpState, rpStack, 0x800000000000808a, 0
    mKeccakRound    rpStack, rpState, 0x8000000080008000, 0
    mKeccakRound    rpState, rpStack, 0x000000000000808b, 0
    mKeccakRound    rpStack, rpState, 0x0000000080000001, 0
    mKeccakRound    rpState, rpStack, 0x8000000080008081, 0
    mKeccakRound    rpStack, rpState, 0x8000000000008009, 0
    mKeccakRound    rpState, rpStack, 0x000000000000008a, 0
    mKeccakRound    rpStack, rpState, 0x0000000000000088, 0
    mKeccakRound    rpState, rpStack, 0x0000000080008009, 0
    mKeccakRound    rpStack, rpState, 0x000000008000000a, 0

    mKeccakRound    rpState, rpStack, 0x000000008000808b, 0
    mKeccakRound    rpStack, rpState, 0x800000000000008b, 0
    mKeccakRound    rpState, rpStack, 0x8000000000008089, 0
    mKeccakRound    rpStack, rpState, 0x8000000000008003, 0
    mKeccakRound    rpState, rpStack, 0x8000000000008002, 0
    mKeccakRound    rpStack, rpState, 0x8000000000000080, 0
    mKeccakRound    rpState, rpStack, 0x000000000000800a, 0
    mKeccakRound    rpStack, rpState, 0x800000008000000a, 0
    mKeccakRound    rpState, rpStack, 0x8000000080008081, 0
    mKeccakRound    rpStack, rpState, 0x8000000000008080, 0
    mKeccakRound    rpState, rpStack, 0x0000000080000001, 0
    mKeccakRound    rpStack, rpState, 0x8000000080008008, 1
    addq    $(200), %rsp // 200 = 8*25
    .endm

.macro      mKeccakPermutationInlinable24
    .if     InlinePerm == 1
    mKeccakPermutation24
    .else
    callq   _MIRATH_KeccakP1600_Permute_24rounds
    .endif
    .endm

.macro      mPushRegs
    pushq   %rbx
    pushq   %rbp
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15
    .endm

.macro      mPopRegs
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbp
    popq    %rbx
    .endm

.macro      mXor128 input, output, offset
    movdqu  \offset(\input), %xmm0
    movdqu  \offset(\output), %xmm1
    pxor    %xmm1, %xmm0
    movdqu  %xmm0, \offset(\output)
    .endm

.macro      mXor256 input, output, offset
    movdqu  \offset(\input), %xmm0
    movdqu  \offset(\output), %xmm1
    pxor    %xmm1, %xmm0
    movdqu  %xmm0, \offset(\output)
    movdqu  \offset+16(\input), %xmm0
    movdqu  \offset+16(\output), %xmm1
    pxor    %xmm1, %xmm0
    movdqu  %xmm0, \offset+16(\output)
    .endm

.macro      mXor512 input, output, offset
    movdqu  \offset(\input), %xmm0
    movdqu  \offset(\output), %xmm1
    pxor    %xmm1, %xmm0
    movdqu  %xmm0, \offset(\output)
    movdqu  \offset+16(\input), %xmm0
    movdqu  \offset+16(\output), %xmm1
    pxor    %xmm1, %xmm0
    movdqu  %xmm0, \offset+16(\output)
    movdqu  \offset+32(\input), %xmm0
    movdqu  \offset+32(\output), %xmm1
    pxor    %xmm1, %xmm0
    movdqu  %xmm0, \offset+32(\output)
    movdqu  \offset+48(\input), %xmm0
    movdqu  \offset+48(\output), %xmm1
    pxor    %xmm1, %xmm0
    movdqu  %xmm0, \offset+48(\output)
    .endm

//----------------------------------------------------------------------------
//
// void MIRATH_KeccakP1600_StaticInitialize( void )
//
    .align  8
    .globl _MIRATH_KeccakP1600_StaticInitialize
_MIRATH_KeccakP1600_StaticInitialize:
    retq

//----------------------------------------------------------------------------
//
// void MIRATH_KeccakP1600_Initialize(void *state)
//
    .align  8
    .globl _MIRATH_KeccakP1600_Initialize
_MIRATH_KeccakP1600_Initialize:
    xorq    %rax, %rax
    xorq    %rcx, %rcx
    notq    %rcx
    pxor    %xmm0, %xmm0
    movq    %rax,  _ba(arg1)
    movq    %rcx,  _be(arg1)
    movq    %rcx,  _bi(arg1)
    movq    %rax,  _bo(arg1)
    movdqu  %xmm0, _bu(arg1)
    movdqu  %xmm0, _ge(arg1)
    movq    %rcx,  _go(arg1)
    movq    %rax,  _gu(arg1)
    movdqu  %xmm0, _ka(arg1)
    movq    %rcx,  _ki(arg1)
    movq    %rax,  _ko(arg1)
    movdqu  %xmm0, _ku(arg1)
    movq    %rax,  _me(arg1)
    movq    %rcx,  _mi(arg1)
    movdqu  %xmm0, _mo(arg1)
    movq    %rcx,  _sa(arg1)
    movq    %rax,  _se(arg1)
    movdqu  %xmm0, _si(arg1)
    movq    %rax,  _su(arg1)
    retq

//----------------------------------------------------------------------------
//
// void MIRATH_KeccakP1600_AddByte(void *state, unsigned char data, unsigned int offset)
//
    .align  8
    .globl _MIRATH_KeccakP1600_AddByte
_MIRATH_KeccakP1600_AddByte:
    addq    arg3, arg1
    mov     arg2, %rax
    xorb    %al, (arg1)
    retq

//----------------------------------------------------------------------------
//
// void MIRATH_KeccakP1600_AddBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length)
//
    .align  8
    .globl _MIRATH_KeccakP1600_AddBytes
_MIRATH_KeccakP1600_AddBytes:
    pushq   rT1e
    pushq   rT1i
    pushq   rT1o
    addq    arg3, arg1
    testq   $0xF8, arg4
    jz      MIRATH_KeccakP1600_AddBytes_Bytes
    movq    arg4, arg6
    shrq    $3, arg6
    testq   $16, arg6
    jz      MIRATH_KeccakP1600_AddBytes_8Lanes
    mXor512 arg2, arg1, 0
    mXor512 arg2, arg1, 64
    addq    $128, arg2
    addq    $128, arg1
MIRATH_KeccakP1600_AddBytes_8Lanes:
    testq   $8, arg6
    jz      MIRATH_KeccakP1600_AddBytes_4Lanes
    mXor512 arg2, arg1, 0
    addq    $64, arg2
    addq    $64, arg1
MIRATH_KeccakP1600_AddBytes_4Lanes:
    testq   $4, arg6
    jz      MIRATH_KeccakP1600_AddBytes_2Lanes
    mXor256 arg2, arg1, 0
    addq    $32, arg2
    addq    $32, arg1
MIRATH_KeccakP1600_AddBytes_2Lanes:
    testq   $2, arg6
    jz      MIRATH_KeccakP1600_AddBytes_1Lane
    mXor128 arg2, arg1, 0
    addq    $16, arg2
    addq    $16, arg1
MIRATH_KeccakP1600_AddBytes_1Lane:
    testq   $1, arg6
    jz      MIRATH_KeccakP1600_AddBytes_Bytes
    movq    (arg2), rT1
    xorq    rT1, (arg1)
    addq    $8, arg2
    addq    $8, arg1
MIRATH_KeccakP1600_AddBytes_Bytes:
    andq    $7, arg4
    jz      MIRATH_KeccakP1600_AddBytes_Exit
MIRATH_KeccakP1600_AddBytes_BytesLoop:
    movb    (arg2), %al
    xorb    %al, (arg1)
    addq    $1, arg2
    addq    $1, arg1
    subq    $1, arg4
    jnz     MIRATH_KeccakP1600_AddBytes_BytesLoop
MIRATH_KeccakP1600_AddBytes_Exit:
    popq   rT1o
    popq   rT1i
    popq   rT1e
    retq


KeccakLaneComplementTable:
    .quad   0
    .quad   0xFFFFFFFFFFFFFFFF  //  1 be
    .quad   0xFFFFFFFFFFFFFFFF  //  2 bi
    .quad   0
    .quad   0

    .quad   0
    .quad   0
    .quad   0
    .quad   0xFFFFFFFFFFFFFFFF  //  8 go
    .quad   0

    .quad   0
    .quad   0
    .quad   0xFFFFFFFFFFFFFFFF  // 12 ki
    .quad   0
    .quad   0

    .quad   0
    .quad   0
    .quad   0xFFFFFFFFFFFFFFFF  // 17 mi
    .quad   0
    .quad   0

    .quad   0xFFFFFFFFFFFFFFFF  // 20 sa
    .quad   0
    .quad   0
    .quad   0
    .quad   0

//----------------------------------------------------------------------------
//
// void MIRATH_KeccakP1600_OverwriteBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length)
//
    .align  8
    .globl _MIRATH_KeccakP1600_OverwriteBytes
_MIRATH_KeccakP1600_OverwriteBytes:
    addq    arg3, arg1
    leaq    KeccakLaneComplementTable(%rip), arg5
    addq    arg3, arg5
    subq    $8, arg4
    jc      MIRATH_KeccakP1600_OverwriteBytes_Bytes
MIRATH_KeccakP1600_OverwriteBytes_LanesLoop:
    movq    (arg2), rT1
    xorq    (arg5), rT1
    movq    rT1, (arg1)
    addq    $8, arg2
    addq    $8, arg5
    addq    $8, arg1
    subq    $8, arg4
    jnc     MIRATH_KeccakP1600_OverwriteBytes_LanesLoop
MIRATH_KeccakP1600_OverwriteBytes_Bytes:
    addq    $8, arg4
    jz      MIRATH_KeccakP1600_OverwriteBytes_Exit
MIRATH_KeccakP1600_OverwriteBytes_BytesLoop:
    movb    (arg2), %al
    xorb    (arg5), %al
    movb    %al, (arg1)
    addq    $1, arg2
    addq    $1, arg5
    addq    $1, arg1
    subq    $1, arg4
    jnz     MIRATH_KeccakP1600_OverwriteBytes_BytesLoop
MIRATH_KeccakP1600_OverwriteBytes_Exit:
    retq

//----------------------------------------------------------------------------
//
// void MIRATH_KeccakP1600_OverwriteWithZeroes(void *state, unsigned int byteCount)
//
    .align  8
    .globl _MIRATH_KeccakP1600_OverwriteWithZeroes
_MIRATH_KeccakP1600_OverwriteWithZeroes:
    leaq    KeccakLaneComplementTable(%rip), arg5
    subq    $8, arg2
    jc      MIRATH_KeccakP1600_OverwriteWithZeroes_Bytes
MIRATH_KeccakP1600_OverwriteWithZeroes_LanesLoop:
    movq    $0, rT1
    xorq    (arg5), rT1
    movq    rT1, (arg1)
    addq    $8, arg5
    addq    $8, arg1
    subq    $8, arg2
    jnc     MIRATH_KeccakP1600_OverwriteWithZeroes_LanesLoop
MIRATH_KeccakP1600_OverwriteWithZeroes_Bytes:
    addq    $8, arg2
    jz      MIRATH_KeccakP1600_OverwriteWithZeroes_Exit
MIRATH_KeccakP1600_OverwriteWithZeroes_BytesLoop:
    movb    $0, %al
    xorb    (arg5), %al
    movb    %al, (arg1)
    addq    $1, arg5
    addq    $1, arg1
    subq    $1, arg2
    jnz     MIRATH_KeccakP1600_OverwriteWithZeroes_BytesLoop
MIRATH_KeccakP1600_OverwriteWithZeroes_Exit:
    retq

//----------------------------------------------------------------------------
//
// void MIRATH_KeccakP1600_ExtractBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length)
//
    .align  8
    .globl _MIRATH_KeccakP1600_ExtractBytes
_MIRATH_KeccakP1600_ExtractBytes:
    addq    arg3, arg1
    leaq    KeccakLaneComplementTable(%rip), arg5
    addq    arg3, arg5
    subq    $8, arg4
    jc      MIRATH_KeccakP1600_ExtractBytes_Bytes
MIRATH_KeccakP1600_ExtractBytes_LanesLoop:
    movq    (arg1), rT1
    xorq    (arg5), rT1
    movq    rT1, (arg2)
    addq    $8, arg2
    addq    $8, arg5
    addq    $8, arg1
    subq    $8, arg4
    jnc     MIRATH_KeccakP1600_ExtractBytes_LanesLoop
MIRATH_KeccakP1600_ExtractBytes_Bytes:
    addq    $8, arg4
    jz      MIRATH_KeccakP1600_ExtractBytes_Exit
MIRATH_KeccakP1600_ExtractBytes_BytesLoop:
    movb    (arg1), %al
    xorb    (arg5), %al
    movb    %al, (arg2)
    addq    $1, arg2
    addq    $1, arg5
    addq    $1, arg1
    subq    $1, arg4
    jnz     MIRATH_KeccakP1600_ExtractBytes_BytesLoop
MIRATH_KeccakP1600_ExtractBytes_Exit:
    retq

//----------------------------------------------------------------------------
//
// void MIRATH_MIRATH_KeccakP1600_ExtractAndAddBytes(void *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
//
    .align  8
    .globl _MIRATH_MIRATH_KeccakP1600_ExtractAndAddBytes
_MIRATH_MIRATH_KeccakP1600_ExtractAndAddBytes:
    addq    arg4, arg1
    leaq    KeccakLaneComplementTable(%rip), arg6
    addq    arg4, arg6
    subq    $8, arg5
    jc      MIRATH_MIRATH_KeccakP1600_ExtractAndAddBytes_Bytes
MIRATH_MIRATH_KeccakP1600_ExtractAndAddBytes_LanesLoop:
    movq    (arg1), rT1
    xorq    (arg6), rT1
    xorq    (arg2), rT1
    movq    rT1, (arg3)
    addq    $8, arg2
    addq    $8, arg3
    addq    $8, arg6
    addq    $8, arg1
    subq    $8, arg5
    jnc     MIRATH_MIRATH_KeccakP1600_ExtractAndAddBytes_LanesLoop
MIRATH_MIRATH_KeccakP1600_ExtractAndAddBytes_Bytes:
    addq    $8, arg5
    jz      MIRATH_MIRATH_KeccakP1600_ExtractAndAddBytes_Exit
MIRATH_MIRATH_KeccakP1600_ExtractAndAddBytes_BytesLoop:
    movb    (arg1), %al
    xorb    (arg6), %al
    xorb    (arg2), %al
    movb    %al, (arg3)
    addq    $1, arg2
    addq    $1, arg3
    addq    $1, arg6
    addq    $1, arg1
    subq    $1, arg5
    jnz     MIRATH_MIRATH_KeccakP1600_ExtractAndAddBytes_BytesLoop
MIRATH_MIRATH_KeccakP1600_ExtractAndAddBytes_Exit:
    retq

//----------------------------------------------------------------------------
//
// void MIRATH_KeccakP1600_Permute_Nrounds( void *state, unsigned int nrounds )
//
    .align  8
    .globl _MIRATH_KeccakP1600_Permute_Nrounds
_MIRATH_KeccakP1600_Permute_Nrounds:
    mPushRegs
    subq    $8*25, %rsp
    movq    arg2, rT1

    movq    _ba(rpState), rCa
    movq    _be(rpState), rCe
    movq    _bu(rpState), rCu

    xorq    _ga(rpState), rCa
    xorq    _ge(rpState), rCe
    xorq    _gu(rpState), rCu

    xorq    _ka(rpState), rCa
    xorq    _ke(rpState), rCe
    xorq    _ku(rpState), rCu

    xorq    _ma(rpState), rCa
    xorq    _me(rpState), rCe
    xorq    _mu(rpState), rCu

    xorq    _sa(rpState), rCa
    xorq    _se(rpState), rCe
    movq    _si(rpState), rDi
    movq    _so(rpState), rDo
    xorq    _su(rpState), rCu

    testq    $1, rT1
    jz       MIRATH_KeccakP1600_Permute_Nrounds_Dispatch
    movq    _ba(rpState), rT2a  // copy to stack
    movq    rT2a, _ba(rpStack)
    movq    _be(rpState), rT2a
    movq    rT2a, _be(rpStack)
    movq    _bi(rpState), rT2a
    movq    rT2a, _bi(rpStack)
    movq    _bo(rpState), rT2a
    movq    rT2a, _bo(rpStack)
    movq    _bu(rpState), rT2a
    movq    rT2a, _bu(rpStack)
    movq    _ga(rpState), rT2a
    movq    rT2a, _ga(rpStack)
    movq    _ge(rpState), rT2a
    movq    rT2a, _ge(rpStack)
    movq    _gi(rpState), rT2a
    movq    rT2a, _gi(rpStack)
    movq    _go(rpState), rT2a
    movq    rT2a, _go(rpStack)
    movq    _gu(rpState), rT2a
    movq    rT2a, _gu(rpStack)
    movq    _ka(rpState), rT2a
    movq    rT2a, _ka(rpStack)
    movq    _ke(rpState), rT2a
    movq    rT2a, _ke(rpStack)
    movq    _ki(rpState), rT2a
    movq    rT2a, _ki(rpStack)
    movq    _ko(rpState), rT2a
    movq    rT2a, _ko(rpStack)
    movq    _ku(rpState), rT2a
    movq    rT2a, _ku(rpStack)
    movq    _ma(rpState), rT2a
    movq    rT2a, _ma(rpStack)
    movq    _me(rpState), rT2a
    movq    rT2a, _me(rpStack)
    movq    _mi(rpState), rT2a
    movq    rT2a, _mi(rpStack)
    movq    _mo(rpState), rT2a
    movq    rT2a, _mo(rpStack)
    movq    _mu(rpState), rT2a
    movq    rT2a, _mu(rpStack)
    movq    _sa(rpState), rT2a
    movq    rT2a, _sa(rpStack)
    movq    _se(rpState), rT2a
    movq    rT2a, _se(rpStack)
    movq    _si(rpState), rT2a
    movq    rT2a, _si(rpStack)
    movq    _so(rpState), rT2a
    movq    rT2a, _so(rpStack)
    movq    _su(rpState), rT2a
    movq    rT2a, _su(rpStack)
MIRATH_KeccakP1600_Permute_Nrounds_Dispatch:
    shlq    $3, rT1
    lea MIRATH_KeccakP1600_Permute_NroundsTable(%rip), %rbx
    jmp *-8(%rbx, %rax)

MIRATH_KeccakP1600_Permute_Nrounds24:
    mKeccakRound    rpState, rpStack, 0x0000000000000001, 0
MIRATH_KeccakP1600_Permute_Nrounds23:
    mKeccakRound    rpStack, rpState, 0x0000000000008082, 0
MIRATH_KeccakP1600_Permute_Nrounds22:
    mKeccakRound    rpState, rpStack, 0x800000000000808a, 0
MIRATH_KeccakP1600_Permute_Nrounds21:
    mKeccakRound    rpStack, rpState, 0x8000000080008000, 0
MIRATH_KeccakP1600_Permute_Nrounds20:
    mKeccakRound    rpState, rpStack, 0x000000000000808b, 0
MIRATH_KeccakP1600_Permute_Nrounds19:
    mKeccakRound    rpStack, rpState, 0x0000000080000001, 0
MIRATH_KeccakP1600_Permute_Nrounds18:
    mKeccakRound    rpState, rpStack, 0x8000000080008081, 0
MIRATH_KeccakP1600_Permute_Nrounds17:
    mKeccakRound    rpStack, rpState, 0x8000000000008009, 0
MIRATH_KeccakP1600_Permute_Nrounds16:
    mKeccakRound    rpState, rpStack, 0x000000000000008a, 0
MIRATH_KeccakP1600_Permute_Nrounds15:
    mKeccakRound    rpStack, rpState, 0x0000000000000088, 0
MIRATH_KeccakP1600_Permute_Nrounds14:
    mKeccakRound    rpState, rpStack, 0x0000000080008009, 0
MIRATH_KeccakP1600_Permute_Nrounds13:
    mKeccakRound    rpStack, rpState, 0x000000008000000a, 0
MIRATH_KeccakP1600_Permute_Nrounds12:
    mKeccakRound    rpState, rpStack, 0x000000008000808b, 0
MIRATH_KeccakP1600_Permute_Nrounds11:
    mKeccakRound    rpStack, rpState, 0x800000000000008b, 0
MIRATH_KeccakP1600_Permute_Nrounds10:
    mKeccakRound    rpState, rpStack, 0x8000000000008089, 0
MIRATH_KeccakP1600_Permute_Nrounds9:
    mKeccakRound    rpStack, rpState, 0x8000000000008003, 0
MIRATH_KeccakP1600_Permute_Nrounds8:
    mKeccakRound    rpState, rpStack, 0x8000000000008002, 0
MIRATH_KeccakP1600_Permute_Nrounds7:
    mKeccakRound    rpStack, rpState, 0x8000000000000080, 0
MIRATH_KeccakP1600_Permute_Nrounds6:
    mKeccakRound    rpState, rpStack, 0x000000000000800a, 0
MIRATH_KeccakP1600_Permute_Nrounds5:
    mKeccakRound    rpStack, rpState, 0x800000008000000a, 0
MIRATH_KeccakP1600_Permute_Nrounds4:
    mKeccakRound    rpState, rpStack, 0x8000000080008081, 0
MIRATH_KeccakP1600_Permute_Nrounds3:
    mKeccakRound    rpStack, rpState, 0x8000000000008080, 0
MIRATH_KeccakP1600_Permute_Nrounds2:
    mKeccakRound    rpState, rpStack, 0x0000000080000001, 0
MIRATH_KeccakP1600_Permute_Nrounds1:
    mKeccakRound    rpStack, rpState, 0x8000000080008008, 1
    addq    $8*25, %rsp
    mPopRegs
    retq

MIRATH_KeccakP1600_Permute_NroundsTable:
    .quad   MIRATH_KeccakP1600_Permute_Nrounds1
    .quad   MIRATH_KeccakP1600_Permute_Nrounds2
    .quad   MIRATH_KeccakP1600_Permute_Nrounds3
    .quad   MIRATH_KeccakP1600_Permute_Nrounds4
    .quad   MIRATH_KeccakP1600_Permute_Nrounds5
    .quad   MIRATH_KeccakP1600_Permute_Nrounds6
    .quad   MIRATH_KeccakP1600_Permute_Nrounds7
    .quad   MIRATH_KeccakP1600_Permute_Nrounds8
    .quad   MIRATH_KeccakP1600_Permute_Nrounds9
    .quad   MIRATH_KeccakP1600_Permute_Nrounds10
    .quad   MIRATH_KeccakP1600_Permute_Nrounds11
    .quad   MIRATH_KeccakP1600_Permute_Nrounds12
    .quad   MIRATH_KeccakP1600_Permute_Nrounds13
    .quad   MIRATH_KeccakP1600_Permute_Nrounds14
    .quad   MIRATH_KeccakP1600_Permute_Nrounds15
    .quad   MIRATH_KeccakP1600_Permute_Nrounds16
    .quad   MIRATH_KeccakP1600_Permute_Nrounds17
    .quad   MIRATH_KeccakP1600_Permute_Nrounds18
    .quad   MIRATH_KeccakP1600_Permute_Nrounds19
    .quad   MIRATH_KeccakP1600_Permute_Nrounds20
    .quad   MIRATH_KeccakP1600_Permute_Nrounds21
    .quad   MIRATH_KeccakP1600_Permute_Nrounds22
    .quad   MIRATH_KeccakP1600_Permute_Nrounds23
    .quad   MIRATH_KeccakP1600_Permute_Nrounds24

//----------------------------------------------------------------------------
//
// void MIRATH_KeccakP1600_Permute_12rounds( void *state )
//
    .align  8
    .globl _MIRATH_KeccakP1600_Permute_12rounds
_MIRATH_KeccakP1600_Permute_12rounds:
    mPushRegs
    mKeccakPermutation12
    mPopRegs
    retq

//----------------------------------------------------------------------------
//
// void MIRATH_KeccakP1600_Permute_24rounds( void *state )
//
    .align  8
    .globl _MIRATH_KeccakP1600_Permute_24rounds
_MIRATH_KeccakP1600_Permute_24rounds:
    mPushRegs
    mKeccakPermutation24
    mPopRegs
    retq

//----------------------------------------------------------------------------
//
// size_t MIRATH_KeccakF1600_FastLoop_Absorb( void *state, unsigned int laneCount, unsigned char *data,
//                                     size_t dataByteLen, unsigned char trailingBits )
//
    .align  8
    .globl _MIRATH_KeccakF1600_FastLoop_Absorb
_MIRATH_KeccakF1600_FastLoop_Absorb:
    mPushRegs
    pushq   arg3                        // save initial data pointer
    pushq   arg5                        // save trailingBits
    shrq    $3, arg4                    // nbrLanes = dataByteLen / SnP_laneLengthInBytes
    subq    arg2, arg4                  // if (nbrLanes >= laneCount)
    jc      MIRATH_KeccakF1600_FastLoop_Absorb_Exit
    cmpq    $21, arg2
    jnz     MIRATH_KeccakF1600_FastLoop_Absorb_VariableLaneCountLoop
MIRATH_KeccakF1600_FastLoop_Absorb_Loop21:     // Fixed laneCount = 21 (rate = 1344, capacity = 256)
    movq    _ba(arg3), rT1a
    movq    _be(arg3), rT1e
    movq    _bi(arg3), rT1i
    movq    _bo(arg3), rT1o
    movq    _bu(arg3), rT1u
    movq    _ga(arg3), rT2a
    movq    _ge(arg3), rT2e
    movq    _gi(arg3), rT2i
    movq    _go(arg3), rT2o
    movq    _gu(arg3), rT2u
    xorq    rT1a, _ba(arg1)
    xorq    rT1e, _be(arg1)
    xorq    rT1i, _bi(arg1)
    xorq    rT1o, _bo(arg1)
    xorq    rT1u, _bu(arg1)
    xorq    rT2a, _ga(arg1)
    xorq    rT2e, _ge(arg1)
    xorq    rT2i, _gi(arg1)
    xorq    rT2o, _go(arg1)
    xorq    rT2u, _gu(arg1)
    movq    _ka(arg3), rT1a
    movq    _ke(arg3), rT1e
    movq    _ki(arg3), rT1i
    movq    _ko(arg3), rT1o
    movq    _ku(arg3), rT1u
    movq    _ma(arg3), rT2a
    movq    _me(arg3), rT2e
    movq    _mi(arg3), rT2i
    movq    _mo(arg3), rT2o
    movq    _mu(arg3), rT2u
    xorq    rT1a, _ka(arg1)
    xorq    rT1e, _ke(arg1)
    xorq    rT1i, _ki(arg1)
    xorq    rT1o, _ko(arg1)
    xorq    rT1u, _ku(arg1)
    movq    _sa(arg3), rT1a
    movq    (%rsp), rT1e                // xor trailingBits
    xorq    rT2a, _ma(arg1)
    xorq    rT2e, _me(arg1)
    xorq    rT2i, _mi(arg1)
    addq    $_se, arg3
    xorq    rT2o, _mo(arg1)
    xorq    rT2u, _mu(arg1)
    xorq    rT1a, _sa(arg1)
    xorq    rT1e, _se(arg1)
    pushq   arg3
    pushq   arg4
    mKeccakPermutationInlinable24
    popq    arg4
    popq    arg3
    subq    $21, arg4                   // while (nbrLanes >= 21)
    jnc     MIRATH_KeccakF1600_FastLoop_Absorb_Loop21
MIRATH_KeccakF1600_FastLoop_Absorb_Exit:
    addq    $8, %rsp                    // free trailingBits
    popq    rT1a                        // restore initial data pointer
    subq    rT1a, arg3                  // processed = data pointer - initial data pointer
    movq    arg3, rT1a
    mPopRegs
    retq
MIRATH_KeccakF1600_FastLoop_Absorb_VariableLaneCountLoop:
    pushq   arg4
    pushq   arg2
    pushq   arg1
    movq    arg2, arg4                  // prepare xor call: length (in bytes)
    shlq    $3, arg4
    movq    arg3, arg2                  // data pointer
    xorq    arg3, arg3                  // offset = 0
    callq   _MIRATH_KeccakP1600_AddBytes   //  (void *state, const unsigned char *data, unsigned int offset, unsigned int length)
    movq    arg2, arg3                  // updated data pointer
    movq    24(%rsp), rT1a              // xor trailingBits
    xorq    rT1a, (arg1)
    popq    arg1
    pushq   arg3
    callq   _MIRATH_KeccakP1600_Permute_24rounds
    popq    arg3
    popq    arg2
    popq    arg4
    subq    arg2, arg4                  // while (nbrLanes >= 21)
    jnc     MIRATH_KeccakF1600_FastLoop_Absorb_VariableLaneCountLoop
    jmp     MIRATH_KeccakF1600_FastLoop_Absorb_Exit

