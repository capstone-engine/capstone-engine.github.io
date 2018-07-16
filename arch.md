---
layout: default
title: Hardware architectures
---

## Supported architectures

At the moment, Capstone can (fully, or partially in some cases) disassemble binary for the following hardware architectures.

#### ARM

- Cortex-A15, Cortex-A5, Cortex-A53, Cortex-A57, Cortex-A8, Cortex-A9, crc, crypto, d16, db, fp-armv8, fp16, hwdiv, mp, nacl-trap, neon, neonfp, perfmon, Cortex-r5, swift, t2dsp, t2xtpk, thumb, thumb2, trustzone, armv4t, armv5t, armv5te, armv6, armv6m, armv6t2, armv7, armv8, vfp2, vfp3, vfp4, virtualization.

#### ARM-64 (aka ARMv8/AArch64)

- crypto, fp-armv8, neon.

#### Mips

- dsp, dspr2, fp64, fpidx, micromips, mips32, mips64, msa, n64, swap.

#### PowerPC

- 32bit, 64bit, altivec, fpcvt, fprnd, popcntd, qpx, stfiwx, vsx.

#### Sparc

- v8, v9, vis, vis2, vis3

#### SystemZ

- generic, z10, z196, zEC12

#### XCore

- generic, xs1b-generic

#### X86 (16-bit, 32-bit & 64-bit)

- 3dnow, 3dnowa, x86_64, adx, aes, atom, avx, avx2, avx512cd, avx512er, avx512f, avx512pf, bmi, bmi2, fma, fma4, fsgsbase, lzcnt, mmx, sgx, sha, slm, sse, sse2, sse3, sse4.1, sse4.2, sse4a, ssse3, tbm, xop.

#### More?

This is not the end, however. We plan to extend the list of supported architectures in the future when possible.
