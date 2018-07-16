---
layout: default
title: prominent features
---

Capstone offers some unparalleled features in comparison with alternative disassembly frameworks.

#### Multiple architectures

Capstone is one of a very few disassembly frameworks that can support multi-architectures. So far, it can handle 9 architectures: ARM, ARM64 (aka ARMv8/AArch64), M68K, Mips, PowerPC, Sparc, SystemZ, XCore, X86 (including X86_64). More will be added in the future when possible.

#### Updated

As far as we are aware, in all 9 architectures, Capstone can handle more instructions than other frameworks. Especially, it even supports most modern CPU extensions & is guaranteed to remain updated in the future.

#### Clean, simple & intuitive architecture-neutral API

Clean & intuitive is the key principle in designing the API for Capstone. The interface has always been as simple as possible. It would take a new user just few minutes to understand & start writing his own tools based on available samples accompanying Capstone source code.

Even better, the API is independent of the hardwares, so your analysis tools can work in the same way across all the architectures.

#### Detailed instruction information

Capstone breaks down instruction information, making it straightforward to access to instruction operands & other internal instruction data.

This feature is called *decomposer* by some alternatives, but Capstone is the only framework having this across all the architectures, in seamless way.

#### Instruction semantics

Capstone provides some important semantics of the disassembled instruction, such as list of implicit registers read & written, or if this instruction belongs to a group of instructions (such as *ARM Neon* group, or *Intel SSE4.2* group). Now writing your own machine code normalization becomes easier than ever.

#### Zero barrier

Implemented in pure C language, Capstone is easy to be adopted for your low-level tools. Furthermore, lightweight & efficient bindings for popular languages such as *Python*, *Ruby*, *NodeJS*, *C#*, *Java*, *Go*, *Ocaml*, *Perl*, *Pascal*, *Delphi*, *Lua*, *Rust* & *Vala* are also available.

Note that all of our the bindings are all manually coded, since we do not want to rely on bloated SWIG for wrapping.

#### Multiple platforms

With native support for *Windows* & \*nix (confirmed to work on *OSX*, *iOS*, *Android*, *Linux*, \*BSD & *Solaris*), Capstone is available for your tools regardless of the platform.

#### Thread-safe

Thread-safe is the first priority when designing & implementing Capstone. Thanks to this feature, your tools can disassemble binary code in multiple threads without any issue.

#### Embedding into firmware/OS kernel

Capstone is designed to be able to easily embed into firmware & OS kernel. The framework can be built to be minimized, and with some special APIs provided by Capstone, the engine can ben programmed to use in those special environments. Details are available [here](embed.html).

#### Beyond LLVM

Capstone is based on the almighty LLVM compiler framework, but it is not just LLVM: our engine it has [a lot more to offer](beyond_llvm.html).

#### Liberal license

Capstone has been released under the BSD open source license. Thus there is no obligation, except products using Capstone need to redistribute file LICENSE.TXT found the source of Capstone in the same packages.

However, we would be glad to hear from you, so we can link to your products in our [showcases](showcase.html).

