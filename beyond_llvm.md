---
layout: default
title: Capstone & LLVM
---

## Capstone & LLVM

<br>
Capstone framework is based on the [MC component](http://blog.llvm.org/2010/04/intro-to-llvm-mc-project.html) of the LLVM compiler infrastructure, which among many stuffs has a disassembly engine inside called *MCDisassembler*. LLVM even has a tool named *llvm-mc* that can be used to disassemble input binary.

While Capstone reuses a part of MCDisassembler as its core (with quite a few of changes to adapt to our design), there is a major difference between them. Notably, *Capstone is able to do whatever MCDisassembler can*, but beyond that our engine can do more & do better in many aspects.

<br>
The section below highlights the areas where Capstone shines.

- *llvm-mc* is a tool, not a framework, so unlike Capstone, we cannot specify the address of binary code, number of instructions we want to parse, etc. In return, we cannot get back the number of successfully disassembled instructions, or have detail error reported on failure.

- From inside applications, calling to *llvm-mc* tool to disassemble binary code is possible, but this is extremely expensive due to extra resource needed to launch an external process. Performance overhead would be significantly high too, especially when we need to disassemble multiple code at the same time.

- Given an input binary, *llvm-mc* can only provide a string of disassembly. Meanwhile, Capstone offers a lot more data including (but not limited to) instruction ID, implicit registerers read/written, semantic instruction groups, details on operands and so on. These kind of information is invaluable for advanced binary analysis. Needless to say, Capstone is the only framework (that we are aware of) can do this across all of 5 architectures it supports at the moment (version 2.0).

- Capstone does everything it can to reverse the input code, making life very simple for applications. All application need to do is to tell the engine the architecture & mode of binary code, and Capstone will do the rest. In contrast, with *llvm-mc* we must know in advance what kind of code we are dealing with, which is a dilemma. For example, to disassemble the ARM's *sdiv* instruction, we need to explicitly turn on the *hwdiv-arm* feature like below, otherwise *llvm-mc* would report *invalid encoding error*.

{% highlight bash %}

  echo "0x10 0xf1 0x10 0xe7" | llvm-mc -disassemble -arch=arm -mattr=+hwdiv-arm

{% endhighlight %}

- Internally, MCDisassembler is *not* designed to be thread-safe. This is understandable since there is no need for concurrent processing inside LLVM core, at least regarding disassembling. In contrast, from day 1 Capstone was designed to guarantee applications can safely execute multiple engines at the same time, even with different architectures & modes.

- MCDisassembler is huge in size. In contrast, Capstone is much more compact since we reimplemented all the dependent layers of LLVM to remove unneeded code. Besides, users can even choose which architectures to compile in to tailor the library to their need. Future versions will continue this path by introducing more finer-granularity options to further reduce the binary size.

- MCDisassembler is not designed to be used in restricted environments such as kernel or firmware. In contrast, Capstone has flexibility to restructure itself for these platforms. Coupling with much smaller size, Capstone is practical to be embedded anywhere.

- LLVM is implemented in C++, but Capstone is implemented in pure C, making it much easier to be adopted by low-level tools. A rich list of efficient bindings - 7 languages have been supported in 2.0 -  lowers the barrier even more for every user.

- Malware implement a lot of low-level tricks to fool disassemblers. Because MCDisassembler is built only for the internal usage of LLVM, solid resistance against malware attacks is never be the issue. In contrast, being designed towards reversing & security analysis, this is the top priority for Capstone. At the moment, Capstone can handle quite a lot of tricky *X86* undocumented instructions that are not supported by LLVM.

- Capstone has more optimisation towards disassembling tasks. We even introduced some APIs to support this ([more documentation](http://capstone-engine.org/documentation.html)).

- Capstone can handle some hardware modes that LLVM does not due to some reasons. For example, at the time of this writing (version 2.0), our framework can disassemble *Big-Endian modes* of *Arm* & *Arm64*, but LLVM does not.

- Capstone supports other architectures that do not come from LLVM, such as *M68K*.

<br>
With all that said, LLVM is an awesome project, which Capstone was born from. However, Capstone is not just LLVM, but offering a lot more because it has been designed & implemented especially for disassembling/reversing to answer the demand of security community.
