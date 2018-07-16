---
layout: default
title: Testimonials
---

## Testimonials

> Capstone has changed the Reverse Engineering landscape: We finally have a solid, independent, and free disassembler engine.
>
> <p style="text-align: right"><i>Felix "FX" Lindner, Recurity-labs.com</i></p>

> Capstone takes LLVM, the standard backend for binary manipulation, and exposes a simple Python API for structured disassembly. Something people have wanted for years; the value is apparent in the implementation, and it's nice to finally have an industry standard for this.
>
> <p style="text-align: right"><i>George "Geohot" Hotz, qira.me</i></p>

> Capstone provides the most advanced API to build a stream-based disassembler. Thanks for the great work!
>
> <p style="text-align: right"><i>Mehdi Talbi, Paul Fariello & Pierre-Sylvain Desse, haka-security.org</i></p>

> Capstone is a solid and easy to use engine; you can start disassembling in seconds, for many different architectures, and really, this is a game-changer!
>
> <p style="text-align: right"><i>Vincent Bénony, hopperapp.com</i></p>

> Capstone is really the ultimate disassembly engine for binary analysis and reversing in the security community. I use Capstone for a lot of projects and it is simply the best.
>
> <p style="text-align: right"><i>David Reguera Garcia aka Dreg, github.com/David-Reguera-Garcia-Dreg</i></p>

> The Capstone API is very clean and well thought-out. I was able to disassemble instructions from data in around one hour from just looking in the header file. The same can't be said about binutils!
>
> <p style="text-align: right"><i>Simon Kågström, Emilpro</i></p>

> We're using Capstone in our analysis engine. Once used to, it makes x86 disassembly a very pleasant and seamless experience!
>
> <p style="text-align: right"><i>Duncan Ogilvie, x64dbg.com</i></p>

> While on the lookout for a disassembler to be used in Senseye, Capstone first seemed like just an interesting choice, but after only a handful of experiments, it turned into the obvious choice; Intuitive to work with, and a clean no-nonsense API -- solid engineering work!
>
> <p style="text-align: right"><i>Björn Ståhl, Reverse Engineer, arcan-fe.com</i></p>

> Capstone is the best disassembly framework that I found. It is very easy to use and so powerful. This engine gives many opportunities to create new tools for reverse engineering.
>
> <p style="text-align: right"><i>Joel, github.com/joelpx/reverse</i></p>

> Capstone API is very handy, and it is evolving rapidly. It was an easy decision to choose it for disassembler for our Android native runtime emulator project.
>
> <p style="text-align: right"><i>Qinglai Xiao, Nokia</i></p>

> So impressed by the speed of @capstone_engine is getting more updates and bug fixes rolled out. A tool to use for life!
>
> <p style="text-align: right"><i>Mohamed Saher (@halsten)</i></p>

> Capstone will soon be the standard disassembly engine.
>
> <p style="text-align: right"><i>Bruce Dang, author of "Practical Reverse Engineering"</i></p>

> Capstone solves a well known issue in the reverse engineering community which is having a well tested and maintained library for disassembling most common architectures using a generic API.
>
> <p style="text-align: right"><i>Pancake, Radare.org</i></p>

> You fall in love with only a few tools. Just added Capstone to my list. I must have mentioned it at least 25 times today with our client. Not sure yet, but this engine might just be the gold standard.
>
Our story: we actually used Capstone recently where Binwalk failed us. Previously I wrote some code to use llvm-mc for this case, but it was very buggy. Essentially sometimes we take firmware dumps from devices. Binwalk and other tools can't identify blobs...we used Capstone to walk through a binary to look for "correct" or "intelligible" code segments. We do disassembly about 256 bytes at a time
in both ARM and THUMB mode walking through the binary on a two byte boundary. Then we have some test cases that we run on all the resultant disassembly. Mostly we used Capstone for gadget hunting but this is a case where it is very invaluable for locating code in firmware dumps.
>
> <p style="text-align: right"><i>Stephen Ridley, Xipiter LLC</i></p>

> And, nowadays, Capstone is the best embeddable disassembler out there.
>
>  <p style="text-align: right"><i>Joxean Koret, Pyew malware analysis tool</i></p>

> At Persistence Labs we've been using Capstone for the past few months
> at the core of one of our program analysis products. The API is
> straightforward and easy to work with, and on the few occasions we have
> run into issues the Capstone developers have provided bug fixes, new features, and support
> in a matter of hours. Overall a super-useful project and one I would
> happily recommend - thanks!
>
> <p style="text-align: right"><i>Sean Heelan, Persistence Labs</i></p>

> Capstone's growing list of supported architectures makes it an obvious choice for any executable analysis application. Its simple API provides detailed information about each instruction. As a bonus, using Capstone saved me from rolling my own x86_64 disassembler! 
>
<p style="text-align: right"><i>Jay Oster, Kodewerx.org</i></p>

> Capstone is a promising disassembly framework. I use Capstone for the ROPgadget project and
others personal stuffs and I am very satisfied. However, it will be awesome if in the future Capstone could offer a semantic of instructions to do some advanced analysis like ROP chain generation based on semantic or symbolic analysis. Anyway, I use and recommend Capstone :).
>
<p style="text-align: right"><i>Jonathan Salwan, Shell-storm.org</i></p>

> I was looking for a disassembly framework for Frida when I discovered Capstone. It was love at first sight, and since then it has made it into the heart of Frida, now even powering its Stalker, a code tracing engine based on dynamic recompilation. By providing a beautiful API and a roaring engine across architectures, with support for the latest instructions, it's clear that Capstone truly is the ultimate disassembly framework. 
>
<p style="text-align: right"><i>Ole André Vadla Ravnås, Frida.re</i></p>

> I really like to use Capstone, because it is an easy to use disassembly
framework with great architecture support. I am excited about the great
support for different languages. For me, it is the best disassembly
framework. 
>
<p style="text-align: right"><i>Sascha Schirra, Scoding.de</i></p>

> I am very happy that the author accepted the challenge to create a modern ARM disassembler library.
It turns out that he went further and created the most complete disassembler library available today.
This has been an excellent contribution to the reverse engineering and information security communities.
Thank you :-)
>
<p style="text-align: right"><i>Pedro "osxreverser" Vilaça, Reverse.put.as</i></p>

> Thanks to capstone-engine, it saved much time for me to coding a disassembler (ARM/Thumb2). Capstone-engine provides a convenient and powerful way to use, which is one of the best options for disassembler. 
>
<p style="text-align: right"><i>Jushun Lee, Security researcher at Alipay System Security Team</i></p>

> While working on Mainframes security along with Matthieu Suiche, I was
thrilled when Capstone offered to maintain SystemZ disassembly support into
Capstone. Not only the disassembly is sound and accurate (being derived
from LLVM's specifications), but it's also fully open source. Best of
all, we could leverage previous work done with Capstone to craft our own
disassembly tools targetting SystemZ. Just plain awesome! A warm thank
to the Capstone community :) 
>
<p style="text-align: right"><i>Jonathan Brossard, Toucan System</i></p>

> Simply the best - recommended to anyone asking which disassembler to use! 
>
<p style="text-align: right"><i>Jurriaan Bremer, Cuckoosandbox.org</i></p>

> The community has always needed a project like Capstone and finally we have one. Kudos! 
>
<p style="text-align: right"><i>Daniel Pistelli, Cerbero.io</i></p>

> Before Capstone Engine I wrote my own x86/x64 disassembler that covered the most common instructions of a PE file entry point. The problem was edge cases, there was always an edge case! With Capstone Engine, all edge cases are covered as it's a full disassembler and I refactored about 500 lines of code! 
>
<p style="text-align: right"><i>Joshua Pitts, Tool: "The Backdoor Factory"</i></p>

> And there is ... Capstone! Cool, lightweight, open-source, LLVM-based dissasembly engine for various architectures (x86, arm and many others!) and available to use in different languages like Python, Go, C++! Its small size and high modularity makes it perfectly working in kernel as well! 
>
> Its community is growing, and developers of Capstone provide great support! Thank you guys for providing great tool!
>
> <p style="text-align: right"><i>Peter Hlavaty (@zer0mem), Security researcher at KEEN Team</i></p>

> Compact, simple, supports many architectures and well maintained. All you will ever need for disassembling!
>
> <p style="text-align: right"><i>deroko, ARTeam</i></p>

> If you haven't tried Capstone disassembler yet, you should definitely check it out right now!
>
<p style="text-align: right"><i>Mario Vilas, Winappdbg.sourceforge.net</i></p>

> It is true that the community did a big step forward when this library went out!
>
> <p style="text-align: right"><i>Emmanuel Fleury, Associate Professor, Université de Bordeaux, France</i></p>

> I'm not sure if Capstone still requires any recommendation at this point. The author did what I couldn't do (when I forked libdasm), and provide
a powerful yet permissive disassembly engine, that I expect to become the standard, a stepping stone for all projects everywhere.
>
> For my own experience, I sent several bug reports about various x86 quirks, which were fixed within a few hours usually.
>
> <p style="text-align: right"><i>Ange Albertini - Reverse engineer, author of Corkami</i></p>

> We definitely need more easy-to-use and well-supported reverse engineering tools like Capstone. Keep up the good work!
>
> <p style="text-align: right"><i>Nicolas RUFF, Google Security Team</i></p>

> Capstone is a solid disassembler for all widely-used architectures, small, nimble, and configurable at compile time for easy embedding. I can see it becoming the standard low-level building block for reverse engineering and binary analysis tools.
>
> <p style="text-align: right"><i>Daniel Godas-Lopez, nonnymous.com</i></p>

> The engine has seen a significant amount of development in that short amount of time and has a good track record of handling some tricky disassembly... Capstone is a useful tool to have in your toolbox.
>
> <p style="text-align: right"><i>Jason Jones, Arbor Networks</i></p>

> Complete, easy to use, multi-arch, cross-platform, open-source and well maintained... an easy choice to make when looking for a disassembler engine!
>
> <p style="text-align: right"><i>Karl Vogel, Inuits.eu</i></p>

> After trying a few open disassembly frameworks, I found that Capstone could bring me the most interesting benefits of the LLVM MC architecture (very detailed information about instructions) with a no-nonsense API oriented towards disassembling rather than compiling.
>
> <p style="text-align: right"><i>Félix Cloutier, security enthusiast</i></p>

> Capstone makes it seem like there was no disassembly library before it. It's incredibly simple to use!
>
> <p style="text-align: right"><i>Amat Cama, UCSB/Virtual Security Research</i></p>

> Capstone's ease of use and architecture support make it a great
choice for any binary analysis tool. I've been using it for a few months now
and I am very satisfied with the project. It will definitely become the
standard disassembly framework. Highly recommended!
>
> <p style="text-align: right"><i>Christian Heitman, Security researcher at Programa STIC</i></p>

