---
layout: default
title: The Ultimate Disassembly Framework
---

## Welcome

**Capstone** is a lightweight multi-platform, multi-architecture disassembly framework.

Our target is to make Capstone the ultimate disassembly engine for binary analysis and reversing in the security community.

### Highlight features

- Multi-architectures: *Arm*, *Arm64* (*Armv8*), *Ethereum Virtual Machine*, *M68K*, *M680X*, *Mips*, *MOS65XX*, *PowerPC*, *Sparc*, *SystemZ*, *TMS320C64X*, *Web Assembly*, *XCore* & *X86* (include *X86_64*) ([details](arch.html)).

- Clean/simple/lightweight/intuitive architecture-neutral API.

- Provide details on disassembled instruction (called "decomposer" by some others).

- Provide some semantics of the disassembled instruction, such as list of implicit registers read & written.

- Implemented in pure C language, with bindings for *D*, *Clojure*, *F#*, *Common Lisp*, *Visual Basic*, *PHP*, *PowerShell*, *Haskell*, *Perl*, *Python*, *Ruby*, *C#*, *NodeJS*, *Java*, *GO*, *C++*, *OCaml*, *Lua*, *Rust*, *Delphi*, *Free Pascal* & *Vala* available.

- Native support for *Windows* & \*nix (with *Mac OSX*, *iOS*, *Android*, *Linux*, \*BSD & *Solaris* confirmed).

- Thread-safe by design.

- Special support for embedding into firmware or OS kernel.

- High performance & suitable for malware analysis (capable of handling various *X86* malware tricks).

- Distributed under the open source *BSD* license.

<br>
Some of the reasons making Capstone unique are elaborated [here](features.html).

Find in this [Blackhat USA 2014 slides](BHUSA2014-capstone.pdf) more technical details behind our disassembly engine.

### Testimonials

> <i>"Capstone is something people have wanted for years; the value is apparent in the implementation, and it’s nice to finally have an industry standard for this".</i>
> -- George "Geohot" Hotz.

> <i>"Capstone has changed the Reverse Engineering landscape: We finally have a solid, independent, and free disassembler engine".</i>
> -- Felix "FX" Lindner.

> <i>"Capstone will soon be the standard disassembly engine".</i>
> -- Bruce Dang.

> <i>"Capstone solves a well known issue in the reversing community by a well tested and maintained library for most common architectures using a generic API".</i>
> -- Pancake.

> <i>"And, nowadays, Capstone is the best embeddable disassembler out there".</i>
> -- Joxean Koret.

> <i>"I must have mentioned it at least 25 times today with our client. Not sure yet, but this engine might just be the gold standard".</i>
> -- Stephen Ridley.

> <i>"Developers of Capstone provide great support. Its small size and high modularity makes it perfectly working in kernel as well!".</i>
> -- Peter Hlavaty.

> <i>"Love at first sight! Beautiful API, support latest instructions, Capstone truly is the ultimate disassembly framework!".</i>
> -- Ole André Vadla Ravnås.

> <i>"Simply the best - recommended to anyone asking which disassembler to use!".</i>
> -- Jurriaan Bremer.

> <i>"The most complete disassembler library available for the reverse engineering and information security communities".</i>
> -- Pedro "osxreverser" Vilaça.

> <i>"The API is straightforward and easy to work with, and on the few occasions we have run into issues the Capstone developers have provided bug fixes, new features, and support in a matter of hours".</i>
> -- Sean Heelan.

> <i>"I expect Capstone to become the standard, a stepping stone for all projects everywhere".</i>
> -- Ange Albertini.

See complete testimonials for Capstone [here](testimonial.html).

---

<div class="posts">
{% for post in site.tags.news limit:8 %}
<article class="post">

<h2><a href="{{ site.baseurl }}{{ post.url }}">{{ post.title }}</a></h2>

<div class="date">
{{ post.date | date: "%B %e, %Y" }}
</div>

<div class="entry">
{{ post.content }}
</div>
</article>
{% endfor %}
</div>

See the [news archive](news.html) for older posts.

