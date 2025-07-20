---
layout: default
title: Download
---

{% for post in site.tags.changelog limit:1 %}

## Download

The current version is **{{ post.title }}**, which was released on <time datetime="{{ post.date | date: "%Y-%m-%d" }}"> {{ post.date | date: "%B %e, %Y" }}</time>.

See the [version history](changelog.html) for a list of changes.

<br>
**NOTE**: Capstone has been released under the **BSD** license. There is no obligation, except that products using Capstone need to redistribute in the same package file LICENSE.TXT found the source of Capstone.

---

### Git repository <img src="img/octocat.jpg" height="32" width="32">

The latest version of the source code can be retrieved at our [Git repository](https://github.com/capstone-engine/capstone).

---

### Package repositories <img src="img/osx.png" height="28" width="28"> <img src="img/ubuntu.png" height="28" width="28"> <img src="img/debian.png" height="28" width="28"> <img src="img/fedora.png" height="28" width="90"> <img src="img/freebsd.png" height="28" width="28"> <img src="img/openbsd.png" height="28" width="28"> <img src="img/netbsd.png" height="28" width="28"> <img src="img/python.png" height="28" width="28">

At the moment Capstone are available for *Mac OSX*, *Ubuntu*, *Debian*, *Fedora Core*, *FreeBSD*, *OpenBSD*, *NetBSD* & *Python* in some package repositories. See [Documentation](documentation.html) for instructions.

---

### Source archive <img src="img/tgz.png" height="28" width="28"> <img src="img/zip.png" height="32" width="32">

<a class="download" href="https://github.com/capstone-engine/capstone/archive/{{ post.title }}.tar.gz" title="Download source (TGZ)">.TGZ</a>

This package contains:

- The complete source code for the Capstone framework.
- Bindings for Java, Python, Ocaml, PowerShell and VB6.
- A collection of example and test programs.

This is the recommended version for all platforms.

<a class="download" href="https://github.com/capstone-engine/capstone/archive/{{ post.title }}.zip" title="Download source (ZIP)">.ZIP</a>

---

### Community bindings <img src="img/binder.png" height="24" width="24"> 

Besides PowerShell, Python, Java & Ocaml get supported in the main code, some bindings for other languages are created and maintained by the community.

- [Gapstone](https://github.com/bnagy/gapstone): Go binding (by Ben Nagy).
- [Crabstone](https://github.com/bnagy/crabstone): Ruby binding (by Ben Nagy).
- [Capstone-Vala](https://github.com/radare/capstone-vala): Vala binding (by Pancake).
- [Capstone.NET](https://github.com/9ee1/Capstone.NET): .NET framework binding (by Ahmed Garhy).
- [Node-Capstone](https://github.com/parasyte/node-capstone): NodeJS binding (by Jason Oster).
- [CCcapstone](https://github.com/zer0mem/cccapstone): C++ binding (by Peter Hlavaty).
- [LuaCapstone](https://github.com/Dax89/LuaCapstone): Lua binding (by Antonio Davide).
- [Capstone-RS](https://github.com/richo/capstone-rs): Rust binding (by Richo Healey).
- [Capstone-Perl](https://github.com/t00sh/capstone-perl): Perl binding (by Tosh).
- [TCapstone](https://github.com/delphilite/CapstoneDelphi): Delphi/Free Pascal binding (by Lsuper).
- [CapstoneJ](https://github.com/kevemueller/capstonej): Java binding (by Keve Müller).
- [Hapstone](https://github.com/ibabushkin/hapstone): Haskell binding (by ibabushkin).
- [Emacs-capstone](https://github.com/collarchoke/emacs-capstone): Emacs (elisp) binding (by Bas Alberts).
- [PHP-capstone](https://github.com/firodj/php-capstone): PHP binding (by Fadhil Mandaga).
- [Common Lisp](https://github.com/jingtaozf/capstone): Common Lisp binding (by Jingtao Xu).
- [Capstone.FSharp](https://github.com/cagyirey/Capstone.FSharp): F# binding (by Cagyirey).
- [Capstone-Clj](https://github.com/williballenthin/reversing-clj/tree/master/capstone-clj): Clojure binding (by Willi Ballenthin).
- [capstone-d](https://github.com/bohlender/capstone-d): D binding (by Dimitri Bohlender).
- [C# binding](https://github.com/mattifestation/capstone) (by Matt Graeber) (*Note: this is only for the older version Capstone 2.0*).

---

### Python module for Windows/MacOS/Linux - Binaries <img src="img/python.png" height="28" width="28"> <img src="img/windows.png" height="28" width="28"> <img src="img/osx.png" height="28" width="28"> <img src="img/linux.png" height="28" width="28"> 

With `pip`, you can easily install Python module for either Windows, MacOS or Linux.

{% highlight bash %}
pip install capstone
{% endhighlight %}

In case you wish to upgrade from older version of Capstone, do:

{% highlight bash %}
pip install capstone --upgrade
{% endhighlight %}

Remember to stick "sudo" in front for root privilege if needed.

---

### Brew package for MacOS - Binaries <img src="img/homebrew.png" height="28" width="28"> <img src="img/osx.png" height="28" width="28">

Install Brew package of Capstone on MacOS with:

{% highlight bash %}
brew install capstone
{% endhighlight %}

In case you wish to upgrade from older version of Capstone, do:

{% highlight bash %}
brew update
brew upgrade capstone
{% endhighlight %}

{% endfor %}

