---
layout: default
title: Arch-selected libraries
---

## Build & programming with arch-selected engine

This documentation introduces how to build Capstone to support selected architectures for more compact libraries.

Later part presents the APIs related to this feature and suggests what programmers need to pay attention in their code.


### 1. Building selected archs for compact engine

Capstone is a multi-arch disassembly framework and by default all 5 architectures (Arm, Arm64, Mips, PowerPC & X86) are compiled, thus supported in the final libraries. But Capstone also lets we choose to only build selected architectures, so we can tailor the library to our need.

The main reason to do this is to have more compact binary to make it easier to embed Capstone into special products and environments (thinking about disassembling from inside OS kernel, or even firmware).

This customization to the library is done at compile time, and very straightforward: All we need to do is to tell *make.sh* which architectures we need.

For example, to compile only *ARM*, *ARM64* & *X86* architectures, do:

{% highlight bash %}
  $ CAPSTONE_ARCHS="arm aarch64 x86" ./make.sh
{% endhighlight %}

The remaining step is to build the libraries and install them with: (demonstration is on \*nix systems)

{% highlight bash %}
$ ./make.sh
$ sudo ./make.sh install
{% endhighlight %}

<br>
Find below the libraries' size for each individual architecture.

| Architecture | Library | Binary size |
| :---: | :--- | :---: |
| Arm | libcapstone.a<br>libcapstone.dylib | 730 KB<br>599 KB |
| Arm64 | libcapstone.a<br>libcapstone.dylib | 519 KB<br>398 KB |
| Mips | libcapstone.a<br>libcapstone.dylib | 206 KB<br>164 KB |
| PowerPC | libcapstone.a<br>libcapstone.dylib | 140 KB<br>103 KB |
| X86 | libcapstone.a<br>libcapstone.dylib | 809 KB<br>728 KB |
| Combine all 5 archs | libcapstone.a<br>libcapstone.dylib | 2.3 MB<br>1.9 MB |

<br>
(Above statistics were collected as of version *2.1-rc1*, built on Mac OSX 10.9.1 with clang-500.2.79)

### 2. Programming with arch-selected engine

Fortunately, when libraries built with selected architectures, Capstone APIs are still functioning in exactly the same way. However, if our program tries to initialize an absent architecture (which was not compiled in), it would fail. When this happens, we can confirm the issue with the API **cs_errno()**, with would return error type **CS_ERR_ARCH** to indicate this arch is unsupported.

Therefore, it is a good idea to always check for the returned value of **cs_open()** to make sure nothing is wrong. Coding this in C will be like below.

{% highlight c %}
csh handle;

if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK) {
	// X86 is supported.
	// ...
} else {
	// X86 was not compiled-in, thus unsupported.
	// cs_errno() should return 'CS_ERR_ARCH' here.
	// ...
}

{% endhighlight %}

<br>
Alternatively, we can always verify if a particular arch is supported with the API **cs_support()**, like below (sample code is again in C).

{% highlight c %}
if (cs_support(CS_ARCH_X86)) {
	// X86 is supported.
	// ...
} else {
	// X86 was not compiled-in, thus unsupported.
	// ...
}
{% endhighlight %}


