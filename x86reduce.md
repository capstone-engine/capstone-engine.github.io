---
layout: default
title: X86-reduce engine
---

## Building X86-reduce engine

(Note: at the moment, this *X86-reduce* option is only availabe in the [next branch](https://github.com/capstone-engine/capstone/tree/next) of our Github repo. It will be integrated into the next release of Capstone)

This documentation introduces how to build the X86 engine of Capstone to be as small as *200KB* - about *60% smaller* than the [diet engine](diet.html) - for embedding purpose.

Later part presents the APIs related to this reduced mode.


### 1. Building a small engine

Typically, we use Capstone for usual applications, where the library weight does not really matter. Indeed, as of version *2.1-RC1*, the whole engine is only 1.9 MB including all architectures, and this size raises no issue to most people.

However, to embed Capstone into special enviroments, such as OS kernel driver or firmware, the engine size should be as small as possible due to space restriction. To achieve this object, we must compile Capstone using special methods.

To build a tiny engine, consult three documentations below.

- [Build only selected architectures to suite your need](compile.html).

- [Build diet engine](diet.html).

- [Build embedded engine for firmware/OS kernel](embed.html)


For X86 architecture, after applying all of the above techniques, the binary size of Capstone reduces to around 486KB. If you still desire a smaller engine, Capstone has another *compile time option* called **X86-reduce**.

### 2. Building X86-reduce engine

To reduce the X86 engine even futher, compile Capstone in *X86-reduce* mode to remove some exotic non-critical X86 instruction sets. As a result, this downsizes the engine by *around 60%*, to under *200KB*.

Below is the list of instruction sets removed by this option:

- Floating Point Unit (FPU)

- MultiMedia eXtension (MMX)

- Streaming SIMD Extensions (SSE)

- 3DNow

- Advanced Vector Extensions (AVX)

- Fused Multiply Add Operations (FMA)

- eXtended Operations (XOP)

- Transactional Synchronization Extensions (TSX)

<br>
Obviously, the price to pay for this tiny size is that the engine can no longer understand the removed instructions. But in special environments such as OS kernel, where these instructions are never used, this is acceptable.

By default, Capstone for X86 is built with complete instructions. To build and install the *X86-reduce* engine, do: (demonstration is on \*nix systems)

{% highlight bash %}
$ CAPSTONE_X86_REDUCE=yes ./make.sh
$ sudo ./make.sh install
{% endhighlight %}


### 3. Checking X86 engine for "reduce" status

Capstone allows us to check if the engine was compiled in *X86-reduce* mode with **cs_support()** API, as follows - sample code in C.

{% highlight c %}
if (cs_support(CS_SUPPORT_X86_REDUCE)) {
	// Engine is in X86-reduce mode.
	// ...
} else {
	// Engine was compiled with complete instructions.
	// ...
}
{% endhighlight %}

<br>
With Python, we can either check the *X86-reduce* mode via the function **cs_support** of *capstone* module, as follows.

{% highlight python %}
from capstone import *

if cs_support(CS_SUPPORT_X86_REDUCE):
    # engine is in X86-reduce mode
    # ....
else:
    # engine was compiled with complete instructions.
    # ....
{% endhighlight %}

<br>
Or we can also use the **x86_reduce** getter of *Cs* class for the same purpose, as follows.

{% highlight python %}
cs = Cs(CS_ARCH_X86, CS_MODE_64)
if cs.x86_reduce:
    # engine is in X86-reduce mode
    # ....
else:
    # engine was compiled in standard mode
    # ....
{% endhighlight %}

