---
layout: default
title: Customize instruction mnemonic
---

## Customize instruction mnemonic at run-time

### 1. Setup Capstone to customize mnemonic

In some architectures, an instruction might have alternative mnemonic. Example is the *JNE* instruction on *X86*: this is also called *JNZ* by some disassemblers. The problem is that all the mnemonics are fixed in the engine and cannot be customized. For this reason, some disassembly tools built on top of Capstone have to use some tricks to modify mnemonics at the output for what they desire.

This has been changed with a new option **CS\_OPT\_MNEMONIC** (available in the Github branch [next](https://github.com/capstone-engine/capstone/tree/next) now, and will be ready when version *4.0* is out). Use this option with *cs_option()* to customize instruction mnemonics, as in the sample C code below.

<br>

{% highlight c linenos %}
csh handle;

// Customize mnemonic JNE to "jnz"
cs_opt_mnem my_mnem = { X86_INS_JNE, "jnz" };

if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK) {
    cs_option(handle, CS_OPT_MNEMONIC, (size_t)&my_mnem);
    // from here onwards, disassembling will give JNE a mnemonic "jnz"
    // ...
}
{% endhighlight %}

<br>
Below is the explanation for important lines of the above C sample.

- Line 4: Declare variables *my_mnem* of data type *cs\_opt\_mnem* to customize *JNE* instruction (indicated by *X86\_INS\_JNE*) to have mnemonic *"jnz"*.

- Line 6: Initialize X86 engine of 32-bit mode.

- Line 7: Call *cs_option* with option *CS\_OPT\_MNEMONIC*, and pass the address of *my_mnem* in the third parameter. After this, we can start disassembling and instruction *JNE* will have *"jnz"* mnemonic, rather than the default value *"jne"*.

<br>
The below Python code does the same thing as the above C sample. The only important difference is that we use method *mnemonic_setup()* to customize the menemonic of *JNE* instruction in *line 5*.

{% highlight python linenos %}
from capstone import *
from capstone.x86 import *

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.mnemonic_setup(X86_INS_JNE, "jnz")
{% endhighlight %}

<br>
Finally, note that while the above samples are for X86, the same technique can be applied for all other architectures supported by Capstone. Because we can run *cs\_option(CS\_OPT\_MNEMONIC)* as many times as we want, there is no limitation on the number of instructions we can customize.

---

### 2. Reset Capstone to the default mnemonic

After customizing instruction mnemonic as in section 1 above, we can always reset Capstone to the default mnemonic, as in the sample C code below.

<br>

{% highlight c linenos %}
// Reset instruction JNE to use its default mnemonic
cs_opt_mnem default_mnem = { X86_INS_JNE, NULL };

cs_option(handle, CS_OPT_MNEMONIC, (size_t)&default_mnem);
// from here onwards, our engine will switch back to the default mnemonic "jne" for JNE.
{% endhighlight %}

<br>
Basically, rather than using a string for the mnemonic, we pass the value *NULL* in *line 2* when declaring the *cs\_opt\_mnem* structure.

<br>
The below Python sample does the same thing to reset the engine, which is self explanatory.

{% highlight python linenos %}
md.mnemonic_setup(X86_INS_JNE, None)
{% endhighlight %}

---

### 3. More examples

Find the full samples on how to use *CS\_OPT\_MNEMONIC* in the source of [test_x86.c](https://github.com/capstone-engine/capstone/blob/next/tests/test_customized_mnem.c) or [test_x86.py](https://github.com/capstone-engine/capstone/blob/next/bindings/python/test_customized_mnem.py).

<br>
When running these samples, the output is as follows.

{% highlight text %}
Disassemble X86 code with default instruction mnemonic
75 01		jne	0x1003

Now customize engine to change mnemonic from 'JNE' to 'JNZ'
75 01		jnz	0x1003

Reset engine to use the default mnemonic
75 01		jne	0x1003
{% endhighlight %}

