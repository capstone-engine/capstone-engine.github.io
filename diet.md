---
layout: default
title: Diet engine
---

## Building & programming with "diet" engine

This documentation introduces how to build Capstone for X86 architecture to minimize the libraries for embedding purpose.

Later part presents the APIs related to this feature and recommends the areas programmers should to pay attention to in their code.


### 1. Building "diet" engine

Typically, we use Capstone for usual applications, where the library weight does not really matter. Indeed, as of version *2.1-RC1*, the whole engine is only 1.9 MB including all architectures, and this size raises no issue to most people.

However, there are cases when we want to embed Capstone into special environments, such as OS kernel driver or firmware, where its size should be as small as possible due to space restriction. While we can always [compile only selected architectures](compile.html) to make the libraries more compact, we still want to slim them down further.

Towards this object, since version *2.1*, Capstone supports *diet* mode, in which some non-critical data are removed, thus making the engine size at least 40% smaller.

By default, Capstone is built in standard mode. To build *diet* engine, do: (demonstration is on \*nix systems)

{% highlight bash %}
$ CAPSTONE_DIET=yes ./make.sh
$ sudo ./make.sh install
{% endhighlight %}

<br>
If we only [build selected architectures](compile.html), the engine is even smaller. Find below the size for each individual architecture compiled in *diet* mode.

| Architecture | Library | Standard binary | "Diet" binary | Reduced size |
| :--: | :-- | :--: | :--: | :--: |
| Arm | libcapstone.a<br>libcapstone.dylib | 730 KB<br>599 KB | 603 KB<br>491 KB | 18%<br>19% |
| Arm64 | libcapstone.a<br>libcapstone.dylib | 519 KB<br>398 KB | 386 KB<br>273 KB | 26%<br>32% |
| Mips | libcapstone.a<br>libcapstone.dylib | 206 KB<br>164 KB | 136 KB<br>95 KB | 34%<br>43% |
| PowerPC | libcapstone.a<br>libcapstone.dylib | 140 KB<br>103 KB | 69 KB<br>50 KB | 51%<br>52% |
| X86 | libcapstone.a<br>libcapstone.dylib | 809 KB<br>728 KB | 486 KB<br>452 KB | 40%<br>38% |
| Combine all archs | libcapstone.a<br>libcapstone.dylib | 2.3 MB<br>1.9 MB | 1.6 MB<br>1.3 MB | 31%<br>32% |
{: .tablelines}

<br>
(Above statistics were collected as of version *2.1-RC1*, built on Mac OSX 10.9.1 with clang-500.2.79)

### 2. Programming with "diet" engine

#### 2.1 Irrelevant data fields with "diet" engine

To significantly reduce the engine size, some internal data has to be sacrificed. Specifically, the following data fields in *cs_insn* struct become irrelevant.

| Data field | Meaning | Replaced with |
| :-- | :-- | :-- |
| @mnemonic | Mnemonic of instruction | @id |
| @op_str | Operand string of instruction | @detail->operands |
| @detail->regs_read<br>@detail->regs_read_count | Registers implicitly read by instruction | No |
| @detail->regs_write<br>@detail->regs_write_count | Registers implicitly written by instruction | No |
| @detail->groups<br>@detail->groups_count | Semantic groups instruction belong to | No |
{: .tablelines}

<br>
While these information is missing, fortunately we can still work out some critical information with the remaining data fields of *cs_insn* struct.

- **@mnemonic**

  Without mnemonic information, we can rely on *@id* field of *cs_insn* struct.

  For example, instruction "*ADD EAX, EBX*" would have @id as *X86_INS_ADD*.

- **@op_str**

  Without operand string, we can still extract equivalent information out of *@detail->operands*, which contains all details about operands of instruction.

  For example, instruction "*ADD EAX, EBX*" would have 2 operands of register type *X86_OP_REG*, with register IDs of *X86_REG_EAX* & *X86_REG_EBX*.


Besides, all the details in architecture-dependent structures such as *cs_arm*, *cs_arm64*, *cs_mips*, *cs_ppc* & *cs_x86* is still there for us to work out all the information needed, even without the missing fields. 

#### 2.2 Irrelevant APIs with "diet" engine

While most Capstone APIs are still function exactly the same, due to these absent data fields, the following APIs become *irrelevant*.

- **cs_reg_name()**
  
  Given a register ID (like X86_REG_EAX), we cannot retrieve its register name anymore.

- **cs_insn_name()**
  
  Given an instruction ID (like X86_INS_SUB), we cannot retrieve its instruction name anymore.

- **cs_insn_group()**

  We no longer have group information, so we cannot check if an instruction belongs to a particular group.

- **cs_reg_read()**

  We no longer have information about registers implicitly read by instructions, so we cannot tell if an instruction read a particular register.

- **cs_write_read()**

  We no longer have information about registers implicitly read by instructions, so we cannot tell if an instruction modify a particular register.

<br>
By *irrelevant*, we mean above APIs would return undefined value. Therefore, programmers have been warned *not to use these APIs* in *diet* mode.

#### 2.3 Checking engine for "diet" status

Capstone allows us to check if the engine was compiled in *diet* mode with **cs_support()** API, as follows - sample code in C.

{% highlight c %}
if (cs_support(CS_SUPPORT_DIET)) {
	// Engine is in "diet" mode.
	// ...
} else {
	// Engine was compiled in standard mode.
	// ...
}
{% endhighlight %}

<br>
With Python, we can either check the *diet* mode via the function **cs_support** of *capstone* module, as follows.

{% highlight python %}
from capstone import *

if cs_support(CS_SUPPORT_DIET):
    # engine is in diet mode
    # ....
else:
    # engine was compiled in standard mode
    # ....
{% endhighlight %}

<br>
Or we can also use the **diet** getter of *Cs* class for the same purpose, as follows.

{% highlight python %}
cs = Cs(CS_ARCH_X86, CS_MODE_64)
if cs.diet:
    # engine is in diet mode
    # ....
else:
    # engine was compiled in standard mode
    # ....
{% endhighlight %}

