---
layout: default
title: Version 2.0
---

## Changes from 1.0 to 2.0

After version 2.0 was released to public, we no longer support version 1.0. For this reason, we strongly recommend users to switch to 2.0 ASAP.

This documentation explains how to adapt code written for Capstone version 1.0 to work with API changes made by 2.0. Fortunately, the changes to be made are minimal & trivial: this would take tool authors just few minutes to fix their existent code to upgrade to the new API in 2.0.

Depending on the programming language your tool uses (either C, Python or Java), find the corresponding section below.

---

### C code

- From version 2.0, Capstone no longer generates details for every disassembled instruction by default. Therefore, if you need those details such as implicit registers read/written or information on operands, you must turn it on right after intializing the engine like in the code below.

{% highlight c %}
	csh handle;

	cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // generate details with CS_OPT_ON

{% endhighlight %}

  Afterwards, access to instruction details are done exactly like in version 1.0.

- The APIs **cs_disasm()** & **cs_disasm_dyn()** has been dropped, and users should switch to use the new API *cs_disasm_ex()* (see below).

- New API **cs_disasm_ex()** works exactly like the old *cs_disasm_dyn()*, so you just simply need to rename all code calling *cs_disasm_dyn()* to call *cs_disasm_ex()* instead.

- The API **cs_free()** now accepts one more argument: this second parameter is the number of disassembled instructions returned by *cs_disasm_ex()*. See example below.


{% highlight c %}

	cs_insn *insn;
	size_t count = cs_disasm_dyn(handle, CODE, sizeof(CODE)-1, 0x1000, 0, &insn);
	if (count > 0) {
		// do something with disassembled instructions in insn ...

		// when done, free @insn with @count as second parameter of cs_free()
		cs_free(insn, count);
	}

{% endhighlight %}
---

### Python code

From version 2.0, Capstone no longer generates details for every disassembled instruction by default. Therefore, if you need those details such as implicit registers read/written or information on operands, you must turn it on right after intializing the engine like in the code below.

{% highlight python %}

	md = Cs(CS_ARCH_X86, CS_MODE_32)
	md.detail = True  # generate details by turning detail property to True

{% endhighlight %}

  Afterwards, access to instruction details are done exactly like in version 1.0.

---

### Java code

From version 2.0, Capstone no longer generates details for every disassembled instruction by default. Therefore, if you need those details such as implicit registers read/written or information on operands, you must turn it on right after intializing the engine like in the code below.

{% highlight java %}

	md = capstone.Capstone(Capstone.CS_ARCH_X86, Capstone.CS_MODE_32)
	md.setDetail(true)  // generate details by turning detail property to True

{% endhighlight %}

  Afterwards, access to instruction details are done exactly like in version 1.0.
