---
layout: default
title: Programming with Python language
---

## Python tutorial for Capstone

### 1. Basic sample

Capstone has a very simple API, so it is very easy to write tools using the framework. To start, the below code disassembles some X86 binary, and prints out its assembly.

{% highlight python linenos %}
# test1.py
from capstone import *

CODE = b"\x55\x48\x8b\x05\xb8\x13\x00\x00"

md = Cs(CS_ARCH_X86, CS_MODE_64)
for i in md.disasm(CODE, 0x1000):
    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
{% endhighlight %}

<br>
Readers can download the code from [here](/samples/test1.py). Output of this sample is like below:

{% highlight bash %}
$ python test1.py

0x1000:	push	rbp
0x1001:	mov	rax, qword ptr [rip + 0x13b8]

{% endhighlight %}

<br>
The Python sample is intuitive, right? But just in case, readers can find below the explanation for each line of *test1.py*.

- Line 2: Import Python module **capstone** before we do anything.

- Line 4: Raw binary code we want to disassemble. The code in this sample is in hex mode.

- Line 6: Initialize Python class for Capstone with class **Cs**. We need to give this class two arguments: the hardware architecture & the hardware mode. In this sample, we want to disassemble 64-bit code for X86 architecture.

- Line 7: Disassemble the binary code with method **disasm()** of the class *Cs* class instance we created above. The second argument of *disasm* is the address of the first instruction, which is *0x1000* in this case. By default, *disasm* disassembles all the code until either there is no more code, or it encounters a broken instruction. In return, *disasm* gives back a list of instructions of the class type **CsInsn**, and the *for* loop here iterates this list.

- Line 8: Print out some internal information about this instruction. Class *CsInsn* exposes all the internal information about the disassembled instruction that we want to access to. Some of the most used fields of this class are presented below.

![fields](/img/capstone-fields.png)

---

### 2. Faster-simpler API for basic information

Example in section 1 uses *disasm()* method to retrieve *CsInsn* objects. This offers full information available for disassembled instructions. However, if all we want is just basic data such as *address*, *size*, *mnemonic* & *op_str*, we can use a lighter API *disasm_lite()*.

From version *2.1*, Python binding provides this new method *disasm_lite()* in *Cs* class. Unlike *disasm()*, *disasm_lite()* just returns tuples of (*address*, *size*, *mnemonic*, *op_str*). Benchmarks show that this light API is up to *30% faster* than its counterpart.

Below is an example of *disasm_lite()*, which is self-explanatory.

{% highlight python %}
from capstone import *

CODE = b"\x55\x48\x8b\x05\xb8\x13\x00\x00"

md = Cs(CS_ARCH_X86, CS_MODE_64)
for (address, size, mnemonic, op_str) in md.disasm_lite(CODE, 0x1000):
	print("0x%x:\t%s\t%s" %(address, mnemonic, op_str))
{% endhighlight %}

---

### 3. Architectures and modes

At the moment, Capstone supports 8 hardware architectures with corresponding hardware modes, as follows.

<br>

![archs](/img/capstone-archs.png)

<br>
Besides, there are few modes to be combined with basic modes above.

![modes](/img/capstone-modes.png)

<br>
The way to combine extra modes with basic modes is to use the operand `` + ``. For example, the code below disassembles some Mips64 code in *little endian* mode.

{% highlight python %}
from capstone import *

CODE = b"\x56\x34\x21\x34\xc2\x17\x01\x00"

md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN)
for i in md.disasm(CODE, 0x1000):
	print("%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

{% endhighlight %}

---

### 4. More architecture-independent data for disassembled instructions

By default, Capstone do not generate details for disassembled instruction. If we want information such as implicit registers read/written or semantic groups that this instruction belongs to, we need to explicitly turn this option *on*, like in the sample code below.

{% highlight python %}

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

{% endhighlight %}

However, keep in mind that producing details costs more memory, complicates the internal operations and slows down the engine a bit, so only do that if needed. If this is no longer desired, we can always reset the engine back to default state at run-time with similar method.

{% highlight python %}

md.detail = False

{% endhighlight %}

Details produced by Capstone provides access to a lot more internal data of the disassembled instruction than the fields introduced in the last sections. Note that these data are all architecture-independent.

The sample below shows how to extract out details on implicit registers being read by instructions, as well as all the semantic groups this instruction belongs to in some ARM binary.


{% highlight python linenos %}
from capstone import *
from capstone.arm import *

CODE = b"\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3"

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md.detail = True

for i in md.disasm(CODE, 0x1000):
    if i.id in (ARM_INS_BL, ARM_INS_CMP):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

        if len(i.regs_read) > 0:
            print("\tImplicit registers read: "),
            for r in i.regs_read:
                print("%s " %i.reg_name(r)),
            print

        if len(i.groups) > 0:
            print("\tThis instruction belongs to groups:"),
            for g in i.groups:
                print("%u" %g),
            print
{% endhighlight %}

<br>
Readers might already figure out how the code above work, as it is simple enough:

- Line 2: Import *arm* module, since we want to work with ARM architecture here.

- Line 6 ~ 7: Initialize engine with Arm mode for Arm architecture, then turn on detail feature.

- Line 9: Disassemble the Arm binary, then iterate the disassembled instructions.

- Line 10: In this example, we only care about some instructions, which is *bl* & *cmp*, and ignore everything else. All the constant numbers can be found in file **arm_const.py** in the source of Python binding.

- Line 13: Check if this instruction *implicitly* reads any registers. If so, print out all register names

- Line 16: While we can simply print out the register ID (which has *int* type), it is more friendly to print out register name instead. This can be done with method **reg_name()**, which receives the register ID as its only argument.

- Line 19: Check if this instruction belongs to any semantic group. If so, print out all group ID.

- Line 21 ~ 22: Print out all the group IDs in a loop.

<br>
The output of the above sample is like below.

{% highlight objdump %}

0x1000:	bl	#0x104c
		Implicit registers read:  pc
		This instruction belongs to groups: 20
0x101c:	cmp	r3, #0
		This instruction belongs to groups: 20

{% endhighlight %}

---

### 5. Architecture-dependent details

When detail option is on, *CsInsn* provides a field named **operands**, which is a list of all operands of the instruction. Unlike the fields presented in section 4 above, this field is different for each architecture.

The sample below shows how to extract the details on instruction operands of ARM64 code.

{% highlight python linenos %}
from capstone import *
from capstone.arm64 import *

CODE = b"\xe1\x0b\x40\xb9\x20\x04\x81\xda\x20\x08\x02\x8b"

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

for insn in md.disasm(CODE, 0x38):
    print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))

    if len(insn.operands) > 0:
        print("\tNumber of operands: %u" %len(insn.operands))
        c = -1
        for i in insn.operands:
            c += 1
            if i.type == ARM64_OP_REG:
                print("\t\toperands[%u].type: REG = %s" %(c, insn.reg_name(i.value.reg)))
            if i.type == ARM64_OP_IMM:
                print("\t\toperands[%u].type: IMM = 0x%x" %(c, i.value.imm))
            if i.type == ARM64_OP_CIMM:
                print("\t\toperands[%u].type: C-IMM = %u" %(c, i.value.imm))
            if i.type == ARM64_OP_FP:
                print("\t\toperands[%u].type: FP = %f" %(c, i.value.fp))
            if i.type == ARM64_OP_MEM:
                print("\t\toperands[%u].type: MEM" %c)
                if i.value.mem.base != 0:
                    print("\t\t\toperands[%u].mem.base: REG = %s" \
                        %(c, insn.reg_name(i.value.mem.base)))
                if i.value.mem.index != 0:
                    print("\t\t\toperands[%u].mem.index: REG = %s" \
                        %(c, insn.reg_name(i.value.mem.index)))
                if i.value.mem.disp != 0:
                    print("\t\t\toperands[%u].mem.disp: 0x%x" \
                        %(c, i.value.mem.disp))

            if i.shift.type != ARM64_SFT_INVALID and i.shift.value:
	            print("\t\t\tShift: type = %u, value = %u" \
                    %(i.shift.type, i.shift.value))

            if i.ext != ARM64_EXT_INVALID:
	            print("\t\t\tExt: %u" %i.ext)

    if insn.writeback:
        print("\tWrite-back: True")
    if not insn.cc in [ARM64_CC_AL, ARM64_CC_INVALID]:
        print("\tCode condition: %u" %insn.cc)
    if insn.update_flags:
        print("\tUpdate-flags: True")

{% endhighlight %}

<br>
The code looks a bit complicated, but actually pretty simple:

- Line 12: Check if this instruction has any operands to print out.

- Line 17 ~ 18: If this operand is register (reflected by type *ARM64_OP_REG*), then print out its register name.

- Line 19 ~ 20: If this operand is immediate (reflected by type *ARM64_OP_IMM*), then print out its numerical value.

- Line 21 ~ 22: If this operand is of type C-IMM (coprocessor register type, reflected by *ARM64_OP_CIMM*), then print out its index value.

- Line 23 ~ 24: If this operand is real number (reflected by type *ARM64_OP_FP*), then print out its numerical value.

- Line 25 ~ 35: If this operand is memory reference  (reflected by type *ARM64_OP_MEM*), then print out its base/index registers, together with offset value.

- Line 37 ~ 42: If this operand uses shift or extender, print out their value.

- Line 44 ~ 45: If this instruction writes back its value afterwards, print out that.

- Line 46 ~ 47: Print out the code condition of this instruction.

- Line 48 ~ 49: If this instruction update flags, print out that.

<br>
The output of the above sample is like below.

{% highlight objdump %}
0x38:	ldr	w1, [sp, #8]
	Number of operands: 2
		operands[0].type: REG = w1
		operands[1].type: MEM
			operands[1].mem.base: REG = sp
			operands[1].mem.disp: 0x8

0x3c:	csneg	x0, x1, x1, eq
	Number of operands: 3
		operands[0].type: REG = x0
		operands[1].type: REG = x1
		operands[2].type: REG = x1
	Code condition: 1

0x40:	add	x0, x1, x2, lsl #2
	Number of operands: 3
		operands[0].type: REG = x0
		operands[1].type: REG = x1
		operands[2].type: REG = x2
			Shift: type = 1, value = 2
{% endhighlight %}

---

### 6. Run-time options

Besides the *detail* option previously introduced in section 4, Capstone can customize the engine at run-time, allowing us to set the assembly syntax or dynamically change engine's mode.

#### 6.1 Syntax option

By default, X86 assembly outputs in Intel syntax. To switch to AT&T syntax instead, we can simply set syntax option like below.

{% highlight python %}

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.syntax = CS_OPT_SYNTAX_ATT

{% endhighlight %}

<br>
In case we want to return to Intel syntax, we can reset the syntax in the similar way:

{% highlight python %}

md.syntax = CS_OPT_SYNTAX_INTEL

{% endhighlight %}

#### 6.2 Dynamically change disassemble mode at run-time

From version 2.0, we can dynamically change the engine's mode at run-time thanks to a new option **mode**.
    
This is useful for example with Arm, where we might frequently switch between Arm & Thumb modes without having to create a new engine. This also happens with X86, where we might want to switch back and forth between protected-mode & real-mode code.

Below sample shows how to switch back and forth between Arm & Thumb modes at run-time.

{% highlight python %}

md = Cs(CS_ARCH_ARM, CS_MODE_ARM) # dynamically switch to Arm mode
# from now on disassemble Arm code ....

md.mode = CS_MODE_THUMB # dynamically change to Thumb mode
# from now on disassemble Thumb code ....

md.mode = CS_MODE_ARM # change back to Arm mode again
# from now on disassemble Arm code ....

{% endhighlight %}


---

### 7. Diet engine

From version 2.1, Capstone supports "diet" compilation option to minimize the engine for embedded purpose. The *diet* engine no longer updates some data fields of the *CsInsn* class, so these fields & some related APIs become irrelevant. See [this documentation](diet.html) for further information.

---

### 8. More examples

This tutorial does not explain all the API of Capstone yet. Please find more advanced examples in source of *test_\*.py* files under Python binding directory [bindings/python](https://github.com/aquynh/capstone/tree/master/bindings/python) in the Capstone source code.

