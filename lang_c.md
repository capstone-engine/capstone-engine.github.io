---
layout: default
title: Programming with C language
---

## C tutorial for Capstone

### Example code

This short example shows how the Capstone API looks and how easy it is to disassemble binary code with it. There are more APIs than those used here, but these are all we need to get started.

{% highlight c linenos %}
/* test1.c */

#include <stdio.h>
#include <inttypes.h>

#include <capstone/capstone.h>

#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

int main(void)
{
	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;
	count = cs_disasm(handle, CODE, sizeof(CODE)-1, 0x1000, 0, &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
					insn[j].op_str);
		}

		cs_free(insn, count);
	} else
		printf("ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);

    return 0;
}
{% endhighlight %}

<br>
To compile this file, we need a Makefile like below.

{% highlight makefile %}
# capstone library name (without prefix 'lib' and suffix '.so')
LIBNAME = capstone

test1: test1.o
	${CC} $< -O3 -Wall -l$(LIBNAME) -o $@

%.o: %.c
	${CC} -c $< -o $@
{% endhighlight %}


<br>
Readers can get this sample code in a zip file [here](/samples/test1.tgz). Compile and run it as follows.

{% highlight bash %}

$ make
cc -c test1.c -o test1.o
cc test1.o -O3 -Wall -lcapstone -o test1

$ ./test1
0x1000:	push		rbp
0x1001:	mov		rax, qword ptr [rip + 0x13b8]
{% endhighlight %}

<br>
The C sample is intuitive, but just in case, readers can find below the explanation for each line of *test1.c*.

- Line 6: Include header file **capstone.h** before we do anything.

- Line 8: Raw binary code we want to disassemble. The code in this sample is in hex mode.

- Line 12: Declare a handle variable of the type **csh**. This handle will be used at every API of Capstone.

- Line 13: Declare *insn*, a pointer variable of the type **cs_insn**, which points to a memory containing all disassembled instructions.

- Line 16: Initialize Capstone with function **cs_open()**. This API accepts 3 arguments: the hardware architecture, hardware mode and pointer to handle. In this sample, we want to disassemble 64-bit code for X86 architecture. In return, we have the handle updated in variable *handle*. This API can fail in extreme cases, so our sample verifies the returned result against the error code *CS_ERR_OK*.

- Line 18: Disassemble the binary code using the API **cs_disasm()** with the handle we got from the *cs_open()*. The 2nd & 3rd arguments of *cs_disasm()* is the binary code to be disassembled and its length. The 4th argument is the address of the first instruction, which is *0x1000* in this case. If we want to disassemble all the code until either there is no more code, or it encounters a broken instruction, use *0* as the next argument. In return, this API gives back a dynamically allocated memory in the last argument *insn*, which can be used to extract out all the disassembled instructions in the next steps. The result of *cs_disasm()* is the number of instructions successfully disassembled.

- Line 19: Check if we really have some disassembled instructions at the output of *cs_disasm()*

- Line 21 ~ 24: Print out all disassembled instructions with their addresses, mnemonics and operands. The structure **cs_insn** exposes all the internal information about the disassembled instruction we are looking at. Some of the most used fields of this structure are presented below.

![fields](/img/capstone-fields.png)

- Line 26: Free dynamic memory allocated by *cs_disasm()* with the API **cs_free()**. The 2nd argument passed to *cs_free()* is the number of disassembled instructions returned by *cs_disasm()* in line 18.

- Line 30: Close the handle when we are done with the API **cs_close()**.

---

### 2. Architectures and modes

At the moment, Capstone supports 8 hardware architectures with corresponding hardware modes, as follows.

![archs](/img/capstone-archs.png)

Besides, depending on cases, there are few more modes to be combined with basic modes above.

![modes](/img/capstone-modes.png)

The way to combine extra modes with basic modes is to use the operand `` + ``. For example, the sample below initializes Capstone for Mips64 in *little endian* mode.

{% highlight c %}
cs_open(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN, &handle);
{% endhighlight %}

---

### 3. More architecture-independent internal data of the disassembled instruction

By default, Capstone do not generate details for disassembled instruction. If we want information such as implicit registers read/written or semantic groups that this instruction belongs to, we need to explicitly turn this option *on*, like in the sample code below.

{% highlight c %}
csh handle;

cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // turn ON detail feature with CS_OPT_ON

{% endhighlight %}

<br>
However, keep in mind that producing details costs more memory, complicates the internal operations and slows down the engine a bit, so only do that if needed. If this is no longer desired, we can always reset the engine back to default state at run-time with similar method.

{% highlight c %}

cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);	// no longer generate details

{% endhighlight %}

<br>
Details produced by Capstone provides access to a lot more internal data of the disassembled instruction than the fields introduced in the last sections. Note that these data are all architecture-independent.

The sample below shows how to extract out details on implicit registers being read by instructions, as well as all the semantic groups this instruction belongs to in some ARM binary.


{% highlight c linenos %}
count = cs_disasm(handle, CODE, sizeof(CODE)-1, 0x1000, 0, &all_insn);
if (count > 0) {
	size_t j;
	int n;
	for (j = 0; j < count; j++) {
		cs_insn *i = &(all_insn[j]);
		if (i->id != ARM_INS_BL && i->id != ARM_INS_CMP)
			continue;
		printf("0x%"PRIx64":\t%s\t\t%s // insn-mnem: %s\n",
				i->address, i->mnemonic, i->op_str,
				cs_insn_name(handle, i->id));

		cs_detail *detail = i->detail;
		if (detail->regs_read_count > 0) {
			printf("\tImplicit registers read: ");
			for (n = 0; n < detail->regs_read_count; n++) {
				printf("%s ", cs_reg_name(handle, detail->regs_read[n]));
			}
			printf("\n");
		}

		if (detail->groups_count > 0) {
			printf("\tThis instruction belongs to groups: ");
			for (n = 0; n < detail->groups_count; n++) {
				printf("%u ", detail->groups[n]);
			}
			printf("\n");
		}
	}
}

{% endhighlight %}

<br>
Readers might already figure out how the code above work, as it is simple enough:

- Line 6: type-cast inspected instruction to variable *i* for simplicity.

- Line 7: In this example, we only care about some instructions, which is either *bl* or *cmp*, and ignore everything else. All the constant numbers can be found in file **arm.h** in the same directory of the header file *capstone.h*.

- Line 13: Type-cast detail information (of data type **cs_detail**) to a variable named *detail* for brevity.

- Line 14: Check if this instruction *implicitly* reads any registers. If so, next block prints out all these register names.

- Line 17: While we can simply print out the register ID (which has data type *int*), it is more friendly to print out its register name instead. This can be done with the API **cs_reg_name()**, which accepts the register ID as its 2nd argument.

- Line 22 ~ 26: Check if this instruction belongs to any semantic group. If so, print out all group ID. Similarly, we can find all the group ID in the header file *arm.h*.

<br>
The output of the above sample is like below.

{% highlight objdump %}

0x1000:	bl	#0x104c			// insn-name: BL
		Implicit registers read:  pc
		This instruction belongs to groups: 20
0x101c:	cmp	r3, #0			// insn-name: CMP
		This instruction belongs to groups: 20

{% endhighlight %}

---

### 4. Architecture-dependent details

Structure *cs_detail* has an union structure enabling access to architectured details in *arm*, *arm64*, *mips*, *ppc* or *x86* structures, depending on the current disassembling hardware mode. Refer to corresponding header file *arm.h*, *arm64.h*, *mips.h*, *ppc.h* & *x86.h* for further details on what information Capstone can provide.

The sample below demonstrates how to extract the details of instruction operands of ARM64 code.

{% highlight c linenos %}
// assume "insn"is a pointer variable to structure cs_insn
cs_detail *detail = insn->detail;
if (detail->arm64.op_count)
  printf("\tNumber of operands: %u\n", detail->arm64.op_count);

for (n = 0; n < detail->arm64.op_count; n++) {
  cs_arm64_op *op = &(detail->arm64.operands[n]);
  switch(op->type) {
    case ARM64_OP_REG:
      printf("\t\toperands[%u].type: REG = %s\n", n, cs_reg_name(handle, op->reg));
      break;
    case ARM64_OP_IMM:
      printf("\t\toperands[%u].type: IMM = 0x%x\n", n, op->imm);
      break;
    case ARM64_OP_FP:
      printf("\t\toperands[%u].type: FP = %f\n", n, op->fp);
      break;
    case ARM64_OP_MEM:
      printf("\t\toperands[%u].type: MEM\n", n);
      if (op->mem.base != ARM64_REG_INVALID)
        printf("\t\t\toperands[%u].mem.base: REG = %s\n", n, cs_reg_name(handle, op->mem.base));
      if (op->mem.index != ARM64_REG_INVALID)
        printf("\t\t\toperands[%u].mem.index: REG = %s\n", n, cs_reg_name(handle, op->mem.index));
      if (op->mem.disp != 0)
        printf("\t\t\toperands[%u].mem.disp: 0x%x\n", n, op->mem.disp);
      break;
    case ARM64_OP_CIMM:
      printf("\t\toperands[%u].type: C-IMM = %u\n", n, op->imm);
      break;
  }

  if (op->shift.type != ARM64_SFT_INVALID && op->shift.value)
    printf("\t\t\tShift: type = %u, value = %u\n", op->shift.type, op->shift.value);

  if (op->ext != ARM64_EXT_INVALID)
    printf("\t\t\tExt: %u\n", op->ext);
}

if (detail->arm64.cc != ARM64_CC_INVALID)
  printf("\tCode condition: %u\n", detail->arm64.cc);

if (detail->arm64.update_flags)
  printf("\tUpdate-flags: True\n");

if (detail->arm64.writeback)
  printf("\tWrite-back: True\n");
{% endhighlight %}

<br>
The code looks a bit complicated, but actually pretty simple:

- Line 2: Assume we already have a pointer to cs_insn structure. This line casts the details to a variable named *detail* for simplicity.

- Line 3: Check if this instruction has any operands to print out.

- Line 9 ~ 11: If this operand is register (reflected by type *ARM64_OP_REG*), then print out its register name with the API **cs_reg_name()**.

- Line 12 ~ 14: If this operand is immediate (reflected by type *ARM64_OP_IMM*), then print out its numerical value.

- Line 15 ~ 17: If this operand is real number (reflected by type *ARM64_OP_FP*), then print out its numerical value.

- Line 18 ~ 26: If this operand is memory reference  (reflected by type *ARM64_OP_MEM*), then print out its base/index registers, together with offset value.

- Line 27 ~ 29: If this operand is of type C-IMM (coprocessor register type, reflected by *ARM64_OP_CIMM*), then print out its index value.

- Line 32 ~ 36: If this operand uses shift or extender, print out their value.

- Line 39 ~ 40: Print out the code condition of this instruction if relevant.

- Line 42 ~ 43: If this instruction update flags, print out that.

- Line 45 ~ 46: If this instruction writes back its value afterwards, print out that.

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

### 5. Run-time options

Besides the *CS_OPT_DETAIL* option previously introduced, Capstone can customize the engine at run-time, allowing us to set the assembly syntax or dynamically change engine's mode with the same API *cs_option()*.

#### 5.1 Syntax option

By default, X86 assembly outputs in Intel syntax. To switch to AT&T syntax instead, we can simply set syntax option using the option **CS_OPT_SYNTAX** with *cs_option()* like below.

{% highlight c %}
csh handle;

cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT); // CS_OPT_SYNTAX_ATT represents AT&T syntax

{% endhighlight %}

<br>
In case we want to return to Intel syntax, we can reset the syntax in the similar way:

{% highlight c %}

cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL); // CS_OPT_SYNTAX_INTEL indicates Intel syntax

{% endhighlight %}

#### 5.2 Dynamically change disassemble mode at run-time

From version 2.0, we can dynamically change the engine's mode with *cs_open()* at run-time thanks to a new option **CS_OPT_MODE**.
    
This is useful for example with Arm, where we might frequently switch between Arm & Thumb modes without having to create a new engine. This also happens with X86, where we might want to switch back and forth between protected-mode & real-mode code.

Below sample shows how *CS_OPT_MODE* can be used to switch back and forth between Arm & Thumb modes at run-time.

{% highlight c %}

cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle);
// from now on disassemble Arm code ....

cs_option(handle, CS_OPT_MODE, CS_MODE_THUMB); // dynamically change engine's mode at run-time
// from now on disassemble Thumb code ....

cs_option(handle, CS_OPT_MODE, CS_MODE_ARM); // change back to Arm mode again
// from now on disassemble Arm code again

{% endhighlight %}

---

### 6. Diet engine

From version 2.1, Capstone supports "diet" compilation option to minimize the engine for embedded purpose. The *diet* engine no longer updates some data fields of the *cs_insn* struct, so these fields & some related APIs become irrelevant. See [this documentation](diet.html) for further information.

---

### 7. More examples

This tutorial does not explain all the API of Capstone yet. Please find more advanced examples in source of *test_\*.c* files under directory [tests/](https://github.com/capstone-engine/capstone/tree/master/tests) in the Capstone source code.

