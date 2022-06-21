---
layout: default
title: Access information of operands.
---

## Retrieve access information of instruction operands

### 1. Get access info of registers

Now available in the Github branch [next](https://github.com/capstone-engine/capstone/tree/next), Capstone provides a new API named **cs\_regs\_access()**. This function can retrieve the list of all registers *read* or *modified* - either implicitly or explicitly - by instructions.

<br>
The C sample code below demonstrates how to use *cs\_regs\_access* on X86 input.

{% highlight c linenos %}
#include <stdio.h>

#include <capstone/capstone.h>

#define CODE "\x8d\x4c\x32\x08\x01\xd8"

int main(void)
{
  csh handle;
  cs_insn *insn;
  size_t count, j;
  cs_regs regs_read, regs_write;
  uint8_t read_count, write_count, i;
  
  if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
    return -1;
  
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
  
  count = cs_disasm(handle, CODE, sizeof(CODE)-1, 0x1000, 0, &insn);
  if (count > 0) {
    for (j = 0; j < count; j++) {
      // Print assembly
      printf("%s\t%s\n", insn[j].mnemonic, insn[j].op_str);

      // Print all registers accessed by this instruction.
      if (cs_regs_access(handle, &insn[j],
            regs_read, &read_count,
            regs_write, &write_count) == 0) {
        if (read_count > 0) {
          printf("\n\tRegisters read:");
          for (i = 0; i < read_count; i++) {
          	printf(" %s", cs_reg_name(handle, regs_read[i]));
          }
          printf("\n");
        }

        if (write_count > 0) {
          printf("\n\tRegisters modified:");
          for (i = 0; i < write_count; i++) {
            printf(" %s", cs_reg_name(handle, regs_write[i]));
          }
          printf("\n");
        }
      }
    }

    cs_free(insn, count);
  } else
  	printf("ERROR: Failed to disassemble given code!\n");

  cs_close(&handle);

  return 0;
}
{% endhighlight %}

<br>
Compile and run this sample, we have the output as follows.

{% highlight bash %}
lea	ecx, [edx + esi + 8]

	Registers read: edx esi
	Registers modified: ecx

add	eax, ebx

	Registers read: eax ebx
	Registers modified: eflags eax
{% endhighlight %}

<br>
Below is the explanation for important lines of the above C sample.

- Line 12: Declare variables *regs_read* & *regs_write* of data type *cs\_regs* to keep the list of registers being read or modified later. Note that *cs\_regs* is actually a data type of an array of *uint16_t*.

- Line 15 ~ 18: Initialize X86 engine, then turn on the *DETAIL* mode, which is required to get the access information of operands & registers.

- Line 20 ~ 24: Disassemble input code, then print out the assembly of all the instructions.

- Line 27 ~ 29: Retrieve access information of registers with *cs\_regs\_access()*. After this, *regs_read* & *regs_write* keep all the registers being read & modified by current assembly instructions. Meanwhile, *read_count* & *write_count* contain number of registers kept inside array *regs_read* & *regs_write*, respectively.

- Line 30 ~ 36: If there are registers being read (see the checking condition *read_count > 0*), print out these registers inside *regs_read* array. Register name is retrieved with the API *cs\_reg\_name()*.

- Line 38 ~ 44: If there are registers being modified (see the checking condition *write_count > 0*), print out these registers inside *regs_write* array.

<br>
For those readers more familiar with Python, the below code does the same thing as the above C sample.

{% highlight python linenos %}
from capstone import *

CODE = b"\x8d\x4c\x32\x08\x01\xd8"

md = Cs(arch, mode)
md.detail = True

for insn in md.disasm(code, 0x1000):
	print("%s\t%s" % (insn.mnemonic, insn.op_str))

	(regs_read, regs_write) = insn.regs_access()

	if len(regs_read) > 0:
		print("\n\tRegisters read:", end="")
		for r in regs_read:
			print(" %s" %(insn.reg_name(r)), end="")
		print()

	if len(regs_write) > 0:
		print("\n\tRegisters modified:", end="")
		for r in regs_write:
			print(" %s" %(insn.reg_name(r)), end="")
		print()
{% endhighlight %}

<br>
Below is the explanation for important lines of this Python sample.

- Line 5 ~ 6: Initialize X86 engine, then turn on the *DETAIL* mode, which is required to get the access information of operands & registers.

- Line 8 ~ 9: Disassemble input code, then print out the assembly of all the instructions.

- Line 11: Retrieve access information of registers with *regs_access()* method. After this, the lists of *regs_read* & *regs_write* keep all the registers being read & modified by current assembly instructions.

- Line 13 ~ 17: If there are registers being read (see the checking condition for the length of *regs_read*), print out these registers inside the list *regs_read*. Register name is retrieved with method *reg_name()*.

- Line 19 ~ 23: If there are registers being modified (see the checking condition for the length of *regs_write*), print out these registers inside the list *regs_write*.

---

### 2. Get access info of operands

For instruction operands, besides the information such as *size* & *type*, now we can retrieve the access information. This is possible thanks to the new field *cs_x86_op.access* in *x86.h*.

- The value *CS_AC_READ* indicates this operand is read.

- The value *CS_AC_WRITE* indicates this operand is modified.

- The value *(CS_AC_READ* &#124; *CS_AC_WRITE)* indicates this operand is read first, then modified later.

- The value *CS_AC_INVALID* indicates this operand is not accessed, for example *immediate* operand.

<br>
With the help of *cs_x86_op.access*, we can find out how each instruction operand is accessed, like below.

{% highlight bash %}
lea	ecx, [edx + esi + 8]
	Number of operands: 2
		operands[0].type: REG = ecx
		operands[0].access: WRITE

add	eax, ebx
	Number of operands: 2
		operands[0].type: REG = eax
		operands[0].access: READ | WRITE

		operands[1].type: REG = ebx
		operands[1].access: READ
{% endhighlight %}

<br>
Note that instruction *LEA* do not actually access the second operand, hence this operand is ignored.


---

### 3. Status register update

Arithmetic instructions might update status flags. In X86 case, this is the *EFLAGS* register. Capstone does not only tell you that *EFLAGS* is modified, but can also provide details on individual bits inside *EFLAGS*. Examples are *CF*, *ZF*, *OF*, *SF* flags and so on.

On X86, this information is available in the field *cs_x86.eflags*, which is bitwise *OR* of *X86_EFLAGS_\** values. Again, this requires the engine to be configured in *DETAIL* mode.

<br>
See the screenshot below for what this feature can provide.

<img src="http://capstone-engine.org/capstone-newapi.png" width="800px"/>

---

### 4. More examples

Find the full sample on how to retrieve information on operand access in source of [test_x86.c](https://github.com/capstone-engine/capstone/blob/next/tests/test_x86.c) or [test_x86.py](https://github.com/capstone-engine/capstone/blob/next/bindings/python/test_x86.py).

