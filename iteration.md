---
layout: default
title: Disassemble in iterartion style
---

### 1. Introduction of cs_disasm_iter API.

The API *cs_disasm* automatically allocates memory internally for disassembled instructions, which is expensive if we need to decode a lot of instructions.

From version 3.0, Capstone provides **cs_disasm_iter**, a new API that can improve the performance by up to 30% depending on cases. The principle is: rather than letting the core allocate memory, *user pre-allocates the memory required*, then pass it to the core, so Capstone can reuse the same memory to store the disassembled instructions. Elimination of many alloc/realloc calls is the reason behind the performance gained.

See below for a sample C code demonstrating this API.

{% highlight c linenos %}
    csh handle;
    cs_open(CS_ARCH_X86, CS_MODE_32, &handle);

    // allocate memory cache for 1 instruction, to be used by cs_disasm_iter later.
    cs_insn *insn = cs_malloc(handle);

    uint8_t *code = "\x90\x91\x92";
	size_t code_size = 3;	// size of @code buffer above
	uint64_t address = 0x1000;	// address of first instruction to be disassembled

    // disassemble one instruction a time & store the result into @insn variable above
    while(cs_disasm_iter(handle, &code, &code_size, &address, insn)) {
        // analyze disassembled instruction in @insn variable ...
        // NOTE: @code, @code_size & @address variables are all updated
        // to point to the next instruction after each iteration.
    }

    // release the cache memory when done
    cs_free(insn, 1);
{% endhighlight %}

<br>

- On *line 5*, we pre-allocate memory for one instruction and keep it in the variable *insn*. This is done thanks to **cs_malloc**, another new API introduced in Capstone 3.0.

- One *line 12*, we disassemble one instruction a time in a loop with *cs_disasm_iter*, which takes 5 arguments: the Capstone handle, the pointer to the input binary code, the pointer to the size of this input, the pointer to the address of the first instruction & the memory cache generated in *line 5*. On success, this API updates all these pointers to the next instruction, making it ready for the next iteration in the *while* loop.

  The API *cs_disasm_iter* returns *true* when it successfully decodes one instruction, or *false* otherwise. Therefore, readers can see that the *while* loop will disassemble until it either hits an invalid instruction, or end of the input buffer. Inside the loop, we would do usual binary analysis on the resulted instruction.

- On *line 19*, we release the cache memory allocated by *cs_malloc* with *cs_free*. Note that we have to tell *cs_free* to *free 1 instruction* because this is what *cs_malloc* did in *line 5* above: allocated memory for 1 instruction of the type *cs_insn*. 

---

### 2. Notes.

Internally, *cs_disasm_iter* behaves exactly like *cs_disasm* if we call *cs_disasm* with argument *count = 1*. However, *cs_disasm_iter* is faster because it reuses (and also overwrites) the same memory to store disassembled instruction, avoiding all the malloc/realloc in the loop above. So if we just need to do some quick iteration through all the instructions, *cs_disasm_iter* should be considered.

On the other hand, *cs_disasm* is more approriate when we want to disassemble all the instructions (using *count = 0*), or when we want to save all the disassembled instructions - without overwriting them in the loop - for future reference.

See a full sample of *cs_disasm_iter* & *cs_malloc* in [https://github.com/capstone-engine/capstone/blob/next/tests/test_iter.c](https://github.com/capstone-engine/capstone/blob/next/tests/test_iter.c)
