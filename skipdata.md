---
layout: default
title: SKIPDATA mode
---

## SKIPDATA mode

(Note: at the moment, this option is only available in the [next branch](https://github.com/capstone-engine/capstone/tree/next) of our Github repo. It will be integrated into the next release of Capstone)

By default, Capstone stops disassembling when it encounters a broken instruction. Most of the time, the reason is that this is data mixed inside the input, and it is understandable that Capstone does not understand this "weird" code.

Typically, you are recommended to determine yourself where the next code is, and then continue disassembling from that place. However, in some cases you just want to let Capstone automatically skip some data until it finds a legitimate instruction, then just carries on from there. Hence, the **SKIPDATA** mode is introduced for this purpose.

In general, this solution is suboptimal because Capstone can make a mistake deciding what is data, what is code. Only rely on a fact that input can be disassembled to determine the code start from there is fundamentally wrong, so you are warned: only use this mode when you know what you are doing.

---

### 1. Turn on SKIPDATA mode

To tell Capstone to skip some (unknown) amount of data until the next legitimate instruction, simply use *cs_option()* to turn on option *CS_OPT_SKIPDATA* (which is *off* by default) as follows.

{% highlight c %}
csh handle;
cs_open(CS_ARCH_X86, CS_MODE_32, &handle);

// turn on SKIPDATA mode
cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
{% endhighlight %}

<br>
The output of some X86 code with data mixed inside can be like the sample below

{% highlight bash linenos %}
Platform: X86 32 (Intel syntax)
Code: 0x8d 0x4c 0x32 0x08 0x01 0xd8 0x81 0xc6 0x34 0x12 0x00 0x00 0x00 0x91 0x92
Disasm:
0x1000:	lea	ecx, dword ptr [edx + esi + 8]
0x1004:	add	eax, ebx
0x1006:	add	esi, 0x1234
0x100c:	.byte	0x00
0x100d:	xchg	eax, ecx
0x100e:	xchg	eax, edx
{% endhighlight %}

<br>
Readers can see that in *line 7*, Capstone skips 1 byte of data (*0x00*) and continues to disassemble from the next bytes in the input stream. In this case, actually Capstone considers the skip data a special instruction with instruction ID of **zero**, with mnemonic as "*.byte*" and operand string as a hex-code of the sequence of bytes it skipped.

NOTE that on this special "data" instruction, the *detail* pointer of struct *CsInsn* points to NULL, because obviously it has no detail. Therefore, programmers need to be careful not to access the detail pointer of this "data" instruction.

By default, for each iteration, Capstone skips 1 byte on *X86* architecture, 2 bytes on *Thumb* mode on *Arm* architecture, and 4 bytes for the rest. The reason while Capstone skips 1 byte on X86 is that X86 puts no restriction on instruction alignment, but other architectures enforces some requirements on this aspect.

When we do not want Capstone to skip data anymore, but just stop when hitting broken instruction, we can return to the default mode by simply turnning off SKIPDATA mode, as follwings.

{% highlight c %}
// turn off SKIPDATA mode
cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_OFF);
{% endhighlight %}

<br>
For Python code, turning on and off this option can be done simply by modifying *skipdata* status of *Cs* class, like in the below code.

{% highlight python %}
md = Cs(CS_ARCH_X86, CS_MODE_32)

# By default, SKIPDATA mode is OFF. Now let's turn it ON
md.skipdata = True
# From here onwards, Capstone skips data until it finds a legitimate instruction
# .....

# Turn off SKIPDATA mode, so we are back to the default mode
md.skipdata = False
{% endhighlight %}

---

### 2. Customize the "data" instruction's mnemonic

As presented above, Capstone considers data to be skipped an instruction with the default mnemonic "*.byte*". To change this mnemonic, use *cs_option()* with *CS_OPT_SKIPDATA_SETUP*, as follows.

{% highlight c linenos %}
csh handle;
cs_open(CS_ARCH_X86, CS_MODE_32, &handle);

cs_opt_skipdata skipdata = {
    .mnemonic = "db",
};

// customize SKIPDATA mode
cs_option(handle, CS_OPT_SKIPDATA_SETUP, &skipdata);

// Turn on SKIPDATA mode
cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
{% endhighlight %}

<br>
The code above is intuitive enough itself.

- Line 4: declare the customization with *cs_opt_skipdata* struct

- Line 5: change mnemonic of the "data" instruction to "db"

- Line 9: customize SKIPDATA mode with our struct above using *cs_option()* & *CS_OPT_SKIPDATA_SETUP* option.

<br>
Thanks to this, the output of the same input in section 1 above will be as follwings (note the change on *line 7*).

{% highlight bash linenos %}
Platform: X86 32 (Intel syntax)
Code: 0x8d 0x4c 0x32 0x08 0x01 0xd8 0x81 0xc6 0x34 0x12 0x00 0x00 0x00 0x91 0x92
Disasm:
0x1000:	lea	ecx, dword ptr [edx + esi + 8]
0x1004:	add	eax, ebx
0x1006:	add	esi, 0x1234
0x100c:	db	0x00
0x100d:	xchg	eax, ecx
0x100e:	xchg	eax, edx
{% endhighlight %}

<br>
For Python code, this customization can be done easier thanks to the *skipdata_setup* getter, as follows.

{% highlight python %}
md = Cs(CS_ARCH_X86, CS_MODE_32)

# Customize the mnemonic of "data" instruction
md.skipdata_setup = ("db", None, None)

# Turn on SKIPDATA mode
md.skipdata = True
{% endhighlight %}

<br>
As you can see, simply pass a *Python tuple* of *3 members* to *skipdata_setup*, with the *first member* is the *mnemonic* string, and the other two members as *None*.

---

### 3. Customize SKIPDATA with user-defined callback function

By default, depending on architecture, Capstone skips a certain number of bytes on each iteration, as pointed out in section 1 above. In case we want to customize this, we can program a callback and setup that with the same option *CS_OPT_SKIPDATA_SETUP* above.

The user-defined callback is a function that returns the number of bytes to skip, which takes 3 arguments: the first is the input buffer passed to *cs_disasm_ex()*, the second is the offset of currently examining byte in the above input buffer, and the last is an user-data pointer.

Note that in case we no longer want to disassemble, we simply return **zero** (*value 0*) from the callback. In this case, Capstone will immediately bail out, and stop all the reverse process.

See the sample code below for how to setup the callback, in which the callback tells Capstone to always skip 2 bytes.

{% highlight c %}
size_t mycallback(const uint8_t *buffer, uint64_t offset, void *user_data)
{
    // always skip 2 bytes when encountering data
    return 2;
}

csh handle;
cs_open(CS_ARCH_X86, CS_MODE_32, &handle);

cs_opt_skipdata skipdata = {
    .mnemonic = "db",        // set mnemonic to "db"
    .callback = &mycallback,  // use the callback defined above
    .user_data = NULL,       // do not have user-data in this sample
};

// customize SKIPDATA mode with our callback
cs_option(handle, CS_OPT_SKIPDATA_SETUP, &skipdata);

// Turn on SKIPDATA mode
cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
{% endhighlight %}

<br>
For Python, this customization is easier: we just need to pass a *Python tuple* of *3 members* to *skipdata_setup*, with the *first member* is the *mnemonic* string, the *second* is the *callback function*, and the *third* is the *user-data*.

The same sample of the C code above, but in Python, is as follows.

{% highlight python %}
def mycallback(buffer, offset, userdata):
    return 2

md = Cs(CS_ARCH_X86, CS_MODE_32)

# Customize the SKIPDATA mode with our callback
md.skipdata_setup = ("db", mycallback, None)

# Turn on SKIPDATA mode
md.skipdata = True
{% endhighlight %}

---

### 4. Sample code for SKIPDATA mode

For sample C code, see [https://github.com/capstone-engine/capstone/blob/next/tests/test_skipdata.c](https://github.com/capstone-engine/capstone/blob/next/tests/test_skipdata.c)

For sample Python code, see [https://github.com/capstone-engine/capstone/blob/next/bindings/python/test_skipdata.py](https://github.com/capstone-engine/capstone/blob/next/bindings/python/test_skipdata.py)
