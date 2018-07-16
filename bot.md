---
layout: default
title: Twitter-based reversing bot
---

## Reversing in open wide public, on Twitter

### 1. Introduction
**CEbot** is a tool that lets you disassemble binary code from your own Twitter!

How? Do this in 2 simple steps:

- Send a tweet with your hex string. *CEbot* supports 2 tweet syntaxes as follows.

  1. Either *tweet* your hex string with hashtag **#cebot** or **#2ce** (read: "**To-C**apstone-**E**ngine").

  2. Or *tweet* the hex string directly to **@ceb0t**. In this case, the hashtag *#cebot* (or *#2ce*) is not needed.

  The first method can be used if you want all of your followers to see your reverse code.

  Meanwhile, the second method makes less noise because only those following both you and *@ceb0t* will see the tweet.

- Wait 1 ~ 2 seconds, the reversed assembly code will be sent back, also via Twitter. Be sure to check the *Notifications* tab if you do not see it soon enough.

  `NOTE`: If you do not see any reply, check the *FAQ* in *section 4* below for the possible reasons.

<br>
Few examples on tweets accepted by *CEbot*:

- **x32 909090 #2ce**

  Reverse *x86 32-bit* code with hex-string of 3 bytes *909090*. The result sent back would be *3 NOP* instructions.

- **x64 att 0x90 0x90 0x90 #2ce**

  Reverse *x86-64* code of the same 3 NOPs, but get back assembly in *AT&T syntax* (rather than default *Intel* syntax).

- **arm #cebot "\x04\xe0\x2d\xe5"**

  Reverse ARM code. Note that the hashtag can be put *anywhere in the tweet*.

- **@ceb0t m64 be 0C,10,00,97**

  Reverse Mips *64-bit* code in *big-endian* mode. This time, tweet is directly sent to *@ceb0t*, and hashtag *#2ce* is not required.

<br>
Readers might already noted that *CEbot* is flexible with format of the input hex-string: it is perfectly legal to have *space*, *quote*, *double-quote*, *comma* or even *plus sign* (*+*) inside the code.

For now, 8 architectures are supported: *Arm*, *Arm64*, *Mips*, *PowerPC*, *Sparc*, *SystemZ*, *XCore* & *X86*. See section 3 below for further details.

---
### 2. Real-life example
A blog entry on [BostonKeyParty CTF 2014](http://toanpv.wordpress.com/2014/03/06/boston-key-party-ctf-deepblue-writeup/) has this PowerPC shellcode:

{% highlight bash %}
  shellcode_read_exec = "\x38\xa0\x04\x03"+
                      "\x30\x05\xfb\xff"+
                      "\x7c\x24\x0b\x78"+
                      "\x44\x00\x00\x02"+
                      "\x69\x69\x69\x69"+
                      "\x7c\x29\x03\xa6"+
                      "\x4e\x80\x04\x21"
{% endhighlight %}

<br>
The author never explained this shellcode, but we can find out by just copying its content, putting *"ppc"* in front, then tweet it like below (actually with one *plus sign* removed to fit everything in a tweet).

{% highlight bash %}
ppc "\x38\xa0\x04\x03""\x30\x05\xfb\xff"+"\x7c\x24\x0b\x78"+"\x44\x00\x00\x02"+
"\x69\x69\x69\x69"+"\x7c\x29\x03\xa6"+"\x4e\x80\x04\x21" #2ce
{% endhighlight %}

<br>
In under 2 seconds, we get back a tweet from *@ceb0t* with the assembly of the shellcode inside.

{% highlight bash %}
	li r5, 0x403
	addic r0, r5, -0x401
	mr r4, r1
	sc 0
	xori r9, r11, 0x6969
	mtctr r1
	bctrl
{% endhighlight %}

---
### 3. Tweet syntax for CEbot

*CEbot* only serves requests with proper content: the accepted syntax is simple & intuitive, as follows.


{% highlight bash %}
[@ceb0t] <arch> [mode1 mode2 ...] [syntax] <hex-string> [#2ce|#cebot]
{% endhighlight %}

<br>
This means to send the tweet directly to *@ceb0t*, put its Twitter ID at the front. Then, the first word in the hex-string must indicate the *hardware architecture*. Next part specifies the *hardware modes*, *assembly syntax*, then the input *hex-string*. It is possible to combine more than one modes, like when we want to reverse Mips code in *64-bit* & *big-endian* mode. But if the *modes* & *syntax* are missing, the *default modes* & *default syntax* will be used.

Note that the hashtag *#2ce* (or *#cebot*, but only one of them is needed) can be put anywhere in the tweet, not necessarily at the end. Moreover, if we tweet directly to *@ceb0t*, hashtag is not required. Vice versa, mass-tweet would need hashtag, but not *@ceb0t* in front.

Finally, to shorten the tweet contents, *CEbot* supports **alias**, which combines *arch* & *modes*. Example: *x32* is actually the alias of *x86 32* (32-bit X86), *m64* is the alias of *mips 64* (64-bit Mips)

At the moment, *CEbot* supports 8 architectures with the following setup.

<br>
**X86**

| Field | Value | Meaning |
| :--: |:--:|:--|
| arch | x86 | X86 architecture |
| mode | 16<br>32<br>64 | 16-bit<br>32-bit (**default mode**)<br>64-bit |
| syntax | intel<br>att | Intel assembly syntax (**default syntax**)<br>AT&T assembly syntax |
| alias | x16<br>x32<br>x64 | x86 16<br>x86 32<br>x86 64 |

<br>
**ARM**

| Field | Value | Meaning |
| :--: |:--:|:--|
| arch | arm | ARM architecture |
| mode | le<br>be<br>thumb | Little endian (**default endian**)<br>Big-endian<br>Thumb mode |

<br>
**Thumb (ARM)**

| Field | Value | Meaning |
| :--: |:--:|:--|
| arch | thumb | Thumb mode of ARM architecture |
| mode | le<br>be<br> | Little endian (**default endian**)<br>Big-endian |

<br>
**Arm64**

| Field | Value | Meaning |
| :--: |:--:|:--|
| arch | arm64 | Arm64 (or Aarch64/ArmV8) architecture |
| mode | le<br>be<br> | Little endian (**default endian**)<br>Big-endian |
| alias | a64 | arm64 |

<br>
**Mips**

| Field | Value | Meaning |
| :--: |:--:|:--|
| arch | mips | Mips architecture |
| mode | 32<br>64<br>le<br>be<br> | 32-bit (**default mode**)<br>64-bit<br>Little endian (**default endian**)<br>Big-endian |
| alias | m32<br>m64 | mips 32<br>mips 64 |

<br>
**PowerPC**

| Field | Value | Meaning |
| :--: |:--:|:--|
| arch | ppc | PowerPC architecture |
| mode | - | No mode specified is needed |

<br>
**Sparc**

| Field | Value | Meaning |
| :--: |:--:|:--|
| arch | sparc | Sparc architecture |
| mode | v9 | Sparc V9 |
| alias | spv9 | sparc v9 |

<br>
**SystemZ**

| Field | Value | Meaning |
| :--: |:--:|:--|
| arch | sysz | SystemZ architecture |
| mode | - | No mode specified is needed |

<br>
**XCore**

| Field | Value | Meaning |
| :--: |:--:|:--|
| arch | xcore | XCore architecture |
| mode | - | No mode specified is needed |
| alias | xc | xcore |

---
### 4. FAQ

- **Why this tool?**

  - It can be helpful for those who are on Twitter all the time.
  
  - This is the best way to show your reverse kungfu to the world in open wide public :-)

  - We hope through this more people use Capstone disassembly framework & actively report bugs in it.

  - It is fun: *CEbot* is the first ever Twitter-based bot for reversing, no less :-)

- **How this works?**

  Our bot with the Twitter ID **@CEb0t** watches for Twitter stream with hashtags *#2ce* and *#cebot* to pick up the requests. Powered by the latest [Capstone Engine](https://github.com/aquynh/capstone/tree/next), this bot reverses the input hex-string, then sends back the assembly to the user via Twitter.

  Note that the input code is disassembled with *offset 0*.

- **I tweeted my hex-string, but saw nothing returned (!?)**

  There are two main reasons when no assembly code is sent back.

  - *CEbot* does not pick up requests with wrong format. Perhaps your tweet did not follow the strict syntax introduced in section 3 above. Note that the very first word must be either the hashtag or *arch*. *Do not mention* the bot, or any other tweeter ID. The hashtag (either *#2ce* or *#cebot*) can be put anywhere, however.

  - If you are sure your tweet is correct, perhaps *CEbot* is not online for some unexpected reasons. Confirm that by checking for its status announced at its [Twitter page](https://twitter.com/ceb0t)
  
    If you suspect that the bot is died, please report to [@capstone_engine](https://twitter.com/capstone_engine) or [@ceb0t](https://twitter.com/ceb0t), we will fix it.

- **Can I receive the output on Direct-Message (DM)?**

  Too bad, Twitter puts a tight limit on DM: we can only send *15 DMs in 15 minutes*, and this restriction effectively makes it pretty useless. Therefore, *CEbot* has to stick with public tweets.

- **Is CEbot disturbing people with public tweets?**

  *CEbot* only answers requests having hashtags *#2ce* or *#cebot#*, plus the tweet content must strictly follows the syntax presented in section 3 above. It is unlikely that usual tweets meet these requirements. Therefore, there is little chance that *CEbot* will bother those who do not explicitly ask for its service.

- **Any limitations of this bot?**

  The main issue comes from Twitter itself, as users can only send in short hex-strings: keep in mind that Twitter allows *no more than 140 chars* in a tweet.

  In return, we walkaround this limit by sending back the assembly on Twitter only if the output is *shorter than 140 chars*. With longer code, we post the result on *Pastebin.com*, then send back the link instead.

<!---
  Finally, Twitter caps the number of tweets a bot can send daily at 1000. For this reason, when reaching this limit, *CEbot* will have to wait for the timeout. We took some measures to prevent spams, but please do not abuse *CEbot* by sending too many requests a day. 
-->
