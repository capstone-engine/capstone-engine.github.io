---
layout: default
title: Version 2.0
---

## Changes from 2.0 to 2.1

This documentation describes how to adapt code written for Capstone version *2.0* to version **2.1**. Fortunately, the changes to be made are trivial, if any:

- Tools written in C just need some minimal modification to one API (see section 1).

- Code developed in other binding languages (Java, Python) do not need any change. The bindings must be upgraded, however (see section 2).

---
### 1. API change

Version 2.1 changes the API **cs_close()** from prototype:

{% highlight c %}
    cs_err cs_close(csh handle);   // in 2.0, cs_close() used to take handle as argument.
{% endhighlight %}

to:

{% highlight c %}
    cs_err cs_close(csh *handle);  // <-- now cs_close() takes pointer to handle as argument.
{% endhighlight %}

<br>
Therefore, all C code written on top of Capstone must be fixed accordingly, from something like:

{% highlight c %}
    csh handle;
    //....
    cs_close(handle);   // in 2.0, cs_close() used to take handle as argument.
{% endhighlight %}

to:

{% highlight c %}
    csh handle;
    //....
    cs_close(&handle);  // <-- now cs_close() takes pointer to handle as argument.
{% endhighlight %}

<br>
Internally, this change is to invalidate @handle, making sure it cannot be mistakenly used after the handle is closed.

<br>
`NOTE`: this change **breaks backward compatibility for C code only**. All the bindings of Python, Java or bindings made by community, such as C#, Go, Ruby & Vala, should hide this change behind their API. For this reason, code using these bindings still work exactly like before and do not need to have any modification.

---
### 2. Upgrade bindings

Version 2.1 makes some changes to Java & Python bindings, like adding some new instructions (affecting \*_const.py & \*_const.java). While this *does not break API compatibility* (i.e users do not need to modify their program written with prior version 2.0), they **must upgrade these bindings** and **must not use the old bindings from prior versions**.

<br>
We cannot emphasize this enough: When upgrading to the new engine, **always upgrade to the bindings coming with the same core**. If you do not follow this principle, applications written with old bindings would run with the new incompatible core, thus silently break without any clear evidence, making it extremely hard to debug.

