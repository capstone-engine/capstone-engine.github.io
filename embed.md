---
layout: default
title: Embed engine
---

## Building embedded engine

This documentation introduces necessary steps to build Capstone for embedding into special environments such as firmware or OS kernel.


### 1. Building a minimized engine

Typically, we use Capstone for usual applications, where the library weight does not really matter. Indeed, as of version *2.1-RC1*, the whole engine is only 1.9 MB including all architectures, and this size raise no issue to most people.

However, to embed Capstone into special environments, such as OS kernel driver or firmware, the engine size should be as small as possible due to space restriction. To achieve this object, we must compile Capstone using special methods.

To build a minimize engine, consult two documentations below.

- [Build only selected architectures to suite your need](compile.html).

- [Build diet engine](diet.html).

### 2. Building an embedded engine

By default, Capstone is built in *standard mode*, which just uses *system*'s dynamic memory management functions. In the embedded environment, there might not be such functions, however. For this reason, we need to tell building process that we will use our own dynamic memory functions, rather than standard functions.

For the first step, build the embedded engine and install with: (demonstration is on \*nix systems)

{% highlight bash %}
$ CAPSTONE_USE_SYS_DYN_MEM=no ./make.sh
$ sudo ./make.sh install
{% endhighlight %}

<br>
After this step, the final binaries can be ready to use for embedding.

NOTE: the observant readers might already see that we can combine step (1) & (2) into one. Indeed, we can simply modify *config.mk* in one go, including select architectures, configure diet engine and embedded engine, then compile the framework. However, we still present this in 2 steps for the sake of clarity.

### 3. Setting up dynamic memory management

In step (2) above, we already specified at compile-time that we will use our own dynamic memory management functions, provided by our embedded environment. Next, we need to declare these functions.

Capstone needs the following functions: *malloc*, *calloc*, *realloc*, *free* & *vsnprintf*. Unsurprisingly, these functions use exactly the same prototypes of system functions in style of *Unix stdlibc*, like below.

{% highlight c %}
void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void  free(void *ptr);
int   vsnprintf(char *str, size_t size, const char *format, va_list ap);
{% endhighlight %}

<br>
Our embedded environment has to prepare these functions: they must be ready for the engine before it can do anything, which means we have to do the setup even before the first call to *cs_open()*. This is done thanks to the API *cs_option()* as in the sample below.

{% highlight c linenos %}
void *my_malloc(size_t size)
{
    // Allocate & return a chunk of memory with @size bytes.
    // ...
}

void *my_calloc(size_t nmemb, size_t size)
{
    // Allocate & return @nmemb block of memory, with each block
    // has the size of @size bytes. Memory must be ZERO out before
    // returning.
    // ...
}

void *my_realloc(void *ptr, size_t size)
{
    // Re-allocate & return memory of former allocation with
    // new size of @size bytes.
    // ...
}

void  my_free(void *ptr)
{
    // Free memory formerly allocated by my_malloc/my_calloc/my_realloc.
    // ...
}

int   my_vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
    // Write a NULL terminated string to @str, with maximum size of @size bytes.
    // String is formatted according to @format, with variables provided in @ap.
    // ...
}

// ....
// Prepare these function for the setup step.
cs_opt_mem setup;

setup.malloc = my_malloc;
setup.calloc = my_calloc;
setup.realloc = my_realloc;
setup.free = my_free;
setup.vsnprintf = my_vsnprintf;

// Finally, setup our own dynamic memory functions with cs_option().
if (!cs_option(0, CS_OPT_MEM, &setup)) {
    // OK, successfully setup our own dynamic memory management.
    // From now on, we can use other Capstone APIs.
} else {
    // Failed to initialize our user-defined dynamic mem functions.
    // Quit is the only choice here :-(
}
{% endhighlight %}

<br>
Below is the explanation for each line of this simple code.

- Line 1 ~ 33: Declare our own dynamic memory functions with similar prototype to *malloc*, *calloc*, *realloc*, *free* & *vsnprintf*.

- Line 37 ~ 43: Setup a *cs_opt_mem* structure with our own functions declared above.

- Line 46: Inform Capstone engine about our own dynamic memory management code using the API *cs_option()*, which is called with (special) handle *0* & dedicated option type *CS_OPT_MEM*. This step is only considered successfully if the returned value is 0.

<br>
NOTE: it is *illegal* to use *cs_option()* with *0* as the first argument, as this API expects a valid handle. However, this is acceptable (only) with the option type *CS_OPT_MEM*, like in this case.
