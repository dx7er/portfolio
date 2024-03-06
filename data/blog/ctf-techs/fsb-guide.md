---
title: A Definitive Guide to Format String Bug
date: '2024-02-29'
tags: ['ctf-techs', 'fsb', 'format-string', 'printf']
draft: false
summary: A detailed guide on how printf's can be used for arbitrary read and arbitrary write.
---

# Introduction

In this guide, I'll go towards intricate details of Format String Bugs, how they occur, how they work and how they can be exploited to read values from the stack, write values to an arbitrary location and get a shell. This blog post will go in-depth to make sure that we fully understand each concept as we go through them.

---

## What is a Format String and Printf?

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

There's also one sub-specifier (per-se) that allows an exact position offset value (from `RSP`.). The usage of that is as follows:

```c
%{POSITION}${SPECIFIER}

// Example:
// %10$p
// This will print the 10th value as a pointer address from the RSP.
```

### Printf

According to [`cplusplus.com`](https://cplusplus.com/reference/cstdio/printf/):

> Writes the C string pointed by format to the standard output (stdout). If format includes format specifiers (subsequences beginning with %), the additional arguments following format are formatted and inserted in the resulting string replacing their respective specifiers.

In simpler terms, `printf` is a function that takes in a [`format specifier`](#specifiers), parses it and displays it to `stdout`.
